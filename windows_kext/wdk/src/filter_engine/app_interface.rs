//! Session-owned WFP interface policies. Only the passive command path touches
//! this state; WFP's built-in callout applies policies without a driver lookup.

use alloc::vec::Vec;
use core::{mem, ptr};
use windows_sys::{
    core::GUID,
    Wdk::System::SystemServices::ExUuidCreate,
    Win32::{
        Foundation::{HANDLE, NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE},
        NetworkManagement::WindowsFilteringPlatform::{
            FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_FILTER_CONDITION0,
            FWPM_NETWORK_CONNECTION_POLICY_CONTEXT, FWPM_NETWORK_CONNECTION_POLICY_SETTING0,
            FWPM_NETWORK_CONNECTION_POLICY_SETTINGS0, FWPM_PROVIDER_CONTEXT3, FWPM_SESSION0,
            FWPM_SESSION_FLAG_DYNAMIC, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB,
            FWP_BYTE_BLOB_TYPE, FWP_IP_VERSION, FWP_IP_VERSION_V4, FWP_IP_VERSION_V6,
            FWP_MATCH_EQUAL, FWP_MATCH_NOT_EQUAL, FWP_NETWORK_CONNECTION_POLICY_NEXT_HOP_INTERFACE,
            FWP_UINT64, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
        },
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
};

use crate::ffi::{
    FwpmConnectionPolicyAdd0, FwpmConnectionPolicyDeleteByKey0, FwpmEngineClose0, FwpmEngineOpen0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};

#[cfg(not(test))]
use crate::ffi::RtlDowncaseUnicodeChar;
#[cfg(test)]
use windows_sys::Wdk::System::SystemServices::RtlDowncaseUnicodeChar;

struct AppPolicy {
    app_id: Vec<u8>,
    luid: u64,
    keys: [GUID; 2],
}

pub struct AppInterfacePolicies {
    handle: HANDLE,
    policies: Vec<AppPolicy>,
}

// The session is accessed only under Device's PASSIVE_LEVEL mutex. Raw handles
// and GUIDs have no thread affinity and contain no borrowed Rust references.
unsafe impl Send for AppInterfacePolicies {}

fn check(status: NTSTATUS) -> Result<(), NTSTATUS> {
    if status < 0 {
        Err(status)
    } else {
        Ok(())
    }
}

impl AppInterfacePolicies {
    pub fn new() -> Self {
        Self {
            handle: ptr::null_mut(),
            policies: Vec::new(),
        }
    }

    fn open(&mut self) -> Result<(), NTSTATUS> {
        if !self.handle.is_null() {
            return Ok(());
        }
        let mut session: FWPM_SESSION0 = unsafe { mem::zeroed() };
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        let mut handle = ptr::null_mut();
        // SAFETY: All structures live through the synchronous PASSIVE_LEVEL call.
        check(unsafe {
            FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT,
                ptr::null_mut(),
                &session,
                &mut handle,
            )
        })?;
        if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.handle = handle;
        Ok(())
    }

    /// `app_id` must be the validated canonical UTF-16LE blob returned by
    /// FwpmGetAppIdFromFileName0, including its NUL terminator. LUID zero removes
    /// the policy. Both address families are changed atomically.
    pub fn set(&mut self, app_id: &[u8], luid: u64) -> Result<(), NTSTATUS> {
        let app_id = downcase_app_id(app_id)?;
        let existing = self
            .policies
            .iter()
            .position(|policy| policy.app_id == app_id);
        if let Some(index) = existing {
            if self.policies[index].luid == luid {
                return Ok(());
            }
        } else if luid == 0 {
            return Ok(());
        }

        // Reserve every Rust allocation before modifying WFP. A failed update
        // keeps the previous policies and the local bookkeeping unchanged.
        let new_policy = if existing.is_none() {
            self.policies
                .try_reserve(1)
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            let mut keys = [GUID::from_u128(0); 2];
            for key in &mut keys {
                // SAFETY: A live GUID output is supplied at PASSIVE_LEVEL.
                check(unsafe { ExUuidCreate(key) })?;
            }
            Some(AppPolicy { app_id, luid, keys })
        } else {
            None
        };

        self.open()?;
        let transaction = PolicyTransaction::begin(self.handle)?;
        if let Some(index) = existing {
            for key in &self.policies[index].keys {
                // SAFETY: The key belongs to this live dynamic session.
                check(unsafe { FwpmConnectionPolicyDeleteByKey0(self.handle, key) })?;
            }
        }
        if luid != 0 {
            let policy = existing
                .map(|i| &self.policies[i])
                .unwrap_or_else(|| new_policy.as_ref().unwrap());
            for (key, version) in policy
                .keys
                .iter()
                .zip([FWP_IP_VERSION_V4, FWP_IP_VERSION_V6])
            {
                add_policy(self.handle, key, version, &policy.app_id, luid)?;
            }
        }
        transaction.commit()?;

        if let Some(index) = existing {
            if luid == 0 {
                self.policies.swap_remove(index);
            } else {
                self.policies[index].luid = luid;
            }
        } else {
            self.policies.push(new_policy.unwrap());
        }
        Ok(())
    }

    /// Closing a dynamic session deletes every policy, including any WFP state
    /// that was not committed to the local bookkeeping. No process scan is used.
    pub fn close(&mut self) -> Result<(), NTSTATUS> {
        if !self.handle.is_null() {
            // SAFETY: Calls are serialized and this object owns the session.
            check(unsafe { FwpmEngineClose0(self.handle) })?;
            self.handle = ptr::null_mut();
        }
        self.policies = Vec::new();
        Ok(())
    }
}

impl Drop for AppInterfacePolicies {
    fn drop(&mut self) {
        while let Err(status) = self.close() {
            crate::err!(
                "failed to close app interface policies: NTSTATUS({:#010x})",
                status as u32
            );
            crate::utils::sleep_ms(1);
        }
    }
}

// FwpmGetAppIdFromFileName0 can preserve non-ASCII capitals, while ALE's
// native application ID uses Windows Unicode lowercase. Apply that same NLS
// mapping once per command, not Rust's locale-independent Unicode expansion
// rules and never a userspace-locale/ANSI conversion. The wire can be unaligned.
fn downcase_app_id(app_id: &[u8]) -> Result<Vec<u8>, NTSTATUS> {
    let mut normalized = Vec::new();
    normalized
        .try_reserve_exact(app_id.len())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    for pair in app_id.chunks_exact(2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        // SAFETY: This value-only NLS call runs on the PASSIVE_LEVEL command path.
        // Unit tests use ntdll's equivalent; kernel builds import ntoskrnl's API.
        let lower = unsafe { RtlDowncaseUnicodeChar(unit) };
        normalized.extend_from_slice(&lower.to_le_bytes());
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::{downcase_app_id, policy_conditions, LoopbackAddresses};
    use alloc::{string::String, vec, vec::Vec};
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_BYTE_ARRAY16_TYPE,
        FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_IP_VERSION_V4, FWP_IP_VERSION_V6, FWP_MATCH_EQUAL,
        FWP_MATCH_NOT_EQUAL, FWP_V4_ADDR_MASK,
    };

    #[test]
    fn policy_matches_the_app_and_excludes_each_familys_loopback_destinations() {
        let mut app_id = encoded(concat!(r"\device\volume\app.exe", "\0"));
        let mut blob = FWP_BYTE_BLOB {
            size: app_id.len() as u32,
            data: app_id.as_mut_ptr(),
        };
        let mut loopback = LoopbackAddresses::new();
        let key = |guid: &windows_sys::core::GUID| (guid.data1, guid.data2, guid.data3, guid.data4);
        for version in [FWP_IP_VERSION_V4, FWP_IP_VERSION_V6] {
            let conditions = policy_conditions(&mut blob, version, &mut loopback);
            assert_eq!(conditions.len(), 2);
            assert_eq!(
                key(&conditions[0].fieldKey),
                key(&FWPM_CONDITION_ALE_APP_ID)
            );
            assert_eq!(conditions[0].matchType, FWP_MATCH_EQUAL);
            assert_eq!(conditions[0].conditionValue.r#type, FWP_BYTE_BLOB_TYPE);
            assert_eq!(
                unsafe { conditions[0].conditionValue.Anonymous.byteBlob },
                core::ptr::addr_of_mut!(blob)
            );
            assert_eq!(
                key(&conditions[1].fieldKey),
                key(&FWPM_CONDITION_IP_REMOTE_ADDRESS)
            );
            assert_eq!(conditions[1].matchType, FWP_MATCH_NOT_EQUAL);
            if version == FWP_IP_VERSION_V4 {
                assert_eq!(conditions[1].conditionValue.r#type, FWP_V4_ADDR_MASK);
                let mask = unsafe { &*conditions[1].conditionValue.Anonymous.v4AddrMask };
                assert_eq!(mask.addr, 0x7f00_0000);
                assert_eq!(mask.mask, 0xff00_0000);
                for address in [0x7f00_0000, 0x7f00_0001, 0x7f00_0002, 0x7fff_ffff] {
                    assert_eq!(address & mask.mask, mask.addr);
                }
                for address in [
                    0x0101_0101,
                    0x0a00_0001,
                    0x7eff_ffff,
                    0x8000_0000,
                    0xc0a8_0001,
                ] {
                    assert_ne!(address & mask.mask, mask.addr);
                }
            } else {
                assert_eq!(conditions[1].conditionValue.r#type, FWP_BYTE_ARRAY16_TYPE);
                let address = unsafe { &*conditions[1].conditionValue.Anonymous.byteArray16 };
                assert_eq!(
                    address.byteArray16,
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                );
            }
        }
    }

    fn encoded(path: &str) -> Vec<u8> {
        path.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn app_id_uses_windows_unicode_case_mapping_and_preserves_surrogate_pairs() {
        let original = encoded(concat!(
            r"\DEVICE\HarddiskVolume6\Тест\ПРИЛОЖЕНИЕ_É_应用_🚀.EXE",
            "\0"
        ));
        let expected = encoded(concat!(
            r"\device\harddiskvolume6\тест\приложение_é_应用_🚀.exe",
            "\0"
        ));
        let normalized = downcase_app_id(&original).unwrap();
        assert_eq!(normalized, expected);
        assert_eq!(downcase_app_id(&normalized).unwrap(), expected);
        assert_eq!(normalized.len(), original.len());
        let units: Vec<u16> = normalized
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        assert!(String::from_utf16(&units).unwrap().contains('🚀'));
    }

    #[test]
    fn app_id_case_mapping_accepts_unaligned_wire_bytes() {
        let original = encoded(concat!(r"\Device\Volume\ПРОЦЕСС.exe", "\0"));
        let mut storage = vec![0xaa];
        storage.extend_from_slice(&original);
        assert_eq!(
            downcase_app_id(&storage[1..]).unwrap(),
            encoded(concat!(r"\device\volume\процесс.exe", "\0"))
        );
    }
}

struct PolicyTransaction {
    handle: HANDLE,
    committed: bool,
}

impl PolicyTransaction {
    fn begin(handle: HANDLE) -> Result<Self, NTSTATUS> {
        // SAFETY: The caller owns and serializes this live session.
        check(unsafe { FwpmTransactionBegin0(handle, 0) })?;
        Ok(Self {
            handle,
            committed: false,
        })
    }

    fn commit(mut self) -> Result<(), NTSTATUS> {
        // SAFETY: This guard owns the session's active transaction.
        check(unsafe { FwpmTransactionCommit0(self.handle) })?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for PolicyTransaction {
    fn drop(&mut self) {
        if !self.committed {
            // SAFETY: All fallible policy calls have returned before rollback.
            unsafe {
                FwpmTransactionAbort0(self.handle);
            }
        }
    }
}

struct LoopbackAddresses {
    ipv4: FWP_V4_ADDR_AND_MASK,
    ipv6: FWP_BYTE_ARRAY16,
}

impl LoopbackAddresses {
    fn new() -> Self {
        Self {
            // FWP's IPv4 address/mask values use host byte order.
            ipv4: FWP_V4_ADDR_AND_MASK {
                addr: 0x7f00_0000,
                mask: 0xff00_0000,
            },
            ipv6: FWP_BYTE_ARRAY16 {
                byteArray16: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            },
        }
    }
}

fn policy_conditions(
    blob: &mut FWP_BYTE_BLOB,
    version: FWP_IP_VERSION,
    loopback: &mut LoopbackAddresses,
) -> [FWPM_FILTER_CONDITION0; 2] {
    let mut conditions: [FWPM_FILTER_CONDITION0; 2] = unsafe { mem::zeroed() };
    conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
    conditions[0].conditionValue.Anonymous.byteBlob = blob;
    // IS_LOOPBACK is not sufficient at connection-policy route lookup on the test
    // OS. Exclude destinations explicitly before forcing an external interface.
    conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conditions[1].matchType = FWP_MATCH_NOT_EQUAL;
    if version == FWP_IP_VERSION_V4 {
        conditions[1].conditionValue.r#type = FWP_V4_ADDR_MASK;
        conditions[1].conditionValue.Anonymous.v4AddrMask = &mut loopback.ipv4;
    } else {
        conditions[1].conditionValue.r#type = FWP_BYTE_ARRAY16_TYPE;
        conditions[1].conditionValue.Anonymous.byteArray16 = &mut loopback.ipv6;
    }
    conditions
}

fn add_policy(
    handle: HANDLE,
    key: &GUID,
    version: FWP_IP_VERSION,
    app_id: &[u8],
    mut luid: u64,
) -> Result<(), NTSTATUS> {
    let mut blob = FWP_BYTE_BLOB {
        size: app_id.len() as u32,
        data: app_id.as_ptr().cast_mut(),
    };
    let mut loopback = LoopbackAddresses::new();
    let conditions = policy_conditions(&mut blob, version, &mut loopback);

    let mut setting: FWPM_NETWORK_CONNECTION_POLICY_SETTING0 = unsafe { mem::zeroed() };
    setting.r#type = FWP_NETWORK_CONNECTION_POLICY_NEXT_HOP_INTERFACE;
    setting.value.r#type = FWP_UINT64;
    setting.value.Anonymous.uint64 = &mut luid;
    let mut settings = FWPM_NETWORK_CONNECTION_POLICY_SETTINGS0 {
        numSettings: 1,
        settings: &mut setting,
    };
    let mut context: FWPM_PROVIDER_CONTEXT3 = unsafe { mem::zeroed() };
    context.providerContextKey = *key;
    let mut name = [0u16; 32];
    for (dest, source) in name.iter_mut().zip(b"Portmaster app interface") {
        *dest = *source as u16;
    }
    context.displayData.name = name.as_mut_ptr();
    context.r#type = FWPM_NETWORK_CONNECTION_POLICY_CONTEXT;
    context.Anonymous.networkConnectionPolicy = &mut settings;

    // SAFETY: Every pointed-to value is live through this synchronous call. WFP
    // copies the app ID/settings; it does not retain these Rust stack pointers.
    check(unsafe {
        FwpmConnectionPolicyAdd0(
            handle,
            &context,
            version,
            100,
            conditions.len() as u32,
            conditions.as_ptr(),
            ptr::null_mut(),
        )
    })
}

// These complete structures are passed by pointer to the native kernel API.
#[cfg(target_pointer_width = "64")]
const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<FWPM_PROVIDER_CONTEXT3>() == 88);
    assert!(align_of::<FWPM_PROVIDER_CONTEXT3>() == 8);
    assert!(offset_of!(FWPM_PROVIDER_CONTEXT3, providerContextKey) == 0);
    assert!(offset_of!(FWPM_PROVIDER_CONTEXT3, displayData) == 16);
    assert!(offset_of!(FWPM_PROVIDER_CONTEXT3, r#type) == 64);
    assert!(offset_of!(FWPM_PROVIDER_CONTEXT3, Anonymous) == 72);
    assert!(size_of::<FWPM_NETWORK_CONNECTION_POLICY_SETTING0>() == 24);
    assert!(offset_of!(FWPM_NETWORK_CONNECTION_POLICY_SETTING0, value) == 8);
    assert!(size_of::<FWPM_NETWORK_CONNECTION_POLICY_SETTINGS0>() == 16);
    assert!(offset_of!(FWPM_NETWORK_CONNECTION_POLICY_SETTINGS0, settings) == 8);
};
