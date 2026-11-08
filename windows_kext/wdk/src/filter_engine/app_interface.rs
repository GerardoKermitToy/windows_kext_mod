//! Session-owned WFP interface policies. Only the passive command path touches
//! this state; WFP's built-in callout applies policies without a driver lookup.

use alloc::vec::Vec;
use core::{mem, ptr};
use windows_sys::{
    core::GUID,
    Wdk::System::SystemServices::ExUuidCreate,
    Win32::{
        Foundation::{
            HANDLE, NTSTATUS, STATUS_DEVICE_NOT_READY, STATUS_INSUFFICIENT_RESOURCES,
            STATUS_INVALID_HANDLE,
        },
        NetworkManagement::WindowsFilteringPlatform::{
            FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_FILTER_CONDITION0,
            FWPM_NETWORK_CONNECTION_POLICY_CONTEXT, FWPM_NETWORK_CONNECTION_POLICY_SETTING0,
            FWPM_NETWORK_CONNECTION_POLICY_SETTINGS0, FWPM_PROVIDER_CONTEXT3, FWPM_SESSION0,
            FWPM_SESSION_FLAG_DYNAMIC, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB,
            FWP_BYTE_BLOB_TYPE, FWP_IP_VERSION, FWP_IP_VERSION_V4, FWP_IP_VERSION_V6,
            FWP_MATCH_EQUAL, FWP_MATCH_RANGE, FWP_NETWORK_CONNECTION_POLICY_NEXT_HOP_INTERFACE,
            FWP_RANGE0, FWP_RANGE_TYPE, FWP_UINT32, FWP_UINT64,
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

use super::address_ranges::{AddressRange, AddressRanges};

struct AppPolicy {
    app_id: Vec<u8>,
    luid: u64,
    // One key per disjoint permitted destination interval in each family.
    keys: [Vec<GUID>; 2],
}

pub struct AppInterfacePolicies {
    handle: HANDLE,
    policies: Vec<AppPolicy>,
    addresses: Option<AddressRanges>,
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
            addresses: None,
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

    /// `app_id` is the validated canonical UTF-16LE WFP app ID. LUID zero
    /// removes the policy. All intervals and both families change atomically.
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
        let addresses = self.addresses.as_ref().ok_or(STATUS_DEVICE_NOT_READY)?;
        let new_policy = if existing.is_none() {
            self.policies
                .try_reserve(1)
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            Some(AppPolicy {
                app_id,
                luid,
                keys: [
                    make_keys(&[], addresses.ipv4.len())?,
                    make_keys(&[], addresses.ipv6.len())?,
                ],
            })
        } else {
            None
        };

        self.open()?;
        let transaction = PolicyTransaction::begin(self.handle)?;
        if let Some(index) = existing {
            delete_keys(self.handle, &self.policies[index].keys[0])?;
            delete_keys(self.handle, &self.policies[index].keys[1])?;
        }
        if luid != 0 {
            let policy = existing
                .map(|i| &self.policies[i])
                .unwrap_or_else(|| new_policy.as_ref().unwrap());
            let addresses = self.addresses.as_ref().unwrap();
            add_ranges(
                self.handle,
                policy,
                luid,
                0,
                &policy.keys[0],
                &addresses.ipv4,
            )?;
            add_ranges(
                self.handle,
                policy,
                luid,
                1,
                &policy.keys[1],
                &addresses.ipv6,
            )?;
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

    /// Replace the canonical snapshot and atomically rebuild every affected
    /// policy. If allocation or WFP fails, both the old snapshot and all old
    /// policies remain active. Unchanged address families are left untouched.
    pub fn update_addresses(&mut self, addresses: AddressRanges) -> Result<(), NTSTATUS> {
        let changed = [
            self.addresses
                .as_ref()
                .map_or(true, |old| old.ipv4 != addresses.ipv4),
            self.addresses
                .as_ref()
                .map_or(true, |old| old.ipv6 != addresses.ipv6),
        ];
        if !changed[0] && !changed[1] {
            return Ok(());
        }
        if self.policies.is_empty() {
            self.addresses = Some(addresses);
            return Ok(());
        }

        let lengths = [addresses.ipv4.len(), addresses.ipv6.len()];
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(self.policies.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        for policy in &self.policies {
            replacement.push([
                if changed[0] {
                    Some(make_keys(&policy.keys[0], lengths[0])?)
                } else {
                    None
                },
                if changed[1] {
                    Some(make_keys(&policy.keys[1], lengths[1])?)
                } else {
                    None
                },
            ]);
        }
        let transaction = PolicyTransaction::begin(self.handle)?;
        for (policy, keys) in self.policies.iter().zip(&replacement) {
            for family in 0..2 {
                if let Some(keys) = &keys[family] {
                    delete_keys(self.handle, &policy.keys[family])?;
                    let ranges = if family == 0 {
                        &addresses.ipv4
                    } else {
                        &addresses.ipv6
                    };
                    add_ranges(self.handle, policy, policy.luid, family, keys, ranges)?;
                }
            }
        }
        transaction.commit()?;
        for (policy, keys) in self.policies.iter_mut().zip(replacement) {
            for (family, keys) in keys.into_iter().enumerate() {
                if let Some(keys) = keys {
                    policy.keys[family] = keys;
                }
            }
        }
        self.addresses = Some(addresses);
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
    use super::{downcase_app_id, policy_conditions};
    use alloc::{string::String, vec, vec::Vec};
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_BYTE_BLOB,
        FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL, FWP_MATCH_RANGE, FWP_RANGE0, FWP_RANGE_TYPE,
    };

    #[test]
    fn policy_matches_app_and_one_destination_interval() {
        let mut app_id = encoded(concat!(r"\device\volume\app.exe", "\0"));
        let mut blob = FWP_BYTE_BLOB {
            size: app_id.len() as u32,
            data: app_id.as_mut_ptr(),
        };
        let mut range: FWP_RANGE0 = unsafe { core::mem::zeroed() };
        let conditions = policy_conditions(&mut blob, &mut range);
        let key = |guid: &windows_sys::core::GUID| (guid.data1, guid.data2, guid.data3, guid.data4);
        assert_eq!(
            key(&conditions[0].fieldKey),
            key(&FWPM_CONDITION_ALE_APP_ID)
        );
        assert_eq!(conditions[0].matchType, FWP_MATCH_EQUAL);
        assert_eq!(conditions[0].conditionValue.r#type, FWP_BYTE_BLOB_TYPE);
        assert_eq!(
            key(&conditions[1].fieldKey),
            key(&FWPM_CONDITION_IP_REMOTE_ADDRESS)
        );
        assert_eq!(conditions[1].matchType, FWP_MATCH_RANGE);
        assert_eq!(conditions[1].conditionValue.r#type, FWP_RANGE_TYPE);
        assert_eq!(
            unsafe { conditions[1].conditionValue.Anonymous.rangeValue },
            core::ptr::addr_of_mut!(range)
        );
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

fn make_keys(old: &[GUID], count: usize) -> Result<Vec<GUID>, NTSTATUS> {
    let mut keys = Vec::new();
    keys.try_reserve_exact(count)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    keys.extend_from_slice(&old[..old.len().min(count)]);
    while keys.len() < count {
        let mut key = GUID::from_u128(0);
        // SAFETY: A live GUID output is supplied at PASSIVE_LEVEL.
        check(unsafe { ExUuidCreate(&mut key) })?;
        keys.push(key);
    }
    Ok(keys)
}

fn delete_keys(handle: HANDLE, keys: &[GUID]) -> Result<(), NTSTATUS> {
    for key in keys {
        // SAFETY: Each key belongs to this live dynamic session.
        check(unsafe { FwpmConnectionPolicyDeleteByKey0(handle, key) })?;
    }
    Ok(())
}

fn add_ranges(
    handle: HANDLE,
    policy: &AppPolicy,
    luid: u64,
    family: usize,
    keys: &[GUID],
    ranges: &[AddressRange],
) -> Result<(), NTSTATUS> {
    debug_assert_eq!(keys.len(), ranges.len());
    let version = if family == 0 {
        FWP_IP_VERSION_V4
    } else {
        FWP_IP_VERSION_V6
    };
    for (key, range) in keys.iter().zip(ranges) {
        add_policy(handle, key, version, &policy.app_id, luid, *range)?;
    }
    Ok(())
}

fn policy_conditions(
    blob: &mut FWP_BYTE_BLOB,
    range: &mut FWP_RANGE0,
) -> [FWPM_FILTER_CONDITION0; 2] {
    let mut conditions: [FWPM_FILTER_CONDITION0; 2] = unsafe { mem::zeroed() };
    conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
    conditions[0].conditionValue.Anonymous.byteBlob = blob;
    conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conditions[1].matchType = FWP_MATCH_RANGE;
    conditions[1].conditionValue.r#type = FWP_RANGE_TYPE;
    conditions[1].conditionValue.Anonymous.rangeValue = range;
    conditions
}

fn add_policy(
    handle: HANDLE,
    key: &GUID,
    version: FWP_IP_VERSION,
    app_id: &[u8],
    mut luid: u64,
    interval: AddressRange,
) -> Result<(), NTSTATUS> {
    let mut blob = FWP_BYTE_BLOB {
        size: app_id.len() as u32,
        data: app_id.as_ptr().cast_mut(),
    };
    let mut low6 = FWP_BYTE_ARRAY16 {
        byteArray16: interval.first.to_be_bytes(),
    };
    let mut high6 = FWP_BYTE_ARRAY16 {
        byteArray16: interval.last.to_be_bytes(),
    };
    let mut range: FWP_RANGE0 = unsafe { mem::zeroed() };
    if version == FWP_IP_VERSION_V4 {
        range.valueLow.r#type = FWP_UINT32;
        range.valueHigh.r#type = FWP_UINT32;
        range.valueLow.Anonymous.uint32 = interval.first as u32;
        range.valueHigh.Anonymous.uint32 = interval.last as u32;
    } else {
        range.valueLow.r#type = FWP_BYTE_ARRAY16_TYPE;
        range.valueHigh.r#type = FWP_BYTE_ARRAY16_TYPE;
        range.valueLow.Anonymous.byteArray16 = &mut low6;
        range.valueHigh.Anonymous.byteArray16 = &mut high6;
    }
    let conditions = policy_conditions(&mut blob, &mut range);
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
    // SAFETY: The app ID, interval and settings all remain live through this
    // synchronous call; WFP copies them before returning.
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
