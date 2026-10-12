use core::sync::atomic::{AtomicBool, Ordering};
use windows_sys::Win32::System::Registry::REG_DWORD;

static INBOUND_UDP_PID_FALLBACK_ENABLED: AtomicBool = AtomicBool::new(false);
static IGNORE_SPECIAL_PORTS: AtomicBool = AtomicBool::new(false);

/// The value is read once during DriverEntry and stays fixed until driver unload.
#[inline]
pub(crate) fn inbound_udp_pid_fallback_enabled() -> bool {
    INBOUND_UDP_PID_FALLBACK_ENABLED.load(Ordering::Relaxed)
}

/// The value is read once during DriverEntry and stays fixed until driver unload.
#[inline]
pub(crate) fn ignore_special_ports() -> bool {
    IGNORE_SPECIAL_PORTS.load(Ordering::Relaxed)
}

fn dword_enabled(value_type: u32, data: &[u8]) -> bool {
    value_type == REG_DWORD && data == 1u32.to_le_bytes()
}

#[cfg(not(test))]
pub(crate) use kernel::initialize;

#[cfg(not(test))]
mod kernel {
    use super::{dword_enabled, IGNORE_SPECIAL_PORTS, INBOUND_UDP_PID_FALLBACK_ENABLED};
    use alloc::vec::Vec;
    use core::{mem::size_of, ptr, sync::atomic::Ordering};
    use windows_sys::{
        Wdk::{
            Foundation::OBJECT_ATTRIBUTES,
            System::{
                Registry::{KeyValuePartialInformation, ZwOpenKey, ZwQueryValueKey},
                SystemServices::ZwClose,
            },
        },
        Win32::{
            Foundation::{
                NTSTATUS, STATUS_INVALID_DEVICE_STATE, STATUS_INVALID_PARAMETER, UNICODE_STRING,
            },
            System::{
                Kernel::{OBJ_CASE_INSENSITIVE, OBJ_KERNEL_HANDLE},
                Registry::KEY_QUERY_VALUE,
            },
        },
    };

    // KEY_VALUE_PARTIAL_INFORMATION with room for exactly one DWORD.
    #[repr(C)]
    struct DwordValueInformation {
        title_index: u32,
        value_type: u32,
        data_length: u32,
        data: [u8; 4],
    }

    const _: () = assert!(size_of::<DwordValueInformation>() == 16);

    fn unicode_string(buffer: &[u16]) -> UNICODE_STRING {
        let length = u16::try_from(buffer.len() * 2).expect("registry string is too long");
        UNICODE_STRING {
            Length: length,
            MaximumLength: length,
            // The WDK input APIs do not mutate this buffer despite PWSTR's type.
            Buffer: buffer.as_ptr() as *mut u16,
        }
    }

    /// Reads the settings once before WFP is activated. Missing/inaccessible keys
    /// and invalid values leave the options disabled. No registry handle or
    /// subscription is retained after this call.
    ///
    /// # Safety
    ///
    /// Must be called once from DriverEntry at PASSIVE_LEVEL with its live
    /// registry path, before any packet classification can read the setting.
    pub(crate) unsafe fn initialize(registry_path: *const UNICODE_STRING) -> Result<(), NTSTATUS> {
        if !wdk::utils::is_passive_level() {
            return Err(STATUS_INVALID_DEVICE_STATE);
        }
        let path = unsafe { registry_path.as_ref() }.ok_or(STATUS_INVALID_PARAMETER)?;
        if path.Length == 0
            || path.Length % 2 != 0
            || path.Length > path.MaximumLength
            || path.Buffer.is_null()
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let suffix: Vec<u16> = "\\Parameters".encode_utf16().collect();
        if usize::from(path.Length) + suffix.len() * 2 > usize::from(u16::MAX) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut parameters_path = unsafe {
            core::slice::from_raw_parts(path.Buffer, usize::from(path.Length) / 2).to_vec()
        };
        parameters_path.extend_from_slice(&suffix);

        let enabled = read_enabled(&parameters_path, "EnableInboundUdpCacheMissPidFallback");
        INBOUND_UDP_PID_FALLBACK_ENABLED.store(enabled, Ordering::Relaxed);
        crate::info!("EnableInboundUdpCacheMissPidFallback={}", u8::from(enabled));
        let ignore_special_ports = read_enabled(&parameters_path, "IgnoreSpecialPorts");
        IGNORE_SPECIAL_PORTS.store(ignore_special_ports, Ordering::Relaxed);
        crate::info!("IgnoreSpecialPorts={}", u8::from(ignore_special_ports));
        Ok(())
    }

    fn read_enabled(parameters_path: &[u16], value_name: &str) -> bool {
        let path = unicode_string(parameters_path);
        let value_name_buffer: Vec<u16> = value_name.encode_utf16().collect();
        let value_name = unicode_string(&value_name_buffer);
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: ptr::null_mut(),
            ObjectName: &path,
            Attributes: (OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE) as u32,
            SecurityDescriptor: ptr::null(),
            SecurityQualityOfService: ptr::null(),
        };
        let mut key = ptr::null_mut();
        let status = unsafe { ZwOpenKey(&mut key, KEY_QUERY_VALUE, &attributes) };
        if status < 0 {
            return false;
        }
        let mut information = DwordValueInformation {
            title_index: 0,
            value_type: 0,
            data_length: 0,
            data: [0; 4],
        };
        let mut result_length = 0;
        let status = unsafe {
            ZwQueryValueKey(
                key,
                &value_name,
                KeyValuePartialInformation,
                ptr::from_mut(&mut information).cast(),
                size_of::<DwordValueInformation>() as u32,
                &mut result_length,
            )
        };
        unsafe { ZwClose(key) };
        status >= 0
            && result_length == size_of::<DwordValueInformation>() as u32
            && information.data_length == 4
            && dword_enabled(information.value_type, &information.data)
    }
}

#[cfg(test)]
mod tests {
    use super::dword_enabled;
    use windows_sys::Win32::System::Registry::{
        REG_BINARY, REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_QWORD, REG_SZ,
    };

    #[test]
    fn settings_default_to_disabled() {
        assert!(!super::inbound_udp_pid_fallback_enabled());
        assert!(!super::ignore_special_ports());
    }

    #[test]
    fn only_dword_one_enables_settings() {
        assert!(dword_enabled(REG_DWORD, &1u32.to_le_bytes()));
        for value in [0, 2, 0x100, u32::MAX] {
            assert!(!dword_enabled(REG_DWORD, &value.to_le_bytes()));
        }
    }

    #[test]
    fn wrong_registry_types_do_not_enable_settings() {
        for value_type in [REG_BINARY, REG_DWORD_BIG_ENDIAN, REG_QWORD, REG_SZ] {
            assert!(!dword_enabled(value_type, &1u32.to_le_bytes()));
        }
    }

    #[test]
    fn malformed_dword_lengths_do_not_enable_settings() {
        for data in [
            &[][..],
            &[1][..],
            &[1, 0, 0][..],
            &[1, 0, 0, 0, 0][..],
            &[1, 0, 0, 0, 0, 0, 0, 0][..],
        ] {
            assert!(!dword_enabled(REG_DWORD, data));
        }
    }
}
