use windows_sys::{
    Wdk::Foundation::DRIVER_OBJECT,
    Win32::Foundation::{NTSTATUS, UNICODE_STRING},
};

// A regular Rust function could use SSE4.2 before checking the CPU when that
// feature is enabled globally. Keep the entire gate in baseline x64 assembly
// and enter Rust initialization only through the successful tail call.
macro_rules! sse42_entry {
    ($(#[$attribute:meta])* $name:ident, $cpuid:literal, $initialize:path) => {
        $(#[$attribute])*
        #[unsafe(naked)]
        unsafe extern "system" fn $name(
            _driver_object: *mut DRIVER_OBJECT,
            _registry_path: *mut UNICODE_STRING,
        ) -> NTSTATUS {
            core::arch::naked_asm!(
                ".seh_proc {function}",
                "push rbx",
                ".seh_pushreg rbx",
                ".seh_endprologue",
                "mov r8, rcx",
                "mov r9, rdx",
                "mov eax, 1",
                "xor ecx, ecx",
                $cpuid,
                "test ecx, {sse42_bit}",
                "jz 2f",
                "mov rcx, r8",
                "mov rdx, r9",
                "pop rbx",
                "jmp {initialize}",
                "2:",
                "mov eax, {not_supported}",
                "pop rbx",
                "ret",
                ".seh_endproc",
                function = sym $name,
                sse42_bit = const 1 << 20,
                not_supported = const windows_sys::Win32::Foundation::STATUS_NOT_SUPPORTED as u32,
                initialize = sym $initialize,
            );
        }
    };
}

#[cfg(not(test))]
sse42_entry!(
    #[export_name = "DriverEntry"]
    driver_entry,
    "cpuid",
    crate::entry::driver_entry
);

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::{
        STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED, STATUS_SUCCESS,
    };

    const DRIVER_OBJECT_ADDRESS: usize = 0x1234_5000;
    const REGISTRY_PATH_ADDRESS: usize = 0x9876_5000;

    unsafe extern "system" fn initialize(
        driver_object: *mut DRIVER_OBJECT,
        registry_path: *mut UNICODE_STRING,
    ) -> NTSTATUS {
        if driver_object as usize != DRIVER_OBJECT_ADDRESS
            || registry_path as usize != REGISTRY_PATH_ADDRESS
        {
            return STATUS_INVALID_PARAMETER;
        }
        STATUS_SUCCESS
    }

    // Replace only CPUID's outputs; exercise the same gate and epilogues as the
    // real entry without requiring a machine that lacks SSE4.2. Clobber every
    // CPUID output register so argument forwarding is covered as well.
    sse42_entry!(
        without_sse42,
        "mov eax, -1\nmov ebx, -1\nmov ecx, 0xffefffff\nmov edx, -1",
        initialize
    );
    sse42_entry!(
        with_sse42,
        "mov eax, -1\nmov ebx, -1\nmov ecx, 0x00100000\nmov edx, -1",
        initialize
    );

    #[test]
    fn missing_sse42_rejects_initialization() {
        // SAFETY: The test initializer compares addresses without dereferencing
        // either pointer, and the rejected entry must not call it at all.
        let status = unsafe {
            without_sse42(
                DRIVER_OBJECT_ADDRESS as *mut DRIVER_OBJECT,
                REGISTRY_PATH_ADDRESS as *mut UNICODE_STRING,
            )
        };
        assert_eq!(status, STATUS_NOT_SUPPORTED);
    }

    #[test]
    fn sse42_preserves_initialization_arguments() {
        // SAFETY: The test initializer never dereferences the sentinel pointers.
        let status = unsafe {
            with_sse42(
                DRIVER_OBJECT_ADDRESS as *mut DRIVER_OBJECT,
                REGISTRY_PATH_ADDRESS as *mut UNICODE_STRING,
            )
        };
        assert_eq!(status, STATUS_SUCCESS);
    }

    #[test]
    fn sse42_preserves_initialization_failure() {
        // SAFETY: The test initializer never dereferences these null pointers.
        let status = unsafe { with_sse42(core::ptr::null_mut(), core::ptr::null_mut()) };
        assert_eq!(status, STATUS_INVALID_PARAMETER);
    }
}
