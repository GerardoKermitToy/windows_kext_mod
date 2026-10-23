use alloc::string::{String, ToString};
use likely_stable::likely;
use ntstatus::ntstatus::NtStatus;
use windows_sys::{
    Wdk::System::SystemServices::{
        KeDelayExecutionThread, KeGetCurrentIrql, KeQueryInterruptTimePrecise, PASSIVE_LEVEL,
    },
    Win32::Foundation::NTSTATUS,
};

use crate::ffi;

/// Checks a kernel NTSTATUS, including fwpmk.h and Fwps* results.
/// User-mode Win32/DWORD errors use a different success contract.
pub fn check_ntstatus(status: NTSTATUS) -> Result<(), String> {
    // Match the native NT_SUCCESS macro: informational and warning-free positive
    // statuses are successful too, not only STATUS_SUCCESS (zero).
    if likely(status >= 0) {
        return Ok(());
    }

    let Some(status_name) = NtStatus::from_u32(status as u32) else {
        return Err(alloc::format!("NTSTATUS({:#010x})", status as u32));
    };

    Err(status_name.to_string())
}

pub fn is_passive_level() -> bool {
    unsafe { KeGetCurrentIrql() == PASSIVE_LEVEL as u8 }
}

///
/// `KeQueryInterruptTimePrecise` is based on interrupt time rather than system
/// time. It is not changed when the wall clock is adjusted and it includes time
/// spent in low-power states, which makes it suitable for connection and cache
/// expiry deadlines. The returned value is measured from system boot and is
/// safe to query at any IRQL at which the driver runs.
///
/// The timestamp is one-based because connection state reserves zero to mean
/// that no end time has been recorded.
pub fn get_monotonic_timestamp_ms() -> u64 {
    let mut qpc_timestamp = 0;
    (unsafe { KeQueryInterruptTimePrecise(&mut qpc_timestamp) } / 10_000).saturating_add(1)
}

/// Delays the current kernel thread by a relative interval.
///
/// The caller must run at IRQL <= APC_LEVEL; driver unload runs at PASSIVE_LEVEL.
pub fn sleep_ms(milliseconds: u64) {
    let ticks = milliseconds.saturating_mul(10_000).min(i64::MAX as u64) as i64;
    let interval = -ticks;
    unsafe {
        let _ = KeDelayExecutionThread(0, 0, &interval);
    }
}

/// Process ID of the thread context this code is running in.
///
/// This is the *current thread's* process, not a property of any packet or
/// connection, so it only identifies an originator where the caller knows the
/// work is being done synchronously on the originating thread. Sending from an
/// application is such a path. The same is true when a user-space packet tool
/// synchronously asks its driver to inject an outbound packet. Receiving is not -
/// inbound processing runs in an arbitrary or DPC context, where the answer is
/// whichever thread happened to be interrupted.
///
/// Safe at IRQL <= DISPATCH_LEVEL.
pub fn current_process_id() -> u64 {
    unsafe { ffi::PsGetCurrentProcessId() as u64 }
}

/// ID of the currently executing thread, not a WFP flow handle.
/// Safe at IRQL <= DISPATCH_LEVEL.
pub fn current_thread_id() -> u64 {
    unsafe { ffi::PsGetCurrentThreadId() as u64 }
}

#[cfg(test)]
mod tests {
    use super::check_ntstatus;
    use windows_sys::Win32::Foundation::NTSTATUS;

    #[test]
    fn nt_success_accepts_zero_pending_and_informational_statuses() {
        for status in [0, 1, 0x0000_0103, 0x4000_0000] {
            assert!(check_ntstatus(status).is_ok(), "{status:#010x}");
        }
    }

    #[test]
    fn nt_success_uses_the_sign_bit_not_zero_equality() {
        assert!(check_ntstatus(i32::MAX).is_ok());
        assert!(check_ntstatus(i32::MIN).is_err());
    }

    #[test]
    fn kernel_access_and_parameter_errors_remain_errors() {
        for status in [0xc000_0022u32, 0xc000_000d] {
            assert!(check_ntstatus(status as NTSTATUS).is_err(), "{status:#010x}");
        }
    }

    #[test]
    fn kernel_rpc_and_wfp_errors_remain_errors() {
        for status in [0xc002_0017u32, 0xc002_001b, 0xc022_0001, 0xc022_000a] {
            assert!(check_ntstatus(status as NTSTATUS).is_err(), "{status:#010x}");
        }
    }

    #[test]
    fn warning_statuses_are_not_nt_success() {
        assert!(check_ntstatus(0x8000_0005u32 as NTSTATUS).is_err());
    }

    #[test]
    fn unknown_error_preserves_all_native_status_bits() {
        assert_eq!(
            check_ntstatus(0xe123_4567u32 as NTSTATUS).unwrap_err(),
            "NTSTATUS(0xe1234567)"
        );
    }
}
