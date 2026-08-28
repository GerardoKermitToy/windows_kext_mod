use alloc::string::{String, ToString};
use ntstatus::ntstatus::NtStatus;
use windows_sys::{
    Wdk::System::SystemServices::KeDelayExecutionThread, Win32::Foundation::STATUS_SUCCESS,
};

use crate::ffi;

pub fn check_ntstatus(status: i32) -> Result<(), String> {
    if status == STATUS_SUCCESS {
        return Ok(());
    }

    let Some(status) = NtStatus::from_u32(status as u32) else {
        return Err("UNKNOWN_ERROR_CODE".to_string());
    };

    return Err(status.to_string());
}

pub fn get_system_timestamp_ms() -> u64 {
    // 100 nano seconds units -> device by 10 -> micro seconds -> divide by 1000 -> milliseconds
    unsafe { ffi::pm_QuerySystemTime() / 10_000 }
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
/// application is such a path; receiving is not - inbound processing runs in an
/// arbitrary or DPC context, where the answer is whichever thread happened to be
/// interrupted.
///
/// Safe at IRQL <= DISPATCH_LEVEL.
pub fn current_process_id() -> u64 {
    unsafe { ffi::PsGetCurrentProcessId() as u64 }
}
