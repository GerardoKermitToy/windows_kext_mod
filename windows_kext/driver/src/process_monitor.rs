//! Session-owned process notification registration and initial inventory.

use alloc::{format, string::String, vec::Vec};
use core::ffi::c_void;
use protocol::info::{process_created_info, process_terminated_info};
use wdk::passive_mutex::PassiveMutex;
use windows_sys::{
    Wdk::{
        Foundation::PEPROCESS,
        Storage::FileSystem::PsLookupProcessByProcessId,
        System::SystemServices::{
            ObfDereferenceObject, PsCreateProcessNotifySubsystems, PsGetProcessExitStatus,
            PsSetCreateProcessNotifyRoutineEx2, PS_CREATE_NOTIFY_INFO,
        },
    },
    Win32::Foundation::{
        HANDLE, NTSTATUS, STATUS_BUFFER_TOO_SMALL, STATUS_DEVICE_NOT_READY,
        STATUS_INFO_LENGTH_MISMATCH, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_DEVICE_STATE,
        STATUS_INVALID_PARAMETER, STATUS_PENDING,
    },
};

use crate::{
    event_queue::EventQueue,
    process_snapshot::{parse_system_processes, ProcessChange, ProcessSnapshot},
};

const BATCH_SIZE: usize = 256;

struct State {
    snapshot: ProcessSnapshot,
    session: u64,
}

struct Lifecycle {
    registered: bool,
    shutdown: bool,
}

pub(crate) struct ProcessMonitor {
    // Registration/removal may wait for callbacks, so callbacks take only state.
    lifecycle: PassiveMutex<Lifecycle>,
    state: PassiveMutex<State>,
}

impl ProcessMonitor {
    pub(crate) fn new() -> Result<Self, String> {
        Ok(Self {
            lifecycle: PassiveMutex::new(Lifecycle {
                registered: false,
                shutdown: false,
            })
            .map_err(|err| format!("process lifecycle lock: {}", err))?,
            state: PassiveMutex::new(State {
                snapshot: ProcessSnapshot::new(),
                session: 0,
            })
            .map_err(|err| format!("process snapshot lock: {}", err))?,
        })
    }

    /// Starts only on an explicit IOCTL/write command. A repeated request drains
    /// the old callback and rebuilds the inventory, but keeps already queued
    /// records (and any partially read frame) in the same device-open session.
    pub(crate) fn restart(&self, queue: &EventQueue) -> Result<(), NTSTATUS> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| STATUS_INVALID_DEVICE_STATE)?;
        if lifecycle.shutdown {
            return Err(STATUS_DEVICE_NOT_READY);
        }
        self.stop_locked(queue, &mut lifecycle, false);
        {
            let mut state = self.state.lock().map_err(|_| STATUS_INVALID_DEVICE_STATE)?;
            if state.session == 0 {
                state.session = queue.begin_process_session();
            }
            state.snapshot.begin();
        }

        // SAFETY: The callback lives in the loaded driver image and resolves only
        // the published Device. stop() unregisters and drains it before reclamation.
        let status = set_process_notification(false);
        if status < 0 {
            self.clear(queue, false)?;
            return Err(status);
        }
        lifecycle.registered = true;

        // Do not hold state during the system query: callbacks must be able to
        // journal exits/creations while the snapshot buffer is being assembled.
        let result = enumerate_processes().and_then(|processes| {
            let mut state = self.state.lock().map_err(|_| STATUS_INVALID_DEVICE_STATE)?;
            let (baseline, changes) = state
                .snapshot
                .finish(processes)
                .ok_or(STATUS_INVALID_DEVICE_STATE)?;
            for chunk in baseline.chunks(BATCH_SIZE) {
                queue
                    .push_process(process_created_info(chunk.iter().copied()), state.session)
                    .map_err(|_| STATUS_DEVICE_NOT_READY)?;
            }
            publish_changes(queue, state.session, &changes)
        });
        if let Err(status) = result {
            // A failed request must not leave a registered callback or a partial
            // inventory. Previously queued records remain readable in this session.
            // Never unregister under state.
            self.stop_locked(queue, &mut lifecycle, false);
            return Err(status);
        }
        Ok(())
    }

    /// Serializes with restart(), but never holds the callback's state lock while
    /// Windows waits for in-flight process notifications to return.
    pub(crate) fn stop(&self, queue: &EventQueue, shutdown: bool) -> Result<(), NTSTATUS> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| STATUS_INVALID_DEVICE_STATE)?;
        lifecycle.shutdown |= shutdown;
        self.stop_locked(queue, &mut lifecycle, true);
        Ok(())
    }

    fn stop_locked(&self, queue: &EventQueue, lifecycle: &mut Lifecycle, end_session: bool) {
        while lifecycle.registered {
            // SAFETY: Same callback that restart() registered. Remove=TRUE also
            // waits for every invocation, keeping Device alive through the drain.
            let status = set_process_notification(true);
            if status >= 0 {
                lifecycle.registered = false;
            } else {
                crate::err!(
                    "failed to unregister process notifications: NTSTATUS({:#010x})",
                    status as u32
                );
                wdk::utils::sleep_ms(1);
            }
        }
        while let Err(status) = self.clear(queue, end_session) {
            crate::err!(
                "failed to clear process snapshot: NTSTATUS({:#010x})",
                status as u32
            );
            wdk::utils::sleep_ms(1);
        }
    }

    fn clear(&self, queue: &EventQueue, end_session: bool) -> Result<(), NTSTATUS> {
        let mut state = self.state.lock().map_err(|_| STATUS_INVALID_DEVICE_STATE)?;
        state.snapshot.clear();
        if end_session {
            state.session = 0;
            queue.end_process_session();
        }
        Ok(())
    }

    fn record(&self, queue: &EventQueue, change: ProcessChange) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(status) => {
                crate::err!("failed to lock process snapshot: {}", status);
                return;
            }
        };
        if let Some(change) = state.snapshot.record(change) {
            if let Err(status) = publish_changes(queue, state.session, &[change]) {
                crate::err!(
                    "failed to publish process event: NTSTATUS({:#010x})",
                    status as u32
                );
            }
        }
    }
}

fn publish_changes(
    queue: &EventQueue,
    session: u64,
    mut changes: &[ProcessChange],
) -> Result<(), NTSTATUS> {
    while let Some(first) = changes.first() {
        let created = matches!(first, ProcessChange::Created { .. });
        let count = changes
            .iter()
            .take(BATCH_SIZE)
            .take_while(|change| matches!(change, ProcessChange::Created { .. }) == created)
            .count();
        let batch = &changes[..count];
        let info = if created {
            process_created_info(batch.iter().map(|change| match change {
                ProcessChange::Created { pid, parent_pid } => (*pid, *parent_pid),
                ProcessChange::Terminated { .. } => unreachable!(),
            }))
        } else {
            process_terminated_info(batch.iter().map(|change| match change {
                ProcessChange::Terminated { pid } => *pid,
                ProcessChange::Created { .. } => unreachable!(),
            }))
        };
        queue
            .push_process(info, session)
            .map_err(|_| STATUS_DEVICE_NOT_READY)?;
        changes = &changes[count..];
    }
    Ok(())
}

fn set_process_notification(remove: bool) -> NTSTATUS {
    // SAFETY: Ex2 takes the same static callback address for registration/removal.
    // Subsystem notifications include non-Win32 processes as well. This API is
    // available on the supported Windows 10 1703+/Windows 11 kernel.
    unsafe {
        PsSetCreateProcessNotifyRoutineEx2(
            PsCreateProcessNotifySubsystems,
            process_notify as *const () as *const c_void,
            u8::from(remove),
        )
    }
}

unsafe extern "system" fn process_notify(
    _process: PEPROCESS,
    process_id: HANDLE,
    create_info: *mut PS_CREATE_NOTIFY_INFO,
) {
    // Registration is owned by Device's accepted session. Its cleanup/unload
    // unregisters (and waits for us) before the published allocation is removed.
    let Some(device) = crate::entry::get_device() else {
        return;
    };
    let pid = process_id as usize as u64;
    // SAFETY: Windows supplies a live PS_CREATE_NOTIFY_INFO only for creation;
    // on exit the pointer is null. No borrowed OS data escapes this callback.
    let change = match unsafe { create_info.as_ref() } {
        Some(info) if info.CreationStatus >= 0 => ProcessChange::Created {
            pid,
            parent_pid: info.ParentProcessId as usize as u64,
        },
        Some(_) => return,
        None => ProcessChange::Terminated { pid },
    };
    device.process_monitor.record(&device.event_queue, change);
}

fn enumerate_processes() -> Result<Vec<(u64, u64)>, NTSTATUS> {
    const SYSTEM_PROCESS_INFORMATION: i32 = 5;
    const MAX_BUFFER: usize = 64 * 1024 * 1024;
    let mut size = 64 * 1024usize;
    // Process creation can outgrow ReturnLength between queries. Retry with
    // headroom, but fail the open rather than expose a silently partial snapshot.
    for _ in 0..16 {
        if size > MAX_BUFFER {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let words = size.div_ceil(core::mem::size_of::<u64>());
        let mut buffer = Vec::<u64>::new();
        buffer
            .try_reserve_exact(words)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        buffer.resize(words, 0);
        let byte_len = buffer.len() * core::mem::size_of::<u64>();
        let mut returned = 0u32;
        // SAFETY: Vec<u64> gives the query its required 8-byte alignment. The
        // writable, initialized buffer and ReturnLength outlive the kernel call.
        let status = unsafe {
            wdk::ffi::ZwQuerySystemInformation(
                SYSTEM_PROCESS_INFORMATION,
                buffer.as_mut_ptr().cast::<c_void>(),
                byte_len as u32,
                &mut returned,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL {
            size = (returned as usize).max(byte_len * 2);
            continue;
        }
        if status < 0 {
            return Err(status);
        }
        if returned == 0 || returned as usize > byte_len {
            return Err(STATUS_INVALID_PARAMETER);
        }
        // SAFETY: All bytes are initialized and returned is bounded by byte_len;
        // the borrow ends before the owning vector is dropped.
        let bytes =
            unsafe { core::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), returned as usize) };
        let mut processes = parse_system_processes(bytes).map_err(|_| STATUS_INVALID_PARAMETER)?;
        // A terminated process object may still have external references. Keep
        // only live entries, using temporary references, never retained objects.
        processes.retain(|&(pid, _)| process_is_live(pid));
        return Ok(processes);
    }
    Err(STATUS_INFO_LENGTH_MISMATCH)
}

fn process_is_live(pid: u64) -> bool {
    if pid == 0 {
        return true; // The idle process has no ordinary lookup handle.
    }
    let mut process: PEPROCESS = 0;
    // SAFETY: Output receives one referenced process on success; no access to
    // image paths or user memory is required, including for protected processes.
    if unsafe { PsLookupProcessByProcessId(pid as usize as HANDLE, &mut process) } < 0 {
        return false;
    }
    // SAFETY: The successful lookup owns this reference through both calls.
    let live = unsafe { PsGetProcessExitStatus(process) } == STATUS_PENDING;
    unsafe {
        ObfDereferenceObject(process as *const c_void);
    }
    live
}
