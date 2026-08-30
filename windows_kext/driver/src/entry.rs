use crate::common::ControlCode;
use crate::device;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use num_traits::FromPrimitive;
use wdk::irp_helpers::{
    CleanupRequest, CloseRequest, CreateRequest, DeviceControlRequest, ReadRequest, WriteRequest,
};
use wdk::{err, info, interface, rw_spin_lock::RwSpinLock};
use windows_sys::Wdk::Foundation::{DEVICE_OBJECT, DRIVER_OBJECT, IRP};
use windows_sys::Win32::Foundation::{
    NTSTATUS, STATUS_DEVICE_NOT_READY, STATUS_SHARING_VIOLATION, STATUS_SUCCESS,
};

static VERSION: [u8; 4] = include!("../../kextinterface/version.txt");

/// Global device pointer.
///
/// We use `AtomicPtr` to ensure thread safety.
/// - **Safety**: Prevents data races and acts as a compiler barrier against dangerous optimizations
///   (e.g., load hoisting), ensuring concurrent callouts see a valid, up-to-date pointer.
/// - **Performance**: Negligible overhead. On x64, `Acquire` is free (same as a normal load).
///   On ARM64, it uses efficient hardware-supported load-acquire instructions.
static DEVICE: AtomicPtr<device::Device> = AtomicPtr::new(core::ptr::null_mut());

/// Serializes user-mode dispatch routines with driver teardown.
///
/// The control device is a singleton and the driver accepts only one file object,
/// so a lightweight gate is sufficient. A dispatch increments the active count
/// only while unload is not closing the gate. Unload drains ordinary dispatches,
/// runs the existing shutdown path to wake blocked reads, and then waits for those
/// reads before destroying the WDFDEVICE-backed Device allocation.
struct DispatchGate {
    /// Serializes the short admission/closure transition. It is held only
    /// while counters and admission flags are updated; readers never wait for
    /// Device work while holding it.
    admission_lock: RwSpinLock<()>,
    unloading: AtomicBool,
    active: core::sync::atomic::AtomicU32,
    non_read: core::sync::atomic::AtomicU32,
    reads_closed: AtomicBool,
    reads: core::sync::atomic::AtomicU32,
    session_busy: AtomicBool,
}

impl DispatchGate {
    const fn new() -> Self {
        Self {
            admission_lock: RwSpinLock::new(()),
            unloading: AtomicBool::new(false),
            active: core::sync::atomic::AtomicU32::new(0),
            non_read: core::sync::atomic::AtomicU32::new(0),
            reads_closed: AtomicBool::new(false),
            reads: core::sync::atomic::AtomicU32::new(0),
            session_busy: AtomicBool::new(false),
        }
    }

    /// Reopens the gate for a new driver instance. The gate is static because
    /// dispatch routines may outlive the stack frame of DriverEntry, so it must
    /// be explicitly reset after a previous unload before a service restart.
    fn reopen(&self) {
        let _admission_guard = self.acquire_admission();
        debug_assert_eq!(self.active.load(Ordering::Acquire), 0);
        debug_assert_eq!(self.non_read.load(Ordering::Acquire), 0);
        debug_assert_eq!(self.reads.load(Ordering::Acquire), 0);
        debug_assert!(!self.session_busy.load(Ordering::Acquire));
        self.reads_closed.store(false, Ordering::Release);
        self.unloading.store(false, Ordering::Release);
    }

    fn enter(&self, is_read: bool) -> Option<DispatchGuard<'_>> {
        // Admission and closure use the same short lock. This makes the
        // counter a reliable snapshot for cleanup: a read that observed an open
        // gate is counted before cleanup can close it.
        let _admission_guard = self.acquire_admission();
        if self.unloading.load(Ordering::Acquire)
            || (is_read && self.reads_closed.load(Ordering::Acquire))
        {
            return None;
        }

        self.active.fetch_add(1, Ordering::AcqRel);
        if is_read {
            self.reads.fetch_add(1, Ordering::AcqRel);
        } else {
            self.non_read.fetch_add(1, Ordering::AcqRel);
        }

        Some(DispatchGuard {
            gate: self,
            is_read,
        })
    }

    /// Acquires the short admission lock used to serialize dispatch entry with
    /// cleanup and unload closure. The lock is never held during Device work.
    fn acquire_admission(&self) -> wdk::rw_spin_lock::RwLockWriteGuard<'_, ()> {
        self.admission_lock.write_lock()
    }

    /// Closes admission for all new dispatches.
    fn close(&self) {
        let _admission_guard = self.acquire_admission();
        self.reads_closed.store(true, Ordering::Release);
        self.unloading.store(true, Ordering::Release);
    }

    /// Waits until no ordinary dispatch can mutate Device.
    ///
    /// Reads are deliberately excluded here: a read may be blocked in the
    /// cancellable queue wait and must be released before the final all-dispatch
    /// drain below.
    fn wait_for_non_read(&self) {
        while self.non_read.load(Ordering::Acquire) != 0 {
            wdk::utils::sleep_ms(1);
        }
    }

    /// Returns whether the driver is closing admission for unload.
    fn is_unloading(&self) -> bool {
        let _admission_guard = self.acquire_admission();
        self.unloading.load(Ordering::Acquire)
    }

    /// Prevents a new read from racing session cancellation/reset.
    fn close_reads(&self) {
        let _admission_guard = self.acquire_admission();
        self.reads_closed.store(true, Ordering::Release);
    }

    /// Allows reads for the newly accepted file object.
    fn open_reads(&self) {
        let _admission_guard = self.acquire_admission();
        self.reads_closed.store(false, Ordering::Release);
    }

    fn wait_for_reads(&self) {
        while self.reads.load(Ordering::Acquire) != 0 {
            wdk::utils::sleep_ms(1);
        }
    }

    /// Serializes CREATE/CLEANUP session transitions. These routines run at
    /// PASSIVE_LEVEL, so sleeping is preferable to holding a spin lock while
    /// another dispatch routine drains the active readers.
    fn acquire_session(&self) -> SessionGuard<'_> {
        while self
            .session_busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            wdk::utils::sleep_ms(1);
        }

        SessionGuard { gate: self }
    }

    fn wait_for_all(&self) {
        while self.active.load(Ordering::Acquire) != 0 {
            wdk::utils::sleep_ms(1);
        }
    }
}

struct DispatchGuard<'a> {
    gate: &'a DispatchGate,
    is_read: bool,
}

impl Drop for DispatchGuard<'_> {
    fn drop(&mut self) {
        if self.is_read {
            self.gate.reads.fetch_sub(1, Ordering::AcqRel);
        } else {
            self.gate.non_read.fetch_sub(1, Ordering::AcqRel);
        }
        self.gate.active.fetch_sub(1, Ordering::AcqRel);
    }
}

struct SessionGuard<'a> {
    gate: &'a DispatchGate,
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        self.gate.session_busy.store(false, Ordering::Release);
    }
}

static DISPATCH_GATE: DispatchGate = DispatchGate::new();

/// Loads the published Device pointer.
///
/// This is only a publication/load operation; it does not keep the allocation
/// alive. WFP classify callers must hold the callback barrier guard acquired by
/// the common trampoline, and user-mode dispatch callers must hold a
/// DispatchGate guard, for the entire duration of their Device access. Unload
/// closes both admission paths and waits for their guards before swapping and
/// dropping the pointer.
pub fn get_device() -> Option<&'static device::Device> {
    // Acquire pairs with the Release store in driver_entry and the AcqRel swap in driver_unload.
    unsafe { DEVICE.load(Ordering::Acquire).as_ref() }
}

// DriverEntry is the entry point of the driver (main function). Will be called when driver is loaded.
// Name should not be changed
#[export_name = "DriverEntry"]
pub extern "system" fn driver_entry(
    driver_object: *mut windows_sys::Wdk::Foundation::DRIVER_OBJECT,
    registry_path: *mut windows_sys::Win32::Foundation::UNICODE_STRING,
) -> windows_sys::Win32::Foundation::NTSTATUS {
    info!("Starting initialization...");
    if !wdk::callback_barrier::CALLBACK_BARRIER.start() {
        err!("driver_entry: callback barrier is still in use");
        return windows_sys::Win32::Foundation::STATUS_FAILED_DRIVER_ENTRY;
    }
    DISPATCH_GATE.reopen();

    // Initialize driver object.
    let mut driver = match interface::init_driver_object(
        driver_object,
        registry_path,
        "PortmasterKext",
        core::ptr::null_mut(),
    ) {
        Ok(driver) => driver,
        Err(status) => {
            // No WFP callbacks should remain admitted if initialization aborts
            // before the DriverUnload pointer is installed.
            wdk::callback_barrier::CALLBACK_BARRIER.close_all_and_wait();
            err!("driver_entry: failed to initialize driver: {}", status);
            return windows_sys::Win32::Foundation::STATUS_FAILED_DRIVER_ENTRY;
        }
    };

    // Set driver functions.
    driver.set_driver_unload(Some(driver_unload));
    driver.set_create_fn(Some(driver_create));
    driver.set_cleanup_fn(Some(driver_cleanup));
    driver.set_close_fn(Some(driver_close));
    driver.set_read_fn(Some(driver_read));
    driver.set_write_fn(Some(driver_write));
    driver.set_device_control_fn(Some(device_control));

    // Initialize device.
    let device = match device::Device::new(&driver) {
        Ok(device) => Box::new(device),
        Err(err) => {
            // Device::new may have registered WFP callbacks before a later
            // initialization step failed.  Close admission even on this error
            // path so no callback can outlive the temporary FilterEngine state.
            wdk::callback_barrier::CALLBACK_BARRIER.close_all_and_wait();
            wdk::err!("filed to initialize device: {}", err);
            return -1;
        }
    };
    // Release: makes the fully-constructed Device visible to all cores that subsequently
    // perform an Acquire load.
    DEVICE.store(Box::into_raw(device), Ordering::Release);

    STATUS_SUCCESS
}

// driver_unload function is called when service delete is called from user-space.
unsafe extern "system" fn driver_unload(_object: *const DRIVER_OBJECT) {
    info!("Unloading driver");

    // Close user-mode dispatch and WFP classify admission before touching
    // Device.  The classify barrier is closed first, but flow-delete admission
    // remains open while prepare_unload asks WFP to remove the contexts that
    // invoke flowDeleteFn.
    DISPATCH_GATE.close();
    wdk::callback_barrier::CALLBACK_BARRIER.close_classify_and_wait();

    // Signal the queue before waiting for non-read dispatches. CLEANUP itself
    // can be one of those dispatches and may be waiting for an admitted read;
    // delaying cancellation until after that wait would deadlock unload.
    if let Some(device) = get_device() {
        device.cancel_read_waiters();
    }
    DISPATCH_GATE.wait_for_non_read();
    // The cancellation flag is already set. Drain admitted reads before any
    // Device teardown so no user dispatch can touch the object while its WFP
    // state or queue is being reclaimed.
    DISPATCH_GATE.wait_for_reads();

    if let Some(device) = get_device() {
        // Stop new flow callbacks and drain contexts while the event queue and
        // the rest of Device are still usable.  Flow-delete callbacks are the
        // only WFP callbacks still admitted in this phase and are counted by
        // the second half of the common callback barrier.
        device.prepare_unload();

        // No flow context or callback may remain before any Device field is
        // reclaimed.  This also closes the defensive late-callback path before
        // FilterEngine/Injector teardown starts.
        wdk::callback_barrier::CALLBACK_BARRIER.close_all_and_wait();
        device.shutdown();
        DISPATCH_GATE.wait_for_all();
    } else {
        wdk::callback_barrier::CALLBACK_BARRIER.close_all_and_wait();
        DISPATCH_GATE.wait_for_all();
    }

    // Null the global pointer only after every user dispatch and WFP callback
    // has drained.  FilterEngine::drop then unregisters callouts and deletes
    // WFP state while the callback barrier rejects any late callback before it
    // can inspect a Callout or Device pointer.
    let ptr = DEVICE.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr));
        }
    }
}

/// driver_create is triggered when user-space opens a handle to the device (CreateFile).
unsafe extern "system" fn driver_create(
    _device_object: *const DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    let mut create_request = CreateRequest::new(irp.as_mut().unwrap());
    let Some(_dispatch_guard) = DISPATCH_GATE.enter(false) else {
        return create_request.fail(STATUS_DEVICE_NOT_READY);
    };
    let Some(device) = get_device() else {
        return create_request.fail(STATUS_DEVICE_NOT_READY);
    };
    let _session_guard = DISPATCH_GATE.acquire_session();

    if DISPATCH_GATE.is_unloading() {
        return create_request.fail(STATUS_DEVICE_NOT_READY);
    }

    let pid = create_request.get_requestor_pid();
    let file_object = create_request.get_file_object();
    if file_object.is_null()
        || device
            .owner_file_object
            .compare_exchange(
                core::ptr::null_mut(),
                file_object,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
    {
        crate::warn!("Rejecting additional device open from PID {}", pid);
        return create_request.fail(STATUS_SHARING_VIOLATION);
    }

    device.owner_pid.store(pid, Ordering::Release);
    // A previous owner may have canceled the shared read wait. Reset it only
    // after the new file object owns the session, then reopen read admission.
    device.reset_read_cancellation();
    DISPATCH_GATE.open_reads();
    info!("Device opened by PID {}", pid);
    create_request.complete()
}

/// driver_cleanup is triggered when user-space closes the last handle to the device.
unsafe extern "system" fn driver_cleanup(
    _device_object: *const DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    let mut cleanup_request = CleanupRequest::new(irp.as_mut().unwrap());
    let Some(_dispatch_guard) = DISPATCH_GATE.enter(false) else {
        return cleanup_request.complete();
    };
    let Some(device) = get_device() else {
        return cleanup_request.complete();
    };

    {
        let _session_guard = DISPATCH_GATE.acquire_session();
        let file_object = cleanup_request.get_file_object();
        if !file_object.is_null() && device.owner_file_object.load(Ordering::Acquire) == file_object
        {
            // Stop new reads before signaling the wait. Reads that passed the
            // admission check are counted by DispatchGate and are drained below.
            DISPATCH_GATE.close_reads();
            device.cancel_read_waiters();
            DISPATCH_GATE.wait_for_reads();

            // Keep the owner pointer published until every old read has left;
            // this prevents a replacement CREATE from resetting the event too
            // early. The session gate serializes this transition with CREATE.
            if device
                .owner_file_object
                .compare_exchange(
                    file_object,
                    core::ptr::null_mut(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                let old_pid = device.owner_pid.swap(0, Ordering::AcqRel);
                info!("Device closed by PID {}", old_pid);
            }
        }
    }

    cleanup_request.complete()
}

/// IRP_MJ_CLOSE is a separate lifetime phase from CLEANUP. Complete it through
/// the driver's own dispatch table so a late file-object deletion never falls
/// back into KMDF after the WDFDEVICE has begun teardown.
unsafe extern "system" fn driver_close(
    _device_object: *const DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    let mut close_request = CloseRequest::new(irp.as_mut().unwrap());
    let _dispatch_guard = DISPATCH_GATE.enter(false);
    close_request.complete()
}

// driver_read event triggered from user-space on file.Read.
unsafe extern "system" fn driver_read(
    _device_object: *const DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    let mut read_request = ReadRequest::new(irp.as_mut().unwrap());
    let Some(_dispatch_guard) = DISPATCH_GATE.enter(true) else {
        return read_request.end_of_file();
    };
    let Some(device) = get_device() else {
        return read_request.complete();
    };

    device.read(&mut read_request)
}

/// driver_write event triggered from user-space on file.Write.
unsafe extern "system" fn driver_write(
    _device_object: *const DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    let mut write_request = WriteRequest::new(irp.as_mut().unwrap());
    let Some(_dispatch_guard) = DISPATCH_GATE.enter(false) else {
        return write_request.complete();
    };
    let Some(device) = get_device() else {
        return write_request.complete();
    };

    device.write(&mut write_request);

    write_request.mark_all_as_read();
    write_request.complete()
}

/// device_control event triggered from user-space on file.deviceIOControl.
unsafe extern "system" fn device_control(
    _device_object: *const DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    let mut control_request = DeviceControlRequest::new(irp.as_mut().unwrap());
    let Some(_dispatch_guard) = DISPATCH_GATE.enter(false) else {
        return control_request.not_implemented();
    };
    let Some(device) = get_device() else {
        return control_request.complete();
    };

    let Some(control_code): Option<ControlCode> =
        FromPrimitive::from_u32(control_request.get_control_code())
    else {
        wdk::info!("Unknown IOCTL code: {}", control_request.get_control_code());
        return control_request.not_implemented();
    };

    wdk::info!("IOCTL: {}", control_code);

    match control_code {
        ControlCode::Version => {
            control_request.write(&VERSION);
        }
        ControlCode::ShutdownRequest => device.shutdown(),
    };

    control_request.complete()
}
