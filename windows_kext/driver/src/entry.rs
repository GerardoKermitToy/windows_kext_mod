use crate::common::ControlCode;
use crate::device;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use num_traits::FromPrimitive;
use wdk::irp_helpers::{
    CleanupRequest, CloseRequest, CreateRequest, DeviceControlRequest, ReadRequest, WriteRequest,
};
use wdk::{err, info, interface};
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
    unloading: AtomicBool,
    active: core::sync::atomic::AtomicU32,
    non_read: core::sync::atomic::AtomicU32,
}

impl DispatchGate {
    const fn new() -> Self {
        Self {
            unloading: AtomicBool::new(false),
            active: core::sync::atomic::AtomicU32::new(0),
            non_read: core::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Reopens the gate for a new driver instance. The gate is static because
    /// dispatch routines may outlive the stack frame of DriverEntry, so it must
    /// be explicitly reset after a previous unload before a service restart.
    fn reopen(&self) {
        debug_assert_eq!(self.active.load(Ordering::Acquire), 0);
        debug_assert_eq!(self.non_read.load(Ordering::Acquire), 0);
        self.unloading.store(false, Ordering::Release);
    }

    fn enter(&self, is_read: bool) -> Option<DispatchGuard<'_>> {
        if self.unloading.load(Ordering::Acquire) {
            return None;
        }

        self.active.fetch_add(1, Ordering::AcqRel);
        if !is_read {
            self.non_read.fetch_add(1, Ordering::AcqRel);
        }
        if self.unloading.load(Ordering::Acquire) {
            if !is_read {
                self.non_read.fetch_sub(1, Ordering::AcqRel);
            }
            self.active.fetch_sub(1, Ordering::AcqRel);
            return None;
        }

        Some(DispatchGuard {
            gate: self,
            is_read,
        })
    }

    /// Closes admission and waits until no ordinary dispatch can mutate Device.
    /// A read may remain blocked in KeRemoveQueue; `Device::shutdown` wakes it.
    fn close_and_wait_non_read(&self) {
        self.unloading.store(true, Ordering::Release);
        while self.non_read.load(Ordering::Acquire) != 0 {
            wdk::utils::sleep_ms(1);
        }
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
        if !self.is_read {
            self.gate.non_read.fetch_sub(1, Ordering::AcqRel);
        }
        self.gate.active.fetch_sub(1, Ordering::AcqRel);
    }
}

static DISPATCH_GATE: DispatchGate = DispatchGate::new();

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

    // Stop new user-mode dispatches first. A read may remain blocked in
    // KeRemoveQueue, but ordinary writes/cleanup/create handlers must be out of
    // the way before any Device-owned teardown begins.
    DISPATCH_GATE.close_and_wait_non_read();

    if let Some(device) = get_device() {
        // Stop new flow callbacks and drain contexts while the event queue and
        // the rest of Device are still usable. Callbacks that arrive after this
        // point only reclaim their opaque WFP allocation.
        device.prepare_unload();

        // Wake a read blocked in KeRemoveQueue. The read guard then drops, and we
        // can wait for every user dispatch before destroying the WDFDEVICE-backed
        // Device allocation.
        device.shutdown();
        DISPATCH_GATE.wait_for_all();
    } else {
        DISPATCH_GATE.wait_for_all();
    }

    // Null the global pointer only after every user dispatch and flow context has
    // drained. FilterEngine::drop then unregisters callouts and deletes WFP state
    // while no routine can still access Device.
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
        create_request.fail(STATUS_DEVICE_NOT_READY);
        return create_request.get_status();
    };
    let Some(device) = get_device() else {
        create_request.fail(STATUS_DEVICE_NOT_READY);
        return create_request.get_status();
    };

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
        create_request.fail(STATUS_SHARING_VIOLATION);
        return create_request.get_status();
    }

    device.owner_pid.store(pid, Ordering::Release);
    info!("Device opened by PID {}", pid);
    create_request.complete();
    create_request.get_status()
}

/// driver_cleanup is triggered when user-space closes the last handle to the device.
unsafe extern "system" fn driver_cleanup(
    _device_object: *const DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    let mut cleanup_request = CleanupRequest::new(irp.as_mut().unwrap());
    let Some(_dispatch_guard) = DISPATCH_GATE.enter(false) else {
        cleanup_request.complete();
        return cleanup_request.get_status();
    };
    if let Some(device) = get_device() {
        let file_object = cleanup_request.get_file_object();
        if !file_object.is_null()
            && device
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
    cleanup_request.complete();
    cleanup_request.get_status()
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
    close_request.complete();
    close_request.get_status()
}

// driver_read event triggered from user-space on file.Read.
unsafe extern "system" fn driver_read(
    _device_object: *const DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    let mut read_request = ReadRequest::new(irp.as_mut().unwrap());
    let Some(_dispatch_guard) = DISPATCH_GATE.enter(true) else {
        read_request.end_of_file();
        return read_request.get_status();
    };
    let Some(device) = get_device() else {
        read_request.complete();

        return read_request.get_status();
    };

    device.read(&mut read_request);
    read_request.get_status()
}

/// driver_write event triggered from user-space on file.Write.
unsafe extern "system" fn driver_write(
    _device_object: *const DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    let mut write_request = WriteRequest::new(irp.as_mut().unwrap());
    let Some(_dispatch_guard) = DISPATCH_GATE.enter(false) else {
        write_request.complete();
        return write_request.get_status();
    };
    let Some(device) = get_device() else {
        write_request.complete();
        return write_request.get_status();
    };

    device.write(&mut write_request);

    write_request.mark_all_as_read();
    write_request.complete();
    write_request.get_status()
}

/// device_control event triggered from user-space on file.deviceIOControl.
unsafe extern "system" fn device_control(
    _device_object: *const DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    let mut control_request = DeviceControlRequest::new(irp.as_mut().unwrap());
    let Some(_dispatch_guard) = DISPATCH_GATE.enter(false) else {
        control_request.not_implemented();
        return control_request.get_status();
    };
    let Some(device) = get_device() else {
        control_request.complete();
        return control_request.get_status();
    };

    let Some(control_code): Option<ControlCode> =
        FromPrimitive::from_u32(control_request.get_control_code())
    else {
        wdk::info!("Unknown IOCTL code: {}", control_request.get_control_code());
        control_request.not_implemented();
        return control_request.get_status();
    };

    wdk::info!("IOCTL: {}", control_code);

    match control_code {
        ControlCode::Version => {
            control_request.write(&VERSION);
        }
        ControlCode::ShutdownRequest => device.shutdown(),
    };

    control_request.complete();
    control_request.get_status()
}
