//! Event-driven local unicast address inventory. The notification callback only
//! signals a resident event; a single sleeping PASSIVE_LEVEL thread coalesces
//! bursts and performs snapshots / WFP transactions outside the callback.

use crate::device::Device;
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    mem, ptr,
    sync::atomic::{AtomicBool, Ordering},
};
use wdk::{filter_engine::address_ranges::AddressRanges, passive_mutex::PassiveMutex};
use windows_sys::{
    Wdk::{
        Foundation::{KEVENT, OBJECT_ATTRIBUTES},
        System::SystemServices::{
            Executive, KeInitializeEvent, KeSetEvent, KeWaitForSingleObject,
            PsTerminateSystemThread,
        },
    },
    Win32::{
        Foundation::{
            HANDLE, NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_DEVICE_STATE,
            STATUS_NOT_FOUND, STATUS_SUCCESS,
        },
        NetworkManagement::IpHelper::{MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE},
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC},
        System::Kernel::SynchronizationEvent,
    },
};

// The windows-sys IP Helper imports target the user-mode DLL; kernel-mode
// builds must import these exact NTSTATUS-returning symbols from netio.lib.
extern "system" {
    fn NotifyUnicastIpAddressChange(
        family: u16,
        callback: Option<
            unsafe extern "system" fn(*const c_void, *const MIB_UNICASTIPADDRESS_ROW, i32),
        >,
        context: *const c_void,
        initial: u8,
        handle: *mut HANDLE,
    ) -> NTSTATUS;
    fn CancelMibChangeNotify2(handle: HANDLE) -> NTSTATUS;
    fn GetUnicastIpAddressTable(
        family: u16,
        table: *mut *mut MIB_UNICASTIPADDRESS_TABLE,
    ) -> NTSTATUS;
    fn FreeMibTable(table: *const c_void);
    fn PsCreateSystemThread(
        handle: *mut HANDLE,
        access: u32,
        attributes: *const OBJECT_ATTRIBUTES,
        process: HANDLE,
        client_id: *mut c_void,
        start: Option<unsafe extern "system" fn(*mut c_void)>,
        context: *mut c_void,
    ) -> NTSTATUS;
    fn ZwWaitForSingleObject(handle: HANDLE, alertable: u8, timeout: *const i64) -> NTSTATUS;
    fn ZwClose(handle: HANDLE) -> NTSTATUS;
}

struct Handles {
    notification: HANDLE,
    thread: HANDLE,
}
// Handles are opaque kernel values; all lifecycle access is under the mutex.
unsafe impl Send for Handles {}

pub(crate) struct AddressMonitor {
    // Nonpaged and pinned: callbacks and the worker use only the kernel event APIs.
    event: Box<UnsafeCell<KEVENT>>,
    stopping: AtomicBool,
    handles: PassiveMutex<Handles>,
}
unsafe impl Send for AddressMonitor {}
unsafe impl Sync for AddressMonitor {}

impl AddressMonitor {
    pub(crate) fn new() -> Result<Self, String> {
        let event = Box::new(UnsafeCell::new(unsafe { mem::zeroed() }));
        // SAFETY: This nonpaged dispatcher object is initialized at its final address.
        unsafe { KeInitializeEvent(event.get(), SynchronizationEvent, false) };
        Ok(Self {
            event,
            stopping: AtomicBool::new(false),
            handles: PassiveMutex::new(Handles {
                notification: ptr::null_mut(),
                thread: ptr::null_mut(),
            })
            .map_err(|err| format!("address monitor lock: {}", err))?,
        })
    }

    /// Called after Device publication and before user I/O is enabled.
    pub(crate) fn start(&self, device: &Device) -> Result<(), NTSTATUS> {
        let mut handles = self
            .handles
            .lock()
            .map_err(|_| STATUS_INVALID_DEVICE_STATE)?;
        let mut notification = ptr::null_mut();
        // Subscribe before the baseline snapshot. Any concurrent address change
        // sets the auto-reset event, which stays signaled until the worker starts.
        let status = unsafe {
            NotifyUnicastIpAddressChange(
                AF_UNSPEC,
                Some(address_changed),
                self.event.get().cast(),
                0,
                &mut notification,
            )
        };
        if status < 0 {
            return Err(status);
        }
        if notification.is_null() {
            return Err(STATUS_INVALID_DEVICE_STATE);
        }
        handles.notification = notification;
        if let Err(status) = device.refresh_local_addresses() {
            drop(handles);
            self.stop();
            return Err(status);
        }
        let mut attributes: OBJECT_ATTRIBUTES = unsafe { mem::zeroed() };
        attributes.Length = mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
        attributes.Attributes = 0x0000_0200; // OBJ_KERNEL_HANDLE
        let mut thread = ptr::null_mut();
        // SAFETY: Device is already pinned in its published Box. stop() joins
        // the kernel thread before Device or its fields can be freed.
        let status = unsafe {
            PsCreateSystemThread(
                &mut thread,
                0x001f_03ff,
                &attributes,
                ptr::null_mut(),
                ptr::null_mut(),
                Some(worker),
                (device as *const Device).cast_mut().cast(),
            )
        };
        if status < 0 {
            drop(handles);
            self.stop();
            return Err(status);
        }
        handles.thread = thread;
        Ok(())
    }

    /// Cancellation waits for notification callbacks, so hold no lock used by
    /// a callback or the worker while calling it or joining the worker.
    pub(crate) fn stop(&self) {
        let Ok(mut handles) = self.handles.lock() else {
            return;
        };
        self.stopping.store(true, Ordering::Release);
        while !handles.notification.is_null() {
            let status = unsafe { CancelMibChangeNotify2(handles.notification) };
            if status >= 0 {
                handles.notification = ptr::null_mut();
            } else {
                crate::err!(
                    "failed to cancel IP notifications: NTSTATUS({:#010x})",
                    status as u32
                );
                wdk::utils::sleep_ms(100);
            }
        }
        unsafe {
            KeSetEvent(self.event.get(), 0, false);
        }
        while !handles.thread.is_null() {
            let status = unsafe { ZwWaitForSingleObject(handles.thread, 0, ptr::null()) };
            if status >= 0 {
                unsafe {
                    ZwClose(handles.thread);
                }
                handles.thread = ptr::null_mut();
            } else {
                crate::err!(
                    "failed to join IP monitor: NTSTATUS({:#010x})",
                    status as u32
                );
                wdk::utils::sleep_ms(100);
            }
        }
    }
}

impl Drop for AddressMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

unsafe extern "system" fn address_changed(
    context: *const c_void,
    _row: *const MIB_UNICASTIPADDRESS_ROW,
    _kind: i32,
) {
    // SAFETY: Cancellation drains callbacks before the resident event is freed.
    unsafe {
        KeSetEvent(context.cast_mut().cast(), 0, false);
    }
}

unsafe extern "system" fn worker(context: *mut c_void) {
    // SAFETY: start() pins Device; stop() joins us before reclaiming it.
    let device = unsafe { &*context.cast::<Device>() };
    let monitor = &device.address_monitor;
    let mut retry_ms = 0i64;
    loop {
        let timeout = -retry_ms * 10_000;
        unsafe {
            KeWaitForSingleObject(
                monitor.event.get().cast(),
                Executive,
                0,
                false,
                if retry_ms == 0 { ptr::null() } else { &timeout },
            )
        };
        if monitor.stopping.load(Ordering::Acquire) {
            break;
        }
        match device.refresh_local_addresses() {
            Ok(()) => retry_ms = 0,
            Err(status) => {
                crate::err!(
                    "failed to refresh local IP policies: NTSTATUS({:#010x})",
                    status as u32
                );
                retry_ms = if retry_ms == 0 {
                    1000
                } else {
                    (retry_ms * 2).min(30_000)
                };
            }
        }
    }
    unsafe {
        PsTerminateSystemThread(STATUS_SUCCESS);
    }
}

struct Table(*mut MIB_UNICASTIPADDRESS_TABLE);
impl Drop for Table {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { FreeMibTable(self.0.cast()) }
        }
    }
}

pub(crate) fn local_address_ranges() -> Result<AddressRanges, NTSTATUS> {
    let mut table = Table(ptr::null_mut());
    let status = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table.0) };
    if status == STATUS_NOT_FOUND {
        return AddressRanges::new(&[], &[]);
    }
    if status < 0 {
        return Err(status);
    }
    if table.0.is_null() {
        return Err(STATUS_INVALID_DEVICE_STATE);
    }
    // Use the table field's actual offset and ROW stride, including any WDK padding.
    let count = unsafe { (*table.0).NumEntries as usize };
    let first = unsafe { ptr::addr_of!((*table.0).Table).cast::<MIB_UNICASTIPADDRESS_ROW>() };
    // windows-sys models the native BOOLEAN SkipAsSource field as Rust bool.
    // Keep each row as a raw pointer so an arbitrary nonzero native byte cannot
    // create an invalid Rust bool when forming a reference to the whole row.
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    ipv4.try_reserve(count)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    ipv6.try_reserve(count)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    for index in 0..count {
        // SAFETY: GetUnicastIpAddressTable returned count contiguous rows and
        // the allocation remains live until Table is dropped. Read only the
        // address union; do not materialize a reference to the enclosing row.
        let address = unsafe { ptr::addr_of!((*first.add(index)).Address) };
        let family = unsafe { ptr::addr_of!((*address).si_family).read() };
        if family == AF_INET {
            // SOCKADDR stores network bytes; WFP's UINT32 uses host order.
            let value = unsafe { ptr::addr_of!((*address).Ipv4.sin_addr.S_un.S_addr).read() };
            ipv4.push(u32::from_be(value));
        } else if family == AF_INET6 {
            let value = unsafe { ptr::addr_of!((*address).Ipv6.sin6_addr.u.Byte).read() };
            ipv6.push(value);
        }
    }
    AddressRanges::new(&ipv4, &ipv6)
}
