use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
};
use core::{
    ffi::c_void,
    sync::atomic::{AtomicPtr, Ordering},
};
use windows_sys::Win32::{
    Foundation::{BOOLEAN, INVALID_HANDLE_VALUE, STATUS_SUCCESS},
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SCOPE_ID, SCOPE_ID_0},
    System::Kernel::{COMPARTMENT_ID, UNSPECIFIED_COMPARTMENT_ID},
};

use crate::{
    ffi::{
        FwpsInjectNetworkReceiveAsync0, FwpsInjectNetworkSendAsync0,
        FwpsInjectTransportReceiveAsync0, FwpsInjectTransportSendAsync1,
        FwpsInjectionHandleCreate0, FwpsInjectionHandleDestroy0, FwpsQueryPacketInjectionState0,
        FWPS_INJECTION_TYPE_NETWORK, FWPS_INJECTION_TYPE_TRANSPORT, FWPS_PACKET_INJECTION_STATE,
        FWPS_TRANSPORT_SEND_PARAMS1, NET_BUFFER_LIST,
    },
    utils::check_ntstatus,
};

use super::{callout_data::CalloutData, net_buffer::NetBufferList};

pub struct TransportPacketList {
    ipv6: bool,
    pub net_buffer_list: NetBufferList,
    event_data_offset: usize,
    remote_ip: [u8; 16],
    endpoint_handle: u64,
    remote_scope_id: SCOPE_ID,
    // Owned copy of the WFP control data. The original WFP pointer is only
    // valid during the ALE classify callback; the bytes are copied here so they outlive it.
    control_data: Option<Box<[u8]>>,
    inbound: bool,
    compartment_id: COMPARTMENT_ID,
    interface_index: u32,
    sub_interface_index: u32,
    // send_params and remote_ip must outlive inject_packet_list_transport
    // because FwpsInjectTransportSendAsync1 may read them after the function returns.
    // Storing send_params here ensures it lives on the heap inside Box<TransportPacketList>
    // until the WFP completion callback (free_transport_packet) drops it.
    send_params: FWPS_TRANSPORT_SEND_PARAMS1,
}

// The list is moved from classify to the verdict path and then reclaimed by a
// potentially different CPU in the WFP injection completion callback. All raw
// pointers either target fields in the same pinned Box or native NBL state whose
// ownership moves with this value.
unsafe impl Send for TransportPacketList {}

#[derive(Clone, Copy)]
pub struct InjectInfo {
    pub ipv6: bool,
    pub inbound: bool,
    pub loopback: bool,
    pub interface_index: u32,
    pub sub_interface_index: u32,
}

impl TransportPacketList {
    /// Packet bytes exposed to user space. Inbound ALE clones start at the IP
    /// header for reinjection, but connection events are transport-layer records.
    pub fn get_event_data(&self) -> Option<&[u8]> {
        self.net_buffer_list
            .get_data()?
            .get(self.event_data_offset..)
    }
}

pub struct Injector {
    transport_inject_handle: AtomicPtr<c_void>,
    packet_inject_handle_v4: AtomicPtr<c_void>,
    packet_inject_handle_v6: AtomicPtr<c_void>,
}

// Injection handles are atomically published and are destroyed only after both
// callback and dispatch admission have drained. The atomics make the handle
// storage safe to access through `&Device` during the final teardown phase.

// TODO: Implement custom allocator for the packet buffers for reusing memory and reducing allocations. This should improve latency.
impl Injector {
    pub fn new() -> Result<Self, String> {
        // Commit each output only after WFP reports success and returns a usable
        // handle. A failed native call owns the contents of its output parameter;
        // leaving that value in `self` would make Drop attempt to destroy an
        // uninitialized or otherwise invalid handle.
        let injector = Self {
            transport_inject_handle: AtomicPtr::new(INVALID_HANDLE_VALUE),
            packet_inject_handle_v4: AtomicPtr::new(INVALID_HANDLE_VALUE),
            packet_inject_handle_v6: AtomicPtr::new(INVALID_HANDLE_VALUE),
        };

        unsafe {
            let mut handle = INVALID_HANDLE_VALUE;
            let status = FwpsInjectionHandleCreate0(
                AF_UNSPEC,
                FWPS_INJECTION_TYPE_TRANSPORT,
                &mut handle,
            );
            check_ntstatus(status)
                .map_err(|err| format!("failed to create transport injection handle: {}", err))?;
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err("WFP returned an invalid transport injection handle".to_string());
            }
            injector
                .transport_inject_handle
                .store(handle, Ordering::Release);

            handle = INVALID_HANDLE_VALUE;
            let status = FwpsInjectionHandleCreate0(
                AF_INET,
                FWPS_INJECTION_TYPE_NETWORK,
                &mut handle,
            );
            check_ntstatus(status)
                .map_err(|err| format!("failed to create IPv4 injection handle: {}", err))?;
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err("WFP returned an invalid IPv4 injection handle".to_string());
            }
            injector
                .packet_inject_handle_v4
                .store(handle, Ordering::Release);

            handle = INVALID_HANDLE_VALUE;
            let status = FwpsInjectionHandleCreate0(
                AF_INET6,
                FWPS_INJECTION_TYPE_NETWORK,
                &mut handle,
            );
            check_ntstatus(status)
                .map_err(|err| format!("failed to create IPv6 injection handle: {}", err))?;
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err("WFP returned an invalid IPv6 injection handle".to_string());
            }
            injector
                .packet_inject_handle_v6
                .store(handle, Ordering::Release);
        }

        Ok(injector)
    }

    /// Destroys every injection handle owned by this object.
    ///
    /// WFP waits for pending injections before returning from each destroy call.
    /// A handle is cleared only after the API reports `STATUS_SUCCESS`, so a
    /// caller can retry a failed teardown without losing track of a possibly
    /// live handle. This method must run at PASSIVE_LEVEL.
    pub fn destroy(&self) -> Result<(), String> {
        if !crate::utils::is_passive_level() {
            return Err("WFP injection handles must be destroyed at PASSIVE_LEVEL".to_string());
        }

        fn destroy_one(handle: &AtomicPtr<c_void>, name: &str) -> Result<(), String> {
            let value = handle.load(Ordering::Acquire);
            if value == INVALID_HANDLE_VALUE || value.is_null() {
                return Ok(());
            }

            let status = unsafe { FwpsInjectionHandleDestroy0(value) };
            if status == STATUS_SUCCESS {
                handle.store(INVALID_HANDLE_VALUE, Ordering::Release);
                return Ok(());
            }

            Err(format!(
                "failed to destroy {} injection handle: NTSTATUS({:#010x})",
                name, status as u32
            ))
        }

        let mut first_error = None;
        for (handle, name) in [
            (&self.transport_inject_handle, "transport"),
            (&self.packet_inject_handle_v4, "IPv4 network"),
            (&self.packet_inject_handle_v6, "IPv6 network"),
        ] {
            if let Err(err) = destroy_one(handle, name) {
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
        }

        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Creates the packet list used to replay an ALE indication.
    pub fn from_ale_callout(
        ipv6: bool,
        callout_data: &CalloutData,
        net_buffer_list: NetBufferList,
        event_data_offset: usize,
        remote_ip_slice: &[u8],
        inbound: bool,
        interface_index: u32,
        sub_interface_index: u32,
    ) -> Result<TransportPacketList, String> {
        let control_data = callout_data
            .get_control_data()
            .map(|cd| cd.to_vec().into_boxed_slice());

        let address_length = if ipv6 { 16 } else { 4 };
        if remote_ip_slice.len() != address_length {
            return Err("invalid remote address length".to_string());
        }
        let mut remote_ip = [0; 16];
        remote_ip[..address_length].copy_from_slice(remote_ip_slice);

        let remote_scope_id = callout_data
            .get_remote_scope_id()
            .unwrap_or(SCOPE_ID {
                Anonymous: SCOPE_ID_0 { Value: 0 },
            });
        let send_params = FWPS_TRANSPORT_SEND_PARAMS1 {
            remote_address: core::ptr::null(),
            remote_scope_id,
            control_data: core::ptr::null_mut(),
            control_data_length: 0,
            header_include_header: core::ptr::null_mut(),
            header_include_header_length: 0,
        };

        Ok(TransportPacketList {
            ipv6,
            net_buffer_list,
            event_data_offset,
            remote_ip,
            endpoint_handle: callout_data.get_transport_endpoint_handle().unwrap_or(0),
            remote_scope_id,
            control_data,
            inbound,
            compartment_id: callout_data
                .get_compartment_id()
                .map(|id| id as COMPARTMENT_ID)
                .unwrap_or(UNSPECIFIED_COMPARTMENT_ID),
            interface_index,
            sub_interface_index,
            // Pointers are populated after this object has a stable Box address.
            send_params,
        })
    }

    // TODO: pick a better name. This is not transport
    pub fn inject_packet_list_transport(
        &self,
        packet_list: TransportPacketList,
    ) -> Result<(), String> {
        let transport_inject_handle = self
            .transport_inject_handle
            .load(Ordering::Acquire);
        if transport_inject_handle == INVALID_HANDLE_VALUE || transport_inject_handle.is_null() {
            return Err("failed to inject packet: invalid handle value".to_string());
        }
        // Box the entire packet_list so that remote_ip and send_params
        // are heap-allocated. Their addresses remain stable until free_transport_packet
        // drops the Box after WFP calls the completion callback.
        let mut boxed = Box::new(packet_list);
        let raw_nbl = boxed.net_buffer_list.nbl;

        unsafe {
            // Populate send_params with pointers into the boxed struct.
            // These addresses are stable because the Box will not move until freed.
            let mut control_data_length = 0;
            let control_data: *mut c_void = match &boxed.control_data {
                Some(cd) => {
                    control_data_length = cd.len();
                    cd.as_ptr() as *mut c_void
                }
                None => core::ptr::null_mut(),
            };
            boxed.send_params = FWPS_TRANSPORT_SEND_PARAMS1 {
                remote_address: boxed.remote_ip.as_ptr(),
                remote_scope_id: boxed.remote_scope_id,
                control_data,
                control_data_length: control_data_length as u32,
                header_include_header: core::ptr::null_mut(),
                header_include_header_length: 0,
            };

            let address_family = if boxed.ipv6 { AF_INET6 } else { AF_INET };
            let raw_ptr = Box::into_raw(boxed);

            // Inject. Context is *mut TransportPacketList; freed by free_transport_packet.
            let status = if (*raw_ptr).inbound {
                FwpsInjectTransportReceiveAsync0(
                    transport_inject_handle,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    0,
                    address_family,
                    (*raw_ptr).compartment_id,
                    (*raw_ptr).interface_index,
                    (*raw_ptr).sub_interface_index,
                    raw_nbl,
                    free_transport_packet,
                    raw_ptr as _,
                )
            } else {
                FwpsInjectTransportSendAsync1(
                    transport_inject_handle,
                    core::ptr::null_mut(),
                    (*raw_ptr).endpoint_handle,
                    0,
                    &mut (*raw_ptr).send_params,
                    address_family,
                    (*raw_ptr).compartment_id,
                    raw_nbl,
                    free_transport_packet,
                    raw_ptr as _,
                )
            };
            // Check for success
            if let Err(err) = check_ntstatus(status) {
                _ = Box::from_raw(raw_ptr);
                return Err(err);
            }
        }

        return Ok(());
    }

    pub fn inject_net_buffer_list(
        &self,
        net_buffer_list: NetBufferList,
        inject_info: InjectInfo,
    ) -> Result<(), String> {
        let inject_handle = if inject_info.ipv6 {
            self.packet_inject_handle_v6.load(Ordering::Acquire)
        } else {
            self.packet_inject_handle_v4.load(Ordering::Acquire)
        };
        if inject_handle == INVALID_HANDLE_VALUE || inject_handle.is_null() {
            return Err("failed to inject packet: invalid handle value".to_string());
        }

        // Escape the stack, so the data can be freed after inject is complete.
        let packet_boxed = Box::new(net_buffer_list);
        let nbl = packet_boxed.nbl;
        let packet_pointer = Box::into_raw(packet_boxed);

        let status = if inject_info.inbound && !inject_info.loopback {
            // Inject inbound.
            unsafe {
                FwpsInjectNetworkReceiveAsync0(
                    inject_handle,
                    core::ptr::null_mut(),
                    0,
                    UNSPECIFIED_COMPARTMENT_ID,
                    inject_info.interface_index,
                    inject_info.sub_interface_index,
                    nbl,
                    free_packet,
                    (packet_pointer as *mut NetBufferList) as _,
                )
            }
        } else {
            // Inject outbound.
            unsafe {
                FwpsInjectNetworkSendAsync0(
                    inject_handle,
                    core::ptr::null_mut(),
                    0,
                    UNSPECIFIED_COMPARTMENT_ID,
                    nbl,
                    free_packet,
                    (packet_pointer as *mut NetBufferList) as _,
                )
            }
        };

        // Check for error.
        if let Err(err) = check_ntstatus(status) {
            unsafe {
                // Get back ownership for data.
                _ = Box::from_raw(packet_pointer);
            }
            return Err(err);
        }

        return Ok(());
    }

    pub fn was_network_packet_injected_by_self(
        &self,
        nbl: *const NET_BUFFER_LIST,
        ipv6: bool,
    ) -> bool {
        let inject_handle = if ipv6 {
            self.packet_inject_handle_v6.load(Ordering::Acquire)
        } else {
            self.packet_inject_handle_v4.load(Ordering::Acquire)
        };
        if inject_handle == INVALID_HANDLE_VALUE || inject_handle.is_null() || nbl.is_null() {
            return false;
        }

        unsafe {
            let state = FwpsQueryPacketInjectionState0(inject_handle, nbl, core::ptr::null_mut());

            match state {
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_NOT_INJECTED => false,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_INJECTED_BY_SELF => true,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_INJECTED_BY_OTHER => false,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF => true,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_INJECTION_STATE_MAX => false,
                _ => false,
            }
        }
    }

    pub fn was_transport_packet_injected_by_self(&self, nbl: *const NET_BUFFER_LIST) -> bool {
        let transport_inject_handle = self
            .transport_inject_handle
            .load(Ordering::Acquire);
        if transport_inject_handle == INVALID_HANDLE_VALUE
            || transport_inject_handle.is_null()
            || nbl.is_null()
        {
            return false;
        }

        unsafe {
            let state = FwpsQueryPacketInjectionState0(
                transport_inject_handle,
                nbl,
                core::ptr::null_mut(),
            );

            match state {
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_NOT_INJECTED => false,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_INJECTED_BY_SELF => true,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_INJECTED_BY_OTHER => false,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF => true,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_INJECTION_STATE_MAX => false,
                _ => false,
            }
        }
    }
}

impl Drop for Injector {
    fn drop(&mut self) {
        if !crate::utils::is_passive_level() {
            // The WFP API is PASSIVE_LEVEL-only. Do not call it from an
            // arbitrary destructor context; normal Device teardown invokes
            // destroy before this object is dropped and at PASSIVE_LEVEL.
            crate::err!("cannot destroy injection handles outside PASSIVE_LEVEL");
            return;
        }

        // A live injection handle must never survive the end of DriverUnload.
        // Retry here as a final guard for construction/error paths; normal
        // teardown has already cleared all handles, so this loop is normally
        // entered only once and returns immediately.
        loop {
            match self.destroy() {
                Ok(()) => return,
                Err(err) => {
                    crate::err!("failed to destroy injection handles during drop: {}", err);
                    crate::utils::sleep_ms(1);
                }
            }
        }
    }
}

unsafe extern "system" fn free_packet(
    context: *mut c_void,
    net_buffer_list: *mut NET_BUFFER_LIST,
    _dispatch_level: BOOLEAN,
) {
    if let Some(nbl) = net_buffer_list.as_ref() {
        if let Err(err) = check_ntstatus(nbl.Status) {
            crate::err!("inject status: {}", err);
        } else {
            crate::dbg!("inject status: Ok");
        }
    }
    if !context.is_null() {
        _ = Box::from_raw(context as *mut NetBufferList);
    }
}

/// Completion callback for transport inject paths (both inbound and outbound).
/// The context is a `Box<TransportPacketList>` cast to `*mut c_void`.
/// Dropping it also correctly drops the inner `NetBufferList`.
unsafe extern "system" fn free_transport_packet(
    context: *mut c_void,
    net_buffer_list: *mut NET_BUFFER_LIST,
    _dispatch_level: BOOLEAN,
) {
    if let Some(nbl) = net_buffer_list.as_ref() {
        if let Err(err) = check_ntstatus(nbl.Status) {
            crate::err!("inject status: {}", err);
        } else {
            crate::dbg!("inject status: Ok");
        }
    }
    if !context.is_null() {
        _ = Box::from_raw(context as *mut TransportPacketList);
    }
}
