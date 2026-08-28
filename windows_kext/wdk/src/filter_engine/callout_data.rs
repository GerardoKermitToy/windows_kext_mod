use crate::{
    ffi::{FwpsCompleteOperation0, FwpsFlowAssociateContext0, FwpsPendOperation0},
    utils::check_ntstatus,
};

use super::{
    classify::ClassifyOut,
    layer::{Layer, Value, ValueType},
    metadata::FwpsIncomingMetadataValues,
    packet::TransportPacketList,
    stream_data::StreamCalloutIoPacket,
    FilterEngine,
};
use crate::consts::FWP_CONDITION_FLAG_IS_REASSEMBLED;
use alloc::string::{String, ToString};
use core::{ffi::c_void, ptr::NonNull};
use windows_sys::Win32::{
    Foundation::HANDLE,
    NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_FLAG_IS_REAUTHORIZE,
    Networking::WinSock::SCOPE_ID,
};

pub enum ClassifyDefer {
    Initial(HANDLE, Option<TransportPacketList>),
    Reauthorization(u32, Option<TransportPacketList>),
}

impl ClassifyDefer {
    pub fn complete(
        self,
        filter_engine: &mut FilterEngine,
        inject_packet: bool,
    ) -> Result<Option<TransportPacketList>, String> {
        unsafe {
            match self {
                ClassifyDefer::Initial(context, packet_list) => {
                    // An inbound packet that will be injected from
                    // ALE_AUTH_RECV_ACCEPT must also be supplied to
                    // FwpsCompleteOperation. A denied packet is completed with a
                    // null NBL and the owned clone is discarded by the caller.
                    let nbl = if inject_packet {
                        packet_list
                            .as_ref()
                            .map(|packet| packet.net_buffer_list.nbl as *mut c_void)
                            .unwrap_or(core::ptr::null_mut())
                    } else {
                        core::ptr::null_mut()
                    };
                    FwpsCompleteOperation0(context, nbl);
                    return Ok(packet_list);
                }
                ClassifyDefer::Reauthorization(_callout_id, packet_list) => {
                    // There is no way to reset single filter. If another request for filter reset is trigger at the same time it will fail.
                    //
                    // Resetting all filters forces WFP to re-evaluate (reauthorize) all existing connections
                    // using the updated verdict cache.
                    // If STATUS_FWP_TXN_IN_PROGRESS is returned, another reset_all_filters() call is
                    // already running concurrently, which will trigger the same WFP reauthorization.
                    // It is safe to ignore this specific error and proceed with injecting the packet:
                    // the verdict for this connection is already in the connection_cache, so the callout
                    // will apply the correct verdict when the injected packet passes through.
                    match filter_engine.reset_all_filters() {
                        Ok(_) => {}
                        Err(err) if err.contains("STATUS_FWP_TXN_IN_PROGRESS") => {
                            // Another transaction is already in progress and will handle reauthorization.
                        }
                        Err(err) => return Err(err),
                    }
                    return Ok(packet_list);
                }
            }
        }
    }

    // pub fn add_net_buffer(&mut self, nbl: NetBufferList) {
    //     if let Some(packet_list) = match self {
    //         ClassifyDefer::Initial(_, packet_list) => packet_list,
    //         ClassifyDefer::Reauthorization(_, packet_list) => packet_list,
    //     } {
    //         packet_list.net_buffer_list_queue.push(nbl);
    //     }
    // }
}

pub struct CalloutData<'a> {
    pub layer: Layer,
    pub(crate) layer_id: u16,
    pub(crate) callout_id: u32,
    pub(crate) flow_context: u64,
    pub(crate) values: &'a [Value],
    pub(crate) metadata: *const FwpsIncomingMetadataValues,
    pub(crate) classify_out: *mut ClassifyOut,
    pub(crate) layer_data: *mut c_void,
}

impl<'a> CalloutData<'a> {
    pub fn get_value_type(&self, index: usize) -> ValueType {
        self.values[index].value_type
    }

    pub fn get_value_u8(&'a self, index: usize) -> u8 {
        unsafe {
            return self.values[index].value.uint8;
        };
    }

    pub fn get_value_u16(&'a self, index: usize) -> u16 {
        unsafe {
            return self.values[index].value.uint16;
        };
    }

    pub fn get_value_u32(&'a self, index: usize) -> u32 {
        unsafe {
            return self.values[index].value.uint32;
        };
    }

    pub fn get_value_byte_array16(&'a self, index: usize) -> &'a [u8; 16] {
        unsafe {
            return self.values[index].value.byte_array16.as_ref().unwrap();
        };
    }

    pub fn get_flow_handle(&self) -> Option<u64> {
        unsafe { (*self.metadata).get_flow_handle() }
    }

    pub fn has_flow_context(&self) -> bool {
        self.flow_context != 0
    }

    pub fn get_layer_id(&self) -> u16 {
        self.layer_id
    }

    pub fn get_callout_id(&self) -> u32 {
        self.callout_id
    }

    /// Associates a non-zero driver-owned context with the current WFP flow.
    /// On success WFP owns the association and returns the same value to the
    /// callout's flowDeleteFn. The caller retains ownership when this fails.
    pub fn associate_flow_context(&self, flow_context: u64) -> Result<(), String> {
        if flow_context == 0 {
            return Err("flow context must not be zero".to_string());
        }
        if self.has_flow_context() {
            return Err("flow already has a context for this callout".to_string());
        }
        let Some(flow_id) = self.get_flow_handle().filter(|flow_id| *flow_id != 0) else {
            return Err("flow handle metadata is missing or zero".to_string());
        };

        let status = unsafe {
            FwpsFlowAssociateContext0(flow_id, self.layer_id, self.callout_id, flow_context)
        };
        check_ntstatus(status)
    }

    pub fn get_process_id(&self) -> Option<u64> {
        unsafe { (*self.metadata).get_process_id() }
    }

    pub fn get_process_path(&self) -> Option<String> {
        unsafe {
            return (*self.metadata).get_process_path();
        }
    }

    pub fn get_transport_endpoint_handle(&self) -> Option<u64> {
        unsafe {
            return (*self.metadata).get_transport_endpoint_handle();
        }
    }

    pub fn get_remote_scope_id(&self) -> Option<SCOPE_ID> {
        unsafe {
            return (*self.metadata).get_remote_scope_id();
        }
    }

    pub fn get_control_data(&self) -> Option<NonNull<[u8]>> {
        unsafe {
            return (*self.metadata).get_control_data();
        }
    }

    pub fn get_layer_data(&self) -> *mut c_void {
        return self.layer_data;
    }

    pub fn get_stream_callout_packet(&self) -> Option<&mut StreamCalloutIoPacket> {
        match self.layer {
            Layer::StreamV4 | Layer::StreamV4Discard | Layer::StreamV6 | Layer::StreamV6Discard => unsafe {
                (self.layer_data as *mut StreamCalloutIoPacket).as_mut()
            },
            _ => None,
        }
    }

    pub fn is_fragment_data(&self) -> bool {
        unsafe { (*self.metadata).is_fragment_data() }
    }

    /// Size of the IP header for this indication, if WFP provided it.
    pub fn get_ip_header_size(&self) -> Option<u32> {
        unsafe { (*self.metadata).get_ip_header_size() }
    }

    /// Size of the transport header for this indication, if WFP provided it.
    pub fn get_transport_header_size(&self) -> Option<u32> {
        unsafe { (*self.metadata).get_transport_header_size() }
    }

    /// Routing compartment for this indication, if WFP provided it.
    pub fn get_compartment_id(&self) -> Option<u32> {
        unsafe { (*self.metadata).get_compartment_id() }
    }

    pub fn pend_operation(
        &mut self,
        packet_list: Option<TransportPacketList>,
    ) -> Result<ClassifyDefer, String> {
        unsafe {
            let mut completion_context: HANDLE = core::ptr::null_mut();
            if let Some(completion_handle) = (*self.metadata).get_completion_handle() {
                let status = FwpsPendOperation0(completion_handle, &mut completion_context);
                check_ntstatus(status)?;

                return Ok(ClassifyDefer::Initial(completion_context, packet_list));
            }

            Err("callout not supported".to_string())
        }
    }

    pub fn pend_filter_rest(&mut self, packet_list: Option<TransportPacketList>) -> ClassifyDefer {
        ClassifyDefer::Reauthorization(self.callout_id, packet_list)
    }

    pub fn action_permit(&mut self) {
        unsafe {
            (*self.classify_out).action_permit();
            (*self.classify_out).clear_absorb_flag();
        }
    }

    pub fn action_continue(&mut self) {
        unsafe {
            (*self.classify_out).action_continue();
            (*self.classify_out).clear_absorb_flag();
        }
    }

    // Block action and clear the write flag.
    // This will block the packet and prevent next filter in the chain to change the action.
    pub fn action_block_hard(&mut self) {
        unsafe {
            (*self.classify_out).action_block();
            (*self.classify_out).clear_absorb_flag();
            // Next filter in the chain will not change the action.
            (*self.classify_out).clear_write_flag();
        }
    }

    pub fn action_none(&mut self) {
        unsafe {
            (*self.classify_out).set_none();
            (*self.classify_out).clear_absorb_flag();
        }
    }

    pub fn block_and_absorb(&mut self) {
        unsafe {
            (*self.classify_out).action_block();
            (*self.classify_out).set_absorb();
        }
    }
    pub fn clear_write_flag(&mut self) {
        unsafe {
            (*self.classify_out).clear_write_flag();
        }
    }

    pub fn is_reauthorize(&self, flags_index: usize) -> bool {
        self.get_value_u32(flags_index) & FWP_CONDITION_FLAG_IS_REAUTHORIZE > 0
    }

    /// Returns true if WFP indicated this packet as a reassembled datagram, i.e.
    /// the individual fragments have been merged back into one packet with a
    /// complete transport header.
    ///
    /// Reads false when the FLAGS field is not a u32, so an unexpected layout
    /// cannot cause a fragment to be mistaken for a reassembled packet.
    pub fn is_reassembled(&self, flags_index: usize) -> bool {
        match self.get_value_type(flags_index) {
            ValueType::FwpUint32 => {
                self.get_value_u32(flags_index) & FWP_CONDITION_FLAG_IS_REASSEMBLED > 0
            }
            _ => false,
        }
    }
}
