use crate::{
    ffi::{FwpsCompleteOperation0, FwpsFlowAssociateContext0, FwpsPendOperation0},
    utils::check_ntstatus,
};

use super::{
    classify::ClassifyOut,
    layer::{Layer, Value, ValueType},
    metadata::{FwpsIncomingMetadataValues, PacketDirection},
    packet::TransportPacketList,
    stream_data::StreamCalloutIoPacket,
};
use crate::consts::FWP_CONDITION_FLAG_IS_REASSEMBLED;
use alloc::string::{String, ToString};
use core::ffi::c_void;
use windows_sys::Win32::{
    Foundation::HANDLE,
    NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_FLAG_IS_REAUTHORIZE,
    Networking::WinSock::SCOPE_ID,
};

enum ClassifyDeferKind {
    Initial(HANDLE),
    Reauthorization,
}

/// An ALE operation whose native completion context is owned by this wrapper.
///
/// The private representation prevents safe code from manufacturing a WFP
/// completion context. Values can be created only from a live [`CalloutData`]
/// indication through [`CalloutData::pend_operation`] or
/// [`CalloutData::pend_filter_rest`].
pub struct ClassifyDefer {
    kind: ClassifyDeferKind,
    packet_list: Option<TransportPacketList>,
}

impl ClassifyDefer {
    fn initial(context: HANDLE, packet_list: Option<TransportPacketList>) -> Self {
        Self {
            kind: ClassifyDeferKind::Initial(context),
            packet_list,
        }
    }

    fn reauthorization(packet_list: Option<TransportPacketList>) -> Self {
        Self {
            kind: ClassifyDeferKind::Reauthorization,
            packet_list,
        }
    }

    /// Completes an ALE operation or returns a saved reauthorization packet.
    ///
    /// This method is callable from a classify callback, including at
    /// DISPATCH_LEVEL. Reauthorization is deliberately only represented here;
    /// the caller must invoke the WFP management operation from a
    /// PASSIVE_LEVEL path after this method returns.
    pub fn complete(self, inject_packet: bool) -> Result<Option<TransportPacketList>, String> {
        match self.kind {
            ClassifyDeferKind::Initial(context) => {
                // An inbound packet that will be injected from
                // ALE_AUTH_RECV_ACCEPT must also be supplied to
                // FwpsCompleteOperation. A denied packet is completed with a
                // null NBL and the owned clone is discarded by the caller.
                let nbl = if inject_packet {
                    self.packet_list
                        .as_ref()
                        .map(|packet| packet.net_buffer_list.nbl)
                        .unwrap_or(core::ptr::null_mut())
                } else {
                    core::ptr::null_mut()
                };
                // SAFETY: Only `CalloutData::pend_operation` can construct this
                // variant, and it stores the non-null context returned by
                // `FwpsPendOperation0`. This value owns that context until this
                // one completion call.
                unsafe { FwpsCompleteOperation0(context, nbl) };
                Ok(self.packet_list)
            }
            ClassifyDeferKind::Reauthorization => Ok(self.packet_list),
        }
    }

    /// Returns whether completing this value requires a PASSIVE_LEVEL WFP
    /// management operation to reauthorize existing flows.
    pub fn is_reauthorization(&self) -> bool {
        matches!(self.kind, ClassifyDeferKind::Reauthorization)
    }

    /// Returns the saved packet list, if this defer carries one.
    pub fn packet_list(&self) -> Option<&TransportPacketList> {
        self.packet_list.as_ref()
    }
}

pub(super) struct CalloutDataParts<'a> {
    pub layer: Layer,
    pub layer_id: u16,
    pub callout_id: u32,
    pub flow_context: u64,
    pub values: &'a [Value],
    pub metadata: &'a FwpsIncomingMetadataValues,
    pub classify_out: &'a mut ClassifyOut,
    pub layer_data: *mut c_void,
}

/// Borrowed access to one WFP classify indication.
///
/// Only the validated classify trampoline can construct this type. Its native
/// pointers and borrowed views remain valid only for the callback lifetime `'a`;
/// methods that expose a raw layer-data pointer do not extend that lifetime.
pub struct CalloutData<'a> {
    layer: Layer,
    layer_id: u16,
    callout_id: u32,
    flow_context: u64,
    values: &'a [Value],
    metadata: &'a FwpsIncomingMetadataValues,
    classify_out: &'a mut ClassifyOut,
    layer_data: *mut c_void,
}

impl<'a> CalloutData<'a> {
    pub(super) fn from_parts(parts: CalloutDataParts<'a>) -> Self {
        Self {
            layer: parts.layer,
            layer_id: parts.layer_id,
            callout_id: parts.callout_id,
            flow_context: parts.flow_context,
            values: parts.values,
            metadata: parts.metadata,
            classify_out: parts.classify_out,
            layer_data: parts.layer_data,
        }
    }

    pub fn get_value_type(&self, index: usize) -> ValueType {
        self.values
            .get(index)
            .map(|value| value.value_type)
            .unwrap_or(ValueType::FwpEmpty)
    }

    pub fn get_value_u8(&self, index: usize) -> u8 {
        let Some(value) = self.values.get(index) else {
            return 0;
        };
        if value.value_type != ValueType::FwpUint8 {
            return 0;
        }

        unsafe { value.value.uint8 }
    }

    pub fn get_value_u16(&self, index: usize) -> u16 {
        let Some(value) = self.values.get(index) else {
            return 0;
        };
        if value.value_type != ValueType::FwpUint16 {
            return 0;
        }

        unsafe { value.value.uint16 }
    }

    pub fn get_value_u32(&self, index: usize) -> u32 {
        let Some(value) = self.values.get(index) else {
            return 0;
        };
        if value.value_type != ValueType::FwpUint32 {
            return 0;
        }

        unsafe { value.value.uint32 }
    }

    pub fn get_value_byte_array16(&self, index: usize) -> &[u8; 16] {
        static EMPTY: [u8; 16] = [0; 16];

        let Some(value) = self.values.get(index) else {
            return &EMPTY;
        };
        if value.value_type != ValueType::FwpByteArray16Type {
            return &EMPTY;
        }

        unsafe { value.value.byte_array16.as_ref().unwrap_or(&EMPTY) }
    }

    pub fn get_flow_handle(&self) -> Option<u64> {
        self.metadata.get_flow_handle()
    }

    pub fn has_flow_context(&self) -> bool {
        self.flow_context != 0
    }

    pub fn get_layer(&self) -> Layer {
        self.layer
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
        self.metadata.get_process_id()
    }

    pub fn get_process_path(&self) -> Option<String> {
        unsafe { self.metadata.get_process_path() }
    }

    pub fn get_transport_endpoint_handle(&self) -> Option<u64> {
        self.metadata.get_transport_endpoint_handle()
    }

    pub fn get_parent_endpoint_handle(&self) -> Option<u64> {
        self.metadata.get_parent_endpoint_handle()
    }

    pub fn get_remote_scope_id(&self) -> Option<SCOPE_ID> {
        self.metadata.get_remote_scope_id()
    }

    pub fn get_control_data(&self) -> Option<&[u8]> {
        unsafe { self.metadata.get_control_data() }
    }

    pub fn get_layer_data(&self) -> *mut c_void {
        return self.layer_data;
    }

    pub fn get_stream_callout_packet(&mut self) -> Option<&mut StreamCalloutIoPacket> {
        match self.layer {
            Layer::StreamV4 | Layer::StreamV4Discard | Layer::StreamV6 | Layer::StreamV6Discard => unsafe {
                (self.layer_data as *mut StreamCalloutIoPacket).as_mut()
            },
            _ => None,
        }
    }

    pub fn is_fragment_data(&self) -> bool {
        self.metadata.is_fragment_data()
    }

    /// Size of the IP header for this indication, if WFP provided it.
    pub fn get_ip_header_size(&self) -> Option<u32> {
        self.metadata.get_ip_header_size()
    }

    /// Size of the transport header for this indication, if WFP provided it.
    pub fn get_transport_header_size(&self) -> Option<u32> {
        self.metadata.get_transport_header_size()
    }

    /// Routing compartment for this indication, if WFP provided it.
    pub fn get_compartment_id(&self) -> Option<u32> {
        self.metadata.get_compartment_id()
    }

    /// Direction of the packet that triggered ALE reauthorization.
    ///
    /// WFP omits this metadata for an ordinary ALE authorization; callers must
    /// then infer direction from the connect or receive/accept layer.
    pub fn get_packet_direction(&self) -> Option<PacketDirection> {
        self.metadata.get_packet_direction()
    }

    pub fn pend_operation(
        &mut self,
        packet_list: Option<TransportPacketList>,
    ) -> Result<ClassifyDefer, String> {
        let mut completion_context: HANDLE = core::ptr::null_mut();
        if let Some(completion_handle) = self.metadata.get_completion_handle() {
            let status = unsafe { FwpsPendOperation0(completion_handle, &mut completion_context) };
            check_ntstatus(status)?;
            if completion_context.is_null() {
                return Err("WFP returned a null completion context".to_string());
            }

            return Ok(ClassifyDefer::initial(completion_context, packet_list));
        }

        Err("callout not supported".to_string())
    }

    pub fn pend_filter_rest(&mut self, packet_list: Option<TransportPacketList>) -> ClassifyDefer {
        ClassifyDefer::reauthorization(packet_list)
    }

    pub fn action_permit(&mut self) {
        self.classify_out.action_permit();
        self.classify_out.clear_absorb_flag();
    }

    pub fn action_continue(&mut self) {
        self.classify_out.action_continue();
        self.classify_out.clear_absorb_flag();
    }

    // Block action and clear the write flag.
    // This will block the packet and prevent next filter in the chain to change the action.
    pub fn action_block_hard(&mut self) {
        self.classify_out.action_block();
        self.classify_out.clear_absorb_flag();
        // Next filter in the chain will not change the action.
        self.classify_out.clear_write_flag();
    }

    pub fn action_none(&mut self) {
        self.classify_out.set_none();
        self.classify_out.clear_absorb_flag();
    }

    pub fn block_and_absorb(&mut self) {
        self.classify_out.action_block();
        self.classify_out.set_absorb();
    }
    pub fn clear_write_flag(&mut self) {
        self.classify_out.clear_write_flag();
    }

    pub fn is_reauthorize(&self, flags_index: usize) -> bool {
        self.get_value_type(flags_index) == ValueType::FwpUint32
            && self.get_value_u32(flags_index) & FWP_CONDITION_FLAG_IS_REAUTHORIZE > 0
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
