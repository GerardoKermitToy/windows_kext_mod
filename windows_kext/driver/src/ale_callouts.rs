use crate::connection::{Connection, ConnectionV4, ConnectionV6, Direction, Verdict};
use crate::connection_map::Key;
use crate::device::{Device, Packet};
use crate::udp_flow_cache::UdpFlowRegistration;
use alloc::{boxed::Box, string::String, vec::Vec};

use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv6Address, IPV4_HEADER_LEN, IPV6_HEADER_LEN,
};
use wdk::filter_engine::layer::{
    self, FieldsAleAuthConnectV4, FieldsAleAuthConnectV6, FieldsAleAuthRecvAcceptV4,
    FieldsAleAuthRecvAcceptV6, ValueType,
};
use wdk::filter_engine::net_buffer::NetBufferList;
use wdk::filter_engine::packet::{Injector, TransportPacketList, TransportProtocol};
use wdk::filter_engine::{callout_data::CalloutData, PacketDirection as WfpPacketDirection};

// ALE Layers

#[derive(Debug)]
#[allow(dead_code)]
struct AleLayerData {
    is_ipv6: bool,
    reauthorize: bool,
    process_id: u64,
    protocol: IpProtocol,
    /// Direction assigned to the ALE flow, derived from its authorization layer.
    connection_direction: Direction,
    /// Direction of the packet currently being classified. During reauthorization
    /// this can be opposite to `connection_direction`.
    packet_direction: Direction,
    local_ip: IpAddress,
    local_port: u16,
    remote_ip: IpAddress,
    remote_port: u16,
    interface_index: u32,
    sub_interface_index: u32,
}

impl AleLayerData {
    fn as_key(&self) -> Key {
        let mut local_port = 0;
        let mut remote_port = 0;
        match self.protocol {
            IpProtocol::Tcp | IpProtocol::Udp => {
                local_port = self.local_port;
                remote_port = self.remote_port;
            }
            _ => {}
        }

        Key {
            protocol: self.protocol,
            local_address: self.local_ip,
            local_port,
            remote_address: self.remote_ip,
            remote_port,
        }
    }
}

fn get_protocol(data: &CalloutData, index: usize) -> IpProtocol {
    IpProtocol::from(data.get_value_u8(index))
}

fn get_protocol_if_present(data: &CalloutData, index: usize) -> Option<IpProtocol> {
    matches!(data.get_value_type(index), ValueType::FwpUint8).then(|| get_protocol(data, index))
}

fn get_u16_if_present(data: &CalloutData, index: usize) -> Option<u16> {
    matches!(data.get_value_type(index), ValueType::FwpUint16).then(|| data.get_value_u16(index))
}

/// Reads a `FWP_UINT32` field, returning 0 when the field is not populated.
///
/// Several fields are only filled in at some layers. Reading the union member
/// regardless yields an unrelated value rather than an error, so the type is
/// checked first.
fn get_u32_or_zero(data: &CalloutData, index: usize) -> u32 {
    match data.get_value_type(index) {
        ValueType::FwpUint32 => data.get_value_u32(index),
        _ => 0,
    }
}

/// Resolves the current packet direction without changing the direction assigned
/// to the ALE flow. WFP supplies packet-direction metadata only for
/// reauthorization; its absence means the authorization layer direction applies.
fn get_packet_direction(data: &CalloutData, connection_direction: Direction) -> Direction {
    match data.get_packet_direction() {
        Some(WfpPacketDirection::Outbound) => Direction::Outbound,
        Some(WfpPacketDirection::Inbound) => Direction::Inbound,
        None => connection_direction,
    }
}

fn get_ipv4_address(data: &CalloutData, index: usize) -> IpAddress {
    IpAddress::Ipv4(Ipv4Address::from_bytes(
        &data.get_value_u32(index).to_be_bytes(),
    ))
}

fn get_ipv4_address_if_present(data: &CalloutData, index: usize) -> Option<IpAddress> {
    matches!(data.get_value_type(index), ValueType::FwpUint32)
        .then(|| get_ipv4_address(data, index))
}

fn get_ipv6_address(data: &CalloutData, index: usize) -> IpAddress {
    IpAddress::Ipv6(Ipv6Address::from_bytes(data.get_value_byte_array16(index)))
}

fn get_ipv6_address_if_present(data: &CalloutData, index: usize) -> Option<IpAddress> {
    matches!(data.get_value_type(index), ValueType::FwpByteArray16Type)
        .then(|| get_ipv6_address(data, index))
}

pub fn ale_layer_connect_v4(data: CalloutData) {
    type Fields = FieldsAleAuthConnectV4;
    let ale_data = AleLayerData {
        is_ipv6: false,
        reauthorize: data.is_reauthorize(Fields::Flags as usize),
        process_id: data.get_process_id().unwrap_or(0),
        protocol: get_protocol(&data, Fields::IpProtocol as usize),
        connection_direction: Direction::Outbound,
        packet_direction: get_packet_direction(&data, Direction::Outbound),
        local_ip: get_ipv4_address(&data, Fields::IpLocalAddress as usize),
        local_port: data.get_value_u16(Fields::IpLocalPort as usize),
        remote_ip: get_ipv4_address(&data, Fields::IpRemoteAddress as usize),
        remote_port: data.get_value_u16(Fields::IpRemotePort as usize),
        interface_index: get_u32_or_zero(&data, Fields::InterfaceIndex as usize),
        sub_interface_index: get_u32_or_zero(&data, Fields::SubInterfaceIndex as usize),
    };

    ale_layer_auth(data, ale_data);
}

pub fn ale_layer_connect_v6(data: CalloutData) {
    type Fields = FieldsAleAuthConnectV6;

    let ale_data = AleLayerData {
        is_ipv6: true,
        reauthorize: data.is_reauthorize(Fields::Flags as usize),
        process_id: data.get_process_id().unwrap_or(0),
        protocol: get_protocol(&data, Fields::IpProtocol as usize),
        connection_direction: Direction::Outbound,
        packet_direction: get_packet_direction(&data, Direction::Outbound),
        local_ip: get_ipv6_address(&data, Fields::IpLocalAddress as usize),
        local_port: data.get_value_u16(Fields::IpLocalPort as usize),
        remote_ip: get_ipv6_address(&data, Fields::IpRemoteAddress as usize),
        remote_port: data.get_value_u16(Fields::IpRemotePort as usize),
        // Read only when actually populated. WFP reports SubInterfaceIndex as
        // FWP_EMPTY at the connect authorization layer - there is no interface
        // binding yet at that point - so reading it unconditionally returned
        // whatever the union held, and that value went on to be used as an
        // injection parameter. The v4 path already passes zeros here.
        interface_index: get_u32_or_zero(&data, Fields::InterfaceIndex as usize),
        sub_interface_index: get_u32_or_zero(&data, Fields::SubInterfaceIndex as usize),
    };

    ale_layer_auth(data, ale_data);
}

pub fn ale_layer_recv_accept_v4(data: CalloutData) {
    type Fields = FieldsAleAuthRecvAcceptV4;

    let ale_data = AleLayerData {
        is_ipv6: false,
        reauthorize: data.is_reauthorize(Fields::Flags as usize),
        process_id: data.get_process_id().unwrap_or(0),
        protocol: get_protocol(&data, Fields::IpProtocol as usize),
        connection_direction: Direction::Inbound,
        packet_direction: get_packet_direction(&data, Direction::Inbound),
        local_ip: get_ipv4_address(&data, Fields::IpLocalAddress as usize),
        local_port: data.get_value_u16(Fields::IpLocalPort as usize),
        remote_ip: get_ipv4_address(&data, Fields::IpRemoteAddress as usize),
        remote_port: data.get_value_u16(Fields::IpRemotePort as usize),
        interface_index: get_u32_or_zero(&data, Fields::InterfaceIndex as usize),
        sub_interface_index: get_u32_or_zero(&data, Fields::SubInterfaceIndex as usize),
    };

    ale_layer_auth(data, ale_data);
}

pub fn ale_layer_recv_accept_v6(data: CalloutData) {
    type Fields = FieldsAleAuthRecvAcceptV6;

    let ale_data = AleLayerData {
        is_ipv6: true,
        reauthorize: data.is_reauthorize(Fields::Flags as usize),
        process_id: data.get_process_id().unwrap_or(0),
        protocol: get_protocol(&data, Fields::IpProtocol as usize),
        connection_direction: Direction::Inbound,
        packet_direction: get_packet_direction(&data, Direction::Inbound),
        local_ip: get_ipv6_address(&data, Fields::IpLocalAddress as usize),
        local_port: data.get_value_u16(Fields::IpLocalPort as usize),
        remote_ip: get_ipv6_address(&data, Fields::IpRemoteAddress as usize),
        remote_port: data.get_value_u16(Fields::IpRemotePort as usize),
        interface_index: get_u32_or_zero(&data, Fields::InterfaceIndex as usize),
        sub_interface_index: get_u32_or_zero(&data, Fields::SubInterfaceIndex as usize),
    };

    ale_layer_auth(data, ale_data);
}

fn udp_endpoint_handle(data: &CalloutData) -> Option<u64> {
    data.get_transport_endpoint_handle()
        .filter(|endpoint_handle| *endpoint_handle != 0)
}

/// Associates an endpoint only after a concrete live connection-cache instance
/// exists. This avoids unbound peers that no flow callback or periodic cleanup can
/// identify precisely.
fn track_udp_endpoint_instance(
    device: &Device,
    endpoint_handle: Option<u64>,
    key: Key,
    instance_id: u64,
) {
    let Some(endpoint_handle) = endpoint_handle else {
        return;
    };
    let mut endpoint_cache = device.udp_endpoint_cache.write_lock();
    let _ = endpoint_cache.associate_instance(endpoint_handle, key, instance_id);
}

fn ale_layer_auth(mut data: CalloutData, ale_data: AleLayerData) {
    // Make the default path as drop.
    data.block_and_absorb();

    let Some(device) = crate::entry::get_device() else {
        return;
    };

    // Network-layer reinjection is used by the packet path, while packets held at
    // ALE receive/accept are returned with the transport injector. Either kind can
    // be indicated here again and must be permitted without creating another pend.
    let layer_data = data.get_layer_data();
    // SAFETY: A non-null ALE layer-data value is a WFP-owned NBL that remains
    // live for this classify callback. Both injection-state queries are
    // synchronous and do not retain it.
    let injected_by_self = !layer_data.is_null()
        && unsafe {
            device
                .injector
                .was_network_packet_injected_by_self(layer_data as _, ale_data.is_ipv6)
                || device
                    .injector
                    .was_transport_packet_injected_by_self(layer_data as _)
        };
    if injected_by_self {
        data.action_permit();
        return;
    }

    match ale_data.protocol {
        IpProtocol::Tcp | IpProtocol::Udp => {
            // Only TCP and UDP make sense to be supported in the ALE layer.
            // Everything else is not associated with a connection and will be handled in the packet layer.
        }
        _ => {
            // Outbound: Will be handled by packet layer next.
            // Inbound: Was already handled by the packet layer.
            data.action_permit();
            return;
        }
    }

    let key = ale_data.as_key();

    // Keep the handle now, but associate it only after this authorization has a
    // concrete connection-cache instance. In particular, a blocked first packet
    // must not leave an unbound peer for the lifetime of a listening socket.
    let endpoint_handle = if matches!(ale_data.protocol, IpProtocol::Udp) {
        udp_endpoint_handle(&data)
    } else {
        None
    };

    // Outbound UDP is decided at the IP packet layer, not here.
    //
    // Holding a datagram at this layer corrupts the send status seen by the
    // application. Both ways of holding it are broken for Registered I/O:
    // pend_operation freezes the endpoint, so datagrams submitted concurrently
    // are completed with WSAEINVAL and never reach the stack at all; absorbing
    // instead keeps every datagram (they are re-injected once a verdict arrives)
    // but still completes them with WSAEINVAL, so the application is told a
    // delivered datagram failed. A caller that retries on error duplicates it.
    //
    // The IP packet layer sits below the socket, so by the time a datagram is
    // absorbed there its send has already completed successfully. Verified with
    // RIOSendEx: six concurrent datagrams all report success, all six are
    // delivered, and the packet layer still gets to decide each one.
    //
    // Register the connection here so the process ID is recorded while it is
    // available - the packet layer has no access to it and would store 0 - then
    // permit and let the packet layer classify. During ordinary authorization,
    // inbound UDP does not take this branch. During cross-direction
    // reauthorization, the current packet direction deliberately controls it.
    if matches!(ale_data.protocol, IpProtocol::Udp)
        && matches!(ale_data.packet_direction, Direction::Outbound)
    {
        match device.connection_cache.register_connection(
            &key,
            ale_data.process_id,
            ale_data.connection_direction,
        ) {
            Ok(registration) => {
                if registration.inserted {
                    crate::dbg!(
                        "ale layer registered udp connection for packet layer: {} PID: {}",
                        key,
                        ale_data.process_id
                    );
                }
                track_udp_endpoint_instance(device, endpoint_handle, key, registration.instance_id);
            }
            Err(err) => crate::err!("failed to build connection: {}", err),
        }

        data.action_permit();

        if device.is_owner_pid(ale_data.process_id as u32) {
            // Keep other firewalls from overriding the permit on Portmaster's own
            // traffic, matching the cached-verdict path below.
            data.clear_write_flag();
        }
        return;
    }

    // Check if connection is already in cache.
    let cached = if ale_data.is_ipv6 {
        device
            .connection_cache
            .read_connection_v6(&key, |conn| -> Option<(Verdict, u64)> {
                // Function is behind spin lock, just copy and return.
                Some((conn.verdict, conn.get_instance_id()))
            })
    } else {
        device
            .connection_cache
            .read_connection_v4(&key, |conn| -> Option<(Verdict, u64)> {
                // Function is behind spin lock, just copy and return.
                Some((conn.verdict, conn.get_instance_id()))
            })
    };

    // Connection already in cache.
    if let Some((verdict, connection_instance_id)) = cached {
        track_udp_endpoint_instance(device, endpoint_handle, key, connection_instance_id);
        crate::dbg!("processing existing connection: {} {}", key, verdict);
        match verdict {
            // No verdict yet
            Verdict::Undecided => {
                crate::dbg!("saving packet: {}", key);
                // Connection is already pended. Save packet and wait for verdict.
                match save_packet(device, &mut data, &ale_data, false) {
                    Ok(packet) => {
                        let info = {
                            let mut packet_cache = device.packet_cache.write_lock();
                            packet_cache.push(
                                (key, packet),
                                Some(connection_instance_id),
                                ale_data.process_id,
                                ale_data.packet_direction,
                                true,
                            )
                        };
                        if let Some(info) = info {
                            let _ = device.event_queue.push(info);
                        }
                    }
                    Err(err) => {
                        crate::err!("failed to pend packet: {}", err);
                    }
                };
                data.block_and_absorb();
            }
            // There is a verdict
            Verdict::PermanentAccept
            | Verdict::Accept
            | Verdict::RedirectNameServer
            | Verdict::RedirectTunnel
            | Verdict::RedirectSplitTunnel => {
                // Authorize at ALE. Outbound traffic continues to the packet
                // layer; inbound traffic has already passed it.
                data.action_permit();

                if device.is_owner_pid(ale_data.process_id as u32)
                    && matches!(ale_data.packet_direction, Direction::Outbound)
                {
                    // If this is Portmaster's own outbound packet, clear the write flag
                    // to prevent subsequent filters in the chain from overriding the permit action.
                    // This prevents other firewall applications from blocking Portmaster's own traffic.
                    data.clear_write_flag();
                }
            }
            Verdict::PermanentBlock | Verdict::Undeterminable | Verdict::Failed => {
                // Packet layer will not see this connection.
                crate::dbg!("permanent block {}", key);
                data.action_block_hard();
            }
            Verdict::PermanentDrop => {
                // Packet layer will not see this connection.
                crate::dbg!("permanent drop {}", key);
                data.block_and_absorb();
            }
            Verdict::Block => {
                if let Direction::Outbound = ale_data.packet_direction {
                    // Handled by packet layer.
                    data.action_permit();
                } else {
                    // Inbound authorization is enforced here.
                    data.action_block_hard();
                }
            }
            Verdict::Drop => {
                if let Direction::Outbound = ale_data.packet_direction {
                    // Handled by packet layer.
                    data.action_permit();
                } else {
                    // Inbound authorization is enforced here.
                    data.block_and_absorb();
                }
            }
        }
    } else {
        crate::dbg!("pending connection: {} {}", key, ale_data.packet_direction);
        // Only first packet of a connection can be pended: reauthorize == false
        //
        // Outbound UDP never reaches this point - it returns above and is decided
        // at the packet layer, because holding a datagram at this layer breaks the
        // send status reported to the application. Inbound UDP still arrives here
        // and is safe to pend: there is no application send operation to freeze.
        let can_pend_connection = !ale_data.reauthorize;
        let packet = match save_packet(device, &mut data, &ale_data, can_pend_connection) {
            Ok(packet) => packet,
            Err(err) => {
                crate::err!("failed to pend packet: {}", err);
                return;
            }
        };

        // Register before publishing the request. The cache performs the live
        // lookup and insertion under one write guard, so a concurrent classify
        // callback cannot create another live entry for this tuple.
        let registration = match device.connection_cache.register_connection(
            &key,
            ale_data.process_id,
            ale_data.connection_direction,
        ) {
            Ok(registration) => {
                if registration.inserted {
                    crate::dbg!(
                        "ale layer added connection: {} PID: {}",
                        key,
                        ale_data.process_id
                    );
                } else {
                    crate::dbg!("connection registered concurrently: {}", key);
                }
                registration
            }
            Err(err) => {
                crate::err!("failed to build connection: {}", err);
                if let Err(complete_err) = device.inject_packet(packet, true) {
                    crate::err!("failed to complete ALE operation: {}", complete_err);
                }
                return;
            }
        };

        track_udp_endpoint_instance(device, endpoint_handle, key, registration.instance_id);
        let info = {
            let mut packet_cache = device.packet_cache.write_lock();
            packet_cache.push(
                (key, packet),
                Some(registration.instance_id),
                ale_data.process_id,
                ale_data.packet_direction,
                true,
            )
        };
        if let Some(info) = info {
            let _ = device.event_queue.push(info);
        }

        // Absorb this indication. A reusable packet clone, when WFP supplied one,
        // will be re-injected after Portmaster returns a verdict.
        data.block_and_absorb();
    }
}

fn save_packet(
    device: &Device,
    callout_data: &mut CalloutData,
    ale_data: &AleLayerData,
    pend: bool,
) -> Result<Packet, alloc::string::String> {
    let mut packet_list = None;
    let mut save_packet_list = true;
    if ale_data.protocol == IpProtocol::Tcp
        && matches!(ale_data.packet_direction, Direction::Outbound)
    {
        // Initial outbound TCP authorization has no packet data. A later
        // reauthorization may carry a transport-header NBL, so preserve it when
        // WFP makes one available.
        save_packet_list = ale_data.reauthorize;
    }
    if save_packet_list {
        packet_list = create_packet_list(device, callout_data, ale_data)?;
    }
    if pend && matches!(ale_data.packet_direction, Direction::Inbound) && packet_list.is_none() {
        return Err("ALE receive/accept indication has no packet data".into());
    }
    if pend && matches!(ale_data.protocol, IpProtocol::Tcp | IpProtocol::Udp) {
        match callout_data.pend_operation(packet_list) {
            Ok(classify_defer) => Ok(Packet::AleLayer(classify_defer)),
            Err(err) => Err(alloc::format!("failed to defer connection: {}", err)),
        }
    } else {
        Ok(Packet::AleLayer(callout_data.pend_filter_rest(packet_list)))
    }
}

fn create_packet_list(
    device: &Device,
    callout_data: &mut CalloutData,
    ale_data: &AleLayerData,
) -> Result<Option<TransportPacketList>, String> {
    // An inbound packet can reauthorize an outbound ALE flow at AUTH_CONNECT.
    // WFP does not expose a valid IP header for packet inspection at that layer,
    // so it cannot be converted into the IP-header NBL required by transport
    // receive injection. Absorb this indication without a clone; after the verdict
    // forces another reauthorization, the next packet is classified normally.
    if ale_data.reauthorize
        && matches!(ale_data.connection_direction, Direction::Outbound)
        && matches!(ale_data.packet_direction, Direction::Inbound)
    {
        return Ok(None);
    }

    if callout_data.get_layer_data().is_null() {
        return Ok(None);
    }

    // SAFETY: This function runs synchronously inside an ALE classify callback.
    // WFP owns the non-null layer-data NBL and keeps it live through callback
    // return; this borrowed wrapper is dropped after cloning and never escapes.
    let mut nbl = unsafe { NetBufferList::new(callout_data.get_layer_data() as _) };
    let mut inbound = false;
    let mut event_data_offset = 0;
    if let Direction::Inbound = ale_data.packet_direction {
        // At ALE_AUTH_RECV_ACCEPT the inbound data offset is at the payload.
        // Retreat over both headers so the clone passed to
        // FwpsInjectTransportReceiveAsync starts at the IP header.
        let base = if ale_data.is_ipv6 {
            IPV6_HEADER_LEN
        } else {
            IPV4_HEADER_LEN
        } as u32;
        let ip_header_size = callout_data
            .get_ip_header_size()
            .ok_or_else(|| String::from("missing ALE IP header size metadata"))?;
        if ip_header_size < base {
            return Err(alloc::format!(
                "invalid ALE IP header size: {}",
                ip_header_size
            ));
        }

        let transport_header_size = callout_data
            .get_transport_header_size()
            .ok_or_else(|| String::from("missing ALE transport header size metadata"))?;
        let minimum_transport_header_size = match ale_data.protocol {
            IpProtocol::Tcp => 20,
            IpProtocol::Udp => 8,
            _ => 0,
        };
        if transport_header_size < minimum_transport_header_size {
            return Err(alloc::format!(
                "invalid ALE transport header size: {}",
                transport_header_size
            ));
        }

        let header_size = ip_header_size
            .checked_add(transport_header_size)
            .ok_or_else(|| String::from("ALE header size overflow"))?;
        nbl.retreat(header_size, true)
            .map_err(|err| alloc::format!("failed to retreat ALE packet: {}", err))?;
        event_data_offset = ip_header_size as usize;
        inbound = true;
    }

    let address: &[u8] = match &ale_data.remote_ip {
        IpAddress::Ipv4(address) => &address.0,
        IpAddress::Ipv6(address) => &address.0,
    };
    let clone = nbl
        .clone(&device.network_allocator)
        .map_err(|err| alloc::format!("failed to clone ALE packet: {}", err))?;
    let transport_protocol = match ale_data.protocol {
        IpProtocol::Tcp => TransportProtocol::Tcp,
        IpProtocol::Udp => TransportProtocol::Udp,
        _ => return Err(String::from("unsupported ALE transport protocol")),
    };

    Ok(Some(Injector::from_ale_callout(
        transport_protocol,
        ale_data.is_ipv6,
        callout_data,
        clone,
        event_data_offset,
        address,
        inbound,
        ale_data.interface_index,
        ale_data.sub_interface_index,
    )?))
}

fn discard_pending_connections<T: Connection>(device: &Device, connections: &[T]) {
    let instance_ids: Vec<u64> = connections
        .iter()
        .map(Connection::get_instance_id)
        .collect();
    device.discard_pending_connection_instances(&instance_ids);
}

pub(crate) fn emit_connection_end_v4(device: &Device, conn: ConnectionV4, process_id: u64) {
    let info = protocol::info::connection_end_event_v4_info(
        if conn.process_id == 0 {
            process_id
        } else {
            conn.process_id
        },
        conn.get_direction() as u8,
        u8::from(conn.protocol),
        conn.local_address.0,
        conn.remote_address.0,
        conn.local_port,
        conn.remote_port,
    );
    let _ = device.event_queue.push(info);
}

pub(crate) fn emit_connection_end_v6(device: &Device, conn: ConnectionV6, process_id: u64) {
    let info = protocol::info::connection_end_event_v6_info(
        if conn.process_id == 0 {
            process_id
        } else {
            conn.process_id
        },
        conn.get_direction() as u8,
        u8::from(conn.protocol),
        conn.local_address.0,
        conn.remote_address.0,
        conn.local_port,
        conn.remote_port,
    );
    let _ = device.event_queue.push(info);
}

struct UdpFlowContext {
    key: Key,
    process_id: u64,
    connection_instance_id: u64,
    endpoint_handle: Option<u64>,
}

pub(crate) fn reclaim_udp_flow_context(
    device: &Device,
    flow_context: u64,
    connection_instance_id: u64,
) {
    if device
        .udp_flow_cache
        .cancel_registration(flow_context, connection_instance_id)
    {
        unsafe {
            drop(Box::from_raw(flow_context as *mut UdpFlowContext));
        }
    }
}

/// Associates the cached UDP tuple with WFP's native ALE-flow lifetime.
///
/// Endpoint lifetime tracking is established independently at authorization and
/// remains valid even if WFP rejects this flow-context association.
///
/// The registration table owns the identifiers needed to retire stale contexts
/// during periodic cleanup and to remove every remaining context during unload.
/// WFP owns `flow_context` after association succeeds and returns it exactly once
/// through `udp_flow_delete` when the peer flow expires or its socket closes.
fn associate_udp_flow_context(
    device: &Device,
    data: &CalloutData,
    key: Key,
    endpoint_handle: Option<u64>,
    connection_instance_id: u64,
) {
    if data.has_flow_context() {
        return;
    }
    let Some(flow_id) = data.get_flow_handle() else {
        crate::err!("UDP flow has no WFP flow handle: {}", key);
        return;
    };

    if connection_instance_id == 0 {
        return;
    }
    let registration = UdpFlowRegistration::new(
        flow_id,
        data.get_layer_id(),
        data.get_callout_id(),
        connection_instance_id,
    );
    let flow_context = Box::into_raw(Box::new(UdpFlowContext {
        key,
        process_id: data.get_process_id().unwrap_or(0),
        connection_instance_id,
        endpoint_handle,
    })) as u64;

    if !device.udp_flow_cache.register(flow_context, registration) {
        unsafe {
            drop(Box::from_raw(flow_context as *mut UdpFlowContext));
        }
        return;
    }

    if let Err(err) = data.associate_flow_context(flow_context) {
        // Normally a failed FwpsFlowAssociateContext call never transfers
        // ownership to WFP. Keep the conditional as a guard for the termination
        // race where flowDeleteFn has already claimed the registration.
        reclaim_udp_flow_context(device, flow_context, connection_instance_id);
        crate::err!("failed to associate UDP flow {}: {}", key, err);
        return;
    }

    // From this point WFP owns the context. flowDeleteFn may already have claimed
    // it while FwpsFlowAssociateContext0 was returning.
    if device
        .udp_flow_cache
        .mark_associated(flow_context, connection_instance_id)
    {
        // Touch only the exact cache instance that received this context, so a
        // concurrently reused tuple cannot record activity on its replacement.
        let _ = device
            .connection_cache
            .touch_connection_instance(&key, connection_instance_id);
    }
}

/// WFP invokes this after a UDP ALE flow reaches its native idle timeout or its
/// socket closes.  The context is driver-owned again on entry; the normal path
/// claims and frees it while the callback barrier keeps Device alive.
pub(crate) unsafe extern "system" fn udp_flow_delete(
    layer_id: u16,
    callout_id: u32,
    flow_context: u64,
) {
    // Acquire the flow-delete half of the common callback barrier before
    // dereferencing either Device or the opaque flow context.  During unload
    // classify admission is closed first, but this half remains open while
    // prepare_unload removes WFP contexts and receives their callbacks.
    let Some(callback_admission) = wdk::callback_barrier::CALLBACK_BARRIER.enter_flow_delete()
    else {
        return;
    };
    if !callback_admission.is_active() {
        // PREPARED and final-drain callbacks are counted for code lifetime but
        // cannot safely resolve Device or interpret an opaque context.
        return;
    }

    if flow_context == 0 {
        return;
    }

    // The flow cache is part of Device.  Resolve Device while the barrier
    // reference is held, then validate/claim the context through that cache.
    // This intentionally avoids reading a flow-cache pointer out of an
    // untrusted raw context before the registry has accepted the callback.
    let Some(device) = crate::entry::get_device() else {
        // Flow contexts are created only after Device has been published.  A
        // missing pointer is therefore an abnormal teardown/init race; leaking
        // the opaque allocation is safer than touching memory whose owner may
        // already have been destroyed.
        return;
    };

    let Some(reclaim_only) =
        device
            .udp_flow_cache
            .begin_callback(flow_context, layer_id, callout_id)
    else {
        // A duplicate, mismatched, or already-reclaimed callback has no
        // ownership left to release. In particular, never reconstruct a Box for
        // an unknown ID or for a reused address belonging to another callout.
        return;
    };
    let context = unsafe { Box::from_raw(flow_context as *mut UdpFlowContext) };

    // Periodic cleanup and unload have already retired (or are discarding) the
    // corresponding cache state.  Their callbacks only reclaim the WFP
    // allocation; this also avoids re-entering Device while
    // FwpsFlowRemoveContext0 completes synchronously inside the cleanup path.
    if reclaim_only {
        device.udp_flow_cache.finish_callback();
        return;
    }

    if let Some(endpoint_handle) = context.endpoint_handle {
        let mut endpoint_cache = device.udp_endpoint_cache.write_lock();
        let _ =
            endpoint_cache.dissociate(endpoint_handle, context.key, context.connection_instance_id);
    }

    let key = context.key;
    if key.is_ipv6() {
        if let Some(conn) = device
            .connection_cache
            .end_connection_instance_v6(key, context.connection_instance_id)
        {
            discard_pending_connections(device, core::slice::from_ref(&conn));
            emit_connection_end_v6(device, conn, context.process_id);
        }
    } else if let Some(conn) = device
        .connection_cache
        .end_connection_instance_v4(key, context.connection_instance_id)
    {
        discard_pending_connections(device, core::slice::from_ref(&conn));
        emit_connection_end_v4(device, conn, context.process_id);
    }

    device.udp_flow_cache.finish_callback();
}

fn end_udp_endpoint(device: &Device, endpoint_handle: u64, process_id: u64) {
    let endpoint = {
        let mut endpoint_cache = device.udp_endpoint_cache.write_lock();
        endpoint_cache.take(endpoint_handle)
    };
    let Some(endpoint) = endpoint else {
        return;
    };

    let mut ended_v4 = Vec::new();
    let mut ended_v6 = Vec::new();
    for peer in endpoint {
        let key = peer.key;
        if key.is_ipv6() {
            if let Some(conn) = device
                .connection_cache
                .end_connection_instance_v6(key, peer.instance_id)
            {
                ended_v6.push(conn);
            }
        } else if let Some(conn) = device
            .connection_cache
            .end_connection_instance_v4(key, peer.instance_id)
        {
            ended_v4.push(conn);
        }
    }

    discard_pending_connections(device, &ended_v4);
    discard_pending_connections(device, &ended_v6);
    for conn in ended_v4 {
        emit_connection_end_v4(device, conn, process_id);
    }
    for conn in ended_v6 {
        emit_connection_end_v6(device, conn, process_id);
    }
}

fn end_local_endpoint_v4(
    device: &Device,
    protocol: IpProtocol,
    local_port: u16,
    local_address: Option<IpAddress>,
    process_id: u64,
) {
    if let Some(conns) = device.connection_cache.end_all_on_endpoint_v4(
        (protocol, local_port),
        local_address,
        (process_id != 0).then_some(process_id),
    ) {
        discard_pending_connections(device, &conns);
        for conn in conns {
            emit_connection_end_v4(device, conn, process_id);
        }
    }
}

fn end_local_endpoint_v6(
    device: &Device,
    protocol: IpProtocol,
    local_port: u16,
    local_address: Option<IpAddress>,
    process_id: u64,
) {
    if let Some(conns) = device.connection_cache.end_all_on_endpoint_v6(
        (protocol, local_port),
        local_address,
        (process_id != 0).then_some(process_id),
    ) {
        discard_pending_connections(device, &conns);
        for conn in conns {
            emit_connection_end_v6(device, conn, process_id);
        }
    }
}

pub fn endpoint_closure_v4(data: CalloutData) {
    type Fields = layer::FieldsAleEndpointClosureV4;
    let Some(device) = crate::entry::get_device() else {
        return;
    };
    let process_id = data.get_process_id().unwrap_or(0);
    let protocol = get_protocol_if_present(&data, Fields::IpProtocol as usize);

    // UDP closure is socket-level and may omit its remote tuple. A concrete
    // endpoint handle is authoritative: consume its exact peers when tracked and
    // otherwise ignore the indication. Falling back by local port for an unknown or
    // repeated handle could end bookkeeping for a replacement socket, and avoiding
    // that fallback removes the need to retain endpoint tombstones forever.
    if matches!(protocol, Some(IpProtocol::Udp)) {
        if let Some(endpoint_handle) = udp_endpoint_handle(&data) {
            end_udp_endpoint(device, endpoint_handle, process_id);
            return;
        }

        let Some(local_port) = get_u16_if_present(&data, Fields::IpLocalPort as usize) else {
            return;
        };
        end_local_endpoint_v4(
            device,
            IpProtocol::Udp,
            local_port,
            get_ipv4_address_if_present(&data, Fields::IpLocalAddress as usize),
            process_id,
        );
        return;
    }

    let Some(protocol) = protocol else {
        // A generic UDP closure can omit the protocol as well as the remote tuple.
        // The endpoint map contains only UDP associations, so it remains safe to
        // consume a known handle here. An unknown handle cannot be matched safely.
        if let Some(endpoint_handle) = udp_endpoint_handle(&data) {
            end_udp_endpoint(device, endpoint_handle, process_id);
        }
        return;
    };

    let (Some(local_address), Some(local_port), Some(remote_address), Some(remote_port)) = (
        get_ipv4_address_if_present(&data, Fields::IpLocalAddress as usize),
        get_u16_if_present(&data, Fields::IpLocalPort as usize),
        get_ipv4_address_if_present(&data, Fields::IpRemoteAddress as usize),
        get_u16_if_present(&data, Fields::IpRemotePort as usize),
    ) else {
        return;
    };

    let key = Key {
        protocol,
        local_address,
        local_port,
        remote_address,
        remote_port,
    };

    if let Some(conn) = device.connection_cache.end_connection_v4(key) {
        discard_pending_connections(device, core::slice::from_ref(&conn));
        emit_connection_end_v4(device, conn, process_id);
    }
}

pub fn endpoint_closure_v6(data: CalloutData) {
    type Fields = layer::FieldsAleEndpointClosureV6;
    let Some(device) = crate::entry::get_device() else {
        return;
    };
    let process_id = data.get_process_id().unwrap_or(0);
    let protocol = get_protocol_if_present(&data, Fields::IpProtocol as usize);

    // See endpoint_closure_v4 for why a present but unknown handle is ignored
    // instead of retained as a tombstone or converted to a local-port sweep.
    if matches!(protocol, Some(IpProtocol::Udp)) {
        if let Some(endpoint_handle) = udp_endpoint_handle(&data) {
            end_udp_endpoint(device, endpoint_handle, process_id);
            return;
        }

        let Some(local_port) = get_u16_if_present(&data, Fields::IpLocalPort as usize) else {
            return;
        };
        end_local_endpoint_v6(
            device,
            IpProtocol::Udp,
            local_port,
            get_ipv6_address_if_present(&data, Fields::IpLocalAddress as usize),
            process_id,
        );
        return;
    }

    let Some(protocol) = protocol else {
        if let Some(endpoint_handle) = udp_endpoint_handle(&data) {
            end_udp_endpoint(device, endpoint_handle, process_id);
        }
        return;
    };

    let (Some(local_address), Some(local_port), Some(remote_address), Some(remote_port)) = (
        get_ipv6_address_if_present(&data, Fields::IpLocalAddress as usize),
        get_u16_if_present(&data, Fields::IpLocalPort as usize),
        get_ipv6_address_if_present(&data, Fields::IpRemoteAddress as usize),
        get_u16_if_present(&data, Fields::IpRemotePort as usize),
    ) else {
        return;
    };

    let key = Key {
        protocol,
        local_address,
        local_port,
        remote_address,
        remote_port,
    };

    if let Some(conn) = device.connection_cache.end_connection_v6(key) {
        discard_pending_connections(device, core::slice::from_ref(&conn));
        emit_connection_end_v6(device, conn, process_id);
    }
}

/// Refreshes the owning process when a TCP or UDP ALE flow becomes active.
///
/// WFP indicates TCP here after the three-way handshake completes. UDP has no
/// handshake, so its flow is indicated immediately after `ALE_AUTH_CONNECT` or
/// `ALE_AUTH_RECV_ACCEPT` authorizes the first packet for a remote tuple.
///
/// The authorization layers normally cache the flow with its owning PID. This
/// layer provides a second opportunity to repair entries created by the packet
/// fallback with PID 0, or entries whose earlier attribution was less reliable
/// than the concrete application PID supplied for the established flow.
///
/// This does not help flows that were already active before the driver loaded:
/// successful reauthorization does not produce another flow-established
/// indication.
///
/// Registered as an inspection callout.
pub fn ale_flow_established_monitor(data: CalloutData) {
    let Some(device) = crate::entry::get_device() else {
        return;
    };
    let process_id = data.get_process_id().filter(|pid| *pid != 0);

    let key = match data.get_layer() {
        layer::Layer::AleFlowEstablishedV4 => {
            type Fields = layer::FieldsAleFlowEstablishedV4;

            let Some(protocol) = get_protocol_if_present(&data, Fields::IpProtocol as usize) else {
                return;
            };
            if !matches!(protocol, IpProtocol::Tcp | IpProtocol::Udp) {
                return;
            }

            let (Some(local_address), Some(local_port), Some(remote_address), Some(remote_port)) = (
                get_ipv4_address_if_present(&data, Fields::IpLocalAddress as usize),
                get_u16_if_present(&data, Fields::IpLocalPort as usize),
                get_ipv4_address_if_present(&data, Fields::IpRemoteAddress as usize),
                get_u16_if_present(&data, Fields::IpRemotePort as usize),
            ) else {
                return;
            };

            Key {
                protocol,
                local_address,
                local_port,
                remote_address,
                remote_port,
            }
        }
        layer::Layer::AleFlowEstablishedV6 => {
            type Fields = layer::FieldsAleFlowEstablishedV6;

            let Some(protocol) = get_protocol_if_present(&data, Fields::IpProtocol as usize) else {
                return;
            };
            if !matches!(protocol, IpProtocol::Tcp | IpProtocol::Udp) {
                return;
            }

            let (Some(local_address), Some(local_port), Some(remote_address), Some(remote_port)) = (
                get_ipv6_address_if_present(&data, Fields::IpLocalAddress as usize),
                get_u16_if_present(&data, Fields::IpLocalPort as usize),
                get_ipv6_address_if_present(&data, Fields::IpRemoteAddress as usize),
                get_u16_if_present(&data, Fields::IpRemotePort as usize),
            ) else {
                return;
            };

            Key {
                protocol,
                local_address,
                local_port,
                remote_address,
                remote_port,
            }
        }
        _ => return,
    };

    if matches!(key.protocol, IpProtocol::Udp) {
        let endpoint_handle = udp_endpoint_handle(&data);
        // Authorization records the exact cache instance under the endpoint
        // handle. Resolve and validate it while both endpoint and connection
        // guards are held, so endpoint closure cannot turn an old flow callback
        // into a tuple-only match against a replacement connection.
        let connection_instance_id = if let Some(endpoint_handle) = endpoint_handle {
            let endpoint_cache = device.udp_endpoint_cache.read_lock();
            endpoint_cache.with_instance_id(endpoint_handle, &key, |instance_id| {
                device
                    .connection_cache
                    .with_live_connection_instance(&key, instance_id, Some)
            })
        } else {
            device.connection_cache.get_connection_instance_id(&key)
        };
        let Some(connection_instance_id) = connection_instance_id else {
            return;
        };

        // Refresh attribution before exposing the context to WFP: a flow can begin
        // terminating as soon as it has been associated. Use the same exact
        // instance selected above rather than a second tuple-only update.
        if let Some(process_id) = process_id {
            device.connection_cache.update_process_id_instance(
                &key,
                connection_instance_id,
                process_id,
            );
        }
        associate_udp_flow_context(device, &data, key, endpoint_handle, connection_instance_id);
    } else if let Some(process_id) = process_id {
        // TCP has no endpoint-peer map; preserve its existing tuple attribution
        // path. The UDP path above is protected by the endpoint instance identity.
        device.connection_cache.update_process_id(&key, process_id);
    }
}
