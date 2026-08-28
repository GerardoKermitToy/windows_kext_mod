use crate::connection::{Connection, ConnectionV4, ConnectionV6, Direction, Verdict};
use crate::connection_map::Key;
use crate::device::{Device, Packet};
use alloc::string::String;

use crate::info;
use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv6Address, IPV4_HEADER_LEN, IPV6_HEADER_LEN,
};
use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer::{
    self, FieldsAleAuthConnectV4, FieldsAleAuthConnectV6, FieldsAleAuthRecvAcceptV4,
    FieldsAleAuthRecvAcceptV6, ValueType,
};
use wdk::filter_engine::net_buffer::NetBufferList;
use wdk::filter_engine::packet::{Injector, TransportPacketList};

// ALE Layers

#[derive(Debug)]
#[allow(dead_code)]
struct AleLayerData {
    is_ipv6: bool,
    reauthorize: bool,
    process_id: u64,
    protocol: IpProtocol,
    direction: Direction,
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
        direction: Direction::Outbound,
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
        direction: Direction::Outbound,
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
        direction: Direction::Inbound,
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
        direction: Direction::Inbound,
        local_ip: get_ipv6_address(&data, Fields::IpLocalAddress as usize),
        local_port: data.get_value_u16(Fields::IpLocalPort as usize),
        remote_ip: get_ipv6_address(&data, Fields::IpRemoteAddress as usize),
        remote_port: data.get_value_u16(Fields::IpRemotePort as usize),
        interface_index: get_u32_or_zero(&data, Fields::InterfaceIndex as usize),
        sub_interface_index: get_u32_or_zero(&data, Fields::SubInterfaceIndex as usize),
    };

    ale_layer_auth(data, ale_data);
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
    if !layer_data.is_null()
        && (device
            .injector
            .was_network_packet_injected_by_self(layer_data as _, ale_data.is_ipv6)
            || device
                .injector
                .was_transport_packet_injected_by_self(layer_data as _))
    {
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
    // permit and let the packet layer classify. Inbound UDP does not take this
    // branch; it is authorized at ALE_AUTH_RECV_ACCEPT.
    if matches!(ale_data.protocol, IpProtocol::Udp)
        && matches!(ale_data.direction, Direction::Outbound)
    {
        // Only register once. A cached connection may already carry a verdict,
        // and overwriting it with Undecided would send it for a decision again.
        let known = if ale_data.is_ipv6 {
            device
                .connection_cache
                .read_connection_v6(&key, |_| -> Option<()> { Some(()) })
        } else {
            device
                .connection_cache
                .read_connection_v4(&key, |_| -> Option<()> { Some(()) })
        };

        if known.is_none() {
            crate::dbg!(
                "ale layer registering udp connection for packet layer: {} PID: {}",
                key,
                ale_data.process_id
            );
            if ale_data.is_ipv6 {
                match ConnectionV6::from_key(&key, ale_data.process_id, ale_data.direction) {
                    Ok(conn) => device.connection_cache.add_connection_v6(conn),
                    Err(err) => crate::err!("failed to build connection: {}", err),
                }
            } else {
                match ConnectionV4::from_key(&key, ale_data.process_id, ale_data.direction) {
                    Ok(conn) => device.connection_cache.add_connection_v4(conn),
                    Err(err) => crate::err!("failed to build connection: {}", err),
                }
            }
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
    let verdict = if ale_data.is_ipv6 {
        device
            .connection_cache
            .read_connection_v6(&key, |conn| -> Option<Verdict> {
                // Function is behind spin lock, just copy and return.
                Some(conn.verdict)
            })
    } else {
        device
            .connection_cache
            .read_connection_v4(&ale_data.as_key(), |conn| -> Option<Verdict> {
                // Function is behind spin lock, just copy and return.
                Some(conn.verdict)
            })
    };

    // Connection already in cache.
    if let Some(verdict) = verdict {
        crate::dbg!("processing existing connection: {} {}", key, verdict);
        match verdict {
            // No verdict yet
            Verdict::Undecided => {
                crate::dbg!("saving packet: {}", key);
                // Connection is already pended. Save packet and wait for verdict.
                match save_packet(device, &mut data, &ale_data, false) {
                    Ok(packet) => {
                        let info = device.packet_cache.push(
                            (key, packet),
                            ale_data.process_id,
                            ale_data.direction,
                            true,
                        );
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
                    && matches!(ale_data.direction, Direction::Outbound)
                {
                    // If this is Portmaster's own outbound connection, clear the write flag
                    // to prevent subsequent filters in the chain from overriding the permit action.
                    // This prevents other firewall applications from blocking Portmaster's own connections.
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
                if let Direction::Outbound = ale_data.direction {
                    // Handled by packet layer.
                    data.action_permit();
                } else {
                    // Inbound authorization is enforced here.
                    data.action_block_hard();
                }
            }
            Verdict::Drop => {
                if let Direction::Outbound = ale_data.direction {
                    // Handled by packet layer.
                    data.action_permit();
                } else {
                    // Inbound authorization is enforced here.
                    data.block_and_absorb();
                }
            }
        }
    } else {
        crate::dbg!("pending connection: {} {}", key, ale_data.direction);
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

        // Connection is not in cache, add it before publishing the request. A
        // verdict can arrive as soon as the event becomes visible to user space.
        crate::dbg!(
            "ale layer adding connection: {} PID: {}",
            key,
            ale_data.process_id
        );
        if ale_data.is_ipv6 {
            match ConnectionV6::from_key(&key, ale_data.process_id, ale_data.direction) {
                Ok(conn) => device.connection_cache.add_connection_v6(conn),
                Err(err) => {
                    crate::err!("failed to build connection: {}", err);
                    if let Err(complete_err) = device.inject_packet(packet, true) {
                        crate::err!("failed to complete ALE operation: {}", complete_err);
                    }
                    return;
                }
            }
        } else {
            match ConnectionV4::from_key(&key, ale_data.process_id, ale_data.direction) {
                Ok(conn) => device.connection_cache.add_connection_v4(conn),
                Err(err) => {
                    crate::err!("failed to build connection: {}", err);
                    if let Err(complete_err) = device.inject_packet(packet, true) {
                        crate::err!("failed to complete ALE operation: {}", complete_err);
                    }
                    return;
                }
            }
        }

        let info = device.packet_cache.push(
            (key, packet),
            ale_data.process_id,
            ale_data.direction,
            true,
        );
        if let Some(info) = info {
            let _ = device.event_queue.push(info);
        }

        // Drop packet. It will be re-injected after Portmaster returns a verdict.
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
    if ale_data.protocol == IpProtocol::Tcp {
        if let Direction::Outbound = ale_data.direction {
            // Only time a packet data is missing is during connect state of outbound TCP connection.
            // Don't save packet list only if connection is outbound, reauthorize is false and the protocol is TCP.
            save_packet_list = ale_data.reauthorize;
        }
    };
    if save_packet_list {
        packet_list = create_packet_list(device, callout_data, ale_data)?;
    }
    if pend && matches!(ale_data.direction, Direction::Inbound) && packet_list.is_none() {
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
    if callout_data.get_layer_data().is_null() {
        return Ok(None);
    }

    let mut nbl = NetBufferList::new(callout_data.get_layer_data() as _);
    let mut inbound = false;
    let mut event_data_offset = 0;
    if let Direction::Inbound = ale_data.direction {
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

    Ok(Some(Injector::from_ale_callout(
        ale_data.is_ipv6,
        callout_data,
        clone,
        event_data_offset,
        address,
        inbound,
        ale_data.interface_index,
        ale_data.sub_interface_index,
    )))
}

pub fn endpoint_closure_v4(data: CalloutData) {
    type Fields = layer::FieldsAleEndpointClosureV4;
    let Some(device) = crate::entry::get_device() else {
        return;
    };
    let ip_address_type = data.get_value_type(Fields::IpLocalAddress as usize);
    // The remote endpoint is checked as well, not just the local one. WFP leaves
    // IpRemoteAddress and IpRemotePort as FWP_EMPTY for closures that have no
    // remote peer (a listening socket, for example). Reading them regardless
    // returns whatever the union happens to hold, and the resulting key either
    // matches no cached connection - so the entry is never removed and the cache
    // grows - or matches an unrelated one and ends the wrong connection.
    //
    // The v6 path already validates both addresses; this brings v4 in line.
    let remote_address_type = data.get_value_type(Fields::IpRemoteAddress as usize);
    let remote_port_type = data.get_value_type(Fields::IpRemotePort as usize);
    let remote_present = matches!(remote_address_type, ValueType::FwpUint32)
        && matches!(remote_port_type, ValueType::FwpUint16);

    if matches!(ip_address_type, ValueType::FwpUint32) && remote_present {
        let key = Key {
            protocol: get_protocol(&data, Fields::IpProtocol as usize),
            local_address: get_ipv4_address(&data, Fields::IpLocalAddress as usize),
            local_port: data.get_value_u16(Fields::IpLocalPort as usize),
            remote_address: get_ipv4_address(&data, Fields::IpRemoteAddress as usize),
            remote_port: data.get_value_u16(Fields::IpRemotePort as usize),
        };

        let conn = device.connection_cache.end_connection_v4(key);
        if let Some(conn) = conn {
            let info = protocol::info::connection_end_event_v4_info(
                data.get_process_id().unwrap_or(0),
                conn.get_direction() as u8,
                u8::from(get_protocol(&data, Fields::IpProtocol as usize)),
                conn.local_address.0,
                conn.remote_address.0,
                conn.local_port,
                conn.remote_port,
            );
            let _ = device.event_queue.push(info);
        }
    } else {
        // Invalid ip address type. Just ignore the error.
        // err!(
        //     device.logger,
        //     "unknown ipv4 address type: {:?}",
        //     ip_address_type
        // );
    }
}

pub fn endpoint_closure_v6(data: CalloutData) {
    type Fields = layer::FieldsAleEndpointClosureV6;
    let Some(device) = crate::entry::get_device() else {
        return;
    };
    let local_ip_address_type = data.get_value_type(Fields::IpLocalAddress as usize);
    let remote_ip_address_type = data.get_value_type(Fields::IpRemoteAddress as usize);
    // Ports are validated too: the addresses being present does not guarantee the
    // port fields are, and an unpopulated port would silently become part of the
    // key. See endpoint_closure_v4 for the consequences.
    let ports_present = matches!(
        data.get_value_type(Fields::IpLocalPort as usize),
        ValueType::FwpUint16
    ) && matches!(
        data.get_value_type(Fields::IpRemotePort as usize),
        ValueType::FwpUint16
    );

    if let ValueType::FwpByteArray16Type = local_ip_address_type {
        if matches!(remote_ip_address_type, ValueType::FwpByteArray16Type) && ports_present {
            let key = Key {
                protocol: get_protocol(&data, Fields::IpProtocol as usize),
                local_address: get_ipv6_address(&data, Fields::IpLocalAddress as usize),
                local_port: data.get_value_u16(Fields::IpLocalPort as usize),
                remote_address: get_ipv6_address(&data, Fields::IpRemoteAddress as usize),
                remote_port: data.get_value_u16(Fields::IpRemotePort as usize),
            };

            let conn = device.connection_cache.end_connection_v6(key);
            if let Some(conn) = conn {
                let info = protocol::info::connection_end_event_v6_info(
                    data.get_process_id().unwrap_or(0),
                    conn.get_direction() as u8,
                    u8::from(get_protocol(&data, Fields::IpProtocol as usize)),
                    conn.local_address.0,
                    conn.remote_address.0,
                    conn.local_port,
                    conn.remote_port,
                );
                let _ = device.event_queue.push(info);
            }
        }
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
    let Some(process_id) = data.get_process_id().filter(|pid| *pid != 0) else {
        return;
    };

    let key = match data.layer {
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

    // update_process_id applies the PID precedence rules and safely does nothing
    // when no matching cached tuple exists.
    device.connection_cache.update_process_id(&key, process_id);
}

pub fn ale_resource_monitor(data: CalloutData) {
    let Some(device) = crate::entry::get_device() else {
        return;
    };

    match data.layer {
        layer::Layer::AleResourceAssignmentV4Discard => {
            type Fields = layer::FieldsAleResourceAssignmentV4;
            if let Some(conns) = device.connection_cache.end_all_on_endpoint_v4(
                (
                    get_protocol(&data, Fields::IpProtocol as usize),
                    data.get_value_u16(Fields::IpLocalPort as usize),
                ),
                get_ipv4_address_if_present(&data, Fields::IpLocalAddress as usize),
                data.get_process_id().filter(|pid| *pid != 0),
            ) {
                let process_id = data.get_process_id().unwrap_or(0);
                info!(
                    "Port {}/{} Ipv4 assign request discarded pid={}",
                    data.get_value_u16(Fields::IpLocalPort as usize),
                    get_protocol(&data, Fields::IpProtocol as usize),
                    process_id,
                );
                for conn in conns {
                    let info = protocol::info::connection_end_event_v4_info(
                        process_id,
                        conn.get_direction() as u8,
                        data.get_value_u8(Fields::IpProtocol as usize),
                        conn.local_address.0,
                        conn.remote_address.0,
                        conn.local_port,
                        conn.remote_port,
                    );
                    let _ = device.event_queue.push(info);
                }
            }
        }
        layer::Layer::AleResourceAssignmentV6Discard => {
            type Fields = layer::FieldsAleResourceAssignmentV6;
            if let Some(conns) = device.connection_cache.end_all_on_endpoint_v6(
                (
                    get_protocol(&data, Fields::IpProtocol as usize),
                    data.get_value_u16(Fields::IpLocalPort as usize),
                ),
                get_ipv6_address_if_present(&data, Fields::IpLocalAddress as usize),
                data.get_process_id().filter(|pid| *pid != 0),
            ) {
                let process_id = data.get_process_id().unwrap_or(0);
                info!(
                    "Port {}/{} Ipv6 assign request discarded pid={}",
                    data.get_value_u16(Fields::IpLocalPort as usize),
                    get_protocol(&data, Fields::IpProtocol as usize),
                    process_id,
                );
                for conn in conns {
                    let info = protocol::info::connection_end_event_v6_info(
                        process_id,
                        conn.get_direction() as u8,
                        data.get_value_u8(Fields::IpProtocol as usize),
                        conn.local_address.0,
                        conn.remote_address.0,
                        conn.local_port,
                        conn.remote_port,
                    );
                    let _ = device.event_queue.push(info);
                }
            }
        }
        layer::Layer::AleResourceReleaseV4 => {
            type Fields = layer::FieldsAleResourceReleaseV4;
            if let Some(conns) = device.connection_cache.end_all_on_endpoint_v4(
                (
                    get_protocol(&data, Fields::IpProtocol as usize),
                    data.get_value_u16(Fields::IpLocalPort as usize),
                ),
                get_ipv4_address_if_present(&data, Fields::IpLocalAddress as usize),
                data.get_process_id().filter(|pid| *pid != 0),
            ) {
                let process_id = data.get_process_id().unwrap_or(0);
                info!(
                    "Port {}/{} released pid={}",
                    data.get_value_u16(Fields::IpLocalPort as usize),
                    get_protocol(&data, Fields::IpProtocol as usize),
                    process_id,
                );
                for conn in conns {
                    let info = protocol::info::connection_end_event_v4_info(
                        process_id,
                        conn.get_direction() as u8,
                        data.get_value_u8(Fields::IpProtocol as usize),
                        conn.local_address.0,
                        conn.remote_address.0,
                        conn.local_port,
                        conn.remote_port,
                    );
                    let _ = device.event_queue.push(info);
                }
            }
        }
        layer::Layer::AleResourceReleaseV6 => {
            type Fields = layer::FieldsAleResourceReleaseV6;
            if let Some(conns) = device.connection_cache.end_all_on_endpoint_v6(
                (
                    get_protocol(&data, Fields::IpProtocol as usize),
                    data.get_value_u16(Fields::IpLocalPort as usize),
                ),
                get_ipv6_address_if_present(&data, Fields::IpLocalAddress as usize),
                data.get_process_id().filter(|pid| *pid != 0),
            ) {
                let process_id = data.get_process_id().unwrap_or(0);
                info!(
                    "Port {}/{} released pid={}",
                    data.get_value_u16(Fields::IpLocalPort as usize),
                    get_protocol(&data, Fields::IpProtocol as usize),
                    process_id,
                );
                for conn in conns {
                    let info = protocol::info::connection_end_event_v6_info(
                        process_id,
                        conn.get_direction() as u8,
                        data.get_value_u8(Fields::IpProtocol as usize),
                        conn.local_address.0,
                        conn.remote_address.0,
                        conn.local_port,
                        conn.remote_port,
                    );
                    let _ = device.event_queue.push(info);
                }
            }
        }
        _ => {}
    }
}
