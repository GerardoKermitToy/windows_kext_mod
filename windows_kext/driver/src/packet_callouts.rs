use alloc::string::{String, ToString};
use smoltcp::wire::{IPV4_HEADER_LEN, IPV6_HEADER_LEN};
use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer;
use wdk::filter_engine::net_buffer::{NetBufferList, NetBufferListIter};
use wdk::filter_engine::packet::InjectInfo;

use crate::connection::{
    Connection, ConnectionV4, ConnectionV6, Direction, RedirectInfo, Verdict, PM_DNS_PORT,
    PM_SPLIT_TUN_PORT, PM_SPN_PORT,
};
use crate::connection_cache::ConnectionCache;
use crate::connection_map::Key;
use crate::device::{Device, Packet};
use crate::packet_util::{
    get_icmp_echo_from_nbl, get_key_from_nbl_v4, get_key_from_nbl_v6, is_fragment_v4,
    is_fragment_v6, is_icmp_port_unreachable_from_nbl, is_tcp_reset_from_nbl,
    recalc_header_checksums, Redirect,
};

// IP packet layers
pub fn ip_packet_layer_outbound_v4(data: CalloutData) {
    type Fields = layer::FieldsOutboundIppacketV4;
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);

    ip_packet_layer(
        data,
        false,
        Direction::Outbound,
        interface_index,
        sub_interface_index,
        Fields::Flags as usize,
    );
}

pub fn ip_packet_layer_inbound_v4(data: CalloutData) {
    type Fields = layer::FieldsInboundIppacketV4;
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);
    ip_packet_layer(
        data,
        false,
        Direction::Inbound,
        interface_index,
        sub_interface_index,
        Fields::Flags as usize,
    );
}

pub fn ip_packet_layer_outbound_v6(data: CalloutData) {
    type Fields = layer::FieldsOutboundIppacketV6;
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);

    ip_packet_layer(
        data,
        true,
        Direction::Outbound,
        interface_index,
        sub_interface_index,
        Fields::Flags as usize,
    );
}

pub fn ip_packet_layer_inbound_v6(data: CalloutData) {
    type Fields = layer::FieldsInboundIppacketV6;
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);

    ip_packet_layer(
        data,
        true,
        Direction::Inbound,
        interface_index,
        sub_interface_index,
        Fields::Flags as usize,
    );
}

/// Largest retreat accepted from WFP metadata.
///
/// `NdisRetreatNetBufferDataStart` can fail, so the amount accepted from WFP
/// metadata is bounded and the retreat result is propagated to the caller. IPv4
/// headers cap at 60 bytes (IHL is 4 bits of 32-bit words); IPv6 base plus a
/// realistic extension header chain is bounded well below this.
const MAX_IP_HEADER_RETREAT: u32 = 128;

/// Retreats an inbound net buffer to the start of the IP header.
///
/// At the inbound packet layers the buffer starts past the IP header. The amount
/// to move back is *not* a constant: with IPv4 options the header is IHL*4 up to
/// 60 bytes, and for IPv6 the size reported by WFP includes any extension header
/// chain. Retreating a fixed 20 or 40 bytes leaves the buffer pointing inside the
/// header, so everything downstream parses option or extension bytes as an IP
/// header - which produced keys with protocol 0 and address 0.0.0.0.
///
/// `wfp_ip_header_size` is FWPS_METADATA_FIELD_IP_HEADER_SIZE, which is
/// authoritative for both families. It falls back to the fixed base header size
/// when absent, preserving the previous behaviour rather than guessing.
fn retreat_to_ip_header(
    nbl: &mut NetBufferList,
    ipv6: bool,
    wfp_ip_header_size: Option<u32>,
) -> Result<(), String> {
    let base = if ipv6 {
        IPV6_HEADER_LEN
    } else {
        IPV4_HEADER_LEN
    } as u32;

    // A value below the base header size cannot be right; treat it as missing.
    let size = match wfp_ip_header_size {
        Some(size) if size >= base && size <= MAX_IP_HEADER_RETREAT => size,
        _ => base,
    };

    nbl.retreat(size, true)
}

/// Returns true if the packet described by this indication is an individual IP
/// fragment rather than a whole datagram.
///
/// Reads the fragment fields from the IP header itself. For inbound packets the
/// header sits before the current data pointer, so the buffer is retreated first;
/// the retreat is undone when the local `NetBufferList` goes out of scope.
///
/// For IPv6 the fragment information sits in an extension header after the base
/// header, so the chain is walked rather than reading a fixed field.
fn is_ip_fragment(
    data: &CalloutData,
    ipv6: bool,
    direction: Direction,
    wfp_ip_header_size: Option<u32>,
) -> bool {
    // SAFETY: This helper is reached only from the IP-packet classify functions.
    // WFP owns their layer-data NBL chain and keeps it stable until the callback
    // returns; the iterator and every yielded wrapper remain inside this call.
    let mut nbls = unsafe { NetBufferListIter::new(data.get_layer_data() as _) };
    let Some(mut nbl) = nbls.next() else {
        return false;
    };

    if let Direction::Inbound = direction {
        if let Err(err) = retreat_to_ip_header(&mut nbl, ipv6, wfp_ip_header_size) {
            crate::err!("failed to retreat packet to IP header: {}", err);
            return false;
        }
    }

    if ipv6 {
        is_fragment_v6(&nbl)
    } else {
        is_fragment_v4(&nbl)
    }
}

struct ConnectionInfo {
    verdict: Verdict,
    process_id: u64,
    direction: Direction,
    instance_id: u64,
    redirect_info: Option<RedirectInfo>,
}

impl ConnectionInfo {
    fn from_connection<T: Connection>(conn: &T) -> Self {
        ConnectionInfo {
            verdict: conn.get_verdict(),
            process_id: conn.get_process_id(),
            direction: conn.get_direction(),
            instance_id: conn.get_instance_id(),
            redirect_info: conn.redirect_info(),
        }
    }
}

fn fast_track_pm_packets(key: &Key, _: Direction) -> bool {
    if key.local_port == PM_DNS_PORT
        || key.local_port == PM_SPN_PORT
        || key.local_port == PM_SPLIT_TUN_PORT
    {
        return key.local_address == key.remote_address;
    }

    return false;
}

fn ip_packet_layer(
    mut data: CalloutData,
    ipv6: bool,
    direction: Direction,
    interface_index: u32,
    sub_interface_index: u32,
    flags_index: usize,
) {
    // Make the default path as drop.
    data.block_and_absorb();

    // How far back an inbound buffer has to be moved to reach the IP header.
    // Read once here: it is needed both by the fragment check below and by every
    // retreat in the loop.
    let wfp_ip_header_size = data.get_ip_header_size();
    // Preserve the namespace/routing context for every clone that can outlive
    // this classify callback. The injector falls back to WFP's unspecified
    // compartment only when this metadata is absent.
    let compartment_id = data.get_compartment_id();

    // A fragmented datagram is indicated twice at this layer: once per individual
    // fragment, and once more as the reassembled whole (verified on Windows 11:
    // the reassembled indication carries FWP_CONDITION_FLAG_IS_REASSEMBLED and the
    // full 3028-byte length, while the fragments carry only 1500).
    //
    // Only the reassembled indication has a usable transport header. Individual
    // fragments other than the first begin directly with payload bytes, so reading
    // ports at the transport offset returns payload data - that is where the bogus
    // `0 -> 0` connection keys came from.
    //
    // Skip the individual fragments and decide on the reassembled packet, which
    // gives Portmaster the correct ports and the true datagram size.
    //
    // Note: the fragment flag is not set on every fragment indication (the first
    // pass reports flags=0x0), so the IP header's own fragment fields are the
    // reliable discriminator. A packet is an individual fragment when it either
    // has a non-zero offset or has the more-fragments bit set; an unfragmented
    // packet has neither, and the reassembled one is explicitly flagged.
    if !data.is_reassembled(flags_index)
        && is_ip_fragment(&data, ipv6, direction, wfp_ip_header_size)
    {
        data.action_permit();
        return;
    }

    let Some(device) = crate::entry::get_device() else {
        return;
    };
    // SAFETY: `ip_packet_layer` is called only by IP-packet classify handlers.
    // Their layer data is a WFP-owned NBL chain that stays live throughout this
    // callback, and the injection-state query is synchronous.
    if unsafe {
        device
            .injector
            .was_network_packet_injected_by_self(data.get_layer_data() as _, ipv6)
    } {
        data.action_permit();
        return;
    }

    // SAFETY: The same WFP callback contract keeps the complete NBL chain stable;
    // all yielded wrappers are consumed by this loop before the callback returns.
    let nbls = unsafe { NetBufferListIter::new(data.get_layer_data() as _) };
    for mut nbl in nbls {
        if let Direction::Inbound = direction {
            // The header is not part of the NBL for incoming packets. Move the beginning of the buffer back so we get access to it.
            // The NBL will auto advance after it loses scope.
            if let Err(err) = retreat_to_ip_header(&mut nbl, ipv6, wfp_ip_header_size) {
                crate::err!("failed to retreat packet to IP header: {}", err);
                return;
            }
        }

        // Get key from packet.
        let key = match if ipv6 {
            get_key_from_nbl_v6(&nbl, direction)
        } else {
            get_key_from_nbl_v4(&nbl, direction)
        } {
            Ok(key) => key,
            Err(err) => {
                crate::err!("failed to get key from nbl: {}", err);
                return;
            }
        };

        if fast_track_pm_packets(&key, direction) {
            data.action_permit();
            return;
        }

        // The local IP stack emits this response when a UDP datagram reaches a
        // port with no listener. It has no user-space owner or meaningful verdict
        // target, so permit it without publishing a PID-0 request to Portmaster.
        // Match the semantic equivalent in both families: ICMPv4 type 3/code 3
        // and ICMPv6 type 1/code 4.
        if matches!(direction, Direction::Outbound)
            && matches!(
                key.protocol,
                smoltcp::wire::IpProtocol::Icmp | smoltcp::wire::IpProtocol::Icmpv6
            )
            && is_icmp_port_unreachable_from_nbl(&nbl, ipv6)
        {
            data.action_permit();
            return;
        }

        // A TCP reset emitted by the local stack in response to a packet for
        // which no socket is listening has no user-space connection behind it.
        // There is no ALE record or process to attribute, so do not manufacture
        // a PID-0 connection and do not send a request that cannot be meaningfully
        // decided. Existing cached connections are deliberately handled below so
        // their configured policy still applies.
        if matches!(direction, Direction::Outbound)
            && key.protocol == smoltcp::wire::IpProtocol::Tcp
            && is_tcp_reset_from_nbl(&nbl, ipv6)
            && get_connection_info(&device.connection_cache, &key, ipv6, direction).is_none()
        {
            data.action_permit();
            return;
        }

        let mut send_request_to_portmaster = true;
        let mut process_id = 0;
        let mut connection_instance_id = None;

        // For loopback ICMP echo reply, WFP reports it as OUTBOUND but it is
        // semantically INBOUND. Track the effective direction separately.
        let mut effective_direction = direction;

        // Protocols without ports - ICMP above all - are not classified at the
        // ALE layers and are reported with PID 0 unless packet-specific attribution
        // below can resolve their originator.
        //
        // For an outbound packet the originator is available anyway, from the
        // thread this callout runs on. An application sending an echo request
        // travels down the stack synchronously on its own thread, so the current
        // process *is* the sender.
        //
        // Measured on Windows 11 with three concurrent `ping` processes: every
        // outbound ICMP indication carried the PID of the process that sent it, and
        // two pings to the same destination were told apart - which the destination
        // address alone cannot do. IRQL was DISPATCH_LEVEL throughout, where
        // PsGetCurrentProcessId is legal.
        //
        // Deliberately restricted to outbound. The same measurement showed inbound
        // indications carrying PID 0, System, and unrelated processes, because
        // receive processing happens in an arbitrary context - there the thread says
        // nothing about the packet. Measuring the transport and flow-established
        // layers did not help either: an echo reply is not indicated there at all,
        // because no socket is associated with it.
        //
        // An inbound echo reply is therefore matched against the request that caused
        // it, using the identifier the sender chose and the responder echoed back.
        if !matches!(
            key.protocol,
            smoltcp::wire::IpProtocol::Tcp | smoltcp::wire::IpProtocol::Udp
        ) {
            match direction {
                Direction::Outbound => {
                    if let Some(echo) = get_icmp_echo_from_nbl(&nbl, ipv6) {
                        if !echo.is_request {
                            // This is an echo reply reported as OUTBOUND. Two cases:
                            // 1. Reply to our own request (loopback or external): we
                            //    sent a request, this is the answer coming back. WFP
                            //    reports it as OUTBOUND (routing quirk). Semantically
                            //    it's inbound, and we have the request cached.
                            // 2. Our reply to someone else's request: they sent us a
                            //    request, this is our answer going out. WFP correctly
                            //    reports it as OUTBOUND, and we have no cached request.
                            //
                            // Distinguish by checking if we have a cached request.
                            let request_pid = {
                                let mut icmp_echo_cache = device.icmp_echo_cache.write_lock();
                                icmp_echo_cache
                                    .take_request_pid(key.remote_address, echo.identifier)
                            };

                            if let Some(pid) = request_pid {
                                // Case 1: Found our request > this is a reply to us.
                                // Correct direction to INBOUND for semantic accuracy.
                                effective_direction = Direction::Inbound;
                                process_id = pid;
                            } else {
                                // Case 2: No cached request > this is our reply to them.
                                // This is a kernel stack reply (automatic ICMP response).
                                // current_process_id() would return arbitrary DPC context,
                                // so use 0 (System/kernel) instead.
                                process_id = 0;
                            }
                        } else {
                            // This is a request. Use the current process as the sender.
                            process_id = wdk::utils::current_process_id();

                            // Remember the request so its reply can be attributed.
                            {
                                let mut icmp_echo_cache = device.icmp_echo_cache.write_lock();
                                icmp_echo_cache.insert_request(
                                    key.remote_address,
                                    echo.identifier,
                                    process_id,
                                );
                            }
                        }
                    } else {
                        // Not an ICMP echo (request or reply), but still outbound
                        // non-TCP/UDP (e.g., ICMP destination unreachable, ICMPv6
                        // neighbor discovery, router advertisement). These are kernel
                        // stack originated. current_process_id() returns arbitrary
                        // DPC context, so use 0 (System/kernel).
                        process_id = 0;
                    }
                }
                Direction::Inbound => {
                    // Inbound ICMP echo replies are straightforward: someone sent us
                    // a request, they're getting their reply back. Try to attribute
                    // it to their original request if we cached it.
                    if let Some(echo) = get_icmp_echo_from_nbl(&nbl, ipv6) {
                        if !echo.is_request {
                            process_id = {
                                let mut icmp_echo_cache = device.icmp_echo_cache.write_lock();
                                icmp_echo_cache
                                    .take_request_pid(key.remote_address, echo.identifier)
                                    .unwrap_or(0)
                            };
                        }
                    }
                }
            }
        }

        if matches!(
            key.protocol,
            smoltcp::wire::IpProtocol::Tcp | smoltcp::wire::IpProtocol::Udp
        ) {
            if let Some(mut conn_info) =
                get_connection_info(&device.connection_cache, &key, ipv6, direction)
            {
                // A new inbound connection must reach ALE_AUTH_RECV_ACCEPT so it
                // can be attributed and authorized there. Keep permitting it while
                // that authorization is still pending and the owning process is
                // unknown or System, but once ALE has cached a verdict or a concrete
                // application PID is known, enforce it at the packet layer below.
                //
                // Connections authorized by ALE_AUTH_CONNECT are intentionally not
                // bypassed here. Their packet path still handles temporary verdicts
                // and reverse redirect rewriting on received packets.
                if matches!(conn_info.direction, Direction::Inbound)
                    && matches!(conn_info.verdict, Verdict::Undecided)
                    && matches!(conn_info.process_id, 0 | 4)
                {
                    data.action_permit();
                    return;
                }

                process_id = conn_info.process_id;
                connection_instance_id = Some(conn_info.instance_id);
                // Check if there is action for this connection.
                match conn_info.verdict {
                    Verdict::Undecided | Verdict::Accept | Verdict::Block | Verdict::Drop => {}
                    Verdict::PermanentAccept => {
                        send_request_to_portmaster = false;
                        data.action_permit();
                    }
                    Verdict::PermanentBlock => {
                        send_request_to_portmaster = false;
                        data.action_block_hard();
                    }
                    Verdict::Undeterminable | Verdict::PermanentDrop | Verdict::Failed => {
                        send_request_to_portmaster = false;
                        data.block_and_absorb();
                    }
                    Verdict::RedirectNameServer
                    | Verdict::RedirectTunnel
                    | Verdict::RedirectSplitTunnel => {
                        if let Some(redirect_info) = conn_info.redirect_info.take() {
                            match clone_packet(
                                device,
                                nbl,
                                effective_direction,
                                ipv6,
                                key.is_loopback(),
                                compartment_id,
                                interface_index,
                                sub_interface_index,
                            ) {
                                Ok(mut packet) => match packet.redirect(redirect_info) {
                                    Ok(()) => {
                                        if let Err(err) = device.inject_packet(packet, false) {
                                            crate::err!("failed to inject packet: {}", err);
                                        }
                                    }
                                    Err(err) => {
                                        // The original packet is absorbed below. Drop an
                                        // unmodified or partially redirected clone rather
                                        // than bypassing the redirect policy.
                                        crate::err!("failed to redirect packet: {}", err);
                                    }
                                },
                                Err(err) => crate::err!("failed to clone packet: {}", err),
                            }
                        }

                        // This will block the original packet. Even if injection failed.
                        data.block_and_absorb();
                        continue;
                    }
                }
            } else if matches!(direction, Direction::Inbound) {
                // No connection exists yet. Let WFP continue to
                // ALE_AUTH_RECV_ACCEPT, where the owning PID is available and the
                // TCP/UDP connection will be pended and sent to Portmaster.
                data.action_permit();
                return;
            } else {
                // An outbound TCP/UDP packet should normally have been registered at
                // ALE_AUTH_CONNECT. Preserve the defensive fallback for packets that
                // reach this layer without a cache entry.
                process_id = 0;

                match device.connection_cache.register_connection(
                    &key,
                    process_id,
                    effective_direction,
                ) {
                    Ok(registration) => {
                        connection_instance_id = Some(registration.instance_id);
                        if registration.inserted {
                            crate::dbg!(
                                "packet layer added connection: {} PID: {}",
                                key,
                                process_id
                            );
                        } else {
                            crate::dbg!("connection registered concurrently: {}", key);
                        }
                    }
                    Err(err) => {
                        crate::err!("failed to build connection: {}", err);
                        return;
                    }
                }
            }
        }

        // Clone packet and send to Portmaster.
        if send_request_to_portmaster {
            let packet = match clone_packet(
                device,
                nbl,
                effective_direction,
                ipv6,
                key.is_loopback(),
                compartment_id,
                interface_index,
                sub_interface_index,
            ) {
                Ok(p) => p,
                Err(err) => {
                    crate::err!("failed to clone packet: {}", err);
                    return;
                }
            };

            if let Some(pending) = device.publish_pending_packet(
                (key, packet),
                connection_instance_id,
                process_id,
                effective_direction,
                false,
            ) {
                crate::dbg!(
                    "discarding packet queued after its connection ended: {}",
                    key
                );
                if let Err(err) = device.inject_packet(pending.packet, true) {
                    crate::err!("failed to discard stale pending packet: {}", err);
                }
            }
            data.block_and_absorb();
        }
    }
}

fn clone_packet(
    device: &Device,
    nbl: NetBufferList,
    direction: Direction,
    ipv6: bool,
    loopback: bool,
    compartment_id: Option<u32>,
    interface_index: u32,
    sub_interface_index: u32,
) -> Result<Packet, String> {
    let mut clones = nbl.clone_all(&device.network_allocator)?;
    let inbound = match direction {
        Direction::Outbound => false,
        Direction::Inbound => true,
    };

    for clone in &mut clones {
        let Some(data) = clone.get_data_mut() else {
            return Err("failed to access cloned packet data".to_string());
        };
        // Outbound packets intercepted at the IP layer may carry only a partial
        // pseudo-header checksum because the TCP/IP stack relies on NIC hardware
        // checksum offload to fill in the real value before transmission.
        // When this clone is later re-injected via FwpsInjectNetwork*Async (on
        // Accept/PermanentAccept verdict), it bypasses the NIC entirely, so offload
        // never runs. We must compute the full software checksum here. An IPv6
        // packet whose extension chain cannot be resolved must not enter the
        // pending cache with a checksum that can never be made valid.
        recalc_header_checksums(data, ipv6)?;
    }

    Ok(Packet::PacketLayer(
        clones,
        InjectInfo {
            ipv6,
            inbound,
            loopback,
            compartment_id,
            interface_index,
            sub_interface_index,
        },
    ))
}

fn get_connection_info(
    connection_cache: &ConnectionCache,
    key: &Key,
    ipv6: bool,
    packet_direction: Direction,
) -> Option<ConnectionInfo> {
    // A packet already in flight can arrive after endpoint closure. Preserve the
    // ended-entry fallback only on the outbound packet path, which TCP/UDP reaches
    // after ALE has registered any newly reused tuple. On the inbound path an
    // ended entry is indistinguishable from the first packet of a new inbound flow;
    // treating it as a miss lets that flow reach ALE_AUTH_RECV_ACCEPT for fresh
    // attribution and authorization.
    if ipv6 {
        let conn_info = connection_cache.read_connection_v6_for_packet(
            key,
            packet_direction,
            |conn: &ConnectionV6| -> Option<ConnectionInfo> {
                // Function is is behind spin lock. Just copy and return.
                Some(ConnectionInfo::from_connection(conn))
            },
        );
        return conn_info;
    } else {
        let conn_info = connection_cache.read_connection_v4_for_packet(
            key,
            packet_direction,
            |conn: &ConnectionV4| -> Option<ConnectionInfo> {
                // Function is is behind spin lock. Just copy and return.
                Some(ConnectionInfo::from_connection(conn))
            },
        );
        return conn_info;
    }
}
