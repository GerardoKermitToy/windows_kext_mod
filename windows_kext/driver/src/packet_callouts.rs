use alloc::string::{String, ToString};
use smoltcp::wire::{IPV4_HEADER_LEN, IPV6_HEADER_LEN};
use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer;
use wdk::filter_engine::net_buffer::{NetBufferList, NetBufferListClones, NetBufferListIter};
use wdk::filter_engine::packet::InjectInfo;

use crate::ale_policy::{classify_packet_injection, PacketInjectionAction};
use crate::connection::{
    Connection, ConnectionV4, ConnectionV6, Direction, RedirectInfo, Verdict, PM_DNS_PORT,
    PM_SPLIT_TUN_PORT, PM_SPN_PORT,
};
use crate::connection_cache::ConnectionCache;
use crate::connection_map::Key;
use crate::device::{Device, Packet};
use crate::packet_util::{inspect_packet, recalc_header_checksums, Redirect};

struct PacketLayerFields {
    interface_index: usize,
    sub_interface_index: usize,
    flags: usize,
}

// IP packet layers
pub fn ip_packet_layer_outbound_v4(data: CalloutData) {
    type Fields = layer::FieldsOutboundIppacketV4;
    ip_packet_layer(
        data,
        false,
        Direction::Outbound,
        PacketLayerFields {
            interface_index: Fields::InterfaceIndex as usize,
            sub_interface_index: Fields::SubInterfaceIndex as usize,
            flags: Fields::Flags as usize,
        },
    );
}

pub fn ip_packet_layer_inbound_v4(data: CalloutData) {
    type Fields = layer::FieldsInboundIppacketV4;
    ip_packet_layer(
        data,
        false,
        Direction::Inbound,
        PacketLayerFields {
            interface_index: Fields::InterfaceIndex as usize,
            sub_interface_index: Fields::SubInterfaceIndex as usize,
            flags: Fields::Flags as usize,
        },
    );
}

pub fn ip_packet_layer_outbound_v6(data: CalloutData) {
    type Fields = layer::FieldsOutboundIppacketV6;
    ip_packet_layer(
        data,
        true,
        Direction::Outbound,
        PacketLayerFields {
            interface_index: Fields::InterfaceIndex as usize,
            sub_interface_index: Fields::SubInterfaceIndex as usize,
            flags: Fields::Flags as usize,
        },
    );
}

pub fn ip_packet_layer_inbound_v6(data: CalloutData) {
    type Fields = layer::FieldsInboundIppacketV6;
    ip_packet_layer(
        data,
        true,
        Direction::Inbound,
        PacketLayerFields {
            interface_index: Fields::InterfaceIndex as usize,
            sub_interface_index: Fields::SubInterfaceIndex as usize,
            flags: Fields::Flags as usize,
        },
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

struct ConnectionInfo {
    verdict: Verdict,
    process_id: u64,
    direction: Direction,
    instance_id: u64,
    redirect_info: Option<RedirectInfo>,
}

impl ConnectionInfo {
    fn from_connection<T: Connection>(conn: &T) -> Self {
        let verdict = conn.get_verdict();
        ConnectionInfo {
            verdict,
            process_id: conn.get_process_id(),
            direction: conn.get_direction(),
            instance_id: conn.get_instance_id(),
            // Avoid a second redirect-policy dispatch for the overwhelmingly
            // common non-redirect verdicts.
            redirect_info: if matches!(
                verdict,
                Verdict::RedirectNameServer
                    | Verdict::RedirectTunnel
                    | Verdict::RedirectSplitTunnel
            ) {
                conn.redirect_info()
            } else {
                None
            },
        }
    }
}

#[inline]
fn fast_track_pm_packets(key: &Key) -> bool {
    (key.local_port == PM_DNS_PORT
        || key.local_port == PM_SPN_PORT
        || key.local_port == PM_SPLIT_TUN_PORT)
        && key.local_address == key.remote_address
}

fn ip_packet_layer(
    mut data: CalloutData,
    ipv6: bool,
    direction: Direction,
    fields: PacketLayerFields,
) {
    // Fail closed until a later path explicitly permits the indication. Do not
    // make this provisional action hard: the callback still needs to replace it.
    data.set_default_block_and_absorb();

    let layer_data = data.get_layer_data();
    let inbound = matches!(direction, Direction::Inbound);

    // SAFETY: `ip_packet_layer` is called only by IP-packet classify handlers.
    // WFP owns this NBL chain for the complete callback, and every yielded wrapper
    // remains inside it.
    let mut nbls = unsafe { NetBufferListIter::new(layer_data as _) };
    let Some(mut first_nbl) = nbls.next() else {
        return;
    };

    // Only inbound buffers need the IP-header size. Routing metadata is read
    // lazily below, once per indication, if any packet actually needs a clone.
    let wfp_ip_header_size = if inbound {
        data.get_ip_header_size()
    } else {
        None
    };
    let reassembled = data.is_reassembled(fields.flags);

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
    // Inspect the first NBL once and retain both its retreat and parsed metadata for
    // the main loop. Previously the fragment pass restored the inbound data offset,
    // then the normal pass retreated and read the same header again.
    let mut first_retreated = false;
    let mut first_inspection = None;
    if !reassembled {
        if !inbound {
            let inspection = inspect_packet(&first_nbl, ipv6, direction);
            if inspection.is_fragment {
                data.action_permit();
                return;
            }
            if inspection.metadata.is_ok() {
                first_inspection = Some(inspection);
            }
        } else {
            match retreat_to_ip_header(&mut first_nbl, ipv6, wfp_ip_header_size) {
                Ok(()) => {
                    first_retreated = true;
                    let inspection = inspect_packet(&first_nbl, ipv6, direction);
                    if inspection.is_fragment {
                        data.action_permit();
                        return;
                    }
                    if inspection.metadata.is_ok() {
                        first_inspection = Some(inspection);
                    }
                }
                Err(err) => {
                    // Preserve the self-injection bypass below. A non-self packet
                    // gets the same second retreat attempt the old normal pass made.
                    crate::err!("failed to retreat packet to IP header: {}", err);
                }
            }
        }
    }

    let Some(device) = crate::entry::get_device() else {
        return;
    };

    // Portmaster's own local redirect traffic and ICMP Port Unreachable responses
    // in either direction are unconditional permits. Their already parsed first packet does
    // not need the comparatively expensive WFP injection-state query.
    if let Some(metadata) = first_inspection.and_then(|inspection| inspection.metadata.ok()) {
        if fast_track_pm_packets(&metadata.key) || metadata.is_icmp_port_unreachable {
            data.action_permit();
            return;
        }
    }

    // SAFETY: The WFP-owned layer data is still live. The synchronous query
    // does not depend on the first net buffer's data offset.
    let network_injection_origin = unsafe {
        device
            .injector
            .network_packet_injection_origin(layer_data as _, ipv6)
    };
    let injection_action = classify_packet_injection(
        network_injection_origin.is_self_injected(),
        network_injection_origin.is_injected_by_other(),
        || {
            // SAFETY: The same WFP-owned NBL is still live. A transport clone can
            // be "other" relative to the network handle, so query this handle unless
            // the network result already proved local ownership.
            let origin = unsafe {
                device
                    .injector
                    .transport_packet_injection_origin(layer_data as _)
            };
            (origin.is_self_injected(), origin.is_injected_by_other())
        },
    );
    let injected_by_other = match injection_action {
        PacketInjectionAction::PermitSelfInjected => {
            data.action_permit();
            return;
        }
        PacketInjectionAction::Process { injected_by_other } => injected_by_other,
    };
    let mut routing_info = None;
    let mut other_injector_process_id = None;

    let mut first = true;
    for mut nbl in core::iter::once(first_nbl).chain(nbls) {
        let inspection = if first {
            first = false;
            if inbound && !first_retreated {
                // The first fragment probe can fail its retreat. Retry here after
                // the self-injection check, matching the previous two-pass path.
                if let Err(err) = retreat_to_ip_header(&mut nbl, ipv6, wfp_ip_header_size) {
                    crate::err!("failed to retreat packet to IP header: {}", err);
                    return;
                }
            }
            first_inspection
                .take()
                .unwrap_or_else(|| inspect_packet(&nbl, ipv6, direction))
        } else {
            if inbound {
                // At inbound packet layers the current offset follows the IP header.
                // The wrapper restores it automatically when this iteration ends.
                if let Err(err) = retreat_to_ip_header(&mut nbl, ipv6, wfp_ip_header_size) {
                    crate::err!("failed to retreat packet to IP header: {}", err);
                    return;
                }
            }
            inspect_packet(&nbl, ipv6, direction)
        };

        let packet_metadata = match inspection.metadata {
            Ok(metadata) => metadata,
            Err(err) => {
                crate::err!("failed to get key from nbl: {}", err);
                return;
            }
        };
        let mut key = packet_metadata.key;

        if fast_track_pm_packets(&key) || packet_metadata.is_icmp_port_unreachable {
            data.action_permit();
            return;
        }

        let transport_protocol = matches!(
            key.protocol,
            smoltcp::wire::IpProtocol::Tcp | smoltcp::wire::IpProtocol::Udp
        );
        // Read connection state once for policy or redirect rewriting.
        let connection_info = if transport_protocol {
            get_connection_info(
                &device.connection_cache,
                &key,
                ipv6,
                direction,
                !injected_by_other,
            )
        } else {
            None
        };

        // Resets never need a userspace verdict, but cached redirects must
        // rewrite their tuple below, even after the sending endpoint closes.
        if packet_metadata.is_tcp_reset
            && connection_info
                .as_ref()
                .and_then(|info| info.redirect_info.as_ref())
                .is_none()
        {
            data.action_permit();
            return;
        }

        let mut process_id = 0;
        let mut thread_id = 0;
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
        if !transport_protocol {
            match direction {
                Direction::Outbound => {
                    if let Some(echo) = packet_metadata.icmp_echo {
                        if !echo.is_request {
                            // WFP reports a loopback reply as OUTBOUND, so its source
                            // is the request's remote address. Match the reversed key,
                            // then normalize both the tuple and semantic direction.
                            // A normal outbound kernel reply to a remote ping must not
                            // consume an unrelated request with the same identifier.
                            let request = echo.loopback_reply_key(key).and_then(|reply_key| {
                                let mut icmp_echo_cache = device.icmp_echo_cache.write_lock();
                                icmp_echo_cache
                                    .take_request_identity(reply_key.remote_address, echo.identifier)
                                    .map(|identity| (reply_key, identity))
                            });

                            if let Some((reply_key, identity)) = request {
                                key = reply_key;
                                effective_direction = Direction::Inbound;
                                (process_id, thread_id) = identity;
                            } else {
                                // No matching local request: keep this a kernel reply.
                                // Its current process is an arbitrary DPC context.
                                process_id = 0;
                            }
                        } else {
                            // This is a request. Capture the sending thread's identity.
                            process_id = wdk::utils::current_process_id();
                            thread_id = wdk::utils::current_thread_id();

                            // Remember the request so its reply can be attributed.
                            {
                                let mut icmp_echo_cache = device.icmp_echo_cache.write_lock();
                                icmp_echo_cache.insert_request(
                                    key.remote_address,
                                    echo.identifier,
                                    process_id,
                                    thread_id,
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
                    // A received echo reply belongs to our original outbound
                    // request, not to the current receive-processing thread.
                    if let Some(echo) = packet_metadata.icmp_echo {
                        if !echo.is_request {
                            (process_id, thread_id) = {
                                let mut icmp_echo_cache = device.icmp_echo_cache.write_lock();
                                icmp_echo_cache
                                    .take_request_identity(key.remote_address, echo.identifier)
                                    .unwrap_or((0, 0))
                            };
                        }
                    }
                }
            }
        }

        if transport_protocol {
            if let Some(mut conn_info) = connection_info {
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
                        data.action_permit();
                        continue;
                    }
                    Verdict::PermanentBlock => {
                        data.action_block_hard();
                        continue;
                    }
                    Verdict::Undeterminable | Verdict::PermanentDrop | Verdict::Failed => {
                        data.block_and_absorb();
                        continue;
                    }
                    Verdict::RedirectNameServer
                    | Verdict::RedirectTunnel
                    | Verdict::RedirectSplitTunnel => {
                        if let Some(redirect_info) = conn_info.redirect_info.take() {
                            match clone_packet(
                                device,
                                nbl,
                                packet_inject_info(
                                    &data,
                                    &fields,
                                    &mut routing_info,
                                    effective_direction,
                                    ipv6,
                                    key.is_loopback(),
                                ),
                                CloneChecksum::RedirectWillRecalculate,
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
            } else if injected_by_other {
                // A foreign network injector can emit a packet after the native
                // application endpoint has already closed. It has no trustworthy
                // socket endpoint that this driver can use for connection lifetime
                // tracking: WinDivert, for example, shares one raw endpoint across
                // many unrelated tuples.
                //
                // Treat this as a stateless packet decision. The pending record has
                // no connection instance, so a permanent verdict cannot pollute a
                // later application connection that reuses the tuple. The current
                // process is the user-space injector that synchronously submitted
                // this outbound packet.
                process_id =
                    *other_injector_process_id.get_or_insert_with(wdk::utils::current_process_id);
                crate::dbg!(
                    "packet layer handling externally injected packet: {} PID: {}",
                    key,
                    process_id
                );
            } else {
                // An outbound TCP/UDP packet should normally have been registered at
                // ALE_AUTH_CONNECT. Preserve the defensive fallback for packets that
                // reach this layer without a cache entry, but mark it untracked: this
                // layer exposes no endpoint identity that could retire it on closure.
                process_id = 0;

                match device.connection_cache.register_untracked_connection(
                    &key,
                    process_id,
                    effective_direction,
                ) {
                    Ok(registration) => {
                        connection_instance_id = Some(registration.instance_id);
                        if registration.inserted {
                            crate::dbg!(
                                "packet layer added untracked connection: {} PID: {}",
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

        // Only temporary/stateless decisions reach the pending-packet path.
        let packet = match clone_packet(
            device,
            nbl,
            packet_inject_info(
                &data,
                &fields,
                &mut routing_info,
                effective_direction,
                ipv6,
                key.is_loopback(),
            ),
            CloneChecksum::Recalculate,
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
            thread_id,
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

enum CloneChecksum {
    Recalculate,
    RedirectWillRecalculate,
}

struct PacketRoutingInfo {
    compartment_id: Option<u32>,
    interface_index: u32,
    sub_interface_index: u32,
}

#[inline]
fn packet_inject_info(
    data: &CalloutData,
    fields: &PacketLayerFields,
    routing_info: &mut Option<PacketRoutingInfo>,
    direction: Direction,
    ipv6: bool,
    loopback: bool,
) -> InjectInfo {
    // WFP keeps indication-wide routing values stable for the whole callback.
    // Permit/block/drop paths need none of them; cloned NBLs share one snapshot.
    let routing_info = routing_info.get_or_insert_with(|| PacketRoutingInfo {
        compartment_id: data.get_compartment_id(),
        interface_index: data.get_value_u32(fields.interface_index),
        sub_interface_index: data.get_value_u32(fields.sub_interface_index),
    });
    InjectInfo {
        ipv6,
        inbound: matches!(direction, Direction::Inbound),
        loopback,
        compartment_id: routing_info.compartment_id,
        interface_index: routing_info.interface_index,
        sub_interface_index: routing_info.sub_interface_index,
    }
}

fn clone_packet(
    device: &Device,
    nbl: NetBufferList,
    inject_info: InjectInfo,
    checksum: CloneChecksum,
) -> Result<Packet, String> {
    let mut clones = nbl.clone_packets(&device.network_allocator)?;

    if matches!(checksum, CloneChecksum::Recalculate) {
        match &mut clones {
            NetBufferListClones::Single(clone) => {
                recalculate_clone_checksum(clone, inject_info.ipv6)?;
            }
            NetBufferListClones::Batch(clones) => {
                for clone in clones {
                    recalculate_clone_checksum(clone, inject_info.ipv6)?;
                }
            }
        }
    }

    Ok(match clones {
        NetBufferListClones::Single(clone) => Packet::Network(clone, inject_info),
        NetBufferListClones::Batch(clones) => Packet::NetworkBatch(clones, inject_info),
    })
}

fn recalculate_clone_checksum(clone: &mut NetBufferList, ipv6: bool) -> Result<(), String> {
    let Some(data) = clone.get_data_mut() else {
        return Err("failed to access cloned packet data".to_string());
    };
    // Outbound packets intercepted at the IP layer may carry only a partial
    // pseudo-header checksum because the TCP/IP stack asked the NIC to finish
    // checksum offload. Packet cloning copies the bytes into a fresh NBL but does
    // not copy the original checksum-offload metadata, so a pending clone needs
    // complete software checksums. Cached redirects defer this pass because they
    // immediately write the final addresses, port and checksum in one traversal.
    recalc_header_checksums(data, ipv6)
}

fn get_connection_info(
    connection_cache: &ConnectionCache,
    key: &Key,
    ipv6: bool,
    packet_direction: Direction,
    use_ended_fallback: bool,
) -> Option<ConnectionInfo> {
    // A packet already in flight can arrive after endpoint closure. Preserve the
    // ended-entry fallback only on the ordinary outbound packet path, which
    // TCP/UDP reaches after ALE has registered any newly reused tuple. A packet
    // injected by another driver has its own user-space originator and must not be
    // mistaken for retained history belonging to the application whose tuple it
    // copied. Inbound lookups likewise use live state only because the tuple can
    // identify a new flow awaiting ALE authorization.
    if ipv6 {
        let process = |conn: &ConnectionV6| -> Option<ConnectionInfo> {
            // The callback runs behind the cache's spin lock. Just copy and return.
            Some(ConnectionInfo::from_connection(conn))
        };
        if use_ended_fallback {
            connection_cache.read_connection_v6_for_packet(key, packet_direction, process)
        } else {
            connection_cache.read_connection_v6(key, process)
        }
    } else {
        let process = |conn: &ConnectionV4| -> Option<ConnectionInfo> {
            // The callback runs behind the cache's spin lock. Just copy and return.
            Some(ConnectionInfo::from_connection(conn))
        };
        if use_ended_fallback {
            connection_cache.read_connection_v4_for_packet(key, packet_direction, process)
        } else {
            connection_cache.read_connection_v4(key, process)
        }
    }
}
