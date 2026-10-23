use alloc::string::{String, ToString};
use core::mem::MaybeUninit;
use likely_stable::{likely, unlikely};
use smoltcp::wire::{IPV4_HEADER_LEN, IPV6_HEADER_LEN};
use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer;
use wdk::filter_engine::net_buffer::{NetBufferList, NetBufferListClones, NetBufferListIter};
use wdk::filter_engine::packet::InjectInfo;

use crate::ale_policy::{
    classify_packet_injection, inbound_udp_fallback_pid, PacketInjectionAction,
};
use crate::connection::{
    fast_track_pm_packets, Connection, ConnectionV4, ConnectionV6, Direction, RedirectInfo, Verdict,
};
use crate::connection_cache::ConnectionCache;
use crate::connection_map::Key;
use crate::device::{Device, Packet};
use crate::packet_metadata::{IcmpError, PacketInspector, PacketMetadataError};
use crate::packet_util::{packet_reader, recalc_header_checksums, Redirect};

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
    let base = if unlikely(ipv6) {
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
    let Some(first_nbl) = nbls.next() else {
        return;
    };

    let Some(device) = crate::entry::get_device() else {
        return;
    };

    // Self-injected packets need no header reads, parsing or inbound retreat.
    // SAFETY: WFP owns the live NBL for this entire synchronous query.
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
    let wfp_ip_header_size = if inbound {
        data.get_ip_header_size()
    } else {
        None
    };
    let reassembled = data.is_reassembled(fields.flags);
    let mut routing_info = None;
    let mut other_injector_process_id = None;

    let mut first = true;
    for mut nbl in core::iter::once(first_nbl).chain(nbls) {
        let permit_fragments = first && !reassembled;
        if inbound {
            // At inbound packet layers the current offset follows the IP header.
            // The wrapper restores it automatically when this iteration ends.
            let retreat = retreat_to_ip_header(&mut nbl, ipv6, wfp_ip_header_size).or_else(|err| {
                if !permit_fragments {
                    return Err(err);
                }
                // Preserve the old first-probe retry, but only after an actual failure.
                crate::err!("failed to retreat packet to IP header: {}", err);
                retreat_to_ip_header(&mut nbl, ipv6, wfp_ip_header_size)
            });
            if let Err(err) = retreat {
                crate::err!("failed to retreat packet to IP header: {}", err);
                return;
            }
        }
        let mut storage = MaybeUninit::uninit();
        let mut reader = packet_reader(&nbl, &mut storage);
        let mut inspection = PacketInspector::new(&mut reader, ipv6, direction, permit_fragments);
        // Resolve fragment status and key in one pass. Individual fragments still
        // bypass transport parsing and preserve the indication-wide first-NBL
        // permit; do not call a separate header accessor on every normal packet.
        let key = match inspection.key() {
            Err(PacketMetadataError::FragmentRequiresReassembly) if permit_fragments => {
                data.action_permit();
                return;
            }
            // Keep the old first probe's one retry after a real failure only.
            Err(_) if permit_fragments => inspection.retry_key(),
            result => result,
        };
        let mut key = match key {
            Ok(key) => key,
            Err(err) => {
                crate::err!("failed to get key from nbl: {}", err);
                return;
            }
        };
        first = false;

        if fast_track_pm_packets(&key) {
            data.action_permit();
            return;
        }

        let transport_protocol = matches!(
            key.protocol,
            smoltcp::wire::IpProtocol::Tcp | smoltcp::wire::IpProtocol::Udp
        );
        // Read connection state once for policy or redirect rewriting.
        let connection_info = if likely(transport_protocol) {
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
        if unlikely(
            key.protocol == smoltcp::wire::IpProtocol::Tcp
                && inspection.is_tcp_reset()
                && connection_info
                    .as_ref()
                    .and_then(|info| info.redirect_info.as_ref())
                    .is_none(),
        ) {
            data.action_permit();
            return;
        }

        let icmp_metadata = if unlikely(!transport_protocol) {
            inspection.icmp_metadata(&key)
        } else {
            Default::default()
        };
        drop(inspection);
        drop(reader);

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
        // Inbound errors use the quoted TCP/UDP tuple or echo identity; echo
        // replies use their identifier and sequence number.
        if unlikely(!transport_protocol) {
            match direction {
                Direction::Outbound if !icmp_metadata.is_local_error => {
                    if let Some(echo) = icmp_metadata.echo {
                        if !echo.is_request {
                            // WFP reports a loopback reply as OUTBOUND, so its source
                            // is the request's remote address. Match the reversed key,
                            // then normalize both the tuple and semantic direction.
                            // A normal outbound kernel reply to a remote ping must not
                            // consume an unrelated request with the same identifier.
                            let request = echo.loopback_reply_key(key).and_then(|reply_key| {
                                let mut icmp_echo_cache = device.icmp_echo_cache.write_lock();
                                icmp_echo_cache
                                    .take_request_identity(
                                        reply_key.remote_address,
                                        echo.identifier,
                                        echo.sequence,
                                    )
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
                                    echo.sequence,
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
                _ => {
                    // Attribute only: the outer ICMP key, verdict and lifetime
                    // must not become those of the quoted connection.
                    let request = match icmp_metadata.error {
                        Some(IcmpError::Transport(
                            protocol,
                            remote_address,
                            local_port,
                            remote_port,
                        )) => {
                            let quoted_key = Key {
                                protocol,
                                local_address: key.local_address,
                                local_port,
                                remote_address,
                                remote_port,
                            };
                            // The error can arrive after the sending endpoint closed.
                            let cache = &device.connection_cache;
                            (process_id, thread_id) = if unlikely(ipv6) {
                                let identity = |conn: &ConnectionV6| {
                                    Some((conn.get_process_id(), conn.thread_id))
                                };
                                cache.read_connection_v6(&quoted_key, identity).or_else(|| {
                                    cache.read_ended_connection_v6(&quoted_key, identity)
                                })
                            } else {
                                let identity = |conn: &ConnectionV4| {
                                    Some((conn.get_process_id(), conn.thread_id))
                                };
                                cache.read_connection_v4(&quoted_key, identity).or_else(|| {
                                    cache.read_ended_connection_v4(&quoted_key, identity)
                                })
                            }
                            .unwrap_or((0, 0));
                            None
                        }
                        Some(IcmpError::Echo(address, identifier, sequence)) => {
                            Some((address, identifier, sequence))
                        }
                        None => icmp_metadata
                            .echo
                            .filter(|echo| !echo.is_request)
                            .map(|echo| (key.remote_address, echo.identifier, echo.sequence)),
                    };
                    if let Some((remote_address, identifier, sequence)) = request {
                        (process_id, thread_id) = {
                            let mut icmp_echo_cache = device.icmp_echo_cache.write_lock();
                            icmp_echo_cache
                                .take_request_identity(remote_address, identifier, sequence)
                                .unwrap_or((0, 0))
                        };
                    }
                }
            }
        }

        if likely(transport_protocol) {
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
                let fallback_pid = inbound_udp_fallback_pid(
                    key.protocol,
                    crate::registry_settings::inbound_udp_pid_fallback_enabled(),
                    || device.connection_cache.find_active_udp_pid(&key),
                );
                let Some(pid) = fallback_pid else {
                    // Preserve native ALE authorization when the option is off,
                    // no live UDP match exists, or its PID is unknown/System.
                    data.action_permit();
                    return;
                };

                // Borrow only the PID. The exact tuple gets its own cache instance
                // and policy; a concurrent registration keeps its existing state.
                let registration = match device
                    .connection_cache
                    .register_inbound_udp_fallback_connection(&key, pid)
                {
                    Ok(registration) => registration,
                    Err(err) => {
                        crate::err!(
                            "failed to register inbound UDP fallback connection: {}",
                            err
                        );
                        data.action_permit();
                        return;
                    }
                };
                process_id = pid;
                connection_instance_id = Some(registration.instance_id);
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

        // Preserve outbound reinjection; only userspace sees a local error as inbound.
        if unlikely(icmp_metadata.is_local_error) {
            effective_direction = Direction::Inbound;
        }
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
    if unlikely(ipv6) {
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
