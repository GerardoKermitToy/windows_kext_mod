use smoltcp::wire::{IpAddress, IpProtocol};

use crate::connection::Direction;

/// Raw receive indications describe delivery of a packet copy, not ownership of
/// its TCP/UDP tuple. Keep the observer out of native connection lifecycle state.
/// Raw sends still need normal authorization and packet-layer policy.
#[inline]
pub(crate) fn should_skip_raw_receive(raw_endpoint: bool, inbound: bool) -> bool {
    raw_endpoint && inbound
}

/// Restricts the notification-only policy to loopback-interface UDP multicast.
/// Windows loopback uses interface index 1; IPv4 loopback is 127.0.0.0/8.
#[inline]
pub(crate) fn is_local_loopback_multicast_udp(
    loopback: bool,
    interface_index: u32,
    protocol: IpProtocol,
    source: IpAddress,
    destination: IpAddress,
) -> bool {
    loopback
        && interface_index == 1
        && protocol == IpProtocol::Udp
        && has_loopback_multicast_addresses(source, destination)
}

/// Defer the WFP interface-field read until protocol and addresses can match.
#[inline]
pub(crate) fn is_local_loopback_multicast_udp_with_interface(
    loopback: bool,
    protocol: IpProtocol,
    source: IpAddress,
    destination: IpAddress,
    interface_index: impl FnOnce() -> u32,
) -> bool {
    loopback
        && protocol == IpProtocol::Udp
        && has_loopback_multicast_addresses(source, destination)
        && interface_index() == 1
}

#[inline]
fn has_loopback_multicast_addresses(source: IpAddress, destination: IpAddress) -> bool {
    match (source, destination) {
        (IpAddress::Ipv4(source), IpAddress::Ipv4(destination)) => {
            source.is_loopback() && destination.is_multicast()
        }
        (IpAddress::Ipv6(source), IpAddress::Ipv6(destination)) => {
            source.is_loopback() && destination.is_multicast()
        }
        _ => false,
    }
}

/// A replay may reach every subscriber, but only the exact live generation
/// that requested its verdict may receive it. Never match an absent identity.
#[inline]
pub(crate) fn multicast_replay_matches(target: u64, receiver: Option<u64>) -> bool {
    target != 0 && receiver == Some(target)
}

/// Policy result after combining the network and transport injection handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AleInjectionAction {
    Process,
    PermitSelfInjected,
    PermitOtherInjectedOutbound,
}

/// Combined view of one NBL queried against both driver injection handles.
///
/// WFP can report the same self-injected NBL as `InjectedByOther` relative to
/// the other handle. Callers must therefore test `self_injected` first.
#[derive(Clone, Copy)]
pub(crate) struct InjectionStatus {
    self_injected: bool,
    injected_by_other: bool,
}

impl InjectionStatus {
    pub(crate) fn new(
        network_self_injected: bool,
        transport_self_injected: bool,
        network_injected_by_other: bool,
        transport_injected_by_other: bool,
    ) -> Self {
        Self {
            self_injected: network_self_injected || transport_self_injected,
            injected_by_other: network_injected_by_other || transport_injected_by_other,
        }
    }

    pub(crate) fn is_self_injected(self) -> bool {
        self.self_injected
    }

    pub(crate) fn is_injected_by_other(self) -> bool {
        self.injected_by_other
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketInjectionAction {
    PermitSelfInjected,
    Process { injected_by_other: bool },
}

/// Packet layers always permit self-injection. Unlike ALE's inbound loopback
/// authorization, they need no other-handle state once local ownership is proven.
#[inline]
pub(crate) fn classify_packet_injection(
    network_self_injected: bool,
    network_injected_by_other: bool,
    query_transport: impl FnOnce() -> (bool, bool),
) -> PacketInjectionAction {
    if network_self_injected {
        return PacketInjectionAction::PermitSelfInjected;
    }

    // "Other" relative to the network handle can still be our transport clone.
    let (transport_self_injected, transport_injected_by_other) = query_transport();
    if transport_self_injected {
        PacketInjectionAction::PermitSelfInjected
    } else {
        PacketInjectionAction::Process {
            injected_by_other: network_injected_by_other || transport_injected_by_other,
        }
    }
}

/// A missing inbound UDP tuple may borrow only process attribution, and only
/// from the first live match. Multicast destinations and Unknown/System attribution
/// still need native ALE authorization. Callers invoke this only after the normal
/// cache lookup misses.
#[inline]
pub(crate) fn inbound_udp_fallback_pid(
    protocol: IpProtocol,
    local_address: IpAddress,
    enabled: bool,
    lookup: impl FnOnce() -> Option<u64>,
) -> Option<u64> {
    if !enabled || protocol != IpProtocol::Udp || local_address.is_multicast() {
        return None;
    }

    lookup().filter(|pid| !matches!(*pid, 0 | 4))
}

/// Returns whether an ALE indication has the signature of a final TCP
/// reauthorization racing endpoint closure.
pub(crate) fn can_reuse_ended_tcp_policy(reauthorize: bool, protocol: IpProtocol) -> bool {
    reauthorize && protocol == IpProtocol::Tcp
}

/// Selects the ALE loop guard without allowing an "other" result from one
/// handle to override proof that the NBL belongs to the other local handle.
pub(crate) fn classify_ale_injection(
    injection: InjectionStatus,
    protocol: IpProtocol,
    loopback: bool,
    connection_direction: Direction,
    packet_direction: Direction,
) -> AleInjectionAction {
    if injection.is_self_injected()
        && !self_injected_packet_needs_accept_authorization(
            protocol,
            loopback,
            connection_direction,
            packet_direction,
        )
    {
        return AleInjectionAction::PermitSelfInjected;
    }

    if injection.is_injected_by_other() && matches!(packet_direction, Direction::Outbound) {
        return AleInjectionAction::PermitOtherInjectedOutbound;
    }

    AleInjectionAction::Process
}

/// Returns whether an outbound synthetic flow belongs to any injector.
pub(crate) fn should_skip_injected_outbound_flow(
    outbound: bool,
    network_injected: bool,
    transport_injected: bool,
) -> bool {
    outbound && (network_injected || transport_injected)
}

/// Initial outbound TCP has no NBL; all other ALE packet-bearing paths may clone it.
pub(crate) fn should_capture_ale_packet(
    protocol: IpProtocol,
    packet_direction: Direction,
    reauthorize: bool,
) -> bool {
    protocol != IpProtocol::Tcp || !matches!(packet_direction, Direction::Outbound) || reauthorize
}

/// Resets observed during reauthorization have no live send endpoint to replay
/// through. Leave their delivery to packet layers.
pub(crate) fn should_permit_ale_tcp_reset(
    protocol: IpProtocol,
    reauthorize: bool,
    transport_header: &[u8],
) -> bool {
    protocol == IpProtocol::Tcp
        && reauthorize
        && transport_header.len() >= 20
        && transport_header[12] >> 4 >= 5
        && transport_header[13] & 0x04 != 0
}

/// Preserve inbound UDP replies at AUTH_CONNECT: unlike TCP, a dropped datagram
/// cannot rely on retransmission after the verdict triggers reauthorization.
pub(crate) fn should_skip_cross_direction_ale_clone(
    protocol: IpProtocol,
    reauthorize: bool,
    connection_direction: Direction,
    packet_direction: Direction,
) -> bool {
    protocol != IpProtocol::Udp
        && reauthorize
        && matches!(connection_direction, Direction::Outbound)
        && matches!(packet_direction, Direction::Inbound)
}

/// Returns whether the transport endpoint handle of a self-injected ALE
/// indication identifies the application's own socket.
///
/// Reinjection re-indicates a packet without any application send context, so WFP
/// reports one shared raw endpoint for everything the injector emits. Runtime
/// capture showed a single outbound handle offered for dozens of unrelated
/// connections, including different remote addresses, which made each following
/// connection look like a handle collision and left the borrowed handle in the
/// cache as an alias of the first tuple that claimed it.
///
/// Nothing is lost by ignoring it: the genuine authorization that created the
/// pended request already associated the real endpoint, and `ALE_FLOW_ESTABLISHED`
/// rebinds the established child handle. An inbound self-injected packet is
/// returned to a concrete receiving endpoint and keeps native identity.
pub(crate) fn self_injected_endpoint_identifies_socket(packet_direction: Direction) -> bool {
    matches!(packet_direction, Direction::Inbound)
}

/// Returns whether a self-injected ALE indication must still run the server-side
/// TCP/UDP receive/accept authorization path.
///
/// Network reinjection of the first outbound loopback packet can be the first NBL
/// seen by the listening endpoint. Every other self-injected indication keeps the
/// normal immediate-permit loop guard.
pub(crate) fn self_injected_packet_needs_accept_authorization(
    protocol: IpProtocol,
    loopback: bool,
    connection_direction: Direction,
    packet_direction: Direction,
) -> bool {
    matches!(protocol, IpProtocol::Tcp | IpProtocol::Udp)
        && loopback
        && matches!(connection_direction, Direction::Inbound)
        && matches!(packet_direction, Direction::Inbound)
}

#[cfg(test)]
mod tests {
    use super::{
        can_reuse_ended_tcp_policy, classify_ale_injection, classify_packet_injection,
        inbound_udp_fallback_pid, is_local_loopback_multicast_udp,
        is_local_loopback_multicast_udp_with_interface, multicast_replay_matches,
        self_injected_endpoint_identifies_socket, self_injected_packet_needs_accept_authorization,
        should_capture_ale_packet, should_permit_ale_tcp_reset,
        should_skip_cross_direction_ale_clone, should_skip_injected_outbound_flow,
        should_skip_raw_receive, AleInjectionAction, InjectionStatus, PacketInjectionAction,
    };
    use crate::connection::Direction;
    use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv6Address};

    #[test]
    fn loopback_multicast_exception_requires_interface_address_and_udp() {
        let loopback4 = IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1));
        let other_loopback4 = IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 2));
        let lan4 = IpAddress::Ipv4(Ipv4Address::new(192, 0, 2, 10));
        let multicast4 = IpAddress::Ipv4(Ipv4Address::new(239, 255, 23, 91));
        let unicast4 = IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 3));
        let loopback6 = IpAddress::Ipv6(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1));
        let other6 = IpAddress::Ipv6(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 2));
        let multicast6 = IpAddress::Ipv6(Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 0x114));
        let udp = IpProtocol::Udp;
        for (flag, interface, protocol, source, destination, expected) in [
            (true, 1, udp, loopback4, multicast4, true),
            (true, 1, udp, other_loopback4, multicast4, true),
            (true, 1, udp, loopback6, multicast6, true),
            (false, 1, udp, loopback4, multicast4, false),
            (true, 0, udp, loopback4, multicast4, false),
            (true, 2, udp, loopback4, multicast4, false),
            (true, 2, udp, loopback6, multicast6, false),
            (true, 1, IpProtocol::Tcp, loopback4, multicast4, false),
            (true, 1, IpProtocol::Icmp, loopback4, multicast4, false),
            (true, 1, udp, lan4, multicast4, false),
            (true, 1, udp, loopback4, unicast4, false),
            (true, 1, udp, other6, multicast6, false),
            (true, 1, udp, loopback4, multicast6, false),
            (true, 1, udp, multicast4, loopback4, false),
        ] {
            assert_eq!(
                is_local_loopback_multicast_udp(flag, interface, protocol, source, destination),
                expected
            );
        }
    }

    #[test]
    fn loopback_multicast_interface_read_is_deferred() {
        let loopback = IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1));
        let unicast = IpAddress::Ipv4(Ipv4Address::new(192, 0, 2, 1));
        let multicast = IpAddress::Ipv4(Ipv4Address::new(239, 1, 2, 3));
        let ipv6_multicast = IpAddress::Ipv6(Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        for (flag, protocol, source, destination, index, expected_reads, expected) in [
            (false, IpProtocol::Udp, loopback, multicast, 1, 0, false),
            (true, IpProtocol::Tcp, loopback, multicast, 1, 0, false),
            (true, IpProtocol::Udp, unicast, multicast, 1, 0, false),
            (true, IpProtocol::Udp, loopback, unicast, 1, 0, false),
            (true, IpProtocol::Udp, loopback, ipv6_multicast, 1, 0, false),
            (true, IpProtocol::Udp, loopback, multicast, 18, 1, false),
            (true, IpProtocol::Udp, loopback, multicast, 1, 1, true),
        ] {
            let mut reads = 0;
            let matched = is_local_loopback_multicast_udp_with_interface(
                flag,
                protocol,
                source,
                destination,
                || {
                    reads += 1;
                    index
                },
            );
            assert_eq!(reads, expected_reads);
            assert_eq!(matched, expected);
        }
    }

    #[test]
    fn multicast_replay_requires_the_exact_live_generation() {
        assert!(multicast_replay_matches(10, Some(10)));
        assert!(!multicast_replay_matches(10, Some(11)));
        assert!(!multicast_replay_matches(10, None));
        assert!(!multicast_replay_matches(0, None));
        assert!(!multicast_replay_matches(0, Some(0)));
    }

    #[test]
    fn raw_receive_copies_never_enter_native_connection_lifecycle() {
        assert!(should_skip_raw_receive(true, true));
    }

    #[test]
    fn native_receives_and_raw_sends_keep_normal_authorization() {
        assert!(!should_skip_raw_receive(false, true));
        assert!(!should_skip_raw_receive(false, false));
        assert!(!should_skip_raw_receive(true, false));
    }

    #[test]
    fn inbound_udp_fallback_does_not_lookup_when_disabled_or_not_udp() {
        let local_address = IpAddress::Ipv4(Ipv4Address::new(192, 0, 2, 1));
        for protocol in [IpProtocol::Udp, IpProtocol::Tcp, IpProtocol::Icmp] {
            for enabled in [false, true] {
                let mut calls = 0;
                let pid = inbound_udp_fallback_pid(protocol, local_address, enabled, || {
                    calls += 1;
                    Some(123)
                });
                let allowed = enabled && protocol == IpProtocol::Udp;
                assert_eq!(calls, usize::from(allowed));
                assert_eq!(pid, allowed.then_some(123));
            }
        }
    }

    #[test]
    fn inbound_udp_fallback_leaves_missing_unknown_and_system_pid_to_ale() {
        let local_address = IpAddress::Ipv4(Ipv4Address::new(192, 0, 2, 1));
        for pid in [None, Some(0), Some(4)] {
            assert_eq!(
                inbound_udp_fallback_pid(IpProtocol::Udp, local_address, true, || pid),
                None
            );
        }
        assert_eq!(
            inbound_udp_fallback_pid(IpProtocol::Udp, local_address, true, || Some(123)),
            Some(123),
        );
    }

    #[test]
    fn inbound_udp_fallback_leaves_multicast_destinations_to_ale() {
        let destinations = [
            IpAddress::Ipv4(Ipv4Address::new(224, 0, 0, 0)),
            IpAddress::Ipv4(Ipv4Address::new(224, 0, 0, 251)),
            IpAddress::Ipv4(Ipv4Address::new(239, 255, 255, 255)),
            IpAddress::Ipv6(Ipv6Address::new(0xff00, 0, 0, 0, 0, 0, 0, 0)),
            IpAddress::Ipv6(Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)),
            IpAddress::Ipv6(Ipv6Address::new(0xffff, 0, 0, 0, 0, 0, 0, 0xffff)),
        ];

        for local_address in destinations {
            let mut calls = 0;
            let pid = inbound_udp_fallback_pid(IpProtocol::Udp, local_address, true, || {
                calls += 1;
                Some(123)
            });
            assert_eq!(pid, None, "multicast destination: {local_address}");
            assert_eq!(calls, 0, "multicast destination: {local_address}");
        }
    }

    #[test]
    fn inbound_udp_fallback_preserves_non_multicast_destinations() {
        let destinations = [
            IpAddress::Ipv4(Ipv4Address::new(223, 255, 255, 255)),
            IpAddress::Ipv4(Ipv4Address::new(240, 0, 0, 0)),
            IpAddress::Ipv4(Ipv4Address::new(255, 255, 255, 255)),
            IpAddress::Ipv6(Ipv6Address::new(0xfeff, 0, 0, 0, 0, 0, 0, 0xffff)),
            IpAddress::Ipv6(Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ];

        for local_address in destinations {
            let mut calls = 0;
            let pid = inbound_udp_fallback_pid(IpProtocol::Udp, local_address, true, || {
                calls += 1;
                Some(123)
            });
            assert_eq!(pid, Some(123), "non-multicast destination: {local_address}");
            assert_eq!(calls, 1, "non-multicast destination: {local_address}");
        }
    }

    #[test]
    fn packet_injection_short_circuits_only_proven_network_self() {
        // NotInjected, Injected/PreviouslyInjectedBySelf, InjectedByOther, Unknown.
        // Include all boolean combinations too so ownership always has priority.
        for network_self in [false, true] {
            for network_other in [false, true] {
                for transport_self in [false, true] {
                    for transport_other in [false, true] {
                        let mut calls = 0;
                        let actual = classify_packet_injection(network_self, network_other, || {
                            calls += 1;
                            (transport_self, transport_other)
                        });
                        let eager = InjectionStatus::new(
                            network_self,
                            transport_self,
                            network_other,
                            transport_other,
                        );
                        let expected = if eager.is_self_injected() {
                            PacketInjectionAction::PermitSelfInjected
                        } else {
                            PacketInjectionAction::Process {
                                injected_by_other: eager.is_injected_by_other(),
                            }
                        };
                        assert_eq!(actual, expected);
                        assert_eq!(calls, usize::from(!network_self));
                    }
                }
            }
        }
    }

    #[test]
    fn network_other_still_queries_the_own_transport_handle() {
        assert_eq!(
            classify_packet_injection(false, true, || (true, false)),
            PacketInjectionAction::PermitSelfInjected,
        );
        assert_eq!(
            classify_packet_injection(false, false, || (false, true)),
            PacketInjectionAction::Process {
                injected_by_other: true,
            },
        );
    }

    #[test]
    fn only_inbound_self_injected_endpoint_identifies_a_socket() {
        // An outbound reinjection carries the injector's shared raw endpoint for
        // every tuple it emits, so it must never be associated regardless of
        // whether the traffic happens to be local.
        assert!(!self_injected_endpoint_identifies_socket(
            Direction::Outbound
        ));
        assert!(self_injected_endpoint_identifies_socket(Direction::Inbound));
    }

    #[test]
    fn reauthorization_permits_resets_with_or_without_ack() {
        let mut header = [0u8; 20];
        header[12] = 5 << 4;
        for flags in [0x04, 0x14] {
            header[13] = flags;
            assert!(should_permit_ale_tcp_reset(IpProtocol::Tcp, true, &header));
            assert!(!should_permit_ale_tcp_reset(
                IpProtocol::Tcp,
                false,
                &header
            ));
            for protocol in [IpProtocol::Udp, IpProtocol::Icmp, IpProtocol::Icmpv6] {
                assert!(!should_permit_ale_tcp_reset(protocol, true, &header));
            }
        }
    }

    #[test]
    fn reauthorization_keeps_non_reset_packets_on_the_policy_path() {
        let mut header = [0u8; 20];
        header[12] = 5 << 4;
        for flags in [0x00, 0x02, 0x10, 0x11, 0x12, 0x18, 0x19] {
            header[13] = flags;
            assert!(!should_permit_ale_tcp_reset(IpProtocol::Tcp, true, &header));
        }
    }

    #[test]
    fn reset_detection_rejects_truncated_or_invalid_transport_headers() {
        let mut header = [0u8; 20];
        header[12] = 5 << 4;
        header[13] = 0x14;
        for size in 0..20 {
            assert!(!should_permit_ale_tcp_reset(
                IpProtocol::Tcp,
                true,
                &header[..size]
            ));
        }
        for words in 0..5 {
            header[12] = words << 4;
            assert!(!should_permit_ale_tcp_reset(IpProtocol::Tcp, true, &header));
        }
    }

    #[test]
    fn ended_policy_is_used_only_for_tcp_reauthorization() {
        assert!(can_reuse_ended_tcp_policy(true, IpProtocol::Tcp));
        assert!(!can_reuse_ended_tcp_policy(false, IpProtocol::Tcp));
        assert!(!can_reuse_ended_tcp_policy(true, IpProtocol::Udp));
    }

    #[test]
    fn only_inbound_loopback_transport_needs_accept_authorization() {
        for protocol in [IpProtocol::Tcp, IpProtocol::Udp] {
            assert!(self_injected_packet_needs_accept_authorization(
                protocol,
                true,
                Direction::Inbound,
                Direction::Inbound,
            ));
        }
        assert!(!self_injected_packet_needs_accept_authorization(
            IpProtocol::Icmp,
            true,
            Direction::Inbound,
            Direction::Inbound,
        ));
        assert!(!self_injected_packet_needs_accept_authorization(
            IpProtocol::Tcp,
            false,
            Direction::Inbound,
            Direction::Inbound,
        ));
        assert!(!self_injected_packet_needs_accept_authorization(
            IpProtocol::Tcp,
            true,
            Direction::Outbound,
            Direction::Inbound,
        ));
        assert!(!self_injected_packet_needs_accept_authorization(
            IpProtocol::Tcp,
            true,
            Direction::Inbound,
            Direction::Outbound,
        ));
    }

    #[test]
    fn self_injection_bypasses_ale_from_either_injection_handle() {
        for (network_self, transport_self, network_other, transport_other) in [
            (true, false, false, false),
            (false, true, false, false),
            (true, false, false, true),
            // Observed for transport-reinjected ALE clones at the IP layer:
            // "other" relative to the network handle, "self" relative to transport.
            (false, true, true, false),
        ] {
            assert_eq!(
                classify_ale_injection(
                    InjectionStatus::new(
                        network_self,
                        transport_self,
                        network_other,
                        transport_other,
                    ),
                    IpProtocol::Tcp,
                    false,
                    Direction::Outbound,
                    Direction::Outbound,
                ),
                AleInjectionAction::PermitSelfInjected
            );
        }
    }

    #[test]
    fn self_injected_loopback_transport_still_authorizes_server_endpoint() {
        for injection in [
            InjectionStatus::new(true, false, false, false),
            InjectionStatus::new(false, true, true, false),
        ] {
            for protocol in [IpProtocol::Tcp, IpProtocol::Udp] {
                assert_eq!(
                    classify_ale_injection(
                        injection,
                        protocol,
                        true,
                        Direction::Inbound,
                        Direction::Inbound,
                    ),
                    AleInjectionAction::Process
                );
            }
        }
    }

    #[test]
    fn foreign_injection_bypasses_only_outbound_ale() {
        for (network_other, transport_other) in [(true, false), (false, true)] {
            assert_eq!(
                classify_ale_injection(
                    InjectionStatus::new(false, false, network_other, transport_other),
                    IpProtocol::Udp,
                    false,
                    Direction::Outbound,
                    Direction::Outbound,
                ),
                AleInjectionAction::PermitOtherInjectedOutbound
            );
            assert_eq!(
                classify_ale_injection(
                    InjectionStatus::new(false, false, network_other, transport_other),
                    IpProtocol::Udp,
                    false,
                    Direction::Inbound,
                    Direction::Inbound,
                ),
                AleInjectionAction::Process
            );
        }
    }

    #[test]
    fn non_injected_and_unknown_packets_follow_normal_ale_policy() {
        assert_eq!(
            classify_ale_injection(
                InjectionStatus::new(false, false, false, false),
                IpProtocol::Tcp,
                false,
                Direction::Outbound,
                Direction::Outbound,
            ),
            AleInjectionAction::Process
        );
    }

    #[test]
    fn flow_established_skips_any_injected_outbound_origin_only() {
        for network_injected in [false, true] {
            for transport_injected in [false, true] {
                let injected = network_injected || transport_injected;
                assert_eq!(
                    should_skip_injected_outbound_flow(true, network_injected, transport_injected),
                    injected
                );
                assert!(!should_skip_injected_outbound_flow(
                    false,
                    network_injected,
                    transport_injected
                ));
            }
        }
    }

    #[test]
    fn outbound_tcp_capture_depends_on_reauthorization() {
        assert!(!should_capture_ale_packet(
            IpProtocol::Tcp,
            Direction::Outbound,
            false
        ));
        assert!(should_capture_ale_packet(
            IpProtocol::Tcp,
            Direction::Outbound,
            true
        ));
        assert!(should_capture_ale_packet(
            IpProtocol::Tcp,
            Direction::Inbound,
            false
        ));
        assert!(should_capture_ale_packet(
            IpProtocol::Udp,
            Direction::Outbound,
            false
        ));
    }

    #[test]
    fn udp_replies_are_captured_even_when_they_reauthorize_an_outbound_flow() {
        for reauthorize in [false, true] {
            for connection_direction in [Direction::Inbound, Direction::Outbound] {
                for packet_direction in [Direction::Inbound, Direction::Outbound] {
                    assert!(should_capture_ale_packet(
                        IpProtocol::Udp,
                        packet_direction,
                        reauthorize,
                    ));
                    assert!(!should_skip_cross_direction_ale_clone(
                        IpProtocol::Udp,
                        reauthorize,
                        connection_direction,
                        packet_direction,
                    ));
                }
            }
        }
    }

    #[test]
    fn non_udp_cross_direction_clone_policy_is_unchanged() {
        for protocol in [IpProtocol::Tcp, IpProtocol::Icmp, IpProtocol::Icmpv6] {
            for reauthorize in [false, true] {
                for connection_direction in [Direction::Inbound, Direction::Outbound] {
                    for packet_direction in [Direction::Inbound, Direction::Outbound] {
                        assert_eq!(
                            should_skip_cross_direction_ale_clone(
                                protocol,
                                reauthorize,
                                connection_direction,
                                packet_direction,
                            ),
                            reauthorize
                                && matches!(connection_direction, Direction::Outbound)
                                && matches!(packet_direction, Direction::Inbound),
                        );
                    }
                }
            }
        }
    }
}
