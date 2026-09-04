use smoltcp::wire::IpProtocol;

use crate::connection::Direction;

/// Returns whether a self-injected ALE indication must still run the server-side
/// TCP receive/accept authorization path.
///
/// Network reinjection of an outbound loopback SYN can be the first packet seen
/// by the listening endpoint. Every other self-injected indication keeps the
/// normal immediate-permit loop guard.
pub(crate) fn self_injected_packet_needs_tcp_accept_authorization(
    protocol: IpProtocol,
    loopback: bool,
    connection_direction: Direction,
    packet_direction: Direction,
) -> bool {
    protocol == IpProtocol::Tcp
        && loopback
        && matches!(connection_direction, Direction::Inbound)
        && matches!(packet_direction, Direction::Inbound)
}

#[cfg(test)]
mod tests {
    use super::self_injected_packet_needs_tcp_accept_authorization;
    use crate::connection::Direction;
    use smoltcp::wire::IpProtocol;

    #[test]
    fn only_inbound_loopback_tcp_needs_accept_authorization() {
        assert!(self_injected_packet_needs_tcp_accept_authorization(
            IpProtocol::Tcp,
            true,
            Direction::Inbound,
            Direction::Inbound,
        ));
        assert!(!self_injected_packet_needs_tcp_accept_authorization(
            IpProtocol::Udp,
            true,
            Direction::Inbound,
            Direction::Inbound,
        ));
        assert!(!self_injected_packet_needs_tcp_accept_authorization(
            IpProtocol::Tcp,
            false,
            Direction::Inbound,
            Direction::Inbound,
        ));
        assert!(!self_injected_packet_needs_tcp_accept_authorization(
            IpProtocol::Tcp,
            true,
            Direction::Outbound,
            Direction::Inbound,
        ));
        assert!(!self_injected_packet_needs_tcp_accept_authorization(
            IpProtocol::Tcp,
            true,
            Direction::Inbound,
            Direction::Outbound,
        ));
    }
}
