//! Recognition of the outbound loopback IGMP path that cannot be replayed.

use smoltcp::wire::IpProtocol;

/// The exception depends on the WFP path and protocol only, not on the IGMP
/// message type, destination address, or message contents.
pub(crate) fn is_loopback_igmp(
    outbound: bool,
    ipv6: bool,
    interface_index: impl FnOnce() -> u32,
    protocol: IpProtocol,
    not_injected: bool,
) -> bool {
    outbound && !ipv6 && protocol == IpProtocol::Igmp && not_injected && interface_index() == 1
}

#[cfg(test)]
mod tests {
    use super::is_loopback_igmp;
    use smoltcp::wire::IpProtocol;

    #[test]
    fn interface_is_read_only_for_native_outbound_igmp() {
        for (outbound, ipv6, protocol, native, expected_reads) in [
            (false, false, IpProtocol::Igmp, true, 0),
            (true, true, IpProtocol::Igmp, true, 0),
            (true, false, IpProtocol::Udp, true, 0),
            (true, false, IpProtocol::Igmp, false, 0),
            (true, false, IpProtocol::Igmp, true, 1),
        ] {
            let mut reads = 0;
            let matched = is_loopback_igmp(
                outbound,
                ipv6,
                || {
                    reads += 1;
                    1
                },
                protocol,
                native,
            );
            assert_eq!(reads, expected_reads);
            assert_eq!(matched, expected_reads == 1);
        }
    }

    #[test]
    fn only_native_outbound_ipv4_igmp_on_loopback_matches() {
        assert!(is_loopback_igmp(true, false, || 1, IpProtocol::Igmp, true));
        assert!(!is_loopback_igmp(
            false,
            false,
            || 1,
            IpProtocol::Igmp,
            true
        ));
        assert!(!is_loopback_igmp(true, true, || 1, IpProtocol::Igmp, true));
        assert!(!is_loopback_igmp(
            true,
            false,
            || 18,
            IpProtocol::Igmp,
            true
        ));
        assert!(!is_loopback_igmp(true, false, || 1, IpProtocol::Udp, true));
        assert!(!is_loopback_igmp(true, false, || 1, IpProtocol::Icmp, true));
        assert!(!is_loopback_igmp(
            true,
            false,
            || 1,
            IpProtocol::Igmp,
            false
        ));
    }
}
