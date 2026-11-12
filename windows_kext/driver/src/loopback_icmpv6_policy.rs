//! Recognition of native outbound loopback ICMPv6 to IPv6 multicast.

use smoltcp::wire::{IpAddress, IpProtocol, Ipv6Address};

/// Reinjection has failed on observed ::1 -> ff02::1 and ::1 -> ff02::16
/// paths. The exception covers all IPv6 multicast destinations, independent of
/// ICMPv6 message type, payload and IP options.
pub(crate) fn is_loopback_icmpv6_multicast(
    outbound: bool,
    ipv6: bool,
    interface_index: impl FnOnce() -> u32,
    protocol: IpProtocol,
    source: IpAddress,
    destination: IpAddress,
    not_injected: bool,
) -> bool {
    outbound
        && ipv6
        && protocol == IpProtocol::Icmpv6
        && source == IpAddress::Ipv6(Ipv6Address::LOCALHOST)
        && matches!(destination, IpAddress::Ipv6(address) if address.is_multicast())
        && not_injected
        && interface_index() == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::Ipv4Address;

    #[test]
    fn qualifies_ipv6_multicast_destinations_only() {
        let source = IpAddress::Ipv6(Ipv6Address::LOCALHOST);
        let test = |destination| {
            is_loopback_icmpv6_multicast(
                true,
                true,
                || 1,
                IpProtocol::Icmpv6,
                source,
                destination,
                true,
            )
        };
        // Check the whole ff00::/8 prefix, not only known MLD destinations or scopes.
        for address in [
            Ipv6Address::new(0xff00, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Address::new(0xff01, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16),
            Ipv6Address::new(0xff05, 0, 0, 0, 0, 0, 0, 0x1234),
            Ipv6Address::new(0xff0e, 0, 0, 0, 0, 0, 0, 0x1234),
            Ipv6Address::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ),
        ] {
            assert!(test(IpAddress::Ipv6(address)), "{address}");
        }
        for address in [
            IpAddress::Ipv6(Ipv6Address::UNSPECIFIED),
            source,
            IpAddress::Ipv6(Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddress::Ipv6(Ipv6Address::new(
                0xfeff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            )),
            IpAddress::Ipv4(Ipv4Address::new(224, 0, 0, 1)),
        ] {
            assert!(!test(address), "{address}");
        }
    }

    #[test]
    fn interface_is_read_only_after_other_conditions_match() {
        let source = IpAddress::Ipv6(Ipv6Address::LOCALHOST);
        let other_source = IpAddress::Ipv6(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let multicast = IpAddress::Ipv6(Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        for (outbound, ipv6, protocol, src, dst, native, expected_reads) in [
            (false, true, IpProtocol::Icmpv6, source, multicast, true, 0),
            (true, false, IpProtocol::Icmpv6, source, multicast, true, 0),
            (true, true, IpProtocol::Udp, source, multicast, true, 0),
            (
                true,
                true,
                IpProtocol::Icmpv6,
                other_source,
                multicast,
                true,
                0,
            ),
            (true, true, IpProtocol::Icmpv6, source, source, true, 0),
            (true, true, IpProtocol::Icmpv6, source, multicast, false, 0),
            (true, true, IpProtocol::Icmpv6, source, multicast, true, 1),
        ] {
            let mut reads = 0;
            let matched = is_loopback_icmpv6_multicast(
                outbound,
                ipv6,
                || {
                    reads += 1;
                    1
                },
                protocol,
                src,
                dst,
                native,
            );
            assert_eq!(reads, expected_reads);
            assert_eq!(matched, expected_reads == 1);
        }
    }

    #[test]
    fn only_native_outbound_icmpv6_from_loopback_qualifies() {
        let source = IpAddress::Ipv6(Ipv6Address::LOCALHOST);
        let target = IpAddress::Ipv6(Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        let other_source = IpAddress::Ipv6(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let test = |outbound, ipv6, interface, protocol, src, dst, native| {
            is_loopback_icmpv6_multicast(outbound, ipv6, || interface, protocol, src, dst, native)
        };
        assert!(test(
            true,
            true,
            1,
            IpProtocol::Icmpv6,
            source,
            target,
            true
        ));
        assert!(!test(
            false,
            true,
            1,
            IpProtocol::Icmpv6,
            source,
            target,
            true
        ));
        assert!(!test(
            true,
            false,
            1,
            IpProtocol::Icmpv6,
            source,
            target,
            true
        ));
        assert!(!test(
            true,
            true,
            2,
            IpProtocol::Icmpv6,
            source,
            target,
            true
        ));
        assert!(!test(true, true, 1, IpProtocol::Udp, source, target, true));
        assert!(!test(
            true,
            true,
            1,
            IpProtocol::Icmpv6,
            other_source,
            target,
            true
        ));
        assert!(!test(
            true,
            true,
            1,
            IpProtocol::Icmpv6,
            source,
            target,
            false
        ));
    }
}
