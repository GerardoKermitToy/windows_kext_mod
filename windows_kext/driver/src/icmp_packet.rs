use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet, IPV4_HEADER_LEN, IPV6_HEADER_LEN};

use crate::common::{
    ICMPV4_CODE_DU_PORT_UNREACHABLE, ICMPV4_TYPE_DESTINATION_UNREACHABLE,
    ICMPV6_CODE_DU_PORT_UNREACHABLE, ICMPV6_TYPE_DESTINATION_UNREACHABLE,
};
use crate::ipv6_packet::walk_ipv6_headers;

const ICMP_HEADER_LEN: usize = 8;
const IPV4_MAX_HEADER_LEN: usize = 60;

/// Returns true for an ICMP Destination Unreachable / Port Unreachable packet.
///
/// `packet` starts at the IP header. IPv4 options and IPv6 extension headers are
/// followed before the ICMP type and code are inspected. Short, malformed and
/// unresolved packets are not accepted by this fast path.
pub(crate) fn is_icmp_port_unreachable(packet: &[u8], ipv6: bool) -> bool {
    if ipv6 {
        return is_icmpv6_port_unreachable(packet);
    }

    is_icmpv4_port_unreachable(packet)
}

fn is_icmpv4_port_unreachable(packet: &[u8]) -> bool {
    if packet.len() < IPV4_HEADER_LEN {
        return false;
    }

    let ip_packet = Ipv4Packet::new_unchecked(packet);
    if ip_packet.version() != 4 || ip_packet.next_header() != IpProtocol::Icmp {
        return false;
    }

    let transport_offset = ip_packet.header_len() as usize;
    if !(IPV4_HEADER_LEN..=IPV4_MAX_HEADER_LEN).contains(&transport_offset) {
        return false;
    }

    let Some(icmp_end) = transport_offset.checked_add(ICMP_HEADER_LEN) else {
        return false;
    };
    if usize::from(ip_packet.total_len()) < icmp_end {
        return false;
    }

    is_port_unreachable_header(packet.get(transport_offset..icmp_end), false)
}

fn is_icmpv6_port_unreachable(packet: &[u8]) -> bool {
    if packet.len() < IPV6_HEADER_LEN {
        return false;
    }

    let ip_packet = Ipv6Packet::new_unchecked(packet);
    if ip_packet.version() != 6 {
        return false;
    }

    let headers = walk_ipv6_headers(packet);
    if !headers.resolved || headers.protocol != IpProtocol::Icmpv6 {
        return false;
    }

    let Some(icmp_end) = headers.transport_offset.checked_add(ICMP_HEADER_LEN) else {
        return false;
    };
    let Some(total_len) = IPV6_HEADER_LEN.checked_add(ip_packet.payload_len() as usize) else {
        return false;
    };
    if total_len < icmp_end {
        return false;
    }

    is_port_unreachable_header(packet.get(headers.transport_offset..icmp_end), true)
}

fn is_port_unreachable_header(header: Option<&[u8]>, ipv6: bool) -> bool {
    let Some(header) = header else {
        return false;
    };

    let (message_type, code) = if ipv6 {
        (
            ICMPV6_TYPE_DESTINATION_UNREACHABLE,
            ICMPV6_CODE_DU_PORT_UNREACHABLE,
        )
    } else {
        (
            ICMPV4_TYPE_DESTINATION_UNREACHABLE,
            ICMPV4_CODE_DU_PORT_UNREACHABLE,
        )
    };

    header[0] == message_type && header[1] == code
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOGGED_ICMPV4_PORT_UNREACHABLE: [u8; 57] = [
        0x45, 0x00, 0x00, 0x39, 0x55, 0x3a, 0x00, 0x00, 0x80, 0x01, 0xad, 0x97, 0xc0, 0xa8, 0xdb,
        0x10, 0xc0, 0xa8, 0xdb, 0x90, 0x03, 0x03, 0x35, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00,
        0x00, 0x1d, 0x0e, 0x62, 0x00, 0x00, 0x80, 0x11, 0xf4, 0x7b, 0xc0, 0xa8, 0xdb, 0x90, 0xc0,
        0xa8, 0xdb, 0x10, 0xa9, 0x07, 0x04, 0xd2, 0x00, 0x09, 0x1a, 0x10, 0x00,
    ];

    #[test]
    fn recognizes_logged_ipv4_port_unreachable() {
        assert!(is_icmp_port_unreachable(
            &LOGGED_ICMPV4_PORT_UNREACHABLE,
            false
        ));
    }

    #[test]
    fn rejects_other_icmpv4_types_and_codes() {
        let mut packet = LOGGED_ICMPV4_PORT_UNREACHABLE;
        packet[21] = crate::common::ICMPV4_CODE_DU_ADMINISTRATIVELY_PROHIBITED;
        assert!(!is_icmp_port_unreachable(&packet, false));

        packet[20] = 8;
        packet[21] = 0;
        assert!(!is_icmp_port_unreachable(&packet, false));
    }

    #[test]
    fn rejects_truncated_ipv4_message() {
        assert!(!is_icmp_port_unreachable(
            &LOGGED_ICMPV4_PORT_UNREACHABLE[..27],
            false
        ));
    }

    #[test]
    fn recognizes_ipv6_port_unreachable_after_extension_header() {
        let mut packet = [0u8; 56];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&16u16.to_be_bytes());
        packet[6] = u8::from(IpProtocol::Ipv6Opts);
        packet[7] = 64;
        packet[40] = u8::from(IpProtocol::Icmpv6);
        packet[41] = 0;
        packet[48] = ICMPV6_TYPE_DESTINATION_UNREACHABLE;
        packet[49] = ICMPV6_CODE_DU_PORT_UNREACHABLE;

        assert!(is_icmp_port_unreachable(&packet, true));
    }
}
