use core::fmt;

use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Packet, IPV4_HEADER_LEN, IPV6_HEADER_LEN,
};

use crate::{connection::Direction, connection_map::Key, ipv6_packet::walk_ipv6_headers};

/// Prefix large enough for the IPv6 base header, the bounded extension-header
/// chain and every transport field inspected by the packet callout.
pub(crate) const MAX_PACKET_INSPECT_LEN: usize = 128;

const IPV4_MAX_HEADER_LEN: usize = 60;
const ICMP_HEADER_LEN: usize = 8;
const TCP_FLAGS_OFFSET: usize = 13;
const TCP_RST_FLAG: u8 = 0x04;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketMetadataError {
    UnreadablePacket,
    UnresolvedIpv6Headers,
}

impl fmt::Display for PacketMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnreadablePacket => "failed to get net_buffer data",
            Self::UnresolvedIpv6Headers => "IPv6 extension header chain did not resolve",
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct IcmpEcho {
    pub(crate) is_request: bool,
    pub(crate) identifier: u16,
    pub(crate) sequence: u16,
}

impl IcmpEcho {
    /// An outbound loopback reply has the request's remote address as its source.
    /// Return the requester's key; a cache match must still establish ownership.
    pub(crate) fn loopback_reply_key(self, key: Key) -> Option<Key> {
        if !self.is_request && key.is_loopback_like() {
            Some(key.reverse())
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum IcmpError {
    // The quoted local address is already validated against the outer key.
    Transport(IpProtocol, IpAddress, u16, u16),
    Echo(IpAddress, u16, u16),
}

#[derive(Clone, Copy)]
pub(crate) struct PacketMetadata {
    pub(crate) key: Key,
    pub(crate) icmp_echo: Option<IcmpEcho>,
    pub(crate) icmp_error: Option<IcmpError>,
    pub(crate) is_local_icmp_error: bool,
    pub(crate) is_tcp_reset: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct PacketInspection {
    pub(crate) is_fragment: bool,
    pub(crate) metadata: Result<PacketMetadata, PacketMetadataError>,
}

impl PacketInspection {
    pub(crate) const fn unreadable() -> Self {
        Self {
            is_fragment: false,
            metadata: Err(PacketMetadataError::UnreadablePacket),
        }
    }
}

/// Parses every field needed by the packet callout from one bounded prefix.
///
/// Fragment state is returned independently from the remaining metadata. This
/// preserves the packet-layer rule that an identifiable individual fragment is
/// permitted even when it is too short to produce a connection key.
pub(crate) fn inspect_packet(packet: &[u8], ipv6: bool, direction: Direction) -> PacketInspection {
    if ipv6 {
        inspect_ipv6_packet(packet, direction)
    } else {
        inspect_ipv4_packet(packet, direction)
    }
}

fn inspect_ipv4_packet(packet: &[u8], direction: Direction) -> PacketInspection {
    if packet.len() < IPV4_HEADER_LEN {
        return PacketInspection::unreadable();
    }

    let ip_packet = Ipv4Packet::new_unchecked(packet);
    let is_fragment = ip_packet.frag_offset() != 0 || ip_packet.more_frags();

    // Preserve the existing key contract: four bytes beyond the base header
    // must be readable even for a protocol that does not use ports.
    if packet.len() < IPV4_HEADER_LEN + 4 {
        return PacketInspection {
            is_fragment,
            metadata: Err(PacketMetadataError::UnreadablePacket),
        };
    }

    let protocol = ip_packet.next_header();
    let raw_transport_offset = ip_packet.header_len() as usize;
    let transport_offset = core::cmp::max(raw_transport_offset, IPV4_HEADER_LEN);
    let transport = packet.get(transport_offset..).unwrap_or_default();
    let (source_port, destination_port) = get_ports(transport, protocol);
    let key = build_key(
        direction,
        protocol,
        IpAddress::Ipv4(ip_packet.src_addr()),
        source_port,
        IpAddress::Ipv4(ip_packet.dst_addr()),
        destination_port,
    );

    let (icmp_echo, icmp_error, is_local_icmp_error) =
        if protocol == IpProtocol::Icmp && transport.len() >= ICMP_HEADER_LEN {
            let echo = get_icmp_echo(transport, false);
            let is_error = matches!(transport[0], 3 | 11 | 12)
                && ip_packet.version() == 4
                && raw_transport_offset >= IPV4_HEADER_LEN
                && usize::from(ip_packet.total_len()) >= raw_transport_offset + ICMP_HEADER_LEN;
            let local_error = is_error
                && matches!(direction, Direction::Outbound)
                && key.local_address == key.remote_address;
            let error = if is_error && (matches!(direction, Direction::Inbound) || local_error) {
                let end = core::cmp::min(packet.len(), usize::from(ip_packet.total_len()));
                packet
                    .get(raw_transport_offset..end)
                    .and_then(|transport| get_icmpv4_error(transport, ip_packet.dst_addr()))
            } else {
                None
            };
            (echo, error, local_error)
        } else {
            (None, None, false)
        };

    let is_tcp_reset = protocol == IpProtocol::Tcp
        && (IPV4_HEADER_LEN..=IPV4_MAX_HEADER_LEN).contains(&raw_transport_offset)
        && has_tcp_reset(packet, raw_transport_offset);

    PacketInspection {
        is_fragment,
        metadata: Ok(PacketMetadata {
            key,
            icmp_echo,
            icmp_error,
            is_local_icmp_error,
            is_tcp_reset,
        }),
    }
}

fn inspect_ipv6_packet(packet: &[u8], direction: Direction) -> PacketInspection {
    if packet.len() < IPV6_HEADER_LEN {
        return PacketInspection::unreadable();
    }

    let ip_packet = Ipv6Packet::new_unchecked(packet);
    let headers = walk_ipv6_headers(packet);
    if !headers.resolved {
        return PacketInspection {
            is_fragment: headers.is_fragment,
            metadata: Err(PacketMetadataError::UnresolvedIpv6Headers),
        };
    }

    let transport = packet.get(headers.transport_offset..).unwrap_or_default();
    let (source_port, destination_port) = get_ports(transport, headers.protocol);
    let key = build_key(
        direction,
        headers.protocol,
        IpAddress::Ipv6(ip_packet.src_addr()),
        source_port,
        IpAddress::Ipv6(ip_packet.dst_addr()),
        destination_port,
    );

    let (icmp_echo, icmp_error, is_local_icmp_error) =
        if headers.protocol == IpProtocol::Icmpv6 && transport.len() >= ICMP_HEADER_LEN {
            let echo = get_icmp_echo(transport, true);
            let is_error = matches!(transport[0], 1..=4)
                && ip_packet.version() == 6
                && ip_packet.total_len() >= headers.transport_offset + ICMP_HEADER_LEN;
            let local_error = is_error
                && matches!(direction, Direction::Outbound)
                && key.local_address == key.remote_address;
            let error = if is_error && (matches!(direction, Direction::Inbound) || local_error) {
                let end = core::cmp::min(packet.len(), ip_packet.total_len());
                packet
                    .get(headers.transport_offset..end)
                    .and_then(|transport| get_icmpv6_error(transport, ip_packet.dst_addr()))
            } else {
                None
            };
            (echo, error, local_error)
        } else {
            (None, None, false)
        };

    let is_tcp_reset =
        headers.protocol == IpProtocol::Tcp && has_tcp_reset(packet, headers.transport_offset);

    PacketInspection {
        is_fragment: headers.is_fragment,
        metadata: Ok(PacketMetadata {
            key,
            icmp_echo,
            icmp_error,
            is_local_icmp_error,
            is_tcp_reset,
        }),
    }
}

fn build_key(
    direction: Direction,
    protocol: IpProtocol,
    source_address: IpAddress,
    source_port: u16,
    destination_address: IpAddress,
    destination_port: u16,
) -> Key {
    match direction {
        Direction::Outbound => Key {
            protocol,
            local_address: source_address,
            local_port: source_port,
            remote_address: destination_address,
            remote_port: destination_port,
        },
        Direction::Inbound => Key {
            protocol,
            local_address: destination_address,
            local_port: destination_port,
            remote_address: source_address,
            remote_port: source_port,
        },
    }
}

fn get_ports(transport: &[u8], protocol: IpProtocol) -> (u16, u16) {
    if !matches!(protocol, IpProtocol::Tcp | IpProtocol::Udp) || transport.len() < 4 {
        return (0, 0);
    }

    (
        u16::from_be_bytes([transport[0], transport[1]]),
        u16::from_be_bytes([transport[2], transport[3]]),
    )
}

fn get_icmp_echo(transport: &[u8], ipv6: bool) -> Option<IcmpEcho> {
    if transport.len() < ICMP_HEADER_LEN {
        return None;
    }

    let message_type = transport[0];
    let is_request = if ipv6 {
        message_type == 128
    } else {
        message_type == 8
    };
    let is_reply = if ipv6 {
        message_type == 129
    } else {
        message_type == 0
    };
    if !is_request && !is_reply {
        return None;
    }

    Some(IcmpEcho {
        is_request,
        identifier: u16::from_be_bytes([transport[4], transport[5]]),
        sequence: u16::from_be_bytes([transport[6], transport[7]]),
    })
}

/// Errors quote the original packet, whose destination need not be the router.
fn get_icmpv4_error(transport: &[u8], local_address: Ipv4Address) -> Option<IcmpError> {
    let quoted = transport.get(ICMP_HEADER_LEN..)?;
    quoted.get(..IPV4_HEADER_LEN)?;
    let ip_packet = Ipv4Packet::new_unchecked(quoted);
    let offset = usize::from(ip_packet.header_len());
    if ip_packet.version() != 4
        || offset < IPV4_HEADER_LEN
        || ip_packet.src_addr() != local_address
        || ip_packet.frag_offset() != 0
    {
        return None;
    }
    let end = core::cmp::min(quoted.len(), usize::from(ip_packet.total_len()));
    get_icmp_error(
        ip_packet.next_header(),
        IpAddress::Ipv4(local_address),
        IpAddress::Ipv4(ip_packet.dst_addr()),
        quoted.get(offset..end)?,
    )
}

fn get_icmpv6_error(
    transport: &[u8],
    local_address: smoltcp::wire::Ipv6Address,
) -> Option<IcmpError> {
    let quoted = transport.get(ICMP_HEADER_LEN..)?;
    quoted.get(..IPV6_HEADER_LEN)?;
    let ip_packet = Ipv6Packet::new_unchecked(quoted);
    if ip_packet.version() != 6 || ip_packet.src_addr() != local_address {
        return None;
    }
    let end = core::cmp::min(quoted.len(), ip_packet.total_len());
    let quoted = &quoted[..end];
    let headers = walk_ipv6_headers(quoted);
    if !headers.resolved || headers.is_fragment {
        return None;
    }
    get_icmp_error(
        headers.protocol,
        IpAddress::Ipv6(local_address),
        IpAddress::Ipv6(ip_packet.dst_addr()),
        quoted.get(headers.transport_offset..)?,
    )
}

fn get_icmp_error(
    protocol: IpProtocol,
    local_address: IpAddress,
    remote_address: IpAddress,
    transport: &[u8],
) -> Option<IcmpError> {
    match protocol {
        IpProtocol::Tcp | IpProtocol::Udp => {
            transport.get(..4)?;
            let (local_port, remote_port) = get_ports(transport, protocol);
            Some(IcmpError::Transport(
                protocol,
                remote_address,
                local_port,
                remote_port,
            ))
        }
        IpProtocol::Icmp | IpProtocol::Icmpv6 => {
            if (protocol == IpProtocol::Icmpv6) != matches!(local_address, IpAddress::Ipv6(_)) {
                return None;
            }
            let echo = get_icmp_echo(transport, protocol == IpProtocol::Icmpv6)?;
            (echo.is_request && transport[1] == 0).then_some(IcmpError::Echo(
                remote_address,
                echo.identifier,
                echo.sequence,
            ))
        }
        _ => None,
    }
}

fn has_tcp_reset(packet: &[u8], transport_offset: usize) -> bool {
    transport_offset
        .checked_add(TCP_FLAGS_OFFSET)
        .and_then(|offset| packet.get(offset))
        .is_some_and(|flags| flags & TCP_RST_FLAG != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{
        ICMPV4_CODE_DU_PORT_UNREACHABLE, ICMPV4_TYPE_DESTINATION_UNREACHABLE,
        ICMPV6_CODE_DU_PORT_UNREACHABLE, ICMPV6_TYPE_DESTINATION_UNREACHABLE,
    };
    use smoltcp::wire::{Ipv4Address, Ipv6Address};

    fn set_ipv4_endpoints(packet: &mut [u8]) {
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
    }

    #[test]
    fn inspects_ipv4_options_and_tcp_reset_once() {
        let mut packet = [0u8; 80];
        packet[0] = 0x4f;
        packet[2..4].copy_from_slice(&80u16.to_be_bytes());
        packet[9] = u8::from(IpProtocol::Tcp);
        set_ipv4_endpoints(&mut packet);
        packet[60..62].copy_from_slice(&50_000u16.to_be_bytes());
        packet[62..64].copy_from_slice(&443u16.to_be_bytes());
        packet[73] = TCP_RST_FLAG;

        let inspected = inspect_packet(&packet, false, Direction::Outbound);
        assert!(!inspected.is_fragment);
        let metadata = inspected.metadata.expect("IPv4 metadata");
        assert_eq!(metadata.key.protocol, IpProtocol::Tcp);
        assert_eq!(metadata.key.local_port, 50_000);
        assert_eq!(metadata.key.remote_port, 443);
        assert_eq!(
            metadata.key.local_address,
            IpAddress::Ipv4(Ipv4Address::new(192, 0, 2, 1))
        );
        assert!(metadata.is_tcp_reset);
        for direction in [Direction::Outbound, Direction::Inbound] {
            for (flags, is_reset) in [(0x04, true), (0x14, true), (0x02, false), (0x11, false)] {
                packet[73] = flags;
                let metadata = inspect_packet(&packet, false, direction).metadata.unwrap();
                assert_eq!(metadata.is_tcp_reset, is_reset);
            }
            packet[73] = TCP_RST_FLAG;
            let truncated = inspect_packet(&packet[..73], false, direction)
                .metadata
                .unwrap();
            assert!(!truncated.is_tcp_reset);
        }
    }

    #[test]
    fn identifies_fragment_even_when_too_short_for_key() {
        let mut packet = [0u8; IPV4_HEADER_LEN];
        packet[0] = 0x45;
        packet[6..8].copy_from_slice(&0x2000u16.to_be_bytes());

        let inspected = inspect_packet(&packet, false, Direction::Outbound);
        assert!(inspected.is_fragment);
        assert!(matches!(
            inspected.metadata,
            Err(PacketMetadataError::UnreadablePacket)
        ));
    }

    #[test]
    fn extracts_ipv4_echo_and_port_unreachable_metadata() {
        let mut packet = [0u8; IPV4_HEADER_LEN + ICMP_HEADER_LEN];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[9] = u8::from(IpProtocol::Icmp);
        set_ipv4_endpoints(&mut packet);
        packet[20] = 8;
        packet[24..26].copy_from_slice(&0x1234u16.to_be_bytes());

        let metadata = inspect_packet(&packet, false, Direction::Outbound)
            .metadata
            .expect("ICMP echo metadata");
        let echo = metadata.icmp_echo.expect("echo request");
        assert!(echo.is_request);
        assert_eq!(echo.identifier, 0x1234);

        packet[20] = ICMPV4_TYPE_DESTINATION_UNREACHABLE;
        packet[21] = ICMPV4_CODE_DU_PORT_UNREACHABLE;
        for direction in [Direction::Outbound, Direction::Inbound] {
            let metadata = inspect_packet(&packet, false, direction)
                .metadata
                .expect("ICMP unreachable metadata");
            assert_eq!(metadata.key.protocol, IpProtocol::Icmp);
            assert_eq!(metadata.key.local_port, 0);
            assert_eq!(metadata.key.remote_port, 0);
            assert!(metadata.icmp_echo.is_none());
            assert!(metadata.icmp_error.is_none());
            assert!(!metadata.is_tcp_reset);
        }
    }

    #[test]
    fn echo_identity_keeps_sequence_for_ipv4_and_ipv6() {
        for ipv6 in [false, true] {
            let mut header = [0u8; ICMP_HEADER_LEN];
            header[0] = if ipv6 { 128 } else { 8 };
            header[4..6].copy_from_slice(&1u16.to_be_bytes());
            for sequence in [0x006fu16, 0x0070] {
                header[6..8].copy_from_slice(&sequence.to_be_bytes());
                let echo = get_icmp_echo(&header, ipv6).unwrap();
                assert!(echo.is_request);
                assert_eq!(echo.identifier, 1);
                assert_eq!(echo.sequence, sequence);
                header[0] = if ipv6 { 129 } else { 0 };
                let reply = get_icmp_echo(&header, ipv6).unwrap();
                assert!(!reply.is_request);
                assert_eq!(reply.sequence, sequence);
                header[0] = if ipv6 { 128 } else { 8 };
            }
            for len in 0..ICMP_HEADER_LEN {
                assert!(get_icmp_echo(&header[..len], ipv6).is_none());
            }
        }
    }

    #[test]
    fn outbound_loopback_echo_reply_uses_requesters_key() {
        let mut packet = [0u8; IPV4_HEADER_LEN + ICMP_HEADER_LEN];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[9] = u8::from(IpProtocol::Icmp);
        packet[12..16].copy_from_slice(&[127, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[127, 0, 0, 1]);
        packet[24..26].copy_from_slice(&0x1234u16.to_be_bytes());

        let metadata = inspect_packet(&packet, false, Direction::Outbound)
            .metadata
            .expect("outbound loopback echo reply");
        let echo = metadata.icmp_echo.unwrap();
        let reply_key = echo.loopback_reply_key(metadata.key).unwrap();
        assert_eq!(echo.identifier, 0x1234);
        assert_eq!(
            reply_key.remote_address,
            IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 2))
        );
        assert_eq!(
            reply_key.local_address,
            IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1))
        );
        let inbound_key = inspect_packet(&packet, false, Direction::Inbound)
            .metadata
            .unwrap()
            .key;
        assert!(reply_key == inbound_key);

        packet[20] = 8;
        let request = inspect_packet(&packet, false, Direction::Outbound)
            .metadata
            .unwrap();
        assert!(request
            .icmp_echo
            .unwrap()
            .loopback_reply_key(request.key)
            .is_none());
    }

    #[test]
    fn outbound_kernel_echo_reply_has_no_requesters_key() {
        let mut packet = [0u8; IPV4_HEADER_LEN + ICMP_HEADER_LEN];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[9] = u8::from(IpProtocol::Icmp);
        set_ipv4_endpoints(&mut packet);
        let metadata = inspect_packet(&packet, false, Direction::Outbound)
            .metadata
            .unwrap();
        assert!(metadata
            .icmp_echo
            .unwrap()
            .loopback_reply_key(metadata.key)
            .is_none());
    }

    #[test]
    fn same_address_echo_replies_keep_their_key() {
        let echo = IcmpEcho {
            is_request: false,
            identifier: 0x1234,
            sequence: 0x5678,
        };
        for address in [
            IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)),
            IpAddress::Ipv4(Ipv4Address::new(192, 0, 2, 1)),
            IpAddress::Ipv6(Ipv6Address::LOOPBACK),
        ] {
            let key = Key {
                protocol: match address {
                    IpAddress::Ipv4(_) => IpProtocol::Icmp,
                    IpAddress::Ipv6(_) => IpProtocol::Icmpv6,
                },
                local_address: address,
                local_port: 0,
                remote_address: address,
                remote_port: 0,
            };
            assert!(echo.loopback_reply_key(key) == Some(key));
        }
    }

    fn captured_ipv4_time_exceeded() -> [u8; 56] {
        // Only the quoted IP/ICMP headers are needed, not the full 92-byte request.
        [
            0x45, 0xc0, 0x00, 0x78, 0x6b, 0x70, 0x00, 0x00, 0x40, 0x01, 0xd6, 0xe3, 0xc0, 0xa8,
            0xdb, 0x0f, 0xc0, 0xa8, 0xdb, 0x10, 0x0b, 0x00, 0xf4, 0xff, 0x00, 0x00, 0x00, 0x00,
            0x45, 0x00, 0x00, 0x5c, 0x99, 0x23, 0x00, 0x00, 0x01, 0x01, 0x82, 0xc3, 0xc0, 0xa8,
            0xdb, 0x10, 0x01, 0x01, 0x01, 0x01, 0x08, 0x00, 0xf7, 0x8f, 0x00, 0x01, 0x00, 0x6f,
        ]
    }

    #[test]
    fn time_exceeded_uses_quoted_echo_target_and_identifier() {
        let packet = captured_ipv4_time_exceeded();
        let metadata = inspect_packet(&packet, false, Direction::Inbound)
            .metadata
            .unwrap();
        assert!(
            metadata.icmp_error
                == Some(IcmpError::Echo(
                    IpAddress::Ipv4(Ipv4Address::new(1, 1, 1, 1)),
                    1,
                    0x006f,
                ))
        );
        assert_eq!(
            metadata.key.remote_address,
            IpAddress::Ipv4(Ipv4Address::new(192, 168, 219, 15))
        );
        assert!(metadata.icmp_echo.is_none());
        assert!(inspect_packet(&packet, false, Direction::Outbound)
            .metadata
            .unwrap()
            .icmp_error
            .is_none());
    }

    #[test]
    fn time_exceeded_rejects_truncated_and_unrelated_quotes() {
        let packet = captured_ipv4_time_exceeded();
        for len in IPV4_HEADER_LEN + 4..packet.len() {
            assert!(inspect_packet(&packet[..len], false, Direction::Inbound)
                .metadata
                .unwrap()
                .icmp_error
                .is_none());
        }
        for (offset, value) in [
            (0, 0x65),  // wrong outer IP version
            (0, 0x44),  // invalid outer IHL
            (3, 55),    // quote extends beyond declared outer length
            (20, 8),    // not Time Exceeded
            (20, 9),    // not an ICMP error
            (28, 0x65), // wrong quoted IP version
            (28, 0x44), // invalid quoted IHL
            (28, 0x4f), // truncated quoted options
            (31, 27),   // quoted IP too short for an echo header
            (35, 1),    // non-initial quoted fragment
            (37, 47),   // unsupported quoted protocol
            (40, 203),  // quote belongs to another local address
            (48, 0),    // quoted Echo Reply, not Request
            (49, 1),    // invalid Echo Request code
        ] {
            let mut invalid = packet;
            invalid[offset] = value;
            assert!(
                inspect_packet(&invalid, false, Direction::Inbound)
                    .metadata
                    .unwrap()
                    .icmp_error
                    .is_none(),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn time_exceeded_handles_outer_and_quoted_ipv4_options() {
        let captured = captured_ipv4_time_exceeded();
        let mut packet = [0u8; 64];
        packet[..20].copy_from_slice(&captured[..20]);
        packet[0] = 0x46;
        packet[2..4].copy_from_slice(&64u16.to_be_bytes());
        packet[24..32].copy_from_slice(&captured[20..28]);
        packet[32..52].copy_from_slice(&captured[28..48]);
        packet[32] = 0x46;
        packet[56..64].copy_from_slice(&captured[48..56]);
        assert!(
            inspect_packet(&packet, false, Direction::Inbound)
                .metadata
                .unwrap()
                .icmp_error
                == Some(IcmpError::Echo(
                    IpAddress::Ipv4(Ipv4Address::new(1, 1, 1, 1)),
                    1,
                    0x006f,
                ))
        );
    }

    #[test]
    fn captured_ipv4_port_unreachable_keeps_icmp_key() {
        let packet = [
            0x45, 0x00, 0x00, 0x39, 0x55, 0x3a, 0x00, 0x00, 0x80, 0x01, 0xad, 0x97, 0xc0, 0xa8,
            0xdb, 0x10, 0xc0, 0xa8, 0xdb, 0x90, 0x03, 0x03, 0x35, 0x0a, 0x00, 0x00, 0x00, 0x00,
            0x45, 0x00, 0x00, 0x1d, 0x0e, 0x62, 0x00, 0x00, 0x80, 0x11, 0xf4, 0x7b, 0xc0, 0xa8,
            0xdb, 0x90, 0xc0, 0xa8, 0xdb, 0x10, 0xa9, 0x07, 0x04, 0xd2, 0x00, 0x09, 0x1a, 0x10,
            0x00,
        ];

        for direction in [Direction::Outbound, Direction::Inbound] {
            let metadata = inspect_packet(&packet, false, direction)
                .metadata
                .expect("captured ICMPv4 metadata");
            assert_eq!(metadata.key.protocol, IpProtocol::Icmp);
            assert_eq!(metadata.key.local_port, 0);
            assert_eq!(metadata.key.remote_port, 0);
            assert!(metadata.icmp_echo.is_none());
            if matches!(direction, Direction::Inbound) {
                assert!(matches!(
                    metadata.icmp_error,
                    Some(IcmpError::Transport(IpProtocol::Udp, address, 43_271, 1234))
                        if address == IpAddress::Ipv4(Ipv4Address::new(192, 168, 219, 16))
                ));
            } else {
                assert!(metadata.icmp_error.is_none());
            }
            assert!(!metadata.is_tcp_reset);
        }
    }

    fn captured_local_ipv4_host_unreachable() -> [u8; 88] {
        [
            0x45, 0x00, 0x00, 0x58, 0x00, 0x19, 0x00, 0x00, 0x80, 0x01, 0x03, 0x1a, 0xc0, 0xa8,
            0xdb, 0x10, 0xc0, 0xa8, 0xdb, 0x10, 0x03, 0x01, 0x41, 0xfe, 0x00, 0x00, 0x00, 0x00,
            0x45, 0x00, 0x00, 0x3c, 0xfa, 0xc4, 0x40, 0x00, 0x80, 0x06, 0x00, 0x00, 0xc0, 0xa8,
            0xdb, 0x10, 0xc0, 0xa8, 0xdb, 0xae, 0x9d, 0x55, 0x04, 0xd2, 0x15, 0x58, 0xfe, 0x22,
            0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xff, 0xff, 0x38, 0x3f, 0x00, 0x00, 0x02, 0x04,
            0x3e, 0xca, 0x01, 0x03, 0x03, 0x08, 0x04, 0x02, 0x08, 0x0a, 0x00, 0xa3, 0xa3, 0x7a,
            0x00, 0x00, 0x00, 0x00,
        ]
    }

    #[test]
    fn local_ipv4_errors_expose_quoted_owner() {
        let captured = captured_local_ipv4_host_unreachable();
        for protocol in [IpProtocol::Tcp, IpProtocol::Udp] {
            for kind in [3, 11, 12] {
                let mut packet = captured;
                packet[20] = kind;
                packet[37] = u8::from(protocol);
                for direction in [Direction::Outbound, Direction::Inbound] {
                    let metadata = inspect_packet(&packet, false, direction).metadata.unwrap();
                    assert_eq!(
                        metadata.is_local_icmp_error,
                        matches!(direction, Direction::Outbound)
                    );
                    assert_eq!(metadata.key.protocol, IpProtocol::Icmp);
                    assert_eq!(metadata.key.local_address, metadata.key.remote_address);
                    assert_eq!(metadata.key.local_port, 0);
                    assert_eq!(metadata.key.remote_port, 0);
                    assert!(matches!(metadata.icmp_error,
                        Some(IcmpError::Transport(quoted_protocol, address, 40_277, 1234))
                            if quoted_protocol == protocol
                                && address == IpAddress::Ipv4(Ipv4Address::new(192, 168, 219, 174))));
                    assert!(!metadata.is_tcp_reset);
                }
            }
        }
    }

    #[test]
    fn local_ipv4_error_marker_requires_an_error_but_not_a_resolved_quote() {
        let captured = captured_local_ipv4_host_unreachable();
        for (offset, value) in [(28, 0x65), (35, 1), (37, 47), (40, 203)] {
            let mut packet = captured;
            packet[offset] = value;
            let metadata = inspect_packet(&packet, false, Direction::Outbound)
                .metadata
                .unwrap();
            assert!(metadata.is_local_icmp_error);
            assert!(metadata.icmp_error.is_none());
        }
        for len in 28..52 {
            let metadata = inspect_packet(&captured[..len], false, Direction::Outbound)
                .metadata
                .unwrap();
            assert!(metadata.is_local_icmp_error);
            assert!(metadata.icmp_error.is_none());
        }
        for len in 24..28 {
            assert!(
                !inspect_packet(&captured[..len], false, Direction::Outbound)
                    .metadata
                    .unwrap()
                    .is_local_icmp_error
            );
        }
        for (offset, value) in [
            (0, 0x65),
            (0, 0x44),
            (3, 27), // invalid outer header or length
            (9, 6),
            (9, 17),  // not ICMP
            (19, 17), // different destination
            (20, 0),
            (20, 8),
            (20, 9),
            (20, 5), // echo and non-error messages
        ] {
            let mut packet = captured;
            packet[offset] = value;
            let metadata = inspect_packet(&packet, false, Direction::Outbound)
                .metadata
                .unwrap();
            assert!(
                !metadata.is_local_icmp_error,
                "offset {offset}, value {value}"
            );
            assert!(metadata.icmp_error.is_none());
        }
    }

    #[test]
    fn local_ipv6_errors_expose_quoted_owner_without_normalizing_echo() {
        let local = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        for protocol in [IpProtocol::Tcp, IpProtocol::Udp] {
            for kind in 1..=4 {
                let mut packet = ipv6_error_quote(protocol);
                packet[8..24].copy_from_slice(&local.0);
                packet[40] = kind;
                let metadata = inspect_packet(&packet, true, Direction::Outbound)
                    .metadata
                    .unwrap();
                assert!(metadata.is_local_icmp_error);
                assert_eq!(metadata.key.local_address, metadata.key.remote_address);
                assert!(matches!(metadata.icmp_error,
                    Some(IcmpError::Transport(quoted_protocol, _, 50_000, 443))
                        if quoted_protocol == protocol));
                assert!(
                    !inspect_packet(&packet, true, Direction::Inbound)
                        .metadata
                        .unwrap()
                        .is_local_icmp_error
                );
                packet[54] = 47; // unsupported quote, still a local error
                let metadata = inspect_packet(&packet, true, Direction::Outbound)
                    .metadata
                    .unwrap();
                assert!(metadata.is_local_icmp_error);
                assert!(metadata.icmp_error.is_none());
                for message_type in [128, 129, 135] {
                    packet[40] = message_type;
                    let metadata = inspect_packet(&packet, true, Direction::Outbound)
                        .metadata
                        .unwrap();
                    assert!(!metadata.is_local_icmp_error);
                    assert!(metadata.icmp_error.is_none());
                }
            }
        }
    }

    fn captured_ipv4_network_unreachable() -> [u8; 96] {
        [
            0x45, 0x00, 0x00, 0x60, 0x78, 0xd0, 0x00, 0x00, 0xfc, 0x01, 0x34, 0x68, 0xb2, 0x49,
            0xc3, 0x61, 0xc0, 0xa8, 0xdb, 0x10, 0x03, 0x00, 0xc8, 0x90, 0x00, 0x11, 0x00, 0x00,
            0x45, 0x00, 0x00, 0x3c, 0x6d, 0x41, 0x40, 0x00, 0x7d, 0x06, 0xc5, 0x07, 0xc0, 0xa8,
            0xdb, 0x10, 0xc0, 0xa8, 0x6f, 0x11, 0x88, 0x60, 0x04, 0xd2, 0xf4, 0x56, 0x54, 0x8d,
            0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xff, 0xff, 0x90, 0x0e, 0x00, 0x00, 0x02, 0x04,
            0x04, 0xf0, 0x01, 0x03, 0x03, 0x08, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x7f, 0x16, 0xac,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    #[test]
    fn ipv4_errors_use_quoted_transport_key_and_keep_outer_icmp_key() {
        let captured = captured_ipv4_network_unreachable();
        for protocol in [IpProtocol::Tcp, IpProtocol::Udp] {
            for kind in [3, 11, 12] {
                let mut packet = captured;
                packet[20] = kind;
                packet[37] = u8::from(protocol);
                let metadata = inspect_packet(&packet, false, Direction::Inbound)
                    .metadata
                    .unwrap();
                assert_eq!(metadata.key.protocol, IpProtocol::Icmp);
                assert_eq!(metadata.key.local_port, 0);
                assert_eq!(metadata.key.remote_port, 0);
                assert_eq!(
                    metadata.key.remote_address,
                    IpAddress::Ipv4(Ipv4Address::new(178, 73, 195, 97))
                );
                assert!(metadata.icmp_echo.is_none());
                assert!(!metadata.is_tcp_reset);
                assert!(matches!(
                    metadata.icmp_error,
                    Some(IcmpError::Transport(quoted_protocol, address, 34_912, 1234))
                        if quoted_protocol == protocol
                            && address == IpAddress::Ipv4(Ipv4Address::new(192, 168, 111, 17))
                ));
                assert!(inspect_packet(&packet, false, Direction::Outbound)
                    .metadata
                    .unwrap()
                    .icmp_error
                    .is_none());
            }
        }
        for len in 52..=captured.len() {
            assert!(matches!(
                inspect_packet(&captured[..len], false, Direction::Inbound)
                    .metadata
                    .unwrap()
                    .icmp_error,
                Some(IcmpError::Transport(..))
            ));
        }
    }

    #[test]
    fn ipv4_error_rejects_truncated_ports_and_unrelated_quotes() {
        let captured = captured_ipv4_network_unreachable();
        for len in IPV4_HEADER_LEN + 4..52 {
            assert!(inspect_packet(&captured[..len], false, Direction::Inbound)
                .metadata
                .unwrap()
                .icmp_error
                .is_none());
        }
        for (offset, value) in [
            (0, 0x65),  // wrong outer version
            (0, 0x44),  // invalid outer IHL
            (3, 51),    // ports outside declared outer length
            (20, 8),    // not an ICMP error
            (28, 0x65), // wrong quoted version
            (28, 0x44), // invalid quoted IHL
            (28, 0x4f), // options leave no quoted ports
            (31, 23),   // ports outside declared quoted length
            (35, 1),    // non-initial quoted fragment
            (37, 47),   // unsupported quoted protocol
            (40, 203),  // quoted source is not the local address
        ] {
            let mut packet = captured;
            packet[offset] = value;
            assert!(
                inspect_packet(&packet, false, Direction::Inbound)
                    .metadata
                    .unwrap()
                    .icmp_error
                    .is_none(),
                "offset {offset}"
            );
        }
    }

    fn ipv6_error_quote(protocol: IpProtocol) -> [u8; 96] {
        let mut packet = [0u8; 96];
        let local = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let router = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff);
        let remote = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&56u16.to_be_bytes());
        packet[6] = u8::from(IpProtocol::Icmpv6);
        packet[8..24].copy_from_slice(&router.0);
        packet[24..40].copy_from_slice(&local.0);
        packet[40] = 1;
        packet[48] = 0x60;
        packet[52..54].copy_from_slice(&20u16.to_be_bytes());
        packet[54] = u8::from(protocol);
        packet[56..72].copy_from_slice(&local.0);
        packet[72..88].copy_from_slice(&remote.0);
        packet[88..90].copy_from_slice(&50_000u16.to_be_bytes());
        packet[90..92].copy_from_slice(&443u16.to_be_bytes());
        packet
    }

    #[test]
    fn ipv6_errors_use_quoted_tcp_udp_and_echo_identity() {
        for protocol in [IpProtocol::Tcp, IpProtocol::Udp] {
            for kind in 1..=4 {
                let mut packet = ipv6_error_quote(protocol);
                packet[40] = kind;
                let metadata = inspect_packet(&packet, true, Direction::Inbound)
                    .metadata
                    .unwrap();
                assert_eq!(metadata.key.protocol, IpProtocol::Icmpv6);
                assert_eq!(metadata.key.local_port, 0);
                assert_eq!(metadata.key.remote_port, 0);
                assert!(
                    matches!(metadata.icmp_error, Some(IcmpError::Transport(quoted_protocol, address, 50_000, 443))
                    if quoted_protocol == protocol
                        && address == IpAddress::Ipv6(Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)))
                );
                assert!(inspect_packet(&packet, true, Direction::Outbound)
                    .metadata
                    .unwrap()
                    .icmp_error
                    .is_none());
            }
        }
        let mut packet = ipv6_error_quote(IpProtocol::Icmpv6);
        packet[88] = 128;
        packet[89] = 0;
        packet[92..94].copy_from_slice(&1u16.to_be_bytes());
        packet[94..96].copy_from_slice(&2u16.to_be_bytes());
        assert!(
            inspect_packet(&packet, true, Direction::Inbound)
                .metadata
                .unwrap()
                .icmp_error
                == Some(IcmpError::Echo(
                    IpAddress::Ipv6(Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
                    1,
                    2
                ))
        );
    }

    #[test]
    fn ipv6_error_rejects_truncated_and_unrelated_quotes() {
        let captured = ipv6_error_quote(IpProtocol::Tcp);
        for len in IPV6_HEADER_LEN..92 {
            assert!(inspect_packet(&captured[..len], true, Direction::Inbound)
                .metadata
                .unwrap()
                .icmp_error
                .is_none());
        }
        for (offset, value) in [
            (0, 0x40),  // wrong outer version
            (5, 51),    // ports outside declared outer length
            (40, 128),  // not an ICMPv6 error
            (48, 0x40), // wrong quoted version
            (53, 3),    // ports outside declared quoted payload
            (54, 47),   // unsupported quoted protocol
            (56, 0),    // quoted source is not the local address
        ] {
            let mut packet = captured;
            packet[offset] = value;
            assert!(
                inspect_packet(&packet, true, Direction::Inbound)
                    .metadata
                    .unwrap()
                    .icmp_error
                    .is_none(),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn ipv6_error_walks_outer_and_quoted_extensions_but_rejects_fragments() {
        let captured = ipv6_error_quote(IpProtocol::Udp);
        let mut packet = [0u8; 112];
        packet[..40].copy_from_slice(&captured[..40]);
        packet[4..6].copy_from_slice(&72u16.to_be_bytes());
        packet[6] = u8::from(IpProtocol::Ipv6Opts);
        packet[40] = u8::from(IpProtocol::Icmpv6);
        packet[48..96].copy_from_slice(&captured[40..88]);
        packet[60..62].copy_from_slice(&28u16.to_be_bytes());
        packet[62] = u8::from(IpProtocol::Ipv6Opts);
        packet[96] = u8::from(IpProtocol::Udp);
        packet[104..112].copy_from_slice(&captured[88..96]);
        assert!(matches!(
            inspect_packet(&packet, true, Direction::Inbound)
                .metadata
                .unwrap()
                .icmp_error,
            Some(IcmpError::Transport(IpProtocol::Udp, _, 50_000, 443))
        ));
        packet[62] = u8::from(IpProtocol::Ipv6Frag);
        packet[99] = 8; // non-initial fragment
        assert!(inspect_packet(&packet, true, Direction::Inbound)
            .metadata
            .unwrap()
            .icmp_error
            .is_none());
        packet[99] = 0; // atomic fragment
        assert!(matches!(
            inspect_packet(&packet, true, Direction::Inbound)
                .metadata
                .unwrap()
                .icmp_error,
            Some(IcmpError::Transport(..))
        ));
    }

    #[test]
    fn inspects_ipv6_tcp_after_extension_header() {
        const TRANSPORT_OFFSET: usize = IPV6_HEADER_LEN + 8;
        let mut packet = [0u8; TRANSPORT_OFFSET + 20];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&28u16.to_be_bytes());
        packet[6] = u8::from(IpProtocol::Ipv6Opts);
        packet[8..24].copy_from_slice(&Ipv6Address::LOOPBACK.0);
        let remote = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        packet[24..40].copy_from_slice(&remote.0);
        packet[40] = u8::from(IpProtocol::Tcp);
        packet[41] = 0;
        packet[TRANSPORT_OFFSET..TRANSPORT_OFFSET + 2].copy_from_slice(&50_001u16.to_be_bytes());
        packet[TRANSPORT_OFFSET + 2..TRANSPORT_OFFSET + 4].copy_from_slice(&443u16.to_be_bytes());
        packet[TRANSPORT_OFFSET + TCP_FLAGS_OFFSET] = TCP_RST_FLAG;

        let metadata = inspect_packet(&packet, true, Direction::Outbound)
            .metadata
            .expect("IPv6 metadata");
        assert_eq!(metadata.key.local_port, 50_001);
        assert_eq!(metadata.key.remote_port, 443);
        assert_eq!(metadata.key.remote_address, IpAddress::Ipv6(remote));
        assert!(metadata.is_tcp_reset);
        for direction in [Direction::Outbound, Direction::Inbound] {
            for (flags, is_reset) in [(0x04, true), (0x14, true), (0x10, false), (0x11, false)] {
                packet[TRANSPORT_OFFSET + TCP_FLAGS_OFFSET] = flags;
                let metadata = inspect_packet(&packet, true, direction).metadata.unwrap();
                assert_eq!(metadata.is_tcp_reset, is_reset);
            }
            packet[TRANSPORT_OFFSET + TCP_FLAGS_OFFSET] = TCP_RST_FLAG;
            let truncated = inspect_packet(
                &packet[..TRANSPORT_OFFSET + TCP_FLAGS_OFFSET],
                true,
                direction,
            )
            .metadata
            .unwrap();
            assert!(!truncated.is_tcp_reset);
        }
    }

    #[test]
    fn udp_payload_bit_is_not_a_tcp_reset() {
        for ipv6 in [false, true] {
            let mut packet = [0u8; IPV6_HEADER_LEN + 20];
            let transport_offset = if ipv6 {
                packet[0] = 0x60;
                packet[4..6].copy_from_slice(&20u16.to_be_bytes());
                packet[6] = u8::from(IpProtocol::Udp);
                IPV6_HEADER_LEN
            } else {
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&40u16.to_be_bytes());
                packet[9] = u8::from(IpProtocol::Udp);
                IPV4_HEADER_LEN
            };
            packet[transport_offset + TCP_FLAGS_OFFSET] = TCP_RST_FLAG;
            for direction in [Direction::Outbound, Direction::Inbound] {
                let metadata = inspect_packet(&packet, ipv6, direction).metadata.unwrap();
                assert!(!metadata.is_tcp_reset);
            }
        }
    }

    #[test]
    fn reports_ipv6_fragment_independently_from_transport_key() {
        let mut packet = [0u8; IPV6_HEADER_LEN + 8];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8u16.to_be_bytes());
        packet[6] = u8::from(IpProtocol::Ipv6Frag);
        packet[40] = u8::from(IpProtocol::Udp);
        packet[43] = 1;

        let inspected = inspect_packet(&packet, true, Direction::Inbound);
        assert!(inspected.is_fragment);
        let metadata = inspected.metadata.expect("fragment metadata");
        assert_eq!(metadata.key.protocol, IpProtocol::Udp);
        assert_eq!(metadata.key.local_port, 0);
        assert_eq!(metadata.key.remote_port, 0);
    }

    #[test]
    fn ipv6_port_unreachable_after_extension_header_keeps_icmp_key() {
        let mut packet = [0u8; IPV6_HEADER_LEN + 16];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&16u16.to_be_bytes());
        packet[6] = u8::from(IpProtocol::Ipv6Opts);
        packet[40] = u8::from(IpProtocol::Icmpv6);
        packet[41] = 0;
        packet[48] = ICMPV6_TYPE_DESTINATION_UNREACHABLE;
        packet[49] = ICMPV6_CODE_DU_PORT_UNREACHABLE;

        for direction in [Direction::Outbound, Direction::Inbound] {
            let metadata = inspect_packet(&packet, true, direction)
                .metadata
                .expect("ICMPv6 metadata");
            assert_eq!(metadata.key.protocol, IpProtocol::Icmpv6);
            assert_eq!(metadata.key.local_port, 0);
            assert_eq!(metadata.key.remote_port, 0);
            assert!(metadata.icmp_echo.is_none());
            assert!(metadata.icmp_error.is_none());
            assert!(!metadata.is_tcp_reset);
        }
    }

    #[test]
    fn rejects_unresolved_ipv6_extension_chain() {
        let mut packet = [0u8; IPV6_HEADER_LEN + 9 * 8];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(9u16 * 8).to_be_bytes());
        packet[6] = u8::from(IpProtocol::Ipv6Opts);
        for index in 0..9 {
            let offset = IPV6_HEADER_LEN + index * 8;
            packet[offset] = if index == 8 {
                u8::from(IpProtocol::Udp)
            } else {
                u8::from(IpProtocol::Ipv6Opts)
            };
        }

        let inspected = inspect_packet(&packet, true, Direction::Outbound);
        assert!(matches!(
            inspected.metadata,
            Err(PacketMetadataError::UnresolvedIpv6Headers)
        ));
    }
}
