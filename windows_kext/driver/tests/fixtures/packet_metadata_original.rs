// Frozen parser and IPv6 walker from bab1546, before the on-demand reader.
// Test-only reference: keep behavior independent of the optimized parser.
#![allow(dead_code, unused_imports)]

use core::fmt;

use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Packet, IPV4_HEADER_LEN, IPV6_HEADER_LEN,
};

use crate::{connection::Direction, connection_map::Key};
use original_ipv6::walk_ipv6_headers;

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
    FragmentRequiresReassembly,
}

impl fmt::Display for PacketMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnreadablePacket => "failed to get net_buffer data",
            Self::UnresolvedIpv6Headers => "IPv6 extension header chain did not resolve",
            Self::FragmentRequiresReassembly => "IP fragment requires reassembly",
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

/// Parses the packet callout's metadata from one bounded prefix. When the first
/// NBL can bypass policy as an individual fragment, stop before parsing its key
/// or transport fields; reassembled indications still need that metadata.
pub(crate) fn inspect_packet(
    packet: &[u8],
    ipv6: bool,
    direction: Direction,
    permit_fragments: bool,
) -> PacketInspection {
    if ipv6 {
        inspect_ipv6_packet(packet, direction, permit_fragments)
    } else {
        inspect_ipv4_packet(packet, direction, permit_fragments)
    }
}

fn inspect_ipv4_packet(
    packet: &[u8],
    direction: Direction,
    permit_fragments: bool,
) -> PacketInspection {
    if packet.len() < IPV4_HEADER_LEN {
        return PacketInspection::unreadable();
    }

    let ip_packet = Ipv4Packet::new_unchecked(packet);
    let is_fragment = ip_packet.frag_offset() != 0 || ip_packet.more_frags();
    if permit_fragments && is_fragment {
        return PacketInspection {
            is_fragment,
            metadata: Err(PacketMetadataError::FragmentRequiresReassembly),
        };
    }

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

fn inspect_ipv6_packet(
    packet: &[u8],
    direction: Direction,
    permit_fragments: bool,
) -> PacketInspection {
    if packet.len() < IPV6_HEADER_LEN {
        return PacketInspection::unreadable();
    }

    let ip_packet = Ipv6Packet::new_unchecked(packet);
    let headers = walk_ipv6_headers(packet, permit_fragments);
    if permit_fragments && headers.is_fragment {
        return PacketInspection {
            is_fragment: true,
            metadata: Err(PacketMetadataError::FragmentRequiresReassembly),
        };
    }
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
    let headers = walk_ipv6_headers(quoted, false);
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

mod original_ipv6 {
    use core::fmt;

    use smoltcp::wire::{
        IpAddress, IpProtocol, Ipv6Address, Ipv6ExtHeader, Ipv6FragmentHeader, Ipv6Packet,
        TcpPacket, UdpPacket, IPV6_HEADER_LEN,
    };

    /// Maximum number of IPv6 extension headers followed before a packet is
    /// considered unresolved. This bounds work performed by a packet callout at
    /// DISPATCH_LEVEL.
    const MAX_IPV6_EXT_HEADERS: usize = 8;

    /// Result of walking an IPv6 extension-header chain.
    pub(crate) struct Ipv6Headers {
        /// The upper-layer protocol after all supported extension headers.
        pub(crate) protocol: IpProtocol,
        /// Byte offset of the upper-layer header from the IPv6 base header.
        pub(crate) transport_offset: usize,
        /// True for a non-atomic fragment. Its transport checksum cannot be
        /// recalculated from this packet alone.
        pub(crate) is_fragment: bool,
        /// A routing header with Segments Left greater than zero was encountered.
        /// In that case the final destination needed by the pseudo-header is not
        /// necessarily the destination in the IPv6 base header.
        active_routing_header: bool,
        /// True when the walk reached an upper-layer protocol within the limit.
        pub(crate) resolved: bool,
    }

    /// Walks the supported IPv6 extension headers and returns the upper-layer
    /// protocol and offset. `packet` must begin at the IPv6 base header.
    ///
    /// The walker understands Hop-by-Hop Options, Routing, Fragment and Destination
    /// Options headers. An exact chain of `MAX_IPV6_EXT_HEADERS` is accepted when
    /// the eighth header points to an upper-layer protocol; a ninth extension
    /// header remains unresolved. With `stop_at_fragment`, a non-atomic Fragment
    /// header ends the walk with `is_fragment = true` and `resolved = false`.
    pub(crate) fn walk_ipv6_headers(packet: &[u8], stop_at_fragment: bool) -> Ipv6Headers {
        let mut result = Ipv6Headers {
            protocol: IpProtocol::Unknown(0),
            transport_offset: IPV6_HEADER_LEN,
            is_fragment: false,
            active_routing_header: false,
            resolved: false,
        };

        if packet.len() < IPV6_HEADER_LEN {
            return result;
        }

        let mut protocol = Ipv6Packet::new_unchecked(packet).next_header();
        let mut offset = IPV6_HEADER_LEN;
        let mut extension_count = 0;

        loop {
            match protocol {
                IpProtocol::Ipv6Frag => {
                    if extension_count >= MAX_IPV6_EXT_HEADERS {
                        break;
                    }
                    extension_count += 1;

                    // The complete Fragment header is eight bytes. smoltcp's
                    // Ipv6FragmentHeader models only the six bytes after Next Header
                    // and Reserved, so pass exactly that sub-slice to it.
                    let Some(end) = offset.checked_add(8) else {
                        break;
                    };
                    let Some(header) = packet.get(offset..end) else {
                        break;
                    };
                    let Ok(fragment) = Ipv6FragmentHeader::new_checked(&header[2..]) else {
                        break;
                    };

                    protocol = IpProtocol::from(header[0]);
                    offset = end;
                    if fragment.frag_offset() != 0 || fragment.more_frags() {
                        result.is_fragment = true;
                        if stop_at_fragment {
                            break;
                        }
                    }
                }
                IpProtocol::HopByHop | IpProtocol::Ipv6Route | IpProtocol::Ipv6Opts => {
                    if extension_count >= MAX_IPV6_EXT_HEADERS {
                        break;
                    }
                    extension_count += 1;

                    let Some(rest) = packet.get(offset..) else {
                        break;
                    };
                    let Ok(extension) = Ipv6ExtHeader::new_checked(rest) else {
                        break;
                    };

                    // A checksum pseudo-header uses the final destination when a
                    // Routing header is active. Generic routing types encode that
                    // address differently, so checksum rewriting is rejected below
                    // unless Segments Left is zero and the base destination is final.
                    if protocol == IpProtocol::Ipv6Route
                        && rest.get(3).copied().unwrap_or_default() != 0
                    {
                        result.active_routing_header = true;
                    }

                    // Hdr Ext Len counts eight-octet units after the first eight.
                    let length = (extension.header_len() as usize + 1) * 8;
                    protocol = extension.next_header();
                    let Some(next_offset) = offset.checked_add(length) else {
                        break;
                    };
                    offset = next_offset;
                }
                _ => {
                    // Reaching this branch after parsing the eighth extension header
                    // is valid. The old fixed-range loop stopped one iteration too
                    // early and incorrectly left such a chain unresolved.
                    result.resolved = true;
                    break;
                }
            }
        }

        result.protocol = protocol;
        result.transport_offset = offset;
        result
    }
}
