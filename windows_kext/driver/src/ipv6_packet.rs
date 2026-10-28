use core::fmt;

use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv6Address, Ipv6ExtHeader, Ipv6Packet, TcpPacket, UdpPacket,
    IPV6_HEADER_LEN,
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

/// A read-only packet source. A prefix is requested only when its fields are
/// needed; readers may cache it without copying contiguous packet storage.
pub(crate) trait PacketData {
    fn len(&self) -> usize;
    fn prefix(&mut self, length: usize) -> Option<&[u8]>;

    #[inline]
    fn byte(&mut self, offset: usize) -> Option<u8> {
        self.prefix(offset.checked_add(1)?)?.get(offset).copied()
    }
}

impl<R: PacketData + ?Sized> PacketData for &mut R {
    #[inline]
    fn len(&self) -> usize {
        (**self).len()
    }

    #[inline]
    fn prefix(&mut self, length: usize) -> Option<&[u8]> {
        (**self).prefix(length)
    }

    #[inline]
    fn byte(&mut self, offset: usize) -> Option<u8> {
        (**self).byte(offset)
    }
}

impl PacketData for &[u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn prefix(&mut self, length: usize) -> Option<&[u8]> {
        self.get(..length)
    }
}

/// Walks the supported IPv6 extension headers and returns the upper-layer
/// protocol and offset. `packet` must begin at the IPv6 base header.
///
/// The walker understands Hop-by-Hop Options, Routing, Fragment and Destination
/// Options headers. An exact chain of `MAX_IPV6_EXT_HEADERS` is accepted when
/// the eighth header points to an upper-layer protocol; a ninth extension
/// header remains unresolved. With `stop_at_fragment`, a non-atomic Fragment
/// header ends the walk with `is_fragment = true` and `resolved = false`.
pub(crate) fn walk_ipv6_headers(mut packet: &[u8], stop_at_fragment: bool) -> Ipv6Headers {
    walk_ipv6_headers_reader(&mut packet, stop_at_fragment, true)
}

pub(crate) fn walk_ipv6_headers_reader(
    packet: &mut impl PacketData,
    stop_at_fragment: bool,
    inspect_routing_header: bool,
) -> Ipv6Headers {
    let mut result = Ipv6Headers {
        protocol: IpProtocol::Unknown(0),
        transport_offset: IPV6_HEADER_LEN,
        is_fragment: false,
        active_routing_header: false,
        resolved: false,
    };

    let Some(base_header) = packet.prefix(IPV6_HEADER_LEN) else {
        return result;
    };

    let mut protocol = Ipv6Packet::new_unchecked(base_header).next_header();
    let mut offset = IPV6_HEADER_LEN;
    let mut extension_count = 0;

    loop {
        match protocol {
            IpProtocol::Ipv6Frag => {
                if extension_count >= MAX_IPV6_EXT_HEADERS {
                    break;
                }
                extension_count += 1;

                // Require the complete eight-byte header to be present, but
                // only Next Header and the fragment bits need to be read.
                let Some(end) = offset.checked_add(8).filter(|end| *end <= packet.len()) else {
                    break;
                };
                let Some(prefix) = packet.prefix(offset + 4) else {
                    break;
                };
                let fragment_bits = u16::from_be_bytes([prefix[offset + 2], prefix[offset + 3]]);
                protocol = IpProtocol::from(prefix[offset]);
                offset = end;
                if fragment_bits & 0xfff9 != 0 {
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

                let Some(end) = offset.checked_add(2) else {
                    break;
                };
                let Some(prefix) = packet.prefix(end) else {
                    break;
                };
                let extension = Ipv6ExtHeader::new_unchecked(&prefix[offset..end]);
                let next_header = extension.next_header();
                // Hdr Ext Len counts eight-octet units after the first eight.
                let length = (extension.header_len() as usize + 1) * 8;
                // Preserve the checked-header contract without materializing its
                // uninterpreted body: the whole declared header must be present.
                let Some(next_offset) = offset
                    .checked_add(length)
                    .filter(|end| *end <= packet.len())
                else {
                    break;
                };

                // Only checksum rewriting needs Segments Left. Its packet source
                // is already a slice; metadata inspection does not read options
                // bodies or routing addresses.
                if inspect_routing_header && protocol == IpProtocol::Ipv6Route {
                    result.active_routing_header |= offset
                        .checked_add(4)
                        .and_then(|end| packet.prefix(end))
                        .is_some_and(|prefix| prefix[offset + 3] != 0);
                }

                protocol = next_header;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ipv6TransportError {
    InvalidPacket,
    UnresolvedHeaders,
    FragmentedPacket,
    ActiveRoutingHeader,
    UnsupportedProtocol,
    InvalidTransportHeader,
}

impl fmt::Display for Ipv6TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidPacket => "invalid IPv6 packet",
            Self::UnresolvedHeaders => "IPv6 extension header chain did not resolve",
            Self::FragmentedPacket => "cannot calculate a checksum for an individual IPv6 fragment",
            Self::ActiveRoutingHeader => {
                "cannot calculate a checksum through an active IPv6 routing header"
            }
            Self::UnsupportedProtocol => "IPv6 packet does not contain TCP or UDP",
            Self::InvalidTransportHeader => "invalid IPv6 transport header",
        };
        formatter.write_str(message)
    }
}

struct TransportContext {
    protocol: IpProtocol,
    offset: usize,
    total_len: usize,
    source: Ipv6Address,
    destination: Ipv6Address,
}

fn transport_context(packet: &[u8]) -> Result<TransportContext, Ipv6TransportError> {
    let ip_packet =
        Ipv6Packet::new_checked(packet).map_err(|_| Ipv6TransportError::InvalidPacket)?;
    if ip_packet.version() != 6 {
        return Err(Ipv6TransportError::InvalidPacket);
    }

    let total_len = ip_packet.total_len();
    // A zero Payload Length can denote a jumbogram, whose 32-bit length lives
    // in the Hop-by-Hop Jumbo Payload option. smoltcp exposes only the base
    // 16-bit field here, so treating the trailing bytes as a normal transport
    // segment would calculate the wrong pseudo-header length.
    if ip_packet.payload_len() == 0 && packet.len() > IPV6_HEADER_LEN {
        return Err(Ipv6TransportError::InvalidPacket);
    }
    let headers = walk_ipv6_headers(&packet[..total_len], false);
    if !headers.resolved || headers.transport_offset > total_len {
        return Err(Ipv6TransportError::UnresolvedHeaders);
    }
    if headers.is_fragment {
        return Err(Ipv6TransportError::FragmentedPacket);
    }
    if headers.active_routing_header {
        return Err(Ipv6TransportError::ActiveRoutingHeader);
    }

    Ok(TransportContext {
        protocol: headers.protocol,
        offset: headers.transport_offset,
        total_len,
        source: ip_packet.src_addr(),
        destination: ip_packet.dst_addr(),
    })
}

fn validate_transport(packet: &[u8], context: &TransportContext) -> Result<(), Ipv6TransportError> {
    let transport = packet
        .get(context.offset..context.total_len)
        .ok_or(Ipv6TransportError::InvalidTransportHeader)?;

    match context.protocol {
        IpProtocol::Udp => UdpPacket::new_checked(transport)
            .map(|_| ())
            .map_err(|_| Ipv6TransportError::InvalidTransportHeader),
        IpProtocol::Tcp => TcpPacket::new_checked(transport)
            .map(|_| ())
            .map_err(|_| Ipv6TransportError::InvalidTransportHeader),
        _ => Err(Ipv6TransportError::UnsupportedProtocol),
    }
}

/// Recomputes a TCP or UDP checksum using the upper-layer length, excluding all
/// IPv6 extension headers from the pseudo-header length.
pub(crate) fn recalculate_ipv6_transport_checksum(
    packet: &mut [u8],
) -> Result<(), Ipv6TransportError> {
    let context = transport_context(packet)?;

    // Preserve the old behavior for non-TCP/UDP traffic: there is no transport
    // checksum for this routine to update.
    if !matches!(context.protocol, IpProtocol::Tcp | IpProtocol::Udp) {
        return Ok(());
    }
    validate_transport(packet, &context)?;

    let transport = packet
        .get_mut(context.offset..context.total_len)
        .ok_or(Ipv6TransportError::InvalidTransportHeader)?;
    let source = IpAddress::Ipv6(context.source);
    let destination = IpAddress::Ipv6(context.destination);

    match context.protocol {
        IpProtocol::Udp => UdpPacket::new_checked(transport)
            .map_err(|_| Ipv6TransportError::InvalidTransportHeader)?
            .fill_checksum(&source, &destination),
        IpProtocol::Tcp => TcpPacket::new_checked(transport)
            .map_err(|_| Ipv6TransportError::InvalidTransportHeader)?
            .fill_checksum(&source, &destination),
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_address() -> Ipv6Address {
        Ipv6Address::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6)
    }

    fn destination_address() -> Ipv6Address {
        Ipv6Address::new(0x2001, 0xdb8, 7, 8, 9, 10, 11, 12)
    }

    fn initialize_ipv6(
        packet: &mut [u8],
        next_header: IpProtocol,
        source: Ipv6Address,
        destination: Ipv6Address,
    ) {
        let payload_len = packet.len() - IPV6_HEADER_LEN;
        let mut ip_packet = Ipv6Packet::new_unchecked(packet);
        ip_packet.set_version(6);
        ip_packet.set_payload_len(payload_len as u16);
        ip_packet.set_next_header(next_header);
        ip_packet.set_hop_limit(64);
        ip_packet.set_src_addr(source);
        ip_packet.set_dst_addr(destination);
    }

    fn initialize_udp(
        packet: &mut [u8],
        offset: usize,
        source: Ipv6Address,
        destination: Ipv6Address,
        source_port: u16,
        destination_port: u16,
    ) {
        let length = packet.len() - offset;
        let mut udp_packet = UdpPacket::new_unchecked(&mut packet[offset..]);
        udp_packet.set_src_port(source_port);
        udp_packet.set_dst_port(destination_port);
        udp_packet.set_len(length as u16);
        udp_packet.fill_checksum(&IpAddress::Ipv6(source), &IpAddress::Ipv6(destination));
    }

    fn initialize_tcp(
        packet: &mut [u8],
        offset: usize,
        source: Ipv6Address,
        destination: Ipv6Address,
        source_port: u16,
        destination_port: u16,
    ) {
        let mut tcp_packet = TcpPacket::new_unchecked(&mut packet[offset..]);
        tcp_packet.set_src_port(source_port);
        tcp_packet.set_dst_port(destination_port);
        tcp_packet.set_header_len(20);
        tcp_packet.fill_checksum(&IpAddress::Ipv6(source), &IpAddress::Ipv6(destination));
    }

    fn options_chain(extension_count: usize) -> Vec<u8> {
        let transport_offset = IPV6_HEADER_LEN + extension_count * 8;
        let mut packet = vec![0u8; transport_offset + 8];
        initialize_ipv6(
            &mut packet,
            IpProtocol::Ipv6Opts,
            source_address(),
            destination_address(),
        );

        for index in 0..extension_count {
            let offset = IPV6_HEADER_LEN + index * 8;
            packet[offset] = if index + 1 == extension_count {
                u8::from(IpProtocol::Udp)
            } else {
                u8::from(IpProtocol::Ipv6Opts)
            };
            packet[offset + 1] = 0;
        }

        initialize_udp(
            &mut packet,
            transport_offset,
            source_address(),
            destination_address(),
            1000,
            2000,
        );
        packet
    }

    #[test]
    fn resolves_exactly_eight_extension_headers() {
        let packet = options_chain(MAX_IPV6_EXT_HEADERS);
        let headers = walk_ipv6_headers(&packet, false);

        assert!(headers.resolved);
        assert_eq!(headers.protocol, IpProtocol::Udp);
        assert_eq!(
            headers.transport_offset,
            IPV6_HEADER_LEN + MAX_IPV6_EXT_HEADERS * 8
        );
    }

    #[test]
    fn rejects_a_ninth_extension_header() {
        let packet = options_chain(MAX_IPV6_EXT_HEADERS + 1);
        let headers = walk_ipv6_headers(&packet, false);

        assert!(!headers.resolved);
        assert_eq!(headers.protocol, IpProtocol::Ipv6Opts);
    }

    #[test]
    fn reads_fragment_fields_after_next_header_and_reserved() {
        let transport_offset = IPV6_HEADER_LEN + 8;
        let mut packet = vec![0u8; transport_offset + 8];
        initialize_ipv6(
            &mut packet,
            IpProtocol::Ipv6Frag,
            source_address(),
            destination_address(),
        );
        packet[IPV6_HEADER_LEN] = u8::from(IpProtocol::Udp);

        let atomic = walk_ipv6_headers(&packet, false);
        assert!(atomic.resolved);
        assert!(!atomic.is_fragment);
        assert_eq!(atomic.protocol, IpProtocol::Udp);
        assert_eq!(atomic.transport_offset, transport_offset);

        // The M bit is in byte three of the complete Fragment header, not in
        // the Next Header/Reserved pair at bytes zero and one.
        packet[IPV6_HEADER_LEN + 3] = 1;
        assert!(walk_ipv6_headers(&packet, false).is_fragment);
    }

    #[test]
    fn stops_at_non_atomic_fragments_only_when_requested() {
        // Options -> Fragment -> Options -> UDP.
        let mut packet = options_chain(3);
        packet[IPV6_HEADER_LEN] = u8::from(IpProtocol::Ipv6Frag);
        let fragment_offset = IPV6_HEADER_LEN + 8;
        let fragment_end = fragment_offset + 8;

        for bits in [0u16, 1, 8, 9] {
            packet[fragment_offset + 2..fragment_offset + 4].copy_from_slice(&bits.to_be_bytes());
            for stop_at_fragment in [false, true] {
                let headers = walk_ipv6_headers(&packet, stop_at_fragment);
                let stopped = stop_at_fragment && bits != 0;
                assert_eq!(headers.is_fragment, bits != 0);
                assert_eq!(headers.resolved, !stopped);
                assert_eq!(
                    headers.transport_offset,
                    if stopped {
                        fragment_end
                    } else {
                        fragment_end + 8
                    }
                );
                assert_eq!(
                    headers.protocol,
                    if stopped {
                        IpProtocol::Ipv6Opts
                    } else {
                        IpProtocol::Udp
                    }
                );

                let truncated = walk_ipv6_headers(&packet[..fragment_end], stop_at_fragment);
                assert_eq!(truncated.is_fragment, bits != 0);
                assert!(!truncated.resolved);
                assert_eq!(truncated.transport_offset, fragment_end);
            }
        }
    }

    #[test]
    fn recalculates_udp_checksum_after_multiple_extension_headers() {
        let source = source_address();
        let destination = destination_address();
        let transport_offset = IPV6_HEADER_LEN + 16;
        let mut packet = vec![0u8; transport_offset + 12];
        initialize_ipv6(&mut packet, IpProtocol::HopByHop, source, destination);
        packet[IPV6_HEADER_LEN] = u8::from(IpProtocol::Ipv6Opts);
        packet[IPV6_HEADER_LEN + 1] = 0;
        packet[IPV6_HEADER_LEN + 8] = u8::from(IpProtocol::Udp);
        packet[IPV6_HEADER_LEN + 9] = 0;
        initialize_udp(
            &mut packet,
            transport_offset,
            source,
            destination,
            12000,
            53,
        );
        let headers = packet[..transport_offset].to_vec();
        packet[transport_offset + 6..transport_offset + 8].fill(0);

        recalculate_ipv6_transport_checksum(&mut packet).unwrap();

        assert_eq!(&packet[..transport_offset], &headers);
        let udp_packet = UdpPacket::new_checked(&packet[transport_offset..]).unwrap();
        assert_eq!(udp_packet.src_port(), 12000);
        assert_eq!(udp_packet.dst_port(), 53);
        assert!(udp_packet.verify_checksum(&IpAddress::Ipv6(source), &IpAddress::Ipv6(destination)));
    }

    #[test]
    fn recalculates_tcp_checksum_after_inactive_routing_header() {
        let source = source_address();
        let destination = destination_address();
        let transport_offset = IPV6_HEADER_LEN + 8;
        let mut packet = vec![0u8; transport_offset + 24];
        initialize_ipv6(&mut packet, IpProtocol::Ipv6Route, source, destination);
        packet[IPV6_HEADER_LEN] = u8::from(IpProtocol::Tcp);
        packet[IPV6_HEADER_LEN + 1] = 0;
        packet[IPV6_HEADER_LEN + 2] = 4;
        packet[IPV6_HEADER_LEN + 3] = 0;
        initialize_tcp(
            &mut packet,
            transport_offset,
            source,
            destination,
            443,
            40000,
        );
        let headers = packet[..transport_offset].to_vec();
        packet[transport_offset + 16..transport_offset + 18].fill(0);

        recalculate_ipv6_transport_checksum(&mut packet).unwrap();

        assert_eq!(&packet[..transport_offset], &headers);
        let tcp_packet = TcpPacket::new_checked(&packet[transport_offset..]).unwrap();
        assert_eq!(tcp_packet.src_port(), 443);
        assert_eq!(tcp_packet.dst_port(), 40000);
        assert!(tcp_packet.verify_checksum(&IpAddress::Ipv6(source), &IpAddress::Ipv6(destination)));
    }

    #[test]
    fn recalculates_checksum_from_transport_offset() {
        let mut packet = options_chain(2);
        let headers = walk_ipv6_headers(&packet, false);
        let checksum_offset = headers.transport_offset + 6;
        packet[checksum_offset] = 0;
        packet[checksum_offset + 1] = 0;

        recalculate_ipv6_transport_checksum(&mut packet).unwrap();

        let udp_packet = UdpPacket::new_checked(&packet[headers.transport_offset..]).unwrap();
        assert!(udp_packet.verify_checksum(
            &IpAddress::Ipv6(source_address()),
            &IpAddress::Ipv6(destination_address()),
        ));
    }

    #[test]
    fn leaves_unresolved_packet_unchanged() {
        let mut packet = options_chain(1);
        packet[IPV6_HEADER_LEN + 1] = 10;
        let original = packet.clone();

        assert_eq!(
            recalculate_ipv6_transport_checksum(&mut packet),
            Err(Ipv6TransportError::UnresolvedHeaders)
        );
        assert_eq!(packet, original);
    }

    #[test]
    fn rejects_active_routing_header_without_mutation() {
        let source = source_address();
        let destination = destination_address();
        let transport_offset = IPV6_HEADER_LEN + 8;
        let mut packet = vec![0u8; transport_offset + 20];
        initialize_ipv6(&mut packet, IpProtocol::Ipv6Route, source, destination);
        packet[IPV6_HEADER_LEN] = u8::from(IpProtocol::Tcp);
        packet[IPV6_HEADER_LEN + 1] = 0;
        packet[IPV6_HEADER_LEN + 2] = 4;
        packet[IPV6_HEADER_LEN + 3] = 1;
        initialize_tcp(
            &mut packet,
            transport_offset,
            source,
            destination,
            443,
            40000,
        );
        let original = packet.clone();

        assert_eq!(
            recalculate_ipv6_transport_checksum(&mut packet),
            Err(Ipv6TransportError::ActiveRoutingHeader)
        );
        assert_eq!(packet, original);
    }
}
