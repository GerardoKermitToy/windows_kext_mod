use core::fmt;

use likely_stable::{likely, unlikely};
use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet, IPV4_HEADER_LEN,
    IPV6_HEADER_LEN,
};

use crate::{
    connection::Direction,
    connection_map::Key,
    ipv6_packet::{walk_ipv6_headers_reader, PacketData},
};

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

#[derive(Clone, Copy, Default)]
pub(crate) struct IcmpMetadata {
    pub(crate) echo: Option<IcmpEcho>,
    pub(crate) error: Option<IcmpError>,
    pub(crate) is_local_error: bool,
}

// Keep this cache register-sized: fragment/key/RST checks must not copy IP
// addresses or compute ICMP validation fields. The bounded IPv6 walker advances
// through at most eight 2048-byte extension headers, so its offset fits in u16.
#[derive(Clone, Copy)]
struct HeaderInspection {
    protocol: IpProtocol,
    transport_offset: u16,
    is_fragment: bool,
    valid_tcp_flags: bool,
    error: Option<PacketMetadataError>,
}

impl HeaderInspection {
    fn unreadable() -> Self {
        Self {
            protocol: IpProtocol::Unknown(0),
            transport_offset: 0,
            is_fragment: false,
            valid_tcp_flags: false,
            error: Some(PacketMetadataError::UnreadablePacket),
        }
    }
}

/// Packet-callout fields are resolved on demand. The reader is borrowed in the
/// callout, and the caller owns the key: neither packet storage nor a second key
/// is copied into this inspector. TCP flags and ICMP quotes remain lazy.
/// Branch hints favor IPv4 TCP/UDP traffic without excluding other packets.
pub(crate) struct PacketInspector<R> {
    reader: R,
    ipv6: bool,
    direction: Direction,
    permit_fragments: bool,
    header: Option<HeaderInspection>,
    tcp_reset: Option<bool>,
}

impl<R: PacketData> PacketInspector<R> {
    pub(crate) fn new(reader: R, ipv6: bool, direction: Direction, permit_fragments: bool) -> Self {
        Self {
            reader,
            ipv6,
            direction,
            permit_fragments,
            header: None,
            tcp_reset: None,
        }
    }

    #[cfg(test)]
    fn is_fragment(&mut self) -> bool {
        self.header().is_fragment
    }

    #[inline]
    pub(crate) fn key(&mut self) -> Result<Key, PacketMetadataError> {
        self.read_key()
    }

    // Preserve the first probe's single retry on an actual read/parse failure.
    pub(crate) fn retry_key(&mut self) -> Result<Key, PacketMetadataError> {
        self.permit_fragments = false;
        self.header = None;
        self.tcp_reset = None;
        self.key()
    }

    pub(crate) fn icmp_metadata(&mut self, key: &Key) -> IcmpMetadata {
        self.read_icmp_metadata(key).unwrap_or_default()
    }

    #[inline]
    pub(crate) fn is_tcp_reset(&mut self) -> bool {
        if let Some(reset) = self.tcp_reset {
            return reset;
        }
        let header = self.header();
        let offset = usize::from(header.transport_offset);
        let reset = header.error.is_none()
            && header.protocol == IpProtocol::Tcp
            && header.valid_tcp_flags
            && self
                .reader
                .byte(offset + TCP_FLAGS_OFFSET)
                .is_some_and(|flags| flags & TCP_RST_FLAG != 0);
        self.tcp_reset = Some(reset);
        reset
    }

    #[inline(always)]
    fn header(&mut self) -> HeaderInspection {
        // Keep cache hits out of the reader/walker's stack frame. In particular,
        // the RST accessor after a key lookup only loads this small value.
        match self.header {
            Some(header) => header,
            None => self.read_header(),
        }
    }

    fn read_header(&mut self) -> HeaderInspection {
        let base_length = if unlikely(self.ipv6) {
            IPV6_HEADER_LEN
        } else {
            IPV4_HEADER_LEN
        };
        // Four bytes of lookahead keep the ordinary IP+ports path to one NDIS
        // call rather than doubling its cost just to learn the protocol/IHL.
        let initial_length = core::cmp::min(self.reader.len(), base_length + 4);
        let header = if likely(initial_length >= base_length) {
            self.reader
                .prefix(initial_length)
                .map(|packet| Self::parse_base_header(packet, self.ipv6, self.permit_fragments))
        } else {
            None
        }
        .or_else(|| {
            self.reader
                .prefix(base_length)
                .map(|packet| Self::parse_base_header(packet, self.ipv6, self.permit_fragments))
        })
        .unwrap_or_else(HeaderInspection::unreadable);
        let header = self.resolve_ipv6_header(header);
        self.header = Some(header);
        header
    }

    fn resolve_ipv6_header(&mut self, mut header: HeaderInspection) -> HeaderInspection {
        if unlikely(
            self.ipv6
                && header.error.is_none()
                && matches!(
                    header.protocol,
                    IpProtocol::HopByHop
                        | IpProtocol::Ipv6Route
                        | IpProtocol::Ipv6Frag
                        | IpProtocol::Ipv6Opts
                ),
        ) {
            let headers = walk_ipv6_headers_reader(&mut self.reader, self.permit_fragments, false);
            header.protocol = headers.protocol;
            header.transport_offset = headers.transport_offset as u16;
            header.is_fragment = headers.is_fragment;
            header.error = if self.permit_fragments && headers.is_fragment {
                Some(PacketMetadataError::FragmentRequiresReassembly)
            } else if !headers.resolved {
                Some(PacketMetadataError::UnresolvedIpv6Headers)
            } else {
                None
            };
        }
        header
    }

    #[inline(always)]
    fn parse_base_header(packet: &[u8], ipv6: bool, permit_fragments: bool) -> HeaderInspection {
        if unlikely(ipv6) {
            HeaderInspection {
                protocol: IpProtocol::from(packet[6]),
                transport_offset: IPV6_HEADER_LEN as u16,
                is_fragment: false,
                valid_tcp_flags: true,
                error: None,
            }
        } else {
            let ip_packet = Ipv4Packet::new_unchecked(packet);
            let is_fragment = ip_packet.frag_offset() != 0 || ip_packet.more_frags();
            let raw_offset = usize::from(ip_packet.header_len());
            HeaderInspection {
                protocol: IpProtocol::from(packet[9]),
                transport_offset: core::cmp::max(raw_offset, IPV4_HEADER_LEN) as u16,
                is_fragment,
                valid_tcp_flags: (IPV4_HEADER_LEN..=IPV4_MAX_HEADER_LEN).contains(&raw_offset),
                error: unlikely(permit_fragments && is_fragment)
                    .then_some(PacketMetadataError::FragmentRequiresReassembly),
            }
        }
    }

    #[inline]
    fn read_key(&mut self) -> Result<Key, PacketMetadataError> {
        if self.header.is_none() {
            let base_length = if unlikely(self.ipv6) {
                IPV6_HEADER_LEN
            } else {
                IPV4_HEADER_LEN
            };
            let initial_length = core::cmp::min(self.reader.len(), base_length + 4);
            let packet = if likely(initial_length >= base_length) {
                self.reader.prefix(initial_length)
            } else {
                None
            };
            if let Some(packet) = packet {
                let header = Self::parse_base_header(packet, self.ipv6, self.permit_fragments);
                self.header = Some(header);
                if let Some(error) = header.error {
                    return Err(error);
                }
                let extension = self.ipv6
                    && matches!(
                        header.protocol,
                        IpProtocol::HopByHop
                            | IpProtocol::Ipv6Route
                            | IpProtocol::Ipv6Frag
                            | IpProtocol::Ipv6Opts
                    );
                let key_end =
                    if likely(matches!(header.protocol, IpProtocol::Tcp | IpProtocol::Udp)) {
                        usize::from(header.transport_offset) + 4
                    } else if unlikely(self.ipv6) {
                        IPV6_HEADER_LEN
                    } else {
                        IPV4_HEADER_LEN + 4
                    };
                if likely(!extension && packet.len() >= key_end) {
                    // The common path parses the key from the first read itself,
                    // not through another cached-prefix lookup or header call.
                    return Ok(Self::parse_key(packet, self.ipv6, self.direction, header));
                }
                if unlikely(extension) {
                    let header = self.resolve_ipv6_header(header);
                    self.header = Some(header);
                }
            } else {
                // A short fallback must still detect fragments, and the key's
                // mandatory bytes may recover on the subsequent read below.
                let header = self
                    .reader
                    .prefix(base_length)
                    .map(|packet| Self::parse_base_header(packet, self.ipv6, self.permit_fragments))
                    .unwrap_or_else(HeaderInspection::unreadable);
                let header = self.resolve_ipv6_header(header);
                self.header = Some(header);
            }
        }
        let header = self.header();
        if let Some(error) = header.error {
            return Err(error);
        }
        // Preserve the IPv4 key contract even for protocols without ports.
        let length = if unlikely(self.ipv6) {
            IPV6_HEADER_LEN
        } else {
            IPV4_HEADER_LEN + 4
        };
        let packet = self
            .reader
            .prefix(length)
            .ok_or(PacketMetadataError::UnreadablePacket)?;
        let (source, destination) = Self::key_addresses(packet, self.ipv6);
        let offset = usize::from(header.transport_offset);
        let ports = if likely(matches!(header.protocol, IpProtocol::Tcp | IpProtocol::Udp)) {
            if let Some(transport) = packet.get(offset..offset + 4) {
                get_ports(transport, header.protocol)
            } else if unlikely(offset + 4 > self.reader.len()) {
                (0, 0)
            } else {
                // Present but unreadable ports must not produce a cache-miss key.
                self.reader
                    .prefix(offset + 4)
                    .map(|packet| get_ports(&packet[offset..], header.protocol))
                    .ok_or(PacketMetadataError::UnreadablePacket)?
            }
        } else {
            (0, 0)
        };
        Ok(build_key(
            self.direction,
            header.protocol,
            source,
            ports.0,
            destination,
            ports.1,
        ))
    }

    #[inline(always)]
    fn parse_key(packet: &[u8], ipv6: bool, direction: Direction, header: HeaderInspection) -> Key {
        let (source, destination) = Self::key_addresses(packet, ipv6);
        let transport = packet
            .get(usize::from(header.transport_offset)..)
            .unwrap_or_default();
        let (source_port, destination_port) = get_ports(transport, header.protocol);
        build_key(
            direction,
            header.protocol,
            source,
            source_port,
            destination,
            destination_port,
        )
    }

    #[inline(always)]
    fn key_addresses(packet: &[u8], ipv6: bool) -> (IpAddress, IpAddress) {
        // Both callers already require a complete base header. Read its known
        // address ranges without separate IP packet accessor call frames.
        if unlikely(ipv6) {
            (
                IpAddress::Ipv6(Ipv6Address::from_bytes(&packet[8..24])),
                IpAddress::Ipv6(Ipv6Address::from_bytes(&packet[24..40])),
            )
        } else {
            (
                IpAddress::Ipv4(Ipv4Address::from_bytes(&packet[12..16])),
                IpAddress::Ipv4(Ipv4Address::from_bytes(&packet[16..20])),
            )
        }
    }

    fn read_icmp_metadata(&mut self, key: &Key) -> Option<IcmpMetadata> {
        let header = self.header();
        if header.error.is_some()
            || header.protocol
                != if unlikely(self.ipv6) {
                    IpProtocol::Icmpv6
                } else {
                    IpProtocol::Icmp
                }
        {
            return None;
        }
        let offset = usize::from(header.transport_offset);
        let end = offset + ICMP_HEADER_LEN;
        let packet = self.reader.prefix(end)?;
        let transport = &packet[offset..];
        let echo = get_icmp_echo(transport, self.ipv6);
        // Version and declared length matter only for ICMP error attribution,
        // not for the common TCP/UDP key or fragment path.
        let (packet_end, valid_error) = if unlikely(self.ipv6) {
            let ip_packet = Ipv6Packet::new_unchecked(packet);
            (
                ip_packet.total_len(),
                ip_packet.version() == 6 && matches!(transport[0], 1..=4),
            )
        } else {
            let ip_packet = Ipv4Packet::new_unchecked(packet);
            (
                usize::from(ip_packet.total_len()),
                ip_packet.version() == 4
                    && usize::from(ip_packet.header_len()) >= IPV4_HEADER_LEN
                    && matches!(transport[0], 3 | 11 | 12),
            )
        };
        let is_error = valid_error && packet_end >= end;
        let is_local_error = is_error
            && matches!(self.direction, Direction::Outbound)
            && key.local_address == key.remote_address;
        let error = if is_error && (matches!(self.direction, Direction::Inbound) || is_local_error)
        {
            self.read_icmp_error(key, end, packet_end)
        } else {
            None
        };
        Some(IcmpMetadata {
            echo,
            error,
            is_local_error,
        })
    }

    fn read_icmp_error(
        &mut self,
        key: &Key,
        quote_offset: usize,
        packet_end: usize,
    ) -> Option<IcmpError> {
        let outer_end = core::cmp::min(self.reader.len(), packet_end);
        let mut quote = PacketWindow {
            reader: &mut self.reader,
            start: quote_offset,
            end: outer_end,
        };
        let base_length = if unlikely(self.ipv6) {
            IPV6_HEADER_LEN
        } else {
            IPV4_HEADER_LEN
        };
        let quoted = quote.prefix(base_length)?;
        let (protocol, offset) = if unlikely(self.ipv6) {
            let ip_packet = Ipv6Packet::new_unchecked(quoted);
            if ip_packet.version() != 6
                || IpAddress::Ipv6(ip_packet.src_addr()) != key.local_address
            {
                return None;
            }
            let total_len = ip_packet.total_len();
            quote.end = core::cmp::min(quote.end, quote_offset.checked_add(total_len)?);
            let headers = walk_ipv6_headers_reader(&mut quote, false, false);
            if !headers.resolved || headers.is_fragment {
                return None;
            }
            (headers.protocol, headers.transport_offset)
        } else {
            let ip_packet = Ipv4Packet::new_unchecked(quoted);
            let offset = usize::from(ip_packet.header_len());
            if ip_packet.version() != 4
                || offset < IPV4_HEADER_LEN
                || IpAddress::Ipv4(ip_packet.src_addr()) != key.local_address
                || ip_packet.frag_offset() != 0
            {
                return None;
            }
            let protocol = ip_packet.next_header();
            let total_len = usize::from(ip_packet.total_len());
            quote.end = core::cmp::min(quote.end, quote_offset.checked_add(total_len)?);
            (protocol, offset)
        };
        let transport_length = match protocol {
            IpProtocol::Tcp | IpProtocol::Udp => 4,
            IpProtocol::Icmp if !self.ipv6 => ICMP_HEADER_LEN,
            IpProtocol::Icmpv6 if self.ipv6 => ICMP_HEADER_LEN,
            _ => return None,
        };
        let quoted = quote.prefix(offset.checked_add(transport_length)?)?;
        get_icmp_error(
            protocol,
            key.local_address,
            if unlikely(self.ipv6) {
                IpAddress::Ipv6(Ipv6Packet::new_unchecked(quoted).dst_addr())
            } else {
                IpAddress::Ipv4(Ipv4Packet::new_unchecked(quoted).dst_addr())
            },
            &quoted[offset..],
        )
    }
}

struct PacketWindow<'reader, R> {
    reader: &'reader mut R,
    start: usize,
    end: usize,
}

impl<R: PacketData> PacketData for PacketWindow<'_, R> {
    fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    fn prefix(&mut self, length: usize) -> Option<&[u8]> {
        let end = self.start.checked_add(length)?;
        if end > self.end {
            return None;
        }
        self.reader.prefix(end)?.get(self.start..end)
    }
}

#[cfg(test)]
#[path = "../tests/fixtures/packet_metadata_original.rs"]
mod original;

#[cfg(test)]
struct PacketMetadata {
    key: Key,
    icmp_echo: Option<IcmpEcho>,
    icmp_error: Option<IcmpError>,
    is_local_icmp_error: bool,
    is_tcp_reset: bool,
}

#[cfg(test)]
struct PacketInspection {
    is_fragment: bool,
    metadata: Result<PacketMetadata, PacketMetadataError>,
}

#[cfg(test)]
fn inspect_packet(
    packet: &[u8],
    ipv6: bool,
    direction: Direction,
    permit_fragments: bool,
) -> PacketInspection {
    let mut inspector = PacketInspector::new(packet, ipv6, direction, permit_fragments);
    let key = inspector.key();
    let is_fragment = inspector.is_fragment();
    let metadata = key.map(|key| {
        let icmp = inspector.icmp_metadata(&key);
        PacketMetadata {
            key,
            icmp_echo: icmp.echo,
            icmp_error: icmp.error,
            is_local_icmp_error: icmp.is_local_error,
            is_tcp_reset: inspector.is_tcp_reset(),
        }
    });
    PacketInspection {
        is_fragment,
        metadata,
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
    if unlikely(!matches!(protocol, IpProtocol::Tcp | IpProtocol::Udp) || transport.len() < 4) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{
        ICMPV4_CODE_DU_PORT_UNREACHABLE, ICMPV4_TYPE_DESTINATION_UNREACHABLE,
        ICMPV6_CODE_DU_PORT_UNREACHABLE, ICMPV6_TYPE_DESTINATION_UNREACHABLE,
    };
    use smoltcp::wire::{Ipv4Address, Ipv6Address};

    fn inspect_packet(packet: &[u8], ipv6: bool, direction: Direction) -> PacketInspection {
        super::inspect_packet(packet, ipv6, direction, false)
    }

    struct CountingReader<'packet> {
        packet: &'packet [u8],
        cached_length: usize,
        readable_length: usize,
        failures: usize,
        reads: Vec<usize>,
        requests: Vec<usize>,
    }

    impl<'packet> CountingReader<'packet> {
        fn new(packet: &'packet [u8]) -> Self {
            Self {
                packet,
                cached_length: 0,
                readable_length: MAX_PACKET_INSPECT_LEN,
                failures: 0,
                reads: Vec::new(),
                requests: Vec::new(),
            }
        }
    }

    impl PacketData for CountingReader<'_> {
        fn len(&self) -> usize {
            core::cmp::min(self.packet.len(), MAX_PACKET_INSPECT_LEN)
        }

        fn prefix(&mut self, length: usize) -> Option<&[u8]> {
            self.requests.push(length);
            if length > self.len() {
                return None;
            }
            if length > self.cached_length {
                self.reads.push(length);
                if self.failures != 0 {
                    self.failures -= 1;
                    return None;
                }
                if length > self.readable_length {
                    return None;
                }
                self.cached_length = length;
            }
            self.packet.get(..length)
        }
    }

    fn basic_packet(ipv6: bool, protocol: IpProtocol) -> [u8; 160] {
        let mut packet = [0u8; 160];
        let offset = if ipv6 {
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&120u16.to_be_bytes());
            packet[6] = u8::from(protocol);
            packet[8..24].copy_from_slice(&Ipv6Address::LOOPBACK.0);
            packet[24..40].copy_from_slice(&Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).0);
            IPV6_HEADER_LEN
        } else {
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&160u16.to_be_bytes());
            packet[9] = u8::from(protocol);
            set_ipv4_endpoints(&mut packet);
            IPV4_HEADER_LEN
        };
        packet[offset..offset + 2].copy_from_slice(&50_000u16.to_be_bytes());
        packet[offset + 2..offset + 4].copy_from_slice(&443u16.to_be_bytes());
        packet[offset + TCP_FLAGS_OFFSET] = TCP_RST_FLAG;
        packet
    }

    // Measures parser/reader bookkeeping in user mode, not NDIS or total driver
    // CPU. Ignored so timing noise never affects the regular correctness suite.
    #[test]
    #[ignore]
    fn packet_inspector_microbenchmark() {
        use core::{hint::black_box, mem::MaybeUninit};
        use std::time::Instant;

        struct Reader<'packet, 'storage> {
            packet: &'packet [u8],
            native: bool,
            cached_length: usize,
            storage: &'storage mut MaybeUninit<[u8; MAX_PACKET_INSPECT_LEN]>,
        }

        impl Reader<'_, '_> {
            #[inline(never)]
            fn materialize(&mut self, length: usize) {
                let packet = black_box(self.packet);
                self.cached_length = if self.native {
                    core::cmp::min(packet.len(), MAX_PACKET_INSPECT_LEN)
                } else {
                    // SAFETY: The caller has checked both bounds. Only this
                    // initialized prefix is returned by `prefix` below.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            packet.as_ptr(),
                            self.storage.as_mut_ptr().cast::<u8>(),
                            length,
                        );
                    }
                    length
                };
            }
        }

        impl PacketData for Reader<'_, '_> {
            fn len(&self) -> usize {
                core::cmp::min(self.packet.len(), MAX_PACKET_INSPECT_LEN)
            }

            fn prefix(&mut self, length: usize) -> Option<&[u8]> {
                if length > self.len() {
                    return None;
                }
                if length > self.cached_length {
                    self.materialize(length);
                }
                if self.native {
                    self.packet.get(..length)
                } else {
                    // SAFETY: A complete materialization covers `length` bytes.
                    Some(unsafe {
                        core::slice::from_raw_parts(self.storage.as_ptr().cast::<u8>(), length)
                    })
                }
            }

            fn byte(&mut self, offset: usize) -> Option<u8> {
                if offset < self.cached_length {
                    let ptr = if self.native {
                        self.packet.as_ptr()
                    } else {
                        self.storage.as_ptr().cast::<u8>()
                    };
                    // SAFETY: The cached range is initialized and still live.
                    return Some(unsafe { *ptr.add(offset) });
                }
                self.prefix(offset.checked_add(1)?)?.get(offset).copied()
            }
        }

        #[inline(never)]
        fn inspect(packet: &[u8], ipv6: bool, direction: Direction, native: bool, eager: bool) {
            let mut storage = MaybeUninit::uninit();
            let mut reader = Reader {
                packet,
                native,
                cached_length: 0,
                storage: &mut storage,
            };
            if eager {
                let length = reader.len();
                let packet = reader.prefix(length).unwrap();
                let inspection = original::inspect_packet(packet, ipv6, direction, true);
                if inspection.is_fragment {
                    black_box(true);
                    return;
                }
                let metadata = inspection.metadata.unwrap();
                if metadata.key.protocol == IpProtocol::Tcp {
                    black_box(metadata.is_tcp_reset);
                }
                black_box(metadata.key);
            } else {
                let mut inspector = PacketInspector::new(&mut reader, ipv6, direction, true);
                let key = match inspector.key() {
                    Err(PacketMetadataError::FragmentRequiresReassembly) => {
                        black_box(true);
                        return;
                    }
                    result => result.unwrap(),
                };
                if key.protocol == IpProtocol::Tcp {
                    black_box(inspector.is_tcp_reset());
                }
                black_box(key);
            }
        }

        const ITERATIONS: usize = 2_000_000;
        for ipv6 in [false, true] {
            for protocol in [IpProtocol::Udp, IpProtocol::Tcp] {
                let mut packet = basic_packet(ipv6, protocol);
                let offset = if ipv6 {
                    IPV6_HEADER_LEN
                } else {
                    IPV4_HEADER_LEN
                };
                packet[offset + TCP_FLAGS_OFFSET] = 0x10;
                for native in [true, false] {
                    // Alternate the order within each pair so CPU frequency
                    // drift does not always favor the same implementation.
                    let mut samples = [[0u128; 7]; 2];
                    for sample in 0..7 {
                        for pass in 0..2 {
                            let mode = (sample + pass) % 2;
                            let start = Instant::now();
                            for i in 0..ITERATIONS {
                                inspect(
                                    black_box(&packet),
                                    black_box(ipv6),
                                    black_box(if i & 1 == 0 {
                                        Direction::Outbound
                                    } else {
                                        Direction::Inbound
                                    }),
                                    black_box(native),
                                    black_box(mode == 0),
                                );
                            }
                            samples[mode][sample] = start.elapsed().as_nanos();
                        }
                    }
                    for (mode, mut samples) in samples.into_iter().enumerate() {
                        samples.sort_unstable();
                        println!(
                            "IPv{} {} {} {}: median {:.2} ns/packet",
                            if ipv6 { 6 } else { 4 },
                            protocol,
                            if native { "native" } else { "scratch" },
                            if mode == 0 { "original" } else { "optimized" },
                            samples[3] as f64 / ITERATIONS as f64,
                        );
                    }
                }
            }
        }
    }

    fn assert_original_metadata(packet: &[u8], ipv6: bool) {
        for direction in [Direction::Outbound, Direction::Inbound] {
            for permit_fragments in [false, true] {
                let actual = super::inspect_packet(packet, ipv6, direction, permit_fragments);
                let expected = original::inspect_packet(packet, ipv6, direction, permit_fragments);
                assert_eq!(actual.is_fragment, expected.is_fragment);
                match (actual.metadata, expected.metadata) {
                    (Ok(actual), Ok(expected)) => {
                        assert!(
                            actual.key == expected.key,
                            "key mismatch for IPv{} prefix {}: {} != {}",
                            if ipv6 { 6 } else { 4 }, packet.len(), actual.key, expected.key,
                        );
                        assert_eq!(actual.is_tcp_reset, expected.is_tcp_reset);
                        assert_eq!(actual.is_local_icmp_error, expected.is_local_icmp_error);
                        let echo = |echo: IcmpEcho| (echo.is_request, echo.identifier, echo.sequence);
                        assert_eq!(
                            actual.icmp_echo.map(echo),
                            expected.icmp_echo.map(|echo| (echo.is_request, echo.identifier, echo.sequence)),
                        );
                        let expected_error = expected.icmp_error.map(|error| match error {
                            original::IcmpError::Transport(protocol, remote, local_port, remote_port) =>
                                IcmpError::Transport(protocol, remote, local_port, remote_port),
                            original::IcmpError::Echo(remote, identifier, sequence) =>
                                IcmpError::Echo(remote, identifier, sequence),
                        });
                        assert!(actual.icmp_error == expected_error, "ICMP quote mismatch: {packet:02x?}");
                    }
                    (Err(actual), Err(expected)) => {
                        let expected = match expected {
                            original::PacketMetadataError::UnreadablePacket => PacketMetadataError::UnreadablePacket,
                            original::PacketMetadataError::UnresolvedIpv6Headers => PacketMetadataError::UnresolvedIpv6Headers,
                            original::PacketMetadataError::FragmentRequiresReassembly => PacketMetadataError::FragmentRequiresReassembly,
                        };
                        assert_eq!(actual, expected);
                    }
                    (actual, expected) => panic!(
                        "metadata availability mismatch for IPv{} prefix {}: actual={}, original={}, bytes={packet:02x?}",
                        if ipv6 { 6 } else { 4 }, packet.len(), actual.is_ok(), expected.is_ok(),
                    ),
                }
            }
        }
    }

    #[test]
    fn every_base_protocol_and_truncation_matches_the_original_parser() {
        for ipv6 in [false, true] {
            for protocol in 0..=u8::MAX {
                let packet = basic_packet(ipv6, IpProtocol::from(protocol));
                for length in 0..=MAX_PACKET_INSPECT_LEN {
                    assert_original_metadata(&packet[..length], ipv6);
                }
            }
        }
    }

    #[test]
    fn ipv4_options_fragments_and_declared_lengths_match_the_original_parser() {
        for version in [0, 4, 6, 15] {
            for ihl in 0..=15 {
                for protocol in [
                    IpProtocol::Tcp,
                    IpProtocol::Udp,
                    IpProtocol::Icmp,
                    IpProtocol::Unknown(47),
                ] {
                    let mut packet = basic_packet(false, protocol);
                    packet[0] = (version << 4) | ihl;
                    for fragments in [0u16, 1, 0x2000, 0x3fff] {
                        packet[6..8].copy_from_slice(&fragments.to_be_bytes());
                        for declared in [0u16, 20, 24, 28, 64, 160, u16::MAX] {
                            packet[2..4].copy_from_slice(&declared.to_be_bytes());
                            for length in
                                [0, 19, 20, 23, 24, 27, 28, 33, 34, 63, 64, 73, 74, 127, 128]
                            {
                                assert_original_metadata(&packet[..length], false);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn ipv6_extension_chains_match_the_original_parser() {
        for extension in [
            IpProtocol::HopByHop,
            IpProtocol::Ipv6Opts,
            IpProtocol::Ipv6Route,
            IpProtocol::Ipv6Frag,
        ] {
            for count in 1..=9 {
                for protocol in [
                    IpProtocol::Tcp,
                    IpProtocol::Udp,
                    IpProtocol::Icmpv6,
                    IpProtocol::Unknown(47),
                ] {
                    for bits in [0u16, 1, 2, 8, 0x8000] {
                        let mut packet = basic_packet(true, extension);
                        for index in 0..count {
                            let offset = IPV6_HEADER_LEN + index * 8;
                            packet[offset..offset + 8].fill(0);
                            packet[offset] = u8::from(if index + 1 == count {
                                protocol
                            } else {
                                extension
                            });
                            packet[offset + 2..offset + 4].copy_from_slice(&bits.to_be_bytes());
                        }
                        let offset = IPV6_HEADER_LEN + count * 8;
                        packet[offset..offset + 2].copy_from_slice(&50_000u16.to_be_bytes());
                        packet[offset + 2..offset + 4].copy_from_slice(&443u16.to_be_bytes());
                        packet[offset + TCP_FLAGS_OFFSET] = TCP_RST_FLAG;
                        for length in [
                            39, 40, 41, 42, 43, 44, 47, 48, 51, 52, 55, 56, 63, 64, 127, 128,
                        ] {
                            assert_original_metadata(&packet[..length], true);
                        }
                    }
                }
            }
        }
        for extension in [
            IpProtocol::HopByHop,
            IpProtocol::Ipv6Opts,
            IpProtocol::Ipv6Route,
        ] {
            let mut packet = basic_packet(true, extension);
            packet[40] = u8::from(IpProtocol::Tcp);
            for declared in 0..=u8::MAX {
                packet[41] = declared;
                for length in 40..=MAX_PACKET_INSPECT_LEN {
                    assert_original_metadata(&packet[..length], true);
                }
            }
        }
    }

    #[test]
    fn icmp_quotes_and_truncation_match_the_original_parser() {
        let packet = captured_ipv4_network_unreachable();
        for length in 0..=packet.len().min(MAX_PACKET_INSPECT_LEN) {
            assert_original_metadata(&packet[..length], false);
        }
        for protocol in [IpProtocol::Tcp, IpProtocol::Udp, IpProtocol::Icmpv6] {
            let packet = ipv6_error_quote(protocol);
            for length in 0..=packet.len().min(MAX_PACKET_INSPECT_LEN) {
                assert_original_metadata(&packet[..length], true);
            }
        }
    }

    fn late_ports_packet(ipv6: bool, offset: usize, protocol: IpProtocol) -> [u8; 160] {
        let mut packet = basic_packet(ipv6, protocol);
        if ipv6 {
            packet[6] = u8::from(IpProtocol::Ipv6Opts);
            packet[40] = u8::from(protocol);
            packet[41] = ((offset - IPV6_HEADER_LEN) / 8 - 1) as u8;
            packet[42..offset].fill(0);
        } else {
            packet[0] = 0x40 | (offset / 4) as u8;
        }
        packet[offset..offset + 2].copy_from_slice(&50_000u16.to_be_bytes());
        packet[offset + 2..offset + 4].copy_from_slice(&443u16.to_be_bytes());
        packet[offset + TCP_FLAGS_OFFSET] = TCP_RST_FLAG;
        packet
    }

    #[test]
    fn unreadable_existing_ports_are_errors_not_zero_port_keys() {
        for (ipv6, offset) in [(false, 24), (false, 60), (true, 48), (true, 56)] {
            for protocol in [IpProtocol::Tcp, IpProtocol::Udp] {
                let packet = late_ports_packet(ipv6, offset, protocol);
                for direction in [Direction::Inbound, Direction::Outbound] {
                    for permit_fragments in [false, true] {
                        let mut reader = CountingReader::new(&packet);
                        reader.readable_length = if ipv6 { 44 } else { 24 };
                        let mut inspector =
                            PacketInspector::new(reader, ipv6, direction, permit_fragments);
                        assert!(matches!(
                            inspector.key(),
                            Err(PacketMetadataError::UnreadablePacket)
                        ));
                        assert!(matches!(
                            inspector.retry_key(),
                            Err(PacketMetadataError::UnreadablePacket)
                        ));
                    }
                }
                // Actual truncation still has the original zero-port semantics.
                for length in offset..offset + 4 {
                    assert_original_metadata(&packet[..length], ipv6);
                }
            }
        }
    }

    #[test]
    fn first_probe_retry_recovers_the_real_late_transport_key() {
        struct FailingPorts<'packet> {
            reader: CountingReader<'packet>,
            end: usize,
            fail: bool,
        }
        impl PacketData for FailingPorts<'_> {
            fn len(&self) -> usize {
                self.reader.len()
            }
            fn prefix(&mut self, length: usize) -> Option<&[u8]> {
                if length == self.end && self.fail {
                    self.fail = false;
                    return None;
                }
                self.reader.prefix(length)
            }
        }
        for (ipv6, offset) in [(false, 24), (false, 60), (true, 48), (true, 56)] {
            for protocol in [IpProtocol::Tcp, IpProtocol::Udp] {
                let packet = late_ports_packet(ipv6, offset, protocol);
                for direction in [Direction::Inbound, Direction::Outbound] {
                    let reader = FailingPorts {
                        reader: CountingReader::new(&packet),
                        end: offset + 4,
                        fail: true,
                    };
                    let mut inspector = PacketInspector::new(reader, ipv6, direction, true);
                    assert!(matches!(
                        inspector.key(),
                        Err(PacketMetadataError::UnreadablePacket)
                    ));
                    let expected = original::inspect_packet(&packet[..128], ipv6, direction, false)
                        .metadata
                        .unwrap()
                        .key;
                    assert!(inspector.retry_key().unwrap() == expected);
                }
            }
        }
    }

    #[test]
    fn borrowed_inspector_contains_no_key_or_packet_buffer() {
        assert!(core::mem::size_of::<PacketInspector<&mut &[u8]>>() <= 24);
    }

    #[test]
    fn tcp_reset_uses_the_borrowed_readers_byte_accessor_once() {
        struct ByteReader<'packet> {
            reader: CountingReader<'packet>,
            offset: usize,
            flags: Option<u8>,
            byte_reads: usize,
        }
        impl PacketData for ByteReader<'_> {
            fn len(&self) -> usize {
                self.reader.len()
            }
            fn prefix(&mut self, length: usize) -> Option<&[u8]> {
                self.reader.prefix(length)
            }
            fn byte(&mut self, offset: usize) -> Option<u8> {
                assert_eq!(offset, self.offset);
                self.byte_reads += 1;
                self.flags
            }
        }
        for ipv6 in [false, true] {
            for flags in [Some(TCP_RST_FLAG), Some(0x10), None] {
                let packet = basic_packet(ipv6, IpProtocol::Tcp);
                let length = if ipv6 { 44 } else { 24 };
                let mut reader = ByteReader {
                    reader: CountingReader::new(&packet),
                    offset: if ipv6 { 53 } else { 33 },
                    flags,
                    byte_reads: 0,
                };
                let mut inspector =
                    PacketInspector::new(&mut reader, ipv6, Direction::Outbound, true);
                let key = inspector.key().unwrap();
                assert_eq!(key.protocol, IpProtocol::Tcp);
                let reset = flags.is_some_and(|flags| flags & TCP_RST_FLAG != 0);
                assert_eq!(inspector.is_tcp_reset(), reset);
                assert_eq!(inspector.is_tcp_reset(), reset);
                drop(inspector);
                assert_eq!(reader.byte_reads, 1);
                assert_eq!(reader.reader.requests, [length]);
                assert_eq!(reader.reader.reads, [length]);
            }
        }
    }

    #[test]
    fn ordinary_key_uses_its_initial_prefix_without_a_second_lookup() {
        for ipv6 in [false, true] {
            for protocol in [IpProtocol::Tcp, IpProtocol::Udp, IpProtocol::Unknown(47)] {
                let packet = basic_packet(ipv6, protocol);
                let mut reader = CountingReader::new(&packet);
                let mut inspector =
                    PacketInspector::new(&mut reader, ipv6, Direction::Outbound, true);
                let key = inspector.key().unwrap();
                assert_eq!(key.protocol, protocol);
                let length = if ipv6 { 44 } else { 24 };
                assert_eq!(inspector.reader.requests, [length]);
                assert_eq!(inspector.reader.reads, [length]);
            }
        }
    }

    #[test]
    fn basic_keys_share_one_small_read_and_transport_flags_are_lazy() {
        for ipv6 in [false, true] {
            for protocol in [IpProtocol::Tcp, IpProtocol::Udp] {
                let packet = basic_packet(ipv6, protocol);
                let prefix_length = if ipv6 { 44 } else { 24 };
                for direction in [Direction::Outbound, Direction::Inbound] {
                    let reader = CountingReader::new(&packet);
                    let mut inspector = PacketInspector::new(reader, ipv6, direction, true);
                    assert!(inspector.reader.reads.is_empty());
                    assert!(!inspector.is_fragment());
                    let key = inspector.key().unwrap();
                    assert_eq!(key.protocol, protocol);
                    assert_eq!(
                        key.local_port,
                        if matches!(direction, Direction::Outbound) {
                            50_000
                        } else {
                            443
                        }
                    );
                    assert!(inspector.key().unwrap() == key);
                    assert!(inspector.icmp_metadata(&key).echo.is_none());
                    assert_eq!(inspector.reader.reads, [prefix_length]);
                    let reset = protocol == IpProtocol::Tcp;
                    assert_eq!(inspector.is_tcp_reset(), reset);
                    assert_eq!(inspector.is_tcp_reset(), reset);
                    assert!(inspector.key().unwrap() == key);
                    let expected = if reset {
                        vec![prefix_length, prefix_length + 10]
                    } else {
                        vec![prefix_length]
                    };
                    assert_eq!(inspector.reader.reads, expected);
                }
            }
        }
    }

    #[test]
    fn header_cache_stays_register_sized() {
        assert!(core::mem::size_of::<HeaderInspection>() <= core::mem::size_of::<u64>());
    }

    #[test]
    fn a_single_key_request_bypasses_individual_fragments_before_ports() {
        for ipv6 in [false, true] {
            let mut packet = basic_packet(ipv6, IpProtocol::Tcp);
            let expected_read = if ipv6 {
                packet[6] = u8::from(IpProtocol::Ipv6Frag);
                packet[40] = u8::from(IpProtocol::Tcp);
                packet[42] = 0;
                packet[43] = 1;
                44
            } else {
                packet[6] = 0x20;
                24
            };
            for direction in [Direction::Inbound, Direction::Outbound] {
                let mut inspector =
                    PacketInspector::new(CountingReader::new(&packet), ipv6, direction, true);
                assert_eq!(
                    inspector.key().err(),
                    Some(PacketMetadataError::FragmentRequiresReassembly)
                );
                assert!(!inspector.is_tcp_reset());
                assert_eq!(inspector.reader.reads, [expected_read]);
            }
        }
    }

    #[test]
    fn fragment_probes_do_not_read_transport_or_unresolved_tails() {
        let mut ipv4 = basic_packet(false, IpProtocol::Tcp);
        ipv4[6] = 0x20;
        let mut inspector =
            PacketInspector::new(CountingReader::new(&ipv4), false, Direction::Outbound, true);
        assert!(inspector.is_fragment());
        assert!(matches!(
            inspector.key(),
            Err(PacketMetadataError::FragmentRequiresReassembly)
        ));
        assert!(!inspector.is_tcp_reset());
        assert_eq!(inspector.reader.reads, [24]);

        let mut ipv6 = basic_packet(true, IpProtocol::Ipv6Opts);
        ipv6[40] = u8::from(IpProtocol::Ipv6Frag);
        ipv6[41] = 0;
        ipv6[48] = u8::from(IpProtocol::Ipv6Opts);
        ipv6[51] = 1;
        ipv6[57] = 255; // the chain after this fragment cannot resolve
        let mut inspector =
            PacketInspector::new(CountingReader::new(&ipv6), true, Direction::Inbound, true);
        assert!(inspector.is_fragment());
        assert!(matches!(
            inspector.key(),
            Err(PacketMetadataError::FragmentRequiresReassembly)
        ));
        assert!(!inspector.is_tcp_reset());
        assert_eq!(inspector.reader.reads, [44, 52]);
    }

    #[test]
    fn ipv6_options_are_validated_without_reading_their_bodies() {
        let mut packet = basic_packet(true, IpProtocol::Ipv6Route);
        packet[40] = 47; // a non-TCP/UDP protocol after a 48-byte Routing header
        packet[41] = 5;
        packet[43] = 1;
        let mut inspector = PacketInspector::new(
            CountingReader::new(&packet),
            true,
            Direction::Outbound,
            true,
        );
        assert!(!inspector.is_fragment());
        let key = inspector.key().unwrap();
        assert_eq!(key.protocol, IpProtocol::Unknown(47));
        assert!(inspector.icmp_metadata(&key).echo.is_none());
        assert!(!inspector.is_tcp_reset());
        assert_eq!(inspector.reader.reads, [44]);

        let mut inspector = PacketInspector::new(
            CountingReader::new(&packet[..87]),
            true,
            Direction::Outbound,
            true,
        );
        assert!(!inspector.is_fragment());
        assert!(matches!(
            inspector.key(),
            Err(PacketMetadataError::UnresolvedIpv6Headers)
        ));
        assert_eq!(inspector.reader.reads, [44]);
    }

    #[test]
    fn icmp_quotes_are_read_only_for_attribution_and_stop_at_identity() {
        let packet = captured_ipv4_network_unreachable();
        for direction in [Direction::Inbound, Direction::Outbound] {
            let mut inspector =
                PacketInspector::new(CountingReader::new(&packet), false, direction, true);
            let key = inspector.key().unwrap();
            assert_eq!(key.protocol, IpProtocol::Icmp);
            assert_eq!(inspector.reader.reads, [24]);
            assert!(!inspector.is_tcp_reset());
            let icmp = inspector.icmp_metadata(&key);
            if matches!(direction, Direction::Inbound) {
                assert!(matches!(
                    icmp.error,
                    Some(IcmpError::Transport(IpProtocol::Tcp, _, 34_912, 1234))
                ));
                assert_eq!(inspector.reader.reads, [24, 28, 48, 52]);
            } else {
                assert!(icmp.error.is_none());
                assert_eq!(inspector.reader.reads, [24, 28]);
            }
            let reads = inspector.reader.reads.clone();
            assert!(inspector.icmp_metadata(&key).error == icmp.error);
            assert_eq!(inspector.reader.reads, reads);
        }

        let packet = ipv6_error_quote(IpProtocol::Udp);
        let mut inspector = PacketInspector::new(
            CountingReader::new(&packet),
            true,
            Direction::Inbound,
            false,
        );
        let key = inspector.key().unwrap();
        assert_eq!(key.protocol, IpProtocol::Icmpv6);
        assert_eq!(inspector.reader.reads, [44]);
        assert!(matches!(
            inspector.icmp_metadata(&key).error,
            Some(IcmpError::Transport(IpProtocol::Udp, _, 50_000, 443))
        ));
        assert_eq!(inspector.reader.reads, [44, 48, 88, 92]);
    }

    #[test]
    fn failed_optional_fields_are_cached_without_losing_the_key() {
        let packet = basic_packet(false, IpProtocol::Tcp);
        let mut reader = CountingReader::new(&packet);
        reader.readable_length = 24;
        let mut inspector = PacketInspector::new(reader, false, Direction::Outbound, true);
        let key = inspector.key().unwrap();
        assert!(!inspector.is_tcp_reset());
        assert!(!inspector.is_tcp_reset());
        assert!(inspector.key().unwrap() == key);
        assert_eq!(inspector.reader.reads, [24, 34]);
    }

    #[test]
    fn failed_optional_materialization_keeps_the_callers_key_valid() {
        struct Reader<'packet> {
            packet: &'packet [u8],
            storage: [u8; MAX_PACKET_INSPECT_LEN],
            cached_length: usize,
            reads: Vec<usize>,
        }
        impl PacketData for Reader<'_> {
            fn len(&self) -> usize {
                self.packet.len().min(MAX_PACKET_INSPECT_LEN)
            }
            fn prefix(&mut self, length: usize) -> Option<&[u8]> {
                if length > self.len() {
                    return None;
                }
                if length > self.cached_length {
                    self.reads.push(length);
                    if length > 24 {
                        // A failed NDIS expansion may overwrite earlier scratch
                        // bytes. The callout's already-owned key must survive.
                        self.storage[..24].fill(0);
                        self.cached_length = 0;
                        return None;
                    }
                    self.storage[..length].copy_from_slice(&self.packet[..length]);
                    self.cached_length = length;
                }
                Some(&self.storage[..length])
            }
        }
        let packet = basic_packet(false, IpProtocol::Tcp);
        let expected = original::inspect_packet(&packet[..128], false, Direction::Outbound, true)
            .metadata
            .unwrap()
            .key;
        let mut reader = Reader {
            packet: &packet,
            storage: [0; MAX_PACKET_INSPECT_LEN],
            cached_length: 0,
            reads: Vec::new(),
        };
        let mut inspector = PacketInspector::new(&mut reader, false, Direction::Outbound, true);
        let key = inspector.key().unwrap();
        assert!(!inspector.is_tcp_reset());
        assert!(!inspector.is_tcp_reset());
        assert!(key == expected);
        drop(inspector);
        assert_eq!(reader.reads, [24, 34]);
        assert_eq!(&reader.storage[..24], &[0; 24]);
    }

    #[test]
    fn failed_first_probe_is_retried_only_when_requested() {
        let packet = basic_packet(false, IpProtocol::Udp);
        let mut reader = CountingReader::new(&packet);
        reader.failures = 2;
        let mut inspector = PacketInspector::new(reader, false, Direction::Outbound, true);
        assert!(!inspector.is_fragment());
        assert!(matches!(
            inspector.key(),
            Err(PacketMetadataError::UnreadablePacket)
        ));
        assert!(matches!(
            inspector.key(),
            Err(PacketMetadataError::UnreadablePacket)
        ));
        assert_eq!(inspector.reader.reads, [24, 20]);
        assert_eq!(inspector.retry_key().unwrap().local_port, 50_000);
        assert_eq!(inspector.reader.reads, [24, 20, 24]);
    }

    #[test]
    fn ipv4_options_extend_the_prefix_only_to_requested_fields() {
        let mut packet = basic_packet(false, IpProtocol::Tcp);
        packet[0] = 0x4f;
        packet[60..62].copy_from_slice(&50_001u16.to_be_bytes());
        packet[62..64].copy_from_slice(&443u16.to_be_bytes());
        packet[73] = TCP_RST_FLAG;
        let mut inspector = PacketInspector::new(
            CountingReader::new(&packet),
            false,
            Direction::Outbound,
            true,
        );
        assert!(!inspector.is_fragment());
        assert_eq!(inspector.reader.reads, [24]);
        assert_eq!(inspector.key().unwrap().local_port, 50_001);
        assert_eq!(inspector.reader.reads, [24, 64]);
        assert!(inspector.is_tcp_reset());
        assert_eq!(inspector.reader.reads, [24, 64, 74]);
    }

    #[test]
    fn fragment_bypass_skips_metadata_only_for_individual_fragments() {
        for ipv6 in [false, true] {
            let mut packet = [0u8; IPV6_HEADER_LEN + 8 + 20];
            let transport_offset = if ipv6 {
                packet[0] = 0x60;
                packet[4..6].copy_from_slice(&28u16.to_be_bytes());
                packet[6] = u8::from(IpProtocol::Ipv6Frag);
                packet[40] = u8::from(IpProtocol::Tcp);
                IPV6_HEADER_LEN + 8
            } else {
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&40u16.to_be_bytes());
                packet[9] = u8::from(IpProtocol::Tcp);
                IPV4_HEADER_LEN
            };
            packet[transport_offset..transport_offset + 2]
                .copy_from_slice(&50_000u16.to_be_bytes());
            packet[transport_offset + 2..transport_offset + 4]
                .copy_from_slice(&443u16.to_be_bytes());
            packet[transport_offset + TCP_FLAGS_OFFSET] = TCP_RST_FLAG;

            for fragmented in [false, true] {
                if ipv6 {
                    packet[43] = u8::from(fragmented);
                } else {
                    packet[6] = if fragmented { 0x20 } else { 0 };
                }
                for direction in [Direction::Outbound, Direction::Inbound] {
                    let inspected = super::inspect_packet(&packet, ipv6, direction, true);
                    assert_eq!(inspected.is_fragment, fragmented);
                    let full = inspect_packet(&packet, ipv6, direction).metadata.unwrap();
                    assert!(full.is_tcp_reset);
                    assert_eq!(
                        full.key.local_port,
                        if matches!(direction, Direction::Outbound) {
                            50_000
                        } else {
                            443
                        }
                    );
                    if fragmented {
                        assert!(matches!(
                            inspected.metadata,
                            Err(PacketMetadataError::FragmentRequiresReassembly)
                        ));
                    } else {
                        let metadata = inspected.metadata.unwrap();
                        assert!(metadata.key == full.key);
                        assert_eq!(metadata.is_tcp_reset, full.is_tcp_reset);
                    }
                }
            }
        }
    }

    #[test]
    fn ipv6_fragment_bypass_preserves_full_and_atomic_header_parsing() {
        // Options -> Fragment -> Options -> TCP.
        let mut packet = [0u8; IPV6_HEADER_LEN + 3 * 8 + 20];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&44u16.to_be_bytes());
        packet[6] = u8::from(IpProtocol::Ipv6Opts);
        packet[40] = u8::from(IpProtocol::Ipv6Frag);
        packet[48] = u8::from(IpProtocol::Ipv6Opts);
        packet[56] = u8::from(IpProtocol::Tcp);
        packet[64..66].copy_from_slice(&50_000u16.to_be_bytes());
        packet[66..68].copy_from_slice(&443u16.to_be_bytes());
        packet[64 + TCP_FLAGS_OFFSET] = TCP_RST_FLAG;

        for bits in [0u16, 1, 8, 9] {
            packet[50..52].copy_from_slice(&bits.to_be_bytes());
            for direction in [Direction::Outbound, Direction::Inbound] {
                let full = inspect_packet(&packet, true, direction).metadata.unwrap();
                assert_eq!(full.key.protocol, IpProtocol::Tcp);
                assert_eq!(
                    full.key.local_port,
                    if matches!(direction, Direction::Outbound) {
                        50_000
                    } else {
                        443
                    }
                );
                assert!(full.is_tcp_reset);
                let lazy = super::inspect_packet(&packet, true, direction, true);
                assert_eq!(lazy.is_fragment, bits != 0);
                if bits != 0 {
                    assert!(matches!(
                        lazy.metadata,
                        Err(PacketMetadataError::FragmentRequiresReassembly)
                    ));
                } else {
                    let metadata = lazy.metadata.unwrap();
                    assert!(metadata.key == full.key);
                    assert_eq!(metadata.is_tcp_reset, full.is_tcp_reset);
                }

                let truncated = &packet[..56];
                assert!(matches!(
                    inspect_packet(truncated, true, direction).metadata,
                    Err(PacketMetadataError::UnresolvedIpv6Headers)
                ));
                let lazy = super::inspect_packet(truncated, true, direction, true);
                assert!(matches!(
                    (bits, lazy.metadata),
                    (0, Err(PacketMetadataError::UnresolvedIpv6Headers))
                        | (
                            1 | 8 | 9,
                            Err(PacketMetadataError::FragmentRequiresReassembly)
                        )
                ));
            }
        }
    }

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
