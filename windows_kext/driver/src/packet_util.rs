use alloc::string::{String, ToString};
use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet, TcpPacket, UdpPacket,
    IPV4_HEADER_LEN, IPV6_HEADER_LEN,
};
use wdk::filter_engine::net_buffer::NetBufferList;

use crate::connection_map::Key;
use crate::device::Packet;
use crate::ipv6_packet::{
    recalculate_ipv6_transport_checksum, rewrite_ipv6_tcp_udp, walk_ipv6_headers, PortRewrite,
};
use crate::{
    connection::{Direction, RedirectInfo},
    dbg, err,
};

/// `Redirect` is a trait that defines a method for redirecting network packets.
///
/// This trait is used to implement different strategies for redirecting packets,
/// depending on the specific requirements of the application.
pub trait Redirect {
    /// Redirects a network packet based on the provided `RedirectInfo`.
    ///
    /// # Arguments
    ///
    /// * `redirect_info` - A struct containing information about how to redirect the packet.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the packet was successfully redirected.
    /// * `Err(String)` if there was an error redirecting the packet.
    fn redirect(&mut self, redirect_info: RedirectInfo) -> Result<(), String>;
}

impl Redirect for Packet {
    fn redirect(&mut self, redirect_info: RedirectInfo) -> Result<(), String> {
        if let Packet::PacketLayer(nbls, inject_info) = self {
            for nbl in nbls {
                let Some(data) = nbl.get_data_mut() else {
                    return Err("trying to redirect immutable NBL".to_string());
                };

                if inject_info.inbound {
                    redirect_inbound_packet(
                        data,
                        redirect_info.local_address,
                        redirect_info.remote_address,
                        redirect_info.remote_port,
                    )?;
                } else {
                    redirect_outbound_packet(
                        data,
                        redirect_info.redirect_address,
                        redirect_info.redirect_port,
                        redirect_info.unify,
                    )?;
                }
            }
            return Ok(());
        }
        // return Err("can't redirect from non packet layer".to_string());
        return Ok(());
    }
}

/// Redirects an outbound packet to a specified remote address and port.
///
/// # Arguments
///
/// * `packet` - A mutable reference to the packet data.
/// * `remote_address` - The IP address to redirect the packet to.
/// * `remote_port` - The port to redirect the packet to.
/// * `unify` - If true, the source and destination addresses of the packet will be set to the same value.
///
/// This function modifies the packet in-place to change its destination address and port.
/// It also updates the checksums for the IP and transport layer headers.
/// If the `unify` parameter is true, it sets the source and destination addresses to be the same.
/// If the remote address is a loopback address, it sets the source address to the loopback address.
fn redirect_outbound_packet(
    packet: &mut [u8],
    remote_address: IpAddress,
    remote_port: u16,
    unify: bool,
) -> Result<(), String> {
    match remote_address {
        IpAddress::Ipv4(remote_address) => {
            if let Ok(mut ip_packet) = Ipv4Packet::new_checked(packet) {
                if unify {
                    ip_packet.set_dst_addr(ip_packet.src_addr());
                } else {
                    ip_packet.set_dst_addr(remote_address);
                    if remote_address.is_loopback() {
                        ip_packet.set_src_addr(Ipv4Address::new(127, 0, 0, 1));
                    }
                }
                ip_packet.fill_checksum();
                let src_addr = ip_packet.src_addr();
                let dst_addr = ip_packet.dst_addr();
                if ip_packet.next_header() == IpProtocol::Udp {
                    if let Ok(mut udp_packet) = UdpPacket::new_checked(ip_packet.payload_mut()) {
                        udp_packet.set_dst_port(remote_port);
                        udp_packet
                            .fill_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr));
                    }
                }
                if ip_packet.next_header() == IpProtocol::Tcp {
                    if let Ok(mut tcp_packet) = TcpPacket::new_checked(ip_packet.payload_mut()) {
                        tcp_packet.set_dst_port(remote_port);
                        tcp_packet
                            .fill_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr));
                    }
                }
            }
            Ok(())
        }
        IpAddress::Ipv6(remote_address) => {
            // The base Next Header can name an extension header, so resolve the
            // upper-layer offset before changing either addresses or ports.
            let ip_packet = Ipv6Packet::new_checked(&*packet)
                .map_err(|_| "invalid outbound IPv6 packet".to_string())?;
            let original_source = ip_packet.src_addr();
            let destination = if unify {
                original_source
            } else {
                remote_address
            };
            let source = if !unify && remote_address.is_loopback() {
                Ipv6Address::LOOPBACK
            } else {
                original_source
            };

            rewrite_ipv6_tcp_udp(
                packet,
                source,
                destination,
                PortRewrite::Destination(remote_port),
            )
            .map_err(|error| error.to_string())
        }
    }
}

/// Redirects an inbound packet to a local address.
///
/// This function takes a mutable reference to a packet and modifies it in place.
/// It changes the destination address to the provided local address and the source address
/// to the original remote address. It also sets the source port to the original remote port.
/// The function handles both IPv4 and IPv6 addresses.
///
/// # Arguments
///
/// * `packet` - A mutable reference to the packet data.
/// * `local_address` - The local IP address to redirect the packet to.
/// * `original_remote_address` - The original remote IP address of the packet.
/// * `original_remote_port` - The original remote port of the packet.
///
fn redirect_inbound_packet(
    packet: &mut [u8],
    local_address: IpAddress,
    original_remote_address: IpAddress,
    original_remote_port: u16,
) -> Result<(), String> {
    match local_address {
        IpAddress::Ipv4(local_address) => {
            let IpAddress::Ipv4(original_remote_address) = original_remote_address else {
                return Err("IPv4 redirect has an IPv6 remote address".to_string());
            };

            if let Ok(mut ip_packet) = Ipv4Packet::new_checked(packet) {
                ip_packet.set_dst_addr(local_address);
                ip_packet.set_src_addr(original_remote_address);
                ip_packet.fill_checksum();
                let src_addr = ip_packet.src_addr();
                let dst_addr = ip_packet.dst_addr();
                if ip_packet.next_header() == IpProtocol::Udp {
                    if let Ok(mut udp_packet) = UdpPacket::new_checked(ip_packet.payload_mut()) {
                        udp_packet.set_src_port(original_remote_port);
                        udp_packet
                            .fill_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr));
                    }
                }
                if ip_packet.next_header() == IpProtocol::Tcp {
                    if let Ok(mut tcp_packet) = TcpPacket::new_checked(ip_packet.payload_mut()) {
                        tcp_packet.set_src_port(original_remote_port);
                        tcp_packet
                            .fill_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr));
                    }
                }
            }
            Ok(())
        }
        IpAddress::Ipv6(local_address) => {
            let IpAddress::Ipv6(original_remote_address) = original_remote_address else {
                return Err("IPv6 redirect has an IPv4 remote address".to_string());
            };

            rewrite_ipv6_tcp_udp(
                packet,
                original_remote_address,
                local_address,
                PortRewrite::Source(original_remote_port),
            )
            .map_err(|error| error.to_string())
        }
    }
}

pub fn recalc_header_checksums(packet: &mut [u8], ipv6: bool) -> Result<(), String> {
    if ipv6 {
        // TCP/UDP start after the complete extension-header chain, and the
        // pseudo-header length is the upper-layer length rather than the IPv6
        // payload length (which includes extensions).
        recalculate_ipv6_transport_checksum(packet).map_err(|error| error.to_string())?;
    } else {
        if let Ok(mut ip_packet) = Ipv4Packet::new_checked(packet) {
            ip_packet.fill_checksum();
            let src_addr = ip_packet.src_addr();
            let dst_addr = ip_packet.dst_addr();
            if ip_packet.next_header() == IpProtocol::Udp {
                if let Ok(mut udp_packet) = UdpPacket::new_checked(ip_packet.payload_mut()) {
                    udp_packet
                        .fill_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr));
                }
            }
            if ip_packet.next_header() == IpProtocol::Tcp {
                if let Ok(mut tcp_packet) = TcpPacket::new_checked(ip_packet.payload_mut()) {
                    tcp_packet
                        .fill_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr));
                }
            }
        }
    }

    Ok(())
}

#[allow(dead_code)]
fn print_packet(packet: &[u8]) {
    if let Ok(ip_packet) = Ipv4Packet::new_checked(packet) {
        if ip_packet.next_header() == IpProtocol::Udp {
            if let Ok(udp_packet) = UdpPacket::new_checked(ip_packet.payload()) {
                dbg!("packet {} {}", ip_packet, udp_packet);
            }
        }
        if ip_packet.next_header() == IpProtocol::Tcp {
            if let Ok(tcp_packet) = TcpPacket::new_checked(ip_packet.payload()) {
                dbg!("packet {} {}", ip_packet, tcp_packet);
            }
        }
    } else {
        err!("failed to print packet: invalid ip header: {:?}", packet);
    }
}

/// This function extracts a key from a given IPv4 network buffer list (NBL).
/// The key contains the protocol, local and remote addresses and ports.
///
/// # Arguments
///
/// * `nbl` - A reference to the network buffer list from which the key will be extracted.
/// * `direction` - The direction of the packet (Inbound or Outbound).
///
/// # Returns
///
/// * `Ok(Key)` - A key containing the protocol, local and remote addresses and ports.
/// * `Err(String)` - An error message if the function fails to get net_buffer data.
/// ICMP echo type, code and identifier, read from the start of an ICMP header.
///
/// Returns `None` unless the message is an echo request or reply - the identifier
/// field only exists for those. Other ICMP types put different data at the same
/// offset, so reading it regardless would yield a number that means nothing.
///
/// `is_ipv6` selects the type numbering: echo request/reply are 8/0 in ICMPv4 and
/// 128/129 in ICMPv6.
///
/// Layout, identical for both versions: type (1), code (1), checksum (2),
/// identifier (2), sequence (2).
pub fn get_icmp_echo(packet: &[u8], is_ipv6: bool) -> Option<IcmpEcho> {
    // The identifier ends at byte 6. Anything shorter is not an echo header, and
    // indexing it would panic and trigger the driver's fatal diagnostic bug check.
    const ECHO_HEADER_LEN: usize = 6;
    if packet.len() < ECHO_HEADER_LEN {
        return None;
    }

    let message_type = packet[0];
    let is_request = if is_ipv6 {
        message_type == 128
    } else {
        message_type == 8
    };
    let is_reply = if is_ipv6 {
        message_type == 129
    } else {
        message_type == 0
    };

    if !is_request && !is_reply {
        return None;
    }

    Some(IcmpEcho {
        is_request,
        identifier: u16::from_be_bytes([packet[4], packet[5]]),
    })
}

/// An ICMP echo request or reply, reduced to what identifies its sender.
pub struct IcmpEcho {
    /// True for a request, false for a reply. Which one it is decides whether the
    /// process is recorded or looked up.
    pub is_request: bool,
    /// Chosen by the sender and echoed back unchanged.
    pub identifier: u16,
}

fn get_ports(packet: &[u8], protocol: smoltcp::wire::IpProtocol) -> (u16, u16) {
    // The port fields occupy the first four bytes of both the TCP and the UDP
    // header. smoltcp's src_port/dst_port index the buffer directly
    // (`data[0..2]`, `data[2..4]`) with no bounds check, so a shorter slice is an
    // out-of-bounds index and a fatal driver panic. Not all callers can guarantee
    // the length: the IPv6 path derives the offset from an attacker-controlled
    // extension header chain, so the check belongs here, at the single point every
    // path goes through.
    const PORTS_LEN: usize = 4;
    if packet.len() < PORTS_LEN {
        return (0, 0);
    }

    match protocol {
        smoltcp::wire::IpProtocol::Tcp => {
            let tcp_packet = TcpPacket::new_unchecked(packet);
            (tcp_packet.src_port(), tcp_packet.dst_port())
        }
        smoltcp::wire::IpProtocol::Udp => {
            let udp_packet = UdpPacket::new_unchecked(packet);
            (udp_packet.src_port(), udp_packet.dst_port())
        }
        _ => (0, 0), // No ports for other protocols
    }
}

/// Returns true if this IPv4 packet is part of a fragmented datagram, whether or
/// not it is the first fragment.
///
/// Both conditions matter. A non-zero fragment offset means the packet starts
/// mid-datagram and carries no transport header at all. The more-fragments bit
/// marks the *first* fragment, which does carry a transport header but describes
/// only its own slice of the datagram, not the whole one.
///
/// Returns false when the header cannot be read, so an unreadable buffer falls
/// through to the normal path rather than being silently permitted.
pub fn is_fragment_v4(nbl: &NetBufferList) -> bool {
    let mut header = [0; smoltcp::wire::IPV4_HEADER_LEN];
    if nbl.read_bytes(&mut header).is_err() {
        return false;
    }

    let packet = Ipv4Packet::new_unchecked(&header);
    packet.frag_offset() != 0 || packet.more_frags()
}

/// Largest possible IPv4 header: IHL is 4 bits counting 32-bit words, so the
/// maximum is 15 * 4 = 60 bytes (40 bytes of options beyond the fixed 20).
pub const IPV4_MAX_HEADER_LEN: usize = 60;

/// Reads as many leading bytes of a packet as it actually contains, up to
/// `buffer.len()`.
///
/// `NetBufferList::read_bytes` fails outright when asked for more bytes than the
/// net buffer holds, so the amount to read has to be known up front. The length
/// is taken from the net buffer itself and clamped to the buffer size, which
/// takes one read instead of probing sizes downwards.
///
/// Returns `None` if fewer than `min_len` bytes are available.
fn read_leading_bytes(nbl: &NetBufferList, buffer: &mut [u8], min_len: usize) -> Option<usize> {
    let available = nbl.get_data_length() as usize;
    if available < min_len {
        return None;
    }

    let size = core::cmp::min(available, buffer.len());
    if nbl.read_bytes(&mut buffer[..size]).is_ok() {
        return Some(size);
    }

    // The reported length and what the first net buffer can actually hand over
    // may differ: get_data_length sums every net buffer in the list, while
    // read_bytes only reads the first one. Fall back to the minimum, which is all
    // the callers strictly need.
    if nbl.read_bytes(&mut buffer[..min_len]).is_ok() {
        Some(min_len)
    } else {
        None
    }
}

/// Number of bytes read from an IPv6 packet to inspect the base header plus any
/// extension header chain and the start of the transport header.
///
/// Sized to cover the base header, a realistic extension header chain and the two
/// port fields. A chain longer than this is not decoded: `walk_ipv6_headers`
/// reports what it managed to parse rather than reading past the buffer.
pub const IPV6_INSPECT_LEN: usize = 128;

/// Returns true if this IPv6 packet is an individual fragment of a larger
/// datagram.
///
/// Returns false when the header cannot be read, so an unreadable buffer falls
/// through to the normal path rather than being silently permitted.
pub fn is_fragment_v6(nbl: &NetBufferList) -> bool {
    match read_ipv6_headers(nbl) {
        Some((buf, len)) => walk_ipv6_headers(&buf[..len]).is_fragment,
        None => false,
    }
}

/// Reads as much of an IPv6 header chain as the packet actually contains.
///
/// The amount read has to match what the packet holds: `read_bytes` fails when
/// asked for more. Reading a fixed smaller amount instead is not an option
/// either - it truncates the extension header chain, and the walk then stops
/// mid-chain and reports an extension header type as the transport protocol,
/// with ports 0. Observed with a DestOpt+Routing+UDP packet of 69 bytes, whose
/// transport header sits at offset 56: reading only 48 bytes produced
/// protocol 43 (Routing) instead of 17 (UDP).
///
/// So the length is taken from the net buffer and clamped to the inspection
/// window.
///
/// Returns `None` if the base header is not fully available.
fn read_ipv6_headers(nbl: &NetBufferList) -> Option<([u8; IPV6_INSPECT_LEN], usize)> {
    let mut buffer = [0u8; IPV6_INSPECT_LEN];

    let available = nbl.get_data_length() as usize;
    if available >= IPV6_HEADER_LEN {
        let size = core::cmp::min(available, IPV6_INSPECT_LEN);
        if nbl.read_bytes(&mut buffer[..size]).is_ok() {
            return Some((buffer, size));
        }
    }

    // get_data_length sums the whole net buffer list while read_bytes only reads
    // the first buffer, so the two can disagree. Fall back to the base header,
    // which is enough to build a key from addresses alone.
    if nbl.read_bytes(&mut buffer[..IPV6_HEADER_LEN]).is_ok() {
        return Some((buffer, IPV6_HEADER_LEN));
    }

    None
}

/// Offset of the TCP flags byte from the start of the TCP header.
const TCP_FLAGS_OFFSET: usize = 13;
const TCP_RST_FLAG: u8 = 0x04;

/// Returns true when an IP packet in this NBL carries a TCP reset.
///
/// Packet-layer indications start at the IP header after the caller has applied
/// any required inbound retreat. The transport offset cannot be assumed: IPv4
/// options and IPv6 extension headers both move the TCP header.
///
/// A short or malformed packet returns false. In particular, every indexed byte
/// is obtained through `get`, because a panic in this callout is a fatal driver
/// bug check.
pub fn is_tcp_reset_from_nbl(nbl: &NetBufferList, ipv6: bool) -> bool {
    if ipv6 {
        let Some((packet, len)) = read_ipv6_headers(nbl) else {
            return false;
        };
        let packet = &packet[..len];
        let headers = walk_ipv6_headers(packet);
        if !headers.resolved || headers.protocol != IpProtocol::Tcp {
            return false;
        }

        return packet
            .get(headers.transport_offset + TCP_FLAGS_OFFSET)
            .map(|flags| flags & TCP_RST_FLAG != 0)
            .unwrap_or(false);
    }

    // Read through the flags byte even when the IPv4 header has its maximum
    // 40 bytes of options.
    let mut packet = [0u8; IPV4_MAX_HEADER_LEN + TCP_FLAGS_OFFSET + 1];
    let Some(len) = read_leading_bytes(nbl, &mut packet, IPV4_HEADER_LEN + TCP_FLAGS_OFFSET + 1)
    else {
        return false;
    };
    let packet = &packet[..len];
    let ip_packet = Ipv4Packet::new_unchecked(packet);
    if ip_packet.next_header() != IpProtocol::Tcp {
        return false;
    }

    let transport_offset = ip_packet.header_len() as usize;
    if !(IPV4_HEADER_LEN..=IPV4_MAX_HEADER_LEN).contains(&transport_offset) {
        return false;
    }

    packet
        .get(transport_offset + TCP_FLAGS_OFFSET)
        .map(|flags| flags & TCP_RST_FLAG != 0)
        .unwrap_or(false)
}

pub fn get_key_from_nbl_v4(nbl: &NetBufferList, direction: Direction) -> Result<Key, String> {
    // Read enough for the largest possible IPv4 header plus the two port fields.
    // A fixed IPV4_HEADER_LEN + 4 read is only correct when IHL is 5: with IP
    // options present the transport header starts at IHL*4, so the ports would be
    // read from inside the options field instead.
    let mut headers = [0u8; IPV4_MAX_HEADER_LEN + 4];
    let len = match read_leading_bytes(nbl, &mut headers, IPV4_HEADER_LEN + 4) {
        Some(len) => len,
        None => return Err("failed to get net_buffer data".to_string()),
    };
    let headers = &headers[..len];

    // This will panic in debug mode, probably because of runtime checks.
    // Parse packet
    let ip_packet = Ipv4Packet::new_unchecked(headers);

    // header_len() is IHL*4, so it reflects any options actually present. Values
    // below the minimum mean a malformed header; fall back to the minimum rather
    // than trusting an offset that would point into the header itself.
    let mut transport_offset = ip_packet.header_len() as usize;
    if transport_offset < IPV4_HEADER_LEN {
        transport_offset = IPV4_HEADER_LEN;
    }

    let (src_port, dst_port) = match headers.get(transport_offset..) {
        Some(transport) => get_ports(transport, ip_packet.next_header()),
        None => (0, 0),
    };

    // Build key
    match direction {
        Direction::Outbound => Ok(Key {
            protocol: ip_packet.next_header(),
            local_address: IpAddress::Ipv4(ip_packet.src_addr()),
            local_port: src_port,
            remote_address: IpAddress::Ipv4(ip_packet.dst_addr()),
            remote_port: dst_port,
        }),
        Direction::Inbound => Ok(Key {
            protocol: ip_packet.next_header(),
            local_address: IpAddress::Ipv4(ip_packet.dst_addr()),
            local_port: dst_port,
            remote_address: IpAddress::Ipv4(ip_packet.src_addr()),
            remote_port: src_port,
        }),
    }
}

/// This function extracts a key from a given IPv6 network buffer list (NBL).
/// The key contains the protocol, local and remote addresses and ports.
///
/// # Arguments
///
/// * `nbl` - A reference to the network buffer list from which the key will be extracted.
/// * `direction` - The direction of the packet (Inbound or Outbound).
///
/// # Returns
///
/// * `Ok(Key)` - A key containing the protocol, local and remote addresses and ports.
/// * `Err(String)` - An error message if the function fails to get net_buffer data.
/// Reads the ICMP echo header of a packet, if it has one.
///
/// The buffer must already be positioned at the IP header, which is what the packet
/// layer arranges before calling this.
///
/// Returns `None` for anything that is not an ICMP echo request or reply, including
/// a packet whose IPv6 extension header chain does not resolve - the ICMP header is
/// not where the offset claims in that case.
pub fn get_icmp_echo_from_nbl(nbl: &NetBufferList, is_ipv6: bool) -> Option<IcmpEcho> {
    if is_ipv6 {
        let (buffer, len) = read_ipv6_headers(nbl)?;
        let packet = buffer.get(..len)?;
        if packet.len() < IPV6_HEADER_LEN {
            return None;
        }
        let headers = walk_ipv6_headers(packet);
        if !headers.resolved || headers.protocol != smoltcp::wire::IpProtocol::Icmpv6 {
            return None;
        }
        get_icmp_echo(packet.get(headers.transport_offset..)?, true)
    } else {
        // Same reasoning as get_key_from_nbl_v4: read enough for the largest IPv4
        // header, because IP options move the ICMP header past IPV4_HEADER_LEN.
        let mut buffer = [0u8; IPV4_MAX_HEADER_LEN + 8];
        let len = read_leading_bytes(nbl, &mut buffer, IPV4_HEADER_LEN + 8)?;
        let packet = buffer.get(..len)?;

        let ip_packet = Ipv4Packet::new_unchecked(packet);
        if ip_packet.next_header() != smoltcp::wire::IpProtocol::Icmp {
            return None;
        }

        let mut transport_offset = ip_packet.header_len() as usize;
        if transport_offset < IPV4_HEADER_LEN {
            transport_offset = IPV4_HEADER_LEN;
        }

        get_icmp_echo(packet.get(transport_offset..)?, false)
    }
}

pub fn get_key_from_nbl_v6(nbl: &NetBufferList, direction: Direction) -> Result<Key, String> {
    // Read enough to cover the base header, any extension header chain and the
    // two port fields. Reading only IPV6_HEADER_LEN + 4 would place the ports
    // inside the first extension header whenever the chain is non-empty.
    let Some((headers, len)) = read_ipv6_headers(nbl) else {
        return Err("failed to get net_buffer data".to_string());
    };

    build_key_v6(&headers[..len], direction)
}

/// Builds a connection key from an IPv6 packet, resolving the transport protocol
/// and port offset through the extension header chain.
fn build_key_v6(packet: &[u8], direction: Direction) -> Result<Key, String> {
    if packet.len() < IPV6_HEADER_LEN {
        return Err("packet shorter than IPv6 header".to_string());
    }

    // This will panic in debug mode, probably because of runtime checks.
    let ip_packet = Ipv6Packet::new_unchecked(packet);
    let headers = walk_ipv6_headers(packet);

    // An unresolved chain yields no usable key: `protocol` is an extension header
    // type and the ports are not where the offset says. Building a key anyway put
    // entries like "protocol 60, port 0" into the connection cache, and a verdict
    // was then issued against them - the same cache poisoning that unparsed
    // fragments used to cause.
    //
    // A packet whose chain does not resolve is either malformed or has more
    // extension headers than MAX_IPV6_EXT_HEADERS. Neither can be attributed to a
    // connection, so it is rejected here and the caller drops it.
    if !headers.resolved {
        return Err("IPv6 extension header chain did not resolve".to_string());
    }

    // Ports live at the transport offset, which is past any extension headers.
    // An individual fragment other than the first carries no transport header at
    // all, so get_ports is only meaningful when the slice actually reaches it.
    let (src_port, dst_port) = match packet.get(headers.transport_offset..) {
        Some(transport) => get_ports(transport, headers.protocol),
        None => (0, 0),
    };

    match direction {
        Direction::Outbound => Ok(Key {
            protocol: headers.protocol,
            local_address: IpAddress::Ipv6(ip_packet.src_addr()),
            local_port: src_port,
            remote_address: IpAddress::Ipv6(ip_packet.dst_addr()),
            remote_port: dst_port,
        }),
        Direction::Inbound => Ok(Key {
            protocol: headers.protocol,
            local_address: IpAddress::Ipv6(ip_packet.dst_addr()),
            local_port: dst_port,
            remote_address: IpAddress::Ipv6(ip_packet.src_addr()),
            remote_port: src_port,
        }),
    }
}

// Converts a given key into connection information.
//
// This function takes a key, packet id, process id, and direction as input.
// It then uses these to create a new `ConnectionInfoV6` or `ConnectionInfoV4` object,
// depending on whether the IP addresses in the key are IPv6 or IPv4 respectively.
//
// # Arguments
//
// * `key` - A reference to the key object containing the connection details.
// * `packet_id` - The id of the packet.
// * `process_id` - The id of the process.
// * `direction` - The direction of the connection.
//
// # Returns
//
// * `Some(Box<dyn Info>)` - A boxed `Info` trait object if the key contains valid IPv4 or IPv6 addresses.
// * `None` - If the key does not contain valid IPv4 or IPv6 addresses.
// pub fn key_to_connection_info(
//     key: &Key,
//     packet_id: u64,
//     process_id: u64,
//     direction: Direction,
//     payload: &[u8],
// ) -> Option<Info> {
//     let (local_port, remote_port) = match key.protocol {
//         IpProtocol::Tcp | IpProtocol::Udp => (key.local_port, key.remote_port),
//         _ => (0, 0),
//     };

//     match (key.local_address, key.remote_address) {
//         (IpAddress::Ipv6(local_ip), IpAddress::Ipv6(remote_ip)) if key.is_ipv6() => {
//             Some(protocol::info::connection_info_v6(
//                 packet_id,
//                 process_id,
//                 direction as u8,
//                 u8::from(key.protocol),
//                 local_ip.0,
//                 remote_ip.0,
//                 local_port,
//                 remote_port,
//                 payload,
//             ))
//         }
//         (IpAddress::Ipv4(local_ip), IpAddress::Ipv4(remote_ip)) => {
//             Some(protocol::info::connection_info_v4(
//                 packet_id,
//                 process_id,
//                 direction as u8,
//                 u8::from(key.protocol),
//                 local_ip.0,
//                 remote_ip.0,
//                 local_port,
//                 remote_port,
//                 payload,
//             ))
//         }
//         _ => None,
//     }
// }
