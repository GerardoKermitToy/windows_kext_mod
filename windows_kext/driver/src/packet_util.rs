use alloc::string::{String, ToString};
use core::mem::MaybeUninit;
use likely_stable::unlikely;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, TcpPacket, UdpPacket};
use wdk::filter_engine::net_buffer::{NetBufferList, NetBufferReader};

use crate::ipv6_packet::recalculate_ipv6_transport_checksum;
use crate::{dbg, err, ipv6_packet::PacketData, packet_metadata::MAX_PACKET_INSPECT_LEN};

pub fn recalc_header_checksums(packet: &mut [u8], ipv6: bool) -> Result<(), String> {
    if unlikely(ipv6) {
        // TCP/UDP start after the complete extension-header chain, and the
        // pseudo-header length is the upper-layer length rather than the IPv6
        // payload length (which includes extensions).
        recalculate_ipv6_transport_checksum(packet).map_err(|error| error.to_string())?;
    } else {
        if let Ok(mut ip_packet) = Ipv4Packet::new_checked(packet) {
            ip_packet.fill_checksum();
            let protocol = ip_packet.next_header();
            let source = IpAddress::Ipv4(ip_packet.src_addr());
            let destination = IpAddress::Ipv4(ip_packet.dst_addr());
            match protocol {
                IpProtocol::Udp => {
                    if let Ok(mut udp_packet) = UdpPacket::new_checked(ip_packet.payload_mut()) {
                        udp_packet.fill_checksum(&source, &destination);
                    }
                }
                IpProtocol::Tcp => {
                    if let Ok(mut tcp_packet) = TcpPacket::new_checked(ip_packet.payload_mut()) {
                        tcp_packet.fill_checksum(&source, &destination);
                    }
                }
                _ => {}
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

impl<const N: usize> PacketData for Option<NetBufferReader<'_, '_, N>> {
    #[inline]
    fn len(&self) -> usize {
        self.as_ref().map_or(0, NetBufferReader::len)
    }

    #[inline]
    fn prefix(&mut self, length: usize) -> Option<&[u8]> {
        self.as_mut()?.prefix(length).ok()
    }

    #[inline]
    fn byte(&mut self, offset: usize) -> Option<u8> {
        self.as_mut()?.byte(offset).ok()
    }
}

/// Borrows the packet and scratch storage without reading or copying either.
#[inline]
pub(crate) fn packet_reader<'nbl, 'storage>(
    nbl: &'nbl NetBufferList,
    storage: &'storage mut MaybeUninit<[u8; MAX_PACKET_INSPECT_LEN]>,
) -> Option<NetBufferReader<'nbl, 'storage, MAX_PACKET_INSPECT_LEN>> {
    // SAFETY: The WFP-owned NBL is borrowed for synchronous, read-only inspection.
    // The callout stops using the reader before moving or injecting the packet.
    unsafe { nbl.reader(storage).ok() }
}
