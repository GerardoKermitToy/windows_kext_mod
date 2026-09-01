use core::mem;

use alloc::collections::VecDeque;
use protocol::info::Info;
use smoltcp::wire::{IpAddress, IpProtocol};
use wdk::rw_spin_lock::RwSpinLock;

use crate::{connection::Direction, connection_map::Key, device::Packet};

pub struct Entry<T> {
    pub value: T,
    id: u64,
}

pub struct PendingPacket {
    pub key: Key,
    pub packet: Packet,
    /// Exact live connection that queued this packet. Protocols without
    /// connection state (for example ICMP) deliberately leave this unset.
    pub connection_instance_id: Option<u64>,
}

pub struct IdCache {
    values: VecDeque<Entry<PendingPacket>>,
    lock: RwSpinLock,
    next_id: u64,
}

impl IdCache {
    pub fn new() -> Self {
        Self {
            values: VecDeque::with_capacity(1000),
            lock: RwSpinLock::default(),
            next_id: 1, // 0 is invalid id
        }
    }

    pub fn push(
        &mut self,
        value: (Key, Packet),
        connection_instance_id: Option<u64>,
        process_id: u64,
        direction: Direction,
        ale_layer: bool,
    ) -> Option<Info> {
        let _guard = self.lock.write_lock();
        let id = self.next_id;
        let info = build_info(&value.0, id, process_id, direction, &value.1, ale_layer);
        self.values.push_back(Entry {
            value: PendingPacket {
                key: value.0,
                packet: value.1,
                connection_instance_id,
            },
            id,
        });
        self.next_id = self.next_id.wrapping_add(1); // Assuming this will not overflow.

        return info;
    }

    pub fn pop_id(&mut self, id: u64) -> Option<PendingPacket> {
        let _guard = self.lock.write_lock();
        if let Ok(index) = self.values.binary_search_by_key(&id, |val| val.id) {
            return self.values.remove(index).map(|entry| entry.value);
        }
        None
    }

    /// Removes every pending packet owned by one of the supplied connection
    /// instances while preserving the ID order of unrelated requests.
    ///
    /// The caller completes the returned ALE operations as blocked after both the
    /// cache lock and its outer Device lock have been released.
    pub fn pop_connection_instances(
        &mut self,
        sorted_instance_ids: &[u64],
    ) -> VecDeque<PendingPacket> {
        if sorted_instance_ids.is_empty() {
            return VecDeque::new();
        }

        let _guard = self.lock.write_lock();
        let mut retained = VecDeque::with_capacity(self.values.len());
        let mut removed = VecDeque::new();

        while let Some(entry) = self.values.pop_front() {
            let belongs_to_closed_instance = entry
                .value
                .connection_instance_id
                .map(|instance_id| sorted_instance_ids.binary_search(&instance_id).is_ok())
                .unwrap_or(false);
            if belongs_to_closed_instance {
                removed.push_back(entry.value);
            } else {
                retained.push_back(entry);
            }
        }
        self.values = retained;
        removed
    }

    #[allow(dead_code)]
    pub fn get_entries_count(&self) -> usize {
        let _guard = self.lock.read_lock();
        return self.values.len();
    }

    pub fn pop_all(&mut self) -> VecDeque<Entry<PendingPacket>> {
        let mut values = VecDeque::with_capacity(1);
        let _guard = self.lock.write_lock();
        mem::swap(&mut self.values, &mut values);

        return values;
    }
}

fn get_payload(packet: &Packet) -> Option<&[u8]> {
    match packet {
        Packet::PacketLayer(nbls, _) => nbls.first().and_then(|nbl| nbl.get_data()),
        Packet::AleLayer(defer) => defer
            .packet_list()
            .and_then(|packet_list| packet_list.get_event_data()),
    }
}

fn build_info(
    key: &Key,
    packet_id: u64,
    process_id: u64,
    direction: Direction,
    packet: &Packet,
    ale_layer: bool,
) -> Option<Info> {
    let (local_port, remote_port) = match key.protocol {
        IpProtocol::Tcp | IpProtocol::Udp => (key.local_port, key.remote_port),
        _ => (0, 0),
    };

    let payload_layer = if ale_layer {
        4 // Transport layer
    } else {
        3 // Network layer
    };

    let mut payload = &[][..];
    if let Some(p) = get_payload(packet) {
        payload = p;
    }

    match (key.local_address, key.remote_address) {
        (IpAddress::Ipv6(local_ip), IpAddress::Ipv6(remote_ip)) if key.is_ipv6() => {
            Some(protocol::info::connection_info_v6(
                packet_id,
                process_id,
                direction as u8,
                u8::from(key.protocol),
                local_ip.0,
                remote_ip.0,
                local_port,
                remote_port,
                payload_layer,
                payload,
            ))
        }
        (IpAddress::Ipv4(local_ip), IpAddress::Ipv4(remote_ip)) => {
            Some(protocol::info::connection_info_v4(
                packet_id,
                process_id,
                direction as u8,
                u8::from(key.protocol),
                local_ip.0,
                remote_ip.0,
                local_port,
                remote_port,
                payload_layer,
                payload,
            ))
        }
        _ => None,
    }
}
