use core::mem;

use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};
use protocol::info::Info;
use smoltcp::wire::{IpAddress, IpProtocol};
use wdk::rw_spin_lock::RwSpinLock;

use crate::{
    connection::Direction, connection_map::Key, device::Packet,
    tcp_closure_cache::request_matches_tcp_endpoint,
};

pub struct Entry<T> {
    pub value: T,
    id: u64,
}

impl<T> Entry<T> {
    pub fn id(&self) -> u64 {
        self.id
    }
}

#[derive(Clone, Copy)]
struct PendingIdentity {
    key: Key,
    connection_instance_id: Option<u64>,
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
    active: BTreeMap<u64, PendingIdentity>,
    lock: RwSpinLock,
    next_id: u64,
}

impl IdCache {
    pub fn new() -> Self {
        Self {
            values: VecDeque::with_capacity(1000),
            active: BTreeMap::new(),
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
    ) -> Vec<(u64, Info)> {
        let _guard = self.lock.write_lock();
        let (key, packet) = value;

        // One outgoing WFP indication can contain several NET_BUFFER packets.
        // Userspace decides packets rather than indications, so give every clone
        // its own cache entry, event and verdict ID. Keep this expansion under the
        // same lock (and the caller's connection-liveness guard) so endpoint closure
        // cannot observe only part of the original batch.
        match packet {
            Packet::NetworkBatch(nbls, inject_info) => {
                let mut queued = Vec::with_capacity(nbls.len());
                for nbl in nbls {
                    let packet = Packet::Network(nbl, inject_info);
                    if let Some(entry) = push_packet(
                        &mut self.values,
                        &mut self.next_id,
                        key,
                        packet,
                        connection_instance_id,
                        process_id,
                        direction,
                        ale_layer,
                    ) {
                        queued.push(entry);
                    }
                }
                queued
            }
            packet => push_packet(
                &mut self.values,
                &mut self.next_id,
                key,
                packet,
                connection_instance_id,
                process_id,
                direction,
                ale_layer,
            )
            .into_iter()
            .collect(),
        }
    }

    pub fn pop_id(&mut self, id: u64) -> Option<PendingPacket> {
        let _guard = self.lock.write_lock();
        if let Ok(index) = self.values.binary_search_by_key(&id, |val| val.id) {
            let entry = self.values.remove(index)?;
            self.active.insert(
                id,
                PendingIdentity {
                    key: entry.value.key,
                    connection_instance_id: entry.value.connection_instance_id,
                },
            );
            return Some(entry.value);
        }
        None
    }

    /// Removes the in-progress marker created when a verdict claimed this ID.
    pub fn finish_id(&mut self, id: u64) {
        let _guard = self.lock.write_lock();
        self.active.remove(&id);
    }

    /// Snapshots packet decisions already queued or being applied for one closing
    /// TCP endpoint. A loopback peer's packet-layer tuple is reversed, so include
    /// that side as well as requests bound directly to this connection generation.
    pub fn tcp_endpoint_request_ids(&self, key: &Key, instance_id: u64) -> Vec<u64> {
        let _guard = self.lock.read_lock();
        let matches = |identity: PendingIdentity| {
            request_matches_tcp_endpoint(
                key,
                instance_id,
                &identity.key,
                identity.connection_instance_id,
            )
        };

        let mut ids = Vec::new();
        ids.extend(self.values.iter().filter_map(|entry| {
            matches(PendingIdentity {
                key: entry.value.key,
                connection_instance_id: entry.value.connection_instance_id,
            })
            .then_some(entry.id)
        }));
        ids.extend(
            self.active
                .iter()
                .filter_map(|(id, identity)| matches(*identity).then_some(*id)),
        );
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// Retires pending packets owned by one of the supplied connection instances
    /// while preserving the ID order of unrelated requests.
    ///
    /// Outbound UDP packet-layer clones are retained but detached from the ended
    /// instance. The application's send completed before the packet was absorbed,
    /// and endpoint closure must not revoke that already accepted datagram. A later
    /// verdict therefore remains valid for the clone, but cannot update a reused
    /// connection tuple. Every NET_BUFFER packet retains its own request ID; entries
    /// are never merged. Other packets are removed and returned for fail-closed
    /// completion after both the cache lock and its outer Device lock are released.
    pub fn retire_connection_instances(
        &mut self,
        sorted_instance_ids: &[u64],
    ) -> VecDeque<Entry<PendingPacket>> {
        if sorted_instance_ids.is_empty() {
            return VecDeque::new();
        }

        let _guard = self.lock.write_lock();
        let mut retained = VecDeque::with_capacity(self.values.len());
        let mut removed = VecDeque::new();

        while let Some(mut entry) = self.values.pop_front() {
            let belongs_to_closed_instance = entry
                .value
                .connection_instance_id
                .map(|instance_id| sorted_instance_ids.binary_search(&instance_id).is_ok())
                .unwrap_or(false);
            if belongs_to_closed_instance
                && entry.value.packet.survives_connection_end(&entry.value.key)
            {
                entry.value.connection_instance_id = None;
                retained.push_back(entry);
            } else if belongs_to_closed_instance {
                removed.push_back(entry);
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
        return self.values.len() + self.active.len();
    }

    pub fn pop_all(&mut self) -> VecDeque<Entry<PendingPacket>> {
        let mut values = VecDeque::with_capacity(1);
        let _guard = self.lock.write_lock();
        mem::swap(&mut self.values, &mut values);

        return values;
    }
}

fn push_packet(
    values: &mut VecDeque<Entry<PendingPacket>>,
    next_id: &mut u64,
    key: Key,
    packet: Packet,
    connection_instance_id: Option<u64>,
    process_id: u64,
    direction: Direction,
    ale_layer: bool,
) -> Option<(u64, Info)> {
    let id = *next_id;
    let info = build_info(&key, id, process_id, direction, &packet, ale_layer)?;
    values.push_back(Entry {
        value: PendingPacket {
            key,
            packet,
            connection_instance_id,
        },
        id,
    });
    *next_id = next_id.wrapping_add(1); // Assuming this will not overflow.
    Some((id, info))
}

fn get_payload(packet: &Packet) -> Option<&[u8]> {
    match packet {
        Packet::Network(nbl, _) => nbl.get_data(),
        Packet::NetworkBatch(nbls, _) => nbls.first().and_then(|nbl| nbl.get_data()),
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
