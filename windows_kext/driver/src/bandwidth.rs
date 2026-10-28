use core::hash::{BuildHasherDefault, Hash, Hasher};
use hashbrown::HashMap;
use protocol::info::{BandwidthValueV4, BandwidthValueV6, Info};
use rustc_hash::FxHasher;
use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv6Address};
#[cfg(not(test))]
use wdk::rw_spin_lock::RwSpinLock;

use crate::connection::Direction;

#[cfg(test)]
struct RwSpinLock<T>(std::sync::RwLock<T>);

#[cfg(test)]
impl<T> RwSpinLock<T> {
    fn new(value: T) -> Self {
        Self(std::sync::RwLock::new(value))
    }

    fn read_lock(&self) -> std::sync::RwLockReadGuard<'_, T> {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_lock(&self) -> std::sync::RwLockWriteGuard<'_, T> {
        self.0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

const SHARD_COUNT: usize = 16;
const _: () = assert!(SHARD_COUNT.is_power_of_two());

type FxBuildHasher = BuildHasherDefault<FxHasher>;
type StatsMap<Address> = HashMap<Key<Address>, Value, FxBuildHasher>;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy, Default)]
pub struct Key<Address> {
    pub local_ip: Address,
    pub local_port: u16,
    pub remote_ip: Address,
    pub remote_port: u16,
}

#[derive(Default)]
struct Value {
    received_bytes: u64,
    transmitted_bytes: u64,
}

/// Independent maps for one protocol/address-family class. Fixed FxHash is an
/// intentional throughput choice, not protection against adversarial keys.
/// There is no entry limit, eviction, aggregation or retained capacity pool.
struct ShardedStats<Address> {
    shards: [RwSpinLock<StatsMap<Address>>; SHARD_COUNT],
}

impl<Address> ShardedStats<Address> {
    fn new() -> Self {
        Self {
            shards: core::array::from_fn(|_| RwSpinLock::new(StatsMap::default())),
        }
    }

    fn take(&self) -> Snapshot<Address> {
        // Lock in shard order so the class has one snapshot boundary. Taking
        // ownership and installing zero-capacity maps cannot allocate or free.
        let mut guards = self.shards.each_ref().map(|shard| shard.write_lock());
        let maps = guards.each_mut().map(|guard| core::mem::take(&mut **guard));
        // Nested spin locks must restore IRQL in reverse acquisition order.
        release_in_reverse(guards);

        let remaining = maps.iter().map(StatsMap::len).sum();
        Snapshot {
            entries: maps.into_iter().flatten(),
            remaining,
        }
    }
}

impl<Address: Eq + Hash> ShardedStats<Address> {
    #[inline]
    fn update(&self, key: Key<Address>, direction: Direction, bytes: usize) {
        let mut stats = self.shards[shard_index(&key)].write_lock();
        let value = stats.entry(key).or_default();
        match direction {
            Direction::Outbound => value.transmitted_bytes += bytes as u64,
            Direction::Inbound => value.received_bytes += bytes as u64,
        }
    }
}

fn release_in_reverse<T, const N: usize>(guards: [T; N]) {
    for guard in guards.into_iter().rev() {
        drop(guard);
    }
}

#[inline]
fn shard_index<Address: Hash>(key: &Key<Address>) -> usize {
    let mut hasher = FxHasher::default();
    key.hash(&mut hasher);
    // Avoid routing on the low bucket-index bits or the top SwissTable tag bits.
    (hasher.finish() >> 32) as usize & (SHARD_COUNT - 1)
}

/// Owns detached tables until they have been serialized, then frees them. The
/// exact remaining length lets the wire serializer allocate its output once,
/// without materializing a second collection of all tuple/counter records.
struct Snapshot<Address> {
    entries: core::iter::Flatten<core::array::IntoIter<StatsMap<Address>, SHARD_COUNT>>,
    remaining: usize,
}

impl<Address> Iterator for Snapshot<Address> {
    type Item = (Key<Address>, Value);

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.entries.next();
        if entry.is_some() {
            self.remaining -= 1;
        }
        entry
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<Address> ExactSizeIterator for Snapshot<Address> {}

pub struct Bandwidth {
    stats_tcp_v4: ShardedStats<Ipv4Address>,
    stats_tcp_v6: ShardedStats<Ipv6Address>,
    stats_udp_v4: ShardedStats<Ipv4Address>,
    stats_udp_v6: ShardedStats<Ipv6Address>,
}

impl Bandwidth {
    pub fn new() -> Self {
        Self {
            stats_tcp_v4: ShardedStats::new(),
            stats_tcp_v6: ShardedStats::new(),
            stats_udp_v4: ShardedStats::new(),
            stats_udp_v6: ShardedStats::new(),
        }
    }

    pub fn get_all_updates_tcp_v4(&self) -> Option<Info> {
        Self::drain_v4(&self.stats_tcp_v4, IpProtocol::Tcp)
    }

    pub fn get_all_updates_tcp_v6(&self) -> Option<Info> {
        Self::drain_v6(&self.stats_tcp_v6, IpProtocol::Tcp)
    }

    pub fn get_all_updates_udp_v4(&self) -> Option<Info> {
        Self::drain_v4(&self.stats_udp_v4, IpProtocol::Udp)
    }

    pub fn get_all_updates_udp_v6(&self) -> Option<Info> {
        Self::drain_v6(&self.stats_udp_v6, IpProtocol::Udp)
    }

    fn drain_v4(stats: &ShardedStats<Ipv4Address>, protocol: IpProtocol) -> Option<Info> {
        let snapshot = stats.take();
        if snapshot.len() == 0 {
            return None;
        }
        let values = snapshot.map(|(key, value)| BandwidthValueV4 {
            local_ip: key.local_ip.0,
            local_port: key.local_port,
            remote_ip: key.remote_ip.0,
            remote_port: key.remote_port,
            transmitted_bytes: value.transmitted_bytes,
            received_bytes: value.received_bytes,
        });
        Some(protocol::info::bandiwth_stats_array_v4(
            u8::from(protocol),
            values,
        ))
    }

    fn drain_v6(stats: &ShardedStats<Ipv6Address>, protocol: IpProtocol) -> Option<Info> {
        let snapshot = stats.take();
        if snapshot.len() == 0 {
            return None;
        }
        let values = snapshot.map(|(key, value)| BandwidthValueV6 {
            local_ip: key.local_ip.0,
            local_port: key.local_port,
            remote_ip: key.remote_ip.0,
            remote_port: key.remote_port,
            transmitted_bytes: value.transmitted_bytes,
            received_bytes: value.received_bytes,
        });
        Some(protocol::info::bandiwth_stats_array_v6(
            u8::from(protocol),
            values,
        ))
    }

    #[inline]
    pub fn update_tcp_v4(&self, key: Key<Ipv4Address>, direction: Direction, bytes: usize) {
        self.stats_tcp_v4.update(key, direction, bytes);
    }

    #[inline]
    pub fn update_tcp_v6(&self, key: Key<Ipv6Address>, direction: Direction, bytes: usize) {
        self.stats_tcp_v6.update(key, direction, bytes);
    }

    #[inline]
    pub fn update_udp_v4(&self, key: Key<Ipv4Address>, direction: Direction, bytes: usize) {
        self.stats_udp_v4.update(key, direction, bytes);
    }

    #[inline]
    pub fn update_udp_v6(&self, key: Key<Ipv6Address>, direction: Direction, bytes: usize) {
        self.stats_udp_v6.update(key, direction, bytes);
    }

    #[allow(dead_code)]
    pub fn get_entries_counts(&self) -> (usize, usize, usize, usize) {
        // Retain all guards for one coherent diagnostic snapshot. The lock order
        // matches take(); release classes and shards in reverse to restore IRQL.
        let tcp_v4 = self.stats_tcp_v4.shards.each_ref().map(|s| s.read_lock());
        let tcp_v6 = self.stats_tcp_v6.shards.each_ref().map(|s| s.read_lock());
        let udp_v4 = self.stats_udp_v4.shards.each_ref().map(|s| s.read_lock());
        let udp_v6 = self.stats_udp_v6.shards.each_ref().map(|s| s.read_lock());
        let counts = (
            tcp_v4.iter().map(|s| s.len()).sum(),
            tcp_v6.iter().map(|s| s.len()).sum(),
            udp_v4.iter().map(|s| s.len()).sum(),
            udp_v6.iter().map(|s| s.len()).sum(),
        );
        release_in_reverse(udp_v6);
        release_in_reverse(udp_v4);
        release_in_reverse(tcp_v6);
        release_in_reverse(tcp_v4);
        counts
    }
}

#[cfg(test)]
mod tests;
