use super::*;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

type Totals<Address> = BTreeMap<Key<Address>, (u64, u64)>;

fn key_v4(id: u32) -> Key<Ipv4Address> {
    Key {
        local_ip: Ipv4Address::new(10, 0, 0, 1),
        local_port: 49152 + (id % 16384) as u16,
        remote_ip: Ipv4Address(id.to_be_bytes()),
        remote_port: 443,
    }
}

fn key_v6(id: u32) -> Key<Ipv6Address> {
    let mut remote_ip = [0; 16];
    remote_ip[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    remote_ip[12..].copy_from_slice(&id.to_be_bytes());
    Key {
        local_ip: Ipv6Address::LOOPBACK,
        local_port: 49152 + (id % 16384) as u16,
        remote_ip: Ipv6Address(remote_ip),
        remote_port: 443,
    }
}

fn decode<Address: Ord>(
    info: Info,
    info_type: u8,
    protocol: u8,
    addr_len: usize,
    address: impl Fn(&[u8]) -> Address,
) -> Totals<Address> {
    let bytes = info.as_bytes();
    assert_eq!(bytes[0], info_type);
    assert_eq!(bytes[5], protocol);
    assert_eq!(
        u32::from_le_bytes(bytes[1..5].try_into().unwrap()) as usize,
        bytes.len() - 5
    );
    let count = u32::from_le_bytes(bytes[6..10].try_into().unwrap()) as usize;
    let entry_size = addr_len * 2 + 4 + 16;
    assert_eq!(bytes.len(), 10 + count * entry_size);
    let mut result = BTreeMap::new();
    for entry in bytes[10..].chunks_exact(entry_size) {
        let remote = addr_len + 2;
        let counters = addr_len * 2 + 4;
        let key = Key {
            local_ip: address(&entry[..addr_len]),
            local_port: u16::from_le_bytes(entry[addr_len..remote].try_into().unwrap()),
            remote_ip: address(&entry[remote..remote + addr_len]),
            remote_port: u16::from_le_bytes(entry[remote + addr_len..counters].try_into().unwrap()),
        };
        let tx = u64::from_le_bytes(entry[counters..counters + 8].try_into().unwrap());
        let rx = u64::from_le_bytes(entry[counters + 8..].try_into().unwrap());
        assert!(
            result.insert(key, (tx, rx)).is_none(),
            "duplicate wire tuple"
        );
    }
    result
}

fn decode_v4(info: Info, protocol: u8) -> Totals<Ipv4Address> {
    decode(info, 5, protocol, 4, |ip| {
        Ipv4Address(ip.try_into().unwrap())
    })
}

fn decode_v6(info: Info, protocol: u8) -> Totals<Ipv6Address> {
    decode(info, 6, protocol, 16, |ip| {
        Ipv6Address(ip.try_into().unwrap())
    })
}

fn assert_released<Address>(stats: &ShardedStats<Address>) {
    for shard in &stats.shards {
        let map = shard.read_lock();
        assert_eq!(map.len(), 0);
        assert_eq!(map.capacity(), 0, "empty map retained its backing table");
    }
}

fn assert_all_released(bandwidth: &Bandwidth) {
    assert_released(&bandwidth.stats_tcp_v4);
    assert_released(&bandwidth.stats_tcp_v6);
    assert_released(&bandwidth.stats_udp_v4);
    assert_released(&bandwidth.stats_udp_v6);
}

#[test]
fn dropping_partial_snapshot_releases_all_owned_keys() {
    struct Address {
        id: u32,
        drops: Arc<AtomicUsize>,
    }
    impl PartialEq for Address {
        fn eq(&self, other: &Self) -> bool {
            self.id == other.id
        }
    }
    impl Eq for Address {}
    impl Hash for Address {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.id.hash(state);
        }
    }
    impl Drop for Address {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    let drops = Arc::new(AtomicUsize::new(0));
    let stats = ShardedStats::new();
    for id in 0..256 {
        stats.update(
            Key {
                local_ip: Address {
                    id: 0,
                    drops: Arc::clone(&drops),
                },
                local_port: 1234,
                remote_ip: Address {
                    id,
                    drops: Arc::clone(&drops),
                },
                remote_port: 443,
            },
            Direction::Inbound,
            1,
        );
    }
    let mut snapshot = stats.take();
    assert_released(&stats);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    drop(snapshot.next().unwrap());
    assert_eq!(drops.load(Ordering::Relaxed), 2);
    drop(snapshot);
    assert_eq!(drops.load(Ordering::Relaxed), 512);
}

#[test]
fn empty_maps_and_repeated_empty_drains_have_no_capacity() {
    let bandwidth = Bandwidth::new();
    for _ in 0..3 {
        assert_eq!(bandwidth.get_entries_counts(), (0, 0, 0, 0));
        assert!(bandwidth.get_all_updates_tcp_v4().is_none());
        assert!(bandwidth.get_all_updates_tcp_v6().is_none());
        assert!(bandwidth.get_all_updates_udp_v4().is_none());
        assert!(bandwidth.get_all_updates_udp_v6().is_none());
        assert_all_released(&bandwidth);
    }
}

#[test]
fn repeated_updates_preserve_direction_family_and_protocol() {
    let bandwidth = Bandwidth::new();
    let k4 = key_v4(1);
    let k6 = key_v6(1);
    for _ in 0..10 {
        bandwidth.update_tcp_v4(k4, Direction::Outbound, 100);
        bandwidth.update_tcp_v4(k4, Direction::Inbound, 7);
        bandwidth.update_udp_v4(k4, Direction::Outbound, 31);
        bandwidth.update_udp_v4(k4, Direction::Inbound, 11);
        bandwidth.update_tcp_v6(k6, Direction::Outbound, 4096);
        bandwidth.update_tcp_v6(k6, Direction::Inbound, 19);
        bandwidth.update_udp_v6(k6, Direction::Outbound, 57);
        bandwidth.update_udp_v6(k6, Direction::Inbound, 29);
    }
    assert_eq!(bandwidth.get_entries_counts(), (1, 1, 1, 1));
    assert_eq!(
        decode_v4(bandwidth.get_all_updates_tcp_v4().unwrap(), 6),
        BTreeMap::from([(k4, (1000, 70))])
    );
    assert_eq!(
        decode_v6(bandwidth.get_all_updates_tcp_v6().unwrap(), 6),
        BTreeMap::from([(k6, (40960, 190))])
    );
    assert_eq!(
        decode_v4(bandwidth.get_all_updates_udp_v4().unwrap(), 17),
        BTreeMap::from([(k4, (310, 110))])
    );
    assert_eq!(
        decode_v6(bandwidth.get_all_updates_udp_v6().unwrap(), 17),
        BTreeMap::from([(k6, (570, 290))])
    );
    assert_all_released(&bandwidth);
}

#[test]
fn every_tuple_field_participates_in_identity() {
    let bandwidth = Bandwidth::new();
    let base4 = key_v4(1);
    let base6 = key_v6(1);
    let keys4 = [
        base4,
        Key {
            local_ip: Ipv4Address::new(127, 0, 0, 1),
            ..base4
        },
        Key {
            local_port: 1234,
            ..base4
        },
        Key {
            remote_ip: Ipv4Address::new(127, 0, 0, 1),
            ..base4
        },
        Key {
            remote_port: 53,
            ..base4
        },
    ];
    let keys6 = [
        base6,
        Key {
            local_ip: Ipv6Address::UNSPECIFIED,
            ..base6
        },
        Key {
            local_port: 1234,
            ..base6
        },
        Key {
            remote_ip: Ipv6Address::LOOPBACK,
            ..base6
        },
        Key {
            remote_port: 53,
            ..base6
        },
    ];
    for (i, (k4, k6)) in keys4.iter().zip(&keys6).enumerate() {
        bandwidth.update_udp_v4(*k4, Direction::Inbound, i + 1);
        bandwidth.update_udp_v6(*k6, Direction::Inbound, i + 1);
    }
    let actual4 = decode_v4(bandwidth.get_all_updates_udp_v4().unwrap(), 17);
    let actual6 = decode_v6(bandwidth.get_all_updates_udp_v6().unwrap(), 17);
    assert_eq!(actual4.len(), 5);
    assert_eq!(actual6.len(), 5);
    for (i, (k4, k6)) in keys4.iter().zip(&keys6).enumerate() {
        assert_eq!(actual4[k4], (0, i as u64 + 1));
        assert_eq!(actual6[k6], (0, i as u64 + 1));
    }
}

#[test]
fn counters_preserve_values_above_u32() {
    let bandwidth = Bandwidth::new();
    let bytes = u32::MAX as usize + 123;
    bandwidth.update_tcp_v4(key_v4(1), Direction::Outbound, bytes);
    bandwidth.update_tcp_v4(key_v4(1), Direction::Outbound, bytes);
    bandwidth.update_tcp_v4(key_v4(1), Direction::Inbound, bytes + 1);
    let result = decode_v4(bandwidth.get_all_updates_tcp_v4().unwrap(), 6);
    assert_eq!(result[&key_v4(1)], (bytes as u64 * 2, bytes as u64 + 1));
}

#[test]
fn routing_uses_all_shards_and_snapshot_len_is_exact() {
    let stats = ShardedStats::new();
    for id in 0..4096 {
        stats.update(key_v4(id), Direction::Outbound, 1);
    }
    assert!(stats.shards.iter().all(|s| !s.read_lock().is_empty()));
    let mut snapshot = stats.take();
    assert_released(&stats);
    for remaining in (1..=4096).rev() {
        assert_eq!(snapshot.len(), remaining);
        assert_eq!(snapshot.size_hint(), (remaining, Some(remaining)));
        assert!(snapshot.next().is_some());
    }
    assert_eq!(snapshot.len(), 0);
    assert_eq!(snapshot.size_hint(), (0, Some(0)));
    assert!(snapshot.next().is_none());
    assert!(snapshot.next().is_none());
}

#[test]
fn detached_snapshot_does_not_absorb_next_interval() {
    let stats = ShardedStats::new();
    let key = key_v6(1);
    stats.update(key, Direction::Outbound, 123);
    let mut old = stats.take();
    assert_released(&stats);
    stats.update(key, Direction::Inbound, 456);
    let (_, old_value) = old.next().unwrap();
    assert_eq!(old_value.transmitted_bytes, 123);
    assert_eq!(old_value.received_bytes, 0);
    assert!(old.next().is_none());
    let mut new = stats.take();
    let (new_key, new_value) = new.next().unwrap();
    assert_eq!(new_key, key);
    assert_eq!(new_value.transmitted_bytes, 0);
    assert_eq!(new_value.received_bytes, 456);
    assert!(new.next().is_none());
    assert_released(&stats);
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CollisionAddress(u32);

impl Hash for CollisionAddress {
    fn hash<H: Hasher>(&self, state: &mut H) {
        0u32.hash(state);
    }
}

#[test]
fn identical_hashes_never_merge_distinct_tuples() {
    let stats = ShardedStats::new();
    for id in 0..1024 {
        let key = Key {
            local_ip: CollisionAddress(0),
            local_port: 1234,
            remote_ip: CollisionAddress(id),
            remote_port: 443,
        };
        stats.update(key, Direction::Inbound, id as usize + 1);
    }
    let snapshot = stats.take();
    assert_eq!(snapshot.len(), 1024);
    let totals: Totals<_> = snapshot
        .map(|(key, value)| (key, (value.transmitted_bytes, value.received_bytes)))
        .collect();
    for (key, (tx, rx)) in &totals {
        assert_eq!(*tx, 0);
        assert_eq!(*rx, key.remote_ip.0 as u64 + 1);
    }
    assert_eq!(totals.len(), 1024);
    assert_released(&stats);
}

#[test]
fn nested_guards_are_released_in_reverse_order() {
    use std::cell::RefCell;
    struct Guard<'a>(usize, &'a RefCell<Vec<usize>>);
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            self.1.borrow_mut().push(self.0);
        }
    }
    let released = RefCell::new(Vec::new());
    release_in_reverse(core::array::from_fn::<_, SHARD_COUNT, _>(|i| {
        Guard(i, &released)
    }));
    assert_eq!(
        *released.borrow(),
        (0..SHARD_COUNT).rev().collect::<Vec<_>>()
    );
}

#[test]
fn repeated_growth_and_drain_release_all_capacity() {
    let bandwidth = Bandwidth::new();
    for count in [8192, 65536, 3, 32768, 1] {
        for id in 0..count {
            bandwidth.update_tcp_v4(key_v4(id), Direction::Outbound, id as usize + 1);
            bandwidth.update_udp_v6(key_v6(id), Direction::Inbound, id as usize + 2);
        }
        assert_eq!(
            bandwidth.get_entries_counts(),
            (count as usize, 0, 0, count as usize)
        );
        let v4 = decode_v4(bandwidth.get_all_updates_tcp_v4().unwrap(), 6);
        let v6 = decode_v6(bandwidth.get_all_updates_udp_v6().unwrap(), 17);
        assert_eq!(v4.len(), count as usize);
        assert_eq!(v6.len(), count as usize);
        for id in 0..count {
            assert_eq!(v4[&key_v4(id)], (id as u64 + 1, 0));
            assert_eq!(v6[&key_v6(id)], (0, id as u64 + 2));
        }
        assert_all_released(&bandwidth);
    }
}

#[test]
fn million_distinct_tuples_are_exported_without_a_limit() {
    let bandwidth = Bandwidth::new();
    const PER_CLASS: u32 = 250_000;
    for id in 0..PER_CLASS {
        let k4 = key_v4(id);
        let k6 = key_v6(id);
        bandwidth.update_tcp_v4(k4, Direction::Outbound, id as usize + 1);
        bandwidth.update_udp_v4(k4, Direction::Inbound, id as usize + 2);
        bandwidth.update_tcp_v6(k6, Direction::Inbound, id as usize + 3);
        bandwidth.update_udp_v6(k6, Direction::Outbound, id as usize + 4);
    }
    assert_eq!(
        bandwidth.get_entries_counts(),
        (250_000, 250_000, 250_000, 250_000)
    );
    let tcp4 = decode_v4(bandwidth.get_all_updates_tcp_v4().unwrap(), 6);
    assert_eq!(tcp4.len(), PER_CLASS as usize);
    for id in 0..PER_CLASS {
        assert_eq!(tcp4[&key_v4(id)], (id as u64 + 1, 0));
    }
    drop(tcp4);
    let tcp6 = decode_v6(bandwidth.get_all_updates_tcp_v6().unwrap(), 6);
    assert_eq!(tcp6.len(), PER_CLASS as usize);
    for id in 0..PER_CLASS {
        assert_eq!(tcp6[&key_v6(id)], (0, id as u64 + 3));
    }
    drop(tcp6);
    let udp4 = decode_v4(bandwidth.get_all_updates_udp_v4().unwrap(), 17);
    assert_eq!(udp4.len(), PER_CLASS as usize);
    for id in 0..PER_CLASS {
        assert_eq!(udp4[&key_v4(id)], (0, id as u64 + 2));
    }
    drop(udp4);
    let udp6 = decode_v6(bandwidth.get_all_updates_udp_v6().unwrap(), 17);
    assert_eq!(udp6.len(), PER_CLASS as usize);
    for id in 0..PER_CLASS {
        assert_eq!(udp6[&key_v6(id)], (id as u64 + 4, 0));
    }
    assert_all_released(&bandwidth);
}

#[derive(Default)]
struct AllTotals {
    tcp4: Totals<Ipv4Address>,
    tcp6: Totals<Ipv6Address>,
    udp4: Totals<Ipv4Address>,
    udp6: Totals<Ipv6Address>,
}

fn merge<Address: Ord>(target: &mut Totals<Address>, source: Totals<Address>) {
    for (key, (tx, rx)) in source {
        let total = target.entry(key).or_default();
        total.0 += tx;
        total.1 += rx;
    }
}

impl AllTotals {
    fn collect(&mut self, bandwidth: &Bandwidth) {
        if let Some(info) = bandwidth.get_all_updates_tcp_v4() {
            merge(&mut self.tcp4, decode_v4(info, 6));
        }
        if let Some(info) = bandwidth.get_all_updates_tcp_v6() {
            merge(&mut self.tcp6, decode_v6(info, 6));
        }
        if let Some(info) = bandwidth.get_all_updates_udp_v4() {
            merge(&mut self.udp4, decode_v4(info, 17));
        }
        if let Some(info) = bandwidth.get_all_updates_udp_v6() {
            merge(&mut self.udp6, decode_v6(info, 17));
        }
    }

    fn add(&mut self, other: Self) {
        merge(&mut self.tcp4, other.tcp4);
        merge(&mut self.tcp6, other.tcp6);
        merge(&mut self.udp4, other.udp4);
        merge(&mut self.udp6, other.udp6);
    }
}

#[test]
fn concurrent_writers_drainers_and_diagnostics_preserve_every_tuple() {
    const WRITERS: usize = 4;
    const DRAINERS: usize = 2;
    const UPDATES: usize = 8000;
    let bandwidth = Bandwidth::new();
    let active = AtomicUsize::new(WRITERS);
    let start = Barrier::new(WRITERS + DRAINERS + 1);
    let mut actual = std::thread::scope(|scope| {
        for worker in 0..WRITERS {
            let bandwidth = &bandwidth;
            let start = &start;
            let active = &active;
            scope.spawn(move || {
                start.wait();
                for event in 0..UPDATES {
                    let id = ((event + worker) % 1024) as u32;
                    let direction = if event % 2 == 0 {
                        Direction::Outbound
                    } else {
                        Direction::Inbound
                    };
                    bandwidth.update_tcp_v4(key_v4(id), direction, worker + 1);
                    bandwidth.update_tcp_v6(key_v6(id), direction, worker + 2);
                    bandwidth.update_udp_v4(key_v4(id), direction, worker + 3);
                    bandwidth.update_udp_v6(key_v6(id), direction, worker + 4);
                    if event % 64 == 0 {
                        std::thread::yield_now();
                    }
                }
                active.fetch_sub(1, Ordering::Release);
            });
        }
        let drainers: Vec<_> = (0..DRAINERS)
            .map(|_| {
                let bandwidth = &bandwidth;
                let start = &start;
                let active = &active;
                scope.spawn(move || {
                    let mut totals = AllTotals::default();
                    start.wait();
                    while active.load(Ordering::Acquire) != 0 {
                        totals.collect(bandwidth);
                        bandwidth.get_entries_counts();
                        std::thread::yield_now();
                    }
                    totals.collect(bandwidth);
                    totals
                })
            })
            .collect();
        start.wait();
        let mut totals = AllTotals::default();
        for drainer in drainers {
            totals.add(drainer.join().unwrap());
        }
        totals
    });
    actual.collect(&bandwidth);
    let mut expected = AllTotals::default();
    for worker in 0..WRITERS {
        for event in 0..UPDATES {
            let id = ((event + worker) % 1024) as u32;
            let column = event % 2;
            let v4 = key_v4(id);
            let v6 = key_v6(id);
            for (total, bytes) in [
                (expected.tcp4.entry(v4).or_default(), worker + 1),
                (expected.tcp6.entry(v6).or_default(), worker + 2),
                (expected.udp4.entry(v4).or_default(), worker + 3),
                (expected.udp6.entry(v6).or_default(), worker + 4),
            ] {
                if column == 0 {
                    total.0 += bytes as u64;
                } else {
                    total.1 += bytes as u64;
                }
            }
        }
    }
    assert_eq!(actual.tcp4, expected.tcp4);
    assert_eq!(actual.tcp6, expected.tcp6);
    assert_eq!(actual.udp4, expected.udp4);
    assert_eq!(actual.udp6, expected.udp6);
    assert_all_released(&bandwidth);
}
