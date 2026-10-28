use hashbrown::HashMap as HashBrownMap;
use rustc_hash::FxHasher;
use siphasher::sip::SipHasher13;
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::hash::{BuildHasher, BuildHasherDefault, Hash, Hasher};
use std::hint::black_box;
use std::mem;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const DEFAULT_EVENT_COUNT: usize = 1_000_000;
const DEFAULT_UNIQUE_COUNT: usize = 8_192;
const DEFAULT_RUNS: usize = 5;
const WORKLOAD_SEED: u64 = 0x5e_ed_2026_10_28;

struct CountingAllocator;

static COUNT_ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);
static LIVE_BYTES: AtomicU64 = AtomicU64::new(0);
static PEAK_LIVE_BYTES: AtomicU64 = AtomicU64::new(0);

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

impl CountingAllocator {
    fn record_alloc(size: usize) {
        if COUNT_ALLOCATIONS.load(Ordering::Relaxed) == 0 {
            return;
        }
        let size = size as u64;
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(size, Ordering::Relaxed);
        let live = LIVE_BYTES.fetch_add(size, Ordering::Relaxed) + size;
        let mut peak = PEAK_LIVE_BYTES.load(Ordering::Relaxed);
        while live > peak {
            match PEAK_LIVE_BYTES.compare_exchange_weak(
                peak,
                live,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => peak = observed,
            }
        }
    }

    fn record_dealloc(size: usize) {
        if COUNT_ALLOCATIONS.load(Ordering::Relaxed) != 0 {
            LIVE_BYTES.fetch_sub(size as u64, Ordering::Relaxed);
        }
    }

    fn reset(track: bool) {
        COUNT_ALLOCATIONS.store(0, Ordering::Relaxed);
        assert_eq!(
            LIVE_BYTES.load(Ordering::Relaxed),
            0,
            "benchmark allocation accounting was not quiescent"
        );
        ALLOC_CALLS.store(0, Ordering::Relaxed);
        ALLOCATED_BYTES.store(0, Ordering::Relaxed);
        PEAK_LIVE_BYTES.store(0, Ordering::Relaxed);
        COUNT_ALLOCATIONS.store(u64::from(track), Ordering::Relaxed);
    }

    fn snapshot() -> AllocationStats {
        AllocationStats {
            calls: ALLOC_CALLS.load(Ordering::Relaxed),
            allocated_bytes: ALLOCATED_BYTES.load(Ordering::Relaxed),
            peak_live_bytes: PEAK_LIVE_BYTES.load(Ordering::Relaxed),
        }
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            CountingAllocator::record_alloc(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            CountingAllocator::record_alloc(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        CountingAllocator::record_dealloc(layout.size());
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
        if !new_pointer.is_null() && COUNT_ALLOCATIONS.load(Ordering::Relaxed) != 0 {
            ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
            ALLOCATED_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
            if new_size >= layout.size() {
                let delta = (new_size - layout.size()) as u64;
                let live = LIVE_BYTES.fetch_add(delta, Ordering::Relaxed) + delta;
                PEAK_LIVE_BYTES.fetch_max(live, Ordering::Relaxed);
            } else {
                LIVE_BYTES.fetch_sub((layout.size() - new_size) as u64, Ordering::Relaxed);
            }
        }
        new_pointer
    }
}

#[derive(Clone, Copy)]
struct FnvHasher(u64);

impl FnvHasher {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
}

impl Default for FnvHasher {
    fn default() -> Self {
        Self(Self::OFFSET_BASIS)
    }
}

impl Hasher for FnvHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(Self::PRIME);
        }
    }
}

type FastBuildHasher = BuildHasherDefault<FxHasher>;

#[derive(Clone, Copy)]
struct SipBuildHasher {
    key0: u64,
    key1: u64,
}

impl Default for SipBuildHasher {
    fn default() -> Self {
        // A fixed seed makes repeated benchmark runs comparable. Production
        // code must choose an unpredictable per-driver seed instead.
        Self {
            key0: 0x6d_5a_4e_32_1f_09_c7_b3,
            key1: 0xa4_72_18_d0_5b_9e_63_2f,
        }
    }
}

impl BuildHasher for SipBuildHasher {
    type Hasher = SipHasher13;

    fn build_hasher(&self) -> Self::Hasher {
        SipHasher13::new_with_keys(self.key0, self.key1)
    }
}

fn hash_key<K: Hash>(key: &K) -> u64 {
    let mut hasher = FnvHasher::default();
    key.hash(&mut hasher);
    hasher.finish()
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct Key4 {
    local_ip: [u8; 4],
    local_port: u16,
    remote_ip: [u8; 4],
    remote_port: u16,
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct Key6 {
    local_ip: [u8; 16],
    local_port: u16,
    remote_ip: [u8; 16],
    remote_port: u16,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Counter {
    received_bytes: u64,
    transmitted_bytes: u64,
}

impl Counter {
    fn add(&mut self, outbound: bool, bytes: u64) {
        if outbound {
            self.transmitted_bytes += bytes;
        } else {
            self.received_bytes += bytes;
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Summary {
    entries: usize,
    received_bytes: u64,
    transmitted_bytes: u64,
    fingerprint: u64,
}

impl Summary {
    fn add<K: Hash>(&mut self, key: &K, counter: &Counter) {
        self.entries += 1;
        self.received_bytes += counter.received_bytes;
        self.transmitted_bytes += counter.transmitted_bytes;
        let key_hash = hash_key(key);
        let value_hash = counter
            .received_bytes
            .rotate_left(17)
            .wrapping_add(counter.transmitted_bytes.rotate_left(41));
        self.fingerprint = self.fingerprint.wrapping_add(
            key_hash
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add(value_hash),
        );
    }

    fn merge(&mut self, other: Summary) {
        self.entries += other.entries;
        self.received_bytes += other.received_bytes;
        self.transmitted_bytes += other.transmitted_bytes;
        self.fingerprint = self.fingerprint.wrapping_add(other.fingerprint);
    }
}

mod alternatives;
mod export;
mod parallel;
#[cfg(test)]
mod regressions;

static ORDERED_OUTPUT: AtomicU64 = AtomicU64::new(0);

trait StatsMap<K> {
    const SORTED: bool = false;
    fn len(&self) -> usize;
    fn into_pairs(self) -> impl Iterator<Item = (K, Counter)>;
    fn update(&mut self, key: K, outbound: bool, bytes: u64);
    fn snapshot(&self) -> Summary;
    fn capacity(&self) -> usize;
}

struct BTreeStore<K>(BTreeMap<K, Counter>);

impl<K> Default for BTreeStore<K> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl<K: Ord + Hash> StatsMap<K> for BTreeStore<K> {
    const SORTED: bool = true;
    fn len(&self) -> usize {
        self.0.len()
    }
    fn into_pairs(self) -> impl Iterator<Item = (K, Counter)> {
        self.0.into_iter()
    }
    fn update(&mut self, key: K, outbound: bool, bytes: u64) {
        self.0.entry(key).or_default().add(outbound, bytes);
    }

    fn snapshot(&self) -> Summary {
        let mut summary = Summary::default();
        for (key, counter) in &self.0 {
            summary.add(key, counter);
        }
        summary
    }

    fn capacity(&self) -> usize {
        self.0.len()
    }
}

struct HashBrownStore<K, S> {
    map: HashBrownMap<K, Counter, S>,
}

impl<K, S> Default for HashBrownStore<K, S>
where
    S: BuildHasher + Default,
{
    fn default() -> Self {
        Self {
            map: HashBrownMap::with_hasher(S::default()),
        }
    }
}

impl<K: Eq + Hash, S: BuildHasher> StatsMap<K> for HashBrownStore<K, S> {
    fn len(&self) -> usize {
        self.map.len()
    }
    fn into_pairs(self) -> impl Iterator<Item = (K, Counter)> {
        self.map.into_iter()
    }
    fn update(&mut self, key: K, outbound: bool, bytes: u64) {
        self.map.entry(key).or_default().add(outbound, bytes);
    }

    fn snapshot(&self) -> Summary {
        let mut summary = Summary::default();
        for (key, counter) in &self.map {
            summary.add(key, counter);
        }
        summary
    }

    fn capacity(&self) -> usize {
        self.map.capacity()
    }
}

struct OpenEntry<K> {
    key: K,
    counter: Counter,
}

struct OpenAddressMap<K> {
    slots: Vec<Option<OpenEntry<K>>>,
    len: usize,
}

impl<K> Default for OpenAddressMap<K> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            len: 0,
        }
    }
}

impl<K: Copy + Eq + Hash> OpenAddressMap<K> {
    fn empty_slots(capacity: usize) -> Vec<Option<OpenEntry<K>>> {
        std::iter::repeat_with(|| None).take(capacity).collect()
    }

    fn rehash(&mut self, capacity: usize) {
        debug_assert!(capacity.is_power_of_two());
        let old_slots = mem::replace(&mut self.slots, Self::empty_slots(capacity));
        self.len = 0;
        for entry in old_slots.into_iter().flatten() {
            self.insert_existing(entry);
        }
    }

    fn insert_existing(&mut self, entry: OpenEntry<K>) {
        let mask = self.slots.len() - 1;
        let mut index = (hash_key(&entry.key) as usize) & mask;
        loop {
            if self.slots[index].is_none() {
                self.slots[index] = Some(entry);
                self.len += 1;
                return;
            }
            index = (index + 1) & mask;
        }
    }
}

impl<K: Copy + Eq + Hash> StatsMap<K> for OpenAddressMap<K> {
    fn len(&self) -> usize {
        self.len
    }
    fn into_pairs(self) -> impl Iterator<Item = (K, Counter)> {
        self.slots
            .into_iter()
            .flatten()
            .map(|entry| (entry.key, entry.counter))
    }
    fn update(&mut self, key: K, outbound: bool, bytes: u64) {
        if self.slots.is_empty() {
            self.rehash(16);
        }
        let mask = self.slots.len() - 1;
        let mut index = (hash_key(&key) as usize) & mask;
        loop {
            if let Some(entry) = self.slots[index].as_mut() {
                if entry.key == key {
                    entry.counter.add(outbound, bytes);
                    return;
                }
            } else {
                if (self.len + 1) * 10 >= self.slots.len() * 7 {
                    self.rehash(self.slots.len() * 2);
                    self.update(key, outbound, bytes);
                    return;
                }
                self.slots[index] = Some(OpenEntry {
                    key,
                    counter: Counter {
                        received_bytes: 0,
                        transmitted_bytes: 0,
                    },
                });
                self.slots[index]
                    .as_mut()
                    .expect("new open-address slot")
                    .counter
                    .add(outbound, bytes);
                self.len += 1;
                return;
            }
            index = (index + 1) & mask;
        }
    }

    fn snapshot(&self) -> Summary {
        let mut summary = Summary::default();
        for entry in self.slots.iter().flatten() {
            summary.add(&entry.key, &entry.counter);
        }
        summary
    }

    fn capacity(&self) -> usize {
        self.slots.len()
    }
}

#[derive(Clone, Copy)]
enum Class {
    TcpV4,
    UdpV4,
    TcpV6,
    UdpV6,
}

impl Class {
    fn index(self) -> usize {
        match self {
            Self::TcpV4 => 0,
            Self::UdpV4 => 1,
            Self::TcpV6 => 2,
            Self::UdpV6 => 3,
        }
    }
}

#[derive(Clone, Copy)]
enum EventKey {
    V4(Key4),
    V6(Key6),
}

#[derive(Clone, Copy)]
struct Event {
    class: Class,
    key: EventKey,
    outbound: bool,
    bytes: u64,
}

struct FourMaps<M4, M6> {
    tcp_v4: M4,
    udp_v4: M4,
    tcp_v6: M6,
    udp_v6: M6,
}

impl<M4, M6> FourMaps<M4, M6>
where
    M4: Default + StatsMap<Key4>,
    M6: Default + StatsMap<Key6>,
{
    fn new() -> Self {
        Self {
            tcp_v4: M4::default(),
            udp_v4: M4::default(),
            tcp_v6: M6::default(),
            udp_v6: M6::default(),
        }
    }

    fn update(&mut self, event: &Event) {
        match (event.class, event.key) {
            (Class::TcpV4, EventKey::V4(key)) => {
                self.tcp_v4.update(key, event.outbound, event.bytes)
            }
            (Class::UdpV4, EventKey::V4(key)) => {
                self.udp_v4.update(key, event.outbound, event.bytes)
            }
            (Class::TcpV6, EventKey::V6(key)) => {
                self.tcp_v6.update(key, event.outbound, event.bytes)
            }
            (Class::UdpV6, EventKey::V6(key)) => {
                self.udp_v6.update(key, event.outbound, event.bytes)
            }
            _ => panic!("event address family does not match its map"),
        }
    }

    fn snapshot(&self) -> Summary {
        let mut summary = Summary::default();
        summary.merge(self.tcp_v4.snapshot());
        summary.merge(self.udp_v4.snapshot());
        summary.merge(self.tcp_v6.snapshot());
        summary.merge(self.udp_v6.snapshot());
        summary
    }

    fn capacity(&self) -> usize {
        self.tcp_v4.capacity()
            + self.udp_v4.capacity()
            + self.tcp_v6.capacity()
            + self.udp_v6.capacity()
    }

    fn drain_wire(self) -> Vec<Vec<u8>> {
        let mut packets = Vec::with_capacity(4);
        if let Some(packet) = export::serialize(self.tcp_v4, 6) {
            packets.push(packet);
        }
        if let Some(packet) = export::serialize(self.udp_v4, 17) {
            packets.push(packet);
        }
        if let Some(packet) = export::serialize(self.tcp_v6, 6) {
            packets.push(packet);
        }
        if let Some(packet) = export::serialize(self.udp_v6, 17) {
            packets.push(packet);
        }
        packets
    }
}

trait Candidate: Sized {
    fn new() -> Self;
    fn update(&mut self, event: &Event);
    fn snapshot(&self) -> Summary;
    fn capacity(&self) -> usize;
    fn drain_wire(self) -> Vec<Vec<u8>>;
}

impl<M4, M6> Candidate for FourMaps<M4, M6>
where
    M4: Default + StatsMap<Key4>,
    M6: Default + StatsMap<Key6>,
{
    fn new() -> Self {
        Self::new()
    }

    fn update(&mut self, event: &Event) {
        self.update(event);
    }

    fn snapshot(&self) -> Summary {
        self.snapshot()
    }

    fn capacity(&self) -> usize {
        self.capacity()
    }

    fn drain_wire(self) -> Vec<Vec<u8>> {
        self.drain_wire()
    }
}

type BTreeCandidate = FourMaps<BTreeStore<Key4>, BTreeStore<Key6>>;
type FastHashCandidate =
    FourMaps<HashBrownStore<Key4, FastBuildHasher>, HashBrownStore<Key6, FastBuildHasher>>;
type SipHashCandidate =
    FourMaps<HashBrownStore<Key4, SipBuildHasher>, HashBrownStore<Key6, SipBuildHasher>>;
type OpenCandidate = FourMaps<OpenAddressMap<Key4>, OpenAddressMap<Key6>>;
type SortedCandidate = FourMaps<alternatives::SortedStore<Key4>, alternatives::SortedStore<Key6>>;
type DenseCandidate = FourMaps<alternatives::DenseStore<Key4>, alternatives::DenseStore<Key6>>;

#[derive(Clone, Copy)]
struct AllocationStats {
    calls: u64,
    allocated_bytes: u64,
    peak_live_bytes: u64,
}

struct Sample {
    fill_ns: u128,
    drain_ns: u128,
    summary: Summary,
    capacity: usize,
    allocation: AllocationStats,
    rows: export::Rows,
}

#[derive(Clone, Copy)]
struct Measurement {
    fill_ns: u128,
    drain_ns: u128,
    capacity: usize,
    allocation_calls: u64,
    allocated_bytes: u64,
    peak_live_bytes: u64,
}

fn execute<C: Candidate>(events: &[Event], track_allocations: bool) -> Sample {
    CountingAllocator::reset(track_allocations);
    let fill_start = Instant::now();
    let mut candidate = C::new();
    for event in events {
        candidate.update(event);
    }
    let fill_ns = fill_start.elapsed().as_nanos();

    let summary = black_box(candidate.snapshot());
    let capacity = candidate.capacity();
    let drain_start = Instant::now();
    let packets = black_box(candidate.drain_wire());
    let drain_ns = drain_start.elapsed().as_nanos();
    let allocation = CountingAllocator::snapshot();
    let rows = if track_allocations {
        Vec::new()
    } else {
        export::decode(&packets)
    };
    drop(packets);
    COUNT_ALLOCATIONS.store(0, Ordering::Relaxed);
    assert_eq!(LIVE_BYTES.load(Ordering::Relaxed), 0);

    Sample {
        fill_ns,
        drain_ns,
        summary,
        capacity,
        allocation,
        rows,
    }
}

fn median_u128(values: &mut [u128]) -> u128 {
    values.sort_unstable();
    values[values.len() / 2]
}

fn benchmark<C: Candidate>(
    name: &str,
    events: &[Event],
    expected: Summary,
    runs: usize,
) -> Measurement {
    let expected_rows = export::reference(events);
    let warmup = execute::<C>(events, false);
    assert_eq!(
        warmup.rows, expected_rows,
        "warm-up per-key mismatch for {name}"
    );
    assert_eq!(
        warmup.summary, expected,
        "warm-up result mismatch for {name}"
    );

    let mut fill_times = Vec::with_capacity(runs);
    let mut snapshot_times = Vec::with_capacity(runs);
    let mut capacities = Vec::with_capacity(runs);

    for _ in 0..runs {
        let sample = execute::<C>(events, false);
        assert_eq!(sample.rows, expected_rows, "per-key mismatch for {name}");
        assert_eq!(sample.summary, expected, "result mismatch for {name}");
        fill_times.push(sample.fill_ns);
        snapshot_times.push(sample.drain_ns);
        capacities.push(sample.capacity);
    }

    let allocation_sample = execute::<C>(events, true);
    assert_eq!(
        allocation_sample.summary, expected,
        "allocation result mismatch for {name}"
    );
    let fill_ns = median_u128(&mut fill_times);
    let drain_ns = median_u128(&mut snapshot_times);
    let allocation_calls = allocation_sample.allocation.calls;
    let allocated_bytes = allocation_sample.allocation.allocated_bytes;
    let peak_live_bytes = allocation_sample.allocation.peak_live_bytes;
    capacities.sort_unstable();
    let capacity = capacities[capacities.len() / 2];

    let events_per_second = events.len() as f64 / (fill_ns as f64 / 1_000_000_000.0);
    println!(
        "RESULT name={name} fill_ms={:.3} updates_per_sec={:.0} drain_ms={:.3} slots_or_entries={capacity} alloc_calls={allocation_calls} allocated_mib={:.2} peak_live_mib={:.2}",
        fill_ns as f64 / 1_000_000.0,
        events_per_second,
        drain_ns as f64 / 1_000_000.0,
        allocated_bytes as f64 / 1_048_576.0,
        peak_live_bytes as f64 / 1_048_576.0,
    );

    Measurement {
        fill_ns,
        drain_ns,
        capacity,
        allocation_calls,
        allocated_bytes,
        peak_live_bytes,
    }
}

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 7;
        value ^= value >> 9;
        value ^= value << 8;
        self.0 = value;
        value
    }

    fn range(&mut self, upper: usize) -> usize {
        debug_assert!(upper > 0);
        (self.next_u64() % upper as u64) as usize
    }
}

fn local_v4(id: usize) -> [u8; 4] {
    match id % 4 {
        0 => [192, 168, 1, 100],
        1 => [10, 0, 2, 15],
        2 => [172, 16, 4, 20],
        _ => [192, 168, 50, 7],
    }
}

fn local_v6(id: usize) -> [u8; 16] {
    let mut address = [0u8; 16];
    address[0..4].copy_from_slice(&[0xfd, 0x00, 0x00, 0x01]);
    address[15] = (id % 4) as u8 + 1;
    address
}

fn remote_port(tcp: bool, rng: &mut Rng) -> u16 {
    let roll = rng.range(100);
    if tcp {
        match roll {
            0..=59 => 443,
            60..=79 => 80,
            80..=89 => 8443,
            _ => 1024 + rng.range(64511) as u16,
        }
    } else {
        match roll {
            0..=34 => 443,
            35..=64 => 53,
            65..=74 => 123,
            _ => 1024 + rng.range(64511) as u16,
        }
    }
}

fn make_v4_key(id: usize, tcp: bool, rng: &mut Rng) -> Key4 {
    let mut remote_ip = [0u8; 4];
    remote_ip[0] = 198;
    remote_ip[1] = 18 + ((id >> 16) & 0xff) as u8;
    remote_ip[2] = (id >> 8) as u8;
    remote_ip[3] = id as u8;
    Key4 {
        local_ip: local_v4(id),
        local_port: 32768 + (id % 28232) as u16,
        remote_ip,
        remote_port: remote_port(tcp, rng),
    }
}

fn make_v6_key(id: usize, tcp: bool, rng: &mut Rng) -> Key6 {
    let mut remote_ip = [0u8; 16];
    remote_ip[0..8].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1]);
    remote_ip[8] = (id >> 24) as u8;
    remote_ip[9] = (id >> 16) as u8;
    remote_ip[10] = (id >> 8) as u8;
    remote_ip[11] = id as u8;
    remote_ip[15] = (id % 251) as u8;
    Key6 {
        local_ip: local_v6(id),
        local_port: 32768 + (id % 28232) as u16,
        remote_ip,
        remote_port: remote_port(tcp, rng),
    }
}

fn payload_size(rng: &mut Rng) -> u64 {
    match rng.range(100) {
        0..=54 => 64 + rng.range(449) as u64,
        55..=94 => 513 + rng.range(988) as u64,
        _ => 1501 + rng.range(64_035) as u64,
    }
}

fn make_event(id: usize, class: Class, rng: &mut Rng) -> Event {
    let tcp = matches!(class, Class::TcpV4 | Class::TcpV6);
    let key = match class {
        Class::TcpV4 | Class::UdpV4 => EventKey::V4(make_v4_key(id, tcp, rng)),
        Class::TcpV6 | Class::UdpV6 => EventKey::V6(make_v6_key(id, tcp, rng)),
    };
    Event {
        class,
        key,
        outbound: rng.range(100) < 68,
        bytes: payload_size(rng).min(if tcp { 65_535 } else { 1_400 }),
    }
}

fn class_for(rng: &mut Rng) -> Class {
    match rng.range(100) {
        0..=54 => Class::TcpV4,
        55..=79 => Class::UdpV4,
        80..=94 => Class::TcpV6,
        _ => Class::UdpV6,
    }
}

fn generate_workload(event_count: usize, unique_count: usize, seed: u64) -> Vec<Event> {
    assert!(unique_count > 0);
    assert!(unique_count <= event_count);
    let mut rng = Rng::new(seed);
    let mut unique_events = Vec::with_capacity(unique_count);
    for id in 0..unique_count {
        unique_events.push(make_event(id, class_for(&mut rng), &mut rng));
    }

    let mut events = unique_events.clone();
    let hot_count = unique_count.max(10) / 10;
    for _ in unique_count..event_count {
        let source = if rng.range(100) < 70 {
            rng.range(hot_count.min(unique_count))
        } else {
            rng.range(unique_count)
        };
        let template = unique_events[source];
        events.push(Event {
            class: template.class,
            key: template.key,
            outbound: rng.range(100) < 68,
            bytes: payload_size(&mut rng).min(
                if matches!(template.class, Class::TcpV4 | Class::TcpV6) {
                    65_535
                } else {
                    1_400
                },
            ),
        });
    }
    drop(unique_events);

    for index in (1..events.len()).rev() {
        let other = rng.range(index + 1);
        events.swap(index, other);
    }
    events
}

fn distribution(events: &[Event]) -> [usize; 4] {
    let mut counts = [0; 4];
    for event in events {
        counts[event.class.index()] += 1;
    }
    counts
}

fn class_name(index: usize) -> &'static str {
    match index {
        0 => "tcp-v4",
        1 => "udp-v4",
        2 => "tcp-v6",
        3 => "udp-v6",
        _ => unreachable!(),
    }
}

fn expected_summary(events: &[Event]) -> Summary {
    let mut reference = BTreeCandidate::new();
    for event in events {
        reference.update(event);
    }
    reference.snapshot()
}

#[derive(Clone, Copy)]
struct Config {
    events: usize,
    unique: usize,
    runs: usize,
    seed: u64,
}

fn parse_usize(args: &[String], name: &str, default: usize) -> usize {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| {
            pair[1]
                .parse()
                .unwrap_or_else(|_| panic!("invalid value for {name}: {}", pair[1]))
        })
        .unwrap_or(default)
}

fn parse_u64(args: &[String], name: &str, default: u64) -> u64 {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| {
            if let Some(hex) = pair[1].strip_prefix("0x") {
                u64::from_str_radix(hex, 16)
                    .unwrap_or_else(|_| panic!("invalid hexadecimal value for {name}"))
            } else {
                pair[1]
                    .parse()
                    .unwrap_or_else(|_| panic!("invalid value for {name}: {}", pair[1]))
            }
        })
        .unwrap_or(default)
}

fn print_help() {
    println!("Usage: traffic-stats-bench [--events N] [--unique N] [--runs N] [--seed N]\n\n");
    println!(
        "Defaults: --events {DEFAULT_EVENT_COUNT} --unique {DEFAULT_UNIQUE_COUNT} --runs {DEFAULT_RUNS}"
    );
    println!(
        "The workload contains unique connection keys plus repeat packet updates; all candidates receive the same shuffled events."
    );
    println!("Options: --ordered-output --reverse-order --parallel [--threads N] [--shards N]");
    println!("Parallel mode additionally compares user-mode spinlocks, not kernel IRQL latency.");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return;
    }

    let config = Config {
        events: parse_usize(&args, "--events", DEFAULT_EVENT_COUNT),
        unique: parse_usize(&args, "--unique", DEFAULT_UNIQUE_COUNT),
        runs: parse_usize(&args, "--runs", DEFAULT_RUNS),
        seed: parse_u64(&args, "--seed", WORKLOAD_SEED),
    };
    assert!(config.events > 0);
    assert!(config.unique > 0 && config.unique <= config.events);
    assert!(config.runs > 0);

    println!(
        "traffic-stats-bench events={} unique_keys={} repeat_updates={} runs={} seed=0x{:x}",
        config.events,
        config.unique,
        config.events - config.unique,
        config.runs,
        config.seed
    );
    println!(
        "key sizes: v4={} bytes v6={} bytes counter={} bytes",
        std::mem::size_of::<Key4>(),
        std::mem::size_of::<Key6>(),
        std::mem::size_of::<Counter>()
    );

    let events = generate_workload(config.events, config.unique, config.seed);
    let counts = distribution(&events);
    println!(
        "event distribution: {}={} {}={} {}={} {}={}",
        class_name(0),
        counts[0],
        class_name(1),
        counts[1],
        class_name(2),
        counts[2],
        class_name(3),
        counts[3]
    );
    let expected = expected_summary(&events);
    println!(
        "reference: entries={} received_bytes={} transmitted_bytes={} fingerprint=0x{:016x}",
        expected.entries, expected.received_bytes, expected.transmitted_bytes, expected.fingerprint
    );

    ORDERED_OUTPUT.store(
        u64::from(args.iter().any(|arg| arg == "--ordered-output")),
        Ordering::Relaxed,
    );
    println!(
        "ordered_output={} allocation_tracking=separate_pass",
        ORDERED_OUTPUT.load(Ordering::Relaxed)
    );
    let mut results = Vec::new();
    macro_rules! run_candidate {
        ($name:expr, $candidate:ty) => {
            results.push((
                $name,
                benchmark::<$candidate>($name, &events, expected, config.runs),
            ));
        };
    }
    if args.iter().any(|arg| arg == "--reverse-order") {
        if config.unique <= 65_536 {
            run_candidate!("sorted-vec", SortedCandidate);
        }
        run_candidate!("dense-index-fx", DenseCandidate);
        run_candidate!("open-address-fnv", OpenCandidate);
        run_candidate!("hashbrown-sip13", SipHashCandidate);
        run_candidate!("hashbrown-fx", FastHashCandidate);
        run_candidate!("btree", BTreeCandidate);
    } else {
        run_candidate!("btree", BTreeCandidate);
        run_candidate!("hashbrown-fx", FastHashCandidate);
        run_candidate!("hashbrown-sip13", SipHashCandidate);
        run_candidate!("open-address-fnv", OpenCandidate);
        run_candidate!("dense-index-fx", DenseCandidate);
        if config.unique <= 65_536 {
            run_candidate!("sorted-vec", SortedCandidate);
        }
    }
    if config.unique > 65_536 {
        println!("SKIP name=sorted-vec reason=quadratic_insertion_above_65536_keys");
    }
    if args.iter().any(|arg| arg == "--parallel") {
        let threads = parse_usize(&args, "--threads", 4);
        let shards = parse_usize(&args, "--shards", 1);
        parallel::benchmark(&events, config.runs, threads, shards);
    }

    println!("SUMMARY median fill time (lower is better):");
    for (name, measurement) in &results {
        print_summary_line(name, *measurement, events.len());
    }
    let fastest = results
        .iter()
        .min_by_key(|(_, measurement)| measurement.fill_ns)
        .expect("candidate list is not empty");
    println!(
        "winner_by_fill={} (fast hash candidates require collision-hardening before kernel use)",
        fastest.0
    );
}

fn print_summary_line(name: &str, measurement: Measurement, event_count: usize) {
    println!(
        "  {name:<18} fill={:>9.3} ms ({:>12.0}/s) drain={:>8.3} ms slots={:>9} allocs={:>8} alloc_mib={:>8.2} peak_mib={:>8.2}",
        measurement.fill_ns as f64 / 1_000_000.0,
        event_count as f64 / (measurement.fill_ns as f64 / 1_000_000_000.0),
        measurement.drain_ns as f64 / 1_000_000.0,
        measurement.capacity,
        measurement.allocation_calls,
        measurement.allocated_bytes as f64 / 1_048_576.0,
        measurement.peak_live_bytes as f64 / 1_048_576.0,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_address_map_matches_btree_for_repeated_updates() {
        let mut open = OpenAddressMap::<Key4>::default();
        let mut btree: BTreeMap<Key4, Counter> = BTreeMap::new();
        let mut rng = Rng::new(0x1234_5678);

        for id in 0..10_000 {
            let key = make_v4_key(id % 1_000, id % 2 == 0, &mut rng);
            let outbound = id % 3 != 0;
            let bytes = (id * 17 + 31) as u64;
            open.update(key, outbound, bytes);
            btree.entry(key).or_default().add(outbound, bytes);
        }

        let mut expected = Summary::default();
        for (key, counter) in &btree {
            expected.add(key, counter);
        }
        assert_eq!(open.snapshot(), expected);
        assert_eq!(open.len, btree.len());
        assert!(open.capacity() >= open.len);
    }

    #[test]
    fn generated_workload_has_requested_shape() {
        let events = generate_workload(10_000, 7_000, WORKLOAD_SEED);
        assert_eq!(events.len(), 10_000);
        let summary = expected_summary(&events);
        assert_eq!(summary.entries, 7_000);
    }
}
