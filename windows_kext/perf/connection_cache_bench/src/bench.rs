use crate::allocations::{self, Stats};
use crate::connection::{Connection, ConnectionV4, ConnectionV6, Direction};
use crate::connection_map::Key;
use crate::workload::{
    snapshot, Family, PacketInfo, Query, Shape, Workload, CONNECTIONS, HITS, REQUESTS, SEED,
};
use smoltcp::wire::IpProtocol;
use std::{
    env,
    fs::{self, File},
    hint::black_box,
    io::{BufWriter, Write},
    time::Instant,
};

trait Cache<T: Family>: Sized {
    fn new() -> Self;
    fn insert(&mut self, connection: T);
    fn lookup(&self, key: &Key, direction: Direction) -> Option<PacketInfo>;
    fn count(&self) -> usize;
    fn live_instance(&self, key: &Key, instance: u64) -> bool;
    fn end_port(&mut self, port: (IpProtocol, u16)) -> usize;
    fn clean(&mut self);
}

macro_rules! cache {
    ($module:ident) => {
        impl<T: Family<RemoteAddressKey: std::hash::Hash>> Cache<T>
            for crate::$module::ConnectionMap<T>
        {
            fn new() -> Self {
                Self::new()
            }
            fn insert(&mut self, connection: T) {
                assert!(self.insert_if_absent_with(connection, |_| {}).is_ok());
            }
            fn lookup(&self, key: &Key, direction: Direction) -> Option<PacketInfo> {
                self.read_for_packet(key, direction, snapshot::<T>)
            }
            fn count(&self) -> usize {
                self.get_count()
            }
            fn live_instance(&self, key: &Key, instance: u64) -> bool {
                self.has_live_instance(key, instance)
            }
            fn end_port(&mut self, port: (IpProtocol, u16)) -> usize {
                self.end_all_on_endpoint(port, None, None)
                    .map_or(0, |ended| ended.len())
            }
            fn clean(&mut self) {
                self.clean_ended_connections();
            }
        }
    };
}
cache!(connection_map);
cache!(hash_tree);
cache!(tree_hash);
cache!(hash_hash);
cache!(directory_tree);
cache!(tree_tree);
cache!(sip_sip);
cache!(directory_sip);

const VARIANTS: [&str; 8] = [
    "btree-btree",
    "fx-btree",
    "btree-fx",
    "fx-fx",
    "directory-btree",
    "directory-fx",
    "sip-sip",
    "directory-sip",
];

#[derive(Default)]
struct Measurement {
    insert_ns: u128,
    lookup_ns: u128,
    instance_ns: u128,
    end_ns: u128,
    cleanup_ns: u128,
    allocation: Option<Stats>,
    empty_bytes: usize,
}

fn populate<T: Family, M: Cache<T>>(workload: &Workload<T>, aged: bool) -> M {
    let mut map = M::new();
    for connection in &workload.connections {
        let mut connection = connection.clone();
        if aged {
            connection.end(1);
        }
        map.insert(connection);
    }
    map
}

#[inline(never)]
fn lookups<T: Family, M: Cache<T>>(map: &M, queries: &[Query]) -> (usize, u64) {
    let map = black_box(map);
    let queries = black_box(queries);
    let mut found = 0;
    let mut checksum = 0u64;
    for query in queries {
        if let Some(info) = map.lookup(&query.key, query.direction) {
            found += 1;
            checksum = checksum.wrapping_add(info.checksum());
        }
    }
    black_box((found, checksum))
}

fn measure<T: Family, M: Cache<T>>(workload: &Workload<T>, memory: bool) -> Measurement {
    let start = Instant::now();
    let mut map: M = populate(workload, false);
    let insert_ns = start.elapsed().as_nanos();
    assert_eq!(map.count(), CONNECTIONS);

    // Full untimed validation also warms this candidate. Compare all four packet
    // metadata fields, not merely the number of hits or a weak checksum.
    for (query, expected) in workload.queries.iter().zip(&workload.expected) {
        assert_eq!(map.lookup(&query.key, query.direction), *expected);
    }
    let start = Instant::now();
    let (found, checksum) = lookups(&map, &workload.queries);
    let lookup_ns = start.elapsed().as_nanos();
    assert_eq!(found, HITS);
    assert_eq!(checksum, workload.checksum);

    // A separate exact-generation operation used by lifecycle/verdict paths.
    let start = Instant::now();
    let mut live = 0;
    for connection in black_box(&workload.connections) {
        live += usize::from(map.live_instance(&connection.get_key(), connection.get_instance_id()));
    }
    let instance_ns = start.elapsed().as_nanos();
    assert_eq!(black_box(live), CONNECTIONS);

    let start = Instant::now();
    let mut ended = 0;
    for &port in &workload.ports {
        ended += map.end_port(port);
    }
    let end_ns = start.elapsed().as_nanos();
    assert_eq!(ended, CONNECTIONS);
    for connection in &workload.connections {
        assert!(map
            .lookup(&connection.get_key(), Direction::Inbound)
            .is_none());
        assert_eq!(
            map.lookup(&connection.get_key(), Direction::Outbound),
            snapshot(connection)
        );
    }
    drop(map);

    // The production test clock is fixed. Age a separate cache explicitly so the
    // real grace-period cleanup removes every record rather than timing a no-op.
    let mut old: M = populate(workload, true);
    let start = Instant::now();
    old.clean();
    let cleanup_ns = start.elapsed().as_nanos();
    assert_eq!(old.count(), 0);
    drop(old);

    let mut result = Measurement {
        insert_ns,
        lookup_ns,
        instance_ns,
        end_ns,
        cleanup_ns,
        ..Default::default()
    };
    if memory {
        // Allocation instrumentation is a separate pass: never time allocations
        // while counting. Workload buffers are created before tracking starts.
        allocations::start();
        let map: M = populate(workload, false);
        let before = allocations::snapshot();
        assert_eq!(lookups(&map, &workload.queries), (HITS, workload.checksum));
        let after = allocations::snapshot();
        assert_eq!(before.calls, after.calls, "packet lookup must not allocate");
        assert_eq!(before.live, after.live);
        result.allocation = Some(after);
        drop(map);
        allocations::finish();

        allocations::start();
        let mut old: M = populate(workload, true);
        old.clean();
        assert_eq!(old.count(), 0);
        result.empty_bytes = allocations::snapshot().live;
        drop(old);
        allocations::finish();
    }
    result
}

fn dispatch<T: Family<RemoteAddressKey: std::hash::Hash>>(
    variant: usize,
    workload: &Workload<T>,
    memory: bool,
) -> Measurement {
    match variant {
        0 => measure::<T, crate::tree_tree::ConnectionMap<T>>(workload, memory),
        1 => measure::<T, crate::hash_tree::ConnectionMap<T>>(workload, memory),
        2 => measure::<T, crate::tree_hash::ConnectionMap<T>>(workload, memory),
        3 => measure::<T, crate::hash_hash::ConnectionMap<T>>(workload, memory),
        4 => measure::<T, crate::directory_tree::ConnectionMap<T>>(workload, memory),
        5 => measure::<T, crate::connection_map::ConnectionMap<T>>(workload, memory),
        6 => measure::<T, crate::sip_sip::ConnectionMap<T>>(workload, memory),
        7 => measure::<T, crate::directory_sip::ConnectionMap<T>>(workload, memory),
        _ => unreachable!(),
    }
}

fn scenario<T: Family<RemoteAddressKey: std::hash::Hash>>(
    shape: Shape,
    burst: bool,
    rounds: usize,
    output: &mut impl Write,
) {
    let workload = Workload::<T>::new(shape, burst);
    println!(
        "{}: {} entries, {} local-port groups, {} queries, {} hits",
        workload.name,
        CONNECTIONS,
        workload.ports.len(),
        REQUESTS,
        HITS
    );
    for round in 0..rounds {
        // Rotate candidates across rounds to reduce fixed-order thermal/frequency
        // bias. Each candidate gets its own equally validated/warmed cache.
        for step in 0..VARIANTS.len() {
            let variant = (step + round) % VARIANTS.len();
            let m = dispatch(variant, &workload, round == 0);
            let stats = m.allocation.unwrap_or_default();
            writeln!(output,
                "{{\"scenario\":\"{}\",\"variant\":\"{}\",\"round\":{},\"entries\":{},\"queries\":{},\"hits\":{},\"lookup_ns\":{},\"insert_ns\":{},\"instance_ns\":{},\"end_ns\":{},\"cleanup_ns\":{},\"memory_measured\":{},\"live_bytes\":{},\"peak_bytes\":{},\"alloc_calls\":{},\"empty_bytes\":{},\"checksum\":{}}}",
                workload.name, VARIANTS[variant], round + 1, CONNECTIONS, REQUESTS, HITS,
                m.lookup_ns, m.insert_ns, m.instance_ns, m.end_ns, m.cleanup_ns,
                m.allocation.is_some(), stats.live, stats.peak, stats.calls, m.empty_bytes, workload.checksum,
            ).unwrap();
            output.flush().unwrap();
            println!(
                "  round {:2} {:17} {:8.2} ns/lookup ({:7.2} ms / million)",
                round + 1,
                VARIANTS[variant],
                m.lookup_ns as f64 / REQUESTS as f64,
                m.lookup_ns as f64 / 1e6
            );
        }
    }
}

#[cfg(windows)]
fn pin_cpu() -> usize {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> isize;
        fn SetProcessAffinityMask(process: isize, mask: usize) -> i32;
        fn GetProcessAffinityMask(
            process: isize,
            process_mask: *mut usize,
            system_mask: *mut usize,
        ) -> i32;
    }
    let cpu: u32 = env::var("CC_BENCH_CPU")
        .unwrap_or_else(|_| "2".into())
        .parse()
        .unwrap();
    let requested = 1usize
        .checked_shl(cpu)
        .expect("CPU index fits affinity mask");
    let mut allowed = 0usize;
    let mut system = 0usize;
    // SAFETY: pseudo-handle names this process; out-pointers are writable locals.
    unsafe {
        let process = GetCurrentProcess();
        assert_ne!(
            GetProcessAffinityMask(process, &mut allowed, &mut system),
            0
        );
        assert_ne!(allowed & requested, 0, "requested CPU is not allowed");
        assert_ne!(SetProcessAffinityMask(process, requested), 0);
    }
    requested
}

#[cfg(not(windows))]
fn pin_cpu() -> usize {
    0
}

#[test]
#[ignore = "long-running release microbenchmark; see README.md"]
fn benchmark_connection_lookup() {
    assert!(!cfg!(debug_assertions), "use cargo test --release");
    let rounds: usize = env::var("CC_BENCH_ROUNDS")
        .unwrap_or_else(|_| "9".into())
        .parse()
        .unwrap();
    assert!(rounds >= 3);
    let output_dir = env::var("CC_BENCH_OUT").expect("set CC_BENCH_OUT to a new result directory");
    fs::create_dir_all(&output_dir).unwrap();
    // Refuse to overwrite the evidence of an earlier benchmark.
    let path = std::path::Path::new(&output_dir).join("samples.jsonl");
    let file = File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    let mut output = BufWriter::new(file);
    let affinity = pin_cpu();
    println!("seed={SEED:#018x}; rounds={rounds}; process_affinity={affinity:#x}; Key={} bytes; Query={} bytes; ConnectionV4={} bytes; ConnectionV6={} bytes",
        std::mem::size_of::<Key>(), std::mem::size_of::<Query>(), std::mem::size_of::<ConnectionV4>(), std::mem::size_of::<ConnectionV6>());
    let filter = env::var("CC_BENCH_FILTER").unwrap_or_default();
    for shape in [Shape::Client, Shape::Listener, Shape::Mixed] {
        for burst in [false, true] {
            // Locality sensitivity is checked on the mixed topology in addition
            // to the three uniformly shuffled primary workloads.
            if burst && !matches!(shape, Shape::Mixed) {
                continue;
            }
            for family in ["v4", "v6"] {
                let name = format!(
                    "{family}-{}-{}",
                    shape.name(),
                    if burst { "burst" } else { "uniform" }
                );
                if !filter.is_empty() && !name.contains(&filter) {
                    continue;
                }
                if family == "v4" {
                    scenario::<ConnectionV4>(shape, burst, rounds, &mut output);
                } else {
                    scenario::<ConnectionV6>(shape, burst, rounds, &mut output);
                }
            }
        }
    }
}
