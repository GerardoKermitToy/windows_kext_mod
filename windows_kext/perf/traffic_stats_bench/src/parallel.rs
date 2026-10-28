use super::*;
use std::cell::UnsafeCell;
use std::sync::{atomic::AtomicBool, Barrier};

struct Spin<T> {
    held: AtomicBool,
    value: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for Spin<T> {}
unsafe impl<T: Send> Sync for Spin<T> {}

impl<T: Default> Default for Spin<T> {
    fn default() -> Self {
        Self {
            held: AtomicBool::new(false),
            value: UnsafeCell::new(T::default()),
        }
    }
}

impl<T> Spin<T> {
    fn with<R>(&self, action: impl FnOnce(&mut T) -> R) -> R {
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.held.load(Ordering::Relaxed) {
                std::hint::spin_loop();
            }
        }
        struct Unlock<'a>(&'a AtomicBool);
        impl Drop for Unlock<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _unlock = Unlock(&self.held);
        // The acquired flag grants unique access; RAII releases it even if
        // the closure panics. No borrow of the value escapes the closure.
        action(unsafe { &mut *self.value.get() })
    }
    fn into_inner(self) -> T {
        self.value.into_inner()
    }
}

struct Shared<M4, M6> {
    v4: Vec<Spin<M4>>,
    v6: Vec<Spin<M6>>,
    shards: usize,
}

impl<M4: Default + StatsMap<Key4>, M6: Default + StatsMap<Key6>> Shared<M4, M6> {
    fn new(shards: usize) -> Self {
        assert!(shards.is_power_of_two());
        Self {
            v4: (0..2 * shards).map(|_| Spin::default()).collect(),
            v6: (0..2 * shards).map(|_| Spin::default()).collect(),
            shards,
        }
    }
    fn update(&self, event: &Event) {
        let udp = matches!(event.class, Class::UdpV4 | Class::UdpV6);
        let protocol_offset = usize::from(udp) * self.shards;
        match event.key {
            EventKey::V4(key) => {
                let shard = if self.shards == 1 {
                    0
                } else {
                    FastBuildHasher::default().hash_one(key) as usize & (self.shards - 1)
                };
                self.v4[protocol_offset + shard]
                    .with(|map| map.update(key, event.outbound, event.bytes));
            }
            EventKey::V6(key) => {
                let shard = if self.shards == 1 {
                    0
                } else {
                    FastBuildHasher::default().hash_one(key) as usize & (self.shards - 1)
                };
                self.v6[protocol_offset + shard]
                    .with(|map| map.update(key, event.outbound, event.bytes));
            }
        }
    }
    fn drain(self) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        for (index, map) in self.v4.into_iter().enumerate() {
            if let Some(packet) =
                export::serialize(map.into_inner(), if index < self.shards { 6 } else { 17 })
            {
                packets.push(packet);
            }
        }
        for (index, map) in self.v6.into_iter().enumerate() {
            if let Some(packet) =
                export::serialize(map.into_inner(), if index < self.shards { 6 } else { 17 })
            {
                packets.push(packet);
            }
        }
        packets
    }
}

fn run<M4, M6>(events: &[Event], threads: usize, shards: usize) -> (u128, export::Rows)
where
    M4: Default + StatsMap<Key4> + Send,
    M6: Default + StatsMap<Key6> + Send,
{
    let shared = Shared::<M4, M6>::new(shards);
    let ready = Barrier::new(threads + 1);
    let go = Barrier::new(threads + 1);
    let done = Barrier::new(threads + 1);
    let elapsed = std::thread::scope(|scope| {
        for worker in 0..threads {
            let shared = &shared;
            let ready = &ready;
            let go = &go;
            let done = &done;
            let from = worker * events.len() / threads;
            let to = (worker + 1) * events.len() / threads;
            let events = &events[from..to];
            scope.spawn(move || {
                ready.wait();
                go.wait();
                for event in events {
                    shared.update(event);
                }
                done.wait();
            });
        }
        ready.wait();
        let start = Instant::now();
        go.wait();
        done.wait();
        start.elapsed().as_nanos()
    });
    (elapsed, export::decode(&shared.drain()))
}

fn measure<M4, M6>(
    name: &str,
    events: &[Event],
    expected: &export::Rows,
    runs: usize,
    threads: usize,
    shards: usize,
) where
    M4: Default + StatsMap<Key4> + Send,
    M6: Default + StatsMap<Key6> + Send,
{
    assert_eq!(&run::<M4, M6>(events, threads, shards).1, expected);
    let mut samples = Vec::with_capacity(runs);
    for _ in 0..runs {
        let (elapsed, rows) = run::<M4, M6>(events, threads, shards);
        assert_eq!(&rows, expected);
        samples.push(elapsed);
    }
    let min = *samples.iter().min().unwrap();
    let max = *samples.iter().max().unwrap();
    let median = median_u128(&mut samples);
    println!("PARALLEL name={name} threads={threads} shards_per_class={shards} fill_ms={:.3} min_ms={:.3} max_ms={:.3} updates_per_sec={:.0}",
        median as f64 / 1e6, min as f64 / 1e6, max as f64 / 1e6, events.len() as f64 * 1e9 / median as f64);
}

pub(super) fn benchmark(events: &[Event], runs: usize, threads: usize, shards: usize) {
    assert!(threads > 0 && threads <= 64);
    assert!(shards.is_power_of_two() && shards <= 256);
    println!(
        "MODEL user_mode_spinlocks=true kernel_IRQL=false events={} threads={} shards_per_class={}",
        events.len(),
        threads,
        shards
    );
    let expected = export::reference(events);
    measure::<BTreeStore<Key4>, BTreeStore<Key6>>(
        "btree", events, &expected, runs, threads, shards,
    );
    measure::<HashBrownStore<Key4, FastBuildHasher>, HashBrownStore<Key6, FastBuildHasher>>(
        "hashbrown-fx",
        events,
        &expected,
        runs,
        threads,
        shards,
    );
    measure::<HashBrownStore<Key4, SipBuildHasher>, HashBrownStore<Key6, SipBuildHasher>>(
        "hashbrown-sip13",
        events,
        &expected,
        runs,
        threads,
        shards,
    );
}

#[test]
fn concurrent_updates_preserve_every_key_and_direction() {
    let events = generate_workload(10_000, 200, WORKLOAD_SEED);
    let expected = export::reference(&events);
    for shards in [1, 4] {
        assert_eq!(
            run::<BTreeStore<Key4>, BTreeStore<Key6>>(&events, 4, shards).1,
            expected
        );
        assert_eq!(
            run::<HashBrownStore<Key4, FastBuildHasher>, HashBrownStore<Key6, FastBuildHasher>>(
                &events, 4, shards
            )
            .1,
            expected
        );
        assert_eq!(
            run::<HashBrownStore<Key4, SipBuildHasher>, HashBrownStore<Key6, SipBuildHasher>>(
                &events, 4, shards
            )
            .1,
            expected
        );
    }
}
