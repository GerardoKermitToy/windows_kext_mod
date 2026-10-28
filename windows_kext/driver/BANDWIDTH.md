# Traffic statistics storage

## Container and key

`src/bandwidth.rs` stores four independent classes: TCP/IPv4, TCP/IPv6,
UDP/IPv4 and UDP/IPv6. Each class contains 16 shards of
`RwSpinLock<hashbrown::HashMap<Key<Address>, Value, BuildHasherDefault<FxHasher>>>`.
The implementation uses `hashbrown 0.15.5` and `rustc-hash 2.1.1` with default
features disabled, compatible with `no_std` + `alloc`.

The key is the full `(local_ip, local_port, remote_ip, remote_port)` tuple.
The class determines the protocol and address family. The value contains
separate `u64` RX/TX counters. Every key field participates in `Hash` and `Eq`:
hash collisions never merge different tuples. As before, reuse of the same
tuple within an interval is aggregated; PID and connection generations are
not part of the key.

## Sharding

The shard is selected deterministically from bits 32..35 of the full key's
FxHash. These are neither the table's low bucket-index bits nor its top
seven-bit tags. The same tuple always reaches the same shard, so an update
acquires only one exclusive lock, calls `entry(key).or_default()` and
increments the appropriate counter.

There are 64 independent maps in total. A hot connection still serializes its
own updates, but usually does not block other shards. Sixteen is a starting
point selected from the earlier synthetic comparison, not a universal optimum.
Fixed FxHash was explicitly selected for throughput: it **does not provide**
protection against deliberately crafted collisions or concentration of keys
in a single shard.

## GetBandwidthStats and memory lifetime

For each class separately:

1. Acquire all 16 exclusive locks in ascending shard order.
2. Replace each map using `mem::take` with an empty map of **zero capacity**.
   This only transfers ownership: it does not allocate, traverse entries or
   free memory.
3. Release the locks in reverse order. This is required for nested Windows
   spinlocks: restore the saved raised IRQL first and the caller's original
   IRQL last.
4. Traverse the detached maps directly. `Snapshot` implements
   `ExactSizeIterator`, so the serializer immediately allocates a wire buffer
   of the required size. There is no intermediate `Vec` containing a second
   copy of every tuple/counter record.
5. Free consumed maps and their bucket/control allocations outside the locks;
   then pass the returned `Info` to the existing event queue.

The snapshot boundary is coherent across one entire class; the four classes
are still drained sequentially rather than in one global transaction. An
update completed before detachment belongs to the old snapshot; a later
update belongs to the new map. Concurrent requests may split events across
responses, but must neither lose nor duplicate them. Row order is now
unspecified; the `BandwidthStatsV4/V6` layout, count and directional counters
are unchanged.

`get_entries_counts()` acquires shared locks in the same class/shard order,
retains a coherent diagnostic snapshot, and releases the guards in reverse
order. This is not the per-packet update path.

### Selected memory policy

As required for this implementation:

- There is **no** entry or byte limit.
- There is no eviction, TTL, sampling, overflow aggregation or rejection of
  new tuples.
- OOM is outside the model.
- There is no initial reservation, permanent pool or retained high-water
  capacity.
- Repeated updates to an existing tuple do not create new entries.
- New tuples cause ordinary dynamic growth only in their own shard.
- After a drain, old large tables are not retained for the next interval.
- New entries after the snapshot may allocate again: these are live data,
  not a leak from the previous interval.

This is a policy of **releasing memory between intervals**, not a hard upper
bound. If userspace does not request statistics, memory grows with the number
of unique tuples. If userspace requests statistics but does not read the
responses, memory may instead accumulate in the event queue. Userspace remains
responsible for both regular requests and reads. A wire buffer is freed after
it is consumed by the existing read/fragment path or the queue is cleared
during shutdown. A request alone cannot free an undelivered result without
losing statistics.

During serialization, a detached snapshot, the wire buffer being built, and
maps for the new interval may coexist. The change eliminates retention of
old capacity after processing, not this necessary transient high-water mark.
Map growth/reallocation on insertion still occurs under the shard write lock;
this change does not promise an allocation-free update path or kernel p99
latency bounds.

## Verification

Unit tests exercise the same map, routing, snapshot and wire-serialization
code; only the WDK spinlock is replaced with `std::sync::RwLock` for user-mode
execution. Coverage includes:

- All four classes and both directions, including values above `u32::MAX`.
- Distinguishing every full-key field and deliberately identical hashes.
- Distribution across all shards and an exact snapshot remaining count.
- Empty drains, interval separation and partial snapshot consumption.
- Reverse-order guard release.
- Repeated growth/drain cycles and zero capacity in all 64 maps.
- 1,000,000 distinct records (250,000 per class), with exact wire decoding of
  every tuple.
- Four writers, two concurrent drainers and diagnostic snapshots, with exact
  per-key totals compared against an independent BTreeMap model.

From `windows_kext/driver`:

```bash
RUSTFLAGS="" cargo test --release
```

These tests do not replace verification of real EX_SPIN_LOCK/IRQL behavior,
nonpaged pool, WFP, or shutdown/unload with the driver loaded. Historical
container measurements are in
[TRAFFIC_STATS_BENCHMARK.md](../perf/TRAFFIC_STATS_BENCHMARK.md); their timings
are not new measurements of this production implementation.
