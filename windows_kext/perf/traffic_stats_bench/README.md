# Traffic statistics container benchmark

Standalone Windows user-mode Rust benchmark for the storage pattern in `windows_kext/driver/src/bandwidth.rs`. It never loads a driver or sends network traffic. The production driver is not changed.

The report is [TRAFFIC_STATS_BENCHMARK.md](../TRAFFIC_STATS_BENCHMARK.md). Raw output under `windows_kext/perf/results/` remains local and is not included in this commit.

## Reproduce

From the repository root, run the complete four-profile suite (release tests, build, seven timed runs per candidate, metadata and SHA-256 hashes):

```bash
powershell.exe -NoProfile -File windows_kext/perf/run-traffic-stats-bench.ps1
```

Or build and run individual profiles:

```bash
RUSTFLAGS="-C panic=abort -C target-feature=+sse4.2" cargo build --release --locked --manifest-path windows_kext/perf/traffic_stats_bench/Cargo.toml
```

```bash
windows_kext/perf/traffic_stats_bench/target/release/traffic-stats-bench.exe --events 1000000 --unique 8192 --runs 7
```

```bash
windows_kext/perf/traffic_stats_bench/target/release/traffic-stats-bench.exe --events 1000000 --unique 100000 --runs 7
```

```bash
windows_kext/perf/traffic_stats_bench/target/release/traffic-stats-bench.exe --events 1000000 --unique 1000000 --runs 7
```

Defaults: one million updates, 8,192 different tuples, five timed runs. The runner explicitly requests seven runs. Every candidate also has one warm-up and one separate allocation-instrumented pass.

Use `--reverse-order` to run candidates in the opposite order. Use `--ordered-output` to include sorting of hash-table output, preserving the existing per-map key order. Without it, row order is unspecified, as permitted by the current C++ consumer.

Additional synchronization model, executed after the single-thread benchmarks:

```bash
windows_kext/perf/traffic_stats_bench/target/release/traffic-stats-bench.exe --events 1000000 --unique 8192 --runs 3 --parallel --threads 4 --shards 16
```

This has four independent user-mode spinlocks with `--shards 1`, or 16 shards per protocol/address-family class with `--shards 16`. Threads are created before the timed start barrier. It measures elapsed time, including waits and scheduling, not CPU cycles or Windows kernel spinlock latency. Shard selection uses FxHash in this synthetic model; this routing choice also needs hardening in a production driver.

## Candidates

| Name | Storage | Hash |
|---|---|---|
| `btree` | Current `BTreeMap` baseline | None |
| `hashbrown-fx` | SwissTable, inline counters | FxHash, fast/non-adversarial only |
| `hashbrown-sip13` | Same SwissTable, inline counters | Keyed SipHash-1-3 |
| `open-address-fnv` | Exact full-key linear-probing table, 70% growth threshold | FNV-1a |
| `dense-index-fx` | Dense `Vec` of keys/counters plus key-to-index SwissTable | FxHash |
| `sorted-vec` | Sorted `Vec`, binary search and element shifts | None |

`sorted-vec` is deliberately skipped above 65,536 distinct keys: random insertions are quadratic in element movement. No candidate is allowed to discard keys or merge different tuples because hashes collide. All grow dynamically; there is no hidden oracle preallocation. Preallocated fixed-capacity or direct-flow-ID arrays are not compared as equivalent drop-in implementations.

`hashbrown`, `rustc-hash` and `siphasher` are pinned with default features disabled. The benchmark itself uses `std` for timing, threads and the host allocator. SipHash keys are fixed only for reproducibility, never a production seed recommendation.

## Synthetic trace

- Exactly the requested number of pre-generated updates and different full tuples.
- Four separate maps, as in the driver; 12-byte IPv4 and 36-byte IPv6 keys, two 64-bit counters.
- Template probabilities: 55% TCP/IPv4, 25% UDP/IPv4, 15% TCP/IPv6, 5% UDP/IPv6. Actual event counts are printed.
- Each tuple occurs at least once. For repeat events, 70% of selections choose from the hot 10% of tuples and 30% choose from all tuples.
- Four local interfaces; repeated popular service ports (HTTPS, HTTP, DNS, NTP), ephemeral local ports, mixed inbound/outbound events.
- TCP indication lengths range from 64 to 65,535 bytes; UDP lengths are capped at 1,400 bytes. These are counter updates, not an assertion that a TCP stream indication is one on-wire packet.
- Fixed seed and Fisher-Yates interleaving. This is a reproducible interleaved workload, not a measured pcap or a burst-preserving traffic replay.

Changing only `--unique` isolates repeat-heavy, high-cardinality and all-new-key behavior. One million different tuples is the insertion/memory stress profile, not the representative desktop traffic mix.

## Metrics and verification

- `fill_ms`: candidate creation, all lookups, insertions, growth and counter increments. No RNG, formatting, serialization or correctness checks.
- `drain_ms`: detached-map traversal, wire serialization, map destruction and optional ordering; it does not include delivery to the monitor or a concurrent updater.
- Timing uses uninstrumented allocation passes. Allocation counters are enabled only in a separate pass and balanced back to zero before it ends.
- `allocated_mib`: total requested allocation bytes, including full realloc requests, during fill plus serialization. It is cumulative, not resident memory.
- `peak_live_mib`: peak logically live requested heap bytes in that same pass, including growth and wire output. This excludes allocator headers/fragmentation and the already generated input/reference trace; it is not process RSS or actual kernel pool usage.
- Every warm-up and timed run decodes the complete serialized output and compares each full tuple and both directional totals with an independent `BTreeMap` reference. The printed checksum is supplementary, not the sole correctness check.
- Synchronization runs verify the same exact per-key totals after all workers finish. They do not simulate a concurrent drainer.

Run tests with release mode and an unwind-capable test binary:

```bash
RUSTFLAGS="-C target-feature=+sse4.2" cargo test --release --locked --manifest-path windows_kext/perf/traffic_stats_bench/Cargo.toml
```

Tests cover all candidates, collisions, empty drains, detached intervals, large `u32` counts, field order/endian, malformed framing and concurrent updates. The existing driver and protocol crates have separate release tests; they are not replaced by this harness.
