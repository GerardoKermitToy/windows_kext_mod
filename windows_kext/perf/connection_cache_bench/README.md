# Packet-layer connection-cache benchmark

This is an isolated **user-mode release microbenchmark**, not a driver load or a WFP traffic test. It does not start `kext_monitor`, install a service, sign a SYS, change the power plan, or contact a test host. Running this benchmark does not modify driver sources. The driver now uses the `directory-fx` organization; historical pre-integration measurements remain unchanged.

Recorded runs: [2026-10-29 results, recommendation and driver integration](../CONNECTION_CACHE_BENCHMARK.md). The main series contains 576 samples; the independent repeat and post-integration run contain 192 samples each. The post-integration run uses the actual production `directory-fx` implementation. Driver/protocol regression and signed-build verification results are documented in the report. Raw samples, environment/source hashes, detailed summaries and logs are kept locally and excluded from version control.

## Run

From Git Bash at the repository root:

```bash
powershell.exe -NoProfile -ExecutionPolicy Bypass -File windows_kext/perf/run-connection-cache-bench.ps1 -Rounds 9
```

The runner creates a new timestamped `windows_kext/perf/results/connection-cache-*` directory, builds the release test executable, runs all ordinary regression tests, then runs the ignored benchmark. It saves environment/source/executable hashes, the test log, the complete benchmark log, and `samples.jsonl`. Existing result directories/files are not overwritten. `-Cpu 2` is the default; it pins only the benchmark process to that **logical** CPU. `-Filter v4-mixed-uniform` selects one profile for a shorter repeat. The selected CPU must be available in the process's affinity mask.

Summarize a completed result directory (replace the example path):

```bash
"C:/Program Files/Python314/python.exe" -I windows_kext/perf/connection_cache_bench/summarize.py windows_kext/perf/results/connection-cache-YYYYMMDD-HHMMSS
```

Tests alone, without pinning or timings:

```bash
RUSTFLAGS='' cargo test --release --locked --manifest-path windows_kext/perf/connection_cache_bench/Cargo.toml -- --test-threads=1
```

## What is measured

Every profile inserts **50,000 distinct complete connection tuples** into an initially empty cache. Every timed packet-lookup pass executes **1,000,000 pre-generated requests: exactly 700,000 successful and 300,000 unsuccessful**. Queries do not create entries on a miss; this deliberately isolates the lookup, not packet cloning, new-connection registration, or userspace verdict latency.

The `directory-fx` candidate imports the actual `driver/src/connection.rs`, `connection_map.rs` and `port_table.rs`. The `btree-btree` reference is generated from that same current source with both indices replaced by B-trees. `read_for_packet` applies the real direction-dependent lookup and copies the same four fields as `packet_callouts::ConnectionInfo`: verdict, PID, connection direction, and instance ID. Cache population uses actual `ConnectionV4/ConnectionV6` records, not a reduced dummy value. The `Key` and connection types are shared by every variant.

`build.rs` derives alternative modules from the **current** production source in Cargo's `OUT_DIR`. It replaces index types/construction and retains the production generation logic and explicit UDP PID donor selection. Sparse hash storage is shrunk without dropping live records. The source anchors are checked; a changed anchor fails the build instead of silently benchmarking stale code. No generated variant is checked into the driver.

| Label | Outer `(protocol, local_port)` index | Inner remote-endpoint index |
|---|---|---|
| `btree-btree` | Reference B-tree (generated) | Inline-one / B-tree |
| `fx-btree` | hashbrown + FxHash | Inline-one / B-tree |
| `btree-fx` | B-tree | Inline-one / hashbrown + FxHash |
| `fx-fx` | hashbrown + FxHash | Inline-one / hashbrown + FxHash |
| `directory-btree` | TCP/UDP direct port directory | Inline-one / B-tree |
| `directory-fx` | Production TCP/UDP direct port directory | Production inline-one / hashbrown + FxHash |
| `sip-sip` | hashbrown + SipHash-1-3 | Inline-one / hashbrown + SipHash-1-3 |
| `directory-sip` | TCP/UDP direct port directory | Inline-one / hashbrown + SipHash-1-3 |

The directory is one heap allocation with two 65,536-cell `u32` ranges (512 KiB **per address family**) indexing densely stored local-port groups. Zero means absent. It avoids allocating a large inline connection object for every possible port. Non-TCP/UDP groups use a fallback B-tree. Deletion repairs moved dense-slot indices; cleanup shrinks a severely underfilled slot vector. Hash candidates also shrink severely underfilled maps; `clear` releases their outer allocation.

All candidates retain the actual generation buckets, exact local-address validation, native-lifecycle state and inline-one optimization. Hash iteration is not allowed to change which UDP PID is borrowed: its donor lookup explicitly chooses the lowest eligible remote port, preserving the former B-tree order and generation precedence. Other cold-path enumeration order is not a wire contract; candidates may enumerate different endpoints in a different order.

There is **no total connection limit, per-port limit, generation limit, LRU or capacity-based eviction**. The finite port directory indexes groups, not individual connections. Remote hash maps and generation vectors grow dynamically; OOM is assumed not to occur. Regression tests cover 150,000 connections behind one port in each address family, retained-generation growth, all 131,072 TCP/UDP groups occupied at once, and differential directory churn against a B-tree.

## Workload profiles

Each topology is measured separately for **IPv4 and IPv6**, each with its own 50,000-entry cache:

- **client-uniform:** 50,000 occupied `(protocol, local_port)` groups, one remote endpoint per group, TCP/UDP split equally. This exercises the existing inline-one fast path and the outer index.
- **listener-uniform:** one UDP listener group with 50,000 remote endpoints. This isolates the inner index. It is a deliberately concentrated listener workload, not a claim about typical protocol proportions.
- **mixed-uniform:** 40,000 single-peer client groups plus 10,000 peers spread over 16 TCP/UDP listener groups.
- **mixed-burst:** the mixed topology, ten-request groups targeting one randomly selected connection: seven hits and three distinct misses, shuffled inside each group. This tests flow locality rather than uniformly shuffling the entire request stream.

Uniform profiles shuffle all requests deterministically. All profiles randomize record insertion order. Fixed SplitMix64 seed: `0x2026102970475000`. There are four local addresses; exact local-address checks therefore cannot be replaced by matching only the remote endpoint. Every profile uses an approximately 50/50 random packet-direction mix. The primary datasets are live, natively tracked records with cached permanent verdicts; ended/reused/untracked behavior is exercised by the regression suites, not mixed into the required hit ratio.

The 300,000 misses have three equal classes:

1. Existing local-port group, absent remote address.
2. Existing remote endpoint and local port, **wrong local address**; this reaches the generation bucket but must not match.
3. Absent local-port group (ports 60,000–64,095).

This misses mix is an explicit synthetic assumption, not a measured traffic trace. A benchmark with only unused-local-port misses would unfairly hide inner-index costs. The workload independently verifies all tuple membership and the exact hit count before timing.

## Measurement and validation

- Nine timed rounds by default; candidate order rotates each round.
- An untimed full pass compares **every result and every returned field** against the precomputed answer, and also warms each candidate before timing.
- A timed pass checks the hit count and metadata checksum. `black_box` and a non-inlined batch boundary prevent elimination of the lookup loop.
- Query generation, correctness assertions, allocation counting, cache teardown and logging are **outside** packet-lookup timing.
- Additional timings cover inserting 50,000 records; 50,000 successful exact-instance checks; ending all 50,000 records by occupied local endpoint; and removing 50,000 pre-aged records with actual cleanup.
- A separate untimed counting-allocator pass measures live/peak **requested heap bytes**, counts allocation/reallocation calls, asserts **zero allocations across all one million lookups**, and verifies that all tracked bytes are freed on drop. Request arrays and template connections are excluded. Empty-cache retention after cleanup is also recorded.
- Every generated variant runs the current production map's complete private regression test module, in addition to explicit directory integrity and hit-ratio tests. That covers exact tuple/address matching, retained generations, direction-specific fallback, instance isolation, registration, endpoint filters, UDP attribution and cleanup.
- Output includes all individual samples. `summarize.py` uses medians and full-pass min/max, not invented per-request latency percentiles. Its geometric means weight all tested profiles equally; they are **not** an estimate of a real workload's traffic mix.

## Limits and integration constraints

- This measures the container lookup and metadata copy **without a lock**. The driver has one kernel `RwSpinLock` per address family; IRQL transitions, writer contention, WFP, NDIS and nonpaged-pool allocation are not emulated. Timings are not end-to-end packet latency or an expected kernel CPU reduction.
- Real connection/map code uses its existing `cfg(test)` clocks, because kernel time imports are unavailable. All primary entries have native lifecycle, so packet lookup does not invoke the untracked-activity clock. The untracked and timeout rules are covered by regression tests. Test-framework panic behavior and the allocator differ from the kernel.
- The runner enables SSE4.2 like `build-signed.bat`. The benchmark uses opt-level 3, one codegen unit and fat LTO for all variants; this is an optimized synthetic comparison, not a bit-for-bit driver build. It does not use `target-cpu=native`.
- Production deliberately uses FxHash for throughput, as requested. It is not collision-resistant for hostile packet-derived keys. If collision resistance is required, a keyed alternative needs unpredictable per-load keys prepared before classify callbacks; the SipHash variants use a **fixed benchmark seed only**, not suitable production keys.
- The production directory is allocated eagerly on the heap at cache construction: 512 KiB/family even when empty, 1 MiB for IPv4+IPv6. The kernel allocator uses nonpaged NX pool. No directory array is constructed on the kernel stack; `clear` retains the directory but frees dense slots and remote maps.
- A flat full-tuple hash map would lose cheap endpoint-scoped operations and the existing UDP PID fallback unless it also maintained another index. An unsynchronized per-CPU/MRU verdict cache could return stale policy after updates or tuple reuse; it requires lifetime/invalidation design, not just a lookup microbenchmark. Sorted vectors reintroduce O(n) insertion moves under the write lock. These are not equivalent drop-in candidates and are not represented as measured results.
- Any production change still needs full release driver/protocol tests, a signed build, bounded monitor tests and concurrency/lifecycle validation. This benchmark does **not** perform or claim those kernel runtime checks.
