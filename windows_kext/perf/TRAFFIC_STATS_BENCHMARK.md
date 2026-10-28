# Traffic statistics containers: results and selection

**Date:** 2026-10-28. **Measurement baseline:** `554d737`, branch `dev`. Production driver sources were not changed during the measurements themselves, and no commit was created as part of those measurements.

**Subsequent implementation:** after these measurements, `driver/src/bandwidth.rs` was converted to `hashbrown + FxHash`, with 16 shards per class and old tables freed after draining. Exact accounting without a tuple limit, eviction or overflow aggregation was explicitly requested; OOM is outside the model. This is an intentional departure from the conservative keyed-hash/memory-budget recommendation below. Policy details and limitations: [traffic statistics storage](../driver/BANDWIDTH.md). The numbers in this report describe the original benchmark, not a new kernel-performance measurement.

## Conclusion

**The selected container is SwissTable, `hashbrown::HashMap`, with inline counters and a full tuple key.** For concurrent writes, use sharding within each of the four existing TCP/UDP x IPv4/IPv6 classes.

- **Raw-throughput winner:** SwissTable + FxHash. Filling the main profile was **7.58 times** faster than the BTreeMap baseline; reversing candidate order confirmed the advantage (**6.95 times**).
- **Conservative network-driver recommendation among the tested options:** the same SwissTable with **keyed SipHash-1-3**, using unpredictable keys generated per driver load. Fixed FxHash/FNV do not protect against deliberately crafted network keys. Even the SipHash variant was **2.68 times** faster than BTreeMap in the single-thread series.
- **Write architecture matters more than the container alone:** with eight threads, four shared locks became a bottleneck. With 16 shards per class, hashbrown+SipHash took **34.93 ms**, compared with **264.06 ms** without sharding. This is a user-mode model, not a Windows kernel spinlock measurement.

Sixteen shards is a measured, useful starting point for a prototype, **not a proven optimum**: only 1 and 16 were compared. At the time of the measurements, the prototype had not yet been integrated into the driver.

## Preserved accounting entity

The current `driver/src/bandwidth.rs` implementation uses four TCP/UDP x IPv4/IPv6 classes. Each class has 16 independent `RwSpinLock<hashbrown::HashMap<...>>` shards with `BuildHasherDefault<FxHasher>`. The key is:

```text
(local_ip, local_port, remote_ip, remote_port)
```

The selected map determines the protocol and address family. On x64, keys occupy 12/36 bytes, and the counter pair occupies 16 bytes. Updates select a shard from the full tuple and then call `entry(key).or_default()` while holding only that shard's lock. During `GetBandwidthStats`, all maps in a class are replaced with empty maps using `mem::take`; old tables are serialized outside the locks and freed after the snapshot is consumed. See [BANDWIDTH.md](../driver/BANDWIDTH.md) for the complete policy.

Fixed FxHash was selected explicitly for throughput. It does not harden externally influenced keys against collisions; this is a security limitation, not a property of `hashbrown` itself.

**The accounting unit remains the full connection tuple**, not an individual IP, port or process. Existing semantics aggregate reuse of the same tuple within an interval; they do not distinguish PID or connection generations.

A direct array indexed by `flow_id` was not compared as an equivalent replacement: the identifier must be obtained reliably on every accounting path, linked to a tuple, and managed correctly across lifetime/reuse. A bare index that excludes acquisition and lifetime-management costs would have an artificial advantage.

## Reproduction

From the repository root:

```bash
powershell.exe -NoProfile -File windows_kext/perf/run-traffic-stats-bench.ps1
```

The runner executes release benchmark tests, builds the EXE, runs four profiles, and records metadata/SHA-256 hashes. The timed EXE used `RUSTFLAGS="-C panic=abort -C target-feature=+sse4.2"`, `opt-level=3`, fat LTO, and one codegen unit. The test binary uses unwind and `+sse4.2`.

CLI and metric details: [README](traffic_stats_bench/README.md). The final raw series is stored locally under `results/traffic-stats-20261028-final/`, including environment metadata, the four cardinality profiles, reverse candidate order, ordered output, and the parallel model. The entire `results/` directory, including `environment.txt`, is intentionally excluded from this commit. Run the reproduction command to generate a fresh result directory.

## One million events resembling real traffic accounting

Every profile contains **exactly 1,000,000 pre-generated events**, identical for all candidates:

| Profile | Distinct connections | Repeated updates |
|---|---:|---:|
| Main | 8,192 | 991,808 - **99.1808%** |
| Many short connections | 100,000 | 900,000 - **90%** |
| High share of distinct connections | 700,000 | 300,000 - **30%** |
| Insertion/memory stress | 1,000,000 | 0 - not the main realistic profile |

Generator characteristics:

- Four separate classes, mixed directions, four local interfaces, ephemeral ports, and popular remote HTTPS/HTTP/DNS/NTP ports.
- Template mix: 55% TCPv4 / 25% UDPv4 / 15% TCPv6 / 5% UDPv6; the actual event mix depends on connection popularity.
- For repeated updates, 70% of selections come from the hot 10% of keys, and 30% come from all keys. This is not uniform writing to one million new addresses.
- TCP stream indications range from 64 to 65,535 bytes; UDP payloads are capped at 1,400 bytes. A TCP indication is not treated as an individual IP packet.
- Fixed seed `0x5eed20261028`, Fisher-Yates interleaving. This is a synthetic interleaved workload, not a real pcap or a replay preserving temporal burst patterns.

The main profile contains 526,522 TCPv4, 266,795 UDPv4, 152,526 TCPv6, and 54,157 UDPv6 events. Verified byte totals: RX **546,977,156**, TX **1,175,517,621**.

## Methodology and correctness

`fill_ms` includes creating empty maps, lookup, insertion, growth, and counter increments. RNG, formatting, verification, and serialization are outside this timer. There is no preallocation based on knowledge of the future key count.

`drain_ms` includes traversal/consumption of detached maps, generation of the real bandwidth wire layout, and freeing the maps. Verification decodes the result and compares **every tuple and both counters** with a separate BTreeMap reference model on every warm-up and timed run. The checksum in the log is supplementary diagnostics only.

Main values are medians of **7** timed runs after one warm-up. Allocation tracking uses a separate pass. `peak_live_mib` is the peak of requested live heap bytes during fill and serialization; it includes growth and the output buffer, but excludes the input trace, reference model, allocator overhead, and fragmentation. It is **not RSS or a nonpaged-pool measurement**.

## Results: main profile

| Container | Fill, ms | Million updates/s | Drain, ms | Peak live, MiB |
|---|---:|---:|---:|---:|
| BTreeMap baseline | 228.269 | 4.38 | 0.521 | 0.52 |
| **hashbrown + FxHash** | **30.106** | **33.22** | 0.410 | 0.64 |
| hashbrown + SipHash-1-3 | 85.093 | 11.75 | 0.396 | 0.64 |
| Linear open addressing + FNV | 55.623 | 17.98 | 0.418 | 0.77 |
| Dense Vec + Fx hash index | 36.877 | 27.12 | 0.469 | 1.04 |
| Sorted Vec + binary search | 184.607 | 5.42 | 0.319 | 0.63 |

Dense Vec did not win: the additional index, indirect access, and duplicate key storage cost more than an inline value in SwissTable. Sorted Vec has cheap sequential output, but loses substantially on updates and requires shifts on insertion.

## High cardinality and memory

| Container | 100,000 keys: fill, ms | 700,000 keys: fill, ms | 1,000,000 keys: fill, ms | One million: drain, ms | One million: peak MiB |
|---|---:|---:|---:|---:|---:|
| BTreeMap | 327.662 | 608.927 | 682.432 | 69.354 | **63.58** |
| **hashbrown + FxHash** | **47.091** | **142.889** | **200.971** | 30.501 | 82.00 |
| hashbrown + SipHash-1-3 | 120.078 | 315.002 | 409.823 | 30.105 | 82.00 |
| Open addressing + FNV | 81.717 | 226.881 | 241.715 | 32.394 | 98.68 |
| Dense Vec + Fx index | 70.699 | 225.015 | 265.989 | 29.755 | 125.00 |

Sorted Vec is deliberately skipped above 65,536 distinct keys because of quadratic insertion shifts, not recorded as taking zero time. Hashbrown is faster at all measured cardinalities, but requires more peak memory than the tree at one million keys. Cumulative allocation bytes and allocation counts are preserved in the raw logs; they are separate metrics, not resident memory.

## Output order and candidate order

The current C++ parser, `kext_client/src/PortmasterKext.cpp:639-670`, does not rely on key ordering. The main series allows unordered output. If needed, `--ordered-output` sorts outside the update path.

Reverse candidate order (local `results/traffic-stats-20261028-final/reverse-8192.txt`) produced BTreeMap **210.811 ms**, FxHash **30.315 ms**, and SipHash **86.620 ms**: the conclusion is stable across candidate order, although wall-clock numbers fluctuate.

Preserving output order (local `results/traffic-stats-20261028-final/ordered-8192.txt`): FxHash fill **29.006 ms**, drain **1.696 ms**; SipHash fill **87.227 ms**, drain **1.658 ms**. Sorting is visible in drain time but does not change the selected container. Fill-time differences between these series are not caused by sorting: sorting happens after filling.

## Concurrent writes and sharding

The same one-million-event / 8,192-key workload, with **3** timed runs. Thread creation is excluded using start barriers. Exact totals are verified after joins. Time includes user-mode waits and scheduling; it is neither CPU time nor a Windows IRQL measurement.

| Threads | Shards per class | BTreeMap, ms | Swiss+Fx, ms | Swiss+Sip, ms |
|---:|---:|---:|---:|---:|
| 1 | 1 | 203.094 | 27.061 | 86.040 |
| 1 | 16 | 160.124 | 35.745 | 91.705 |
| 4 | 1 | 195.662 | 140.175 | 137.866 |
| 4 | 16 | 70.308 | 27.985 | 51.791 |
| 8 | 1 | 331.614 | 264.816 | 264.061 |
| 8 | 16 | 42.421 | **22.072** | **34.930** |

The recommendation is therefore a **sharded hash table**, not a mechanical tree replacement retaining the same hot locks. With one writer, sharding adds overhead for the hash candidates; 16 shards must not be treated as a universal optimum. The model uses FxHash for shard selection; production routing also needs hardening. Min/max values and full commands are in the model logs (local `results/traffic-stats-20261028-final/parallel-t8-s16.txt`).

## Verification and limits of the conclusions

- Benchmark: **16 passed**, including identical hashes for different keys, all six containers, empty drains, interval separation, endianness/framing, `u32` counts above 65,535, and concurrent updates.
- Before integration: driver unit tests **194 passed, 0 failed, 1 ignored**. After integrating sharded statistics: **206 passed, 0 failed, 1 ignored**, using `RUSTFLAGS="" cargo test --release`. Existing `dead_code` warnings remain.
- Protocol release tests: **14 passed**.
- A separate `#![no_std]` probe using `HashMap::entry`, Fx/Sip, `panic=abort`, and `+sse4.2` successfully compiled to an rlib; temporary files were removed. That probe is not a kernel link/load-admission test.
- All million-event and additional benchmark series completed with exit code **0**, without counter mismatches.
- After integration, the release staticlib was built, a new `.sys` was linked/signed, and a bounded smoke test ran with `kext_monitor.exe --duration 3 --poll 200 --memory-stats`. The monitor exited with code 0, no monitor process or service remained, and the smoke audit found no WARN/ERROR/failure diagnostics; 15 bandwidth records and 128 requested memory-stat lines were recorded. The complete standard lifecycle/live-unload suite was not run.

**Not established:** absolute kernel-callback latency, nonpaged-allocator behavior at IRQL, safe growth under a real EX_SPIN_LOCK, individual-update p99, the global memory high-water mark of two map generations, and OOM behavior. OOM is explicitly outside the model. Concurrent drains have user-mode regression coverage, and the smoke exercises runtime collection, but neither is xperf/ETW profiling; IPv4/IPv6 UDP live-unload regression was not included in this run.

Fixed FxHash retains the known risk of deliberately crafted network collisions; a keyed hash was not integrated because `hashbrown + FxHash` was explicitly selected. Kernel lock/IRQL behavior, allocator/high-water behavior under real traffic, and the required IPv4/IPv6 UDP live-unload cases remain outside the completed verification. These are verification limits, not a hidden memory/overflow policy.

Environment: Windows 11 Enterprise `10.0.26300`, approximately 28 GiB RAM; Balanced power plan, Normal priority. Rust `1.99.0-nightly (7608eb7b0 2026-08-05)`, LLVM 23.1.0, `x86_64-pc-windows-msvc`. Power settings, priorities, and system security settings were not changed.

Note: three initial PowerShell logs were normalized to UTF-8 without changing benchmark output; their original bytes are retained under ignored `test/_out`. The runner was changed to append UTF-8 explicitly. Raw result files, including `environment.txt`, remain local and are not part of this commit.
