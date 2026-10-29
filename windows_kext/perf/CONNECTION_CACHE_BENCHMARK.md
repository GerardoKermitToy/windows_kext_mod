# Packet-layer connection lookup: synthetic benchmark

Date: 2026-10-29. Original commit: `9cdedc3848c1e83dc13ff2d24dadca5f3b9e06e8`.

> The main series and independent repeat below were recorded **before integration**: "current B-tree" in those sections refers to the driver at the original commit. After measurement, a separate request authorized replacing the production cache with a port directory + FxHash without an entry-count limit. See [driver integration](#driver-integration). Historical timing samples and recorded source hashes are preserved; report metadata were sanitized before committing.

## Workload and measurement scope

Each profile inserts **50,000 distinct complete tuples** into an empty cache. Each timed pass then performs **1,000,000 queries: exactly 700,000 hits and 300,000 misses**. IPv4 and IPv6 are tested separately, not as two simultaneously populated 50,000-entry caches.

The benchmark uses the actual `ConnectionV4`, `ConnectionV6`, `Key` and `ConnectionMap::read_for_packet`. Lookup copies the verdict, PID, direction and instance ID, just like `ConnectionInfo` in the packet callback. Instead of using a separate simplified implementation, the original baseline imports the driver source directly. Alternative modules are generated from the same file by replacing its indices.

**This is an unlocked user-mode release container benchmark, not kernel-callback latency.** It excludes WFP/NDIS, packet parsing, IRQL, kernel `RwSpinLock`, contention, reinjection and userspace verdict latency. A miss does not insert an entry. The primary workload uses live records with native lifecycle; history, tuple reuse and untracked expiration are covered by correctness tests but are not mixed into the required hit ratio.

## Why these candidates

The original cache has an outer B-tree keyed by `(protocol, local_port)`, followed by an inline-one / B-tree index keyed by compact remote endpoint. Generations and different local addresses sharing one remote endpoint are stored in a separate inline-one / `Vec` bucket.

| Label | Outer index | Inner index |
|---|---|---|
| `btree-btree` | Original B-tree | Original inline-one / B-tree |
| `fx-btree` | hashbrown + FxHash | Inline-one / B-tree |
| `btree-fx` | B-tree | Inline-one / hashbrown + FxHash |
| `fx-fx` | hashbrown + FxHash | Inline-one / hashbrown + FxHash |
| `directory-btree` | Direct TCP/UDP port directory | Inline-one / B-tree |
| `directory-fx` | Direct TCP/UDP port directory | Inline-one / hashbrown + FxHash |
| `sip-sip` | hashbrown + SipHash-1-3 | Inline-one / hashbrown + SipHash-1-3 |
| `directory-sip` | Direct TCP/UDP port directory | Inline-one / hashbrown + SipHash-1-3 |

The directory contains two ranges of 65,536 `u32` cells in one heap allocation. Zero means that a group is absent; other cells point into a dense group array. **Its fixed cost is 512 KiB per address family, or 1 MiB for both families in `ConnectionCache`, even when empty.** The inner index is retained: a busy port does not degrade into a linear scan of every connection behind it. Other protocols use a fallback B-tree. Deletion repairs indices for moved dense slots.

Hash candidates preserve adaptive inline-one storage and generation buckets. The infrequent UDP PID fallback explicitly selects the lowest eligible remote port so hash iteration does not change attribution relative to the B-tree. This can require a more complete cold-path scan; its duration is not measured separately. Severely underfilled hash tables and dense arrays shrink their capacity; `clear` releases outer hash allocations.

### Preserved architectural requirements

- After selecting a remote endpoint, lookup still validates the **complete tuple, including the local address**.
- A retained ended generation is not overwritten by a new live generation; insertion order inside each bucket is preserved.
- `instance_id` continues to protect a reused tuple from a delayed verdict or END.
- Inbound packet lookup does not use ended history; ordinary outbound lookup may use it. The separate foreign-injection policy is outside the measured container and remains unchanged.
- Endpoint-wide END retains local-address/PID filters and scans only one `(protocol, local_port)` group.
- Cleanup preserves the grace period and native/untracked lifecycle rules.

A flat five-tuple hash without a second index makes endpoint-wide operations and UDP PID lookup more expensive; it is not an equivalent single-table replacement. A sorted vector reintroduces O(n) movement during insertion under the write lock. An unsynchronized per-CPU/MRU verdict cache needs a separate invalidation protocol for policy changes, END and tuple reuse. These approaches were considered, **but their performance was not measured here**.

## Methodology

Environment: Windows 11 build 26300. The Balanced power plan was left unchanged. The benchmark process is pinned to logical CPU 2; its priority is unchanged. Processor and host hardware identifiers are intentionally omitted.

Toolchain: `rustc 1.99.0-nightly (7608eb7b0 2026-08-05)`, LLVM 23.1.0, MSVC x64 target. Every candidate uses release, opt-level 3, fat LTO, one codegen unit and `-C target-feature=+sse4.2`, without `target-cpu=native`. This is a common optimized profile for synthetic comparison, not the exact SYS link configuration. The allocator and panic behavior are user-mode; clocks use the existing `cfg(test)` doubles.

- **Nine passes** per candidate, with candidate order rotated each round.
- Before every measurement, a complete untimed pass validates **every query and every returned field**, also warming the cache.
- The timed pass additionally checks the hit count and metadata checksum. Generation, allocation accounting, teardown and output are outside lookup time.
- A separate pass measures live/peak requested heap bytes and allocation/reallocation calls. It verifies **zero allocations** across all 1,000,000 lookups and zero tracked bytes remaining after drop.
- Additional measurements cover inserting 50,000 records, 50,000 exact-instance checks, ending all 50,000 connections by occupied endpoint groups, and cleaning up 50,000 pre-aged records.
- Medians describe complete passes. Min/max describe pass-to-pass variation, **not per-request latency percentiles**.

### Profiles

Each profile runs separately for IPv4 and IPv6:

1. **client-uniform:** 50,000 `(protocol, local_port)` groups, one peer per group, TCP/UDP split equally.
2. **listener-uniform:** one UDP listener with 50,000 remote endpoints, testing high concentration behind one port.
3. **mixed-uniform:** 40,000 single-peer client groups plus 10,000 peers across 16 listener groups.
4. **mixed-burst:** the same mixed topology, using ten-query blocks targeting one selected connection: seven hits and three misses, shuffled within the block.

Insertion order is random and identical across implementations. Uniform queries are fully shuffled; the seed is `0x2026102970475000`. Packet directions are approximately evenly split. There are four local addresses. Each miss class has 100,000 queries: an unknown remote endpoint behind an occupied local port; a known remote endpoint with the wrong local address; and an absent local port. This is an explicit synthetic model, not a distribution obtained from an ETW trace.

## Selected organization

**For throughput across the full tested set, the selected candidate is `directory-fx`: a direct `(TCP/UDP, local_port)` directory plus adaptive inline-one / hashbrown with FxHash for remote endpoints.** Generation buckets and all exact-match checks remain unchanged.

The equal-weight geometric mean speedup over the original cache across eight profiles is **3.33x** in the main series and **3.26x** in the independent repeat. These figures describe this workload set, not predicted CPU reduction in the real driver. The selected candidate's weakest profile is still **2.86x** faster than the baseline in the main series.

If the fixed **1 MiB for both families** is undesirable, `fx-fx` is a practical alternative: **3.09x / 3.06x** in the two series, without a large empty directory. The directory's average throughput advantage over that candidate is much smaller, approximately **6.5-7.8%**. Adopting it therefore requires an explicit nonpaged-pool budget decision, not just a comparison with the original B-tree.

### Lookup: main series

Median of nine passes, **milliseconds per 1,000,000 queries**. The numerical value also equals **nanoseconds per query**, but this is not a separate latency measurement for every operation.

| Profile | Original B-tree | Fx / B-tree | B-tree / Fx | Fx / Fx | Directory / B-tree | Directory / Fx | Sip / Sip | Directory / Sip |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| IPv4, client uniform | 200.00 | 54.52 | 198.35 | 53.27 | 54.09 | **52.92** | 71.30 | 53.48 |
| IPv6, client uniform | 205.71 | 55.70 | 213.60 | **55.56** | 59.95 | 57.67 | 76.35 | 58.92 |
| IPv4, listener uniform | 162.22 | 191.51 | **44.86** | 57.70 | 180.33 | 50.05 | 84.16 | 61.22 |
| IPv6, listener uniform | 195.20 | 216.61 | **57.66** | 66.40 | 209.61 | 58.94 | 107.40 | 73.36 |
| IPv4, mixed uniform | 197.65 | 78.06 | 181.90 | 60.08 | 75.35 | **57.19** | 78.42 | 59.54 |
| IPv6, mixed uniform | 210.35 | 83.47 | 195.33 | 64.43 | 84.64 | **63.00** | 87.85 | 65.05 |
| IPv4, mixed burst | 124.74 | 61.98 | 118.09 | 48.99 | 51.12 | **39.20** | 60.79 | 40.53 |
| IPv6, mixed burst | 134.90 | 64.51 | 127.14 | 50.74 | 60.37 | 47.17 | 68.66 | **46.87** |

On mixed-uniform workloads, the selected candidate reaches approximately **17.49 million lookups/s for IPv4** and **15.87 million lookups/s for IPv6** on one pinned logical CPU, excluding the kernel lock and other packet processing.

Important observations:

- Replacing **only the outer** B-tree helps client-port workloads but does not solve the single-busy-listener case and is slower in that workload.
- Replacing **only the inner** B-tree helps a busy listener but has little effect when there is one peer per port.
- `directory-fx` is the best overall measured throughput compromise, **not the winner in every row**. B-tree / Fx is faster for a single busy listener; Fx / Fx is faster for IPv6 client-uniform.
- For IPv6 burst, Directory / Sip and Directory / Fx differ by less than 1%; that does not establish an unconditional winner given the observed variability.
- Complete min/median/max values are saved in the summary. IPv6 listener has substantial individual outliers; nine passes and an independent repeat are more informative than isolated minima.

### Independent repeat

The same executable, a new process, and three passes for each of the 64 profile/candidate combinations:

| Candidate | Main-series geometric mean speedup | Repeat geometric mean speedup |
|---|---:|---:|
| B-tree / B-tree | 1.000x | 1.000x |
| Fx / B-tree | 2.020x | 1.944x |
| B-tree / Fx | 1.410x | 1.433x |
| Fx / Fx | 3.092x | 3.059x |
| Directory / B-tree | 2.100x | 2.156x |
| **Directory / Fx** | **3.332x** | **3.259x** |
| Sip / Sip | 2.245x | 2.260x |
| Directory / Sip | 3.110x | 3.073x |

Close individual rankings change in the repeat. For example, IPv6 mixed-uniform takes 70.08 ms with Directory / Fx versus 65.08 ms with Fx / Fx. The overall selection is unchanged, but there is no universal winner for every topology. The power plan and background OS load were not artificially fixed, limiting the precision of small differences.

### Memory

Live heap after population, **MiB per address family**, excluding request arrays and template records:

| Profile | Original B-tree | Fx / Fx | Directory / Fx |
|---|---:|---:|---:|
| IPv4, client | 4.89 | 4.56 | 5.00 |
| IPv6, client | 6.56 | 6.06 | 6.50 |
| IPv4, listener | 5.19 | 4.56 | 5.06 |
| IPv6, listener | 7.98 | 7.06 | 7.56 |
| IPv4, mixed | 4.96 | 5.70 | 6.14 |
| IPv6, mixed | 6.86 | 7.83 | 8.27 |

Hashing does not always save memory: spare capacity makes the mixed topology more expensive than B-trees. The directory also retains 512 KiB/family after cleanup. On mixed IPv4, population allocation/reallocation calls fall from **6,659 to 160**, but live memory increases by approximately **24%**. Rehash peaks are included in the samples; live and peak usage must not be conflated.

These are allocator-requested bytes, **not NonPagedPool measurements or allocator-header accounting**. Zero tracked bytes after drop is verified only in the user-mode test process.

### Other driver operations

Main-series medians, total milliseconds, using the same 50,000-record mixed-uniform profile:

| Family / candidate | Insert | 50,000 instance checks | END by endpoint groups | Cleanup |
|---|---:|---:|---:|---:|
| IPv4, original B-tree | 18.05 | 9.62 | 8.25 | 6.29 |
| IPv4, Fx / Fx | 13.09 | 2.49 | 6.33 | 2.15 |
| IPv4, Directory / Fx | **5.99** | **1.93** | **5.75** | **1.92** |
| IPv6, original B-tree | 19.25 | 10.34 | 7.65 | 6.31 |
| IPv6, Fx / Fx | 16.58 | **2.49** | 5.77 | 2.34 |
| IPv6, Directory / Fx | **7.16** | 3.18 | **4.97** | **1.92** |

The packet-lookup improvement is not obtained at the expense of these measured operations relative to the baseline. Fx / Fx is nevertheless faster than the directory for IPv6 instance checks. UDP PID fallback on an incomplete tuple preserves its result, but its separate duration and simultaneous reader/writer performance were **not measured**. Those remain subjects for kernel validation.

### Validation results

- Benchmark crate: **300 passed, 0 failed, 1 ignored**. The ignored test is the long benchmark, subsequently run successfully in both series.
- Full driver `RUSTFLAGS='' cargo test --release`: **198 passed, 0 failed, 1 ignored**, with seven dead-code warnings in the existing test graph.
- **One successful benchmark test** per series. The main series took 158.73 seconds overall, including setup and validation outside lookup time.
- **576 + 192 = 768 validated timed passes**, or **768 million timed queries**. Warmups and validation/memory passes are not included in this count.
- Every candidate returned the expected complete metadata, exactly 70% hits and zero lookup allocations. Existing map regression tests ran for every generated candidate.
- Rust formatting, PowerShell syntax and the result aggregator were checked; the aggregator used a separate synthetic fixture that was not included in measurements.
- Executable SHA-256 in both series: `149BB90406FFB535F7EDD0A50F11141B9A7D010C7449C7E5C4312C644A69383A`.
- Two preliminary runner attempts stopped before measurement on Windows PowerShell 5.1 incompatibilities. These were fixed and are not included in results.

Raw samples, environment/source hashes and detailed numerical summaries are kept locally and are not included in the repository.

**Before production adoption:** FxHash does not protect against deliberately chosen collisions in packet-derived keys. If that protection is required, an unpredictable per-load keyed hash is needed; Directory / Sip was also measured, but its fixed benchmark seed must not be deployed in the driver. Replacing the structure also requires kernel lock/concurrency validation, not only these single-thread container results. No signed SYS was built and no kernel runtime was tested during the original benchmark-only stage, because the production driver was unchanged at that point.

## Reproduction

From Git Bash at the repository root:

```bash
powershell.exe -NoProfile -ExecutionPolicy Bypass -File windows_kext/perf/run-connection-cache-bench.ps1 -Rounds 9
```

Summarize a new results directory:

```bash
"C:/Program Files/Python314/python.exe" -I windows_kext/perf/connection_cache_bench/summarize.py windows_kext/perf/results/connection-cache-YYYYMMDD-HHMMSS
```

See the [benchmark README](connection_cache_bench/README.md) for code structure and limitations.

The benchmark does not install a service, load a driver or start the monitor. Running it does not automatically replace the production cache or create a commit.

## Driver integration

After the original measurements, a separate request authorized adopting the **port directory + FxHash** in the production cache:

- [PortTable](../driver/src/port_table.rs) holds two heap ranges of 65,536 `u32` cells and a dense array of occupied TCP/UDP groups. Other protocols retain a fallback B-tree. After `swap_remove`, deletion repairs the directory reference for the moved group.
- [ConnectionMap](../driver/src/connection_map.rs) uses this directory and `hashbrown::HashMap` with `BuildHasherDefault<FxHasher>` for remote endpoints; one endpoint is still stored inline.
- **There is no total connection limit, per-port peer limit or retained-generation limit.** There is no LRU, capacity-based insertion rejection or size-based eviction. Directory `u32` cells index at most 131,072 distinct TCP/UDP groups, not connections; remote maps and generation vectors grow dynamically. OOM is assumed not to occur, as requested; no extra OOM recovery/fallback mechanism was introduced.
- Complete tuple matching, `instance_id`, generation order, live-only inbound lookup, outbound ended fallback, native/untracked lifecycle and endpoint END filters are preserved. UDP PID selection uses the lowest eligible remote port with the former generation precedence, independently of hash iteration.
- Locking is unchanged: the existing per-family `RwSpinLock` protects every operation. The directory is allocated at cache construction through the existing NonPaged NX allocator: 512 KiB/family, without a large kernel-stack array. `clear` releases groups and remote maps while retaining the directory until cache destruction.
- Cleanup capacity shrinking releases spare storage without removing live entries. Ended/untracked-state expiration rules are unchanged.
- FxHash is an explicit throughput choice, not protection against intentional hash collisions. The fixed-seed benchmark SipHash was not copied into the driver.

In the current benchmark, `directory-fx` imports the **production implementation**, including `port_table.rs`; `btree-btree` is now generated as a reference from the same current source. Candidate labels were not retroactively reassigned. Historical timing samples and recorded hashes in `main`/`repeat` are preserved.

### Integration validation

| Check | Result |
|---|---|
| Full release driver unit-test suite | **208 passed, 0 failed, 1 ignored** |
| Regressions for all eight cache candidates | **350 passed, 0 failed, 1 ignored** |
| Release protocol tests | **14 passed, 0 failed** |
| Additional concurrent growth / packet lookup / cleanup repeats | **5 of 5 passed** |
| `build-signed.bat`: release driver, link, SYS signing | Built and signed `windows_kext/portmaster-kext.sys` |
| `signtool verify /v /pa` | **1 verified, 0 warnings, 0 errors** |
| Kernel runtime, WFP traffic, UDP live-unload IPv4/IPv6 | **Not run** |

New regressions cover 150,000 connections behind one UDP port separately for IPv4/IPv6, live-entry preservation after substantial hash-table contraction, retained-generation growth, deterministic UDP PID selection, all 131,072 TCP/UDP groups occupied at once, repeated directory churn compared with a B-tree, and concurrent writes/lookups/cleanup through `ConnectionCache`. Unit tests use the existing user-mode lock double; they do not measure kernel spin-lock contention.

The first run of the new concurrency test found a **test-data error**: its first generated IPv6 tuple duplicated the stable control entry. The address range was corrected; the full suite and five additional repeats passed.

The build emitted environment warnings about `vswhere.exe` and LNK4099 for `c_helper.pdb`. Build/link/sign completed; the signature was checked separately. A temporary Python wrapper failed to print a localized warning to cp1251 after SYS signing; that wrapper failure was not treated as a successful wrapper exit. After restoring the original CRLF in `lib.rs`, the full driver suite, build/link/sign and signature verification were repeated with explicit **exit-code-0** checks. Source/SYS hashes, commands and limitations are kept with the local validation results.

No driver was loaded, `kext_monitor` was not started, and no service was created manually. No commit was created while recording these benchmark and integration runs.

### Post-integration repeat

A new executable, **three passes for each of 64 family/profile/candidate combinations**, producing **192 validated timed passes**. `directory-fx` directly imports production source rather than a separate algorithm copy. Each pass has 50,000 entries, 1,000,000 queries and exactly 700,000 hits; metadata/checksums are validated and lookup does not allocate.

Medians, milliseconds per 1,000,000 lookups:

| Profile | B-tree reference | Integrated directory / FxHash |
|---|---:|---:|
| IPv4, client uniform | 210.44 | 57.00 |
| IPv6, client uniform | 212.15 | 57.82 |
| IPv4, listener uniform | 167.17 | 53.03 |
| IPv6, listener uniform | 189.32 | 56.62 |
| IPv4, mixed uniform | 206.43 | 57.33 |
| IPv6, mixed uniform | 247.36 | 77.25 |
| IPv4, mixed burst | 139.23 | 46.45 |
| IPv6, mixed burst | 136.75 | 45.10 |

The production candidate's geometric mean speedup over the B-tree reference in the same run is **3.326x**, with a minimum of **2.997x** across the eight profiles. Fx / Fx reaches 2.956x in this run. Absolute times, especially IPv6 mixed, vary from the original series; three repeats validate integration, not the absence of background-load or Balanced-power-plan effects. These figures do not establish kernel CPU reduction or latency.

The complete eight-candidate summary, 192 JSONL samples, environment/source hashes and integrity checks are kept locally and are not included in the repository. All 11 recorded benchmark executable/source/dependency hashes and ten driver source/build/image hashes matched the corresponding files after integration. Timing samples are unchanged. Build, test and benchmark logs are kept locally and excluded from version control.

### Pre-commit report cleanup

The report was translated into English. Processor and host hardware identifiers were removed from captured environment metadata and are no longer collected by the runner. The timed samples, numerical summaries, hit counts, metadata checksums and recorded source/executable hashes were not changed by this cleanup.
