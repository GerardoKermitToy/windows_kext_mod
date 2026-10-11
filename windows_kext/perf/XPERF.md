# Profiling the Portmaster WFP Driver with xperf

## What Is Measured

Two independent sources of information are available:

1. **Kernel CPU sampling with call stacks** — where CPU time is spent, including Windows kernel work triggered by the driver. A normal release build with its matching PDB is sufficient.
2. **Optional driver ETW provider** — operation durations, invocation counts, and the kernel-visible round-trip time of a request to userspace. It is included only when building with `--features perf-etw`.

A normal build without the feature does not contain these instrumentation points, counters, or additional pending-request fields. In an instrumented build with the provider disabled, provider-state checks and the larger `PendingPacket` size remain. Enabling timing adds a relaxed atomic counter sharded by CPU; QPC reads and ETW writes occur only for selected invocations. **Measure absolute CPU performance without the feature first**, then investigate latency causes in a separate diagnostic run.

The instrumentation does not read additional NBL/packet headers, change verdicts, or use the driver logger, new locks, heap allocations, or floating-point operations. Static metadata and payloads on the kernel stack are accessible at DISPATCH_LEVEL. The provider is registered before callback admission opens and unregistered after rundown and destruction of the injection handles.

## Provider and Keywords

- Name: `Portmaster.Kext.Performance`
- GUID: `5af3e2b6-6a7b-4d89-98b5-5e7da86c328d`
- Level: `4` (Informational)
- TraceLogging: the ETL contains event and field names. No manifest installation / `wevtutil im` is required.

| Keyword | Purpose |
|---|---|
| `0x1` | Operation durations and exact invocation counters. Normally every 64th invocation per CPU/operation; Cleanup is always recorded. |
| `0x2` | Pending-request round trips. Stable sampling based on a hash of the request ID, approximately 1/64. |
| `0x4` | Modifier: disables sampling for the selected `0x1`/`0x2` events. Does not enable events on its own. |
| **`0x3`** | Recommended diagnostic mode: sampled timings + round trips. |
| `0x7` | All timings + all round trips. Use only for a short, separate run at a low load. |

Do not use an all-keywords mask by default: it also enables `0x4`, switching from sampled to full recording. Do not enable stack capture for every event from this provider: kernel sampling already collects stacks.

### Events

**Duration**

`Operation`, `Detail`, `StartQpc`, `DurationNs`, `Result`, `Flags`, `SampleEvery`, `Epoch`.

| Operation | Measured Boundary | Detail / Result / Flags |
|---|---|---|
| `1` Classify | Invocation of a specific WFP handler from the common trampoline, after admission and argument validation. | Detail = native `FWPS_LAYER_*` ID. Result = final `FWP_ACTION_*`; Flags = `FWPS_CLASSIFY_OUT.flags`. |
| `2` Verdict | Parsing the action, claiming the pending request, applying the verdict, preparing/submitting injection, and completing the pending guard. | Detail = request ID. Result = wire verdict. Flags: `0` pending request found; `1` already completed ID; `2` unknown ID; `3` invalid action; `4` stale dependent packet. |
| `3` Read | `Device::read`, including the read-stream lock, waiting for the event queue, and packing/delivering records. | Detail = initial read-buffer size. Result/Flags are unused. |
| `4` Cleanup | Processing `CleanEndedConnections` and the related lifecycle/ICMP sweeps. | Detail/Result/Flags are unused. |
| `5` Inject | `inject_verdict_packet`, including any reauthorization and handing the packet to the existing injection path. | Detail: `0` permit, `1` blocked/discard. Result: `0` successful submission/preparation, `1` synchronous error. |

`FWP_ACTION_BLOCK = 4097`, `FWP_ACTION_PERMIT = 4098`, `FWP_ACTION_CONTINUE = 8198`; `Flags & 1` means absorb. For example, BLOCK + ABSORB at the packet layer may represent the normal pending-verdict slow path rather than a final denial of traffic. Classify counts measure **WFP indications**, including reauthorization/self-injection, not application packets.

**RequestRoundTrip**

`RequestId`, `OwnerPid`, `Protocol`, `IpVersion`, `Verdict`, `StartQpc`, `DurationNs`, `SampleEvery`, `Epoch`.

Starts when the request ID is assigned **before** Info construction; ends when the verdict is received and the pending packet is claimed, **after** releasing the packet-cache lock. Includes Info construction, queues, ReadFile, userspace scheduling, policy/monitor processing, and WriteFile. Does not include subsequent verdict application or asynchronous reinjection delivery. No event is emitted for pending requests that have already been removed: this is neither a timeout histogram nor a counter of lost verdicts. Pending requests spanning an ETW enable-configuration change are also excluded.

**Counter**

`Operation`, `Detail`, `Calls`, `Epoch`: cumulative counts over the lifetime of the loaded driver, **only while keyword `0x1` is enabled**. Classify is split by layer; other operations are summed regardless of Detail. Counters are not multiplied by the sampling rate. Capture-state produces a concurrent snapshot; the final snapshot after rundown is exact. Differences between snapshots give interval counts; without an initial snapshot, the total includes warm-up and unrelated traffic.

**ProviderState**

`SchemaVersion`, `Phase`, `QpcFrequency`, `SampleEvery`, `EnabledKeywords`, `WriteFailures`, `Epoch`.

Phase: `1` enable/registration, `2` unload, `3` capture-state. `WriteFailures` is the number of negative EtwWrite statuses observed before this snapshot; it is **not** ETW Events Lost, which must be checked separately. `SampleEvery` here is the base sampling interval of 64; the actual interval is recorded in Duration/RequestRoundTrip (1 in full mode and for Cleanup).

Durations measure **elapsed wall time**, not CPU time: lock waits, preemption, interrupts/DPCs, and userspace delays also fall within the measured boundary. An outer span may include writes of inner ETW events. Writing the span's own closing event is excluded from DurationNs, but sampling/counters and other instrumentation overhead remain. The sum of nested Duration values is not CPU time; avoid double-counting.

Inject success means successful preparation/submission, **not confirmation of delivery**: WFP injection is asynchronous. Final delivery must be measured using your workload's counters; the existing monitor reports completion errors. ETW deliberately does not change completion ownership or packet lifetime.

## Preparation

You need the Windows Performance Toolkit (xperf + WPA), an **elevated administrator terminal**, free space on a local SSD, and the exact SYS/PDB pair for each build. The examples below are intended for **Git Bash**, opened as administrator on this machine. Variables must be set again in a second terminal.

### Building

Normal baseline build (release only):

```bash
cmd.exe //c "C:\portmaster_v3\windows_kext\build-signed.bat"
```

For a diagnostic run, use this instead:

```bash
cmd.exe //c "C:\portmaster_v3\windows_kext\build-signed.bat --features perf-etw"
```

The script passes the feature to cargo and performs the normal linking/signing steps. Do not use a debug build, `opt-level=0`, disabled inlining, or Driver Verifier when comparing release performance. `debug = 2`, `/DEBUG`, `/PROFILE`, and `/INCREMENTAL:NO` are already configured. Optimizations and ICF remain enabled: inline frames and folded functions can complicate attribution, but that is not a reason to change release code before measuring it.

Build the monitor if its current version does not match the source:

```bash
cmd.exe //c "C:\portmaster_v3\kext_client\build.bat"
```

### Unit Tests Before a Runtime Run (Optional)

Driver tests and separate TraceLogging schema / sampling checks in the WDK crate:

```bash
(cd /c/portmaster_v3/windows_kext/driver && RUSTFLAGS="" cargo test --release --features perf-etw)
```

```bash
(cd /c/portmaster_v3/windows_kext/wdk && RUSTFLAGS="" cargo test --release --features perf-etw)
```

These unit tests do not load the driver or verify writing/decoding an actual ETW event. Runtime validation requires Duration / RequestRoundTrip / the final ProviderState to appear in WPA, with zero trace losses.

### Run Directory and Matching Symbols

Use a new directory for every run; change the name for the next recording:

```bash
XPERF='/c/Program Files (x86)/Windows Kits/10/Windows Performance Toolkit/xperf.exe'
```

```bash
RUN='C:/traces/pm-etw-01'
```

```bash
test ! -e "$RUN" && mkdir -p "$RUN/artifacts"
```

```bash
cp C:/portmaster_v3/windows_kext/portmaster-kext.sys C:/portmaster_v3/windows_kext/portmaster-kext.pdb "$RUN/artifacts/"
```

```bash
sha256sum "$RUN/artifacts/portmaster-kext.sys" "$RUN/artifacts/portmaster-kext.pdb" > "$RUN/artifacts/SHA256SUMS.txt"
```

Load this exact saved SYS copy and keep its matching PDB alongside it. Do not rebuild or replace the artifacts before stop/merge. A PDB built from "the same source" is not a substitute for one with matching GUID/age. Save the new pair again for the next run. Before starting, shut down the previous monitor normally: do not measure an already loaded driver from an older build or run two control-device owners at the same time.

Inspect existing trace sessions and the current sampling interval:

```bash
"$XPERF" -loggers
```

```bash
"$XPERF" -profint
```

Do not blindly stop other sessions with `xperf -stop`/`wpr -cancel`. If NT Kernel Logger is already in use, finish your own previous recording first or coordinate with its owner. The usual interval is 10000 units of 100 ns, or 1 ms. Record the actual value: a script must not silently change the global profile interval. In a VM, the PROFILE source may sometimes return `0x32` (not supported); this is not a reason to change security policy. You can capture CSwitch/ETW, but that is not a sampled CPU profile and is not a substitute for one.

## A. Lightweight CPU Profile — The First and Primary Measurement

Use a normal build **without** `perf-etw`. Do not add CSwitch stacks, pool tracing, or packet capture to the first run:

```bash
"$XPERF" -on PROC_THREAD+LOADER+PROFILE -stackwalk Profile -BufferSize 256 -MinBuffers 128 -MaxBuffers 256 -ClockType PerfCounter -f "$RUN/kernel.raw.etl"
```

Run the duration-bounded monitor and your own workload in another terminal. Recommended order: trace → monitor → 3–5 s warm-up → 15–30 s of a fixed workload → wait for the monitor to exit normally → stop/merge. In WPA, select **only the workload interval**; exclude load/unload/warm-up from comparisons.

After the monitor exits:

```bash
"$XPERF" -d "$RUN/driver.etl"
```

`-d` stops NT Kernel Logger and creates an analysis copy with image identification. Do not treat the raw trace as a replacement for the final merged ETL.

## B. CPU + Sampled Driver Events

Use a signed build with `perf-etw`. Start **both** sessions before loading the driver to preserve ProviderState and the initial image events:

```bash
"$XPERF" -on PROC_THREAD+LOADER+PROFILE -stackwalk Profile -BufferSize 256 -MinBuffers 128 -MaxBuffers 256 -ClockType PerfCounter -f "$RUN/kernel.raw.etl" -start PortmasterKextPerf -on 5af3e2b6-6a7b-4d89-98b5-5e7da86c328d:0x3:4 -BufferSize 64 -MinBuffers 64 -MaxBuffers 256 -ClockType PerfCounter -f "$RUN/driver.raw.etl"
```

In xperf terminology, this is a non-kernel session for the provider, even though the provider itself resides in the kernel driver. The GUID can be enabled before the provider registers.

Optional counter snapshot after warm-up or just before the workload ends (keep the same mask):

```bash
"$XPERF" -capturestate PortmasterKextPerf 5af3e2b6-6a7b-4d89-98b5-5e7da86c328d:0x3:4
```

**First wait for the monitor to exit normally and the driver to unload**, while the ETW sessions are still running. Otherwise, the final Counter / ProviderState Phase=2 events will be missing. Then stop only your two sessions and merge them immediately:

```bash
"$XPERF" -stop PortmasterKextPerf -stop "NT Kernel Logger" -d "$RUN/driver.etl"
```

To recreate the analysis copy from already stopped raw files on the original machine, with the original artifacts still in place:

```bash
"$XPERF" -merge "$RUN/kernel.raw.etl" "$RUN/driver.raw.etl" "$RUN/driver-merged.etl"
```

## C. Separate Short Wait/DPC Profile

If you need scheduler waits/lock stalls, repeat B in a **new directory** with this start command (RUN must already point to the new directory containing the artifacts):

```bash
"$XPERF" -on PROC_THREAD+LOADER+PROFILE+CSWITCH+DISPATCHER+DPC+INTERRUPT -stackwalk Profile+CSwitch+ReadyThread -BufferSize 256 -MinBuffers 256 -MaxBuffers 1024 -ClockType PerfCounter -f "$RUN/kernel.raw.etl" -start PortmasterKextPerf -on 5af3e2b6-6a7b-4d89-98b5-5e7da86c328d:0x3:4 -BufferSize 64 -MinBuffers 64 -MaxBuffers 256 -ClockType PerfCounter -f "$RUN/driver.raw.etl"
```

Use the same monitor, capture-state, and stop/merge sequence as in B. Record 5–10 s of representative workload: full CSwitch/ReadyThread stack walking is substantially more expensive than CPU sampling.

For full ETW recording, replace `:0x3:4` with `:0x7:4` in start/capturestate. This is another diagnostic run, not a baseline. First determine whether sampled mode is sufficient. p95/p99 from a sparse sample are not reliable tail estimates without enough samples; full mode at a reduced load helps inspect the distribution but changes the system being observed.

If PROFILE fails, you can remove `PROFILE` and `Profile` from the respective lists to capture waits/DPC/ETW, explicitly labeling the run as **without CPU sampling**. Do not automate a silent fallback.

## Monitor and Workload

**Always run `kext_monitor.exe` with `--duration`**. It creates/loads the service and normally unloads/removes it itself; `sc create` is unnecessary. Do not forcibly kill the monitor or use `sc stop` while the device handle is open. Before capture, choose a duration with enough headroom for warm-up and completion of your workload.

Do not disable verdicts (`--no-verdicts`): that artificially stalls pending traffic. By default, the monitor replies with PermanentAccept. For a separate pending/reinjection stress test, you can use temporary `--verdict accept`; results from these two modes are **not comparable**: Accept regularly takes the slow path, whereas PermanentAccept establishes a cached fast path.

Minimize connection/bandwidth output while preserving automatic verdicts (run in a separate elevated Git Bash; the SYS path is a **positional argument**):

```bash
C:/portmaster_v3/kext_client/build/kext_monitor.exe --duration 40 --poll 5000 --only-logs C:/traces/pm-etw-01/artifacts/portmaster-kext.sys
```

`--poll 5000` reduces periodic GetLogs/GetBandwidthStats requests but does not delay immediate verdicts from the reader thread. Exiting after the requested duration may be delayed by one poll interval; wait for the process to actually exit before stopping xperf. Change the SYS path if you use a different directory. This version has no `--quiet` or `--driver` option.

Do not use `--verdict-delay`, flush every record to a file, print every packet to the terminal, or use a heavyweight pipe consumer when measuring the driver's minimum cost. These costs increase round-trip time and should be assessed separately. Monitor display filters affect output only, not WFP policy or the number of kernel classifications. `--only-logs` / `--no-bandwidth` hide bandwidth output but **do not disable** RequestBandwidthStats: the current monitor continues requesting stats on every poll. Record both display options and the actual `--poll` value when comparing runs.

## Trace Quality Checks and WPA

Check both original session headers, not just the merged file:

```bash
"$XPERF" -i "$RUN/kernel.raw.etl" -a tracestats
```

```bash
"$XPERF" -i "$RUN/driver.raw.etl" -a tracestats
```

The second file does not exist for A. Save a report for the final trace:

```bash
"$XPERF" -i "$RUN/driver.etl" -o "$RUN/tracestats.txt" -a tracestats -detail
```

Comparable runs require **Events Lost / Buffers Lost = 0**. If events are lost, reduce verbosity/stacks, increase buffers, or shorten capture, then repeat. Provider `WriteFailures=0` does not replace checking ETW losses. BufferSize is specified in KB; Min/MaxBuffers are buffer counts. With 256 KB and 128–256 buffers, one kernel session uses approximately 32–64 MiB, and Windows may raise the minimum on a system with many processors. Avoid circular mode when comparing complete runs: it truncates the beginning and breaks the alignment of boundaries/counters.

For symbols, specify the local artifact directory first, followed by the Microsoft symbol server:

```bash
export _NT_SYMBOL_PATH="$RUN/artifacts;srv*C:/symbols*https://msdl.microsoft.com/download/symbols"
```

```bash
'/c/Program Files (x86)/Windows Kits/10/Windows Performance Toolkit/wpa.exe' "$RUN/driver.etl"
```

In WPA:

1. **Trace → Load Symbols**. Verify that `portmaster-kext.sys` resolves to functions from the current PDB, not just addresses. Check GUID/age when using an old symcache: do not accept cached names from a different binary.
2. **CPU Usage (Sampled)**: select the workload interval. Group by Process / Stack and look for **stacks containing `portmaster-kext.sys`**, not just driver leaf modules. `memcpy`, allocation, spin-lock waits, and WFP/NDIS work may appear in Windows modules below a driver frame. Driver code runs in the context of different applications, System, and the monitor; filtering only by the monitor PID excludes a substantial amount of work.
3. Compare inclusive stacks and exclusive CPU; do not sum overlapping inclusive frames. Analyze the ALE cached path separately from the IP packet slow path, verdict/closure processing, and cleanup.
4. **System Activity → Generic Events**: use Filter to Selection on `Portmaster.Kext.Performance`, then separate by Event Name. For Duration, group by Operation / Detail and inspect DurationNs and sample count. For RequestRoundTrip, use Protocol / IpVersion / OwnerPid / Verdict. `StartQpc` together with QpcFrequency helps align the measurement start with the overall timeline; the event's ETW timestamp corresponds to its completion.
5. **Counter**: use the final Phase=2 snapshot alongside ProviderState, or differences between capture-state snapshots. Counts help normalize driver work but do not replace your successful transaction/byte counts.
6. In mode C, add **CPU Usage (Precise)** and **DPC/ISR**. Classify may run inside a Windows networking DPC, so the absence of a separate driver DPC routine does not establish the absence of its CPU cost.

## Comparing Results

- Perform at least 3 identical runs; compare medians using matching warm-up and workload windows.
- Record SYS/PDB SHA256 hashes, commit + local diff, feature, keywords, profile interval, xperf flags, OS/VM/vCPU configuration, affinity/power settings, protocol/address family, worker/flow counts, payload size, verdict mode, and monitor configuration.
- Collect counts of **successful** operations and transferred bytes from the workload itself. Primary metrics: CPU-ms/successful operation, CPU-ms/MiB, throughput, and userspace latency. Process lifetime or CONN counts alone are insufficient to claim that performance improved.
- Separate steady cached traffic, large-scale TCP/UDP flow creation/closure, and temporary Accept/reinjection. Do not change the workload and driver feature at the same time.
- Do not combine pool/heap/full stacks/full ETW in one baseline: investigate causes using a separate capture.
- Preserve the merged ETL, both raw files (if present), the exact SYS/PDB pair, tracestats, the command/parameters, and workload results. ETL files may contain process names, paths, and other sensitive information; review them before publishing.

## Sources

- [Microsoft: recording TraceLogging and viewing Generic Events in WPA](https://learn.microsoft.com/en-us/windows/win32/tracelogging/tracelogging-record-and-display-tracelogging-events).
- [Microsoft: ETW methods, buffering, and image identification during merge](https://learn.microsoft.com/en-us/archive/blogs/ntdebugging/part-3-etw-methods-of-tracing).
- [Microsoft: wait analysis and CSwitch/ReadyThread stack walking](https://learn.microsoft.com/en-us/shows/defrag-tools/43-wpt-wait-analysis).
- [Microsoft: DPC/ISR measurement and monitoring lost events](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/example-15--measuring-dpc-isr-time).
- Exact start/stop/capturestate syntax was checked against the installed xperf `10.0.26100`, using `-help start`, `-help stop`, `-help query`, and `-help tracestats`.
