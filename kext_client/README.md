# kext_client

User-space client and console monitor for the Portmaster Windows kernel extension.

## Direct driver delivery

`Driver::Open` opens the driver device directly. This client has no named-pipe
or RPC server, does not accept remote commands, and does not depend on `winrpc`.
Existing named-pipe clients can no longer attach to `kext_monitor.exe`.

Driver reads are accumulated until a complete wire record is available:

```text
[InfoType: u8][payload size: u32 little-endian][payload]
```

Every complete record is parsed locally and delivered to its optional
`Handlers` callback on the reader thread. The periodic `on_poll` callback
continues independently on `Run`'s thread. Bandwidth snapshots larger than the
former 64-MiB pipe-message limit are no longer skipped or diverted away from
`on_bandwidth`: the reader accumulates them across 64-KiB reads, just like other
records. The wire format, including its `u32` payload length, is unchanged.

`bandwidth_record_tests` covers IPv4/IPv6 and TCP/UDP snapshots immediately below
and above that former limit, including 2,396,745 IPv4 tuples or 1,290,555 IPv6
tuples in one record. It checks every tuple and both 64-bit counters, split
headers and payloads, exactly-once delivery, subsequent records, and empty
buffer state after dispatch. After building the client, run the suite from the
repository root:

```bash
ctest --test-dir kext_client/build -C Release --output-on-failure
```

## Monitor command-line interface selection

Use `--app PATH` with exactly one interface selector:

- `--interface INDEX_OR_ALIAS`: a nonzero decimal interface index, or the Windows
  adapter alias (for example, `wg0` or `Ethernet 2`). The monitor resolves
  it to a LUID using the documented IP Helper APIs.
- `--interface-luid LUID`: the native 64-bit LUID in decimal or `0x` hexadecimal.
  LUID zero removes an assignment. Other values must resolve to an existing
  interface.

```bash
./kext_client/build/kext_monitor.exe --duration 30 --app "C:/Apps/client.exe" --interface 76 ./windows_kext/portmaster-kext.sys
```

```bash
./kext_client/build/kext_monitor.exe --duration 30 --app "C:/Apps/client.exe" --interface "wg0" ./windows_kext/portmaster-kext.sys
```

One application is supported per monitor run. A relative Unicode application path
is resolved to an absolute path; the file and interface are checked before
`netsh` or service installation. The monitor does **not** launch the application.
After opening the device, it calls `SetAppInterface` over IOCTL and stops startup
on failure. The policy applies to new connections from every instance of that
executable path, including future instances, and is removed when the monitor
closes the device or exits. Existing connections are not migrated. Status output
is suppressed in `--process-events-only` mode; fatal diagnostics remain on stderr.

## Application interface policies

`pmkext::Driver::SetAppInterface(const std::wstring& path, uint64_t luid,
std::string& error, bool via_write = false)` installs an interface policy for
**every instance of the executable at that path**, not for a PID. Pass a fully
qualified Unicode executable filename and a native `NET_LUID::Value` (not an
interface index). LUID zero removes the assignment; removing a missing assignment
is successful and does not open a WFP session.

The client uses `FwpmGetAppIdFromFileName0` to resolve the filename to WFP's
canonical native application path. It sends that UTF-16LE blob unchanged: there
is no ANSI conversion, locale-dependent lowercase operation, or UTF-8 path on
the wire. The driver then applies Windows' native Unicode case mapping with
`RtlDowncaseUnicodeChar` before lookup and WFP insertion. This matters on the test
OS: `FwpmGetAppIdFromFileName0` preserved `Тест\\Приложение`, but ALE supplied
`тест\\приложение`; using the userspace blob verbatim did not match. Normalization
also makes replacement/removal use the same identity across case variants.
Low-level clients must perform the filename-to-native-path resolution too; a plain
DOS path is not a WFP app ID. Cyrillic, CJK, accented Latin characters, surrogate
pairs such as emoji, and Unicode case variants are covered by tests.

Both transports use the same payload:

```text
luid:        u64 little-endian
app_id_size: u32 little-endian (bytes, including the UTF-16 NUL terminator)
app_id:      app_id_size bytes of canonical UTF-16LE native path
```

- IOCTL `SetAppInterface`: `CTL_CODE(40000, 0x804, METHOD_BUFFERED,
  FILE_READ_DATA | FILE_WRITE_DATA)` = `0x9c40e010`. The payload is input-only;
  there is no output buffer or response body.
- `WriteFile`: byte `10` (`CommandType::SetAppInterface`), then that payload.
  The explicit app-ID byte size permits concatenating this variable-size command
  with other commands in one write. Commands before an invalid record remain
  applied, as with the existing fixed-size commands.

The driver rejects oversized paths (more than 65,534 bytes), odd byte counts,
missing or embedded NUL terminators, malformed UTF-16, and truncated payloads.
It calls the kernel `FwpmConnectionPolicyAdd0` with `FWPM_CONDITION_ALE_APP_ID`
and `FWP_NETWORK_CONNECTION_POLICY_NEXT_HOP_INTERFACE` (`FWP_UINT64`). IPv4 and
IPv6 policies are added, replaced, or removed in one WFP transaction. Failed
updates preserve the previous pair. Setting an unchanged assignment is a no-op.
WFP management failures are returned to the caller, rather than logged as success.

Policies belong to a separate dynamic WFP session. Device-handle cleanup or
shutdown closes it and removes all assignments. Process exit does **not** delete
a path policy: other instances may still be running or start later. No process
monitoring, timer, userspace decision, or new per-packet driver lookup is needed.
Updates are serialized at `PASSIVE_LEVEL`, never under a packet-path spin lock.

This uses the newer Windows 11 kernel connection-policy API (WDK guard
`NTDDI_WIN11_ZN`), which must be exported by the target OS. The driver directly
imports it; older Windows versions without those exports cannot load this build.
Interface selection is a routing policy for new connections, not a migration of
already-established flows. It does not apply to other executable paths, child
executables, or DNS requests made by a separate DNS service.

**Required OS setting:** route-policy evaluation is independently enabled for
IPv4 and IPv6. `FwpmConnectionPolicyAdd0` can succeed while this setting is
**disabled**, in which case the stack keeps using the normal route. Check
`netsh interface ipv4 show global` / `netsh interface ipv6 show global`.
To enable evaluation for the current boot (Administrator):

```bash
netsh interface ipv4 set global routepolicies=enabled store=active
```

```bash
netsh interface ipv6 set global routepolicies=enabled store=active
```

`kext_monitor` checks active IPv4 **and** IPv6 route policies before loading the
driver. Each family is queried independently through `NsiGetAllParameters`, linked
normally through `build/nsi.lib` generated from `src/nsi.def`; there is no manual
`LoadLibrary`/`GetProcAddress`. The library imports only this read-only query,
never an NSI setter. The IP global-table layout is a private Windows ABI: only a
successful exact-size query with the route-policy flag equal to `1` confirms that
evaluation is enabled. A disabled flag, unexpected value, incompatible layout, or
query error all mean "not confirmed".

For each unconfirmed family, the monitor enables evaluation through the system
`netsh.exe` using the corresponding command above. Confirmed families do **not**
launch netsh. The executable is selected from the Windows system directory and
launched directly without a shell or PATH lookup. Each command is idempotent;
netsh is the only configuration-writing path, with no NSI or registry writes.
Netsh output is suppressed so localized messages do not mix with monitor records.
Every attempted command must succeed; creation failures, nonzero exit codes, or
a 10-second timeout per child stop startup with a family-specific error before
loading the driver. A timed-out child is terminated. When NSI cannot confirm the
state, successful netsh completion is the fallback result; NSI compatibility is
not required for startup. The OS loader must provide the imported NSI query.
These are independent active-store changes: if IPv6 activation fails after IPv4
succeeds, IPv4 remains enabled.

Help, invalid arguments, a missing driver file, and a rejected duplicate instance
do not change these settings. Both stay enabled after the monitor exits; neither
change is persisted across reboot.

The driver and client library do not change this machine-wide setting, interface
metrics, or route tables. `store=active` does not persist across reboot; persistent
configuration is a separate administrator decision. Applications using only the
library still require explicit administrator configuration for both address
families. To restore a previously disabled active setting, use the same command
with `routepolicies=disabled`.

After building, the bounded Administrator-only runtime probe checks native WFP
objects, both command transports, replacement/removal, handle cleanup, and actual
TCP interface selection. It is deliberately **not** registered with offline CTest:

```bash
./kext_client/build/app_interface_runtime.exe --duration 30 ./windows_kext/portmaster-kext.sys --interface-address 10.94.59.5
```

The optional interface address selects a second adapter with a usable route.
The live probe makes short TCP connections to `1.1.1.1:443`, sends no application
data, and fails if the policy is stored but does not change the observed route.
Successful IOCTL completion proves policy installation, not successful egress:
OS support and a usable route on the selected interface remain necessary.

## Process lifecycle events

Loading the driver or opening its device does **not** start process collection.
After opening the device, explicitly request it with either:

- `DeviceIoControl(handle, 0x9c40e00c, nullptr, 0, nullptr, 0, ...)`:
  `StartProcessMonitoring`, `CTL_CODE(40000, 0x803, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)`.
  There is no input or output payload; completion reports success or failure.
  The removed GetThreadId IOCTL's `0x802` slot remains unused.
- `WriteFile(handle, "\x09", 1, ...)`: `CommandType::StartProcessMonitoring = 9`,
  with no payload. It also works in the existing concatenated-command format.

`pmkext::Driver::StartProcessMonitoring(error, via_write = false)` exposes both
paths. Every request, including a repeated IOCTL or write command, unregisters and
drains the previous callback, clears the internal inventory, then starts from a
fresh full snapshot. **Unread old records stay queued in order**, including any
partially read frame. No restart marker is added to the wire protocol.

On that explicit request, the driver registers a process callback and enumerates all live
system processes, including idle/system and protected processes. It keeps only
`pid -> parent_pid` entries, with no names, paths, or retained process objects.
Creation/exit notifications racing that initial enumeration are journaled and
replayed in order after the baseline, before publishing subsequent live events.
In live mode each callback enqueues its event immediately; there is no batching
wait, timer, or dependency on the monitor's `--poll` interval.

On disconnect the callback is removed and drained and the inventory is freed;
the next connection remains idle until its own explicit start request. Exiting a
parent does not remove or reparent its live children, so a stored parent PID need
not itself be alive. Process notifications include non-Win32 subsystem processes
and use the Windows 10 1703+ / Windows 11 notification API.

Once requested, the driver emits process batches on the same direct device stream as
connection records. `InfoType::ProcessCreated` is `9` and its payload is a packed,
count-free repetition of:

```text
pid: u64 little-endian
parent_pid: u64 little-endian
```

Its payload size must be a multiple of 16. `InfoType::ProcessTerminated` is `10`
and its payload is a packed, count-free repetition of:

```text
pid: u64 little-endian
```

Its payload size must be a multiple of 8. An empty payload is a valid empty batch
for either event. There is no count field, process path/name, snapshot marker, or
event subtype. Created records use the same upsert-shaped entry for the initial
snapshot and subsequent live creates, so consumers cannot distinguish those sources
from the wire data alone.

The client invokes the corresponding `Handlers` callback immediately from its reader
thread once a complete frame has arrived; it does not wait for `on_poll` or collect
process events across records. By default the console monitor does not request
process collection. `--process-events-only` explicitly issues the start IOCTL once
after opening the device and prints process lifecycle records:

```bash
./kext_client/build/kext_monitor.exe --duration 10 --process-events-only ./windows_kext/portmaster-kext.sys
```

To use the equivalent `WriteFile` command instead of the IOCTL:

```bash
./kext_client/build/kext_monitor.exe --duration 10 --process-events-only --process-events-write ./windows_kext/portmaster-kext.sys
```

To request another fresh snapshot periodically, use `--process-events-restart-ms N`
(`1..4294967295`). It requires `--process-events-only`, as does
`--process-events-write`. Restarts use the chosen transport and are checked at the
`--poll` cadence; live events still arrive immediately, independently of polling.
By default no periodic restart is requested.

```bash
./kext_client/build/kext_monitor.exe --duration 10 --poll 100 --process-events-only --process-events-restart-ms 2000 ./windows_kext/portmaster-kext.sys
```

The record output uses the normal `--timestamps` and `--out` machinery:

```text
[PROCESS_CREATE] pid=<u64> parent_pid=<u64>
[PROCESS_EXIT] pid=<u64>
```

`--process-events-only` opts into process collection, but connection parsing, verdicts,
delayed verdict scheduling, and optional delayed-verdict PID suspension/resume keep
running. It takes priority over `--only-logs` regardless of argument order and
suppresses normal connection, end, bandwidth, log, warning, startup, and final
statistics output where practical. Fatal startup errors remain visible on stderr.

In this mode `--filter-pid PID` compares only the event's `pid` (never
`parent_pid`). `--filter-ip`, `--filter-protocol`, and port portions of IP filters
do not apply to process events.

The bounded Administrator-only feature regression uses fresh output directories:

```bash
python -I windows_kext/test/process_events.py --output windows_kext/test/_out/process-events-run
```

It compares the initial inventory against stable `Win32_Process` entries, checks
parent/child and short-lived lifetimes, verifies event delivery with a 5-second
poll interval, and tests both display modes and TCP/UDP IPv4/IPv6 verdicts. It also
checks repeated snapshots via IOCTL and WriteFile. An Administrator-only native
probe checks that no process records arrive before the first request, pauses the
reader across two restarts to verify unread snapshots are retained, and verifies
that both command paths fail after shutdown. This probe is built with the client
but is not part of the offline CTest suite. Extra
IPv4/IPv6 UDP controls keep the same sockets exchanging 275-byte payloads across
monitor exit and driver unload. These are feature checks, not the complete
standard runtime suite: the legacy `IgnoreSpecialPorts=1` regression condition
cannot be exercised by the current redirect-free driver, which has no such setting.

## Inbound UDP PID fallback

By default, the monitor writes `EnableInboundUdpCacheMissPidFallback=1` as a
`REG_DWORD` in the driver's service `Parameters` key before starting it. To disable
this packet-layer fallback and keep native ALE authorization for inbound UDP
cache misses, use `--no-inbound-udp-pid-fallback`:

```bash
./kext_client/build/kext_monitor.exe --duration 10 --no-inbound-udp-pid-fallback ./windows_kext/portmaster-kext.sys
```

The flag writes `0`, overwriting any previous `1`. Without the flag, the monitor
writes `1` again. The driver reads the setting once at load; changing the registry
while it is running does not change its behavior. See
[the driver setting documentation](../windows_kext/INBOUND_UDP_PID_FALLBACK.md).

## Supported verdicts

`--verdict` accepts `accept`, `permanent-accept`, `block`, `drop`,
`permanent-block`, and `permanent-drop`. Traffic redirection is not supported.
Ports 53, 717, and 719 use the same exact-tuple lookup and filtering as other ports;
there is no special-port registry setting.

## Connection metadata

`ConnectionIpv4` uses `InfoType = 7`; `ConnectionIpv6` uses `InfoType = 8`.
Values `1` and `2` remain reserved for the legacy connection format and are not
parsed as the new events. Driver and client must be updated together. Other
InfoType values, including `ConnectionEnd`, are unchanged.

The connection payload has this field order, with no padding and all integers
little-endian:

```text
id: u64
process_id: u64
tid: u64
compartment_id: u32
condition_flags: u32
interface_index: u32
sub_interface_index: u32
direction: u8
protocol: u8
local_ip: [u8; 4 or 16]
remote_ip: [u8; 4 or 16]
local_port: u16
remote_port: u16
payload_layer: u8
payload_size: u32
payload: [u8; payload_size]
```

The fixed payload prefix is 59 bytes for IPv4 and 83 bytes for IPv6, excluding
the five-byte record header and captured packet bytes.

`CONN` output includes `tid=...` in its header and the routing fields with
`condition_flags=0x%08x` on a separate line. The driver snapshots the exact live connection generation's TID
when publishing the event. Existing outbound execution-context and ICMP echo
attribution still apply; an unavailable TID is `0`.

`Connection::condition_flags` contains the complete raw `FWP_CONDITION_FLAG_*`
mask from the current ALE or IP-packet classification, not flags cached from
an earlier event. Unknown bits are preserved; unavailable flags are `0`.
For example, bit `0x00000001` denotes loopback and bit `0x00000004` denotes
reauthorization where that flag applies to the layer. This extra `u32` shifts
all following fields by four bytes; earlier v3 clients without it are not
compatible even though the event IDs and `IOCTL_VERSION` are unchanged.

Routing values describe the current WFP indication, not an immutable route for
the connection. Unavailable metadata is `0`; interface and subinterface fields
can legitimately be zero at ALE layers. A zero value does not distinguish
unavailable metadata from a native zero.

TID, condition flags and routing metadata are part of the event even when the monitor hides it,
delays its verdict, or uses `--no-verdicts`. No extra IOCTL query is needed and
metadata does not depend on the pending request still existing. The former
GetThreadId IOCTL (`0x9c40e008`) and client method have been removed.

## Verdict delay

`--verdict-delay-ms N` waits `N` milliseconds before sending each automatic
connection verdict. The default is `0` (send immediately); accepted values are
unsigned decimal integers from `0` through `4294967295`.

For example, from the repository root:

```bash
./kext_client/build/kext_monitor.exe --duration 10 --verdict-delay-ms 250 ./windows_kext/portmaster-kext.sys
```

Each verdict has its own deadline measured from enqueue time. The reader keeps
processing events while verdicts wait, so a burst does not incur `N` additional
milliseconds per preceding verdict. With `--match`, the delay applies only to
connections matching its IP and optional port; connections outside the rule receive
`PermanentAccept` immediately. Without `--match`, all automatic verdicts are delayed.
Display filters affect neither rule matching nor the delay, even for hidden records.
Pending traffic waits for the verdict, so large delays can stall networking; use
`--duration` for unattended runs.

Delayed records show `scheduled after N ms`; successful sends later produce a
separate `[VERDICT] id=...` line. The final `verdicts sent` count includes only
successful sends, not scheduled verdicts. Stopping discards unsent verdicts without
waiting for their deadlines, and joins the sender before closing the device.

`--no-verdicts` still disables automatic answers entirely.

## Suspend processes during verdict delay

`--suspend-pid-on-verdict-delay` pauses the process identified by a `CONN` record
while its delayed verdict is pending. It is disabled by default and has no effect
when the delay is `0`, `--no-verdicts` is active, or the record does not match an
active `--match` rule. Display filters do not affect suspension.

For example, from the repository root:

```bash
./kext_client/build/kext_monitor.exe --duration 10 --verdict permanent-accept --match 192.168.219.15:9999 --verdict-delay-ms 250 --suspend-pid-on-verdict-delay ./windows_kext/portmaster-kext.sys
```

The monitor retains a process handle and makes one native suspension per live
process generation, shared by its pending delayed verdicts. Generation tokens keep
callbacks for an exited process separate from a later process that reuses its PID.
Each successful verdict write releases one hold; the process resumes only after
the last hold for that generation is released.
The log shows `[SUSPEND]`, `[VERDICT]`, and `[RESUME]` records in that order. Process
control records are shown even when the connection itself is hidden by filters.
A failed verdict write keeps its hold until monitor shutdown. A failed suspension
is reported as a warning and does not prevent the delayed verdict from being sent.

PID `0`, PID `4`, this monitor, and critical Windows processes are never suspended.
Access-denied/protected or exited processes are handled without reopening the PID
for resume. Processes created after the monitor observed the `CONN` are also skipped.
The event carries only a numeric PID, not a kernel process-start key: the initial
lookup is best-effort if the original process exits and its PID is reused before
the monitor receives the event. Identity is pinned once the handle is acquired.
Existing external suspension counts are not deliberately reset.
Graceful shutdown cancels queued verdicts, joins the sender, and restores all holds
owned by the monitor; failed resumes are reported and retried during cleanup.

Use a narrow `--match` and a bounded `--duration`: without `--match`, unrelated
processes can be paused. Forcibly terminating or crashing the monitor can leave
processes suspended, because closing a process handle does not resume its threads.

## Display filters

`kext_monitor.exe` supports composable display filters:

```text
--filter-ip IP[:PORT]
--filter-pid PID
--filter-protocol N
```

`--filter-protocol` accepts the numeric IP protocol value from 0 through 255
(for example: ICMP 1, TCP 6, UDP 17, ICMPv6 58). Active filters combine with
AND and affect output only; connection verdicts are still sent for records that
are hidden. PID filtering applies to connection and connection-end records, and to
the event PID of process records in `--process-events-only` mode (never its parent
PID). Bandwidth records contain no PID and are therefore hidden while `--filter-pid`
is active. Driver logs and warnings are never suppressed by these filters in normal
output modes.
