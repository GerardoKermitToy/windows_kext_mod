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

## Special ports

The monitor does not write `IgnoreSpecialPorts` in
`HKLM\SYSTEM\CurrentControlSet\Services\PortmasterKext\Parameters` and has no
command-line option for this setting. `--no-inbound-udp-pid-fallback` controls only
`EnableInboundUdpCacheMissPidFallback`; it does not change special-port handling.

The driver reads this value once at load. Only `REG_DWORD` value `1`
disables port-based special handling for `PM_DNS_PORT` (53), `PM_SPN_PORT` (717),
and `PM_SPLIT_TUN_PORT` (719), treating them as ordinary ports. An absent/invalid
value or any DWORD other than `1` preserves special handling, including when
started by the monitor. Changing the value while loaded has no effect until the
next driver load. See [the driver setting documentation](../windows_kext/IGNORE_SPECIAL_PORTS.md).

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

The fixed payload prefix is 55 bytes for IPv4 and 79 bytes for IPv6, excluding
the five-byte record header and captured packet bytes.

`CONN` output includes `tid=...` in its header and the three routing fields on a
separate line. The driver snapshots the exact live connection generation's TID
when publishing the event. Existing outbound execution-context and ICMP echo
attribution still apply; an unavailable TID is `0`.

Routing values describe the current WFP indication, not an immutable route for
the connection. Unavailable metadata is `0`; interface and subinterface fields
can legitimately be zero at ALE layers. A zero value does not distinguish
unavailable metadata from a native zero.

TID and routing metadata are part of the event even when the monitor hides it,
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
are hidden. PID filtering applies to connection and connection-end records.
Bandwidth records contain no PID and are therefore hidden while `--filter-pid`
is active. Driver logs and warnings are never suppressed by these filters.
