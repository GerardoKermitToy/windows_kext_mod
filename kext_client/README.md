# kext_client

User-space client and console monitor for the Portmaster Windows kernel extension.

## Named-pipe bridge

Opening the driver also starts `duplex_pipe::Server` on
`\\.\pipe\WinNamedPipeDuplex.Service`. The server keeps the authorization rule
from `winrpc`: by default, only `pipe_client.exe` next to `kext_monitor.exe` is
trusted. The client must likewise start with `kext_monitor.exe` as its trusted
server path.

Each client `Data` message is passed to `Driver::SendCommand` with the original
pointer and size. The bridge does not decode, validate, combine, or modify client
commands, so every message must already contain one valid driver command.

Driver reads are still accumulated until a complete wire record is available:

```text
[InfoType: u8][payload size: u32 little-endian][payload]
```

While a client is connected, each complete record (including the five-byte
header) is sent in one `Server::Send` call and the local event handlers are not
invoked for it. If sending detects that the client disconnected, that record
falls back to the existing parser; subsequent records continue through the
normal local handlers until another client connects. The periodic `on_poll`
callback is independent of event dispatch and continues to run in both modes.

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

The monitor always writes `IgnoreSpecialPorts=1` as a `REG_DWORD` in
`HKLM\SYSTEM\CurrentControlSet\Services\PortmasterKext\Parameters` before starting
it. Ports `PM_DNS_PORT`, `PM_SPN_PORT`, and `PM_SPLIT_TUN_PORT` then use normal
connection processing instead of the driver's port-based special handling. This
is independent of `--no-inbound-udp-pid-fallback` and has no monitor opt-out flag.

The driver reads this value once at load. When started by another controller,
an absent/invalid value or any DWORD other than `1` preserves special handling.
See [the driver setting documentation](../windows_kext/IGNORE_SPECIAL_PORTS.md).

## Connection thread IDs

Displayed `CONN` records include `tid=...`. The monitor queries the driver's
`IOCTL_GET_THREAD_ID` before sending or scheduling a verdict, including when
`--no-verdicts` is active. Hidden connection records do not trigger this query.
A failed query is reported as a warning without withholding the verdict.

`Driver::GetThreadId(connection_id, thread_id, error)` returns the saved thread
ID for the `id` from a `CONN` record, not the driver's internal connection instance
ID. The event wire format and the named-pipe bridge are unchanged.

The driver snapshots the exact live connection generation's TID when publishing
CONN and indexes it by request ID. The IOCTL only reads this index under the packet
cache's existing lock: no packet/connection array search, allocation, or per-query
log record. Query before sending the verdict: the snapshot is discarded when
verdict processing finishes or the pending request is retired. Outbound UDP
requests retained after socket closure keep their snapshot until their verdict
finishes. A successful query returns `0` for an unknown, completed, or unattributed
request, including ID `0`.

The IOCTL is `CTL_CODE(40000, 0x802, METHOD_BUFFERED,
FILE_READ_DATA | FILE_WRITE_DATA)` (`0x9c40e008`). Input is an eight-byte
little-endian CONN ID; output is an eight-byte little-endian thread ID.
Input shorter than eight bytes fails with `STATUS_INVALID_PARAMETER`; output
shorter than eight bytes fails with `STATUS_BUFFER_TOO_SMALL`, without partial
output. A successful response contains exactly eight bytes.

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

`--no-verdicts` still disables automatic answers entirely. The option does not
change or delay raw commands submitted by a connected named-pipe client.

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
