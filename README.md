# Modified Portmaster Windows Kernel Extension

This repository contains a modified version of the original Portmaster Windows Kernel Extension. **Version 3.0.0.0 is not API-compatible with the original Portmaster Windows Kernel Extension.** The driver and its user-mode client must both support the version 3 connection-event format described below.

The modified driver is implemented in Rust as a `no_std` KMDF non-PnP Windows network driver. It registers Windows Filtering Platform (WFP) callouts, intercepts IPv4 and IPv6 traffic, delegates packet decisions to a user-mode process, caches verdicts, blocks or redirects traffic, and collects TCP/UDP bandwidth statistics.

## API version and compatibility

The current API version is **3.0.0.0**, stored as `[3, 0, 0, 0]` in [windows_kext/kextinterface/version.txt](windows_kext/kextinterface/version.txt) and returned as four raw bytes by `IOCTL_VERSION`.

This is a **breaking API change**, not a drop-in replacement for the original driver or clients using the legacy connection-event layout:

- `ConnectionIpv4` now uses `info_type = 7`, and `ConnectionIpv6` uses `info_type = 8`. Values `1` and `2` remain reserved for the legacy format; the version 3 driver does not emit that format.
- Both connection events include `tid: u64`, `compartment_id: u32`, `interface_index: u32`, and `sub_interface_index: u32` immediately after `process_id`. Their fixed payload sizes are now 55 bytes for IPv4 and 79 bytes for IPv6.
- The former `IOCTL_GET_THREAD_ID` (`0x9C40E008`) and C++ `Driver::GetThreadId` method have been removed. Read `Connection::tid` directly from the decoded event; no per-request IOCTL lookup is needed.
- The device paths, five-byte event framing, command IDs and layouts, verdict values, and log, connection-end, and bandwidth event formats are unchanged. These unchanged parts do **not** make the complete API compatible with the original implementation.

Update the driver and client together. Clients must check `IOCTL_VERSION` and support the corresponding event IDs and layouts before processing traffic. A legacy client may reject or ignore the new decision requests and leave retained packets without verdicts. Unless stated otherwise, references to "the driver" below mean this modified version 3 implementation.

The driver and its user-mode controller operate as one system:

- `windows_kext/driver` — the driver and WFP callout handlers;
- `windows_kext/protocol` — the source of truth for the binary protocol;
- `windows_kext/wdk` and `windows_kext/c_helper` — wrappers around WDK, KMDF, WFP, and NDIS;
- `windows_kext/kextinterface` — legacy Go protocol reference and the shared driver-version file; its Go connection-event decoder has not been migrated to API version 3;
- `kext_client` — the C++ client library and `kext_monitor`, updated for API version 3.

The packet path through WFP is described in detail in [windows_kext/PacketFlow.md](windows_kext/PacketFlow.md). This document defines the complete external driver API: the control device, `ReadFile`/`WriteFile`, IOCTLs, commands, events, and enumeration values. Internal Rust functions are not part of the driver API.

## Key properties

The driver creates 16 WFP callouts:

- ALE authorization for outbound and inbound TCP/UDP connections over IPv4 and IPv6;
- ALE endpoint closure callouts for connection lifetime tracking;
- ALE flow-established callouts for PID attribution and flow lifetime tracking;
- stream and datagram callouts for TCP/UDP bandwidth statistics;
- inbound and outbound IP packet callouts for IPv4 and IPv6.

A new packet without a permanent cached decision is blocked and retained until the user-mode process responds. User mode receives a `ConnectionIpv4` or `ConnectionIpv6` event with a unique request ID and responds with a `Verdict` command. An accepted packet clone is then returned to the network stack asynchronously through a WFP injection API.

`Permanent*` in a verdict name means that the decision remains cached for the lifetime of that specific connection-cache instance. It does not create a global firewall rule. A new connection that reuses the same five-tuple after the old connection ends must receive a new decision.

## Registry settings

The driver supports two optional `REG_DWORD` values under:

```text
HKLM\SYSTEM\CurrentControlSet\Services\PortmasterKext\Parameters
```

Only a DWORD value of exactly `1` enables an option. A missing value, a different registry type, malformed data, or any other DWORD value leaves it disabled. Both options are read **once in `DriverEntry`, before WFP filtering starts**. The driver does not monitor registry changes; a change takes effect only after unloading and reloading the driver, not after reopening the device or clearing the cache.

| Value name | Driver default when absent |
|---|---:|
| `EnableInboundUdpCacheMissPidFallback` | `0` (disabled) |
| `IgnoreSpecialPorts` | `0` (disabled) |

These registry options do not add commands or change the driver wire protocol.

### `EnableInboundUdpCacheMissPidFallback`

With this option enabled, an inbound IPv4 or IPv6 UDP packet that misses the normal connection-cache lookup can borrow a PID from the first active UDP entry matching `(local_ip, local_port, remote_ip)` in the same IP family. The donor's `remote_port` is ignored. If several entries match, the first active match is used; this is heuristic PID attribution, not proof of the packet's socket owner.

If no match exists, or the selected PID is `0` or `4`, the packet proceeds to native `ALE_AUTH_RECV_ACCEPT` authorization. Disabling the option preserves this ALE path for inbound UDP cache misses. Exact cache hits are unchanged.

A successful fallback creates a separate inbound cache entry for the packet's **exact five-tuple**, with the borrowed PID, TID `0`, and its own initially `Undecided` policy and connection-instance ID. It does not copy the donor's verdict or lifetime, and it does not overwrite an exact entry registered concurrently. The user-mode decision request contains network-layer bytes (`payload_layer = 3`); a `PermanentAccept` or another permanent verdict is cached for this new exact instance, so later packets with the same tuple can reuse it in either direction.

Until associated with a native UDP endpoint, the heuristic entry is eligible for expiration after 60 seconds of inactivity during `CleanEndedConnections`. Once native lifecycle tracking is attached, endpoint closure governs its lifetime instead.

See [windows_kext/INBOUND_UDP_PID_FALLBACK.md](windows_kext/INBOUND_UDP_PID_FALLBACK.md) for matching and cache-lifecycle details.

### `IgnoreSpecialPorts`

Despite its name, setting this option to `1` does **not** exempt traffic on special ports from filtering. It disables the historical port-based packet bypasses and reverse-redirect cache lookup. Such packets use ordinary exact-tuple cache lookup and policy handling instead of receiving an implicit exception or being matched to another connection through the special-port reverse lookup.

When `IgnoreSpecialPorts = 0`, the following historical shortcuts remain active for IPv4 and IPv6:

| Shortcut | Condition |
|---|---|
| Automatic packet permit | Local and remote IP addresses are equal, and the **local port** is `53` (DNS), `717` (tunnel), or `719` (split tunnel) |
| DNS reverse-redirect lookup | The **remote port** is `53` and the remote address is the IP family's loopback address |
| Tunnel reverse-redirect lookup | The **remote port** is `717` and local and remote IP addresses are equal |
| Split-tunnel reverse-redirect lookup | The **remote port** is `719` and local and remote IP addresses are equal |

The port conditions can match TCP or UDP and apply in either packet direction. They use the cache-normalized local/remote endpoints, not fixed source/destination positions: the local port is the source port outbound and the destination port inbound. There is no blanket bypass for all traffic whose remote port is one of these special ports. Reverse lookup searches redirect aliases within the same protocol/local-port cache group.

Explicit redirect verdicts remain available with `IgnoreSpecialPorts = 1`, including forward address/port rewriting, but special-port reverse-redirect lookup is disabled; clients relying on the historical reply-matching behavior must account for this setting.

See [windows_kext/IGNORE_SPECIAL_PORTS.md](windows_kext/IGNORE_SPECIAL_PORTS.md) for the affected ports and matching rules.

## Device access

| Property | Value |
|---|---|
| NT device name | `\Device\PortmasterKext` |
| Win32 path | `\\.\PortmasterKext` |
| Control-device type | `FILE_DEVICE_NETWORK` |
| I/O mode | Buffered I/O |
| Required access | `GENERIC_READ | GENERIC_WRITE` |
| Share mode | `0` |
| ACL | Full access for `SYSTEM` and Administrators only |
| Concurrent clients | One open file object |

A second concurrent `CreateFile` request fails with `STATUS_SHARING_VIOLATION`. The driver records the PID that owns the handle and uses it when applying policy to Portmaster's own traffic.

For full-duplex communication, open the handle with `FILE_FLAG_OVERLAPPED`. Without this flag, a waiting `ReadFile` serializes I/O on the file object and can prevent another thread from executing `WriteFile` or `DeviceIoControl`. Every operation on an overlapped handle must use its own `OVERLAPPED` structure. A client should also serialize writes when commands may be sent by multiple threads.

Example:

```cpp
HANDLE device = CreateFileW(
    L"\\\\.\\PortmasterKext",
    GENERIC_READ | GENERIC_WRITE,
    0,
    nullptr,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
    nullptr);
```

Use a single reader thread. `ReadFile`, `WriteFile`, and all IOCTL handlers require `PASSIVE_LEVEL` inside the driver.

## Wire-format conventions

- The protocol is binary and contains no alignment padding.
- Every multi-byte integer is encoded in little-endian order.
- IPv4 and IPv6 addresses are transmitted as 4 or 16 raw bytes in network order, as they appear in an IP packet.
- Ports are numeric `u16` values encoded in little-endian order on the wire.
- `protocol` is an IANA IP protocol number, such as TCP `6`, UDP `17`, ICMP `1`, or ICMPv6 `58`.
- `local_*` identifies the local endpoint and `remote_*` identifies the remote endpoint; these fields are not necessarily the source and destination of the current packet.
- The command and event streams are independent. Unless an IOCTL explicitly returns output, accepting a command does not produce a synchronous response.

## Reading events with `ReadFile`

The driver exposes a byte stream of records. Every record begins with the same five-byte header:

```text
Offset  Size  Field
0       1     info_type
1       4     payload_size (u32 LE)
5       N     payload
```

`payload_size` excludes the five-byte header.

One `ReadFile` call may return:

- multiple complete records;
- one or more complete records followed by the start of another record;
- an arbitrary fragment of one record.

A client must accumulate bytes until it has a complete header and then wait for all `5 + payload_size` bytes. `ReadFile` boundaries are not record boundaries. An unknown `info_type` can be skipped using its declared payload length.

When no event is available, the read waits. During shutdown, an already waiting read can complete as cancelled, while a new read after admission has closed can complete as EOF. A client should treat `STATUS_CANCELLED`/`ERROR_OPERATION_ABORTED` and `STATUS_END_OF_FILE`/`ERROR_HANDLE_EOF` as normal session termination, wait for every pending `OVERLAPPED` operation to complete, and only then release its buffer.

### Event types

| `info_type` | Name | Payload |
|---:|---|---|
| `0` | `LogLine` | Severity and message text |
| `1`, `2` | Reserved | Legacy connection formats; not emitted by the version 3 driver |
| `3` | `ConnectionEndEventV4` | IPv4 connection ended |
| `4` | `ConnectionEndEventV6` | IPv6 connection ended |
| `5` | `BandwidthStatsV4` | IPv4 bandwidth counters |
| `6` | `BandwidthStatsV6` | IPv6 bandwidth counters |
| `7` | `ConnectionIpv4` | IPv4 packet-decision request with thread and routing metadata |
| `8` | `ConnectionIpv6` | IPv6 packet-decision request with thread and routing metadata |

### `ConnectionIpv4` (`info_type = 7`)

The fixed payload is 55 bytes, followed by the captured packet bytes. Offsets are relative to the payload, excluding the five-byte record header:

| Offset | Size | Field | Description |
|---:|---:|---|---|
| `0` | 8 | `id` | Request ID for a `Verdict` command; `0` is reserved as invalid |
| `8` | 8 | `process_id` | Attributed PID, or `0` when it cannot be determined |
| `16` | 8 | `tid` | Captured Windows thread ID (`u64`), or `0` when unavailable |
| `24` | 4 | `compartment_id` | WFP network compartment ID (`u32`), or `0` when unavailable |
| `28` | 4 | `interface_index` | Interface index for the WFP indication (`u32`) |
| `32` | 4 | `sub_interface_index` | Subinterface index for the WFP indication (`u32`) |
| `36` | 1 | `direction` | Direction of the packet being decided |
| `37` | 1 | `protocol` | IP protocol number |
| `38` | 4 | `local_ip` | Local IPv4 address |
| `42` | 4 | `remote_ip` | Remote IPv4 address |
| `46` | 2 | `local_port` | Local port, or `0` for a protocol without ports |
| `48` | 2 | `remote_port` | Remote port, or `0` for a protocol without ports |
| `50` | 1 | `payload_layer` | Layer represented by the captured bytes |
| `51` | 4 | `captured_length` | Number of bytes that follow |
| `55` | N | `captured_bytes` | Captured packet bytes |

A valid payload length is `55 + captured_length`. A complete framed record is `5 + 55 + captured_length` bytes.

### `ConnectionIpv6` (`info_type = 8`)

The fixed payload is 79 bytes. The metadata prefix and its offsets are identical to IPv4; the larger addresses shift the following fields:

| Offset | Size | Field | Description |
|---:|---:|---|---|
| `0` | 8 | `id` | Request ID for a `Verdict` command |
| `8` | 8 | `process_id` | Attributed PID, or `0` when unknown |
| `16` | 8 | `tid` | Captured Windows thread ID (`u64`), or `0` when unavailable |
| `24` | 4 | `compartment_id` | WFP network compartment ID (`u32`), or `0` when unavailable |
| `28` | 4 | `interface_index` | Interface index for the WFP indication (`u32`) |
| `32` | 4 | `sub_interface_index` | Subinterface index for the WFP indication (`u32`) |
| `36` | 1 | `direction` | Direction of the packet being decided |
| `37` | 1 | `protocol` | IP protocol number |
| `38` | 16 | `local_ip` | Local IPv6 address |
| `54` | 16 | `remote_ip` | Remote IPv6 address |
| `70` | 2 | `local_port` | Local port, or `0` |
| `72` | 2 | `remote_port` | Remote port, or `0` |
| `74` | 1 | `payload_layer` | Layer represented by the captured bytes |
| `75` | 4 | `captured_length` | Number of bytes that follow |
| `79` | N | `captured_bytes` | Captured packet bytes |

A valid payload length is `79 + captured_length`. A complete framed record is `5 + 79 + captured_length` bytes.

#### Connection-event field semantics

`direction`:

| Value | Name | Meaning |
|---:|---|---|
| `0` | `Outbound` | The packet is traveling from the local endpoint outward |
| `1` | `Inbound` | The packet is traveling toward the local endpoint |

In a connection event, this is the effective direction of the packet being decided. In a connection-end event, it is the connection direction stored when that connection was registered.

`payload_layer`:

| Value | Layer | Contents of `captured_bytes` |
|---:|---|---|
| `3` | Network | Bytes beginning with the IP header |
| `4` | Transport/ALE | Transport-layer bytes; the initial outbound TCP connect normally has no captured payload |

A connection event is a decision request, not a guarantee of one event per logical connection. While a decision is temporary or the connection remains `Undecided`, multiple packets with the same five-tuple can receive distinct IDs. A WFP indication containing multiple `NET_BUFFER` objects is split into one event and one request ID per packet. Every nonzero ID should receive exactly one `Verdict`, even when a UI or display filter hides the event.

`tid` is included directly in every version 3 connection event. For connection-associated requests, publication snapshots the TID from the exact live cache generation. For outbound TCP/UDP ALE attribution, a TID is captured only when the PID is neither unknown/System (`0` or `4`) nor the controller owning the driver handle; existing outbound execution-context and ICMP echo attribution also apply. An unavailable TID is `0`. The value is attributed to the observed request or connection and is not necessarily the thread that sent each subsequent packet. It is not the monitor's reader thread. No IOCTL query is required, and consuming or retiring the request does not invalidate metadata already carried by its event.

`compartment_id`, `interface_index`, and `sub_interface_index` describe the current WFP indication, not an immutable route for the connection. They are copied from ALE classification data or the packet-layer routing snapshot. Unavailable values are encoded as `0`; interface and subinterface indices may legitimately be zero at ALE layers. The format has no presence mask, so a native zero and unavailable metadata cannot be distinguished.

The C++ client exposes these fields as `Connection::tid`, `Connection::compartment_id`, `Connection::interface_index`, and `Connection::sub_interface_index`. `kext_monitor` prints `tid` in the `CONN` header and the three routing fields on a separate line. Metadata is carried by the event regardless of display filters, delayed verdicts, or `--no-verdicts`. Connection-end records do not include these four fields and retain their existing format.

A successful `WriteFile` for a verdict means that the driver accepted the command; it does not confirm delivery of the reinjected packet. WFP injection completes asynchronously, and a final injection failure is written to the driver's log ring. Independent UDP reinjections do not form a FIFO contract, so this API does not guarantee the delivery order of accepted UDP datagrams.

### `ConnectionEndEventV4` (`info_type = 3`)

The payload is 22 bytes:

| Offset | Size | Field |
|---:|---:|---|
| `0` | 8 | `process_id` |
| `8` | 1 | `direction` |
| `9` | 1 | `protocol` |
| `10` | 4 | `local_ip` |
| `14` | 4 | `remote_ip` |
| `18` | 2 | `local_port` |
| `20` | 2 | `remote_port` |

### `ConnectionEndEventV6` (`info_type = 4`)

The payload is 46 bytes:

| Offset | Size | Field |
|---:|---:|---|
| `0` | 8 | `process_id` |
| `8` | 1 | `direction` |
| `9` | 1 | `protocol` |
| `10` | 16 | `local_ip` |
| `26` | 16 | `remote_ip` |
| `42` | 2 | `local_port` |
| `44` | 2 | `remote_port` |

An end event has no request ID. It reports that a particular observed connection instance ended, identifying it by tuple, PID, and direction. The event can be generated by a native WFP endpoint/flow lifecycle signal or by periodic expiration of fallback state that has no native identity.

### `LogLine` (`info_type = 0`)

```text
Offset  Size  Field
0       1     severity
1       N     UTF-8 message without a terminating NUL
```

| `severity` | Name |
|---:|---|
| `1` | `Trace` |
| `2` | `Debug` |
| `3` | `Info` |
| `4` | `Warning` |
| `5` | `Error` |
| `6` | `Critical` |
| `7` | `Disabled` |

The current release configuration records messages at `Warning` severity and above. The ring holds 1,024 messages and overwrites the oldest message when full. `LogLine` records enter the output stream only after a `GetLogs` command drains the accumulated messages from the ring.

### `BandwidthStatsV4` (`info_type = 5`)

```text
Offset  Size  Field
0       1     protocol
1       4     entry_count (u32 LE)
5       ...   entry[entry_count]
```

Each IPv4 entry is 28 bytes:

| Offset within entry | Size | Field |
|---:|---:|---|
| `0` | 4 | `local_ip` |
| `4` | 2 | `local_port` |
| `6` | 4 | `remote_ip` |
| `10` | 2 | `remote_port` |
| `12` | 8 | `transmitted_bytes` |
| `20` | 8 | `received_bytes` |

The total payload length is `5 + entry_count * 28`.

### `BandwidthStatsV6` (`info_type = 6`)

The payload header is identical. Each IPv6 entry is 52 bytes:

| Offset within entry | Size | Field |
|---:|---:|---|
| `0` | 16 | `local_ip` |
| `16` | 2 | `local_port` |
| `18` | 16 | `remote_ip` |
| `34` | 2 | `remote_port` |
| `36` | 8 | `transmitted_bytes` |
| `44` | 8 | `received_bytes` |

The total payload length is `5 + entry_count * 52`.

One `GetBandwidthStats` command can enqueue up to four records: TCPv4, TCPv6, UDPv4, and UDPv6. Empty sets are not emitted. Each request atomically takes the current maps, so values represent bytes accumulated since the previous request:

- TCP counters contain stream-data lengths;
- UDP counters contain datagram payload lengths excluding the UDP header;
- `transmitted_bytes` is outbound traffic;
- `received_bytes` is inbound traffic.

Bandwidth records do not contain a PID.

## Writing commands with `WriteFile`

Every command begins with a one-byte `command_type`. There is no common length field because each command type has a fixed payload size.

One `WriteFile` call may contain several complete commands concatenated in order. A command cannot be split across separate `WriteFile` calls: an incomplete payload is invalid. An empty write, an unknown type, or a truncated command completes with `STATUS_INVALID_PARAMETER`.

Commands are applied in buffer order. If a later command in the same buffer is invalid, every preceding command has already taken effect, and `IoStatus.Information` contains the byte offset of the invalid command. On complete success, the consumed length equals the complete input-buffer length.

| `command_type` | Name | Payload | Total size |
|---:|---|---:|---:|
| `0` | `Shutdown` | None | 1 |
| `1` | `Verdict` | 9 bytes | 10 |
| `2` | `UpdateV4` | 14 bytes | 15 |
| `3` | `UpdateV6` | 38 bytes | 39 |
| `4` | `ClearCache` | None | 1 |
| `5` | `GetLogs` | None | 1 |
| `6` | `GetBandwidthStats` | None | 1 |
| `7` | `PrintMemoryStats` | None | 1 |
| `8` | `CleanEndedConnections` | None | 1 |

### `Shutdown` (`command_type = 0`)

This command has no payload and performs the same shutdown operation as `IOCTL_SHUTDOWN_REQUEST`:

- closes admission for new WFP classifications;
- releases a waiting read;
- resolves every packet still waiting for a verdict as fail-closed;
- clears endpoint state required for an orderly unload.

This is the final command for the current driver instance. It does not unload the service itself. After it completes, the client must wait for read completion, close the device handle, and only then stop the service. Reusing the session after `Shutdown` is unsupported.

### `Verdict` (`command_type = 1`)

Payload:

| Offset | Size | Field |
|---:|---:|---|
| `0` | 8 | `id` (`u64 LE`) |
| `8` | 1 | `verdict` |

`id` must identify a still-pending `ConnectionIpv4` or `ConnectionIpv6` event. An unknown or already consumed ID does not fail `WriteFile`: the command completes successfully, but the driver writes `Verdict invalid id` to its log ring. An invalid numeric `verdict` completes with `STATUS_INVALID_PARAMETER` and does not consume the pending packet.

| Value | Name | Semantics |
|---:|---|---|
| `0` | `Undecided` | Internal initial state; as a response it does not admit the current packet and leaves the connection requiring later decisions |
| `1` | `Undeterminable` | Fail closed without new requests while the cache instance remains alive |
| `2` | `Accept` | Admit only the current retained packet; later packets require another decision |
| `3` | `PermanentAccept` | Admit the current and later packets for this cache instance |
| `4` | `Block` | Block the current packet; the decision is temporary and a later packet can create another request |
| `5` | `PermanentBlock` | Hard-block the current and later packets for this cache instance |
| `6` | `Drop` | Silently absorb the current packet; the decision is temporary |
| `7` | `PermanentDrop` | Silently absorb later packets for this cache instance |
| `8` | `RedirectNameServer` | Redirect TCP/UDP traffic to loopback port `53` |
| `9` | `RedirectTunnel` | Redirect TCP/UDP traffic to the local address on port `717` |
| `10` | `Failed` | Fail closed, representing a persistent policy-decision failure |
| `11` | `RedirectSplitTunnel` | Redirect TCP/UDP traffic to the local address on port `719` |

Redirect verdicts are cached for the connection. Outbound packets receive a rewritten destination address and port with recalculated IP/TCP/UDP checksums. With `IgnoreSpecialPorts = 0`, the historical reverse-redirect lookup allows reply traffic to be rewritten back so that the application continues to observe the original remote endpoint. `IgnoreSpecialPorts = 1` disables this lookup, as described in [Registry settings](#ignorespecialports). Redirects are meaningful only for a live TCP/UDP cache instance. If redirect state is unavailable or a packet cannot be rewritten safely, the packet is dropped and an error is recorded in the log ring.

For a stateless packet with no connection instance, such as some ICMP traffic or externally injected traffic observed after the original endpoint closed, the verdict applies only to the specified request ID. Even `PermanentAccept` does not create a persistent entry for later stateless packets.

### `UpdateV4` (`command_type = 2`)

Changes the verdict of an existing live IPv4 connection selected by its exact five-tuple:

| Offset | Size | Field |
|---:|---:|---|
| `0` | 1 | `protocol` |
| `1` | 4 | `local_address` |
| `5` | 2 | `local_port` |
| `7` | 4 | `remote_address` |
| `11` | 2 | `remote_port` |
| `13` | 1 | `verdict` |

### `UpdateV6` (`command_type = 3`)

| Offset | Size | Field |
|---:|---:|---|
| `0` | 1 | `protocol` |
| `1` | 16 | `local_address` |
| `17` | 2 | `local_port` |
| `19` | 16 | `remote_address` |
| `35` | 2 | `remote_port` |
| `37` | 1 | `verdict` |

Both update commands:

- accept the same verdict values as `Verdict`;
- update only the current live entry and never mutate retained ended history;
- are successful no-ops when no matching tuple exists;
- do not answer a pending request ID;
- reset the resettable ALE filters after the update so that an existing flow is reauthorized against the new policy.

There is no response event or separate indication that the tuple was found.

### `ClearCache` (`command_type = 4`)

Clears the IPv4 and IPv6 connection caches and the TCP and UDP endpoint caches, reconciles remaining UDP lifecycle state, and resets the resettable ALE filters. It does not emit `ConnectionEnd` events for removed entries.

`ClearCache` does not clear pending request IDs, bandwidth maps, the ICMP echo cache, or the log ring. A client can still receive request IDs that were published before the clear. A late verdict cannot be applied to a new connection that reused the old tuple.

### `GetLogs` (`command_type = 5`)

Takes all currently accumulated messages from the log ring and enqueues their `LogLine` records. Delivery is asynchronous through `ReadFile`, with no end-of-list marker. Messages written after the snapshot remain in the ring until the next `GetLogs` request.

### `GetBandwidthStats` (`command_type = 6`)

Takes the accumulated TCP/UDP maps and enqueues nonempty `BandwidthStatsV4` and `BandwidthStatsV6` records. There is no end-of-response marker, and bandwidth records can be interleaved with connection and log events.

### `PrintMemoryStats` (`command_type = 7`)

First performs bounded maintenance of unestablished TCP state, then writes diagnostic sizes to the log ring for:

- the pending-packet cache;
- the IPv4 and IPv6 connection caches;
- untracked connection-cache entries;
- all four bandwidth maps;
- the TCP endpoint cache and pending closures;
- UDP endpoints and peers;
- UDP flow registrations and callbacks;
- the ICMP echo cache.

The statistics are generated as log lines and do not enter the output stream by themselves. Send `GetLogs` afterward to receive them. Both commands can be sent in one write as the bytes `[7, 5]`.

### `CleanEndedConnections` (`command_type = 8`)

Performs periodic state maintenance:

- removes ended history after its 60-second grace period;
- ends untracked packet-layer fallback connections, including heuristic inbound UDP entries created by `EnableInboundUdpCacheMissPidFallback`, after 60 seconds of inactivity and emits their end events;
- ends local TCP authorizations that have not reached `FLOW_ESTABLISHED` within 10 seconds;
- reconciles stale UDP endpoint and flow registrations;
- removes expired ICMP echo mappings.

The user-mode client is responsible for sending this command periodically. The driver does not run this periodic sweep autonomously.

## IOCTL API

All control codes use:

```text
CTL_CODE(40000, function, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
```

The device handle must therefore have both read and write access.

| Code | Numeric value | Input | Output | Description |
|---|---:|---:|---:|---|
| `IOCTL_VERSION` | `0x9C40E000` | None | Exactly 4 bytes | Wire-interface version |
| `IOCTL_SHUTDOWN_REQUEST` | `0x9C40E004` | None | None | Final driver shutdown |

### `IOCTL_VERSION`

Returns the four raw bytes stored in [windows_kext/kextinterface/version.txt](windows_kext/kextinterface/version.txt). The current version is `[3, 0, 0, 0]`, conventionally displayed as **3.0.0.0**; the returned bytes are `03 00 00 00`. This version requires the connection-event IDs and layouts documented above and is not compatible with the original Portmaster Windows Kernel Extension. If the output buffer is shorter than four bytes, the request completes with `STATUS_BUFFER_TOO_SMALL` and returns no partial result.

### `IOCTL_SHUTDOWN_REQUEST`

Performs the same operation as the `Shutdown` command. The IOCTL provides a convenient out-of-band final request while an overlapped read is waiting. It has no output.

The former `IOCTL_GET_THREAD_ID` (`0x9C40E008`, function `0x802`) is not supported in version 3. Its per-request lookup has been removed; use the `tid` field in the connection event instead. Calling this removed IOCTL, like any other unknown IOCTL, completes with `STATUS_NOT_IMPLEMENTED`.

## Recommended client lifecycle

1. Configure any [registry settings](#registry-settings) before starting the kernel-driver service, or use an already installed release driver.
2. Open `\\.\PortmasterKext` with `GENERIC_READ | GENERIC_WRITE`, share mode `0`, and `FILE_FLAG_OVERLAPPED`.
3. Check `IOCTL_VERSION` and verify that the client supports the returned version before beginning protocol communication; version 3 requires `info_type` values `7`/`8` and the extended connection-event layouts.
4. Start one persistent overlapped read and assemble records independently of read boundaries.
5. Read TID and routing metadata directly from each connection event. Respond to every nonzero connection request ID with a verdict; no metadata IOCTL is needed. Display filters must not suppress verdicts.
6. Send `CleanEndedConnections` periodically and request logs or bandwidth statistics as needed.
7. To terminate, issue `IOCTL_SHUTDOWN_REQUEST` or the `Shutdown` command.
8. Wait for and reap the pending read, then close the device handle.
9. Stop the service only after closing the handle. A non-PnP driver cannot finish unloading while its control device remains open.

Do not forcibly terminate a controller with an open handle and then expect `sc stop` to complete: the service can remain in `STOP_PENDING`.

## C++ API (`kext_client`)

The [kext_client/include/PortmasterKext.h](kext_client/include/PortmasterKext.h) header provides the `pmkext` namespace and decoded `Connection`, `ConnectionEnd`, `LogLine`, `BandwidthEntry`, and `BandwidthStats` structures.

In addition to `process_id`, every decoded `Connection` exposes the version 3 metadata:

| Field | C++ type | Meaning |
|---|---|---|
| `tid` | `uint64_t` | Captured Windows thread ID, or `0` when unavailable |
| `compartment_id` | `uint32_t` | WFP network compartment ID, or `0` when unavailable |
| `interface_index` | `uint32_t` | Interface index for the current WFP indication |
| `sub_interface_index` | `uint32_t` | Subinterface index for the current WFP indication |

Read these members in `on_connection`; there is no `Driver::GetThreadId` method in this API. The decoder accepts connection events with types `7`/`8` and warns on the legacy types `1`/`2`. These are decoded C++ objects, not packed wire structs; use the wire layouts above rather than copying `sizeof(Connection)` bytes to or from the device. See [kext_client/README.md](kext_client/README.md#connection-metadata) for monitor output and client usage.

### `pmkext::Driver`

| Method | Purpose |
|---|---|
| `Driver(service_name)` | Constructs a controller; the default name is `PortmasterKext` |
| `Install(sys_path, error, inbound_udp_pid_fallback = true)` | Creates and starts a demand-start kernel service using an absolute path; writes `EnableInboundUdpCacheMissPidFallback` from the optional argument but does not write `IgnoreSpecialPorts`; an existing service is treated as a conflict |
| `Open(error)` | Opens the overlapped device handle and starts the named-pipe bridge server |
| `Run(handlers, poll_interval_ms)` | Reads and dispatches events until `Stop`; calls `on_poll` at the requested interval |
| `Stop()` | Signals `Run` and submits the shutdown IOCTL once |
| `GetVersion(out, error)` | Calls `IOCTL_VERSION` |
| `RequestShutdown(error)` | Calls `IOCTL_SHUTDOWN_REQUEST` |
| `SendVerdict(id, verdict, error)` | Encodes and sends a `Verdict` command |
| `RequestLogs(error)` | Sends `GetLogs` |
| `RequestBandwidthStats(error)` | Sends `GetBandwidthStats` |
| `RequestMemoryStats(error)` | Sends `PrintMemoryStats` |
| `RequestCleanEndedConnections(error)` | Sends the periodic maintenance command |
| `RequestClearCache(error)` | Sends `ClearCache` |
| `Cleanup()` | Closes the handle, stops only a service started by this object, and deletes only a service created by this object |

`Driver` is non-copyable, and its destructor calls `Cleanup()`.

`Handlers` contains optional callbacks:

- `on_connection(const Connection&)`;
- `on_connection_end(const ConnectionEnd&)`;
- `on_log(const LogLine&)`;
- `on_bandwidth(const BandwidthStats&)`;
- `on_warning(const std::string&)` for decoding and protocol warnings;
- `on_poll()` for periodic commands.

Event callbacks run on the reader thread, while `on_poll` runs on the thread that called `Run`. When a named-pipe client is connected to the bridge, complete raw driver records are forwarded to that client instead of being passed to the local event callbacks. The connected client is then responsible for returning verdicts.

The C++ class does not currently expose methods for `UpdateV4` or `UpdateV6`; these commands remain available through the raw driver protocol. The bundled Go reference still uses legacy connection-event IDs and layouts and must be migrated before it can serve as a version 3 controller.

The `ToString`, `PayloadLayerToString`, `ProtocolToString`, `DirectionToString`, `FormatIpv4`, and `FormatIpv6` helpers only format already decoded values.

## Building and testing

### Supported configuration and precautions

This build-and-run procedure is documented **only for Windows 11 Enterprise 26H2, x64**, with **UEFI Secure Boot enabled** and the **`CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners`** policy manually activated. It uses a custom UEFI Platform Key (PK), a signed Code Integrity policy, and a locally issued kernel-mode signing certificate. It is not a Microsoft/WHQL signing procedure, and it does not establish compatibility with other Windows releases or editions.

The driver supports **release builds only**. A debug build intentionally fails with a compile-time error. The target is fixed to `x86_64-pc-windows-msvc` with `panic=abort`.

> **Before changing the system:** use a development/test machine you administer, with local console access and a tested recovery USB. Back up Windows, the existing EFI policy, and the firmware's Secure Boot keys/databases (PK, KEK, db, and dbx), or establish a vendor-supported way to restore them. Save the BitLocker/device-encryption recovery key outside the machine and suspend protection for the planned firmware/boot changes according to your recovery procedure. An incorrect enforced policy or missing bootloader certificate can prevent Windows from starting. A signed policy is protected against tampering; removing its file is not a general rollback procedure. Review Microsoft's [signed-policy precautions](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/use-signed-policies-to-protect-appcontrol-against-tampering) before deployment.

**Check OS support before deploying anything:** the existing `REG_DWORD` value `CustomKernelSignerLockedEnabled` must be present under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Protected`. If it is absent, install the current Windows updates for Windows 11 Enterprise 26H2, reboot, and check again **before copying an enforced policy to EFI**. Do not create the value manually to substitute for missing OS support. If it remains absent, stop this procedure.

Install the [build prerequisites](#build-prerequisites) before starting: `signtool.exe` from the Windows SDK is already needed in step 2. The examples assume the checkout is `C:\portmaster_v3` and Windows is installed in `C:\Windows`.

Use **64-bit Windows PowerShell 5.1 as Administrator** for the certificate, ConfigCI, EFI, and verification commands below. The Windows PowerShell/ConfigCI commands are not Git Bash commands; do not substitute PowerShell 7 for this procedure. Stop at any error rather than continuing with incomplete output.

### Build prerequisites

Install the following software before configuring the policy or building the driver:

| Software | Required components and purpose |
|---|---|
| [Visual Studio or Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/) | **Desktop development with C++**, including the MSVC x64/x86 compiler/linker and Windows C++ libraries. The scripts currently use the **Visual Studio 18 Enterprise** installation path shown below. Other editions/Build Tools require adjusting that path. |
| [Windows SDK and Windows Driver Kit (WDK)](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) | The current linker script selects **10.0.28000.0**. Install the matching SDK/WDK kernel libraries, the SDK tools **`rc.exe`** and **`signtool.exe`**, and ensure the **KMDF 1.15 x64** libraries are available. Merely installing the user-mode SDK is insufficient. |
| [Rust via rustup](https://rustup.rs/) | Install the **stable MSVC** toolchain on the `x86_64-pc-windows-msvc` host, including Cargo and the `x86_64-pc-windows-msvc` target. The driver's `rust-toolchain` selects `stable`; nightly is not required. Make `%USERPROFILE%\.cargo\bin` available on `PATH`. |
| Windows PowerShell 5.1 | Included with Windows. Used for certificate creation, the built-in **ConfigCI** module, version-resource generation, and `link-dev.ps1`. |
| [Git for Windows](https://gitforwindows.org/) | For obtaining the checkout and for **Git Bash** if using the unit-test command below. |
| CMake **3.15 or newer** and Ninja — **client only** | Needed for the C++ monitor, not for `build-signed.bat`. They can be installed through Visual Studio's **C++ CMake tools for Windows** component. The client requires a C++20-capable compiler. |

After installing Rust, ensure the selected toolchain and target are available:

```powershell
rustup toolchain install stable
rustup target add x86_64-pc-windows-msvc --toolchain stable
```

Open a new shell after installing tools so that `cargo` is on `PATH`. Initial builds need access to crates.io and the pinned `windows-rs` GitHub dependency; driver timestamping also needs access to `http://timestamp.digicert.com`.

**Match the scripts' paths to the installed tools.** The current defaults are:

- `windows_kext\build-signed.bat`: `VCVARS` points to `C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvarsall.bat`.
- `windows_kext\link-dev.ps1`: `$SDK_Version = "10.0.28000.0"`; kernel libraries are under `C:\Program Files (x86)\Windows Kits\10\lib\10.0.28000.0\km\x64`, and KMDF libraries are under `C:\Program Files (x86)\Windows Kits\10\lib\wdf\kmdf\x64\1.15` (`WdfLdr.lib` and `WdfDriverEntry.lib`).
- `kext_client\build.bat`, if building the monitor: its own `VCVARS` points to `C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat`.

If the installed edition/version differs, adjust the corresponding paths before building; `build-signed.bat` does not discover arbitrary Visual Studio or WDK installations. Use the matching SDK version in the full SignTool path in step 2 as well. The normal driver build uses the checked-in `windows_kext\c_helper\x64\c_helper.lib`; it does not rebuild the C helper. Go, Python, Perl, and LLVM/Clang are not required for this build path.

### Download the source

After installing [Git for Windows](https://gitforwindows.org/), open a new PowerShell window and clone the complete [windows_kext_mod repository](https://github.com/GerardoKermitToy/windows_kext_mod) into the directory used by the examples:

```powershell
git clone https://github.com/GerardoKermitToy/windows_kext_mod.git 'C:\portmaster_v3'
```

The destination must not already exist or must be empty. If `C:\portmaster_v3` already contains the desired checkout, skip cloning; do not delete or overwrite it. To use a different location, clone into a new directory and replace `C:\portmaster_v3` in all subsequent commands with that path.

Change to the repository root:

```powershell
Set-Location 'C:\portmaster_v3'
```

Keep the repository layout: `windows_kext` contains the driver and signing scripts, while `kext_client` contains the C++ monitor and communicates directly with the driver. Continue with certificate creation below before building and signing the driver.

### 1. Create the local certificates

Change to `windows_kext`; all relative output paths in steps 1 and 2 refer to this directory:

```powershell
Set-Location 'C:\portmaster_v3\windows_kext'
```

Run the following certificate-generation script. It creates a self-signed root CA and two certificates issued by that CA, with exportable private keys in `Cert:\LocalMachine\My`, then exports them to the current directory:

```powershell
$pwd = ConvertTo-SecureString -String "1" -Force -AsPlainText

$cert_params = @{
    Type = 'Custom'
    Subject = 'CN=Localhost Root Certification Authority'
    FriendlyName = 'Localhost Root Certification Authority'
    TextExtension = '2.5.29.19={text}CA=1'
    HashAlgorithm = 'sha512'
    KeyLength = 4096
    KeyAlgorithm = 'RSA'
    KeyUsage = 'CertSign','CRLSign'
    KeyExportPolicy = 'Exportable'
    NotAfter = (Get-Date).AddYears(100)
    CertStoreLocation = 'Cert:\LocalMachine\My'
}

$root_cert = New-SelfSignedCertificate @cert_params

Export-PfxCertificate -Cert $root_cert -FilePath ./localhost-root-ca.pfx -Password $pwd
Export-Certificate -Cert $root_cert -FilePath ./localhost-root-ca.der


$cert_params = @{
    Type = 'Custom'
    Subject = 'CN=Localhost UEFI Platform Key Certificate'
    FriendlyName = 'Localhost UEFI Platform Key Certificate'
    TextExtension = '2.5.29.19={text}CA=0'
    Signer = $root_cert
    HashAlgorithm = 'sha256'
    KeyLength = 2048
    KeyAlgorithm = 'RSA'
    KeyUsage = 'DigitalSignature'
    KeyExportPolicy = 'Exportable'
    NotAfter = (Get-Date).AddYears(10)
    CertStoreLocation = 'Cert:\LocalMachine\My'
}

$pk_cert = New-SelfSignedCertificate @cert_params

Export-PfxCertificate -Cert $pk_cert -FilePath ./localhost-pk.pfx -Password $pwd
Export-Certificate -Cert $pk_cert -FilePath ./localhost-pk.der


$cert_params = @{
    Type = 'CodeSigningCert'
    Subject = 'CN=Localhost Kernel Mode Driver Certificate'
    FriendlyName = 'Localhost Kernel Mode Driver Certificate'
    TextExtension = '2.5.29.19={text}CA=0'
    Signer = $root_cert
    HashAlgorithm = 'sha256'
    KeyLength = 2048
    KeyAlgorithm = 'RSA'
    KeyUsage = 'DigitalSignature'
    KeyExportPolicy = 'Exportable'
    NotAfter = (Get-Date).AddYears(10)
    CertStoreLocation = 'Cert:\LocalMachine\My'
}

$km_cert = New-SelfSignedCertificate @cert_params

Export-PfxCertificate -Cert $km_cert -FilePath ./localhost-km.pfx -Password $pwd
Export-Certificate -Cert $km_cert -FilePath ./localhost-km.der
```

| File pair (`.pfx` / `.der`) | Purpose |
|---|---|
| `localhost-root-ca` | Root CA issuing the PK and KM certificates; its public certificate supplies the driver signing chain |
| `localhost-pk` | Signs `SiPolicy.bin`; its public certificate is enrolled as the UEFI **PK** |
| `localhost-km` | Signs the driver; its public certificate is authorized by the Code Integrity policy for **kernel-mode** code |

The `.der` files contain public certificates; the `.pfx` files also contain **private keys**. Do not commit PFX files or publish them with build artifacts. Keep secure backups, particularly of the root and PK private keys: they control certificate issuance and future policy updates. Do not regenerate the certificates after enrolling the PK/deploying the policy unless you also plan the corresponding trust-policy migration.

> The supplied script uses the example PFX password **`1`**, matching the signing examples below. This is not a secure password for real key storage. If you change it, update the policy-signing command and the PFX password used by `windows_kext\link-dev.ps1` as well.

### 2. Create and sign `SiPolicy.p7b`

Continue in the same elevated Windows PowerShell session and `windows_kext` directory. Generate a single-policy-format Code Integrity policy from the installed system's signing roots, authorize PK-signed policy updates, and add the KM certificate as a kernel-mode signer:

```powershell
New-CIPolicy -FilePath .\SiPolicy.xml -Level RootCertificate -ScanPath C:\Windows\System32\
Set-RuleOption -FilePath .\SiPolicy.xml -Option 3 -Delete
Set-RuleOption -FilePath .\SiPolicy.xml -Option 6 -Delete
Add-SignerRule -FilePath .\SiPolicy.xml -CertificatePath .\localhost-pk.der -Update
Add-SignerRule -FilePath .\SiPolicy.xml -CertificatePath .\localhost-km.der -Kernel
ConvertFrom-CIPolicy -XmlFilePath .\SiPolicy.xml -BinaryFilePath .\SiPolicy.bin
```

- Removing option **3** (`Enabled:Audit Mode`) makes the policy **enforced**, not audit-only.
- Removing option **6** (`Enabled:Unsigned System Integrity Policy`) requires signed policy updates.
- `-Update` authorizes the PK certificate to sign policy updates; it does not authorize that certificate to sign drivers. `-Kernel` authorizes the KM certificate for kernel-mode code.
- `RootCertificate` rules trust signing roots, not just individual scanned files. Conversely, a scan of `System32` may miss required third-party drivers stored elsewhere. Review scan warnings and policy coverage, including boot/storage drivers, before enforcing it. Do not deploy an incomplete policy.

Sign the binary policy using the PK's private key. The full SDK path below assumes Windows SDK **10.0.28000.0**; if a different version is installed, use its actual `x64\signtool.exe` path:

```powershell
& 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe' sign /fd sha256 /p7co 1.3.6.1.4.1.311.79.1 /p7 . /f .\localhost-pk.pfx /p 1 /n "Localhost UEFI Platform Key Certificate" .\SiPolicy.bin
```

Only after SignTool succeeds and produces `SiPolicy.bin.p7`, rename that **signed output**, not the unsigned `.bin` file:

```powershell
Move-Item -LiteralPath .\SiPolicy.bin.p7 -Destination .\SiPolicy.p7b
```

Keep `SiPolicy.xml`, the certificates, and the signed policy for recovery and future updates. These steps describe initial deployment: do not overwrite an existing signed policy without a planned update signed by an authorized update signer.

### 3. Copy the signed policy to the EFI System Partition

Use a free drive letter (`X:` in this example) and mount the EFI System Partition of the Windows installation being configured:

```powershell
mountvol.exe X: /S
```

If `X:\EFI\Microsoft\Boot\SiPolicy.p7b` already exists, **stop and back it up** before planning a replacement. On a multi-boot/multi-disk machine, verify that this is the correct EFI partition. For a new deployment, copy the signed file:

```powershell
Copy-Item -LiteralPath .\SiPolicy.p7b -Destination 'X:\EFI\Microsoft\Boot\SiPolicy.p7b'
```

Remove the temporary drive-letter mount:

```powershell
mountvol.exe X: /D
```

Complete the offline registry and firmware changes below **before the next startup of the target Windows installation**.

### 4. Enable `CustomKernelSigners` in the offline SYSTEM hive

The required value in the target Windows installation is:

```text
Key:   HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Protected
Value: CustomKernelSignerLockedEnabled
Type:  REG_DWORD
Data:  1
```

The value must already exist, as checked before policy deployment. Do not create it manually if it is missing; the required Windows updates must be installed before starting this procedure.

This protected value cannot be changed from the running target system. Do not change ownership/permissions of the live `CI\Protected` key. Instead, load the target system's registry hive from another Windows installation or a trusted Windows PE/live USB:

1. Fully shut down the target Windows installation; do not leave it hibernated or use a Fast Startup shutdown. Boot the other Windows/Windows PE environment. Verify beforehand that the recovery media can boot with the intended Secure Boot configuration.
2. Locate the target Windows volume. Its drive letter may differ from normal; the example below uses **`D:\Windows`**. If BitLocker is enabled, unlock that volume with its recovery key. Back up `D:\Windows\System32\Config\SYSTEM` and its associated transaction logs before editing.
3. Start **Registry Editor (`regedit.exe`) as Administrator** in the recovery environment. Select **`HKEY_LOCAL_MACHINE`**, then **File → Load Hive**. Open **`D:\Windows\System32\Config\SYSTEM`** and give it the temporary name **`OfflineSYSTEM`**. Do not edit the recovery environment's own SYSTEM hive.
4. Open **`HKEY_LOCAL_MACHINE\OfflineSYSTEM\Select`** and inspect the DWORD values **`Current`** and **`Default`**. `Current` identifies the last active control set; `Default` selects the control set for the next normal startup. Usually both are `1`, meaning **`ControlSet001`**. For `Default = 2`, use `ControlSet002`, and so on. Do not assume `ControlSet001` without checking. An offline hive has no live `CurrentControlSet` alias.
5. In the control set selected for the next normal startup, open **`Control\CI\Protected`**. For `Default = 1`, the complete offline path is:

   ```text
   HKEY_LOCAL_MACHINE\OfflineSYSTEM\ControlSet001\Control\CI\Protected
   ```

   Double-click the existing **`CustomKernelSignerLockedEnabled`** value, confirm it is **`REG_DWORD`**, and set **Value data** to **`1`**. Decimal or hexadecimal is equivalent for this value. If the value is missing, do not create it; return to the Windows-update/support check above.
6. Select **`HKEY_LOCAL_MACHINE\OfflineSYSTEM`**, then **File → Unload Hive**, and confirm. This saves the changes and releases the hive. Close Registry Editor and shut down the recovery environment.

### 5. Enroll the custom PK and verify Secure Boot

Copy the public **`localhost-pk.der`** certificate to a firmware-readable USB drive (typically FAT32). Do not put the PFX/private keys on that drive. Enter the machine's UEFI/BIOS settings:

1. Switch Secure Boot key management from **Standard Mode** to **Custom Mode**. The exact menu names and enrollment procedure depend on the firmware vendor.
2. In **Platform Key (PK)** management, replace/enroll the PK using **`localhost-pk.der`**, the same certificate whose private key signed `SiPolicy.p7b`. This certificate belongs in **PK**, not in db or KEK. The KM driver certificate is authorized by the CI policy and does not need to be enrolled as the firmware PK.
3. Preserve the existing **KEK, db, and dbx** entries needed to boot Windows and maintain revocations. Do not use a blanket **Clear all Secure Boot keys** operation. Ensure db trusts the certificate chain of the installed Windows boot manager.
4. Leave **Secure Boot enabled and active**, save the firmware settings, and boot the configured Windows installation. **Custom Mode is not the same as disabling Secure Boot**; the machine must not remain in Setup Mode without an enrolled PK.

**Optional Microsoft certificate updates.** If the appropriate current Microsoft certificates are not already installed, firmware may allow appending them to **db**. Microsoft's [Secure Boot certificate-expiration and CA-update guidance](https://support.microsoft.com/en-us/servicing/os/secure-boot/2025/06/windows-secure-boot-certificate-expiration-and-ca-updates) explains the transition. Public db certificates are available in Microsoft's [secureboot_objects repository](https://github.com/microsoft/secureboot_objects/tree/main/PreSignedObjects/DB/Certificates), including:

- `windows uefi ca 2023.der` — Windows bootloaders;
- `microsoft uefi ca 2023.der` — third-party bootloaders/EFI applications;
- `microsoft option rom uefi ca 2023.der` — third-party option ROMs.

Append only the certificates appropriate for the machine; do not replace the entire db or put these certificates in the PK slot. The linked directory contains **db certificates**, not the Microsoft KEK update. Follow the separate Microsoft/OEM guidance for KEK updates; adding db certificates alone does not complete the whole certificate-transition process.

After Windows starts, verify from an elevated Windows PowerShell session:

```powershell
Confirm-SecureBootUEFI
```

The result must be **`True`**. Then verify the live registry value:

```powershell
Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Protected' -Name 'CustomKernelSignerLockedEnabled'
```

The result must be **`1`**. If either check fails, resolve the system/firmware configuration before trying to load the driver. These checks are prerequisites, not proof that a particular `.sys` file will be admitted by kernel Code Integrity.

### 6. Build and sign the driver

Build and sign the `.sys` file with:

```powershell
& 'C:\portmaster_v3\windows_kext\build-signed.bat'
```

The batch file changes to its own directory, builds `driver\target\x86_64-pc-windows-msvc\release\driver.lib` with `cargo build --release`, initializes the x64 Visual Studio environment, generates/compiles the version resource, and invokes `link-dev.ps1` to link and sign **`C:\portmaster_v3\windows_kext\portmaster-kext.sys`**.

The current signing command in `link-dev.ps1` uses:

- **`localhost-km.pfx`**, subject **`Localhost Kernel Mode Driver Certificate`**, to sign the driver;
- **`localhost-root-ca.der`** as the additional chain certificate;
- PFX password **`1`**, SHA-256, and the DigiCert timestamp service.

Keep those files in `windows_kext`, or deliberately update the signing command if using different locations/passwords. `localhost-pk.pfx` signs the policy in step 2, **not** the driver. The batch file builds/signs the driver; it does not enroll firmware keys, activate `CustomKernelSigners`, deploy the policy, or load the driver.

A successful build/signature operation, or even a successful `signtool verify /pa` Authenticode check, is not proof that Windows kernel Code Integrity will admit the driver. Use the bounded monitor run below to check actual loading under the configured policy. Authenticode chain validation also depends on certificate-store trust; the custom kernel-admission setup is defined by the signed policy and enrolled PK, not just the ordinary certificate store.

### Unit tests and C++ client

Run the driver unit tests from Git Bash with:

```bash
cd /c/portmaster_v3/windows_kext/driver && RUSTFLAGS="" cargo test --release
```

Build the C++ client/monitor from PowerShell with:

```powershell
& 'C:\portmaster_v3\kext_client\build.bat'
```

With the default Ninja build, the monitor is `C:\portmaster_v3\kext_client\build\kext_monitor.exe`. If CMake falls back to a multi-configuration generator, the executable may be under `build\Release` instead. Run it **as Administrator**, always with **`--duration`** for a bounded test and with the explicit driver path:

```powershell
& 'C:\portmaster_v3\kext_client\build\kext_monitor.exe' --duration 10 'C:\portmaster_v3\windows_kext\portmaster-kext.sys'
```

The monitor creates/starts the driver service itself, opens the device, and on normal completion closes the device, stops/unloads the driver, and removes its service. **Do not create the service manually.** The default verdict is `PermanentAccept`; avoid global blocking/redirect verdicts for an initial smoke test. Wait for the timed run to finish and clean up; do not forcibly kill the process or stop its service while the device handle is open. Do not run the monitor without a duration limit for unattended tests.

## License

This project is distributed under the [GNU General Public License v3](LICENSE).
