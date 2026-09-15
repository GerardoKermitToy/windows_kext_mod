# Modified Portmaster Windows Kernel Extension

This repository contains a modified version of the original Portmaster Windows Kernel Extension. It is not the original implementation, but it remains fully compatible with the original driver's external API.

The modified driver is implemented in Rust as a `no_std` KMDF non-PnP Windows network driver. It registers Windows Filtering Platform (WFP) callouts, intercepts IPv4 and IPv6 traffic, delegates packet decisions to a user-mode process, caches verdicts, blocks or redirects traffic, and collects TCP/UDP bandwidth statistics.

## API compatibility

The modifications change the internal implementation without changing the API exposed to existing Portmaster clients. Compatibility includes:

- the `\Device\PortmasterKext` device name and `\\.\PortmasterKext` Win32 path;
- device access and I/O semantics;
- event framing, IDs, field order, field widths, and byte order;
- command IDs, payload layouts, and verdict values;
- IOCTL values and responses.

A client written for the original Portmaster Windows Kernel Extension can communicate with this modified driver without protocol changes. Unless stated otherwise, references to "the driver" below mean this modified, API-compatible implementation.

The driver and its user-mode controller operate as one system:

- `windows_kext/driver` — the driver and WFP callout handlers;
- `windows_kext/protocol` — the source of truth for the binary protocol;
- `windows_kext/wdk` and `windows_kext/c_helper` — wrappers around WDK, KMDF, WFP, and NDIS;
- `windows_kext/kextinterface` — the Go implementation of the client protocol;
- `kext_client` — the C++ client and the `kext_monitor.exe` diagnostic tool.

The packet path through WFP is described in detail in [windows_kext/PacketFlow.md](windows_kext/PacketFlow.md). This document defines the complete external driver API: the control device, `ReadFile`/`WriteFile`, IOCTLs, commands, events, and enumeration values. Internal Rust functions and the `kext_monitor` named-pipe protocol are not part of the driver API.

## Key properties

The driver creates 16 WFP callouts:

- ALE authorization for outbound and inbound TCP/UDP connections over IPv4 and IPv6;
- ALE endpoint closure callouts for connection lifetime tracking;
- ALE flow-established callouts for PID attribution and flow lifetime tracking;
- stream and datagram callouts for TCP/UDP bandwidth statistics;
- inbound and outbound IP packet callouts for IPv4 and IPv6.

A new packet without a permanent cached decision is blocked and retained until the user-mode process responds. User mode receives a `ConnectionIpv4` or `ConnectionIpv6` event with a unique request ID and responds with a `Verdict` command. An accepted packet clone is then returned to the network stack asynchronously through a WFP injection API.

`Permanent*` in a verdict name means that the decision remains cached for the lifetime of that specific connection-cache instance. It does not create a global firewall rule. A new connection that reuses the same five-tuple after the old connection ends must receive a new decision.

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

Use a single reader thread. `ReadFile`, `WriteFile`, and both IOCTL handlers require `PASSIVE_LEVEL` inside the driver.

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
| `1` | `ConnectionIpv4` | IPv4 packet-decision request |
| `2` | `ConnectionIpv6` | IPv6 packet-decision request |
| `3` | `ConnectionEndEventV4` | IPv4 connection ended |
| `4` | `ConnectionEndEventV6` | IPv6 connection ended |
| `5` | `BandwidthStatsV4` | IPv4 bandwidth counters |
| `6` | `BandwidthStatsV6` | IPv6 bandwidth counters |

### `ConnectionIpv4` (`info_type = 1`)

The fixed payload is 35 bytes, followed by the captured packet bytes:

| Offset | Size | Field | Description |
|---:|---:|---|---|
| `0` | 8 | `id` | Request ID for a `Verdict` command; `0` is reserved as invalid |
| `8` | 8 | `process_id` | Owning PID, or `0` when it cannot be determined |
| `16` | 1 | `direction` | Direction of the packet being decided |
| `17` | 1 | `protocol` | IP protocol number |
| `18` | 4 | `local_ip` | Local IPv4 address |
| `22` | 4 | `remote_ip` | Remote IPv4 address |
| `26` | 2 | `local_port` | Local port, or `0` for a protocol without ports |
| `28` | 2 | `remote_port` | Remote port, or `0` for a protocol without ports |
| `30` | 1 | `payload_layer` | Layer represented by the captured bytes |
| `31` | 4 | `captured_length` | Number of bytes that follow |
| `35` | N | `captured_bytes` | Captured packet bytes |

A valid payload length is `35 + captured_length`.

### `ConnectionIpv6` (`info_type = 2`)

The fixed payload is 59 bytes:

| Offset | Size | Field | Description |
|---:|---:|---|---|
| `0` | 8 | `id` | Request ID for a `Verdict` command |
| `8` | 8 | `process_id` | Owning PID, or `0` when unknown |
| `16` | 1 | `direction` | Direction of the packet being decided |
| `17` | 1 | `protocol` | IP protocol number |
| `18` | 16 | `local_ip` | Local IPv6 address |
| `34` | 16 | `remote_ip` | Remote IPv6 address |
| `50` | 2 | `local_port` | Local port, or `0` |
| `52` | 2 | `remote_port` | Remote port, or `0` |
| `54` | 1 | `payload_layer` | Layer represented by the captured bytes |
| `55` | 4 | `captured_length` | Number of bytes that follow |
| `59` | N | `captured_bytes` | Captured packet bytes |

A valid payload length is `59 + captured_length`.

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

Redirect verdicts are cached for the connection. Outbound packets receive a rewritten destination address and port with recalculated IP/TCP/UDP checksums. Reverse traffic is rewritten back so that the application continues to observe the original remote endpoint. Redirects are meaningful only for a live TCP/UDP cache instance. If redirect state is unavailable or a packet cannot be rewritten safely, the packet is dropped and an error is recorded in the log ring.

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
- ends outbound fallback connections without native lifecycle identity after 60 seconds of inactivity and emits their end events;
- ends local TCP authorizations that have not reached `FLOW_ESTABLISHED` within 10 seconds;
- reconciles stale UDP endpoint and flow registrations;
- removes expired ICMP echo mappings.

The production client and `kext_monitor` send this command every 30 seconds. The driver does not run this periodic sweep autonomously.

## IOCTL API

Both control codes use:

```text
CTL_CODE(40000, function, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
```

The device handle must therefore have both read and write access.

| Code | Numeric value | Input | Output | Description |
|---|---:|---:|---:|---|
| `IOCTL_VERSION` | `0x9C40E000` | None | Exactly 4 bytes | Wire-interface version |
| `IOCTL_SHUTDOWN_REQUEST` | `0x9C40E004` | None | None | Final driver shutdown |

### `IOCTL_VERSION`

Returns the four raw bytes stored in `windows_kext/kextinterface/version.txt`. The current version is `[2, 1, 1, 0]`, conventionally displayed as `2.1.1.0`. If the output buffer is shorter than four bytes, the request completes with `STATUS_BUFFER_TOO_SMALL` and returns no partial result.

### `IOCTL_SHUTDOWN_REQUEST`

Performs the same operation as the `Shutdown` command. The IOCTL provides a convenient out-of-band final request while an overlapped read is waiting. It has no output.

An unknown IOCTL completes with `STATUS_NOT_IMPLEMENTED`.

## Recommended client lifecycle

1. Install and start the kernel-driver service, or use an already installed release driver.
2. Open `\\.\PortmasterKext` with `GENERIC_READ | GENERIC_WRITE`, share mode `0`, and `FILE_FLAG_OVERLAPPED`.
3. Check `IOCTL_VERSION` before beginning protocol communication.
4. Start one persistent overlapped read and assemble records independently of read boundaries.
5. Respond to every nonzero connection request ID. Display filters must not suppress verdicts.
6. Send `CleanEndedConnections` periodically and request logs or bandwidth statistics as needed.
7. To terminate, issue `IOCTL_SHUTDOWN_REQUEST` or the `Shutdown` command.
8. Wait for and reap the pending read, then close the device handle.
9. Stop the service only after closing the handle. A non-PnP driver cannot finish unloading while its control device remains open.

Do not forcibly terminate a controller with an open handle and then expect `sc stop` to complete: the service can remain in `STOP_PENDING`. Diagnostic runs should always use a bounded `--duration`.

## C++ API (`kext_client`)

The [kext_client/include/PortmasterKext.h](kext_client/include/PortmasterKext.h) header provides the `pmkext` namespace and decoded `Connection`, `ConnectionEnd`, `LogLine`, `BandwidthEntry`, and `BandwidthStats` structures.

### `pmkext::Driver`

| Method | Purpose |
|---|---|
| `Driver(service_name)` | Constructs a controller; the default name is `PortmasterKext` |
| `Install(sys_path, error)` | Creates and starts a demand-start kernel service using an absolute path; an existing service is treated as a conflict |
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

The C++ class does not currently expose methods for `UpdateV4` or `UpdateV6`; these commands remain available through the raw driver protocol or the Go interface.

The `ToString`, `PayloadLayerToString`, `ProtocolToString`, `DirectionToString`, `FormatIpv4`, and `FormatIpv6` helpers only format already decoded values.

## Building and testing

The driver supports release builds only. A debug build intentionally fails with a compile-time error. The target is fixed to `x86_64-pc-windows-msvc` with `panic=abort`.

Build and sign the `.sys` file with:

```bat
C:\portmaster_v3\windows_kext\build-signed.bat
```

The script runs `cargo build --release`, links the resulting static library against WDK/KMDF, and signs `windows_kext\portmaster-kext.sys`. It requires Visual Studio, WDK, and a configured signing certificate.

Run the driver unit tests with:

```bash
cd /c/portmaster_v3/windows_kext/driver && RUSTFLAGS="" cargo test --release
```

Build the C++ client with:

```bat
C:\portmaster_v3\kext_client\build.bat
```

Always use `--duration` for a bounded smoke test. The monitor creates, starts, stops, and removes its driver service automatically:

```bat
C:\portmaster_v3\kext_client\build\kext_monitor.exe --duration 10 C:\portmaster_v3\windows_kext\portmaster-kext.sys
```

By default, the monitor responds to every nonzero request ID with `PermanentAccept`. `--no-verdicts` intentionally stalls pending traffic, while global block, drop, or redirect verdicts can disconnect the machine. Apply those verdicts only with a narrow `--match` and a bounded `--duration`. Run `kext_monitor.exe --help` for the complete option list.

## License

This project is distributed under the [GNU General Public License v3](LICENSE).
