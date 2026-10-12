# Inbound UDP cache-miss PID fallback

The driver defaults to the existing inbound path: a TCP/UDP packet with no live
cached connection is permitted to reach `ALE_AUTH_RECV_ACCEPT`, where Windows can
identify and authorize the receiving socket.

## Registry setting

```text
HKLM\SYSTEM\CurrentControlSet\Services\PortmasterKext\Parameters
    EnableInboundUdpCacheMissPidFallback    REG_DWORD
```

Only a `REG_DWORD` containing exactly `1` enables the fallback. A missing value,
wrong type, or any other value disables it. The driver derives the service registry
path from `DriverEntry`; `PortmasterKext` is the service name used by `kext_monitor`.

`kext_monitor` writes `1` by default after creating the service and before starting
the driver. With `--no-inbound-udp-pid-fallback`, it writes `0` instead, overwriting
any previous value. A failed registry write aborts driver installation. The driver
reads the setting once in `DriverEntry`, before packet classification starts. No
registry callbacks or background refresh thread are used. Changing or deleting the
value while the driver is running has no effect until it is unloaded and loaded
again.

To disable it for a bounded monitor run, from the repository root:

```bash
./kext_client/build/kext_monitor.exe --duration 10 --no-inbound-udp-pid-fallback ./windows_kext/portmaster-kext.sys
```

For a loader that does not overwrite the setting, configure it before driver
startup. To disable it, from an elevated Git Bash shell:

```bash
MSYS_NO_PATHCONV=1 reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\PortmasterKext\Parameters' /v EnableInboundUdpCacheMissPidFallback /t REG_DWORD /d 0 /f
```

To re-enable it:

```bash
MSYS_NO_PATHCONV=1 reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\PortmasterKext\Parameters' /v EnableInboundUdpCacheMissPidFallback /t REG_DWORD /d 1 /f
```

Starting `kext_monitor` without the opt-out flag sets the value back to `1`
before driver startup.
Always use `--duration N` for unattended monitor tests; the monitor loads and
unloads the driver itself.

## Packet behavior

When enabled, an inbound UDP packet whose normal connection lookup misses searches
for the first active UDP entry matching `(local_ip, local_port, remote_ip)`, ignoring
`remote_port`. This applies to IPv4 and IPv6. If that entry has a PID other than
`0` or `4`, the packet is sent to userspace with that PID. If there is no match, or
the first match has PID `0`/`4`, the packet still proceeds to ALE. The lookup does
not skip a first match with PID `0`/`4` to look for a different owner. TCP and normal
cache-hit handling are unchanged.

This is best-effort attribution, not proof of socket ownership. Shared local
endpoints can belong to different processes; the first matching active cache entry
is used without checking for ambiguity, and is not necessarily the newest entry.
Only the PID is borrowed: the donor's verdict, thread ID, connection instance and
lifetime are not reused or refreshed. The fallback registers a separate untracked
inbound connection for the packet's complete tuple, including its remote port,
with an initial `Undecided` verdict and thread ID `0`. The pending packet carries
that new connection's instance ID, so permanent userspace verdicts are cached for
it, not for the donor. Later packets in either direction use the normal exact
cache lookup. A concurrently registered exact tuple is reused without overwriting
its owner, thread ID, verdict or lifecycle.

Accepted reinjection can associate this exact instance with the actual receiving
UDP endpoint at ALE and promote it to native lifecycle tracking. Until then, the
heuristic entry is eligible for the existing one-minute idle timeout; activity on
its exact tuple refreshes that timeout. Ordinary inbound ALE connections retain
their existing socket-closure lifetime policy.

## Cost and diagnostics

The normal cached-verdict path is unchanged. On an inbound cache miss, the option
is read from an atomic flag. When enabled for UDP, the lookup scans only the
`(UDP, local_port)` group and stops at the first live address match. The scan itself
allocates nothing, but retains the family cache's read spin lock. Registering the
new exact tuple then takes the write lock and may allocate cache storage. Large
local-port groups and misses can therefore be more expensive than a full-key
indexed lookup. Once a permanent verdict is cached, subsequent packets use the
ordinary fast path. No extra packet/NBL inspection is introduced.

No per-packet fallback log is emitted. Configuration info logging is limited to
the initial state read during driver load; the normal production warning log
level suppresses it.
