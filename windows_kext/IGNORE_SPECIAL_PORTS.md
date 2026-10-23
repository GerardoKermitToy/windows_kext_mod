# Ignore Portmaster special ports

## Registry contract

The driver reads this value once during `DriverEntry`, before WFP is activated:

```text
HKLM\SYSTEM\CurrentControlSet\Services\PortmasterKext\Parameters
    IgnoreSpecialPorts    REG_DWORD
```

Only a `REG_DWORD` whose value is exactly `1` disables port-based special
handling. An absent/inaccessible key or value, a different registry type,
malformed data, or any other DWORD value preserves the existing behavior.

The driver does not subscribe to registry changes. Changing the value while the
driver is running has no effect until it is unloaded and loaded again.

## Monitor behavior

`kext_monitor` does not write `IgnoreSpecialPorts` and has no command-line option
for it. The driver uses the value available when it loads; an absent or invalid
value preserves special handling, as described above.

`--no-inbound-udp-pid-fallback` controls only
`EnableInboundUdpCacheMissPidFallback`, which the monitor does write before
starting the driver. If that write fails, the monitor reports the error and does
not start the driver; there is no `IgnoreSpecialPorts` write in this path.

For a bounded run from the repository root:

```bash
./kext_client/build/kext_monitor.exe --duration 10 ./windows_kext/portmaster-kext.sys
```

## Driver behavior

The affected ports are:

| Constant | Port |
| --- | ---: |
| `PM_DNS_PORT` | 53 |
| `PM_SPN_PORT` | 717 |
| `PM_SPLIT_TUN_PORT` | 719 |

When enabled, these are treated as ordinary ports for IPv4 and IPv6:

- The packet layer does not automatically permit packets merely because the
  local port is special and the local and remote addresses are equal.
- Cache lookup, pending-instance validation, and verdict updates do not scan for
  reverse-redirect aliases on these ports. Only exact tuple/instance matches apply.
- The normal connection cache, userspace verdicts, and ALE authorization rules
  continue to apply.

This option does not replace an explicitly requested redirect verdict with
accept: forward redirect rewriting still applies. However, its return traffic no
longer gets automatic reverse-redirect matching while this setting is enabled.
Use the existing special handling if transparent round-trip redirects are needed.

The setting does not disable filtering or grant unconditional permission to
traffic on these ports. Other bypass conditions, such as driver self-reinjection,
are unchanged. The cached boolean is checked only for the three special ports;
no registry access or additional packet inspection occurs in the classify path.
