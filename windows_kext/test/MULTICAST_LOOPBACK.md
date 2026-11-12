# Local multicast loopback regression

This regression compares delivery without the driver and with a bounded
`kext_monitor`. It covers IPv4 and IPv6, a wildcard or explicit sender bind,
one or two joined sockets, receivers in one or two processes, and an additional
socket bound to the same port without joining the group. It checks exact payloads,
source addresses and ports, missing or duplicate datagrams, monitor completion,
and removal of the monitor-owned driver service. Any asynchronous WFP injection
failures are printed and recorded in `result.json`; because they are not all
correlated to the test payload, they do not by themselves fail the delivery assertion.

Run on Windows as Administrator, with no existing monitor or PortmasterKext
service. The monitor uses `--duration` and owns driver load/unload. Its startup
may enable IPv4/IPv6 route policies in the active store, as described by
`kext_monitor --help`. Each run creates a fresh output directory under
`windows_kext/test/_out` with records, console output and `result.json`.

```bash
python windows_kext/test/test_multicast_loopback.py
```

```bash
python windows_kext/test/test_multicast_loopback.py --ipv6
```

The default IPv6 loopback interface index is 1. `--ipv6-interface-index` can
select another index for diagnostics, but the driver exception is deliberately
limited to index 1. A different IPv4 loopback address can be tested with:

```bash
python windows_kext/test/test_multicast_loopback.py --ipv4-loopback 127.0.0.2
```

The default verdict is PermanentAccept. These tests send a blocking verdict
specifically for the incoming notification or, respectively, the outgoing
notification. Both must still deliver the local multicast datagrams:

```bash
python windows_kext/test/test_multicast_loopback.py --verdict permanent-block
```

```bash
python windows_kext/test/test_multicast_loopback.py --verdict permanent-block --match-group-sends
```

Delay matching replies to verify that delivery does not wait for userspace:

```bash
python windows_kext/test/test_multicast_loopback.py --verdict permanent-block --verdict-delay-ms 5000
```

Temporary Accept can be checked separately:

```bash
python windows_kext/test/test_multicast_loopback.py --verdict accept
```

To check that the existing multicast idle cleanup produces END while the
receiving socket remains open, add `--idle-end`. The monitor runs for 175 seconds;
multicast expiry is 60 seconds and the monitor requests cleanup every 30 seconds.
On the test machine END arrived after about 88 seconds with the socket still open.

```bash
python windows_kext/test/test_multicast_loopback.py --verdict permanent-block --idle-end
```

To also test local delivery through a specific non-loopback IPv4 interface,
pass its **local** address. The additional case sets TTL=0; it tests local loop
and does not establish delivery to a remote host:

```bash
python windows_kext/test/test_multicast_loopback.py --extra-interface 192.168.219.16
```

That address was local to the original test machine; select the actual local
interface on another machine. To verify that a non-loopback receiver still
honors a blocking verdict, match the additional interface instead:

```bash
python windows_kext/test/test_multicast_loopback.py --extra-interface 192.168.219.16 --match-interface 192.168.219.16 --verdict permanent-block
```

Loopback IPv4 defaults to source `127.0.0.1`, destination `239.255.23.91`, TTL 1,
and `IP_MULTICAST_LOOP=1`. A wildcard-bound sender on this machine used
`127.0.0.1` even when interface `127.0.0.2` was selected. IPv6 uses `::1` to
`ff02::114` with hop limit 1. The IPv4 and IPv6 sender ports are dynamically
allocated, then held constant for the matrix so that a blocking test can match
only the chosen source address and port.

## Loopback-only workaround and policy consequences

UDP multicast with a `127.0.0.0/8` or `::1` source and loopback interface
index 1 is treated as observational for the tested local loopback path. The
inbound ALE indication must also carry WFP's loopback flag, identify a
receiving endpoint and not be injected by another provider. Its original packet
is permitted without a pend/replay.
Outbound indications can lack the loopback flag, so the outgoing packet path
instead requires interface index 1, the loopback source, multicast destination,
a live notification-only outbound cache generation and no foreign injection.
An existing ordinary sender generation does not acquire the exception marker.
Sender and
receiver CONN events use distinct, nonzero IDs; their replies have no pending
packet and are ignored. The existing per-receiver cache and endpoint tracking
produce END on closure or on a subsequent multicast idle-cleanup sweep.

**This is a Portmaster policy exception, not a hard system-wide permit:**
Portmaster Block/Drop verdicts for these notifications cannot prevent the
loopback delivery. The callout leaves the WFP action-write right intact, so
other filters/layers can still block it. Ordinary non-loopback multicast keeps
its per-receiver policy. The wire format does not mark an event as observational;
userspace sees an ordinary nonzero ID even though its verdict has no effect.

## Loopback IGMP exception

A separate exception avoids network-send failures for outbound IPv4 IGMP
(protocol 2) on loopback interface index 1, irrespective of the source,
destination, TTL, IP options, IGMP type or message contents. It is limited to
an indication containing one packet in the entire NBL chain and requires both
network and transport injection handles to report `NotInjected`. Unknown or
foreign injection origins, mixed/batched NBLs, and other packets keep their
pre-existing handling, including fragment handling. Physical-interface IGMP
keeps its ordinary verdict path; the separate IPv6 exception is described below.

Packet origin is not authenticated by the protocol or interface checks: a
privileged raw sender can create IGMP packets on loopback. For qualifying
packets, Portmaster verdicts cannot block delivery; other WFP filters can.

Each qualifying WFP indication publishes an ordinary CONN event with payload and
a new, nonzero notification-only ID. Windows may indicate one raw IGMP send more
than once, so it can produce multiple events. Its copied IPv4 header checksum is
completed in software, just as for ordinary cloned packet events; the original
packet is not modified. This preserves separate report payloads even when multiple
group changes share the same zero-port IP tuple. There is no connection cache
entry or END event for these individual IGMP notifications; zero ports are wire
format placeholders, not IGMP ports. A verdict for the packet is ignored,
including Block/Drop; the original packet is soft-permitted without replay.
Other WFP filters can still block it. If the packet cannot be read, the event
cannot be built or queued, or its notification ID cannot be allocated, the driver
falls back to the ordinary packet path rather than silently permitting it. There
is no special observational flag in the wire format.

```bash
python windows_kext/test/test_igmp_raw.py
```

This sends five raw IGMP types to `224.0.0.1`, `224.0.0.2` and `224.0.0.22`
through loopback, with and without a delayed blocking verdict. It compares each
`sendto` result with native Windows. On the test machine native Windows returned
`WSAENETUNREACH` (10051) for these raw sends; the old block/replay path instead
returned success before its injection failed. The bypass restores the native
application-visible error, not guaranteed delivery of those raw packets. Its
blocking phase also matches any other traffic involving `224.0.0.22`.

The bounded loopback control compares multicast UDP delivery without and with
the driver, checks report events and ignored PermanentBlock, and can verify
that no END appears through an idle sweep while the receiver stays open. **The
monitor's block match covers any traffic
involving `224.0.0.22`, regardless of protocol**, including unrelated traffic
on physical interfaces, so choose an appropriate time to run it:

```bash
python windows_kext/test/test_igmp_loopback.py --verdict-delay-ms 5000
```

```bash
python windows_kext/test/test_igmp_loopback.py --ipv4-loopback 127.0.0.2
```

```bash
python windows_kext/test/test_igmp_loopback.py --assert-no-end
```

`--assert-no-end` runs the monitor for 125 seconds. The physical-interface control
requires Npcap and Scapy and uses a capture filter for only IGMP to
`224.0.0.22` from the given local interface. It compares native reports,
PermanentAccept and PermanentBlock. Its blocking phase temporarily blocks any
traffic involving that destination, regardless of protocol:

```bash
python windows_kext/test/test_igmp_wire.py --interface 192.168.219.16 --capture-interface Ethernet
```

Select the actual local address and Npcap adapter name on another machine.
The tests create unique output directories under `_out` and never manually
start/stop the driver service. They refuse to run with an existing driver owner.

## Loopback ICMPv6 to IPv6 multicast

`ff02::16` is the link-local multicast address for MLDv2-capable routers;
MLDv2 membership reports carry their actual joined group addresses in the
ICMPv6 payload. On this Windows build, reinjecting the observed native reports
from `::1` to `ff02::16` on interface 1 failed with
`STATUS_NETWORK_UNREACHABLE`. The same was true for 18 raw ICMPv6 types on that
path, including non-MLD types; classifying the packet by MLD message type alone
would not describe this observed failure.

The exception covers **outbound IPv6 ICMPv6, source `::1`, any multicast
destination in `ff00::/8`, interface index 1**, independent of ICMPv6 type,
payload and IPv6 options. It requires exactly one packet in the entire NBL chain
and both injection handles to report `NotInjected`. Existing packet validation
still excludes, for example, unresolved extension chains, active IPv6 routing
headers, and unsupported jumbograms; fragment handling and other nonqualifying
indications keep their existing behavior. Physical-interface ICMPv6 and IPv6
unicast retain their ordinary verdict path. A synthetic raw MLD Query to
`ff02::1` was also observed to fail during replay before this broader exception.
Failures for every possible IPv6 multicast destination have not been established:
the expanded scope is a precautionary Portmaster policy choice.

Every qualifying indication publishes an ordinary network-layer CONN with a
nonzero notification-only ID and a copy of the packet. Its verdict is ignored;
the original is soft-permitted, so other WFP filters can still block it. This is
a Portmaster policy exception, not a system-wide allow. A raw sender can create
non-MLD ICMPv6 traffic on the same path; these packets are also within the
exception. These independent packet notifications create no connection cache
entry and do not produce END; their zero ports are placeholders, not ICMPv6
ports. Ordinary ICMP echo PID/TID attribution is preserved. As with IGMP,
failure to read the packet or publish its event falls back to the ordinary
packet path. The wire format has no observational flag.

```bash
python windows_kext/test/test_mld_loopback.py --verdict-delay-ms 3000
```

```bash
python windows_kext/test/test_mld_loopback.py --assert-no-end
```

Both tests compare native and driver UDP multicast delivery, validate the report
payload and ICMPv6 checksum, and check for correlated network-send failures.
The first verifies delayed PermanentBlock replies; the second checks for the
absence of END across an idle sweep while the receiving socket remains open.
To check IGMP, MLD reports and a raw `ff02::1` notification together
through an idle sweep with one monitor and PermanentAccept:

```bash
python windows_kext/test/test_control_no_end.py
```

The matching verdict in the blocked MLD test applies to
**all traffic involving `ff02::16`**, irrespective of protocol or interface,
so choose an appropriate time to run that test. The raw test compares native
send results for 18 ICMPv6 types to `ff02::16` and probes additional multicast
destinations. Its delayed PermanentBlock phase matches all traffic involving the
test address `ff02::a3:fd01`, regardless of protocol or interface, then repeats
the send after the block verdicts were actually delivered:

```bash
python windows_kext/test/test_mld_raw.py
```

Raw sends on the test machine returned native `WSAENETUNREACH` (10051). The old
block/replay path reported success before its injection later failed; the
exception restores the native application-visible error, not guaranteed delivery.
A raw probe to `ff0e::1234` did not produce a corresponding notification in
this machine's monitored callout path, so exception matching is covered by the
policy unit test rather than a runtime notification test.
For physical-interface verification, the following test requires Npcap and
Scapy and uses a capture filter for `ff02::16` on the chosen adapter. Its block
phase has the same broad verdict-match caveat:

```bash
python windows_kext/test/test_mld_wire.py --interface-index 18 --capture-interface Ethernet
```

Choose the actual non-loopback interface index and Npcap adapter on another
machine. The diagnostic `--diagnose` option in the loopback and raw tests is for
comparison with a pre-exception diagnostic driver; it deliberately requires
correlated failures and must not be used as a post-fix success test.

## Baseline observations on Windows 11 build 26300

- Without the driver all three packets reached all joined sockets exactly once
  for both IPv4 and IPv6; the nonmember received none.
- With the release driver and PermanentAccept, the first packet was missing on
  loopback for both families; the second and third arrived once per subscriber.
- With temporary Accept on IPv4 loopback, the first packet was missing and the
  second and third arrived twice per subscriber. IPv6 temporary Accept was not
  checked in that comparison.
- With PermanentBlock matched against the outbound destination group before
  the workaround, no subscriber received a packet.
- With PermanentAccept on the machine's non-loopback IPv4 interface and TTL=0,
  local subscribers received all packets once. External network delivery and
  mixed accept/block policies across subscribers were not established by these
  checks.

Async injection errors observed during these runs included
`STATUS_NETWORK_UNREACHABLE` on network-send and `STATUS_DATA_NOT_ACCEPTED` on
transport-receive. A pre-workaround run already contained network-send failures.
A join/leave-only control produced 13 IGMP events to `224.0.0.22` and 13
network-send failures. A later diagnostic build included the cloned IPv4 header
identity in failed completion logs: four reports from `127.0.0.1` had IP IDs
`6129`–`6132`, exactly matching four network-send completions with
`STATUS_NETWORK_UNREACHABLE`. Five further raw packets without Router Alert,
with IGMP types `0x11`, `0x16`, `0x17`, `0x22` and `0xfe` and destinations
`224.0.0.1`, `224.0.0.2` and `224.0.0.22`, likewise each matched a failed
completion before the expanded exception. This confirms which test packets
failed, but not which internal Windows route or stack state caused the status. The same control
using `127.0.0.2` for membership generated reports sourced from `127.0.0.1`.
On the local physical Ethernet interface, an Npcap comparison captured four
test-group IGMP reports both without the driver and with PermanentAccept; no
network-send failures occurred during that physical-interface phase.

A later diagnostic build logged IPv6 protocol, ICMPv6 type, addresses, length
and a bounded fingerprint of the first 128 packet bytes on failed network
completions. In a controlled loopback join/leave test, four MLDv2 report
notifications had fingerprints matching four `STATUS_NETWORK_UNREACHABLE`
completions. A separate control matched failures for 18 different raw ICMPv6
types on `::1 -> ff02::16`, including Echo and Neighbor Discovery type values.
This does not establish that every possible packet or type was tested. The
fingerprint and IPv4 ID/tuple are correlation aids, not globally unique packet
identities. The original WFP compartment was already preserved; network-send
injection accepts no output interface or IPv6 scope argument. The exact Windows
routing/stack cause remains unproven.

On physical Ethernet (IPv6 interface 18), an Npcap control captured four MLDv2
reports without the driver and four with PermanentAccept, but none with
PermanentBlock. No network-send failure was recorded in the two physical phases;
this confirms why physical MLD must remain on its ordinary verdict path.

The following narrow IPv4 diagnostic variants did **not** restore the first
loopback packet: network-receive of the ALE clone using the indicated interface;
rebuilding its IP header and checksums using
`FwpsConstructIpHeaderForTransportPacket0`; both operations combined;
transport-receive with `interfaceIndex=1, subInterfaceIndex=1` instead of the
inbound metadata's `1,0`; a combined network-send/network-receive of outbound
clones; and two exploratory transport-send arrangements. An ALE hard-permit
probe ran for later cached packets but was not reached for the first replay.
These experiments were removed; they do not establish that any API can never
work in a different arrangement. Permitting only outbound indications carrying
WFP's loopback flag was also insufficient: another indication for the same
local send had no such flag, and replaying it duplicated local delivery.

A brief WFP net-event capture found a classify-drop for the test tuple on the
Portmaster inbound ALE callout while an authorization was pending, not on the
`WSH Default Inbound Block` filter. That observation does not rule out every
other filter or explain later asynchronous injection status. WFP event options
were restored after the capture. Do not replace a per-receiver multicast verdict
with a tuple-wide permit or a generic hard permit merely to make this test pass.
