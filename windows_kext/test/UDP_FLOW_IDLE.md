# UDP ALE idle lifetime and regression

The documented UDP unicast ALE idle timeout defaults to 60 seconds, but it is not
an upper bound on when `flowDeleteFn` arrives. On Windows 11 build 26300, testing
an existing `127.0.0.2:53` listener showed:

- Eight completed `nslookup` processes left 24 inbound peers and WFP contexts
  after almost three minutes without further test traffic.
- Association succeeded at layer 52, and client socket closures produced matching
  flow-delete callbacks immediately. No callback was rejected by the registry.
- After 95 seconds of inactivity, fresh DNS traffic triggered deletion of the
  original server flows. Later idle cleanup arrived in another partial batch.
- An isolated echo test reused an exact client tuple after 90 seconds of inactivity.
  Windows still used the old server ALE flow, without another server authorization.

Native remote-peer maintenance can therefore defer idle deletion. A retained
server peer belongs to the listener, not the exited remote client process. Do not
free an associated context directly: WFP owns it until a callback returns it. Do
not simply idle-expire inbound connection policy either: a still-authorized native
flow can skip ALE, and the inbound packet-layer cache-miss path permits packets in
expectation of an ALE authorization that may not occur.

References: [Microsoft ALE stateful filtering](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-stateful-filtering),
[OSR discussion of deferred Windows UDP ALE maintenance](https://community.osr.com/t/wfp-ale-flow-lifetime/59141).

## Opt-in flow diagnostics

Normal builds do not emit these diagnostic records. To build and sign with the
`udp-lifecycle-diagnostics` feature, run from the repository root:

```bash
powershell.exe -NoProfile -Command '& ".\windows_kext\build-signed.bat" --features udp-lifecycle-diagnostics'
```

The feature emits `crate::err!` records for successful associations and callback
entry, acceptance or rejection. They include monotonic time, flow/context and
connection instance IDs, endpoint, PID, layer, callout and tuple. These Error-level
records are intentional diagnostics, not necessarily failures. Associate/delete
records can be correlated by `ctx`; callbacks themselves need not arrive at the
nominal idle deadline. Rebuild without the feature after diagnostics.

## Runtime regression

Run as Administrator, with no existing monitor or PortmasterKext service. The test
refuses to take over an existing driver owner. It creates its own listener on an
unused loopback port, never touches a production DNS listener, and always launches
the monitor with `--duration` (200 seconds with the default idle interval).

```bash
python windows_kext/test/test_udp_flow_idle.py --output windows_kext/test/_out/udp_idle_run
```

Use temporary Accept to also check that a new client process receives an outbound
verdict when it reuses the exact tuple after the idle interval:

```bash
python windows_kext/test/test_udp_flow_idle.py --verdict accept --output windows_kext/test/_out/udp_idle_accept_run
```

Each output directory must be fresh. The test records client process exits,
server events before and after idle/reuse/probe traffic, listener closure and
post-grace cleanup. It verifies request/reply delivery, END events, absence of
invalid verdict/injection/association errors, and graceful monitor/service cleanup.
It does not require native WFP idle deletion to happen at an exact deadline.
The optional verdict applies only to the isolated test endpoint; unrelated traffic
retains the monitor's default PermanentAccept.
