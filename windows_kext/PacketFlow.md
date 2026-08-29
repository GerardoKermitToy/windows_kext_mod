# There and back again: a packet's path

This document describes how packets move through the Windows kernel extension and where Portmaster decisions are applied.

## Entry layers

The first callout depends on packet direction and protocol:

- Outbound TCP enters `ALE_AUTH_CONNECT` before it reaches the outbound IP packet layer.
- Outbound UDP is registered at `ALE_AUTH_CONNECT` to capture its PID, but is authorized at the outbound IP packet layer so an ALE pend cannot corrupt the application's send result.
- Inbound traffic first reaches the inbound IP packet layer.
  - A new TCP or UDP tuple is permitted upward to `ALE_AUTH_RECV_ACCEPT`.
  - A tuple already known as an inbound connection bypasses packet-level classification in both directions because its policy is owned by ALE.
  - A received packet belonging to an outbound connection remains on the packet path; this is required for temporary verdicts and reverse redirect rewriting.
- ICMP and other protocols are handled at the IP packet layer.

## ALE authorization

Two pairs of terminating, resettable callouts implement connection-level authorization:

- `ALE_AUTH_CONNECT_V4/V6` for outbound connections.
- `ALE_AUTH_RECV_ACCEPT_V4/V6` for inbound TCP accepts and the first inbound UDP packet from a unique remote tuple.

Both paths build the same connection key from WFP's fixed fields and use the process ID supplied in ALE metadata. This means an inbound connection is created with its owning PID instead of the PID 0 that the IP packet layer had to use.

### New connection

For a new TCP/UDP connection:

1. Build the connection key from ALE fields.
2. Save the classify operation and, when packet data exists, clone it.
   - At inbound receive/accept the NBL data offset is at the transport payload. The driver retreats by WFP's IP-header size plus transport-header size before cloning, so the clone starts at the IP header as required by transport receive injection.
   - The event sent to Portmaster exposes the clone from the transport header and reports payload layer 4.
3. Pend an initial ALE operation with `FwpsPendOperation0`. A reauthorization cannot be pended, so that path blocks the current indication and later resets the resettable filters.
4. Add an `Undecided` cache entry before publishing the request to Portmaster.
5. Block and absorb the current indication while Portmaster decides.

If another indication arrives while the cache entry is still `Undecided`, it is saved under a separate packet ID and another event is queued.

### Applying a verdict

- `Accept` and `PermanentAccept` complete the ALE operation and reinject a saved packet when one exists.
- For inbound receive/accept, the same NBL is supplied to `FwpsCompleteOperation0` before `FwpsInjectTransportReceiveAsync0` is called. The transport injection handle is checked when the clone is indicated again, and self-injected packets are permitted without another request.
- Block/drop/failed verdicts complete an ALE pend without injecting the clone.
- Permanent cached verdicts are applied directly on later ALE classifications.
- Updating a cached verdict resets the resettable ALE filters so existing ALE-authorized flows are reauthorized against the new value.

### Flow-established attribution

The inspection callouts at `ALE_FLOW_ESTABLISHED_V4/V6` refresh the process ID of an existing TCP or UDP cache entry. TCP reaches this layer after its three-way handshake; UDP reaches it immediately after `ALE_AUTH_CONNECT` or `ALE_AUTH_RECV_ACCEPT` authorizes the first packet for a remote tuple. Required fixed fields are type-checked before the five-tuple is read, because the filters also see non-TCP/UDP protocols and generic flows that cannot be matched safely to an exact cache key.

For UDP, the driver associates a context containing the remote tuple with the WFP flow via `FwpsFlowAssociateContext`. WFP invokes `flowDeleteFn` when that peer flow is actually reclaimed, and the callback emits the connection-end event. Windows documents a 60-second default idle lifetime, but current Windows versions can defer idle reclamation substantially and, in observed inbound tests, beyond four minutes while the socket remains open. Therefore native flow deletion is an early lifecycle signal rather than the only deadline: the connection-cache watchdog emits END after ten minutes of observed inactivity. The same cleanup pass removes that exact instance from the endpoint cache and calls `FwpsFlowRemoveContext` to return the driver-owned context; removing a callout context does not close the application's socket or terminate the underlying WFP flow. When WFP supplies a transport endpoint handle at authorization or flow establishment, the driver associates the authorized tuple with that handle. Windows emits `ALE_ENDPOINT_CLOSURE` once for the UDP socket, not once per remote peer, so socket closure ends any associated tuples that still have a live cache entry.

The cache's PID precedence rules ignore PID 0, prevent System (PID 4) from replacing a concrete application, and allow a concrete application PID to replace less reliable attribution. This repairs packet-layer fallback entries and refreshes the UDP owner without changing the cached verdict.

`ALE_FLOW_ESTABLISHED` is not emitted again for successful reauthorization, so this monitor cannot attribute a flow that was already active when the driver loaded.

`ALE_AUTH_RECV_ACCEPT` is a connection/remote-tuple authorization layer, not a per-packet layer. Consequently, inbound TCP/UDP verdicts apply to the ALE connection or UDP remote tuple. Per-packet temporary verdict processing remains only for flows owned by the outbound packet path.

## IP packet layer

The packet callouts still see every network-layer indication, but they no longer create or decide inbound TCP/UDP connections.

### TCP and UDP

- A new inbound tuple is permitted to `ALE_AUTH_RECV_ACCEPT`.
- Packets whose cached connection direction is inbound are permitted without a second packet-level decision.
- Packets whose cached connection direction is outbound retain the existing packet behavior:
  - permanent accept/block/drop is applied immediately;
  - temporary verdicts create a Portmaster request;
  - redirect verdicts clone, rewrite, recalculate checksums, inject the replacement, and absorb the original.
- An outbound tuple unexpectedly missing from the cache uses the defensive packet-level fallback.

### Other protocols

ICMP, IGMP, and protocols without TCP/UDP connection state are treated as temporary packet decisions. Each packet is cloned, sent to Portmaster, and reinjected only when allowed. ICMP echo requests use a short-lived identifier cache to associate replies with the sending process.

### Fragments and injected packets

Individual IP fragments are permitted until WFP presents the reassembled datagram, which has a complete transport header and can be keyed safely. Network- and transport-injected packets are detected with the corresponding injection handle and permitted to prevent reinjection loops.

## Connection cache

The cache stores TCP and UDP keys, direction, process ID, verdict, redirect state, and activity timestamps. Native WFP flow deletion, endpoint closure, and resource release mark tracked connections as ended and emit their lifecycle event. Cleanup removes ended entries after their one-minute late-packet grace period. A ten-minute inactivity watchdog applies only to live UDP entries: it emits END, removes the endpoint association, and returns the callout-owned WFP context, including when native WFP cleanup is delayed. Live TCP entries are never removed for inactivity; they remain until a native lifecycle signal ends them, the cache is explicitly cleared, or the driver unloads. These cleanup operations are bookkeeping only and do not abort the WFP flow or close the application's socket.
