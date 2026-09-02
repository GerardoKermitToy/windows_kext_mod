use core::{fmt::Display, time::Duration};

use crate::connection::{is_redirect_port, Connection, Direction};
use alloc::{collections::BTreeMap, vec::Vec};
use core::ops::Range;
use smoltcp::wire::{IpAddress, IpProtocol};

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
pub struct Key {
    pub(crate) protocol: IpProtocol,
    pub(crate) local_address: IpAddress,
    pub(crate) local_port: u16,
    pub(crate) remote_address: IpAddress,
    pub(crate) remote_port: u16,
}

impl Display for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "p: {} l: {}:{} r: {}:{}",
            self.protocol,
            self.local_address,
            self.local_port,
            self.remote_address,
            self.remote_port
        )
    }
}

impl Key {
    /// Returns the protocol and port as a tuple.
    pub fn small(&self) -> (IpProtocol, u16) {
        (self.protocol, self.local_port)
    }

    /// Returns true if the local address is an IPv4 address.
    pub fn is_ipv6(&self) -> bool {
        match self.local_address {
            IpAddress::Ipv4(_) => false,
            IpAddress::Ipv6(_) => true,
        }
    }

    /// Returns true if the local address is a loopback address.
    pub fn is_loopback(&self) -> bool {
        match self.local_address {
            IpAddress::Ipv4(ip) => ip.is_loopback(),
            IpAddress::Ipv6(ip) => ip.is_loopback(),
        }
    }

    /// Returns a new key with the local and remote addresses and ports reversed.
    #[allow(dead_code)]
    pub fn reverse(&self) -> Key {
        Key {
            protocol: self.protocol,
            local_address: self.remote_address,
            local_port: self.remote_port,
            remote_address: self.local_address,
            remote_port: self.local_port,
        }
    }
}

/// Connections grouped by `(protocol, local port)`.
///
/// Each vector is kept sorted by `Connection::remote_key()`, so a lookup by
/// remote endpoint is a binary search rather than a scan of the whole port. That
/// matters for ports carrying many connections at once - a busy listener, or an
/// inbound flood - where every packet used to walk the entire vector while
/// holding a spin lock at DISPATCH_LEVEL.
///
/// The invariant is maintained by the insertion methods alone. Nothing else
/// inserts, `retain` preserves relative order, and the fields callers mutate
/// through `get_mut` are not part of the sort key. Should that ever change,
/// lookups would start missing silently.
///
/// The sort key is deliberately *not* unique. Several connections can share a
/// remote endpoint on the same local port: an ended entry still awaiting cleanup
/// in front of its live replacement, or entries that differ only in local
/// address. Lookups therefore resolve the whole run of equal keys. They retain
/// insertion order among equally viable entries, but an ended entry can never
/// shadow a live replacement.
pub struct ConnectionMap<T: Connection>(BTreeMap<(IpProtocol, u16), Vec<T>>);

/// Returns the range of entries whose remote endpoint equals `target`.
///
/// `partition_point` is used twice instead of `binary_search_by`, because the
/// sort key is not unique: `binary_search_by` returns an arbitrary index inside
/// a run of equal keys, and selecting only that entry could let retained ended
/// history shadow the live replacement behind it. The two bounds give the whole
/// run, in insertion order.
fn equal_range<T: Connection>(connections: &[T], target: (IpAddress, u16)) -> Range<usize> {
    let start = connections.partition_point(|conn| conn.remote_key() < target);
    let end = connections.partition_point(|conn| conn.remote_key() <= target);
    start..end
}

/// Returns the first live match and remembers the first ended match as a
/// possible late-packet fallback.
fn live_and_ended_match<T, F>(connections: &[T], mut matches: F) -> (Option<&T>, Option<&T>)
where
    T: Connection,
    F: FnMut(&T) -> bool,
{
    let mut ended_match = None;

    for conn in connections {
        if !matches(conn) {
            continue;
        }

        if !conn.has_ended() {
            return (Some(conn), ended_match);
        }

        if ended_match.is_none() {
            ended_match = Some(conn);
        }
    }

    (None, ended_match)
}

#[inline]
fn get_monotonic_timestamp_ms() -> u64 {
    #[cfg(not(test))]
    {
        wdk::utils::get_monotonic_timestamp_ms()
    }

    #[cfg(test)]
    {
        // Keep test timestamps beyond both cleanup thresholds without linking
        // the kernel clock into the user-mode test executable.
        Duration::from_secs(60 * 60).as_millis() as u64
    }
}

impl<T: Connection + Clone> ConnectionMap<T> {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    fn add(&mut self, conn: T) {
        let key = conn.get_key().small();
        if let Some(connections) = self.0.get_mut(&key) {
            // Insert *after* any entries with the same remote endpoint. That keeps
            // the vector in insertion order within a run of equal keys, which the
            // lookups and exact-instance operations can reach a live connection
            // added behind ended history, while `read_with_ended_fallback` keeps
            // the oldest ended match for late packets.
            let index = connections.partition_point(|c| c.remote_key() <= conn.remote_key());
            connections.insert(index, conn);
        } else {
            self.0.insert(key, alloc::vec![conn]);
        }
    }

    /// Inserts `conn` only when its exact tuple has no live cache entry.
    ///
    /// The caller owns the map exclusively for this entire check-and-insert, so
    /// two classify callbacks cannot both observe absence and create duplicate
    /// live entries. Retained ended history deliberately does not block tuple
    /// reuse. The live instance ID is returned on both paths so callers can bind
    /// follow-up state to the same entry without a second tuple lookup.
    pub(crate) fn insert_if_absent(&mut self, conn: T) -> Result<u64, (T, u64)> {
        let key = conn.get_key();
        if let Some(connections) = self.0.get(&key.small()) {
            let range = equal_range(connections, (key.remote_address, key.remote_port));
            if let Some(existing) = connections[range]
                .iter()
                .find(|existing| existing.remote_equals(&key) && !existing.has_ended())
            {
                return Err((conn, existing.get_instance_id()));
            }
        }

        let instance_id = conn.get_instance_id();
        self.add(conn);
        Ok(instance_id)
    }

    /// Returns the live connection matching `key` for mutation.
    ///
    /// Ended entries are deliberately not a fallback here. A delayed verdict or
    /// PID update belongs either to a live replacement or to no current
    /// connection; mutating retained history would make a stale verdict visible
    /// to late packets without changing the active flow.
    pub fn get_mut(&mut self, key: &Key) -> Option<&mut T> {
        if let Some(connections) = self.0.get_mut(&key.small()) {
            let range = equal_range(connections, (key.remote_address, key.remote_port));
            for conn in &mut connections[range] {
                if conn.remote_equals(key) && !conn.has_ended() {
                    conn.set_last_accessed_time(get_monotonic_timestamp_ms());
                    return Some(conn);
                }
            }
        }

        None
    }

    /// Returns whether one exact connection-cache instance is still live.
    ///
    /// Unlike `read`, this check does not refresh activity and never falls back to
    /// redirected or ended state. It is used to validate endpoint-owned identity.
    pub fn has_live_instance(&self, key: &Key, instance_id: u64) -> bool {
        if instance_id == 0 {
            return false;
        }

        if let Some(connections) = self.0.get(&key.small()) {
            let range = equal_range(connections, (key.remote_address, key.remote_port));
            return connections[range].iter().any(|conn| {
                conn.remote_equals(key)
                    && conn.get_instance_id() == instance_id
                    && !conn.has_ended()
            });
        }
        false
    }

    /// Returns the exact live cache instance for mutation.
    ///
    /// Pending verdicts carry the instance that existed when their packet was
    /// queued. Requiring both identities prevents a delayed verdict from mutating
    /// a replacement connection that reused the same tuple. Redirected packet keys
    /// are supported for the packet-layer path in the same way as `read_matching`.
    pub fn get_mut_instance(&mut self, key: &Key, instance_id: u64) -> Option<&mut T> {
        if instance_id == 0 {
            return None;
        }

        let timestamp = get_monotonic_timestamp_ms();
        if let Some(connections) = self.0.get_mut(&key.small()) {
            let range = equal_range(connections, (key.remote_address, key.remote_port));
            if let Some(index) = range.clone().find(|index| {
                let conn = &connections[*index];
                conn.remote_equals(key)
                    && conn.get_instance_id() == instance_id
                    && !conn.has_ended()
            }) {
                let conn = &mut connections[index];
                conn.set_last_accessed_time(timestamp);
                return Some(conn);
            }

            if is_redirect_port(key.remote_port) {
                if let Some(conn) = connections.iter_mut().find(|conn| {
                    conn.redirect_equals(key)
                        && conn.get_instance_id() == instance_id
                        && !conn.has_ended()
                }) {
                    conn.set_last_accessed_time(timestamp);
                    return Some(conn);
                }
            }
        }

        None
    }

    /// Reads the best live connection matching `key`.
    ///
    /// Live exact matches take precedence over live redirect matches. Ended
    /// entries are deliberately ignored so connection-establishment and update
    /// paths cannot mistake retained history for a current flow.
    pub fn read<C>(&self, key: &Key, read_connection: fn(&T) -> Option<C>) -> Option<C> {
        self.read_matching(key, read_connection, false)
    }

    /// Reads the best connection matching `key`, including retained history.
    ///
    /// Live exact and redirect matches still take precedence. An ended match is
    /// returned only when no live candidate exists, preserving policy for a
    /// packet already in flight after its connection closed.
    pub fn read_with_ended_fallback<C>(
        &self,
        key: &Key,
        read_connection: fn(&T) -> Option<C>,
    ) -> Option<C> {
        self.read_matching(key, read_connection, true)
    }

    /// Reads connection policy for one packet indication.
    ///
    /// An inbound packet can be the first packet of a new flow that reused an
    /// ended tuple before ALE registered its replacement, so it must use live
    /// state only. Outbound TCP/UDP reaches ALE before the packet layer; when no
    /// live entry exists there, retained state can still classify a packet that
    /// was already in flight when its connection closed.
    pub fn read_for_packet<C>(
        &self,
        key: &Key,
        packet_direction: Direction,
        read_connection: fn(&T) -> Option<C>,
    ) -> Option<C> {
        match packet_direction {
            Direction::Inbound => self.read(key, read_connection),
            Direction::Outbound => self.read_with_ended_fallback(key, read_connection),
        }
    }

    fn read_matching<C>(
        &self,
        key: &Key,
        read_connection: fn(&T) -> Option<C>,
        use_ended_fallback: bool,
    ) -> Option<C> {
        if let Some(connections) = self.0.get(&key.small()) {
            // Exact remote match first, over the run of equal keys only.
            let range = equal_range(connections, (key.remote_address, key.remote_port));
            let (live_exact, ended_exact) =
                live_and_ended_match(&connections[range], |conn| conn.remote_equals(key));

            if let Some(conn) = live_exact {
                conn.set_last_accessed_time(get_monotonic_timestamp_ms());
                return read_connection(conn);
            }

            // A redirected connection cannot be found by the search above: it is
            // stored under its real remote endpoint, while the packet that comes
            // back carries the redirect target instead (loopback:53 for a DNS
            // redirect, for example). Those are found by scanning.
            //
            // The scan is guarded by the port test so it does not run on every
            // miss. `redirect_equals` only ever accepts one of the three redirect
            // ports, so for any other remote port the scan cannot match and is
            // skipped - which is what keeps an inbound flood, where every lookup
            // misses, off the O(n) path.
            let (live_redirect, ended_redirect) = if is_redirect_port(key.remote_port) {
                live_and_ended_match(connections, |conn| conn.redirect_equals(key))
            } else {
                (None, None)
            };

            // Any live redirect is newer connection state than retained ended
            // history, even if that history happens to be an exact match for the
            // redirect endpoint. Exact matching still wins when both are live.
            let ended_match = if use_ended_fallback {
                ended_exact.or(ended_redirect)
            } else {
                None
            };
            if let Some(conn) = live_redirect.or(ended_match) {
                conn.set_last_accessed_time(get_monotonic_timestamp_ms());
                return read_connection(conn);
            }
        }

        None
    }

    /// Refreshes one exact live cache instance.
    pub fn touch_instance(&mut self, key: &Key, instance_id: u64) -> bool {
        if let Some(connections) = self.0.get_mut(&key.small()) {
            let range = equal_range(connections, (key.remote_address, key.remote_port));
            for conn in &mut connections[range] {
                if conn.remote_equals(key)
                    && conn.get_instance_id() == instance_id
                    && !conn.has_ended()
                {
                    conn.set_last_accessed_time(get_monotonic_timestamp_ms());
                    return true;
                }
            }
        }
        false
    }

    /// Ends the live connection matching both its tuple and cache-instance ID.
    ///
    /// WFP flow deletion can race with tuple reuse. Binding the callback to the
    /// instance that existed when its context was associated prevents an old flow
    /// from ending a newer connection with the same five-tuple.
    pub fn end_instance(&mut self, key: Key, instance_id: u64) -> Option<T> {
        if let Some(connections) = self.0.get_mut(&key.small()) {
            let range = equal_range(connections, (key.remote_address, key.remote_port));
            for conn in &mut connections[range] {
                if conn.remote_equals(&key)
                    && conn.get_instance_id() == instance_id
                    && !conn.has_ended()
                {
                    conn.end(get_monotonic_timestamp_ms());
                    return Some(conn.clone());
                }
            }
        }
        None
    }

    /// Ends live connections for one local endpoint and returns copies of them.
    ///
    /// The map is grouped by protocol and local port, but that grouping is not a
    /// sufficient identity: two local addresses can listen on the same port, and
    /// multiple processes can share an endpoint with `SO_REUSEADDR`. The optional
    /// address and PID filters are supplied by the ALE endpoint-closure indication.
    ///
    /// A connection with PID 0 is treated as an unknown owner and is eligible when
    /// a closure carries a PID. Otherwise a PID-0 connection would remain stale
    /// forever when it was created before attribution became available. A missing
    /// local address (WFP `FWP_EMPTY` for a wildcard bind) deliberately means
    /// "all local addresses", leaving the PID as the disambiguating field.
    pub fn end_all_on_endpoint(
        &mut self,
        key: (IpProtocol, u16),
        local_address: Option<IpAddress>,
        process_id: Option<u64>,
    ) -> Option<Vec<T>> {
        if let Some(connections) = self.0.get_mut(&key) {
            let mut vec = Vec::with_capacity(connections.len());
            for conn in connections.iter_mut() {
                let address_matches = local_address
                    .map(|address| conn.get_local_address() == address)
                    .unwrap_or(true);
                let process_matches = process_id
                    .map(|pid| conn.get_process_id() == 0 || conn.get_process_id() == pid)
                    .unwrap_or(true);

                if !conn.has_ended() && address_matches && process_matches {
                    conn.end(get_monotonic_timestamp_ms());
                    vec.push(conn.clone());
                }
            }
            return Some(vec);
        }
        return None;
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Removes ended history after its one-minute late-packet grace period.
    /// Live TCP and UDP entries are retained regardless of inactivity until a
    /// native lifecycle indication ends them, the cache is cleared, or the driver
    /// unloads.
    pub fn clean_ended_connections(&mut self) {
        let now = get_monotonic_timestamp_ms();
        let before_one_minute = now.saturating_sub(Duration::from_secs(60).as_millis() as u64);

        for connections in self.0.values_mut() {
            // `retain` preserves the relative order of the entries it keeps, so
            // the sort order the lookups depend on survives the sweep.
            connections.retain(|c| !c.has_ended() || c.get_end_time() >= before_one_minute);
        }
        self.0.retain(|_, v| !v.is_empty());
    }

    /// Appends the IDs of every live UDP cache instance without refreshing activity.
    ///
    /// Periodic UDP lifecycle cleanup uses this snapshot after taking its endpoint
    /// and flow snapshots. A newly created association therefore cannot be mistaken
    /// for stale state, and inspecting an instance does not postpone its timeout.
    pub fn append_live_udp_instance_ids(&self, instance_ids: &mut Vec<u64>) {
        for connections in self.0.values() {
            for connection in connections {
                if connection.get_protocol() == IpProtocol::Udp && !connection.has_ended() {
                    instance_ids.push(connection.get_instance_id());
                }
            }
        }
    }

    pub fn get_count(&self) -> usize {
        let mut count = 0;
        for conn in self.0.values() {
            count += conn.len();
        }
        return count;
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectionMap, Key};
    use crate::connection::{Connection, ConnectionV4, Direction, Verdict, PM_DNS_PORT};
    use core::time::Duration;
    use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address};

    fn key(remote_address: [u8; 4], remote_port: u16) -> Key {
        Key {
            protocol: IpProtocol::Udp,
            local_address: IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)),
            local_port: 50_000,
            remote_address: IpAddress::Ipv4(Ipv4Address::from_bytes(&remote_address)),
            remote_port,
        }
    }

    fn live(key: &Key, process_id: u64) -> ConnectionV4 {
        ConnectionV4::from_key(key, process_id, Direction::Outbound).expect("IPv4 key")
    }

    fn ended(key: &Key, process_id: u64) -> ConnectionV4 {
        let mut conn = live(key, process_id);
        conn.end(1);
        conn
    }

    fn ended_in_direction(key: &Key, process_id: u64, direction: Direction) -> ConnectionV4 {
        let mut conn = ConnectionV4::from_key(key, process_id, direction).expect("IPv4 key");
        conn.end(1);
        conn
    }

    fn redirected(mut conn: ConnectionV4) -> ConnectionV4 {
        conn.verdict = Verdict::RedirectNameServer;
        conn
    }

    fn read_process_id(conn: &ConnectionV4) -> Option<u64> {
        Some(conn.process_id)
    }

    #[test]
    fn reused_live_exact_entry_wins_and_survives_cleanup() {
        let tuple = key([8, 8, 8, 8], 53);
        let mut map = ConnectionMap::new();
        map.add(ended(&tuple, 10));
        map.add(live(&tuple, 20));

        assert_eq!(map.read(&tuple, read_process_id), Some(20));
        assert_eq!(
            map.read_with_ended_fallback(&tuple, read_process_id),
            Some(20)
        );

        let conn = map.get_mut(&tuple).expect("live entry");
        assert_eq!(conn.process_id, 20);
        conn.process_id = 21;

        map.clean_ended_connections();

        assert_eq!(map.get_count(), 1);
        assert_eq!(map.read(&tuple, read_process_id), Some(21));
    }

    #[test]
    fn ended_exact_entry_is_not_inbound_packet_fallback() {
        let tuple = key([8, 8, 4, 4], 53);

        for connection_direction in [Direction::Inbound, Direction::Outbound] {
            let mut map = ConnectionMap::new();
            map.add(ended_in_direction(&tuple, 10, connection_direction));

            assert_eq!(
                map.read_for_packet(&tuple, Direction::Inbound, read_process_id),
                None
            );
        }
    }

    #[test]
    fn ended_exact_entry_is_read_only_late_packet_fallback() {
        let tuple = key([8, 8, 4, 4], 53);
        let mut map = ConnectionMap::new();
        map.add(ended(&tuple, 10));

        assert_eq!(map.read(&tuple, read_process_id), None);
        assert_eq!(
            map.read_with_ended_fallback(&tuple, read_process_id),
            Some(10)
        );
        assert_eq!(
            map.read_for_packet(&tuple, Direction::Outbound, read_process_id),
            Some(10)
        );
        assert!(map.get_mut(&tuple).is_none());
    }

    #[test]
    fn insert_if_absent_rejects_duplicate_live_tuple() {
        let tuple = key([8, 8, 8, 8], 443);
        let mut map = ConnectionMap::new();
        let existing = live(&tuple, 10);
        let existing_instance_id = existing.get_instance_id();
        map.add(existing);

        let rejected = match map.insert_if_absent(live(&tuple, 20)) {
            Ok(_) => panic!("duplicate live tuple was inserted"),
            Err((connection, returned_instance_id)) => {
                assert_eq!(returned_instance_id, existing_instance_id);
                assert_ne!(returned_instance_id, connection.get_instance_id());
                connection
            }
        };

        assert_eq!(rejected.process_id, 20);
        assert_eq!(map.get_count(), 1);
        assert_eq!(map.read(&tuple, read_process_id), Some(10));
    }

    #[test]
    fn insert_if_absent_allows_tuple_reuse_after_end() {
        let tuple = key([8, 8, 4, 4], 443);
        let mut map = ConnectionMap::new();
        map.add(ended(&tuple, 10));

        assert!(map.insert_if_absent(live(&tuple, 20)).is_ok());
        assert_eq!(map.get_count(), 2);
        assert_eq!(map.read(&tuple, read_process_id), Some(20));
    }

    #[test]
    fn reused_live_redirect_entry_wins() {
        let original = key([8, 8, 8, 8], 53);
        let redirect_target = key([127, 0, 0, 1], PM_DNS_PORT);
        let mut map = ConnectionMap::new();
        map.add(redirected(ended(&original, 10)));
        map.add(redirected(live(&original, 20)));

        assert_eq!(map.read(&redirect_target, read_process_id), Some(20));
        assert_eq!(
            map.read_with_ended_fallback(&redirect_target, read_process_id),
            Some(20)
        );
    }

    #[test]
    fn live_redirect_wins_over_ended_exact_fallback() {
        let redirect_target = key([127, 0, 0, 1], PM_DNS_PORT);
        let original = key([8, 8, 8, 8], 53);
        let mut map = ConnectionMap::new();
        map.add(ended(&redirect_target, 10));
        map.add(redirected(live(&original, 20)));

        assert_eq!(
            map.read_with_ended_fallback(&redirect_target, read_process_id),
            Some(20)
        );
    }

    #[test]
    fn live_exact_wins_over_live_redirect() {
        let redirect_target = key([127, 0, 0, 1], PM_DNS_PORT);
        let original = key([8, 8, 8, 8], 53);
        let mut map = ConnectionMap::new();
        map.add(redirected(live(&original, 20)));
        map.add(live(&redirect_target, 10));

        assert_eq!(map.read(&redirect_target, read_process_id), Some(10));
    }

    #[test]
    fn cleanup_keeps_inactive_live_udp_until_lifecycle_end() {
        let tuple = key([203, 0, 113, 1], 443);
        let conn = live(&tuple, 10);
        conn.set_last_accessed_time(Duration::from_secs(50 * 60).as_millis() as u64);
        let mut map = ConnectionMap::new();
        map.add(conn);

        map.clean_ended_connections();

        assert_eq!(map.get_count(), 1);
        assert_eq!(map.read(&tuple, read_process_id), Some(10));
    }

    #[test]
    fn cleanup_keeps_inactive_live_tcp_until_lifecycle_end() {
        let mut tuple = key([203, 0, 113, 4], 443);
        tuple.protocol = IpProtocol::Tcp;
        let conn = live(&tuple, 10);
        conn.set_last_accessed_time(Duration::from_secs(50 * 60).as_millis() as u64);
        let mut map = ConnectionMap::new();
        map.add(conn);

        map.clean_ended_connections();

        assert_eq!(map.get_count(), 1);
        assert_eq!(map.read(&tuple, read_process_id), Some(10));
    }

    #[test]
    fn cleanup_removes_ended_entry_after_grace_period() {
        let tuple = key([203, 0, 113, 2], 443);
        let mut map = ConnectionMap::new();
        map.add(ended(&tuple, 10));

        map.clean_ended_connections();
        assert_eq!(map.get_count(), 0);
    }

    #[test]
    fn stale_flow_instance_cannot_end_reused_tuple() {
        let tuple = key([198, 51, 100, 1], 443);
        let old = live(&tuple, 10);
        let old_instance_id = old.get_instance_id();
        let mut map = ConnectionMap::new();
        map.add(old);
        map.clear();
        map.add(live(&tuple, 20));

        assert!(map.end_instance(tuple, old_instance_id).is_none());
        assert_eq!(map.read(&tuple, read_process_id), Some(20));
    }

    #[test]
    fn exact_live_instance_can_be_touched() {
        let tuple = key([198, 51, 100, 3], 443);
        let conn = live(&tuple, 10);
        let instance_id = conn.get_instance_id();
        let mut map = ConnectionMap::new();
        map.add(conn);

        assert!(map.touch_instance(&tuple, instance_id));
        assert_eq!(map.get_count(), 1);
    }

    #[test]
    fn live_udp_instance_snapshot_excludes_ended_and_tcp() {
        let udp_key = key([198, 51, 100, 4], 443);
        let live_udp = live(&udp_key, 10);
        let live_udp_instance_id = live_udp.get_instance_id();
        let ended_udp = ended(&key([198, 51, 100, 5], 443), 20);
        let mut tcp_key = key([198, 51, 100, 6], 443);
        tcp_key.protocol = IpProtocol::Tcp;
        let live_tcp = live(&tcp_key, 30);

        let mut map = ConnectionMap::new();
        map.add(live_udp);
        map.add(ended_udp);
        map.add(live_tcp);

        let mut instance_ids = alloc::vec::Vec::new();
        map.append_live_udp_instance_ids(&mut instance_ids);
        assert_eq!(instance_ids, alloc::vec![live_udp_instance_id]);
    }

    #[test]
    fn stale_instance_cannot_mutate_reused_tuple() {
        let tuple = key([198, 51, 100, 7], 443);
        let old = live(&tuple, 10);
        let old_instance_id = old.get_instance_id();
        let mut map = ConnectionMap::new();
        map.add(old);
        map.clear();

        let replacement = live(&tuple, 20);
        let replacement_instance_id = replacement.get_instance_id();
        map.add(replacement);

        assert!(!map.has_live_instance(&tuple, old_instance_id));
        assert!(map.has_live_instance(&tuple, replacement_instance_id));
        assert!(map.get_mut_instance(&tuple, old_instance_id).is_none());
        map.get_mut_instance(&tuple, replacement_instance_id)
            .expect("replacement instance")
            .process_id = 30;
        assert_eq!(map.read(&tuple, read_process_id), Some(30));
    }

    #[test]
    fn exact_instance_update_resolves_redirected_packet_key() {
        let original = key([198, 51, 100, 8], 53);
        let redirect_target = key([127, 0, 0, 1], PM_DNS_PORT);
        let connection = redirected(live(&original, 10));
        let instance_id = connection.get_instance_id();
        let mut map = ConnectionMap::new();
        map.add(connection);

        map.get_mut_instance(&redirect_target, instance_id)
            .expect("redirected instance")
            .process_id = 40;
        assert_eq!(map.read(&original, read_process_id), Some(40));
    }

    #[test]
    fn stale_instance_cannot_refresh_reused_tuple() {
        let tuple = key([198, 51, 100, 2], 443);
        let old = live(&tuple, 10);
        let old_instance_id = old.get_instance_id();
        let mut map = ConnectionMap::new();
        map.add(old);
        map.clear();
        map.add(live(&tuple, 20));

        assert!(!map.touch_instance(&tuple, old_instance_id));
        assert_eq!(map.read(&tuple, read_process_id), Some(20));
    }

    #[test]
    fn ended_redirect_is_late_packet_fallback() {
        let original = key([8, 8, 8, 8], 53);
        let redirect_target = key([127, 0, 0, 1], PM_DNS_PORT);
        let mut map = ConnectionMap::new();
        map.add(redirected(ended(&original, 10)));

        assert_eq!(map.read(&redirect_target, read_process_id), None);
        assert_eq!(
            map.read_with_ended_fallback(&redirect_target, read_process_id),
            Some(10)
        );
    }

    #[test]
    fn ended_redirect_is_not_inbound_packet_fallback() {
        let original = key([8, 8, 8, 8], 53);
        let redirect_target = key([127, 0, 0, 1], PM_DNS_PORT);

        for connection_direction in [Direction::Inbound, Direction::Outbound] {
            let mut map = ConnectionMap::new();
            map.add(redirected(ended_in_direction(
                &original,
                10,
                connection_direction,
            )));

            assert_eq!(
                map.read_for_packet(&redirect_target, Direction::Inbound, read_process_id),
                None
            );
        }
    }
}
