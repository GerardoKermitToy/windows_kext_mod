use core::{fmt::Display, ops::Bound, time::Duration};

use crate::connection::{is_redirect_port, Connection, Direction};
use alloc::{collections::BTreeMap, vec::Vec};
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

/// Orderable identity used inside one `(protocol, local port)` bucket.
///
/// The remote endpoint is the searchable prefix. The map-local sequence makes
/// retained generations distinct and preserves their insertion order without moving
/// existing connection objects when a new remote endpoint is inserted.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct ConnectionIndex {
    remote_address: IpAddress,
    remote_port: u16,
    sequence: u64,
}

impl ConnectionIndex {
    fn from_connection<T: Connection>(connection: &T, sequence: u64) -> Self {
        Self {
            remote_address: connection.get_remote_address(),
            remote_port: connection.get_remote_port(),
            sequence,
        }
    }

    fn first(key: &Key) -> Self {
        Self {
            remote_address: key.remote_address,
            remote_port: key.remote_port,
            sequence: 0,
        }
    }

    fn last(key: &Key) -> Self {
        Self {
            remote_address: key.remote_address,
            remote_port: key.remote_port,
            sequence: u64::MAX,
        }
    }
}

/// Connections grouped by `(protocol, local port)` and indexed by remote endpoint.
///
/// Busy listeners retain many ended generations for late packets. A contiguous,
/// sorted vector made each randomly ordered remote insertion move O(n) connection
/// objects while holding the map's write spin lock. The inner B-tree keeps exact
/// lookup and insertion O(log n) without relocating unrelated generations.
///
/// The remote endpoint prefix is deliberately not the complete tuple. Two local
/// addresses can use the same port and remote endpoint, so exact operations still
/// validate `Connection::remote_equals`. A sequence assigned under exclusive map
/// access preserves the previous insertion-order choice within that candidate range.
pub struct ConnectionMap<T: Connection>(
    BTreeMap<(IpProtocol, u16), BTreeMap<ConnectionIndex, T>>,
    u64,
);

fn connection_range(key: &Key) -> (Bound<ConnectionIndex>, Bound<ConnectionIndex>) {
    (
        Bound::Included(ConnectionIndex::first(key)),
        Bound::Included(ConnectionIndex::last(key)),
    )
}

/// Returns the first live match and remembers the first ended match as a
/// possible late-packet fallback.
fn live_and_ended_match<'a, T, F, I>(
    connections: I,
    mut matches: F,
) -> (Option<&'a T>, Option<&'a T>)
where
    T: Connection + 'a,
    F: FnMut(&T) -> bool,
    I: IntoIterator<Item = &'a T>,
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

const UNTRACKED_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

fn should_expire_untracked<T: Connection>(connection: &T, cutoff: u64) -> bool {
    !connection.has_ended()
        && !connection.has_native_lifecycle()
        && matches!(connection.get_direction(), Direction::Outbound)
        && connection.get_last_accessed_time() < cutoff
}

/// Refreshes the only connections whose lifetime depends on packet activity.
/// Native WFP state retires tracked connections, while inbound fallbacks wait for
/// endpoint closure, so reading the system clock and storing a timestamp for either
/// category cannot affect cleanup.
#[inline]
fn refresh_untracked_activity<T: Connection>(connection: &T) {
    if !connection.has_ended()
        && !connection.has_native_lifecycle()
        && matches!(connection.get_direction(), Direction::Outbound)
    {
        connection.set_last_accessed_time(get_monotonic_timestamp_ms());
    }
}

fn matches_endpoint<T: Connection>(
    connection: &T,
    local_address: Option<IpAddress>,
    process_id: Option<u64>,
    untracked_only: bool,
) -> bool {
    let address_matches = local_address
        .map(|address| connection.get_local_address() == address)
        .unwrap_or(true);
    let process_matches = process_id
        .map(|pid| connection.get_process_id() == 0 || connection.get_process_id() == pid)
        .unwrap_or(true);
    let lifecycle_matches = !untracked_only || !connection.has_native_lifecycle();

    !connection.has_ended() && address_matches && process_matches && lifecycle_matches
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
        Self(BTreeMap::new(), 1)
    }

    fn next_sequence(&mut self) -> u64 {
        loop {
            let sequence = self.1;
            self.1 = self.1.wrapping_add(1);
            if sequence != 0 {
                return sequence;
            }
        }
    }

    #[cfg(test)]
    fn add(&mut self, conn: T) {
        let key = conn.get_key().small();
        let sequence = self.next_sequence();
        let index = ConnectionIndex::from_connection(&conn, sequence);
        self.0.entry(key).or_default().insert(index, conn);
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
        let instance_id = conn.get_instance_id();
        let sequence = self.next_sequence();
        let connections = self.0.entry(key.small()).or_default();

        if let Some(existing_id) = connections
            .range(connection_range(&key))
            .map(|(_, connection)| connection)
            .find(|existing| existing.remote_equals(&key) && !existing.has_ended())
            .map(Connection::get_instance_id)
        {
            return Err((conn, existing_id));
        }

        let index = ConnectionIndex::from_connection(&conn, sequence);
        connections.insert(index, conn);
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
            for (_, conn) in connections.range_mut(connection_range(key)) {
                if conn.remote_equals(key) && !conn.has_ended() {
                    refresh_untracked_activity(conn);
                    return Some(conn);
                }
            }
        }

        None
    }

    /// Returns the live fallback instance for an exact tuple, if one exists.
    /// This does not refresh activity; a caller that successfully binds native
    /// lifecycle state performs the exact-instance update separately.
    pub fn untracked_instance_id(&self, key: &Key) -> Option<u64> {
        let connections = self.0.get(&key.small())?;
        connections
            .range(connection_range(key))
            .map(|(_, connection)| connection)
            .find(|conn| {
                conn.remote_equals(key) && !conn.has_ended() && !conn.has_native_lifecycle()
            })
            .map(Connection::get_instance_id)
    }

    /// Returns whether one exact connection-cache instance is still live.
    ///
    /// Unlike `read`, this check does not refresh activity and never falls back to
    /// redirected or ended state. It is used to validate endpoint-owned identity.
    pub fn has_live_instance(&self, key: &Key, instance_id: u64) -> bool {
        if instance_id == 0 {
            return false;
        }

        self.0.get(&key.small()).is_some_and(|connections| {
            connections
                .range(connection_range(key))
                .map(|(_, connection)| connection)
                .any(|conn| {
                    conn.remote_equals(key)
                        && conn.get_instance_id() == instance_id
                        && !conn.has_ended()
                })
        })
    }

    /// Returns whether one exact live instance matches either its original tuple or
    /// its current reverse-redirect tuple.
    ///
    /// Pending packet publication uses the packet's observed key. A response from a
    /// local redirect target no longer carries the original remote endpoint, but its
    /// instance ID still identifies exactly one cached generation. The instance
    /// check makes the otherwise ambiguous redirect scan safe for this operation.
    pub fn has_live_instance_matching(&self, key: &Key, instance_id: u64) -> bool {
        if self.has_live_instance(key, instance_id) {
            return true;
        }
        if instance_id == 0 || !is_redirect_port(key.remote_port) {
            return false;
        }

        self.0.get(&key.small()).is_some_and(|connections| {
            connections.values().any(|conn| {
                conn.redirect_equals(key)
                    && conn.get_instance_id() == instance_id
                    && !conn.has_ended()
            })
        })
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

        if let Some(connections) = self.0.get_mut(&key.small()) {
            let index = connections
                .range(connection_range(key))
                .find_map(|(index, conn)| {
                    (conn.remote_equals(key)
                        && conn.get_instance_id() == instance_id
                        && !conn.has_ended())
                    .then_some(*index)
                });
            if let Some(index) = index {
                let conn = connections.get_mut(&index)?;
                refresh_untracked_activity(conn);
                return Some(conn);
            }

            if is_redirect_port(key.remote_port) {
                if let Some(conn) = connections.values_mut().find(|conn| {
                    conn.redirect_equals(key)
                        && conn.get_instance_id() == instance_id
                        && !conn.has_ended()
                }) {
                    refresh_untracked_activity(conn);
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
            // Exact remote match first, over the indexed candidate range only.
            let (live_exact, ended_exact) = live_and_ended_match(
                connections
                    .range(connection_range(key))
                    .map(|(_, connection)| connection),
                |conn| conn.remote_equals(key),
            );

            if let Some(conn) = live_exact {
                refresh_untracked_activity(conn);
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
                live_and_ended_match(connections.values(), |conn| conn.redirect_equals(key))
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
                refresh_untracked_activity(conn);
                return read_connection(conn);
            }
        }

        None
    }

    /// Binds native endpoint/flow lifetime to one exact live fallback instance.
    pub fn mark_native_lifecycle_instance(&mut self, key: &Key, instance_id: u64) -> bool {
        if instance_id == 0 {
            return false;
        }

        if let Some(connections) = self.0.get_mut(&key.small()) {
            for (_, conn) in connections.range_mut(connection_range(key)) {
                if conn.remote_equals(key)
                    && conn.get_instance_id() == instance_id
                    && !conn.has_ended()
                {
                    conn.mark_native_lifecycle();
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
        if instance_id == 0 {
            return None;
        }

        if let Some(connections) = self.0.get_mut(&key.small()) {
            for (_, conn) in connections.range_mut(connection_range(&key)) {
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
        self.end_matching_on_endpoint(key, local_address, process_id, false)
    }

    /// Ends only fallback entries that lack native endpoint/flow identity.
    ///
    /// A closure carrying an unknown endpoint handle cannot safely end tracked
    /// generations by tuple, because that handle may belong to an older socket.
    /// Untracked entries have no stronger identity available, so the closure's
    /// local endpoint is their authoritative best-effort lifetime signal.
    pub fn end_untracked_on_endpoint(
        &mut self,
        key: (IpProtocol, u16),
        local_address: Option<IpAddress>,
        process_id: Option<u64>,
    ) -> Option<Vec<T>> {
        self.end_matching_on_endpoint(key, local_address, process_id, true)
    }

    fn end_matching_on_endpoint(
        &mut self,
        key: (IpProtocol, u16),
        local_address: Option<IpAddress>,
        process_id: Option<u64>,
        untracked_only: bool,
    ) -> Option<Vec<T>> {
        if let Some(connections) = self.0.get_mut(&key) {
            let count = connections
                .values()
                .filter(|connection| {
                    matches_endpoint(*connection, local_address, process_id, untracked_only)
                })
                .count();
            let mut vec = Vec::with_capacity(count);
            let timestamp = get_monotonic_timestamp_ms();
            for conn in connections.values_mut() {
                if matches_endpoint(conn, local_address, process_id, untracked_only) {
                    conn.end(timestamp);
                    vec.push(conn.clone());
                }
            }
            return Some(vec);
        }
        None
    }

    /// Ends outbound fallback entries not observed for one minute.
    ///
    /// Native endpoint and flow callbacks remain authoritative for tracked state.
    /// Inbound fallbacks are not idle-expired: after ALE authorizes their flow, a
    /// later packet might not revisit ALE and must continue to find cached policy.
    pub fn end_inactive_untracked_connections(&mut self) -> Vec<T> {
        let now = get_monotonic_timestamp_ms();
        let cutoff = now.saturating_sub(UNTRACKED_IDLE_TIMEOUT.as_millis() as u64);
        let count = self
            .0
            .values()
            .map(|connections| {
                connections
                    .values()
                    .filter(|connection| should_expire_untracked(*connection, cutoff))
                    .count()
            })
            .sum();
        let mut ended = Vec::with_capacity(count);

        for connections in self.0.values_mut() {
            for conn in connections.values_mut() {
                if should_expire_untracked(conn, cutoff) {
                    conn.end(now);
                    ended.push(conn.clone());
                }
            }
        }
        ended
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
            connections.retain(|_, connection| {
                !connection.has_ended() || connection.get_end_time() >= before_one_minute
            });
        }
        self.0.retain(|_, connections| !connections.is_empty());
    }

    /// Appends the IDs of every live UDP cache instance without refreshing activity.
    ///
    /// Periodic UDP lifecycle cleanup uses this snapshot after taking its endpoint
    /// and flow snapshots. A newly created association therefore cannot be mistaken
    /// for stale state, and inspecting an instance does not postpone its timeout.
    pub fn append_live_udp_instance_ids(&self, instance_ids: &mut Vec<u64>) {
        for connections in self.0.values() {
            for connection in connections.values() {
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

    pub fn get_untracked_count(&self) -> usize {
        self.0
            .values()
            .flat_map(|connections| connections.values())
            .filter(|connection| !connection.has_ended() && !connection.has_native_lifecycle())
            .count()
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

    fn untracked(key: &Key, process_id: u64) -> ConnectionV4 {
        ConnectionV4::from_untracked_key(key, process_id, Direction::Outbound).expect("IPv4 key")
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
    fn indexed_range_distinguishes_local_addresses() {
        let first = key([198, 51, 100, 10], 443);
        let mut second = first;
        second.local_address = IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 2));
        let mut map = ConnectionMap::new();
        map.add(live(&first, 10));
        map.add(live(&second, 20));

        assert_eq!(map.read(&first, read_process_id), Some(10));
        assert_eq!(map.read(&second, read_process_id), Some(20));
    }

    #[test]
    fn ended_fallback_preserves_insertion_order() {
        let tuple = key([198, 51, 100, 11], 443);
        let created_first = ended(&tuple, 10);
        let created_second = ended(&tuple, 20);
        let mut map = ConnectionMap::new();

        // Insert in reverse construction/instance-ID order. Selection must follow
        // the old vector's insertion-order rule rather than the instance value.
        map.add(created_second);
        map.add(created_first);
        assert_eq!(
            map.read_with_ended_fallback(&tuple, read_process_id),
            Some(20)
        );

        map.add(live(&tuple, 30));
        assert_eq!(
            map.read_with_ended_fallback(&tuple, read_process_id),
            Some(30)
        );
    }

    #[test]
    fn unordered_remote_insertions_remain_exactly_searchable() {
        const CONNECTIONS: u16 = 4_096;
        let mut map = ConnectionMap::new();

        for ordinal in 0..CONNECTIONS {
            let remote_port = 10_000 + ((u32::from(ordinal) * 4_051) % 4_096) as u16;
            let tuple = key([203, 0, 113, 1], remote_port);
            map.add(live(&tuple, u64::from(remote_port)));
        }

        assert_eq!(map.get_count(), usize::from(CONNECTIONS));
        for remote_port in 10_000..10_000 + CONNECTIONS {
            let tuple = key([203, 0, 113, 1], remote_port);
            assert_eq!(
                map.read(&tuple, read_process_id),
                Some(u64::from(remote_port))
            );
        }
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
    fn inactive_untracked_udp_ends_without_expiring_tracked_peer() {
        let fallback_tuple = key([203, 0, 113, 2], 443);
        let tracked_tuple = key([203, 0, 113, 3], 443);
        let mut map = ConnectionMap::new();
        map.add(untracked(&fallback_tuple, 0));
        map.add(live(&tracked_tuple, 20));

        let ended = map.end_inactive_untracked_connections();

        assert_eq!(ended.len(), 1);
        assert!(ended[0].has_ended());
        assert!(ended[0].get_key() == fallback_tuple);
        assert_eq!(map.read(&fallback_tuple, read_process_id), None);
        assert_eq!(map.read(&tracked_tuple, read_process_id), Some(20));
    }

    #[test]
    fn packet_lookup_refreshes_outbound_untracked_activity() {
        let tuple = key([203, 0, 113, 7], 443);
        let mut map = ConnectionMap::new();
        map.add(untracked(&tuple, 10));

        assert_eq!(map.read(&tuple, read_process_id), Some(10));
        assert!(map.end_inactive_untracked_connections().is_empty());
        assert_eq!(map.get_count(), 1);
    }

    #[test]
    fn inactive_untracked_inbound_waits_for_socket_closure() {
        let tuple = key([203, 0, 113, 4], 443);
        let connection =
            ConnectionV4::from_untracked_key(&tuple, 20, Direction::Inbound).expect("IPv4 key");
        let mut map = ConnectionMap::new();
        map.add(connection);

        assert!(map.end_inactive_untracked_connections().is_empty());
        assert_eq!(map.read(&tuple, read_process_id), Some(20));
    }

    #[test]
    fn endpoint_closure_ends_only_untracked_fallbacks() {
        let fallback_tuple = key([203, 0, 113, 2], 443);
        let tracked_tuple = key([203, 0, 113, 3], 443);
        let mut map = ConnectionMap::new();
        map.add(untracked(&fallback_tuple, 0));
        map.add(live(&tracked_tuple, 20));

        let ended = map
            .end_untracked_on_endpoint(
                (IpProtocol::Udp, fallback_tuple.local_port),
                Some(fallback_tuple.local_address),
                Some(20),
            )
            .expect("local endpoint bucket");

        assert_eq!(ended.len(), 1);
        assert!(ended[0].get_key() == fallback_tuple);
        assert_eq!(map.read(&fallback_tuple, read_process_id), None);
        assert_eq!(map.read(&tracked_tuple, read_process_id), Some(20));
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
    fn cleanup_reclaims_ended_entries_while_bucket_remains() {
        let live_tuple = key([203, 0, 113, 255], 443);
        let mut map = ConnectionMap::new();
        for last_octet in 1..=64 {
            map.add(ended(&key([203, 0, 113, last_octet], 443), 10));
        }
        map.add(live(&live_tuple, 20));
        let bucket_key = live_tuple.small();
        assert_eq!(map.0.get(&bucket_key).expect("connection bucket").len(), 65);

        map.clean_ended_connections();

        let connections = map.0.get(&bucket_key).expect("live connection bucket");
        assert_eq!(connections.len(), 1);
        assert_eq!(map.read(&live_tuple, read_process_id), Some(20));
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
    fn exact_live_fallback_can_acquire_native_lifecycle() {
        let tuple = key([198, 51, 100, 3], 443);
        let conn = untracked(&tuple, 10);
        let instance_id = conn.get_instance_id();
        let mut map = ConnectionMap::new();
        map.add(conn);

        assert!(map.mark_native_lifecycle_instance(&tuple, instance_id));
        assert!(map.end_inactive_untracked_connections().is_empty());
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
    fn stale_instance_cannot_promote_reused_tuple() {
        let tuple = key([198, 51, 100, 2], 443);
        let old = untracked(&tuple, 10);
        let old_instance_id = old.get_instance_id();
        let mut map = ConnectionMap::new();
        map.add(old);
        map.clear();
        map.add(untracked(&tuple, 20));

        assert!(!map.mark_native_lifecycle_instance(&tuple, old_instance_id));
        assert_eq!(map.end_inactive_untracked_connections().len(), 1);
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
