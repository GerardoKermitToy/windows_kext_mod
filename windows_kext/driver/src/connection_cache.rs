use crate::{
    connection::{Connection, ConnectionV4, ConnectionV6, RedirectInfo, Verdict},
    connection_map::{ConnectionMap, Key},
};
use alloc::vec::Vec;

use smoltcp::wire::{IpAddress, IpProtocol};
use wdk::rw_spin_lock::RwSpinLock;

pub struct ConnectionCache {
    connections_v4: ConnectionMap<ConnectionV4>,
    connections_v6: ConnectionMap<ConnectionV6>,
    lock_v4: RwSpinLock,
    lock_v6: RwSpinLock,
}

impl ConnectionCache {
    pub fn new() -> Self {
        Self {
            connections_v4: ConnectionMap::new(),
            connections_v6: ConnectionMap::new(),
            lock_v4: RwSpinLock::default(),
            lock_v6: RwSpinLock::default(),
        }
    }

    pub fn add_connection_v4(&mut self, connection: ConnectionV4) {
        let _guard = self.lock_v4.write_lock();
        self.connections_v4.add(connection);
    }

    pub fn add_connection_v6(&mut self, connection: ConnectionV6) {
        let _guard = self.lock_v6.write_lock();
        self.connections_v6.add(connection);
    }

    /// Updates the owning process of a connection when the incoming PID is usable.
    ///
    /// Returns true if the entry was updated.
    ///
    /// PID 0 is ignored. PID 4 may replace an unknown PID (0), but must not
    /// replace a concrete application PID. Any other PID takes precedence and
    /// replaces the currently stored value, including 0 or 4.
    ///
    /// Flow-established attribution uses this when an inbound packet-layer fallback
    /// starts with PID 0 because no socket is associated at that layer, or when ALE
    /// later supplies a concrete application PID that takes precedence over earlier
    /// attribution. Without the PID-0 repair, every later packet repeats the endpoint
    /// lookup - roughly 200 times for a single loopback connection in the capture
    /// that motivated it.
    pub fn update_process_id(&mut self, key: &Key, process_id: u64) -> bool {
        // PID 0 carries no attribution and must never replace a stored value.
        if process_id == 0 {
            return false;
        }

        if key.is_ipv6() {
            let _guard = self.lock_v6.write_lock();
            if let Some(conn) = self.connections_v6.get_mut(key) {
                // PID 4 may fill an unknown entry, while every other PID may
                // replace the current value. A PID 4 must not replace a
                // concrete application PID.
                if conn.process_id == 0 || process_id != 4 {
                    conn.process_id = process_id;
                    return true;
                }
            }
        } else {
            let _guard = self.lock_v4.write_lock();
            if let Some(conn) = self.connections_v4.get_mut(key) {
                if conn.process_id == 0 || process_id != 4 {
                    conn.process_id = process_id;
                    return true;
                }
            }
        }
        false
    }

    /// Returns the instance ID of the current live entry.
    pub fn get_connection_instance_id(&self, key: &Key) -> Option<u64> {
        if key.is_ipv6() {
            self.read_connection_v6(key, |conn| Some(conn.get_instance_id()))
        } else {
            self.read_connection_v4(key, |conn| Some(conn.get_instance_id()))
        }
    }

    /// Marks one specific live entry as covered by a native WFP lifetime callback.
    pub fn mark_lifecycle_tracked(&mut self, key: &Key, instance_id: u64) -> bool {
        if key.is_ipv6() {
            let _guard = self.lock_v6.write_lock();
            if let Some(conn) = self.connections_v6.get_mut(key) {
                if conn.get_instance_id() == instance_id {
                    conn.mark_lifecycle_tracked();
                    return true;
                }
            }
        } else {
            let _guard = self.lock_v4.write_lock();
            if let Some(conn) = self.connections_v4.get_mut(key) {
                if conn.get_instance_id() == instance_id {
                    conn.mark_lifecycle_tracked();
                    return true;
                }
            }
        }
        false
    }

    pub fn update_connection(&mut self, key: Key, verdict: Verdict) -> Option<RedirectInfo> {
        if key.is_ipv6() {
            let _guard = self.lock_v6.write_lock();
            if let Some(conn) = self.connections_v6.get_mut(&key) {
                conn.verdict = verdict;
                return conn.redirect_info();
            }
        } else {
            let _guard = self.lock_v4.write_lock();
            if let Some(conn) = self.connections_v4.get_mut(&key) {
                conn.verdict = verdict;
                return conn.redirect_info();
            }
        }
        None
    }

    /// Reads a live IPv4 connection. Ended entries are not current connection
    /// state and are ignored by ALE and update paths.
    pub fn read_connection_v4<T>(
        &self,
        key: &Key,
        process_connection: fn(&ConnectionV4) -> Option<T>,
    ) -> Option<T> {
        let _guard = self.lock_v4.read_lock();
        self.connections_v4.read(key, process_connection)
    }

    /// Reads a live IPv6 connection. Ended entries are not current connection
    /// state and are ignored by ALE and update paths.
    pub fn read_connection_v6<T>(
        &self,
        key: &Key,
        process_connection: fn(&ConnectionV6) -> Option<T>,
    ) -> Option<T> {
        let _guard = self.lock_v6.read_lock();
        self.connections_v6.read(key, process_connection)
    }

    /// Reads current IPv4 state, falling back to an ended entry only for a late
    /// packet that has no live connection match.
    pub fn read_connection_v4_with_ended_fallback<T>(
        &self,
        key: &Key,
        process_connection: fn(&ConnectionV4) -> Option<T>,
    ) -> Option<T> {
        let _guard = self.lock_v4.read_lock();
        self.connections_v4
            .read_with_ended_fallback(key, process_connection)
    }

    /// Reads current IPv6 state, falling back to an ended entry only for a late
    /// packet that has no live connection match.
    pub fn read_connection_v6_with_ended_fallback<T>(
        &self,
        key: &Key,
        process_connection: fn(&ConnectionV6) -> Option<T>,
    ) -> Option<T> {
        let _guard = self.lock_v6.read_lock();
        self.connections_v6
            .read_with_ended_fallback(key, process_connection)
    }

    pub fn end_connection_instance_v4(
        &mut self,
        key: Key,
        instance_id: u64,
    ) -> Option<ConnectionV4> {
        let _guard = self.lock_v4.write_lock();
        self.connections_v4.end_instance(key, instance_id)
    }

    pub fn end_connection_instance_v6(
        &mut self,
        key: Key,
        instance_id: u64,
    ) -> Option<ConnectionV6> {
        let _guard = self.lock_v6.write_lock();
        self.connections_v6.end_instance(key, instance_id)
    }

    pub fn end_connection_v4(&mut self, key: Key) -> Option<ConnectionV4> {
        let _guard = self.lock_v4.write_lock();
        self.connections_v4.end(key)
    }

    pub fn end_connection_v6(&mut self, key: Key) -> Option<ConnectionV6> {
        let _guard = self.lock_v6.write_lock();
        self.connections_v6.end(key)
    }

    pub fn end_all_on_endpoint_v4(
        &mut self,
        key: (IpProtocol, u16),
        local_address: Option<IpAddress>,
        process_id: Option<u64>,
    ) -> Option<Vec<ConnectionV4>> {
        let _guard = self.lock_v4.write_lock();
        self.connections_v4
            .end_all_on_endpoint(key, local_address, process_id)
    }

    pub fn end_all_on_endpoint_v6(
        &mut self,
        key: (IpProtocol, u16),
        local_address: Option<IpAddress>,
        process_id: Option<u64>,
    ) -> Option<Vec<ConnectionV6>> {
        let _guard = self.lock_v6.write_lock();
        self.connections_v6
            .end_all_on_endpoint(key, local_address, process_id)
    }

    /// Cleans retained history and returns untracked UDP entries expired by the
    /// fallback watchdog. The caller must publish END for each returned entry.
    pub fn clean_ended_connections(&mut self) -> (Vec<ConnectionV4>, Vec<ConnectionV6>) {
        let inactive_v4 = {
            let _guard = self.lock_v4.write_lock();
            self.connections_v4.clean_ended_connections()
        };
        let inactive_v6 = {
            let _guard = self.lock_v6.write_lock();
            self.connections_v6.clean_ended_connections()
        };
        (inactive_v4, inactive_v6)
    }

    pub fn clear(&mut self) {
        {
            let _guard = self.lock_v4.write_lock();
            self.connections_v4.clear();
        }
        {
            let _guard = self.lock_v6.write_lock();
            self.connections_v6.clear();
        }
    }

    #[allow(dead_code)]
    pub fn get_entries_count(&self) -> usize {
        let mut size = 0;
        {
            let _guard = self.lock_v4.read_lock();
            size += self.connections_v4.get_count();
        }

        {
            let _guard = self.lock_v6.read_lock();
            size += self.connections_v6.get_count();
        }

        return size;
    }
}
