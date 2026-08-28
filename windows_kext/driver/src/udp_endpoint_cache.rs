//! Associates cached UDP remote tuples with their socket endpoint.
//!
//! WFP creates one UDP ALE flow per remote peer, but reports endpoint closure only
//! once for the socket. The closure indication therefore cannot identify every
//! remote tuple by its fixed fields. The transport endpoint handle is the stable
//! correlation key shared by authorization and endpoint-closure indications.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

#[cfg(not(test))]
use wdk::rw_spin_lock::RwSpinLock;

#[cfg(test)]
struct RwSpinLock;

#[cfg(test)]
impl RwSpinLock {
    const fn default() -> Self {
        Self
    }

    fn write_lock(&self) {}
}

use crate::connection_map::Key;

struct EndpointEntry {
    keys: Vec<Key>,
}

pub struct ClosedUdpEndpoint {
    pub keys: Vec<Key>,
}

/// Result of consuming an endpoint lifetime indication.
///
/// `Unknown` means this handle was never tracked, so the caller may use a coarse
/// local-endpoint fallback. `AlreadyTaken` means an earlier closure or resource
/// release already consumed the handle; falling back again could end a replacement
/// socket that reused the same local port.
pub enum UdpEndpointTake {
    Tracked(ClosedUdpEndpoint),
    AlreadyTaken,
    Unknown,
}

pub struct UdpEndpointCache {
    endpoints: BTreeMap<u64, EndpointEntry>,
    /// Tombstones suppress duplicate closure/resource-release sweeps. Handles are
    /// removed from this map when a later association reuses them.
    closed_endpoints: BTreeMap<u64, ()>,
    lock: RwSpinLock,
}

impl UdpEndpointCache {
    pub fn new() -> Self {
        Self {
            endpoints: BTreeMap::new(),
            closed_endpoints: BTreeMap::new(),
            lock: RwSpinLock::default(),
        }
    }

    /// Associates one UDP remote tuple with its socket endpoint.
    ///
    /// Reauthorizations and repeated indications are idempotent.
    pub fn associate(&mut self, endpoint_handle: u64, key: Key) {
        if endpoint_handle == 0 {
            return;
        }

        let _guard = self.lock.write_lock();
        // A handle can be reused after its previous socket has closed.
        self.closed_endpoints.remove(&endpoint_handle);

        if let Some(entry) = self.endpoints.get_mut(&endpoint_handle) {
            if entry.keys.contains(&key) {
                return;
            }
            entry.keys.push(key);
            return;
        }

        self.endpoints.insert(
            endpoint_handle,
            EndpointEntry {
                keys: alloc::vec![key],
            },
        );
    }

    /// Consumes one endpoint lifetime indication and returns every UDP tuple
    /// observed on its socket.
    pub fn take(&mut self, endpoint_handle: u64) -> UdpEndpointTake {
        if endpoint_handle == 0 {
            return UdpEndpointTake::Unknown;
        }

        let _guard = self.lock.write_lock();
        if let Some(entry) = self.endpoints.remove(&endpoint_handle) {
            remember_closed(&mut self.closed_endpoints, endpoint_handle);
            return UdpEndpointTake::Tracked(ClosedUdpEndpoint { keys: entry.keys });
        }

        if self.closed_endpoints.contains_key(&endpoint_handle) {
            UdpEndpointTake::AlreadyTaken
        } else {
            // Remember an untracked handle too: a later resource-release
            // indication for the same endpoint must not sweep a reused port twice.
            remember_closed(&mut self.closed_endpoints, endpoint_handle);
            UdpEndpointTake::Unknown
        }
    }

    pub fn clear(&mut self) {
        let _guard = self.lock.write_lock();
        self.endpoints.clear();
        self.closed_endpoints.clear();
    }
}

fn remember_closed(closed_endpoints: &mut BTreeMap<u64, ()>, endpoint_handle: u64) {
    closed_endpoints.insert(endpoint_handle, ());
}

#[cfg(test)]
mod tests {
    use super::{UdpEndpointCache, UdpEndpointTake};
    use crate::connection_map::Key;
    use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address};

    fn key(remote_port: u16) -> Key {
        Key {
            protocol: IpProtocol::Udp,
            local_address: IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)),
            local_port: 40_000,
            remote_address: IpAddress::Ipv4(Ipv4Address::new(192, 0, 2, 1)),
            remote_port,
        }
    }

    #[test]
    fn groups_remote_tuples_under_one_endpoint_and_takes_once() {
        let mut cache = UdpEndpointCache::new();
        cache.associate(10, key(1000));
        cache.associate(10, key(1001));
        cache.associate(10, key(1001));

        let UdpEndpointTake::Tracked(closed) = cache.take(10) else {
            panic!("endpoint was not tracked");
        };
        assert_eq!(closed.keys.len(), 2);
        assert!(matches!(cache.take(10), UdpEndpointTake::AlreadyTaken));
    }

    #[test]
    fn unknown_handles_are_tombstoned_after_first_take() {
        let mut cache = UdpEndpointCache::new();
        assert!(matches!(cache.take(10), UdpEndpointTake::Unknown));
        assert!(matches!(cache.take(10), UdpEndpointTake::AlreadyTaken));

        cache.associate(10, key(1000));
        assert!(matches!(cache.take(10), UdpEndpointTake::Tracked(_)));
    }
}
