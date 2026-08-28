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

struct EndpointPeer {
    key: Key,
    instance_id: Option<u64>,
}

struct EndpointEntry {
    peers: Vec<EndpointPeer>,
}

pub struct ClosedUdpPeer {
    pub key: Key,
    pub instance_id: Option<u64>,
}

pub struct ClosedUdpEndpoint {
    pub peers: Vec<ClosedUdpPeer>,
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
            if entry.peers.iter().any(|peer| peer.key == key) {
                return;
            }
            entry.peers.push(EndpointPeer {
                key,
                instance_id: None,
            });
            return;
        }

        self.endpoints.insert(
            endpoint_handle,
            EndpointEntry {
                peers: alloc::vec![EndpointPeer {
                    key,
                    instance_id: None,
                }],
            },
        );
    }

    /// Associates one concrete cache instance with its endpoint.
    ///
    /// An earlier authorization/datagram observation may have inserted an unbound
    /// key. Bind that observation in place; a later flow with the same tuple gets a
    /// separate peer so delayed closure cannot target its replacement.
    pub fn associate_instance(&mut self, endpoint_handle: u64, key: Key, instance_id: u64) {
        if endpoint_handle == 0 || instance_id == 0 {
            return;
        }

        let _guard = self.lock.write_lock();
        self.closed_endpoints.remove(&endpoint_handle);

        if let Some(entry) = self.endpoints.get_mut(&endpoint_handle) {
            if entry
                .peers
                .iter()
                .any(|peer| peer.key == key && peer.instance_id == Some(instance_id))
            {
                return;
            }
            if let Some(peer) = entry
                .peers
                .iter_mut()
                .find(|peer| peer.key == key && peer.instance_id.is_none())
            {
                peer.instance_id = Some(instance_id);
                return;
            }
            entry.peers.push(EndpointPeer {
                key,
                instance_id: Some(instance_id),
            });
            return;
        }

        self.endpoints.insert(
            endpoint_handle,
            EndpointEntry {
                peers: alloc::vec![EndpointPeer {
                    key,
                    instance_id: Some(instance_id),
                }],
            },
        );
    }

    /// Removes a peer whose WFP ALE flow has ended.
    ///
    /// The endpoint entry itself is retained even when it becomes empty. A later
    /// socket-closure indication must still be recognized as tracked so it does not
    /// fall back to sweeping a local port that may already have been reused.
    pub fn dissociate(&mut self, endpoint_handle: u64, key: Key, instance_id: u64) -> bool {
        if endpoint_handle == 0 || instance_id == 0 {
            return false;
        }

        let _guard = self.lock.write_lock();
        let Some(entry) = self.endpoints.get_mut(&endpoint_handle) else {
            return false;
        };
        let previous_len = entry.peers.len();
        entry
            .peers
            .retain(|peer| peer.key != key || peer.instance_id != Some(instance_id));
        entry.peers.len() != previous_len
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
            return UdpEndpointTake::Tracked(ClosedUdpEndpoint {
                peers: entry
                    .peers
                    .into_iter()
                    .map(|peer| ClosedUdpPeer {
                        key: peer.key,
                        instance_id: peer.instance_id,
                    })
                    .collect(),
            });
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
        assert_eq!(closed.peers.len(), 2);
        assert!(matches!(cache.take(10), UdpEndpointTake::AlreadyTaken));
    }

    #[test]
    fn flow_delete_dissociates_only_its_cache_instance() {
        let mut cache = UdpEndpointCache::new();
        let peer = key(1000);
        cache.associate(10, peer);
        cache.associate_instance(10, peer, 100);
        cache.associate_instance(10, peer, 200);

        assert!(cache.dissociate(10, peer, 100));
        assert!(!cache.dissociate(10, peer, 100));

        let UdpEndpointTake::Tracked(closed) = cache.take(10) else {
            panic!("endpoint was no longer tracked");
        };
        assert_eq!(closed.peers.len(), 1);
        assert_eq!(closed.peers[0].instance_id, Some(200));
    }

    #[test]
    fn flow_delete_keeps_empty_endpoint_tracked() {
        let mut cache = UdpEndpointCache::new();
        let peer = key(1000);
        cache.associate_instance(10, peer, 100);

        assert!(cache.dissociate(10, peer, 100));

        let UdpEndpointTake::Tracked(closed) = cache.take(10) else {
            panic!("empty endpoint was no longer tracked");
        };
        assert!(closed.peers.is_empty());
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
