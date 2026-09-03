//! Associates one cached TCP connection generation with its WFP endpoint.
//!
//! For an accepted inbound connection, WFP can report a provisional transport
//! endpoint handle at `ALE_AUTH_RECV_ACCEPT` and a different child endpoint handle
//! at `ALE_FLOW_ESTABLISHED`. The parent endpoint and tuple correlate those stages;
//! endpoint closure then consumes the established handle and exact instance ID.

use alloc::collections::BTreeMap;

use crate::connection_map::Key;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TcpEndpointConnection {
    pub key: Key,
    pub parent_endpoint_handle: Option<u64>,
    pub instance_id: u64,
}

pub struct TcpEndpointCache {
    endpoints: BTreeMap<u64, TcpEndpointConnection>,
}

impl TcpEndpointCache {
    pub fn new() -> Self {
        Self {
            endpoints: BTreeMap::new(),
        }
    }

    /// Associates one exact live connection-cache instance with its WFP endpoint.
    ///
    /// Reauthorization can repeat the same association while omitting optional
    /// parent-endpoint metadata. Returns `true` when the mapping was inserted or
    /// still identifies the same connection instance. A newly supplied parent is
    /// retained, but two different concrete parents remain a conflict.
    ///
    /// A different connection for an already tracked handle is rejected: WFP
    /// defines the handle as unique for the endpoint lifetime, so replacing it
    /// could let an old closure consume a newer connection generation.
    pub fn associate_instance(
        &mut self,
        endpoint_handle: u64,
        key: Key,
        parent_endpoint_handle: Option<u64>,
        instance_id: u64,
    ) -> bool {
        if endpoint_handle == 0 || instance_id == 0 {
            return false;
        }

        if let Some(existing) = self.endpoints.get_mut(&endpoint_handle) {
            if existing.key != key || existing.instance_id != instance_id {
                return false;
            }

            match (existing.parent_endpoint_handle, parent_endpoint_handle) {
                (Some(existing_parent), Some(parent)) => return existing_parent == parent,
                (None, Some(parent)) => existing.parent_endpoint_handle = Some(parent),
                _ => {}
            }
            return true;
        }

        self.endpoints.insert(
            endpoint_handle,
            TcpEndpointConnection {
                key,
                parent_endpoint_handle,
                instance_id,
            },
        );
        true
    }

    /// Resolves the live authorization generation corresponding to an established
    /// flow. Matching the parent endpoint as well as the tuple prevents connections
    /// accepted by different listeners from sharing the transition.
    pub fn resolve_live_instance(
        &self,
        key: &Key,
        parent_endpoint_handle: Option<u64>,
        mut is_live: impl FnMut(u64) -> bool,
    ) -> Option<TcpEndpointConnection> {
        self.endpoints.values().copied().find(|endpoint| {
            endpoint.key == *key
                && endpoint.parent_endpoint_handle == parent_endpoint_handle
                && is_live(endpoint.instance_id)
        })
    }

    /// Replaces every provisional/alias handle for a connection generation with
    /// the endpoint handle reported for its established flow.
    pub fn rebind_established(
        &mut self,
        endpoint_handle: u64,
        endpoint: TcpEndpointConnection,
    ) -> bool {
        if endpoint_handle == 0 || endpoint.instance_id == 0 {
            return false;
        }
        if self
            .endpoints
            .get(&endpoint_handle)
            .is_some_and(|existing| *existing != endpoint)
        {
            return false;
        }

        self.endpoints.retain(|_, candidate| *candidate != endpoint);
        self.endpoints.insert(endpoint_handle, endpoint);
        true
    }

    /// Consumes the exact connection identity assigned to the closing endpoint.
    /// Every alias of the same generation is removed defensively as well.
    pub fn take(&mut self, endpoint_handle: u64) -> Option<TcpEndpointConnection> {
        if endpoint_handle == 0 {
            return None;
        }

        let endpoint = self.endpoints.remove(&endpoint_handle)?;
        self.endpoints.retain(|_, candidate| *candidate != endpoint);
        Some(endpoint)
    }

    #[allow(dead_code)]
    pub fn get_entries_count(&self) -> usize {
        self.endpoints.len()
    }

    pub fn clear(&mut self) {
        self.endpoints.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::TcpEndpointCache;
    use crate::{
        connection::{Connection, ConnectionV4, Direction},
        connection_map::{ConnectionMap, Key},
    };
    use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address};

    fn key() -> Key {
        Key {
            protocol: IpProtocol::Tcp,
            local_address: IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)),
            local_port: 40_000,
            remote_address: IpAddress::Ipv4(Ipv4Address::new(192, 0, 2, 1)),
            remote_port: 443,
        }
    }

    fn connection(key: &Key, process_id: u64) -> ConnectionV4 {
        ConnectionV4::from_key(key, process_id, Direction::Outbound).expect("IPv4 key")
    }

    #[test]
    fn established_flow_rebinds_the_authorization_handle() {
        let mut cache = TcpEndpointCache::new();
        let tuple = key();
        let parent = Some(20);

        assert!(cache.associate_instance(10, tuple, parent, 100));
        let endpoint = cache
            .resolve_live_instance(&tuple, parent, |instance_id| instance_id == 100)
            .expect("authorization generation");
        assert!(cache.rebind_established(30, endpoint));

        assert!(cache.take(10).is_none());
        assert_eq!(cache.take(30).expect("established endpoint").instance_id, 100);
    }

    #[test]
    fn reauthorization_may_omit_parent_endpoint() {
        let mut cache = TcpEndpointCache::new();
        let tuple = key();

        assert!(cache.associate_instance(10, tuple, Some(20), 100));
        assert!(cache.associate_instance(10, tuple, None, 100));
        assert_eq!(
            cache
                .resolve_live_instance(&tuple, Some(20), |_| true)
                .expect("preserved parent endpoint")
                .instance_id,
            100
        );
    }

    #[test]
    fn repeated_association_fills_but_does_not_replace_parent() {
        let mut cache = TcpEndpointCache::new();
        let tuple = key();

        assert!(cache.associate_instance(10, tuple, None, 100));
        assert!(cache.associate_instance(10, tuple, Some(20), 100));
        assert!(!cache.associate_instance(10, tuple, Some(21), 100));
        assert!(!cache.associate_instance(10, tuple, None, 101));
        let mut other_tuple = tuple;
        other_tuple.remote_port = 8443;
        assert!(!cache.associate_instance(10, other_tuple, None, 100));
        assert_eq!(
            cache
                .resolve_live_instance(&tuple, Some(20), |_| true)
                .expect("filled parent endpoint")
                .instance_id,
            100
        );
    }

    #[test]
    fn flow_rebind_requires_matching_parent_and_live_instance() {
        let mut cache = TcpEndpointCache::new();
        let tuple = key();
        assert!(cache.associate_instance(10, tuple, Some(20), 100));

        assert!(cache
            .resolve_live_instance(&tuple, Some(21), |_| true)
            .is_none());
        assert!(cache
            .resolve_live_instance(&tuple, Some(20), |_| false)
            .is_none());
        assert_eq!(
            cache
                .resolve_live_instance(&tuple, Some(20), |_| true)
                .expect("matching generation")
                .instance_id,
            100
        );
    }

    #[test]
    fn delayed_closure_cannot_end_reused_tuple() {
        let tuple = key();
        let mut connections = ConnectionMap::new();
        let old = connection(&tuple, 100);
        let old_instance_id = old.get_instance_id();
        assert!(matches!(
            connections.insert_if_absent(old),
            Ok(instance_id) if instance_id == old_instance_id
        ));

        let mut endpoints = TcpEndpointCache::new();
        assert!(endpoints.associate_instance(10, tuple, Some(1), old_instance_id));
        assert!(connections.end_instance(tuple, old_instance_id).is_some());

        let replacement = connection(&tuple, 200);
        let replacement_instance_id = replacement.get_instance_id();
        assert!(matches!(
            connections.insert_if_absent(replacement),
            Ok(instance_id) if instance_id == replacement_instance_id
        ));
        assert!(endpoints.associate_instance(20, tuple, Some(1), replacement_instance_id));

        let delayed = endpoints.take(10).expect("old endpoint identity");
        assert_eq!(delayed.instance_id, old_instance_id);
        assert!(connections
            .end_instance(delayed.key, delayed.instance_id)
            .is_none());
        assert!(connections.has_live_instance(&tuple, replacement_instance_id));

        let current = endpoints.take(20).expect("replacement endpoint identity");
        assert_eq!(current.instance_id, replacement_instance_id);
        assert!(connections
            .end_instance(current.key, current.instance_id)
            .is_some());
    }
}
