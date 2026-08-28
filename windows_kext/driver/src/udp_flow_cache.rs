//! Tracks driver-owned contexts associated with UDP ALE flows.
//!
//! WFP owns each context after `FwpsFlowAssociateContext0` succeeds and returns it
//! through flowDeleteFn when the flow expires. The registration tuple is retained
//! separately so driver unload can explicitly remove every outstanding context
//! before unregistering the callout.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::UnsafeCell;

#[cfg(not(test))]
use wdk::rw_spin_lock::RwSpinLock;

#[cfg(test)]
struct RwSpinLock;

#[cfg(test)]
impl RwSpinLock {
    const fn default() -> Self {
        Self
    }

    fn read_lock(&self) {}
    fn write_lock(&self) {}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpFlowRegistration {
    pub flow_context: u64,
    pub flow_id: u64,
    pub layer_id: u16,
    pub callout_id: u32,
    associated: bool,
    removal_requested: bool,
}

impl UdpFlowRegistration {
    pub fn new(flow_id: u64, layer_id: u16, callout_id: u32) -> Self {
        Self {
            flow_context: 0,
            flow_id,
            layer_id,
            callout_id,
            associated: false,
            removal_requested: false,
        }
    }
}

struct UdpFlowState {
    registrations: BTreeMap<u64, UdpFlowRegistration>,
    callbacks_in_progress: usize,
    shutting_down: bool,
}

pub struct UdpFlowCache {
    state: UnsafeCell<UdpFlowState>,
    lock: RwSpinLock,
}

// Every access to `state` is serialized by `lock`. This cache is called from
// classifyFn, flowDeleteFn and driver unload, potentially on different CPUs.
unsafe impl Sync for UdpFlowCache {}

impl UdpFlowCache {
    pub fn new() -> Self {
        Self {
            state: UnsafeCell::new(UdpFlowState {
                registrations: BTreeMap::new(),
                callbacks_in_progress: 0,
                shutting_down: false,
            }),
            lock: RwSpinLock::default(),
        }
    }

    /// Records a context before it is exposed to WFP.
    ///
    /// Returns false once unload has started or if the pointer is invalid/already
    /// registered. A false result leaves ownership with the caller.
    pub fn register(&self, flow_context: u64, mut registration: UdpFlowRegistration) -> bool {
        if flow_context == 0 {
            return false;
        }

        let _guard = self.lock.write_lock();
        let state = unsafe { &mut *self.state.get() };
        if state.shutting_down || state.registrations.contains_key(&flow_context) {
            return false;
        }
        registration.flow_context = flow_context;
        registration.associated = false;
        registration.removal_requested = false;
        state.registrations.insert(flow_context, registration);
        true
    }

    /// Marks a registration after WFP accepted ownership of its context. False
    /// means flowDeleteFn already claimed it while `FwpsFlowAssociateContext0` was
    /// returning.
    pub fn mark_associated(&self, flow_context: u64) -> bool {
        let _guard = self.lock.write_lock();
        let state = unsafe { &mut *self.state.get() };
        let Some(registration) = state.registrations.get_mut(&flow_context) else {
            return false;
        };
        registration.associated = true;
        true
    }

    /// Cancels a registration after `FwpsFlowAssociateContext0` failed. WFP never
    /// owned the context in this case, so flowDeleteFn cannot race this removal.
    pub fn cancel_registration(&self, flow_context: u64) -> bool {
        let _guard = self.lock.write_lock();
        let state = unsafe { &mut *self.state.get() };
        state.registrations.remove(&flow_context).is_some()
    }

    /// Claims a callback and returns whether unload is in progress.
    ///
    /// Removing the record before doing callback work makes the record an explicit
    /// in-flight count: unload cannot drop `Device` until `finish_callback` runs.
    /// `None` means a duplicate/unknown callback, whose opaque pointer must not be
    /// dereferenced because its owner has already reclaimed it.
    pub fn begin_callback(&self, flow_context: u64) -> Option<bool> {
        let _guard = self.lock.write_lock();
        let state = unsafe { &mut *self.state.get() };
        state.registrations.remove(&flow_context)?;
        state.callbacks_in_progress = state.callbacks_in_progress.saturating_add(1);
        Some(state.shutting_down)
    }

    pub fn finish_callback(&self) {
        let _guard = self.lock.write_lock();
        let state = unsafe { &mut *self.state.get() };
        state.callbacks_in_progress = state.callbacks_in_progress.saturating_sub(1);
    }

    /// Prevents new associations before driver unload removes the outstanding ones.
    pub fn start_shutdown(&self) {
        let _guard = self.lock.write_lock();
        let state = unsafe { &mut *self.state.get() };
        state.shutting_down = true;
    }

    /// Returns the registrations still owned by WFP and marks each as requested.
    /// A record is yielded once; it remains in the map until flowDeleteFn claims it.
    pub fn pending_removals(&self) -> Vec<UdpFlowRegistration> {
        let _guard = self.lock.write_lock();
        let state = unsafe { &mut *self.state.get() };
        let mut pending = Vec::new();
        for registration in state.registrations.values_mut() {
            if registration.associated && !registration.removal_requested {
                registration.removal_requested = true;
                pending.push(*registration);
            }
        }
        pending
    }

    pub fn retry_removal(&self, flow_context: u64) {
        let _guard = self.lock.write_lock();
        let state = unsafe { &mut *self.state.get() };
        if let Some(registration) = state.registrations.get_mut(&flow_context) {
            registration.removal_requested = false;
        }
    }

    pub fn is_drained(&self) -> bool {
        let _guard = self.lock.read_lock();
        let state = unsafe { &*self.state.get() };
        state.registrations.is_empty() && state.callbacks_in_progress == 0
    }

    #[cfg(test)]
    pub fn snapshot(&self) -> Vec<UdpFlowRegistration> {
        let _guard = self.lock.read_lock();
        let state = unsafe { &*self.state.get() };
        state.registrations.values().copied().collect()
    }

    #[cfg(test)]
    pub fn callbacks_in_progress(&self) -> usize {
        let _guard = self.lock.read_lock();
        let state = unsafe { &*self.state.get() };
        state.callbacks_in_progress
    }
}

#[cfg(test)]
mod tests {
    use super::{UdpFlowCache, UdpFlowRegistration};

    fn registration(flow_id: u64) -> UdpFlowRegistration {
        UdpFlowRegistration::new(flow_id, 48, 7)
    }

    #[test]
    fn failed_association_cancels_registration() {
        let cache = UdpFlowCache::new();
        assert!(cache.register(100, registration(1)));
        assert!(cache.cancel_registration(100));
        assert!(!cache.cancel_registration(100));
        assert!(cache.is_drained());
    }

    #[test]
    fn tracks_context_until_flow_delete() {
        let cache = UdpFlowCache::new();
        assert!(cache.register(100, registration(1)));
        assert!(!cache.register(100, registration(2)));
        assert!(cache.mark_associated(100));
        assert_eq!(
            cache.snapshot(),
            alloc::vec![UdpFlowRegistration {
                flow_context: 100,
                associated: true,
                ..registration(1)
            }]
        );
        assert_eq!(cache.begin_callback(100), Some(false));
        assert!(!cache.is_drained());
        assert_eq!(cache.callbacks_in_progress(), 1);
        cache.finish_callback();
        assert!(cache.is_drained());
        assert!(cache.begin_callback(100).is_none());
    }

    #[test]
    fn shutdown_blocks_late_associations_and_drains_callback() {
        let cache = UdpFlowCache::new();
        assert!(cache.register(100, registration(1)));
        assert!(cache.mark_associated(100));
        cache.start_shutdown();
        assert_eq!(
            cache.pending_removals(),
            alloc::vec![UdpFlowRegistration {
                flow_context: 100,
                associated: true,
                removal_requested: true,
                ..registration(1)
            }]
        );
        assert!(cache.pending_removals().is_empty());
        assert!(!cache.register(200, registration(2)));
        assert_eq!(cache.begin_callback(100), Some(true));
        assert!(!cache.is_drained());
        assert_eq!(cache.callbacks_in_progress(), 1);
        cache.finish_callback();
        assert!(cache.is_drained());
    }

    #[test]
    fn shutdown_waits_for_association_in_progress() {
        let cache = UdpFlowCache::new();
        assert!(cache.register(100, registration(1)));
        cache.start_shutdown();
        assert!(cache.pending_removals().is_empty());
        assert!(!cache.is_drained());

        assert!(cache.mark_associated(100));
        assert_eq!(cache.pending_removals().len(), 1);
    }

    #[test]
    fn failed_removal_can_be_retried() {
        let cache = UdpFlowCache::new();
        assert!(cache.register(100, registration(1)));
        assert!(cache.mark_associated(100));
        cache.start_shutdown();
        let removal = cache.pending_removals().pop().expect("pending removal");
        cache.retry_removal(removal.flow_context);
        assert_eq!(cache.pending_removals().len(), 1);
    }
}
