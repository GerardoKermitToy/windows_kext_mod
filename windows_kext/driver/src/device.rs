use alloc::{format, string::String, vec::Vec};
use core::{
    ffi::c_void,
    sync::atomic::{AtomicPtr, AtomicU32, Ordering},
};
use num_traits::FromPrimitive;
use protocol::{command::CommandType, info::Info};
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv6Address};
use wdk::{
    driver::Driver,
    filter_engine::{
        callout_data::ClassifyDefer,
        net_buffer::{NetBufferList, NetworkAllocator},
        packet::{InjectInfo, Injector},
        FilterEngine,
    },
    ioqueue::{self, IOQueue},
    irp_helpers::{ReadRequest, WriteRequest},
    passive_mutex::PassiveMutex,
    rw_spin_lock::RwSpinLock,
};

use windows_sys::Win32::Foundation::NTSTATUS;

use crate::{
    array_holder::ArrayHolder,
    bandwidth::Bandwidth,
    callouts,
    connection_cache::ConnectionCache,
    connection_map::Key,
    dbg, err,
    icmp_echo_cache::IcmpEchoCache,
    id_cache::IdCache,
    logger,
    packet_util::Redirect,
    udp_endpoint_cache::UdpEndpointCache,
    udp_flow_cache::{UdpFlowCache, UdpFlowRegistration},
};

pub enum Packet {
    PacketLayer(Vec<NetBufferList>, InjectInfo),
    AleLayer(ClassifyDefer),
}

impl Packet {
    /// Returns whether applying a verdict requires a passive-level WFP
    /// management transaction before the saved packet can be reinjected.
    fn requires_reauthorization(&self) -> bool {
        matches!(
            self,
            Self::AleLayer(defer) if defer.is_reauthorization()
        )
    }
}

// Device Context
pub struct Device {
    pub(crate) filter_engine: PassiveMutex<FilterEngine>,
    pub(crate) read_leftover: RwSpinLock<ArrayHolder>,
    pub(crate) event_queue: IOQueue<Info>, // Queue for events to user-space
    pub(crate) packet_cache: RwSpinLock<IdCache>, // Cache of pending packets waiting for verdict
    pub(crate) connection_cache: ConnectionCache, // Cache of connections and their verdicts
    /// UDP remote tuples grouped by WFP transport endpoint handle. A UDP socket
    /// receives one endpoint-closure indication regardless of its remote peers.
    pub(crate) udp_endpoint_cache: RwSpinLock<UdpEndpointCache>,
    /// Contexts currently owned by WFP for per-peer UDP ALE flows.
    pub(crate) udp_flow_cache: UdpFlowCache,
    /// (remote address, echo identifier) -> PID that sent the request.
    /// An inbound echo reply has no process of its own to read, so it is matched
    /// against the outbound request that caused it.
    pub(crate) icmp_echo_cache: RwSpinLock<IcmpEchoCache>,
    pub(crate) injector: Injector,
    pub(crate) network_allocator: NetworkAllocator,
    pub(crate) bandwidth_stats: RwSpinLock<Bandwidth>,
    /// File object for the one accepted user-mode device open. The pointer is an
    /// opaque identity token; it is never dereferenced. A rejected CREATE gets a
    /// different file object, so its CLEANUP cannot release the active owner.
    pub(crate) owner_file_object: AtomicPtr<c_void>,
    /// PID belonging to `owner_file_object`, used by callouts to recognize the
    /// current Portmaster process. Zero means that no device open is accepted.
    pub(crate) owner_pid: AtomicU32,
}

// All mutable/non-Sync state is accessed through its owning lock. The remaining
// members either provide their own synchronization or are immutable after init.
unsafe impl Sync for Device {}

impl Device {
    /// Initialize all members of the device. Memory is handled by windows.
    /// Make sure everything is initialized here.
    pub fn new(driver: &Driver) -> Result<Self, String> {
        let filter_engine = FilterEngine::new(driver, 0x7dab1057_8e2b_40c4_9b85_693e381d7896)
            .map_err(|err| alloc::format!("filter engine error: {}", err))?;
        // Initialize the passive-level lock before registering any WFP state.
        // If lock initialization fails, the unregistered FilterEngine can be
        // dropped without a callback/Device lifetime race.
        let filter_engine = PassiveMutex::new(filter_engine)
            .map_err(|err| format!("filter engine lock error: {}", err))?;

        {
            let mut filter_engine_guard = filter_engine
                .lock()
                .map_err(|err| format!("failed to acquire filter engine: {}", err))?;
            if let Err(err) = filter_engine_guard.commit(callouts::get_callout_vec()) {
                // FilterEngine owns runtime WFP callback targets even while this
                // Device is still being constructed.  Close callback admission
                // before the lock and FilterEngine are dropped on this error
                // path.
                drop(filter_engine_guard);
                wdk::callback_barrier::CALLBACK_BARRIER.close_all_and_wait();
                return Err(err);
            }
        }

        Ok(Self {
            filter_engine,
            read_leftover: RwSpinLock::new(ArrayHolder::default()),
            event_queue: IOQueue::new(), // Queue for events to user-space
            packet_cache: RwSpinLock::new(IdCache::new()), // Cache of pending packets waiting for verdict
            connection_cache: ConnectionCache::new(),
            udp_endpoint_cache: RwSpinLock::new(UdpEndpointCache::new()),
            udp_flow_cache: UdpFlowCache::new(),
            icmp_echo_cache: RwSpinLock::new(IcmpEchoCache::new()),
            injector: Injector::new(),
            network_allocator: NetworkAllocator::new(),
            bandwidth_stats: RwSpinLock::new(Bandwidth::new()),
            owner_file_object: AtomicPtr::new(core::ptr::null_mut()),
            owner_pid: AtomicU32::new(0),
        })
    }

    /// Returns the PID of the process that currently has the device handle open, or 0 if none.
    pub fn is_owner_pid(&self, pid: u32) -> bool {
        let p = self.owner_pid.load(Ordering::Acquire);
        p != 0 && p == pid
    }

    /// Marks reads waiting for an event so the owning handle's cleanup can
    /// finish. The queue observes this state at its next bounded wait check.
    pub fn cancel_read_waiters(&self) {
        self.event_queue.cancel_waiters();
    }

    /// Clears the read cancellation state after all reads from the previous
    /// owner have returned and a new owner has been installed.
    pub fn reset_read_cancellation(&self) {
        self.event_queue.reset_cancellation();
    }

    /// Reauthorizes existing ALE flows after a cache policy change.
    ///
    /// WFP management APIs require PASSIVE_LEVEL. Keep this operation behind a
    /// passive-level mutex rather than the spin lock used by packet-path state;
    /// the caller must be a PASSIVE_LEVEL dispatch path (normally a user write).
    fn reset_filters(&self) -> Result<(), String> {
        let mut filter_engine = self
            .filter_engine
            .lock()
            .map_err(|err| format!("failed to acquire filter engine: {}", err))?;
        filter_engine.reset_all_filters()
    }

    /// Reauthorization is already covered when another passive worker owns the
    /// WFP transaction. Preserve the old behavior for a deferred ALE verdict:
    /// the cached verdict is visible to the next classification even when this
    /// particular reset loses the transaction race.
    fn reset_filters_for_defer(&self) -> Result<(), String> {
        match self.reset_filters() {
            Err(err) if err.contains("STATUS_FWP_TXN_IN_PROGRESS") => Ok(()),
            result => result,
        }
    }

    /// Applies a user-space verdict to a saved packet.
    ///
    /// A reauthorization marker is created only for an ALE indication that could
    /// not be pended. Reset the filters before consuming that marker so an IRQL
    /// failure cannot strand its packet after ownership has left the cache.
    fn inject_verdict_packet(&self, packet: Packet, blocked: bool) -> Result<(), String> {
        if packet.requires_reauthorization() {
            self.reset_filters_for_defer()?;
        }
        self.inject_packet(packet, blocked)
    }

    fn write_buffer(&self, read_request: &mut ReadRequest, info: Info) {
        let bytes = info.as_bytes();
        let count = read_request.write(bytes);

        // Check if the full buffer was written.
        if count < bytes.len() {
            // Save the leftovers for later.
            let leftover = self.read_leftover.write_lock();
            leftover.save(&bytes[count..]);
        }
    }

    /// Called when handle. Read is called from user-space.
    pub fn read(&self, read_request: &mut ReadRequest) -> NTSTATUS {
        let leftover_data = {
            let leftover = self.read_leftover.write_lock();
            leftover.load()
        };
        if let Some(data) = leftover_data {
            // There are leftovers from previous request.
            let count = read_request.write(&data);

            // Check if full command was written.
            if count < data.len() {
                // Save the leftovers for later.
                let leftover = self.read_leftover.write_lock();
                leftover.save(&data[count..]);
            }
        } else {
            // Noting left from before. Wait for next commands.
            match self.event_queue.wait_and_pop_cancellable() {
                Ok(info) => {
                    self.write_buffer(read_request, info);
                }
                Err(ioqueue::Status::Timeout) => {
                    // Timeout. This will only trigger if pop function is called with timeout.
                    return read_request.timeout();
                }
                Err(ioqueue::Status::Cancelled) => {
                    // The owning file object was cleaned up while this
                    // synchronous wait was blocked.
                    return read_request.cancelled();
                }
                Err(err) => {
                    // Queue failed. Send EOF, to notify user-space. Usually happens on rundown.
                    err!("failed to pop value: {}", err);
                    return read_request.end_of_file();
                }
            }
        }

        // Check if we have more space. InfoType + data_size == 5 bytes
        while read_request.free_space() > 5 {
            match self.event_queue.pop() {
                Ok(info) => {
                    self.write_buffer(read_request, info);
                }
                Err(_) => {
                    break;
                }
            }
        }
        read_request.complete()
    }

    // Called when handle.Write is called from user-space.
    pub fn write(&self, write_request: &mut WriteRequest) {
        // Try parsing the command.
        let mut buffer = write_request.get_buffer();
        let command = protocol::command::parse_type(buffer);
        let Some(command) = command else {
            err!("Unknown command number: {}", buffer[0]);
            return;
        };
        buffer = &buffer[1..];

        match command {
            CommandType::Shutdown => {
                wdk::dbg!("Shutdown command");
                self.shutdown();
            }
            CommandType::Verdict => {
                let verdict = protocol::command::parse_verdict(buffer);
                wdk::dbg!("Verdict command");
                // Received verdict decision for a specific connection.
                let packet = {
                    let mut packet_cache = self.packet_cache.write_lock();
                    packet_cache.pop_id(verdict.id)
                };
                if let Some((key, mut packet)) = packet {
                    if let Some(verdict) = FromPrimitive::from_u8(verdict.verdict) {
                        dbg!("Verdict received {}: {}", key, verdict);
                        // Add verdict in the cache.
                        let redirect_info = self.connection_cache.update_connection(key, verdict);

                        match verdict {
                            crate::connection::Verdict::Accept
                            | crate::connection::Verdict::PermanentAccept => {
                                if let Err(err) = self.inject_verdict_packet(packet, false) {
                                    err!("failed to inject packet: {}", err);
                                } else {
                                    dbg!("packet injected: {}", key);
                                }
                            }
                            crate::connection::Verdict::RedirectNameServer
                            | crate::connection::Verdict::RedirectTunnel
                            | crate::connection::Verdict::RedirectSplitTunnel => {
                                if let Some(redirect_info) = redirect_info {
                                    // Will not redirect packets from ALE layer
                                    if let Err(err) = packet.redirect(redirect_info) {
                                        err!("failed to redirect packet: {}", err);
                                    }
                                    if let Err(err) = self.inject_verdict_packet(packet, false) {
                                        err!("failed to inject packet: {}", err);
                                    }
                                } else {
                                    // The connection disappeared before its verdict was
                                    // applied. Complete an ALE pend, if this is one, but
                                    // do not inject a packet with no redirect state.
                                    if let Err(err) = self.inject_verdict_packet(packet, true) {
                                        err!("failed to complete packet: {}", err);
                                    }
                                }
                            }
                            _ => {
                                // Complete ALE operations without injecting their
                                // packet clone. Packet-layer clones are discarded.
                                if let Err(err) = self.inject_verdict_packet(packet, true) {
                                    err!("failed to inject packet: {}", err);
                                }
                            }
                        }
                    } else {
                        let invalid_verdict = verdict.verdict;
                        err!("invalid verdict value: {}", invalid_verdict);
                        if let Err(err) = self.inject_verdict_packet(packet, true) {
                            err!("failed to complete packet: {}", err);
                        }
                    }
                } else {
                    // Id was not in the packet cache.
                    let id = verdict.id;
                    err!("Verdict invalid id: {}", id);
                }
            }
            CommandType::UpdateV4 => {
                let update = protocol::command::parse_update_v4(buffer);
                // Build the new action.
                if let Some(verdict) = FromPrimitive::from_u8(update.verdict) {
                    // Update with new action.
                    dbg!("Verdict update received {:?}: {}", update, verdict);
                    _ = self.connection_cache.update_connection(
                        Key {
                            protocol: IpProtocol::from(update.protocol),
                            local_address: IpAddress::Ipv4(Ipv4Address::from_bytes(
                                &update.local_address,
                            )),
                            local_port: update.local_port,
                            remote_address: IpAddress::Ipv4(Ipv4Address::from_bytes(
                                &update.remote_address,
                            )),
                            remote_port: update.remote_port,
                        },
                        verdict,
                    );
                    // Packet-layer lookups observe cache updates on the next packet.
                    // ALE-authorized flows need an explicit policy reauthorization.
                    if let Err(err) = self.reset_filters() {
                        err!("failed to reauthorize connections: {}", err);
                    }
                } else {
                    err!("invalid verdict value: {}", update.verdict);
                }
            }
            CommandType::UpdateV6 => {
                let update = protocol::command::parse_update_v6(buffer);
                // Build the new action.
                if let Some(verdict) = FromPrimitive::from_u8(update.verdict) {
                    // Update with new action.
                    dbg!("Verdict update received {:?}: {}", update, verdict);
                    _ = self.connection_cache.update_connection(
                        Key {
                            protocol: IpProtocol::from(update.protocol),
                            local_address: IpAddress::Ipv6(Ipv6Address::from_bytes(
                                &update.local_address,
                            )),
                            local_port: update.local_port,
                            remote_address: IpAddress::Ipv6(Ipv6Address::from_bytes(
                                &update.remote_address,
                            )),
                            remote_port: update.remote_port,
                        },
                        verdict,
                    );
                    // Packet-layer lookups observe cache updates on the next packet.
                    // ALE-authorized flows need an explicit policy reauthorization.
                    if let Err(err) = self.reset_filters() {
                        err!("failed to reauthorize connections: {}", err);
                    }
                } else {
                    err!("invalid verdict value: {}", update.verdict);
                }
            }
            CommandType::ClearCache => {
                wdk::dbg!("ClearCache command");
                self.connection_cache.clear();
                {
                    let mut endpoint_cache = self.udp_endpoint_cache.write_lock();
                    endpoint_cache.clear();
                }
                self.clean_udp_lifecycle_state();
                if let Err(err) = self.reset_filters() {
                    err!("failed to reset filters: {}", err);
                }
            }
            CommandType::GetLogs => {
                wdk::dbg!("GetLogs command");
                let lines_vec = logger::flush();
                for line in lines_vec {
                    let _ = self.event_queue.push(line);
                }
            }
            CommandType::GetBandwidthStats => {
                wdk::dbg!("GetBandwidthStats command");
                let stats = {
                    let mut bandwidth_stats = self.bandwidth_stats.write_lock();
                    bandwidth_stats.get_all_updates_tcp_v4()
                };
                if let Some(stats) = stats {
                    _ = self.event_queue.push(stats);
                }

                let stats = {
                    let mut bandwidth_stats = self.bandwidth_stats.write_lock();
                    bandwidth_stats.get_all_updates_tcp_v6()
                };
                if let Some(stats) = stats {
                    _ = self.event_queue.push(stats);
                }

                let stats = {
                    let mut bandwidth_stats = self.bandwidth_stats.write_lock();
                    bandwidth_stats.get_all_updates_udp_v4()
                };
                if let Some(stats) = stats {
                    _ = self.event_queue.push(stats);
                }

                let stats = {
                    let mut bandwidth_stats = self.bandwidth_stats.write_lock();
                    bandwidth_stats.get_all_updates_udp_v6()
                };
                if let Some(stats) = stats {
                    _ = self.event_queue.push(stats);
                }
            }
            CommandType::PrintMemoryStats => {
                // Getting the information takes a long time and interferes with the callouts causing the device to crash.
                // TODO(vladimir): Make more optimized version
                // info!(
                //     "Packet cache: {} entries",
                //     self.packet_cache.get_entries_count()
                // );
                // info!(
                //     "BandwidthStats cache: {} entries",
                //     self.bandwidth_stats.get_entries_count()
                // );
                // info!(
                //     "Connection cache: {} entries\n {}",
                //     self.connection_cache.get_entries_count(),
                //     self.connection_cache.get_full_cache_info()
                // );
            }
            CommandType::CleanEndedConnections => {
                wdk::dbg!("CleanEndedConnections command");
                let (inactive_v4, inactive_v6) = self.connection_cache.clean_ended_connections();
                // Native flow deletion emits promptly when WFP actually reclaims
                // the ALE flow. This ten-minute watchdog also covers associated UDP
                // flows whose Windows cleanup callback is delayed until socket close.
                // It expires only Portmaster's cache record; it does not abort the
                // WFP flow or close the socket. Either path consumes the exact live
                // cache instance, so the later one cannot duplicate END.
                for conn in inactive_v4 {
                    crate::ale_callouts::emit_connection_end_v4(self, conn, 0);
                }
                for conn in inactive_v6 {
                    crate::ale_callouts::emit_connection_end_v6(self, conn, 0);
                }
                // Reconcile only after the watchdog has removed inactive connection
                // instances. Removing a WFP callout context does not close the UDP
                // socket or flow; it merely asks WFP to return our allocation through
                // flowDeleteFn.
                self.clean_udp_lifecycle_state();
                // Same intent for the ICMP echo table: an unanswered request is
                // state that is no longer needed. Expired entries only, so that
                // requests still in flight keep their process attribution.
                //
                // Doing it here also keeps the sweep off the packet path - the
                // only other one runs inside a callout at DISPATCH_LEVEL.
                let mut icmp_echo_cache = self.icmp_echo_cache.write_lock();
                icmp_echo_cache.clean_expired_entries();
            }
        }
    }

    /// Removes one associated WFP flow context without terminating the socket or
    /// its network flow. WFP reclaims only the callout-owned bookkeeping and invokes
    /// `udp_flow_delete`, which frees the allocation and consumes the exact cache
    /// instance if it is still live.
    fn remove_udp_flow_context(&self, registration: UdpFlowRegistration) {
        match wdk::filter_engine::flow::remove_context(
            registration.flow_id,
            registration.layer_id,
            registration.callout_id,
        ) {
            Ok(wdk::filter_engine::flow::RemoveContextResult::Removed)
            | Ok(wdk::filter_engine::flow::RemoveContextResult::Pending) => {}
            Ok(wdk::filter_engine::flow::RemoveContextResult::AlreadyGone) => {
                // WFP has no association left and therefore cannot call
                // flowDeleteFn; reclaim the driver-owned allocation here.
                crate::ale_callouts::reclaim_udp_flow_context(
                    self,
                    registration.flow_context,
                    registration.connection_instance_id,
                );
            }
            Err(err) => {
                self.udp_flow_cache.retry_removal(
                    registration.flow_context,
                    registration.connection_instance_id,
                );
                crate::err!(
                    "failed to remove UDP flow context {}: {}",
                    registration.flow_id,
                    err
                );
            }
        }
    }

    /// Reconciles endpoint/flow bookkeeping with the live connection cache.
    ///
    /// Snapshot order is intentional: endpoint and flow state are captured before
    /// live connections. Any association created concurrently is therefore visible
    /// in the later live snapshot or remains untouched until the next pass.
    fn clean_udp_lifecycle_state(&self) {
        let endpoint_instances = self.udp_endpoint_cache.write_lock().instance_ids();
        let flow_candidates = self.udp_flow_cache.removal_candidates();
        let live_instances = self.connection_cache.live_udp_instance_ids();

        let stale_endpoint_instances = endpoint_instances
            .into_iter()
            .filter(|instance_id| live_instances.binary_search(instance_id).is_err())
            .collect();
        {
            let mut endpoint_cache = self.udp_endpoint_cache.write_lock();
            let _ = endpoint_cache.remove_instances(stale_endpoint_instances);
        }

        for (flow_context, connection_instance_id) in flow_candidates {
            if live_instances
                .binary_search(&connection_instance_id)
                .is_ok()
            {
                continue;
            }
            if let Some(registration) = self
                .udp_flow_cache
                .claim_removal(flow_context, connection_instance_id)
            {
                self.remove_udp_flow_context(registration);
            }
        }
    }

    /// Removes every context still owned by WFP before callout unregistration.
    ///
    /// `FwpsCalloutUnregisterById0` returns STATUS_DEVICE_BUSY while any context
    /// remains associated. Keep the global Device pointer valid until the resulting
    /// flowDeleteFn callbacks have drained this cache.
    pub fn prepare_unload(&self) {
        self.udp_flow_cache.start_shutdown();
        while !self.udp_flow_cache.is_drained() {
            for registration in self.udp_flow_cache.pending_removals() {
                self.remove_udp_flow_context(registration);
            }

            if !self.udp_flow_cache.is_drained() {
                // STATUS_PENDING completes through flowDeleteFn after any active
                // classification returns. Each association is requested once unless
                // the WFP removal call itself failed.
                wdk::utils::sleep_ms(1);
            }
        }
    }

    pub fn shutdown(&self) {
        // End blocking operations from the queue. This also sets the
        // cancellation flag so reads that are in a bounded wait leave before
        // the queue is reclaimed.
        self.event_queue.rundown();

        // Resolve all pending packets. This is important for proper driver unload.
        let pending_packets = {
            let mut packet_cache = self.packet_cache.write_lock();
            packet_cache.pop_all()
        };
        for el in pending_packets {
            let key = el.value.0;
            let packet = el.value.1;
            // Set any verdict. Driver will unload after that and the filter will not be active.
            _ = self
                .connection_cache
                .update_connection(key, crate::connection::Verdict::PermanentBlock);
            _ = self.inject_packet(packet, true); // Complete ALE pends and discard all packet clones.
        }

        let mut endpoint_cache = self.udp_endpoint_cache.write_lock();
        endpoint_cache.clear();
    }

    pub fn inject_packet(&self, packet: Packet, blocked: bool) -> Result<(), String> {
        match packet {
            Packet::PacketLayer(nbls, inject_info) => {
                if !blocked {
                    for nbl in nbls {
                        self.injector.inject_net_buffer_list(nbl, inject_info)?;
                    }
                }
                Ok(())
            }
            Packet::AleLayer(defer) => {
                // Initial ALE pends can be completed at the callback's IRQL and
                // do not need the FilterEngine. Reauthorization is performed by
                // the PASSIVE_LEVEL verdict path before this packet reaches here.
                let packet_list = defer.complete(!blocked)?;
                if !blocked {
                    if let Some(packet_list) = packet_list {
                        self.injector.inject_packet_list_transport(packet_list)?;
                    }
                }

                Ok(())
            }
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // Normal unload closes this barrier before reaching Drop.  Keep the
        // guard here as a last line of defense for an initialization/error path
        // that destroys Device through a different route.
        wdk::callback_barrier::CALLBACK_BARRIER.close_all_and_wait();
        _ = logger::flush();
        // dbg!("Device Context drop called.");
    }
}
