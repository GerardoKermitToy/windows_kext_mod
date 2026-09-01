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
        FilterEngine, UnregisterCalloutsResult,
    },
    ioqueue::{self, IOQueue},
    irp_helpers::{ReadRequest, WriteRequest},
    passive_mutex::PassiveMutex,
    rw_spin_lock::RwSpinLock,
};

use windows_sys::Win32::Foundation::{
    NTSTATUS, STATUS_INVALID_DEVICE_STATE, STATUS_INVALID_PARAMETER,
};

use crate::{
    array_holder::ArrayHolder,
    bandwidth::Bandwidth,
    callouts,
    connection::Connection,
    connection_cache::ConnectionCache,
    connection_map::Key,
    dbg, err,
    icmp_echo_cache::IcmpEchoCache,
    id_cache::{IdCache, PendingPacket},
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
    /// Serializes the complete event-stream read transaction: consuming a saved
    /// fragment, waiting for/dequeuing records, and publishing the next fragment.
    /// A spin lock cannot protect this state because an empty stream may wait.
    read_stream: PassiveMutex<ArrayHolder>,
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

// Every mutable field is owned by its synchronization primitive. The resource
// wrappers in wdk expose their cross-thread contracts individually, so Device's
// auto-traits are checked field by field rather than bypassed with a blanket impl.

impl Device {
    /// Initialize all members of the device. Memory is handled by windows.
    /// Make sure everything is initialized here.
    pub fn new(driver: &Driver) -> Result<Self, String> {
        // Complete every fallible standalone allocation before registering WFP
        // callbacks. If either resource is unavailable, DriverEntry fails without
        // ever exposing a callback that depends on a partially built Device.
        let injector = Injector::new().map_err(|err| format!("injector error: {}", err))?;
        let network_allocator =
            NetworkAllocator::new().map_err(|err| format!("network allocator error: {}", err))?;
        let read_stream = PassiveMutex::new(ArrayHolder::default())
            .map_err(|err| format!("read stream lock error: {}", err))?;

        let filter_engine = FilterEngine::new(driver, 0x7dab1057_8e2b_40c4_9b85_693e381d7896)
            .map_err(|err| alloc::format!("filter engine error: {}", err))?;
        // Initialize the passive-level lock before publishing the Device. WFP
        // filters are committed separately, after the complete Device has been
        // stored in the global pointer.
        let filter_engine = PassiveMutex::new(filter_engine)
            .map_err(|err| format!("filter engine lock error: {}", err))?;

        Ok(Self {
            filter_engine,
            read_stream,
            event_queue: IOQueue::new(), // Queue for events to user-space
            packet_cache: RwSpinLock::new(IdCache::new()), // Cache of pending packets waiting for verdict
            connection_cache: ConnectionCache::new(),
            udp_endpoint_cache: RwSpinLock::new(UdpEndpointCache::new()),
            udp_flow_cache: UdpFlowCache::new(),
            icmp_echo_cache: RwSpinLock::new(IcmpEchoCache::new()),
            injector,
            network_allocator,
            bandwidth_stats: RwSpinLock::new(Bandwidth::new()),
            owner_file_object: AtomicPtr::new(core::ptr::null_mut()),
            owner_pid: AtomicU32::new(0),
        })
    }

    /// Registers and activates all WFP state after the complete Device has been
    /// published. Runtime callbacks can begin as soon as the FWPM transaction is
    /// committed, so publication must precede this call.
    pub fn start_filtering(&self) -> Result<(), String> {
        let mut filter_engine = self
            .filter_engine
            .lock()
            .map_err(|err| format!("failed to acquire filter engine: {}", err))?;
        filter_engine.commit(callouts::get_callout_vec())
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

    fn write_buffer(read_request: &mut ReadRequest, info: Info, read_stream: &mut ArrayHolder) {
        let bytes = info.as_bytes();
        let count = read_request.write(bytes);

        // Check if the full buffer was written.
        if count < bytes.len() {
            // Save the leftovers for later while the same stream transaction is
            // still exclusively owned by this read.
            read_stream.save(&bytes[count..]);
        }
    }

    /// Discards a partial record after every read admitted for the old owner has
    /// returned. A replacement handle must always begin at a record boundary.
    pub(crate) fn clear_read_leftover(&self) -> Result<(), String> {
        let mut read_stream = self
            .read_stream
            .lock()
            .map_err(|err| format!("failed to lock read stream: {}", err))?;
        read_stream.clear();
        Ok(())
    }

    /// Called when handle. Read is called from user-space.
    pub fn read(&self, read_request: &mut ReadRequest) -> NTSTATUS {
        // Keep one exclusive owner across the entire operation. Locking only the
        // individual load/save calls permits two overlapped reads to consume the
        // same logical stream concurrently and overwrite each other's fragment.
        let mut read_stream = match self.read_stream.lock() {
            Ok(read_stream) => read_stream,
            Err(err) => {
                err!("failed to lock read stream: {}", err);
                return read_request.fail(STATUS_INVALID_DEVICE_STATE);
            }
        };

        if let Some(data) = read_stream.load() {
            // There are leftovers from previous request.
            let count = read_request.write(&data);

            // Check if full command was written.
            if count < data.len() {
                // Save the leftovers for later.
                read_stream.save(&data[count..]);
            }
        } else {
            // Nothing left from before. Wait for the next record.
            match self.event_queue.wait_and_pop_cancellable() {
                Ok(info) => {
                    Self::write_buffer(read_request, info, &mut read_stream);
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
                    Self::write_buffer(read_request, info, &mut read_stream);
                }
                Err(_) => {
                    break;
                }
            }
        }
        read_request.complete()
    }

    /// Applies exactly one command supplied by a user-mode WriteFile request.
    /// Malformed commands fail without consuming input bytes or mutating state.
    pub fn write(&self, write_request: &WriteRequest) -> Result<(), NTSTATUS> {
        // Every WriteFile contains exactly one command. Validate the command byte
        // and complete payload before reading any field from user-controlled data.
        let buffer = write_request.get_buffer();
        let Some(command) = protocol::command::parse_type(buffer) else {
            match buffer.first() {
                Some(command) => err!("Unknown command number: {}", command),
                None => err!("Rejecting empty command write"),
            }
            return Err(STATUS_INVALID_PARAMETER);
        };
        let payload = &buffer[1..];
        if !protocol::command::has_valid_payload_length(command, payload) {
            err!(
                "Invalid command payload length: expected {}, received {}",
                command.payload_size(),
                payload.len()
            );
            return Err(STATUS_INVALID_PARAMETER);
        }

        match command {
            CommandType::Shutdown => {
                wdk::dbg!("Shutdown command");
                self.shutdown();
            }
            CommandType::Verdict => {
                let Some(verdict) = protocol::command::parse_verdict(payload) else {
                    // The length was checked above; keep this guard in case the
                    // parser and command table ever diverge.
                    err!("Failed to decode Verdict command");
                    return Err(STATUS_INVALID_PARAMETER);
                };
                let Some(action): Option<crate::connection::Verdict> =
                    FromPrimitive::from_u8(verdict.verdict)
                else {
                    // Validate the action before consuming the pending packet. A
                    // malformed command must not mutate driver state before its
                    // WriteFile request is failed.
                    err!("invalid verdict value: {}", verdict.verdict);
                    return Err(STATUS_INVALID_PARAMETER);
                };

                wdk::dbg!("Verdict command");
                // Received verdict decision for a specific connection.
                let packet = {
                    let mut packet_cache = self.packet_cache.write_lock();
                    packet_cache.pop_id(verdict.id)
                };
                if let Some(PendingPacket {
                    key,
                    mut packet,
                    connection_instance_id,
                }) = packet
                {
                    dbg!("Verdict received {}: {}", key, action);
                    // A connection verdict belongs to the exact cache instance that
                    // queued this packet. If endpoint/flow cleanup already ended it,
                    // complete the saved operation as blocked instead of applying a
                    // stale decision to a tuple replacement or reinjecting into a
                    // closed endpoint. Protocols without connection state have no
                    // instance and continue to use packet-only verdict handling.
                    let redirect_info = if let Some(instance_id) = connection_instance_id {
                        let Some(update) = self.connection_cache.update_connection_instance(
                            key,
                            instance_id,
                            action,
                        ) else {
                            dbg!(
                                "discarding stale verdict for ended connection instance {}: {}",
                                instance_id,
                                key
                            );
                            if let Err(err) = self.inject_packet(packet, true) {
                                err!("failed to complete stale packet: {}", err);
                            }
                            return Ok(());
                        };
                        update.redirect_info
                    } else {
                        None
                    };

                    match action {
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
                                // Never inject a clone when redirect validation or
                                // checksum reconstruction failed. The packet is dropped
                                // with this verdict instead of escaping unredirected.
                                match packet.redirect(redirect_info) {
                                    Ok(()) => {
                                        if let Err(err) = self.inject_verdict_packet(packet, false)
                                        {
                                            err!("failed to inject packet: {}", err);
                                        }
                                    }
                                    Err(err) => err!("failed to redirect packet: {}", err),
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
                    // Id was not in the packet cache.
                    let id = verdict.id;
                    err!("Verdict invalid id: {}", id);
                }
            }
            CommandType::UpdateV4 => {
                let Some(update) = protocol::command::parse_update_v4(payload) else {
                    err!("Failed to decode UpdateV4 command");
                    return Err(STATUS_INVALID_PARAMETER);
                };
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
                    return Err(STATUS_INVALID_PARAMETER);
                }
            }
            CommandType::UpdateV6 => {
                let Some(update) = protocol::command::parse_update_v6(payload) else {
                    err!("Failed to decode UpdateV6 command");
                    return Err(STATUS_INVALID_PARAMETER);
                };
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
                    return Err(STATUS_INVALID_PARAMETER);
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
                let mut inactive_instance_ids =
                    Vec::with_capacity(inactive_v4.len() + inactive_v6.len());
                inactive_instance_ids.extend(inactive_v4.iter().map(Connection::get_instance_id));
                inactive_instance_ids.extend(inactive_v6.iter().map(Connection::get_instance_id));
                self.discard_pending_connection_instances(&inactive_instance_ids);
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

        Ok(())
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

    /// Stops new flow-context associations before the remaining asynchronous ALE
    /// operations are completed. Classify admission must already be closed and
    /// drained by the caller.
    pub fn begin_unload(&self) {
        self.udp_flow_cache.start_shutdown();
    }

    /// Drains every context still owned by WFP, unregisters all runtime callouts,
    /// and destroys injection handles before the Device or its Callout allocations
    /// can be released.
    ///
    /// `FwpsCalloutUnregisterById0` returns STATUS_DEVICE_BUSY while any context
    /// remains associated. Keep the global Device pointer valid until the resulting
    /// flowDeleteFn callbacks have drained this cache and WFP confirms that every
    /// runtime registration is gone. Injection-handle destruction is last because
    /// WFP waits for all pending injections before each handle is destroyed.
    pub fn prepare_unload(&self) {
        self.drain_udp_flow_contexts();
        self.unregister_wfp_state();
        self.destroy_injection_handles();
    }

    fn destroy_injection_handles(&self) {
        loop {
            match self.injector.destroy() {
                Ok(()) => return,
                Err(err) => {
                    // Keep the Injector alive and retry. A failed destroy leaves
                    // its handle published so unload cannot accidentally release
                    // the Device while WFP may still reference it.
                    crate::err!("failed to destroy WFP injection handles: {}", err);
                }
            }
            wdk::utils::sleep_ms(1);
        }
    }

    fn drain_udp_flow_contexts(&self) {
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

    fn unregister_wfp_state(&self) {
        loop {
            let result = match self.filter_engine.lock() {
                Ok(mut filter_engine) => filter_engine.unregister_all(),
                Err(err) => Err(format!("failed to acquire filter engine: {}", err)),
            };

            match result {
                Ok(UnregisterCalloutsResult::Complete) => return,
                Ok(UnregisterCalloutsResult::Busy) => {
                    self.drain_udp_flow_contexts();
                    crate::err!(
                        "WFP callout unregister is busy; retrying after flow-context removal"
                    );
                }
                Err(err) => {
                    crate::err!("failed to tear down WFP state: {}", err);
                }
            }
            wdk::utils::sleep_ms(1);
        }
    }

    /// Permanently stops classification for this driver instance and resolves all
    /// pending user-space decisions. This runs from PASSIVE_LEVEL dispatch or
    /// DriverUnload and is idempotent.
    pub fn shutdown(&self) {
        // A user-mode shutdown command can arrive before service-driven unload.
        // Close callback admission here as well as in DriverUnload so no classify
        // can enqueue a new packet after the cache and event queue are drained.
        wdk::callback_barrier::CALLBACK_BARRIER.close_classify_and_wait();
        self.begin_unload();

        // KeRundownQueue cannot race a thread blocked in KeRemoveQueue. Close
        // read admission, wake the bounded waits, and drain their dispatch guards
        // before reclaiming queued entries. The queue itself is reclaimed by
        // Device::drop after DriverUnload has closed all dispatch admission. Do
        // not run it down here: a user-issued shutdown can race CLEANUP followed
        // by a new CREATE, and that new session may reopen read admission while
        // this dispatch is still finishing.
        crate::entry::close_and_wait_for_reads(self);

        // Resolve all pending packets. This is important for proper driver unload.
        let pending_packets = {
            let mut packet_cache = self.packet_cache.write_lock();
            packet_cache.pop_all()
        };
        for el in pending_packets {
            let pending = el.value;
            // Set any verdict. Driver will unload after that and the filter will not be active.
            if let Some(instance_id) = pending.connection_instance_id {
                _ = self.connection_cache.update_connection_instance(
                    pending.key,
                    instance_id,
                    crate::connection::Verdict::PermanentBlock,
                );
            }
            _ = self.inject_packet(pending.packet, true); // Complete ALE pends and discard all packet clones.
        }

        let mut endpoint_cache = self.udp_endpoint_cache.write_lock();
        endpoint_cache.clear();
    }

    /// Cancels queued decisions for connection instances whose native lifetime has
    /// ended. Packet ownership is removed under the cache lock, then every ALE pend
    /// is completed as blocked after the lock has been released.
    pub(crate) fn discard_pending_connection_instances(&self, instance_ids: &[u64]) {
        if instance_ids.is_empty() {
            return;
        }

        let mut sorted_instance_ids = instance_ids.to_vec();
        sorted_instance_ids.retain(|instance_id| *instance_id != 0);
        sorted_instance_ids.sort_unstable();
        sorted_instance_ids.dedup();
        if sorted_instance_ids.is_empty() {
            return;
        }

        let pending_packets = {
            let mut packet_cache = self.packet_cache.write_lock();
            packet_cache.pop_connection_instances(&sorted_instance_ids)
        };
        for pending in pending_packets {
            if let Err(err) = self.inject_packet(pending.packet, true) {
                crate::err!(
                    "failed to discard pending packet for ended connection {}: {}",
                    pending.key,
                    err
                );
            }
        }
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
