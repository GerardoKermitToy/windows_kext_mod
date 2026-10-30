//! Keeps process notifications scoped to the device-open session without dropping
//! network records (and their pending verdicts) when a client reconnects.

use core::sync::atomic::{AtomicU64, Ordering};
use protocol::info::Info;
#[cfg(test)]
use tests::{IOQueue, Status};
#[cfg(not(test))]
use wdk::ioqueue::{IOQueue, Status};

struct QueuedInfo {
    info: Info,
    process_session: Option<u64>,
}

pub(crate) struct EventQueue {
    queue: IOQueue<QueuedInfo>,
    process_session: AtomicU64,
}

impl EventQueue {
    pub(crate) fn new() -> Self {
        Self {
            queue: IOQueue::new(),
            process_session: AtomicU64::new(0),
        }
    }

    pub(crate) fn push(&self, info: Info) -> Result<(), Status> {
        self.queue.push(QueuedInfo {
            info,
            process_session: None,
        })
    }

    pub(crate) fn begin_process_session(&self) -> u64 {
        self.process_session
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1)
    }

    pub(crate) fn end_process_session(&self) {
        self.process_session.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn push_process(&self, info: Info, session: u64) -> Result<(), Status> {
        self.queue.push(QueuedInfo {
            info,
            process_session: Some(session),
        })
    }

    fn current(&self, entry: QueuedInfo) -> Option<Info> {
        if entry
            .process_session
            .is_some_and(|session| session != self.process_session.load(Ordering::Acquire))
        {
            None
        } else {
            Some(entry.info)
        }
    }

    pub(crate) fn pop(&self) -> Result<Info, Status> {
        loop {
            let entry = self.queue.pop()?;
            if let Some(info) = self.current(entry) {
                return Ok(info);
            }
        }
    }

    pub(crate) fn wait_and_pop_cancellable(&self) -> Result<Info, Status> {
        loop {
            let entry = self.queue.wait_and_pop_cancellable()?;
            if let Some(info) = self.current(entry) {
                return Ok(info);
            }
        }
    }

    pub(crate) fn cancel_waiters(&self) {
        self.queue.cancel_waiters();
    }

    pub(crate) fn reset_cancellation(&self) {
        self.queue.reset_cancellation();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicBool;
    use protocol::info::{log_line, process_created_info, process_terminated_info, Severity};
    use std::{collections::VecDeque, sync::Mutex};

    #[derive(Debug)]
    pub(crate) enum Status {
        Empty,
        Cancelled,
    }

    // Kernel waits are tested by runtime suites. This FIFO double exercises
    // the real session filtering, including both dequeue entry points, offline.
    pub(crate) struct IOQueue<T> {
        entries: Mutex<VecDeque<T>>,
        cancelled: AtomicBool,
    }

    impl<T> IOQueue<T> {
        pub(crate) fn new() -> Self {
            Self {
                entries: Mutex::new(VecDeque::new()),
                cancelled: AtomicBool::new(false),
            }
        }
        pub(crate) fn push(&self, entry: T) -> Result<(), Status> {
            self.entries.lock().unwrap().push_back(entry);
            Ok(())
        }
        pub(crate) fn pop(&self) -> Result<T, Status> {
            self.entries
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(Status::Empty)
        }
        pub(crate) fn wait_and_pop_cancellable(&self) -> Result<T, Status> {
            if self.cancelled.load(Ordering::Acquire) {
                return Err(Status::Cancelled);
            }
            self.pop()
        }
        pub(crate) fn cancel_waiters(&self) {
            self.cancelled.store(true, Ordering::Release);
        }
        pub(crate) fn reset_cancellation(&self) {
            self.cancelled.store(false, Ordering::Release);
        }
    }

    #[test]
    fn reconnect_skips_old_process_records_without_dropping_normal_events() {
        let queue = EventQueue::new();
        let old = queue.begin_process_session();
        queue
            .push_process(process_created_info([(80, 4)]), old)
            .unwrap();
        let normal = log_line(Severity::Info, 0);
        let expected = normal.as_bytes().to_vec();
        queue.push(normal).unwrap();
        queue
            .push_process(process_terminated_info([80]), old)
            .unwrap();
        queue.end_process_session();
        let current = queue.begin_process_session();
        queue
            .push_process(process_created_info([(81, 4)]), current)
            .unwrap();
        assert_eq!(queue.pop().unwrap().as_bytes(), expected);
        assert_eq!(
            queue.pop().unwrap().as_bytes(),
            process_created_info([(81, 4)]).as_bytes()
        );
        assert!(queue.pop().is_err());
    }

    #[test]
    fn restart_preserves_unread_process_and_network_records_in_wire_order() {
        let queue = EventQueue::new();
        let session = queue.begin_process_session();
        let before = process_created_info([(80, 4)]);
        let network = log_line(Severity::Info, 0);
        let exit = process_terminated_info([80]);
        let fresh = process_created_info([(4, 0), (81, 4)]);
        let expected = [&before, &network, &exit, &fresh].map(|info| info.as_bytes().to_vec());
        queue.push_process(before, session).unwrap();
        queue.push(network).unwrap();
        queue.push_process(exit, session).unwrap();
        // A collection restart retains the device-open epoch, unlike reconnect.
        queue.push_process(fresh, session).unwrap();
        for bytes in expected {
            assert_eq!(queue.wait_and_pop_cancellable().unwrap().as_bytes(), bytes);
        }
        assert!(queue.pop().is_err());
    }

    #[test]
    fn blocking_dequeue_skips_stale_records_and_preserves_cancellation() {
        let queue = EventQueue::new();
        let old = queue.begin_process_session();
        queue
            .push_process(process_terminated_info([80]), old)
            .unwrap();
        queue.end_process_session();
        let current = queue.begin_process_session();
        queue
            .push_process(process_created_info([(81, 4)]), current)
            .unwrap();
        queue.cancel_waiters();
        assert!(matches!(
            queue.wait_and_pop_cancellable(),
            Err(Status::Cancelled)
        ));
        queue.reset_cancellation();
        assert_eq!(
            queue.wait_and_pop_cancellable().unwrap().as_bytes(),
            process_created_info([(81, 4)]).as_bytes()
        );
        assert!(queue.wait_and_pop_cancellable().is_err());
    }
}
