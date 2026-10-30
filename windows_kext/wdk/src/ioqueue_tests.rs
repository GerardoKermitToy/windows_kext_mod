//! Host tests exercise the production FIFO and cancellation logic. Only the
//! kernel spin lock and dispatcher events are replaced by blocking std primitives.

use super::*;
use std::{
    cell::Cell,
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender},
        Arc, Barrier, Condvar, Mutex, MutexGuard, OnceLock,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

thread_local! {
    static LOCK_DEPTH: Cell<usize> = const { Cell::new(0) };
}

pub(super) struct RwSpinLock<T>(Mutex<T>);

impl<T> RwSpinLock<T> {
    pub(super) fn new(value: T) -> Self {
        Self(Mutex::new(value))
    }

    pub(super) fn write_lock(&self) -> LockGuard<'_, T> {
        let guard = self.0.lock().unwrap();
        LOCK_DEPTH.with(|depth| depth.set(depth.get() + 1));
        LockGuard(guard)
    }
}

pub(super) struct LockGuard<'a, T>(MutexGuard<'a, T>);

impl<T> Deref for LockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for LockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> Drop for LockGuard<'_, T> {
    fn drop(&mut self) {
        LOCK_DEPTH.with(|depth| depth.set(depth.get() - 1));
    }
}

#[derive(Default)]
struct Signals {
    ready: bool,
    cancelled: bool,
}

#[derive(Default)]
pub(super) struct WaitEvents {
    signals: Mutex<Signals>,
    changed: Condvar,
    waits: AtomicUsize,
    timed_waits: AtomicUsize,
    ready_signals: AtomicUsize,
    before_wait: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    before_block: Mutex<Option<Sender<()>>>,
}

impl WaitEvents {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn set_ready(&self) {
        self.signals.lock().unwrap().ready = true;
        self.ready_signals.fetch_add(1, Ordering::Relaxed);
        self.changed.notify_all();
    }

    pub(super) fn clear_ready(&self) {
        self.signals.lock().unwrap().ready = false;
    }

    pub(super) fn set_cancelled(&self) {
        self.signals.lock().unwrap().cancelled = true;
        self.changed.notify_all();
    }

    pub(super) fn clear_cancelled(&self) {
        self.signals.lock().unwrap().cancelled = false;
    }

    pub(super) fn wait(&self, cancellable: bool, timeout_ms: Option<u64>) -> Result<(), Status> {
        assert_eq!(LOCK_DEPTH.with(Cell::get), 0, "wait under queue lock");
        self.waits.fetch_add(1, Ordering::Relaxed);
        if timeout_ms.is_some() {
            self.timed_waits.fetch_add(1, Ordering::Relaxed);
        }
        let hook = self.before_wait.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }

        let signals = self.signals.lock().unwrap();
        let pending = |signals: &mut Signals| !signals.ready && !(cancellable && signals.cancelled);
        if !signals.ready && !(cancellable && signals.cancelled) {
            if let Some(sender) = self.before_block.lock().unwrap().take() {
                sender.send(()).unwrap();
            }
        }
        if let Some(timeout) = timeout_ms {
            let (_signals, result) = self
                .changed
                .wait_timeout_while(signals, Duration::from_millis(timeout), pending)
                .unwrap();
            if result.timed_out() {
                return Err(Status::Timeout);
            }
        } else {
            drop(self.changed.wait_while(signals, pending).unwrap());
        }
        Ok(())
    }
}

pub(super) fn timestamp_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

fn pause_before_wait<T>(queue: &IOQueue<T>) -> (Receiver<()>, SyncSender<()>) {
    let (entered, entry) = mpsc::channel();
    let (resume, resumed) = mpsc::sync_channel(0);
    *queue.events.before_wait.lock().unwrap() = Some(Box::new(move || {
        entered.send(()).unwrap();
        resumed.recv_timeout(TEST_TIMEOUT).unwrap();
    }));
    (entry, resume)
}

fn notify_before_block<T>(queue: &IOQueue<T>) -> Receiver<()> {
    let (sender, receiver) = mpsc::channel();
    *queue.events.before_block.lock().unwrap() = Some(sender);
    receiver
}

fn reader<T: Send + 'static>(
    queue: &Arc<IOQueue<T>>,
    cancellable: bool,
) -> (Receiver<Result<T, Status>>, JoinHandle<()>) {
    let queue = Arc::clone(queue);
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        let result = if cancellable {
            queue.wait_and_pop_cancellable()
        } else {
            queue.wait_and_pop()
        };
        sender.send(result).unwrap();
    });
    (receiver, thread)
}

#[test]
fn fifo_pops_never_wait_and_signal_only_on_empty_transition() {
    let queue = IOQueue::new();
    assert_eq!(queue.pop(), Err(Status::Timeout));
    for value in 0..100 {
        queue.push(value).unwrap();
    }
    assert_eq!(queue.events.ready_signals.load(Ordering::Relaxed), 1);
    for value in 0..100 {
        assert_eq!(queue.pop(), Ok(value));
    }
    assert_eq!(queue.pop(), Err(Status::Timeout));
    assert!(!queue.events.signals.lock().unwrap().ready);
    queue.push(100).unwrap();
    assert_eq!(queue.events.ready_signals.load(Ordering::Relaxed), 2);
    assert_eq!(queue.pop(), Ok(100));
    assert_eq!(queue.events.waits.load(Ordering::Relaxed), 0);
}

#[test]
fn push_between_empty_check_and_wait_is_not_lost() {
    let queue = Arc::new(IOQueue::new());
    let (entered, resume) = pause_before_wait(&queue);
    let (result, worker) = reader(&queue, true);
    entered.recv_timeout(TEST_TIMEOUT).unwrap();
    queue.push(42).unwrap();
    resume.send(()).unwrap();
    assert_eq!(result.recv_timeout(TEST_TIMEOUT).unwrap(), Ok(42));
    worker.join().unwrap();
    assert_eq!(queue.events.waits.load(Ordering::Relaxed), 1);
    assert_eq!(queue.events.timed_waits.load(Ordering::Relaxed), 0);
}

#[test]
fn cancellation_between_empty_check_and_wait_is_not_lost() {
    let queue = Arc::new(IOQueue::<u32>::new());
    let (entered, resume) = pause_before_wait(&queue);
    let (result, worker) = reader(&queue, true);
    entered.recv_timeout(TEST_TIMEOUT).unwrap();
    queue.cancel_waiters();
    resume.send(()).unwrap();
    assert_eq!(
        result.recv_timeout(TEST_TIMEOUT).unwrap(),
        Err(Status::Cancelled)
    );
    worker.join().unwrap();
    assert_eq!(queue.events.waits.load(Ordering::Relaxed), 1);
}

#[test]
fn idle_read_has_one_untimed_wait_until_cancelled() {
    let queue = Arc::new(IOQueue::<u32>::new());
    let blocked = notify_before_block(&queue);
    let (result, worker) = reader(&queue, true);
    blocked.recv_timeout(TEST_TIMEOUT).unwrap();
    assert!(matches!(
        result.recv_timeout(Duration::from_millis(80)),
        Err(RecvTimeoutError::Timeout)
    ));
    assert_eq!(queue.events.waits.load(Ordering::Relaxed), 1);
    assert_eq!(queue.events.timed_waits.load(Ordering::Relaxed), 0);
    queue.cancel_waiters();
    assert_eq!(
        result.recv_timeout(TEST_TIMEOUT).unwrap(),
        Err(Status::Cancelled)
    );
    worker.join().unwrap();
}

#[test]
fn push_wakes_an_already_blocked_reader() {
    let queue = Arc::new(IOQueue::new());
    let blocked = notify_before_block(&queue);
    let (result, worker) = reader(&queue, true);
    blocked.recv_timeout(TEST_TIMEOUT).unwrap();
    queue.push(7).unwrap();
    assert_eq!(result.recv_timeout(TEST_TIMEOUT).unwrap(), Ok(7));
    worker.join().unwrap();
}

#[test]
fn cancellation_preserves_records_and_reset_reopens_reads() {
    let queue = IOQueue::new();
    queue.push(1).unwrap();
    queue.cancel_waiters();
    queue.cancel_waiters();
    queue.push(2).unwrap();
    assert_eq!(queue.wait_and_pop_cancellable(), Err(Status::Cancelled));
    // Noncancellable pops still work during cancellation.
    assert_eq!(queue.pop(), Ok(1));
    queue.reset_cancellation();
    assert_eq!(queue.wait_and_pop_cancellable(), Ok(2));
    assert_eq!(queue.pop(), Err(Status::Timeout));
}

#[test]
fn reset_after_draining_cancelled_reader_allows_another_wait() {
    let queue = Arc::new(IOQueue::new());
    for value in 0..32 {
        let blocked = notify_before_block(&queue);
        let (result, worker) = reader(&queue, true);
        blocked.recv_timeout(TEST_TIMEOUT).unwrap();
        queue.cancel_waiters();
        assert_eq!(
            result.recv_timeout(TEST_TIMEOUT).unwrap(),
            Err(Status::Cancelled)
        );
        worker.join().unwrap();
        queue.reset_cancellation();
        queue.push(value).unwrap();
        assert_eq!(queue.wait_and_pop_cancellable(), Ok(value));
    }
}

#[test]
fn cancellation_does_not_wake_a_noncancellable_wait_into_a_loop() {
    let queue = Arc::new(IOQueue::new());
    let blocked = notify_before_block(&queue);
    let (result, worker) = reader(&queue, false);
    blocked.recv_timeout(TEST_TIMEOUT).unwrap();
    queue.cancel_waiters();
    assert!(matches!(
        result.recv_timeout(Duration::from_millis(30)),
        Err(RecvTimeoutError::Timeout)
    ));
    assert_eq!(queue.events.waits.load(Ordering::Relaxed), 1);
    queue.push(9).unwrap();
    assert_eq!(result.recv_timeout(TEST_TIMEOUT).unwrap(), Ok(9));
    worker.join().unwrap();
}

#[test]
fn rundown_wakes_both_kinds_of_reader_and_rejects_pushes() {
    for cancellable in [false, true] {
        let queue = Arc::new(IOQueue::<u32>::new());
        let blocked = notify_before_block(&queue);
        let (result, worker) = reader(&queue, cancellable);
        blocked.recv_timeout(TEST_TIMEOUT).unwrap();
        queue.rundown();
        let expected = if cancellable {
            Status::Cancelled
        } else {
            Status::Uninitialized
        };
        assert_eq!(result.recv_timeout(TEST_TIMEOUT).unwrap(), Err(expected));
        worker.join().unwrap();
        assert_eq!(queue.push(1), Err(Status::Uninitialized));
        queue.rundown();
    }
}

#[test]
fn explicit_timeout_still_works_without_affecting_immediate_pops() {
    let queue = IOQueue::<u32>::new();
    assert_eq!(queue.pop_timeout(5), Err(Status::Timeout));
    assert_eq!(queue.events.timed_waits.load(Ordering::Relaxed), 1);
    assert_eq!(queue.pop(), Err(Status::Timeout));
    assert_eq!(queue.events.waits.load(Ordering::Relaxed), 1);
}

struct DropProbe(Arc<AtomicUsize>);

impl Drop for DropProbe {
    fn drop(&mut self) {
        assert_eq!(
            LOCK_DEPTH.with(Cell::get),
            0,
            "record dropped under queue lock"
        );
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn rejected_consumed_and_drained_values_drop_outside_lock() {
    let drops = Arc::new(AtomicUsize::new(0));
    let queue = IOQueue::new();
    for _ in 0..3 {
        queue.push(DropProbe(Arc::clone(&drops))).unwrap();
    }
    drop(queue.pop().unwrap());
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    queue.rundown();
    assert_eq!(drops.load(Ordering::Relaxed), 3);
    assert_eq!(
        queue.push(DropProbe(Arc::clone(&drops))),
        Err(Status::Uninitialized)
    );
    assert_eq!(drops.load(Ordering::Relaxed), 4);
    drop(queue);
    assert_eq!(drops.load(Ordering::Relaxed), 4);
}

#[test]
fn concurrent_push_and_rundown_reclaim_every_value_once() {
    for _ in 0..16 {
        let queue = Arc::new(IOQueue::new());
        let drops = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(5));
        let mut workers = Vec::new();
        for _ in 0..4 {
            let queue = Arc::clone(&queue);
            let drops = Arc::clone(&drops);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..500 {
                    let _ = queue.push(DropProbe(Arc::clone(&drops)));
                }
            }));
        }
        barrier.wait();
        queue.rundown();
        for worker in workers {
            worker.join().unwrap();
        }
        drop(queue);
        assert_eq!(drops.load(Ordering::Relaxed), 2000);
    }
}

#[test]
fn concurrent_producers_and_consumers_deliver_each_record_once() {
    const COUNT: usize = 4000;
    let queue = Arc::new(IOQueue::new());
    let mut consumers = Vec::new();
    for _ in 0..4 {
        let queue = Arc::clone(&queue);
        consumers.push(thread::spawn(move || {
            (0..COUNT / 4)
                .map(|_| queue.wait_and_pop().unwrap())
                .collect::<Vec<_>>()
        }));
    }
    let mut producers = Vec::new();
    for producer in 0..4 {
        let queue = Arc::clone(&queue);
        producers.push(thread::spawn(move || {
            for value in (producer..COUNT).step_by(4) {
                queue.push(value).unwrap();
            }
        }));
    }
    for producer in producers {
        producer.join().unwrap();
    }
    let mut received = Vec::new();
    for consumer in consumers {
        received.extend(consumer.join().unwrap());
    }
    received.sort_unstable();
    assert_eq!(received, (0..COUNT).collect::<Vec<_>>());
    assert_eq!(queue.pop(), Err(Status::Timeout));
}
