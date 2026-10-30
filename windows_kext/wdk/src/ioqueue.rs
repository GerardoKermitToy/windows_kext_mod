use core::{fmt::Display, ptr};

use alloc::boxed::Box;

#[cfg(not(test))]
use crate::rw_spin_lock::RwSpinLock;
#[cfg(not(test))]
use kernel::WaitEvents;
#[cfg(test)]
use tests::{RwSpinLock, WaitEvents};

#[derive(Debug, Eq, PartialEq)]
pub enum Status {
    Uninitialized,
    Timeout,
    UserAPC,
    Abandoned,
    Cancelled,
    InvalidResult,
}

impl Display for Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Status::Uninitialized => write!(f, "Uninitialized"),
            Status::Timeout => write!(f, "Timeout"),
            Status::UserAPC => write!(f, "UserAPC"),
            Status::Abandoned => write!(f, "Abandoned"),
            Status::Cancelled => write!(f, "Cancelled"),
            Status::InvalidResult => write!(f, "InvalidResult"),
        }
    }
}

struct Entry<T> {
    next: *mut Entry<T>,
    value: T,
}

struct State<T> {
    head: *mut Entry<T>,
    tail: *mut Entry<T>,
    initialized: bool,
    cancelled: bool,
}

// The pointers own Box allocations and are accessed only under the queue lock.
unsafe impl<T: Send> Send for State<T> {}

pub struct IOQueue<T> {
    state: RwSpinLock<State<T>>,
    events: WaitEvents,
}

impl<T> IOQueue<T> {
    /// Make sure `rundown` is called on exit, if `drop()` is not called for queue.
    pub fn new() -> Self {
        Self {
            state: RwSpinLock::new(State {
                head: ptr::null_mut(),
                tail: ptr::null_mut(),
                initialized: true,
                cancelled: false,
            }),
            events: WaitEvents::new(),
        }
    }

    /// Pushes new entry of any type.
    pub fn push(&self, value: T) -> Result<(), Status> {
        // Allocate before taking the spin lock; reclaim rejected values outside it.
        let entry = Box::new(Entry {
            next: ptr::null_mut(),
            value,
        });
        let mut state = self.state.write_lock();
        if !state.initialized {
            drop(state);
            return Err(Status::Uninitialized);
        }

        let entry = Box::into_raw(entry);
        if state.head.is_null() {
            state.head = entry;
            state.tail = entry;
            // Signal only on the empty -> nonempty transition. Consumers reset
            // the notification under this same lock, so no wakeup can be lost.
            self.events.set_ready();
        } else {
            // SAFETY: The nonempty FIFO owns tail and the lock excludes consumers.
            unsafe { (*state.tail).next = entry };
            state.tail = entry;
        }
        Ok(())
    }

    /// Cancels current/future cancellable waits and wakes blocked readers immediately.
    /// Other pop methods ignore cancellation. Queued records remain available to
    /// the next owner after `reset_cancellation`.
    pub fn cancel_waiters(&self) {
        let mut state = self.state.write_lock();
        if !state.cancelled {
            state.cancelled = true;
            self.events.set_cancelled();
        }
    }

    /// Clears cancellation after the caller has closed read admission and drained
    /// every previous reader. This method must run at PASSIVE_LEVEL.
    pub fn reset_cancellation(&self) {
        let mut state = self.state.write_lock();
        state.cancelled = false;
        self.events.clear_cancelled();
    }

    fn pop_internal(&self, timeout_ms: Option<i64>, cancellable: bool) -> Result<T, Status> {
        // Only explicitly timed callers read the clock. Idle stream reads pass
        // None and wait indefinitely, without periodic timer wakeups.
        let deadline = timeout_ms
            .filter(|timeout| *timeout > 0)
            .map(|timeout| timestamp_ms().saturating_add(timeout as u64));

        loop {
            let entry = {
                let mut state = self.state.write_lock();
                if cancellable && state.cancelled {
                    return Err(Status::Cancelled);
                }
                if !state.initialized {
                    return Err(Status::Uninitialized);
                }

                let entry = state.head;
                if !entry.is_null() {
                    // SAFETY: The lock exclusively owns this linked-list head.
                    state.head = unsafe { (*entry).next };
                    if state.head.is_null() {
                        state.tail = ptr::null_mut();
                        self.events.clear_ready();
                    }
                }
                entry
            };
            if !entry.is_null() {
                // SAFETY: Unlinking transfers the Box to this consumer. Free it
                // only after the spin lock has restored the caller's IRQL.
                return Ok(unsafe { Box::from_raw(entry) }.value);
            }

            let remaining = match timeout_ms {
                Some(timeout) if timeout <= 0 => return Err(Status::Timeout),
                Some(_) => {
                    let remaining = deadline.unwrap().saturating_sub(timestamp_ms());
                    if remaining == 0 {
                        return Err(Status::Timeout);
                    }
                    Some(remaining)
                }
                None => None,
            };
            // No spin lock is held across this wait. Notification events retain
            // a signal delivered between the empty check and the kernel wait.
            self.events.wait(cancellable, remaining)?;
        }
    }

    /// Waits until an entry is pushed or the queue is run down.
    pub fn wait_and_pop(&self) -> Result<T, Status> {
        self.pop_internal(None, false)
    }

    /// Waits indefinitely for data or cancellation of the owning handle. Cleanup,
    /// rather than `CancelIoEx`, owns the cancellation transition for this
    /// synchronous queue. There is no timeout or periodic cancellation polling.
    pub fn wait_and_pop_cancellable(&self) -> Result<T, Status> {
        self.pop_internal(None, true)
    }

    /// Returns an element immediately, or Timeout if the queue is empty.
    pub fn pop(&self) -> Result<T, Status> {
        self.pop_internal(Some(0), false)
    }

    /// Waits up to the specified number of milliseconds for an entry.
    pub fn pop_timeout(&self, timeout: i64) -> Result<T, Status> {
        self.pop_internal(Some(timeout), false)
    }

    /// Permanently shuts down the queue and frees detached records outside the
    /// spin lock. Callers must drain all readers before dropping the queue itself.
    pub fn rundown(&self) {
        let mut entry = {
            let mut state = self.state.write_lock();
            state.initialized = false;
            state.cancelled = true;
            let head = state.head;
            state.head = ptr::null_mut();
            state.tail = ptr::null_mut();
            // Wake both kinds of waiter, even when the FIFO was already empty.
            self.events.set_cancelled();
            self.events.set_ready();
            head
        };
        while !entry.is_null() {
            // SAFETY: Detachment transfers this entire list to rundown. No
            // producer can append after initialized was cleared under the lock.
            let owned = unsafe { Box::from_raw(entry) };
            entry = owned.next;
            drop(owned);
        }
    }
}

impl<T> Drop for IOQueue<T> {
    fn drop(&mut self) {
        self.rundown();
    }
}

#[cfg(not(test))]
fn timestamp_ms() -> u64 {
    crate::utils::get_monotonic_timestamp_ms()
}

#[cfg(test)]
fn timestamp_ms() -> u64 {
    tests::timestamp_ms()
}

#[cfg(not(test))]
mod kernel {
    use super::Status;
    use alloc::boxed::Box;
    use core::{cell::UnsafeCell, mem::MaybeUninit, ptr};
    use windows_sys::{
        Wdk::{
            Foundation::KEVENT,
            System::SystemServices::{
                Executive, KeClearEvent, KeInitializeEvent, KeSetEvent, KeWaitForMultipleObjects,
                KeWaitForSingleObject,
            },
        },
        Win32::{
            Foundation::{STATUS_ABANDONED, STATUS_SUCCESS, STATUS_TIMEOUT, STATUS_USER_APC},
            System::Kernel::{NotificationEvent, WaitAny},
        },
    };

    #[cfg(target_pointer_width = "64")]
    const _: () = {
        assert!(core::mem::size_of::<KEVENT>() == 24);
        assert!(core::mem::align_of::<KEVENT>() == 8);
    };

    pub(super) struct WaitEvents {
        // The global kernel allocator provides resident nonpaged storage. Box
        // keeps both dispatcher objects at stable addresses for their lifetimes.
        events: Box<UnsafeCell<[KEVENT; 2]>>,
    }

    // Only the interlocked kernel event APIs access the resident objects.
    unsafe impl Send for WaitEvents {}
    unsafe impl Sync for WaitEvents {}

    impl WaitEvents {
        pub(super) fn new() -> Self {
            // SAFETY: KEVENT backing bytes are initialized by KeInitializeEvent
            // at their final addresses before any signal or wait can access them.
            let events = Box::new(UnsafeCell::new(unsafe {
                MaybeUninit::<[KEVENT; 2]>::zeroed().assume_init()
            }));
            unsafe {
                KeInitializeEvent(events.get().cast::<KEVENT>(), NotificationEvent, 0);
                KeInitializeEvent(events.get().cast::<KEVENT>().add(1), NotificationEvent, 0);
            }
            Self { events }
        }

        fn ready(&self) -> *mut KEVENT {
            self.events.get().cast::<KEVENT>()
        }

        fn cancelled(&self) -> *mut KEVENT {
            // SAFETY: The resident allocation contains exactly two KEVENTs.
            unsafe { self.ready().add(1) }
        }

        pub(super) fn set_ready(&self) {
            // Wait=FALSE is required while the queue's spin lock is held.
            unsafe { KeSetEvent(self.ready(), 0, 0) };
        }

        pub(super) fn clear_ready(&self) {
            unsafe { KeClearEvent(self.ready()) };
        }

        pub(super) fn set_cancelled(&self) {
            unsafe { KeSetEvent(self.cancelled(), 0, 0) };
        }

        pub(super) fn clear_cancelled(&self) {
            unsafe { KeClearEvent(self.cancelled()) };
        }

        pub(super) fn wait(
            &self,
            cancellable: bool,
            timeout_ms: Option<u64>,
        ) -> Result<(), Status> {
            let timeout =
                timeout_ms.map(|ms| (ms.min(i64::MAX as u64) as i64).saturating_mul(-10_000));
            let timeout = timeout.as_ref().map_or(ptr::null(), ptr::from_ref);
            // SAFETY: Both objects remain resident through the wait. There are
            // only two objects (<= THREAD_WAIT_OBJECTS), so the thread's builtin
            // wait blocks suffice. Wait in KernelMode, non-alertably, with no
            // timeout for normal stream reads and no queue spin lock held.
            let status = unsafe {
                if cancellable {
                    let objects = [
                        self.ready().cast_const().cast(),
                        self.cancelled().cast_const().cast(),
                    ];
                    KeWaitForMultipleObjects(
                        objects.len() as u32,
                        objects.as_ptr(),
                        WaitAny,
                        Executive,
                        0,
                        0,
                        timeout,
                        ptr::null_mut(),
                    )
                } else {
                    KeWaitForSingleObject(self.ready().cast(), Executive, 0, 0, timeout)
                }
            };
            match status {
                // Recheck queue/cancellation under the queue lock after either signal.
                STATUS_SUCCESS | 1 => Ok(()),
                STATUS_TIMEOUT => Err(Status::Timeout),
                STATUS_USER_APC => Err(Status::UserAPC),
                STATUS_ABANDONED => Err(Status::Abandoned),
                _ => Err(Status::InvalidResult),
            }
        }
    }
}

#[cfg(test)]
#[path = "ioqueue_tests.rs"]
mod tests;
