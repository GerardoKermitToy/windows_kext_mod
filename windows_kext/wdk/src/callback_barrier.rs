//! Coordinates WFP callback admission with driver teardown.
//!
//! The WFP filter engine can invoke a classify callback concurrently with
//! `DriverUnload`.  A raw `AtomicPtr<Device>` only publishes the pointer; it
//! does not keep the allocation alive after a callback has loaded it.  Use the
//! kernel's rundown protection to make callback admission and destruction a
//! single lifetime protocol.

use core::{
    cell::UnsafeCell,
    marker::PhantomData,
    sync::atomic::{AtomicU8, Ordering},
};

use windows_sys::Wdk::System::SystemServices::{
    ExAcquireRundownProtection, ExInitializeRundownProtection, ExReInitializeRundownProtection,
    ExReleaseRundownProtection, ExRundownCompleted, ExWaitForRundownProtectionRelease,
    EX_RUNDOWN_REF, EX_RUNDOWN_REF_0,
};

const NEVER_STARTED: u8 = 0;
const OPEN: u8 = 1;
const CLASSIFY_CLOSING: u8 = 2;
const CLASSIFY_CLOSED: u8 = 3;
const DRAINING: u8 = 4;
const CLOSED: u8 = 5;
const STARTING: u8 = 6;

/// A callback lifetime barrier for the singleton driver instance.
///
/// Classify callbacks and flow-delete callbacks have separate rundown
/// references because unload must stop new classify work before removing the
/// flow contexts that cause `flowDeleteFn` to run.  Both references are still
/// part of one barrier and must be drained before `Device` is destroyed.
pub struct CallbackBarrier {
    classify: UnsafeCell<EX_RUNDOWN_REF>,
    flow_delete: UnsafeCell<EX_RUNDOWN_REF>,
    state: AtomicU8,
}

// The EX_RUNDOWN_REF values are accessed only through the interlocked kernel
// rundown APIs.  The lifecycle state transitions are serialized by the driver
// entry/unload path; callback admission is safe from any CPU at <= DISPATCH_LEVEL.
unsafe impl Sync for CallbackBarrier {}

impl CallbackBarrier {
    const fn empty_rundown_ref() -> EX_RUNDOWN_REF {
        EX_RUNDOWN_REF {
            Anonymous: EX_RUNDOWN_REF_0 { Count: 0 },
        }
    }

    const fn new() -> Self {
        Self {
            classify: UnsafeCell::new(Self::empty_rundown_ref()),
            flow_delete: UnsafeCell::new(Self::empty_rundown_ref()),
            state: AtomicU8::new(NEVER_STARTED),
        }
    }

    /// Initializes or reinitializes the barrier for a new driver instance.
    ///
    /// A reinitialization is allowed only after the previous instance has
    /// completed `close_all_and_wait`.  The short STARTING transition
    /// serializes concurrent lifecycle callers; a caller that observes an
    /// already-open or still-draining instance returns false.
    pub fn start(&self) -> bool {
        loop {
            let state = self.state.load(Ordering::Acquire);
            match state {
                NEVER_STARTED | CLOSED => {}
                STARTING => {
                    core::hint::spin_loop();
                    continue;
                }
                OPEN | CLASSIFY_CLOSED | DRAINING => return false,
                _ => return false,
            }

            if self
                .state
                .compare_exchange(state, STARTING, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }

            unsafe {
                if state == NEVER_STARTED {
                    ExInitializeRundownProtection(self.classify.get());
                    ExInitializeRundownProtection(self.flow_delete.get());
                } else {
                    // The previous close path waits for both references before
                    // publishing CLOSED, which is the prerequisite for this API.
                    ExReInitializeRundownProtection(self.classify.get());
                    ExReInitializeRundownProtection(self.flow_delete.get());
                }
            }
            self.state.store(OPEN, Ordering::Release);
            return true;
        }
    }

    /// Admits a classify callback, or returns `None` after classify admission
    /// has been closed.  This must be the first operation in the WFP classify
    /// trampoline, before reading filter or callout memory owned by `Device`.
    pub fn enter_classify(&self) -> Option<CallbackGuard<'_>> {
        if self.state.load(Ordering::Acquire) != OPEN {
            return None;
        }
        self.acquire(self.classify.get())
    }

    /// Admits a flow-delete callback.  Flow-delete admission remains open while
    /// unload removes WFP flow contexts, even after classify admission closes.
    pub fn enter_flow_delete(&self) -> Option<CallbackGuard<'_>> {
        match self.state.load(Ordering::Acquire) {
            OPEN | CLASSIFY_CLOSING | CLASSIFY_CLOSED => self.acquire(self.flow_delete.get()),
            _ => None,
        }
    }

    fn acquire(&self, rundown: *mut EX_RUNDOWN_REF) -> Option<CallbackGuard<'_>> {
        let acquired = unsafe { ExAcquireRundownProtection(rundown) } != 0;
        acquired.then_some(CallbackGuard {
            rundown,
            _barrier: PhantomData,
        })
    }

    /// Closes classify admission and waits for every classify callback that
    /// already passed the admission point.  Flow-delete callbacks remain
    /// admissible until `close_all_and_wait` is called.
    ///
    /// The caller must be at PASSIVE_LEVEL because rundown waits can block.
    pub fn close_classify_and_wait(&self) {
        loop {
            match self.state.load(Ordering::Acquire) {
                OPEN => {
                    if self
                        .state
                        .compare_exchange(
                            OPEN,
                            CLASSIFY_CLOSING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_err()
                    {
                        continue;
                    }

                    unsafe {
                        ExRundownCompleted(self.classify.get());
                        ExWaitForRundownProtectionRelease(self.classify.get());
                    }
                    self.state.store(CLASSIFY_CLOSED, Ordering::Release);
                    return;
                }
                STARTING | CLASSIFY_CLOSING | DRAINING => core::hint::spin_loop(),
                // CLASSIFY_CLOSED means this method already completed the
                // classify wait.  CLOSED/NEVER_STARTED need no work.
                CLASSIFY_CLOSED | CLOSED | NEVER_STARTED => return,
                _ => return,
            }
        }
    }

    /// Closes both callback classes and waits until no callback can still
    /// access the current `Device`.  The barrier is left in CLOSED state and
    /// can be reused only through `start` for the next driver instance.
    ///
    /// The caller must be at PASSIVE_LEVEL.
    pub fn close_all_and_wait(&self) {
        let previous = loop {
            let state = self.state.load(Ordering::Acquire);
            match state {
                OPEN | CLASSIFY_CLOSED => {
                    if self
                        .state
                        .compare_exchange(state, DRAINING, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        break state;
                    }
                }
                STARTING | CLASSIFY_CLOSING | DRAINING => {
                    // A concurrent lifecycle caller is completing the
                    // transition.  Do not return until it has published a
                    // fully drained state; returning early would let the
                    // Device be destroyed while a callback is still active.
                    core::hint::spin_loop();
                }
                NEVER_STARTED | CLOSED => return,
                _ => return,
            }
        };

        unsafe {
            // If classify was still open, it has not been completed yet.  When
            // it was already closed by close_classify_and_wait, completing it
            // again would violate the rundown API contract.
            if previous == OPEN {
                ExRundownCompleted(self.classify.get());
            }
            ExRundownCompleted(self.flow_delete.get());

            if previous == OPEN {
                ExWaitForRundownProtectionRelease(self.classify.get());
            }
            ExWaitForRundownProtectionRelease(self.flow_delete.get());
        }
        self.state.store(CLOSED, Ordering::Release);
    }
}

/// A reference held from callback admission through callback return.
pub struct CallbackGuard<'a> {
    rundown: *mut EX_RUNDOWN_REF,
    _barrier: PhantomData<&'a CallbackBarrier>,
}

impl Drop for CallbackGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            ExReleaseRundownProtection(self.rundown);
        }
    }
}

/// The WFP callback barrier for the one `Device` owned by this driver image.
pub static CALLBACK_BARRIER: CallbackBarrier = CallbackBarrier::new();
