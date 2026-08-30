use alloc::boxed::Box;
use core::{
    cell::UnsafeCell,
    fmt,
    marker::PhantomData,
    mem::{ManuallyDrop, MaybeUninit},
    ops::{Deref, DerefMut},
};

use windows_sys::{
    Wdk::{
        Foundation::ERESOURCE,
        System::SystemServices::{
            ExDeleteResourceLite, ExEnterCriticalRegionAndAcquireResourceExclusive,
            ExInitializeResourceLite, ExReleaseResourceAndLeaveCriticalRegion, KeGetCurrentIrql,
            PASSIVE_LEVEL,
        },
    },
    Win32::Foundation::{NTSTATUS, STATUS_SUCCESS},
};

/// Error returned when a passive-level mutex cannot be used by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassiveMutexError {
    /// The executive resource could not be initialized.
    InitializationFailed(NTSTATUS),
    /// The caller is not running at PASSIVE_LEVEL.
    WrongIrql(u8),
}

impl fmt::Display for PassiveMutexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitializationFailed(status) => {
                write!(f, "failed to initialize passive mutex: {status:#x}")
            }
            Self::WrongIrql(irql) => {
                write!(
                    f,
                    "passive mutex used at IRQL {irql}, expected PASSIVE_LEVEL"
                )
            }
        }
    }
}

/// An exclusive mutex for state that may call APIs restricted to PASSIVE_LEVEL.
///
/// Unlike a spin lock, an executive resource does not raise the current IRQL
/// while it is held. `lock` still requires the caller to already be at
/// PASSIVE_LEVEL because the protected operation is allowed to wait and may
/// call PASSIVE_LEVEL-only kernel APIs.
pub struct PassiveMutex<T> {
    value: UnsafeCell<ManuallyDrop<T>>,
    // ERESOURCE must remain at a stable address for its entire initialized
    // lifetime. Keeping it in a nonpaged Box prevents moving the initialized
    // kernel object when this wrapper itself is moved. UnsafeCell documents
    // that the kernel mutates the resource through shared wrapper references.
    resource: Box<UnsafeCell<ERESOURCE>>,
    initialized: bool,
}

impl<T> PassiveMutex<T> {
    /// Creates and initializes a passive-level mutex containing `value`.
    pub fn new(value: T) -> Result<Self, PassiveMutexError> {
        let resource = Box::new(UnsafeCell::new(unsafe {
            MaybeUninit::zeroed().assume_init()
        }));
        let mut mutex = Self {
            value: UnsafeCell::new(ManuallyDrop::new(value)),
            resource,
            initialized: false,
        };

        let status = unsafe { ExInitializeResourceLite(mutex.resource_ptr()) };
        if status != STATUS_SUCCESS {
            return Err(PassiveMutexError::InitializationFailed(status));
        }

        mutex.initialized = true;
        Ok(mutex)
    }

    #[inline]
    fn resource_ptr(&self) -> *mut ERESOURCE {
        self.resource.get()
    }

    /// Acquires the mutex without changing the caller's IRQL.
    pub fn lock(&self) -> Result<PassiveMutexGuard<'_, T>, PassiveMutexError> {
        let irql = unsafe { KeGetCurrentIrql() };
        if irql != PASSIVE_LEVEL as u8 {
            return Err(PassiveMutexError::WrongIrql(irql));
        }

        debug_assert!(self.initialized);
        unsafe {
            ExEnterCriticalRegionAndAcquireResourceExclusive(self.resource_ptr());
        }

        Ok(PassiveMutexGuard {
            mutex: self,
            // An executive resource is owned by the acquiring thread. Do not
            // allow its guard to move to another thread.
            _not_send: PhantomData,
        })
    }
}

impl<T> Drop for PassiveMutex<T> {
    fn drop(&mut self) {
        // Drop the protected value while the resource is still initialized. The
        // Device is destroyed at PASSIVE_LEVEL during DriverUnload, which is the
        // required context for FilterEngine's WFP management teardown.
        unsafe {
            ManuallyDrop::drop(&mut *self.value.get());
            if self.initialized {
                _ = ExDeleteResourceLite(self.resource_ptr());
            }
        }
    }
}

unsafe impl<T: Send> Sync for PassiveMutex<T> {}
unsafe impl<T: Send> Send for PassiveMutex<T> {}

/// Guard returned by [`PassiveMutex::lock`].
pub struct PassiveMutexGuard<'a, T> {
    mutex: &'a PassiveMutex<T>,
    _not_send: PhantomData<*mut T>,
}

impl<T> Deref for PassiveMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // ManuallyDrop<T> is repr(transparent), so its address is the address of
        // the contained T. The resource excludes all mutable access here.
        unsafe { &*(self.mutex.value.get() as *const T) }
    }
}

impl<T> DerefMut for PassiveMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *(self.mutex.value.get() as *mut T) }
    }
}

impl<T> Drop for PassiveMutexGuard<'_, T> {
    fn drop(&mut self) {
        unsafe {
            ExReleaseResourceAndLeaveCriticalRegion(self.mutex.resource_ptr());
        }
    }
}
