//! Original reader/writer lock custody and release-driven publication retries.
//!
//! Every acquired reader and writer retains the notification belonging to its
//! physical lock. A release is a retry hint, not a reservation: another reader
//! or writer may still hold the lock. Enclosing publication owners must retain
//! deferred notifications until their other physical guards have released.

use iroha_allocation::release::{
    DeferredRelease, DeferredReleaseBatch, ReleaseGuard, ReleaseNotification, ReleaseWait,
};

mod deferred;
pub(crate) use deferred::DeferredPublicationRwLock;

/// A parking-lot reader/writer lock with one original release-notification source.
///
/// Like the underlying lock, this lock does not poison on unwind. Constructing
/// `try_new` admits the notification control from the caller's original pool.
/// Native lock internals and later waiter registrations remain separate owners.
#[derive(Default)]
pub struct PublicationRwLock<T> {
    inner: parking_lot::RwLock<T>,
    released: ReleaseNotification,
}

/// An original shared reader whose notification follows physical unlock.
pub struct PublicationRwLockReadGuard<'lock, T> {
    inner: ReleaseGuard<'lock, parking_lot::RwLockReadGuard<'lock, T>>,
}

/// An original exclusive writer whose notification follows physical unlock.
pub struct PublicationRwLockWriteGuard<'lock, T> {
    inner: ReleaseGuard<'lock, parking_lot::RwLockWriteGuard<'lock, T>>,
}

impl<T> PublicationRwLock<T> {
    /// Observe this lock's actual release without acquiring a guard or allocating.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub(crate) fn observe_release(&self) -> ReleaseWait {
        self.released.observe()
    }

    /// Construct the exact release control from the caller's original finite pool.
    /// Native mutex internals and future waiter registrations are separate owners.
    ///
    /// # Errors
    /// Preserves original credit refusal or the actual failed control allocation.
    pub(crate) fn try_new(
        value: T,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Self, mv::storage::AdmittedStorageError> {
        let layout = ReleaseNotification::allocation_layout::<iroha_allocation::AllocationCharge>();
        let mut reservation = budget
            .try_reserve(layout)
            .map_err(mv::storage::AdmittedStorageError::Allocation)?;
        let charge = reservation
            .try_split(layout)
            .expect("exact original control layout");
        let released =
            ReleaseNotification::try_new_charged(charge).map_err(|(charge, error)| {
                drop(charge);
                mv::storage::AdmittedStorageError::Allocator {
                    layout: error.layout(),
                }
            })?;
        Ok(Self {
            inner: parking_lot::RwLock::new(value),
            released,
        })
    }

    /// Bind the protected value and its release source at construction.
    pub fn new(value: T) -> Self {
        Self {
            inner: parking_lot::RwLock::new(value),
            released: ReleaseNotification::default(),
        }
    }

    /// Access the value through exclusive ownership without acquiring or
    /// releasing a physical guard, and therefore without a release notification.
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }

    /// Acquire shared access using the underlying lock's blocking semantics.
    pub fn read(&self) -> PublicationRwLockReadGuard<'_, T> {
        PublicationRwLockReadGuard {
            inner: self.released.guard(self.inner.read()),
        }
    }

    /// Probe shared access without blocking.
    pub fn try_read(&self) -> Option<PublicationRwLockReadGuard<'_, T>> {
        self.inner
            .try_read()
            .map(|guard| PublicationRwLockReadGuard {
                inner: self.released.guard(guard),
            })
    }

    /// Acquire a reader or retain its exact physical source observed before probing.
    ///
    /// # Errors
    ///
    /// Returns this lock's release observation if shared access is unavailable.
    pub fn try_read_or_wait(&self) -> Result<PublicationRwLockReadGuard<'_, T>, ReleaseWait> {
        let wait = self.released.observe();
        self.try_read().ok_or(wait)
    }

    /// Acquire exclusive access using the underlying lock's blocking semantics.
    pub fn write(&self) -> PublicationRwLockWriteGuard<'_, T> {
        PublicationRwLockWriteGuard {
            inner: self.released.guard(self.inner.write()),
        }
    }

    /// Probe exclusive access without blocking.
    pub fn try_write(&self) -> Option<PublicationRwLockWriteGuard<'_, T>> {
        self.inner
            .try_write()
            .map(|guard| PublicationRwLockWriteGuard {
                inner: self.released.guard(guard),
            })
    }

    /// Acquire a writer or return the original release observation made before
    /// the probe, including a blocking reader's release before first polling.
    ///
    /// Release every earlier aggregate guard before awaiting this event. A wake
    /// requires retrying acquisition and authenticating the original operation.
    ///
    /// # Errors
    ///
    /// Returns this lock's release observation if exclusive access is unavailable.
    pub fn try_write_or_wait(&self) -> Result<PublicationRwLockWriteGuard<'_, T>, ReleaseWait> {
        let wait = self.released.observe();
        self.try_write().ok_or(wait)
    }

    /// Create an empty, allocation-free batch for this exact lock's releases.
    /// Only original guards from this lock can record into the batch.
    pub fn deferred_releases(&self) -> DeferredReleaseBatch {
        self.released.deferred_batch()
    }
}

impl<T> PublicationRwLockReadGuard<'_, T> {
    /// Unlock this reader now and retain its original notification for the
    /// enclosing aggregate to deliver after releasing its other physical guards.
    pub fn release_deferred(self) -> DeferredRelease {
        self.inner.release_deferred(drop).1
    }

    /// Unlock into a batch of this exact source without invoking callbacks.
    /// A foreign batch returns this same held reader without any release.
    ///
    /// # Errors
    ///
    /// Returns the still-held guard when the batch belongs to a different
    /// release source.
    pub fn try_release_into(self, batch: &mut DeferredReleaseBatch) -> Result<(), Self> {
        self.inner
            .try_release_into(batch, drop)
            .map_err(|inner| Self { inner })
    }
}

impl<T> PublicationRwLockWriteGuard<'_, T> {
    /// Unlock this writer now and retain its original notification for the
    /// enclosing aggregate to deliver after releasing its other physical guards.
    pub fn release_deferred(self) -> DeferredRelease {
        self.inner.release_deferred(drop).1
    }

    /// Unlock into a batch of this exact source without invoking callbacks.
    /// A foreign batch returns this same held writer without any release.
    ///
    /// # Errors
    ///
    /// Returns the still-held guard when the batch belongs to a different
    /// release source.
    pub fn try_release_into(self, batch: &mut DeferredReleaseBatch) -> Result<(), Self> {
        self.inner
            .try_release_into(batch, drop)
            .map_err(|inner| Self { inner })
    }
}

impl<T> std::ops::Deref for PublicationRwLockReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T> std::ops::Deref for PublicationRwLockWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T> std::ops::DerefMut for PublicationRwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T> std::fmt::Debug for PublicationRwLock<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Formatting neither acquires the lock nor generates a release event.
        formatter
            .debug_struct("PublicationRwLock")
            .finish_non_exhaustive()
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for PublicationRwLockReadGuard<'_, T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&**self, formatter)
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for PublicationRwLockWriteGuard<'_, T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&**self, formatter)
    }
}

#[cfg(test)]
mod tests;
