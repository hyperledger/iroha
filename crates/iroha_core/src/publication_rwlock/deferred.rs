//! Borrowed physical access with notification custody in an enclosing owner.

use super::*;

/// Coalesces releases from this exact lock after enclosing guards have dropped.
pub(crate) struct DeferredPublicationRwLock<'lock, T> {
    lock: &'lock PublicationRwLock<T>,
    releases: DeferredReleaseBatch,
}

impl<T> PublicationRwLock<T> {
    /// Retain all releases through the lifetime of this enclosing owner.
    pub(crate) fn defer_notifications(&self) -> DeferredPublicationRwLock<'_, T> {
        DeferredPublicationRwLock {
            lock: self,
            releases: self.deferred_releases(),
        }
    }
}

impl<'lock, T> DeferredPublicationRwLock<'lock, T> {
    /// End access while retaining this original source through an enclosing State swap.
    pub(crate) fn into_releases(self) -> DeferredReleaseBatch {
        self.releases
    }

    /// Acquire the original reader without delivering its release on guard Drop.
    pub(crate) fn read(&mut self) -> DeferredReadGuard<'_, 'lock, T> {
        DeferredReadGuard {
            guard: Some(self.lock.read()),
            releases: &mut self.releases,
        }
    }

    /// Probe the original reader while keeping all actual unlocks with this owner.
    pub(crate) fn try_read_or_wait(
        &mut self,
    ) -> Result<DeferredReadGuard<'_, 'lock, T>, ReleaseWait> {
        Ok(DeferredReadGuard {
            guard: Some(self.lock.try_read_or_wait()?),
            releases: &mut self.releases,
        })
    }

    /// Acquire the original writer without delivering its release on guard Drop.
    pub(crate) fn write(&mut self) -> DeferredWriteGuard<'_, 'lock, T> {
        DeferredWriteGuard {
            guard: Some(self.lock.write()),
            releases: &mut self.releases,
        }
    }
}

macro_rules! deferred_guard {
    ($name:ident, $original:ident) => {
        /// Physically unlocks on Drop; the original notification stays outside.
        pub(crate) struct $name<'scope, 'lock, T> {
            guard: Option<$original<'lock, T>>,
            releases: &'scope mut DeferredReleaseBatch,
        }

        impl<T> std::ops::Deref for $name<'_, '_, T> {
            type Target = T;
            fn deref(&self) -> &T {
                self.guard
                    .as_deref()
                    .expect("original deferred index guard")
            }
        }

        impl<T> Drop for $name<'_, '_, T> {
            fn drop(&mut self) {
                if let Some(guard) = self.guard.take() {
                    assert!(
                        guard.try_release_into(self.releases).is_ok(),
                        "original deferred index source"
                    );
                }
            }
        }
    };
}
deferred_guard!(DeferredReadGuard, PublicationRwLockReadGuard);
deferred_guard!(DeferredWriteGuard, PublicationRwLockWriteGuard);

impl<T> std::ops::DerefMut for DeferredWriteGuard<'_, '_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.guard
            .as_deref_mut()
            .expect("original deferred index guard")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::{Context, Wake, Waker},
    };

    struct Probe {
        index: Arc<PublicationRwLock<u64>>,
        outer: Arc<parking_lot::Mutex<()>>,
        calls: AtomicUsize,
        blocked: AtomicBool,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.blocked.store(
                self.index.try_write().is_none() || self.outer.try_lock().is_none(),
                Ordering::SeqCst,
            );
        }
    }

    #[test]
    fn enclosing_owner_coalesces_read_write_and_unwind_after_outer_unlock() {
        let observer_budget = iroha_allocation::AllocationBudget::new(
            iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
        );
        let mut registration = crate::unit_test_support::release_registration(&observer_budget);
        for unwind in [false, true] {
            let index = Arc::new(PublicationRwLock::new(1_u64));
            let outer = Arc::new(parking_lot::Mutex::new(()));
            let probe = Arc::new(Probe {
                index: Arc::clone(&index),
                outer: Arc::clone(&outer),
                calls: AtomicUsize::new(0),
                blocked: AtomicBool::new(false),
            });
            let waker = Waker::from(Arc::clone(&probe));
            let mut context = Context::from_waker(&waker);
            let mut pending = None;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut releases = index.defer_notifications();
                let _outer = outer.lock();
                let reader = releases.read();
                let wait = index
                    .try_write_or_wait()
                    .expect_err("actual reader blocks writer");
                let future = wait;
                assert!(registration.poll_wait(&future, &mut context).is_pending());
                pending = Some(future);
                assert_eq!(*reader, 1);
                drop(reader);
                let mut writer = releases.write();
                *writer += 1;
                assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
                assert!(!unwind, "unwind through the held original writer");
                drop(writer);
                assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
            }));
            assert_eq!(result.is_err(), unwind);
            assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
            assert!(!probe.blocked.load(Ordering::SeqCst));
            assert!(
                registration
                    .poll_wait(pending.as_ref().unwrap(), &mut context)
                    .is_ready()
            );
            assert_eq!(*index.read(), 2);
        }
    }
}
