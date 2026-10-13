//! Actual storage mutex custody with release-driven local publication retries.
//!
//! The physical mutex and its notification travel together through replay swaps
//! and shared commit-lock Arcs. No raw mutex or synthetic notification escapes.

/// A physical storage fence which notifies only after its actual guard releases.
/// Parking-lot mutexes do not poison; unwind remains an ordinary release.
#[derive(Default)]
pub(crate) struct PublicationMutex<T = ()> {
    inner: parking_lot::Mutex<T>,
    released: iroha_allocation::release::ReleaseNotification,
    /// Successful ordinary acquisitions invalidate earlier readonly observations.
    mutation_epoch: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
}

/// Move-only permission for audited nonmutating uses of one original unit fence.
///
/// Only the paired constructor can create this capability. The shared epoch
/// allocation identifies the exact original mutex even if its value moves.
/// No caller-supplied path, pointer, or generation can manufacture the binding.
#[derive(Debug)]
pub(crate) struct PublicationReadPermit {
    original_epoch: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

/// A read permit belongs to a different original physical fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublicationReadPermitMismatch;

/// An original storage mutex guard, retaining the established lock-order boundary.
pub(crate) struct PublicationGuard<'state, T = ()> {
    inner: iroha_allocation::release::ReleaseGuard<'state, PhysicalPublicationGuard<'state, T>>,
    mutation_epoch: Option<u64>,
}

/// Original physical guard whose unlock policy is selected before its release.
struct PhysicalPublicationGuard<'state, T> {
    guard: Option<parking_lot::MutexGuard<'state, T>>,
    fair: bool,
}

impl<T> Drop for PhysicalPublicationGuard<'_, T> {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            if self.fair {
                parking_lot::MutexGuard::unlock_fair(guard);
            } else {
                drop(guard);
            }
        }
    }
}

impl<T> PublicationGuard<'_, T> {
    /// Mutation epoch captured under this original physical guard; exhaustion
    /// permanently refuses observation reuse.
    pub(crate) fn mutation_epoch(&self) -> Option<u64> {
        self.mutation_epoch
    }

    /// Unlock this original mutex into its exact source's retained release batch.
    /// A foreign batch returns the original guard without unlocking or notifying.
    pub(crate) fn try_release_into(
        self,
        batch: &mut iroha_allocation::release::DeferredReleaseBatch,
    ) -> Result<(), Self> {
        let mutation_epoch = self.mutation_epoch;
        self.inner
            .try_release_into(batch, drop)
            .map_err(|inner| Self {
                inner,
                mutation_epoch,
            })
    }

    /// Unlock the actual mutex and retain its original notification until the
    /// enclosing aggregate has released every other physical fence.
    pub(crate) fn release_deferred(self) -> iroha_allocation::release::DeferredRelease {
        self.inner.release_deferred(drop).1
    }

    /// Exercise fair physical unlock in release-custody regression tests.
    /// The shared release guard signals only after the physical unlock completes.
    #[cfg(test)]
    pub(crate) fn unlock_fair(mut self) {
        self.inner.fair = true;
        drop(self);
    }
}

impl<T> std::ops::Deref for PublicationGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.inner
            .guard
            .as_deref()
            .expect("retained physical guard")
    }
}

impl<T> std::ops::DerefMut for PublicationGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.inner
            .guard
            .as_deref_mut()
            .expect("retained physical guard")
    }
}

impl<T> PublicationMutex<T> {
    /// Construct this original fence's notification from the caller's finite pool.
    /// Native mutex internals and future waiter registrations remain separate owners.
    pub(crate) fn try_new(
        value: T,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Self, mv::storage::AdmittedStorageError> {
        let layout = iroha_allocation::release::ReleaseNotification::allocation_layout::<
            iroha_allocation::AllocationCharge,
        >();
        let mut reservation = budget
            .try_reserve(layout)
            .map_err(mv::storage::AdmittedStorageError::Allocation)?;
        let charge = reservation
            .try_split(layout)
            .expect("exact original fence control layout");
        let released = iroha_allocation::release::ReleaseNotification::try_new_charged(charge)
            .map_err(|(charge, error)| {
                drop(charge);
                mv::storage::AdmittedStorageError::Allocator {
                    layout: error.layout(),
                }
            })?;
        Ok(Self {
            inner: parking_lot::Mutex::new(value),
            released,
            mutation_epoch: None,
        })
    }

    /// Observe this actual fence before sampling state published beneath it.
    /// A release is only a retry hint and grants no read or publication authority.
    pub(crate) fn observe_release(&self) -> iroha_allocation::release::ReleaseWait {
        self.released.observe()
    }

    /// An empty, allocation-free release batch bound to this actual mutex.
    pub(crate) fn deferred_releases(&self) -> iroha_allocation::release::DeferredReleaseBatch {
        self.released.deferred_batch()
    }

    /// Bind the original protected value and its release observation at creation.
    pub(crate) fn new(value: T) -> Self {
        Self {
            inner: parking_lot::Mutex::new(value),
            released: iroha_allocation::release::ReleaseNotification::default(),
            mutation_epoch: None,
        }
    }

    /// Bind notification to the acquired physical owner without exposing it.
    fn wrap<'state>(
        &'state self,
        guard: parking_lot::MutexGuard<'state, T>,
    ) -> PublicationGuard<'state, T> {
        // Advance while the actual physical mutex is held, before any caller
        // can create/rename/unlink or unwind. Saturation permanently disables
        // observation reuse instead of allowing an ABA wraparound.
        if let Some(epoch) = &self.mutation_epoch {
            let _ = epoch.fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |epoch| epoch.checked_add(1),
            );
        }
        self.wrap_read_only(guard)
    }

    fn wrap_read_only<'state>(
        &'state self,
        guard: parking_lot::MutexGuard<'state, T>,
    ) -> PublicationGuard<'state, T> {
        let epoch = self.mutation_epoch.as_ref().and_then(|epoch| {
            let epoch = epoch.load(std::sync::atomic::Ordering::Relaxed);
            (epoch != u64::MAX).then_some(epoch)
        });
        PublicationGuard {
            mutation_epoch: epoch,
            inner: self.released.guard(PhysicalPublicationGuard {
                guard: Some(guard),
                fair: false,
            }),
        }
    }

    /// Acquire the existing physical fence for its original synchronous caller.
    pub(crate) fn lock(&self) -> PublicationGuard<'_, T> {
        self.wrap(self.inner.lock())
    }

    /// Probe the physical fence without waiting or retaining a retry observation.
    pub(crate) fn try_lock(&self) -> Option<PublicationGuard<'_, T>> {
        self.inner.try_lock().map(|guard| self.wrap(guard))
    }

    /// Acquire the exact fence or return its pre-probe release observation.
    ///
    /// The aggregate publisher must release every earlier acquired fence before
    /// awaiting this event. A wake grants no predecessor or publication authority;
    /// retry must re-acquire the same target and rejoin its original journals.
    /// No publication, height change, timer, or scheduled polling is required.
    pub(crate) fn try_lock_or_wait(
        &self,
    ) -> Result<PublicationGuard<'_, T>, iroha_allocation::release::ReleaseWait> {
        let wait = self.released.observe();
        self.try_lock().ok_or(wait)
    }
}

impl PublicationMutex {
    /// Create one unit fence and its original, uncloneable read capability.
    ///
    /// The owner must keep the permit private and lend it only to complete
    /// paths audited for absence of namespace mutation or mutable callbacks.
    /// Ordinary `new` and `default` constructors do not issue a read permit.
    pub(crate) fn with_read_permit() -> (Self, PublicationReadPermit) {
        let original_epoch = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut mutex = Self::new(());
        mutex.mutation_epoch = Some(std::sync::Arc::clone(&original_epoch));
        let permit = PublicationReadPermit { original_epoch };
        (mutex, permit)
    }

    /// Retain the same physical fence without invalidating prior namespace
    /// observations, using only its originally paired read capability.
    /// This remains an exclusive physical acquisition, not a shared read lock.
    /// A foreign permit fails before acquiring or observing the target mutex.
    pub(crate) fn lock_read_only(
        &self,
        permit: &PublicationReadPermit,
    ) -> Result<PublicationGuard<'_>, PublicationReadPermitMismatch> {
        if !self
            .mutation_epoch
            .as_ref()
            .is_some_and(|epoch| std::sync::Arc::ptr_eq(epoch, &permit.original_epoch))
        {
            return Err(PublicationReadPermitMismatch);
        }
        Ok(self.wrap_read_only(self.inner.lock()))
    }
}

impl<T> std::fmt::Debug for PublicationMutex<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublicationMutex")
            .finish_non_exhaustive()
    }
}

/// Same-source release custody, retained outside the complete State owner.
/// Each short physical lock borrows this owner and records its release on Drop.
/// The batch never accepts a caller-selected notification source.
pub(crate) struct DeferredPublicationFence<'state, T> {
    mutex: &'state PublicationMutex<T>,
    releases: iroha_allocation::release::DeferredReleaseBatch,
}

/// Physical guard whose original notification stays with its enclosing fence.
pub(crate) struct DeferredPublicationGuard<'fence, 'state, T> {
    guard: Option<PublicationGuard<'state, T>>,
    releases: &'fence mut iroha_allocation::release::DeferredReleaseBatch,
}

impl<'state, T> DeferredPublicationFence<'state, T> {
    /// Acquire the original mutex; release notification stays in this owner.
    pub(crate) fn lock(&mut self) -> DeferredPublicationGuard<'_, 'state, T> {
        DeferredPublicationGuard {
            guard: Some(self.mutex.lock()),
            releases: &mut self.releases,
        }
    }
}

impl<T> std::ops::Deref for DeferredPublicationGuard<'_, '_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.guard
            .as_deref()
            .expect("original deferred physical guard")
    }
}

impl<T> std::ops::DerefMut for DeferredPublicationGuard<'_, '_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.guard
            .as_deref_mut()
            .expect("original deferred physical guard")
    }
}

impl<T> Drop for DeferredPublicationGuard<'_, '_, T> {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            // Both fields are private and created together by defer_notifications.
            // The source cannot change between acquisition and physical release.
            assert!(
                guard.try_release_into(self.releases).is_ok(),
                "original fence release source"
            );
        }
    }
}

impl<T> PublicationMutex<T> {
    /// Retain all original release hints through an enclosing aggregate's Drop.
    pub(crate) fn defer_notifications(&self) -> DeferredPublicationFence<'_, T> {
        DeferredPublicationFence {
            mutex: self,
            releases: self.deferred_releases(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };

    #[test]
    fn typed_guard_notifies_after_unlock_and_preserves_value() {
        let observer_budget = iroha_allocation::AllocationBudget::new(
            iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
        );
        let mut registration = crate::unit_test_support::release_registration(&observer_budget);
        struct AcquireOnWake {
            original: Arc<PublicationMutex<Vec<u8>>>,
            observed: AtomicBool,
        }
        impl Wake for AcquireOnWake {
            fn wake(self: Arc<Self>) {
                let value = self
                    .original
                    .try_lock()
                    .expect("wake follows physical unlock");
                assert_eq!(&*value, &[1, 2]);
                self.observed.store(true, Ordering::SeqCst);
            }
        }
        let original = Arc::new(PublicationMutex::new(vec![1_u8]));
        let mut held = original.lock();
        held.push(2);
        let wait = match original.try_lock_or_wait() {
            Err(wait) => wait,
            Ok(_) => panic!("original backend is still held"),
        };
        let probe = Arc::new(AcquireOnWake {
            original: Arc::clone(&original),
            observed: AtomicBool::new(false),
        });
        let waker = Waker::from(Arc::clone(&probe));
        let mut context = Context::from_waker(&waker);
        let pending = wait;
        assert!(registration.poll_wait(&pending, &mut context).is_pending());
        let foreign = PublicationMutex::new(vec![8_u8]);
        drop(foreign.lock());
        assert!(!probe.observed.load(Ordering::SeqCst));
        assert!(registration.poll_wait(&pending, &mut context).is_pending());
        drop(held);
        assert!(probe.observed.load(Ordering::SeqCst));
        assert_eq!(
            registration.poll_wait(&pending, &mut context),
            Poll::Ready(())
        );
    }

    #[test]
    fn typed_fair_unlock_and_release_before_poll_are_observable() {
        let observer_budget = iroha_allocation::AllocationBudget::new(
            iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
        );
        let mut registration = crate::unit_test_support::release_registration(&observer_budget);
        let original = PublicationMutex::new(String::from("original"));
        let mut held = original.lock();
        held.push_str(" retained");
        let wait = match original.try_lock_or_wait() {
            Err(wait) => wait,
            Ok(_) => panic!("original backend is still held"),
        };
        held.unlock_fair();
        let pending = wait;
        assert_eq!(
            registration.poll_wait(&pending, &mut Context::from_waker(Waker::noop())),
            Poll::Ready(())
        );
        assert_eq!(&*original.lock(), "original retained");
    }

    #[test]
    fn typed_unwind_releases_original_value_without_poisoning() {
        let observer_budget = iroha_allocation::AllocationBudget::new(
            iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
        );
        let mut registration = crate::unit_test_support::release_registration(&observer_budget);
        let original = PublicationMutex::new(vec![1_u8]);
        let mut wait = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut held = original.lock();
            held.push(3);
            wait = original.try_lock_or_wait().err();
            panic!("exercise the real backend guard's unwind release");
        }));
        assert!(result.is_err());
        let pending = wait.expect("held original returns its wait");
        assert_eq!(
            registration.poll_wait(&pending, &mut Context::from_waker(Waker::noop())),
            Poll::Ready(())
        );
        let value = original
            .try_lock_or_wait()
            .ok()
            .expect("parking-lot is not poisoned");
        assert_eq!(&*value, &[1, 3]);
    }

    #[test]
    fn deferred_notification_reenters_all_original_fences_after_outer_unlock() {
        let observer_budget = iroha_allocation::AllocationBudget::new(
            iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
        );
        let mut registration = crate::unit_test_support::release_registration(&observer_budget);
        struct AcquireBoth {
            locks: [Arc<PublicationMutex>; 2],
            observed: AtomicBool,
        }
        impl Wake for AcquireBoth {
            fn wake(self: Arc<Self>) {
                let first = self.locks[0]
                    .inner
                    .try_lock()
                    .expect("first physical unlock");
                let second = self.locks[1]
                    .inner
                    .try_lock()
                    .expect("outer physical unlock");
                self.observed.store(true, Ordering::SeqCst);
                drop((first, second));
            }
        }
        for unwind in [false, true] {
            let locks = [
                Arc::new(PublicationMutex::default()),
                Arc::new(PublicationMutex::default()),
            ];
            let held = locks[0].lock();
            let outer = locks[1].lock();
            let pending = locks[0].try_lock_or_wait().err().unwrap();
            let probe = Arc::new(AcquireBoth {
                locks: locks.clone(),
                observed: AtomicBool::new(false),
            });
            let waker = Waker::from(Arc::clone(&probe));
            assert!(
                registration
                    .poll_wait(&pending, &mut Context::from_waker(&waker))
                    .is_pending()
            );
            let released = held.release_deferred();
            assert!(locks[0].inner.try_lock().is_some());
            assert!(!probe.observed.load(Ordering::SeqCst));
            if unwind {
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                        // Reverse local order unlocks the enclosing owner first.
                        let _released = released;
                        let _outer = outer;
                        panic!("completion cleanup unwind");
                    }))
                    .is_err()
                );
            } else {
                drop(outer);
                drop(released);
            }
            assert!(probe.observed.load(Ordering::SeqCst));
            assert!(
                registration
                    .poll_wait(&pending, &mut Context::from_waker(&waker))
                    .is_ready()
            );
        }
    }
}

#[cfg(test)]
#[path = "publication_lock_scoped_tests.rs"]
mod scoped_tests;

#[cfg(test)]
mod mutation_epoch_tests {
    use super::*;
    use std::{
        sync::atomic::Ordering,
        task::{Context, Poll, Waker},
    };

    fn read_epoch(mutex: &PublicationMutex, permit: &PublicationReadPermit) -> Option<u64> {
        mutex.lock_read_only(permit).unwrap().mutation_epoch()
    }

    // Mirrors generic publication-lease acquisition: a shared reference to the
    // original wrapper must never erase its mutation behavior.
    fn lease_like_acquire(mutex: &PublicationMutex) -> PublicationGuard<'_> {
        mutex
            .try_lock_or_wait()
            .unwrap_or_else(|_| panic!("uncontended original publication fence"))
    }

    #[test]
    fn every_successful_ordinary_acquisition_invalidates_prior_observations() {
        let (mutex, permit) = PublicationMutex::with_read_permit();
        assert_eq!(read_epoch(&mutex, &permit), Some(0));
        assert_eq!(read_epoch(&mutex, &permit), Some(0));
        assert_eq!(mutex.lock().mutation_epoch(), Some(1));
        assert_eq!(read_epoch(&mutex, &permit), Some(1));
        assert_eq!(mutex.try_lock().unwrap().mutation_epoch(), Some(2));
        assert_eq!(lease_like_acquire(&mutex).mutation_epoch(), Some(3));
        {
            let mut deferred = mutex.defer_notifications();
            let held = deferred.lock();
            assert_eq!(held.guard.as_ref().unwrap().mutation_epoch(), Some(4));
        }
        assert_eq!(read_epoch(&mutex, &permit), Some(4));
    }

    #[test]
    fn contended_probes_do_not_claim_a_mutation_acquisition() {
        let (mutex, permit) = PublicationMutex::with_read_permit();
        let held = mutex.lock_read_only(&permit).unwrap();
        assert!(mutex.try_lock().is_none());
        assert!(mutex.try_lock_or_wait().is_err());
        assert_eq!(held.mutation_epoch(), Some(0));
        assert_eq!(
            mutex
                .mutation_epoch
                .as_ref()
                .unwrap()
                .load(Ordering::Relaxed),
            0
        );
        drop(held);
        assert_eq!(lease_like_acquire(&mutex).mutation_epoch(), Some(1));
    }

    #[test]
    fn read_permit_is_bound_to_original_mutex_and_survives_owner_move() {
        let (original, permit) = PublicationMutex::with_read_permit();
        let (foreign, foreign_permit) = PublicationMutex::with_read_permit();
        let default = PublicationMutex::default();
        let constructed = PublicationMutex::new(());
        // Wrong permits refuse even while the target is physically locked.
        // Validation after lock acquisition would deadlock this same thread.
        let held = original.lock_read_only(&permit).unwrap();
        assert!(matches!(
            original.lock_read_only(&foreign_permit),
            Err(PublicationReadPermitMismatch)
        ));
        assert!(matches!(
            foreign.lock_read_only(&permit),
            Err(PublicationReadPermitMismatch)
        ));
        assert!(matches!(
            default.lock_read_only(&permit),
            Err(PublicationReadPermitMismatch)
        ));
        assert!(matches!(
            constructed.lock_read_only(&permit),
            Err(PublicationReadPermitMismatch)
        ));
        assert_eq!(held.mutation_epoch(), Some(0));
        assert_eq!(
            foreign
                .mutation_epoch
                .as_ref()
                .unwrap()
                .load(Ordering::Relaxed),
            0
        );
        assert!(default.mutation_epoch.is_none());
        assert!(constructed.mutation_epoch.is_none());
        assert_eq!(default.lock().mutation_epoch(), None);
        assert_eq!(constructed.try_lock().unwrap().mutation_epoch(), None);
        drop(held);
        let moved = Box::new(original);
        assert_eq!(read_epoch(&moved, &permit), Some(0));
        assert_eq!(moved.lock().mutation_epoch(), Some(1));
        assert_eq!(read_epoch(&moved, &permit), Some(1));
    }

    #[test]
    fn errors_and_unwind_invalidate_before_any_caller_work() {
        let (mutex, permit) = PublicationMutex::with_read_permit();
        let failed: Result<(), &'static str> = (|| {
            let held = mutex.lock();
            assert_eq!(held.mutation_epoch(), Some(1));
            Err("operation failed after acquiring original mutation fence")
        })();
        assert!(failed.is_err());
        assert_eq!(read_epoch(&mutex, &permit), Some(1));
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let held = lease_like_acquire(&mutex);
            assert_eq!(held.mutation_epoch(), Some(2));
            panic!("operation unwinds after acquiring original mutation fence");
        }));
        assert!(unwound.is_err());
        assert_eq!(read_epoch(&mutex, &permit), Some(2));
        assert_eq!(mutex.try_lock().unwrap().mutation_epoch(), Some(3));
    }

    #[test]
    fn saturated_epoch_permanently_disables_reuse_without_wrapping() {
        let (mutex, permit) = PublicationMutex::with_read_permit();
        // Private test setup; no production epoch setter is exposed.
        mutex
            .mutation_epoch
            .as_ref()
            .unwrap()
            .store(u64::MAX - 2, Ordering::Relaxed);
        assert_eq!(mutex.lock().mutation_epoch(), Some(u64::MAX - 1));
        assert_eq!(read_epoch(&mutex, &permit), Some(u64::MAX - 1));
        assert_eq!(lease_like_acquire(&mutex).mutation_epoch(), None);
        for _ in 0..3 {
            assert_eq!(read_epoch(&mutex, &permit), None);
            assert_eq!(mutex.try_lock().unwrap().mutation_epoch(), None);
            assert_eq!(
                mutex
                    .mutation_epoch
                    .as_ref()
                    .unwrap()
                    .load(Ordering::Relaxed),
                u64::MAX
            );
        }
    }

    #[test]
    fn read_guard_unlock_and_deferred_notification_preserve_original_source() {
        let observer_budget = iroha_allocation::AllocationBudget::new(
            iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
        );
        let mut registration = crate::unit_test_support::release_registration(&observer_budget);
        let (mutex, permit) = PublicationMutex::with_read_permit();
        let held = mutex.lock_read_only(&permit).unwrap();
        let wait = mutex
            .try_lock_or_wait()
            .err()
            .expect("physical fence is held");
        let pending = wait;
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(
            registration.poll_wait(&pending, &mut context),
            Poll::Pending
        );
        let released = held.release_deferred();
        // Probe the private backend only in this notification-order test, so
        // the probe itself cannot signal the notification under observation.
        assert!(mutex.inner.try_lock().is_some());
        assert_eq!(
            registration.poll_wait(&pending, &mut context),
            Poll::Pending
        );
        drop(released);
        assert_eq!(
            registration.poll_wait(&pending, &mut context),
            Poll::Ready(())
        );
        assert_eq!(read_epoch(&mutex, &permit), Some(0));
        assert_eq!(mutex.lock().mutation_epoch(), Some(1));
    }

    #[test]
    fn foreign_release_batch_preserves_guard_and_captured_epoch() {
        let (mutex, permit) = PublicationMutex::with_read_permit();
        let foreign: PublicationMutex = PublicationMutex::default();
        let mut foreign_batch = foreign.deferred_releases();
        let held = mutex.lock();
        let held = held
            .try_release_into(&mut foreign_batch)
            .err()
            .expect("foreign batch returns the original guard");
        assert_eq!(held.mutation_epoch(), Some(1));
        assert!(mutex.try_lock().is_none());
        let mut original_batch = mutex.deferred_releases();
        assert!(held.try_release_into(&mut original_batch).is_ok());
        assert_eq!(read_epoch(&mutex, &permit), Some(1));
        drop(original_batch);
    }
}

#[cfg(test)]
mod admitted_control_tests {
    use super::*;
    #[test]
    fn original_fence_control_is_fallible_and_retained_by_its_release_observation() {
        use iroha_allocation::{AllocationBudget, AllocationCharge, release::ReleaseNotification};
        let layout = ReleaseNotification::allocation_layout::<AllocationCharge>();
        let empty = AllocationBudget::new(0);
        let expected = empty.try_reserve(layout).unwrap_err();
        assert!(matches!(PublicationMutex::try_new((), &empty),
            Err(mv::storage::AdmittedStorageError::Allocation(ref actual)) if actual == &expected));
        let budget = AllocationBudget::new(layout.size());
        let lock = PublicationMutex::try_new((), &budget).unwrap();
        let wait = lock.observe_release();
        assert_eq!(budget.reserved_bytes(), layout.size());
        drop(lock);
        assert_eq!(budget.reserved_bytes(), layout.size());
        drop(wait);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
