//! Checked resident-index publication under the index's existing mutation lock.

use std::{
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use parking_lot::{Mutex, MutexGuard};

use super::resource_inventory::{Family, Inventory, Mutation, Unavailable, Usage};

/// Constant-time resident count and semantic completeness of one locked owner.
pub(super) trait ResidentOwner {
    /// Shared fixed family; independent objects publish exact additive deltas.
    const FAMILY: Family;

    /// Count actual stored associations without walking historical collections.
    fn resident_associations(&self) -> Result<u64, Unavailable>;

    /// Whether the owner has finished the required authenticated reconstruction.
    fn resident_complete(&self) -> bool;

    /// Families whose observations become unknown if this owner's mutation fails.
    ///
    /// Include the resident family. An owner with deferred physical repair may
    /// additionally invalidate its physical representations without publishing
    /// overlapping filesystem deltas from every reader.
    fn failure_invalidation_mask() -> u32 {
        Self::FAMILY.mask()
    }
}

/// Existing index mutex plus its shared publication authority.
#[derive(Debug)]
pub(super) struct ResidentMutex<T: ResidentOwner> {
    inner: Mutex<T>,
    inventory: Arc<Inventory>,
    publication_valid: AtomicBool,
}

impl<T: ResidentOwner> ResidentMutex<T> {
    /// Bind one actual object; registration remains the reconciliation owner's job.
    pub(super) fn new(value: T, inventory: &Arc<Inventory>) -> Self {
        Self {
            inner: Mutex::new(value),
            inventory: Arc::clone(inventory),
            publication_valid: AtomicBool::new(true),
        }
    }

    /// Acquire only the original owner lock; a read does not mutate the registry.
    pub(super) fn lock(&self) -> ResidentGuard<'_, T> {
        self.guard(self.inner.lock())
    }

    /// Preserve callers' existing nonblocking owner-lock behavior.
    pub(super) fn try_lock(&self) -> Option<ResidentGuard<'_, T>> {
        self.inner.try_lock().map(|guard| self.guard(guard))
    }

    fn guard<'a>(&'a self, inner: MutexGuard<'a, T>) -> ResidentGuard<'a, T> {
        ResidentGuard {
            inner,
            inventory: &self.inventory,
            publication_valid: &self.publication_valid,
            before: None,
            mutation: None,
            began: false,
        }
    }
}

/// A mutable borrow marks the registry busy before exposing the owner.
pub(super) struct ResidentGuard<'a, T: ResidentOwner> {
    inner: MutexGuard<'a, T>,
    inventory: &'a Inventory,
    publication_valid: &'a AtomicBool,
    before: Option<Usage>,
    mutation: Option<Mutation<'a>>,
    began: bool,
}

impl<T: ResidentOwner> ResidentOwner for ResidentGuard<'_, T> {
    const FAMILY: Family = T::FAMILY;
    fn failure_invalidation_mask() -> u32 {
        T::failure_invalidation_mask()
    }
    fn resident_associations(&self) -> Result<u64, Unavailable> {
        if !self.publication_valid.load(Ordering::Acquire) {
            return Err(Unavailable::Interrupted);
        }
        self.inner.resident_associations()
    }
    fn resident_complete(&self) -> bool {
        self.publication_valid.load(Ordering::Acquire) && self.inner.resident_complete()
    }
}

impl<T: ResidentOwner> Deref for ResidentGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: ResidentOwner> DerefMut for ResidentGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        if !self.began {
            self.began = true;
            match self.inventory.begin(T::FAMILY.mask()) {
                Ok(mutation) => self.mutation = Some(mutation),
                Err(reason) => self
                    .inventory
                    .invalidate(T::failure_invalidation_mask(), reason),
            }
            match self.inner.resident_associations() {
                Ok(resident_associations) => {
                    self.before = Some(Usage {
                        resident_associations,
                        ..Usage::default()
                    })
                }
                Err(reason) => self
                    .inventory
                    .invalidate(T::failure_invalidation_mask(), reason),
            }
        }
        &mut self.inner
    }
}

/// Keep the expanded failure mask armed while owner callbacks and publication run.
struct ResidentFailureFence<'a> {
    inventory: &'a Inventory,
    publication_valid: &'a AtomicBool,
    mask: u32,
    armed: bool,
}

impl ResidentFailureFence<'_> {
    fn invalidate(&mut self, reason: Unavailable) {
        self.inventory.invalidate(self.mask, reason);
        self.armed = false;
    }
}

impl Drop for ResidentFailureFence<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.publication_valid.store(false, Ordering::Release);
            self.inventory
                .invalidate(self.mask, Unavailable::Interrupted);
        }
    }
}

impl<T: ResidentOwner> Drop for ResidentGuard<'_, T> {
    fn drop(&mut self) {
        // Declare the fence before taking the token: both unwind before the
        // original mutex guard, even if a count/completeness callback panics.
        let mut failure = ResidentFailureFence {
            inventory: self.inventory,
            publication_valid: self.publication_valid,
            mask: T::failure_invalidation_mask(),
            armed: self.began,
        };
        let Some(mutation) = self.mutation.take() else {
            if self.began {
                self.publication_valid.store(false, Ordering::Release);
                failure.invalidate(Unavailable::Interrupted);
            }
            return;
        };
        // Dropping an unfinished token invalidates the family. In particular,
        // unwinding never certifies an interrupted multi-map publication.
        if std::thread::panicking() {
            self.publication_valid.store(false, Ordering::Release);
            failure.invalidate(Unavailable::Interrupted);
            return;
        }
        let Some(before) = self.before else {
            self.publication_valid.store(false, Ordering::Release);
            failure.invalidate(Unavailable::Interrupted);
            return;
        };
        let after = match self.inner.resident_associations() {
            Ok(resident_associations) => Usage {
                resident_associations,
                ..Usage::default()
            },
            Err(reason) => {
                self.publication_valid.store(false, Ordering::Release);
                failure.invalidate(reason);
                return;
            }
        };
        if !self.inner.resident_complete() {
            self.inventory.invalidate(
                T::failure_invalidation_mask(),
                Unavailable::InvalidInventory,
            );
        }
        if let Err(reason) = mutation.publish(&[(T::FAMILY, before, after)]) {
            failure.invalidate(reason);
        } else {
            failure.armed = false;
        }
        // The registry lock is released before the original owner lock drops.
    }
}

/// Sticky checked cardinality for nested memberships updated by real mutations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AssociationCount(Option<u64>);

impl Default for AssociationCount {
    fn default() -> Self {
        Self(Some(0))
    }
}

impl AssociationCount {
    /// Increment only after the actual set/map reports a newly stored association.
    pub(super) fn inserted(&mut self, inserted: bool) {
        if inserted {
            self.0 = self.0.and_then(|value| value.checked_add(1));
        }
    }

    /// Subtract exactly the observed successful removal count.
    pub(super) fn removed(&mut self, removed: Option<u64>) {
        self.0 = self
            .0
            .zip(removed)
            .and_then(|(value, removed)| value.checked_sub(removed));
    }

    /// Replace one exact nested weight while preserving a prior arithmetic failure.
    #[expect(
        dead_code,
        reason = "TODO: connect exact cardinality replacement to retained inventory publication; preserve checked overflow and underflow accounting"
    )]
    pub(super) fn replace(&mut self, before: Option<u64>, after: Option<u64>) {
        self.0 = self
            .0
            .zip(before)
            .zip(after)
            .and_then(|((total, before), after)| total.checked_sub(before)?.checked_add(after));
    }

    /// Return exact cardinality; overflow/underflow cannot recover by later updates.
    pub(super) fn get(self) -> Result<u64, Unavailable> {
        self.0.ok_or(Unavailable::Arithmetic)
    }
}

/// Checked reduction of a fixed number of O(1) collection lengths.
pub(super) fn lengths(values: impl IntoIterator<Item = usize>) -> Result<u64, Unavailable> {
    values.into_iter().try_fold(0_u64, |total, value| {
        total
            .checked_add(u64::try_from(value).map_err(|_| Unavailable::Arithmetic)?)
            .ok_or(Unavailable::Arithmetic)
    })
}

#[cfg(test)]
#[path = "resident_inventory_tests.rs"]
mod tests;
