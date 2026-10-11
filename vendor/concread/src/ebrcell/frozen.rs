//! Immutable handles to an original unpublished charged EBR allocation.
//!
//! Freezing does not enter the epoch collector or construct another allocation.
//! The counter is part of the original admitted layout. Only the unique frozen
//! owner can restore writable ownership, after all immutable handles retire.

use super::{reclaim, Allocation, EbrCellOwned, Untracked};
use crossbeam_epoch::Owned;
use std::{
    mem::ManuallyDrop,
    ops::Deref,
    ptr::NonNull,
    sync::atomic::{
        fence,
        Ordering::{Acquire, Relaxed, Release},
    },
};

/// Exact unpublished allocation held immutable without a Cell or epoch pin.
///
/// This retains physical allocation custody only. The enclosing MV owner must
/// separately retain the original Cell, predecessor and publication mode.
#[must_use = "retain this owner until its original reads retire"]
pub struct EbrCellFrozen<
    T: Clone + Send + Sync + 'static,
    Charge: Send + Sync + 'static = Untracked,
> {
    original: EbrCellFrozenRead<T, Charge>,
}

/// Strong immutable handle to the same original unpublished allocation.
///
/// Cloning shares the charged allocation without cloning its payload, allocating
/// a wrapper, or pinning the collector. It grants no writable ownership.
pub struct EbrCellFrozenRead<
    T: Clone + Send + Sync + 'static,
    Charge: Send + Sync + 'static = Untracked,
> {
    pointer: NonNull<Allocation<T, Charge>>,
}

// SAFETY: shared handles expose only immutable T; T and Charge are Send + Sync.
// The last handle alone takes ownership and reclaims on its current thread.
unsafe impl<T: Clone + Send + Sync + 'static, C: Send + Sync + 'static> Send
    for EbrCellFrozenRead<T, C>
{
}
unsafe impl<T: Clone + Send + Sync + 'static, C: Send + Sync + 'static> Sync
    for EbrCellFrozenRead<T, C>
{
}

impl<T: Clone + Send + Sync + 'static, C: Send + Sync + 'static> EbrCellOwned<T, C> {
    /// Move this exact unpublished allocation into immutable shared custody.
    /// No payload clone, allocation, epoch pin or target publication occurs.
    pub fn freeze(mut self) -> EbrCellFrozen<T, C> {
        let allocation = self.data.take().expect("original unpublished allocation");
        // into_box and into_raw transfer the same original allocation, without
        // allocating. All mutable access is consumed before a read can exist.
        let pointer = NonNull::from(Box::leak(allocation.into_box()));
        EbrCellFrozen {
            original: EbrCellFrozenRead { pointer },
        }
    }
}

impl<T: Clone + Send + Sync + 'static, C: Send + Sync + 'static> EbrCellFrozen<T, C> {
    /// Borrow the same original immutable payload without acquiring another handle.
    /// Consuming this owner to thaw is excluded while the returned borrow lives.
    /// No clone, allocation or epoch pin occurs.
    pub fn get(&self) -> &T {
        &self.original
    }

    /// Retain an immutable handle to this exact original allocation.
    pub fn read(&self) -> EbrCellFrozenRead<T, C> {
        self.original.clone()
    }

    /// Whether a live handle retains this same original allocation.
    /// Equal values and a Cell's later generations never establish this identity.
    pub fn matches_read(&self, read: &EbrCellFrozenRead<T, C>) -> bool {
        self.original.same_source(read)
    }

    /// Restore unique ownership only after all immutable handles have retired.
    ///
    /// Refusal returns this same frozen owner intact. It supplies no release
    /// ticket and does not wait for, acquire or publish through any Cell writer.
    pub fn try_thaw(self) -> Result<EbrCellOwned<T, C>, Self> {
        // SAFETY: this owner retains one strong reference throughout the load.
        // Acquire joins the final reader's Release before restoring mutation.
        if unsafe { self.original.pointer.as_ref() }
            .frozen_owners
            .load(Acquire)
            != 1
        {
            return Err(self);
        }
        // No other handle exists to clone. Consuming self excludes a concurrent
        // read() on this owner. Suppress its drop before transferring ownership.
        let original = ManuallyDrop::new(self);
        // SAFETY: the exact initialized backing is again uniquely owned; this
        // is the inverse of freeze's allocation-preserving conversion.
        let allocation = unsafe { Owned::from_raw(original.original.pointer.as_ptr()) };
        Ok(EbrCellOwned {
            data: Some(allocation),
        })
    }
}

impl<T: Clone + Send + Sync + 'static, C: Send + Sync + 'static> EbrCellFrozenRead<T, C> {
    /// Whether both live handles retain the exact same original allocation.
    pub fn same_source(&self, other: &Self) -> bool {
        self.pointer == other.pointer
    }
}

impl<T: Clone + Send + Sync + 'static, C: Send + Sync + 'static> Clone for EbrCellFrozenRead<T, C> {
    fn clone(&self) -> Self {
        // SAFETY: self retains a strong reference, excluding reclamation.
        // Refuse overflow without changing the count or losing original custody.
        unsafe { self.pointer.as_ref() }
            .frozen_owners
            .fetch_update(Relaxed, Relaxed, |count| {
                (count < isize::MAX as usize).then(|| count + 1)
            })
            .expect("frozen EBR ownership count exhausted");
        Self {
            pointer: self.pointer,
        }
    }
}

impl<T: Clone + Send + Sync + 'static, C: Send + Sync + 'static> Deref for EbrCellFrozenRead<T, C> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: this strong immutable owner retains the initialized payload;
        // no writable EbrCellOwned can coexist with this handle.
        &unsafe { self.pointer.as_ref() }.value
    }
}

impl<T: Clone + Send + Sync + 'static, C: Send + Sync + 'static> Drop for EbrCellFrozenRead<T, C> {
    fn drop(&mut self) {
        // SAFETY: this handle owns one reference; only its last release reclaims.
        if unsafe { self.pointer.as_ref() }
            .frozen_owners
            .fetch_sub(1, Release)
            == 1
        {
            fence(Acquire);
            // SAFETY: no reader or writable owner remains. Reclaim destroys the
            // payload and backing before releasing their original charge.
            reclaim(unsafe { Owned::from_raw(self.pointer.as_ptr()) });
        }
    }
}

#[cfg(test)]
#[path = "frozen_tests.rs"]
mod tests;
