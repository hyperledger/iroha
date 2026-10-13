// SPDX-License-Identifier: MPL-2.0
//! Shared allocation custody without weak references or guessed Arc layouts.
//!
//! The concrete control block owns a prepaid charge. The last reference frees
//! that exact block, then destroys its moved payload, then releases its charge.
//! No public operation exposes weak references, raw ownership or the counter.

#![allow(unsafe_code)]

use std::alloc::{Layout, alloc, handle_alloc_error};
use std::cell::UnsafeCell;
use std::fmt;
use std::mem::{ManuallyDrop, MaybeUninit};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering, fence};

#[repr(C)]
struct Allocation<T, Charge> {
    references: AtomicUsize,
    value: UnsafeCell<MaybeUninit<T>>,
    charge: ManuallyDrop<Charge>,
}

/// One originally allocated shell that has not yet received its payload.
///
/// Reserve it before entering a phase that cannot allocate, then consume it with
/// [`Self::initialize`]. The opaque charge must already cover [`Self::layout`];
/// this owner neither grants credit nor funds allocations nested in the payload
/// or charge. Charge is caller-owned custody; this generic owner does not
/// validate it as credit authority. Dropping an unused shell frees it before
/// dropping its charge.
///
/// The shell cannot be cloned or initialized twice:
/// ```compile_fail
/// use iroha_allocation::shared::Reserved;
/// fn initialize_twice(shell: Reserved<u64, ()>) {
///     let first = shell.initialize(1);
///     let second = shell.initialize(2);
/// }
/// ```
pub struct Reserved<T, Charge> {
    pointer: NonNull<Allocation<T, Charge>>,
}

/// The allocator refused one exact shared control-block layout.
///
/// This describes an allocation failure, not a pool admission decision. The
/// failed constructor returns the original charge separately for retry or abort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservationError {
    layout: Layout,
}

impl ReservationError {
    /// Exact layout refused before any shell or payload was initialized.
    pub fn layout(self) -> Layout {
        self.layout
    }
}

impl fmt::Display for ReservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "shared allocation refused ({} bytes, alignment {})",
            self.layout.size(),
            self.layout.align()
        )
    }
}

impl std::error::Error for ReservationError {}

/// Strong references to one original initialized allocation and its charge.
pub struct Shared<T, Charge> {
    pointer: NonNull<Allocation<T, Charge>>,
}

/// An already admitted runtime wake target shared by canonical charged handles.
pub trait SharedWake: Send + Sync + 'static {
    /// Notify the target while its original shared allocation remains alive.
    fn wake(&self);
}

impl<T: SharedWake, Charge: Send + Sync + 'static> Shared<T, Charge> {
    /// Transfer exactly this strong reference into the canonical Waker vtable.
    pub(crate) fn into_waker(self) -> std::task::Waker {
        struct Vtable<T, Charge>(std::marker::PhantomData<(T, Charge)>);
        impl<T: SharedWake, Charge: Send + Sync + 'static> Vtable<T, Charge> {
            const TABLE: std::task::RawWakerVTable = std::task::RawWakerVTable::new(
                Self::clone,
                Self::wake,
                Self::wake_by_ref,
                Self::drop,
            );

            unsafe fn owner(pointer: *const ()) -> Shared<T, Charge> {
                Shared {
                    pointer: unsafe { NonNull::new_unchecked(pointer.cast_mut().cast()) },
                }
            }

            unsafe fn clone(pointer: *const ()) -> std::task::RawWaker {
                // Borrow the original ownership unit and create exactly one
                // additional canonical reference without allocation.
                let original = ManuallyDrop::new(unsafe { Self::owner(pointer) });
                Self::raw(Shared::clone(&original))
            }

            unsafe fn wake(pointer: *const ()) {
                // This stack owner retires its reference after the callback,
                // including callback unwind, while retaining original custody.
                let original = unsafe { Self::owner(pointer) };
                T::wake(&original);
            }

            unsafe fn wake_by_ref(pointer: *const ()) {
                let original = ManuallyDrop::new(unsafe { Self::owner(pointer) });
                T::wake(&original);
            }

            unsafe fn drop(pointer: *const ()) {
                drop(unsafe { Self::owner(pointer) });
            }

            fn raw(original: Shared<T, Charge>) -> std::task::RawWaker {
                let original = ManuallyDrop::new(original);
                std::task::RawWaker::new(original.pointer.as_ptr().cast(), &Self::TABLE)
            }
        }
        // SAFETY: every entry consumes, borrows or clones exactly the ownership
        // unit supplied by raw. Its payload and charge satisfy thread bounds.
        unsafe { std::task::Waker::from_raw(Vtable::<T, Charge>::raw(self)) }
    }
}

/// One original shared owner with an allocation-free erased charge type.
///
/// The payload and its charge remain in their original concrete allocation.
/// Erasure adds no Box, reference counter, or replacement allocation.
pub(crate) struct ErasedShared<T> {
    allocation: NonNull<()>,
    value: NonNull<T>,
    clone_owner: unsafe fn(NonNull<()>),
    drop_owner: unsafe fn(NonNull<()>),
}

// Construction requires the erased charge to satisfy the same thread bounds.
unsafe impl<T: Send + Sync> Send for ErasedShared<T> {}
unsafe impl<T: Send + Sync> Sync for ErasedShared<T> {}

impl<T> ErasedShared<T> {
    pub(crate) fn new<Charge: Send + Sync + 'static>(value: T, charge: Charge) -> Self {
        Self::from_owner(Shared::new(value, charge))
    }

    pub(crate) fn try_new<Charge: Send + Sync + 'static>(
        value: T,
        charge: Charge,
    ) -> Result<Self, (T, Charge, ReservationError)> {
        Shared::try_new(value, charge).map(Self::from_owner)
    }

    fn from_owner<Charge: Send + Sync + 'static>(owner: Shared<T, Charge>) -> Self {
        unsafe fn clone_owner<T, Charge>(pointer: NonNull<()>) {
            let original = ManuallyDrop::new(Shared::<T, Charge> {
                pointer: pointer.cast(),
            });
            // Retain exactly one additional strong reference in the same block.
            std::mem::forget(Shared::clone(&original));
        }
        unsafe fn drop_owner<T, Charge>(pointer: NonNull<()>) {
            drop(Shared::<T, Charge> {
                pointer: pointer.cast(),
            });
        }
        let value = NonNull::from(&*owner);
        let owner = ManuallyDrop::new(owner);
        Self {
            allocation: owner.pointer.cast(),
            value,
            clone_owner: clone_owner::<T, Charge>,
            drop_owner: drop_owner::<T, Charge>,
        }
    }

    pub(crate) fn ptr_eq(left: &Self, right: &Self) -> bool {
        left.allocation == right.allocation
    }

    #[cfg(test)]
    pub(crate) fn strong_count(&self) -> usize {
        // Allocation is repr(C), with this counter as its first field for every
        // erased charge. This diagnostic does not grant unique ownership.
        unsafe { self.allocation.cast::<AtomicUsize>().as_ref() }.load(Ordering::Acquire)
    }
}

impl<T> Clone for ErasedShared<T> {
    fn clone(&self) -> Self {
        // SAFETY: the function and pointer are installed together by `new`,
        // and this live reference prevents concurrent final destruction.
        unsafe { (self.clone_owner)(self.allocation) };
        Self {
            allocation: self.allocation,
            value: self.value,
            clone_owner: self.clone_owner,
            drop_owner: self.drop_owner,
        }
    }
}

impl<T> Deref for ErasedShared<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: every erased owner retains one original initialized reference.
        unsafe { self.value.as_ref() }
    }
}

impl<T> Drop for ErasedShared<T> {
    fn drop(&mut self) {
        // SAFETY: this consumes exactly the original reference held by self.
        unsafe { (self.drop_owner)(self.allocation) };
    }
}

/// The uniquely owned payload and charge after their control block was freed.
pub struct Reclaimed<T, Charge> {
    value: ManuallyDrop<T>,
    charge: ManuallyDrop<Charge>,
}

// Only the last strong owner mutates or destroys a published payload. No weak
// references exist, and publication transfers an already initialized value.
unsafe impl<T: Send + Sync, Charge: Send + Sync> Send for Shared<T, Charge> {}
unsafe impl<T: Send + Sync, Charge: Send + Sync> Sync for Shared<T, Charge> {}
// Reserved shells are unique and expose no payload reference before initialization.
unsafe impl<T: Send, Charge: Send> Send for Reserved<T, Charge> {}
unsafe impl<T: Sync, Charge: Sync> Sync for Reserved<T, Charge> {}

impl<T, Charge> Reserved<T, Charge> {
    /// Exact original allocation layout, including the charge and all padding.
    ///
    /// Rust bounds this concrete sized layout before the allocator is called;
    /// the reference count makes it nonzero even for zero-sized payload/charge.
    pub fn layout() -> Layout {
        Layout::new::<Allocation<T, Charge>>()
    }

    /// Allocate one uninitialized shell with its already admitted charge.
    ///
    /// On allocator refusal, return that same charge without destroying it or
    /// constructing any payload. The caller can retry with the returned owner;
    /// no allocation size estimate or replacement capacity grant is used.
    /// Success retains the charge until the original allocation is freed.
    ///
    /// # Errors
    /// Returns the unchanged charge and requested layout if the global allocator refuses it.
    pub fn try_new(charge: Charge) -> Result<Self, (Charge, ReservationError)> {
        let layout = Self::layout();
        // SAFETY: the concrete sized layout is valid and nonzero. alloc uses the
        // same global allocator/layout that the existing Box reclamation owns.
        let Some(pointer) = NonNull::new(unsafe { alloc(layout) }.cast::<Allocation<T, Charge>>())
        else {
            return Err((charge, ReservationError { layout }));
        };
        // SAFETY: this unique, correctly aligned allocation has room for the
        // exact header. Initialize only its live fields; UnsafeCell<MaybeUninit<T>>
        // permits uninitialized bytes. No payload-sized stack temporary or
        // initialized T exists until the consuming initialize operation. These
        // field moves cannot invoke user code or unwind.
        unsafe {
            std::ptr::addr_of_mut!((*pointer.as_ptr()).references).write(AtomicUsize::new(1));
            std::ptr::addr_of_mut!((*pointer.as_ptr()).charge).write(ManuallyDrop::new(charge));
        }
        Ok(Self { pointer })
    }

    /// Borrow the original charge while this uninitialized physical shell lives.
    pub(crate) fn charge(&self) -> &Charge {
        // SAFETY: this unique live shell initialized only the charge and counter.
        unsafe { &self.pointer.as_ref().charge }
    }

    /// Allocate the same exact shell, invoking the standard allocation-error handler on refusal.
    /// Fallible admission paths should retain their charge through [`Self::try_new`].
    pub fn new(charge: Charge) -> Self {
        match Self::try_new(charge) {
            Ok(shell) => shell,
            Err((_charge, error)) => handle_alloc_error(error.layout()),
        }
    }

    /// Consume this shell and move the payload into its original allocation.
    ///
    /// This does not allocate, clone, invoke a callback, or drop either owner.
    /// The returned strong owner retains exactly the shell's original charge.
    pub fn initialize(self, value: T) -> Shared<T, Charge> {
        let this = ManuallyDrop::new(self);
        // SAFETY: Reserved is unique, cannot be cloned and has no published
        // payload. Initialization happens exactly once before the type changes.
        unsafe { (*this.pointer.as_ref().value.get()).write(value) };
        Shared {
            pointer: this.pointer,
        }
    }
}

impl<T, Charge> Drop for Reserved<T, Charge> {
    fn drop(&mut self) {
        // SAFETY: this shell never escaped as a shared initialized owner.
        let mut allocation = unsafe { Box::from_raw(self.pointer.as_ptr()) };
        let charge = ManuallyDrop::new(unsafe { ManuallyDrop::take(&mut allocation.charge) });
        drop(allocation);
        // The uninitialized shell and its exact control block are now gone.
        drop(ManuallyDrop::into_inner(charge));
    }
}

impl<T, Charge> Shared<T, Charge> {
    /// Exact layout of the one allocation retained by this shared owner.
    /// Nested allocations in `T` or `Charge` require their own funding.
    pub fn layout() -> Layout {
        Reserved::<T, Charge>::layout()
    }

    /// Allocate one initialized owner, retaining its original charge until the
    /// final reference has freed the allocation and destroyed its payload.
    pub fn new(value: T, charge: Charge) -> Self {
        Reserved::new(charge).initialize(value)
    }

    /// Fallibly allocate one initialized owner using the same exact layout and
    /// final-reference destruction protocol as [`Self::new`].
    ///
    /// No payload or charge is cloned or destroyed when the allocator refuses.
    /// The caller remains responsible for admitting this control allocation and
    /// any nested payload allocations before entering this function.
    ///
    /// # Errors
    /// Returns the original payload and charge unchanged with the exact refused layout.
    pub fn try_new(value: T, charge: Charge) -> Result<Self, (T, Charge, ReservationError)> {
        match Reserved::try_new(charge) {
            Ok(reserved) => Ok(reserved.initialize(value)),
            Err((charge, error)) => Err((value, charge, error)),
        }
    }

    /// Whether both references retain the same original allocation.
    pub fn ptr_eq(left: &Self, right: &Self) -> bool {
        left.pointer == right.pointer
    }

    /// Borrow custody metadata without detaching it from its physical owner.
    pub(crate) fn charge(&self) -> &Charge {
        // The live shared reference keeps this initialized allocation and its charge alive.
        unsafe { &self.pointer.as_ref().charge }
    }

    /// Borrow the payload only when this is its sole original strong reference.
    /// No weak references exist, so another owner cannot race an upgrade.
    pub fn get_mut(&mut self) -> Option<&mut T> {
        // No weak owner can race an upgrade. With one strong reference and an
        // exclusive borrow of it, no other owner can create a competing clone.
        if unsafe { self.pointer.as_ref() }
            .references
            .load(Ordering::Acquire)
            != 1
        {
            return None;
        }
        Some(unsafe { (&mut *self.pointer.as_ref().value.get()).assume_init_mut() })
    }

    /// Consume one reference; the last owner frees the original control block.
    /// Retain the returned payload and charge until the caller completes reclamation.
    pub fn into_inner(self) -> Option<Reclaimed<T, Charge>> {
        let this = ManuallyDrop::new(self);
        // SAFETY: this consumes exactly one strong reference. Suppressing its
        // destructor prevents a second decrement of the same ownership unit.
        unsafe { Self::release(this.pointer) }
    }

    unsafe fn release(pointer: NonNull<Allocation<T, Charge>>) -> Option<Reclaimed<T, Charge>> {
        // Release publishes each previous owner's accesses. The final acquire
        // fence joins them before reading or destroying the unique payload.
        let allocation = unsafe { pointer.as_ref() };
        if allocation.references.fetch_sub(1, Ordering::Release) != 1 {
            return None;
        }
        fence(Ordering::Acquire);
        let mut allocation = unsafe { Box::from_raw(pointer.as_ptr()) };
        let value = ManuallyDrop::new(unsafe { allocation.value.get_mut().assume_init_read() });
        let charge = ManuallyDrop::new(unsafe { ManuallyDrop::take(&mut allocation.charge) });
        // MaybeUninit and ManuallyDrop suppress automatic payload/charge drop.
        // The exact allocation is freed before either is returned to the caller.
        drop(allocation);
        Some(Reclaimed { value, charge })
    }
}

impl<T, Charge> Clone for Shared<T, Charge> {
    fn clone(&self) -> Self {
        let previous = unsafe { self.pointer.as_ref() }
            .references
            .fetch_add(1, Ordering::Relaxed);
        // As with Arc, abort before an overflowing reference count can make a
        // live allocation appear uniquely owned. No panic may expose that state.
        if previous >= isize::MAX as usize {
            std::process::abort();
        }
        Self {
            pointer: self.pointer,
        }
    }
}

impl<T, Charge> Deref for Shared<T, Charge> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: Shared is constructed only after full initialization; its
        // strong reference retains the original allocation throughout this borrow.
        unsafe { (&*self.pointer.as_ref().value.get()).assume_init_ref() }
    }
}

impl<T, Charge> Drop for Shared<T, Charge> {
    fn drop(&mut self) {
        // SAFETY: this destructor consumes its one original strong reference.
        drop(unsafe { Self::release(self.pointer) });
    }
}

impl<T, Charge> Reclaimed<T, Charge> {
    /// Consume the unique payload while retaining its original charge through the callback.
    /// A panicking callback conservatively retains the charge rather than refunding early.
    pub fn consume<R>(self, consume: impl FnOnce(T) -> R) -> (R, Charge) {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: self is consumed, its automatic destructor is suppressed, and
        // these are the only reads of the original payload and charge.
        let value = unsafe { ManuallyDrop::take(&mut this.value) };
        let output = consume(value);
        // A panicking consumer retains the charge conservatively. Return the
        // original charge so the caller can finish publication before invoking
        // its destructor. This charge covers the control block, not nested T.
        let charge = unsafe { ManuallyDrop::take(&mut this.charge) };
        (output, charge)
    }
}

impl<T, Charge> Deref for Reclaimed<T, Charge> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T, Charge> DerefMut for Reclaimed<T, Charge> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

impl<T, Charge> Drop for Reclaimed<T, Charge> {
    fn drop(&mut self) {
        // If payload destruction unwinds, charge stays retained rather than
        // falsely reporting complete reclamation of an incompletely dropped T.
        unsafe { ManuallyDrop::drop(&mut self.value) };
        unsafe { ManuallyDrop::drop(&mut self.charge) };
    }
}

impl<T: fmt::Debug, Charge> fmt::Debug for Shared<T, Charge> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<T, Charge> fmt::Debug for Reserved<T, Charge> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reserved")
            .field("pointer", &self.pointer)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{ErasedShared, Reserved, Shared};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    struct Charge(Arc<AtomicUsize>);

    impl Drop for Charge {
        fn drop(&mut self) {
            assert_eq!(self.0.fetch_add(1, SeqCst), 0);
        }
    }

    #[test]
    fn erased_shared_preserves_original_pointer_and_charge_until_last_owner() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let original = ErasedShared::new(17_u64, Charge(Arc::clone(&dropped)));
        let pointer = std::ptr::from_ref(&*original) as usize;
        let other = original.clone();
        assert!(ErasedShared::ptr_eq(&original, &other));
        assert_eq!(original.strong_count(), 2);
        drop(original);
        assert_eq!(dropped.load(SeqCst), 0);
        std::thread::spawn(move || {
            let copy = other.clone();
            assert_eq!(std::ptr::from_ref(&*copy) as usize, pointer);
            assert_eq!(*copy, 17);
        })
        .join()
        .unwrap();
        assert_eq!(dropped.load(SeqCst), 1);
    }

    #[test]
    fn concurrent_clones_retain_one_original_allocation_and_unique_mutation() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut original = Reserved::new(Charge(Arc::clone(&dropped))).initialize(17_u64);
        let pointer = std::ptr::from_ref(&*original) as usize;
        let other = original.clone();
        assert!(Shared::ptr_eq(&original, &other));
        assert!(Shared::get_mut(&mut original).is_none());
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let owner = other.clone();
                scope.spawn(move || {
                    for _ in 0..10_000 {
                        let copy = owner.clone();
                        assert_eq!(*copy, 17);
                        assert_eq!(std::ptr::from_ref(&*copy) as usize, pointer);
                    }
                });
            }
        });
        drop(other);
        assert_eq!(dropped.load(SeqCst), 0);
        *Shared::get_mut(&mut original).unwrap() = 23;
        assert_eq!(*original, 23);
        drop(original);
        assert_eq!(dropped.load(SeqCst), 1);
    }
}

#[cfg(all(test, not(miri)))]
#[path = "shared_reservation_tests.rs"]
mod reservation_tests;

#[cfg(test)]
#[path = "shared_wake_tests.rs"]
mod wake_tests;
