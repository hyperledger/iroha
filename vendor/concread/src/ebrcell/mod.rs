//! EbrCell - A concurrently readable cell with Ebr
//!
//! An [EbrCell] can be used in place of a `RwLock`. Readers are guaranteed that
//! the data will not change during the lifetime of the read. Readers do
//! not block writers, and writers do not block readers. Writers are serialised
//! same as the write in a `RwLock`.
//!
//! This is the Ebr collected implementation.
//! Ebr is the crossbeam-epoch based reclaim system for async memory
//! garbage collection. Ebr is faster than `Arc`,
//! but long transactions can cause the memory usage to grow very quickly
//! before a garbage reclaim. This is a space time trade, where you gain
//! performance at the expense of delaying garbage collection. Holding Ebr
//! reads for too long may impact garbage collection of other epoch structures
//! or crossbeam library components.
//! If you need accurate memory reclaim, use the Arc (`CowCell`) implementation.

mod frozen;
pub use frozen::{EbrCellFrozen, EbrCellFrozenRead};

mod results;
use results::CloneAdmissionResult;

use crossbeam_epoch as epoch;
use crossbeam_epoch::{Atomic, Guard, Owned, Shared};
use std::alloc::Layout;
use std::sync::atomic::{
    AtomicUsize,
    Ordering::{AcqRel, Acquire},
};

use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::sync::{Mutex, MutexGuard, TryLockError};

// Construct the permanent native mutex before an original read or admission probe.
// Opaque platform mutex storage is separate from allocation_layout's payload charge.
fn initialized_writer_mutex() -> Mutex<()> {
    let mutex = Mutex::new(());
    drop(mutex.lock().expect("new EBR writer mutex is not poisoned"));
    mutex
}

/// Explicitly unaccounted mode for callers that do not attach allocation custody.
///
/// This mode makes no resource-admission guarantee. A cell using another charge
/// type cannot use the unaccounted `write` or `try_write` convenience methods.
#[derive(Debug)]
pub struct Untracked;

#[derive(Debug)]
#[repr(C)]
struct Allocation<T, Charge> {
    value: T,
    // Inline in the original admitted allocation, never a separately allocated wrapper.
    frozen_owners: AtomicUsize,
    // Never release custody through automatic field drop: the enclosing Box has
    // not yet been deallocated then, and a payload destructor may unwind.
    charge: ManuallyDrop<Charge>,
}

/// Unique prepaid physical EBR backing before any payload is constructed.
///
/// Initialization moves the payload once into this same allocation. Dropping an
/// unused reservation frees its backing before returning the original charge.
/// Neither construction nor abandonment pins the epoch collector.
#[must_use = "initialize or abandon this exact original EBR backing"]
pub struct ReservedEbrCell<T, Charge> {
    pointer: NonNull<Allocation<T, Charge>>,
}

// The uninitialized payload is inaccessible; only its original charge is live.
unsafe impl<T: Send, Charge: Send> Send for ReservedEbrCell<T, Charge> {}
unsafe impl<T: Sync, Charge: Sync> Sync for ReservedEbrCell<T, Charge> {}

impl<T, Charge> ReservedEbrCell<T, Charge> {
    /// Exact requested layout, including padding and retained charge custody.
    pub fn allocation_layout() -> Layout {
        Layout::new::<Allocation<T, Charge>>()
    }

    /// Allocate physical backing, returning the same charge on allocator refusal.
    /// The caller owns logical admission and nested payload allocation separately.
    pub fn try_new(charge: Charge) -> Result<Self, (Charge, Layout)> {
        let layout = Self::allocation_layout();
        let pointer: NonNull<Allocation<T, Charge>> = if layout.size() == 0 {
            NonNull::dangling()
        } else {
            // SAFETY: sized nonzero layout and the same allocator used on drop.
            let Some(pointer) = NonNull::new(unsafe { std::alloc::alloc(layout) }.cast()) else {
                return Err((charge, layout));
            };
            pointer
        };
        // SAFETY: only the charge becomes initialized. No T reference is formed.
        unsafe {
            std::ptr::addr_of_mut!((*pointer.as_ptr()).frozen_owners).write(AtomicUsize::new(1));
            std::ptr::addr_of_mut!((*pointer.as_ptr()).charge).write(ManuallyDrop::new(charge));
        }
        Ok(Self { pointer })
    }
}

impl<T: Clone + Send + Sync + 'static, Charge: Send + Sync + 'static> ReservedEbrCell<T, Charge> {
    /// Move the original value into its reserved allocation without another allocation.
    pub fn initialize(self, value: T) -> EbrCell<T, Charge> {
        let mut original = self.initialize_owned(value);
        EbrCell {
            write: initialized_writer_mutex(),
            active: Atomic::from(original.data.take().expect("original initialized backing")),
        }
    }

    /// Initialize one original detached generation without a Cell or epoch pin.
    pub fn initialize_owned(self, value: T) -> EbrCellOwned<T, Charge> {
        let original = ManuallyDrop::new(self);
        // SAFETY: unique reserved backing receives its only payload. Owned adopts
        // the same Box-compatible allocation and retains its initialized charge.
        let data = unsafe {
            std::ptr::addr_of_mut!((*original.pointer.as_ptr()).value).write(value);
            Owned::from_raw(original.pointer.as_ptr())
        };
        EbrCellOwned { data: Some(data) }
    }
}

impl<T, Charge> ReservedEbrCell<T, Charge> {
    /// Free unused physical backing and return its unchanged original charge.
    /// No logical capacity is refunded; the caller still owns the same admission.
    pub fn into_charge(self) -> Charge {
        let original = ManuallyDrop::new(self);
        // SAFETY: self was consumed without initializing or exposing its payload.
        unsafe { Self::free_uninitialized(original.pointer) }
    }

    unsafe fn free_uninitialized(pointer: NonNull<Allocation<T, Charge>>) -> Charge {
        // SAFETY: caller uniquely owns uninitialized payload backing with one
        // initialized charge. Read it without forming a reference to an invalid T.
        let charge = unsafe { std::ptr::addr_of!((*pointer.as_ptr()).charge).read() };
        let layout = Self::allocation_layout();
        if layout.size() != 0 {
            // SAFETY: same original physical allocation and exact requested layout.
            unsafe { std::alloc::dealloc(pointer.as_ptr().cast(), layout) };
        }
        ManuallyDrop::into_inner(charge)
    }
}

impl<T, Charge> Drop for ReservedEbrCell<T, Charge> {
    fn drop(&mut self) {
        // SAFETY: this unique unused reservation owns the only live charge.
        drop(unsafe { Self::free_uninitialized(self.pointer) });
    }
}

fn reclaim<T, Charge>(mut allocation: Owned<Allocation<T, Charge>>) {
    // SAFETY: this allocation is uniquely owned, either by an abandoned writer
    // or by the epoch collector after every reader of this generation is gone.
    // Its charge is extracted exactly once and never automatically dropped.
    let charge = unsafe { ManuallyDrop::take(&mut allocation.charge) };
    let charge = ManuallyDrop::new(charge);
    drop(allocation);
    // Releasing only after drop returns also covers the outer allocation free.
    // If T::drop panics, retain the charge rather than claiming reclamation.
    drop(ManuallyDrop::into_inner(charge));
}

unsafe fn defer_reclaim<T: Send + 'static, Charge: Send + 'static>(
    guard: &Guard,
    allocation: Shared<'_, Allocation<T, Charge>>,
) {
    // SAFETY: the caller has unlinked this exact allocation. The epoch guard
    // protects its readers, and both payload and custody may move to the thread
    // that eventually performs collection. Conversion to Owned happens only
    // inside the deferred callback, after the original EBR grace period.
    unsafe {
        guard.defer_unchecked(move || reclaim(allocation.into_owned()));
    }
}

/// Original physical writer acquired before admission, cloning or allocation.
///
/// A poisoned guard remains owned so enclosing aggregates can unlock all of
/// their original guards before cleanup and report the actual physical poison.
#[must_use = "retain this original acquisition until construction or release"]
pub struct EbrCellWriterAcquisition<
    'a,
    T: Clone + Send + Sync + 'static,
    Charge: Send + Sync + 'static = Untracked,
> {
    caller: &'a EbrCell<T, Charge>,
    guard: MutexGuard<'a, ()>,
}

impl<'a, T: Clone + Send + Sync + 'static, Charge: Send + Sync + 'static>
    EbrCellWriterAcquisition<'a, T, Charge>
{
    /// Whether the original lock is poisoned, including before acquisition.
    pub fn is_poisoned(&self) -> bool {
        self.caller.is_poisoned()
    }

    /// Borrow the current value while retaining its sole original physical writer.
    ///
    /// The reference cannot outlive this acquisition. No clone, collector pin,
    /// payload allocation or publication occurs; no mutable reference is exposed.
    ///
    /// # Errors
    /// Refuses original writer poison before exposing its payload.
    ///
    /// ```compile_fail
    /// use concread::ebrcell::EbrCell;
    /// let cell=EbrCell::new(String::from("original"));
    /// let original=cell.try_acquire_writer().unwrap();
    /// let borrowed=original.borrow_current().unwrap();
    /// drop(original);
    /// assert_eq!(borrowed,"original");
    /// ```
    pub fn borrow_current(
        &self,
    ) -> Result<&T, EbrCellWriterAdmissionError<std::convert::Infallible>> {
        if self.is_poisoned() {
            return Err(EbrCellWriterAdmissionError::Poisoned);
        }
        // SAFETY: this acquisition holds the sole original physical writer and
        // borrows its Cell. Replacement and Cell destruction cannot occur; the
        // returned shared reference is bounded by this acquisition's borrow.
        let current = self
            .caller
            .active
            .load(Acquire, unsafe { epoch::unprotected() });
        Ok(&unsafe { current.deref() }.value)
    }

    /// Copy the current value while this original physical writer prevents replacement.
    ///
    /// No clone, payload allocation, collector registration or publication occurs.
    /// A Copy value is returned inline; no reference escapes the acquisition.
    ///
    /// # Errors
    /// Refuses a poisoned original writer before reading its payload.
    pub fn copy_current(&self) -> Result<T, EbrCellWriterAdmissionError<std::convert::Infallible>>
    where
        T: Copy,
    {
        Ok(*self.borrow_current()?)
    }

    /// Admit and clone under this original physical owner, without releasing it.
    /// Refusal returns the same acquisition; success returns its exact private
    /// generation separately. Consuming the acquisition ensures a callee panic
    /// releases and poisons the actual mutex, even if its caller catches unwind.
    /// A Clone panic retains the charge conservatively, as it may leak payloads.
    pub fn try_clone_charged<E>(
        self,
        admit: impl FnOnce(&T, Layout) -> Result<Charge, E>,
    ) -> CloneAdmissionResult<'a, T, Charge, E> {
        if self.is_poisoned() {
            return Err((self, EbrCellWriterAdmissionError::Poisoned));
        }
        // SAFETY: this original writer excludes replacement, and its borrowed
        // cell excludes destruction. The active allocation therefore cannot be
        // unlinked while admission and cloning run; no collector pin is needed.
        let current = self
            .caller
            .active
            .load(Acquire, unsafe { epoch::unprotected() });
        let current = unsafe { current.deref() };
        let charge = match admit(&current.value, EbrCell::<T, Charge>::allocation_layout()) {
            Ok(charge) => ManuallyDrop::new(charge),
            Err(error) => return Err((self, EbrCellWriterAdmissionError::Refused(error))),
        };
        let allocation = Owned::new(Allocation {
            value: current.value.clone(),
            frozen_owners: AtomicUsize::new(1),
            charge,
        });
        Ok((
            self,
            EbrCellOwned {
                data: Some(allocation),
            },
        ))
    }

    /// Clone into already owned backing without allocating an outer generation.
    /// Poison returns both exact original owners. Nested clone allocations remain
    /// the caller's obligation; clone unwind conservatively retains its backing
    /// and charge because user Clone may leak partially constructed payloads.
    pub fn try_clone_reserved(
        self,
        backing: ReservedEbrCell<T, Charge>,
    ) -> Result<
        (Self, EbrCellOwned<T, Charge>),
        (
            Self,
            ReservedEbrCell<T, Charge>,
            EbrCellWriterAdmissionError<std::convert::Infallible>,
        ),
    > {
        if self.is_poisoned() {
            return Err((self, backing, EbrCellWriterAdmissionError::Poisoned));
        }
        // SAFETY: the original physical writer excludes replacement and cell
        // destruction for the complete clone, without pinning the collector.
        let current = self
            .caller
            .active
            .load(Acquire, unsafe { epoch::unprotected() });
        let current = unsafe { current.deref() };
        let backing = ManuallyDrop::new(backing);
        let value = current.value.clone();
        Ok((
            self,
            ManuallyDrop::into_inner(backing).initialize_owned(value),
        ))
    }

    /// Attach an original private generation without cloning or allocating.
    /// Poison returns both exact owners. This grants no predecessor or aggregate
    /// publication authority; the enclosing MV owner must authenticate those.
    pub fn try_write_owned(
        self,
        owned: EbrCellOwned<T, Charge>,
    ) -> Result<EbrCellWriteTxn<'a, T, Charge>, (Self, EbrCellOwned<T, Charge>)> {
        if self.is_poisoned() {
            return Err((self, owned));
        }
        Ok(self.install_owned(owned))
    }

    fn install_owned(self, mut owned: EbrCellOwned<T, Charge>) -> EbrCellWriteTxn<'a, T, Charge> {
        EbrCellWriteTxn {
            data: owned.data.take(),
            caller: self.caller,
            _guard: Some(self.guard),
        }
    }
}

/// Why an acquired EBR writer refused construction before cloning.
#[derive(Debug, PartialEq, Eq)]
pub enum EbrCellWriterAdmissionError<E> {
    /// The original physical writer was already poisoned.
    Poisoned,
    /// The allocation admission policy refused the original generation.
    Refused(E),
}

/// An `EbrCell` Write Transaction handle.
///
/// This allows mutation of the content of the `EbrCell` without blocking or
/// affecting current readers.
///
/// Changes are only stored in the structure until you call commit: to
/// abort a change, don't call commit and allow the write transaction to
/// go out of scope. This causes the `EbrCell` to unlock allowing other
/// writes to proceed.
pub struct EbrCellWriteTxn<
    'a,
    T: 'static + Clone + Send + Sync,
    Charge: Send + Sync + 'static = Untracked,
> {
    data: Option<Owned<Allocation<T, Charge>>>,
    // This way we know who to contact for updating our data ....
    caller: &'a EbrCell<T, Charge>,
    _guard: Option<MutexGuard<'a, ()>>,
}

/// An unpublished generation detached from its writer without cloning payloads.
///
/// This owner retains the exact original allocation and charge, but no cell
/// reference, epoch pin or writer lock. It grants no publication or predecessor
/// authority. An enclosing MV owner must retain and authenticate that identity
/// before installing this generation through [`EbrCell::try_write_owned`].
pub struct EbrCellOwned<T: Clone + Send + Sync + 'static, Charge: Send + Sync + 'static = Untracked>
{
    data: Option<Owned<Allocation<T, Charge>>>,
}

impl<T, Charge> Deref for EbrCellOwned<T, Charge>
where
    T: Clone + Send + Sync + 'static,
    Charge: Send + Sync + 'static,
{
    type Target = T;

    fn deref(&self) -> &T {
        &self.data.as_ref().unwrap().value
    }
}

impl<T, Charge> Drop for EbrCellOwned<T, Charge>
where
    T: Clone + Send + Sync + 'static,
    Charge: Send + Sync + 'static,
{
    fn drop(&mut self) {
        if let Some(allocation) = self.data.take() {
            reclaim(allocation);
        }
    }
}

impl<'a, T, Charge> EbrCellWriteTxn<'a, T, Charge>
where
    T: Clone + Sync + Send + 'static,
    Charge: Send + Sync + 'static,
{
    /// Access a mutable pointer of the data in the `EbrCell`. This data is only
    /// visible to this write transaction object in this thread until you call
    /// 'commit'.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.data.as_mut().unwrap().value
    }

    /// Commit the changes in this write transaction to the `EbrCell`. This will
    /// consume the transaction so that further changes can not be made to it
    /// after this function is called.
    pub fn commit(self) {
        drop(self.prepare_commit().publish().release());
    }

    /// Validate the original writer before beginning an aggregate publication.
    /// This neither pins the epoch collector nor changes the active generation.
    pub fn prepare_commit(self) -> EbrCellPreparedCommit<'a, T, Charge> {
        let mut slot = self.commit_slot();
        slot.prepare();
        slot.into_prepared()
    }

    /// Move the original writer into caller custody before validating it.
    pub fn commit_slot(self) -> EbrCellCommitSlot<'a, T, Charge> {
        EbrCellCommitSlot {
            writer: Some(self),
            ready: false,
        }
    }

    fn validate_commit(&self) {
        assert!(self.data.is_some(), "original unpublished allocation");
        // SAFETY: this writer exclusively prevents replacement of active. Its
        // borrowed cell cannot be destroyed, and active is never null in a live
        // cell. No protected payload reference escapes this ownership phase.
        let active = self
            .caller
            .active
            .load(Acquire, unsafe { epoch::unprotected() });
        assert!(!active.is_null(), "original initialized generation");
    }

    /// Release this writer while retaining its exact unpublished allocation.
    /// No clone, new payload allocation or publication occurs. The returned
    /// owner can cross threads; it does not retain this cell or its lock.
    pub fn detach(mut self) -> EbrCellOwned<T, Charge> {
        EbrCellOwned {
            data: self.data.take(),
        }
    }
}

/// The original EBR writer retained by its caller throughout validation.
/// Construction and preparation do not pin the collector or allocate a payload.
#[must_use = "retain the original writer until aggregate release or publication"]
pub struct EbrCellCommitSlot<'a, T, Charge = Untracked>
where
    T: Clone + Send + Sync + 'static,
    Charge: Send + Sync + 'static,
{
    writer: Option<EbrCellWriteTxn<'a, T, Charge>>,
    ready: bool,
}

impl<'a, T, Charge> EbrCellCommitSlot<'a, T, Charge>
where
    T: Clone + Send + Sync + 'static,
    Charge: Send + Sync + 'static,
{
    /// Validate while the caller continues to own the original physical writer.
    pub fn prepare(&mut self) {
        assert!(!self.ready, "original EBR writer prepares once");
        self.writer
            .as_ref()
            .expect("original EBR writer")
            .validate_commit();
        self.ready = true;
    }

    /// Whether the retained writer has completed validation.
    pub fn is_prepared(&self) -> bool {
        self.ready
    }

    /// Transfer only checked ownership without additional work or callbacks.
    pub fn into_prepared(mut self) -> EbrCellPreparedCommit<'a, T, Charge> {
        assert!(self.ready, "original preparation must complete");
        EbrCellPreparedCommit {
            writer: self.writer.take().expect("original EBR writer"),
        }
    }

    /// Return the exact original writer without publication or reconstruction.
    pub fn abort(mut self) -> EbrCellWriteTxn<'a, T, Charge> {
        self.writer.take().expect("original EBR writer")
    }
}

/// Original validated writer ready for a publication that runs no collector work.
#[must_use = "publish the original writer or abandon its private allocation"]
pub struct EbrCellPreparedCommit<
    'a,
    T: Clone + Send + Sync + 'static,
    Charge: Send + Sync + 'static = Untracked,
> {
    writer: EbrCellWriteTxn<'a, T, Charge>,
}

/// Published generation retaining its physical writer until aggregate release.
#[must_use = "retain this writer until every aggregate component is installed"]
pub struct EbrCellPublished<
    'a,
    T: Clone + Send + Sync + 'static,
    Charge: Send + Sync + 'static = Untracked,
> {
    // Drop order also unlocks before reclamation if the staged owner is abandoned.
    writer: EbrCellWriteTxn<'a, T, Charge>,
    retirement: EbrCellRetirement<T, Charge>,
}

/// Sole unscheduled custody of an unlinked allocation and its original charge.
///
/// No reader can newly acquire this allocation after the publication swap.
/// Existing readers remain protected by their epoch pins. Dropping this owner
/// schedules reclamation only; actual destruction still waits for that grace
/// period. Keep it until all enclosing physical/publication locks are released.
#[must_use = "drop only after releasing all enclosing publication locks"]
pub struct EbrCellRetirement<
    T: Clone + Send + Sync + 'static,
    Charge: Send + Sync + 'static = Untracked,
> {
    allocation: Option<NonNull<Allocation<T, Charge>>>,
}

// SAFETY: this move-only owner never dereferences the unlinked allocation.
// Collection can already execute on any thread, and both payload and charge are
// Send. Its sole pointer is submitted to the collector exactly once on Drop.
unsafe impl<T: Clone + Send + Sync + 'static, Charge: Send + Sync + 'static> Send
    for EbrCellRetirement<T, Charge>
{
}

impl<'a, T: Clone + Send + Sync + 'static, Charge: Send + Sync + 'static>
    EbrCellPreparedCommit<'a, T, Charge>
{
    /// Return the same unpublished writer without allocating or publishing.
    /// Its original exclusive lock remains held for aggregate rollback.
    pub fn abort(self) -> EbrCellWriteTxn<'a, T, Charge> {
        self.writer
    }

    /// Install the already allocated successor, retaining the original writer.
    /// No epoch pin, collector callback, payload clone or user destructor runs.
    pub fn publish(mut self) -> EbrCellPublished<'a, T, Charge> {
        let next = self
            .writer
            .data
            .take()
            .expect("prepared original allocation");
        // SAFETY: the exclusive writer is the only possible unlinker of active.
        // The old pointer is not dereferenced or destroyed here: retirement owns
        // it unscheduled until a real post-unlock pin can defer its reclamation.
        let previous = self
            .writer
            .caller
            .active
            .swap(next, AcqRel, unsafe { epoch::unprotected() });
        EbrCellPublished {
            writer: self.writer,
            retirement: EbrCellRetirement {
                allocation: NonNull::new(previous.as_raw().cast_mut()),
            },
        }
    }
}

impl<T: Clone + Send + Sync + 'static, Charge: Send + Sync + 'static>
    EbrCellPublished<'_, T, Charge>
{
    /// Unlock without reclaiming a payload, refunding a charge, or notifying.
    pub fn release(self) -> EbrCellRetirement<T, Charge> {
        let Self { writer, retirement } = self;
        // The original allocation has moved to active, so writer Drop only
        // releases its physical guard. Retirement remains separately owned.
        drop(writer);
        retirement
    }
}

impl<T: Clone + Send + Sync + 'static, Charge: Send + Sync + 'static> Drop
    for EbrCellRetirement<T, Charge>
{
    fn drop(&mut self) {
        // Pinning may collect unrelated old generations and run arbitrary user
        // destructors. It belongs after physical/publication release. If that
        // cleanup panics, retain the unscheduled allocation/charge conservatively
        // instead of freeing memory still protected by existing reader pins.
        let guard = epoch::pin();
        if let Some(allocation) = self.allocation.take() {
            // SAFETY: this original pointer has been unlinked exactly once and
            // remains unscheduled custody of this owner. The real guard defers
            // conversion to Owned until all readers of the old generation exit.
            unsafe { defer_reclaim(&guard, Shared::from(allocation.as_ptr().cast_const())) };
        }
    }
}

impl<T, Charge> Drop for EbrCellWriteTxn<'_, T, Charge>
where
    T: Clone + Sync + Send + 'static,
    Charge: Send + Sync + 'static,
{
    fn drop(&mut self) {
        // No payload destructor or capacity refund may run under this writer.
        // Aggregates additionally retain the private allocation until every
        // sibling guard releases, using detach rather than sequential Drop.
        drop(self._guard.take());
        if let Some(allocation) = self.data.take() {
            reclaim(allocation);
        }
    }
}

impl<T, Charge> Deref for EbrCellWriteTxn<'_, T, Charge>
where
    T: Clone + Sync + Send,
    Charge: Send + Sync + 'static,
{
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        &self.data.as_ref().unwrap().value
    }
}

impl<T, Charge> DerefMut for EbrCellWriteTxn<'_, T, Charge>
where
    T: Clone + Sync + Send,
    Charge: Send + Sync + 'static,
{
    fn deref_mut(&mut self) -> &mut T {
        self.get_mut()
    }
}

/// A concurrently readable cell.
///
/// This structure behaves in a similar manner to a `RwLock<Box<T>>`. However
/// unlike a read-write lock, writes and parallel reads can be performed
/// simultaneously. This means writes do not block reads or reads do not
/// block writes.
///
/// To achieve this a form of "copy-on-write" (or for Rust, clone on write) is
/// used. As a write transaction begins, we clone the existing data to a new
/// location that is capable of being mutated.
///
/// Readers are guaranteed that the content of the `EbrCell` will live as long
/// as the read transaction is open, and will be consistent for the duration
/// of the transaction. There can be an "unlimited" number of readers in parallel
/// accessing different generations of data of the `EbrCell`.
///
/// Data that is copied is garbage collected using the crossbeam-epoch library.
///
/// Writers are serialised and are guaranteed they have exclusive write access
/// to the structure.
///
/// A cell with a `Charge` type other than [`Untracked`] retains each move-only
/// charge in its actual allocated generation until both the payload and the
/// allocation have been destroyed. Admission precedes cloning, and commit moves
/// the writer's already allocated generation. This is an ownership hook, not a
/// complete heap budget: callers must separately fund nested payload allocations,
/// mutation growth, allocator overhead and epoch collector bookkeeping.
///
/// Charged cells have no unaccounted writer convenience:
/// ```compile_fail
/// use concread::ebrcell::EbrCell;
/// struct Charge;
/// let cell = EbrCell::new_charged(0_u64, Charge);
/// let _writer = cell.write();
/// ```
///
/// # Examples
/// ```
/// use concread::ebrcell::EbrCell;
///
/// let data: i64 = 0;
/// let ebrcell = EbrCell::new(data);
///
/// // Begin a read transaction
/// let read_txn = ebrcell.read();
/// assert_eq!(*read_txn, 0);
/// {
///     // Now create a write, and commit it.
///     let mut write_txn = ebrcell.write();
///     *write_txn = 1;
///     // Commit the change
///     write_txn.commit();
/// }
/// // Show the previous generation still reads '0'
/// assert_eq!(*read_txn, 0);
/// let new_read_txn = ebrcell.read();
/// // And a new read transaction has '1'
/// assert_eq!(*new_read_txn, 1);
/// ```
#[derive(Debug)]
pub struct EbrCell<T: Clone + Sync + Send + 'static, Charge: Send + Sync + 'static = Untracked> {
    write: Mutex<()>,
    active: Atomic<Allocation<T, Charge>>,
}

impl<T> Default for EbrCell<T>
where
    T: Default + Clone + Sync + Send + 'static,
{
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<T> EbrCell<T>
where
    T: Clone + Sync + Send + 'static,
{
    /// Create a new `EbrCell` storing type `T`. `T` must implement `Clone`.
    /// This convenience constructor does not account for resource ownership.
    pub fn new(data: T) -> Self {
        Self::new_charged(data, Untracked)
    }

    /// Begin a write transaction, returning a write guard.
    /// This convenience method is available only in unaccounted mode.
    pub fn write(&self) -> EbrCellWriteTxn<'_, T> {
        match self.write_charged(|_, _| Ok::<_, std::convert::Infallible>(Untracked)) {
            Ok(writer) => writer,
            Err(never) => match never {},
        }
    }

    /// Attempt to begin a write transaction. If it's already held,
    /// `None` is returned.
    /// This convenience method is available only in unaccounted mode.
    pub fn try_write(&self) -> Option<EbrCellWriteTxn<'_, T>> {
        match self.try_write_charged(|_, _| Ok::<_, std::convert::Infallible>(Untracked)) {
            Ok(writer) => writer,
            Err(never) => match never {},
        }
    }
}

impl<T, Charge> EbrCell<T, Charge>
where
    T: Clone + Sync + Send + 'static,
    Charge: Send + Sync + 'static,
{
    /// Acquire only the physical writer, retaining poison without cloning.
    /// No epoch pin, admission callback or successor allocation occurs.
    pub fn acquire_writer(&self) -> EbrCellWriterAcquisition<'_, T, Charge> {
        EbrCellWriterAcquisition {
            caller: self,
            guard: self
                .write
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()),
        }
    }

    /// Try to acquire only the original physical writer.
    /// `None` means contention exclusively; a poisoned lock remains owned.
    pub fn try_acquire_writer(&self) -> Option<EbrCellWriterAcquisition<'_, T, Charge>> {
        let guard = match self.write.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(poison)) => poison.into_inner(),
            Err(TryLockError::WouldBlock) => return None,
        };
        Some(EbrCellWriterAcquisition {
            caller: self,
            guard,
        })
    }

    /// Whether an earlier writer or clone unwound while holding this cell's lock.
    /// A failed nonblocking acquisition on a poisoned cell requires recovery;
    /// waiting for a future release alone cannot make that lock usable.
    pub fn is_poisoned(&self) -> bool {
        self.write.is_poisoned()
    }

    /// The exact layout requested for one allocated payload and its charge.
    ///
    /// This excludes allocations owned by `T` or `Charge`, allocator overhead,
    /// and epoch collector bookkeeping. It is not an estimate of total heap use.
    pub fn allocation_layout() -> Layout {
        Layout::new::<Allocation<T, Charge>>()
    }

    /// Store an already owned value with its prepaid allocation custody.
    ///
    /// The caller must acquire custody before constructing any payload it needs
    /// to fund. This constructor cannot retroactively admit `data`'s allocations.
    /// A charge need not implement `Clone`; it is moved into this exact allocation.
    pub fn new_charged(data: T, charge: Charge) -> Self {
        Self {
            write: initialized_writer_mutex(),
            active: Atomic::new(Allocation {
                value: data,
                frozen_owners: AtomicUsize::new(1),
                charge: ManuallyDrop::new(charge),
            }),
        }
    }

    /// Admit and allocate a writable clone while holding the original writer lock.
    ///
    /// `admit` sees the current value and the exact outer allocation layout before
    /// the payload clone or generation allocation. Refusal leaves the cell unchanged.
    /// The returned charge must cover the intended clone and mutation lifetime;
    /// mutable payload access does not separately measure or admit later growth.
    /// A panic during cloning conservatively retains the charge because `Clone`
    /// may have leaked partially constructed payload allocations.
    pub fn write_charged<E>(
        &self,
        admit: impl FnOnce(&T, Layout) -> Result<Charge, E>,
    ) -> Result<EbrCellWriteTxn<'_, T, Charge>, E> {
        self.write_from_guard(self.write.lock().unwrap(), admit)
    }

    /// Attempt charged admission without waiting for the original writer lock.
    ///
    /// `Ok(None)` means the lock was unavailable or poisoned; in that case
    /// `admit` is never called and no value is cloned. Otherwise this has the same
    /// custody and panic behavior as [`Self::write_charged`].
    pub fn try_write_charged<E>(
        &self,
        admit: impl FnOnce(&T, Layout) -> Result<Charge, E>,
    ) -> Result<Option<EbrCellWriteTxn<'_, T, Charge>>, E> {
        let Ok(mguard) = self.write.try_lock() else {
            return Ok(None);
        };
        self.write_from_guard(mguard, admit).map(Some)
    }

    /// Acquire a writer for an already owned unpublished generation.
    ///
    /// This operation clones no payload and allocates no successor. Contention
    /// or poison returns the exact input owner. It does not compare an original
    /// cell or predecessor: an enclosing MV owner must check its original
    /// publication identity while all required writers are held. As with any
    /// ordinary mutable writer, this method alone grants no application-level
    /// permission to publish the supplied value.
    pub fn try_write_owned(
        &self,
        owner: EbrCellOwned<T, Charge>,
    ) -> Result<EbrCellWriteTxn<'_, T, Charge>, EbrCellOwned<T, Charge>> {
        let Some(acquired) = self.try_acquire_writer() else {
            return Err(owner);
        };
        acquired
            .try_write_owned(owner)
            .map_err(|(acquired, owner)| {
                drop(acquired);
                owner
            })
    }

    fn write_from_guard<'a, E>(
        &'a self,
        mguard: MutexGuard<'a, ()>,
        admit: impl FnOnce(&T, Layout) -> Result<Charge, E>,
    ) -> Result<EbrCellWriteTxn<'a, T, Charge>, E> {
        let acquired = EbrCellWriterAcquisition {
            caller: self,
            guard: mguard,
        };
        match acquired.try_clone_charged(admit) {
            Ok((acquired, owned)) => Ok(acquired.install_owned(owned)),
            Err((_acquired, EbrCellWriterAdmissionError::Poisoned)) => {
                panic!("original writer is poisoned")
            }
            Err((_acquired, EbrCellWriterAdmissionError::Refused(error))) => Err(error),
        }
    }

    /// Check that a retained read still names this cell's current allocation.
    ///
    /// This compares the original protected allocation, not payload equality.
    /// It neither pins the collector nor clones a value. The read's existing
    /// epoch guard protects both pointers from reclamation during comparison.
    /// The caller must retain its joint publication boundary across comparisons
    /// when more than one cell belongs to a single logical observation.
    /// Even an empty payload has a unique allocated ownership header.
    pub fn matches_read(&self, read: &EbrCellReadTxn<T>) -> bool {
        let active = self.active.load(Acquire, &read._guard);
        // SAFETY: a live cell always has an initialized allocation, protected
        // by the exact guard already retained in read. No reference escapes.
        let current = unsafe { &active.deref().value as *const T };
        std::ptr::eq(current, read.data)
    }

    /// Begin a read transaction. The returned [`EbrCellReadTxn`] guarantees
    /// the data lives long enough via crossbeam's Epoch type. When this is
    /// dropped the data *may* be freed at some point in the future.
    pub fn read(&self) -> EbrCellReadTxn<T> {
        let guard = epoch::pin();

        // This option returns None on null pointer, but we can never be null
        // as we have to init with data, and all replacement ALWAYS gives us
        // a ptr, so unwrap?
        let cur = {
            let c = self.active.load(Acquire, &guard);
            // SAFETY: the guard protects this initialized allocation; the read
            // transaction retains that same guard for the payload reference.
            unsafe { &c.deref().value as *const T }
        };

        EbrCellReadTxn {
            _guard: guard,
            data: cur,
        }
    }
}

impl<T, Charge> Drop for EbrCell<T, Charge>
where
    T: Clone + Sync + Send + 'static,
    Charge: Send + Sync + 'static,
{
    fn drop(&mut self) {
        // Right, we are dropping! Everything is okay here *except*
        // that we need to tell our active data to be unlinked, else it may
        // be dropped "unsafely".
        let guard = epoch::pin();

        let prev_data = self.active.load(Acquire, &guard);
        // SAFETY: the cell is exclusively owned during Drop. Existing read
        // transactions remain protected by the same epoch reclamation boundary.
        unsafe { defer_reclaim(&guard, prev_data) };
    }
}

/// A read transaction. This stores a reference to the data from the main
/// `EbrCell`, and guarantees it is alive for the duration of the read.
// #[derive(Debug)]
pub struct EbrCellReadTxn<T> {
    _guard: Guard,
    data: *const T,
}

impl<T> Deref for EbrCellReadTxn<T> {
    type Target = T;

    /// De-reference and access the value within the read transaction.
    fn deref(&self) -> &T {
        unsafe { &(*self.data) }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::EbrCell;
    use std::thread::scope;

    #[cfg(all(feature = "maps", not(feature = "dhat-heap"), not(miri)))]
    #[test]
    fn fresh_original_writer_constructors_need_no_cold_acquisition_allocation() {
        use crate::internals::bptree::node::allocation_tests::without_allocations;
        let ordinary = EbrCell::new(37_u64);
        let reserved = super::ReservedEbrCell::try_new(super::Untracked)
            .unwrap_or_else(|_| panic!("original backing admission"))
            .initialize(41_u64);
        scope(|scope| {
            scope
                .spawn(|| {
                    for (cell, expected) in [(&ordinary, 37), (&reserved, 41)] {
                        let original = without_allocations(|| cell.try_acquire_writer().unwrap());
                        assert_eq!(original.copy_current().unwrap(), expected);
                        without_allocations(|| drop(original));
                    }
                })
                .join()
                .unwrap();
        });
    }

    #[test]
    fn original_writer_copy_never_clones_or_publishes_and_preserves_poison() {
        #[derive(Copy)]
        struct Inline(u64);
        #[expect(
            clippy::non_canonical_clone_impl,
            reason = "observation must use Copy without dispatching adversarial Clone"
        )]
        impl Clone for Inline {
            fn clone(&self) -> Self {
                panic!("Copy observation must not clone")
            }
        }
        let cell = EbrCell::new(Inline(37));
        let original = cell.try_acquire_writer().unwrap();
        assert_eq!(original.copy_current().unwrap().0, 37);
        assert!(cell.try_acquire_writer().is_none());
        drop(original);
        assert_eq!(
            cell.try_acquire_writer().unwrap().copy_current().unwrap().0,
            37
        );
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = cell.try_acquire_writer().unwrap();
            panic!("original writer poison");
        }));
        let original = cell
            .try_acquire_writer()
            .expect("poison retains physical owner");
        assert!(matches!(
            original.copy_current(),
            Err(super::EbrCellWriterAdmissionError::Poisoned)
        ));
    }

    #[test]
    fn test_deref_mut() {
        let data: i64 = 0;
        let cc = EbrCell::new(data);
        {
            /* Take a write txn */
            let mut cc_wrtxn = cc.write();
            *cc_wrtxn = 1;
            cc_wrtxn.commit();
        }
        let cc_rotxn = cc.read();
        assert_eq!(*cc_rotxn, 1);
    }

    #[test]
    fn test_try_write() {
        let data: i64 = 0;
        let cc = EbrCell::new(data);
        /* Take a write txn */
        let cc_wrtxn_a = cc.try_write();
        assert!(cc_wrtxn_a.is_some());
        /* Because we already hold the writ, the second is guaranteed to fail */
        let cc_wrtxn_a = cc.try_write();
        assert!(cc_wrtxn_a.is_none());
    }

    #[test]
    fn test_simple_create() {
        let data: i64 = 0;
        let cc = EbrCell::new(data);

        let cc_rotxn_a = cc.read();
        assert_eq!(*cc_rotxn_a, 0);

        {
            /* Take a write txn */
            let mut cc_wrtxn = cc.write();
            /* Get the data ... */
            {
                let mut_ptr = cc_wrtxn.get_mut();
                /* Assert it's 0 */
                assert_eq!(*mut_ptr, 0);
                *mut_ptr = 1;
                assert_eq!(*mut_ptr, 1);
            }
            assert_eq!(*cc_rotxn_a, 0);

            let cc_rotxn_b = cc.read();
            assert_eq!(*cc_rotxn_b, 0);
            /* The write txn and it's lock is dropped here */
            cc_wrtxn.commit();
        }

        /* Start a new txn and see it's still good */
        let cc_rotxn_c = cc.read();
        assert_eq!(*cc_rotxn_c, 1);
        assert_eq!(*cc_rotxn_a, 0);
    }

    const MAX_TARGET: i64 = 2000;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_multithread_create() {
        use std::time::Instant;

        let start = Instant::now();
        // Create the new ebrcell.
        let data: i64 = 0;
        let cc = EbrCell::new(data);

        assert!(scope(|scope| {
            let cc_ref = &cc;

            let readers: Vec<_> = (0..7)
                .map(|_| {
                    scope.spawn(move || {
                        let mut last_value: i64 = 0;
                        while last_value < MAX_TARGET {
                            let cc_rotxn = cc_ref.read();
                            {
                                assert!(*cc_rotxn >= last_value);
                                last_value = *cc_rotxn;
                            }
                        }
                    })
                })
                .collect();

            let writers: Vec<_> = (0..3)
                .map(|_| {
                    scope.spawn(move || {
                        let mut last_value: i64 = 0;
                        while last_value < MAX_TARGET {
                            let mut cc_wrtxn = cc_ref.write();
                            {
                                let mut_ptr = cc_wrtxn.get_mut();
                                assert!(*mut_ptr >= last_value);
                                last_value = *mut_ptr;
                                *mut_ptr += 1;
                            }
                            cc_wrtxn.commit();
                        }
                    })
                })
                .collect();

            for h in readers.into_iter() {
                h.join().unwrap();
            }
            for h in writers.into_iter() {
                h.join().unwrap();
            }
            true
        }));

        let end = Instant::now();
        print!("Ebr MT create :{:?} ", end - start);
    }

    static GC_COUNT: AtomicUsize = AtomicUsize::new(0);

    #[derive(Debug, Clone)]
    struct TestGcWrapper<T> {
        data: T,
    }

    impl<T> Drop for TestGcWrapper<T> {
        fn drop(&mut self) {
            // Add to the atomic counter ...
            GC_COUNT.fetch_add(1, Ordering::Release);
        }
    }

    fn test_gc_operation_thread(cc: &EbrCell<TestGcWrapper<i64>>) {
        while GC_COUNT.load(Ordering::Acquire) < 50 {
            // thread::sleep(std::time::Duration::from_millis(200));
            {
                let mut cc_wrtxn = cc.write();
                {
                    let mut_ptr = cc_wrtxn.get_mut();
                    mut_ptr.data += 1;
                }
                cc_wrtxn.commit();
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_gc_operation() {
        GC_COUNT.store(0, Ordering::Release);
        let data = TestGcWrapper { data: 0 };
        let cc = EbrCell::new(data);

        assert!(scope(|scope| {
            let cc_ref = &cc;
            let writers: Vec<_> = (0..3)
                .map(|_| {
                    scope.spawn(move || {
                        test_gc_operation_thread(cc_ref);
                    })
                })
                .collect();

            for h in writers.into_iter() {
                h.join().unwrap();
            }
            true
        }));

        assert!(GC_COUNT.load(Ordering::Acquire) >= 50);
    }
}

#[cfg(test)]
mod tests_linear {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::EbrCell;

    static GC_COUNT: AtomicUsize = AtomicUsize::new(0);

    #[derive(Debug, Clone)]
    struct TestGcWrapper<T> {
        data: T,
    }

    impl<T> Drop for TestGcWrapper<T> {
        fn drop(&mut self) {
            // Add to the atomic counter ...
            GC_COUNT.fetch_add(1, Ordering::Release);
        }
    }

    #[test]
    fn test_gc_operation_linear() {
        /*
         * Test if epoch drops in order (or ordered enough).
         * A property required for b+tree with cow is that txn's
         * are dropped in order so that tree states are not invalidated.
         *
         * A -> B -> C
         *
         * If B is dropped, it invalidates nodes copied from A
         * causing the tree to corrupt txn A (and maybe C).
         *
         * EBR due to it's design while it won't drop in order,
         * it drops generationally, in blocks. This is probably
         * good enough. This means that:
         *
         * A -> B -> C .. -> X -> Y
         *
         * EBR will drop in blocks such as:
         *
         * |  g1   |  g2   |  live |
         * A -> B -> C .. -> X -> Y
         *
         * This test is "small" but asserts a basic sanity of drop
         * ordering, but it's not conclusive for b+tree. More testing
         * (likely multi-thread strees test) is needed, or analysis from
         * other EBR developers.
         */
        GC_COUNT.store(0, Ordering::Release);
        let data = TestGcWrapper { data: 0 };
        let cc = EbrCell::new(data);

        // Open a read A.
        let cc_rotxn_a = cc.read();
        // open a write, change and commit
        {
            let mut cc_wrtxn = cc.write();
            {
                let mut_ptr = cc_wrtxn.get_mut();
                mut_ptr.data += 1;
            }
            cc_wrtxn.commit();
        }
        // open a read B.
        let cc_rotxn_b = cc.read();
        // open a write, change and commit
        {
            let mut cc_wrtxn = cc.write();
            {
                let mut_ptr = cc_wrtxn.get_mut();
                mut_ptr.data += 1;
            }
            cc_wrtxn.commit();
        }
        // open a read C
        let cc_rotxn_c = cc.read();

        assert!(GC_COUNT.load(Ordering::Acquire) == 0);

        // drop B
        drop(cc_rotxn_b);

        // gc count should be 0.
        assert!(GC_COUNT.load(Ordering::Acquire) == 0);

        // drop C
        drop(cc_rotxn_c);

        // gc count should be 0
        assert!(GC_COUNT.load(Ordering::Acquire) == 0);

        // drop A
        drop(cc_rotxn_a);

        // gc count should be 2 (A + B, C is still live)
        assert!(GC_COUNT.load(Ordering::Acquire) <= 2);
    }

    #[test]
    fn test_default() {
        EbrCell::<()>::default();
    }
}

#[cfg(test)]
mod staged_commit_tests {
    use super::*;
    use std::sync::{atomic::AtomicUsize, Arc};
    use std::time::{Duration, Instant};

    struct Counts {
        clones: AtomicUsize,
        payloads: [AtomicUsize; 3],
        charges: [AtomicUsize; 3],
    }

    impl Counts {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                clones: AtomicUsize::new(0),
                payloads: std::array::from_fn(|_| AtomicUsize::new(0)),
                charges: std::array::from_fn(|_| AtomicUsize::new(0)),
            })
        }
    }

    struct Payload {
        value: Box<u64>,
        id: usize,
        counts: Arc<Counts>,
    }

    impl Clone for Payload {
        fn clone(&self) -> Self {
            Self {
                value: self.value.clone(),
                id: self.counts.clones.fetch_add(1, AcqRel) + 1,
                counts: Arc::clone(&self.counts),
            }
        }
    }

    impl Drop for Payload {
        fn drop(&mut self) {
            assert_eq!(self.counts.payloads[self.id].fetch_add(1, AcqRel), 0);
        }
    }

    struct Charge {
        id: usize,
        counts: Arc<Counts>,
    }

    impl Drop for Charge {
        fn drop(&mut self) {
            assert_eq!(self.counts.payloads[self.id].load(Acquire), 1);
            assert_eq!(self.counts.charges[self.id].fetch_add(1, AcqRel), 0);
        }
    }

    fn charged(counts: &Arc<Counts>) -> EbrCell<Payload, Charge> {
        EbrCell::new_charged(
            Payload {
                value: Box::new(10),
                id: 0,
                counts: Arc::clone(counts),
            },
            Charge {
                id: 0,
                counts: Arc::clone(counts),
            },
        )
    }

    fn collect_until(mut complete: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !complete() {
            assert!(
                Instant::now() < deadline,
                "original retired allocation was not reclaimed"
            );
            let guard = epoch::pin();
            guard.flush();
            drop(guard);
            std::thread::yield_now();
        }
    }

    #[test]
    fn staged_publication_moves_original_allocation_and_preserves_old_reader_charge() {
        let counts = Counts::new();
        let cell = charged(&counts);
        let old = cell.read();
        let mut writer = cell
            .write_charged(|_, _| {
                Ok::<_, ()>(Charge {
                    id: 1,
                    counts: Arc::clone(&counts),
                })
            })
            .unwrap();
        *writer.value = 11;
        let successor = &**writer.data.as_ref().unwrap() as *const Allocation<Payload, Charge>;
        let original = cell
            .active
            .load(Acquire, unsafe { epoch::unprotected() })
            .as_raw();
        let prepared = writer.prepare_commit();
        assert!(cell.write.try_lock().is_err());
        assert_eq!(
            cell.active
                .load(Acquire, unsafe { epoch::unprotected() })
                .as_raw(),
            original
        );
        let published = prepared.publish();
        assert!(cell.write.try_lock().is_err());
        assert_eq!(
            cell.active
                .load(Acquire, unsafe { epoch::unprotected() })
                .as_raw(),
            successor
        );
        assert_eq!(counts.clones.load(Acquire), 1);
        let retirement = published.release();
        assert!(cell.write.try_lock().is_ok());
        assert_eq!(counts.payloads[0].load(Acquire), 0);
        assert_eq!(counts.charges[0].load(Acquire), 0);
        drop(retirement);
        for _ in 0..8 {
            let guard = epoch::pin();
            guard.flush();
        }
        assert_eq!(*old.value, 10);
        assert_eq!(counts.charges[0].load(Acquire), 0);
        assert_eq!(*cell.read().value, 11);
        drop(old);
        collect_until(|| counts.charges[0].load(Acquire) == 1);
        assert_eq!(counts.charges[1].load(Acquire), 0);
        drop(cell);
        collect_until(|| counts.charges[1].load(Acquire) == 1);
    }

    #[test]
    fn abandoned_prepared_writer_reclaims_only_original_private_allocation() {
        let counts = Counts::new();
        let cell = charged(&counts);
        let writer = cell
            .write_charged(|_, _| {
                Ok::<_, ()>(Charge {
                    id: 1,
                    counts: Arc::clone(&counts),
                })
            })
            .unwrap();
        drop(writer.prepare_commit());
        assert_eq!(counts.clones.load(Acquire), 1);
        assert_eq!(counts.charges[1].load(Acquire), 1);
        assert_eq!(counts.charges[0].load(Acquire), 0);
        assert!(!cell.is_poisoned());
        assert_eq!(*cell.read().value, 10);
        drop(cell);
        collect_until(|| counts.charges[0].load(Acquire) == 1);
    }

    #[test]
    fn published_owner_drop_unlocks_and_retirement_can_move_to_another_thread() {
        let counts = Counts::new();
        let cell = charged(&counts);
        let mut writer = cell
            .write_charged(|_, _| {
                Ok::<_, ()>(Charge {
                    id: 1,
                    counts: Arc::clone(&counts),
                })
            })
            .unwrap();
        *writer.value = 12;
        let retirement = writer.prepare_commit().publish().release();
        assert!(cell.write.try_lock().is_ok());
        std::thread::spawn(move || drop(retirement)).join().unwrap();
        collect_until(|| counts.charges[0].load(Acquire) == 1);
        let mut next = cell
            .write_charged(|_, _| {
                Ok::<_, ()>(Charge {
                    id: 2,
                    counts: Arc::clone(&counts),
                })
            })
            .unwrap();
        *next.value = 13;
        // Abandoning the already published stage follows the same field order:
        // physical writer first, then the unscheduled old-generation retirement.
        drop(next.prepare_commit().publish());
        assert!(cell.write.try_lock().is_ok());
        assert_eq!(counts.clones.load(Acquire), 2);
        assert_eq!(*cell.read().value, 13);
        drop(cell);
        collect_until(|| {
            counts.charges[1].load(Acquire) == 1 && counts.charges[2].load(Acquire) == 1
        });
    }
}

#[cfg(test)]
#[path = "acquisition_tests.rs"]
mod acquisition_tests;

#[cfg(test)]
mod commit_slot_tests;

#[cfg(test)]
#[path = "original_read_tests.rs"]
mod original_read_tests;
