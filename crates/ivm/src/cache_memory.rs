//! Allocation-owned accounting shared by IVM and Core preparation/runtime caches.
//!
//! Admission is nonblocking: allocations which cannot enter the retention budget
//! remain active and usable. Eviction drops a cache reference; it cannot refund
//! memory still owned by an executing VM or another borrower.
//!
//! Payload owners and retained index capacities share one admission budget.
//! Cache control, shard arrays and eviction-registry allocations remain active
//! infrastructure even when retention is disabled.
//! TODO: Complete active scratch ownership/admission and classify composite
//! retained owners before claiming complete process-memory accounting. Active invocation
//! scratch reports an explicitly unmeasured footprint until a VM returns to its
//! pool.
//! Allocator bookkeeping and fragmentation are not included.

use std::{
    ops::{Deref, DerefMut},
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    },
};

#[cfg(test)]
std::thread_local! {
    static REFUSE_OWNED_ALLOCATION_AFTER: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static REFUSE_NEXT_OWNED_VEC_GROWTH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static REFUSE_NEXT_SHARED_ALLOCATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn refuse_next_owned_vec_growth_for_test() {
    REFUSE_NEXT_OWNED_VEC_GROWTH.set(true);
}

/// Refuse one fixed payload after its allocation-lifetime charge is reserved.
#[cfg(test)]
pub(crate) fn refuse_next_owned_allocation_for_test() {
    REFUSE_OWNED_ALLOCATION_AFTER.set(Some(0));
}

/// Refuse a payload after this many successful fixed-payload allocations.
#[cfg(test)]
pub(crate) fn refuse_owned_allocation_after_for_test(successes: usize) {
    REFUSE_OWNED_ALLOCATION_AFTER.set(Some(successes));
}

/// Inject one thread-local physical allocation refusal, restoring any outer scope.
#[cfg(test)]
pub(crate) fn with_refused_shared_allocation_for_test<T>(operation: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            REFUSE_NEXT_SHARED_ALLOCATION.set(self.0);
        }
    }
    let _restore = Restore(REFUSE_NEXT_SHARED_ALLOCATION.replace(true));
    operation()
}

mod reg_log_owner;
pub(crate) use reg_log_owner::SharedRegLog;

pub(crate) mod strong_owner;
use strong_owner::StrongOwner;

const DEFAULT_RETENTION_BYTES: usize = 64 * 1024 * 1024;

/// Memory charged to cache allocation owners, including evicted borrowers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryStats {
    /// Configured aggregate retention limit. Zero disables retention.
    pub limit_bytes: usize,
    /// Bytes admitted to retention and not yet destroyed.
    ///
    /// This can exceed a newly reduced limit while existing borrowers are alive.
    pub retained_bytes: usize,
    /// Retained shared allocations held only by cache entries and immediately reclaimable.
    pub shared_reclaimable_bytes: usize,
    /// Retained shared allocations with both cache entries and other borrowers.
    pub shared_borrowed_bytes: usize,
    /// Retained shared allocations whose cache entry was evicted while a borrower lives.
    pub shared_evicted_live_bytes: usize,
    /// Bytes used by allocations that have not been admitted to retention.
    pub active_bytes: usize,
    /// Cold metadata owners whose dynamic footprint could not be measured.
    ///
    /// Such owners cannot enter retention. When nonzero, `active_bytes` includes
    /// only their measured portions and is not a complete active-memory total.
    pub unmeasured_active_owners: usize,
    /// High-water mark of measured allocation-owner reservations.
    ///
    /// This is requested storage, including conservative conversion-overlap
    /// precharges, not process RSS. It excludes the unknown dynamic portions of
    /// `unmeasured_active_owners`.
    pub peak_reserved_bytes: usize,
}

impl MemoryStats {
    /// Measured bytes whose allocation owners are still alive.
    pub fn measured_resident_bytes(self) -> usize {
        self.active_bytes
            .checked_add(self.retained_bytes)
            .expect("measured allocation total fits host address space")
    }

    /// Retained allocations whose cache/borrower ownership is not classified yet.
    pub fn unclassified_retained_bytes(self) -> usize {
        self.retained_bytes
            - self.shared_reclaimable_bytes
            - self.shared_borrowed_bytes
            - self.shared_evicted_live_bytes
    }

    fn record_peak(&mut self) {
        self.peak_reserved_bytes = self.peak_reserved_bytes.max(self.measured_resident_bytes());
    }

    fn shared_class_counter_mut(&mut self, class: RetainedClass) -> Option<&mut usize> {
        match class {
            RetainedClass::Unclassified => None,
            RetainedClass::Reclaimable => Some(&mut self.shared_reclaimable_bytes),
            RetainedClass::Borrowed => Some(&mut self.shared_borrowed_bytes),
            RetainedClass::EvictedLive => Some(&mut self.shared_evicted_live_bytes),
        }
    }
}

#[derive(Clone, Debug)]
struct MemoryBudget(Arc<Mutex<MemoryStats>>);

impl MemoryBudget {
    fn new(limit_bytes: usize) -> Self {
        Self(Arc::new(Mutex::new(MemoryStats {
            limit_bytes,
            ..MemoryStats::default()
        })))
    }

    fn reserve(&self, bytes: usize) -> MemoryReservation {
        let mut stats = self.0.lock().expect("memory accounting lock");
        let active_bytes = stats
            .active_bytes
            .checked_add(bytes)
            .expect("measured allocation total fits host address space");
        let _total_bytes = active_bytes
            .checked_add(stats.retained_bytes)
            .expect("measured allocation total fits host address space");
        stats.active_bytes = active_bytes;
        stats.record_peak();
        drop(stats);
        MemoryReservation {
            budget: self.clone(),
            bytes,
            retained: AtomicBool::new(false),
            unmeasured: false,
            shared_handles: AtomicUsize::new(0),
            cache_handles: AtomicUsize::new(0),
            ever_cache_held: AtomicBool::new(false),
            shared_tracked: AtomicBool::new(false),
            retained_class: AtomicU8::new(RetainedClass::Unclassified as u8),
        }
    }

    fn set_limit(&self, limit_bytes: usize) {
        self.0.lock().expect("memory accounting lock").limit_bytes = limit_bytes;
    }

    fn stats(&self) -> MemoryStats {
        *self.0.lock().expect("memory accounting lock")
    }
}

fn global_budget() -> &'static MemoryBudget {
    static BUDGET: OnceLock<MemoryBudget> = OnceLock::new();
    BUDGET.get_or_init(|| MemoryBudget::new(DEFAULT_RETENTION_BYTES))
}

/// Snapshot of the aggregate cache-allocation budget.
pub fn memory_stats() -> MemoryStats {
    global_budget().stats()
}

pub(crate) fn set_retention_limit(bytes: usize) {
    global_budget().set_limit(bytes);
}

type EvictionCallback = dyn Fn() + Send + Sync;
struct EvictionSlot {
    callback: Weak<EvictionCallback>,
    // A Weak keeps the Arc allocation alive after its payload is dropped. The
    // accompanying charge therefore follows the registry slot as well.
    allocation: Arc<MemoryReservation>,
}
fn eviction_callbacks() -> &'static Mutex<OwnedVec<EvictionSlot>> {
    static CALLBACKS: OnceLock<Mutex<OwnedVec<EvictionSlot>>> = OnceLock::new();
    CALLBACKS.get_or_init(Mutex::default)
}

/// Keeps an idle-cache eviction callback registered for the owner's lifetime.
#[derive(Clone)]
pub struct CacheEvictionRegistration {
    _callback: Arc<EvictionCallback>,
    _allocation: Arc<MemoryReservation>,
}

impl std::fmt::Debug for CacheEvictionRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CacheEvictionRegistration")
            .finish_non_exhaustive()
    }
}

fn arc_allocation_bytes<T: ?Sized>(value: &T) -> usize {
    std::alloc::Layout::new::<(usize, usize)>()
        .extend(std::alloc::Layout::for_value(value))
        .expect("Arc allocation layout fits host address space")
        .0
        .pad_to_align()
        .size()
}

/// Register a callback which drops idle retained references after budget shrink.
///
/// The callback must not capture its cache strongly or wait for active execution.
/// It runs after the accounting mutex is released and may evict borrowed owners;
/// those allocations keep their reservations until their final borrower drops.
pub fn register_cache_evictor(
    callback: impl Fn() + Send + Sync + 'static,
) -> CacheEvictionRegistration {
    let mut memory = MemoryReservation::active(arc_allocation_bytes(&callback));
    memory.set_known_bytes(memory.bytes() + arc_allocation_bytes(&memory));
    let allocation = Arc::new(memory);
    let callback: Arc<EvictionCallback> = Arc::new(callback);
    let mut callbacks = eviction_callbacks()
        .lock()
        .expect("cache eviction registry lock");
    callbacks
        .values
        .retain(|entry| entry.callback.strong_count() != 0);
    callbacks
        .try_push(EvictionSlot {
            callback: Arc::downgrade(&callback),
            allocation: Arc::clone(&allocation),
        })
        .expect("cache eviction registry allocation");
    CacheEvictionRegistration {
        _callback: callback,
        _allocation: allocation,
    }
}

pub(crate) fn evict_registered_caches() {
    let callbacks = {
        let mut registry = eviction_callbacks()
            .lock()
            .expect("cache eviction registry lock");
        registry
            .values
            .retain(|entry| entry.callback.strong_count() != 0);
        let mut callbacks = OwnedVec::default();
        for entry in registry.iter() {
            if let Some(callback) = entry.callback.upgrade() {
                callbacks
                    .try_push((callback, Arc::clone(&entry.allocation)))
                    .expect("cache eviction snapshot allocation");
            }
        }
        callbacks
    };
    for (callback, _) in callbacks.iter() {
        callback();
    }
}

/// A charge whose lifetime must match the allocation it describes.
///
/// Keep this inside the shared allocation owner, never in a cache entry or a
/// borrower's handle. Cold allocations remain active even when retention is full.
#[derive(Debug)]
pub struct MemoryReservation {
    budget: MemoryBudget,
    bytes: usize,
    retained: AtomicBool,
    unmeasured: bool,
    shared_handles: AtomicUsize,
    cache_handles: AtomicUsize,
    ever_cache_held: AtomicBool,
    shared_tracked: AtomicBool,
    retained_class: AtomicU8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum RetainedClass {
    Unclassified,
    Reclaimable,
    Borrowed,
    EvictedLive,
}

impl RetainedClass {
    fn from_byte(value: u8) -> Self {
        match value {
            1 => Self::Reclaimable,
            2 => Self::Borrowed,
            3 => Self::EvictedLive,
            _ => Self::Unclassified,
        }
    }
}

impl MemoryReservation {
    fn register_shared_initial(&self) {
        let _stats = self.budget.0.lock().expect("memory accounting lock");
        assert!(!self.shared_tracked.swap(true, Ordering::Relaxed));
        self.shared_handles.store(1, Ordering::Relaxed);
    }

    fn add_shared_handle(&self, cache_handle: bool) {
        let mut stats = self.budget.0.lock().expect("memory accounting lock");
        assert!(self.shared_tracked.load(Ordering::Relaxed));
        self.shared_handles.fetch_add(1, Ordering::Relaxed);
        if cache_handle {
            self.cache_handles.fetch_add(1, Ordering::Relaxed);
            self.ever_cache_held.store(true, Ordering::Relaxed);
        }
        self.refresh_retained_class(&mut stats);
    }

    fn promote_shared_cache_handle(&self) {
        let mut stats = self.budget.0.lock().expect("memory accounting lock");
        assert!(self.shared_tracked.load(Ordering::Relaxed));
        self.cache_handles.fetch_add(1, Ordering::Relaxed);
        self.ever_cache_held.store(true, Ordering::Relaxed);
        self.refresh_retained_class(&mut stats);
    }

    fn remove_shared_handle(&self, cache_handle: bool) {
        let mut stats = self.budget.0.lock().expect("memory accounting lock");
        assert!(self.shared_tracked.load(Ordering::Relaxed));
        if cache_handle {
            assert!(self.cache_handles.fetch_sub(1, Ordering::Relaxed) > 0);
        }
        assert!(self.shared_handles.fetch_sub(1, Ordering::Relaxed) > 0);
        self.refresh_retained_class(&mut stats);
    }

    fn refresh_retained_class(&self, stats: &mut MemoryStats) {
        let previous = RetainedClass::from_byte(self.retained_class.load(Ordering::Relaxed));
        let next = if !self.retained.load(Ordering::Relaxed)
            || !self.shared_tracked.load(Ordering::Relaxed)
        {
            RetainedClass::Unclassified
        } else {
            let cache = self.cache_handles.load(Ordering::Relaxed);
            let handles = self.shared_handles.load(Ordering::Relaxed);
            // The final handle is removed before its Arc payload is destroyed.
            // Its reservation remains live during teardown, but no borrower does.
            if handles == 0 {
                RetainedClass::Unclassified
            } else if cache == 0 && self.ever_cache_held.load(Ordering::Relaxed) {
                RetainedClass::EvictedLive
            } else if cache == 0 {
                RetainedClass::Unclassified
            } else if cache == handles {
                RetainedClass::Reclaimable
            } else {
                RetainedClass::Borrowed
            }
        };
        if previous == next {
            return;
        }
        if let Some(bytes) = stats.shared_class_counter_mut(previous) {
            *bytes -= self.bytes;
        }
        if let Some(bytes) = stats.shared_class_counter_mut(next) {
            *bytes = bytes
                .checked_add(self.bytes)
                .expect("shared retained allocation total fits host address space");
        }
        self.retained_class.store(next as u8, Ordering::Relaxed);
    }

    /// Account for a new active allocation without waiting for retention space.
    pub fn active(bytes: usize) -> Self {
        global_budget().reserve(bytes)
    }

    pub(crate) fn active_unmeasured(bytes: usize) -> Self {
        let mut reservation = Self::active(bytes);
        reservation.unmeasured = true;
        reservation
            .budget
            .0
            .lock()
            .expect("memory accounting lock")
            .unmeasured_active_owners += 1;
        reservation
    }

    /// Attempt to admit this allocation to the aggregate retention budget.
    ///
    /// Admission never waits for borrowers to release memory. Repeated admission
    /// of the same owner does not charge it again.
    pub fn try_retain(&self) -> bool {
        let mut stats = self.budget.0.lock().expect("memory accounting lock");
        if stats.limit_bytes == 0 || self.unmeasured {
            return false;
        }
        if self.retained.load(Ordering::Relaxed) {
            return true;
        }
        if self.bytes > stats.limit_bytes.saturating_sub(stats.retained_bytes) {
            return false;
        }
        stats.active_bytes -= self.bytes;
        stats.retained_bytes += self.bytes;
        self.retained.store(true, Ordering::Relaxed);
        self.refresh_retained_class(&mut stats);
        true
    }

    /// Number of bytes charged to this owner.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Move a uniquely owned cached allocation into active execution accounting.
    ///
    /// Shared immutable owners must keep their retention charge while borrowed.
    pub(crate) fn make_active(&self) {
        let mut stats = self.budget.0.lock().expect("memory accounting lock");
        if self.retained.swap(false, Ordering::Relaxed) {
            stats.retained_bytes -= self.bytes;
            stats.active_bytes += self.bytes;
            self.refresh_retained_class(&mut stats);
        }
    }

    fn resize_active(&mut self, bytes: usize) {
        let mut stats = self.budget.0.lock().expect("memory accounting lock");
        let was_retained = self.retained.load(Ordering::Relaxed);
        let active_without_self = if was_retained {
            stats.active_bytes
        } else {
            stats.active_bytes - self.bytes
        };
        let retained_without_self = if was_retained {
            stats.retained_bytes - self.bytes
        } else {
            stats.retained_bytes
        };
        let active_bytes = active_without_self
            .checked_add(bytes)
            .expect("measured allocation total fits host address space");
        let _total_bytes = active_bytes
            .checked_add(retained_without_self)
            .expect("measured allocation total fits host address space");
        self.retained.store(false, Ordering::Relaxed);
        self.refresh_retained_class(&mut stats);
        self.bytes = bytes;
        stats.active_bytes = active_bytes;
        stats.retained_bytes = retained_without_self;
        stats.record_peak();
    }

    /// Update the complete footprint of a uniquely owned mutable allocation.
    ///
    /// The owner must call this after a capacity change and before retention.
    /// Shared owners must instead attach separate reservations to new allocations.
    pub fn set_known_bytes(&mut self, bytes: usize) {
        self.resize_active(bytes);
        if self.unmeasured {
            self.budget
                .0
                .lock()
                .expect("memory accounting lock")
                .unmeasured_active_owners -= 1;
            self.unmeasured = false;
        }
    }

    /// Clear an unmeasured mark on an owner whose footprint never changes.
    ///
    /// Fixed-size owners keep their charged byte count while unmeasured, so the
    /// existing charge is the full measure. Measured or retained owners are
    /// left untouched.
    pub(crate) fn remeasure_fixed(&mut self) {
        if self.unmeasured {
            self.set_known_bytes(self.bytes);
        }
    }

    /// Mark a mutable owner's dynamic footprint as unknown during active work.
    ///
    /// Retention remains disabled until `set_known_bytes` supplies a full measure.
    pub fn mark_unmeasured(&mut self) {
        self.make_active();
        if !self.unmeasured {
            self.budget
                .0
                .lock()
                .expect("memory accounting lock")
                .unmeasured_active_owners += 1;
            self.unmeasured = true;
        }
    }
}

impl Drop for MemoryReservation {
    fn drop(&mut self) {
        let mut stats = self.budget.0.lock().expect("memory accounting lock");
        let was_retained = self.retained.swap(false, Ordering::Relaxed);
        self.refresh_retained_class(&mut stats);
        if was_retained {
            stats.retained_bytes -= self.bytes;
        } else {
            stats.active_bytes -= self.bytes;
        }
        if self.unmeasured {
            stats.unmeasured_active_owners -= 1;
        }
    }
}

mod shared_allocation;
#[cfg(test)]
use shared_allocation::Allocation;
pub use shared_allocation::SharedAllocation;

#[derive(Debug)]
struct ValueAllocation<T> {
    value: T,
    reservation: MemoryReservation,
}

/// Shared immutable metadata with an allocation-owned footprint.
#[derive(Debug)]
pub struct SharedValue<T>(StrongOwner<ValueAllocation<T>>, bool);

impl<T> SharedValue<T> {
    /// Own an immutable value and its complete dynamic allocation footprint.
    ///
    /// `heap_bytes` must include capacity and nested allocations owned by `value`,
    /// excluding its inline size, which is added here. Use `None` for an unknown
    /// footprint; unknown values remain usable but cannot enter retention.
    pub fn new(value: T, heap_bytes: Option<usize>) -> Self {
        Self::with_budget(value, heap_bytes, global_budget())
    }

    fn with_budget(value: T, heap_bytes: Option<usize>, budget: &MemoryBudget) -> Self {
        let owner_bytes = std::alloc::Layout::new::<(usize, usize)>()
            .extend(std::alloc::Layout::new::<ValueAllocation<T>>())
            .expect("shared metadata owner layout fits")
            .0
            .pad_to_align()
            .size();
        let measured_bytes = heap_bytes.and_then(|bytes| bytes.checked_add(owner_bytes));
        let bytes = measured_bytes.unwrap_or(owner_bytes);
        let mut reservation = budget.reserve(bytes);
        if measured_bytes.is_none() {
            reservation.mark_unmeasured();
        }
        let owner = Self(
            StrongOwner::new(ValueAllocation { value, reservation }),
            false,
        );
        owner.0.reservation.register_shared_initial();
        owner
    }

    /// Whether two handles identify the same immutable allocation owner.
    #[must_use]
    pub fn ptr_eq(left: &Self, right: &Self) -> bool {
        StrongOwner::ptr_eq(&left.0, &right.0)
    }

    /// Complete charged footprint, or `None` while nested storage is unmeasured.
    #[must_use]
    pub fn allocation_bytes(&self) -> Option<usize> {
        (!self.0.reservation.unmeasured).then_some(self.0.reservation.bytes())
    }

    /// Attempt nonblocking admission of this shared owner to the retention budget.
    pub fn try_retain(&self) -> bool {
        self.0.reservation.try_retain()
    }

    /// Keep the value alive for one synchronous operation of this handle's holder.
    ///
    /// Unlike [`Clone::clone`], the returned strong reference registers no
    /// borrower and therefore takes no process-wide accounting lock. The holder
    /// keeps its own registered handle for the whole operation, so retention
    /// classification is unchanged. Drop the transient reference before that
    /// operation returns; never store, measure or retain it. Should it outlive
    /// every registered handle anyway, it only keeps the allocation and its
    /// charge alive until its own final release.
    pub(crate) fn transient(&self) -> TransientValue<T> {
        TransientValue(self.0.clone())
    }

    /// Clone one cache-held reference; ordinary clones remain borrower references.
    pub fn cache_clone(&self) -> Self {
        self.0.reservation.add_shared_handle(true);
        Self(self.0.clone(), true)
    }

    /// Transfer this reference into a cache without copying the allocation.
    pub fn into_cache_owner(mut self) -> Self {
        if !self.1 {
            self.0.reservation.promote_shared_cache_handle();
            self.1 = true;
        }
        self
    }
}

impl<T> Clone for SharedValue<T> {
    fn clone(&self) -> Self {
        self.0.reservation.add_shared_handle(false);
        Self(self.0.clone(), false)
    }
}

/// Unregistered strong reference returned by [`SharedValue::transient`].
pub(crate) struct TransientValue<T>(StrongOwner<ValueAllocation<T>>);

impl<T> Deref for TransientValue<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0.value
    }
}

impl<T> Drop for SharedValue<T> {
    fn drop(&mut self) {
        self.0.reservation.remove_shared_handle(self.1);
    }
}

impl<T> Deref for SharedValue<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0.value
    }
}

impl<T> AsRef<T> for SharedValue<T> {
    fn as_ref(&self) -> &T {
        self
    }
}

/// A uniquely owned fixed-size allocation, independently charged on cloning.
/// Inline wrapper bytes belong to the enclosing allocation's reservation.
#[derive(Debug)]
pub(crate) struct OwnedAllocation<T> {
    values: Box<[T]>,
    reservation: MemoryReservation,
}

impl<T> From<Vec<T>> for OwnedAllocation<T> {
    fn from(values: Vec<T>) -> Self {
        let values = values.into_boxed_slice();
        let bytes = std::mem::size_of_val(values.as_ref());
        Self {
            values,
            reservation: MemoryReservation::active(bytes),
        }
    }
}

impl<T: Clone> Clone for OwnedAllocation<T> {
    fn clone(&self) -> Self {
        let reservation = self
            .reservation
            .budget
            .reserve(std::mem::size_of_val(self.values.as_ref()));
        Self {
            values: self.values.to_vec().into_boxed_slice(),
            reservation,
        }
    }
}

impl<T> OwnedAllocation<T> {
    pub(crate) fn try_retain(&self) -> bool {
        self.reservation.try_retain()
    }

    pub(crate) fn make_active(&self) {
        self.reservation.make_active();
    }

    pub(crate) fn mark_unmeasured(&mut self) {
        self.reservation.mark_unmeasured();
    }

    /// Restore the exact measure of this fixed-size allocation after active work.
    pub(crate) fn remeasure_fixed(&mut self) {
        self.reservation.remeasure_fixed();
    }
}

impl<T: Copy> OwnedAllocation<T> {
    pub(crate) fn try_filled_copy(len: usize, value: T) -> Result<Self, crate::error::VMError> {
        Self::try_filled_copy_with_budget(len, value, global_budget())
    }

    fn try_filled_copy_with_budget(
        len: usize,
        value: T,
        budget: &MemoryBudget,
    ) -> Result<Self, crate::error::VMError> {
        use crate::error::{ExecutionDeferral, VMError};

        let bytes = len
            .checked_mul(std::mem::size_of::<T>())
            .ok_or(VMError::ExecutionDeferred(
                ExecutionDeferral::AllocationUnavailable,
            ))?;
        if bytes > isize::MAX as usize {
            return Err(VMError::ExecutionDeferred(
                ExecutionDeferral::AllocationUnavailable,
            ));
        }
        let mut reservation = budget.reserve(bytes);
        #[cfg(test)]
        if REFUSE_OWNED_ALLOCATION_AFTER.with(|refuse| match refuse.get() {
            Some(0) => {
                refuse.set(None);
                true
            }
            Some(remaining) => {
                refuse.set(Some(remaining - 1));
                false
            }
            None => false,
        }) {
            return Err(VMError::ExecutionDeferred(
                ExecutionDeferral::AllocationUnavailable,
            ));
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(len)
            .map_err(|_| VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable))?;
        let vec_bytes = values
            .capacity()
            .checked_mul(std::mem::size_of::<T>())
            .expect("allocated Vec fits host address space");
        reservation.set_known_bytes(vec_bytes);
        values.resize(len, value);
        // `into_boxed_slice` may hold the Vec and exact-sized Box at once.
        // Prepay that overlap, then reconcile the final owner's exact size.
        reservation.set_known_bytes(
            vec_bytes
                .checked_add(bytes)
                .expect("two addressable allocations fit host address space"),
        );
        let values = values.into_boxed_slice();
        reservation.set_known_bytes(bytes);
        Ok(Self {
            values,
            reservation,
        })
    }
}

impl OwnedAllocation<u8> {
    pub(crate) fn try_zeroed(len: usize) -> Result<Self, std::collections::TryReserveError> {
        Self::try_zeroed_with_budget(len, global_budget())
    }

    fn try_zeroed_with_budget(
        len: usize,
        budget: &MemoryBudget,
    ) -> Result<Self, std::collections::TryReserveError> {
        let mut reservation = budget.reserve(len);
        let mut values = Vec::new();
        values.try_reserve_exact(len)?;
        let vec_bytes = values.capacity();
        reservation.set_known_bytes(vec_bytes);
        values.resize(len, 0);
        // Account for a possible second allocation before Box conversion.
        reservation.set_known_bytes(
            vec_bytes
                .checked_add(len)
                .expect("two addressable allocations fit host address space"),
        );
        let values = values.into_boxed_slice();
        reservation.set_known_bytes(len);
        Ok(Self {
            values,
            reservation,
        })
    }
}

impl<T> Deref for OwnedAllocation<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.values
    }
}

impl<T> DerefMut for OwnedAllocation<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.values
    }
}

/// A growable allocation which keeps spare capacity charged until it is freed.
#[derive(Debug)]
pub(crate) struct OwnedVec<T> {
    values: Vec<T>,
    reservation: MemoryReservation,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OwnedVecGrowthError {
    CapacityOverflow,
    AllocationUnavailable,
}

fn owned_vec_growth<T>(capacity: usize) -> Result<(usize, usize), OwnedVecGrowthError> {
    let next_capacity = capacity
        .checked_mul(2)
        .ok_or(OwnedVecGrowthError::CapacityOverflow)?
        .max(4);
    let bytes = std::alloc::Layout::array::<T>(next_capacity)
        .map_err(|_| OwnedVecGrowthError::CapacityOverflow)?
        .size();
    Ok((next_capacity, bytes))
}

impl<T> Default for OwnedVec<T> {
    fn default() -> Self {
        Self::from(Vec::new())
    }
}

impl<T> From<Vec<T>> for OwnedVec<T> {
    fn from(values: Vec<T>) -> Self {
        let bytes = values.capacity() * std::mem::size_of::<T>();
        Self {
            values,
            reservation: MemoryReservation::active(bytes),
        }
    }
}

impl<T: Clone> Clone for OwnedVec<T> {
    fn clone(&self) -> Self {
        let mut reservation = self
            .reservation
            .budget
            .reserve(self.values.len() * std::mem::size_of::<T>());
        let values = self.values.clone();
        reservation.set_known_bytes(values.capacity() * std::mem::size_of::<T>());
        Self {
            values,
            reservation,
        }
    }
}

impl<T> OwnedVec<T> {
    fn try_with_capacity_in_budget(
        capacity: usize,
        budget: &MemoryBudget,
    ) -> Result<Self, OwnedVecGrowthError> {
        let bytes = std::alloc::Layout::array::<T>(capacity)
            .map_err(|_| OwnedVecGrowthError::CapacityOverflow)?
            .size();
        let mut reservation = budget.reserve(bytes);
        #[cfg(test)]
        if capacity != 0 && REFUSE_NEXT_OWNED_VEC_GROWTH.with(|refuse| refuse.replace(false)) {
            return Err(OwnedVecGrowthError::AllocationUnavailable);
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(capacity)
            .map_err(|_| OwnedVecGrowthError::AllocationUnavailable)?;
        reservation.set_known_bytes(values.capacity() * std::mem::size_of::<T>());
        Ok(Self {
            values,
            reservation,
        })
    }

    /// Reserve empty copy storage from this owner's existing accounting budget.
    pub(crate) fn try_copy_capacity(&self, capacity: usize) -> Result<Self, OwnedVecGrowthError> {
        Self::try_with_capacity_in_budget(capacity, &self.reservation.budget)
    }

    /// Copy one fixed payload with the same real accounting owner as these rows.
    pub(crate) fn try_copy_bytes(
        &self,
        bytes: &[u8],
    ) -> Result<OwnedAllocation<u8>, crate::VMError> {
        let mut copied =
            OwnedAllocation::try_filled_copy_with_budget(bytes.len(), 0, &self.reservation.budget)?;
        copied.copy_from_slice(bytes);
        Ok(copied)
    }

    pub(crate) fn capacity(&self) -> usize {
        self.values.capacity()
    }

    pub(crate) fn try_reserve_one(&mut self) -> Result<(), OwnedVecGrowthError> {
        if self.values.len() < self.values.capacity() {
            return Ok(());
        }
        let old_bytes = self.reservation.bytes();
        let (capacity, bytes) = owned_vec_growth::<T>(self.values.capacity())?;
        // Vec may hold its old and replacement buffers at the same time.
        // Keep both charged until the allocator completes the growth.
        let overlap_bytes = old_bytes
            .checked_add(bytes)
            .ok_or(OwnedVecGrowthError::CapacityOverflow)?;
        self.reservation.resize_active(overlap_bytes);
        #[cfg(test)]
        if REFUSE_NEXT_OWNED_VEC_GROWTH.with(|refuse| refuse.replace(false)) {
            self.reservation.resize_active(old_bytes);
            return Err(OwnedVecGrowthError::AllocationUnavailable);
        }
        if self
            .values
            .try_reserve_exact(capacity - self.values.len())
            .is_err()
        {
            self.reservation.resize_active(old_bytes);
            return Err(OwnedVecGrowthError::AllocationUnavailable);
        }
        self.reservation
            .resize_active(self.values.capacity() * std::mem::size_of::<T>());
        Ok(())
    }

    pub(crate) fn insert_reserved(&mut self, index: usize, value: T) {
        assert!(self.values.len() < self.values.capacity());
        self.values.insert(index, value);
    }

    #[cfg(test)]
    pub(crate) fn remove_at(&mut self, index: usize) -> T {
        self.values.remove(index)
    }

    pub(crate) fn remove_range(&mut self, range: std::ops::Range<usize>) {
        self.values.drain(range);
    }

    #[cfg(test)]
    pub(crate) fn copy_from_preallocated(&mut self, source: &Self)
    where
        T: Copy,
    {
        assert!(self.values.capacity() >= source.values.len());
        self.values.clear();
        self.values.extend_from_slice(&source.values);
    }

    pub(crate) fn try_push(&mut self, value: T) -> Result<(), OwnedVecGrowthError> {
        self.try_reserve_one()?;
        self.values.push(value);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn try_copy_exact(&self) -> Result<Self, OwnedVecGrowthError>
    where
        T: Copy,
    {
        let mut copied = self.try_copy_capacity(self.values.len())?;
        copied.values.extend_from_slice(&self.values);
        Ok(copied)
    }

    pub(crate) fn pop(&mut self) -> Option<T> {
        self.values.pop()
    }

    pub(crate) fn clear(&mut self) {
        self.values.clear();
    }

    pub(crate) fn clear_and_shrink(&mut self) {
        self.values = Vec::new();
        self.reservation.resize_active(0);
    }

    pub(crate) fn try_retain(&self) -> bool {
        self.reservation.try_retain()
    }

    pub(crate) fn make_active(&self) {
        self.reservation.make_active();
    }
}

impl<T> Deref for OwnedVec<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.values
    }
}

impl<T> DerefMut for OwnedVec<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.values
    }
}

/// Owner for a mutable value whose allocation geometry is fixed after creation.
///
/// Mutation may replace bytes but must not change allocation capacities. A new
/// geometry must be installed as a new owner; in-place Merkle refreshes retain it.
pub(crate) struct FixedAllocationValue<T> {
    value: T,
    reservation: MemoryReservation,
    measure: fn(&T) -> usize,
}

impl<T> FixedAllocationValue<T> {
    pub(crate) fn new(value: T, measure: fn(&T) -> usize) -> Self {
        let bytes = measure(&value);
        Self {
            value,
            reservation: MemoryReservation::active(bytes),
            measure,
        }
    }

    /// Transfer a charge made before fallible construction to its final owner.
    ///
    /// The reservation covers the requested allocation while it is made;
    /// once the temporary builder has gone away, retain only the actual
    /// allocation capacity reported by `measure`.
    pub(crate) fn from_pre_reserved(
        value: T,
        mut reservation: MemoryReservation,
        measure: fn(&T) -> usize,
    ) -> Self {
        reservation.set_known_bytes(measure(&value));
        Self {
            value,
            reservation,
            measure,
        }
    }

    pub(crate) fn try_retain(&self) -> bool {
        self.reservation.try_retain()
    }

    pub(crate) fn make_active(&self) {
        self.reservation.make_active();
    }
}

impl<T: Clone> Clone for FixedAllocationValue<T> {
    fn clone(&self) -> Self {
        let mut reservation = self.reservation.budget.reserve(self.reservation.bytes());
        let value = self.value.clone();
        reservation.set_known_bytes((self.measure)(&value));
        Self {
            value,
            reservation,
            measure: self.measure,
        }
    }
}

impl<T> Deref for FixedAllocationValue<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> DerefMut for FixedAllocationValue<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

#[cfg(test)]
pub(crate) struct TestMemoryBudget(MemoryBudget);
#[cfg(test)]
impl TestMemoryBudget {
    pub(crate) fn new(limit: usize) -> Self {
        Self(MemoryBudget::new(limit))
    }
    pub(crate) fn stats(&self) -> MemoryStats {
        self.0.stats()
    }
    pub(crate) fn set_limit(&self, limit: usize) {
        self.0.set_limit(limit);
    }
    pub(crate) fn empty_rows<T>(&self) -> OwnedVec<T> {
        OwnedVec::try_with_capacity_in_budget(0, &self.0).expect("empty rows allocate no backing")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_owner_reuses_preallocation_charge_and_releases_unused_capacity() {
        let reservation = MemoryReservation::active(128);
        assert_eq!(reservation.bytes(), 128);
        let owner = FixedAllocationValue::from_pre_reserved(
            vec![1_u64, 2, 3],
            reservation,
            |values: &Vec<u64>| values.capacity() * std::mem::size_of::<u64>(),
        );
        assert_eq!(owner.reservation.bytes(), 3 * std::mem::size_of::<u64>());
        assert_eq!(&*owner, &[1, 2, 3]);
    }

    #[test]
    fn filled_copy_preserves_bytes_and_defers_unrepresentable_demand() {
        let filled = OwnedAllocation::try_filled_copy(3, [0xa5_u8; 32]).unwrap();
        assert_eq!(&*filled, &[[0xa5; 32]; 3]);
        assert!(matches!(
            OwnedAllocation::<[u8; 32]>::try_filled_copy(usize::MAX, [0; 32]),
            Err(crate::error::VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
        assert!(matches!(
            OwnedAllocation::<[u8; 32]>::try_filled_copy(isize::MAX as usize / 32 + 1, [0; 32]),
            Err(crate::error::VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
    }

    #[test]
    fn filled_copy_prepays_vec_box_overlap_and_refunds_after_unwind() {
        #[derive(Copy)]
        struct PanicOnClone(u8);
        #[allow(
            clippy::non_canonical_clone_impl,
            reason = "the panicking clone deliberately unwinds the filled copy to prove the budget refund"
        )]
        impl Clone for PanicOnClone {
            fn clone(&self) -> Self {
                let _ = self.0;
                panic!("copy construction unwinds");
            }
        }

        let budget = MemoryBudget::new(4_096);
        let owner = OwnedAllocation::try_filled_copy_with_budget(3, [0xa5_u8; 32], &budget)
            .expect("small allocation");
        assert_eq!(owner.reservation.bytes(), 96);
        assert_eq!(budget.stats().active_bytes, 96);
        assert!(budget.stats().peak_reserved_bytes >= 192);
        drop(owner);
        assert_eq!(budget.stats().active_bytes, 0);

        assert!(
            std::panic::catch_unwind(|| {
                let _ = OwnedAllocation::try_filled_copy_with_budget(2, PanicOnClone(1), &budget);
            })
            .is_err()
        );
        assert_eq!(budget.stats().active_bytes, 0);
    }

    #[test]
    fn zeroed_allocation_prepays_vec_box_overlap_and_refunds_on_error() {
        let budget = MemoryBudget::new(4_096);
        let owner = OwnedAllocation::try_zeroed_with_budget(64, &budget).expect("small allocation");
        assert_eq!(owner.reservation.bytes(), 64);
        assert_eq!(budget.stats().active_bytes, 64);
        assert!(budget.stats().peak_reserved_bytes >= 128);
        drop(owner);
        assert_eq!(budget.stats().active_bytes, 0);

        assert!(OwnedAllocation::try_zeroed_with_budget(isize::MAX as usize + 1, &budget).is_err());
        assert_eq!(budget.stats().active_bytes, 0);
    }

    #[test]
    fn value_destruction_finishes_before_its_allocation_charge_is_refunded() {
        struct DropProbe(MemoryBudget);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                assert_eq!(self.0.stats().retained_bytes, 64);
            }
        }
        let budget = MemoryBudget::new(64);
        let reservation = budget.reserve(64);
        assert!(reservation.try_retain());
        let owner = Arc::new(ValueAllocation {
            value: DropProbe(budget.clone()),
            reservation,
        });
        let borrower = Arc::clone(&owner);
        drop(owner);
        assert_eq!(budget.stats().retained_bytes, 64);
        drop(borrower);
        assert_eq!(budget.stats().retained_bytes, 0);
    }

    #[test]
    fn shared_value_accounts_alignment_and_keeps_identity_across_borrowers() {
        #[repr(align(64))]
        struct Aligned(u8);
        let owner = SharedValue::new(Aligned(7), Some(0));
        assert_eq!(
            owner.allocation_bytes(),
            Some(64 + std::mem::size_of::<ValueAllocation<Aligned>>())
        );
        let borrower = owner.clone();
        assert!(SharedValue::ptr_eq(&owner, &borrower));
        drop(owner);
        assert_eq!(borrower.0.value.0, 7);
    }

    #[test]
    fn shared_allocation_classifies_cache_borrow_and_evicted_live_lifetimes() {
        let budget = MemoryBudget::new(4_096);
        let owner = SharedAllocation::with_budget(vec![1_u64, 2].into_boxed_slice(), &budget);
        let bytes = owner.allocation_bytes();
        assert!(owner.try_retain());
        assert_eq!(budget.stats().unclassified_retained_bytes(), bytes);

        let cache = owner.cache_clone();
        assert_eq!(budget.stats().shared_borrowed_bytes, bytes);
        drop(owner);
        assert_eq!(budget.stats().shared_reclaimable_bytes, bytes);
        let borrower = cache.clone();
        assert_eq!(budget.stats().shared_borrowed_bytes, bytes);
        drop(cache);
        assert_eq!(budget.stats().shared_evicted_live_bytes, bytes);
        assert_eq!(budget.stats().retained_bytes, bytes);
        drop(borrower);
        assert_eq!(budget.stats().measured_resident_bytes(), 0);
        assert_eq!(budget.stats().shared_evicted_live_bytes, 0);
    }

    #[test]
    fn shared_value_cache_promotion_and_active_transition_preserve_one_charge() {
        let budget = MemoryBudget::new(4_096);
        let owner = SharedValue::with_budget(7_u64, Some(0), &budget);
        let bytes = owner.allocation_bytes().expect("measured value");
        assert!(owner.try_retain());
        let cache = owner.into_cache_owner();
        assert_eq!(budget.stats().shared_reclaimable_bytes, bytes);
        let borrower = cache.clone();
        assert_eq!(budget.stats().shared_borrowed_bytes, bytes);
        cache.0.reservation.make_active();
        assert_eq!(budget.stats().shared_borrowed_bytes, 0);
        assert_eq!(budget.stats().active_bytes, bytes);
        assert!(cache.try_retain());
        drop(cache);
        assert_eq!(budget.stats().shared_evicted_live_bytes, bytes);
        assert_eq!(*borrower, 7);
        drop(borrower);
        assert_eq!(budget.stats().measured_resident_bytes(), 0);
    }

    #[test]
    fn evicted_shared_value_keeps_charge_until_final_destructor_without_phantom_borrower() {
        struct DropProbe {
            budget: MemoryBudget,
            active_bytes: usize,
        }

        impl Drop for DropProbe {
            fn drop(&mut self) {
                let stats = self.budget.stats();
                assert_eq!(stats.active_bytes, self.active_bytes);
                assert!(stats.retained_bytes > 0);
                assert_eq!(stats.shared_reclaimable_bytes, 0);
                assert_eq!(stats.shared_borrowed_bytes, 0);
                assert_eq!(stats.shared_evicted_live_bytes, 0);
                assert_eq!(stats.unclassified_retained_bytes(), stats.retained_bytes);
                assert_eq!(
                    stats.measured_resident_bytes(),
                    self.active_bytes + stats.retained_bytes
                );
            }
        }

        let budget = MemoryBudget::new(4_096);
        let active = budget.reserve(7);
        let owner = SharedValue::with_budget(
            DropProbe {
                budget: budget.clone(),
                active_bytes: 7,
            },
            Some(0),
            &budget,
        );
        let bytes = owner.allocation_bytes().expect("measured owner");
        assert!(owner.try_retain());
        let cache = owner.into_cache_owner();
        assert_eq!(budget.stats().shared_reclaimable_bytes, bytes);

        let first = cache.clone();
        let last = cache.clone();
        assert_eq!(budget.stats().shared_borrowed_bytes, bytes);
        drop(cache);
        assert_eq!(budget.stats().shared_evicted_live_bytes, bytes);
        drop(first);
        assert_eq!(budget.stats().shared_evicted_live_bytes, bytes);
        assert_eq!(budget.stats().retained_bytes, bytes);
        drop(last);

        let stats = budget.stats();
        assert_eq!(stats.active_bytes, 7);
        assert_eq!(stats.retained_bytes, 0);
        assert_eq!(stats.measured_resident_bytes(), 7);
        assert_eq!(stats.shared_evicted_live_bytes, 0);
        assert_eq!(stats.peak_reserved_bytes, bytes + 7);
        drop(active);
        let stats = budget.stats();
        assert_eq!(stats.measured_resident_bytes(), 0);
        assert_eq!(stats.peak_reserved_bytes, bytes + 7);
    }

    #[test]
    fn transient_shared_value_reference_registers_no_borrower_and_keeps_the_charge_alive() {
        let budget = MemoryBudget::new(4_096);
        let owner = SharedValue::with_budget(7_u64, Some(0), &budget);
        let bytes = owner.allocation_bytes().expect("measured value");
        assert!(owner.try_retain());
        let cache = owner.into_cache_owner();
        assert_eq!(budget.stats().shared_reclaimable_bytes, bytes);
        let transient = cache.transient();
        // Unlike a registered clone, the classification stays reclaimable.
        assert_eq!(budget.stats().shared_reclaimable_bytes, bytes);
        assert_eq!(budget.stats().shared_borrowed_bytes, 0);
        assert_eq!(
            cache.0.reservation.shared_handles.load(Ordering::Relaxed),
            1
        );
        assert_eq!(*transient, 7);
        drop(transient);
        assert_eq!(budget.stats().shared_reclaimable_bytes, bytes);
        // A transient outliving every registered handle still holds the charge
        // until its own final release, without counting as a borrower.
        let transient = cache.transient();
        drop(cache);
        assert_eq!(budget.stats().retained_bytes, bytes);
        assert_eq!(budget.stats().shared_borrowed_bytes, 0);
        assert_eq!(*transient, 7);
        drop(transient);
        assert_eq!(budget.stats().measured_resident_bytes(), 0);
    }

    #[test]
    fn unmeasured_shared_values_remain_usable_but_never_enter_retention() {
        let owner = SharedValue::new(vec![1_u64, 2, 3], None);
        assert_eq!(owner.allocation_bytes(), None);
        assert!(!owner.try_retain());
        let borrower = owner.clone();
        drop(owner);
        assert_eq!(borrower.as_ref(), &[1, 2, 3]);
        assert!(!borrower.try_retain());
    }

    #[test]
    fn overflowing_shared_value_measurement_stays_active_and_unmeasured() {
        let budget = MemoryBudget::new(1024);
        let owner = SharedValue::with_budget(7_u64, Some(usize::MAX), &budget);
        assert_eq!(owner.allocation_bytes(), None);
        assert_eq!(budget.stats().unmeasured_active_owners, 1);
        assert!(budget.stats().active_bytes > 0);
        assert!(!owner.try_retain());
        drop(owner);
        assert_eq!(budget.stats().active_bytes, 0);
        assert_eq!(budget.stats().unmeasured_active_owners, 0);
    }

    #[test]
    fn mutable_owners_move_between_active_and_retained_without_refunding_live_storage() {
        let budget = MemoryBudget::new(1024);
        let mut owner = budget.reserve(64);
        assert!(owner.try_retain());
        owner.make_active();
        assert_eq!(budget.stats().active_bytes, 64);
        assert_eq!(budget.stats().retained_bytes, 0);
        owner.set_known_bytes(128);
        assert!(owner.try_retain());
        owner.mark_unmeasured();
        owner.mark_unmeasured();
        assert_eq!(budget.stats().unmeasured_active_owners, 1);
        assert!(!owner.try_retain());
        owner.set_known_bytes(32);
        assert_eq!(budget.stats().unmeasured_active_owners, 0);
        assert!(owner.try_retain());
        drop(owner);
        assert_eq!(budget.stats().active_bytes, 0);
        assert_eq!(budget.stats().retained_bytes, 0);
    }

    #[test]
    fn owned_slice_clone_gets_an_independent_active_reservation() {
        let budget = MemoryBudget::new(4096);
        let bytes = 32;
        let mut original = OwnedAllocation {
            values: vec![7_u8; 32].into_boxed_slice(),
            reservation: budget.reserve(bytes),
        };
        assert!(original.try_retain());
        let clone = original.clone();
        original[0] = 9;
        assert_eq!(clone[0], 7);
        assert_eq!(budget.stats().retained_bytes, bytes);
        assert_eq!(budget.stats().active_bytes, bytes);
        drop(original);
        assert_eq!(budget.stats().retained_bytes, 0);
        assert_eq!(clone[0], 7);
        drop(clone);
        assert_eq!(budget.stats().active_bytes, 0);
    }

    #[test]
    fn owned_vector_keeps_spare_capacity_charged_until_storage_is_released() {
        let budget = MemoryBudget::new(4096);
        let inline = 0;
        let mut values: OwnedVec<u64> = OwnedVec {
            values: Vec::new(),
            reservation: budget.reserve(inline),
        };
        for value in 0..9 {
            values.try_push(value).expect("small allocation");
        }
        let bytes = inline + values.values.capacity() * std::mem::size_of::<u64>();
        assert!(values.try_retain());
        assert_eq!(values.pop(), Some(8));
        values.clear();
        assert_eq!(budget.stats().retained_bytes, bytes);
        values.clear_and_shrink();
        assert_eq!(budget.stats().retained_bytes, 0);
        assert_eq!(budget.stats().active_bytes, inline);
        values.try_push(42).expect("small allocation");
        let clone = values.clone();
        assert_eq!(&clone[..], &[42]);
        assert_eq!(
            budget.stats().active_bytes,
            values.reservation.bytes() + clone.reservation.bytes()
        );
        drop(values);
        drop(clone);
        assert_eq!(budget.stats().active_bytes, 0);
    }

    #[test]
    fn owned_vector_prepaid_edits_and_fallible_copy_preserve_independent_bytes() {
        let mut values = OwnedVec::<u64>::default();
        for value in 0..4 {
            values.try_push(value).unwrap();
        }
        assert_eq!(values.values.capacity(), 4);
        let copy = values.try_copy_exact().unwrap();
        assert_eq!(values.remove_at(1), 1);
        values.insert_reserved(1, 9);
        values.remove_range(2..4);
        assert_eq!(&values[..], &[0, 9]);
        assert_eq!(&copy[..], &[0, 1, 2, 3]);
        values.copy_from_preallocated(&copy);
        assert_eq!(&values[..], &copy[..]);
        assert_eq!(values.reservation.bytes(), values.values.capacity() * 8);
        assert_eq!(copy.reservation.bytes(), copy.values.capacity() * 8);
    }

    #[test]
    fn owned_vector_growth_rejects_unrepresentable_capacity_before_reserving() {
        assert_eq!(
            (owned_vec_growth::<u64>(0)).expect("expected successful fixture result"),
            (4, 32)
        );
        assert_eq!(
            owned_vec_growth::<u64>(usize::MAX),
            Err(OwnedVecGrowthError::CapacityOverflow)
        );
        assert_eq!(
            owned_vec_growth::<u64>(isize::MAX as usize / 8),
            Err(OwnedVecGrowthError::CapacityOverflow)
        );
    }

    #[test]
    fn owned_vector_growth_charges_both_live_buffers_and_refunds_refusal() {
        let budget = MemoryBudget::new(1024);
        let mut values = OwnedVec {
            values: vec![1_u64, 2, 3, 4],
            reservation: budget.reserve(4 * std::mem::size_of::<u64>()),
        };
        values.values.shrink_to_fit();
        assert_eq!(values.values.capacity(), 4);
        let old_bytes = values.reservation.bytes();
        refuse_next_owned_vec_growth_for_test();
        assert_eq!(
            values.try_push(5),
            Err(OwnedVecGrowthError::AllocationUnavailable)
        );
        assert_eq!(&values[..], &[1, 2, 3, 4]);
        assert_eq!(budget.stats().active_bytes, old_bytes);
        assert!(budget.stats().peak_reserved_bytes >= old_bytes * 3);

        values.try_push(5).expect("retry after local refusal");
        assert_eq!(&values[..], &[1, 2, 3, 4, 5]);
        assert_eq!(
            budget.stats().active_bytes,
            values.values.capacity() * std::mem::size_of::<u64>()
        );
        drop(values);
        assert_eq!(budget.stats().measured_resident_bytes(), 0);
    }

    #[test]
    fn retained_owned_vector_stays_charged_until_final_borrower_drops() {
        let budget = MemoryBudget::new(1024);
        let owner = Arc::new(OwnedVec {
            values: vec![7_u64; 4],
            reservation: budget.reserve(4 * std::mem::size_of::<u64>()),
        });
        assert!(owner.try_retain());
        let borrower = Arc::clone(&owner);
        drop(owner);
        assert_eq!(budget.stats().retained_bytes, 32);
        assert_eq!(&borrower[..], &[7; 4]);
        drop(borrower);
        assert_eq!(budget.stats().measured_resident_bytes(), 0);
    }

    #[test]
    fn fixed_geometry_clone_and_drop_keep_independent_capacity_charges() {
        fn bytes(value: &Vec<u64>) -> usize {
            value.capacity() * std::mem::size_of::<u64>()
        }
        let budget = MemoryBudget::new(4096);
        let original_bytes =
            32 * std::mem::size_of::<u64>() + std::mem::size_of::<FixedAllocationValue<Vec<u64>>>();
        let mut value = Vec::with_capacity(32);
        value.push(1);
        let owner = FixedAllocationValue {
            value,
            measure: bytes,
            reservation: budget.reserve(original_bytes),
        };
        assert!(owner.try_retain());
        let mut clone = owner.clone();
        clone[0] = 2;
        assert_eq!(owner[0], 1);
        assert_eq!(budget.stats().retained_bytes, original_bytes);
        assert_eq!(budget.stats().active_bytes, clone.reservation.bytes());
        drop(owner);
        assert_eq!(budget.stats().retained_bytes, 0);
        drop(clone);
        assert_eq!(budget.stats().active_bytes, 0);
    }

    #[test]
    fn shrinking_caches_drops_references_without_refunding_borrowers() {
        let budget = MemoryBudget::new(4096);
        let allocation = SharedAllocation::with_budget(vec![1_u64; 8].into_boxed_slice(), &budget);
        assert!(allocation.try_retain());
        let bytes = allocation.allocation_bytes();
        let cache = Arc::new(Mutex::new(Some(allocation.clone())));
        let weak = Arc::downgrade(&cache);
        let registration = register_cache_evictor(move || {
            if let Some(cache) = weak.upgrade() {
                cache.lock().expect("cache lock").take();
            }
        });
        evict_registered_caches();
        assert!(cache.lock().expect("cache lock").is_none());
        assert_eq!(budget.stats().retained_bytes, bytes);
        drop(allocation);
        assert_eq!(budget.stats().retained_bytes, 0);
        drop(registration);
        evict_registered_caches();
    }

    #[test]
    fn shared_borrower_keeps_charge_after_cache_eviction() {
        let budget = MemoryBudget::new(1024);
        let cached = SharedAllocation::with_budget(vec![1_u64; 4].into_boxed_slice(), &budget);
        assert!(cached.try_retain());
        let bytes = cached.allocation_bytes();
        let borrower = cached.clone();
        assert!(SharedAllocation::ptr_eq(&cached, &borrower));
        assert_eq!(borrower.as_ref(), &[1; 4]);
        drop(cached);
        assert_eq!(budget.stats().retained_bytes, bytes);
        drop(borrower);
        assert_eq!(budget.stats().retained_bytes, 0);
    }

    #[test]
    fn aggregate_admission_stays_cold_until_final_borrower_returns() {
        let budget = MemoryBudget::new(16);
        let retained = budget.reserve(16);
        assert!(retained.try_retain());
        assert!(retained.try_retain());
        let cold = budget.reserve(8);
        assert!(!cold.try_retain());
        assert_eq!(budget.stats().active_bytes, 8);
        drop(retained);
        assert!(cold.try_retain());
        assert_eq!(budget.stats().active_bytes, 0);
        assert_eq!(budget.stats().retained_bytes, 8);
    }

    #[test]
    fn budget_shrink_preserves_pinned_charges_and_zero_disables_retention() {
        let budget = MemoryBudget::new(32);
        let pinned = budget.reserve(32);
        assert!(pinned.try_retain());
        budget.set_limit(8);
        let cold = budget.reserve(8);
        assert!(!cold.try_retain());
        assert_eq!(budget.stats().retained_bytes, 32);
        budget.set_limit(0);
        assert!(!pinned.try_retain());
        drop(pinned);
        assert!(!cold.try_retain());
        drop(cold);
        assert_eq!(budget.stats().measured_resident_bytes(), 0);
        assert_eq!(budget.stats().peak_reserved_bytes, 40);
    }

    #[test]
    fn measured_resident_and_peak_follow_owner_growth_and_final_release() {
        let budget = MemoryBudget::new(128);
        let mut first = budget.reserve(32);
        let second = budget.reserve(16);
        assert_eq!(budget.stats().measured_resident_bytes(), 48);
        assert_eq!(budget.stats().peak_reserved_bytes, 48);
        assert!(first.try_retain());
        assert_eq!(budget.stats().measured_resident_bytes(), 48);
        first.set_known_bytes(64);
        assert_eq!(budget.stats().measured_resident_bytes(), 80);
        assert_eq!(budget.stats().peak_reserved_bytes, 80);
        drop(first);
        assert_eq!(budget.stats().measured_resident_bytes(), 16);
        drop(second);
        assert_eq!(budget.stats().measured_resident_bytes(), 0);
        assert_eq!(budget.stats().peak_reserved_bytes, 80);
    }

    #[test]
    fn active_reservations_refund_on_error_and_unwind() {
        let budget = MemoryBudget::new(16);
        let fail = || -> Result<(), ()> {
            let _owner = budget.reserve(8);
            Err(())
        };
        assert!(fail().is_err());
        assert_eq!(budget.stats().active_bytes, 0);
        assert!(
            std::panic::catch_unwind(|| {
                let _owner = budget.reserve(8);
                panic!("owner unwinds");
            })
            .is_err()
        );
        assert_eq!(budget.stats().active_bytes, 0);
    }

    #[test]
    fn partial_construction_refunds_allocations_on_error_and_unwind() {
        let budget = MemoryBudget::new(1024);
        let build = SharedAllocation::try_from_iter_with_budget(
            [Ok(1_u64), Err(crate::error::VMError::DecodeError)].into_iter(),
            &budget,
        );
        assert!(build.is_err());
        assert_eq!(budget.stats().active_bytes, 0);
        assert!(
            std::panic::catch_unwind(|| {
                let values = (0..2).map(|index| -> Result<u64, crate::error::VMError> {
                    assert!(budget.stats().active_bytes > 0);
                    if index == 1 {
                        panic!("construction unwinds");
                    }
                    Ok(1)
                });
                let _ = SharedAllocation::try_from_iter_with_budget(values, &budget);
            })
            .is_err()
        );
        assert_eq!(budget.stats().active_bytes, 0);
    }

    #[test]
    fn shared_allocation_rejects_unrepresentable_capacity_before_polling_values() {
        let budget = MemoryBudget::new(1024);
        let values = (0..usize::MAX).map(|_| -> Result<u64, crate::error::VMError> {
            panic!("oversized iterator must not be polled")
        });
        assert!(matches!(
            SharedAllocation::try_from_iter_with_budget(values, &budget),
            Err(crate::error::VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::AllocationUnavailable
            ))
        ));
        assert_eq!(budget.stats().active_bytes, 0);
    }

    #[test]
    fn shared_allocation_rejects_an_inaccurate_exact_size_before_growth() {
        struct InaccurateSize(u8);

        impl Iterator for InaccurateSize {
            type Item = Result<u64, crate::error::VMError>;

            fn next(&mut self) -> Option<Self::Item> {
                let index = self.0;
                self.0 = self.0.saturating_add(1);
                (index < 2).then(|| Ok(u64::from(index)))
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                (1, Some(1))
            }
        }

        impl ExactSizeIterator for InaccurateSize {}

        let budget = MemoryBudget::new(1024);
        assert!(matches!(
            SharedAllocation::try_from_iter_with_budget(InaccurateSize(0), &budget),
            Err(crate::error::VMError::DecodeError)
        ));
        assert_eq!(budget.stats().active_bytes, 0);
    }

    #[test]
    fn shared_allocation_peak_covers_temporary_vec_and_final_box() {
        let budget = MemoryBudget::new(1024);
        let owner = SharedAllocation::try_from_iter_with_budget(
            (0_u32..3).map(|value| Ok::<_, crate::error::VMError>(u64::from(value))),
            &budget,
        )
        .expect("three words fit the allocation budget");
        let final_bytes = 3 * std::mem::size_of::<u64>()
            + std::mem::size_of::<Allocation<u64>>()
            + 2 * std::mem::size_of::<usize>();
        assert_eq!(budget.stats().active_bytes, final_bytes);
        assert!(budget.stats().peak_reserved_bytes >= final_bytes + 3 * std::mem::size_of::<u64>());
        drop(owner);
        assert_eq!(budget.stats().active_bytes, 0);
    }
}
