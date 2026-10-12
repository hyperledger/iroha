//! Std-only original allocation custody with release-driven retry.
//!
//! Codecs, cryptography and runtime storage share these physical owners. Storage
//! generations, maps and transactions remain in their separate runtime crates.
//!
//! Enumerate real allocation layouts before constructing their objects, reserve
//! their combined demand once, then split the prepaid owner into charges held
//! by those allocations through actual deallocation. A charge is not a lifetime
//! wrapper: its consumer must bind it to the real allocation owner, such as the
//! charged Concread EBR cell. Returning a charge at publication is too early.
//!
//! This accounts requested layout bytes, not RSS. Nested payloads, allocator and
//! collector bookkeeping, and this budget's fixed control storage are not
//! inferred. Their complete admission remains the integrating caller's job.

#![allow(unsafe_code)]

use std::{
    alloc::Layout,
    cell::Cell,
    fmt, ptr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering},
    },
};

/// Physical release observations and deferred notification custody.
pub mod release;
/// Generic shared backing and its exact original allocation charge.
pub mod shared;

use crate::release::{ReleaseNotification, ReleaseWait};

#[path = "allocation/buffer.rs"]
mod buffer;
#[path = "allocation/shared.rs"]
mod charged_shared;
#[path = "allocation/refund_batch.rs"]
mod refund_batch;
#[path = "allocation/retained_payload.rs"]
mod retained_payload;

pub use buffer::{
    ChargedBuffer, ChargedBufferError, ChargedBufferFromChargeError, PrepaidBufferError,
};
pub use charged_shared::{
    ChargedShared, PrepaidSharedError, ReservedChargedShared, SharedFromChargeError,
};
pub use refund_batch::AllocationRefundBatch;
pub use retained_payload::{RetainedPayload, RetainedPayloadError};

thread_local! {
    // Scope records have stable stack or originally admitted control addresses.
    // Only their active thread links or follows this chain.
    static REFUND_SCOPES: Cell<*const RefundScope> = const { Cell::new(ptr::null()) };
}

struct RefundScope {
    pool: AtomicPtr<Pool>,
    previous: AtomicPtr<RefundScope>,
    pending: AtomicBool,
}

impl RefundScope {
    fn new(pool: &Arc<Pool>, previous: *const Self) -> Self {
        Self {
            pool: AtomicPtr::new(Arc::as_ptr(pool).cast_mut()),
            previous: AtomicPtr::new(previous.cast_mut()),
            pending: AtomicBool::new(false),
        }
    }

    // Owned sibling scopes may finish in a different order from acquisition.
    // Every linked record stays at its original stable address on this thread.
    fn unlink(&self) {
        REFUND_SCOPES.with(|head| {
            let own = ptr::from_ref(self);
            if head.get() == own {
                head.set(self.previous.load(Ordering::Relaxed));
                return;
            }
            let mut current = head.get();
            while !current.is_null() {
                // SAFETY: all linked records are retained on this same thread.
                let record = unsafe { &*current };
                if ptr::eq(record.previous.load(Ordering::Relaxed), own) {
                    record
                        .previous
                        .store(self.previous.load(Ordering::Relaxed), Ordering::Relaxed);
                    return;
                }
                current = record.previous.load(Ordering::Relaxed);
            }
            unreachable!("original refund scope remains registered until final custody drops");
        });
    }
}

// This borrow keeps the stack record at its registered address. Neither the
// record nor this guard escapes the synchronous closure API or crosses threads.
struct EnteredRefundScope<'scope> {
    scope: &'scope RefundScope,
    pool: &'scope Pool,
    retained: Option<&'scope Cell<bool>>,
}

impl Drop for EnteredRefundScope<'_> {
    fn drop(&mut self) {
        self.scope.unlink();
        // Unlink and end the TLS access before invoking any user callback. A
        // matching outer scope receives this wake; other threads are unaffected.
        if self.scope.pending.load(Ordering::Relaxed) {
            if let Some(retained) = self.retained {
                retained.set(true);
            } else {
                self.pool.notify_refund();
            }
        }
    }
}

struct Pool {
    // A configuration reload changes the limit of this same original pool.
    // The read lock spans acquisition so a concurrent shrink cannot admit
    // fresh credits against the former limit.
    limit: RwLock<usize>,
    reserved: AtomicUsize,
    peak_reserved: AtomicUsize,
    released: ReleaseNotification,
}

impl Pool {
    fn refund(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        // Credits become reusable immediately, even if this thread must defer
        // notification until its physical writer guards have been released.
        let previous = self.reserved.fetch_sub(bytes, Ordering::AcqRel);
        debug_assert!(previous >= bytes, "allocation custody cannot refund twice");
        self.notify_refund();
    }

    fn notify_refund(&self) {
        let deferred = REFUND_SCOPES.with(|head| {
            let mut current = head.get();
            while !current.is_null() {
                // SAFETY: only this thread accesses its TLS chain. Each record
                // stays at its stable stack or admitted owned address until
                // its final guard/custodian unlinks it before reclamation.
                let scope = unsafe { &*current };
                if ptr::eq(scope.pool.load(Ordering::Relaxed), self) {
                    scope.pending.store(true, Ordering::Relaxed);
                    return true;
                }
                current = scope.previous.load(Ordering::Relaxed);
            }
            false
        });
        if !deferred {
            // No TLS access or pool lock remains while Waker::wake can reenter.
            drop(self.released.guard(()));
        }
    }
}

/// Borrowed proof that one original pool defers refunds on this thread.
///
/// Only the budget's synchronous callback creates this token. Physical owners
/// which borrow it cannot escape the callback or move to another thread.
/// Detached owners may leave after their physical guards have been released.
///
/// ```compile_fail
/// let budget = iroha_allocation::AllocationBudget::new(1024);
/// let escaped = budget.with_deferred_refund_notifications(|scope| scope);
/// drop(escaped);
/// ```
///
/// The scope cannot be used from a different thread:
/// ```compile_fail
/// let budget = iroha_allocation::AllocationBudget::new(1024);
/// budget.with_deferred_refund_notifications(|scope| {
///     std::thread::scope(|threads| {
///         threads.spawn(move || { std::hint::black_box(scope); });
///     });
/// });
/// ```
pub struct AllocationScope<'scope> {
    budget: &'scope AllocationBudget,
    // Refund deferral is thread-local. Even a scoped thread cannot borrow this
    // token to acquire writers whose refunds would notify on another thread.
    _thread: std::marker::PhantomData<*mut ()>,
}

// Zero permits one activation. Counts belong only to its active thread; the
// retiring sentinel excludes reentry until the final callback cohort unwinds.
const REFUND_SCOPE_RETIRING: usize = usize::MAX;

struct OwnedRefundControl {
    record: RefundScope,
    active_owners: AtomicUsize,
}

/// An originally admitted refund control reusable on successive threads.
///
/// Obtain this capability from [`OwnedAllocationScope::control`] before
/// detaching physical ownership. Cloning and activating it allocate nothing and
/// acquire no new pool capacity. It can cross threads; an active scope cannot.
/// Activation refuses until every old active custodian and its deferred wake
/// callbacks have completed. This capability neither releases physical writers
/// nor authenticates publication; their aggregate owner must retain its active
/// guard through every sibling release and cleanup.
///
/// ```
/// fn send_sync<T: Send + Sync>() {}
/// send_sync::<iroha_allocation::AllocationScopeControl>();
/// ```
#[derive(Clone)]
pub struct AllocationScopeControl {
    control: crate::shared::Shared<OwnedRefundControl, AllocationCharge>,
    budget: AllocationBudget,
}

/// The original control still has active or retiring physical custodians.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationScopeActive;

impl fmt::Display for AllocationScopeActive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("original refund control is still active or retiring")
    }
}

impl std::error::Error for AllocationScopeActive {}

impl AllocationScopeControl {
    /// Borrow the exact original finite pool, without granting new capacity.
    pub fn allocation_budget(&self) -> &AllocationBudget {
        &self.budget
    }

    /// Whether this control belongs to the exact original finite pool.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.budget.same_pool(budget)
    }

    /// Activate the same stable control on this thread without allocating.
    ///
    /// The compare/exchange grants one thread exclusive access to the record's
    /// TLS membership. Atomic record fields make the inactive shared owner
    /// `Send + Sync`; no other thread follows or mutates an active TLS chain.
    /// The original charge and pool handles outlive every active guard, so its
    /// raw pool pointer and record address remain valid until it is unlinked.
    ///
    /// # Errors
    /// Refuses while any prior active guard or its final callbacks still lives.
    pub fn try_activate(&self) -> Result<OwnedAllocationScope, AllocationScopeActive> {
        self.control
            .active_owners
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| AllocationScopeActive)?;
        let record = &self.control.record;
        record.pending.store(false, Ordering::Relaxed);
        REFUND_SCOPES.with(|head| {
            record
                .previous
                .store(head.get().cast_mut(), Ordering::Relaxed);
            head.set(ptr::from_ref(record));
        });
        Ok(OwnedAllocationScope {
            control: self.clone(),
            _thread: std::marker::PhantomData,
        })
    }
}

/// Original prepaid thread-bound refund scope retained by physical owners.
///
/// Clones share one active generation of the same admitted control allocation.
/// The final owner unlinks before invoking deferred wakes; only after the whole
/// callback cohort returns or unwinds can its control be activated again.
/// Retain a clone in every physical owner and release all sibling guards before
/// cleanup. An inactive [`AllocationScopeControl`] can outlive these guards,
/// retaining their exact allocation and its original charge for later reuse.
///
/// This owner cannot cross threads, including scoped threads:
/// ```compile_fail
/// let budget = iroha_allocation::AllocationBudget::new(4096);
/// let scope = budget.try_owned_refund_scope().unwrap();
/// std::thread::scope(|threads| { threads.spawn(move || drop(scope)); });
/// ```
/// A shared borrow cannot cross threads either:
/// ```compile_fail
/// let budget = iroha_allocation::AllocationBudget::new(4096);
/// let scope = budget.try_owned_refund_scope().unwrap();
/// std::thread::scope(|threads| { threads.spawn(|| { let _ = &scope; }); });
/// ```
pub struct OwnedAllocationScope {
    control: AllocationScopeControl,
    _thread: std::marker::PhantomData<*mut ()>,
}

impl OwnedAllocationScope {
    /// Allocate the original scope control from an already retained exact charge.
    /// A foreign or wrong-layout charge is returned before allocator work; an
    /// allocator refusal returns that same charge without linking any TLS scope.
    ///
    /// # Errors
    /// Returns unchanged charge custody and the precise local refusal.
    pub fn try_from_charge(
        budget: &AllocationBudget,
        charge: AllocationCharge,
    ) -> Result<Self, (AllocationCharge, OwnedScopeError)> {
        if !charge.belongs_to(budget) {
            return Err((charge, OwnedScopeError::ForeignPool));
        }
        let expected = Self::allocation_layout();
        if charge.layout() != expected {
            let actual = charge.layout();
            return Err((charge, OwnedScopeError::LayoutMismatch { expected, actual }));
        }
        let control = crate::shared::Shared::try_new(
            OwnedRefundControl {
                record: RefundScope::new(&budget.pool, ptr::null()),
                active_owners: AtomicUsize::new(0),
            },
            charge,
        )
        .map_err(|(_record, charge, error)| {
            (
                charge,
                OwnedScopeError::Allocator {
                    layout: error.layout(),
                },
            )
        })?;
        let control = AllocationScopeControl {
            control,
            budget: budget.clone(),
        };
        Ok(control
            .try_activate()
            .expect("new original control is inactive"))
    }
    /// Exact original allocation retained until the last active or inactive owner releases.
    pub fn allocation_layout() -> Layout {
        crate::shared::Shared::<OwnedRefundControl, AllocationCharge>::layout()
    }

    /// Retain this exact already admitted control for later allocation-free activation.
    /// The returned capability can cross threads while this guard remains local.
    pub fn control(&self) -> AllocationScopeControl {
        self.control.clone()
    }

    /// Borrow the exact finite pool backing this thread-bound refund scope.
    pub fn allocation_budget(&self) -> &AllocationBudget {
        self.control.allocation_budget()
    }

    /// Check whether this scope retains the exact original finite pool.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.control.belongs_to(budget)
    }

    /// Borrow the same active scope for a synchronous preparation operation.
    pub fn borrowed(&self) -> AllocationScope<'_> {
        AllocationScope {
            budget: self.control.allocation_budget(),
            _thread: std::marker::PhantomData,
        }
    }
}

impl Clone for OwnedAllocationScope {
    fn clone(&self) -> Self {
        // Active guards are neither Send nor Sync, so only this thread changes
        // a live count. Inactive owners only compare/exchange zero to one.
        let owners = &self.control.control.active_owners;
        let count = owners.load(Ordering::Relaxed);
        if count >= isize::MAX as usize {
            std::process::abort();
        }
        owners.store(count + 1, Ordering::Relaxed);
        Self {
            control: self.control.clone(),
            _thread: std::marker::PhantomData,
        }
    }
}

/// Local refusal constructing an original prepaid refund-scope control.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnedScopeError {
    /// The offered charge belongs to another original pool.
    ForeignPool,
    /// The offered charge does not describe this exact physical control.
    LayoutMismatch {
        /// Actual required control layout.
        expected: Layout,
        /// Offered original charge layout.
        actual: Layout,
    },
    /// The allocator refused the already admitted control layout.
    Allocator {
        /// Original requested layout.
        layout: Layout,
    },
}

impl Drop for OwnedAllocationScope {
    fn drop(&mut self) {
        let control = &self.control.control;
        let count = control.active_owners.load(Ordering::Relaxed);
        if count > 1 {
            control.active_owners.store(count - 1, Ordering::Relaxed);
            return;
        }
        control
            .active_owners
            .store(REFUND_SCOPE_RETIRING, Ordering::Relaxed);
        control.record.unlink();
        struct Deactivate<'a>(&'a AtomicUsize);
        impl Drop for Deactivate<'_> {
            fn drop(&mut self) {
                // Callback unwind has already drained the original cohort.
                // A new activation acquires all previous record operations.
                self.0.store(0, Ordering::Release);
            }
        }
        let _deactivate = Deactivate(&control.active_owners);
        if control.record.pending.load(Ordering::Relaxed) {
            self.control.budget.pool.notify_refund();
        }
        // Automatic fields retain the control through deactivation, then free
        // it (only if no inactive owner remains) before returning its charge.
    }
}

impl AllocationScope<'_> {
    /// Check whether this scope retains the exact original finite pool.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        Arc::ptr_eq(&self.budget.pool, &budget.pool)
    }
}

/// One finite allocation pool shared by its outstanding owners.
///
/// Clones refer to the same pool. Dropping the budget handle does not invalidate
/// outstanding reservations or allocation charges. Zero allows only zero-byte
/// layouts; it never means unlimited. A configuration update changes the
/// limit in place without forgiving charges held by earlier borrowers.
#[derive(Clone)]
pub struct AllocationBudget {
    pool: Arc<Pool>,
}

impl AllocationBudget {
    /// Check identity of retained pool owners without reserving or allocating.
    ///
    /// Cloned handles identify the same pool; equal limits and caller-supplied
    /// digests do not. This predicate grants no allocation credit.
    pub fn same_pool(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.pool, &other.pool)
    }

    /// Construct a pool with an explicit finite requested-byte limit.
    pub fn new(limit_bytes: usize) -> Self {
        Self {
            pool: Arc::new(Pool {
                limit: RwLock::new(limit_bytes),
                reserved: AtomicUsize::new(0),
                peak_reserved: AtomicUsize::new(0),
                released: ReleaseNotification::default(),
            }),
        }
    }

    /// Return the current policy limit in requested allocation bytes.
    pub fn limit_bytes(&self) -> usize {
        *self
            .pool
            .limit
            .read()
            .expect("allocation budget limit lock")
    }

    /// Reconfigure this original pool without releasing any outstanding charge.
    ///
    /// Shrinking below live reservations blocks new nonzero admissions until
    /// enough allocations are actually freed. Growth wakes capacity waiters
    /// after the limit lock is released. Callers holding physical cache locks
    /// must enclose the entire reload in `with_deferred_refund_notifications`.
    pub fn set_limit_bytes(&self, limit_bytes: usize) {
        let mut limit = self
            .pool
            .limit
            .write()
            .expect("allocation budget limit lock");
        let grew = limit_bytes > *limit;
        *limit = limit_bytes;
        drop(limit);
        if grew {
            self.pool.notify_refund();
        }
    }

    /// Observe credits currently held by prepaid or allocated owners.
    /// This snapshot is diagnostic and grants no allocation permission.
    pub fn reserved_bytes(&self) -> usize {
        self.pool.reserved.load(Ordering::Acquire)
    }

    /// Admit an original movable scope before acquiring any physical writer.
    /// Its control storage comes from this same finite pool; refusal creates no
    /// scope and does not authorize replacement allocation or a different pool.
    ///
    /// # Errors
    /// Refuses when the original pool cannot admit the exact scope control allocation.
    pub fn try_owned_refund_scope(&self) -> Result<OwnedAllocationScope, AllocationRefusal> {
        let layout = OwnedAllocationScope::allocation_layout();
        let mut reservation = self.try_reserve(layout)?;
        let charge = reservation
            .try_split(layout)
            .expect("original scope capacity");
        let control = AllocationScopeControl {
            control: crate::shared::Shared::new(
                OwnedRefundControl {
                    record: RefundScope::new(&self.pool, ptr::null()),
                    active_owners: AtomicUsize::new(0),
                },
                charge,
            ),
            budget: self.clone(),
        };
        Ok(control
            .try_activate()
            .expect("new original control is inactive"))
    }

    /// Highest original-pool demand admitted since this budget was created.
    ///
    /// Credits held by prepaid leases remain included until their actual owner
    /// refunds them. Reloading the limit does not reset this diagnostic.
    pub fn peak_reserved_bytes(&self) -> usize {
        self.pool.peak_reserved.load(Ordering::Acquire)
    }

    /// Defer this thread's refund notifications through a synchronous operation.
    ///
    /// Freed allocation credits become available immediately. Only wakes for
    /// this exact pool wait until the closure returns or unwinds. Nested scopes
    /// for the same pool coalesce; other pools and other threads notify normally.
    /// Entering, recording refunds and leaving the scope allocate no storage.
    /// User waker callbacks can still allocate or panic when notification runs.
    ///
    /// Acquire and release every physical guard inside the closure. Do not keep
    /// an enclosing guard held or return one from the closure: the budget cannot
    /// infer lock ownership. Detached allocation owners may escape after their
    /// physical guards have been released. The callback receives a borrowed,
    /// thread-bound token for APIs that enforce this lifetime in their physical
    /// owner types. This does not make an async future execute inside the scope.
    pub fn with_deferred_refund_notifications<R>(
        &self,
        operation: impl for<'scope> FnOnce(&'scope AllocationScope<'scope>) -> R,
    ) -> R {
        self.with_refund_scope(None, operation)
    }

    /// Retain this original pool's wakes beyond a synchronous scratch operation.
    /// The returned owner must outlive every physical writer enclosing its scopes.
    /// Creating it only clones the existing pool handle and allocates nothing.
    pub fn deferred_refund_batch(&self) -> AllocationRefundBatch {
        AllocationRefundBatch::new(self.clone())
    }

    fn with_refund_scope<R>(
        &self,
        retained: Option<&Cell<bool>>,
        operation: impl for<'scope> FnOnce(&'scope AllocationScope<'scope>) -> R,
    ) -> R {
        let scope = RefundScope::new(&self.pool, REFUND_SCOPES.with(Cell::get));
        let entered = EnteredRefundScope {
            scope: &scope,
            pool: &self.pool,
            retained,
        };
        REFUND_SCOPES.with(|head| head.set(ptr::from_ref(&scope)));
        let capability = AllocationScope {
            budget: self,
            _thread: std::marker::PhantomData,
        };
        let output = operation(&capability);
        drop(entered);
        output
    }

    /// Prepay one exact allocation layout without allocating its payload.
    ///
    /// # Errors
    /// Refuses demands above the policy limit or unavailable original-pool capacity.
    pub fn try_reserve(&self, layout: Layout) -> Result<AllocationReservation, AllocationRefusal> {
        self.try_reserve_layouts([layout])
    }

    /// Prepay all supplied layouts atomically before any payload construction.
    ///
    /// This method retains no collection of layouts. Their checked sum must fit
    /// the finite policy limit. Refusal changes no credits; a temporary capacity
    /// refusal includes the original pool's pre-probe release observation.
    ///
    /// # Errors
    /// Refuses a sum that overflows `usize`, exceeds the policy limit, or lacks pool capacity.
    pub fn try_reserve_layouts(
        &self,
        layouts: impl IntoIterator<Item = Layout>,
    ) -> Result<AllocationReservation, AllocationRefusal> {
        let bytes = layouts.into_iter().try_fold(0_usize, |total, layout| {
            total
                .checked_add(layout.size())
                .ok_or(AllocationRefusal::DemandOverflow)
        })?;
        self.try_reserve_bytes(bytes)
    }

    /// Prepay an already checked sum of concrete requested allocation layouts.
    ///
    /// Use this when allocation-free planning has accumulated a complete demand
    /// without retaining a collection of layouts. The sum may exceed the maximum
    /// size of one allocation; it is not represented by a fabricated aggregate
    /// `Layout`. Each actual allocation still splits its exact layout from the
    /// returned original reservation. This method does not infer nested storage
    /// or validate a caller's payload-cloning policy.
    ///
    /// # Errors
    /// Refuses demands above the policy limit or unavailable original-pool capacity.
    pub fn try_reserve_bytes(
        &self,
        bytes: usize,
    ) -> Result<AllocationReservation, AllocationRefusal> {
        let limit_guard = self
            .pool
            .limit
            .read()
            .expect("allocation budget limit lock");
        let limit = *limit_guard;
        if bytes > limit {
            return Err(AllocationRefusal::ExceedsLimit {
                requested_bytes: bytes,
                limit_bytes: limit,
            });
        }
        let release = self.pool.released.observe();
        let mut reserved = self.pool.reserved.load(Ordering::Acquire);
        loop {
            // A shrink may leave prior reservations above the new limit.
            // The limit read lock serializes this decision with reconfiguration.
            if bytes > limit.saturating_sub(reserved) {
                return Err(AllocationRefusal::Capacity {
                    requested_bytes: bytes,
                    reserved_bytes: reserved,
                    limit_bytes: limit,
                    release,
                });
            }
            match self.pool.reserved.compare_exchange_weak(
                reserved,
                reserved + bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.pool
                        .peak_reserved
                        .fetch_max(reserved + bytes, Ordering::AcqRel);
                    return Ok(AllocationReservation {
                        pool: Arc::clone(&self.pool),
                        remaining: bytes,
                    });
                }
                Err(current) => reserved = current,
            }
        }
    }
}

impl fmt::Debug for AllocationBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AllocationBudget")
            .field("limit_bytes", &self.limit_bytes())
            .field("reserved_bytes", &self.reserved_bytes())
            .field("peak_reserved_bytes", &self.peak_reserved_bytes())
            .finish()
    }
}

/// Local resource refusal, independent of proposal validity or publication.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    variant_size_differences,
    reason = "capacity refusal must retain its inline release observation without allocating"
)]
pub enum AllocationRefusal {
    /// The requested layout sum is not representable; no credits were changed.
    DemandOverflow,
    /// This demand cannot fit even after every outstanding allocation is freed.
    ExceedsLimit {
        /// Checked requested layout sum.
        requested_bytes: usize,
        /// Policy limit observed for this refusal.
        limit_bytes: usize,
    },
    /// Other outstanding owners temporarily occupy the required capacity.
    Capacity {
        /// Checked requested layout sum.
        requested_bytes: usize,
        /// Diagnostic occupied credits at the refused probe.
        reserved_bytes: usize,
        /// Policy limit observed for this refusal.
        limit_bytes: usize,
        /// Retry hint tied to this exact pool; it grants no future reservation.
        release: ReleaseWait,
    },
}

impl fmt::Display for AllocationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DemandOverflow => f.write_str("allocation layout demand overflows"),
            Self::ExceedsLimit {
                requested_bytes,
                limit_bytes,
            } => write!(
                f,
                "allocation demand {requested_bytes} exceeds finite limit {limit_bytes}"
            ),
            Self::Capacity {
                requested_bytes,
                reserved_bytes,
                limit_bytes,
                ..
            } => write!(
                f,
                "allocation demand {requested_bytes} unavailable: {reserved_bytes}/{limit_bytes} reserved"
            ),
        }
    }
}

impl std::error::Error for AllocationRefusal {}

/// Prepaid aggregate demand, split before constructing its actual allocations.
///
/// Dropping this owner refunds only its unused remainder. Charges already moved
/// into allocations remain reserved until those allocation owners release them.
#[must_use = "retain prepaid credits until split into actual allocation owners"]
pub struct AllocationReservation {
    pool: Arc<Pool>,
    remaining: usize,
}

impl AllocationReservation {
    /// Return prepaid bytes not yet moved into an allocation charge.
    pub fn remaining_bytes(&self) -> usize {
        self.remaining
    }

    /// Whether this original reservation belongs to the exact budget pool.
    /// Equal limits or available-byte observations never establish this identity.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        Arc::ptr_eq(&self.pool, &budget.pool)
    }

    /// Move part of one already prepaid sum into a second move-only reservation.
    ///
    /// No pool CAS, allocation, refund or notification occurs. Both remainders
    /// retain the same original pool and together own exactly the previous sum.
    /// A refused partition leaves the original owner unchanged.
    ///
    /// # Errors
    /// Returns the requested and remaining byte counts when the partition exceeds the remainder.
    pub fn try_partition_bytes(&mut self, bytes: usize) -> Result<Self, InsufficientReservation> {
        if bytes > self.remaining {
            return Err(InsufficientReservation {
                requested_bytes: bytes,
                remaining_bytes: self.remaining,
            });
        }
        self.remaining -= bytes;
        Ok(Self {
            pool: Arc::clone(&self.pool),
            remaining: bytes,
        })
    }

    /// Move one exact layout's credits into an independent allocation owner.
    /// No pool acquisition or payload allocation occurs here. Refusal preserves
    /// the complete original reservation for a corrected split or abandonment.
    ///
    /// # Errors
    /// Returns the requested and remaining byte counts when the layout exceeds the remainder.
    pub fn try_split(
        &mut self,
        layout: Layout,
    ) -> Result<AllocationCharge, InsufficientReservation> {
        let bytes = layout.size();
        if bytes > self.remaining {
            return Err(InsufficientReservation {
                requested_bytes: bytes,
                remaining_bytes: self.remaining,
            });
        }
        self.remaining -= bytes;
        Ok(AllocationCharge {
            pool: Arc::clone(&self.pool),
            layout,
        })
    }
}

impl fmt::Debug for AllocationReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AllocationReservation")
            .field("remaining_bytes", &self.remaining)
            .finish_non_exhaustive()
    }
}

impl Drop for AllocationReservation {
    fn drop(&mut self) {
        self.pool.refund(self.remaining);
    }
}

/// An allocation or component partition exceeds this owner's prepaid remainder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InsufficientReservation {
    /// Requested allocation layout size or checked component layout sum.
    pub requested_bytes: usize,
    /// Original prepaid remainder, unchanged by refusal.
    pub remaining_bytes: usize,
}

impl fmt::Display for InsufficientReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "allocation needs {} bytes but only {} prepaid bytes remain",
            self.requested_bytes, self.remaining_bytes
        )
    }
}

impl std::error::Error for InsufficientReservation {}

/// Move-only credits belonging to one concrete requested allocation layout.
///
/// Bind this owner to the allocation's actual deallocator. The charged EBR
/// implementation does so across writer abort, commit and deferred reclamation.
/// This value deliberately cannot be cloned or detached into a refundable count.
#[must_use = "move this charge into its actual allocation owner"]
pub struct AllocationCharge {
    pool: Arc<Pool>,
    layout: Layout,
}

impl AllocationCharge {
    /// Return the exact layout whose requested bytes remain prepaid.
    pub fn layout(&self) -> Layout {
        self.layout
    }

    /// Whether this charge belongs to the exact finite pool, not an equal limit.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        Arc::ptr_eq(&self.pool, &budget.pool)
    }
}

impl fmt::Debug for AllocationCharge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AllocationCharge")
            .field("layout", &self.layout)
            .finish_non_exhaustive()
    }
}

impl Drop for AllocationCharge {
    fn drop(&mut self) {
        self.pool.refund(self.layout.size());
    }
}

#[cfg(test)]
#[path = "allocation_tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) use test_support::without_allocations;

#[cfg(test)]
mod test_support;
