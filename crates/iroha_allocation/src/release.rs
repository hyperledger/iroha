// SPDX-License-Identifier: MPL-2.0
//! Physical release and original capacity observations for callback or thread retry.

use crate::shared::{ErasedShared, Shared};

use std::{
    future::Future,
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
    thread::Thread,
};

#[derive(Default)]
struct State {
    sequence: u64,
    poisoned: bool,
    waiters: Waiters,
    // Only allocation pools have an immediate credit-return sequence. Physical
    // sources use their actual lock-release sequence for both kinds of waiter.
    capacity_sequence: Option<u64>,
    threads: Waiters,
}

/// Nonowning links: every published node is retained by its unique registration.
#[derive(Default)]
struct Waiters {
    first: Option<std::ptr::NonNull<WaiterNode>>,
    last: Option<std::ptr::NonNull<WaiterNode>>,
    count: usize,
}

// Linked nodes remain in their original charged allocations until their owner
// unlinks under this State's mutex. Moving State transfers only those links.
unsafe impl Send for Waiters {}

#[derive(Default)]
struct WaiterLinks {
    previous: Option<std::ptr::NonNull<WaiterNode>>,
    next: Option<std::ptr::NonNull<WaiterNode>>,
    linked: bool,
    sequence: u64,
    waker: Option<WakeTarget>,
}

/// Thread unparking cannot execute caller code under an enclosing writer.
/// Task callbacks retain their ordinary physical-release deferral contract.
enum WakeTarget {
    Task(Waker),
    Thread(Thread),
}
impl WakeTarget {
    fn wake(self) {
        match self {
            Self::Task(waker) => waker.wake(),
            Self::Thread(thread) => thread.unpark(),
        }
    }
}

struct WaiterNode {
    links: std::cell::UnsafeCell<WaiterLinks>,
}

// Every linked access holds the original source's State mutex. Unlinked nodes
// are accessible only through an exclusive registration borrow, and source
// release never retains a node reference after unlocking that same mutex.
unsafe impl Send for WaiterNode {}
unsafe impl Sync for WaiterNode {}

impl Waiters {
    /// The original charged node remains live and unlinked during this call.
    unsafe fn push(
        &mut self,
        node: std::ptr::NonNull<WaiterNode>,
        sequence: u64,
        waker: WakeTarget,
    ) {
        // SAFETY: caller holds this source's mutex and retains the unique shell.
        let links = unsafe { &mut *node.as_ref().links.get() };
        debug_assert!(!links.linked);
        debug_assert!(links.waker.is_none());
        links.previous = self.last;
        links.next = None;
        links.linked = true;
        links.sequence = sequence;
        links.waker = Some(waker);
        if let Some(last) = self.last {
            // SAFETY: every linked predecessor is retained through this lock.
            unsafe { (*last.as_ref().links.get()).next = Some(node) };
        } else {
            self.first = Some(node);
        }
        self.last = Some(node);
        self.count += 1;
    }

    /// The original node belongs to this source or was already popped by it.
    unsafe fn unlink(&mut self, node: std::ptr::NonNull<WaiterNode>) -> Option<WakeTarget> {
        // SAFETY: caller retains this node and holds its original source mutex.
        let links = unsafe { &mut *node.as_ref().links.get() };
        if !links.linked {
            debug_assert!(links.waker.is_none());
            return None;
        }
        let previous = links.previous.take();
        let next = links.next.take();
        if let Some(previous) = previous {
            // SAFETY: a predecessor is distinct and retained while linked.
            unsafe { (*previous.as_ref().links.get()).next = next };
        } else {
            self.first = next;
        }
        if let Some(next) = next {
            // SAFETY: a successor is distinct and retained while linked.
            unsafe { (*next.as_ref().links.get()).previous = previous };
        } else {
            self.last = previous;
        }
        links.linked = false;
        self.count -= 1;
        links.waker.take()
    }

    fn pop_before(&mut self, cutoff: u64) -> Option<WakeTarget> {
        let first = self.first?;
        // SAFETY: the source mutex retains all live intrusive links. A release
        // takes only the Waker out; no node reference survives the unlock.
        if unsafe { (*first.as_ref().links.get()).sequence } >= cutoff {
            return None;
        }
        unsafe { self.unlink(first) }
    }
}

/// Notification source belonging to one physical lock or allocation pool.
///
/// Observe before attempting acquisition and wrap every acquired guard with
/// [`Self::guard`]. A refused acquisition can then return its observation even
/// if the blocking owner released before the caller registered an async waiter.
/// Readers that exclude writers must also be wrapped. Allocation pools additionally
/// record actual returned credits for callback-free native thread parking. Signals
/// grant no mutation authority: every retry must acquire its original resource.
#[derive(Clone)]
pub struct ReleaseNotification {
    state: ErasedShared<Mutex<State>>,
}

impl std::fmt::Debug for ReleaseNotification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReleaseNotification")
            .finish_non_exhaustive()
    }
}

impl Default for ReleaseNotification {
    fn default() -> Self {
        let state = ErasedShared::new(Mutex::new(State::default()), ());
        // Some platforms allocate native mutex storage on first acquisition.
        // Pay that construction cost here, before allocation-free observations
        // or a release that may itself be returning exhausted capacity.
        drop(state.lock().unwrap_or_else(PoisonError::into_inner));
        Self { state }
    }
}

impl ReleaseNotification {
    /// Construct the allocation pool's original source, including its immediate
    /// credit sequence. Only actual refunds or limit growth may advance it.
    pub(crate) fn for_capacity() -> Self {
        let state = ErasedShared::new(
            Mutex::new(State {
                capacity_sequence: Some(0),
                ..State::default()
            }),
            (),
        );
        drop(state.lock().unwrap_or_else(PoisonError::into_inner));
        Self { state }
    }

    /// Record an actual return of usable credits without executing callbacks.
    /// Registered threads may run independently; arbitrary task wakers remain
    /// deferred until `released` runs after this thread's physical guards retire.
    pub(crate) fn capacity_returned(&self) {
        let cutoff = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let sequence = state
                .capacity_sequence
                .as_mut()
                .expect("original capacity source");
            *sequence = sequence.saturating_add(1);
            *sequence
        };
        self.unpark_before(cutoff);
    }

    fn unpark_before(&self, cutoff: u64) {
        loop {
            let retired = {
                let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                state.threads.pop_before(cutoff)
            };
            let Some(WakeTarget::Thread(thread)) = retired else {
                debug_assert!(retired.is_none(), "callback-free thread list");
                break;
            };
            // The original Thread handle was captured before pool exhaustion.
            // No callback, waiter allocation or TLS thread initialization occurs.
            thread.unpark();
        }
    }

    /// Exact original notification-state allocation, including its counter and charge.
    /// Native mutex internals and pending waiter storage are separate owners.
    pub fn allocation_layout<Charge>() -> std::alloc::Layout {
        Shared::<Mutex<State>, Charge>::layout()
    }

    /// Construct the original notification state with prepaid control custody.
    /// Observations and deferred releases retain this same allocation and charge.
    /// This does not admit native mutex internals or future waiter allocations.
    pub fn new_charged<Charge: Send + Sync + 'static>(charge: Charge) -> Self {
        let state = ErasedShared::new(Mutex::new(State::default()), charge);
        drop(state.lock().unwrap_or_else(PoisonError::into_inner));
        Self { state }
    }

    /// Fallibly construct the same prepaid notification control allocation.
    /// Refusal returns its unchanged charge; no observation or signal was created.
    /// Native mutex internals and future waiter storage remain separate owners.
    ///
    /// # Errors
    /// Returns the unchanged charge when the notification control allocation is refused.
    pub fn try_new_charged<Charge: Send + Sync + 'static>(
        charge: Charge,
    ) -> Result<Self, (Charge, crate::shared::ReservationError)> {
        let state = ErasedShared::try_new(Mutex::new(State::default()), charge)
            .map_err(|(_, charge, error)| (charge, error))?;
        drop(state.lock().unwrap_or_else(PoisonError::into_inner));
        Ok(Self { state })
    }

    /// Observe releases before probing this notification's physical lock.
    pub fn observe(&self) -> ReleaseWait {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let sequence = state.sequence;
        let thread_sequence = state.capacity_sequence.unwrap_or(sequence);
        drop(state);
        ReleaseWait {
            state: self.state.clone(),
            sequence,
            thread_sequence,
        }
    }

    /// Retain any number of actual releases of this source in constant space.
    /// An empty batch emits no notification. Each release must be transferred
    /// by its original guard; this constructor grants no authority to signal.
    pub fn deferred_batch(&self) -> DeferredReleaseBatch {
        DeferredReleaseBatch {
            notification: ReleaseNotification {
                state: self.state.clone(),
            },
            released: false,
            poisoned: false,
        }
    }

    /// Check original batch custody before acquiring a physical owner. This
    /// observation grants no authority to record a release or signal a wake.
    pub fn owns_batch(&self, batch: &DeferredReleaseBatch) -> bool {
        ErasedShared::ptr_eq(&self.state, &batch.notification.state)
    }

    /// Bind a physical guard to notification after its actual release.
    /// Read guards and locks without poisoning use this form: their unwind does
    /// not turn later ordinary contention into a poisoned-writer failure.
    pub fn guard<T>(&self, guard: T) -> ReleaseGuard<'_, T> {
        ReleaseGuard {
            inner: Some(guard),
            notification: self,
            poison: PoisonPolicy::Never,
        }
    }

    /// Bind a guard whose underlying lock becomes poisoned when it unwinds.
    /// This retains that distinction for try-lock APIs that erase poison into
    /// the same absence result as ordinary contention.
    pub fn poisoning_guard<T>(&self, guard: T) -> ReleaseGuard<'_, T> {
        ReleaseGuard {
            inner: Some(guard),
            notification: self,
            poison: PoisonPolicy::Unwind,
        }
    }

    /// Bind the native lock's permanent poison flag to its exact release.
    /// Private retained owners distinguish immutable abandonment from a failed
    /// mutation; observe after unlocking, before any user wake callback.
    pub fn observed_guard<'a, T>(
        &'a self,
        guard: T,
        poisoned: &'a AtomicBool,
    ) -> ReleaseGuard<'a, T> {
        ReleaseGuard {
            inner: Some(guard),
            notification: self,
            poison: PoisonPolicy::Observed(poisoned),
        }
    }

    /// Cover acquisition that may panic after locking but before returning its
    /// physical guard, for example while cloning an EBR generation. Normal
    /// completion emits no signal: the caller must immediately wrap the returned
    /// physical guard. Unwinding signals only after the inner acquisition stack
    /// has released its raw lock, so an already-waiting retry learns of poison.
    pub fn with_acquisition_unwind_notification<T>(&self, acquire: impl FnOnce() -> T) -> T {
        struct Acquisition<'a> {
            notification: &'a ReleaseNotification,
            armed: bool,
        }
        impl Drop for Acquisition<'_> {
            fn drop(&mut self) {
                if self.armed {
                    self.notification.released(true);
                }
            }
        }
        let mut acquisition = Acquisition {
            notification: self,
            armed: true,
        };
        let guard = acquire();
        acquisition.armed = false;
        guard
    }

    fn released(&self, poisoned: bool) {
        struct WakeCohort<'a> {
            source: &'a ReleaseNotification,
            cutoff: u64,
        }
        impl WakeCohort<'_> {
            fn drain(&mut self) {
                loop {
                    let waker = {
                        let mut state = self
                            .source
                            .state
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner);
                        state.waiters.pop_before(self.cutoff)
                    };
                    let Some(waker) = waker else { break };
                    // Only this owned callback leaves the source lock. A
                    // callback may cancel/rearm any node without invalidating
                    // an outer release's pointers or joining its old cohort.
                    waker.wake();
                }
            }
        }
        impl Drop for WakeCohort<'_> {
            fn drop(&mut self) {
                // Preserve the original panic while notifying survivors. A
                // second callback panic has ordinary double-panic semantics.
                self.drain();
            }
        }
        let (cutoff, physical_threads) = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.sequence = state.sequence.saturating_add(1);
            state.poisoned |= poisoned;
            (state.sequence, state.capacity_sequence.is_none())
        };
        if physical_threads {
            self.unpark_before(cutoff);
        }
        let mut cohort = WakeCohort {
            source: self,
            cutoff,
        };
        cohort.drain();
    }
}

/// Opaque observation of one original resource, safe to retain across dispatch.
///
/// Callback registrations observe physical release after enclosing writer scopes.
/// Native thread registrations observe actual allocation credit returns for pools,
/// or the same physical release for locks. Both cuts belong to this exact source.
/// This grants neither publication authority nor possession of the resource.
/// Clones retain the same cuts and may wait independently; observation allocates
/// nothing. Each waiter retains its original prepaid registration and wake target.
#[derive(Clone)]
pub struct ReleaseWait {
    state: ErasedShared<Mutex<State>>,
    sequence: u64,
    thread_sequence: u64,
}

impl std::fmt::Debug for ReleaseWait {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReleaseWait").finish_non_exhaustive()
    }
}

impl PartialEq for ReleaseWait {
    fn eq(&self, other: &Self) -> bool {
        ErasedShared::ptr_eq(&self.state, &other.state)
            && self.sequence == other.sequence
            && self.thread_sequence == other.thread_sequence
    }
}
impl Eq for ReleaseWait {}

/// Reusable waiter storage admitted before an operation can encounter refusal.
///
/// One stable charged allocation is retained until this owner drops. Arming,
/// polling, replacement, cancellation and release allocate no waiter storage.
/// Arbitrary Waker callbacks remain owned by their callers. A registration is
/// move-only and one exclusive borrow prevents overlapping borrowed futures.
pub struct ReleaseRegistration {
    node: crate::ChargedShared<WaiterNode>,
    observation: Option<ReleaseWait>,
    thread: Option<Thread>,
}

impl std::fmt::Debug for ReleaseRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReleaseRegistration")
            .field("observing", &self.observation.is_some())
            .finish_non_exhaustive()
    }
}

impl ReleaseRegistration {
    /// Exact original control, inline waiter links, callback slot and charge.
    pub fn allocation_layout() -> std::alloc::Layout {
        crate::ChargedShared::<WaiterNode>::allocation_layout()
    }

    /// Construct one reusable physical node from its original prepaid owner.
    ///
    /// # Errors
    /// Returns exact reservation shortage or allocator refusal. No new pool,
    /// release observation or successful registration is manufactured on error.
    pub fn from_reservation(
        reservation: &mut crate::AllocationReservation,
    ) -> Result<Self, crate::PrepaidSharedError> {
        let node = crate::ChargedShared::from_reservation(
            WaiterNode {
                links: std::cell::UnsafeCell::new(WaiterLinks::default()),
            },
            reservation,
        )
        .map_err(|(_, error)| error)?;
        Ok(Self {
            node,
            observation: None,
            thread: None,
        })
    }

    /// Whether the physical waiter allocation retains this exact original pool.
    pub fn belongs_to(&self, budget: &crate::AllocationBudget) -> bool {
        self.node.belongs_to(budget)
    }

    fn pointer(&self) -> std::ptr::NonNull<WaiterNode> {
        std::ptr::NonNull::from(&*self.node)
    }

    /// Bind this existing prepaid node to callback-free parking of an original
    /// thread captured during startup, before the pool can become exhausted.
    ///
    /// Changing the target cancels its old observation. Subsequent `poll_wait`
    /// calls do not clone, retain or invoke their Context's Waker. Actual pool
    /// credits can wake this thread while generic callbacks still await writer
    /// retirement. Physical lock waits still require the real lock's release.
    /// No thread handle is constructed and no waiter storage is allocated here.
    pub fn bind_thread(&mut self, thread: Thread) {
        self.cancel();
        self.thread = Some(thread);
    }

    /// Detach the current wait while retaining its physical node for reuse.
    /// Original callbacks and source retirement run only after source unlock.
    pub fn cancel(&mut self) {
        let Some(observation) = self.observation.take() else {
            return;
        };
        let retired = {
            let mut state = observation
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            // SAFETY: self owns the stable node; observation is its exact source.
            unsafe {
                if self.thread.is_some() {
                    state.threads.unlink(self.pointer())
                } else {
                    state.waiters.unlink(self.pointer())
                }
            }
        };
        drop(retired);
        drop(observation);
    }

    /// Poll one exact pre-probe observation using this original reusable node.
    ///
    /// Changing source or sequence cancels the old wait first. A completed
    /// release permits a new attempt; it grants neither lock nor capacity.
    /// When `bind_thread` selected native parking, the captured thread receives
    /// the wake and `cx` is not retained or invoked.
    pub fn poll_wait(&mut self, observation: &ReleaseWait, cx: &mut Context<'_>) -> Poll<()> {
        if self.observation.as_ref() != Some(observation) {
            self.cancel();
            self.observation = Some(observation.clone());
        }
        self.poll_current(cx)
    }

    fn poll_current(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.thread.is_some() {
            return self.poll_thread();
        }
        // Clone callbacks may reenter a source; no internal mutex is held.
        let replacement = cx.waker().clone();
        let original = self.observation.as_ref().expect("original release source");
        let mut state = original
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if state.sequence != original.sequence || state.sequence == u64::MAX {
            // SAFETY: this registration retains its exact node and source.
            let retired = unsafe { state.waiters.unlink(self.pointer()) };
            drop(state);
            drop(retired);
            drop(replacement);
            return Poll::Ready(());
        }
        // SAFETY: this source's mutex excludes release and list mutation, while
        // the exclusive registration borrow excludes concurrent rearming.
        let links = unsafe { &mut *self.node.links.get() };
        let retired = if links.linked {
            if links.waker.as_ref().is_none_or(
                |old| !matches!(old, WakeTarget::Task(old) if old.will_wake(cx.waker())),
            ) {
                links.waker.replace(WakeTarget::Task(replacement))
            } else {
                Some(WakeTarget::Task(replacement))
            }
        } else {
            // SAFETY: this original node is live, unlinked, and retained by self.
            unsafe {
                state.waiters.push(
                    self.pointer(),
                    original.sequence,
                    WakeTarget::Task(replacement),
                )
            };
            None
        };
        drop(state);
        drop(retired);
        Poll::Pending
    }

    fn poll_thread(&mut self) -> Poll<()> {
        let original = self.observation.as_ref().expect("original release source");
        let mut state = original
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let sequence = state.capacity_sequence.unwrap_or(state.sequence);
        if sequence != original.thread_sequence || sequence == u64::MAX {
            // SAFETY: the same charged node and exact source remain owned here.
            let retired = unsafe { state.threads.unlink(self.pointer()) };
            drop(state);
            drop(retired);
            return Poll::Ready(());
        }
        // SAFETY: this source mutex excludes release and cancellation; this
        // exclusive registration borrow excludes target replacement.
        let links = unsafe { &*self.node.links.get() };
        if !links.linked {
            let thread = self.thread.as_ref().expect("bound original thread").clone();
            // SAFETY: the original stable node remains live and unlinked.
            unsafe {
                state.threads.push(
                    self.pointer(),
                    original.thread_sequence,
                    WakeTarget::Thread(thread),
                );
            }
        }
        Poll::Pending
    }
}

impl Drop for ReleaseRegistration {
    fn drop(&mut self) {
        // Unlink before ChargedShared frees the physical node or refunds credit.
        // Retaining the source here also covers a forgotten borrowed future.
        self.cancel();
    }
}

impl ReleaseWait {
    /// Whether a released physical owner reported permanent mutex poison.
    pub fn is_poisoned(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .poisoned
    }

    /// Borrow already admitted storage for this exact release observation.
    /// Dropping the future cancels the wait but retains its reusable storage.
    pub fn wait_for_release(self, registration: &mut ReleaseRegistration) -> ReleaseFuture<'_> {
        registration.cancel();
        registration.observation = Some(self);
        ReleaseFuture { registration }
    }
}

/// One borrowed wait over the canonical reusable registration engine.
pub struct ReleaseFuture<'registration> {
    registration: &'registration mut ReleaseRegistration,
}

impl Future for ReleaseFuture<'_> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        this.registration.poll_current(cx)
    }
}

impl Drop for ReleaseFuture<'_> {
    fn drop(&mut self) {
        self.registration.cancel();
    }
}

#[derive(Clone, Copy)]
#[allow(
    variant_size_differences,
    reason = "native poison observation remains inline so physical release never allocates"
)]
enum PoisonPolicy<'a> {
    Never,
    Unwind,
    Observed(&'a AtomicBool),
    Fixed(bool),
}
impl PoisonPolicy<'_> {
    fn observe(self) -> bool {
        match self {
            Self::Never => false,
            Self::Unwind => std::thread::panicking(),
            Self::Observed(flag) => flag.load(Ordering::Acquire),
            Self::Fixed(value) => value,
        }
    }
}

/// Physical guard that signals only after its inner guard has been released.
///
/// Drop covers abort/unwind as well as ordinary release. This wrapper deliberately
/// exposes no extraction that could separate the guard from its release signal.
pub struct ReleaseGuard<'owner, T> {
    inner: Option<T>,
    notification: &'owner ReleaseNotification,
    poison: PoisonPolicy<'owner>,
}

/// Original notification retained after physical unlock until aggregate cleanup.
/// This owns the same notification state and allocates no replacement source.
/// Dropping it delivers the recorded release, even if later cleanup unwinds.
pub struct DeferredRelease {
    notification: ReleaseNotification,
    poisoned: bool,
    armed: bool,
}

impl DeferredRelease {
    /// Retain this actual release in a batch belonging to the same original source.
    /// A foreign batch returns the unchanged notice. Success coalesces release and
    /// poison without waking, allocating, or retiring any protected payload.
    ///
    /// # Errors
    /// Returns this unchanged notice when the batch belongs to another notification source.
    pub fn try_merge_into(mut self, batch: &mut DeferredReleaseBatch) -> Result<(), Self> {
        if !ErasedShared::ptr_eq(&self.notification.state, &batch.notification.state) {
            return Err(self);
        }
        batch.released = true;
        batch.poisoned |= self.poisoned;
        self.armed = false;
        Ok(())
    }
}

/// Bounded custody of actual releases from one original physical lock.
///
/// All recorded releases remain deferred until this owner drops. They coalesce
/// into one wake hint: waiters must still reacquire and authenticate the lock.
/// Recording does not allocate, invoke callbacks, or create another source.
#[must_use = "retain recorded releases through all enclosing physical owners"]
pub struct DeferredReleaseBatch {
    notification: ReleaseNotification,
    released: bool,
    poisoned: bool,
}

impl Drop for DeferredReleaseBatch {
    fn drop(&mut self) {
        if self.released {
            self.notification.released(self.poisoned);
        }
    }
}

impl Drop for DeferredRelease {
    fn drop(&mut self) {
        if self.armed {
            self.notification.released(self.poisoned);
        }
    }
}

impl<'owner, T> ReleaseGuard<'owner, T> {
    /// Release this actual guard into a batch of the same original source.
    /// A foreign batch returns the unchanged guard without calling `release`.
    /// The callback must unlock the physical owner on success and unwind;
    /// returned values may retain cleanup but never the physical guard.
    /// Acquisition poison is recorded before any later cleanup can unwind.
    ///
    /// # Errors
    /// Returns the unchanged guard if the batch belongs to another notification source.
    pub fn try_release_into<R>(
        mut self,
        batch: &mut DeferredReleaseBatch,
        release: impl FnOnce(T) -> R,
    ) -> Result<R, Self> {
        struct Record<'a> {
            batch: &'a mut DeferredReleaseBatch,
            poison: PoisonPolicy<'a>,
        }
        impl Drop for Record<'_> {
            fn drop(&mut self) {
                self.batch.released = true;
                self.batch.poisoned |= self.poison.observe();
            }
        }
        if !ErasedShared::ptr_eq(&self.notification.state, &batch.notification.state) {
            return Err(self);
        }
        // On callback unwind the original physical owner drops before this
        // record. The batch remains in its caller's aggregate throughout.
        let record = Record {
            batch,
            poison: self.poison,
        };
        let inner = self.inner.take().expect("owned release guard");
        let _transferred = std::mem::ManuallyDrop::new(self);
        let result = release(inner);
        drop(record);
        Ok(result)
    }

    /// Release a physical owner now, retaining its original notification by value.
    /// The callback must release the physical guard on success and unwind. Normal
    /// release allocates nothing and runs no wake callback; the returned owner is
    /// dropped only after every enclosing publication fence has released.
    pub fn release_deferred<R>(self, release: impl FnOnce(T) -> R) -> (R, DeferredRelease) {
        let policy = self.poison;
        let mut retirement = self.release_retaining(release);
        // Actual primitive poison is established when its guard is released.
        let poisoned = policy.observe();
        let notification = DeferredRelease {
            notification: ReleaseNotification {
                state: retirement.notification.state.clone(),
            },
            poisoned,
            armed: true,
        };
        let retained = retirement.inner.take().expect("owned release retirement");
        let _transferred = std::mem::ManuallyDrop::new(retirement);
        (retained, notification)
    }

    /// Release this actual guard into its original batch with an exact poison verdict.
    /// A foreign batch returns the unchanged guard without invoking either callback.
    /// `release` must unlock on success and unwind; `observe_poison` must inspect
    /// only the corresponding native mutex and cannot invoke user code.
    ///
    /// # Errors
    /// Returns the unchanged guard if the batch belongs to another notification source.
    pub fn try_release_into_observed<R>(
        mut self,
        batch: &mut DeferredReleaseBatch,
        release: impl FnOnce(T) -> R,
        observe_poison: impl Fn() -> bool,
    ) -> Result<R, Self> {
        struct Record<'a, F: Fn() -> bool> {
            batch: &'a mut DeferredReleaseBatch,
            observe_poison: F,
        }
        impl<F: Fn() -> bool> Drop for Record<'_, F> {
            fn drop(&mut self) {
                self.batch.released = true;
                self.batch.poisoned |= (self.observe_poison)();
            }
        }
        if !ErasedShared::ptr_eq(&self.notification.state, &batch.notification.state) {
            return Err(self);
        }
        let record = Record {
            batch,
            observe_poison,
        };
        let inner = self.inner.take().expect("original physical guard");
        let _transferred = std::mem::ManuallyDrop::new(self);
        let result = release(inner);
        drop(record);
        Ok(result)
    }

    /// Change ownership phase while the caller retains original unwind notification.
    ///
    /// The outer error returns a foreign-batch guard untouched. The inner result
    /// transfers the original notification with either the new or refused guard.
    /// Only a callee unwind records a release in `batch`, after `consume` has
    /// destroyed its physical guard. Completed payloads and unused charges must
    /// already belong to the caller's acquisition slot before another conversion.
    /// `observe_poison` inspects only this original native mutex and cannot panic.
    ///
    /// # Errors
    /// The outer error returns the unchanged guard for a foreign batch. The inner error
    /// returns the original guard and the callback's refusal without recording a release.
    pub fn try_map_preserving_release_into<R, E>(
        mut self,
        batch: &mut DeferredReleaseBatch,
        consume: impl FnOnce(T) -> Result<R, (T, E)>,
        observe_poison: impl Fn() -> bool,
    ) -> Result<Result<ReleaseGuard<'owner, R>, (Self, E)>, Self> {
        struct Record<'a, F: Fn() -> bool> {
            batch: &'a mut DeferredReleaseBatch,
            observe_poison: F,
            armed: bool,
        }
        impl<F: Fn() -> bool> Drop for Record<'_, F> {
            fn drop(&mut self) {
                if self.armed {
                    self.batch.released = true;
                    self.batch.poisoned |= (self.observe_poison)();
                }
            }
        }
        if !ErasedShared::ptr_eq(&self.notification.state, &batch.notification.state) {
            return Err(self);
        }
        let mut record = Record {
            batch,
            observe_poison,
            armed: true,
        };
        let inner = self.inner.take().expect("original physical guard");
        let transferred = std::mem::ManuallyDrop::new(self);
        let result = consume(inner);
        record.armed = false;
        drop(record);
        Ok(match result {
            Ok(inner) => Ok(ReleaseGuard {
                inner: Some(inner),
                notification: transferred.notification,
                poison: transferred.poison,
            }),
            Err((inner, error)) => Err((
                Self {
                    inner: Some(inner),
                    notification: transferred.notification,
                    poison: transferred.poison,
                },
                error,
            )),
        })
    }

    /// Attempt a phase change while retaining the original guard on refusal.
    /// Neither success nor refusal emits a release; the returned owner remains
    /// responsible for the same physical lock. Unwind releases before signaling.
    ///
    /// # Errors
    /// Returns the original guard and the callback's error when the phase change is refused.
    pub fn try_map_preserving_release<R, E>(
        mut self,
        consume: impl FnOnce(T) -> Result<R, (T, E)>,
    ) -> Result<ReleaseGuard<'owner, R>, (Self, E)> {
        let result = consume(self.inner.take().expect("owned release guard"));
        let result = match result {
            Ok(inner) => Ok(ReleaseGuard {
                inner: Some(inner),
                notification: self.notification,
                poison: self.poison,
            }),
            Err((inner, error)) => Err((
                Self {
                    inner: Some(inner),
                    notification: self.notification,
                    poison: self.poison,
                },
                error,
            )),
        };
        let _transferred = std::mem::ManuallyDrop::new(self);
        result
    }

    /// Transfer the original release notification across an ownership phase.
    /// No notification or old-owner destructor runs after a successful transfer.
    /// An unwind still drops the consumed physical owner before signaling.
    pub fn map_preserving_release<R>(
        mut self,
        consume: impl FnOnce(T) -> R,
    ) -> ReleaseGuard<'owner, R> {
        let inner = consume(self.inner.take().expect("owned release guard"));
        let result = ReleaseGuard {
            inner: Some(inner),
            notification: self.notification,
            poison: self.poison,
        };
        // The empty predecessor owns no allocation or physical guard. Its
        // notification has moved to result and must not run at this transition.
        let _transferred = std::mem::ManuallyDrop::new(self);
        result
    }

    /// Release the physical owner while retaining cleanup and its notification.
    /// The callback must return only owners whose destruction cannot poison the
    /// released physical lock. A callback unwind retains the original poisoning
    /// behavior; a later cleanup unwind must not poison an already healthy lock.
    pub fn release_retaining<R>(self, release: impl FnOnce(T) -> R) -> ReleaseGuard<'owner, R> {
        let mut retirement = self.map_preserving_release(release);
        retirement.poison = match retirement.poison {
            PoisonPolicy::Observed(flag) => PoisonPolicy::Fixed(flag.load(Ordering::Acquire)),
            PoisonPolicy::Fixed(value) => PoisonPolicy::Fixed(value),
            _ => PoisonPolicy::Never,
        };
        retirement
    }

    /// Consume a guard through its commit operation, then notify after it returns.
    /// Unwinding also releases the guard before notification.
    pub fn release_with<R>(mut self, consume: impl FnOnce(T) -> R) -> R {
        consume(self.inner.take().expect("owned release guard"))
    }

    /// Release this actual owner and report its physical poison after unlock.
    /// `consume` must release the lock on success and unwind. Unlike thread-local
    /// panic state, the observation also preserves poison predating acquisition
    /// and excludes a later callback panic after a healthy physical release.
    pub fn release_with_observed_poison<R>(
        mut self,
        consume: impl FnOnce(T) -> R,
        observe_poison: impl Fn() -> bool,
    ) -> R {
        struct Signal<'a, F: Fn() -> bool> {
            notification: &'a ReleaseNotification,
            observe_poison: F,
        }
        impl<F: Fn() -> bool> Drop for Signal<'_, F> {
            fn drop(&mut self) {
                self.notification.released((self.observe_poison)());
            }
        }
        let signal = Signal {
            notification: self.notification,
            observe_poison,
        };
        let inner = self.inner.take().expect("owned release guard");
        let _transferred = std::mem::ManuallyDrop::new(self);
        let result = consume(inner);
        drop(signal);
        result
    }

    /// Release both original physical owners before either notification runs.
    /// The callback must release both owners on success and unwind; returned
    /// values may retain cleanup, but never physical guards. Observe the actual
    /// two locks' poison state after release, before any arbitrary wake callback.
    pub fn release_pair_with<S, R>(
        self,
        other: ReleaseGuard<'_, S>,
        consume: impl FnOnce(T, S) -> R,
        observe_poison: impl Fn() -> (bool, bool),
    ) -> R {
        match self.try_map_pair_preserving_release::<_, (), (), R>(
            other,
            |first, second| Err(consume(first, second)),
            observe_poison,
        ) {
            Err(result) => result,
            Ok(_) => unreachable!("release never transfers physical owners"),
        }
    }

    /// Transfer both original guards through one fallible construction phase.
    /// Success retains both original notifications without invoking callbacks.
    /// On error or unwind, `consume` must release both physical guards before
    /// returning or unwinding; neither notification runs until that completes.
    /// Freeze both physical poison verdicts before any wake callback can panic.
    ///
    /// # Errors
    /// Returns the callback's error after both physical guards are released and notified.
    pub fn try_map_pair_preserving_release<'other, S, A, B, E>(
        mut self,
        mut other: ReleaseGuard<'other, S>,
        consume: impl FnOnce(T, S) -> Result<(A, B), E>,
        observe_poison: impl Fn() -> (bool, bool),
    ) -> Result<(ReleaseGuard<'owner, A>, ReleaseGuard<'other, B>), E> {
        struct Signal<'a> {
            notification: &'a ReleaseNotification,
            poisoned: bool,
        }
        impl Drop for Signal<'_> {
            fn drop(&mut self) {
                self.notification.released(self.poisoned);
            }
        }
        struct PairSignals<'a, 'b, F: Fn() -> (bool, bool)> {
            first: &'a ReleaseNotification,
            second: &'b ReleaseNotification,
            observe_poison: F,
            armed: bool,
        }
        impl<F: Fn() -> (bool, bool)> Drop for PairSignals<'_, '_, F> {
            fn drop(&mut self) {
                if !self.armed {
                    return;
                }
                let (first, second) = (self.observe_poison)();
                let first = Signal {
                    notification: self.first,
                    poisoned: first,
                };
                let second = Signal {
                    notification: self.second,
                    poisoned: second,
                };
                // Both verdicts are frozen before the first callback. Unwind
                // must still deliver the other original release with its own
                // physical verdict, not the callback's panic state.
                drop(first);
                drop(second);
            }
        }
        let mut signals = PairSignals {
            first: self.notification,
            second: other.notification,
            observe_poison,
            armed: true,
        };
        let first = self.inner.take().expect("owned first release guard");
        let second = other.inner.take().expect("owned second release guard");
        // Only empty wrappers remain; the pair owns both original signals.
        let first_owner = std::mem::ManuallyDrop::new(self);
        let second_owner = std::mem::ManuallyDrop::new(other);
        match consume(first, second) {
            Ok((first, second)) => {
                signals.armed = false;
                Ok((
                    ReleaseGuard {
                        inner: Some(first),
                        notification: first_owner.notification,
                        poison: first_owner.poison,
                    },
                    ReleaseGuard {
                        inner: Some(second),
                        notification: second_owner.notification,
                        poison: second_owner.poison,
                    },
                ))
            }
            Err(error) => {
                drop(signals);
                Err(error)
            }
        }
    }
}

impl<T> Deref for ReleaseGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().expect("owned release guard")
    }
}
impl<T> DerefMut for ReleaseGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut().expect("owned release guard")
    }
}
impl<T> Drop for ReleaseGuard<'_, T> {
    fn drop(&mut self) {
        struct SignalAfterRelease<'a> {
            notification: &'a ReleaseNotification,
            poison: PoisonPolicy<'a>,
        }
        impl Drop for SignalAfterRelease<'_> {
            fn drop(&mut self) {
                self.notification.released(self.poison.observe());
            }
        }
        let signal = SignalAfterRelease {
            notification: self.notification,
            poison: self.poison,
        };
        // Even a panic in the inner destructor must run its drop glue before
        // signaling. The local guard keeps that ordering on both exits.
        drop(self.inner.take());
        drop(signal);
    }
}

#[cfg(test)]
#[path = "release_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "release_registration_tests.rs"]
mod registration_tests;

#[cfg(test)]
#[path = "release_thread_tests.rs"]
mod thread_tests;
