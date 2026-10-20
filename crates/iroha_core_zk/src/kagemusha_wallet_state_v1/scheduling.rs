//! Cooperative fold cancellation, exclusive payment priority and non-preempting ingests.
//!
//! A fold sub-proof holds the background slot from its locked prepare through its proof,
//! which runs without the wallet owner. It releases the slot before taking the owner again to
//! publish, so a payment that holds the owner and joins the slot never waits on that owner.
//!
//! The scheduler also owns the one volatile retention slot between the sub-proofs of a step
//! (D6b). A sub-proof takes it at its locked prepare and parks what it leaves for the next
//! sub-proof under its own attempt, atomically with releasing the background slot; only that
//! attempt's successful checkpoint publication promotes it. Payment priority, inactivity and
//! close invalidate it, so payment proving never runs beside retained fold memory.
//!
//! One speculative proof slot sits between the two (design §5.1, Payment row): a review's
//! `σ_send` proved before the user confirms. It is admitted only while no payment holds
//! priority, takes payment priority over the fold, and every payment waits for it instead of
//! cancelling it, so a confirmed payment finds the proof finished and no two provers overlap.
//! Its job uses the wallet owner only before admission, so that wait never needs the owner.
//! Close cancels it; dropping its [`Speculation`] cancels it and discards what it made.

use std::{
    any::Any,
    sync::{Arc, Condvar, Mutex, MutexGuard},
};

use super::{
    Error, FoldStatus,
    fold_metrics::{FoldCallClassV1, FoldCancelCauseV1, FoldObserverV1, FoldTurnV1},
};

/// Cloneable cancellation token checked at proving task boundaries.
#[derive(Debug, Clone)]
pub struct Cancellation(iroha_pasta::CancellationToken);

impl Cancellation {
    fn new() -> Self {
        Self(iroha_pasta::CancellationToken::new())
    }

    /// Stop at a cooperative boundary, releasing the caller's proving allocations on return.
    ///
    /// # Errors
    /// `Cancelled` after a payment interaction has requested priority.
    pub fn check(&self) -> Result<(), Error> {
        self.0.check().map_err(|_| Error::Cancelled)
    }

    // This exact signal follows a fold into every proving task; no process-global flag.
    pub(super) const fn prover_token(&self) -> &iroha_pasta::CancellationToken {
        &self.0
    }

    fn cancel(&self) {
        self.0.cancel();
    }
}

/// Volatile native fold state that one sub-proof leaves for the next sub-proof of the same
/// step (D6b).
///
/// The coordinator and the scheduler never read it. Only the native fold owner that created
/// it can recover its value; any other value, or none, is that owner's cold path in the same
/// call. It is process-local and move-only: it is never serialized, persisted, hashed into
/// durable data or exposed over FFI, and it grants no proof, custody or monetary authority.
/// Dropping it only releases memory; it does no I/O, takes no lock and proves nothing.
pub struct FoldRetentionV1(Box<dyn Any + Send>);

impl FoldRetentionV1 {
    pub(super) fn new<T: Any + Send>(value: T) -> Self {
        Self(Box::new(value))
    }

    /// The value, when its owner created it as a `T`; otherwise `None`, and it is dropped.
    pub(super) fn downcast<T: Any>(self) -> Option<T> {
        self.0.downcast::<T>().ok().map(|value| *value)
    }

    /// Test support: the value in place, when its owner created it as a `T`.
    #[cfg(test)]
    pub(super) fn downcast_mut<T: Any>(&mut self) -> Option<&mut T> {
        self.0.downcast_mut::<T>()
    }
}

/// The one retention slot of a scheduler.
enum Slot {
    /// Parked by the released sub-proof `attempt` until its publication settles. It is not a
    /// completed continuation: a new sub-proof evicts it and runs cold.
    Pending {
        attempt: u64,
        value: FoldRetentionV1,
    },
    /// Promoted by that sub-proof's durable checkpoint publication, for the next sub-proof.
    Ready(FoldRetentionV1),
}

#[derive(Default)]
struct State {
    eligible: bool,
    payments: usize,
    running: Option<Cancellation>,
    // The first signal that cancelled the running sub-proof; fold telemetry only.
    cause: Option<FoldCancelCauseV1>,
    // Ingests that ran while the running sub-proof held the slot; fold telemetry only.
    ingests: u32,
    observer: Option<Arc<dyn FoldObserverV1>>,
    // Volatile fold state between the sub-proofs of one step, owned by exactly one attempt.
    retained: Option<Slot>,
    // The identity of the last sub-proof attempt this scheduler started; never reused.
    attempts: u64,
    // The signal of the admitted speculative proof while it holds the speculation slot.
    speculating: Option<Cancellation>,
    // Close admits no later speculation.
    closed: bool,
}

impl State {
    fn cancel(&mut self, cause: FoldCancelCauseV1) {
        if let Some(token) = &self.running {
            self.cause = self.cause.or(Some(cause));
            token.cancel();
        }
    }
}

struct Inner {
    state: Mutex<State>,
    idle: Condvar,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Shared foreground/charging gate with payment preemption and proof-workspace release.
///
/// Payment arrival can call `payment` from another thread while a fold sub-proof proves. It
/// first signals cancellation, then waits until the sub-proof has returned and dropped its
/// work. Holding the returned guard prevents a new background proof from starting. Dropping
/// it permits resumption from the last durable checkpoint. No payment state is rolled back.
/// An `ingest` never cancels or waits: the sub-proof keeps proving outside the wallet owner.
/// Payment priority, inactivity and close also drop the volatile fold state retained between
/// sub-proofs; an ingest leaves it.
#[derive(Clone)]
pub struct Scheduler(Arc<Inner>);

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    /// Initially inactive; enable work explicitly when foreground or charging.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(Inner {
            state: Mutex::new(State::default()),
            idle: Condvar::new(),
        }))
    }

    /// Update app/device activity. Leaving both states cancels an existing sub-proof and drops
    /// the retained fold state.
    pub fn set_activity(&self, foreground: bool, charging: bool) {
        let released = {
            let mut state = self.0.lock();
            state.eligible = foreground || charging;
            if state.eligible {
                None
            } else {
                state.cancel(FoldCancelCauseV1::Activity);
                state.retained.take()
            }
        };
        // Retained fold memory is released after the state lock.
        drop(released);
    }

    /// The owner is closing: leave both states like [`Self::set_activity`], reporting a
    /// cancelled sub-proof as closed. A running speculative proof is cancelled and no later
    /// one is admitted.
    pub fn close(&self) {
        let released = {
            let mut state = self.0.lock();
            state.eligible = false;
            state.closed = true;
            state.cancel(FoldCancelCauseV1::Close);
            if let Some(token) = &state.speculating {
                token.cancel();
            }
            state.retained.take()
        };
        // A speculation still waiting for admission observes close and ends.
        self.0.idle.notify_all();
        drop(released);
    }

    /// Signal payment priority and join the current sub-proof before returning.
    #[must_use]
    pub fn payment(&self) -> PaymentGuard {
        self.payment_for(FoldCallClassV1::Payment)
    }

    /// [`Self::payment`] for a host call of `class`. The class only labels a cancelled
    /// sub-proof in fold telemetry; priority, cancellation and the join are identical.
    ///
    /// An admitted speculative proof is joined without being cancelled: it finishes, so a
    /// confirmed payment can use it, and only then may this payment prove.
    #[must_use]
    pub fn payment_for(&self, class: FoldCallClassV1) -> PaymentGuard {
        let mut state = self.0.lock();
        state.payments += 1;
        state.cancel(class.cause());
        while state.running.is_some() || state.speculating.is_some() {
            state = self
                .0
                .idle
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        // Payment proving never runs beside retained fold memory: take the sole retained
        // value, pending or ready, and drop it after the lock and before the guard returns.
        // A publication still waiting for the wallet owner finds its value gone.
        let released = state.retained.take();
        drop(state);
        drop(released);
        PaymentGuard(self.clone())
    }

    /// A host call that neither proves, signs, commits an Advance nor deletes custody. It never
    /// cancels or joins: a running sub-proof keeps proving outside the wallet owner and
    /// publishes only if its fold fields are still unchanged. Fold telemetry counts the call on
    /// that sub-proof (observation only). The retained fold state is left alone.
    pub fn ingest(&self) {
        let mut state = self.0.lock();
        if state.running.is_some() {
            state.ingests = state.ingests.saturating_add(1);
        }
    }

    /// Report every finished fold sub-proof of this scheduler to `observer`, replacing an
    /// earlier observer. Observation only: nothing reads the reports back.
    pub fn observe(&self, observer: Arc<dyn FoldObserverV1>) {
        self.0.lock().observer = Some(observer);
    }

    /// Report a finished turn of this scheduler (observation only). A published turn has
    /// released its slot, so it carries no cancellation cause.
    pub(super) fn report(
        &self,
        turn: FoldTurnV1,
        result: Result<FoldStatus, &Error>,
        cause: Option<FoldCancelCauseV1>,
        ingests: u32,
    ) {
        let observer = self.0.lock().observer.clone();
        if let Some(mut record) = turn.finish(result, cause)
            && let Some(observer) = observer
        {
            record.ingests = ingests;
            observer.sub_proof(record);
        }
    }

    pub(super) fn start(&self) -> Option<FoldGuard> {
        let mut state = self.0.lock();
        if !state.eligible
            || state.payments != 0
            || state.running.is_some()
            || state.speculating.is_some()
        {
            return None;
        }
        let token = Cancellation::new();
        state.running = Some(token.clone());
        state.cause = None;
        state.ingests = 0;
        // One identity per started attempt; 2^64 attempts never wrap in practice.
        state.attempts = state.attempts.wrapping_add(1);
        Some(FoldGuard {
            scheduler: self.clone(),
            token,
            attempt: state.attempts,
            released: false,
        })
    }

    /// Whether the retention slot holds a value, pending or ready.
    #[cfg(test)]
    pub(super) fn holds_retained_for_test(&self) -> bool {
        self.0.lock().retained.is_some()
    }

    /// Test support for the genuine fold flows: apply `change` in place to a ready retained
    /// value. It runs under the state lock, so it only edits the value: it neither drops nor
    /// replaces it. `false` when the slot holds no ready value or `change` declines it.
    #[cfg(test)]
    pub(crate) fn change_ready_for_test(
        &self,
        change: impl FnOnce(&mut FoldRetentionV1) -> bool,
    ) -> bool {
        match self.0.lock().retained.as_mut() {
            Some(Slot::Ready(value)) => change(value),
            Some(Slot::Pending { .. }) | None => false,
        }
    }
}

/// Holds payment priority after the cancelled sub-proof has released its allocations.
pub struct PaymentGuard(Scheduler);

impl Drop for PaymentGuard {
    fn drop(&mut self) {
        let mut state = self.0.0.lock();
        state.payments -= 1;
        self.0.0.idle.notify_all();
    }
}

/// One speculative proof shared by the call that may use it and the job that makes it.
///
/// The call keeps this value; the job holds a [`SpeculationJob`] and proves only after
/// [`Scheduler::speculate`] admits it. Dropping this value cancels the proof and drops any
/// finished result, so nothing a dropped speculation made is used, signed or kept. It is
/// process-local and move-only: never serialized, persisted or exposed over FFI.
pub struct Speculation<T>(Arc<Shared<T>>);

/// The job side of one [`Speculation`]: it can only run or abandon that one proof.
pub struct SpeculationJob<T>(Arc<Shared<T>>);

impl<T> Clone for SpeculationJob<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T> SpeculationJob<T> {
    /// The proof's cooperative cancellation signal: its call ended it, or close cancelled
    /// the admitted proof.
    pub(super) fn token(&self) -> &Cancellation {
        &self.0.token
    }

    /// Whether its call already ended the speculation or a job was admitted for it.
    pub(super) fn ended(&self) -> bool {
        self.0.token.check().is_err() || !matches!(*self.0.lock(), Speculated::Waiting)
    }
}

struct Shared<T> {
    token: Cancellation,
    state: Mutex<Speculated<T>>,
}

enum Speculated<T> {
    /// Not admitted yet.
    Waiting,
    /// Admitted: preparing or proving.
    Proving,
    /// Finished, for its call.
    Done(T),
    /// Cancelled, failed, abandoned or taken. Final.
    Ended,
}

impl<T> Shared<T> {
    fn lock(&self) -> MutexGuard<'_, Speculated<T>> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // Cancel and end; the caller drops the returned state (a finished value) after the lock.
    fn end(&self) -> Speculated<T> {
        self.token.cancel();
        core::mem::replace(&mut *self.lock(), Speculated::Ended)
    }
}

impl<T> Speculation<T> {
    /// A speculation whose job has not been admitted.
    pub(super) fn new() -> Self {
        Self(Arc::new(Shared {
            token: Cancellation::new(),
            state: Mutex::new(Speculated::Waiting),
        }))
    }

    /// The job side, for the thread that proves.
    pub(super) fn job(&self) -> SpeculationJob<T> {
        SpeculationJob(Arc::clone(&self.0))
    }

    /// End the speculation and return its finished result, if its job published one.
    /// Payment priority joins an admitted job first, so a call holding it never finds the
    /// proof still running; a job not yet admitted then finds its speculation ended.
    pub(super) fn take(self) -> Option<T> {
        match self.0.end() {
            Speculated::Done(value) => Some(value),
            ended => {
                debug_assert!(
                    !matches!(ended, Speculated::Proving),
                    "payment priority joins an admitted speculation before its call takes it"
                );
                None
            }
        }
    }
}

impl<T> Drop for Speculation<T> {
    fn drop(&mut self) {
        drop(self.0.end());
    }
}

/// An admitted speculative proof. It holds the scheduler's speculation slot until dropped:
/// meanwhile no fold sub-proof starts and every payment waits for it.
pub struct SpeculationRun<T> {
    scheduler: Scheduler,
    shared: Arc<Shared<T>>,
}

impl<T> SpeculationRun<T> {
    /// The proof's cooperative cancellation signal: its call ended it, or the owner closes.
    #[must_use]
    pub fn token(&self) -> &Cancellation {
        &self.shared.token
    }

    /// Publish the finished `value` for its call, then release the slot. A speculation its
    /// call already ended drops `value` instead.
    pub fn finish(self, value: T) {
        let rejected = {
            let mut speculated = self.shared.lock();
            if matches!(*speculated, Speculated::Proving) && self.shared.token.check().is_ok() {
                *speculated = Speculated::Done(value);
                None
            } else {
                Some(value)
            }
        };
        // Released after the lock; the slot is released when `self` drops.
        drop(rejected);
    }
}

impl<T> Drop for SpeculationRun<T> {
    fn drop(&mut self) {
        let unfinished = {
            let mut speculated = self.shared.lock();
            matches!(*speculated, Speculated::Proving)
                .then(|| core::mem::replace(&mut *speculated, Speculated::Ended))
        };
        drop(unfinished);
        self.scheduler.0.lock().speculating = None;
        self.scheduler.0.idle.notify_all();
    }
}

impl Scheduler {
    /// Admit `job`'s speculative proof. It waits until no payment holds priority and no other
    /// speculation runs, then cancels and joins a running fold sub-proof and drops the
    /// retained fold state, like payment priority. `None` after close, or once the job's call
    /// has ended its speculation.
    ///
    /// Call it without the wallet owner, and keep the admitted proof off that owner: payments
    /// wait for the proof while possibly holding it.
    #[must_use]
    pub fn speculate<T>(&self, job: &SpeculationJob<T>) -> Option<SpeculationRun<T>> {
        let mut state = self.0.lock();
        loop {
            if state.closed || job.0.token.check().is_err() {
                return None;
            }
            if state.payments == 0 && state.speculating.is_none() {
                break;
            }
            state = self
                .0
                .idle
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        {
            let mut speculated = job.0.lock();
            if !matches!(*speculated, Speculated::Waiting) {
                return None;
            }
            *speculated = Speculated::Proving;
        }
        state.speculating = Some(job.0.token.clone());
        state.cancel(FoldCallClassV1::Payment.cause());
        while state.running.is_some() {
            state = self
                .0
                .idle
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        // The speculative prover never runs beside retained fold memory either.
        let released = state.retained.take();
        drop(state);
        drop(released);
        Some(SpeculationRun {
            scheduler: self.clone(),
            shared: Arc::clone(&job.0),
        })
    }

    /// Whether a payment holds priority now; a speculation it would only wait for is skipped.
    pub(super) fn payment_pending(&self) -> bool {
        self.0.lock().payments != 0
    }

    /// Whether a speculative proof holds the speculation slot.
    #[cfg(test)]
    pub(super) fn speculating_for_test(&self) -> bool {
        self.0.lock().speculating.is_some()
    }
}

pub(super) struct FoldGuard {
    scheduler: Scheduler,
    pub(super) token: Cancellation,
    // The identity of this attempt; it owns at most the one value it parks.
    attempt: u64,
    // The slot was released with this attempt's publication identity.
    released: bool,
}

impl FoldGuard {
    /// Report the finished turn to the observer while this sub-proof still holds the slot,
    /// so a joining payment returns only after its cancellation was reported.
    pub(super) fn report(&self, turn: FoldTurnV1, result: Result<FoldStatus, &Error>) {
        let (cause, ingests) = {
            let state = self.scheduler.0.lock();
            (state.cause, state.ingests)
        };
        self.scheduler.report(turn, result, cause, ingests);
    }

    /// Take the value the previous sub-proof's checkpoint publication promoted for this
    /// attempt. A value still parked by an unsettled publication is evicted instead: this
    /// attempt runs cold and that publication finds its slot gone. Called once, at the locked
    /// prepare; the native owner alone decides whether the value is usable.
    pub(super) fn take_retained(&self) -> Option<FoldRetentionV1> {
        let taken = self.scheduler.0.lock().retained.take();
        match taken {
            Some(Slot::Ready(value)) => Some(value),
            // An evicted pending value is dropped here, after the state lock.
            Some(Slot::Pending { .. }) | None => None,
        }
    }

    /// Release the slot of a sub-proof whose proof finished, before its locked publication.
    /// A payment waiting for the slot proceeds; the publication re-checks the fold fields
    /// under the wallet owner. `retained` is parked under this attempt atomically with the
    /// release, unless a payment holds priority, the scheduler is ineligible or this
    /// sub-proof's signal was cancelled: then it is dropped before the slot is released, so a
    /// joining payment never runs beside it. The proved job keeps only the returned
    /// publication identity, never the value. Returns the ingests the sub-proof overlapped.
    pub(super) fn release(mut self, retained: Option<FoldRetentionV1>) -> (u32, FoldPublicationV1) {
        let mut state = self.scheduler.0.lock();
        let parks = state.eligible && state.payments == 0 && self.token.check().is_ok();
        let displaced = if !parks && retained.is_some() {
            drop(state);
            drop(retained);
            state = self.scheduler.0.lock();
            None
        } else if let Some(value) = retained {
            // The slot is empty here: this attempt took it at its prepare, and no other
            // attempt runs before this release.
            debug_assert!(
                state.retained.is_none(),
                "an attempt parks only into the slot its prepare emptied"
            );
            state.retained.replace(Slot::Pending {
                attempt: self.attempt,
                value,
            })
        } else {
            None
        };
        let ingests = state.ingests;
        state.running = None;
        drop(state);
        // Anything displaced is released after the state lock, like every retained value.
        drop(displaced);
        self.released = true;
        self.scheduler.0.idle.notify_all();
        let publication = FoldPublicationV1 {
            scheduler: self.scheduler.clone(),
            attempt: self.attempt,
            published: false,
        };
        (ingests, publication)
    }

    #[cfg(test)]
    fn cause(&self) -> Option<FoldCancelCauseV1> {
        self.scheduler.0.lock().cause
    }
}

/// The publication identity of a released sub-proof.
///
/// It settles only the value its own attempt parked, and only while that value is still in
/// the slot. A durable checkpoint publication promotes it for the next sub-proof, unless a
/// payment holds priority or the scheduler is ineligible. Every other end drops it: a
/// discarded, failed or refused publication, a completed Ω, or this identity dropped
/// unpublished. A value already evicted, taken or invalidated is never recreated, and a newer
/// attempt's value is never cleared or promoted.
pub(super) struct FoldPublicationV1 {
    scheduler: Scheduler,
    attempt: u64,
    published: bool,
}

impl FoldPublicationV1 {
    /// Settle this sub-proof's parked value with its publication result: only a durable
    /// checkpoint keeps it.
    pub(super) fn settle(mut self, result: Result<FoldStatus, &Error>) {
        self.published = matches!(result, Ok(FoldStatus::Checkpoint { .. }));
    }
}

impl Drop for FoldPublicationV1 {
    fn drop(&mut self) {
        let released = {
            let mut state = self.scheduler.0.lock();
            match state.retained.take() {
                Some(Slot::Pending { attempt, value }) if attempt == self.attempt => {
                    if self.published && state.eligible && state.payments == 0 {
                        state.retained = Some(Slot::Ready(value));
                        None
                    } else {
                        Some(value)
                    }
                }
                // Absent, another attempt's or already promoted: never touched.
                other => {
                    state.retained = other;
                    None
                }
            }
        };
        drop(released);
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Scheduler {
    /// Host test support: hold the background slot exactly like one fold sub-proof of head
    /// `sequence` while `work` runs, then report it like `fold_once` does. Returns `false`
    /// without running `work` when no sub-proof may start.
    ///
    /// # Errors
    /// The error of `work`, including `Cancelled` after an activity, close or priority signal.
    pub fn sub_proof_for_test(
        &self,
        sequence: u128,
        work: impl FnOnce(&Cancellation) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        let Some(guard) = self.start() else {
            return Ok(false);
        };
        let mut turn = FoldTurnV1::start();
        turn.select(sequence, 0);
        super::fold_metrics::enter(super::FoldPhaseV1::Prove);
        let result = work(&guard.token).map(|()| FoldStatus::Checkpoint {
            sequence,
            ordinal: 0,
        });
        guard.report(turn, result.as_ref().copied());
        result.map(|_| true)
    }
}

impl Drop for FoldGuard {
    fn drop(&mut self) {
        if !self.released {
            self.scheduler.0.lock().running = None;
            self.scheduler.0.idle.notify_all();
        }
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;

    #[test]
    fn scheduler_and_prover_share_one_operation_signal() {
        let scheduler = Scheduler::new();
        scheduler.set_activity(true, false);
        let fold = scheduler.start().unwrap();
        let token = fold.token.prover_token().clone();
        let unrelated = Cancellation::new();
        token.check().unwrap();
        scheduler.set_activity(false, false);
        assert_eq!(token.check(), Err(iroha_pasta::Cancelled));
        assert!(matches!(fold.token.check(), Err(Error::Cancelled)));
        unrelated.check().unwrap();
        drop(fold);
        scheduler.set_activity(true, false);
        let retry = scheduler.start().unwrap();
        retry.token.prover_token().check().unwrap();
        assert_eq!(token.check(), Err(iroha_pasta::Cancelled));
    }

    #[test]
    fn the_first_cancelling_signal_is_the_reported_cause_of_one_sub_proof() {
        let scheduler = Scheduler::new();
        scheduler.set_activity(true, false);
        let fold = scheduler.start().unwrap();
        assert_eq!(fold.cause(), None);
        let payer = scheduler.clone();
        let payment =
            std::thread::spawn(move || drop(payer.payment_for(FoldCallClassV1::StatusRead)));
        while fold.token.check().is_ok() {
            std::thread::yield_now();
        }
        // Later signals change neither the cancellation nor its reported cause.
        scheduler.set_activity(false, false);
        scheduler.close();
        assert_eq!(fold.cause(), Some(FoldCancelCauseV1::StatusRead));
        drop(fold);
        payment.join().unwrap();

        scheduler.set_activity(true, false);
        let fold = scheduler.start().unwrap();
        assert_eq!(fold.cause(), None, "each sub-proof starts without a cause");
        scheduler.close();
        assert!(matches!(fold.token.check(), Err(Error::Cancelled)));
        assert_eq!(fold.cause(), Some(FoldCancelCauseV1::Close));
        drop(fold);
        assert!(
            scheduler.start().is_none(),
            "close leaves the scheduler ineligible"
        );
    }

    #[test]
    fn an_ingest_never_cancels_or_joins_and_counts_on_the_running_sub_proof() {
        let scheduler = Scheduler::new();
        scheduler.ingest();
        scheduler.set_activity(true, false);
        let fold = scheduler.start().unwrap();
        // Both return at once on this thread: an ingest never waits for the slot.
        scheduler.ingest();
        scheduler.ingest();
        fold.token.check().unwrap();
        assert_eq!(fold.cause(), None);
        assert_eq!(fold.release(None).0, 2, "an idle ingest is not counted");
        // The released slot admits a payment without a join; the next sub-proof starts at 0.
        drop(scheduler.payment());
        let fold = scheduler.start().unwrap();
        fold.token.check().unwrap();
        assert_eq!(fold.release(None).0, 0);
    }
}

#[cfg(test)]
mod retention_tests;

#[cfg(test)]
mod speculation_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    // Counts its drops, so a test sees exactly when a finished result is released.
    struct Counted(Arc<AtomicUsize>);
    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn wait_until(condition: impl Fn() -> bool) {
        for _ in 0..2_000 {
            if condition() {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("condition not reached");
    }

    #[test]
    fn a_payment_joins_an_admitted_speculation_without_cancelling_it() {
        let scheduler = Scheduler::new();
        let speculation = Speculation::<u32>::new();
        let run = scheduler.speculate(&speculation.job()).unwrap();
        assert!(scheduler.speculating_for_test());
        let payer = scheduler.clone();
        let paid = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&paid);
        let payment = std::thread::spawn(move || {
            let guard = payer.payment();
            observed.store(1, Ordering::SeqCst);
            guard
        });
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            paid.load(Ordering::SeqCst),
            0,
            "the payment waits for the proof"
        );
        run.token().check().unwrap();
        run.finish(7);
        let guard = payment.join().unwrap();
        assert!(!scheduler.speculating_for_test());
        assert_eq!(
            speculation.take(),
            Some(7),
            "the confirmed payment finds the proof"
        );
        drop(guard);
    }

    #[test]
    fn close_cancels_an_admitted_speculation_and_admits_no_later_one() {
        let scheduler = Scheduler::new();
        let speculation = Speculation::<u32>::new();
        let run = scheduler.speculate(&speculation.job()).unwrap();
        scheduler.close();
        assert!(matches!(run.token().check(), Err(Error::Cancelled)));
        let closer = scheduler.clone();
        let join = std::thread::spawn(move || drop(closer.payment()));
        // A cancelled job publishes nothing; releasing its slot lets close join it.
        run.finish(7);
        join.join().unwrap();
        assert_eq!(speculation.take(), None);
        let later = Speculation::<u32>::new();
        assert!(scheduler.speculate(&later.job()).is_none());
    }

    #[test]
    fn a_speculation_cancels_and_joins_a_fold_and_blocks_new_folds() {
        let scheduler = Scheduler::new();
        scheduler.set_activity(true, false);
        let fold = scheduler.start().unwrap();
        let speculation = Speculation::<u32>::new();
        let job = speculation.job();
        let admitting = scheduler.clone();
        let admitted = std::thread::spawn(move || admitting.speculate(&job));
        wait_until(|| fold.token.check().is_err());
        assert_eq!(fold.cause(), Some(FoldCancelCauseV1::Payment));
        drop(fold);
        let run = admitted.join().unwrap().unwrap();
        assert!(scheduler.speculating_for_test());
        assert!(
            scheduler.start().is_none(),
            "no fold beside the speculative prover"
        );
        drop(speculation);
        assert!(matches!(run.token().check(), Err(Error::Cancelled)));
        drop(run);
        assert!(!scheduler.speculating_for_test());
        assert!(scheduler.start().is_some());
    }

    #[test]
    fn a_dropped_speculation_cancels_its_proof_and_releases_any_result() {
        let scheduler = Scheduler::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let speculation = Speculation::<Counted>::new();
        let run = scheduler.speculate(&speculation.job()).unwrap();
        drop(speculation);
        assert!(matches!(run.token().check(), Err(Error::Cancelled)));
        run.finish(Counted(Arc::clone(&drops)));
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "a declined proof is dropped"
        );
        assert!(!scheduler.speculating_for_test());

        let speculation = Speculation::<Counted>::new();
        let run = scheduler.speculate(&speculation.job()).unwrap();
        run.finish(Counted(Arc::clone(&drops)));
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "a finished proof waits for its call"
        );
        drop(speculation);
        assert_eq!(drops.load(Ordering::SeqCst), 2, "and is dropped with it");
    }

    #[test]
    fn admission_waits_for_payments_and_ends_for_a_taken_speculation() {
        let scheduler = Scheduler::new();
        let payment = scheduler.payment();
        assert!(
            scheduler.payment_pending(),
            "a locked prepare skips its speculation"
        );
        let speculation = Speculation::<u32>::new();
        let job = speculation.job();
        let admitting = scheduler.clone();
        let admitted = std::thread::spawn(move || admitting.speculate(&job).is_some());
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !scheduler.speculating_for_test(),
            "no admission beside a payment"
        );
        // The payment's call ends the speculation it found unadmitted, then proves itself.
        assert_eq!(speculation.take(), None);
        drop(payment);
        assert!(!admitted.join().unwrap());
        assert!(!scheduler.speculating_for_test());
        assert!(!scheduler.payment_pending());
    }

    #[test]
    fn one_speculation_runs_at_a_time() {
        let scheduler = Scheduler::new();
        let first = Speculation::<u32>::new();
        let second = Speculation::<u32>::new();
        let run = scheduler.speculate(&first.job()).unwrap();
        let job = second.job();
        let admitting = scheduler.clone();
        let next = std::thread::spawn(move || {
            let run = admitting.speculate(&job).unwrap();
            run.finish(2);
        });
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            second.0.lock().is_waiting(),
            "the second waits for the first"
        );
        run.finish(1);
        next.join().unwrap();
        assert!(
            scheduler.speculate(&first.job()).is_none(),
            "one admission per job"
        );
        assert_eq!(first.take(), Some(1));
        assert_eq!(second.take(), Some(2));
    }

    impl<T> Speculated<T> {
        fn is_waiting(&self) -> bool {
            matches!(self, Self::Waiting)
        }
    }
}
