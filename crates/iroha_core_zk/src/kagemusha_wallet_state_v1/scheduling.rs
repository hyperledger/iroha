//! Cooperative fold cancellation, exclusive payment priority and non-preempting ingests.
//!
//! A fold sub-proof holds the background slot from its locked prepare through its proof,
//! which runs without the wallet owner. It releases the slot before taking the owner again to
//! publish, so a payment that holds the owner and joins the slot never waits on that owner.

use std::sync::{Arc, Condvar, Mutex, MutexGuard};

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

    /// Update app/device activity. Leaving both states cancels an existing sub-proof.
    pub fn set_activity(&self, foreground: bool, charging: bool) {
        let mut state = self.0.lock();
        state.eligible = foreground || charging;
        if !state.eligible {
            state.cancel(FoldCancelCauseV1::Activity);
        }
    }

    /// The owner is closing: leave both states like [`Self::set_activity`], reporting a
    /// cancelled sub-proof as closed.
    pub fn close(&self) {
        let mut state = self.0.lock();
        state.eligible = false;
        state.cancel(FoldCancelCauseV1::Close);
    }

    /// Signal payment priority and join the current sub-proof before returning.
    #[must_use]
    pub fn payment(&self) -> PaymentGuard {
        self.payment_for(FoldCallClassV1::Payment)
    }

    /// [`Self::payment`] for a host call of `class`. The class only labels a cancelled
    /// sub-proof in fold telemetry; priority, cancellation and the join are identical.
    #[must_use]
    pub fn payment_for(&self, class: FoldCallClassV1) -> PaymentGuard {
        let mut state = self.0.lock();
        state.payments += 1;
        state.cancel(class.cause());
        while state.running.is_some() {
            state = self
                .0
                .idle
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        PaymentGuard(self.clone())
    }

    /// A host call that neither proves, signs, commits an Advance nor deletes custody. It never
    /// cancels or joins: a running sub-proof keeps proving outside the wallet owner and
    /// publishes only if its fold fields are still unchanged. Fold telemetry counts the call on
    /// that sub-proof (observation only).
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
        if !state.eligible || state.payments != 0 || state.running.is_some() {
            return None;
        }
        let token = Cancellation::new();
        state.running = Some(token.clone());
        state.cause = None;
        state.ingests = 0;
        Some(FoldGuard {
            scheduler: self.clone(),
            token,
        })
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

pub(super) struct FoldGuard {
    scheduler: Scheduler,
    pub(super) token: Cancellation,
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

    /// Release the slot of a sub-proof whose proof finished, before its locked publication.
    /// A payment waiting for the slot proceeds; the publication re-checks the fold fields
    /// under the wallet owner. Returns the ingests the sub-proof overlapped.
    pub(super) fn release(self) -> u32 {
        let ingests = self.scheduler.0.lock().ingests;
        drop(self);
        ingests
    }

    #[cfg(test)]
    fn cause(&self) -> Option<FoldCancelCauseV1> {
        self.scheduler.0.lock().cause
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
        self.scheduler.0.lock().running = None;
        self.scheduler.0.idle.notify_all();
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
        assert_eq!(fold.release(), 2, "an idle ingest is not counted");
        // The released slot admits a payment without a join; the next sub-proof starts at 0.
        drop(scheduler.payment());
        let fold = scheduler.start().unwrap();
        fold.token.check().unwrap();
        assert_eq!(fold.release(), 0);
    }
}
