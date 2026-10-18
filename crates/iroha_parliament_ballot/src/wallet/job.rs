//! Finish-and-discard preparation jobs (`specs/parliament_ballot_prover_lifecycle.md`).
//!
//! A job owns its inputs (a copy of the credential in its own erasing owner, the context and
//! the acknowledgement) and runs one preparation on its own thread. Cancellation and
//! publication share one synchronized decision:
//!
//! - [`WalletCancelHandleV1::cancel`] irrevocably suppresses publication if the job has not
//!   published yet, and asks the stamp search and the proving loop to stop cooperatively. It
//!   does not interrupt a proving invocation, release memory or acknowledge cleanup.
//! - [`WalletJobV1::wait`] joins the computation and acknowledges that its inputs were
//!   dropped, without publishing; [`WalletJobV1::finish`] joins and then decides: a
//!   cancelled job discards its result, an uncancelled one publishes it. Dropping an
//!   unfinished job requests cancellation and joins its thread.
//!
//! Results are public data (a registration or an envelope); a discarded result is dropped
//! unpublished. Secrets (the job's credential copy and every tape) are erased by their own
//! owners whether the job publishes or not. No guarantee follows for process abort.

use std::{
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
};

use iroha_data_model::{
    account::AccountId,
    governance::{anonymous_ballot::CredentialRegistrationV1, types::AssignmentId},
};

use super::{
    WalletErrorV1,
    credential::CredentialHandleV1,
    disclosure::BallotDisclosureAcknowledgementV1,
    prepare::{
        BallotPreparationOptionsV1, BallotSubmissionV1, prepare_ballot_with,
        prepare_registration_with, registration_prover, vote_prover,
    },
};
use crate::{
    context::ScopedBallotContextV1,
    entropy::{EntropySource, OsEntropy},
};

/// Stack of a preparation thread.
const JOB_STACK_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gate {
    Open,
    Cancelled,
    Closed,
}

#[derive(Debug)]
struct JobControl {
    gate: Mutex<Gate>,
    stop: AtomicBool,
}

impl JobControl {
    fn gate(&self) -> std::sync::MutexGuard<'_, Gate> {
        self.gate.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The answer to a cancellation request. Only finishing or dropping the job acknowledges
/// that the computation ended and its inputs were dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CancellationV1 {
    /// This request suppressed any future publication.
    Accepted,
    /// An earlier request already suppressed publication.
    AlreadyRequested,
    /// The job already published its result.
    TooLate,
}

/// A cloneable handle that requests a job's cancellation from any thread. It holds no input
/// or result.
#[derive(Debug, Clone)]
pub struct WalletCancelHandleV1 {
    control: Arc<JobControl>,
}

impl WalletCancelHandleV1 {
    /// Request cancellation: suppress publication unless it already happened, and ask the
    /// computation to stop where it can.
    pub fn cancel(&self) -> CancellationV1 {
        let mut gate = self.control.gate();
        match *gate {
            Gate::Open => {
                *gate = Gate::Cancelled;
                self.control.stop.store(true, Ordering::Relaxed);
                CancellationV1::Accepted
            }
            Gate::Cancelled => CancellationV1::AlreadyRequested,
            Gate::Closed => CancellationV1::TooLate,
        }
    }
}

/// How a job's computation ended, with no result bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobStatusV1 {
    /// The computation produced a result.
    Completed,
    /// The computation failed (a cancellation the computation observed is
    /// [`WalletErrorV1::Cancelled`]).
    Failed(WalletErrorV1),
    /// The thread did not return normally; no cleanup claim is made.
    WorkerPanicked,
}

/// What finishing a job releases.
#[derive(Debug)]
pub enum JobOutcomeV1<T> {
    /// The uncancelled result.
    Published(T),
    /// Cancellation won; whatever was computed was dropped unpublished.
    Discarded(JobStatusV1),
    /// The uncancelled computation failed.
    Failed(WalletErrorV1),
    /// The thread did not return normally.
    WorkerPanicked,
}

type Completion<T> = Result<Result<T, WalletErrorV1>, ()>;

/// One preparation running on its own thread. Not cloneable; dropping it requests
/// cancellation and joins the thread.
#[derive(Debug)]
pub struct WalletJobV1<T: Send + 'static> {
    control: Arc<JobControl>,
    worker: Option<JoinHandle<Result<T, WalletErrorV1>>>,
    completion: Option<Completion<T>>,
}

impl<T: Send + 'static> WalletJobV1<T> {
    /// Run `work` on a new thread; it receives the job's stop flag.
    fn spawn(
        name: &str,
        work: impl FnOnce(&AtomicBool) -> Result<T, WalletErrorV1> + Send + 'static,
    ) -> Result<Self, WalletErrorV1> {
        let control = Arc::new(JobControl {
            gate: Mutex::new(Gate::Open),
            stop: AtomicBool::new(false),
        });
        let worker_control = Arc::clone(&control);
        let worker = thread::Builder::new()
            .name(name.to_owned())
            .stack_size(JOB_STACK_BYTES)
            .spawn(move || work(&worker_control.stop))
            .map_err(|_| WalletErrorV1::Worker)?;
        Ok(Self {
            control,
            worker: Some(worker),
            completion: None,
        })
    }

    /// A handle that can request cancellation from another thread.
    pub fn cancellation(&self) -> WalletCancelHandleV1 {
        WalletCancelHandleV1 {
            control: Arc::clone(&self.control),
        }
    }

    /// Join the computation and acknowledge that its inputs were dropped, without
    /// publishing. Repeated calls return the same status; cancellation stays possible until
    /// [`Self::finish`].
    pub fn wait(&mut self) -> JobStatusV1 {
        if let Some(worker) = self.worker.take() {
            self.completion = Some(worker.join().map_err(|_| ()));
        }
        match &self.completion {
            Some(Ok(Ok(_))) => JobStatusV1::Completed,
            Some(Ok(Err(error))) => JobStatusV1::Failed(error.clone()),
            Some(Err(())) | None => JobStatusV1::WorkerPanicked,
        }
    }

    /// Join, then decide atomically whether the result may be published: a cancellation
    /// accepted before this decision always discards it.
    pub fn finish(mut self) -> JobOutcomeV1<T> {
        let status = self.wait();
        let cancelled = {
            let mut gate = self.control.gate();
            let cancelled = *gate == Gate::Cancelled;
            *gate = Gate::Closed;
            cancelled
        };
        let completion = self.completion.take();
        if cancelled {
            drop(completion);
            return JobOutcomeV1::Discarded(status);
        }
        match completion {
            Some(Ok(Ok(result))) => JobOutcomeV1::Published(result),
            Some(Ok(Err(error))) => JobOutcomeV1::Failed(error),
            Some(Err(())) | None => JobOutcomeV1::WorkerPanicked,
        }
    }
}

impl<T: Send + 'static> Drop for WalletJobV1<T> {
    fn drop(&mut self) {
        if self.worker.is_some() || self.completion.is_some() {
            self.cancellation().cancel();
            self.wait();
            self.completion.take();
            *self.control.gate() = Gate::Closed;
        }
    }
}

/// Start preparing `handle`'s locked ballot in `context`'s scope on its own thread (see
/// [`super::prepare_ballot_v1`]), with fresh tapes and a stamp start nonce from the
/// operating system.
///
/// # Errors
/// [`WalletErrorV1::Worker`] if the thread cannot be started; every preparation error is
/// reported by the job.
pub fn spawn_ballot_preparation_v1(
    handle: &CredentialHandleV1,
    context: Arc<ScopedBallotContextV1>,
    acknowledgement: &BallotDisclosureAcknowledgementV1,
    options: BallotPreparationOptionsV1,
) -> Result<WalletJobV1<BallotSubmissionV1>, WalletErrorV1> {
    spawn_ballot_preparation_with(handle, context, acknowledgement, options, OsEntropy)
}

/// [`spawn_ballot_preparation_v1`] with injected entropy.
pub fn spawn_ballot_preparation_with<E: EntropySource + Send + 'static>(
    handle: &CredentialHandleV1,
    context: Arc<ScopedBallotContextV1>,
    acknowledgement: &BallotDisclosureAcknowledgementV1,
    options: BallotPreparationOptionsV1,
    mut entropy: E,
) -> Result<WalletJobV1<BallotSubmissionV1>, WalletErrorV1> {
    let owned = handle.duplicate();
    let acknowledgement = *acknowledgement;
    WalletJobV1::spawn("parliament-ballot", move |stop| {
        let result = prepare_ballot_with(
            &owned,
            &context,
            &acknowledgement,
            options,
            stop,
            &mut entropy,
            vote_prover,
        );
        // The job's secret copy is erased before the result can be observed.
        drop(owned);
        result
    })
}

/// Start preparing the registration of `handle`'s credential for `assignment_id` on its own
/// thread (see [`super::prepare_registration_v1`]).
///
/// # Errors
/// [`WalletErrorV1::Worker`] if the thread cannot be started.
pub fn spawn_registration_v1(
    handle: &CredentialHandleV1,
    authority: AccountId,
    assignment_id: AssignmentId,
) -> Result<WalletJobV1<CredentialRegistrationV1>, WalletErrorV1> {
    let owned = handle.duplicate();
    WalletJobV1::spawn("parliament-registration", move |stop| {
        let result = prepare_registration_with(
            &owned,
            &authority,
            &assignment_id,
            stop,
            &mut OsEntropy,
            registration_prover,
        );
        drop(owned);
        result
    })
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use iroha_data_model::governance::anonymous_ballot::BallotChoiceV1;

    use super::*;
    use crate::{
        entropy::ScriptedEntropy,
        registration::verify_registration_v1,
        test_support::{
            AYE_0, FIXTURE_BALLOTS, account, body_context, fixture_bytes, scoped_context,
            secret_bytes, tape,
        },
        wallet::{BallotDisclosureV1, DisclosureStatementV1},
    };

    /// A job that reaches a milestone, then waits for permission to return `value`.
    fn gated_job(value: u32) -> (WalletJobV1<u32>, mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (reached, milestone) = mpsc::channel();
        let (release, permitted) = mpsc::channel::<()>();
        let job = WalletJobV1::spawn("test-job", move |_stop| {
            reached.send(()).expect("milestone");
            permitted.recv().expect("permission");
            Ok(value)
        })
        .expect("job");
        (job, milestone, release)
    }

    #[test]
    fn an_uncancelled_job_publishes_and_a_late_cancellation_is_too_late() {
        let (job, milestone, release) = gated_job(7);
        let control = job.cancellation();
        milestone.recv().expect("milestone");
        release.send(()).expect("release");
        assert!(matches!(job.finish(), JobOutcomeV1::Published(7)));
        assert_eq!(control.cancel(), CancellationV1::TooLate);
    }

    #[test]
    fn cancellation_during_the_computation_discards_its_result() {
        let (mut job, milestone, release) = gated_job(9);
        let control = job.cancellation();
        // Cancel while the computation is inside its work, then let it complete normally.
        milestone.recv().expect("milestone");
        assert_eq!(control.cancel(), CancellationV1::Accepted);
        assert_eq!(control.cancel(), CancellationV1::AlreadyRequested);
        release.send(()).expect("release");
        assert_eq!(job.wait(), JobStatusV1::Completed);
        assert_eq!(job.wait(), JobStatusV1::Completed);
        assert!(matches!(
            job.finish(),
            JobOutcomeV1::Discarded(JobStatusV1::Completed)
        ));
        assert_eq!(control.cancel(), CancellationV1::TooLate);
    }

    #[test]
    fn cancellation_after_completion_but_before_finish_still_discards() {
        let (mut job, milestone, release) = gated_job(3);
        milestone.recv().expect("milestone");
        release.send(()).expect("release");
        assert_eq!(job.wait(), JobStatusV1::Completed);
        assert_eq!(job.cancellation().cancel(), CancellationV1::Accepted);
        assert!(matches!(job.finish(), JobOutcomeV1::Discarded(_)));
    }

    #[test]
    fn failures_and_panics_are_reported_and_dropping_joins() {
        let failing =
            WalletJobV1::<u32>::spawn("test-job", |_| Err(WalletErrorV1::Cancelled)).expect("job");
        assert!(matches!(
            failing.finish(),
            JobOutcomeV1::Failed(WalletErrorV1::Cancelled)
        ));
        let panicking =
            WalletJobV1::<u32>::spawn("test-job", |_| panic!("worker failure")).expect("job");
        assert!(matches!(panicking.finish(), JobOutcomeV1::WorkerPanicked));
        // The stop flag reaches the computation; dropping the job cancels and joins it.
        let (stopped, observed) = mpsc::channel();
        let job = WalletJobV1::<u32>::spawn("test-job", move |stop| {
            while !stop.load(Ordering::Relaxed) {
                thread::yield_now();
            }
            stopped.send(()).expect("observed");
            Err(WalletErrorV1::Cancelled)
        })
        .expect("job");
        drop(job);
        observed
            .recv()
            .expect("the worker saw the stop flag before the drop returned");
    }

    #[test]
    fn a_ballot_preparation_job_publishes_the_prepared_envelope() {
        let context = scoped_context();
        let acknowledgement = BallotDisclosureV1::for_context_v1(&context)
            .acknowledge(&DisclosureStatementV1::ALL)
            .expect("acknowledged");
        let mut handle =
            CredentialHandleV1::import_v1(body_context(), &secret_bytes(0), None).expect("handle");
        let intent = handle
            .lock_choice_v1(&context, BallotChoiceV1::Aye, &acknowledgement)
            .expect("locked");
        handle
            .confirm_choice_persisted_v1(&intent.to_record_bytes().expect("record"))
            .expect("confirmed");
        let ballot = FIXTURE_BALLOTS[AYE_0];
        let entropy = ScriptedEntropy::new([
            Some(tape(ballot.tape).to_vec()),
            Some(ballot.nonce.to_vec()),
        ]);
        let job = spawn_ballot_preparation_with(
            &handle,
            Arc::clone(&context),
            &acknowledgement,
            BallotPreparationOptionsV1 {
                stamp_threads: std::num::NonZeroUsize::MIN,
            },
            entropy,
        )
        .expect("job");
        let JobOutcomeV1::Published(submission) = job.finish() else {
            panic!("published");
        };
        assert_eq!(submission.as_bytes(), &fixture_bytes(AYE_0)[..]);
        // A job of an unlocked credential reports the refusal.
        let unlocked =
            CredentialHandleV1::import_v1(body_context(), &secret_bytes(1), None).expect("handle");
        let refused = spawn_ballot_preparation_v1(
            &unlocked,
            context,
            &acknowledgement,
            BallotPreparationOptionsV1::default(),
        )
        .expect("job");
        assert!(matches!(
            refused.finish(),
            JobOutcomeV1::Failed(WalletErrorV1::ChoiceNotLocked)
        ));
    }

    #[test]
    fn a_registration_job_can_be_cancelled_before_it_proves() {
        let handle = CredentialHandleV1::generate_v1(body_context()).expect("credential");
        let job =
            spawn_registration_v1(&handle, account(), AssignmentId::new([0x51; 32])).expect("job");
        let control = job.cancellation();
        let first = control.cancel();
        let outcome = job.finish();
        match (first, outcome) {
            // Whatever the worker had reached, an accepted cancellation discards.
            (CancellationV1::Accepted, JobOutcomeV1::Discarded(_)) => {}
            other => panic!("unexpected {other:?}"),
        }
        // Uncancelled, the job publishes a registration that verifies.
        let job =
            spawn_registration_v1(&handle, account(), AssignmentId::new([0x52; 32])).expect("job");
        let JobOutcomeV1::Published(registration) = job.finish() else {
            panic!("published");
        };
        assert_eq!(
            verify_registration_v1(
                &body_context(),
                &account(),
                &AssignmentId::new([0x52; 32]),
                &registration
            ),
            Ok(())
        );
    }
}
