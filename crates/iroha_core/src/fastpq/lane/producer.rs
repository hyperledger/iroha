//! One retained autonomous source at a time inside the existing FASTPQ worker.
//!
//! The authenticated prefix is rebuilt from pinned signed genesis after restart.
//! Disk artifacts are advertisements and never advance a statement without fresh verification.
//! A local attempt budget is not a customer payment deadline or evidence of settlement.

use super::*;
use crate::{
    query::native_context_archive::{
        NativeContextArchiveError,
        fastpq_source::{NativeFastpqSourceRead, SourceReadError, SourceReadLimits},
    },
    state::{State, StateReadOnly, StateViewError},
    sumeragi::finality::{NativeFinalityCursorErrorV1, NativeFinalityCursorV1, ProofError},
};
use iroha_allocation::{AllocationRefusal, ChargedBuffer, ChargedBufferError};
use iroha_config::parameters::actual::FastpqProducer;
use std::{io::ErrorKind, num::NonZeroU64};

/// Original causal operation failure; no diagnostic text is used for retry policy.
#[derive(Debug, thiserror::Error)]
pub(super) enum ProducerError {
    #[error("FASTPQ producer attempt deadline expired")]
    Deadline,
    #[error(transparent)]
    View(#[from] StateViewError),
    #[error(transparent)]
    Finality(#[from] NativeFinalityCursorErrorV1),
    #[error(transparent)]
    Source(#[from] SourceReadError),
    #[error(transparent)]
    Durable(#[from] durable::DurableError),
    #[error(transparent)]
    Work(#[from] FastpqWorkRefusal),
    #[error(transparent)]
    Replay(#[from] crate::sumeragi::node::IsolatedReplayError),
    #[error("FASTPQ producer original source: {0}")]
    Identity(&'static str),
}
impl ProducerError {
    fn retryable(&self) -> bool {
        match self {
            Self::Deadline | Self::View(StateViewError::Busy(_)) => true,
            Self::Finality(NativeFinalityCursorErrorV1::Deadline) => true,
            Self::Finality(NativeFinalityCursorErrorV1::Proof(ProofError::Deferred(error))) => {
                deferred_retryable(error)
            }
            Self::Source(error) => source_retryable(error),
            Self::Replay(error) => replay_retryable(error),
            Self::Durable(durable::DurableError::Storage(error)) => storage_retryable(error),
            Self::Durable(durable::DurableError::Verification(error)) => {
                verification_retryable(error)
            }
            Self::Durable(durable::DurableError::Source(error)) => work_source_retryable(error),
            Self::Work(FastpqWorkRefusal::Source(error)) => work_source_retryable(error),
            Self::Work(FastpqWorkRefusal::Prove(ProvingError::Busy)) => true,
            Self::Work(FastpqWorkRefusal::Prove(ProvingError::Verify(error))) => {
                verification_retryable(error)
            }
            Self::Work(FastpqWorkRefusal::Prove(ProvingError::Prove(error))) => {
                backend_retryable(error)
            }
            _ => false,
        }
    }
}
// Classify the original owner before its lossy VM-facing category. This is a
// worker scheduling decision, never a proof verdict or a ledger rejection.
fn deferred_retryable(error: &crate::execution_attempt::ExecutionDeferred) -> bool {
    if let Some(original) = error.allocation_refusal() {
        return allocation_retryable(original);
    }
    if error.allocator_refusal().is_some() || error.decode_refusal().is_some() {
        return true;
    }
    // No verification/history/invariant category is sufficient evidence of a
    // retryable read. The cursor explicitly owns this physical allocator case.
    matches!(
        error.reason(),
        ivm::error::ExecutionDeferral::AllocationUnavailable
    )
}
fn allocation_retryable(error: &AllocationRefusal) -> bool {
    matches!(error, AllocationRefusal::Capacity { .. })
}
fn buffer_retryable(error: &ChargedBufferError) -> bool {
    match error {
        ChargedBufferError::Admission(error) => allocation_retryable(error),
        ChargedBufferError::Allocator { .. } => true,
    }
}
fn storage_retryable(error: &crate::kura::Error) -> bool {
    matches!(error, crate::kura::Error::FastpqArtifactQuota { .. })
        || matches!(error, crate::kura::Error::IO(error, _) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted | ErrorKind::NotFound))
}
fn backend_retryable(error: &fastpq_prover::Error) -> bool {
    match error {
        fastpq_prover::Error::ProducerBusy
        | fastpq_prover::Error::LocalAllocationUnavailable { .. } => true,
        fastpq_prover::Error::AllocationAdmission(error) => allocation_retryable(error),
        fastpq_prover::Error::AllocationBacking(
            iroha_allocation::PrepaidBufferError::Allocation(error),
        ) => buffer_retryable(error),
        _ => false,
    }
}
fn verification_retryable(error: &offline_compact::VerificationError) -> bool {
    match error {
        offline_compact::VerificationError::Verify(error) => backend_retryable(error),
        _ => false,
    }
}
fn work_source_retryable(error: &source::SourceWorkError) -> bool {
    match error {
        source::SourceWorkError::Allocation(error) => allocation_retryable(error),
        source::SourceWorkError::Preparation(error) => backend_retryable(error),
        _ => false,
    }
}
fn source_retryable(error: &SourceReadError) -> bool {
    match error {
        SourceReadError::Allocation(error) => allocation_retryable(error),
        SourceReadError::Writes(
            crate::query::native_receipts::ordinary_writes::WriteDecodeError::Admission(error),
        ) => allocation_retryable(error),
        SourceReadError::Writes(
            crate::query::native_receipts::ordinary_writes::WriteDecodeError::Materialization(
                iroha_allocation::PrepaidBufferError::Allocation(error),
            ),
        ) => buffer_retryable(error),
        SourceReadError::Lane(error)
        | SourceReadError::Archive(NativeContextArchiveError::Proof(error)) => {
            error.is_local_refusal()
        }
        SourceReadError::Workspace(norito::core::PreparedDecodeScopeError::Allocation(
            iroha_allocation::PrepaidSharedError::Allocator { .. },
        )) => true,
        SourceReadError::Buffer(error)
        | SourceReadError::Effects(
            iroha_data_model::fastpq::FastpqEffectsDecodeError::Allocation(error),
        )
        | SourceReadError::Archive(NativeContextArchiveError::Allocation(error)) => {
            buffer_retryable(error)
        }
        SourceReadError::Decode(error) => error.local_refusal().is_some(),
        SourceReadError::Archive(NativeContextArchiveError::Io(error)) => matches!(
            error.kind(),
            ErrorKind::NotFound | ErrorKind::Interrupted | ErrorKind::WouldBlock
        ),
        SourceReadError::Archive(NativeContextArchiveError::Storage(error)) => {
            storage_retryable(error)
        }
        _ => false,
    }
}

fn archive_replay_retryable(error: &NativeContextArchiveError) -> bool {
    match error {
        NativeContextArchiveError::Storage(original) => storage_retryable(original),
        NativeContextArchiveError::Allocation(original) => buffer_retryable(original),
        NativeContextArchiveError::CaptureAdmission(original) => allocation_retryable(original),
        NativeContextArchiveError::Proof(original) => original.is_local_refusal(),
        NativeContextArchiveError::Io(original) => matches!(
            original.kind(),
            ErrorKind::Interrupted | ErrorKind::WouldBlock
        ),
        _ => false,
    }
}
fn world_storage_retryable(error: &mv::storage::AdmittedStorageError) -> bool {
    error.release_wait().is_some()
        || matches!(error, mv::storage::AdmittedStorageError::Allocator { .. })
}
fn storage_admission_retryable(error: &crate::state::StateStorageAdmissionError) -> bool {
    match error {
        crate::state::StateStorageAdmissionError::World(original) => {
            world_storage_retryable(original)
        }
        _ => error.release_wait().is_some(),
    }
}
fn membership_retryable(error: &crate::state::MembershipAdmissionError) -> bool {
    error.release_wait().is_some()
        || matches!(
            error,
            crate::state::MembershipAdmissionError::Allocator { .. }
        )
}
fn validation_replay_retryable(error: &crate::block::BlockValidationError) -> bool {
    use crate::block::BlockValidationError as Error;
    match error {
        Error::ExecutionDeferred(original) => deferred_retryable(original),
        Error::StateStorageAdmission(original) => storage_admission_retryable(original),
        Error::MembershipAdmission(original) => membership_retryable(original),
        Error::BlockHashAdmission(original) => original.release_wait().is_some(),
        Error::StateView(StateViewError::Busy(_)) => true,
        Error::LaneStorage(original) => matches!(
            original.kind(),
            ErrorKind::Interrupted | ErrorKind::WouldBlock
        ),
        _ => false,
    }
}
fn state_publication_retryable(
    error: &crate::state::storage_transactions::TransactionsBlockError,
) -> bool {
    use crate::state::storage_transactions::TransactionsBlockError as Error;
    match error {
        Error::LocalStateStorage(original) => storage_admission_retryable(original),
        Error::MembershipAdmission(original) => membership_retryable(original),
        Error::BlockHashesBusy(_) | Error::PublicationBusy(_) => true,
        Error::ExecutionDeferred(original) => deferred_retryable(original),
        Error::CaptureDeferred(original) => {
            if let Some(admission) = original.allocation_refusal() {
                return allocation_retryable(admission);
            }
            original.buffer_refusal().is_some_and(buffer_retryable)
                || matches!(
                    original.shared_refusal(),
                    Some(iroha_allocation::PrepaidSharedError::Allocator { .. })
                )
                || original.codec_allocation_bytes().is_some()
        }
        _ => false,
    }
}
fn startup_replay_retryable(error: &crate::sumeragi::startup::StartupError) -> bool {
    use crate::sumeragi::{commitment::ResultPreimageError, startup::StartupError as Error};
    use iroha_data_model::block::CertificateAdmissionError;
    match error {
        Error::Deferred(original)
        | Error::LaneStep(crate::sumeragi::lanes::step::LaneStepError::Deferred(original)) => {
            deferred_retryable(original)
        }
        Error::InvalidGenesis(original) => validation_replay_retryable(original),
        Error::LaneProof(original) => original.is_local_refusal(),
        Error::ResultPreimage(ResultPreimageError::Allocation(original))
        | Error::CertificateBuffer(original)
        | Error::Certificate(CertificateAdmissionError::Buffer(original)) => {
            buffer_retryable(original)
        }
        Error::Certificate(CertificateAdmissionError::ControlAdmission(original)) => {
            allocation_retryable(original)
        }
        Error::Certificate(CertificateAdmissionError::ControlAllocation(
            iroha_allocation::PrepaidSharedError::Allocator { .. },
        )) => true,
        Error::Storage(original) => {
            matches!(original, crate::kura::Error::IO(io, _) if matches!(io.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock))
        }
        Error::StateApplication(original) => state_replay_retryable(original),
        Error::StatePublication(original) => state_publication_retryable(&original.0),
        Error::IsolatedSourceTransport(original) => archive_replay_retryable(original),
        _ => false,
    }
}
fn state_replay_retryable(error: &crate::state::MergeLedgerCommitError) -> bool {
    use crate::state::MergeLedgerCommitError as Error;
    match error {
        Error::StateView(StateViewError::Busy(_)) => true,
        Error::ExecutionDeferred(original) => deferred_retryable(original),
        Error::NativeResourceAdmission(original) => allocation_retryable(original),
        Error::StateStorageAdmission(original) => storage_admission_retryable(original),
        Error::MembershipAdmission(original) => membership_retryable(original),
        Error::BlockHashAdmission(original) => original.release_wait().is_some(),
        Error::Persistence(original) => storage_retryable(original),
        _ => false,
    }
}
fn replay_retryable(error: &crate::sumeragi::node::IsolatedReplayError) -> bool {
    use crate::{
        execution_attempt::ExecutionAttemptError as Attempt,
        sumeragi::{
            driver::traits::{PublicationDeferral, PublicationError},
            node::IsolatedReplayError as Error,
        },
    };
    match error {
        Error::Deadline | Error::View(StateViewError::Busy(_)) => true,
        Error::Read(Attempt::Deferred(original))
        | Error::KuraRead(Attempt::Deferred(original))
        | Error::Startup(crate::sumeragi::node::NodeError::Deferred(original))
        | Error::World(crate::state::WorldConstructionError::Initialization(Attempt::Deferred(
            original,
        )))
        | Error::Sns(crate::sns::SnsError::Deferred(original)) => deferred_retryable(original),
        Error::World(crate::state::WorldConstructionError::Storage(original)) => {
            world_storage_retryable(original)
        }
        Error::State(crate::state::IsolatedReplayStateError::State(original)) => {
            state_replay_retryable(original)
        }
        Error::Read(Attempt::Rejected(original)) => matches!(
            original.kind(),
            ErrorKind::Interrupted | ErrorKind::WouldBlock
        ),
        Error::Kura(original) | Error::KuraRead(Attempt::Rejected(original)) => {
            storage_retryable(original)
        }
        Error::Startup(crate::sumeragi::node::NodeError::Startup(original)) => {
            startup_replay_retryable(original)
        }
        Error::Execution(PublicationError::Deferred(original)) => match original {
            PublicationDeferral::Execution(original) => deferred_retryable(original),
            PublicationDeferral::IsolatedSourceTransport(original) => {
                archive_replay_retryable(original)
            }
            // Each wait belongs to the actual original acquisition owner. It
            // grants scheduling only, never evidence of an execution outcome.
            _ => original.release_wait().is_some(),
        },
        _ => false,
    }
}
// Only a completed optional capture retaining actual pool contention needs a
// fresh execution. Storage/projection retries keep their exact staged witness;
// fixed limits, missing provenance and corruption cannot request reconstruction.
fn replay_needs_fresh_capture(error: &crate::sumeragi::node::IsolatedReplayError) -> bool {
    use crate::sumeragi::{
        driver::traits::{PublicationDeferral, PublicationError},
        node::{IsolatedReplayError, NodeError},
        startup::StartupError,
    };
    matches!(
        error,
        IsolatedReplayError::Execution(PublicationError::Deferred(
            PublicationDeferral::IsolatedSourceTransport(
                NativeContextArchiveError::CaptureAdmission(AllocationRefusal::Capacity { .. })
            )
        )) | IsolatedReplayError::Startup(NodeError::Startup(
            StartupError::IsolatedSourceTransport(NativeContextArchiveError::CaptureAdmission(
                AllocationRefusal::Capacity { .. }
            ))
        ))
    )
}
fn missing_transport(error: &SourceReadError) -> bool {
    matches!(error, SourceReadError::Archive(NativeContextArchiveError::Io(original)) if original.kind() == ErrorKind::NotFound)
        || matches!(error, SourceReadError::Archive(NativeContextArchiveError::Storage(crate::kura::Error::IO(original, _))) if original.kind() == ErrorKind::NotFound)
}

/// Original startup inputs retained until the existing State pool admits one slot.
struct PendingProducer {
    state: Arc<State>,
    policy: FastpqProducer,
    replay_seed: Option<crate::sumeragi::node::NativeReplaySeed>,
}

/// Stable unique producer backing moved through the worker's blocking task returns.
///
/// Native finality and isolated replay retain large inline state. Returning that
/// state by value repeats its layout in Tokio's result/poll frames while decoding.
/// This owner moves only the admitted backing handle and bounded startup inputs.
/// The original pool funds the exact slot before any Producer is constructed;
/// nested native, replay and proof owners keep their existing separate charges.
pub(super) struct WorkerProducer {
    pending: Option<PendingProducer>,
    retained: Option<ChargedBuffer<Producer>>,
    poll_interval: std::time::Duration,
    admission: Option<ChargedBufferError>,
    stopped: bool,
}
impl WorkerProducer {
    pub(super) fn new(
        state: Arc<State>,
        policy: FastpqProducer,
        replay_seed: Option<crate::sumeragi::node::NativeReplaySeed>,
    ) -> Self {
        Self {
            poll_interval: policy.poll_interval,
            pending: Some(PendingProducer {
                state,
                policy,
                replay_seed,
            }),
            retained: None,
            admission: None,
            stopped: false,
        }
    }

    pub(super) fn poll_interval(&self) -> std::time::Duration {
        self.poll_interval
    }

    // Keep construction's by-value temporaries off the subsequent decode stack.
    // This frame returns before the retained producer's first attempt begins.
    #[inline(never)]
    fn initialize(&mut self) -> Result<(), ChargedBufferError> {
        if self.retained.is_some() {
            return Ok(());
        }
        let pending = self
            .pending
            .as_ref()
            .expect("original producer startup inputs");
        let mut retained = ChargedBuffer::new(1, &pending.state.ivm_execution_budget())?;
        let pending = self
            .pending
            .take()
            .expect("admitted original producer startup inputs");
        retained.push_reserved(Producer::new(
            pending.state,
            pending.policy,
            pending.replay_seed,
        ));
        self.retained = Some(retained);
        self.admission = None;
        Ok(())
    }

    pub(super) fn attempt(
        &mut self,
        engine: &Arc<dyn FastpqProofEngine>,
        generation: u64,
        shutdown: &ShutdownSignal,
        external_shutdown: Option<&ShutdownSignal>,
    ) {
        if self.stopped || shutdown_requested(shutdown, external_shutdown) {
            return;
        }
        if let Err(error) = self.initialize() {
            let retryable = buffer_retryable(&error);
            warn!(retryable, %error, "FASTPQ worker retains original startup inputs pending producer backing");
            self.stopped = !retryable;
            self.admission = Some(error);
            return;
        }
        self.retained
            .as_mut()
            .expect("one initialized original producer slot")
            .as_mut_slice()[0]
            .attempt(engine, generation, shutdown, external_shutdown);
    }
}

/// Retained progress of the existing worker, not a second dispatch queue or workflow.
pub(super) struct Producer {
    state: Arc<State>,
    policy: FastpqProducer,
    cursor: Option<NativeFinalityCursorV1>,
    height: u64,
    h2: Option<crate::sumeragi::certified_chain::AuthenticatedExecutionBlock>,
    source: Option<NativeFastpqSourceRead>,
    replay_seed: Option<crate::sumeragi::node::NativeReplaySeed>,
    replay: Option<crate::sumeragi::node::IsolatedNativeReplay>,
    source_missing: bool,
    source_replayed: bool,
    job: Option<FastpqWitnessJob>,
    completed: Option<FastpqCompletedEntry>,
    // A terminal proof/source failure stops dispatch but retains its original work owner.
    stopped: bool,
    cause: Option<ProducerError>,
}
impl Producer {
    pub(super) fn new(
        state: Arc<State>,
        policy: FastpqProducer,
        replay_seed: Option<crate::sumeragi::node::NativeReplaySeed>,
    ) -> Self {
        Self {
            state,
            policy,
            cursor: None,
            height: 1,
            h2: None,
            source: None,
            replay_seed,
            replay: None,
            source_missing: false,
            source_replayed: false,
            job: None,
            completed: None,
            stopped: false,
            cause: None,
        }
    }
    pub(super) fn attempt(
        &mut self,
        engine: &Arc<dyn FastpqProofEngine>,
        generation: u64,
        shutdown: &ShutdownSignal,
        external_shutdown: Option<&ShutdownSignal>,
    ) {
        if self.stopped || shutdown_requested(shutdown, external_shutdown) {
            return;
        }
        let Some(deadline) = Instant::now().checked_add(self.policy.step_timeout) else {
            self.cause = Some(ProducerError::Identity(
                "attempt duration is not representable",
            ));
            self.stopped = true;
            return;
        };
        let result = self.step(engine, generation, shutdown, external_shutdown, deadline);
        if let Err(error) = result {
            let retryable = error.retryable();
            warn!(height = self.height, retryable, %error, "FASTPQ producer retains unresolved exact source");
            self.stopped = !retryable;
            self.cause = Some(error);
        } else {
            self.cause = None;
        }
    }

    // Each phase owns large native by-value results. End unrelated temporary
    // frames before replay acquires World blocks on the ordinary blocking worker.
    fn step(
        &mut self,
        engine: &Arc<dyn FastpqProofEngine>,
        generation: u64,
        shutdown: &ShutdownSignal,
        external_shutdown: Option<&ShutdownSignal>,
        deadline: Instant,
    ) -> Result<(), ProducerError> {
        check(deadline)?;
        if self.completed.is_some() {
            return self.persist_completed(shutdown, external_shutdown, deadline);
        }
        if self.job.is_some() {
            return self.advance_job(engine, generation, shutdown, external_shutdown, deadline);
        }
        if self.source.is_some() {
            if self.source_missing {
                return self.replay_source(deadline);
            }
            return self.read_source(deadline);
        }
        self.select_source(engine, deadline)
    }

    #[inline(never)]
    fn persist_completed(
        &mut self,
        shutdown: &ShutdownSignal,
        external_shutdown: Option<&ShutdownSignal>,
        deadline: Instant,
    ) -> Result<(), ProducerError> {
        let completed = self.completed.take().expect("retained completed proof");
        // The generation lease held by the worker spans this exact-byte barrier.
        // Cancellation checks precede persistence; a completed barrier remains a fact.
        if shutdown_requested(shutdown, external_shutdown) {
            self.completed = Some(completed);
            return Ok(());
        }
        match completed.persist(self.state.kura()) {
            Ok(job) => self.job = Some(job),
            Err((completed, error)) => {
                self.completed = Some(completed);
                return Err(error.into());
            }
        }
        check(deadline)
    }

    #[inline(never)]
    fn advance_job(
        &mut self,
        engine: &Arc<dyn FastpqProofEngine>,
        generation: u64,
        shutdown: &ShutdownSignal,
        external_shutdown: Option<&ShutdownSignal>,
        deadline: Instant,
    ) -> Result<(), ProducerError> {
        let job = self.job.as_mut().expect("retained exact job");
        if job.next_statement == job.source.leaves().len() {
            // Empty manifests advance only after the complete native D7 and source
            // inventory were actually authenticated by NativeFastpqSourceRead.
            self.height = self
                .height
                .checked_add(1)
                .ok_or(ProducerError::Identity("height exhausted"))?;
            self.job = None;
            return Ok(());
        }
        let (proving, verification) = engine.limits();
        if job.recover_next(self.state.kura(), proving, &verification)? {
            return check(deadline);
        }
        check(deadline)?;
        let job = self.job.take().expect("retained exact job");
        match process_job(engine, job, generation, shutdown, external_shutdown) {
            FastpqJobOutcome::Complete(completed) => self.completed = Some(completed),
            FastpqJobOutcome::Exhausted(job) => self.job = Some(job),
            FastpqJobOutcome::Deferred { job, error } => {
                self.job = Some(job);
                return Err(error.into());
            }
        }
        // A synchronous proof cannot be preempted. The same absolute budget is
        // checked after it, preserving the produced owner for a later finite turn.
        check(deadline)
    }

    #[inline(never)]
    fn replay_source(&mut self, deadline: Instant) -> Result<(), ProducerError> {
        let read = self.source.as_mut().expect("retained original source");
        let seed = self.replay_seed.as_ref().ok_or(ProducerError::Identity(
            "missing original startup replay seed",
        ))?;
        if !seed.belongs_to(&self.state) {
            return Err(ProducerError::Identity(
                "replay seed differs from original State, Kura or pool",
            ));
        }
        if self.replay.is_none() {
            self.replay = Some(seed.begin(read.native()?, deadline)?);
            return check(deadline);
        }
        let completed = self
            .replay
            .as_mut()
            .expect("retained original replay")
            .advance(
                read.native()?,
                deadline,
                usize::from(self.policy.max_native_steps.get()),
            );
        let completed = match completed {
            Ok(completed) => completed,
            Err(error) => {
                if replay_needs_fresh_capture(&error) {
                    // Drop only this isolated temporary destination. The
                    // original authenticated source, seed and deadline
                    // remain selected; no durable cursor has advanced.
                    self.replay = None;
                }
                return Err(error.into());
            }
        };
        if let Some(transport) = completed {
            read.use_replayed_transport(transport)?;
            self.source_missing = false;
            self.source_replayed = true;
            self.replay = None;
        }
        check(deadline)
    }

    #[inline(never)]
    fn read_source(&mut self, deadline: Instant) -> Result<(), ProducerError> {
        let read = self.source.as_mut().expect("retained original source");
        match read.poll() {
            Ok(Some(source)) => {
                self.job = Some(FastpqWitnessJob::from_recovered(source));
                self.source = None;
                self.source_replayed = false;
            }
            Ok(None) => {}
            Err(error) if missing_transport(&error) => {
                if self.source_replayed {
                    return Err(ProducerError::Identity(
                        "completed isolated replay omitted exact source transport",
                    ));
                }
                self.source_missing = true;
                return Err(error.into());
            }
            Err(error) => return Err(error.into()),
        }
        check(deadline)
    }

    #[inline(never)]
    fn select_source(
        &mut self,
        engine: &Arc<dyn FastpqProofEngine>,
        deadline: Instant,
    ) -> Result<(), ProducerError> {
        if u64::try_from(self.state.committed_height())
            .map_err(|_| ProducerError::Identity("committed height is not representable"))?
            < self.height.max(2)
        {
            return Ok(());
        }
        let native = if self.height == 2 {
            self.h2
                .take()
                .ok_or(ProducerError::Identity("original H2 output is missing"))?
        } else {
            let view = self.state.try_view_once()?;
            let selected = view
                .native_execution_tip()
                .ok_or(ProducerError::Identity("applied native tip is missing"))?
                .root_scope();
            let cursor = self
                .cursor
                .get_or_insert_with(|| NativeFinalityCursorV1::new(selected));
            let target = NonZeroU64::new(self.height.max(2))
                .ok_or(ProducerError::Identity("zero target"))?;
            let Some(output) = cursor.advance_to_height(
                &view,
                target,
                &self.state.ivm_execution_budget(),
                deadline,
                self.policy.max_native_steps,
            )?
            else {
                return Ok(());
            };
            if self.height == 1 {
                let genesis = cursor
                    .take_genesis_execution()
                    .ok_or(ProducerError::Identity(
                        "verified H2 omitted original genesis anchor",
                    ))?;
                self.h2 = Some(output.into_authenticated_execution());
                genesis.into_authenticated_execution()
            } else {
                output.into_authenticated_execution()
            }
        };
        let (_, verification) = engine.limits();
        self.source = Some(NativeFastpqSourceRead::new(
            self.state.kura_handle(),
            native,
            self.state.ivm_execution_budget(),
            SourceReadLimits {
                max_entries: self.policy.max_source_entries.get(),
                max_statements: self.policy.max_source_statements.get(),
                max_effects_per_statement: verification.public_statement.max_effects,
            },
        ));
        check(deadline)
    }
}
fn check(deadline: Instant) -> Result<(), ProducerError> {
    if Instant::now() >= deadline {
        Err(ProducerError::Deadline)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct BusyEngine(Arc<AtomicUsize>);
    impl FastpqProofEngine for BusyEngine {
        fn limits(&self) -> (ProvingLimits, ExecutionEffectVerificationLimits) {
            (
                ProvingLimits::default(),
                ExecutionEffectVerificationLimits::default(),
            )
        }
        fn prove(
            &self,
            _: &SourceExecutionEffectStatement<'_>,
            _: ExpectedExecutionEffects<'_>,
            _: &AllocationBudget,
            _: &mut AllocationReservation,
        ) -> Result<FastpqProofOutput, ProvingError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(ProvingError::Busy)
        }
    }

    #[test]
    fn idle_final_source_retains_original_job_across_typed_prover_capacity() {
        let (chain, original) = crate::fastpq::finalized_source::test_fixture::original_source(
            iroha_primitives::numeric::Quantity::from(100_u32),
            &[3],
        );
        drop(original);
        chain
            .state()
            .ivm_execution_budget()
            .set_limit_bytes(2 * 1024 * 1024 * 1024);
        let calls = Arc::new(AtomicUsize::new(0));
        let engine: Arc<dyn FastpqProofEngine> = Arc::new(BusyEngine(Arc::clone(&calls)));
        // Retain the production worker's original charged slot while directly
        // observing retries. Inline Producer construction retains its large native
        // replay layout in this test frame throughout the finality decoder call.
        let mut owner =
            WorkerProducer::new(Arc::clone(chain.state()), FastpqProducer::default(), None);
        owner.initialize().expect("original worker backing");
        assert!(owner.pending.is_none());
        let retained = owner.retained.as_mut().expect("original producer slot");
        assert!(retained.belongs_to(&chain.state().ivm_execution_budget()));
        assert_eq!(retained.as_slice().len(), 1);
        let producer = &mut retained.as_mut_slice()[0];
        let shutdown = ShutdownSignal::new();
        for _ in 0..256 {
            producer.attempt(&engine, 0, &shutdown, None);
            if calls.load(Ordering::SeqCst) >= 2 {
                break;
            }
            assert!(!producer.stopped, "{:?}", producer.cause);
        }
        assert!(
            calls.load(Ordering::SeqCst) >= 2,
            "finite unchanged-source retries need no unrelated traffic"
        );
        assert_eq!(chain.state().committed_height(), 2);
        let retained = producer
            .job
            .as_ref()
            .expect("original typed capacity returns the source");
        assert_eq!(retained.next_statement, 0);
        let height = retained.height();
        let pointer = std::ptr::from_ref(retained.source.entry(0).unwrap().effects());
        producer.attempt(&engine, 0, &shutdown, None);
        assert_eq!(producer.job.as_ref().unwrap().height(), height);
        assert_eq!(
            std::ptr::from_ref(
                producer
                    .job
                    .as_ref()
                    .unwrap()
                    .source
                    .entry(0)
                    .unwrap()
                    .effects()
            ),
            pointer
        );
        assert!(matches!(
            producer.cause,
            Some(ProducerError::Work(FastpqWorkRefusal::Prove(
                ProvingError::Busy
            )))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn existing_worker_polls_final_native_tip_without_queue_or_new_block() {
        let (chain, source) = crate::fastpq::finalized_source::test_fixture::original_source(
            iroha_primitives::numeric::Quantity::from(100_u32),
            &[3],
        );
        drop(source);
        chain
            .state()
            .ivm_execution_budget()
            .set_limit_bytes(2 * 1024 * 1024 * 1024);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut policy = FastpqProducer::default();
        policy.poll_interval = std::time::Duration::from_millis(1);
        let producer = WorkerProducer::new(Arc::clone(chain.state()), policy, None);
        let (_sender, receiver) = tokio::sync::mpsc::channel(1);
        let shutdown = ShutdownSignal::new();
        let callback_calls = Arc::clone(&calls);
        let task = spawn_worker(
            receiver,
            Arc::new(AtomicBool::new(false)),
            Some(producer),
            Arc::new(FastpqLaneGenerationLease { generation: 0 }),
            shutdown.clone(),
            None,
            move || Some(Arc::new(BusyEngine(callback_calls))),
        );
        let observed = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while calls.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        shutdown.send();
        task.await.unwrap();
        assert!(
            observed.is_ok(),
            "finite original source must retry on the existing idle worker"
        );
        assert_eq!(
            chain.state().committed_height(),
            2,
            "no unrelated transaction or empty block was produced"
        );
    }

    #[test]
    fn malformed_source_and_proof_failures_are_terminal_without_text_classification() {
        assert!(!ProducerError::Source(SourceReadError::Source("capacity")).retryable());
        assert!(!ProducerError::Durable(durable::DurableError::Identity("busy")).retryable());
        assert!(
            !ProducerError::Work(FastpqWorkRefusal::Prove(ProvingError::Prove(
                fastpq_prover::Error::CommitmentMismatch
            )))
            .retryable()
        );
        assert!(!ProducerError::View(StateViewError::Changed).retryable());
        assert!(!ProducerError::View(StateViewError::Poisoned).retryable());
        assert!(ProducerError::Work(FastpqWorkRefusal::Prove(ProvingError::Busy)).retryable());
        assert!(
            ProducerError::Source(SourceReadError::Archive(NativeContextArchiveError::Io(
                std::io::Error::new(ErrorKind::NotFound, "original tape missing"),
            )))
            .retryable()
        );
    }

    #[test]
    fn expired_original_attempt_deadline_does_not_acquire_or_dispatch_source() {
        let (chain, source) = crate::fastpq::finalized_source::test_fixture::original_source(
            iroha_primitives::numeric::Quantity::from(100_u32),
            &[3],
        );
        drop(source);
        let calls = Arc::new(AtomicUsize::new(0));
        let engine: Arc<dyn FastpqProofEngine> = Arc::new(BusyEngine(Arc::clone(&calls)));
        let mut producer =
            Producer::new(Arc::clone(chain.state()), FastpqProducer::default(), None);
        assert!(matches!(
            producer.step(&engine, 0, &ShutdownSignal::new(), None, Instant::now()),
            Err(ProducerError::Deadline)
        ));
        assert!(producer.cursor.is_none() && producer.source.is_none() && producer.job.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(producer.height, 1);
    }
    #[test]
    fn finality_retry_requires_original_capacity_not_its_lossy_vm_category() {
        use crate::execution_attempt::ExecutionDeferred;
        use ivm::error::ExecutionDeferral;

        fn finality(original: ExecutionDeferred) -> ProducerError {
            ProducerError::Finality(NativeFinalityCursorErrorV1::Proof(ProofError::Deferred(
                original,
            )))
        }
        let budget = iroha_allocation::AllocationBudget::new(8);
        let occupied = budget.try_reserve_bytes(8).unwrap();
        let capacity = budget.try_reserve_bytes(1).unwrap_err();
        let error = finality(capacity.clone().into());
        assert!(error.retryable());
        let ProducerError::Finality(NativeFinalityCursorErrorV1::Proof(ProofError::Deferred(
            retained,
        ))) = &error
        else {
            panic!("original finality owner lost")
        };
        assert_eq!(retained.allocation_refusal(), Some(&capacity));
        drop(occupied);
        assert!(budget.try_reserve_bytes(1).is_ok());

        for original in [
            iroha_allocation::AllocationBudget::new(0)
                .try_reserve_bytes(1)
                .unwrap_err(),
            AllocationRefusal::DemandOverflow,
        ] {
            let error = finality(original.clone().into());
            assert!(
                !error.retryable(),
                "permanent original geometry cannot improve on an idle tick"
            );
            let ProducerError::Finality(NativeFinalityCursorErrorV1::Proof(ProofError::Deferred(
                retained,
            ))) = error
            else {
                unreachable!()
            };
            assert_eq!(retained.reason(), ExecutionDeferral::ActiveMemoryCapacity);
            assert_eq!(retained.allocation_refusal(), Some(&original));
        }
        for kind in [
            ExecutionDeferral::LocalInvariantViolation,
            ExecutionDeferral::ActiveMemoryCapacity,
            ExecutionDeferral::VerifierArtifactsUnavailable,
            ExecutionDeferral::VerificationCancelled,
            ExecutionDeferral::NativeVerificationMemoryUnavailable,
            ExecutionDeferral::VerifierInitializationUnavailable,
            ExecutionDeferral::CanonicalHistoryUnavailable,
            ExecutionDeferral::CanonicalHistoryCapacity,
            ExecutionDeferral::TraceOwnerUnavailable,
        ] {
            assert!(
                !finality(kind.into()).retryable(),
                "unowned or permanent kind: {kind:?}"
            );
        }
        // This exact physical allocator category is constructed by the cursor's
        // fallible buffer/key destination owners; it does not imply a pool wake.
        assert!(finality(ExecutionDeferral::AllocationUnavailable.into()).retryable());
    }

    #[test]
    fn finality_retry_preserves_original_enclosing_decoder_refusal() {
        use norito::core::{DecodeLimits, with_decode_limits_scope};
        let bytes = norito::encode_canonical(&vec![19_u8; 32]).unwrap();
        let cause = with_decode_limits_scope(
            DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || {
                norito::decode_canonical_for_admission::<Vec<u8>>(
                    &bytes,
                    norito::canonical_decode_limits(bytes.len()),
                )
            },
        )
        .unwrap_err();
        let original = cause.local_refusal().unwrap();
        let error = ProducerError::Finality(NativeFinalityCursorErrorV1::Proof(
            ProofError::Deferred(original.clone().into()),
        ));
        assert!(error.retryable());
        let ProducerError::Finality(NativeFinalityCursorErrorV1::Proof(ProofError::Deferred(
            retained,
        ))) = error
        else {
            unreachable!()
        };
        assert_eq!(retained.decode_refusal(), Some(&original));
        assert!(
            retained.allocation_refusal().is_none(),
            "decoder cause cannot invent a pool release source"
        );
    }
    #[test]
    fn replay_retry_rebuilds_only_original_optional_pool_capture() {
        use crate::sumeragi::{
            driver::traits::{PublicationDeferral, PublicationError},
            node::IsolatedReplayError,
        };
        let pool = iroha_allocation::AllocationBudget::new(8);
        let occupied = pool.try_reserve_bytes(8).unwrap();
        let capacity = pool.try_reserve_bytes(1).unwrap_err();
        let capture = |error| {
            IsolatedReplayError::Execution(PublicationError::Deferred(
                PublicationDeferral::IsolatedSourceTransport(error),
            ))
        };
        let error = capture(NativeContextArchiveError::CaptureAdmission(
            capacity.clone(),
        ));
        assert!(replay_retryable(&error));
        assert!(replay_needs_fresh_capture(&error));
        let IsolatedReplayError::Execution(PublicationError::Deferred(
            PublicationDeferral::IsolatedSourceTransport(
                NativeContextArchiveError::CaptureAdmission(original),
            ),
        )) = &error
        else {
            panic!("original capture cause lost")
        };
        assert_eq!(original, &capacity);
        drop(occupied);
        assert!(pool.try_reserve_bytes(1).is_ok());
        for original in [
            pool.try_reserve_bytes(9).unwrap_err(),
            AllocationRefusal::DemandOverflow,
        ] {
            let error = capture(NativeContextArchiveError::CaptureAdmission(original));
            assert!(!replay_retryable(&error));
            assert!(!replay_needs_fresh_capture(&error));
        }
        let projection = capture(NativeContextArchiveError::Allocation(
            ChargedBufferError::Admission(capacity),
        ));
        assert!(replay_retryable(&projection));
        assert!(
            !replay_needs_fresh_capture(&projection),
            "projection retains its immutable witness"
        );
        for error in [
            NativeContextArchiveError::Source("erased capture capacity"),
            NativeContextArchiveError::Source("foreign original pool"),
            NativeContextArchiveError::Limit {
                maximum: 1,
                actual: 2,
            },
            NativeContextArchiveError::Io(std::io::Error::new(
                ErrorKind::InvalidData,
                "corrupt source",
            )),
        ] {
            let error = capture(error);
            assert!(!replay_retryable(&error));
            assert!(!replay_needs_fresh_capture(&error));
        }
    }
    #[test]
    fn missing_transport_reconstruction_requires_exact_file_absence() {
        let absent = SourceReadError::Archive(NativeContextArchiveError::Io(std::io::Error::new(
            ErrorKind::NotFound,
            "original source tape missing",
        )));
        assert!(missing_transport(&absent));
        for error in [
            SourceReadError::Archive(NativeContextArchiveError::Io(std::io::Error::new(
                ErrorKind::InvalidData,
                "NotFound: corrupt retained tape",
            ))),
            SourceReadError::Archive(NativeContextArchiveError::Source("missing optional tape")),
            SourceReadError::Archive(NativeContextArchiveError::Limit {
                maximum: 1,
                actual: 2,
            }),
            SourceReadError::Source("missing authenticated source"),
        ] {
            assert!(!missing_transport(&error));
        }
    }
    #[test]
    fn idle_worker_reconstructs_missing_nonempty_h1_before_retrying_original_proof() {
        std::thread::Builder::new()
            .name("missing-fastpq-source-fixture".into())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                // The large stack belongs only to construction of the genuine fixture;
                // the existing asynchronous worker retains its normal runtime threads.
                let (chain, mut seeds, _) = crate::sumeragi::node::isolated_replay_source_fixture_for_test(1);
                let seed = seeds.pop().unwrap();
                let source_root = chain.kura().store_root().join(crate::kura::Kura::fastpq_source_namespace());
                let mut removed = 0;
                for entry in std::fs::read_dir(&source_root).unwrap() {
                    let path = entry.unwrap().path();
                    if path.extension().is_some_and(|extension| extension == "fqs") {
                        std::fs::remove_file(path).unwrap();
                        removed += 1;
                    }
                }
                assert!(removed > 0, "the genuine nonempty source had retained optional tapes");
                let root_before = chain.state().verify_world_state_accumulator().unwrap();
                let calls = Arc::new(AtomicUsize::new(0));
                let observed_calls = Arc::clone(&calls);
                let runtime = tokio::runtime::Runtime::new().unwrap();
                runtime.block_on(async {
                    let policy = FastpqProducer {
                        poll_interval: std::time::Duration::from_millis(1),
                        ..FastpqProducer::default()
                    };
                    let producer = WorkerProducer::new(Arc::clone(chain.state()), policy, Some(seed));
                    let (_sender, receiver) = tokio::sync::mpsc::channel(1);
                    let shutdown = ShutdownSignal::new();
                    let task = spawn_worker(
                        receiver,
                        Arc::new(AtomicBool::new(false)),
                        Some(producer),
                        Arc::new(FastpqLaneGenerationLease { generation: 0 }),
                        shutdown.clone(),
                        None,
                        move || Some(Arc::new(BusyEngine(observed_calls))),
                    );
                    let observed = tokio::time::timeout(std::time::Duration::from_secs(120), async {
                        while calls.load(Ordering::SeqCst) < 2 {
                            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        }
                    }).await;
                    shutdown.send();
                    task.await.unwrap();
                    assert!(observed.is_ok(), "the idle worker must reconstruct the missing source before invoking its proof engine");
                });
                assert_eq!(chain.state().committed_height(), 2, "no successor traffic was submitted");
                assert_eq!(chain.state().verify_world_state_accumulator().unwrap(), root_before);
                assert!(std::fs::read_dir(source_root).unwrap().all(|entry| {
                    !entry.unwrap().path().extension().is_some_and(|extension| extension == "fqs")
                }), "isolated reconstruction must not rewrite live optional source custody");
            })
            .unwrap()
            .join()
            .unwrap_or_else(|failure| std::panic::resume_unwind(failure));
    }
}

#[cfg(test)]
pub(crate) fn isolated_replay_retryable_for_test(
    error: &crate::sumeragi::node::IsolatedReplayError,
) -> bool {
    replay_retryable(error)
}

#[cfg(test)]
mod proof_completion_tests;

#[cfg(test)]
mod worker_tests;
