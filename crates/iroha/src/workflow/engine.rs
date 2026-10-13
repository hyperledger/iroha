//! The durable workflow engine: run, read-only recovery, cancellation and progress.
//!
//! The engine owns ordering and durability only. Capability logic lives in a
//! [`WorkflowDriver`], signing in a [`WorkflowAccount`], submission and
//! committed-outcome reads in a [`WorkflowLedger`]. Every external effect is
//! preceded by a compare-and-swap of the journal, and every interrupted step is
//! reconciled by a read-only query before anything else happens.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use super::{
    contract::{
        MAX_DISPATCHES_PER_IDENTITY_V1, MAX_WORKFLOW_TRANSACTION_BYTES_V1, RoundStateV1,
        StepKindV1, TransactionStateV1, WorkflowErrorCode, WorkflowStage, WorkflowStatusV1,
    },
    error::{WorkflowBounds, WorkflowError},
    journal::{
        CustodyHandleV1, Digest32, DriverIdentityV1, NativePaymentCompletionV1, RoundInputV1,
        StepDescriptorV1, TransactionIdentityV1, TransactionInputV1, WorkflowBindingV1, WorkflowId,
        WorkflowIdentityV1, WorkflowJournalV1, WorkflowPlanV1, WorkflowProgressV1, record_digest,
        round_identity,
    },
    storage::{WorkflowRunnerLease, WorkflowStorage, WorkflowStorageErrorKind},
};

/// Boxed future returned by the engine's collaborators.
pub type WorkflowFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Typed failure reported by a driver or by the account context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepFailure {
    /// Closed error code.
    pub code: WorkflowErrorCode,
    /// Diagnostic without secret material.
    pub detail: String,
}

impl StepFailure {
    /// Create a typed failure.
    #[must_use]
    pub fn new(code: WorkflowErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    fn unsupported(what: &str) -> Self {
        Self::new(
            WorkflowErrorCode::UnsupportedOperation,
            format!("the capability driver does not implement {what}"),
        )
    }

    fn into_error(self, stage: WorkflowStage, step: usize) -> WorkflowError {
        WorkflowError::new(self.code, stage, self.detail).with_step(step)
    }
}

/// Signed bytes and the identity the signer computed for them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedStepTransaction {
    /// Canonical signed transaction bytes.
    pub signed_transaction: Vec<u8>,
    /// Identity of those bytes.
    pub identity: TransactionIdentityV1,
}

/// The account context of a workflow: who signs and on which network.
pub trait WorkflowAccount: Send + Sync {
    /// Network and authority every transaction of the workflow is bound to.
    fn binding(&self) -> WorkflowBindingV1;

    /// Sign one exact unsigned payload.
    fn sign<'a>(
        &'a self,
        unsigned_payload: &'a [u8],
    ) -> WorkflowFuture<'a, Result<SignedStepTransaction, StepFailure>>;

    /// Recompute the identity of canonical signed bytes.
    ///
    /// # Errors
    /// `NonCanonicalEncoding` when the bytes are not a canonical signed transaction.
    fn identify(&self, signed_transaction: &[u8]) -> Result<TransactionIdentityV1, StepFailure>;
}

/// Typed result of one dispatch, established by the submission owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// Admission was acknowledged.
    Accepted,
    /// The exact transaction is already queued or committed.
    AlreadyKnown,
    /// A validated definite refusal: this dispatch did not admit the transaction.
    Refused {
        /// Refusal diagnostic.
        detail: String,
    },
    /// This dispatch did not admit the bytes and they may be sent again later.
    NotAdmitted {
        /// Actual cause: local resource, unsupported node, malformed request.
        code: WorkflowErrorCode,
        /// Diagnostic.
        detail: String,
    },
    /// The bytes may have been admitted and nothing proves either way.
    Ambiguous {
        /// Diagnostic.
        detail: String,
    },
}

/// Result of one read-only committed-outcome query on a transaction identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommittedOutcome {
    /// Authoritative state-resolved `Applied`.
    Applied {
        /// Reported block height.
        block_height: Option<u64>,
    },
    /// Authoritative state-resolved `Rejected`.
    Rejected {
        /// Rejection diagnostic.
        detail: String,
    },
    /// Authoritative state-resolved `Expired`.
    Expired,
    /// The network shows the transaction without authoritative finality.
    ObservedNotFinal,
    /// Canonical absence for exactly this identity and the global scope.
    ExactAbsence,
    /// The read failed or its response could not be bound to this identity.
    ReadFailed {
        /// Diagnostic.
        detail: String,
    },
}

/// Submission and committed-outcome reads of the ledger a workflow runs against.
pub trait WorkflowLedger: Send + Sync {
    /// Dispatch the exact signed bytes once and classify the result.
    fn dispatch<'a>(
        &'a self,
        signed_transaction: &'a [u8],
        identity: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, DispatchOutcome>;

    /// Read the committed outcome of one identity. This never submits anything.
    fn committed_outcome<'a>(
        &'a self,
        identity: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, CommittedOutcome>;
}

/// Clock used for polling and for the caller's local observation bound only.
///
/// Time never closes a transaction identity and never changes a state.
pub trait WorkflowClock: Send + Sync {
    /// Monotonic milliseconds on the Unix time scale of this process.
    fn now_unix_ms(&self) -> u64;

    /// Wait for `duration`.
    fn sleep(&self, duration: Duration) -> WorkflowFuture<'_, ()>;
}

/// Wall-clock origin advanced by a monotonic timer, sleeping on the Tokio timer.
#[derive(Clone, Copy, Debug)]
pub struct SystemWorkflowClock {
    origin: std::time::Instant,
    origin_unix_ms: u64,
}

impl SystemWorkflowClock {
    /// Read the wall clock once and advance monotonically from there.
    #[must_use]
    pub fn new() -> Self {
        let origin_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            });
        Self {
            origin: std::time::Instant::now(),
            origin_unix_ms,
        }
    }
}

impl Default for SystemWorkflowClock {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkflowClock for SystemWorkflowClock {
    fn now_unix_ms(&self) -> u64 {
        let elapsed = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.origin_unix_ms.saturating_add(elapsed)
    }

    fn sleep(&self, duration: Duration) -> WorkflowFuture<'_, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// Receives the progress snapshot of every journal record a call stores.
pub trait WorkflowObserver: Send + Sync {
    /// Called after the record is durable.
    fn on_progress(&self, progress: &WorkflowProgressV1);
}

/// What a driver sees when it builds the payload of a transaction step.
#[derive(Clone, Copy, Debug)]
pub struct StepContext<'a> {
    /// Workflow identifier.
    pub workflow_id: WorkflowId,
    /// Zero-based step index.
    pub step_index: u32,
    /// The planned step, including its bound intent digest.
    pub descriptor: &'a StepDescriptorV1,
    /// One-based ordinal of the transaction identity being built.
    pub identity_ordinal: u8,
    /// The journal, for the public outputs of earlier steps.
    pub journal: &'a WorkflowJournalV1,
}

/// The exact unsigned payload of one transaction identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltStepPayload {
    /// Intent the payload implements; must equal the step's bound intent digest.
    pub intent_digest: Digest32,
    /// Canonical unsigned payload bytes.
    pub unsigned_payload: Vec<u8>,
}

/// What a driver sees when it starts or recovers an off-chain round.
#[derive(Clone, Copy, Debug)]
pub struct RoundContext<'a> {
    /// Workflow identifier.
    pub workflow_id: WorkflowId,
    /// Zero-based step index.
    pub step_index: u32,
    /// The planned step, including its bound context digest.
    pub descriptor: &'a StepDescriptorV1,
    /// The persisted round identity. A driver never invents another one.
    pub round_id: Digest32,
    /// The journal, for the public outputs of earlier steps.
    pub journal: &'a WorkflowJournalV1,
}

/// Binding and participant set a driver reports for a round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundStatusReport {
    /// Round identity the report belongs to.
    pub round_id: Digest32,
    /// Context the round ran under; must equal the step's bound context digest.
    pub context_digest: Digest32,
    /// Participants received, strictly ascending.
    pub participants: Vec<Digest32>,
}

/// State of a round as its driver reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoundReport {
    /// The round completed.
    Completed {
        /// Binding and final participant set.
        status: RoundStatusReport,
        /// Public transcript.
        transcript: Vec<u8>,
        /// References to secret material kept in the caller's custody.
        custody_handles: Vec<CustodyHandleV1>,
    },
    /// The round runs and waits for participants.
    Waiting(RoundStatusReport),
    /// The round failed for good (abort, revocation, epoch change).
    Failed {
        /// Typed failure.
        code: WorkflowErrorCode,
        /// Diagnostic.
        detail: String,
    },
}

/// Result of recovering a round under its persisted identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoundRecovery {
    /// No external effect of this round exists.
    NotStarted,
    /// The round exists in the reported state.
    Found(RoundReport),
}

/// Capability binding of a workflow: builds payloads and runs rounds.
///
/// The defaults return `UnsupportedOperation`: the workflow scaffolding does not
/// by itself deliver bootstrap, key generation or threshold cryptography.
pub trait WorkflowDriver: Send + Sync {
    /// Identity and schema the plan must be bound to.
    fn identity(&self) -> DriverIdentityV1;

    /// Prove and build the exact unsigned payload of one transaction identity.
    ///
    /// A replacement identity refreshes authoritative context (nonce, lifetime,
    /// parameters) and keeps the step's bound intent.
    fn build_transaction<'a>(
        &'a self,
        context: StepContext<'a>,
    ) -> WorkflowFuture<'a, Result<BuiltStepPayload, StepFailure>> {
        let _ = context;
        Box::pin(async { Err(StepFailure::unsupported("transaction steps")) })
    }

    /// Start the round with the persisted identity. Called after the intent is durable.
    fn start_round<'a>(
        &'a self,
        context: RoundContext<'a>,
    ) -> WorkflowFuture<'a, Result<RoundReport, StepFailure>> {
        let _ = context;
        Box::pin(async { Err(StepFailure::unsupported("off-chain rounds")) })
    }

    /// Whether Run may continue effects of an already started waiting round.
    ///
    /// Opt-in preserves the existing read-only waiting behavior of other drivers.
    fn supports_round_continuation(&self) -> bool {
        false
    }

    /// Continue authorized effects of a freshly recovered waiting round during Run.
    ///
    /// The engine retains the original runner lease and persists the same round identity
    /// before this call. Recover and cancellation never invoke it. The default performs
    /// no effects and returns the observed waiting state unchanged.
    fn continue_round<'a>(
        &'a self,
        context: RoundContext<'a>,
        observed: RoundStatusReport,
    ) -> WorkflowFuture<'a, Result<RoundReport, StepFailure>> {
        let _ = context;
        Box::pin(async move { Ok(RoundReport::Waiting(observed)) })
    }

    /// Recover the round with the persisted identity without sending anything.
    ///
    /// A round that completed externally returns its original transcript and
    /// custody references. A restart never creates a fresh round.
    fn recover_round<'a>(
        &'a self,
        context: RoundContext<'a>,
    ) -> WorkflowFuture<'a, Result<RoundRecovery, StepFailure>> {
        let _ = context;
        Box::pin(async { Err(StepFailure::unsupported("off-chain round recovery")) })
    }
}

/// Per-call policy. Nothing here changes what the ledger accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkflowRunOptions {
    /// How long this call keeps observing an unresolved transaction. Local only.
    pub observation_timeout: Duration,
    /// Interval between committed-outcome reads; must be nonzero.
    pub poll_interval: Duration,
    /// Explicitly authorize one re-dispatch of the exact persisted bytes after a
    /// fresh exact-absence read.
    pub retransmit_identical_bytes: bool,
    /// Explicitly authorize a replacement transaction identity for a step whose
    /// previous identity is authoritatively closed.
    pub retry_rejected_step: bool,
}

impl Default for WorkflowRunOptions {
    /// The observation bound and poll interval of the client's transaction wait; no
    /// retransmission and no replacement identity.
    fn default() -> Self {
        Self {
            observation_timeout: crate::client::DEFAULT_TRANSACTION_WAIT_TIMEOUT,
            poll_interval: crate::client::DEFAULT_TRANSACTION_WAIT_POLL_INTERVAL,
            retransmit_identical_bytes: false,
            retry_rejected_step: false,
        }
    }
}

/// Shared collaborators of every workflow of one account context.
#[derive(Clone)]
pub struct WorkflowEngine {
    storage: Arc<dyn WorkflowStorage>,
    account: Arc<dyn WorkflowAccount>,
    ledger: Arc<dyn WorkflowLedger>,
    clock: Arc<dyn WorkflowClock>,
    observer: Option<Arc<dyn WorkflowObserver>>,
}

impl core::fmt::Debug for WorkflowEngine {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WorkflowEngine")
            .field("durability", &self.storage.durability())
            .field("binding", &self.account.binding())
            .finish_non_exhaustive()
    }
}

/// Durable handle of one workflow: run, recover read-only, cancel and inspect.
#[derive(Clone, Debug)]
pub struct WorkflowHandle {
    engine: WorkflowEngine,
    plan: WorkflowPlanV1,
    id: WorkflowId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Run,
    Recover,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stored {
    Applied,
    Reloaded,
}

const FACT_STORE_ATTEMPTS: usize = 4;
const CANCEL_STORE_ATTEMPTS: usize = 8;

struct Session<'e> {
    engine: &'e WorkflowEngine,
    id: WorkflowId,
    journal: WorkflowJournalV1,
    stored: Digest32,
    _lease: Box<dyn WorkflowRunnerLease>,
}

fn storage_error(error: &super::storage::WorkflowStorageError) -> WorkflowError {
    let code = match error.kind {
        WorkflowStorageErrorKind::Conflict | WorkflowStorageErrorKind::Busy => {
            WorkflowErrorCode::JournalConflict
        }
        WorkflowStorageErrorKind::Unavailable | WorkflowStorageErrorKind::WriteUncertain => {
            WorkflowErrorCode::LocalResourceUnavailable
        }
        // A record above the bound is damage of the stored journal, like any other
        // record that does not decode: reported at load, never repaired.
        WorkflowStorageErrorKind::Oversized => {
            return WorkflowError::new(
                WorkflowErrorCode::StorageCorrupted,
                WorkflowStage::Load,
                error.detail.clone(),
            );
        }
    };
    WorkflowError::new(code, WorkflowStage::Store, error.detail.clone())
}

impl Session<'_> {
    fn reload(&mut self) -> Result<(), WorkflowError> {
        let previous = self.journal.sequence;
        let (journal, stored) = self
            .engine
            .load(&self.id)
            .and_then(|loaded| {
                loaded.ok_or_else(|| {
                    WorkflowError::new(
                        WorkflowErrorCode::StorageCorrupted,
                        WorkflowStage::Load,
                        "the journal disappeared while the workflow was running",
                    )
                })
            })
            .map_err(|mut error| {
                error.last_validated_sequence = Some(previous);
                error
            })?;
        self.journal = journal;
        self.stored = stored;
        Ok(())
    }

    /// Apply `change` to a copy of the journal and store it by compare-and-swap.
    ///
    /// On a lost compare-and-swap the journal is reloaded and nothing is applied.
    /// Any other storage failure aborts the call before a further effect.
    fn commit(
        &mut self,
        change: impl FnOnce(&mut WorkflowJournalV1) -> Result<(), WorkflowError>,
    ) -> Result<Stored, WorkflowError> {
        let mut next = self.journal.clone();
        change(&mut next)?;
        next.sequence += 1;
        next.updated_at_ms = self.engine.clock.now_unix_ms();
        let record = next.encode_record()?;
        match self
            .engine
            .storage
            .compare_and_store(&self.id, Some(&self.stored), &record)
        {
            Ok(()) => {
                self.stored = record_digest(&record);
                self.journal = next;
                self.engine.notify(&self.journal);
                Ok(Stored::Applied)
            }
            Err(error) if error.kind == WorkflowStorageErrorKind::Conflict => {
                self.reload()?;
                Ok(Stored::Reloaded)
            }
            Err(error) => Err(storage_error(&error)),
        }
    }

    /// Record an observed external fact. A concurrent cancellation must not lose it.
    fn record(
        &mut self,
        change: impl Fn(&mut WorkflowJournalV1) -> Result<(), WorkflowError>,
    ) -> Result<(), WorkflowError> {
        for _ in 0..FACT_STORE_ATTEMPTS {
            if self.commit(&change)? == Stored::Applied {
                return Ok(());
            }
        }
        Err(WorkflowError::new(
            WorkflowErrorCode::JournalConflict,
            WorkflowStage::Store,
            "the journal kept changing while an observed fact was being recorded",
        ))
    }

    fn finish(
        self,
        result: Result<(), WorkflowError>,
    ) -> Result<WorkflowProgressV1, WorkflowError> {
        match result {
            Ok(()) => Ok(self.journal.progress()),
            Err(error)
                if error.progress.is_none()
                    && error.code != WorkflowErrorCode::StorageCorrupted =>
            {
                Err(error.with_progress(self.journal.progress()))
            }
            Err(error) => Err(error),
        }
    }

    fn transaction_state(&self, index: usize) -> TransactionStateV1 {
        self.journal.steps[index]
            .transaction
            .as_ref()
            .map_or(TransactionStateV1::Planned, |operation| operation.state)
    }

    fn identity(&self, index: usize) -> Option<TransactionIdentityV1> {
        self.journal.steps[index]
            .transaction
            .as_ref()
            .and_then(super::journal::TransactionOperationV1::current_identity)
    }

    fn unresolved_error(&self, index: usize) -> WorkflowError {
        let (code, detail) = if self.transaction_state(index) == TransactionStateV1::Pending {
            (
                WorkflowErrorCode::FinalityPending,
                "the transaction is known to the network and not yet final",
            )
        } else {
            (
                WorkflowErrorCode::SubmissionOutcomeUnknown,
                "a dispatch may have been admitted and no authoritative outcome is known",
            )
        };
        WorkflowError::new(code, WorkflowStage::Reconcile, detail)
            .with_step(index)
            .with_transaction(self.identity(index))
    }
}

impl WorkflowEngine {
    /// Bind storage, account context, ledger and clock.
    #[must_use]
    pub fn new(
        storage: Arc<dyn WorkflowStorage>,
        account: Arc<dyn WorkflowAccount>,
        ledger: Arc<dyn WorkflowLedger>,
        clock: Arc<dyn WorkflowClock>,
    ) -> Self {
        Self {
            storage,
            account,
            ledger,
            clock,
            observer: None,
        }
    }

    /// Report the progress of every stored record to `observer`.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn WorkflowObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Bind a plan to this account context and return its durable handle.
    ///
    /// The same plan and account always produce the same workflow identifier, so
    /// a handle can be rebuilt after a restart.
    ///
    /// # Errors
    /// Returns the plan or binding validation error.
    pub fn workflow(&self, plan: WorkflowPlanV1) -> Result<WorkflowHandle, WorkflowError> {
        let id = WorkflowIdentityV1::new(&plan, &self.account.binding())?.workflow_id()?;
        Ok(WorkflowHandle {
            engine: self.clone(),
            plan,
            id,
        })
    }

    fn notify(&self, journal: &WorkflowJournalV1) {
        if let Some(observer) = &self.observer {
            observer.on_progress(&journal.progress());
        }
    }

    /// Attach the progress of the stored journal to an error that carries none.
    ///
    /// Errors raised before a call validated a journal (a refused driver, invalid
    /// options, a lease another runner holds) still state partial completion when a
    /// trustworthy journal of this workflow exists. The read takes no lease and
    /// stores nothing. Progress stays absent when no journal exists, when it cannot
    /// be read, when it is corrupted or when it is bound to another workflow.
    fn with_stored_progress(&self, id: &WorkflowId, error: WorkflowError) -> WorkflowError {
        if error.progress.is_some() || error.code == WorkflowErrorCode::StorageCorrupted {
            return error;
        }
        match self.load(id) {
            Ok(Some((journal, _))) => error.with_progress(journal.progress()),
            Ok(None) | Err(_) => error,
        }
    }

    /// Load, verify and bind the stored journal of `id`.
    fn load(
        &self,
        id: &WorkflowId,
    ) -> Result<Option<(WorkflowJournalV1, Digest32)>, WorkflowError> {
        let Some(record) = self
            .storage
            .load(id)
            .map_err(|error| storage_error(&error))?
        else {
            return Ok(None);
        };
        let journal = WorkflowJournalV1::decode_record(&record)?;
        let binding = self.account.binding();
        if journal.id() != *id
            || journal.identity.network != binding.network
            || journal.identity.authority != binding.authority
        {
            return Err(WorkflowError::new(
                WorkflowErrorCode::BindingMismatch,
                WorkflowStage::Load,
                "the stored journal belongs to another workflow, network or authority",
            ));
        }
        // Recompute the identity of the bytes that may still be dispatched.
        for (index, step) in journal.steps.iter().enumerate() {
            let Some(operation) = &step.transaction else {
                continue;
            };
            let Some(bytes) = &operation.signed_transaction else {
                continue;
            };
            let recomputed = self.account.identify(bytes).map_err(|failure| {
                if failure.code == WorkflowErrorCode::LocalResourceUnavailable {
                    return failure.into_error(WorkflowStage::Load, index);
                }
                WorkflowError::new(
                    WorkflowErrorCode::StorageCorrupted,
                    WorkflowStage::Load,
                    format!(
                        "retained signed bytes are not canonical: {}",
                        failure.detail
                    ),
                )
                .with_step(index)
            })?;
            if Some(recomputed) != operation.current_identity() {
                return Err(WorkflowError::new(
                    WorkflowErrorCode::StorageCorrupted,
                    WorkflowStage::Load,
                    "retained signed bytes do not hash to the recorded transaction identity",
                )
                .with_step(index));
            }
        }
        Ok(Some((journal, record_digest(&record))))
    }

    /// Take the runner lease and load the journal, creating it from `plan` when absent.
    fn open(
        &self,
        id: WorkflowId,
        plan: Option<&WorkflowPlanV1>,
    ) -> Result<Session<'_>, WorkflowError> {
        let lease = self
            .storage
            .acquire_runner(&id)
            .map_err(|error| storage_error(&error))?;
        // A lost creation race reloads the winner's journal.
        for _ in 0..2 {
            if let Some((journal, stored)) = self.load(&id)? {
                return Ok(Session {
                    engine: self,
                    id,
                    journal,
                    stored,
                    _lease: lease,
                });
            }
            let Some(plan) = plan else {
                return Err(WorkflowError::new(
                    WorkflowErrorCode::InvalidInput,
                    WorkflowStage::Load,
                    "no journal exists for this workflow",
                ));
            };
            let mut journal =
                WorkflowJournalV1::new(plan, &self.account.binding(), self.clock.now_unix_ms())?;
            journal.sequence = 1;
            let record = journal.encode_record()?;
            match self.storage.compare_and_store(&id, None, &record) {
                Ok(()) => {
                    self.notify(&journal);
                    return Ok(Session {
                        engine: self,
                        id,
                        journal,
                        stored: record_digest(&record),
                        _lease: lease,
                    });
                }
                Err(error) if error.kind == WorkflowStorageErrorKind::Conflict => {}
                Err(error) => return Err(storage_error(&error)),
            }
        }
        Err(WorkflowError::new(
            WorkflowErrorCode::JournalConflict,
            WorkflowStage::Store,
            "the journal could not be created",
        ))
    }

    /// Read-only recovery of the workflow `id`.
    ///
    /// Performs ledger reads, read-only round recovery when `driver` is given and
    /// journal writes. It never builds, signs, dispatches or starts a round, and
    /// returns the progress it could establish.
    ///
    /// # Errors
    /// Storage, corruption and binding errors.
    pub async fn recover_by_id(
        &self,
        id: WorkflowId,
        driver: Option<&dyn WorkflowDriver>,
        options: &WorkflowRunOptions,
    ) -> Result<WorkflowProgressV1, WorkflowError> {
        self.recover_session(id, driver, options)
            .await
            .map_err(|error| self.with_stored_progress(&id, error))
    }

    async fn recover_session(
        &self,
        id: WorkflowId,
        driver: Option<&dyn WorkflowDriver>,
        options: &WorkflowRunOptions,
    ) -> Result<WorkflowProgressV1, WorkflowError> {
        check_options(options)?;
        let mut session = self.open(id, None)?;
        // A refused driver still reports the progress of the journal this call validated.
        let result =
            match driver.map(|driver| check_driver(driver, &session.journal.identity.driver)) {
                Some(Err(error)) => Err(error),
                Some(Ok(())) | None => {
                    self.drive(&mut session, driver, options, Mode::Recover)
                        .await
                }
            };
        session.finish(result)
    }

    /// Request cancellation of the workflow `id`.
    ///
    /// Local only: one compare-and-swap of the journal, serialized with dispatch
    /// and round intents. Returns the resulting progress; a workflow whose current
    /// step may still have external effect is `cancelling`.
    ///
    /// # Errors
    /// Storage, corruption and binding errors; `InvalidInput` when no journal exists.
    pub fn cancel_by_id(&self, id: WorkflowId) -> Result<WorkflowProgressV1, WorkflowError> {
        self.cancel_stored(id)
            .map_err(|error| self.with_stored_progress(&id, error))
    }

    fn cancel_stored(&self, id: WorkflowId) -> Result<WorkflowProgressV1, WorkflowError> {
        for _ in 0..CANCEL_STORE_ATTEMPTS {
            let Some((journal, stored)) = self.load(&id)? else {
                return Err(WorkflowError::new(
                    WorkflowErrorCode::InvalidInput,
                    WorkflowStage::Cancel,
                    "no journal exists for this workflow",
                ));
            };
            let mut next = journal.clone();
            if !next.request_cancel() {
                return Ok(journal.progress());
            }
            next.sequence += 1;
            next.updated_at_ms = self.clock.now_unix_ms();
            let record = next.encode_record()?;
            match self.storage.compare_and_store(&id, Some(&stored), &record) {
                Ok(()) => {
                    self.notify(&next);
                    return Ok(next.progress());
                }
                Err(error) if error.kind == WorkflowStorageErrorKind::Conflict => {}
                Err(error) => return Err(storage_error(&error).with_progress(journal.progress())),
            }
        }
        Err(WorkflowError::new(
            WorkflowErrorCode::JournalConflict,
            WorkflowStage::Cancel,
            "the journal kept changing while cancellation was being recorded",
        ))
    }

    /// Verify the stored journal of `id` and report its progress without any ledger call.
    ///
    /// # Errors
    /// Storage, corruption and binding errors.
    pub fn progress_by_id(
        &self,
        id: WorkflowId,
    ) -> Result<Option<WorkflowProgressV1>, WorkflowError> {
        Ok(self.load(&id)?.map(|(journal, _)| journal.progress()))
    }

    async fn drive(
        &self,
        session: &mut Session<'_>,
        driver: Option<&dyn WorkflowDriver>,
        options: &WorkflowRunOptions,
        mode: Mode,
    ) -> Result<(), WorkflowError> {
        let mut retransmitted = false;
        loop {
            if session.journal.native_payment_completion.is_some() {
                return Err(WorkflowError::new(
                    WorkflowErrorCode::UnsupportedOperation,
                    WorkflowStage::Reconcile,
                    "native payment business completion requires receipt re-verification; further dispatch is disabled",
                ));
            }
            let status = session.journal.status;
            if status.is_terminal() && mode == Mode::Recover {
                return Ok(());
            }
            match status {
                WorkflowStatusV1::Completed => return Ok(()),
                WorkflowStatusV1::Failed => return Err(failed_error(&session.journal)),
                WorkflowStatusV1::Cancelled => return Err(cancelled_error(&session.journal)),
                WorkflowStatusV1::InProgress | WorkflowStatusV1::Cancelling => {}
            }
            let Some(index) = session.journal.current_step() else {
                return Err(inconsistent_journal(0));
            };
            let read_only = mode == Mode::Recover || status == WorkflowStatusV1::Cancelling;
            let advanced = match session.journal.steps[index].descriptor.kind {
                StepKindV1::Transaction => {
                    self.advance_transaction(
                        session,
                        index,
                        driver,
                        options,
                        read_only,
                        &mut retransmitted,
                    )
                    .await?
                }
                StepKindV1::OffchainRound => {
                    self.advance_round(session, index, driver, read_only)
                        .await?
                }
            };
            if !advanced {
                // Nothing more can be established read-only.
                return if mode == Mode::Recover {
                    Ok(())
                } else if session.journal.steps[index].round.is_some() {
                    Err(round_pending_error(&session.journal, index))
                } else {
                    Err(session.unresolved_error(index))
                };
            }
        }
    }

    /// Advance a transaction step by one stage. Returns whether the state changed.
    async fn advance_transaction(
        &self,
        session: &mut Session<'_>,
        index: usize,
        driver: Option<&dyn WorkflowDriver>,
        options: &WorkflowRunOptions,
        read_only: bool,
        retransmitted: &mut bool,
    ) -> Result<bool, WorkflowError> {
        use TransactionStateV1 as S;
        let state = session.transaction_state(index);
        match state {
            // A persisted dispatch ordinal without a result is an unknown outcome.
            S::Submitting => {
                session.record(|journal| {
                    journal
                        .apply_transaction(index, TransactionInputV1::DispatchInterrupted)
                        .map(drop)
                })?;
                return Ok(true);
            }
            S::OutcomeUnknown | S::Pending => {
                return self
                    .observe(session, index, options, read_only, retransmitted)
                    .await;
            }
            _ if read_only => return Ok(false),
            _ => {}
        }
        let Some(driver) = driver else {
            return Ok(false);
        };
        match state {
            S::Planned => {
                session.commit(|journal| {
                    journal
                        .apply_transaction(index, TransactionInputV1::OpenAttempt)
                        .map(drop)
                })?;
            }
            S::Rejected => {
                if !options.retry_rejected_step {
                    return Err(closed_identity_error(&session.journal, index));
                }
                session.commit(|journal| {
                    journal
                        .apply_transaction(index, TransactionInputV1::OpenAttempt)
                        .map(drop)
                })?;
            }
            S::Prepared => {
                session.commit(|journal| {
                    journal
                        .apply_transaction(index, TransactionInputV1::BuildStarted)
                        .map(drop)
                })?;
            }
            S::Proving => self.build(session, index, driver).await?,
            S::ReadyToSign => self.sign(session, index).await?,
            S::Signed => self.dispatch_persisted(session, index, false).await?,
            // Handled above, or never the current step of a workflow that is not terminal.
            S::Submitting
            | S::OutcomeUnknown
            | S::Pending
            | S::Finalized
            | S::CancelledBeforeSubmission => return Err(inconsistent_journal(index)),
        }
        Ok(true)
    }

    async fn build(
        &self,
        session: &mut Session<'_>,
        index: usize,
        driver: &dyn WorkflowDriver,
    ) -> Result<(), WorkflowError> {
        let built = {
            let step = &session.journal.steps[index];
            let identity_ordinal = step
                .transaction
                .as_ref()
                .and_then(|operation| operation.current())
                .map_or(1, |attempt| attempt.ordinal);
            driver
                .build_transaction(StepContext {
                    workflow_id: session.id,
                    step_index: u32::try_from(index).unwrap_or(u32::MAX),
                    descriptor: &step.descriptor,
                    identity_ordinal,
                    journal: &session.journal,
                })
                .await
        };
        let failure = match built {
            Ok(built) => {
                let expected = session.journal.steps[index].descriptor.intent_digest;
                if built.intent_digest != expected {
                    WorkflowError::new(
                        WorkflowErrorCode::BindingMismatch,
                        WorkflowStage::Prove,
                        "the built payload implements another intent than the step is bound to",
                    )
                } else if built.unsigned_payload.len() > MAX_WORKFLOW_TRANSACTION_BYTES_V1 {
                    WorkflowError::limit(
                        WorkflowStage::Prove,
                        "transaction bytes",
                        built.unsigned_payload.len(),
                        MAX_WORKFLOW_TRANSACTION_BYTES_V1,
                    )
                } else if built.unsigned_payload.is_empty() {
                    WorkflowError::new(
                        WorkflowErrorCode::InvalidInput,
                        WorkflowStage::Prove,
                        "the built payload is empty",
                    )
                } else {
                    let payload = built.unsigned_payload;
                    session.commit(move |journal| {
                        journal
                            .apply_transaction(index, TransactionInputV1::PayloadBuilt { payload })
                            .map(drop)
                    })?;
                    return Ok(());
                }
            }
            Err(failure) => failure.into_error(WorkflowStage::Prove, index),
        };
        // No payload exists: return the identity slot to `prepared` so a later run rebuilds.
        if session.transaction_state(index) == TransactionStateV1::Proving {
            session.commit(|journal| {
                journal
                    .apply_transaction(index, TransactionInputV1::BuildFailed)
                    .map(drop)
            })?;
        }
        Err(failure.with_step(index))
    }

    async fn sign(&self, session: &mut Session<'_>, index: usize) -> Result<(), WorkflowError> {
        let payload = session.journal.steps[index]
            .transaction
            .as_ref()
            .and_then(|operation| operation.unsigned_payload.clone())
            .ok_or_else(|| inconsistent_journal(index))?;
        let signed = self
            .account
            .sign(&payload)
            .await
            .map_err(|failure| failure.into_error(WorkflowStage::Sign, index))?;
        let recomputed = self
            .account
            .identify(&signed.signed_transaction)
            .map_err(|failure| failure.into_error(WorkflowStage::Sign, index))?;
        if recomputed != signed.identity {
            return Err(WorkflowError::new(
                WorkflowErrorCode::BindingMismatch,
                WorkflowStage::Sign,
                "the signer reported an identity its bytes do not hash to",
            )
            .with_step(index));
        }
        session.commit(move |journal| {
            journal
                .apply_transaction(
                    index,
                    TransactionInputV1::Signed {
                        signed_transaction: signed.signed_transaction,
                        identity: signed.identity,
                    },
                )
                .map(drop)
        })?;
        Ok(())
    }

    /// Persist the dispatch ordinal, send the exact persisted bytes once and record the result.
    async fn dispatch_persisted(
        &self,
        session: &mut Session<'_>,
        index: usize,
        retransmission: bool,
    ) -> Result<(), WorkflowError> {
        // The ordinal is durable before any byte leaves. A runner that loses this
        // compare-and-swap (to a cancellation) sends nothing. A never-admitted identity
        // always has a dispatch left; a retransmission is offered only within the bound.
        let stored = session.commit(|journal| {
            journal
                .apply_transaction(
                    index,
                    TransactionInputV1::DispatchIntent {
                        retransmission_after_exact_absence: retransmission,
                    },
                )
                .map(drop)
        })?;
        if stored == Stored::Reloaded {
            return Ok(());
        }
        let retained = session.journal.steps[index]
            .transaction
            .as_ref()
            .and_then(|operation| {
                Some((
                    operation.signed_transaction.clone()?,
                    operation.current_identity()?,
                ))
            });
        let Some((bytes, identity)) = retained else {
            return Err(inconsistent_journal(index));
        };
        let outcome = self.ledger.dispatch(&bytes, &identity).await;
        let (input, not_admitted) = match outcome {
            DispatchOutcome::Accepted => (TransactionInputV1::DispatchAccepted, None),
            DispatchOutcome::AlreadyKnown => (TransactionInputV1::DispatchAlreadyKnown, None),
            DispatchOutcome::Ambiguous { .. } => (TransactionInputV1::DispatchAmbiguous, None),
            DispatchOutcome::Refused { detail } => {
                (TransactionInputV1::DispatchRefused { detail }, None)
            }
            DispatchOutcome::NotAdmitted { code, detail } => (
                TransactionInputV1::DispatchNotAdmitted,
                Some((code, detail)),
            ),
        };
        session.record(|journal| journal.apply_transaction(index, input.clone()).map(drop))?;
        if let Some((code, detail)) = not_admitted {
            // With no earlier possible admission the bytes are back in `signed` and the
            // ordinal is released: the caller sees the cause and may run again any number
            // of times. A cancellation that won meanwhile has dropped the bytes instead.
            if session.transaction_state(index) == TransactionStateV1::Signed {
                return Err(WorkflowError::new(code, WorkflowStage::Submit, detail)
                    .with_step(index)
                    .with_transaction(Some(identity)));
            }
        }
        Ok(())
    }

    /// Reconcile an unresolved identity by read-only queries. Returns whether it changed state.
    async fn observe(
        &self,
        session: &mut Session<'_>,
        index: usize,
        options: &WorkflowRunOptions,
        read_only: bool,
        retransmitted: &mut bool,
    ) -> Result<bool, WorkflowError> {
        let started = self.clock.now_unix_ms();
        let timeout = duration_ms(options.observation_timeout);
        let interval = duration_ms(options.poll_interval);
        let mut bound_exhausted = false;
        loop {
            let identity = session
                .identity(index)
                .ok_or_else(|| inconsistent_journal(index))?;
            let outcome = self.ledger.committed_outcome(&identity).await;
            let input = match outcome {
                CommittedOutcome::Applied { block_height } => {
                    Some(TransactionInputV1::ReconciledApplied { block_height })
                }
                CommittedOutcome::Rejected { detail } => {
                    Some(TransactionInputV1::ReconciledRejected { detail })
                }
                CommittedOutcome::Expired => Some(TransactionInputV1::ReconciledExpired),
                CommittedOutcome::ObservedNotFinal => {
                    if session.transaction_state(index) == TransactionStateV1::OutcomeUnknown {
                        session.record(|journal| {
                            journal
                                .apply_transaction(index, TransactionInputV1::ObservedInPipeline)
                                .map(drop)
                        })?;
                    }
                    None
                }
                CommittedOutcome::ExactAbsence => {
                    let dispatches_remain = session.journal.steps[index]
                        .transaction
                        .as_ref()
                        .and_then(|operation| operation.current())
                        .is_some_and(|attempt| {
                            attempt.dispatch_ordinal < MAX_DISPATCHES_PER_IDENTITY_V1
                        });
                    // The only permitted re-dispatch: the exact persisted bytes, explicitly
                    // authorized, after this fresh exact-absence read, once per call and
                    // within the dispatch bound.
                    let authorized =
                        !read_only && options.retransmit_identical_bytes && !*retransmitted;
                    if authorized && dispatches_remain {
                        *retransmitted = true;
                        self.dispatch_persisted(session, index, true).await?;
                        return Ok(true);
                    }
                    // The caller asked for a retransmission the bound no longer allows.
                    bound_exhausted |= authorized;
                    None
                }
                CommittedOutcome::ReadFailed { .. } => None,
            };
            if let Some(input) = input {
                // Terminal evidence is durable before the workflow advances.
                session
                    .record(|journal| journal.apply_transaction(index, input.clone()).map(drop))?;
                return Ok(true);
            }
            let elapsed = self.clock.now_unix_ms().saturating_sub(started);
            if elapsed.saturating_add(interval) > timeout {
                if bound_exhausted {
                    // Still unresolved, and reads remain the only way forward: the error
                    // keeps its unresolved code and states the exhausted bound.
                    let mut error = session.unresolved_error(index);
                    error.bounds = Some(WorkflowBounds {
                        actual: u64::from(MAX_DISPATCHES_PER_IDENTITY_V1),
                        maximum: u64::from(MAX_DISPATCHES_PER_IDENTITY_V1),
                    });
                    error.detail.push_str(
                        "; the authorized retransmission was not sent because the dispatch \
                         bound of this identity is exhausted",
                    );
                    return Err(error);
                }
                return Ok(false);
            }
            self.clock.sleep(options.poll_interval).await;
        }
    }

    /// Advance a round step. Returns whether the state changed.
    async fn advance_round(
        &self,
        session: &mut Session<'_>,
        index: usize,
        driver: Option<&dyn WorkflowDriver>,
        read_only: bool,
    ) -> Result<bool, WorkflowError> {
        let step_index = u32::try_from(index).unwrap_or(u32::MAX);
        let round_id = round_identity(&session.id, step_index);
        let state = session.journal.steps[index]
            .round
            .as_ref()
            .map_or(RoundStateV1::Planned, |round| round.state);
        let Some(driver) = driver else {
            // Read-only recovery without the capability driver cannot recover a round.
            return Ok(false);
        };
        let report = match state {
            RoundStateV1::Planned => {
                if read_only {
                    return Ok(false);
                }
                // The round identity is durable before the driver starts the round.
                let stored = session.commit(|journal| {
                    journal
                        .apply_round(index, RoundInputV1::Intent { round_id })
                        .map(drop)
                })?;
                if stored == Stored::Reloaded {
                    return Ok(true);
                }
                driver
                    .start_round(round_context(session, index, round_id))
                    .await
            }
            RoundStateV1::RoundStarted | RoundStateV1::RoundWaiting => {
                let recovery = driver
                    .recover_round(round_context(session, index, round_id))
                    .await
                    .map_err(|failure| failure.into_error(WorkflowStage::Round, index))?;
                match recovery {
                    RoundRecovery::Found(report) => Ok(report),
                    RoundRecovery::NotStarted if state == RoundStateV1::RoundWaiting => {
                        return Err(WorkflowError::new(
                            WorkflowErrorCode::BindingMismatch,
                            WorkflowStage::Round,
                            "a round recorded as waiting was reported as never started",
                        )
                        .with_step(index));
                    }
                    RoundRecovery::NotStarted
                        if session.journal.status == WorkflowStatusV1::Cancelling =>
                    {
                        session.record(|journal| {
                            journal
                                .apply_round(index, RoundInputV1::NotStarted)
                                .map(drop)
                        })?;
                        return Ok(true);
                    }
                    RoundRecovery::NotStarted if read_only => return Ok(false),
                    // Never started: start it under the same persisted identity. The
                    // restart intent is durable first, exactly like the first intent: the
                    // answer above was obtained from a journal that a cancellation may have
                    // replaced while the recovery was in flight, and a runner that loses
                    // this compare-and-swap starts nothing.
                    RoundRecovery::NotStarted => {
                        let stored = session.commit(|journal| {
                            journal
                                .apply_round(index, RoundInputV1::RestartIntent)
                                .map(drop)
                        })?;
                        if stored == Stored::Reloaded {
                            return Ok(true);
                        }
                        driver
                            .start_round(round_context(session, index, round_id))
                            .await
                    }
                }
            }
            // A completed round is never current and a failed one ends the workflow.
            RoundStateV1::RoundCompleted | RoundStateV1::RoundFailed => {
                return Err(inconsistent_journal(index));
            }
        };
        let report = report.map_err(|failure| failure.into_error(WorkflowStage::Round, index))?;
        let context_digest = session.journal.steps[index].descriptor.intent_digest;
        let bound = move |status: &RoundStatusReport| {
            if status.round_id != round_id {
                Err("the report belongs to another round")
            } else if status.context_digest != context_digest {
                Err("the round context differs from the context the step is bound to")
            } else {
                Ok(())
            }
        };
        let report = if !read_only
            && driver.supports_round_continuation()
            && matches!(
                state,
                RoundStateV1::RoundStarted | RoundStateV1::RoundWaiting
            )
            && session.journal.status != WorkflowStatusV1::Cancelling
        {
            if let RoundReport::Waiting(status) = report {
                bound(&status).map_err(|detail| round_binding_error(index, detail))?;
                let participants = status.participants.clone();
                let stored = session.commit(|journal| {
                    journal
                        .apply_round(
                            index,
                            RoundInputV1::Waiting {
                                participants: participants.clone(),
                            },
                        )
                        .map(drop)
                })?;
                if stored == Stored::Reloaded {
                    return Ok(true);
                }
                driver
                    .continue_round(round_context(session, index, round_id), status)
                    .await
                    .map_err(|failure| failure.into_error(WorkflowStage::Round, index))?
            } else {
                report
            }
        } else {
            report
        };
        let input = match report {
            RoundReport::Completed {
                status,
                transcript,
                custody_handles,
            } => {
                bound(&status).map_err(|detail| round_binding_error(index, detail))?;
                RoundInputV1::Completed {
                    participants: status.participants,
                    transcript,
                    custody_handles,
                }
            }
            RoundReport::Waiting(status) => {
                bound(&status).map_err(|detail| round_binding_error(index, detail))?;
                let unchanged = session.journal.steps[index]
                    .round
                    .as_ref()
                    .is_some_and(|round| {
                        round.state == RoundStateV1::RoundWaiting
                            && round.participants == status.participants
                    });
                if !unchanged {
                    let participants = status.participants;
                    session.record(|journal| {
                        journal
                            .apply_round(
                                index,
                                RoundInputV1::Waiting {
                                    participants: participants.clone(),
                                },
                            )
                            .map(drop)
                    })?;
                }
                return Ok(false);
            }
            RoundReport::Failed { code, .. } => RoundInputV1::Failed { code },
        };
        session.record(|journal| journal.apply_round(index, input.clone()).map(drop))?;
        Ok(true)
    }
}

fn round_context<'a>(
    session: &'a Session<'_>,
    index: usize,
    round_id: Digest32,
) -> RoundContext<'a> {
    RoundContext {
        workflow_id: session.id,
        step_index: u32::try_from(index).unwrap_or(u32::MAX),
        descriptor: &session.journal.steps[index].descriptor,
        round_id,
        journal: &session.journal,
    }
}

/// A validated journal never reaches this: the step state contradicts the workflow status.
fn inconsistent_journal(index: usize) -> WorkflowError {
    WorkflowError::new(
        WorkflowErrorCode::StorageCorrupted,
        WorkflowStage::Load,
        "the journal step state contradicts the workflow status",
    )
    .with_step(index)
}

fn round_binding_error(index: usize, detail: &str) -> WorkflowError {
    WorkflowError::new(
        WorkflowErrorCode::BindingMismatch,
        WorkflowStage::Round,
        detail,
    )
    .with_step(index)
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn check_options(options: &WorkflowRunOptions) -> Result<(), WorkflowError> {
    if options.poll_interval.is_zero() {
        return Err(WorkflowError::new(
            WorkflowErrorCode::InvalidInput,
            WorkflowStage::Plan,
            "poll_interval must be greater than zero",
        ));
    }
    Ok(())
}

fn check_driver(
    driver: &dyn WorkflowDriver,
    expected: &DriverIdentityV1,
) -> Result<(), WorkflowError> {
    if &driver.identity() != expected {
        return Err(WorkflowError::new(
            WorkflowErrorCode::BindingMismatch,
            WorkflowStage::Plan,
            "the capability driver is not the one the plan is bound to",
        ));
    }
    Ok(())
}

fn current_identity(journal: &WorkflowJournalV1, index: usize) -> Option<TransactionIdentityV1> {
    journal.steps[index]
        .transaction
        .as_ref()
        .and_then(super::journal::TransactionOperationV1::current_identity)
}

/// Error of a transaction step whose latest identity is closed while identities remain.
fn closed_identity_error(journal: &WorkflowJournalV1, index: usize) -> WorkflowError {
    use super::contract::AttemptEvidenceKindV1 as Evidence;
    let evidence = journal.steps[index]
        .transaction
        .as_ref()
        .and_then(|operation| operation.current())
        .and_then(|attempt| attempt.evidence.as_ref());
    let (code, stage) = match evidence.map(|evidence| evidence.kind) {
        Some(Evidence::LedgerExpired) => (WorkflowErrorCode::Expired, WorkflowStage::Reconcile),
        Some(Evidence::AdmissionRefused) => (WorkflowErrorCode::Rejected, WorkflowStage::Submit),
        _ => (WorkflowErrorCode::Rejected, WorkflowStage::Reconcile),
    };
    WorkflowError::new(
        code,
        stage,
        evidence.map_or_else(String::new, |evidence| evidence.detail.clone()),
    )
    .with_step(index)
    .with_transaction(current_identity(journal, index))
}

fn failed_error(journal: &WorkflowJournalV1) -> WorkflowError {
    let index = journal.failure_step.map_or(0, |step| step as usize);
    let code = journal.failure_code.unwrap_or(WorkflowErrorCode::Rejected);
    if journal
        .steps
        .get(index)
        .is_some_and(|step| step.round.is_some())
    {
        return WorkflowError::new(code, WorkflowStage::Round, "the off-chain round failed")
            .with_step(index);
    }
    let mut error = closed_identity_error(journal, index);
    error.code = code;
    error
}

fn cancelled_error(journal: &WorkflowJournalV1) -> WorkflowError {
    let current = journal.current_step();
    let step = current.map(|index| &journal.steps[index]);
    let closed = step
        .and_then(|step| step.transaction.as_ref())
        .is_some_and(|operation| operation.state == TransactionStateV1::Rejected);
    let detail = if closed {
        "the workflow was cancelled; the closed transaction identity of the current step was not replaced and earlier progress is not rolled back"
    } else if step.is_some_and(|step| step.round.is_some()) {
        "the workflow was cancelled; the current round was not completed and earlier progress is not rolled back"
    } else {
        "the workflow was cancelled; the current step was not submitted and earlier progress is not rolled back"
    };
    let error = WorkflowError::new(
        WorkflowErrorCode::CancelledBeforeSubmission,
        WorkflowStage::Cancel,
        detail,
    );
    match current {
        Some(index) => error.with_step(index),
        None => error,
    }
}

fn round_pending_error(journal: &WorkflowJournalV1, index: usize) -> WorkflowError {
    let step = &journal.steps[index];
    let received = step
        .round
        .as_ref()
        .map_or(0, |round| round.participants.len());
    WorkflowError::new(
        WorkflowErrorCode::RoundPending,
        WorkflowStage::Round,
        format!(
            "the off-chain round is unresolved: {received} of {} required participants recorded",
            step.descriptor.participants_required
        ),
    )
    .with_step(index)
}

impl WorkflowHandle {
    /// Read the existing engine-owned journal without granting receipt authority.
    pub(crate) fn journal_snapshot(&self) -> Result<Option<WorkflowJournalV1>, WorkflowError> {
        Ok(self.engine.load(&self.id)?.map(|(journal, _)| journal))
    }

    /// Record an already verified business outcome under the engine's runner lease and CAS.
    /// The concrete carrier state is left intact, including a rejected duplicate carrier.
    pub(crate) fn record_native_payment_completion(
        &self,
        completion: NativePaymentCompletionV1,
    ) -> Result<WorkflowProgressV1, WorkflowError> {
        let mut session = self.engine.open(self.id, Some(&self.plan))?;
        if session.journal.native_payment_completion.as_ref() == Some(&completion) {
            return Ok(session.journal.progress());
        }
        session.record(|journal| {
            if journal
                .native_payment_completion
                .as_ref()
                .is_some_and(|stored| stored != &completion)
            {
                return Err(WorkflowError::new(
                    WorkflowErrorCode::BindingMismatch,
                    WorkflowStage::Store,
                    "native payment already binds another business completion",
                ));
            }
            journal.native_payment_completion = Some(completion.clone());
            Ok(())
        })?;
        Ok(session.journal.progress())
    }

    /// The workflow identifier.
    #[must_use]
    pub const fn id(&self) -> WorkflowId {
        self.id
    }

    /// The plan this handle is bound to.
    #[must_use]
    pub const fn plan(&self) -> &WorkflowPlanV1 {
        &self.plan
    }

    /// Start or resume the workflow and run it as far as it can go.
    ///
    /// Returns the progress of a completed workflow. Every other result is a
    /// typed error whose progress states what is confirmed, unresolved and not
    /// started. A resumed workflow first reconciles the committed outcome of its
    /// interrupted transaction identity by read-only queries.
    ///
    /// # Errors
    /// Every code of the contract; see [`WorkflowErrorCode`].
    pub async fn run(
        &self,
        driver: &dyn WorkflowDriver,
        options: &WorkflowRunOptions,
    ) -> Result<WorkflowProgressV1, WorkflowError> {
        self.run_session(driver, options)
            .await
            .map_err(|error| self.engine.with_stored_progress(&self.id, error))
    }

    async fn run_session(
        &self,
        driver: &dyn WorkflowDriver,
        options: &WorkflowRunOptions,
    ) -> Result<WorkflowProgressV1, WorkflowError> {
        check_options(options)?;
        check_driver(driver, &self.plan.driver)?;
        let mut session = self.engine.open(self.id, Some(&self.plan))?;
        let result = self
            .engine
            .drive(&mut session, Some(driver), options, Mode::Run)
            .await;
        session.finish(result)
    }

    /// Read-only recovery; see [`WorkflowEngine::recover_by_id`].
    ///
    /// # Errors
    /// Storage, corruption and binding errors.
    pub async fn recover(
        &self,
        driver: Option<&dyn WorkflowDriver>,
        options: &WorkflowRunOptions,
    ) -> Result<WorkflowProgressV1, WorkflowError> {
        self.engine.recover_by_id(self.id, driver, options).await
    }

    /// Request cancellation; see [`WorkflowEngine::cancel_by_id`].
    ///
    /// # Errors
    /// Storage, corruption and binding errors.
    pub fn cancel(&self) -> Result<WorkflowProgressV1, WorkflowError> {
        self.engine.cancel_by_id(self.id)
    }

    /// Verified local progress; see [`WorkflowEngine::progress_by_id`].
    ///
    /// # Errors
    /// Storage, corruption and binding errors.
    pub fn progress(&self) -> Result<Option<WorkflowProgressV1>, WorkflowError> {
        self.engine.progress_by_id(self.id)
    }
}
