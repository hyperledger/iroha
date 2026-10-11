//! The node's executor for the Sumeragi driver: executes blocks on the committed [`State`],
//! applies committed blocks and builds payloads (`specs/sumeragi.md` §4, §6.10, §12.2,
//! §12.3 O3/O4).
//!
//! State allows one writer at a time and an executed overlay borrows the state, so all work
//! runs on one dedicated thread that owns the state and keeps at most **one live overlay**
//! (the most recent execution). [`StateExecutor`] is the driver-facing handle: it forwards
//! each call to that thread and waits for the answer.
//!
//! - `execute` runs only on the applied tip (the core requests an execution once its parent's
//!   `CommitBlock` was emitted, and the driver applies in order); otherwise it answers `None`
//!   and the driver parks the request (never `Failed` for that).
//! - A local condition (storage, admission, a panic) is `Failed` and retried; everything else
//!   the validator rejects is `Invalid` — a deterministic verdict every honest node reaches.
//! - `prepare` pins the original matching overlay, capture and one certified staged frame until
//!   publication. A missing speculative overlay may execute again only before preparation.
//! - `commit` retains that owner on reversible durable-authorization refusal. Once the one-shot
//!   State apply begins, any failure requires recovery; the worker cannot re-execute or retry
//!   partially consumed publication. Successful repeated completion emits no duplicate events.

/// Move-only authority issued inside the original native execution worker.
/// No decoder, clone or public constructor can recreate this proof of origin.
pub(crate) struct NativeExecutionAuthorization {
    state: usize,
    tip: crate::state::native_execution_tip::NativeExecutionTipRecord,
    parent: Option<(Hash32, Hash32)>,
    telemetry_origin: CommitTelemetryOrigin,
}

/// Local observations of an authenticated execution; never protocol authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitTelemetryOrigin {
    /// A newly committed execution emits its transition observations once.
    Forward,
    /// Startup re-execution restores gauges without recounting historical transitions.
    HistoricalReplay,
}
impl NativeExecutionAuthorization {
    /// The startup module can transfer only its own original signed-genesis execution.
    pub(super) fn from_genesis(original: super::startup::GenesisExecutionAuthorization) -> Self {
        let (state, tip, telemetry_origin) = original.into_parts();
        Self {
            state,
            tip,
            parent: None,
            telemetry_origin,
        }
    }

    /// Observe the local origin retained beside this exact execution authorization.
    pub(crate) fn telemetry_origin(&self) -> CommitTelemetryOrigin {
        self.telemetry_origin
    }

    /// Return fixed claims only for the exact State that owns the execution.
    pub(crate) fn for_state(
        &self,
        state: &State,
    ) -> Result<
        (
            crate::state::native_execution_tip::NativeExecutionTipRecord,
            Option<(Hash32, Hash32)>,
        ),
        String,
    > {
        if self.state != std::ptr::from_ref(state) as usize {
            return Err("native execution authorization belongs to another State".into());
        }
        Ok((self.tip, self.parent))
    }
}

use std::{
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, mpsc},
    thread::JoinHandle,
    time::Duration,
};

use iroha_data_model::{
    account::AccountId,
    block::{BlockHeader as IrohaHeader, CommitCertificate, SignedBlock},
    events::EventBox,
    parameter::system::ConsensusMode,
    transaction::TransactionEntrypoint,
};
use iroha_model_base::peer::PeerId;
use iroha_sumeragi::{
    api::{ApplicationControlContext, ControlWitnessContext, ExecOutcome},
    availability::{AvailabilityFrame, AvailableBody, PayloadBytes},
    message::{ApplicationControl, Qc},
    types::{AppliedConfig, ControlWitness, Hash32, PublicKey},
};

use super::{
    block_store::{StagedBlock, Staging},
    commitment::{
        ExecutionResultCommitment, encode_result_preimage, execution_result, result_of_preimage,
    },
    driver::traits::{Executor, PublicationDeferral, PublicationError},
    lanes,
    network_topology::Topology,
    payload::{self, Assembly},
    schedule::{self, NativeExecutionInputs},
};
use crate::{
    EventsSender,
    block::{BlockValidationError, CommittedBlock, ValidBlock},
    query::native_context_archive::{
        NativeContextArchive, NativeContextArchiveError, PreparedNativeContext,
    },
    queue::Queue,
    state::{
        NativeLaneStateProof, NativeLaneStateProofError, State, StateBlock, StateReadOnly,
        WorldReadOnly,
    },
};

/// Borrow only a retryable refusal while the original shared proof error stays in its phase.
/// Invalid source, encoder failures and scratch demand above the hard pool ceiling remain recovery.
fn original_lane_proof_deferral(
    error: &NativeLaneStateProofError,
) -> Option<crate::execution_attempt::ExecutionDeferred> {
    if !error.is_local_refusal() {
        return None;
    }
    match error {
        NativeLaneStateProofError::Scratch(original) => Some(preparation::buffer_refusal(original)),
        NativeLaneStateProofError::Decode(original) => {
            crate::execution_attempt::canonical_decode_deferral(original)
        }
        _ => None,
    }
}

/// Payload bytes kept free for the block's non-transaction fields when selecting. The data
/// model owns the reserve so queue admission and SDK preflight use the same value.
const PAYLOAD_OVERHEAD: usize =
    iroha_data_model::parameter::system::BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES as usize;

/// What the executor thread needs.
#[derive(Clone)]
pub struct ExecutorContext {
    /// The node's state.
    pub state: Arc<State>,
    /// Mandatory original-pool archive of complete context values from each native execution.
    pub native_context_archive: Arc<NativeContextArchive>,
    /// The transaction queue (peeked by the builder, cleaned after apply); `None` until the
    /// node attaches it ([`StateExecutor::attach_queue`]), e.g. during startup replay.
    pub queue: Option<Arc<Queue>>,
    /// Hand-off of executed blocks to the block store.
    pub staging: Staging,
    /// Pipeline and state events of applied blocks.
    pub events: EventsSender,
    /// The genesis account.
    pub genesis_account: AccountId,
    /// The chain's consensus mode.
    pub consensus_mode: ConsensusMode,
    /// The applied tip: its height and core block hash.
    pub applied: (u64, Hash32),
    /// The driver's cryptography: the keys of each newly scheduled committee are admitted
    /// (their proofs of possession verified) as blocks commit.
    pub crypto: Option<Arc<super::crypto::BlsCrypto>>,
    /// The applied tip published to the node's lane instances (`specs/sumeragi_lanes.md` §3.2).
    pub applied_watch: Arc<crate::sumeragi::lanes::global::AppliedWatch>,
    /// The node's committed lane blocks, which merged global blocks execute (§4.3).
    pub lane_blocks: Arc<dyn crate::sumeragi::lanes::merge::LaneBlockSource>,
}

/// Configured SoraFS archives captured from the exact committed State before apply completes.
///
/// The executor is their single capture producer. A failed capture keeps the committed decision
/// pending, so the driver cannot acknowledge it or advance to another height before recovery.
#[derive(Clone, Default)]
pub struct FinalizedArchives {
    /// Finalized provider assignments and completions.
    pub provider_ingest:
        Option<Arc<crate::query::provider_ingest_finalized::ProviderIngestFinalizedArchiveV1>>,
    /// Finalized provider reputation state.
    pub reputation: Option<Arc<crate::query::reputation_finalized::ReputationFinalizedArchive>>,
}

impl FinalizedArchives {
    fn capture(&self, view: &impl StateReadOnly) -> Result<(), PublicationError> {
        use crate::query::{
            provider_ingest_finalized::ProviderIngestFinalizedArchiveErrorV1 as ProviderError,
            reputation_finalized::ReputationFinalizedArchiveError as ReputationError,
        };
        if let Some(archive) = &self.provider_ingest {
            archive
                .capture_certified_view(view, view.kura())
                .map_err(|error| match error {
                    ProviderError::Deferred(original) => {
                        archive_publication_deferral(original.into())
                    }
                    ProviderError::IndexBusy { wait } => {
                        archive_publication_deferral(PublicationDeferral::ProviderArchiveBusy(wait))
                    }
                    error => PublicationError::Retryable(format!(
                        "provider-ingest archive capture failed: {error}"
                    )),
                })?;
        }
        if let Some(archive) = &self.reputation {
            archive
                .capture_certified_view(view, view.kura())
                .map_err(|error| match error {
                    ReputationError::Deferred(original) => {
                        archive_publication_deferral(original.into())
                    }
                    ReputationError::IndexBusy { wait } => archive_publication_deferral(
                        PublicationDeferral::ReputationArchiveBusy(wait),
                    ),
                    error => PublicationError::Retryable(format!(
                        "reputation archive capture failed: {error}"
                    )),
                })?;
        }
        Ok(())
    }
}

fn archive_publication_deferral(original: PublicationDeferral) -> PublicationError {
    // HC64: a diagnostic must not replace the actual history pool or index release owner.
    if cfg!(all(test, sumeragi_core_mutation = "HC64")) {
        PublicationError::Retryable(original.to_string())
    } else {
        PublicationError::Deferred(original)
    }
}

/// One State publication awaiting durable archive capture and its remaining notifications.
struct PendingCommit {
    telemetry_origin: CommitTelemetryOrigin,
    native_contexts: PreparedNativeContext,
    archive_refusal: Option<PublicationDeferral>,
    header: iroha_sumeragi::message::BlockHeader,
    availability: AvailabilityFrame,
    source: iroha_sumeragi::availability::AvailabilitySource,
    qc: Qc,
    state_hash: iroha_crypto::HashOf<IrohaHeader>,
    next: AppliedConfig,
    hashes: Vec<iroha_crypto::HashOf<TransactionEntrypoint>>,
    events: Vec<EventBox>,
}

impl PendingCommit {
    fn matches(&self, block: &AvailableBody, qc: &Qc) -> bool {
        self.header == *block.header()
            && self.availability == *block.availability()
            && self.source == *block.source()
            && self.qc == *qc
    }
}

/// Read-only original witness inspection with an explicit reconstructed-tamper seam.
/// The testing control cannot extract or mutate charged original wire allocations.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub struct WitnessInspection<'borrow>(&'borrow mut crate::state::CapturedExecWitness);
#[cfg(any(test, feature = "iroha-core-tests"))]
impl WitnessInspection<'_> {
    /// Borrow the wire currently offered to the same native production checks.
    pub fn wire(&self) -> &iroha_data_model::block::consensus::ExecWitness {
        self.0.wire()
    }
    /// Reconstruct and alter an offered wire, retaining the funded original separately.
    /// This test injection never lends mutable original buffers or creates authority.
    pub fn offer_reconstructed_tamper(
        &mut self,
        alter: impl FnOnce(&mut iroha_data_model::block::consensus::ExecWitness),
    ) {
        self.0.offer_reconstructed_tamper_for_test(alter);
    }
}
#[cfg(any(test, feature = "iroha-core-tests"))]
impl std::ops::Deref for WitnessInspection<'_> {
    type Target = iroha_data_model::block::consensus::ExecWitness;
    fn deref(&self) -> &Self::Target {
        self.wire()
    }
}

/// Borrowed original Worker execution for component assertions and refusal controls.
///
/// This view grants no certificate or publication capability. Mutating any sealed source
/// makes the production preparation boundary reject that same retained execution.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub struct PendingExecutionView<'borrow, 'state> {
    /// The exact originally executed carrier before a certificate is attached.
    pub block: &'borrow mut ValidBlock,
    /// The original overlay retained by the Worker.
    pub state: &'borrow mut StateBlock<'state>,
    /// The exact witness retained with the original R.
    pub witness: WitnessInspection<'borrow>,
}

/// Immutable observation of the actual certificate-authorized publication overlay.
/// No source mutation or publication capability is exposed by this test view.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub struct PreparedExecutionView<'borrow, 'state> {
    /// The exact originally executed carrier with its native certificate.
    pub block: &'borrow CommittedBlock,
    /// The original prepared overlay whose projected snapshot will be published.
    pub state: &'borrow StateBlock<'state>,
    /// The original execution witness, retained with certified R.
    pub witness: &'borrow iroha_data_model::block::consensus::ExecWitness,
}

#[cfg(any(test, feature = "iroha-core-tests"))]
type PreparedInspection = Box<
    dyn for<'borrow, 'state> FnOnce(Result<PreparedExecutionView<'borrow, 'state>, String>) + Send,
>;

#[cfg(any(test, feature = "iroha-core-tests"))]
type PendingInspection = Box<
    dyn for<'borrow, 'state> FnOnce(Result<PendingExecutionView<'borrow, 'state>, String>) + Send,
>;

enum Request {
    TakeFinalizedFastpqSource(
        super::certified_chain::AuthenticatedExecutionBlock,
        mpsc::SyncSender<Result<crate::fastpq::finalized_source::FinalizedFastpqSource, String>>,
    ),
    #[cfg(test)]
    PreparePublicationForInspection(AvailableBody, Qc, mpsc::SyncSender<Result<(), String>>),
    #[cfg(any(test, feature = "iroha-core-tests"))]
    InspectPending(Hash32, PendingInspection),
    #[cfg(any(test, feature = "iroha-core-tests"))]
    InspectPrepared(Hash32, PreparedInspection),
    Execute(AvailableBody, Hash32, mpsc::SyncSender<Option<ExecOutcome>>),
    Discard(u64, Vec<Hash32>),
    Prepare(
        AvailableBody,
        Qc,
        CommitTelemetryOrigin,
        mpsc::SyncSender<Result<Option<Hash32>, PublicationError>>,
    ),
    Commit(
        AvailableBody,
        Qc,
        mpsc::SyncSender<Result<AppliedConfig, PublicationError>>,
    ),
    Replay(
        AvailableBody,
        Qc,
        mpsc::SyncSender<Result<(), PublicationError>>,
    ),
    Build(
        u64,
        u64,
        u32,
        u32,
        mpsc::SyncSender<Result<Option<PayloadBytes>, PublicationError>>,
    ),
    BuildControl(
        ControlWitnessContext,
        mpsc::SyncSender<Result<ControlWitness, PublicationError>>,
    ),
    DriveControl(
        ApplicationControlContext,
        mpsc::SyncSender<Result<Option<ApplicationControl>, PublicationError>>,
    ),
    ReceiveControl(
        PublicKey,
        ApplicationControl,
        mpsc::SyncSender<Result<(), PublicationError>>,
    ),
    AttachBeacon {
        instance: Hash32,
        local_bls: Option<[u8; 48]>,
        signer: Option<Arc<dyn crate::beacon::GlobalThresholdBeaconPartialSignerV1>>,
        reply: mpsc::SyncSender<
            Result<super::epoch_beacon::producer::NativeBeaconReadiness, PublicationError>,
        >,
    },
    Reject(u64, u64, Hash32),
    AttachQueue(Arc<Queue>),
    AttachFinalizedArchives(FinalizedArchives, mpsc::SyncSender<Result<(), String>>),
}

/// Only the exact verified frame and payload from this State pool may enter execution.
fn require_body_admission(
    body: &AvailableBody,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<(), PublicationError> {
    if !body.admitted_to(budget) {
        return Err(PublicationError::RecoveryRequired(
            "available body belongs to another State pool".into(),
        ));
    }
    Ok(())
}

/// The driver-facing owner of the executor thread.
///
/// Dropping a caller-owned handle closes request admission and waits for the original worker
/// to finish accepted work and release its State, storage and archive owners. Constructors
/// never give the worker a request sender or this handle, and synchronous calls retain the
/// handle through their reply. Defensive self-destruction closes admission without joining
/// the current thread; canonical callers cannot transfer their borrowed owner that way.
pub struct StateExecutor {
    /// The same pool as the worker, checked before retaining a queued certificate.
    execution_budget: iroha_allocation::AllocationBudget,
    requests: Option<mpsc::SyncSender<Request>>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for StateExecutor {
    fn drop(&mut self) {
        // Disconnect before joining: both receive paths stop after the original queued
        // requests drain. No request cancellation, publication shortcut or new signal is used.
        drop(self.requests.take());
        if let Some(thread) = self.thread.take() {
            if thread.thread().id() == std::thread::current().id() {
                // Canonical callers never move the owner into its worker. If a private
                // callback does so, its current stack must return before the worker can exit.
                // Closing admission is still necessary; joining ourselves would deadlock.
                return;
            }
            if thread.join().is_err() {
                iroha_logger::error!("sumeragi state executor panicked during shutdown");
            }
        }
    }
}

impl StateExecutor {
    /// Move the one already-published original witness to complete-effect work.
    /// The caller must retain actual native execution authority; this performs no
    /// proof dispatch and accepts no advertised roots or replacement witness.
    pub(crate) fn take_finalized_fastpq_source(
        &self,
        native: super::certified_chain::AuthenticatedExecutionBlock,
    ) -> Result<crate::fastpq::finalized_source::FinalizedFastpqSource, String> {
        self.call(|reply| Request::TakeFinalizedFastpqSource(native, reply))
            .unwrap_or_else(|| Err("original execution Worker stopped".into()))
    }

    /// Finalize the durable original metadata while a real history writer refuses visibility.
    /// The same prepared owner remains available for immutable inspection and ordinary retry.
    #[cfg(test)]
    pub(crate) fn prepare_publication_for_inspection(
        &self,
        block: &AvailableBody,
        qc: &Qc,
    ) -> Result<(), String> {
        self.call(|reply| {
            Request::PreparePublicationForInspection(block.clone(), qc.clone(), reply)
        })
        .ok_or_else(|| "original execution Worker stopped".to_owned())?
    }

    /// Spawn the executor thread.
    ///
    /// # Errors
    /// The thread could not be spawned.
    pub fn spawn(context: ExecutorContext) -> std::io::Result<Self> {
        // One serialized worker can retain at most one waiting request. The driver
        // already owns bounded control ingress and the original publication retry.
        let (requests, rx) = mpsc::sync_channel(1);
        let execution_budget = context.state.ivm_execution_budget();
        #[cfg(test)]
        let exit_hook = shutdown_tests::take_exit_hook();
        let thread =
            super::threads::sumeragi_thread_builder("sumeragi-state-exec").spawn(move || {
                run(&context, &rx);
                #[cfg(test)]
                if let Some(exit_hook) = exit_hook {
                    exit_hook();
                }
                drop(context);
            })?;
        Ok(Self {
            execution_budget,
            requests: Some(requests),
            thread: Some(thread),
        })
    }

    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub(crate) fn inspect_pending<R: Send + 'static>(
        &self,
        block_hash: Hash32,
        inspect: impl for<'borrow, 'state> FnOnce(PendingExecutionView<'borrow, 'state>) -> R
        + Send
        + 'static,
    ) -> Result<R, String> {
        self.call(|reply| {
            Request::InspectPending(
                block_hash,
                Box::new(move |original| {
                    let result = original.and_then(|original| {
                        catch_unwind(AssertUnwindSafe(|| inspect(original)))
                            .map_err(|_| "pending execution inspection panicked".to_owned())
                    });
                    let _ = reply.send(result);
                }),
            )
        })
        .ok_or_else(|| "original execution Worker stopped".to_owned())?
    }

    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub(crate) fn inspect_prepared<R: Send + 'static>(
        &self,
        block_hash: Hash32,
        inspect: impl for<'borrow, 'state> FnOnce(PreparedExecutionView<'borrow, 'state>) -> R
        + Send
        + 'static,
    ) -> Result<R, String> {
        self.call(|reply| {
            Request::InspectPrepared(
                block_hash,
                Box::new(move |original| {
                    let result = original.and_then(|original| {
                        catch_unwind(AssertUnwindSafe(|| inspect(original)))
                            .map_err(|_| "prepared execution inspection panicked".to_owned())
                    });
                    let _ = reply.send(result);
                }),
            )
        })
        .ok_or_else(|| "original execution Worker stopped".to_owned())?
    }

    fn call<T>(&self, request: impl FnOnce(mpsc::SyncSender<T>) -> Request) -> Option<T> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.requests.as_ref()?.send(request(tx)).ok()?;
        rx.recv().ok()
    }
}

impl StateExecutor {
    /// Attach the transaction queue: the builder reads it and applied blocks clean it.
    pub fn attach_queue(&self, queue: Arc<Queue>) {
        if let Some(requests) = &self.requests {
            let _ = requests.send(Request::AttachQueue(queue));
        }
    }

    /// Attach the configured archives once, after replay and before starting the driver.
    /// This synchronously captures the reconciled tip before the executor acknowledges binding;
    /// the replayed tip published by startup replay is that tip, not an execution.
    ///
    /// # Errors
    /// The executor is unavailable, already bound, recovering or executing beyond the applied
    /// tip, or the exact tip cannot be captured.
    pub fn attach_finalized_archives(&self, archives: FinalizedArchives) -> Result<(), String> {
        self.call(|reply| Request::AttachFinalizedArchives(archives, reply))
            .unwrap_or_else(|| Err("executor thread stopped".into()))
    }

    /// Attach the actual runtime beacon custodian once before the driver starts.
    /// Startup replay consumes the signed witness and needs no local producer.
    ///
    /// # Errors
    /// A producer is already attached or the serialized executor stopped.
    pub(crate) fn attach_beacon(
        &self,
        instance: Hash32,
        local_bls: Option<[u8; 48]>,
        signer: Option<Arc<dyn crate::beacon::GlobalThresholdBeaconPartialSignerV1>>,
    ) -> Result<super::epoch_beacon::producer::NativeBeaconReadiness, PublicationError> {
        self.call(|reply| Request::AttachBeacon {
            instance,
            local_bls,
            signer,
            reply,
        })
        .unwrap_or_else(|| Err(control::stopped()))
    }

    /// Re-apply a block Kura already holds (startup replay): execute it on the applied tip
    /// and require the certified result. The caller must admit any decoded witness to the
    /// original State pool before this retained handoff; KuraBlockStore does that explicitly.
    /// Exact retries acknowledge the worker's original completion after its heavy execution
    /// owner retires; changed certificates or sources cannot reuse that acknowledgement.
    ///
    /// # Errors
    /// The block does not re-execute to its certified result, or a local failure retaining
    /// its original release source. A terminal publication failure requires recovery.
    pub fn replay(
        &mut self,
        block: &AvailableBody,
        commit_qc: &Qc,
    ) -> Result<(), PublicationError> {
        require_body_admission(block, &self.execution_budget)?;

        self.call(|reply| Request::Replay(block.clone(), commit_qc.clone(), reply))
            .unwrap_or_else(|| Err(control::stopped()))
    }

    fn prepare_with_origin(
        &mut self,
        block: &AvailableBody,
        commit_qc: &Qc,
        origin: CommitTelemetryOrigin,
    ) -> Result<Option<Hash32>, PublicationError> {
        require_body_admission(block, &self.execution_budget)?;

        self.call(|reply| Request::Prepare(block.clone(), commit_qc.clone(), origin, reply))
            .unwrap_or_else(|| {
                Err(PublicationError::RecoveryRequired(
                    "executor thread stopped".into(),
                ))
            })
    }
}

impl Executor for StateExecutor {
    fn execute(&mut self, block: &AvailableBody, block_hash: &Hash32) -> Option<ExecOutcome> {
        let outcome = match require_body_admission(block, &self.execution_budget) {
            Err(error) => Some(ExecOutcome::Failed(error.to_string())),
            Ok(()) => self
                .call(|reply| Request::Execute(block.clone(), *block_hash, reply))
                .unwrap_or_else(|| Some(ExecOutcome::Failed("executor thread stopped".into()))),
        };
        iroha_logger::debug!(
            instance = ?block.header().instance.0,
            height = block.header().height,
            view = block.header().origin_view,
            block_hash = ?block_hash.0,
            parent_hash = ?block.header().parent_hash.0,
            ?outcome,
            "sumeragi: original native execution answer"
        );
        // The core reports only `LocalFault::ExecutorFailed { height }` and retries; the
        // local reason is logged here, once per failed answer.
        if let Some(ExecOutcome::Failed(reason)) = &outcome {
            iroha_logger::warn!(
                height = block.header().height,
                view = block.header().origin_view,
                %reason,
                "sumeragi: local execution failure"
            );
        }
        outcome
    }

    fn discard(&mut self, height: u64, keep: &[Hash32]) {
        if let Some(requests) = &self.requests {
            let _ = requests.send(Request::Discard(height, keep.to_vec()));
        }
    }

    fn prepare(
        &mut self,
        block: &AvailableBody,
        commit_qc: &Qc,
    ) -> Result<Option<Hash32>, PublicationError> {
        self.prepare_with_origin(block, commit_qc, CommitTelemetryOrigin::Forward)
    }

    fn commit(
        &mut self,
        block: &AvailableBody,
        commit_qc: &Qc,
    ) -> Result<AppliedConfig, PublicationError> {
        require_body_admission(block, &self.execution_budget)?;

        self.call(|reply| Request::Commit(block.clone(), commit_qc.clone(), reply))
            .unwrap_or_else(|| {
                Err(PublicationError::RecoveryRequired(
                    "executor thread stopped".into(),
                ))
            })
    }

    fn build(
        &mut self,
        height: u64,
        view: u64,
        max_bytes: u32,
        exec_budget_ms: u32,
    ) -> Result<Option<PayloadBytes>, PublicationError> {
        self.call(|reply| Request::Build(height, view, max_bytes, exec_budget_ms, reply))
            .unwrap_or_else(|| {
                Err(PublicationError::RecoveryRequired(
                    "payload builder stopped".into(),
                ))
            })
    }

    fn build_control_witness(
        &mut self,
        context: &ControlWitnessContext,
    ) -> Result<ControlWitness, PublicationError> {
        self.call(|reply| Request::BuildControl(*context, reply))
            .unwrap_or_else(|| Err(control::stopped()))
    }

    fn drive_control(
        &mut self,
        context: &ApplicationControlContext,
    ) -> Result<Option<ApplicationControl>, PublicationError> {
        self.call(|reply| Request::DriveControl(*context, reply))
            .unwrap_or_else(|| Err(control::stopped()))
    }

    fn receive_application_control(
        &mut self,
        from: &PublicKey,
        message: &ApplicationControl,
    ) -> Result<(), PublicationError> {
        self.call(|reply| Request::ReceiveControl(from.clone(), message.clone(), reply))
            .unwrap_or_else(|| Err(control::stopped()))
    }

    fn reject(&mut self, height: u64, view: u64, block_hash: &Hash32) {
        if let Some(requests) = &self.requests {
            let _ = requests.send(Request::Reject(height, view, *block_hash));
        }
    }
}

/// A read handle into the exact funded World graph; cloning a decoded epoch is forbidden here.
struct ScheduledAuthority {
    schedule: schedule::RetainedConsensusSchedule,
    height: u64,
}
impl std::ops::Deref for ScheduledAuthority {
    type Target = schedule::ScheduledConfig;
    fn deref(&self) -> &Self::Target {
        self.schedule
            .ready(self.height)
            .expect("immutable ready slot checked at acquisition")
    }
}

/// Original completed execution inputs advance once through proof and result preparation.
enum FinishingPhase {
    ContextProof {
        inputs: iroha_allocation::RetainedPayload<NativeExecutionInputs>,
        refusal: Option<NativeLaneStateProofError>,
    },
    Ready(iroha_allocation::RetainedPayload<ExecutionResultCommitment>),
    /// A one-shot deterministic transition failed or unwound; only recovery may release it.
    Consuming,
}
impl FinishingPhase {
    fn ready(&self) -> Option<&iroha_allocation::RetainedPayload<ExecutionResultCommitment>> {
        match self {
            Self::Ready(commitment) => Some(commitment),
            Self::ContextProof { .. } | Self::Consuming => None,
        }
    }
}

/// One completed execution retained while its proof or result encoding awaits local resources.
/// No retry of either phase re-executes transactions or creates another overlay.
struct Finishing<'s> {
    block_hash: Hash32,
    height: u64,
    header: iroha_sumeragi::message::BlockHeader,
    availability: AvailabilityFrame,
    source: iroha_sumeragi::availability::AvailabilitySource,
    valid: ValidBlock,
    overlay: Box<StateBlock<'s>>,
    witness: crate::state::CapturedExecWitness,
    phase: FinishingPhase,
    applied_config: AppliedConfig,
    committee: Vec<PeerId>,
    events: Vec<EventBox>,
    /// Original typed source of the latest refusal; never a cached invalid verdict.
    encoding_refusal: Option<super::commitment::ResultPreimageError>,
    native_contexts: Option<PreparedNativeContext>,
    archive_refusal: Option<NativeContextArchiveError>,
    world_cut_refusal:
        Option<crate::state::world_projection::world_state_accumulator::world_state_cut::CutError>,
}

/// The executed overlay of one block.
struct Live<'s> {
    telemetry_origin: Option<CommitTelemetryOrigin>,
    native_contexts: Option<PreparedNativeContext>,
    block_hash: Hash32,
    height: u64,
    header: iroha_sumeragi::message::BlockHeader,
    availability: AvailabilityFrame,
    source: iroha_sumeragi::availability::AvailabilitySource,
    phase: PublicationPhase,
    overlay: Option<Box<StateBlock<'s>>>,
    witness: Option<crate::state::CapturedExecWitness>,
    result: Hash32,
    /// Complete original canonical epoch result and its exact source-bound allocation ledger.
    /// Retained for custody through the same Live lifetime and field drop order, even when
    /// shipping execution no longer reads its value after encoding the original preimage.
    _commitment: iroha_allocation::RetainedPayload<ExecutionResultCommitment>,
    applied_config: AppliedConfig,
    committee: Vec<PeerId>,
    events: Vec<EventBox>,
}

#[cfg(test)]
impl Live<'_> {
    /// Borrow the retained canonical result for original-custody assertions.
    fn commitment(&self) -> &iroha_allocation::RetainedPayload<ExecutionResultCommitment> {
        let Self {
            _commitment: commitment,
            ..
        } = self;
        commitment
    }
}

/// The one original execution's progress; no phase reconstructs a predecessor owner.
enum PublicationPhase {
    Executed {
        valid: ValidBlock,
        preimage: iroha_allocation::ChargedBuffer<u8>,
    },
    /// Each successful encoding remains owned while a later allocation is refused.
    EncodingCertificate {
        valid: ValidBlock,
        preimage: iroha_allocation::ChargedBuffer<u8>,
        header_wire: Option<iroha_allocation::ChargedBuffer<u8>>,
        qc_wire: Option<iroha_allocation::ChargedBuffer<u8>>,
        availability_wire: Option<iroha_allocation::ChargedBuffer<u8>>,
        qc: Qc,
        refusal: Option<super::commitment::ResultPreimageError>,
    },
    /// All four original byte allocations await shared-control admission.
    Certifying {
        valid: ValidBlock,
        parts: Option<iroha_data_model::block::ChargedCertificateParts>,
        qc: Qc,
        refusal: Option<iroha_data_model::block::CertificateAdmissionError>,
    },
    Prepared {
        committed: CommittedBlock,
        staged: StagedBlock,
        qc: Qc,
        state_events: Option<Vec<EventBox>>,
    },
    /// A conversion or consuming apply is in progress; unwind requires recovery.
    Consuming,
    Published {
        staged: StagedBlock,
        qc: Qc,
    },
}

#[path = "executor_control.rs"]
mod control;
mod preparation;
mod publication;
mod replay;

/// Exact validation identity permitting transaction isolation; a control refusal never sets it.
#[derive(Clone, Copy)]
struct QuarantineContext {
    height: u64,
    view: u64,
    block_hash: Hash32,
    _pulse_context: iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1,
}

mod payload_owner;
use payload_owner::{CompletedPayload, OriginalPayloadScope};

struct GlobalPayloadSource {
    block: SignedBlock,
    pending_inputs: Option<crate::queue::PendingPayloadLease>,
}

impl super::driver::payload_build::PayloadSourcePreparation for GlobalPayloadSource {
    type Error = iroha_data_model::block::BlockSignatureCustodyError;

    fn prepared_for(&self, budget: &iroha_allocation::AllocationBudget) -> bool {
        self.block.is_resultless_proposal()
            && self.block.signatures().len() == 0
            && self.block.signatures_admitted_to(budget)
    }

    fn prepare_for(
        &mut self,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<(), Self::Error> {
        self.block.prepare_local_unsigned_signature_custody(budget)
    }
}

type GlobalPayloadPreparationError = super::driver::payload_build::SourcePreparationError<
    iroha_data_model::block::BlockSignatureCustodyError,
>;

struct GlobalPayloadBuild {
    scope: OriginalPayloadScope,
    job: super::driver::payload_build::PayloadBuild<GlobalPayloadSource>,
    /// Exact original pre-wire refusal; survives retry with this same source and job.
    preparation_refusal: Option<GlobalPayloadPreparationError>,
}

/// Own the exact authenticated source, partial leaves and completed decoded proposal.
/// Decoding custody grants no State, schedule, execution or finality authority.
struct SignatureDecodeAttempt {
    block_hash: Hash32,
    source: AvailableBody,
    decoder: iroha_data_model::block::PreparedSignedBlockSignaturesDecode,
    decoded: Option<SignedBlock>,
    /// An original returned graph cannot be reused after an unfinished or mismatched projection.
    returned_refusal: Option<ReturnedDecodedRefusal>,
    /// Completed leg graphs and decoder controls from this exact original proposal.
    amx_legs: Option<super::amx::NativeAmxLegPreparations>,
}

/// Original failure retained beside the same graph after the validator returned ownership.
enum ReturnedDecodedRefusal {
    Codec(norito::Error),
    SourceMismatch,
}

impl SignatureDecodeAttempt {
    /// Complete the sole canonical decode once; retries borrow only that exact original graph.
    fn original_decoded(
        &mut self,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<&SignedBlock, payload::PayloadError> {
        if !self.decoder.belongs_to(budget) {
            return Err(payload::PayloadError::SignatureCustodyInvariant(
                "completed proposal decoder belongs to another original pool".into(),
            ));
        }
        let Some(source) = self.source.payload().charged_source(budget) else {
            return Err(payload::PayloadError::SignatureCustodyInvariant(
                "completed proposal has no original State-funded source".into(),
            ));
        };
        if let Some(refusal) = &self.returned_refusal {
            let reason = match refusal {
                ReturnedDecodedRefusal::Codec(error) => {
                    format!("original returned proposal projection is unfinished: {error}")
                }
                ReturnedDecodedRefusal::SourceMismatch => {
                    "original returned proposal differs from its authenticated source".into()
                }
            };
            return Err(payload::PayloadError::SignatureCustodyInvariant(reason));
        }
        // A completed graph remains owned by this attempt; a retry must not reconstruct it.
        #[cfg(all(test, sumeragi_core_mutation = "HC130"))]
        {
            self.decoded = None;
        }
        if self.decoded.is_none() {
            self.decoded = Some(payload::decode_prepared(source, &mut self.decoder)?);
        }
        let original = self.decoded.as_ref().expect("completed original decode");
        // This rechecks the original address, length, whole-wire hash and pool, without
        // reentering the canonical field walker or issuing new decode counters.
        let original_control = self
            .decoder
            .retains_signature_custody(source, original)
            .map_err(|error| payload::PayloadError::SignatureCustodyInvariant(error.to_string()))?;
        // HC131 mutates only this physical-control obligation. The same source,
        // pool, canonical wire and current authority checks remain mandatory.
        if (!cfg!(all(test, sumeragi_core_mutation = "HC131")) && !original_control)
            || !original.signatures_admitted_to(budget)
        {
            return Err(payload::PayloadError::SignatureCustodyInvariant(
                "completed proposal lost its original signature custody".into(),
            ));
        }
        Ok(original)
    }

    /// Recover only the actual block returned by the consuming production validator.
    /// Its canonical projection must match the immutable original available wire exactly.
    fn retain_validation_return(
        &mut self,
        original: SignedBlock,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<(), PublicationError> {
        // The callsite takes this slot immediately before validation. It cannot replace
        // or drop another completed owner while the validator holds the original graph.
        debug_assert!(self.decoded.is_none());
        let original = match original.into_resultless_proposal() {
            Ok(original) => original,
            Err((original, error)) => {
                let reason = format!("original returned proposal projection: {error}");
                self.decoded = Some(original);
                self.returned_refusal = Some(ReturnedDecodedRefusal::Codec(error));
                return Err(PublicationError::RecoveryRequired(reason));
            }
        };
        self.decoded = Some(original);
        if !self.decoder.belongs_to(budget) {
            self.returned_refusal = Some(ReturnedDecodedRefusal::SourceMismatch);
            return Err(PublicationError::RecoveryRequired(
                "returned proposal decoder belongs to another original pool".into(),
            ));
        }
        let Some(source) = self.source.payload().charged_source(budget) else {
            self.returned_refusal = Some(ReturnedDecodedRefusal::SourceMismatch);
            return Err(PublicationError::RecoveryRequired(
                "returned proposal has no original State-funded source".into(),
            ));
        };
        let original = self.decoded.as_ref().expect("original validation return");
        let matches = match original.matches_resultless_proposal_wire(source.as_slice()) {
            Ok(matches) => matches,
            Err(error) => {
                let reason = format!("original returned proposal source comparison: {error}");
                self.returned_refusal = Some(ReturnedDecodedRefusal::Codec(error));
                return Err(PublicationError::RecoveryRequired(reason));
            }
        };
        if !matches || !original.signatures_admitted_to(budget) {
            self.returned_refusal = Some(ReturnedDecodedRefusal::SourceMismatch);
            return Err(PublicationError::RecoveryRequired(
                "returned proposal differs from its original authenticated source or pool".into(),
            ));
        }
        // Check the same ordinary decoder's source identity without entering the retry
        // path, walking fields again, or replacing the returned graph.
        match self.decoder.retains_signature_custody(source, original) {
            Ok(original_control)
                if original_control || cfg!(all(test, sumeragi_core_mutation = "HC131")) =>
            {
                Ok(())
            }
            _ => {
                self.returned_refusal = Some(ReturnedDecodedRefusal::SourceMismatch);
                Err(PublicationError::RecoveryRequired(
                    "returned proposal lost its original decoder source custody".into(),
                ))
            }
        }
    }
}

struct Worker<'s> {
    payload_build: Option<GlobalPayloadBuild>,
    signature_decode: Option<SignatureDecodeAttempt>,
    /// Exact latest unfinished local execution refusal, kept outside deterministic verdicts.
    routing_refusal: Option<crate::execution_attempt::ExecutionDeferred>,
    /// Original payload preparation refusal, including State lock and pool release observations.
    payload_refusal: Option<payload::PayloadError>,
    context: &'s ExecutorContext,
    state: &'s State,
    applied: (u64, Hash32),
    live: Option<Live<'s>>,
    finishing: Option<Finishing<'s>>,
    /// Verdicts of executions whose overlay is gone, by block hash (bounded per height).
    results: BTreeMap<
        Hash32,
        (
            iroha_sumeragi::availability::AvailabilitySource,
            ExecOutcome,
        ),
    >,
    /// One original nonempty funded output, reusable only while its genuine input lease lives.
    completed_payload: Option<CompletedPayload>,
    queue: Option<Arc<Queue>>,
    /// The process-lifetime partial owner; view changes never replace it.
    beacon: Option<super::epoch_beacon::producer::NativeBeaconProducer>,
    /// Only an exact control-free transaction rejection permits queue isolation.
    quarantine_context: Option<QuarantineContext>,
    /// A consuming publication cannot be retried on this worker, even after an unwind.
    recovery: Option<String>,
    archives: Option<FinalizedArchives>,
    pending_commit: Option<PendingCommit>,
    /// One original completed startup replay; no execution/proof graph is retained.
    completed_replay: Option<replay::CompletedReplay>,
}

fn run(context: &ExecutorContext, requests: &mpsc::Receiver<Request>) {
    let state = Arc::clone(&context.state);
    let mut worker = Worker {
        payload_build: None,
        signature_decode: None,
        routing_refusal: None,
        payload_refusal: None,
        context,
        state: &state,
        applied: context.applied,
        live: None,
        finishing: None,
        results: BTreeMap::new(),
        completed_payload: None,
        queue: context.queue.clone(),
        recovery: None,
        beacon: None,
        archives: None,
        pending_commit: None,
        completed_replay: None,
        quarantine_context: None,
    };
    loop {
        let request = match worker.payload_storage_wait() {
            Some(wait) => match requests.recv_timeout(wait) {
                Ok(request) => request,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            },
            None => match requests.recv() {
                Ok(request) => request,
                Err(_) => break,
            },
        };
        worker.serve(request);
    }
}

impl<'s> Worker<'s> {
    fn serve(&mut self, request: Request) {
        // Every request observes actual source/Queue withdrawal before retained bytes can lend.
        self.payload_storage_wait();
        match request {
            Request::TakeFinalizedFastpqSource(native, reply) => {
                let _ = reply.send(self.take_finalized_fastpq_source(native));
            }
            #[cfg(test)]
            Request::PreparePublicationForInspection(block, qc, reply) => {
                let state = self.state;
                let original_height = state.committed_height();
                let result = state.with_publication_blocked_for_test(|| self.commit(&block, &qc));
                let prepared = self.live.as_ref().is_some_and(|live| {
                    live.block_hash == qc.block_hash
                        && matches!(&live.phase,
                            PublicationPhase::Prepared { qc: original, state_events: Some(_), .. }
                                if original == &qc)
                });
                let result = if matches!(
                    result,
                    Err(PublicationError::Deferred(
                        PublicationDeferral::PublicationBusy(_)
                    ))
                ) && self.recovery.is_none()
                    && prepared
                    && state.committed_height() == original_height
                {
                    Ok(())
                } else {
                    Err(format!(
                        "original publication did not defer before visibility: {result:?}"
                    ))
                };
                let _ = reply.send(result);
            }
            #[cfg(any(test, feature = "iroha-core-tests"))]
            Request::InspectPending(block_hash, inspect) => {
                let original =
                    self.live
                        .as_mut()
                        .ok_or_else(|| "no original pending execution".to_owned())
                        .and_then(|live| {
                            if live.block_hash != block_hash {
                                return Err(
                                    "pending inspection belongs to a different execution".into()
                                );
                            }
                            let PublicationPhase::Executed { valid, .. } = &mut live.phase else {
                                return Err("certified publication cannot be mutated".into());
                            };
                            let state = live.overlay.as_deref_mut().ok_or_else(|| {
                                "original pending overlay was consumed".to_owned()
                            })?;
                            Ok(PendingExecutionView {
                                block: valid,
                                state,
                                witness: WitnessInspection(
                                    live.witness
                                        .as_mut()
                                        .ok_or("original witness already handed off")?,
                                ),
                            })
                        });
                inspect(original);
            }
            #[cfg(any(test, feature = "iroha-core-tests"))]
            Request::InspectPrepared(block_hash, inspect) => {
                let original = self
                    .live
                    .as_ref()
                    .ok_or_else(|| "no original prepared execution".to_owned())
                    .and_then(|live| {
                        if live.block_hash != block_hash {
                            return Err(
                                "prepared inspection belongs to a different execution".into()
                            );
                        }
                        let PublicationPhase::Prepared {
                            committed,
                            state_events: Some(_),
                            ..
                        } = &live.phase
                        else {
                            return Err("original execution is not prepared for publication".into());
                        };
                        let state = live
                            .overlay
                            .as_deref()
                            .ok_or_else(|| "original prepared overlay was consumed".to_owned())?;
                        Ok(PreparedExecutionView {
                            block: committed,
                            state,
                            witness: live
                                .witness
                                .as_ref()
                                .ok_or("original witness already handed off")?
                                .wire(),
                        })
                    });
                inspect(original);
            }
            Request::Execute(block, block_hash, reply) => {
                let _ = reply.send(self.execute(&block, block_hash));
            }
            Request::Discard(height, keep) => self.discard(height, &keep),
            Request::Prepare(block, qc, origin, reply) => {
                let _ = reply.send(self.prepare_with_origin(&block, &qc, origin));
            }
            Request::Commit(block, qc, reply) => {
                let _ = reply.send(self.commit(&block, &qc));
            }
            Request::Replay(block, qc, reply) => {
                let _ = reply.send(self.replay(&block, &qc));
            }
            Request::Build(height, view, max_bytes, exec_budget_ms, reply) => {
                let _ = reply.send(self.build(height, view, max_bytes, exec_budget_ms));
            }
            Request::BuildControl(context, reply) => {
                let _ = reply.send(self.build_control_witness(&context));
            }
            Request::DriveControl(context, reply) => {
                let _ = reply.send(self.drive_control(&context));
            }
            Request::ReceiveControl(from, message, reply) => {
                let _ = reply.send(self.receive_application_control(&from, &message));
            }
            Request::AttachBeacon {
                instance,
                local_bls,
                signer,
                reply,
            } => {
                let _ = reply.send(self.attach_beacon(instance, local_bls, signer));
            }
            Request::Reject(height, view, block_hash) => self.reject(height, view, block_hash),
            Request::AttachQueue(queue) => {
                self.completed_payload = None;
                self.payload_build = None;
                self.queue = Some(queue);
            }
            Request::AttachFinalizedArchives(archives, reply) => {
                let _ = reply.send(self.bind_finalized_archives(archives));
            }
        }
    }

    /// Handoff occurs only after durable publication and all original archive work.
    /// A refusal retains the exact witness in Live; repeated successful transfer is refused.
    fn take_finalized_fastpq_source(
        &mut self,
        native: super::certified_chain::AuthenticatedExecutionBlock,
    ) -> Result<crate::fastpq::finalized_source::FinalizedFastpqSource, String> {
        use crate::fastpq::finalized_source::FinalizedFastpqSource;
        if self.pending_commit.is_some() || self.recovery.is_some() {
            return Err("original execution publication has not completed".into());
        }
        let live = self
            .live
            .as_mut()
            .ok_or("original execution is no longer retained")?;
        if !matches!(live.phase, PublicationPhase::Published { .. })
            || self.applied != (live.height, live.block_hash)
            || native.committed().height() != live.height
            || native.committed().core_hash() != live.block_hash
            || native.committed().result() != live.result
        {
            return Err(
                "FASTPQ handoff requires the exact already-published native execution".into(),
            );
        }
        let original = live
            .witness
            .take()
            .ok_or("original source was already handed off")?;
        match FinalizedFastpqSource::bind(original, native) {
            Ok(source) => Ok(source),
            Err((original, _, error)) => {
                live.witness = Some(original);
                Err(error.to_string())
            }
        }
    }

    /// Bind the configured archives once, at the applied tip and before any execution beyond
    /// it. Startup replay retains only its exact completed tip identity. The binding captures
    /// the exact certified tip State (a no-op when startup
    /// reconciliation already captured it), and every later commit captures its own height, so
    /// no height is skipped or captured twice.
    fn bind_finalized_archives(&mut self, archives: FinalizedArchives) -> Result<(), String> {
        if self.archives.is_some() {
            return Err("finalized archives are already bound".into());
        }
        if let Some(reason) = &self.recovery {
            return Err(format!(
                "finalized archives cannot bind during recovery: {reason}"
            ));
        }
        let (height, block_hash) = self.applied;
        if self.pending_commit.is_some()
            || self.signature_decode.is_some()
            || self.finishing.is_some()
            || self.live.as_ref().is_some_and(|live| {
                (live.height, live.block_hash) != (height, block_hash)
                    || !matches!(live.phase, PublicationPhase::Published { .. })
            })
        {
            return Err(
                "finalized archives must be bound before execution beyond the applied tip".into(),
            );
        }
        let view = self.state.view();
        if u64::try_from(view.height()).ok() != Some(height) {
            return Err(format!(
                "committed State height {} differs from the applied tip {height}",
                view.height()
            ));
        }
        // Startup binding is terminal on failure and has no pending State publication owner.
        // Only this outer startup diagnostic boundary returns a string; live capture retains
        // the original resource source in PendingCommit and the driver response.
        archives.capture(&view).map_err(|error| error.to_string())?;
        drop(view);
        self.archives = Some(archives);
        Ok(())
    }

    /// Answer an `Execute` (O4): the live overlay or a remembered verdict, `None` while the
    /// parent is not applied, otherwise a fresh execution.
    fn execute(&mut self, block: &AvailableBody, block_hash: Hash32) -> Option<ExecOutcome> {
        if self.pending_commit.is_some() {
            return None;
        }
        if let Some(reason) = &self.recovery {
            return Some(execution_report(Err(PublicationError::RecoveryRequired(
                reason.clone(),
            ))));
        }
        if let Some(live) = &self.live {
            if live.block_hash == block_hash {
                if live.header != *block.header()
                    || live.availability != *block.availability()
                    || live.source != *block.source()
                {
                    return Some(invalid(
                        block.header().height,
                        &"execution retry changes its original header",
                    ));
                }
                return Some(ExecOutcome::Valid(live.result));
            }
        }
        if let Some((source, outcome)) = self.results.get(&block_hash) {
            return Some(if source == block.source() {
                outcome.clone()
            } else {
                invalid(
                    block.header().height,
                    &"execution retry changes its original authority",
                )
            });
        }
        if !self.parent_applied(block) {
            iroha_logger::debug!(
                instance = ?block.header().instance.0,
                height = block.header().height,
                view = block.header().origin_view,
                block_hash = ?block_hash.0,
                parent_hash = ?block.header().parent_hash.0,
                applied_height = self.applied.0,
                applied_hash = ?self.applied.1.0,
                "sumeragi: original native execution awaits its applied parent"
            );
            return None;
        }
        let outcome = execution_report(self.run_execution(block, block_hash));
        if !matches!(outcome, ExecOutcome::Valid(_) | ExecOutcome::Failed(_)) {
            self.remember(block.source().clone(), block_hash, outcome.clone());
        }
        Some(outcome)
    }

    fn parent_applied(&self, block: &AvailableBody) -> bool {
        block.header().height == self.applied.0.saturating_add(1)
            && block.header().parent_hash == self.applied.1
    }

    fn remember(
        &mut self,
        source: iroha_sumeragi::availability::AvailabilitySource,
        block_hash: Hash32,
        outcome: ExecOutcome,
    ) {
        self.results.insert(block_hash, (source, outcome));
        // The core keeps at most a handful of bodies per height (§8.4); stay bounded.
        while self.results.len() > 16 {
            let Some(oldest) = self
                .results
                .iter()
                .min_by_key(|(_, (source, _))| source.height())
                .map(|(hash, _)| *hash)
            else {
                break;
            };
            self.results.remove(&oldest);
        }
    }

    /// Execute `block` on the applied tip, keeping the overlay as the live one.
    fn run_execution(
        &mut self,
        block: &AvailableBody,
        block_hash: Hash32,
    ) -> Result<Option<Hash32>, PublicationError> {
        let outcome = self.run_execution_with_encoder(block, block_hash, encode_result_preimage);
        if let Err(PublicationError::RecoveryRequired(reason)) = &outcome {
            self.recovery = Some(reason.clone());
        }
        outcome
    }

    fn run_execution_with_encoder(
        &mut self,
        block: &AvailableBody,
        block_hash: Hash32,
        encode: impl FnOnce(
            &iroha_allocation::RetainedPayload<ExecutionResultCommitment>,
            &iroha_allocation::AllocationBudget,
        ) -> Result<
            iroha_allocation::ChargedBuffer<u8>,
            super::commitment::ResultPreimageError,
        >,
    ) -> Result<Option<Hash32>, PublicationError> {
        let outcome = self.run_execution_with_finisher(block, block_hash, |worker| {
            worker.finish_execution_with_encoder(encode)
        });
        if matches!(outcome, Ok(None)) {
            // Only a completed intrinsic rejection retires this original decode custody.
            self.signature_decode = None;
        }
        outcome
    }

    /// The callback receives the sole completed original, before any proof scratch allocation.
    fn run_execution_with_finisher(
        &mut self,
        block: &AvailableBody,
        block_hash: Hash32,
        finish: impl FnOnce(&mut Self) -> Result<Option<Hash32>, PublicationError>,
    ) -> Result<Option<Hash32>, PublicationError> {
        self.retire_completed_payload(block.header().height);
        if self.publication_pending() {
            return Err(PublicationError::Retryable(
                "the original prepared publication is still retained".into(),
            ));
        }
        if let Some(original) = &self.finishing {
            if original.block_hash == block_hash {
                if original.header != *block.header()
                    || original.availability != *block.availability()
                    || original.source != *block.source()
                {
                    return invalid_attempt(
                        block.header().height,
                        &"result retry changes its original header",
                    );
                }
                return finish(self);
            }
        }
        // An explicitly superseded candidate releases its original private execution.
        self.finishing = None;
        // The state admits one overlay: drop the previous one first.
        if let Some(previous) = self.live.take() {
            // Its overlay is gone; a later `prepare` executes again.
            self.results.remove(&previous.block_hash);
        }
        // A fresh attempt explicitly abandons the prior local refusal; completed verdicts own none.
        self.routing_refusal = None;
        let height = block.header().height;
        let budget = self.state.ivm_execution_budget();
        if self
            .signature_decode
            .as_ref()
            .is_some_and(|attempt| attempt.block_hash != block_hash)
        {
            // A different authenticated candidate explicitly retires the old original owners.
            self.signature_decode = None;
        }
        if let Some(attempt) = &self.signature_decode {
            if attempt.source != *block {
                return Err(PublicationError::RecoveryRequired(
                    "signature preparation retry changed its original authenticated body".into(),
                ));
            }
        } else {
            let decoder = match iroha_data_model::block::PreparedSignedBlockSignaturesDecode::new(
                &budget,
            ) {
                Ok(decoder) => decoder,
                Err(error) => {
                    return match crate::execution_attempt::prepared_signature_block_attempt_error(
                        error,
                        |reason| reason,
                    ) {
                        crate::execution_attempt::ExecutionAttemptError::Deferred(original) => {
                            self.routing_refusal = Some(original.clone());
                            Err(PublicationError::Deferred(original.into()))
                        }
                        crate::execution_attempt::ExecutionAttemptError::Rejected(reason) => {
                            Err(PublicationError::RecoveryRequired(reason))
                        }
                    };
                }
            };
            self.signature_decode = Some(SignatureDecodeAttempt {
                block_hash,
                source: block.clone(),
                decoder,
                decoded: None,
                returned_refusal: None,
                amx_legs: None,
            });
        }
        let attempt = self
            .signature_decode
            .as_mut()
            .expect("original signature decode source");
        match attempt.original_decoded(&budget) {
            Ok(_) => {}
            Err(payload::PayloadError::DecodeResource(reason))
                if !cfg!(all(test, sumeragi_core_mutation = "HC8")) =>
            {
                // Keep the typed refusal with the unchanged available owner before formatting.
                // Failed remains retryable and never enters the deterministic negative-result cache.
                if !cfg!(all(test, sumeragi_core_mutation = "HC45")) {
                    self.routing_refusal = Some(reason.clone());
                }
                return Err(PublicationError::Deferred(reason.into()));
            }
            Err(payload::PayloadError::SignatureCustodyInvariant(reason)) => {
                return Err(PublicationError::RecoveryRequired(reason));
            }
            Err(error) => {
                self.signature_decode = None;
                return invalid_attempt(height, &error);
            }
        }
        match self.state.view().latest_block() {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(PublicationError::Retryable(
                    "the applied parent block is not available".into(),
                ));
            }
            Err(error) => {
                if let crate::execution_attempt::ExecutionAttemptError::Deferred(original) = &error
                {
                    self.routing_refusal = Some(original.clone());
                }
                return Err(error.map_rejection(|error| error.to_string()).into());
            }
        }
        let Some(scheduled) = self.scheduled(height) else {
            return Err(PublicationError::Retryable(format!(
                "no scheduled configuration for height {height}"
            )));
        };
        let configured = match scheduled.height_config() {
            Ok(config) => config,
            Err(error) => {
                return Err(PublicationError::Retryable(format!(
                    "invalid retained epoch: {error}"
                )));
            }
        };
        if block.source().config() != &configured || block.header().epoch != configured.epoch.id {
            return invalid_attempt(
                height,
                &"available custody does not bind the complete scheduled authority",
            );
        }
        self.quarantine_context = None;
        // Decode solely inside the original header/payload validation boundary.
        let pulse_context = control::pulse_context(block.header());
        let cadence = Duration::from_millis(scheduled.params.block_time_ms);
        let iroha_block = self
            .signature_decode
            .as_ref()
            .and_then(|attempt| attempt.decoded.as_ref())
            .expect("original completed proposal remains before validation");
        if !proposal_matches_header(iroha_block.header(), block) {
            return invalid_attempt(
                height,
                &"the payload's height or view differs from the header",
            );
        }
        // Merged lane blocks execute after the block's own transactions (§4.3 of
        // `specs/sumeragi_lanes.md`); the node waits for its lane stores within `E_max`.
        let expansion = match lanes::merge::expand(
            self.state,
            iroha_block,
            &*self.context.lane_blocks,
            Duration::from_millis(scheduled.params.exec_budget_ms),
        ) {
            Ok(expansion) => {
                self.routing_refusal = None;
                expansion
            }
            Err(error @ lanes::merge::MergeError::SourceChanged { .. }) => {
                return Err(PublicationError::Retryable(error.to_string()));
            }
            Err(lanes::merge::MergeError::StateView(error)) => return Err(error.into()),
            Err(lanes::merge::MergeError::RoutingDeferred(reason)) => {
                self.routing_refusal = Some(reason.clone());
                return Err(PublicationError::Deferred(reason.into()));
            }
            Err(lanes::merge::MergeError::Pending(reason)) => {
                return Err(PublicationError::Retryable(reason));
            }
            Err(error @ lanes::merge::MergeError::Invalid(_)) => {
                return invalid_attempt(height, &error);
            }
            Err(lanes::merge::MergeError::Storage(error)) => {
                if let crate::execution_attempt::ExecutionAttemptError::Deferred(original) = &error
                {
                    self.routing_refusal = Some(original.clone());
                }
                let reason = format!("lane storage during execution: {error}");
                if !matches!(
                    error.io_kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) {
                    self.recovery = Some(reason.clone());
                }
                return Err(error.map_rejection(|_| reason).into());
            }
        };
        let committee = scheduled
            .epoch
            .committee
            .iter()
            .map(|member| member.validator.clone())
            .collect::<Vec<_>>();
        let topology = Topology::new(committee.clone());
        // All current authority/source gates ran on the borrowed original. The expansion
        // borrows only State; transfer that same graph to the real validator once.
        let iroha_block = self
            .signature_decode
            .as_mut()
            .and_then(|attempt| attempt.decoded.take())
            .expect("original completed proposal transfers to validation");
        let genesis_account = &self.context.genesis_account;
        let consensus_mode = self.context.consensus_mode;
        let state = self.state;
        let attempt = self
            .signature_decode
            .as_mut()
            .expect("original validation attempt");
        // Expansion legitimately appends/moves lane inputs. This first owner
        // retains only unexpanded originals; other calls use the same funded kernel.
        // TODO: compose retained leg identity with actual lane input ownership.
        let amx_legs = if iroha_block.lane_merge().is_none() {
            let original_source = &attempt.source;
            let bank = attempt.amx_legs.get_or_insert_with(|| {
                super::amx::NativeAmxLegPreparations::new(&iroha_block, original_source, &budget)
            });
            let original_matches =
                bank.matches_original(&iroha_block, original_source, block, &budget);
            #[cfg(all(test, sumeragi_core_mutation = "HC167"))]
            let original_matches = original_matches
                && bank.matches_original_publication(state.state_view_generation());
            if !original_matches {
                attempt.decoded = Some(iroha_block);
                return Err(PublicationError::RecoveryRequired(
                    "completed AMX preparation changed its original block, source or pool".into(),
                ));
            }
            Some(bank)
        } else {
            if attempt.amx_legs.is_some() {
                attempt.decoded = Some(iroha_block);
                return Err(PublicationError::RecoveryRequired(
                    "completed AMX attempt acquired a substituted lane expansion".into(),
                ));
            }
            None
        };
        let validated = catch_unwind(AssertUnwindSafe(|| {
            ValidBlock::validate_sumeragi_block_with_amx(
                iroha_block,
                &topology,
                genesis_account,
                cadence,
                consensus_mode,
                expansion,
                block.header(),
                block.payload().as_slice(),
                state,
                amx_legs,
            )
        }));
        let validated = match validation_result(validated) {
            Ok(completed) => completed,
            Err(recovery) => return Err(recovery),
        };
        let mut events = Vec::new();
        let (valid, overlay) = match validated.unpack(|event| events.push(event.into())) {
            Ok(executed) => executed,
            Err((returned, error)) => {
                if !cfg!(all(test, sumeragi_core_mutation = "HC44"))
                    && let BlockValidationError::ExecutionDeferred(reason) = error.as_ref()
                {
                    self.routing_refusal = Some(reason.clone());
                }
                // Native validation attaches a rejection only after checking the original
                // header/payload source. Local refusals and unbound sources attach none.
                // Rejection is an observation, not a committed transaction outcome.
                for event in events {
                    let _ = self.context.events.send(event);
                }
                if block.header().control_witness.is_empty()
                    && control::transaction_rejection(&error)
                {
                    self.quarantine_context = Some(QuarantineContext {
                        height,
                        view: block.header().origin_view,
                        block_hash,
                        _pulse_context: pulse_context,
                    });
                }
                let outcome = classify(height, &error);
                if outcome.is_err() {
                    // Keep the actual original graph for a local validation refusal.
                    // Completed intrinsic rejection explicitly retires it as before.
                    self.signature_decode
                        .as_mut()
                        .expect("original validation attempt")
                        .retain_validation_return(*returned, &budget)?;
                }
                return outcome;
            }
        };
        if self
            .retain_validated_execution(block, block_hash, valid, overlay, committee, events)?
            .is_none()
        {
            return Ok(None);
        }
        finish(self)
    }

    /// Transfer one actual validator result into its completed owner. Witness extraction
    /// checks the retained source; absence cannot promise a retry after these owners drop.
    /// Some denotes the retained completed owner; None preserves intrinsic rejection.
    fn retain_validated_execution(
        &mut self,
        block: &AvailableBody,
        block_hash: Hash32,
        valid: ValidBlock,
        mut overlay: Box<StateBlock<'s>>,
        committee: Vec<PeerId>,
        events: Vec<EventBox>,
    ) -> Result<Option<()>, PublicationError> {
        let height = block.header().height;
        if let Err(error) = overlay.take_sumeragi_lanes() {
            if let lanes::step::LaneStepError::Deferred(reason) = &error {
                self.routing_refusal = Some(reason.clone());
            }
            return classify_lane_step(height, &error).map(|_| None);
        }
        let inputs = match overlay.take_sumeragi_execution_inputs() {
            Ok(inputs) => inputs,
            Err(error) => {
                let error = BlockValidationError::from(error);
                if !cfg!(all(test, sumeragi_core_mutation = "HC44"))
                    && let BlockValidationError::ExecutionDeferred(reason) = &error
                {
                    self.routing_refusal = Some(reason.clone());
                }
                return classify(height, &error).map(|_| None);
            }
        };
        let applied_config = match inputs.get().schedule.applied_config() {
            Ok(config) => config,
            Err(error) => return invalid_attempt(height, &error).map(|_| None),
        };
        let Some(witness) = overlay.take_exec_witness() else {
            if cfg!(all(test, sumeragi_core_mutation = "HC134")) {
                return Err(PublicationError::Retryable(
                    "the execution witness was not captured".into(),
                ));
            }
            // Guard failure or prior extraction has no resumable captured owner. Latch
            // recovery before this handoff consumes the sole valid block and overlay.
            let reason = self
                .recovery
                .get_or_insert_with(|| {
                    "the original execution witness is absent or no longer source-valid".into()
                })
                .clone();
            return Err(PublicationError::RecoveryRequired(reason));
        };
        // The original valid block now retains the same immutable signature owner.
        // Retire only its preparation controls/source; later phases move this exact block.
        self.signature_decode = None;
        self.finishing = Some(Finishing {
            block_hash,
            height,
            header: block.header().clone(),
            availability: block.availability().clone(),
            source: block.source().clone(),
            valid,
            overlay,
            witness,
            phase: FinishingPhase::ContextProof {
                inputs,
                refusal: None,
            },
            applied_config,
            committee,
            events,
            encoding_refusal: None,
            native_contexts: None,
            archive_refusal: None,
            world_cut_refusal: None,
        });
        Ok(Some(()))
    }

    /// Construct the mandatory context proof from the same original witness and input owner.
    fn prepare_original_result(&mut self) -> Result<(), PublicationError> {
        let original = self
            .finishing
            .as_ref()
            .expect("original completed execution");
        match &original.phase {
            FinishingPhase::Ready(_) => return Ok(()),
            FinishingPhase::Consuming => {
                let reason = "original result transition requires recovery".to_owned();
                self.recovery = Some(reason.clone());
                return Err(PublicationError::RecoveryRequired(reason));
            }
            FinishingPhase::ContextProof { .. } => {}
        }
        let budget = self.state.ivm_execution_budget();
        let proof = match NativeLaneStateProof::from_witness(&original.witness, &budget) {
            Ok(proof) => proof,
            Err(error) => {
                let failure = match original_lane_proof_deferral(&error) {
                    Some(original) => PublicationError::Deferred(original.into()),
                    None => PublicationError::RecoveryRequired(format!(
                        "original context proof requires recovery: {error}"
                    )),
                };
                if !error.is_local_refusal() {
                    self.recovery = Some(failure.to_string());
                }
                let FinishingPhase::ContextProof { refusal, .. } =
                    &mut self.finishing.as_mut().unwrap().phase
                else {
                    unreachable!("original proof phase")
                };
                *refusal = Some(error);
                return Err(failure);
            }
        };
        // The complete World state before and after this execution and its emitted events
        // (§4.1, Appendix E, E51), read from the same sealed original overlay.
        let transition = match self
            .finishing
            .as_ref()
            .expect("original completed execution")
            .overlay
            .world_state_transition()
        {
            Ok(transition) => transition,
            Err(error) => {
                let reason = format!("original World state transition requires recovery: {error}");
                self.recovery = Some(reason.clone());
                return Err(PublicationError::RecoveryRequired(reason));
            }
        };
        // Retain only original journal-touched native hashes at precisely this R.
        // Local refusal leaves the same completed overlay and one-shot inputs live.
        if let Err(error) = self
            .finishing
            .as_mut()
            .unwrap()
            .overlay
            .capture_original_world_cut(transition.world_state_root)
        {
            use crate::state::world_projection::world_state_accumulator::world_state_cut::CutError;
            let failure = match &error {
                CutError::Deferred(original) => PublicationError::Deferred(original.clone().into()),
                CutError::Invalid(reason) => {
                    let reason = format!("original World cut requires recovery: {reason}");
                    self.recovery = Some(reason.clone());
                    PublicationError::RecoveryRequired(reason)
                }
            };
            self.finishing.as_mut().unwrap().world_cut_refusal = Some(error);
            return Err(failure);
        }
        self.finishing.as_mut().unwrap().world_cut_refusal = None;
        let original = self.finishing.as_mut().unwrap();
        let FinishingPhase::ContextProof { inputs, .. } =
            std::mem::replace(&mut original.phase, FinishingPhase::Consuming)
        else {
            unreachable!("original proof inputs")
        };
        let commitment = execution_result(
            &mut original.witness,
            original.valid.as_ref(),
            &transition,
            inputs,
            proof,
        )
        .map_err(|error| {
            let reason = format!("original result requires recovery: {error}");
            self.recovery = Some(reason.clone());
            PublicationError::RecoveryRequired(reason)
        })?;
        original.phase = FinishingPhase::Ready(commitment);
        Ok(())
    }

    /// Capture complete original values before any State publication. Retry reuses the same
    /// overlay and retained R; once admitted, the exact charged projection is never encoded twice.
    fn prepare_original_context_archive(&mut self) -> Result<(), PublicationError> {
        let original = self
            .finishing
            .as_mut()
            .expect("original completed execution");
        let capture = (|| {
            if original.native_contexts.is_none() {
                original.native_contexts = Some(self.context.native_context_archive.prepare(
                    &original.overlay,
                    original.valid.as_ref(),
                    original.phase.ready().expect("original prepared result"),
                    &original.witness,
                )?);
            }
            self.context.native_context_archive.prepare_amx_intents(
                original
                    .native_contexts
                    .as_mut()
                    .expect("original context capture"),
                &original.overlay,
                original.valid.as_ref(),
                original.phase.ready().expect("original prepared result"),
                &original.witness,
            )
        })();
        match capture {
            Ok(()) => {
                original.archive_refusal = None;
                Ok(())
            }
            Err(error) => {
                let failure = match &error {
                    NativeContextArchiveError::Allocation(error) => {
                        PublicationError::Deferred(preparation::buffer_refusal(error).into())
                    }
                    NativeContextArchiveError::Proof(error) => {
                        match original_lane_proof_deferral(error) {
                            Some(original) => PublicationError::Deferred(original.into()),
                            None => PublicationError::RecoveryRequired(format!(
                                "original native context archive requires recovery: {error}"
                            )),
                        }
                    }
                    _ => PublicationError::RecoveryRequired(format!(
                        "original native context archive requires recovery: {error}"
                    )),
                };
                if !error.is_local_refusal() {
                    self.recovery = Some(failure.to_string());
                }
                original.archive_refusal = Some(error);
                Err(failure)
            }
        }
    }

    /// Retry only proof or encoding of the original completed execution.
    fn finish_execution_with_encoder(
        &mut self,
        encode: impl FnOnce(
            &iroha_allocation::RetainedPayload<ExecutionResultCommitment>,
            &iroha_allocation::AllocationBudget,
        ) -> Result<
            iroha_allocation::ChargedBuffer<u8>,
            super::commitment::ResultPreimageError,
        >,
    ) -> Result<Option<Hash32>, PublicationError> {
        self.prepare_original_result()?;
        self.prepare_original_context_archive()?;
        let original = self
            .finishing
            .as_ref()
            .expect("original completed execution");
        let budget = self.state.ivm_execution_budget();
        let preimage = match encode(
            original.phase.ready().expect("original prepared result"),
            &budget,
        ) {
            Ok(preimage) => preimage,
            Err(error) => {
                // TODO: driver retry dispatch must wait on this retained original
                // capacity observation; diagnostic text is not a release source.
                let failure = if error.is_local_refusal() {
                    preparation::encoding_failure(&error)
                } else {
                    let reason = format!(
                        "original result encoding invariant failed; recovery required: {error}"
                    );
                    self.recovery = Some(reason.clone());
                    PublicationError::RecoveryRequired(reason)
                };
                self.finishing.as_mut().unwrap().encoding_refusal = Some(error);
                return Err(failure);
            }
        };
        let result = result_of_preimage(preimage.as_slice());
        let original = self.finishing.take().unwrap();
        let FinishingPhase::Ready(commitment) = original.phase else {
            unreachable!("encoded original result")
        };
        self.live = Some(Live {
            telemetry_origin: None,
            native_contexts: Some(
                original
                    .native_contexts
                    .expect("original preapply context projection"),
            ),
            block_hash: original.block_hash,
            height: original.height,
            header: original.header,
            availability: original.availability,
            source: original.source,
            phase: PublicationPhase::Executed {
                valid: original.valid,
                preimage,
            },
            overlay: Some(original.overlay),
            witness: Some(original.witness),
            result,
            _commitment: commitment,
            applied_config: original.applied_config,
            committee: original.committee,
            events: original.events,
        });
        Ok(Some(result))
    }

    /// Admit the keys of the committee scheduled for `height` into the driver's cryptography.
    fn admit_scheduled(&self, height: u64) {
        let Some(crypto) = &self.context.crypto else {
            return;
        };
        let Some(config) = self.scheduled(height) else {
            return;
        };
        for member in &config.epoch.committee {
            if let Err(error) =
                crypto.admit(member.validator.public_key(), &member.proof_of_possession)
            {
                iroha_logger::warn!(peer = %member.validator, ?error, "sumeragi: committee key not admitted");
            }
        }
    }

    /// Reconstruct authority from the independently authenticated committed source even
    /// during startup replay, using the exact authenticated BLS quorum.
    fn verify_prepared_certificate(
        &self,
        block: &AvailableBody,
        qc: &Qc,
    ) -> Result<(), PublicationError> {
        let view = self.state.try_view_once().map_err(|error| {
            if cfg!(all(test, sumeragi_core_mutation = "HC72"))
                && matches!(&error, crate::state::StateViewError::Busy(_))
            {
                PublicationError::Retryable(error.to_string())
            } else {
                PublicationError::from(error)
            }
        })?;
        // Only signed genesis selects the root instance. Its result-only R is not
        // needed here; reading an executed receipt would walk the entire history
        // on every new certificate. The sole durable reader still authenticates
        // this State cut's exact genesis hash, network, payload and signatures.
        #[cfg(all(test, sumeragi_core_mutation = "HC139"))]
        let instance = {
            let genesis = crate::sumeragi::certified_chain::committed_block(&view, 1)
                .map_err(|error| error.map_rejection(|error| error.to_string()))?;
            crate::sumeragi::node::root_instance(genesis.block(), &view.chain_id().to_string())?
        };
        #[cfg(not(all(test, sumeragi_core_mutation = "HC139")))]
        let instance = crate::sumeragi::certified_chain::CertifiedChain::new(&view)
            .map_err(|error| error.map_rejection(|error| error.to_string()))?
            .instance();
        let scheduled = view
            .world()
            .consensus_schedule()
            .ready(block.header().height)
            .map_err(|error| error.to_string())?;
        let config = scheduled
            .height_config()
            .map_err(|error| error.to_string())?;
        if block.source().instance() != instance || block.source().config() != &config {
            return Err(
                "available body does not bind the independently authenticated authority".into(),
            );
        }
        let crypto = self
            .context
            .crypto
            .as_ref()
            .ok_or("native committee crypto is not attached")?;
        // New scheduled keys must be admitted from their exact authenticated PoPs.
        for member in &scheduled.epoch.committee {
            crypto
                .admit(member.validator.public_key(), &member.proof_of_possession)
                .map_err(|error| error.to_string())?;
        }
        iroha_sumeragi::crypto::Verifier::new(
            &**crypto,
            &instance,
            &config.epoch.id,
            &config.committee,
        )
        .verify_qc(qc)
        .map_err(|error| {
            PublicationError::Retryable(format!("native quorum verification failed: {error:?}"))
        })
    }

    fn scheduled(&self, height: u64) -> Option<ScheduledAuthority> {
        let view = self.state.view();
        let schedule = view.world().consensus_schedule();
        schedule.ready(height).ok()?;
        Some(ScheduledAuthority {
            schedule: schedule.clone(),
            height,
        })
    }

    fn discard(&mut self, height: u64, keep: &[Hash32]) {
        self.retire_completed_payload(height);
        if self.recovery.is_some() || self.publication_pending() {
            return;
        }
        if self
            .live
            .as_ref()
            .is_some_and(|live| live.height == height && !keep.contains(&live.block_hash))
        {
            self.live = None;
        }
        if self.finishing.as_ref().is_some_and(|original| {
            original.height == height && !keep.contains(&original.block_hash)
        }) {
            self.finishing = None;
        }
        self.results
            .retain(|hash, (source, _)| source.height() != height || keep.contains(hash));
    }

    fn publication_pending(&self) -> bool {
        self.pending_commit.is_some()
            || self.live.as_ref().is_some_and(|live| {
                matches!(
                    live.phase,
                    PublicationPhase::EncodingCertificate { .. }
                        | PublicationPhase::Certifying { .. }
                        | PublicationPhase::Prepared { .. }
                        | PublicationPhase::Consuming
                )
            })
    }

    /// Pin the original execution and exactly one certified frame for durable append.
    #[cfg(test)]
    fn prepare(
        &mut self,
        block: &AvailableBody,
        qc: &Qc,
    ) -> Result<Option<Hash32>, PublicationError> {
        self.prepare_with_origin(block, qc, CommitTelemetryOrigin::Forward)
    }

    fn prepare_with_origin(
        &mut self,
        block: &AvailableBody,
        qc: &Qc,
        origin: CommitTelemetryOrigin,
    ) -> Result<Option<Hash32>, PublicationError> {
        self.prepare_with_encoder(block, qc, origin, |part, budget| {
            super::commitment::encode_certificate_part(
                part,
                budget,
                super::commitment::MAX_RESULT_PREIMAGE_BYTES,
            )
        })
    }

    fn prepare_with_encoder(
        &mut self,
        block: &AvailableBody,
        qc: &Qc,
        origin: CommitTelemetryOrigin,
        encode: impl FnMut(
            super::commitment::CertificatePart<'_>,
            &iroha_allocation::AllocationBudget,
        ) -> Result<
            iroha_allocation::ChargedBuffer<u8>,
            super::commitment::ResultPreimageError,
        >,
    ) -> Result<Option<Hash32>, PublicationError> {
        self.prepare_with_operations(block, qc, origin, encode, |worker, block, hash| {
            worker.run_execution(block, hash)
        })
    }

    /// The original cold operation runs only after normal certificate authentication.
    fn prepare_with_operations(
        &mut self,
        block: &AvailableBody,
        qc: &Qc,
        origin: CommitTelemetryOrigin,
        mut encode: impl FnMut(
            super::commitment::CertificatePart<'_>,
            &iroha_allocation::AllocationBudget,
        ) -> Result<
            iroha_allocation::ChargedBuffer<u8>,
            super::commitment::ResultPreimageError,
        >,
        execute: impl FnOnce(
            &mut Self,
            &AvailableBody,
            Hash32,
        ) -> Result<Option<Hash32>, PublicationError>,
    ) -> Result<Option<Hash32>, PublicationError> {
        if let Some(reason) = &self.recovery {
            return Err(PublicationError::RecoveryRequired(reason.clone()));
        }

        match catch_unwind(AssertUnwindSafe(|| {
            self.prepare_inner(block, qc, origin, &mut encode, execute)
        })) {
            Ok(result) => result.map_err(|error| match &self.recovery {
                Some(reason) => PublicationError::RecoveryRequired(reason.clone()),
                None => error,
            }),
            Err(_) => {
                let reason = "publication preparation panicked; recovery required".to_owned();
                self.recovery = Some(reason.clone());
                Err(PublicationError::RecoveryRequired(reason))
            }
        }
    }

    fn prepare_inner(
        &mut self,
        block: &AvailableBody,
        qc: &Qc,
        origin: CommitTelemetryOrigin,
        encode: &mut impl FnMut(
            super::commitment::CertificatePart<'_>,
            &iroha_allocation::AllocationBudget,
        ) -> Result<
            iroha_allocation::ChargedBuffer<u8>,
            super::commitment::ResultPreimageError,
        >,
        execute: impl FnOnce(
            &mut Self,
            &AvailableBody,
            Hash32,
        ) -> Result<Option<Hash32>, PublicationError>,
    ) -> Result<Option<Hash32>, PublicationError> {
        if let Some(pending) = &self.pending_commit {
            return if pending.matches(block, qc) && pending.telemetry_origin == origin {
                Ok(Some(pending.qc.result))
            } else {
                Err(PublicationError::Retryable(
                    "another committed decision is awaiting archive capture".into(),
                ))
            };
        }
        let block_hash = qc.block_hash;
        if qc.kind != iroha_sumeragi::message::VoteKind::Commit
            || qc.height != block.header().height
            || qc.instance != block.header().instance
            || qc.epoch != block.header().epoch
            || super::commitment::chain_hash(&iroha_sumeragi::preimage::block_hash_preimage(
                block.header(),
            )) != block_hash
        {
            return Err(PublicationError::Retryable(
                "commit certificate does not bind the exact requested block".into(),
            ));
        }
        // A published execution already owns this exact checked certificate; its old
        // schedule slot may have retired. Every new certificate is checked independently.
        let authenticated = self.live.as_ref().is_some_and(|live| {
            live.block_hash == block_hash
                && live.header == *block.header()
                && live.availability == *block.availability()
                && live.source == *block.source()
                && matches!(&live.phase,
                    PublicationPhase::Prepared { qc: original, .. }
                    | PublicationPhase::Published { qc: original, .. } if original == qc)
        });
        if !authenticated {
            match self.verify_prepared_certificate(block, qc) {
                Ok(()) => self.routing_refusal = None,
                Err(PublicationError::Deferred(reason)) => {
                    if !cfg!(all(test, sumeragi_core_mutation = "HC44")) {
                        self.routing_refusal = reason.execution().cloned();
                    }
                    return Err(PublicationError::Deferred(reason));
                }
                Err(error) => return Err(error),
            }
        }
        let reusable = self
            .live
            .as_ref()
            .is_some_and(|live| live.block_hash == block_hash);
        if !reusable {
            if self.publication_pending() {
                return Err(PublicationError::Retryable(
                    "cannot replace the original prepared publication".into(),
                ));
            }
            if !self.parent_applied(block) {
                return Err(PublicationError::Retryable(
                    "the committed block's parent is not applied".into(),
                ));
            }
            self.results.remove(&block_hash);
            let outcome = execute(self, block, block_hash);
            #[cfg(all(test, sumeragi_core_mutation = "HC65"))]
            let outcome = outcome.map_err(|error| PublicationError::Retryable(error.to_string()));
            if outcome?.is_none() {
                return Ok(None);
            }
        }
        let live = self
            .live
            .as_mut()
            .ok_or_else(|| PublicationError::Retryable("no executed overlay to prepare".into()))?;
        if live.header != *block.header()
            || live.availability != *block.availability()
            || live.source != *block.source()
        {
            return Err(PublicationError::Retryable(
                "prepared header differs from original execution".into(),
            ));
        }
        if live
            .telemetry_origin
            .is_some_and(|original| original != origin)
        {
            return Err(PublicationError::Retryable(
                "prepared execution telemetry origin cannot be replaced".into(),
            ));
        }
        match &live.phase {
            PublicationPhase::Prepared {
                staged,
                qc: original,
                ..
            }
            | PublicationPhase::Published {
                staged,
                qc: original,
            } => {
                if original != qc {
                    return Err(PublicationError::Retryable(
                        "prepared certificate cannot be replaced".into(),
                    ));
                }
                self.context.staging.stage(staged.clone());
                return Ok(Some(live.result));
            }
            PublicationPhase::Consuming => {
                return Err(PublicationError::Retryable(
                    "publication requires recovery".into(),
                ));
            }
            PublicationPhase::EncodingCertificate { qc: original, .. }
            | PublicationPhase::Certifying { qc: original, .. }
                if original != qc =>
            {
                return Err(PublicationError::Retryable(
                    "original certificate parts cannot be replaced".into(),
                ));
            }
            PublicationPhase::EncodingCertificate { .. }
            | PublicationPhase::Certifying { .. }
            | PublicationPhase::Executed { .. } => {}
        }
        // A disagreement reports the original result, never a fresh execution of the same source.
        if live.result != qc.result {
            return Ok(Some(live.result));
        }
        let budget = self.state.ivm_execution_budget();
        if let PublicationPhase::Executed { valid, .. } = &live.phase {
            live.overlay
                .as_ref()
                .ok_or_else(|| {
                    PublicationError::Retryable("original pending overlay was consumed".into())
                })?
                .verify_sumeragi_execution_witness(
                    valid.as_ref(),
                    live.witness
                        .as_ref()
                        .ok_or_else(|| {
                            PublicationError::RecoveryRequired(
                                "original witness disappeared before publication".into(),
                            )
                        })?
                        .wire(),
                )
                .map_err(PublicationError::Retryable)?;
        }
        live.telemetry_origin = Some(origin);
        if matches!(live.phase, PublicationPhase::Executed { .. }) {
            let PublicationPhase::Executed { valid, preimage } =
                std::mem::replace(&mut live.phase, PublicationPhase::Consuming)
            else {
                unreachable!("original executed phase")
            };
            live.phase = PublicationPhase::EncodingCertificate {
                valid,
                preimage,
                header_wire: None,
                qc_wire: None,
                availability_wire: None,
                qc: qc.clone(),
                refusal: None,
            };
        }
        if let PublicationPhase::EncodingCertificate {
            header_wire,
            qc_wire,
            availability_wire,
            refusal,
            ..
        } = &mut live.phase
        {
            for (slot, part) in [
                (
                    header_wire,
                    super::commitment::CertificatePart::Header(block.header()),
                ),
                (qc_wire, super::commitment::CertificatePart::Qc(qc)),
                (
                    availability_wire,
                    super::commitment::CertificatePart::Availability(&live.availability),
                ),
            ] {
                if slot.is_some() {
                    continue;
                }
                match encode(part, &budget) {
                    Ok(bytes) => {
                        *slot = Some(bytes);
                        *refusal = None;
                    }
                    Err(error) => {
                        let message = error.to_string();
                        if !error.is_local_refusal() {
                            self.recovery =
                                Some(format!("original certificate encoding failed: {message}"));
                        }
                        let failure = preparation::encoding_failure(&error);
                        *refusal = Some(error);
                        return Err(failure);
                    }
                }
            }
            let PublicationPhase::EncodingCertificate {
                valid,
                preimage,
                header_wire,
                qc_wire,
                availability_wire,
                qc,
                ..
            } = std::mem::replace(&mut live.phase, PublicationPhase::Consuming)
            else {
                unreachable!("original encoded parts")
            };
            live.phase = PublicationPhase::Certifying {
                valid,
                parts: Some(iroha_data_model::block::ChargedCertificateParts {
                    consensus_header: header_wire.expect("retained original header"),
                    commit_qc: qc_wire.expect("retained original QC"),
                    result_preimage: preimage,
                    availability: availability_wire.expect("retained original availability frame"),
                }),
                qc,
                refusal: None,
            };
        }
        let PublicationPhase::Certifying { parts, refusal, .. } = &mut live.phase else {
            unreachable!("original charged certificate parts")
        };
        // Reserve the physical block control before either original graph or certificate
        // owner is consumed. A refusal leaves the complete Certifying phase retryable.
        let shell = iroha_data_model::block::SharedSignedBlock::reserve(&budget)
            .map_err(|error| preparation::block_failure(&error))?;
        let certificate = match CommitCertificate::from_charged_owner(
            parts.take().expect("same retained buffers"),
            &budget,
        ) {
            Ok(certificate) => certificate,
            Err((original, error)) => {
                let message = error.to_string();
                if !error.is_local_refusal() {
                    self.recovery = Some(format!("original certificate source changed: {message}"));
                }
                let failure = preparation::certificate_failure(&error);
                *parts = Some(original);
                *refusal = Some(error);
                return Err(failure);
            }
        };
        let PublicationPhase::Certifying { valid, .. } =
            std::mem::replace(&mut live.phase, PublicationPhase::Consuming)
        else {
            unreachable!("original certificate phase")
        };
        // Move the original graph once. Staging is an inline immutable handle; every reader
        // retains this same physically funded control and independently checked certificate.
        // TODO: finish admission of the graph's nested execution/decode allocations.
        let committed = valid
            .with_commit_certificate(certificate)
            .commit_unchecked(shell)
            .unpack(|event| live.events.push(event.into()));
        let staged = StagedBlock {
            block_hash,
            executed: committed.shared().clone(),
        };
        live.phase = PublicationPhase::Prepared {
            committed,
            staged: staged.clone(),
            qc: qc.clone(),
            state_events: None,
        };
        self.context.staging.stage(staged);
        Ok(Some(live.result))
    }

    /// Publish the same prepared owner after its exact frame is durable.
    fn commit(
        &mut self,
        block: &AvailableBody,
        qc: &Qc,
    ) -> Result<AppliedConfig, PublicationError> {
        self.commit_with(block, qc, StateBlock::try_publish)
    }

    // One original State boundary. Tests inject failures on either side of actual visibility
    // without replacing validation, authorization, metadata preparation or its original owner.
    fn commit_with(
        &mut self,
        block: &AvailableBody,
        qc: &Qc,
        publish: impl FnOnce(&mut StateBlock<'s>) -> crate::state::StatePublicationOutcome,
    ) -> Result<AppliedConfig, PublicationError> {
        if let Some(reason) = &self.recovery {
            return Err(PublicationError::RecoveryRequired(reason.clone()));
        }

        match catch_unwind(AssertUnwindSafe(|| self.commit_inner(block, qc, publish))) {
            Ok(Err(error)) if self.recovery.is_some() => {
                let reason = format!("publication requires recovery: {error}");
                self.recovery = Some(reason.clone());
                Err(PublicationError::RecoveryRequired(reason))
            }
            Ok(result) => result,
            Err(_) => {
                let reason = "publication panicked; recovery required".to_owned();
                self.recovery = Some(reason.clone());
                Err(PublicationError::RecoveryRequired(reason))
            }
        }
    }

    fn commit_inner(
        &mut self,
        block: &AvailableBody,
        qc: &Qc,
        publish: impl FnOnce(&mut StateBlock<'s>) -> crate::state::StatePublicationOutcome,
    ) -> Result<AppliedConfig, PublicationError> {
        if let Some(pending) = &self.pending_commit {
            if !pending.matches(block, qc) {
                return Err("another committed decision is awaiting archive capture".into());
            }
            return self.finish_commit().map_err(Into::into);
        }
        let live = self
            .live
            .as_mut()
            .ok_or("commit without its prepared overlay")?;
        if live.block_hash != qc.block_hash
            || live.result != qc.result
            || live.header != *block.header()
            || live.availability != *block.availability()
            || live.source != *block.source()
        {
            return Err("commit differs from its original prepared execution".into());
        }
        match &live.phase {
            PublicationPhase::Published { qc: original, .. } if original == qc => {
                return Ok(live.applied_config.clone());
            }
            PublicationPhase::Prepared { qc: original, .. } if original == qc => {}
            _ => return Err("commit without its exact prepared certificate".into()),
        }
        let PublicationPhase::Prepared {
            committed,
            staged,
            state_events,
            ..
        } = &mut live.phase
        else {
            unreachable!("checked prepared phase")
        };
        if !cfg!(all(test, sumeragi_core_mutation = "HC62"))
            && (!iroha_data_model::block::SharedSignedBlock::ptr_eq(
                committed.shared(),
                &staged.executed,
            ) || !staged
                .executed
                .belongs_to(&self.state.ivm_execution_budget()))
        {
            self.recovery = Some("prepared block lost original shared execution custody".into());
            return Err("prepared block lost original shared execution custody".into());
        }
        let certificate = staged
            .executed
            .commit_certificate()
            .ok_or("prepared frame lost its certificate")?;
        if !certificate.admitted_to(&self.state.ivm_execution_budget()) {
            self.recovery = Some("prepared certificate lost its original pool custody".into());
            return Err("prepared certificate lost its original pool custody".into());
        }
        let overlay = live
            .overlay
            .as_mut()
            .ok_or("prepared publication lost its original overlay")?;
        if state_events.is_none() {
            // A normal authorization refusal retains the same original and can retry
            // after append. Metadata finalization itself is one-shot and may unwind.
            let native_execution = NativeExecutionAuthorization {
                telemetry_origin: live
                    .telemetry_origin
                    .expect("original prepared telemetry origin"),
                state: std::ptr::from_ref(self.state) as usize,
                tip: crate::state::native_execution_tip::NativeExecutionTipRecord {
                    height: live.header.height,
                    creation_time_ms: u64::try_from(
                        committed.as_ref().header().creation_time().as_millis(),
                    )
                    .expect("block creation time fits u64"),
                    iroha_hash: committed.as_ref().hash(),
                    core_hash: live.block_hash.0,
                    result: live.result.0,
                },
                parent: Some((live.header.parent_hash, live.header.parent_result)),
            };
            overlay.authorize_sumeragi_output_publication(
                committed,
                live.witness
                    .as_ref()
                    .ok_or_else(|| {
                        PublicationError::RecoveryRequired(
                            "original witness disappeared before publication".into(),
                        )
                    })?
                    .wire(),
                certificate,
                native_execution,
            )?;
            self.recovery =
                Some("finalizing original metadata; recovery required on failure".into());
            *state_events = Some(
                overlay
                    .apply_without_execution_with_sumeragi_commit(
                        committed,
                        certificate,
                        std::mem::take(&mut live.committee),
                    )
                    .map_err(|error| error.to_string())?,
            );
        }
        self.recovery = Some("publishing original State; recovery required on failure".into());
        match publish(overlay) {
            crate::state::StatePublicationOutcome::Published => {}
            crate::state::StatePublicationOutcome::Deferred(reason) => {
                let error = publication::original_refusal(reason);
                if !matches!(error, PublicationError::RecoveryRequired(_)) {
                    self.recovery = None;
                }
                return Err(error);
            }
            crate::state::StatePublicationOutcome::RecoveryRequired(reason) => {
                return Err(reason.to_string().into());
            }
        }
        let state_events = state_events
            .take()
            .expect("original finalized State events");
        // Retire only after the complete original State and its retained post-effects
        // have published. State's Drop releases siblings before refunds and notices.
        drop(live.overlay.take().expect("original published overlay"));
        let PublicationPhase::Prepared {
            committed,
            staged,
            qc,
            ..
        } = std::mem::replace(&mut live.phase, PublicationPhase::Consuming)
        else {
            unreachable!("original prepared owner")
        };
        self.pending_commit = Some(PendingCommit {
            telemetry_origin: live
                .telemetry_origin
                .expect("original prepared telemetry origin"),
            native_contexts: live
                .native_contexts
                .take()
                .expect("original preapply context projection"),
            archive_refusal: None,
            header: live.header.clone(),
            availability: live.availability.clone(),
            source: live.source.clone(),
            qc: qc.clone(),
            state_hash: committed.as_ref().hash(),
            next: live.applied_config.clone(),
            hashes: committed
                .as_ref()
                .external_entrypoints_slice()
                .iter()
                .map(TransactionEntrypoint::hash)
                .collect(),
            events: std::mem::take(&mut live.events)
                .into_iter()
                .chain(state_events)
                .collect(),
        });
        live.phase = PublicationPhase::Published { staged, qc };
        self.recovery = None;
        self.finish_commit().map_err(Into::into)
    }

    /// Retry durable archive capture without publishing State or notifications twice.
    fn finish_commit(&mut self) -> Result<AppliedConfig, PublicationError> {
        let pending = self
            .pending_commit
            .as_ref()
            .ok_or_else(|| "no committed decision is awaiting completion".to_owned())?;
        let capture = (|| -> Result<(), PublicationError> {
            let view = self.state.view();
            let height = u64::try_from(view.height()).map_err(|_| "State height exceeds u64")?;
            if height != pending.header.height
                || view.latest_block_hash() != Some(pending.state_hash)
            {
                return Err("State changed while committed archive capture was pending".into());
            }
            self.context
                .native_context_archive
                .publish(&pending.native_contexts)
                .map_err(|error| {
                    // The complete original projection was already admitted before State
                    // publication. This path borrows those bytes and performs only namespace
                    // and immutable I/O checks; it has no allocation release source to invent.
                    format!("original native context archive publication failed: {error}")
                })?;
            if let Some(archives) = &self.archives {
                archives.capture(&view)?;
            }
            Ok(())
        })();
        if let Err(error) = capture {
            self.pending_commit
                .as_mut()
                .expect("retained committed publication")
                .archive_refusal = match &error {
                PublicationError::Deferred(original) => Some(original.clone()),
                _ => None,
            };
            return Err(error);
        }
        let pending = self
            .pending_commit
            .take()
            .ok_or_else(|| "committed completion disappeared".to_owned())?;
        let height = pending.header.height;
        self.completed_replay = None;
        self.applied = (height, pending.qc.block_hash);
        self.context
            .applied_watch
            .publish(height, pending.state_hash);
        self.results
            .retain(|_, (source, _)| source.height() > height);
        if let Some(queue) = &self.queue {
            queue.remove_committed_hashes(pending.hashes, None);
        }
        self.admit_scheduled(height.saturating_add(1));
        self.admit_scheduled(height.saturating_add(2));
        for event in pending.events {
            let _ = self.context.events.send(event);
        }
        Ok(pending.next)
    }

    /// Build a payload for `(height, view)` over the applied tip (§6.10).
    fn build(
        &mut self,
        height: u64,
        view: u64,
        max_bytes: u32,
        exec_budget_ms: u32,
    ) -> Result<Option<PayloadBytes>, PublicationError> {
        // The inner body acquires and retires its original State view and Queue
        // guards before same-pool refund callbacks can reenter either owner.
        let budget = self.state.ivm_execution_budget();
        budget.with_deferred_refund_notifications(|_| {
            self.build_with_original_refund_scope(height, view, max_bytes, exec_budget_ms)
        })
    }

    /// Borrow current source ownership inside the original operation pool's refund scope.
    fn build_with_original_refund_scope(
        &mut self,
        height: u64,
        view: u64,
        max_bytes: u32,
        exec_budget_ms: u32,
    ) -> Result<Option<PayloadBytes>, PublicationError> {
        if let Some(reason) = &self.recovery {
            self.completed_payload = None;
            return Err(PublicationError::RecoveryRequired(reason.clone()));
        }
        if self.pending_commit.is_some()
            || self.publication_pending()
            || height != self.applied.0.saturating_add(1)
        {
            self.completed_payload = None;
            iroha_logger::debug!(
                height,
                view,
                applied_height = self.applied.0,
                pending_commit = self.pending_commit.is_some(),
                publication_pending = self.publication_pending(),
                "sumeragi: payload selection awaits its original applied parent"
            );
            return Ok(None);
        }
        if self.payload_build.as_ref().is_some_and(|build| {
            !build
                .scope
                .matches_request(height, view, max_bytes, exec_budget_ms)
        }) {
            self.payload_build = None;
        }
        // Proven input withdrawal retires storage even if an unrelated source probe
        // subsequently refuses. This expiry-only check creates no lending authority.
        self.partial_payload_expiry_wait();
        self.payload_refusal = None;
        let original_generation = self.state.state_view_generation();
        let current_view = match self.state.try_view_once() {
            Ok(view) => view,
            Err(crate::state::StateViewError::Busy(release)) => {
                return Err(PublicationError::Deferred(
                    PublicationDeferral::StateViewBusy(release),
                ));
            }
            Err(error) => {
                self.completed_payload = None;
                return Err(PublicationError::Retryable(error.to_string()));
            }
        };
        // Certified lane blocks come first: they reserve their share of the block's capacity
        // (`specs/sumeragi_lanes.md` §4.2).
        let merges = match lanes::merge::propose(&current_view, &*self.context.lane_blocks, height)
        {
            Ok(merges) => {
                self.routing_refusal = None;
                merges
            }
            Err(error) => {
                if let crate::execution_attempt::ExecutionAttemptError::Deferred(reason) = &error {
                    self.routing_refusal = Some(reason.clone());
                }
                let reason = format!("lane storage during payload selection: {error}");
                if matches!(
                    error.io_kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) {
                    return Err(PublicationError::Retryable(reason));
                }
                self.recovery = Some(reason.clone());
                return Err(PublicationError::RecoveryRequired(reason));
            }
        };
        // Original lane policy/refusal custody is resolved before the canonical read.
        // Every successful build and lend then authenticates the complete physical parent.
        let parent = {
            match std::num::NonZeroUsize::new(current_view.height()) {
                Some(height) => current_view
                    .canonical_history()
                    .executed_block(height, |_, _| Ok(()))
                    .map(Some),
                None => Ok(None),
            }
        }
        .map_err(|error| match error {
            crate::execution_attempt::ExecutionAttemptError::Deferred(original) => {
                self.payload_refusal =
                    Some(payload::PayloadError::RoutingDeferred(original.clone()));
                PublicationError::Deferred(original.into())
            }
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                self.completed_payload = None;
                PublicationError::Retryable(error.to_string())
            }
        })?;
        let Some(parent) = parent else {
            self.completed_payload = None;
            iroha_logger::debug!(
                height,
                view,
                "sumeragi: payload selection has no published parent"
            );
            return Ok(None);
        };
        let schedule = current_view.world().consensus_schedule();
        if schedule.ready(height).is_err() {
            self.completed_payload = None;
            iroha_logger::debug!(
                height,
                view,
                "sumeragi: payload selection has no authenticated scheduled authority"
            );
            return Ok(None);
        }
        let scheduled = ScheduledAuthority {
            schedule: schedule.clone(),
            height,
        };
        if self.queue.is_none() {
            self.completed_payload = None;
            return Ok(None);
        }
        let scope = OriginalPayloadScope::capture(
            &current_view,
            original_generation,
            height,
            view,
            max_bytes,
            exec_budget_ms,
        );
        if self.retained_payload_build_is_current(scope, &parent, &current_view, &merges)? {
            return self.finish_payload_build();
        }
        if merges.merges.is_empty() {
            if let Some(original) =
                self.reusable_completed_payload(scope, &parent, &current_view)?
            {
                return Ok(original);
            }
        } else {
            // Newly available mandatory lane work withdraws Queue-only reuse authority.
            self.completed_payload = None;
        }
        let queue = self.queue.as_ref().expect("original queue checked above");
        let max_bytes = usize::try_from(max_bytes).unwrap_or(usize::MAX);
        let selection: Option<crate::queue::PendingPayloadSelection> =
            queue.begin_pending_payload_selection(self.state, original_generation);
        let mut selected = match payload::select(
            self.state,
            queue,
            max_bytes.saturating_sub(PAYLOAD_OVERHEAD),
            merges.transactions,
        ) {
            Ok(selected) => {
                self.routing_refusal = None;
                selected
            }
            Err(reason) => {
                let message = reason.to_string();
                self.routing_refusal = Some(reason);
                return Err(PublicationError::Retryable(message));
            }
        };
        iroha_logger::debug!(
            height,
            view,
            transactions = selected.len(),
            lane_merges = merges.merges.len(),
            "sumeragi: payload selection completed"
        );
        // Only real work may activate the pulse signer. A pulse cannot create a block.
        if selected.is_empty() && merges.merges.is_empty() {
            #[cfg(test)]
            queue.record_empty_native_payload();
            return Ok(None);
        }
        let assembly = Assembly {
            parent: &parent,
            view,
            cadence: Duration::from_millis(scheduled.params.block_time_ms),
        };
        while !selected.is_empty() || !merges.merges.is_empty() {
            // Every selected Queue input retains its original admission receipt,
            // including mixed sources. Lane-bearing completion retains this same
            // source and rechecks its actual ranges and original lease on every lend.
            let pending_inputs = match selection {
                Some(selection) => queue
                    .capture_pending_payload_lease(
                        self.state,
                        selection,
                        &current_view,
                        &selected,
                        &self.state.ivm_execution_budget(),
                    )
                    .map_err(payload_owner::lease_admission_error)?,
                None => None,
            };
            let block =
                match payload::assemble_with_merges(self.state, assembly, &selected, &merges) {
                    Ok(block) => {
                        self.routing_refusal = None;
                        block
                    }
                    Err(payload::PayloadError::RoutingDeferred(reason)) => {
                        let message = reason.to_string();
                        self.routing_refusal = Some(reason);
                        return Err(PublicationError::Retryable(message));
                    }
                    Err(error) => {
                        match &error {
                            payload::PayloadError::StakingPreparation(
                                crate::state::EvidencePreparationError::Admission(refusal),
                            ) => {
                                self.routing_refusal = Some(refusal.clone().into());
                                self.payload_refusal = Some(error.clone());
                            }
                            payload::PayloadError::StakingPreparation(_)
                            | payload::PayloadError::StakingAdmission(_) => {
                                self.payload_refusal = Some(error.clone());
                            }
                            _ => {}
                        }
                        iroha_logger::warn!(height, %error, "sumeragi: payload assembly failed");
                        return Err(PublicationError::Retryable(format!(
                            "payload assembly: {error}"
                        )));
                    }
                };
            match block.resultless_proposal_wire_len() {
                Ok(length) if length <= max_bytes => {
                    let source = GlobalPayloadSource {
                        pending_inputs,
                        block,
                    };
                    self.payload_build = Some(GlobalPayloadBuild {
                        scope,
                        job: super::driver::payload_build::PayloadBuild::new(
                            source,
                            self.state.ivm_execution_budget(),
                            max_bytes,
                        ),
                        preparation_refusal: None,
                    });
                    return self.finish_payload_build();
                }
                Ok(_) if !selected.is_empty() => {
                    selected.pop();
                }
                Ok(_) => {
                    return Err(PublicationError::Retryable(
                        "mandatory lane merges exceed payload limit".into(),
                    ));
                }
                Err(error) => {
                    return Err(PublicationError::RecoveryRequired(format!(
                        "canonical payload length: {error}"
                    )));
                }
            }
        }
        Ok(None)
    }

    fn finish_payload_build(&mut self) -> Result<Option<PayloadBytes>, PublicationError> {
        let GlobalPayloadBuild {
            scope,
            mut job,
            preparation_refusal,
        } = self.payload_build.take().ok_or_else(|| {
            PublicationError::RecoveryRequired("payload source disappeared".into())
        })?;
        let preparation: Result<(), GlobalPayloadPreparationError> = {
            #[cfg(not(all(test, sumeragi_core_mutation = "HC128")))]
            {
                job.prepare_source()
            }
            #[cfg(all(test, sumeragi_core_mutation = "HC128"))]
            {
                Ok(())
            }
        };
        if let Err(error) = preparation {
            use super::driver::payload_build::SourcePreparationError;
            use iroha_allocation::ChargedBufferError;
            use iroha_data_model::block::BlockSignatureCustodyError;
            // The original typed owner remains in the job. The driver receives the
            // same refusal/ReleaseWait, not an error string standing in for custody.
            let publication = match &error {
                SourcePreparationError::Source(
                    BlockSignatureCustodyError::ControlAdmission(original)
                    | BlockSignatureCustodyError::Buffer(ChargedBufferError::Admission(original)),
                ) => PublicationError::Deferred(PublicationDeferral::Execution(
                    original.clone().into(),
                )),
                SourcePreparationError::Source(BlockSignatureCustodyError::ControlAllocation(
                    original,
                )) => PublicationError::Deferred(PublicationDeferral::SharedControl(*original)),
                _ => PublicationError::RecoveryRequired(format!(
                    "original local payload signature preparation: {error:?}"
                )),
            };
            self.payload_build = Some(GlobalPayloadBuild {
                scope,
                job,
                preparation_refusal: Some(error),
            });
            return Err(publication);
        }
        // Only a new actual preparation probe may retire its previous refusal owner.
        drop(preparation_refusal);
        if job.source().block.lane_merge().is_some() {
            let result = job.finish_retained(
                |source| source.block.resultless_proposal_wire_len(),
                |source, writer| source.block.write_resultless_proposal_wire(writer),
            );
            #[cfg(not(all(test, sumeragi_core_mutation = "HC199")))]
            {
                // The actual source, mixed Queue lease, signature custody and
                // immutable output retire together. Fresh source checks precede
                // each retry; a Core build deadline does not recreate this work.
                self.payload_build = Some(GlobalPayloadBuild {
                    scope,
                    job,
                    preparation_refusal: None,
                });
            }
            #[cfg(all(test, sumeragi_core_mutation = "HC199"))]
            {
                // Restore only the completed-stage loss; refused original work
                // remains retained exactly as in the unmutated implementation.
                if result.is_err() {
                    self.payload_build = Some(GlobalPayloadBuild {
                        scope,
                        job,
                        preparation_refusal: None,
                    });
                }
            }
            return match result {
                Ok(payload) => {
                    iroha_logger::debug!(
                        height = scope.height,
                        view = scope.view,
                        bytes = payload.as_slice().len(),
                        "sumeragi: original funded lane payload build completed"
                    );
                    Ok(Some(payload))
                }
                Err(error) => {
                    let reason = format!("canonical payload admission: {error:?}");
                    Err(if error.is_local_refusal() {
                        PublicationError::Retryable(reason)
                    } else {
                        PublicationError::RecoveryRequired(reason)
                    })
                }
            };
        }
        match job.finish(
            |source| source.block.resultless_proposal_wire_len(),
            |source, writer| source.block.write_resultless_proposal_wire(writer),
        ) {
            Ok((source, payload)) => {
                iroha_logger::debug!(
                    height = scope.height,
                    view = scope.view,
                    bytes = payload.as_slice().len(),
                    "sumeragi: original funded payload build completed"
                );
                self.retain_completed_payload(scope, source.pending_inputs, &payload);
                Ok(Some(payload))
            }
            Err((job, error)) => {
                let retry = error.is_local_refusal();
                self.payload_build = Some(GlobalPayloadBuild {
                    scope,
                    job,
                    preparation_refusal: None,
                });
                let reason = format!("canonical payload admission: {error:?}");
                Err(if retry {
                    PublicationError::Retryable(reason)
                } else {
                    PublicationError::RecoveryRequired(reason)
                })
            }
        }
    }

    /// Retain queue ownership after a rejected proposal until the offending original
    /// transaction can be proved without forging a replacement native source header.
    fn reject(&mut self, height: u64, view: u64, block_hash: Hash32) {
        if self
            .completed_payload
            .as_ref()
            .is_some_and(|original| original.scope.height == height && original.scope.view == view)
        {
            self.completed_payload = None;
        }
        if self.payload_build.as_ref().is_some_and(|original| {
            original.scope.height == height
                && original.scope.view == view
                && original.job.is_completed()
        }) {
            self.payload_build = None;
        }
        if self.recovery.is_some() || self.publication_pending() {
            return;
        }
        if self.signature_decode.as_ref().is_some_and(|attempt| {
            attempt.block_hash == block_hash
                && attempt.source.header().height == height
                && attempt.source.header().origin_view == view
        }) {
            // Explicit rejection retires only this original partial decode and its source.
            self.signature_decode = None;
            self.routing_refusal = None;
        }
        if self.quarantine_context.is_some_and(|checked| {
            (checked.height, checked.view, checked.block_hash) == (height, view, block_hash)
        }) {
            self.quarantine_context = None;
        }
        // TODO: an admission-isolation primitive must identify the exact offending transaction
        // under the retained original source before removal can be authorized. Subset execution
        // with a newly synthesized header is not the original consensus source.
    }
}

/// The iroha header of a decoded payload must match the certified core header.
fn proposal_matches_header(header: IrohaHeader, block: &AvailableBody) -> bool {
    header.height().get() == block.header().height
        && header.view_change_index() == block.header().origin_view
}

/// A deterministically invalid block at `height`, logged with its reason.
fn invalid(height: u64, reason: &dyn std::fmt::Display) -> ExecOutcome {
    iroha_logger::warn!(height, %reason, "sumeragi: block is invalid");
    ExecOutcome::Invalid
}

/// Internal attempts retain exact local sources until the terminal execution report.
fn execution_report(outcome: Result<Option<Hash32>, PublicationError>) -> ExecOutcome {
    match outcome {
        Ok(Some(result)) => ExecOutcome::Valid(result),
        Ok(None) => ExecOutcome::Invalid,
        Err(error) => ExecOutcome::Failed(error.to_string()),
    }
}

/// A consuming validation unwind lost its original graph and cannot request a retry.
fn validation_result<T>(outcome: std::thread::Result<T>) -> Result<T, PublicationError> {
    outcome.map_err(|_| {
        let reason = "block validation panicked".into();
        if cfg!(all(test, sumeragi_core_mutation = "HC129")) {
            PublicationError::Retryable(reason)
        } else {
            PublicationError::RecoveryRequired(reason)
        }
    })
}

/// Log a completed invalid attempt without manufacturing a local refusal.
fn invalid_attempt(
    height: u64,
    reason: &dyn std::fmt::Display,
) -> Result<Option<Hash32>, PublicationError> {
    invalid(height, reason);
    Ok(None)
}

/// Custody allocator refusal is local; a semantic lane transition defect is deterministic.
fn classify_lane_step(
    height: u64,
    error: &lanes::step::LaneStepError,
) -> Result<Option<Hash32>, PublicationError> {
    match error {
        lanes::step::LaneStepError::Deferred(original)
            if original.reason() == ivm::error::ExecutionDeferral::LocalInvariantViolation =>
        {
            Err(PublicationError::RecoveryRequired(original.to_string()))
        }
        lanes::step::LaneStepError::Deferred(original) => {
            Err(PublicationError::Deferred(original.clone().into()))
        }
        _ => invalid_attempt(height, error),
    }
}

/// A direct local refusal remains typed; completed semantic rejection is invalid.
fn classify(height: u64, error: &BlockValidationError) -> Result<Option<Hash32>, PublicationError> {
    preparation::validation_failure(error).map_or_else(|| invalid_attempt(height, error), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Empty input cannot obtain available custody; a genuinely available zero-transaction
    /// carrier is invalid before any execution overlay or state publication is created.
    #[test]
    fn empty_and_encoded_zero_transaction_payloads_are_invalid_without_state_work() {
        use iroha_sumeragi::{
            availability::PayloadBytes, message::ByteAdmissionError, preimage::payload_hash,
        };

        publication_tests::with_worker(|chain, worker, _blocks, _events| {
            let original = publication_tests::proposal(chain, worker);
            let state_height = worker.state.view().height();
            let before = worker.state.ivm_execution_budget().reserved_bytes();
            let budget = worker.state.ivm_execution_budget();
            let empty = iroha_allocation::ChargedBuffer::new(0, &budget).unwrap();
            let (empty_owner, error) = PayloadBytes::from_charged(empty, &budget)
                .err()
                .expect("empty payload never obtains available custody");
            assert!(matches!(error, ByteAdmissionError::Length { length: 0 }));
            assert_eq!(worker.state.view().height(), state_height);
            assert!(worker.live.is_none());
            assert!(worker.finishing.is_none());
            drop(empty_owner);
            assert_eq!(worker.state.ivm_execution_budget().reserved_bytes(), before);

            let proposal = payload::decode(original.payload().as_slice()).unwrap();
            let zero_transaction_wire =
                iroha_data_model::block::builder::BlockBuilder::new(proposal.header())
                    .build(iroha_data_model::block::BlockSignatures::default())
                    .encode_wire()
                    .unwrap();
            let mut header = original.header().clone();
            header.payload_hash = payload_hash(
                &**worker.context.crypto.as_ref().unwrap(),
                &zero_transaction_wire,
            );
            header.payload_len = u32::try_from(zero_transaction_wire.len()).unwrap();
            let block = chain.author_payload(header, zero_transaction_wire);
            let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
            assert!(matches!(
                worker.execute(&block, hash),
                Some(ExecOutcome::Invalid)
            ));
            assert_eq!(
                worker.state.view().height(),
                state_height,
                "no synthesized block or overlay committed"
            );
            assert!(worker.live.is_none());
            assert!(worker.finishing.is_none());
            assert!(worker.context.staging.get(&hash).is_none());
        });
    }

    #[test]
    fn lane_custody_allocation_refusal_is_local_and_semantic_errors_remain_invalid() {
        use lanes::step::LaneStepError;
        assert!(matches!(
            execution_report(classify_lane_step(
                2,
                &LaneStepError::Deferred(
                    ivm::error::ExecutionDeferral::AllocationUnavailable.into()
                ),
            )),
            ExecOutcome::Failed(_)
        ));
        for error in [
            LaneStepError::Custody(lanes::step::CustodyViolation::StakeBinding),
            LaneStepError::NotAdvanced,
            LaneStepError::MissingLane(iroha_model_base::topology::LaneId::new(1)),
        ] {
            assert!(matches!(
                execution_report(classify_lane_step(2, &error)),
                ExecOutcome::Invalid
            ));
        }
    }

    #[test]
    fn completed_validation_returns_the_same_original_funded_owner() {
        let budget = iroha_allocation::AllocationBudget::new(4096);
        let mut original = iroha_allocation::ChargedBuffer::<u8>::new(127, &budget).unwrap();
        original.append(&[0x5a; 127]).unwrap();
        let pointer = original.as_slice().as_ptr();
        let retained = budget.reserved_bytes();
        assert!(retained > 0);
        let returned = validation_result(Ok(original)).unwrap();
        assert_eq!(returned.as_slice().as_ptr(), pointer);
        assert_eq!(returned.as_slice(), &[0x5a; 127]);
        assert!(returned.belongs_to(&budget));
        assert_eq!(budget.reserved_bytes(), retained);
        drop(returned);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn consuming_validation_unwind_requires_recovery_after_original_owner_is_lost() {
        let budget = iroha_allocation::AllocationBudget::new(4096);
        let original = iroha_allocation::ChargedBuffer::<u8>::new(127, &budget).unwrap();
        assert!(budget.reserved_bytes() > 0);
        let caught: std::thread::Result<()> = catch_unwind(AssertUnwindSafe(move || {
            drop(original);
            panic!("controlled consuming validation unwind");
        }));
        assert_eq!(
            budget.reserved_bytes(),
            0,
            "the consumed graph is already lost"
        );
        let error = validation_result(caught).unwrap_err();
        assert!(matches!(error, PublicationError::RecoveryRequired(reason)
            if reason == "block validation panicked"));
    }

    /// Local conditions are retried (`Failed`); a property of the block is `Invalid`.
    #[test]
    fn classification_table() {
        let budget = iroha_allocation::AllocationBudget::new(1);
        let occupied = budget.try_reserve_bytes(1).unwrap();
        let original = budget.try_reserve_bytes(1).unwrap_err();
        let failure = BlockValidationError::ExecutionDeferred(original.clone().into());
        let Err(PublicationError::Deferred(source)) = classify(2, &failure) else {
            panic!("direct block validation keeps the original pool refusal");
        };
        assert_eq!(source.allocation_refusal(), Some(&original));
        let failure = lanes::step::LaneStepError::Deferred(original.clone().into());
        let Err(PublicationError::Deferred(source)) = classify_lane_step(2, &failure) else {
            panic!("direct lane completion keeps the original pool refusal");
        };
        assert_eq!(source.allocation_refusal(), Some(&original));
        drop(occupied);
        let local = [
            BlockValidationError::LaneStorage(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "original lane read waits for capacity",
            )),
            BlockValidationError::StateStorageAdmission(
                mv::storage::AdmittedStorageError::Changed.into(),
            ),
            BlockValidationError::EvidencePreparation(
                crate::state::EvidencePreparationError::Allocator {
                    requested_bytes: 64,
                },
            ),
            BlockValidationError::ExecutionDeferred(
                ivm::error::ExecutionDeferral::ActiveMemoryCapacity.into(),
            ),
            BlockValidationError::DaIndexHydration("cold".into()),
            BlockValidationError::LocalStorageRecoveryRequired {
                reason: "disk".into(),
            },
        ];
        for error in &local {
            assert!(
                matches!(execution_report(classify(2, error)), ExecOutcome::Failed(_)),
                "{error:?} is local"
            );
        }
        let invalid = [
            BlockValidationError::InvalidGenesis(crate::block::InvalidGenesisError::InvalidHeader),
            BlockValidationError::ExecutionContextInvalid("bad".into()),
            BlockValidationError::HasCommittedTransactions,
        ];
        for error in &invalid {
            assert!(
                matches!(execution_report(classify(2, error)), ExecOutcome::Invalid),
                "{error:?} is a property of the block"
            );
        }
    }
}

#[cfg(test)]
#[path = "executor_validation_refusal_tests.rs"]
mod validation_refusal_tests;

#[cfg(test)]
#[path = "executor_decoded_custody_tests.rs"]
mod decoded_custody_tests;

#[cfg(test)]
mod archive_tests;
#[cfg(test)]
#[path = "executor_publication_tests.rs"]
mod publication_tests;

#[cfg(test)]
mod native_execution_authorization_tests {
    use super::*;

    #[test]
    fn original_execution_authorization_is_bound_to_its_actual_state() {
        use crate::{kura::Kura, query::store::LiveQueryStore, state::World};
        let original = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let foreign = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let token = NativeExecutionAuthorization {
            telemetry_origin: CommitTelemetryOrigin::Forward,
            state: std::ptr::from_ref(&original) as usize,
            tip: crate::state::native_execution_tip::NativeExecutionTipRecord {
                height: 1,
                creation_time_ms: 0,
                iroha_hash: iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                    b"origin identity test",
                )),
                core_hash: [1; 32],
                result: [2; 32],
            },
            parent: None,
        };
        assert!(token.for_state(&original).is_ok());
        assert!(token.for_state(&foreign).is_err());
    }
}

#[cfg(test)]
#[path = "executor_payload_refusal_tests.rs"]
mod payload_refusal_tests;

#[cfg(test)]
#[path = "executor_local_signature_preparation_tests.rs"]
mod local_signature_preparation_tests;

#[cfg(test)]
#[path = "executor_amx_retry_tests.rs"]
mod amx_retry_tests;

#[cfg(test)]
mod shutdown_tests;

#[cfg(test)]
#[path = "executor_amx_intent_tests.rs"]
mod amx_intent_tests;
