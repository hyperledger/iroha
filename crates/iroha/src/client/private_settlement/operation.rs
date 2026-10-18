//! Durable orchestration of caller-retained prepared artifacts; no witness serialization.

use super::*;
use crate::workflow::{
    BuiltStepPayload, CommittedOutcome, Digest32, DispatchOutcome, DriverIdentityV1, RoundContext,
    RoundRecovery, RoundReport, RoundStatusReport, SignedStepTransaction, StepContext,
    StepDescriptorV1, StepFailure, SystemWorkflowClock, TransactionIdentityV1, WorkflowAccount,
    WorkflowBindingV1, WorkflowDriver, WorkflowEngine, WorkflowError, WorkflowErrorCode,
    WorkflowFuture, WorkflowHandle, WorkflowId, WorkflowJournalV1, WorkflowLedger, WorkflowPlanV1,
    WorkflowProgressV1, WorkflowRunOptions, WorkflowStorage, WorkflowStorageDurability,
    domain_digest,
};
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    sumeragi_finality::{FinalityError, FinalityReadError, SumeragiFinalityVerifier},
    transaction::FeeChargeKind,
};
use std::{
    num::NonZeroU16,
    sync::{Arc, Mutex},
};

mod observation;
mod phases;
mod worker;
use observation::SettlementLedger;
use phases::{OnlinePhases, SettlementPhases};
pub use worker::run_private_settlement_worker;

const AVAILABILITY: usize = 0;
const PREPARE: usize = 1;
const REGISTER: usize = 2;
const COMMIT: usize = 3;
const FINALIZE: usize = 4;
// 255 fixed-shape BLS certificates fit well below this original transcript ceiling.
// The exact maximum-size fixture is the contract; restricted materials never enter it.
const CERTIFICATE_TRANSCRIPT_BYTES: u32 = 1_048_576;

/// Original restricted prepared artifacts retained by the caller across restart.
///
/// This object accepts proof bytes and encrypted audit capsules, never plaintext
/// witnesses or spending keys. Supply the same artifacts again when reopening the
/// operation. Its journal binds exact artifact digests without copying them into storage.
/// Structural validation is not a local proof-verification claim: produce these artifacts
/// with the existing native settlement prover; committees independently verify every proof.
#[derive(Clone)]
pub struct PrivateSettlementRequest(Arc<Prepared>);
struct Prepared {
    materials: Vec<PrivateSettlementProvisionalLegMaterialV1>,
    endpoints: Vec<Vec<Url>>,
    max_carrier_bytes: u64,
    digest: Digest32,
}
impl std::fmt::Debug for PrivateSettlementRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateSettlementRequest")
            .field("bundle_id", &self.manifest().bundle_id)
            .field("legs", &self.0.materials.len())
            .finish_non_exhaustive()
    }
}
impl PrivateSettlementRequest {
    /// Validate exact provisional artifacts and their roster-aligned transport endpoints.
    ///
    /// `max_carrier_bytes` is the active governed limit; no larger protocol ceiling
    /// is silently substituted. Endpoints may be updated on resume; original authority
    /// and all cryptographic/material bindings remain fixed.
    /// # Errors
    /// Incomplete/substituted material, unsupported fees, endpoints or carrier bound.
    pub fn new(
        materials: Vec<PrivateSettlementProvisionalLegMaterialV1>,
        endpoints: Vec<Vec<Url>>,
        max_carrier_bytes: u64,
    ) -> std::result::Result<Self, PrivateSettlementError> {
        let first = materials.first().ok_or(PrivateSettlementError::Binding)?;
        first
            .manifest
            .validate_provisional()
            .map_err(|_| PrivateSettlementError::Binding)?;
        if materials.len() != first.manifest.legs.len()
            || endpoints.len() != materials.len()
            || !(1..=PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1 as u64).contains(&max_carrier_bytes)
            || first
                .manifest
                .public_fee_intent
                .charge_limits()
                .iter()
                .any(|limit| limit.kind == FeeChargeKind::PipelineGas)
        {
            return Err(PrivateSettlementError::Binding);
        }
        let mut bindings = Vec::with_capacity(materials.len());
        for (index, (material, endpoints)) in materials.iter().zip(&endpoints).enumerate() {
            material
                .validate()
                .map_err(|_| PrivateSettlementError::Binding)?;
            validate_private_settlement_committee_endpoints_v1(endpoints)
                .map_err(|_| PrivateSettlementError::Binding)?;
            if material.manifest != first.manifest
                || usize::from(material.statement.leg_ordinal) != index
            {
                return Err(PrivateSettlementError::Binding);
            }
            bindings.push((material.payload_digest()?, material.availability_body));
        }
        let bytes =
            norito::encode_canonical(&(first.manifest.clone(), bindings, max_carrier_bytes))?;
        let digest = domain_digest(b"iroha:private-settlement:prepared-request:v1\0", &[&bytes]);
        Ok(Self(Arc::new(Prepared {
            materials,
            endpoints,
            max_carrier_bytes,
            digest,
        })))
    }
    /// Borrow the exact original prepared artifacts for advanced audit and transport inspection.
    ///
    /// These contain public statements and proofs plus encrypted outputs/audit capsules. They
    /// never contain a wallet witness, spending key or plaintext audit opening. This structural
    /// request accessor grants no verification or settlement authority and creates no copy.
    #[must_use]
    pub fn materials(&self) -> &[PrivateSettlementProvisionalLegMaterialV1] {
        &self.0.materials
    }

    /// Public intent skeleton bound to the exact original proof/capsule artifacts.
    #[must_use]
    pub fn manifest(&self) -> &AtomicPrivateSettlementV1 {
        &self.0.materials[0].manifest
    }
    fn plan(&self) -> WorkflowPlanV1 {
        let round = |label| {
            StepDescriptorV1::offchain_round(label, self.0.digest, true, 0, 0)
                .with_max_transcript_bytes(CERTIFICATE_TRANSCRIPT_BYTES)
        };
        WorkflowPlanV1 {
            kind: crate::workflow::WorkflowKindV1::PrivateSettlement,
            instance: hex::encode(self.manifest().bundle_id.as_ref()),
            driver: driver_identity(),
            request_context_digest: self.0.digest,
            steps: vec![
                round("availability"),
                round("prepare"),
                StepDescriptorV1::transaction("register", self.0.digest),
                round("commit"),
                StepDescriptorV1::transaction("finalize", self.0.digest),
            ],
        }
    }
    fn manifest_with(
        &self,
        certificates: &[PrivateSettlementSidecarAvailabilityV1],
    ) -> std::result::Result<AtomicPrivateSettlementV1, PrivateSettlementError> {
        private_settlement_manifest_with_availability_v1(&self.0.materials, certificates)
            .map_err(PrivateSettlementError::Protocol)
    }

    fn barrier(
        &self,
        journal: &WorkflowJournalV1,
    ) -> std::result::Result<PrivateSettlementPrepareBarrierV1, PrivateSettlementError> {
        let availability =
            transcript::<Vec<PrivateSettlementSidecarAvailabilityV1>>(journal, AVAILABILITY)?;
        let manifest = self.manifest_with(&availability)?;
        let certificates =
            transcript::<Vec<PrivateSettlementPhaseCertificateV1>>(journal, PREPARE)?;
        Client::build_private_settlement_prepare_barrier_v1(
            manifest,
            &self
                .0
                .materials
                .iter()
                .map(|m| m.committee_authority.clone())
                .collect::<Vec<_>>(),
            self.0.materials.iter().map(|m| m.delta.clone()).collect(),
            certificates,
        )
        .map_err(PrivateSettlementError::Protocol)
    }
}

/// Local call bounds; these never change consensus validity.
#[derive(Clone, Copy, Debug)]
pub struct PrivateSettlementRunOptions {
    /// Existing durable workflow observation and exact-byte retransmission policy.
    pub workflow: WorkflowRunOptions,
    /// Maximum finality reads, including authenticated-prefix catch-up.
    pub max_finality_proof_reads: NonZeroU16,
}
impl Default for PrivateSettlementRunOptions {
    fn default() -> Self {
        Self {
            workflow: WorkflowRunOptions::default(),
            max_finality_proof_reads: NonZeroU16::new(64).unwrap(),
        }
    }
}
/// Successful original private settlement and this coordinator's carrier progress.
#[derive(Debug)]
pub struct PrivateSettlementResult {
    /// Independently authenticated final successful execution and original public receipt.
    pub receipt: VerifiedPrivateSettlementReceipt,
    /// Durable phase and carrier state; completion never rewrites a rejected carrier as Applied.
    pub progress: WorkflowProgressV1,
}
/// Read-only recovery, which never signs, certifies, uploads or submits.
#[derive(Debug)]
pub struct PrivateSettlementRecovery {
    /// Existing durable workflow state, when one was created.
    pub progress: Option<WorkflowProgressV1>,
    /// Original success only after fresh independent finality verification.
    pub receipt: Option<VerifiedPrivateSettlementReceipt>,
}
/// A retryable observation, journal, or independently retained request failure.
#[derive(Debug, thiserror::Error)]
pub enum PrivateSettlementError {
    /// The request, checkpoint, account or trusted root was substituted.
    #[error("private settlement binding mismatch")]
    Binding,
    /// Existing typed workflow failure, including progress and ambiguous writes.
    #[error(transparent)]
    Workflow(#[from] WorkflowError),
    /// Original certificate/transport error; never written into the journal.
    #[error("private settlement phase or transport unavailable")]
    Protocol(#[source] eyre::Report),
    /// Canonical encoding/decoding failed; original local resource cause retained.
    #[error(transparent)]
    Codec(#[from] norito::Error),
    /// Existing native finality verifier refusal.
    #[error(transparent)]
    Finality(#[from] FinalityReadError),
    /// Exact input/output authentication failed.
    #[error(transparent)]
    Execution(#[from] FinalityError),
    /// Independently verified receipt was not established.
    #[error(transparent)]
    Receipt(#[from] PrivateSettlementReceiptError),
    /// Local proof budget exhausted; every unresolved identity remains retained.
    #[error("private settlement finality read budget exhausted")]
    ReadBudget,
    /// No verified successful business completion was established in this call.
    #[error("private settlement remains unresolved")]
    Unresolved,
    /// Local worker/synchronization failure; no ledger failure is inferred.
    #[error("private settlement local worker unavailable")]
    Worker,
}
fn failure(error: &PrivateSettlementError) -> StepFailure {
    let code = match error {
        PrivateSettlementError::Binding | PrivateSettlementError::Receipt(_) => {
            WorkflowErrorCode::BindingMismatch
        }
        _ => WorkflowErrorCode::LocalResourceUnavailable,
    };
    StepFailure::new(code, error.to_string())
}
fn lock<T>(
    value: &Mutex<T>,
) -> std::result::Result<std::sync::MutexGuard<'_, T>, PrivateSettlementError> {
    value.lock().map_err(|_| PrivateSettlementError::Worker)
}
fn driver_identity() -> DriverIdentityV1 {
    DriverIdentityV1 {
        id: "private_settlement".into(),
        schema_version: 1,
    }
}
fn transcript<T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>>(
    journal: &WorkflowJournalV1,
    index: usize,
) -> std::result::Result<T, PrivateSettlementError> {
    let round = journal
        .steps
        .get(index)
        .and_then(|step| step.round.as_ref())
        .ok_or(PrivateSettlementError::Binding)?;
    if round.state != crate::workflow::RoundStateV1::RoundCompleted {
        return Err(PrivateSettlementError::Binding);
    }
    Ok(norito::decode_canonical(
        round
            .transcript
            .as_deref()
            .ok_or(PrivateSettlementError::Binding)?,
    )?)
}

/// Prepared confidential settlement using the existing journal and signing owners.
///
/// Reopen with the same external prepared artifacts and storage. Only bounded public
/// certificates and exact public carriers enter the journal. No plaintext witness,
/// proof blob, capsule or secret handle is persisted by this operation. Committee
/// methods run on one bounded blocking worker per operation, preserving their existing
/// four-endpoint fanout and transport deadlines. Cancellation may leave that original
/// phase finishing; its permit remains held until it exits and recovery reads first.
pub struct PrivateSettlementOperation {
    handle: WorkflowHandle,
    driver: Arc<SettlementDriver>,
    ledger: Arc<SettlementLedger>,
    call: tokio::sync::Mutex<()>,
}
impl std::fmt::Debug for PrivateSettlementOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateSettlementOperation")
            .field("workflow_id", &self.id())
            .finish_non_exhaustive()
    }
}
impl AccountClient {
    /// Open a durable operation over exact caller-retained prepared artifacts.
    ///
    /// The verifier must derive from independently authenticated signed genesis or an
    /// independently retained authenticated checkpoint, never trust supplied by Torii.
    /// # Errors
    /// Volatile storage, mismatched sponsor/network/root, malformed plan or account binding.
    pub fn private_settlement(
        &self,
        request: PrivateSettlementRequest,
        storage: Arc<dyn WorkflowStorage>,
        verifier: SumeragiFinalityVerifier,
    ) -> std::result::Result<PrivateSettlementOperation, PrivateSettlementError> {
        if storage.durability() != WorkflowStorageDurability::Durable
            || self.authority() != &request.manifest().sponsor
            || self.network_id() != &request.manifest().network_id
            || verifier.initial_epoch().network_id != request.manifest().network_id
            || verifier.root_scope() != SumeragiRootScope::Global
            || verifier.chain_id() != self.client().chain.as_ref()
        {
            return Err(PrivateSettlementError::Binding);
        }
        let context = Arc::new(AccountWorkflowContext::new(self.clone())?);
        let worker = Arc::new(tokio::sync::Semaphore::new(1));
        let phases = Arc::new(OnlinePhases::new(
            self.client().clone(),
            request.clone(),
            worker.clone(),
        ));
        let state = Arc::new(Mutex::new(None));
        let ledger = Arc::new(SettlementLedger::new(
            self.clone(),
            request.clone(),
            state.clone(),
            verifier,
            worker,
        ));
        let driver = Arc::new(SettlementDriver {
            account: self.clone(),
            request: request.clone(),
            phases,
            state: state.clone(),
            ledger: ledger.clone(),
        });
        let plan = request.plan();
        let account = Arc::new(SettlementAccount {
            account: context,
            request,
            state,
        });
        let engine = WorkflowEngine::new(
            storage,
            account,
            ledger.clone(),
            Arc::new(SystemWorkflowClock::new()),
        );
        Ok(PrivateSettlementOperation {
            handle: engine.workflow(plan)?,
            driver,
            ledger,
            call: tokio::sync::Mutex::new(()),
        })
    }
}
impl PrivateSettlementOperation {
    /// Stable identity of this exact request, sponsor and original journal plan.
    #[must_use]
    pub fn id(&self) -> WorkflowId {
        self.handle.id()
    }
    fn load(&self) -> std::result::Result<Option<WorkflowJournalV1>, PrivateSettlementError> {
        let journal = self.handle.journal_snapshot()?;
        if let Some(journal) = &journal {
            self.driver.load(journal)?;
        }
        Ok(journal)
    }
    /// Run or resume and return only independently verified successful settlement.
    /// # Errors
    /// Typed journal/resource/observation failure or unresolved success; original identities remain.
    pub async fn run(
        &self,
        options: &PrivateSettlementRunOptions,
    ) -> std::result::Result<PrivateSettlementResult, PrivateSettlementError> {
        let _call = self.call.lock().await;
        self.ledger
            .begin_call(options.max_finality_proof_reads.get() as usize)?;
        if let Some(journal) = self.load()?
            && let Some(receipt) = self.ledger.recover_business(&journal).await?
        {
            return Ok(PrivateSettlementResult {
                receipt,
                progress: journal.progress(),
            });
        }
        let result = self
            .handle
            .run(self.driver.as_ref(), &options.workflow)
            .await;
        let original_error = self.ledger.take_error()?;
        let journal = self.load()?;
        let recovered = if let Some(journal) = &journal {
            self.ledger.recover_business(journal).await
        } else {
            Ok(None)
        };
        if let Ok(Some(receipt)) = recovered {
            return Ok(PrivateSettlementResult {
                receipt,
                progress: journal.ok_or(PrivateSettlementError::Binding)?.progress(),
            });
        }
        if let Some(error) = original_error {
            return Err(error);
        }
        recovered?;
        result?;
        Err(PrivateSettlementError::Unresolved)
    }
    /// Reopen and reverify without any new phase, signature, promotion or dispatch effects.
    /// # Errors
    /// Exact original observation/storage failure; no failure authorizes another identity.
    pub async fn recover(
        &self,
        options: &PrivateSettlementRunOptions,
    ) -> std::result::Result<PrivateSettlementRecovery, PrivateSettlementError> {
        let _call = self.call.lock().await;
        self.ledger
            .begin_call(options.max_finality_proof_reads.get() as usize)?;
        if self.load()?.is_none() {
            return Ok(PrivateSettlementRecovery {
                progress: None,
                receipt: None,
            });
        }
        let result = self
            .handle
            .recover(Some(self.driver.as_ref()), &options.workflow)
            .await;
        let original_error = self.ledger.take_error()?;
        let journal = self.load()?.ok_or(PrivateSettlementError::Binding)?;
        let recovered = self.ledger.recover_business(&journal).await;
        if let Ok(Some(receipt)) = recovered {
            return Ok(PrivateSettlementRecovery {
                progress: Some(journal.progress()),
                receipt: Some(receipt),
            });
        }
        if let Some(error) = original_error {
            return Err(error);
        }
        recovered?;
        result?;
        Ok(PrivateSettlementRecovery {
            progress: Some(journal.progress()),
            receipt: None,
        })
    }
}

struct PublicContext {
    barrier: PrivateSettlementPrepareBarrierV1,
    phase: usize,
}
struct SettlementDriver {
    account: AccountClient,
    request: PrivateSettlementRequest,
    phases: Arc<dyn SettlementPhases>,
    state: Arc<Mutex<Option<PublicContext>>>,
    ledger: Arc<SettlementLedger>,
}
impl SettlementDriver {
    fn load(&self, journal: &WorkflowJournalV1) -> std::result::Result<(), PrivateSettlementError> {
        if journal.plan() != self.request.plan() {
            return Err(PrivateSettlementError::Binding);
        }
        if journal.steps[AVAILABILITY].is_done() {
            self.request.manifest_with(&transcript::<
                Vec<PrivateSettlementSidecarAvailabilityV1>,
            >(journal, AVAILABILITY)?)?;
        }
        if journal.steps[PREPARE].is_done() {
            let barrier = self.request.barrier(journal)?;
            if journal.steps[COMMIT].is_done() {
                build_private_settlement_commit_bundle_v1(
                    &barrier,
                    &transcript::<Vec<PrivateSettlementPhaseCertificateV1>>(journal, COMMIT)?,
                )
                .map_err(PrivateSettlementError::Protocol)?;
            }
            let phase = journal
                .steps
                .iter()
                .position(|step| !step.is_done())
                .unwrap_or(FINALIZE);
            *lock(&self.state)? = Some(PublicContext { barrier, phase });
        }
        Ok(())
    }
    async fn phase(
        &self,
        context: RoundContext<'_>,
        read_only: bool,
    ) -> std::result::Result<RoundReport, StepFailure> {
        self.load(context.journal)
            .map_err(|error| failure(&error))?;
        if context.step_index as usize == COMMIT {
            self.ledger
                .verify_registration(context.journal)
                .await
                .map_err(|error| failure(&error))?;
        }
        let transcript = self
            .phases
            .run(
                context.step_index as usize,
                context.journal.clone(),
                read_only,
            )
            .await
            .map_err(|error| failure(&error))?;
        let status = RoundStatusReport {
            round_id: context.round_id,
            context_digest: self.request.0.digest,
            participants: Vec::new(),
        };
        Ok(match transcript {
            Some(transcript) => RoundReport::Completed {
                status,
                transcript,
                custody_handles: Vec::new(),
            },
            None => RoundReport::Waiting(status),
        })
    }
}
impl WorkflowDriver for SettlementDriver {
    fn supports_round_continuation(&self) -> bool {
        true
    }
    fn identity(&self) -> DriverIdentityV1 {
        driver_identity()
    }
    fn start_round<'a>(
        &'a self,
        context: RoundContext<'a>,
    ) -> WorkflowFuture<'a, std::result::Result<RoundReport, StepFailure>> {
        Box::pin(self.phase(context, false))
    }
    fn recover_round<'a>(
        &'a self,
        context: RoundContext<'a>,
    ) -> WorkflowFuture<'a, std::result::Result<RoundRecovery, StepFailure>> {
        Box::pin(async move { Ok(RoundRecovery::Found(self.phase(context, true).await?)) })
    }
    fn continue_round<'a>(
        &'a self,
        context: RoundContext<'a>,
        _observed: RoundStatusReport,
    ) -> WorkflowFuture<'a, std::result::Result<RoundReport, StepFailure>> {
        Box::pin(self.phase(context, false))
    }
    fn build_transaction<'a>(
        &'a self,
        context: StepContext<'a>,
    ) -> WorkflowFuture<'a, std::result::Result<BuiltStepPayload, StepFailure>> {
        Box::pin(async move {
            self.load(context.journal)
                .map_err(|error| failure(&error))?;
            let barrier = self
                .request
                .barrier(context.journal)
                .map_err(|error| failure(&error))?;
            let instruction: InstructionBox = match context.step_index as usize {
                REGISTER => RegisterAtomicPrivateSettlementPrepareV1::new(barrier.clone()).into(),
                FINALIZE => {
                    self.ledger
                        .verify_registration(context.journal)
                        .await
                        .map_err(|error| failure(&error))?;
                    let commits = transcript::<Vec<PrivateSettlementPhaseCertificateV1>>(
                        context.journal,
                        COMMIT,
                    )
                    .map_err(|error| failure(&error))?;
                    FinalizeAtomicPrivateSettlementV1::new(
                        build_private_settlement_commit_bundle_v1(&barrier, &commits)
                            .map_err(|error| failure(&PrivateSettlementError::Protocol(error)))?,
                    )
                    .into()
                }
                _ => return Err(failure(&PrivateSettlementError::Binding)),
            };
            let payload = self
                .account
                .prepare_transaction(AccountTransactionDraft::new(
                    [instruction],
                    barrier.manifest.public_fee_intent.clone(),
                    Metadata::default(),
                ))
                .map_err(|error| super::super::workflow_ledger::signing_failure(&error))?;
            check_payload(
                &self.request,
                lock(&self.state).map_err(|error| failure(&error))?.as_ref(),
                &payload,
                true,
            )
            .map_err(|error| failure(&error))?;
            let unsigned_payload =
                norito::encode_canonical(&payload).map_err(|e| failure(&e.into()))?;
            Ok(BuiltStepPayload {
                intent_digest: self.request.0.digest,
                unsigned_payload,
            })
        })
    }
}

fn check_payload(
    request: &PrivateSettlementRequest,
    context: Option<&PublicContext>,
    payload: &TransactionPayload,
    signing: bool,
) -> std::result::Result<usize, PrivateSettlementError> {
    let context = context.ok_or(PrivateSettlementError::Binding)?;
    verified::check_carrier_context(payload, &context.barrier.manifest)?;
    let Executable::Instructions(instructions) = payload.instructions() else {
        return Err(PrivateSettlementError::Binding);
    };
    let [instruction] = instructions.as_ref() else {
        return Err(PrivateSettlementError::Binding);
    };
    let phase = if let Some(register) = instruction
        .as_any()
        .downcast_ref::<RegisterAtomicPrivateSettlementPrepareV1>()
    {
        validate_prepare_barrier_v1(&register.barrier).map_err(PrivateSettlementError::Protocol)?;
        if !register.barrier.quorum_equivalent_to(&context.barrier) {
            return Err(PrivateSettlementError::Binding);
        }
        REGISTER
    } else if let Some(finalize) = instruction
        .as_any()
        .downcast_ref::<FinalizeAtomicPrivateSettlementV1>()
    {
        let commits = finalize
            .commit_bundle
            .legs
            .iter()
            .map(|leg| leg.commit.clone())
            .collect::<Vec<_>>();
        let expected = build_private_settlement_commit_bundle_v1(&context.barrier, &commits)
            .map_err(PrivateSettlementError::Protocol)?;
        // Exact checkpoint bytes are used for newly authorized effects. Original successful
        // recovery separately permits valid quorum-equivalent Prepare certificates.
        if finalize.commit_bundle != expected {
            return Err(PrivateSettlementError::Binding);
        }
        FINALIZE
    } else {
        return Err(PrivateSettlementError::Binding);
    };
    if signing && context.phase != phase {
        return Err(PrivateSettlementError::Binding);
    }
    if norito::encode_canonical(instruction)?.len() as u64 > request.0.max_carrier_bytes {
        return Err(PrivateSettlementError::Binding);
    }
    Ok(phase)
}
struct SettlementAccount {
    account: Arc<dyn WorkflowAccount>,
    request: PrivateSettlementRequest,
    state: Arc<Mutex<Option<PublicContext>>>,
}
impl WorkflowAccount for SettlementAccount {
    fn binding(&self) -> WorkflowBindingV1 {
        self.account.binding()
    }
    fn sign<'a>(
        &'a self,
        bytes: &'a [u8],
    ) -> WorkflowFuture<'a, std::result::Result<SignedStepTransaction, StepFailure>> {
        Box::pin(async move {
            let payload = super::super::workflow_ledger::decode_unsigned(bytes)?;
            check_payload(
                &self.request,
                lock(&self.state).map_err(|error| failure(&error))?.as_ref(),
                &payload,
                true,
            )
            .map_err(|error| failure(&error))?;
            let signed = self.account.sign(bytes).await?;
            let transaction =
                super::super::workflow_ledger::decode_signed(&signed.signed_transaction)?;
            if transaction.payload() != &payload
                || signed.signed_transaction.len() as u64 > self.request.0.max_carrier_bytes
                || self.identify(&signed.signed_transaction)? != signed.identity
            {
                return Err(failure(&PrivateSettlementError::Binding));
            }
            Ok(signed)
        })
    }
    fn identify(&self, bytes: &[u8]) -> std::result::Result<TransactionIdentityV1, StepFailure> {
        let transaction = super::super::workflow_ledger::decode_signed(bytes)?;
        // Journal decoding recomputes identity before certificate checkpoints have
        // been loaded. It grants no authority to sign or dispatch: those boundaries
        // independently require the fully verified exact request and current phase.
        verified::check_carrier_context(transaction.payload(), self.request.manifest())
            .map_err(|error| failure(&error.into()))?;
        if bytes.len() as u64 > self.request.0.max_carrier_bytes {
            return Err(failure(&PrivateSettlementError::Binding));
        }
        transaction
            .verify_signature()
            .map_err(|_| failure(&PrivateSettlementError::Binding))?;
        Ok(identity(&transaction))
    }
}
fn identity(transaction: &SignedTransaction) -> TransactionIdentityV1 {
    TransactionIdentityV1 {
        signed_transaction_hash: *Hash::from(transaction.hash()).as_ref(),
        entrypoint_hash: *Hash::from(transaction.hash_as_entrypoint()).as_ref(),
    }
}

#[cfg(test)]
mod tests;
