//! The current full-World context transport requires all-ledger read authority; selected
//! bank permissions are insufficient. Scoped authenticated context reads remain unsupported.
//! One-call wallet preparation followed by the existing prepared settlement operation.
//! The existing workflow owns round identity and retries; immutable encrypted artifacts own
//! proof recovery. No plaintext witness is serialized by this operation.
use iroha::client::{
    AccountClient, AccountWorkflowContext, PRIVATE_SETTLEMENT_RESPONSE_MAX_BYTES_V1,
    PrivateSettlementError, PrivateSettlementRecovery, PrivateSettlementRequest,
    PrivateSettlementResult, PrivateSettlementRunOptions, run_private_settlement_worker,
    validate_private_settlement_committee_endpoints_v1,
};
use iroha::workflow::{
    CommittedOutcome, Digest32, DispatchOutcome, DriverIdentityV1, RoundContext, RoundRecovery,
    RoundReport, RoundStatusReport, StepDescriptorV1, StepFailure, SystemWorkflowClock,
    TransactionIdentityV1, WorkflowAccount, WorkflowBindingV1, WorkflowDriver, WorkflowEngine,
    WorkflowError, WorkflowErrorCode, WorkflowFuture, WorkflowHandle, WorkflowId, WorkflowLedger,
    WorkflowPlanV1, WorkflowStorage, WorkflowStorageDurability, domain_digest,
};
use iroha_core_privacy::privacy_engines::atomic_private_settlement::{
    AtomicPrivateSettlementAuthorizedWalletLegV1, AtomicPrivateSettlementPreparationErrorV1,
    AtomicPrivateSettlementPreparedLegV1, AtomicPrivateSettlementProvisionalLegInputV1,
    finalize_atomic_private_settlement_provisional_bundle_v1,
    prepare_atomic_private_settlement_leg_v1, verify_atomic_private_settlement_intent_v1,
};
use iroha_crypto::Hash;
use iroha_data_model::{
    asset::AssetDefinitionId,
    block::consensus::SumeragiRootScope,
    nexus::{
        PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1, PrivateSettlementAuditPolicyV1,
        PrivateSettlementCapsulePaddingV1, PrivateSettlementContextRequestV1,
        PrivateSettlementContextsProofV1, PrivateSettlementPoolGovernanceV1,
        PrivateSettlementPoolKeyV1, PrivateSettlementProofIntentV1,
    },
    sumeragi_finality::{
        FinalityError, FinalityReadError, SumeragiFinalityVerifier, VerifiedSumeragiBlock,
    },
};
use std::{
    num::NonZeroU64,
    sync::{Arc, Mutex},
};
use url::Url;

mod artifacts;
mod errors;
mod preparation;
pub use artifacts::FilePrivateSettlementArtifacts;
use artifacts::{Artifact, ArtifactKey};
use preparation::{NoPreparationEffects, PreparationDriver};

/// Independently chosen private business terms; never copied to the workflow journal.
/// These are checked against the wallet's original signed authorization before proving.
#[derive(Clone)]
pub struct PrivateSettlementBusinessTerms {
    /// Exact governed asset selected by the customer.
    pub asset: AssetDefinitionId,
    /// Authorized input owner.
    pub payer: iroha_data_model::account::AccountId,
    /// Authorized settlement recipient.
    pub recipient: iroha_data_model::account::AccountId,
    /// Positive exact atomic amount.
    pub amount: u128,
    /// Exact private sponsor reimbursement (zero on non-designated legs).
    pub reimbursement: u128,
    /// Exact bounded business reference/memo, retained only by the caller.
    pub memo: Vec<u8>,
}
impl std::fmt::Debug for PrivateSettlementBusinessTerms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateSettlementBusinessTerms(<restricted>)")
    }
}
/// Original governed restricted openings. Secret-bearing Model values keep their existing
/// redacted Debug and zeroizing discard behavior.
pub struct PrivateSettlementRestrictedOpening {
    /// Exact governed pool-to-asset opening.
    pub governance: PrivateSettlementPoolGovernanceV1,
    /// Exact active governed auditor policy.
    pub policy: PrivateSettlementAuditPolicyV1,
}
/// Untrusted context transport. Implementations enforce the existing bounded canonical
/// context-response decoder; neither endpoint identity nor status grants state authority.
pub trait PrivateSettlementContextSource: Send + Sync {
    /// Fetch all selected public originals atomically from one current cut, without wallet material.
    /// # Errors
    /// Invalid height or selectors, unavailable source, or a response that fails bounded decoding.
    fn fetch(
        &self,
        height: u64,
        selectors: PrivateSettlementContextRequestV1,
    ) -> WorkflowFuture<
        '_,
        std::result::Result<PrivateSettlementContextsProofV1, OneCallPrivateSettlementError>,
    >;
}
impl PrivateSettlementContextSource for AccountClient {
    fn fetch(
        &self,
        height: u64,
        selectors: PrivateSettlementContextRequestV1,
    ) -> WorkflowFuture<
        '_,
        std::result::Result<PrivateSettlementContextsProofV1, OneCallPrivateSettlementError>,
    > {
        Box::pin(async move {
            self.get_private_settlement_context_async(
                NonZeroU64::new(height).ok_or(OneCallPrivateSettlementError::Binding)?,
                selectors,
            )
            .await
            .map_err(OneCallPrivateSettlementError::Provider)
        })
    }
}
/// Wallet-owned durable reservation and secret custody, called only during explicit Run.
///
/// `round` and `leg` identify one original reservation. A resumed call must reopen the same
/// reserved notes and authorizations, never silently choose different inputs. Implementations
/// may use their existing wallet storage; this operation never encodes these returned witnesses.
pub trait PrivateSettlementWallet: Send + Sync {
    /// Reopen exact restricted governed openings for the independent asset selection.
    /// # Errors
    /// Unavailable original custody, denied access, or no opening for the selected intent leg
    /// and independently chosen business terms.
    fn open_policy(
        &self,
        intent: &PrivateSettlementProofIntentV1,
        leg: u8,
        terms: &PrivateSettlementBusinessTerms,
    ) -> std::result::Result<PrivateSettlementRestrictedOpening, OneCallPrivateSettlementError>;
    /// Reserve or reopen the original explicitly authorized wallet inputs and output views.
    /// Called under a durable original round lease retained until native proof work exits.
    /// # Errors
    /// Missing authorization, unavailable durable custody, or a conflict with the original
    /// reservation bound to this round, intent leg and business terms.
    fn reserve_or_reopen(
        &self,
        round: Digest32,
        intent: &PrivateSettlementProofIntentV1,
        leg: u8,
        terms: &PrivateSettlementBusinessTerms,
    ) -> std::result::Result<
        AtomicPrivateSettlementAuthorizedWalletLegV1,
        OneCallPrivateSettlementError,
    >;
}
/// Immutable caller request. Private terms are held in memory; only its domain-separated
/// digest and public round/certificate metadata enter the existing journal.
#[derive(Clone)]
pub struct OneCallPrivateSettlementRequest(Arc<Request>);
struct Request {
    intent: PrivateSettlementProofIntentV1,
    terms: Vec<PrivateSettlementBusinessTerms>,
    schema: Hash,
    minimum_context_time_ms: u64,
    endpoints: Vec<Vec<Url>>,
    padding: PrivateSettlementCapsulePaddingV1,
    retention_height: u64,
    max_carrier_bytes: u64,
    max_artifact_bytes: usize,
    max_total_artifact_bytes: usize,
    digest: Digest32,
}
impl OneCallPrivateSettlementRequest {
    /// Bind selected intent, independently chosen private terms, trust schema and local bounds.
    ///
    /// The original context height is part of `intent`; Run fetches and authenticates it.
    /// `minimum_context_time_ms` is an explicit caller freshness floor, not a latest-status
    /// assertion. Local byte limits do not replace the protocol's fixed proof/carrier limits.
    /// # Errors
    /// Invalid intent, shape, zero/oversized local budgets or mismatched reimbursement scope.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent: PrivateSettlementProofIntentV1,
        terms: Vec<PrivateSettlementBusinessTerms>,
        schema: Hash,
        minimum_context_time_ms: u64,
        endpoints: Vec<Vec<Url>>,
        padding: PrivateSettlementCapsulePaddingV1,
        retention_height: u64,
        max_carrier_bytes: u64,
        max_artifact_bytes: usize,
        max_total_artifact_bytes: usize,
    ) -> std::result::Result<Self, OneCallPrivateSettlementError> {
        intent
            .validate()
            .map_err(|_| OneCallPrivateSettlementError::Binding)?;
        if intent.authority_context_height < 2
            || terms.len() != intent.legs.len()
            || endpoints.len() != terms.len()
            || retention_height < intent.expiry_height
            || max_carrier_bytes == 0
            || max_carrier_bytes > PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1 as u64
            || max_artifact_bytes == 0
            || max_artifact_bytes > PRIVATE_SETTLEMENT_RESPONSE_MAX_BYTES_V1
            || max_total_artifact_bytes < max_artifact_bytes
            || terms.iter().enumerate().any(|(i, t)| {
                t.amount == 0
                    || t.memo.len()
                        > iroha_data_model::nexus::PRIVATE_SETTLEMENT_MAX_AUDIT_MEMO_BYTES_V1
                    || (t.reimbursement != 0)
                        != (i == usize::from(intent.reimbursement_leg_ordinal))
            })
        {
            return Err(OneCallPrivateSettlementError::Binding);
        }
        for row in &endpoints {
            validate_private_settlement_committee_endpoints_v1(row)
                .map_err(OneCallPrivateSettlementError::Provider)?;
        }
        // Canonical restricted terms are hashed in memory and wiped, never persisted as a journal.
        let business = terms
            .iter()
            .map(|t| {
                (
                    t.asset.clone(),
                    t.payer.clone(),
                    t.recipient.clone(),
                    t.amount,
                    t.reimbursement,
                    domain_digest(b"iroha:private-settlement:business-memo:v1\0", &[&t.memo]),
                )
            })
            .collect::<Vec<_>>();
        let encoded = zeroize::Zeroizing::new(norito::encode_canonical(&(
            intent.clone(),
            business,
            schema,
            minimum_context_time_ms,
            padding,
            retention_height,
            max_carrier_bytes,
            max_artifact_bytes as u64,
            max_total_artifact_bytes as u64,
        ))?);
        let digest = domain_digest(
            b"iroha:private-settlement:one-call-request:v1\0",
            &[&encoded],
        );
        Ok(Self(Arc::new(Request {
            intent,
            terms,
            schema,
            minimum_context_time_ms,
            endpoints,
            padding,
            retention_height,
            max_carrier_bytes,
            max_artifact_bytes,
            max_total_artifact_bytes,
            digest,
        })))
    }
    /// Exact public intent available for review before invoking the wallet.
    pub fn intent(&self) -> &PrivateSettlementProofIntentV1 {
        &self.0.intent
    }
    fn plan(&self) -> WorkflowPlanV1 {
        WorkflowPlanV1 {
            kind: iroha::workflow::WorkflowKindV1::PrivateSettlement,
            instance: hex::encode(self.intent().bundle_id.as_ref()),
            driver: preparation::driver_identity(),
            request_context_digest: self.0.digest,
            steps: vec![
                StepDescriptorV1::offchain_round("native_prepare", self.0.digest, true, 0, 1)
                    .with_max_transcript_bytes(16 * 1024),
            ],
        }
    }
}
impl std::fmt::Debug for OneCallPrivateSettlementRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OneCallPrivateSettlementRequest")
            .field("bundle_id", &self.intent().bundle_id)
            .finish_non_exhaustive()
    }
}
/// Closed local failures. Provider diagnostics and secret inputs are never written to journals.
#[derive(Debug, thiserror::Error)]
pub enum OneCallPrivateSettlementError {
    /// Original user intent, source, opening or persisted artifact was substituted.
    #[error("private one-call binding differs")]
    Binding,
    /// Local proof/custody capacity is unavailable; no ledger verdict is inferred.
    #[error("private one-call local capacity unavailable")]
    Capacity,
    /// Preparation remains incomplete; Run may continue the original round.
    #[error("private one-call preparation pending")]
    Pending,
    /// Exact original journal/custody failure.
    #[error(transparent)]
    Workflow(#[from] WorkflowError),
    /// Original file/custody owner failure; no file is deleted or repaired automatically.
    #[error("private one-call artifact custody unavailable")]
    Storage(#[source] std::io::Error),
    /// Existing finality verifier refused the untrusted evidence.
    #[error(transparent)]
    Finality(#[from] FinalityError),
    /// Original resource or authentication refusal from the finality evidence reader.
    #[error(transparent)]
    FinalityRead(#[from] FinalityReadError),
    /// Existing native proof preparation failure.
    #[error(transparent)]
    Preparation(#[from] AtomicPrivateSettlementPreparationErrorV1),
    /// Original untrusted-source/wallet provider error, kept outside durable diagnostics.
    #[error("private one-call source or wallet unavailable")]
    Provider(#[source] eyre::Report),
    /// Canonical artifact/intent encoding failed.
    #[error(transparent)]
    Encoding(#[from] norito::Error),
    /// Existing prepared operation returned its original typed error.
    #[error(transparent)]
    Settlement(#[from] PrivateSettlementError),
}
/// Async one-call operation: acquire/authenticate context, reserve/prove/self-verify, persist
/// encrypted prepared artifacts, then use the existing certify/upload/Register/Finalize owner.
///
/// Reopen with the same request, durable stores and independently pinned verifier. Recovery
/// reauthenticates the original selected cut and verifies stored proofs; decoded completion
/// never creates a verified settlement receipt.
pub struct OneCallPrivateSettlementOperation {
    account: AccountClient,
    storage: Arc<dyn WorkflowStorage>,
    handle: WorkflowHandle,
    driver: Arc<PreparationDriver>,
    call: tokio::sync::Mutex<()>,
}
impl OneCallPrivateSettlementOperation {
    /// Construct one-call preparation using this account's bounded native context transport.
    /// Restricted policy openings and original witness custody remain with the supplied wallet.
    /// # Errors
    /// Wrong original trust/intent binding, volatile journal storage or invalid local bounds.
    pub fn new(
        account: AccountClient,
        request: OneCallPrivateSettlementRequest,
        storage: Arc<dyn WorkflowStorage>,
        artifacts: Arc<FilePrivateSettlementArtifacts>,
        wallet: Arc<dyn PrivateSettlementWallet>,
        verifier: SumeragiFinalityVerifier,
    ) -> std::result::Result<OneCallPrivateSettlementOperation, OneCallPrivateSettlementError> {
        Self::with_source(
            account.clone(),
            request,
            storage,
            artifacts,
            Arc::new(account),
            wallet,
            verifier,
        )
    }
    /// Construct a durable one-call confidential settlement with explicit wallet and source custody.
    /// # Errors
    /// Volatile storage, foreign sponsor/network/root/schema or malformed bound workflow.
    pub fn with_source(
        account: AccountClient,
        request: OneCallPrivateSettlementRequest,
        storage: Arc<dyn WorkflowStorage>,
        artifacts: Arc<FilePrivateSettlementArtifacts>,
        source: Arc<dyn PrivateSettlementContextSource>,
        wallet: Arc<dyn PrivateSettlementWallet>,
        verifier: SumeragiFinalityVerifier,
    ) -> std::result::Result<OneCallPrivateSettlementOperation, OneCallPrivateSettlementError> {
        if storage.durability() != WorkflowStorageDurability::Durable
            || account.authority() != &request.intent().sponsor
            || account.network_id() != &request.intent().network_id
            || verifier.initial_epoch().network_id != request.intent().network_id
            || verifier.root_scope() != SumeragiRootScope::Global
            || verifier.chain_id() != account.chain_id().as_ref()
        {
            return Err(OneCallPrivateSettlementError::Binding);
        }
        let context = Arc::new(
            AccountWorkflowContext::new(account.clone()).map_err(PrivateSettlementError::from)?,
        );
        let no_effects = Arc::new(NoPreparationEffects(context.binding()));
        let handle = WorkflowEngine::new(
            storage.clone(),
            no_effects.clone(),
            no_effects,
            Arc::new(SystemWorkflowClock::new()),
        )
        .workflow(request.plan())?;
        let driver = Arc::new(PreparationDriver::new(
            account.clone(),
            request,
            storage.clone(),
            artifacts,
            source,
            wallet,
            verifier,
        ));
        Ok(OneCallPrivateSettlementOperation {
            account,
            storage,
            handle,
            driver,
            call: tokio::sync::Mutex::new(()),
        })
    }
}
impl OneCallPrivateSettlementOperation {
    /// Existing workflow identity of the original preparation round.
    pub fn id(&self) -> WorkflowId {
        self.handle.id()
    }
    /// Complete or resume original local preparation and return independently verified settlement.
    /// # Errors
    /// Original capacity, custody, wallet, proof, finality or prepared-operation error.
    pub async fn run(
        &self,
        options: &PrivateSettlementRunOptions,
    ) -> std::result::Result<PrivateSettlementResult, OneCallPrivateSettlementError> {
        let _call = self.call.lock().await;
        self.driver
            .begin_call(options.max_finality_proof_reads.get() as usize)?;
        let result = self
            .handle
            .run(self.driver.as_ref(), &options.workflow)
            .await;
        if let Some(error) = self.driver.take_error()? {
            return Err(error);
        }
        result?;
        let request = self
            .driver
            .recovered_request(self.handle.journal_snapshot()?.as_ref())
            .await?;
        let (verifier, options) = self.driver.settlement_handoff(options)?;
        Ok(self
            .account
            .private_settlement(request, self.storage.clone(), verifier)?
            .run(&options)
            .await?)
    }
    /// Reopen the exact prepared form without wallet work, proving, signing or submission.
    ///
    /// A never-started original returns `None` without creating a journal or calling a provider.
    /// Every stored artifact and its original selected cut are reverified using the supplied
    /// independent finality pins. `None` means preparation is incomplete, never absent effects.
    /// Returned material contains only public/proved fields and encrypted capsules; retaining
    /// it is caller custody, so a cold-process recovery test must drop this value as well.
    /// # Errors
    /// Original authentication, bounded-read or durable custody failure.
    pub async fn prepared_request(
        &self,
        options: &PrivateSettlementRunOptions,
    ) -> std::result::Result<Option<PrivateSettlementRequest>, OneCallPrivateSettlementError> {
        let _call = self.call.lock().await;
        if self.handle.journal_snapshot()?.is_none() {
            return Ok(None);
        }
        self.driver
            .begin_call(options.max_finality_proof_reads.get() as usize)?;
        let recovered = self
            .handle
            .recover(Some(self.driver.as_ref()), &options.workflow)
            .await;
        if let Some(error) = self.driver.take_error()? {
            return Err(error);
        }
        recovered?;
        let journal = self.handle.journal_snapshot()?;
        if journal.as_ref().is_none_or(|j| !j.steps[0].is_done()) {
            return Ok(None);
        }
        Ok(Some(self.driver.recovered_request(journal.as_ref()).await?))
    }

    /// Recover original preparation and settlement without reserving, proving, signing or sending.
    /// A never-started original returns empty progress without creating a journal.
    /// # Errors
    /// Exact original authentication, custody or bounded read failure.
    pub async fn recover(
        &self,
        options: &PrivateSettlementRunOptions,
    ) -> std::result::Result<PrivateSettlementRecovery, OneCallPrivateSettlementError> {
        let _call = self.call.lock().await;
        if self.handle.journal_snapshot()?.is_none() {
            return Ok(PrivateSettlementRecovery {
                progress: None,
                receipt: None,
            });
        }
        self.driver
            .begin_call(options.max_finality_proof_reads.get() as usize)?;
        let recovered = self
            .handle
            .recover(Some(self.driver.as_ref()), &options.workflow)
            .await;
        if let Some(error) = self.driver.take_error()? {
            return Err(error);
        }
        recovered?;
        let journal = self.handle.journal_snapshot()?;
        if journal.as_ref().is_none_or(|j| !j.steps[0].is_done()) {
            return Ok(PrivateSettlementRecovery {
                progress: journal.map(|j| j.progress()),
                receipt: None,
            });
        }
        let request = self.driver.recovered_request(journal.as_ref()).await?;
        let (verifier, options) = self.driver.settlement_handoff(options)?;
        Ok(self
            .account
            .private_settlement(request, self.storage.clone(), verifier)?
            .recover(&options)
            .await?)
    }
}

#[cfg(test)]
mod cold_context_tests;

#[cfg(test)]
mod test_support;
