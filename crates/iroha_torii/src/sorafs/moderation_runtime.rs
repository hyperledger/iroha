//! Production adapter boundaries for the finalized-chain SoraFS moderation orchestrator.
//!
//! These adapters intentionally own no moderation consensus state. Transaction idempotency and
//! terminal handoff deduplication are delegated to injected durable boundaries, while finalized
//! projections are read from one immutable [`State::query_view`] and cross-checked through the
//! native committed-event query.
use iroha_core::{
    queue::Queue,
    smartcontracts::ValidSingularQuery,
    state::{
        State, StateQueryView, StateReadOnly, StateReadOnlyWithTransactions, TransactionsReadOnly,
    },
};
use iroha_crypto::{Hash, HashOf};
#[cfg(test)]
use iroha_data_model::account::AccountId;
use iroha_data_model::{
    NetworkId,
    query::sorafs::prelude::{FindSorafsModerationEvents, FindSorafsModerationSnapshot},
    sorafs::moderation_ledger::{
        MODERATION_FINALIZED_SNAPSHOT_VERSION_V1, MODERATION_QUERY_MAX_CASES_V1,
        MODERATION_QUERY_MAX_EVENTS_V1, ModerationFinalizedEventCursorV1,
        ModerationFinalizedEventPageV1, ModerationFinalizedLedgerSnapshotV1,
        is_canonical_moderation_identifier_v1,
    },
    transaction::{
        Executable, FeePaymentIntent, SignedTransaction, TransactionBuilder, TransactionDomain,
        TransactionPayload,
    },
};
#[cfg(test)]
use sorafs_node::moderation_orchestrator::ModerationPanelNotificationKindV1;
#[cfg(test)]
use sorafs_node::moderation_orchestrator::ModerationPanelNotificationV1;
use sorafs_node::moderation_orchestrator::{
    MODERATION_EXTERNAL_WORK_LEASE_MS_V1, MODERATION_TRANSACTION_TTL_MS_V1,
    ModerationFinalizedCursorV1, ModerationFinalizedSnapshotReaderV1, ModerationHandoffFailureV1,
    ModerationOrchestratorDurableHealthV1, ModerationOrchestratorV1,
    ModerationPanelNotificationArchiveHeadV1, ModerationPanelNotificationClaimV1,
    ModerationPanelNotificationDeliveryReceiptV1, ModerationPanelNotificationFailureV1,
    ModerationPanelNotificationSinkV1, ModerationRuntimeProviderQualificationErrorV1,
    ModerationRuntimeProviderQualificationV1, ModerationRuntimeProviderReadinessErrorV1,
    ModerationRuntimeProviderV1, ModerationSignedTransactionV1, ModerationSnapshotReadErrorV1,
    ModerationSubmissionFailureV1, ModerationSubmissionLookupV1, ModerationTerminalHandoffKindV1,
    ModerationTerminalHandoffSinkV1, ModerationTerminalHandoffV1, ModerationTransactionReceiptV1,
    ModerationTransactionRequestV1, ModerationTransactionSubmitterV1,
    qualify_moderation_runtime_provider_v1, revalidate_moderation_runtime_provider_v1,
};
use std::{
    cmp,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
const MODERATION_HANDOFF_MAX_BYTES_V1: usize = 64 * 1024;
const MODERATION_PANEL_NOTIFICATION_MAX_BYTES_V1: usize = 64 * 1024;
const DEFAULT_MODERATION_EVENT_PAGE_SIZE_V1: u32 = 256;
const MODERATION_TRANSACTION_TTL_V1: Duration =
    Duration::from_millis(MODERATION_TRANSACTION_TTL_MS_V1);
const MODERATION_TRANSACTION_PAYLOAD_MAX_BYTES_V1: usize = 4 * 1024 * 1024;
/// Fixed identity of the in-process V1 Torii strict-durable ingress.
pub const TORII_MODERATION_STRICT_INGRESS_HANDLE_V1: &str =
    "torii.sorafs.moderation-strict-ingress.v1";
/// Revision of the in-process V1 Torii strict-durable ingress policy.
pub const TORII_MODERATION_STRICT_INGRESS_REVISION_V1: u64 = 1;
/// BLAKE3 digest of `sorafs.moderation.strict-ingress.torii.v1\0`.
pub const TORII_MODERATION_STRICT_INGRESS_POLICY_DIGEST_V1: [u8; 32] = [
    0xcc, 0x0c, 0xea, 0xc1, 0x8b, 0x93, 0xfa, 0x97, 0x05, 0xc0, 0xef, 0x86, 0xf6, 0x57, 0xa9, 0xed,
    0x94, 0xc5, 0xdd, 0x65, 0x31, 0x57, 0x84, 0x96, 0xa2, 0xd6, 0x4e, 0x8e, 0xc5, 0x21, 0x6d, 0x2e,
];
/// Return the exact public qualification of Torii's built-in V1 moderation ingress.
#[must_use]
pub const fn torii_moderation_strict_ingress_qualification_v1()
-> ModerationRuntimeProviderQualificationV1 {
    ModerationRuntimeProviderQualificationV1::new(
        TORII_MODERATION_STRICT_INGRESS_REVISION_V1,
        TORII_MODERATION_STRICT_INGRESS_POLICY_DIGEST_V1,
    )
}
#[derive(Debug)]
struct ToriiModerationStrictIngressBindingV1;
impl ModerationRuntimeProviderV1 for ToriiModerationStrictIngressBindingV1 {
    fn handle(&self) -> &str {
        TORII_MODERATION_STRICT_INGRESS_HANDLE_V1
    }
    fn qualification(
        &self,
    ) -> Result<ModerationRuntimeProviderQualificationV1, ModerationRuntimeProviderReadinessErrorV1>
    {
        Ok(torii_moderation_strict_ingress_qualification_v1())
    }
}
/// Qualify configured public metadata against Torii's built-in V1 moderation ingress.
///
/// This preflight needs no queue, ledger state, credentials, or private key and
/// can therefore run before Tokio and node-owned durable state are opened.
///
/// # Errors
///
/// Returns a payload-free qualification error when the configured handle is
/// missing, substituted, test-marked, or its revision/policy digest is stale.
pub fn qualify_torii_moderation_strict_ingress_binding_v1(
    configured_handle: &str,
    configured_qualification: ModerationRuntimeProviderQualificationV1,
) -> Result<(), ModerationRuntimeProviderQualificationErrorV1> {
    qualify_moderation_runtime_provider_v1(
        configured_handle,
        configured_qualification,
        &ToriiModerationStrictIngressBindingV1,
    )
}
/// Fail-closed reason that prevents serving a cached moderation projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModerationProjectionReadErrorV1 {
    /// No supervised reconciliation has completed since process start.
    Cold,
    /// The last successful reconciliation exceeded its monotonic freshness budget.
    Stale,
    /// A runtime dependency failed during the latest worker pass.
    DependencyFailed,
    /// A synchronous worker pass exceeded its deadline and is still fenced.
    DeadlineExceeded,
    /// Durable submission, handoff, or notification work is dead-lettered.
    DeadLetters,
    /// The worker observed a regressing or equivocal cache update.
    InvalidProjection,
    /// The supervised worker has stopped.
    WorkerStopped,
    /// A local cache or health lock was poisoned.
    Poisoned,
}
#[derive(Debug)]
struct ModerationProjectionHealthStateV1 {
    last_success_at: Option<Instant>,
    last_cursor: Option<ModerationFinalizedCursorV1>,
    failure: Option<ModerationProjectionReadErrorV1>,
    worker_stopped: bool,
}
/// Bounded read cache and monotonic liveness state for finalized moderation.
///
/// Only the supervised maintenance worker may publish into this cache. Request
/// handlers clone an `Arc` and never invoke the ledger reader, signer, ingress,
/// lookup, or downstream handoff boundaries.
#[derive(Debug)]
struct ModerationFinalizedProjectionCacheV1 {
    freshness_limit: Duration,
    in_flight: AtomicBool,
    health: Mutex<ModerationProjectionHealthStateV1>,
    snapshot: RwLock<Option<Arc<ModerationFinalizedLedgerSnapshotV1>>>,
}
impl ModerationFinalizedProjectionCacheV1 {
    fn new(freshness_limit: Duration) -> Self {
        Self {
            freshness_limit,
            in_flight: AtomicBool::new(false),
            health: Mutex::new(ModerationProjectionHealthStateV1 {
                last_success_at: None,
                last_cursor: None,
                failure: None,
                worker_stopped: false,
            }),
            snapshot: RwLock::new(None),
        }
    }
    fn begin_maintenance(&self) -> bool {
        self.in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
    fn mark_deadline_exceeded(&self) {
        if !self.in_flight.load(Ordering::Acquire) {
            return;
        }
        if let Ok(mut health) = self.health.lock() {
            health.failure = Some(ModerationProjectionReadErrorV1::DeadlineExceeded);
        }
    }
    fn finish_failure(&self, failure: ModerationProjectionReadErrorV1) {
        if let Ok(mut health) = self.health.lock() {
            health.failure = Some(failure);
        }
        self.in_flight.store(false, Ordering::Release);
    }
    fn finish_success(
        &self,
        snapshot: ModerationFinalizedLedgerSnapshotV1,
        durable_health: ModerationOrchestratorDurableHealthV1,
    ) -> Result<(), ModerationProjectionReadErrorV1> {
        let cursor = snapshot.anchor();
        let mut health = self.health.lock().map_err(|_| {
            self.in_flight.store(false, Ordering::Release);
            ModerationProjectionReadErrorV1::Poisoned
        })?;
        let invalid_cursor = durable_health.finalized_cursor != Some(cursor)
            || !durable_health.archive_is_fresh()
            || health.last_cursor.is_some_and(|previous| {
                cursor.height < previous.height
                    || (cursor.height == previous.height
                        && cursor.block_hash != previous.block_hash)
            });
        if invalid_cursor {
            health.failure = Some(ModerationProjectionReadErrorV1::InvalidProjection);
            self.in_flight.store(false, Ordering::Release);
            return Err(ModerationProjectionReadErrorV1::InvalidProjection);
        }
        if durable_health.has_dead_letters() {
            health.failure = Some(ModerationProjectionReadErrorV1::DeadLetters);
            self.in_flight.store(false, Ordering::Release);
            return Err(ModerationProjectionReadErrorV1::DeadLetters);
        }
        let mut cached = self.snapshot.write().map_err(|_| {
            health.failure = Some(ModerationProjectionReadErrorV1::Poisoned);
            self.in_flight.store(false, Ordering::Release);
            ModerationProjectionReadErrorV1::Poisoned
        })?;
        *cached = Some(Arc::new(snapshot));
        health.last_success_at = Some(Instant::now());
        health.last_cursor = Some(cursor);
        health.failure = None;
        health.worker_stopped = false;
        self.in_flight.store(false, Ordering::Release);
        Ok(())
    }
    fn mark_worker_stopped(&self) {
        if let Ok(mut health) = self.health.lock() {
            health.failure = Some(ModerationProjectionReadErrorV1::WorkerStopped);
            health.worker_stopped = true;
        }
    }
    fn snapshot(
        &self,
    ) -> Result<Arc<ModerationFinalizedLedgerSnapshotV1>, ModerationProjectionReadErrorV1> {
        let health = self
            .health
            .lock()
            .map_err(|_| ModerationProjectionReadErrorV1::Poisoned)?;
        if health.worker_stopped {
            return Err(ModerationProjectionReadErrorV1::WorkerStopped);
        }
        if let Some(failure) = health.failure {
            return Err(failure);
        }
        let Some(last_success_at) = health.last_success_at else {
            return Err(ModerationProjectionReadErrorV1::Cold);
        };
        if last_success_at.elapsed() >= self.freshness_limit {
            return Err(ModerationProjectionReadErrorV1::Stale);
        }
        self.snapshot
            .read()
            .map_err(|_| ModerationProjectionReadErrorV1::Poisoned)?
            .clone()
            .ok_or(ModerationProjectionReadErrorV1::Cold)
    }
}
/// Supervised Torii owner for one finalized moderation orchestrator.
#[derive(Debug)]
pub(crate) struct ModerationOrchestratorRuntimeV1 {
    orchestrator: Arc<ModerationOrchestratorV1>,
    projection: ModerationFinalizedProjectionCacheV1,
}
impl ModerationOrchestratorRuntimeV1 {
    pub(crate) fn new(
        orchestrator: Arc<ModerationOrchestratorV1>,
        freshness_limit: Duration,
    ) -> Self {
        Self {
            orchestrator,
            projection: ModerationFinalizedProjectionCacheV1::new(freshness_limit),
        }
    }
    pub(crate) fn orchestrator(&self) -> Arc<ModerationOrchestratorV1> {
        Arc::clone(&self.orchestrator)
    }
    pub(crate) fn begin_maintenance(&self) -> bool {
        self.projection.begin_maintenance()
    }
    pub(crate) fn mark_deadline_exceeded(&self) {
        self.projection.mark_deadline_exceeded();
    }
    pub(crate) fn finish_failure(&self) {
        self.projection
            .finish_failure(ModerationProjectionReadErrorV1::DependencyFailed);
    }
    pub(crate) fn finish_success(
        &self,
        snapshot: ModerationFinalizedLedgerSnapshotV1,
        durable_health: ModerationOrchestratorDurableHealthV1,
    ) -> Result<(), ModerationProjectionReadErrorV1> {
        self.projection.finish_success(snapshot, durable_health)
    }
    pub(crate) fn mark_worker_stopped(&self) {
        self.projection.mark_worker_stopped();
    }
    pub(crate) fn snapshot(
        &self,
    ) -> Result<Arc<ModerationFinalizedLedgerSnapshotV1>, ModerationProjectionReadErrorV1> {
        self.projection.snapshot()
    }
}
/// Derive the synchronous worker deadline from governed cadence and the exact
/// external-work lease. No request thread observes this timeout.
#[must_use]
pub(crate) fn moderation_worker_deadline(worker_interval: Duration) -> Duration {
    cmp::max(
        worker_interval,
        Duration::from_millis(MODERATION_EXTERNAL_WORK_LEASE_MS_V1),
    )
}
/// Derive the monotonic projection freshness budget from governed cadence.
#[must_use]
pub(crate) fn moderation_projection_freshness_limit(worker_interval: Duration) -> Duration {
    let deadline = moderation_worker_deadline(worker_interval);
    deadline
        .checked_add(worker_interval)
        .and_then(|value| value.checked_add(worker_interval))
        .unwrap_or(Duration::MAX)
}
/// Fixed runtime signing failures that are safe to surface to the orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModerationSigningFailureV1 {
    /// The signing service is temporarily unavailable.
    Unavailable,
    /// The signer queue is full and no signature was produced.
    Backpressure,
    /// The signer permanently refused the exact request.
    Refused,
}
/// Runtime-only signer for one exact native moderation transaction.
///
/// Implementations may delegate to a deployment-owned signing service. A
/// returned envelope is durably retained by the orchestrator before ingress;
/// signing itself is never used as an idempotency or crash-recovery boundary.
pub trait ModerationSignedTransactionSignerV1: ModerationRuntimeProviderV1 {
    /// Sign the exact fee-quoted payload supplied by Torii.
    ///
    /// # Errors
    ///
    /// Returns a fixed failure class without provider diagnostics when no
    /// acceptable signature was produced.
    fn sign(
        &self,
        payload: TransactionPayload,
    ) -> Result<SignedTransaction, ModerationSigningFailureV1>;
}
/// Fixed fee-quote failures safe to return across the signer boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModerationFeeQuoteFailureV1 {
    /// The finalized fee view or routing policy is temporarily unavailable.
    Unavailable,
    /// The exact payload cannot satisfy governed fee policy.
    Rejected,
}
/// Runtime fee quoter used after Torii has built the exact V1 payload.
pub trait ModerationFeeQuoterV1: Send + Sync {
    /// Quote the signature-bound fee intent without changing any other field.
    fn quote(
        &self,
        payload: &TransactionPayload,
    ) -> Result<FeePaymentIntent, ModerationFeeQuoteFailureV1>;
}
/// Receipt returned by the strict, durable transaction ingress boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModerationStrictIngressReceiptV1 {
    /// Hash of the exact signed transaction durably admitted by ingress.
    pub transaction_id: [u8; 32],
    /// Finalized height observed while admitting or replaying the operation.
    pub observed_finalized_height: u64,
    /// Whether ingress returned an already retained operation.
    pub replay: bool,
}
/// Fixed strict-ingress failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModerationStrictIngressFailureV1 {
    /// No admission occurred and a later retry is safe.
    Unavailable,
    /// No admission occurred because the bounded ingress queue is full.
    Backpressure,
    /// Admission may have occurred; lookup by `operation_id` is required.
    Ambiguous,
    /// The signed transaction was permanently rejected before admission.
    PermanentRejection,
    /// Runtime-only policy or credentials are unavailable.
    RuntimeUnavailable,
}
/// Strict signed-transaction ingress used by the moderation adapter.
///
/// The orchestrator has already persisted the exact operation-to-transaction binding before
/// `submit_exact`. Ingress must run the canonical Torii signature, network, fee, queue-plan, and
/// durable-admission checks without replacing that transaction. Distinct envelopes signed by racing
/// replicas are resolved by native ledger CAS semantics and finalized reconciliation; no
/// process-local operation map is authoritative.
pub trait ModerationStrictTransactionIngressV1: ModerationRuntimeProviderV1 {
    /// Durably admit or replay one exact signed transaction.
    ///
    /// # Errors
    ///
    /// Returns a fixed admission class. An ambiguous result must be resolved
    /// with [`Self::lookup_exact`] before any replacement is signed.
    fn submit_exact(
        &self,
        request: &ModerationTransactionRequestV1,
        transaction: SignedTransaction,
    ) -> Result<ModerationStrictIngressReceiptV1, ModerationStrictIngressFailureV1>;
    /// Resolve a retained operation through durable ingress/committed state.
    fn lookup_exact(
        &self,
        operation_id: [u8; 32],
        transaction_id: Option<[u8; 32]>,
    ) -> ModerationSubmissionLookupV1;
}
struct QualifiedModerationRuntimeProviderV1<P: ModerationRuntimeProviderV1 + ?Sized> {
    handle: String,
    qualification: ModerationRuntimeProviderQualificationV1,
    provider: Arc<P>,
}
impl<P: ModerationRuntimeProviderV1 + ?Sized> QualifiedModerationRuntimeProviderV1<P> {
    fn try_new(
        expected_handle: &str,
        expected_qualification: ModerationRuntimeProviderQualificationV1,
        provider: Arc<P>,
    ) -> Result<Self, ModerationRuntimeProviderQualificationErrorV1> {
        qualify_moderation_runtime_provider_v1(
            expected_handle,
            expected_qualification,
            provider.as_ref(),
        )?;
        Ok(Self {
            handle: expected_handle.to_owned(),
            qualification: expected_qualification,
            provider,
        })
    }
    fn revalidate(&self) -> Result<(), ModerationRuntimeProviderQualificationErrorV1> {
        revalidate_moderation_runtime_provider_v1(
            &self.handle,
            self.qualification,
            self.provider.as_ref(),
        )
    }
}
impl<P: ModerationRuntimeProviderV1 + ?Sized> core::fmt::Debug
    for QualifiedModerationRuntimeProviderV1<P>
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("QualifiedModerationRuntimeProviderV1")
            .field("handle", &self.handle)
            .field("qualification", &self.qualification)
            .field("provider", &"<runtime-only>")
            .finish()
    }
}
/// Fail-closed bridge from moderation operations to signed Torii ingress.
pub struct ModerationTransactionSubmitterAdapterV1 {
    network_id: NetworkId,
    signer: QualifiedModerationRuntimeProviderV1<dyn ModerationSignedTransactionSignerV1>,
    fee_quoter: Arc<dyn ModerationFeeQuoterV1>,
    ingress: QualifiedModerationRuntimeProviderV1<dyn ModerationStrictTransactionIngressV1>,
}
impl core::fmt::Debug for ModerationTransactionSubmitterAdapterV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ModerationTransactionSubmitterAdapterV1")
            .field("network_id", &self.network_id)
            .field("signer", &"<runtime-only>")
            .field("fee_quoter", &"<finalized-policy>")
            .field("ingress", &"<durable-strict-ingress>")
            .finish()
    }
}
impl ModerationTransactionSubmitterAdapterV1 {
    /// Construct and qualify a submitter for one exact genesis-derived network.
    ///
    /// # Errors
    ///
    /// Fails when either injected provider is unavailable, test-marked,
    /// substituted, stale, or differs from its independent exact binding.
    pub fn try_new(
        network_id: NetworkId,
        transaction_signer_handle: &str,
        expected_transaction_signer_qualification: ModerationRuntimeProviderQualificationV1,
        signer: Arc<dyn ModerationSignedTransactionSignerV1>,
        fee_quoter: Arc<dyn ModerationFeeQuoterV1>,
        strict_ingress_handle: &str,
        expected_strict_ingress_qualification: ModerationRuntimeProviderQualificationV1,
        ingress: Arc<dyn ModerationStrictTransactionIngressV1>,
    ) -> Result<Self, ModerationRuntimeProviderQualificationErrorV1> {
        let signer = QualifiedModerationRuntimeProviderV1::try_new(
            transaction_signer_handle,
            expected_transaction_signer_qualification,
            signer,
        )?;
        let ingress = QualifiedModerationRuntimeProviderV1::try_new(
            strict_ingress_handle,
            expected_strict_ingress_qualification,
            ingress,
        )?;
        Ok(Self {
            network_id,
            signer,
            fee_quoter,
            ingress,
        })
    }
}
impl ModerationTransactionSubmitterV1 for ModerationTransactionSubmitterAdapterV1 {
    fn transaction_signer_provider(&self) -> &dyn ModerationRuntimeProviderV1 {
        self.signer.provider.as_ref()
    }
    fn strict_ingress_provider(&self) -> &dyn ModerationRuntimeProviderV1 {
        self.ingress.provider.as_ref()
    }
    fn network_id(&self) -> NetworkId {
        self.network_id
    }
    fn sign(
        &self,
        request: &ModerationTransactionRequestV1,
    ) -> Result<ModerationSignedTransactionV1, ModerationSubmissionFailureV1> {
        validate_moderation_transaction_request(request)?;
        let mut builder = TransactionBuilder::new(
            self.network_id,
            request.authority.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([request.action.instruction()]);
        builder.set_ttl(MODERATION_TRANSACTION_TTL_V1);
        let mut payload = builder
            .into_payload()
            .map_err(|_| ModerationSubmissionFailureV1::PermanentRejection)?;
        validate_unsigned_moderation_payload(&self.network_id, request, &payload)?;
        payload.fee_payment = self
            .fee_quoter
            .quote(&payload)
            .map_err(|error| match error {
                ModerationFeeQuoteFailureV1::Unavailable => {
                    ModerationSubmissionFailureV1::RuntimeUnavailable
                }
                ModerationFeeQuoteFailureV1::Rejected => {
                    ModerationSubmissionFailureV1::PermanentRejection
                }
            })?;
        validate_unsigned_moderation_payload(&self.network_id, request, &payload)?;
        let expected_payload = payload.clone();
        self.signer
            .revalidate()
            .map_err(|_| ModerationSubmissionFailureV1::RuntimeUnavailable)?;
        let transaction = self.signer.provider.sign(payload);
        self.signer
            .revalidate()
            .map_err(|_| ModerationSubmissionFailureV1::RuntimeUnavailable)?;
        let transaction = transaction.map_err(map_signing_failure)?;
        if transaction.payload() != &expected_payload {
            return Err(ModerationSubmissionFailureV1::PermanentRejection);
        }
        validate_signed_moderation_transaction(&self.network_id, request, &transaction)?;
        ModerationSignedTransactionV1::from_signed_transaction(request, &transaction)
    }
    fn submit_signed(
        &self,
        request: &ModerationTransactionRequestV1,
        signed: &ModerationSignedTransactionV1,
    ) -> Result<ModerationTransactionReceiptV1, ModerationSubmissionFailureV1> {
        validate_moderation_transaction_request(request)?;
        let transaction = signed.decode_for_request(request)?;
        validate_signed_moderation_transaction(&self.network_id, request, &transaction)?;
        let expected_transaction_id = signed.transaction_id;
        self.ingress
            .revalidate()
            .map_err(|_| ModerationSubmissionFailureV1::NotSubmittedUnavailable)?;
        let receipt = self.ingress.provider.submit_exact(request, transaction);
        self.ingress
            .revalidate()
            .map_err(|_| ModerationSubmissionFailureV1::Ambiguous)?;
        let receipt = receipt.map_err(map_ingress_failure)?;
        if receipt.transaction_id != expected_transaction_id
            || receipt.observed_finalized_height < request.baseline_finalized_height
        {
            // Ingress may already have accepted a transaction. Reconciliation
            // is mandatory; signing or submitting a replacement is unsafe.
            return Err(ModerationSubmissionFailureV1::Ambiguous);
        }
        Ok(ModerationTransactionReceiptV1 {
            transaction_id: receipt.transaction_id,
            observed_finalized_height: receipt.observed_finalized_height,
        })
    }
    fn lookup(
        &self,
        operation_id: [u8; 32],
        transaction_id: Option<[u8; 32]>,
    ) -> ModerationSubmissionLookupV1 {
        if operation_id == [0; 32] || transaction_id == Some([0; 32]) {
            return ModerationSubmissionLookupV1::Unknown;
        }
        if self.ingress.revalidate().is_err() {
            return ModerationSubmissionLookupV1::Unknown;
        }
        let lookup = self
            .ingress
            .provider
            .lookup_exact(operation_id, transaction_id);
        if self.ingress.revalidate().is_err() {
            return ModerationSubmissionLookupV1::Unknown;
        }
        sanitize_submission_lookup(lookup, transaction_id)
    }
}
fn validate_moderation_transaction_request(
    request: &ModerationTransactionRequestV1,
) -> Result<(), ModerationSubmissionFailureV1> {
    request
        .validate()
        .map_err(|_| ModerationSubmissionFailureV1::PermanentRejection)
}
fn validate_unsigned_moderation_payload(
    network_id: &NetworkId,
    request: &ModerationTransactionRequestV1,
    payload: &TransactionPayload,
) -> Result<(), ModerationSubmissionFailureV1> {
    let canonical =
        norito::to_bytes(payload).map_err(|_| ModerationSubmissionFailureV1::PermanentRejection)?;
    let expected_ttl_ms =
        u64::try_from(MODERATION_TRANSACTION_TTL_V1.as_millis()).unwrap_or(u64::MAX);
    if canonical.is_empty()
        || canonical.len() > MODERATION_TRANSACTION_PAYLOAD_MAX_BYTES_V1
        || request.network_id != *network_id
        || payload.domain != TransactionDomain::Network(*network_id)
        || payload.authority != request.authority
        || payload.creation_time_ms == 0
        || payload.time_to_live_ms.map(core::num::NonZeroU64::get) != Some(expected_ttl_ms)
        || payload.nonce.is_some()
        || !payload.metadata.is_empty()
        || payload.fee_payment.validate().is_err()
    {
        return Err(ModerationSubmissionFailureV1::PermanentRejection);
    }
    let expected = request.action.instruction();
    match &payload.instructions {
        Executable::Instructions(instructions)
            if instructions.len() == 1 && instructions.first() == Some(&expected) =>
        {
            Ok(())
        }
        _ => Err(ModerationSubmissionFailureV1::PermanentRejection),
    }
}
fn validate_signed_moderation_transaction(
    network_id: &NetworkId,
    request: &ModerationTransactionRequestV1,
    transaction: &SignedTransaction,
) -> Result<(), ModerationSubmissionFailureV1> {
    if transaction.verify_signature().is_err()
        || request.network_id != *network_id
        || transaction.network_id() != Some(network_id)
        || transaction.authority() != &request.authority
    {
        return Err(ModerationSubmissionFailureV1::PermanentRejection);
    }
    let expected = request.action.instruction();
    match transaction.instructions() {
        Executable::Instructions(instructions)
            if instructions.len() == 1 && instructions.first() == Some(&expected) =>
        {
            Ok(())
        }
        _ => Err(ModerationSubmissionFailureV1::PermanentRejection),
    }
}
/// Canonical Torii fee quoter for the exact moderation payload.
pub(crate) struct ToriiModerationFeeQuoterV1 {
    queue: Arc<Queue>,
    state: Arc<State>,
}
impl core::fmt::Debug for ToriiModerationFeeQuoterV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ToriiModerationFeeQuoterV1")
            .field("queue", &"<canonical-routing>")
            .field("state", &"<finalized-fee-view>")
            .finish()
    }
}
impl ToriiModerationFeeQuoterV1 {
    #[must_use]
    pub(crate) fn new(queue: Arc<Queue>, state: Arc<State>) -> Self {
        Self { queue, state }
    }
}
impl ModerationFeeQuoterV1 for ToriiModerationFeeQuoterV1 {
    fn quote(
        &self,
        payload: &TransactionPayload,
    ) -> Result<FeePaymentIntent, ModerationFeeQuoteFailureV1> {
        crate::quote_internal_fee_payment_from_parts(
            self.state.network_id_ref(),
            self.queue.as_ref(),
            self.state.as_ref(),
            payload,
        )
        .map_err(|_| ModerationFeeQuoteFailureV1::Rejected)
    }
}
/// Canonical local strict-durable ingress and exact finalized transaction observer.
pub(crate) struct ToriiModerationStrictTransactionIngressV1 {
    queue: Arc<Queue>,
    state: Arc<State>,
    telemetry: crate::routing::MaybeTelemetry,
    pipeline_status_cache: Arc<crate::PipelineStatusCache>,
}
impl core::fmt::Debug for ToriiModerationStrictTransactionIngressV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ToriiModerationStrictTransactionIngressV1")
            .field(
                "provider_handle",
                &TORII_MODERATION_STRICT_INGRESS_HANDLE_V1,
            )
            .field(
                "provider_qualification",
                &torii_moderation_strict_ingress_qualification_v1(),
            )
            .field("queue", &"<strict-durable>")
            .field("state", &"<authoritative>")
            .field("pipeline_status_cache", &"<positive-hints-only>")
            .finish()
    }
}
impl ToriiModerationStrictTransactionIngressV1 {
    #[must_use]
    pub(crate) fn new(
        queue: Arc<Queue>,
        state: Arc<State>,
        telemetry: crate::routing::MaybeTelemetry,
        pipeline_status_cache: Arc<crate::PipelineStatusCache>,
    ) -> Self {
        Self {
            queue,
            state,
            telemetry,
            pipeline_status_cache,
        }
    }
    fn validate_retained_baseline(
        &self,
        request: &ModerationTransactionRequestV1,
    ) -> Result<u64, ModerationStrictIngressFailureV1> {
        let view = self.state.view();
        let observed_finalized_height = u64::try_from(view.block_hashes().len())
            .map_err(|_| ModerationStrictIngressFailureV1::Unavailable)?;
        let baseline_index = usize::try_from(request.baseline_finalized_height)
            .ok()
            .and_then(|height| height.checked_sub(1))
            .ok_or(ModerationStrictIngressFailureV1::PermanentRejection)?;
        if observed_finalized_height == 0 {
            return Err(ModerationStrictIngressFailureV1::Unavailable);
        }
        let Some(baseline_hash) = view.block_hashes().get(baseline_index) else {
            return Err(ModerationStrictIngressFailureV1::Unavailable);
        };
        if baseline_hash.as_ref() != &request.baseline_finalized_block_hash {
            return Err(ModerationStrictIngressFailureV1::PermanentRejection);
        }
        Ok(observed_finalized_height)
    }
    fn has_positive_pending_hint(&self, transaction_hash: &HashOf<SignedTransaction>) -> bool {
        self.queue.contains_pending_hash(
            iroha_core::tx::external_entrypoint_hash_from_signed_hash(transaction_hash.clone()),
            self.state.as_ref(),
        ) || self
            .pipeline_status_cache
            .lookup(transaction_hash)
            .is_some_and(|entry| {
                matches!(
                    entry.kind,
                    crate::PipelineStatusKind::Queued
                        | crate::PipelineStatusKind::Approved
                        | crate::PipelineStatusKind::Committed
                        | crate::PipelineStatusKind::Applied
                )
            })
    }
}
impl ModerationRuntimeProviderV1 for ToriiModerationStrictTransactionIngressV1 {
    fn handle(&self) -> &str {
        TORII_MODERATION_STRICT_INGRESS_HANDLE_V1
    }
    fn qualification(
        &self,
    ) -> Result<ModerationRuntimeProviderQualificationV1, ModerationRuntimeProviderReadinessErrorV1>
    {
        Ok(torii_moderation_strict_ingress_qualification_v1())
    }
}
impl ModerationStrictTransactionIngressV1 for ToriiModerationStrictTransactionIngressV1 {
    fn submit_exact(
        &self,
        request: &ModerationTransactionRequestV1,
        transaction: SignedTransaction,
    ) -> Result<ModerationStrictIngressReceiptV1, ModerationStrictIngressFailureV1> {
        if request.operation_id == [0; 32]
            || request.network_id != *self.state.network_id_ref()
            || transaction.network_id() != Some(self.state.network_id_ref())
            || *transaction.hash().as_ref() == [0; 32]
        {
            return Err(ModerationStrictIngressFailureV1::PermanentRejection);
        }
        let observed_finalized_height = self.validate_retained_baseline(request)?;
        let transaction_id = *transaction.hash().as_ref();
        let accepted = crate::routing::accept_transaction_for_ingress(
            Arc::clone(&self.state),
            transaction,
            &self.telemetry,
        )
        .map_err(|error| match error {
            crate::Error::AcceptTransaction(
                iroha_core::tx::AcceptTransactionFail::NetworkTimeUnhealthy { .. }
                | iroha_core::tx::AcceptTransactionFail::TransactionInTheFuture { .. },
            ) => ModerationStrictIngressFailureV1::Unavailable,
            crate::Error::AcceptTransaction(_) => {
                ModerationStrictIngressFailureV1::PermanentRejection
            }
            _ => ModerationStrictIngressFailureV1::Unavailable,
        })?;
        let routing_plan = self
            .queue
            .route_plan_with_state(&accepted, self.state.as_ref())
            .map_err(|_| ModerationStrictIngressFailureV1::Unavailable)?;
        match crate::routing::push_accepted_transaction_for_ingress_with_routing_plan(
            Arc::clone(&self.queue),
            Arc::clone(&self.state),
            accepted,
            Some(routing_plan),
        ) {
            Ok(_) => Ok(ModerationStrictIngressReceiptV1 {
                transaction_id,
                observed_finalized_height,
                replay: false,
            }),
            Err(crate::Error::PushIntoQueue { source, .. }) => {
                classify_local_moderation_queue_rejection(source.as_ref())?;
                Ok(ModerationStrictIngressReceiptV1 {
                    transaction_id,
                    observed_finalized_height,
                    replay: true,
                })
            }
            Err(_) => Err(ModerationStrictIngressFailureV1::Unavailable),
        }
    }
    fn lookup_exact(
        &self,
        operation_id: [u8; 32],
        transaction_id: Option<[u8; 32]>,
    ) -> ModerationSubmissionLookupV1 {
        let Some(transaction_id) = transaction_id.filter(|id| *id != [0; 32]) else {
            return ModerationSubmissionLookupV1::Unknown;
        };
        if operation_id == [0; 32] {
            return ModerationSubmissionLookupV1::Unknown;
        }
        let transaction_hash = HashOf::from_untyped_unchecked(Hash::prehashed(transaction_id));
        let entrypoint_hash =
            iroha_core::tx::external_entrypoint_hash_from_signed_hash(transaction_hash.clone());
        let view = self.state.view();
        let Some(observed_finalized_height) = u64::try_from(view.block_hashes().len())
            .ok()
            .filter(|height| *height != 0)
        else {
            return ModerationSubmissionLookupV1::Unknown;
        };
        let Some(block_height) = view.transactions().get(&entrypoint_hash) else {
            drop(view);
            return if self.has_positive_pending_hint(&transaction_hash) {
                ModerationSubmissionLookupV1::Pending { transaction_id }
            } else {
                ModerationSubmissionLookupV1::NotFound {
                    observed_finalized_height,
                }
            };
        };
        if block_height.get() > view.block_hashes().len() {
            return ModerationSubmissionLookupV1::Unknown;
        }
        let Some(expected_block_hash) = view
            .block_hashes()
            .get(block_height.get().saturating_sub(1))
            .copied()
        else {
            return ModerationSubmissionLookupV1::Unknown;
        };
        drop(view);
        let work = crate::routing::app_query_limits().max_fetch_size;
        let Ok(carrier) = self.state.read_finalized_execution_carrier(
            block_height,
            work,
            iroha_core::smartcontracts::isi::tx::transaction_history_byte_limit(work),
        ) else {
            return ModerationSubmissionLookupV1::Unknown;
        };
        if carrier.block().hash() != expected_block_hash
            || self.state.committed_entrypoint_height(&entrypoint_hash) != Some(block_height)
        {
            return ModerationSubmissionLookupV1::Unknown;
        }
        let Ok(calls) = crate::canonical_history::signed_calls(carrier.block()) else {
            return ModerationSubmissionLookupV1::Unknown;
        };
        let mut exact_results = calls.filter_map(|(source_hash, signed, result)| {
            crate::signed_transaction_carrier_matches_indexed_identity(
                &source_hash,
                signed,
                &entrypoint_hash,
            )
            .then_some(result.is_ok())
        });
        match (exact_results.next(), exact_results.next()) {
            (Some(true), None) => ModerationSubmissionLookupV1::Applied { transaction_id },
            (Some(false), None) => ModerationSubmissionLookupV1::Rejected {
                transaction_id: Some(transaction_id),
                observed_finalized_height,
            },
            _ => ModerationSubmissionLookupV1::Unknown,
        }
    }
}
fn map_signing_failure(error: ModerationSigningFailureV1) -> ModerationSubmissionFailureV1 {
    match error {
        ModerationSigningFailureV1::Unavailable => {
            ModerationSubmissionFailureV1::RuntimeUnavailable
        }
        ModerationSigningFailureV1::Backpressure => {
            ModerationSubmissionFailureV1::NotSubmittedBackpressure
        }
        ModerationSigningFailureV1::Refused => ModerationSubmissionFailureV1::PermanentRejection,
    }
}
// Only exact already-retained transactions produce a replay receipt. A signed
// domain mismatch is permanent even when preacceptance came from another State.
fn classify_local_moderation_queue_rejection(
    error: &iroha_core::queue::Error,
) -> Result<(), ModerationStrictIngressFailureV1> {
    match error {
        iroha_core::queue::Error::InBlockchain | iroha_core::queue::Error::IsInQueue => Ok(()),
        iroha_core::queue::Error::Full
        | iroha_core::queue::Error::Deferred(_)
        | iroha_core::queue::Error::LatencySaturated
        | iroha_core::queue::Error::MaximumTransactionsPerUser => {
            Err(ModerationStrictIngressFailureV1::Backpressure)
        }
        iroha_core::queue::Error::AdmissionInvariant { .. }
        | iroha_core::queue::Error::UnresolvedRoute { .. } => {
            Err(ModerationStrictIngressFailureV1::Unavailable)
        }
        iroha_core::queue::Error::Expired
        | iroha_core::queue::Error::TransactionDomainMismatch(_)
        | iroha_core::queue::Error::UnsupportedTransactionAdmission { .. }
        | iroha_core::queue::Error::UnregisteredAuthority { .. }
        | iroha_core::queue::Error::Governance(_)
        | iroha_core::queue::Error::GovernanceNotPermitted { .. }
        | iroha_core::queue::Error::LaneComplianceDenied { .. }
        | iroha_core::queue::Error::LanePrivacyProofRejected { .. }
        | iroha_core::queue::Error::NexusFeeAdmissionRejected { .. }
        | iroha_core::queue::Error::NexusFeeAdmissionConfigInvalid { .. } => {
            Err(ModerationStrictIngressFailureV1::PermanentRejection)
        }
    }
}
fn map_ingress_failure(error: ModerationStrictIngressFailureV1) -> ModerationSubmissionFailureV1 {
    match error {
        ModerationStrictIngressFailureV1::Unavailable => {
            ModerationSubmissionFailureV1::NotSubmittedUnavailable
        }
        ModerationStrictIngressFailureV1::Backpressure => {
            ModerationSubmissionFailureV1::NotSubmittedBackpressure
        }
        ModerationStrictIngressFailureV1::Ambiguous => ModerationSubmissionFailureV1::Ambiguous,
        ModerationStrictIngressFailureV1::PermanentRejection => {
            ModerationSubmissionFailureV1::PermanentRejection
        }
        ModerationStrictIngressFailureV1::RuntimeUnavailable => {
            ModerationSubmissionFailureV1::RuntimeUnavailable
        }
    }
}
fn sanitize_submission_lookup(
    lookup: ModerationSubmissionLookupV1,
    expected_transaction_id: Option<[u8; 32]>,
) -> ModerationSubmissionLookupV1 {
    let matches_expected = |candidate: [u8; 32]| {
        candidate != [0; 32] && expected_transaction_id.is_none_or(|expected| expected == candidate)
    };
    match lookup {
        ModerationSubmissionLookupV1::NotFound {
            observed_finalized_height,
        } if observed_finalized_height != 0 => ModerationSubmissionLookupV1::NotFound {
            observed_finalized_height,
        },
        ModerationSubmissionLookupV1::Pending { transaction_id }
            if matches_expected(transaction_id) =>
        {
            ModerationSubmissionLookupV1::Pending { transaction_id }
        }
        ModerationSubmissionLookupV1::Applied { transaction_id }
            if matches_expected(transaction_id) =>
        {
            ModerationSubmissionLookupV1::Applied { transaction_id }
        }
        ModerationSubmissionLookupV1::Rejected {
            transaction_id,
            observed_finalized_height,
        } if observed_finalized_height != 0
            && transaction_id.is_none_or(matches_expected)
            && transaction_id != Some([0; 32]) =>
        {
            ModerationSubmissionLookupV1::Rejected {
                transaction_id,
                observed_finalized_height,
            }
        }
        ModerationSubmissionLookupV1::Unknown
        | ModerationSubmissionLookupV1::NotFound { .. }
        | ModerationSubmissionLookupV1::Pending { .. }
        | ModerationSubmissionLookupV1::Applied { .. }
        | ModerationSubmissionLookupV1::Rejected { .. } => ModerationSubmissionLookupV1::Unknown,
    }
}
/// Finalized snapshot reader backed directly by native state queries.
pub struct ModerationStateSnapshotReaderV1 {
    state: Arc<State>,
    event_page_size: u32,
}
impl core::fmt::Debug for ModerationStateSnapshotReaderV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ModerationStateSnapshotReaderV1")
            .field("state", &"<immutable-query-view>")
            .field("event_page_size", &self.event_page_size)
            .finish()
    }
}
impl ModerationStateSnapshotReaderV1 {
    /// Construct a reader with the default bounded committed-event page size.
    #[must_use]
    pub fn new(state: Arc<State>) -> Self {
        Self {
            state,
            event_page_size: DEFAULT_MODERATION_EVENT_PAGE_SIZE_V1,
        }
    }
}
impl ModerationFinalizedSnapshotReaderV1 for ModerationStateSnapshotReaderV1 {
    fn read_finalized_snapshot(
        &self,
        max_cases: usize,
        max_events: usize,
    ) -> Result<ModerationFinalizedLedgerSnapshotV1, ModerationSnapshotReadErrorV1> {
        let max_cases = bounded_query_limit(max_cases, MODERATION_QUERY_MAX_CASES_V1)?;
        let max_events = bounded_query_limit(max_events, MODERATION_QUERY_MAX_EVENTS_V1)?;
        // Both the snapshot and every validation page borrow this exact query
        // view. No field can be observed from a later finalized fork/tip.
        let view = self.state.query_view();
        let queries = StateModerationQueryViewV1 { view: &view };
        let snapshot =
            read_and_validate_snapshot(&queries, max_cases, max_events, self.event_page_size)?;
        validate_snapshot_finalized_block(&view, &snapshot)?;
        Ok(snapshot)
    }
}
fn validate_snapshot_finalized_block(
    view: &impl StateReadOnly,
    snapshot: &ModerationFinalizedLedgerSnapshotV1,
) -> Result<(), ModerationSnapshotReadErrorV1> {
    validate_snapshot_finalized_block_fields(
        snapshot,
        u64::try_from(view.height()).map_err(|_| ModerationSnapshotReadErrorV1::Unavailable)?,
        *view
            .latest_block_hash()
            .ok_or(ModerationSnapshotReadErrorV1::Unavailable)?
            .as_ref(),
        view.authenticated_query_ledger_time_ms()
            .ok_or(ModerationSnapshotReadErrorV1::Unavailable)?,
    )
}
fn validate_snapshot_finalized_block_fields(
    snapshot: &ModerationFinalizedLedgerSnapshotV1,
    block_height: u64,
    block_hash: [u8; 32],
    block_creation_time_ms: u64,
) -> Result<(), ModerationSnapshotReadErrorV1> {
    if block_height != snapshot.finalized_height
        || block_hash != snapshot.finalized_block_hash
        || block_creation_time_ms == 0
        || block_creation_time_ms != snapshot.finalized_at_unix_ms
    {
        return Err(ModerationSnapshotReadErrorV1::InvalidSnapshot);
    }
    Ok(())
}
fn bounded_query_limit(
    requested: usize,
    hard_max: u32,
) -> Result<u32, ModerationSnapshotReadErrorV1> {
    let requested =
        u32::try_from(requested).map_err(|_| ModerationSnapshotReadErrorV1::ResourceExhausted)?;
    if !(1..=hard_max).contains(&requested) {
        return Err(ModerationSnapshotReadErrorV1::ResourceExhausted);
    }
    Ok(requested)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeModerationQueryFailureV1 {
    Unavailable,
}
trait ModerationQueryViewV1 {
    fn snapshot(
        &self,
        max_cases: u32,
        max_events: u32,
    ) -> Result<ModerationFinalizedLedgerSnapshotV1, NativeModerationQueryFailureV1>;
    fn event_page(
        &self,
        expected_finalized_cursor:
            iroha_data_model::sorafs::moderation_ledger::ModerationFinalizedCursorV1,
        after: Option<ModerationFinalizedEventCursorV1>,
        limit: u32,
    ) -> Result<ModerationFinalizedEventPageV1, NativeModerationQueryFailureV1>;
}
struct StateModerationQueryViewV1<'view, 'state> {
    view: &'view StateQueryView<'state>,
}
impl ModerationQueryViewV1 for StateModerationQueryViewV1<'_, '_> {
    fn snapshot(
        &self,
        max_cases: u32,
        max_events: u32,
    ) -> Result<ModerationFinalizedLedgerSnapshotV1, NativeModerationQueryFailureV1> {
        FindSorafsModerationSnapshot {
            max_cases,
            max_events,
        }
        .execute(self.view)
        .map_err(|_| NativeModerationQueryFailureV1::Unavailable)
    }
    fn event_page(
        &self,
        expected_finalized_cursor:
            iroha_data_model::sorafs::moderation_ledger::ModerationFinalizedCursorV1,
        after: Option<ModerationFinalizedEventCursorV1>,
        limit: u32,
    ) -> Result<ModerationFinalizedEventPageV1, NativeModerationQueryFailureV1> {
        FindSorafsModerationEvents {
            expected_finalized_cursor,
            after,
            limit,
        }
        .execute(self.view)
        .map_err(|_| NativeModerationQueryFailureV1::Unavailable)
    }
}
fn read_and_validate_snapshot(
    queries: &impl ModerationQueryViewV1,
    max_cases: u32,
    max_events: u32,
    page_size: u32,
) -> Result<ModerationFinalizedLedgerSnapshotV1, ModerationSnapshotReadErrorV1> {
    if !(1..=MODERATION_QUERY_MAX_CASES_V1).contains(&max_cases)
        || !(1..=MODERATION_QUERY_MAX_EVENTS_V1).contains(&max_events)
        || !(1..=MODERATION_QUERY_MAX_EVENTS_V1).contains(&page_size)
    {
        return Err(ModerationSnapshotReadErrorV1::ResourceExhausted);
    }
    let snapshot = queries
        .snapshot(max_cases, max_events)
        .map_err(|_| ModerationSnapshotReadErrorV1::Unavailable)?;
    let max_cases_usize =
        usize::try_from(max_cases).map_err(|_| ModerationSnapshotReadErrorV1::ResourceExhausted)?;
    let max_events_usize = usize::try_from(max_events)
        .map_err(|_| ModerationSnapshotReadErrorV1::ResourceExhausted)?;
    if snapshot.version != MODERATION_FINALIZED_SNAPSHOT_VERSION_V1
        || snapshot.finalized_height == 0
        || snapshot.finalized_block_hash == [0; 32]
        || snapshot.finalized_at_unix_ms == 0
        || snapshot.appeals.len() > max_cases_usize
        || snapshot.cases.len() > max_cases_usize
        || snapshot.events.len() > max_events_usize
    {
        return Err(ModerationSnapshotReadErrorV1::InvalidSnapshot);
    }
    validate_snapshot_event_pages(queries, &snapshot, page_size, max_events)?;
    Ok(snapshot)
}
fn validate_snapshot_event_pages(
    queries: &impl ModerationQueryViewV1,
    snapshot: &ModerationFinalizedLedgerSnapshotV1,
    page_size: u32,
    max_events: u32,
) -> Result<(), ModerationSnapshotReadErrorV1> {
    let anchor = snapshot.anchor();
    let Some(first_event) = snapshot.events.first() else {
        let page = queries
            .event_page(anchor, None, page_size)
            .map_err(|_| ModerationSnapshotReadErrorV1::Unavailable)?;
        return if page.finalized_cursor == anchor
            && page.events.is_empty()
            && !page.has_more
            && page.next_after.is_none()
        {
            Ok(())
        } else {
            Err(ModerationSnapshotReadErrorV1::InvalidSnapshot)
        };
    };
    let mut after = if first_event.sequence == 1 {
        None
    } else {
        Some(first_event.cursor())
    };
    let mut expected_index = usize::from(first_event.sequence != 1);
    let maximum_pages = usize::try_from(max_events.div_ceil(page_size))
        .map_err(|_| ModerationSnapshotReadErrorV1::ResourceExhausted)?
        .saturating_add(1);
    let page_size_usize =
        usize::try_from(page_size).map_err(|_| ModerationSnapshotReadErrorV1::ResourceExhausted)?;
    for _ in 0..maximum_pages {
        let page = queries
            .event_page(anchor, after, page_size)
            .map_err(|_| ModerationSnapshotReadErrorV1::Unavailable)?;
        if page.finalized_cursor != anchor
            || page.events.len() > page_size_usize
            || page.next_after.is_some() != page.has_more
        {
            return Err(ModerationSnapshotReadErrorV1::InvalidSnapshot);
        }
        for event in &page.events {
            if snapshot.events.get(expected_index) != Some(event) {
                return Err(ModerationSnapshotReadErrorV1::InvalidSnapshot);
            }
            expected_index = expected_index
                .checked_add(1)
                .ok_or(ModerationSnapshotReadErrorV1::ResourceExhausted)?;
        }
        if page.has_more {
            let Some(last) = page.events.last() else {
                return Err(ModerationSnapshotReadErrorV1::InvalidSnapshot);
            };
            if page.next_after != Some(last.cursor()) || after == page.next_after {
                return Err(ModerationSnapshotReadErrorV1::InvalidSnapshot);
            }
            after = page.next_after;
            continue;
        }
        return if expected_index == snapshot.events.len() {
            Ok(())
        } else {
            Err(ModerationSnapshotReadErrorV1::InvalidSnapshot)
        };
    }
    Err(ModerationSnapshotReadErrorV1::ResourceExhausted)
}
/// Canonical handoff request supplied to a durable downstream boundary.
#[derive(Debug, Clone)]
pub struct ModerationDurableHandoffRequestV1 {
    /// Exact typed payload-free finalized handoff.
    pub handoff: ModerationTerminalHandoffV1,
    /// Canonical Norito encoding of `handoff`.
    pub canonical_handoff: Vec<u8>,
}
/// Canonical signed archive-head request supplied to the slot-20
/// `ModerationPublicationHandoff` boundary.
#[derive(Debug, Clone)]
pub struct ModerationDurableArchiveHeadPublicationRequestV1 {
    /// Exact authenticated monotonic archive head.
    pub head: ModerationPanelNotificationArchiveHeadV1,
    /// Canonical Norito encoding of `head`.
    pub canonical_head: Vec<u8>,
}
/// Successful result from a durable handoff boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModerationDurableHandoffOutcomeV1 {
    /// This call durably accepted the handoff.
    Delivered,
    /// The same handoff identity and bytes were already durably accepted.
    AlreadyDelivered,
}
/// Fixed durable-boundary failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModerationDurableHandoffFailureV1 {
    /// No delivery occurred and retry is safe.
    NotDelivered,
    /// Delivery may have occurred; retrying the same identity is required.
    Ambiguous,
    /// The exact handoff was permanently rejected.
    Permanent,
}
/// Durable, idempotent terminal settlement or publication boundary.
///
/// Implementations must atomically retain `handoff_id`, the digest of
/// `canonical_handoff`, and their downstream outbox effect before returning
/// [`ModerationDurableHandoffOutcomeV1::Delivered`]. A replay with different
/// bytes must return [`ModerationDurableHandoffFailureV1::Permanent`].
pub trait ModerationDurableHandoffBoundaryV1: ModerationRuntimeProviderV1 {
    /// Deliver or replay one exact terminal handoff.
    ///
    /// # Errors
    ///
    /// Returns a fixed delivery class. An ambiguous result is retried with the
    /// same handoff identity and canonical bytes.
    fn deliver_once(
        &self,
        request: &ModerationDurableHandoffRequestV1,
    ) -> Result<ModerationDurableHandoffOutcomeV1, ModerationDurableHandoffFailureV1>;
    /// Publish or replay one exact signed archive head under its operation identity.
    ///
    /// Implementations must atomically enforce generation/predecessor continuity,
    /// reject forks and gaps, and make the accepted monotonic head publicly readable.
    fn publish_archive_head_once(
        &self,
        request: &ModerationDurableArchiveHeadPublicationRequestV1,
    ) -> Result<ModerationDurableHandoffOutcomeV1, ModerationDurableHandoffFailureV1>;
    /// Read the monotonic public archive head from the publication store.
    fn read_published_archive_head(
        &self,
    ) -> Result<Option<ModerationPanelNotificationArchiveHeadV1>, ModerationDurableHandoffFailureV1>;
}
/// Destination-bound terminal handoff adapter.
pub struct ModerationTerminalHandoffSinkAdapterV1 {
    kind: ModerationTerminalHandoffKindV1,
    boundary: QualifiedModerationRuntimeProviderV1<dyn ModerationDurableHandoffBoundaryV1>,
}
impl core::fmt::Debug for ModerationTerminalHandoffSinkAdapterV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ModerationTerminalHandoffSinkAdapterV1")
            .field("kind", &self.kind)
            .field("boundary", &"<durable-idempotent-boundary>")
            .finish()
    }
}
impl ModerationTerminalHandoffSinkAdapterV1 {
    /// Construct and qualify the appeal-finance settlement sink.
    ///
    /// # Errors
    ///
    /// Fails when the boundary is unavailable, test-marked, substituted,
    /// stale, or differs from its independent exact binding.
    pub fn try_settlement(
        expected_handle: &str,
        expected_qualification: ModerationRuntimeProviderQualificationV1,
        boundary: Arc<dyn ModerationDurableHandoffBoundaryV1>,
    ) -> Result<Self, ModerationRuntimeProviderQualificationErrorV1> {
        Ok(Self {
            kind: ModerationTerminalHandoffKindV1::Settlement,
            boundary: QualifiedModerationRuntimeProviderV1::try_new(
                expected_handle,
                expected_qualification,
                boundary,
            )?,
        })
    }
    /// Construct and qualify the governance/transparency publication sink.
    ///
    /// # Errors
    ///
    /// Fails when the boundary is unavailable, test-marked, substituted,
    /// stale, or differs from its independent exact binding.
    pub fn try_publication(
        expected_handle: &str,
        expected_qualification: ModerationRuntimeProviderQualificationV1,
        boundary: Arc<dyn ModerationDurableHandoffBoundaryV1>,
    ) -> Result<Self, ModerationRuntimeProviderQualificationErrorV1> {
        Ok(Self {
            kind: ModerationTerminalHandoffKindV1::Publication,
            boundary: QualifiedModerationRuntimeProviderV1::try_new(
                expected_handle,
                expected_qualification,
                boundary,
            )?,
        })
    }
}
impl ModerationRuntimeProviderV1 for ModerationTerminalHandoffSinkAdapterV1 {
    fn handle(&self) -> &str {
        self.boundary.provider.handle()
    }
    fn qualification(
        &self,
    ) -> Result<ModerationRuntimeProviderQualificationV1, ModerationRuntimeProviderReadinessErrorV1>
    {
        self.boundary.provider.qualification()
    }
}
impl ModerationTerminalHandoffSinkV1 for ModerationTerminalHandoffSinkAdapterV1 {
    fn deliver(
        &self,
        handoff: &ModerationTerminalHandoffV1,
    ) -> Result<(), ModerationHandoffFailureV1> {
        if handoff.kind != self.kind
            || !handoff.is_bound_to_network(&handoff.network_id)
            || handoff.handoff_id == [0; 32]
            || handoff.outcome_digest == [0; 32]
            || handoff.finalized_cursor.block_height == 0
            || handoff.finalized_cursor.block_hash == [0; 32]
            || !is_canonical_moderation_identifier_v1(&handoff.case_id)
            || !is_canonical_moderation_identifier_v1(&handoff.round_id)
        {
            return Err(ModerationHandoffFailureV1::Permanent);
        }
        let canonical_handoff =
            norito::to_bytes(handoff).map_err(|_| ModerationHandoffFailureV1::Permanent)?;
        if canonical_handoff.is_empty() || canonical_handoff.len() > MODERATION_HANDOFF_MAX_BYTES_V1
        {
            return Err(ModerationHandoffFailureV1::Permanent);
        }
        let request = ModerationDurableHandoffRequestV1 {
            handoff: handoff.clone(),
            canonical_handoff,
        };
        self.boundary
            .revalidate()
            .map_err(|_| ModerationHandoffFailureV1::NotDelivered)?;
        let result = self.boundary.provider.deliver_once(&request);
        self.boundary
            .revalidate()
            .map_err(|_| ModerationHandoffFailureV1::Ambiguous)?;
        result.map(|_| ()).map_err(|error| match error {
            ModerationDurableHandoffFailureV1::NotDelivered => {
                ModerationHandoffFailureV1::NotDelivered
            }
            ModerationDurableHandoffFailureV1::Ambiguous => ModerationHandoffFailureV1::Ambiguous,
            ModerationDurableHandoffFailureV1::Permanent => ModerationHandoffFailureV1::Permanent,
        })
    }
    fn publish_panel_notification_archive_head(
        &self,
        head: &ModerationPanelNotificationArchiveHeadV1,
    ) -> Result<(), ModerationHandoffFailureV1> {
        if self.kind != ModerationTerminalHandoffKindV1::Publication
            || head
                .verify(
                    &head.archive_handle,
                    ModerationRuntimeProviderQualificationV1::new(
                        head.archive_revision,
                        head.archive_policy_digest,
                    ),
                    head.archive_id,
                    head.archive_public_key,
                )
                .is_err()
        {
            return Err(ModerationHandoffFailureV1::Permanent);
        }
        let canonical_head =
            norito::to_bytes(head).map_err(|_| ModerationHandoffFailureV1::Permanent)?;
        if canonical_head.is_empty() || canonical_head.len() > MODERATION_HANDOFF_MAX_BYTES_V1 {
            return Err(ModerationHandoffFailureV1::Permanent);
        }
        let request = ModerationDurableArchiveHeadPublicationRequestV1 {
            head: head.clone(),
            canonical_head,
        };
        self.boundary
            .revalidate()
            .map_err(|_| ModerationHandoffFailureV1::NotDelivered)?;
        let result = self.boundary.provider.publish_archive_head_once(&request);
        self.boundary
            .revalidate()
            .map_err(|_| ModerationHandoffFailureV1::Ambiguous)?;
        result.map(|_| ()).map_err(|error| match error {
            ModerationDurableHandoffFailureV1::NotDelivered => {
                ModerationHandoffFailureV1::NotDelivered
            }
            ModerationDurableHandoffFailureV1::Ambiguous => ModerationHandoffFailureV1::Ambiguous,
            ModerationDurableHandoffFailureV1::Permanent => ModerationHandoffFailureV1::Permanent,
        })
    }
    fn read_panel_notification_archive_head(
        &self,
    ) -> Result<Option<ModerationPanelNotificationArchiveHeadV1>, ModerationHandoffFailureV1> {
        if self.kind != ModerationTerminalHandoffKindV1::Publication {
            return Err(ModerationHandoffFailureV1::Permanent);
        }
        self.boundary
            .revalidate()
            .map_err(|_| ModerationHandoffFailureV1::NotDelivered)?;
        let result = self.boundary.provider.read_published_archive_head();
        self.boundary
            .revalidate()
            .map_err(|_| ModerationHandoffFailureV1::Ambiguous)?;
        let head = result.map_err(|error| match error {
            ModerationDurableHandoffFailureV1::NotDelivered => {
                ModerationHandoffFailureV1::NotDelivered
            }
            ModerationDurableHandoffFailureV1::Ambiguous => ModerationHandoffFailureV1::Ambiguous,
            ModerationDurableHandoffFailureV1::Permanent => ModerationHandoffFailureV1::Permanent,
        })?;
        if head.as_ref().is_some_and(|head| {
            norito::to_bytes(head).ok().is_none_or(|bytes| {
                bytes.is_empty() || bytes.len() > MODERATION_HANDOFF_MAX_BYTES_V1
            }) || head
                .verify(
                    &head.archive_handle,
                    ModerationRuntimeProviderQualificationV1::new(
                        head.archive_revision,
                        head.archive_policy_digest,
                    ),
                    head.archive_id,
                    head.archive_public_key,
                )
                .is_err()
        }) {
            return Err(ModerationHandoffFailureV1::Permanent);
        }
        Ok(head)
    }
}
/// Canonical request supplied to a durable panel-notification boundary.
#[derive(Debug, Clone)]
pub struct ModerationDurablePanelNotificationRequestV1 {
    /// Exact typed payload-free notification.
    pub notification: sorafs_node::moderation_orchestrator::ModerationPanelNotificationV1,
    /// Canonical Norito encoding of `notification`.
    pub canonical_notification: Vec<u8>,
    /// Exclusive expiry of the durable orchestrator claim.
    pub lease_expires_at_unix_ms: u64,
    /// One-based delivery attempt.
    pub attempt: u32,
    /// Immutable bounded attempt ceiling.
    pub attempt_limit: u32,
}
/// Durable, idempotent payload-free panel-notification boundary.
///
/// Implementations must atomically bind `notification.notification_id` to the digest of
/// `canonical_notification` and the stable receipt before returning. Exact replays return the same
/// receipt; a conflicting byte stream is permanently rejected. Credentials and recipient-facing
/// message bodies stay behind this runtime-only boundary.
pub trait ModerationDurablePanelNotificationBoundaryV1: ModerationRuntimeProviderV1 {
    /// Deliver or replay one exact payload-free notification.
    ///
    /// # Errors
    ///
    /// Returns a fixed delivery class without provider diagnostics.
    fn deliver_once(
        &self,
        request: &ModerationDurablePanelNotificationRequestV1,
    ) -> Result<ModerationPanelNotificationDeliveryReceiptV1, ModerationPanelNotificationFailureV1>;
}
/// Adapter from the durable runtime boundary to the moderation orchestrator.
pub struct ModerationPanelNotificationSinkAdapterV1 {
    boundary:
        QualifiedModerationRuntimeProviderV1<dyn ModerationDurablePanelNotificationBoundaryV1>,
}
impl core::fmt::Debug for ModerationPanelNotificationSinkAdapterV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ModerationPanelNotificationSinkAdapterV1")
            .field("boundary", &"<durable-idempotent-boundary>")
            .finish()
    }
}
impl ModerationPanelNotificationSinkAdapterV1 {
    /// Construct and qualify the payload-free notification boundary.
    ///
    /// # Errors
    ///
    /// Fails when the boundary is unavailable, test-marked, substituted,
    /// stale, or differs from its independent exact binding.
    pub fn try_new(
        expected_handle: &str,
        expected_qualification: ModerationRuntimeProviderQualificationV1,
        boundary: Arc<dyn ModerationDurablePanelNotificationBoundaryV1>,
    ) -> Result<Self, ModerationRuntimeProviderQualificationErrorV1> {
        Ok(Self {
            boundary: QualifiedModerationRuntimeProviderV1::try_new(
                expected_handle,
                expected_qualification,
                boundary,
            )?,
        })
    }
}
impl ModerationRuntimeProviderV1 for ModerationPanelNotificationSinkAdapterV1 {
    fn handle(&self) -> &str {
        self.boundary.provider.handle()
    }
    fn qualification(
        &self,
    ) -> Result<ModerationRuntimeProviderQualificationV1, ModerationRuntimeProviderReadinessErrorV1>
    {
        self.boundary.provider.qualification()
    }
}
impl ModerationPanelNotificationSinkV1 for ModerationPanelNotificationSinkAdapterV1 {
    fn deliver(
        &self,
        claim: &ModerationPanelNotificationClaimV1,
    ) -> Result<ModerationPanelNotificationDeliveryReceiptV1, ModerationPanelNotificationFailureV1>
    {
        if !claim
            .notification
            .is_bound_to_network(&claim.notification.network_id)
            || claim.notification.notification_id == [0; 32]
            || claim.notification.source_operation_id == [0; 32]
            || claim.notification.scope_digest == [0; 32]
            || claim.notification.finalized_event_cursor.sequence == 0
            || claim.notification.finalized_event_cursor.block_height == 0
            || claim.notification.finalized_event_cursor.block_hash == [0; 32]
            || claim.notification.source_occurred_at_unix_ms == 0
            || claim.worker_id == [0; 32]
            || claim.lease_token == [0; 32]
            || claim.lease_expires_at_unix_ms <= claim.notification.source_occurred_at_unix_ms
            || claim.attempt == 0
            || claim.attempt > claim.attempt_limit
        {
            return Err(ModerationPanelNotificationFailureV1::Permanent);
        }
        let canonical_notification = norito::to_bytes(&claim.notification)
            .map_err(|_| ModerationPanelNotificationFailureV1::Permanent)?;
        if canonical_notification.is_empty()
            || canonical_notification.len() > MODERATION_PANEL_NOTIFICATION_MAX_BYTES_V1
        {
            return Err(ModerationPanelNotificationFailureV1::Permanent);
        }
        let request = ModerationDurablePanelNotificationRequestV1 {
            notification: claim.notification.clone(),
            canonical_notification,
            lease_expires_at_unix_ms: claim.lease_expires_at_unix_ms,
            attempt: claim.attempt,
            attempt_limit: claim.attempt_limit,
        };
        self.boundary
            .revalidate()
            .map_err(|_| ModerationPanelNotificationFailureV1::NotDelivered)?;
        let result = self.boundary.provider.deliver_once(&request);
        self.boundary
            .revalidate()
            .map_err(|_| ModerationPanelNotificationFailureV1::Ambiguous)?;
        let receipt = result?;
        if receipt.notification_id != request.notification.notification_id
            || receipt.receipt_digest == [0; 32]
            || receipt.delivered_at_unix_ms < request.notification.source_occurred_at_unix_ms
            || receipt.delivered_at_unix_ms >= request.lease_expires_at_unix_ms
        {
            return Err(ModerationPanelNotificationFailureV1::Ambiguous);
        }
        Ok(receipt)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair, Signature};
    use iroha_data_model::{
        events::data::sorafs::{SorafsModerationLedgerEvent, SorafsModerationLedgerEventKind},
        isi::sorafs::FinalizeSorafsModerationCase,
        sorafs::moderation_ledger::{ModerationFinalizedCursorV1, ModerationFinalizedEventV1},
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    use sorafs_node::moderation_orchestrator::ModerationNativeActionV1;
    use std::{
        collections::{BTreeMap, VecDeque},
        sync::{
            Barrier, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };
    const TEST_SIGNER_HANDLE: &str = "moderation-provider-primary";
    const TEST_INGRESS_HANDLE: &str = "moderation-ingress-primary";
    const TEST_HANDOFF_HANDLE: &str = "moderation-handoff-primary";
    const TEST_NOTIFICATION_HANDLE: &str = "moderation-notification-primary";
    const TEST_SIGNER_QUALIFICATION: ModerationRuntimeProviderQualificationV1 =
        ModerationRuntimeProviderQualificationV1::new(1, [0xA1; 32]);
    const TEST_INGRESS_QUALIFICATION: ModerationRuntimeProviderQualificationV1 =
        ModerationRuntimeProviderQualificationV1::new(1, [0xA2; 32]);
    const TEST_HANDOFF_QUALIFICATION: ModerationRuntimeProviderQualificationV1 =
        ModerationRuntimeProviderQualificationV1::new(1, [0xA3; 32]);
    const TEST_NOTIFICATION_QUALIFICATION: ModerationRuntimeProviderQualificationV1 =
        ModerationRuntimeProviderQualificationV1::new(1, [0xA4; 32]);
    fn test_network_id(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(
            HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                Hash::prehashed([seed; 32]),
            ),
        )
    }
    #[test]
    fn queue_domain_mismatch_is_permanent_moderation_rejection() {
        use iroha_core::queue::Error;
        use iroha_data_model::{isi::error::Mismatch, transaction::TransactionDomain};

        for actual in [
            TransactionDomain::Genesis,
            TransactionDomain::Network(test_network_id(2)),
        ] {
            let error = Error::TransactionDomainMismatch(Mismatch {
                expected: TransactionDomain::Network(test_network_id(1)),
                actual,
            });
            assert_eq!(
                classify_local_moderation_queue_rejection(&error),
                Err(ModerationStrictIngressFailureV1::PermanentRejection)
            );
        }
        assert_eq!(
            classify_local_moderation_queue_rejection(&Error::IsInQueue),
            Ok(())
        );
        assert_eq!(
            classify_local_moderation_queue_rejection(&Error::InBlockchain),
            Ok(())
        );
        assert_eq!(
            classify_local_moderation_queue_rejection(&Error::Full),
            Err(ModerationStrictIngressFailureV1::Backpressure)
        );
        assert_eq!(
            classify_local_moderation_queue_rejection(&Error::AdmissionInvariant {
                reason: "original index unavailable".to_owned()
            }),
            Err(ModerationStrictIngressFailureV1::Unavailable)
        );
    }
    #[test]
    fn torii_strict_ingress_public_binding_preflight_is_exact() {
        let exact = torii_moderation_strict_ingress_qualification_v1();
        assert_eq!(
            qualify_torii_moderation_strict_ingress_binding_v1(
                TORII_MODERATION_STRICT_INGRESS_HANDLE_V1,
                exact,
            ),
            Ok(())
        );
        for (handle, qualification, expected) in [
            (
                "",
                exact,
                ModerationRuntimeProviderQualificationErrorV1::InvalidConfiguredHandle,
            ),
            (
                "torii.sorafs.moderation-test-ingress.v1",
                exact,
                ModerationRuntimeProviderQualificationErrorV1::TestMarkedConfiguredHandle,
            ),
            (
                "torii.sorafs.moderation-strict-ingress.primary",
                exact,
                ModerationRuntimeProviderQualificationErrorV1::SubstitutedProvider,
            ),
            (
                TORII_MODERATION_STRICT_INGRESS_HANDLE_V1,
                ModerationRuntimeProviderQualificationV1::new(0, exact.policy_digest()),
                ModerationRuntimeProviderQualificationErrorV1::InvalidConfiguredQualification,
            ),
            (
                TORII_MODERATION_STRICT_INGRESS_HANDLE_V1,
                ModerationRuntimeProviderQualificationV1::new(
                    exact.revision() + 1,
                    exact.policy_digest(),
                ),
                ModerationRuntimeProviderQualificationErrorV1::QualificationMismatch,
            ),
        ] {
            assert_eq!(
                qualify_torii_moderation_strict_ingress_binding_v1(handle, qualification),
                Err(expected)
            );
        }
    }
    #[test]
    fn local_strict_ingress_identity_is_implementation_derived() {
        assert_eq!(
            TORII_MODERATION_STRICT_INGRESS_POLICY_DIGEST_V1,
            *blake3::hash(b"sorafs.moderation.strict-ingress.torii.v1\0").as_bytes()
        );
        let qualification = torii_moderation_strict_ingress_qualification_v1();
        assert_eq!(
            qualification.revision(),
            TORII_MODERATION_STRICT_INGRESS_REVISION_V1
        );
        assert_eq!(
            qualification.policy_digest(),
            TORII_MODERATION_STRICT_INGRESS_POLICY_DIGEST_V1
        );
        assert_eq!(
            TORII_MODERATION_STRICT_INGRESS_HANDLE_V1,
            "torii.sorafs.moderation-strict-ingress.v1"
        );
        assert!(iroha_config::parameters::is_production_runtime_handle(
            TORII_MODERATION_STRICT_INGRESS_HANDLE_V1
        ));
    }
    fn key(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("test Ed25519 key")
    }
    fn account(key_pair: &KeyPair) -> AccountId {
        AccountId::new(key_pair.public_key().clone())
    }
    fn cached_snapshot(
        finalized_height: u64,
        finalized_block_hash: [u8; 32],
    ) -> ModerationFinalizedLedgerSnapshotV1 {
        ModerationFinalizedLedgerSnapshotV1 {
            version: MODERATION_FINALIZED_SNAPSHOT_VERSION_V1,
            finalized_height,
            finalized_block_hash,
            finalized_at_unix_ms: finalized_height.saturating_mul(1_000),
            policy: None,
            status: None,
            appeals: Vec::new(),
            cases: Vec::new(),
            events: Vec::new(),
        }
    }
    fn cached_health(
        snapshot: &ModerationFinalizedLedgerSnapshotV1,
    ) -> ModerationOrchestratorDurableHealthV1 {
        ModerationOrchestratorDurableHealthV1 {
            finalized_cursor: Some(snapshot.anchor()),
            pending_submissions: 0,
            pending_handoffs: 0,
            pending_panel_notifications: 0,
            durable_dead_letters: 0,
            panel_notification_dead_letters: 0,
            panel_notification_archive_generation: 0,
            panel_notification_archive_published_generation: 0,
            panel_notification_archive_audited_generation: 0,
        }
    }
    #[test]
    fn hung_maintenance_is_unready_and_cannot_overlap_after_deadline() {
        let cache = ModerationFinalizedProjectionCacheV1::new(Duration::from_secs(60));
        assert!(cache.begin_maintenance());
        cache.mark_deadline_exceeded();
        assert!(!cache.begin_maintenance());
        assert_eq!(
            cache.snapshot(),
            Err(ModerationProjectionReadErrorV1::DeadlineExceeded)
        );
        cache.finish_failure(ModerationProjectionReadErrorV1::DependencyFailed);
        assert!(cache.begin_maintenance());
    }
    #[test]
    fn cached_projection_fails_closed_after_monotonic_freshness_expires() {
        let cache = ModerationFinalizedProjectionCacheV1::new(Duration::ZERO);
        let snapshot = cached_snapshot(7, [0x71; 32]);
        assert!(cache.begin_maintenance());
        cache
            .finish_success(snapshot.clone(), cached_health(&snapshot))
            .expect("install finalized projection");
        assert_eq!(
            cache.snapshot(),
            Err(ModerationProjectionReadErrorV1::Stale)
        );
    }
    #[test]
    fn concurrent_cached_reads_never_start_maintenance_or_mutate_projection() {
        const READERS: usize = 16;
        const READS_PER_THREAD: usize = 128;
        let cache = Arc::new(ModerationFinalizedProjectionCacheV1::new(
            Duration::from_secs(60),
        ));
        let snapshot = cached_snapshot(9, [0x91; 32]);
        assert!(cache.begin_maintenance());
        cache
            .finish_success(snapshot.clone(), cached_health(&snapshot))
            .expect("install finalized projection");
        let barrier = Arc::new(Barrier::new(READERS));
        let readers = (0..READERS)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..READS_PER_THREAD {
                        let snapshot = cache.snapshot().expect("fresh cached projection");
                        assert_eq!(snapshot.finalized_height, 9);
                        assert_eq!(snapshot.finalized_block_hash, [0x91; 32]);
                    }
                })
            })
            .collect::<Vec<_>>();
        for reader in readers {
            reader.join().expect("cached projection reader");
        }
        assert!(!cache.in_flight.load(Ordering::Acquire));
    }
    #[test]
    fn durable_dead_letter_blocks_projection_readiness() {
        let cache = ModerationFinalizedProjectionCacheV1::new(Duration::from_secs(60));
        let snapshot = cached_snapshot(11, [0xB1; 32]);
        let mut health = cached_health(&snapshot);
        health.panel_notification_dead_letters = 1;
        assert!(cache.begin_maintenance());
        assert_eq!(
            cache.finish_success(snapshot, health),
            Err(ModerationProjectionReadErrorV1::DeadLetters)
        );
        assert_eq!(
            cache.snapshot(),
            Err(ModerationProjectionReadErrorV1::DeadLetters)
        );
    }
    #[test]
    fn cache_rejects_finalized_cursor_regression_and_equivocation() {
        for invalid in [
            cached_snapshot(12, [0xC2; 32]),
            cached_snapshot(13, [0xD3; 32]),
        ] {
            let cache = ModerationFinalizedProjectionCacheV1::new(Duration::from_secs(60));
            let initial = cached_snapshot(13, [0xC3; 32]);
            assert!(cache.begin_maintenance());
            cache
                .finish_success(initial.clone(), cached_health(&initial))
                .expect("install initial cursor");
            assert!(cache.begin_maintenance());
            assert_eq!(
                cache.finish_success(invalid.clone(), cached_health(&invalid)),
                Err(ModerationProjectionReadErrorV1::InvalidProjection)
            );
            assert_eq!(
                cache.snapshot(),
                Err(ModerationProjectionReadErrorV1::InvalidProjection)
            );
        }
    }
    #[test]
    fn worker_deadline_and_freshness_are_bounded_by_cadence_and_external_lease() {
        let cadence = Duration::from_secs(1);
        assert_eq!(
            moderation_worker_deadline(cadence),
            Duration::from_millis(MODERATION_EXTERNAL_WORK_LEASE_MS_V1)
        );
        assert_eq!(
            moderation_projection_freshness_limit(cadence),
            Duration::from_millis(MODERATION_EXTERNAL_WORK_LEASE_MS_V1)
                .checked_add(Duration::from_secs(2))
                .expect("test duration")
        );
        let slow_cadence = Duration::from_secs(60);
        assert_eq!(moderation_worker_deadline(slow_cadence), slow_cadence);
        assert_eq!(
            moderation_projection_freshness_limit(slow_cadence),
            Duration::from_secs(180)
        );
    }
    fn action() -> ModerationNativeActionV1 {
        ModerationNativeActionV1::FinalizeCase(FinalizeSorafsModerationCase::new(
            "case-1".to_owned(),
            "round-1".to_owned(),
        ))
    }
    fn transaction_request(authority: AccountId) -> ModerationTransactionRequestV1 {
        ModerationTransactionRequestV1::new(
            test_network_id(0xA5),
            1,
            authority,
            action(),
            [0x42; 32],
            7,
            [0x43; 32],
        )
        .expect("canonical transaction request")
    }
    fn sign_and_submit(
        adapter: &ModerationTransactionSubmitterAdapterV1,
        request: &ModerationTransactionRequestV1,
    ) -> Result<ModerationTransactionReceiptV1, ModerationSubmissionFailureV1> {
        let signed = adapter.sign(request)?;
        adapter.submit_signed(request, &signed)
    }
    #[derive(Debug)]
    enum FixedSignerBehavior {
        Exact,
        SubstituteNetwork,
        Forged(KeyPair),
    }
    #[derive(Debug)]
    struct FixedSigner {
        key_pair: KeyPair,
        behavior: FixedSignerBehavior,
        calls: AtomicUsize,
        handle: String,
        qualification: Mutex<
            Result<
                ModerationRuntimeProviderQualificationV1,
                ModerationRuntimeProviderReadinessErrorV1,
            >,
        >,
        qualification_after_sign: Mutex<Option<ModerationRuntimeProviderQualificationV1>>,
    }
    impl FixedSigner {
        fn exact(key_pair: KeyPair) -> Self {
            Self {
                key_pair,
                behavior: FixedSignerBehavior::Exact,
                calls: AtomicUsize::new(0),
                handle: TEST_SIGNER_HANDLE.to_owned(),
                qualification: Mutex::new(Ok(TEST_SIGNER_QUALIFICATION)),
                qualification_after_sign: Mutex::new(None),
            }
        }
        fn substitute_network(key_pair: KeyPair) -> Self {
            Self {
                key_pair,
                behavior: FixedSignerBehavior::SubstituteNetwork,
                calls: AtomicUsize::new(0),
                handle: TEST_SIGNER_HANDLE.to_owned(),
                qualification: Mutex::new(Ok(TEST_SIGNER_QUALIFICATION)),
                qualification_after_sign: Mutex::new(None),
            }
        }
        fn forged(key_pair: KeyPair, forgery_key: KeyPair) -> Self {
            Self {
                key_pair,
                behavior: FixedSignerBehavior::Forged(forgery_key),
                calls: AtomicUsize::new(0),
                handle: TEST_SIGNER_HANDLE.to_owned(),
                qualification: Mutex::new(Ok(TEST_SIGNER_QUALIFICATION)),
                qualification_after_sign: Mutex::new(None),
            }
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
        fn drift_after_sign(&self, qualification: ModerationRuntimeProviderQualificationV1) {
            *self
                .qualification_after_sign
                .lock()
                .expect("signer qualification drift lock") = Some(qualification);
        }
    }
    impl ModerationRuntimeProviderV1 for FixedSigner {
        fn handle(&self) -> &str {
            &self.handle
        }
        fn qualification(
            &self,
        ) -> Result<
            ModerationRuntimeProviderQualificationV1,
            ModerationRuntimeProviderReadinessErrorV1,
        > {
            *self
                .qualification
                .lock()
                .expect("signer qualification lock")
        }
    }
    impl ModerationSignedTransactionSignerV1 for FixedSigner {
        fn sign(
            &self,
            mut payload: TransactionPayload,
        ) -> Result<SignedTransaction, ModerationSigningFailureV1> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let result = match &self.behavior {
                FixedSignerBehavior::Exact => TransactionBuilder::from_payload(payload)
                    .and_then(|builder| builder.try_sign(self.key_pair.private_key()))
                    .map_err(|_| ModerationSigningFailureV1::Refused),
                FixedSignerBehavior::SubstituteNetwork => {
                    payload.domain = TransactionDomain::Network(test_network_id(0xEE));
                    TransactionBuilder::from_payload(payload)
                        .and_then(|builder| builder.try_sign(self.key_pair.private_key()))
                        .map_err(|_| ModerationSigningFailureV1::Refused)
                }
                FixedSignerBehavior::Forged(forgery_key) => {
                    Ok(TransactionBuilder::from_payload(payload)
                        .map_err(|_| ModerationSigningFailureV1::Refused)?
                        .build_with_signature(Signature::new(
                            forgery_key.private_key(),
                            b"not-the-transaction-payload",
                        )))
                }
            };
            if let Some(qualification) = self
                .qualification_after_sign
                .lock()
                .expect("signer qualification drift lock")
                .take()
            {
                *self
                    .qualification
                    .lock()
                    .expect("signer qualification lock") = Ok(qualification);
            }
            result
        }
    }
    #[derive(Debug)]
    struct TestFeeQuoter;
    impl ModerationFeeQuoterV1 for TestFeeQuoter {
        fn quote(
            &self,
            payload: &TransactionPayload,
        ) -> Result<FeePaymentIntent, ModerationFeeQuoteFailureV1> {
            Ok(payload.fee_payment.clone())
        }
    }
    fn adapter(
        signer: Arc<dyn ModerationSignedTransactionSignerV1>,
        ingress: Arc<dyn ModerationStrictTransactionIngressV1>,
    ) -> ModerationTransactionSubmitterAdapterV1 {
        ModerationTransactionSubmitterAdapterV1::try_new(
            test_network_id(0xA5),
            TEST_SIGNER_HANDLE,
            TEST_SIGNER_QUALIFICATION,
            signer,
            Arc::new(TestFeeQuoter),
            TEST_INGRESS_HANDLE,
            TEST_INGRESS_QUALIFICATION,
            ingress,
        )
        .expect("qualified moderation adapter")
    }
    #[derive(Debug, Default)]
    struct TestIngressState {
        calls: usize,
        admissions: BTreeMap<[u8; 32], [u8; 32]>,
    }
    #[derive(Debug)]
    struct TestIngress {
        state: Mutex<TestIngressState>,
        handle: String,
        qualification: Mutex<
            Result<
                ModerationRuntimeProviderQualificationV1,
                ModerationRuntimeProviderReadinessErrorV1,
            >,
        >,
        qualification_after_submit: Mutex<Option<ModerationRuntimeProviderQualificationV1>>,
        qualification_after_lookup: Mutex<Option<ModerationRuntimeProviderQualificationV1>>,
    }
    impl Default for TestIngress {
        fn default() -> Self {
            Self {
                state: Mutex::new(TestIngressState::default()),
                handle: TEST_INGRESS_HANDLE.to_owned(),
                qualification: Mutex::new(Ok(TEST_INGRESS_QUALIFICATION)),
                qualification_after_submit: Mutex::new(None),
                qualification_after_lookup: Mutex::new(None),
            }
        }
    }
    impl TestIngress {
        fn calls(&self) -> usize {
            self.state.lock().expect("ingress lock").calls
        }
        fn unique_admissions(&self) -> usize {
            self.state.lock().expect("ingress lock").admissions.len()
        }
        fn drift_after_submit(&self, qualification: ModerationRuntimeProviderQualificationV1) {
            *self
                .qualification_after_submit
                .lock()
                .expect("ingress submit drift lock") = Some(qualification);
        }
        fn drift_after_lookup(&self, qualification: ModerationRuntimeProviderQualificationV1) {
            *self
                .qualification_after_lookup
                .lock()
                .expect("ingress lookup drift lock") = Some(qualification);
        }
        fn set_qualification(&self, qualification: ModerationRuntimeProviderQualificationV1) {
            *self
                .qualification
                .lock()
                .expect("ingress qualification lock") = Ok(qualification);
        }
    }
    impl ModerationRuntimeProviderV1 for TestIngress {
        fn handle(&self) -> &str {
            &self.handle
        }
        fn qualification(
            &self,
        ) -> Result<
            ModerationRuntimeProviderQualificationV1,
            ModerationRuntimeProviderReadinessErrorV1,
        > {
            *self
                .qualification
                .lock()
                .expect("ingress qualification lock")
        }
    }
    impl ModerationStrictTransactionIngressV1 for TestIngress {
        fn submit_exact(
            &self,
            request: &ModerationTransactionRequestV1,
            transaction: SignedTransaction,
        ) -> Result<ModerationStrictIngressReceiptV1, ModerationStrictIngressFailureV1> {
            let transaction_id = *transaction.hash().as_ref();
            let mut state = self.state.lock().expect("ingress lock");
            state.calls = state.calls.saturating_add(1);
            let replay = match state.admissions.get(&request.operation_id) {
                Some(existing) if *existing == transaction_id => true,
                Some(_) => return Err(ModerationStrictIngressFailureV1::PermanentRejection),
                None => {
                    state
                        .admissions
                        .insert(request.operation_id, transaction_id);
                    false
                }
            };
            let result = Ok(ModerationStrictIngressReceiptV1 {
                transaction_id,
                observed_finalized_height: 7,
                replay,
            });
            if let Some(qualification) = self
                .qualification_after_submit
                .lock()
                .expect("ingress submit drift lock")
                .take()
            {
                *self
                    .qualification
                    .lock()
                    .expect("ingress qualification lock") = Ok(qualification);
            }
            result
        }
        fn lookup_exact(
            &self,
            operation_id: [u8; 32],
            _transaction_id: Option<[u8; 32]>,
        ) -> ModerationSubmissionLookupV1 {
            let lookup = self
                .state
                .lock()
                .expect("ingress lock")
                .admissions
                .get(&operation_id)
                .copied()
                .map_or(
                    ModerationSubmissionLookupV1::NotFound {
                        observed_finalized_height: 7,
                    },
                    |transaction_id| ModerationSubmissionLookupV1::Pending { transaction_id },
                );
            if let Some(qualification) = self
                .qualification_after_lookup
                .lock()
                .expect("ingress lookup drift lock")
                .take()
            {
                *self
                    .qualification
                    .lock()
                    .expect("ingress qualification lock") = Ok(qualification);
            }
            lookup
        }
    }
    #[test]
    fn submitter_rejects_a_test_marked_signer_before_use() {
        let signer_key = key(31);
        let mut signer = FixedSigner::exact(signer_key);
        signer.handle = "moderation-test-signer".to_owned();
        let ingress = Arc::new(TestIngress::default());
        let error = ModerationTransactionSubmitterAdapterV1::try_new(
            test_network_id(0xA5),
            TEST_SIGNER_HANDLE,
            TEST_SIGNER_QUALIFICATION,
            Arc::new(signer),
            Arc::new(TestFeeQuoter),
            TEST_INGRESS_HANDLE,
            TEST_INGRESS_QUALIFICATION,
            ingress,
        )
        .expect_err("test-marked signer must fail qualification");
        assert_eq!(
            error,
            ModerationRuntimeProviderQualificationErrorV1::TestMarkedProviderHandle
        );
    }
    #[test]
    fn signer_policy_drift_discards_the_returned_envelope() {
        let signer_key = key(32);
        let request = transaction_request(account(&signer_key));
        let signer = Arc::new(FixedSigner::exact(signer_key));
        let ingress = Arc::new(TestIngress::default());
        let adapter = adapter(signer.clone(), ingress);
        signer.drift_after_sign(ModerationRuntimeProviderQualificationV1::new(2, [0xB1; 32]));
        assert_eq!(
            adapter.sign(&request),
            Err(ModerationSubmissionFailureV1::RuntimeUnavailable)
        );
        assert_eq!(signer.calls(), 1);
    }
    #[test]
    fn same_label_different_genesis_is_rejected_before_signer_or_ingress() {
        let configured_display_label = "moderation-runtime-test".to_owned();
        let foreign_display_label = configured_display_label.clone();
        assert_eq!(configured_display_label, foreign_display_label);
        let signer_key = key(34);
        let request = ModerationTransactionRequestV1::new(
            test_network_id(0xA6),
            1,
            account(&signer_key),
            action(),
            [0x42; 32],
            7,
            [0x43; 32],
        )
        .expect("canonical request for the other genesis");
        let signer = Arc::new(FixedSigner::exact(signer_key));
        let ingress = Arc::new(TestIngress::default());
        let adapter = adapter(signer.clone(), ingress.clone());
        assert_eq!(
            adapter.sign(&request),
            Err(ModerationSubmissionFailureV1::PermanentRejection)
        );
        assert_eq!(signer.calls(), 0);
        assert_eq!(ingress.calls(), 0);
        assert_eq!(ingress.unique_admissions(), 0);
    }
    #[test]
    fn ingress_policy_drift_after_admission_is_ambiguous_and_lookup_is_discarded() {
        let signer_key = key(33);
        let request = transaction_request(account(&signer_key));
        let signer = Arc::new(FixedSigner::exact(signer_key));
        let ingress = Arc::new(TestIngress::default());
        let adapter = adapter(signer, ingress.clone());
        let signed = adapter.sign(&request).expect("qualified signer result");
        ingress.drift_after_submit(ModerationRuntimeProviderQualificationV1::new(2, [0xB2; 32]));
        assert_eq!(
            adapter.submit_signed(&request, &signed),
            Err(ModerationSubmissionFailureV1::Ambiguous)
        );
        assert_eq!(ingress.calls(), 1);
        assert_eq!(ingress.unique_admissions(), 1);
        ingress.set_qualification(TEST_INGRESS_QUALIFICATION);
        ingress.drift_after_lookup(ModerationRuntimeProviderQualificationV1::new(3, [0xC2; 32]));
        assert_eq!(
            adapter.lookup(request.operation_id, Some(signed.transaction_id)),
            ModerationSubmissionLookupV1::Unknown
        );
    }
    #[test]
    fn signer_authority_mismatch_is_rejected_before_ingress() {
        let expected_key = key(1);
        let substituted_key = key(2);
        let request = transaction_request(account(&expected_key));
        let signer = Arc::new(FixedSigner::exact(substituted_key));
        let ingress = Arc::new(TestIngress::default());
        let adapter = adapter(signer, ingress.clone());
        assert_eq!(
            sign_and_submit(&adapter, &request),
            Err(ModerationSubmissionFailureV1::PermanentRejection)
        );
        assert_eq!(ingress.calls(), 0);
        assert_eq!(ingress.unique_admissions(), 0);
    }
    #[test]
    fn canonical_request_digest_tampering_is_rejected_before_signing() {
        let signer_key = key(12);
        let mut request = transaction_request(account(&signer_key));
        let signer = Arc::new(FixedSigner::exact(signer_key));
        let ingress = Arc::new(TestIngress::default());
        let adapter = adapter(signer.clone(), ingress.clone());
        request.action_digest[0] ^= 0x80;
        assert_eq!(
            sign_and_submit(&adapter, &request),
            Err(ModerationSubmissionFailureV1::PermanentRejection)
        );
        assert_eq!(signer.calls(), 0);
        assert_eq!(ingress.calls(), 0);
    }
    #[test]
    fn forged_transaction_signature_is_rejected_before_ingress() {
        let authority_key = key(13);
        let forgery_key = key(14);
        let request = transaction_request(account(&authority_key));
        let signer = Arc::new(FixedSigner::forged(authority_key, forgery_key));
        let ingress = Arc::new(TestIngress::default());
        let adapter = adapter(signer, ingress.clone());
        assert_eq!(
            sign_and_submit(&adapter, &request),
            Err(ModerationSubmissionFailureV1::PermanentRejection)
        );
        assert_eq!(ingress.calls(), 0);
    }
    #[test]
    fn signer_payload_substitution_is_rejected_before_ingress() {
        let signer_key = key(15);
        let request = transaction_request(account(&signer_key));
        let signer = Arc::new(FixedSigner::substitute_network(signer_key));
        let ingress = Arc::new(TestIngress::default());
        let adapter = adapter(signer, ingress.clone());
        assert_eq!(
            sign_and_submit(&adapter, &request),
            Err(ModerationSubmissionFailureV1::PermanentRejection)
        );
        assert_eq!(ingress.calls(), 0);
    }
    #[test]
    fn strict_ingress_replay_admits_one_exact_retained_transaction() {
        let signer_key = key(3);
        let request = transaction_request(account(&signer_key));
        let signer = Arc::new(FixedSigner::exact(signer_key));
        let ingress = Arc::new(TestIngress::default());
        let adapter = adapter(signer, ingress.clone());
        let signed = adapter.sign(&request).expect("sign exact payload");
        let expected_transaction_id = signed.transaction_id;
        let first = adapter
            .submit_signed(&request, &signed)
            .expect("first submission");
        let replay = adapter
            .submit_signed(&request, &signed)
            .expect("idempotent replay");
        assert_eq!(first, replay);
        assert_eq!(first.transaction_id, expected_transaction_id);
        assert_eq!(ingress.calls(), 2);
        assert_eq!(ingress.unique_admissions(), 1);
    }
    #[test]
    fn lookup_rejects_a_foreign_transaction_identity() {
        assert_eq!(
            sanitize_submission_lookup(
                ModerationSubmissionLookupV1::Applied {
                    transaction_id: [0x51; 32],
                },
                Some([0x52; 32]),
            ),
            ModerationSubmissionLookupV1::Unknown
        );
    }
    #[derive(Debug)]
    struct TestQueries {
        snapshot: Result<ModerationFinalizedLedgerSnapshotV1, NativeModerationQueryFailureV1>,
        pages:
            Mutex<VecDeque<Result<ModerationFinalizedEventPageV1, NativeModerationQueryFailureV1>>>,
        requests: Mutex<Vec<(ModerationFinalizedCursorV1, Option<u64>, u32)>>,
    }
    impl TestQueries {
        fn new(
            snapshot: ModerationFinalizedLedgerSnapshotV1,
            pages: impl IntoIterator<
                Item = Result<ModerationFinalizedEventPageV1, NativeModerationQueryFailureV1>,
            >,
        ) -> Self {
            Self {
                snapshot: Ok(snapshot),
                pages: Mutex::new(pages.into_iter().collect()),
                requests: Mutex::new(Vec::new()),
            }
        }
        fn request_count(&self) -> usize {
            self.requests.lock().expect("query requests lock").len()
        }
        fn requested_limits(&self) -> Vec<u32> {
            self.requests
                .lock()
                .expect("query requests lock")
                .iter()
                .map(|(_, _, limit)| *limit)
                .collect()
        }
    }
    impl ModerationQueryViewV1 for TestQueries {
        fn snapshot(
            &self,
            _max_cases: u32,
            _max_events: u32,
        ) -> Result<ModerationFinalizedLedgerSnapshotV1, NativeModerationQueryFailureV1> {
            self.snapshot.clone()
        }
        fn event_page(
            &self,
            expected_finalized_cursor: ModerationFinalizedCursorV1,
            after: Option<ModerationFinalizedEventCursorV1>,
            limit: u32,
        ) -> Result<ModerationFinalizedEventPageV1, NativeModerationQueryFailureV1> {
            self.requests.lock().expect("query requests lock").push((
                expected_finalized_cursor,
                after.map(|cursor| cursor.sequence),
                limit,
            ));
            self.pages
                .lock()
                .expect("query pages lock")
                .pop_front()
                .unwrap_or(Err(NativeModerationQueryFailureV1::Unavailable))
        }
    }
    fn finalized_event(
        sequence: u64,
        finalized_height: u64,
        finalized_hash: [u8; 32],
        authority: AccountId,
    ) -> ModerationFinalizedEventV1 {
        ModerationFinalizedEventV1 {
            sequence,
            block_height: finalized_height,
            block_hash: finalized_hash,
            event_index: u32::try_from(sequence.saturating_sub(1)).expect("event index"),
            event: SorafsModerationLedgerEvent::new(
                SorafsModerationLedgerEventKind::PolicyActivated,
                None,
                None,
                authority,
                sequence,
            ),
        }
    }
    fn snapshot_with_events(
        finalized_height: u64,
        finalized_hash: [u8; 32],
        events: Vec<ModerationFinalizedEventV1>,
    ) -> ModerationFinalizedLedgerSnapshotV1 {
        ModerationFinalizedLedgerSnapshotV1 {
            version: MODERATION_FINALIZED_SNAPSHOT_VERSION_V1,
            finalized_height,
            finalized_block_hash: finalized_hash,
            finalized_at_unix_ms: finalized_height.max(1),
            policy: None,
            status: None,
            appeals: Vec::new(),
            cases: Vec::new(),
            events,
        }
    }
    fn event_page(
        cursor: ModerationFinalizedCursorV1,
        events: Vec<ModerationFinalizedEventV1>,
        has_more: bool,
    ) -> ModerationFinalizedEventPageV1 {
        let next_after = has_more.then(|| {
            events
                .last()
                .expect("continuing page must contain an event")
                .cursor()
        });
        ModerationFinalizedEventPageV1 {
            finalized_cursor: cursor,
            events,
            has_more,
            next_after,
        }
    }
    #[test]
    fn finalized_reader_binds_timestamp_to_the_exact_tip_block() {
        let mut snapshot = snapshot_with_events(8, [8; 32], Vec::new());
        snapshot.finalized_at_unix_ms = 8_000;
        assert_eq!(
            validate_snapshot_finalized_block_fields(&snapshot, 8, [8; 32], 8_000),
            Ok(())
        );
        for (height, hash, creation_time_ms) in [
            (7, [8; 32], 8_000),
            (8, [9; 32], 8_000),
            (8, [8; 32], 0),
            (8, [8; 32], 7_999),
            (8, [8; 32], 8_001),
        ] {
            assert_eq!(
                validate_snapshot_finalized_block_fields(&snapshot, height, hash, creation_time_ms,),
                Err(ModerationSnapshotReadErrorV1::InvalidSnapshot)
            );
        }
    }
    #[test]
    fn finalized_reader_rejects_stale_and_forked_page_cursors() {
        let authority = account(&key(4));
        let snapshot_cursor = ModerationFinalizedCursorV1 {
            height: 8,
            block_hash: [8; 32],
        };
        let events = vec![finalized_event(
            1,
            snapshot_cursor.height,
            snapshot_cursor.block_hash,
            authority,
        )];
        let snapshot = snapshot_with_events(
            snapshot_cursor.height,
            snapshot_cursor.block_hash,
            events.clone(),
        );
        for conflicting_cursor in [
            ModerationFinalizedCursorV1 {
                height: 7,
                block_hash: [7; 32],
            },
            ModerationFinalizedCursorV1 {
                height: snapshot_cursor.height,
                block_hash: [9; 32],
            },
        ] {
            let queries = TestQueries::new(
                snapshot.clone(),
                [Ok(event_page(conflicting_cursor, events.clone(), false))],
            );
            assert_eq!(
                read_and_validate_snapshot(&queries, 1, 1, 1),
                Err(ModerationSnapshotReadErrorV1::InvalidSnapshot)
            );
        }
    }
    #[test]
    fn finalized_reader_fails_closed_after_partial_query_failure() {
        let authority = account(&key(5));
        let cursor = ModerationFinalizedCursorV1 {
            height: 9,
            block_hash: [9; 32],
        };
        let snapshot = snapshot_with_events(
            cursor.height,
            cursor.block_hash,
            vec![finalized_event(
                1,
                cursor.height,
                cursor.block_hash,
                authority,
            )],
        );
        let queries =
            TestQueries::new(snapshot, [Err(NativeModerationQueryFailureV1::Unavailable)]);
        assert_eq!(
            read_and_validate_snapshot(&queries, 1, 1, 1),
            Err(ModerationSnapshotReadErrorV1::Unavailable)
        );
        assert_eq!(queries.request_count(), 1);
    }
    #[test]
    fn finalized_reader_rejects_events_omitted_from_an_empty_snapshot() {
        let authority = account(&key(15));
        let cursor = ModerationFinalizedCursorV1 {
            height: 12,
            block_hash: [12; 32],
        };
        let omitted = finalized_event(1, cursor.height, cursor.block_hash, authority);
        let queries = TestQueries::new(
            snapshot_with_events(cursor.height, cursor.block_hash, Vec::new()),
            [Ok(event_page(cursor, vec![omitted], false))],
        );
        assert_eq!(
            read_and_validate_snapshot(&queries, 1, 1, 1),
            Err(ModerationSnapshotReadErrorV1::InvalidSnapshot)
        );
        assert_eq!(queries.request_count(), 1);
    }
    #[test]
    fn finalized_reader_pages_within_the_requested_bound() {
        let authority = account(&key(6));
        let cursor = ModerationFinalizedCursorV1 {
            height: 10,
            block_hash: [10; 32],
        };
        let events = (1..=5)
            .map(|sequence| {
                finalized_event(
                    sequence,
                    cursor.height,
                    cursor.block_hash,
                    authority.clone(),
                )
            })
            .collect::<Vec<_>>();
        let queries = TestQueries::new(
            snapshot_with_events(cursor.height, cursor.block_hash, events.clone()),
            [
                Ok(event_page(cursor, events[0..2].to_vec(), true)),
                Ok(event_page(cursor, events[2..4].to_vec(), true)),
                Ok(event_page(cursor, events[4..5].to_vec(), false)),
            ],
        );
        let snapshot =
            read_and_validate_snapshot(&queries, 1, 5, 2).expect("bounded snapshot pages");
        assert_eq!(snapshot.events, events);
        assert_eq!(queries.request_count(), 3);
        assert_eq!(queries.requested_limits(), vec![2, 2, 2]);
    }
    #[derive(Debug, Default)]
    struct TestHandoffBoundaryState {
        calls: usize,
        fail_next: Option<ModerationDurableHandoffFailureV1>,
        delivered: BTreeMap<[u8; 32], Vec<u8>>,
        published_archive_heads:
            BTreeMap<[u8; 32], (Vec<u8>, ModerationPanelNotificationArchiveHeadV1)>,
    }
    #[derive(Debug)]
    struct TestHandoffBoundary {
        state: Mutex<TestHandoffBoundaryState>,
        handle: String,
        qualification: Mutex<
            Result<
                ModerationRuntimeProviderQualificationV1,
                ModerationRuntimeProviderReadinessErrorV1,
            >,
        >,
        qualification_after_delivery: Mutex<Option<ModerationRuntimeProviderQualificationV1>>,
    }
    impl Default for TestHandoffBoundary {
        fn default() -> Self {
            Self {
                state: Mutex::new(TestHandoffBoundaryState::default()),
                handle: TEST_HANDOFF_HANDLE.to_owned(),
                qualification: Mutex::new(Ok(TEST_HANDOFF_QUALIFICATION)),
                qualification_after_delivery: Mutex::new(None),
            }
        }
    }
    impl TestHandoffBoundary {
        fn fail_next(&self, error: ModerationDurableHandoffFailureV1) {
            self.state.lock().expect("handoff lock").fail_next = Some(error);
        }
        fn calls(&self) -> usize {
            self.state.lock().expect("handoff lock").calls
        }
        fn deliveries(&self) -> usize {
            self.state.lock().expect("handoff lock").delivered.len()
        }
        fn drift_after_delivery(&self, qualification: ModerationRuntimeProviderQualificationV1) {
            *self
                .qualification_after_delivery
                .lock()
                .expect("handoff qualification drift lock") = Some(qualification);
        }
    }
    impl ModerationRuntimeProviderV1 for TestHandoffBoundary {
        fn handle(&self) -> &str {
            &self.handle
        }
        fn qualification(
            &self,
        ) -> Result<
            ModerationRuntimeProviderQualificationV1,
            ModerationRuntimeProviderReadinessErrorV1,
        > {
            *self
                .qualification
                .lock()
                .expect("handoff qualification lock")
        }
    }
    impl ModerationDurableHandoffBoundaryV1 for TestHandoffBoundary {
        fn deliver_once(
            &self,
            request: &ModerationDurableHandoffRequestV1,
        ) -> Result<ModerationDurableHandoffOutcomeV1, ModerationDurableHandoffFailureV1> {
            let mut state = self.state.lock().expect("handoff lock");
            state.calls = state.calls.saturating_add(1);
            if let Some(error) = state.fail_next.take() {
                return Err(error);
            }
            let outcome = match state.delivered.get(&request.handoff.handoff_id) {
                Some(existing) if existing == &request.canonical_handoff => {
                    Ok(ModerationDurableHandoffOutcomeV1::AlreadyDelivered)
                }
                Some(_) => Err(ModerationDurableHandoffFailureV1::Permanent),
                None => {
                    state.delivered.insert(
                        request.handoff.handoff_id,
                        request.canonical_handoff.clone(),
                    );
                    Ok(ModerationDurableHandoffOutcomeV1::Delivered)
                }
            };
            drop(state);
            if let Some(qualification) = self
                .qualification_after_delivery
                .lock()
                .expect("handoff qualification drift lock")
                .take()
            {
                *self
                    .qualification
                    .lock()
                    .expect("handoff qualification lock") = Ok(qualification);
            }
            outcome
        }
        fn publish_archive_head_once(
            &self,
            request: &ModerationDurableArchiveHeadPublicationRequestV1,
        ) -> Result<ModerationDurableHandoffOutcomeV1, ModerationDurableHandoffFailureV1> {
            let mut state = self.state.lock().expect("handoff lock");
            state.calls = state.calls.saturating_add(1);
            if let Some(error) = state.fail_next.take() {
                return Err(error);
            }
            if let Some((canonical, head)) = state
                .published_archive_heads
                .get(&request.head.operation_id)
            {
                return if canonical == &request.canonical_head && head == &request.head {
                    Ok(ModerationDurableHandoffOutcomeV1::AlreadyDelivered)
                } else {
                    Err(ModerationDurableHandoffFailureV1::Permanent)
                };
            }
            let latest = state
                .published_archive_heads
                .values()
                .map(|(_, head)| head)
                .max_by_key(|head| head.generation);
            let lineage_is_valid = match latest {
                None => {
                    request.head.generation == 1
                        && request.head.predecessor_operation_id.is_none()
                        && request.head.predecessor_head_digest.is_none()
                        && request.head.predecessor_chain_commitment.is_none()
                }
                Some(predecessor) => {
                    predecessor.generation.checked_add(1) == Some(request.head.generation)
                        && request.head.predecessor_operation_id == Some(predecessor.operation_id)
                        && request.head.predecessor_head_digest == Some(predecessor.head_digest)
                        && request.head.predecessor_chain_commitment
                            == Some(predecessor.chain_commitment)
                }
            };
            if !lineage_is_valid {
                return Err(ModerationDurableHandoffFailureV1::Permanent);
            }
            state.published_archive_heads.insert(
                request.head.operation_id,
                (request.canonical_head.clone(), request.head.clone()),
            );
            Ok(ModerationDurableHandoffOutcomeV1::Delivered)
        }
        fn read_published_archive_head(
            &self,
        ) -> Result<
            Option<ModerationPanelNotificationArchiveHeadV1>,
            ModerationDurableHandoffFailureV1,
        > {
            Ok(self
                .state
                .lock()
                .expect("handoff lock")
                .published_archive_heads
                .values()
                .map(|(_, head)| head)
                .max_by_key(|head| head.generation)
                .cloned())
        }
    }
    fn terminal_handoff(kind: ModerationTerminalHandoffKindV1) -> ModerationTerminalHandoffV1 {
        let mut handoff = ModerationTerminalHandoffV1 {
            handoff_id: [0; 32],
            network_id: test_network_id(0xA5),
            kind,
            case_id: "case-1".to_owned(),
            round_id: "round-1".to_owned(),
            outcome_digest: [0x62; 32],
            outcome_finalized_at_unix_ms: 11,
            finalized_cursor: ModerationFinalizedEventCursorV1 {
                sequence: 1,
                block_height: 11,
                block_hash: [0x63; 32],
                event_index: 0,
            },
            source_event_witness: ModerationFinalizedEventV1 {
                sequence: 1,
                block_height: 11,
                block_hash: [0x63; 32],
                event_index: 0,
                event: SorafsModerationLedgerEvent::new(
                    SorafsModerationLedgerEventKind::CaseFinalized,
                    Some("case-1".to_owned()),
                    Some("round-1".to_owned()),
                    account(&key(61)),
                    11,
                ),
            },
        };
        handoff.handoff_id = handoff.canonical_id();
        handoff
    }
    #[test]
    fn terminal_handoff_failure_retries_the_same_idempotency_identity() {
        let boundary = Arc::new(TestHandoffBoundary::default());
        boundary.fail_next(ModerationDurableHandoffFailureV1::NotDelivered);
        let sink = ModerationTerminalHandoffSinkAdapterV1::try_settlement(
            TEST_HANDOFF_HANDLE,
            TEST_HANDOFF_QUALIFICATION,
            boundary.clone(),
        )
        .expect("qualified settlement boundary");
        let handoff = terminal_handoff(ModerationTerminalHandoffKindV1::Settlement);
        assert_eq!(
            sink.deliver(&handoff),
            Err(ModerationHandoffFailureV1::NotDelivered)
        );
        sink.deliver(&handoff).expect("retry delivery");
        sink.deliver(&handoff).expect("idempotent replay");
        assert_eq!(boundary.calls(), 3);
        assert_eq!(boundary.deliveries(), 1);
    }
    #[test]
    fn terminal_handoff_policy_drift_after_delivery_is_ambiguous() {
        let boundary = Arc::new(TestHandoffBoundary::default());
        let sink = ModerationTerminalHandoffSinkAdapterV1::try_settlement(
            TEST_HANDOFF_HANDLE,
            TEST_HANDOFF_QUALIFICATION,
            boundary.clone(),
        )
        .expect("qualified settlement boundary");
        let handoff = terminal_handoff(ModerationTerminalHandoffKindV1::Settlement);
        boundary.drift_after_delivery(ModerationRuntimeProviderQualificationV1::new(2, [0xB3; 32]));
        assert_eq!(
            sink.deliver(&handoff),
            Err(ModerationHandoffFailureV1::Ambiguous)
        );
        assert_eq!(boundary.calls(), 1);
        assert_eq!(boundary.deliveries(), 1);
    }
    #[test]
    fn terminal_handoff_cannot_cross_destination_boundaries() {
        let boundary = Arc::new(TestHandoffBoundary::default());
        let sink = ModerationTerminalHandoffSinkAdapterV1::try_publication(
            TEST_HANDOFF_HANDLE,
            TEST_HANDOFF_QUALIFICATION,
            boundary.clone(),
        )
        .expect("qualified publication boundary");
        let settlement = terminal_handoff(ModerationTerminalHandoffKindV1::Settlement);
        assert_eq!(
            sink.deliver(&settlement),
            Err(ModerationHandoffFailureV1::Permanent)
        );
        assert_eq!(boundary.calls(), 0);
    }
    #[derive(Debug, Default)]
    struct TestNotificationBoundaryState {
        calls: usize,
        fail_next: Option<ModerationPanelNotificationFailureV1>,
        delivered: BTreeMap<[u8; 32], (Vec<u8>, ModerationPanelNotificationDeliveryReceiptV1)>,
    }
    #[derive(Debug)]
    struct TestNotificationBoundary {
        state: Mutex<TestNotificationBoundaryState>,
        handle: String,
        qualification: Mutex<
            Result<
                ModerationRuntimeProviderQualificationV1,
                ModerationRuntimeProviderReadinessErrorV1,
            >,
        >,
        qualification_after_delivery: Mutex<Option<ModerationRuntimeProviderQualificationV1>>,
    }
    impl Default for TestNotificationBoundary {
        fn default() -> Self {
            Self {
                state: Mutex::new(TestNotificationBoundaryState::default()),
                handle: TEST_NOTIFICATION_HANDLE.to_owned(),
                qualification: Mutex::new(Ok(TEST_NOTIFICATION_QUALIFICATION)),
                qualification_after_delivery: Mutex::new(None),
            }
        }
    }
    impl TestNotificationBoundary {
        fn fail_next(&self, error: ModerationPanelNotificationFailureV1) {
            self.state.lock().expect("notification lock").fail_next = Some(error);
        }
        fn calls(&self) -> usize {
            self.state.lock().expect("notification lock").calls
        }
        fn deliveries(&self) -> usize {
            self.state
                .lock()
                .expect("notification lock")
                .delivered
                .len()
        }
        fn drift_after_delivery(&self, qualification: ModerationRuntimeProviderQualificationV1) {
            *self
                .qualification_after_delivery
                .lock()
                .expect("notification qualification drift lock") = Some(qualification);
        }
    }
    impl ModerationRuntimeProviderV1 for TestNotificationBoundary {
        fn handle(&self) -> &str {
            &self.handle
        }
        fn qualification(
            &self,
        ) -> Result<
            ModerationRuntimeProviderQualificationV1,
            ModerationRuntimeProviderReadinessErrorV1,
        > {
            *self
                .qualification
                .lock()
                .expect("notification qualification lock")
        }
    }
    impl ModerationDurablePanelNotificationBoundaryV1 for TestNotificationBoundary {
        fn deliver_once(
            &self,
            request: &ModerationDurablePanelNotificationRequestV1,
        ) -> Result<
            ModerationPanelNotificationDeliveryReceiptV1,
            ModerationPanelNotificationFailureV1,
        > {
            let mut state = self.state.lock().expect("notification lock");
            state.calls = state.calls.saturating_add(1);
            if let Some(error) = state.fail_next.take() {
                return Err(error);
            }
            let receipt = match state.delivered.get(&request.notification.notification_id) {
                Some((canonical, receipt))
                    if canonical.as_slice() == request.canonical_notification.as_slice() =>
                {
                    Ok(*receipt)
                }
                Some(_) => Err(ModerationPanelNotificationFailureV1::Permanent),
                None => {
                    let delivered_at_unix_ms = request
                        .notification
                        .source_occurred_at_unix_ms
                        .checked_add(1)
                        .filter(|delivered_at| *delivered_at < request.lease_expires_at_unix_ms)
                        .ok_or(ModerationPanelNotificationFailureV1::Permanent)?;
                    let receipt = ModerationPanelNotificationDeliveryReceiptV1 {
                        notification_id: request.notification.notification_id,
                        receipt_digest: [0x72; 32],
                        delivered_at_unix_ms,
                    };
                    state.delivered.insert(
                        request.notification.notification_id,
                        (request.canonical_notification.clone(), receipt),
                    );
                    Ok(receipt)
                }
            };
            drop(state);
            if let Some(qualification) = self
                .qualification_after_delivery
                .lock()
                .expect("notification qualification drift lock")
                .take()
            {
                *self
                    .qualification
                    .lock()
                    .expect("notification qualification lock") = Ok(qualification);
            }
            receipt
        }
    }
    fn panel_notification_claim() -> ModerationPanelNotificationClaimV1 {
        let mut notification = ModerationPanelNotificationV1 {
            notification_id: [0; 32],
            network_id: test_network_id(0xA5),
            source_operation_id: [0x72; 32],
            scope_digest: [0x73; 32],
            kind: ModerationPanelNotificationKindV1::PrimaryAssignment,
            recipient: account(&key(7)),
            finalized_event_cursor: ModerationFinalizedEventCursorV1 {
                sequence: 1,
                block_height: 11,
                block_hash: [0x74; 32],
                event_index: 0,
            },
            source_occurred_at_unix_ms: 100,
        };
        notification.notification_id = notification.canonical_id();
        ModerationPanelNotificationClaimV1 {
            notification,
            worker_id: [0x75; 32],
            lease_token: [0x76; 32],
            lease_expires_at_unix_ms: 1_000,
            attempt: 1,
            attempt_limit: 3,
        }
    }
    #[test]
    fn panel_notification_failure_retries_the_same_idempotency_identity() {
        let boundary = Arc::new(TestNotificationBoundary::default());
        boundary.fail_next(ModerationPanelNotificationFailureV1::NotDelivered);
        let sink = ModerationPanelNotificationSinkAdapterV1::try_new(
            TEST_NOTIFICATION_HANDLE,
            TEST_NOTIFICATION_QUALIFICATION,
            boundary.clone(),
        )
        .expect("qualified notification boundary");
        let claim = panel_notification_claim();
        assert_eq!(
            sink.deliver(&claim),
            Err(ModerationPanelNotificationFailureV1::NotDelivered)
        );
        let receipt = sink.deliver(&claim).expect("retry delivery");
        assert_eq!(sink.deliver(&claim).expect("idempotent replay"), receipt);
        assert_eq!(boundary.calls(), 3);
        assert_eq!(boundary.deliveries(), 1);
    }
    #[test]
    fn panel_notification_policy_drift_after_delivery_is_ambiguous() {
        let boundary = Arc::new(TestNotificationBoundary::default());
        let sink = ModerationPanelNotificationSinkAdapterV1::try_new(
            TEST_NOTIFICATION_HANDLE,
            TEST_NOTIFICATION_QUALIFICATION,
            boundary.clone(),
        )
        .expect("qualified notification boundary");
        boundary.drift_after_delivery(ModerationRuntimeProviderQualificationV1::new(2, [0xB4; 32]));
        assert_eq!(
            sink.deliver(&panel_notification_claim()),
            Err(ModerationPanelNotificationFailureV1::Ambiguous)
        );
        assert_eq!(boundary.calls(), 1);
        assert_eq!(boundary.deliveries(), 1);
    }
    #[test]
    fn panel_notification_adapter_rejects_malformed_claim_before_delivery() {
        let boundary = Arc::new(TestNotificationBoundary::default());
        let sink = ModerationPanelNotificationSinkAdapterV1::try_new(
            TEST_NOTIFICATION_HANDLE,
            TEST_NOTIFICATION_QUALIFICATION,
            boundary.clone(),
        )
        .expect("qualified notification boundary");
        let mut claim = panel_notification_claim();
        claim.notification.notification_id = [0; 32];
        assert_eq!(
            sink.deliver(&claim),
            Err(ModerationPanelNotificationFailureV1::Permanent)
        );
        assert_eq!(boundary.calls(), 0);
        assert_eq!(boundary.deliveries(), 0);
    }
}
