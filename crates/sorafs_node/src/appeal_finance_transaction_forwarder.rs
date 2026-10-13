//! Durable forwarding for appeal-finance asset-lock operations.
//!
//! Torii admits only native escrow instructions bound to one finalized ledger
//! projection. This module persists the semantic operation before an isolated
//! runtime signer sees it, persists the exact verified signed transaction before
//! submission, and retains bounded completed/dead-letter state for replay-safe
//! reconciliation. It never owns private keys or an authoritative finance model.
use crate::durable_transaction_forwarder::{
    self as durable, AtomicCheckpointStore, CheckpointStoreError, DeliveryRecord,
    DeliveryTransitionError, FinalizedCursorV1, RetryBoundOutcome, StoredDeliveryStateV1,
};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use iroha_config::parameters::{ProductionRuntimeHandleError, validate_production_runtime_handle};
use iroha_crypto::numeric::{Quantity, XorQuantity};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    escrow::{AssetEscrowKind, AssetEscrowRecord, AssetEscrowStatus, EscrowId},
    isi::{
        InstructionBox,
        escrow::{CancelAssetLock, DrawdownAssetLock, OpenAssetLock},
    },
    transaction::{Executable, SignedTransaction},
};
use iroha_model_base::chain::ChainId;
use norito::derive::{NoritoDeserialize, NoritoSerialize};
use std::{
    collections::BTreeSet,
    fmt,
    path::Path,
    sync::{Arc, Mutex},
};
use thiserror::Error;
/// Durable checkpoint schema version.
pub const APPEAL_FINANCE_FORWARDER_CHECKPOINT_VERSION_V1: u8 = 1;
/// Canonical checkpoint file name.
pub const APPEAL_FINANCE_FORWARDER_CHECKPOINT_FILE_NAME_V1: &str =
    "appeal-finance-transaction-forwarder-state.to";
/// Maximum entries returned by one bounded worker scan.
pub const APPEAL_FINANCE_FORWARDER_MAX_SCAN_ITEMS_V1: usize = 1_000;
/// Hard ceiling for one signed appeal-finance transaction.
pub const APPEAL_FINANCE_TRANSACTION_MAX_CANONICAL_BYTES_V1: usize = 2 * 1024 * 1024;
/// Hard ceiling for opaque canonical reconciliation context.
pub const APPEAL_FINANCE_RECONCILIATION_CONTEXT_MAX_BYTES_V1: usize = 64 * 1024;
/// Maximum active chain identifier retained by the checkpoint.
pub const APPEAL_FINANCE_MAX_CHAIN_ID_BYTES_V1: usize = 128;
/// Authenticated checkpoint runtime identity schema version.
pub const APPEAL_FINANCE_CHECKPOINT_AUTHENTICATION_POLICY_VERSION_V1: u8 = 1;
/// Public runtime-provider qualification schema version.
pub const APPEAL_FINANCE_RUNTIME_PROVIDER_QUALIFICATION_VERSION_V1: u8 = 1;
/// Sealed checkpoint record schema version.
pub const APPEAL_FINANCE_SEALED_CHECKPOINT_RECORD_VERSION_V1: u8 = 1;
/// Maximum canonical wrapper overhead beyond the embedded checkpoint bytes.
pub const APPEAL_FINANCE_SEALED_CHECKPOINT_RECORD_MAX_OVERHEAD_BYTES_V1: u64 = 4 * 1024;
const CHECKPOINT_LOCK_FILE_NAME: &str = "appeal-finance-transaction-forwarder-state.lock";
const IDENTITY_DOMAIN_V1: &[u8] = b"sorafs.appeal-finance.identity.v1\0";
const OPERATION_ID_DOMAIN_V1: &[u8] = b"sorafs.appeal-finance.operation.v1\0";
const SEMANTIC_DIGEST_DOMAIN_V1: &[u8] = b"sorafs.appeal-finance.semantic.v1\0";
const CHECKPOINT_BODY_DIGEST_DOMAIN_V1: &[u8] = b"sorafs.appeal-finance.checkpoint-body.v1\0";
const AUTHENTICATED_CHECKPOINT_DIGEST_DOMAIN_V1: &[u8] =
    b"sorafs.appeal-finance.authenticated-checkpoint.v1\0";
const AUTHENTICATED_CHECKPOINT_SIGNATURE_DOMAIN_V1: &[u8] =
    b"sorafs.appeal-finance.authenticated-checkpoint-signature.v1\0";
const SEALED_CHECKPOINT_RECORD_REVISION_DOMAIN_V1: &[u8] =
    b"sorafs.appeal-finance.sealed-checkpoint-record.v1\0";
const CHECKPOINT_ELEMENT_AMPLIFICATION_LIMIT: usize = 8;
const CHECKPOINT_ALLOCATION_AMPLIFICATION_LIMIT: usize = 20;
const CHECKPOINT_ALLOCATION_FIXED_OVERHEAD_BYTES: usize = 1024 * 1024;
const CHECKPOINT_MAX_NESTING_DEPTH: usize = 128;
const TRANSACTION_ELEMENT_AMPLIFICATION_LIMIT: usize = 8;
const TRANSACTION_ALLOCATION_AMPLIFICATION_LIMIT: usize = 20;
const TRANSACTION_ALLOCATION_FIXED_OVERHEAD_BYTES: usize = 512 * 1024;
const TRANSACTION_MAX_NESTING_DEPTH: usize = 128;
/// Bounded persistence and retry policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppealFinanceTransactionForwarderPolicyV1 {
    /// Maximum pending semantic operations.
    pub max_pending: usize,
    /// Maximum finalized idempotency tombstones.
    pub max_completed: usize,
    /// Maximum terminal dead letters.
    pub max_dead_letters: usize,
    /// Maximum attempts for one semantic operation.
    pub max_attempts: u32,
    /// Maximum accepted canonical transaction bytes.
    pub max_transaction_bytes: usize,
    /// Maximum canonical checkpoint bytes.
    pub checkpoint_max_bytes: u64,
}
impl AppealFinanceTransactionForwarderPolicyV1 {
    /// Validate every first-release resource bound.
    pub fn validate(self) -> Result<(), AppealFinanceTransactionForwarderError> {
        if self.max_pending == 0
            || self.max_completed == 0
            || self.max_dead_letters == 0
            || self.max_attempts == 0
            || self.max_transaction_bytes == 0
            || self.max_transaction_bytes > APPEAL_FINANCE_TRANSACTION_MAX_CANONICAL_BYTES_V1
            || self.checkpoint_max_bytes == 0
        {
            return Err(AppealFinanceTransactionForwarderError::InvalidPolicy);
        }
        Ok(())
    }
}
/// Configured public identity of the runtime checkpoint provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppealFinanceCheckpointAuthenticationPolicyV1 {
    /// Schema version.
    pub version: u8,
    /// Stable opaque provider handle.
    pub provider_handle: String,
    /// Exact Ed25519 verification key controlled by the provider.
    pub public_key: [u8; 32],
    /// Exact non-zero deployment adapter and public-policy revision.
    pub revision: u64,
    /// Exact non-zero digest of the provider's public policy.
    pub policy_digest: [u8; 32],
}
impl AppealFinanceCheckpointAuthenticationPolicyV1 {
    /// Validate the bounded handle, strong Ed25519 key, and qualification.
    ///
    /// # Errors
    ///
    /// Rejects an unsupported version, noncanonical handle, malformed key, or
    /// zero revision/policy digest.
    pub fn validate(&self) -> Result<(), AppealFinanceTransactionForwarderError> {
        if self.version != APPEAL_FINANCE_CHECKPOINT_AUTHENTICATION_POLICY_VERSION_V1 {
            return Err(
                AppealFinanceTransactionForwarderError::InvalidCheckpointAuthenticationPolicy,
            );
        }
        validate_runtime_handle(&self.provider_handle)?;
        checked_checkpoint_verifying_key(self.public_key).map_err(|()| {
            AppealFinanceTransactionForwarderError::InvalidCheckpointAuthenticationPolicy
        })?;
        AppealFinanceRuntimeProviderQualificationV1::new(self.revision, self.policy_digest)
            .validate()
            .map_err(|_| {
                AppealFinanceTransactionForwarderError::InvalidCheckpointAuthenticationPolicy
            })?;
        Ok(())
    }
}
/// Public, non-secret qualification for an appeal-finance runtime provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppealFinanceRuntimeProviderQualificationV1 {
    /// Qualification schema version.
    pub version: u8,
    /// Non-zero deployment adapter and public-policy revision.
    pub revision: u64,
    /// Non-zero digest of the exact public provider policy.
    pub policy_digest: [u8; 32],
}
impl AppealFinanceRuntimeProviderQualificationV1 {
    /// Construct a first-release provider qualification.
    #[must_use]
    pub const fn new(revision: u64, policy_digest: [u8; 32]) -> Self {
        Self {
            version: APPEAL_FINANCE_RUNTIME_PROVIDER_QUALIFICATION_VERSION_V1,
            revision,
            policy_digest,
        }
    }
    /// Validate the schema, revision, and public-policy digest.
    ///
    /// # Errors
    ///
    /// Rejects unsupported schemas, zero revisions, and zero policy digests.
    pub fn validate(self) -> Result<(), AppealFinanceTransactionForwarderError> {
        if self.version != APPEAL_FINANCE_RUNTIME_PROVIDER_QUALIFICATION_VERSION_V1
            || self.revision == 0
            || self.policy_digest == [0; 32]
        {
            return Err(
                AppealFinanceTransactionForwarderError::InvalidRuntimeProviderQualification,
            );
        }
        Ok(())
    }
}
/// Identity returned by the injected runtime checkpoint provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppealFinanceCheckpointRuntimeIdentityV1 {
    /// Stable opaque provider handle.
    pub provider_handle: String,
    /// Exact Ed25519 verification key controlled by the provider.
    pub public_key: [u8; 32],
    /// Active adapter and public-policy qualification.
    pub qualification: AppealFinanceRuntimeProviderQualificationV1,
}
/// Fixed external failure classes without provider diagnostics or credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppealFinanceCheckpointExternalError {
    /// The signing provider or sealed store is temporarily unavailable.
    Unavailable,
    /// The provider rejected the exact request.
    Rejected,
    /// A compare-and-swap may have committed and requires authoritative lookup.
    Ambiguous,
}
/// Exact sealed recovery record for one authenticated local checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "sorafs_node::appeal_finance_transaction_forwarder::AppealFinanceSealedCheckpointRecordV1"
)]
pub struct AppealFinanceSealedCheckpointRecordV1 {
    /// Schema version.
    pub version: u8,
    /// Monotonic authenticated checkpoint sequence.
    pub checkpoint_sequence: u64,
    /// Digest of the exact authenticated checkpoint.
    pub checkpoint_digest: [u8; 32],
    /// Exact canonical authenticated checkpoint bytes.
    pub checkpoint_bytes: Vec<u8>,
    /// Deterministic compare-and-swap revision.
    pub revision: [u8; 32],
}
impl AppealFinanceSealedCheckpointRecordV1 {
    fn new(
        checkpoint_sequence: u64,
        checkpoint_digest: [u8; 32],
        checkpoint_bytes: Vec<u8>,
    ) -> Self {
        let mut record = Self {
            version: APPEAL_FINANCE_SEALED_CHECKPOINT_RECORD_VERSION_V1,
            checkpoint_sequence,
            checkpoint_digest,
            checkpoint_bytes,
            revision: [0; 32],
        };
        record.revision = sealed_checkpoint_record_revision(&record);
        record
    }
    /// Validate schema, bounds, identity, and deterministic CAS revision.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, or revision-substituted records.
    pub fn validate(
        &self,
        checkpoint_max_bytes: u64,
    ) -> Result<(), AppealFinanceTransactionForwarderError> {
        if checkpoint_max_bytes == 0
            || self.version != APPEAL_FINANCE_SEALED_CHECKPOINT_RECORD_VERSION_V1
            || self.checkpoint_sequence == 0
            || self.checkpoint_digest == [0; 32]
            || self.checkpoint_bytes.is_empty()
            || u64::try_from(self.checkpoint_bytes.len()).unwrap_or(u64::MAX) > checkpoint_max_bytes
            || self.revision != sealed_checkpoint_record_revision(self)
        {
            return Err(AppealFinanceTransactionForwarderError::InvalidSealedCheckpoint);
        }
        Ok(())
    }
    /// Encode the exact canonical Norito record for external sealed storage.
    ///
    /// # Errors
    ///
    /// Rejects invalid records and any encoding above the bounded wrapper size.
    pub fn to_canonical_bytes(
        &self,
        checkpoint_max_bytes: u64,
    ) -> Result<Vec<u8>, AppealFinanceTransactionForwarderError> {
        self.validate(checkpoint_max_bytes)?;
        let max_record_bytes = sealed_checkpoint_record_max_bytes(checkpoint_max_bytes)?;
        let bytes = norito::to_bytes(self)
            .map_err(|_| AppealFinanceTransactionForwarderError::InvalidSealedCheckpoint)?;
        if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_record_bytes {
            return Err(AppealFinanceTransactionForwarderError::InvalidSealedCheckpoint);
        }
        Ok(bytes)
    }
    /// Decode one exact canonical Norito record from external sealed storage.
    ///
    /// # Errors
    ///
    /// Rejects malformed, noncanonical, oversized, or revision-substituted
    /// records before they cross the runtime boundary.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        checkpoint_max_bytes: u64,
    ) -> Result<Self, AppealFinanceTransactionForwarderError> {
        let max_record_bytes = sealed_checkpoint_record_max_bytes(checkpoint_max_bytes)?;
        if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_record_bytes {
            return Err(AppealFinanceTransactionForwarderError::InvalidSealedCheckpoint);
        }
        norito::core::from_bytes_view(bytes)
            .map_err(|_| AppealFinanceTransactionForwarderError::InvalidSealedCheckpoint)?;
        let max_record_bytes = usize::try_from(max_record_bytes)
            .map_err(|_| AppealFinanceTransactionForwarderError::ResourceLimitExceeded)?;
        let record = norito::decode_from_bytes_with_limits::<Self>(
            bytes,
            decode_limits(
                bytes.len(),
                max_record_bytes,
                CHECKPOINT_ELEMENT_AMPLIFICATION_LIMIT,
                CHECKPOINT_ALLOCATION_AMPLIFICATION_LIMIT,
                CHECKPOINT_ALLOCATION_FIXED_OVERHEAD_BYTES,
                CHECKPOINT_MAX_NESTING_DEPTH,
            )?,
        )
        .map_err(|_| AppealFinanceTransactionForwarderError::InvalidSealedCheckpoint)?;
        if norito::to_bytes(&record)
            .map_err(|_| AppealFinanceTransactionForwarderError::InvalidSealedCheckpoint)?
            != bytes
        {
            return Err(AppealFinanceTransactionForwarderError::InvalidSealedCheckpoint);
        }
        record.validate(checkpoint_max_bytes)?;
        Ok(record)
    }
}
/// Runtime-only signer plus monotonic sealed checkpoint head.
///
/// Implementations must keep signing material and credentials out of process configuration, make
/// the head compare-and-swap linearizable, preserve the exact latest record across restarts, and
/// never roll its revision back. Persisted heads must use
/// [`AppealFinanceSealedCheckpointRecordV1::to_canonical_bytes`] and
/// [`AppealFinanceSealedCheckpointRecordV1::from_canonical_bytes`]; provider metadata belongs
/// outside that canonical record.
pub trait AppealFinanceCheckpointRuntime: Send + Sync + fmt::Debug {
    /// Return the current provider identity.
    ///
    /// # Errors
    ///
    /// Returns a fixed payload-free provider failure.
    fn identity(
        &self,
    ) -> Result<AppealFinanceCheckpointRuntimeIdentityV1, AppealFinanceCheckpointExternalError>;
    /// Sign one exact domain-separated checkpoint digest.
    ///
    /// # Errors
    ///
    /// Returns a fixed payload-free provider failure.
    fn sign_digest(
        &self,
        digest: [u8; 32],
    ) -> Result<[u8; 64], AppealFinanceCheckpointExternalError>;
    /// Load the exact authenticated latest sealed record.
    ///
    /// # Errors
    ///
    /// Returns a fixed payload-free provider failure.
    fn load_latest(
        &self,
    ) -> Result<Option<AppealFinanceSealedCheckpointRecordV1>, AppealFinanceCheckpointExternalError>;
    /// Atomically replace the sealed head if its exact revision is unchanged.
    ///
    /// Uncertain writes must return [`AppealFinanceCheckpointExternalError::Ambiguous`].
    ///
    /// # Errors
    ///
    /// Returns a fixed payload-free provider failure.
    fn compare_and_swap_latest(
        &self,
        expected_revision: Option<[u8; 32]>,
        next: &AppealFinanceSealedCheckpointRecordV1,
    ) -> Result<(), AppealFinanceCheckpointExternalError>;
}
/// Finalized ledger cursor bound to appeal-finance operations.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, NoritoSerialize, NoritoDeserialize,
)]
pub struct AppealFinanceFinalizedCursorV1 {
    /// Finalized block height.
    pub height: u64,
    /// Finalized block hash.
    pub block_hash: [u8; 32],
}
/// Exact native instruction retained by the outbox.
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub enum AppealFinanceOperationV1 {
    /// Open and fund the authoritative generic asset lock.
    Open(OpenAssetLock),
    /// Disburse the non-refund partition.
    Drawdown(DrawdownAssetLock),
    /// Refund all authoritative remaining custody.
    Cancel(CancelAssetLock),
}
impl AppealFinanceOperationV1 {
    /// Return the operation kind.
    #[must_use]
    pub const fn kind(&self) -> AppealFinanceTransactionKindV1 {
        match self {
            Self::Open(_) => AppealFinanceTransactionKindV1::Open,
            Self::Drawdown(_) => AppealFinanceTransactionKindV1::Drawdown,
            Self::Cancel(_) => AppealFinanceTransactionKindV1::Cancel,
        }
    }
    /// Return the native escrow identity.
    #[must_use]
    pub fn escrow_id(&self) -> &EscrowId {
        match self {
            Self::Open(instruction) => instruction.escrow_id(),
            Self::Drawdown(instruction) => instruction.escrow_id(),
            Self::Cancel(instruction) => instruction.escrow_id(),
        }
    }
}
impl From<AppealFinanceOperationV1> for InstructionBox {
    fn from(operation: AppealFinanceOperationV1) -> Self {
        match operation {
            AppealFinanceOperationV1::Open(instruction) => instruction.into(),
            AppealFinanceOperationV1::Drawdown(instruction) => instruction.into(),
            AppealFinanceOperationV1::Cancel(instruction) => instruction.into(),
        }
    }
}
/// Native appeal-finance transaction kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppealFinanceTransactionKindV1 {
    /// Open and fund.
    Open,
    /// Disburse non-refund custody.
    Drawdown,
    /// Refund remaining custody.
    Cancel,
}
/// Finalized context required to admit one operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppealFinanceTransactionContextV1 {
    /// Exact genesis-hash-derived transaction domain.
    pub network_id: NetworkId,
    /// Active business chain identifier retained as semantic context.
    pub chain_id: ChainId,
    /// Finalized block anchor for the authoritative projection.
    pub finalized_cursor: AppealFinanceFinalizedCursorV1,
    /// Authoritative pre-operation escrow, absent only for `Open`.
    pub expected_record: Option<AssetEscrowRecord>,
    /// Bounded canonical context used to rebuild an idempotent receipt.
    pub reconciliation_context: Vec<u8>,
}
impl AppealFinanceTransactionContextV1 {
    fn validate(&self) -> Result<(), AppealFinanceTransactionForwarderError> {
        validate_finalized_cursor(self.finalized_cursor)?;
        if self.chain_id.as_str().is_empty()
            || self.chain_id.as_str().len() > APPEAL_FINANCE_MAX_CHAIN_ID_BYTES_V1
            || self.reconciliation_context.is_empty()
            || self.reconciliation_context.len()
                > APPEAL_FINANCE_RECONCILIATION_CONTEXT_MAX_BYTES_V1
        {
            return Err(AppealFinanceTransactionForwarderError::InvalidContext);
        }
        Ok(())
    }
}
/// Exact signer/reconciler work item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppealFinanceTransactionSigningRequestV1 {
    /// Stable semantic operation identity.
    pub operation_id: [u8; 32],
    /// Exact genesis-hash-derived transaction domain.
    pub network_id: NetworkId,
    /// Active business chain identifier retained as semantic context.
    pub chain_id: ChainId,
    /// Exact transaction authority.
    pub authority: AccountId,
    /// Exact native operation.
    pub operation: AppealFinanceOperationV1,
    /// Authoritative pre-operation escrow.
    pub expected_record: Option<AssetEscrowRecord>,
    /// Exact bounded receipt-reconciliation context.
    pub reconciliation_context: Vec<u8>,
    /// Finalized cursor from the latest durable attempt.
    pub baseline_finalized_cursor: AppealFinanceFinalizedCursorV1,
}
/// Durable enqueue result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppealFinanceTransactionEnqueueResultV1 {
    /// A new semantic operation was persisted.
    Inserted {
        /// Stable semantic operation identity.
        operation_id: [u8; 32],
    },
    /// The byte-identical semantic operation already exists.
    Existing {
        /// Stable semantic operation identity.
        operation_id: [u8; 32],
    },
}
impl AppealFinanceTransactionEnqueueResultV1 {
    /// Return the stable semantic operation identity.
    #[must_use]
    pub const fn operation_id(self) -> [u8; 32] {
        match self {
            Self::Inserted { operation_id } | Self::Existing { operation_id } => operation_id,
        }
    }
}
/// Runtime-visible crash state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppealFinanceTransactionDeliveryStateV1 {
    /// Ready for isolated signing.
    Ready,
    /// A signing claim is durable.
    Signing,
    /// Exact signed bytes are durable.
    Signed,
    /// Submission may have happened.
    Ambiguous,
    /// Submission is known pending/applied.
    Submitted,
}
impl From<StoredDeliveryStateV1> for AppealFinanceTransactionDeliveryStateV1 {
    fn from(value: StoredDeliveryStateV1) -> Self {
        match value {
            StoredDeliveryStateV1::Ready => Self::Ready,
            StoredDeliveryStateV1::Signing => Self::Signing,
            StoredDeliveryStateV1::Signed => Self::Signed,
            StoredDeliveryStateV1::Ambiguous => Self::Ambiguous,
            StoredDeliveryStateV1::Submitted => Self::Submitted,
        }
    }
}
/// Pending operation snapshot.
#[derive(Debug, Clone)]
pub struct AppealFinanceTransactionPendingV1 {
    /// Insertion sequence.
    pub sequence: u64,
    /// Stable semantic identity.
    pub operation_id: [u8; 32],
    /// Native operation kind.
    pub kind: AppealFinanceTransactionKindV1,
    /// Exact authority.
    pub authority: AccountId,
    /// Current delivery state.
    pub state: AppealFinanceTransactionDeliveryStateV1,
    /// Attempts consumed.
    pub attempts: u32,
    /// Baseline finalized height.
    pub baseline_finalized_height: u64,
    /// Baseline finalized block hash.
    pub baseline_finalized_block_hash: [u8; 32],
    /// Exact signed bytes, when available.
    pub signed_transaction_bytes: Option<Vec<u8>>,
}
/// Terminal reason retained without request payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppealFinanceTransactionDeadLetterReasonV1 {
    /// Finalized state conflicts with the retained semantics.
    FinalizedConflict,
    /// Exact transaction was terminally rejected.
    TransactionRejected,
    /// Signing/submission retry budget was exhausted.
    RetryExhausted,
    /// Finalized cursor forked or moved backwards.
    StaleFinalizedCursor,
    /// The governed appeal-finance policy changed before submission.
    PolicySuperseded,
    /// The durable reconciliation context is malformed or noncanonical.
    InvalidContext,
    /// The governed signer binding is no longer active for the operation authority.
    SignerBindingInactive,
}
/// Payload-free terminal delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppealFinanceTransactionDeadLetterV1 {
    /// Stable semantic operation identity.
    pub operation_id: [u8; 32],
    /// Native operation kind.
    pub kind: AppealFinanceTransactionKindV1,
    /// Terminal reason.
    pub reason: AppealFinanceTransactionDeadLetterReasonV1,
    /// Finalized height observing the terminal condition.
    pub observed_finalized_height: u64,
    /// Finalized hash paired with the observed height.
    pub observed_finalized_block_hash: [u8; 32],
}
/// Pure authoritative reconciliation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppealFinanceOperationReconciliationV1 {
    /// Finalized state still equals the exact precondition.
    Ready,
    /// Finalized state proves the exact semantic operation.
    Finalized,
    /// Finalized state consumed or contradicted the precondition.
    Conflict,
}
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, NoritoSerialize, NoritoDeserialize,
)]
enum StoredIdentityScopeV1 {
    Open,
    Drawdown,
    Cancel,
}
impl StoredIdentityScopeV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Drawdown => 1,
            Self::Cancel => 2,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
enum StoredDeadLetterReasonV1 {
    FinalizedConflict,
    TransactionRejected,
    RetryExhausted,
    StaleFinalizedCursor,
    PolicySuperseded,
    InvalidContext,
    SignerBindingInactive,
}
impl From<StoredDeadLetterReasonV1> for AppealFinanceTransactionDeadLetterReasonV1 {
    fn from(value: StoredDeadLetterReasonV1) -> Self {
        match value {
            StoredDeadLetterReasonV1::FinalizedConflict => Self::FinalizedConflict,
            StoredDeadLetterReasonV1::TransactionRejected => Self::TransactionRejected,
            StoredDeadLetterReasonV1::RetryExhausted => Self::RetryExhausted,
            StoredDeadLetterReasonV1::StaleFinalizedCursor => Self::StaleFinalizedCursor,
            StoredDeadLetterReasonV1::PolicySuperseded => Self::PolicySuperseded,
            StoredDeadLetterReasonV1::InvalidContext => Self::InvalidContext,
            StoredDeadLetterReasonV1::SignerBindingInactive => Self::SignerBindingInactive,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
struct StoredPendingV1 {
    sequence: u64,
    operation_id: [u8; 32],
    identity_scope: StoredIdentityScopeV1,
    identity_digest: [u8; 32],
    semantic_digest: [u8; 32],
    network_id: NetworkId,
    chain_id: ChainId,
    authority: AccountId,
    operation: AppealFinanceOperationV1,
    expected_record: Option<AssetEscrowRecord>,
    reconciliation_context: Vec<u8>,
    state: StoredDeliveryStateV1,
    attempts: u32,
    baseline_finalized_height: u64,
    baseline_finalized_block_hash: [u8; 32],
    signed_transaction_bytes: Option<Vec<u8>>,
}
impl StoredPendingV1 {
    fn snapshot(&self) -> AppealFinanceTransactionPendingV1 {
        AppealFinanceTransactionPendingV1 {
            sequence: self.sequence,
            operation_id: self.operation_id,
            kind: self.operation.kind(),
            authority: self.authority.clone(),
            state: self.state.into(),
            attempts: self.attempts,
            baseline_finalized_height: self.baseline_finalized_height,
            baseline_finalized_block_hash: self.baseline_finalized_block_hash,
            signed_transaction_bytes: self.signed_transaction_bytes.clone(),
        }
    }
    fn request(&self) -> AppealFinanceTransactionSigningRequestV1 {
        AppealFinanceTransactionSigningRequestV1 {
            operation_id: self.operation_id,
            network_id: self.network_id,
            chain_id: self.chain_id.clone(),
            authority: self.authority.clone(),
            operation: self.operation.clone(),
            expected_record: self.expected_record.clone(),
            reconciliation_context: self.reconciliation_context.clone(),
            baseline_finalized_cursor: AppealFinanceFinalizedCursorV1 {
                height: self.baseline_finalized_height,
                block_hash: self.baseline_finalized_block_hash,
            },
        }
    }
}
impl DeliveryRecord for StoredPendingV1 {
    type Transaction = Vec<u8>;
    fn delivery_state(&self) -> StoredDeliveryStateV1 {
        self.state
    }
    fn set_delivery_state(&mut self, state: StoredDeliveryStateV1) {
        self.state = state;
    }
    fn attempts(&self) -> u32 {
        self.attempts
    }
    fn set_attempts(&mut self, attempts: u32) {
        self.attempts = attempts;
    }
    fn baseline_finalized_height(&self) -> u64 {
        self.baseline_finalized_height
    }
    fn set_baseline_finalized_height(&mut self, height: u64) {
        self.baseline_finalized_height = height;
    }
    fn baseline_finalized_block_hash(&self) -> [u8; 32] {
        self.baseline_finalized_block_hash
    }
    fn set_baseline_finalized_block_hash(&mut self, block_hash: [u8; 32]) {
        self.baseline_finalized_block_hash = block_hash;
    }
    fn signed_transaction(&self) -> Option<&Self::Transaction> {
        self.signed_transaction_bytes.as_ref()
    }
    fn set_signed_transaction(&mut self, transaction: Option<Self::Transaction>) {
        self.signed_transaction_bytes = transaction;
    }
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
struct StoredCompletedV1 {
    operation_id: [u8; 32],
    identity_scope: StoredIdentityScopeV1,
    identity_digest: [u8; 32],
    semantic_digest: [u8; 32],
    finalized_height: u64,
    finalized_block_hash: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
struct StoredDeadLetterV1 {
    operation_id: [u8; 32],
    identity_scope: StoredIdentityScopeV1,
    identity_digest: [u8; 32],
    semantic_digest: [u8; 32],
    kind: StoredIdentityScopeV1,
    reason: StoredDeadLetterReasonV1,
    observed_finalized_height: u64,
    observed_finalized_block_hash: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "sorafs_node::appeal_finance_transaction_forwarder::CheckpointBodyV1")]
struct CheckpointBodyV1 {
    next_sequence: u64,
    pending: Vec<StoredPendingV1>,
    completed: Vec<StoredCompletedV1>,
    dead_letters: Vec<StoredDeadLetterV1>,
}
impl Default for CheckpointBodyV1 {
    fn default() -> Self {
        Self {
            next_sequence: 1,
            pending: Vec::new(),
            completed: Vec::new(),
            dead_letters: Vec::new(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "sorafs_node::appeal_finance_transaction_forwarder::AuthenticatedCheckpointV1"
)]
struct AuthenticatedCheckpointV1 {
    version: u8,
    checkpoint_sequence: u64,
    predecessor_checkpoint_digest: Option<[u8; 32]>,
    provider_handle: String,
    public_key: [u8; 32],
    provider_revision: u64,
    provider_policy_digest: [u8; 32],
    body_digest: [u8; 32],
    body: CheckpointBodyV1,
    checkpoint_digest: [u8; 32],
    signature: [u8; 64],
}
#[derive(Debug)]
struct DurableState {
    checkpoint: CheckpointBodyV1,
    authenticated_checkpoint: Option<AuthenticatedCheckpointV1>,
    sealed_revision: Option<[u8; 32]>,
    fingerprint: Option<[u8; 32]>,
    durability_failure: bool,
}
#[derive(Clone)]
struct CheckpointAuthenticationContext {
    policy: AppealFinanceCheckpointAuthenticationPolicyV1,
    runtime: Arc<dyn AppealFinanceCheckpointRuntime>,
}
impl fmt::Debug for CheckpointAuthenticationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckpointAuthenticationContext")
            .field("provider_handle", &self.policy.provider_handle)
            .field("credentials", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
/// Durable bounded appeal-finance transaction forwarder.
#[derive(Debug, Clone)]
pub struct AppealFinanceTransactionForwarder {
    policy: AppealFinanceTransactionForwarderPolicyV1,
    checkpoint_authentication: Option<CheckpointAuthenticationContext>,
    state: Arc<Mutex<DurableState>>,
    store: Option<Arc<AtomicCheckpointStore>>,
}
impl AppealFinanceTransactionForwarder {
    /// Construct a non-persistent forwarder for focused tests.
    #[cfg(test)]
    fn in_memory(
        policy: AppealFinanceTransactionForwarderPolicyV1,
    ) -> Result<Self, AppealFinanceTransactionForwarderError> {
        policy.validate()?;
        Ok(Self {
            policy,
            checkpoint_authentication: None,
            state: Arc::new(Mutex::new(DurableState {
                checkpoint: CheckpointBodyV1::default(),
                authenticated_checkpoint: None,
                sealed_revision: None,
                fingerprint: None,
                durability_failure: false,
            })),
            store: None,
        })
    }
    /// Open or create a private, authenticated, single-writer durable checkpoint.
    ///
    /// The qualified runtime provider signs every exact checkpoint and owns a monotonic sealed head.
    /// The sealed record is committed before the local atomic rename so a crash can recover the
    /// exact newer checkpoint without accepting rollback or substitution.
    ///
    /// # Errors
    ///
    /// Fails closed on provider identity drift, signature failure, local or
    /// sealed tamper, rollback/fork, skipped predecessor, unsafe persistence,
    /// or unavailable runtime authentication.
    pub fn open(
        state_dir: &Path,
        policy: AppealFinanceTransactionForwarderPolicyV1,
        authentication_policy: AppealFinanceCheckpointAuthenticationPolicyV1,
        checkpoint_runtime: Arc<dyn AppealFinanceCheckpointRuntime>,
    ) -> Result<Self, AppealFinanceTransactionForwarderError> {
        policy.validate()?;
        authentication_policy.validate()?;
        verify_checkpoint_runtime_identity(&authentication_policy, checkpoint_runtime.as_ref())?;
        let store = Arc::new(AtomicCheckpointStore::new(
            state_dir,
            APPEAL_FINANCE_FORWARDER_CHECKPOINT_FILE_NAME_V1,
            CHECKPOINT_LOCK_FILE_NAME,
            policy.checkpoint_max_bytes,
        )?);
        let (bytes, fingerprint) = store.load_bytes()?;
        let local_checkpoint = bytes
            .as_deref()
            .map(|bytes| decode_authenticated_checkpoint(bytes, policy, &authentication_policy))
            .transpose();
        let sealed_record =
            load_latest_qualified(&authentication_policy, checkpoint_runtime.as_ref())?;
        if let Some(record) = &sealed_record {
            record.to_canonical_bytes(policy.checkpoint_max_bytes)?;
        }
        let mut recovered_local = false;
        let (authenticated_checkpoint, sealed_revision) =
            match (local_checkpoint, sealed_record.as_ref()) {
                (Ok(Some(local)), Some(record)) => {
                    let sealed = decode_sealed_checkpoint(record, policy, &authentication_policy)?;
                    if local.checkpoint_sequence > sealed.checkpoint_sequence {
                        return Err(AppealFinanceTransactionForwarderError::CheckpointRollback);
                    }
                    if local.checkpoint_sequence == sealed.checkpoint_sequence {
                        if local != sealed {
                            return Err(AppealFinanceTransactionForwarderError::CheckpointFork);
                        }
                        (local, Some(record.revision))
                    } else if local.checkpoint_sequence.checked_add(1)
                        == Some(sealed.checkpoint_sequence)
                        && sealed.predecessor_checkpoint_digest == Some(local.checkpoint_digest)
                    {
                        recovered_local = true;
                        (sealed, Some(record.revision))
                    } else {
                        return Err(AppealFinanceTransactionForwarderError::CheckpointRollback);
                    }
                }
                (Ok(Some(_)), None) => {
                    return Err(AppealFinanceTransactionForwarderError::CheckpointRollback);
                }
                (Ok(None), Some(record)) => {
                    let sealed = decode_sealed_checkpoint(record, policy, &authentication_policy)?;
                    if sealed.checkpoint_sequence != 1
                        || sealed.predecessor_checkpoint_digest.is_some()
                    {
                        return Err(AppealFinanceTransactionForwarderError::CheckpointRollback);
                    }
                    recovered_local = true;
                    (sealed, Some(record.revision))
                }
                (Ok(None), None) => {
                    let genesis = sign_authenticated_checkpoint(
                        CheckpointBodyV1::default(),
                        1,
                        None,
                        policy,
                        &authentication_policy,
                        checkpoint_runtime.as_ref(),
                    )?;
                    let genesis_bytes =
                        encode_authenticated_checkpoint(&genesis, policy, &authentication_policy)?;
                    let record = AppealFinanceSealedCheckpointRecordV1::new(
                        genesis.checkpoint_sequence,
                        genesis.checkpoint_digest,
                        genesis_bytes,
                    );
                    seal_checkpoint_record(
                        checkpoint_runtime.as_ref(),
                        &authentication_policy,
                        policy.checkpoint_max_bytes,
                        None,
                        &record,
                    )?;
                    (genesis, Some(record.revision))
                }
                (Err(error), _) => return Err(error),
            };
        verify_checkpoint_runtime_identity(&authentication_policy, checkpoint_runtime.as_ref())?;
        let checkpoint_bytes = encode_authenticated_checkpoint(
            &authenticated_checkpoint,
            policy,
            &authentication_policy,
        )?;
        let fingerprint = if bytes.is_none() || recovered_local {
            Some(store.commit_bytes(&checkpoint_bytes, fingerprint)?)
        } else {
            fingerprint
        };
        let mut checkpoint = authenticated_checkpoint.body.clone();
        let recovered = checkpoint
            .pending
            .iter_mut()
            .fold(false, |recovered, entry| {
                recover_interrupted_signing(entry) || recovered
            });
        let forwarder = Self {
            policy,
            checkpoint_authentication: Some(CheckpointAuthenticationContext {
                policy: authentication_policy,
                runtime: checkpoint_runtime,
            }),
            state: Arc::new(Mutex::new(DurableState {
                checkpoint,
                authenticated_checkpoint: Some(authenticated_checkpoint),
                sealed_revision,
                fingerprint,
                durability_failure: false,
            })),
            store: Some(store),
        };
        if recovered {
            let mut state = forwarder.lock_state()?;
            let candidate = state.checkpoint.clone();
            forwarder.commit_candidate(&mut state, candidate)?;
        }
        Ok(forwarder)
    }
    /// Validate and durably enqueue one authority-bound native operation.
    pub fn enqueue_unsigned_operation(
        &self,
        authority: AccountId,
        operation: AppealFinanceOperationV1,
        context: &AppealFinanceTransactionContextV1,
    ) -> Result<AppealFinanceTransactionEnqueueResultV1, AppealFinanceTransactionForwarderError>
    {
        context.validate()?;
        let prepared = PreparedOperation::new_bounded(
            context.network_id,
            context.chain_id.clone(),
            authority,
            operation,
            context.expected_record.clone(),
            context.reconciliation_context.clone(),
            self.policy.max_transaction_bytes,
        )?;
        let operation_id = prepared.operation_id();
        let mut state = self.lock_state()?;
        if let Some(existing) = state.checkpoint.pending.iter().find(|entry| {
            entry.identity_scope == prepared.identity_scope
                && entry.identity_digest == prepared.identity_digest
        }) {
            return if existing.operation_id == operation_id
                && existing.semantic_digest == prepared.semantic_digest
            {
                Ok(AppealFinanceTransactionEnqueueResultV1::Existing { operation_id })
            } else {
                Err(AppealFinanceTransactionForwarderError::IdentityConflict)
            };
        }
        if let Some(existing) = state.checkpoint.completed.iter().find(|entry| {
            entry.identity_scope == prepared.identity_scope
                && entry.identity_digest == prepared.identity_digest
        }) {
            return if existing.operation_id == operation_id
                && existing.semantic_digest == prepared.semantic_digest
            {
                Ok(AppealFinanceTransactionEnqueueResultV1::Existing { operation_id })
            } else {
                Err(AppealFinanceTransactionForwarderError::IdentityConflict)
            };
        }
        if state.checkpoint.dead_letters.iter().any(|entry| {
            entry.identity_scope == prepared.identity_scope
                && entry.identity_digest == prepared.identity_digest
        }) {
            return Err(AppealFinanceTransactionForwarderError::DeadLetterConflict);
        }
        if state.checkpoint.pending.len() >= self.policy.max_pending {
            return Err(AppealFinanceTransactionForwarderError::PendingCapacityExhausted);
        }
        let sequence = state.checkpoint.next_sequence;
        let mut candidate = state.checkpoint.clone();
        candidate.next_sequence = sequence
            .checked_add(1)
            .ok_or(AppealFinanceTransactionForwarderError::SequenceExhausted)?;
        candidate.pending.push(StoredPendingV1 {
            sequence,
            operation_id,
            identity_scope: prepared.identity_scope,
            identity_digest: prepared.identity_digest,
            semantic_digest: prepared.semantic_digest,
            network_id: prepared.network_id,
            chain_id: prepared.chain_id,
            authority: prepared.authority,
            operation: prepared.operation,
            expected_record: prepared.expected_record,
            reconciliation_context: prepared.reconciliation_context,
            state: StoredDeliveryStateV1::Ready,
            attempts: 0,
            baseline_finalized_height: context.finalized_cursor.height,
            baseline_finalized_block_hash: context.finalized_cursor.block_hash,
            signed_transaction_bytes: None,
        });
        candidate.pending.sort_by_key(|entry| entry.sequence);
        self.commit_candidate(&mut state, candidate)?;
        Ok(AppealFinanceTransactionEnqueueResultV1::Inserted { operation_id })
    }
    /// Return a fair circular page after an immutable sequence cursor.
    pub fn pending_after(
        &self,
        after_sequence: Option<u64>,
        limit: usize,
    ) -> Result<Vec<AppealFinanceTransactionPendingV1>, AppealFinanceTransactionForwarderError>
    {
        if limit == 0 || limit > APPEAL_FINANCE_FORWARDER_MAX_SCAN_ITEMS_V1 {
            return Err(AppealFinanceTransactionForwarderError::InvalidScanLimit);
        }
        let state = self.lock_state()?;
        let pending = &state.checkpoint.pending;
        if pending.is_empty() {
            return Ok(Vec::new());
        }
        let start = after_sequence.map_or(0, |sequence| {
            pending.partition_point(|entry| entry.sequence <= sequence)
        });
        Ok(pending[start..]
            .iter()
            .chain(pending[..start].iter())
            .take(limit.min(pending.len()))
            .map(StoredPendingV1::snapshot)
            .collect())
    }
    /// Read exact semantic material without claiming a signer attempt.
    pub fn operation_for_reconciliation(
        &self,
        operation_id: [u8; 32],
    ) -> Result<AppealFinanceTransactionSigningRequestV1, AppealFinanceTransactionForwarderError>
    {
        let state = self.lock_state()?;
        state
            .checkpoint
            .pending
            .iter()
            .find(|entry| entry.operation_id == operation_id)
            .map(StoredPendingV1::request)
            .ok_or(AppealFinanceTransactionForwarderError::UnknownOperation)
    }
    /// Return bounded payload-free dead letters.
    pub fn dead_letters(
        &self,
        limit: usize,
    ) -> Result<Vec<AppealFinanceTransactionDeadLetterV1>, AppealFinanceTransactionForwarderError>
    {
        if limit == 0 || limit > APPEAL_FINANCE_FORWARDER_MAX_SCAN_ITEMS_V1 {
            return Err(AppealFinanceTransactionForwarderError::InvalidScanLimit);
        }
        let state = self.lock_state()?;
        Ok(state
            .checkpoint
            .dead_letters
            .iter()
            .take(limit)
            .map(|entry| AppealFinanceTransactionDeadLetterV1 {
                operation_id: entry.operation_id,
                kind: match entry.kind {
                    StoredIdentityScopeV1::Open => AppealFinanceTransactionKindV1::Open,
                    StoredIdentityScopeV1::Drawdown => AppealFinanceTransactionKindV1::Drawdown,
                    StoredIdentityScopeV1::Cancel => AppealFinanceTransactionKindV1::Cancel,
                },
                reason: entry.reason.into(),
                observed_finalized_height: entry.observed_finalized_height,
                observed_finalized_block_hash: entry.observed_finalized_block_hash,
            })
            .collect())
    }
    /// Durably claim one ready operation for an isolated signer.
    pub fn claim_for_signing(
        &self,
        operation_id: [u8; 32],
        finalized_cursor: AppealFinanceFinalizedCursorV1,
    ) -> Result<AppealFinanceTransactionSigningRequestV1, AppealFinanceTransactionForwarderError>
    {
        validate_finalized_cursor(finalized_cursor)?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let position = pending_position(&candidate, operation_id)?;
        if let Err(error) = validate_observed_cursor(&candidate.pending[position], finalized_cursor)
        {
            self.move_to_dead_letter(
                &mut candidate,
                position,
                StoredDeadLetterReasonV1::StaleFinalizedCursor,
                finalized_cursor,
            )?;
            self.commit_candidate(&mut state, candidate)?;
            return Err(error);
        }
        claim_for_signing(
            &mut candidate.pending[position],
            finalized_cursor,
            self.policy.max_attempts,
        )?;
        let request = candidate.pending[position].request();
        self.commit_candidate(&mut state, candidate)?;
        Ok(request)
    }
    /// Persist exact canonical signed bytes and verify all semantic material.
    pub fn store_signed_transaction(
        &self,
        operation_id: [u8; 32],
        signed_transaction_bytes: &[u8],
    ) -> Result<[u8; 32], AppealFinanceTransactionForwarderError> {
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let entry = find_pending_mut(&mut candidate, operation_id)?;
        let prepared = PreparedOperation::decode_signed_transaction(
            signed_transaction_bytes,
            &entry.network_id,
            &entry.chain_id,
            &entry.authority,
            entry.expected_record.clone(),
            entry.reconciliation_context.clone(),
            self.policy.max_transaction_bytes,
        )?;
        if prepared.operation_id() != entry.operation_id
            || prepared.identity_scope != entry.identity_scope
            || prepared.identity_digest != entry.identity_digest
            || prepared.semantic_digest != entry.semantic_digest
            || prepared.network_id != entry.network_id
            || prepared.authority != entry.authority
            || prepared.operation != entry.operation
        {
            return Err(AppealFinanceTransactionForwarderError::InvalidSignedTransaction);
        }
        store_signed_transaction(entry, signed_transaction_bytes.to_vec())?;
        let digest = transaction_digest(signed_transaction_bytes);
        self.commit_candidate(&mut state, candidate)?;
        Ok(digest)
    }
    /// Release a signing claim known not to have submitted.
    pub fn release_signing_claim(
        &self,
        operation_id: [u8; 32],
    ) -> Result<(), AppealFinanceTransactionForwarderError> {
        self.mutate_entry(operation_id, release_signing_claim_preserving_cursor)
    }
    /// Consume one failed signing attempt, dead-lettering at the configured bound.
    pub fn mark_signing_failed(
        &self,
        operation_id: [u8; 32],
        observed_cursor: AppealFinanceFinalizedCursorV1,
    ) -> Result<(), AppealFinanceTransactionForwarderError> {
        validate_finalized_cursor(observed_cursor)?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let position = pending_position(&candidate, operation_id)?;
        validate_observed_cursor(&candidate.pending[position], observed_cursor)?;
        let entry = &mut candidate.pending[position];
        if entry.state != StoredDeliveryStateV1::Signing || entry.signed_transaction_bytes.is_some()
        {
            return Err(AppealFinanceTransactionForwarderError::InvalidTransition);
        }
        if entry.attempts >= self.policy.max_attempts {
            self.move_to_dead_letter(
                &mut candidate,
                position,
                StoredDeadLetterReasonV1::RetryExhausted,
                observed_cursor,
            )?;
        } else {
            entry.state = StoredDeliveryStateV1::Ready;
            entry.baseline_finalized_height = observed_cursor.height;
            entry.baseline_finalized_block_hash = observed_cursor.block_hash;
        }
        self.commit_candidate(&mut state, candidate)
    }
    /// Mark exact signed bytes ambiguous before any submitter sees them.
    pub fn begin_submission(
        &self,
        operation_id: [u8; 32],
    ) -> Result<Vec<u8>, AppealFinanceTransactionForwarderError> {
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let bytes = durable::begin_submission(find_pending_mut(&mut candidate, operation_id)?)?;
        self.commit_candidate(&mut state, candidate)?;
        Ok(bytes)
    }
    /// Record a known pending/applied submission.
    pub fn mark_submitted(
        &self,
        operation_id: [u8; 32],
    ) -> Result<(), AppealFinanceTransactionForwarderError> {
        self.mutate_entry(operation_id, |entry| {
            durable::mark_submitted(entry).map_err(Into::into)
        })
    }
    /// Return a known pre-queue failure to exact signed state.
    pub fn mark_not_submitted(
        &self,
        operation_id: [u8; 32],
    ) -> Result<(), AppealFinanceTransactionForwarderError> {
        self.mutate_entry(operation_id, |entry| {
            durable::mark_not_submitted(entry).map_err(Into::into)
        })
    }
    /// Consume one definitely-not-submitted retry, preserving exact signed bytes.
    pub fn mark_retryable_submission_failed(
        &self,
        operation_id: [u8; 32],
        observed_cursor: AppealFinanceFinalizedCursorV1,
    ) -> Result<(), AppealFinanceTransactionForwarderError> {
        validate_finalized_cursor(observed_cursor)?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let position = pending_position(&candidate, operation_id)?;
        validate_observed_cursor(&candidate.pending[position], observed_cursor)?;
        let entry = &mut candidate.pending[position];
        if !matches!(
            entry.state,
            StoredDeliveryStateV1::Signed | StoredDeliveryStateV1::Ambiguous
        ) || entry.signed_transaction_bytes.is_none()
        {
            return Err(AppealFinanceTransactionForwarderError::InvalidTransition);
        }
        if entry.attempts >= self.policy.max_attempts {
            self.move_to_dead_letter(
                &mut candidate,
                position,
                StoredDeadLetterReasonV1::RetryExhausted,
                observed_cursor,
            )?;
        } else {
            entry.attempts = entry
                .attempts
                .checked_add(1)
                .ok_or(AppealFinanceTransactionForwarderError::RetryExhausted)?;
            entry.baseline_finalized_height = observed_cursor.height;
            entry.baseline_finalized_block_hash = observed_cursor.block_hash;
            entry.state = StoredDeliveryStateV1::Signed;
        }
        self.commit_candidate(&mut state, candidate)
    }
    /// Retry exact signed bytes after authoritative finalized absence.
    pub fn mark_finalized_absent(
        &self,
        operation_id: [u8; 32],
        observed_cursor: AppealFinanceFinalizedCursorV1,
    ) -> Result<(), AppealFinanceTransactionForwarderError> {
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let position = pending_position(&candidate, operation_id)?;
        validate_observed_cursor(&candidate.pending[position], observed_cursor)?;
        if durable::mark_finalized_absent(
            &mut candidate.pending[position],
            observed_cursor.into(),
            self.policy.max_attempts,
        )? == RetryBoundOutcome::Exhausted
        {
            self.move_to_dead_letter(
                &mut candidate,
                position,
                StoredDeadLetterReasonV1::RetryExhausted,
                observed_cursor,
            )?;
        }
        self.commit_candidate(&mut state, candidate)
    }
    /// Reconcile semantic success committed through any peer.
    pub fn mark_semantic_finalized(
        &self,
        operation_id: [u8; 32],
        finalized_cursor: AppealFinanceFinalizedCursorV1,
    ) -> Result<(), AppealFinanceTransactionForwarderError> {
        validate_finalized_cursor(finalized_cursor)?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let position = pending_position(&candidate, operation_id)?;
        validate_observed_cursor(&candidate.pending[position], finalized_cursor)?;
        if candidate.completed.len() >= self.policy.max_completed {
            // A completed identity is an exactly-once tombstone. Dropping an
            // older entry would make the same economic operation admissible
            // again while its escrow can still hold funds. Compaction is safe
            // only after a committed ledger idempotency record supersedes the
            // local tombstone, so this bounded projector fails closed instead.
            return Err(AppealFinanceTransactionForwarderError::CompletedCapacityExhausted);
        }
        let entry = candidate.pending.remove(position);
        candidate.completed.push(StoredCompletedV1 {
            operation_id: entry.operation_id,
            identity_scope: entry.identity_scope,
            identity_digest: entry.identity_digest,
            semantic_digest: entry.semantic_digest,
            finalized_height: finalized_cursor.height,
            finalized_block_hash: finalized_cursor.block_hash,
        });
        candidate.completed.sort_by_key(|entry| entry.operation_id);
        self.commit_candidate(&mut state, candidate)
    }
    /// Dead-letter a semantic conflict.
    pub fn mark_finalized_conflict(
        &self,
        operation_id: [u8; 32],
        observed_cursor: AppealFinanceFinalizedCursorV1,
    ) -> Result<(), AppealFinanceTransactionForwarderError> {
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let position = pending_position(&candidate, operation_id)?;
        validate_observed_cursor(&candidate.pending[position], observed_cursor)?;
        self.move_to_dead_letter(
            &mut candidate,
            position,
            StoredDeadLetterReasonV1::FinalizedConflict,
            observed_cursor,
        )?;
        self.commit_candidate(&mut state, candidate)
    }
    /// Dead-letter an operation whose bound governed policy is no longer active.
    pub fn mark_policy_superseded(
        &self,
        operation_id: [u8; 32],
        observed_cursor: AppealFinanceFinalizedCursorV1,
    ) -> Result<(), AppealFinanceTransactionForwarderError> {
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let position = pending_position(&candidate, operation_id)?;
        validate_observed_cursor(&candidate.pending[position], observed_cursor)?;
        self.move_to_dead_letter(
            &mut candidate,
            position,
            StoredDeadLetterReasonV1::PolicySuperseded,
            observed_cursor,
        )?;
        self.commit_candidate(&mut state, candidate)
    }
    /// Dead-letter a malformed or noncanonical durable reconciliation context.
    pub fn mark_invalid_context(
        &self,
        operation_id: [u8; 32],
        observed_cursor: AppealFinanceFinalizedCursorV1,
    ) -> Result<(), AppealFinanceTransactionForwarderError> {
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let position = pending_position(&candidate, operation_id)?;
        validate_observed_cursor(&candidate.pending[position], observed_cursor)?;
        self.move_to_dead_letter(
            &mut candidate,
            position,
            StoredDeadLetterReasonV1::InvalidContext,
            observed_cursor,
        )?;
        self.commit_candidate(&mut state, candidate)
    }
    /// Dead-letter an operation whose governed signer binding is terminally inactive.
    pub fn mark_signer_binding_inactive(
        &self,
        operation_id: [u8; 32],
        observed_cursor: AppealFinanceFinalizedCursorV1,
    ) -> Result<(), AppealFinanceTransactionForwarderError> {
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let position = pending_position(&candidate, operation_id)?;
        validate_observed_cursor(&candidate.pending[position], observed_cursor)?;
        self.move_to_dead_letter(
            &mut candidate,
            position,
            StoredDeadLetterReasonV1::SignerBindingInactive,
            observed_cursor,
        )?;
        self.commit_candidate(&mut state, candidate)
    }
    /// Dead-letter a finalized cursor rollback or same-height fork.
    pub fn mark_stale_finalized_cursor(
        &self,
        operation_id: [u8; 32],
        observed_cursor: AppealFinanceFinalizedCursorV1,
    ) -> Result<(), AppealFinanceTransactionForwarderError> {
        validate_finalized_cursor(observed_cursor)?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let position = pending_position(&candidate, operation_id)?;
        if validate_observed_cursor(&candidate.pending[position], observed_cursor).is_ok() {
            return Err(AppealFinanceTransactionForwarderError::InvalidTransition);
        }
        self.move_to_dead_letter(
            &mut candidate,
            position,
            StoredDeadLetterReasonV1::StaleFinalizedCursor,
            observed_cursor,
        )?;
        self.commit_candidate(&mut state, candidate)
    }
    /// Clear a terminally rejected envelope for bounded replacement signing.
    pub fn mark_transaction_rejected(
        &self,
        operation_id: [u8; 32],
        observed_cursor: AppealFinanceFinalizedCursorV1,
    ) -> Result<(), AppealFinanceTransactionForwarderError> {
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let position = pending_position(&candidate, operation_id)?;
        validate_observed_cursor(&candidate.pending[position], observed_cursor)?;
        if durable::mark_transaction_rejected(
            &mut candidate.pending[position],
            self.policy.max_attempts,
        ) == RetryBoundOutcome::Exhausted
        {
            self.move_to_dead_letter(
                &mut candidate,
                position,
                StoredDeadLetterReasonV1::TransactionRejected,
                observed_cursor,
            )?;
        } else {
            candidate.pending[position].baseline_finalized_height = observed_cursor.height;
            candidate.pending[position].baseline_finalized_block_hash = observed_cursor.block_hash;
        }
        self.commit_candidate(&mut state, candidate)
    }
    fn move_to_dead_letter(
        &self,
        checkpoint: &mut CheckpointBodyV1,
        position: usize,
        reason: StoredDeadLetterReasonV1,
        cursor: AppealFinanceFinalizedCursorV1,
    ) -> Result<(), AppealFinanceTransactionForwarderError> {
        validate_finalized_cursor(cursor)?;
        if checkpoint.dead_letters.len() >= self.policy.max_dead_letters {
            return Err(AppealFinanceTransactionForwarderError::DeadLetterCapacityExhausted);
        }
        let entry = checkpoint.pending.remove(position);
        checkpoint.dead_letters.push(StoredDeadLetterV1 {
            operation_id: entry.operation_id,
            identity_scope: entry.identity_scope,
            identity_digest: entry.identity_digest,
            semantic_digest: entry.semantic_digest,
            kind: entry.identity_scope,
            reason,
            observed_finalized_height: cursor.height,
            observed_finalized_block_hash: cursor.block_hash,
        });
        checkpoint
            .dead_letters
            .sort_by_key(|entry| entry.operation_id);
        Ok(())
    }
    fn mutate_entry(
        &self,
        operation_id: [u8; 32],
        mutate: impl FnOnce(&mut StoredPendingV1) -> Result<(), AppealFinanceTransactionForwarderError>,
    ) -> Result<(), AppealFinanceTransactionForwarderError> {
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        mutate(find_pending_mut(&mut candidate, operation_id)?)?;
        self.commit_candidate(&mut state, candidate)
    }
    fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, DurableState>, AppealFinanceTransactionForwarderError>
    {
        let state = self
            .state
            .lock()
            .map_err(|_| AppealFinanceTransactionForwarderError::RuntimePoisoned)?;
        if state.durability_failure {
            return Err(AppealFinanceTransactionForwarderError::DurabilityPoisoned);
        }
        Ok(state)
    }
    fn commit_candidate(
        &self,
        state: &mut DurableState,
        candidate: CheckpointBodyV1,
    ) -> Result<(), AppealFinanceTransactionForwarderError> {
        validate_checkpoint(&candidate, self.policy)?;
        if let Some(store) = self.store.as_ref() {
            let authentication = self.checkpoint_authentication.as_ref().ok_or(
                AppealFinanceTransactionForwarderError::InvalidCheckpointAuthenticationPolicy,
            )?;
            verify_checkpoint_runtime_identity(
                &authentication.policy,
                authentication.runtime.as_ref(),
            )?;
            let current = state
                .authenticated_checkpoint
                .as_ref()
                .ok_or(AppealFinanceTransactionForwarderError::InvalidAuthenticatedCheckpoint)?;
            let current_bytes =
                encode_authenticated_checkpoint(current, self.policy, &authentication.policy)?;
            let expected_record = AppealFinanceSealedCheckpointRecordV1::new(
                current.checkpoint_sequence,
                current.checkpoint_digest,
                current_bytes,
            );
            if state.sealed_revision != Some(expected_record.revision)
                || load_latest_qualified(&authentication.policy, authentication.runtime.as_ref())?
                    .as_ref()
                    != Some(&expected_record)
            {
                return Err(AppealFinanceTransactionForwarderError::CheckpointRollback);
            }
            let checkpoint_sequence = current
                .checkpoint_sequence
                .checked_add(1)
                .ok_or(AppealFinanceTransactionForwarderError::SequenceExhausted)?;
            let authenticated = sign_authenticated_checkpoint(
                candidate.clone(),
                checkpoint_sequence,
                Some(current.checkpoint_digest),
                self.policy,
                &authentication.policy,
                authentication.runtime.as_ref(),
            )?;
            let bytes = encode_authenticated_checkpoint(
                &authenticated,
                self.policy,
                &authentication.policy,
            )?;
            let next_record = AppealFinanceSealedCheckpointRecordV1::new(
                authenticated.checkpoint_sequence,
                authenticated.checkpoint_digest,
                bytes.clone(),
            );
            seal_checkpoint_record(
                authentication.runtime.as_ref(),
                &authentication.policy,
                self.policy.checkpoint_max_bytes,
                state.sealed_revision,
                &next_record,
            )?;
            match store.commit_bytes(&bytes, state.fingerprint) {
                Ok(fingerprint) => state.fingerprint = Some(fingerprint),
                Err(error) => {
                    state.durability_failure = true;
                    return Err(error.into());
                }
            }
            state.authenticated_checkpoint = Some(authenticated);
            state.sealed_revision = Some(next_record.revision);
        }
        state.checkpoint = candidate;
        Ok(())
    }
}
#[derive(Debug, Clone)]
struct PreparedOperation {
    identity_scope: StoredIdentityScopeV1,
    identity_digest: [u8; 32],
    semantic_digest: [u8; 32],
    network_id: NetworkId,
    chain_id: ChainId,
    authority: AccountId,
    operation: AppealFinanceOperationV1,
    expected_record: Option<AssetEscrowRecord>,
    reconciliation_context: Vec<u8>,
}
#[derive(Debug, Clone, NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "sorafs_node::appeal_finance_transaction_forwarder::PreparedOperationMaterialV1"
)]
struct PreparedOperationMaterialV1 {
    network_id: NetworkId,
    chain_id: ChainId,
    authority: AccountId,
    operation: AppealFinanceOperationV1,
    expected_record: Option<AssetEscrowRecord>,
    reconciliation_context: Vec<u8>,
}
#[derive(Debug, Clone, NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "sorafs_node::appeal_finance_transaction_forwarder::DrawdownIdentityMaterialV1"
)]
struct DrawdownIdentityMaterialV1 {
    escrow_id: EscrowId,
    amount: Quantity,
    expected_remaining_amount: Quantity,
}
impl PreparedOperation {
    fn new(
        network_id: NetworkId,
        chain_id: ChainId,
        authority: AccountId,
        operation: AppealFinanceOperationV1,
        expected_record: Option<AssetEscrowRecord>,
        reconciliation_context: Vec<u8>,
    ) -> Result<Self, AppealFinanceTransactionForwarderError> {
        if chain_id.as_str().is_empty()
            || chain_id.as_str().len() > APPEAL_FINANCE_MAX_CHAIN_ID_BYTES_V1
            || reconciliation_context.is_empty()
            || reconciliation_context.len() > APPEAL_FINANCE_RECONCILIATION_CONTEXT_MAX_BYTES_V1
        {
            return Err(AppealFinanceTransactionForwarderError::InvalidContext);
        }
        validate_operation(&operation, &authority, expected_record.as_ref())?;
        let (identity_scope, identity_digest) = operation_identity(&operation)?;
        let semantic_digest = semantic_digest(
            &network_id,
            &chain_id,
            &authority,
            &operation,
            expected_record.as_ref(),
            &reconciliation_context,
        )?;
        Ok(Self {
            identity_scope,
            identity_digest,
            semantic_digest,
            network_id,
            chain_id,
            authority,
            operation,
            expected_record,
            reconciliation_context,
        })
    }
    fn new_bounded(
        network_id: NetworkId,
        chain_id: ChainId,
        authority: AccountId,
        operation: AppealFinanceOperationV1,
        expected_record: Option<AssetEscrowRecord>,
        reconciliation_context: Vec<u8>,
        max_transaction_bytes: usize,
    ) -> Result<Self, AppealFinanceTransactionForwarderError> {
        let prepared = Self::new(
            network_id,
            chain_id,
            authority,
            operation,
            expected_record,
            reconciliation_context,
        )?;
        let encoded = norito::to_bytes(&PreparedOperationMaterialV1 {
            network_id: prepared.network_id,
            chain_id: prepared.chain_id.clone(),
            authority: prepared.authority.clone(),
            operation: prepared.operation.clone(),
            expected_record: prepared.expected_record.clone(),
            reconciliation_context: prepared.reconciliation_context.clone(),
        })
        .map_err(AppealFinanceTransactionForwarderError::CanonicalEncoding)?;
        if encoded.len() > max_transaction_bytes {
            return Err(AppealFinanceTransactionForwarderError::ResourceLimitExceeded);
        }
        Ok(prepared)
    }
    fn decode_signed_transaction(
        bytes: &[u8],
        expected_network_id: &NetworkId,
        expected_chain_id: &ChainId,
        expected_authority: &AccountId,
        expected_record: Option<AssetEscrowRecord>,
        reconciliation_context: Vec<u8>,
        max_transaction_bytes: usize,
    ) -> Result<Self, AppealFinanceTransactionForwarderError> {
        if bytes.is_empty()
            || bytes.len() > max_transaction_bytes
            || bytes.len() > APPEAL_FINANCE_TRANSACTION_MAX_CANONICAL_BYTES_V1
        {
            return Err(AppealFinanceTransactionForwarderError::InvalidSignedTransaction);
        }
        norito::core::from_bytes_view(bytes)
            .map_err(|_| AppealFinanceTransactionForwarderError::InvalidSignedTransaction)?;
        let transaction = norito::decode_from_bytes_with_limits::<SignedTransaction>(
            bytes,
            transaction_decode_limits(bytes.len(), max_transaction_bytes)?,
        )
        .map_err(|_| AppealFinanceTransactionForwarderError::InvalidSignedTransaction)?;
        if norito::to_bytes(&transaction)
            .map_err(AppealFinanceTransactionForwarderError::CanonicalEncoding)?
            != bytes
            || transaction.verify_signature().is_err()
            || transaction.network_id() != Some(expected_network_id)
            || transaction.authority() != expected_authority
            || transaction.attachments().is_some()
            || transaction.multisig_signatures().is_some()
        {
            return Err(AppealFinanceTransactionForwarderError::InvalidSignedTransaction);
        }
        let Executable::Instructions(instructions) = transaction.instructions() else {
            return Err(AppealFinanceTransactionForwarderError::InvalidSignedTransaction);
        };
        if instructions.len() != 1 {
            return Err(AppealFinanceTransactionForwarderError::InvalidSignedTransaction);
        }
        let instruction = &instructions[0];
        let operation = if let Some(instruction) =
            instruction.as_any().downcast_ref::<OpenAssetLock>()
        {
            AppealFinanceOperationV1::Open(instruction.clone())
        } else if let Some(instruction) = instruction.as_any().downcast_ref::<DrawdownAssetLock>() {
            AppealFinanceOperationV1::Drawdown(instruction.clone())
        } else if let Some(instruction) = instruction.as_any().downcast_ref::<CancelAssetLock>() {
            AppealFinanceOperationV1::Cancel(instruction.clone())
        } else {
            return Err(AppealFinanceTransactionForwarderError::InvalidSignedTransaction);
        };
        Self::new_bounded(
            *expected_network_id,
            expected_chain_id.clone(),
            transaction.authority().clone(),
            operation,
            expected_record,
            reconciliation_context,
            max_transaction_bytes,
        )
    }
    fn operation_id(&self) -> [u8; 32] {
        operation_id_from_parts(
            self.identity_scope,
            self.identity_digest,
            self.semantic_digest,
        )
    }
}
fn validate_xor_quantity(amount: &Quantity) -> Result<(), AppealFinanceTransactionForwarderError> {
    XorQuantity::try_from_quantity(amount.clone())
        .map(|_| ())
        .map_err(|_| AppealFinanceTransactionForwarderError::InvalidOperation)
}
fn validate_operation(
    operation: &AppealFinanceOperationV1,
    authority: &AccountId,
    expected_record: Option<&AssetEscrowRecord>,
) -> Result<(), AppealFinanceTransactionForwarderError> {
    match operation {
        AppealFinanceOperationV1::Open(instruction) => {
            validate_xor_quantity(instruction.amount())?;
            if expected_record.is_some()
                || instruction.amount().is_zero()
                || instruction.evidence_hashes().len() > 128
                || instruction
                    .expires_at_ms()
                    .is_some_and(|expires_at| expires_at == 0)
            {
                return Err(AppealFinanceTransactionForwarderError::InvalidOperation);
            }
        }
        AppealFinanceOperationV1::Drawdown(instruction) => {
            let Some(record) = expected_record else {
                return Err(AppealFinanceTransactionForwarderError::InvalidOperation);
            };
            validate_xor_quantity(instruction.amount())?;
            validate_xor_quantity(instruction.expected_remaining_amount())?;
            validate_xor_quantity(&record.amount)?;
            validate_xor_quantity(&record.remaining_amount)?;
            let required_authority = record
                .release_authority
                .as_ref()
                .or(record.buyer.as_ref())
                .ok_or(AppealFinanceTransactionForwarderError::InvalidOperation)?;
            if record.id != *instruction.escrow_id()
                || record.kind != AssetEscrowKind::Lock
                || record.status != AssetEscrowStatus::Locked
                || &record.remaining_amount != instruction.expected_remaining_amount()
                || &record.remaining_amount < instruction.amount()
                || instruction.amount().is_zero()
                || required_authority != authority
                || !has_canonical_open_lock_lifecycle(record)
            {
                return Err(AppealFinanceTransactionForwarderError::InvalidOperation);
            }
        }
        AppealFinanceOperationV1::Cancel(instruction) => {
            let Some(record) = expected_record else {
                return Err(AppealFinanceTransactionForwarderError::InvalidOperation);
            };
            validate_xor_quantity(instruction.expected_remaining_amount())?;
            validate_xor_quantity(&record.amount)?;
            validate_xor_quantity(&record.remaining_amount)?;
            if record.id != *instruction.escrow_id()
                || record.kind != AssetEscrowKind::Lock
                || record.status != AssetEscrowStatus::Locked
                || record.remaining_amount.is_zero()
                || &record.remaining_amount != instruction.expected_remaining_amount()
                || &record.seller != authority
                || !has_canonical_open_lock_lifecycle(record)
            {
                return Err(AppealFinanceTransactionForwarderError::InvalidOperation);
            }
        }
    }
    Ok(())
}
/// Reconcile exact semantics against one finalized authoritative escrow.
pub fn reconcile_appeal_finance_operation_v1(
    request: &AppealFinanceTransactionSigningRequestV1,
    finalized_cursor: AppealFinanceFinalizedCursorV1,
    current_record: Option<&AssetEscrowRecord>,
) -> Result<AppealFinanceOperationReconciliationV1, AppealFinanceTransactionForwarderError> {
    validate_finalized_cursor(finalized_cursor)?;
    validate_request_cursor(request, finalized_cursor)?;
    validate_operation(
        &request.operation,
        &request.authority,
        request.expected_record.as_ref(),
    )?;
    Ok(match &request.operation {
        AppealFinanceOperationV1::Open(instruction) => match current_record {
            None => AppealFinanceOperationReconciliationV1::Ready,
            Some(record)
                if record.id == *instruction.escrow_id()
                    && record.kind == AssetEscrowKind::Lock
                    && record.status == AssetEscrowStatus::Locked
                    && record.seller == request.authority
                    && record.buyer.as_ref() == Some(instruction.destination())
                    && record.asset_definition == *instruction.asset_definition()
                    && record.amount == *instruction.amount()
                    && record.remaining_amount == *instruction.amount()
                    && record.release_authority.as_ref()
                        == instruction.release_authority().as_ref()
                    && record.expires_at_ms == *instruction.expires_at_ms()
                    && record.evidence_hashes.as_slice()
                        == instruction.evidence_hashes().as_slice()
                    && has_canonical_open_lock_lifecycle(record) =>
            {
                AppealFinanceOperationReconciliationV1::Finalized
            }
            Some(_) => AppealFinanceOperationReconciliationV1::Conflict,
        },
        AppealFinanceOperationV1::Drawdown(instruction) => {
            let expected = request
                .expected_record
                .as_ref()
                .ok_or(AppealFinanceTransactionForwarderError::InvalidOperation)?;
            match current_record {
                Some(record) if record == expected => AppealFinanceOperationReconciliationV1::Ready,
                Some(record) if same_lock_identity(record, expected) => {
                    let remaining = expected
                        .remaining_amount
                        .try_sub(instruction.amount())
                        .map_err(|_| AppealFinanceTransactionForwarderError::InvalidOperation)?;
                    let expected_status = if remaining.is_zero() {
                        AssetEscrowStatus::DrawnDown
                    } else {
                        AssetEscrowStatus::Locked
                    };
                    let expected_closed = if remaining.is_zero() {
                        record.closed_at_ms.is_some()
                    } else {
                        record.closed_at_ms == expected.closed_at_ms
                    };
                    if record.remaining_amount == remaining
                        && record.status == expected_status
                        && expected_closed
                    {
                        AppealFinanceOperationReconciliationV1::Finalized
                    } else {
                        AppealFinanceOperationReconciliationV1::Conflict
                    }
                }
                _ => AppealFinanceOperationReconciliationV1::Conflict,
            }
        }
        AppealFinanceOperationV1::Cancel(_) => {
            let expected = request
                .expected_record
                .as_ref()
                .ok_or(AppealFinanceTransactionForwarderError::InvalidOperation)?;
            match current_record {
                Some(record) if record == expected => AppealFinanceOperationReconciliationV1::Ready,
                Some(record)
                    if same_lock_identity(record, expected)
                        && record.status == AssetEscrowStatus::Cancelled
                        && record.remaining_amount.is_zero()
                        && record.closed_at_ms.is_some() =>
                {
                    AppealFinanceOperationReconciliationV1::Finalized
                }
                _ => AppealFinanceOperationReconciliationV1::Conflict,
            }
        }
    })
}
fn same_lock_identity(left: &AssetEscrowRecord, right: &AssetEscrowRecord) -> bool {
    left.id == right.id
        && left.seller == right.seller
        && left.buyer == right.buyer
        && left.asset_definition == right.asset_definition
        && left.amount == right.amount
        && left.custody == right.custody
        && left.kind == right.kind
        && left.release_authority == right.release_authority
        && left.expires_at_ms == right.expires_at_ms
        && left.evidence_hashes == right.evidence_hashes
        && left.created_at_ms == right.created_at_ms
        && left.accepted_at_ms == right.accepted_at_ms
        && left.payment_sent_at_ms == right.payment_sent_at_ms
        && left.disputed_at_ms == right.disputed_at_ms
        && left.resolution == right.resolution
}
fn has_canonical_open_lock_lifecycle(record: &AssetEscrowRecord) -> bool {
    record.accepted_at_ms.is_none()
        && record.payment_sent_at_ms.is_none()
        && record.disputed_at_ms.is_none()
        && record.closed_at_ms.is_none()
        && record.resolution.is_none()
}
fn operation_identity(
    operation: &AppealFinanceOperationV1,
) -> Result<(StoredIdentityScopeV1, [u8; 32]), AppealFinanceTransactionForwarderError> {
    let (scope, bytes) = match operation {
        AppealFinanceOperationV1::Open(instruction) => (
            StoredIdentityScopeV1::Open,
            norito::to_bytes(instruction.escrow_id()),
        ),
        AppealFinanceOperationV1::Drawdown(instruction) => (
            StoredIdentityScopeV1::Drawdown,
            norito::to_bytes(&DrawdownIdentityMaterialV1 {
                escrow_id: *instruction.escrow_id(),
                amount: instruction.amount().clone(),
                expected_remaining_amount: instruction.expected_remaining_amount().clone(),
            }),
        ),
        AppealFinanceOperationV1::Cancel(instruction) => (
            StoredIdentityScopeV1::Cancel,
            norito::to_bytes(instruction.escrow_id()),
        ),
    };
    let bytes = bytes.map_err(AppealFinanceTransactionForwarderError::CanonicalEncoding)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(IDENTITY_DOMAIN_V1);
    hasher.update(&[scope.tag()]);
    hasher.update(
        &u64::try_from(bytes.len())
            .map_err(|_| AppealFinanceTransactionForwarderError::ResourceLimitExceeded)?
            .to_le_bytes(),
    );
    hasher.update(&bytes);
    Ok((scope, *hasher.finalize().as_bytes()))
}
fn semantic_digest(
    network_id: &NetworkId,
    chain_id: &ChainId,
    authority: &AccountId,
    operation: &AppealFinanceOperationV1,
    expected_record: Option<&AssetEscrowRecord>,
    reconciliation_context: &[u8],
) -> Result<[u8; 32], AppealFinanceTransactionForwarderError> {
    let bytes = norito::to_bytes(&PreparedOperationMaterialV1 {
        network_id: *network_id,
        chain_id: chain_id.clone(),
        authority: authority.clone(),
        operation: operation.clone(),
        expected_record: expected_record.cloned(),
        reconciliation_context: reconciliation_context.to_vec(),
    })
    .map_err(AppealFinanceTransactionForwarderError::CanonicalEncoding)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(SEMANTIC_DIGEST_DOMAIN_V1);
    hasher.update(
        &u64::try_from(bytes.len())
            .map_err(|_| AppealFinanceTransactionForwarderError::ResourceLimitExceeded)?
            .to_le_bytes(),
    );
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}
fn operation_id_from_parts(
    scope: StoredIdentityScopeV1,
    identity_digest: [u8; 32],
    semantic_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(OPERATION_ID_DOMAIN_V1);
    hasher.update(&[scope.tag()]);
    hasher.update(&identity_digest);
    hasher.update(&semantic_digest);
    *hasher.finalize().as_bytes()
}
fn transaction_digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}
fn find_pending_mut(
    checkpoint: &mut CheckpointBodyV1,
    operation_id: [u8; 32],
) -> Result<&mut StoredPendingV1, AppealFinanceTransactionForwarderError> {
    checkpoint
        .pending
        .iter_mut()
        .find(|entry| entry.operation_id == operation_id)
        .ok_or(AppealFinanceTransactionForwarderError::UnknownOperation)
}
fn pending_position(
    checkpoint: &CheckpointBodyV1,
    operation_id: [u8; 32],
) -> Result<usize, AppealFinanceTransactionForwarderError> {
    checkpoint
        .pending
        .iter()
        .position(|entry| entry.operation_id == operation_id)
        .ok_or(AppealFinanceTransactionForwarderError::UnknownOperation)
}
fn validate_finalized_cursor(
    cursor: AppealFinanceFinalizedCursorV1,
) -> Result<(), AppealFinanceTransactionForwarderError> {
    durable::validate_finalized_cursor(cursor.into()).map_err(Into::into)
}
impl From<AppealFinanceFinalizedCursorV1> for FinalizedCursorV1 {
    fn from(value: AppealFinanceFinalizedCursorV1) -> Self {
        Self {
            height: value.height,
            block_hash: value.block_hash,
        }
    }
}
fn validate_request_cursor(
    request: &AppealFinanceTransactionSigningRequestV1,
    observed: AppealFinanceFinalizedCursorV1,
) -> Result<(), AppealFinanceTransactionForwarderError> {
    let baseline = request.baseline_finalized_cursor;
    if observed.height < baseline.height
        || (observed.height == baseline.height && observed.block_hash != baseline.block_hash)
    {
        return Err(AppealFinanceTransactionForwarderError::StaleFinalizedCursor);
    }
    Ok(())
}
fn validate_observed_cursor(
    entry: &StoredPendingV1,
    observed: AppealFinanceFinalizedCursorV1,
) -> Result<(), AppealFinanceTransactionForwarderError> {
    validate_request_cursor(&entry.request(), observed)
}
fn validate_delivery(entry: &StoredPendingV1, max_attempts: u32) -> bool {
    let has_baseline =
        entry.baseline_finalized_height != 0 && entry.baseline_finalized_block_hash != [0; 32];
    let valid_state = match entry.state {
        StoredDeliveryStateV1::Ready | StoredDeliveryStateV1::Signing => {
            entry.signed_transaction_bytes.is_none()
        }
        StoredDeliveryStateV1::Signed
        | StoredDeliveryStateV1::Ambiguous
        | StoredDeliveryStateV1::Submitted => entry.signed_transaction_bytes.is_some(),
    };
    has_baseline && valid_state && entry.attempts <= max_attempts
}
fn recover_interrupted_signing(entry: &mut StoredPendingV1) -> bool {
    if entry.state != StoredDeliveryStateV1::Signing {
        return false;
    }
    entry.state = StoredDeliveryStateV1::Ready;
    true
}
fn claim_for_signing(
    entry: &mut StoredPendingV1,
    cursor: AppealFinanceFinalizedCursorV1,
    max_attempts: u32,
) -> Result<(), AppealFinanceTransactionForwarderError> {
    validate_finalized_cursor(cursor)?;
    if entry.state != StoredDeliveryStateV1::Ready
        || entry.signed_transaction_bytes.is_some()
        || entry.attempts >= max_attempts
    {
        return Err(if entry.attempts >= max_attempts {
            AppealFinanceTransactionForwarderError::RetryExhausted
        } else {
            AppealFinanceTransactionForwarderError::InvalidTransition
        });
    }
    entry.attempts = entry
        .attempts
        .checked_add(1)
        .ok_or(AppealFinanceTransactionForwarderError::RetryExhausted)?;
    entry.baseline_finalized_height = cursor.height;
    entry.baseline_finalized_block_hash = cursor.block_hash;
    entry.state = StoredDeliveryStateV1::Signing;
    Ok(())
}
fn store_signed_transaction(
    entry: &mut StoredPendingV1,
    bytes: Vec<u8>,
) -> Result<(), AppealFinanceTransactionForwarderError> {
    if entry.state != StoredDeliveryStateV1::Signing
        || entry.signed_transaction_bytes.is_some()
        || entry.attempts == 0
    {
        return Err(AppealFinanceTransactionForwarderError::InvalidTransition);
    }
    entry.signed_transaction_bytes = Some(bytes);
    entry.state = StoredDeliveryStateV1::Signed;
    Ok(())
}
fn release_signing_claim_preserving_cursor(
    entry: &mut StoredPendingV1,
) -> Result<(), AppealFinanceTransactionForwarderError> {
    if entry.state != StoredDeliveryStateV1::Signing || entry.signed_transaction_bytes.is_some() {
        return Err(AppealFinanceTransactionForwarderError::InvalidTransition);
    }
    entry.state = StoredDeliveryStateV1::Ready;
    Ok(())
}
fn validate_checkpoint(
    checkpoint: &CheckpointBodyV1,
    policy: AppealFinanceTransactionForwarderPolicyV1,
) -> Result<(), AppealFinanceTransactionForwarderError> {
    if checkpoint.next_sequence == 0
        || checkpoint.pending.len() > policy.max_pending
        || checkpoint.completed.len() > policy.max_completed
        || checkpoint.dead_letters.len() > policy.max_dead_letters
    {
        return Err(AppealFinanceTransactionForwarderError::InvalidCheckpoint);
    }
    let mut identities = BTreeSet::new();
    let mut operations = BTreeSet::new();
    let mut previous_sequence = 0;
    for entry in &checkpoint.pending {
        let prepared = PreparedOperation::new_bounded(
            entry.network_id,
            entry.chain_id.clone(),
            entry.authority.clone(),
            entry.operation.clone(),
            entry.expected_record.clone(),
            entry.reconciliation_context.clone(),
            policy.max_transaction_bytes,
        )
        .map_err(|_| AppealFinanceTransactionForwarderError::InvalidCheckpoint)?;
        if entry.sequence == 0
            || entry.sequence <= previous_sequence
            || entry.sequence >= checkpoint.next_sequence
            || entry.operation_id == [0; 32]
            || entry.identity_digest == [0; 32]
            || entry.semantic_digest == [0; 32]
            || prepared.identity_scope != entry.identity_scope
            || prepared.identity_digest != entry.identity_digest
            || prepared.semantic_digest != entry.semantic_digest
            || prepared.network_id != entry.network_id
            || prepared.operation_id() != entry.operation_id
            || !validate_delivery(entry, policy.max_attempts)
            || !identities.insert((entry.identity_scope, entry.identity_digest))
            || !operations.insert(entry.operation_id)
        {
            return Err(AppealFinanceTransactionForwarderError::InvalidCheckpoint);
        }
        if let Some(bytes) = entry.signed_transaction_bytes.as_deref() {
            let signed = PreparedOperation::decode_signed_transaction(
                bytes,
                &entry.network_id,
                &entry.chain_id,
                &entry.authority,
                entry.expected_record.clone(),
                entry.reconciliation_context.clone(),
                policy.max_transaction_bytes,
            )
            .map_err(|_| AppealFinanceTransactionForwarderError::InvalidCheckpoint)?;
            if signed.operation_id() != entry.operation_id
                || signed.network_id != entry.network_id
                || signed.authority != entry.authority
                || signed.operation != entry.operation
            {
                return Err(AppealFinanceTransactionForwarderError::InvalidCheckpoint);
            }
        }
        previous_sequence = entry.sequence;
    }
    for entry in &checkpoint.completed {
        if entry.operation_id == [0; 32]
            || entry.identity_digest == [0; 32]
            || entry.semantic_digest == [0; 32]
            || entry.finalized_height == 0
            || entry.finalized_block_hash == [0; 32]
            || operation_id_from_parts(
                entry.identity_scope,
                entry.identity_digest,
                entry.semantic_digest,
            ) != entry.operation_id
            || !identities.insert((entry.identity_scope, entry.identity_digest))
            || !operations.insert(entry.operation_id)
        {
            return Err(AppealFinanceTransactionForwarderError::InvalidCheckpoint);
        }
    }
    for entry in &checkpoint.dead_letters {
        if entry.operation_id == [0; 32]
            || entry.identity_digest == [0; 32]
            || entry.semantic_digest == [0; 32]
            || entry.kind != entry.identity_scope
            || entry.observed_finalized_height == 0
            || entry.observed_finalized_block_hash == [0; 32]
            || operation_id_from_parts(
                entry.identity_scope,
                entry.identity_digest,
                entry.semantic_digest,
            ) != entry.operation_id
            || !identities.insert((entry.identity_scope, entry.identity_digest))
            || !operations.insert(entry.operation_id)
        {
            return Err(AppealFinanceTransactionForwarderError::InvalidCheckpoint);
        }
    }
    Ok(())
}
fn validate_runtime_handle(value: &str) -> Result<(), AppealFinanceTransactionForwarderError> {
    validate_production_runtime_handle(value).map_err(|error| match error {
        ProductionRuntimeHandleError::InvalidSyntax | ProductionRuntimeHandleError::TestMarked => {
            AppealFinanceTransactionForwarderError::InvalidCheckpointAuthenticationPolicy
        }
    })
}
fn checked_checkpoint_verifying_key(bytes: [u8; 32]) -> Result<VerifyingKey, ()> {
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| ())?;
    if key.to_bytes() != bytes || key.is_weak() {
        return Err(());
    }
    Ok(key)
}
fn checkpoint_canonical_digest<T: norito::NoritoSerialize>(
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], AppealFinanceTransactionForwarderError> {
    let bytes = norito::to_bytes(value)
        .map_err(|_| AppealFinanceTransactionForwarderError::InvalidAuthenticatedCheckpoint)?;
    let length = u64::try_from(bytes.len())
        .map_err(|_| AppealFinanceTransactionForwarderError::ResourceLimitExceeded)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&length.to_le_bytes());
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}
fn checkpoint_body_digest(
    body: &CheckpointBodyV1,
) -> Result<[u8; 32], AppealFinanceTransactionForwarderError> {
    checkpoint_canonical_digest(CHECKPOINT_BODY_DIGEST_DOMAIN_V1, body)
}
fn authenticated_checkpoint_digest(
    checkpoint: &AuthenticatedCheckpointV1,
) -> Result<[u8; 32], AppealFinanceTransactionForwarderError> {
    let mut canonical = checkpoint.clone();
    canonical.checkpoint_digest = [0; 32];
    canonical.signature = [0; 64];
    checkpoint_canonical_digest(AUTHENTICATED_CHECKPOINT_DIGEST_DOMAIN_V1, &canonical)
}
fn checkpoint_signature_digest(checkpoint_digest: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(AUTHENTICATED_CHECKPOINT_SIGNATURE_DOMAIN_V1);
    hasher.update(&checkpoint_digest);
    *hasher.finalize().as_bytes()
}
fn validate_authenticated_checkpoint(
    checkpoint: &AuthenticatedCheckpointV1,
    policy: AppealFinanceTransactionForwarderPolicyV1,
    authentication_policy: &AppealFinanceCheckpointAuthenticationPolicyV1,
) -> Result<(), AppealFinanceTransactionForwarderError> {
    authentication_policy.validate()?;
    validate_checkpoint(&checkpoint.body, policy)
        .map_err(|_| AppealFinanceTransactionForwarderError::InvalidAuthenticatedCheckpoint)?;
    let valid_predecessor = if checkpoint.checkpoint_sequence == 1 {
        checkpoint.predecessor_checkpoint_digest.is_none()
    } else {
        checkpoint
            .predecessor_checkpoint_digest
            .is_some_and(|digest| digest != [0; 32])
    };
    if checkpoint.version != APPEAL_FINANCE_FORWARDER_CHECKPOINT_VERSION_V1
        || checkpoint.checkpoint_sequence == 0
        || !valid_predecessor
        || checkpoint.provider_handle != authentication_policy.provider_handle
        || checkpoint.public_key != authentication_policy.public_key
        || checkpoint.provider_revision != authentication_policy.revision
        || checkpoint.provider_policy_digest != authentication_policy.policy_digest
        || checkpoint.body_digest != checkpoint_body_digest(&checkpoint.body)?
        || checkpoint.checkpoint_digest == [0; 32]
        || checkpoint.checkpoint_digest != authenticated_checkpoint_digest(checkpoint)?
    {
        return Err(AppealFinanceTransactionForwarderError::InvalidAuthenticatedCheckpoint);
    }
    let key = checked_checkpoint_verifying_key(checkpoint.public_key)
        .map_err(|()| AppealFinanceTransactionForwarderError::InvalidAuthenticatedCheckpoint)?;
    key.verify_strict(
        &checkpoint_signature_digest(checkpoint.checkpoint_digest),
        &Ed25519Signature::from_bytes(&checkpoint.signature),
    )
    .map_err(|_| AppealFinanceTransactionForwarderError::InvalidAuthenticatedCheckpoint)
}
fn encode_authenticated_checkpoint(
    checkpoint: &AuthenticatedCheckpointV1,
    policy: AppealFinanceTransactionForwarderPolicyV1,
    authentication_policy: &AppealFinanceCheckpointAuthenticationPolicyV1,
) -> Result<Vec<u8>, AppealFinanceTransactionForwarderError> {
    validate_authenticated_checkpoint(checkpoint, policy, authentication_policy)?;
    let bytes = norito::to_bytes(checkpoint)
        .map_err(|_| AppealFinanceTransactionForwarderError::InvalidAuthenticatedCheckpoint)?;
    if bytes.is_empty()
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > policy.checkpoint_max_bytes
    {
        return Err(AppealFinanceTransactionForwarderError::CheckpointTooLarge);
    }
    Ok(bytes)
}
fn decode_authenticated_checkpoint(
    bytes: &[u8],
    policy: AppealFinanceTransactionForwarderPolicyV1,
    authentication_policy: &AppealFinanceCheckpointAuthenticationPolicyV1,
) -> Result<AuthenticatedCheckpointV1, AppealFinanceTransactionForwarderError> {
    if bytes.is_empty() {
        return Err(AppealFinanceTransactionForwarderError::InvalidAuthenticatedCheckpoint);
    }
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > policy.checkpoint_max_bytes {
        return Err(AppealFinanceTransactionForwarderError::CheckpointTooLarge);
    }
    norito::core::from_bytes_view(bytes)
        .map_err(|_| AppealFinanceTransactionForwarderError::InvalidAuthenticatedCheckpoint)?;
    let checkpoint = norito::decode_from_bytes_with_limits::<AuthenticatedCheckpointV1>(
        bytes,
        checkpoint_decode_limits(bytes.len())?,
    )
    .map_err(|_| AppealFinanceTransactionForwarderError::InvalidAuthenticatedCheckpoint)?;
    if norito::to_bytes(&checkpoint)
        .map_err(|_| AppealFinanceTransactionForwarderError::InvalidAuthenticatedCheckpoint)?
        != bytes
    {
        return Err(AppealFinanceTransactionForwarderError::InvalidAuthenticatedCheckpoint);
    }
    validate_authenticated_checkpoint(&checkpoint, policy, authentication_policy)?;
    Ok(checkpoint)
}
fn sealed_checkpoint_record_revision(record: &AppealFinanceSealedCheckpointRecordV1) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SEALED_CHECKPOINT_RECORD_REVISION_DOMAIN_V1);
    hasher.update(&[record.version]);
    hasher.update(&record.checkpoint_sequence.to_le_bytes());
    hasher.update(&record.checkpoint_digest);
    hasher.update(
        &u64::try_from(record.checkpoint_bytes.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(&record.checkpoint_bytes);
    *hasher.finalize().as_bytes()
}
fn sealed_checkpoint_record_max_bytes(
    checkpoint_max_bytes: u64,
) -> Result<u64, AppealFinanceTransactionForwarderError> {
    if checkpoint_max_bytes == 0 {
        return Err(AppealFinanceTransactionForwarderError::InvalidSealedCheckpoint);
    }
    checkpoint_max_bytes
        .checked_add(APPEAL_FINANCE_SEALED_CHECKPOINT_RECORD_MAX_OVERHEAD_BYTES_V1)
        .ok_or(AppealFinanceTransactionForwarderError::ResourceLimitExceeded)
}
fn decode_sealed_checkpoint(
    record: &AppealFinanceSealedCheckpointRecordV1,
    policy: AppealFinanceTransactionForwarderPolicyV1,
    authentication_policy: &AppealFinanceCheckpointAuthenticationPolicyV1,
) -> Result<AuthenticatedCheckpointV1, AppealFinanceTransactionForwarderError> {
    record.validate(policy.checkpoint_max_bytes)?;
    let checkpoint =
        decode_authenticated_checkpoint(&record.checkpoint_bytes, policy, authentication_policy)?;
    if checkpoint.checkpoint_sequence != record.checkpoint_sequence
        || checkpoint.checkpoint_digest != record.checkpoint_digest
    {
        return Err(AppealFinanceTransactionForwarderError::InvalidSealedCheckpoint);
    }
    Ok(checkpoint)
}
fn verify_checkpoint_runtime_identity(
    policy: &AppealFinanceCheckpointAuthenticationPolicyV1,
    runtime: &dyn AppealFinanceCheckpointRuntime,
) -> Result<(), AppealFinanceTransactionForwarderError> {
    policy.validate()?;
    let identity = runtime.identity()?;
    identity.qualification.validate()?;
    if identity.provider_handle != policy.provider_handle
        || identity.public_key != policy.public_key
        || identity.qualification
            != AppealFinanceRuntimeProviderQualificationV1::new(
                policy.revision,
                policy.policy_digest,
            )
        || validate_runtime_handle(&identity.provider_handle).is_err()
        || checked_checkpoint_verifying_key(identity.public_key).is_err()
    {
        return Err(AppealFinanceTransactionForwarderError::CheckpointRuntimeIdentityMismatch);
    }
    Ok(())
}
fn sign_authenticated_checkpoint(
    body: CheckpointBodyV1,
    checkpoint_sequence: u64,
    predecessor_checkpoint_digest: Option<[u8; 32]>,
    policy: AppealFinanceTransactionForwarderPolicyV1,
    authentication_policy: &AppealFinanceCheckpointAuthenticationPolicyV1,
    runtime: &dyn AppealFinanceCheckpointRuntime,
) -> Result<AuthenticatedCheckpointV1, AppealFinanceTransactionForwarderError> {
    authentication_policy.validate()?;
    validate_checkpoint(&body, policy)?;
    verify_checkpoint_runtime_identity(authentication_policy, runtime)?;
    let valid_predecessor = if checkpoint_sequence == 1 {
        predecessor_checkpoint_digest.is_none()
    } else {
        predecessor_checkpoint_digest.is_some_and(|digest| digest != [0; 32])
    };
    if checkpoint_sequence == 0 || !valid_predecessor {
        return Err(AppealFinanceTransactionForwarderError::InvalidAuthenticatedCheckpoint);
    }
    let mut checkpoint = AuthenticatedCheckpointV1 {
        version: APPEAL_FINANCE_FORWARDER_CHECKPOINT_VERSION_V1,
        checkpoint_sequence,
        predecessor_checkpoint_digest,
        provider_handle: authentication_policy.provider_handle.clone(),
        public_key: authentication_policy.public_key,
        provider_revision: authentication_policy.revision,
        provider_policy_digest: authentication_policy.policy_digest,
        body_digest: checkpoint_body_digest(&body)?,
        body,
        checkpoint_digest: [0; 32],
        signature: [0; 64],
    };
    checkpoint.checkpoint_digest = authenticated_checkpoint_digest(&checkpoint)?;
    let unsigned_bytes = norito::to_bytes(&checkpoint)
        .map_err(|_| AppealFinanceTransactionForwarderError::InvalidAuthenticatedCheckpoint)?;
    if unsigned_bytes.is_empty()
        || u64::try_from(unsigned_bytes.len()).unwrap_or(u64::MAX) > policy.checkpoint_max_bytes
    {
        return Err(AppealFinanceTransactionForwarderError::CheckpointTooLarge);
    }
    let signature = runtime.sign_digest(checkpoint_signature_digest(checkpoint.checkpoint_digest));
    verify_checkpoint_runtime_identity(authentication_policy, runtime)?;
    checkpoint.signature = signature?;
    validate_authenticated_checkpoint(&checkpoint, policy, authentication_policy)?;
    Ok(checkpoint)
}
fn load_latest_qualified(
    authentication_policy: &AppealFinanceCheckpointAuthenticationPolicyV1,
    runtime: &dyn AppealFinanceCheckpointRuntime,
) -> Result<Option<AppealFinanceSealedCheckpointRecordV1>, AppealFinanceTransactionForwarderError> {
    verify_checkpoint_runtime_identity(authentication_policy, runtime)?;
    let result = runtime.load_latest();
    verify_checkpoint_runtime_identity(authentication_policy, runtime)?;
    result.map_err(Into::into)
}
fn seal_checkpoint_record(
    runtime: &dyn AppealFinanceCheckpointRuntime,
    authentication_policy: &AppealFinanceCheckpointAuthenticationPolicyV1,
    checkpoint_max_bytes: u64,
    expected_revision: Option<[u8; 32]>,
    next: &AppealFinanceSealedCheckpointRecordV1,
) -> Result<(), AppealFinanceTransactionForwarderError> {
    next.to_canonical_bytes(checkpoint_max_bytes)?;
    verify_checkpoint_runtime_identity(authentication_policy, runtime)?;
    let current = load_latest_qualified(authentication_policy, runtime)?;
    if current.as_ref().map(|record| record.revision) != expected_revision {
        return Err(AppealFinanceTransactionForwarderError::CheckpointFork);
    }
    let compare_and_swap_result = runtime.compare_and_swap_latest(expected_revision, next);
    if let Err(error) = verify_checkpoint_runtime_identity(authentication_policy, runtime) {
        return Err(
            if matches!(
                compare_and_swap_result,
                Ok(()) | Err(AppealFinanceCheckpointExternalError::Ambiguous)
            ) {
                AppealFinanceTransactionForwarderError::CheckpointAuthenticationAmbiguous
            } else {
                error
            },
        );
    }
    match compare_and_swap_result {
        Ok(()) => {}
        Err(AppealFinanceCheckpointExternalError::Ambiguous) => {
            if load_latest_qualified(authentication_policy, runtime)
                .map_err(|_| {
                    AppealFinanceTransactionForwarderError::CheckpointAuthenticationAmbiguous
                })?
                .as_ref()
                != Some(next)
            {
                return Err(
                    AppealFinanceTransactionForwarderError::CheckpointAuthenticationAmbiguous,
                );
            }
        }
        Err(error) => return Err(error.into()),
    }
    if load_latest_qualified(authentication_policy, runtime)
        .map_err(|_| AppealFinanceTransactionForwarderError::CheckpointAuthenticationAmbiguous)?
        .as_ref()
        != Some(next)
    {
        return Err(AppealFinanceTransactionForwarderError::CheckpointFork);
    }
    verify_checkpoint_runtime_identity(authentication_policy, runtime)
        .map_err(|_| AppealFinanceTransactionForwarderError::CheckpointAuthenticationAmbiguous)
}
fn checkpoint_decode_limits(
    encoded_bytes: usize,
) -> Result<norito::DecodeLimits, AppealFinanceTransactionForwarderError> {
    decode_limits(
        encoded_bytes,
        encoded_bytes,
        CHECKPOINT_ELEMENT_AMPLIFICATION_LIMIT,
        CHECKPOINT_ALLOCATION_AMPLIFICATION_LIMIT,
        CHECKPOINT_ALLOCATION_FIXED_OVERHEAD_BYTES,
        CHECKPOINT_MAX_NESTING_DEPTH,
    )
}
fn transaction_decode_limits(
    encoded_bytes: usize,
    max_transaction_bytes: usize,
) -> Result<norito::DecodeLimits, AppealFinanceTransactionForwarderError> {
    decode_limits(
        encoded_bytes,
        max_transaction_bytes,
        TRANSACTION_ELEMENT_AMPLIFICATION_LIMIT,
        TRANSACTION_ALLOCATION_AMPLIFICATION_LIMIT,
        TRANSACTION_ALLOCATION_FIXED_OVERHEAD_BYTES,
        TRANSACTION_MAX_NESTING_DEPTH,
    )
}
fn decode_limits(
    encoded_bytes: usize,
    max_bytes: usize,
    element_amplification: usize,
    allocation_amplification: usize,
    fixed_allocation: usize,
    max_depth: usize,
) -> Result<norito::DecodeLimits, AppealFinanceTransactionForwarderError> {
    if encoded_bytes == 0 || encoded_bytes > max_bytes {
        return Err(AppealFinanceTransactionForwarderError::ResourceLimitExceeded);
    }
    let total_elements = encoded_bytes
        .checked_mul(element_amplification)
        .ok_or(AppealFinanceTransactionForwarderError::ResourceLimitExceeded)?;
    let total_allocated_bytes = encoded_bytes
        .checked_mul(allocation_amplification)
        .and_then(|bytes| bytes.checked_add(fixed_allocation))
        .ok_or(AppealFinanceTransactionForwarderError::ResourceLimitExceeded)?;
    Ok(norito::DecodeLimits::new(
        max_bytes,
        max_bytes,
        total_elements,
        total_allocated_bytes,
        max_depth,
    ))
}
/// Appeal-finance durable forwarding error.
#[derive(Debug, Error)]
pub enum AppealFinanceTransactionForwarderError {
    /// Policy contains an invalid or unbounded limit.
    #[error("appeal-finance transaction forwarder policy is invalid")]
    InvalidPolicy,
    /// Chain, cursor, record, or reconciliation context is invalid.
    #[error("appeal-finance finalized context is invalid")]
    InvalidContext,
    /// Native operation or authority binding is invalid.
    #[error("appeal-finance native operation is invalid")]
    InvalidOperation,
    /// Signed bytes are malformed, noncanonical, or semantically substituted.
    #[error("signed appeal-finance transaction is invalid")]
    InvalidSignedTransaction,
    /// Semantic identity is retained with different material.
    #[error("appeal-finance operation identity conflicts with retained state")]
    IdentityConflict,
    /// Semantic identity already has a terminal dead letter.
    #[error("appeal-finance operation identity has a terminal dead letter")]
    DeadLetterConflict,
    /// Pending capacity is exhausted.
    #[error("appeal-finance pending capacity is exhausted")]
    PendingCapacityExhausted,
    /// Exactly-once completion tombstone capacity is exhausted.
    #[error("appeal-finance completion tombstone capacity is exhausted")]
    CompletedCapacityExhausted,
    /// Dead-letter capacity is exhausted.
    #[error("appeal-finance dead-letter capacity is exhausted")]
    DeadLetterCapacityExhausted,
    /// Sequence allocation overflowed.
    #[error("appeal-finance operation sequence is exhausted")]
    SequenceExhausted,
    /// Worker scan limit is invalid.
    #[error("appeal-finance scan limit is invalid")]
    InvalidScanLimit,
    /// Operation is not pending.
    #[error("appeal-finance operation is not pending")]
    UnknownOperation,
    /// State-machine transition is unsafe.
    #[error("appeal-finance transition is invalid")]
    InvalidTransition,
    /// Finalized cursor is zero.
    #[error("appeal-finance finalized cursor is invalid")]
    InvalidFinalizedCursor,
    /// Finalized cursor moved backwards or equivocated.
    #[error("appeal-finance finalized cursor is stale or forked")]
    StaleFinalizedCursor,
    /// Retry budget is exhausted.
    #[error("appeal-finance retry bound is exhausted")]
    RetryExhausted,
    /// A canonical value exceeds a resource limit.
    #[error("appeal-finance resource limit is exceeded")]
    ResourceLimitExceeded,
    /// Canonical encoding failed.
    #[error("appeal-finance canonical encoding failed: {0}")]
    CanonicalEncoding(#[source] norito::Error),
    /// Runtime checkpoint identity policy is malformed or unsupported.
    #[error("appeal-finance checkpoint authentication policy is invalid")]
    InvalidCheckpointAuthenticationPolicy,
    /// Runtime provider revision or public-policy digest is malformed.
    #[error("appeal-finance runtime provider qualification is invalid")]
    InvalidRuntimeProviderQualification,
    /// The runtime provider identity differs from the configured identity.
    #[error("appeal-finance checkpoint runtime identity does not match configuration")]
    CheckpointRuntimeIdentityMismatch,
    /// The signed checkpoint envelope is malformed, noncanonical, or untrusted.
    #[error("appeal-finance authenticated checkpoint is invalid")]
    InvalidAuthenticatedCheckpoint,
    /// The monotonic sealed checkpoint record is malformed or inconsistent.
    #[error("appeal-finance sealed checkpoint is invalid")]
    InvalidSealedCheckpoint,
    /// Local state is newer than, missing from, or too far behind the sealed head.
    #[error("appeal-finance checkpoint rollback was detected")]
    CheckpointRollback,
    /// Local and sealed checkpoint histories conflict.
    #[error("appeal-finance checkpoint fork was detected")]
    CheckpointFork,
    /// The runtime provider or sealed store is unavailable.
    #[error("appeal-finance checkpoint authentication is unavailable")]
    CheckpointAuthenticationUnavailable,
    /// The runtime provider or sealed store rejected the request.
    #[error("appeal-finance checkpoint authentication request was rejected")]
    CheckpointAuthenticationRejected,
    /// The sealed checkpoint outcome cannot be established safely.
    #[error("appeal-finance checkpoint authentication outcome is ambiguous")]
    CheckpointAuthenticationAmbiguous,
    /// Checkpoint is malformed or inconsistent.
    #[error("appeal-finance checkpoint is invalid")]
    InvalidCheckpoint,
    /// Checkpoint exceeds its byte ceiling.
    #[error("appeal-finance checkpoint exceeds its byte limit")]
    CheckpointTooLarge,
    /// Checkpoint path is unsafe or inaccessible.
    #[error("appeal-finance checkpoint I/O failed")]
    CheckpointIo,
    /// Another runtime changed the checkpoint.
    #[error("appeal-finance checkpoint changed concurrently")]
    StaleCheckpoint,
    /// Another writer owns the checkpoint.
    #[error("appeal-finance checkpoint writer is busy")]
    CheckpointBusy,
    /// Rename may be visible but directory durability is unknown.
    #[error("appeal-finance checkpoint durability is uncertain")]
    CheckpointDurabilityUncertain,
    /// Runtime stopped after uncertain durability.
    #[error("appeal-finance checkpoint durability is poisoned")]
    DurabilityPoisoned,
    /// Runtime state mutex is poisoned.
    #[error("appeal-finance runtime lock is poisoned")]
    RuntimePoisoned,
}
impl From<DeliveryTransitionError> for AppealFinanceTransactionForwarderError {
    fn from(error: DeliveryTransitionError) -> Self {
        match error {
            DeliveryTransitionError::InvalidFinalizedCursor => Self::InvalidFinalizedCursor,
            DeliveryTransitionError::InvalidTransition => Self::InvalidTransition,
            DeliveryTransitionError::RetryExhausted => Self::RetryExhausted,
        }
    }
}
impl From<CheckpointStoreError> for AppealFinanceTransactionForwarderError {
    fn from(error: CheckpointStoreError) -> Self {
        match error {
            CheckpointStoreError::Io => Self::CheckpointIo,
            CheckpointStoreError::TooLarge => Self::CheckpointTooLarge,
            CheckpointStoreError::Busy => Self::CheckpointBusy,
            CheckpointStoreError::Stale => Self::StaleCheckpoint,
            CheckpointStoreError::DurabilityUncertain => Self::CheckpointDurabilityUncertain,
            CheckpointStoreError::RuntimePoisoned => Self::RuntimePoisoned,
        }
    }
}
impl From<AppealFinanceCheckpointExternalError> for AppealFinanceTransactionForwarderError {
    fn from(error: AppealFinanceCheckpointExternalError) -> Self {
        match error {
            AppealFinanceCheckpointExternalError::Unavailable => {
                Self::CheckpointAuthenticationUnavailable
            }
            AppealFinanceCheckpointExternalError::Rejected => {
                Self::CheckpointAuthenticationRejected
            }
            AppealFinanceCheckpointExternalError::Ambiguous => {
                Self::CheckpointAuthenticationAmbiguous
            }
        }
    }
}
#[cfg(test)]
mod tests {
    include!("appeal_finance_transaction_forwarder/schema_identity_tests.rs");
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use iroha_crypto::numeric::Quantity;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        NetworkId,
        asset::AssetDefinitionId,
        block::BlockHeader,
        proof::{ProofAttachment, ProofBox, VerifyingKeyId},
        transaction::{FeePaymentIntent, TransactionBuilder, signed::MultisigSignatures},
    };
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;
    #[derive(Debug)]
    struct TestCheckpointRuntime {
        provider_handle: String,
        key: SigningKey,
        qualification: Mutex<AppealFinanceRuntimeProviderQualificationV1>,
        qualification_after_sign: Mutex<Option<AppealFinanceRuntimeProviderQualificationV1>>,
        qualification_after_compare_and_swap:
            Mutex<Option<AppealFinanceRuntimeProviderQualificationV1>>,
        latest: Mutex<Option<AppealFinanceSealedCheckpointRecordV1>>,
    }
    impl TestCheckpointRuntime {
        fn new(seed: u8) -> Self {
            Self {
                provider_handle: format!("appeal-finance-provider-{seed}"),
                key: SigningKey::from_bytes(&[seed; 32]),
                qualification: Mutex::new(AppealFinanceRuntimeProviderQualificationV1::new(
                    1, [seed; 32],
                )),
                qualification_after_sign: Mutex::new(None),
                qualification_after_compare_and_swap: Mutex::new(None),
                latest: Mutex::new(None),
            }
        }
        fn authentication_policy(&self) -> AppealFinanceCheckpointAuthenticationPolicyV1 {
            AppealFinanceCheckpointAuthenticationPolicyV1 {
                version: APPEAL_FINANCE_CHECKPOINT_AUTHENTICATION_POLICY_VERSION_V1,
                provider_handle: self.provider_handle.clone(),
                public_key: self.key.verifying_key().to_bytes(),
                revision: 1,
                policy_digest: [self.key.to_bytes()[0]; 32],
            }
        }
        fn replace_qualification(
            &self,
            qualification: AppealFinanceRuntimeProviderQualificationV1,
        ) {
            *self.qualification.lock().expect("test qualification lock") = qualification;
        }
        fn replace_qualification_after_next_sign(
            &self,
            qualification: AppealFinanceRuntimeProviderQualificationV1,
        ) {
            *self
                .qualification_after_sign
                .lock()
                .expect("test post-sign qualification lock") = Some(qualification);
        }
        fn replace_qualification_after_next_compare_and_swap(
            &self,
            qualification: AppealFinanceRuntimeProviderQualificationV1,
        ) {
            *self
                .qualification_after_compare_and_swap
                .lock()
                .expect("test post-CAS qualification lock") = Some(qualification);
        }
        fn replace_latest(&self, record: Option<AppealFinanceSealedCheckpointRecordV1>) {
            *self.latest.lock().expect("test sealed checkpoint lock") = record;
        }
    }
    impl AppealFinanceCheckpointRuntime for TestCheckpointRuntime {
        fn identity(
            &self,
        ) -> Result<AppealFinanceCheckpointRuntimeIdentityV1, AppealFinanceCheckpointExternalError>
        {
            Ok(AppealFinanceCheckpointRuntimeIdentityV1 {
                provider_handle: self.provider_handle.clone(),
                public_key: self.key.verifying_key().to_bytes(),
                qualification: *self
                    .qualification
                    .lock()
                    .map_err(|_| AppealFinanceCheckpointExternalError::Unavailable)?,
            })
        }
        fn sign_digest(
            &self,
            digest: [u8; 32],
        ) -> Result<[u8; 64], AppealFinanceCheckpointExternalError> {
            let signature = self.key.sign(&digest).to_bytes();
            if let Some(qualification) = self
                .qualification_after_sign
                .lock()
                .map_err(|_| AppealFinanceCheckpointExternalError::Unavailable)?
                .take()
            {
                *self
                    .qualification
                    .lock()
                    .map_err(|_| AppealFinanceCheckpointExternalError::Unavailable)? =
                    qualification;
            }
            Ok(signature)
        }
        fn load_latest(
            &self,
        ) -> Result<
            Option<AppealFinanceSealedCheckpointRecordV1>,
            AppealFinanceCheckpointExternalError,
        > {
            self.latest
                .lock()
                .map(|latest| latest.clone())
                .map_err(|_| AppealFinanceCheckpointExternalError::Unavailable)
        }
        fn compare_and_swap_latest(
            &self,
            expected_revision: Option<[u8; 32]>,
            next: &AppealFinanceSealedCheckpointRecordV1,
        ) -> Result<(), AppealFinanceCheckpointExternalError> {
            let mut latest = self
                .latest
                .lock()
                .map_err(|_| AppealFinanceCheckpointExternalError::Unavailable)?;
            if latest.as_ref().map(|record| record.revision) != expected_revision
                || latest
                    .as_ref()
                    .map_or(1, |record| record.checkpoint_sequence.saturating_add(1))
                    != next.checkpoint_sequence
            {
                return Err(AppealFinanceCheckpointExternalError::Rejected);
            }
            *latest = Some(next.clone());
            if let Some(qualification) = self
                .qualification_after_compare_and_swap
                .lock()
                .map_err(|_| AppealFinanceCheckpointExternalError::Unavailable)?
                .take()
            {
                *self
                    .qualification
                    .lock()
                    .map_err(|_| AppealFinanceCheckpointExternalError::Unavailable)? =
                    qualification;
            }
            Ok(())
        }
    }
    fn open_durable(
        directory: &Path,
        runtime: Arc<TestCheckpointRuntime>,
    ) -> Result<AppealFinanceTransactionForwarder, AppealFinanceTransactionForwarderError> {
        let authentication_policy = runtime.authentication_policy();
        AppealFinanceTransactionForwarder::open(directory, policy(), authentication_policy, runtime)
    }
    fn checkpoint_path(directory: &Path) -> std::path::PathBuf {
        directory.join(APPEAL_FINANCE_FORWARDER_CHECKPOINT_FILE_NAME_V1)
    }
    fn key(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).unwrap()
    }
    fn account(seed: u8) -> AccountId {
        AccountId::new(key(seed).public_key().clone())
    }
    fn cursor(height: u64, hash: u8) -> AppealFinanceFinalizedCursorV1 {
        AppealFinanceFinalizedCursorV1 {
            height,
            block_hash: [hash; 32],
        }
    }
    fn network_id(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([seed; 32]),
        ))
    }
    fn test_network_id() -> NetworkId {
        network_id(0xA1)
    }
    fn policy() -> AppealFinanceTransactionForwarderPolicyV1 {
        AppealFinanceTransactionForwarderPolicyV1 {
            max_pending: 8,
            max_completed: 8,
            max_dead_letters: 8,
            max_attempts: 2,
            max_transaction_bytes: 1024 * 1024,
            checkpoint_max_bytes: 8 * 1024 * 1024,
        }
    }
    fn escrow_id() -> EscrowId {
        EscrowId::new(Hash::new("appeal-finance-forwarder-test"))
    }
    fn asset_definition() -> AssetDefinitionId {
        "61CtjvNd9T3THAR65GsMVHr82Bjc".parse().unwrap()
    }
    fn active_record() -> AssetEscrowRecord {
        AssetEscrowRecord {
            id: escrow_id(),
            seller: account(1),
            buyer: Some(account(2)),
            asset_definition: asset_definition(),
            amount: Quantity::from(100_u32),
            custody: account(3),
            status: AssetEscrowStatus::Locked,
            kind: AssetEscrowKind::Lock,
            remaining_amount: Quantity::from(100_u32),
            release_authority: Some(account(4)),
            expires_at_ms: Some(10_000),
            evidence_hashes: vec![Hash::new("appeal-evidence")],
            conditions: Vec::new(),
            created_at_ms: 1,
            accepted_at_ms: None,
            payment_sent_at_ms: None,
            disputed_at_ms: None,
            closed_at_ms: None,
            resolution: None,
        }
    }
    fn drawdown_context() -> AppealFinanceTransactionContextV1 {
        AppealFinanceTransactionContextV1 {
            network_id: test_network_id(),
            chain_id: ChainId::from("appeal-finance-forwarder-test"),
            finalized_cursor: cursor(7, 7),
            expected_record: Some(active_record()),
            reconciliation_context: vec![0xA1, 0x01],
        }
    }
    fn drawdown_operation() -> AppealFinanceOperationV1 {
        AppealFinanceOperationV1::Drawdown(DrawdownAssetLock::new(
            escrow_id(),
            Quantity::from(60_u32),
            Quantity::from(100_u32),
        ))
    }
    #[test]
    fn appeal_finance_operations_reject_non_xor_precision_before_queueing() {
        let forwarder = AppealFinanceTransactionForwarder::in_memory(policy()).unwrap();
        let invalid_xor: Quantity = "0.0000000001"
            .parse()
            .expect("generic quantity permits scale ten");
        let open_context = AppealFinanceTransactionContextV1 {
            network_id: test_network_id(),
            chain_id: ChainId::from("appeal-finance-forwarder-test"),
            finalized_cursor: cursor(7, 7),
            expected_record: None,
            reconciliation_context: vec![0xA1, 0x00],
        };
        let open = AppealFinanceOperationV1::Open(OpenAssetLock::new(
            escrow_id(),
            asset_definition(),
            account(2),
            invalid_xor.clone(),
        ));
        assert!(matches!(
            forwarder.enqueue_unsigned_operation(account(1), open, &open_context),
            Err(AppealFinanceTransactionForwarderError::InvalidOperation)
        ));
        let invalid_drawdown = AppealFinanceOperationV1::Drawdown(DrawdownAssetLock::new(
            escrow_id(),
            invalid_xor.clone(),
            Quantity::from(100_u32),
        ));
        assert!(matches!(
            forwarder.enqueue_unsigned_operation(account(4), invalid_drawdown, &drawdown_context()),
            Err(AppealFinanceTransactionForwarderError::InvalidOperation)
        ));
        let invalid_precondition = AppealFinanceOperationV1::Drawdown(DrawdownAssetLock::new(
            escrow_id(),
            Quantity::from(60_u32),
            invalid_xor.clone(),
        ));
        assert!(matches!(
            forwarder.enqueue_unsigned_operation(
                account(4),
                invalid_precondition,
                &drawdown_context()
            ),
            Err(AppealFinanceTransactionForwarderError::InvalidOperation)
        ));
        let mut poisoned_record = active_record();
        poisoned_record.amount = invalid_xor.clone();
        let poisoned_drawdown_context = AppealFinanceTransactionContextV1 {
            expected_record: Some(poisoned_record),
            ..drawdown_context()
        };
        assert!(matches!(
            forwarder.enqueue_unsigned_operation(
                account(4),
                drawdown_operation(),
                &poisoned_drawdown_context
            ),
            Err(AppealFinanceTransactionForwarderError::InvalidOperation)
        ));
        let mut poisoned_record = active_record();
        poisoned_record.remaining_amount = invalid_xor.clone();
        let poisoned_cancel_context = AppealFinanceTransactionContextV1 {
            expected_record: Some(poisoned_record),
            ..drawdown_context()
        };
        let cancel =
            AppealFinanceOperationV1::Cancel(CancelAssetLock::new(escrow_id(), invalid_xor));
        assert!(matches!(
            forwarder.enqueue_unsigned_operation(account(1), cancel, &poisoned_cancel_context),
            Err(AppealFinanceTransactionForwarderError::InvalidOperation)
        ));
        assert!(forwarder.pending_after(None, 8).unwrap().is_empty());
    }
    #[test]
    fn cancel_operation_binds_the_observed_remaining_amount() {
        let forwarder = AppealFinanceTransactionForwarder::in_memory(policy()).unwrap();
        let stale_cancel = AppealFinanceOperationV1::Cancel(CancelAssetLock::new(
            escrow_id(),
            Quantity::from(99_u32),
        ));
        assert!(matches!(
            forwarder.enqueue_unsigned_operation(account(1), stale_cancel, &drawdown_context()),
            Err(AppealFinanceTransactionForwarderError::InvalidOperation)
        ));
        assert!(forwarder.pending_after(None, 8).unwrap().is_empty());
    }
    fn signed_bytes(
        signer: &KeyPair,
        authority: AccountId,
        operation: AppealFinanceOperationV1,
    ) -> Vec<u8> {
        signed_bytes_on_network(test_network_id(), signer, authority, operation)
    }
    fn signed_bytes_on_network(
        network_id: NetworkId,
        signer: &KeyPair,
        authority: AccountId,
        operation: AppealFinanceOperationV1,
    ) -> Vec<u8> {
        let transaction = TransactionBuilder::new(
            network_id,
            authority,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([InstructionBox::from(operation)])
        .try_sign(signer.private_key())
        .unwrap();
        norito::to_bytes(&transaction).unwrap()
    }
    #[test]
    fn replay_is_idempotent_but_semantic_substitution_conflicts() {
        let forwarder = AppealFinanceTransactionForwarder::in_memory(policy()).unwrap();
        let context = drawdown_context();
        let authority = account(4);
        let inserted = forwarder
            .enqueue_unsigned_operation(authority.clone(), drawdown_operation(), &context)
            .unwrap();
        assert!(matches!(
            forwarder
                .enqueue_unsigned_operation(authority.clone(), drawdown_operation(), &context)
                .unwrap(),
            AppealFinanceTransactionEnqueueResultV1::Existing { .. }
        ));
        let mut substituted_context = context;
        substituted_context.reconciliation_context = vec![0xA1, 0x02];
        assert!(matches!(
            forwarder.enqueue_unsigned_operation(
                authority,
                drawdown_operation(),
                &substituted_context
            ),
            Err(AppealFinanceTransactionForwarderError::IdentityConflict)
        ));
        assert_ne!(inserted.operation_id(), [0; 32]);
    }
    #[test]
    fn signed_envelope_rejects_wrong_authority_and_wrong_signature() {
        let forwarder = AppealFinanceTransactionForwarder::in_memory(policy()).unwrap();
        let context = drawdown_context();
        let signer = key(4);
        let authority = AccountId::new(signer.public_key().clone());
        let operation_id = forwarder
            .enqueue_unsigned_operation(authority.clone(), drawdown_operation(), &context)
            .unwrap()
            .operation_id();
        forwarder
            .claim_for_signing(operation_id, cursor(7, 7))
            .unwrap();
        let wrong = key(5);
        let wrong_authority = AccountId::new(wrong.public_key().clone());
        let wrong_authority_bytes = signed_bytes(&wrong, wrong_authority, drawdown_operation());
        assert!(matches!(
            forwarder.store_signed_transaction(operation_id, &wrong_authority_bytes),
            Err(AppealFinanceTransactionForwarderError::InvalidSignedTransaction)
        ));
        let wrong_network_bytes = signed_bytes_on_network(
            network_id(0xF1),
            &signer,
            authority.clone(),
            drawdown_operation(),
        );
        assert!(matches!(
            forwarder.store_signed_transaction(operation_id, &wrong_network_bytes),
            Err(AppealFinanceTransactionForwarderError::InvalidSignedTransaction)
        ));
        let mismatched_signature = {
            let transaction = TransactionBuilder::new(
                test_network_id(),
                AccountId::new(wrong.public_key().clone()),
                FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([InstructionBox::from(drawdown_operation())])
            .try_sign(wrong.private_key())
            .unwrap()
            .with_authority(authority);
            norito::to_bytes(&transaction).unwrap()
        };
        assert!(matches!(
            forwarder.store_signed_transaction(operation_id, &mismatched_signature),
            Err(AppealFinanceTransactionForwarderError::InvalidSignedTransaction)
        ));
        let valid = signed_bytes(&signer, account(4), drawdown_operation());
        assert_ne!(
            forwarder
                .store_signed_transaction(operation_id, &valid)
                .unwrap(),
            [0; 32]
        );
    }
    #[test]
    fn signed_envelope_rejects_invalid_frames_without_consuming_signing_claim() {
        let signer = key(4);
        let authority = AccountId::new(signer.public_key().clone());
        let context = drawdown_context();
        let claimed_forwarder = |policy| {
            let forwarder = AppealFinanceTransactionForwarder::in_memory(policy).unwrap();
            let operation_id = forwarder
                .enqueue_unsigned_operation(authority.clone(), drawdown_operation(), &context)
                .unwrap()
                .operation_id();
            forwarder
                .claim_for_signing(operation_id, cursor(7, 7))
                .unwrap();
            (forwarder, operation_id)
        };
        let limited_policy = AppealFinanceTransactionForwarderPolicyV1 {
            max_transaction_bytes: 64 * 1024,
            ..policy()
        };
        let valid = signed_bytes(&signer, authority.clone(), drawdown_operation());
        assert!(valid.len() < limited_policy.max_transaction_bytes);
        let (baseline, operation_id) = claimed_forwarder(limited_policy);
        assert_eq!(
            baseline
                .store_signed_transaction(operation_id, &valid)
                .unwrap(),
            transaction_digest(&valid)
        );

        // This frame is canonical and authorized; only the configured byte limit rejects it.
        let padding = "x".repeat(limited_policy.max_transaction_bytes);
        let mut metadata = iroha_model_base::metadata::Metadata::default();
        metadata.insert("padding".parse().unwrap(), padding.as_str());
        let oversized = TransactionBuilder::new(
            test_network_id(),
            authority.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([InstructionBox::from(drawdown_operation())])
        .with_metadata(metadata)
        .try_sign(signer.private_key())
        .unwrap();
        let oversized = norito::to_bytes(&oversized).unwrap();
        assert!(oversized.len() > limited_policy.max_transaction_bytes);
        assert!(oversized.len() <= policy().max_transaction_bytes);
        let (permissive_baseline, oversized_operation_id) = claimed_forwarder(policy());
        assert_eq!(
            permissive_baseline
                .store_signed_transaction(oversized_operation_id, &oversized)
                .unwrap(),
            transaction_digest(&oversized)
        );

        let truncated = valid[..valid.len() - 1].to_vec();
        let mut trailing = valid.clone();
        trailing.push(0);
        let mut wrong_header = valid.clone();
        wrong_header[..4].copy_from_slice(b"BAD!");
        let (forwarder, claimed_operation_id) = claimed_forwarder(limited_policy);
        assert_eq!(claimed_operation_id, operation_id);
        let claimed_checkpoint = forwarder.state.lock().unwrap().checkpoint.clone();
        for (label, bytes) in [
            ("truncated", truncated),
            ("trailing", trailing),
            ("wrong header", wrong_header),
            ("over policy", oversized),
        ] {
            if label != "over policy" {
                assert!(bytes.len() <= limited_policy.max_transaction_bytes);
            }
            assert!(
                matches!(
                    forwarder.store_signed_transaction(operation_id, &bytes),
                    Err(AppealFinanceTransactionForwarderError::InvalidSignedTransaction)
                ),
                "{label} frame must be rejected"
            );
            assert_eq!(
                forwarder.state.lock().unwrap().checkpoint,
                claimed_checkpoint,
                "{label} rejection must preserve the complete signing claim"
            );
        }
        assert_eq!(
            forwarder
                .store_signed_transaction(operation_id, &valid)
                .unwrap(),
            transaction_digest(&valid)
        );
        let pending = forwarder.pending_after(None, 1).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].state,
            AppealFinanceTransactionDeliveryStateV1::Signed
        );
        assert_eq!(pending[0].attempts, claimed_checkpoint.pending[0].attempts);
        assert_eq!(
            pending[0].signed_transaction_bytes.as_deref(),
            Some(valid.as_slice())
        );
    }
    #[test]
    fn signed_envelope_rejects_proof_and_even_empty_multisig_sidecars() {
        let forwarder = AppealFinanceTransactionForwarder::in_memory(policy()).unwrap();
        let context = drawdown_context();
        let signer = key(4);
        let authority = AccountId::new(signer.public_key().clone());
        let operation_id = forwarder
            .enqueue_unsigned_operation(authority.clone(), drawdown_operation(), &context)
            .unwrap()
            .operation_id();
        forwarder
            .claim_for_signing(operation_id, cursor(7, 7))
            .unwrap();
        let transaction_builder = || {
            TransactionBuilder::new(
                test_network_id(),
                authority.clone(),
                FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([InstructionBox::from(drawdown_operation())])
        };
        let attachments = vec![ProofAttachment::new_ref(
            "halo2/ipa".into(),
            ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
            VerifyingKeyId::new("halo2/ipa", "appeal-sidecar-vk"),
        )];
        let attached = transaction_builder()
            .with_proof_attachments(attachments)
            .expect("valid proof carriers")
            .try_sign(signer.private_key())
            .unwrap();
        assert!(attached.verify_signature().is_ok());
        assert!(matches!(
            forwarder.store_signed_transaction(operation_id, &norito::to_bytes(&attached).unwrap()),
            Err(AppealFinanceTransactionForwarderError::InvalidSignedTransaction)
        ));
        let mut empty_multisig = transaction_builder()
            .try_sign(signer.private_key())
            .unwrap();
        assert!(empty_multisig.verify_signature().is_ok());
        empty_multisig.set_multisig_signatures(MultisigSignatures::new(Vec::new()));
        assert_eq!(
            empty_multisig.verify_signature(),
            Err(
                iroha_data_model::transaction::signed::TransactionSignatureError::UnexpectedMultisigSignatures
            )
        );
        assert!(matches!(
            forwarder.store_signed_transaction(
                operation_id,
                &norito::to_bytes(&empty_multisig).unwrap()
            ),
            Err(AppealFinanceTransactionForwarderError::InvalidSignedTransaction)
        ));
        let exact = transaction_builder()
            .try_sign(signer.private_key())
            .unwrap();
        assert!(exact.attachments().is_none());
        assert!(exact.multisig_signatures().is_none());
        assert_ne!(
            forwarder
                .store_signed_transaction(operation_id, &norito::to_bytes(&exact).unwrap())
                .unwrap(),
            [0; 32]
        );
    }
    #[test]
    fn crash_recovery_preserves_attempts_and_retry_exhaustion_dead_letters() {
        let dir = TempDir::new().unwrap();
        let runtime = Arc::new(TestCheckpointRuntime::new(41));
        let context = drawdown_context();
        let operation_id = {
            let forwarder = open_durable(dir.path(), runtime.clone()).unwrap();
            let operation_id = forwarder
                .enqueue_unsigned_operation(account(4), drawdown_operation(), &context)
                .unwrap()
                .operation_id();
            forwarder
                .claim_for_signing(operation_id, cursor(7, 7))
                .unwrap();
            operation_id
        };
        let restored = open_durable(dir.path(), runtime).unwrap();
        let pending = restored.pending_after(None, 8).unwrap();
        assert_eq!(
            pending[0].state,
            AppealFinanceTransactionDeliveryStateV1::Ready
        );
        assert_eq!(pending[0].attempts, 1);
        restored
            .claim_for_signing(operation_id, cursor(8, 8))
            .unwrap();
        restored
            .mark_signing_failed(operation_id, cursor(8, 8))
            .unwrap();
        assert!(restored.pending_after(None, 8).unwrap().is_empty());
        assert_eq!(
            restored.dead_letters(8).unwrap()[0].reason,
            AppealFinanceTransactionDeadLetterReasonV1::RetryExhausted
        );
    }
    #[test]
    fn definitely_not_submitted_retries_are_bounded() {
        let forwarder = AppealFinanceTransactionForwarder::in_memory(policy()).unwrap();
        let signer = key(4);
        let operation_id = forwarder
            .enqueue_unsigned_operation(account(4), drawdown_operation(), &drawdown_context())
            .unwrap()
            .operation_id();
        forwarder
            .claim_for_signing(operation_id, cursor(7, 7))
            .unwrap();
        forwarder
            .store_signed_transaction(
                operation_id,
                &signed_bytes(&signer, account(4), drawdown_operation()),
            )
            .unwrap();
        forwarder
            .mark_retryable_submission_failed(operation_id, cursor(7, 7))
            .unwrap();
        forwarder
            .mark_retryable_submission_failed(operation_id, cursor(8, 8))
            .unwrap();
        assert!(forwarder.pending_after(None, 8).unwrap().is_empty());
        assert_eq!(
            forwarder.dead_letters(8).unwrap()[0].reason,
            AppealFinanceTransactionDeadLetterReasonV1::RetryExhausted
        );
    }
    #[test]
    fn completed_capacity_never_evicts_exactly_once_tombstones() {
        let mut bounded_policy = policy();
        bounded_policy.max_completed = 1;
        let forwarder = AppealFinanceTransactionForwarder::in_memory(bounded_policy).unwrap();
        let context = drawdown_context();
        let first = forwarder
            .enqueue_unsigned_operation(account(4), drawdown_operation(), &context)
            .unwrap()
            .operation_id();
        forwarder
            .mark_semantic_finalized(first, cursor(8, 8))
            .unwrap();
        let cancel = AppealFinanceOperationV1::Cancel(CancelAssetLock::new(
            escrow_id(),
            Quantity::from(100_u32),
        ));
        let second = forwarder
            .enqueue_unsigned_operation(account(1), cancel, &context)
            .unwrap()
            .operation_id();
        assert!(matches!(
            forwarder.mark_semantic_finalized(second, cursor(9, 9)),
            Err(AppealFinanceTransactionForwarderError::CompletedCapacityExhausted)
        ));
        assert_eq!(
            forwarder.pending_after(None, 8).unwrap()[0].operation_id,
            second,
            "capacity failure must retain the pending operation"
        );
        assert_eq!(
            forwarder
                .enqueue_unsigned_operation(account(4), drawdown_operation(), &context)
                .unwrap(),
            AppealFinanceTransactionEnqueueResultV1::Existing {
                operation_id: first
            },
            "the original completion tombstone must remain replay-safe"
        );
    }
    #[test]
    fn reconciliation_proves_each_atomic_partition_and_rejects_stale_fork() {
        let record = active_record();
        let drawdown = AppealFinanceTransactionSigningRequestV1 {
            operation_id: [1; 32],
            network_id: test_network_id(),
            chain_id: ChainId::from("appeal-finance-forwarder-test"),
            authority: account(4),
            operation: drawdown_operation(),
            expected_record: Some(record.clone()),
            reconciliation_context: vec![1],
            baseline_finalized_cursor: cursor(7, 7),
        };
        assert_eq!(
            reconcile_appeal_finance_operation_v1(&drawdown, cursor(7, 7), Some(&record)).unwrap(),
            AppealFinanceOperationReconciliationV1::Ready
        );
        let mut after_drawdown = record.clone();
        after_drawdown.remaining_amount = Quantity::from(40_u32);
        assert_eq!(
            reconcile_appeal_finance_operation_v1(&drawdown, cursor(8, 8), Some(&after_drawdown))
                .unwrap(),
            AppealFinanceOperationReconciliationV1::Finalized
        );
        let mut substituted_lifecycle = after_drawdown.clone();
        substituted_lifecycle.accepted_at_ms = Some(8);
        assert_eq!(
            reconcile_appeal_finance_operation_v1(
                &drawdown,
                cursor(8, 8),
                Some(&substituted_lifecycle)
            )
            .unwrap(),
            AppealFinanceOperationReconciliationV1::Conflict
        );
        let cancel = AppealFinanceTransactionSigningRequestV1 {
            operation_id: [2; 32],
            network_id: drawdown.network_id,
            chain_id: drawdown.chain_id.clone(),
            authority: record.seller.clone(),
            operation: AppealFinanceOperationV1::Cancel(CancelAssetLock::new(
                record.id,
                Quantity::from(40_u32),
            )),
            expected_record: Some(after_drawdown.clone()),
            reconciliation_context: vec![2],
            baseline_finalized_cursor: cursor(8, 8),
        };
        let mut after_cancel = after_drawdown;
        after_cancel.status = AssetEscrowStatus::Cancelled;
        after_cancel.remaining_amount = Quantity::zero();
        after_cancel.closed_at_ms = Some(9);
        assert_eq!(
            reconcile_appeal_finance_operation_v1(&cancel, cursor(9, 9), Some(&after_cancel))
                .unwrap(),
            AppealFinanceOperationReconciliationV1::Finalized
        );
        assert!(matches!(
            reconcile_appeal_finance_operation_v1(&cancel, cursor(8, 9), Some(&after_cancel)),
            Err(AppealFinanceTransactionForwarderError::StaleFinalizedCursor)
        ));
        let mut forged_expected = record;
        forged_expected.closed_at_ms = Some(7);
        let forged = AppealFinanceTransactionSigningRequestV1 {
            operation_id: [3; 32],
            network_id: drawdown.network_id,
            chain_id: drawdown.chain_id,
            authority: account(4),
            operation: drawdown_operation(),
            expected_record: Some(forged_expected),
            reconciliation_context: vec![3],
            baseline_finalized_cursor: cursor(7, 7),
        };
        assert!(matches!(
            reconcile_appeal_finance_operation_v1(&forged, cursor(7, 7), None),
            Err(AppealFinanceTransactionForwarderError::InvalidOperation)
        ));
    }
    #[test]
    fn stale_same_height_fork_is_dead_lettered_without_signing() {
        let forwarder = AppealFinanceTransactionForwarder::in_memory(policy()).unwrap();
        let operation_id = forwarder
            .enqueue_unsigned_operation(account(4), drawdown_operation(), &drawdown_context())
            .unwrap()
            .operation_id();
        forwarder
            .mark_stale_finalized_cursor(operation_id, cursor(7, 9))
            .unwrap();
        assert!(forwarder.pending_after(None, 8).unwrap().is_empty());
        assert_eq!(
            forwarder.dead_letters(8).unwrap()[0].reason,
            AppealFinanceTransactionDeadLetterReasonV1::StaleFinalizedCursor
        );
    }
    #[test]
    fn superseded_policy_and_invalid_context_are_distinct_terminal_reasons() {
        let superseded = AppealFinanceTransactionForwarder::in_memory(policy()).unwrap();
        let superseded_id = superseded
            .enqueue_unsigned_operation(account(4), drawdown_operation(), &drawdown_context())
            .unwrap()
            .operation_id();
        superseded
            .mark_policy_superseded(superseded_id, cursor(8, 8))
            .unwrap();
        assert!(superseded.pending_after(None, 8).unwrap().is_empty());
        assert_eq!(
            superseded.dead_letters(8).unwrap()[0].reason,
            AppealFinanceTransactionDeadLetterReasonV1::PolicySuperseded
        );
        let invalid = AppealFinanceTransactionForwarder::in_memory(policy()).unwrap();
        let invalid_id = invalid
            .enqueue_unsigned_operation(account(4), drawdown_operation(), &drawdown_context())
            .unwrap()
            .operation_id();
        invalid
            .mark_invalid_context(invalid_id, cursor(8, 9))
            .unwrap();
        assert!(invalid.pending_after(None, 8).unwrap().is_empty());
        assert_eq!(
            invalid.dead_letters(8).unwrap()[0].reason,
            AppealFinanceTransactionDeadLetterReasonV1::InvalidContext
        );
    }
    #[test]
    fn inactive_signer_binding_is_a_payload_free_terminal_reason() {
        let forwarder = AppealFinanceTransactionForwarder::in_memory(policy()).unwrap();
        let operation_id = forwarder
            .enqueue_unsigned_operation(account(4), drawdown_operation(), &drawdown_context())
            .unwrap()
            .operation_id();
        let observed_cursor = cursor(8, 10);
        forwarder
            .mark_signer_binding_inactive(operation_id, observed_cursor)
            .unwrap();
        assert!(forwarder.pending_after(None, 8).unwrap().is_empty());
        let dead_letters = forwarder.dead_letters(8).unwrap();
        assert_eq!(dead_letters.len(), 1);
        assert_eq!(dead_letters[0].operation_id, operation_id);
        assert_eq!(
            dead_letters[0].kind,
            AppealFinanceTransactionKindV1::Drawdown
        );
        assert_eq!(
            dead_letters[0].reason,
            AppealFinanceTransactionDeadLetterReasonV1::SignerBindingInactive
        );
        assert_eq!(
            dead_letters[0].observed_finalized_height,
            observed_cursor.height
        );
        assert_eq!(
            dead_letters[0].observed_finalized_block_hash,
            observed_cursor.block_hash
        );
    }
    #[test]
    fn poisoned_checkpoint_fails_closed() {
        let dir = TempDir::new().unwrap();
        let runtime = Arc::new(TestCheckpointRuntime::new(42));
        let forwarder = open_durable(dir.path(), runtime.clone()).unwrap();
        forwarder
            .enqueue_unsigned_operation(account(4), drawdown_operation(), &drawdown_context())
            .unwrap();
        drop(forwarder);
        std::fs::write(checkpoint_path(dir.path()), b"not canonical norito").unwrap();
        assert!(matches!(
            open_durable(dir.path(), runtime),
            Err(AppealFinanceTransactionForwarderError::InvalidAuthenticatedCheckpoint)
        ));
    }
    #[test]
    fn sealed_checkpoint_record_has_one_bounded_canonical_persistence_format() {
        let dir = TempDir::new().unwrap();
        let runtime = Arc::new(TestCheckpointRuntime::new(49));
        let forwarder = open_durable(dir.path(), runtime.clone()).unwrap();
        drop(forwarder);
        let record = runtime.load_latest().unwrap().unwrap();
        let bytes = record
            .to_canonical_bytes(policy().checkpoint_max_bytes)
            .unwrap();
        assert_eq!(
            AppealFinanceSealedCheckpointRecordV1::from_canonical_bytes(
                &bytes,
                policy().checkpoint_max_bytes,
            )
            .unwrap(),
            record
        );
        assert_eq!(
            crate::frame_test_support::assert_current_frame(
                &record,
                "sorafs_node::appeal_finance_transaction_forwarder::AppealFinanceSealedCheckpointRecordV1"
            ),
            bytes
        );
        let authenticated = decode_authenticated_checkpoint(
            &record.checkpoint_bytes,
            policy(),
            &runtime.authentication_policy(),
        )
        .expect("production authenticated checkpoint");
        crate::frame_test_support::assert_current_frame(
            &authenticated,
            "sorafs_node::appeal_finance_transaction_forwarder::AuthenticatedCheckpointV1",
        );
        crate::frame_test_support::assert_current_frame(
            &authenticated.body,
            "sorafs_node::appeal_finance_transaction_forwarder::CheckpointBodyV1",
        );
        assert_eq!(
            <PreparedOperationMaterialV1 as norito::NoritoSchema>::frame_name(),
            "sorafs_node::appeal_finance_transaction_forwarder::PreparedOperationMaterialV1"
        );
        assert_eq!(
            <DrawdownIdentityMaterialV1 as norito::NoritoSchema>::frame_name(),
            "sorafs_node::appeal_finance_transaction_forwarder::DrawdownIdentityMaterialV1"
        );
        let mut substituted = record;
        substituted.revision[0] ^= 0x80;
        let substituted_bytes = norito::to_bytes(&substituted).unwrap();
        assert!(matches!(
            AppealFinanceSealedCheckpointRecordV1::from_canonical_bytes(
                &substituted_bytes,
                policy().checkpoint_max_bytes,
            ),
            Err(AppealFinanceTransactionForwarderError::InvalidSealedCheckpoint)
        ));
    }
    #[test]
    fn signed_checkpoint_tamper_fails_closed() {
        let dir = TempDir::new().unwrap();
        let runtime = Arc::new(TestCheckpointRuntime::new(43));
        let authentication_policy = runtime.authentication_policy();
        let forwarder = open_durable(dir.path(), runtime.clone()).unwrap();
        forwarder
            .enqueue_unsigned_operation(account(4), drawdown_operation(), &drawdown_context())
            .unwrap();
        drop(forwarder);
        let bytes = std::fs::read(checkpoint_path(dir.path())).unwrap();
        let mut checkpoint =
            decode_authenticated_checkpoint(&bytes, policy(), &authentication_policy).unwrap();
        checkpoint.signature[0] ^= 0x80;
        std::fs::write(
            checkpoint_path(dir.path()),
            norito::to_bytes(&checkpoint).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            open_durable(dir.path(), runtime),
            Err(AppealFinanceTransactionForwarderError::InvalidAuthenticatedCheckpoint)
        ));
    }
    #[test]
    fn missing_or_rolled_back_sealed_head_fails_closed() {
        let dir = TempDir::new().unwrap();
        let runtime = Arc::new(TestCheckpointRuntime::new(44));
        let forwarder = open_durable(dir.path(), runtime.clone()).unwrap();
        forwarder
            .enqueue_unsigned_operation(account(4), drawdown_operation(), &drawdown_context())
            .unwrap();
        drop(forwarder);
        runtime.replace_latest(None);
        assert!(matches!(
            open_durable(dir.path(), runtime),
            Err(AppealFinanceTransactionForwarderError::CheckpointRollback)
        ));
    }
    #[test]
    fn validly_signed_same_sequence_substitution_is_a_fork() {
        let dir = TempDir::new().unwrap();
        let runtime = Arc::new(TestCheckpointRuntime::new(45));
        let authentication_policy = runtime.authentication_policy();
        let forwarder = open_durable(dir.path(), runtime.clone()).unwrap();
        forwarder
            .enqueue_unsigned_operation(account(4), drawdown_operation(), &drawdown_context())
            .unwrap();
        drop(forwarder);
        let bytes = std::fs::read(checkpoint_path(dir.path())).unwrap();
        let checkpoint =
            decode_authenticated_checkpoint(&bytes, policy(), &authentication_policy).unwrap();
        let mut substituted_body = checkpoint.body.clone();
        substituted_body.next_sequence = substituted_body.next_sequence.checked_add(1).unwrap();
        let substituted = sign_authenticated_checkpoint(
            substituted_body,
            checkpoint.checkpoint_sequence,
            checkpoint.predecessor_checkpoint_digest,
            policy(),
            &authentication_policy,
            runtime.as_ref(),
        )
        .unwrap();
        let substituted_bytes =
            encode_authenticated_checkpoint(&substituted, policy(), &authentication_policy)
                .unwrap();
        runtime.replace_latest(Some(AppealFinanceSealedCheckpointRecordV1::new(
            substituted.checkpoint_sequence,
            substituted.checkpoint_digest,
            substituted_bytes,
        )));
        assert!(matches!(
            open_durable(dir.path(), runtime),
            Err(AppealFinanceTransactionForwarderError::CheckpointFork)
        ));
    }
    #[test]
    fn crash_after_seal_before_local_rename_recovers_exact_head() {
        let dir = TempDir::new().unwrap();
        let runtime = Arc::new(TestCheckpointRuntime::new(46));
        let authentication_policy = runtime.authentication_policy();
        let forwarder = open_durable(dir.path(), runtime.clone()).unwrap();
        forwarder
            .enqueue_unsigned_operation(account(4), drawdown_operation(), &drawdown_context())
            .unwrap();
        drop(forwarder);
        let local_bytes = std::fs::read(checkpoint_path(dir.path())).unwrap();
        let local = decode_authenticated_checkpoint(&local_bytes, policy(), &authentication_policy)
            .unwrap();
        let next = sign_authenticated_checkpoint(
            local.body.clone(),
            local.checkpoint_sequence.checked_add(1).unwrap(),
            Some(local.checkpoint_digest),
            policy(),
            &authentication_policy,
            runtime.as_ref(),
        )
        .unwrap();
        let next_bytes =
            encode_authenticated_checkpoint(&next, policy(), &authentication_policy).unwrap();
        let next_record = AppealFinanceSealedCheckpointRecordV1::new(
            next.checkpoint_sequence,
            next.checkpoint_digest,
            next_bytes.clone(),
        );
        let current = runtime.load_latest().unwrap().unwrap();
        runtime
            .compare_and_swap_latest(Some(current.revision), &next_record)
            .unwrap();
        let restored = open_durable(dir.path(), runtime).unwrap();
        assert_eq!(
            std::fs::read(checkpoint_path(dir.path())).unwrap(),
            next_bytes
        );
        assert_eq!(restored.pending_after(None, 8).unwrap().len(), 1);
    }
    #[test]
    fn substituted_runtime_identity_is_rejected_before_state_access() {
        let dir = TempDir::new().unwrap();
        let configured_runtime = Arc::new(TestCheckpointRuntime::new(47));
        let substituted_runtime = Arc::new(TestCheckpointRuntime::new(48));
        assert!(matches!(
            AppealFinanceTransactionForwarder::open(
                dir.path(),
                policy(),
                configured_runtime.authentication_policy(),
                substituted_runtime,
            ),
            Err(AppealFinanceTransactionForwarderError::CheckpointRuntimeIdentityMismatch)
        ));
        assert!(!checkpoint_path(dir.path()).exists());
    }
    #[test]
    fn test_marked_checkpoint_provider_is_rejected_before_state_access() {
        let dir = TempDir::new().unwrap();
        let runtime = Arc::new(TestCheckpointRuntime::new(50));
        let mut authentication_policy = runtime.authentication_policy();
        authentication_policy.provider_handle = "provider:dummy:appeal-finance".to_owned();
        assert!(matches!(
            AppealFinanceTransactionForwarder::open(
                dir.path(),
                policy(),
                authentication_policy,
                runtime,
            ),
            Err(AppealFinanceTransactionForwarderError::InvalidCheckpointAuthenticationPolicy)
        ));
        assert!(!checkpoint_path(dir.path()).exists());
    }
    #[test]
    fn checkpoint_provider_handles_use_central_production_grammar() {
        let runtime = TestCheckpointRuntime::new(49);
        let mut authentication_policy = runtime.authentication_policy();
        authentication_policy.provider_handle =
            "provider://appeal-finance/checkpoint.primary-v1_slot-a".to_owned();
        authentication_policy
            .validate()
            .expect("canonical production provider handle");
        for handle in [
            "https://operator:secret@checkpoint",
            "https://checkpoint/path?credential=secret",
            "https://checkpoint/path#fragment",
            "provider://appeal-finance/%63heckpoint",
            "provider:\\appeal-finance\\checkpoint",
        ] {
            authentication_policy.provider_handle = handle.to_owned();
            assert!(matches!(
                authentication_policy.validate(),
                Err(AppealFinanceTransactionForwarderError::InvalidCheckpointAuthenticationPolicy)
            ));
        }
    }
    #[test]
    fn qualification_drift_discards_candidate_before_durable_state_changes() {
        let dir = TempDir::new().unwrap();
        let runtime = Arc::new(TestCheckpointRuntime::new(51));
        let forwarder = open_durable(dir.path(), runtime.clone()).unwrap();
        let checkpoint_before = std::fs::read(checkpoint_path(dir.path())).unwrap();
        let sealed_before = runtime.load_latest().unwrap();
        runtime.replace_qualification(AppealFinanceRuntimeProviderQualificationV1::new(
            2, [0xA5; 32],
        ));
        assert!(matches!(
            forwarder.enqueue_unsigned_operation(
                account(4),
                drawdown_operation(),
                &drawdown_context(),
            ),
            Err(AppealFinanceTransactionForwarderError::CheckpointRuntimeIdentityMismatch)
        ));
        assert!(forwarder.pending_after(None, 8).unwrap().is_empty());
        assert_eq!(
            std::fs::read(checkpoint_path(dir.path())).unwrap(),
            checkpoint_before
        );
        assert_eq!(runtime.load_latest().unwrap(), sealed_before);
    }
    #[test]
    fn post_sign_qualification_drift_discards_checkpoint_signature() {
        let dir = TempDir::new().unwrap();
        let runtime = Arc::new(TestCheckpointRuntime::new(52));
        let forwarder = open_durable(dir.path(), runtime.clone()).unwrap();
        let checkpoint_before = std::fs::read(checkpoint_path(dir.path())).unwrap();
        let sealed_before = runtime.load_latest().unwrap();
        runtime.replace_qualification_after_next_sign(
            AppealFinanceRuntimeProviderQualificationV1::new(2, [0xA6; 32]),
        );
        assert!(matches!(
            forwarder.enqueue_unsigned_operation(
                account(4),
                drawdown_operation(),
                &drawdown_context(),
            ),
            Err(AppealFinanceTransactionForwarderError::CheckpointRuntimeIdentityMismatch)
        ));
        assert!(forwarder.pending_after(None, 8).unwrap().is_empty());
        assert_eq!(
            std::fs::read(checkpoint_path(dir.path())).unwrap(),
            checkpoint_before
        );
        assert_eq!(runtime.load_latest().unwrap(), sealed_before);
    }
    #[test]
    fn post_compare_and_swap_qualification_drift_is_ambiguous() {
        let dir = TempDir::new().unwrap();
        let runtime = Arc::new(TestCheckpointRuntime::new(53));
        let forwarder = open_durable(dir.path(), runtime.clone()).unwrap();
        let checkpoint_before = std::fs::read(checkpoint_path(dir.path())).unwrap();
        let sealed_before = runtime.load_latest().unwrap().unwrap();
        runtime.replace_qualification_after_next_compare_and_swap(
            AppealFinanceRuntimeProviderQualificationV1::new(2, [0xA7; 32]),
        );
        assert!(matches!(
            forwarder.enqueue_unsigned_operation(
                account(4),
                drawdown_operation(),
                &drawdown_context(),
            ),
            Err(AppealFinanceTransactionForwarderError::CheckpointAuthenticationAmbiguous)
        ));
        assert!(forwarder.pending_after(None, 8).unwrap().is_empty());
        assert_eq!(
            std::fs::read(checkpoint_path(dir.path())).unwrap(),
            checkpoint_before
        );
        let sealed_after = runtime.load_latest().unwrap().unwrap();
        assert_eq!(
            sealed_after.checkpoint_sequence,
            sealed_before.checkpoint_sequence + 1
        );
        assert_ne!(sealed_after.revision, sealed_before.revision);
    }
}
