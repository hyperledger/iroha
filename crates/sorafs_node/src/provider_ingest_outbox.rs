//! Durable, payload-free state machine for finalized-ledger provider ingest.
//!
//! The checkpoint deliberately excludes payload bytes, staging paths, source URLs, credentials, and
//! signer material. It retains the immutable ledger binding, source-delivery crash state, and the
//! exact signed completion transaction required for reconciliation.

use crate::provider_ingest_runtime::{
    ProviderIngestVerifiedMusubiBundleReceiptV1, StoredProviderIngestVerifiedMusubiBundleReceiptV1,
};
use crate::{
    durable_transaction_forwarder::{
        self as durable, DeliveryRecord, DeliveryTransitionError, FinalizedCursorV1,
        RetryBoundOutcome, StoredDeliveryStateV1,
    },
    read_local_checkpoint_bounded, write_local_checkpoint_atomic_bounded,
};
use iroha_config::parameters::{
    defaults::sorafs::storage::provider_ingest_runtime::outbox as provider_ingest_outbox_defaults,
    is_production_runtime_handle,
};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    isi::sorafs::CompleteReplicationOrder,
    musubi::ArchiveId,
    sorafs::pin_registry::{
        ManifestRootCid, ProviderIngestCompletionAuthorityV1, ProviderIngestFinalizedAnchorV1,
    },
    transaction::{Executable, SignedTransaction, TransactionPayload},
};
use norito::derive::{NoritoDeserialize, NoritoSerialize};
#[cfg(unix)]
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::{
    collections::{BTreeSet, BinaryHeap},
    fmt,
    fs::{self, File},
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;
// Internal persisted-layout revision. The product/wire contract remains V1,
// while pre-release checkpoint layouts are intentionally rejected and reseeded.
const PROVIDER_INGEST_OUTBOX_LAYOUT_VERSION_V5: u8 = 5;
const PROVIDER_INGEST_CHECKPOINT_MAGIC_V5: [u8; 16] = *b"SORAFSINGESTV5\0\0";
const PROVIDER_INGEST_JOB_ID_DOMAIN_V1: &[u8] = b"sorafs.provider.ingest.job.v1\0";
const PROVIDER_INGEST_LEASE_TOKEN_DOMAIN_V1: &[u8] = b"sorafs.provider.ingest.source-lease.v1\0";
const PROVIDER_INGEST_SIGNING_TOKEN_DOMAIN_V1: &[u8] =
    b"sorafs.provider.ingest.completion-signing.v1\0";
const PROVIDER_INGEST_OUTBOX_LOCK_SUFFIX_V1: &str = ".lock";
const PROVIDER_INGEST_CHECKPOINT_PROVIDER_QUALIFICATION_VERSION_V1: u8 = 1;
const PROVIDER_INGEST_SEALED_CHECKPOINT_RECORD_VERSION_V1: u8 = 1;
const PROVIDER_INGEST_SEALED_CHECKPOINT_NAMESPACE_V1: [u8; 32] =
    *b"sorafs.provider.ingest.outbox.v1";
const PROVIDER_INGEST_SEALED_CHECKPOINT_REVISION_DOMAIN_V1: &[u8] =
    b"sorafs.provider.ingest.sealed-checkpoint.revision.v1\0";
/// Maximum canonical sealed-record bytes surrounding one provider-ingest checkpoint.
///
/// Runtime transports use this public V1 bound in addition to the configured checkpoint limit so a
/// maximum-sized valid record is never rejected at the deployment-provider boundary.
pub const PROVIDER_INGEST_SEALED_CHECKPOINT_RECORD_MAX_OVERHEAD_BYTES_V1: u64 = 1_024;
const PROVIDER_INGEST_CHECKPOINT_REQUEST_CAPACITY_V1: usize = 1;
const PROVIDER_INGEST_CHECKPOINT_OPERATION_TIMEOUT_MAX_MS_V1: u64 = 24 * 60 * 60 * 1_000;
const MAX_CHUNKER_HANDLE_BYTES_V1: usize = 128;
const MAX_MANIFEST_ID_BYTES_V1: usize = 128;
static PROVIDER_INGEST_PROCESS_LOCKS: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());
/// File name used for the provider-ingest outbox checkpoint.
pub const PROVIDER_INGEST_OUTBOX_FILE_V1: &str = "provider_ingest_outbox_v1.to";
/// Protocol ceiling for one payload-free status page.
pub const PROVIDER_INGEST_STATUS_PAGE_MAX_V1: usize = 1_000;
/// Non-secret configured identity of the production sealed checkpoint store.
///
/// Credentials, authentication tokens, private keys, and vendor diagnostics
/// are runtime-only and are never represented by this binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestCheckpointProviderBindingV1 {
    /// Stable opaque deployment handle.
    pub handle: String,
    /// Exact non-zero adapter and public-policy revision.
    pub revision: u64,
    /// Exact non-zero digest of the provider's public policy.
    pub policy_digest: [u8; 32],
}
impl ProviderIngestCheckpointProviderBindingV1 {
    /// Return the exact qualification required from the injected provider.
    #[must_use]
    pub const fn qualification(&self) -> ProviderIngestCheckpointProviderQualificationV1 {
        ProviderIngestCheckpointProviderQualificationV1::new(self.revision, self.policy_digest)
    }
    /// Validate the complete canonical finalized authorization binding.
    ///
    /// This is exposed for authenticated runtime boundaries that decode the
    /// authorization outside the outbox crate and must reject substituted or
    /// noncanonical job identities before performing I/O.
    pub fn validate(&self) -> Result<(), ProviderIngestOutboxError> {
        validate_provider_ingest_runtime_handle(&self.handle)?;
        self.qualification().validate()
    }
}
/// Payload-free public qualification returned by the sealed checkpoint store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderIngestCheckpointProviderQualificationV1 {
    /// Qualification schema version.
    pub version: u8,
    /// Non-zero adapter and public-policy revision.
    pub revision: u64,
    /// Non-zero digest of the exact public provider policy.
    pub policy_digest: [u8; 32],
}
impl ProviderIngestCheckpointProviderQualificationV1 {
    /// Construct a first-release provider qualification.
    #[must_use]
    pub const fn new(revision: u64, policy_digest: [u8; 32]) -> Self {
        Self {
            version: PROVIDER_INGEST_CHECKPOINT_PROVIDER_QUALIFICATION_VERSION_V1,
            revision,
            policy_digest,
        }
    }
    /// Validate the qualification schema and non-zero binding.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema or zero revision/digest.
    pub fn validate(self) -> Result<(), ProviderIngestOutboxError> {
        if self.version != PROVIDER_INGEST_CHECKPOINT_PROVIDER_QUALIFICATION_VERSION_V1
            || self.revision == 0
            || self.policy_digest == [0; 32]
        {
            return Err(ProviderIngestOutboxError::InvalidCheckpointProviderBinding);
        }
        Ok(())
    }
}
/// Fixed payload-free failure classes returned by an external sealed store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderIngestCheckpointExternalErrorV1 {
    /// The external store is unavailable.
    Unavailable,
    /// The external store rejected the exact request.
    Rejected,
    /// A compare-and-swap may have committed and requires authoritative readback.
    Ambiguous,
}
/// Canonical external authority record for one provider-ingest checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "sorafs_node::provider_ingest_outbox::ProviderIngestSealedCheckpointRecordV1"
)]
pub struct ProviderIngestSealedCheckpointRecordV1 {
    /// Fixed provider-ingest checkpoint namespace.
    pub namespace: [u8; 32],
    /// Record schema version.
    pub version: u8,
    /// Monotonic sequence of the authoritative checkpoint.
    pub checkpoint_sequence: u64,
    /// Exact predecessor CAS revision, absent only for sequence one.
    pub predecessor_revision: Option<[u8; 32]>,
    /// Exact predecessor checkpoint digest, absent only for sequence one.
    pub predecessor_checkpoint_digest: Option<[u8; 32]>,
    /// Digest of the exact canonical checkpoint bytes.
    pub checkpoint_digest: [u8; 32],
    /// Exact canonical bounded provider-ingest checkpoint.
    pub checkpoint_bytes: Vec<u8>,
    /// Deterministic content-addressed compare-and-swap revision.
    pub revision: [u8; 32],
}
impl ProviderIngestSealedCheckpointRecordV1 {
    fn new(
        checkpoint_sequence: u64,
        predecessor_revision: Option<[u8; 32]>,
        predecessor_checkpoint_digest: Option<[u8; 32]>,
        checkpoint_bytes: Vec<u8>,
    ) -> Self {
        let checkpoint_digest = *blake3::hash(&checkpoint_bytes).as_bytes();
        let mut record = Self {
            namespace: PROVIDER_INGEST_SEALED_CHECKPOINT_NAMESPACE_V1,
            version: PROVIDER_INGEST_SEALED_CHECKPOINT_RECORD_VERSION_V1,
            checkpoint_sequence,
            predecessor_revision,
            predecessor_checkpoint_digest,
            checkpoint_digest,
            checkpoint_bytes,
            revision: [0; 32],
        };
        record.revision = provider_ingest_sealed_checkpoint_revision(&record);
        record
    }
    /// Validate namespace, schema, lineage, bounds, bytes, and deterministic revision.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, oversized, substituted, or noncanonical state.
    pub fn validate(&self, checkpoint_max_bytes: u64) -> Result<(), ProviderIngestOutboxError> {
        let valid_lineage = if self.checkpoint_sequence == 1 {
            self.predecessor_revision.is_none() && self.predecessor_checkpoint_digest.is_none()
        } else {
            self.predecessor_revision
                .is_some_and(|revision| revision != [0; 32])
                && self
                    .predecessor_checkpoint_digest
                    .is_some_and(|digest| digest != [0; 32])
        };
        if checkpoint_max_bytes == 0
            || self.namespace != PROVIDER_INGEST_SEALED_CHECKPOINT_NAMESPACE_V1
            || self.version != PROVIDER_INGEST_SEALED_CHECKPOINT_RECORD_VERSION_V1
            || self.checkpoint_sequence == 0
            || !valid_lineage
            || self.checkpoint_bytes.is_empty()
            || u64::try_from(self.checkpoint_bytes.len()).unwrap_or(u64::MAX) > checkpoint_max_bytes
            || self.checkpoint_digest == [0; 32]
            || self.checkpoint_digest != *blake3::hash(&self.checkpoint_bytes).as_bytes()
            || self.revision != provider_ingest_sealed_checkpoint_revision(self)
        {
            return Err(ProviderIngestOutboxError::InvalidSealedCheckpoint);
        }
        Ok(())
    }
    /// Encode the exact bounded canonical Norito record used by the provider and cache.
    ///
    /// # Errors
    ///
    /// Returns an error when validation, encoding, or the byte bound fails.
    pub fn to_canonical_bytes(
        &self,
        checkpoint_max_bytes: u64,
    ) -> Result<Vec<u8>, ProviderIngestOutboxError> {
        self.validate(checkpoint_max_bytes)?;
        let max_record_bytes =
            provider_ingest_sealed_checkpoint_record_max_bytes(checkpoint_max_bytes)?;
        let bytes = norito::encode_canonical(self)
            .map_err(|error| ProviderIngestOutboxError::CanonicalEncoding(error.to_string()))?;
        if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_record_bytes {
            return Err(ProviderIngestOutboxError::InvalidSealedCheckpoint);
        }
        Ok(bytes)
    }
    /// Decode one exact bounded canonical record from sealed storage or local cache.
    ///
    /// # Errors
    ///
    /// Returns an error before installation for oversized, malformed,
    /// noncanonical, or substituted bytes.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        checkpoint_max_bytes: u64,
    ) -> Result<Self, ProviderIngestOutboxError> {
        let max_record_bytes =
            provider_ingest_sealed_checkpoint_record_max_bytes(checkpoint_max_bytes)?;
        if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_record_bytes {
            return Err(ProviderIngestOutboxError::InvalidSealedCheckpoint);
        }
        let element_limit = bytes
            .len()
            .checked_mul(4)
            .ok_or(ProviderIngestOutboxError::CheckpointTooLarge)?
            .max(1);
        let record: Self =
            crate::decode_local_checkpoint_canonical(bytes, max_record_bytes, element_limit)
                .map_err(|_| ProviderIngestOutboxError::InvalidSealedCheckpoint)?;
        record.validate(checkpoint_max_bytes)?;
        Ok(record)
    }
}
/// Runtime-only sealed, monotonic provider-ingest checkpoint authority.
///
/// Implementations must preserve exact canonical records across restarts and
/// enforce a linearizable compare-and-swap over `revision`. Credentials and
/// private provider state must never be exposed through this trait.
pub trait ProviderIngestCheckpointRuntimeV1: Send + Sync + fmt::Debug {
    /// Return the stable opaque production handle.
    fn handle(&self) -> &str;
    /// Return the current payload-free provider qualification.
    ///
    /// # Errors
    ///
    /// Returns a fixed payload-free provider failure.
    fn qualification(
        &self,
    ) -> Result<
        ProviderIngestCheckpointProviderQualificationV1,
        ProviderIngestCheckpointExternalErrorV1,
    >;
    /// Load the exact latest authoritative record.
    ///
    /// # Errors
    ///
    /// Returns a fixed payload-free provider failure.
    fn load_latest(
        &self,
    ) -> Result<
        Option<ProviderIngestSealedCheckpointRecordV1>,
        ProviderIngestCheckpointExternalErrorV1,
    >;
    /// Replace the exact latest record if its deterministic revision is unchanged.
    ///
    /// A write whose commit outcome is unknown must return
    /// [`ProviderIngestCheckpointExternalErrorV1::Ambiguous`].
    ///
    /// # Errors
    ///
    /// Returns a fixed payload-free provider failure.
    fn compare_and_swap_latest(
        &self,
        expected_revision: Option<[u8; 32]>,
        next: &ProviderIngestSealedCheckpointRecordV1,
    ) -> Result<(), ProviderIngestCheckpointExternalErrorV1>;
}
/// Finalized block identity used by provider-ingest reconciliation.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, NoritoSerialize, NoritoDeserialize,
)]
pub struct ProviderIngestFinalizedCursorV1 {
    /// Finalized block height.
    pub height: u64,
    /// Finalized block hash at `height`.
    pub block_hash: [u8; 32],
}
impl ProviderIngestFinalizedCursorV1 {
    fn validate(self) -> Result<(), ProviderIngestOutboxError> {
        if self.height == 0 || self.block_hash == [0; 32] {
            return Err(ProviderIngestOutboxError::InvalidFinalizedCursor);
        }
        Ok(())
    }
}
/// Dedicated bounded policy for the provider-ingest outbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderIngestOutboxPolicyV1 {
    /// Maximum non-terminal jobs. Active work is never pruned.
    pub max_active_entries: usize,
    /// Maximum retained terminal tombstones.
    pub max_terminal_entries: usize,
    /// Maximum failures or completion delivery attempts.
    pub max_attempts: u32,
    /// Maximum canonical checkpoint bytes.
    pub checkpoint_max_bytes: u64,
    /// Deadline for one external sealed-checkpoint operation, in milliseconds.
    pub checkpoint_operation_timeout_ms: u64,
    /// Source-claim lease duration in milliseconds.
    pub source_lease_ttl_ms: u64,
    /// Initial retry delay in milliseconds.
    pub retry_base_delay_ms: u64,
    /// Maximum retry delay in milliseconds.
    pub retry_max_delay_ms: u64,
    /// Maximum finalized-block age of a terminal tombstone.
    pub terminal_retention_blocks: u64,
    /// Maximum canonical bytes for one retained signed completion transaction.
    pub max_signed_transaction_bytes: u64,
    /// Maximum rows returned by one status page.
    pub max_status_page_size: usize,
}
impl Default for ProviderIngestOutboxPolicyV1 {
    fn default() -> Self {
        Self {
            max_active_entries: provider_ingest_outbox_defaults::MAX_ACTIVE_ENTRIES,
            max_terminal_entries: provider_ingest_outbox_defaults::MAX_TERMINAL_ENTRIES,
            max_attempts: provider_ingest_outbox_defaults::MAX_ATTEMPTS,
            checkpoint_max_bytes: provider_ingest_outbox_defaults::CHECKPOINT_MAX_BYTES.0,
            checkpoint_operation_timeout_ms:
                provider_ingest_outbox_defaults::CHECKPOINT_OPERATION_TIMEOUT_MS,
            source_lease_ttl_ms: provider_ingest_outbox_defaults::SOURCE_LEASE_TTL_MS,
            retry_base_delay_ms: provider_ingest_outbox_defaults::RETRY_BASE_DELAY_MS,
            retry_max_delay_ms: provider_ingest_outbox_defaults::RETRY_MAX_DELAY_MS,
            terminal_retention_blocks: provider_ingest_outbox_defaults::TERMINAL_RETENTION_BLOCKS,
            max_signed_transaction_bytes:
                provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES.0,
            max_status_page_size: provider_ingest_outbox_defaults::MAX_STATUS_PAGE_SIZE,
        }
    }
}
impl ProviderIngestOutboxPolicyV1 {
    /// Validate all first-release resource and timing bounds.
    pub fn validate(self) -> Result<(), ProviderIngestOutboxError> {
        let max_checkpoint_usize = usize::try_from(self.checkpoint_max_bytes)
            .map_err(|_| ProviderIngestOutboxError::InvalidPolicy)?;
        let entry_capacity = self
            .max_active_entries
            .checked_add(self.max_terminal_entries)
            .ok_or(ProviderIngestOutboxError::InvalidPolicy)?;
        let worst_case_checkpoint_bytes =
            provider_ingest_outbox_defaults::worst_case_checkpoint_bytes_v1(
                self.max_active_entries,
                self.max_terminal_entries,
                self.max_signed_transaction_bytes,
            )
            .ok_or(ProviderIngestOutboxError::InvalidPolicy)?;
        if self.max_active_entries == 0
            || self.max_terminal_entries == 0
            || self.max_attempts == 0
            || self.checkpoint_max_bytes == 0
            || self.checkpoint_max_bytes
                > provider_ingest_outbox_defaults::CHECKPOINT_MAX_BYTES_LIMIT
            || self.checkpoint_operation_timeout_ms == 0
            || self.checkpoint_operation_timeout_ms
                > PROVIDER_INGEST_CHECKPOINT_OPERATION_TIMEOUT_MAX_MS_V1
            || self.source_lease_ttl_ms == 0
            || self.source_lease_ttl_ms.checked_mul(2).is_none()
            || self.retry_base_delay_ms == 0
            || self.retry_max_delay_ms < self.retry_base_delay_ms
            || self.terminal_retention_blocks == 0
            || self.max_signed_transaction_bytes
                < provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES_MIN
            || self.max_signed_transaction_bytes
                > provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES_LIMIT
            || self.max_signed_transaction_bytes > self.checkpoint_max_bytes
            || self.max_status_page_size == 0
            || self.max_status_page_size > PROVIDER_INGEST_STATUS_PAGE_MAX_V1
            || entry_capacity > max_checkpoint_usize
            || worst_case_checkpoint_bytes > self.checkpoint_max_bytes
        {
            return Err(ProviderIngestOutboxError::InvalidPolicy);
        }
        Ok(())
    }
}
/// Payload-free retry classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub enum ProviderIngestFailureClassV1 {
    /// No admitted source was reachable.
    SourceUnavailable,
    /// A source returned malformed or cryptographically mismatched material.
    SourceRejected,
    /// A source worker lost its durable lease before committing a result.
    LeaseExpired,
    /// Local storage returned a retryable failure.
    StorageRejected,
    /// The runtime signer was temporarily unavailable.
    SignerUnavailable,
    /// Fee quoting or exact completion-payload construction failed.
    PayloadPreparationFailed,
    /// The queue definitely rejected the transaction before admission.
    SubmissionUnavailable,
    /// The exact transaction was terminally rejected and must be re-signed.
    TransactionRejected,
    /// Finalized provider ownership changed after completion preparation.
    ProviderOwnerChanged,
    /// A later finalized view proved the exact transaction absent.
    FinalizedAbsent,
    /// Immutable finalized ledger or manifest material conflicted.
    BindingMismatch,
    /// Governed completion-signer policy changed or was revoked.
    SignerPolicyChanged,
}
impl ProviderIngestFailureClassV1 {
    const fn is_source_retryable(self) -> bool {
        matches!(
            self,
            Self::SourceUnavailable
                | Self::SourceRejected
                | Self::LeaseExpired
                | Self::StorageRejected
        )
    }
    const fn is_retry_exhaustible(self) -> bool {
        !matches!(self, Self::BindingMismatch)
    }
}
/// Payload-free terminal dead-letter reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub enum ProviderIngestDeadLetterReasonV1 {
    /// Immutable finalized binding validation failed.
    BindingMismatch,
    /// Local storage permanently rejected the exact payload.
    StorageRejected,
    /// The governed retry bound was consumed.
    RetryExhausted,
}
/// Finalized-chain reason for cancelling active work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub enum ProviderIngestCancellationReasonV1 {
    /// The replication order expired.
    OrderExpired,
    /// The order reached its target before this provider completed.
    OrderCompletedByOther,
    /// The manifest was retired.
    ManifestRetired,
}
/// Opaque runtime identity owning one source lease.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, NoritoSerialize, NoritoDeserialize,
)]
pub struct ProviderIngestClaimOwnerV1([u8; 32]);
impl ProviderIngestClaimOwnerV1 {
    /// Construct a runtime owner from non-zero runtime entropy.
    pub fn new(bytes: [u8; 32]) -> Result<Self, ProviderIngestOutboxError> {
        if bytes == [0; 32] {
            return Err(ProviderIngestOutboxError::InvalidClaimOwner);
        }
        Ok(Self(bytes))
    }
}
/// Exact finalized network and archive identity retained for one Musubi ingest job.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "sorafs_node::provider_ingest_outbox::FinalizedProviderIngestMusubiContextV1"
)]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub struct FinalizedProviderIngestMusubiContextV1 {
    network_id: NetworkId,
    archive_id: ArchiveId,
}
impl FinalizedProviderIngestMusubiContextV1 {
    /// Construct and validate an exact finalized Musubi context.
    ///
    /// # Errors
    ///
    /// Returns an error when the network identity is malformed or the archive is inert.
    pub fn new(
        network_id: NetworkId,
        archive_id: ArchiveId,
    ) -> Result<Self, ProviderIngestOutboxError> {
        let context = Self {
            network_id,
            archive_id,
        };
        context.validate()?;
        Ok(context)
    }
    /// Exact configured deployment identity.
    #[must_use]
    pub const fn network_id(&self) -> &NetworkId {
        &self.network_id
    }
    /// Exact finalized Musubi archive identity.
    #[must_use]
    pub const fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }
    /// Validate the bounded canonical context.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid network identity or inert archive digest.
    pub fn validate(&self) -> Result<(), ProviderIngestOutboxError> {
        if self.network_id.as_bytes()[31] & 1 != 1 || self.archive_id.is_zero() {
            return Err(ProviderIngestOutboxError::InvalidAuthorization);
        }
        Ok(())
    }
}
/// Immutable authorization derived from exact finalized ledger state.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "sorafs_node::provider_ingest_outbox::FinalizedProviderIngestAuthorizationV1"
)]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub struct FinalizedProviderIngestAuthorizationV1 {
    job_id: [u8; 32],
    admission_finalized_cursor: ProviderIngestFinalizedCursorV1,
    provider_id: [u8; 32],
    order_id: [u8; 32],
    manifest_digest: [u8; 32],
    manifest_cid: ManifestRootCid,
    chunker_handle: String,
    chunk_digest_sha3_256: [u8; 32],
    por_root: [u8; 32],
    content_length: u64,
    musubi_context: Option<FinalizedProviderIngestMusubiContextV1>,
}
impl FinalizedProviderIngestAuthorizationV1 {
    #[allow(clippy::too_many_arguments)]
    /// Construct and validate the immutable authorization captured from one
    /// exact finalized ledger view.
    ///
    /// Callers remain responsible for obtaining these values from an authoritative finalized query;
    /// the value itself contains no capability, credential, or mutable authority.
    ///
    /// # Errors
    ///
    /// Returns an error when any finalized field is zero, malformed, out of
    /// bounds, or inconsistent with the deterministically derived job ID.
    pub fn from_finalized_state(
        finalized_height: u64,
        finalized_block_hash: [u8; 32],
        provider_id: [u8; 32],
        order_id: [u8; 32],
        manifest_digest: [u8; 32],
        manifest_cid: Vec<u8>,
        chunker_handle: String,
        chunk_digest_sha3_256: [u8; 32],
        por_root: [u8; 32],
        content_length: u64,
    ) -> Result<Self, ProviderIngestOutboxError> {
        let manifest_cid = ManifestRootCid::try_from_slice(&manifest_cid)
            .map_err(|_| ProviderIngestOutboxError::InvalidAuthorization)?;
        let mut authorization = Self {
            job_id: [0; 32],
            admission_finalized_cursor: ProviderIngestFinalizedCursorV1 {
                height: finalized_height,
                block_hash: finalized_block_hash,
            },
            provider_id,
            order_id,
            manifest_digest,
            manifest_cid,
            chunker_handle,
            chunk_digest_sha3_256,
            por_root,
            content_length,
            musubi_context: None,
        };
        authorization.job_id = authorization.derived_job_id();
        authorization.validate()?;
        Ok(authorization)
    }
    #[allow(clippy::too_many_arguments)]
    /// Construct and validate an immutable Musubi authorization captured from
    /// one exact finalized ledger view.
    ///
    /// The supplied context becomes part of both the durable binding and the derived job identity.
    /// A generic authorization with otherwise identical fields is therefore a different job.
    ///
    /// # Errors
    ///
    /// Returns an error when any finalized field or Musubi context field is
    /// zero, malformed, out of bounds, or inconsistent with the derived job ID.
    pub fn from_finalized_musubi_state(
        finalized_height: u64,
        finalized_block_hash: [u8; 32],
        provider_id: [u8; 32],
        order_id: [u8; 32],
        manifest_digest: [u8; 32],
        manifest_cid: Vec<u8>,
        chunker_handle: String,
        chunk_digest_sha3_256: [u8; 32],
        por_root: [u8; 32],
        content_length: u64,
        musubi_context: FinalizedProviderIngestMusubiContextV1,
    ) -> Result<Self, ProviderIngestOutboxError> {
        musubi_context.validate()?;
        let mut authorization = Self::from_finalized_state(
            finalized_height,
            finalized_block_hash,
            provider_id,
            order_id,
            manifest_digest,
            manifest_cid,
            chunker_handle,
            chunk_digest_sha3_256,
            por_root,
            content_length,
        )?;
        authorization.musubi_context = Some(musubi_context);
        authorization.job_id = authorization.derived_job_id();
        authorization.validate()?;
        Ok(authorization)
    }
    /// Stable job identity derived from provider, order, and manifest binding.
    ///
    /// The admission cursor is intentionally excluded so an unchanged pending
    /// assignment remains replayable after the finalized head advances.
    #[must_use]
    pub const fn job_id(&self) -> [u8; 32] {
        self.job_id
    }
    /// Original finalized cursor that admitted this job.
    #[must_use]
    pub const fn admission_finalized_cursor(&self) -> ProviderIngestFinalizedCursorV1 {
        self.admission_finalized_cursor
    }
    /// Original finalized admission height.
    #[must_use]
    pub const fn finalized_height(&self) -> u64 {
        self.admission_finalized_cursor.height
    }
    /// Original finalized admission block hash.
    #[must_use]
    pub const fn finalized_block_hash(&self) -> [u8; 32] {
        self.admission_finalized_cursor.block_hash
    }
    /// Configured provider identity.
    #[must_use]
    pub const fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }
    /// Replication order identity.
    #[must_use]
    pub const fn order_id(&self) -> [u8; 32] {
        self.order_id
    }
    /// Canonical manifest digest.
    #[must_use]
    pub const fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }
    /// Canonical manifest CID.
    #[must_use]
    pub fn manifest_cid(&self) -> &[u8] {
        self.manifest_cid.as_bytes()
    }
    /// Canonical chunker profile handle.
    #[must_use]
    pub fn chunker_handle(&self) -> &str {
        &self.chunker_handle
    }
    /// Finalized chunk-plan commitment.
    #[must_use]
    pub const fn chunk_digest_sha3_256(&self) -> [u8; 32] {
        self.chunk_digest_sha3_256
    }
    /// Finalized PoR root.
    #[must_use]
    pub const fn por_root(&self) -> [u8; 32] {
        self.por_root
    }
    /// Finalized payload length.
    #[must_use]
    pub const fn content_length(&self) -> u64 {
        self.content_length
    }
    /// Exact finalized Musubi context, absent for a generic replication job.
    #[must_use]
    pub const fn musubi_context(&self) -> Option<&FinalizedProviderIngestMusubiContextV1> {
        self.musubi_context.as_ref()
    }
    fn derived_job_id(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PROVIDER_INGEST_JOB_ID_DOMAIN_V1);
        hasher.update(&self.provider_id);
        hasher.update(&self.order_id);
        hasher.update(&self.manifest_digest);
        hash_length_prefixed(&mut hasher, self.manifest_cid.as_bytes());
        hash_length_prefixed(&mut hasher, self.chunker_handle.as_bytes());
        hasher.update(&self.chunk_digest_sha3_256);
        hasher.update(&self.por_root);
        hasher.update(&self.content_length.to_le_bytes());
        match &self.musubi_context {
            None => {
                hasher.update(&[0]);
            }
            Some(context) => {
                hasher.update(&[1]);
                hasher.update(context.network_id().as_bytes());
                hasher.update(context.archive_id().as_bytes());
            }
        }
        *hasher.finalize().as_bytes()
    }
    fn same_binding(&self, other: &Self) -> bool {
        self.provider_id == other.provider_id
            && self.order_id == other.order_id
            && self.manifest_digest == other.manifest_digest
            && self.manifest_cid == other.manifest_cid
            && self.chunker_handle == other.chunker_handle
            && self.chunk_digest_sha3_256 == other.chunk_digest_sha3_256
            && self.por_root == other.por_root
            && self.content_length == other.content_length
            && self.musubi_context == other.musubi_context
    }
    /// Validate the complete canonical finalized authorization binding.
    ///
    /// This is exposed for authenticated runtime boundaries that decode the
    /// authorization outside the outbox crate and must reject substituted or
    /// noncanonical job identities before performing I/O.
    ///
    /// # Errors
    ///
    /// Returns an error when any field or the derived job identity is invalid.
    pub fn validate(&self) -> Result<(), ProviderIngestOutboxError> {
        self.admission_finalized_cursor.validate()?;
        if self.provider_id == [0; 32]
            || self.order_id == [0; 32]
            || self.manifest_digest == [0; 32]
            || self.chunker_handle.is_empty()
            || self.chunker_handle.len() > MAX_CHUNKER_HANDLE_BYTES_V1
            || self.chunker_handle.trim() != self.chunker_handle
            || self.chunker_handle.chars().any(char::is_control)
            || self.chunk_digest_sha3_256 == [0; 32]
            || self.por_root == [0; 32]
            || self.content_length == 0
            || self
                .musubi_context
                .as_ref()
                .is_some_and(|context| context.validate().is_err())
            || self.job_id != self.derived_job_id()
        {
            return Err(ProviderIngestOutboxError::InvalidAuthorization);
        }
        Ok(())
    }
}
fn hash_length_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}
/// Opaque, leased source claim returned to one worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestSourceClaimV1 {
    job_id: [u8; 32],
    owner: ProviderIngestClaimOwnerV1,
    generation: u64,
    lease_token: [u8; 32],
    lease_expires_at_ms: u64,
    authorization: FinalizedProviderIngestAuthorizationV1,
}
impl ProviderIngestSourceClaimV1 {
    /// Stable job identity.
    #[must_use]
    pub const fn job_id(&self) -> [u8; 32] {
        self.job_id
    }
    /// Lease expiry in runtime milliseconds.
    #[must_use]
    pub const fn lease_expires_at_ms(&self) -> u64 {
        self.lease_expires_at_ms
    }
    /// Immutable payload-free ledger authorization.
    #[must_use]
    pub fn authorization(&self) -> &FinalizedProviderIngestAuthorizationV1 {
        &self.authorization
    }
}
/// Public completion-delivery state without retained transaction bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderIngestCompletionStateV1 {
    /// Local storage is complete and no signer owns the completion operation.
    Ready {
        /// Failed signing/submission attempts consumed.
        attempts: u32,
        /// Earliest runtime time for the next signing claim.
        next_attempt_at_ms: u64,
        /// Last payload-free failure class, when retry-delayed.
        last_failure_class: Option<ProviderIngestFailureClassV1>,
    },
    /// An isolated signer owns the semantic completion operation.
    Signing {
        /// Attempts consumed before this signer claim.
        attempts: u32,
        /// Finalized baseline preceding the signer call.
        baseline_finalized_cursor: ProviderIngestFinalizedCursorV1,
        /// Provider-specific completion epoch being signed.
        completion_epoch: u64,
    },
    /// Exact signed bytes are durable for first exposure or safe same-byte
    /// resubmission after finalized absence.
    Signed {
        /// Attempts consumed.
        attempts: u32,
        /// Finalized baseline preceding submission.
        baseline_finalized_cursor: ProviderIngestFinalizedCursorV1,
        /// Provider-specific completion epoch.
        completion_epoch: u64,
        /// Exact signed transaction hash.
        transaction_hash: [u8; 32],
        /// Whether these exact bytes crossed the durable exposure boundary.
        ever_exposed: bool,
        /// Earliest runtime time for a proven-safe resubmission.
        next_attempt_at_ms: u64,
    },
    /// Submission may have occurred and requires finalized reconciliation.
    Ambiguous {
        /// Attempts consumed.
        attempts: u32,
        /// Finalized baseline preceding submission.
        baseline_finalized_cursor: ProviderIngestFinalizedCursorV1,
        /// Provider-specific completion epoch.
        completion_epoch: u64,
        /// Exact signed transaction hash.
        transaction_hash: [u8; 32],
    },
    /// The exact transaction is known pending or applied but not finalized.
    Submitted {
        /// Attempts consumed.
        attempts: u32,
        /// Finalized baseline preceding submission.
        baseline_finalized_cursor: ProviderIngestFinalizedCursorV1,
        /// Provider-specific completion epoch.
        completion_epoch: u64,
        /// Exact signed transaction hash.
        transaction_hash: [u8; 32],
    },
}
/// Payload-free runtime status for one provider-ingest job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderIngestDeliveryStateV1 {
    /// Awaiting an admitted payload source.
    PendingSource {
        /// Source failures consumed.
        attempts: u32,
    },
    /// One worker owns a bounded source lease.
    SourceClaimed {
        /// Source failures consumed.
        attempts: u32,
        /// Monotonic claim generation.
        generation: u64,
        /// Lease expiry in runtime milliseconds.
        lease_expires_at_ms: u64,
    },
    /// Source/storage work is durably delayed.
    RetryScheduled {
        /// Source failures consumed.
        attempts: u32,
        /// Earliest runtime retry time.
        next_attempt_at_ms: u64,
        /// Fixed payload-free failure class.
        failure_class: ProviderIngestFailureClassV1,
    },
    /// Exact manifest bytes are present in local storage.
    LocalStored {
        /// Canonical local manifest identifier.
        manifest_id: String,
        /// Exact persisted Musubi verification receipt, absent for generic orders.
        musubi_bundle: Option<Box<ProviderIngestVerifiedMusubiBundleReceiptV1>>,
        /// Provider-specific completion transaction delivery.
        completion: ProviderIngestCompletionStateV1,
    },
    /// This provider's completion is committed in finalized chain state.
    FinalizedCompleted {
        /// Canonical local manifest identifier, when this replica stored it.
        manifest_id: Option<String>,
        /// Exact pre-completion Musubi verification receipt, when applicable.
        musubi_bundle: Option<Box<ProviderIngestVerifiedMusubiBundleReceiptV1>>,
        /// Provider-specific completion epoch.
        completion_epoch: u64,
        /// Ledger account that committed the provider completion.
        completed_by: AccountId,
        /// Committed transaction hash, when exposed by the finalized reader.
        committed_transaction_hash: Option<[u8; 32]>,
        /// Finalized cursor proving completion.
        finalized_cursor: ProviderIngestFinalizedCursorV1,
    },
    /// Finalized chain state made the job inapplicable.
    Cancelled {
        /// Authoritative cancellation class.
        reason: ProviderIngestCancellationReasonV1,
        /// Finalized cursor proving cancellation.
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    },
    /// Work stopped after a permanent failure or bounded retry exhaustion.
    DeadLetter {
        /// Attempts consumed.
        attempts: u32,
        /// Terminal reason.
        reason: ProviderIngestDeadLetterReasonV1,
        /// Last fixed payload-free failure class.
        last_failure_class: ProviderIngestFailureClassV1,
        /// Finalized cursor observed at terminal transition.
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    },
}
/// Payload-free status row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestStatusV1 {
    /// Stable provider-ingest job identity.
    pub job_id: [u8; 32],
    /// Original finalized admission cursor.
    pub admission_finalized_cursor: ProviderIngestFinalizedCursorV1,
    /// Provider identity.
    pub provider_id: [u8; 32],
    /// Replication order identity.
    pub order_id: [u8; 32],
    /// Canonical manifest digest.
    pub manifest_digest: [u8; 32],
    /// Current durable state without payload or signed transaction bytes.
    pub state: ProviderIngestDeliveryStateV1,
}
/// Bounded deterministic status page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestStatusPageV1 {
    /// Rows in stable job-id order.
    pub rows: Vec<ProviderIngestStatusV1>,
    /// Pass this value as `after_job_id` to read the next page.
    pub next_after_job_id: Option<[u8; 32]>,
}
/// Constant-time payload-free aggregate counts for daemon readiness.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProviderIngestOutboxCountsV1 {
    /// Non-terminal durable jobs.
    pub active: usize,
    /// Retained terminal tombstones, including dead letters.
    pub terminal: usize,
    /// Retained terminal dead letters.
    pub dead_letters: usize,
}
/// Result of idempotently admitting one finalized provider-ingest job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderIngestEnqueueResultV1 {
    /// A new active job was durably inserted.
    Inserted {
        /// Stable job identity.
        job_id: [u8; 32],
    },
    /// The same immutable binding is already active.
    ExistingActive {
        /// Stable job identity.
        job_id: [u8; 32],
    },
    /// The same immutable binding is retained as terminal.
    ExistingTerminal {
        /// Stable job identity.
        job_id: [u8; 32],
    },
}
impl ProviderIngestEnqueueResultV1 {
    /// Return the stable job identity.
    #[must_use]
    pub const fn job_id(self) -> [u8; 32] {
        match self {
            Self::Inserted { job_id }
            | Self::ExistingActive { job_id }
            | Self::ExistingTerminal { job_id } => job_id,
        }
    }
}
/// Outcome of a bounded retry transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderIngestRetryOutcomeV1 {
    /// The job remains active after a durable delay.
    RetryScheduled {
        /// Failures consumed.
        attempts: u32,
        /// Earliest runtime retry time.
        next_attempt_at_ms: u64,
    },
    /// The job moved to terminal retry exhaustion.
    DeadLettered,
}
fn validate_completion_authority(
    authority: &ProviderIngestCompletionAuthorityV1,
) -> Result<(), ProviderIngestOutboxError> {
    if !authority.is_valid()
        || !completion_account_id_fits_canonical_bound(&authority.provider_owner)
        || !completion_account_id_fits_canonical_bound(&authority.completion_signer)
    {
        return Err(ProviderIngestOutboxError::InvalidSignerPolicy);
    }
    Ok(())
}
/// Current finalized observation used to reconcile a prepared full completion authority.
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub(crate) enum ProviderIngestCompletionAuthorityObservationV1 {
    /// Only provider ownership was checked; signer policy was not queried.
    NotChecked,
    /// The finalized policy resolver proves no eligible signer policy exists.
    Missing,
    /// Exact active finalized provider owner, completion signer and policy.
    Active(ProviderIngestCompletionAuthorityV1),
}
/// Exact evidence and timing inputs required to expire one exposed completion.
#[derive(Debug, Clone)]
pub(crate) struct ProviderIngestExposedCompletionExpiryV1<'a> {
    /// Durable provider-ingest job identity.
    pub(crate) job_id: [u8; 32],
    /// Hash of the exact signed transaction retained by the outbox.
    pub(crate) expected_transaction_hash: [u8; 32],
    /// Current finalized owner of the configured provider identity.
    pub(crate) current_provider_owner: Option<&'a AccountId>,
    /// Current finalized full completion-authority observation for that owner.
    pub(crate) current_authority: &'a ProviderIngestCompletionAuthorityObservationV1,
    /// Runtime clock used only to schedule a bounded retry.
    pub(crate) runtime_now_ms: u64,
    /// Finalized block time proving the retained transaction has expired.
    pub(crate) finalized_block_time_ms: u64,
    /// Finalized cursor at which absence and authority were observed.
    pub(crate) observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
struct StoredFinalizedCompletionAuthorityObservationV1 {
    cursor: ProviderIngestFinalizedCursorV1,
    provider_owner: Option<AccountId>,
    completion_authority: ProviderIngestCompletionAuthorityObservationV1,
}
/// Exact finalized and fee-quoted payload handed to an isolated signer.
#[derive(Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "sorafs_node::provider_ingest_outbox::ProviderIngestCompletionSigningContextV1"
)]
pub struct ProviderIngestCompletionSigningContextV1 {
    /// Finalized baseline preceding payload construction and signing.
    pub baseline_finalized_cursor: ProviderIngestFinalizedCursorV1,
    /// Exact genesis-derived network identity signed into the payload.
    pub network_id: NetworkId,
    /// Exact full governed completion binding resolved at the finalized baseline.
    pub expected_authority: ProviderIngestCompletionAuthorityV1,
    /// Exact order-scoped assignment revision at the finalized baseline.
    pub assignment_revision: u64,
    /// Provider-specific completion epoch.
    pub completion_epoch: u64,
    /// Exact fee-quoted payload that the isolated signer must sign.
    pub expected_payload: TransactionPayload,
}
impl fmt::Debug for ProviderIngestCompletionSigningContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderIngestCompletionSigningContextV1")
            .field("baseline_finalized_cursor", &self.baseline_finalized_cursor)
            .field("network_id", &self.network_id)
            .field("expected_authority", &self.expected_authority)
            .field("assignment_revision", &self.assignment_revision)
            .field("completion_epoch", &self.completion_epoch)
            .field("expected_payload", &"<redacted>")
            .finish()
    }
}
/// Opaque claim handed to the isolated completion signer.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderIngestCompletionSigningClaimV1 {
    job_id: [u8; 32],
    generation: u64,
    signing_token: [u8; 32],
    context: ProviderIngestCompletionSigningContextV1,
}
impl fmt::Debug for ProviderIngestCompletionSigningClaimV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderIngestCompletionSigningClaimV1")
            .field("job_id", &hex::encode(self.job_id))
            .field("generation", &self.generation)
            .field("signing_token", &"<redacted>")
            .field("context", &self.context)
            .finish()
    }
}
impl ProviderIngestCompletionSigningClaimV1 {
    /// Stable job identity.
    #[must_use]
    pub const fn job_id(&self) -> [u8; 32] {
        self.job_id
    }
    /// Monotonic signer-claim generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Exact prepared context that the isolated signer must sign.
    #[must_use]
    pub const fn context(&self) -> &ProviderIngestCompletionSigningContextV1 {
        &self.context
    }
}
/// Exact transaction returned only after the ambiguous state is durable.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderIngestCompletionSubmissionV1 {
    /// Stable job identity.
    pub job_id: [u8; 32],
    /// Exact signed transaction hash.
    pub transaction_hash: [u8; 32],
    /// Exact signed provider-specific completion transaction.
    pub signed_transaction: SignedTransaction,
}
impl fmt::Debug for ProviderIngestCompletionSubmissionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderIngestCompletionSubmissionV1")
            .field("job_id", &hex::encode(self.job_id))
            .field("transaction_hash", &hex::encode(self.transaction_hash))
            .field("signed_transaction", &"<redacted>")
            .finish()
    }
}
/// Typed committed-state evidence for this provider's completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestFinalizedCompletionV1 {
    /// Finalized cursor containing the committed completion.
    pub finalized_cursor: ProviderIngestFinalizedCursorV1,
    /// Provider identity whose completion was committed.
    pub provider_id: [u8; 32],
    /// Replication order identity.
    pub order_id: [u8; 32],
    /// Manifest identity resolved from the same finalized order view.
    pub manifest_digest: [u8; 32],
    /// Provider-specific completion epoch.
    pub completion_epoch: u64,
    /// Ledger account that committed the provider completion.
    pub completed_by: AccountId,
    /// Committed transaction hash, when exposed by the finalized reader.
    pub committed_transaction_hash: Option<[u8; 32]>,
}
/// Typed finalized-state evidence proving that active work is inapplicable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderIngestFinalizedCancellationV1 {
    /// Finalized cursor proving cancellation.
    pub finalized_cursor: ProviderIngestFinalizedCursorV1,
    /// Provider identity whose work is cancelled.
    pub provider_id: [u8; 32],
    /// Replication order identity.
    pub order_id: [u8; 32],
    /// Manifest identity resolved from the same finalized order view.
    pub manifest_digest: [u8; 32],
    /// Authoritative cancellation class.
    pub reason: ProviderIngestCancellationReasonV1,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_node::provider_ingest_outbox::StoredCompletionDeliveryV1")]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
struct StoredCompletionDeliveryV1 {
    state: StoredDeliveryStateV1,
    attempts: u32,
    signing_generation: u64,
    signing_claimed_at_ms: u64,
    baseline_finalized_height: u64,
    baseline_finalized_block_hash: [u8; 32],
    completion_epoch: Option<u64>,
    finalized_authority_observation: Option<StoredFinalizedCompletionAuthorityObservationV1>,
    authority_owner: Option<AccountId>,
    authority_floor: Option<ProviderIngestCompletionAuthorityV1>,
    authority_successor_required: bool,
    signing_context: Option<ProviderIngestCompletionSigningContextV1>,
    transaction_hash: Option<[u8; 32]>,
    signed_transaction: Option<SignedTransaction>,
    ever_exposed: bool,
    next_attempt_at_ms: u64,
    last_failure_class: Option<ProviderIngestFailureClassV1>,
}
impl Default for StoredCompletionDeliveryV1 {
    fn default() -> Self {
        Self {
            state: StoredDeliveryStateV1::Ready,
            attempts: 0,
            signing_generation: 0,
            signing_claimed_at_ms: 0,
            baseline_finalized_height: 0,
            baseline_finalized_block_hash: [0; 32],
            completion_epoch: None,
            finalized_authority_observation: None,
            authority_owner: None,
            authority_floor: None,
            authority_successor_required: false,
            signing_context: None,
            transaction_hash: None,
            signed_transaction: None,
            ever_exposed: false,
            next_attempt_at_ms: 0,
            last_failure_class: None,
        }
    }
}
impl DeliveryRecord for StoredCompletionDeliveryV1 {
    type Transaction = SignedTransaction;
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
        self.signed_transaction.as_ref()
    }
    fn set_signed_transaction(&mut self, transaction: Option<Self::Transaction>) {
        self.signed_transaction = transaction;
    }
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
enum StoredProviderIngestStateV1 {
    PendingSource,
    SourceClaimed {
        owner: ProviderIngestClaimOwnerV1,
        generation: u64,
        lease_token: [u8; 32],
        lease_expires_at_ms: u64,
    },
    RetryScheduled {
        next_attempt_at_ms: u64,
        failure_class: ProviderIngestFailureClassV1,
    },
    LocalStored {
        manifest_id: String,
        musubi_bundle: Option<Box<StoredProviderIngestVerifiedMusubiBundleReceiptV1>>,
        completion: Box<StoredCompletionDeliveryV1>,
    },
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_node::provider_ingest_outbox::StoredActiveProviderIngestV1")]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
struct StoredActiveProviderIngestV1 {
    sequence: u64,
    authorization: FinalizedProviderIngestAuthorizationV1,
    source_attempts: u32,
    claim_generation: u64,
    state: StoredProviderIngestStateV1,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "sorafs_node::provider_ingest_outbox::StoredProviderIngestTerminalOutcomeV1"
)]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
enum StoredProviderIngestTerminalOutcomeV1 {
    FinalizedCompleted {
        manifest_id: Option<String>,
        musubi_bundle: Option<Box<StoredProviderIngestVerifiedMusubiBundleReceiptV1>>,
        completion_epoch: u64,
        completed_by: AccountId,
        committed_transaction_hash: Option<[u8; 32]>,
        finalized_cursor: ProviderIngestFinalizedCursorV1,
    },
    Cancelled {
        reason: ProviderIngestCancellationReasonV1,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    },
    DeadLetter {
        attempts: u32,
        reason: ProviderIngestDeadLetterReasonV1,
        last_failure_class: ProviderIngestFailureClassV1,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    },
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_node::provider_ingest_outbox::StoredTerminalProviderIngestV1")]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
struct StoredTerminalProviderIngestV1 {
    sequence: u64,
    authorization: FinalizedProviderIngestAuthorizationV1,
    outcome: StoredProviderIngestTerminalOutcomeV1,
}
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "sorafs_node::provider_ingest_outbox::ProviderIngestOutboxCheckpointV1")]
struct ProviderIngestOutboxCheckpointV1 {
    magic: [u8; 16],
    version: u8,
    next_sequence: u64,
    finalized_cursor_high_water: Option<ProviderIngestFinalizedCursorV1>,
    finalized_block_time_ms_high_water: Option<u64>,
    active: Vec<StoredActiveProviderIngestV1>,
    terminal: Vec<StoredTerminalProviderIngestV1>,
}
impl Default for ProviderIngestOutboxCheckpointV1 {
    fn default() -> Self {
        Self {
            magic: PROVIDER_INGEST_CHECKPOINT_MAGIC_V5,
            version: PROVIDER_INGEST_OUTBOX_LAYOUT_VERSION_V5,
            next_sequence: 1,
            finalized_cursor_high_water: None,
            finalized_block_time_ms_high_water: None,
            active: Vec::new(),
            terminal: Vec::new(),
        }
    }
}
#[derive(Debug, Clone)]
struct ProviderIngestOutboxState {
    checkpoint: ProviderIngestOutboxCheckpointV1,
    sealed_record: Option<ProviderIngestSealedCheckpointRecordV1>,
    aggregate_counts: ProviderIngestOutboxCountsV1,
    durability_failure: Option<String>,
}
enum ProviderIngestCheckpointWorkerOperation {
    Qualification,
    LoadLatest,
    CompareAndSwap {
        expected_revision: Option<[u8; 32]>,
        next: Box<ProviderIngestSealedCheckpointRecordV1>,
    },
}
struct ProviderIngestCheckpointIdentityResponse {
    handle_before: String,
    qualification: ProviderIngestCheckpointProviderQualificationV1,
    handle_after: String,
}
enum ProviderIngestCheckpointWorkerResponse {
    Qualification(
        Result<ProviderIngestCheckpointIdentityResponse, ProviderIngestCheckpointExternalErrorV1>,
    ),
    LoadLatest(
        Box<
            Result<
                Option<ProviderIngestSealedCheckpointRecordV1>,
                ProviderIngestCheckpointExternalErrorV1,
            >,
        >,
    ),
    CompareAndSwap(Result<(), ProviderIngestCheckpointExternalErrorV1>),
    Panicked,
    TimedOut,
}
struct ProviderIngestCheckpointWorkerCall {
    operation: ProviderIngestCheckpointWorkerOperation,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    response: SyncSender<ProviderIngestCheckpointWorkerResponse>,
}
enum ProviderIngestCheckpointWorkerRequest {
    Call(ProviderIngestCheckpointWorkerCall),
    Shutdown(SyncSender<()>),
}
struct ProviderIngestCheckpointWorker {
    requests: SyncSender<ProviderIngestCheckpointWorkerRequest>,
    operation_timeout: Duration,
    timed_out: Arc<AtomicBool>,
    call_active: Mutex<bool>,
    call_available: Condvar,
}
struct ProviderIngestCheckpointCallAdmission<'worker> {
    worker: &'worker ProviderIngestCheckpointWorker,
}
impl ProviderIngestCheckpointWorker {
    fn try_new(
        runtime: Arc<dyn ProviderIngestCheckpointRuntimeV1>,
        operation_timeout: Duration,
        writer_lock_lease: Arc<ProviderIngestWriterLock>,
    ) -> Result<Self, ProviderIngestOutboxError> {
        if operation_timeout.is_zero() {
            return Err(ProviderIngestOutboxError::InvalidPolicy);
        }
        let (requests, receiver) =
            mpsc::sync_channel(PROVIDER_INGEST_CHECKPOINT_REQUEST_CAPACITY_V1);
        let timed_out = Arc::new(AtomicBool::new(false));
        let worker_timed_out = Arc::clone(&timed_out);
        // Detach deliberately: shutdown must never join a provider call that
        // exceeded its deadline and may remain blocked inside vendor code.
        let _worker_thread = thread::Builder::new()
            .name("sorafs-provider-ingest-checkpoint-v1".to_owned())
            .spawn(move || {
                provider_ingest_checkpoint_worker(
                    runtime,
                    receiver,
                    worker_timed_out,
                    writer_lock_lease,
                );
            })
            .map_err(|_| ProviderIngestOutboxError::CheckpointProviderUnavailable)?;
        Ok(Self {
            requests,
            operation_timeout,
            timed_out,
            call_active: Mutex::new(false),
            call_available: Condvar::new(),
        })
    }
    fn acquire_call(
        &self,
        deadline: Instant,
    ) -> Result<ProviderIngestCheckpointCallAdmission<'_>, ProviderIngestOutboxError> {
        let mut call_active = self
            .call_active
            .lock()
            .map_err(|_| ProviderIngestOutboxError::CheckpointProviderUnavailable)?;
        loop {
            if self.timed_out.load(Ordering::Acquire) {
                return Err(ProviderIngestOutboxError::CheckpointProviderTimeout);
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ProviderIngestOutboxError::CheckpointProviderBusy);
            };
            if !*call_active {
                *call_active = true;
                drop(call_active);
                return Ok(ProviderIngestCheckpointCallAdmission { worker: self });
            }
            let (next, wait) = self
                .call_available
                .wait_timeout(call_active, remaining)
                .map_err(|_| ProviderIngestOutboxError::CheckpointProviderUnavailable)?;
            call_active = next;
            if wait.timed_out() && *call_active {
                return Err(ProviderIngestOutboxError::CheckpointProviderBusy);
            }
        }
    }
    fn call(
        &self,
        operation: ProviderIngestCheckpointWorkerOperation,
    ) -> Result<ProviderIngestCheckpointWorkerResponse, ProviderIngestOutboxError> {
        if self.timed_out.load(Ordering::Acquire) {
            return Err(ProviderIngestOutboxError::CheckpointProviderTimeout);
        }
        let deadline = Instant::now()
            .checked_add(self.operation_timeout)
            .ok_or(ProviderIngestOutboxError::InvalidPolicy)?;
        let _admission = self.acquire_call(deadline)?;
        if Instant::now() >= deadline {
            return Err(ProviderIngestOutboxError::CheckpointProviderBusy);
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let (response, response_receiver) = mpsc::sync_channel(1);
        let request =
            ProviderIngestCheckpointWorkerRequest::Call(ProviderIngestCheckpointWorkerCall {
                operation,
                deadline,
                cancelled: Arc::clone(&cancelled),
                response,
            });
        match self.requests.try_send(request) {
            Ok(()) => {}
            Err(TrySendError::Full(ProviderIngestCheckpointWorkerRequest::Call(call))) => {
                call.cancelled.store(true, Ordering::Release);
                return Err(ProviderIngestOutboxError::CheckpointProviderUnavailable);
            }
            Err(TrySendError::Disconnected(ProviderIngestCheckpointWorkerRequest::Call(call))) => {
                call.cancelled.store(true, Ordering::Release);
                return Err(ProviderIngestOutboxError::CheckpointProviderUnavailable);
            }
            Err(TrySendError::Full(ProviderIngestCheckpointWorkerRequest::Shutdown(_)))
            | Err(TrySendError::Disconnected(ProviderIngestCheckpointWorkerRequest::Shutdown(_))) =>
            {
                return Err(ProviderIngestOutboxError::CheckpointProviderUnavailable);
            }
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            cancelled.store(true, Ordering::Release);
            self.timed_out.store(true, Ordering::Release);
            return Err(ProviderIngestOutboxError::CheckpointProviderTimeout);
        };
        match response_receiver.recv_timeout(remaining) {
            Ok(ProviderIngestCheckpointWorkerResponse::TimedOut) => {
                cancelled.store(true, Ordering::Release);
                Err(ProviderIngestOutboxError::CheckpointProviderBusy)
            }
            Ok(ProviderIngestCheckpointWorkerResponse::Panicked) => {
                Err(ProviderIngestOutboxError::CheckpointProviderResponseLost)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                cancelled.store(true, Ordering::Release);
                self.timed_out.store(true, Ordering::Release);
                Err(ProviderIngestOutboxError::CheckpointProviderTimeout)
            }
            Ok(response)
                if !self.timed_out.load(Ordering::Acquire) && Instant::now() < deadline =>
            {
                Ok(response)
            }
            Ok(_) => {
                cancelled.store(true, Ordering::Release);
                self.timed_out.store(true, Ordering::Release);
                Err(ProviderIngestOutboxError::CheckpointProviderTimeout)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(ProviderIngestOutboxError::CheckpointProviderResponseLost)
            }
        }
    }
}
impl Drop for ProviderIngestCheckpointCallAdmission<'_> {
    fn drop(&mut self) {
        if let Ok(mut call_active) = self.worker.call_active.lock() {
            *call_active = false;
        }
        self.worker.call_available.notify_one();
    }
}
impl Drop for ProviderIngestCheckpointWorker {
    fn drop(&mut self) {
        let timed_out = self.timed_out.swap(true, Ordering::AcqRel);
        let (acknowledge, acknowledged) = mpsc::sync_channel(1);
        if self
            .requests
            .try_send(ProviderIngestCheckpointWorkerRequest::Shutdown(acknowledge))
            .is_ok()
            && !timed_out
        {
            let _ = acknowledged.recv_timeout(self.operation_timeout.min(Duration::from_secs(1)));
        }
    }
}
fn provider_ingest_checkpoint_worker(
    runtime: Arc<dyn ProviderIngestCheckpointRuntimeV1>,
    receiver: mpsc::Receiver<ProviderIngestCheckpointWorkerRequest>,
    timed_out: Arc<AtomicBool>,
    writer_lock_lease: Arc<ProviderIngestWriterLock>,
) {
    while let Ok(request) = receiver.recv() {
        let call = match request {
            ProviderIngestCheckpointWorkerRequest::Call(call) => call,
            ProviderIngestCheckpointWorkerRequest::Shutdown(acknowledge) => {
                drop(writer_lock_lease);
                let _ = acknowledge.send(());
                return;
            }
        };
        if timed_out.load(Ordering::Acquire)
            || call.cancelled.load(Ordering::Acquire)
            || Instant::now() >= call.deadline
        {
            let _ = call
                .response
                .send(ProviderIngestCheckpointWorkerResponse::TimedOut);
            continue;
        }
        let response =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match call.operation {
                ProviderIngestCheckpointWorkerOperation::Qualification => {
                    let handle_before = runtime.handle().to_owned();
                    let qualification = runtime.qualification();
                    let handle_after = runtime.handle().to_owned();
                    ProviderIngestCheckpointWorkerResponse::Qualification(qualification.map(
                        |qualification| ProviderIngestCheckpointIdentityResponse {
                            handle_before,
                            qualification,
                            handle_after,
                        },
                    ))
                }
                ProviderIngestCheckpointWorkerOperation::LoadLatest => {
                    ProviderIngestCheckpointWorkerResponse::LoadLatest(Box::new(
                        runtime.load_latest(),
                    ))
                }
                ProviderIngestCheckpointWorkerOperation::CompareAndSwap {
                    expected_revision,
                    next,
                } => ProviderIngestCheckpointWorkerResponse::CompareAndSwap(
                    runtime.compare_and_swap_latest(expected_revision, &next),
                ),
            }));
        match response {
            Ok(response) => {
                let _ = call.response.send(response);
            }
            Err(_) => {
                let _ = call
                    .response
                    .send(ProviderIngestCheckpointWorkerResponse::Panicked);
                return;
            }
        }
    }
}
#[derive(Clone)]
struct ProviderIngestCheckpointAuthority {
    binding: ProviderIngestCheckpointProviderBindingV1,
    worker: Arc<ProviderIngestCheckpointWorker>,
}
impl fmt::Debug for ProviderIngestCheckpointAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderIngestCheckpointAuthority")
            .field("handle", &self.binding.handle)
            .finish_non_exhaustive()
    }
}
/// Durable payload-free outbox for provider-internal finalized-ledger ingest.
#[derive(Clone)]
pub struct ProviderIngestOutbox {
    path: Option<Arc<PathBuf>>,
    writer_lock: Option<Arc<ProviderIngestWriterLock>>,
    checkpoint_authority: Option<ProviderIngestCheckpointAuthority>,
    policy: ProviderIngestOutboxPolicyV1,
    state: Arc<Mutex<ProviderIngestOutboxState>>,
}
impl fmt::Debug for ProviderIngestOutbox {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderIngestOutbox")
            .field("persistent", &self.path.is_some())
            .field("sealed_authoritative", &self.checkpoint_authority.is_some())
            .field("policy", &self.policy)
            .field("state", &"<redacted>")
            .finish()
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct ProviderIngestDirectoryIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}
struct ProviderIngestWriterLock {
    _process_guard: ProviderIngestProcessLock,
    _file: File,
    lock_path: PathBuf,
    parent_path: PathBuf,
    parent_identity: ProviderIngestDirectoryIdentity,
}
impl ProviderIngestWriterLock {
    fn acquire(checkpoint_path: &Path) -> Result<Self, ProviderIngestOutboxError> {
        let parent = checkpoint_path.parent().ok_or_else(|| {
            ProviderIngestOutboxError::Checkpoint(
                "provider-ingest checkpoint has no parent directory".to_owned(),
            )
        })?;
        let parent_path = fs::canonicalize(parent)
            .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?;
        let parent_identity = provider_ingest_directory_identity(&parent_path)?;
        let lock_path = provider_ingest_lock_path(checkpoint_path)?;
        crate::reject_unsafe_checkpoint_ancestors(&lock_path)
            .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?;
        let process_guard = ProviderIngestProcessLock::acquire(&lock_path)?;
        let before_open = match fs::symlink_metadata(&lock_path) {
            Ok(metadata) => {
                validate_provider_ingest_lock_metadata(&lock_path, &metadata)?;
                Some(metadata)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(ProviderIngestOutboxError::Checkpoint(error.to_string()));
            }
        };
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        crate::fs_flags::set_no_follow_flag(&mut options);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options
            .open(&lock_path)
            .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?;
        let opened = file
            .metadata()
            .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?;
        validate_provider_ingest_lock_metadata(&lock_path, &opened)?;
        if before_open
            .as_ref()
            .is_some_and(|before| !crate::same_local_file_identity(before, &opened))
        {
            return Err(ProviderIngestOutboxError::Checkpoint(
                "provider-ingest writer lock changed while opening".to_owned(),
            ));
        }
        let linked = fs::symlink_metadata(&lock_path)
            .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?;
        validate_provider_ingest_lock_metadata(&lock_path, &linked)?;
        if !crate::same_local_file_identity(&opened, &linked) {
            return Err(ProviderIngestOutboxError::Checkpoint(
                "provider-ingest writer lock path changed while opening".to_owned(),
            ));
        }
        crate::reject_unsafe_checkpoint_ancestors(&lock_path)
            .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?;
        match file.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(ProviderIngestOutboxError::CheckpointBusy);
            }
            Err(fs::TryLockError::Error(error)) => {
                return Err(ProviderIngestOutboxError::Checkpoint(error.to_string()));
            }
        }
        let locked = fs::symlink_metadata(&lock_path)
            .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?;
        validate_provider_ingest_lock_metadata(&lock_path, &locked)?;
        if !crate::same_local_file_identity(&opened, &locked) {
            return Err(ProviderIngestOutboxError::Checkpoint(
                "provider-ingest writer lock path changed while locking".to_owned(),
            ));
        }
        crate::reject_unsafe_checkpoint_ancestors(&lock_path)
            .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?;
        let writer_lock = Self {
            _process_guard: process_guard,
            _file: file,
            lock_path,
            parent_path,
            parent_identity,
        };
        writer_lock.validate_live(checkpoint_path)?;
        Ok(writer_lock)
    }
    fn validate_live(&self, checkpoint_path: &Path) -> Result<(), ProviderIngestOutboxError> {
        crate::reject_unsafe_checkpoint_ancestors(checkpoint_path)
            .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?;
        let parent = checkpoint_path.parent().ok_or_else(|| {
            ProviderIngestOutboxError::Checkpoint(
                "provider-ingest checkpoint has no parent directory".to_owned(),
            )
        })?;
        let parent_path = fs::canonicalize(parent)
            .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?;
        if parent_path != self.parent_path
            || provider_ingest_directory_identity(&parent_path)? != self.parent_identity
        {
            return Err(ProviderIngestOutboxError::Checkpoint(
                "provider-ingest checkpoint parent changed identity".to_owned(),
            ));
        }
        if provider_ingest_lock_path(checkpoint_path)? != self.lock_path {
            return Err(ProviderIngestOutboxError::Checkpoint(
                "provider-ingest writer lock path changed".to_owned(),
            ));
        }
        let opened = self
            ._file
            .metadata()
            .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?;
        validate_provider_ingest_lock_metadata(&self.lock_path, &opened)?;
        let linked = fs::symlink_metadata(&self.lock_path)
            .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?;
        validate_provider_ingest_lock_metadata(&self.lock_path, &linked)?;
        if !crate::same_local_file_identity(&opened, &linked) {
            return Err(ProviderIngestOutboxError::Checkpoint(
                "provider-ingest writer lock changed identity".to_owned(),
            ));
        }
        Ok(())
    }
}
struct ProviderIngestProcessLock {
    path: PathBuf,
}
impl ProviderIngestProcessLock {
    fn acquire(path: &Path) -> Result<Self, ProviderIngestOutboxError> {
        let parent = path.parent().ok_or_else(|| {
            ProviderIngestOutboxError::Checkpoint(
                "provider-ingest writer lock has no parent".to_owned(),
            )
        })?;
        let file_name = path.file_name().ok_or_else(|| {
            ProviderIngestOutboxError::Checkpoint(
                "provider-ingest writer lock has no file name".to_owned(),
            )
        })?;
        let path = fs::canonicalize(parent)
            .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?
            .join(file_name);
        let mut held = PROVIDER_INGEST_PROCESS_LOCKS
            .lock()
            .map_err(|_| ProviderIngestOutboxError::StateUnavailable)?;
        if !held.insert(path.clone()) {
            return Err(ProviderIngestOutboxError::CheckpointBusy);
        }
        drop(held);
        Ok(Self { path })
    }
}
impl Drop for ProviderIngestProcessLock {
    fn drop(&mut self) {
        if let Ok(mut held) = PROVIDER_INGEST_PROCESS_LOCKS.lock() {
            held.remove(&self.path);
        }
    }
}
fn prepare_provider_ingest_checkpoint_path(
    path: PathBuf,
) -> Result<PathBuf, ProviderIngestOutboxError> {
    let path = crate::absolute_local_checkpoint_path(&path)
        .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?;
    crate::reject_unsafe_checkpoint_ancestors(&path)
        .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?;
    let parent = path.parent().ok_or_else(|| {
        ProviderIngestOutboxError::Checkpoint(
            "provider-ingest checkpoint has no parent directory".to_owned(),
        )
    })?;
    match fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(ProviderIngestOutboxError::Checkpoint(
                "provider-ingest checkpoint parent must be a real directory".to_owned(),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            builder.mode(0o700);
            builder
                .create(parent)
                .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?;
        }
        Err(error) => {
            return Err(ProviderIngestOutboxError::Checkpoint(error.to_string()));
        }
    }
    crate::reject_unsafe_checkpoint_ancestors(&path)
        .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?;
    Ok(path)
}
fn provider_ingest_lock_path(checkpoint_path: &Path) -> Result<PathBuf, ProviderIngestOutboxError> {
    let mut file_name = checkpoint_path
        .file_name()
        .ok_or_else(|| {
            ProviderIngestOutboxError::Checkpoint(
                "provider-ingest checkpoint has no file name".to_owned(),
            )
        })?
        .to_os_string();
    file_name.push(PROVIDER_INGEST_OUTBOX_LOCK_SUFFIX_V1);
    Ok(checkpoint_path.with_file_name(file_name))
}
fn provider_ingest_directory_identity(
    path: &Path,
) -> Result<ProviderIngestDirectoryIdentity, ProviderIngestOutboxError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ProviderIngestOutboxError::Checkpoint(format!(
            "provider-ingest checkpoint parent `{}` must be a real directory",
            path.display()
        )));
    }
    Ok(ProviderIngestDirectoryIdentity {
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
    })
}
fn validate_provider_ingest_lock_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), ProviderIngestOutboxError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ProviderIngestOutboxError::Checkpoint(format!(
            "provider-ingest writer lock `{}` must be a non-symlink regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        if metadata.nlink() != 1 {
            return Err(ProviderIngestOutboxError::Checkpoint(format!(
                "provider-ingest writer lock `{}` must have exactly one hard link",
                path.display()
            )));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ProviderIngestOutboxError::Checkpoint(format!(
                "provider-ingest writer lock `{}` must not be accessible by group or other users",
                path.display()
            )));
        }
    }
    Ok(())
}
fn validate_provider_ingest_runtime_handle(value: &str) -> Result<(), ProviderIngestOutboxError> {
    if !is_production_runtime_handle(value) {
        return Err(ProviderIngestOutboxError::InvalidCheckpointProviderBinding);
    }
    Ok(())
}
fn provider_ingest_sealed_checkpoint_revision(
    record: &ProviderIngestSealedCheckpointRecordV1,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROVIDER_INGEST_SEALED_CHECKPOINT_REVISION_DOMAIN_V1);
    hasher.update(&record.namespace);
    hasher.update(&[record.version]);
    hasher.update(&record.checkpoint_sequence.to_le_bytes());
    match record.predecessor_revision {
        Some(revision) => {
            hasher.update(&[1]);
            hasher.update(&revision);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match record.predecessor_checkpoint_digest {
        Some(digest) => {
            hasher.update(&[1]);
            hasher.update(&digest);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.update(&record.checkpoint_digest);
    hasher.update(
        &u64::try_from(record.checkpoint_bytes.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(&record.checkpoint_bytes);
    *hasher.finalize().as_bytes()
}
fn provider_ingest_sealed_checkpoint_record_max_bytes(
    checkpoint_max_bytes: u64,
) -> Result<u64, ProviderIngestOutboxError> {
    if checkpoint_max_bytes == 0 {
        return Err(ProviderIngestOutboxError::InvalidPolicy);
    }
    checkpoint_max_bytes
        .checked_add(PROVIDER_INGEST_SEALED_CHECKPOINT_RECORD_MAX_OVERHEAD_BYTES_V1)
        .ok_or(ProviderIngestOutboxError::CheckpointTooLarge)
}
fn encode_provider_ingest_checkpoint(
    checkpoint: &ProviderIngestOutboxCheckpointV1,
    policy: ProviderIngestOutboxPolicyV1,
) -> Result<Vec<u8>, ProviderIngestOutboxError> {
    validate_checkpoint(checkpoint, policy)?;
    let bytes = norito::encode_canonical(checkpoint)
        .map_err(|error| ProviderIngestOutboxError::CanonicalEncoding(error.to_string()))?;
    if bytes.is_empty()
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > policy.checkpoint_max_bytes
    {
        return Err(ProviderIngestOutboxError::CheckpointTooLarge);
    }
    Ok(bytes)
}
fn decode_provider_ingest_checkpoint(
    bytes: &[u8],
    policy: ProviderIngestOutboxPolicyV1,
) -> Result<ProviderIngestOutboxCheckpointV1, ProviderIngestOutboxError> {
    if bytes.is_empty()
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > policy.checkpoint_max_bytes
    {
        return Err(ProviderIngestOutboxError::CheckpointTooLarge);
    }
    let element_limit = bytes
        .len()
        .checked_mul(4)
        .ok_or(ProviderIngestOutboxError::CheckpointTooLarge)?
        .max(1);
    let checkpoint =
        crate::decode_local_checkpoint_canonical(bytes, policy.checkpoint_max_bytes, element_limit)
            .map_err(|_| ProviderIngestOutboxError::InvalidCheckpoint)?;
    validate_checkpoint(&checkpoint, policy)?;
    Ok(checkpoint)
}
impl ProviderIngestCheckpointAuthority {
    fn try_new(
        binding: ProviderIngestCheckpointProviderBindingV1,
        runtime: Arc<dyn ProviderIngestCheckpointRuntimeV1>,
        operation_timeout: Duration,
        writer_lock_lease: Arc<ProviderIngestWriterLock>,
    ) -> Result<Self, ProviderIngestOutboxError> {
        binding.validate()?;
        let worker = Arc::new(ProviderIngestCheckpointWorker::try_new(
            runtime,
            operation_timeout,
            writer_lock_lease,
        )?);
        let authority = Self { binding, worker };
        authority.assert_identity()?;
        authority.assert_identity()?;
        Ok(authority)
    }
    fn assert_identity(&self) -> Result<(), ProviderIngestOutboxError> {
        self.binding.validate()?;
        let response = self
            .worker
            .call(ProviderIngestCheckpointWorkerOperation::Qualification)?;
        let ProviderIngestCheckpointWorkerResponse::Qualification(qualification) = response else {
            return Err(ProviderIngestOutboxError::CheckpointProviderUnavailable);
        };
        let identity = qualification?;
        validate_provider_ingest_runtime_handle(&identity.handle_before)
            .map_err(|_| ProviderIngestOutboxError::CheckpointProviderIdentityMismatch)?;
        validate_provider_ingest_runtime_handle(&identity.handle_after)
            .map_err(|_| ProviderIngestOutboxError::CheckpointProviderIdentityMismatch)?;
        identity
            .qualification
            .validate()
            .map_err(|_| ProviderIngestOutboxError::CheckpointProviderIdentityMismatch)?;
        if identity.handle_before != self.binding.handle
            || identity.handle_after != self.binding.handle
            || identity.handle_before != identity.handle_after
            || identity.qualification != self.binding.qualification()
        {
            return Err(ProviderIngestOutboxError::CheckpointProviderIdentityMismatch);
        }
        Ok(())
    }
    fn load_latest(
        &self,
        checkpoint_max_bytes: u64,
    ) -> Result<Option<ProviderIngestSealedCheckpointRecordV1>, ProviderIngestOutboxError> {
        self.assert_identity()?;
        let response = self
            .worker
            .call(ProviderIngestCheckpointWorkerOperation::LoadLatest)?;
        self.assert_identity()?;
        let ProviderIngestCheckpointWorkerResponse::LoadLatest(result) = response else {
            return Err(ProviderIngestOutboxError::CheckpointProviderUnavailable);
        };
        let record = (*result)?;
        if let Some(record) = &record {
            let canonical = record.to_canonical_bytes(checkpoint_max_bytes)?;
            if ProviderIngestSealedCheckpointRecordV1::from_canonical_bytes(
                &canonical,
                checkpoint_max_bytes,
            )? != *record
            {
                return Err(ProviderIngestOutboxError::InvalidSealedCheckpoint);
            }
        }
        Ok(record)
    }
    fn compare_and_swap(
        &self,
        checkpoint_max_bytes: u64,
        expected: Option<&ProviderIngestSealedCheckpointRecordV1>,
        next: &ProviderIngestSealedCheckpointRecordV1,
    ) -> Result<(), ProviderIngestOutboxError> {
        next.to_canonical_bytes(checkpoint_max_bytes)?;
        self.assert_identity()?;
        let current = self.load_latest(checkpoint_max_bytes)?;
        if current.as_ref() != expected {
            return Err(ProviderIngestOutboxError::CheckpointFork);
        }
        let expected_revision = expected.map(|record| record.revision);
        let result = self
            .worker
            .call(ProviderIngestCheckpointWorkerOperation::CompareAndSwap {
                expected_revision,
                next: Box::new(next.clone()),
            });
        let result = match result {
            Ok(ProviderIngestCheckpointWorkerResponse::CompareAndSwap(result)) => result,
            Ok(_) => return Err(ProviderIngestOutboxError::CheckpointProviderUnavailable),
            Err(ProviderIngestOutboxError::CheckpointProviderResponseLost) => {
                return Err(ProviderIngestOutboxError::CheckpointAuthorityAmbiguous);
            }
            Err(error) => return Err(error),
        };
        if let Err(identity_error) = self.assert_identity() {
            if identity_error == ProviderIngestOutboxError::CheckpointProviderTimeout {
                return Err(identity_error);
            }
            return Err(
                if matches!(
                    result,
                    Ok(()) | Err(ProviderIngestCheckpointExternalErrorV1::Ambiguous)
                ) {
                    ProviderIngestOutboxError::CheckpointAuthorityAmbiguous
                } else {
                    identity_error
                },
            );
        }
        match result {
            Err(ProviderIngestCheckpointExternalErrorV1::Unavailable) => {
                return Err(ProviderIngestOutboxError::CheckpointProviderUnavailable);
            }
            Err(ProviderIngestCheckpointExternalErrorV1::Rejected) => {
                return Err(ProviderIngestOutboxError::CheckpointProviderRejected);
            }
            Ok(()) | Err(ProviderIngestCheckpointExternalErrorV1::Ambiguous) => {}
        }
        let readback = match self.load_latest(checkpoint_max_bytes) {
            Ok(readback) => readback,
            Err(ProviderIngestOutboxError::CheckpointProviderTimeout) => {
                return Err(ProviderIngestOutboxError::CheckpointProviderTimeout);
            }
            Err(_) => return Err(ProviderIngestOutboxError::CheckpointAuthorityAmbiguous),
        };
        if readback.as_ref() == Some(next) {
            return Ok(());
        }
        if readback.as_ref() == expected {
            return Err(ProviderIngestOutboxError::CheckpointCasUnchanged);
        }
        Err(ProviderIngestOutboxError::CheckpointAuthorityAmbiguous)
    }
}
impl ProviderIngestOutbox {
    /// Construct a non-persistent outbox for crate-internal composition tests.
    #[cfg(test)]
    pub(crate) fn in_memory(
        policy: ProviderIngestOutboxPolicyV1,
    ) -> Result<Self, ProviderIngestOutboxError> {
        policy.validate()?;
        Ok(Self {
            path: None,
            writer_lock: None,
            checkpoint_authority: None,
            policy,
            state: Arc::new(Mutex::new(ProviderIngestOutboxState {
                checkpoint: ProviderIngestOutboxCheckpointV1::default(),
                sealed_record: None,
                aggregate_counts: ProviderIngestOutboxCountsV1::default(),
                durability_failure: None,
            })),
        })
    }
    /// Open a local-only bounded checkpoint for crate-internal composition tests.
    ///
    /// The standard daemon never selects this constructor. Production provider
    /// ingest must use [`Self::open_with_checkpoint_authority`].
    #[cfg(test)]
    pub(crate) fn open(
        path: impl Into<PathBuf>,
        policy: ProviderIngestOutboxPolicyV1,
    ) -> Result<Self, ProviderIngestOutboxError> {
        policy.validate()?;
        let path = prepare_provider_ingest_checkpoint_path(path.into())?;
        let writer_lock = Arc::new(ProviderIngestWriterLock::acquire(&path)?);
        let checkpoint = match read_local_checkpoint_bounded(&path, policy.checkpoint_max_bytes)
            .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?
        {
            Some(bytes) => decode_provider_ingest_checkpoint(&bytes, policy)?,
            None => ProviderIngestOutboxCheckpointV1::default(),
        };
        let aggregate_counts = checkpoint_counts(&checkpoint);
        Ok(Self {
            path: Some(Arc::new(path)),
            writer_lock: Some(writer_lock),
            checkpoint_authority: None,
            policy,
            state: Arc::new(Mutex::new(ProviderIngestOutboxState {
                checkpoint,
                sealed_record: None,
                aggregate_counts,
                durability_failure: None,
            })),
        })
    }
    /// Open a production outbox whose external sealed head is authoritative.
    ///
    /// The local file is only a revalidated cache. It may be absent or exactly
    /// one committed predecessor behind the sealed head, but it can never seed,
    /// replace, or override external state.
    ///
    /// # Errors
    ///
    /// Fails closed for missing, stale, substituted, test-marked, unavailable,
    /// forked, rolled-back, malformed, or durability-ambiguous state.
    pub fn open_with_checkpoint_authority(
        path: impl Into<PathBuf>,
        policy: ProviderIngestOutboxPolicyV1,
        binding: ProviderIngestCheckpointProviderBindingV1,
        runtime: Arc<dyn ProviderIngestCheckpointRuntimeV1>,
    ) -> Result<Self, ProviderIngestOutboxError> {
        policy.validate()?;
        let path = prepare_provider_ingest_checkpoint_path(path.into())?;
        let writer_lock = Arc::new(ProviderIngestWriterLock::acquire(&path)?);
        let authority = ProviderIngestCheckpointAuthority::try_new(
            binding,
            runtime,
            Duration::from_millis(policy.checkpoint_operation_timeout_ms),
            Arc::clone(&writer_lock),
        )?;
        let record_max_bytes =
            provider_ingest_sealed_checkpoint_record_max_bytes(policy.checkpoint_max_bytes)?;
        let local_record = read_local_checkpoint_bounded(&path, record_max_bytes)
            .map_err(|error| ProviderIngestOutboxError::Checkpoint(error.to_string()))?
            .map(|bytes| {
                ProviderIngestSealedCheckpointRecordV1::from_canonical_bytes(
                    &bytes,
                    policy.checkpoint_max_bytes,
                )
            })
            .transpose()?;
        let sealed_record = authority.load_latest(policy.checkpoint_max_bytes)?;
        let (sealed_record, checkpoint, rewrite_cache) =
            match (local_record.as_ref(), sealed_record) {
                (Some(_), None) => {
                    return Err(ProviderIngestOutboxError::CheckpointRollback);
                }
                (None, None) => {
                    let checkpoint = ProviderIngestOutboxCheckpointV1::default();
                    let checkpoint_bytes = encode_provider_ingest_checkpoint(&checkpoint, policy)?;
                    let record = ProviderIngestSealedCheckpointRecordV1::new(
                        1,
                        None,
                        None,
                        checkpoint_bytes,
                    );
                    authority.compare_and_swap(policy.checkpoint_max_bytes, None, &record)?;
                    (record, checkpoint, true)
                }
                (local, Some(record)) => {
                    let checkpoint =
                        decode_provider_ingest_checkpoint(&record.checkpoint_bytes, policy)?;
                    let rewrite_cache = match local {
                        None => true,
                        Some(local) if local == &record => false,
                        Some(local)
                            if record.checkpoint_sequence.checked_sub(1)
                                == Some(local.checkpoint_sequence)
                                && record.predecessor_revision == Some(local.revision)
                                && record.predecessor_checkpoint_digest
                                    == Some(local.checkpoint_digest) =>
                        {
                            true
                        }
                        Some(local) if local.checkpoint_sequence == record.checkpoint_sequence => {
                            return Err(ProviderIngestOutboxError::CheckpointFork);
                        }
                        Some(local) if local.checkpoint_sequence > record.checkpoint_sequence => {
                            return Err(ProviderIngestOutboxError::CheckpointRollback);
                        }
                        Some(_) => {
                            return Err(ProviderIngestOutboxError::CheckpointRollback);
                        }
                    };
                    (record, checkpoint, rewrite_cache)
                }
            };
        if rewrite_cache {
            let bytes = sealed_record.to_canonical_bytes(policy.checkpoint_max_bytes)?;
            write_local_checkpoint_atomic_bounded(&path, &bytes, record_max_bytes).map_err(
                |error| {
                    if error.committed {
                        ProviderIngestOutboxError::DurabilityUncertain
                    } else {
                        ProviderIngestOutboxError::Checkpoint(error.to_string())
                    }
                },
            )?;
        }
        writer_lock.validate_live(&path)?;
        authority.assert_identity()?;
        let aggregate_counts = checkpoint_counts(&checkpoint);
        Ok(Self {
            path: Some(Arc::new(path)),
            writer_lock: Some(writer_lock),
            checkpoint_authority: Some(authority),
            policy,
            state: Arc::new(Mutex::new(ProviderIngestOutboxState {
                checkpoint,
                sealed_record: Some(sealed_record),
                aggregate_counts,
                durability_failure: None,
            })),
        })
    }
    /// Return the validated policy.
    #[must_use]
    pub const fn policy(&self) -> ProviderIngestOutboxPolicyV1 {
        self.policy
    }
    /// Return the greatest finalized cursor durably observed by this outbox.
    pub fn finalized_cursor_high_water(
        &self,
    ) -> Result<Option<ProviderIngestFinalizedCursorV1>, ProviderIngestOutboxError> {
        let state = self.lock_state()?;
        Ok(
            validate_retained_finalized_snapshot(&state.checkpoint, None)?
                .map(|(cursor, _)| cursor),
        )
    }
    /// Return the finalized cursor and block time durably bound as one snapshot.
    pub fn finalized_snapshot_high_water(
        &self,
    ) -> Result<Option<(ProviderIngestFinalizedCursorV1, u64)>, ProviderIngestOutboxError> {
        let state = self.lock_state()?;
        validate_retained_finalized_snapshot(&state.checkpoint, None)
    }
    /// Durably advance one finalized cursor/time snapshot, rejecting regression,
    /// block substitution, or time equivocation for the same finalized block.
    pub fn observe_finalized_snapshot(
        &self,
        cursor: ProviderIngestFinalizedCursorV1,
        finalized_block_time_ms: u64,
    ) -> Result<(), ProviderIngestOutboxError> {
        cursor.validate()?;
        if finalized_block_time_ms == 0 {
            return Err(ProviderIngestOutboxError::InvalidFinalizedBlockTime);
        }
        let mut state = self.lock_state()?;
        if let Some((retained_cursor, retained_block_time_ms)) =
            validate_retained_finalized_snapshot(&state.checkpoint, None)?
        {
            validate_cursor_not_before(retained_cursor, cursor)?;
            if retained_cursor == cursor {
                return if retained_block_time_ms == finalized_block_time_ms {
                    Ok(())
                } else {
                    Err(ProviderIngestOutboxError::FinalizedSnapshotConflict)
                };
            }
            if finalized_block_time_ms <= retained_block_time_ms {
                return Err(ProviderIngestOutboxError::FinalizedSnapshotConflict);
            }
        }
        let mut candidate = state.checkpoint.clone();
        candidate.finalized_cursor_high_water = Some(cursor);
        candidate.finalized_block_time_ms_high_water = Some(finalized_block_time_ms);
        self.persist_candidate(&mut state, candidate)
    }
    /// Durably admit one immutable provider/order/manifest binding.
    pub fn enqueue(
        &self,
        authorization: FinalizedProviderIngestAuthorizationV1,
    ) -> Result<ProviderIngestEnqueueResultV1, ProviderIngestOutboxError> {
        authorization.validate()?;
        let job_id = authorization.job_id;
        let mut state = self.lock_state()?;
        if let Some(existing) = state
            .checkpoint
            .active
            .iter()
            .find(|entry| entry.authorization.job_id == job_id)
        {
            validate_replayed_authorization(&existing.authorization, &authorization)?;
            return Ok(ProviderIngestEnqueueResultV1::ExistingActive { job_id });
        }
        if let Some(existing) = state
            .checkpoint
            .terminal
            .iter()
            .find(|entry| entry.authorization.job_id == job_id)
        {
            validate_replayed_authorization(&existing.authorization, &authorization)?;
            return Ok(ProviderIngestEnqueueResultV1::ExistingTerminal { job_id });
        }
        if state
            .checkpoint
            .active
            .iter()
            .map(|entry| &entry.authorization)
            .chain(
                state
                    .checkpoint
                    .terminal
                    .iter()
                    .map(|entry| &entry.authorization),
            )
            .any(|existing| {
                existing.provider_id == authorization.provider_id
                    && existing.order_id == authorization.order_id
                    && !existing.same_binding(&authorization)
            })
        {
            return Err(ProviderIngestOutboxError::OrderBindingConflict);
        }
        let mut candidate = state.checkpoint.clone();
        prune_terminal_entries(
            &mut candidate,
            authorization.admission_finalized_cursor.height,
            self.policy,
        );
        if candidate.active.len() >= self.policy.max_active_entries {
            return Err(ProviderIngestOutboxError::CapacityExhausted);
        }
        let sequence = candidate.next_sequence;
        candidate.next_sequence = sequence
            .checked_add(1)
            .ok_or(ProviderIngestOutboxError::SequenceExhausted)?;
        candidate.active.push(StoredActiveProviderIngestV1 {
            sequence,
            authorization,
            source_attempts: 0,
            claim_generation: 0,
            state: StoredProviderIngestStateV1::PendingSource,
        });
        candidate.active.sort_by_key(|entry| entry.sequence);
        self.persist_candidate(&mut state, candidate)?;
        Ok(ProviderIngestEnqueueResultV1::Inserted { job_id })
    }
    /// Atomically claim the next eligible source job in admission sequence.
    #[cfg(test)]
    pub fn claim_next_source(
        &self,
        owner: ProviderIngestClaimOwnerV1,
        now_ms: u64,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> Result<Option<ProviderIngestSourceClaimV1>, ProviderIngestOutboxError> {
        observed_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let mut changed = prune_terminal_entries(
            &mut candidate,
            observed_finalized_cursor.height,
            self.policy,
        ) != 0;
        let mut position = 0;
        while position < candidate.active.len() {
            let eligibility = match &candidate.active[position].state {
                StoredProviderIngestStateV1::PendingSource => SourceEligibility::Eligible,
                StoredProviderIngestStateV1::RetryScheduled {
                    next_attempt_at_ms, ..
                } if now_ms >= *next_attempt_at_ms => SourceEligibility::Eligible,
                StoredProviderIngestStateV1::SourceClaimed {
                    lease_expires_at_ms,
                    ..
                } if now_ms >= *lease_expires_at_ms => SourceEligibility::ExpiredLease,
                StoredProviderIngestStateV1::RetryScheduled { .. }
                | StoredProviderIngestStateV1::SourceClaimed { .. }
                | StoredProviderIngestStateV1::LocalStored { .. } => SourceEligibility::Skip,
            };
            if eligibility == SourceEligibility::Skip {
                position += 1;
                continue;
            }
            validate_cursor_after_admission(
                &candidate.active[position].authorization,
                observed_finalized_cursor,
            )?;
            if eligibility == SourceEligibility::ExpiredLease {
                let attempts = increment_attempt(candidate.active[position].source_attempts)?;
                candidate.active[position].source_attempts = attempts;
                changed = true;
                if attempts >= self.policy.max_attempts {
                    move_active_to_dead_letter(
                        &mut candidate,
                        position,
                        attempts,
                        ProviderIngestDeadLetterReasonV1::RetryExhausted,
                        ProviderIngestFailureClassV1::LeaseExpired,
                        observed_finalized_cursor,
                        self.policy,
                    )?;
                    continue;
                }
            }
            let claim = install_source_claim(
                &mut candidate.active[position],
                owner,
                now_ms,
                self.policy.source_lease_ttl_ms,
            )?;
            self.persist_candidate(&mut state, candidate)?;
            return Ok(Some(claim));
        }
        if changed {
            self.persist_candidate(&mut state, candidate)?;
        }
        Ok(None)
    }
    /// Claim one exact source job, reclaiming an expired lease when bounded.
    pub fn claim_source(
        &self,
        job_id: [u8; 32],
        owner: ProviderIngestClaimOwnerV1,
        now_ms: u64,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> Result<ProviderIngestSourceClaimV1, ProviderIngestOutboxError> {
        observed_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let position = active_position(&candidate, job_id)?;
        validate_cursor_after_admission(
            &candidate.active[position].authorization,
            observed_finalized_cursor,
        )?;
        let eligibility = match &candidate.active[position].state {
            StoredProviderIngestStateV1::PendingSource => ExactSourceEligibility::Eligible,
            StoredProviderIngestStateV1::RetryScheduled {
                next_attempt_at_ms, ..
            } if now_ms >= *next_attempt_at_ms => ExactSourceEligibility::Eligible,
            StoredProviderIngestStateV1::RetryScheduled { .. } => {
                ExactSourceEligibility::RetryNotDue
            }
            StoredProviderIngestStateV1::SourceClaimed {
                lease_expires_at_ms,
                ..
            } if now_ms >= *lease_expires_at_ms => ExactSourceEligibility::ExpiredLease,
            StoredProviderIngestStateV1::SourceClaimed { .. } => ExactSourceEligibility::LeaseHeld,
            StoredProviderIngestStateV1::LocalStored { .. } => ExactSourceEligibility::LocalStored,
        };
        match eligibility {
            ExactSourceEligibility::Eligible => {}
            ExactSourceEligibility::RetryNotDue => {
                return Err(ProviderIngestOutboxError::RetryNotDue);
            }
            ExactSourceEligibility::ExpiredLease => {
                let attempts = increment_attempt(candidate.active[position].source_attempts)?;
                candidate.active[position].source_attempts = attempts;
                if attempts >= self.policy.max_attempts {
                    move_active_to_dead_letter(
                        &mut candidate,
                        position,
                        attempts,
                        ProviderIngestDeadLetterReasonV1::RetryExhausted,
                        ProviderIngestFailureClassV1::LeaseExpired,
                        observed_finalized_cursor,
                        self.policy,
                    )?;
                    self.persist_candidate(&mut state, candidate)?;
                    return Err(ProviderIngestOutboxError::RetryExhausted);
                }
            }
            ExactSourceEligibility::LeaseHeld => {
                return Err(ProviderIngestOutboxError::LeaseAlreadyHeld);
            }
            ExactSourceEligibility::LocalStored => {
                return Err(ProviderIngestOutboxError::InvalidTransition);
            }
        }
        let claim = install_source_claim(
            &mut candidate.active[position],
            owner,
            now_ms,
            self.policy.source_lease_ttl_ms,
        )?;
        self.persist_candidate(&mut state, candidate)?;
        Ok(claim)
    }
    /// Renew one exact live source claim without changing its owner or generation.
    ///
    /// The returned claim replaces the caller's previous claim. Any transition
    /// attempted with the previous lease token is rejected.
    pub fn renew_source_claim(
        &self,
        claim: &ProviderIngestSourceClaimV1,
        now_ms: u64,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> Result<ProviderIngestSourceClaimV1, ProviderIngestOutboxError> {
        observed_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let position = active_position(&candidate, claim.job_id)?;
        validate_cursor_after_admission(
            &candidate.active[position].authorization,
            observed_finalized_cursor,
        )?;
        validate_live_claim(&candidate.active[position], claim, now_ms)?;
        let requested_expiry = now_ms
            .checked_add(self.policy.source_lease_ttl_ms)
            .ok_or(ProviderIngestOutboxError::TimestampOverflow)?;
        let lease_expires_at_ms = requested_expiry.max(
            claim
                .lease_expires_at_ms
                .checked_add(1)
                .ok_or(ProviderIngestOutboxError::TimestampOverflow)?,
        );
        let lease_token = derive_lease_token(
            claim.job_id,
            claim.owner,
            claim.generation,
            lease_expires_at_ms,
        );
        candidate.active[position].state = StoredProviderIngestStateV1::SourceClaimed {
            owner: claim.owner,
            generation: claim.generation,
            lease_token,
            lease_expires_at_ms,
        };
        let renewed = ProviderIngestSourceClaimV1 {
            job_id: claim.job_id,
            owner: claim.owner,
            generation: claim.generation,
            lease_token,
            lease_expires_at_ms,
            authorization: claim.authorization.clone(),
        };
        self.persist_candidate(&mut state, candidate)?;
        Ok(renewed)
    }
    /// Persist a retryable source/storage failure under the exact live lease.
    pub fn schedule_source_retry(
        &self,
        claim: &ProviderIngestSourceClaimV1,
        now_ms: u64,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
        failure_class: ProviderIngestFailureClassV1,
    ) -> Result<ProviderIngestRetryOutcomeV1, ProviderIngestOutboxError> {
        if !failure_class.is_source_retryable() {
            return Err(ProviderIngestOutboxError::InvalidFailureClass);
        }
        observed_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let position = active_position(&candidate, claim.job_id)?;
        validate_cursor_after_admission(
            &candidate.active[position].authorization,
            observed_finalized_cursor,
        )?;
        validate_live_claim(&candidate.active[position], claim, now_ms)?;
        let attempts = increment_attempt(candidate.active[position].source_attempts)?;
        candidate.active[position].source_attempts = attempts;
        if attempts >= self.policy.max_attempts {
            move_active_to_dead_letter(
                &mut candidate,
                position,
                attempts,
                ProviderIngestDeadLetterReasonV1::RetryExhausted,
                failure_class,
                observed_finalized_cursor,
                self.policy,
            )?;
            self.persist_candidate(&mut state, candidate)?;
            return Ok(ProviderIngestRetryOutcomeV1::DeadLettered);
        }
        let next_attempt_at_ms = retry_at(now_ms, attempts, self.policy)?;
        candidate.active[position].state = StoredProviderIngestStateV1::RetryScheduled {
            next_attempt_at_ms,
            failure_class,
        };
        self.persist_candidate(&mut state, candidate)?;
        Ok(ProviderIngestRetryOutcomeV1::RetryScheduled {
            attempts,
            next_attempt_at_ms,
        })
    }
    /// Move a source claim to a permanent payload-free dead letter.
    pub fn dead_letter_source(
        &self,
        claim: &ProviderIngestSourceClaimV1,
        now_ms: u64,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
        reason: ProviderIngestDeadLetterReasonV1,
        failure_class: ProviderIngestFailureClassV1,
    ) -> Result<(), ProviderIngestOutboxError> {
        if !valid_permanent_failure_pair(reason, failure_class) {
            return Err(ProviderIngestOutboxError::InvalidTransition);
        }
        observed_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let position = active_position(&candidate, claim.job_id)?;
        validate_cursor_after_admission(
            &candidate.active[position].authorization,
            observed_finalized_cursor,
        )?;
        validate_live_claim(&candidate.active[position], claim, now_ms)?;
        let attempts = increment_attempt(candidate.active[position].source_attempts)?;
        move_active_to_dead_letter(
            &mut candidate,
            position,
            attempts,
            reason,
            failure_class,
            observed_finalized_cursor,
            self.policy,
        )?;
        self.persist_candidate(&mut state, candidate)
    }
    /// Record that exact verified bytes are present in local storage.
    pub fn mark_local_stored(
        &self,
        claim: &ProviderIngestSourceClaimV1,
        now_ms: u64,
        manifest_id: String,
    ) -> Result<(), ProviderIngestOutboxError> {
        self.mark_local_stored_verified(claim, now_ms, manifest_id, None)
    }
    /// Record exact locally stored bytes together with any mandatory Musubi verifier receipt.
    pub fn mark_local_stored_verified(
        &self,
        claim: &ProviderIngestSourceClaimV1,
        now_ms: u64,
        manifest_id: String,
        musubi_bundle: Option<ProviderIngestVerifiedMusubiBundleReceiptV1>,
    ) -> Result<(), ProviderIngestOutboxError> {
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let position = active_position(&candidate, claim.job_id)?;
        let authorization = &candidate.active[position].authorization;
        validate_manifest_id(authorization, &manifest_id)?;
        if !provided_musubi_receipt_shape_is_valid(authorization, musubi_bundle.as_ref()) {
            return Err(ProviderIngestOutboxError::InvalidAuthorization);
        }
        let musubi_bundle = musubi_bundle.map(|receipt| Box::new(receipt.to_stored()));
        if let StoredProviderIngestStateV1::LocalStored {
            manifest_id: existing,
            musubi_bundle: existing_musubi,
            ..
        } = &candidate.active[position].state
        {
            return if existing == &manifest_id && existing_musubi == &musubi_bundle {
                Ok(())
            } else {
                Err(ProviderIngestOutboxError::InvalidManifestId)
            };
        }
        validate_live_claim(&candidate.active[position], claim, now_ms)?;
        candidate.active[position].state = StoredProviderIngestStateV1::LocalStored {
            manifest_id,
            musubi_bundle,
            completion: Box::default(),
        };
        self.persist_candidate(&mut state, candidate)
    }
    /// Durably back off a failed fee quote or completion-payload construction.
    pub fn record_completion_preparation_failure(
        &self,
        job_id: [u8; 32],
        now_ms: u64,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> Result<ProviderIngestRetryOutcomeV1, ProviderIngestOutboxError> {
        self.record_completion_ready_failure(
            job_id,
            now_ms,
            observed_finalized_cursor,
            ProviderIngestFailureClassV1::PayloadPreparationFailed,
            None,
        )
    }
    /// Durably back off unavailable or rejected governed signer resolution.
    pub fn record_completion_signer_resolution_failure(
        &self,
        job_id: [u8; 32],
        now_ms: u64,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> Result<ProviderIngestRetryOutcomeV1, ProviderIngestOutboxError> {
        self.record_completion_ready_failure(
            job_id,
            now_ms,
            observed_finalized_cursor,
            ProviderIngestFailureClassV1::SignerUnavailable,
            None,
        )
    }
    /// Durably record a proved missing or revoked signer policy.
    ///
    /// When the same finalized owner previously used a governed policy, the
    /// next signing claim must carry a strict successor. A changed owner clears
    /// the prior owner's policy lineage before applying bounded backoff.
    pub(crate) fn record_completion_signer_policy_missing(
        &self,
        job_id: [u8; 32],
        current_provider_owner: &AccountId,
        now_ms: u64,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> Result<ProviderIngestRetryOutcomeV1, ProviderIngestOutboxError> {
        self.record_completion_ready_failure(
            job_id,
            now_ms,
            observed_finalized_cursor,
            ProviderIngestFailureClassV1::SignerPolicyChanged,
            Some(current_provider_owner),
        )
    }
    fn record_completion_ready_failure(
        &self,
        job_id: [u8; 32],
        now_ms: u64,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
        failure_class: ProviderIngestFailureClassV1,
        missing_policy_owner: Option<&AccountId>,
    ) -> Result<ProviderIngestRetryOutcomeV1, ProviderIngestOutboxError> {
        if now_ms == 0 {
            return Err(ProviderIngestOutboxError::InvalidRuntimeTimestamp);
        }
        if !matches!(
            failure_class,
            ProviderIngestFailureClassV1::PayloadPreparationFailed
                | ProviderIngestFailureClassV1::SignerUnavailable
                | ProviderIngestFailureClassV1::SignerPolicyChanged
        ) || (failure_class == ProviderIngestFailureClassV1::SignerPolicyChanged)
            != missing_policy_owner.is_some()
        {
            return Err(ProviderIngestOutboxError::InvalidFailureClass);
        }
        observed_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        if candidate.finalized_cursor_high_water != Some(observed_finalized_cursor) {
            return Err(ProviderIngestOutboxError::StaleFinalizedCursor);
        }
        let position = active_position(&candidate, job_id)?;
        validate_cursor_after_admission(
            &candidate.active[position].authorization,
            observed_finalized_cursor,
        )?;
        let attempts = {
            let completion = local_completion_mut(&mut candidate.active[position])?;
            if completion.state != StoredDeliveryStateV1::Ready {
                return Err(ProviderIngestOutboxError::InvalidTransition);
            }
            if let Some(current_owner) = missing_policy_owner {
                observe_finalized_completion_authority(
                    completion,
                    Some(current_owner),
                    &ProviderIngestCompletionAuthorityObservationV1::Missing,
                    observed_finalized_cursor,
                )?;
                match completion.authority_owner.as_ref() {
                    Some(retained_owner) if retained_owner == current_owner => {
                        if completion.authority_floor.is_some() {
                            completion.authority_successor_required = true;
                        }
                    }
                    Some(_) => {
                        completion.authority_owner = Some(current_owner.clone());
                        completion.authority_floor = None;
                        completion.authority_successor_required = false;
                    }
                    None => {
                        completion.authority_owner = Some(current_owner.clone());
                    }
                }
            }
            completion.attempts =
                consume_bounded_attempt(completion.attempts, self.policy.max_attempts)?;
            completion.attempts
        };
        if attempts >= self.policy.max_attempts {
            move_active_to_dead_letter(
                &mut candidate,
                position,
                attempts,
                ProviderIngestDeadLetterReasonV1::RetryExhausted,
                failure_class,
                observed_finalized_cursor,
                self.policy,
            )?;
            self.persist_candidate(&mut state, candidate)?;
            return Ok(ProviderIngestRetryOutcomeV1::DeadLettered);
        }
        let next_attempt_at_ms = retry_at(now_ms, attempts, self.policy)?;
        let completion = local_completion_mut(&mut candidate.active[position])?;
        completion.next_attempt_at_ms = next_attempt_at_ms;
        completion.last_failure_class = Some(failure_class);
        self.persist_candidate(&mut state, candidate)?;
        Ok(ProviderIngestRetryOutcomeV1::RetryScheduled {
            attempts,
            next_attempt_at_ms,
        })
    }
    /// Reconcile the finalized owner before resolving or constructing a new Ready-state completion.
    ///
    /// Policy lineages are scoped to one provider owner. A finalized owner change therefore clears
    /// the prior floor and revocation latch atomically; an unchanged owner is an idempotent no-op.
    pub(crate) fn reconcile_ready_completion_owner(
        &self,
        job_id: [u8; 32],
        current_provider_owner: &AccountId,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> Result<bool, ProviderIngestOutboxError> {
        observed_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        if candidate.finalized_cursor_high_water != Some(observed_finalized_cursor) {
            return Err(ProviderIngestOutboxError::StaleFinalizedCursor);
        }
        let position = active_position(&candidate, job_id)?;
        validate_cursor_after_admission(
            &candidate.active[position].authorization,
            observed_finalized_cursor,
        )?;
        let completion = local_completion_mut(&mut candidate.active[position])?;
        if completion.state != StoredDeliveryStateV1::Ready {
            return Err(ProviderIngestOutboxError::InvalidTransition);
        }
        let observation_changed = observe_finalized_completion_authority(
            completion,
            Some(current_provider_owner),
            &ProviderIngestCompletionAuthorityObservationV1::NotChecked,
            observed_finalized_cursor,
        )?;
        let owner_changed = completion
            .authority_owner
            .as_ref()
            .is_some_and(|owner| owner != current_provider_owner);
        if owner_changed {
            completion.authority_owner = None;
            completion.authority_floor = None;
            completion.authority_successor_required = false;
            completion.next_attempt_at_ms = 0;
            completion.last_failure_class =
                Some(ProviderIngestFailureClassV1::ProviderOwnerChanged);
        }
        if observation_changed || owner_changed {
            self.persist_candidate(&mut state, candidate)?;
        }
        Ok(owner_changed)
    }
    /// Validate the exact active completion authority for a Ready entry before fee
    /// quoting or payload construction performs any work.
    pub(crate) fn validate_ready_completion_authority(
        &self,
        job_id: [u8; 32],
        current_provider_owner: &AccountId,
        current_authority: &ProviderIngestCompletionAuthorityV1,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> Result<(), ProviderIngestOutboxError> {
        validate_completion_authority(current_authority)?;
        observed_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        if candidate.finalized_cursor_high_water != Some(observed_finalized_cursor) {
            return Err(ProviderIngestOutboxError::StaleFinalizedCursor);
        }
        let position = active_position(&candidate, job_id)?;
        validate_cursor_after_admission(
            &candidate.active[position].authorization,
            observed_finalized_cursor,
        )?;
        let completion = local_completion_mut(&mut candidate.active[position])?;
        if completion.state != StoredDeliveryStateV1::Ready
            || completion
                .authority_owner
                .as_ref()
                .is_some_and(|owner| owner != current_provider_owner)
        {
            return Err(ProviderIngestOutboxError::InvalidTransition);
        }
        validate_authority_progress(
            completion.authority_floor.clone(),
            completion.authority_successor_required,
            current_authority,
        )?;
        let observation_changed = observe_finalized_completion_authority(
            completion,
            Some(current_provider_owner),
            &ProviderIngestCompletionAuthorityObservationV1::Active(current_authority.clone()),
            observed_finalized_cursor,
        )?;
        let lineage_changed = completion.authority_owner.as_ref() != Some(current_provider_owner)
            || completion.authority_floor.as_ref() != Some(current_authority)
            || completion.authority_successor_required;
        completion.authority_owner = Some(current_provider_owner.clone());
        completion.authority_floor = Some(current_authority.clone());
        completion.authority_successor_required = false;
        if observation_changed || lineage_changed {
            self.persist_candidate(&mut state, candidate)?;
        }
        Ok(())
    }
    /// Durably claim a local-stored job for isolated completion signing.
    pub(crate) fn claim_completion_signing(
        &self,
        job_id: [u8; 32],
        context: ProviderIngestCompletionSigningContextV1,
        now_ms: u64,
    ) -> Result<ProviderIngestCompletionSigningClaimV1, ProviderIngestOutboxError> {
        if now_ms == 0 {
            return Err(ProviderIngestOutboxError::InvalidRuntimeTimestamp);
        }
        completion_signing_recover_at_ms(now_ms, self.policy)?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let finalized_cursor_high_water = candidate.finalized_cursor_high_water;
        let entry = find_active_mut(&mut candidate, job_id)?;
        validate_completion_signing_context(&entry.authorization, &context, self.policy)?;
        validate_cursor_after_admission(&entry.authorization, context.baseline_finalized_cursor)?;
        let completion = local_completion_mut(entry)?;
        if completion.state != StoredDeliveryStateV1::Ready {
            return Err(ProviderIngestOutboxError::InvalidTransition);
        }
        if finalized_cursor_high_water != Some(context.baseline_finalized_cursor) {
            return Err(ProviderIngestOutboxError::StaleFinalizedCursor);
        }
        if now_ms < completion.next_attempt_at_ms {
            return Err(ProviderIngestOutboxError::RetryNotDue);
        }
        if completion
            .authority_owner
            .as_ref()
            .is_some_and(|owner| owner != &context.expected_authority.provider_owner)
        {
            return Err(ProviderIngestOutboxError::InvalidSigningContext);
        }
        validate_authority_progress(
            completion.authority_floor.clone(),
            completion.authority_successor_required,
            &context.expected_authority,
        )?;
        observe_finalized_completion_authority(
            completion,
            Some(&context.expected_authority.provider_owner),
            &ProviderIngestCompletionAuthorityObservationV1::Active(
                context.expected_authority.clone(),
            ),
            context.baseline_finalized_cursor,
        )?;
        let generation = completion
            .signing_generation
            .checked_add(1)
            .ok_or(ProviderIngestOutboxError::SigningGenerationExhausted)?;
        completion.signing_generation = generation;
        completion.signing_claimed_at_ms = now_ms;
        completion.completion_epoch = Some(context.completion_epoch);
        completion.authority_owner = Some(context.expected_authority.provider_owner.clone());
        completion.authority_floor = Some(context.expected_authority.clone());
        completion.authority_successor_required = false;
        completion.signing_context = Some(context.clone());
        completion.last_failure_class = None;
        completion.next_attempt_at_ms = 0;
        durable::claim_for_signing(
            completion,
            finalized_cursor(context.baseline_finalized_cursor),
            self.policy.max_attempts,
        )?;
        let signing_token = derive_signing_token(job_id, generation, &context)?;
        let claim = ProviderIngestCompletionSigningClaimV1 {
            job_id,
            generation,
            signing_token,
            context,
        };
        self.persist_candidate(&mut state, candidate)?;
        Ok(claim)
    }
    /// Release a signer-only claim and durably apply bounded backoff.
    pub(crate) fn release_completion_signing(
        &self,
        claim: &ProviderIngestCompletionSigningClaimV1,
        now_ms: u64,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> Result<ProviderIngestRetryOutcomeV1, ProviderIngestOutboxError> {
        observed_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let position = active_position(&candidate, claim.job_id)?;
        validate_cursor_after_admission(
            &candidate.active[position].authorization,
            observed_finalized_cursor,
        )?;
        let attempts = {
            let completion = local_completion_mut(&mut candidate.active[position])?;
            validate_signing_claim(completion, claim)?;
            durable::release_signing_claim(completion)?;
            completion.completion_epoch = None;
            completion.signing_context = None;
            completion.transaction_hash = None;
            completion.signing_claimed_at_ms = 0;
            completion.attempts =
                consume_bounded_attempt(completion.attempts, self.policy.max_attempts)?;
            completion.attempts
        };
        if attempts >= self.policy.max_attempts {
            move_active_to_dead_letter(
                &mut candidate,
                position,
                attempts,
                ProviderIngestDeadLetterReasonV1::RetryExhausted,
                ProviderIngestFailureClassV1::SignerUnavailable,
                observed_finalized_cursor,
                self.policy,
            )?;
            self.persist_candidate(&mut state, candidate)?;
            return Ok(ProviderIngestRetryOutcomeV1::DeadLettered);
        }
        let next_attempt_at_ms = retry_at(now_ms, attempts, self.policy)?;
        let completion = local_completion_mut(&mut candidate.active[position])?;
        completion.next_attempt_at_ms = next_attempt_at_ms;
        completion.last_failure_class = Some(ProviderIngestFailureClassV1::SignerUnavailable);
        self.persist_candidate(&mut state, candidate)?;
        Ok(ProviderIngestRetryOutcomeV1::RetryScheduled {
            attempts,
            next_attempt_at_ms,
        })
    }
    /// Invalidate completion material prepared by a superseded provider owner
    /// or governed completion signer/policy.
    ///
    /// `current_provider_owner` is `None` when finalized state no longer has an owner for the
    /// provider. `current_authority` distinguishes an authority that was not queried from a proved
    /// revocation and an exact active owner/key/policy record. `observed_finalized_cursor` must be strictly newer
    /// than the retained preparation baseline when ownership or signer policy differs or is absent.
    /// Only signer-owned or provably unexposed signed material may be discarded. Ambiguous,
    /// submitted, and previously exposed signed bytes remain retained for exact-hash
    /// reconciliation. A signing-only claim consumes one attempt here; signed states have already
    /// consumed their current attempt. Matching authority, an exposed entry, or a ready entry
    /// without signing context is an idempotent no-op.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn invalidate_stale_completion_authority(
        &self,
        job_id: [u8; 32],
        current_provider_owner: Option<&AccountId>,
        current_authority: &ProviderIngestCompletionAuthorityObservationV1,
        now_ms: u64,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> Result<Option<ProviderIngestRetryOutcomeV1>, ProviderIngestOutboxError> {
        if now_ms == 0 {
            return Err(ProviderIngestOutboxError::InvalidRuntimeTimestamp);
        }
        observed_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        if candidate.finalized_cursor_high_water != Some(observed_finalized_cursor) {
            return Err(ProviderIngestOutboxError::StaleFinalizedCursor);
        }
        let position = active_position(&candidate, job_id)?;
        validate_cursor_after_admission(
            &candidate.active[position].authorization,
            observed_finalized_cursor,
        )?;
        let completion = local_completion_mut(&mut candidate.active[position])?;
        let Some(signing_context) = completion.signing_context.clone() else {
            return Ok(None);
        };
        let authority_observation_changed = observe_finalized_completion_authority(
            completion,
            current_provider_owner,
            current_authority,
            observed_finalized_cursor,
        )?;
        let owner_matches =
            current_provider_owner == Some(&signing_context.expected_authority.provider_owner);
        let policy_matches = match current_authority {
            ProviderIngestCompletionAuthorityObservationV1::NotChecked => true,
            ProviderIngestCompletionAuthorityObservationV1::Missing => false,
            ProviderIngestCompletionAuthorityObservationV1::Active(policy) => {
                validate_completion_authority(policy)?;
                policy == &signing_context.expected_authority
            }
        };
        if owner_matches && policy_matches {
            match current_authority {
                ProviderIngestCompletionAuthorityObservationV1::NotChecked => {
                    if authority_observation_changed {
                        self.persist_candidate(&mut state, candidate)?;
                    }
                    return Ok(None);
                }
                ProviderIngestCompletionAuthorityObservationV1::Active(policy)
                    if completion.authority_owner.as_ref()
                        == Some(&signing_context.expected_authority.provider_owner)
                        && completion.authority_floor.as_ref() == Some(policy)
                        && !completion.authority_successor_required =>
                {
                    if authority_observation_changed {
                        self.persist_candidate(&mut state, candidate)?;
                    }
                    return Ok(None);
                }
                ProviderIngestCompletionAuthorityObservationV1::Active(_)
                | ProviderIngestCompletionAuthorityObservationV1::Missing => {}
            }
        }
        validate_cursor_after_baseline(completion, observed_finalized_cursor)?;
        if matches!(
            completion.state,
            StoredDeliveryStateV1::Ambiguous | StoredDeliveryStateV1::Submitted
        ) || (completion.state == StoredDeliveryStateV1::Signed && completion.ever_exposed)
        {
            let retained = (
                completion.authority_owner.clone(),
                completion.authority_floor.clone(),
                completion.authority_successor_required,
            );
            match current_provider_owner {
                None => {
                    completion.authority_owner = None;
                    completion.authority_floor = None;
                    completion.authority_successor_required = false;
                }
                Some(owner) if owner == &signing_context.expected_authority.provider_owner => {
                    match current_authority {
                        ProviderIngestCompletionAuthorityObservationV1::NotChecked => {}
                        ProviderIngestCompletionAuthorityObservationV1::Missing => {
                            let floor = if completion.authority_owner.as_ref() == Some(owner) {
                                completion
                                    .authority_floor
                                    .clone()
                                    .or(Some(signing_context.expected_authority.clone()))
                            } else {
                                Some(signing_context.expected_authority.clone())
                            };
                            completion.authority_owner = Some(owner.clone());
                            completion.authority_floor = floor;
                            completion.authority_successor_required = true;
                        }
                        ProviderIngestCompletionAuthorityObservationV1::Active(policy) => {
                            let same_latched_owner =
                                completion.authority_owner.as_ref() == Some(owner);
                            validate_authority_progress(
                                same_latched_owner
                                    .then_some(completion.authority_floor.clone())
                                    .flatten(),
                                same_latched_owner && completion.authority_successor_required,
                                policy,
                            )?;
                            completion.authority_owner = Some(owner.clone());
                            completion.authority_floor = Some(policy.clone());
                            completion.authority_successor_required = false;
                        }
                    }
                }
                Some(owner) => match current_authority {
                    ProviderIngestCompletionAuthorityObservationV1::Active(policy) => {
                        let same_latched_owner = completion.authority_owner.as_ref() == Some(owner);
                        validate_authority_progress(
                            same_latched_owner
                                .then_some(completion.authority_floor.clone())
                                .flatten(),
                            same_latched_owner && completion.authority_successor_required,
                            policy,
                        )?;
                        completion.authority_owner = Some(owner.clone());
                        completion.authority_floor = Some(policy.clone());
                        completion.authority_successor_required = false;
                    }
                    ProviderIngestCompletionAuthorityObservationV1::Missing => {
                        let same_latched_owner = completion.authority_owner.as_ref() == Some(owner);
                        if !same_latched_owner {
                            completion.authority_owner = Some(owner.clone());
                            completion.authority_floor = None;
                        }
                        completion.authority_successor_required =
                            same_latched_owner && completion.authority_floor.is_some();
                    }
                    ProviderIngestCompletionAuthorityObservationV1::NotChecked
                        if completion.authority_owner.as_ref() == Some(owner) => {}
                    ProviderIngestCompletionAuthorityObservationV1::NotChecked => {
                        completion.authority_owner = Some(owner.clone());
                        completion.authority_floor = None;
                        completion.authority_successor_required = false;
                    }
                },
            }
            if authority_observation_changed
                || retained
                    != (
                        completion.authority_owner.clone(),
                        completion.authority_floor.clone(),
                        completion.authority_successor_required,
                    )
            {
                self.persist_candidate(&mut state, candidate)?;
            }
            return Ok(None);
        }
        let failure_class = if owner_matches {
            ProviderIngestFailureClassV1::SignerPolicyChanged
        } else {
            ProviderIngestFailureClassV1::ProviderOwnerChanged
        };
        let (next_authority_floor, authority_successor_required) = if owner_matches {
            match current_authority {
                ProviderIngestCompletionAuthorityObservationV1::Active(policy) => {
                    validate_authority_progress(
                        Some(signing_context.expected_authority.clone()),
                        true,
                        policy,
                    )?;
                    (Some(policy.clone()), false)
                }
                ProviderIngestCompletionAuthorityObservationV1::Missing => {
                    (Some(signing_context.expected_authority.clone()), true)
                }
                ProviderIngestCompletionAuthorityObservationV1::NotChecked => {
                    return Err(ProviderIngestOutboxError::InvalidCheckpoint);
                }
            }
        } else {
            (None, false)
        };
        let attempts = match completion.state {
            StoredDeliveryStateV1::Signing => {
                durable::release_signing_claim(completion)?;
                completion.attempts =
                    consume_bounded_attempt(completion.attempts, self.policy.max_attempts)?;
                completion.attempts
            }
            StoredDeliveryStateV1::Signed => {
                let attempts = completion.attempts;
                let _ = durable::mark_transaction_rejected(completion, self.policy.max_attempts);
                attempts
            }
            StoredDeliveryStateV1::Ready
            | StoredDeliveryStateV1::Ambiguous
            | StoredDeliveryStateV1::Submitted => {
                return Err(ProviderIngestOutboxError::InvalidCheckpoint);
            }
        };
        clear_completion_signing_material(completion);
        completion.authority_owner = if owner_matches {
            current_provider_owner.cloned()
        } else {
            None
        };
        completion.authority_floor = next_authority_floor;
        completion.authority_successor_required = authority_successor_required;
        if attempts >= self.policy.max_attempts {
            move_active_to_dead_letter(
                &mut candidate,
                position,
                attempts,
                ProviderIngestDeadLetterReasonV1::RetryExhausted,
                failure_class,
                observed_finalized_cursor,
                self.policy,
            )?;
            self.persist_candidate(&mut state, candidate)?;
            return Ok(Some(ProviderIngestRetryOutcomeV1::DeadLettered));
        }
        let next_attempt_at_ms = retry_at(now_ms, attempts, self.policy)?;
        let completion = local_completion_mut(&mut candidate.active[position])?;
        completion.next_attempt_at_ms = next_attempt_at_ms;
        completion.last_failure_class = Some(failure_class);
        self.persist_candidate(&mut state, candidate)?;
        Ok(Some(ProviderIngestRetryOutcomeV1::RetryScheduled {
            attempts,
            next_attempt_at_ms,
        }))
    }
    /// Recover signer-only claims whose bounded in-process lease elapsed.
    ///
    /// This is safe after a worker task is aborted because signer-only claims
    /// cannot submit. A live claim remains protected until twice the source
    /// lease TTL, which is longer than the default resolver-plus-signer budget.
    pub fn recover_expired_completion_signing(
        &self,
        now_ms: u64,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> Result<usize, ProviderIngestOutboxError> {
        if now_ms == 0 {
            return Err(ProviderIngestOutboxError::InvalidRuntimeTimestamp);
        }
        observed_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let mut recovered = 0usize;
        let mut position = 0usize;
        while position < candidate.active.len() {
            let recover_at_ms = match &candidate.active[position].state {
                StoredProviderIngestStateV1::LocalStored { completion, .. }
                    if completion.state == StoredDeliveryStateV1::Signing =>
                {
                    completion_signing_recover_at_ms(completion.signing_claimed_at_ms, self.policy)?
                }
                StoredProviderIngestStateV1::PendingSource
                | StoredProviderIngestStateV1::SourceClaimed { .. }
                | StoredProviderIngestStateV1::RetryScheduled { .. }
                | StoredProviderIngestStateV1::LocalStored { .. } => {
                    position += 1;
                    continue;
                }
            };
            if now_ms < recover_at_ms {
                position += 1;
                continue;
            }
            validate_cursor_after_admission(
                &candidate.active[position].authorization,
                observed_finalized_cursor,
            )?;
            let attempts = {
                let completion = local_completion_mut(&mut candidate.active[position])?;
                if !durable::recover_interrupted_signing(completion) {
                    return Err(ProviderIngestOutboxError::InvalidTransition);
                }
                completion.completion_epoch = None;
                completion.signing_context = None;
                completion.transaction_hash = None;
                completion.ever_exposed = false;
                normalize_authority_lineage(completion);
                completion.signing_claimed_at_ms = 0;
                completion.attempts =
                    consume_bounded_attempt(completion.attempts, self.policy.max_attempts)?;
                completion.attempts
            };
            recovered = recovered.saturating_add(1);
            if attempts >= self.policy.max_attempts {
                move_active_to_dead_letter(
                    &mut candidate,
                    position,
                    attempts,
                    ProviderIngestDeadLetterReasonV1::RetryExhausted,
                    ProviderIngestFailureClassV1::SignerUnavailable,
                    observed_finalized_cursor,
                    self.policy,
                )?;
                continue;
            }
            let next_attempt_at_ms = retry_at(now_ms, attempts, self.policy)?;
            let completion = local_completion_mut(&mut candidate.active[position])?;
            completion.next_attempt_at_ms = next_attempt_at_ms;
            completion.last_failure_class = Some(ProviderIngestFailureClassV1::SignerUnavailable);
            position += 1;
        }
        if recovered != 0 {
            self.persist_candidate(&mut state, candidate)?;
        }
        Ok(recovered)
    }
    /// Persist the exact provider-specific signed completion transaction.
    pub fn store_completion_transaction(
        &self,
        claim: &ProviderIngestCompletionSigningClaimV1,
        transaction: SignedTransaction,
    ) -> Result<[u8; 32], ProviderIngestOutboxError> {
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let entry = find_active_mut(&mut candidate, claim.job_id)?;
        let authorization = entry.authorization.clone();
        let completion = local_completion_mut(entry)?;
        validate_signing_claim(completion, claim)?;
        let transaction_hash = validate_completion_transaction(
            &authorization,
            &claim.context,
            &transaction,
            self.policy,
        )?;
        durable::store_signed_transaction(completion, transaction)?;
        completion.signing_claimed_at_ms = 0;
        completion.transaction_hash = Some(transaction_hash);
        completion.next_attempt_at_ms = 0;
        completion.last_failure_class = None;
        self.persist_candidate(&mut state, candidate)?;
        Ok(transaction_hash)
    }
    /// Read exact bytes for preflight only when their retained signing context
    /// still matches the current finalized owner and governed signer policy.
    ///
    /// The exposure transition repeats these checks atomically after preflight
    /// so authority changes during an async queue preparation remain fail-closed.
    pub(crate) fn completion_transaction_for_authorized_preflight(
        &self,
        job_id: [u8; 32],
        current_provider_owner: &AccountId,
        current_authority: &ProviderIngestCompletionAuthorityV1,
        checked_finalized_cursor: ProviderIngestFinalizedCursorV1,
        now_ms: u64,
    ) -> Result<ProviderIngestCompletionSubmissionV1, ProviderIngestOutboxError> {
        if now_ms == 0 {
            return Err(ProviderIngestOutboxError::InvalidRuntimeTimestamp);
        }
        validate_completion_authority(current_authority)?;
        checked_finalized_cursor.validate()?;
        let state = self.lock_state()?;
        if state.checkpoint.finalized_cursor_high_water != Some(checked_finalized_cursor) {
            return Err(ProviderIngestOutboxError::StaleFinalizedCursor);
        }
        let entry = state
            .checkpoint
            .active
            .iter()
            .find(|entry| entry.authorization.job_id == job_id)
            .ok_or(ProviderIngestOutboxError::UnknownJob)?;
        validate_cursor_after_admission(&entry.authorization, checked_finalized_cursor)?;
        let StoredProviderIngestStateV1::LocalStored { completion, .. } = &entry.state else {
            return Err(ProviderIngestOutboxError::InvalidTransition);
        };
        validate_completion_submission_authority(
            completion,
            current_provider_owner,
            current_authority,
            checked_finalized_cursor,
        )?;
        if now_ms < completion.next_attempt_at_ms {
            return Err(ProviderIngestOutboxError::RetryNotDue);
        }
        let transaction_hash = completion
            .transaction_hash
            .ok_or(ProviderIngestOutboxError::InvalidCheckpoint)?;
        let signed_transaction = completion
            .signed_transaction
            .clone()
            .ok_or(ProviderIngestOutboxError::InvalidCheckpoint)?;
        Ok(ProviderIngestCompletionSubmissionV1 {
            job_id,
            transaction_hash,
            signed_transaction,
        })
    }
    /// Durably back off an ingress preflight that failed before exposure.
    pub(crate) fn mark_completion_preflight_unavailable(
        &self,
        job_id: [u8; 32],
        expected_transaction_hash: [u8; 32],
        now_ms: u64,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> Result<ProviderIngestRetryOutcomeV1, ProviderIngestOutboxError> {
        if now_ms == 0 {
            return Err(ProviderIngestOutboxError::InvalidRuntimeTimestamp);
        }
        observed_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        if candidate.finalized_cursor_high_water != Some(observed_finalized_cursor) {
            return Err(ProviderIngestOutboxError::StaleFinalizedCursor);
        }
        let position = active_position(&candidate, job_id)?;
        validate_cursor_after_admission(
            &candidate.active[position].authorization,
            observed_finalized_cursor,
        )?;
        let attempts = {
            let completion = local_completion_mut(&mut candidate.active[position])?;
            require_transaction_hash(completion, expected_transaction_hash)?;
            if completion.state != StoredDeliveryStateV1::Signed {
                return Err(ProviderIngestOutboxError::InvalidTransition);
            }
            completion.attempts =
                consume_bounded_attempt(completion.attempts, self.policy.max_attempts)?;
            completion.attempts
        };
        if attempts >= self.policy.max_attempts {
            move_active_to_dead_letter(
                &mut candidate,
                position,
                attempts,
                ProviderIngestDeadLetterReasonV1::RetryExhausted,
                ProviderIngestFailureClassV1::SubmissionUnavailable,
                observed_finalized_cursor,
                self.policy,
            )?;
            self.persist_candidate(&mut state, candidate)?;
            return Ok(ProviderIngestRetryOutcomeV1::DeadLettered);
        }
        let next_attempt_at_ms = retry_at(now_ms, attempts, self.policy)?;
        let completion = local_completion_mut(&mut candidate.active[position])?;
        completion.next_attempt_at_ms = next_attempt_at_ms;
        completion.last_failure_class = Some(ProviderIngestFailureClassV1::SubmissionUnavailable);
        self.persist_candidate(&mut state, candidate)?;
        Ok(ProviderIngestRetryOutcomeV1::RetryScheduled {
            attempts,
            next_attempt_at_ms,
        })
    }
    /// Handle terminal rejection in queue preflight.
    ///
    /// Never-exposed bytes may be discarded and re-signed. Bytes exposed by an earlier attempt
    /// remain quarantined under their exact hash and receive bounded backoff instead.
    pub(crate) fn mark_completion_preflight_rejected(
        &self,
        job_id: [u8; 32],
        expected_transaction_hash: [u8; 32],
        now_ms: u64,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> Result<ProviderIngestRetryOutcomeV1, ProviderIngestOutboxError> {
        if now_ms == 0 {
            return Err(ProviderIngestOutboxError::InvalidRuntimeTimestamp);
        }
        observed_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        if candidate.finalized_cursor_high_water != Some(observed_finalized_cursor) {
            return Err(ProviderIngestOutboxError::StaleFinalizedCursor);
        }
        let position = active_position(&candidate, job_id)?;
        validate_cursor_after_admission(
            &candidate.active[position].authorization,
            observed_finalized_cursor,
        )?;
        let attempts = {
            let completion = local_completion_mut(&mut candidate.active[position])?;
            require_transaction_hash(completion, expected_transaction_hash)?;
            if completion.state != StoredDeliveryStateV1::Signed {
                return Err(ProviderIngestOutboxError::InvalidTransition);
            }
            if completion.ever_exposed {
                completion.attempts =
                    consume_bounded_attempt(completion.attempts, self.policy.max_attempts)?;
                completion.attempts
            } else {
                let attempts = completion.attempts;
                if durable::mark_transaction_rejected(completion, self.policy.max_attempts)
                    == RetryBoundOutcome::Pending
                {
                    completion.completion_epoch = None;
                    completion.signing_context = None;
                    completion.transaction_hash = None;
                    completion.ever_exposed = false;
                    normalize_authority_lineage(completion);
                }
                attempts
            }
        };
        if attempts >= self.policy.max_attempts {
            move_active_to_dead_letter(
                &mut candidate,
                position,
                attempts,
                ProviderIngestDeadLetterReasonV1::RetryExhausted,
                ProviderIngestFailureClassV1::TransactionRejected,
                observed_finalized_cursor,
                self.policy,
            )?;
            self.persist_candidate(&mut state, candidate)?;
            return Ok(ProviderIngestRetryOutcomeV1::DeadLettered);
        }
        let next_attempt_at_ms = retry_at(now_ms, attempts, self.policy)?;
        let completion = local_completion_mut(&mut candidate.active[position])?;
        completion.next_attempt_at_ms = next_attempt_at_ms;
        completion.last_failure_class = Some(ProviderIngestFailureClassV1::TransactionRejected);
        self.persist_candidate(&mut state, candidate)?;
        Ok(ProviderIngestRetryOutcomeV1::RetryScheduled {
            attempts,
            next_attempt_at_ms,
        })
    }
    /// Atomically authorize current finalized signing authority and enter the
    /// ambiguous crash state before exposing exact bytes to a queue.
    pub(crate) fn authorize_and_begin_completion_submission(
        &self,
        job_id: [u8; 32],
        expected_transaction_hash: [u8; 32],
        current_provider_owner: &AccountId,
        current_authority: &ProviderIngestCompletionAuthorityV1,
        checked_finalized_cursor: ProviderIngestFinalizedCursorV1,
        now_ms: u64,
    ) -> Result<ProviderIngestCompletionSubmissionV1, ProviderIngestOutboxError> {
        if now_ms == 0 {
            return Err(ProviderIngestOutboxError::InvalidRuntimeTimestamp);
        }
        validate_completion_authority(current_authority)?;
        checked_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        if candidate.finalized_cursor_high_water != Some(checked_finalized_cursor) {
            return Err(ProviderIngestOutboxError::StaleFinalizedCursor);
        }
        let entry = find_active_mut(&mut candidate, job_id)?;
        validate_cursor_after_admission(&entry.authorization, checked_finalized_cursor)?;
        let completion = local_completion_mut(entry)?;
        require_transaction_hash(completion, expected_transaction_hash)?;
        validate_completion_submission_authority(
            completion,
            current_provider_owner,
            current_authority,
            checked_finalized_cursor,
        )?;
        if now_ms < completion.next_attempt_at_ms {
            return Err(ProviderIngestOutboxError::RetryNotDue);
        }
        let signed_transaction = durable::begin_submission(completion)?;
        completion.ever_exposed = true;
        completion.next_attempt_at_ms = 0;
        completion.last_failure_class = None;
        self.persist_candidate(&mut state, candidate)?;
        Ok(ProviderIngestCompletionSubmissionV1 {
            job_id,
            transaction_hash: expected_transaction_hash,
            signed_transaction,
        })
    }
    /// Record that the exact transaction is known pending or applied.
    pub(crate) fn mark_completion_submitted(
        &self,
        job_id: [u8; 32],
        expected_transaction_hash: [u8; 32],
    ) -> Result<(), ProviderIngestOutboxError> {
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let completion = local_completion_mut(find_active_mut(&mut candidate, job_id)?)?;
        require_transaction_hash(completion, expected_transaction_hash)?;
        if completion.state == StoredDeliveryStateV1::Submitted {
            return Ok(());
        }
        durable::mark_submitted(completion)?;
        self.persist_candidate(&mut state, candidate)
    }
    /// Retain an already-exposed exact transaction after observation proves it
    /// pending or committed at the transaction layer.
    pub(crate) fn mark_exposed_completion_observed(
        &self,
        job_id: [u8; 32],
        expected_transaction_hash: [u8; 32],
    ) -> Result<(), ProviderIngestOutboxError> {
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let completion = local_completion_mut(find_active_mut(&mut candidate, job_id)?)?;
        require_transaction_hash(completion, expected_transaction_hash)?;
        if completion.state == StoredDeliveryStateV1::Submitted {
            return Ok(());
        }
        match completion.state {
            StoredDeliveryStateV1::Ambiguous => {
                durable::mark_submitted(completion)?;
            }
            StoredDeliveryStateV1::Signed if completion.ever_exposed => {
                completion.state = StoredDeliveryStateV1::Submitted;
                completion.next_attempt_at_ms = 0;
                completion.last_failure_class = None;
            }
            StoredDeliveryStateV1::Ready
            | StoredDeliveryStateV1::Signing
            | StoredDeliveryStateV1::Signed => {
                return Err(ProviderIngestOutboxError::InvalidTransition);
            }
            StoredDeliveryStateV1::Submitted => return Ok(()),
        }
        self.persist_candidate(&mut state, candidate)
    }
    /// Discard a previously exposed signed transaction only after its signed
    /// TTL elapsed and a strictly newer finalized cursor still proves it
    /// absent. This is the safe rotation escape hatch for quarantined bytes.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn expire_absent_exposed_completion(
        &self,
        request: ProviderIngestExposedCompletionExpiryV1<'_>,
    ) -> Result<Option<ProviderIngestRetryOutcomeV1>, ProviderIngestOutboxError> {
        let ProviderIngestExposedCompletionExpiryV1 {
            job_id,
            expected_transaction_hash,
            current_provider_owner,
            current_authority,
            runtime_now_ms,
            finalized_block_time_ms,
            observed_finalized_cursor,
        } = request;
        if runtime_now_ms == 0 || finalized_block_time_ms == 0 {
            return Err(ProviderIngestOutboxError::InvalidRuntimeTimestamp);
        }
        observed_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        if candidate.finalized_cursor_high_water != Some(observed_finalized_cursor) {
            return Err(ProviderIngestOutboxError::StaleFinalizedCursor);
        }
        if candidate.finalized_block_time_ms_high_water != Some(finalized_block_time_ms) {
            return Err(ProviderIngestOutboxError::FinalizedSnapshotConflict);
        }
        let position = active_position(&candidate, job_id)?;
        validate_cursor_after_admission(
            &candidate.active[position].authorization,
            observed_finalized_cursor,
        )?;
        let (attempts, next_authority_owner, next_authority_floor, successor_required) = {
            let completion = local_completion_mut(&mut candidate.active[position])?;
            require_transaction_hash(completion, expected_transaction_hash)?;
            if completion.state != StoredDeliveryStateV1::Signed || !completion.ever_exposed {
                return Err(ProviderIngestOutboxError::InvalidTransition);
            }
            validate_finalized_completion_authority_matches(
                completion,
                current_provider_owner,
                current_authority,
                observed_finalized_cursor,
            )?;
            if observed_finalized_cursor.height <= completion.baseline_finalized_height {
                return Ok(None);
            }
            let transaction = completion
                .signed_transaction
                .as_ref()
                .ok_or(ProviderIngestOutboxError::InvalidCheckpoint)?;
            let creation_ms = u64::try_from(transaction.creation_time().as_millis())
                .map_err(|_| ProviderIngestOutboxError::TimestampOverflow)?;
            let ttl_ms = u64::try_from(
                transaction
                    .time_to_live()
                    .ok_or(ProviderIngestOutboxError::InvalidCheckpoint)?
                    .as_millis(),
            )
            .map_err(|_| ProviderIngestOutboxError::TimestampOverflow)?;
            let expires_at_ms = creation_ms
                .checked_add(ttl_ms)
                .ok_or(ProviderIngestOutboxError::TimestampOverflow)?;
            if finalized_block_time_ms <= expires_at_ms {
                return Ok(None);
            }
            let context = completion
                .signing_context
                .as_ref()
                .ok_or(ProviderIngestOutboxError::InvalidCheckpoint)?
                .clone();
            let (next_owner, next_floor, successor_required) = match current_provider_owner {
                None => (None, None, false),
                Some(owner) => {
                    let same_latched_owner = completion.authority_owner.as_ref() == Some(owner);
                    match current_authority {
                        ProviderIngestCompletionAuthorityObservationV1::Active(policy) => {
                            validate_authority_progress(
                                if same_latched_owner {
                                    completion.authority_floor.clone()
                                } else {
                                    None
                                },
                                same_latched_owner && completion.authority_successor_required,
                                policy,
                            )?;
                            (Some(owner.clone()), Some(policy.clone()), false)
                        }
                        ProviderIngestCompletionAuthorityObservationV1::Missing => {
                            let floor = if same_latched_owner {
                                completion.authority_floor.clone()
                            } else if owner == &context.expected_authority.provider_owner {
                                Some(context.expected_authority.clone())
                            } else {
                                None
                            };
                            (
                                floor.as_ref().map(|_| owner.clone()),
                                floor.clone(),
                                floor.is_some(),
                            )
                        }
                        ProviderIngestCompletionAuthorityObservationV1::NotChecked => {
                            return Err(ProviderIngestOutboxError::InvalidCheckpoint);
                        }
                    }
                }
            };
            let attempts = completion.attempts;
            if durable::mark_transaction_rejected(completion, self.policy.max_attempts)
                == RetryBoundOutcome::Pending
            {
                completion.completion_epoch = None;
                completion.signing_context = None;
                completion.transaction_hash = None;
                completion.ever_exposed = false;
                normalize_authority_lineage(completion);
            }
            (attempts, next_owner, next_floor, successor_required)
        };
        if attempts >= self.policy.max_attempts {
            move_active_to_dead_letter(
                &mut candidate,
                position,
                attempts,
                ProviderIngestDeadLetterReasonV1::RetryExhausted,
                ProviderIngestFailureClassV1::SignerPolicyChanged,
                observed_finalized_cursor,
                self.policy,
            )?;
            self.persist_candidate(&mut state, candidate)?;
            return Ok(Some(ProviderIngestRetryOutcomeV1::DeadLettered));
        }
        let next_attempt_at_ms = retry_at(runtime_now_ms, attempts, self.policy)?;
        let completion = local_completion_mut(&mut candidate.active[position])?;
        completion.authority_owner = next_authority_owner;
        completion.authority_floor = next_authority_floor;
        completion.authority_successor_required = successor_required;
        completion.next_attempt_at_ms = next_attempt_at_ms;
        completion.last_failure_class = Some(ProviderIngestFailureClassV1::SignerPolicyChanged);
        self.persist_candidate(&mut state, candidate)?;
        Ok(Some(ProviderIngestRetryOutcomeV1::RetryScheduled {
            attempts,
            next_attempt_at_ms,
        }))
    }
    /// Record a failure proven to have occurred before queue admission.
    pub(crate) fn mark_completion_not_submitted(
        &self,
        job_id: [u8; 32],
        expected_transaction_hash: [u8; 32],
        now_ms: u64,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> Result<ProviderIngestRetryOutcomeV1, ProviderIngestOutboxError> {
        if now_ms == 0 {
            return Err(ProviderIngestOutboxError::InvalidRuntimeTimestamp);
        }
        observed_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        if candidate.finalized_cursor_high_water != Some(observed_finalized_cursor) {
            return Err(ProviderIngestOutboxError::StaleFinalizedCursor);
        }
        let position = active_position(&candidate, job_id)?;
        validate_cursor_after_admission(
            &candidate.active[position].authorization,
            observed_finalized_cursor,
        )?;
        let (attempts, exhausted) = {
            let completion = local_completion_mut(&mut candidate.active[position])?;
            require_transaction_hash(completion, expected_transaction_hash)?;
            durable::mark_not_submitted(completion)?;
            if completion.attempts >= self.policy.max_attempts {
                (completion.attempts, true)
            } else {
                completion.attempts = increment_attempt(completion.attempts)?;
                (completion.attempts, false)
            }
        };
        if exhausted {
            move_active_to_dead_letter(
                &mut candidate,
                position,
                attempts,
                ProviderIngestDeadLetterReasonV1::RetryExhausted,
                ProviderIngestFailureClassV1::SubmissionUnavailable,
                observed_finalized_cursor,
                self.policy,
            )?;
            self.persist_candidate(&mut state, candidate)?;
            return Ok(ProviderIngestRetryOutcomeV1::DeadLettered);
        }
        let next_attempt_at_ms = retry_at(now_ms, attempts, self.policy)?;
        let completion = local_completion_mut(&mut candidate.active[position])?;
        completion.next_attempt_at_ms = next_attempt_at_ms;
        completion.last_failure_class = Some(ProviderIngestFailureClassV1::SubmissionUnavailable);
        self.persist_candidate(&mut state, candidate)?;
        Ok(ProviderIngestRetryOutcomeV1::RetryScheduled {
            attempts,
            next_attempt_at_ms,
        })
    }
    /// Retry the same exact transaction only after finalized absence is proven.
    pub(crate) fn mark_completion_finalized_absent(
        &self,
        job_id: [u8; 32],
        expected_transaction_hash: [u8; 32],
        now_ms: u64,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> Result<ProviderIngestRetryOutcomeV1, ProviderIngestOutboxError> {
        observed_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        if candidate.finalized_cursor_high_water != Some(observed_finalized_cursor) {
            return Err(ProviderIngestOutboxError::StaleFinalizedCursor);
        }
        let position = active_position(&candidate, job_id)?;
        validate_cursor_after_admission(
            &candidate.active[position].authorization,
            observed_finalized_cursor,
        )?;
        let outcome = {
            let completion = local_completion_mut(&mut candidate.active[position])?;
            require_transaction_hash(completion, expected_transaction_hash)?;
            durable::mark_finalized_absent(
                completion,
                finalized_cursor(observed_finalized_cursor),
                self.policy.max_attempts,
            )?
        };
        if outcome == RetryBoundOutcome::Exhausted {
            let attempts = local_completion_mut(&mut candidate.active[position])?.attempts;
            move_active_to_dead_letter(
                &mut candidate,
                position,
                attempts,
                ProviderIngestDeadLetterReasonV1::RetryExhausted,
                ProviderIngestFailureClassV1::FinalizedAbsent,
                observed_finalized_cursor,
                self.policy,
            )?;
            self.persist_candidate(&mut state, candidate)?;
            return Ok(ProviderIngestRetryOutcomeV1::DeadLettered);
        }
        let attempts = local_completion_mut(&mut candidate.active[position])?.attempts;
        let next_attempt_at_ms = retry_at(now_ms, attempts, self.policy)?;
        let completion = local_completion_mut(&mut candidate.active[position])?;
        completion.next_attempt_at_ms = next_attempt_at_ms;
        completion.last_failure_class = Some(ProviderIngestFailureClassV1::FinalizedAbsent);
        self.persist_candidate(&mut state, candidate)?;
        Ok(ProviderIngestRetryOutcomeV1::RetryScheduled {
            attempts,
            next_attempt_at_ms,
        })
    }
    /// Re-sign after a terminal pipeline rejection, or dead-letter at the bound.
    ///
    /// The rejection cursor must exactly match a prior durable
    /// [`Self::observe_finalized_snapshot`] observation.
    pub(crate) fn mark_completion_transaction_rejected(
        &self,
        job_id: [u8; 32],
        expected_transaction_hash: [u8; 32],
        now_ms: u64,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> Result<ProviderIngestRetryOutcomeV1, ProviderIngestOutboxError> {
        observed_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        validate_retained_finalized_snapshot(&state.checkpoint, Some(observed_finalized_cursor))?;
        let mut candidate = state.checkpoint.clone();
        let position = active_position(&candidate, job_id)?;
        validate_cursor_after_admission(
            &candidate.active[position].authorization,
            observed_finalized_cursor,
        )?;
        let attempts = {
            let completion = local_completion_mut(&mut candidate.active[position])?;
            require_transaction_hash(completion, expected_transaction_hash)?;
            if !(matches!(
                completion.state,
                StoredDeliveryStateV1::Ambiguous | StoredDeliveryStateV1::Submitted
            ) || completion.state == StoredDeliveryStateV1::Signed && completion.ever_exposed)
            {
                return Err(ProviderIngestOutboxError::InvalidTransition);
            }
            let attempts = completion.attempts;
            if durable::mark_transaction_rejected(completion, self.policy.max_attempts)
                == RetryBoundOutcome::Pending
            {
                completion.completion_epoch = None;
                completion.signing_context = None;
                completion.transaction_hash = None;
                completion.ever_exposed = false;
                normalize_authority_lineage(completion);
            }
            attempts
        };
        if attempts >= self.policy.max_attempts {
            move_active_to_dead_letter(
                &mut candidate,
                position,
                attempts,
                ProviderIngestDeadLetterReasonV1::RetryExhausted,
                ProviderIngestFailureClassV1::TransactionRejected,
                observed_finalized_cursor,
                self.policy,
            )?;
            self.persist_candidate(&mut state, candidate)?;
            return Ok(ProviderIngestRetryOutcomeV1::DeadLettered);
        }
        let next_attempt_at_ms = retry_at(now_ms, attempts, self.policy)?;
        let completion = local_completion_mut(&mut candidate.active[position])?;
        completion.next_attempt_at_ms = next_attempt_at_ms;
        completion.last_failure_class = Some(ProviderIngestFailureClassV1::TransactionRejected);
        self.persist_candidate(&mut state, candidate)?;
        Ok(ProviderIngestRetryOutcomeV1::RetryScheduled {
            attempts,
            next_attempt_at_ms,
        })
    }
    /// Mark this provider complete only after exact committed-state confirmation.
    ///
    /// The evidence cursor must exactly match a prior durable
    /// [`Self::observe_finalized_snapshot`] observation.
    #[allow(clippy::too_many_lines)]
    pub fn mark_finalized_complete(
        &self,
        job_id: [u8; 32],
        evidence: ProviderIngestFinalizedCompletionV1,
    ) -> Result<(), ProviderIngestOutboxError> {
        validate_finalized_completion_evidence(&evidence)?;
        let mut state = self.lock_state()?;
        validate_retained_finalized_snapshot(&state.checkpoint, Some(evidence.finalized_cursor))?;
        if let Some(position) = state
            .checkpoint
            .terminal
            .iter()
            .position(|entry| entry.authorization.job_id == job_id)
        {
            let existing = &state.checkpoint.terminal[position];
            validate_completion_binding(&existing.authorization, &evidence)?;
            validate_cursor_after_admission(&existing.authorization, evidence.finalized_cursor)?;
            match &existing.outcome {
                StoredProviderIngestTerminalOutcomeV1::FinalizedCompleted {
                    completion_epoch,
                    completed_by,
                    committed_transaction_hash,
                    finalized_cursor,
                    ..
                } => {
                    validate_cursor_not_before(*finalized_cursor, evidence.finalized_cursor)?;
                    if *completion_epoch != evidence.completion_epoch
                        || completed_by != &evidence.completed_by
                        || committed_hashes_conflict(
                            *committed_transaction_hash,
                            evidence.committed_transaction_hash,
                        )
                    {
                        return Err(ProviderIngestOutboxError::AlreadyTerminal);
                    }
                    if committed_transaction_hash.is_some()
                        || evidence.committed_transaction_hash.is_none()
                    {
                        return Ok(());
                    }
                    let mut candidate = state.checkpoint.clone();
                    let StoredProviderIngestTerminalOutcomeV1::FinalizedCompleted {
                        committed_transaction_hash,
                        ..
                    } = &mut candidate.terminal[position].outcome
                    else {
                        unreachable!("matched finalized completion above");
                    };
                    *committed_transaction_hash = evidence.committed_transaction_hash;
                    return self.persist_candidate(&mut state, candidate);
                }
                StoredProviderIngestTerminalOutcomeV1::Cancelled {
                    observed_finalized_cursor,
                    ..
                }
                | StoredProviderIngestTerminalOutcomeV1::DeadLetter {
                    observed_finalized_cursor,
                    ..
                } => {
                    validate_cursor_not_before(
                        *observed_finalized_cursor,
                        evidence.finalized_cursor,
                    )?;
                    let mut candidate = state.checkpoint.clone();
                    let terminal = &mut candidate.terminal[position];
                    terminal.outcome = StoredProviderIngestTerminalOutcomeV1::FinalizedCompleted {
                        manifest_id: None,
                        musubi_bundle: None,
                        completion_epoch: evidence.completion_epoch,
                        completed_by: evidence.completed_by,
                        committed_transaction_hash: evidence.committed_transaction_hash,
                        finalized_cursor: evidence.finalized_cursor,
                    };
                    prune_terminal_entries(
                        &mut candidate,
                        evidence.finalized_cursor.height,
                        self.policy,
                    );
                    return self.persist_candidate(&mut state, candidate);
                }
            }
        }
        let mut candidate = state.checkpoint.clone();
        let position = active_position(&candidate, job_id)?;
        let authorization = &candidate.active[position].authorization;
        validate_cursor_after_admission(authorization, evidence.finalized_cursor)?;
        validate_completion_binding(authorization, &evidence)?;
        let (manifest_id, musubi_bundle) = match &candidate.active[position].state {
            StoredProviderIngestStateV1::LocalStored {
                manifest_id,
                musubi_bundle,
                completion,
            } => {
                if completion.baseline_finalized_height != 0 {
                    validate_cursor_after_baseline(completion, evidence.finalized_cursor)?;
                }
                (Some(manifest_id.clone()), musubi_bundle.clone())
            }
            StoredProviderIngestStateV1::PendingSource
            | StoredProviderIngestStateV1::SourceClaimed { .. }
            | StoredProviderIngestStateV1::RetryScheduled { .. } => (None, None),
        };
        prune_terminal_entries(
            &mut candidate,
            evidence.finalized_cursor.height,
            self.policy,
        );
        ensure_terminal_slot(&candidate, self.policy)?;
        let active = candidate.active.remove(position);
        candidate.terminal.push(StoredTerminalProviderIngestV1 {
            sequence: active.sequence,
            authorization: active.authorization,
            outcome: StoredProviderIngestTerminalOutcomeV1::FinalizedCompleted {
                manifest_id,
                musubi_bundle,
                completion_epoch: evidence.completion_epoch,
                completed_by: evidence.completed_by,
                committed_transaction_hash: evidence.committed_transaction_hash,
                finalized_cursor: evidence.finalized_cursor,
            },
        });
        candidate
            .terminal
            .sort_by_key(|entry| entry.authorization.job_id);
        self.persist_candidate(&mut state, candidate)
    }
    /// Reconcile finalized completion, including an absent local job.
    ///
    /// An absent completion is written directly as a terminal tombstone. It
    /// therefore never consumes active capacity or exposes already-completed
    /// source work between admission and finalization.
    ///
    /// The evidence cursor must exactly match a prior durable [`Self::observe_finalized_snapshot`]
    /// observation, including when no local job is retained.
    pub fn reconcile_finalized_completion(
        &self,
        authorization: FinalizedProviderIngestAuthorizationV1,
        evidence: ProviderIngestFinalizedCompletionV1,
    ) -> Result<(), ProviderIngestOutboxError> {
        authorization.validate()?;
        validate_finalized_completion_evidence(&evidence)?;
        validate_cursor_after_admission(&authorization, evidence.finalized_cursor)?;
        validate_completion_binding(&authorization, &evidence)?;
        let job_id = authorization.job_id;
        let mut state = self.lock_state()?;
        validate_retained_finalized_snapshot(&state.checkpoint, Some(evidence.finalized_cursor))?;
        if let Some(existing) = state
            .checkpoint
            .active
            .iter()
            .map(|entry| &entry.authorization)
            .chain(
                state
                    .checkpoint
                    .terminal
                    .iter()
                    .map(|entry| &entry.authorization),
            )
            .find(|existing| existing.job_id == job_id)
        {
            validate_replayed_authorization(existing, &authorization)?;
            drop(state);
            return self.mark_finalized_complete(job_id, evidence);
        }
        if state
            .checkpoint
            .active
            .iter()
            .map(|entry| &entry.authorization)
            .chain(
                state
                    .checkpoint
                    .terminal
                    .iter()
                    .map(|entry| &entry.authorization),
            )
            .any(|existing| {
                existing.provider_id == authorization.provider_id
                    && existing.order_id == authorization.order_id
            })
        {
            return Err(ProviderIngestOutboxError::OrderBindingConflict);
        }
        let mut candidate = state.checkpoint.clone();
        prune_terminal_entries(
            &mut candidate,
            evidence.finalized_cursor.height,
            self.policy,
        );
        ensure_terminal_slot(&candidate, self.policy)?;
        let sequence = candidate.next_sequence;
        candidate.next_sequence = sequence
            .checked_add(1)
            .ok_or(ProviderIngestOutboxError::SequenceExhausted)?;
        candidate.terminal.push(StoredTerminalProviderIngestV1 {
            sequence,
            authorization,
            outcome: StoredProviderIngestTerminalOutcomeV1::FinalizedCompleted {
                manifest_id: None,
                musubi_bundle: None,
                completion_epoch: evidence.completion_epoch,
                completed_by: evidence.completed_by,
                committed_transaction_hash: evidence.committed_transaction_hash,
                finalized_cursor: evidence.finalized_cursor,
            },
        });
        candidate
            .terminal
            .sort_by_key(|entry| entry.authorization.job_id);
        self.persist_candidate(&mut state, candidate)
    }
    /// Reconcile finalized cancellation, including an absent local job.
    ///
    /// An absent job is written directly as a terminal tombstone so a crash
    /// cannot expose cancelled source work between admission and cancellation.
    ///
    /// The evidence cursor must exactly match a prior durable [`Self::observe_finalized_snapshot`]
    /// observation, including when no local job is retained.
    pub fn reconcile_finalized_cancellation(
        &self,
        authorization: FinalizedProviderIngestAuthorizationV1,
        evidence: ProviderIngestFinalizedCancellationV1,
    ) -> Result<(), ProviderIngestOutboxError> {
        authorization.validate()?;
        validate_finalized_cancellation_evidence(&evidence)?;
        validate_cursor_after_admission(&authorization, evidence.finalized_cursor)?;
        validate_cancellation_binding(&authorization, &evidence)?;
        let job_id = authorization.job_id;
        let mut state = self.lock_state()?;
        validate_retained_finalized_snapshot(&state.checkpoint, Some(evidence.finalized_cursor))?;
        if let Some(existing) = state
            .checkpoint
            .active
            .iter()
            .map(|entry| &entry.authorization)
            .chain(
                state
                    .checkpoint
                    .terminal
                    .iter()
                    .map(|entry| &entry.authorization),
            )
            .find(|existing| existing.job_id == job_id)
        {
            validate_replayed_authorization(existing, &authorization)?;
            drop(state);
            return self.cancel(job_id, evidence);
        }
        if state
            .checkpoint
            .active
            .iter()
            .map(|entry| &entry.authorization)
            .chain(
                state
                    .checkpoint
                    .terminal
                    .iter()
                    .map(|entry| &entry.authorization),
            )
            .any(|existing| {
                existing.provider_id == authorization.provider_id
                    && existing.order_id == authorization.order_id
            })
        {
            return Err(ProviderIngestOutboxError::OrderBindingConflict);
        }
        let mut candidate = state.checkpoint.clone();
        prune_terminal_entries(
            &mut candidate,
            evidence.finalized_cursor.height,
            self.policy,
        );
        ensure_terminal_slot(&candidate, self.policy)?;
        let sequence = candidate.next_sequence;
        candidate.next_sequence = sequence
            .checked_add(1)
            .ok_or(ProviderIngestOutboxError::SequenceExhausted)?;
        candidate.terminal.push(StoredTerminalProviderIngestV1 {
            sequence,
            authorization,
            outcome: StoredProviderIngestTerminalOutcomeV1::Cancelled {
                reason: evidence.reason,
                observed_finalized_cursor: evidence.finalized_cursor,
            },
        });
        candidate
            .terminal
            .sort_by_key(|entry| entry.authorization.job_id);
        self.persist_candidate(&mut state, candidate)
    }
    /// Cancel active work after finalized chain state proves it inapplicable.
    ///
    /// The evidence cursor must exactly match a prior durable
    /// [`Self::observe_finalized_snapshot`] observation.
    pub fn cancel(
        &self,
        job_id: [u8; 32],
        evidence: ProviderIngestFinalizedCancellationV1,
    ) -> Result<(), ProviderIngestOutboxError> {
        validate_finalized_cancellation_evidence(&evidence)?;
        let mut state = self.lock_state()?;
        validate_retained_finalized_snapshot(&state.checkpoint, Some(evidence.finalized_cursor))?;
        if let Some(position) = state
            .checkpoint
            .terminal
            .iter()
            .position(|entry| entry.authorization.job_id == job_id)
        {
            let existing = &state.checkpoint.terminal[position];
            validate_cancellation_binding(&existing.authorization, &evidence)?;
            return match &existing.outcome {
                StoredProviderIngestTerminalOutcomeV1::DeadLetter {
                    observed_finalized_cursor,
                    ..
                } => {
                    validate_cursor_not_before(
                        *observed_finalized_cursor,
                        evidence.finalized_cursor,
                    )?;
                    let mut candidate = state.checkpoint.clone();
                    candidate.terminal[position].outcome =
                        StoredProviderIngestTerminalOutcomeV1::Cancelled {
                            reason: evidence.reason,
                            observed_finalized_cursor: evidence.finalized_cursor,
                        };
                    self.persist_candidate(&mut state, candidate)
                }
                StoredProviderIngestTerminalOutcomeV1::Cancelled {
                    reason,
                    observed_finalized_cursor,
                } if *reason == evidence.reason
                    && validate_cursor_not_before(
                        *observed_finalized_cursor,
                        evidence.finalized_cursor,
                    )
                    .is_ok() =>
                {
                    Ok(())
                }
                StoredProviderIngestTerminalOutcomeV1::FinalizedCompleted { .. }
                | StoredProviderIngestTerminalOutcomeV1::Cancelled { .. } => {
                    Err(ProviderIngestOutboxError::AlreadyTerminal)
                }
            };
        }
        let mut candidate = state.checkpoint.clone();
        let position = active_position(&candidate, job_id)?;
        validate_cursor_after_admission(
            &candidate.active[position].authorization,
            evidence.finalized_cursor,
        )?;
        validate_cancellation_binding(&candidate.active[position].authorization, &evidence)?;
        prune_terminal_entries(
            &mut candidate,
            evidence.finalized_cursor.height,
            self.policy,
        );
        ensure_terminal_slot(&candidate, self.policy)?;
        let active = candidate.active.remove(position);
        candidate.terminal.push(StoredTerminalProviderIngestV1 {
            sequence: active.sequence,
            authorization: active.authorization,
            outcome: StoredProviderIngestTerminalOutcomeV1::Cancelled {
                reason: evidence.reason,
                observed_finalized_cursor: evidence.finalized_cursor,
            },
        });
        candidate
            .terminal
            .sort_by_key(|entry| entry.authorization.job_id);
        self.persist_candidate(&mut state, candidate)
    }
    /// Deterministically prune only governed terminal tombstones.
    #[cfg(test)]
    pub fn prune_terminal(
        &self,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> Result<usize, ProviderIngestOutboxError> {
        observed_finalized_cursor.validate()?;
        let mut state = self.lock_state()?;
        let mut candidate = state.checkpoint.clone();
        let removed = prune_terminal_entries(
            &mut candidate,
            observed_finalized_cursor.height,
            self.policy,
        );
        if removed != 0 {
            self.persist_candidate(&mut state, candidate)?;
        }
        Ok(removed)
    }
    /// Return constant-time payload-free aggregate counts under one state lock.
    ///
    /// Checkpoints are exhaustively validated before installation. This accessor revalidates the
    /// installed checkpoint's constant-time structural/count seal before returning the cached exact
    /// counts, so daemon readiness does not need to allocate, sort, or page status rows.
    pub fn aggregate_counts(
        &self,
    ) -> Result<ProviderIngestOutboxCountsV1, ProviderIngestOutboxError> {
        let state = self.lock_state()?;
        validate_checkpoint_count_snapshot(&state.checkpoint, state.aggregate_counts, self.policy)?;
        Ok(state.aggregate_counts)
    }
    /// Return the exact cloned finalized authorization retained for one job.
    ///
    /// This accessor exposes no lease or signer material and returns the same
    /// durable binding for active and terminal jobs.
    pub fn authorization(
        &self,
        job_id: [u8; 32],
    ) -> Result<FinalizedProviderIngestAuthorizationV1, ProviderIngestOutboxError> {
        let state = self.lock_state()?;
        state
            .checkpoint
            .active
            .iter()
            .map(|entry| &entry.authorization)
            .chain(
                state
                    .checkpoint
                    .terminal
                    .iter()
                    .map(|entry| &entry.authorization),
            )
            .find(|authorization| authorization.job_id == job_id)
            .cloned()
            .ok_or(ProviderIngestOutboxError::UnknownJob)
    }
    /// Return one payload-free status by stable job identity.
    pub fn status(
        &self,
        job_id: [u8; 32],
    ) -> Result<ProviderIngestStatusV1, ProviderIngestOutboxError> {
        let state = self.lock_state()?;
        if let Some(entry) = state
            .checkpoint
            .active
            .iter()
            .find(|entry| entry.authorization.job_id == job_id)
        {
            return Ok(active_status(entry));
        }
        state
            .checkpoint
            .terminal
            .iter()
            .find(|entry| entry.authorization.job_id == job_id)
            .map(terminal_status)
            .ok_or(ProviderIngestOutboxError::UnknownJob)
    }
    /// Return a bounded payload-free page in stable job-id order.
    pub fn statuses_page(
        &self,
        after_job_id: Option<[u8; 32]>,
        limit: usize,
    ) -> Result<ProviderIngestStatusPageV1, ProviderIngestOutboxError> {
        if limit == 0 || limit > self.policy.max_status_page_size {
            return Err(ProviderIngestOutboxError::InvalidPageLimit);
        }
        let state = self.lock_state()?;
        // Select the first `limit + 1` identities before cloning any status or Musubi receipt.
        // The ordinal preserves the former stable-sort order if a corrupt in-memory snapshot
        // contains duplicate job IDs; valid checkpoints reject duplicates during installation.
        let selection_limit = limit + 1;
        let mut selected = BinaryHeap::new();
        selected
            .try_reserve(selection_limit)
            .map_err(|_| ProviderIngestOutboxError::StateUnavailable)?;
        for (ordinal, job_id) in state
            .checkpoint
            .active
            .iter()
            .map(|entry| entry.authorization.job_id)
            .chain(
                state
                    .checkpoint
                    .terminal
                    .iter()
                    .map(|entry| entry.authorization.job_id),
            )
            .enumerate()
        {
            if after_job_id.is_some_and(|after| job_id <= after) {
                continue;
            }
            let candidate = (job_id, ordinal);
            if selected.len() < selection_limit {
                selected.push(candidate);
            } else if selected.peek().is_some_and(|last| candidate < *last) {
                selected.pop();
                selected.push(candidate);
            }
        }
        let selected = selected.into_sorted_vec();
        let has_more = selected.len() > limit;
        let mut rows = Vec::new();
        rows.try_reserve(selected.len().min(limit))
            .map_err(|_| ProviderIngestOutboxError::StateUnavailable)?;
        let active_len = state.checkpoint.active.len();
        for (_, ordinal) in selected.into_iter().take(limit) {
            rows.push(if ordinal < active_len {
                active_status(&state.checkpoint.active[ordinal])
            } else {
                terminal_status(&state.checkpoint.terminal[ordinal - active_len])
            });
        }
        let next_after_job_id = has_more.then(|| {
            rows.last()
                .expect("has_more implies at least one returned row")
                .job_id
        });
        Ok(ProviderIngestStatusPageV1 {
            rows,
            next_after_job_id,
        })
    }
    fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, ProviderIngestOutboxState>, ProviderIngestOutboxError>
    {
        self.lock_state_after_authoritative_load(|| {})
    }
    fn lock_state_after_authoritative_load(
        &self,
        authoritative_loaded: impl FnOnce(),
    ) -> Result<std::sync::MutexGuard<'_, ProviderIngestOutboxState>, ProviderIngestOutboxError>
    {
        match (&self.path, &self.writer_lock) {
            (Some(path), Some(writer_lock)) => writer_lock.validate_live(path.as_path())?,
            (None, None) => {}
            (Some(_), None) | (None, Some(_)) => {
                return Err(ProviderIngestOutboxError::InvalidCheckpoint);
            }
        }
        // Retain the local mutex across the authoritative read and comparison:
        // every local persist advances `sealed_record` under this same lock.
        let state = self
            .state
            .lock()
            .map_err(|_| ProviderIngestOutboxError::StateUnavailable)?;
        if state.durability_failure.is_some() {
            return Err(ProviderIngestOutboxError::DurabilityPoisoned);
        }
        let authoritative_record = self
            .checkpoint_authority
            .as_ref()
            .map(|authority| authority.load_latest(self.policy.checkpoint_max_bytes))
            .transpose()?;
        authoritative_loaded();
        if authoritative_record.as_ref().is_some_and(Option::is_none) {
            return Err(ProviderIngestOutboxError::CheckpointRollback);
        }
        if let Some(authoritative_record) = authoritative_record.flatten()
            && state.sealed_record.as_ref() != Some(&authoritative_record)
        {
            return Err(match state.sealed_record.as_ref() {
                Some(local)
                    if local.checkpoint_sequence > authoritative_record.checkpoint_sequence =>
                {
                    ProviderIngestOutboxError::CheckpointRollback
                }
                _ => ProviderIngestOutboxError::CheckpointFork,
            });
        }
        Ok(state)
    }
    fn persist_candidate(
        &self,
        live: &mut ProviderIngestOutboxState,
        candidate: ProviderIngestOutboxCheckpointV1,
    ) -> Result<(), ProviderIngestOutboxError> {
        validate_checkpoint(&candidate, self.policy)?;
        let aggregate_counts = checkpoint_counts(&candidate);
        let Some(path) = &self.path else {
            if self.checkpoint_authority.is_some() || live.sealed_record.is_some() {
                return Err(ProviderIngestOutboxError::InvalidCheckpoint);
            }
            live.checkpoint = candidate;
            live.aggregate_counts = aggregate_counts;
            return Ok(());
        };
        let writer_lock = self
            .writer_lock
            .as_ref()
            .ok_or(ProviderIngestOutboxError::InvalidCheckpoint)?;
        writer_lock.validate_live(path.as_path())?;
        let checkpoint_bytes = encode_provider_ingest_checkpoint(&candidate, self.policy)?;
        let (bytes, max_bytes, next_sealed_record) = if let Some(authority) =
            &self.checkpoint_authority
        {
            let current = live
                .sealed_record
                .as_ref()
                .ok_or(ProviderIngestOutboxError::InvalidSealedCheckpoint)?;
            let live_bytes = encode_provider_ingest_checkpoint(&live.checkpoint, self.policy)?;
            if current.checkpoint_bytes != live_bytes
                || current.checkpoint_digest != *blake3::hash(&live_bytes).as_bytes()
            {
                live.durability_failure =
                    Some("sealed provider-ingest state diverged from memory".to_owned());
                return Err(ProviderIngestOutboxError::CheckpointFork);
            }
            let next_sequence = current
                .checkpoint_sequence
                .checked_add(1)
                .ok_or(ProviderIngestOutboxError::SequenceExhausted)?;
            let next = ProviderIngestSealedCheckpointRecordV1::new(
                next_sequence,
                Some(current.revision),
                Some(current.checkpoint_digest),
                checkpoint_bytes,
            );
            let next_bytes = next.to_canonical_bytes(self.policy.checkpoint_max_bytes)?;
            let record_max_bytes = provider_ingest_sealed_checkpoint_record_max_bytes(
                self.policy.checkpoint_max_bytes,
            )?;
            if let Err(error) =
                authority.compare_and_swap(self.policy.checkpoint_max_bytes, Some(current), &next)
            {
                // A timed-out worker is already sticky and preserves the typed
                // timeout until this outbox is reopened. Poison only response
                // loss whose ambiguity is not represented by worker state.
                if error == ProviderIngestOutboxError::CheckpointAuthorityAmbiguous {
                    live.durability_failure =
                        Some("sealed provider-ingest commit outcome is ambiguous".to_owned());
                }
                return Err(error);
            }
            (next_bytes, record_max_bytes, Some(next))
        } else {
            if live.sealed_record.is_some() {
                return Err(ProviderIngestOutboxError::InvalidSealedCheckpoint);
            }
            (checkpoint_bytes, self.policy.checkpoint_max_bytes, None)
        };
        match write_local_checkpoint_atomic_bounded(path.as_path(), &bytes, max_bytes) {
            Ok(()) => {
                if let Err(error) = writer_lock.validate_live(path.as_path()) {
                    live.checkpoint = candidate;
                    live.sealed_record = next_sealed_record;
                    live.aggregate_counts = aggregate_counts;
                    live.durability_failure = Some(error.to_string());
                    return Err(ProviderIngestOutboxError::DurabilityUncertain);
                }
                live.checkpoint = candidate;
                live.sealed_record = next_sealed_record;
                live.aggregate_counts = aggregate_counts;
                Ok(())
            }
            Err(error) if error.committed => {
                live.checkpoint = candidate;
                live.sealed_record = next_sealed_record;
                live.aggregate_counts = aggregate_counts;
                live.durability_failure = Some(error.to_string());
                Err(ProviderIngestOutboxError::DurabilityUncertain)
            }
            Err(error) => {
                if next_sealed_record.is_some() {
                    live.checkpoint = candidate;
                    live.sealed_record = next_sealed_record;
                    live.aggregate_counts = aggregate_counts;
                    live.durability_failure = Some(error.to_string());
                    Err(ProviderIngestOutboxError::DurabilityUncertain)
                } else {
                    Err(ProviderIngestOutboxError::Checkpoint(error.to_string()))
                }
            }
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
enum SourceEligibility {
    Eligible,
    ExpiredLease,
    Skip,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactSourceEligibility {
    Eligible,
    ExpiredLease,
    RetryNotDue,
    LeaseHeld,
    LocalStored,
}
fn install_source_claim(
    entry: &mut StoredActiveProviderIngestV1,
    owner: ProviderIngestClaimOwnerV1,
    now_ms: u64,
    lease_ttl_ms: u64,
) -> Result<ProviderIngestSourceClaimV1, ProviderIngestOutboxError> {
    let generation = entry
        .claim_generation
        .checked_add(1)
        .ok_or(ProviderIngestOutboxError::LeaseGenerationExhausted)?;
    let lease_expires_at_ms = now_ms
        .checked_add(lease_ttl_ms)
        .ok_or(ProviderIngestOutboxError::TimestampOverflow)?;
    let lease_token = derive_lease_token(
        entry.authorization.job_id,
        owner,
        generation,
        lease_expires_at_ms,
    );
    entry.claim_generation = generation;
    entry.state = StoredProviderIngestStateV1::SourceClaimed {
        owner,
        generation,
        lease_token,
        lease_expires_at_ms,
    };
    Ok(ProviderIngestSourceClaimV1 {
        job_id: entry.authorization.job_id,
        owner,
        generation,
        lease_token,
        lease_expires_at_ms,
        authorization: entry.authorization.clone(),
    })
}
fn derive_lease_token(
    job_id: [u8; 32],
    owner: ProviderIngestClaimOwnerV1,
    generation: u64,
    lease_expires_at_ms: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROVIDER_INGEST_LEASE_TOKEN_DOMAIN_V1);
    hasher.update(&job_id);
    hasher.update(&owner.0);
    hasher.update(&generation.to_le_bytes());
    hasher.update(&lease_expires_at_ms.to_le_bytes());
    *hasher.finalize().as_bytes()
}
fn validate_live_claim(
    entry: &StoredActiveProviderIngestV1,
    claim: &ProviderIngestSourceClaimV1,
    now_ms: u64,
) -> Result<(), ProviderIngestOutboxError> {
    let StoredProviderIngestStateV1::SourceClaimed {
        owner,
        generation,
        lease_token,
        lease_expires_at_ms,
    } = &entry.state
    else {
        return Err(ProviderIngestOutboxError::InvalidSourceClaim);
    };
    if now_ms >= *lease_expires_at_ms {
        return Err(ProviderIngestOutboxError::SourceClaimExpired);
    }
    if claim.job_id != entry.authorization.job_id
        || claim.authorization != entry.authorization
        || claim.owner != *owner
        || claim.generation != *generation
        || claim.lease_token != *lease_token
        || claim.lease_expires_at_ms != *lease_expires_at_ms
    {
        return Err(ProviderIngestOutboxError::InvalidSourceClaim);
    }
    Ok(())
}
fn validate_replayed_authorization(
    retained: &FinalizedProviderIngestAuthorizationV1,
    replayed: &FinalizedProviderIngestAuthorizationV1,
) -> Result<(), ProviderIngestOutboxError> {
    if !retained.same_binding(replayed) || retained.job_id != replayed.job_id {
        return Err(ProviderIngestOutboxError::IdempotencyConflict);
    }
    if retained.admission_finalized_cursor.height == replayed.admission_finalized_cursor.height
        && retained.admission_finalized_cursor.block_hash
            != replayed.admission_finalized_cursor.block_hash
    {
        return Err(ProviderIngestOutboxError::AdmissionEvidenceConflict);
    }
    Ok(())
}
fn active_position(
    checkpoint: &ProviderIngestOutboxCheckpointV1,
    job_id: [u8; 32],
) -> Result<usize, ProviderIngestOutboxError> {
    checkpoint
        .active
        .iter()
        .position(|entry| entry.authorization.job_id == job_id)
        .ok_or(ProviderIngestOutboxError::UnknownJob)
}
fn find_active_mut(
    checkpoint: &mut ProviderIngestOutboxCheckpointV1,
    job_id: [u8; 32],
) -> Result<&mut StoredActiveProviderIngestV1, ProviderIngestOutboxError> {
    checkpoint
        .active
        .iter_mut()
        .find(|entry| entry.authorization.job_id == job_id)
        .ok_or(ProviderIngestOutboxError::UnknownJob)
}
fn local_completion_mut(
    entry: &mut StoredActiveProviderIngestV1,
) -> Result<&mut StoredCompletionDeliveryV1, ProviderIngestOutboxError> {
    let StoredProviderIngestStateV1::LocalStored { completion, .. } = &mut entry.state else {
        return Err(ProviderIngestOutboxError::InvalidTransition);
    };
    Ok(completion)
}
fn clear_completion_signing_material(completion: &mut StoredCompletionDeliveryV1) {
    completion.state = StoredDeliveryStateV1::Ready;
    completion.signing_claimed_at_ms = 0;
    completion.baseline_finalized_height = 0;
    completion.baseline_finalized_block_hash = [0; 32];
    completion.completion_epoch = None;
    completion.signing_context = None;
    completion.transaction_hash = None;
    completion.signed_transaction = None;
    completion.ever_exposed = false;
    completion.next_attempt_at_ms = 0;
    completion.last_failure_class = None;
}
fn normalize_authority_lineage(completion: &mut StoredCompletionDeliveryV1) {
    if completion.authority_floor.is_none() {
        completion.authority_owner = None;
        completion.authority_successor_required = false;
    }
}
fn validate_manifest_id(
    authorization: &FinalizedProviderIngestAuthorizationV1,
    manifest_id: &str,
) -> Result<(), ProviderIngestOutboxError> {
    if manifest_id.is_empty()
        || manifest_id.len() > MAX_MANIFEST_ID_BYTES_V1
        || manifest_id.trim() != manifest_id
        || manifest_id.chars().any(char::is_control)
        || manifest_id != hex::encode(authorization.manifest_digest)
    {
        return Err(ProviderIngestOutboxError::InvalidManifestId);
    }
    Ok(())
}
fn provided_musubi_receipt_shape_is_valid(
    authorization: &FinalizedProviderIngestAuthorizationV1,
    musubi_bundle: Option<&ProviderIngestVerifiedMusubiBundleReceiptV1>,
) -> bool {
    match (authorization.musubi_context(), musubi_bundle) {
        (None, None) => true,
        (Some(_), Some(receipt)) => receipt.validate_stored(authorization),
        (None, Some(_)) | (Some(_), None) => false,
    }
}
fn stored_musubi_receipt_shape_is_valid(
    authorization: &FinalizedProviderIngestAuthorizationV1,
    musubi_bundle: Option<&StoredProviderIngestVerifiedMusubiBundleReceiptV1>,
) -> bool {
    match (authorization.musubi_context(), musubi_bundle) {
        (None, None) => true,
        (Some(_), Some(receipt)) => receipt.validate_stored(authorization),
        (None, Some(_)) | (Some(_), None) => false,
    }
}
fn increment_attempt(attempts: u32) -> Result<u32, ProviderIngestOutboxError> {
    attempts
        .checked_add(1)
        .ok_or(ProviderIngestOutboxError::AttemptOverflow)
}
fn consume_bounded_attempt(
    attempts: u32,
    max_attempts: u32,
) -> Result<u32, ProviderIngestOutboxError> {
    if attempts >= max_attempts {
        Ok(attempts)
    } else {
        increment_attempt(attempts)
    }
}
const fn valid_permanent_failure_pair(
    reason: ProviderIngestDeadLetterReasonV1,
    failure_class: ProviderIngestFailureClassV1,
) -> bool {
    matches!(
        (reason, failure_class),
        (
            ProviderIngestDeadLetterReasonV1::BindingMismatch,
            ProviderIngestFailureClassV1::BindingMismatch,
        ) | (
            ProviderIngestDeadLetterReasonV1::StorageRejected,
            ProviderIngestFailureClassV1::StorageRejected,
        )
    )
}
fn retry_at(
    now_ms: u64,
    attempts: u32,
    policy: ProviderIngestOutboxPolicyV1,
) -> Result<u64, ProviderIngestOutboxError> {
    let shift = attempts.saturating_sub(1).min(63);
    let multiplier = 1_u64.checked_shl(shift).unwrap_or(u64::MAX);
    let delay = policy
        .retry_base_delay_ms
        .saturating_mul(multiplier)
        .min(policy.retry_max_delay_ms);
    now_ms
        .checked_add(delay)
        .ok_or(ProviderIngestOutboxError::TimestampOverflow)
}
fn completion_signing_recover_at_ms(
    claimed_at_ms: u64,
    policy: ProviderIngestOutboxPolicyV1,
) -> Result<u64, ProviderIngestOutboxError> {
    if claimed_at_ms == 0 {
        return Err(ProviderIngestOutboxError::InvalidRuntimeTimestamp);
    }
    let recovery_delay = policy
        .source_lease_ttl_ms
        .checked_mul(2)
        .ok_or(ProviderIngestOutboxError::TimestampOverflow)?;
    claimed_at_ms
        .checked_add(recovery_delay)
        .ok_or(ProviderIngestOutboxError::TimestampOverflow)
}
fn validate_cursor_after_admission(
    authorization: &FinalizedProviderIngestAuthorizationV1,
    observed: ProviderIngestFinalizedCursorV1,
) -> Result<(), ProviderIngestOutboxError> {
    observed.validate()?;
    let admission = authorization.admission_finalized_cursor;
    if observed.height < admission.height
        || (observed.height == admission.height && observed.block_hash != admission.block_hash)
    {
        return Err(ProviderIngestOutboxError::StaleFinalizedCursor);
    }
    Ok(())
}
fn validate_cursor_after_baseline(
    completion: &StoredCompletionDeliveryV1,
    observed: ProviderIngestFinalizedCursorV1,
) -> Result<(), ProviderIngestOutboxError> {
    if observed.height <= completion.baseline_finalized_height {
        return Err(ProviderIngestOutboxError::StaleFinalizedCursor);
    }
    Ok(())
}
const fn finalized_cursor(cursor: ProviderIngestFinalizedCursorV1) -> FinalizedCursorV1 {
    FinalizedCursorV1 {
        height: cursor.height,
        block_hash: cursor.block_hash,
    }
}
fn move_active_to_dead_letter(
    checkpoint: &mut ProviderIngestOutboxCheckpointV1,
    position: usize,
    attempts: u32,
    reason: ProviderIngestDeadLetterReasonV1,
    last_failure_class: ProviderIngestFailureClassV1,
    observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    policy: ProviderIngestOutboxPolicyV1,
) -> Result<(), ProviderIngestOutboxError> {
    prune_terminal_entries(checkpoint, observed_finalized_cursor.height, policy);
    ensure_terminal_slot(checkpoint, policy)?;
    let active = checkpoint.active.remove(position);
    checkpoint.terminal.push(StoredTerminalProviderIngestV1 {
        sequence: active.sequence,
        authorization: active.authorization,
        outcome: StoredProviderIngestTerminalOutcomeV1::DeadLetter {
            attempts,
            reason,
            last_failure_class,
            observed_finalized_cursor,
        },
    });
    checkpoint
        .terminal
        .sort_by_key(|entry| entry.authorization.job_id);
    Ok(())
}
fn terminal_observed_height(entry: &StoredTerminalProviderIngestV1) -> u64 {
    match &entry.outcome {
        StoredProviderIngestTerminalOutcomeV1::FinalizedCompleted {
            finalized_cursor, ..
        } => finalized_cursor.height,
        StoredProviderIngestTerminalOutcomeV1::Cancelled {
            observed_finalized_cursor,
            ..
        }
        | StoredProviderIngestTerminalOutcomeV1::DeadLetter {
            observed_finalized_cursor,
            ..
        } => observed_finalized_cursor.height,
    }
}
fn prune_terminal_entries(
    checkpoint: &mut ProviderIngestOutboxCheckpointV1,
    observed_finalized_height: u64,
    policy: ProviderIngestOutboxPolicyV1,
) -> usize {
    let before = checkpoint.terminal.len();
    checkpoint.terminal.retain(|entry| {
        observed_finalized_height.saturating_sub(terminal_observed_height(entry))
            <= policy.terminal_retention_blocks
    });
    checkpoint
        .terminal
        .sort_by_key(|entry| entry.authorization.job_id);
    before - checkpoint.terminal.len()
}
fn ensure_terminal_slot(
    checkpoint: &ProviderIngestOutboxCheckpointV1,
    policy: ProviderIngestOutboxPolicyV1,
) -> Result<(), ProviderIngestOutboxError> {
    if checkpoint.terminal.len() >= policy.max_terminal_entries {
        return Err(ProviderIngestOutboxError::CapacityExhausted);
    }
    Ok(())
}
fn require_transaction_hash(
    completion: &StoredCompletionDeliveryV1,
    expected: [u8; 32],
) -> Result<(), ProviderIngestOutboxError> {
    if expected == [0; 32] || completion.transaction_hash != Some(expected) {
        return Err(ProviderIngestOutboxError::TransactionHashMismatch);
    }
    Ok(())
}
fn validate_completion_submission_authority(
    completion: &StoredCompletionDeliveryV1,
    current_provider_owner: &AccountId,
    current_authority: &ProviderIngestCompletionAuthorityV1,
    checked_finalized_cursor: ProviderIngestFinalizedCursorV1,
) -> Result<(), ProviderIngestOutboxError> {
    if completion.state != StoredDeliveryStateV1::Signed {
        return Err(ProviderIngestOutboxError::InvalidTransition);
    }
    let context = completion
        .signing_context
        .as_ref()
        .ok_or(ProviderIngestOutboxError::InvalidCheckpoint)?;
    validate_cursor_not_before(context.baseline_finalized_cursor, checked_finalized_cursor)?;
    if &context.expected_authority.provider_owner != current_provider_owner
        || completion.authority_owner.as_ref() != Some(current_provider_owner)
    {
        return Err(ProviderIngestOutboxError::InvalidSigningContext);
    }
    if &context.expected_authority != current_authority
        || completion.authority_floor.as_ref() != Some(current_authority)
        || completion.authority_successor_required
    {
        return Err(ProviderIngestOutboxError::SignerPolicyRollback);
    }
    let observation = completion
        .finalized_authority_observation
        .as_ref()
        .ok_or(ProviderIngestOutboxError::InvalidCheckpoint)?;
    if observation.cursor != checked_finalized_cursor {
        return Err(ProviderIngestOutboxError::StaleFinalizedCursor);
    }
    if observation.provider_owner.as_ref() != Some(current_provider_owner) {
        return Err(ProviderIngestOutboxError::InvalidSigningContext);
    }
    if &observation.completion_authority
        != &ProviderIngestCompletionAuthorityObservationV1::Active(current_authority.clone())
    {
        return Err(ProviderIngestOutboxError::SignerPolicyRollback);
    }
    Ok(())
}
fn derive_signing_token(
    job_id: [u8; 32],
    generation: u64,
    context: &ProviderIngestCompletionSigningContextV1,
) -> Result<[u8; 32], ProviderIngestOutboxError> {
    let encoded = norito::encode_canonical(context)
        .map_err(|error| ProviderIngestOutboxError::CanonicalEncoding(error.to_string()))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROVIDER_INGEST_SIGNING_TOKEN_DOMAIN_V1);
    hasher.update(&job_id);
    hasher.update(&generation.to_le_bytes());
    hash_length_prefixed(&mut hasher, &encoded);
    Ok(*hasher.finalize().as_bytes())
}
fn validate_signing_claim(
    completion: &StoredCompletionDeliveryV1,
    claim: &ProviderIngestCompletionSigningClaimV1,
) -> Result<(), ProviderIngestOutboxError> {
    if completion.state != StoredDeliveryStateV1::Signing
        || claim.generation == 0
        || completion.signing_generation != claim.generation
        || completion.signing_context.as_ref() != Some(&claim.context)
        || completion.completion_epoch != Some(claim.context.completion_epoch)
        || completion.baseline_finalized_height != claim.context.baseline_finalized_cursor.height
        || completion.baseline_finalized_block_hash
            != claim.context.baseline_finalized_cursor.block_hash
        || claim.signing_token
            != derive_signing_token(claim.job_id, claim.generation, &claim.context)?
    {
        return Err(ProviderIngestOutboxError::InvalidSigningClaim);
    }
    Ok(())
}
fn validate_completion_signing_context(
    authorization: &FinalizedProviderIngestAuthorizationV1,
    context: &ProviderIngestCompletionSigningContextV1,
    policy: ProviderIngestOutboxPolicyV1,
) -> Result<(), ProviderIngestOutboxError> {
    context.baseline_finalized_cursor.validate()?;
    validate_completion_authority(&context.expected_authority)?;
    if context.assignment_revision == 0
        || context.completion_epoch == 0
        || context.network_id.as_bytes()[31] & 1 != 1
        || !completion_account_id_fits_canonical_bound(&context.expected_authority.provider_owner)
        || context.expected_payload.network_id() != Some(&context.network_id)
        || context.expected_payload.authority() != &context.expected_authority.completion_signer
        || context.expected_payload.time_to_live().is_none()
    {
        return Err(ProviderIngestOutboxError::InvalidSigningContext);
    }
    let encoded = norito::encode_canonical(&context.expected_payload)
        .map_err(|error| ProviderIngestOutboxError::CanonicalEncoding(error.to_string()))?;
    if encoded.is_empty()
        || u64::try_from(encoded.len()).unwrap_or(u64::MAX) > policy.max_signed_transaction_bytes
    {
        return Err(ProviderIngestOutboxError::InvalidSigningContext);
    }
    validate_completion_instruction(
        authorization,
        context,
        context.expected_payload.instructions(),
    )
    .map_err(|_| ProviderIngestOutboxError::InvalidSigningContext)
}
fn completion_account_id_fits_canonical_bound(account_id: &AccountId) -> bool {
    norito::encode_canonical(account_id).is_ok_and(|encoded| {
        !encoded.is_empty()
            && u64::try_from(encoded.len()).is_ok_and(|length| {
                length
                    <= provider_ingest_outbox_defaults::COMPLETION_ACCOUNT_ID_MAX_CANONICAL_BYTES_V1
            })
    })
}
fn validate_authority_progress(
    retained: Option<ProviderIngestCompletionAuthorityV1>,
    successor_required: bool,
    candidate: &ProviderIngestCompletionAuthorityV1,
) -> Result<(), ProviderIngestOutboxError> {
    validate_completion_authority(candidate)?;
    let Some(retained) = retained else {
        return if successor_required {
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        } else {
            Ok(())
        };
    };
    validate_completion_authority(&retained)?;
    if candidate == &retained {
        return if successor_required {
            Err(ProviderIngestOutboxError::SignerPolicyRollback)
        } else {
            Ok(())
        };
    }
    if candidate.provider_owner != retained.provider_owner {
        return Err(ProviderIngestOutboxError::SignerPolicyRollback);
    }
    let candidate = candidate.signer_policy;
    let retained = retained.signer_policy;
    // Equal policy bytes do not permit replacing the key; full equality was handled above.
    if candidate.policy_id == retained.policy_id {
        let expected_revision = retained
            .revision
            .checked_add(1)
            .ok_or(ProviderIngestOutboxError::SignerPolicyRollback)?;
        if candidate.revision != expected_revision
            || candidate.predecessor_digest != Some(retained.policy_digest)
            || candidate.policy_digest == retained.policy_digest
        {
            return Err(ProviderIngestOutboxError::SignerPolicyRollback);
        }
    } else if candidate.revision != 1 || candidate.predecessor_digest.is_some() {
        return Err(ProviderIngestOutboxError::SignerPolicyRollback);
    }
    Ok(())
}
fn observe_finalized_completion_authority(
    completion: &mut StoredCompletionDeliveryV1,
    provider_owner: Option<&AccountId>,
    completion_authority: &ProviderIngestCompletionAuthorityObservationV1,
    cursor: ProviderIngestFinalizedCursorV1,
) -> Result<bool, ProviderIngestOutboxError> {
    cursor.validate()?;
    if let ProviderIngestCompletionAuthorityObservationV1::Active(authority) = completion_authority
    {
        validate_completion_authority(authority)?;
        if provider_owner != Some(&authority.provider_owner) {
            return Err(ProviderIngestOutboxError::InvalidFinalizedAuthorityObservation);
        }
    }
    if provider_owner.is_none()
        && completion_authority != &ProviderIngestCompletionAuthorityObservationV1::NotChecked
    {
        return Err(ProviderIngestOutboxError::InvalidFinalizedAuthorityObservation);
    }
    let incoming = StoredFinalizedCompletionAuthorityObservationV1 {
        cursor,
        provider_owner: provider_owner.cloned(),
        completion_authority: completion_authority.clone(),
    };
    let Some(retained) = completion.finalized_authority_observation.as_mut() else {
        completion.finalized_authority_observation = Some(incoming);
        return Ok(true);
    };
    validate_finalized_completion_authority_observation(retained)?;
    validate_cursor_not_before(retained.cursor, cursor)?;
    if retained.cursor != cursor {
        *retained = incoming;
        return Ok(true);
    }
    if retained.provider_owner != incoming.provider_owner {
        return Err(ProviderIngestOutboxError::FinalizedAuthorityConflict);
    }
    match (
        &retained.completion_authority,
        &incoming.completion_authority,
    ) {
        (
            &ProviderIngestCompletionAuthorityObservationV1::NotChecked,
            &ProviderIngestCompletionAuthorityObservationV1::NotChecked,
        )
        | (
            &ProviderIngestCompletionAuthorityObservationV1::Missing,
            &ProviderIngestCompletionAuthorityObservationV1::Missing,
        ) => Ok(false),
        (
            ProviderIngestCompletionAuthorityObservationV1::Active(left),
            ProviderIngestCompletionAuthorityObservationV1::Active(right),
        ) => {
            if left == right {
                Ok(false)
            } else {
                Err(ProviderIngestOutboxError::FinalizedAuthorityConflict)
            }
        }
        (
            &ProviderIngestCompletionAuthorityObservationV1::NotChecked,
            ProviderIngestCompletionAuthorityObservationV1::Missing
            | ProviderIngestCompletionAuthorityObservationV1::Active(_),
        ) => {
            retained.completion_authority = incoming.completion_authority.clone();
            Ok(true)
        }
        (
            ProviderIngestCompletionAuthorityObservationV1::Missing
            | ProviderIngestCompletionAuthorityObservationV1::Active(_),
            &ProviderIngestCompletionAuthorityObservationV1::NotChecked,
        ) => Ok(false),
        (
            &ProviderIngestCompletionAuthorityObservationV1::Missing,
            ProviderIngestCompletionAuthorityObservationV1::Active(_),
        )
        | (
            ProviderIngestCompletionAuthorityObservationV1::Active(_),
            &ProviderIngestCompletionAuthorityObservationV1::Missing,
        ) => Err(ProviderIngestOutboxError::FinalizedAuthorityConflict),
    }
}
fn validate_finalized_completion_authority_observation(
    observation: &StoredFinalizedCompletionAuthorityObservationV1,
) -> Result<(), ProviderIngestOutboxError> {
    observation
        .cursor
        .validate()
        .map_err(|_| ProviderIngestOutboxError::InvalidCheckpoint)?;
    if observation
        .provider_owner
        .as_ref()
        .is_some_and(|owner| !completion_account_id_fits_canonical_bound(owner))
        || (observation.provider_owner.is_none()
            && observation.completion_authority
                != ProviderIngestCompletionAuthorityObservationV1::NotChecked)
    {
        return Err(ProviderIngestOutboxError::InvalidCheckpoint);
    }
    if let ProviderIngestCompletionAuthorityObservationV1::Active(policy) =
        &observation.completion_authority
    {
        validate_completion_authority(policy)
            .map_err(|_| ProviderIngestOutboxError::InvalidCheckpoint)?;
        if observation.provider_owner.as_ref() != Some(&policy.provider_owner) {
            return Err(ProviderIngestOutboxError::InvalidCheckpoint);
        }
    }
    Ok(())
}
fn validate_finalized_completion_authority_matches(
    completion: &StoredCompletionDeliveryV1,
    provider_owner: Option<&AccountId>,
    completion_authority: &ProviderIngestCompletionAuthorityObservationV1,
    cursor: ProviderIngestFinalizedCursorV1,
) -> Result<(), ProviderIngestOutboxError> {
    let observation = completion
        .finalized_authority_observation
        .as_ref()
        .ok_or(ProviderIngestOutboxError::InvalidCheckpoint)?;
    if observation.cursor != cursor
        || observation.provider_owner.as_ref() != provider_owner
        || &observation.completion_authority != completion_authority
    {
        return Err(ProviderIngestOutboxError::FinalizedAuthorityConflict);
    }
    Ok(())
}
fn validate_completion_instruction(
    authorization: &FinalizedProviderIngestAuthorizationV1,
    context: &ProviderIngestCompletionSigningContextV1,
    executable: &Executable,
) -> Result<(), ProviderIngestOutboxError> {
    let Executable::Instructions(instructions) = executable else {
        return Err(ProviderIngestOutboxError::InvalidSignedTransaction);
    };
    if instructions.len() != 1 {
        return Err(ProviderIngestOutboxError::InvalidSignedTransaction);
    }
    let completion = instructions[0]
        .as_any()
        .downcast_ref::<CompleteReplicationOrder>()
        .ok_or(ProviderIngestOutboxError::InvalidSignedTransaction)?;
    if completion.order_id().as_bytes() != &authorization.order_id
        || completion.provider_id().as_bytes() != &authorization.provider_id
        || *completion.completion_epoch() != context.completion_epoch
        || completion.expected_authority() != &context.expected_authority
        || *completion.expected_assignment_revision() != context.assignment_revision
        || *completion.finalized_anchor()
            != (ProviderIngestFinalizedAnchorV1 {
                height: context.baseline_finalized_cursor.height,
                block_hash: context.baseline_finalized_cursor.block_hash,
            })
    {
        return Err(ProviderIngestOutboxError::InvalidSignedTransaction);
    }
    Ok(())
}
fn validate_completion_transaction(
    authorization: &FinalizedProviderIngestAuthorizationV1,
    context: &ProviderIngestCompletionSigningContextV1,
    transaction: &SignedTransaction,
    policy: ProviderIngestOutboxPolicyV1,
) -> Result<[u8; 32], ProviderIngestOutboxError> {
    validate_completion_signing_context(authorization, context, policy)
        .map_err(|_| ProviderIngestOutboxError::InvalidSignedTransaction)?;
    let encoded = norito::encode_canonical(transaction)
        .map_err(|error| ProviderIngestOutboxError::CanonicalEncoding(error.to_string()))?;
    if encoded.is_empty()
        || u64::try_from(encoded.len()).unwrap_or(u64::MAX) > policy.max_signed_transaction_bytes
    {
        return Err(ProviderIngestOutboxError::InvalidSignedTransaction);
    }
    if transaction.payload() != &context.expected_payload
        || transaction.network_id() != Some(&context.network_id)
        || transaction.authority() != &context.expected_authority.completion_signer
        || transaction.attachments().is_some()
        || transaction.multisig_signatures().is_some()
        || transaction.verify_signature().is_err()
    {
        return Err(ProviderIngestOutboxError::InvalidSignedTransaction);
    }
    validate_completion_instruction(authorization, context, transaction.instructions())?;
    let transaction_hash = *transaction.hash().as_ref();
    if transaction_hash == [0; 32] {
        return Err(ProviderIngestOutboxError::InvalidSignedTransaction);
    }
    Ok(transaction_hash)
}
fn validate_finalized_completion_evidence(
    evidence: &ProviderIngestFinalizedCompletionV1,
) -> Result<(), ProviderIngestOutboxError> {
    evidence.finalized_cursor.validate()?;
    if evidence.provider_id == [0; 32]
        || evidence.order_id == [0; 32]
        || evidence.manifest_digest == [0; 32]
        || evidence.completion_epoch == 0
        || evidence
            .committed_transaction_hash
            .is_some_and(|hash| hash == [0; 32])
    {
        return Err(ProviderIngestOutboxError::InvalidCompletionEvidence);
    }
    Ok(())
}
fn validate_completion_binding(
    authorization: &FinalizedProviderIngestAuthorizationV1,
    evidence: &ProviderIngestFinalizedCompletionV1,
) -> Result<(), ProviderIngestOutboxError> {
    if evidence.provider_id != authorization.provider_id
        || evidence.order_id != authorization.order_id
        || evidence.manifest_digest != authorization.manifest_digest
    {
        return Err(ProviderIngestOutboxError::InvalidCompletionEvidence);
    }
    Ok(())
}
fn validate_finalized_cancellation_evidence(
    evidence: &ProviderIngestFinalizedCancellationV1,
) -> Result<(), ProviderIngestOutboxError> {
    evidence.finalized_cursor.validate()?;
    if evidence.provider_id == [0; 32]
        || evidence.order_id == [0; 32]
        || evidence.manifest_digest == [0; 32]
    {
        return Err(ProviderIngestOutboxError::InvalidCancellationEvidence);
    }
    Ok(())
}
fn validate_retained_finalized_snapshot(
    checkpoint: &ProviderIngestOutboxCheckpointV1,
    required_finalized_cursor: Option<ProviderIngestFinalizedCursorV1>,
) -> Result<Option<(ProviderIngestFinalizedCursorV1, u64)>, ProviderIngestOutboxError> {
    let retained_snapshot = match (
        checkpoint.finalized_cursor_high_water,
        checkpoint.finalized_block_time_ms_high_water,
    ) {
        (Some(cursor), Some(finalized_block_time_ms)) => {
            cursor
                .validate()
                .map_err(|_| ProviderIngestOutboxError::InvalidCheckpoint)?;
            if finalized_block_time_ms == 0 {
                return Err(ProviderIngestOutboxError::InvalidCheckpoint);
            }
            Some((cursor, finalized_block_time_ms))
        }
        (None, None) => None,
        (None, Some(_)) | (Some(_), None) => {
            return Err(ProviderIngestOutboxError::InvalidCheckpoint);
        }
    };
    if let Some(required_finalized_cursor) = required_finalized_cursor
        && retained_snapshot.map(|(cursor, _)| cursor) != Some(required_finalized_cursor)
    {
        return Err(ProviderIngestOutboxError::StaleFinalizedCursor);
    }
    Ok(retained_snapshot)
}
fn validate_cancellation_binding(
    authorization: &FinalizedProviderIngestAuthorizationV1,
    evidence: &ProviderIngestFinalizedCancellationV1,
) -> Result<(), ProviderIngestOutboxError> {
    if evidence.provider_id != authorization.provider_id
        || evidence.order_id != authorization.order_id
        || evidence.manifest_digest != authorization.manifest_digest
    {
        return Err(ProviderIngestOutboxError::InvalidCancellationEvidence);
    }
    Ok(())
}
fn validate_cursor_not_before(
    retained: ProviderIngestFinalizedCursorV1,
    observed: ProviderIngestFinalizedCursorV1,
) -> Result<(), ProviderIngestOutboxError> {
    if observed.height < retained.height
        || (observed.height == retained.height && observed.block_hash != retained.block_hash)
    {
        return Err(ProviderIngestOutboxError::StaleFinalizedCursor);
    }
    Ok(())
}
fn committed_hashes_conflict(retained: Option<[u8; 32]>, observed: Option<[u8; 32]>) -> bool {
    matches!((retained, observed), (Some(left), Some(right)) if left != right)
}
fn completion_status(completion: &StoredCompletionDeliveryV1) -> ProviderIngestCompletionStateV1 {
    let baseline = ProviderIngestFinalizedCursorV1 {
        height: completion.baseline_finalized_height,
        block_hash: completion.baseline_finalized_block_hash,
    };
    match completion.state {
        StoredDeliveryStateV1::Ready => ProviderIngestCompletionStateV1::Ready {
            attempts: completion.attempts,
            next_attempt_at_ms: completion.next_attempt_at_ms,
            last_failure_class: completion.last_failure_class,
        },
        StoredDeliveryStateV1::Signing => ProviderIngestCompletionStateV1::Signing {
            attempts: completion.attempts,
            baseline_finalized_cursor: baseline,
            completion_epoch: completion
                .completion_epoch
                .expect("validated signing state has completion epoch"),
        },
        StoredDeliveryStateV1::Signed => ProviderIngestCompletionStateV1::Signed {
            attempts: completion.attempts,
            baseline_finalized_cursor: baseline,
            completion_epoch: completion
                .completion_epoch
                .expect("validated signed state has completion epoch"),
            transaction_hash: completion
                .transaction_hash
                .expect("validated signed state has transaction hash"),
            ever_exposed: completion.ever_exposed,
            next_attempt_at_ms: completion.next_attempt_at_ms,
        },
        StoredDeliveryStateV1::Ambiguous => ProviderIngestCompletionStateV1::Ambiguous {
            attempts: completion.attempts,
            baseline_finalized_cursor: baseline,
            completion_epoch: completion
                .completion_epoch
                .expect("validated ambiguous state has completion epoch"),
            transaction_hash: completion
                .transaction_hash
                .expect("validated ambiguous state has transaction hash"),
        },
        StoredDeliveryStateV1::Submitted => ProviderIngestCompletionStateV1::Submitted {
            attempts: completion.attempts,
            baseline_finalized_cursor: baseline,
            completion_epoch: completion
                .completion_epoch
                .expect("validated submitted state has completion epoch"),
            transaction_hash: completion
                .transaction_hash
                .expect("validated submitted state has transaction hash"),
        },
    }
}
fn active_status(entry: &StoredActiveProviderIngestV1) -> ProviderIngestStatusV1 {
    let state = match &entry.state {
        StoredProviderIngestStateV1::PendingSource => {
            ProviderIngestDeliveryStateV1::PendingSource {
                attempts: entry.source_attempts,
            }
        }
        StoredProviderIngestStateV1::SourceClaimed {
            generation,
            lease_expires_at_ms,
            ..
        } => ProviderIngestDeliveryStateV1::SourceClaimed {
            attempts: entry.source_attempts,
            generation: *generation,
            lease_expires_at_ms: *lease_expires_at_ms,
        },
        StoredProviderIngestStateV1::RetryScheduled {
            next_attempt_at_ms,
            failure_class,
        } => ProviderIngestDeliveryStateV1::RetryScheduled {
            attempts: entry.source_attempts,
            next_attempt_at_ms: *next_attempt_at_ms,
            failure_class: *failure_class,
        },
        StoredProviderIngestStateV1::LocalStored {
            manifest_id,
            musubi_bundle,
            completion,
        } => ProviderIngestDeliveryStateV1::LocalStored {
            manifest_id: manifest_id.clone(),
            musubi_bundle: musubi_bundle
                .as_deref()
                .map(|receipt| Box::new(receipt.to_receipt())),
            completion: completion_status(completion),
        },
    };
    status_row(&entry.authorization, state)
}
fn terminal_status(entry: &StoredTerminalProviderIngestV1) -> ProviderIngestStatusV1 {
    let state = match &entry.outcome {
        StoredProviderIngestTerminalOutcomeV1::FinalizedCompleted {
            manifest_id,
            musubi_bundle,
            completion_epoch,
            completed_by,
            committed_transaction_hash,
            finalized_cursor,
        } => ProviderIngestDeliveryStateV1::FinalizedCompleted {
            manifest_id: manifest_id.clone(),
            musubi_bundle: musubi_bundle
                .as_deref()
                .map(|receipt| Box::new(receipt.to_receipt())),
            completion_epoch: *completion_epoch,
            completed_by: completed_by.clone(),
            committed_transaction_hash: *committed_transaction_hash,
            finalized_cursor: *finalized_cursor,
        },
        StoredProviderIngestTerminalOutcomeV1::Cancelled {
            reason,
            observed_finalized_cursor,
        } => ProviderIngestDeliveryStateV1::Cancelled {
            reason: *reason,
            observed_finalized_cursor: *observed_finalized_cursor,
        },
        StoredProviderIngestTerminalOutcomeV1::DeadLetter {
            attempts,
            reason,
            last_failure_class,
            observed_finalized_cursor,
        } => ProviderIngestDeliveryStateV1::DeadLetter {
            attempts: *attempts,
            reason: *reason,
            last_failure_class: *last_failure_class,
            observed_finalized_cursor: *observed_finalized_cursor,
        },
    };
    status_row(&entry.authorization, state)
}
fn status_row(
    authorization: &FinalizedProviderIngestAuthorizationV1,
    state: ProviderIngestDeliveryStateV1,
) -> ProviderIngestStatusV1 {
    ProviderIngestStatusV1 {
        job_id: authorization.job_id,
        admission_finalized_cursor: authorization.admission_finalized_cursor,
        provider_id: authorization.provider_id,
        order_id: authorization.order_id,
        manifest_digest: authorization.manifest_digest,
        state,
    }
}
fn checkpoint_counts(
    checkpoint: &ProviderIngestOutboxCheckpointV1,
) -> ProviderIngestOutboxCountsV1 {
    ProviderIngestOutboxCountsV1 {
        active: checkpoint.active.len(),
        terminal: checkpoint.terminal.len(),
        dead_letters: checkpoint
            .terminal
            .iter()
            .filter(|entry| {
                matches!(
                    &entry.outcome,
                    StoredProviderIngestTerminalOutcomeV1::DeadLetter { .. }
                )
            })
            .count(),
    }
}
fn validate_checkpoint_count_snapshot(
    checkpoint: &ProviderIngestOutboxCheckpointV1,
    counts: ProviderIngestOutboxCountsV1,
    policy: ProviderIngestOutboxPolicyV1,
) -> Result<(), ProviderIngestOutboxError> {
    let retained_entries = counts
        .active
        .checked_add(counts.terminal)
        .and_then(|count| u64::try_from(count).ok())
        .ok_or(ProviderIngestOutboxError::InvalidCheckpoint)?;
    if checkpoint.magic != PROVIDER_INGEST_CHECKPOINT_MAGIC_V5
        || checkpoint.version != PROVIDER_INGEST_OUTBOX_LAYOUT_VERSION_V5
        || checkpoint.next_sequence == 0
        || counts.active != checkpoint.active.len()
        || counts.terminal != checkpoint.terminal.len()
        || counts.active > policy.max_active_entries
        || counts.terminal > policy.max_terminal_entries
        || counts.dead_letters > counts.terminal
        || retained_entries >= checkpoint.next_sequence
    {
        return Err(ProviderIngestOutboxError::InvalidCheckpoint);
    }
    validate_retained_finalized_snapshot(checkpoint, None)?;
    Ok(())
}
fn validate_checkpoint(
    checkpoint: &ProviderIngestOutboxCheckpointV1,
    policy: ProviderIngestOutboxPolicyV1,
) -> Result<(), ProviderIngestOutboxError> {
    validate_checkpoint_count_snapshot(checkpoint, checkpoint_counts(checkpoint), policy)?;
    let mut job_ids = BTreeSet::new();
    let mut order_bindings = BTreeSet::new();
    let mut sequences = BTreeSet::new();
    let mut previous_sequence = 0;
    for entry in &checkpoint.active {
        entry.authorization.validate()?;
        if entry.sequence == 0
            || entry.sequence <= previous_sequence
            || entry.sequence >= checkpoint.next_sequence
            || entry.source_attempts >= policy.max_attempts
            || !job_ids.insert(entry.authorization.job_id)
            || !order_bindings.insert((
                entry.authorization.provider_id,
                entry.authorization.order_id,
            ))
            || !sequences.insert(entry.sequence)
        {
            return Err(ProviderIngestOutboxError::InvalidCheckpoint);
        }
        validate_active_state(entry, policy)?;
        previous_sequence = entry.sequence;
    }
    let mut previous_terminal_job = None;
    for entry in &checkpoint.terminal {
        entry.authorization.validate()?;
        if entry.sequence == 0
            || entry.sequence >= checkpoint.next_sequence
            || previous_terminal_job.is_some_and(|previous| previous >= entry.authorization.job_id)
            || !job_ids.insert(entry.authorization.job_id)
            || !order_bindings.insert((
                entry.authorization.provider_id,
                entry.authorization.order_id,
            ))
            || !sequences.insert(entry.sequence)
        {
            return Err(ProviderIngestOutboxError::InvalidCheckpoint);
        }
        validate_terminal(entry, policy)?;
        previous_terminal_job = Some(entry.authorization.job_id);
    }
    validate_checkpoint_finalized_high_water(checkpoint)?;
    Ok(())
}
fn validate_checkpoint_finalized_high_water(
    checkpoint: &ProviderIngestOutboxCheckpointV1,
) -> Result<(), ProviderIngestOutboxError> {
    let retained_snapshot = validate_retained_finalized_snapshot(checkpoint, None)?;
    let Some((high_water, _)) = retained_snapshot else {
        let has_receipt = checkpoint.active.iter().any(|entry| {
            matches!(
                &entry.state,
                StoredProviderIngestStateV1::LocalStored {
                    musubi_bundle: Some(_),
                    ..
                }
            )
        }) || checkpoint.terminal.iter().any(|entry| {
            matches!(
                &entry.outcome,
                StoredProviderIngestTerminalOutcomeV1::FinalizedCompleted {
                    musubi_bundle: Some(_),
                    ..
                }
            )
        });
        return if has_receipt {
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        } else {
            Ok(())
        };
    };
    for entry in &checkpoint.active {
        validate_cursor_not_before(entry.authorization.admission_finalized_cursor, high_water)
            .map_err(|_| ProviderIngestOutboxError::InvalidCheckpoint)?;
        if let StoredProviderIngestStateV1::LocalStored { completion, .. } = &entry.state
            && completion.baseline_finalized_height != 0
        {
            validate_cursor_not_before(
                ProviderIngestFinalizedCursorV1 {
                    height: completion.baseline_finalized_height,
                    block_hash: completion.baseline_finalized_block_hash,
                },
                high_water,
            )
            .map_err(|_| ProviderIngestOutboxError::InvalidCheckpoint)?;
        }
        if let StoredProviderIngestStateV1::LocalStored { completion, .. } = &entry.state
            && let Some(observation) = &completion.finalized_authority_observation
        {
            validate_cursor_not_before(observation.cursor, high_water)
                .map_err(|_| ProviderIngestOutboxError::InvalidCheckpoint)?;
        }
        if let StoredProviderIngestStateV1::LocalStored {
            musubi_bundle: Some(receipt),
            ..
        } = &entry.state
        {
            validate_cursor_not_before(receipt.observed_finalized_cursor(), high_water)
                .map_err(|_| ProviderIngestOutboxError::InvalidCheckpoint)?;
        }
    }
    for entry in &checkpoint.terminal {
        validate_cursor_not_before(entry.authorization.admission_finalized_cursor, high_water)
            .map_err(|_| ProviderIngestOutboxError::InvalidCheckpoint)?;
        let terminal_cursor = match &entry.outcome {
            StoredProviderIngestTerminalOutcomeV1::FinalizedCompleted {
                finalized_cursor, ..
            } => *finalized_cursor,
            StoredProviderIngestTerminalOutcomeV1::Cancelled {
                observed_finalized_cursor,
                ..
            }
            | StoredProviderIngestTerminalOutcomeV1::DeadLetter {
                observed_finalized_cursor,
                ..
            } => *observed_finalized_cursor,
        };
        validate_cursor_not_before(terminal_cursor, high_water)
            .map_err(|_| ProviderIngestOutboxError::InvalidCheckpoint)?;
        if let StoredProviderIngestTerminalOutcomeV1::FinalizedCompleted {
            musubi_bundle: Some(receipt),
            finalized_cursor,
            ..
        } = &entry.outcome
        {
            validate_cursor_not_before(receipt.observed_finalized_cursor(), *finalized_cursor)
                .map_err(|_| ProviderIngestOutboxError::InvalidCheckpoint)?;
            validate_cursor_not_before(receipt.observed_finalized_cursor(), high_water)
                .map_err(|_| ProviderIngestOutboxError::InvalidCheckpoint)?;
        }
    }
    Ok(())
}
fn validate_active_state(
    entry: &StoredActiveProviderIngestV1,
    policy: ProviderIngestOutboxPolicyV1,
) -> Result<(), ProviderIngestOutboxError> {
    match &entry.state {
        StoredProviderIngestStateV1::PendingSource => {}
        StoredProviderIngestStateV1::SourceClaimed {
            owner,
            generation,
            lease_token,
            lease_expires_at_ms,
        } => {
            if *generation == 0
                || *generation != entry.claim_generation
                || *lease_expires_at_ms == 0
                || *lease_token
                    != derive_lease_token(
                        entry.authorization.job_id,
                        *owner,
                        *generation,
                        *lease_expires_at_ms,
                    )
            {
                return Err(ProviderIngestOutboxError::InvalidCheckpoint);
            }
        }
        StoredProviderIngestStateV1::RetryScheduled {
            next_attempt_at_ms,
            failure_class,
        } => {
            if entry.source_attempts == 0
                || *next_attempt_at_ms == 0
                || !failure_class.is_source_retryable()
            {
                return Err(ProviderIngestOutboxError::InvalidCheckpoint);
            }
        }
        StoredProviderIngestStateV1::LocalStored {
            manifest_id,
            musubi_bundle,
            completion,
        } => {
            validate_manifest_id(&entry.authorization, manifest_id)?;
            if !stored_musubi_receipt_shape_is_valid(&entry.authorization, musubi_bundle.as_deref())
            {
                return Err(ProviderIngestOutboxError::InvalidCheckpoint);
            }
            validate_completion_delivery(&entry.authorization, completion, policy)?;
        }
    }
    Ok(())
}
#[allow(clippy::too_many_lines)]
fn validate_completion_delivery(
    authorization: &FinalizedProviderIngestAuthorizationV1,
    completion: &StoredCompletionDeliveryV1,
    policy: ProviderIngestOutboxPolicyV1,
) -> Result<(), ProviderIngestOutboxError> {
    if !durable::validate_delivery(completion, policy.max_attempts) {
        return Err(ProviderIngestOutboxError::InvalidCheckpoint);
    }
    if completion
        .authority_owner
        .as_ref()
        .is_some_and(|owner| !completion_account_id_fits_canonical_bound(owner))
    {
        return Err(ProviderIngestOutboxError::InvalidCheckpoint);
    }
    let is_exposed = matches!(
        completion.state,
        StoredDeliveryStateV1::Ambiguous | StoredDeliveryStateV1::Submitted
    ) || (completion.state == StoredDeliveryStateV1::Signed
        && completion.ever_exposed);
    if let Some(observation) = &completion.finalized_authority_observation {
        validate_finalized_completion_authority_observation(observation)?;
        validate_cursor_after_admission(authorization, observation.cursor)
            .map_err(|_| ProviderIngestOutboxError::InvalidCheckpoint)?;
    }
    match (
        completion.authority_owner.as_ref(),
        completion.authority_floor.clone(),
    ) {
        (Some(owner), Some(authority)) => {
            validate_completion_authority(&authority)
                .map_err(|_| ProviderIngestOutboxError::InvalidCheckpoint)?;
            if owner != &authority.provider_owner {
                return Err(ProviderIngestOutboxError::InvalidCheckpoint);
            }
        }
        (None, None) if completion.authority_successor_required => {
            return Err(ProviderIngestOutboxError::InvalidCheckpoint);
        }
        (None, None) => {}
        (Some(_), None) if is_exposed => {}
        (Some(owner), None)
            if completion.state == StoredDeliveryStateV1::Ready
                && !completion.authority_successor_required
                && completion
                    .finalized_authority_observation
                    .as_ref()
                    .is_some_and(|observation| {
                        observation.provider_owner.as_ref() == Some(owner)
                    }) => {}
        (Some(_), None) | (None, Some(_)) => {
            return Err(ProviderIngestOutboxError::InvalidCheckpoint);
        }
    }
    match completion.state {
        StoredDeliveryStateV1::Ready => {
            if completion.completion_epoch.is_some()
                || completion.signing_context.is_some()
                || completion.transaction_hash.is_some()
                || completion.signed_transaction.is_some()
                || completion.signing_claimed_at_ms != 0
                || completion.ever_exposed
            {
                return Err(ProviderIngestOutboxError::InvalidCheckpoint);
            }
        }
        StoredDeliveryStateV1::Signing => {
            let context = completion
                .signing_context
                .as_ref()
                .ok_or(ProviderIngestOutboxError::InvalidCheckpoint)?;
            if completion.signing_generation == 0
                || completion.signing_claimed_at_ms == 0
                || completion.completion_epoch != Some(context.completion_epoch)
                || completion.authority_owner.as_ref()
                    != Some(&context.expected_authority.provider_owner)
                || completion.authority_floor.as_ref() != Some(&context.expected_authority)
                || completion.authority_successor_required
                || completion.baseline_finalized_height != context.baseline_finalized_cursor.height
                || completion.baseline_finalized_block_hash
                    != context.baseline_finalized_cursor.block_hash
                || completion.transaction_hash.is_some()
                || completion.next_attempt_at_ms != 0
                || completion.ever_exposed
            {
                return Err(ProviderIngestOutboxError::InvalidCheckpoint);
            }
            validate_unexposed_completion_authority_observation(completion, context)?;
            completion_signing_recover_at_ms(completion.signing_claimed_at_ms, policy)
                .map_err(|_| ProviderIngestOutboxError::InvalidCheckpoint)?;
            validate_completion_signing_context(authorization, context, policy)
                .map_err(|_| ProviderIngestOutboxError::InvalidCheckpoint)?;
        }
        StoredDeliveryStateV1::Signed
        | StoredDeliveryStateV1::Ambiguous
        | StoredDeliveryStateV1::Submitted => {
            let context = completion
                .signing_context
                .as_ref()
                .ok_or(ProviderIngestOutboxError::InvalidCheckpoint)?;
            if completion.signing_generation == 0
                || completion.signing_claimed_at_ms != 0
                || completion.completion_epoch != Some(context.completion_epoch)
                || (!is_exposed
                    && (completion.authority_owner.as_ref()
                        != Some(&context.expected_authority.provider_owner)
                        || completion.authority_floor.as_ref()
                            != Some(&context.expected_authority)
                        || completion.authority_successor_required))
                || (matches!(
                    completion.state,
                    StoredDeliveryStateV1::Ambiguous | StoredDeliveryStateV1::Submitted
                ) && !completion.ever_exposed)
            {
                return Err(ProviderIngestOutboxError::InvalidCheckpoint);
            }
            if !is_exposed {
                validate_unexposed_completion_authority_observation(completion, context)?;
            }
            validate_cursor_not_before(
                context.baseline_finalized_cursor,
                ProviderIngestFinalizedCursorV1 {
                    height: completion.baseline_finalized_height,
                    block_hash: completion.baseline_finalized_block_hash,
                },
            )
            .map_err(|_| ProviderIngestOutboxError::InvalidCheckpoint)?;
            let transaction = completion
                .signed_transaction
                .as_ref()
                .ok_or(ProviderIngestOutboxError::InvalidCheckpoint)?;
            let transaction_hash =
                validate_completion_transaction(authorization, context, transaction, policy)?;
            if completion.transaction_hash != Some(transaction_hash)
                || (matches!(
                    completion.state,
                    StoredDeliveryStateV1::Ambiguous | StoredDeliveryStateV1::Submitted
                ) && completion.next_attempt_at_ms != 0)
            {
                return Err(ProviderIngestOutboxError::InvalidCheckpoint);
            }
        }
    }
    Ok(())
}
fn validate_unexposed_completion_authority_observation(
    completion: &StoredCompletionDeliveryV1,
    context: &ProviderIngestCompletionSigningContextV1,
) -> Result<(), ProviderIngestOutboxError> {
    let observation = completion
        .finalized_authority_observation
        .as_ref()
        .ok_or(ProviderIngestOutboxError::InvalidCheckpoint)?;
    validate_cursor_not_before(context.baseline_finalized_cursor, observation.cursor)
        .map_err(|_| ProviderIngestOutboxError::InvalidCheckpoint)?;
    let signer_policy_matches = match &observation.completion_authority {
        ProviderIngestCompletionAuthorityObservationV1::NotChecked => true,
        ProviderIngestCompletionAuthorityObservationV1::Missing => false,
        ProviderIngestCompletionAuthorityObservationV1::Active(policy) => {
            policy == &context.expected_authority
        }
    };
    if observation.provider_owner.as_ref() != Some(&context.expected_authority.provider_owner)
        || !signer_policy_matches
    {
        return Err(ProviderIngestOutboxError::InvalidCheckpoint);
    }
    Ok(())
}
fn validate_terminal(
    entry: &StoredTerminalProviderIngestV1,
    policy: ProviderIngestOutboxPolicyV1,
) -> Result<(), ProviderIngestOutboxError> {
    match &entry.outcome {
        StoredProviderIngestTerminalOutcomeV1::FinalizedCompleted {
            manifest_id,
            musubi_bundle,
            completion_epoch,
            completed_by,
            committed_transaction_hash,
            finalized_cursor,
        } => {
            match manifest_id {
                Some(manifest_id) => {
                    validate_manifest_id(&entry.authorization, manifest_id)?;
                    if !stored_musubi_receipt_shape_is_valid(
                        &entry.authorization,
                        musubi_bundle.as_deref(),
                    ) {
                        return Err(ProviderIngestOutboxError::InvalidCheckpoint);
                    }
                }
                None if musubi_bundle.is_some() => {
                    return Err(ProviderIngestOutboxError::InvalidCheckpoint);
                }
                None => {}
            }
            validate_cursor_after_admission(&entry.authorization, *finalized_cursor)?;
            if *completion_epoch == 0
                || !completion_account_id_fits_canonical_bound(completed_by)
                || committed_transaction_hash.is_some_and(|hash| hash == [0; 32])
            {
                return Err(ProviderIngestOutboxError::InvalidCheckpoint);
            }
        }
        StoredProviderIngestTerminalOutcomeV1::Cancelled {
            observed_finalized_cursor,
            ..
        } => {
            validate_cursor_after_admission(&entry.authorization, *observed_finalized_cursor)?;
        }
        StoredProviderIngestTerminalOutcomeV1::DeadLetter {
            attempts,
            reason,
            last_failure_class,
            observed_finalized_cursor,
            ..
        } => {
            validate_cursor_after_admission(&entry.authorization, *observed_finalized_cursor)?;
            if *attempts == 0
                || (*reason == ProviderIngestDeadLetterReasonV1::RetryExhausted
                    && (*attempts < policy.max_attempts
                        || !last_failure_class.is_retry_exhaustible()))
                || (*reason != ProviderIngestDeadLetterReasonV1::RetryExhausted
                    && *attempts > policy.max_attempts)
                || (*reason != ProviderIngestDeadLetterReasonV1::RetryExhausted
                    && !valid_permanent_failure_pair(*reason, *last_failure_class))
            {
                return Err(ProviderIngestOutboxError::InvalidCheckpoint);
            }
        }
    }
    Ok(())
}
/// Durable provider-ingest state-machine errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProviderIngestOutboxError {
    /// Dedicated policy is zero, inconsistent, or unrepresentable.
    #[error("provider-ingest outbox policy is invalid")]
    InvalidPolicy,
    /// Finalized authorization is malformed or self-inconsistent.
    #[error("provider-ingest authorization is invalid")]
    InvalidAuthorization,
    /// Canonical encoding failed.
    #[error("provider-ingest canonical encoding failed: {0}")]
    CanonicalEncoding(String),
    /// Checkpoint I/O failed before commit.
    #[error("provider-ingest checkpoint failed: {0}")]
    Checkpoint(String),
    /// Another live runtime owns this persistent outbox.
    #[error("provider-ingest checkpoint writer is busy")]
    CheckpointBusy,
    /// Checkpoint is malformed, noncanonical, or from a retired layout.
    #[error("provider-ingest checkpoint is invalid")]
    InvalidCheckpoint,
    /// Configured external checkpoint provider identity or qualification is invalid.
    #[error("provider-ingest checkpoint provider binding is invalid")]
    InvalidCheckpointProviderBinding,
    /// Injected provider identity or qualification differs from configuration.
    #[error("provider-ingest checkpoint provider identity does not match configuration")]
    CheckpointProviderIdentityMismatch,
    /// External sealed checkpoint provider is unavailable.
    #[error("provider-ingest checkpoint provider is unavailable")]
    CheckpointProviderUnavailable,
    /// External sealed checkpoint provider rejected the exact operation.
    #[error("provider-ingest checkpoint provider rejected the operation")]
    CheckpointProviderRejected,
    /// The bounded checkpoint worker could not admit an operation before its deadline.
    #[error("provider-ingest checkpoint provider worker is busy")]
    CheckpointProviderBusy,
    /// A dispatched checkpoint operation lost its worker response.
    #[error("provider-ingest checkpoint provider response was lost")]
    CheckpointProviderResponseLost,
    /// External sealed checkpoint operation exceeded its configured deadline.
    #[error("provider-ingest checkpoint provider operation timed out")]
    CheckpointProviderTimeout,
    /// CAS readback proves that the exact predecessor remains authoritative.
    #[error("provider-ingest sealed checkpoint compare-and-swap left the predecessor unchanged")]
    CheckpointCasUnchanged,
    /// External sealed checkpoint commit cannot be established safely.
    #[error("provider-ingest sealed checkpoint outcome is ambiguous")]
    CheckpointAuthorityAmbiguous,
    /// External sealed checkpoint record is malformed or substituted.
    #[error("provider-ingest sealed checkpoint is invalid")]
    InvalidSealedCheckpoint,
    /// Local/cache state is ahead of, absent from, or too far behind sealed state.
    #[error("provider-ingest checkpoint rollback was detected")]
    CheckpointRollback,
    /// Local/cache and sealed checkpoint histories conflict.
    #[error("provider-ingest checkpoint fork was detected")]
    CheckpointFork,
    /// Canonical checkpoint or signed transaction exceeds its bound.
    #[error("provider-ingest checkpoint exceeds its configured bound")]
    CheckpointTooLarge,
    /// Active capacity or protected terminal-tombstone capacity is exhausted.
    #[error("provider-ingest active or protected terminal capacity is exhausted")]
    CapacityExhausted,
    /// Stable job identity conflicts with different immutable material.
    #[error("provider-ingest job identity conflicts with retained material")]
    IdempotencyConflict,
    /// The same finalized height was presented with another block hash.
    #[error("provider-ingest admission evidence conflicts at the same finalized height")]
    AdmissionEvidenceConflict,
    /// A provider/order identity was reused for different manifest material.
    #[error("provider-ingest provider/order binding conflicts with retained state")]
    OrderBindingConflict,
    /// Sequence allocation overflowed.
    #[error("provider-ingest sequence is exhausted")]
    SequenceExhausted,
    /// Stable job identity is not retained as active.
    #[error("provider-ingest job is unknown or not active")]
    UnknownJob,
    /// An opaque claim owner was zero.
    #[error("provider-ingest source claim owner is invalid")]
    InvalidClaimOwner,
    /// Another unexpired source lease is active.
    #[error("provider-ingest source lease is already held")]
    LeaseAlreadyHeld,
    /// Source claim generation overflowed.
    #[error("provider-ingest source claim generation is exhausted")]
    LeaseGenerationExhausted,
    /// Source claim does not match the exact durable lease.
    #[error("provider-ingest source claim is invalid")]
    InvalidSourceClaim,
    /// Source claim lease expired.
    #[error("provider-ingest source claim expired")]
    SourceClaimExpired,
    /// Retry backoff has not elapsed.
    #[error("provider-ingest retry is not due")]
    RetryNotDue,
    /// Failure class is not valid for the requested transition.
    #[error("provider-ingest failure class is invalid for this transition")]
    InvalidFailureClass,
    /// Canonical manifest identifier is invalid.
    #[error("provider-ingest manifest identifier is invalid")]
    InvalidManifestId,
    /// Attempt accounting overflowed.
    #[error("provider-ingest attempt counter overflowed")]
    AttemptOverflow,
    /// Retry attempts reached the governed bound.
    #[error("provider-ingest retry bound is exhausted")]
    RetryExhausted,
    /// Timestamp arithmetic overflowed.
    #[error("provider-ingest timestamp arithmetic overflowed")]
    TimestampOverflow,
    /// Runtime time must be non-zero for a durable retry or lease transition.
    #[error("provider-ingest runtime timestamp is invalid")]
    InvalidRuntimeTimestamp,
    /// Finalized cursor is zero.
    #[error("provider-ingest finalized cursor is invalid")]
    InvalidFinalizedCursor,
    /// Finalized block creation time is zero and cannot prove transaction expiry.
    #[error("provider-ingest finalized block time is invalid")]
    InvalidFinalizedBlockTime,
    /// Finalized cursor predates or forks retained evidence.
    #[error("provider-ingest finalized cursor is stale or conflicting")]
    StaleFinalizedCursor,
    /// The same finalized cursor was presented with another block creation time.
    #[error("provider-ingest finalized cursor/time snapshot conflicts with retained evidence")]
    FinalizedSnapshotConflict,
    /// Finalized owner/policy observation is internally inconsistent.
    #[error("provider-ingest finalized completion authority observation is invalid")]
    InvalidFinalizedAuthorityObservation,
    /// One finalized cursor was presented with conflicting provider authority.
    #[error("provider-ingest finalized completion authority conflicts at one cursor")]
    FinalizedAuthorityConflict,
    /// Signed transaction is not the exact provider-specific completion.
    #[error("provider-ingest signed completion transaction is invalid")]
    InvalidSignedTransaction,
    /// Prepared completion signing context is malformed or mismatched.
    #[error("provider-ingest completion signing context is invalid")]
    InvalidSigningContext,
    /// Governed completion-signer policy identity, revision, or digest is invalid.
    #[error("provider-ingest completion signer policy is invalid")]
    InvalidSignerPolicy,
    /// Governed signer policy regressed, equivocated, or changed identity.
    #[error("provider-ingest completion signer policy is not a canonical successor")]
    SignerPolicyRollback,
    /// Signer claim does not match the exact durable prepared operation.
    #[error("provider-ingest completion signing claim is invalid")]
    InvalidSigningClaim,
    /// Completion signer-claim generation overflowed.
    #[error("provider-ingest completion signing generation is exhausted")]
    SigningGenerationExhausted,
    /// Caller referenced a different exact transaction.
    #[error("provider-ingest completion transaction hash does not match")]
    TransactionHashMismatch,
    /// Committed-state evidence does not match the retained provider completion.
    #[error("provider-ingest finalized completion evidence is invalid")]
    InvalidCompletionEvidence,
    /// Finalized cancellation evidence does not match the retained binding.
    #[error("provider-ingest finalized cancellation evidence is invalid")]
    InvalidCancellationEvidence,
    /// Requested transition is unsafe from the current crash state.
    #[error("provider-ingest state transition is invalid")]
    InvalidTransition,
    /// Job is already terminal with another outcome.
    #[error("provider-ingest job is already terminal")]
    AlreadyTerminal,
    /// Status page limit is outside the governed bound.
    #[error("provider-ingest status page limit is invalid")]
    InvalidPageLimit,
    /// Runtime state lock or bounded status-page reservation is unavailable.
    #[error("provider-ingest outbox state is unavailable")]
    StateUnavailable,
    /// Atomic rename committed but directory durability is uncertain.
    #[error("provider-ingest checkpoint durability is uncertain")]
    DurabilityUncertain,
    /// A prior uncertain write poisoned all further mutation/readback.
    #[error("provider-ingest outbox durability is poisoned")]
    DurabilityPoisoned,
}
impl From<DeliveryTransitionError> for ProviderIngestOutboxError {
    fn from(error: DeliveryTransitionError) -> Self {
        match error {
            DeliveryTransitionError::InvalidFinalizedCursor => Self::InvalidFinalizedCursor,
            DeliveryTransitionError::InvalidTransition => Self::InvalidTransition,
            DeliveryTransitionError::RetryExhausted => Self::RetryExhausted,
        }
    }
}
impl From<ProviderIngestCheckpointExternalErrorV1> for ProviderIngestOutboxError {
    fn from(error: ProviderIngestCheckpointExternalErrorV1) -> Self {
        match error {
            ProviderIngestCheckpointExternalErrorV1::Unavailable => {
                Self::CheckpointProviderUnavailable
            }
            ProviderIngestCheckpointExternalErrorV1::Rejected => Self::CheckpointProviderRejected,
            ProviderIngestCheckpointExternalErrorV1::Ambiguous => {
                Self::CheckpointAuthorityAmbiguous
            }
        }
    }
}
#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod tests {
    use iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionSignerPolicyV1;
    mod authorization_fixtures;

    use super::*;
    use authorization_fixtures::{
        assert_musubi_context_rejects_unmarked_network, authorization,
        authorization_with_musubi_context, musubi_authorization_and_receipt, musubi_commitment,
        network_id, test_network_id,
    };
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_data_model::{
        account::AccountId,
        isi::InstructionBox,
        proof::{ProofAttachment, ProofBox, VerifyingKeyId},
        sorafs::{
            capacity::ProviderId,
            pin_registry::{ManifestDigest, ReplicationOrderId},
        },
        transaction::{FeePaymentIntent, TransactionBuilder, signed::MultisigSignatures},
    };
    use std::{
        fs,
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };
    use tempfile::{TempDir, tempdir};
    fn policy() -> ProviderIngestOutboxPolicyV1 {
        ProviderIngestOutboxPolicyV1 {
            max_active_entries: 16,
            max_terminal_entries: 4,
            max_attempts: 4,
            checkpoint_max_bytes: 8 * 1024 * 1024,
            checkpoint_operation_timeout_ms: 250,
            source_lease_ttl_ms: 10,
            retry_base_delay_ms: 10,
            retry_max_delay_ms: 25,
            terminal_retention_blocks: 5,
            max_signed_transaction_bytes: 128 * 1024,
            max_status_page_size: 4,
        }
    }
    include!("provider_ingest_outbox/tests/canonical_completion.rs");
    include!("provider_ingest_outbox/tests/status_page.rs");

    fn assert_ingest_frame<T>(value: &T, name: &str) -> Vec<u8>
    where
        T: norito::NoritoSerialize
            + for<'de> norito::NoritoDeserialize<'de>
            + PartialEq
            + fmt::Debug,
    {
        assert_eq!(T::nominal_name(), name);
        assert_eq!(T::frame_name(), name);
        let bytes = norito::encode_canonical(value).expect("canonical ingest frame");
        assert_eq!(bytes[6..22], norito::schema::identity::frame_hash::<T>());
        let decoded: T = norito::decode_canonical(&bytes).expect("exact ingest frame roundtrip");
        assert_eq!(&decoded, value);
        assert_eq!(norito::encode_canonical(&decoded).unwrap(), bytes);
        let mut wrong_owner = bytes.clone();
        wrong_owner[6] ^= 1;
        assert!(matches!(
            norito::decode_canonical::<T>(&wrong_owner),
            Err(norito::Error::SchemaMismatch)
        ));
        assert!(norito::decode_canonical::<T>(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(norito::decode_canonical::<T>(&trailing).is_err());
        bytes
    }
    #[test]
    fn checkpoint_and_sealed_record_have_distinct_exact_frame_owners() {
        let checkpoint = ProviderIngestOutboxCheckpointV1::default();
        let bytes = assert_ingest_frame(
            &checkpoint,
            "sorafs_node::provider_ingest_outbox::ProviderIngestOutboxCheckpointV1",
        );
        assert_eq!(
            encode_provider_ingest_checkpoint(&checkpoint, policy()).unwrap(),
            bytes
        );
        assert_eq!(
            decode_provider_ingest_checkpoint(&bytes, policy()).unwrap(),
            checkpoint
        );
        let record = ProviderIngestSealedCheckpointRecordV1::new(1, None, None, bytes.clone());
        let sealed = assert_ingest_frame(
            &record,
            "sorafs_node::provider_ingest_outbox::ProviderIngestSealedCheckpointRecordV1",
        );
        assert_eq!(
            record
                .to_canonical_bytes(policy().checkpoint_max_bytes)
                .unwrap(),
            sealed
        );
        assert_eq!(
            ProviderIngestSealedCheckpointRecordV1::from_canonical_bytes(
                &sealed,
                policy().checkpoint_max_bytes
            )
            .unwrap(),
            record
        );
        assert!(decode_provider_ingest_checkpoint(&sealed, policy()).is_err());
        assert!(
            ProviderIngestSealedCheckpointRecordV1::from_canonical_bytes(
                &bytes,
                policy().checkpoint_max_bytes
            )
            .is_err()
        );
    }
    fn checkpoint_path(directory: &TempDir) -> PathBuf {
        fs::canonicalize(directory.path())
            .expect("canonical tempdir")
            .join(PROVIDER_INGEST_OUTBOX_FILE_V1)
    }
    fn cursor(height: u64) -> ProviderIngestFinalizedCursorV1 {
        ProviderIngestFinalizedCursorV1 {
            height,
            block_hash: [u8::try_from(height).unwrap_or(0xFE); 32],
        }
    }
    fn finalized_block_time_ms(cursor: ProviderIngestFinalizedCursorV1) -> u64 {
        cursor
            .height
            .checked_mul(1_000)
            .expect("fixture block time")
    }
    fn observe_finalized(outbox: &ProviderIngestOutbox, cursor: ProviderIngestFinalizedCursorV1) {
        outbox
            .observe_finalized_snapshot(cursor, finalized_block_time_ms(cursor))
            .expect("observe finalized fixture snapshot");
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestCheckpointCasBehavior {
        Normal,
        CommitAmbiguous,
        CommitThenPanic,
        UnchangedOk,
        UnchangedAmbiguous,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestCheckpointOperation {
        Qualification,
        LoadLatest,
        CompareAndSwap,
    }
    #[derive(Debug, Default)]
    struct TestCheckpointBlockState {
        operation: Option<TestCheckpointOperation>,
    }
    #[derive(Debug)]
    struct TestCheckpointRuntime {
        handle: String,
        qualification: Mutex<ProviderIngestCheckpointProviderQualificationV1>,
        latest: Mutex<Option<ProviderIngestSealedCheckpointRecordV1>>,
        next_cas_behavior: Mutex<TestCheckpointCasBehavior>,
        qualification_after_next_cas:
            Mutex<Option<ProviderIngestCheckpointProviderQualificationV1>>,
        blocked: Mutex<TestCheckpointBlockState>,
        blocked_changed: Condvar,
        block_load_after_next_cas: AtomicBool,
        qualification_calls: AtomicUsize,
        load_latest_calls: AtomicUsize,
        compare_and_swap_calls: AtomicUsize,
    }
    impl TestCheckpointRuntime {
        fn new(seed: u8) -> Self {
            Self {
                handle: format!("sealed.sorafs.provider-ingest.primary-{seed}"),
                qualification: Mutex::new(ProviderIngestCheckpointProviderQualificationV1::new(
                    1, [seed; 32],
                )),
                latest: Mutex::new(None),
                next_cas_behavior: Mutex::new(TestCheckpointCasBehavior::Normal),
                qualification_after_next_cas: Mutex::new(None),
                blocked: Mutex::new(TestCheckpointBlockState::default()),
                blocked_changed: Condvar::new(),
                block_load_after_next_cas: AtomicBool::new(false),
                qualification_calls: AtomicUsize::new(0),
                load_latest_calls: AtomicUsize::new(0),
                compare_and_swap_calls: AtomicUsize::new(0),
            }
        }
        fn binding(&self) -> ProviderIngestCheckpointProviderBindingV1 {
            ProviderIngestCheckpointProviderBindingV1 {
                handle: self.handle.clone(),
                revision: 1,
                policy_digest: self
                    .qualification
                    .lock()
                    .expect("test checkpoint qualification")
                    .policy_digest,
            }
        }
        fn latest(&self) -> Option<ProviderIngestSealedCheckpointRecordV1> {
            self.latest.lock().expect("test checkpoint latest").clone()
        }
        fn replace_latest(&self, record: Option<ProviderIngestSealedCheckpointRecordV1>) {
            *self.latest.lock().expect("test checkpoint latest") = record;
        }
        fn set_next_cas_behavior(&self, behavior: TestCheckpointCasBehavior) {
            *self
                .next_cas_behavior
                .lock()
                .expect("test checkpoint CAS behavior") = behavior;
        }
        fn set_qualification(
            &self,
            qualification: ProviderIngestCheckpointProviderQualificationV1,
        ) {
            *self
                .qualification
                .lock()
                .expect("test checkpoint qualification") = qualification;
        }
        fn set_qualification_after_next_cas(
            &self,
            qualification: ProviderIngestCheckpointProviderQualificationV1,
        ) {
            *self
                .qualification_after_next_cas
                .lock()
                .expect("test post-CAS checkpoint qualification") = Some(qualification);
        }
        fn block_operation(&self, operation: TestCheckpointOperation) {
            self.blocked
                .lock()
                .expect("test checkpoint block state")
                .operation = Some(operation);
        }
        fn block_load_after_next_cas(&self) {
            self.block_load_after_next_cas
                .store(true, Ordering::Release);
        }
        fn release_blocked_operation(&self) {
            self.blocked
                .lock()
                .expect("test checkpoint block state")
                .operation = None;
            self.blocked_changed.notify_all();
        }
        fn wait_if_blocked(&self, operation: TestCheckpointOperation) {
            let mut blocked = self.blocked.lock().expect("test checkpoint block state");
            while blocked.operation == Some(operation) {
                blocked = self
                    .blocked_changed
                    .wait(blocked)
                    .expect("test checkpoint block state");
            }
        }
        fn operation_calls(&self, operation: TestCheckpointOperation) -> usize {
            match operation {
                TestCheckpointOperation::Qualification => {
                    self.qualification_calls.load(Ordering::Acquire)
                }
                TestCheckpointOperation::LoadLatest => {
                    self.load_latest_calls.load(Ordering::Acquire)
                }
                TestCheckpointOperation::CompareAndSwap => {
                    self.compare_and_swap_calls.load(Ordering::Acquire)
                }
            }
        }
    }
    impl ProviderIngestCheckpointRuntimeV1 for TestCheckpointRuntime {
        fn handle(&self) -> &str {
            &self.handle
        }
        fn qualification(
            &self,
        ) -> Result<
            ProviderIngestCheckpointProviderQualificationV1,
            ProviderIngestCheckpointExternalErrorV1,
        > {
            self.qualification_calls.fetch_add(1, Ordering::AcqRel);
            self.wait_if_blocked(TestCheckpointOperation::Qualification);
            self.qualification
                .lock()
                .map(|qualification| *qualification)
                .map_err(|_| ProviderIngestCheckpointExternalErrorV1::Unavailable)
        }
        fn load_latest(
            &self,
        ) -> Result<
            Option<ProviderIngestSealedCheckpointRecordV1>,
            ProviderIngestCheckpointExternalErrorV1,
        > {
            self.load_latest_calls.fetch_add(1, Ordering::AcqRel);
            self.wait_if_blocked(TestCheckpointOperation::LoadLatest);
            self.latest
                .lock()
                .map(|latest| latest.clone())
                .map_err(|_| ProviderIngestCheckpointExternalErrorV1::Unavailable)
        }
        fn compare_and_swap_latest(
            &self,
            expected_revision: Option<[u8; 32]>,
            next: &ProviderIngestSealedCheckpointRecordV1,
        ) -> Result<(), ProviderIngestCheckpointExternalErrorV1> {
            self.compare_and_swap_calls.fetch_add(1, Ordering::AcqRel);
            self.wait_if_blocked(TestCheckpointOperation::CompareAndSwap);
            let mut latest = self
                .latest
                .lock()
                .map_err(|_| ProviderIngestCheckpointExternalErrorV1::Unavailable)?;
            if latest.as_ref().map(|record| record.revision) != expected_revision
                || latest
                    .as_ref()
                    .map_or(1, |record| record.checkpoint_sequence.saturating_add(1))
                    != next.checkpoint_sequence
                || next.predecessor_revision != expected_revision
                || next.predecessor_checkpoint_digest
                    != latest.as_ref().map(|record| record.checkpoint_digest)
            {
                return Err(ProviderIngestCheckpointExternalErrorV1::Rejected);
            }
            let behavior = std::mem::replace(
                &mut *self
                    .next_cas_behavior
                    .lock()
                    .map_err(|_| ProviderIngestCheckpointExternalErrorV1::Unavailable)?,
                TestCheckpointCasBehavior::Normal,
            );
            let panic_after_commit = behavior == TestCheckpointCasBehavior::CommitThenPanic;
            let outcome = match behavior {
                TestCheckpointCasBehavior::Normal => {
                    *latest = Some(next.clone());
                    Ok(())
                }
                TestCheckpointCasBehavior::CommitAmbiguous => {
                    *latest = Some(next.clone());
                    Err(ProviderIngestCheckpointExternalErrorV1::Ambiguous)
                }
                TestCheckpointCasBehavior::CommitThenPanic => {
                    *latest = Some(next.clone());
                    Ok(())
                }
                TestCheckpointCasBehavior::UnchangedOk => Ok(()),
                TestCheckpointCasBehavior::UnchangedAmbiguous => {
                    Err(ProviderIngestCheckpointExternalErrorV1::Ambiguous)
                }
            };
            drop(latest);
            if let Some(qualification) = self
                .qualification_after_next_cas
                .lock()
                .map_err(|_| ProviderIngestCheckpointExternalErrorV1::Unavailable)?
                .take()
            {
                self.set_qualification(qualification);
            }
            if self.block_load_after_next_cas.swap(false, Ordering::AcqRel) {
                self.block_operation(TestCheckpointOperation::LoadLatest);
            }
            assert!(!panic_after_commit, "test checkpoint CAS response panic");
            outcome
        }
    }
    fn open_sealed(
        directory: &TempDir,
        runtime: Arc<TestCheckpointRuntime>,
    ) -> Result<ProviderIngestOutbox, ProviderIngestOutboxError> {
        ProviderIngestOutbox::open_with_checkpoint_authority(
            checkpoint_path(directory),
            policy(),
            runtime.binding(),
            runtime,
        )
    }
    fn deadline_policy() -> ProviderIngestOutboxPolicyV1 {
        ProviderIngestOutboxPolicyV1 {
            checkpoint_operation_timeout_ms: 750,
            ..policy()
        }
    }
    fn open_sealed_with_deadline(
        directory: &TempDir,
        runtime: Arc<TestCheckpointRuntime>,
    ) -> Result<ProviderIngestOutbox, ProviderIngestOutboxError> {
        ProviderIngestOutbox::open_with_checkpoint_authority(
            checkpoint_path(directory),
            deadline_policy(),
            runtime.binding(),
            runtime,
        )
    }
    fn reopen_sealed_after_worker_release(
        directory: &TempDir,
        runtime: Arc<TestCheckpointRuntime>,
    ) -> Result<ProviderIngestOutbox, ProviderIngestOutboxError> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match open_sealed_with_deadline(directory, Arc::clone(&runtime)) {
                Err(ProviderIngestOutboxError::CheckpointBusy) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                result => return result,
            }
        }
    }
    fn wait_for_checkpoint_sequence(runtime: &TestCheckpointRuntime, expected_sequence: u64) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if runtime
                .latest()
                .is_some_and(|record| record.checkpoint_sequence == expected_sequence)
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "checkpoint worker did not finish the released operation"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn wait_for_operation_calls(
        runtime: &TestCheckpointRuntime,
        operation: TestCheckpointOperation,
        minimum_calls: usize,
    ) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while runtime.operation_calls(operation) < minimum_calls {
            assert!(
                Instant::now() < deadline,
                "checkpoint worker did not enter the expected operation"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    include!("provider_ingest_outbox/tests/sealed_checkpoint_lifecycle.rs");
    include!("provider_ingest_outbox/tests/canonical_authorization.rs");
    include!("provider_ingest_outbox/tests/sealed_record_schema.rs");
    #[test]
    fn provider_drift_substitution_and_test_markers_fail_closed() {
        let directory = tempdir().expect("checkpoint directory");
        let runtime = Arc::new(TestCheckpointRuntime::new(0x76));
        let outbox = open_sealed(&directory, Arc::clone(&runtime)).expect("sealed outbox");
        runtime.set_qualification(ProviderIngestCheckpointProviderQualificationV1::new(
            2, [0x76; 32],
        ));
        assert_eq!(
            outbox.finalized_cursor_high_water(),
            Err(ProviderIngestOutboxError::CheckpointProviderIdentityMismatch)
        );
        drop(outbox);
        let substituted = Arc::new(TestCheckpointRuntime::new(0x77));
        let configured = ProviderIngestCheckpointProviderBindingV1 {
            handle: "sealed.sorafs.provider-ingest.configured".to_owned(),
            revision: 1,
            policy_digest: [0x77; 32],
        };
        assert!(matches!(
            ProviderIngestOutbox::open_with_checkpoint_authority(
                checkpoint_path(&directory),
                policy(),
                configured,
                substituted,
            ),
            Err(ProviderIngestOutboxError::CheckpointProviderIdentityMismatch)
        ));
        let stale = Arc::new(TestCheckpointRuntime::new(0x7B));
        let stale_binding = ProviderIngestCheckpointProviderBindingV1 {
            handle: stale.handle.clone(),
            revision: 2,
            policy_digest: [0x7B; 32],
        };
        assert!(matches!(
            ProviderIngestOutbox::open_with_checkpoint_authority(
                checkpoint_path(&directory),
                policy(),
                stale_binding,
                stale,
            ),
            Err(ProviderIngestOutboxError::CheckpointProviderIdentityMismatch)
        ));
        let test_marked = Arc::new(TestCheckpointRuntime::new(0x78));
        let invalid_binding = ProviderIngestCheckpointProviderBindingV1 {
            handle: "sealed.sorafs.provider-ingest.test".to_owned(),
            revision: 1,
            policy_digest: [0x78; 32],
        };
        assert!(matches!(
            ProviderIngestOutbox::open_with_checkpoint_authority(
                checkpoint_path(&directory),
                policy(),
                invalid_binding,
                test_marked,
            ),
            Err(ProviderIngestOutboxError::InvalidCheckpointProviderBinding)
        ));
    }
    #[test]
    fn post_cas_provider_drift_is_ambiguous_and_poisoned() {
        let directory = tempdir().expect("checkpoint directory");
        let runtime = Arc::new(TestCheckpointRuntime::new(0x7A));
        let outbox = open_sealed(&directory, Arc::clone(&runtime)).expect("sealed outbox");
        runtime.set_qualification_after_next_cas(
            ProviderIngestCheckpointProviderQualificationV1::new(2, [0x7A; 32]),
        );
        assert_eq!(
            outbox.observe_finalized_snapshot(cursor(10), finalized_block_time_ms(cursor(10))),
            Err(ProviderIngestOutboxError::CheckpointAuthorityAmbiguous)
        );
        assert_eq!(
            runtime
                .latest()
                .expect("post-CAS authoritative record")
                .checkpoint_sequence,
            2
        );
    }
    fn signer_policy(revision: u64) -> ProviderIngestCompletionSignerPolicyV1 {
        let digest_byte = u8::try_from(revision).unwrap_or(0xFE);
        ProviderIngestCompletionSignerPolicyV1 {
            policy_id: [0xA1; 32],
            revision,
            predecessor_digest: (revision > 1).then(|| [digest_byte.saturating_sub(1); 32]),
            policy_digest: [digest_byte; 32],
        }
    }
    fn fixture_authority(
        owner: &AccountId,
        policy: ProviderIngestCompletionSignerPolicyV1,
    ) -> ProviderIngestCompletionAuthorityV1 {
        ProviderIngestCompletionAuthorityV1::new(owner.clone(), owner.clone(), policy)
    }
    fn owner(seed: u8) -> ProviderIngestClaimOwnerV1 {
        ProviderIngestClaimOwnerV1::new([seed; 32]).expect("owner")
    }
    fn manifest_id(authorization: &FinalizedProviderIngestAuthorizationV1) -> String {
        hex::encode(authorization.manifest_digest())
    }
    fn signed_completion_for(
        provider_id: [u8; 32],
        order_id: [u8; 32],
        completion_epoch: u64,
        seed: u8,
    ) -> SignedTransaction {
        signed_completion_for_at(
            provider_id,
            order_id,
            completion_epoch,
            cursor(completion_epoch),
            seed,
        )
    }
    fn signed_completion_for_at(
        provider_id: [u8; 32],
        order_id: [u8; 32],
        completion_epoch: u64,
        finalized_cursor: ProviderIngestFinalizedCursorV1,
        seed: u8,
    ) -> SignedTransaction {
        signed_completion_for_at_with_policy(
            provider_id,
            order_id,
            completion_epoch,
            finalized_cursor,
            seed,
            signer_policy(1),
        )
    }
    fn signed_completion_for_at_with_policy(
        provider_id: [u8; 32],
        order_id: [u8; 32],
        completion_epoch: u64,
        finalized_cursor: ProviderIngestFinalizedCursorV1,
        seed: u8,
        completion_signer_policy: ProviderIngestCompletionSignerPolicyV1,
    ) -> SignedTransaction {
        let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("key");
        let provider_owner = AccountId::new(key.public_key().clone());
        let mut builder = TransactionBuilder::new(
            test_network_id(),
            provider_owner.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([InstructionBox::from(CompleteReplicationOrder {
            order_id: ReplicationOrderId::new(order_id),
            provider_id: ProviderId::new(provider_id),
            completion_epoch,
            expected_authority: ProviderIngestCompletionAuthorityV1::new(
                (provider_owner).clone(),
                provider_owner,
                completion_signer_policy,
            ),
            expected_assignment_revision: 1,
            finalized_anchor: ProviderIngestFinalizedAnchorV1 {
                height: finalized_cursor.height,
                block_hash: finalized_cursor.block_hash,
            },
        })]);
        builder.set_creation_time(Duration::from_secs(u64::from(seed) + 1));
        builder.set_ttl(Duration::from_secs(30));
        builder.try_sign(key.private_key()).expect("sign")
    }
    fn signed_completion(
        authorization: &FinalizedProviderIngestAuthorizationV1,
        completion_epoch: u64,
        seed: u8,
    ) -> SignedTransaction {
        signed_completion_for(
            authorization.provider_id(),
            authorization.order_id(),
            completion_epoch,
            seed,
        )
    }
    fn signed_completion_at(
        authorization: &FinalizedProviderIngestAuthorizationV1,
        completion_epoch: u64,
        finalized_cursor: ProviderIngestFinalizedCursorV1,
        seed: u8,
    ) -> SignedTransaction {
        signed_completion_for_at(
            authorization.provider_id(),
            authorization.order_id(),
            completion_epoch,
            finalized_cursor,
            seed,
        )
    }
    fn signed_completion_with_policy_at(
        authorization: &FinalizedProviderIngestAuthorizationV1,
        completion_epoch: u64,
        finalized_cursor: ProviderIngestFinalizedCursorV1,
        seed: u8,
        completion_signer_policy: ProviderIngestCompletionSignerPolicyV1,
    ) -> SignedTransaction {
        signed_completion_for_at_with_policy(
            authorization.provider_id(),
            authorization.order_id(),
            completion_epoch,
            finalized_cursor,
            seed,
            completion_signer_policy,
        )
    }
    fn enqueue_and_store_local(
        outbox: &ProviderIngestOutbox,
        authorization: &FinalizedProviderIngestAuthorizationV1,
        now_ms: u64,
    ) {
        outbox
            .enqueue(authorization.clone())
            .expect("enqueue local fixture");
        let claim = outbox
            .claim_source(
                authorization.job_id(),
                owner(1),
                now_ms,
                authorization.admission_finalized_cursor(),
            )
            .expect("claim source");
        outbox
            .mark_local_stored(&claim, now_ms + 1, manifest_id(authorization))
            .expect("mark local");
    }
    fn completion_context(
        transaction: &SignedTransaction,
        completion_epoch: u64,
        baseline_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> ProviderIngestCompletionSigningContextV1 {
        ProviderIngestCompletionSigningContextV1 {
            baseline_finalized_cursor,
            network_id: *transaction
                .network_id()
                .expect("ordinary completion transaction network"),
            expected_authority: ProviderIngestCompletionAuthorityV1::new(
                transaction.authority().clone(),
                transaction.authority().clone(),
                signer_policy(1),
            ),
            assignment_revision: 1,
            completion_epoch,
            expected_payload: transaction.payload().clone(),
        }
    }
    fn claim_for_transaction(
        outbox: &ProviderIngestOutbox,
        job_id: [u8; 32],
        transaction: &SignedTransaction,
        completion_epoch: u64,
        now_ms: u64,
        baseline_finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> ProviderIngestCompletionSigningClaimV1 {
        observe_finalized(outbox, baseline_finalized_cursor);
        outbox
            .claim_completion_signing(
                job_id,
                completion_context(transaction, completion_epoch, baseline_finalized_cursor),
                now_ms,
            )
            .expect("claim completion signing")
    }
    fn stored_completion(
        outbox: &ProviderIngestOutbox,
        job_id: [u8; 32],
    ) -> StoredCompletionDeliveryV1 {
        let state = outbox.state.lock().unwrap();
        let entry = state
            .checkpoint
            .active
            .iter()
            .find(|entry| entry.authorization.job_id == job_id)
            .expect("active job");
        let StoredProviderIngestStateV1::LocalStored { completion, .. } = &entry.state else {
            panic!("job must be locally stored");
        };
        completion.as_ref().clone()
    }
    fn begin_submission(
        outbox: &ProviderIngestOutbox,
        job_id: [u8; 32],
        transaction_hash: [u8; 32],
        now_ms: u64,
    ) -> Result<ProviderIngestCompletionSubmissionV1, ProviderIngestOutboxError> {
        let completion = stored_completion(outbox, job_id);
        let context = completion
            .signing_context
            .as_ref()
            .expect("signed fixture has signing context");
        let checked_cursor = outbox
            .finalized_cursor_high_water()?
            .ok_or(ProviderIngestOutboxError::InvalidCheckpoint)?;
        outbox.authorize_and_begin_completion_submission(
            job_id,
            transaction_hash,
            &context.expected_authority.provider_owner,
            &context.expected_authority,
            checked_cursor,
            now_ms,
        )
    }
    fn completed_by(seed: u8) -> AccountId {
        let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("key");
        AccountId::new(key.public_key().clone())
    }
    fn finalized_evidence(
        authorization: &FinalizedProviderIngestAuthorizationV1,
        completion_epoch: u64,
        committed_transaction_hash: Option<[u8; 32]>,
        finalized_height: u64,
    ) -> ProviderIngestFinalizedCompletionV1 {
        ProviderIngestFinalizedCompletionV1 {
            finalized_cursor: cursor(finalized_height),
            provider_id: authorization.provider_id(),
            order_id: authorization.order_id(),
            manifest_digest: authorization.manifest_digest(),
            completion_epoch,
            completed_by: completed_by(0xED),
            committed_transaction_hash,
        }
    }
    fn cancellation_evidence(
        authorization: &FinalizedProviderIngestAuthorizationV1,
        reason: ProviderIngestCancellationReasonV1,
        finalized_height: u64,
    ) -> ProviderIngestFinalizedCancellationV1 {
        ProviderIngestFinalizedCancellationV1 {
            finalized_cursor: cursor(finalized_height),
            provider_id: authorization.provider_id(),
            order_id: authorization.order_id(),
            manifest_digest: authorization.manifest_digest(),
            reason,
        }
    }
    #[test]
    fn completion_signer_policy_validity_is_const_and_requires_nonzero_components() {
        const VALID: bool = ProviderIngestCompletionSignerPolicyV1 {
            policy_id: [1; 32],
            revision: 1,
            predecessor_digest: None,
            policy_digest: [2; 32],
        }
        .is_valid();
        const ZERO_POLICY_ID: bool = ProviderIngestCompletionSignerPolicyV1 {
            policy_id: [0; 32],
            revision: 1,
            predecessor_digest: None,
            policy_digest: [2; 32],
        }
        .is_valid();
        const ZERO_REVISION: bool = ProviderIngestCompletionSignerPolicyV1 {
            policy_id: [1; 32],
            revision: 0,
            predecessor_digest: None,
            policy_digest: [2; 32],
        }
        .is_valid();
        const ZERO_POLICY_DIGEST: bool = ProviderIngestCompletionSignerPolicyV1 {
            policy_id: [1; 32],
            revision: 1,
            predecessor_digest: None,
            policy_digest: [0; 32],
        }
        .is_valid();
        const REVISION_ONE_WITH_PREDECESSOR: bool = ProviderIngestCompletionSignerPolicyV1 {
            policy_id: [1; 32],
            revision: 1,
            predecessor_digest: Some([3; 32]),
            policy_digest: [2; 32],
        }
        .is_valid();
        const SUCCESSOR_WITHOUT_PREDECESSOR: bool = ProviderIngestCompletionSignerPolicyV1 {
            policy_id: [1; 32],
            revision: 2,
            predecessor_digest: None,
            policy_digest: [2; 32],
        }
        .is_valid();
        const SUCCESSOR_WITH_ZERO_PREDECESSOR: bool = ProviderIngestCompletionSignerPolicyV1 {
            policy_id: [1; 32],
            revision: 2,
            predecessor_digest: Some([0; 32]),
            policy_digest: [2; 32],
        }
        .is_valid();
        const _: [(); 7] = [(); VALID as usize
            + (!ZERO_POLICY_ID) as usize
            + (!ZERO_REVISION) as usize
            + (!ZERO_POLICY_DIGEST) as usize
            + (!REVISION_ONE_WITH_PREDECESSOR) as usize
            + (!SUCCESSOR_WITHOUT_PREDECESSOR) as usize
            + (!SUCCESSOR_WITH_ZERO_PREDECESSOR) as usize];
        let mut sparse_policy = ProviderIngestCompletionSignerPolicyV1 {
            policy_id: [0; 32],
            revision: 1,
            predecessor_digest: None,
            policy_digest: [0; 32],
        };
        sparse_policy.policy_id[31] = 1;
        sparse_policy.policy_digest[0] = 1;
        assert!(sparse_policy.is_valid());
    }
    #[test]
    fn repeated_unchecked_authority_observation_is_idempotent() {
        let owner = completed_by(0xA0);
        let mut completion = StoredCompletionDeliveryV1::default();
        assert_eq!(
            observe_finalized_completion_authority(
                &mut completion,
                Some(&owner),
                &ProviderIngestCompletionAuthorityObservationV1::NotChecked,
                cursor(8),
            ),
            Ok(true)
        );
        let retained = completion.clone();
        assert_eq!(
            observe_finalized_completion_authority(
                &mut completion,
                Some(&owner),
                &ProviderIngestCompletionAuthorityObservationV1::NotChecked,
                cursor(8),
            ),
            Ok(false)
        );
        assert_eq!(completion, retained);
    }
    #[test]
    fn checkpoint_finalized_high_water_requires_a_complete_nonzero_time_pair() {
        let mut checkpoint = ProviderIngestOutboxCheckpointV1::default();
        assert_eq!(
            validate_checkpoint_finalized_high_water(&checkpoint),
            Ok(())
        );
        checkpoint.finalized_cursor_high_water = Some(cursor(8));
        assert_eq!(
            validate_checkpoint_finalized_high_water(&checkpoint),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        );
        checkpoint.finalized_block_time_ms_high_water = Some(8_000);
        assert_eq!(
            validate_checkpoint_finalized_high_water(&checkpoint),
            Ok(())
        );
        checkpoint.finalized_block_time_ms_high_water = Some(0);
        assert_eq!(
            validate_checkpoint_finalized_high_water(&checkpoint),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        );
        checkpoint.finalized_cursor_high_water = None;
        checkpoint.finalized_block_time_ms_high_water = Some(8_000);
        assert_eq!(
            validate_checkpoint_finalized_high_water(&checkpoint),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        );
    }
    #[test]
    fn policy_bounds_worst_case_checkpoint_capacity() {
        let defaults = ProviderIngestOutboxPolicyV1::default();
        assert_eq!(defaults.max_active_entries, 128);
        assert_eq!(defaults.checkpoint_max_bytes, 192 * 1024 * 1024);
        assert_eq!(defaults.checkpoint_operation_timeout_ms, 30_000);
        defaults.validate().expect("default capacity fits");
        let mut invalid_checkpoint_deadline = policy();
        invalid_checkpoint_deadline.checkpoint_operation_timeout_ms = 0;
        assert_eq!(
            invalid_checkpoint_deadline.validate(),
            Err(ProviderIngestOutboxError::InvalidPolicy)
        );
        invalid_checkpoint_deadline.checkpoint_operation_timeout_ms =
            PROVIDER_INGEST_CHECKPOINT_OPERATION_TIMEOUT_MAX_MS_V1 + 1;
        assert_eq!(
            invalid_checkpoint_deadline.validate(),
            Err(ProviderIngestOutboxError::InvalidPolicy)
        );
        let mut exact = policy();
        exact.max_active_entries = 1;
        exact.max_terminal_entries = 1;
        exact.max_signed_transaction_bytes =
            provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES_MIN;
        exact.checkpoint_max_bytes =
            provider_ingest_outbox_defaults::worst_case_checkpoint_bytes_v1(
                exact.max_active_entries,
                exact.max_terminal_entries,
                exact.max_signed_transaction_bytes,
            )
            .expect("exact checked capacity");
        assert_eq!(
            exact.checkpoint_max_bytes,
            provider_ingest_outbox_defaults::CHECKPOINT_CANONICAL_OVERHEAD_BYTES_V1
                + 2 * exact.max_signed_transaction_bytes
                + provider_ingest_outbox_defaults::ACTIVE_ENTRY_CANONICAL_OVERHEAD_BYTES_V1
                + provider_ingest_outbox_defaults::TERMINAL_ENTRY_CANONICAL_OVERHEAD_BYTES_V1
        );
        exact.validate().expect("exact capacity boundary fits");
        exact.checkpoint_max_bytes -= 1;
        assert_eq!(
            exact.validate(),
            Err(ProviderIngestOutboxError::InvalidPolicy)
        );
        let mut overflow = policy();
        overflow.max_active_entries = usize::MAX;
        overflow.checkpoint_max_bytes = u64::MAX;
        assert_eq!(
            overflow.validate(),
            Err(ProviderIngestOutboxError::InvalidPolicy)
        );
    }
    #[test]
    fn canonical_active_fixture_fits_payload_and_structural_capacity_budgets() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        let authorization = authorization(0x50, 7);
        let job_id = authorization.job_id();
        enqueue_and_store_local(&outbox, &authorization, 100);
        let transaction = signed_completion(&authorization, 8, 8);
        let expected_payload_bytes =
            norito::to_bytes(transaction.payload()).expect("encode expected payload fixture");
        let signed_transaction_bytes =
            norito::to_bytes(&transaction).expect("encode signed transaction fixture");
        let signing_claim = claim_for_transaction(&outbox, job_id, &transaction, 8, 102, cursor(8));
        outbox
            .store_completion_transaction(&signing_claim, transaction)
            .expect("store signed completion fixture");
        let checkpoint = outbox.state.lock().unwrap().checkpoint.clone();
        let active_len =
            crate::frame_test_support::nested_record_reserve_len(&checkpoint.active[0]);
        let retained_payload_bytes = expected_payload_bytes
            .len()
            .checked_add(signed_transaction_bytes.len())
            .expect("fixture retained payload bytes");
        assert!(
            active_len
                <= retained_payload_bytes
                    + usize::try_from(
                        provider_ingest_outbox_defaults::ACTIVE_ENTRY_CANONICAL_OVERHEAD_BYTES_V1,
                    )
                    .expect("active overhead fits usize")
        );
        encode_provider_ingest_checkpoint(&checkpoint, policy())
            .expect("canonical active fixture fits configured checkpoint");
    }
    #[test]
    fn canonical_terminal_fixture_fits_derived_structural_charge_and_capacity_boundary() {
        assert!(
            provider_ingest_outbox_defaults::TERMINAL_OUTCOME_FIXED_CANONICAL_RESERVE_BYTES_V1
                >= u64::try_from(
                    crate::provider_ingest_runtime::
                        PROVIDER_INGEST_VERIFIED_MUSUBI_RECEIPT_MAX_CANONICAL_BYTES_V1,
                )
                .expect("Musubi receipt bound fits u64")
                .saturating_add(4 * 1024),
            "terminal outcome reserve must include the bounded Musubi receipt and fixed evidence",
        );
        let authorization = FinalizedProviderIngestAuthorizationV1::from_finalized_state(
            7,
            cursor(7).block_hash,
            [0x11; 32],
            [0x51; 32],
            [0x71; 32],
            ManifestRootCid::from_blake3_digest([0xA5; 32])
                .expect("canonical maximum-width root CID")
                .as_bytes()
                .to_vec(),
            "x".repeat(MAX_CHUNKER_HANDLE_BYTES_V1),
            [0x81; 32],
            [0x91; 32],
            u64::MAX,
        )
        .expect("maximum-field authorization");
        let completed_by = completed_by(0xA1);
        let outcome = StoredProviderIngestTerminalOutcomeV1::FinalizedCompleted {
            manifest_id: Some(manifest_id(&authorization)),
            musubi_bundle: None,
            completion_epoch: u64::MAX,
            completed_by: completed_by.clone(),
            committed_transaction_hash: Some([0xB1; 32]),
            finalized_cursor: cursor(8),
        };
        let terminal = StoredTerminalProviderIngestV1 {
            sequence: 1,
            authorization: authorization.clone(),
            outcome: outcome.clone(),
        };
        let authorization_len = u64::try_from(
            crate::frame_test_support::nested_record_reserve_len(&authorization),
        )
        .expect("authorization reserve fits u64");
        let completed_by_bytes =
            norito::to_bytes(&completed_by).expect("encode terminal completion account");
        let completed_by_len =
            u64::try_from(completed_by_bytes.len()).expect("account length fits u64");
        let outcome_len = u64::try_from(crate::frame_test_support::nested_record_reserve_len(
            &outcome,
        ))
        .expect("outcome reserve fits u64");
        let terminal_len = u64::try_from(crate::frame_test_support::nested_record_reserve_len(
            &terminal,
        ))
        .expect("terminal reserve fits u64");
        assert!(
            authorization_len
                <= provider_ingest_outbox_defaults::TERMINAL_AUTHORIZATION_CANONICAL_RESERVE_BYTES_V1
        );
        assert!(
            completed_by_len
                <= provider_ingest_outbox_defaults::COMPLETION_ACCOUNT_ID_MAX_CANONICAL_BYTES_V1
        );
        assert!(
            outcome_len
                <= completed_by_len
                    .checked_add(
                        provider_ingest_outbox_defaults::TERMINAL_OUTCOME_FIXED_CANONICAL_RESERVE_BYTES_V1,
                    )
                    .expect("outcome component budget")
        );
        assert!(
            terminal_len
                <= authorization_len
                    .checked_add(outcome_len)
                    .and_then(|bytes| {
                        bytes.checked_add(
                            provider_ingest_outbox_defaults::TERMINAL_ENTRY_CANONICAL_FRAMING_RESERVE_BYTES_V1,
                        )
                    })
                    .expect("terminal component budget")
        );
        assert!(
            terminal_len
                <= provider_ingest_outbox_defaults::TERMINAL_ENTRY_CANONICAL_OVERHEAD_BYTES_V1
        );
        let checkpoint = ProviderIngestOutboxCheckpointV1 {
            next_sequence: 2,
            finalized_cursor_high_water: Some(cursor(8)),
            finalized_block_time_ms_high_water: Some(finalized_block_time_ms(cursor(8))),
            terminal: vec![terminal],
            ..ProviderIngestOutboxCheckpointV1::default()
        };
        let checkpoint_bytes = encode_provider_ingest_checkpoint(&checkpoint, policy())
            .expect("canonical terminal fixture fits configured checkpoint");
        assert!(
            u64::try_from(checkpoint_bytes.len()).expect("checkpoint length fits u64")
                <= provider_ingest_outbox_defaults::CHECKPOINT_CANONICAL_OVERHEAD_BYTES_V1
                    + provider_ingest_outbox_defaults::TERMINAL_ENTRY_CANONICAL_OVERHEAD_BYTES_V1
        );
        let mut boundary = policy();
        boundary.max_active_entries = 1;
        boundary.max_terminal_entries = 1;
        boundary.max_signed_transaction_bytes =
            provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES_MIN;
        boundary.checkpoint_max_bytes =
            provider_ingest_outbox_defaults::worst_case_checkpoint_bytes_v1(
                boundary.max_active_entries,
                boundary.max_terminal_entries,
                boundary.max_signed_transaction_bytes,
            )
            .expect("checked terminal capacity boundary");
        boundary
            .validate()
            .expect("full terminal structural charge fits at exact boundary");
        boundary.checkpoint_max_bytes = boundary
            .checkpoint_max_bytes
            .checked_sub(1)
            .expect("non-zero capacity boundary");
        assert_eq!(
            boundary.validate(),
            Err(ProviderIngestOutboxError::InvalidPolicy)
        );
    }
    #[test]
    fn stable_job_identity_excludes_advancing_admission_cursor() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        let first = authorization(0x51, 7);
        let later = authorization(0x51, 8);
        assert_eq!(first.job_id(), later.job_id());
        assert_eq!(
            outbox.enqueue(first.clone()).expect("first enqueue"),
            ProviderIngestEnqueueResultV1::Inserted {
                job_id: first.job_id()
            }
        );
        assert_eq!(
            outbox.enqueue(later).expect("head-advance replay"),
            ProviderIngestEnqueueResultV1::ExistingActive {
                job_id: first.job_id()
            }
        );
        assert_eq!(
            outbox
                .status(first.job_id())
                .unwrap()
                .admission_finalized_cursor,
            cursor(7)
        );
        let mut same_height_fork = first.clone();
        same_height_fork.admission_finalized_cursor.block_hash = [0xEE; 32];
        assert_eq!(
            outbox.enqueue(same_height_fork),
            Err(ProviderIngestOutboxError::AdmissionEvidenceConflict)
        );
    }
    #[test]
    fn duplicate_source_claim_is_rejected_and_expired_lease_is_reclaimed() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        let authorization = authorization(0x52, 7);
        outbox.enqueue(authorization.clone()).unwrap();
        let first = outbox
            .claim_source(authorization.job_id(), owner(1), 100, cursor(7))
            .unwrap();
        assert_eq!(first.lease_expires_at_ms(), 110);
        assert_eq!(
            outbox.claim_source(authorization.job_id(), owner(2), 109, cursor(7)),
            Err(ProviderIngestOutboxError::LeaseAlreadyHeld)
        );
        let second = outbox
            .claim_source(authorization.job_id(), owner(2), 110, cursor(7))
            .expect("expired lease is reclaimable");
        assert_ne!(first.generation, second.generation);
        assert_eq!(
            outbox.mark_local_stored(&first, 111, manifest_id(&authorization)),
            Err(ProviderIngestOutboxError::InvalidSourceClaim)
        );
        assert!(matches!(
            outbox.status(authorization.job_id()).unwrap().state,
            ProviderIngestDeliveryStateV1::SourceClaimed {
                attempts: 1,
                generation: 2,
                lease_expires_at_ms: 120,
            }
        ));
        outbox
            .mark_local_stored(&second, 111, manifest_id(&authorization))
            .unwrap();
    }
    #[test]
    fn claim_next_source_is_sequence_ordered_and_single_flight() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        let first = authorization(0x60, 7);
        let second = authorization(0x61, 7);
        outbox.enqueue(first.clone()).unwrap();
        outbox.enqueue(second.clone()).unwrap();
        let first_claim = outbox
            .claim_next_source(owner(1), 100, cursor(7))
            .unwrap()
            .expect("first claim");
        assert_eq!(first_claim.job_id(), first.job_id());
        let second_claim = outbox
            .claim_next_source(owner(2), 100, cursor(7))
            .unwrap()
            .expect("second claim");
        assert_eq!(second_claim.job_id(), second.job_id());
        assert!(
            outbox
                .claim_next_source(owner(3), 100, cursor(7))
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn retry_backoff_is_capped_and_retry_exhausted_is_reachable() {
        let mut bounded = policy();
        bounded.max_attempts = 5;
        let outbox = ProviderIngestOutbox::in_memory(bounded).expect("outbox");
        let authorization = authorization(0x53, 7);
        outbox.enqueue(authorization.clone()).unwrap();
        let mut claim = outbox
            .claim_source(authorization.job_id(), owner(1), 100, cursor(7))
            .unwrap();
        for (failure_at, expected_next, expected_attempts) in
            [(101, 111, 1), (112, 132, 2), (133, 158, 3), (159, 184, 4)]
        {
            assert_eq!(
                outbox
                    .schedule_source_retry(
                        &claim,
                        failure_at,
                        cursor(7),
                        ProviderIngestFailureClassV1::SourceUnavailable,
                    )
                    .unwrap(),
                ProviderIngestRetryOutcomeV1::RetryScheduled {
                    attempts: expected_attempts,
                    next_attempt_at_ms: expected_next,
                }
            );
            assert_eq!(
                outbox.claim_source(
                    authorization.job_id(),
                    owner(2),
                    expected_next - 1,
                    cursor(7),
                ),
                Err(ProviderIngestOutboxError::RetryNotDue)
            );
            claim = outbox
                .claim_source(authorization.job_id(), owner(1), expected_next, cursor(7))
                .unwrap();
        }
        assert_eq!(
            outbox
                .schedule_source_retry(
                    &claim,
                    185,
                    cursor(7),
                    ProviderIngestFailureClassV1::SourceUnavailable,
                )
                .unwrap(),
            ProviderIngestRetryOutcomeV1::DeadLettered
        );
        assert!(matches!(
            outbox.status(authorization.job_id()).unwrap().state,
            ProviderIngestDeliveryStateV1::DeadLetter {
                attempts: 5,
                reason: ProviderIngestDeadLetterReasonV1::RetryExhausted,
                last_failure_class: ProviderIngestFailureClassV1::SourceUnavailable,
                ..
            }
        ));
    }
    #[test]
    fn every_crash_state_survives_or_recovers_safely() {
        let directory = tempdir().expect("tempdir");
        let path = checkpoint_path(&directory);
        let initial_authorization = authorization(0x54, 7);
        let job_id = initial_authorization.job_id();
        let mut outbox = ProviderIngestOutbox::open(&path, policy()).expect("open");
        outbox.enqueue(initial_authorization.clone()).unwrap();
        drop(outbox);
        outbox = ProviderIngestOutbox::open(&path, policy()).expect("pending restart");
        assert!(matches!(
            outbox.status(job_id).unwrap().state,
            ProviderIngestDeliveryStateV1::PendingSource { attempts: 0 }
        ));
        let first_claim = outbox
            .claim_source(job_id, owner(1), 100, cursor(7))
            .unwrap();
        drop(outbox);
        outbox = ProviderIngestOutbox::open(&path, policy()).expect("claim restart");
        assert!(matches!(
            outbox.status(job_id).unwrap().state,
            ProviderIngestDeliveryStateV1::SourceClaimed { generation: 1, .. }
        ));
        let retry = outbox
            .schedule_source_retry(
                &first_claim,
                101,
                cursor(7),
                ProviderIngestFailureClassV1::SourceUnavailable,
            )
            .unwrap();
        assert_eq!(
            retry,
            ProviderIngestRetryOutcomeV1::RetryScheduled {
                attempts: 1,
                next_attempt_at_ms: 111,
            }
        );
        drop(outbox);
        outbox = ProviderIngestOutbox::open(&path, policy()).expect("retry restart");
        assert!(matches!(
            outbox.status(job_id).unwrap().state,
            ProviderIngestDeliveryStateV1::RetryScheduled {
                attempts: 1,
                next_attempt_at_ms: 111,
                ..
            }
        ));
        let second_claim = outbox
            .claim_source(job_id, owner(2), 111, cursor(8))
            .unwrap();
        outbox
            .mark_local_stored(&second_claim, 112, manifest_id(&initial_authorization))
            .unwrap();
        drop(outbox);
        outbox = ProviderIngestOutbox::open(&path, policy()).expect("local restart");
        assert!(matches!(
            outbox.status(job_id).unwrap().state,
            ProviderIngestDeliveryStateV1::LocalStored {
                completion: ProviderIngestCompletionStateV1::Ready { .. },
                ..
            }
        ));
        let interrupted_transaction = signed_completion(&initial_authorization, 8, 8);
        let interrupted_claim =
            claim_for_transaction(&outbox, job_id, &interrupted_transaction, 8, 113, cursor(8));
        drop(outbox);
        outbox = ProviderIngestOutbox::open(&path, policy()).expect("signing restart");
        assert!(matches!(
            outbox.status(job_id).unwrap().state,
            ProviderIngestDeliveryStateV1::LocalStored {
                completion: ProviderIngestCompletionStateV1::Signing { .. },
                ..
            }
        ));
        assert_eq!(
            outbox
                .recover_expired_completion_signing(132, cursor(8))
                .unwrap(),
            0
        );
        assert_eq!(
            outbox
                .recover_expired_completion_signing(133, cursor(8))
                .unwrap(),
            1
        );
        assert_eq!(
            outbox.store_completion_transaction(&interrupted_claim, interrupted_transaction),
            Err(ProviderIngestOutboxError::InvalidSigningClaim)
        );
        let transaction = signed_completion(&initial_authorization, 9, 8);
        let signing_claim = claim_for_transaction(&outbox, job_id, &transaction, 9, 143, cursor(9));
        let transaction_hash = outbox
            .store_completion_transaction(&signing_claim, transaction)
            .unwrap();
        drop(outbox);
        outbox = ProviderIngestOutbox::open(&path, policy()).expect("signed restart");
        assert!(matches!(
            outbox.status(job_id).unwrap().state,
            ProviderIngestDeliveryStateV1::LocalStored {
                completion: ProviderIngestCompletionStateV1::Signed {
                    transaction_hash: hash,
                    ..
                },
                ..
            } if hash == transaction_hash
        ));
        begin_submission(&outbox, job_id, transaction_hash, 144).unwrap();
        drop(outbox);
        outbox = ProviderIngestOutbox::open(&path, policy()).expect("ambiguous restart");
        assert!(matches!(
            outbox.status(job_id).unwrap().state,
            ProviderIngestDeliveryStateV1::LocalStored {
                completion: ProviderIngestCompletionStateV1::Ambiguous { .. },
                ..
            }
        ));
        outbox
            .mark_completion_submitted(job_id, transaction_hash)
            .unwrap();
        drop(outbox);
        outbox = ProviderIngestOutbox::open(&path, policy()).expect("submitted restart");
        assert!(matches!(
            outbox.status(job_id).unwrap().state,
            ProviderIngestDeliveryStateV1::LocalStored {
                completion: ProviderIngestCompletionStateV1::Submitted { .. },
                ..
            }
        ));
        observe_finalized(&outbox, cursor(10));
        let evidence = finalized_evidence(&initial_authorization, 9, Some(transaction_hash), 10);
        outbox.mark_finalized_complete(job_id, evidence).unwrap();
        drop(outbox);
        outbox = ProviderIngestOutbox::open(&path, policy()).expect("terminal restart");
        assert!(matches!(
            outbox.status(job_id).unwrap().state,
            ProviderIngestDeliveryStateV1::FinalizedCompleted {
                completion_epoch: 9,
                committed_transaction_hash: Some(hash),
                ..
            } if hash == transaction_hash
        ));
        let cancelled = authorization(0x5D, 7);
        outbox.enqueue(cancelled.clone()).unwrap();
        outbox
            .cancel(
                cancelled.job_id(),
                cancellation_evidence(
                    &cancelled,
                    ProviderIngestCancellationReasonV1::ManifestRetired,
                    10,
                ),
            )
            .unwrap();
        let dead = authorization(0x5E, 7);
        outbox.enqueue(dead.clone()).unwrap();
        let dead_claim = outbox
            .claim_source(dead.job_id(), owner(3), 200, cursor(10))
            .unwrap();
        outbox
            .dead_letter_source(
                &dead_claim,
                201,
                cursor(10),
                ProviderIngestDeadLetterReasonV1::BindingMismatch,
                ProviderIngestFailureClassV1::BindingMismatch,
            )
            .unwrap();
        drop(outbox);
        outbox = ProviderIngestOutbox::open(&path, policy()).expect("terminal variants restart");
        assert!(matches!(
            outbox.status(cancelled.job_id()).unwrap().state,
            ProviderIngestDeliveryStateV1::Cancelled {
                reason: ProviderIngestCancellationReasonV1::ManifestRetired,
                ..
            }
        ));
        assert!(matches!(
            outbox.status(dead.job_id()).unwrap().state,
            ProviderIngestDeliveryStateV1::DeadLetter {
                reason: ProviderIngestDeadLetterReasonV1::BindingMismatch,
                ..
            }
        ));
    }
    #[test]
    fn finalized_cursor_high_water_survives_restart_and_rejects_substitution() {
        let directory = tempdir().expect("tempdir");
        let path = checkpoint_path(&directory);
        let outbox = ProviderIngestOutbox::open(&path, policy()).expect("open");
        outbox
            .observe_finalized_snapshot(cursor(8), 8_000)
            .expect("persist high-water");
        outbox
            .observe_finalized_snapshot(cursor(8), 8_000)
            .expect("idempotent high-water");
        assert_eq!(
            outbox.observe_finalized_snapshot(cursor(7), 7_000),
            Err(ProviderIngestOutboxError::StaleFinalizedCursor)
        );
        assert_eq!(
            outbox.observe_finalized_snapshot(cursor(8), 8_001),
            Err(ProviderIngestOutboxError::FinalizedSnapshotConflict)
        );
        let substituted = ProviderIngestFinalizedCursorV1 {
            height: 8,
            block_hash: [0xFE; 32],
        };
        assert_eq!(
            outbox.observe_finalized_snapshot(substituted, 8_000),
            Err(ProviderIngestOutboxError::StaleFinalizedCursor)
        );
        drop(outbox);
        let reopened = ProviderIngestOutbox::open(&path, policy()).expect("restart");
        assert_eq!(
            reopened.finalized_cursor_high_water().unwrap(),
            Some(cursor(8))
        );
        assert_eq!(
            reopened.finalized_snapshot_high_water().unwrap(),
            Some((cursor(8), 8_000))
        );
        assert_eq!(
            reopened.observe_finalized_snapshot(cursor(9), 8_000),
            Err(ProviderIngestOutboxError::FinalizedSnapshotConflict)
        );
        assert_eq!(
            reopened.observe_finalized_snapshot(cursor(9), 7_999),
            Err(ProviderIngestOutboxError::FinalizedSnapshotConflict)
        );
        assert_eq!(
            reopened.finalized_snapshot_high_water().unwrap(),
            Some((cursor(8), 8_000))
        );
        reopened
            .observe_finalized_snapshot(cursor(9), 9_000)
            .expect("advance after restart");
        drop(reopened);
        assert_eq!(
            ProviderIngestOutbox::open(&path, policy())
                .unwrap()
                .finalized_cursor_high_water()
                .unwrap(),
            Some(cursor(9))
        );
    }
    #[test]
    fn retained_finalized_snapshot_validation_fails_closed() {
        let mut checkpoint = ProviderIngestOutboxCheckpointV1::default();
        assert_eq!(
            validate_retained_finalized_snapshot(&checkpoint, Some(cursor(8))),
            Err(ProviderIngestOutboxError::StaleFinalizedCursor)
        );
        assert_eq!(
            validate_retained_finalized_snapshot(&checkpoint, None),
            Ok(None)
        );
        checkpoint.finalized_cursor_high_water = Some(cursor(8));
        assert_eq!(
            validate_retained_finalized_snapshot(&checkpoint, Some(cursor(8))),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        );
        checkpoint.finalized_cursor_high_water = None;
        checkpoint.finalized_block_time_ms_high_water = Some(8_000);
        assert_eq!(
            validate_retained_finalized_snapshot(&checkpoint, Some(cursor(8))),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        );
        checkpoint.finalized_cursor_high_water = Some(cursor(8));
        checkpoint.finalized_block_time_ms_high_water = Some(0);
        assert_eq!(
            validate_retained_finalized_snapshot(&checkpoint, Some(cursor(8))),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        );
        checkpoint.finalized_cursor_high_water = Some(cursor(0));
        checkpoint.finalized_block_time_ms_high_water = Some(8_000);
        assert_eq!(
            validate_retained_finalized_snapshot(&checkpoint, Some(cursor(8))),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        );
        checkpoint.finalized_cursor_high_water = Some(cursor(8));
        assert_eq!(
            validate_retained_finalized_snapshot(&checkpoint, Some(cursor(9))),
            Err(ProviderIngestOutboxError::StaleFinalizedCursor)
        );
        assert_eq!(
            validate_retained_finalized_snapshot(&checkpoint, Some(cursor(8))),
            Ok(Some((cursor(8), 8_000)))
        );
    }
    #[test]
    fn finalized_transition_rejects_malformed_snapshot_before_absent_job_lookup() {
        let authorization = authorization(0x7A, 7);
        let evidence = finalized_evidence(&authorization, 8, None, 8);
        for (retained_cursor, retained_block_time_ms) in [
            (Some(cursor(8)), None),
            (None, Some(8_000)),
            (Some(cursor(8)), Some(0)),
        ] {
            let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
            {
                let mut state = outbox.state.lock().unwrap();
                state.checkpoint.finalized_cursor_high_water = retained_cursor;
                state.checkpoint.finalized_block_time_ms_high_water = retained_block_time_ms;
            }
            let malformed = outbox.state.lock().unwrap().checkpoint.clone();
            assert_eq!(
                outbox.finalized_snapshot_high_water(),
                Err(ProviderIngestOutboxError::InvalidCheckpoint)
            );
            assert_eq!(
                outbox.observe_finalized_snapshot(cursor(9), 9_000),
                Err(ProviderIngestOutboxError::InvalidCheckpoint)
            );
            assert_eq!(
                outbox.mark_finalized_complete(authorization.job_id(), evidence.clone()),
                Err(ProviderIngestOutboxError::InvalidCheckpoint)
            );
            assert_eq!(outbox.state.lock().unwrap().checkpoint, malformed);
        }
    }
    #[test]
    fn finalized_transitions_require_snapshot_before_absent_job_lookup() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        let authorization = authorization(0x7B, 7);
        let finalized_completion = finalized_evidence(&authorization, 8, None, 8);
        let finalized_cancellation = cancellation_evidence(
            &authorization,
            ProviderIngestCancellationReasonV1::OrderExpired,
            8,
        );
        let empty = outbox.state.lock().unwrap().checkpoint.clone();
        assert_eq!(
            outbox.mark_completion_transaction_rejected(
                authorization.job_id(),
                [0xA5; 32],
                100,
                cursor(8),
            ),
            Err(ProviderIngestOutboxError::StaleFinalizedCursor)
        );
        assert_eq!(
            outbox.mark_finalized_complete(authorization.job_id(), finalized_completion),
            Err(ProviderIngestOutboxError::StaleFinalizedCursor)
        );
        assert_eq!(
            outbox.cancel(authorization.job_id(), finalized_cancellation),
            Err(ProviderIngestOutboxError::StaleFinalizedCursor)
        );
        assert_eq!(outbox.state.lock().unwrap().checkpoint, empty);
    }
    #[test]
    fn persistent_outbox_holds_one_hardened_writer_lock_for_its_lifetime() {
        let directory = tempdir().expect("tempdir");
        let path = checkpoint_path(&directory);
        let first = ProviderIngestOutbox::open(&path, policy()).expect("first writer");
        assert!(matches!(
            ProviderIngestOutbox::open(&path, policy()),
            Err(ProviderIngestOutboxError::CheckpointBusy)
        ));
        drop(first);
        let reopened = ProviderIngestOutbox::open(&path, policy()).expect("lock released");
        drop(reopened);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt as _, symlink};
            let lock_path = provider_ingest_lock_path(&path).expect("lock path");
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644))
                .expect("weaken lock permissions");
            assert!(matches!(
                ProviderIngestOutbox::open(&path, policy()),
                Err(ProviderIngestOutboxError::Checkpoint(_))
            ));
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
                .expect("restore lock permissions");
            let alias = directory.path().join("provider-ingest-lock-alias");
            fs::hard_link(&lock_path, &alias).expect("hard-link lock");
            assert!(matches!(
                ProviderIngestOutbox::open(&path, policy()),
                Err(ProviderIngestOutboxError::Checkpoint(_))
            ));
            fs::remove_file(&alias).expect("remove hard-link alias");
            fs::remove_file(&lock_path).expect("remove regular lock");
            let target = directory.path().join("provider-ingest-lock-target");
            fs::write(&target, b"").expect("write lock target");
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
                .expect("protect lock target");
            symlink(&target, &lock_path).expect("symlink lock");
            assert!(matches!(
                ProviderIngestOutbox::open(&path, policy()),
                Err(ProviderIngestOutboxError::Checkpoint(_))
            ));
        }
    }
    #[test]
    fn completion_ambiguity_absence_rejection_and_duplicates_are_safe() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        let authorization = authorization(0x55, 7);
        let job_id = authorization.job_id();
        enqueue_and_store_local(&outbox, &authorization, 100);
        let first_transaction = signed_completion(&authorization, 8, 8);
        let first_claim =
            claim_for_transaction(&outbox, job_id, &first_transaction, 8, 102, cursor(8));
        let completion_owner = first_claim
            .context
            .expected_authority
            .provider_owner
            .clone();
        let first_hash = outbox
            .store_completion_transaction(&first_claim, first_transaction)
            .unwrap();
        begin_submission(&outbox, job_id, first_hash, 103).unwrap();
        let ambiguous = stored_completion(&outbox, job_id);
        assert_eq!(
            outbox.mark_completion_not_submitted(job_id, first_hash, 0, cursor(8)),
            Err(ProviderIngestOutboxError::InvalidRuntimeTimestamp)
        );
        assert_eq!(stored_completion(&outbox, job_id), ambiguous);
        outbox
            .mark_completion_submitted(job_id, first_hash)
            .unwrap();
        outbox
            .mark_completion_submitted(job_id, first_hash)
            .expect("duplicate submitted acknowledgement is idempotent");
        observe_finalized(&outbox, cursor(9));
        assert_eq!(
            outbox
                .mark_completion_finalized_absent(job_id, first_hash, 200, cursor(9))
                .unwrap(),
            ProviderIngestRetryOutcomeV1::RetryScheduled {
                attempts: 2,
                next_attempt_at_ms: 220,
            }
        );
        let absence_retry = stored_completion(&outbox, job_id);
        assert_eq!(absence_retry.baseline_finalized_height, 9);
        assert_eq!(
            absence_retry.baseline_finalized_block_hash,
            cursor(9).block_hash
        );
        assert_eq!(
            absence_retry
                .signing_context
                .as_ref()
                .expect("signed retry retains its immutable signing context")
                .baseline_finalized_cursor,
            cursor(8)
        );
        assert_eq!(
            begin_submission(&outbox, job_id, first_hash, 219),
            Err(ProviderIngestOutboxError::StaleFinalizedCursor)
        );
        outbox
            .invalidate_stale_completion_authority(
                job_id,
                Some(&completion_owner),
                &ProviderIngestCompletionAuthorityObservationV1::Active(fixture_authority(
                    &completion_owner,
                    signer_policy(1),
                )),
                210,
                cursor(9),
            )
            .expect("refresh finalized completion authority");
        assert_eq!(
            begin_submission(&outbox, job_id, first_hash, 219),
            Err(ProviderIngestOutboxError::RetryNotDue)
        );
        begin_submission(&outbox, job_id, first_hash, 220).unwrap();
        observe_finalized(&outbox, cursor(10));
        assert_eq!(
            outbox
                .mark_completion_transaction_rejected(job_id, first_hash, 221, cursor(10),)
                .unwrap(),
            ProviderIngestRetryOutcomeV1::RetryScheduled {
                attempts: 2,
                next_attempt_at_ms: 241,
            }
        );
        let second_transaction = signed_completion(&authorization, 10, 8);
        let second_context = completion_context(&second_transaction, 10, cursor(10));
        assert_eq!(
            outbox.claim_completion_signing(job_id, second_context.clone(), 240),
            Err(ProviderIngestOutboxError::RetryNotDue)
        );
        let second_claim = outbox
            .claim_completion_signing(job_id, second_context, 241)
            .unwrap();
        let second_hash = outbox
            .store_completion_transaction(&second_claim, second_transaction)
            .unwrap();
        assert_ne!(first_hash, second_hash);
        begin_submission(&outbox, job_id, second_hash, 242).unwrap();
        outbox
            .mark_completion_submitted(job_id, second_hash)
            .unwrap();
        observe_finalized(&outbox, cursor(11));
        let evidence = finalized_evidence(&authorization, 10, Some(second_hash), 11);
        outbox
            .mark_finalized_complete(job_id, evidence.clone())
            .unwrap();
        outbox
            .mark_finalized_complete(job_id, evidence.clone())
            .expect("duplicate finalized reconciliation is idempotent");
        observe_finalized(&outbox, cursor(12));
        let finalized = outbox.state.lock().unwrap().checkpoint.clone();
        assert_eq!(
            outbox.mark_finalized_complete(job_id, evidence),
            Err(ProviderIngestOutboxError::StaleFinalizedCursor)
        );
        assert_eq!(outbox.state.lock().unwrap().checkpoint, finalized);
    }
    #[test]
    fn completion_transaction_is_bound_to_provider_order_and_epoch() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        let authorization = authorization(0x56, 7);
        let job_id = authorization.job_id();
        enqueue_and_store_local(&outbox, &authorization, 100);
        let expected = signed_completion(&authorization, 8, 8);
        let signing_claim = claim_for_transaction(&outbox, job_id, &expected, 8, 102, cursor(8));
        let wrong_provider = signed_completion_for([0x99; 32], authorization.order_id(), 8, 8);
        assert_eq!(
            outbox.store_completion_transaction(&signing_claim, wrong_provider),
            Err(ProviderIngestOutboxError::InvalidSignedTransaction)
        );
        let wrong_order = signed_completion_for(authorization.provider_id(), [0x99; 32], 8, 8);
        assert_eq!(
            outbox.store_completion_transaction(&signing_claim, wrong_order),
            Err(ProviderIngestOutboxError::InvalidSignedTransaction)
        );
        let wrong_epoch =
            signed_completion_for(authorization.provider_id(), authorization.order_id(), 9, 8);
        assert_eq!(
            outbox.store_completion_transaction(&signing_claim, wrong_epoch),
            Err(ProviderIngestOutboxError::InvalidSignedTransaction)
        );
    }
    #[test]
    fn completion_transaction_rejects_envelope_sidecars() {
        let authorization = authorization(0x57, 7);
        let expected = signed_completion(&authorization, 8, 8);
        let context = completion_context(&expected, 8, cursor(8));
        assert!(
            validate_completion_transaction(&authorization, &context, &expected, policy()).is_ok()
        );
        let key = KeyPair::try_from_seed(vec![8; 32], Algorithm::Ed25519).expect("key");
        let attachments = vec![ProofAttachment::new_ref(
            "halo2/ipa".into(),
            ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
            VerifyingKeyId::new("halo2/ipa", "vk_1"),
        )];
        let attached = TransactionBuilder::from_payload(expected.payload().clone())
            .expect("rebuild completion payload")
            .with_proof_attachments(attachments)
            .expect("valid proof carriers")
            .try_sign(key.private_key())
            .expect("sign attached completion");
        assert_eq!(
            validate_completion_transaction(&authorization, &context, &attached, policy()),
            Err(ProviderIngestOutboxError::InvalidSignedTransaction)
        );
        let mut multisig = expected.clone();
        multisig.set_multisig_signatures(MultisigSignatures::new(Vec::new()));
        assert_eq!(
            validate_completion_transaction(&authorization, &context, &multisig, policy()),
            Err(ProviderIngestOutboxError::InvalidSignedTransaction)
        );
    }
    #[test]
    fn rejected_completion_reaches_retry_exhausted_terminal_state() {
        let mut one_attempt = policy();
        one_attempt.max_attempts = 1;
        let outbox = ProviderIngestOutbox::in_memory(one_attempt).expect("outbox");
        let authorization = authorization(0x62, 7);
        let job_id = authorization.job_id();
        enqueue_and_store_local(&outbox, &authorization, 100);
        observe_finalized(&outbox, cursor(8));
        let transaction = signed_completion(&authorization, 8, 8);
        let signing_claim = claim_for_transaction(&outbox, job_id, &transaction, 8, 102, cursor(8));
        let transaction_hash = outbox
            .store_completion_transaction(&signing_claim, transaction)
            .unwrap();
        begin_submission(&outbox, job_id, transaction_hash, 103).unwrap();
        let ambiguous = outbox.state.lock().unwrap().checkpoint.clone();
        assert_eq!(
            outbox.mark_completion_transaction_rejected(job_id, transaction_hash, 104, cursor(9),),
            Err(ProviderIngestOutboxError::StaleFinalizedCursor)
        );
        assert_eq!(outbox.state.lock().unwrap().checkpoint, ambiguous);
        observe_finalized(&outbox, cursor(9));
        assert_eq!(
            outbox
                .mark_completion_transaction_rejected(job_id, transaction_hash, 104, cursor(9),)
                .unwrap(),
            ProviderIngestRetryOutcomeV1::DeadLettered
        );
        assert!(matches!(
            outbox.status(job_id).unwrap().state,
            ProviderIngestDeliveryStateV1::DeadLetter {
                attempts: 1,
                reason: ProviderIngestDeadLetterReasonV1::RetryExhausted,
                last_failure_class: ProviderIngestFailureClassV1::TransactionRejected,
                ..
            }
        ));
    }
    #[test]
    fn retry_exhaustion_rejects_non_retryable_failure_class() {
        let configured_policy = policy();
        let entry = StoredTerminalProviderIngestV1 {
            sequence: 1,
            authorization: authorization(0x63, 7),
            outcome: StoredProviderIngestTerminalOutcomeV1::DeadLetter {
                attempts: configured_policy.max_attempts,
                reason: ProviderIngestDeadLetterReasonV1::RetryExhausted,
                last_failure_class: ProviderIngestFailureClassV1::BindingMismatch,
                observed_finalized_cursor: cursor(8),
            },
        };
        assert_eq!(
            validate_terminal(&entry, configured_policy),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        );
    }
    #[test]
    fn protected_terminal_capacity_fails_closed_until_retention_expires() {
        let mut bounded = policy();
        bounded.max_terminal_entries = 2;
        let outbox = ProviderIngestOutbox::in_memory(bounded).expect("outbox");
        for (order, observed_height) in [(1, 10), (2, 11)] {
            let authorization = authorization(order, 7);
            outbox.enqueue(authorization.clone()).unwrap();
            observe_finalized(&outbox, cursor(observed_height));
            outbox
                .cancel(
                    authorization.job_id(),
                    cancellation_evidence(
                        &authorization,
                        ProviderIngestCancellationReasonV1::OrderExpired,
                        observed_height,
                    ),
                )
                .unwrap();
        }
        let protected = authorization(3, 7);
        outbox.enqueue(protected.clone()).unwrap();
        observe_finalized(&outbox, cursor(12));
        assert_eq!(
            outbox.cancel(
                protected.job_id(),
                cancellation_evidence(
                    &protected,
                    ProviderIngestCancellationReasonV1::OrderExpired,
                    12,
                ),
            ),
            Err(ProviderIngestOutboxError::CapacityExhausted)
        );
        assert_eq!(outbox.state.lock().unwrap().checkpoint.terminal.len(), 2);
        assert!(matches!(
            outbox.status(authorization(1, 7).job_id()).unwrap().state,
            ProviderIngestDeliveryStateV1::Cancelled { .. }
        ));
        assert!(matches!(
            outbox.status(protected.job_id()).unwrap().state,
            ProviderIngestDeliveryStateV1::PendingSource { .. }
        ));
        let completed = authorization(5, 7);
        assert_eq!(
            outbox.reconcile_finalized_completion(
                completed.clone(),
                finalized_evidence(&completed, 8, None, 12),
            ),
            Err(ProviderIngestOutboxError::CapacityExhausted)
        );
        assert_eq!(
            outbox.status(completed.job_id()),
            Err(ProviderIngestOutboxError::UnknownJob)
        );
        assert_eq!(outbox.state.lock().unwrap().checkpoint.terminal.len(), 2);
        let active = authorization(4, 7);
        outbox.enqueue(active.clone()).unwrap();
        observe_finalized(&outbox, cursor(20));
        assert_eq!(outbox.prune_terminal(cursor(20)).unwrap(), 2);
        outbox
            .cancel(
                protected.job_id(),
                cancellation_evidence(
                    &protected,
                    ProviderIngestCancellationReasonV1::OrderExpired,
                    20,
                ),
            )
            .unwrap();
        assert!(matches!(
            outbox.status(active.job_id()).unwrap().state,
            ProviderIngestDeliveryStateV1::PendingSource { .. }
        ));
        assert_eq!(outbox.state.lock().unwrap().checkpoint.active.len(), 1);
    }
    #[test]
    fn status_inventory_is_bounded_and_paginated() {
        let mut bounded = policy();
        bounded.max_status_page_size = 2;
        let outbox = ProviderIngestOutbox::in_memory(bounded).expect("outbox");
        for order in 1..=3 {
            outbox.enqueue(authorization(order, 7)).unwrap();
        }
        let first = outbox.statuses_page(None, 2).unwrap();
        assert_eq!(first.rows.len(), 2);
        assert!(first.next_after_job_id.is_some());
        let second = outbox.statuses_page(first.next_after_job_id, 2).unwrap();
        assert_eq!(second.rows.len(), 1);
        assert!(second.next_after_job_id.is_none());
        assert_eq!(
            outbox.statuses_page(None, 3),
            Err(ProviderIngestOutboxError::InvalidPageLimit)
        );
    }
    #[test]
    fn aggregate_counts_are_exact_durable_and_fail_closed_on_an_invalid_seal() {
        let directory = tempdir().expect("tempdir");
        let path = checkpoint_path(&directory);
        let mut outbox = ProviderIngestOutbox::open(&path, policy()).expect("outbox");
        assert_eq!(
            outbox.aggregate_counts().unwrap(),
            ProviderIngestOutboxCountsV1::default()
        );
        let active = authorization(0x31, 7);
        let cancelled = authorization(0x32, 7);
        let dead_letter = authorization(0x33, 7);
        for authorization in [&active, &cancelled, &dead_letter] {
            outbox.enqueue(authorization.clone()).unwrap();
        }
        observe_finalized(&outbox, cursor(8));
        outbox
            .cancel(
                cancelled.job_id(),
                cancellation_evidence(
                    &cancelled,
                    ProviderIngestCancellationReasonV1::ManifestRetired,
                    8,
                ),
            )
            .unwrap();
        let claim = outbox
            .claim_source(dead_letter.job_id(), owner(1), 100, cursor(8))
            .unwrap();
        outbox
            .dead_letter_source(
                &claim,
                101,
                cursor(8),
                ProviderIngestDeadLetterReasonV1::BindingMismatch,
                ProviderIngestFailureClassV1::BindingMismatch,
            )
            .unwrap();
        let expected = ProviderIngestOutboxCountsV1 {
            active: 1,
            terminal: 2,
            dead_letters: 1,
        };
        assert_eq!(outbox.aggregate_counts().unwrap(), expected);
        drop(outbox);
        outbox = ProviderIngestOutbox::open(&path, policy()).expect("restart");
        assert_eq!(outbox.aggregate_counts().unwrap(), expected);
        outbox.state.lock().unwrap().aggregate_counts.active = 2;
        assert_eq!(
            outbox.aggregate_counts(),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        );
    }
    #[test]
    fn malformed_corrupt_noncanonical_and_retired_checkpoints_fail_closed() {
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "sorafs_node::provider_ingest_outbox::tests::malformed_corrupt_noncanonical_and_retired_checkpoints_fail_closed::RetiredPreReleaseCheckpointV1"
        )]
        #[derive(Debug, NoritoSerialize, NoritoDeserialize)]
        struct RetiredPreReleaseCheckpointV1 {
            version: u8,
            entries: Vec<u8>,
        }
        let directory = tempdir().expect("tempdir");
        let path = checkpoint_path(&directory);
        let outbox = ProviderIngestOutbox::open(&path, policy()).unwrap();
        outbox.enqueue(authorization(0x57, 7)).unwrap();
        drop(outbox);
        let valid = fs::read(&path).unwrap();
        let current: ProviderIngestOutboxCheckpointV1 =
            norito::decode_canonical(&valid).expect("populated current checkpoint control");
        assert_eq!(norito::encode_canonical(&current).unwrap(), valid);
        fs::write(&path, &valid[..valid.len() / 2]).unwrap();
        assert!(matches!(
            ProviderIngestOutbox::open(&path, policy()),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        ));
        let mut corrupt = valid.clone();
        corrupt[0] ^= 0xFF;
        fs::write(&path, corrupt).unwrap();
        assert!(matches!(
            ProviderIngestOutbox::open(&path, policy()),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        ));
        let mut noncanonical = valid.clone();
        noncanonical.push(0);
        fs::write(&path, noncanonical).unwrap();
        assert!(matches!(
            ProviderIngestOutbox::open(&path, policy()),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        ));
        // This malformed old field shape is not an independent accepted frame owner.
        // Give its payload the actual current owner so rejection exercises the layout.
        let retired = {
            let _flags =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            let (payload, flags) =
                norito::codec::encode_with_header_flags(&RetiredPreReleaseCheckpointV1 {
                    version: 1,
                    entries: Vec::new(),
                });
            norito::core::frame_bare_with_header_flags::<ProviderIngestOutboxCheckpointV1>(
                &payload, flags,
            )
            .expect("current owner with rejected field shape")
        };
        assert!(matches!(
            norito::decode_canonical::<ProviderIngestOutboxCheckpointV1>(&retired),
            Err(error) if !matches!(error, norito::Error::SchemaMismatch)
        ));
        fs::write(&path, retired).unwrap();
        assert!(matches!(
            ProviderIngestOutbox::open(&path, policy()),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        ));
        fs::write(&path, &valid).unwrap();
        let restored = ProviderIngestOutbox::open(&path, policy()).unwrap();
        let mut retired_layout = restored.state.lock().unwrap().checkpoint.clone();
        retired_layout.magic = *b"SORAFSINGESTV1\0\0";
        retired_layout.version = 1;
        drop(restored);
        fs::write(&path, norito::to_bytes(&retired_layout).unwrap()).unwrap();
        assert!(matches!(
            ProviderIngestOutbox::open(&path, policy()),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        ));
        fs::write(&path, &valid).unwrap();
        let restored = ProviderIngestOutbox::open(&path, policy()).unwrap();
        let mut malformed = restored.state.lock().unwrap().checkpoint.clone();
        malformed.active.push(malformed.active[0].clone());
        drop(restored);
        fs::write(&path, norito::to_bytes(&malformed).unwrap()).unwrap();
        assert!(matches!(
            ProviderIngestOutbox::open(&path, policy()),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        ));
        let mut tiny = policy();
        tiny.max_active_entries = 1;
        tiny.max_terminal_entries = 1;
        tiny.max_signed_transaction_bytes =
            provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES_MIN;
        tiny.checkpoint_max_bytes =
            provider_ingest_outbox_defaults::worst_case_checkpoint_bytes_v1(
                tiny.max_active_entries,
                tiny.max_terminal_entries,
                tiny.max_signed_transaction_bytes,
            )
            .expect("tiny checked capacity");
        fs::write(
            &path,
            vec![
                0_u8;
                usize::try_from(tiny.checkpoint_max_bytes + 1)
                    .expect("tiny checkpoint bound fits usize")
            ],
        )
        .unwrap();
        assert!(matches!(
            ProviderIngestOutbox::open(&path, tiny),
            Err(ProviderIngestOutboxError::Checkpoint(_))
        ));
    }
    #[test]
    fn retired_v2_checkpoint_magic_and_layout_are_rejected() {
        let directory = tempdir().expect("tempdir");
        let path = checkpoint_path(&directory);
        let outbox = ProviderIngestOutbox::open(&path, policy()).expect("outbox");
        outbox.enqueue(authorization(0x58, 7)).expect("enqueue");
        let mut retired_v2 = outbox.state.lock().unwrap().checkpoint.clone();
        retired_v2.magic = *b"SORAFSINGESTV2\0\0";
        retired_v2.version = 2;
        drop(outbox);
        fs::write(
            &path,
            norito::to_bytes(&retired_v2).expect("encode retired V2 layout"),
        )
        .expect("write retired V2 layout");
        assert!(matches!(
            ProviderIngestOutbox::open(&path, policy()),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        ));
    }
    #[test]
    fn retired_v3_checkpoint_magic_and_layout_are_rejected() {
        let directory = tempdir().expect("tempdir");
        let path = checkpoint_path(&directory);
        let outbox = ProviderIngestOutbox::open(&path, policy()).expect("outbox");
        outbox.enqueue(authorization(0x59, 7)).expect("enqueue");
        let mut retired_v3 = outbox.state.lock().unwrap().checkpoint.clone();
        retired_v3.magic = *b"SORAFSINGESTV3\0\0";
        retired_v3.version = 3;
        drop(outbox);
        fs::write(
            &path,
            norito::to_bytes(&retired_v3).expect("encode retired V3 layout"),
        )
        .expect("write retired V3 layout");
        assert!(matches!(
            ProviderIngestOutbox::open(&path, policy()),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        ));
    }
    #[test]
    fn retired_v4_checkpoint_magic_and_layout_are_rejected() {
        let directory = tempdir().expect("tempdir");
        let path = checkpoint_path(&directory);
        let outbox = ProviderIngestOutbox::open(&path, policy()).expect("outbox");
        outbox.enqueue(authorization(0x5A, 7)).expect("enqueue");
        let mut retired_v4 = outbox.state.lock().unwrap().checkpoint.clone();
        retired_v4.magic = *b"SORAFSINGESTV4\0\0";
        retired_v4.version = 4;
        drop(outbox);
        fs::write(
            &path,
            norito::to_bytes(&retired_v4).expect("encode retired V4 layout"),
        )
        .expect("write retired V4 layout");
        assert!(matches!(
            ProviderIngestOutbox::open(&path, policy()),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        ));
    }
    #[test]
    fn generic_and_musubi_local_receipt_pairing_is_exact() {
        let (musubi, receipt) = musubi_authorization_and_receipt(0x5B, 7, 0x32);
        let generic = authorization(0x5B, 7);
        let generic_outbox = ProviderIngestOutbox::in_memory(policy()).expect("generic outbox");
        generic_outbox
            .enqueue(generic.clone())
            .expect("enqueue generic");
        let generic_claim = generic_outbox
            .claim_source(generic.job_id(), owner(1), 100, cursor(7))
            .expect("claim generic");
        assert_eq!(
            generic_outbox.mark_local_stored_verified(
                &generic_claim,
                101,
                manifest_id(&generic),
                Some(receipt.clone()),
            ),
            Err(ProviderIngestOutboxError::InvalidAuthorization)
        );
        generic_outbox
            .mark_local_stored(&generic_claim, 101, manifest_id(&generic))
            .expect("store generic without receipt");
        let musubi_outbox = ProviderIngestOutbox::in_memory(policy()).expect("Musubi outbox");
        observe_finalized(&musubi_outbox, cursor(7));
        musubi_outbox
            .enqueue(musubi.clone())
            .expect("enqueue Musubi");
        let musubi_claim = musubi_outbox
            .claim_source(musubi.job_id(), owner(2), 100, cursor(7))
            .expect("claim Musubi");
        assert_eq!(
            musubi_outbox.mark_local_stored(&musubi_claim, 101, manifest_id(&musubi)),
            Err(ProviderIngestOutboxError::InvalidAuthorization)
        );
        musubi_outbox
            .mark_local_stored_verified(&musubi_claim, 101, manifest_id(&musubi), Some(receipt))
            .expect("store Musubi with exact receipt");
        assert_eq!(
            musubi_outbox
                .authorization(musubi.job_id())
                .expect("active authorization"),
            musubi
        );
        assert!(matches!(
            musubi_outbox
                .status(musubi.job_id())
                .expect("local Musubi status")
                .state,
            ProviderIngestDeliveryStateV1::LocalStored {
                musubi_bundle: Some(_),
                ..
            }
        ));
        observe_finalized(&musubi_outbox, cursor(8));
        musubi_outbox
            .mark_finalized_complete(musubi.job_id(), finalized_evidence(&musubi, 8, None, 8))
            .expect("finalize locally stored Musubi");
        assert_eq!(
            musubi_outbox
                .authorization(musubi.job_id())
                .expect("terminal authorization"),
            musubi
        );
        assert!(matches!(
            musubi_outbox
                .status(musubi.job_id())
                .expect("terminal Musubi status")
                .state,
            ProviderIngestDeliveryStateV1::FinalizedCompleted {
                manifest_id: Some(_),
                musubi_bundle: Some(_),
                ..
            }
        ));
    }
    #[test]
    fn private_musubi_receipt_checkpoint_roundtrip_preserves_public_projection() {
        let directory = tempdir().expect("tempdir");
        let path = checkpoint_path(&directory);
        let (authorization, receipt) = musubi_authorization_and_receipt(0x60, 7, 0x36);
        let job_id = authorization.job_id();
        let outbox = ProviderIngestOutbox::open(&path, policy()).expect("outbox");
        observe_finalized(&outbox, cursor(7));
        outbox
            .enqueue(authorization.clone())
            .expect("enqueue Musubi");
        let claim = outbox
            .claim_source(job_id, owner(6), 100, cursor(7))
            .expect("claim Musubi source");
        outbox
            .mark_local_stored_verified(
                &claim,
                101,
                manifest_id(&authorization),
                Some(receipt.clone()),
            )
            .expect("persist private receipt DTO");
        drop(outbox);
        let restored = ProviderIngestOutbox::open(&path, policy()).expect("restore local state");
        let ProviderIngestDeliveryStateV1::LocalStored {
            musubi_bundle: Some(local_receipt),
            ..
        } = restored.status(job_id).expect("local status").state
        else {
            panic!("restored Musubi state must project its opaque receipt");
        };
        assert_eq!(*local_receipt, receipt);
        observe_finalized(&restored, cursor(8));
        restored
            .mark_finalized_complete(job_id, finalized_evidence(&authorization, 8, None, 8))
            .expect("finalize restored Musubi state");
        drop(restored);
        let restored = ProviderIngestOutbox::open(&path, policy()).expect("restore terminal state");
        let ProviderIngestDeliveryStateV1::FinalizedCompleted {
            musubi_bundle: Some(terminal_receipt),
            ..
        } = restored.status(job_id).expect("terminal status").state
        else {
            panic!("terminal Musubi state must project its opaque receipt");
        };
        assert_eq!(*terminal_receipt, receipt);
    }
    #[test]
    fn checkpoint_rejects_future_or_postcompletion_receipt_cursor() {
        let (authorization, receipt) = musubi_authorization_and_receipt(0x61, 7, 0x37);
        let job_id = authorization.job_id();
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        observe_finalized(&outbox, cursor(8));
        outbox
            .enqueue(authorization.clone())
            .expect("enqueue Musubi");
        let claim = outbox
            .claim_source(job_id, owner(7), 100, cursor(8))
            .expect("claim Musubi source");
        outbox
            .mark_local_stored_verified(&claim, 101, manifest_id(&authorization), Some(receipt))
            .expect("store exact Musubi receipt");
        let mut future = outbox.state.lock().unwrap().checkpoint.clone();
        let StoredProviderIngestStateV1::LocalStored {
            musubi_bundle: Some(receipt),
            ..
        } = &mut future.active[0].state
        else {
            panic!("fixture must retain a Musubi receipt");
        };
        receipt.set_observed_finalized_cursor_for_test(cursor(9));
        assert_eq!(
            validate_checkpoint(&future, policy()),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        );
        outbox
            .mark_finalized_complete(job_id, finalized_evidence(&authorization, 8, None, 8))
            .expect("finalize Musubi receipt at height eight");
        observe_finalized(&outbox, cursor(10));
        let mut postcompletion = outbox.state.lock().unwrap().checkpoint.clone();
        let StoredProviderIngestTerminalOutcomeV1::FinalizedCompleted {
            musubi_bundle: Some(receipt),
            ..
        } = &mut postcompletion.terminal[0].outcome
        else {
            panic!("terminal fixture must retain a Musubi receipt");
        };
        receipt.set_observed_finalized_cursor_for_test(cursor(9));
        assert_eq!(
            validate_checkpoint(&postcompletion, policy()),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        );
    }
    #[test]
    fn musubi_receipt_context_substitution_is_rejected() {
        let (original, receipt) = musubi_authorization_and_receipt(0x5C, 7, 0x33);
        let original_context = original.musubi_context().expect("Musubi context");
        let substituted_context = FinalizedProviderIngestMusubiContextV1::new(
            network_id(0xF1),
            original_context.archive_id(),
        )
        .expect("substituted context");
        let substituted =
            authorization_with_musubi_context(&authorization(0x5C, 7), substituted_context);
        assert_ne!(original.job_id(), substituted.job_id());
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        outbox
            .enqueue(substituted.clone())
            .expect("enqueue substituted authorization");
        let claim = outbox
            .claim_source(substituted.job_id(), owner(3), 100, cursor(7))
            .expect("claim source");
        assert_eq!(
            outbox.mark_local_stored_verified(
                &claim,
                101,
                manifest_id(&substituted),
                Some(receipt),
            ),
            Err(ProviderIngestOutboxError::InvalidAuthorization)
        );
    }
    #[test]
    fn checkpoint_validation_rejects_musubi_receipt_shape_substitution() {
        let (musubi, receipt) = musubi_authorization_and_receipt(0x5D, 7, 0x34);
        let generic = authorization(0x5D, 7);
        let generic_outbox = ProviderIngestOutbox::in_memory(policy()).expect("generic outbox");
        generic_outbox
            .enqueue(generic.clone())
            .expect("enqueue generic");
        let generic_claim = generic_outbox
            .claim_source(generic.job_id(), owner(4), 100, cursor(7))
            .expect("claim generic");
        generic_outbox
            .mark_local_stored(&generic_claim, 101, manifest_id(&generic))
            .expect("store generic");
        let mut generic_checkpoint = generic_outbox.state.lock().unwrap().checkpoint.clone();
        let StoredProviderIngestStateV1::LocalStored { musubi_bundle, .. } =
            &mut generic_checkpoint.active[0].state
        else {
            panic!("generic fixture must be locally stored");
        };
        *musubi_bundle = Some(Box::new(receipt.to_stored()));
        assert_eq!(
            validate_checkpoint(&generic_checkpoint, policy()),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        );
        let musubi_outbox = ProviderIngestOutbox::in_memory(policy()).expect("Musubi outbox");
        observe_finalized(&musubi_outbox, cursor(7));
        musubi_outbox
            .enqueue(musubi.clone())
            .expect("enqueue Musubi");
        let musubi_claim = musubi_outbox
            .claim_source(musubi.job_id(), owner(5), 100, cursor(7))
            .expect("claim Musubi");
        musubi_outbox
            .mark_local_stored_verified(&musubi_claim, 101, manifest_id(&musubi), Some(receipt))
            .expect("store Musubi");
        let mut musubi_checkpoint = musubi_outbox.state.lock().unwrap().checkpoint.clone();
        let StoredProviderIngestStateV1::LocalStored { musubi_bundle, .. } =
            &mut musubi_checkpoint.active[0].state
        else {
            panic!("Musubi fixture must be locally stored");
        };
        *musubi_bundle = None;
        assert_eq!(
            validate_checkpoint(&musubi_checkpoint, policy()),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        );
    }
    #[test]
    fn terminal_without_local_manifest_permits_no_receipt_only() {
        let (musubi, receipt) = musubi_authorization_and_receipt(0x5E, 7, 0x35);
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        outbox.enqueue(musubi.clone()).expect("enqueue Musubi");
        observe_finalized(&outbox, cursor(8));
        outbox
            .mark_finalized_complete(musubi.job_id(), finalized_evidence(&musubi, 8, None, 8))
            .expect("observe another provider's completion");
        assert!(matches!(
            outbox
                .status(musubi.job_id())
                .expect("terminal status")
                .state,
            ProviderIngestDeliveryStateV1::FinalizedCompleted {
                manifest_id: None,
                musubi_bundle: None,
                ..
            }
        ));
        let mut substituted = outbox.state.lock().unwrap().checkpoint.clone();
        let StoredProviderIngestTerminalOutcomeV1::FinalizedCompleted { musubi_bundle, .. } =
            &mut substituted.terminal[0].outcome
        else {
            panic!("fixture must be finalized completed");
        };
        *musubi_bundle = Some(Box::new(receipt.to_stored()));
        assert_eq!(
            validate_checkpoint(&substituted, policy()),
            Err(ProviderIngestOutboxError::InvalidCheckpoint)
        );
    }
    #[test]
    fn generic_local_and_terminal_rows_remain_receipt_free() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        let authorization = authorization(0x59, 7);
        let job_id = authorization.job_id();
        outbox.enqueue(authorization.clone()).expect("enqueue");
        let claim = outbox
            .claim_source(job_id, owner(1), 100, cursor(7))
            .expect("claim source");
        outbox
            .mark_local_stored(&claim, 101, manifest_id(&authorization))
            .expect("store generic payload");
        assert!(matches!(
            outbox.status(job_id).expect("local status").state,
            ProviderIngestDeliveryStateV1::LocalStored {
                musubi_bundle: None,
                ..
            }
        ));
        observe_finalized(&outbox, cursor(8));
        outbox
            .mark_finalized_complete(job_id, finalized_evidence(&authorization, 8, None, 8))
            .expect("finalize generic payload");
        assert!(matches!(
            outbox.status(job_id).expect("terminal status").state,
            ProviderIngestDeliveryStateV1::FinalizedCompleted {
                musubi_bundle: None,
                ..
            }
        ));
    }
    #[test]
    fn illegal_transitions_and_stale_material_are_rejected() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        let authorization = authorization(0x58, 7);
        let job_id = authorization.job_id();
        outbox.enqueue(authorization.clone()).unwrap();
        let transaction = signed_completion(&authorization, 8, 8);
        let context = completion_context(&transaction, 8, cursor(8));
        assert_eq!(
            outbox.claim_completion_signing(job_id, context, 100),
            Err(ProviderIngestOutboxError::InvalidTransition)
        );
        let claim = outbox
            .claim_source(job_id, owner(1), 100, cursor(7))
            .unwrap();
        let mut stale_claim = claim.clone();
        stale_claim.generation += 1;
        assert_eq!(
            outbox.mark_local_stored(&stale_claim, 101, manifest_id(&authorization)),
            Err(ProviderIngestOutboxError::InvalidSourceClaim)
        );
        assert_eq!(
            outbox.dead_letter_source(
                &claim,
                101,
                cursor(7),
                ProviderIngestDeadLetterReasonV1::RetryExhausted,
                ProviderIngestFailureClassV1::SourceRejected,
            ),
            Err(ProviderIngestOutboxError::InvalidTransition)
        );
        outbox
            .mark_local_stored(&claim, 101, manifest_id(&authorization))
            .unwrap();
        let signing_claim = claim_for_transaction(&outbox, job_id, &transaction, 8, 102, cursor(8));
        let transaction_hash = outbox
            .store_completion_transaction(&signing_claim, transaction)
            .unwrap();
        begin_submission(&outbox, job_id, transaction_hash, 103).unwrap();
        assert_eq!(
            begin_submission(&outbox, job_id, transaction_hash, 103),
            Err(ProviderIngestOutboxError::InvalidTransition)
        );
        observe_finalized(&outbox, cursor(9));
        outbox
            .cancel(
                job_id,
                cancellation_evidence(
                    &authorization,
                    ProviderIngestCancellationReasonV1::OrderCompletedByOther,
                    9,
                ),
            )
            .unwrap();
        assert_eq!(
            outbox.mark_completion_submitted(job_id, transaction_hash),
            Err(ProviderIngestOutboxError::UnknownJob)
        );
    }
    #[test]
    fn uncertain_durability_poison_is_fail_closed() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        outbox.state.lock().unwrap().durability_failure = Some("uncertain".to_owned());
        assert_eq!(
            outbox.statuses_page(None, 1),
            Err(ProviderIngestOutboxError::DurabilityPoisoned)
        );
        assert_eq!(
            outbox.enqueue(authorization(0x59, 7)),
            Err(ProviderIngestOutboxError::DurabilityPoisoned)
        );
    }
    #[test]
    fn checkpoint_validation_rejects_signed_transaction_substitution() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        let authorization = authorization(0x5A, 7);
        let job_id = authorization.job_id();
        enqueue_and_store_local(&outbox, &authorization, 100);
        observe_finalized(&outbox, cursor(8));
        let transaction = signed_completion(&authorization, 8, 8);
        let signing_claim = claim_for_transaction(&outbox, job_id, &transaction, 8, 102, cursor(8));
        outbox
            .store_completion_transaction(&signing_claim, transaction)
            .unwrap();
        let mut checkpoint = outbox.state.lock().unwrap().checkpoint.clone();
        let completion = local_completion_mut(&mut checkpoint.active[0]).unwrap();
        let substituted = signed_completion_for([0x99; 32], authorization.order_id(), 8, 9);
        completion.transaction_hash = Some(*substituted.hash().as_ref());
        completion.signed_transaction = Some(substituted);
        assert_eq!(
            validate_checkpoint(&checkpoint, policy()),
            Err(ProviderIngestOutboxError::InvalidSignedTransaction)
        );
        let mut substituted_context = outbox.state.lock().unwrap().checkpoint.clone();
        let completion = local_completion_mut(&mut substituted_context.active[0]).unwrap();
        completion
            .signing_context
            .as_mut()
            .expect("signed context")
            .network_id = network_id(0xF2);
        assert_eq!(
            validate_checkpoint(&substituted_context, policy()),
            Err(ProviderIngestOutboxError::InvalidSignedTransaction)
        );
    }
    #[test]
    fn terminal_finalization_requires_this_provider_not_only_order_completion() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        let authorization = authorization(0x5B, 7);
        let job_id = authorization.job_id();
        enqueue_and_store_local(&outbox, &authorization, 100);
        let transaction = signed_completion(&authorization, 8, 8);
        let signing_claim = claim_for_transaction(&outbox, job_id, &transaction, 8, 102, cursor(8));
        let transaction_hash = outbox
            .store_completion_transaction(&signing_claim, transaction)
            .unwrap();
        begin_submission(&outbox, job_id, transaction_hash, 103).unwrap();
        outbox
            .mark_completion_submitted(job_id, transaction_hash)
            .unwrap();
        observe_finalized(&outbox, cursor(9));
        let mut other_provider = finalized_evidence(&authorization, 8, Some(transaction_hash), 9);
        other_provider.provider_id = [0x99; 32];
        assert_eq!(
            outbox.mark_finalized_complete(job_id, other_provider),
            Err(ProviderIngestOutboxError::InvalidCompletionEvidence)
        );
        assert!(matches!(
            outbox.status(job_id).unwrap().state,
            ProviderIngestDeliveryStateV1::LocalStored {
                completion: ProviderIngestCompletionStateV1::Submitted { .. },
                ..
            }
        ));
    }
    #[test]
    fn source_lease_renewal_is_durable_and_invalidates_the_previous_token() {
        let directory = tempdir().expect("tempdir");
        let path = checkpoint_path(&directory);
        let initial_authorization = authorization(0x64, 7);
        let outbox = ProviderIngestOutbox::open(&path, policy()).expect("outbox");
        outbox.enqueue(initial_authorization.clone()).unwrap();
        let original = outbox
            .claim_source(initial_authorization.job_id(), owner(1), 100, cursor(7))
            .unwrap();
        let renewed = outbox
            .renew_source_claim(&original, 105, cursor(8))
            .expect("renew lease");
        assert_eq!(renewed.generation, original.generation);
        assert!(renewed.lease_expires_at_ms() > original.lease_expires_at_ms());
        assert_eq!(
            outbox.mark_local_stored(&original, 106, manifest_id(&initial_authorization)),
            Err(ProviderIngestOutboxError::InvalidSourceClaim)
        );
        drop(outbox);
        let reopened = ProviderIngestOutbox::open(&path, policy()).expect("reopen");
        reopened
            .mark_local_stored(&renewed, 106, manifest_id(&initial_authorization))
            .expect("renewed token survives restart");
        let expired = authorization(0x65, 7);
        reopened.enqueue(expired.clone()).unwrap();
        let expired_claim = reopened
            .claim_source(expired.job_id(), owner(2), 200, cursor(7))
            .unwrap();
        assert_eq!(
            reopened.renew_source_claim(&expired_claim, 210, cursor(8)),
            Err(ProviderIngestOutboxError::SourceClaimExpired)
        );
    }
    #[test]
    fn prepared_signing_context_binds_network_owner_payload_and_claim_generation() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        let authorization = authorization(0x66, 7);
        let job_id = authorization.job_id();
        enqueue_and_store_local(&outbox, &authorization, 100);
        observe_finalized(&outbox, cursor(8));
        let transaction = signed_completion(&authorization, 8, 8);
        let valid = completion_context(&transaction, 8, cursor(8));
        assert_ingest_frame(
            &valid,
            "sorafs_node::provider_ingest_outbox::ProviderIngestCompletionSigningContextV1",
        );
        let mut wrong_network = valid.clone();
        wrong_network.network_id = network_id(0xF3);
        assert_eq!(
            outbox.claim_completion_signing(job_id, wrong_network, 102),
            Err(ProviderIngestOutboxError::InvalidSigningContext)
        );
        let mut wrong_owner = valid.clone();
        wrong_owner.expected_authority.provider_owner = completed_by(0x77);
        assert_eq!(
            outbox.claim_completion_signing(job_id, wrong_owner, 102),
            Err(ProviderIngestOutboxError::InvalidSigningContext)
        );
        let mut missing_ttl = valid.clone();
        missing_ttl.expected_payload.time_to_live_ms = None;
        assert_eq!(
            outbox.claim_completion_signing(job_id, missing_ttl, 102),
            Err(ProviderIngestOutboxError::InvalidSigningContext)
        );
        for invalid_policy in [
            ProviderIngestCompletionSignerPolicyV1 {
                policy_id: [0; 32],
                ..signer_policy(1)
            },
            ProviderIngestCompletionSignerPolicyV1 {
                revision: 0,
                ..signer_policy(1)
            },
            ProviderIngestCompletionSignerPolicyV1 {
                policy_digest: [0; 32],
                ..signer_policy(1)
            },
        ] {
            let mut invalid = valid.clone();
            invalid.expected_authority.signer_policy = invalid_policy;
            assert_eq!(
                outbox.claim_completion_signing(job_id, invalid, 102),
                Err(ProviderIngestOutboxError::InvalidSignerPolicy)
            );
        }
        let first_claim = outbox
            .claim_completion_signing(job_id, valid.clone(), 102)
            .unwrap();
        let substituted = signed_completion(&authorization, 8, 9);
        assert_eq!(
            outbox.store_completion_transaction(&first_claim, substituted),
            Err(ProviderIngestOutboxError::InvalidSignedTransaction)
        );
        let mut bad_signature = transaction.clone();
        let other_signature = signed_completion(&authorization, 8, 9);
        bad_signature.set_signature(other_signature.signature().clone());
        assert_eq!(
            outbox.store_completion_transaction(&first_claim, bad_signature),
            Err(ProviderIngestOutboxError::InvalidSignedTransaction)
        );
        outbox
            .release_completion_signing(&first_claim, 103, cursor(8))
            .unwrap();
        assert_eq!(
            outbox.store_completion_transaction(&first_claim, transaction.clone()),
            Err(ProviderIngestOutboxError::InvalidSigningClaim)
        );
        let second_claim = outbox
            .claim_completion_signing(job_id, valid, 113)
            .expect("reclaim after backoff");
        assert!(second_claim.generation() > first_claim.generation());
        outbox
            .store_completion_transaction(&second_claim, transaction)
            .expect("exact signature");
    }
    #[test]
    fn signer_policy_floor_rejects_rollback_equivocation_and_identity_substitution() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        let authorization = authorization(0x67, 7);
        let job_id = authorization.job_id();
        enqueue_and_store_local(&outbox, &authorization, 100);
        observe_finalized(&outbox, cursor(8));
        let transaction =
            signed_completion_with_policy_at(&authorization, 8, cursor(8), 8, signer_policy(2));
        let mut revision_two = completion_context(&transaction, 8, cursor(8));
        revision_two.expected_authority.signer_policy = signer_policy(2);
        let claim = outbox
            .claim_completion_signing(job_id, revision_two.clone(), 102)
            .expect("claim revision two");
        outbox
            .release_completion_signing(&claim, 103, cursor(8))
            .expect("release revision two");
        observe_finalized(&outbox, cursor(9));
        let mut identity_substitution_policy = signer_policy(3);
        identity_substitution_policy.policy_id = [0xB1; 32];
        let revision_rollback_policy = signer_policy(1);
        let mut digest_equivocation_policy = signer_policy(2);
        digest_equivocation_policy.policy_digest = [0xEE; 32];
        let mut unchanged_digest_policy = signer_policy(3);
        unchanged_digest_policy.policy_digest = signer_policy(2).policy_digest;
        for invalid_policy in [
            identity_substitution_policy,
            revision_rollback_policy,
            digest_equivocation_policy,
            unchanged_digest_policy,
        ] {
            let transaction =
                signed_completion_with_policy_at(&authorization, 8, cursor(9), 8, invalid_policy);
            let mut invalid = completion_context(&transaction, 8, cursor(9));
            invalid.expected_authority.signer_policy = invalid_policy;
            assert_eq!(
                outbox.claim_completion_signing(job_id, invalid, 113),
                Err(ProviderIngestOutboxError::SignerPolicyRollback)
            );
        }
        let successor_policy = signer_policy(3);
        let successor_transaction =
            signed_completion_with_policy_at(&authorization, 8, cursor(9), 8, successor_policy);
        let mut canonical_successor = completion_context(&successor_transaction, 8, cursor(9));
        canonical_successor.expected_authority.signer_policy = successor_policy;
        outbox
            .claim_completion_signing(job_id, canonical_successor, 113)
            .expect("claim canonical strict policy successor");
    }
    #[test]
    fn signer_policy_floor_accepts_canonical_replacement_identity() {
        let replacement = ProviderIngestCompletionSignerPolicyV1 {
            policy_id: [0xB1; 32],
            revision: 1,
            predecessor_digest: None,
            policy_digest: [0xB2; 32],
        };
        validate_authority_progress(
            Some(fixture_authority(&completed_by(8), signer_policy(2))),
            false,
            &fixture_authority(&completed_by(8), replacement),
        )
        .expect("replacement policy identity may restart at canonical revision one");
        validate_authority_progress(
            Some(fixture_authority(&completed_by(8), signer_policy(2))),
            true,
            &fixture_authority(&completed_by(8), replacement),
        )
        .expect("canonical replacement satisfies a required post-revocation successor");
    }
    #[test]
    fn finalized_owner_rotation_invalidates_only_unexposed_prepared_state() {
        let prepared_states = [
            StoredDeliveryStateV1::Signing,
            StoredDeliveryStateV1::Signed,
            StoredDeliveryStateV1::Ambiguous,
            StoredDeliveryStateV1::Submitted,
        ];
        for (index, prepared_state) in prepared_states.into_iter().enumerate() {
            let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
            let order = 0x80_u8.saturating_add(u8::try_from(index).unwrap());
            let authorization = authorization(order, 7);
            let job_id = authorization.job_id();
            enqueue_and_store_local(&outbox, &authorization, 100);
            let old_transaction = signed_completion(&authorization, 8, 8);
            let old_owner = old_transaction.authority().clone();
            let old_claim =
                claim_for_transaction(&outbox, job_id, &old_transaction, 8, 102, cursor(8));
            let old_hash = if prepared_state == StoredDeliveryStateV1::Signing {
                None
            } else {
                Some(
                    outbox
                        .store_completion_transaction(&old_claim, old_transaction.clone())
                        .unwrap(),
                )
            };
            if matches!(
                prepared_state,
                StoredDeliveryStateV1::Ambiguous | StoredDeliveryStateV1::Submitted
            ) {
                begin_submission(&outbox, job_id, old_hash.unwrap(), 103).unwrap();
            }
            if prepared_state == StoredDeliveryStateV1::Submitted {
                outbox
                    .mark_completion_submitted(job_id, old_hash.unwrap())
                    .unwrap();
            }
            let prepared = stored_completion(&outbox, job_id);
            assert_eq!(prepared.state, prepared_state);
            observe_finalized(&outbox, cursor(9));
            assert_eq!(
                outbox
                    .invalidate_stale_completion_authority(
                        job_id,
                        Some(&old_owner),
                        &ProviderIngestCompletionAuthorityObservationV1::NotChecked,
                        104,
                        cursor(9)
                    )
                    .unwrap(),
                None,
                "current owner must be idempotent for {prepared_state:?}"
            );
            let before_rotation = stored_completion(&outbox, job_id);
            assert_eq!(before_rotation.state, prepared.state);
            assert_eq!(before_rotation.signing_context, prepared.signing_context);
            assert_eq!(before_rotation.transaction_hash, prepared.transaction_hash);
            assert_eq!(
                before_rotation.signed_transaction,
                prepared.signed_transaction
            );
            let replacement_seed = 0x40_u8.saturating_add(u8::try_from(index).unwrap());
            let replacement_owner = completed_by(replacement_seed);
            assert_eq!(
                outbox.invalidate_stale_completion_authority(
                    job_id,
                    Some(&replacement_owner),
                    &ProviderIngestCompletionAuthorityObservationV1::NotChecked,
                    104,
                    cursor(8)
                ),
                Err(ProviderIngestOutboxError::StaleFinalizedCursor),
                "same-baseline owner substitution must fail for {prepared_state:?}"
            );
            assert_eq!(stored_completion(&outbox, job_id), before_rotation);
            assert_eq!(
                outbox.invalidate_stale_completion_authority(
                    job_id,
                    Some(&replacement_owner),
                    &ProviderIngestCompletionAuthorityObservationV1::NotChecked,
                    104,
                    cursor(9)
                ),
                Err(ProviderIngestOutboxError::FinalizedAuthorityConflict),
                "one finalized cursor cannot equivocate about provider ownership"
            );
            assert_eq!(stored_completion(&outbox, job_id), before_rotation);
            observe_finalized(&outbox, cursor(10));
            let invalidation = outbox
                .invalidate_stale_completion_authority(
                    job_id,
                    Some(&replacement_owner),
                    &ProviderIngestCompletionAuthorityObservationV1::NotChecked,
                    104,
                    cursor(10),
                )
                .unwrap();
            if matches!(
                prepared_state,
                StoredDeliveryStateV1::Ambiguous | StoredDeliveryStateV1::Submitted
            ) {
                assert_eq!(
                    invalidation, None,
                    "exposed {prepared_state:?} bytes must remain quarantined"
                );
                let retained = stored_completion(&outbox, job_id);
                assert_eq!(retained.state, prepared_state);
                assert_eq!(retained.signing_context, before_rotation.signing_context);
                assert_eq!(retained.transaction_hash, before_rotation.transaction_hash);
                assert_eq!(
                    retained.signed_transaction,
                    before_rotation.signed_transaction
                );
                assert!(retained.ever_exposed);
                assert_eq!(
                    retained.finalized_authority_observation,
                    Some(StoredFinalizedCompletionAuthorityObservationV1 {
                        cursor: cursor(10),
                        provider_owner: Some(replacement_owner.clone()),
                        completion_authority:
                            ProviderIngestCompletionAuthorityObservationV1::NotChecked,
                    })
                );
                assert_eq!(retained.authority_owner.as_ref(), Some(&replacement_owner));
                assert_eq!(
                    retained
                        .authority_floor
                        .as_ref()
                        .map(|authority| authority.signer_policy),
                    None
                );
                assert_eq!(
                    outbox.store_completion_transaction(&old_claim, old_transaction),
                    Err(ProviderIngestOutboxError::InvalidSigningClaim)
                );
                continue;
            }
            assert_eq!(
                invalidation,
                Some(ProviderIngestRetryOutcomeV1::RetryScheduled {
                    attempts: 1,
                    next_attempt_at_ms: 114,
                }),
                "new finalized owner must invalidate unexposed {prepared_state:?}"
            );
            let cleared = stored_completion(&outbox, job_id);
            assert_eq!(cleared.state, StoredDeliveryStateV1::Ready);
            assert_eq!(cleared.attempts, 1);
            assert_eq!(cleared.baseline_finalized_height, 0);
            assert_eq!(cleared.baseline_finalized_block_hash, [0; 32]);
            assert_eq!(cleared.completion_epoch, None);
            assert_eq!(cleared.signing_context, None);
            assert_eq!(cleared.transaction_hash, None);
            assert_eq!(cleared.signed_transaction, None);
            assert_eq!(cleared.next_attempt_at_ms, 114);
            assert_eq!(
                cleared.last_failure_class,
                Some(ProviderIngestFailureClassV1::ProviderOwnerChanged)
            );
            assert_eq!(
                outbox
                    .invalidate_stale_completion_authority(
                        job_id,
                        Some(&replacement_owner),
                        &ProviderIngestCompletionAuthorityObservationV1::NotChecked,
                        105,
                        cursor(10)
                    )
                    .unwrap(),
                None,
                "already-cleared state must be idempotent"
            );
            assert_eq!(
                outbox.store_completion_transaction(&old_claim, old_transaction),
                Err(ProviderIngestOutboxError::InvalidSigningClaim)
            );
            let replacement_transaction = signed_completion(&authorization, 10, replacement_seed);
            assert_eq!(replacement_transaction.authority(), &replacement_owner);
            outbox
                .claim_completion_signing(
                    job_id,
                    completion_context(&replacement_transaction, 10, cursor(10)),
                    114,
                )
                .expect("replacement owner may sign after bounded backoff");
        }
    }
    #[test]
    fn newer_matching_authority_observation_is_restart_safe_for_unexposed_state() {
        for prepared_state in [
            StoredDeliveryStateV1::Signing,
            StoredDeliveryStateV1::Signed,
        ] {
            let directory = tempdir().expect("tempdir");
            let path = checkpoint_path(&directory);
            let authorization = authorization(
                if prepared_state == StoredDeliveryStateV1::Signing {
                    0x91
                } else {
                    0x92
                },
                7,
            );
            let job_id = authorization.job_id();
            let transaction = signed_completion(&authorization, 8, 8);
            let owner = transaction.authority().clone();
            let mut outbox = ProviderIngestOutbox::open(&path, policy()).expect("outbox");
            enqueue_and_store_local(&outbox, &authorization, 100);
            let claim = claim_for_transaction(&outbox, job_id, &transaction, 8, 102, cursor(8));
            if prepared_state == StoredDeliveryStateV1::Signed {
                outbox
                    .store_completion_transaction(&claim, transaction)
                    .expect("store exact signed completion");
            }
            observe_finalized(&outbox, cursor(9));
            outbox
                .invalidate_stale_completion_authority(
                    job_id,
                    Some(&owner),
                    &ProviderIngestCompletionAuthorityObservationV1::NotChecked,
                    104,
                    cursor(9),
                )
                .expect("record owner-only observation");
            drop(outbox);
            outbox = ProviderIngestOutbox::open(&path, policy())
                .expect("restart after owner-only observation");
            let owner_checked = stored_completion(&outbox, job_id);
            assert_eq!(owner_checked.state, prepared_state);
            assert_eq!(
                owner_checked.finalized_authority_observation,
                Some(StoredFinalizedCompletionAuthorityObservationV1 {
                    cursor: cursor(9),
                    provider_owner: Some(owner.clone()),
                    completion_authority:
                        ProviderIngestCompletionAuthorityObservationV1::NotChecked,
                })
            );
            outbox
                .invalidate_stale_completion_authority(
                    job_id,
                    Some(&owner),
                    &ProviderIngestCompletionAuthorityObservationV1::Active(fixture_authority(
                        &owner,
                        signer_policy(1),
                    )),
                    105,
                    cursor(9),
                )
                .expect("refine exact active policy");
            drop(outbox);
            outbox = ProviderIngestOutbox::open(&path, policy())
                .expect("restart after exact active policy");
            let fully_checked = stored_completion(&outbox, job_id);
            assert_eq!(fully_checked.state, prepared_state);
            assert_eq!(
                fully_checked.finalized_authority_observation,
                Some(StoredFinalizedCompletionAuthorityObservationV1 {
                    cursor: cursor(9),
                    provider_owner: Some(owner.clone()),
                    completion_authority: ProviderIngestCompletionAuthorityObservationV1::Active(
                        fixture_authority(&owner, signer_policy(1))
                    ),
                })
            );
        }
    }
    #[test]
    fn finalized_signer_policy_change_invalidates_only_unexposed_bytes_after_restart() {
        let prepared_states = [
            StoredDeliveryStateV1::Signed,
            StoredDeliveryStateV1::Ambiguous,
            StoredDeliveryStateV1::Submitted,
        ];
        for (index, prepared_state) in prepared_states.into_iter().enumerate() {
            let directory = tempdir().expect("tempdir");
            let path = checkpoint_path(&directory);
            let authorization =
                authorization(0xA0_u8.saturating_add(u8::try_from(index).unwrap()), 7);
            let job_id = authorization.job_id();
            let transaction = signed_completion(&authorization, 8, 8);
            let owner = transaction.authority().clone();
            let mut outbox = ProviderIngestOutbox::open(&path, policy()).expect("outbox");
            enqueue_and_store_local(&outbox, &authorization, 100);
            let claim = claim_for_transaction(&outbox, job_id, &transaction, 8, 102, cursor(8));
            let transaction_hash = outbox
                .store_completion_transaction(&claim, transaction.clone())
                .expect("store signed completion");
            if matches!(
                prepared_state,
                StoredDeliveryStateV1::Ambiguous | StoredDeliveryStateV1::Submitted
            ) {
                begin_submission(&outbox, job_id, transaction_hash, 103).expect("begin submission");
            }
            if prepared_state == StoredDeliveryStateV1::Submitted {
                outbox
                    .mark_completion_submitted(job_id, transaction_hash)
                    .expect("mark submitted");
            }
            assert_eq!(stored_completion(&outbox, job_id).state, prepared_state);
            drop(outbox);
            outbox = ProviderIngestOutbox::open(&path, policy()).expect("restart");
            let restored = stored_completion(&outbox, job_id);
            assert_eq!(restored.state, prepared_state);
            observe_finalized(&outbox, cursor(9));
            assert_eq!(
                outbox
                    .invalidate_stale_completion_authority(
                        job_id,
                        Some(&owner),
                        &ProviderIngestCompletionAuthorityObservationV1::NotChecked,
                        104,
                        cursor(9)
                    )
                    .expect("owner-only reconciliation"),
                None
            );
            assert_eq!(
                outbox
                    .invalidate_stale_completion_authority(
                        job_id,
                        Some(&owner),
                        &ProviderIngestCompletionAuthorityObservationV1::Active(fixture_authority(
                            &owner,
                            signer_policy(1)
                        )),
                        104,
                        cursor(9)
                    )
                    .expect("same signer policy"),
                None
            );
            let before_policy_change = stored_completion(&outbox, job_id);
            let changed_policy = if index == 0 {
                ProviderIngestCompletionAuthorityObservationV1::Missing
            } else {
                ProviderIngestCompletionAuthorityObservationV1::Active(fixture_authority(
                    &owner,
                    signer_policy(2),
                ))
            };
            assert_eq!(
                outbox.invalidate_stale_completion_authority(
                    job_id,
                    Some(&owner),
                    &changed_policy,
                    104,
                    cursor(8)
                ),
                Err(ProviderIngestOutboxError::StaleFinalizedCursor),
                "same-baseline policy substitution must fail closed"
            );
            assert_eq!(stored_completion(&outbox, job_id), before_policy_change);
            assert_eq!(
                outbox.invalidate_stale_completion_authority(
                    job_id,
                    Some(&owner),
                    &changed_policy,
                    104,
                    cursor(9)
                ),
                Err(ProviderIngestOutboxError::FinalizedAuthorityConflict),
                "one finalized cursor cannot equivocate about signer policy"
            );
            assert_eq!(stored_completion(&outbox, job_id), before_policy_change);
            observe_finalized(&outbox, cursor(10));
            let invalidation = outbox
                .invalidate_stale_completion_authority(
                    job_id,
                    Some(&owner),
                    &changed_policy,
                    104,
                    cursor(10),
                )
                .expect("newer signer policy is reconciled");
            if matches!(
                prepared_state,
                StoredDeliveryStateV1::Ambiguous | StoredDeliveryStateV1::Submitted
            ) {
                assert_eq!(invalidation, None);
                let retained = stored_completion(&outbox, job_id);
                assert_eq!(retained.state, prepared_state);
                assert_eq!(
                    retained.signing_context,
                    before_policy_change.signing_context
                );
                assert_eq!(
                    retained.transaction_hash,
                    before_policy_change.transaction_hash
                );
                assert_eq!(
                    retained.signed_transaction,
                    before_policy_change.signed_transaction
                );
                assert!(retained.ever_exposed);
                assert_eq!(retained.authority_owner.as_ref(), Some(&owner));
                assert_eq!(
                    retained.finalized_authority_observation,
                    Some(StoredFinalizedCompletionAuthorityObservationV1 {
                        cursor: cursor(10),
                        provider_owner: Some(owner.clone()),
                        completion_authority: changed_policy.clone(),
                    })
                );
                match &changed_policy {
                    ProviderIngestCompletionAuthorityObservationV1::Missing => {
                        assert_eq!(
                            retained
                                .authority_floor
                                .as_ref()
                                .map(|authority| authority.signer_policy),
                            Some(signer_policy(1))
                        );
                        assert!(retained.authority_successor_required);
                    }
                    ProviderIngestCompletionAuthorityObservationV1::Active(policy) => {
                        assert_eq!(retained.authority_floor.as_ref(), Some(policy));
                        assert!(!retained.authority_successor_required);
                    }
                    ProviderIngestCompletionAuthorityObservationV1::NotChecked => unreachable!(),
                }
                assert_eq!(
                    outbox.store_completion_transaction(&claim, transaction),
                    Err(ProviderIngestOutboxError::InvalidSigningClaim)
                );
                continue;
            }
            assert_eq!(
                invalidation,
                Some(ProviderIngestRetryOutcomeV1::RetryScheduled {
                    attempts: 1,
                    next_attempt_at_ms: 114,
                })
            );
            let cleared = stored_completion(&outbox, job_id);
            assert_eq!(cleared.state, StoredDeliveryStateV1::Ready);
            assert_eq!(cleared.signing_context, None);
            assert_eq!(cleared.transaction_hash, None);
            assert_eq!(cleared.signed_transaction, None);
            assert_eq!(
                cleared.last_failure_class,
                Some(ProviderIngestFailureClassV1::SignerPolicyChanged)
            );
            if changed_policy == ProviderIngestCompletionAuthorityObservationV1::Missing {
                observe_finalized(&outbox, cursor(11));
                let same_policy_transaction = signed_completion(&authorization, 11, 8);
                let same_policy = completion_context(&same_policy_transaction, 11, cursor(11));
                assert_eq!(
                    outbox.claim_completion_signing(job_id, same_policy.clone(), 114),
                    Err(ProviderIngestOutboxError::SignerPolicyRollback),
                    "revocation requires a strict policy successor"
                );
                let successor_policy = signer_policy(2);
                let successor_transaction = signed_completion_with_policy_at(
                    &authorization,
                    11,
                    cursor(11),
                    8,
                    successor_policy,
                );
                let mut strict_successor =
                    completion_context(&successor_transaction, 11, cursor(11));
                strict_successor.expected_authority.signer_policy = successor_policy;
                outbox
                    .claim_completion_signing(job_id, strict_successor, 114)
                    .expect("strict successor may resume after revocation");
            }
            assert_eq!(
                outbox.store_completion_transaction(&claim, transaction),
                Err(ProviderIngestOutboxError::InvalidSigningClaim)
            );
        }
    }
    #[test]
    fn missing_finalized_owner_retains_exposed_states_across_restart() {
        let prepared_states = [
            StoredDeliveryStateV1::Signing,
            StoredDeliveryStateV1::Signed,
            StoredDeliveryStateV1::Ambiguous,
            StoredDeliveryStateV1::Submitted,
        ];
        for (index, prepared_state) in prepared_states.into_iter().enumerate() {
            let directory = tempdir().expect("tempdir");
            let path = checkpoint_path(&directory);
            let mut outbox = ProviderIngestOutbox::open(&path, policy()).expect("outbox");
            let order = 0x90_u8.saturating_add(u8::try_from(index).unwrap());
            let authorization = authorization(order, 7);
            let job_id = authorization.job_id();
            enqueue_and_store_local(&outbox, &authorization, 100);
            let transaction = signed_completion(&authorization, 8, 8);
            let claim = claim_for_transaction(&outbox, job_id, &transaction, 8, 102, cursor(8));
            let transaction_hash = if prepared_state == StoredDeliveryStateV1::Signing {
                None
            } else {
                Some(
                    outbox
                        .store_completion_transaction(&claim, transaction)
                        .unwrap(),
                )
            };
            if matches!(
                prepared_state,
                StoredDeliveryStateV1::Ambiguous | StoredDeliveryStateV1::Submitted
            ) {
                begin_submission(&outbox, job_id, transaction_hash.unwrap(), 103).unwrap();
            }
            if prepared_state == StoredDeliveryStateV1::Submitted {
                outbox
                    .mark_completion_submitted(job_id, transaction_hash.unwrap())
                    .unwrap();
            }
            let prepared = stored_completion(&outbox, job_id);
            assert_eq!(prepared.state, prepared_state);
            assert_eq!(
                outbox.invalidate_stale_completion_authority(
                    job_id,
                    None,
                    &ProviderIngestCompletionAuthorityObservationV1::NotChecked,
                    104,
                    cursor(8)
                ),
                Err(ProviderIngestOutboxError::FinalizedAuthorityConflict),
                "one finalized cursor cannot remove the retained owner for {prepared_state:?}"
            );
            assert_eq!(stored_completion(&outbox, job_id), prepared);
            observe_finalized(&outbox, cursor(9));
            let invalidation = outbox
                .invalidate_stale_completion_authority(
                    job_id,
                    None,
                    &ProviderIngestCompletionAuthorityObservationV1::NotChecked,
                    104,
                    cursor(9),
                )
                .unwrap();
            let reconciled = stored_completion(&outbox, job_id);
            if matches!(
                prepared_state,
                StoredDeliveryStateV1::Ambiguous | StoredDeliveryStateV1::Submitted
            ) {
                assert_eq!(invalidation, None);
                assert_eq!(reconciled.state, prepared_state);
                assert_eq!(reconciled.signing_context, prepared.signing_context);
                assert_eq!(reconciled.transaction_hash, prepared.transaction_hash);
                assert_eq!(reconciled.signed_transaction, prepared.signed_transaction);
                assert!(reconciled.ever_exposed);
            } else {
                assert_eq!(
                    invalidation,
                    Some(ProviderIngestRetryOutcomeV1::RetryScheduled {
                        attempts: 1,
                        next_attempt_at_ms: 114,
                    }),
                    "missing finalized owner must invalidate unexposed {prepared_state:?}"
                );
                assert_eq!(reconciled.state, StoredDeliveryStateV1::Ready);
                assert_eq!(reconciled.attempts, 1);
                assert_eq!(reconciled.baseline_finalized_height, 0);
                assert_eq!(reconciled.baseline_finalized_block_hash, [0; 32]);
                assert_eq!(reconciled.completion_epoch, None);
                assert_eq!(reconciled.signing_context, None);
                assert_eq!(reconciled.transaction_hash, None);
                assert_eq!(reconciled.signed_transaction, None);
                assert_eq!(reconciled.next_attempt_at_ms, 114);
                assert_eq!(
                    reconciled.last_failure_class,
                    Some(ProviderIngestFailureClassV1::ProviderOwnerChanged)
                );
            }
            assert_eq!(reconciled.authority_owner, None);
            assert_eq!(
                reconciled
                    .authority_floor
                    .as_ref()
                    .map(|authority| authority.signer_policy),
                None
            );
            assert!(!reconciled.authority_successor_required);
            assert_eq!(
                reconciled.finalized_authority_observation,
                Some(StoredFinalizedCompletionAuthorityObservationV1 {
                    cursor: cursor(9),
                    provider_owner: None,
                    completion_authority:
                        ProviderIngestCompletionAuthorityObservationV1::NotChecked,
                })
            );
            drop(outbox);
            outbox = ProviderIngestOutbox::open(&path, policy()).expect("restart");
            assert_eq!(
                stored_completion(&outbox, job_id),
                reconciled,
                "authority reconciliation and exact bytes must survive restart"
            );
        }
    }
    #[test]
    fn exposed_expiry_uses_finalized_chain_time_and_preserves_revocation_lineage() {
        let directory = tempdir().expect("tempdir");
        let path = checkpoint_path(&directory);
        let authorization = authorization(0x85, 7);
        let job_id = authorization.job_id();
        let transaction = signed_completion(&authorization, 8, 8);
        let owner = transaction.authority().clone();
        let mut outbox = ProviderIngestOutbox::open(&path, policy()).expect("outbox");
        enqueue_and_store_local(&outbox, &authorization, 100);
        let claim = claim_for_transaction(&outbox, job_id, &transaction, 8, 102, cursor(8));
        let transaction_hash = outbox
            .store_completion_transaction(&claim, transaction)
            .expect("store exact transaction");
        begin_submission(&outbox, job_id, transaction_hash, 103).expect("begin submission");
        outbox
            .mark_completion_submitted(job_id, transaction_hash)
            .expect("mark submitted");
        observe_finalized(&outbox, cursor(9));
        outbox
            .mark_completion_finalized_absent(job_id, transaction_hash, 200, cursor(9))
            .expect("prove finalized absence");
        outbox
            .observe_finalized_snapshot(cursor(10), 20_000)
            .expect("advance below transaction expiry");
        outbox
            .invalidate_stale_completion_authority(
                job_id,
                Some(&owner),
                &ProviderIngestCompletionAuthorityObservationV1::Missing,
                201,
                cursor(10),
            )
            .expect("latch revoked policy");
        let quarantined = stored_completion(&outbox, job_id);
        assert_eq!(quarantined.state, StoredDeliveryStateV1::Signed);
        assert!(quarantined.ever_exposed);
        assert!(quarantined.authority_successor_required);
        drop(outbox);
        outbox = ProviderIngestOutbox::open(&path, policy()).expect("restart");
        assert_eq!(stored_completion(&outbox, job_id), quarantined);
        assert_eq!(
            outbox.expire_absent_exposed_completion(ProviderIngestExposedCompletionExpiryV1 {
                job_id,
                expected_transaction_hash: transaction_hash,
                current_provider_owner: Some(&owner),
                current_authority: &ProviderIngestCompletionAuthorityObservationV1::Missing,
                runtime_now_ms: 1_000_000,
                finalized_block_time_ms: 40_000,
                observed_finalized_cursor: cursor(10),
            }),
            Err(ProviderIngestOutboxError::FinalizedSnapshotConflict)
        );
        assert_eq!(stored_completion(&outbox, job_id), quarantined);
        assert_eq!(
            outbox
                .expire_absent_exposed_completion(ProviderIngestExposedCompletionExpiryV1 {
                    job_id,
                    expected_transaction_hash: transaction_hash,
                    current_provider_owner: Some(&owner),
                    current_authority: &ProviderIngestCompletionAuthorityObservationV1::Missing,
                    runtime_now_ms: 1_000_000,
                    finalized_block_time_ms: 20_000,
                    observed_finalized_cursor: cursor(10),
                })
                .expect("runtime time alone cannot expire"),
            None
        );
        assert_eq!(stored_completion(&outbox, job_id), quarantined);
        outbox
            .observe_finalized_snapshot(cursor(11), 39_000)
            .expect("advance to exact transaction expiry");
        assert_eq!(
            outbox.invalidate_stale_completion_authority(
                job_id,
                Some(&owner),
                &ProviderIngestCompletionAuthorityObservationV1::Active(fixture_authority(
                    &owner,
                    signer_policy(1)
                )),
                202,
                cursor(11)
            ),
            Err(ProviderIngestOutboxError::SignerPolicyRollback)
        );
        outbox
            .invalidate_stale_completion_authority(
                job_id,
                Some(&owner),
                &ProviderIngestCompletionAuthorityObservationV1::Missing,
                202,
                cursor(11),
            )
            .expect("retain revocation at exact expiry");
        assert_eq!(
            outbox
                .expire_absent_exposed_completion(ProviderIngestExposedCompletionExpiryV1 {
                    job_id,
                    expected_transaction_hash: transaction_hash,
                    current_provider_owner: Some(&owner),
                    current_authority: &ProviderIngestCompletionAuthorityObservationV1::Missing,
                    runtime_now_ms: 1_000_000,
                    finalized_block_time_ms: 39_000,
                    observed_finalized_cursor: cursor(11),
                })
                .expect("exact expiry remains live"),
            None
        );
        outbox
            .observe_finalized_snapshot(cursor(12), 39_001)
            .expect("advance beyond transaction expiry");
        outbox
            .invalidate_stale_completion_authority(
                job_id,
                Some(&owner),
                &ProviderIngestCompletionAuthorityObservationV1::Missing,
                203,
                cursor(12),
            )
            .expect("retain revocation beyond expiry");
        assert!(matches!(
            outbox
                .expire_absent_exposed_completion(ProviderIngestExposedCompletionExpiryV1 {
                    job_id,
                    expected_transaction_hash: transaction_hash,
                    current_provider_owner: Some(&owner),
                    current_authority: &ProviderIngestCompletionAuthorityObservationV1::Missing,
                    runtime_now_ms: 500,
                    finalized_block_time_ms: 39_001,
                    observed_finalized_cursor: cursor(12),
                })
                .expect("expire quarantined bytes"),
            Some(ProviderIngestRetryOutcomeV1::RetryScheduled { .. })
        ));
        let expired = stored_completion(&outbox, job_id);
        assert_eq!(expired.state, StoredDeliveryStateV1::Ready);
        assert_eq!(expired.signing_context, None);
        assert_eq!(expired.transaction_hash, None);
        assert_eq!(expired.signed_transaction, None);
        assert_eq!(expired.authority_owner.as_ref(), Some(&owner));
        assert_eq!(
            expired
                .authority_floor
                .as_ref()
                .map(|authority| authority.signer_policy),
            Some(signer_policy(1))
        );
        assert!(expired.authority_successor_required);
        drop(outbox);
        outbox = ProviderIngestOutbox::open(&path, policy()).expect("restart after expiry");
        assert_eq!(stored_completion(&outbox, job_id), expired);
        outbox
            .observe_finalized_snapshot(cursor(13), 40_000)
            .expect("advance after transaction expiry");
        let successor_transaction = signed_completion(&authorization, 13, 8);
        let same_policy = completion_context(&successor_transaction, 13, cursor(13));
        assert_eq!(
            outbox.claim_completion_signing(job_id, same_policy.clone(), 1_000_001),
            Err(ProviderIngestOutboxError::SignerPolicyRollback)
        );
        let successor_policy = signer_policy(2);
        let successor_transaction =
            signed_completion_with_policy_at(&authorization, 13, cursor(13), 8, successor_policy);
        let mut successor = completion_context(&successor_transaction, 13, cursor(13));
        successor.expected_authority.signer_policy = successor_policy;
        outbox
            .claim_completion_signing(job_id, successor, 1_000_001)
            .expect("strict successor resumes after chain-proven expiry");
    }
    #[test]
    fn missing_finalized_owner_dead_letter_is_durable_and_payload_free() {
        let directory = tempdir().expect("tempdir");
        let path = checkpoint_path(&directory);
        let mut one_attempt = policy();
        one_attempt.max_attempts = 1;
        let authorization = authorization(0x84, 7);
        let job_id = authorization.job_id();
        let mut outbox = ProviderIngestOutbox::open(&path, one_attempt).expect("outbox");
        enqueue_and_store_local(&outbox, &authorization, 100);
        let transaction = signed_completion(&authorization, 8, 8);
        let claim = claim_for_transaction(&outbox, job_id, &transaction, 8, 102, cursor(8));
        let _transaction_hash = outbox
            .store_completion_transaction(&claim, transaction)
            .unwrap();
        observe_finalized(&outbox, cursor(9));
        assert_eq!(
            outbox
                .invalidate_stale_completion_authority(
                    job_id,
                    None,
                    &ProviderIngestCompletionAuthorityObservationV1::NotChecked,
                    104,
                    cursor(9)
                )
                .unwrap(),
            Some(ProviderIngestRetryOutcomeV1::DeadLettered)
        );
        assert_eq!(
            outbox.aggregate_counts().unwrap(),
            ProviderIngestOutboxCountsV1 {
                active: 0,
                terminal: 1,
                dead_letters: 1,
            }
        );
        drop(outbox);
        outbox = ProviderIngestOutbox::open(&path, one_attempt).expect("restart");
        assert!(matches!(
            outbox.status(job_id).unwrap().state,
            ProviderIngestDeliveryStateV1::DeadLetter {
                attempts: 1,
                reason: ProviderIngestDeadLetterReasonV1::RetryExhausted,
                last_failure_class: ProviderIngestFailureClassV1::ProviderOwnerChanged,
                observed_finalized_cursor,
            } if observed_finalized_cursor == cursor(9)
        ));
        assert_eq!(
            outbox.aggregate_counts().unwrap(),
            ProviderIngestOutboxCountsV1 {
                active: 0,
                terminal: 1,
                dead_letters: 1,
            }
        );
    }
    #[test]
    fn completion_preparation_preflight_and_signing_recovery_are_bounded() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        let preparation = authorization(0x70, 7);
        enqueue_and_store_local(&outbox, &preparation, 100);
        observe_finalized(&outbox, cursor(8));
        assert_eq!(
            outbox
                .record_completion_preparation_failure(preparation.job_id(), 102, cursor(8),)
                .unwrap(),
            ProviderIngestRetryOutcomeV1::RetryScheduled {
                attempts: 1,
                next_attempt_at_ms: 112,
            }
        );
        assert!(matches!(
            outbox.status(preparation.job_id()).unwrap().state,
            ProviderIngestDeliveryStateV1::LocalStored {
                completion: ProviderIngestCompletionStateV1::Ready {
                    attempts: 1,
                    next_attempt_at_ms: 112,
                    last_failure_class: Some(
                        ProviderIngestFailureClassV1::PayloadPreparationFailed
                    ),
                },
                ..
            }
        ));
        let preflight = authorization(0x71, 7);
        enqueue_and_store_local(&outbox, &preflight, 100);
        let transaction = signed_completion(&preflight, 8, 8);
        let claim =
            claim_for_transaction(&outbox, preflight.job_id(), &transaction, 8, 102, cursor(8));
        let provider_owner = claim.context().expected_authority.provider_owner.clone();
        let signer_policy = claim.context().expected_authority.signer_policy;
        let transaction_hash = outbox
            .store_completion_transaction(&claim, transaction)
            .unwrap();
        let signed = stored_completion(&outbox, preflight.job_id());
        assert_eq!(
            outbox.mark_completion_preflight_rejected(
                preflight.job_id(),
                transaction_hash,
                0,
                cursor(8),
            ),
            Err(ProviderIngestOutboxError::InvalidRuntimeTimestamp)
        );
        assert_eq!(stored_completion(&outbox, preflight.job_id()), signed);
        assert_eq!(
            outbox
                .mark_completion_preflight_unavailable(
                    preflight.job_id(),
                    transaction_hash,
                    103,
                    cursor(8),
                )
                .unwrap(),
            ProviderIngestRetryOutcomeV1::RetryScheduled {
                attempts: 2,
                next_attempt_at_ms: 123,
            }
        );
        assert_eq!(
            outbox.completion_transaction_for_authorized_preflight(
                preflight.job_id(),
                &provider_owner,
                &fixture_authority(&provider_owner, signer_policy),
                cursor(8),
                122
            ),
            Err(ProviderIngestOutboxError::RetryNotDue)
        );
        outbox
            .completion_transaction_for_authorized_preflight(
                preflight.job_id(),
                &provider_owner,
                &fixture_authority(&provider_owner, signer_policy),
                cursor(8),
                123,
            )
            .expect("preflight becomes available exactly when due");
        let interrupted = authorization(0x72, 7);
        enqueue_and_store_local(&outbox, &interrupted, 100);
        let transaction = signed_completion(&interrupted, 8, 8);
        let stale_claim = claim_for_transaction(
            &outbox,
            interrupted.job_id(),
            &transaction,
            8,
            102,
            cursor(8),
        );
        assert_eq!(
            outbox
                .recover_expired_completion_signing(121, cursor(8))
                .unwrap(),
            0
        );
        assert_eq!(
            outbox
                .recover_expired_completion_signing(122, cursor(8))
                .unwrap(),
            1
        );
        assert!(matches!(
            outbox.status(interrupted.job_id()).unwrap().state,
            ProviderIngestDeliveryStateV1::LocalStored {
                completion: ProviderIngestCompletionStateV1::Ready {
                    attempts: 1,
                    next_attempt_at_ms: 132,
                    last_failure_class: Some(ProviderIngestFailureClassV1::SignerUnavailable),
                },
                ..
            }
        ));
        assert_eq!(
            outbox.store_completion_transaction(&stale_claim, transaction),
            Err(ProviderIngestOutboxError::InvalidSigningClaim)
        );
    }
    #[test]
    fn finalized_completion_inserts_an_absent_terminal_without_active_capacity() {
        let mut bounded = policy();
        bounded.max_active_entries = 1;
        let outbox = ProviderIngestOutbox::in_memory(bounded).expect("outbox");
        let active = authorization(0x73, 7);
        outbox.enqueue(active).expect("fill active capacity");
        let completed = authorization(0x74, 7);
        let before_reconciliation = outbox.state.lock().unwrap().checkpoint.clone();
        assert_eq!(
            outbox.reconcile_finalized_completion(
                completed.clone(),
                finalized_evidence(&completed, 8, None, 8),
            ),
            Err(ProviderIngestOutboxError::StaleFinalizedCursor)
        );
        assert_eq!(
            outbox.state.lock().unwrap().checkpoint,
            before_reconciliation
        );
        assert_eq!(
            outbox.status(completed.job_id()),
            Err(ProviderIngestOutboxError::UnknownJob)
        );
        observe_finalized(&outbox, cursor(8));
        outbox
            .reconcile_finalized_completion(
                completed.clone(),
                finalized_evidence(&completed, 8, None, 8),
            )
            .expect("direct finalized tombstone");
        assert!(matches!(
            outbox.status(completed.job_id()).unwrap().state,
            ProviderIngestDeliveryStateV1::FinalizedCompleted {
                manifest_id: None,
                completion_epoch: 8,
                ..
            }
        ));
        assert_eq!(outbox.state.lock().unwrap().checkpoint.active.len(), 1);
        observe_finalized(&outbox, cursor(9));
        let finalized = outbox.state.lock().unwrap().checkpoint.clone();
        assert_eq!(
            outbox.reconcile_finalized_completion(
                completed.clone(),
                finalized_evidence(&completed, 8, None, 8),
            ),
            Err(ProviderIngestOutboxError::StaleFinalizedCursor)
        );
        assert_eq!(outbox.state.lock().unwrap().checkpoint, finalized);
    }
    #[test]
    fn finalized_cancellation_inserts_absent_and_supersedes_dead_letter() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        let absent = authorization(0x75, 7);
        let before_reconciliation = outbox.state.lock().unwrap().checkpoint.clone();
        assert_eq!(
            outbox.reconcile_finalized_cancellation(
                absent.clone(),
                cancellation_evidence(
                    &absent,
                    ProviderIngestCancellationReasonV1::OrderExpired,
                    8,
                ),
            ),
            Err(ProviderIngestOutboxError::StaleFinalizedCursor)
        );
        assert_eq!(
            outbox.state.lock().unwrap().checkpoint,
            before_reconciliation
        );
        assert_eq!(
            outbox.status(absent.job_id()),
            Err(ProviderIngestOutboxError::UnknownJob)
        );
        observe_finalized(&outbox, cursor(8));
        outbox
            .reconcile_finalized_cancellation(
                absent.clone(),
                cancellation_evidence(&absent, ProviderIngestCancellationReasonV1::OrderExpired, 8),
            )
            .expect("absent cancellation tombstone");
        assert!(matches!(
            outbox.status(absent.job_id()).unwrap().state,
            ProviderIngestDeliveryStateV1::Cancelled {
                reason: ProviderIngestCancellationReasonV1::OrderExpired,
                ..
            }
        ));
        let dead = authorization(0x76, 7);
        outbox.enqueue(dead.clone()).unwrap();
        let claim = outbox
            .claim_source(dead.job_id(), owner(4), 100, cursor(8))
            .unwrap();
        outbox
            .dead_letter_source(
                &claim,
                101,
                cursor(8),
                ProviderIngestDeadLetterReasonV1::BindingMismatch,
                ProviderIngestFailureClassV1::BindingMismatch,
            )
            .unwrap();
        observe_finalized(&outbox, cursor(9));
        outbox
            .reconcile_finalized_cancellation(
                dead.clone(),
                cancellation_evidence(
                    &dead,
                    ProviderIngestCancellationReasonV1::ManifestRetired,
                    9,
                ),
            )
            .expect("newer finalized cancellation overrides local failure");
        assert!(matches!(
            outbox.status(dead.job_id()).unwrap().state,
            ProviderIngestDeliveryStateV1::Cancelled {
                reason: ProviderIngestCancellationReasonV1::ManifestRetired,
                observed_finalized_cursor,
            } if observed_finalized_cursor == cursor(9)
        ));
    }
    #[test]
    fn semantic_finalization_accepts_other_replica_and_overrides_terminal_tombstones() {
        let mut roomy = policy();
        roomy.max_terminal_entries = 16;
        let outbox = ProviderIngestOutbox::in_memory(roomy).expect("outbox");
        let pending = authorization(0x67, 7);
        outbox.enqueue(pending.clone()).unwrap();
        observe_finalized(&outbox, cursor(8));
        outbox
            .mark_finalized_complete(pending.job_id(), finalized_evidence(&pending, 8, None, 8))
            .expect("semantic completion needs no local bytes");
        assert!(matches!(
            outbox.status(pending.job_id()).unwrap().state,
            ProviderIngestDeliveryStateV1::FinalizedCompleted {
                manifest_id: None,
                committed_transaction_hash: None,
                ..
            }
        ));
        let signed = authorization(0x68, 7);
        enqueue_and_store_local(&outbox, &signed, 100);
        let transaction = signed_completion(&signed, 8, 8);
        let claim =
            claim_for_transaction(&outbox, signed.job_id(), &transaction, 8, 102, cursor(8));
        let local_hash = outbox
            .store_completion_transaction(&claim, transaction)
            .unwrap();
        let other_hash = [0xAB; 32];
        assert_ne!(local_hash, other_hash);
        observe_finalized(&outbox, cursor(9));
        outbox
            .mark_finalized_complete(
                signed.job_id(),
                finalized_evidence(&signed, 9, Some(other_hash), 9),
            )
            .expect("another replica may commit the same semantic completion");
        assert!(matches!(
            outbox.status(signed.job_id()).unwrap().state,
            ProviderIngestDeliveryStateV1::FinalizedCompleted {
                manifest_id: Some(_),
                completion_epoch: 9,
                committed_transaction_hash: Some(hash),
                ..
            } if hash == other_hash
        ));
        let signing = authorization(0x6C, 7);
        enqueue_and_store_local(&outbox, &signing, 120);
        let transaction = signed_completion_at(&signing, 8, cursor(9), 8);
        let signing_claim =
            claim_for_transaction(&outbox, signing.job_id(), &transaction, 8, 122, cursor(9));
        observe_finalized(&outbox, cursor(10));
        outbox
            .mark_finalized_complete(signing.job_id(), finalized_evidence(&signing, 9, None, 10))
            .expect("semantic completion safely supersedes signer-only state");
        assert_eq!(
            outbox.store_completion_transaction(&signing_claim, transaction),
            Err(ProviderIngestOutboxError::UnknownJob)
        );
        let cancelled = authorization(0x69, 7);
        outbox.enqueue(cancelled.clone()).unwrap();
        outbox
            .cancel(
                cancelled.job_id(),
                cancellation_evidence(
                    &cancelled,
                    ProviderIngestCancellationReasonV1::OrderExpired,
                    10,
                ),
            )
            .unwrap();
        observe_finalized(&outbox, cursor(11));
        outbox
            .mark_finalized_complete(
                cancelled.job_id(),
                finalized_evidence(&cancelled, 9, None, 11),
            )
            .expect("later semantic success supersedes cancellation");
        let dead = authorization(0x6A, 7);
        outbox.enqueue(dead.clone()).unwrap();
        let claim = outbox
            .claim_source(dead.job_id(), owner(3), 200, cursor(11))
            .unwrap();
        outbox
            .dead_letter_source(
                &claim,
                201,
                cursor(11),
                ProviderIngestDeadLetterReasonV1::BindingMismatch,
                ProviderIngestFailureClassV1::BindingMismatch,
            )
            .unwrap();
        observe_finalized(&outbox, cursor(12));
        let evidence = finalized_evidence(&dead, 9, None, 12);
        outbox
            .mark_finalized_complete(dead.job_id(), evidence.clone())
            .expect("later semantic success supersedes dead letter");
        outbox
            .mark_finalized_complete(dead.job_id(), evidence)
            .expect("semantic replay is idempotent");
    }
    #[test]
    fn typed_cancellation_rejects_substituted_binding_and_stale_cursor() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        let authorization = authorization(0x6B, 7);
        outbox.enqueue(authorization.clone()).unwrap();
        let before_cancellation = outbox.state.lock().unwrap().checkpoint.clone();
        assert_eq!(
            outbox.cancel(
                authorization.job_id(),
                cancellation_evidence(
                    &authorization,
                    ProviderIngestCancellationReasonV1::ManifestRetired,
                    8,
                ),
            ),
            Err(ProviderIngestOutboxError::StaleFinalizedCursor)
        );
        assert_eq!(outbox.state.lock().unwrap().checkpoint, before_cancellation);
        observe_finalized(&outbox, cursor(8));
        let mut wrong_provider = cancellation_evidence(
            &authorization,
            ProviderIngestCancellationReasonV1::ManifestRetired,
            8,
        );
        wrong_provider.provider_id = [0x99; 32];
        assert_eq!(
            outbox.cancel(authorization.job_id(), wrong_provider),
            Err(ProviderIngestOutboxError::InvalidCancellationEvidence)
        );
        let stale = cancellation_evidence(
            &authorization,
            ProviderIngestCancellationReasonV1::ManifestRetired,
            6,
        );
        assert_eq!(
            outbox.cancel(authorization.job_id(), stale),
            Err(ProviderIngestOutboxError::StaleFinalizedCursor)
        );
        let evidence = cancellation_evidence(
            &authorization,
            ProviderIngestCancellationReasonV1::ManifestRetired,
            8,
        );
        outbox
            .cancel(authorization.job_id(), evidence.clone())
            .unwrap();
        outbox
            .cancel(authorization.job_id(), evidence.clone())
            .expect("matching cancellation replay is idempotent");
        observe_finalized(&outbox, cursor(9));
        let cancelled = outbox.state.lock().unwrap().checkpoint.clone();
        assert_eq!(
            outbox.cancel(authorization.job_id(), evidence),
            Err(ProviderIngestOutboxError::StaleFinalizedCursor)
        );
        assert_eq!(outbox.state.lock().unwrap().checkpoint, cancelled);
    }
    #[test]
    fn canonical_manifest_digest_type_matches_status_binding() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).expect("outbox");
        let authorization = authorization(0x5C, 7);
        outbox.enqueue(authorization.clone()).unwrap();
        let status = outbox.status(authorization.job_id()).unwrap();
        assert_eq!(
            ManifestDigest::new(status.manifest_digest),
            ManifestDigest::new(authorization.manifest_digest())
        );
    }
    // These are outbox component controls over actual signed envelopes. The authorization/cursor
    // fixture is the existing test owner; these tests do not claim native State execution.
    fn distinct_completion(
        authorization: &FinalizedProviderIngestAuthorizationV1,
        authority: &ProviderIngestCompletionAuthorityV1,
        signer_seed: u8,
        anchor: ProviderIngestFinalizedCursorV1,
    ) -> (SignedTransaction, ProviderIngestCompletionSigningContextV1) {
        let key = KeyPair::try_from_seed(vec![signer_seed; 32], Algorithm::Ed25519).unwrap();
        let mut builder = TransactionBuilder::new(
            test_network_id(),
            AccountId::new(key.public_key().clone()),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([InstructionBox::from(CompleteReplicationOrder {
            order_id: ReplicationOrderId::new(authorization.order_id()),
            provider_id: ProviderId::new(authorization.provider_id()),
            completion_epoch: 8,
            expected_authority: authority.clone(),
            expected_assignment_revision: 1,
            finalized_anchor: ProviderIngestFinalizedAnchorV1 {
                height: anchor.height,
                block_hash: anchor.block_hash,
            },
        })]);
        builder.set_creation_time(Duration::from_secs(9));
        builder.set_ttl(Duration::from_secs(30));
        let transaction = builder.try_sign(key.private_key()).unwrap();
        let context = ProviderIngestCompletionSigningContextV1 {
            baseline_finalized_cursor: anchor,
            network_id: test_network_id(),
            expected_authority: authority.clone(),
            assignment_revision: 1,
            completion_epoch: 8,
            expected_payload: transaction.payload().clone(),
        };
        (transaction, context)
    }

    #[test]
    fn dedicated_completion_key_survives_reopen_without_becoming_provider_owner() {
        let directory = tempdir().unwrap();
        let path = checkpoint_path(&directory);
        let outbox = ProviderIngestOutbox::open(&path, policy()).unwrap();
        let authorization = authorization(0xE1, 7);
        let job = authorization.job_id();
        enqueue_and_store_local(&outbox, &authorization, 100);
        observe_finalized(&outbox, cursor(8));
        let authority = ProviderIngestCompletionAuthorityV1::new(
            completed_by(9),
            completed_by(8),
            signer_policy(1),
        );
        let (_, wrong_context) = distinct_completion(&authorization, &authority, 9, cursor(8));
        assert_eq!(
            outbox.claim_completion_signing(job, wrong_context, 102),
            Err(ProviderIngestOutboxError::InvalidSigningContext)
        );
        let (transaction, context) = distinct_completion(&authorization, &authority, 8, cursor(8));
        let claim = outbox.claim_completion_signing(job, context, 102).unwrap();
        let wire = norito::to_bytes(&transaction).unwrap();
        let hash = outbox
            .store_completion_transaction(&claim, transaction)
            .unwrap();
        drop(outbox);
        let reopened = ProviderIngestOutbox::open(&path, policy()).unwrap();
        let submission = reopened
            .completion_transaction_for_authorized_preflight(
                job,
                &authority.provider_owner,
                &authority,
                cursor(8),
                103,
            )
            .unwrap();
        assert_eq!(submission.transaction_hash, hash);
        assert_eq!(
            submission.signed_transaction.authority(),
            &authority.completion_signer
        );
        assert_ne!(
            submission.signed_transaction.authority(),
            &authority.provider_owner
        );
        assert_eq!(
            norito::to_bytes(&submission.signed_transaction).unwrap(),
            wire
        );
        assert_eq!(
            stored_completion(&reopened, job).authority_floor.as_ref(),
            Some(&authority)
        );
        let mut same_policy_other_key = authority.clone();
        same_policy_other_key.completion_signer = completed_by(10);
        assert!(
            reopened
                .completion_transaction_for_authorized_preflight(
                    job,
                    &authority.provider_owner,
                    &same_policy_other_key,
                    cursor(8),
                    103,
                )
                .is_err()
        );
        assert_eq!(
            stored_completion(&reopened, job).transaction_hash,
            Some(hash)
        );
    }

    #[test]
    fn full_authority_floor_rejects_same_policy_key_swap_and_same_cut_conflict() {
        let outbox = ProviderIngestOutbox::in_memory(policy()).unwrap();
        let authorization = authorization(0xE2, 7);
        let job = authorization.job_id();
        enqueue_and_store_local(&outbox, &authorization, 100);
        observe_finalized(&outbox, cursor(8));
        let original = ProviderIngestCompletionAuthorityV1::new(
            completed_by(9),
            completed_by(8),
            signer_policy(1),
        );
        outbox
            .validate_ready_completion_authority(
                job,
                &original.provider_owner,
                &original,
                cursor(8),
            )
            .unwrap();
        let before = outbox.state.lock().unwrap().checkpoint.clone();
        let mut changed = original.clone();
        changed.completion_signer = completed_by(10);
        assert_eq!(
            outbox.validate_ready_completion_authority(
                job,
                &original.provider_owner,
                &changed,
                cursor(8)
            ),
            Err(ProviderIngestOutboxError::SignerPolicyRollback)
        );
        assert_eq!(outbox.state.lock().unwrap().checkpoint, before);
        let mut observation = stored_completion(&outbox, job);
        assert_eq!(
            observe_finalized_completion_authority(
                &mut observation,
                Some(&original.provider_owner),
                &ProviderIngestCompletionAuthorityObservationV1::Active(changed.clone()),
                cursor(8)
            ),
            Err(ProviderIngestOutboxError::FinalizedAuthorityConflict)
        );
        observe_finalized(&outbox, cursor(9));
        assert_eq!(
            outbox.validate_ready_completion_authority(
                job,
                &original.provider_owner,
                &changed,
                cursor(9)
            ),
            Err(ProviderIngestOutboxError::SignerPolicyRollback)
        );
        changed.signer_policy = signer_policy(2);
        outbox
            .validate_ready_completion_authority(job, &original.provider_owner, &changed, cursor(9))
            .expect("new key requires the genuine next policy binding");
        assert_eq!(
            stored_completion(&outbox, job).authority_floor.as_ref(),
            Some(&changed)
        );
    }

    #[test]
    fn dedicated_key_rotation_keeps_exposed_original_bytes_for_reconciliation() {
        let directory = tempdir().unwrap();
        let path = checkpoint_path(&directory);
        let outbox = ProviderIngestOutbox::open(&path, policy()).unwrap();
        let authorization = authorization(0xE3, 7);
        let job = authorization.job_id();
        enqueue_and_store_local(&outbox, &authorization, 100);
        observe_finalized(&outbox, cursor(8));
        let original = ProviderIngestCompletionAuthorityV1::new(
            completed_by(9),
            completed_by(8),
            signer_policy(1),
        );
        let (transaction, context) = distinct_completion(&authorization, &original, 8, cursor(8));
        let wire = norito::to_bytes(&transaction).unwrap();
        let claim = outbox.claim_completion_signing(job, context, 102).unwrap();
        let hash = outbox
            .store_completion_transaction(&claim, transaction)
            .unwrap();
        begin_submission(&outbox, job, hash, 103).unwrap();
        observe_finalized(&outbox, cursor(9));
        let rotated = ProviderIngestCompletionAuthorityV1::new(
            original.provider_owner.clone(),
            completed_by(10),
            signer_policy(2),
        );
        assert_eq!(
            outbox
                .invalidate_stale_completion_authority(
                    job,
                    Some(&original.provider_owner),
                    &ProviderIngestCompletionAuthorityObservationV1::Active(rotated.clone()),
                    104,
                    cursor(9)
                )
                .unwrap(),
            None
        );
        drop(outbox);
        let reopened = ProviderIngestOutbox::open(&path, policy()).unwrap();
        let retained = stored_completion(&reopened, job);
        assert_eq!(retained.state, StoredDeliveryStateV1::Ambiguous);
        assert!(retained.ever_exposed);
        assert_eq!(retained.transaction_hash, Some(hash));
        assert_eq!(
            norito::to_bytes(retained.signed_transaction.as_ref().unwrap()).unwrap(),
            wire
        );
        assert_eq!(
            retained
                .signing_context
                .as_ref()
                .unwrap()
                .expected_authority,
            original
        );
        assert_eq!(retained.authority_floor.as_ref(), Some(&rotated));
        assert!(
            reopened
                .completion_transaction_for_authorized_preflight(
                    job,
                    &rotated.provider_owner,
                    &rotated,
                    cursor(9),
                    105
                )
                .is_err()
        );
    }
}
