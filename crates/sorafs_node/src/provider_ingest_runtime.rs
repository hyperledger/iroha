//! Supervised finalized-ledger runtime for provider replication ingest.
//!
//! The runtime deliberately owns no authoritative order, completion, or
//! provider-registration state. Every scan reads one immutable finalized view,
//! drives the durable [`ProviderIngestOutbox`], and reconciles semantic ledger
//! completion before considering transaction-level delivery state.
use crate::provider_ingest_outbox::{
    FinalizedProviderIngestAuthorizationV1, FinalizedProviderIngestMusubiContextV1,
    PROVIDER_INGEST_STATUS_PAGE_MAX_V1, ProviderIngestCancellationReasonV1,
    ProviderIngestClaimOwnerV1, ProviderIngestCompletionAuthorityObservationV1,
    ProviderIngestCompletionSigningContextV1, ProviderIngestCompletionStateV1,
    ProviderIngestDeadLetterReasonV1, ProviderIngestDeliveryStateV1,
    ProviderIngestExposedCompletionExpiryV1, ProviderIngestFailureClassV1,
    ProviderIngestFinalizedCancellationV1, ProviderIngestFinalizedCompletionV1,
    ProviderIngestFinalizedCursorV1, ProviderIngestOutbox, ProviderIngestOutboxError,
    ProviderIngestSourceClaimV1,
};
use crate::store::AdmittedPayloadReadLeaseV1;
use iroha_config::parameters::is_production_runtime_handle;
use iroha_crypto::Signature as IrohaSignature;
use iroha_crypto::{Algorithm, PublicKey};
use iroha_data_model::musubi::MUSUBI_REGISTRY_VERSION_V1;
use iroha_data_model::musubi::MusubiArtifactDescriptorV1;
use iroha_data_model::musubi::MusubiContentDigestV1;
use iroha_data_model::musubi::MusubiProviderBundleVerificationBindingV1;
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    musubi::{
        ArchiveId, MusubiArchiveCommitmentV1, MusubiProviderBundleVerificationPayloadV1,
        MusubiReplicationOrderArchiveBindingV1, MusubiSemanticReleaseDigestV1,
        MusubiVerificationLockDigestV1,
    },
    sorafs::{
        capacity::ProviderId,
        pin_registry::{
            PinManifestFinalizedRecordV1, PinManifestRecord, PinStatus,
            ProviderIngestCompletionAuthorityV1, ProviderIngestCompletionSignerPolicyV1,
            ReplicationOrderCompletionRecord, ReplicationOrderRecord, ReplicationOrderStatus,
            derive_sorafs_auto_replication_order_id_v1,
        },
    },
    transaction::{SignedTransaction, TransactionPayload},
};
use norito::codec::Encode as _;
use norito::{
    core::DecodeLimits,
    decode_canonical_with_limits,
    derive::{NoritoDeserialize, NoritoSerialize},
};
use sorafs_car::CarBuildPlan;
use sorafs_car::compute_chunk_plan_digest_sha3;
use sorafs_car::musubi::MusubiBundleVerifierV1;
use sorafs_car::musubi::VerifiedMusubiBundleV1;
use sorafs_manifest::capacity::{
    MAX_CAPACITY_METADATA_VALUE_BYTES, MAX_REPLICATION_ORDER_ASSIGNMENTS, ReplicationOrderV1,
};
use std::cell::Cell;
use std::io;
use std::io::Read;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::sync::watch;
const REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1: usize = 256 * 1024;
const PROVIDER_INGEST_SOURCE_QUALIFICATION_VERSION_V1: u8 = 1;
const PROVIDER_INGEST_COMPLETION_SIGNER_QUALIFICATION_VERSION_V1: u8 = 1;
const PROVIDER_INGEST_COMPLETED_MUSUBI_CAPTURE_TRANSCRIPT_VERSION_V1: u8 = 1;
const PROVIDER_INGEST_COMPLETED_MUSUBI_CAPTURE_SESSION_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.provider-ingest.completed-musubi-capture-session.v1\0";
const PROVIDER_INGEST_COMPLETED_MUSUBI_CAPTURE_TRANSCRIPT_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.provider-ingest.completed-musubi-capture-transcript.v1\0";
const PROVIDER_INGEST_COMPLETED_MUSUBI_CAPTURE_TRANSCRIPT_MAX_CANONICAL_BYTES_V1: usize =
    16 * 1024 * 1024;
const PROVIDER_INGEST_COMPLETED_MUSUBI_CAPTURE_ROW_MAX_CANONICAL_BYTES_V1: usize = 512 * 1024;
const PROVIDER_INGEST_MUSUBI_COMPLETION_CLAIM_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.sorafs.provider-ingest.musubi-completion-claim.v1\0";
const MUSUBI_ARTIFACT_DESCRIPTOR_DIGEST_DOMAIN_V1: &[u8] = b"musubi-artifact-descriptor-v1\0";
/// Maximum canonical bytes for one persisted pre-completion Musubi verification receipt.
pub const PROVIDER_INGEST_VERIFIED_MUSUBI_RECEIPT_MAX_CANONICAL_BYTES_V1: usize = 8 * 1024;
const REPLICATION_ORDER_DECODE_LIMITS_V1: DecodeLimits = DecodeLimits::new(
    MAX_CAPACITY_METADATA_VALUE_BYTES,
    REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1,
    131_072,
    REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1 * 4,
    32,
);
/// Boxed asynchronous operation used by provider-ingest integration traits.
pub type ProviderIngestFutureV1<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
/// Resource and timeout policy for one provider-ingest runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderIngestRuntimePolicyV1 {
    /// Maximum finalized assignment rows requested in one page.
    pub max_page_rows: usize,
    /// Maximum finalized pages reconciled in one tick.
    pub max_pages_per_tick: usize,
    /// Maximum source jobs performed in one tick.
    pub max_source_jobs_per_tick: usize,
    /// Maximum governed source provider identities passed to one fetch.
    pub max_source_providers: usize,
    /// Delay between supervised scans.
    pub scan_interval_ms: u64,
    /// Timeout for source verification and fetch, and soft deadline for a
    /// mutating storage operation that must finish under its durable lease.
    pub source_operation_timeout_ms: u64,
    /// Interval used to durably renew a source lease during slow I/O.
    pub source_lease_renew_interval_ms: u64,
    /// Timeout for payload construction, signer resolution, and signing.
    pub signer_timeout_ms: u64,
    /// Timeout for queue preflight, exposure, and transaction observation.
    pub ingress_timeout_ms: u64,
}
impl Default for ProviderIngestRuntimePolicyV1 {
    fn default() -> Self {
        Self {
            max_page_rows: 256,
            max_pages_per_tick: 16,
            max_source_jobs_per_tick: 16,
            max_source_providers: MAX_REPLICATION_ORDER_ASSIGNMENTS,
            scan_interval_ms: 1_000,
            source_operation_timeout_ms: 5 * 60_000,
            source_lease_renew_interval_ms: 15_000,
            signer_timeout_ms: 30_000,
            ingress_timeout_ms: 30_000,
        }
    }
}
impl ProviderIngestRuntimePolicyV1 {
    fn validate(self, outbox: &ProviderIngestOutbox) -> Result<(), ProviderIngestRuntimeErrorV1> {
        if self.max_page_rows == 0
            || self.max_page_rows > PROVIDER_INGEST_STATUS_PAGE_MAX_V1
            || self.max_pages_per_tick == 0
            || self.max_source_jobs_per_tick == 0
            || self.max_source_providers == 0
            || self.max_source_providers > MAX_REPLICATION_ORDER_ASSIGNMENTS
            || self.scan_interval_ms == 0
            || self.source_operation_timeout_ms == 0
            || self.source_lease_renew_interval_ms == 0
            || self.source_lease_renew_interval_ms >= outbox.policy().source_lease_ttl_ms
            || self.signer_timeout_ms == 0
            || self.ingress_timeout_ms == 0
            || self
                .max_page_rows
                .checked_mul(self.max_pages_per_tick)
                .is_none()
        {
            return Err(ProviderIngestRuntimeErrorV1::InvalidPolicy);
        }
        Ok(())
    }
}
/// One assignment row read from a single immutable finalized state view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestFinalizedAssignmentV1 {
    /// Chain-authoritative pin manifest and its finalized cursor.
    pub pin: PinManifestFinalizedRecordV1,
    /// Chain-authoritative replication order.
    pub order: ReplicationOrderRecord,
    /// Reader-authenticated Musubi archive claim, absent for generic non-Musubi replication orders.
    pub musubi_archive: Option<ProviderIngestFinalizedMusubiArchiveClaimV1>,
    /// Reader-authenticated Musubi archive and this provider's exact finalized
    /// completion, absent until the local provider completion is committed.
    pub completed_musubi_archive: Option<ProviderIngestFinalizedMusubiCompletionClaimV1>,
    /// Current registered owner of this runtime's provider identity.
    pub provider_owner: Option<AccountId>,
    /// Exact current native provider owner, completion signer and policy.
    pub completion_authority: Option<ProviderIngestCompletionAuthorityV1>,
    /// Current authoritative epoch to use for a new completion transaction.
    pub completion_epoch: Option<u64>,
    /// Exact committed transaction hash, when the finalized reader exposes it.
    pub committed_transaction_hash: Option<[u8; 32]>,
}
/// Opaque consensus-authenticated Musubi archive binding emitted only by a finalized-ledger reader.
///
/// The private representation deliberately prevents publisher request DTOs from being reinterpreted
/// as finalized evidence. A reader can create this value only while servicing a runtime-issued
/// [`ProviderIngestFinalizedClaimFactoryV1`].
///
/// This pre-completion claim binds the exact genesis-derived network identity and the exact
/// finalized archive cursor. The source and storage path may use it only to fetch and semantically
/// verify the bundle before replication completion. It contains no post-completion finalized row
/// and therefore cannot authorize a Musubi provider attestation.
///
/// ```compile_fail
/// use sorafs_node::ProviderIngestFinalizedMusubiArchiveClaimV1;
///
/// let _forged = ProviderIngestFinalizedMusubiArchiveClaimV1 {
///     binding: unreachable!("private field"),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestFinalizedMusubiArchiveClaimV1 {
    network_id: NetworkId,
    provider_id: [u8; 32],
    observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    binding: MusubiReplicationOrderArchiveBindingV1,
}
impl ProviderIngestFinalizedMusubiArchiveClaimV1 {
    /// Exact configured deployment identity authenticated by the runtime boundary.
    #[must_use]
    pub const fn network_id(&self) -> &NetworkId {
        &self.network_id
    }
    /// Local provider identity for which the finalized assignment was read.
    #[must_use]
    pub const fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }
    /// Exact finalized archive cursor at which this binding was observed.
    #[must_use]
    pub const fn observed_finalized_cursor(&self) -> ProviderIngestFinalizedCursorV1 {
        self.observed_finalized_cursor
    }
    /// Exact replication order authenticated by the finalized reader.
    #[must_use]
    pub const fn replication_order(&self) -> [u8; 32] {
        *self.binding.replication_order.as_bytes()
    }
    /// Exact derived archive identity authenticated by the finalized reader.
    #[must_use]
    pub const fn archive_id(&self) -> ArchiveId {
        self.binding.archive_id
    }
    /// Complete immutable archive commitment authenticated by the finalized reader.
    #[must_use]
    pub const fn commitment(&self) -> &MusubiArchiveCommitmentV1 {
        &self.binding.commitment
    }
    /// Check every field shared with one finalized local-ingest authorization.
    #[must_use]
    pub fn matches_authorization(
        &self,
        authorization: &FinalizedProviderIngestAuthorizationV1,
    ) -> bool {
        let commitment = self.commitment();
        authorization.validate().is_ok()
            && self.network_id.as_bytes()[31] & 1 == 1
            && self.provider_id == authorization.provider_id()
            && authorization_musubi_context_matches(
                authorization,
                &self.network_id,
                self.archive_id(),
            )
            && finalized_cursor_is_same_or_later(
                self.observed_finalized_cursor,
                authorization.admission_finalized_cursor(),
            )
            && self.replication_order() == authorization.order_id()
            && self.archive_id() == commitment.archive_id()
            && commitment.validate().is_ok()
            && commitment.root_cid.as_bytes() == authorization.manifest_cid()
            && commitment.chunker.to_handle() == authorization.chunker_handle()
            && commitment.chunk_plan_digest.as_bytes() == &authorization.chunk_digest_sha3_256()
            && commitment.por_root.as_bytes() == &authorization.por_root()
            && commitment.content_length == authorization.content_length()
    }
}
/// Process-local identity of the exact storage/outbox instance allowed to
/// derive completed-Musubi attestation work.
///
/// Instance matching uses pointer identity. The marker deliberately has no stable bytes, hash,
/// codec, or public constructor: it is an in-process authority fence, not part of any persistent
/// claim, approval ID, or wire transcript.
#[derive(Clone)]
pub(crate) struct CompletedMusubiStoreInstanceV1(Arc<CompletedMusubiStoreInstanceInnerV1>);
struct CompletedMusubiStoreInstanceInnerV1 {
    _non_zst: u8,
    capture_coordinator_taken: AtomicBool,
}
impl CompletedMusubiStoreInstanceV1 {
    pub(crate) fn new() -> Self {
        Self(Arc::new(CompletedMusubiStoreInstanceInnerV1 {
            _non_zst: 0,
            capture_coordinator_taken: AtomicBool::new(false),
        }))
    }
    pub(crate) fn matches(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    /// Reserve the one completed-Musubi capture coordinator allowed for this
    /// exact storage/outbox instance.
    ///
    /// The reservation is deliberately non-resetting. Dropping a coordinator, failing its lazy
    /// reader binding, or cloning the surrounding [`crate::NodeHandle`] can never reopen reader
    /// selection for the same process-local store incarnation.
    pub(crate) fn try_take_capture_coordinator(&self) -> bool {
        self.0
            .capture_coordinator_taken
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}
impl fmt::Debug for CompletedMusubiStoreInstanceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<completed-musubi-store-instance>")
    }
}
/// Opaque consensus-authenticated Musubi claim sealed only from this provider's
/// finalized completion row.
///
/// This value is intentionally distinct from [`ProviderIngestFinalizedMusubiArchiveClaimV1`]. The
/// pre-completion claim can authorize fetching and semantic verification before storage completion,
/// but only this completed-row capability may enter the later provider-attestation path. It has no
/// public constructor or serialization implementation. Equality compares finalized semantic
/// evidence only; the private process-local authority marker is checked separately and is never an
/// equality capability.
///
/// ```compile_fail
/// use sorafs_node::provider_ingest_runtime::ProviderIngestFinalizedMusubiCompletionClaimV1;
///
/// let _forged = ProviderIngestFinalizedMusubiCompletionClaimV1 {
///     network_id: unreachable!("private field"),
///     provider_id: [0; 32],
///     observed_finalized_cursor: unreachable!("private field"),
///     binding: unreachable!("private field"),
///     completion: unreachable!("private field"),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ProviderIngestFinalizedMusubiCompletionClaimV1 {
    network_id: NetworkId,
    provider_id: [u8; 32],
    observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    binding: MusubiReplicationOrderArchiveBindingV1,
    completion: ReplicationOrderCompletionRecord,
    completed_musubi_store_instance: Option<CompletedMusubiStoreInstanceV1>,
}
impl PartialEq for ProviderIngestFinalizedMusubiCompletionClaimV1 {
    fn eq(&self, other: &Self) -> bool {
        self.network_id == other.network_id
            && self.provider_id == other.provider_id
            && self.observed_finalized_cursor == other.observed_finalized_cursor
            && self.binding == other.binding
            && self.completion == other.completion
    }
}
impl Eq for ProviderIngestFinalizedMusubiCompletionClaimV1 {}
impl ProviderIngestFinalizedMusubiCompletionClaimV1 {
    /// Exact configured deployment identity authenticated by the finalized reader.
    #[must_use]
    pub const fn network_id(&self) -> &NetworkId {
        &self.network_id
    }
    /// Local provider whose finalized completion was observed.
    #[must_use]
    pub const fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }
    /// Exact finalized archive cursor at which the completion row was observed.
    #[must_use]
    pub const fn observed_finalized_cursor(&self) -> ProviderIngestFinalizedCursorV1 {
        self.observed_finalized_cursor
    }
    /// Exact replication order authenticated by the finalized reader.
    #[must_use]
    pub const fn replication_order(&self) -> [u8; 32] {
        *self.binding.replication_order.as_bytes()
    }
    /// Exact derived archive identity authenticated by the finalized reader.
    #[must_use]
    pub const fn archive_id(&self) -> ArchiveId {
        self.binding.archive_id
    }
    /// Complete immutable archive commitment authenticated by the finalized reader.
    #[must_use]
    pub const fn commitment(&self) -> &MusubiArchiveCommitmentV1 {
        &self.binding.commitment
    }
    /// Exact provider-scoped completion copied from the finalized order row.
    #[must_use]
    pub const fn completion(&self) -> &ReplicationOrderCompletionRecord {
        &self.completion
    }
    pub(crate) fn matches_completed_musubi_store_instance(
        &self,
        expected: &CompletedMusubiStoreInstanceV1,
    ) -> bool {
        self.completed_musubi_store_instance
            .as_ref()
            .is_some_and(|actual| actual.matches(expected))
    }
    /// Check every finalized identity, cursor, completion, and commitment field against the
    /// retained local-ingest authorization.
    ///
    /// The completed row may first be observed after both its original admission cursor and its
    /// own finalized anchor. When either earlier point has the same height as the observed cursor,
    /// its block hash must also match. Conflicting admission and completion hashes at one height
    /// are always rejected, including when the completed row is observed at a later height.
    #[must_use]
    pub fn matches_authorization(
        &self,
        authorization: &FinalizedProviderIngestAuthorizationV1,
    ) -> bool {
        let Some(context) = authorization.musubi_context() else {
            return false;
        };
        let admission_cursor = authorization.admission_finalized_cursor();
        let completion_anchor = self.completion.finalized_anchor;
        authorization.validate().is_ok()
            && self.binding.validate().is_ok()
            && context.network_id() == &self.network_id
            && context.archive_id() == self.archive_id()
            && self.provider_id == authorization.provider_id()
            && self.replication_order() == authorization.order_id()
            && self.archive_id() == self.commitment().archive_id()
            && self.observed_finalized_cursor.height != 0
            && self.observed_finalized_cursor.block_hash != [0; 32]
            && self.completion.provider_id == ProviderId::new(self.provider_id)
            && self.completion.completed_by
                == self.completion.completion_authority.completion_signer
            && self.completion.completion_authority.is_valid()
            && self.completion.assignment_revision != 0
            && self.completion.completion_epoch != 0
            && completion_anchor.is_valid()
            && (admission_cursor.height != completion_anchor.height
                || admission_cursor.block_hash == completion_anchor.block_hash)
            && finalized_cursor_is_same_or_later(self.observed_finalized_cursor, admission_cursor)
            && finalized_cursor_is_same_or_later(
                self.observed_finalized_cursor,
                ProviderIngestFinalizedCursorV1 {
                    height: completion_anchor.height,
                    block_hash: completion_anchor.block_hash,
                },
            )
            && self.commitment().root_cid.as_bytes() == authorization.manifest_cid()
            && self.commitment().chunker.to_handle() == authorization.chunker_handle()
            && self.commitment().chunk_plan_digest.as_bytes()
                == &authorization.chunk_digest_sha3_256()
            && self.commitment().por_root.as_bytes() == &authorization.por_root()
            && self.commitment().content_length == authorization.content_length()
    }
}
/// Closed failure returned while deriving a provider-attestation approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProviderIngestMusubiAttestationApprovalRequestErrorV1 {
    /// The completed claim or canonical verifier evidence was inconsistent.
    #[error("provider-ingest Musubi attestation evidence was rejected")]
    Rejected,
}
/// Opaque, unsigned request to approve one exact Musubi provider attestation payload.
///
/// This value is deliberately nonserializable and has no arbitrary constructor. It can be
/// derived only by combining a finalized post-completion claim with the canonical bundle
/// verifier's opaque output. Construction performs no signing and activates no runtime path.
///
/// Neither pre-completion receipt nor verifier evidence can bypass the storage lifecycle lease.
/// Both the raw evidence constructor and lease-level request minting are crate-private. Downstream
/// code cannot turn verifier evidence or a generic finalized-ledger claim into an approval request.
/// Public equality compares the stable request semantics and deliberately omits the private
/// process-local authority marker.
///
/// ```compile_fail
/// use sorafs_node::{
///     ProviderIngestFinalizedMusubiCompletionClaimV1,
///     ProviderIngestMusubiAttestationApprovalRequestV1,
/// };
/// use sorafs_car::musubi::VerifiedMusubiBundleV1;
///
/// fn cannot_reuse_precompletion_verifier_evidence(
///     claim: &ProviderIngestFinalizedMusubiCompletionClaimV1,
///     verified: &VerifiedMusubiBundleV1,
/// ) {
///     let _ = ProviderIngestMusubiAttestationApprovalRequestV1::from_verified_completion(
///         claim, verified,
///     );
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ProviderIngestMusubiAttestationApprovalRequestV1 {
    payload: MusubiProviderBundleVerificationPayloadV1,
    completion_claim_digest: [u8; 32],
    observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    signer_policy: ProviderIngestCompletionSignerPolicyV1,
    completed_musubi_store_instance: CompletedMusubiStoreInstanceV1,
}
impl PartialEq for ProviderIngestMusubiAttestationApprovalRequestV1 {
    fn eq(&self, other: &Self) -> bool {
        self.payload == other.payload
            && self.completion_claim_digest == other.completion_claim_digest
            && self.observed_finalized_cursor == other.observed_finalized_cursor
            && self.signer_policy == other.signer_policy
    }
}
impl Eq for ProviderIngestMusubiAttestationApprovalRequestV1 {}
impl ProviderIngestMusubiAttestationApprovalRequestV1 {
    /// Derive an unsigned approval request from exact finalized completion and verifier evidence.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical or substituted claim fields, completion authority, archive
    /// commitment, CAR statistics, descriptor, semantic release, or verification lock evidence.
    fn from_verified_completion(
        claim: &ProviderIngestFinalizedMusubiCompletionClaimV1,
        verified: &VerifiedMusubiBundleV1,
    ) -> Result<Self, ProviderIngestMusubiAttestationApprovalRequestErrorV1> {
        let rejected = || ProviderIngestMusubiAttestationApprovalRequestErrorV1::Rejected;
        let commitment = claim.commitment();
        let completion = claim.completion();
        let descriptor = verified.descriptor();
        let car_stats = verified.car_stats();
        let semantic_release_manifest_digest = verified.semantic_release().semantic_digest();
        let verification_lock_digest = verified.verification_lock().digest();
        let descriptor_digest =
            musubi_artifact_descriptor_digest_v1(descriptor).ok_or_else(rejected)?;
        let completed_musubi_store_instance = claim
            .completed_musubi_store_instance
            .clone()
            .ok_or_else(rejected)?;
        claim.binding.validate().map_err(|_| rejected())?;
        descriptor.validate().map_err(|_| rejected())?;
        if claim.network_id.as_bytes()[31] & 1 != 1
            || claim.provider_id == [0; 32]
            || claim.observed_finalized_cursor.height == 0
            || claim.observed_finalized_cursor.block_hash == [0; 32]
            || verified.archive_id() != claim.archive_id()
            || claim.archive_id() != commitment.archive_id()
            || completion.provider_id != ProviderId::new(claim.provider_id)
            || completion.completed_by != completion.completion_authority.completion_signer
            || !completion.completion_authority.is_valid()
            || completion.assignment_revision == 0
            || completion.completion_epoch == 0
            || !completion.finalized_anchor.is_valid()
            || completion.finalized_anchor.height > claim.observed_finalized_cursor.height
            || completion.finalized_anchor.height == claim.observed_finalized_cursor.height
                && completion.finalized_anchor.block_hash
                    != claim.observed_finalized_cursor.block_hash
            || descriptor.semantic_release_manifest_digest != semantic_release_manifest_digest
            || descriptor.verification_lock_digest != verification_lock_digest
            || descriptor.source_tree_digest != commitment.source_tree_digest
            || descriptor_digest != commitment.descriptor_digest
            || descriptor.source_file_count != verified.source_file_count()
            || descriptor.source_bytes != verified.source_bytes()
            || commitment.file_count != verified.source_file_count()
            || car_stats.payload_bytes != commitment.content_length
            || car_stats.car_size != commitment.car_size
            || car_stats.car_archive_digest.as_bytes() != commitment.car_digest.as_bytes()
            || car_stats.chunk_count
                != usize::try_from(commitment.chunk_count).unwrap_or(usize::MAX)
            || car_stats.root_cids.len() != 1
            || car_stats.root_cids[0].as_slice() != commitment.root_cid.as_bytes()
        {
            return Err(rejected());
        }
        let payload = MusubiProviderBundleVerificationPayloadV1 {
            version: MUSUBI_REGISTRY_VERSION_V1,
            binding: MusubiProviderBundleVerificationBindingV1 {
                network_id: claim.network_id,
                provider_id: ProviderId::new(claim.provider_id),
                completed_by: completion.completed_by.clone(),
                completion_authority: completion.completion_authority.clone(),
                replication_order: claim.binding.replication_order,
                assignment_revision: completion.assignment_revision,
                completion_epoch: completion.completion_epoch,
                finalized_anchor: completion.finalized_anchor,
                archive_id: claim.archive_id(),
                bundle_digest: commitment.bundle_digest,
                descriptor_digest,
                semantic_release_manifest_digest,
                verification_lock_digest,
                source_tree_digest: descriptor.source_tree_digest,
            },
        };
        payload.validate().map_err(|_| rejected())?;
        let completion_claim_digest =
            provider_ingest_musubi_completion_claim_digest_v1(claim).ok_or_else(rejected)?;
        Ok(Self {
            payload,
            completion_claim_digest,
            observed_finalized_cursor: claim.observed_finalized_cursor,
            signer_policy: completion.completion_authority.signer_policy,
            completed_musubi_store_instance,
        })
    }
    /// Construct a structurally valid opaque request for crate-local unit tests.
    ///
    /// Production code cannot call this helper, and the helper deliberately
    /// preserves the same completed-owner, signer-policy, cursor, and non-zero
    /// claim-digest invariants exposed through the request accessors.
    #[cfg(test)]
    pub(crate) fn test_fixture(
        payload: MusubiProviderBundleVerificationPayloadV1,
        completion_claim_digest: [u8; 32],
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
        signer_policy: ProviderIngestCompletionSignerPolicyV1,
    ) -> Result<Self, ProviderIngestMusubiAttestationApprovalRequestErrorV1> {
        let anchor = payload.binding.finalized_anchor;
        if payload.validate().is_err()
            || payload.binding.network_id.as_bytes()[31] & 1 != 1
            || completion_claim_digest == [0; 32]
            || observed_finalized_cursor.height == 0
            || observed_finalized_cursor.block_hash == [0; 32]
            || !signer_policy.is_valid()
            || payload.binding.completion_authority.signer_policy != signer_policy
            || payload.binding.completed_by
                != payload.binding.completion_authority.completion_signer
            || anchor.height > observed_finalized_cursor.height
            || anchor.height == observed_finalized_cursor.height
                && anchor.block_hash != observed_finalized_cursor.block_hash
        {
            return Err(ProviderIngestMusubiAttestationApprovalRequestErrorV1::Rejected);
        }
        Ok(Self {
            payload,
            completion_claim_digest,
            observed_finalized_cursor,
            signer_policy,
            completed_musubi_store_instance: CompletedMusubiStoreInstanceV1::new(),
        })
    }
    /// Return the exact unsigned provider-attestation payload.
    #[must_use]
    pub const fn payload(&self) -> &MusubiProviderBundleVerificationPayloadV1 {
        &self.payload
    }
    /// Return the stable domain-separated digest of the completed-row evidence.
    ///
    /// The observation cursor is retained separately and deliberately excluded from this digest so
    /// an identical completed row can be reverified at a later finalized head after restart.
    #[must_use]
    pub const fn completion_claim_digest(&self) -> [u8; 32] {
        self.completion_claim_digest
    }
    /// Return the finalized cursor at which the completed row was observed.
    #[must_use]
    pub const fn observed_finalized_cursor(&self) -> ProviderIngestFinalizedCursorV1 {
        self.observed_finalized_cursor
    }
    /// Return the exact governed signer policy accepted by the finalized completion.
    #[must_use]
    pub const fn signer_policy(&self) -> ProviderIngestCompletionSignerPolicyV1 {
        self.signer_policy
    }
    pub(crate) fn matches_completed_musubi_store_instance(
        &self,
        expected: &CompletedMusubiStoreInstanceV1,
    ) -> bool {
        self.completed_musubi_store_instance.matches(expected)
    }
}
impl AdmittedPayloadReadLeaseV1<'_> {
    /// Reverify one completed Musubi bundle and mint its opaque unsigned approval request.
    ///
    /// This crate-private request-minting boundary binds the retained finalized authorization and
    /// sealed completed-row claim to both the exact storage/outbox instance and this
    /// storage-admitted manifest. It checks the supplied reconstruction plan against the admitted
    /// payload and opens all three byte-zero readers itself while the storage lifecycle lease
    /// remains held. The canonical Musubi V1 verifier applies its fixed consensus bounds; no
    /// caller-controlled limit or previously retained verifier result is accepted.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderIngestLocalStorageErrorV1::Permanent`] for an identity, cursor, plan,
    /// commitment, payload, or semantic-integrity mismatch. Transient admitted-storage reader
    /// failures return [`ProviderIngestLocalStorageErrorV1::Retryable`].
    pub(crate) fn verify_completed_musubi_bundle(
        &self,
        expected_store_instance: &CompletedMusubiStoreInstanceV1,
        plan: &CarBuildPlan,
        authorization: &FinalizedProviderIngestAuthorizationV1,
        completed_claim: &ProviderIngestFinalizedMusubiCompletionClaimV1,
    ) -> Result<ProviderIngestMusubiAttestationApprovalRequestV1, ProviderIngestLocalStorageErrorV1>
    {
        if !completed_claim.matches_completed_musubi_store_instance(expected_store_instance)
            || !completed_claim.matches_authorization(authorization)
            || self.manifest_digest() != &authorization.manifest_digest()
            || self.content_length() != authorization.content_length()
            || self.payload_digest() != plan.payload_digest.as_bytes()
            || plan.content_length != authorization.content_length()
            || compute_chunk_plan_digest_sha3(&plan.chunks) != authorization.chunk_digest_sha3_256()
        {
            return Err(ProviderIngestLocalStorageErrorV1::Permanent);
        }
        let first_read_error = Cell::new(None);
        let verified = MusubiBundleVerifierV1::verify_payload_with_factory(
            plan,
            completed_claim.commitment(),
            || {
                self.open_reader()
                    .inspect_err(|error| {
                        if first_read_error.get().is_none() {
                            first_read_error.set(Some(error.kind()));
                        }
                    })
                    .map(|inner| ProviderIngestObservedAdmittedPayloadReaderV1 {
                        inner,
                        first_error_kind: &first_read_error,
                    })
            },
        );
        match verified {
            Ok(verified) => {
                ProviderIngestMusubiAttestationApprovalRequestV1::from_verified_completion(
                    completed_claim,
                    &verified,
                )
                .map_err(|_| ProviderIngestLocalStorageErrorV1::Permanent)
            }
            Err(_)
                if first_read_error.get().is_some_and(|kind| {
                    provider_ingest_admitted_payload_read_error_is_retryable(kind)
                }) =>
            {
                Err(ProviderIngestLocalStorageErrorV1::Retryable)
            }
            Err(_) => Err(ProviderIngestLocalStorageErrorV1::Permanent),
        }
    }
}
struct ProviderIngestObservedAdmittedPayloadReaderV1<'observation, R> {
    inner: R,
    first_error_kind: &'observation Cell<Option<io::ErrorKind>>,
}
impl<R: Read> Read for ProviderIngestObservedAdmittedPayloadReaderV1<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.inner.read(output).inspect_err(|error| {
            if self.first_error_kind.get().is_none() {
                self.first_error_kind.set(Some(error.kind()));
            }
        })
    }
}
const fn provider_ingest_admitted_payload_read_error_is_retryable(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::NotFound
            | io::ErrorKind::Other
    )
}
#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "sorafs_node::provider_ingest_runtime::ProviderIngestMusubiCompletionClaimDigestPreimageV1"
)]
struct ProviderIngestMusubiCompletionClaimDigestPreimageV1 {
    network_id: NetworkId,
    provider_id: [u8; 32],
    binding: MusubiReplicationOrderArchiveBindingV1,
    completion: ReplicationOrderCompletionRecord,
}
fn provider_ingest_musubi_completion_claim_digest_v1(
    claim: &ProviderIngestFinalizedMusubiCompletionClaimV1,
) -> Option<[u8; 32]> {
    let preimage = ProviderIngestMusubiCompletionClaimDigestPreimageV1 {
        network_id: claim.network_id,
        provider_id: claim.provider_id,
        binding: claim.binding.clone(),
        completion: claim.completion.clone(),
    };
    let canonical = norito::encode_canonical(&preimage).ok()?;
    let canonical_len = u64::try_from(canonical.len()).ok()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROVIDER_INGEST_MUSUBI_COMPLETION_CLAIM_DIGEST_DOMAIN_V1);
    hasher.update(&canonical_len.to_be_bytes());
    hasher.update(&canonical);
    Some(*hasher.finalize().as_bytes())
}
fn musubi_artifact_descriptor_digest_v1(
    descriptor: &MusubiArtifactDescriptorV1,
) -> Option<MusubiContentDigestV1> {
    let descriptor_bytes = descriptor.encode();
    let domain_len = u64::try_from(MUSUBI_ARTIFACT_DESCRIPTOR_DIGEST_DOMAIN_V1.len()).ok()?;
    let descriptor_len = u64::try_from(descriptor_bytes.len()).ok()?;
    let material_len = 8_u64
        .checked_add(domain_len)?
        .checked_add(8)?
        .checked_add(descriptor_len)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(MUSUBI_ARTIFACT_DESCRIPTOR_DIGEST_DOMAIN_V1);
    hasher.update(&material_len.to_be_bytes());
    hasher.update(&domain_len.to_be_bytes());
    hasher.update(MUSUBI_ARTIFACT_DESCRIPTOR_DIGEST_DOMAIN_V1);
    hasher.update(&descriptor_len.to_be_bytes());
    hasher.update(&descriptor_bytes);
    Some(MusubiContentDigestV1::new(*hasher.finalize().as_bytes()))
}
/// Runtime-owned capability for constructing opaque claims inside one finalized-ledger read.
///
/// This type has no public constructor. Generic finalized-ledger reads receive an unbound factory
/// for ordinary ingest claims. Only the private signed-page scanner can create the store-bound
/// variant used for completed-Musubi attestation claims.
///
/// The capability authenticates the configured finalized-ledger implementation boundary, not
/// arbitrary bytes. That trusted implementation receives ownership and can retain the capability;
/// production wiring must therefore install only the qualified archive-backed reader.
#[derive(Debug)]
pub struct ProviderIngestFinalizedClaimFactoryV1 {
    network_id: NetworkId,
    provider_id: [u8; 32],
    completed_musubi_store_instance: Option<CompletedMusubiStoreInstanceV1>,
}
impl ProviderIngestFinalizedClaimFactoryV1 {
    fn new(network_id: NetworkId, provider_id: [u8; 32]) -> Self {
        Self {
            network_id,
            provider_id,
            completed_musubi_store_instance: None,
        }
    }
    fn new_completed_musubi_capture(
        network_id: NetworkId,
        provider_id: [u8; 32],
        completed_musubi_store_instance: CompletedMusubiStoreInstanceV1,
    ) -> Self {
        Self {
            network_id,
            provider_id,
            completed_musubi_store_instance: Some(completed_musubi_store_instance),
        }
    }
    /// Validate and seal one exact projected Musubi archive binding.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical binding or one substituted from another
    /// replication order or pin commitment.
    pub fn seal_musubi_archive(
        &self,
        observed_network_id: &NetworkId,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
        expected_order: [u8; 32],
        expected_pin: &PinManifestRecord,
        binding: MusubiReplicationOrderArchiveBindingV1,
    ) -> Result<ProviderIngestFinalizedMusubiArchiveClaimV1, ProviderIngestFinalizedLedgerErrorV1>
    {
        binding
            .validate()
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Rejected)?;
        let commitment = &binding.commitment;
        if observed_network_id != &self.network_id
            || observed_finalized_cursor.height == 0
            || observed_finalized_cursor.block_hash == [0; 32]
            || binding.replication_order.as_bytes() != &expected_order
            || commitment.root_cid != expected_pin.root_cid
            || commitment.chunker != expected_pin.chunker
            || commitment.chunk_plan_digest.as_bytes() != &expected_pin.chunk_digest_sha3_256
            || commitment.por_root.as_bytes() != &expected_pin.por_root
            || commitment.content_length != expected_pin.content_length
        {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
        }
        Ok(ProviderIngestFinalizedMusubiArchiveClaimV1 {
            network_id: self.network_id,
            provider_id: self.provider_id,
            observed_finalized_cursor,
            binding,
        })
    }
    /// Seal this provider's exact completed Musubi row as a post-completion capability.
    ///
    /// The method accepts the complete finalized order record and locates the
    /// configured provider's completion itself. A caller therefore cannot
    /// substitute a detached completion record that was not part of the row.
    ///
    /// # Errors
    ///
    /// Rejects a pending local provider, a noncanonical completion, or any
    /// substituted chain, cursor, order, pin, archive, or commitment field.
    pub fn seal_completed_musubi_archive(
        &self,
        observed_network_id: &NetworkId,
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
        expected_provider_id: ProviderId,
        expected_order: &ReplicationOrderRecord,
        expected_pin: &PinManifestRecord,
        binding: MusubiReplicationOrderArchiveBindingV1,
    ) -> Result<ProviderIngestFinalizedMusubiCompletionClaimV1, ProviderIngestFinalizedLedgerErrorV1>
    {
        binding
            .validate()
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Rejected)?;
        let commitment = &binding.commitment;
        let provider_id = ProviderId::new(self.provider_id);
        let canonical_order = decode_bound_replication_order(expected_order)
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Rejected)?;
        let mut provider_completions = expected_order
            .provider_completions
            .iter()
            .filter(|completion| completion.provider_id == provider_id);
        let completion = provider_completions
            .next()
            .ok_or(ProviderIngestFinalizedLedgerErrorV1::Rejected)?;
        let completion_anchor = completion.finalized_anchor;
        if observed_network_id != &self.network_id
            || observed_finalized_cursor.height == 0
            || observed_finalized_cursor.block_hash == [0; 32]
            || provider_id != expected_provider_id
            || canonical_order.order_id != *expected_order.order_id.as_bytes()
            || canonical_order.manifest_digest != *expected_order.manifest_digest.as_bytes()
            || canonical_order.manifest_cid.as_slice()
                != expected_order.manifest_root_cid.as_bytes()
            || !canonical_order
                .assignments
                .iter()
                .any(|assignment| assignment.provider_id == self.provider_id)
            || provider_completions.next().is_some()
            || binding.replication_order != expected_order.order_id
            || expected_order.musubi_archive != Some(binding.archive_id)
            || expected_order.manifest_digest != expected_pin.digest
            || expected_order.manifest_root_cid != expected_pin.root_cid
            || commitment.root_cid != expected_pin.root_cid
            || commitment.chunker != expected_pin.chunker
            || commitment.chunk_plan_digest.as_bytes() != &expected_pin.chunk_digest_sha3_256
            || commitment.por_root.as_bytes() != &expected_pin.por_root
            || commitment.content_length != expected_pin.content_length
            || completion.provider_id != provider_id
            || completion.completed_by != completion.completion_authority.completion_signer
            || !completion.completion_authority.is_valid()
            || completion.assignment_revision == 0
            || completion.assignment_revision != expected_order.assignment_revision
            || completion.completion_epoch < expected_order.issued_epoch
            || completion.completion_epoch > expected_order.deadline_epoch
            || !completion_anchor.is_valid()
            || completion_anchor.height > observed_finalized_cursor.height
            || completion_anchor.height == observed_finalized_cursor.height
                && completion_anchor.block_hash != observed_finalized_cursor.block_hash
        {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
        }
        Ok(ProviderIngestFinalizedMusubiCompletionClaimV1 {
            network_id: self.network_id,
            provider_id: self.provider_id,
            observed_finalized_cursor,
            binding,
            completion: completion.clone(),
            completed_musubi_store_instance: self.completed_musubi_store_instance.clone(),
        })
    }
}
/// Bounded stable page of provider assignments from one finalized state view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestFinalizedAssignmentPageV1 {
    /// Immutable finalized cursor shared by every row.
    pub finalized_cursor: ProviderIngestFinalizedCursorV1,
    /// Finalized block creation time used for transaction-TTL proofs.
    pub finalized_block_time_ms: u64,
    /// Rows in strictly increasing replication-order identity.
    pub rows: Vec<ProviderIngestFinalizedAssignmentV1>,
    /// Last returned order identity when another page exists.
    pub next_after_order_id: Option<[u8; 32]>,
}
/// Finalized-ledger paging failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderIngestFinalizedLedgerErrorV1 {
    /// The finalized query service is temporarily unavailable.
    Unavailable,
    /// The finalized query service rejected the bounded request.
    Rejected,
}
/// Reader for chain-authoritative assignments and provider completions.
pub trait ProviderIngestFinalizedLedgerV1: Send + Sync + 'static {
    /// Read one stable page after `after_order_id`.
    ///
    /// `at_finalized_cursor` is `None` only for the first page of a scan. Every
    /// continuation supplies the exact immutable cursor returned by that first
    /// page, including continuations resumed in a later runtime tick.
    fn read_assignment_page<'a>(
        &'a self,
        claim_factory: ProviderIngestFinalizedClaimFactoryV1,
        at_finalized_cursor: Option<ProviderIngestFinalizedCursorV1>,
        after_order_id: Option<[u8; 32]>,
        limit: usize,
    ) -> ProviderIngestFutureV1<
        'a,
        Result<ProviderIngestFinalizedAssignmentPageV1, ProviderIngestFinalizedLedgerErrorV1>,
    >;
}
include!("provider_ingest_runtime/completed_musubi_capture.rs");
/// Authenticated source-fetch outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderIngestSourceFetchErrorV1 {
    /// No currently admitted authenticated source was reachable.
    Unavailable,
    /// A source returned malformed, noncanonical, or authorization-mismatched material.
    ContentRejected,
    /// A source identity, public policy, or qualification binding was rejected.
    Rejected,
}
/// Exact Musubi commitment forwarded only across the private authenticated source boundary.
///
/// This value is not finalized evidence and cannot authorize storage completion or provider
/// attestation. The runtime derives it from an opaque finalized claim, and the private broker
/// revalidates every field against the ordinary finalized ingest authorization before transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestMusubiArchiveFetchBindingV1 {
    network_id: NetworkId,
    provider_id: [u8; 32],
    observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    binding: MusubiReplicationOrderArchiveBindingV1,
}
impl ProviderIngestMusubiArchiveFetchBindingV1 {
    /// Construct and validate one private-broker Musubi fetch binding.
    ///
    /// This constructor does not confer finality. It exists so an authenticated private broker
    /// can reconstruct the checked informational binding on its server side.
    ///
    /// # Errors
    ///
    /// Returns a fixed rejection when an identity or commitment is inert or noncanonical.
    pub fn new(
        network_id: NetworkId,
        provider_id: [u8; 32],
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
        binding: MusubiReplicationOrderArchiveBindingV1,
    ) -> Result<Self, ProviderIngestSourceFetchErrorV1> {
        if network_id.as_bytes()[31] & 1 != 1
            || provider_id == [0; 32]
            || observed_finalized_cursor.height == 0
            || observed_finalized_cursor.block_hash == [0; 32]
            || binding.validate().is_err()
        {
            return Err(ProviderIngestSourceFetchErrorV1::Rejected);
        }
        Ok(Self {
            network_id,
            provider_id,
            observed_finalized_cursor,
            binding,
        })
    }
    fn from_finalized_claim(claim: &ProviderIngestFinalizedMusubiArchiveClaimV1) -> Self {
        Self {
            network_id: claim.network_id,
            provider_id: claim.provider_id,
            observed_finalized_cursor: claim.observed_finalized_cursor,
            binding: claim.binding.clone(),
        }
    }
    /// Exact configured deployment identity.
    #[must_use]
    pub const fn network_id(&self) -> &NetworkId {
        &self.network_id
    }
    /// Provider for which the finalized assignment was read.
    #[must_use]
    pub const fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }
    /// Finalized archive cursor from which the runtime derived this binding.
    #[must_use]
    pub const fn observed_finalized_cursor(&self) -> ProviderIngestFinalizedCursorV1 {
        self.observed_finalized_cursor
    }
    /// Complete order/archive commitment forwarded to the authenticated source.
    #[must_use]
    pub const fn binding(&self) -> &MusubiReplicationOrderArchiveBindingV1 {
        &self.binding
    }
    /// Check this informational binding against the exact finalized ingest authorization.
    #[must_use]
    pub fn matches_authorization(
        &self,
        authorization: &FinalizedProviderIngestAuthorizationV1,
    ) -> bool {
        let commitment = &self.binding.commitment;
        authorization.validate().is_ok()
            && self.network_id.as_bytes()[31] & 1 == 1
            && self.provider_id == authorization.provider_id()
            && authorization_musubi_context_matches(
                authorization,
                &self.network_id,
                self.binding.archive_id,
            )
            && finalized_cursor_is_same_or_later(
                self.observed_finalized_cursor,
                authorization.admission_finalized_cursor(),
            )
            && self.binding.validate().is_ok()
            && self.binding.replication_order.as_bytes() == &authorization.order_id()
            && commitment.archive_id() == self.binding.archive_id
            && commitment.root_cid.as_bytes() == authorization.manifest_cid()
            && commitment.chunker.to_handle() == authorization.chunker_handle()
            && commitment.chunk_plan_digest.as_bytes() == &authorization.chunk_digest_sha3_256()
            && commitment.por_root.as_bytes() == &authorization.por_root()
            && commitment.content_length == authorization.content_length()
    }
}
/// Exact fetch request containing no source credentials or lease material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestSourceRequestV1 {
    authorization: FinalizedProviderIngestAuthorizationV1,
    source_provider_ids: Vec<[u8; 32]>,
    musubi_archive: Option<ProviderIngestMusubiArchiveFetchBindingV1>,
}
impl ProviderIngestSourceRequestV1 {
    /// Construct one canonical request for an authenticated provider source.
    ///
    /// The optional Musubi value is informational transport data, not finalized evidence. It must
    /// agree exactly with the ordinary finalized ingest authorization.
    ///
    /// # Errors
    ///
    /// Returns a fixed rejection for an invalid authorization, an empty, oversized, unsorted,
    /// duplicate, self-referential, or zero source list, or a substituted Musubi binding.
    pub fn new(
        authorization: FinalizedProviderIngestAuthorizationV1,
        source_provider_ids: Vec<[u8; 32]>,
        musubi_archive: Option<ProviderIngestMusubiArchiveFetchBindingV1>,
    ) -> Result<Self, ProviderIngestSourceFetchErrorV1> {
        if authorization.validate().is_err()
            || source_provider_ids.is_empty()
            || source_provider_ids.len() > MAX_REPLICATION_ORDER_ASSIGNMENTS
            || source_provider_ids.iter().any(|provider_id| {
                *provider_id == [0; 32] || *provider_id == authorization.provider_id()
            })
            || source_provider_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || match (authorization.musubi_context(), musubi_archive.as_ref()) {
                (None, None) => false,
                (Some(_), Some(binding)) => !binding.matches_authorization(&authorization),
                (None, Some(_)) | (Some(_), None) => true,
            }
        {
            return Err(ProviderIngestSourceFetchErrorV1::Rejected);
        }
        Ok(Self {
            authorization,
            source_provider_ids,
            musubi_archive,
        })
    }
    /// Immutable finalized provider/order/manifest authorization.
    #[must_use]
    pub const fn authorization(&self) -> &FinalizedProviderIngestAuthorizationV1 {
        &self.authorization
    }
    /// Canonically ordered governed source provider identities.
    #[must_use]
    pub fn source_provider_ids(&self) -> &[[u8; 32]] {
        &self.source_provider_ids
    }
    /// Informational Musubi commitment derived from the opaque finalized claim.
    #[must_use]
    pub const fn musubi_archive(&self) -> Option<&ProviderIngestMusubiArchiveFetchBindingV1> {
        self.musubi_archive.as_ref()
    }
    /// Consume the request into its checked transport components.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        FinalizedProviderIngestAuthorizationV1,
        Vec<[u8; 32]>,
        Option<ProviderIngestMusubiArchiveFetchBindingV1>,
    ) {
        (
            self.authorization,
            self.source_provider_ids,
            self.musubi_archive,
        )
    }
}
/// Public, non-secret qualification for a top-level provider-ingest adapter.
///
/// The source-pool and governed signer-resolver roles each expose an
/// independently configured value. Credentials, endpoint material, grants,
/// private keys, and payload data are never represented by this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderIngestRuntimeProviderQualificationV1 {
    /// Non-zero adapter and public-policy revision.
    pub revision: u64,
    /// Non-zero digest of the exact public adapter policy.
    pub policy_digest: [u8; 32],
}
impl ProviderIngestRuntimeProviderQualificationV1 {
    /// Construct one first-release public adapter qualification.
    #[must_use]
    pub const fn new(revision: u64, policy_digest: [u8; 32]) -> Self {
        Self {
            revision,
            policy_digest,
        }
    }
    /// Return whether both required public qualification pins are non-zero.
    #[must_use]
    pub fn is_valid(self) -> bool {
        self.revision != 0 && self.policy_digest != [0; 32]
    }
}
/// Payload-free public qualification of one authenticated provider source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderIngestSourceQualificationV1 {
    /// Qualification schema version.
    pub version: u8,
    /// Non-zero adapter and public-policy revision.
    pub revision: u64,
    /// Non-zero digest of the exact public source policy.
    pub policy_digest: [u8; 32],
}
impl ProviderIngestSourceQualificationV1 {
    /// Construct a first-release source qualification.
    #[must_use]
    pub const fn new(revision: u64, policy_digest: [u8; 32]) -> Self {
        Self {
            version: PROVIDER_INGEST_SOURCE_QUALIFICATION_VERSION_V1,
            revision,
            policy_digest,
        }
    }
    /// Validate the qualification schema and non-zero binding.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema or zero revision/digest.
    pub fn validate(self) -> Result<(), ProviderIngestAuthenticatedSourcePoolErrorV1> {
        if self.version != PROVIDER_INGEST_SOURCE_QUALIFICATION_VERSION_V1
            || self.revision == 0
            || self.policy_digest == [0; 32]
        {
            return Err(ProviderIngestAuthenticatedSourcePoolErrorV1::InvalidSourceQualification);
        }
        Ok(())
    }
}
/// Independently configured public binding for one authenticated provider source.
///
/// The binding contains no endpoint credentials, grants, tokens, private keys, or payload material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestAuthenticatedSourceBindingV1 {
    /// Exact governed provider identity served by the source.
    pub provider_id: [u8; 32],
    /// Stable opaque identity of the provider-specific transport.
    pub runtime_handle: String,
    /// Exact non-zero adapter and public-policy revision.
    pub revision: u64,
    /// Exact non-zero digest of the public source policy.
    pub policy_digest: [u8; 32],
}
impl ProviderIngestAuthenticatedSourceBindingV1 {
    /// Return the exact qualification required from the injected source.
    #[must_use]
    pub const fn qualification(&self) -> ProviderIngestSourceQualificationV1 {
        ProviderIngestSourceQualificationV1::new(self.revision, self.policy_digest)
    }
    fn validate(
        &self,
        pool_runtime_handle: &str,
    ) -> Result<(), ProviderIngestAuthenticatedSourcePoolErrorV1> {
        if self.provider_id == [0; 32] {
            return Err(ProviderIngestAuthenticatedSourcePoolErrorV1::InvalidProviderId);
        }
        if !is_production_runtime_handle(&self.runtime_handle)
            || self.runtime_handle == pool_runtime_handle
        {
            return Err(ProviderIngestAuthenticatedSourcePoolErrorV1::InvalidSourceHandle);
        }
        self.qualification().validate()
    }
}
/// Authenticated source fetch boundary.
///
/// Production implementations must resolve only current governance-admitted signed adverts,
/// authenticate a bounded stream grant, require HTTPS with pinned trust and DNS-rebinding defenses,
/// reject redirects and implicit decompression, and enforce the exact manifest, chunk-plan,
/// payload-length, chunk digest, and PoR-root binding in the request. Implementations try only a
/// bounded canonical source list and never persist tokens, URLs, or payload bytes in the outbox.
pub trait ProviderIngestAuthenticatedSourceFetchV1: Send + Sync + 'static {
    /// Verified material passed directly to local storage.
    type Fetched: Send + 'static;
    /// Fetch and verify exact material from an authenticated governed source.
    fn fetch<'a>(
        &'a self,
        request: ProviderIngestSourceRequestV1,
    ) -> ProviderIngestFutureV1<'a, Result<Self::Fetched, ProviderIngestSourceFetchErrorV1>>;
}
/// One independently authenticated provider source used by the production pool.
///
/// Implementations own their runtime-only endpoint, grant, credential, and pinned-trust material.
/// The stable handle and provider identity are public policy identifiers only. A fetch must use a
/// hard transport deadline, reject redirects and implicit decompression, and verify the exact
/// finalized authorization before returning.
pub trait ProviderIngestAuthenticatedProviderSourceV1: Send + Sync + 'static {
    /// Verified material returned by this source.
    type Fetched: Send + 'static;
    /// Exact governed provider identity served by this source.
    fn provider_id(&self) -> [u8; 32];
    /// Stable public identity of this provider-specific transport.
    fn runtime_handle(&self) -> &str;
    /// Current payload-free adapter and public-policy qualification.
    ///
    /// # Errors
    ///
    /// Returns a fixed payload-free source failure when the qualification cannot be authenticated.
    fn qualification(
        &self,
    ) -> Result<ProviderIngestSourceQualificationV1, ProviderIngestSourceFetchErrorV1>;
    /// Non-mutating authenticated readiness check.
    ///
    /// # Errors
    ///
    /// Returns a fixed payload-free source failure when the source is not
    /// currently ready or its public policy is rejected.
    fn check_readiness(&self) -> Result<(), ProviderIngestSourceFetchErrorV1>;
    /// Fetch exact material for one finalized authorization.
    fn fetch_provider<'a>(
        &'a self,
        authorization: FinalizedProviderIngestAuthorizationV1,
        musubi_archive: Option<ProviderIngestMusubiArchiveFetchBindingV1>,
    ) -> ProviderIngestFutureV1<'a, Result<Self::Fetched, ProviderIngestSourceFetchErrorV1>>;
}
/// Invalid construction of an authenticated multi-provider source pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProviderIngestAuthenticatedSourcePoolErrorV1 {
    /// The pool's public runtime identity is not production-safe.
    #[error("provider-ingest source-pool handle is invalid")]
    InvalidPoolHandle,
    /// The pool's top-level public qualification is zero or otherwise invalid.
    #[error("provider-ingest source-pool qualification is invalid")]
    InvalidPoolQualification,
    /// The per-request source bound is outside the V1 protocol range.
    #[error("provider-ingest source-pool request bound is invalid")]
    InvalidSourceLimit,
    /// A production pool must contain at least two and at most the V1 maximum sources.
    #[error("provider-ingest source-pool size is invalid")]
    InvalidSourceCount,
    /// A source exposed a zero provider identity.
    #[error("provider-ingest source-pool provider identity is invalid")]
    InvalidProviderId,
    /// A source's public runtime identity is invalid or aliases the pool.
    #[error("provider-ingest provider-source handle is invalid")]
    InvalidSourceHandle,
    /// A configured source qualification is unsupported or contains a zero pin.
    #[error("provider-ingest provider-source qualification is invalid")]
    InvalidSourceQualification,
    /// An injected source does not match its independent public binding.
    #[error("provider-ingest provider-source identity or qualification does not match")]
    SourceBindingMismatch,
    /// Two sources claimed the same governed provider.
    #[error("provider-ingest source-pool contains a duplicate provider")]
    DuplicateProvider,
    /// Two independently administered sources reused one runtime identity.
    #[error("provider-ingest source-pool contains a duplicate source handle")]
    DuplicateSourceHandle,
}
/// One independently bound authenticated provider source.
pub struct ProviderIngestAuthenticatedSourceRegistrationV1<Fetched: Send + 'static> {
    binding: ProviderIngestAuthenticatedSourceBindingV1,
    source: Arc<dyn ProviderIngestAuthenticatedProviderSourceV1<Fetched = Fetched>>,
}
impl<Fetched: Send + 'static> fmt::Debug
    for ProviderIngestAuthenticatedSourceRegistrationV1<Fetched>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderIngestAuthenticatedSourceRegistrationV1")
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}
impl<Fetched: Send + 'static> ProviderIngestAuthenticatedSourceRegistrationV1<Fetched> {
    /// Pair an independently configured public binding with one injected source.
    #[must_use]
    pub fn new(
        binding: ProviderIngestAuthenticatedSourceBindingV1,
        source: Arc<dyn ProviderIngestAuthenticatedProviderSourceV1<Fetched = Fetched>>,
    ) -> Self {
        Self { binding, source }
    }
}
struct PinnedProviderIngestSourceV1<Fetched: Send + 'static> {
    binding: ProviderIngestAuthenticatedSourceBindingV1,
    source: Arc<dyn ProviderIngestAuthenticatedProviderSourceV1<Fetched = Fetched>>,
}
/// Bounded, identity-pinned authenticated multi-provider source coordinator.
///
/// The pool freezes a canonical public provider inventory at construction, retains an independent
/// top-level revision/policy-digest qualification, rejects missing or substituted sources before
/// contacting any transport, and tries only the exact canonical source list carried by finalized
/// assignment state. Each selected source is rechecked before and after its fetch. Source
/// locations, grants, credentials, and payload bytes remain inside the child adapters and are never
/// copied into pool metadata or durable state.
pub struct ProviderIngestAuthenticatedSourcePoolV1<Fetched: Send + 'static> {
    runtime_handle: String,
    qualification: ProviderIngestRuntimeProviderQualificationV1,
    max_sources_per_fetch: usize,
    provider_ids: Vec<[u8; 32]>,
    sources: BTreeMap<[u8; 32], PinnedProviderIngestSourceV1<Fetched>>,
}
impl<Fetched: Send + 'static> fmt::Debug for ProviderIngestAuthenticatedSourcePoolV1<Fetched> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderIngestAuthenticatedSourcePoolV1")
            .field("runtime_handle", &self.runtime_handle)
            .field("qualification", &self.qualification)
            .field("max_sources_per_fetch", &self.max_sources_per_fetch)
            .field("provider_ids", &self.provider_ids)
            .finish_non_exhaustive()
    }
}
impl<Fetched: Send + 'static> ProviderIngestAuthenticatedSourcePoolV1<Fetched> {
    /// Construct a production pool from independently configured source bindings.
    ///
    /// # Errors
    ///
    /// Returns an error when the pool bounds or any independently configured
    /// source identity, handle, qualification, or injected adapter is invalid.
    pub fn new(
        runtime_handle: impl Into<String>,
        qualification: ProviderIngestRuntimeProviderQualificationV1,
        max_sources_per_fetch: usize,
        sources: Vec<ProviderIngestAuthenticatedSourceRegistrationV1<Fetched>>,
    ) -> Result<Self, ProviderIngestAuthenticatedSourcePoolErrorV1> {
        let runtime_handle = runtime_handle.into();
        if !is_production_runtime_handle(&runtime_handle) {
            return Err(ProviderIngestAuthenticatedSourcePoolErrorV1::InvalidPoolHandle);
        }
        if !qualification.is_valid() {
            return Err(ProviderIngestAuthenticatedSourcePoolErrorV1::InvalidPoolQualification);
        }
        if max_sources_per_fetch == 0 || max_sources_per_fetch > MAX_REPLICATION_ORDER_ASSIGNMENTS {
            return Err(ProviderIngestAuthenticatedSourcePoolErrorV1::InvalidSourceLimit);
        }
        if sources.len() < 2 || sources.len() > MAX_REPLICATION_ORDER_ASSIGNMENTS {
            return Err(ProviderIngestAuthenticatedSourcePoolErrorV1::InvalidSourceCount);
        }
        let mut pinned_handles = BTreeSet::new();
        let mut pinned_sources = BTreeMap::new();
        for registration in sources {
            let binding = registration.binding;
            binding.validate(&runtime_handle)?;
            if !pinned_handles.insert(binding.runtime_handle.clone()) {
                return Err(ProviderIngestAuthenticatedSourcePoolErrorV1::DuplicateSourceHandle);
            }
            let source = registration.source;
            let qualification = source
                .qualification()
                .map_err(|_| ProviderIngestAuthenticatedSourcePoolErrorV1::SourceBindingMismatch)?;
            if source.provider_id() != binding.provider_id
                || source.runtime_handle() != binding.runtime_handle.as_str()
                || qualification != binding.qualification()
            {
                return Err(ProviderIngestAuthenticatedSourcePoolErrorV1::SourceBindingMismatch);
            }
            let provider_id = binding.provider_id;
            let pinned = PinnedProviderIngestSourceV1 { binding, source };
            if pinned_sources.insert(provider_id, pinned).is_some() {
                return Err(ProviderIngestAuthenticatedSourcePoolErrorV1::DuplicateProvider);
            }
        }
        let provider_ids = pinned_sources.keys().copied().collect();
        Ok(Self {
            runtime_handle,
            qualification,
            max_sources_per_fetch,
            provider_ids,
            sources: pinned_sources,
        })
    }
    /// Stable public identity of the complete source pool.
    #[must_use]
    pub fn runtime_handle(&self) -> &str {
        &self.runtime_handle
    }
    /// Return the pool's exact top-level adapter qualification.
    #[must_use]
    pub const fn qualification(&self) -> ProviderIngestRuntimeProviderQualificationV1 {
        self.qualification
    }
    /// Canonical identity-pinned provider inventory.
    #[must_use]
    pub fn source_provider_ids(&self) -> &[[u8; 32]] {
        &self.provider_ids
    }
    /// Maximum sources admitted in one finalized fetch request.
    #[must_use]
    pub const fn max_sources_per_fetch(&self) -> usize {
        self.max_sources_per_fetch
    }
    /// Revalidate every pinned source without exposing request material.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderIngestSourceFetchErrorV1::Unavailable`] when no independently qualified
    /// source is currently ready, or [`ProviderIngestSourceFetchErrorV1::Rejected`] when any pinned
    /// source is substituted, stale, or policy-rejected.
    pub fn check_readiness(&self) -> Result<(), ProviderIngestSourceFetchErrorV1> {
        if !is_production_runtime_handle(&self.runtime_handle)
            || !self.qualification.is_valid()
            || self.provider_ids.len() < 2
            || self.provider_ids.len() != self.sources.len()
            || self.max_sources_per_fetch == 0
            || self.max_sources_per_fetch > MAX_REPLICATION_ORDER_ASSIGNMENTS
        {
            return Err(ProviderIngestSourceFetchErrorV1::Rejected);
        }
        let mut ready = false;
        for provider_id in &self.provider_ids {
            let source = self
                .sources
                .get(provider_id)
                .ok_or(ProviderIngestSourceFetchErrorV1::Rejected)?;
            if self.source_is_ready(source)? {
                ready = true;
            }
        }
        if !ready {
            return Err(ProviderIngestSourceFetchErrorV1::Unavailable);
        }
        Ok(())
    }
    fn source_is_ready(
        &self,
        source: &PinnedProviderIngestSourceV1<Fetched>,
    ) -> Result<bool, ProviderIngestSourceFetchErrorV1> {
        let before_ready = match self.validate_source(source) {
            Ok(()) => true,
            Err(ProviderIngestSourceFetchErrorV1::Unavailable) => false,
            Err(
                ProviderIngestSourceFetchErrorV1::ContentRejected
                | ProviderIngestSourceFetchErrorV1::Rejected,
            ) => return Err(ProviderIngestSourceFetchErrorV1::Rejected),
        };
        let readiness = source.source.check_readiness();
        let after = self.validate_source(source);
        if matches!(
            readiness,
            Err(ProviderIngestSourceFetchErrorV1::ContentRejected
                | ProviderIngestSourceFetchErrorV1::Rejected)
        ) || matches!(
            after,
            Err(ProviderIngestSourceFetchErrorV1::ContentRejected
                | ProviderIngestSourceFetchErrorV1::Rejected)
        ) {
            return Err(ProviderIngestSourceFetchErrorV1::Rejected);
        }
        Ok(before_ready && readiness.is_ok() && after.is_ok())
    }
    fn validate_source(
        &self,
        source: &PinnedProviderIngestSourceV1<Fetched>,
    ) -> Result<(), ProviderIngestSourceFetchErrorV1> {
        let actual_handle = source.source.runtime_handle();
        if source.binding.validate(&self.runtime_handle).is_err()
            || source.source.provider_id() != source.binding.provider_id
            || !is_production_runtime_handle(actual_handle)
            || actual_handle != source.binding.runtime_handle.as_str()
        {
            return Err(ProviderIngestSourceFetchErrorV1::Rejected);
        }
        let actual_qualification = match source.source.qualification() {
            Ok(qualification) => qualification,
            Err(ProviderIngestSourceFetchErrorV1::Unavailable) => {
                return Err(ProviderIngestSourceFetchErrorV1::Unavailable);
            }
            Err(
                ProviderIngestSourceFetchErrorV1::ContentRejected
                | ProviderIngestSourceFetchErrorV1::Rejected,
            ) => return Err(ProviderIngestSourceFetchErrorV1::Rejected),
        };
        if actual_qualification != source.binding.qualification() {
            return Err(ProviderIngestSourceFetchErrorV1::Rejected);
        }
        Ok(())
    }
    fn validate_request(
        &self,
        request: &ProviderIngestSourceRequestV1,
    ) -> Result<(), ProviderIngestSourceFetchErrorV1> {
        if request.source_provider_ids().len() > self.max_sources_per_fetch
            || request.source_provider_ids().iter().any(|provider_id| {
                *provider_id == [0; 32]
                    || *provider_id == request.authorization().provider_id()
                    || !self.sources.contains_key(provider_id)
            })
            || request
                .source_provider_ids()
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || request
                .musubi_archive()
                .is_some_and(|binding| !binding.matches_authorization(request.authorization()))
        {
            return Err(ProviderIngestSourceFetchErrorV1::Rejected);
        }
        Ok(())
    }
}
impl<Fetched: Send + 'static> ProviderIngestAuthenticatedSourceFetchV1
    for ProviderIngestAuthenticatedSourcePoolV1<Fetched>
{
    type Fetched = Fetched;
    fn fetch<'a>(
        &'a self,
        request: ProviderIngestSourceRequestV1,
    ) -> ProviderIngestFutureV1<'a, Result<Self::Fetched, ProviderIngestSourceFetchErrorV1>> {
        Box::pin(async move {
            self.validate_request(&request)?;
            let mut content_rejected = false;
            for provider_id in request.source_provider_ids() {
                let source = self
                    .sources
                    .get(provider_id)
                    .ok_or(ProviderIngestSourceFetchErrorV1::Rejected)?;
                if !self.source_is_ready(source)? {
                    continue;
                }
                let result = source
                    .source
                    .fetch_provider(
                        request.authorization().clone(),
                        request.musubi_archive().cloned(),
                    )
                    .await;
                let post_fetch_ready = self.source_is_ready(source)?;
                match result {
                    Ok(fetched) if post_fetch_ready => return Ok(fetched),
                    Ok(_) => {}
                    Err(ProviderIngestSourceFetchErrorV1::Unavailable) => {}
                    Err(ProviderIngestSourceFetchErrorV1::ContentRejected) => {
                        content_rejected = true;
                    }
                    Err(ProviderIngestSourceFetchErrorV1::Rejected) => {
                        return Err(ProviderIngestSourceFetchErrorV1::Rejected);
                    }
                }
            }
            Err(if content_rejected {
                ProviderIngestSourceFetchErrorV1::ContentRejected
            } else {
                ProviderIngestSourceFetchErrorV1::Unavailable
            })
        })
    }
}
/// Local storage verification/persistence failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderIngestLocalStorageErrorV1 {
    /// Local storage failed in a retryable manner.
    Retryable,
    /// Local storage permanently rejected exact verified material.
    Permanent,
    /// Newly admitted material permanently failed post-admission verification.
    ///
    /// The generic SoraFS object may already have another live reference, so the storage adapter
    /// must not delete it. The provider-ingest runtime instead moves the exact authorization into
    /// its durable payload-free dead letter, which binds the job, provider, order, manifest, and
    /// finalized cursor while making completion unreachable.
    Quarantined,
}
/// Closed evidence that one immutable local payload passed the complete Musubi verifier.
///
/// The value can be constructed only from [`VerifiedMusubiBundleV1`], whose representation is
/// private to the canonical `sorafs_car` verifier. It is deliberately not Norito-decodable:
/// durable checkpoints use a crate-private representation so downstream callers cannot fabricate
/// verifier evidence from public field-shaped bytes. It is a pre-completion receipt, not a
/// provider attestation, and intentionally contains no finalized completion row or signature.
///
/// ```compile_fail
/// use sorafs_node::ProviderIngestVerifiedMusubiBundleReceiptV1;
///
/// let encoded = [];
/// let _: ProviderIngestVerifiedMusubiBundleReceiptV1 =
///     norito::decode_from_bytes(&encoded).expect("public receipts are not decodable");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestVerifiedMusubiBundleReceiptV1 {
    network_id: NetworkId,
    provider_id: [u8; 32],
    observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    replication_order: [u8; 32],
    manifest_digest: [u8; 32],
    archive_id: ArchiveId,
    commitment: MusubiArchiveCommitmentV1,
    semantic_release_manifest_digest: MusubiSemanticReleaseDigestV1,
    verification_lock_digest: MusubiVerificationLockDigestV1,
}
/// Crate-private canonical checkpoint representation of a verified Musubi receipt.
///
/// Keeping codec implementations on this non-exported type preserves durable checkpointing
/// without turning public receipt bytes into a construction capability.
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "sorafs_node::provider_ingest_runtime::StoredProviderIngestVerifiedMusubiBundleReceiptV1"
)]
pub(crate) struct StoredProviderIngestVerifiedMusubiBundleReceiptV1 {
    network_id: NetworkId,
    provider_id: [u8; 32],
    observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    replication_order: [u8; 32],
    manifest_digest: [u8; 32],
    archive_id: ArchiveId,
    commitment: MusubiArchiveCommitmentV1,
    semantic_release_manifest_digest: MusubiSemanticReleaseDigestV1,
    verification_lock_digest: MusubiVerificationLockDigestV1,
}
impl ProviderIngestVerifiedMusubiBundleReceiptV1 {
    /// Bind canonical verifier output to the exact opaque finalized precursor.
    ///
    /// # Errors
    ///
    /// Returns a permanent failure if the parsed descriptor does not agree with the verified
    /// semantic release, verification lock, or finalized archive commitment.
    pub fn from_verified_bundle(
        claim: &ProviderIngestFinalizedMusubiArchiveClaimV1,
        authorization: &FinalizedProviderIngestAuthorizationV1,
        verified: &VerifiedMusubiBundleV1,
    ) -> Result<Self, ProviderIngestLocalStorageErrorV1> {
        let descriptor = verified.descriptor();
        let semantic_release_manifest_digest = verified.semantic_release().semantic_digest();
        let verification_lock_digest = verified.verification_lock().digest();
        if verified.archive_id() != claim.archive_id()
            || !claim.matches_authorization(authorization)
            || descriptor.semantic_release_manifest_digest != semantic_release_manifest_digest
            || descriptor.verification_lock_digest != verification_lock_digest
            || descriptor.source_tree_digest != claim.commitment().source_tree_digest
            || claim.archive_id() != claim.commitment().archive_id()
            || claim.provider_id() != authorization.provider_id()
            || claim.replication_order() != authorization.order_id()
        {
            return Err(ProviderIngestLocalStorageErrorV1::Permanent);
        }
        let receipt = Self {
            network_id: claim.network_id,
            provider_id: claim.provider_id,
            observed_finalized_cursor: claim.observed_finalized_cursor,
            replication_order: claim.replication_order(),
            manifest_digest: authorization.manifest_digest(),
            archive_id: claim.archive_id(),
            commitment: claim.commitment().clone(),
            semantic_release_manifest_digest,
            verification_lock_digest,
        };
        if !receipt.validate_stored(authorization) {
            return Err(ProviderIngestLocalStorageErrorV1::Permanent);
        }
        Ok(receipt)
    }
    /// Return whether this receipt covers the exact finalized precursor and local authorization.
    #[must_use]
    pub fn matches(
        &self,
        claim: &ProviderIngestFinalizedMusubiArchiveClaimV1,
        authorization: &FinalizedProviderIngestAuthorizationV1,
    ) -> bool {
        self.validate_stored(authorization)
            && claim.matches_authorization(authorization)
            && self.network_id == claim.network_id
            && self.provider_id == claim.provider_id
            && self.provider_id == authorization.provider_id()
            && finalized_cursor_is_same_or_later(
                self.observed_finalized_cursor,
                authorization.admission_finalized_cursor(),
            )
            && finalized_cursor_is_same_or_later(
                claim.observed_finalized_cursor,
                self.observed_finalized_cursor,
            )
            && self.replication_order == claim.replication_order()
            && self.replication_order == authorization.order_id()
            && self.manifest_digest == authorization.manifest_digest()
            && self.archive_id == claim.archive_id()
            && self.commitment == *claim.commitment()
            && !self.semantic_release_manifest_digest.is_zero()
            && !self.verification_lock_digest.is_zero()
    }
    pub(crate) fn validate_stored(
        &self,
        authorization: &FinalizedProviderIngestAuthorizationV1,
    ) -> bool {
        let commitment = &self.commitment;
        authorization.validate().is_ok()
            && self.network_id.as_bytes()[31] & 1 == 1
            && self.provider_id == authorization.provider_id()
            && authorization_musubi_context_matches(
                authorization,
                &self.network_id,
                self.archive_id,
            )
            && self.replication_order == authorization.order_id()
            && self.manifest_digest == authorization.manifest_digest()
            && finalized_cursor_is_same_or_later(
                self.observed_finalized_cursor,
                authorization.admission_finalized_cursor(),
            )
            && self.archive_id == commitment.archive_id()
            && commitment.validate().is_ok()
            && commitment.root_cid.as_bytes() == authorization.manifest_cid()
            && commitment.chunker.to_handle() == authorization.chunker_handle()
            && commitment.chunk_plan_digest.as_bytes() == &authorization.chunk_digest_sha3_256()
            && commitment.por_root.as_bytes() == &authorization.por_root()
            && commitment.content_length == authorization.content_length()
            && !self.semantic_release_manifest_digest.is_zero()
            && !self.verification_lock_digest.is_zero()
            && self.canonical_stored_len().is_ok_and(|length| {
                length <= PROVIDER_INGEST_VERIFIED_MUSUBI_RECEIPT_MAX_CANONICAL_BYTES_V1
            })
    }
    /// Measure the actual canonical receipt frame without allocating another encoded copy.
    fn canonical_stored_len(&self) -> Result<usize, norito::Error> {
        norito::canonical_frame_len(&self.to_stored())
    }
    /// Domain-separated semantic release-manifest digest parsed from the bundle.
    #[must_use]
    pub const fn semantic_release_manifest_digest(&self) -> MusubiSemanticReleaseDigestV1 {
        self.semantic_release_manifest_digest
    }
    /// Normalized verification-lock digest parsed from the bundle.
    #[must_use]
    pub const fn verification_lock_digest(&self) -> MusubiVerificationLockDigestV1 {
        self.verification_lock_digest
    }
    pub(crate) fn to_stored(&self) -> StoredProviderIngestVerifiedMusubiBundleReceiptV1 {
        StoredProviderIngestVerifiedMusubiBundleReceiptV1 {
            network_id: self.network_id,
            provider_id: self.provider_id,
            observed_finalized_cursor: self.observed_finalized_cursor,
            replication_order: self.replication_order,
            manifest_digest: self.manifest_digest,
            archive_id: self.archive_id,
            commitment: self.commitment.clone(),
            semantic_release_manifest_digest: self.semantic_release_manifest_digest,
            verification_lock_digest: self.verification_lock_digest,
        }
    }
    #[cfg(test)]
    pub(crate) fn new_for_test(
        authorization: &FinalizedProviderIngestAuthorizationV1,
        commitment: MusubiArchiveCommitmentV1,
        semantic_release_manifest_digest: MusubiSemanticReleaseDigestV1,
        verification_lock_digest: MusubiVerificationLockDigestV1,
    ) -> Self {
        let context = authorization
            .musubi_context()
            .expect("test receipt requires Musubi authorization context");
        Self {
            network_id: *context.network_id(),
            provider_id: authorization.provider_id(),
            observed_finalized_cursor: authorization.admission_finalized_cursor(),
            replication_order: authorization.order_id(),
            manifest_digest: authorization.manifest_digest(),
            archive_id: context.archive_id(),
            commitment,
            semantic_release_manifest_digest,
            verification_lock_digest,
        }
    }
}
impl StoredProviderIngestVerifiedMusubiBundleReceiptV1 {
    pub(crate) const fn observed_finalized_cursor(&self) -> ProviderIngestFinalizedCursorV1 {
        self.observed_finalized_cursor
    }
    #[cfg(test)]
    pub(crate) const fn set_observed_finalized_cursor_for_test(
        &mut self,
        cursor: ProviderIngestFinalizedCursorV1,
    ) {
        self.observed_finalized_cursor = cursor;
    }
    pub(crate) fn into_receipt(self) -> ProviderIngestVerifiedMusubiBundleReceiptV1 {
        ProviderIngestVerifiedMusubiBundleReceiptV1 {
            network_id: self.network_id,
            provider_id: self.provider_id,
            observed_finalized_cursor: self.observed_finalized_cursor,
            replication_order: self.replication_order,
            manifest_digest: self.manifest_digest,
            archive_id: self.archive_id,
            commitment: self.commitment,
            semantic_release_manifest_digest: self.semantic_release_manifest_digest,
            verification_lock_digest: self.verification_lock_digest,
        }
    }
    pub(crate) fn to_receipt(&self) -> ProviderIngestVerifiedMusubiBundleReceiptV1 {
        self.clone().into_receipt()
    }
    pub(crate) fn validate_stored(
        &self,
        authorization: &FinalizedProviderIngestAuthorizationV1,
    ) -> bool {
        self.to_receipt().validate_stored(authorization)
    }
}
fn finalized_cursor_is_same_or_later(
    candidate: ProviderIngestFinalizedCursorV1,
    baseline: ProviderIngestFinalizedCursorV1,
) -> bool {
    candidate.height > baseline.height
        || candidate.height == baseline.height && candidate.block_hash == baseline.block_hash
}
fn authorization_musubi_context_matches(
    authorization: &FinalizedProviderIngestAuthorizationV1,
    network_id: &NetworkId,
    archive_id: ArchiveId,
) -> bool {
    authorization.musubi_context().is_some_and(|context| {
        context.network_id() == network_id && context.archive_id() == archive_id
    })
}
/// Exact local-storage result accepted before a completion transaction may be prepared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestLocalStoredV1 {
    manifest_id: String,
    musubi_bundle: Option<ProviderIngestVerifiedMusubiBundleReceiptV1>,
}
impl ProviderIngestLocalStoredV1 {
    /// Construct a result for an ordinary non-Musubi replication order.
    #[must_use]
    pub fn generic(manifest_id: String) -> Self {
        Self {
            manifest_id,
            musubi_bundle: None,
        }
    }
    /// Construct a result whose local payload passed the complete Musubi verifier.
    #[must_use]
    pub fn musubi(
        manifest_id: String,
        receipt: ProviderIngestVerifiedMusubiBundleReceiptV1,
    ) -> Self {
        Self {
            manifest_id,
            musubi_bundle: Some(receipt),
        }
    }
    /// Canonical local manifest identity.
    #[must_use]
    pub fn manifest_id(&self) -> &str {
        &self.manifest_id
    }
    /// Verified Musubi receipt, absent only for a generic replication order.
    #[must_use]
    pub const fn musubi_bundle(&self) -> Option<&ProviderIngestVerifiedMusubiBundleReceiptV1> {
        self.musubi_bundle.as_ref()
    }
}
/// Exact local storage boundary.
pub trait ProviderIngestLocalStorageV1<Fetched>: Send + Sync + 'static {
    /// Verify whether exact authorized material is already durable locally.
    ///
    /// A Musubi claim requires the complete semantic bundle verifier and a matching receipt.
    fn verify_existing<'a>(
        &'a self,
        authorization: FinalizedProviderIngestAuthorizationV1,
        musubi_archive: Option<ProviderIngestFinalizedMusubiArchiveClaimV1>,
    ) -> ProviderIngestFutureV1<
        'a,
        Result<Option<ProviderIngestLocalStoredV1>, ProviderIngestLocalStorageErrorV1>,
    >;
    /// Atomically store exact material, then verify any Musubi bundle from admitted storage.
    fn store<'a>(
        &'a self,
        authorization: FinalizedProviderIngestAuthorizationV1,
        musubi_archive: Option<ProviderIngestFinalizedMusubiArchiveClaimV1>,
        fetched: Fetched,
    ) -> ProviderIngestFutureV1<
        'a,
        Result<ProviderIngestLocalStoredV1, ProviderIngestLocalStorageErrorV1>,
    >;
}
/// Request for one exact fee-quoted provider completion payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestCompletionPayloadRequestV1 {
    /// Immutable provider/order/manifest authorization.
    pub authorization: FinalizedProviderIngestAuthorizationV1,
    /// Current finalized provider owner.
    pub provider_owner: AccountId,
    /// Exact finalized completion authority to compare again at commit.
    pub expected_authority: ProviderIngestCompletionAuthorityV1,
    /// Exact order-scoped assignment revision to compare again at commit.
    pub expected_assignment_revision: u64,
    /// Exact configured production network identity.
    pub network_id: NetworkId,
    /// Authoritative completion epoch.
    pub completion_epoch: u64,
    /// Finalized baseline preceding signing.
    pub finalized_cursor: ProviderIngestFinalizedCursorV1,
}
/// Completion payload construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderIngestCompletionPayloadErrorV1 {
    /// Fee quoting or payload construction is temporarily unavailable.
    Unavailable,
    /// Current policy rejects completion payload construction.
    Rejected,
}
/// Builds the exact bounded, fee-quoted transaction payload to sign.
pub trait ProviderIngestCompletionPayloadBuilderV1: Send + Sync + 'static {
    /// Build one exact completion payload.
    fn build_payload<'a>(
        &'a self,
        request: ProviderIngestCompletionPayloadRequestV1,
    ) -> ProviderIngestFutureV1<
        'a,
        Result<TransactionPayload, ProviderIngestCompletionPayloadErrorV1>,
    >;
}
/// Isolated signer failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderIngestCompletionSignerErrorV1 {
    /// Runtime-provider signing is temporarily unavailable.
    Unavailable,
    /// The signer rejected an otherwise exact prepared operation.
    Rejected,
}
/// Exact finalized authorization independently pinned while resolving a signer.
///
/// The context is carried separately from the transaction payload so an
/// isolated signer can reject payloads whose owner, completion signer, policy, assignment
/// revision, or finalized anchor was substituted after resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestCompletionSignerResolutionContextV1 {
    /// Full current provider-owner, completion-signer and policy binding.
    pub expected_authority: ProviderIngestCompletionAuthorityV1,
    /// Exact non-zero order-scoped assignment revision.
    pub expected_assignment_revision: u64,
    /// Exact finalized baseline whose anchor must appear in the completion.
    pub finalized_cursor: ProviderIngestFinalizedCursorV1,
}
impl ProviderIngestCompletionSignerResolutionContextV1 {
    /// Construct one exact signer-resolution context.
    #[must_use]
    pub fn new(
        expected_authority: ProviderIngestCompletionAuthorityV1,
        expected_assignment_revision: u64,
        finalized_cursor: ProviderIngestFinalizedCursorV1,
    ) -> Self {
        Self {
            expected_authority,
            expected_assignment_revision,
            finalized_cursor,
        }
    }
    /// Return whether every independently pinned field is production-shaped.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.expected_authority.is_valid()
            && self.expected_assignment_revision != 0
            && self.finalized_cursor.height != 0
            && self.finalized_cursor.block_hash != [0; 32]
    }
}
/// Payload-free public qualification of one provider-ingest completion signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestCompletionSignerQualificationV1 {
    /// Qualification schema version.
    pub version: u8,
    /// Non-zero signer adapter and public-policy revision.
    pub adapter_revision: u64,
    /// Exact chain-authoritative signer policy identity and digest lineage.
    pub signer_policy: ProviderIngestCompletionSignerPolicyV1,
    /// Exact admitted signature algorithm.
    pub algorithm: Algorithm,
    /// Exact public key controlled by the external signer.
    pub public_key: PublicKey,
}
impl ProviderIngestCompletionSignerQualificationV1 {
    /// Construct a first-release completion-signer qualification.
    #[must_use]
    pub fn new(
        adapter_revision: u64,
        signer_policy: ProviderIngestCompletionSignerPolicyV1,
        algorithm: Algorithm,
        public_key: PublicKey,
    ) -> Self {
        Self {
            version: PROVIDER_INGEST_COMPLETION_SIGNER_QUALIFICATION_VERSION_V1,
            adapter_revision,
            signer_policy,
            algorithm,
            public_key,
        }
    }
    /// Validate the schema, revision, policy lineage, algorithm, and public key.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, zero revision, invalid
    /// signer policy, unapproved algorithm, or algorithm/key mismatch.
    pub fn validate(&self) -> Result<(), ProviderIngestCompletionSignerBindingErrorV1> {
        let public_key = self.public_key.try_to_bytes().ok();
        if self.version != PROVIDER_INGEST_COMPLETION_SIGNER_QUALIFICATION_VERSION_V1
            || self.adapter_revision == 0
            || !self.signer_policy.is_valid()
            || !matches!(self.algorithm, Algorithm::Ed25519 | Algorithm::MlDsa)
            || public_key.is_none_or(|(algorithm, bytes)| {
                algorithm != self.algorithm
                    || bytes.is_empty()
                    || bytes.iter().all(|byte| *byte == 0)
            })
        {
            return Err(ProviderIngestCompletionSignerBindingErrorV1::InvalidSignerQualification);
        }
        Ok(())
    }
    /// Return whether the qualified public key is the exact single-key authority.
    #[must_use]
    pub fn matches_authority(&self, authority: &AccountId) -> bool {
        authority.try_signatory() == Some(&self.public_key)
    }
}
/// Independently configured public binding for one completion signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIngestCompletionSignerBindingV1 {
    /// Stable opaque signing-provider or key handle.
    pub runtime_handle: String,
    /// Exact payload-free signer qualification.
    pub qualification: ProviderIngestCompletionSignerQualificationV1,
}
impl ProviderIngestCompletionSignerBindingV1 {
    /// Pair a stable public handle with the required signer qualification.
    #[must_use]
    pub fn new(
        runtime_handle: impl Into<String>,
        qualification: ProviderIngestCompletionSignerQualificationV1,
    ) -> Self {
        Self {
            runtime_handle: runtime_handle.into(),
            qualification,
        }
    }
    /// Validate the complete configured signer binding.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-production handle or invalid qualification.
    pub fn validate(&self) -> Result<(), ProviderIngestCompletionSignerBindingErrorV1> {
        if !is_production_runtime_handle(&self.runtime_handle) {
            return Err(ProviderIngestCompletionSignerBindingErrorV1::InvalidSignerHandle);
        }
        self.qualification.validate()
    }
}
/// Invalid public binding for a provider-ingest completion signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProviderIngestCompletionSignerBindingErrorV1 {
    /// The signer handle is missing, test-marked, or otherwise not production-safe.
    #[error("provider-ingest completion-signer handle is invalid")]
    InvalidSignerHandle,
    /// The signer qualification is unsupported, zero, malformed, or inconsistent.
    #[error("provider-ingest completion-signer qualification is invalid")]
    InvalidSignerQualification,
}
/// Isolated runtime signer that has no queue or outbox access.
pub trait ProviderIngestCompletionSignerV1: Send + Sync + 'static {
    /// Stable public signing-provider or key handle.
    fn runtime_handle(&self) -> &str;
    /// Account controlled by this signer.
    fn authority(&self) -> &AccountId;
    /// Current payload-free signer qualification.
    ///
    /// # Errors
    ///
    /// Returns a fixed payload-free signer failure when the signer
    /// qualification cannot be authenticated.
    fn qualification(
        &self,
    ) -> Result<ProviderIngestCompletionSignerQualificationV1, ProviderIngestCompletionSignerErrorV1>;
    /// Exact governed policy identity under which this signer is currently
    /// eligible. Implementations must change this value on key rotation and
    /// reject signing atomically when the policy is revoked or superseded.
    fn signer_policy(&self) -> ProviderIngestCompletionSignerPolicyV1;
    /// Revalidate the live owner/key/policy authority represented by this
    /// signer and return its exact current policy identity.
    ///
    /// This method runs on the async worker thread and therefore must be a bounded, non-blocking
    /// read of a locally maintained eligibility snapshot; it must never perform signing-provider,
    /// network, filesystem, or other blocking I/O. Implementations must update that snapshot on
    /// revocation/rotation and fail closed when it is stale or unavailable. The timed
    /// [`Self::sign`] operation remains responsible for the provider-side atomic check.
    fn current_eligibility(
        &self,
    ) -> Result<ProviderIngestCompletionSignerPolicyV1, ProviderIngestCompletionSignerErrorV1>;
    /// Sign exactly the supplied payload without rewriting any field.
    fn sign<'a>(
        &'a self,
        payload: TransactionPayload,
    ) -> ProviderIngestFutureV1<'a, Result<SignedTransaction, ProviderIngestCompletionSignerErrorV1>>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CurrentSignerAuthorityErrorV1 {
    Unavailable,
    Ineligible,
    ProtocolViolation,
}
fn exact_current_signer_authority<Signer: ProviderIngestCompletionSignerV1>(
    signer: &Signer,
    expected: &ProviderIngestCompletionAuthorityV1,
) -> Result<ProviderIngestCompletionAuthorityV1, CurrentSignerAuthorityErrorV1> {
    if signer.authority() != &expected.completion_signer
        || !is_production_runtime_handle(signer.runtime_handle())
    {
        return Err(CurrentSignerAuthorityErrorV1::ProtocolViolation);
    }
    let qualification = signer.qualification().map_err(|error| match error {
        ProviderIngestCompletionSignerErrorV1::Unavailable => {
            CurrentSignerAuthorityErrorV1::Unavailable
        }
        ProviderIngestCompletionSignerErrorV1::Rejected => {
            CurrentSignerAuthorityErrorV1::Ineligible
        }
    })?;
    let policy = signer.current_eligibility().map_err(|error| match error {
        ProviderIngestCompletionSignerErrorV1::Unavailable => {
            CurrentSignerAuthorityErrorV1::Unavailable
        }
        ProviderIngestCompletionSignerErrorV1::Rejected => {
            CurrentSignerAuthorityErrorV1::Ineligible
        }
    })?;
    if qualification.validate().is_err()
        || !qualification.matches_authority(&expected.completion_signer)
        || !policy.is_valid()
    {
        return Err(CurrentSignerAuthorityErrorV1::ProtocolViolation);
    }
    if signer.signer_policy() != policy
        || qualification.signer_policy != policy
        || expected.signer_policy != policy
        || !expected.is_valid()
    {
        return Err(CurrentSignerAuthorityErrorV1::Ineligible);
    }
    Ok(expected.clone())
}
/// Signer resolution failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderIngestCompletionSignerResolverErrorV1 {
    /// Signer discovery is temporarily unavailable.
    Unavailable,
    /// The requested finalized completion authority is revoked or disallowed.
    Rejected,
}
/// Resolves the signer for one exact finalized completion authorization.
///
/// Implementations must authenticate every field in the resolution context
/// independently of the transaction payload and bind the returned signer to
/// that context for the lifetime of the signing operation.
pub trait ProviderIngestCompletionSignerResolverV1: Send + Sync + 'static {
    /// Isolated signer implementation.
    type Signer: ProviderIngestCompletionSignerV1;
    /// Resolve an eligible signer for one exact finalized authorization.
    fn resolve<'a>(
        &'a self,
        context: ProviderIngestCompletionSignerResolutionContextV1,
    ) -> ProviderIngestFutureV1<
        'a,
        Result<Option<Self::Signer>, ProviderIngestCompletionSignerResolverErrorV1>,
    >;
}
/// Queue preflight failure that occurs before transaction exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderIngestIngressPrepareErrorV1 {
    /// Queue preflight is temporarily unavailable.
    Unavailable,
    /// The exact transaction was terminally rejected before exposure.
    Rejected,
}
/// Outcome after an exact transaction may have been exposed to ingress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderIngestIngressDispositionV1 {
    /// The exact transaction is pending or applied.
    Submitted,
    /// The adapter proves exposure did not reach the queue.
    DefinitelyNotSubmitted,
    /// The exact transaction was terminally rejected.
    Rejected,
    /// Exposure may have happened and requires reconciliation.
    Ambiguous,
}
/// Observation of one exact retained transaction hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderIngestTransactionObservationV1 {
    /// The exact transaction committed and execution succeeded.
    ///
    /// This proves only the transaction-level outcome. The finalized replication-order projection
    /// remains the sole semantic completion authority.
    CommittedSuccess,
    /// The exact transaction committed but execution was rejected.
    CommittedRejected,
    /// The exact transaction remains pending or applied but unfinalized.
    Pending,
    /// The exact transaction is absent from the observed finalized/pipeline view.
    Unknown,
    /// The observation service is temporarily unavailable.
    Unavailable,
}
/// Transaction ingress split into preflight and post-durable exposure phases.
pub trait ProviderIngestTransactionIngressV1: Send + Sync + 'static {
    /// Opaque prepared queue operation that has not exposed transaction bytes.
    type Prepared: Send + 'static;
    /// Validate and prepare queue admission without exposing transaction bytes.
    fn prepare<'a>(
        &'a self,
        transaction: SignedTransaction,
    ) -> ProviderIngestFutureV1<'a, Result<Self::Prepared, ProviderIngestIngressPrepareErrorV1>>;
    /// Expose the exact transaction only after the durable ambiguous transition.
    fn expose<'a>(
        &'a self,
        prepared: Self::Prepared,
        transaction: SignedTransaction,
    ) -> ProviderIngestFutureV1<'a, ProviderIngestIngressDispositionV1>;
    /// Observe one exact retained transaction hash without mutating ingress.
    ///
    /// A committed observation must include the execution result; block/hash
    /// membership alone is not a successful semantic completion signal.
    fn observe<'a>(
        &'a self,
        transaction_hash: [u8; 32],
    ) -> ProviderIngestFutureV1<'a, ProviderIngestTransactionObservationV1>;
}
/// Runtime clock used only for leases, backoff, and timeouts.
pub trait ProviderIngestClockV1: Send + Sync + 'static {
    /// Current runtime time in milliseconds.
    fn now_ms(&self) -> u64;
}
/// Wall-clock implementation for production runtime use.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProviderIngestSystemClockV1;
impl ProviderIngestClockV1 for ProviderIngestSystemClockV1 {
    fn now_ms(&self) -> u64 {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX)
    }
}
/// Payload-free counters for one bounded runtime tick.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProviderIngestTickOutcomeV1 {
    /// Finalized rows validated.
    pub rows_scanned: usize,
    /// New durable jobs admitted.
    pub jobs_inserted: usize,
    /// Jobs reconciled to semantic finalized completion.
    pub jobs_finalized: usize,
    /// Jobs cancelled from finalized state.
    pub jobs_cancelled: usize,
    /// Source jobs claimed in this tick.
    pub source_jobs_claimed: usize,
    /// Exact manifests confirmed or stored locally.
    pub manifests_stored: usize,
    /// Completion transactions durably signed.
    pub completions_signed: usize,
    /// Completion transaction exposure attempts.
    pub completion_submissions: usize,
}
/// Supervised provider-ingest runtime.
pub struct ProviderIngestRuntimeV1<Ledger, Fetch, Storage, Builder, Resolver, Ingress, Clock>
where
    Ledger: ProviderIngestFinalizedLedgerV1,
    Fetch: ProviderIngestAuthenticatedSourceFetchV1,
    Storage: ProviderIngestLocalStorageV1<Fetch::Fetched>,
    Builder: ProviderIngestCompletionPayloadBuilderV1,
    Resolver: ProviderIngestCompletionSignerResolverV1,
    Ingress: ProviderIngestTransactionIngressV1,
    Clock: ProviderIngestClockV1,
{
    provider_id: [u8; 32],
    network_id: NetworkId,
    claim_owner: ProviderIngestClaimOwnerV1,
    policy: ProviderIngestRuntimePolicyV1,
    outbox: ProviderIngestOutbox,
    ledger: Arc<Ledger>,
    fetch: Arc<Fetch>,
    storage: Arc<Storage>,
    payload_builder: Arc<Builder>,
    signer_resolver: Arc<Resolver>,
    ingress: Arc<Ingress>,
    clock: Arc<Clock>,
    last_finalized_cursor: Option<ProviderIngestFinalizedCursorV1>,
    scan_cursor: Option<ProviderIngestFinalizedCursorV1>,
    scan_after_order_id: Option<[u8; 32]>,
}
impl<Ledger, Fetch, Storage, Builder, Resolver, Ingress, Clock>
    ProviderIngestRuntimeV1<Ledger, Fetch, Storage, Builder, Resolver, Ingress, Clock>
where
    Ledger: ProviderIngestFinalizedLedgerV1,
    Fetch: ProviderIngestAuthenticatedSourceFetchV1,
    Storage: ProviderIngestLocalStorageV1<Fetch::Fetched>,
    Builder: ProviderIngestCompletionPayloadBuilderV1,
    Resolver: ProviderIngestCompletionSignerResolverV1,
    Ingress: ProviderIngestTransactionIngressV1,
    Clock: ProviderIngestClockV1,
{
    /// Construct a bounded runtime from explicit production dependencies.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_id: [u8; 32],
        network_id: NetworkId,
        claim_owner: ProviderIngestClaimOwnerV1,
        policy: ProviderIngestRuntimePolicyV1,
        outbox: ProviderIngestOutbox,
        ledger: Arc<Ledger>,
        fetch: Arc<Fetch>,
        storage: Arc<Storage>,
        payload_builder: Arc<Builder>,
        signer_resolver: Arc<Resolver>,
        ingress: Arc<Ingress>,
        clock: Arc<Clock>,
    ) -> Result<Self, ProviderIngestRuntimeErrorV1> {
        if provider_id == [0; 32] {
            return Err(ProviderIngestRuntimeErrorV1::InvalidProviderId);
        }
        if network_id.as_bytes()[31] & 1 != 1 {
            return Err(ProviderIngestRuntimeErrorV1::InvalidNetworkId);
        }
        policy.validate(&outbox)?;
        let last_finalized_cursor = outbox.finalized_cursor_high_water()?;
        Ok(Self {
            provider_id,
            network_id,
            claim_owner,
            policy,
            outbox,
            ledger,
            fetch,
            storage,
            payload_builder,
            signer_resolver,
            ingress,
            clock,
            last_finalized_cursor,
            scan_cursor: None,
            scan_after_order_id: None,
        })
    }
    /// Run until shutdown or a fatal supervised-runtime error.
    pub async fn run(
        mut self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), ProviderIngestRuntimeErrorV1> {
        if *shutdown.borrow() {
            return Ok(());
        }
        let mut interval =
            tokio::time::interval(Duration::from_millis(self.policy.scan_interval_ms));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
                _ = interval.tick() => {
                    let shutdown_requested = std::sync::atomic::AtomicBool::new(false);
                    let tick = self.tick_with_shutdown(&shutdown_requested);
                    tokio::pin!(tick);
                    let mut stop_after_tick = false;
                    loop {
                        tokio::select! {
                            result = &mut tick => {
                                result?;
                                break;
                            }
                            changed = shutdown.changed(), if !stop_after_tick => {
                                if changed.is_err() || *shutdown.borrow() {
                                    shutdown_requested.store(
                                        true,
                                        std::sync::atomic::Ordering::Release,
                                    );
                                    stop_after_tick = true;
                                }
                            }
                        }
                    }
                    if stop_after_tick {
                        return Ok(());
                    }
                }
            }
        }
    }
    /// Execute one bounded finalized scan and delivery pass.
    pub async fn tick(
        &mut self,
    ) -> Result<ProviderIngestTickOutcomeV1, ProviderIngestRuntimeErrorV1> {
        self.tick_inner(None).await
    }
    /// Execute one bounded scan while honoring a cooperative shutdown request.
    ///
    /// The current row always runs to a durable boundary. A request observed
    /// between rows or pages prevents additional work from starting, so callers
    /// may keep polling this same future after selecting their shutdown signal
    /// without detaching a source claim or an in-flight storage mutation.
    pub async fn tick_with_shutdown(
        &mut self,
        shutdown_requested: &std::sync::atomic::AtomicBool,
    ) -> Result<ProviderIngestTickOutcomeV1, ProviderIngestRuntimeErrorV1> {
        self.tick_inner(Some(shutdown_requested)).await
    }
    async fn tick_inner(
        &mut self,
        shutdown_requested: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<ProviderIngestTickOutcomeV1, ProviderIngestRuntimeErrorV1> {
        let mut outcome = ProviderIngestTickOutcomeV1::default();
        let mut source_budget = self.policy.max_source_jobs_per_tick;
        let mut after = self.scan_after_order_id;
        let mut expected_cursor = self.scan_cursor;
        let mut recovered_interrupted_signing = false;
        for _ in 0..self.policy.max_pages_per_tick {
            if shutdown_requested
                .is_some_and(|requested| requested.load(std::sync::atomic::Ordering::Acquire))
            {
                return Ok(outcome);
            }
            let page = self
                .ledger
                .read_assignment_page(
                    ProviderIngestFinalizedClaimFactoryV1::new(self.network_id, self.provider_id),
                    expected_cursor,
                    after,
                    self.policy.max_page_rows,
                )
                .await
                .map_err(|_| ProviderIngestRuntimeErrorV1::FinalizedLedgerUnavailable)?;
            if after.is_some()
                && expected_cursor.is_some_and(|cursor| cursor != page.finalized_cursor)
            {
                return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedPage);
            }
            let cursor = expected_cursor.unwrap_or(page.finalized_cursor);
            validate_page(&page, after, cursor, self.policy.max_page_rows)?;
            validate_monotonic_finalized_cursor(self.last_finalized_cursor, cursor)?;
            self.outbox
                .observe_finalized_snapshot(cursor, page.finalized_block_time_ms)?;
            self.last_finalized_cursor = Some(cursor);
            expected_cursor = Some(cursor);
            if !recovered_interrupted_signing {
                self.outbox
                    .recover_expired_completion_signing(self.clock.now_ms(), cursor)?;
                recovered_interrupted_signing = true;
            }
            let finalized_block_time_ms = page.finalized_block_time_ms;
            for row in page.rows {
                if shutdown_requested
                    .is_some_and(|requested| requested.load(std::sync::atomic::Ordering::Acquire))
                {
                    return Ok(outcome);
                }
                outcome.rows_scanned = outcome.rows_scanned.saturating_add(1);
                self.process_row(
                    row,
                    cursor,
                    finalized_block_time_ms,
                    &mut source_budget,
                    &mut outcome,
                )
                .await?;
            }
            after = page.next_after_order_id;
            if after.is_none() {
                self.scan_after_order_id = None;
                self.scan_cursor = None;
                return Ok(outcome);
            }
        }
        self.scan_after_order_id = after;
        self.scan_cursor = expected_cursor;
        Ok(outcome)
    }
    #[allow(clippy::too_many_lines)]
    async fn process_row(
        &self,
        row: ProviderIngestFinalizedAssignmentV1,
        cursor: ProviderIngestFinalizedCursorV1,
        finalized_block_time_ms: u64,
        source_budget: &mut usize,
        outcome: &mut ProviderIngestTickOutcomeV1,
    ) -> Result<(), ProviderIngestRuntimeErrorV1> {
        let ValidatedAssignmentV1 {
            authorization,
            source_provider_ids,
            musubi_archive,
        } = validate_assignment(
            &row,
            cursor,
            self.provider_id,
            &self.network_id,
            self.policy,
        )?;
        let job_id = authorization.job_id();
        let provider_id = ProviderId::new(self.provider_id);
        if let Some(completion) = row.order.provider_completion(provider_id) {
            self.outbox.reconcile_finalized_completion(
                authorization,
                ProviderIngestFinalizedCompletionV1 {
                    finalized_cursor: cursor,
                    provider_id: self.provider_id,
                    order_id: *row.order.order_id.as_bytes(),
                    manifest_digest: *row.order.manifest_digest.as_bytes(),
                    completion_epoch: completion.completion_epoch,
                    completed_by: completion.completed_by.clone(),
                    committed_transaction_hash: row.committed_transaction_hash,
                },
            )?;
            outcome.jobs_finalized = outcome.jobs_finalized.saturating_add(1);
            return Ok(());
        }
        let cancellation_reason = match row.order.status {
            ReplicationOrderStatus::Cancelled(_) => {
                Some(ProviderIngestCancellationReasonV1::ManifestRetired)
            }
            ReplicationOrderStatus::Expired(_) => {
                Some(ProviderIngestCancellationReasonV1::OrderExpired)
            }
            ReplicationOrderStatus::Completed(_) => {
                Some(ProviderIngestCancellationReasonV1::OrderCompletedByOther)
            }
            ReplicationOrderStatus::Pending => None,
        };
        if let Some(reason) = cancellation_reason {
            self.outbox.reconcile_finalized_cancellation(
                authorization,
                ProviderIngestFinalizedCancellationV1 {
                    finalized_cursor: cursor,
                    provider_id: self.provider_id,
                    order_id: *row.order.order_id.as_bytes(),
                    manifest_digest: *row.order.manifest_digest.as_bytes(),
                    reason,
                },
            )?;
            outcome.jobs_cancelled = outcome.jobs_cancelled.saturating_add(1);
            return Ok(());
        }
        if !matches!(row.pin.manifest.status, PinStatus::Approved(_))
            || !matches!(row.order.status, ReplicationOrderStatus::Pending)
        {
            return Ok(());
        }
        let enqueue = self.outbox.enqueue(authorization.clone())?;
        if matches!(
            enqueue,
            crate::provider_ingest_outbox::ProviderIngestEnqueueResultV1::Inserted { .. }
        ) {
            outcome.jobs_inserted = outcome.jobs_inserted.saturating_add(1);
        }
        // The job identity deliberately excludes the finalized cursor so an unchanged
        // assignment can resume after the head advances. Every source/storage transition must
        // therefore use the exact authorization retained by the outbox, while the freshly
        // sealed Musubi claim proves that binding still exists at the newer scan cursor.
        let authorization = self.outbox.authorization(job_id)?;
        let status = self.outbox.status(job_id)?;
        match status.state {
            ProviderIngestDeliveryStateV1::PendingSource { .. }
            | ProviderIngestDeliveryStateV1::RetryScheduled { .. }
            | ProviderIngestDeliveryStateV1::SourceClaimed { .. }
                if *source_budget != 0 =>
            {
                if self
                    .process_source(
                        authorization.clone(),
                        source_provider_ids,
                        musubi_archive.clone(),
                        cursor,
                        outcome,
                    )
                    .await?
                {
                    *source_budget -= 1;
                    if let Ok(status) = self.outbox.status(job_id)
                        && let ProviderIngestDeliveryStateV1::LocalStored {
                            musubi_bundle,
                            completion,
                            ..
                        } = status.state
                    {
                        if !persisted_receipt_matches(
                            &authorization,
                            musubi_archive.as_ref(),
                            musubi_bundle.as_deref(),
                        ) {
                            return Err(ProviderIngestRuntimeErrorV1::StorageProtocolViolation);
                        }
                        self.process_completion(
                            &row,
                            status.job_id,
                            completion,
                            cursor,
                            finalized_block_time_ms,
                            outcome,
                        )
                        .await?;
                    }
                }
            }
            ProviderIngestDeliveryStateV1::LocalStored {
                musubi_bundle,
                completion,
                ..
            } => {
                if !persisted_receipt_matches(
                    &authorization,
                    musubi_archive.as_ref(),
                    musubi_bundle.as_deref(),
                ) {
                    return Err(ProviderIngestRuntimeErrorV1::StorageProtocolViolation);
                }
                self.process_completion(
                    &row,
                    status.job_id,
                    completion,
                    cursor,
                    finalized_block_time_ms,
                    outcome,
                )
                .await?;
            }
            ProviderIngestDeliveryStateV1::PendingSource { .. }
            | ProviderIngestDeliveryStateV1::RetryScheduled { .. }
            | ProviderIngestDeliveryStateV1::SourceClaimed { .. }
            | ProviderIngestDeliveryStateV1::FinalizedCompleted { .. }
            | ProviderIngestDeliveryStateV1::Cancelled { .. }
            | ProviderIngestDeliveryStateV1::DeadLetter { .. } => {}
        }
        Ok(())
    }
    #[allow(clippy::too_many_lines)]
    async fn process_source(
        &self,
        authorization: FinalizedProviderIngestAuthorizationV1,
        source_provider_ids: Vec<[u8; 32]>,
        musubi_archive: Option<ProviderIngestFinalizedMusubiArchiveClaimV1>,
        cursor: ProviderIngestFinalizedCursorV1,
        outcome: &mut ProviderIngestTickOutcomeV1,
    ) -> Result<bool, ProviderIngestRuntimeErrorV1> {
        // This is intentionally the pre-completion path. Finalized completed
        // rows are independently scanned and reverified by the completed-Musubi
        // capture driver before an approval-only attestation enters its journal;
        // neither this claim nor its receipt authorizes one.
        let claim = match self.outbox.claim_source(
            authorization.job_id(),
            self.claim_owner,
            self.clock.now_ms(),
            cursor,
        ) {
            Ok(claim) => claim,
            Err(
                ProviderIngestOutboxError::RetryNotDue
                | ProviderIngestOutboxError::LeaseAlreadyHeld
                | ProviderIngestOutboxError::InvalidTransition
                | ProviderIngestOutboxError::RetryExhausted,
            ) => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        outcome.source_jobs_claimed = outcome.source_jobs_claimed.saturating_add(1);
        let verify = self
            .storage
            .verify_existing(authorization.clone(), musubi_archive.clone());
        let (claim, existing) = self.await_with_lease(claim, cursor, verify).await?;
        match existing {
            LeaseOperationOutcomeV1::Completed(Ok(Some(stored))) => {
                if !local_stored_matches(&stored, &authorization, musubi_archive.as_ref()) {
                    self.outbox.dead_letter_source(
                        &claim,
                        self.clock.now_ms(),
                        cursor,
                        ProviderIngestDeadLetterReasonV1::StorageRejected,
                        ProviderIngestFailureClassV1::BindingMismatch,
                    )?;
                    return Err(ProviderIngestRuntimeErrorV1::StorageProtocolViolation);
                }
                if let Err(error) = self.outbox.mark_local_stored_verified(
                    &claim,
                    self.clock.now_ms(),
                    stored.manifest_id().to_owned(),
                    stored.musubi_bundle().cloned(),
                ) {
                    if error == ProviderIngestOutboxError::InvalidManifestId {
                        self.outbox.dead_letter_source(
                            &claim,
                            self.clock.now_ms(),
                            cursor,
                            ProviderIngestDeadLetterReasonV1::StorageRejected,
                            ProviderIngestFailureClassV1::StorageRejected,
                        )?;
                        return Err(ProviderIngestRuntimeErrorV1::StorageProtocolViolation);
                    }
                    return Err(error.into());
                }
                outcome.manifests_stored = outcome.manifests_stored.saturating_add(1);
                return Ok(true);
            }
            LeaseOperationOutcomeV1::Completed(Ok(None)) => {}
            LeaseOperationOutcomeV1::Completed(Err(error)) => {
                self.handle_storage_failure(claim, cursor, error)?;
                return Ok(true);
            }
            LeaseOperationOutcomeV1::TimedOut => {
                self.outbox.schedule_source_retry(
                    &claim,
                    self.clock.now_ms(),
                    cursor,
                    ProviderIngestFailureClassV1::StorageRejected,
                )?;
                return Ok(true);
            }
        }
        if source_provider_ids.is_empty() {
            self.outbox.schedule_source_retry(
                &claim,
                self.clock.now_ms(),
                cursor,
                ProviderIngestFailureClassV1::SourceUnavailable,
            )?;
            return Ok(true);
        }
        let request = match ProviderIngestSourceRequestV1::new(
            authorization.clone(),
            source_provider_ids,
            musubi_archive
                .as_ref()
                .map(ProviderIngestMusubiArchiveFetchBindingV1::from_finalized_claim),
        ) {
            Ok(request) => request,
            Err(_) => {
                self.outbox.schedule_source_retry(
                    &claim,
                    self.clock.now_ms(),
                    cursor,
                    ProviderIngestFailureClassV1::SourceRejected,
                )?;
                return Err(ProviderIngestRuntimeErrorV1::SourceProtocolViolation);
            }
        };
        let fetch = self.fetch.fetch(request);
        let (claim, fetched) = self.await_with_lease(claim, cursor, fetch).await?;
        let fetched = match fetched {
            LeaseOperationOutcomeV1::Completed(Ok(fetched)) => fetched,
            LeaseOperationOutcomeV1::Completed(Err(
                ProviderIngestSourceFetchErrorV1::Unavailable,
            ))
            | LeaseOperationOutcomeV1::TimedOut => {
                self.outbox.schedule_source_retry(
                    &claim,
                    self.clock.now_ms(),
                    cursor,
                    ProviderIngestFailureClassV1::SourceUnavailable,
                )?;
                return Ok(true);
            }
            LeaseOperationOutcomeV1::Completed(Err(
                ProviderIngestSourceFetchErrorV1::ContentRejected,
            )) => {
                self.outbox.schedule_source_retry(
                    &claim,
                    self.clock.now_ms(),
                    cursor,
                    ProviderIngestFailureClassV1::SourceRejected,
                )?;
                return Ok(true);
            }
            LeaseOperationOutcomeV1::Completed(Err(ProviderIngestSourceFetchErrorV1::Rejected)) => {
                self.outbox.schedule_source_retry(
                    &claim,
                    self.clock.now_ms(),
                    cursor,
                    ProviderIngestFailureClassV1::SourceRejected,
                )?;
                return Err(ProviderIngestRuntimeErrorV1::SourceProtocolViolation);
            }
        };
        let store = self
            .storage
            .store(authorization.clone(), musubi_archive.clone(), fetched);
        let (claim, stored) = self
            .await_mutating_storage_with_lease(claim, cursor, store)
            .await?;
        let stored = match stored {
            MutatingStorageOutcomeV1::Completed(output)
            | MutatingStorageOutcomeV1::CompletedAfterSoftTimeout(output) => output,
        };
        match stored {
            Ok(stored) => {
                if !local_stored_matches(&stored, &authorization, musubi_archive.as_ref()) {
                    self.outbox.dead_letter_source(
                        &claim,
                        self.clock.now_ms(),
                        cursor,
                        ProviderIngestDeadLetterReasonV1::StorageRejected,
                        ProviderIngestFailureClassV1::BindingMismatch,
                    )?;
                    return Err(ProviderIngestRuntimeErrorV1::StorageProtocolViolation);
                }
                if let Err(error) = self.outbox.mark_local_stored_verified(
                    &claim,
                    self.clock.now_ms(),
                    stored.manifest_id().to_owned(),
                    stored.musubi_bundle().cloned(),
                ) {
                    if error == ProviderIngestOutboxError::InvalidManifestId {
                        self.outbox.dead_letter_source(
                            &claim,
                            self.clock.now_ms(),
                            cursor,
                            ProviderIngestDeadLetterReasonV1::StorageRejected,
                            ProviderIngestFailureClassV1::StorageRejected,
                        )?;
                        return Err(ProviderIngestRuntimeErrorV1::StorageProtocolViolation);
                    }
                    return Err(error.into());
                }
                outcome.manifests_stored = outcome.manifests_stored.saturating_add(1);
            }
            Err(error) => {
                self.handle_storage_failure(claim, cursor, error)?;
            }
        }
        Ok(true)
    }
    fn handle_storage_failure(
        &self,
        claim: ProviderIngestSourceClaimV1,
        cursor: ProviderIngestFinalizedCursorV1,
        error: ProviderIngestLocalStorageErrorV1,
    ) -> Result<(), ProviderIngestRuntimeErrorV1> {
        match error {
            ProviderIngestLocalStorageErrorV1::Retryable => {
                self.outbox.schedule_source_retry(
                    &claim,
                    self.clock.now_ms(),
                    cursor,
                    ProviderIngestFailureClassV1::StorageRejected,
                )?;
            }
            ProviderIngestLocalStorageErrorV1::Permanent
            | ProviderIngestLocalStorageErrorV1::Quarantined => {
                self.outbox.dead_letter_source(
                    &claim,
                    self.clock.now_ms(),
                    cursor,
                    ProviderIngestDeadLetterReasonV1::StorageRejected,
                    ProviderIngestFailureClassV1::StorageRejected,
                )?;
            }
        }
        Ok(())
    }
    async fn await_with_lease<T, Fut>(
        &self,
        mut claim: ProviderIngestSourceClaimV1,
        cursor: ProviderIngestFinalizedCursorV1,
        future: Fut,
    ) -> Result<
        (ProviderIngestSourceClaimV1, LeaseOperationOutcomeV1<T>),
        ProviderIngestRuntimeErrorV1,
    >
    where
        Fut: Future<Output = T> + Send,
    {
        let future = future;
        tokio::pin!(future);
        let timeout = tokio::time::sleep(Duration::from_millis(
            self.policy.source_operation_timeout_ms,
        ));
        tokio::pin!(timeout);
        let renew_period = Duration::from_millis(self.policy.source_lease_renew_interval_ms);
        let mut renewal =
            tokio::time::interval_at(tokio::time::Instant::now() + renew_period, renew_period);
        renewal.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = renewal.tick() => {
                    claim = self.outbox.renew_source_claim(
                        &claim,
                        self.clock.now_ms(),
                        cursor,
                    )?;
                }
                output = &mut future => {
                    return Ok((claim, LeaseOperationOutcomeV1::Completed(output)));
                }
                _ = &mut timeout => {
                    return Ok((claim, LeaseOperationOutcomeV1::TimedOut));
                }
            }
        }
    }
    /// Await an in-flight atomic storage mutation without ever detaching it.
    ///
    /// The configured operation timeout is a soft diagnostic boundary for mutating storage. Once
    /// storage may be writing, the runtime keeps the durable claim renewed and waits for the exact
    /// operation to finish before it can persist success or schedule a retry. This prevents a
    /// timed-out blocking writer from racing a replacement attempt.
    async fn await_mutating_storage_with_lease<T, Fut>(
        &self,
        mut claim: ProviderIngestSourceClaimV1,
        cursor: ProviderIngestFinalizedCursorV1,
        future: Fut,
    ) -> Result<
        (ProviderIngestSourceClaimV1, MutatingStorageOutcomeV1<T>),
        ProviderIngestRuntimeErrorV1,
    >
    where
        Fut: Future<Output = T> + Send,
    {
        let future = future;
        tokio::pin!(future);
        let soft_timeout = tokio::time::sleep(Duration::from_millis(
            self.policy.source_operation_timeout_ms,
        ));
        tokio::pin!(soft_timeout);
        let renew_period = Duration::from_millis(self.policy.source_lease_renew_interval_ms);
        let mut renewal =
            tokio::time::interval_at(tokio::time::Instant::now() + renew_period, renew_period);
        renewal.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut exceeded_soft_timeout = false;
        loop {
            tokio::select! {
                biased;
                _ = renewal.tick() => {
                    claim = self.outbox.renew_source_claim(
                        &claim,
                        self.clock.now_ms(),
                        cursor,
                    )?;
                }
                output = &mut future => {
                    let outcome = if exceeded_soft_timeout {
                        MutatingStorageOutcomeV1::CompletedAfterSoftTimeout(output)
                    } else {
                        MutatingStorageOutcomeV1::Completed(output)
                    };
                    return Ok((claim, outcome));
                }
                _ = &mut soft_timeout, if !exceeded_soft_timeout => {
                    exceeded_soft_timeout = true;
                }
            }
        }
    }
    #[allow(clippy::too_many_lines)]
    async fn process_completion(
        &self,
        row: &ProviderIngestFinalizedAssignmentV1,
        job_id: [u8; 32],
        completion: ProviderIngestCompletionStateV1,
        cursor: ProviderIngestFinalizedCursorV1,
        finalized_block_time_ms: u64,
        outcome: &mut ProviderIngestTickOutcomeV1,
    ) -> Result<(), ProviderIngestRuntimeErrorV1> {
        let mut completion = completion;
        let mut exposed_absent_transaction = None;
        let completion_authority = row.completion_authority.as_ref().filter(|binding| {
            binding.is_valid() && row.provider_owner.as_ref() == Some(&binding.provider_owner)
        });
        // Bytes that may already have crossed the queue boundary are always
        // reconciled by exact hash before any signing-provider dependency is queried.
        match &completion {
            ProviderIngestCompletionStateV1::Ambiguous {
                baseline_finalized_cursor,
                transaction_hash,
                ..
            } => {
                self.reconcile_transaction(
                    job_id,
                    *transaction_hash,
                    *baseline_finalized_cursor,
                    cursor,
                    true,
                )
                .await?;
                return Ok(());
            }
            ProviderIngestCompletionStateV1::Submitted {
                baseline_finalized_cursor,
                transaction_hash,
                ..
            } => {
                self.reconcile_transaction(
                    job_id,
                    *transaction_hash,
                    *baseline_finalized_cursor,
                    cursor,
                    false,
                )
                .await?;
                return Ok(());
            }
            ProviderIngestCompletionStateV1::Ready { .. }
            | ProviderIngestCompletionStateV1::Signing { .. }
            | ProviderIngestCompletionStateV1::Signed { .. } => {}
        }
        if let ProviderIngestCompletionStateV1::Signed {
            baseline_finalized_cursor,
            transaction_hash,
            ever_exposed: true,
            ..
        } = &completion
        {
            let observation = tokio::time::timeout(
                Duration::from_millis(self.policy.ingress_timeout_ms),
                self.ingress.observe(*transaction_hash),
            )
            .await
            .unwrap_or(ProviderIngestTransactionObservationV1::Unavailable);
            match observation {
                ProviderIngestTransactionObservationV1::CommittedSuccess
                | ProviderIngestTransactionObservationV1::Pending => {
                    self.outbox
                        .mark_exposed_completion_observed(job_id, *transaction_hash)?;
                    return Ok(());
                }
                ProviderIngestTransactionObservationV1::CommittedRejected => {
                    self.outbox.mark_completion_transaction_rejected(
                        job_id,
                        *transaction_hash,
                        self.clock.now_ms(),
                        cursor,
                    )?;
                    return Ok(());
                }
                ProviderIngestTransactionObservationV1::Unknown => {
                    if cursor.height > baseline_finalized_cursor.height {
                        exposed_absent_transaction = Some(*transaction_hash);
                    }
                }
                ProviderIngestTransactionObservationV1::Unavailable => return Ok(()),
            }
        }
        let mut submission_authority = None;
        let mut checked_authority = None;
        if matches!(
            &completion,
            ProviderIngestCompletionStateV1::Signing { .. }
                | ProviderIngestCompletionStateV1::Signed { .. }
        ) {
            if completion_authority.is_none() {
                self.outbox.invalidate_stale_completion_authority(
                    job_id,
                    row.provider_owner.as_ref(),
                    &ProviderIngestCompletionAuthorityObservationV1::Missing,
                    self.clock.now_ms(),
                    cursor,
                )?;
                return Ok(());
            }
            self.outbox.invalidate_stale_completion_authority(
                job_id,
                row.provider_owner.as_ref(),
                &ProviderIngestCompletionAuthorityObservationV1::NotChecked,
                self.clock.now_ms(),
                cursor,
            )?;
            completion = match self.outbox.status(job_id)?.state {
                ProviderIngestDeliveryStateV1::LocalStored { completion, .. } => completion,
                ProviderIngestDeliveryStateV1::PendingSource { .. }
                | ProviderIngestDeliveryStateV1::SourceClaimed { .. }
                | ProviderIngestDeliveryStateV1::RetryScheduled { .. }
                | ProviderIngestDeliveryStateV1::FinalizedCompleted { .. }
                | ProviderIngestDeliveryStateV1::Cancelled { .. }
                | ProviderIngestDeliveryStateV1::DeadLetter { .. } => return Ok(()),
            };
        }
        if matches!(
            &completion,
            ProviderIngestCompletionStateV1::Signing { .. }
                | ProviderIngestCompletionStateV1::Signed { .. }
        ) {
            if let Some(provider_owner) = row.provider_owner.clone() {
                let Some(expected_authority) = completion_authority.cloned() else {
                    return Ok(());
                };
                let authority_observation = match tokio::time::timeout(
                    Duration::from_millis(self.policy.signer_timeout_ms),
                    self.signer_resolver.resolve(
                        ProviderIngestCompletionSignerResolutionContextV1::new(
                            expected_authority.clone(),
                            row.order.assignment_revision,
                            cursor,
                        ),
                    ),
                )
                .await
                {
                    Ok(Ok(Some(signer))) => {
                        match exact_current_signer_authority(&signer, &expected_authority) {
                            Ok(signer_authority) => {
                                if signer_authority == expected_authority {
                                    submission_authority = Some(signer_authority.clone());
                                }
                                ProviderIngestCompletionAuthorityObservationV1::Active(
                                    signer_authority,
                                )
                            }
                            Err(CurrentSignerAuthorityErrorV1::Ineligible) => {
                                ProviderIngestCompletionAuthorityObservationV1::Missing
                            }
                            Err(CurrentSignerAuthorityErrorV1::Unavailable) => return Ok(()),
                            Err(CurrentSignerAuthorityErrorV1::ProtocolViolation) => {
                                return Err(ProviderIngestRuntimeErrorV1::SignerProtocolViolation);
                            }
                        }
                    }
                    Ok(Ok(None))
                    | Ok(Err(ProviderIngestCompletionSignerResolverErrorV1::Rejected)) => {
                        ProviderIngestCompletionAuthorityObservationV1::Missing
                    }
                    Ok(Err(ProviderIngestCompletionSignerResolverErrorV1::Unavailable))
                    | Err(_) => {
                        return Ok(());
                    }
                };
                checked_authority = Some(authority_observation.clone());
                self.outbox.invalidate_stale_completion_authority(
                    job_id,
                    Some(&provider_owner),
                    &authority_observation,
                    self.clock.now_ms(),
                    cursor,
                )?;
                completion = match self.outbox.status(job_id)?.state {
                    ProviderIngestDeliveryStateV1::LocalStored { completion, .. } => completion,
                    ProviderIngestDeliveryStateV1::PendingSource { .. }
                    | ProviderIngestDeliveryStateV1::SourceClaimed { .. }
                    | ProviderIngestDeliveryStateV1::RetryScheduled { .. }
                    | ProviderIngestDeliveryStateV1::FinalizedCompleted { .. }
                    | ProviderIngestDeliveryStateV1::Cancelled { .. }
                    | ProviderIngestDeliveryStateV1::DeadLetter { .. } => return Ok(()),
                };
            } else {
                checked_authority =
                    Some(ProviderIngestCompletionAuthorityObservationV1::NotChecked);
            }
        }
        if let Some(transaction_hash) = exposed_absent_transaction
            && self
                .outbox
                .expire_absent_exposed_completion(ProviderIngestExposedCompletionExpiryV1 {
                    job_id,
                    expected_transaction_hash: transaction_hash,
                    current_provider_owner: row.provider_owner.as_ref(),
                    current_authority: checked_authority
                        .as_ref()
                        .unwrap_or(&ProviderIngestCompletionAuthorityObservationV1::NotChecked),
                    runtime_now_ms: self.clock.now_ms(),
                    finalized_block_time_ms,
                    observed_finalized_cursor: cursor,
                })?
                .is_some()
        {
            return Ok(());
        }
        match completion {
            ProviderIngestCompletionStateV1::Ready {
                next_attempt_at_ms, ..
            } => {
                let (Some(completion_authority), Some(completion_epoch)) =
                    (completion_authority.cloned(), row.completion_epoch)
                else {
                    return Ok(());
                };
                let provider_owner = completion_authority.provider_owner.clone();
                if completion_epoch < row.order.issued_epoch
                    || completion_epoch > row.order.deadline_epoch
                {
                    return Ok(());
                }
                let owner_changed = self.outbox.reconcile_ready_completion_owner(
                    job_id,
                    &provider_owner,
                    cursor,
                )?;
                if !owner_changed && self.clock.now_ms() < next_attempt_at_ms {
                    return Ok(());
                }
                let signer = match tokio::time::timeout(
                    Duration::from_millis(self.policy.signer_timeout_ms),
                    self.signer_resolver.resolve(
                        ProviderIngestCompletionSignerResolutionContextV1::new(
                            completion_authority.clone(),
                            row.order.assignment_revision,
                            cursor,
                        ),
                    ),
                )
                .await
                {
                    Ok(Ok(Some(signer))) => signer,
                    Ok(Ok(None))
                    | Ok(Err(ProviderIngestCompletionSignerResolverErrorV1::Rejected)) => {
                        self.outbox.record_completion_signer_policy_missing(
                            job_id,
                            &provider_owner,
                            self.clock.now_ms(),
                            cursor,
                        )?;
                        return Ok(());
                    }
                    Ok(Err(ProviderIngestCompletionSignerResolverErrorV1::Unavailable))
                    | Err(_) => {
                        self.outbox.record_completion_signer_resolution_failure(
                            job_id,
                            self.clock.now_ms(),
                            cursor,
                        )?;
                        return Ok(());
                    }
                };
                let signer_authority =
                    match exact_current_signer_authority(&signer, &completion_authority) {
                        Ok(policy) => policy,
                        Err(CurrentSignerAuthorityErrorV1::Unavailable) => {
                            self.outbox.record_completion_signer_resolution_failure(
                                job_id,
                                self.clock.now_ms(),
                                cursor,
                            )?;
                            return Ok(());
                        }
                        Err(CurrentSignerAuthorityErrorV1::Ineligible) => {
                            self.outbox.record_completion_signer_policy_missing(
                                job_id,
                                &provider_owner,
                                self.clock.now_ms(),
                                cursor,
                            )?;
                            return Ok(());
                        }
                        Err(CurrentSignerAuthorityErrorV1::ProtocolViolation) => {
                            self.outbox.record_completion_signer_resolution_failure(
                                job_id,
                                self.clock.now_ms(),
                                cursor,
                            )?;
                            return Err(ProviderIngestRuntimeErrorV1::SignerProtocolViolation);
                        }
                    };
                if signer_authority != completion_authority {
                    self.outbox.record_completion_signer_policy_missing(
                        job_id,
                        &provider_owner,
                        self.clock.now_ms(),
                        cursor,
                    )?;
                    return Ok(());
                }
                if let Err(error) = self.outbox.validate_ready_completion_authority(
                    job_id,
                    &provider_owner,
                    &signer_authority,
                    cursor,
                ) {
                    self.outbox.record_completion_signer_resolution_failure(
                        job_id,
                        self.clock.now_ms(),
                        cursor,
                    )?;
                    return Err(error.into());
                }
                let status = self.outbox.status(job_id)?;
                let request = ProviderIngestCompletionPayloadRequestV1 {
                    authorization: authorization_from_status_and_row(&status, row, cursor)?,
                    provider_owner: provider_owner.clone(),
                    expected_authority: completion_authority.clone(),
                    expected_assignment_revision: row.order.assignment_revision,
                    network_id: self.network_id,
                    completion_epoch,
                    finalized_cursor: cursor,
                };
                let payload = match tokio::time::timeout(
                    Duration::from_millis(self.policy.signer_timeout_ms),
                    self.payload_builder.build_payload(request),
                )
                .await
                {
                    Ok(Ok(payload)) => payload,
                    Ok(Err(
                        ProviderIngestCompletionPayloadErrorV1::Unavailable
                        | ProviderIngestCompletionPayloadErrorV1::Rejected,
                    ))
                    | Err(_) => {
                        self.outbox.record_completion_preparation_failure(
                            job_id,
                            self.clock.now_ms(),
                            cursor,
                        )?;
                        return Ok(());
                    }
                };
                let Some(network_id) = payload.network_id().copied() else {
                    self.outbox.record_completion_preparation_failure(
                        job_id,
                        self.clock.now_ms(),
                        cursor,
                    )?;
                    return Ok(());
                };
                if network_id != self.network_id {
                    self.outbox.record_completion_preparation_failure(
                        job_id,
                        self.clock.now_ms(),
                        cursor,
                    )?;
                    return Ok(());
                }
                let context = ProviderIngestCompletionSigningContextV1 {
                    baseline_finalized_cursor: cursor,
                    network_id,
                    expected_authority: signer_authority.clone(),
                    assignment_revision: row.order.assignment_revision,
                    completion_epoch,
                    expected_payload: payload,
                };
                let claim =
                    match self
                        .outbox
                        .claim_completion_signing(job_id, context, self.clock.now_ms())
                    {
                        Ok(claim) => claim,
                        Err(ProviderIngestOutboxError::RetryNotDue) => return Ok(()),
                        Err(error) => return Err(error.into()),
                    };
                match exact_current_signer_authority(&signer, &completion_authority) {
                    Ok(policy) if policy == claim.context().expected_authority => {}
                    Err(CurrentSignerAuthorityErrorV1::ProtocolViolation) => {
                        self.outbox.release_completion_signing(
                            &claim,
                            self.clock.now_ms(),
                            cursor,
                        )?;
                        return Err(ProviderIngestRuntimeErrorV1::SignerProtocolViolation);
                    }
                    Ok(_)
                    | Err(
                        CurrentSignerAuthorityErrorV1::Unavailable
                        | CurrentSignerAuthorityErrorV1::Ineligible,
                    ) => {
                        self.outbox.release_completion_signing(
                            &claim,
                            self.clock.now_ms(),
                            cursor,
                        )?;
                        return Ok(());
                    }
                }
                let transaction = match tokio::time::timeout(
                    Duration::from_millis(self.policy.signer_timeout_ms),
                    signer.sign(claim.context().expected_payload.clone()),
                )
                .await
                {
                    Ok(Ok(transaction)) => transaction,
                    Ok(Err(ProviderIngestCompletionSignerErrorV1::Unavailable)) | Err(_) => {
                        self.outbox.release_completion_signing(
                            &claim,
                            self.clock.now_ms(),
                            cursor,
                        )?;
                        return Ok(());
                    }
                    Ok(Err(ProviderIngestCompletionSignerErrorV1::Rejected)) => {
                        self.outbox.release_completion_signing(
                            &claim,
                            self.clock.now_ms(),
                            cursor,
                        )?;
                        return Err(ProviderIngestRuntimeErrorV1::SignerProtocolViolation);
                    }
                };
                match exact_current_signer_authority(&signer, &completion_authority) {
                    Ok(policy) if policy == claim.context().expected_authority => {}
                    Err(CurrentSignerAuthorityErrorV1::ProtocolViolation) => {
                        self.outbox.release_completion_signing(
                            &claim,
                            self.clock.now_ms(),
                            cursor,
                        )?;
                        return Err(ProviderIngestRuntimeErrorV1::SignerProtocolViolation);
                    }
                    Ok(_)
                    | Err(
                        CurrentSignerAuthorityErrorV1::Unavailable
                        | CurrentSignerAuthorityErrorV1::Ineligible,
                    ) => {
                        self.outbox.release_completion_signing(
                            &claim,
                            self.clock.now_ms(),
                            cursor,
                        )?;
                        return Ok(());
                    }
                }
                match self
                    .outbox
                    .store_completion_transaction(&claim, transaction)
                {
                    Ok(_) => {}
                    Err(
                        ProviderIngestOutboxError::InvalidSignedTransaction
                        | ProviderIngestOutboxError::InvalidSigningClaim,
                    ) => {
                        self.outbox.release_completion_signing(
                            &claim,
                            self.clock.now_ms(),
                            cursor,
                        )?;
                        return Err(ProviderIngestRuntimeErrorV1::SignerProtocolViolation);
                    }
                    Err(error) => return Err(error.into()),
                }
                outcome.completions_signed = outcome.completions_signed.saturating_add(1);
                let status = self.outbox.status(job_id)?;
                if let ProviderIngestDeliveryStateV1::LocalStored {
                    completion: ProviderIngestCompletionStateV1::Signed { .. },
                    ..
                } = status.state
                {
                    self.submit_signed(
                        job_id,
                        &signer_authority,
                        row.order.assignment_revision,
                        cursor,
                        outcome,
                    )
                    .await?;
                }
            }
            ProviderIngestCompletionStateV1::Signing { .. } => {}
            ProviderIngestCompletionStateV1::Signed {
                next_attempt_at_ms, ..
            } => {
                if self.clock.now_ms() >= next_attempt_at_ms {
                    let Some(signer_authority) = submission_authority else {
                        return Ok(());
                    };
                    self.submit_signed(
                        job_id,
                        &signer_authority,
                        row.order.assignment_revision,
                        cursor,
                        outcome,
                    )
                    .await?;
                }
            }
            ProviderIngestCompletionStateV1::Ambiguous {
                baseline_finalized_cursor,
                transaction_hash,
                ..
            } => {
                self.reconcile_transaction(
                    job_id,
                    transaction_hash,
                    baseline_finalized_cursor,
                    cursor,
                    true,
                )
                .await?;
            }
            ProviderIngestCompletionStateV1::Submitted {
                baseline_finalized_cursor,
                transaction_hash,
                ..
            } => {
                self.reconcile_transaction(
                    job_id,
                    transaction_hash,
                    baseline_finalized_cursor,
                    cursor,
                    false,
                )
                .await?;
            }
        }
        Ok(())
    }
    #[allow(clippy::too_many_lines)]
    async fn submit_signed(
        &self,
        job_id: [u8; 32],
        expected_authority: &ProviderIngestCompletionAuthorityV1,
        expected_assignment_revision: u64,
        cursor: ProviderIngestFinalizedCursorV1,
        outcome: &mut ProviderIngestTickOutcomeV1,
    ) -> Result<(), ProviderIngestRuntimeErrorV1> {
        let provider_owner = &expected_authority.provider_owner;
        let exact = match self.outbox.completion_transaction_for_authorized_preflight(
            job_id,
            provider_owner,
            expected_authority,
            cursor,
            self.clock.now_ms(),
        ) {
            Ok(exact) => exact,
            Err(
                ProviderIngestOutboxError::RetryNotDue
                | ProviderIngestOutboxError::InvalidTransition
                | ProviderIngestOutboxError::InvalidSigningContext
                | ProviderIngestOutboxError::SignerPolicyRollback
                | ProviderIngestOutboxError::StaleFinalizedCursor,
            ) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let prepared = match tokio::time::timeout(
            Duration::from_millis(self.policy.ingress_timeout_ms),
            self.ingress.prepare(exact.signed_transaction.clone()),
        )
        .await
        {
            Ok(Ok(prepared)) => prepared,
            Ok(Err(ProviderIngestIngressPrepareErrorV1::Unavailable)) | Err(_) => {
                self.outbox.mark_completion_preflight_unavailable(
                    job_id,
                    exact.transaction_hash,
                    self.clock.now_ms(),
                    cursor,
                )?;
                return Ok(());
            }
            Ok(Err(ProviderIngestIngressPrepareErrorV1::Rejected)) => {
                self.outbox.mark_completion_preflight_rejected(
                    job_id,
                    exact.transaction_hash,
                    self.clock.now_ms(),
                    cursor,
                )?;
                return Ok(());
            }
        };
        let signer = match tokio::time::timeout(
            Duration::from_millis(self.policy.signer_timeout_ms),
            self.signer_resolver
                .resolve(ProviderIngestCompletionSignerResolutionContextV1::new(
                    expected_authority.clone(),
                    expected_assignment_revision,
                    cursor,
                )),
        )
        .await
        {
            Ok(Ok(Some(signer))) => signer,
            Ok(Ok(None)) | Ok(Err(ProviderIngestCompletionSignerResolverErrorV1::Rejected)) => {
                self.outbox.invalidate_stale_completion_authority(
                    job_id,
                    Some(provider_owner),
                    &ProviderIngestCompletionAuthorityObservationV1::Missing,
                    self.clock.now_ms(),
                    cursor,
                )?;
                return Ok(());
            }
            Ok(Err(ProviderIngestCompletionSignerResolverErrorV1::Unavailable)) | Err(_) => {
                return Ok(());
            }
        };
        let signer_authority = match exact_current_signer_authority(&signer, expected_authority) {
            Ok(policy) => policy,
            Err(CurrentSignerAuthorityErrorV1::Ineligible) => {
                self.outbox.invalidate_stale_completion_authority(
                    job_id,
                    Some(provider_owner),
                    &ProviderIngestCompletionAuthorityObservationV1::Missing,
                    self.clock.now_ms(),
                    cursor,
                )?;
                return Ok(());
            }
            Err(CurrentSignerAuthorityErrorV1::Unavailable) => return Ok(()),
            Err(CurrentSignerAuthorityErrorV1::ProtocolViolation) => {
                return Err(ProviderIngestRuntimeErrorV1::SignerProtocolViolation);
            }
        };
        if &signer_authority != expected_authority {
            self.outbox.invalidate_stale_completion_authority(
                job_id,
                Some(provider_owner),
                &ProviderIngestCompletionAuthorityObservationV1::Active(signer_authority.clone()),
                self.clock.now_ms(),
                cursor,
            )?;
            return Ok(());
        }
        self.outbox.invalidate_stale_completion_authority(
            job_id,
            Some(provider_owner),
            &ProviderIngestCompletionAuthorityObservationV1::Active(signer_authority.clone()),
            self.clock.now_ms(),
            cursor,
        )?;
        match exact_current_signer_authority(&signer, expected_authority) {
            Ok(current_policy) if current_policy == signer_authority => {}
            Ok(_)
            | Err(
                CurrentSignerAuthorityErrorV1::Ineligible
                | CurrentSignerAuthorityErrorV1::Unavailable,
            ) => return Ok(()),
            Err(CurrentSignerAuthorityErrorV1::ProtocolViolation) => {
                return Err(ProviderIngestRuntimeErrorV1::SignerProtocolViolation);
            }
        }
        let submission = match self.outbox.authorize_and_begin_completion_submission(
            job_id,
            exact.transaction_hash,
            provider_owner,
            &signer_authority,
            cursor,
            self.clock.now_ms(),
        ) {
            Ok(submission) => submission,
            Err(
                ProviderIngestOutboxError::RetryNotDue
                | ProviderIngestOutboxError::InvalidTransition
                | ProviderIngestOutboxError::InvalidSigningContext
                | ProviderIngestOutboxError::SignerPolicyRollback
                | ProviderIngestOutboxError::StaleFinalizedCursor,
            ) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if submission.signed_transaction != exact.signed_transaction {
            return Err(ProviderIngestRuntimeErrorV1::IngressProtocolViolation);
        }
        match exact_current_signer_authority(&signer, expected_authority) {
            Ok(current_policy) if current_policy == signer_authority => {}
            result => {
                self.outbox.mark_completion_not_submitted(
                    job_id,
                    exact.transaction_hash,
                    self.clock.now_ms(),
                    cursor,
                )?;
                if result == Err(CurrentSignerAuthorityErrorV1::ProtocolViolation) {
                    return Err(ProviderIngestRuntimeErrorV1::SignerProtocolViolation);
                }
                return Ok(());
            }
        }
        outcome.completion_submissions = outcome.completion_submissions.saturating_add(1);
        let disposition = match tokio::time::timeout(
            Duration::from_millis(self.policy.ingress_timeout_ms),
            self.ingress.expose(prepared, submission.signed_transaction),
        )
        .await
        {
            Ok(disposition) => disposition,
            Err(_) => ProviderIngestIngressDispositionV1::Ambiguous,
        };
        match disposition {
            ProviderIngestIngressDispositionV1::Submitted => self
                .outbox
                .mark_completion_submitted(job_id, exact.transaction_hash)?,
            ProviderIngestIngressDispositionV1::DefinitelyNotSubmitted => {
                self.outbox.mark_completion_not_submitted(
                    job_id,
                    exact.transaction_hash,
                    self.clock.now_ms(),
                    cursor,
                )?;
            }
            ProviderIngestIngressDispositionV1::Rejected => {
                self.outbox.mark_completion_transaction_rejected(
                    job_id,
                    exact.transaction_hash,
                    self.clock.now_ms(),
                    cursor,
                )?;
            }
            ProviderIngestIngressDispositionV1::Ambiguous => {}
        }
        Ok(())
    }
    async fn reconcile_transaction(
        &self,
        job_id: [u8; 32],
        transaction_hash: [u8; 32],
        baseline: ProviderIngestFinalizedCursorV1,
        cursor: ProviderIngestFinalizedCursorV1,
        ambiguous: bool,
    ) -> Result<(), ProviderIngestRuntimeErrorV1> {
        let observation = tokio::time::timeout(
            Duration::from_millis(self.policy.ingress_timeout_ms),
            self.ingress.observe(transaction_hash),
        )
        .await
        .unwrap_or(ProviderIngestTransactionObservationV1::Unavailable);
        match observation {
            ProviderIngestTransactionObservationV1::CommittedSuccess
            | ProviderIngestTransactionObservationV1::Pending => {
                if ambiguous {
                    self.outbox
                        .mark_completion_submitted(job_id, transaction_hash)?;
                }
            }
            ProviderIngestTransactionObservationV1::CommittedRejected => {
                self.outbox.mark_completion_transaction_rejected(
                    job_id,
                    transaction_hash,
                    self.clock.now_ms(),
                    cursor,
                )?;
            }
            ProviderIngestTransactionObservationV1::Unknown if cursor.height > baseline.height => {
                self.outbox.mark_completion_finalized_absent(
                    job_id,
                    transaction_hash,
                    self.clock.now_ms(),
                    cursor,
                )?;
            }
            ProviderIngestTransactionObservationV1::Unknown
            | ProviderIngestTransactionObservationV1::Unavailable => {}
        }
        Ok(())
    }
}
struct ValidatedAssignmentV1 {
    authorization: FinalizedProviderIngestAuthorizationV1,
    source_provider_ids: Vec<[u8; 32]>,
    musubi_archive: Option<ProviderIngestFinalizedMusubiArchiveClaimV1>,
}
fn local_stored_matches(
    stored: &ProviderIngestLocalStoredV1,
    authorization: &FinalizedProviderIngestAuthorizationV1,
    claim: Option<&ProviderIngestFinalizedMusubiArchiveClaimV1>,
) -> bool {
    if stored.manifest_id().is_empty() {
        return false;
    }
    match (claim, stored.musubi_bundle()) {
        (None, None) => authorization.musubi_context().is_none(),
        (Some(claim), Some(receipt)) => receipt.matches(claim, authorization),
        (None, Some(_)) | (Some(_), None) => false,
    }
}
fn persisted_receipt_matches(
    authorization: &FinalizedProviderIngestAuthorizationV1,
    claim: Option<&ProviderIngestFinalizedMusubiArchiveClaimV1>,
    receipt: Option<&ProviderIngestVerifiedMusubiBundleReceiptV1>,
) -> bool {
    match (claim, receipt) {
        (None, None) => authorization.musubi_context().is_none(),
        (Some(claim), Some(receipt)) => receipt.matches(claim, authorization),
        (None, Some(_)) | (Some(_), None) => false,
    }
}
fn validate_monotonic_finalized_cursor(
    previous: Option<ProviderIngestFinalizedCursorV1>,
    candidate: ProviderIngestFinalizedCursorV1,
) -> Result<(), ProviderIngestRuntimeErrorV1> {
    if previous.is_some_and(|previous| {
        candidate.height < previous.height
            || (candidate.height == previous.height && candidate.block_hash != previous.block_hash)
    }) {
        return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedPage);
    }
    Ok(())
}
fn validate_page(
    page: &ProviderIngestFinalizedAssignmentPageV1,
    after_order_id: Option<[u8; 32]>,
    expected_cursor: ProviderIngestFinalizedCursorV1,
    limit: usize,
) -> Result<(), ProviderIngestRuntimeErrorV1> {
    if page.finalized_cursor != expected_cursor
        || page.finalized_cursor.height == 0
        || page.finalized_cursor.block_hash == [0; 32]
        || page.finalized_block_time_ms == 0
        || page.rows.len() > limit
        || page.next_after_order_id.is_some() && page.rows.is_empty()
        || page.next_after_order_id.is_some() && page.rows.len() != limit
    {
        return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedPage);
    }
    let mut previous = after_order_id;
    for row in &page.rows {
        let order_id = *row.order.order_id.as_bytes();
        if previous.is_some_and(|previous| previous >= order_id) {
            return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedPage);
        }
        previous = Some(order_id);
    }
    if let Some(next) = page.next_after_order_id
        && Some(next) != previous
    {
        return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedPage);
    }
    Ok(())
}
fn validate_assignment(
    row: &ProviderIngestFinalizedAssignmentV1,
    cursor: ProviderIngestFinalizedCursorV1,
    provider_id: [u8; 32],
    network_id: &NetworkId,
    policy: ProviderIngestRuntimePolicyV1,
) -> Result<ValidatedAssignmentV1, ProviderIngestRuntimeErrorV1> {
    validate_assignment_with_source_bound(
        row,
        cursor,
        provider_id,
        network_id,
        policy.max_source_providers,
    )
}
/// Decode the single canonical order and bind every duplicated immutable record field.
fn decode_bound_replication_order(
    record: &ReplicationOrderRecord,
) -> Result<ReplicationOrderV1, ProviderIngestRuntimeErrorV1> {
    if record.canonical_order.is_empty()
        || record.canonical_order.len() > REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1
    {
        return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedBinding);
    }
    let order = decode_canonical_with_limits::<ReplicationOrderV1>(
        &record.canonical_order,
        REPLICATION_ORDER_DECODE_LIMITS_V1,
    )
    .map_err(|_| ProviderIngestRuntimeErrorV1::InvalidFinalizedBinding)?;
    order
        .validate()
        .map_err(|_| ProviderIngestRuntimeErrorV1::InvalidFinalizedBinding)?;
    if order.order_id != *record.order_id.as_bytes()
        || order.manifest_digest != *record.manifest_digest.as_bytes()
        || order.manifest_cid.as_slice() != record.manifest_root_cid.as_bytes()
        || order.issued_at != record.issued_epoch
        || order.deadline_at != record.deadline_epoch
    {
        return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedBinding);
    }
    Ok(order)
}
fn validate_assignment_with_source_bound(
    row: &ProviderIngestFinalizedAssignmentV1,
    cursor: ProviderIngestFinalizedCursorV1,
    provider_id: [u8; 32],
    network_id: &NetworkId,
    max_source_providers: usize,
) -> Result<ValidatedAssignmentV1, ProviderIngestRuntimeErrorV1> {
    if row.pin.finalized_cursor.height != cursor.height
        || row.pin.finalized_cursor.block_hash != cursor.block_hash
        || row.order.deadline_epoch <= row.order.issued_epoch
        || row
            .committed_transaction_hash
            .is_some_and(|hash| hash == [0; 32])
        || row.order.assignment_revision == 0
        || row.order.canonical_order.is_empty()
        || row.order.canonical_order.len() > REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1
        || row.completion_authority.as_ref().is_some_and(|authority| {
            !authority.is_valid() || row.provider_owner.as_ref() != Some(&authority.provider_owner)
        })
        || row.provider_owner.is_none() && row.completion_authority.is_some()
    {
        return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedBinding);
    }
    let order = decode_bound_replication_order(&row.order)?;
    if row.pin.manifest.digest != row.order.manifest_digest
        || row.pin.manifest.root_cid != row.order.manifest_root_cid
        || row.pin.manifest.chunker.to_handle() != order.chunking_profile
    {
        return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedBinding);
    }
    if !order
        .assignments
        .iter()
        .any(|assignment| assignment.provider_id == provider_id)
    {
        return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedBinding);
    }
    match (row.order.musubi_archive, &row.musubi_archive) {
        (None, None) => {}
        (Some(archive_id), Some(claim)) => {
            let commitment = claim.commitment();
            if claim.network_id() != network_id
                || claim.provider_id() != provider_id
                || claim.observed_finalized_cursor() != cursor
                || claim.replication_order() != *row.order.order_id.as_bytes()
                || claim.archive_id() != archive_id
                || claim.archive_id() != commitment.archive_id()
                || commitment.validate().is_err()
                || commitment.root_cid != row.pin.manifest.root_cid
                || commitment.chunker != row.pin.manifest.chunker
                || commitment.chunk_plan_digest.as_bytes()
                    != &row.pin.manifest.chunk_digest_sha3_256
                || commitment.por_root.as_bytes() != &row.pin.manifest.por_root
                || commitment.content_length != row.pin.manifest.content_length
            {
                return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedBinding);
            }
        }
        (None, Some(_)) | (Some(_), None) => {
            return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedBinding);
        }
    }
    let local_completion = row.order.provider_completion(ProviderId::new(provider_id));
    match (
        row.order.musubi_archive,
        local_completion,
        &row.completed_musubi_archive,
    ) {
        (None, _, None) | (Some(_), None, None) => {}
        (Some(archive_id), Some(completion), Some(claim)) => {
            let commitment = claim.commitment();
            let Some(pre_completion_claim) = row.musubi_archive.as_ref() else {
                return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedBinding);
            };
            if claim.network_id() != network_id
                || claim.provider_id() != provider_id
                || claim.observed_finalized_cursor() != cursor
                || claim.replication_order() != *row.order.order_id.as_bytes()
                || claim.archive_id() != archive_id
                || claim.archive_id() != commitment.archive_id()
                || commitment != pre_completion_claim.commitment()
                || claim.completion() != completion
                || commitment.validate().is_err()
                || commitment.root_cid != row.pin.manifest.root_cid
                || commitment.chunker != row.pin.manifest.chunker
                || commitment.chunk_plan_digest.as_bytes()
                    != &row.pin.manifest.chunk_digest_sha3_256
                || commitment.por_root.as_bytes() != &row.pin.manifest.por_root
                || commitment.content_length != row.pin.manifest.content_length
            {
                return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedBinding);
            }
        }
        (None, _, Some(_)) | (Some(_), None, Some(_)) | (Some(_), Some(_), None) => {
            return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedBinding);
        }
    }
    let source_provider_ids = order
        .assignments
        .iter()
        .filter_map(|assignment| {
            (assignment.provider_id != provider_id).then_some(assignment.provider_id)
        })
        .collect::<Vec<_>>();
    if source_provider_ids.len() > max_source_providers {
        return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedBinding);
    }
    let target_replicas = usize::from(order.target_replicas);
    if row.order.provider_completions.len() > target_replicas {
        return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedBinding);
    }
    let mut completions = BTreeSet::new();
    let mut previous_completion_epoch = None;
    for completion in &row.order.provider_completions {
        if !order
            .assignments
            .iter()
            .any(|assignment| assignment.provider_id == *completion.provider_id.as_bytes())
            || completion.completion_epoch < row.order.issued_epoch
            || completion.completion_epoch > row.order.deadline_epoch
            || previous_completion_epoch
                .is_some_and(|previous| completion.completion_epoch < previous)
            || completion.assignment_revision != row.order.assignment_revision
            || !completion.completion_authority.is_valid()
            || completion.completion_authority.completion_signer != completion.completed_by
            || !completion.finalized_anchor.is_valid()
            || completion.finalized_anchor.height > cursor.height
            || completion.finalized_anchor.height == cursor.height
                && completion.finalized_anchor.block_hash != cursor.block_hash
            || !completions.insert(*completion.provider_id.as_bytes())
        {
            return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedBinding);
        }
        previous_completion_epoch = Some(completion.completion_epoch);
    }
    match row.order.status {
        ReplicationOrderStatus::Pending
            if row.order.provider_completions.len() < target_replicas => {}
        ReplicationOrderStatus::Expired(epoch)
            if row.order.provider_completions.len() < target_replicas
                && epoch > row.order.deadline_epoch => {}
        ReplicationOrderStatus::Cancelled(epoch)
            if row.order.provider_completions.len() < target_replicas
                && epoch >= row.order.issued_epoch
                && epoch <= row.order.deadline_epoch => {}
        ReplicationOrderStatus::Completed(epoch)
            if row.order.provider_completions.len() == target_replicas
                && row
                    .order
                    .provider_completions
                    .last()
                    .is_some_and(|completion| completion.completion_epoch == epoch) => {}
        ReplicationOrderStatus::Pending
        | ReplicationOrderStatus::Completed(_)
        | ReplicationOrderStatus::Expired(_)
        | ReplicationOrderStatus::Cancelled(_) => {
            return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedBinding);
        }
    }
    let approved_epoch = row.pin.manifest.approved_epoch;
    let is_automatic = row.order.order_id
        == derive_sorafs_auto_replication_order_id_v1(&row.order.manifest_digest);
    let issued_after_approval =
        approved_epoch.is_some_and(|approved_epoch| row.order.issued_epoch >= approved_epoch);
    let automatic_issued_at_approval =
        !is_automatic || approved_epoch == Some(row.order.issued_epoch);
    let pin_order_lifecycle_is_valid = match (row.pin.manifest.status, row.order.status) {
        (PinStatus::Pending, _) => false,
        (PinStatus::Approved(status_epoch), status) => {
            approved_epoch == Some(status_epoch)
                && issued_after_approval
                && automatic_issued_at_approval
                && !matches!(status, ReplicationOrderStatus::Cancelled(_))
        }
        (PinStatus::Retired(retired_epoch), status) => {
            approved_epoch.is_some_and(|approved_epoch| approved_epoch <= retired_epoch)
                && issued_after_approval
                && automatic_issued_at_approval
                && match status {
                    ReplicationOrderStatus::Pending => false,
                    ReplicationOrderStatus::Cancelled(epoch) => epoch == retired_epoch,
                    ReplicationOrderStatus::Completed(epoch)
                    | ReplicationOrderStatus::Expired(epoch) => epoch <= retired_epoch,
                }
        }
    };
    if !pin_order_lifecycle_is_valid {
        return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedBinding);
    }
    let authorization = if let Some(claim) = row.musubi_archive.as_ref() {
        FinalizedProviderIngestAuthorizationV1::from_finalized_musubi_state(
            cursor.height,
            cursor.block_hash,
            provider_id,
            *row.order.order_id.as_bytes(),
            *row.pin.manifest.digest.as_bytes(),
            order.manifest_cid,
            order.chunking_profile,
            row.pin.manifest.chunk_digest_sha3_256,
            row.pin.manifest.por_root,
            row.pin.manifest.content_length,
            FinalizedProviderIngestMusubiContextV1::new(*network_id, claim.archive_id())?,
        )?
    } else {
        FinalizedProviderIngestAuthorizationV1::from_finalized_state(
            cursor.height,
            cursor.block_hash,
            provider_id,
            *row.order.order_id.as_bytes(),
            *row.pin.manifest.digest.as_bytes(),
            order.manifest_cid,
            order.chunking_profile,
            row.pin.manifest.chunk_digest_sha3_256,
            row.pin.manifest.por_root,
            row.pin.manifest.content_length,
        )?
    };
    Ok(ValidatedAssignmentV1 {
        authorization,
        source_provider_ids,
        musubi_archive: row.musubi_archive.clone(),
    })
}
fn authorization_from_status_and_row(
    status: &crate::provider_ingest_outbox::ProviderIngestStatusV1,
    row: &ProviderIngestFinalizedAssignmentV1,
    cursor: ProviderIngestFinalizedCursorV1,
) -> Result<FinalizedProviderIngestAuthorizationV1, ProviderIngestRuntimeErrorV1> {
    let order = decode_bound_replication_order(&row.order)?;
    let authorization = if let Some(claim) = row.musubi_archive.as_ref() {
        FinalizedProviderIngestAuthorizationV1::from_finalized_musubi_state(
            cursor.height,
            cursor.block_hash,
            status.provider_id,
            status.order_id,
            status.manifest_digest,
            order.manifest_cid,
            order.chunking_profile,
            row.pin.manifest.chunk_digest_sha3_256,
            row.pin.manifest.por_root,
            row.pin.manifest.content_length,
            FinalizedProviderIngestMusubiContextV1::new(*claim.network_id(), claim.archive_id())?,
        )?
    } else {
        FinalizedProviderIngestAuthorizationV1::from_finalized_state(
            cursor.height,
            cursor.block_hash,
            status.provider_id,
            status.order_id,
            status.manifest_digest,
            order.manifest_cid,
            order.chunking_profile,
            row.pin.manifest.chunk_digest_sha3_256,
            row.pin.manifest.por_root,
            row.pin.manifest.content_length,
        )?
    };
    if authorization.job_id() != status.job_id {
        return Err(ProviderIngestRuntimeErrorV1::InvalidFinalizedBinding);
    }
    Ok(authorization)
}
enum LeaseOperationOutcomeV1<T> {
    Completed(T),
    TimedOut,
}
enum MutatingStorageOutcomeV1<T> {
    Completed(T),
    CompletedAfterSoftTimeout(T),
}
/// Fatal supervised-runtime failure.
#[allow(clippy::large_enum_variant, variant_size_differences)]
#[derive(Debug, Error)]
pub enum ProviderIngestRuntimeErrorV1 {
    /// Runtime bounds or timeout policy is invalid.
    #[error("provider-ingest runtime policy is invalid")]
    InvalidPolicy,
    /// Configured provider identity is zero.
    #[error("provider-ingest runtime provider identity is invalid")]
    InvalidProviderId,
    /// Configured exact network identity is malformed.
    #[error("provider-ingest runtime network identity is invalid")]
    InvalidNetworkId,
    /// Finalized ledger paging is unavailable.
    #[error("provider-ingest finalized ledger is unavailable")]
    FinalizedLedgerUnavailable,
    /// Finalized page cursor, bounds, or ordering is invalid.
    #[error("provider-ingest finalized page is invalid")]
    InvalidFinalizedPage,
    /// Finalized pin/order/provider material is noncanonical or inconsistent.
    #[error("provider-ingest finalized binding is invalid")]
    InvalidFinalizedBinding,
    /// Local storage returned a manifest identity that violates its exact contract.
    #[error("provider-ingest local storage violated the exact binding")]
    StorageProtocolViolation,
    /// Authenticated source identity, policy, or qualification drifted.
    #[error("provider-ingest authenticated source violated its exact binding")]
    SourceProtocolViolation,
    /// Resolved signer or signed transaction violated the prepared context.
    #[error("provider-ingest signer violated the prepared operation")]
    SignerProtocolViolation,
    /// Queue preflight/exposure violated the exact transaction contract.
    #[error("provider-ingest ingress violated the prepared operation")]
    IngressProtocolViolation,
    /// Durable outbox transition failed.
    #[error(transparent)]
    Outbox(#[from] ProviderIngestOutboxError),
}
#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod tests {
    include!("provider_ingest_runtime/tests/support.rs");
    include!("provider_ingest_runtime/tests/capture_source.rs");
    include!("provider_ingest_runtime/tests/native_attestation.rs");
    include!("provider_ingest_runtime/tests/runtime.rs");
    include!("provider_ingest_runtime/tests/canonical_order.rs");
}
