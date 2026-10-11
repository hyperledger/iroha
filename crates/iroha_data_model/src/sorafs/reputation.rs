//! Chain-authoritative SoraFS reputation source journal.
//!
//! The first-release reputation projector consumes this payload-free journal for the three source
//! families that are not represented by the existing proof, repair, orderbook, and reserve ledgers:
//! terminal `PoR` outcomes, provider-dispute transitions, and stream-token validation outcomes.
//!
//! Source identifiers are domain separated from their native identifiers. Event identifiers are the
//! BLAKE3 digest of the complete canonical entry with its `event_id` field cleared. A ledger
//! implementation must retain one global event-id index and one exact source-head index. Exact
//! event-id replays are idempotent; a different event at an occupied source revision is
//! equivocation.
//!
//! The module also defines the explicit finalized-archive retention request. That request is a
//! caller-signed custom parameter with a strict digest-linked sequence and exact committed target;
//! it intentionally contains no automatic age, capacity, or process-local retention policy.

/// Native immutable stream-token append recipes and permanent delivery dispositions.
pub mod stream_token_delivery;

use crate::parameter::{CustomParameter, CustomParameterId};
use crate::{
    NetworkId,
    account::AccountId,
    sorafs::capacity::{CapacityDisputeId, CapacityDisputeOutcome, ProviderId},
};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::io;
use thiserror::Error;
/// First-release reputation-journal entry version.
pub const REPUTATION_JOURNAL_ENTRY_VERSION_V1: u16 = 1;
/// First-release governed recorder-policy version.
pub const REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1: u16 = 1;
/// Hard item ceiling for one finalized reputation-journal event page.
pub const REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1: usize = 128;
/// Hard encoded-byte ceiling for one finalized reputation-journal event page.
pub const REPUTATION_JOURNAL_QUERY_MAX_EVENT_PAGE_BYTES_V1: usize = 128 * 1024;
/// Hard encoded-byte ceiling for one committed journal entry.
pub const REPUTATION_JOURNAL_MAX_ENTRY_BYTES_V1: usize = 16 * 1024;
/// Hard UTF-8 byte ceiling for a governance resolution rationale.
pub const REPUTATION_JOURNAL_MAX_TEXT_BYTES_V1: usize = 2_048;
/// Hard governed ceiling for the age of a submitted source observation.
pub const REPUTATION_JOURNAL_MAX_SOURCE_AGE_MS_V1: u64 = 30 * 24 * 60 * 60 * 1_000;
/// First-release finalized-reputation archive retention-request version.
pub const REPUTATION_FINALIZED_ARCHIVE_RETENTION_REQUEST_VERSION_V1: u16 = 1;
/// Reserved custom-parameter identifier carrying explicit retention work.
pub const REPUTATION_FINALIZED_ARCHIVE_RETENTION_REQUEST_PARAMETER_ID_V1: &str =
    "sorafs_reputation_finalized_archive_retention_request_v1";
/// Domain separator for governed recorder-policy digests.
pub const REPUTATION_JOURNAL_AUTHORITY_POLICY_DIGEST_DOMAIN_V1: &[u8] =
    b"sorafs.reputation.journal.authority-policy.v1";
/// Domain separator for globally unique `PoR` source identifiers.
pub const REPUTATION_JOURNAL_POR_SOURCE_ID_DOMAIN_V1: &[u8] =
    b"sorafs.reputation.journal.source.por.v1";
/// Domain separator for globally unique provider-dispute source identifiers.
pub const REPUTATION_JOURNAL_DISPUTE_SOURCE_ID_DOMAIN_V1: &[u8] =
    b"sorafs.reputation.journal.source.provider-dispute.v1";
/// Domain separator for globally unique stream-token source identifiers.
pub const REPUTATION_JOURNAL_TOKEN_SOURCE_ID_DOMAIN_V1: &[u8] =
    b"sorafs.reputation.journal.source.stream-token.v1";
/// Domain separator for canonical stream-token validation identifiers.
pub const STREAM_TOKEN_VALIDATION_ID_DOMAIN_V1: &[u8] =
    b"sorafs.reputation.stream-token.validation-id.v1";
/// Domain separator for stable, network-scoped regional gateway identities.
pub const STREAM_TOKEN_GATEWAY_ID_DOMAIN_V1: &[u8] =
    b"sorafs.reputation.stream-token.gateway-id.v1";
/// Domain separator for exact request-nonce commitments.
pub const STREAM_TOKEN_REQUEST_NONCE_DIGEST_DOMAIN_V1: &[u8] =
    b"sorafs.reputation.stream-token.request-nonce.v1";
/// Domain separator for exact presented stream-token header commitments.
pub const STREAM_TOKEN_EXACT_HEADER_DIGEST_DOMAIN_V1: &[u8] =
    b"sorafs.reputation.stream-token.exact-header.v1";
/// Domain separator for canonical stream-token request-context commitments.
pub const STREAM_TOKEN_REQUEST_CONTEXT_DIGEST_DOMAIN_V1: &[u8] =
    b"sorafs.reputation.stream-token.request-context.v1";
/// First-release canonical stream-token request-context version.
pub const STREAM_TOKEN_REQUEST_CONTEXT_VERSION_V1: u8 = 1;
/// Maximum governed compliance-gateway identity bytes.
pub const STREAM_TOKEN_COMPLIANCE_GATEWAY_ID_MAX_BYTES_V1: usize = 128;
/// Exact canonical first-release manifest-root CID bytes.
pub const STREAM_TOKEN_REQUEST_MANIFEST_CID_BYTES_V1: usize =
    sorafs_manifest::MAX_MANIFEST_ROOT_CID_BYTES;
/// Maximum canonical chunk-profile handle bytes.
pub const STREAM_TOKEN_REQUEST_PROFILE_HANDLE_MAX_BYTES_V1: usize = 128;
/// Maximum canonical visible-ASCII request-nonce bytes.
pub const STREAM_TOKEN_REQUEST_NONCE_MAX_BYTES_V1: usize = 128;
/// Domain separator for content-derived journal event identifiers.
pub const REPUTATION_JOURNAL_EVENT_ID_DOMAIN_V1: &[u8] = b"sorafs.reputation.journal.event-id.v1";
/// Domain separator for explicit finalized-reputation archive retention requests.
pub const REPUTATION_FINALIZED_ARCHIVE_RETENTION_REQUEST_DIGEST_DOMAIN_V1: &[u8] =
    b"sorafs.reputation.finalized-archive.retention-request.v1";
/// Exact finalized ancestor selected by one explicit archive-retention request.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::sorafs::reputation::ReputationFinalizedArchiveRetentionTargetV1"
)]
pub struct ReputationFinalizedArchiveRetentionTargetV1 {
    /// One-based finalized block height.
    pub height: u64,
    /// Exact finalized block hash at `height`.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub block_hash: [u8; 32],
}
impl ReputationFinalizedArchiveRetentionTargetV1 {
    /// Construct one exact non-zero finalized target.
    ///
    /// # Errors
    ///
    /// Rejects height zero or the reserved all-zero block hash.
    pub fn try_new(
        height: u64,
        block_hash: [u8; 32],
    ) -> Result<Self, ReputationFinalizedArchiveRetentionRequestErrorV1> {
        let target = Self { height, block_hash };
        target.validate()?;
        Ok(target)
    }
    /// Validate the exact target identity.
    ///
    /// # Errors
    ///
    /// Rejects height zero or the reserved all-zero block hash.
    pub fn validate(&self) -> Result<(), ReputationFinalizedArchiveRetentionRequestErrorV1> {
        if self.height == 0 {
            return Err(ReputationFinalizedArchiveRetentionRequestErrorV1::ZeroTargetHeight);
        }
        if self.block_hash == [0; 32] {
            return Err(ReputationFinalizedArchiveRetentionRequestErrorV1::ZeroTargetBlockHash);
        }
        Ok(())
    }
}
/// Caller-signed, committed request for one explicit finalized archive compaction.
///
/// This value selects no target automatically. A holder of `CanSetParameters`
/// must submit the exact target as a custom parameter, and consensus validates
/// that target against an already committed block. Successive requests form a
/// strict digest-linked sequence so replicas can reconcile them idempotently.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::sorafs::reputation::ReputationFinalizedArchiveRetentionRequestV1"
)]
pub struct ReputationFinalizedArchiveRetentionRequestV1 {
    /// Schema version.
    pub version: u16,
    /// Exact network whose archive may be compacted.
    pub network_id: NetworkId,
    /// Monotonic request sequence beginning at one.
    pub sequence: u64,
    /// Digest of the immediately preceding canonical request.
    #[norito(json = "crate::json_helpers::fixed_bytes::option")]
    pub predecessor_request_digest: Option<[u8; 32]>,
    /// Exact finalized ancestor selected explicitly by governance.
    pub compact_through: ReputationFinalizedArchiveRetentionTargetV1,
    /// Domain-separated digest of every preceding field.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub request_digest: [u8; 32],
}
impl ReputationFinalizedArchiveRetentionRequestV1 {
    /// Construct one canonical explicit retention request.
    ///
    /// # Errors
    ///
    /// Rejects invalid targets, sequence/predecessor combinations, or a canonical encoding failure.
    pub fn try_new(
        network_id: NetworkId,
        sequence: u64,
        predecessor_request_digest: Option<[u8; 32]>,
        compact_through: ReputationFinalizedArchiveRetentionTargetV1,
    ) -> Result<Self, ReputationFinalizedArchiveRetentionRequestErrorV1> {
        let mut request = Self {
            version: REPUTATION_FINALIZED_ARCHIVE_RETENTION_REQUEST_VERSION_V1,
            network_id,
            sequence,
            predecessor_request_digest,
            compact_through,
            request_digest: [0; 32],
        };
        request.validate_without_digest()?;
        request.request_digest = request.expected_digest()?;
        request.validate()?;
        Ok(request)
    }
    /// Reserved custom-parameter identifier accepted by `SetParameter`.
    #[must_use]
    pub fn parameter_id() -> CustomParameterId {
        REPUTATION_FINALIZED_ARCHIVE_RETENTION_REQUEST_PARAMETER_ID_V1
            .parse()
            .expect("valid finalized-reputation retention parameter identifier")
    }
    /// Convert this request into the caller-signed custom parameter.
    #[must_use]
    pub fn into_custom_parameter(self) -> CustomParameter {
        CustomParameter::new(
            Self::parameter_id(),
            iroha_primitives::json::Json::new(self),
        )
    }
    /// Strictly decode a matching custom parameter.
    ///
    /// Non-matching identifiers return `Ok(None)`. Matching values reject
    /// malformed JSON, unsupported versions, non-canonical digests, and every
    /// invalid sequence/predecessor combination.
    ///
    /// # Errors
    ///
    /// Returns a JSON error for malformed or semantically invalid matching payloads.
    pub fn from_custom_parameter(
        custom: &CustomParameter,
    ) -> Result<Option<Self>, norito::json::Error> {
        if custom.id() != &Self::parameter_id() {
            return Ok(None);
        }
        let request = norito::json::from_str::<Self>(custom.payload().get())?;
        request
            .validate()
            .map_err(|error| norito::json::Error::Message(error.to_string()))?;
        Ok(Some(request))
    }
    /// Validate the request and its embedded canonical digest.
    ///
    /// # Errors
    ///
    /// Rejects malformed versions, targets, lineage, or digest substitution.
    pub fn validate(&self) -> Result<(), ReputationFinalizedArchiveRetentionRequestErrorV1> {
        self.validate_without_digest()?;
        if self.request_digest == [0; 32] {
            return Err(ReputationFinalizedArchiveRetentionRequestErrorV1::ZeroRequestDigest);
        }
        if self.request_digest != self.expected_digest()? {
            return Err(ReputationFinalizedArchiveRetentionRequestErrorV1::RequestDigestMismatch);
        }
        Ok(())
    }
    /// Validate one request as an exact replay or strict successor.
    ///
    /// # Errors
    ///
    /// Rejects cross-network changes, skips, rollback, equivocation, or an
    /// incorrect predecessor digest.
    pub fn validate_transition(
        previous: Option<&Self>,
        next: &Self,
    ) -> Result<(), ReputationFinalizedArchiveRetentionRequestErrorV1> {
        next.validate()?;
        let Some(previous) = previous else {
            return if next.sequence == 1 && next.predecessor_request_digest.is_none() {
                Ok(())
            } else {
                Err(ReputationFinalizedArchiveRetentionRequestErrorV1::InvalidInitialLineage)
            };
        };
        previous.validate()?;
        if next == previous {
            return Ok(());
        }
        if next.network_id != previous.network_id {
            return Err(ReputationFinalizedArchiveRetentionRequestErrorV1::NetworkChanged);
        }
        let expected_sequence = previous
            .sequence
            .checked_add(1)
            .ok_or(ReputationFinalizedArchiveRetentionRequestErrorV1::SequenceOverflow)?;
        if next.sequence != expected_sequence {
            return Err(ReputationFinalizedArchiveRetentionRequestErrorV1::NonContiguousSequence);
        }
        if next.predecessor_request_digest != Some(previous.request_digest) {
            return Err(
                ReputationFinalizedArchiveRetentionRequestErrorV1::PredecessorDigestMismatch,
            );
        }
        if next.compact_through.height <= previous.compact_through.height {
            return Err(ReputationFinalizedArchiveRetentionRequestErrorV1::TargetDidNotAdvance);
        }
        Ok(())
    }
    fn validate_without_digest(
        &self,
    ) -> Result<(), ReputationFinalizedArchiveRetentionRequestErrorV1> {
        if self.version != REPUTATION_FINALIZED_ARCHIVE_RETENTION_REQUEST_VERSION_V1 {
            return Err(
                ReputationFinalizedArchiveRetentionRequestErrorV1::UnsupportedVersion {
                    found: self.version,
                },
            );
        }
        if self.network_id.as_bytes()[31] & 1 != 1 {
            return Err(ReputationFinalizedArchiveRetentionRequestErrorV1::InvalidNetworkId);
        }
        if self.sequence == 0 {
            return Err(ReputationFinalizedArchiveRetentionRequestErrorV1::ZeroSequence);
        }
        match (self.sequence, self.predecessor_request_digest) {
            (1, None) => {}
            (1, Some(_)) => {
                return Err(
                    ReputationFinalizedArchiveRetentionRequestErrorV1::UnexpectedPredecessor,
                );
            }
            (_, Some(digest)) if digest != [0; 32] => {}
            _ => {
                return Err(ReputationFinalizedArchiveRetentionRequestErrorV1::MissingPredecessor);
            }
        }
        self.compact_through.validate()
    }
    fn expected_digest(
        &self,
    ) -> Result<[u8; 32], ReputationFinalizedArchiveRetentionRequestErrorV1> {
        let material = (
            self.version,
            self.network_id,
            self.sequence,
            self.predecessor_request_digest,
            self.compact_through,
        );
        let bytes = norito::encode_canonical(&material)
            .map_err(|_| ReputationFinalizedArchiveRetentionRequestErrorV1::CanonicalEncoding)?;
        Ok(domain_digest(
            REPUTATION_FINALIZED_ARCHIVE_RETENTION_REQUEST_DIGEST_DOMAIN_V1,
            &bytes,
        ))
    }
}
/// Validation failure for an explicit finalized archive retention request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ReputationFinalizedArchiveRetentionRequestErrorV1 {
    /// The payload version is unsupported.
    #[error("unsupported retention-request version {found}")]
    UnsupportedVersion {
        /// Observed version.
        found: u16,
    },
    /// The request carries a malformed exact network identity.
    #[error("retention-request network id must be an exact marked genesis hash")]
    InvalidNetworkId,
    /// Sequence zero is reserved.
    #[error("retention-request sequence must begin at one")]
    ZeroSequence,
    /// A first request unexpectedly names a predecessor.
    #[error("first retention request must not name a predecessor")]
    UnexpectedPredecessor,
    /// A successor omitted or zeroed its predecessor.
    #[error("successor retention request requires a non-zero predecessor digest")]
    MissingPredecessor,
    /// The exact target height is zero.
    #[error("retention target height must be non-zero")]
    ZeroTargetHeight,
    /// The exact target block hash is zero.
    #[error("retention target block hash must be non-zero")]
    ZeroTargetBlockHash,
    /// The embedded request digest is zero.
    #[error("retention request digest must be non-zero")]
    ZeroRequestDigest,
    /// The embedded request digest does not match the canonical payload.
    #[error("retention request digest mismatch")]
    RequestDigestMismatch,
    /// Canonical Norito encoding failed.
    #[error("retention request canonical encoding failed")]
    CanonicalEncoding,
    /// A non-initial request appeared without a predecessor state.
    #[error("retention request has invalid initial lineage")]
    InvalidInitialLineage,
    /// A successor targets another network.
    #[error("retention request network changed")]
    NetworkChanged,
    /// The preceding sequence cannot advance.
    #[error("retention request sequence overflowed")]
    SequenceOverflow,
    /// A successor skipped, repeated, or rolled back its sequence.
    #[error("retention request sequence is not contiguous")]
    NonContiguousSequence,
    /// A successor does not bind the exact preceding request.
    #[error("retention request predecessor digest mismatch")]
    PredecessorDigestMismatch,
    /// A successor did not advance the explicit target height.
    #[error("retention request target did not advance")]
    TargetDidNotAdvance,
}
/// Globally namespaced identity of one native reputation source.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode, IntoSchema, Default,
)]
#[repr(transparent)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::ReputationJournalSourceIdV1")]
pub struct ReputationJournalSourceIdV1(pub [u8; 32]);
impl ReputationJournalSourceIdV1 {
    /// Reserved inert identity.
    pub const ZERO: Self = Self([0; 32]);
    /// Derive the globally namespaced source for a native `PoR` challenge.
    #[must_use]
    pub fn for_por_challenge(challenge_id: [u8; 32]) -> Self {
        source_id(REPUTATION_JOURNAL_POR_SOURCE_ID_DOMAIN_V1, challenge_id)
    }
    /// Derive the globally namespaced source for a native capacity dispute.
    #[must_use]
    pub fn for_provider_dispute(dispute_id: CapacityDisputeId) -> Self {
        source_id(
            REPUTATION_JOURNAL_DISPUTE_SOURCE_ID_DOMAIN_V1,
            *dispute_id.as_bytes(),
        )
    }
    /// Derive the globally namespaced source for one gateway validation sequence.
    ///
    /// The request-context digest is deliberately excluded from this source key. Reusing one
    /// gateway sequence with substituted request context must therefore collide at the source
    /// boundary and fail as equivocation, rather than entering the journal as a distinct event.
    #[must_use]
    pub fn for_stream_token_validation(binding: StreamTokenValidationBindingV1) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(REPUTATION_JOURNAL_TOKEN_SOURCE_ID_DOMAIN_V1);
        hasher.update(&binding.gateway_id);
        hasher.update(&binding.gateway_sequence.to_le_bytes());
        Self(*hasher.finalize().as_bytes())
    }
    /// Access the raw digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
/// Globally unique content-derived identity of one journal event.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode, IntoSchema, Default,
)]
#[repr(transparent)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::ReputationJournalEventIdV1")]
pub struct ReputationJournalEventIdV1(pub [u8; 32]);
impl ReputationJournalEventIdV1 {
    /// Reserved inert identity used only while deriving the canonical id.
    pub const ZERO: Self = Self([0; 32]);
    /// Access the raw digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
/// Stable journal source family.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(tag = "source", content = "detail", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::ReputationJournalSourceKindV1")]
pub enum ReputationJournalSourceKindV1 {
    /// Terminal proof-of-retrievability outcomes.
    Por,
    /// Provider capacity-dispute lifecycle.
    ProviderDispute,
    /// Gateway stream-token validation outcomes.
    StreamToken,
}
/// Governed accounts allowed to append each first-release journal source.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::ReputationJournalAuthorityPolicyV1")]
pub struct ReputationJournalAuthorityPolicyV1 {
    /// Schema version.
    pub version: u16,
    /// Monotonic policy revision beginning at one.
    pub revision: u64,
    /// Digest of the immediately preceding canonical policy.
    #[norito(json = "crate::json_helpers::fixed_bytes::option")]
    pub predecessor_policy_digest: Option<[u8; 32]>,
    /// Exact governed authority allowed to record `PoR` terminals.
    pub por_recorder_authority: AccountId,
    /// Exact governed authority allowed to record dispute transitions.
    pub dispute_recorder_authority: AccountId,
    /// Exact governed regional-gateway authority allowed to record token outcomes.
    pub token_recorder_authority: AccountId,
    /// Governed exact gateway fee delegation and source-derived finite append lifetime.
    pub stream_token_delivery: stream_token_delivery::StreamTokenReputationDeliveryTemplateV1,
    /// Maximum age of an authenticated source decision or observation at commit.
    pub max_source_age_ms: u64,
}
impl ReputationJournalAuthorityPolicyV1 {
    /// Validate the policy version and predecessor chain.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for an unsupported version, zero
    /// revision, non-canonical predecessor link, or unsafe freshness bound.
    pub fn validate(&self) -> Result<(), ReputationJournalValidationError> {
        if self.version != REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1 {
            return Err(
                ReputationJournalValidationError::UnsupportedAuthorityPolicyVersion {
                    found: self.version,
                },
            );
        }
        self.stream_token_delivery
            .validate()
            .map_err(|_| ReputationJournalValidationError::InvalidStreamTokenDelivery)?;
        if self
            .token_recorder_authority
            .try_signatory()
            .is_none_or(|key| key.algorithm() != iroha_crypto::Algorithm::Ed25519)
        {
            return Err(ReputationJournalValidationError::InvalidStreamTokenDelivery);
        }
        if self.revision == 0 {
            return Err(ReputationJournalValidationError::ZeroAuthorityPolicyRevision);
        }
        if self.max_source_age_ms == 0
            || self.max_source_age_ms > REPUTATION_JOURNAL_MAX_SOURCE_AGE_MS_V1
        {
            return Err(ReputationJournalValidationError::InvalidSourceAgeLimit {
                found: self.max_source_age_ms,
                maximum: REPUTATION_JOURNAL_MAX_SOURCE_AGE_MS_V1,
            });
        }
        match (self.revision, self.predecessor_policy_digest) {
            (1, None) => Ok(()),
            (1, Some(_)) => Err(ReputationJournalValidationError::UnexpectedPolicyPredecessor),
            (_, Some(digest)) if digest != [0; 32] => Ok(()),
            _ => Err(ReputationJournalValidationError::MissingPolicyPredecessor),
        }
    }
    /// Compute the canonical domain-separated policy digest.
    ///
    /// # Errors
    ///
    /// Returns a policy validation or canonical encoding error.
    pub fn canonical_digest(&self) -> Result<[u8; 32], ReputationJournalValidationError> {
        self.validate()?;
        canonical_domain_digest(REPUTATION_JOURNAL_AUTHORITY_POLICY_DIGEST_DOMAIN_V1, self)
            .map_err(|_| ReputationJournalValidationError::CanonicalEncoding)
    }
    /// Return the exact recorder authorized for `source`.
    #[must_use]
    pub const fn recorder_authority(&self, source: ReputationJournalSourceKindV1) -> &AccountId {
        match source {
            ReputationJournalSourceKindV1::Por => &self.por_recorder_authority,
            ReputationJournalSourceKindV1::ProviderDispute => &self.dispute_recorder_authority,
            ReputationJournalSourceKindV1::StreamToken => &self.token_recorder_authority,
        }
    }
}
/// Exact original native source of a governed recorder-policy activation.
///
/// Values remain claims. Core authenticates genuine genesis custody or a sole direct ordinary
/// `SetPolicy` input, and finalized readers verify that exact signed execution and successful output.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(
    tag = "origin",
    content = "execution",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::ReputationJournalPolicyOriginV1")]
pub enum ReputationJournalPolicyOriginV1 {
    /// An exact original instruction in the authenticated signed genesis input at height one.
    Genesis(crate::sorafs::stream_token_gateway::native::StreamTokenGatewayExecutionV1),
    /// A sole direct `SetPolicy` in an ordinary signed external transaction after genesis.
    Network(crate::sorafs::stream_token_gateway::native::StreamTokenGatewayExecutionV1),
}
impl ReputationJournalPolicyOriginV1 {
    /// Borrow the exact source coordinates; no block hash is stored while that block executes.
    #[must_use]
    pub fn execution(
        &self,
    ) -> &crate::sorafs::stream_token_gateway::native::StreamTokenGatewayExecutionV1 {
        match self {
            Self::Genesis(execution) | Self::Network(execution) => execution,
        }
    }
    /// Check closed origin shape without authenticating source or finality.
    ///
    /// # Errors
    /// Rejects inert coordinates, impossible genesis height or non-sole ordinary instruction.
    pub fn validate(&self) -> Result<(), ReputationJournalValidationError> {
        let execution = self.execution();
        let invalid = ReputationJournalValidationError::InvalidPolicyOrigin;
        if execution.transaction_hash == [0; 32]
            || execution.recorded_at_unix_ms == 0
            || execution.recorded_at_unix_ms == u64::MAX
        {
            return Err(invalid);
        }
        match self {
            Self::Genesis(_) if execution.height == 1 => Ok(()),
            Self::Network(_) if execution.height > 1 && execution.instruction_index == 0 => Ok(()),
            _ => Err(invalid),
        }
    }
}

/// Auditable activation record for one governed recorder-policy revision.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(
    name = "iroha_data_model::sorafs::reputation::ReputationJournalAuthorityPolicyRecordV1"
)]
pub struct ReputationJournalAuthorityPolicyRecordV1 {
    /// Canonical governed policy.
    pub policy: ReputationJournalAuthorityPolicyV1,
    /// Canonical domain-separated digest of `policy`.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub policy_digest: [u8; 32],
    /// Governance authority that activated the revision.
    pub activated_by: AccountId,
    /// Exact committing block timestamp in milliseconds since Unix epoch.
    pub activated_at_unix_ms: u64,
    /// Exact signed activation provenance; timestamp and author alone cannot identify an input.
    pub origin: ReputationJournalPolicyOriginV1,
}
impl ReputationJournalAuthorityPolicyRecordV1 {
    /// Construct and validate an auditable policy activation record.
    ///
    /// # Errors
    ///
    /// Returns a policy, digest, or timestamp validation error.
    pub fn try_new(
        policy: ReputationJournalAuthorityPolicyV1,
        activated_by: AccountId,
        activated_at_unix_ms: u64,
        origin: ReputationJournalPolicyOriginV1,
    ) -> Result<Self, ReputationJournalValidationError> {
        let policy_digest = policy.canonical_digest()?;
        ensure_digest(policy_digest, "policy_digest")?;
        ensure_timestamp(activated_at_unix_ms, "activated_at_unix_ms")?;
        let value = Self {
            policy,
            policy_digest,
            activated_by,
            activated_at_unix_ms,
            origin,
        };
        value.validate()?;
        Ok(value)
    }
    /// Validate the canonical policy digest and activation timestamp.
    ///
    /// # Errors
    ///
    /// Returns a policy, digest, or timestamp validation error.
    pub fn validate(&self) -> Result<(), ReputationJournalValidationError> {
        ensure_digest(self.policy_digest, "policy_digest")?;
        ensure_timestamp(self.activated_at_unix_ms, "activated_at_unix_ms")?;
        self.origin.validate()?;
        if self.origin.execution().authority != self.activated_by
            || self.origin.execution().recorded_at_unix_ms != self.activated_at_unix_ms
        {
            return Err(ReputationJournalValidationError::InvalidPolicyOrigin);
        }
        if self.policy_digest != self.policy.canonical_digest()? {
            return Err(ReputationJournalValidationError::AuthorityPolicyDigestMismatch);
        }
        Ok(())
    }
}
/// Stable provider-attributable `PoR` failure classification.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(tag = "kind", content = "detail", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::PorTerminalFailureKindV1")]
pub enum PorTerminalFailureKindV1 {
    /// No proof arrived before the governed deadline.
    DeadlineExpired,
    /// A proof arrived after the governed deadline.
    SubmissionLate,
    /// An authenticated proof failed binding, coverage, or Merkle verification.
    InvalidProof,
    /// Retained storage was unavailable for safe proof generation.
    StorageUnavailable,
}
impl PorTerminalFailureKindV1 {
    const fn carries_proof(self) -> bool {
        matches!(self, Self::SubmissionLate | Self::InvalidProof)
    }
}
/// `PoR` terminal that cannot safely affect provider reputation.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(tag = "kind", content = "detail", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::PorTerminalExcludedKindV1")]
pub enum PorTerminalExcludedKindV1 {
    /// Governance revoked provider admission while the challenge was active.
    AdmissionRevoked,
    /// The active admission did not authorize the provider or proof key.
    AdmissionInactive,
}
/// Final, immutable `PoR` classification.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(tag = "status", content = "detail", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::PorTerminalStatusV1")]
pub enum PorTerminalStatusV1 {
    /// The original provider proof verified before the deadline.
    Verified,
    /// The original proof failed, but governed repair recovered service.
    ///
    /// This remains a successful provider observation, but is intentionally
    /// distinct from [`Self::Verified`] so consumers never claim that the
    /// original service attempt completed without recovery.
    Repaired,
    /// The challenge ended with a provider-attributable failure.
    Failed(PorTerminalFailureKindV1),
    /// The challenge ended without a safely attributable provider observation.
    Excluded(PorTerminalExcludedKindV1),
}
impl PorTerminalStatusV1 {
    /// Whether this event increments the provider `PoR` observation counter.
    #[must_use]
    pub const fn counts_for_provider(self) -> bool {
        !matches!(self, Self::Excluded(_))
    }
    /// Whether this terminal records verified or recovered service success.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Verified | Self::Repaired)
    }
    /// Whether this terminal increments the provider `PoR` failure counter.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::Failed(_))
    }
}
/// Payload-free terminal `PoR` projection.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::PorTerminalOutcomeV1")]
pub struct PorTerminalOutcomeV1 {
    /// Native BLAKE3-256 challenge identifier.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub challenge_id: [u8; 32],
    /// Manifest named by the challenge.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub manifest_digest: [u8; 32],
    /// Challenge epoch.
    pub epoch_id: u64,
    /// drand round mixed into challenge selection.
    pub drand_round: u64,
    /// Whether the coordinator forced sampling because provider VRF was absent.
    pub forced: bool,
    /// Number of samples requested.
    pub sample_count: u16,
    /// Number of samples classified as failed.
    pub failed_samples: u16,
    /// Challenge issue time in milliseconds since Unix epoch.
    pub issued_at_unix_ms: u64,
    /// Governed response deadline in milliseconds since Unix epoch.
    pub deadline_at_unix_ms: u64,
    /// Proof receipt time, present exactly for proof-bearing terminals.
    pub responded_at_unix_ms: Option<u64>,
    /// Authenticated terminal decision time in milliseconds since Unix epoch.
    pub decided_at_unix_ms: u64,
    /// Canonical provider-signed proof digest for proof-bearing terminals.
    #[norito(json = "crate::json_helpers::fixed_bytes::option")]
    pub proof_digest: Option<[u8; 32]>,
    /// Authoritative repair task for a failed challenge.
    #[norito(json = "crate::json_helpers::fixed_bytes::option")]
    pub repair_task_id: Option<[u8; 32]>,
    /// Deterministic verifier latency in integer milliseconds.
    pub verifier_latency_ms: Option<u32>,
    /// Stable terminal classification.
    pub status: PorTerminalStatusV1,
}
impl PorTerminalOutcomeV1 {
    fn validate(&self, source_time_unix_ms: u64) -> Result<(), ReputationJournalValidationError> {
        ensure_digest(self.challenge_id, "challenge_id")?;
        ensure_digest(self.manifest_digest, "manifest_digest")?;
        if self.epoch_id == 0 || self.drand_round == 0 {
            return Err(ReputationJournalValidationError::InvalidPorRandomnessIdentity);
        }
        ensure_timestamp(self.issued_at_unix_ms, "issued_at_unix_ms")?;
        ensure_timestamp(self.deadline_at_unix_ms, "deadline_at_unix_ms")?;
        ensure_timestamp(self.decided_at_unix_ms, "decided_at_unix_ms")?;
        if self.deadline_at_unix_ms <= self.issued_at_unix_ms {
            return Err(ReputationJournalValidationError::InvalidTimestampOrder {
                earlier: "issued_at_unix_ms",
                later: "deadline_at_unix_ms",
            });
        }
        if self.decided_at_unix_ms < self.issued_at_unix_ms {
            return Err(ReputationJournalValidationError::InvalidTimestampOrder {
                earlier: "issued_at_unix_ms",
                later: "decided_at_unix_ms",
            });
        }
        if self.decided_at_unix_ms != source_time_unix_ms {
            return Err(ReputationJournalValidationError::SourceTimestampMismatch);
        }
        if let Some(responded_at) = self.responded_at_unix_ms {
            ensure_timestamp(responded_at, "responded_at_unix_ms")?;
            if responded_at < self.issued_at_unix_ms || responded_at > self.decided_at_unix_ms {
                return Err(ReputationJournalValidationError::InvalidPorResponseTimestamp);
            }
        }
        if self.sample_count == 0
            || self.failed_samples > self.sample_count
            || self.proof_digest.is_some_and(|digest| digest == [0; 32])
            || self
                .repair_task_id
                .is_some_and(|task_id| task_id == [0; 32])
        {
            return Err(ReputationJournalValidationError::InvalidPorCounters);
        }
        match self.status {
            PorTerminalStatusV1::Verified | PorTerminalStatusV1::Repaired => {
                if self.failed_samples != 0
                    || self.responded_at_unix_ms.is_none()
                    || self.proof_digest.is_none()
                    || self.repair_task_id.is_some()
                    || self.verifier_latency_ms.is_none()
                    || self
                        .responded_at_unix_ms
                        .is_some_and(|responded_at| responded_at > self.deadline_at_unix_ms)
                {
                    return Err(ReputationJournalValidationError::ImpossiblePorStatus);
                }
            }
            PorTerminalStatusV1::Failed(failure) => {
                if self.failed_samples == 0 || self.repair_task_id.is_none() {
                    return Err(ReputationJournalValidationError::ImpossiblePorStatus);
                }
                self.validate_failure_material(failure)?;
                if failure == PorTerminalFailureKindV1::DeadlineExpired
                    && self.decided_at_unix_ms < self.deadline_at_unix_ms
                {
                    return Err(ReputationJournalValidationError::ImpossiblePorStatus);
                }
            }
            PorTerminalStatusV1::Excluded(_) => {
                if self.failed_samples != 0
                    || self.responded_at_unix_ms.is_some()
                    || self.proof_digest.is_some()
                    || self.repair_task_id.is_some()
                    || self.verifier_latency_ms.is_some()
                {
                    return Err(ReputationJournalValidationError::ImpossiblePorStatus);
                }
            }
        }
        Ok(())
    }
    fn validate_failure_material(
        &self,
        failure: PorTerminalFailureKindV1,
    ) -> Result<(), ReputationJournalValidationError> {
        let proof_present = self.proof_digest.is_some();
        let response_present = self.responded_at_unix_ms.is_some();
        // PoR source timestamps have whole-second resolution. A proof and its
        // terminal decision may therefore have an exact, valid zero-millisecond
        // delta; presence, rather than positivity, carries the evidence bit.
        let latency_present = self.verifier_latency_ms.is_some();
        if failure.carries_proof() != proof_present
            || failure.carries_proof() != response_present
            || failure.carries_proof() != latency_present
        {
            return Err(ReputationJournalValidationError::ImpossiblePorStatus);
        }
        if failure == PorTerminalFailureKindV1::SubmissionLate
            && self
                .responded_at_unix_ms
                .is_none_or(|responded_at| responded_at <= self.deadline_at_unix_ms)
        {
            return Err(ReputationJournalValidationError::ImpossiblePorStatus);
        }
        Ok(())
    }
}
/// Stable provider-dispute category aligned with capacity governance.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(tag = "kind", content = "detail", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::ProviderDisputeKindV1")]
pub enum ProviderDisputeKindV1 {
    /// Provider failed replication-order requirements.
    ReplicationShortfall,
    /// Provider uptime fell below the governed SLA.
    UptimeBreach,
    /// Provider failed proof sampling.
    ProofFailure,
    /// Disagreement over fee accrual or billing.
    FeeDispute,
    /// Governed category not covered above.
    Other,
}
/// Resolution material for a terminal provider-dispute transition.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::ProviderDisputeResolutionV1")]
pub struct ProviderDisputeResolutionV1 {
    /// Existing capacity-governance outcome vocabulary.
    pub outcome: CapacityDisputeOutcome,
    /// Authenticated governance decision time.
    pub resolved_at_unix_ms: u64,
    /// Digest of the canonical decision evidence/envelope.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub decision_digest: [u8; 32],
    /// Optional bounded, canonical governance rationale.
    pub rationale: Option<String>,
}
/// Chain-authoritative provider-dispute lifecycle transition.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(tag = "status", content = "detail", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::ProviderDisputeStatusV1")]
pub enum ProviderDisputeStatusV1 {
    /// Dispute became active at `submitted_at_unix_ms`.
    Opened,
    /// Governance committed one terminal outcome.
    Resolved(
        /// Exact terminal decision material.
        ProviderDisputeResolutionV1,
    ),
}
/// Payload-free provider-dispute journal projection.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::ProviderDisputeEventV1")]
pub struct ProviderDisputeEventV1 {
    /// Existing capacity-dispute identity.
    pub dispute_id: CapacityDisputeId,
    /// Existing capacity-dispute category.
    pub kind: ProviderDisputeKindV1,
    /// Digest of the canonical evidence bundle.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub evidence_digest: [u8; 32],
    /// Authenticated source submission time.
    pub submitted_at_unix_ms: u64,
    /// Lifecycle transition.
    pub status: ProviderDisputeStatusV1,
}
impl ProviderDisputeEventV1 {
    fn validate(&self, source_time_unix_ms: u64) -> Result<(), ReputationJournalValidationError> {
        ensure_digest(*self.dispute_id.as_bytes(), "dispute_id")?;
        ensure_digest(self.evidence_digest, "evidence_digest")?;
        ensure_timestamp(self.submitted_at_unix_ms, "submitted_at_unix_ms")?;
        match &self.status {
            ProviderDisputeStatusV1::Opened => {
                if source_time_unix_ms != self.submitted_at_unix_ms {
                    return Err(ReputationJournalValidationError::SourceTimestampMismatch);
                }
            }
            ProviderDisputeStatusV1::Resolved(resolution) => {
                ensure_timestamp(resolution.resolved_at_unix_ms, "resolved_at_unix_ms")?;
                ensure_digest(resolution.decision_digest, "decision_digest")?;
                if resolution.resolved_at_unix_ms <= self.submitted_at_unix_ms {
                    return Err(ReputationJournalValidationError::InvalidTimestampOrder {
                        earlier: "submitted_at_unix_ms",
                        later: "resolved_at_unix_ms",
                    });
                }
                if source_time_unix_ms != resolution.resolved_at_unix_ms {
                    return Err(ReputationJournalValidationError::SourceTimestampMismatch);
                }
                if let Some(rationale) = &resolution.rationale {
                    validate_text(rationale)?;
                }
            }
        }
        Ok(())
    }
}
/// Provider-attributable stream-token policy violation.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(tag = "kind", content = "detail", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::StreamTokenViolationKindV1")]
pub enum StreamTokenViolationKindV1 {
    /// An authenticated token was used after its expiry.
    Expired,
    /// An authenticated token claimed an issuance time beyond allowed skew.
    FutureIssuedAt,
    /// The token did not authorize the requested manifest.
    ManifestMismatch,
    /// The token named a different chunking profile.
    ProfileMismatch,
    /// The token named a different admitted provider.
    ///
    /// The resulting journal event is attributed to the authoritative local serving provider, never
    /// the token's caller-controlled provider claim. The claimed canonical token material remains
    /// bound by [`StreamTokenValidationOutcomeV1::token_body_digest`].
    ProviderMismatch,
    /// The token exceeded its signed concurrency ceiling.
    ConcurrencyLimitExceeded,
    /// The token exceeded its signed request quota.
    RequestQuotaExceeded,
    /// The token exceeded its signed byte-rate ceiling.
    ByteRateLimitExceeded,
    /// The token identifier collided with a different signed policy.
    IdentifierPolicyConflict,
}
/// Stream-token rejection that cannot safely affect provider reputation.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(tag = "kind", content = "detail", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::StreamTokenExcludedKindV1")]
pub enum StreamTokenExcludedKindV1 {
    /// No stream token was supplied.
    MissingToken,
    /// The transport or canonical token body was malformed.
    MalformedEncoding,
    /// A decoded token carried an invalid signature.
    InvalidSignature,
    /// A decoded token named an unsupported signing-key version.
    UnsupportedKeyVersion,
    /// Fresh signer custody authority could not authorize this admission; provider reputation is excluded.
    SignerAuthorityUnavailable,
}
impl StreamTokenExcludedKindV1 {
    const fn carries_decoded_body(self) -> bool {
        matches!(
            self,
            Self::InvalidSignature | Self::UnsupportedKeyVersion | Self::SignerAuthorityUnavailable
        )
    }
}
/// Typed terminal result of one stream-token validation attempt.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(tag = "status", content = "detail", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::StreamTokenValidationStatusV1")]
pub enum StreamTokenValidationStatusV1 {
    /// The token was admitted for the requested provider-bound stream.
    Accepted,
    /// A validated provider-bound token violated signed policy.
    ProviderViolation(StreamTokenViolationKindV1),
    /// Validation or signer authority failed without a provider-attributable violation.
    Excluded(StreamTokenExcludedKindV1),
}
impl StreamTokenValidationStatusV1 {
    /// Whether this event increments the provider token-observation counter.
    #[must_use]
    pub const fn counts_for_provider(self) -> bool {
        !matches!(self, Self::Excluded(_))
    }
    /// Whether this event increments the provider token-violation counter.
    #[must_use]
    pub const fn is_violation(self) -> bool {
        matches!(self, Self::ProviderViolation(_))
    }
    const fn carries_decoded_body(self) -> bool {
        match self {
            Self::Accepted | Self::ProviderViolation(_) => true,
            Self::Excluded(reason) => reason.carries_decoded_body(),
        }
    }
}
/// Hard-cut validation failures for canonical stream-token gateway and request context.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum StreamTokenRequestContextErrorV1 {
    /// The exact network identity is malformed.
    #[error("stream-token network identity must be an exact marked genesis hash")]
    InvalidNetworkId,
    /// The governed gateway identity is empty, oversized, or not canonical.
    #[error(
        "stream-token compliance gateway identity must contain 1-{STREAM_TOKEN_COMPLIANCE_GATEWAY_ID_MAX_BYTES_V1} canonical lowercase ASCII bytes"
    )]
    InvalidComplianceGatewayId,
    /// A variable-width canonical component cannot be represented by its V1 length frame.
    #[error("stream-token canonical component `{field}` length does not fit u64")]
    LengthOverflow {
        /// Canonical component whose byte length overflowed.
        field: &'static str,
    },
    /// A domain-separated derived gateway or request commitment is inert.
    #[error("stream-token derived digest `{field}` must be non-zero")]
    ZeroDerivedDigest {
        /// Canonical derived field containing the zero digest.
        field: &'static str,
    },
    /// The request-context schema version is unsupported.
    #[error("unsupported stream-token request-context version {found}")]
    UnsupportedVersion {
        /// Version found in the rejected context.
        found: u8,
    },
    /// The authoritative local serving-provider identity is inert.
    #[error("stream-token request-context provider id must be non-zero")]
    ZeroProviderId,
    /// A required request-context digest is inert.
    #[error("stream-token request-context digest `{field}` must be non-zero")]
    ZeroContextDigest {
        /// Canonical field containing the zero digest.
        field: &'static str,
    },
    /// The manifest CID is not the exact canonical V1 dag-cbor/BLAKE3-256 CID.
    #[error(
        "stream-token request manifest CID must be the canonical {STREAM_TOKEN_REQUEST_MANIFEST_CID_BYTES_V1}-byte V1 dag-cbor/BLAKE3-256 CID"
    )]
    InvalidManifestCid,
    /// The chunk-profile handle is empty, oversized, or noncanonical.
    #[error(
        "stream-token request profile handle must contain 1-{STREAM_TOKEN_REQUEST_PROFILE_HANDLE_MAX_BYTES_V1} canonical ASCII bytes"
    )]
    InvalidProfileHandle,
    /// The raw request nonce is empty, oversized, or not visible ASCII.
    #[error(
        "stream-token request nonce must contain 1-{STREAM_TOKEN_REQUEST_NONCE_MAX_BYTES_V1} visible ASCII bytes"
    )]
    InvalidRequestNonce,
    /// A CAR byte range is reversed or its inclusive byte length overflows.
    #[error("stream-token CAR range {start}..={end_inclusive} is invalid")]
    InvalidCarRange {
        /// Inclusive first byte.
        start: u64,
        /// Inclusive last byte.
        end_inclusive: u64,
    },
    /// The chunk digest is inert.
    #[error("stream-token chunk digest must be non-zero")]
    ZeroChunkDigest,
    /// The exact stored chunk length is zero or the reserved maximum sentinel.
    #[error("stream-token stored chunk length must be finite and non-zero")]
    InvalidStoredChunkLength,
}
/// Derive the stable authenticated identity of one governed regional gateway.
///
/// The V1 hash input is:
///
/// `domain || network_id || gateway_len_le_u64 || gateway_utf8`.
///
/// The network identity is the exact genesis-header hash and the gateway component is an exact
/// canonical lowercase ASCII token. Signer public keys are deliberately excluded so signer
/// rotation cannot reset the gateway's sealed validation sequence.
///
/// # Errors
///
/// Rejects empty, oversized, noncanonical, length-overflowing, or inert input.
pub fn derive_stream_token_gateway_id_v1(
    network_id: &NetworkId,
    compliance_gateway_id: &str,
) -> Result<[u8; 32], StreamTokenRequestContextErrorV1> {
    if network_id.as_bytes()[31] & 1 != 1 {
        return Err(StreamTokenRequestContextErrorV1::InvalidNetworkId);
    }
    if !is_canonical_stream_token_identity(
        compliance_gateway_id,
        STREAM_TOKEN_COMPLIANCE_GATEWAY_ID_MAX_BYTES_V1,
    ) {
        return Err(StreamTokenRequestContextErrorV1::InvalidComplianceGatewayId);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(STREAM_TOKEN_GATEWAY_ID_DOMAIN_V1);
    hasher.update(network_id.as_bytes());
    update_length_framed_digest(
        &mut hasher,
        compliance_gateway_id.as_bytes(),
        "compliance_gateway_id",
    )?;
    nonzero_stream_token_derived_digest(hasher.finalize(), "gateway_id")
}
/// Digest of one exact presented stream-token header.
///
/// Only the domain-separated digest is retained or exposed through `Debug`;
/// raw token bytes never enter the canonical request context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
#[repr(transparent)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::StreamTokenExactHeaderDigestV1")]
pub struct StreamTokenExactHeaderDigestV1([u8; 32]);
impl StreamTokenExactHeaderDigestV1 {
    /// Commit to the exact header bytes, including empty or malformed text.
    ///
    /// # Errors
    ///
    /// Returns an error only if the byte length cannot fit the V1 frame or the
    /// domain-separated digest is the reserved all-zero value.
    pub fn from_exact_header(
        exact_header: &[u8],
    ) -> Result<Self, StreamTokenRequestContextErrorV1> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(STREAM_TOKEN_EXACT_HEADER_DIGEST_DOMAIN_V1);
        update_length_framed_digest(&mut hasher, exact_header, "stream_token_header")?;
        nonzero_stream_token_derived_digest(hasher.finalize(), "exact_header_digest").map(Self)
    }
    /// Access the exact domain-separated header digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    fn validate(self) -> Result<(), StreamTokenRequestContextErrorV1> {
        ensure_stream_token_context_digest(self.0, "exact_header_digest")
    }
}
/// Presence commitment for one stream-token presentation.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(
    tag = "presentation",
    content = "detail",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::StreamTokenPresentationV1")]
pub enum StreamTokenPresentationV1 {
    /// The request did not carry a stream-token header.
    Missing,
    /// The request carried exact bytes committed by this digest.
    ExactHeader(StreamTokenExactHeaderDigestV1),
}
impl StreamTokenPresentationV1 {
    /// Build the unambiguous missing-or-exact-header presentation.
    ///
    /// # Errors
    ///
    /// Returns an error when an exact header cannot be length-framed or its digest is inert.
    pub fn from_exact_header(
        exact_header: Option<&[u8]>,
    ) -> Result<Self, StreamTokenRequestContextErrorV1> {
        exact_header.map_or(Ok(Self::Missing), |header| {
            StreamTokenExactHeaderDigestV1::from_exact_header(header).map(Self::ExactHeader)
        })
    }
    fn validate(self) -> Result<(), StreamTokenRequestContextErrorV1> {
        match self {
            Self::Missing => Ok(()),
            Self::ExactHeader(digest) => digest.validate(),
        }
    }
}
/// Canonical inclusive CAR byte range committed by a validation context.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::StreamTokenCarRangeV1")]
pub struct StreamTokenCarRangeV1 {
    /// Inclusive first requested byte.
    pub start: u64,
    /// Inclusive last requested byte.
    pub end_inclusive: u64,
}
impl StreamTokenCarRangeV1 {
    /// Construct an ordered inclusive byte range with a representable length.
    ///
    /// # Errors
    ///
    /// Rejects reversed ranges and the full `u64` interval whose inclusive
    /// length cannot be represented.
    pub fn try_new(
        start: u64,
        end_inclusive: u64,
    ) -> Result<Self, StreamTokenRequestContextErrorV1> {
        let range = Self {
            start,
            end_inclusive,
        };
        range.byte_length()?;
        Ok(range)
    }
    /// Return the exact non-zero inclusive byte length.
    ///
    /// # Errors
    ///
    /// Rejects reversed ranges and an overflowing inclusive length.
    pub fn byte_length(self) -> Result<u64, StreamTokenRequestContextErrorV1> {
        end_inclusive_length(self.start, self.end_inclusive).ok_or(
            StreamTokenRequestContextErrorV1::InvalidCarRange {
                start: self.start,
                end_inclusive: self.end_inclusive,
            },
        )
    }
    fn validate(self) -> Result<(), StreamTokenRequestContextErrorV1> {
        self.byte_length().map(|_| ())
    }
}
/// Canonical full-chunk selector committed by a validation context.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::StreamTokenChunkRequestV1")]
pub struct StreamTokenChunkRequestV1 {
    /// Exact BLAKE3 chunk digest resolved below the manifest.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub chunk_digest: [u8; 32],
    /// Exact stored chunk length served by this request.
    pub stored_length: u64,
}
impl StreamTokenChunkRequestV1 {
    /// Construct a non-inert exact chunk selector.
    ///
    /// # Errors
    ///
    /// Rejects an all-zero digest or zero/reserved-maximum stored length.
    pub fn try_new(
        chunk_digest: [u8; 32],
        stored_length: u64,
    ) -> Result<Self, StreamTokenRequestContextErrorV1> {
        let request = Self {
            chunk_digest,
            stored_length,
        };
        request.validate()?;
        Ok(request)
    }
    fn validate(self) -> Result<(), StreamTokenRequestContextErrorV1> {
        if self.chunk_digest == [0; 32] {
            return Err(StreamTokenRequestContextErrorV1::ZeroChunkDigest);
        }
        if self.stored_length == 0 || self.stored_length == u64::MAX {
            return Err(StreamTokenRequestContextErrorV1::InvalidStoredChunkLength);
        }
        Ok(())
    }
}
/// Exact range-serving route committed by a stream-token validation context.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(
    tag = "route",
    content = "detail",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::StreamTokenRequestRouteV1")]
pub enum StreamTokenRequestRouteV1 {
    /// Canonical inclusive CAR byte range.
    CarRange(StreamTokenCarRangeV1),
    /// Exact full chunk selected by digest.
    Chunk(StreamTokenChunkRequestV1),
}
impl StreamTokenRequestRouteV1 {
    /// Construct a canonical inclusive CAR byte-range route.
    ///
    /// # Errors
    ///
    /// Rejects reversed or length-overflowing ranges.
    pub fn car_range(
        start: u64,
        end_inclusive: u64,
    ) -> Result<Self, StreamTokenRequestContextErrorV1> {
        StreamTokenCarRangeV1::try_new(start, end_inclusive).map(Self::CarRange)
    }
    /// Construct a canonical exact-chunk route.
    ///
    /// # Errors
    ///
    /// Rejects an inert digest or invalid stored length.
    pub fn chunk(
        chunk_digest: [u8; 32],
        stored_length: u64,
    ) -> Result<Self, StreamTokenRequestContextErrorV1> {
        StreamTokenChunkRequestV1::try_new(chunk_digest, stored_length).map(Self::Chunk)
    }
    fn validate(self) -> Result<(), StreamTokenRequestContextErrorV1> {
        match self {
            Self::CarRange(range) => range.validate(),
            Self::Chunk(chunk) => chunk.validate(),
        }
    }
}
/// Payload-free canonical serving context for one stream-token validation.
///
/// The context retains only the authoritative provider and public manifest, profile, and route
/// material. The raw nonce and token header are immediately reduced to separate domain-separated
/// digests. Remote addresses, forwarding headers, aliases, PII, and other caller metadata are
/// neither retained nor exposed through `Debug`.
///
/// Callers must use [`Self::try_new`] with the exact request nonce and optional raw token-header
/// bytes. Deserialized values must pass [`Self::validate`] before use.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::sorafs::reputation::StreamTokenValidationRequestContextV1"
)]
pub struct StreamTokenValidationRequestContextV1 {
    version: u8,
    provider_id: ProviderId,
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    manifest_digest: [u8; 32],
    manifest_cid: Vec<u8>,
    chunk_profile_handle: String,
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    request_nonce_digest: [u8; 32],
    token_presentation: StreamTokenPresentationV1,
    route: StreamTokenRequestRouteV1,
}
impl StreamTokenValidationRequestContextV1 {
    /// Construct and validate one exact payload-free request context.
    ///
    /// `request_nonce` and `exact_token_header` are hashed immediately and are
    /// never retained in this value.
    ///
    /// # Errors
    ///
    /// Rejects inert identities/digests, noncanonical CID/profile/nonce
    /// material, invalid route variants, and length-frame overflow.
    pub fn try_new(
        provider_id: ProviderId,
        manifest_digest: [u8; 32],
        manifest_cid: Vec<u8>,
        chunk_profile_handle: String,
        request_nonce: &str,
        exact_token_header: Option<&[u8]>,
        route: StreamTokenRequestRouteV1,
    ) -> Result<Self, StreamTokenRequestContextErrorV1> {
        validate_stream_token_request_nonce(request_nonce)?;
        let request_nonce_digest = digest_length_framed_component(
            STREAM_TOKEN_REQUEST_NONCE_DIGEST_DOMAIN_V1,
            request_nonce.as_bytes(),
            "request_nonce",
        )?;
        let context = Self {
            version: STREAM_TOKEN_REQUEST_CONTEXT_VERSION_V1,
            provider_id,
            manifest_digest,
            manifest_cid,
            chunk_profile_handle,
            request_nonce_digest,
            token_presentation: StreamTokenPresentationV1::from_exact_header(exact_token_header)?,
            route,
        };
        context.validate()?;
        Ok(context)
    }
    /// Validate a decoded V1 context before deriving its commitment.
    ///
    /// # Errors
    ///
    /// Rejects unsupported versions, inert identities/digests, noncanonical
    /// public serving material, and invalid route variants.
    pub fn validate(&self) -> Result<(), StreamTokenRequestContextErrorV1> {
        if self.version != STREAM_TOKEN_REQUEST_CONTEXT_VERSION_V1 {
            return Err(StreamTokenRequestContextErrorV1::UnsupportedVersion {
                found: self.version,
            });
        }
        if self.provider_id.as_bytes() == &[0; 32] {
            return Err(StreamTokenRequestContextErrorV1::ZeroProviderId);
        }
        ensure_stream_token_context_digest(self.manifest_digest, "manifest_digest")?;
        validate_stream_token_manifest_cid(&self.manifest_cid)?;
        validate_stream_token_profile_handle(&self.chunk_profile_handle)?;
        ensure_stream_token_context_digest(self.request_nonce_digest, "request_nonce_digest")?;
        self.token_presentation.validate()?;
        self.route.validate()
    }
    /// Derive the canonical V1 request-context digest.
    ///
    /// The fixed frame is domain, version, provider id, manifest digest,
    /// length-framed manifest CID, length-framed profile handle, nonce digest,
    /// presentation tag/material, then route tag/material. Tags are `0` for
    /// missing/CAR and `1` for exact-header/chunk. Integers use little endian.
    ///
    /// # Errors
    ///
    /// Rejects an invalid context, length overflow, or the reserved zero digest.
    pub fn digest(&self) -> Result<[u8; 32], StreamTokenRequestContextErrorV1> {
        self.validate()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(STREAM_TOKEN_REQUEST_CONTEXT_DIGEST_DOMAIN_V1);
        hasher.update(&[self.version]);
        hasher.update(self.provider_id.as_bytes());
        hasher.update(&self.manifest_digest);
        update_length_framed_digest(&mut hasher, &self.manifest_cid, "manifest_cid")?;
        update_length_framed_digest(
            &mut hasher,
            self.chunk_profile_handle.as_bytes(),
            "chunk_profile_handle",
        )?;
        hasher.update(&self.request_nonce_digest);
        match self.token_presentation {
            StreamTokenPresentationV1::Missing => {
                hasher.update(&[0]);
            }
            StreamTokenPresentationV1::ExactHeader(digest) => {
                hasher.update(&[1]);
                hasher.update(digest.as_bytes());
            }
        }
        match self.route {
            StreamTokenRequestRouteV1::CarRange(range) => {
                hasher.update(&[0]);
                hasher.update(&range.start.to_le_bytes());
                hasher.update(&range.end_inclusive.to_le_bytes());
            }
            StreamTokenRequestRouteV1::Chunk(chunk) => {
                hasher.update(&[1]);
                hasher.update(&chunk.chunk_digest);
                hasher.update(&chunk.stored_length.to_le_bytes());
            }
        }
        nonzero_stream_token_derived_digest(hasher.finalize(), "request_context_digest")
    }
    /// Return the context schema version.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }
    /// Return the authoritative local serving provider.
    #[must_use]
    pub const fn provider_id(&self) -> ProviderId {
        self.provider_id
    }
    /// Return the exact stored-manifest digest.
    #[must_use]
    pub const fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }
    /// Borrow the canonical stored-manifest CID.
    #[must_use]
    pub fn manifest_cid(&self) -> &[u8] {
        &self.manifest_cid
    }
    /// Borrow the canonical chunk-profile handle.
    #[must_use]
    pub fn chunk_profile_handle(&self) -> &str {
        &self.chunk_profile_handle
    }
    /// Return the domain-separated exact request-nonce digest.
    #[must_use]
    pub const fn request_nonce_digest(&self) -> [u8; 32] {
        self.request_nonce_digest
    }
    /// Return the missing-or-exact-header presentation commitment.
    #[must_use]
    pub const fn token_presentation(&self) -> StreamTokenPresentationV1 {
        self.token_presentation
    }
    /// Return the exact canonical range route.
    #[must_use]
    pub const fn route(&self) -> StreamTokenRequestRouteV1 {
        self.route
    }
}
/// Durable identity and request-context binding for one gateway validation.
///
/// A production gateway must allocate `gateway_sequence` from sealed monotonic state before
/// publishing an outcome. The exact fixed-width canonical binding is:
///
/// `gateway_id[32] || gateway_sequence_le[8] || request_context_digest[32]`.
///
/// There is no caller-supplied validation-id compatibility path.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::StreamTokenValidationBindingV1")]
pub struct StreamTokenValidationBindingV1 {
    /// Stable authenticated identity of the regional gateway.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub gateway_id: [u8; 32],
    /// Non-zero sequence allocated by that gateway's sealed monotonic state.
    pub gateway_sequence: u64,
    /// Digest of the exact range request and provider-serving context.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub request_context_digest: [u8; 32],
}
impl StreamTokenValidationBindingV1 {
    /// Construct a non-inert canonical gateway binding.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero gateway identity, zero sequence, or zero request-context digest.
    pub fn try_new(
        gateway_id: [u8; 32],
        gateway_sequence: u64,
        request_context_digest: [u8; 32],
    ) -> Result<Self, ReputationJournalValidationError> {
        let binding = Self {
            gateway_id,
            gateway_sequence,
            request_context_digest,
        };
        binding.validate()?;
        Ok(binding)
    }
    /// Derive the globally unique validation identity from exact binding bytes.
    #[must_use]
    pub fn validation_id(self) -> [u8; 32] {
        let mut canonical = [0_u8; 72];
        canonical[..32].copy_from_slice(&self.gateway_id);
        canonical[32..40].copy_from_slice(&self.gateway_sequence.to_le_bytes());
        canonical[40..].copy_from_slice(&self.request_context_digest);
        domain_digest(STREAM_TOKEN_VALIDATION_ID_DOMAIN_V1, &canonical)
    }
    fn validate(self) -> Result<(), ReputationJournalValidationError> {
        ensure_digest(self.gateway_id, "stream_token_gateway_id")?;
        if self.gateway_sequence == 0 {
            return Err(ReputationJournalValidationError::ZeroStreamTokenGatewaySequence);
        }
        ensure_digest(
            self.request_context_digest,
            "stream_token_request_context_digest",
        )
    }
}
/// Payload-free result of one provider-bound stream-token validation.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::StreamTokenValidationOutcomeV1")]
pub struct StreamTokenValidationOutcomeV1 {
    /// Durable gateway sequence and request-context binding.
    pub binding: StreamTokenValidationBindingV1,
    /// Canonical signed token-body digest, present exactly after successful decode.
    #[norito(json = "crate::json_helpers::fixed_bytes::option")]
    pub token_body_digest: Option<[u8; 32]>,
    /// Signing-key version from the decoded token body.
    pub token_key_version: Option<u32>,
    /// Authenticated gateway observation time in milliseconds since Unix epoch.
    pub validated_at_unix_ms: u64,
    /// Stable validation result.
    pub status: StreamTokenValidationStatusV1,
}
impl StreamTokenValidationOutcomeV1 {
    fn validate(&self, source_time_unix_ms: u64) -> Result<(), ReputationJournalValidationError> {
        self.binding.validate()?;
        ensure_digest(self.binding.validation_id(), "stream_token_validation_id")?;
        ensure_timestamp(self.validated_at_unix_ms, "validated_at_unix_ms")?;
        if self.validated_at_unix_ms != source_time_unix_ms {
            return Err(ReputationJournalValidationError::SourceTimestampMismatch);
        }
        let carries_decoded_body = self.status.carries_decoded_body();
        if carries_decoded_body != self.token_body_digest.is_some()
            || carries_decoded_body != self.token_key_version.is_some()
            || self
                .token_body_digest
                .is_some_and(|digest| digest == [0; 32])
            || self.token_key_version == Some(0)
        {
            return Err(ReputationJournalValidationError::TokenMaterialMismatch);
        }
        Ok(())
    }
}
/// One typed first-release journal payload.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(tag = "kind", content = "payload", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::ReputationJournalPayloadV1")]
pub enum ReputationJournalPayloadV1 {
    /// Terminal proof-of-retrievability projection.
    PorTerminal(PorTerminalOutcomeV1),
    /// Provider-dispute lifecycle transition.
    ProviderDispute(ProviderDisputeEventV1),
    /// Stream-token validation result.
    StreamTokenValidation(StreamTokenValidationOutcomeV1),
}
impl ReputationJournalPayloadV1 {
    /// Return the stable journal source family.
    #[must_use]
    pub const fn source_kind(&self) -> ReputationJournalSourceKindV1 {
        match self {
            Self::PorTerminal(_) => ReputationJournalSourceKindV1::Por,
            Self::ProviderDispute(_) => ReputationJournalSourceKindV1::ProviderDispute,
            Self::StreamTokenValidation(_) => ReputationJournalSourceKindV1::StreamToken,
        }
    }
    /// Return the domain-separated native source identity.
    #[must_use]
    pub fn source_id(&self) -> ReputationJournalSourceIdV1 {
        match self {
            Self::PorTerminal(outcome) => {
                ReputationJournalSourceIdV1::for_por_challenge(outcome.challenge_id)
            }
            Self::ProviderDispute(event) => {
                ReputationJournalSourceIdV1::for_provider_dispute(event.dispute_id)
            }
            Self::StreamTokenValidation(outcome) => {
                ReputationJournalSourceIdV1::for_stream_token_validation(outcome.binding)
            }
        }
    }
    const fn expected_source_revision(&self) -> u32 {
        match self {
            Self::PorTerminal(_) | Self::StreamTokenValidation(_) => 1,
            Self::ProviderDispute(event) => match &event.status {
                ProviderDisputeStatusV1::Opened => 1,
                ProviderDisputeStatusV1::Resolved(_) => 2,
            },
        }
    }
    fn validate(&self, source_time_unix_ms: u64) -> Result<(), ReputationJournalValidationError> {
        match self {
            Self::PorTerminal(outcome) => outcome.validate(source_time_unix_ms),
            Self::ProviderDispute(event) => event.validate(source_time_unix_ms),
            Self::StreamTokenValidation(outcome) => outcome.validate(source_time_unix_ms),
        }
    }
}
/// One chain-authoritative reputation journal entry.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::ReputationJournalEntryV1")]
pub struct ReputationJournalEntryV1 {
    /// Entry schema version.
    pub version: u16,
    /// Content-derived globally unique journal event id.
    pub event_id: ReputationJournalEventIdV1,
    /// Domain-separated native source id.
    pub source_id: ReputationJournalSourceIdV1,
    /// Monotonic source revision; V1 permits only dispute revision two.
    pub source_revision: u32,
    /// Exact predecessor event for source revisions after one.
    pub predecessor_event_id: Option<ReputationJournalEventIdV1>,
    /// Provider whose counters may be affected.
    pub provider_id: ProviderId,
    /// Digest of the active recorder-authority policy.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub authority_policy_digest: [u8; 32],
    /// Exact governed transaction authority that committed the entry.
    pub recorded_by: AccountId,
    /// Authenticated source decision or observation time in Unix milliseconds.
    pub source_time_unix_ms: u64,
    /// Typed, payload-free source projection.
    pub payload: ReputationJournalPayloadV1,
}
impl ReputationJournalEntryV1 {
    /// Construct and validate an entry with a canonical content-derived id.
    ///
    /// `predecessor_event_id` is required exactly for a resolved dispute and
    /// forbidden for every revision-one entry. `source_time_unix_ms` must equal
    /// the typed payload decision/observation time; consensus supplies the
    /// separate authoritative recorded time when the instruction executes.
    ///
    /// # Errors
    ///
    /// Returns a typed structural, semantic, or encoded-size validation error.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        provider_id: ProviderId,
        authority_policy_digest: [u8; 32],
        recorded_by: AccountId,
        source_time_unix_ms: u64,
        predecessor_event_id: Option<ReputationJournalEventIdV1>,
        payload: ReputationJournalPayloadV1,
    ) -> Result<Self, ReputationJournalValidationError> {
        let source_id = payload.source_id();
        let source_revision = payload.expected_source_revision();
        let mut entry = Self {
            version: REPUTATION_JOURNAL_ENTRY_VERSION_V1,
            event_id: ReputationJournalEventIdV1::ZERO,
            source_id,
            source_revision,
            predecessor_event_id,
            provider_id,
            authority_policy_digest,
            recorded_by,
            source_time_unix_ms,
            payload,
        };
        entry.event_id = entry.expected_event_id()?;
        entry.validate()?;
        Ok(entry)
    }
    /// Return the stable source family.
    #[must_use]
    pub const fn source_kind(&self) -> ReputationJournalSourceKindV1 {
        self.payload.source_kind()
    }
    /// Validate the complete canonical entry.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid ids, provider binding, timestamps,
    /// source revision linkage, payload semantics, event-id mismatch, or size.
    pub fn validate(&self) -> Result<(), ReputationJournalValidationError> {
        if self.version != REPUTATION_JOURNAL_ENTRY_VERSION_V1 {
            return Err(ReputationJournalValidationError::UnsupportedEntryVersion {
                found: self.version,
            });
        }
        if self.event_id == ReputationJournalEventIdV1::ZERO {
            return Err(ReputationJournalValidationError::ZeroEventId);
        }
        if self.source_id == ReputationJournalSourceIdV1::ZERO {
            return Err(ReputationJournalValidationError::ZeroSourceId);
        }
        if self.event_id.as_bytes() == self.source_id.as_bytes() {
            return Err(ReputationJournalValidationError::SourceEventIdCollision);
        }
        if self.provider_id.as_bytes() == &[0; 32] {
            return Err(ReputationJournalValidationError::ZeroProviderId);
        }
        ensure_digest(self.authority_policy_digest, "authority_policy_digest")?;
        ensure_timestamp(self.source_time_unix_ms, "source_time_unix_ms")?;
        self.payload.validate(self.source_time_unix_ms)?;
        if self.source_id != self.payload.source_id() {
            return Err(ReputationJournalValidationError::SourceIdMismatch);
        }
        if self.source_revision != self.payload.expected_source_revision() {
            return Err(ReputationJournalValidationError::InvalidSourceRevision);
        }
        match (self.source_revision, self.predecessor_event_id) {
            (1, None) => {}
            (1, Some(_)) => {
                return Err(ReputationJournalValidationError::UnexpectedEventPredecessor);
            }
            (2, Some(predecessor))
                if predecessor != ReputationJournalEventIdV1::ZERO
                    && predecessor != self.event_id
                    && predecessor.as_bytes() != self.source_id.as_bytes() => {}
            (2, Some(_)) => {
                return Err(ReputationJournalValidationError::InvalidEventPredecessor);
            }
            (2, None) => {
                return Err(ReputationJournalValidationError::MissingEventPredecessor);
            }
            _ => return Err(ReputationJournalValidationError::InvalidSourceRevision),
        }
        if self.event_id != self.expected_event_id()? {
            return Err(ReputationJournalValidationError::EventIdMismatch);
        }
        let encoded_len = canonical_frame_len(self)
            .map_err(|_| ReputationJournalValidationError::CanonicalEncoding)?;
        if encoded_len > REPUTATION_JOURNAL_MAX_ENTRY_BYTES_V1 {
            return Err(ReputationJournalValidationError::EntryTooLarge {
                found: encoded_len,
                maximum: REPUTATION_JOURNAL_MAX_ENTRY_BYTES_V1,
            });
        }
        Ok(())
    }
    /// Validate this entry against the exact active governed authority policy.
    ///
    /// # Errors
    ///
    /// Returns a structural entry/policy error, digest mismatch, or recorder authority mismatch.
    /// Core execution must additionally require the transaction authority to equal `recorded_by`.
    pub fn validate_against_policy(
        &self,
        policy: &ReputationJournalAuthorityPolicyV1,
    ) -> Result<(), ReputationJournalValidationError> {
        self.validate()?;
        if self.authority_policy_digest != policy.canonical_digest()? {
            return Err(ReputationJournalValidationError::AuthorityPolicyDigestMismatch);
        }
        if &self.recorded_by != policy.recorder_authority(self.source_kind()) {
            return Err(ReputationJournalValidationError::RecorderAuthorityMismatch);
        }
        Ok(())
    }
    /// Validate policy binding and source freshness at authoritative commit time.
    ///
    /// V1 accepts no future source skew: an authenticated source decision or
    /// observation must not be later than the executing block. Its age must
    /// also remain within the active governed policy bound.
    ///
    /// # Errors
    ///
    /// Returns a structural/policy error, a future source-time error, or a
    /// governed freshness violation.
    pub fn validate_at_commit(
        &self,
        policy: &ReputationJournalAuthorityPolicyV1,
        recorded_at_unix_ms: u64,
    ) -> Result<(), ReputationJournalValidationError> {
        self.validate_against_policy(policy)?;
        ensure_timestamp(recorded_at_unix_ms, "recorded_at_unix_ms")?;
        let source_age_ms = recorded_at_unix_ms
            .checked_sub(self.source_time_unix_ms)
            .ok_or(ReputationJournalValidationError::SourceTimeAfterCommit)?;
        if source_age_ms > policy.max_source_age_ms {
            return Err(ReputationJournalValidationError::SourceObservationStale {
                age_ms: source_age_ms,
                maximum_ms: policy.max_source_age_ms,
            });
        }
        Ok(())
    }
    fn expected_event_id(
        &self,
    ) -> Result<ReputationJournalEventIdV1, ReputationJournalValidationError> {
        canonical_domain_digest(
            REPUTATION_JOURNAL_EVENT_ID_DOMAIN_V1,
            &ReputationJournalEventIdSource(self),
        )
        .map(ReputationJournalEventIdV1)
        .map_err(|_| ReputationJournalValidationError::CanonicalEncoding)
    }
}
/// Authoritative head of one native reputation source lifecycle.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::ReputationJournalSourceHeadV1")]
pub struct ReputationJournalSourceHeadV1 {
    /// Source family permanently bound to the source id.
    pub source_kind: ReputationJournalSourceKindV1,
    /// Latest committed source revision.
    pub source_revision: u32,
    /// Content-derived id of the latest committed source event.
    pub event_id: ReputationJournalEventIdV1,
    /// Global journal sequence containing the latest source event.
    pub sequence: u64,
}
impl ReputationJournalSourceHeadV1 {
    /// Validate a non-inert source head.
    ///
    /// # Errors
    ///
    /// Returns a typed error for an inert revision, event id, or sequence.
    pub fn validate(self) -> Result<(), ReputationJournalValidationError> {
        let valid_revision = match self.source_kind {
            ReputationJournalSourceKindV1::ProviderDispute => {
                (1..=2).contains(&self.source_revision)
            }
            ReputationJournalSourceKindV1::Por | ReputationJournalSourceKindV1::StreamToken => {
                self.source_revision == 1
            }
        };
        if !valid_revision {
            return Err(ReputationJournalValidationError::InvalidSourceRevision);
        }
        if self.event_id == ReputationJournalEventIdV1::ZERO {
            return Err(ReputationJournalValidationError::ZeroEventId);
        }
        if self.sequence == 0 {
            return Err(ReputationJournalValidationError::InvalidJournalSequence);
        }
        Ok(())
    }
}
/// Pre-finality journal record persisted by consensus execution.
///
/// The committing block hash is deliberately absent while the block executes.
/// Fixed-view queries resolve `target_block_height` against the finalized block
/// hash journal and return [`ReputationJournalFinalizedEventV1`].
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::sorafs::reputation::ReputationJournalCommittedEventRecordV1"
)]
pub struct ReputationJournalCommittedEventRecordV1 {
    /// One-based global journal sequence.
    pub sequence: u64,
    /// Executing block height that must later resolve through finality.
    pub target_block_height: u64,
    /// Reputation-journal event index within the executing block.
    pub event_index: u32,
    /// Authoritative executing-block timestamp in Unix milliseconds.
    pub recorded_at_unix_ms: u64,
    /// Complete canonical journal entry.
    pub entry: ReputationJournalEntryV1,
}
impl ReputationJournalCommittedEventRecordV1 {
    /// Validate the persisted position and canonical journal entry.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for an inert sequence/height or entry.
    pub fn validate(&self) -> Result<(), ReputationJournalValidationError> {
        if self.sequence == 0 {
            return Err(ReputationJournalValidationError::InvalidJournalSequence);
        }
        if self.target_block_height == 0 {
            return Err(ReputationJournalValidationError::InvalidTargetBlockHeight);
        }
        ensure_timestamp(self.recorded_at_unix_ms, "recorded_at_unix_ms")?;
        self.entry.validate()?;
        if self.entry.source_time_unix_ms > self.recorded_at_unix_ms {
            return Err(ReputationJournalValidationError::SourceTimeAfterCommit);
        }
        Ok(())
    }
}
/// Finalized block anchor for one coherent journal query.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::ReputationJournalFinalizedCursorV1")]
pub struct ReputationJournalFinalizedCursorV1 {
    /// Finalized block height observed by the immutable state view.
    pub height: u64,
    /// Exact finalized block hash from that same view.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub block_hash: [u8; 32],
    /// Exact finalized block timestamp in milliseconds since Unix epoch.
    pub finalized_at_unix_ms: u64,
}
impl ReputationJournalFinalizedCursorV1 {
    /// Validate a non-inert finalized identity.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the height, block hash, or finalized
    /// timestamp is inert or otherwise reserved.
    pub fn validate(self) -> Result<(), ReputationJournalValidationError> {
        if self.height == 0
            || self.block_hash == [0; 32]
            || self.finalized_at_unix_ms == 0
            || self.finalized_at_unix_ms == u64::MAX
        {
            return Err(ReputationJournalValidationError::InvalidFinalizedCursor);
        }
        Ok(())
    }
}
/// Exclusive cursor for one committed reputation-journal event.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::sorafs::reputation::ReputationJournalFinalizedEventCursorV1"
)]
pub struct ReputationJournalFinalizedEventCursorV1 {
    /// Monotonic journal sequence beginning at one.
    pub sequence: u64,
    /// Finalized block height containing the event.
    pub block_height: u64,
    /// Exact committing block hash.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub block_hash: [u8; 32],
    /// Journal-event index within the committing block.
    pub event_index: u32,
}
impl ReputationJournalFinalizedEventCursorV1 {
    /// Validate a non-inert event cursor.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the sequence, block height, or block hash is inert.
    pub fn validate(self) -> Result<(), ReputationJournalValidationError> {
        if self.sequence == 0 || self.block_height == 0 || self.block_hash == [0; 32] {
            return Err(ReputationJournalValidationError::InvalidEventCursor);
        }
        Ok(())
    }
}
/// One typed journal entry with an unambiguous finalized-chain cursor.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sorafs::reputation::ReputationJournalFinalizedEventV1")]
pub struct ReputationJournalFinalizedEventV1 {
    /// Monotonic journal sequence beginning at one.
    pub sequence: u64,
    /// Committing block height.
    pub block_height: u64,
    /// Committing block hash.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub block_hash: [u8; 32],
    /// Journal-event index within the committing block.
    pub event_index: u32,
    /// Authoritative committing-block timestamp in Unix milliseconds.
    pub recorded_at_unix_ms: u64,
    /// Chain-authoritative journal entry.
    pub entry: ReputationJournalEntryV1,
}
impl ReputationJournalFinalizedEventV1 {
    /// Return the exclusive cursor identifying this event.
    #[must_use]
    pub const fn cursor(&self) -> ReputationJournalFinalizedEventCursorV1 {
        ReputationJournalFinalizedEventCursorV1 {
            sequence: self.sequence,
            block_height: self.block_height,
            block_hash: self.block_hash,
            event_index: self.event_index,
        }
    }
    /// Validate this event against the exact finalized view that returned it.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the event identity, entry, block position,
    /// source/commit timestamps, or finalized-height/hash binding is invalid.
    pub fn validate(
        &self,
        finalized_cursor: ReputationJournalFinalizedCursorV1,
    ) -> Result<(), ReputationJournalValidationError> {
        finalized_cursor.validate()?;
        self.cursor().validate()?;
        self.entry.validate()?;
        if self.block_height > finalized_cursor.height {
            return Err(ReputationJournalValidationError::EventBeyondFinality);
        }
        let is_at_finalized_height = self.block_height == finalized_cursor.height;
        let matches_finalized_hash = self.block_hash == finalized_cursor.block_hash;
        if is_at_finalized_height && !matches_finalized_hash {
            return Err(ReputationJournalValidationError::FinalizedBlockHashMismatch);
        }
        ensure_timestamp(self.recorded_at_unix_ms, "recorded_at_unix_ms")?;
        if self.entry.source_time_unix_ms > self.recorded_at_unix_ms {
            return Err(ReputationJournalValidationError::SourceTimeAfterCommit);
        }
        if self.recorded_at_unix_ms > finalized_cursor.finalized_at_unix_ms {
            return Err(ReputationJournalValidationError::EventAfterFinalizedTimestamp);
        }
        Ok(())
    }
}
/// Cursor-bounded page of typed committed reputation-journal events.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::sorafs::reputation::ReputationJournalFinalizedEventPageV1"
)]
pub struct ReputationJournalFinalizedEventPageV1 {
    /// Finalized state anchor shared by every event in the page.
    pub finalized_cursor: ReputationJournalFinalizedCursorV1,
    /// Events in strictly contiguous sequence and block/index order.
    pub events: Vec<ReputationJournalFinalizedEventV1>,
    /// Whether at least one later committed event exists at this anchor.
    pub has_more: bool,
    /// Exclusive continuation cursor, present exactly when `has_more` is true.
    pub next_after: Option<ReputationJournalFinalizedEventCursorV1>,
}
impl ReputationJournalFinalizedEventPageV1 {
    /// Validate page bounds, internal ordering, identities, and continuation.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed finality, invalid entries, duplicate
    /// or reordered events, source equivocation, cursor mismatch, or size.
    pub fn validate(&self) -> Result<(), ReputationJournalValidationError> {
        self.validate_after(None)
    }
    /// Validate a page against the exclusive cursor used by the query.
    ///
    /// Passing the request cursor detects stale, overlapping, or skipped
    /// continuations rather than trusting only the response's `next_after`.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed finality, event ordering or
    /// identity, source equivocation, cursor discontinuity, or page bounds.
    pub fn validate_after(
        &self,
        requested_after: Option<ReputationJournalFinalizedEventCursorV1>,
    ) -> Result<(), ReputationJournalValidationError> {
        self.finalized_cursor.validate()?;
        if self.events.len() > REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1 {
            return Err(ReputationJournalValidationError::TooManyPageItems {
                found: self.events.len(),
                maximum: REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1,
            });
        }
        if self.has_more && self.events.is_empty() {
            return Err(ReputationJournalValidationError::EmptyContinuationPage);
        }
        match (self.has_more, self.next_after, self.events.last()) {
            (true, Some(next_after), Some(last)) if next_after == last.cursor() => {}
            (true, Some(_), Some(_)) => {
                return Err(ReputationJournalValidationError::ContinuationCursorMismatch);
            }
            (true, Some(_), None) => {
                return Err(ReputationJournalValidationError::EmptyContinuationPage);
            }
            (true, None, _) => {
                return Err(ReputationJournalValidationError::MissingContinuationCursor);
            }
            (false, None, _) => {}
            (false, Some(_), _) => {
                return Err(ReputationJournalValidationError::UnexpectedContinuationCursor);
            }
        }
        if let Some(requested_after) = requested_after {
            requested_after.validate()?;
            if requested_after.block_height > self.finalized_cursor.height
                || (requested_after.block_height == self.finalized_cursor.height
                    && requested_after.block_hash != self.finalized_cursor.block_hash)
            {
                return Err(ReputationJournalValidationError::RequestedCursorMismatch);
            }
            if let Some(first) = self.events.first() {
                let expected_sequence = requested_after
                    .sequence
                    .checked_add(1)
                    .ok_or(ReputationJournalValidationError::EventSequenceOverflow)?;
                if first.sequence != expected_sequence
                    || !cursor_precedes_event(requested_after, first)
                {
                    return Err(ReputationJournalValidationError::RequestedCursorMismatch);
                }
            }
        }
        let mut previous: Option<&ReputationJournalFinalizedEventV1> = None;
        for (index, event) in self.events.iter().enumerate() {
            event.validate(self.finalized_cursor)?;
            let preceding = &self.events[..index];
            if preceding
                .iter()
                .any(|candidate| candidate.entry.event_id == event.entry.event_id)
            {
                return Err(ReputationJournalValidationError::DuplicateEventId);
            }
            if let Some(previous) = previous {
                let expected_sequence = previous
                    .sequence
                    .checked_add(1)
                    .ok_or(ReputationJournalValidationError::EventSequenceOverflow)?;
                if event.sequence <= previous.sequence {
                    return Err(ReputationJournalValidationError::EventSequenceReordered);
                }
                if event.sequence != expected_sequence {
                    return Err(ReputationJournalValidationError::EventSequenceGap);
                }
                validate_block_order(previous, event)?;
                if event.recorded_at_unix_ms < previous.recorded_at_unix_ms {
                    return Err(ReputationJournalValidationError::EventTimestampReordered);
                }
            }
            let previous_source = preceding
                .iter()
                .rev()
                .find(|candidate| candidate.entry.source_id == event.entry.source_id)
                .map(|candidate| &candidate.entry);
            validate_source_revision(previous_source, &event.entry)?;
            previous = Some(event);
        }
        let encoded_len = canonical_frame_len(self)
            .map_err(|_| ReputationJournalValidationError::CanonicalEncoding)?;
        if encoded_len > REPUTATION_JOURNAL_QUERY_MAX_EVENT_PAGE_BYTES_V1 {
            return Err(ReputationJournalValidationError::EncodedPageTooLarge {
                found: encoded_len,
                maximum: REPUTATION_JOURNAL_QUERY_MAX_EVENT_PAGE_BYTES_V1,
            });
        }
        Ok(())
    }
}
/// Structural and semantic validation failures for the V1 journal.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ReputationJournalValidationError {
    /// Policy activation lacks exact structurally valid original signed execution coordinates.
    #[error("invalid native reputation policy activation origin")]
    InvalidPolicyOrigin,
    /// Delivery template is malformed or token recorder is not a single Ed25519 account.
    #[error("invalid governed stream-token delivery template or recorder")]
    InvalidStreamTokenDelivery,
    /// Recorder policy version is unsupported.
    #[error("unsupported reputation journal authority-policy version {found}")]
    UnsupportedAuthorityPolicyVersion {
        /// Version found in the rejected policy.
        found: u16,
    },
    /// Recorder policy revision zero is reserved.
    #[error("reputation journal authority-policy revision must be non-zero")]
    ZeroAuthorityPolicyRevision,
    /// Revision one must not name a predecessor.
    #[error("reputation journal authority-policy revision one must not name a predecessor")]
    UnexpectedPolicyPredecessor,
    /// Later policy revisions require a non-zero predecessor.
    #[error("reputation journal authority-policy predecessor is missing or zero")]
    MissingPolicyPredecessor,
    /// Governed source-age bound is zero or exceeds the V1 ceiling.
    #[error("reputation journal source-age limit {found}ms is outside 1..={maximum}ms")]
    InvalidSourceAgeLimit {
        /// Rejected governed source-age limit.
        found: u64,
        /// Hard first-release maximum.
        maximum: u64,
    },
    /// Entry version is unsupported.
    #[error("unsupported reputation journal entry version {found}")]
    UnsupportedEntryVersion {
        /// Version found in the rejected entry.
        found: u16,
    },
    /// Event id zero is reserved.
    #[error("reputation journal event id must be non-zero")]
    ZeroEventId,
    /// Source id zero is reserved.
    #[error("reputation journal source id must be non-zero")]
    ZeroSourceId,
    /// Source and event identities must remain in separate namespaces.
    #[error("reputation journal source and event ids must be distinct")]
    SourceEventIdCollision,
    /// Provider id zero is inert.
    #[error("reputation journal provider id must be non-zero")]
    ZeroProviderId,
    /// A required digest is inert.
    #[error("reputation journal digest `{field}` must be non-zero")]
    ZeroDigest {
        /// Canonical field name containing the zero digest.
        field: &'static str,
    },
    /// A required timestamp is zero or the reserved maximum sentinel.
    #[error("reputation journal timestamp `{field}` must be finite and non-zero")]
    InvalidTimestamp {
        /// Canonical field name containing the invalid timestamp.
        field: &'static str,
    },
    /// Two timestamps are not in canonical order.
    #[error("reputation journal timestamp `{later}` must follow `{earlier}`")]
    InvalidTimestampOrder {
        /// Timestamp field that must occur first.
        earlier: &'static str,
        /// Timestamp field that must occur later.
        later: &'static str,
    },
    /// Common source time differs from the typed payload decision/observation.
    #[error("reputation journal source_time_unix_ms differs from the typed payload time")]
    SourceTimestampMismatch,
    /// A source decision or observation lies after the authoritative block time.
    #[error("reputation journal source time lies after authoritative commit time")]
    SourceTimeAfterCommit,
    /// Source material exceeded the active governed freshness limit.
    #[error("reputation journal source observation age {age_ms}ms exceeds {maximum_ms}ms")]
    SourceObservationStale {
        /// Observed source age at authoritative commit.
        age_ms: u64,
        /// Active governed maximum source age.
        maximum_ms: u64,
    },
    /// `PoR` epoch or drand identity is inert.
    #[error("PoR epoch and drand round must be non-zero")]
    InvalidPorRandomnessIdentity,
    /// `PoR` response time lies outside issue/decision bounds.
    #[error("PoR response timestamp lies outside the issue/decision interval")]
    InvalidPorResponseTimestamp,
    /// `PoR` sample counters or optional digests are impossible.
    #[error("PoR sample counters or optional identifiers are inconsistent")]
    InvalidPorCounters,
    /// `PoR` status does not match its proof, timing, latency, or repair fields.
    #[error("PoR terminal status is inconsistent with its evidence fields")]
    ImpossiblePorStatus,
    /// Stream-token status does not match decoded token material.
    #[error("stream-token validation status is inconsistent with decoded token material")]
    TokenMaterialMismatch,
    /// Gateway validation sequence zero is reserved.
    #[error("stream-token gateway validation sequence must be non-zero")]
    ZeroStreamTokenGatewaySequence,
    /// Governance text is empty, non-canonical, control-bearing, or too large.
    #[error("governance rationale must be trimmed control-free UTF-8 within the V1 bound")]
    InvalidText,
    /// Entry source id does not match its domain-separated native id.
    #[error("reputation journal source id does not match the typed payload")]
    SourceIdMismatch,
    /// Source revision does not match the typed lifecycle.
    #[error("reputation journal source revision is invalid for the typed payload")]
    InvalidSourceRevision,
    /// A revision-one event unexpectedly names a predecessor.
    #[error("reputation journal revision-one event must not name a predecessor")]
    UnexpectedEventPredecessor,
    /// A later source revision is missing its predecessor.
    #[error("reputation journal source revision requires a predecessor event")]
    MissingEventPredecessor,
    /// A predecessor id is zero or aliases this source/current event.
    #[error("reputation journal predecessor event id is invalid")]
    InvalidEventPredecessor,
    /// Event id does not match canonical content.
    #[error("reputation journal event id does not match canonical entry content")]
    EventIdMismatch,
    /// Entry exceeds the hard encoded-byte bound.
    #[error("reputation journal entry has {found} bytes; maximum is {maximum}")]
    EntryTooLarge {
        /// Encoded byte count found.
        found: usize,
        /// Maximum admitted encoded bytes.
        maximum: usize,
    },
    /// The active policy digest differs from the entry binding.
    #[error("reputation journal authority-policy digest mismatch")]
    AuthorityPolicyDigestMismatch,
    /// The committing account is not the governed recorder for this source.
    #[error("reputation journal recorder authority mismatch")]
    RecorderAuthorityMismatch,
    /// Canonical Norito encoding failed.
    #[error("reputation journal canonical encoding failed")]
    CanonicalEncoding,
    /// Finalized block identity is inert.
    #[error("reputation journal finalized cursor is invalid")]
    InvalidFinalizedCursor,
    /// Event cursor identity is inert.
    #[error("reputation journal event cursor is invalid")]
    InvalidEventCursor,
    /// Event lies beyond the page finality anchor.
    #[error("reputation journal event lies beyond finalized height")]
    EventBeyondFinality,
    /// An event at the final height names another block hash.
    #[error("reputation journal event hash differs from finalized block hash")]
    FinalizedBlockHashMismatch,
    /// Event timestamp lies after the finalized block timestamp.
    #[error("reputation journal event timestamp lies after finalized time")]
    EventAfterFinalizedTimestamp,
    /// Page item count exceeds the hard bound.
    #[error("reputation journal page has {found} items; maximum is {maximum}")]
    TooManyPageItems {
        /// Item count found.
        found: usize,
        /// Maximum admitted item count.
        maximum: usize,
    },
    /// Encoded page exceeds the hard byte bound.
    #[error("reputation journal page has {found} bytes; maximum is {maximum}")]
    EncodedPageTooLarge {
        /// Encoded byte count found.
        found: usize,
        /// Maximum admitted encoded bytes.
        maximum: usize,
    },
    /// A page claims continuation without advancing.
    #[error("reputation journal continuation page must contain an event")]
    EmptyContinuationPage,
    /// A continuing page omitted its cursor.
    #[error("reputation journal continuing page is missing next_after")]
    MissingContinuationCursor,
    /// A terminal page unexpectedly retained a cursor.
    #[error("reputation journal terminal page must not contain next_after")]
    UnexpectedContinuationCursor,
    /// Continuation cursor is not the last returned event.
    #[error("reputation journal next_after does not identify the last event")]
    ContinuationCursorMismatch,
    /// Query cursor and returned first event are not contiguous.
    #[error("reputation journal page does not continue its requested cursor")]
    RequestedCursorMismatch,
    /// An event id appears more than once in one page.
    #[error("reputation journal page contains a duplicate event id")]
    DuplicateEventId,
    /// Journal sequence moved backwards or repeated.
    #[error("reputation journal event sequence is reordered")]
    EventSequenceReordered,
    /// Journal sequence skipped an event.
    #[error("reputation journal event sequence contains a gap")]
    EventSequenceGap,
    /// Journal sequence overflowed.
    #[error("reputation journal event sequence overflow")]
    EventSequenceOverflow,
    /// Persisted journal sequence zero is reserved.
    #[error("reputation journal persisted sequence must be non-zero")]
    InvalidJournalSequence,
    /// Persisted target block height zero is reserved.
    #[error("reputation journal target block height must be non-zero")]
    InvalidTargetBlockHeight,
    /// Committing block/event position moved backwards or repeated.
    #[error("reputation journal block/event position is reordered")]
    BlockEventReordered,
    /// Events from one block disagree on its hash.
    #[error("reputation journal events at one height disagree on block hash")]
    BlockHashMismatch,
    /// Committing timestamps moved backwards.
    #[error("reputation journal event timestamps are reordered")]
    EventTimestampReordered,
    /// One source revision has conflicting semantic content.
    #[error("reputation journal source revision equivocation")]
    SourceEquivocation,
    /// Same-source lifecycle revisions are reordered or skip their predecessor.
    #[error("reputation journal source lifecycle is not predecessor-contiguous")]
    SourceRevisionDiscontinuity,
}
fn ensure_digest(
    digest: [u8; 32],
    field: &'static str,
) -> Result<(), ReputationJournalValidationError> {
    if digest == [0; 32] {
        return Err(ReputationJournalValidationError::ZeroDigest { field });
    }
    Ok(())
}
fn ensure_timestamp(
    timestamp: u64,
    field: &'static str,
) -> Result<(), ReputationJournalValidationError> {
    if timestamp == 0 || timestamp == u64::MAX {
        return Err(ReputationJournalValidationError::InvalidTimestamp { field });
    }
    Ok(())
}
fn validate_text(text: &str) -> Result<(), ReputationJournalValidationError> {
    if text.is_empty()
        || text.len() > REPUTATION_JOURNAL_MAX_TEXT_BYTES_V1
        || text.trim() != text
        || text.chars().any(char::is_control)
    {
        return Err(ReputationJournalValidationError::InvalidText);
    }
    Ok(())
}
fn is_canonical_stream_token_identity(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'-' | b'_' | b':')
        })
}
fn update_length_framed_digest(
    hasher: &mut blake3::Hasher,
    bytes: &[u8],
    field: &'static str,
) -> Result<(), StreamTokenRequestContextErrorV1> {
    let length = u64::try_from(bytes.len())
        .map_err(|_| StreamTokenRequestContextErrorV1::LengthOverflow { field })?;
    hasher.update(&length.to_le_bytes());
    hasher.update(bytes);
    Ok(())
}
fn nonzero_stream_token_derived_digest(
    hash: blake3::Hash,
    field: &'static str,
) -> Result<[u8; 32], StreamTokenRequestContextErrorV1> {
    let digest = *hash.as_bytes();
    if digest == [0; 32] {
        return Err(StreamTokenRequestContextErrorV1::ZeroDerivedDigest { field });
    }
    Ok(digest)
}
fn digest_length_framed_component(
    domain: &[u8],
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; 32], StreamTokenRequestContextErrorV1> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    update_length_framed_digest(&mut hasher, bytes, field)?;
    nonzero_stream_token_derived_digest(hasher.finalize(), field)
}
fn ensure_stream_token_context_digest(
    digest: [u8; 32],
    field: &'static str,
) -> Result<(), StreamTokenRequestContextErrorV1> {
    if digest == [0; 32] {
        return Err(StreamTokenRequestContextErrorV1::ZeroContextDigest { field });
    }
    Ok(())
}
fn validate_stream_token_request_nonce(
    request_nonce: &str,
) -> Result<(), StreamTokenRequestContextErrorV1> {
    if request_nonce.is_empty()
        || request_nonce.len() > STREAM_TOKEN_REQUEST_NONCE_MAX_BYTES_V1
        || !request_nonce.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(StreamTokenRequestContextErrorV1::InvalidRequestNonce);
    }
    Ok(())
}
fn validate_stream_token_manifest_cid(
    manifest_cid: &[u8],
) -> Result<(), StreamTokenRequestContextErrorV1> {
    sorafs_manifest::validate_manifest_root_cid(
        manifest_cid,
        sorafs_manifest::MANIFEST_DAG_CODEC,
        sorafs_manifest::BLAKE3_256_MULTIHASH_CODE,
    )
    .map_err(|_| StreamTokenRequestContextErrorV1::InvalidManifestCid)
}
fn validate_stream_token_profile_handle(
    profile_handle: &str,
) -> Result<(), StreamTokenRequestContextErrorV1> {
    if profile_handle.is_empty()
        || profile_handle.len() > STREAM_TOKEN_REQUEST_PROFILE_HANDLE_MAX_BYTES_V1
        || !profile_handle.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@' | b':')
        })
    {
        return Err(StreamTokenRequestContextErrorV1::InvalidProfileHandle);
    }
    Ok(())
}
fn end_inclusive_length(start: u64, end_inclusive: u64) -> Option<u64> {
    end_inclusive
        .checked_sub(start)
        .and_then(|distance| distance.checked_add(1))
}
fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}
struct Blake3Writer<'a>(&'a mut blake3::Hasher);
impl io::Write for Blake3Writer<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn canonical_domain_digest<T: norito::core::NoritoSerialize>(
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], norito::core::Error> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    norito::core::write_canonical_to_writer(value, &mut Blake3Writer(&mut hasher))?;
    Ok(*hasher.finalize().as_bytes())
}
fn canonical_frame_len<T: norito::core::NoritoSerialize>(
    value: &T,
) -> Result<usize, norito::core::Error> {
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    norito::core::encoded_frame_len(value)
}
struct ReputationJournalEventIdSource<'a>(&'a ReputationJournalEntryV1);
impl norito::NoritoSchema for ReputationJournalEventIdSource<'_> {
    fn nominal_name() -> String {
        "iroha_data_model::sorafs::reputation::ReputationJournalEventIdSource<'_>".to_owned()
    }
    fn frame_name() -> String {
        <ReputationJournalEntryV1 as norito::NoritoSchema>::frame_name()
    }
}

impl norito::core::SerializePayload for ReputationJournalEventIdSource<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        let zero = ReputationJournalEventIdV1::ZERO;
        let leading_fields: [&dyn norito::core::SerializePayload; 6] = [
            &self.0.version,
            &zero,
            &self.0.source_id,
            &self.0.source_revision,
            &self.0.predecessor_event_id,
            &self.0.provider_id,
        ];
        let trailing_fields: [&dyn norito::core::SerializePayload; 3] = [
            &self.0.recorded_by,
            &self.0.source_time_unix_ms,
            &self.0.payload,
        ];
        for field in leading_fields {
            norito::core::write_len_prefixed(writer, field)?;
        }
        norito::core::write_len(writer, self.0.authority_policy_digest.len() as u64)?;
        writer.write_all(&self.0.authority_policy_digest)?;
        for field in trailing_fields {
            norito::core::write_len_prefixed(writer, field)?;
        }
        Ok(())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        let zero = ReputationJournalEventIdV1::ZERO;
        let leading_fields: [&dyn norito::core::SerializePayload; 6] = [
            &self.0.version,
            &zero,
            &self.0.source_id,
            &self.0.source_revision,
            &self.0.predecessor_event_id,
            &self.0.provider_id,
        ];
        let trailing_fields: [&dyn norito::core::SerializePayload; 3] = [
            &self.0.recorded_by,
            &self.0.source_time_unix_ms,
            &self.0.payload,
        ];
        let leading_len = leading_fields
            .into_iter()
            .try_fold(0usize, |total, field| {
                let field_len = field.encoded_len_exact()?;
                total
                    .checked_add(norito::core::len_prefix_len(field_len))?
                    .checked_add(field_len)
            })?;
        let digest_len = self.0.authority_policy_digest.len();
        let leading_len = leading_len
            .checked_add(norito::core::len_prefix_len(digest_len))?
            .checked_add(digest_len)?;
        trailing_fields
            .into_iter()
            .try_fold(leading_len, |total, field| {
                let field_len = field.encoded_len_exact()?;
                total
                    .checked_add(norito::core::len_prefix_len(field_len))?
                    .checked_add(field_len)
            })
    }
}
fn source_id(domain: &[u8], native_id: [u8; 32]) -> ReputationJournalSourceIdV1 {
    ReputationJournalSourceIdV1(domain_digest(domain, &native_id))
}
fn cursor_precedes_event(
    cursor: ReputationJournalFinalizedEventCursorV1,
    event: &ReputationJournalFinalizedEventV1,
) -> bool {
    if cursor.block_height > event.block_height {
        return false;
    }
    if cursor.block_height == event.block_height {
        return cursor.block_hash == event.block_hash
            && cursor.event_index.checked_add(1) == Some(event.event_index);
    }
    event.event_index == 0
}
fn validate_block_order(
    previous: &ReputationJournalFinalizedEventV1,
    event: &ReputationJournalFinalizedEventV1,
) -> Result<(), ReputationJournalValidationError> {
    if event.block_height < previous.block_height {
        return Err(ReputationJournalValidationError::BlockEventReordered);
    }
    if event.block_height == previous.block_height {
        if event.block_hash != previous.block_hash {
            return Err(ReputationJournalValidationError::BlockHashMismatch);
        }
        if previous.event_index.checked_add(1) != Some(event.event_index) {
            return Err(ReputationJournalValidationError::BlockEventReordered);
        }
    } else if event.event_index != 0 {
        return Err(ReputationJournalValidationError::BlockEventReordered);
    }
    Ok(())
}
fn validate_source_revision(
    previous: Option<&ReputationJournalEntryV1>,
    entry: &ReputationJournalEntryV1,
) -> Result<(), ReputationJournalValidationError> {
    let Some(previous) = previous else {
        return Ok(());
    };
    if previous.source_kind() != entry.source_kind()
        || previous.source_revision == entry.source_revision
    {
        return Err(ReputationJournalValidationError::SourceEquivocation);
    }
    if previous.source_revision.checked_add(1) != Some(entry.source_revision)
        || entry.predecessor_event_id != Some(previous.event_id)
    {
        return Err(ReputationJournalValidationError::SourceRevisionDiscontinuity);
    }
    validate_source_revision_material(previous, entry)
}
fn validate_source_revision_material(
    predecessor: &ReputationJournalEntryV1,
    successor: &ReputationJournalEntryV1,
) -> Result<(), ReputationJournalValidationError> {
    let (
        ReputationJournalPayloadV1::ProviderDispute(opened),
        ReputationJournalPayloadV1::ProviderDispute(resolved),
    ) = (&predecessor.payload, &successor.payload)
    else {
        return Err(ReputationJournalValidationError::SourceEquivocation);
    };
    if predecessor.provider_id != successor.provider_id
        || opened.dispute_id != resolved.dispute_id
        || opened.kind != resolved.kind
        || opened.evidence_digest != resolved.evidence_digest
        || opened.submitted_at_unix_ms != resolved.submitted_at_unix_ms
        || !matches!(&opened.status, ProviderDisputeStatusV1::Opened)
        || !matches!(&resolved.status, ProviderDisputeStatusV1::Resolved(_))
    {
        return Err(ReputationJournalValidationError::SourceEquivocation);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    const BLOCK_HASH: [u8; 32] = [0xB1; 32];
    const FINAL_HASH: [u8; 32] = [0xF1; 32];
    const SOURCE_TIME: u64 = 1_700_000_001_700;
    const RECORDED_AT: u64 = SOURCE_TIME + 250;
    fn account(seed: u8) -> AccountId {
        let keypair = KeyPair::try_from_seed(vec![seed.max(1); 32], Algorithm::Ed25519)
            .expect("nonzero deterministic Ed25519 seed");
        AccountId::new(keypair.public_key().clone())
    }
    fn network_id(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::<crate::block::BlockHeader>::from_untyped_unchecked(
                iroha_crypto::Hash::new(vec![seed; 32]),
            ),
        )
    }
    fn encode_with_alternate_norito_layout<T: norito::NoritoSerialize>(value: &T) -> Vec<u8> {
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        norito::to_bytes(value).expect("encode alternate-layout reputation value")
    }
    fn policy() -> ReputationJournalAuthorityPolicyV1 {
        ReputationJournalAuthorityPolicyV1 {
            version: REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            por_recorder_authority: account(1),
            dispute_recorder_authority: account(2),
            token_recorder_authority: account(3),
            stream_token_delivery:
                crate::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryTemplateV1::default(),
            max_source_age_ms: 24 * 60 * 60 * 1_000,
        }
    }
    #[test]
    fn authority_policy_digest_ignores_ambient_norito_layout() {
        let policy = policy();
        let canonical_digest = policy.canonical_digest().expect("valid policy digest");
        let canonical_bytes =
            norito::encode_canonical(&policy).expect("encode canonical authority policy");
        assert_eq!(
            canonical_digest,
            domain_digest(
                REPUTATION_JOURNAL_AUTHORITY_POLICY_DIGEST_DOMAIN_V1,
                &canonical_bytes,
            ),
            "streamed policy hashing must preserve the canonical digest",
        );
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        assert_ne!(
            norito::to_bytes(&policy).expect("encode alternate-layout authority policy"),
            canonical_bytes,
            "fixture must exercise a distinct ambient Norito layout"
        );
        assert_eq!(
            policy
                .canonical_digest()
                .expect("digest policy under alternate ambient layout"),
            canonical_digest
        );
    }
    fn digest_from_u32(value: u32) -> [u8; 32] {
        let mut digest = [0xA5; 32];
        digest[..4].copy_from_slice(&value.to_be_bytes());
        digest
    }
    fn canonical_stream_token_manifest_cid(marker: u8) -> Vec<u8> {
        sorafs_manifest::canonical_manifest_root_cid([marker; 32])
    }
    fn stream_token_request_context(
        request_nonce: &str,
        exact_token_header: Option<&[u8]>,
        route: StreamTokenRequestRouteV1,
    ) -> Result<StreamTokenValidationRequestContextV1, StreamTokenRequestContextErrorV1> {
        StreamTokenValidationRequestContextV1::try_new(
            ProviderId::new([0x22; 32]),
            [0x33; 32],
            canonical_stream_token_manifest_cid(0x44),
            "sorafs.sf1@1.0.0".to_owned(),
            request_nonce,
            exact_token_header,
            route,
        )
    }
    fn retention_request(
        sequence: u64,
        predecessor_request_digest: Option<[u8; 32]>,
        height: u64,
        block_hash: u8,
    ) -> ReputationFinalizedArchiveRetentionRequestV1 {
        retention_request_on_network(
            network_id(0x52),
            sequence,
            predecessor_request_digest,
            height,
            block_hash,
        )
    }
    fn retention_request_on_network(
        network_id: NetworkId,
        sequence: u64,
        predecessor_request_digest: Option<[u8; 32]>,
        height: u64,
        block_hash: u8,
    ) -> ReputationFinalizedArchiveRetentionRequestV1 {
        ReputationFinalizedArchiveRetentionRequestV1::try_new(
            network_id,
            sequence,
            predecessor_request_digest,
            ReputationFinalizedArchiveRetentionTargetV1::try_new(height, [block_hash; 32])
                .expect("valid exact retention target"),
        )
        .expect("valid explicit retention request")
    }
    #[test]
    fn retention_request_digest_ignores_ambient_norito_layout() {
        let expected = retention_request(1, None, 7, 0x71);
        let canonical = norito::encode_canonical(&expected).expect("canonical retention request");
        let mut distinct_layout = false;
        for flags in 0..=u8::MAX {
            if norito::core::validate_header_flags(flags).is_err() {
                continue;
            }
            let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
            let before = norito::to_bytes(&expected).expect("ambient retention request");
            distinct_layout |= before != canonical;
            assert_eq!(retention_request(1, None, 7, 0x71), expected);
            expected.validate().expect("same digest under every layout");
            assert_ne!(
                retention_request(1, None, 7, 0x72).request_digest,
                expected.request_digest
            );
            assert_eq!(
                norito::to_bytes(&expected).expect("restored layout"),
                before
            );
        }
        assert!(distinct_layout);
    }
    #[test]
    fn retention_request_round_trips_canonically_and_as_custom_parameter() {
        let request = retention_request(1, None, 7, 0x71);
        let bytes = norito::to_bytes(&request).expect("encode retention request");
        let decoded: ReputationFinalizedArchiveRetentionRequestV1 =
            norito::decode_from_bytes(&bytes).expect("decode retention request");
        assert_eq!(decoded, request);
        assert_eq!(
            norito::to_bytes(&decoded).expect("re-encode retention request"),
            bytes
        );

        {
            let parameter = request.into_custom_parameter();
            assert_eq!(
                ReputationFinalizedArchiveRetentionRequestV1::from_custom_parameter(&parameter)
                    .expect("decode strict custom parameter"),
                Some(request)
            );
            let json = norito::json::to_string(&request).expect("encode request JSON");
            let decoded: ReputationFinalizedArchiveRetentionRequestV1 =
                norito::json::from_slice(json.as_bytes()).expect("decode request JSON");
            assert_eq!(decoded, request);
        }
    }
    #[test]
    fn retention_request_lineage_rejects_replay_substitution_skips_and_rollback() {
        let first = retention_request(1, None, 7, 0x71);
        ReputationFinalizedArchiveRetentionRequestV1::validate_transition(None, &first)
            .expect("valid initial request");
        ReputationFinalizedArchiveRetentionRequestV1::validate_transition(Some(&first), &first)
            .expect("exact replay is idempotent");
        let successor = retention_request(2, Some(first.request_digest), 8, 0x81);
        ReputationFinalizedArchiveRetentionRequestV1::validate_transition(Some(&first), &successor)
            .expect("exact successor");
        let foreign_network =
            retention_request_on_network(network_id(0x53), 2, Some(first.request_digest), 8, 0x81);
        assert_eq!(
            ReputationFinalizedArchiveRetentionRequestV1::validate_transition(
                Some(&first),
                &foreign_network,
            ),
            Err(ReputationFinalizedArchiveRetentionRequestErrorV1::NetworkChanged),
            "the same display label cannot make different genesis identities interchangeable",
        );
        let skipped = retention_request(3, Some(first.request_digest), 9, 0x91);
        assert_eq!(
            ReputationFinalizedArchiveRetentionRequestV1::validate_transition(
                Some(&first),
                &skipped,
            ),
            Err(ReputationFinalizedArchiveRetentionRequestErrorV1::NonContiguousSequence)
        );
        let wrong_predecessor = retention_request(2, Some([0xD1; 32]), 8, 0x81);
        assert_eq!(
            ReputationFinalizedArchiveRetentionRequestV1::validate_transition(
                Some(&first),
                &wrong_predecessor,
            ),
            Err(ReputationFinalizedArchiveRetentionRequestErrorV1::PredecessorDigestMismatch)
        );
        let rollback = retention_request(2, Some(first.request_digest), 7, 0x72);
        assert_eq!(
            ReputationFinalizedArchiveRetentionRequestV1::validate_transition(
                Some(&first),
                &rollback,
            ),
            Err(ReputationFinalizedArchiveRetentionRequestErrorV1::TargetDidNotAdvance)
        );
        let mut substituted = successor;
        substituted.compact_through.block_hash[0] ^= 0xFF;
        assert_eq!(
            substituted.validate(),
            Err(ReputationFinalizedArchiveRetentionRequestErrorV1::RequestDigestMismatch)
        );
    }
    fn por_payload(seed: u8) -> ReputationJournalPayloadV1 {
        ReputationJournalPayloadV1::PorTerminal(PorTerminalOutcomeV1 {
            challenge_id: [seed.max(1); 32],
            manifest_digest: [0x44; 32],
            epoch_id: 9,
            drand_round: 11,
            forced: false,
            sample_count: 8,
            failed_samples: 0,
            issued_at_unix_ms: 1_700_000_000_000,
            deadline_at_unix_ms: 1_700_000_001_500,
            responded_at_unix_ms: Some(1_700_000_001_400),
            decided_at_unix_ms: SOURCE_TIME,
            proof_digest: Some([0x55; 32]),
            repair_task_id: None,
            verifier_latency_ms: Some(7),
            status: PorTerminalStatusV1::Verified,
        })
    }
    fn por_entry(seed: u8) -> ReputationJournalEntryV1 {
        let policy = policy();
        ReputationJournalEntryV1::try_new(
            ProviderId::new([0x22; 32]),
            policy.canonical_digest().expect("policy digest"),
            policy.por_recorder_authority.clone(),
            SOURCE_TIME,
            None,
            por_payload(seed),
        )
        .expect("valid PoR entry")
    }

    fn reputation_event_id_identity_fixture_values() -> norito::json::Value {
        let rows = [0x31, 0x52].map(|seed| {
            let entry = por_entry(seed);
            let mut material = entry.clone();
            material.event_id = ReputationJournalEventIdV1::ZERO;
            let projection = ReputationJournalEventIdSource(&entry);
            let frame = norito::encode_canonical(&projection).expect("encode event-id projection");
            assert_eq!(
                entry
                    .expected_event_id()
                    .expect("derive original event identity"),
                ReputationJournalEventIdV1(domain_digest(
                    REPUTATION_JOURNAL_EVENT_ID_DOMAIN_V1,
                    &frame
                )),
            );
            crate::concrete_identity_tests::projected_record(&projection, &material)
        });
        norito::json!({"projections": (rows.to_vec())})
    }

    #[test]
    fn reputation_event_id_identity_projection_matches_capture() {
        assert_eq!(
            reputation_event_id_identity_fixture_values(),
            crate::concrete_identity_tests::fixture_values(include_str!(
                "../../tests/fixtures/reputation_event_id_identity_frames.json"
            )),
        );
    }

    #[test]
    #[ignore = "explicit maintenance command prints current reputation event-id projection frames"]
    #[expect(
        clippy::assertions_on_constants,
        reason = "This ignored fixture producer must fail at runtime when requested without its features while ordinary no-default test builds remain supported"
    )]
    fn print_reputation_event_id_identity_fixture() {
        assert!(cfg!(feature = "governance"), "capture requires governance");
        assert!(cfg!(feature = "http"), "capture requires HTTP");
        let fixture = norito::json!({
            "governance": (cfg!(feature = "governance")),
            "http": (cfg!(feature = "http")),
            "values": (reputation_event_id_identity_fixture_values()),
        });
        println!(
            "REPUTATION_EVENT_ID_FIXTURE={}",
            norito::json::to_json(&fixture).expect("current event-id projection capture")
        );
    }
    #[test]
    fn streamed_event_id_and_frame_count_match_canonical_material() {
        let entry = por_entry(0x31);
        let mut legacy_material = entry.clone();
        legacy_material.event_id = ReputationJournalEventIdV1::ZERO;
        let legacy_bytes =
            norito::encode_canonical(&legacy_material).expect("encode legacy event-id material");
        assert_eq!(
            entry.expected_event_id().expect("stream event-id material"),
            ReputationJournalEventIdV1(domain_digest(
                REPUTATION_JOURNAL_EVENT_ID_DOMAIN_V1,
                &legacy_bytes,
            )),
        );
        assert_eq!(
            canonical_frame_len(&entry).expect("count canonical entry"),
            norito::encode_canonical(&entry)
                .expect("encode canonical entry")
                .len(),
        );
    }
    fn finalized_event(
        sequence: u64,
        event_index: u32,
        seed: u8,
    ) -> ReputationJournalFinalizedEventV1 {
        ReputationJournalFinalizedEventV1 {
            sequence,
            block_height: 5,
            block_hash: BLOCK_HASH,
            event_index,
            recorded_at_unix_ms: RECORDED_AT,
            entry: por_entry(seed),
        }
    }
    fn finalized_cursor() -> ReputationJournalFinalizedCursorV1 {
        ReputationJournalFinalizedCursorV1 {
            height: 10,
            block_hash: FINAL_HASH,
            finalized_at_unix_ms: SOURCE_TIME + 1_000,
        }
    }
    fn page(
        events: Vec<ReputationJournalFinalizedEventV1>,
    ) -> ReputationJournalFinalizedEventPageV1 {
        ReputationJournalFinalizedEventPageV1 {
            finalized_cursor: finalized_cursor(),
            events,
            has_more: false,
            next_after: None,
        }
    }
    fn resolved_dispute_entry(index: u32, rationale: String) -> ReputationJournalEntryV1 {
        let policy = policy();
        ReputationJournalEntryV1::try_new(
            ProviderId::new([0x33; 32]),
            policy.canonical_digest().expect("policy digest"),
            policy.dispute_recorder_authority.clone(),
            SOURCE_TIME,
            Some(ReputationJournalEventIdV1(digest_from_u32(
                index.saturating_add(10_000),
            ))),
            ReputationJournalPayloadV1::ProviderDispute(ProviderDisputeEventV1 {
                dispute_id: CapacityDisputeId::new(digest_from_u32(index.saturating_add(1))),
                kind: ProviderDisputeKindV1::ProofFailure,
                evidence_digest: digest_from_u32(index.saturating_add(20_000)),
                submitted_at_unix_ms: SOURCE_TIME - 1_000,
                status: ProviderDisputeStatusV1::Resolved(ProviderDisputeResolutionV1 {
                    outcome: CapacityDisputeOutcome::Upheld,
                    resolved_at_unix_ms: SOURCE_TIME,
                    decision_digest: digest_from_u32(index.saturating_add(30_000)),
                    rationale: Some(rationale),
                }),
            }),
        )
        .expect("valid resolved dispute")
    }
    #[test]
    fn canonical_ids_and_policy_authority_validate() {
        let entry = por_entry(1);
        entry.validate().expect("entry validates");
        entry
            .validate_against_policy(&policy())
            .expect("governed authority validates");
        assert_ne!(entry.source_id.as_bytes(), entry.event_id.as_bytes());
        let mut wrong_authority = entry;
        wrong_authority.recorded_by = account(9);
        wrong_authority.event_id = wrong_authority.expected_event_id().expect("event id");
        assert_eq!(
            wrong_authority.validate_against_policy(&policy()),
            Err(ReputationJournalValidationError::RecorderAuthorityMismatch)
        );
    }
    #[test]
    fn source_age_policy_is_strictly_bounded() {
        let mut invalid = policy();
        invalid.max_source_age_ms = 0;
        assert_eq!(
            invalid.validate(),
            Err(ReputationJournalValidationError::InvalidSourceAgeLimit {
                found: 0,
                maximum: REPUTATION_JOURNAL_MAX_SOURCE_AGE_MS_V1,
            })
        );
        invalid.max_source_age_ms = REPUTATION_JOURNAL_MAX_SOURCE_AGE_MS_V1 + 1;
        assert_eq!(
            invalid.validate(),
            Err(ReputationJournalValidationError::InvalidSourceAgeLimit {
                found: REPUTATION_JOURNAL_MAX_SOURCE_AGE_MS_V1 + 1,
                maximum: REPUTATION_JOURNAL_MAX_SOURCE_AGE_MS_V1,
            })
        );
        invalid.max_source_age_ms = REPUTATION_JOURNAL_MAX_SOURCE_AGE_MS_V1;
        invalid
            .validate()
            .expect("the hard maximum source-age policy remains valid");
    }
    #[test]
    fn instruction_payloads_have_total_structural_order() {
        fn assert_total_order<T: Ord>() {}
        assert_total_order::<ReputationJournalAuthorityPolicyV1>();
        assert_total_order::<ReputationJournalEntryV1>();
        let first = por_entry(1);
        let second = por_entry(2);
        let ordering = first.cmp(&second);
        assert_ne!(ordering, std::cmp::Ordering::Equal);
        assert_eq!(ordering, second.cmp(&first).reverse());
    }
    #[test]
    fn policy_activation_and_persisted_index_records_fail_closed() {
        let policy = policy();
        let activation = ReputationJournalAuthorityPolicyRecordV1::try_new(
            policy.clone(),
            (account(9)).clone(),
            SOURCE_TIME,
            crate::sorafs::reputation::ReputationJournalPolicyOriginV1::Network(
                crate::sorafs::stream_token_gateway::native::StreamTokenGatewayExecutionV1 {
                    height: 2,
                    transaction_hash: [0x61; 32],
                    entry_index: 0,
                    instruction_index: 0,
                    recorded_at_unix_ms: SOURCE_TIME,
                    authority: (account(9)).clone(),
                },
            ),
        )
        .expect("canonical policy activation");
        activation.validate().expect("activation validates");
        let entry = por_entry(4);
        assert_eq!(
            entry.source_id,
            ReputationJournalSourceIdV1::for_por_challenge([4; 32])
        );
        let source_head = ReputationJournalSourceHeadV1 {
            source_kind: ReputationJournalSourceKindV1::Por,
            source_revision: 1,
            event_id: entry.event_id,
            sequence: 1,
        };
        source_head.validate().expect("source head validates");
        let committed = ReputationJournalCommittedEventRecordV1 {
            sequence: 1,
            target_block_height: 7,
            event_index: 0,
            recorded_at_unix_ms: RECORDED_AT,
            entry,
        };
        committed.validate().expect("committed event validates");
        let mut bad_activation = activation;
        bad_activation.policy_digest[0] ^= 0x01;
        assert_eq!(
            bad_activation.validate(),
            Err(ReputationJournalValidationError::AuthorityPolicyDigestMismatch)
        );
        let mut bad_committed = committed.clone();
        bad_committed.sequence = 0;
        assert_eq!(
            bad_committed.validate(),
            Err(ReputationJournalValidationError::InvalidJournalSequence)
        );
        let mut future_source = committed;
        future_source.recorded_at_unix_ms = SOURCE_TIME - 1;
        assert_eq!(
            future_source.validate(),
            Err(ReputationJournalValidationError::SourceTimeAfterCommit)
        );
    }
    #[test]
    fn zero_and_cross_bound_id_attacks_fail_closed() {
        let base = por_entry(1);
        for expected in [
            ReputationJournalValidationError::ZeroEventId,
            ReputationJournalValidationError::ZeroSourceId,
            ReputationJournalValidationError::ZeroProviderId,
        ] {
            let mut entry = base.clone();
            match expected {
                ReputationJournalValidationError::ZeroEventId => {
                    entry.event_id = ReputationJournalEventIdV1::ZERO;
                }
                ReputationJournalValidationError::ZeroSourceId => {
                    entry.source_id = ReputationJournalSourceIdV1::ZERO;
                }
                ReputationJournalValidationError::ZeroProviderId => {
                    entry.provider_id = ProviderId::new([0; 32]);
                }
                _ => unreachable!(),
            }
            assert_eq!(entry.validate(), Err(expected));
        }
        let mut wrong_source = base;
        wrong_source.source_id = source_id(REPUTATION_JOURNAL_TOKEN_SOURCE_ID_DOMAIN_V1, [1; 32]);
        assert_eq!(
            wrong_source.validate(),
            Err(ReputationJournalValidationError::SourceIdMismatch)
        );
    }
    #[test]
    fn bad_source_commit_and_freshness_timestamps_are_rejected() {
        let mut payload = por_payload(1);
        let ReputationJournalPayloadV1::PorTerminal(outcome) = &mut payload else {
            unreachable!()
        };
        outcome.deadline_at_unix_ms = outcome.issued_at_unix_ms;
        assert_eq!(
            ReputationJournalEntryV1::try_new(
                ProviderId::new([0x22; 32]),
                policy().canonical_digest().expect("policy digest"),
                policy().por_recorder_authority,
                SOURCE_TIME,
                None,
                payload,
            ),
            Err(ReputationJournalValidationError::InvalidTimestampOrder {
                earlier: "issued_at_unix_ms",
                later: "deadline_at_unix_ms",
            })
        );
        let mut entry = por_entry(2);
        entry.source_time_unix_ms += 1;
        assert_eq!(
            entry.validate(),
            Err(ReputationJournalValidationError::SourceTimestampMismatch)
        );
        let mut max_timestamp = por_entry(4);
        max_timestamp.source_time_unix_ms = u64::MAX;
        assert_eq!(
            max_timestamp.validate(),
            Err(ReputationJournalValidationError::InvalidTimestamp {
                field: "source_time_unix_ms",
            })
        );
        let entry = por_entry(5);
        let policy = policy();
        entry
            .validate_at_commit(&policy, RECORDED_AT)
            .expect("asynchronous source time remains fresh");
        assert_eq!(
            entry.validate_at_commit(&policy, SOURCE_TIME - 1),
            Err(ReputationJournalValidationError::SourceTimeAfterCommit)
        );
        assert_eq!(
            entry.validate_at_commit(&policy, SOURCE_TIME + policy.max_source_age_ms + 1,),
            Err(ReputationJournalValidationError::SourceObservationStale {
                age_ms: policy.max_source_age_ms + 1,
                maximum_ms: policy.max_source_age_ms,
            })
        );
        let mut before_source = finalized_event(1, 0, 3);
        before_source.recorded_at_unix_ms = SOURCE_TIME - 1;
        assert_eq!(
            page(vec![before_source]).validate(),
            Err(ReputationJournalValidationError::SourceTimeAfterCommit)
        );
        let event = finalized_event(1, 0, 3);
        let mut page = page(vec![event]);
        page.finalized_cursor.finalized_at_unix_ms = RECORDED_AT - 1;
        assert_eq!(
            page.validate(),
            Err(ReputationJournalValidationError::EventAfterFinalizedTimestamp)
        );
        page.finalized_cursor.finalized_at_unix_ms = u64::MAX;
        assert_eq!(
            page.validate(),
            Err(ReputationJournalValidationError::InvalidFinalizedCursor)
        );
    }
    #[test]
    fn historical_finalized_event_rejects_an_inert_finalized_view() {
        let event = finalized_event(1, 0, 3);
        let mut cursor = finalized_cursor();
        cursor.block_hash = [0; 32];
        assert_eq!(
            event.validate(cursor),
            Err(ReputationJournalValidationError::InvalidFinalizedCursor)
        );
        let mut cursor = finalized_cursor();
        cursor.finalized_at_unix_ms = 0;
        assert_eq!(
            event.validate(cursor),
            Err(ReputationJournalValidationError::InvalidFinalizedCursor)
        );
        let mut cursor = finalized_cursor();
        cursor.finalized_at_unix_ms = u64::MAX;
        assert_eq!(
            event.validate(cursor),
            Err(ReputationJournalValidationError::InvalidFinalizedCursor)
        );
    }
    #[test]
    fn proof_bearing_por_accepts_exact_zero_millisecond_latency() {
        for status in [PorTerminalStatusV1::Verified, PorTerminalStatusV1::Repaired] {
            let mut payload = por_payload(0x31);
            let ReputationJournalPayloadV1::PorTerminal(outcome) = &mut payload else {
                unreachable!()
            };
            outcome.status = status;
            outcome.deadline_at_unix_ms = SOURCE_TIME + 1_000;
            outcome.responded_at_unix_ms = Some(SOURCE_TIME);
            outcome.verifier_latency_ms = Some(0);
            let entry = ReputationJournalEntryV1::try_new(
                ProviderId::new([0x22; 32]),
                policy().canonical_digest().expect("policy digest"),
                policy().por_recorder_authority,
                SOURCE_TIME,
                None,
                payload,
            )
            .expect("whole-second source timestamps permit an exact zero-millisecond delta");
            let ReputationJournalPayloadV1::PorTerminal(outcome) = entry.payload else {
                unreachable!()
            };
            assert_eq!(outcome.status, status);
            assert!(outcome.status.counts_for_provider());
            assert!(outcome.status.is_success());
            assert!(!outcome.status.is_failure());
        }
    }
    #[test]
    fn impossible_por_counters_and_statuses_are_rejected() {
        let mut payload = por_payload(1);
        let ReputationJournalPayloadV1::PorTerminal(outcome) = &mut payload else {
            unreachable!()
        };
        outcome.failed_samples = 1;
        assert_eq!(
            ReputationJournalEntryV1::try_new(
                ProviderId::new([0x22; 32]),
                policy().canonical_digest().expect("policy digest"),
                policy().por_recorder_authority,
                SOURCE_TIME,
                None,
                payload,
            ),
            Err(ReputationJournalValidationError::ImpossiblePorStatus)
        );
        let mut payload = por_payload(2);
        let ReputationJournalPayloadV1::PorTerminal(outcome) = &mut payload else {
            unreachable!()
        };
        outcome.status = PorTerminalStatusV1::Failed(PorTerminalFailureKindV1::DeadlineExpired);
        outcome.failed_samples = outcome.sample_count + 1;
        outcome.responded_at_unix_ms = None;
        outcome.proof_digest = None;
        outcome.repair_task_id = Some([0x77; 32]);
        outcome.verifier_latency_ms = None;
        assert_eq!(
            ReputationJournalEntryV1::try_new(
                ProviderId::new([0x22; 32]),
                policy().canonical_digest().expect("policy digest"),
                policy().por_recorder_authority,
                SOURCE_TIME,
                None,
                payload,
            ),
            Err(ReputationJournalValidationError::InvalidPorCounters)
        );
    }
    #[test]
    fn por_attribution_and_repair_feed_separation_are_explicit() {
        let policy = policy();
        let mut failed_payload = por_payload(3);
        let ReputationJournalPayloadV1::PorTerminal(failed) = &mut failed_payload else {
            unreachable!()
        };
        failed.status = PorTerminalStatusV1::Failed(PorTerminalFailureKindV1::DeadlineExpired);
        failed.failed_samples = failed.sample_count;
        failed.responded_at_unix_ms = None;
        failed.proof_digest = None;
        failed.repair_task_id = Some([0x77; 32]);
        failed.verifier_latency_ms = None;
        let failed_entry = ReputationJournalEntryV1::try_new(
            ProviderId::new([0x22; 32]),
            policy.canonical_digest().expect("policy digest"),
            policy.por_recorder_authority.clone(),
            SOURCE_TIME,
            None,
            failed_payload,
        )
        .expect("original failed PoR terminal");
        let ReputationJournalPayloadV1::PorTerminal(failed) = &failed_entry.payload else {
            unreachable!()
        };
        assert!(failed.status.counts_for_provider());
        assert!(failed.status.is_failure());
        assert!(!failed.status.is_success());
        assert_eq!(failed_entry.source_revision, 1);
        let mut forbidden_recovery_revision = failed_entry;
        forbidden_recovery_revision.source_revision = 2;
        forbidden_recovery_revision.predecessor_event_id =
            Some(forbidden_recovery_revision.event_id);
        assert_eq!(
            forbidden_recovery_revision.validate(),
            Err(ReputationJournalValidationError::InvalidSourceRevision),
            "PoR recovery must arrive through the native repair feed, not replace the terminal"
        );
        let mut excluded_payload = por_payload(4);
        let ReputationJournalPayloadV1::PorTerminal(excluded) = &mut excluded_payload else {
            unreachable!()
        };
        excluded.status =
            PorTerminalStatusV1::Excluded(PorTerminalExcludedKindV1::AdmissionRevoked);
        excluded.responded_at_unix_ms = None;
        excluded.proof_digest = None;
        excluded.repair_task_id = None;
        excluded.verifier_latency_ms = None;
        let excluded_entry = ReputationJournalEntryV1::try_new(
            ProviderId::new([0x22; 32]),
            policy.canonical_digest().expect("policy digest"),
            policy.por_recorder_authority.clone(),
            SOURCE_TIME,
            None,
            excluded_payload.clone(),
        )
        .expect("non-attributable terminal");
        let ReputationJournalPayloadV1::PorTerminal(excluded) = &excluded_entry.payload else {
            unreachable!()
        };
        assert!(!excluded.status.counts_for_provider());
        assert!(!excluded.status.is_failure());
        assert!(!excluded.status.is_success());
        let ReputationJournalPayloadV1::PorTerminal(excluded) = &mut excluded_payload else {
            unreachable!()
        };
        excluded.proof_digest = Some([0x99; 32]);
        assert_eq!(
            ReputationJournalEntryV1::try_new(
                ProviderId::new([0x22; 32]),
                policy.canonical_digest().expect("policy digest"),
                policy.por_recorder_authority,
                SOURCE_TIME,
                None,
                excluded_payload,
            ),
            Err(ReputationJournalValidationError::ImpossiblePorStatus)
        );
    }
    #[test]
    fn stream_token_gateway_id_derivation_is_canonical_and_golden() {
        let taira = network_id(0x61);
        let gateway_id = derive_stream_token_gateway_id_v1(&taira, "gateway.dxb-1")
            .expect("canonical gateway identity");
        assert_eq!(
            hex::encode(gateway_id),
            "d5d601205b62a52229ade1926bb6f0986849f1e9808b86054583165f57ef2be4"
        );
        let split_a =
            derive_stream_token_gateway_id_v1(&taira, "a.bc").expect("first canonical gateway");
        let split_b =
            derive_stream_token_gateway_id_v1(&taira, "ab.c").expect("second canonical gateway");
        assert_ne!(
            split_a, split_b,
            "explicit length frames must prevent gateway-boundary aliases"
        );
        assert_ne!(
            gateway_id,
            derive_stream_token_gateway_id_v1(&network_id(0x62), "gateway.dxb-1")
                .expect("other network"),
            "same-label deployments with different genesis hashes must not alias"
        );
        assert_ne!(
            gateway_id,
            derive_stream_token_gateway_id_v1(&taira, "gateway.dxb-2").expect("other gateway"),
            "governed gateway identities must not alias"
        );
        let mut unmarked = *taira.as_bytes();
        unmarked[31] &= !1;
        assert!(
            NetworkId::decode(&mut unmarked.as_slice()).is_err(),
            "unmarked network identities must fail before gateway derivation",
        );
        let oversized_gateway = "a".repeat(STREAM_TOKEN_COMPLIANCE_GATEWAY_ID_MAX_BYTES_V1 + 1);
        for invalid_gateway in [
            "",
            "Gateway.dxb-1",
            "gateway dxb-1",
            "gateway/dxb-1",
            oversized_gateway.as_str(),
        ] {
            assert_eq!(
                derive_stream_token_gateway_id_v1(&taira, invalid_gateway),
                Err(StreamTokenRequestContextErrorV1::InvalidComplianceGatewayId)
            );
        }
    }
    #[test]
    fn stream_token_request_context_golden_vectors_and_domain_separation() {
        const HEADER: &[u8] = b"Q2Fub25pY2FsVG9rZW4=";
        let car = stream_token_request_context(
            "nonce-golden-001",
            Some(HEADER),
            StreamTokenRequestRouteV1::car_range(64, 1_023).expect("CAR range"),
        )
        .expect("CAR request context");
        assert_eq!(car.version(), STREAM_TOKEN_REQUEST_CONTEXT_VERSION_V1);
        assert_eq!(car.provider_id(), ProviderId::new([0x22; 32]));
        assert_eq!(car.manifest_digest(), [0x33; 32]);
        let expected_manifest_cid = canonical_stream_token_manifest_cid(0x44);
        assert_eq!(car.manifest_cid(), expected_manifest_cid.as_slice());
        assert_eq!(car.chunk_profile_handle(), "sorafs.sf1@1.0.0");
        assert_eq!(
            hex::encode(car.request_nonce_digest()),
            "510825647ebda3933cc33c79b0d489290723c5a40bd0d5b2343043bdb3af0459"
        );
        let StreamTokenPresentationV1::ExactHeader(header_digest) = car.token_presentation() else {
            panic!("golden request must retain an exact-header digest");
        };
        assert_eq!(
            hex::encode(header_digest.as_bytes()),
            "89f238ddbd7e236df52aa8d3a549662cbc1bf7e3a711b2fd7172fcacda77226a"
        );
        assert_eq!(
            hex::encode(car.digest().expect("CAR context digest")),
            "604075922bc0b35a3aaef5928d9ab147bf900272b1697aeb7c4c50cf9eab86a6"
        );
        let chunk = stream_token_request_context(
            "nonce-golden-001",
            Some(HEADER),
            StreamTokenRequestRouteV1::chunk([0x55; 32], 4_096).expect("chunk route"),
        )
        .expect("chunk request context");
        assert_eq!(
            hex::encode(chunk.digest().expect("chunk context digest")),
            "e0a444f4fcd79717a1e53d607f1d401acc05374a58944cb784db3e5957a07874"
        );
        assert_ne!(
            car.digest().expect("CAR digest"),
            chunk.digest().expect("chunk digest"),
            "route tags and route material must be domain separated"
        );
        let missing = stream_token_request_context(
            "nonce-golden-001",
            None,
            StreamTokenRequestRouteV1::car_range(64, 1_023).expect("CAR range"),
        )
        .expect("missing-token context");
        let empty_header = stream_token_request_context(
            "nonce-golden-001",
            Some(&[]),
            StreamTokenRequestRouteV1::car_range(64, 1_023).expect("CAR range"),
        )
        .expect("present empty-header context");
        assert_eq!(
            empty_header.token_presentation(),
            StreamTokenPresentationV1::ExactHeader(
                StreamTokenExactHeaderDigestV1::from_exact_header(&[])
                    .expect("empty header commitment")
            )
        );
        let empty_header_digest = StreamTokenExactHeaderDigestV1::from_exact_header(&[])
            .expect("empty header commitment");
        assert_eq!(
            hex::encode(empty_header_digest.as_bytes()),
            "56a3a091b6c4991e2994deb20837f5fe73478dbb4a794705b88b048bb355f9f1"
        );
        assert_ne!(
            missing.digest().expect("missing digest"),
            empty_header.digest().expect("empty-header digest"),
            "missing and present-but-empty token headers must never alias"
        );
        let gateway_id = derive_stream_token_gateway_id_v1(&network_id(0x61), "gateway.dxb-1")
            .expect("gateway id");
        assert_ne!(
            gateway_id,
            car.digest().expect("context digest"),
            "gateway and request-context domains must remain disjoint"
        );
    }
    #[test]
    fn stream_token_request_context_rejects_bounds_and_binds_every_field() {
        const HEADER: &[u8] = b"Q2Fub25pY2FsVG9rZW4=";
        let base = stream_token_request_context(
            "nonce-golden-001",
            Some(HEADER),
            StreamTokenRequestRouteV1::car_range(64, 1_023).expect("CAR range"),
        )
        .expect("base request context");
        let base_digest = base.digest().expect("base digest");
        let mut changed = base.clone();
        changed.provider_id = ProviderId::new([0x23; 32]);
        assert_ne!(changed.digest().expect("provider tamper"), base_digest);
        changed = base.clone();
        changed.manifest_digest[0] ^= 1;
        assert_ne!(changed.digest().expect("manifest tamper"), base_digest);
        changed = base.clone();
        changed.manifest_cid[4] ^= 1;
        assert_ne!(changed.digest().expect("CID tamper"), base_digest);
        changed = base.clone();
        changed.chunk_profile_handle.push('x');
        assert_ne!(changed.digest().expect("profile tamper"), base_digest);
        changed = base.clone();
        changed.request_nonce_digest[0] ^= 1;
        assert_ne!(changed.digest().expect("nonce tamper"), base_digest);
        changed = base.clone();
        changed.token_presentation =
            StreamTokenPresentationV1::from_exact_header(Some(b"different"))
                .expect("different header");
        assert_ne!(changed.digest().expect("header tamper"), base_digest);
        changed = base.clone();
        changed.route = StreamTokenRequestRouteV1::car_range(65, 1_023).expect("different range");
        assert_ne!(changed.digest().expect("range tamper"), base_digest);
        changed = base.clone();
        changed.version = STREAM_TOKEN_REQUEST_CONTEXT_VERSION_V1 + 1;
        assert_eq!(
            changed.digest(),
            Err(StreamTokenRequestContextErrorV1::UnsupportedVersion {
                found: STREAM_TOKEN_REQUEST_CONTEXT_VERSION_V1 + 1
            })
        );
        changed = base.clone();
        changed.provider_id = ProviderId::new([0; 32]);
        assert_eq!(
            changed.validate(),
            Err(StreamTokenRequestContextErrorV1::ZeroProviderId)
        );
        changed = base.clone();
        changed.manifest_digest = [0; 32];
        assert_eq!(
            changed.validate(),
            Err(StreamTokenRequestContextErrorV1::ZeroContextDigest {
                field: "manifest_digest"
            })
        );
        changed = base.clone();
        changed.request_nonce_digest = [0; 32];
        assert_eq!(
            changed.validate(),
            Err(StreamTokenRequestContextErrorV1::ZeroContextDigest {
                field: "request_nonce_digest"
            })
        );
        changed = base.clone();
        changed.manifest_cid[0] = 2;
        assert_eq!(
            changed.validate(),
            Err(StreamTokenRequestContextErrorV1::InvalidManifestCid)
        );
        changed = base.clone();
        changed.manifest_cid[4..].fill(0);
        assert_eq!(
            changed.validate(),
            Err(StreamTokenRequestContextErrorV1::InvalidManifestCid)
        );
        changed = base.clone();
        changed.chunk_profile_handle = "invalid profile".to_owned();
        assert_eq!(
            changed.validate(),
            Err(StreamTokenRequestContextErrorV1::InvalidProfileHandle)
        );
        let oversized_nonce = "n".repeat(STREAM_TOKEN_REQUEST_NONCE_MAX_BYTES_V1 + 1);
        for invalid_nonce in [
            "",
            "nonce with spaces",
            "nonce\nnewline",
            oversized_nonce.as_str(),
        ] {
            assert_eq!(
                stream_token_request_context(
                    invalid_nonce,
                    Some(HEADER),
                    StreamTokenRequestRouteV1::car_range(64, 1_023).expect("CAR range")
                ),
                Err(StreamTokenRequestContextErrorV1::InvalidRequestNonce)
            );
        }
        assert_eq!(
            StreamTokenRequestRouteV1::car_range(2, 1),
            Err(StreamTokenRequestContextErrorV1::InvalidCarRange {
                start: 2,
                end_inclusive: 1
            })
        );
        assert_eq!(
            StreamTokenRequestRouteV1::car_range(0, u64::MAX),
            Err(StreamTokenRequestContextErrorV1::InvalidCarRange {
                start: 0,
                end_inclusive: u64::MAX
            })
        );
        assert_eq!(
            StreamTokenRequestRouteV1::chunk([0; 32], 1),
            Err(StreamTokenRequestContextErrorV1::ZeroChunkDigest)
        );
        for stored_length in [0, u64::MAX] {
            assert_eq!(
                StreamTokenRequestRouteV1::chunk([0x55; 32], stored_length),
                Err(StreamTokenRequestContextErrorV1::InvalidStoredChunkLength)
            );
        }
    }
    #[test]
    fn stream_token_request_context_roundtrips_without_raw_or_alias_fields() {
        let context = stream_token_request_context(
            "nonce-golden-001",
            Some(b"Q2Fub25pY2FsVG9rZW4="),
            StreamTokenRequestRouteV1::chunk([0x55; 32], 4_096).expect("chunk route"),
        )
        .expect("request context");
        let expected_digest = context.digest().expect("context digest");
        let canonical = norito::encode_canonical(&context).expect("encode canonical context");
        let decoded: StreamTokenValidationRequestContextV1 =
            norito::decode_from_bytes(&canonical).expect("decode canonical context");
        assert_eq!(decoded, context);
        decoded.validate().expect("validate decoded context");
        assert_eq!(decoded.digest().expect("decoded digest"), expected_digest);
        let alternate = encode_with_alternate_norito_layout(&context);
        let alternate_decoded: StreamTokenValidationRequestContextV1 =
            norito::decode_from_bytes(&alternate).expect("decode alternate Norito layout");
        assert_eq!(alternate_decoded, context);
        assert_eq!(
            alternate_decoded.digest().expect("alternate digest"),
            expected_digest,
            "ambient Norito layout must not affect the fixed digest frame"
        );
        let mut trailing = canonical;
        trailing.push(0);
        assert!(
            norito::decode_from_bytes::<StreamTokenValidationRequestContextV1>(&trailing).is_err(),
            "trailing Norito bytes must fail the hard cut"
        );

        {
            let value = norito::json::to_value(&context).expect("serialize request context");
            let decoded = norito::json::value::from_value::<StreamTokenValidationRequestContextV1>(
                value.clone(),
            )
            .expect("deserialize request context");
            assert_eq!(decoded, context);
            decoded.validate().expect("validate JSON context");
            let fields = value.as_object().expect("request context object");
            for forbidden in [
                "request_nonce",
                "exact_token_header",
                "token_header",
                "remote_ip",
                "forwarded_headers",
            ] {
                assert!(
                    !fields.contains_key(forbidden),
                    "raw/private field {forbidden} must not be retained"
                );
            }
            for alias in ["request_nonce", "token_header", "chunk_digest"] {
                let mut aliased = value.clone();
                aliased
                    .as_object_mut()
                    .expect("request context object")
                    .insert(
                        alias.to_owned(),
                        norito::json::Value::String("forbidden".to_owned()),
                    );
                norito::json::value::from_value::<StreamTokenValidationRequestContextV1>(aliased)
                    .expect_err("raw, legacy, and ambiguous aliases must be rejected");
            }
            let canonical_json =
                norito::json::to_string(&context).expect("serialize canonical request JSON");
            let trailing_json = format!("{canonical_json} null");
            norito::json::from_str::<StreamTokenValidationRequestContextV1>(&trailing_json)
                .expect_err("trailing JSON values must fail the hard cut");
        }
    }
    #[test]
    fn token_status_material_is_exact_and_counter_effect_is_typed() {
        let policy = policy();
        let accepted = StreamTokenValidationOutcomeV1 {
            binding: StreamTokenValidationBindingV1 {
                gateway_id: [0x11; 32],
                gateway_sequence: 1,
                request_context_digest: [0x12; 32],
            },
            token_body_digest: Some([0x13; 32]),
            token_key_version: Some(1),
            validated_at_unix_ms: SOURCE_TIME,
            status: StreamTokenValidationStatusV1::Accepted,
        };
        let entry = ReputationJournalEntryV1::try_new(
            ProviderId::new([0x22; 32]),
            policy.canonical_digest().expect("policy digest"),
            policy.token_recorder_authority.clone(),
            SOURCE_TIME,
            None,
            ReputationJournalPayloadV1::StreamTokenValidation(accepted),
        )
        .expect("accepted token entry");
        entry
            .validate_against_policy(&policy)
            .expect("token recorder authority");
        assert!(accepted.status.counts_for_provider());
        assert!(!accepted.status.is_violation());
        assert!(
            StreamTokenValidationStatusV1::ProviderViolation(
                StreamTokenViolationKindV1::RequestQuotaExceeded
            )
            .is_violation()
        );
        assert!(
            !StreamTokenValidationStatusV1::Excluded(StreamTokenExcludedKindV1::InvalidSignature)
                .counts_for_provider()
        );
        let expected_validation_id = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(STREAM_TOKEN_VALIDATION_ID_DOMAIN_V1);
            hasher.update(&[0x11; 32]);
            hasher.update(&1_u64.to_le_bytes());
            hasher.update(&[0x12; 32]);
            *hasher.finalize().as_bytes()
        };
        assert_eq!(accepted.binding.validation_id(), expected_validation_id);
        let mut malformed = accepted;
        malformed.status =
            StreamTokenValidationStatusV1::Excluded(StreamTokenExcludedKindV1::MalformedEncoding);
        assert_eq!(
            ReputationJournalEntryV1::try_new(
                ProviderId::new([0x22; 32]),
                policy.canonical_digest().expect("policy digest"),
                policy.token_recorder_authority.clone(),
                SOURCE_TIME,
                None,
                ReputationJournalPayloadV1::StreamTokenValidation(malformed),
            ),
            Err(ReputationJournalValidationError::TokenMaterialMismatch)
        );
        for mutation in 0..3 {
            let mut invalid = accepted;
            let expected = match mutation {
                0 => {
                    invalid.binding.gateway_id = [0; 32];
                    ReputationJournalValidationError::ZeroDigest {
                        field: "stream_token_gateway_id",
                    }
                }
                1 => {
                    invalid.binding.gateway_sequence = 0;
                    ReputationJournalValidationError::ZeroStreamTokenGatewaySequence
                }
                2 => {
                    invalid.binding.request_context_digest = [0; 32];
                    ReputationJournalValidationError::ZeroDigest {
                        field: "stream_token_request_context_digest",
                    }
                }
                _ => unreachable!(),
            };
            assert_eq!(
                ReputationJournalEntryV1::try_new(
                    ProviderId::new([0x22; 32]),
                    policy.canonical_digest().expect("policy digest"),
                    policy.token_recorder_authority.clone(),
                    SOURCE_TIME,
                    None,
                    ReputationJournalPayloadV1::StreamTokenValidation(invalid),
                ),
                Err(expected)
            );
        }
        let original_source = entry.source_id;
        let mut substituted_context = accepted;
        substituted_context.binding.request_context_digest[0] ^= 1;
        let substituted = ReputationJournalEntryV1::try_new(
            ProviderId::new([0x22; 32]),
            policy.canonical_digest().expect("policy digest"),
            policy.token_recorder_authority,
            SOURCE_TIME,
            None,
            ReputationJournalPayloadV1::StreamTokenValidation(substituted_context),
        )
        .expect("substituted context remains structurally valid");
        assert_eq!(substituted.source_id, original_source);
        assert_ne!(substituted.event_id, entry.event_id);
        assert_ne!(
            substituted_context.binding.validation_id(),
            accepted.binding.validation_id()
        );

        {
            let mut aliased =
                norito::json::to_value(&accepted).expect("serialize token validation outcome");
            let fields = aliased.as_object_mut().expect("token outcome object");
            fields.insert(
                "validation_id".to_owned(),
                norito::json::Value::String("11".repeat(32)),
            );
            fields.insert(
                "request_digest".to_owned(),
                norito::json::Value::String("12".repeat(32)),
            );
            norito::json::value::from_value::<StreamTokenValidationOutcomeV1>(aliased)
                .expect_err("legacy token identity aliases must be rejected beside the binding");
            let mut nested_alias =
                norito::json::to_value(&accepted).expect("serialize token validation outcome");
            nested_alias
                .as_object_mut()
                .expect("token outcome object")
                .get_mut("binding")
                .expect("binding field")
                .as_object_mut()
                .expect("binding object")
                .insert(
                    "validation_id".to_owned(),
                    norito::json::Value::String("11".repeat(32)),
                );
            norito::json::value::from_value::<StreamTokenValidationOutcomeV1>(nested_alias)
                .expect_err("legacy token identity aliases must be rejected inside the binding");
            let mut legacy =
                norito::json::to_value(&accepted).expect("serialize token validation outcome");
            let fields = legacy.as_object_mut().expect("token outcome object");
            assert!(fields.contains_key("binding"));
            assert!(!fields.contains_key("validation_id"));
            assert!(!fields.contains_key("request_digest"));
            fields.remove("binding");
            fields.insert(
                "validation_id".to_owned(),
                norito::json::Value::String("11".repeat(32)),
            );
            fields.insert(
                "request_digest".to_owned(),
                norito::json::Value::String("12".repeat(32)),
            );
            norito::json::value::from_value::<StreamTokenValidationOutcomeV1>(legacy)
                .expect_err("caller-supplied legacy token identities must fail the V1 hard cut");
        }
    }
    #[test]
    fn text_and_page_resource_bounds_are_enforced() {
        assert_eq!(
            ReputationJournalEntryV1::try_new(
                ProviderId::new([0x33; 32]),
                policy().canonical_digest().expect("policy digest"),
                policy().dispute_recorder_authority,
                SOURCE_TIME,
                Some(ReputationJournalEventIdV1([0x88; 32])),
                ReputationJournalPayloadV1::ProviderDispute(ProviderDisputeEventV1 {
                    dispute_id: CapacityDisputeId::new([0x21; 32]),
                    kind: ProviderDisputeKindV1::Other,
                    evidence_digest: [0x22; 32],
                    submitted_at_unix_ms: SOURCE_TIME - 1,
                    status: ProviderDisputeStatusV1::Resolved(ProviderDisputeResolutionV1 {
                        outcome: CapacityDisputeOutcome::Dismissed,
                        resolved_at_unix_ms: SOURCE_TIME,
                        decision_digest: [0x23; 32],
                        rationale: Some("x".repeat(REPUTATION_JOURNAL_MAX_TEXT_BYTES_V1 + 1)),
                    }),
                }),
            ),
            Err(ReputationJournalValidationError::InvalidText)
        );
        let too_many = (0..=REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1)
            .map(|index| {
                finalized_event(
                    u64::try_from(index + 1).expect("bounded sequence"),
                    u32::try_from(index).expect("bounded event index"),
                    u8::try_from(index + 1).unwrap_or(u8::MAX),
                )
            })
            .collect();
        assert!(matches!(
            page(too_many).validate(),
            Err(ReputationJournalValidationError::TooManyPageItems { .. })
        ));
        let large_events = (0..REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1)
            .map(|index| ReputationJournalFinalizedEventV1 {
                sequence: u64::try_from(index + 1).expect("bounded sequence"),
                block_height: 5,
                block_hash: BLOCK_HASH,
                event_index: u32::try_from(index).expect("bounded event index"),
                recorded_at_unix_ms: RECORDED_AT,
                entry: resolved_dispute_entry(
                    u32::try_from(index).expect("bounded dispute index"),
                    "x".repeat(REPUTATION_JOURNAL_MAX_TEXT_BYTES_V1),
                ),
            })
            .collect();
        assert!(matches!(
            page(large_events).validate(),
            Err(ReputationJournalValidationError::EncodedPageTooLarge { .. })
        ));
    }
    #[test]
    fn duplicate_reordered_and_gapped_page_events_are_rejected() {
        let first = finalized_event(1, 0, 1);
        let mut duplicate = first.clone();
        duplicate.sequence = 2;
        duplicate.event_index = 1;
        assert_eq!(
            page(vec![first.clone(), duplicate]).validate(),
            Err(ReputationJournalValidationError::DuplicateEventId)
        );
        let mut reordered = finalized_event(1, 1, 2);
        reordered.sequence = 1;
        assert_eq!(
            page(vec![first.clone(), reordered]).validate(),
            Err(ReputationJournalValidationError::EventSequenceReordered)
        );
        let gap = finalized_event(3, 1, 3);
        assert_eq!(
            page(vec![first.clone(), gap]).validate(),
            Err(ReputationJournalValidationError::EventSequenceGap)
        );
        let mut timestamp_reordered = finalized_event(2, 1, 3);
        timestamp_reordered.recorded_at_unix_ms = RECORDED_AT - 1;
        assert_eq!(
            page(vec![first.clone(), timestamp_reordered]).validate(),
            Err(ReputationJournalValidationError::EventTimestampReordered)
        );
        let index_gap = finalized_event(2, 2, 4);
        assert_eq!(
            page(vec![first.clone(), index_gap]).validate(),
            Err(ReputationJournalValidationError::BlockEventReordered)
        );
        let mut next_block_without_reset = finalized_event(2, 1, 5);
        next_block_without_reset.block_height = 6;
        next_block_without_reset.block_hash = [0xC1; 32];
        assert_eq!(
            page(vec![first, next_block_without_reset]).validate(),
            Err(ReputationJournalValidationError::BlockEventReordered)
        );
    }
    #[test]
    fn continuation_and_requested_cursor_mismatches_are_rejected() {
        let event = finalized_event(10, 4, 1);
        let mut continuing = page(vec![event.clone()]);
        continuing.has_more = true;
        continuing.next_after = Some(ReputationJournalFinalizedEventCursorV1 {
            sequence: 9,
            ..event.cursor()
        });
        assert_eq!(
            continuing.validate(),
            Err(ReputationJournalValidationError::ContinuationCursorMismatch)
        );
        let terminal = page(vec![event]);
        assert_eq!(
            terminal.validate_after(Some(ReputationJournalFinalizedEventCursorV1 {
                sequence: 7,
                block_height: 5,
                block_hash: BLOCK_HASH,
                event_index: 3,
            })),
            Err(ReputationJournalValidationError::RequestedCursorMismatch)
        );
    }
    #[test]
    fn semantic_mutation_and_same_source_revision_are_equivocation() {
        let mut mutated = por_entry(1);
        let ReputationJournalPayloadV1::PorTerminal(outcome) = &mut mutated.payload else {
            unreachable!()
        };
        outcome.verifier_latency_ms = Some(8);
        assert_eq!(
            mutated.validate(),
            Err(ReputationJournalValidationError::EventIdMismatch)
        );
        let first = por_entry(2);
        let mut payload = first.payload.clone();
        let ReputationJournalPayloadV1::PorTerminal(outcome) = &mut payload else {
            unreachable!()
        };
        outcome.verifier_latency_ms = Some(9);
        let second_entry = ReputationJournalEntryV1::try_new(
            first.provider_id,
            first.authority_policy_digest,
            first.recorded_by.clone(),
            first.source_time_unix_ms,
            None,
            payload,
        )
        .expect("individually valid conflicting entry");
        let events = vec![
            ReputationJournalFinalizedEventV1 {
                sequence: 1,
                block_height: 5,
                block_hash: BLOCK_HASH,
                event_index: 0,
                recorded_at_unix_ms: RECORDED_AT,
                entry: first,
            },
            ReputationJournalFinalizedEventV1 {
                sequence: 2,
                block_height: 5,
                block_hash: BLOCK_HASH,
                event_index: 1,
                recorded_at_unix_ms: RECORDED_AT,
                entry: second_entry,
            },
        ];
        assert_eq!(
            page(events).validate(),
            Err(ReputationJournalValidationError::SourceEquivocation)
        );
    }
    #[test]
    fn dispute_revision_requires_exact_predecessor() {
        let opened_policy = policy();
        let opened = ReputationJournalEntryV1::try_new(
            ProviderId::new([0x33; 32]),
            opened_policy.canonical_digest().expect("policy digest"),
            opened_policy.dispute_recorder_authority.clone(),
            SOURCE_TIME - 1_000,
            None,
            ReputationJournalPayloadV1::ProviderDispute(ProviderDisputeEventV1 {
                dispute_id: CapacityDisputeId::new([0x61; 32]),
                kind: ProviderDisputeKindV1::ProofFailure,
                evidence_digest: [0x62; 32],
                submitted_at_unix_ms: SOURCE_TIME - 1_000,
                status: ProviderDisputeStatusV1::Opened,
            }),
        )
        .expect("open dispute");
        let resolved = ReputationJournalEntryV1::try_new(
            opened.provider_id,
            opened.authority_policy_digest,
            opened.recorded_by.clone(),
            SOURCE_TIME,
            Some(opened.event_id),
            ReputationJournalPayloadV1::ProviderDispute(ProviderDisputeEventV1 {
                dispute_id: CapacityDisputeId::new([0x61; 32]),
                kind: ProviderDisputeKindV1::ProofFailure,
                evidence_digest: [0x62; 32],
                submitted_at_unix_ms: SOURCE_TIME - 1_000,
                status: ProviderDisputeStatusV1::Resolved(ProviderDisputeResolutionV1 {
                    outcome: CapacityDisputeOutcome::Upheld,
                    resolved_at_unix_ms: SOURCE_TIME,
                    decision_digest: [0x63; 32],
                    rationale: Some("proof failure upheld".to_owned()),
                }),
            }),
        )
        .expect("resolve dispute");
        let events = vec![
            ReputationJournalFinalizedEventV1 {
                sequence: 1,
                block_height: 4,
                block_hash: [0x40; 32],
                event_index: 9,
                recorded_at_unix_ms: SOURCE_TIME - 500,
                entry: opened.clone(),
            },
            ReputationJournalFinalizedEventV1 {
                sequence: 2,
                block_height: 5,
                block_hash: BLOCK_HASH,
                event_index: 0,
                recorded_at_unix_ms: RECORDED_AT,
                entry: resolved.clone(),
            },
        ];
        page(events)
            .validate()
            .expect("predecessor-contiguous dispute lifecycle");
        let mut substituted_kind = resolved.payload.clone();
        let ReputationJournalPayloadV1::ProviderDispute(dispute) = &mut substituted_kind else {
            panic!("resolved fixture must contain a provider dispute");
        };
        dispute.kind = ProviderDisputeKindV1::FeeDispute;
        let mut substituted_evidence = resolved.payload.clone();
        let ReputationJournalPayloadV1::ProviderDispute(dispute) = &mut substituted_evidence else {
            panic!("resolved fixture must contain a provider dispute");
        };
        dispute.evidence_digest[0] ^= 0xFF;
        let mut substituted_submission = resolved.payload.clone();
        let ReputationJournalPayloadV1::ProviderDispute(dispute) = &mut substituted_submission
        else {
            panic!("resolved fixture must contain a provider dispute");
        };
        dispute.submitted_at_unix_ms += 1;
        for (provider_id, payload) in [
            (ProviderId::new([0x44; 32]), resolved.payload.clone()),
            (resolved.provider_id, substituted_kind),
            (resolved.provider_id, substituted_evidence),
            (resolved.provider_id, substituted_submission),
        ] {
            let substituted = ReputationJournalEntryV1::try_new(
                provider_id,
                resolved.authority_policy_digest,
                resolved.recorded_by.clone(),
                resolved.source_time_unix_ms,
                Some(opened.event_id),
                payload,
            )
            .expect("substituted immutable dispute material remains structurally valid");
            let events = vec![
                ReputationJournalFinalizedEventV1 {
                    sequence: 1,
                    block_height: 4,
                    block_hash: [0x40; 32],
                    event_index: 9,
                    recorded_at_unix_ms: SOURCE_TIME - 500,
                    entry: opened.clone(),
                },
                ReputationJournalFinalizedEventV1 {
                    sequence: 2,
                    block_height: 5,
                    block_hash: BLOCK_HASH,
                    event_index: 0,
                    recorded_at_unix_ms: RECORDED_AT,
                    entry: substituted,
                },
            ];
            assert_eq!(
                page(events).validate(),
                Err(ReputationJournalValidationError::SourceEquivocation)
            );
        }
    }
    #[test]
    fn canonical_norito_and_json_round_trip() {
        let value = page(vec![finalized_event(1, 0, 1)]);
        let bytes = norito::encode_canonical(&value).expect("encode canonical journal page");

        let canonical_json = norito::json::to_string(&value).expect("encode journal JSON");
        let expected_event_id = value.events[0].entry.event_id;
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        {
            let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            value
                .validate()
                .expect("page size gate ignores ambient layout");
            assert_eq!(
                value.events[0]
                    .entry
                    .expected_event_id()
                    .expect("derive event id under alternate ambient layout"),
                expected_event_id
            );
            assert_eq!(
                norito::encode_canonical(&value)
                    .expect("encode page under alternate ambient layout"),
                bytes
            );

            assert_eq!(
                norito::json::to_string(&value).expect("encode ambient-independent journal JSON"),
                canonical_json
            );
        }
        let decoded: ReputationJournalFinalizedEventPageV1 =
            norito::decode_canonical(&bytes).expect("decode canonical journal page");
        assert_eq!(decoded, value);
        assert_eq!(
            norito::encode_canonical(&decoded).expect("re-encode canonical journal page"),
            bytes
        );
        let alternate = encode_with_alternate_norito_layout(&value);
        let alternate_decoded: ReputationJournalFinalizedEventPageV1 =
            norito::decode_from_bytes(&alternate)
                .expect("alternate-layout journal page remains structurally decodable");
        assert_eq!(alternate_decoded, value);
        assert!(matches!(
            norito::decode_canonical::<ReputationJournalFinalizedEventPageV1>(&alternate),
            Err(norito::Error::NonCanonicalEncoding)
        ));

        {
            let decoded: ReputationJournalFinalizedEventPageV1 =
                norito::json::from_slice(canonical_json.as_bytes()).expect("decode journal JSON");
            assert_eq!(decoded, value);
        }
        let persisted = ReputationJournalCommittedEventRecordV1 {
            sequence: 1,
            target_block_height: 5,
            event_index: 0,
            recorded_at_unix_ms: RECORDED_AT,
            entry: value.events[0].entry.clone(),
        };
        persisted
            .validate()
            .expect("valid persisted journal record");
        let persisted_bytes =
            norito::encode_canonical(&persisted).expect("encode persisted journal record");
        let persisted_decoded: ReputationJournalCommittedEventRecordV1 =
            norito::decode_canonical(&persisted_bytes).expect("decode persisted journal record");
        assert_eq!(persisted_decoded, persisted);
        let persisted_alternate = encode_with_alternate_norito_layout(&persisted);
        assert!(matches!(
            norito::decode_canonical::<ReputationJournalCommittedEventRecordV1>(
                &persisted_alternate
            ),
            Err(norito::Error::NonCanonicalEncoding)
        ));
    }
    #[test]
    fn provider_dispute_resolution_norito_and_json_round_trip() {
        let value = ProviderDisputeStatusV1::Resolved(ProviderDisputeResolutionV1 {
            outcome: CapacityDisputeOutcome::Upheld,
            resolved_at_unix_ms: SOURCE_TIME,
            decision_digest: [0xD4; 32],
            rationale: Some("governance upheld the dispute".to_owned()),
        });
        let bytes = norito::encode_canonical(&value).expect("encode provider-dispute resolution");
        let decoded: ProviderDisputeStatusV1 =
            norito::decode_canonical(&bytes).expect("decode provider-dispute resolution");
        assert_eq!(decoded, value);
        assert_eq!(
            norito::encode_canonical(&decoded).expect("re-encode provider-dispute resolution"),
            bytes
        );
        let alternate = encode_with_alternate_norito_layout(&value);
        let alternate_decoded: ProviderDisputeStatusV1 = norito::decode_from_bytes(&alternate)
            .expect("alternate-layout dispute resolution remains structurally decodable");
        assert_eq!(alternate_decoded, value);
        assert!(matches!(
            norito::decode_canonical::<ProviderDisputeStatusV1>(&alternate),
            Err(norito::Error::NonCanonicalEncoding)
        ));

        {
            let json =
                norito::json::to_string(&value).expect("encode provider-dispute resolution JSON");
            let decoded: ProviderDisputeStatusV1 = norito::json::from_slice(json.as_bytes())
                .expect("decode provider-dispute resolution JSON");
            assert_eq!(decoded, value);
        }
    }
}

#[cfg(test)]
mod captured_reputation_schema_tests;

#[cfg(test)]
#[path = "reputation/stream_token_authority_tests.rs"]
mod stream_token_authority_tests;
