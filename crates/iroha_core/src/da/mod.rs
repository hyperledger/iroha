//! Data availability helpers and ingest infrastructure.
//!
//! The DA program introduces Torii ingestion, replication, and enforcement logic that
//! spans multiple crates. This module collects shared building blocks that are consumed
//! by Torii surfaces, orchestrators, and validation pipelines.
#![allow(clippy::module_name_repetitions)]
pub mod commitment_store;
pub mod commitments;
pub mod confidential;
pub mod confidential_store;
pub mod pin_intents;
pub mod pin_store;
pub mod proofs;
pub(crate) mod quota;
pub mod receipts;
pub mod replay_cache;
pub mod shard_cursor;
use crate::da::pin_intents::{PinIntentDropReason, canonicalize_bundle};
use crate::governance::manifest::lane_uses_reserved_autoscale_metadata;
pub use confidential::{ConfidentialComputeError, validate_confidential_compute_record};
use iroha_config::parameters::actual::{LaneConfig, LaneConfigEntry, Nexus};
use iroha_crypto::Hash;
#[cfg(any(test, feature = "iroha-core-tests"))]
use iroha_crypto::HashOf;
use iroha_data_model::{
    NetworkId,
    account::{AccountController, AccountId},
    da::{
        commitment::{
            DaCommitmentBundle, DaCommitmentKey, DaCommitmentRecord, DaProofPolicyBundle,
            DaProofScheme,
        },
        pin_intent::MAX_DA_PIN_INTENT_ALIAS_BYTES,
        prelude::DaProofPolicy,
    },
};
use iroha_model_base::topology::LaneId;
pub use proofs::{
    DaPinIntentProofVerificationError, DaProofVerificationError, build_da_commitment_proof,
    build_da_pin_intent_proof, verify_da_commitment_proof, verify_da_pin_intent_proof,
};
pub use replay_cache::{
    LaneEpoch, ReplayCache, ReplayCacheConfig, ReplayFingerprint, ReplayInsertOutcome, ReplayKey,
    ReplayPrimeError, ReplayReservation,
};
pub use shard_cursor::{
    DaShardCursor, DaShardCursorError, DaShardCursorIndex, DaShardCursorJournal, LaneShardCursor,
    ShardCursorJournalError,
};
use std::collections::BTreeSet;
use thiserror::Error;
/// Errors returned when a DA commitment violates the configured lane proof policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DaProofPolicyError {
    /// Lane referenced by the commitment is not present in the configured catalog.
    #[error("lane {lane} not present in the configured lane catalog")]
    UnknownLane {
        /// Lane identifier that failed the lookup.
        lane: LaneId,
    },
    /// Commitment advertises a proof scheme that differs from the lane policy.
    #[error("lane {lane} expects proof scheme {expected} but commitment uses {observed}")]
    SchemeMismatch {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Proof scheme declared in the lane catalog.
        expected: DaProofScheme,
        /// Proof scheme attached to the commitment.
        observed: DaProofScheme,
    },
    /// Chunk root is zeroed for the commitment.
    #[error("lane {lane} carries a zeroed chunk_root commitment")]
    ZeroChunkRoot {
        /// Lane identifier that failed validation.
        lane: LaneId,
    },
    /// The committed proof-policy bundle uses an unsupported layout version.
    #[error("unsupported DA proof-policy bundle version {version}")]
    UnsupportedPolicyBundleVersion {
        /// Observed bundle version.
        version: u16,
    },
    /// The committed bundle's internal policy hash does not match its policies.
    #[error("DA proof-policy bundle carries an invalid internal policy hash")]
    PolicyBundleHashMismatch,
    /// A committed bundle contains more than one policy for the same lane.
    #[error("DA proof-policy bundle contains duplicate policies for lane {lane}")]
    DuplicateLanePolicy {
        /// Lane with duplicate policy entries.
        lane: LaneId,
    },
}
/// Errors returned when a DA commitment bundle violates invariants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DaCommitmentValidationError {
    /// Commitment bundle uses an unsupported layout version.
    #[error("unsupported DA commitment bundle version {version}")]
    UnsupportedVersion {
        /// Observed bundle version.
        version: u16,
    },
    /// Underlying proof policy validation failed.
    #[error(transparent)]
    ProofPolicy(#[from] DaProofPolicyError),
    /// Confidential-compute policy validation failed.
    #[error(transparent)]
    ConfidentialCompute(#[from] ConfidentialComputeError),
    /// Commitment bundle length cannot be represented in DA location/proof metadata.
    #[error("DA commitment bundle length {len} exceeds representable maximum {max}")]
    BundleTooLarge {
        /// Number of commitments in the bundle.
        len: usize,
        /// Maximum supported commitment count for one bundle.
        max: usize,
    },
    /// Commitment bundle entries are not in canonical sort order.
    #[error("DA commitment bundle is not in canonical order at index {index}")]
    NonCanonicalOrder {
        /// First entry index that differs from canonical ordering.
        index: usize,
    },
    /// Duplicate `(lane, epoch, sequence)` commitment found.
    #[error(
        "duplicate DA commitment detected for lane {key_lane}, epoch {epoch}, sequence {sequence}"
    )]
    DuplicateCommitment {
        /// Lane identifier that failed validation.
        key_lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence number that failed validation.
        sequence: u64,
    },
    /// Duplicate manifest hash detected within the bundle.
    #[error("duplicate DA manifest hash detected for lane {lane}")]
    DuplicateManifest {
        /// Lane identifier that failed validation.
        lane: LaneId,
    },
    /// Manifest hash already exists in a previously committed DA record.
    #[error(
        "DA manifest hash for lane {lane}, epoch {epoch}, sequence {sequence} was already committed at lane {existing_lane}, epoch {existing_epoch}, sequence {existing_sequence}"
    )]
    CommittedManifest {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence number that failed validation.
        sequence: u64,
        /// Lane identifier of the already committed record.
        existing_lane: LaneId,
        /// Epoch of the already committed record.
        existing_epoch: u64,
        /// Sequence number of the already committed record.
        existing_sequence: u64,
    },
    /// Duplicate storage ticket detected within the bundle.
    #[error(
        "duplicate DA storage ticket detected for lane {lane}, epoch {epoch}, sequence {sequence}"
    )]
    DuplicateStorageTicket {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence number that failed validation.
        sequence: u64,
    },
    /// Storage ticket already exists in a previously committed DA record.
    #[error(
        "DA storage ticket for lane {lane}, epoch {epoch}, sequence {sequence} was already committed at lane {existing_lane}, epoch {existing_epoch}, sequence {existing_sequence}"
    )]
    CommittedStorageTicket {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence number that failed validation.
        sequence: u64,
        /// Lane identifier of the already committed record.
        existing_lane: LaneId,
        /// Epoch of the already committed record.
        existing_epoch: u64,
        /// Sequence number of the already committed record.
        existing_sequence: u64,
    },
    /// Manifest hash must be non-zero.
    #[error("lane {lane} carries a zeroed manifest hash at epoch {epoch}, sequence {sequence}")]
    ZeroManifestHash {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence that failed validation.
        sequence: u64,
    },
    /// Storage ticket must be non-zero.
    #[error("lane {lane} carries a zeroed storage ticket at epoch {epoch}, sequence {sequence}")]
    ZeroStorageTicket {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence that failed validation.
        sequence: u64,
    },
}
/// Errors returned when a DA pin intent violates invariants.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DaPinIntentValidationError {
    /// Pin intent bundle version is unsupported.
    #[error("unsupported DA pin-intent bundle version {version}")]
    UnsupportedVersion {
        /// Version carried by the bundle.
        version: u16,
    },
    /// Pin-intent bundle length cannot be represented in DA location/proof metadata.
    #[error("DA pin-intent bundle length {len} exceeds representable maximum {max}")]
    BundleTooLarge {
        /// Number of pin intents in the bundle.
        len: usize,
        /// Maximum supported pin-intent count for one bundle.
        max: usize,
    },
    /// Pin intent bundle entries are not in canonical sort order.
    #[error("DA pin-intent bundle is not in canonical order at index {index}")]
    NonCanonicalOrder {
        /// First entry index that differs from canonical ordering.
        index: usize,
    },
    /// Lane referenced by the pin intent is not present in the configured catalog.
    #[error("lane {lane} not present in the configured lane catalog")]
    UnknownLane {
        /// Lane identifier that failed the lookup.
        lane: LaneId,
    },
    /// Owner account referenced by the pin intent is missing from WSV.
    #[error(
        "owner {owner} not present for lane {lane} epoch {epoch} sequence {sequence} pin intent"
    )]
    UnknownOwner {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence number that failed validation.
        sequence: u64,
        /// Owner account missing from the registry.
        owner: AccountId,
    },
    /// Signed authorization does not describe the enclosing pin intent.
    #[error(
        "DA ingest authorization does not match lane {lane} epoch {epoch} sequence {sequence} pin intent"
    )]
    AuthorizationMismatch {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence number that failed validation.
        sequence: u64,
    },
    /// Producer pin-scope authorization does not describe every enclosing index field.
    #[error(
        "DA pin-scope authorization does not match lane {lane} epoch {epoch} sequence {sequence} pin intent"
    )]
    PinScopeMismatch {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence number that failed validation.
        sequence: u64,
    },
    /// Signed authorization targets another genesis lineage.
    #[error(
        "DA ingest authorization for lane {lane} epoch {epoch} sequence {sequence} targets network {actual}, expected {expected}"
    )]
    WrongNetwork {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence number that failed validation.
        sequence: u64,
        /// Expected exact network identity.
        expected: NetworkId,
        /// Signed network identity.
        actual: NetworkId,
    },
    /// Signed authorization carries no canonical payload charge.
    #[error(
        "DA ingest authorization for lane {lane} epoch {epoch} sequence {sequence} declares zero payload bytes"
    )]
    ZeroPayloadBytes {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence number that failed validation.
        sequence: u64,
    },
    /// Signed authorization witnesses are empty, non-canonical, duplicated, or invalid.
    #[error(
        "DA ingest authorization for lane {lane} epoch {epoch} sequence {sequence} has invalid signer witnesses"
    )]
    InvalidAuthorizationSignatures {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence number that failed validation.
        sequence: u64,
    },
    /// Pin-scope witnesses are empty, non-canonical, duplicated, or invalid.
    #[error(
        "DA pin-scope authorization for lane {lane} epoch {epoch} sequence {sequence} has invalid signer witnesses"
    )]
    InvalidPinScopeSignatures {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence number that failed validation.
        sequence: u64,
    },
    /// Signed witnesses do not satisfy the committed account controller.
    #[error(
        "DA ingest authorization for owner {owner} does not satisfy its committed account controller"
    )]
    UnauthorizedOwner {
        /// Owner whose controller was not satisfied.
        owner: AccountId,
    },
    /// Pin-scope witnesses do not satisfy the committed account controller.
    #[error(
        "DA pin-scope authorization for owner {owner} does not satisfy its committed account controller"
    )]
    UnauthorizedPinScopeOwner {
        /// Owner whose controller was not satisfied.
        owner: AccountId,
    },
    /// Consensus-visible DA producer admission policy is absent.
    #[error("DA ingest admission policy is missing")]
    MissingAdmissionPolicy,
    /// Consensus-visible DA producer admission policy is malformed.
    #[error("DA ingest admission policy is invalid: {reason}")]
    InvalidAdmissionPolicy {
        /// Bounded validation detail.
        reason: String,
    },
    /// The target lane has no active non-zero incarnation at this block height.
    #[error(
        "DA ingest lane {lane} has no active incarnation at epoch {epoch}, sequence {sequence}"
    )]
    InactiveAdmissionLane {
        /// Target lane.
        lane: LaneId,
        /// Requested producer epoch.
        epoch: u64,
        /// Requested sequence.
        sequence: u64,
    },
    /// The committed policy does not authorize the owner/lane/incarnation/epoch tuple.
    #[error(
        "DA ingest admission policy does not authorize owner {owner} for lane {lane}, epoch {epoch}, sequence {sequence}"
    )]
    AdmissionDenied {
        /// Request owner.
        owner: AccountId,
        /// Target lane.
        lane: LaneId,
        /// Requested producer epoch.
        epoch: u64,
        /// Requested sequence.
        sequence: u64,
    },
    /// Deterministic per-account DA ingest count/byte ceiling was exceeded.
    #[error(
        "DA ingest quota for owner {owner} exceeded in window {window}: count {count}/{max_count}, bytes {bytes}/{max_bytes}"
    )]
    QuotaExceeded {
        /// Account whose quota would be exceeded.
        owner: AccountId,
        /// Deterministic block-window index.
        window: u64,
        /// Prospective ingest count.
        count: u64,
        /// Configured count ceiling.
        max_count: u64,
        /// Prospective canonical byte charge.
        bytes: u64,
        /// Configured byte ceiling.
        max_bytes: u64,
    },
    /// Checked quota arithmetic overflowed.
    #[error("DA ingest quota arithmetic overflow for owner {owner}")]
    QuotaOverflow {
        /// Account whose usage could not be represented.
        owner: AccountId,
    },
    /// Persisted deterministic quota state was malformed or non-canonical.
    #[error("DA ingest quota state for owner {owner} is corrupt: {reason}")]
    QuotaStateCorrupt {
        /// Account whose stored usage was corrupt.
        owner: AccountId,
        /// Bounded failure detail.
        reason: String,
    },
    /// Pin-intent alias exceeds the consensus admission bound.
    #[error(
        "pin-intent alias for lane {lane}, epoch {epoch}, sequence {sequence} is {len} bytes; maximum is {max}"
    )]
    AliasTooLong {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence number that failed validation.
        sequence: u64,
        /// Observed UTF-8 byte length.
        len: usize,
        /// Maximum accepted UTF-8 byte length.
        max: usize,
    },
    /// Duplicate `(lane, epoch, sequence)` pin intent found.
    #[error("duplicate DA pin intent detected for lane {lane}, epoch {epoch}, sequence {sequence}")]
    DuplicateIntent {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence number that failed validation.
        sequence: u64,
    },
    /// Duplicate storage ticket found.
    #[error(
        "duplicate DA pin-intent storage ticket detected for lane {lane}, epoch {epoch}, sequence {sequence}"
    )]
    DuplicateStorageTicket {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence number that failed validation.
        sequence: u64,
    },
    /// Duplicate manifest hash found.
    #[error(
        "duplicate DA pin-intent manifest hash detected for lane {lane}, epoch {epoch}, sequence {sequence}"
    )]
    DuplicateManifest {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence number that failed validation.
        sequence: u64,
    },
    /// Manifest hash must be non-zero.
    #[error(
        "lane {lane} carries a zeroed pin-intent manifest hash at epoch {epoch}, sequence {sequence}"
    )]
    ZeroManifestHash {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence that failed validation.
        sequence: u64,
    },
    /// Storage ticket must be non-zero.
    #[error("lane {lane} carries a zeroed storage ticket at epoch {epoch}, sequence {sequence}")]
    ZeroStorageTicket {
        /// Lane identifier that failed validation.
        lane: LaneId,
        /// Epoch that failed validation.
        epoch: u64,
        /// Sequence that failed validation.
        sequence: u64,
    },
    /// Alias collision resolved to a different storage ticket.
    #[error("alias {alias} superseded: dropped {dropped_ticket:?} in favour of {kept_ticket:?}")]
    AliasSuperseded {
        /// Alias that collided.
        alias: String,
        /// Ticket rejected for this alias.
        dropped_ticket: iroha_data_model::da::types::StorageTicketId,
        /// Ticket kept for this alias.
        kept_ticket: iroha_data_model::da::types::StorageTicketId,
    },
}
#[cfg(test)]
/// Enforce that a commitment's proof scheme matches the configured lane policy.
///
/// V1 defines only the Merkle proof scheme.
///
/// # Errors
///
/// Returns a [`DaProofPolicyError`] when the lane is unknown, the proof scheme
/// does not match the lane policy, or the chunk root is zero.
pub fn enforce_lane_proof_policy(
    record: &DaCommitmentRecord,
    lane_config: &LaneConfig,
) -> Result<(), DaProofPolicyError> {
    let Some(entry) = lane_config.entry(record.lane_id) else {
        return Err(DaProofPolicyError::UnknownLane {
            lane: record.lane_id,
        });
    };
    enforce_record_proof_scheme(record, entry.proof_scheme)
}
fn enforce_record_proof_scheme(
    record: &DaCommitmentRecord,
    expected_scheme: DaProofScheme,
) -> Result<(), DaProofPolicyError> {
    if expected_scheme != record.proof_scheme {
        return Err(DaProofPolicyError::SchemeMismatch {
            lane: record.lane_id,
            expected: expected_scheme,
            observed: record.proof_scheme,
        });
    }
    let chunk_root = record.chunk_root.as_ref();
    let chunk_root_zero_like = chunk_root[..Hash::LENGTH - 1].iter().all(|byte| *byte == 0)
        && chunk_root[Hash::LENGTH - 1] <= 1;
    if chunk_root_zero_like {
        return Err(DaProofPolicyError::ZeroChunkRoot {
            lane: record.lane_id,
        });
    }
    Ok(())
}
/// Enforce a commitment against the proof policy authenticated in its block.
///
/// # Errors
///
/// Returns [`DaProofPolicyError`] when the bundle is malformed, contains no
/// unique policy for the record's lane, or the commitment violates that policy.
pub fn enforce_committed_proof_policy(
    record: &DaCommitmentRecord,
    bundle: &DaProofPolicyBundle,
) -> Result<(), DaProofPolicyError> {
    validate_committed_proof_policy_bundle(bundle)?;
    let policy = bundle
        .policies()
        .iter()
        .find(|policy| policy.lane_id == record.lane_id)
        .ok_or(DaProofPolicyError::UnknownLane {
            lane: record.lane_id,
        })?;
    enforce_record_proof_scheme(record, policy.proof_scheme)
}
/// Validate the structure of a proof-policy sidecar authenticated by a block.
///
/// # Errors
///
/// Returns [`DaProofPolicyError`] when the bundle version or internal hash is
/// invalid, or when more than one policy names the same lane.
pub fn validate_committed_proof_policy_bundle(
    bundle: &DaProofPolicyBundle,
) -> Result<(), DaProofPolicyError> {
    if bundle.version() != DaProofPolicyBundle::VERSION_V1 {
        return Err(DaProofPolicyError::UnsupportedPolicyBundleVersion {
            version: bundle.version(),
        });
    }
    if DaProofPolicyBundle::new(bundle.policies().to_vec()).policy_hash() != bundle.policy_hash() {
        return Err(DaProofPolicyError::PolicyBundleHashMismatch);
    }
    let mut lanes = BTreeSet::new();
    for policy in bundle.policies() {
        if !lanes.insert(policy.lane_id) {
            return Err(DaProofPolicyError::DuplicateLanePolicy {
                lane: policy.lane_id,
            });
        }
    }
    Ok(())
}
#[cfg(test)]
fn active_lane_config_entry(
    nexus: &Nexus,
    lane_id: LaneId,
) -> Result<&LaneConfigEntry, DaProofPolicyError> {
    active_lane_config_entry_at_height(nexus, lane_id, None)
}
fn active_lane_config_entry_at_height(
    nexus: &Nexus,
    lane_id: LaneId,
    block_height: Option<u64>,
) -> Result<&LaneConfigEntry, DaProofPolicyError> {
    let Some(current) = nexus.lane_config.entry(lane_id) else {
        return Err(DaProofPolicyError::UnknownLane { lane: lane_id });
    };
    let lanes = nexus.lane_catalog.lanes();
    let Ok(catalog_index) = lanes.binary_search_by_key(&lane_id, |lane| lane.id) else {
        return Err(DaProofPolicyError::UnknownLane { lane: lane_id });
    };
    let catalog_lane = &lanes[catalog_index];
    if !catalog_lane_is_da_active(catalog_lane, nexus, block_height) {
        return Err(DaProofPolicyError::UnknownLane { lane: lane_id });
    }
    if nexus
        .dataspace_catalog
        .by_id(catalog_lane.dataspace_id)
        .is_none()
    {
        return Err(DaProofPolicyError::UnknownLane { lane: lane_id });
    }
    if !current.matches_metadata(catalog_lane) {
        return Err(DaProofPolicyError::UnknownLane { lane: lane_id });
    }
    Ok(current)
}
/// Reusable active-lane policy view over one immutable Nexus snapshot.
///
/// Construction borrows the original snapshot. Each lookup checks all runtime
/// fields against their catalog metadata without cloning policy graphs or strings.
#[derive(Debug)]
pub struct ActiveLaneProofPolicyContext<'a> {
    nexus: &'a Nexus,
}
impl<'a> ActiveLaneProofPolicyContext<'a> {
    /// Borrow a reusable policy view for `nexus` without allocating.
    #[must_use]
    pub fn new(nexus: &'a Nexus) -> Self {
        Self { nexus }
    }
    /// Return the active DA proof policy for a lane at a block height.
    ///
    /// # Errors
    ///
    /// Returns [`DaProofPolicyError::UnknownLane`] when the lane is inactive
    /// or the runtime-derived geometry differs from the catalog snapshot.
    pub fn policy_at_height(
        &self,
        lane_id: LaneId,
        block_height: u64,
    ) -> Result<DaProofPolicy, DaProofPolicyError> {
        let entry = self.entry(lane_id, Some(block_height))?;
        Ok(DaProofPolicy {
            lane_id: entry.lane_id,
            dataspace_id: entry.dataspace_id,
            alias: entry.alias.clone(),
            proof_scheme: entry.proof_scheme,
        })
    }
    #[cfg(test)]
    /// Require a lane to be active in this snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`DaProofPolicyError::UnknownLane`] when the lane is absent,
    /// inactive, or its runtime geometry drifts from the catalog.
    pub fn require_active_lane(&self, lane_id: LaneId) -> Result<(), DaProofPolicyError> {
        self.entry(lane_id, None).map(|_| ())
    }
    /// Require a lane to be active at a historical block height.
    ///
    /// # Errors
    ///
    /// Returns [`DaProofPolicyError::UnknownLane`] when the lane is absent,
    /// inactive at `block_height`, or its runtime geometry drifts.
    pub fn require_active_lane_at_height(
        &self,
        lane_id: LaneId,
        block_height: u64,
    ) -> Result<(), DaProofPolicyError> {
        self.entry(lane_id, Some(block_height)).map(|_| ())
    }
    /// Enforce a commitment against the active lane policy at a block height.
    ///
    /// # Errors
    ///
    /// Returns [`DaProofPolicyError`] when the lane is inactive or the
    /// commitment violates its proof scheme.
    pub fn enforce_commitment_at_height(
        &self,
        record: &DaCommitmentRecord,
        block_height: u64,
    ) -> Result<(), DaProofPolicyError> {
        let entry = self.entry(record.lane_id, Some(block_height))?;
        enforce_record_proof_scheme(record, entry.proof_scheme)
    }
    #[cfg(test)]
    /// Enforce a commitment against the active lane policy.
    ///
    /// # Errors
    ///
    /// Returns [`DaProofPolicyError`] when the lane is inactive or the
    /// commitment violates its proof scheme.
    pub fn enforce_commitment(
        &self,
        record: &DaCommitmentRecord,
    ) -> Result<(), DaProofPolicyError> {
        let entry = self.entry(record.lane_id, None)?;
        enforce_record_proof_scheme(record, entry.proof_scheme)
    }
    fn entry(
        &self,
        lane_id: LaneId,
        block_height: Option<u64>,
    ) -> Result<&LaneConfigEntry, DaProofPolicyError> {
        active_lane_config_entry_at_height(self.nexus, lane_id, block_height)
    }
}
fn catalog_lane_is_da_active(
    lane: &iroha_data_model::nexus::LaneConfig,
    nexus: &Nexus,
    block_height: Option<u64>,
) -> bool {
    let inside_elastic_range = lane_id_inside_enabled_autoscale_range(lane.id, nexus);
    if lane_uses_reserved_autoscale_metadata(lane) {
        return inside_elastic_range
            && lane.is_autoscale_managed_elastic()
            && lane.dataspace_id == nexus.routing_policy.default_dataspace
            && block_height.is_none_or(|height| {
                lane.autoscale_created_height()
                    .is_some_and(|created| created <= height)
            })
            && crate::state::autoscale_lane_accepts_proposal_height(
                lane,
                block_height.unwrap_or(u64::MAX),
            );
    }
    !inside_elastic_range
}
fn lane_id_inside_enabled_autoscale_range(lane_id: LaneId, nexus: &Nexus) -> bool {
    if !nexus.autoscale.enabled {
        return false;
    }
    let min = nexus.autoscale.min_lane_id.get();
    let max = nexus.autoscale.max_lane_id_exclusive.get();
    let lane_id = lane_id.as_u32();
    min < max && lane_id >= min && lane_id < max
}
#[cfg(test)]
/// Return the active DA proof policy for a catalog-backed lane.
///
/// # Errors
///
/// Returns [`DaProofPolicyError::UnknownLane`] when the lane is absent from the authoritative
/// catalog, when derived runtime geometry is missing or drifted from the catalog, or when the lane
/// dataspace is absent from the active dataspace catalog.
pub fn active_lane_proof_policy(
    nexus: &Nexus,
    lane_id: LaneId,
) -> Result<DaProofPolicy, DaProofPolicyError> {
    let entry = active_lane_config_entry(nexus, lane_id)?;
    Ok(DaProofPolicy {
        lane_id: entry.lane_id,
        dataspace_id: entry.dataspace_id,
        alias: entry.alias.clone(),
        proof_scheme: entry.proof_scheme,
    })
}
/// Return the active DA proof policy for a catalog-backed lane at a block height.
///
/// # Errors
///
/// Returns [`DaProofPolicyError::UnknownLane`] when the lane is not active for
/// DA at `block_height`, including autoscale elastic lanes whose declared
/// creation height is still in the future.
pub fn active_lane_proof_policy_at_height(
    nexus: &Nexus,
    lane_id: LaneId,
    block_height: u64,
) -> Result<DaProofPolicy, DaProofPolicyError> {
    let entry = active_lane_config_entry_at_height(nexus, lane_id, Some(block_height))?;
    Ok(DaProofPolicy {
        lane_id: entry.lane_id,
        dataspace_id: entry.dataspace_id,
        alias: entry.alias.clone(),
        proof_scheme: entry.proof_scheme,
    })
}
#[cfg(test)]
/// Filter DA pin intents using the configured lane catalog.
///
/// Returns `(kept, rejected)` where `kept` contains intents that passed validation
/// and `rejected` lists every validation failure. Callers decide whether
/// rejected local spool entries are fatal or can be dropped for their workflow.
pub fn sanitize_pin_intents(
    intents: impl IntoIterator<Item = iroha_data_model::da::pin_intent::DaPinIntent>,
    lane_config: &LaneConfig,
    account_exists: impl Fn(&AccountId) -> bool,
) -> (
    Vec<iroha_data_model::da::pin_intent::DaPinIntent>,
    Vec<DaPinIntentValidationError>,
) {
    sanitize_pin_intents_with_lane_check(
        intents,
        |lane_id| lane_config.entry(lane_id).is_some(),
        account_exists,
    )
}
#[cfg(test)]
/// Filter DA pin intents using the active Nexus lane catalog.
///
/// Returns `(kept, rejected)` where `kept` contains intents that passed
/// validation and `rejected` lists every validation failure.
pub fn sanitize_pin_intents_against_nexus(
    intents: impl IntoIterator<Item = iroha_data_model::da::pin_intent::DaPinIntent>,
    nexus: &Nexus,
    account_exists: impl Fn(&AccountId) -> bool,
) -> (
    Vec<iroha_data_model::da::pin_intent::DaPinIntent>,
    Vec<DaPinIntentValidationError>,
) {
    let context = ActiveLaneProofPolicyContext::new(nexus);
    sanitize_pin_intents_with_lane_check(
        intents,
        |lane_id| context.require_active_lane(lane_id).is_ok(),
        account_exists,
    )
}
/// Filter DA pin intents using the active Nexus lane catalog at a block height.
///
/// Returns `(kept, rejected)` where `kept` contains intents that passed
/// validation and `rejected` lists every validation failure. Autoscale elastic
/// lanes are only active after their declared creation height.
pub fn sanitize_pin_intents_against_nexus_at_height(
    intents: impl IntoIterator<Item = iroha_data_model::da::pin_intent::DaPinIntent>,
    nexus: &Nexus,
    block_height: u64,
    account_exists: impl Fn(&AccountId) -> bool,
) -> (
    Vec<iroha_data_model::da::pin_intent::DaPinIntent>,
    Vec<DaPinIntentValidationError>,
) {
    let context = ActiveLaneProofPolicyContext::new(nexus);
    sanitize_pin_intents_with_lane_check(
        intents,
        |lane_id| {
            context
                .require_active_lane_at_height(lane_id, block_height)
                .is_ok()
        },
        account_exists,
    )
}
fn sanitize_pin_intents_with_lane_check(
    intents: impl IntoIterator<Item = iroha_data_model::da::pin_intent::DaPinIntent>,
    mut lane_is_active: impl FnMut(LaneId) -> bool,
    account_exists: impl Fn(&AccountId) -> bool,
) -> (
    Vec<iroha_data_model::da::pin_intent::DaPinIntent>,
    Vec<DaPinIntentValidationError>,
) {
    let mut seen = BTreeSet::new();
    let mut seen_tickets = BTreeSet::new();
    let mut seen_manifests = BTreeSet::new();
    let mut kept = Vec::new();
    let mut rejected = Vec::new();
    let bounded_intents = intents
        .into_iter()
        .filter_map(|intent| {
            let alias_len = intent.alias.as_ref().map_or(0, |alias| alias.len());
            if alias_len <= MAX_DA_PIN_INTENT_ALIAS_BYTES {
                Some(intent)
            } else {
                rejected.push(DaPinIntentValidationError::AliasTooLong {
                    lane: intent.lane_id,
                    epoch: intent.epoch,
                    sequence: intent.sequence,
                    len: alias_len,
                    max: MAX_DA_PIN_INTENT_ALIAS_BYTES,
                });
                None
            }
        })
        .collect();
    let (canonical, drop_reasons) = canonicalize_bundle(
        iroha_data_model::da::pin_intent::DaPinIntentBundle::new(bounded_intents),
    );
    for reason in drop_reasons {
        match reason {
            PinIntentDropReason::ZeroManifest {
                lane,
                epoch,
                sequence,
            } => rejected.push(DaPinIntentValidationError::ZeroManifestHash {
                lane: LaneId::new(lane),
                epoch,
                sequence,
            }),
            PinIntentDropReason::DuplicateIntent {
                lane,
                epoch,
                sequence,
                ..
            } => rejected.push(DaPinIntentValidationError::DuplicateIntent {
                lane: LaneId::new(lane),
                epoch,
                sequence,
            }),
            PinIntentDropReason::AliasSuperseded {
                alias,
                dropped_ticket,
                kept_ticket,
            } => rejected.push(DaPinIntentValidationError::AliasSuperseded {
                alias,
                dropped_ticket,
                kept_ticket,
            }),
        }
    }
    for intent in canonical.intents {
        let key = (intent.lane_id, intent.epoch, intent.sequence);
        if !lane_is_active(intent.lane_id) {
            rejected.push(DaPinIntentValidationError::UnknownLane {
                lane: intent.lane_id,
            });
            continue;
        }
        if intent
            .manifest_hash
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            rejected.push(DaPinIntentValidationError::ZeroManifestHash {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
            });
            continue;
        }
        if intent.storage_ticket.as_ref().iter().all(|byte| *byte == 0) {
            rejected.push(DaPinIntentValidationError::ZeroStorageTicket {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
            });
            continue;
        }
        let authorization = &intent.authorization;
        if authorization.lane_id != intent.lane_id
            || authorization.epoch != intent.epoch
            || authorization.sequence != intent.sequence
        {
            rejected.push(DaPinIntentValidationError::AuthorizationMismatch {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
            });
            continue;
        }
        if !pin_scope_matches_intent(&intent) {
            rejected.push(DaPinIntentValidationError::PinScopeMismatch {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
            });
            continue;
        }
        if authorization.payload_bytes == 0 {
            rejected.push(DaPinIntentValidationError::ZeroPayloadBytes {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
            });
            continue;
        }
        if !authorization.has_valid_canonical_signatures() {
            rejected.push(DaPinIntentValidationError::InvalidAuthorizationSignatures {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
            });
            continue;
        }
        if !intent
            .pin_scope_authorization
            .has_valid_canonical_signatures()
        {
            rejected.push(DaPinIntentValidationError::InvalidPinScopeSignatures {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
            });
            continue;
        }
        if !account_exists(&authorization.owner) {
            rejected.push(DaPinIntentValidationError::UnknownOwner {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
                owner: authorization.owner.clone(),
            });
            continue;
        }
        if !seen.insert(key) {
            rejected.push(DaPinIntentValidationError::DuplicateIntent {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
            });
            continue;
        }
        if !seen_tickets.insert(intent.storage_ticket) {
            rejected.push(DaPinIntentValidationError::DuplicateStorageTicket {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
            });
            continue;
        }
        if !seen_manifests.insert(intent.manifest_hash) {
            rejected.push(DaPinIntentValidationError::DuplicateManifest {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
            });
            continue;
        }
        kept.push(intent);
    }
    (kept, rejected)
}
fn pin_scope_matches_intent(intent: &iroha_data_model::da::pin_intent::DaPinIntent) -> bool {
    let scope = &intent.pin_scope_authorization.scope;
    scope.matches_authorization(&intent.authorization)
        && scope.lane_id == intent.lane_id
        && scope.epoch == intent.epoch
        && scope.sequence == intent.sequence
        && scope.storage_ticket == intent.storage_ticket
        && scope.manifest_hash == intent.manifest_hash
        && scope.alias == intent.alias
}

fn witnesses_satisfy_controller<T>(
    witnesses: &[T],
    signer: impl Fn(&T) -> &iroha_crypto::PublicKey,
    controller: &AccountController,
) -> bool {
    match controller {
        AccountController::Single(signatory) => {
            matches!(witnesses, [witness] if signer(witness) == signatory)
        }
        AccountController::Multisig(policy) => {
            let Some(weight) = witnesses.iter().try_fold(0_u32, |accumulated, witness| {
                let member = policy
                    .members()
                    .iter()
                    .find(|member| member.public_key() == signer(witness))?;
                accumulated.checked_add(u32::from(member.weight()))
            }) else {
                return false;
            };
            weight >= u32::from(policy.threshold())
        }
    }
}
fn authorization_satisfies_controller(
    authorization: &iroha_data_model::da::ingest::DaIngestAuthorizationV1,
    controller: &AccountController,
) -> bool {
    if !authorization.has_valid_canonical_signatures() {
        return false;
    }
    witnesses_satisfy_controller(
        &authorization.signatures,
        |witness| &witness.signer,
        controller,
    )
}
fn pin_scope_authorization_satisfies_controller(
    authorization: &iroha_data_model::da::ingest::DaPinScopeAuthorizationV1,
    controller: &AccountController,
) -> bool {
    if !authorization.has_valid_canonical_signatures() {
        return false;
    }
    witnesses_satisfy_controller(
        &authorization.signatures,
        |witness| &witness.signer,
        controller,
    )
}
/// Verify every pin-intent authorization against the exact network and committed account state.
///
/// # Errors
///
/// Returns the first missing, cross-network, cryptographically invalid, or
/// controller-insufficient authorization. Call this before quota preparation.
pub fn validate_pin_intent_authorizations(
    bundle: &iroha_data_model::da::pin_intent::DaPinIntentBundle,
    expected_network_id: NetworkId,
    account_controller: impl Fn(&AccountId) -> Option<AccountController>,
) -> Result<(), DaPinIntentValidationError> {
    for intent in &bundle.intents {
        let authorization = &intent.authorization;
        if authorization.lane_id != intent.lane_id
            || authorization.epoch != intent.epoch
            || authorization.sequence != intent.sequence
        {
            return Err(DaPinIntentValidationError::AuthorizationMismatch {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
            });
        }
        if !pin_scope_matches_intent(intent) {
            return Err(DaPinIntentValidationError::PinScopeMismatch {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
            });
        }
        if authorization.network_id != expected_network_id {
            return Err(DaPinIntentValidationError::WrongNetwork {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
                expected: expected_network_id,
                actual: authorization.network_id,
            });
        }
        if authorization.payload_bytes == 0 {
            return Err(DaPinIntentValidationError::ZeroPayloadBytes {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
            });
        }
        if !authorization.has_valid_canonical_signatures() {
            return Err(DaPinIntentValidationError::InvalidAuthorizationSignatures {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
            });
        }
        let Some(controller) = account_controller(&authorization.owner) else {
            return Err(DaPinIntentValidationError::UnknownOwner {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
                owner: authorization.owner.clone(),
            });
        };
        if !authorization_satisfies_controller(authorization, &controller) {
            return Err(DaPinIntentValidationError::UnauthorizedOwner {
                owner: authorization.owner.clone(),
            });
        }
        if !intent
            .pin_scope_authorization
            .has_valid_canonical_signatures()
        {
            return Err(DaPinIntentValidationError::InvalidPinScopeSignatures {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
            });
        }
        if !pin_scope_authorization_satisfies_controller(
            &intent.pin_scope_authorization,
            &controller,
        ) {
            return Err(DaPinIntentValidationError::UnauthorizedPinScopeOwner {
                owner: authorization.owner.clone(),
            });
        }
    }
    Ok(())
}
/// Validate every pin intent against the exact committed producer/epoch policy.
///
/// Empty bundles need no admission policy. Non-empty bundles fail closed when
/// the policy is absent, malformed, stale for the active lane incarnation, or
/// does not grant the exact signed owner and epoch.
///
/// # Errors
///
/// Returns the first policy, incarnation, or authorization mismatch.
pub fn validate_pin_intent_admission_policy(
    bundle: &iroha_data_model::da::pin_intent::DaPinIntentBundle,
    policy: Option<&iroha_data_model::da::ingest::DaIngestAdmissionPolicyV1>,
    lane_incarnation: impl Fn(LaneId) -> Option<Hash>,
) -> Result<(), DaPinIntentValidationError> {
    if bundle.intents.is_empty() {
        return Ok(());
    }
    let Some(policy) = policy else {
        return Err(DaPinIntentValidationError::MissingAdmissionPolicy);
    };
    policy
        .validate()
        .map_err(|error| DaPinIntentValidationError::InvalidAdmissionPolicy {
            reason: error.to_string(),
        })?;
    for intent in &bundle.intents {
        let Some(incarnation) = lane_incarnation(intent.lane_id) else {
            return Err(DaPinIntentValidationError::InactiveAdmissionLane {
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
            });
        };
        if !policy.authorizes(
            &intent.authorization.owner,
            intent.lane_id,
            incarnation,
            intent.epoch,
        ) {
            return Err(DaPinIntentValidationError::AdmissionDenied {
                owner: intent.authorization.owner.clone(),
                lane: intent.lane_id,
                epoch: intent.epoch,
                sequence: intent.sequence,
            });
        }
    }
    Ok(())
}
#[cfg(test)]
/// Build a canonically signed DA ingest authorization for unit-test pin intents.
pub(crate) fn signed_test_ingest_authorization(
    network_id: NetworkId,
    key_pair: &iroha_crypto::KeyPair,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    payload_bytes: u64,
) -> iroha_data_model::da::ingest::DaIngestAuthorizationV1 {
    use iroha_data_model::da::{
        ingest::{DaIngestAuthorizationV1, DaIngestSignatureV1},
        types::BlobDigest,
    };
    let mut authorization = DaIngestAuthorizationV1 {
        network_id,
        owner: AccountId::new(key_pair.public_key().clone()),
        lane_id,
        epoch,
        sequence,
        payload_hash: BlobDigest::new([0xA5; 32]),
        payload_bytes,
        request_content_hash: Hash::prehashed([0x5A; 32]),
        signatures: Vec::new(),
    };
    let signature =
        iroha_crypto::Signature::try_new(key_pair.private_key(), &authorization.signing_digest())
            .expect("test DA ingest authorization must sign");
    authorization.signatures.push(DaIngestSignatureV1 {
        signer: key_pair.public_key().clone(),
        signature,
    });
    authorization
}
#[cfg(test)]
/// Build a canonically signed exact pin-scope authorization for unit-test pin intents.
pub(crate) fn signed_test_pin_scope_authorization(
    authorization: &iroha_data_model::da::ingest::DaIngestAuthorizationV1,
    key_pair: &iroha_crypto::KeyPair,
    storage_ticket: iroha_data_model::da::types::StorageTicketId,
    manifest_hash: iroha_data_model::sorafs::pin_registry::ManifestDigest,
    alias: Option<String>,
) -> iroha_data_model::da::ingest::DaPinScopeAuthorizationV1 {
    let scope = iroha_data_model::da::ingest::DaPinScopeV1::new(
        authorization,
        storage_ticket,
        manifest_hash,
        alias,
    );
    iroha_data_model::da::ingest::DaPinScopeAuthorizationV1::try_sign(scope, key_pair)
        .expect("test DA pin-scope authorization must sign")
}
#[cfg(test)]
/// Build a fully signed DA pin intent for unit tests.
pub(crate) fn signed_test_pin_intent(
    authorization: iroha_data_model::da::ingest::DaIngestAuthorizationV1,
    key_pair: &iroha_crypto::KeyPair,
    storage_ticket: iroha_data_model::da::types::StorageTicketId,
    manifest_hash: iroha_data_model::sorafs::pin_registry::ManifestDigest,
    alias: Option<String>,
) -> iroha_data_model::da::pin_intent::DaPinIntent {
    let scope_authorization = signed_test_pin_scope_authorization(
        &authorization,
        key_pair,
        storage_ticket,
        manifest_hash,
        alias,
    );
    iroha_data_model::da::pin_intent::DaPinIntent::new(authorization, scope_authorization)
}
#[cfg(test)]
/// Validate a DA pin-intent bundle before accepting an inbound block.
///
/// Unlike local spool ingestion, inbound block validation is fail-closed:
/// invalid pin intents reject the block instead of being dropped during apply.
///
/// # Errors
///
/// Returns the first [`DaPinIntentValidationError`] observed in the bundle.
pub fn validate_pin_intent_bundle(
    bundle: &iroha_data_model::da::pin_intent::DaPinIntentBundle,
    lane_config: &LaneConfig,
    account_exists: impl Fn(&AccountId) -> bool,
) -> Result<(), DaPinIntentValidationError> {
    if bundle.version != iroha_data_model::da::pin_intent::DaPinIntentBundle::VERSION_V1 {
        return Err(DaPinIntentValidationError::UnsupportedVersion {
            version: bundle.version,
        });
    }
    validate_pin_intent_bundle_len(bundle.intents.len())?;
    let (_kept, rejected) =
        sanitize_pin_intents(bundle.intents.clone(), lane_config, account_exists);
    if let Some(error) = rejected.into_iter().next() {
        return Err(error);
    }
    let canonical =
        iroha_data_model::da::pin_intent::DaPinIntentBundle::new(bundle.intents.clone());
    if let Some(index) = first_pin_intent_order_mismatch(&bundle.intents, &canonical.intents) {
        return Err(DaPinIntentValidationError::NonCanonicalOrder { index });
    }
    Ok(())
}
#[cfg(test)]
/// Validate a DA pin-intent bundle against active Nexus lane catalogs.
///
/// # Errors
///
/// Returns the first [`DaPinIntentValidationError`] observed in the bundle.
pub fn validate_pin_intent_bundle_against_nexus(
    bundle: &iroha_data_model::da::pin_intent::DaPinIntentBundle,
    nexus: &Nexus,
    account_exists: impl Fn(&AccountId) -> bool,
) -> Result<(), DaPinIntentValidationError> {
    if bundle.version != iroha_data_model::da::pin_intent::DaPinIntentBundle::VERSION_V1 {
        return Err(DaPinIntentValidationError::UnsupportedVersion {
            version: bundle.version,
        });
    }
    validate_pin_intent_bundle_len(bundle.intents.len())?;
    let (_kept, rejected) =
        sanitize_pin_intents_against_nexus(bundle.intents.clone(), nexus, account_exists);
    if let Some(error) = rejected.into_iter().next() {
        return Err(error);
    }
    let canonical =
        iroha_data_model::da::pin_intent::DaPinIntentBundle::new(bundle.intents.clone());
    if let Some(index) = first_pin_intent_order_mismatch(&bundle.intents, &canonical.intents) {
        return Err(DaPinIntentValidationError::NonCanonicalOrder { index });
    }
    Ok(())
}
/// Validate a DA pin-intent bundle against active Nexus lane catalogs at a block height.
///
/// # Errors
///
/// Returns the first [`DaPinIntentValidationError`] observed in the bundle.
pub fn validate_pin_intent_bundle_against_nexus_at_height(
    bundle: &iroha_data_model::da::pin_intent::DaPinIntentBundle,
    nexus: &Nexus,
    block_height: u64,
    account_exists: impl Fn(&AccountId) -> bool,
) -> Result<(), DaPinIntentValidationError> {
    if bundle.version != iroha_data_model::da::pin_intent::DaPinIntentBundle::VERSION_V1 {
        return Err(DaPinIntentValidationError::UnsupportedVersion {
            version: bundle.version,
        });
    }
    validate_pin_intent_bundle_len(bundle.intents.len())?;
    let (_kept, rejected) = sanitize_pin_intents_against_nexus_at_height(
        bundle.intents.clone(),
        nexus,
        block_height,
        account_exists,
    );
    if let Some(error) = rejected.into_iter().next() {
        return Err(error);
    }
    let canonical =
        iroha_data_model::da::pin_intent::DaPinIntentBundle::new(bundle.intents.clone());
    if let Some(index) = first_pin_intent_order_mismatch(&bundle.intents, &canonical.intents) {
        return Err(DaPinIntentValidationError::NonCanonicalOrder { index });
    }
    Ok(())
}
fn first_pin_intent_order_mismatch(
    actual: &[iroha_data_model::da::pin_intent::DaPinIntent],
    canonical: &[iroha_data_model::da::pin_intent::DaPinIntent],
) -> Option<usize> {
    actual
        .iter()
        .zip(canonical.iter())
        .position(|(actual, canonical)| actual != canonical)
        .or_else(|| (actual.len() != canonical.len()).then_some(actual.len().min(canonical.len())))
}
#[cfg(test)]
/// Validate commitment bundle invariants before embedding into a block.
///
/// Enforces a representable bundle length, unique `(lane, epoch, sequence)`
/// tuples, unique manifest hashes and storage tickets within the bundle,
/// non-zero manifest hashes and storage tickets, and lane proof policy
/// compatibility.
///
/// # Errors
///
/// Returns a [`DaCommitmentValidationError`] when invariants are violated.
pub fn validate_commitment_bundle(
    bundle: &DaCommitmentBundle,
    lane_config: &LaneConfig,
) -> Result<(), DaCommitmentValidationError> {
    validate_commitment_bundle_with_policy(bundle, |record| {
        enforce_lane_proof_policy(record, lane_config)?;
        validate_confidential_compute_record(lane_config, record)?;
        Ok(())
    })
}
#[cfg(test)]
/// Validate commitment bundle invariants against active Nexus lane catalogs.
///
/// # Errors
///
/// Returns a [`DaCommitmentValidationError`] when invariants are violated.
pub fn validate_commitment_bundle_against_nexus(
    bundle: &DaCommitmentBundle,
    nexus: &Nexus,
) -> Result<(), DaCommitmentValidationError> {
    let context = ActiveLaneProofPolicyContext::new(nexus);
    validate_commitment_bundle_with_policy(bundle, |record| {
        context.enforce_commitment(record)?;
        validate_confidential_compute_record(&nexus.lane_config, record)?;
        Ok(())
    })
}
/// Validate commitment bundle invariants against active Nexus lanes at a block height.
///
/// # Errors
///
/// Returns a [`DaCommitmentValidationError`] when invariants are violated or a
/// commitment targets a lane that is inactive at `block_height`.
pub fn validate_commitment_bundle_against_nexus_at_height(
    bundle: &DaCommitmentBundle,
    nexus: &Nexus,
    block_height: u64,
) -> Result<(), DaCommitmentValidationError> {
    let context = ActiveLaneProofPolicyContext::new(nexus);
    validate_commitment_bundle_with_policy(bundle, |record| {
        context.enforce_commitment_at_height(record, block_height)?;
        validate_confidential_compute_record(&nexus.lane_config, record)?;
        Ok(())
    })
}
fn validate_commitment_bundle_with_policy(
    bundle: &DaCommitmentBundle,
    mut validate_record_policy: impl FnMut(
        &DaCommitmentRecord,
    ) -> Result<(), DaCommitmentValidationError>,
) -> Result<(), DaCommitmentValidationError> {
    if bundle.version() != DaCommitmentBundle::VERSION_V1 {
        return Err(DaCommitmentValidationError::UnsupportedVersion {
            version: bundle.version(),
        });
    }
    validate_commitment_bundle_len(bundle.commitments().len())?;
    let mut seen_keys = BTreeSet::new();
    let mut seen_manifests = BTreeSet::new();
    let mut seen_tickets = BTreeSet::new();
    for record in bundle.commitments() {
        if record
            .manifest_hash
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(DaCommitmentValidationError::ZeroManifestHash {
                lane: record.lane_id,
                epoch: record.epoch,
                sequence: record.sequence,
            });
        }
        if record.storage_ticket.as_ref().iter().all(|byte| *byte == 0) {
            return Err(DaCommitmentValidationError::ZeroStorageTicket {
                lane: record.lane_id,
                epoch: record.epoch,
                sequence: record.sequence,
            });
        }
        let key = DaCommitmentKey::from_record(record);
        if !seen_keys.insert(key) {
            return Err(DaCommitmentValidationError::DuplicateCommitment {
                key_lane: record.lane_id,
                epoch: record.epoch,
                sequence: record.sequence,
            });
        }
        if !seen_manifests.insert(record.manifest_hash) {
            return Err(DaCommitmentValidationError::DuplicateManifest {
                lane: record.lane_id,
            });
        }
        if !seen_tickets.insert(record.storage_ticket) {
            return Err(DaCommitmentValidationError::DuplicateStorageTicket {
                lane: record.lane_id,
                epoch: record.epoch,
                sequence: record.sequence,
            });
        }
        validate_record_policy(record)?;
    }
    // Ordering scratch is a separate untrusted graph, not an extracted admitted owner.
    let mut canonical = bundle.commitments().to_vec();
    canonical.sort();
    if let Some(index) = first_commitment_order_mismatch(bundle.commitments(), &canonical) {
        return Err(DaCommitmentValidationError::NonCanonicalOrder { index });
    }
    Ok(())
}
fn first_commitment_order_mismatch(
    actual: &[DaCommitmentRecord],
    canonical: &[DaCommitmentRecord],
) -> Option<usize> {
    actual
        .iter()
        .zip(canonical.iter())
        .position(|(actual, canonical)| actual != canonical)
        .or_else(|| (actual.len() != canonical.len()).then_some(actual.len().min(canonical.len())))
}
pub(crate) const MAX_DA_BUNDLE_LOCATIONS: usize = u32::MAX as usize;
pub(crate) fn da_bundle_location_index(index: usize) -> Option<u32> {
    if index >= MAX_DA_BUNDLE_LOCATIONS {
        return None;
    }
    u32::try_from(index).ok()
}
fn validate_commitment_bundle_len(len: usize) -> Result<(), DaCommitmentValidationError> {
    if len > MAX_DA_BUNDLE_LOCATIONS {
        return Err(DaCommitmentValidationError::BundleTooLarge {
            len,
            max: MAX_DA_BUNDLE_LOCATIONS,
        });
    }
    Ok(())
}
fn validate_pin_intent_bundle_len(len: usize) -> Result<(), DaPinIntentValidationError> {
    if len > MAX_DA_BUNDLE_LOCATIONS {
        return Err(DaPinIntentValidationError::BundleTooLarge {
            len,
            max: MAX_DA_BUNDLE_LOCATIONS,
        });
    }
    Ok(())
}
#[cfg(test)]
mod proof_policy_tests {
    use super::*;
    use iroha_data_model::{
        account::{AccountController, AccountId, MultisigMember, MultisigPolicy},
        da::{
            ingest::{
                DaIngestAdmissionLaneV1, DaIngestAdmissionPolicyV1, DaIngestAuthorizationV1,
                DaIngestSignatureV1, DaPinScopeAuthorizationV1, DaPinScopeSignatureV1,
                DaPinScopeV1,
            },
            pin_intent::{DaPinIntent, DaPinIntentBundle},
            types::{BlobDigest, StorageTicketId},
        },
        sorafs::pin_registry::ManifestDigest,
    };
    use iroha_model_base::topology::LaneId;
    fn intent(
        lane: LaneId,
        epoch: u64,
        sequence: u64,
        manifest_bytes: [u8; 32],
        ticket_bytes: [u8; 32],
    ) -> DaPinIntent {
        let key_pair =
            iroha_crypto::KeyPair::try_from_seed(vec![0x5A; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("valid deterministic DA owner key");
        let network_id = iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
            iroha_data_model::block::BlockHeader,
        >::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([0xA5; 32]),
        ));
        let authorization =
            signed_test_ingest_authorization(network_id, &key_pair, lane, epoch, sequence, 1);
        signed_test_pin_intent(
            authorization,
            &key_pair,
            StorageTicketId::new(ticket_bytes),
            ManifestDigest::new(manifest_bytes),
            None,
        )
    }
    fn set_intent_alias(intent: &mut DaPinIntent, alias: Option<String>) {
        let key_pair =
            iroha_crypto::KeyPair::try_from_seed(vec![0x5A; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("valid deterministic DA owner key");
        intent.pin_scope_authorization = signed_test_pin_scope_authorization(
            &intent.authorization,
            &key_pair,
            intent.storage_ticket,
            intent.manifest_hash,
            alias.clone(),
        );
        intent.alias = alias;
    }
    #[test]
    fn sanitize_pin_intents_drops_invalid_entries() {
        let lane_config = LaneConfig::default();
        let lane = lane_config.primary().lane_id;
        let valid = intent(lane, 1, 1, [1; 32], [2; 32]);
        let zero_manifest = intent(lane, 1, 2, [0; 32], [3; 32]);
        let zero_ticket = intent(lane, 1, 3, [4; 32], [0; 32]);
        let duplicate = intent(lane, 1, 1, [5; 32], [2; 32]);
        let (kept, rejected) = sanitize_pin_intents(
            vec![valid.clone(), zero_manifest, zero_ticket, duplicate.clone()],
            &lane_config,
            |_| true,
        );
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0], duplicate);
        assert_eq!(rejected.len(), 3);
        assert!(
            rejected
                .iter()
                .any(|err| matches!(err, DaPinIntentValidationError::ZeroManifestHash { .. }))
        );
        assert!(
            rejected
                .iter()
                .any(|err| matches!(err, DaPinIntentValidationError::ZeroStorageTicket { .. }))
        );
        assert!(
            rejected
                .iter()
                .any(|err| matches!(err, DaPinIntentValidationError::DuplicateIntent { .. }))
        );
    }
    #[test]
    fn sanitize_pin_intents_rejects_duplicate_sequence_with_new_ticket() {
        let lane_config = LaneConfig::default();
        let lane_id = lane_config.primary().lane_id;
        let first = intent(lane_id, 2, 4, [0x11; 32], [0x10; 32]);
        let second = intent(lane_id, 2, 4, [0x33; 32], [0x22; 32]);
        let (kept, rejected) =
            sanitize_pin_intents(vec![first.clone(), second.clone()], &lane_config, |_| true);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].storage_ticket, second.storage_ticket);
        assert!(rejected.iter().any(|err| matches!(
            err,
            DaPinIntentValidationError::DuplicateIntent { lane, epoch, sequence }
                if *lane == lane_id && *epoch == 2 && *sequence == 4
        )));
    }
    #[test]
    fn sanitize_pin_intents_rejects_duplicate_ticket_and_manifest() {
        let lane_config = LaneConfig::default();
        let lane = lane_config.primary().lane_id;
        let first = intent(lane, 1, 1, [0x11; 32], [0x21; 32]);
        let duplicate_ticket = intent(lane, 1, 2, [0x12; 32], [0x21; 32]);
        let duplicate_manifest = intent(lane, 1, 3, [0x11; 32], [0x23; 32]);
        let (kept, rejected) = sanitize_pin_intents(
            [first.clone(), duplicate_ticket, duplicate_manifest],
            &lane_config,
            |_| true,
        );
        assert_eq!(kept, vec![first]);
        assert!(rejected.iter().any(|err| matches!(
            err,
            DaPinIntentValidationError::DuplicateStorageTicket {
                lane: seen_lane,
                epoch: 1,
                sequence: 2
            } if *seen_lane == lane
        )));
        assert!(rejected.iter().any(|err| matches!(
            err,
            DaPinIntentValidationError::DuplicateManifest {
                lane: seen_lane,
                epoch: 1,
                sequence: 3
            } if *seen_lane == lane
        )));
    }
    #[test]
    fn validate_pin_intent_bundle_rejects_unsupported_version() {
        let lane_config = LaneConfig::default();
        let lane = lane_config.primary().lane_id;
        let mut bundle = DaPinIntentBundle::new(vec![intent(lane, 1, 1, [1; 32], [2; 32])]);
        bundle.version = DaPinIntentBundle::VERSION_V1 + 1;
        let err = validate_pin_intent_bundle(&bundle, &lane_config, |_| true)
            .expect_err("unsupported pin intent bundle version must fail");
        assert!(matches!(
            err,
            DaPinIntentValidationError::UnsupportedVersion { version }
                if version == DaPinIntentBundle::VERSION_V1 + 1
        ));
    }
    #[test]
    fn validate_pin_intent_bundle_rejects_non_canonical_order() {
        let lane_config = LaneConfig::default();
        let lane = lane_config.primary().lane_id;
        let first = intent(lane, 1, 1, [0x21; 32], [0x31; 32]);
        let second = intent(lane, 1, 2, [0x22; 32], [0x32; 32]);
        let mut bundle = DaPinIntentBundle::new(vec![first.clone(), second.clone()]);
        assert_eq!(bundle.intents, vec![first.clone(), second.clone()]);
        bundle.intents.swap(0, 1);
        let err = validate_pin_intent_bundle(&bundle, &lane_config, |_| true)
            .expect_err("non-canonical pin intent order must fail");
        assert!(matches!(
            err,
            DaPinIntentValidationError::NonCanonicalOrder { index: 0 }
        ));
    }
    #[test]
    fn first_pin_intent_order_mismatch_reports_first_difference() {
        let lane_config = LaneConfig::default();
        let lane = lane_config.primary().lane_id;
        let first = intent(lane, 1, 1, [0x41; 32], [0x51; 32]);
        let second = intent(lane, 1, 2, [0x42; 32], [0x52; 32]);
        let canonical = vec![first.clone(), second.clone()];
        let reversed = vec![second, first];
        assert_eq!(
            first_pin_intent_order_mismatch(&reversed, &canonical),
            Some(0)
        );
        assert_eq!(
            first_pin_intent_order_mismatch(&canonical, &canonical),
            None
        );
    }
    #[test]
    fn validate_pin_intent_bundle_rejects_duplicate_ticket() {
        let lane_config = LaneConfig::default();
        let lane = lane_config.primary().lane_id;
        let bundle = DaPinIntentBundle::new(vec![
            intent(lane, 1, 1, [0x31; 32], [0x41; 32]),
            intent(lane, 1, 2, [0x32; 32], [0x41; 32]),
        ]);
        let err = validate_pin_intent_bundle(&bundle, &lane_config, |_| true)
            .expect_err("duplicate pin intent ticket must fail");
        assert!(matches!(
            err,
            DaPinIntentValidationError::DuplicateStorageTicket {
                lane: seen_lane,
                epoch: 1,
                sequence: 2
            } if seen_lane == lane
        ));
    }
    #[test]
    fn sanitize_pin_intents_rejects_unknown_lane() {
        let lane_config = LaneConfig::default();
        let unknown_lane = LaneId::new(99);
        let record = intent(unknown_lane, 1, 1, [9; 32], [9; 32]);
        let (kept, rejected) = sanitize_pin_intents([record], &lane_config, |_| true);
        assert!(kept.is_empty());
        assert!(matches!(
            rejected.as_slice(),
            [DaPinIntentValidationError::UnknownLane { lane }] if *lane == unknown_lane
        ));
    }
    #[test]
    fn sanitize_pin_intents_records_alias_collision() {
        let lane_config = LaneConfig::default();
        let lane = lane_config.primary().lane_id;
        let mut first = intent(lane, 1, 1, [1; 32], [1; 32]);
        set_intent_alias(&mut first, Some("alias-collision".to_owned()));
        let mut second = intent(lane, 1, 2, [2; 32], [2; 32]);
        set_intent_alias(&mut second, Some("alias-collision".to_owned()));
        let (kept, rejected) =
            sanitize_pin_intents(vec![first.clone(), second.clone()], &lane_config, |_| true);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].storage_ticket, second.storage_ticket);
        assert!(rejected.iter().any(|err| matches!(
            err,
            DaPinIntentValidationError::AliasSuperseded {
                alias,
                dropped_ticket,
                kept_ticket
            } if alias == "alias-collision"
                && *dropped_ticket == first.storage_ticket
                && *kept_ticket == second.storage_ticket
        )));
    }
    #[test]
    fn sanitize_pin_intents_enforces_alias_byte_limit() {
        let lane_config = LaneConfig::default();
        let lane = lane_config.primary().lane_id;
        let mut accepted = intent(lane, 1, 1, [0x31; 32], [0x41; 32]);
        set_intent_alias(
            &mut accepted,
            Some("a".repeat(MAX_DA_PIN_INTENT_ALIAS_BYTES)),
        );
        let mut rejected = intent(lane, 1, 2, [0x32; 32], [0x42; 32]);
        set_intent_alias(
            &mut rejected,
            Some("a".repeat(MAX_DA_PIN_INTENT_ALIAS_BYTES + 1)),
        );
        let (kept, reasons) =
            sanitize_pin_intents([accepted.clone(), rejected], &lane_config, |_| true);
        assert_eq!(kept, vec![accepted]);
        assert!(matches!(
            reasons.as_slice(),
            [DaPinIntentValidationError::AliasTooLong { len, max, .. }]
                if *len == MAX_DA_PIN_INTENT_ALIAS_BYTES + 1
                    && *max == MAX_DA_PIN_INTENT_ALIAS_BYTES
        ));
    }
    #[test]
    fn sanitize_pin_intents_rejects_unknown_owner() {
        let lane_config = LaneConfig::default();
        let lane = lane_config.primary().lane_id;
        let mut with_owner = intent(lane, 2, 0, [0xAB; 32], [0xCD; 32]);
        let key_pair =
            iroha_crypto::KeyPair::try_from_seed(vec![0xA6; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("valid deterministic unknown-owner key");
        let network_id = iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
            iroha_data_model::block::BlockHeader,
        >::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([0xA5; 32]),
        ));
        with_owner.authorization = signed_test_ingest_authorization(
            network_id,
            &key_pair,
            lane,
            with_owner.epoch,
            with_owner.sequence,
            1,
        );
        with_owner.pin_scope_authorization = signed_test_pin_scope_authorization(
            &with_owner.authorization,
            &key_pair,
            with_owner.storage_ticket,
            with_owner.manifest_hash,
            with_owner.alias.clone(),
        );
        let without_owner = intent(lane, 3, 1, [0xEF; 32], [0x11; 32]);
        let (kept, rejected) = sanitize_pin_intents(
            vec![with_owner.clone(), without_owner.clone()],
            &lane_config,
            |_| false,
        );
        assert!(
            kept.iter()
                .all(|intent| intent.storage_ticket != with_owner.storage_ticket),
            "intent with unknown owner must be dropped"
        );
        assert!(kept.is_empty());
        assert!(
            rejected
                .iter()
                .any(|reason| matches!(reason, DaPinIntentValidationError::UnknownOwner { .. })),
            "unknown owner should surface as a validation error"
        );
    }
    fn signed_authorization_for_controller(
        network_id: NetworkId,
        owner: AccountId,
        lane_id: LaneId,
        epoch: u64,
        sequence: u64,
        signers: &[&iroha_crypto::KeyPair],
    ) -> DaIngestAuthorizationV1 {
        let mut authorization = DaIngestAuthorizationV1 {
            network_id,
            owner,
            lane_id,
            epoch,
            sequence,
            payload_hash: BlobDigest::new([0xC1; 32]),
            payload_bytes: 17,
            request_content_hash: Hash::prehashed([0xC2; 32]),
            signatures: Vec::new(),
        };
        let digest = authorization.signing_digest();
        authorization.signatures = signers
            .iter()
            .map(|key_pair| DaIngestSignatureV1 {
                signer: key_pair.public_key().clone(),
                signature: iroha_crypto::Signature::try_new(key_pair.private_key(), &digest)
                    .expect("sign controller authorization"),
            })
            .collect();
        authorization
            .signatures
            .sort_by(|left, right| left.signer.cmp(&right.signer));
        authorization
    }
    fn signed_scope_for_controller(
        authorization: &DaIngestAuthorizationV1,
        storage_ticket: StorageTicketId,
        manifest_hash: ManifestDigest,
        alias: Option<String>,
        signers: &[&iroha_crypto::KeyPair],
    ) -> DaPinScopeAuthorizationV1 {
        let scope = DaPinScopeV1::new(authorization, storage_ticket, manifest_hash, alias);
        let digest = scope.signing_digest();
        let mut signatures = signers
            .iter()
            .map(|key_pair| DaPinScopeSignatureV1 {
                signer: key_pair.public_key().clone(),
                signature: iroha_crypto::Signature::try_new(key_pair.private_key(), &digest)
                    .expect("sign controller pin scope"),
            })
            .collect::<Vec<_>>();
        signatures.sort_by(|left, right| left.signer.cmp(&right.signer));
        DaPinScopeAuthorizationV1 { scope, signatures }
    }
    fn admission_policy(
        lane_id: LaneId,
        lane_incarnation: Hash,
        owner: AccountId,
        current_epoch: u64,
        grace_epoch: Option<u64>,
    ) -> DaIngestAdmissionPolicyV1 {
        DaIngestAdmissionPolicyV1 {
            version: DaIngestAdmissionPolicyV1::VERSION,
            revision: 1,
            expected_previous_policy_hash: None,
            lanes: vec![DaIngestAdmissionLaneV1 {
                lane_id,
                lane_incarnation,
                producers: vec![owner],
                current_epoch,
                grace_epoch,
            }],
        }
    }
    #[test]
    fn pin_intent_admission_allows_current_and_grace_epoch_for_exact_scope() {
        let lane = LaneId::SINGLE;
        let incarnation = Hash::prehashed([0xD1; 32]);
        let current = intent(lane, 7, 1, [0xD2; 32], [0xD3; 32]);
        let grace = intent(lane, 6, 2, [0xD4; 32], [0xD5; 32]);
        let owner = current.authorization.owner.clone();
        let bundle = DaPinIntentBundle::new(vec![current, grace]);
        let policy = admission_policy(lane, incarnation, owner, 7, Some(6));

        validate_pin_intent_admission_policy(&bundle, Some(&policy), |candidate| {
            (candidate == lane).then_some(incarnation)
        })
        .expect("the exact producer, incarnation, and current/grace epochs must be admitted");
    }
    #[test]
    fn pin_intent_admission_fails_closed_without_policy() {
        let lane = LaneId::SINGLE;
        let bundle = DaPinIntentBundle::new(vec![intent(lane, 7, 1, [0xD6; 32], [0xD7; 32])]);

        let error = validate_pin_intent_admission_policy(&bundle, None, |_| None)
            .expect_err("a non-empty bundle must require the committed admission policy");
        assert!(matches!(
            error,
            DaPinIntentValidationError::MissingAdmissionPolicy
        ));
    }
    #[test]
    fn pin_intent_admission_rejects_unretained_epoch() {
        let lane = LaneId::SINGLE;
        let incarnation = Hash::prehashed([0xD8; 32]);
        let record = intent(lane, 9, 1, [0xD9; 32], [0xDA; 32]);
        let owner = record.authorization.owner.clone();
        let bundle = DaPinIntentBundle::new(vec![record]);
        let policy = admission_policy(lane, incarnation, owner.clone(), 7, Some(6));

        let error =
            validate_pin_intent_admission_policy(&bundle, Some(&policy), |_| Some(incarnation))
                .expect_err("an unrelated future epoch must not be admitted");
        assert!(matches!(
            error,
            DaPinIntentValidationError::AdmissionDenied {
                owner: denied,
                lane: denied_lane,
                epoch: 9,
                sequence: 1,
            } if denied == owner && denied_lane == lane
        ));
    }
    #[test]
    fn pin_intent_admission_rejects_wrong_incarnation() {
        let lane = LaneId::SINGLE;
        let incarnation = Hash::prehashed([0xDB; 32]);
        let record = intent(lane, 7, 1, [0xDC; 32], [0xDD; 32]);
        let owner = record.authorization.owner.clone();
        let bundle = DaPinIntentBundle::new(vec![record]);
        let policy = admission_policy(lane, incarnation, owner, 7, None);

        let error = validate_pin_intent_admission_policy(&bundle, Some(&policy), |_| {
            Some(Hash::prehashed([0xDE; 32]))
        })
        .expect_err("a previous or unrelated lane incarnation must not be admitted");
        assert!(matches!(
            error,
            DaPinIntentValidationError::AdmissionDenied { lane: denied, .. }
                if denied == lane
        ));
    }
    #[test]
    fn pin_intent_admission_rejects_wrong_owner() {
        let lane = LaneId::SINGLE;
        let incarnation = Hash::prehashed([0xDF; 32]);
        let record = intent(lane, 7, 1, [0xE0; 32], [0xE1; 32]);
        let denied_owner = record.authorization.owner.clone();
        let bundle = DaPinIntentBundle::new(vec![record]);
        let admitted_key =
            iroha_crypto::KeyPair::try_from_seed(vec![0xE2; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("valid deterministic admitted owner key");
        let admitted_owner = AccountId::new(admitted_key.public_key().clone());
        let policy = admission_policy(lane, incarnation, admitted_owner, 7, None);

        let error =
            validate_pin_intent_admission_policy(&bundle, Some(&policy), |_| Some(incarnation))
                .expect_err(
                    "an otherwise valid request from an unlisted owner must not be admitted",
                );
        assert!(matches!(
            error,
            DaPinIntentValidationError::AdmissionDenied { owner, .. }
                if owner == denied_owner
        ));
    }
    #[test]
    fn empty_pin_intent_bundle_needs_no_admission_policy() {
        validate_pin_intent_admission_policy(&DaPinIntentBundle::default(), None, |_| None)
            .expect("an empty sidecar carries no producer scope to authorize");
    }
    #[test]
    fn ingest_authorization_rejects_same_label_different_genesis() {
        let key_pair =
            iroha_crypto::KeyPair::try_from_seed(vec![0xC3; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("valid deterministic owner key");
        let owner = AccountId::new(key_pair.public_key().clone());
        let expected = NetworkId::from_genesis_hash(
            HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                Hash::prehashed([0xC4; 32]),
            ),
        );
        let foreign = NetworkId::from_genesis_hash(
            HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                Hash::prehashed([0xC5; 32]),
            ),
        );
        let lane = LaneId::SINGLE;
        let authorization =
            signed_authorization_for_controller(foreign, owner.clone(), lane, 1, 1, &[&key_pair]);
        let scope_authorization = signed_scope_for_controller(
            &authorization,
            StorageTicketId::new([0xC6; 32]),
            ManifestDigest::new([0xC7; 32]),
            None,
            &[&key_pair],
        );
        let bundle =
            DaPinIntentBundle::new(vec![DaPinIntent::new(authorization, scope_authorization)]);
        let error = validate_pin_intent_authorizations(&bundle, expected, |candidate| {
            (candidate == &owner).then(|| owner.controller().clone())
        })
        .expect_err("the same display label cannot bridge distinct genesis lineages");
        assert!(matches!(
            error,
            DaPinIntentValidationError::WrongNetwork { actual, .. } if actual == foreign
        ));
    }
    #[test]
    fn pin_scope_authorization_rejects_outer_ticket_manifest_and_alias_mutation() {
        let original = intent(LaneId::SINGLE, 4, 6, [0xD1; 32], [0xD2; 32]);
        let network_id = original.authorization.network_id;
        let owner = original.authorization.owner.clone();
        let controller = owner.controller().clone();
        let validate = |candidate: DaPinIntent| {
            validate_pin_intent_authorizations(
                &DaPinIntentBundle::new(vec![candidate]),
                network_id,
                |candidate_owner| (candidate_owner == &owner).then(|| controller.clone()),
            )
        };
        validate(original.clone()).expect("the exact producer-approved scope must validate");

        let mut mutated_ticket = original.clone();
        mutated_ticket.storage_ticket = StorageTicketId::new([0xD3; 32]);
        assert!(matches!(
            validate(mutated_ticket),
            Err(DaPinIntentValidationError::PinScopeMismatch { .. })
        ));

        let mut mutated_manifest = original.clone();
        mutated_manifest.manifest_hash = ManifestDigest::new([0xD4; 32]);
        assert!(matches!(
            validate(mutated_manifest),
            Err(DaPinIntentValidationError::PinScopeMismatch { .. })
        ));

        let mut mutated_alias = original;
        mutated_alias.alias = Some("forged-alias".to_owned());
        assert!(matches!(
            validate(mutated_alias),
            Err(DaPinIntentValidationError::PinScopeMismatch { .. })
        ));
    }
    #[test]
    fn ingest_authorization_enforces_committed_multisig_threshold() {
        let member_a =
            iroha_crypto::KeyPair::try_from_seed(vec![0xC8; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("valid member A");
        let member_b =
            iroha_crypto::KeyPair::try_from_seed(vec![0xC9; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("valid member B");
        let policy = MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(member_a.public_key().clone(), 1).expect("member A policy"),
                MultisigMember::new(member_b.public_key().clone(), 1).expect("member B policy"),
            ],
        )
        .expect("two-of-two policy");
        let owner = AccountId::new_multisig(policy.clone());
        let network_id = NetworkId::from_genesis_hash(
            HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                Hash::prehashed([0xCA; 32]),
            ),
        );
        let make_bundle = |request_signers: &[&iroha_crypto::KeyPair],
                           scope_signers: &[&iroha_crypto::KeyPair]| {
            let authorization = signed_authorization_for_controller(
                network_id,
                owner.clone(),
                LaneId::SINGLE,
                2,
                3,
                request_signers,
            );
            let scope_authorization = signed_scope_for_controller(
                &authorization,
                StorageTicketId::new([0xCB; 32]),
                ManifestDigest::new([0xCC; 32]),
                None,
                scope_signers,
            );
            DaPinIntentBundle::new(vec![DaPinIntent::new(authorization, scope_authorization)])
        };
        validate_pin_intent_authorizations(
            &make_bundle(&[&member_a, &member_b], &[&member_a, &member_b]),
            network_id,
            |candidate| (candidate == &owner).then(|| AccountController::Multisig(policy.clone())),
        )
        .expect("canonical two-of-two witnesses satisfy committed state");
        let error = validate_pin_intent_authorizations(
            &make_bundle(&[&member_a], &[&member_a, &member_b]),
            network_id,
            |candidate| (candidate == &owner).then(|| AccountController::Multisig(policy.clone())),
        )
        .expect_err("one witness cannot satisfy a two-of-two account");
        assert!(matches!(
            error,
            DaPinIntentValidationError::UnauthorizedOwner { owner: rejected } if rejected == owner
        ));
        let error = validate_pin_intent_authorizations(
            &make_bundle(&[&member_a, &member_b], &[&member_a]),
            network_id,
            |candidate| (candidate == &owner).then(|| AccountController::Multisig(policy.clone())),
        )
        .expect_err("one pin-scope witness cannot satisfy a two-of-two account");
        assert!(matches!(
            error,
            DaPinIntentValidationError::UnauthorizedPinScopeOwner { owner: rejected }
                if rejected == owner
        ));
    }
}
/// Snapshot the configured proof policies for all lanes.
#[must_use]
pub fn proof_policies(lane_config: &LaneConfig) -> Vec<DaProofPolicy> {
    lane_config
        .entries()
        .iter()
        .map(|entry| DaProofPolicy {
            lane_id: entry.lane_id,
            dataspace_id: entry.dataspace_id,
            alias: entry.alias.clone(),
            proof_scheme: entry.proof_scheme,
        })
        .collect()
}
#[cfg(test)]
/// Snapshot active proof policies for catalog-backed Nexus lanes.
#[must_use]
pub fn active_proof_policies(nexus: &Nexus) -> Vec<DaProofPolicy> {
    nexus
        .lane_catalog
        .lanes()
        .iter()
        .filter_map(|lane| active_lane_proof_policy(nexus, lane.id).ok())
        .collect()
}
/// Snapshot active proof policies for catalog-backed Nexus lanes at a block height.
#[must_use]
pub fn active_proof_policies_at_height(nexus: &Nexus, block_height: u64) -> Vec<DaProofPolicy> {
    let context = ActiveLaneProofPolicyContext::new(nexus);
    nexus
        .lane_catalog
        .lanes()
        .iter()
        .filter_map(|lane| context.policy_at_height(lane.id, block_height).ok())
        .collect()
}
/// Snapshot the configured proof policies as a versioned bundle.
#[must_use]
pub fn proof_policy_bundle(lane_config: &LaneConfig) -> DaProofPolicyBundle {
    DaProofPolicyBundle::new(proof_policies(lane_config))
}
#[cfg(test)]
/// Snapshot active proof policies as a versioned bundle.
#[must_use]
pub fn active_proof_policy_bundle(nexus: &Nexus) -> DaProofPolicyBundle {
    DaProofPolicyBundle::new(active_proof_policies(nexus))
}
/// Snapshot active proof policies as a versioned bundle at a block height.
#[must_use]
pub fn active_proof_policy_bundle_at_height(
    nexus: &Nexus,
    block_height: u64,
) -> DaProofPolicyBundle {
    DaProofPolicyBundle::new(active_proof_policies_at_height(nexus, block_height))
}
#[cfg(any(test, feature = "iroha-core-tests"))]
/// Compute the hash for the current proof policy bundle.
#[must_use]
pub fn proof_policy_bundle_hash(lane_config: &LaneConfig) -> HashOf<DaProofPolicyBundle> {
    let bundle = proof_policy_bundle(lane_config);
    HashOf::new(&bundle)
}
#[cfg(test)]
/// Compute the hash for the active proof policy bundle.
#[must_use]
pub fn active_proof_policy_bundle_hash(nexus: &Nexus) -> HashOf<DaProofPolicyBundle> {
    let bundle = active_proof_policy_bundle(nexus);
    HashOf::new(&bundle)
}
#[cfg(test)]
/// Compute the hash for the active proof policy bundle at a block height.
#[must_use]
pub fn active_proof_policy_bundle_hash_at_height(
    nexus: &Nexus,
    block_height: u64,
) -> HashOf<DaProofPolicyBundle> {
    let bundle = active_proof_policy_bundle_at_height(nexus, block_height);
    HashOf::new(&bundle)
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, Signature};
    use iroha_data_model::{
        da::{
            commitment::RetentionClass,
            types::{BlobDigest, StorageTicketId},
        },
        nexus::{
            DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneCatalogError,
            LaneConfig as ModelLaneConfig, LaneStorageProfile,
        },
    };

    use iroha_model_base::topology::DataSpaceId;
    use norito::to_bytes;
    use std::{collections::BTreeMap, num::NonZeroU32};
    fn test_pin_authorization(
        lane: LaneId,
        epoch: u64,
        sequence: u64,
    ) -> iroha_data_model::da::ingest::DaIngestAuthorizationV1 {
        let key_pair = KeyPair::try_from_seed(vec![0xDA; 32], Algorithm::Ed25519)
            .expect("valid deterministic DA authorization key");
        let network_id = NetworkId::from_genesis_hash(
            HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                Hash::prehashed([0xAD; 32]),
            ),
        );
        signed_test_ingest_authorization(network_id, &key_pair, lane, epoch, sequence, 1)
    }
    fn test_pin_intent(
        lane: LaneId,
        epoch: u64,
        sequence: u64,
        storage_ticket: StorageTicketId,
        manifest_hash: iroha_data_model::sorafs::pin_registry::ManifestDigest,
    ) -> iroha_data_model::da::pin_intent::DaPinIntent {
        let key_pair = KeyPair::try_from_seed(vec![0xDA; 32], Algorithm::Ed25519)
            .expect("valid deterministic DA authorization key");
        signed_test_pin_intent(
            test_pin_authorization(lane, epoch, sequence),
            &key_pair,
            storage_ticket,
            manifest_hash,
            None,
        )
    }
    fn lane_catalog_with(lanes: Vec<ModelLaneConfig>) -> LaneCatalog {
        let max_lane = lanes
            .iter()
            .map(|lane| lane.id.as_u32())
            .max()
            .unwrap_or_default();
        let lane_count =
            NonZeroU32::new(max_lane.saturating_add(1)).expect("lane count is non-zero");
        LaneCatalog::new(lane_count, lanes).expect("lane catalog")
    }
    fn lane_config_with(
        lanes: Vec<ModelLaneConfig>,
    ) -> iroha_config::parameters::actual::LaneConfig {
        let catalog = lane_catalog_with(lanes);
        iroha_config::parameters::actual::LaneConfig::from_catalog(&catalog)
    }
    fn nexus_with_catalog(lane_catalog: LaneCatalog) -> Nexus {
        let dataspace_catalog = DataSpaceCatalog::new(
            lane_catalog
                .lanes()
                .iter()
                .map(|lane| lane.dataspace_id)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(|id| DataSpaceMetadata {
                    id,
                    alias: format!("ds-{}", id.as_u64()),
                    description: None,
                    fault_tolerance: 1,
                })
                .collect(),
        )
        .expect("dataspace catalog");
        Nexus {
            lane_config: LaneConfig::from_catalog(&lane_catalog),
            lane_catalog,
            dataspace_catalog,
            ..Default::default()
        }
    }
    fn merkle_record(lane: u32) -> DaCommitmentRecord {
        DaCommitmentRecord::new(
            LaneId::new(lane),
            1,
            1,
            BlobDigest::new([0x11; 32]),
            iroha_data_model::sorafs::pin_registry::ManifestDigest::new([0x22; 32]),
            DaProofScheme::MerkleSha256,
            Hash::prehashed([0x33; 32]),
            Some(Hash::prehashed([0x44; 32])),
            RetentionClass::default(),
            StorageTicketId::new([0x55; 32]),
            Signature::try_from_bytes(&[0x66; 64])
                .expect("checked core DA Merkle acknowledgement signature fixture"),
        )
    }
    #[test]
    fn proof_policies_reflect_lane_config() {
        let lane_a = ModelLaneConfig {
            id: LaneId::new(1),
            alias: "merkle-lane".to_string(),
            dataspace_id: DataSpaceId::new(7),
            proof_scheme: DaProofScheme::MerkleSha256,
            ..ModelLaneConfig::default()
        };
        let lane_b = ModelLaneConfig {
            id: LaneId::new(2),
            alias: "second-merkle-lane".to_string(),
            dataspace_id: DataSpaceId::new(9),
            proof_scheme: DaProofScheme::MerkleSha256,
            ..ModelLaneConfig::default()
        };
        let lane_config = lane_config_with(vec![lane_a.clone(), lane_b.clone()]);
        let policies = proof_policies(&lane_config);
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].lane_id, lane_a.id);
        assert_eq!(policies[0].dataspace_id, lane_a.dataspace_id);
        assert_eq!(policies[0].alias, lane_a.alias);
        assert_eq!(policies[0].proof_scheme, lane_a.proof_scheme);
        assert_eq!(policies[1].lane_id, lane_b.id);
        assert_eq!(policies[1].dataspace_id, lane_b.dataspace_id);
        assert_eq!(policies[1].alias, lane_b.alias);
        assert_eq!(policies[1].proof_scheme, lane_b.proof_scheme);
    }
    #[test]
    fn active_proof_policy_bundle_ignores_stale_geometry_for_removed_catalog_lane() {
        let stale_lane = LaneId::new(1);
        let authoritative_catalog = lane_catalog_with(vec![ModelLaneConfig::default()]);
        let stale_geometry_catalog = lane_catalog_with(vec![
            ModelLaneConfig::default(),
            ModelLaneConfig {
                id: stale_lane,
                alias: "stale-da".to_owned(),
                ..ModelLaneConfig::default()
            },
        ]);
        let mut nexus = nexus_with_catalog(authoritative_catalog);
        nexus.lane_config = LaneConfig::from_catalog(&stale_geometry_catalog);
        assert!(
            nexus.lane_config.entry(stale_lane).is_some(),
            "test must seed derived geometry for the removed lane"
        );
        let bundle = active_proof_policy_bundle(&nexus);
        assert_eq!(bundle.policies().len(), 1);
        assert_eq!(bundle.policies()[0].lane_id, LaneId::SINGLE);
        assert!(
            bundle
                .policies()
                .iter()
                .all(|policy| policy.lane_id != stale_lane),
            "stale geometry-only lane must not appear in active DA policy bundle"
        );
        assert!(matches!(
            active_lane_proof_policy(&nexus, stale_lane),
            Err(DaProofPolicyError::UnknownLane { lane }) if lane == stale_lane
        ));
    }
    #[test]
    fn validate_commitment_bundle_against_nexus_rejects_stale_geometry_lane() {
        let stale_lane = LaneId::new(1);
        let authoritative_catalog = lane_catalog_with(vec![ModelLaneConfig::default()]);
        let stale_geometry_catalog = lane_catalog_with(vec![
            ModelLaneConfig::default(),
            ModelLaneConfig {
                id: stale_lane,
                alias: "stale-da-commitment".to_owned(),
                ..ModelLaneConfig::default()
            },
        ]);
        let mut nexus = nexus_with_catalog(authoritative_catalog);
        nexus.lane_config = LaneConfig::from_catalog(&stale_geometry_catalog);
        let bundle = DaCommitmentBundle::new(vec![merkle_record(stale_lane.as_u32())]);
        let err = validate_commitment_bundle_against_nexus(&bundle, &nexus)
            .expect_err("stale geometry-only lane must not validate commitments");
        assert!(matches!(
            err,
            DaCommitmentValidationError::ProofPolicy(DaProofPolicyError::UnknownLane { lane })
                if lane == stale_lane
        ));
    }
    #[test]
    fn validate_pin_intent_bundle_against_nexus_rejects_stale_geometry_lane() {
        let stale_lane = LaneId::new(1);
        let authoritative_catalog = lane_catalog_with(vec![ModelLaneConfig::default()]);
        let stale_geometry_catalog = lane_catalog_with(vec![
            ModelLaneConfig::default(),
            ModelLaneConfig {
                id: stale_lane,
                alias: "stale-da-intent".to_owned(),
                ..ModelLaneConfig::default()
            },
        ]);
        let mut nexus = nexus_with_catalog(authoritative_catalog);
        nexus.lane_config = LaneConfig::from_catalog(&stale_geometry_catalog);
        let bundle =
            iroha_data_model::da::pin_intent::DaPinIntentBundle::new(vec![test_pin_intent(
                stale_lane,
                1,
                1,
                StorageTicketId::new([0xCD; 32]),
                iroha_data_model::sorafs::pin_registry::ManifestDigest::new([0xAB; 32]),
            )]);
        let err = validate_pin_intent_bundle_against_nexus(&bundle, &nexus, |_| true)
            .expect_err("stale geometry-only lane must not validate pin intents");
        assert!(matches!(
            err,
            DaPinIntentValidationError::UnknownLane { lane } if lane == stale_lane
        ));
    }
    #[test]
    fn active_proof_policy_rejects_catalog_lane_with_missing_dataspace() {
        let inactive_lane = LaneId::new(1);
        let lane_catalog = lane_catalog_with(vec![
            ModelLaneConfig::default(),
            ModelLaneConfig {
                id: inactive_lane,
                dataspace_id: DataSpaceId::new(7),
                alias: "missing-dataspace-da".to_owned(),
                proof_scheme: DaProofScheme::MerkleSha256,
                ..ModelLaneConfig::default()
            },
        ]);
        let mut nexus = nexus_with_catalog(lane_catalog);
        nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata::default()])
            .expect("dataspace catalog without lane dataspace");
        let bundle = active_proof_policy_bundle(&nexus);
        assert!(
            bundle
                .policies()
                .iter()
                .all(|policy| policy.lane_id != inactive_lane),
            "lanes whose dataspace is absent from the active catalog must not advertise DA policy"
        );
        assert!(matches!(
            active_lane_proof_policy(&nexus, inactive_lane),
            Err(DaProofPolicyError::UnknownLane { lane }) if lane == inactive_lane
        ));
        let commitment_bundle =
            DaCommitmentBundle::new(vec![merkle_record(inactive_lane.as_u32())]);
        let err = validate_commitment_bundle_against_nexus(&commitment_bundle, &nexus)
            .expect_err("missing dataspace must not validate DA commitments");
        assert!(matches!(
            err,
            DaCommitmentValidationError::ProofPolicy(DaProofPolicyError::UnknownLane { lane })
                if lane == inactive_lane
        ));
        let pin_bundle =
            iroha_data_model::da::pin_intent::DaPinIntentBundle::new(vec![test_pin_intent(
                inactive_lane,
                1,
                1,
                StorageTicketId::new([0x41; 32]),
                iroha_data_model::sorafs::pin_registry::ManifestDigest::new([0x43; 32]),
            )]);
        let err = validate_pin_intent_bundle_against_nexus(&pin_bundle, &nexus, |_| true)
            .expect_err("missing dataspace must not validate DA pin intents");
        assert!(matches!(
            err,
            DaPinIntentValidationError::UnknownLane { lane } if lane == inactive_lane
        ));
    }
    #[test]
    fn borrowed_active_policy_keeps_the_original_snapshot_and_rejects_namespace_drift() {
        let lane = LaneId::new(1);
        let catalog = lane_catalog_with(vec![
            ModelLaneConfig::default(),
            ModelLaneConfig {
                id: lane,
                alias: "Original Lane".into(),
                ..ModelLaneConfig::default()
            },
        ]);
        let nexus = nexus_with_catalog(catalog);
        let context = ActiveLaneProofPolicyContext::new(&nexus);
        assert!(std::ptr::eq(context.nexus, &raw const nexus));
        assert!(std::ptr::eq(
            context.entry(lane, Some(1)).unwrap(),
            nexus.lane_config.entry(lane).unwrap()
        ));
        context
            .enforce_commitment_at_height(&merkle_record(1), 1)
            .unwrap();
        // This separate mutable runtime copy cannot replace the context's source.
        let mut changed = nexus.clone();
        let mut drifted_catalog = changed.lane_catalog.lanes().to_vec();
        drifted_catalog[1].alias = "Replacement Lane".into();
        changed.lane_config = LaneConfig::from_catalog(&lane_catalog_with(drifted_catalog));
        assert!(matches!(
            ActiveLaneProofPolicyContext::new(&changed).enforce_commitment_at_height(&merkle_record(1), 1),
            Err(DaProofPolicyError::UnknownLane { lane: rejected }) if rejected == lane
        ));
        context
            .enforce_commitment_at_height(&merkle_record(1), 1)
            .unwrap();
    }
    #[test]
    fn active_proof_policy_rejects_catalog_geometry_drift() {
        let drifted_lane = LaneId::new(1);
        let authoritative_catalog = lane_catalog_with(vec![
            ModelLaneConfig::default(),
            ModelLaneConfig {
                id: drifted_lane,
                alias: "catalog-da".to_owned(),
                dataspace_id: DataSpaceId::new(7),
                proof_scheme: DaProofScheme::MerkleSha256,
                ..ModelLaneConfig::default()
            },
        ]);
        let drifted_geometry_catalog = lane_catalog_with(vec![
            ModelLaneConfig::default(),
            ModelLaneConfig {
                id: drifted_lane,
                alias: "drifted-da".to_owned(),
                dataspace_id: DataSpaceId::new(9),
                proof_scheme: DaProofScheme::MerkleSha256,
                ..ModelLaneConfig::default()
            },
        ]);
        let mut nexus = nexus_with_catalog(authoritative_catalog);
        nexus.lane_config = LaneConfig::from_catalog(&drifted_geometry_catalog);
        let bundle = active_proof_policy_bundle(&nexus);
        assert!(
            bundle
                .policies()
                .iter()
                .all(|policy| policy.lane_id != drifted_lane),
            "catalog/geometry drift must fail closed instead of advertising stale DA policy"
        );
        assert!(matches!(
            active_lane_proof_policy(&nexus, drifted_lane),
            Err(DaProofPolicyError::UnknownLane { lane }) if lane == drifted_lane
        ));
        let commitment_bundle = DaCommitmentBundle::new(vec![merkle_record(drifted_lane.as_u32())]);
        let err = validate_commitment_bundle_against_nexus(&commitment_bundle, &nexus)
            .expect_err("catalog/geometry drift must not validate DA commitments");
        assert!(matches!(
            err,
            DaCommitmentValidationError::ProofPolicy(DaProofPolicyError::UnknownLane { lane })
                if lane == drifted_lane
        ));
        let pin_bundle =
            iroha_data_model::da::pin_intent::DaPinIntentBundle::new(vec![test_pin_intent(
                drifted_lane,
                1,
                1,
                StorageTicketId::new([0x51; 32]),
                iroha_data_model::sorafs::pin_registry::ManifestDigest::new([0x53; 32]),
            )]);
        let err = validate_pin_intent_bundle_against_nexus(&pin_bundle, &nexus, |_| true)
            .expect_err("catalog/geometry drift must not validate DA pin intents");
        assert!(matches!(
            err,
            DaPinIntentValidationError::UnknownLane { lane } if lane == drifted_lane
        ));
    }
    #[test]
    fn proof_policy_bundle_hash_matches_precomputed() {
        let config = lane_config_with(vec![ModelLaneConfig::default()]);
        let bundle = proof_policy_bundle(&config);
        let hash = proof_policy_bundle_hash(&config);
        let expected_hash = HashOf::new(&bundle);
        assert_eq!(hash, expected_hash);
        assert_eq!(bundle.version(), DaProofPolicyBundle::VERSION_V1);
        let encoded = to_bytes(&bundle.policies().to_vec()).expect("encode policies");
        assert_eq!(bundle.policy_hash(), Hash::new(encoded));
    }
    #[test]
    fn allows_merkle_lane_commitment() {
        let lane_config = lane_config_with(vec![ModelLaneConfig::default()]);
        let record = merkle_record(0);
        assert!(enforce_lane_proof_policy(&record, &lane_config).is_ok());
    }
    #[test]
    fn rejects_unknown_lane() {
        let lane_config = lane_config_with(vec![ModelLaneConfig::default()]);
        let record = merkle_record(2);
        let err = enforce_lane_proof_policy(&record, &lane_config).expect_err("should fail");
        assert!(matches!(err, DaProofPolicyError::UnknownLane { .. }));
    }
    #[test]
    fn rejects_zero_chunk_root() {
        let lane_config = lane_config_with(vec![ModelLaneConfig::default()]);
        let record = DaCommitmentRecord {
            chunk_root: Hash::prehashed([0u8; 32]),
            ..merkle_record(0)
        };
        let err = enforce_lane_proof_policy(&record, &lane_config).expect_err("should fail");
        assert!(matches!(err, DaProofPolicyError::ZeroChunkRoot { .. }));
    }
    #[test]
    fn validate_commitment_bundle_rejects_duplicate_key() {
        let lane_config = lane_config_with(vec![ModelLaneConfig::default()]);
        let record = merkle_record(0);
        let duplicate = DaCommitmentRecord {
            acknowledgement_sig: Signature::try_from_bytes(&[0x99; 64])
                .expect("checked core DA duplicate acknowledgement signature fixture"),
            ..record.clone()
        };
        let bundle = DaCommitmentBundle::new(vec![record, duplicate]);
        let err =
            validate_commitment_bundle(&bundle, &lane_config).expect_err("duplicate must fail");
        assert!(matches!(
            err,
            DaCommitmentValidationError::DuplicateCommitment { .. }
        ));
    }
    #[test]
    fn validate_commitment_bundle_rejects_unsupported_version() {
        let lane_config = lane_config_with(vec![ModelLaneConfig::default()]);
        let bundle = DaCommitmentBundle::from_untrusted_parts(
            DaCommitmentBundle::VERSION_V1 + 1,
            vec![merkle_record(0)],
        );
        let err = validate_commitment_bundle(&bundle, &lane_config)
            .expect_err("unsupported commitment bundle version must fail");
        assert!(matches!(
            err,
            DaCommitmentValidationError::UnsupportedVersion { version }
                if version == DaCommitmentBundle::VERSION_V1 + 1
        ));
    }
    #[test]
    fn validate_commitment_bundle_rejects_duplicate_sequence_with_new_ticket() {
        let lane_config = lane_config_with(vec![ModelLaneConfig::default()]);
        let first = merkle_record(0);
        let mut second = first.clone();
        second.storage_ticket = StorageTicketId::new([0x99; 32]);
        second.manifest_hash =
            iroha_data_model::sorafs::pin_registry::ManifestDigest::new([0x77; 32]);
        let bundle = DaCommitmentBundle::new(vec![first, second]);
        let err =
            validate_commitment_bundle(&bundle, &lane_config).expect_err("duplicate must fail");
        assert!(matches!(
            err,
            DaCommitmentValidationError::DuplicateCommitment { .. }
        ));
    }
    #[test]
    fn validate_commitment_bundle_rejects_duplicate_manifest() {
        let lane_config = lane_config_with(vec![ModelLaneConfig::default()]);
        let first = merkle_record(0);
        let mut second = merkle_record(0);
        second.sequence = 9;
        second.storage_ticket = StorageTicketId::new([0x99; 32]);
        let bundle = DaCommitmentBundle::new(vec![first.clone(), second.clone()]);
        let err =
            validate_commitment_bundle(&bundle, &lane_config).expect_err("duplicate must fail");
        assert!(matches!(
            err,
            DaCommitmentValidationError::DuplicateManifest { .. }
        ));
    }
    #[test]
    fn validate_commitment_bundle_rejects_duplicate_storage_ticket() {
        let lane_config = lane_config_with(vec![ModelLaneConfig::default()]);
        let first = merkle_record(0);
        let mut second = merkle_record(0);
        second.sequence = 9;
        second.manifest_hash =
            iroha_data_model::sorafs::pin_registry::ManifestDigest::new([0x77; 32]);
        let bundle = DaCommitmentBundle::new(vec![first.clone(), second.clone()]);
        let err =
            validate_commitment_bundle(&bundle, &lane_config).expect_err("duplicate must fail");
        assert!(matches!(
            err,
            DaCommitmentValidationError::DuplicateStorageTicket { .. }
        ));
    }
    #[test]
    fn validate_commitment_bundle_rejects_non_canonical_order() {
        let lane_config = lane_config_with(vec![ModelLaneConfig::default()]);
        let first = merkle_record(0);
        let mut second = first.clone();
        second.sequence = 2;
        second.manifest_hash =
            iroha_data_model::sorafs::pin_registry::ManifestDigest::new([0x23; 32]);
        second.storage_ticket = StorageTicketId::new([0x56; 32]);
        let canonical = vec![first.clone(), second.clone()];
        let reversed = DaCommitmentBundle::from_untrusted_parts(
            DaCommitmentBundle::VERSION_V1,
            vec![second, first],
        );
        let err = validate_commitment_bundle(&reversed, &lane_config)
            .expect_err("non-canonical commitment bundle order must fail");
        assert_eq!(
            first_commitment_order_mismatch(reversed.commitments(), &canonical),
            Some(0)
        );
        assert!(matches!(
            err,
            DaCommitmentValidationError::NonCanonicalOrder { index: 0 }
        ));
    }
    #[test]
    fn validate_commitment_bundle_accepts_constructor_canonicalized_input() {
        let lane_config = lane_config_with(vec![ModelLaneConfig::default()]);
        let first = merkle_record(0);
        let mut second = first.clone();
        second.sequence = 2;
        second.manifest_hash =
            iroha_data_model::sorafs::pin_registry::ManifestDigest::new([0x25; 32]);
        second.storage_ticket = StorageTicketId::new([0x58; 32]);
        let bundle = DaCommitmentBundle::new(vec![second, first.clone()]);
        assert_eq!(bundle.commitments()[0], first);
        validate_commitment_bundle(&bundle, &lane_config)
            .expect("constructor-canonicalized commitment bundle must validate");
    }
    #[test]
    fn first_commitment_order_mismatch_reports_first_difference() {
        let first = merkle_record(0);
        let mut second = first.clone();
        second.sequence = 2;
        second.manifest_hash =
            iroha_data_model::sorafs::pin_registry::ManifestDigest::new([0x24; 32]);
        second.storage_ticket = StorageTicketId::new([0x57; 32]);
        let canonical = vec![first.clone(), second.clone()];
        let reversed = vec![second, first];
        assert_eq!(
            first_commitment_order_mismatch(&reversed, &canonical),
            Some(0)
        );
        assert_eq!(
            first_commitment_order_mismatch(&canonical, &canonical),
            None
        );
    }
    #[test]
    fn validate_commitment_bundle_rejects_zero_manifest_hash() {
        let lane_config = lane_config_with(vec![ModelLaneConfig::default()]);
        let mut record = merkle_record(0);
        record.manifest_hash = iroha_data_model::sorafs::pin_registry::ManifestDigest::new([0; 32]);
        let bundle = DaCommitmentBundle::new(vec![record]);
        let err =
            validate_commitment_bundle(&bundle, &lane_config).expect_err("zero manifest must fail");
        assert!(matches!(
            err,
            DaCommitmentValidationError::ZeroManifestHash { .. }
        ));
    }
    #[test]
    fn validate_commitment_bundle_rejects_zero_storage_ticket() {
        let lane_config = lane_config_with(vec![ModelLaneConfig::default()]);
        let mut record = merkle_record(0);
        record.storage_ticket = StorageTicketId::new([0; 32]);
        let bundle = DaCommitmentBundle::new(vec![record]);
        let err =
            validate_commitment_bundle(&bundle, &lane_config).expect_err("zero ticket must fail");
        assert!(matches!(
            err,
            DaCommitmentValidationError::ZeroStorageTicket { .. }
        ));
    }
    #[test]
    fn validate_commitment_bundle_rejects_retired_confidential_metadata() {
        let mut metadata = BTreeMap::new();
        metadata.insert("confidential_compute".to_string(), "true".to_string());
        let error = LaneCatalog::new(
            NonZeroU32::new(1).expect("nonzero lane count"),
            vec![ModelLaneConfig {
                storage: LaneStorageProfile::SplitReplica,
                metadata,
                ..ModelLaneConfig::default()
            }],
        )
        .expect_err("retired confidential metadata must fail at catalog admission");
        assert!(matches!(
            error,
            LaneCatalogError::RetiredFunctionalMetadata { .. }
        ));
    }
    #[test]
    fn validate_commitment_bundle_len_rejects_unrepresentable_location_space() {
        assert!(validate_commitment_bundle_len(0).is_ok());
        assert!(validate_commitment_bundle_len(MAX_DA_BUNDLE_LOCATIONS).is_ok());
        if let Some(len) = MAX_DA_BUNDLE_LOCATIONS.checked_add(1) {
            let err = validate_commitment_bundle_len(len)
                .expect_err("unrepresentable DA bundle length must fail");
            assert_eq!(
                err,
                DaCommitmentValidationError::BundleTooLarge {
                    len,
                    max: MAX_DA_BUNDLE_LOCATIONS
                }
            );
        }
    }
    #[test]
    fn validate_pin_intent_bundle_len_rejects_unrepresentable_location_space() {
        assert!(validate_pin_intent_bundle_len(0).is_ok());
        assert!(validate_pin_intent_bundle_len(MAX_DA_BUNDLE_LOCATIONS).is_ok());
        if let Some(len) = MAX_DA_BUNDLE_LOCATIONS.checked_add(1) {
            let err = validate_pin_intent_bundle_len(len)
                .expect_err("unrepresentable DA pin-intent bundle length must fail");
            assert_eq!(
                err,
                DaPinIntentValidationError::BundleTooLarge {
                    len,
                    max: MAX_DA_BUNDLE_LOCATIONS
                }
            );
        }
    }
    #[test]
    fn proof_policy_bundle_exposes_hash() {
        let lanes = vec![
            ModelLaneConfig {
                id: LaneId::new(1),
                alias: "lane-a".to_string(),
                ..ModelLaneConfig::default()
            },
            ModelLaneConfig {
                id: LaneId::new(2),
                alias: "lane-b".to_string(),
                proof_scheme: DaProofScheme::MerkleSha256,
                ..ModelLaneConfig::default()
            },
        ];
        let config = lane_config_with(lanes);
        let bundle = proof_policy_bundle(&config);
        assert_eq!(bundle.policies().len(), 2);
        assert_ne!(bundle.policy_hash(), Hash::prehashed([0; 32]));
        assert_eq!(bundle.version(), DaProofPolicyBundle::VERSION_V1);
    }
    #[test]
    fn committed_policy_bundle_rejects_duplicate_lanes_globally() {
        let policy = DaProofPolicy {
            lane_id: LaneId::new(7),
            dataspace_id: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            alias: "lane-seven".to_owned(),
            proof_scheme: DaProofScheme::MerkleSha256,
        };
        let bundle = DaProofPolicyBundle::new(vec![policy.clone(), policy]);
        assert_eq!(
            validate_committed_proof_policy_bundle(&bundle),
            Err(DaProofPolicyError::DuplicateLanePolicy {
                lane: LaneId::new(7)
            })
        );
    }
}
