//! Durable restricted-availability storage for atomic private settlement legs.
//!
//! The store persists encrypted sidecars as canonical Norito records addressed
//! by their committed payload digest. It exposes separate least-privilege views
//! to the exact four-validator committee and to governed auditors. No plaintext
//! audit material is accepted or persisted by this module.

#[cfg(test)]
use super::state::private_settlement_approvals_digest_v1;
use super::{
    protocol::{
        private_settlement_phase_body_v1, private_settlement_reserved_prepared_bundle_digest_v1,
        validate_authority_cryptography_v1, validate_private_settlement_prepare_barrier_v1,
        verify_private_settlement_phase_certificate_v1, verify_private_settlement_receipt_v1,
    },
    state::{
        PrivateSettlementDurableAvailabilityV1, PrivateSettlementStateErrorV1,
        ValidatedPrivateSettlementLegV1,
    },
};
#[cfg(test)]
use crate::private_settlement::state::PrivateSettlementPoolGovernanceExtV1 as _;
#[cfg(test)]
use iroha_data_model::nexus::PrivateSettlementPoolGovernanceProjectionV1;

fn validate_provisional_authority_cryptography_v1(
    authority: &PrivateSettlementCommitteeAuthorityV1,
) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
    validate_authority_cryptography_v1(authority)
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)
}

fn phase_certificates_are_quorum_equivalent_v1(
    left: &PrivateSettlementPhaseCertificateV1,
    right: &PrivateSettlementPhaseCertificateV1,
) -> bool {
    left.body == right.body && left.authority_catalog_index == right.authority_catalog_index
}
use iroha_crypto::{Algorithm, Hash};
use iroha_data_model::{
    account::AccountId,
    nexus::{
        AtomicPrivateSettlementV1, PrivateSettlementAbortReasonV1, PrivateSettlementAbortReceiptV1,
        PrivateSettlementAuditApprovalV1, PrivateSettlementAuditCapsuleV1,
        PrivateSettlementAuditPolicyV1, PrivateSettlementCommitteeAuthorityV1,
        PrivateSettlementDeltaV1, PrivateSettlementLegPayloadV1, PrivateSettlementPhaseBodyV1,
        PrivateSettlementPhaseCertificateV1, PrivateSettlementPhaseV1,
        PrivateSettlementPrepareBarrierV1, PrivateSettlementProofStatementV1,
        PrivateSettlementProvisionalLegMaterialV1, PrivateSettlementReceiptV1,
        PrivateSettlementRouteV1, PrivateSettlementSidecarAvailabilityV1,
        validate_private_settlement_audit_approval_v1,
        validate_private_settlement_audit_approvals_v1,
    },
    privacy::{PrivacyCommitmentV1, PrivacyNullifierV1, PrivacyPoolIdV1, PrivacyRootV1},
};
use iroha_model_base::peer::PeerId;
use norito::codec::{Decode, Encode};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};
use thiserror::Error;

const SIDECAR_RECORD_MAGIC_V1: [u8; 4] = *b"APS1";
const SIDECAR_RECORD_VERSION_V1: u8 = 1;
const SIDECAR_RECORD_EXTENSION_V1: &str = ".aps1";
const PROVISIONAL_RECORD_MAGIC_V1: [u8; 4] = *b"APV1";
const PROVISIONAL_RECORD_VERSION_V1: u8 = 1;
const PROVISIONAL_RECORD_EXTENSION_V1: &str = ".apv1";
const SIDECAR_TEMP_DIRECTORY_V1: &str = ".tmp";
const SIDECAR_TEMP_EXTENSION_V1: &str = ".tmp";
const SIDECAR_WRITER_LOCK_FILE_V1: &str = ".writer.lock";
const FINALIZED_RECEIPT_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:finalized-receipt:v1\0";
const ABORT_RECEIPT_DIGEST_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:abort-receipt:v1\0";
const LOCAL_EXPIRY_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:nexus:private-settlement:authoritative-height-expiry:v1\0";

/// Maximum canonical bytes accepted for one encrypted settlement sidecar.
pub const PRIVATE_SETTLEMENT_SIDECAR_MAX_RECORD_BYTES_V1: u64 = 12 * 1024 * 1024;
/// Hard maximum retained sidecar count for one store.
pub const PRIVATE_SETTLEMENT_SIDECAR_HARD_MAX_RECORDS_V1: usize = 4_096;
/// Hard maximum canonical byte footprint for one store.
pub const PRIVATE_SETTLEMENT_SIDECAR_HARD_MAX_TOTAL_BYTES_V1: u64 =
    PRIVATE_SETTLEMENT_SIDECAR_MAX_RECORD_BYTES_V1
        * PRIVATE_SETTLEMENT_SIDECAR_HARD_MAX_RECORDS_V1 as u64;
/// Default retained sidecar count.
pub const PRIVATE_SETTLEMENT_SIDECAR_DEFAULT_MAX_RECORDS_V1: usize = 256;
/// Default canonical byte footprint for one store.
pub const PRIVATE_SETTLEMENT_SIDECAR_DEFAULT_MAX_TOTAL_BYTES_V1: u64 =
    PRIVATE_SETTLEMENT_SIDECAR_MAX_RECORD_BYTES_V1
        * PRIVATE_SETTLEMENT_SIDECAR_DEFAULT_MAX_RECORDS_V1 as u64;
/// Maximum records examined by one finality-reconciliation page.
pub const PRIVATE_SETTLEMENT_RECONCILIATION_MAX_PAGE_RECORDS_V1: usize = 256;

/// Exact staged-lock counts bound by the non-shipping private-settlement
/// sidecar commitment used in adversarial real-process tests.
#[cfg(any(test, feature = "test-network-private-settlement-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Decode, Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::private_settlement::sidecar_store::PrivateSettlementStagedLockCountsV1"
)]
pub struct PrivateSettlementStagedLockCountsV1 {
    /// Reserved opaque pool heads.
    pub pool_heads: u64,
    /// Reserved nullifiers.
    pub nullifiers: u64,
    /// Reserved output commitments.
    pub output_commitments: u64,
    /// Sum of all three reservation-map counts.
    pub total: u64,
}

/// Evidence-only commitment to every staged private-settlement reservation.
///
/// The digest and counts expose no reservation keys. They are compiled only
/// for the authenticated test-network diagnostic and are not a production
/// privacy API.
#[cfg(any(test, feature = "test-network-private-settlement-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateSettlementStagedLockEvidenceV1 {
    /// Domain-separated commitment to canonical reservation maps and counts.
    pub commitment: Hash,
    /// Exact staged-lock count vector committed by `commitment`.
    pub counts: PrivateSettlementStagedLockCountsV1,
}

#[cfg(any(test, feature = "test-network-private-settlement-evidence"))]
const PRIVATE_SETTLEMENT_STAGED_LOCK_EVIDENCE_DOMAIN_V1: &[u8] =
    b"iroha:test-network:private-settlement:staged-lock-evidence:v1\0";

#[cfg(any(test, feature = "test-network-private-settlement-evidence"))]
fn private_settlement_staged_lock_commitment_v1(
    sections: &[(&[u8], &[u8])],
    counts: PrivateSettlementStagedLockCountsV1,
) -> Result<Hash, PrivateSettlementSidecarStoreErrorV1> {
    let counts_bytes = norito::encode_canonical(&counts)
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
    let mut preimage = Vec::with_capacity(
        PRIVATE_SETTLEMENT_STAGED_LOCK_EVIDENCE_DOMAIN_V1.len()
            + counts_bytes.len()
            + sections
                .iter()
                .map(|(label, bytes)| label.len().saturating_add(bytes.len()).saturating_add(16))
                .sum::<usize>(),
    );
    preimage.extend_from_slice(PRIVATE_SETTLEMENT_STAGED_LOCK_EVIDENCE_DOMAIN_V1);
    for (label, bytes) in sections {
        let label_len = u64::try_from(label.len()).expect("static evidence label length fits u64");
        let bytes_len = u64::try_from(bytes.len()).expect("canonical map length fits u64");
        preimage.extend_from_slice(&label_len.to_le_bytes());
        preimage.extend_from_slice(label);
        preimage.extend_from_slice(&bytes_len.to_le_bytes());
        preimage.extend_from_slice(bytes);
    }
    let counts_len = u64::try_from(counts_bytes.len()).expect("canonical count vector fits u64");
    preimage.extend_from_slice(&counts_len.to_le_bytes());
    preimage.extend_from_slice(&counts_bytes);
    Ok(Hash::new(&preimage))
}

#[cfg(test)]
mod staged_lock_evidence_tests {
    use super::*;

    const LABELS: [&[u8]; 3] = [b"pool_heads", b"nullifiers", b"output_commitments"];

    fn counts() -> PrivateSettlementStagedLockCountsV1 {
        PrivateSettlementStagedLockCountsV1 {
            pool_heads: 1,
            nullifiers: 2,
            output_commitments: 3,
            total: 6,
        }
    }

    fn commitment(sections: &[Vec<u8>], counts: PrivateSettlementStagedLockCountsV1) -> Hash {
        let borrowed: Vec<_> = LABELS
            .iter()
            .zip(sections)
            .map(|(label, bytes)| (*label, bytes.as_slice()))
            .collect();
        private_settlement_staged_lock_commitment_v1(&borrowed, counts)
            .expect("fixture evidence encodes")
    }

    #[test]
    fn commitment_changes_for_every_reservation_map() {
        let sections: Vec<_> = (0_u8..3).map(|index| vec![index, index + 1]).collect();
        let baseline = commitment(&sections, counts());
        for index in 0..sections.len() {
            let mut changed = sections.clone();
            changed[index].push(0x5a);
            assert_ne!(
                commitment(&changed, counts()),
                baseline,
                "reservation map {} was not bound",
                String::from_utf8_lossy(LABELS[index])
            );
        }
    }

    #[test]
    fn commitment_changes_for_every_staged_lock_count() {
        let sections: Vec<_> = (0_u8..3).map(|index| vec![index, index + 1]).collect();
        let baseline_counts = counts();
        let baseline = commitment(&sections, baseline_counts);
        for index in 0..4 {
            let mut changed = baseline_counts;
            match index {
                0 => changed.pool_heads += 1,
                1 => changed.nullifiers += 1,
                2 => changed.output_commitments += 1,
                3 => changed.total += 1,
                _ => unreachable!("bounded count mutation index"),
            }
            assert_ne!(
                commitment(&sections, changed),
                baseline,
                "staged-lock count field {index} was not bound"
            );
        }
    }
}

/// Capacity policy for one durable restricted-sidecar store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateSettlementSidecarStoreConfigV1 {
    max_records: usize,
    max_total_bytes: u64,
}

impl PrivateSettlementSidecarStoreConfigV1 {
    /// Construct a bounded store configuration.
    ///
    /// # Errors
    ///
    /// Rejects zero limits or limits above the hard protocol caps.
    pub fn new(
        max_records: usize,
        max_total_bytes: u64,
    ) -> Result<Self, PrivateSettlementSidecarStoreErrorV1> {
        if max_records == 0
            || max_records > PRIVATE_SETTLEMENT_SIDECAR_HARD_MAX_RECORDS_V1
            || max_total_bytes == 0
            || max_total_bytes > PRIVATE_SETTLEMENT_SIDECAR_HARD_MAX_TOTAL_BYTES_V1
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::ConfigurationInvalid);
        }
        Ok(Self {
            max_records,
            max_total_bytes,
        })
    }

    /// Maximum retained record count.
    #[must_use]
    pub const fn max_records(self) -> usize {
        self.max_records
    }

    /// Maximum retained canonical bytes.
    #[must_use]
    pub const fn max_total_bytes(self) -> u64 {
        self.max_total_bytes
    }
}

impl Default for PrivateSettlementSidecarStoreConfigV1 {
    fn default() -> Self {
        Self {
            max_records: PRIVATE_SETTLEMENT_SIDECAR_DEFAULT_MAX_RECORDS_V1,
            max_total_bytes: PRIVATE_SETTLEMENT_SIDECAR_DEFAULT_MAX_TOTAL_BYTES_V1,
        }
    }
}

/// Durable lifecycle of one encrypted restricted sidecar.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::private_settlement::sidecar_store::PrivateSettlementSidecarLifecycleV1"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Decode, Encode)]
pub enum PrivateSettlementSidecarLifecycleV1 {
    /// Authenticated bytes are durable while auditor approvals are collected.
    Collecting,
    /// A canonical threshold of governed auditor approvals is durable.
    Audited,
    /// The exact verified delta and replay reservations are durable.
    Prepared,
    /// The local Commit QC is durable and the global carrier may be submitted.
    CommitCertified,
    /// Global atomic application and receipt publication completed.
    Finalized,
    /// An authoritative abort released the staged lock.
    Aborted,
    /// Height expiry released the staged lock.
    Expired,
}

impl PrivateSettlementSidecarLifecycleV1 {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::Aborted | Self::Expired)
    }

    fn permits(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (
                    Self::Collecting | Self::Audited | Self::Prepared | Self::CommitCertified,
                    Self::Aborted | Self::Expired
                )
            )
    }
}

/// Complete encrypted upload admitted at the restricted DA boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateSettlementRestrictedSidecarV1 {
    /// Exact public bundle manifest.
    pub manifest: AtomicPrivateSettlementV1,
    /// Governed local auditor policy active at the authority context.
    pub policy: PrivateSettlementAuditPolicyV1,
    /// Exact four-validator local committee and aligned proofs of possession.
    pub authority: PrivateSettlementCommitteeAuthorityV1,
    /// Proof, opaque fixed delta, encrypted audit capsule, and DA ticket.
    pub payload: PrivateSettlementLegPayloadV1,
    /// Authoritative global height at which this node accepted the upload.
    pub stored_at_height: u64,
}

impl fmt::Debug for PrivateSettlementRestrictedSidecarV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateSettlementRestrictedSidecarV1")
            .field("bundle_id", &self.manifest.bundle_id)
            .field("leg_ordinal", &self.payload.statement.leg_ordinal)
            .field("route", &self.payload.statement.route)
            .field("stored_at_height", &self.stored_at_height)
            .finish_non_exhaustive()
    }
}

impl PrivateSettlementRestrictedSidecarV1 {
    /// Validate every public, policy, committee, proof-sidecar, and height binding.
    ///
    /// # Errors
    ///
    /// Returns a redacted invalid-sidecar error for any mismatch.
    pub fn validate(&self) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
        self.payload
            .validate_against(&self.manifest, &self.policy)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)?;
        self.authority
            .validate()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)?;
        if self.authority.route != self.payload.statement.route
            || self
                .authority
                .digest()
                .ok()
                .is_none_or(|digest| digest != self.payload.availability.body.authority_digest)
            || self.payload.audit_capsule.aad.authority_digest
                != self.payload.availability.body.authority_digest
            || self.payload.audit_capsule.aad.authority_context_height
                != self.payload.availability.body.authority_context_height
            || self.stored_at_height < self.manifest.authority_context_height
            || self.stored_at_height > self.manifest.expiry_height
            || self
                .authority
                .validators
                .iter()
                .zip(&self.authority.validator_pops)
                .any(|(validator, pop)| {
                    validator.public_key().try_algorithm().ok() != Some(Algorithm::BlsNormal)
                        || iroha_crypto::bls_normal_pop_verify(validator.public_key(), pop).is_err()
                })
            || self.policy.body.auditors.iter().any(|auditor| {
                self.authority
                    .validators
                    .iter()
                    .any(|validator| validator.public_key() == &auditor.signing_key)
            })
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::InvalidSidecar);
        }
        verify_private_settlement_availability_certificate_v1(
            &self.payload.availability,
            &self.authority,
        )?;
        Ok(())
    }

    /// Content address committed by the manifest and DA ticket.
    #[must_use]
    pub fn payload_digest(&self) -> Hash {
        self.payload.availability.body.payload_digest
    }
}

pub(super) fn verify_private_settlement_availability_certificate_v1(
    certificate: &PrivateSettlementSidecarAvailabilityV1,
    authority: &PrivateSettlementCommitteeAuthorityV1,
) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
    certificate
        .validate_shape()
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)?;
    authority
        .validate()
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)?;
    if authority.route != certificate.body.route
        || authority
            .digest()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)?
            != certificate.body.authority_digest
    {
        return Err(PrivateSettlementSidecarStoreErrorV1::InvalidSidecar);
    }
    let mut signer_keys = Vec::with_capacity(3);
    let mut signer_pops = Vec::with_capacity(3);
    for index in 0..authority.validators.len() {
        if certificate.signers_bitmap & (1_u8 << index) == 0 {
            continue;
        }
        let validator = authority
            .validators
            .get(index)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)?;
        let pop = authority
            .validator_pops
            .get(index)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)?;
        signer_keys.push(validator.public_key());
        signer_pops.push(pop.as_slice());
    }
    let preimage = certificate
        .signature_preimage()
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)?;
    iroha_crypto::bls_normal_verify_preaggregated_same_message(
        &preimage,
        &certificate.aggregate_signature,
        &signer_keys,
        &signer_pops,
    )
    .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)
}

/// Least-privilege sidecar view returned to a committee validator.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateSettlementCommitteeSidecarViewV1 {
    /// Exact bundle manifest.
    pub manifest: AtomicPrivateSettlementV1,
    /// Policy used to validate the approval roster and threshold.
    pub policy: PrivateSettlementAuditPolicyV1,
    /// Exact local committee authority.
    pub authority: PrivateSettlementCommitteeAuthorityV1,
    /// Restricted public proof statement.
    pub statement: PrivateSettlementProofStatementV1,
    /// Native zero-knowledge proof bytes.
    pub proof: Vec<u8>,
    /// Opaque fixed-shape private-state delta.
    pub delta: PrivateSettlementDeltaV1,
    /// Canonical governed auditor approvals verified before Prepare.
    pub audit_approvals: Vec<PrivateSettlementAuditApprovalV1>,
    /// Digest of the encrypted capsule, never capsule bytes or plaintext.
    pub audit_capsule_digest: Hash,
    /// Durable availability ticket.
    pub availability: PrivateSettlementSidecarAvailabilityV1,
    /// Current durable lifecycle.
    pub lifecycle: PrivateSettlementSidecarLifecycleV1,
}

impl fmt::Debug for PrivateSettlementCommitteeSidecarViewV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateSettlementCommitteeSidecarViewV1")
            .field("bundle_id", &self.manifest.bundle_id)
            .field("leg_ordinal", &self.statement.leg_ordinal)
            .field("route", &self.statement.route)
            .field("lifecycle", &self.lifecycle)
            .finish_non_exhaustive()
    }
}

/// Complete immutable material consumed only inside the committee verifier.
///
/// Unlike the public committee view, this carries the encrypted capsule so
/// the payload digest and durable availability evidence can be revalidated as
/// one object. The committee service never returns this value to its caller.
pub(super) struct PrivateSettlementCommitteeValidationMaterialV1 {
    /// Exact public bundle manifest.
    pub(super) manifest: AtomicPrivateSettlementV1,
    /// Governed auditor roster and threshold.
    pub(super) policy: PrivateSettlementAuditPolicyV1,
    /// Exact four-validator participant authority.
    pub(super) authority: PrivateSettlementCommitteeAuthorityV1,
    /// Complete immutable encrypted payload used only during validation.
    pub(super) payload: PrivateSettlementLegPayloadV1,
    /// Canonical threshold approval set.
    pub(super) audit_approvals: Vec<PrivateSettlementAuditApprovalV1>,
    /// Fsync-backed evidence for the exact immutable payload.
    pub(super) availability: PrivateSettlementDurableAvailabilityV1,
}

/// Least-privilege encrypted capsule view returned to a governed auditor.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateSettlementAuditorSidecarViewV1 {
    /// Exact bundle manifest used when recomputing private bindings.
    pub manifest: AtomicPrivateSettlementV1,
    /// Exact governed local policy.
    pub policy: PrivateSettlementAuditPolicyV1,
    /// Exact consensus authority used to enforce purpose-separated keys.
    pub authority: PrivateSettlementCommitteeAuthorityV1,
    /// Restricted public proof statement.
    pub statement: PrivateSettlementProofStatementV1,
    /// Opaque fixed-shape private-state delta.
    pub delta: PrivateSettlementDeltaV1,
    /// Padded hybrid-encrypted auditor capsule.
    pub audit_capsule: PrivateSettlementAuditCapsuleV1,
    /// Durable availability ticket.
    pub availability: PrivateSettlementSidecarAvailabilityV1,
    /// Current durable lifecycle.
    pub lifecycle: PrivateSettlementSidecarLifecycleV1,
}

/// Auditor view paired with the governed identity authenticated by its signing key.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateSettlementAuthenticatedAuditorViewV1 {
    /// Governed account identity bound to the authenticated signing key.
    pub auditor_id: AccountId,
    /// Exact current policy that authorized access to this retained capsule.
    pub access_policy: PrivateSettlementAuditPolicyV1,
    /// Least-privilege encrypted capsule view.
    pub view: PrivateSettlementAuditorSidecarViewV1,
}

impl fmt::Debug for PrivateSettlementAuthenticatedAuditorViewV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateSettlementAuthenticatedAuditorViewV1")
            .field("view", &self.view)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PrivateSettlementAuditorSidecarViewV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateSettlementAuditorSidecarViewV1")
            .field("bundle_id", &self.manifest.bundle_id)
            .field("leg_ordinal", &self.statement.leg_ordinal)
            .field("route", &self.statement.route)
            .field("lifecycle", &self.lifecycle)
            .finish_non_exhaustive()
    }
}

/// Outcome of an idempotent encrypted-sidecar upload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateSettlementSidecarStoreOutcomeV1 {
    /// New content was durably stored.
    Stored,
    /// The exact canonical content was already durable.
    AlreadyStored,
}

/// Durable result of collecting one governed auditor approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateSettlementAuditCollectionOutcomeV1 {
    /// Number of distinct canonical approvals now durable.
    pub collected: u8,
    /// Governed threshold copied from the immutable policy.
    pub required: u8,
    /// Whether this call inserted new durable approval material.
    pub newly_recorded: bool,
    /// Whether the exact leg has durably crossed into `Audited`.
    pub audited: bool,
}

/// Allowlisted lifecycle projection for one encrypted sidecar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateSettlementPublicSidecarStatusV1 {
    /// Public bundle identifier.
    pub bundle_id: Hash,
    /// Content address of the exact encrypted leg upload.
    pub payload_digest: Hash,
    /// Canonical leg ordinal.
    pub leg_ordinal: u8,
    /// Public dataspace/lane/incarnation route.
    pub route: PrivateSettlementRouteV1,
    /// Height at which the encrypted sidecar first became durable.
    pub stored_at_height: u64,
    /// Latest durable lifecycle height.
    pub lifecycle_height: u64,
    /// Final global height at which the in-flight leg remains valid.
    pub expiry_height: u64,
    /// Current durable lifecycle.
    pub lifecycle: PrivateSettlementSidecarLifecycleV1,
}

/// Sponsor-only recovery projection for exact durable phase certificates.
///
/// The certificates contain only protocol-public quorum material. The view
/// deliberately excludes proof bytes, capsules, approvals, and every audit
/// plaintext field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateSettlementSponsorPhaseCertificatesV1 {
    /// Public bundle identifier.
    pub bundle_id: Hash,
    /// Content address of the exact encrypted leg.
    pub payload_digest: Hash,
    /// Canonical participant ordinal.
    pub leg_ordinal: u8,
    /// Current monotonic local lifecycle.
    pub lifecycle: PrivateSettlementSidecarLifecycleV1,
    /// Exact locally durable Prepare QC, when present.
    pub prepare_certificate: Option<PrivateSettlementPhaseCertificateV1>,
    /// Exact locally durable Commit QC, when present.
    pub commit_certificate: Option<PrivateSettlementPhaseCertificateV1>,
}

/// Allowlisted aggregate lifecycle projection for one public bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateSettlementPublicBundleStatusV1 {
    /// Exact public bundle manifest shared by every local leg.
    pub manifest: AtomicPrivateSettlementV1,
    /// Weakest durable all-participant phase, or a terminal state.
    pub lifecycle: PrivateSettlementSidecarLifecycleV1,
    /// Latest local height contributing to this projection.
    pub lifecycle_height: u64,
    /// Number of canonical participant legs currently durable locally.
    pub durable_legs: u8,
}

/// Allowlisted nonterminal record selected for one bounded reconciliation pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateSettlementReconciliationCandidateV1 {
    /// Content address of the encrypted local leg.
    pub payload_digest: Hash,
    /// Opaque bundle identifier used for immutable WSV terminal lookups.
    pub bundle_id: Hash,
    /// Manifest expiry height used for marker-free authoritative expiry.
    pub expiry_height: u64,
    /// Current durable local lifecycle.
    pub lifecycle: PrivateSettlementSidecarLifecycleV1,
}

/// One deterministic bounded page of nonterminal local records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateSettlementReconciliationPageV1 {
    /// Allowlisted candidates encountered in this page.
    pub candidates: Vec<PrivateSettlementReconciliationCandidateV1>,
    /// Exclusive content-address cursor for the next page, if any records remain.
    pub next_cursor: Option<Hash>,
}

/// Redacted result of reconciling one local record against immutable global state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateSettlementReconciliationOutcomeV1 {
    /// No terminal marker exists and the manifest has not expired.
    Pending,
    /// An exact global atomic receipt is durable locally.
    Finalized,
    /// An exact non-expiry abort marker is durable locally.
    Aborted,
    /// An exact expiry marker or authoritative height expiry is durable locally.
    Expired,
}

/// Redacted restricted-sidecar persistence or access failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PrivateSettlementSidecarStoreErrorV1 {
    /// Configured capacity is zero or exceeds a hard bound.
    #[error("private-settlement sidecar store configuration is invalid")]
    ConfigurationInvalid,
    /// Upload content or one of its cross-object bindings is invalid.
    #[error("private-settlement restricted sidecar is invalid")]
    InvalidSidecar,
    /// A record exceeds configured count or byte capacity.
    #[error("private-settlement sidecar store capacity is exhausted")]
    CapacityExceeded,
    /// Same content address or bundle leg was presented with different material.
    #[error("private-settlement restricted sidecar conflicts with durable content")]
    Conflict,
    /// Missing and unauthorized fetches intentionally share this response.
    #[error("private-settlement restricted sidecar is unavailable")]
    Unavailable,
    /// Requested lifecycle transition is not monotonic or height-valid.
    #[error("private-settlement sidecar lifecycle transition is invalid")]
    InvalidTransition,
    /// A second process or handle already owns this store directory.
    #[error("private-settlement sidecar store is already open")]
    StoreAlreadyOpen,
    /// Durable bytes, names, ownership, or filesystem identity are invalid.
    #[error("private-settlement sidecar store is corrupt")]
    Corrupt,
    /// A local persistence operation failed.
    #[error("private-settlement sidecar persistence failed")]
    Backend,
    /// The production file store requires Unix ownership and no-follow controls.
    #[error("private-settlement sidecar store is unsupported on this platform")]
    UnsupportedPlatform,
}

#[derive(Clone, PartialEq, Eq, Decode, Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::private_settlement::sidecar_store::DurablePrivateSettlementSidecarV1"
)]
struct DurablePrivateSettlementSidecarV1 {
    magic: [u8; 4],
    version: u8,
    sidecar: PrivateSettlementRestrictedSidecarWireV1,
    lifecycle: PrivateSettlementSidecarLifecycleV1,
    lifecycle_height: u64,
    audit_approvals: Vec<PrivateSettlementAuditApprovalV1>,
    audit_approval_validation_height: Option<u64>,
    verified_leg: Option<ValidatedPrivateSettlementLegV1>,
    prepare_certificate: Option<PrivateSettlementPhaseCertificateV1>,
    commit_certificate: Option<PrivateSettlementPhaseCertificateV1>,
    terminal_evidence_digest: Option<Hash>,
    lifecycle_evidence_digest: Option<Hash>,
}

#[derive(Clone, PartialEq, Eq, Decode, Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::private_settlement::sidecar_store::PrivateSettlementRestrictedSidecarWireV1"
)]
struct PrivateSettlementRestrictedSidecarWireV1 {
    manifest: AtomicPrivateSettlementV1,
    policy: PrivateSettlementAuditPolicyV1,
    authority: PrivateSettlementCommitteeAuthorityV1,
    payload: PrivateSettlementLegPayloadV1,
    stored_at_height: u64,
}

#[derive(Clone, PartialEq, Eq, Decode, Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::private_settlement::sidecar_store::DurablePrivateSettlementProvisionalSidecarV1"
)]
struct DurablePrivateSettlementProvisionalSidecarV1 {
    magic: [u8; 4],
    version: u8,
    material: PrivateSettlementProvisionalLegMaterialV1,
    stored_at_height: u64,
}

impl DurablePrivateSettlementProvisionalSidecarV1 {
    fn new(material: PrivateSettlementProvisionalLegMaterialV1, stored_at_height: u64) -> Self {
        Self {
            magic: PROVISIONAL_RECORD_MAGIC_V1,
            version: PROVISIONAL_RECORD_VERSION_V1,
            material,
            stored_at_height,
        }
    }

    fn validate(&self) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
        if self.magic != PROVISIONAL_RECORD_MAGIC_V1
            || self.version != PROVISIONAL_RECORD_VERSION_V1
            || self.stored_at_height < self.material.manifest.authority_context_height
            || self.stored_at_height > self.material.manifest.expiry_height
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
        self.material
            .validate()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        validate_provisional_authority_cryptography_v1(&self.material.committee_authority)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)
    }

    fn payload_digest(&self) -> Hash {
        self.material.availability_body.payload_digest
    }

    fn leg_key(&self) -> (Hash, u8) {
        (
            self.material.manifest.bundle_id,
            self.material.statement.leg_ordinal,
        )
    }
}

impl From<PrivateSettlementRestrictedSidecarV1> for PrivateSettlementRestrictedSidecarWireV1 {
    fn from(value: PrivateSettlementRestrictedSidecarV1) -> Self {
        Self {
            manifest: value.manifest,
            policy: value.policy,
            authority: value.authority,
            payload: value.payload,
            stored_at_height: value.stored_at_height,
        }
    }
}

impl From<PrivateSettlementRestrictedSidecarWireV1> for PrivateSettlementRestrictedSidecarV1 {
    fn from(value: PrivateSettlementRestrictedSidecarWireV1) -> Self {
        Self {
            manifest: value.manifest,
            policy: value.policy,
            authority: value.authority,
            payload: value.payload,
            stored_at_height: value.stored_at_height,
        }
    }
}

impl DurablePrivateSettlementSidecarV1 {
    fn new(sidecar: PrivateSettlementRestrictedSidecarV1) -> Self {
        let lifecycle_height = sidecar.stored_at_height;
        Self {
            magic: SIDECAR_RECORD_MAGIC_V1,
            version: SIDECAR_RECORD_VERSION_V1,
            sidecar: sidecar.into(),
            lifecycle: PrivateSettlementSidecarLifecycleV1::Collecting,
            lifecycle_height,
            audit_approvals: Vec::new(),
            audit_approval_validation_height: None,
            verified_leg: None,
            prepare_certificate: None,
            commit_certificate: None,
            terminal_evidence_digest: None,
            lifecycle_evidence_digest: None,
        }
    }

    fn validate(&self) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
        if self.magic != SIDECAR_RECORD_MAGIC_V1
            || self.version != SIDECAR_RECORD_VERSION_V1
            || self.lifecycle_height < self.sidecar.stored_at_height
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
        let sidecar = PrivateSettlementRestrictedSidecarV1 {
            manifest: self.sidecar.manifest.clone(),
            policy: self.sidecar.policy.clone(),
            authority: self.sidecar.authority.clone(),
            payload: self.sidecar.payload.clone(),
            stored_at_height: self.sidecar.stored_at_height,
        };
        sidecar
            .validate()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        if self.lifecycle == PrivateSettlementSidecarLifecycleV1::Expired
            && self.lifecycle_height <= self.sidecar.manifest.expiry_height
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }

        let approval_count = self.audit_approvals.len();
        let required_approvals = usize::from(self.sidecar.policy.body.min_approvals);
        let threshold_met = approval_count >= required_approvals;
        let approval_validation_height =
            match (approval_count, self.audit_approval_validation_height) {
                (0, None) => self.sidecar.stored_at_height,
                (1.., Some(height)) => height,
                _ => return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt),
            };
        if approval_validation_height < self.sidecar.stored_at_height
            || approval_validation_height > self.sidecar.manifest.expiry_height
            || approval_validation_height > self.lifecycle_height
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
        let mut previous_auditor = None;
        for approval in &self.audit_approvals {
            validate_private_settlement_audit_approval_v1(
                approval,
                &self.sidecar.policy,
                &self.sidecar.payload,
                approval_validation_height,
            )
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
            if previous_auditor
                .as_ref()
                .is_some_and(|auditor| auditor >= &approval.body.auditor_id)
            {
                return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
            }
            previous_auditor = Some(approval.body.auditor_id.clone());
        }
        if threshold_met {
            validate_private_settlement_audit_approvals_v1(
                &self.audit_approvals,
                &self.sidecar.policy,
                &self.sidecar.payload,
                approval_validation_height,
            )
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        }

        if let Some(verified) = self.verified_leg.as_ref() {
            let availability = durable_availability_evidence_for_wire_v1(&self.sidecar)?;
            verified
                .validate_against_payload(
                    &self.sidecar.manifest,
                    &self.sidecar.payload,
                    availability.evidence_digest(),
                )
                .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
            verified
                .validate_against_approvals(&self.audit_approvals)
                .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
            if self.lifecycle_evidence_digest.is_none_or(|digest| {
                digest == Hash::prehashed([0; Hash::LENGTH])
                    || digest != verified.verification_digest()
            }) {
                return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
            }
        } else if self.lifecycle_evidence_digest.is_some() {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }

        let validate_certificate = |certificate: &PrivateSettlementPhaseCertificateV1,
                                    phase: PrivateSettlementPhaseV1|
         -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
            let expected = private_settlement_phase_body_v1(
                &self.sidecar.manifest,
                &self.sidecar.payload.delta,
                &self.sidecar.authority,
                phase,
                match phase {
                    PrivateSettlementPhaseV1::Prepare => {
                        private_settlement_reserved_prepared_bundle_digest_v1()
                    }
                    PrivateSettlementPhaseV1::Commit => certificate.body.prepared_bundle_digest,
                },
            )
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
            if certificate.body != expected {
                return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
            }
            verify_private_settlement_phase_certificate_v1(
                certificate,
                self.sidecar.payload.statement.leg_ordinal,
                &self.sidecar.authority,
            )
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)
        };
        if let Some(prepare) = self.prepare_certificate.as_ref() {
            validate_certificate(prepare, PrivateSettlementPhaseV1::Prepare)?;
        }
        if let Some(commit) = self.commit_certificate.as_ref() {
            validate_certificate(commit, PrivateSettlementPhaseV1::Commit)?;
        }

        let prefix_is_consistent = self.verified_leg.as_ref().is_none_or(|_| threshold_met)
            && self
                .prepare_certificate
                .as_ref()
                .is_none_or(|_| self.verified_leg.is_some())
            && self
                .commit_certificate
                .as_ref()
                .is_none_or(|_| self.prepare_certificate.is_some());
        let exact_state_is_consistent = match self.lifecycle {
            PrivateSettlementSidecarLifecycleV1::Collecting => {
                !threshold_met
                    && self.verified_leg.is_none()
                    && self.prepare_certificate.is_none()
                    && self.commit_certificate.is_none()
                    && self.terminal_evidence_digest.is_none()
            }
            PrivateSettlementSidecarLifecycleV1::Audited => {
                threshold_met
                    && self.verified_leg.is_none()
                    && self.prepare_certificate.is_none()
                    && self.commit_certificate.is_none()
                    && self.terminal_evidence_digest.is_none()
            }
            PrivateSettlementSidecarLifecycleV1::Prepared => {
                threshold_met
                    && self.verified_leg.is_some()
                    && self.commit_certificate.is_none()
                    && self.terminal_evidence_digest.is_none()
            }
            PrivateSettlementSidecarLifecycleV1::CommitCertified => {
                threshold_met
                    && self.verified_leg.is_some()
                    && self.prepare_certificate.is_some()
                    && self.commit_certificate.is_some()
                    && self.terminal_evidence_digest.is_none()
            }
            PrivateSettlementSidecarLifecycleV1::Finalized => {
                prefix_is_consistent
                    && self
                        .terminal_evidence_digest
                        .is_some_and(|digest| digest != Hash::prehashed([0; Hash::LENGTH]))
            }
            PrivateSettlementSidecarLifecycleV1::Aborted
            | PrivateSettlementSidecarLifecycleV1::Expired => {
                prefix_is_consistent
                    && self
                        .terminal_evidence_digest
                        .is_some_and(|digest| digest != Hash::prehashed([0; Hash::LENGTH]))
            }
        };
        if !prefix_is_consistent || !exact_state_is_consistent {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
        Ok(())
    }

    fn payload_digest(&self) -> Hash {
        self.sidecar.payload.availability.body.payload_digest
    }
}

#[derive(Clone, Debug)]
struct IndexedPrivateSettlementSidecarV1 {
    canonical_bytes: u64,
    bundle_id: Hash,
    leg_ordinal: u8,
    expiry_height: u64,
    retention_until_height: u64,
    stored_at_height: u64,
    lifecycle: PrivateSettlementSidecarLifecycleV1,
    lifecycle_height: u64,
    reservations: Option<PrivateSettlementReservationKeysV1>,
}

#[derive(Clone, Debug)]
struct IndexedPrivateSettlementProvisionalSidecarV1 {
    canonical_bytes: u64,
    bundle_id: Hash,
    leg_ordinal: u8,
    retention_until_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PrivateSettlementReservationKeysV1 {
    pool_head: (
        PrivateSettlementRouteV1,
        PrivacyPoolIdV1,
        u64,
        PrivacyRootV1,
    ),
    nullifiers: Vec<(
        PrivateSettlementRouteV1,
        PrivacyPoolIdV1,
        PrivacyNullifierV1,
    )>,
    output_commitments: Vec<(
        PrivateSettlementRouteV1,
        PrivacyPoolIdV1,
        PrivacyCommitmentV1,
    )>,
}

#[derive(Debug)]
struct SidecarStoreStateV1 {
    index: BTreeMap<Hash, IndexedPrivateSettlementSidecarV1>,
    by_leg: BTreeMap<(Hash, u8), Hash>,
    provisional_index: BTreeMap<Hash, IndexedPrivateSettlementProvisionalSidecarV1>,
    provisional_by_leg: BTreeMap<(Hash, u8), Hash>,
    pool_reservations: BTreeMap<
        (
            PrivateSettlementRouteV1,
            PrivacyPoolIdV1,
            u64,
            PrivacyRootV1,
        ),
        Hash,
    >,
    nullifier_reservations: BTreeMap<
        (
            PrivateSettlementRouteV1,
            PrivacyPoolIdV1,
            PrivacyNullifierV1,
        ),
        Hash,
    >,
    output_reservations: BTreeMap<
        (
            PrivateSettlementRouteV1,
            PrivacyPoolIdV1,
            PrivacyCommitmentV1,
        ),
        Hash,
    >,
    canonical_bytes: u64,
    poisoned: bool,
}

#[derive(Debug)]
struct SidecarStoreDirectoryLeaseV1 {
    canonical_root: PathBuf,
}

impl Drop for SidecarStoreDirectoryLeaseV1 {
    fn drop(&mut self) {
        if let Ok(mut open_roots) = open_sidecar_store_roots_v1().lock() {
            open_roots.remove(&self.canonical_root);
        }
    }
}

/// Atomic owner-only file store for encrypted restricted sidecars.
///
/// One process-local lease and one held Unix advisory lock enforce a single
/// writer. Open validates every record before the handle becomes available.
/// Never place the directory or its ancestors in an attacker-writable path.
pub struct PrivateSettlementFileSidecarStoreV1 {
    root: PathBuf,
    temp_root: PathBuf,
    config: PrivateSettlementSidecarStoreConfigV1,
    state: Mutex<SidecarStoreStateV1>,
    _lease: SidecarStoreDirectoryLeaseV1,
    _writer_lock: File,
}

impl fmt::Debug for PrivateSettlementFileSidecarStoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateSettlementFileSidecarStoreV1")
            .field("root", &self.root)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl PrivateSettlementFileSidecarStoreV1 {
    /// Open or create an exclusively owned durable store.
    ///
    /// # Errors
    ///
    /// Rejects unsupported platforms, concurrent openers, permissive ownership,
    /// unknown entries, corrupt/non-canonical records, and capacity violations.
    pub fn open(
        root: impl AsRef<Path>,
        config: PrivateSettlementSidecarStoreConfigV1,
    ) -> Result<Self, PrivateSettlementSidecarStoreErrorV1> {
        #[cfg(not(unix))]
        {
            let _ = (root, config);
            return Err(PrivateSettlementSidecarStoreErrorV1::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            let requested_root = root.as_ref();
            if requested_root.as_os_str().is_empty() {
                return Err(PrivateSettlementSidecarStoreErrorV1::ConfigurationInvalid);
            }
            ensure_owner_directory_v1(requested_root)?;
            let canonical_root = fs::canonicalize(requested_root)
                .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
            let lease = acquire_sidecar_store_lease_v1(canonical_root.clone())?;
            let writer_lock = acquire_sidecar_store_writer_lock_v1(&canonical_root)?;
            let temp_root = canonical_root.join(SIDECAR_TEMP_DIRECTORY_V1);
            ensure_owner_directory_v1(&temp_root)?;
            clean_stale_temp_files_v1(&temp_root)?;
            let state = load_file_store_v1(&canonical_root, config)?;
            Ok(Self {
                root: canonical_root,
                temp_root,
                config,
                state: Mutex::new(state),
                _lease: lease,
                _writer_lock: writer_lock,
            })
        }
    }

    /// Canonical owner-only store directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Commit every staged reservation for a test-network atomicity
    /// observation without exposing any reservation key.
    ///
    /// # Errors
    ///
    /// Fails closed when the store is poisoned, its lock is unavailable, or
    /// canonical encoding fails. Shipping builds do not compile this method.
    #[cfg(any(test, feature = "test-network-private-settlement-evidence"))]
    pub fn staged_lock_evidence_v1(
        &self,
    ) -> Result<PrivateSettlementStagedLockEvidenceV1, PrivateSettlementSidecarStoreErrorV1> {
        let state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        let pool_heads = norito::encode_canonical(&state.pool_reservations)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        let nullifiers = norito::encode_canonical(&state.nullifier_reservations)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        let output_commitments = norito::encode_canonical(&state.output_reservations)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        let pool_head_count = u64::try_from(state.pool_reservations.len())
            .expect("private-settlement pool reservation count fits u64");
        let nullifier_count = u64::try_from(state.nullifier_reservations.len())
            .expect("private-settlement nullifier reservation count fits u64");
        let output_count = u64::try_from(state.output_reservations.len())
            .expect("private-settlement output reservation count fits u64");
        let counts = PrivateSettlementStagedLockCountsV1 {
            pool_heads: pool_head_count,
            nullifiers: nullifier_count,
            output_commitments: output_count,
            total: pool_head_count
                .checked_add(nullifier_count)
                .and_then(|count| count.checked_add(output_count))
                .expect("private-settlement staged-lock count fits u64"),
        };
        let commitment = private_settlement_staged_lock_commitment_v1(
            &[
                (b"pool_heads", &pool_heads),
                (b"nullifiers", &nullifiers),
                (b"output_commitments", &output_commitments),
            ],
            counts,
        )?;
        Ok(PrivateSettlementStagedLockEvidenceV1 { commitment, counts })
    }

    /// Durably persist exact pre-certification material before issuing a share.
    ///
    /// Exact retries are idempotent. The durable record is fsynced and its
    /// directory entry committed before this method returns success; callers
    /// must not sign the availability body before that point.
    ///
    /// # Errors
    ///
    /// Returns a redacted validation, conflict, capacity, corruption, or
    /// persistence error.
    pub(super) fn store_provisional(
        &self,
        material: PrivateSettlementProvisionalLegMaterialV1,
        stored_at_height: u64,
    ) -> Result<PrivateSettlementSidecarStoreOutcomeV1, PrivateSettlementSidecarStoreErrorV1> {
        material
            .validate()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)?;
        validate_provisional_authority_cryptography_v1(&material.committee_authority)?;
        if stored_at_height < material.manifest.authority_context_height
            || stored_at_height > material.manifest.expiry_height
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::InvalidSidecar);
        }
        let candidate =
            DurablePrivateSettlementProvisionalSidecarV1::new(material, stored_at_height);
        candidate
            .validate()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)?;
        let digest = candidate.payload_digest();
        let leg_key = candidate.leg_key();
        let encoded = norito::encode_canonical(&candidate)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)?;
        let encoded_len = u64::try_from(encoded.len())
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::CapacityExceeded)?;
        if encoded_len == 0 || encoded_len > PRIVATE_SETTLEMENT_SIDECAR_MAX_RECORD_BYTES_V1 {
            return Err(PrivateSettlementSidecarStoreErrorV1::CapacityExceeded);
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        if state.provisional_index.contains_key(&digest) {
            let durable = self.read_provisional_record_v1(digest)?;
            return if durable.material == candidate.material {
                Ok(PrivateSettlementSidecarStoreOutcomeV1::AlreadyStored)
            } else {
                Err(PrivateSettlementSidecarStoreErrorV1::Conflict)
            };
        }
        if state.index.contains_key(&digest) {
            let durable = self.read_record_v1(digest)?;
            return if final_matches_provisional_v1(&durable.sidecar, &candidate) {
                Ok(PrivateSettlementSidecarStoreOutcomeV1::AlreadyStored)
            } else {
                Err(PrivateSettlementSidecarStoreErrorV1::Conflict)
            };
        }
        if state.provisional_by_leg.contains_key(&leg_key) || state.by_leg.contains_key(&leg_key) {
            return Err(PrivateSettlementSidecarStoreErrorV1::Conflict);
        }
        state
            .index
            .len()
            .checked_add(state.provisional_index.len())
            .and_then(|count| count.checked_add(1))
            .filter(|count| *count <= self.config.max_records)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::CapacityExceeded)?;
        let next_bytes = state
            .canonical_bytes
            .checked_add(encoded_len)
            .filter(|bytes| *bytes <= self.config.max_total_bytes)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::CapacityExceeded)?;
        match self.persist_provisional_record_v1(digest, &encoded) {
            Ok(()) => {}
            Err(failure) if failure.committed => {
                insert_provisional_index_v1(&mut state, &candidate, encoded_len)?;
                state.canonical_bytes = next_bytes;
                state.poisoned = true;
                return Err(PrivateSettlementSidecarStoreErrorV1::Backend);
            }
            Err(_) => return Err(PrivateSettlementSidecarStoreErrorV1::Backend),
        }
        insert_provisional_index_v1(&mut state, &candidate, encoded_len)?;
        state.canonical_bytes = next_bytes;
        Ok(PrivateSettlementSidecarStoreOutcomeV1::Stored)
    }

    /// Promote fsync-backed provisional material to a certified sidecar.
    ///
    /// The final manifest may differ only by replacing every reserved-zero
    /// availability digest with its exact certificate digest. This leg's
    /// certificate body and all restricted bytes must match the provisional
    /// record byte-for-byte.
    ///
    /// # Errors
    ///
    /// Returns unavailable when no provisional material exists, conflict for
    /// substitution, or a redacted persistence/capacity failure.
    pub fn promote(
        &self,
        mut sidecar: PrivateSettlementRestrictedSidecarV1,
    ) -> Result<PrivateSettlementSidecarStoreOutcomeV1, PrivateSettlementSidecarStoreErrorV1> {
        sidecar.validate()?;
        let digest = sidecar.payload_digest();
        let leg_key = (
            sidecar.manifest.bundle_id,
            sidecar.payload.statement.leg_ordinal,
        );
        let mut state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        if state.index.contains_key(&digest) {
            let durable = self.read_record_v1(digest)?;
            return if same_restricted_material_v1(
                &durable.sidecar,
                &PrivateSettlementRestrictedSidecarWireV1::from(sidecar),
            ) {
                Ok(PrivateSettlementSidecarStoreOutcomeV1::AlreadyStored)
            } else {
                Err(PrivateSettlementSidecarStoreErrorV1::Conflict)
            };
        }
        let provisional_metadata = state
            .provisional_index
            .get(&digest)
            .cloned()
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Unavailable)?;
        if state.provisional_by_leg.get(&leg_key) != Some(&digest) {
            return Err(PrivateSettlementSidecarStoreErrorV1::Conflict);
        }
        let provisional = self.read_provisional_record_v1(digest)?;
        sidecar.stored_at_height = provisional.stored_at_height;
        let candidate = DurablePrivateSettlementSidecarV1::new(sidecar);
        candidate.validate()?;
        if !final_matches_provisional_v1(&candidate.sidecar, &provisional) {
            return Err(PrivateSettlementSidecarStoreErrorV1::Conflict);
        }
        let encoded = norito::encode_canonical(&candidate)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)?;
        let encoded_len = u64::try_from(encoded.len())
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::CapacityExceeded)?;
        if encoded_len == 0 || encoded_len > PRIVATE_SETTLEMENT_SIDECAR_MAX_RECORD_BYTES_V1 {
            return Err(PrivateSettlementSidecarStoreErrorV1::CapacityExceeded);
        }
        let next_bytes = state
            .canonical_bytes
            .checked_sub(provisional_metadata.canonical_bytes)
            .and_then(|bytes| bytes.checked_add(encoded_len))
            .filter(|bytes| *bytes <= self.config.max_total_bytes)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::CapacityExceeded)?;
        if self.persist_record_v1(digest, &encoded, false).is_err() {
            state.poisoned = self.root.join(sidecar_file_name_v1(digest)).exists();
            return Err(PrivateSettlementSidecarStoreErrorV1::Backend);
        }
        if self.remove_provisional_record_v1(digest).is_err() {
            state.poisoned = true;
            return Err(PrivateSettlementSidecarStoreErrorV1::Backend);
        }
        remove_provisional_index_v1(&mut state, digest, &provisional_metadata)?;
        insert_index_v1(&mut state, &candidate, encoded_len)?;
        state.canonical_bytes = next_bytes;
        Ok(PrivateSettlementSidecarStoreOutcomeV1::Stored)
    }

    /// Durably store one fully validated encrypted sidecar.
    ///
    /// Exact retries are idempotent. Any same-digest or same-bundle-leg
    /// substitution is rejected before mutation.
    ///
    /// # Errors
    ///
    /// Returns a typed validation, conflict, capacity, corruption, or backend error.
    #[cfg(test)]
    pub(crate) fn store(
        &self,
        sidecar: PrivateSettlementRestrictedSidecarV1,
    ) -> Result<PrivateSettlementSidecarStoreOutcomeV1, PrivateSettlementSidecarStoreErrorV1> {
        sidecar.validate()?;
        let digest = sidecar.payload_digest();
        let leg_key = (
            sidecar.manifest.bundle_id,
            sidecar.payload.statement.leg_ordinal,
        );
        let candidate = DurablePrivateSettlementSidecarV1::new(sidecar);
        candidate.validate()?;
        let encoded = norito::encode_canonical(&candidate)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)?;
        let encoded_len = u64::try_from(encoded.len())
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::CapacityExceeded)?;
        if encoded_len == 0 || encoded_len > PRIVATE_SETTLEMENT_SIDECAR_MAX_RECORD_BYTES_V1 {
            return Err(PrivateSettlementSidecarStoreErrorV1::CapacityExceeded);
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        if state.index.contains_key(&digest) {
            let durable = self.read_record_v1(digest)?;
            return if same_restricted_material_v1(&durable.sidecar, &candidate.sidecar) {
                Ok(PrivateSettlementSidecarStoreOutcomeV1::AlreadyStored)
            } else {
                Err(PrivateSettlementSidecarStoreErrorV1::Conflict)
            };
        }
        if state.by_leg.contains_key(&leg_key) {
            return Err(PrivateSettlementSidecarStoreErrorV1::Conflict);
        }
        state
            .index
            .len()
            .checked_add(state.provisional_index.len())
            .and_then(|count| count.checked_add(1))
            .filter(|count| *count <= self.config.max_records)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::CapacityExceeded)?;
        let next_bytes = state
            .canonical_bytes
            .checked_add(encoded_len)
            .filter(|bytes| *bytes <= self.config.max_total_bytes)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::CapacityExceeded)?;
        match self.persist_record_v1(digest, &encoded, false) {
            Ok(()) => {}
            Err(failure) if failure.committed => {
                insert_index_v1(&mut state, &candidate, encoded_len)?;
                state.canonical_bytes = next_bytes;
                state.poisoned = true;
                return Err(PrivateSettlementSidecarStoreErrorV1::Backend);
            }
            Err(_) => return Err(PrivateSettlementSidecarStoreErrorV1::Backend),
        }
        insert_index_v1(&mut state, &candidate, encoded_len)?;
        state.canonical_bytes = next_bytes;
        Ok(PrivateSettlementSidecarStoreOutcomeV1::Stored)
    }

    /// Test-only direct access to fsync-backed Prepare evidence.
    ///
    /// This capability is crate-private: callers cannot manufacture it from a
    /// digest, byte count, or claimed filesystem write.  The full persisted
    /// immutable record is decoded and validated before evidence is returned.
    #[cfg(test)]
    pub(crate) fn durable_availability_evidence(
        &self,
        digest: Hash,
    ) -> Result<PrivateSettlementDurableAvailabilityV1, PrivateSettlementSidecarStoreErrorV1> {
        let state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        if !state.index.contains_key(&digest) {
            return Err(PrivateSettlementSidecarStoreErrorV1::Unavailable);
        }
        let durable = self.read_record_v1(digest)?;
        durable.validate()?;
        durable_availability_evidence_for_wire_v1(&durable.sidecar)
    }

    /// Read the allowlisted public lifecycle projection for one encrypted leg.
    ///
    /// Missing and retention-expired records deliberately share the same
    /// unavailable result.  This projection never contains proof bytes,
    /// capsule bytes, approvals, accounts other than the already-public bundle
    /// sponsor, assets, amounts, memos, or note openings.
    ///
    /// # Errors
    ///
    /// Returns unavailable or a local corruption/backend error.
    pub fn public_status(
        &self,
        digest: Hash,
        authoritative_height: u64,
    ) -> Result<PrivateSettlementPublicSidecarStatusV1, PrivateSettlementSidecarStoreErrorV1> {
        let state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        let metadata = state
            .index
            .get(&digest)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Unavailable)?;
        if authoritative_height > metadata.retention_until_height {
            return Err(PrivateSettlementSidecarStoreErrorV1::Unavailable);
        }
        let durable = self.read_record_v1(digest)?;
        Ok(PrivateSettlementPublicSidecarStatusV1 {
            bundle_id: durable.sidecar.manifest.bundle_id,
            payload_digest: digest,
            leg_ordinal: durable.sidecar.payload.statement.leg_ordinal,
            route: durable.sidecar.payload.statement.route,
            stored_at_height: durable.sidecar.stored_at_height,
            lifecycle_height: durable.lifecycle_height,
            expiry_height: durable.sidecar.manifest.expiry_height,
            lifecycle: durable.lifecycle,
        })
    }

    /// Recover exact durable phase certificates as the immutable bundle sponsor.
    ///
    /// Unknown, wrong-sponsor, and retention-expired records deliberately share
    /// the same unavailable result. The full owner-only record is decoded and
    /// validated before any quorum material is returned.
    ///
    /// # Errors
    ///
    /// Returns unavailable or a local corruption/backend error.
    pub fn sponsor_phase_certificates(
        &self,
        digest: Hash,
        sponsor: &AccountId,
        authoritative_height: u64,
    ) -> Result<PrivateSettlementSponsorPhaseCertificatesV1, PrivateSettlementSidecarStoreErrorV1>
    {
        let state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        let metadata = state
            .index
            .get(&digest)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Unavailable)?;
        if authoritative_height > metadata.retention_until_height {
            return Err(PrivateSettlementSidecarStoreErrorV1::Unavailable);
        }
        let durable = self.read_record_v1(digest)?;
        if &durable.sidecar.manifest.sponsor != sponsor {
            return Err(PrivateSettlementSidecarStoreErrorV1::Unavailable);
        }
        Ok(PrivateSettlementSponsorPhaseCertificatesV1 {
            bundle_id: durable.sidecar.manifest.bundle_id,
            payload_digest: digest,
            leg_ordinal: durable.sidecar.payload.statement.leg_ordinal,
            lifecycle: durable.lifecycle,
            prepare_certificate: durable.prepare_certificate,
            commit_certificate: durable.commit_certificate,
        })
    }

    /// Read a public lifecycle projection of this node's retained bundle legs.
    ///
    /// The result contains only the already-public manifest and aggregate phase
    /// counters. It never contains proof bytes, capsules, approvals, or audit
    /// plaintext. Missing and internally inconsistent bundles fail closed.
    ///
    /// # Errors
    ///
    /// Returns unavailable for an unknown bundle and corruption for conflicting
    /// local manifests or index keys that do not bind the exact durable manifest leg.
    /// Sparse local ordinal subsets are valid; all-leg states require every leg.
    pub fn public_bundle_status(
        &self,
        bundle_id: Hash,
        authoritative_height: u64,
    ) -> Result<PrivateSettlementPublicBundleStatusV1, PrivateSettlementSidecarStoreErrorV1> {
        let state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        let mut digests = state
            .by_leg
            .iter()
            .filter_map(|((candidate_bundle, ordinal), digest)| {
                (*candidate_bundle == bundle_id).then_some((*ordinal, *digest))
            })
            .collect::<Vec<_>>();
        if digests.is_empty() {
            return Err(PrivateSettlementSidecarStoreErrorV1::Unavailable);
        }
        digests.sort_unstable_by_key(|(ordinal, _)| *ordinal);

        let mut manifest = None;
        let mut lifecycles = Vec::with_capacity(digests.len());
        let mut lifecycle_height = 0_u64;
        for (ordinal, digest) in digests {
            let metadata = state
                .index
                .get(&digest)
                .ok_or(PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
            let durable = self.read_record_v1(digest)?;
            durable.validate()?;
            let leg = durable
                .sidecar
                .manifest
                .legs
                .get(usize::from(ordinal))
                .ok_or(PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
            if metadata.bundle_id != bundle_id
                || metadata.leg_ordinal != ordinal
                || durable.sidecar.manifest.bundle_id != bundle_id
                || durable.sidecar.payload.statement.leg_ordinal != ordinal
                || leg.ordinal != ordinal
                || leg.payload_digest != digest
            {
                return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
            }
            match &manifest {
                None => manifest = Some(durable.sidecar.manifest.clone()),
                Some(expected) if expected == &durable.sidecar.manifest => {}
                Some(_) => return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt),
            }
            lifecycle_height = lifecycle_height.max(metadata.lifecycle_height);
            lifecycles.push(metadata.lifecycle);
        }
        let manifest = manifest.ok_or(PrivateSettlementSidecarStoreErrorV1::Unavailable)?;
        let complete = lifecycles.len() == manifest.legs.len();
        let lifecycle = if authoritative_height > manifest.expiry_height
            || lifecycles.contains(&PrivateSettlementSidecarLifecycleV1::Expired)
        {
            PrivateSettlementSidecarLifecycleV1::Expired
        } else if lifecycles.contains(&PrivateSettlementSidecarLifecycleV1::Aborted) {
            PrivateSettlementSidecarLifecycleV1::Aborted
        } else if complete
            && lifecycles
                .iter()
                .all(|state| *state == PrivateSettlementSidecarLifecycleV1::Finalized)
        {
            PrivateSettlementSidecarLifecycleV1::Finalized
        } else if complete
            && lifecycles.iter().all(|state| {
                matches!(
                    state,
                    PrivateSettlementSidecarLifecycleV1::CommitCertified
                        | PrivateSettlementSidecarLifecycleV1::Finalized
                )
            })
        {
            PrivateSettlementSidecarLifecycleV1::CommitCertified
        } else if complete
            && lifecycles.iter().all(|state| {
                matches!(
                    state,
                    PrivateSettlementSidecarLifecycleV1::Prepared
                        | PrivateSettlementSidecarLifecycleV1::CommitCertified
                        | PrivateSettlementSidecarLifecycleV1::Finalized
                )
            })
        {
            PrivateSettlementSidecarLifecycleV1::Prepared
        } else if complete
            && lifecycles
                .iter()
                .all(|state| !matches!(state, PrivateSettlementSidecarLifecycleV1::Collecting))
        {
            PrivateSettlementSidecarLifecycleV1::Audited
        } else {
            PrivateSettlementSidecarLifecycleV1::Collecting
        };
        let durable_legs = u8::try_from(lifecycles.len())
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        Ok(PrivateSettlementPublicBundleStatusV1 {
            manifest,
            lifecycle,
            lifecycle_height,
            durable_legs,
        })
    }

    /// Enumerate one deterministic bounded page of nonterminal local records.
    ///
    /// The projection contains only opaque public identifiers and lifecycle
    /// metadata. It never decodes or returns proof, capsule, policy, or account
    /// material. The cursor advances across terminal records as well, ensuring
    /// a bounded full-store pass even when most records are already complete.
    ///
    /// # Errors
    ///
    /// Rejects zero or oversized pages and returns a redacted store-health error.
    pub fn reconciliation_page(
        &self,
        after: Option<Hash>,
        limit: usize,
    ) -> Result<PrivateSettlementReconciliationPageV1, PrivateSettlementSidecarStoreErrorV1> {
        if limit == 0 || limit > PRIVATE_SETTLEMENT_RECONCILIATION_MAX_PAGE_RECORDS_V1 {
            return Err(PrivateSettlementSidecarStoreErrorV1::ConfigurationInvalid);
        }
        let state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        let lower = after.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
        let mut rows = state.index.range((lower, std::ops::Bound::Unbounded));
        let mut candidates = Vec::with_capacity(limit);
        let mut last_visited = None;
        for _ in 0..limit {
            let Some((payload_digest, metadata)) = rows.next() else {
                break;
            };
            last_visited = Some(*payload_digest);
            if !metadata.lifecycle.is_terminal() {
                candidates.push(PrivateSettlementReconciliationCandidateV1 {
                    payload_digest: *payload_digest,
                    bundle_id: metadata.bundle_id,
                    expiry_height: metadata.expiry_height,
                    lifecycle: metadata.lifecycle,
                });
            }
        }
        let next_cursor = if rows.next().is_some() {
            last_visited
        } else {
            None
        };
        Ok(PrivateSettlementReconciliationPageV1 {
            candidates,
            next_cursor,
        })
    }

    /// Fetch proof material for one exact participant validator.
    ///
    /// Missing, expired-retention, and unauthorized requests all return
    /// [`PrivateSettlementSidecarStoreErrorV1::Unavailable`]. The encrypted
    /// capsule itself is deliberately absent from this view.
    ///
    /// # Errors
    ///
    /// Returns unavailable or a local corruption/backend error.
    pub fn fetch_for_committee(
        &self,
        digest: Hash,
        validator: &PeerId,
        authoritative_height: u64,
    ) -> Result<PrivateSettlementCommitteeSidecarViewV1, PrivateSettlementSidecarStoreErrorV1> {
        let state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        let metadata = state
            .index
            .get(&digest)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Unavailable)?;
        if authoritative_height > metadata.retention_until_height {
            return Err(PrivateSettlementSidecarStoreErrorV1::Unavailable);
        }
        let durable = self.read_record_v1(digest)?;
        if !durable.sidecar.authority.validators.contains(validator) {
            return Err(PrivateSettlementSidecarStoreErrorV1::Unavailable);
        }
        let capsule_digest = durable
            .sidecar
            .payload
            .audit_capsule
            .digest()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        Ok(PrivateSettlementCommitteeSidecarViewV1 {
            manifest: durable.sidecar.manifest,
            policy: durable.sidecar.policy,
            authority: durable.sidecar.authority,
            statement: durable.sidecar.payload.statement,
            proof: durable.sidecar.payload.proof,
            delta: durable.sidecar.payload.delta,
            audit_approvals: durable.audit_approvals,
            audit_capsule_digest: capsule_digest,
            availability: durable.sidecar.payload.availability,
            lifecycle: durable.lifecycle,
        })
    }

    /// Fetch one threshold-audited immutable record for complete committee validation.
    ///
    /// This access is restricted to the private-settlement runtime. It returns
    /// the encrypted capsule only so the exact payload and fsync evidence can
    /// be revalidated internally; the committee service returns only a Prepare
    /// body to its caller.
    pub(super) fn fetch_for_committee_validation(
        &self,
        digest: Hash,
        validator: &PeerId,
        authoritative_height: u64,
    ) -> Result<PrivateSettlementCommitteeValidationMaterialV1, PrivateSettlementSidecarStoreErrorV1>
    {
        let state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        let metadata = state
            .index
            .get(&digest)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Unavailable)?;
        if authoritative_height < metadata.lifecycle_height
            || authoritative_height > metadata.expiry_height
            || authoritative_height > metadata.retention_until_height
            || !matches!(
                metadata.lifecycle,
                PrivateSettlementSidecarLifecycleV1::Audited
                    | PrivateSettlementSidecarLifecycleV1::Prepared
                    | PrivateSettlementSidecarLifecycleV1::CommitCertified
            )
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::Unavailable);
        }
        let durable = self.read_record_v1(digest)?;
        if !durable.sidecar.authority.validators.contains(validator) {
            return Err(PrivateSettlementSidecarStoreErrorV1::Unavailable);
        }
        let availability = durable_availability_evidence_for_wire_v1(&durable.sidecar)?;
        Ok(PrivateSettlementCommitteeValidationMaterialV1 {
            manifest: durable.sidecar.manifest,
            policy: durable.sidecar.policy,
            authority: durable.sidecar.authority,
            payload: durable.sidecar.payload,
            audit_approvals: durable.audit_approvals,
            availability,
        })
    }

    /// Fetch the padded encrypted capsule for one exact governed auditor.
    ///
    /// Missing, expired-retention, and unauthorized requests intentionally
    /// share one unavailable response. This method never decrypts the capsule.
    ///
    /// # Errors
    ///
    /// Returns unavailable or a local corruption/backend error.
    #[cfg(test)]
    pub(crate) fn fetch_for_auditor(
        &self,
        digest: Hash,
        auditor: &AccountId,
        authoritative_height: u64,
    ) -> Result<PrivateSettlementAuditorSidecarViewV1, PrivateSettlementSidecarStoreErrorV1> {
        let view = self.auditor_material_v1(digest, authoritative_height)?;
        if !view
            .policy
            .body
            .auditors
            .iter()
            .any(|entry| &entry.auditor_id == auditor)
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::Unavailable);
        }
        Ok(view)
    }

    /// Read the exact immutable auditor material for core authorization.
    ///
    /// This least-privilege primitive is module-private: callers outside core
    /// cannot turn knowledge of a payload digest into capsule access. The
    /// public core operation validates the returned route, pool, network,
    /// historical governance revision, current governance revision, and
    /// authenticated signing key against one exact state snapshot before the
    /// view crosses the crate boundary.
    pub(super) fn auditor_material_v1(
        &self,
        digest: Hash,
        authoritative_height: u64,
    ) -> Result<PrivateSettlementAuditorSidecarViewV1, PrivateSettlementSidecarStoreErrorV1> {
        let state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        let metadata = state
            .index
            .get(&digest)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Unavailable)?;
        if authoritative_height < metadata.stored_at_height
            || authoritative_height < metadata.lifecycle_height
            || authoritative_height > metadata.retention_until_height
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::Unavailable);
        }
        let durable = self.read_record_v1(digest)?;
        Ok(PrivateSettlementAuditorSidecarViewV1 {
            manifest: durable.sidecar.manifest,
            policy: durable.sidecar.policy,
            authority: durable.sidecar.authority,
            statement: durable.sidecar.payload.statement,
            delta: durable.sidecar.payload.delta,
            audit_capsule: durable.sidecar.payload.audit_capsule,
            availability: durable.sidecar.payload.availability,
            lifecycle: durable.lifecycle,
        })
    }

    /// Durably collect one purpose-separated governed auditor approval.
    ///
    /// Approvals are stored in canonical auditor-id order.  Exact retries are
    /// idempotent, a second distinct approval from the same auditor conflicts,
    /// and the record enters `Audited` only when the immutable policy threshold
    /// is durably present.  This permits `M-of-N` policies to survive process
    /// restarts without weakening the Prepare threshold.
    ///
    /// # Errors
    ///
    /// Returns a redacted unavailable, invalid-transition, conflict,
    /// corruption, capacity, or backend error.
    pub fn record_audit_approval(
        &self,
        digest: Hash,
        approval: PrivateSettlementAuditApprovalV1,
        authoritative_height: u64,
    ) -> Result<PrivateSettlementAuditCollectionOutcomeV1, PrivateSettlementSidecarStoreErrorV1>
    {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        let metadata = state
            .index
            .get(&digest)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Unavailable)?
            .clone();
        if authoritative_height < metadata.lifecycle_height
            || authoritative_height > metadata.expiry_height
            || !matches!(
                metadata.lifecycle,
                PrivateSettlementSidecarLifecycleV1::Collecting
                    | PrivateSettlementSidecarLifecycleV1::Audited
            )
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition);
        }
        let mut durable = self.read_record_v1(digest)?;
        validate_private_settlement_audit_approval_v1(
            &approval,
            &durable.sidecar.policy,
            &durable.sidecar.payload,
            authoritative_height,
        )
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidTransition)?;
        let required = durable.sidecar.policy.body.min_approvals;
        match durable
            .audit_approvals
            .binary_search_by(|candidate| candidate.body.auditor_id.cmp(&approval.body.auditor_id))
        {
            Ok(index) => {
                // External providers may produce different valid encodings for
                // the same purpose-separated approval body.
                // Identity and every settlement binding live in the body, so
                // a body-equivalent retry is idempotent after the new
                // signature has already passed validation above.
                if durable.audit_approvals[index].body != approval.body {
                    return Err(PrivateSettlementSidecarStoreErrorV1::Conflict);
                }
                let collected = u8::try_from(durable.audit_approvals.len())
                    .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
                return Ok(PrivateSettlementAuditCollectionOutcomeV1 {
                    collected,
                    required,
                    newly_recorded: false,
                    audited: durable.lifecycle != PrivateSettlementSidecarLifecycleV1::Collecting,
                });
            }
            Err(_) if durable.lifecycle == PrivateSettlementSidecarLifecycleV1::Audited => {
                return Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition);
            }
            Err(index) => durable.audit_approvals.insert(index, approval),
        }
        let collected = u8::try_from(durable.audit_approvals.len())
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        durable.lifecycle_height = authoritative_height;
        durable.audit_approval_validation_height = Some(authoritative_height);
        if collected >= required {
            validate_private_settlement_audit_approvals_v1(
                &durable.audit_approvals,
                &durable.sidecar.policy,
                &durable.sidecar.payload,
                authoritative_height,
            )
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidTransition)?;
            durable.lifecycle = PrivateSettlementSidecarLifecycleV1::Audited;
        }
        durable.validate()?;
        self.persist_lifecycle_record_v1(&mut state, digest, &metadata, &durable)?;
        Ok(PrivateSettlementAuditCollectionOutcomeV1 {
            collected,
            required,
            newly_recorded: true,
            audited: durable.lifecycle == PrivateSettlementSidecarLifecycleV1::Audited,
        })
    }

    /// Test-only bulk persistence of the exact canonical auditor threshold.
    ///
    /// The approvals are signature-verified against the stored policy and
    /// immutable sidecar. Exact retries are idempotent; substitutions fail.
    #[cfg(test)]
    pub(crate) fn record_audited(
        &self,
        digest: Hash,
        approvals: Vec<PrivateSettlementAuditApprovalV1>,
        authoritative_height: u64,
    ) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        let metadata = state
            .index
            .get(&digest)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Unavailable)?
            .clone();
        if authoritative_height < metadata.lifecycle_height
            || authoritative_height > metadata.expiry_height
            || !matches!(
                metadata.lifecycle,
                PrivateSettlementSidecarLifecycleV1::Collecting
                    | PrivateSettlementSidecarLifecycleV1::Audited
            )
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition);
        }
        let mut durable = self.read_record_v1(digest)?;
        validate_private_settlement_audit_approvals_v1(
            &approvals,
            &durable.sidecar.policy,
            &durable.sidecar.payload,
            authoritative_height,
        )
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidTransition)?;
        private_settlement_approvals_digest_v1(&approvals).map_err(map_state_evidence_error_v1)?;
        if durable.lifecycle == PrivateSettlementSidecarLifecycleV1::Audited {
            return if durable.audit_approvals == approvals {
                Ok(())
            } else {
                Err(PrivateSettlementSidecarStoreErrorV1::Conflict)
            };
        }
        durable.lifecycle = PrivateSettlementSidecarLifecycleV1::Audited;
        durable.lifecycle_height = authoritative_height;
        durable.audit_approvals = approvals;
        durable.audit_approval_validation_height = Some(authoritative_height);
        durable.validate()?;
        self.persist_lifecycle_record_v1(&mut state, digest, &metadata, &durable)
    }

    /// Durably stage one leg using a validator-minted complete-verification token.
    ///
    /// The operation atomically installs pool-head, nullifier, and output
    /// reservations in the durable record index before a Prepare vote may be
    /// issued. A raw lifecycle enum can never enter `Prepared`.
    pub(crate) fn stage_verified(
        &self,
        digest: Hash,
        verified: ValidatedPrivateSettlementLegV1,
        authoritative_height: u64,
    ) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        let metadata = state
            .index
            .get(&digest)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Unavailable)?
            .clone();
        if !matches!(
            metadata.lifecycle,
            PrivateSettlementSidecarLifecycleV1::Audited
                | PrivateSettlementSidecarLifecycleV1::Prepared
                | PrivateSettlementSidecarLifecycleV1::CommitCertified
        ) || authoritative_height < metadata.lifecycle_height
            || authoritative_height > metadata.expiry_height
            || verified.verified_at_height() > authoritative_height
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition);
        }
        let mut durable = self.read_record_v1(digest)?;
        let availability = durable_availability_evidence_for_wire_v1(&durable.sidecar)?;
        verified
            .validate_against_payload(
                &durable.sidecar.manifest,
                &durable.sidecar.payload,
                availability.evidence_digest(),
            )
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidTransition)?;
        verified
            .validate_against_approvals(&durable.audit_approvals)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidTransition)?;
        if matches!(
            metadata.lifecycle,
            PrivateSettlementSidecarLifecycleV1::Prepared
                | PrivateSettlementSidecarLifecycleV1::CommitCertified
        ) {
            let existing = durable
                .verified_leg
                .as_ref()
                .ok_or(PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
            return if existing
                .same_transition_as(&verified)
                .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?
            {
                Ok(())
            } else {
                Err(PrivateSettlementSidecarStoreErrorV1::Conflict)
            };
        }
        durable.lifecycle = PrivateSettlementSidecarLifecycleV1::Prepared;
        durable.lifecycle_height = authoritative_height;
        durable.lifecycle_evidence_digest = Some(verified.verification_digest());
        durable.verified_leg = Some(verified);
        durable.validate()?;
        self.persist_lifecycle_record_v1(&mut state, digest, &metadata, &durable)?;
        Ok(())
    }

    /// Confirm that a phase request names the exact locally retained manifest
    /// and return its validator index and retained authority record.
    pub(super) fn validate_phase_manifest(
        &self,
        digest: Hash,
        validator: &PeerId,
        manifest: &AtomicPrivateSettlementV1,
        authoritative_height: u64,
    ) -> Result<(u8, PrivateSettlementCommitteeAuthorityV1), PrivateSettlementSidecarStoreErrorV1>
    {
        let state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        let metadata = state
            .index
            .get(&digest)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Unavailable)?;
        if authoritative_height < metadata.lifecycle_height
            || authoritative_height > metadata.expiry_height
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::Unavailable);
        }
        let durable = self.read_record_v1(digest)?;
        let ordinal = usize::from(durable.sidecar.payload.statement.leg_ordinal);
        let validator_index = durable
            .sidecar
            .authority
            .validators
            .iter()
            .position(|candidate| candidate == validator)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Unavailable)?;
        if &durable.sidecar.manifest != manifest
            || manifest
                .legs
                .get(ordinal)
                .is_none_or(|leg| leg.payload_digest != digest)
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::Unavailable);
        }
        let validator_index = u8::try_from(validator_index)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        Ok((validator_index, durable.sidecar.authority))
    }

    /// Build the sole Commit body admissible for one locally prepared leg.
    ///
    /// This is a read-only operation. It requires the exact complete all-Prepare
    /// barrier, the exact local staged transition, and a quorum-equivalent
    /// locally durable Prepare QC before returning a body that the node
    /// capability may sign.
    pub(super) fn commit_phase_body(
        &self,
        digest: Hash,
        validator: &PeerId,
        barrier: &PrivateSettlementPrepareBarrierV1,
        authoritative_height: u64,
    ) -> Result<PrivateSettlementPhaseBodyV1, PrivateSettlementSidecarStoreErrorV1> {
        validate_private_settlement_prepare_barrier_v1(barrier)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidTransition)?;
        let state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        let metadata = state
            .index
            .get(&digest)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Unavailable)?;
        if !matches!(
            metadata.lifecycle,
            PrivateSettlementSidecarLifecycleV1::Prepared
                | PrivateSettlementSidecarLifecycleV1::CommitCertified
        ) || authoritative_height < metadata.lifecycle_height
            || authoritative_height > metadata.expiry_height
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition);
        }
        let durable = self.read_record_v1(digest)?;
        if !durable.sidecar.authority.validators.contains(validator)
            || durable.sidecar.manifest != barrier.manifest
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::Unavailable);
        }
        let ordinal = usize::from(durable.sidecar.payload.statement.leg_ordinal);
        let manifest_leg = barrier
            .manifest
            .legs
            .get(ordinal)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::InvalidTransition)?;
        let authority = barrier
            .authority_catalog
            .authority_for_leg(&barrier.manifest, ordinal)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidTransition)?;
        let delta = barrier
            .deltas
            .get(ordinal)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::InvalidTransition)?;
        let prepare = barrier
            .prepare_certificates
            .get(ordinal)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::InvalidTransition)?;
        let staged = durable
            .verified_leg
            .as_ref()
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        let durable_prepare_is_equivalent = durable
            .prepare_certificate
            .as_ref()
            .is_some_and(|existing| phase_certificates_are_quorum_equivalent_v1(existing, prepare));
        if manifest_leg.payload_digest != digest
            || authority != durable.sidecar.authority
            || delta != &durable.sidecar.payload.delta
            || staged.delta() != delta
            || !durable_prepare_is_equivalent
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition);
        }
        private_settlement_phase_body_v1(
            &barrier.manifest,
            delta,
            &authority,
            PrivateSettlementPhaseV1::Commit,
            barrier.prepared_bundle_digest,
        )
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidTransition)
    }

    /// Persist the local Prepare QC after the verified delta is already locked.
    ///
    /// A quorum-equivalent retry remains idempotent after the same record
    /// advances to `CommitCertified`; it never rewinds the lifecycle or
    /// rewrites the journal. Different signer subsets over the exact same body
    /// are equivalent because the prepared-bundle digest normalizes their
    /// aggregate encoding.
    pub(crate) fn record_prepare_certificate(
        &self,
        digest: Hash,
        certificate: PrivateSettlementPhaseCertificateV1,
        authoritative_height: u64,
    ) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
        self.record_phase_certificate_v1(
            digest,
            certificate,
            PrivateSettlementPhaseV1::Prepare,
            private_settlement_reserved_prepared_bundle_digest_v1(),
            authoritative_height,
        )
    }

    /// Persist the local Commit QC and enter `CommitCertified`.
    pub(crate) fn record_commit_certificate(
        &self,
        digest: Hash,
        certificate: PrivateSettlementPhaseCertificateV1,
        prepared_bundle_digest: Hash,
        authoritative_height: u64,
    ) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
        self.record_phase_certificate_v1(
            digest,
            certificate,
            PrivateSettlementPhaseV1::Commit,
            prepared_bundle_digest,
            authoritative_height,
        )
    }

    fn record_phase_certificate_v1(
        &self,
        digest: Hash,
        certificate: PrivateSettlementPhaseCertificateV1,
        phase: PrivateSettlementPhaseV1,
        prepared_bundle_digest: Hash,
        authoritative_height: u64,
    ) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        let metadata = state
            .index
            .get(&digest)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Unavailable)?
            .clone();
        let lifecycle_accepts_phase = match phase {
            PrivateSettlementPhaseV1::Prepare => matches!(
                metadata.lifecycle,
                PrivateSettlementSidecarLifecycleV1::Prepared
                    | PrivateSettlementSidecarLifecycleV1::CommitCertified
            ),
            PrivateSettlementPhaseV1::Commit => matches!(
                metadata.lifecycle,
                PrivateSettlementSidecarLifecycleV1::Prepared
                    | PrivateSettlementSidecarLifecycleV1::CommitCertified
            ),
        };
        if !lifecycle_accepts_phase
            || authoritative_height < metadata.lifecycle_height
            || authoritative_height > metadata.expiry_height
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition);
        }
        let mut durable = self.read_record_v1(digest)?;
        if phase == PrivateSettlementPhaseV1::Commit && durable.prepare_certificate.is_none() {
            return Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition);
        }
        let expected = private_settlement_phase_body_v1(
            &durable.sidecar.manifest,
            &durable.sidecar.payload.delta,
            &durable.sidecar.authority,
            phase,
            prepared_bundle_digest,
        )
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidTransition)?;
        if certificate.body != expected {
            return Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition);
        }
        verify_private_settlement_phase_certificate_v1(
            &certificate,
            durable.sidecar.payload.statement.leg_ordinal,
            &durable.sidecar.authority,
        )
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidTransition)?;

        let slot = match phase {
            PrivateSettlementPhaseV1::Prepare => &mut durable.prepare_certificate,
            PrivateSettlementPhaseV1::Commit => &mut durable.commit_certificate,
        };
        if let Some(existing) = slot.as_ref() {
            return if phase_certificates_are_quorum_equivalent_v1(existing, &certificate) {
                Ok(())
            } else {
                Err(PrivateSettlementSidecarStoreErrorV1::Conflict)
            };
        }
        *slot = Some(certificate);
        durable.lifecycle_height = authoritative_height;
        if phase == PrivateSettlementPhaseV1::Commit {
            durable.lifecycle = PrivateSettlementSidecarLifecycleV1::CommitCertified;
        }
        durable.validate()?;
        self.persist_lifecycle_record_v1(&mut state, digest, &metadata, &durable)?;
        Ok(())
    }

    /// Reconcile one local record against an immutable global terminal snapshot.
    ///
    /// An exact receipt has precedence over height expiry. Conflicting receipt
    /// and abort rows fail closed. With neither row present, expiry is admitted
    /// only after the manifest height has passed. Every terminal transition is
    /// persisted and fsynced before its staged reservations are released from
    /// the in-memory index.
    ///
    /// # Errors
    ///
    /// Returns a redacted substitution, transition, corruption, or backend error.
    pub fn reconcile_terminal_state(
        &self,
        digest: Hash,
        receipt: Option<&PrivateSettlementReceiptV1>,
        abort: Option<&PrivateSettlementAbortReceiptV1>,
        authoritative_height: u64,
    ) -> Result<PrivateSettlementReconciliationOutcomeV1, PrivateSettlementSidecarStoreErrorV1>
    {
        match (receipt, abort) {
            (Some(_), Some(_)) => Err(PrivateSettlementSidecarStoreErrorV1::Conflict),
            (Some(receipt), None) => {
                if receipt.finalized_height > authoritative_height {
                    return Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition);
                }
                self.finalize_with_receipt(digest, receipt)?;
                Ok(PrivateSettlementReconciliationOutcomeV1::Finalized)
            }
            (None, Some(abort)) => {
                if abort.finalized_height > authoritative_height {
                    return Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition);
                }
                self.abort_with_receipt(digest, abort)?;
                Ok(match abort.reason {
                    PrivateSettlementAbortReasonV1::Expired => {
                        PrivateSettlementReconciliationOutcomeV1::Expired
                    }
                    PrivateSettlementAbortReasonV1::ParticipantRejected
                    | PrivateSettlementAbortReasonV1::AuditUnavailable
                    | PrivateSettlementAbortReasonV1::SidecarUnavailable => {
                        PrivateSettlementReconciliationOutcomeV1::Aborted
                    }
                })
            }
            (None, None) => {
                if self.expire_at_authoritative_height(digest, authoritative_height)? {
                    Ok(PrivateSettlementReconciliationOutcomeV1::Expired)
                } else {
                    Ok(PrivateSettlementReconciliationOutcomeV1::Pending)
                }
            }
        }
    }

    /// Persist a cryptographically complete global receipt and release locks.
    pub(crate) fn finalize_with_receipt(
        &self,
        digest: Hash,
        receipt: &PrivateSettlementReceiptV1,
    ) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
        verify_private_settlement_receipt_v1(receipt)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidTransition)?;
        let receipt_digest = private_settlement_receipt_digest_v1(receipt)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        let metadata = state
            .index
            .get(&digest)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Unavailable)?
            .clone();
        if metadata.lifecycle == PrivateSettlementSidecarLifecycleV1::Finalized {
            let durable = self.read_record_v1(digest)?;
            return if durable.terminal_evidence_digest == Some(receipt_digest) {
                Ok(())
            } else {
                Err(PrivateSettlementSidecarStoreErrorV1::Conflict)
            };
        }
        if metadata.lifecycle.is_terminal() || receipt.finalized_height > metadata.expiry_height {
            return Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition);
        }
        let mut durable = self.read_record_v1(digest)?;
        let ordinal = usize::from(durable.sidecar.payload.statement.leg_ordinal);
        let receipt_leg = receipt
            .legs
            .get(ordinal)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::InvalidTransition)?;
        let receipt_authority = receipt
            .authority_catalog
            .authority_for_leg(&receipt.manifest, ordinal)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidTransition)?;
        if receipt.manifest != durable.sidecar.manifest
            || receipt_authority != durable.sidecar.authority
            || receipt_leg.delta != durable.sidecar.payload.delta
            || durable.prepare_certificate.as_ref().is_some_and(|prepare| {
                !phase_certificates_are_quorum_equivalent_v1(prepare, &receipt_leg.prepare)
            })
            || durable.commit_certificate.as_ref().is_some_and(|commit| {
                !phase_certificates_are_quorum_equivalent_v1(commit, &receipt_leg.commit)
            })
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition);
        }
        durable.lifecycle = PrivateSettlementSidecarLifecycleV1::Finalized;
        durable.lifecycle_height = metadata.lifecycle_height.max(receipt.finalized_height);
        durable.terminal_evidence_digest = Some(receipt_digest);
        durable.validate()?;
        self.persist_lifecycle_record_v1(&mut state, digest, &metadata, &durable)?;
        Ok(())
    }

    fn abort_with_receipt(
        &self,
        digest: Hash,
        abort: &PrivateSettlementAbortReceiptV1,
    ) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
        abort
            .validate()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::InvalidTransition)?;
        let abort_digest = private_settlement_abort_receipt_digest_v1(abort)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        let metadata = state
            .index
            .get(&digest)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Unavailable)?
            .clone();
        let mut durable = self.read_record_v1(digest)?;
        let manifest = &durable.sidecar.manifest;
        let expected_manifest_digest = manifest
            .manifest_digest()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        let expired = abort.finalized_height > manifest.expiry_height;
        let target = if expired {
            PrivateSettlementSidecarLifecycleV1::Expired
        } else {
            PrivateSettlementSidecarLifecycleV1::Aborted
        };
        if abort.network_id != manifest.network_id
            || abort.bundle_id != manifest.bundle_id
            || abort.manifest_digest != expected_manifest_digest
            || abort.finalized_height < manifest.authority_context_height
            || expired != (abort.reason == PrivateSettlementAbortReasonV1::Expired)
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition);
        }
        if metadata.lifecycle.is_terminal() {
            if metadata.lifecycle == target
                && durable.terminal_evidence_digest == Some(abort_digest)
            {
                return Ok(());
            }
            if metadata.lifecycle == PrivateSettlementSidecarLifecycleV1::Expired
                && target == PrivateSettlementSidecarLifecycleV1::Expired
            {
                let local_expiry_digest = private_settlement_local_expiry_digest_v1(
                    digest,
                    manifest,
                    metadata.lifecycle_height,
                )?;
                if durable.terminal_evidence_digest == Some(local_expiry_digest) {
                    durable.lifecycle_height =
                        metadata.lifecycle_height.max(abort.finalized_height);
                    durable.terminal_evidence_digest = Some(abort_digest);
                    durable.validate()?;
                    return self
                        .persist_lifecycle_record_v1(&mut state, digest, &metadata, &durable);
                }
            }
            return Err(PrivateSettlementSidecarStoreErrorV1::Conflict);
        }
        if !metadata.lifecycle.permits(target) {
            return Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition);
        }
        durable.lifecycle = target;
        durable.lifecycle_height = metadata.lifecycle_height.max(abort.finalized_height);
        durable.terminal_evidence_digest = Some(abort_digest);
        durable.validate()?;
        self.persist_lifecycle_record_v1(&mut state, digest, &metadata, &durable)
    }

    fn expire_at_authoritative_height(
        &self,
        digest: Hash,
        authoritative_height: u64,
    ) -> Result<bool, PrivateSettlementSidecarStoreErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        let metadata = state
            .index
            .get(&digest)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Unavailable)?
            .clone();
        if authoritative_height < metadata.lifecycle_height {
            return Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition);
        }
        if authoritative_height <= metadata.expiry_height {
            return Ok(false);
        }
        let mut durable = self.read_record_v1(digest)?;
        if metadata.lifecycle == PrivateSettlementSidecarLifecycleV1::Expired {
            let evidence = private_settlement_local_expiry_digest_v1(
                digest,
                &durable.sidecar.manifest,
                metadata.lifecycle_height,
            )?;
            return if durable.terminal_evidence_digest == Some(evidence) {
                Ok(true)
            } else {
                Err(PrivateSettlementSidecarStoreErrorV1::Conflict)
            };
        }
        if metadata.lifecycle.is_terminal()
            || !metadata
                .lifecycle
                .permits(PrivateSettlementSidecarLifecycleV1::Expired)
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition);
        }
        let evidence = private_settlement_local_expiry_digest_v1(
            digest,
            &durable.sidecar.manifest,
            authoritative_height,
        )?;
        durable.lifecycle = PrivateSettlementSidecarLifecycleV1::Expired;
        durable.lifecycle_height = authoritative_height;
        durable.terminal_evidence_digest = Some(evidence);
        durable.validate()?;
        self.persist_lifecycle_record_v1(&mut state, digest, &metadata, &durable)?;
        Ok(true)
    }

    fn persist_lifecycle_record_v1(
        &self,
        state: &mut SidecarStoreStateV1,
        digest: Hash,
        metadata: &IndexedPrivateSettlementSidecarV1,
        durable: &DurablePrivateSettlementSidecarV1,
    ) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
        let candidate_metadata = indexed_metadata_v1(durable, metadata.canonical_bytes);
        ensure_reservations_available_v1(state, digest, candidate_metadata.reservations.as_ref())?;
        let encoded = norito::encode_canonical(durable)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        let encoded_len = u64::try_from(encoded.len())
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::CapacityExceeded)?;
        let next_total = state
            .canonical_bytes
            .checked_sub(metadata.canonical_bytes)
            .and_then(|bytes| bytes.checked_add(encoded_len))
            .filter(|bytes| *bytes <= self.config.max_total_bytes)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::CapacityExceeded)?;
        match self.persist_record_v1(digest, &encoded, true) {
            Ok(()) => {}
            Err(failure) if failure.committed => {
                if update_index_v1(state, durable, encoded_len).is_err() {
                    state.poisoned = true;
                    return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
                }
                state.canonical_bytes = next_total;
                state.poisoned = true;
                return Err(PrivateSettlementSidecarStoreErrorV1::Backend);
            }
            Err(_) => return Err(PrivateSettlementSidecarStoreErrorV1::Backend),
        }
        if update_index_v1(state, durable, encoded_len).is_err() {
            state.poisoned = true;
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
        state.canonical_bytes = next_total;
        Ok(())
    }

    /// Remove terminal records whose advertised retention height has passed.
    ///
    /// Certified collecting, audited, prepared, and commit-certified records
    /// are never pruned. Unpromoted provisional records are released only after
    /// their signed retention height passes.
    ///
    /// # Errors
    ///
    /// Returns a local corruption or backend error without silently dropping
    /// an in-flight record.
    pub fn prune(
        &self,
        authoritative_height: u64,
    ) -> Result<usize, PrivateSettlementSidecarStoreErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        ensure_healthy_v1(&state)?;
        let candidates = state
            .index
            .iter()
            .filter_map(|(digest, metadata)| {
                (metadata.lifecycle.is_terminal()
                    && authoritative_height > metadata.retention_until_height)
                    .then_some(*digest)
            })
            .collect::<Vec<_>>();
        let mut removed = 0_usize;
        for digest in candidates {
            let metadata = state
                .index
                .get(&digest)
                .ok_or(PrivateSettlementSidecarStoreErrorV1::Corrupt)?
                .clone();
            match self.remove_record_v1(digest) {
                Ok(()) => {}
                Err(failure) if failure.committed => {
                    remove_index_v1(&mut state, digest, &metadata)?;
                    state.poisoned = true;
                    return Err(PrivateSettlementSidecarStoreErrorV1::Backend);
                }
                Err(_) => return Err(PrivateSettlementSidecarStoreErrorV1::Backend),
            }
            remove_index_v1(&mut state, digest, &metadata)?;
            removed = removed
                .checked_add(1)
                .ok_or(PrivateSettlementSidecarStoreErrorV1::Backend)?;
        }
        let provisional_candidates = state
            .provisional_index
            .iter()
            .filter_map(|(digest, metadata)| {
                (authoritative_height > metadata.retention_until_height).then_some(*digest)
            })
            .collect::<Vec<_>>();
        for digest in provisional_candidates {
            let metadata = state
                .provisional_index
                .get(&digest)
                .ok_or(PrivateSettlementSidecarStoreErrorV1::Corrupt)?
                .clone();
            match self.remove_provisional_record_v1(digest) {
                Ok(()) => {}
                Err(failure) if failure.committed => {
                    remove_provisional_index_v1(&mut state, digest, &metadata)?;
                    state.poisoned = true;
                    return Err(PrivateSettlementSidecarStoreErrorV1::Backend);
                }
                Err(_) => return Err(PrivateSettlementSidecarStoreErrorV1::Backend),
            }
            remove_provisional_index_v1(&mut state, digest, &metadata)?;
            removed = removed
                .checked_add(1)
                .ok_or(PrivateSettlementSidecarStoreErrorV1::Backend)?;
        }
        Ok(removed)
    }

    fn read_record_v1(
        &self,
        digest: Hash,
    ) -> Result<DurablePrivateSettlementSidecarV1, PrivateSettlementSidecarStoreErrorV1> {
        let path = self.root.join(sidecar_file_name_v1(digest));
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        let file = open_owner_file_v1(&path, &metadata)?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len())
                .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?,
        );
        file.take(PRIVATE_SETTLEMENT_SIDECAR_MAX_RECORD_BYTES_V1 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        if bytes.len() as u64 != metadata.len()
            || bytes.is_empty()
            || bytes.len() as u64 > PRIVATE_SETTLEMENT_SIDECAR_MAX_RECORD_BYTES_V1
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
        let record = norito::decode_canonical::<DurablePrivateSettlementSidecarV1>(&bytes)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        record.validate()?;
        if record.payload_digest() != digest {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
        Ok(record)
    }

    fn read_provisional_record_v1(
        &self,
        digest: Hash,
    ) -> Result<DurablePrivateSettlementProvisionalSidecarV1, PrivateSettlementSidecarStoreErrorV1>
    {
        let path = self.root.join(provisional_file_name_v1(digest));
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        let file = open_owner_file_v1(&path, &metadata)?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len())
                .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?,
        );
        file.take(PRIVATE_SETTLEMENT_SIDECAR_MAX_RECORD_BYTES_V1 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        if bytes.len() as u64 != metadata.len()
            || bytes.is_empty()
            || bytes.len() as u64 > PRIVATE_SETTLEMENT_SIDECAR_MAX_RECORD_BYTES_V1
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
        let record =
            norito::decode_canonical::<DurablePrivateSettlementProvisionalSidecarV1>(&bytes)
                .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        record.validate()?;
        if record.payload_digest() != digest {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
        Ok(record)
    }

    fn persist_record_v1(
        &self,
        digest: Hash,
        bytes: &[u8],
        replacing: bool,
    ) -> Result<(), DurableSidecarMutationFailureV1> {
        let file_name = sidecar_file_name_v1(digest);
        self.persist_named_record_v1(&file_name, bytes, replacing)
    }

    fn persist_provisional_record_v1(
        &self,
        digest: Hash,
        bytes: &[u8],
    ) -> Result<(), DurableSidecarMutationFailureV1> {
        let file_name = provisional_file_name_v1(digest);
        self.persist_named_record_v1(&file_name, bytes, false)
    }

    fn persist_named_record_v1(
        &self,
        file_name: &str,
        bytes: &[u8],
        replacing: bool,
    ) -> Result<(), DurableSidecarMutationFailureV1> {
        let target = self.root.join(&file_name);
        let temp = self
            .temp_root
            .join(format!("{file_name}{SIDECAR_TEMP_EXTENSION_V1}"));
        validate_target_state_v1(&target, replacing)
            .map_err(|_| DurableSidecarMutationFailureV1::before())?;
        reject_existing_temp_v1(&temp).map_err(|_| DurableSidecarMutationFailureV1::before())?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|_| DurableSidecarMutationFailureV1::before())?;
        if file.write_all(bytes).is_err() || file.sync_all().is_err() {
            drop(file);
            let _ = fs::remove_file(&temp);
            return Err(DurableSidecarMutationFailureV1::before());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let path_metadata = match fs::symlink_metadata(&temp) {
                Ok(metadata) => metadata,
                Err(_) => {
                    drop(file);
                    let _ = fs::remove_file(&temp);
                    return Err(DurableSidecarMutationFailureV1::before());
                }
            };
            let opened = match file.metadata() {
                Ok(metadata) => metadata,
                Err(_) => {
                    drop(file);
                    let _ = fs::remove_file(&temp);
                    return Err(DurableSidecarMutationFailureV1::before());
                }
            };
            if path_metadata.file_type().is_symlink()
                || !path_metadata.file_type().is_file()
                || path_metadata.nlink() != 1
                || path_metadata.uid() != rustix::process::geteuid().as_raw()
                || path_metadata.mode() & 0o777 != 0o600
                || path_metadata.dev() != opened.dev()
                || path_metadata.ino() != opened.ino()
                || path_metadata.len() != opened.len()
            {
                drop(file);
                let _ = fs::remove_file(&temp);
                return Err(DurableSidecarMutationFailureV1::before());
            }
        }
        drop(file);
        if fs::rename(&temp, &target).is_err() {
            let _ = fs::remove_file(&temp);
            return Err(DurableSidecarMutationFailureV1::before());
        }
        if sync_directory_v1(&self.root).is_err() || sync_directory_v1(&self.temp_root).is_err() {
            return Err(DurableSidecarMutationFailureV1::after());
        }
        Ok(())
    }

    fn remove_record_v1(&self, digest: Hash) -> Result<(), DurableSidecarMutationFailureV1> {
        let target = self.root.join(sidecar_file_name_v1(digest));
        self.remove_named_record_v1(&target)
    }

    fn remove_provisional_record_v1(
        &self,
        digest: Hash,
    ) -> Result<(), DurableSidecarMutationFailureV1> {
        let target = self.root.join(provisional_file_name_v1(digest));
        self.remove_named_record_v1(&target)
    }

    fn remove_named_record_v1(&self, target: &Path) -> Result<(), DurableSidecarMutationFailureV1> {
        validate_target_state_v1(target, true)
            .map_err(|_| DurableSidecarMutationFailureV1::before())?;
        fs::remove_file(target).map_err(|_| DurableSidecarMutationFailureV1::before())?;
        sync_directory_v1(&self.root).map_err(|_| DurableSidecarMutationFailureV1::after())
    }
}

fn map_state_evidence_error_v1(
    _error: PrivateSettlementStateErrorV1,
) -> PrivateSettlementSidecarStoreErrorV1 {
    PrivateSettlementSidecarStoreErrorV1::Corrupt
}

fn private_settlement_receipt_digest_v1(
    receipt: &PrivateSettlementReceiptV1,
) -> Result<Hash, PrivateSettlementSidecarStoreErrorV1> {
    let encoded = norito::encode_canonical(receipt)
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
    let encoded_len =
        u64::try_from(encoded.len()).map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
    Ok(Hash::new_from_chunks(&[
        FINALIZED_RECEIPT_DIGEST_DOMAIN_V1,
        &encoded_len.to_le_bytes(),
        &encoded,
    ]))
}

fn private_settlement_abort_receipt_digest_v1(
    receipt: &PrivateSettlementAbortReceiptV1,
) -> Result<Hash, PrivateSettlementSidecarStoreErrorV1> {
    let encoded = norito::encode_canonical(receipt)
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
    let encoded_len =
        u64::try_from(encoded.len()).map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
    Ok(Hash::new_from_chunks(&[
        ABORT_RECEIPT_DIGEST_DOMAIN_V1,
        &encoded_len.to_le_bytes(),
        &encoded,
    ]))
}

fn private_settlement_local_expiry_digest_v1(
    payload_digest: Hash,
    manifest: &AtomicPrivateSettlementV1,
    observed_height: u64,
) -> Result<Hash, PrivateSettlementSidecarStoreErrorV1> {
    let manifest_digest = manifest
        .manifest_digest()
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
    Ok(Hash::new_from_chunks(&[
        LOCAL_EXPIRY_DIGEST_DOMAIN_V1,
        payload_digest.as_ref(),
        manifest.bundle_id.as_ref(),
        manifest_digest.as_ref(),
        &manifest.expiry_height.to_le_bytes(),
        &observed_height.to_le_bytes(),
    ]))
}

fn durable_availability_evidence_for_wire_v1(
    sidecar: &PrivateSettlementRestrictedSidecarWireV1,
) -> Result<PrivateSettlementDurableAvailabilityV1, PrivateSettlementSidecarStoreErrorV1> {
    let immutable = norito::encode_canonical(sidecar)
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
    let immutable_len = u64::try_from(immutable.len())
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
    let record_digest = Hash::new_from_chunks(&[
        b"iroha:nexus:private-settlement:persisted-sidecar:v1\0",
        &immutable_len.to_le_bytes(),
        &immutable,
    ]);
    let payload_bytes = u64::try_from(
        sidecar
            .payload
            .canonical_bytes_len()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?,
    )
    .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
    PrivateSettlementDurableAvailabilityV1::new(
        sidecar.payload.availability.body.payload_digest,
        record_digest,
        payload_bytes,
        sidecar.stored_at_height,
    )
    .map_err(map_state_evidence_error_v1)
}

#[derive(Clone, Copy, Debug)]
struct DurableSidecarMutationFailureV1 {
    committed: bool,
}

impl DurableSidecarMutationFailureV1 {
    const fn before() -> Self {
        Self { committed: false }
    }

    const fn after() -> Self {
        Self { committed: true }
    }
}

fn ensure_healthy_v1(
    state: &SidecarStoreStateV1,
) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
    if state.poisoned {
        Err(PrivateSettlementSidecarStoreErrorV1::Backend)
    } else {
        Ok(())
    }
}

fn same_restricted_material_v1(
    left: &PrivateSettlementRestrictedSidecarWireV1,
    right: &PrivateSettlementRestrictedSidecarWireV1,
) -> bool {
    left.manifest == right.manifest
        && left.policy == right.policy
        && left.authority == right.authority
        && left.payload == right.payload
}

fn final_matches_provisional_v1(
    final_sidecar: &PrivateSettlementRestrictedSidecarWireV1,
    provisional: &DurablePrivateSettlementProvisionalSidecarV1,
) -> bool {
    let material = &provisional.material;
    let mut projected_manifest = final_sidecar.manifest.clone();
    for leg in &mut projected_manifest.legs {
        leg.availability_certificate_digest = Hash::prehashed([0; Hash::LENGTH]);
    }
    projected_manifest == material.manifest
        && final_sidecar.policy == material.audit_policy
        && final_sidecar.authority == material.committee_authority
        && final_sidecar.payload.statement == material.statement
        && final_sidecar.payload.proof == material.proof
        && final_sidecar.payload.delta == material.delta
        && final_sidecar.payload.audit_capsule == material.audit_capsule
        && final_sidecar.payload.availability.body == material.availability_body
}

fn insert_provisional_index_v1(
    state: &mut SidecarStoreStateV1,
    record: &DurablePrivateSettlementProvisionalSidecarV1,
    canonical_bytes: u64,
) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
    let digest = record.payload_digest();
    let leg_key = record.leg_key();
    if state.provisional_index.contains_key(&digest)
        || state.provisional_by_leg.contains_key(&leg_key)
        || state.index.contains_key(&digest)
        || state.by_leg.contains_key(&leg_key)
    {
        return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
    }
    state.provisional_index.insert(
        digest,
        IndexedPrivateSettlementProvisionalSidecarV1 {
            canonical_bytes,
            bundle_id: leg_key.0,
            leg_ordinal: leg_key.1,
            retention_until_height: record.material.availability_body.retention_until_height,
        },
    );
    state.provisional_by_leg.insert(leg_key, digest);
    Ok(())
}

fn remove_provisional_index_v1(
    state: &mut SidecarStoreStateV1,
    digest: Hash,
    metadata: &IndexedPrivateSettlementProvisionalSidecarV1,
) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
    state
        .provisional_index
        .remove(&digest)
        .ok_or(PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
    if state
        .provisional_by_leg
        .remove(&(metadata.bundle_id, metadata.leg_ordinal))
        != Some(digest)
    {
        return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
    }
    state.canonical_bytes = state
        .canonical_bytes
        .checked_sub(metadata.canonical_bytes)
        .ok_or(PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
    Ok(())
}

fn insert_index_v1(
    state: &mut SidecarStoreStateV1,
    record: &DurablePrivateSettlementSidecarV1,
    canonical_bytes: u64,
) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
    let digest = record.payload_digest();
    let metadata = indexed_metadata_v1(record, canonical_bytes);
    let leg_key = (metadata.bundle_id, metadata.leg_ordinal);
    if state.index.contains_key(&digest) || state.by_leg.contains_key(&leg_key) {
        return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
    }
    ensure_reservations_available_v1(state, digest, metadata.reservations.as_ref())?;
    insert_reservations_v1(state, digest, metadata.reservations.as_ref())?;
    state.index.insert(digest, metadata);
    state.by_leg.insert(leg_key, digest);
    Ok(())
}

fn update_index_v1(
    state: &mut SidecarStoreStateV1,
    record: &DurablePrivateSettlementSidecarV1,
    canonical_bytes: u64,
) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
    let digest = record.payload_digest();
    let metadata = indexed_metadata_v1(record, canonical_bytes);
    let existing = state
        .index
        .get(&digest)
        .cloned()
        .ok_or(PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
    ensure_reservations_available_v1(state, digest, metadata.reservations.as_ref())?;
    remove_reservations_v1(state, digest, existing.reservations.as_ref())?;
    insert_reservations_v1(state, digest, metadata.reservations.as_ref())?;
    state.index.insert(digest, metadata);
    Ok(())
}

fn remove_index_v1(
    state: &mut SidecarStoreStateV1,
    digest: Hash,
    metadata: &IndexedPrivateSettlementSidecarV1,
) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
    remove_reservations_v1(state, digest, metadata.reservations.as_ref())?;
    state
        .index
        .remove(&digest)
        .ok_or(PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
    let removed = state
        .by_leg
        .remove(&(metadata.bundle_id, metadata.leg_ordinal));
    if removed != Some(digest) {
        return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
    }
    state.canonical_bytes = state
        .canonical_bytes
        .checked_sub(metadata.canonical_bytes)
        .ok_or(PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
    Ok(())
}

fn ensure_reservations_available_v1(
    state: &SidecarStoreStateV1,
    owner: Hash,
    reservations: Option<&PrivateSettlementReservationKeysV1>,
) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
    let Some(reservations) = reservations else {
        return Ok(());
    };
    let conflicts = state
        .pool_reservations
        .get(&reservations.pool_head)
        .is_some_and(|existing| *existing != owner)
        || reservations.nullifiers.iter().any(|key| {
            state
                .nullifier_reservations
                .get(key)
                .is_some_and(|existing| *existing != owner)
        })
        || reservations.output_commitments.iter().any(|key| {
            state
                .output_reservations
                .get(key)
                .is_some_and(|existing| *existing != owner)
        });
    if conflicts {
        Err(PrivateSettlementSidecarStoreErrorV1::Conflict)
    } else {
        Ok(())
    }
}

fn insert_reservations_v1(
    state: &mut SidecarStoreStateV1,
    owner: Hash,
    reservations: Option<&PrivateSettlementReservationKeysV1>,
) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
    let Some(reservations) = reservations else {
        return Ok(());
    };
    if state
        .pool_reservations
        .insert(reservations.pool_head, owner)
        .is_some_and(|existing| existing != owner)
    {
        return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
    }
    for key in &reservations.nullifiers {
        if state
            .nullifier_reservations
            .insert(*key, owner)
            .is_some_and(|existing| existing != owner)
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
    }
    for key in &reservations.output_commitments {
        if state
            .output_reservations
            .insert(*key, owner)
            .is_some_and(|existing| existing != owner)
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
    }
    Ok(())
}

fn remove_reservations_v1(
    state: &mut SidecarStoreStateV1,
    owner: Hash,
    reservations: Option<&PrivateSettlementReservationKeysV1>,
) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
    let Some(reservations) = reservations else {
        return Ok(());
    };
    if state.pool_reservations.remove(&reservations.pool_head) != Some(owner) {
        return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
    }
    for key in &reservations.nullifiers {
        if state.nullifier_reservations.remove(key) != Some(owner) {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
    }
    for key in &reservations.output_commitments {
        if state.output_reservations.remove(key) != Some(owner) {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
    }
    Ok(())
}

fn indexed_metadata_v1(
    record: &DurablePrivateSettlementSidecarV1,
    canonical_bytes: u64,
) -> IndexedPrivateSettlementSidecarV1 {
    let reservations = matches!(
        record.lifecycle,
        PrivateSettlementSidecarLifecycleV1::Prepared
            | PrivateSettlementSidecarLifecycleV1::CommitCertified
    )
    .then(|| {
        let verified = record
            .verified_leg
            .as_ref()
            .expect("validated staged record carries verified-leg evidence");
        let pool_id = verified.pool_id();
        let route = verified.delta().route;
        let (epoch, root) = verified.parent_head();
        PrivateSettlementReservationKeysV1 {
            pool_head: (route, pool_id, epoch, root),
            nullifiers: verified
                .nullifiers()
                .iter()
                .copied()
                .map(|nullifier| (route, pool_id, nullifier))
                .collect(),
            output_commitments: verified
                .output_commitments()
                .iter()
                .copied()
                .map(|commitment| (route, pool_id, commitment))
                .collect(),
        }
    });
    IndexedPrivateSettlementSidecarV1 {
        canonical_bytes,
        bundle_id: record.sidecar.manifest.bundle_id,
        leg_ordinal: record.sidecar.payload.statement.leg_ordinal,
        expiry_height: record.sidecar.manifest.expiry_height,
        retention_until_height: record
            .sidecar
            .payload
            .availability
            .body
            .retention_until_height,
        stored_at_height: record.sidecar.stored_at_height,
        lifecycle: record.lifecycle,
        lifecycle_height: record.lifecycle_height,
        reservations,
    }
}

#[cfg(unix)]
fn ensure_owner_directory_v1(root: &Path) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_dir()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o777 != 0o700
            {
                return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = root
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .ok_or(PrivateSettlementSidecarStoreErrorV1::ConfigurationInvalid)?;
            let parent_metadata = fs::symlink_metadata(parent)
                .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
            if parent_metadata.file_type().is_symlink() || !parent_metadata.file_type().is_dir() {
                return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
            }
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(root)
                .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
            sync_directory_v1(parent).map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        }
        Err(_) => return Err(PrivateSettlementSidecarStoreErrorV1::Backend),
    }
    let metadata =
        fs::symlink_metadata(root).map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
    }
    Ok(())
}

#[cfg(unix)]
fn acquire_sidecar_store_writer_lock_v1(
    root: &Path,
) -> Result<File, PrivateSettlementSidecarStoreErrorV1> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let path = root.join(SIDECAR_WRITER_LOCK_FILE_V1);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || metadata.nlink() != 1
                || metadata.len() != 0
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o777 != 0o600
            {
                return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(PrivateSettlementSidecarStoreErrorV1::Backend),
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
        .mode(0o600);
    let file = options
        .open(&path)
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
    let path_metadata =
        fs::symlink_metadata(&path).map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
    let opened = file
        .metadata()
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.nlink() != 1
        || path_metadata.len() != 0
        || path_metadata.uid() != rustix::process::geteuid().as_raw()
        || path_metadata.mode() & 0o777 != 0o600
        || path_metadata.dev() != opened.dev()
        || path_metadata.ino() != opened.ino()
    {
        return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
    }
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::StoreAlreadyOpen)?;
    sync_directory_v1(root).map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
    Ok(file)
}

#[cfg(unix)]
fn open_owner_file_v1(
    path: &Path,
    path_metadata: &fs::Metadata,
) -> Result<File, PrivateSettlementSidecarStoreErrorV1> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.nlink() != 1
        || path_metadata.uid() != rustix::process::geteuid().as_raw()
        || path_metadata.mode() & 0o777 != 0o600
    {
        return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
        .open(path)
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
    let opened = file
        .metadata()
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
    if !opened.file_type().is_file()
        || opened.nlink() != 1
        || opened.uid() != rustix::process::geteuid().as_raw()
        || opened.mode() & 0o777 != 0o600
        || path_metadata.dev() != opened.dev()
        || path_metadata.ino() != opened.ino()
        || path_metadata.len() != opened.len()
    {
        return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_owner_file_v1(
    _path: &Path,
    _path_metadata: &fs::Metadata,
) -> Result<File, PrivateSettlementSidecarStoreErrorV1> {
    Err(PrivateSettlementSidecarStoreErrorV1::UnsupportedPlatform)
}

#[cfg(unix)]
fn validate_target_state_v1(
    path: &Path,
    must_exist: bool,
) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if must_exist => {
            let _ = open_owner_file_v1(path, &metadata)?;
            Ok(())
        }
        Ok(_) => Err(PrivateSettlementSidecarStoreErrorV1::Corrupt),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !must_exist => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(PrivateSettlementSidecarStoreErrorV1::Corrupt)
        }
        Err(_) => Err(PrivateSettlementSidecarStoreErrorV1::Backend),
    }
}

#[cfg(not(unix))]
fn validate_target_state_v1(
    _path: &Path,
    _must_exist: bool,
) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
    Err(PrivateSettlementSidecarStoreErrorV1::UnsupportedPlatform)
}

fn reject_existing_temp_v1(path: &Path) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(PrivateSettlementSidecarStoreErrorV1::Corrupt),
        Err(_) => Err(PrivateSettlementSidecarStoreErrorV1::Backend),
    }
}

#[cfg(unix)]
fn clean_stale_temp_files_v1(temp_root: &Path) -> Result<(), PrivateSettlementSidecarStoreErrorV1> {
    use std::os::unix::fs::MetadataExt as _;
    let mut removed = false;
    for entry in
        fs::read_dir(temp_root).map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?
    {
        let entry = entry.map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        let file_type = entry
            .file_type()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        let record_name = name
            .strip_suffix(SIDECAR_TEMP_EXTENSION_V1)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        if parse_sidecar_file_name_v1(record_name).is_err()
            && parse_provisional_file_name_v1(record_name).is_err()
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
        let metadata = entry
            .metadata()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        if file_type.is_symlink()
            || !file_type.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() > PRIVATE_SETTLEMENT_SIDECAR_MAX_RECORD_BYTES_V1
        {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
        fs::remove_file(entry.path()).map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        removed = true;
    }
    if removed {
        sync_directory_v1(temp_root).map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
    }
    Ok(())
}

#[cfg(unix)]
fn load_file_store_v1(
    root: &Path,
    config: PrivateSettlementSidecarStoreConfigV1,
) -> Result<SidecarStoreStateV1, PrivateSettlementSidecarStoreErrorV1> {
    let mut state = SidecarStoreStateV1 {
        index: BTreeMap::new(),
        by_leg: BTreeMap::new(),
        provisional_index: BTreeMap::new(),
        provisional_by_leg: BTreeMap::new(),
        pool_reservations: BTreeMap::new(),
        nullifier_reservations: BTreeMap::new(),
        output_reservations: BTreeMap::new(),
        canonical_bytes: 0,
        poisoned: false,
    };
    let mut entries = fs::read_dir(root)
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
    entries.sort_by_key(|entry| {
        let name = entry.file_name();
        let provisional = name
            .to_str()
            .is_some_and(|name| name.ends_with(PROVISIONAL_RECORD_EXTENSION_V1));
        (!provisional, name)
    });
    let mut provisional_records = BTreeMap::new();
    let mut final_records = BTreeMap::new();
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        if name == SIDECAR_TEMP_DIRECTORY_V1 {
            let file_type = entry
                .file_type()
                .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
            if file_type.is_symlink() || !file_type.is_dir() {
                return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
            }
            continue;
        }
        if name == SIDECAR_WRITER_LOCK_FILE_V1 {
            continue;
        }
        let provisional = name.ends_with(PROVISIONAL_RECORD_EXTENSION_V1);
        let digest = if provisional {
            parse_provisional_file_name_v1(&name)?
        } else {
            parse_sidecar_file_name_v1(&name)?
        };
        let metadata = entry
            .metadata()
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        if metadata.len() == 0 || metadata.len() > PRIVATE_SETTLEMENT_SIDECAR_MAX_RECORD_BYTES_V1 {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
        let next_total = state
            .canonical_bytes
            .checked_add(metadata.len())
            .ok_or(PrivateSettlementSidecarStoreErrorV1::CapacityExceeded)?;
        let file = open_owner_file_v1(&entry.path(), &metadata)?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len())
                .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?,
        );
        file.take(PRIVATE_SETTLEMENT_SIDECAR_MAX_RECORD_BYTES_V1 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
        if provisional {
            let record =
                norito::decode_canonical::<DurablePrivateSettlementProvisionalSidecarV1>(&bytes)
                    .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
            record.validate()?;
            if record.payload_digest() != digest {
                return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
            }
            insert_provisional_index_v1(&mut state, &record, metadata.len())?;
            provisional_records.insert(digest, record);
        } else {
            let record = norito::decode_canonical::<DurablePrivateSettlementSidecarV1>(&bytes)
                .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
            record.validate()?;
            if record.payload_digest() != digest {
                return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
            }
            insert_index_v1(&mut state, &record, metadata.len())?;
            final_records.insert(digest, record);
        }
        state.canonical_bytes = next_total;
    }
    let mut reconciled = false;
    for (digest, provisional) in provisional_records {
        let leg_key = provisional.leg_key();
        let Some(final_digest) = state.by_leg.get(&leg_key).copied() else {
            continue;
        };
        if final_digest != digest {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
        let final_record = final_records
            .get(&digest)
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        if !final_matches_provisional_v1(&final_record.sidecar, &provisional) {
            return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
        }
        let metadata = state
            .provisional_index
            .get(&digest)
            .cloned()
            .ok_or(PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
        fs::remove_file(root.join(provisional_file_name_v1(digest)))
            .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
        remove_provisional_index_v1(&mut state, digest, &metadata)?;
        reconciled = true;
    }
    if reconciled {
        sync_directory_v1(root).map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
    }
    let record_count = state
        .index
        .len()
        .checked_add(state.provisional_index.len())
        .ok_or(PrivateSettlementSidecarStoreErrorV1::CapacityExceeded)?;
    if record_count > config.max_records || state.canonical_bytes > config.max_total_bytes {
        return Err(PrivateSettlementSidecarStoreErrorV1::CapacityExceeded);
    }
    Ok(state)
}

fn sidecar_file_name_v1(digest: Hash) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut name = String::with_capacity(64 + SIDECAR_RECORD_EXTENSION_V1.len());
    for byte in digest.as_ref() {
        name.push(char::from(HEX[usize::from(*byte >> 4)]));
        name.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    name.push_str(SIDECAR_RECORD_EXTENSION_V1);
    name
}

fn provisional_file_name_v1(digest: Hash) -> String {
    let mut name = sidecar_file_name_v1(digest);
    name.truncate(name.len() - SIDECAR_RECORD_EXTENSION_V1.len());
    name.push_str(PROVISIONAL_RECORD_EXTENSION_V1);
    name
}

fn parse_sidecar_file_name_v1(name: &str) -> Result<Hash, PrivateSettlementSidecarStoreErrorV1> {
    let hex = name
        .strip_suffix(SIDECAR_RECORD_EXTENSION_V1)
        .ok_or(PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
    if hex.len() != 64
        || hex.as_bytes().iter().any(u8::is_ascii_uppercase)
        || !hex.as_bytes().iter().all(u8::is_ascii_hexdigit)
    {
        return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (hex_nibble_v1(pair[0])? << 4) | hex_nibble_v1(pair[1])?;
    }
    let digest = Hash::prehashed(digest);
    if sidecar_file_name_v1(digest) != name {
        return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
    }
    Ok(digest)
}

fn parse_provisional_file_name_v1(
    name: &str,
) -> Result<Hash, PrivateSettlementSidecarStoreErrorV1> {
    let hex = name
        .strip_suffix(PROVISIONAL_RECORD_EXTENSION_V1)
        .ok_or(PrivateSettlementSidecarStoreErrorV1::Corrupt)?;
    if hex.len() != 64
        || hex.as_bytes().iter().any(u8::is_ascii_uppercase)
        || !hex.as_bytes().iter().all(u8::is_ascii_hexdigit)
    {
        return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (hex_nibble_v1(pair[0])? << 4) | hex_nibble_v1(pair[1])?;
    }
    let digest = Hash::prehashed(digest);
    if provisional_file_name_v1(digest) != name {
        return Err(PrivateSettlementSidecarStoreErrorV1::Corrupt);
    }
    Ok(digest)
}

fn hex_nibble_v1(byte: u8) -> Result<u8, PrivateSettlementSidecarStoreErrorV1> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(PrivateSettlementSidecarStoreErrorV1::Corrupt),
    }
}

fn sync_directory_v1(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

fn open_sidecar_store_roots_v1() -> &'static Mutex<BTreeSet<PathBuf>> {
    static ROOTS: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();
    ROOTS.get_or_init(|| Mutex::new(BTreeSet::new()))
}

fn acquire_sidecar_store_lease_v1(
    canonical_root: PathBuf,
) -> Result<SidecarStoreDirectoryLeaseV1, PrivateSettlementSidecarStoreErrorV1> {
    let mut open_roots = open_sidecar_store_roots_v1()
        .lock()
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::Backend)?;
    if !open_roots.insert(canonical_root.clone()) {
        return Err(PrivateSettlementSidecarStoreErrorV1::StoreAlreadyOpen);
    }
    Ok(SidecarStoreDirectoryLeaseV1 { canonical_root })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::privacy_engines::atomic_private_settlement::test_fixtures::*;
    use crate::private_settlement::protocol::{
        private_settlement_prepare_barrier_v1, private_settlement_prepared_bundle_digest_v1,
    };
    use crate::private_settlement::{
        PrivateSettlementAuditEvaluationV1, PrivateSettlementPhaseSignerV1,
        approve_private_settlement_leg_v1,
        protocol::{
            aggregate_private_settlement_phase_votes_v1, private_settlement_phase_body_v1,
            sign_private_settlement_phase_vote_v1,
        },
        state::{
            authorize_private_settlement_auditor_view_against_governance_v1,
            validated_private_settlement_leg_for_sidecar_test_v1,
        },
    };
    use iroha_crypto::{Algorithm, HybridKeyPair, KeyPair, Signature};
    use iroha_data_model::{
        nexus::{
            ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1, PrivateSettlementAuditPlaintextV1,
            PrivateSettlementAuditPolicyBodyV1, PrivateSettlementAuditorV1,
            PrivateSettlementAuthorityCatalogV1, PrivateSettlementHybridPublicKeyV1,
            PrivateSettlementLegReceiptV1, PrivateSettlementPoolGovernanceLifecycleV1,
            PrivateSettlementPoolGovernanceV1,
        },
        privacy::{PrivacyCommitmentV1, PrivacyNullifierV1, PrivacyPoolIdV1, PrivacyRootV1},
    };

    pub(crate) struct SidecarFixtureV1 {
        pub(crate) sidecar: PrivateSettlementRestrictedSidecarV1,
        pub(crate) validator: PeerId,
        pub(crate) auditor: AccountId,
        pub(crate) signing: KeyPair,
        pub(crate) hybrid: HybridKeyPair,
        additional_auditors: Vec<ApsAuditorCredentialV1>,
        pub(crate) validator_keys: Vec<KeyPair>,
        pub(crate) pool_governance: PrivateSettlementPoolGovernanceV1,
        pub(crate) plaintext: PrivateSettlementAuditPlaintextV1,
    }

    #[test]
    fn sidecar_persistence_frames_keep_distinct_owner_roots_and_reject_malformed_bytes() {
        use crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1;

        let fixture = sidecar_fixture();
        let wire = PrivateSettlementRestrictedSidecarWireV1::from(fixture.sidecar.clone());
        let durable = DurablePrivateSettlementSidecarV1::new(fixture.sidecar.clone());
        let provisional = DurablePrivateSettlementProvisionalSidecarV1::new(
            provisional_material_fixture(&fixture),
            fixture.sidecar.stored_at_height,
        );
        let counts = PrivateSettlementStagedLockCountsV1 {
            pool_heads: 1,
            nullifiers: 2,
            output_commitments: 3,
            total: 6,
        };
        macro_rules! check {
            ($owner:ident, $value:expr) => {
                assert_private_settlement_frame_v1::<$owner>(
                    &$value,
                    concat!(
                        "iroha_core::private_settlement::sidecar_store::",
                        stringify!($owner)
                    ),
                );
            };
        }
        check!(PrivateSettlementStagedLockCountsV1, counts);
        check!(PrivateSettlementRestrictedSidecarWireV1, wire);
        check!(DurablePrivateSettlementSidecarV1, durable);
        check!(DurablePrivateSettlementProvisionalSidecarV1, provisional);
        let wire_frame = norito::encode_canonical(&wire).expect("immutable sidecar frame");
        assert!(matches!(
            norito::decode_canonical::<DurablePrivateSettlementSidecarV1>(&wire_frame),
            Err(norito::Error::SchemaMismatch)
        ));
        let mut invalid_lifecycle = durable;
        invalid_lifecycle.version = 0;
        let encoded = norito::encode_canonical(&invalid_lifecycle).expect("structural frame");
        let recovered: DurablePrivateSettlementSidecarV1 = norito::decode_canonical(&encoded)
            .expect("payload reconstruction preserves validation ownership");
        assert_eq!(
            recovered.validate(),
            Err(PrivateSettlementSidecarStoreErrorV1::Corrupt)
        );
    }

    pub(crate) fn sidecar_fixture() -> SidecarFixtureV1 {
        sidecar_fixture_with_threshold(1)
    }

    pub(crate) fn provisional_material_fixture(
        fixture: &SidecarFixtureV1,
    ) -> PrivateSettlementProvisionalLegMaterialV1 {
        let mut manifest = fixture.sidecar.manifest.clone();
        for leg in &mut manifest.legs {
            leg.availability_certificate_digest = Hash::prehashed([0; Hash::LENGTH]);
        }
        let payload = &fixture.sidecar.payload;
        let material = PrivateSettlementProvisionalLegMaterialV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            manifest,
            audit_policy: fixture.sidecar.policy.clone(),
            committee_authority: fixture.sidecar.authority.clone(),
            statement: payload.statement.clone(),
            proof: payload.proof.clone(),
            delta: payload.delta.clone(),
            audit_capsule: payload.audit_capsule.clone(),
            availability_body: payload.availability.body,
        };
        material.validate().expect("provisional material fixture");
        material
    }

    pub(crate) fn sidecar_fixture_with_threshold(min_approvals: u8) -> SidecarFixtureV1 {
        sidecar_fixture_with_threshold_and_ordinal(min_approvals, 0)
    }

    fn sidecar_fixture_with_threshold_and_ordinal(
        min_approvals: u8,
        ordinal: u8,
    ) -> SidecarFixtureV1 {
        let material =
            aps_sidecar_material_fixture_with_threshold_and_ordinal_v1(min_approvals, ordinal);
        let parts = material.sidecar;
        let sidecar = PrivateSettlementRestrictedSidecarV1 {
            manifest: parts.manifest,
            policy: parts.policy,
            authority: parts.authority,
            payload: parts.payload,
            stored_at_height: 11,
        };
        sidecar.validate().expect("complete fixture");
        SidecarFixtureV1 {
            sidecar,
            validator: material.validator,
            auditor: material.auditor,
            signing: material.signing,
            hybrid: material.hybrid,
            additional_auditors: material.additional_auditors,
            validator_keys: material.validator_keys,
            pool_governance: material.pool_governance,
            plaintext: material.plaintext,
        }
    }

    fn extend_sidecar_retention(fixture: &mut SidecarFixtureV1, retention_until_height: u64) {
        fixture
            .sidecar
            .payload
            .availability
            .body
            .retention_until_height = retention_until_height;
        let preimage = fixture
            .sidecar
            .payload
            .availability
            .signature_preimage()
            .expect("retention availability preimage");
        let signatures = fixture.validator_keys[..3]
            .iter()
            .map(|key| {
                Signature::try_new(key.private_key(), &preimage)
                    .expect("retention availability signature")
                    .payload()
                    .to_vec()
            })
            .collect::<Vec<_>>();
        let signature_refs = signatures.iter().map(Vec::as_slice).collect::<Vec<_>>();
        fixture.sidecar.payload.availability.aggregate_signature =
            iroha_crypto::bls_normal_aggregate_signatures(&signature_refs)
                .expect("retention availability aggregate");
        fixture.sidecar.manifest.legs[0].availability_certificate_digest = fixture
            .sidecar
            .payload
            .availability
            .digest()
            .expect("retention availability digest");
        fixture
            .sidecar
            .validate()
            .expect("retention-extended sidecar");
    }

    fn make_successor_policy(
        fixture: &SidecarFixtureV1,
        auditor_id: AccountId,
        signing: &KeyPair,
        hybrid: &HybridKeyPair,
    ) -> PrivateSettlementAuditPolicyV1 {
        PrivateSettlementAuditPolicyV1::new(PrivateSettlementAuditPolicyBodyV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            dataspace_id: fixture.sidecar.policy.body.dataspace_id,
            policy_id: fixture.sidecar.policy.body.policy_id,
            revision: fixture.sidecar.policy.body.revision + 1,
            key_epoch: fixture.sidecar.policy.body.key_epoch + 1,
            activation_height: fixture
                .sidecar
                .policy
                .body
                .retirement_height
                .expect("fixture predecessor retires")
                - 100,
            retirement_height: None,
            min_approvals: 1,
            auditors: vec![PrivateSettlementAuditorV1 {
                auditor_id,
                signing_key: signing.public_key().clone(),
                encryption_key: PrivateSettlementHybridPublicKeyV1::from_hybrid(hybrid.public()),
            }],
        })
        .expect("successor policy")
    }

    fn successor_governance_projection(
        fixture: &SidecarFixtureV1,
        policy: &PrivateSettlementAuditPolicyV1,
    ) -> PrivateSettlementPoolGovernanceProjectionV1 {
        let current =
            PrivateSettlementPoolGovernanceProjectionV1::from_restricted(&fixture.pool_governance)
                .expect("current projection");
        let lifecycle = PrivateSettlementPoolGovernanceLifecycleV1 {
            governance_revision: current.lifecycle.governance_revision + 1,
            activation_height: current
                .lifecycle
                .retirement_height
                .expect("fixture governance predecessor retires"),
            retirement_height: policy.body.retirement_height,
        };
        let replacement = PrivateSettlementPoolGovernanceV1::from_restricted_mapping(
            fixture.pool_governance.body.route,
            fixture.pool_governance.body.pool_id,
            fixture.pool_governance.body.asset_definition_id.clone(),
            fixture.pool_governance.body.asset_binding_salt,
            policy,
            lifecycle,
        )
        .expect("restricted replacement governance");
        current
            .with_replacement(PrivateSettlementPoolGovernanceProjectionV1 {
                version: replacement.body.version,
                route: replacement.body.route,
                pool_id: replacement.body.pool_id,
                asset_binding_commitment: replacement.body.asset_binding_commitment,
                audit_policy_digest: replacement.body.audit_policy_digest,
                audit_key_epoch: replacement.body.audit_key_epoch,
                lifecycle: replacement.body.lifecycle,
                governance_digest: replacement.governance_digest,
                prior_revisions: Vec::new(),
            })
            .expect("successor projection")
    }

    pub(crate) fn audit_approval(
        store: &PrivateSettlementFileSidecarStoreV1,
        fixture: &SidecarFixtureV1,
        digest: Hash,
        height: u64,
    ) -> PrivateSettlementAuditApprovalV1 {
        audit_approval_with_credentials(
            store,
            fixture,
            digest,
            height,
            &fixture.auditor,
            &fixture.hybrid,
            &fixture.signing,
        )
    }

    fn audit_approval_with_credentials(
        store: &PrivateSettlementFileSidecarStoreV1,
        fixture: &SidecarFixtureV1,
        digest: Hash,
        height: u64,
        auditor: &AccountId,
        hybrid: &HybridKeyPair,
        signing: &KeyPair,
    ) -> PrivateSettlementAuditApprovalV1 {
        let view = store
            .fetch_for_auditor(digest, auditor, height)
            .expect("auditor view");
        approve_private_settlement_leg_v1(
            &view,
            &fixture.pool_governance,
            height,
            auditor,
            hybrid.secret(),
            signing,
            &approve_all_audit_material,
        )
        .expect("auditor approval")
    }

    fn approve_all_audit_material(_: PrivateSettlementAuditEvaluationV1<'_>) -> bool {
        true
    }

    fn phase_certificate(
        fixture: &SidecarFixtureV1,
        phase: PrivateSettlementPhaseV1,
        prepared_bundle_digest: Hash,
    ) -> PrivateSettlementPhaseCertificateV1 {
        phase_certificate_for(
            &fixture.sidecar.manifest,
            &fixture.sidecar.payload.delta,
            &fixture.sidecar.authority,
            &fixture.validator_keys,
            phase,
            prepared_bundle_digest,
        )
    }

    fn phase_certificate_for(
        manifest: &AtomicPrivateSettlementV1,
        delta: &PrivateSettlementDeltaV1,
        authority: &PrivateSettlementCommitteeAuthorityV1,
        validator_keys: &[KeyPair],
        phase: PrivateSettlementPhaseV1,
        prepared_bundle_digest: Hash,
    ) -> PrivateSettlementPhaseCertificateV1 {
        let body = private_settlement_phase_body_v1(
            manifest,
            delta,
            authority,
            phase,
            prepared_bundle_digest,
        )
        .expect("phase body");
        let votes = validator_keys[..3]
            .iter()
            .map(|key| sign_private_settlement_phase_vote_v1(body, key).expect("phase vote"))
            .collect::<Vec<_>>();
        aggregate_private_settlement_phase_votes_v1(body, delta.leg_ordinal, authority, &votes)
            .expect("phase certificate")
    }

    fn stage_fixture(
        store: &PrivateSettlementFileSidecarStoreV1,
        fixture: &SidecarFixtureV1,
        digest: Hash,
    ) {
        store.store(fixture.sidecar.clone()).expect("store fixture");
        let approval = audit_approval(store, fixture, digest, 12);
        store
            .record_audited(digest, vec![approval.clone()], 12)
            .expect("durably audit fixture");
        let availability = store
            .durable_availability_evidence(digest)
            .expect("durable fixture availability");
        let verified = validated_private_settlement_leg_for_sidecar_test_v1(
            &fixture.sidecar.manifest,
            &fixture.sidecar.payload,
            &[approval],
            availability.evidence_digest(),
            12,
        );
        store
            .stage_verified(digest, verified, 12)
            .expect("durably stage fixture");
    }

    fn global_receipt_fixture(fixture: &SidecarFixtureV1) -> PrivateSettlementReceiptV1 {
        let second_manifest_leg = fixture.sidecar.manifest.legs[1];
        let second_delta =
            other_leg_delta_v1(&fixture.sidecar.manifest, &fixture.sidecar.payload.delta);
        let mut second_authority = fixture.sidecar.authority.clone();
        second_authority.route = second_manifest_leg.route;
        let local_prepare = phase_certificate(
            fixture,
            PrivateSettlementPhaseV1::Prepare,
            private_settlement_reserved_prepared_bundle_digest_v1(),
        );
        let second_prepare = phase_certificate_for(
            &fixture.sidecar.manifest,
            &second_delta,
            &second_authority,
            &fixture.validator_keys,
            PrivateSettlementPhaseV1::Prepare,
            private_settlement_reserved_prepared_bundle_digest_v1(),
        );
        let authorities = vec![fixture.sidecar.authority.clone(), second_authority.clone()];
        let authority_catalog = PrivateSettlementAuthorityCatalogV1::from_leg_authorities(
            &fixture.sidecar.manifest,
            &authorities,
        )
        .expect("fixture authority catalog");
        let prepared_bundle_digest = private_settlement_prepared_bundle_digest_v1(
            &fixture.sidecar.manifest,
            &authority_catalog,
            &[fixture.sidecar.payload.delta.clone(), second_delta.clone()],
            &[local_prepare.clone(), second_prepare.clone()],
        )
        .expect("prepared fixture bundle digest");
        let local_commit = phase_certificate(
            fixture,
            PrivateSettlementPhaseV1::Commit,
            prepared_bundle_digest,
        );
        let second_commit = phase_certificate_for(
            &fixture.sidecar.manifest,
            &second_delta,
            &second_authority,
            &fixture.validator_keys,
            PrivateSettlementPhaseV1::Commit,
            prepared_bundle_digest,
        );
        PrivateSettlementReceiptV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            manifest: fixture.sidecar.manifest.clone(),
            authority_catalog,
            legs: vec![
                PrivateSettlementLegReceiptV1 {
                    delta: fixture.sidecar.payload.delta.clone(),
                    prepare: local_prepare,
                    commit: local_commit,
                },
                PrivateSettlementLegReceiptV1 {
                    delta: second_delta,
                    prepare: second_prepare,
                    commit: second_commit,
                },
            ],
            finalized_height: 15,
        }
    }

    fn commit_certified_fixture(
        store: &PrivateSettlementFileSidecarStoreV1,
        fixture: &SidecarFixtureV1,
        digest: Hash,
    ) -> PrivateSettlementReceiptV1 {
        stage_fixture(store, fixture, digest);
        let receipt = global_receipt_fixture(fixture);
        let local_leg = &receipt.legs[0];
        store
            .record_prepare_certificate(digest, local_leg.prepare.clone(), 13)
            .expect("durable fixture Prepare QC");
        store
            .record_commit_certificate(
                digest,
                local_leg.commit.clone(),
                local_leg.commit.body.prepared_bundle_digest,
                14,
            )
            .expect("durable fixture Commit QC");
        receipt
    }

    fn abort_receipt(
        fixture: &SidecarFixtureV1,
        finalized_height: u64,
        reason: PrivateSettlementAbortReasonV1,
    ) -> PrivateSettlementAbortReceiptV1 {
        PrivateSettlementAbortReceiptV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            network_id: fixture.sidecar.manifest.network_id,
            bundle_id: fixture.sidecar.manifest.bundle_id,
            manifest_digest: fixture
                .sidecar
                .manifest
                .manifest_digest()
                .expect("fixture manifest digest"),
            finalized_height,
            reason,
        }
    }

    #[test]
    fn configuration_and_lifecycle_are_closed() {
        assert_eq!(
            PrivateSettlementSidecarStoreConfigV1::new(0, 1),
            Err(PrivateSettlementSidecarStoreErrorV1::ConfigurationInvalid)
        );
        assert_eq!(
            PrivateSettlementSidecarStoreConfigV1::new(
                PRIVATE_SETTLEMENT_SIDECAR_HARD_MAX_RECORDS_V1 + 1,
                1,
            ),
            Err(PrivateSettlementSidecarStoreErrorV1::ConfigurationInvalid)
        );
        assert!(
            PrivateSettlementSidecarLifecycleV1::Collecting
                .permits(PrivateSettlementSidecarLifecycleV1::Aborted)
        );
        assert!(
            !PrivateSettlementSidecarLifecycleV1::Collecting
                .permits(PrivateSettlementSidecarLifecycleV1::Audited)
        );
        assert!(
            !PrivateSettlementSidecarLifecycleV1::Finalized
                .permits(PrivateSettlementSidecarLifecycleV1::Prepared)
        );
    }

    #[test]
    fn pool_head_nullifier_and_output_reservations_are_exclusive_and_releasable() {
        let pool = PrivacyPoolIdV1::new([0xE1; 32]);
        let participant_route = route(1);
        let reservations = PrivateSettlementReservationKeysV1 {
            pool_head: (participant_route, pool, 4, PrivacyRootV1::new([0xE2; 32])),
            nullifiers: vec![
                (participant_route, pool, PrivacyNullifierV1::new([0xE3; 32])),
                (participant_route, pool, PrivacyNullifierV1::new([0xE4; 32])),
            ],
            output_commitments: vec![
                (
                    participant_route,
                    pool,
                    PrivacyCommitmentV1::new([0xE5; 32]),
                ),
                (
                    participant_route,
                    pool,
                    PrivacyCommitmentV1::new([0xE6; 32]),
                ),
                (
                    participant_route,
                    pool,
                    PrivacyCommitmentV1::new([0xE7; 32]),
                ),
            ],
        };
        let other_route_reservations = PrivateSettlementReservationKeysV1 {
            pool_head: (
                route(2),
                reservations.pool_head.1,
                reservations.pool_head.2,
                reservations.pool_head.3,
            ),
            nullifiers: reservations
                .nullifiers
                .iter()
                .map(|(_, pool, nullifier)| (route(2), *pool, *nullifier))
                .collect(),
            output_commitments: reservations
                .output_commitments
                .iter()
                .map(|(_, pool, commitment)| (route(2), *pool, *commitment))
                .collect(),
        };
        let owner_a = Hash::new(b"bundle-a");
        let owner_b = Hash::new(b"bundle-b");
        let mut state = SidecarStoreStateV1 {
            index: BTreeMap::new(),
            by_leg: BTreeMap::new(),
            provisional_index: BTreeMap::new(),
            provisional_by_leg: BTreeMap::new(),
            pool_reservations: BTreeMap::new(),
            nullifier_reservations: BTreeMap::new(),
            output_reservations: BTreeMap::new(),
            canonical_bytes: 0,
            poisoned: false,
        };

        insert_reservations_v1(&mut state, owner_a, Some(&reservations))
            .expect("first reservation");
        assert_eq!(
            ensure_reservations_available_v1(&state, owner_b, Some(&reservations)),
            Err(PrivateSettlementSidecarStoreErrorV1::Conflict)
        );
        ensure_reservations_available_v1(&state, owner_b, Some(&other_route_reservations))
            .expect("identical opaque values in a different route are independent");
        remove_reservations_v1(&mut state, owner_a, Some(&reservations)).expect("terminal release");
        ensure_reservations_available_v1(&state, owner_b, Some(&reservations))
            .expect("released resources can be reserved by another bundle");
    }

    #[test]
    fn public_bundle_status_accepts_sparse_local_ordinals_after_restart() {
        let fixture = sidecar_fixture_with_threshold_and_ordinal(1, 1);
        assert_eq!(fixture.sidecar.payload.statement.leg_ordinal, 1);
        fixture
            .sidecar
            .validate()
            .expect("bound nonzero-ordinal sidecar");
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("restricted-sidecars");
        let store =
            PrivateSettlementFileSidecarStoreV1::open(&root, crate::private_settlement::sidecar_store::PrivateSettlementSidecarStoreConfigV1::default()).expect("store");
        store
            .store(fixture.sidecar.clone())
            .expect("store actual leg one");
        drop(store);
        let store =
            PrivateSettlementFileSidecarStoreV1::open(&root, crate::private_settlement::sidecar_store::PrivateSettlementSidecarStoreConfigV1::default()).expect("reopen");
        let status = store
            .public_bundle_status(fixture.sidecar.manifest.bundle_id, 12)
            .expect("sparse local subset");
        assert_eq!(status.manifest, fixture.sidecar.manifest);
        assert_eq!(status.durable_legs, 1);
        assert_eq!(
            status.lifecycle,
            PrivateSettlementSidecarLifecycleV1::Collecting
        );
        assert_eq!(status.lifecycle_height, fixture.sidecar.stored_at_height);
    }

    #[test]
    fn public_bundle_status_rejects_index_key_misbinding() {
        let fixture = sidecar_fixture_with_threshold_and_ordinal(1, 1);
        let temp = tempfile::tempdir().expect("tempdir");
        let store = PrivateSettlementFileSidecarStoreV1::open(
            temp.path().join("restricted-sidecars"),
            crate::private_settlement::sidecar_store::PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("store");
        store
            .store(fixture.sidecar.clone())
            .expect("store actual leg one");
        let bundle = fixture.sidecar.manifest.bundle_id;
        let digest = fixture.sidecar.payload_digest();
        for incorrect_ordinal in [0, 2] {
            let mut state = store.state.lock().expect("state");
            state.by_leg.remove(&(bundle, 1));
            state.by_leg.insert((bundle, incorrect_ordinal), digest);
            drop(state);
            assert_eq!(
                store.public_bundle_status(bundle, 12),
                Err(PrivateSettlementSidecarStoreErrorV1::Corrupt)
            );
            let mut state = store.state.lock().expect("state");
            state.by_leg.remove(&(bundle, incorrect_ordinal));
            state.by_leg.insert((bundle, 1), digest);
        }
        let wrong_bundle = hash(0xFE);
        store
            .state
            .lock()
            .expect("state")
            .by_leg
            .insert((wrong_bundle, 1), digest);
        assert_eq!(
            store.public_bundle_status(wrong_bundle, 12),
            Err(PrivateSettlementSidecarStoreErrorV1::Corrupt)
        );
    }

    #[test]
    fn durable_access_restart_lifecycle_and_retention_are_fail_closed() {
        let fixture = sidecar_fixture();
        let digest = fixture.sidecar.payload_digest();
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("restricted-sidecars");
        let store = PrivateSettlementFileSidecarStoreV1::open(
            &root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("open store");
        assert_eq!(
            store.store(fixture.sidecar.clone()).expect("first store"),
            PrivateSettlementSidecarStoreOutcomeV1::Stored
        );
        assert_eq!(
            store
                .store(fixture.sidecar.clone())
                .expect("idempotent store"),
            PrivateSettlementSidecarStoreOutcomeV1::AlreadyStored
        );
        let bundle_status = store
            .public_bundle_status(fixture.sidecar.manifest.bundle_id, 12)
            .expect("public bundle status");
        assert_eq!(bundle_status.manifest, fixture.sidecar.manifest);
        assert_eq!(bundle_status.durable_legs, 1);
        assert_eq!(
            bundle_status.lifecycle,
            PrivateSettlementSidecarLifecycleV1::Collecting
        );
        assert_eq!(
            PrivateSettlementFileSidecarStoreV1::open(
                &root,
                PrivateSettlementSidecarStoreConfigV1::default(),
            )
            .expect_err("second live opener must fail"),
            PrivateSettlementSidecarStoreErrorV1::StoreAlreadyOpen
        );

        let committee = store
            .fetch_for_committee(digest, &fixture.validator, 12)
            .expect("committee fetch");
        assert_eq!(committee.proof, fixture.sidecar.payload.proof);
        let unknown_validator = PeerId::from(
            KeyPair::from_seed(vec![0xF1; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        assert_eq!(
            store.fetch_for_committee(digest, &unknown_validator, 12),
            Err(PrivateSettlementSidecarStoreErrorV1::Unavailable)
        );
        let auditor = store
            .fetch_for_auditor(digest, &fixture.auditor, 12)
            .expect("auditor fetch");
        assert_eq!(auditor.audit_capsule, fixture.sidecar.payload.audit_capsule);
        let unknown_auditor = AccountId::new(
            KeyPair::from_seed(vec![0xF2; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        assert_eq!(
            store.fetch_for_auditor(digest, &unknown_auditor, 12),
            Err(PrivateSettlementSidecarStoreErrorV1::Unavailable)
        );
        let approval = audit_approval(&store, &fixture, digest, 12);
        store
            .record_audited(digest, vec![approval.clone()], 12)
            .expect("record audited");
        assert_eq!(
            store
                .fetch_for_committee(digest, &fixture.validator, 12)
                .expect("audited committee view")
                .audit_approvals,
            vec![approval.clone()]
        );
        let availability = store
            .durable_availability_evidence(digest)
            .expect("durable availability evidence");
        let verified = validated_private_settlement_leg_for_sidecar_test_v1(
            &fixture.sidecar.manifest,
            &fixture.sidecar.payload,
            &[approval],
            availability.evidence_digest(),
            12,
        );
        store.stage_verified(digest, verified, 12).expect("stage");
        assert_eq!(store.prune(1_000).expect("in-flight prune"), 0);
        drop(store);

        let reopened = PrivateSettlementFileSidecarStoreV1::open(
            &root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("reopen");
        let committee = reopened
            .fetch_for_committee(digest, &fixture.validator, 20)
            .expect("recovered committee fetch");
        assert_eq!(
            committee.lifecycle,
            PrivateSettlementSidecarLifecycleV1::Prepared
        );
        let committee_debug = format!("{committee:?}");
        assert!(!committee_debug.contains("proof"));
        assert!(!committee_debug.contains(&hex::encode(&committee.proof)));
        let abort = abort_receipt(
            &fixture,
            21,
            PrivateSettlementAbortReasonV1::ParticipantRejected,
        );
        assert_eq!(
            reopened
                .reconcile_terminal_state(digest, None, Some(&abort), 21)
                .expect("authoritative abort"),
            PrivateSettlementReconciliationOutcomeV1::Aborted
        );
        assert_eq!(reopened.prune(120).expect("through-height retention"), 0);
        assert_eq!(reopened.prune(121).expect("retention prune"), 1);
        assert_eq!(
            reopened.fetch_for_committee(digest, &fixture.validator, 120),
            Err(PrivateSettlementSidecarStoreErrorV1::Unavailable)
        );
    }

    #[test]
    fn multi_auditor_threshold_is_collected_canonically_across_restart() {
        let fixture = sidecar_fixture_with_threshold(2);
        let digest = fixture.sidecar.payload_digest();
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("multi-auditor-sidecars");
        let store = PrivateSettlementFileSidecarStoreV1::open(
            &root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("open store");
        store.store(fixture.sidecar.clone()).expect("store");

        let governance =
            PrivateSettlementPoolGovernanceProjectionV1::from_restricted(&fixture.pool_governance)
                .expect("governance projection");
        assert_eq!(
            store.auditor_material_v1(digest, 10),
            Err(PrivateSettlementSidecarStoreErrorV1::Unavailable)
        );
        let view = store
            .auditor_material_v1(digest, 12)
            .expect("exact target material");
        let authenticated_auditor =
            authorize_private_settlement_auditor_view_against_governance_v1(
                &governance,
                &fixture.sidecar.manifest.network_id,
                &fixture.sidecar.policy,
                fixture.signing.public_key(),
                12,
                view.clone(),
            )
            .expect("governed signing key resolves without caller-selected identity");
        assert_eq!(authenticated_auditor.auditor_id, fixture.auditor);
        assert_eq!(authenticated_auditor.access_policy, fixture.sidecar.policy);
        let authenticated_debug = format!("{authenticated_auditor:?}");
        assert!(!authenticated_debug.contains("auditor_id"));
        assert!(!authenticated_debug.contains(&fixture.auditor.to_string()));
        let unknown_signer = KeyPair::from_seed(vec![0xF4; 32], Algorithm::Ed25519);
        assert_eq!(
            authorize_private_settlement_auditor_view_against_governance_v1(
                &governance,
                &fixture.sidecar.manifest.network_id,
                &fixture.sidecar.policy,
                unknown_signer.public_key(),
                12,
                view,
            ),
            Err(PrivateSettlementSidecarStoreErrorV1::Unavailable)
        );

        let initial = store.public_status(digest, 12).expect("public status");
        assert_eq!(
            initial.lifecycle,
            PrivateSettlementSidecarLifecycleV1::Collecting
        );

        let first = audit_approval(&store, &fixture, digest, 12);
        let first_outcome = store
            .record_audit_approval(digest, first.clone(), 12)
            .expect("first approval is durable");
        assert_eq!(
            first_outcome,
            PrivateSettlementAuditCollectionOutcomeV1 {
                collected: 1,
                required: 2,
                newly_recorded: true,
                audited: false,
            }
        );
        assert_eq!(
            store
                .public_status(digest, 12)
                .expect("partial status")
                .lifecycle,
            PrivateSettlementSidecarLifecycleV1::Collecting
        );
        drop(store);

        let reopened = PrivateSettlementFileSidecarStoreV1::open(
            &root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("partial threshold survives restart");
        let partial = reopened
            .public_status(digest, 13)
            .expect("recovered status");
        assert_eq!(
            partial.lifecycle,
            PrivateSettlementSidecarLifecycleV1::Collecting
        );

        let second_credentials = fixture
            .additional_auditors
            .first()
            .expect("second auditor credentials");
        let second = audit_approval_with_credentials(
            &reopened,
            &fixture,
            digest,
            13,
            &second_credentials.auditor,
            &second_credentials.hybrid,
            &second_credentials.signing,
        );
        let second_outcome = reopened
            .record_audit_approval(digest, second.clone(), 13)
            .expect("threshold approval is durable");
        assert_eq!(second_outcome.collected, 2);
        assert_eq!(second_outcome.required, 2);
        assert!(second_outcome.newly_recorded);
        assert!(second_outcome.audited);

        let retry = reopened
            .record_audit_approval(digest, second, 13)
            .expect("exact retry is idempotent");
        assert!(!retry.newly_recorded);
        assert!(retry.audited);
        let committee = reopened
            .fetch_for_committee(digest, &fixture.validator, 13)
            .expect("committee sees canonical threshold evidence");
        assert_eq!(
            committee.lifecycle,
            PrivateSettlementSidecarLifecycleV1::Audited
        );
        assert_eq!(committee.audit_approvals.len(), 2);
        assert!(
            committee
                .audit_approvals
                .windows(2)
                .all(|pair| pair[0].body.auditor_id < pair[1].body.auditor_id)
        );
    }

    #[test]
    fn governed_auditor_access_uses_current_key_and_stable_historical_identity() {
        let mut fixture = sidecar_fixture();
        extend_sidecar_retention(&mut fixture, 600);
        let digest = fixture.sidecar.payload_digest();
        let temp = tempfile::tempdir().expect("tempdir");
        let store = PrivateSettlementFileSidecarStoreV1::open(
            temp.path().join("rotated-auditor-access"),
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("open store");
        store.store(fixture.sidecar.clone()).expect("store");

        let successor_signing = KeyPair::from_seed(vec![0xD1; 32], Algorithm::Ed25519);
        let mut successor_hybrid_rng =
            iroha_crypto::rng_from_seed_slice(b"successor auditor encryption key");
        let successor_hybrid =
            HybridKeyPair::generate(&mut successor_hybrid_rng).expect("successor hybrid key");
        let successor_policy = make_successor_policy(
            &fixture,
            fixture.auditor.clone(),
            &successor_signing,
            &successor_hybrid,
        );
        let successor_governance = successor_governance_projection(&fixture, &successor_policy);
        assert!(
            successor_policy.body.activation_height
                < successor_governance.lifecycle.activation_height,
            "a pre-activated restricted policy is selected only by the WSV governance revision"
        );
        let historical_view = store
            .auditor_material_v1(digest, 500)
            .expect("retained historical capsule");
        let historical = authorize_private_settlement_auditor_view_against_governance_v1(
            &successor_governance,
            &fixture.sidecar.manifest.network_id,
            &successor_policy,
            successor_signing.public_key(),
            500,
            historical_view.clone(),
        )
        .expect("same stable auditor may fetch the retained old wrapped capsule");
        assert_eq!(historical.auditor_id, fixture.auditor);
        assert_eq!(historical.access_policy, successor_policy);
        assert!(
            historical
                .view
                .audit_capsule
                .wrapped_deks
                .iter()
                .any(|wrapped| wrapped.auditor_id == historical.auditor_id)
        );

        let unavailable = PrivateSettlementSidecarStoreErrorV1::Unavailable;
        assert_eq!(
            authorize_private_settlement_auditor_view_against_governance_v1(
                &successor_governance,
                &fixture.sidecar.manifest.network_id,
                &successor_policy,
                fixture.signing.public_key(),
                500,
                historical_view.clone(),
            ),
            Err(unavailable),
            "the retired signing key cannot authenticate under the current WSV policy"
        );
        let mut wrong_route_view = historical_view.clone();
        wrong_route_view.statement.route = route(8);
        assert_eq!(
            authorize_private_settlement_auditor_view_against_governance_v1(
                &successor_governance,
                &fixture.sidecar.manifest.network_id,
                &successor_policy,
                successor_signing.public_key(),
                500,
                wrong_route_view,
            ),
            Err(unavailable),
            "a retained capsule from another route cannot inherit access"
        );
        let mut wrong_pool_view = historical_view.clone();
        wrong_pool_view.statement.pool_id = PrivacyPoolIdV1::new([0xEE; 32]);
        assert_eq!(
            authorize_private_settlement_auditor_view_against_governance_v1(
                &successor_governance,
                &fixture.sidecar.manifest.network_id,
                &successor_policy,
                successor_signing.public_key(),
                500,
                wrong_pool_view,
            ),
            Err(unavailable),
            "a retained capsule from another pool cannot inherit access"
        );

        let unrelated_signing = KeyPair::from_seed(vec![0xD2; 32], Algorithm::Ed25519);
        let unrelated_id = AccountId::new(unrelated_signing.public_key().clone());
        let mut unrelated_hybrid_rng =
            iroha_crypto::rng_from_seed_slice(b"unrelated successor encryption key");
        let unrelated_hybrid =
            HybridKeyPair::generate(&mut unrelated_hybrid_rng).expect("unrelated hybrid key");
        let unrelated_policy = make_successor_policy(
            &fixture,
            unrelated_id,
            &unrelated_signing,
            &unrelated_hybrid,
        );
        let unrelated_governance = successor_governance_projection(&fixture, &unrelated_policy);
        assert_eq!(
            authorize_private_settlement_auditor_view_against_governance_v1(
                &unrelated_governance,
                &fixture.sidecar.manifest.network_id,
                &successor_policy,
                successor_signing.public_key(),
                500,
                historical_view.clone(),
            ),
            Err(unavailable),
            "a full policy must match the exact active WSV policy digest and epoch"
        );
        assert_eq!(
            authorize_private_settlement_auditor_view_against_governance_v1(
                &unrelated_governance,
                &fixture.sidecar.manifest.network_id,
                &unrelated_policy,
                unrelated_signing.public_key(),
                500,
                historical_view,
            ),
            Err(unavailable),
            "a different stable auditor must not inherit historical capsule access"
        );
    }

    #[test]
    fn audited_prepare_commit_and_global_receipt_are_durable_and_typed() {
        let fixture = sidecar_fixture();
        let second_manifest_leg = fixture.sidecar.manifest.legs[1];
        let second_delta =
            other_leg_delta_v1(&fixture.sidecar.manifest, &fixture.sidecar.payload.delta);
        assert_eq!(
            fixture.sidecar.manifest.legs[1].delta_digest,
            second_delta.digest().expect("second delta digest")
        );

        let digest = fixture.sidecar.payload_digest();
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("typed-lifecycle-sidecars");
        let store = PrivateSettlementFileSidecarStoreV1::open(
            &root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("open store");
        store.store(fixture.sidecar.clone()).expect("store");
        let approval = audit_approval(&store, &fixture, digest, 12);
        store
            .record_audited(digest, vec![approval.clone()], 12)
            .expect("audited");
        let availability = store
            .durable_availability_evidence(digest)
            .expect("durable availability");
        let verified = validated_private_settlement_leg_for_sidecar_test_v1(
            &fixture.sidecar.manifest,
            &fixture.sidecar.payload,
            &[approval],
            availability.evidence_digest(),
            12,
        );
        store
            .stage_verified(digest, verified, 12)
            .expect("prepared");

        let mut second_authority = fixture.sidecar.authority.clone();
        second_authority.route = second_manifest_leg.route;
        let local_prepare = phase_certificate(
            &fixture,
            PrivateSettlementPhaseV1::Prepare,
            private_settlement_reserved_prepared_bundle_digest_v1(),
        );
        let second_prepare = phase_certificate_for(
            &fixture.sidecar.manifest,
            &second_delta,
            &second_authority,
            &fixture.validator_keys,
            PrivateSettlementPhaseV1::Prepare,
            private_settlement_reserved_prepared_bundle_digest_v1(),
        );
        let authorities = vec![fixture.sidecar.authority.clone(), second_authority.clone()];
        let authority_catalog = PrivateSettlementAuthorityCatalogV1::from_leg_authorities(
            &fixture.sidecar.manifest,
            &authorities,
        )
        .expect("fixture authority catalog");
        let prepared_bundle_digest = private_settlement_prepared_bundle_digest_v1(
            &fixture.sidecar.manifest,
            &authority_catalog,
            &[fixture.sidecar.payload.delta.clone(), second_delta.clone()],
            &[local_prepare.clone(), second_prepare.clone()],
        )
        .expect("prepared bundle digest");
        let barrier = private_settlement_prepare_barrier_v1(
            fixture.sidecar.manifest.clone(),
            vec![fixture.sidecar.authority.clone(), second_authority.clone()],
            vec![fixture.sidecar.payload.delta.clone(), second_delta.clone()],
            vec![local_prepare.clone(), second_prepare.clone()],
        )
        .expect("complete Prepare barrier");
        assert_eq!(
            store.commit_phase_body(digest, &fixture.validator, &barrier, 13),
            Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition),
            "Commit must fail before the local Prepare QC is durable"
        );
        assert_eq!(local_prepare.signers_bitmap, 0b0111);
        let fourth_validator =
            PrivateSettlementPhaseSignerV1::new(fixture.validator_keys[3].clone())
                .expect("fourth committee phase signer");
        fourth_validator
            .persist_certificate(
                &store,
                &fixture.sidecar.manifest,
                digest,
                local_prepare.clone(),
                13,
            )
            .expect("a staged committee node may retain an exact QC it did not sign");
        let record_path = root.join(sidecar_file_name_v1(digest));
        let before_commit_vote = fs::read(&record_path).expect("read journal before Commit vote");
        let commit_body = store
            .commit_phase_body(digest, &fixture.validator, &barrier, 13)
            .expect("complete barrier and local Prepare QC admit Commit");
        let outside_validator = PeerId::from(
            KeyPair::from_seed(vec![0xD7; 32], Algorithm::BlsNormal)
                .public_key()
                .clone(),
        );
        assert_eq!(
            store.commit_phase_body(digest, &outside_validator, &barrier, 13),
            Err(PrivateSettlementSidecarStoreErrorV1::Unavailable),
            "a signer outside the exact local roster is indistinguishably unavailable"
        );
        assert_eq!(commit_body.prepared_bundle_digest, prepared_bundle_digest);
        assert_eq!(
            fs::read(&record_path).expect("read journal after Commit vote"),
            before_commit_vote,
            "Commit candidate construction is read-only"
        );
        drop(store);
        let store = PrivateSettlementFileSidecarStoreV1::open(
            &root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("reopen after durable Prepare QC");
        assert_eq!(
            store
                .commit_phase_body(digest, &fixture.validator, &barrier, 13)
                .expect("Prepare QC survives restart"),
            commit_body
        );
        let local_commit = phase_certificate(
            &fixture,
            PrivateSettlementPhaseV1::Commit,
            prepared_bundle_digest,
        );
        assert_eq!(
            store.record_commit_certificate(
                digest,
                local_commit.clone(),
                Hash::new(b"substituted prepared bundle"),
                14,
            ),
            Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition)
        );
        store
            .record_commit_certificate(digest, local_commit.clone(), prepared_bundle_digest, 14)
            .expect("commit QC");
        drop(store);
        let store = PrivateSettlementFileSidecarStoreV1::open(
            &root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("reopen after durable Commit QC");
        let commit_certified_record =
            fs::read(&record_path).expect("read Commit-certified journal");
        let sponsor_recovery = store
            .sponsor_phase_certificates(digest, &fixture.sidecar.manifest.sponsor, 15)
            .expect("exact sponsor recovers both durable QCs");
        assert_eq!(
            sponsor_recovery.prepare_certificate,
            Some(local_prepare.clone())
        );
        assert_eq!(
            sponsor_recovery.commit_certificate,
            Some(local_commit.clone())
        );
        assert_eq!(
            sponsor_recovery.lifecycle,
            PrivateSettlementSidecarLifecycleV1::CommitCertified
        );
        let wrong_sponsor = AccountId::new(
            KeyPair::from_seed(vec![0x3B; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        assert_eq!(
            store.sponsor_phase_certificates(digest, &wrong_sponsor, 15),
            Err(PrivateSettlementSidecarStoreErrorV1::Unavailable)
        );
        assert_eq!(
            store.sponsor_phase_certificates(
                digest,
                &fixture.sidecar.manifest.sponsor,
                fixture
                    .sidecar
                    .payload
                    .availability
                    .body
                    .retention_until_height
                    + 1,
            ),
            Err(PrivateSettlementSidecarStoreErrorV1::Unavailable)
        );
        store
            .record_prepare_certificate(digest, local_prepare.clone(), 15)
            .expect("exact Prepare QC replay survives restart after Commit certification");
        assert_eq!(
            store
                .public_status(digest, 15)
                .expect("Commit-certified replay status")
                .lifecycle,
            PrivateSettlementSidecarLifecycleV1::CommitCertified,
            "replaying older phase evidence must not regress lifecycle"
        );
        assert_eq!(
            fs::read(&record_path).expect("read journal after exact Prepare QC replay"),
            commit_certified_record,
            "exact Prepare QC replay after Commit certification must be write-free"
        );
        let alternate_prepare_votes = fixture.validator_keys[1..]
            .iter()
            .map(|key| {
                sign_private_settlement_phase_vote_v1(local_prepare.body, key)
                    .expect("alternate Prepare vote")
            })
            .collect::<Vec<_>>();
        let alternate_prepare = aggregate_private_settlement_phase_votes_v1(
            local_prepare.body,
            local_prepare.authority_catalog_index,
            &fixture.sidecar.authority,
            &alternate_prepare_votes,
        )
        .expect("quorum-equivalent Prepare QC");
        assert_ne!(alternate_prepare, local_prepare);
        let mut recovered_barrier = barrier.clone();
        recovered_barrier.prepare_certificates[0] = alternate_prepare.clone();
        assert_eq!(
            store
                .commit_phase_body(digest, &fixture.validator, &recovered_barrier, 15)
                .expect("quorum-equivalent barrier admits Commit after recovery"),
            commit_body,
            "Commit identity must not depend on the recovered Prepare signer subset"
        );
        store
            .record_prepare_certificate(digest, alternate_prepare.clone(), 15)
            .expect("quorum-equivalent Prepare replay survives restart");
        assert_eq!(
            fs::read(&record_path).expect("read journal after equivalent Prepare QC replay"),
            commit_certified_record,
            "quorum-equivalent Prepare QC replay must be write-free"
        );
        let alternate_commit_votes = fixture.validator_keys[1..]
            .iter()
            .map(|key| {
                sign_private_settlement_phase_vote_v1(local_commit.body, key)
                    .expect("alternate Commit vote")
            })
            .collect::<Vec<_>>();
        let alternate_commit = aggregate_private_settlement_phase_votes_v1(
            local_commit.body,
            local_commit.authority_catalog_index,
            &fixture.sidecar.authority,
            &alternate_commit_votes,
        )
        .expect("quorum-equivalent Commit QC");
        assert_ne!(alternate_commit, local_commit);
        store
            .record_commit_certificate(digest, alternate_commit.clone(), prepared_bundle_digest, 15)
            .expect("quorum-equivalent Commit replay survives restart");
        assert_eq!(
            fs::read(&record_path).expect("read journal after equivalent Commit QC replay"),
            commit_certified_record,
            "quorum-equivalent Commit QC replay must be write-free"
        );
        let second_commit = phase_certificate_for(
            &fixture.sidecar.manifest,
            &second_delta,
            &second_authority,
            &fixture.validator_keys,
            PrivateSettlementPhaseV1::Commit,
            prepared_bundle_digest,
        );
        let receipt = PrivateSettlementReceiptV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            manifest: fixture.sidecar.manifest.clone(),
            authority_catalog,
            legs: vec![
                PrivateSettlementLegReceiptV1 {
                    delta: fixture.sidecar.payload.delta.clone(),
                    prepare: alternate_prepare,
                    commit: alternate_commit,
                },
                PrivateSettlementLegReceiptV1 {
                    delta: second_delta,
                    prepare: second_prepare,
                    commit: second_commit,
                },
            ],
            finalized_height: 15,
        };
        store
            .finalize_with_receipt(digest, &receipt)
            .expect("global finality");
        store
            .finalize_with_receipt(digest, &receipt)
            .expect("idempotent global finality");
        assert_eq!(
            store
                .fetch_for_committee(digest, &fixture.validator, 15)
                .expect("finalized view")
                .lifecycle,
            PrivateSettlementSidecarLifecycleV1::Finalized
        );
        drop(store);

        let reopened = PrivateSettlementFileSidecarStoreV1::open(
            &root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("restart reconciliation");
        assert_eq!(
            reopened
                .fetch_for_committee(digest, &fixture.validator, 16)
                .expect("restarted finalized view")
                .lifecycle,
            PrivateSettlementSidecarLifecycleV1::Finalized
        );
    }

    #[test]
    fn finality_reconciliation_is_exact_idempotent_restart_safe_and_releases_reservations() {
        let fixture = sidecar_fixture();
        let digest = fixture.sidecar.payload_digest();
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("receipt-reconciliation-sidecars");
        let store = PrivateSettlementFileSidecarStoreV1::open(
            &root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("open store");
        let receipt = commit_certified_fixture(&store, &fixture, digest);
        let page = store
            .reconciliation_page(None, 1)
            .expect("bounded startup page");
        assert_eq!(page.candidates.len(), 1);
        assert_eq!(page.candidates[0].payload_digest, digest);
        assert_eq!(page.candidates[0].bundle_id, receipt.manifest.bundle_id);
        assert_eq!(
            page.candidates[0].lifecycle,
            PrivateSettlementSidecarLifecycleV1::CommitCertified
        );
        assert!(
            store
                .state
                .lock()
                .expect("store state")
                .pool_reservations
                .values()
                .any(|owner| *owner == digest),
            "CommitCertified must retain its staged pool reservation"
        );
        let record_path = root.join(sidecar_file_name_v1(digest));
        let before_reconciliation = fs::read(&record_path).expect("read CommitCertified record");
        let ambiguous_abort = abort_receipt(
            &fixture,
            14,
            PrivateSettlementAbortReasonV1::ParticipantRejected,
        );
        assert_eq!(
            store.reconcile_terminal_state(digest, Some(&receipt), Some(&ambiguous_abort), 15,),
            Err(PrivateSettlementSidecarStoreErrorV1::Conflict)
        );
        assert_eq!(
            fs::read(&record_path).expect("read after ambiguous WSV terminal rows"),
            before_reconciliation
        );

        // Simulate a crash after immutable WSV finality but before the local
        // sidecar transition by reopening only after the receipt exists.
        drop(store);
        let reopened = PrivateSettlementFileSidecarStoreV1::open(
            &root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("reopen after finality gap");
        assert_eq!(
            reopened
                .reconcile_terminal_state(digest, Some(&receipt), None, 15)
                .expect("reconcile exact WSV receipt"),
            PrivateSettlementReconciliationOutcomeV1::Finalized
        );
        let finalized_bytes = fs::read(&record_path).expect("read finalized record");
        assert_ne!(finalized_bytes, before_reconciliation);
        assert!(
            reopened
                .state
                .lock()
                .expect("reopened state")
                .pool_reservations
                .values()
                .all(|owner| *owner != digest),
            "reservation release occurs only after the terminal record is durable"
        );

        assert_eq!(
            reopened
                .reconcile_terminal_state(digest, Some(&receipt), None, 20)
                .expect("exact receipt retry"),
            PrivateSettlementReconciliationOutcomeV1::Finalized
        );
        assert_eq!(
            fs::read(&record_path).expect("read idempotent finalized record"),
            finalized_bytes
        );
        let mut substituted = receipt.clone();
        substituted.finalized_height += 1;
        assert_eq!(
            reopened.reconcile_terminal_state(digest, Some(&substituted), None, 20),
            Err(PrivateSettlementSidecarStoreErrorV1::Conflict)
        );
        assert_eq!(
            fs::read(&record_path).expect("read after substituted receipt"),
            finalized_bytes,
            "a substituted globally valid receipt must not rewrite local finality"
        );
        let complete_page = reopened
            .reconciliation_page(None, 1)
            .expect("terminal page");
        assert!(complete_page.candidates.is_empty());
        assert!(complete_page.next_cursor.is_none());
        drop(reopened);

        let restarted = PrivateSettlementFileSidecarStoreV1::open(
            &root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("restart finalized store");
        assert_eq!(
            restarted
                .reconcile_terminal_state(digest, Some(&receipt), None, 21)
                .expect("receipt survives another restart"),
            PrivateSettlementReconciliationOutcomeV1::Finalized
        );
        assert_eq!(
            fs::read(record_path).expect("read twice-restarted record"),
            finalized_bytes
        );
    }

    #[test]
    fn exact_global_receipt_recovers_every_valid_local_prefix() {
        let fixture = sidecar_fixture();
        let digest = fixture.sidecar.payload_digest();
        let receipt = global_receipt_fixture(&fixture);
        let temp = tempfile::tempdir().expect("tempdir");

        let collecting_root = temp.path().join("collecting-receipt-recovery");
        let collecting = PrivateSettlementFileSidecarStoreV1::open(
            &collecting_root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("open collecting store");
        collecting
            .store(fixture.sidecar.clone())
            .expect("store collecting fixture");
        assert_eq!(
            collecting
                .reconcile_terminal_state(digest, Some(&receipt), None, 15)
                .expect("receipt recovers Collecting prefix"),
            PrivateSettlementReconciliationOutcomeV1::Finalized
        );
        drop(collecting);
        let collecting_restarted = PrivateSettlementFileSidecarStoreV1::open(
            &collecting_root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("restart collecting-prefix finality");
        assert_eq!(
            collecting_restarted
                .public_status(digest, 16)
                .expect("collecting-prefix terminal status")
                .lifecycle,
            PrivateSettlementSidecarLifecycleV1::Finalized
        );

        let audited_root = temp.path().join("audited-receipt-recovery");
        let audited = PrivateSettlementFileSidecarStoreV1::open(
            &audited_root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("open audited store");
        audited
            .store(fixture.sidecar.clone())
            .expect("store audited fixture");
        let approval = audit_approval(&audited, &fixture, digest, 12);
        audited
            .record_audited(digest, vec![approval], 12)
            .expect("durably audit fixture");
        assert_eq!(
            audited
                .reconcile_terminal_state(digest, Some(&receipt), None, 15)
                .expect("receipt recovers Audited prefix"),
            PrivateSettlementReconciliationOutcomeV1::Finalized
        );
        drop(audited);
        let audited_restarted = PrivateSettlementFileSidecarStoreV1::open(
            &audited_root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("restart audited-prefix finality");
        assert_eq!(
            audited_restarted
                .public_status(digest, 16)
                .expect("audited-prefix terminal status")
                .lifecycle,
            PrivateSettlementSidecarLifecycleV1::Finalized
        );

        let prepared_root = temp.path().join("prepared-receipt-recovery");
        let prepared = PrivateSettlementFileSidecarStoreV1::open(
            &prepared_root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("open prepared store");
        stage_fixture(&prepared, &fixture, digest);
        assert!(
            prepared
                .state
                .lock()
                .expect("prepared state")
                .pool_reservations
                .values()
                .any(|owner| *owner == digest)
        );
        assert_eq!(
            prepared
                .reconcile_terminal_state(digest, Some(&receipt), None, 15)
                .expect("receipt recovers Prepared prefix without a local QC"),
            PrivateSettlementReconciliationOutcomeV1::Finalized
        );
        assert!(
            prepared
                .state
                .lock()
                .expect("prepared terminal state")
                .pool_reservations
                .values()
                .all(|owner| *owner != digest)
        );
        drop(prepared);
        let prepared_restarted = PrivateSettlementFileSidecarStoreV1::open(
            &prepared_root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("restart prepared-prefix finality");
        let recovered = prepared_restarted
            .fetch_for_committee(digest, &fixture.validator, 16)
            .expect("prepared-prefix terminal record");
        assert_eq!(
            recovered.lifecycle,
            PrivateSettlementSidecarLifecycleV1::Finalized
        );
        assert!(
            recovered.audit_approvals.len()
                >= usize::from(fixture.sidecar.policy.body.min_approvals)
        );
    }

    #[test]
    fn authoritative_terminal_markers_override_delayed_valid_local_prefixes() {
        let fixture = sidecar_fixture();
        let digest = fixture.sidecar.payload_digest();
        let receipt = global_receipt_fixture(&fixture);
        let delayed_height = receipt.finalized_height + 1;
        let temp = tempfile::tempdir().expect("tempdir");

        let receipt_root = temp.path().join("delayed-prefix-receipt-recovery");
        let receipt_store = PrivateSettlementFileSidecarStoreV1::open(
            &receipt_root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("open delayed receipt store");
        stage_fixture(&receipt_store, &fixture, digest);
        receipt_store
            .record_prepare_certificate(digest, receipt.legs[0].prepare.clone(), delayed_height)
            .expect("persist delayed local Prepare after global finality");
        assert_eq!(
            receipt_store
                .public_status(digest, delayed_height)
                .expect("delayed receipt prefix")
                .lifecycle_height,
            delayed_height
        );
        assert_eq!(
            receipt_store
                .reconcile_terminal_state(digest, Some(&receipt), None, delayed_height)
                .expect("older exact receipt overrides delayed local prefix"),
            PrivateSettlementReconciliationOutcomeV1::Finalized
        );
        let receipt_status = receipt_store
            .public_status(digest, delayed_height)
            .expect("reconciled delayed receipt status");
        assert_eq!(
            receipt_status.lifecycle,
            PrivateSettlementSidecarLifecycleV1::Finalized
        );
        assert_eq!(receipt_status.lifecycle_height, delayed_height);
        assert!(
            receipt_store
                .state
                .lock()
                .expect("delayed receipt state")
                .pool_reservations
                .values()
                .all(|owner| *owner != digest)
        );

        let abort_root = temp.path().join("delayed-prefix-abort-recovery");
        let abort_store = PrivateSettlementFileSidecarStoreV1::open(
            &abort_root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("open delayed abort store");
        stage_fixture(&abort_store, &fixture, digest);
        abort_store
            .record_prepare_certificate(digest, receipt.legs[0].prepare.clone(), delayed_height)
            .expect("persist delayed local Prepare before observing abort");
        let abort = abort_receipt(
            &fixture,
            receipt.finalized_height,
            PrivateSettlementAbortReasonV1::ParticipantRejected,
        );
        assert_eq!(
            abort_store
                .reconcile_terminal_state(digest, None, Some(&abort), delayed_height)
                .expect("older exact abort overrides delayed local prefix"),
            PrivateSettlementReconciliationOutcomeV1::Aborted
        );
        let abort_status = abort_store
            .public_status(digest, delayed_height)
            .expect("reconciled delayed abort status");
        assert_eq!(
            abort_status.lifecycle,
            PrivateSettlementSidecarLifecycleV1::Aborted
        );
        assert_eq!(abort_status.lifecycle_height, delayed_height);
        assert!(
            abort_store
                .state
                .lock()
                .expect("delayed abort state")
                .pool_reservations
                .values()
                .all(|owner| *owner != digest)
        );
        drop(abort_store);
        let abort_restarted = PrivateSettlementFileSidecarStoreV1::open(
            &abort_root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("restart delayed abort recovery");
        assert_eq!(
            abort_restarted
                .reconcile_terminal_state(digest, None, Some(&abort), delayed_height + 1)
                .expect("delayed abort recovery is idempotent after restart"),
            PrivateSettlementReconciliationOutcomeV1::Aborted
        );
    }

    #[test]
    fn abort_and_height_expiry_reconciliation_are_bound_durable_and_idempotent() {
        let fixture = sidecar_fixture();
        let digest = fixture.sidecar.payload_digest();
        let temp = tempfile::tempdir().expect("tempdir");

        let abort_root = temp.path().join("abort-reconciliation-sidecars");
        let abort_store = PrivateSettlementFileSidecarStoreV1::open(
            &abort_root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("open abort store");
        stage_fixture(&abort_store, &fixture, digest);
        let abort_path = abort_root.join(sidecar_file_name_v1(digest));
        let prepared_bytes = fs::read(&abort_path).expect("read prepared abort candidate");
        let mut substituted_abort = abort_receipt(
            &fixture,
            20,
            PrivateSettlementAbortReasonV1::ParticipantRejected,
        );
        substituted_abort.manifest_digest = Hash::new(b"substituted manifest");
        assert_eq!(
            abort_store.reconcile_terminal_state(digest, None, Some(&substituted_abort), 20),
            Err(PrivateSettlementSidecarStoreErrorV1::InvalidTransition)
        );
        assert_eq!(
            fs::read(&abort_path).expect("read after substituted abort"),
            prepared_bytes
        );
        assert!(
            abort_store
                .state
                .lock()
                .expect("abort store state")
                .pool_reservations
                .values()
                .any(|owner| *owner == digest)
        );
        let abort = abort_receipt(
            &fixture,
            20,
            PrivateSettlementAbortReasonV1::ParticipantRejected,
        );
        assert_eq!(
            abort_store
                .reconcile_terminal_state(digest, None, Some(&abort), 20)
                .expect("exact abort marker"),
            PrivateSettlementReconciliationOutcomeV1::Aborted
        );
        let aborted_bytes = fs::read(&abort_path).expect("read aborted record");
        assert!(
            abort_store
                .state
                .lock()
                .expect("aborted store state")
                .pool_reservations
                .values()
                .all(|owner| *owner != digest)
        );
        assert_eq!(
            abort_store
                .reconcile_terminal_state(digest, None, Some(&abort), 30)
                .expect("exact abort retry"),
            PrivateSettlementReconciliationOutcomeV1::Aborted
        );
        assert_eq!(
            fs::read(&abort_path).expect("read idempotent abort record"),
            aborted_bytes
        );
        drop(abort_store);
        let abort_restarted = PrivateSettlementFileSidecarStoreV1::open(
            &abort_root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("restart aborted store");
        assert_eq!(
            abort_restarted
                .reconcile_terminal_state(digest, None, Some(&abort), 31)
                .expect("abort survives restart"),
            PrivateSettlementReconciliationOutcomeV1::Aborted
        );

        let expiry_root = temp.path().join("expiry-reconciliation-sidecars");
        let expiry_store = PrivateSettlementFileSidecarStoreV1::open(
            &expiry_root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("open expiry store");
        stage_fixture(&expiry_store, &fixture, digest);
        let expiry_path = expiry_root.join(sidecar_file_name_v1(digest));
        let pre_expiry_bytes = fs::read(&expiry_path).expect("read pre-expiry record");
        assert_eq!(
            expiry_store
                .reconcile_terminal_state(
                    digest,
                    None,
                    None,
                    fixture.sidecar.manifest.expiry_height,
                )
                .expect("expiry height itself is not terminal"),
            PrivateSettlementReconciliationOutcomeV1::Pending
        );
        assert_eq!(
            fs::read(&expiry_path).expect("read at expiry height"),
            pre_expiry_bytes
        );
        let observed_expiry_height = fixture.sidecar.manifest.expiry_height + 1;
        assert_eq!(
            expiry_store
                .reconcile_terminal_state(digest, None, None, observed_expiry_height)
                .expect("authoritative height expiry"),
            PrivateSettlementReconciliationOutcomeV1::Expired
        );
        let locally_expired_bytes = fs::read(&expiry_path).expect("read expired record");
        assert!(
            expiry_store
                .state
                .lock()
                .expect("expired store state")
                .pool_reservations
                .values()
                .all(|owner| *owner != digest)
        );
        assert_eq!(
            expiry_store
                .reconcile_terminal_state(digest, None, None, observed_expiry_height + 5)
                .expect("height-expiry retry"),
            PrivateSettlementReconciliationOutcomeV1::Expired
        );
        assert_eq!(
            fs::read(&expiry_path).expect("read idempotent expiry record"),
            locally_expired_bytes
        );

        let expiry_abort = abort_receipt(
            &fixture,
            observed_expiry_height,
            PrivateSettlementAbortReasonV1::Expired,
        );
        assert_eq!(
            expiry_store
                .reconcile_terminal_state(
                    digest,
                    None,
                    Some(&expiry_abort),
                    observed_expiry_height,
                )
                .expect("upgrade local expiry to authoritative marker"),
            PrivateSettlementReconciliationOutcomeV1::Expired
        );
        let marker_expired_bytes = fs::read(&expiry_path).expect("read marker-backed expiry");
        assert_ne!(marker_expired_bytes, locally_expired_bytes);
        assert_eq!(
            expiry_store
                .reconcile_terminal_state(
                    digest,
                    None,
                    Some(&expiry_abort),
                    observed_expiry_height + 1,
                )
                .expect("authoritative expiry-marker retry"),
            PrivateSettlementReconciliationOutcomeV1::Expired
        );
        assert_eq!(
            fs::read(&expiry_path).expect("read idempotent marker expiry"),
            marker_expired_bytes
        );
        drop(expiry_store);
        let expiry_restarted = PrivateSettlementFileSidecarStoreV1::open(
            &expiry_root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("restart expired store");
        assert_eq!(
            expiry_restarted
                .reconcile_terminal_state(
                    digest,
                    None,
                    Some(&expiry_abort),
                    observed_expiry_height + 2,
                )
                .expect("expiry marker survives restart"),
            PrivateSettlementReconciliationOutcomeV1::Expired
        );
    }

    #[test]
    fn unaudited_and_partial_approval_expiry_survive_restart() {
        let temp = tempfile::tempdir().expect("tempdir");

        let unaudited_fixture = sidecar_fixture();
        let unaudited_digest = unaudited_fixture.sidecar.payload_digest();
        let unaudited_root = temp.path().join("unaudited-expiry-recovery");
        let unaudited = PrivateSettlementFileSidecarStoreV1::open(
            &unaudited_root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("open unaudited store");
        unaudited
            .store(unaudited_fixture.sidecar.clone())
            .expect("store unaudited sidecar");
        let unaudited_expiry = unaudited_fixture.sidecar.manifest.expiry_height + 1;
        assert_eq!(
            unaudited
                .reconcile_terminal_state(unaudited_digest, None, None, unaudited_expiry)
                .expect("expire unaudited sidecar"),
            PrivateSettlementReconciliationOutcomeV1::Expired
        );
        drop(unaudited);
        let unaudited_restarted = PrivateSettlementFileSidecarStoreV1::open(
            &unaudited_root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("restart unaudited expiry");
        let unaudited_status = unaudited_restarted
            .public_status(unaudited_digest, unaudited_expiry)
            .expect("unaudited expiry status");
        assert_eq!(
            unaudited_status.lifecycle,
            PrivateSettlementSidecarLifecycleV1::Expired
        );

        let partial_fixture = sidecar_fixture_with_threshold(2);
        let partial_digest = partial_fixture.sidecar.payload_digest();
        let partial_root = temp.path().join("partial-audit-expiry-recovery");
        let partial = PrivateSettlementFileSidecarStoreV1::open(
            &partial_root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("open partial-approval store");
        partial
            .store(partial_fixture.sidecar.clone())
            .expect("store partial-approval sidecar");
        let first = audit_approval(&partial, &partial_fixture, partial_digest, 12);
        let collected = partial
            .record_audit_approval(partial_digest, first, 12)
            .expect("record partial approval");
        assert_eq!(collected.collected, 1);
        assert!(!collected.audited);
        let partial_expiry = partial_fixture.sidecar.manifest.expiry_height + 1;
        assert_eq!(
            partial
                .reconcile_terminal_state(partial_digest, None, None, partial_expiry)
                .expect("expire partial-approval sidecar"),
            PrivateSettlementReconciliationOutcomeV1::Expired
        );
        let partial_path = partial_root.join(sidecar_file_name_v1(partial_digest));
        let partial_expired_bytes = fs::read(&partial_path).expect("read partial-approval expiry");
        drop(partial);
        let partial_restarted = PrivateSettlementFileSidecarStoreV1::open(
            &partial_root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("restart partial-approval expiry");
        let partial_status = partial_restarted
            .public_status(partial_digest, partial_expiry)
            .expect("partial expiry status");
        assert_eq!(
            partial_status.lifecycle,
            PrivateSettlementSidecarLifecycleV1::Expired
        );
        assert_eq!(
            partial_restarted
                .reconcile_terminal_state(partial_digest, None, None, partial_expiry + 5)
                .expect("partial expiry retry"),
            PrivateSettlementReconciliationOutcomeV1::Expired
        );
        assert_eq!(
            fs::read(partial_path).expect("read retried partial expiry"),
            partial_expired_bytes
        );
    }

    #[test]
    fn substitution_expiry_and_redaction_checks_are_enforced() {
        let fixture = sidecar_fixture();
        let digest = fixture.sidecar.payload_digest();
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("restricted-sidecars");
        let store = PrivateSettlementFileSidecarStoreV1::open(
            &root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("open store");
        store.store(fixture.sidecar.clone()).expect("store");
        let mut substituted = fixture.sidecar.clone();
        substituted.authority.validator_pops[0][0] ^= 1;
        assert_eq!(
            store.store(substituted),
            Err(PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)
        );
        let mut signature_substitution = fixture.sidecar.clone();
        signature_substitution
            .payload
            .availability
            .aggregate_signature[0] ^= 1;
        assert_eq!(
            store.store(signature_substitution),
            Err(PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)
        );
        let mut body_substitution = fixture.sidecar.clone();
        body_substitution
            .payload
            .availability
            .body
            .retention_until_height += 1;
        assert_eq!(
            store.store(body_substitution),
            Err(PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)
        );
        let mut roster_aad_substitution = fixture.sidecar.clone();
        roster_aad_substitution
            .payload
            .audit_capsule
            .aad
            .authority_digest = Hash::new(b"substituted capsule authority");
        assert_eq!(
            store.store(roster_aad_substitution),
            Err(PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)
        );
        let mut context_aad_substitution = fixture.sidecar.clone();
        context_aad_substitution
            .payload
            .audit_capsule
            .aad
            .authority_context_height += 1;
        assert_eq!(
            store.store(context_aad_substitution),
            Err(PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)
        );
        let mut four_signers = fixture.sidecar.clone();
        four_signers.payload.availability.signers_bitmap = 0b1111;
        assert_eq!(
            store.store(four_signers),
            Err(PrivateSettlementSidecarStoreErrorV1::InvalidSidecar)
        );
        let mut same_material_new_observation_height = fixture.sidecar.clone();
        same_material_new_observation_height.stored_at_height += 1;
        assert_eq!(
            store.store(same_material_new_observation_height),
            Ok(PrivateSettlementSidecarStoreOutcomeV1::AlreadyStored),
            "local observation height is not restricted material and cannot make an exact retry conflict"
        );
        assert_eq!(
            store
                .reconcile_terminal_state(
                    digest,
                    None,
                    None,
                    fixture.sidecar.manifest.expiry_height,
                )
                .expect("at-expiry reconciliation"),
            PrivateSettlementReconciliationOutcomeV1::Pending
        );
        assert_eq!(
            store
                .reconcile_terminal_state(
                    digest,
                    None,
                    None,
                    fixture.sidecar.manifest.expiry_height + 1,
                )
                .expect("post-expiry reconciliation"),
            PrivateSettlementReconciliationOutcomeV1::Expired
        );
        let sidecar_debug = format!("{:?}", fixture.sidecar);
        assert!(!sidecar_debug.contains("proof"));
        assert!(!sidecar_debug.contains("ciphertext"));
        let payload_debug = format!("{:?}", fixture.sidecar.payload);
        assert!(!payload_debug.contains("proof"));
        assert!(!payload_debug.contains("ciphertext"));
        assert_eq!(
            format!("{:?}", fixture.sidecar.payload.audit_capsule),
            "PrivateSettlementAuditCapsuleV1(<redacted>)"
        );
        assert_eq!(
            format!(
                "{:?}",
                fixture.sidecar.payload.audit_capsule.wrapped_deks[0]
            ),
            "PrivateSettlementWrappedDekV1(<redacted>)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn restart_cleans_known_temp_and_rejects_tampered_canonical_record() {
        use std::os::unix::fs::OpenOptionsExt as _;

        let fixture = sidecar_fixture();
        let digest = fixture.sidecar.payload_digest();
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("restricted-sidecars");
        let store = PrivateSettlementFileSidecarStoreV1::open(
            &root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("open store");
        store.store(fixture.sidecar).expect("store");
        drop(store);

        let stale = root.join(SIDECAR_TEMP_DIRECTORY_V1).join(format!(
            "{}{}",
            sidecar_file_name_v1(digest),
            SIDECAR_TEMP_EXTENSION_V1
        ));
        let mut stale_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stale)
            .expect("stale temp");
        stale_file.write_all(b"interrupted-write").expect("write");
        stale_file.sync_all().expect("sync");
        drop(stale_file);
        let reopened = PrivateSettlementFileSidecarStoreV1::open(
            &root,
            PrivateSettlementSidecarStoreConfigV1::default(),
        )
        .expect("known temp reconciles");
        assert!(!stale.exists());
        drop(reopened);

        let target = root.join(sidecar_file_name_v1(digest));
        let mut target_file = OpenOptions::new()
            .append(true)
            .open(target)
            .expect("record");
        target_file.write_all(&[0]).expect("tamper");
        target_file.sync_all().expect("sync tamper");
        drop(target_file);
        assert_eq!(
            PrivateSettlementFileSidecarStoreV1::open(
                &root,
                PrivateSettlementSidecarStoreConfigV1::default(),
            )
            .expect_err("tamper must fail"),
            PrivateSettlementSidecarStoreErrorV1::Corrupt
        );
    }
}
