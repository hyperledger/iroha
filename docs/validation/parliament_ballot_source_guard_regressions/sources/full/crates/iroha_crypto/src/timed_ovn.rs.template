//! Timed Open Vote Network ballots with an intrinsic threshold-release term.
//!
//! This fixed v1 construction runs the Open Vote Network in the BLS12-381
//! pairing target group.  Each ballot component is
//! `C = Y^x * G_T^m * A_id^r`, with `U = G2^r` and
//! `A_id = e(H(identity), P_TLE)`.  A generalized three-branch Fiat--Shamir OR
//! proof binds the same registered `x`, the ephemeral `r`, and exactly one of
//! Aye/Nay/Abstain to those public values.  Once the threshold committee
//! releases `d_id`, the aggregate opener removes `e(d_id, sum(U))`; it never
//! exposes a per-ballot opening.
//!
//! Survivor membership is immutable before ballot admission.  Aggregation
//! requires exactly one verified ballot from every survivor, in order.  A
//! missing survivor or withheld release key therefore invalidates the whole
//! attempt; this module intentionally has no plaintext, manual-opening, or
//! post-freeze recovery API.
//!
//! Secret target-group exponentiation uses a fixed 256-round
//! square-and-multiply-always routine and limb-mask selection over the public
//! `blst_fp12` representation.  Its result is deterministic across hardware.
//! Runtime protocol validation does not depend on a mutable audit flag.  The
//! separate official binary-publication corridor must call
//! [`validate_timed_ovn_official_release_audit_manifest_bytes_v1`] and supply
//! the exact independently reviewed source archive, release-artifact manifest,
//! target inventory, report, and evidence archive.  No such external audit
//! artifact is asserted or embedded by this module.

use core::{fmt, marker::PhantomData};
use std::{collections::HashSet, vec::Vec};

use blst::{blst_fp, blst_fp12};
use blstrs::{G1Affine, G2Affine, G2Projective, Scalar};
use group::{Curve as _, Group as _, prime::PrimeCurveAffine as _};
use rand_core::{OsRng, TryCryptoRng};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    threshold_bls::{
        THRESHOLD_BLS_PUBLIC_KEY_BYTES, TLE_RELEASE_SIGNATURE_DST_V1, TleReleasePurpose,
        hash_message_to_g1,
    },
    tle::{TleIdentitySecretKeyV1, TleMasterPublicKey, TleReleaseIdentityV1},
};

/// Fixed protocol version for timed OVN ballots.
pub const TIMED_OVN_PROTOCOL_VERSION_V1: u16 = 1;
/// Exact number of choices: Aye, Nay, and Abstain.
pub const TIMED_OVN_CHOICE_COUNT_V1: usize = 3;
/// Maximum frozen survivor roster accepted by the bounded tally decoder.
pub const TIMED_OVN_MAX_PARTICIPANTS_V1: usize = 1_000;
/// Canonical uncompressed width of one BLS12-381 target-group element.
pub const TIMED_OVN_GT_BYTES_V1: usize = 576;
/// Canonical compressed width of one BLS12-381 G2 point.
pub const TIMED_OVN_G2_BYTES_V1: usize = THRESHOLD_BLS_PUBLIC_KEY_BYTES;
/// Canonical big-endian width of one BLS12-381 scalar.
pub const TIMED_OVN_SCALAR_BYTES_V1: usize = 32;
/// Fixed number of target-group square-and-multiply-always rounds.
pub const TIMED_OVN_CT_SCALAR_BITS_V1: usize = 256;
/// Fixed version of the official-release side-channel audit manifest.
pub const TIMED_OVN_OFFICIAL_RELEASE_AUDIT_MANIFEST_VERSION_V1: u16 = 1;
/// Number of fields in the fixed official-release audit manifest.
pub const TIMED_OVN_OFFICIAL_RELEASE_AUDIT_MANIFEST_FIELD_COUNT_V1: u16 = 11;
/// Fixed width of the signed statement prefix in the audit manifest.
pub const TIMED_OVN_OFFICIAL_RELEASE_AUDIT_STATEMENT_BYTES_V1: usize = 237;
/// Fixed width of the complete canonical audit manifest.
pub const TIMED_OVN_OFFICIAL_RELEASE_AUDIT_MANIFEST_BYTES_V1: usize =
    TIMED_OVN_OFFICIAL_RELEASE_AUDIT_STATEMENT_BYTES_V1 + 64;

const SESSION_DOMAIN_V1: &[u8] = b"iroha.parliament.timed-ovn.session.v1\0";
const PARAMETER_PROFILE_DOMAIN_V1: &[u8] =
    b"iroha.parliament.timed-ovn.fixed-parameter-profile.v1\0";
const SESSION_DIGEST_DOMAIN_V1: &[u8] = b"iroha.parliament.timed-ovn.session-digest.v1\0";
const POP_CHALLENGE_DOMAIN_V1: &[u8] = b"iroha.parliament.timed-ovn.pop.v1\0";
const ROSTER_ROOT_DOMAIN_V1: &[u8] = b"iroha.parliament.timed-ovn.roster-root.v1\0";
const SURVIVOR_ROOT_DOMAIN_V1: &[u8] = b"iroha.parliament.timed-ovn.survivor-root.v1\0";
const BALLOT_CHALLENGE_DOMAIN_V1: &[u8] = b"iroha.parliament.timed-ovn.ballot-or-proof.v1\0";
const REGISTRATION_MAGIC_V1: &[u8; 8] = b"ITOVREG1";
const BALLOT_MAGIC_V1: &[u8; 8] = b"ITOVBAL1";
const OFFICIAL_RELEASE_AUDIT_MANIFEST_MAGIC_V1: &[u8; 8] = b"ITOVAUD1";
const OFFICIAL_RELEASE_AUDIT_SIGNING_DOMAIN_V1: &[u8] =
    b"iroha.parliament.timed-ovn.official-release-audit-signoff.v1\0";
const OFFICIAL_RELEASE_AUDIT_SOURCE_DOMAIN_V1: &[u8] =
    b"iroha.parliament.timed-ovn.official-release-audit.source-archive.v1\0";
const OFFICIAL_RELEASE_AUDIT_ARTIFACT_MANIFEST_DOMAIN_V1: &[u8] =
    b"iroha.parliament.timed-ovn.official-release-audit.artifact-manifest.v1\0";
const OFFICIAL_RELEASE_AUDIT_TARGET_INVENTORY_DOMAIN_V1: &[u8] =
    b"iroha.parliament.timed-ovn.official-release-audit.target-inventory.v1\0";
const OFFICIAL_RELEASE_AUDIT_REPORT_DOMAIN_V1: &[u8] =
    b"iroha.parliament.timed-ovn.official-release-audit.report.v1\0";
const OFFICIAL_RELEASE_AUDIT_EVIDENCE_ARCHIVE_DOMAIN_V1: &[u8] =
    b"iroha.parliament.timed-ovn.official-release-audit.evidence-archive.v1\0";
const OPTION_TAGS_V1: [u8; TIMED_OVN_CHOICE_COUNT_V1] = [0, 1, 2];
const FP_BYTES: usize = 48;
const FP_LIMBS: usize = 6;
const FP12_FIELD_ELEMENTS: usize = 12;
const FP12_LIMBS: usize = FP_LIMBS * FP12_FIELD_ELEMENTS;
const SCALAR_REJECTION_LIMIT: u32 = u16::MAX as u32;
const REGISTRATION_WIRE_BYTES_V1: usize = 8
    + 32 * 2
    + TIMED_OVN_CHOICE_COUNT_V1 * (TIMED_OVN_GT_BYTES_V1 * 2 + TIMED_OVN_SCALAR_BYTES_V1);
const BALLOT_WIRE_BYTES_V1: usize = 8
    + 32 * 5
    + 2
    + TIMED_OVN_CHOICE_COUNT_V1 * TIMED_OVN_G2_BYTES_V1
    + TIMED_OVN_CHOICE_COUNT_V1 * TIMED_OVN_GT_BYTES_V1
    + TIMED_OVN_CHOICE_COUNT_V1 * TIMED_OVN_SCALAR_BYTES_V1
    + 2 * TIMED_OVN_CHOICE_COUNT_V1 * TIMED_OVN_CHOICE_COUNT_V1 * TIMED_OVN_SCALAR_BYTES_V1;

/// Canonical uncompressed encoding of one timed-OVN target-group element.
pub type GtBytes = [u8; TIMED_OVN_GT_BYTES_V1];
/// Canonical compressed encoding of one timed-OVN G2 element.
pub type G2Bytes = [u8; TIMED_OVN_G2_BYTES_V1];
/// Canonical big-endian encoding of one timed-OVN scalar.
pub type ScalarBytes = [u8; TIMED_OVN_SCALAR_BYTES_V1];

/// Closed three-choice Parliament ballot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TimedOvnChoiceV1 {
    /// Approve the proposal.
    Aye = 0,
    /// Reject the proposal.
    Nay = 1,
    /// Count toward turnout without choosing Aye or Nay.
    Abstain = 2,
}

/// Machine-checkable decision in an official-release audit manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TimedOvnOfficialReleaseAuditVerdictV1 {
    /// The reviewed artifact set must not be published as an official build.
    Rejected = 0,
    /// The independent reviewer approved exactly the committed artifact set.
    ApprovedForOfficialRelease = 1,
}

impl TimedOvnOfficialReleaseAuditVerdictV1 {
    fn from_tag(tag: u8) -> Result<Self, TimedOvnError> {
        match tag {
            0 => Ok(Self::Rejected),
            1 => Ok(Self::ApprovedForOfficialRelease),
            _ => Err(TimedOvnError::InvalidOfficialReleaseAuditManifest),
        }
    }
}

impl TimedOvnChoiceV1 {
    const fn index(self) -> usize {
        self as usize
    }
}

/// Errors returned by timed-OVN setup, admission, opening, and tallying.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TimedOvnError {
    /// A required protocol binding was the all-zero placeholder.
    #[error("timed-OVN binding digest must be non-zero")]
    ZeroBinding,
    /// The supplied parameter digest did not name the one fixed v1 suite.
    #[error("timed-OVN parameter hash does not match the fixed v1 suite")]
    ParameterProfileMismatch,
    /// The roster is empty or exceeds the fixed v1 bound.
    #[error("timed-OVN roster size is outside the v1 bound")]
    InvalidRosterSize,
    /// Registrations were not supplied in strictly increasing participant order.
    #[error("timed-OVN registrations are not in canonical participant order")]
    NonCanonicalRoster,
    /// A participant identity appeared more than once.
    #[error("timed-OVN roster contains a duplicate participant")]
    DuplicateParticipant,
    /// A registration target-group key appeared more than once.
    #[error("timed-OVN roster contains a duplicate registration key")]
    DuplicateRegistrationKey,
    /// A survivor was absent from the roster or supplied out of order.
    #[error("timed-OVN survivor list is not a canonical roster subsequence")]
    NonCanonicalSurvivorSet,
    /// Target-group bytes were noncanonical, outside the subgroup, or malformed.
    #[error("invalid canonical BLS12-381 target-group element")]
    InvalidTargetGroupElement,
    /// A G2 encoding was malformed, noncanonical, or outside the prime-order subgroup.
    #[error("invalid canonical BLS12-381 G2 point")]
    InvalidG2Point,
    /// A public key, mask, ephemeral, commitment, or release term was identity.
    #[error("timed-OVN public protocol element must be non-identity")]
    IdentityElement,
    /// A scalar was not canonically encoded.
    #[error("invalid canonical BLS12-381 scalar")]
    InvalidScalar,
    /// Hash-to-scalar rejection sampling exhausted its defensive bound.
    #[error("timed-OVN hash-to-scalar derivation failed")]
    ScalarDerivation,
    /// A registration Schnorr proof of possession failed.
    #[error("timed-OVN registration proof of possession failed")]
    InvalidProofOfPossession,
    /// A ballot generalized one-hot OR proof failed.
    #[error("timed-OVN ballot one-hot proof failed")]
    InvalidBallotProof,
    /// An object was replayed under another session, key, identity, roster, or seat.
    #[error("timed-OVN transcript binding mismatch")]
    BindingMismatch,
    /// The future release identity did not match the ballot session and frozen survivors.
    #[error("timed-OVN future release identity does not match the frozen ballot attempt")]
    InvalidReleaseIdentity,
    /// The secret does not match the participant registration.
    #[error("timed-OVN registration secret does not match the frozen registration")]
    SecretMismatch,
    /// The participant is not in the frozen survivor roster.
    #[error("timed-OVN participant is not in the frozen survivor roster")]
    UnknownParticipant,
    /// The ballot corpus omitted, duplicated, or reordered a survivor.
    #[error("timed-OVN ballot corpus must contain every survivor exactly once in order")]
    NonCanonicalBallotCorpus,
    /// Ephemeral G2 values were duplicated within or across the ballot corpus.
    #[error("timed-OVN ballot corpus contains a duplicate ephemeral")]
    DuplicateEphemeral,
    /// Fallible cryptographic randomness failed.
    #[error("timed-OVN CSPRNG failed")]
    RandomnessUnavailable,
    /// Repeated random material failed to produce a nonzero canonical scalar.
    #[error("timed-OVN CSPRNG returned inert scalar material")]
    InertRandomness,
    /// Wire bytes were truncated, oversized, mistagged, or had trailing data.
    #[error("invalid canonical timed-OVN wire encoding")]
    InvalidEncoding,
    /// The threshold release point was absent, malformed, or bound elsewhere.
    #[error("timed-OVN threshold release failed")]
    ReleaseFailed,
    /// OVN masks or the timed release term did not cancel to a bounded count.
    #[error("timed-OVN aggregate does not decode within the survivor bound")]
    MaskCancellationFailed,
    /// Decoded choice counts did not sum to the exact survivor count.
    #[error("timed-OVN decoded counts do not equal the survivor count")]
    InvalidTally,
    /// The official-release corridor did not supply its required audit manifest.
    #[error("timed-OVN official-release audit evidence is required")]
    OfficialReleaseAuditEvidenceRequired,
    /// The official-release audit manifest was malformed or noncanonical.
    #[error("invalid canonical timed-OVN official-release audit manifest")]
    InvalidOfficialReleaseAuditManifest,
    /// The manifest did not approve publication of the committed artifacts.
    #[error("timed-OVN official-release audit manifest does not approve release")]
    OfficialReleaseAuditNotApproved,
    /// The manifest reviewer did not match the release corridor's trusted key.
    #[error("timed-OVN official-release audit reviewer is not trusted")]
    UntrustedOfficialReleaseAuditReviewer,
    /// The reviewer signature was malformed or invalid.
    #[error("invalid timed-OVN official-release audit reviewer signature")]
    InvalidOfficialReleaseAuditSignature,
    /// Supplied release evidence did not match its signed commitment.
    #[error("timed-OVN official-release audit evidence digest mismatch")]
    OfficialReleaseAuditEvidenceMismatch,
}

/// Exact public artifacts reviewed for one official timed-OVN binary release.
///
/// This borrowed view is release-corridor input. It is not consensus state and
/// must never be consulted by ballot registration, sealing, or opening.
pub struct TimedOvnOfficialReleaseAuditArtifactsV1<'a> {
    implementation_source_archive: &'a [u8],
    release_artifact_manifest: &'a [u8],
    supported_target_inventory: &'a [u8],
    audit_report: &'a [u8],
    audit_evidence_archive: &'a [u8],
}

impl<'a> TimedOvnOfficialReleaseAuditArtifactsV1<'a> {
    /// Bind the exact byte artifacts supplied to the official-release verifier.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError::OfficialReleaseAuditEvidenceRequired`] when any
    /// mandatory artifact is empty.
    pub fn new(
        implementation_source_archive: &'a [u8],
        release_artifact_manifest: &'a [u8],
        supported_target_inventory: &'a [u8],
        audit_report: &'a [u8],
        audit_evidence_archive: &'a [u8],
    ) -> Result<Self, TimedOvnError> {
        if [
            implementation_source_archive,
            release_artifact_manifest,
            supported_target_inventory,
            audit_report,
            audit_evidence_archive,
        ]
        .iter()
        .any(|artifact| artifact.is_empty())
        {
            return Err(TimedOvnError::OfficialReleaseAuditEvidenceRequired);
        }
        Ok(Self {
            implementation_source_archive,
            release_artifact_manifest,
            supported_target_inventory,
            audit_report,
            audit_evidence_archive,
        })
    }
}

/// Signable, fixed-suite statement for an official timed-OVN release audit.
///
/// Constructing a statement does not approve a release. Approval exists only
/// when an independent reviewer signs the canonical bytes and the official
/// release corridor validates the resulting manifest against its configured
/// trusted reviewer key and the exact supplied artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimedOvnOfficialReleaseAuditStatementV1 {
    verdict: TimedOvnOfficialReleaseAuditVerdictV1,
    parameter_hash: [u8; 32],
    implementation_source_archive_digest: [u8; 32],
    release_artifact_manifest_digest: [u8; 32],
    supported_target_inventory_digest: [u8; 32],
    audit_report_digest: [u8; 32],
    audit_evidence_archive_digest: [u8; 32],
    reviewer_public_key: [u8; 32],
}

impl TimedOvnOfficialReleaseAuditStatementV1 {
    /// Derive a statement from the exact public artifacts reviewed externally.
    ///
    /// This helper performs no signing and accepts no private key.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for an invalid reviewer key or malformed
    /// artifact bindings.
    pub fn from_artifacts(
        verdict: TimedOvnOfficialReleaseAuditVerdictV1,
        artifacts: &TimedOvnOfficialReleaseAuditArtifactsV1<'_>,
        reviewer_public_key: [u8; 32],
    ) -> Result<Self, TimedOvnError> {
        parse_official_release_audit_reviewer_key(&reviewer_public_key)?;
        let statement = Self {
            verdict,
            parameter_hash: timed_ovn_parameter_hash_v1(),
            implementation_source_archive_digest: official_release_audit_artifact_digest(
                OFFICIAL_RELEASE_AUDIT_SOURCE_DOMAIN_V1,
                artifacts.implementation_source_archive,
            ),
            release_artifact_manifest_digest: official_release_audit_artifact_digest(
                OFFICIAL_RELEASE_AUDIT_ARTIFACT_MANIFEST_DOMAIN_V1,
                artifacts.release_artifact_manifest,
            ),
            supported_target_inventory_digest: official_release_audit_artifact_digest(
                OFFICIAL_RELEASE_AUDIT_TARGET_INVENTORY_DOMAIN_V1,
                artifacts.supported_target_inventory,
            ),
            audit_report_digest: official_release_audit_artifact_digest(
                OFFICIAL_RELEASE_AUDIT_REPORT_DOMAIN_V1,
                artifacts.audit_report,
            ),
            audit_evidence_archive_digest: official_release_audit_artifact_digest(
                OFFICIAL_RELEASE_AUDIT_EVIDENCE_ARCHIVE_DOMAIN_V1,
                artifacts.audit_evidence_archive,
            ),
            reviewer_public_key,
        };
        statement.validate_shape()?;
        Ok(statement)
    }

    /// Return the canonical bytes an external reviewer must sign.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let statement = self.to_wire_prefix();
        let mut bytes =
            Vec::with_capacity(OFFICIAL_RELEASE_AUDIT_SIGNING_DOMAIN_V1.len() + statement.len());
        bytes.extend_from_slice(OFFICIAL_RELEASE_AUDIT_SIGNING_DOMAIN_V1);
        bytes.extend_from_slice(&statement);
        bytes
    }

    /// Return the manifest's explicit release decision.
    #[must_use]
    pub const fn verdict(&self) -> TimedOvnOfficialReleaseAuditVerdictV1 {
        self.verdict
    }

    /// Return the committed fixed-suite parameter hash.
    #[must_use]
    pub const fn parameter_hash(&self) -> &[u8; 32] {
        &self.parameter_hash
    }

    /// Return the external reviewer's canonical Ed25519 public key.
    #[must_use]
    pub const fn reviewer_public_key(&self) -> &[u8; 32] {
        &self.reviewer_public_key
    }

    fn from_wire_prefix(
        bytes: &[u8; TIMED_OVN_OFFICIAL_RELEASE_AUDIT_STATEMENT_BYTES_V1],
    ) -> Result<Self, TimedOvnError> {
        let mut cursor = 0_usize;
        if take::<8>(bytes, &mut cursor)? != *OFFICIAL_RELEASE_AUDIT_MANIFEST_MAGIC_V1
            || u16::from_be_bytes(take::<2>(bytes, &mut cursor)?)
                != TIMED_OVN_OFFICIAL_RELEASE_AUDIT_MANIFEST_VERSION_V1
            || u16::from_be_bytes(take::<2>(bytes, &mut cursor)?)
                != TIMED_OVN_OFFICIAL_RELEASE_AUDIT_MANIFEST_FIELD_COUNT_V1
        {
            return Err(TimedOvnError::InvalidOfficialReleaseAuditManifest);
        }
        let verdict =
            TimedOvnOfficialReleaseAuditVerdictV1::from_tag(take::<1>(bytes, &mut cursor)?[0])?;
        let statement = Self {
            verdict,
            parameter_hash: take::<32>(bytes, &mut cursor)?,
            implementation_source_archive_digest: take::<32>(bytes, &mut cursor)?,
            release_artifact_manifest_digest: take::<32>(bytes, &mut cursor)?,
            supported_target_inventory_digest: take::<32>(bytes, &mut cursor)?,
            audit_report_digest: take::<32>(bytes, &mut cursor)?,
            audit_evidence_archive_digest: take::<32>(bytes, &mut cursor)?,
            reviewer_public_key: take::<32>(bytes, &mut cursor)?,
        };
        if cursor != bytes.len() {
            return Err(TimedOvnError::InvalidOfficialReleaseAuditManifest);
        }
        statement.validate_shape()?;
        Ok(statement)
    }

    fn to_wire_prefix(self) -> [u8; TIMED_OVN_OFFICIAL_RELEASE_AUDIT_STATEMENT_BYTES_V1] {
        let mut bytes = [0_u8; TIMED_OVN_OFFICIAL_RELEASE_AUDIT_STATEMENT_BYTES_V1];
        let mut cursor = 0_usize;
        append_fixed(
            &mut bytes,
            &mut cursor,
            OFFICIAL_RELEASE_AUDIT_MANIFEST_MAGIC_V1,
        );
        append_fixed(
            &mut bytes,
            &mut cursor,
            &TIMED_OVN_OFFICIAL_RELEASE_AUDIT_MANIFEST_VERSION_V1.to_be_bytes(),
        );
        append_fixed(
            &mut bytes,
            &mut cursor,
            &TIMED_OVN_OFFICIAL_RELEASE_AUDIT_MANIFEST_FIELD_COUNT_V1.to_be_bytes(),
        );
        append_fixed(&mut bytes, &mut cursor, &[self.verdict as u8]);
        for field in [
            &self.parameter_hash,
            &self.implementation_source_archive_digest,
            &self.release_artifact_manifest_digest,
            &self.supported_target_inventory_digest,
            &self.audit_report_digest,
            &self.audit_evidence_archive_digest,
            &self.reviewer_public_key,
        ] {
            append_fixed(&mut bytes, &mut cursor, field);
        }
        debug_assert_eq!(cursor, bytes.len());
        bytes
    }

    fn validate_shape(&self) -> Result<(), TimedOvnError> {
        if self.parameter_hash != timed_ovn_parameter_hash_v1() {
            return Err(TimedOvnError::ParameterProfileMismatch);
        }
        let commitments = [
            self.parameter_hash,
            self.implementation_source_archive_digest,
            self.release_artifact_manifest_digest,
            self.supported_target_inventory_digest,
            self.audit_report_digest,
            self.audit_evidence_archive_digest,
        ];
        if commitments.iter().any(|commitment| is_zero(commitment)) {
            return Err(TimedOvnError::InvalidOfficialReleaseAuditManifest);
        }
        for (index, commitment) in commitments.iter().enumerate() {
            if commitments[..index].contains(commitment) {
                return Err(TimedOvnError::InvalidOfficialReleaseAuditManifest);
            }
        }
        parse_official_release_audit_reviewer_key(&self.reviewer_public_key)?;
        Ok(())
    }
}

/// Canonical signed manifest consumed only by the official-release corridor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimedOvnOfficialReleaseAuditManifestV1 {
    statement: TimedOvnOfficialReleaseAuditStatementV1,
    reviewer_signature: [u8; 64],
}

impl TimedOvnOfficialReleaseAuditManifestV1 {
    /// Assemble a manifest from an externally signed statement.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] when the statement is malformed or its
    /// Ed25519 signature does not verify under its embedded reviewer key.
    pub fn from_statement_and_signature(
        statement: TimedOvnOfficialReleaseAuditStatementV1,
        reviewer_signature: [u8; 64],
    ) -> Result<Self, TimedOvnError> {
        statement.validate_shape()?;
        verify_official_release_audit_signature(&statement, &reviewer_signature)?;
        Ok(Self {
            statement,
            reviewer_signature,
        })
    }

    /// Decode a fully consuming fixed-width manifest and verify its signature.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for missing, malformed, noncanonical, or
    /// incorrectly signed bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TimedOvnError> {
        if bytes.is_empty() {
            return Err(TimedOvnError::OfficialReleaseAuditEvidenceRequired);
        }
        if bytes.len() != TIMED_OVN_OFFICIAL_RELEASE_AUDIT_MANIFEST_BYTES_V1 {
            return Err(TimedOvnError::InvalidOfficialReleaseAuditManifest);
        }
        let prefix: &[u8; TIMED_OVN_OFFICIAL_RELEASE_AUDIT_STATEMENT_BYTES_V1] = bytes
            [..TIMED_OVN_OFFICIAL_RELEASE_AUDIT_STATEMENT_BYTES_V1]
            .try_into()
            .map_err(|_| TimedOvnError::InvalidOfficialReleaseAuditManifest)?;
        let reviewer_signature: [u8; 64] = bytes
            [TIMED_OVN_OFFICIAL_RELEASE_AUDIT_STATEMENT_BYTES_V1..]
            .try_into()
            .map_err(|_| TimedOvnError::InvalidOfficialReleaseAuditManifest)?;
        Self::from_statement_and_signature(
            TimedOvnOfficialReleaseAuditStatementV1::from_wire_prefix(prefix)?,
            reviewer_signature,
        )
    }

    /// Encode the complete canonical fixed-width manifest.
    #[must_use]
    pub fn to_bytes(self) -> [u8; TIMED_OVN_OFFICIAL_RELEASE_AUDIT_MANIFEST_BYTES_V1] {
        let mut bytes = [0_u8; TIMED_OVN_OFFICIAL_RELEASE_AUDIT_MANIFEST_BYTES_V1];
        let statement = self.statement.to_wire_prefix();
        bytes[..statement.len()].copy_from_slice(&statement);
        bytes[statement.len()..].copy_from_slice(&self.reviewer_signature);
        bytes
    }

    /// Return the signed release-audit statement.
    #[must_use]
    pub const fn statement(&self) -> &TimedOvnOfficialReleaseAuditStatementV1 {
        &self.statement
    }

    /// Return the canonical reviewer signature bytes.
    #[must_use]
    pub const fn reviewer_signature(&self) -> &[u8; 64] {
        &self.reviewer_signature
    }
}

/// Validate a signed manifest and exact artifacts for official publication.
///
/// This is deliberately not a consensus/runtime readiness predicate. Official
/// release tooling must configure the independently trusted reviewer key and
/// invoke this function before publishing a binary. Runtime timed-OVN ballot
/// admission remains governed solely by the cryptographic transcript checks.
///
/// # Errors
///
/// Returns [`TimedOvnError`] unless the manifest approves release, its embedded
/// key equals the corridor-configured trusted key, its signature is valid, and
/// every supplied artifact exactly matches the signed digest.
pub fn validate_timed_ovn_official_release_audit_manifest_v1(
    manifest: &TimedOvnOfficialReleaseAuditManifestV1,
    artifacts: &TimedOvnOfficialReleaseAuditArtifactsV1<'_>,
    trusted_reviewer_public_key: &[u8; 32],
) -> Result<(), TimedOvnError> {
    manifest.statement.validate_shape()?;
    if manifest.statement.verdict
        != TimedOvnOfficialReleaseAuditVerdictV1::ApprovedForOfficialRelease
    {
        return Err(TimedOvnError::OfficialReleaseAuditNotApproved);
    }
    parse_official_release_audit_reviewer_key(trusted_reviewer_public_key)
        .map_err(|_| TimedOvnError::UntrustedOfficialReleaseAuditReviewer)?;
    if manifest.statement.reviewer_public_key != *trusted_reviewer_public_key {
        return Err(TimedOvnError::UntrustedOfficialReleaseAuditReviewer);
    }
    let expected = TimedOvnOfficialReleaseAuditStatementV1::from_artifacts(
        manifest.statement.verdict,
        artifacts,
        *trusted_reviewer_public_key,
    )?;
    if manifest.statement != expected {
        return Err(TimedOvnError::OfficialReleaseAuditEvidenceMismatch);
    }
    verify_official_release_audit_signature(&manifest.statement, &manifest.reviewer_signature)
}

/// Decode and validate official-release audit manifest bytes and exact artifacts.
///
/// # Errors
///
/// Returns [`TimedOvnError`] for absent/noncanonical manifest bytes or any
/// failure described by [`validate_timed_ovn_official_release_audit_manifest_v1`].
pub fn validate_timed_ovn_official_release_audit_manifest_bytes_v1(
    manifest_bytes: &[u8],
    artifacts: &TimedOvnOfficialReleaseAuditArtifactsV1<'_>,
    trusted_reviewer_public_key: &[u8; 32],
) -> Result<TimedOvnOfficialReleaseAuditManifestV1, TimedOvnError> {
    let manifest = TimedOvnOfficialReleaseAuditManifestV1::from_bytes(manifest_bytes)?;
    validate_timed_ovn_official_release_audit_manifest_v1(
        &manifest,
        artifacts,
        trusted_reviewer_public_key,
    )?;
    Ok(manifest)
}

/// Derive the canonical digest naming the complete fixed timed-OVN v1 suite.
///
/// The digest commits to the curve/encoding profile, all transcript domains,
/// wire tags and widths, roster/tally bounds, constant-time exponent width,
/// choice tags, and the purpose-distinct TLE BLS ciphersuite. It is therefore
/// derived locally and must never be accepted from an untrusted ballot wire.
#[must_use]
pub fn timed_ovn_parameter_hash_v1() -> [u8; 32] {
    fn update_field(hasher: &mut Sha256, field: &[u8]) {
        let length = u32::try_from(field.len()).expect("fixed suite field length fits u32");
        hasher.update(length.to_be_bytes());
        hasher.update(field);
    }

    fn update_width(hasher: &mut Sha256, width: usize) {
        let width = u32::try_from(width).expect("fixed suite width fits u32");
        update_field(hasher, &width.to_be_bytes());
    }

    let mut hasher = Sha256::new();
    update_field(&mut hasher, PARAMETER_PROFILE_DOMAIN_V1);
    update_field(&mut hasher, b"BLS12-381-GT-FP12-BE576-G2-COMPRESSED");
    update_field(&mut hasher, &TIMED_OVN_PROTOCOL_VERSION_V1.to_be_bytes());
    update_width(&mut hasher, TIMED_OVN_CHOICE_COUNT_V1);
    update_width(&mut hasher, TIMED_OVN_MAX_PARTICIPANTS_V1);
    for width in [
        TIMED_OVN_GT_BYTES_V1,
        TIMED_OVN_G2_BYTES_V1,
        TIMED_OVN_SCALAR_BYTES_V1,
        TIMED_OVN_CT_SCALAR_BITS_V1,
        REGISTRATION_WIRE_BYTES_V1,
        BALLOT_WIRE_BYTES_V1,
    ] {
        update_width(&mut hasher, width);
    }
    let transcript_fields: [&[u8]; 10] = [
        SESSION_DOMAIN_V1,
        SESSION_DIGEST_DOMAIN_V1,
        POP_CHALLENGE_DOMAIN_V1,
        ROSTER_ROOT_DOMAIN_V1,
        SURVIVOR_ROOT_DOMAIN_V1,
        BALLOT_CHALLENGE_DOMAIN_V1,
        REGISTRATION_MAGIC_V1,
        BALLOT_MAGIC_V1,
        OPTION_TAGS_V1.as_slice(),
        TLE_RELEASE_SIGNATURE_DST_V1,
    ];
    for field in transcript_fields {
        update_field(&mut hasher, field);
    }
    hasher.finalize().into()
}

/// Complete immutable binding for one timed-OVN registration and ballot attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimedOvnSessionV1 {
    network_id: [u8; 32],
    proposal_content_id: [u8; 32],
    governance_attempt_id: [u8; 32],
    body_instance_id: [u8; 32],
    ballot_attempt_id: [u8; 32],
    parameter_hash: [u8; 32],
    tle_master_public_key: TleMasterPublicKey,
}

impl TimedOvnSessionV1 {
    /// Construct one fully bound session using the independently generated TLE key.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError::ZeroBinding`] for an inert digest placeholder.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_id: [u8; 32],
        proposal_content_id: [u8; 32],
        governance_attempt_id: [u8; 32],
        body_instance_id: [u8; 32],
        ballot_attempt_id: [u8; 32],
        parameter_hash: [u8; 32],
        tle_master_public_key: TleMasterPublicKey,
    ) -> Result<Self, TimedOvnError> {
        if [
            network_id,
            proposal_content_id,
            governance_attempt_id,
            body_instance_id,
            ballot_attempt_id,
            parameter_hash,
        ]
        .iter()
        .any(|binding| is_zero(binding))
        {
            return Err(TimedOvnError::ZeroBinding);
        }
        if parameter_hash != timed_ovn_parameter_hash_v1() {
            return Err(TimedOvnError::ParameterProfileMismatch);
        }
        Ok(Self {
            network_id,
            proposal_content_id,
            governance_attempt_id,
            body_instance_id,
            ballot_attempt_id,
            parameter_hash,
            tle_master_public_key,
        })
    }

    /// Return the ballot-attempt identifier.
    #[must_use]
    pub const fn ballot_attempt_id(&self) -> &[u8; 32] {
        &self.ballot_attempt_id
    }

    /// Return the independently generated threshold-release public key.
    #[must_use]
    pub const fn tle_master_public_key(&self) -> &TleMasterPublicKey {
        &self.tle_master_public_key
    }

    /// Return the deterministic digest of every session and TLE-key binding.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(SESSION_DIGEST_DOMAIN_V1);
        hasher.update(self.canonical_bytes());
        hasher.finalize().into()
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            SESSION_DOMAIN_V1.len() + 2 + 32 * 7 + THRESHOLD_BLS_PUBLIC_KEY_BYTES,
        );
        bytes.extend_from_slice(SESSION_DOMAIN_V1);
        bytes.extend_from_slice(&TIMED_OVN_PROTOCOL_VERSION_V1.to_be_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.proposal_content_id);
        bytes.extend_from_slice(&self.governance_attempt_id);
        bytes.extend_from_slice(&self.body_instance_id);
        bytes.extend_from_slice(&self.ballot_attempt_id);
        bytes.extend_from_slice(&self.parameter_hash);
        bytes.extend_from_slice(self.tle_master_public_key.session_id());
        bytes.extend_from_slice(self.tle_master_public_key.as_bytes());
        bytes
    }

    fn validate_release_identity(
        &self,
        identity: &TleReleaseIdentityV1,
        survivor_root: &[u8; 32],
    ) -> Result<(), TimedOvnError> {
        if identity.session().network_id() != &self.network_id
            || identity.session().session_id() != self.tle_master_public_key.session_id()
            || identity.governance_attempt_id() != &self.governance_attempt_id
            || identity.body_instance_id() != &self.body_instance_id
            || identity.ballot_attempt_id() != &self.ballot_attempt_id
            || identity.survivor_corpus_root() != survivor_root
            || identity.parameter_hash() != &self.parameter_hash
        {
            return Err(TimedOvnError::InvalidReleaseIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct GtElement(blst_fp12);

impl fmt::Debug for GtElement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtElement(<canonical BLS12-381 GT>)")
    }
}

impl GtElement {
    fn identity() -> Self {
        Self(blst_fp12::default())
    }

    fn from_bytes(bytes: &GtBytes, allow_identity: bool) -> Result<Self, TimedOvnError> {
        let mut value = blst_fp12::default();
        let mut cursor = 0_usize;
        // `blst_bendian_from_fp12` emits fp12.fp6[j].fp2[i].fp[k] in this order.
        for i in 0..3 {
            for j in 0..2 {
                for k in 0..2 {
                    let chunk: &[u8; FP_BYTES] = bytes[cursor..cursor + FP_BYTES]
                        .try_into()
                        .map_err(|_| TimedOvnError::InvalidTargetGroupElement)?;
                    value.fp6[j].fp2[i].fp[k] = fp_from_bendian(chunk);
                    cursor += FP_BYTES;
                }
            }
        }
        if cursor != TIMED_OVN_GT_BYTES_V1 || value.to_bendian() != *bytes || !value.in_group() {
            return Err(TimedOvnError::InvalidTargetGroupElement);
        }
        let element = Self(value);
        if !allow_identity && element.is_identity() {
            return Err(TimedOvnError::IdentityElement);
        }
        Ok(element)
    }

    fn to_bytes(self) -> GtBytes {
        self.0.to_bendian()
    }

    fn is_identity(self) -> bool {
        self.0 == blst_fp12::default()
    }

    fn multiply(self, rhs: Self) -> Self {
        Self(self.0 * rhs.0)
    }

    #[allow(unsafe_code)]
    fn inverse(self) -> Self {
        let mut inverse = self.0;
        // SAFETY: `inverse` is a fully initialized `blst_fp12`.  Every caller
        // obtains it from a subgroup-checked pairing or canonical decoder, for
        // which conjugation is the target-group inverse.  The function mutates
        // exactly the referenced value and retains no pointer.
        unsafe { blst::blst_fp12_conjugate(core::ptr::addr_of_mut!(inverse)) };
        Self(inverse)
    }
}

#[allow(unsafe_code)]
fn fp_from_bendian(bytes: &[u8; FP_BYTES]) -> blst_fp {
    let mut value = blst_fp::default();
    // SAFETY: `bytes` is exactly one 48-byte field encoding and `value` is a
    // valid, aligned output.  blst reads 48 bytes, initializes `value`, and
    // retains neither pointer.  The caller enforces canonicality by exactly
    // re-encoding the complete fp12 value before accepting it.
    unsafe { blst::blst_fp_from_bendian(core::ptr::addr_of_mut!(value), bytes.as_ptr()) };
    value
}

fn select_fp12(left: &blst_fp12, right: &blst_fp12, bit: u8) -> blst_fp12 {
    let mask = 0_u64.wrapping_sub(u64::from(bit & 1));
    let mut selected = *left;
    for fp6 in 0..2 {
        for fp2 in 0..3 {
            for fp in 0..2 {
                for limb in 0..FP_LIMBS {
                    let lhs = left.fp6[fp6].fp2[fp2].fp[fp].l[limb];
                    let rhs = right.fp6[fp6].fp2[fp2].fp[fp].l[limb];
                    selected.fp6[fp6].fp2[fp2].fp[fp].l[limb] = (lhs & !mask) | (rhs & mask);
                }
            }
        }
    }
    selected
}

fn ct_gt_scalar_mul(base: &GtElement, scalar_be: &ScalarBytes) -> GtElement {
    let mut ignored = [0_usize; 3];
    ct_gt_scalar_mul_inner::<false>(base, scalar_be, &mut ignored)
}

fn ct_gt_scalar_mul_inner<const COUNT: bool>(
    base: &GtElement,
    scalar_be: &ScalarBytes,
    counts: &mut [usize; 3],
) -> GtElement {
    let mut accumulator = GtElement::identity();
    for byte in scalar_be {
        for shift in (0..8).rev() {
            let squared = accumulator.multiply(accumulator);
            let multiplied = squared.multiply(*base);
            let bit = (byte >> shift) & 1;
            accumulator = GtElement(select_fp12(&squared.0, &multiplied.0, bit));
            if COUNT {
                counts[0] += 1;
                counts[1] += 1;
                counts[2] += FP12_LIMBS;
            }
        }
    }
    accumulator
}

fn pairing_gt(g1: &G1Affine, g2: &G2Affine) -> Result<GtElement, TimedOvnError> {
    let signature = blst::min_sig::Signature::sig_validate(&g1.to_compressed(), true)
        .map_err(|_| TimedOvnError::InvalidTargetGroupElement)?;
    let public_key = blst::min_sig::PublicKey::key_validate(&g2.to_compressed())
        .map_err(|_| TimedOvnError::InvalidTargetGroupElement)?;
    let p: &blst::blst_p1_affine = (&signature).into();
    let q: &blst::blst_p2_affine = (&public_key).into();
    let value = blst_fp12::miller_loop(q, p).final_exp();
    if !value.in_group() {
        return Err(TimedOvnError::InvalidTargetGroupElement);
    }
    let element = GtElement(value);
    if element.is_identity() {
        return Err(TimedOvnError::IdentityElement);
    }
    Ok(element)
}

fn target_generator() -> Result<GtElement, TimedOvnError> {
    pairing_gt(&G1Affine::generator(), &G2Affine::generator())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TimedOvnSchnorrPopV1 {
    commitment: GtBytes,
    response: ScalarBytes,
}

/// Provenance marker for objects whose cryptographic proofs were verified directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimedOvnProofVerifiedV1;

/// Provenance marker for shape-checked objects reconstructed from committed consensus caches.
///
/// This marker deliberately does not imply that the reconstructed object's proof equations were
/// replayed. Consensus code may use it only after its state-admission boundary has established
/// that the exact cached bytes were proof-verified when originally committed and that snapshot
/// restoration fully replays those proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimedOvnCommittedCacheV1;

/// Three independent target-group registration keys and proofs for one participant.
///
/// The default provenance parameter is [`TimedOvnProofVerifiedV1`]. Committed consensus cache
/// reconstruction uses the distinct [`TimedOvnCommittedRegistrationCacheV1`] alias instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedOvnRegistrationV1<Provenance = TimedOvnProofVerifiedV1> {
    session_digest: [u8; 32],
    participant_hash: [u8; 32],
    public_keys: [GtBytes; TIMED_OVN_CHOICE_COUNT_V1],
    proofs: [TimedOvnSchnorrPopV1; TIMED_OVN_CHOICE_COUNT_V1],
    provenance: PhantomData<Provenance>,
}

impl TimedOvnRegistrationV1 {
    /// Decode and verify one fully consuming fixed-width registration.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for a malformed encoding, wrong session,
    /// noncanonical/identity target element, scalar, or failed proof.
    pub fn from_bytes(session: &TimedOvnSessionV1, bytes: &[u8]) -> Result<Self, TimedOvnError> {
        let registration = Self::decode_shape(session, bytes)?;
        registration.verify(session)?;
        Ok(registration)
    }

    fn decode_shape(session: &TimedOvnSessionV1, bytes: &[u8]) -> Result<Self, TimedOvnError> {
        if bytes.len() != REGISTRATION_WIRE_BYTES_V1 {
            return Err(TimedOvnError::InvalidEncoding);
        }
        let mut cursor = 0_usize;
        if take::<8>(bytes, &mut cursor)? != *REGISTRATION_MAGIC_V1 {
            return Err(TimedOvnError::InvalidEncoding);
        }
        let session_digest = take::<32>(bytes, &mut cursor)?;
        let participant_hash = take::<32>(bytes, &mut cursor)?;
        let mut public_keys = [[0_u8; TIMED_OVN_GT_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1];
        for public_key in &mut public_keys {
            *public_key = take::<TIMED_OVN_GT_BYTES_V1>(bytes, &mut cursor)?;
            GtElement::from_bytes(public_key, false)?;
        }
        let mut commitments = [[0_u8; TIMED_OVN_GT_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1];
        for commitment in &mut commitments {
            *commitment = take::<TIMED_OVN_GT_BYTES_V1>(bytes, &mut cursor)?;
            GtElement::from_bytes(commitment, false)?;
        }
        let mut responses = [[0_u8; TIMED_OVN_SCALAR_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1];
        for response in &mut responses {
            *response = take::<TIMED_OVN_SCALAR_BYTES_V1>(bytes, &mut cursor)?;
            decode_scalar(response)?;
        }
        if cursor != bytes.len() {
            return Err(TimedOvnError::InvalidEncoding);
        }
        let registration = Self {
            session_digest,
            participant_hash,
            public_keys,
            proofs: core::array::from_fn(|option| TimedOvnSchnorrPopV1 {
                commitment: commitments[option],
                response: responses[option],
            }),
            provenance: PhantomData,
        };
        registration.validate_cached_shape(session)?;
        Ok(registration)
    }
}

/// Shape-checked registration reconstructed from an exact committed record.
///
/// Unlike [`TimedOvnRegistrationV1`], this type does not claim that its three proof-of-possession
/// equations were replayed. It cannot be converted to the proof-verified type without performing
/// full verification through [`TimedOvnRegistrationV1::from_bytes`].
///
/// ```compile_fail
/// use iroha_crypto::timed_ovn::{
///     TimedOvnCommittedRegistrationCacheV1, TimedOvnRegistrationV1,
/// };
///
/// fn require_verified(_: TimedOvnRegistrationV1) {}
/// fn cannot_promote(cache: TimedOvnCommittedRegistrationCacheV1) {
///     require_verified(cache);
/// }
/// ```
pub type TimedOvnCommittedRegistrationCacheV1 = TimedOvnRegistrationV1<TimedOvnCommittedCacheV1>;

impl TimedOvnCommittedRegistrationCacheV1 {
    /// Decode the canonical shape of a registration already admitted by committed consensus state.
    ///
    /// The exact wire width, session binding, group encodings, and scalars are checked, but the
    /// three proof-of-possession equations are deliberately not replayed. Callers must keep this
    /// cache-provenance type distinct from [`TimedOvnRegistrationV1`].
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for malformed, noncanonical, or cross-session cached material.
    pub fn from_committed_record(
        session: &TimedOvnSessionV1,
        bytes: &[u8],
    ) -> Result<Self, TimedOvnError> {
        let decoded = TimedOvnRegistrationV1::decode_shape(session, bytes)?;
        Ok(Self {
            session_digest: decoded.session_digest,
            participant_hash: decoded.participant_hash,
            public_keys: decoded.public_keys,
            proofs: decoded.proofs,
            provenance: PhantomData,
        })
    }
}

impl<Provenance> TimedOvnRegistrationV1<Provenance> {
    fn validate_cached_shape(&self, session: &TimedOvnSessionV1) -> Result<(), TimedOvnError> {
        if self.session_digest != session.digest() || is_zero(&self.participant_hash) {
            return Err(TimedOvnError::BindingMismatch);
        }
        for option in 0..TIMED_OVN_CHOICE_COUNT_V1 {
            GtElement::from_bytes(&self.public_keys[option], false)?;
            GtElement::from_bytes(&self.proofs[option].commitment, false)?;
            decode_scalar(&self.proofs[option].response)?;
        }
        Ok(())
    }

    /// Encode the canonical fixed-width registration.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(REGISTRATION_WIRE_BYTES_V1);
        bytes.extend_from_slice(REGISTRATION_MAGIC_V1);
        bytes.extend_from_slice(&self.session_digest);
        bytes.extend_from_slice(&self.participant_hash);
        for public_key in self.public_keys {
            bytes.extend_from_slice(&public_key);
        }
        for proof in self.proofs {
            bytes.extend_from_slice(&proof.commitment);
        }
        for proof in self.proofs {
            bytes.extend_from_slice(&proof.response);
        }
        bytes
    }

    /// Return the canonical participant identity hash.
    #[must_use]
    pub const fn participant_hash(&self) -> &[u8; 32] {
        &self.participant_hash
    }

    /// Return the three canonical target-group public keys.
    #[must_use]
    pub const fn public_keys(&self) -> &[GtBytes; TIMED_OVN_CHOICE_COUNT_V1] {
        &self.public_keys
    }

    /// Verify the session binding and all three Schnorr proofs of possession.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for malformed material, a wrong session, or a
    /// proof equation that does not hold.
    pub fn verify(&self, session: &TimedOvnSessionV1) -> Result<(), TimedOvnError> {
        if self.session_digest != session.digest() || is_zero(&self.participant_hash) {
            return Err(TimedOvnError::BindingMismatch);
        }
        let generator = target_generator()?;
        for option in 0..TIMED_OVN_CHOICE_COUNT_V1 {
            let public_key = GtElement::from_bytes(&self.public_keys[option], false)?;
            let commitment = GtElement::from_bytes(&self.proofs[option].commitment, false)?;
            let response = decode_scalar(&self.proofs[option].response)?;
            let challenge = pop_challenge(
                session,
                &self.participant_hash,
                option,
                &self.public_keys[option],
                &self.proofs[option].commitment,
            )?;
            let lhs = ct_gt_scalar_mul(&generator, &response.to_bytes_be());
            let rhs = commitment.multiply(ct_gt_scalar_mul(&public_key, &challenge.to_bytes_be()));
            if lhs != rhs {
                return Err(TimedOvnError::InvalidProofOfPossession);
            }
        }
        Ok(())
    }
}

/// Non-cloneable, zeroizing owner of one participant's three registration secrets.
///
/// This type deliberately has no serialization, byte-export, or `Debug`
/// implementation and is unrelated to [`crate::PrivateKey`] and
/// [`crate::KeyPair`].
pub struct TimedOvnRegistrationSecretV1 {
    session_digest: [u8; 32],
    participant_hash: [u8; 32],
    scalar_bytes: Zeroizing<[ScalarBytes; TIMED_OVN_CHOICE_COUNT_V1]>,
}

impl TimedOvnRegistrationSecretV1 {
    /// Generate secrets and proofs using the operating-system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for an invalid binding or randomness failure.
    pub fn generate(
        session: &TimedOvnSessionV1,
        participant_hash: [u8; 32],
    ) -> Result<(Self, TimedOvnRegistrationV1), TimedOvnError> {
        Self::generate_with_rng(session, participant_hash, &mut OsRng)
    }

    /// Generate secrets and proofs using an explicit cryptographic RNG.
    ///
    /// This entry point exists for deterministic interoperability vectors.
    /// Production callers must not reuse seeded RNG state across registrations.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for an invalid binding or randomness failure.
    pub fn generate_with_rng<R: TryCryptoRng + ?Sized>(
        session: &TimedOvnSessionV1,
        participant_hash: [u8; 32],
        rng: &mut R,
    ) -> Result<(Self, TimedOvnRegistrationV1), TimedOvnError> {
        if is_zero(&participant_hash) {
            return Err(TimedOvnError::ZeroBinding);
        }
        let generator = target_generator()?;
        let mut scalar_bytes =
            Zeroizing::new([[0_u8; TIMED_OVN_SCALAR_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1]);
        let mut public_keys = [[0_u8; TIMED_OVN_GT_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1];
        let mut proofs = [TimedOvnSchnorrPopV1 {
            commitment: [0_u8; TIMED_OVN_GT_BYTES_V1],
            response: [0_u8; TIMED_OVN_SCALAR_BYTES_V1],
        }; TIMED_OVN_CHOICE_COUNT_V1];
        for option in 0..TIMED_OVN_CHOICE_COUNT_V1 {
            let secret_bytes = random_nonzero_scalar_bytes(rng)?;
            let nonce_bytes = Zeroizing::new(random_nonzero_scalar_bytes(rng)?);
            let secret = decode_scalar(&secret_bytes)?;
            let nonce = decode_scalar(&nonce_bytes)?;
            let public_key = ct_gt_scalar_mul(&generator, &secret_bytes).to_bytes();
            let commitment = ct_gt_scalar_mul(&generator, &nonce_bytes).to_bytes();
            let challenge =
                pop_challenge(session, &participant_hash, option, &public_key, &commitment)?;
            scalar_bytes[option] = secret_bytes;
            public_keys[option] = public_key;
            proofs[option] = TimedOvnSchnorrPopV1 {
                commitment,
                response: (nonce + challenge * secret).to_bytes_be(),
            };
        }
        let secret = Self {
            session_digest: session.digest(),
            participant_hash,
            scalar_bytes,
        };
        let registration = TimedOvnRegistrationV1 {
            session_digest: session.digest(),
            participant_hash,
            public_keys,
            proofs,
            provenance: PhantomData,
        };
        registration.verify(session)?;
        Ok((secret, registration))
    }

    fn scalars(&self) -> Result<[Scalar; TIMED_OVN_CHOICE_COUNT_V1], TimedOvnError> {
        let mut scalars = [Scalar::from(0_u64); TIMED_OVN_CHOICE_COUNT_V1];
        for (scalar, bytes) in scalars.iter_mut().zip(self.scalar_bytes.iter()) {
            *scalar = decode_scalar(bytes).map_err(|_| TimedOvnError::SecretMismatch)?;
            if *scalar == Scalar::from(0_u64) {
                return Err(TimedOvnError::SecretMismatch);
            }
        }
        Ok(scalars)
    }
}

/// Canonically ordered timed-OVN registration roster with type-level validation provenance.
///
/// The default provenance is proof-verified. Committed cache reconstruction returns
/// [`TimedOvnCommittedRosterCacheV1`] and cannot be mistaken for this default type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedOvnRosterV1<Provenance = TimedOvnProofVerifiedV1> {
    session: TimedOvnSessionV1,
    registrations: Vec<TimedOvnRegistrationV1<Provenance>>,
    roster_root: [u8; 32],
}

impl TimedOvnRosterV1 {
    /// Freeze one complete registration roster without sorting remote input.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] unless registrations are already ordered,
    /// proof-valid, unique, nonempty, and within the v1 bound.
    pub fn new(
        session: &TimedOvnSessionV1,
        registrations: Vec<TimedOvnRegistrationV1>,
    ) -> Result<Self, TimedOvnError> {
        Self::new_inner(session, registrations, true)
    }
}

/// Canonical roster reconstructed from shape-checked committed registration records.
///
/// This type preserves cache provenance and never presents its registrations as proof-verified.
pub type TimedOvnCommittedRosterCacheV1 = TimedOvnRosterV1<TimedOvnCommittedCacheV1>;

impl TimedOvnCommittedRosterCacheV1 {
    /// Rebuild a roster from shape-checked records admitted by committed consensus state.
    ///
    /// Ordering, uniqueness, canonical public material, and the exact roster root are recomputed,
    /// but proof equations are not repeated. Snapshot restoration must independently rebuild the
    /// same roster through [`TimedOvnRosterV1::new`] before accepting persisted state.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for malformed, duplicate, reordered, or cross-session material.
    pub fn from_committed_records(
        session: &TimedOvnSessionV1,
        registrations: Vec<TimedOvnCommittedRegistrationCacheV1>,
    ) -> Result<Self, TimedOvnError> {
        Self::new_inner(session, registrations, false)
    }
}

impl<Provenance> TimedOvnRosterV1<Provenance> {
    fn new_inner(
        session: &TimedOvnSessionV1,
        registrations: Vec<TimedOvnRegistrationV1<Provenance>>,
        verify_proofs: bool,
    ) -> Result<Self, TimedOvnError> {
        if registrations.is_empty() || registrations.len() > TIMED_OVN_MAX_PARTICIPANTS_V1 {
            return Err(TimedOvnError::InvalidRosterSize);
        }
        let mut previous_participant: Option<[u8; 32]> = None;
        let mut participants = HashSet::with_capacity(registrations.len());
        let mut public_keys =
            HashSet::with_capacity(registrations.len() * TIMED_OVN_CHOICE_COUNT_V1);
        for registration in &registrations {
            registration.validate_cached_shape(session)?;
            if verify_proofs {
                registration.verify(session)?;
            }
            if let Some(previous) = previous_participant {
                if registration.participant_hash == previous {
                    return Err(TimedOvnError::DuplicateParticipant);
                }
                if registration.participant_hash < previous {
                    return Err(TimedOvnError::NonCanonicalRoster);
                }
            }
            if !participants.insert(registration.participant_hash) {
                return Err(TimedOvnError::DuplicateParticipant);
            }
            for public_key in registration.public_keys {
                if !public_keys.insert(public_key) {
                    return Err(TimedOvnError::DuplicateRegistrationKey);
                }
            }
            previous_participant = Some(registration.participant_hash);
        }
        let roster_root = roster_root(session, &registrations);
        Ok(Self {
            session: *session,
            registrations,
            roster_root,
        })
    }

    /// Return the immutable timed ballot session.
    #[must_use]
    pub const fn session(&self) -> &TimedOvnSessionV1 {
        &self.session
    }

    /// Return the canonical complete registration-roster root.
    #[must_use]
    pub const fn roster_root(&self) -> &[u8; 32] {
        &self.roster_root
    }

    /// Return the ordered registrations carrying this roster's validation provenance.
    #[must_use]
    pub fn registrations(&self) -> &[TimedOvnRegistrationV1<Provenance>] {
        &self.registrations
    }

    /// Compute the root to place in a future release identity before freezing it.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError::NonCanonicalSurvivorSet`] unless `survivor_ids`
    /// is a nonempty canonical subsequence of this roster.
    pub fn prospective_survivor_root(
        &self,
        survivor_ids: &[[u8; 32]],
    ) -> Result<[u8; 32], TimedOvnError>
    where
        Provenance: Clone,
    {
        let registrations = select_survivors(self, survivor_ids)?;
        Ok(survivor_root(
            &self.session,
            &self.roster_root,
            &registrations,
        ))
    }
}

/// Frozen survivor corpus, future release identity, pairing release term, and validation provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedOvnSurvivorRosterV1<Provenance = TimedOvnProofVerifiedV1> {
    session: TimedOvnSessionV1,
    roster_root: [u8; 32],
    survivor_root: [u8; 32],
    identity_digest: [u8; 32],
    release_identity: TleReleaseIdentityV1,
    release_term: GtBytes,
    registrations: Vec<TimedOvnRegistrationV1<Provenance>>,
    masking_keys: Vec<TimedOvnMaskingKeysV1>,
}

impl TimedOvnSurvivorRosterV1 {
    /// Freeze one survivor corpus against its exact threshold release identity.
    ///
    /// All pairwise masks are checked here.  A single-seat or otherwise
    /// degenerate corpus fails before any ballot can be admitted.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for a reordered/unknown survivor, mismatched
    /// future identity, malformed release term, or identity masking key.
    pub fn new(
        roster: &TimedOvnRosterV1,
        survivor_ids: &[[u8; 32]],
        release_identity: &TleReleaseIdentityV1,
    ) -> Result<Self, TimedOvnError> {
        Self::new_inner(roster, survivor_ids, release_identity)
    }
}

/// Frozen survivor roster reconstructed from a committed registration cache.
///
/// This type exposes deterministic roots and masking keys while preserving that the underlying
/// registration proof equations were not replayed on the committed-cache path.
pub type TimedOvnCommittedSurvivorRosterCacheV1 =
    TimedOvnSurvivorRosterV1<TimedOvnCommittedCacheV1>;

impl TimedOvnCommittedSurvivorRosterCacheV1 {
    /// Freeze a committed-cache roster against its exact threshold release identity.
    ///
    /// Pairwise masks, survivor ordering, release bindings, and group encodings are checked. The
    /// registration proof equations retain committed-cache provenance and are not replayed.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for a reordered/unknown survivor, mismatched future identity,
    /// malformed release term, or identity masking key.
    pub fn from_committed_roster(
        roster: &TimedOvnCommittedRosterCacheV1,
        survivor_ids: &[[u8; 32]],
        release_identity: &TleReleaseIdentityV1,
    ) -> Result<Self, TimedOvnError> {
        Self::new_inner(roster, survivor_ids, release_identity)
    }
}

impl<Provenance: Clone> TimedOvnSurvivorRosterV1<Provenance> {
    fn new_inner(
        roster: &TimedOvnRosterV1<Provenance>,
        survivor_ids: &[[u8; 32]],
        release_identity: &TleReleaseIdentityV1,
    ) -> Result<Self, TimedOvnError> {
        let registrations = select_survivors(roster, survivor_ids)?;
        let survivor_root = survivor_root(&roster.session, &roster.roster_root, &registrations);
        roster
            .session
            .validate_release_identity(release_identity, &survivor_root)?;
        let release_message = release_identity
            .release_message()
            .map_err(|_| TimedOvnError::InvalidReleaseIdentity)?;
        let identity_digest = Sha256::digest(&release_message).into();
        let identity_point = hash_message_to_g1::<TleReleasePurpose>(&release_message);
        let master_point = decode_nonidentity_g2(roster.session.tle_master_public_key.as_bytes())?;
        let release_term = pairing_gt(&identity_point, &master_point)?.to_bytes();
        let masking_keys = derive_all_masking_keys_v1(
            &roster.session,
            &roster.roster_root,
            &survivor_root,
            &identity_digest,
            &registrations,
        )?;
        Ok(Self {
            session: roster.session,
            roster_root: roster.roster_root,
            survivor_root,
            identity_digest,
            release_identity: *release_identity,
            release_term,
            registrations,
            masking_keys,
        })
    }

    /// Return the original registration-roster root.
    #[must_use]
    pub const fn roster_root(&self) -> &[u8; 32] {
        &self.roster_root
    }

    /// Return the exact frozen survivor-corpus root.
    #[must_use]
    pub const fn survivor_root(&self) -> &[u8; 32] {
        &self.survivor_root
    }

    /// Return SHA-256 of the exact future threshold release message.
    #[must_use]
    pub const fn identity_digest(&self) -> &[u8; 32] {
        &self.identity_digest
    }

    /// Return the ordered frozen survivor registrations.
    #[must_use]
    pub fn registrations(&self) -> &[TimedOvnRegistrationV1<Provenance>] {
        &self.registrations
    }

    /// Return the intrinsic target-group release term `A_id`.
    #[must_use]
    pub const fn release_term(&self) -> &GtBytes {
        &self.release_term
    }

    /// Return the cached three survivor-root-bound pairwise OVN masks for one seat.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for an unknown participant or a degenerate
    /// identity mask.  Such a corpus must be discarded and frozen afresh.
    pub fn masking_keys(
        &self,
        participant_hash: &[u8; 32],
    ) -> Result<TimedOvnMaskingKeysV1, TimedOvnError> {
        let index = self
            .registrations
            .binary_search_by_key(participant_hash, |registration| {
                registration.participant_hash
            })
            .map_err(|_| TimedOvnError::UnknownParticipant)?;
        self.masking_keys
            .get(index)
            .cloned()
            .ok_or(TimedOvnError::UnknownParticipant)
    }

    /// Return every replay-derived masking-key point array in survivor order.
    #[must_use]
    pub fn masking_key_points(&self) -> Vec<[GtBytes; TIMED_OVN_CHOICE_COUNT_V1]> {
        self.masking_keys.iter().map(|keys| keys.points).collect()
    }

    fn verification_common(&self) -> Result<TimedOvnBallotVerificationCommonV1, TimedOvnError> {
        TimedOvnBallotVerificationCommonV1::new(
            &self.session,
            self.roster_root,
            self.survivor_root,
            &self.release_identity,
        )
    }

    fn verification_context_at(
        &self,
        index: usize,
    ) -> Result<TimedOvnBallotVerificationContextV1, TimedOvnError> {
        let registration = self
            .registrations
            .get(index)
            .ok_or(TimedOvnError::UnknownParticipant)?;
        let masks = self
            .masking_keys
            .get(index)
            .ok_or(TimedOvnError::UnknownParticipant)?;
        self.verification_common()?.bind_registration(
            u16::try_from(index).map_err(|_| TimedOvnError::InvalidRosterSize)?,
            registration,
            &masks.points,
        )
    }

    fn registration_at(&self, index: usize) -> Option<&TimedOvnRegistrationV1<Provenance>> {
        self.registrations.get(index)
    }
}

fn derive_all_masking_keys_v1<Provenance>(
    session: &TimedOvnSessionV1,
    roster_root: &[u8; 32],
    survivor_root: &[u8; 32],
    identity_digest: &[u8; 32],
    registrations: &[TimedOvnRegistrationV1<Provenance>],
) -> Result<Vec<TimedOvnMaskingKeysV1>, TimedOvnError> {
    let count = registrations.len();
    let mut point_rows = vec![[[0_u8; TIMED_OVN_GT_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1]; count];
    for (option, _) in OPTION_TAGS_V1.iter().enumerate() {
        let public_keys = registrations
            .iter()
            .map(|registration| GtElement::from_bytes(&registration.public_keys[option], false))
            .collect::<Result<Vec<_>, _>>()?;
        let mut prefix = vec![GtElement::identity(); count.saturating_add(1)];
        for index in 0..count {
            prefix[index + 1] = prefix[index].multiply(public_keys[index]);
        }
        let mut suffix = vec![GtElement::identity(); count.saturating_add(1)];
        for index in (0..count).rev() {
            suffix[index] = public_keys[index].multiply(suffix[index + 1]);
        }
        for index in 0..count {
            let mask = prefix[index].multiply(suffix[index + 1].inverse());
            if mask.is_identity() {
                return Err(TimedOvnError::IdentityElement);
            }
            point_rows[index][option] = mask.to_bytes();
        }
    }
    registrations
        .iter()
        .zip(point_rows)
        .enumerate()
        .map(|(index, (registration, points))| {
            Ok(TimedOvnMaskingKeysV1 {
                session_digest: session.digest(),
                roster_root: *roster_root,
                survivor_root: *survivor_root,
                identity_digest: *identity_digest,
                participant_hash: registration.participant_hash,
                index: u16::try_from(index).map_err(|_| TimedOvnError::InvalidRosterSize)?,
                points,
            })
        })
        .collect()
}

/// Three pairwise-cancelling target-group masks bound to one frozen seat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedOvnMaskingKeysV1 {
    session_digest: [u8; 32],
    roster_root: [u8; 32],
    survivor_root: [u8; 32],
    identity_digest: [u8; 32],
    participant_hash: [u8; 32],
    index: u16,
    points: [GtBytes; TIMED_OVN_CHOICE_COUNT_V1],
}

impl TimedOvnMaskingKeysV1 {
    /// Return the zero-based canonical survivor index.
    #[must_use]
    pub const fn index(&self) -> u16 {
        self.index
    }

    /// Return the three canonical target-group mask encodings.
    #[must_use]
    pub const fn points(&self) -> &[GtBytes; TIMED_OVN_CHOICE_COUNT_V1] {
        &self.points
    }
}

/// Replay-derived common public bindings used to verify bounded ballot chunks.
///
/// Construction recomputes the future identity digest and intrinsic release term. A caller can
/// then bind one committed registration and its snapshot-checked masking-key cache without
/// rebuilding or re-verifying the complete registration corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedOvnBallotVerificationCommonV1 {
    session: TimedOvnSessionV1,
    roster_root: [u8; 32],
    survivor_root: [u8; 32],
    identity_digest: [u8; 32],
    release_identity: TleReleaseIdentityV1,
    release_term: GtBytes,
}

impl TimedOvnBallotVerificationCommonV1 {
    /// Rebuild common verification bindings for one frozen survivor corpus.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for a mismatched future identity, inert root, or invalid release
    /// pairing term.
    pub fn new(
        session: &TimedOvnSessionV1,
        roster_root: [u8; 32],
        survivor_root: [u8; 32],
        release_identity: &TleReleaseIdentityV1,
    ) -> Result<Self, TimedOvnError> {
        if is_zero(&roster_root) || is_zero(&survivor_root) {
            return Err(TimedOvnError::ZeroBinding);
        }
        session.validate_release_identity(release_identity, &survivor_root)?;
        let release_message = release_identity
            .release_message()
            .map_err(|_| TimedOvnError::InvalidReleaseIdentity)?;
        let identity_digest = Sha256::digest(&release_message).into();
        let identity_point = hash_message_to_g1::<TleReleasePurpose>(&release_message);
        let master_point = decode_nonidentity_g2(session.tle_master_public_key.as_bytes())?;
        let release_term = pairing_gt(&identity_point, &master_point)?.to_bytes();
        Ok(Self {
            session: *session,
            roster_root,
            survivor_root,
            identity_digest,
            release_identity: *release_identity,
            release_term,
        })
    }

    /// Bind one survivor registration and its replay-derived masking-key points.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] when the registration, index, or cached points are malformed or
    /// differ from the common frozen bindings.
    pub fn bind_registration<Provenance>(
        &self,
        index: u16,
        registration: &TimedOvnRegistrationV1<Provenance>,
        mask_points: &[GtBytes; TIMED_OVN_CHOICE_COUNT_V1],
    ) -> Result<TimedOvnBallotVerificationContextV1, TimedOvnError> {
        registration.validate_cached_shape(&self.session)?;
        for point in mask_points {
            GtElement::from_bytes(point, false)?;
        }
        Ok(TimedOvnBallotVerificationContextV1 {
            common: self.clone(),
            participant_hash: registration.participant_hash,
            index,
            public_keys: registration.public_keys,
            mask_points: *mask_points,
        })
    }

    /// Return the immutable session digest.
    #[must_use]
    pub fn session_digest(&self) -> [u8; 32] {
        self.session.digest()
    }

    /// Return the registration-roster root.
    #[must_use]
    pub const fn roster_root(&self) -> [u8; 32] {
        self.roster_root
    }

    /// Return the frozen survivor root.
    #[must_use]
    pub const fn survivor_root(&self) -> [u8; 32] {
        self.survivor_root
    }

    /// Return the exact future-identity digest.
    #[must_use]
    pub const fn identity_digest(&self) -> [u8; 32] {
        self.identity_digest
    }

    /// Return the intrinsic release term.
    #[must_use]
    pub const fn release_term(&self) -> GtBytes {
        self.release_term
    }

    /// Borrow the exact typed future release identity.
    #[must_use]
    pub const fn release_identity(&self) -> &TleReleaseIdentityV1 {
        &self.release_identity
    }
}

/// One survivor-specific public context for generalized OR-proof verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedOvnBallotVerificationContextV1 {
    common: TimedOvnBallotVerificationCommonV1,
    participant_hash: [u8; 32],
    index: u16,
    public_keys: [GtBytes; TIMED_OVN_CHOICE_COUNT_V1],
    mask_points: [GtBytes; TIMED_OVN_CHOICE_COUNT_V1],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TimedOvnBallotOrProofV1 {
    challenges: [ScalarBytes; TIMED_OVN_CHOICE_COUNT_V1],
    responses_x: [[ScalarBytes; TIMED_OVN_CHOICE_COUNT_V1]; TIMED_OVN_CHOICE_COUNT_V1],
    responses_r: [[ScalarBytes; TIMED_OVN_CHOICE_COUNT_V1]; TIMED_OVN_CHOICE_COUNT_V1],
}

/// One survivor-bound timed and masked three-choice ballot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedOvnMaskedBallotV1 {
    session_digest: [u8; 32],
    roster_root: [u8; 32],
    survivor_root: [u8; 32],
    identity_digest: [u8; 32],
    participant_hash: [u8; 32],
    index: u16,
    u: [G2Bytes; TIMED_OVN_CHOICE_COUNT_V1],
    c: [GtBytes; TIMED_OVN_CHOICE_COUNT_V1],
    proof: TimedOvnBallotOrProofV1,
}

impl TimedOvnMaskedBallotV1 {
    /// Decode and verify one fully consuming survivor-bound ballot.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for malformed encodings, an identity or
    /// duplicate ephemeral, a transcript mismatch, or an invalid one-hot proof.
    pub fn from_bytes(
        survivors: &TimedOvnSurvivorRosterV1,
        bytes: &[u8],
    ) -> Result<Self, TimedOvnError> {
        let ballot = Self::parse_bytes(bytes)?;
        ballot.verify(survivors)?;
        Ok(ballot)
    }

    /// Decode and verify one ballot against a snapshot-checked survivor context.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for malformed encodings, wrong cached bindings, duplicate
    /// ephemerals, or an invalid generalized OR proof.
    pub fn from_bytes_with_context(
        context: &TimedOvnBallotVerificationContextV1,
        bytes: &[u8],
    ) -> Result<Self, TimedOvnError> {
        let ballot = Self::parse_bytes(bytes)?;
        ballot.verify_with_context(context)?;
        Ok(ballot)
    }

    fn parse_bytes(bytes: &[u8]) -> Result<Self, TimedOvnError> {
        if bytes.len() != BALLOT_WIRE_BYTES_V1 {
            return Err(TimedOvnError::InvalidEncoding);
        }
        let mut cursor = 0_usize;
        if take::<8>(bytes, &mut cursor)? != *BALLOT_MAGIC_V1 {
            return Err(TimedOvnError::InvalidEncoding);
        }
        let session_digest = take::<32>(bytes, &mut cursor)?;
        let roster_root = take::<32>(bytes, &mut cursor)?;
        let survivor_root = take::<32>(bytes, &mut cursor)?;
        let identity_digest = take::<32>(bytes, &mut cursor)?;
        let participant_hash = take::<32>(bytes, &mut cursor)?;
        let index = u16::from_be_bytes(take::<2>(bytes, &mut cursor)?);
        let mut u = [[0_u8; TIMED_OVN_G2_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1];
        let mut unique_u = HashSet::with_capacity(TIMED_OVN_CHOICE_COUNT_V1);
        for ephemeral in &mut u {
            *ephemeral = take::<TIMED_OVN_G2_BYTES_V1>(bytes, &mut cursor)?;
            decode_nonidentity_g2(ephemeral)?;
            if !unique_u.insert(*ephemeral) {
                return Err(TimedOvnError::DuplicateEphemeral);
            }
        }
        let mut c = [[0_u8; TIMED_OVN_GT_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1];
        for commitment in &mut c {
            *commitment = take::<TIMED_OVN_GT_BYTES_V1>(bytes, &mut cursor)?;
            GtElement::from_bytes(commitment, false)?;
        }
        let mut challenges = [[0_u8; TIMED_OVN_SCALAR_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1];
        for challenge in &mut challenges {
            *challenge = take::<TIMED_OVN_SCALAR_BYTES_V1>(bytes, &mut cursor)?;
            decode_scalar(challenge)?;
        }
        let mut responses_x = [[[0_u8; TIMED_OVN_SCALAR_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1];
            TIMED_OVN_CHOICE_COUNT_V1];
        for branch in &mut responses_x {
            for response in branch {
                *response = take::<TIMED_OVN_SCALAR_BYTES_V1>(bytes, &mut cursor)?;
                decode_scalar(response)?;
            }
        }
        let mut responses_r = [[[0_u8; TIMED_OVN_SCALAR_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1];
            TIMED_OVN_CHOICE_COUNT_V1];
        for branch in &mut responses_r {
            for response in branch {
                *response = take::<TIMED_OVN_SCALAR_BYTES_V1>(bytes, &mut cursor)?;
                decode_scalar(response)?;
            }
        }
        if cursor != bytes.len() {
            return Err(TimedOvnError::InvalidEncoding);
        }
        Ok(Self {
            session_digest,
            roster_root,
            survivor_root,
            identity_digest,
            participant_hash,
            index,
            u,
            c,
            proof: TimedOvnBallotOrProofV1 {
                challenges,
                responses_x,
                responses_r,
            },
        })
    }

    /// Encode the canonical fixed-width ballot and one-hot proof.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(BALLOT_WIRE_BYTES_V1);
        bytes.extend_from_slice(BALLOT_MAGIC_V1);
        bytes.extend_from_slice(&self.session_digest);
        bytes.extend_from_slice(&self.roster_root);
        bytes.extend_from_slice(&self.survivor_root);
        bytes.extend_from_slice(&self.identity_digest);
        bytes.extend_from_slice(&self.participant_hash);
        bytes.extend_from_slice(&self.index.to_be_bytes());
        for ephemeral in self.u {
            bytes.extend_from_slice(&ephemeral);
        }
        for commitment in self.c {
            bytes.extend_from_slice(&commitment);
        }
        for challenge in self.proof.challenges {
            bytes.extend_from_slice(&challenge);
        }
        for branch in self.proof.responses_x {
            for response in branch {
                bytes.extend_from_slice(&response);
            }
        }
        for branch in self.proof.responses_r {
            for response in branch {
                bytes.extend_from_slice(&response);
            }
        }
        bytes
    }

    /// Return the canonical participant identity hash.
    #[must_use]
    pub const fn participant_hash(&self) -> &[u8; 32] {
        &self.participant_hash
    }

    /// Return the zero-based canonical survivor index.
    #[must_use]
    pub const fn index(&self) -> u16 {
        self.index
    }

    /// Return the three canonical ephemeral G2 values.
    #[must_use]
    pub const fn ephemerals(&self) -> &[G2Bytes; TIMED_OVN_CHOICE_COUNT_V1] {
        &self.u
    }

    /// Return the three timed target-group ballot commitments.
    #[must_use]
    pub const fn commitments(&self) -> &[GtBytes; TIMED_OVN_CHOICE_COUNT_V1] {
        &self.c
    }

    /// Verify every binding and the generalized three-branch one-hot OR proof.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for a wrong seat/root/session, malformed
    /// element or scalar, duplicate ephemeral, or invalid proof equation.
    pub fn verify(&self, survivors: &TimedOvnSurvivorRosterV1) -> Result<(), TimedOvnError> {
        let index = usize::from(self.index);
        let context = survivors.verification_context_at(index)?;
        self.verify_with_context(&context)
    }

    fn verify_with_context(
        &self,
        context: &TimedOvnBallotVerificationContextV1,
    ) -> Result<(), TimedOvnError> {
        if self.session_digest != context.common.session.digest()
            || self.roster_root != context.common.roster_root
            || self.survivor_root != context.common.survivor_root
            || self.identity_digest != context.common.identity_digest
            || self.participant_hash != context.participant_hash
            || self.index != context.index
        {
            return Err(TimedOvnError::BindingMismatch);
        }
        let public_keys = decode_gt_array(&context.public_keys, false)?;
        let mask_points = decode_gt_array(&context.mask_points, false)?;
        let ballot_points = decode_gt_array(&self.c, false)?;
        let ephemerals = decode_g2_array(&self.u)?;
        let release_term = GtElement::from_bytes(&context.common.release_term, false)?;
        let mut unique_u = HashSet::with_capacity(TIMED_OVN_CHOICE_COUNT_V1);
        for ephemeral in self.u {
            if !unique_u.insert(ephemeral) {
                return Err(TimedOvnError::DuplicateEphemeral);
            }
        }
        let challenges = decode_scalar_array(&self.proof.challenges)?;
        let responses_x = decode_scalar_matrix(&self.proof.responses_x)?;
        let responses_r = decode_scalar_matrix(&self.proof.responses_r)?;
        let decoded_statement = DecodedOrStatementV1 {
            public_keys: &public_keys,
            masks: &mask_points,
            ephemerals: &ephemerals,
            ballot_points: &ballot_points,
            release_term: &release_term,
        };
        let commitments = reconstruct_or_commitments(
            &decoded_statement,
            &challenges,
            &responses_x,
            &responses_r,
        )?;
        let expected = ballot_challenge(
            &context.common.session,
            &context.common.roster_root,
            &context.common.survivor_root,
            &context.common.identity_digest,
            &context.common.release_term,
            &self.participant_hash,
            self.index,
            &context.public_keys,
            &context.mask_points,
            &self.u,
            &self.c,
            &commitments,
        )?;
        if challenges.into_iter().sum::<Scalar>() != expected {
            return Err(TimedOvnError::InvalidBallotProof);
        }
        Ok(())
    }
}

impl TimedOvnRegistrationSecretV1 {
    /// Cast a choice with fresh operating-system proof randomness.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for a secret/binding mismatch, randomness
    /// failure, or degenerate frozen survivor context.
    pub fn cast_ballot(
        &self,
        survivors: &TimedOvnSurvivorRosterV1,
        choice: TimedOvnChoiceV1,
    ) -> Result<TimedOvnMaskedBallotV1, TimedOvnError> {
        self.cast_ballot_with_rng(survivors, choice, &mut OsRng)
    }

    /// Cast a choice using an explicit cryptographic proof RNG.
    ///
    /// This entry point exists for deterministic interoperability vectors.
    /// Production callers must use fresh, non-repeating CSPRNG state per ballot.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for a secret/binding mismatch, randomness
    /// failure, or degenerate frozen survivor context.
    pub fn cast_ballot_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        survivors: &TimedOvnSurvivorRosterV1,
        choice: TimedOvnChoiceV1,
        rng: &mut R,
    ) -> Result<TimedOvnMaskedBallotV1, TimedOvnError> {
        if self.session_digest != survivors.session.digest() {
            return Err(TimedOvnError::BindingMismatch);
        }
        let masks = survivors.masking_keys(&self.participant_hash)?;
        let registration = survivors
            .registration_at(usize::from(masks.index))
            .filter(|registration| registration.participant_hash == self.participant_hash)
            .ok_or(TimedOvnError::UnknownParticipant)?;
        let secrets = self.scalars()?;
        let public_keys = decode_gt_array(&registration.public_keys, false)?;
        let mask_points = decode_gt_array(&masks.points, false)?;
        let generator = target_generator()?;
        for (secret_bytes, public_key) in self.scalar_bytes.iter().zip(&public_keys) {
            if ct_gt_scalar_mul(&generator, secret_bytes) != *public_key {
                return Err(TimedOvnError::SecretMismatch);
            }
        }
        let release_term = GtElement::from_bytes(&survivors.release_term, false)?;
        let mut r_bytes =
            Zeroizing::new([[0_u8; TIMED_OVN_SCALAR_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1]);
        let mut r_scalars = [Scalar::from(0_u64); TIMED_OVN_CHOICE_COUNT_V1];
        let mut u = [[0_u8; TIMED_OVN_G2_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1];
        let mut c = [[0_u8; TIMED_OVN_GT_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1];
        let mut unique_u = HashSet::with_capacity(TIMED_OVN_CHOICE_COUNT_V1);
        for option in 0..TIMED_OVN_CHOICE_COUNT_V1 {
            r_bytes[option] = random_nonzero_scalar_bytes(rng)?;
            r_scalars[option] = decode_scalar(&r_bytes[option])?;
            let ephemeral = (G2Projective::generator() * r_scalars[option])
                .to_affine()
                .to_compressed();
            if !unique_u.insert(ephemeral) {
                return Err(TimedOvnError::DuplicateEphemeral);
            }
            let vote = if option == choice.index() {
                generator
            } else {
                GtElement::identity()
            };
            let commitment = ct_gt_scalar_mul(&mask_points[option], &self.scalar_bytes[option])
                .multiply(vote)
                .multiply(ct_gt_scalar_mul(&release_term, &r_bytes[option]));
            if commitment.is_identity() {
                return Err(TimedOvnError::IdentityElement);
            }
            u[option] = ephemeral;
            c[option] = commitment.to_bytes();
        }

        let proof = build_ballot_or_proof(
            &BallotProofInputsV1 {
                survivors,
                participant_hash: &self.participant_hash,
                registration,
                masks: &masks,
                choice,
                secrets: &secrets,
                r_scalars: &r_scalars,
                public_keys: &public_keys,
                mask_points: &mask_points,
                generator: &generator,
                release_term: &release_term,
                u: &u,
                c: &c,
            },
            rng,
        )?;
        let ballot = TimedOvnMaskedBallotV1 {
            session_digest: survivors.session.digest(),
            roster_root: survivors.roster_root,
            survivor_root: survivors.survivor_root,
            identity_digest: survivors.identity_digest,
            participant_hash: self.participant_hash,
            index: masks.index,
            u,
            c,
            proof,
        };
        ballot.verify(survivors)?;
        Ok(ballot)
    }
}

struct BallotProofInputsV1<'a> {
    survivors: &'a TimedOvnSurvivorRosterV1,
    participant_hash: &'a [u8; 32],
    registration: &'a TimedOvnRegistrationV1,
    masks: &'a TimedOvnMaskingKeysV1,
    choice: TimedOvnChoiceV1,
    secrets: &'a [Scalar; TIMED_OVN_CHOICE_COUNT_V1],
    r_scalars: &'a [Scalar; TIMED_OVN_CHOICE_COUNT_V1],
    public_keys: &'a [GtElement; TIMED_OVN_CHOICE_COUNT_V1],
    mask_points: &'a [GtElement; TIMED_OVN_CHOICE_COUNT_V1],
    generator: &'a GtElement,
    release_term: &'a GtElement,
    u: &'a [G2Bytes; TIMED_OVN_CHOICE_COUNT_V1],
    c: &'a [GtBytes; TIMED_OVN_CHOICE_COUNT_V1],
}

fn build_ballot_or_proof<R: TryCryptoRng + ?Sized>(
    inputs: &BallotProofInputsV1<'_>,
    rng: &mut R,
) -> Result<TimedOvnBallotOrProofV1, TimedOvnError> {
    let true_branch = inputs.choice.index();
    let mut challenges = [Scalar::from(0_u64); TIMED_OVN_CHOICE_COUNT_V1];
    let mut responses_x =
        [[Scalar::from(0_u64); TIMED_OVN_CHOICE_COUNT_V1]; TIMED_OVN_CHOICE_COUNT_V1];
    let mut responses_r =
        [[Scalar::from(0_u64); TIMED_OVN_CHOICE_COUNT_V1]; TIMED_OVN_CHOICE_COUNT_V1];
    let mut true_nonce_x =
        Zeroizing::new([[0_u8; TIMED_OVN_SCALAR_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1]);
    let mut true_nonce_r =
        Zeroizing::new([[0_u8; TIMED_OVN_SCALAR_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1]);
    let mut commitments = OrCommitments::identity();
    let ephemerals = decode_g2_array(inputs.u)?;
    let ballot_points = decode_gt_array(inputs.c, false)?;
    let statement = DecodedOrStatementV1 {
        public_keys: inputs.public_keys,
        masks: inputs.mask_points,
        ephemerals: &ephemerals,
        ballot_points: &ballot_points,
        release_term: inputs.release_term,
    };

    for branch in 0..TIMED_OVN_CHOICE_COUNT_V1 {
        if branch == true_branch {
            for option in 0..TIMED_OVN_CHOICE_COUNT_V1 {
                true_nonce_x[option] = random_nonzero_scalar_bytes(rng)?;
                true_nonce_r[option] = random_nonzero_scalar_bytes(rng)?;
                let nonce_r = decode_scalar(&true_nonce_r[option])?;
                commitments.x[branch][option] =
                    ct_gt_scalar_mul(inputs.generator, &true_nonce_x[option]);
                commitments.r[branch][option] = G2Projective::generator() * nonce_r;
                commitments.relation[branch][option] =
                    ct_gt_scalar_mul(&inputs.mask_points[option], &true_nonce_x[option])
                        .multiply(ct_gt_scalar_mul(inputs.release_term, &true_nonce_r[option]));
            }
        } else {
            challenges[branch] = decode_scalar(&random_nonzero_scalar_bytes(rng)?)?;
            for option in 0..TIMED_OVN_CHOICE_COUNT_V1 {
                responses_x[branch][option] = decode_scalar(&random_nonzero_scalar_bytes(rng)?)?;
                responses_r[branch][option] = decode_scalar(&random_nonzero_scalar_bytes(rng)?)?;
            }
            reconstruct_branch(
                branch,
                &statement,
                challenges[branch],
                &responses_x[branch],
                &responses_r[branch],
                &mut commitments,
            )?;
        }
    }
    commitments.validate_nonidentity()?;
    let challenge = ballot_challenge(
        &inputs.survivors.session,
        &inputs.survivors.roster_root,
        &inputs.survivors.survivor_root,
        &inputs.survivors.identity_digest,
        &inputs.survivors.release_term,
        inputs.participant_hash,
        inputs.masks.index,
        &inputs.registration.public_keys,
        &inputs.masks.points,
        inputs.u,
        inputs.c,
        &commitments,
    )?;
    let simulated_sum = challenges
        .iter()
        .enumerate()
        .filter(|(branch, _)| *branch != true_branch)
        .map(|(_, challenge)| *challenge)
        .sum::<Scalar>();
    challenges[true_branch] = challenge - simulated_sum;
    for option in 0..TIMED_OVN_CHOICE_COUNT_V1 {
        let nonce_x = decode_scalar(&true_nonce_x[option])?;
        let nonce_r = decode_scalar(&true_nonce_r[option])?;
        responses_x[true_branch][option] =
            nonce_x + challenges[true_branch] * inputs.secrets[option];
        responses_r[true_branch][option] =
            nonce_r + challenges[true_branch] * inputs.r_scalars[option];
    }
    Ok(TimedOvnBallotOrProofV1 {
        challenges: challenges.map(|scalar| scalar.to_bytes_be()),
        responses_x: responses_x.map(|branch| branch.map(|scalar| scalar.to_bytes_be())),
        responses_r: responses_r.map(|branch| branch.map(|scalar| scalar.to_bytes_be())),
    })
}

#[derive(Clone, Copy)]
struct OrCommitments {
    x: [[GtElement; TIMED_OVN_CHOICE_COUNT_V1]; TIMED_OVN_CHOICE_COUNT_V1],
    r: [[G2Projective; TIMED_OVN_CHOICE_COUNT_V1]; TIMED_OVN_CHOICE_COUNT_V1],
    relation: [[GtElement; TIMED_OVN_CHOICE_COUNT_V1]; TIMED_OVN_CHOICE_COUNT_V1],
}

struct DecodedOrStatementV1<'a> {
    public_keys: &'a [GtElement; TIMED_OVN_CHOICE_COUNT_V1],
    masks: &'a [GtElement; TIMED_OVN_CHOICE_COUNT_V1],
    ephemerals: &'a [G2Affine; TIMED_OVN_CHOICE_COUNT_V1],
    ballot_points: &'a [GtElement; TIMED_OVN_CHOICE_COUNT_V1],
    release_term: &'a GtElement,
}

impl OrCommitments {
    fn identity() -> Self {
        Self {
            x: [[GtElement::identity(); TIMED_OVN_CHOICE_COUNT_V1]; TIMED_OVN_CHOICE_COUNT_V1],
            r: [[G2Projective::identity(); TIMED_OVN_CHOICE_COUNT_V1]; TIMED_OVN_CHOICE_COUNT_V1],
            relation: [[GtElement::identity(); TIMED_OVN_CHOICE_COUNT_V1];
                TIMED_OVN_CHOICE_COUNT_V1],
        }
    }

    fn validate_nonidentity(&self) -> Result<(), TimedOvnError> {
        for branch in 0..TIMED_OVN_CHOICE_COUNT_V1 {
            for option in 0..TIMED_OVN_CHOICE_COUNT_V1 {
                if self.x[branch][option].is_identity()
                    || bool::from(self.r[branch][option].is_identity())
                    || self.relation[branch][option].is_identity()
                {
                    return Err(TimedOvnError::IdentityElement);
                }
            }
        }
        Ok(())
    }
}

fn reconstruct_or_commitments(
    statement: &DecodedOrStatementV1<'_>,
    challenges: &[Scalar; TIMED_OVN_CHOICE_COUNT_V1],
    responses_x: &[[Scalar; TIMED_OVN_CHOICE_COUNT_V1]; TIMED_OVN_CHOICE_COUNT_V1],
    responses_r: &[[Scalar; TIMED_OVN_CHOICE_COUNT_V1]; TIMED_OVN_CHOICE_COUNT_V1],
) -> Result<OrCommitments, TimedOvnError> {
    let mut commitments = OrCommitments::identity();
    for branch in 0..TIMED_OVN_CHOICE_COUNT_V1 {
        reconstruct_branch(
            branch,
            statement,
            challenges[branch],
            &responses_x[branch],
            &responses_r[branch],
            &mut commitments,
        )?;
    }
    commitments.validate_nonidentity()?;
    Ok(commitments)
}

fn reconstruct_branch(
    branch: usize,
    statement: &DecodedOrStatementV1<'_>,
    challenge: Scalar,
    responses_x: &[Scalar; TIMED_OVN_CHOICE_COUNT_V1],
    responses_r: &[Scalar; TIMED_OVN_CHOICE_COUNT_V1],
    commitments: &mut OrCommitments,
) -> Result<(), TimedOvnError> {
    if branch >= TIMED_OVN_CHOICE_COUNT_V1 {
        return Err(TimedOvnError::InvalidBallotProof);
    }
    let generator = target_generator()?;
    let challenge_bytes = challenge.to_bytes_be();
    for option in 0..TIMED_OVN_CHOICE_COUNT_V1 {
        let secret_response_bytes = responses_x[option].to_bytes_be();
        let ephemeral_response_bytes = responses_r[option].to_bytes_be();
        let vote_statement = if option == branch {
            statement.ballot_points[option].multiply(generator.inverse())
        } else {
            statement.ballot_points[option]
        };
        commitments.x[branch][option] = ct_gt_scalar_mul(&generator, &secret_response_bytes)
            .multiply(ct_gt_scalar_mul(&statement.public_keys[option], &challenge_bytes).inverse());
        commitments.r[branch][option] = G2Projective::generator() * responses_r[option]
            - G2Projective::from(statement.ephemerals[option]) * challenge;
        commitments.relation[branch][option] =
            ct_gt_scalar_mul(&statement.masks[option], &secret_response_bytes)
                .multiply(ct_gt_scalar_mul(
                    statement.release_term,
                    &ephemeral_response_bytes,
                ))
                .multiply(ct_gt_scalar_mul(&vote_statement, &challenge_bytes).inverse());
    }
    Ok(())
}

fn pop_challenge(
    session: &TimedOvnSessionV1,
    participant_hash: &[u8; 32],
    option: usize,
    public_key: &GtBytes,
    commitment: &GtBytes,
) -> Result<Scalar, TimedOvnError> {
    let option_tag = *OPTION_TAGS_V1
        .get(option)
        .ok_or(TimedOvnError::InvalidProofOfPossession)?;
    let mut hasher = Sha256::new();
    hasher.update(POP_CHALLENGE_DOMAIN_V1);
    hasher.update(TIMED_OVN_PROTOCOL_VERSION_V1.to_be_bytes());
    hasher.update(session.canonical_bytes());
    hasher.update(participant_hash);
    hasher.update([option_tag]);
    hasher.update(public_key);
    hasher.update(commitment);
    scalar_from_transcript(&hasher)
}

#[allow(clippy::too_many_arguments)]
fn ballot_challenge(
    session: &TimedOvnSessionV1,
    roster_root: &[u8; 32],
    survivor_root: &[u8; 32],
    identity_digest: &[u8; 32],
    release_term: &GtBytes,
    participant_hash: &[u8; 32],
    index: u16,
    public_keys: &[GtBytes; TIMED_OVN_CHOICE_COUNT_V1],
    masks: &[GtBytes; TIMED_OVN_CHOICE_COUNT_V1],
    ephemerals: &[G2Bytes; TIMED_OVN_CHOICE_COUNT_V1],
    ballot_points: &[GtBytes; TIMED_OVN_CHOICE_COUNT_V1],
    commitments: &OrCommitments,
) -> Result<Scalar, TimedOvnError> {
    commitments.validate_nonidentity()?;
    let mut hasher = Sha256::new();
    hasher.update(BALLOT_CHALLENGE_DOMAIN_V1);
    hasher.update(TIMED_OVN_PROTOCOL_VERSION_V1.to_be_bytes());
    hasher.update(session.canonical_bytes());
    hasher.update(roster_root);
    hasher.update(survivor_root);
    hasher.update(identity_digest);
    hasher.update(release_term);
    hasher.update(participant_hash);
    hasher.update(index.to_be_bytes());
    for (option, option_tag) in OPTION_TAGS_V1.iter().copied().enumerate() {
        hasher.update([option_tag]);
        hasher.update(public_keys[option]);
        hasher.update(masks[option]);
        hasher.update(ephemerals[option]);
        hasher.update(ballot_points[option]);
    }
    for (branch, option_tag) in OPTION_TAGS_V1.iter().copied().enumerate() {
        hasher.update([option_tag]);
        for option in 0..TIMED_OVN_CHOICE_COUNT_V1 {
            hasher.update(commitments.x[branch][option].to_bytes());
            hasher.update(commitments.r[branch][option].to_affine().to_compressed());
            hasher.update(commitments.relation[branch][option].to_bytes());
        }
    }
    scalar_from_transcript(&hasher)
}

fn scalar_from_transcript(hasher: &Sha256) -> Result<Scalar, TimedOvnError> {
    for counter in 0_u32..=SCALAR_REJECTION_LIMIT {
        let mut attempt = (*hasher).clone();
        attempt.update(counter.to_be_bytes());
        let candidate: ScalarBytes = attempt.finalize().into();
        if let Some(scalar) = Scalar::from_bytes_be(&candidate).into_option() {
            return Ok(scalar);
        }
    }
    Err(TimedOvnError::ScalarDerivation)
}

/// Public timed aggregate carrying type-level ballot-validation provenance.
///
/// The default provenance is returned only by [`aggregate_timed_ovn_ballots_v1`] after replaying
/// every ballot proof. Core's rolling accumulator instead returns the distinct
/// [`TimedOvnCommittedAggregateCacheV1`] type for bounded live transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedOvnAggregateV1<Provenance = TimedOvnProofVerifiedV1> {
    session_digest: [u8; 32],
    roster_root: [u8; 32],
    survivor_root: [u8; 32],
    identity_digest: [u8; 32],
    accepted_ballots: u16,
    aggregate_u: [G2Bytes; TIMED_OVN_CHOICE_COUNT_V1],
    aggregate_c: [GtBytes; TIMED_OVN_CHOICE_COUNT_V1],
    provenance: PhantomData<Provenance>,
}

/// Shape-checked rolling aggregate reconstructed from committed consensus state.
///
/// This type does not claim that individual ballot proofs were replayed. It can be opened only
/// through methods whose receiver retains committed-cache provenance, while snapshot restoration
/// must independently rebuild a [`TimedOvnAggregateV1`] from every exact ballot record.
///
/// ```compile_fail
/// use iroha_crypto::timed_ovn::{TimedOvnAggregateV1, TimedOvnCommittedAggregateCacheV1};
///
/// fn require_verified(_: TimedOvnAggregateV1) {}
/// fn cannot_promote(cache: TimedOvnCommittedAggregateCacheV1) {
///     require_verified(cache);
/// }
/// ```
pub type TimedOvnCommittedAggregateCacheV1 = TimedOvnAggregateV1<TimedOvnCommittedCacheV1>;

impl TimedOvnCommittedAggregateCacheV1 {
    /// Reconstruct a rolling aggregate admitted from proof-verified ballot chunks.
    ///
    /// This validates every public binding and canonical aggregate element but does not replay
    /// individual ballot proofs. Persisted snapshot admission must independently rebuild the same
    /// aggregate from the exact ballot records.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for an invalid count, binding, or aggregate encoding.
    pub fn from_committed_accumulator(
        common: &TimedOvnBallotVerificationCommonV1,
        accepted_ballots: u16,
        aggregate_u: &[G2Bytes; TIMED_OVN_CHOICE_COUNT_V1],
        aggregate_c: &[GtBytes; TIMED_OVN_CHOICE_COUNT_V1],
    ) -> Result<Self, TimedOvnError> {
        if accepted_ballots == 0 || usize::from(accepted_ballots) > TIMED_OVN_MAX_PARTICIPANTS_V1 {
            return Err(TimedOvnError::InvalidRosterSize);
        }
        for encoded in aggregate_u {
            decode_g2(encoded, true)?;
        }
        for encoded in aggregate_c {
            GtElement::from_bytes(encoded, true)?;
        }
        Ok(Self {
            session_digest: common.session_digest(),
            roster_root: common.roster_root,
            survivor_root: common.survivor_root,
            identity_digest: common.identity_digest,
            accepted_ballots,
            aggregate_u: *aggregate_u,
            aggregate_c: *aggregate_c,
            provenance: PhantomData,
        })
    }
}

impl<Provenance> TimedOvnAggregateV1<Provenance> {
    /// Open only the exact aggregate and bounded-decode Aye/Nay/Abstain counts.
    ///
    /// No individual decrypted ballot component is returned or made available.
    /// A wrong/withheld release key, cancellation failure, or out-of-range
    /// result fails the complete attempt.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for any binding/release/cancellation failure.
    pub fn open_and_tally(
        &self,
        survivors: &TimedOvnSurvivorRosterV1,
        identity_secret: &TleIdentitySecretKeyV1,
    ) -> Result<TimedOvnTallyV1, TimedOvnError> {
        let common = survivors.verification_common()?;
        self.open_and_tally_with_common(&common, survivors.registrations.len(), identity_secret)
    }

    /// Open a snapshot-checked rolling aggregate without replaying its individual ballots.
    ///
    /// # Errors
    ///
    /// Returns [`TimedOvnError`] for any binding, release, cancellation, or tally failure.
    pub fn open_and_tally_with_common(
        &self,
        common: &TimedOvnBallotVerificationCommonV1,
        expected_ballots: usize,
        identity_secret: &TleIdentitySecretKeyV1,
    ) -> Result<TimedOvnTallyV1, TimedOvnError> {
        if self.session_digest != common.session_digest()
            || self.roster_root != common.roster_root
            || self.survivor_root != common.survivor_root
            || self.identity_digest != common.identity_digest
            || usize::from(self.accepted_ballots) != expected_ballots
        {
            return Err(TimedOvnError::BindingMismatch);
        }
        let secret_point = identity_secret
            .pairing_secret_point(
                &common.session.tle_master_public_key,
                &common.release_identity,
            )
            .map_err(|_| TimedOvnError::ReleaseFailed)?;
        let generator = target_generator()?;
        let mut counts = [0_u16; TIMED_OVN_CHOICE_COUNT_V1];
        for ((count, encoded_u), encoded_c) in counts
            .iter_mut()
            .zip(&self.aggregate_u)
            .zip(&self.aggregate_c)
        {
            // Identity aggregates are valid: non-identity per-ballot
            // ephemerals can sum to zero, and sealed GT terms can multiply to
            // one. Rejecting either only after the complete corpus was frozen
            // would give the last voter a strategic `NoResult` lever. The
            // individual ballot parser still rejects identity elements.
            let aggregate_u = decode_g2(encoded_u, true)?;
            let aggregate_c = GtElement::from_bytes(encoded_c, true)?;
            let release = if bool::from(aggregate_u.is_identity()) {
                GtElement::identity()
            } else {
                pairing_gt(&secret_point, &aggregate_u)?
            };
            let opened = aggregate_c.multiply(release.inverse());
            *count = bounded_discrete_log(&opened, &generator, self.accepted_ballots)
                .ok_or(TimedOvnError::MaskCancellationFailed)?;
        }
        let total = counts
            .iter()
            .try_fold(0_u16, |sum, count| sum.checked_add(*count));
        if total != Some(self.accepted_ballots) {
            return Err(TimedOvnError::InvalidTally);
        }
        Ok(TimedOvnTallyV1 {
            aye: counts[TimedOvnChoiceV1::Aye.index()],
            nay: counts[TimedOvnChoiceV1::Nay.index()],
            abstain: counts[TimedOvnChoiceV1::Abstain.index()],
        })
    }

    /// Return the exact accepted survivor-ballot count.
    #[must_use]
    pub const fn accepted_ballots(&self) -> u16 {
        self.accepted_ballots
    }

    /// Return the aggregate ephemeral G2 values.
    #[must_use]
    pub const fn aggregate_ephemerals(&self) -> &[G2Bytes; TIMED_OVN_CHOICE_COUNT_V1] {
        &self.aggregate_u
    }

    /// Return the sealed aggregate target-group values.
    #[must_use]
    pub const fn aggregate_commitments(&self) -> &[GtBytes; TIMED_OVN_CHOICE_COUNT_V1] {
        &self.aggregate_c
    }
}

/// Fold one already proof-verified ballot into a replay-checkable rolling public aggregate.
///
/// The caller must have obtained `ballot` through [`TimedOvnMaskedBallotV1::from_bytes`] or
/// [`TimedOvnMaskedBallotV1::from_bytes_with_context`] and must separately enforce exact survivor
/// order and cross-ballot ephemeral uniqueness. This helper validates all aggregate encodings and
/// performs only the deterministic public group fold.
///
/// # Errors
///
/// Returns [`TimedOvnError`] for malformed aggregate or ballot group elements.
pub fn fold_verified_timed_ovn_ballot_v1(
    aggregate_u: &[G2Bytes; TIMED_OVN_CHOICE_COUNT_V1],
    aggregate_c: &[GtBytes; TIMED_OVN_CHOICE_COUNT_V1],
    ballot: &TimedOvnMaskedBallotV1,
) -> Result<
    (
        [G2Bytes; TIMED_OVN_CHOICE_COUNT_V1],
        [GtBytes; TIMED_OVN_CHOICE_COUNT_V1],
    ),
    TimedOvnError,
> {
    let mut folded_u = [[0_u8; TIMED_OVN_G2_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1];
    let mut folded_c = [[0_u8; TIMED_OVN_GT_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1];
    for option in 0..TIMED_OVN_CHOICE_COUNT_V1 {
        folded_u[option] = (G2Projective::from(decode_g2(&aggregate_u[option], true)?)
            + G2Projective::from(decode_nonidentity_g2(&ballot.u[option])?))
        .to_affine()
        .to_compressed();
        folded_c[option] = GtElement::from_bytes(&aggregate_c[option], true)?
            .multiply(GtElement::from_bytes(&ballot.c[option], false)?)
            .to_bytes();
    }
    Ok((folded_u, folded_c))
}

/// Decoded timed-OVN Aye/Nay/Abstain counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimedOvnTallyV1 {
    /// Number of Aye ballots.
    pub aye: u16,
    /// Number of Nay ballots.
    pub nay: u16,
    /// Number of Abstain ballots.
    pub abstain: u16,
}

/// Verify and aggregate exactly one ballot per frozen survivor, in order.
///
/// The function has no partial-success mode.  An omitted, duplicated,
/// reordered, replayed, or invalid ballot makes the whole attempt fail.
///
/// # Errors
///
/// Returns [`TimedOvnError`] unless `ballots` is the exact valid survivor corpus.
pub fn aggregate_timed_ovn_ballots_v1(
    survivors: &TimedOvnSurvivorRosterV1,
    ballots: &[TimedOvnMaskedBallotV1],
) -> Result<TimedOvnAggregateV1, TimedOvnError> {
    if ballots.len() != survivors.registrations.len() {
        return Err(TimedOvnError::NonCanonicalBallotCorpus);
    }
    let mut aggregate_u = [G2Projective::identity(); TIMED_OVN_CHOICE_COUNT_V1];
    let mut aggregate_c = [GtElement::identity(); TIMED_OVN_CHOICE_COUNT_V1];
    let mut ephemerals = HashSet::with_capacity(ballots.len() * TIMED_OVN_CHOICE_COUNT_V1);
    for (index, (ballot, registration)) in ballots.iter().zip(&survivors.registrations).enumerate()
    {
        if usize::from(ballot.index) != index
            || ballot.participant_hash != registration.participant_hash
        {
            return Err(TimedOvnError::NonCanonicalBallotCorpus);
        }
        ballot.verify(survivors)?;
        for option in 0..TIMED_OVN_CHOICE_COUNT_V1 {
            if !ephemerals.insert(ballot.u[option]) {
                return Err(TimedOvnError::DuplicateEphemeral);
            }
            aggregate_u[option] += G2Projective::from(decode_nonidentity_g2(&ballot.u[option])?);
            aggregate_c[option] =
                aggregate_c[option].multiply(GtElement::from_bytes(&ballot.c[option], false)?);
        }
    }
    let mut encoded_u = [[0_u8; TIMED_OVN_G2_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1];
    let mut encoded_c = [[0_u8; TIMED_OVN_GT_BYTES_V1]; TIMED_OVN_CHOICE_COUNT_V1];
    for option in 0..TIMED_OVN_CHOICE_COUNT_V1 {
        // Aggregate identities are canonical and openable. In particular, an
        // adversarial last voter can make a sum of otherwise valid G2
        // ephemerals equal zero; treating that as a post-admission error would
        // create a strategic `NoResult` oracle.
        encoded_u[option] = aggregate_u[option].to_affine().to_compressed();
        encoded_c[option] = aggregate_c[option].to_bytes();
    }
    Ok(TimedOvnAggregateV1 {
        session_digest: survivors.session.digest(),
        roster_root: survivors.roster_root,
        survivor_root: survivors.survivor_root,
        identity_digest: survivors.identity_digest,
        accepted_ballots: u16::try_from(ballots.len())
            .map_err(|_| TimedOvnError::InvalidRosterSize)?,
        aggregate_u: encoded_u,
        aggregate_c: encoded_c,
        provenance: PhantomData,
    })
}

fn bounded_discrete_log(target: &GtElement, generator: &GtElement, max: u16) -> Option<u16> {
    if usize::from(max) > TIMED_OVN_MAX_PARTICIPANTS_V1 {
        return None;
    }
    let mut candidate = GtElement::identity();
    for count in 0_u16..=max {
        if candidate == *target {
            return Some(count);
        }
        candidate = candidate.multiply(*generator);
    }
    None
}

fn select_survivors<Provenance: Clone>(
    roster: &TimedOvnRosterV1<Provenance>,
    survivor_ids: &[[u8; 32]],
) -> Result<Vec<TimedOvnRegistrationV1<Provenance>>, TimedOvnError> {
    if survivor_ids.is_empty() || survivor_ids.len() > roster.registrations.len() {
        return Err(TimedOvnError::InvalidRosterSize);
    }
    let mut registrations = Vec::with_capacity(survivor_ids.len());
    let mut roster_cursor = 0_usize;
    for survivor_id in survivor_ids {
        if is_zero(survivor_id) {
            return Err(TimedOvnError::NonCanonicalSurvivorSet);
        }
        while roster_cursor < roster.registrations.len()
            && roster.registrations[roster_cursor].participant_hash < *survivor_id
        {
            roster_cursor += 1;
        }
        let registration = roster
            .registrations
            .get(roster_cursor)
            .filter(|registration| registration.participant_hash == *survivor_id)
            .ok_or(TimedOvnError::NonCanonicalSurvivorSet)?;
        registrations.push(registration.clone());
        roster_cursor += 1;
    }
    Ok(registrations)
}

fn roster_root<Provenance>(
    session: &TimedOvnSessionV1,
    registrations: &[TimedOvnRegistrationV1<Provenance>],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROSTER_ROOT_DOMAIN_V1);
    hasher.update(TIMED_OVN_PROTOCOL_VERSION_V1.to_be_bytes());
    hasher.update(session.canonical_bytes());
    let registration_count =
        u32::try_from(registrations.len()).expect("timed-OVN v1 roster bound fits u32");
    hasher.update(registration_count.to_be_bytes());
    for registration in registrations {
        hasher.update(registration.to_bytes());
    }
    hasher.finalize().into()
}

fn survivor_root<Provenance>(
    session: &TimedOvnSessionV1,
    roster_root: &[u8; 32],
    registrations: &[TimedOvnRegistrationV1<Provenance>],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SURVIVOR_ROOT_DOMAIN_V1);
    hasher.update(TIMED_OVN_PROTOCOL_VERSION_V1.to_be_bytes());
    hasher.update(session.canonical_bytes());
    hasher.update(roster_root);
    let registration_count =
        u32::try_from(registrations.len()).expect("timed-OVN v1 roster bound fits u32");
    hasher.update(registration_count.to_be_bytes());
    for registration in registrations {
        hasher.update(registration.participant_hash);
        for public_key in registration.public_keys {
            hasher.update(public_key);
        }
    }
    hasher.finalize().into()
}

fn decode_nonidentity_g2(bytes: &G2Bytes) -> Result<G2Affine, TimedOvnError> {
    decode_g2(bytes, false)
}

fn decode_g2(bytes: &G2Bytes, allow_identity: bool) -> Result<G2Affine, TimedOvnError> {
    let point = G2Affine::from_compressed(bytes)
        .into_option()
        .ok_or(TimedOvnError::InvalidG2Point)?;
    if !allow_identity && bool::from(point.is_identity()) {
        return Err(TimedOvnError::IdentityElement);
    }
    if point.to_compressed() != *bytes {
        return Err(TimedOvnError::InvalidG2Point);
    }
    Ok(point)
}

fn decode_g2_array(
    bytes: &[G2Bytes; TIMED_OVN_CHOICE_COUNT_V1],
) -> Result<[G2Affine; TIMED_OVN_CHOICE_COUNT_V1], TimedOvnError> {
    let mut points = [G2Affine::identity(); TIMED_OVN_CHOICE_COUNT_V1];
    for (point, encoded) in points.iter_mut().zip(bytes) {
        *point = decode_nonidentity_g2(encoded)?;
    }
    Ok(points)
}

fn decode_gt_array(
    bytes: &[GtBytes; TIMED_OVN_CHOICE_COUNT_V1],
    allow_identity: bool,
) -> Result<[GtElement; TIMED_OVN_CHOICE_COUNT_V1], TimedOvnError> {
    let mut points = [GtElement::identity(); TIMED_OVN_CHOICE_COUNT_V1];
    for (point, encoded) in points.iter_mut().zip(bytes) {
        *point = GtElement::from_bytes(encoded, allow_identity)?;
    }
    Ok(points)
}

fn decode_scalar(bytes: &ScalarBytes) -> Result<Scalar, TimedOvnError> {
    Scalar::from_bytes_be(bytes)
        .into_option()
        .ok_or(TimedOvnError::InvalidScalar)
}

fn decode_scalar_array(
    bytes: &[ScalarBytes; TIMED_OVN_CHOICE_COUNT_V1],
) -> Result<[Scalar; TIMED_OVN_CHOICE_COUNT_V1], TimedOvnError> {
    let mut scalars = [Scalar::from(0_u64); TIMED_OVN_CHOICE_COUNT_V1];
    for (scalar, encoded) in scalars.iter_mut().zip(bytes) {
        *scalar = decode_scalar(encoded)?;
    }
    Ok(scalars)
}

fn decode_scalar_matrix(
    bytes: &[[ScalarBytes; TIMED_OVN_CHOICE_COUNT_V1]; TIMED_OVN_CHOICE_COUNT_V1],
) -> Result<[[Scalar; TIMED_OVN_CHOICE_COUNT_V1]; TIMED_OVN_CHOICE_COUNT_V1], TimedOvnError> {
    let mut scalars = [[Scalar::from(0_u64); TIMED_OVN_CHOICE_COUNT_V1]; TIMED_OVN_CHOICE_COUNT_V1];
    for (decoded_branch, encoded_branch) in scalars.iter_mut().zip(bytes) {
        for (scalar, encoded) in decoded_branch.iter_mut().zip(encoded_branch) {
            *scalar = decode_scalar(encoded)?;
        }
    }
    Ok(scalars)
}

fn random_nonzero_scalar_bytes<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<ScalarBytes, TimedOvnError> {
    let mut candidate = Zeroizing::new([0_u8; TIMED_OVN_SCALAR_BYTES_V1]);
    for _ in 0_u32..=SCALAR_REJECTION_LIMIT {
        rng.try_fill_bytes(candidate.as_mut())
            .map_err(|_| TimedOvnError::RandomnessUnavailable)?;
        if let Some(scalar) = Scalar::from_bytes_be(&candidate).into_option()
            && scalar != Scalar::from(0_u64)
        {
            return Ok(*candidate);
        }
    }
    Err(TimedOvnError::InertRandomness)
}

fn take<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], TimedOvnError> {
    let end = cursor
        .checked_add(N)
        .ok_or(TimedOvnError::InvalidEncoding)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(TimedOvnError::InvalidEncoding)?
        .try_into()
        .map_err(|_| TimedOvnError::InvalidEncoding)?;
    *cursor = end;
    Ok(value)
}

fn append_fixed<const N: usize>(destination: &mut [u8], cursor: &mut usize, value: &[u8; N]) {
    let end = cursor
        .checked_add(N)
        .expect("fixed audit-manifest encoding length cannot overflow");
    destination[*cursor..end].copy_from_slice(value);
    *cursor = end;
}

fn official_release_audit_artifact_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(
        u64::try_from(bytes.len())
            .expect("in-memory release artifact length fits u64")
            .to_be_bytes(),
    );
    hasher.update(bytes);
    hasher.finalize().into()
}

fn parse_official_release_audit_reviewer_key(
    bytes: &[u8; 32],
) -> Result<ed25519_dalek::VerifyingKey, TimedOvnError> {
    if is_zero(bytes) {
        return Err(TimedOvnError::InvalidOfficialReleaseAuditManifest);
    }
    let compressed = curve25519_dalek::edwards::CompressedEdwardsY(*bytes);
    let point = compressed
        .decompress()
        .ok_or(TimedOvnError::InvalidOfficialReleaseAuditManifest)?;
    if point.compress().as_bytes() != bytes || point.is_small_order() || !point.is_torsion_free() {
        return Err(TimedOvnError::InvalidOfficialReleaseAuditManifest);
    }
    ed25519_dalek::VerifyingKey::from_bytes(bytes)
        .map_err(|_| TimedOvnError::InvalidOfficialReleaseAuditManifest)
}

fn verify_official_release_audit_signature(
    statement: &TimedOvnOfficialReleaseAuditStatementV1,
    signature: &[u8; 64],
) -> Result<(), TimedOvnError> {
    let public_key = parse_official_release_audit_reviewer_key(&statement.reviewer_public_key)?;
    let encoded_r: [u8; 32] = signature[..32]
        .try_into()
        .map_err(|_| TimedOvnError::InvalidOfficialReleaseAuditSignature)?;
    let r_point = curve25519_dalek::edwards::CompressedEdwardsY(encoded_r)
        .decompress()
        .ok_or(TimedOvnError::InvalidOfficialReleaseAuditSignature)?;
    if r_point.compress().as_bytes() != &encoded_r || r_point.is_small_order() {
        return Err(TimedOvnError::InvalidOfficialReleaseAuditSignature);
    }
    public_key
        .verify_strict(
            &statement.signing_bytes(),
            &ed25519_dalek::Signature::from_bytes(signature),
        )
        .map_err(|_| TimedOvnError::InvalidOfficialReleaseAuditSignature)
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use ::signature::Signer as _;
    use blstrs::pairing;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng as _;

    use crate::threshold_bls::{ThresholdBlsSession, TleReleasePurpose};

    use super::*;

    fn binding(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    struct Fixture {
        roster: TimedOvnRosterV1,
        survivors: TimedOvnSurvivorRosterV1,
        secrets: Vec<TimedOvnRegistrationSecretV1>,
        identity_secret: TleIdentitySecretKeyV1,
    }

    struct OfficialAuditFixture {
        artifacts: TimedOvnOfficialReleaseAuditArtifactsV1<'static>,
        reviewer: ed25519_dalek::SigningKey,
        reviewer_public_key: [u8; 32],
        manifest: TimedOvnOfficialReleaseAuditManifestV1,
        manifest_bytes: [u8; TIMED_OVN_OFFICIAL_RELEASE_AUDIT_MANIFEST_BYTES_V1],
    }

    fn official_audit_fixture() -> OfficialAuditFixture {
        let artifacts = TimedOvnOfficialReleaseAuditArtifactsV1::new(
            b"canonical timed-ovn source archive test vector",
            b"release binary and toolchain manifest test vector",
            b"supported target inventory test vector",
            b"independent side-channel report test vector",
            b"compiler assembly and timing evidence archive test vector",
        )
        .expect("nonempty synthetic release artifacts");
        let reviewer = ed25519_dalek::SigningKey::from_bytes(&[71_u8; 32]);
        let reviewer_public_key = reviewer.verifying_key().to_bytes();
        let statement = TimedOvnOfficialReleaseAuditStatementV1::from_artifacts(
            TimedOvnOfficialReleaseAuditVerdictV1::ApprovedForOfficialRelease,
            &artifacts,
            reviewer_public_key,
        )
        .expect("canonical synthetic audit statement");
        let signature = reviewer.sign(&statement.signing_bytes()).to_bytes();
        let manifest = TimedOvnOfficialReleaseAuditManifestV1::from_statement_and_signature(
            statement, signature,
        )
        .expect("valid synthetic signed manifest");
        OfficialAuditFixture {
            artifacts,
            reviewer,
            reviewer_public_key,
            manifest,
            manifest_bytes: manifest.to_bytes(),
        }
    }

    fn fixture(seed: u8) -> Fixture {
        let threshold_session = ThresholdBlsSession::<TleReleasePurpose>::new(
            binding(seed),
            binding(seed.wrapping_add(1)),
            binding(seed.wrapping_add(2)),
            4,
            2,
        )
        .expect("threshold session");
        let master_scalar = Scalar::from(u64::from(seed) + 7);
        let master_bytes = (G2Affine::generator() * master_scalar)
            .to_affine()
            .to_compressed();
        let master = TleMasterPublicKey::from_bytes(*threshold_session.session_id(), &master_bytes)
            .expect("master key");
        let session = TimedOvnSessionV1::new(
            binding(seed),
            binding(seed.wrapping_add(3)),
            binding(seed.wrapping_add(4)),
            binding(seed.wrapping_add(5)),
            binding(seed.wrapping_add(6)),
            timed_ovn_parameter_hash_v1(),
            master,
        )
        .expect("timed session");
        let participant_ids = [binding(40), binding(50), binding(60)];
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let mut secrets = Vec::new();
        let mut registrations = Vec::new();
        for participant in participant_ids {
            let (secret, registration) =
                TimedOvnRegistrationSecretV1::generate_with_rng(&session, participant, &mut rng)
                    .expect("registration");
            secrets.push(secret);
            registrations.push(registration);
        }
        let roster = TimedOvnRosterV1::new(&session, registrations).expect("roster");
        let survivor_root = roster
            .prospective_survivor_root(&participant_ids)
            .expect("survivor root");
        let identity = TleReleaseIdentityV1::new(
            threshold_session,
            binding(seed.wrapping_add(4)),
            binding(seed.wrapping_add(5)),
            binding(seed.wrapping_add(6)),
            survivor_root,
            binding(seed.wrapping_add(8)),
            10_000,
            timed_ovn_parameter_hash_v1(),
        )
        .expect("release identity");
        let release_message = identity.release_message().expect("release message");
        let release_secret = (hash_message_to_g1::<TleReleasePurpose>(&release_message)
            * master_scalar)
            .to_affine()
            .to_compressed();
        let identity_secret =
            TleIdentitySecretKeyV1::from_threshold_signature(master, &identity, &release_secret)
                .expect("identity secret");
        let survivors =
            TimedOvnSurvivorRosterV1::new(&roster, &participant_ids, &identity).expect("survivors");
        Fixture {
            roster,
            survivors,
            secrets,
            identity_secret,
        }
    }

    fn cast_fixture_ballots(fixture: &Fixture, seed: u8) -> Vec<TimedOvnMaskedBallotV1> {
        let choices = [
            TimedOvnChoiceV1::Aye,
            TimedOvnChoiceV1::Nay,
            TimedOvnChoiceV1::Abstain,
        ];
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        fixture
            .secrets
            .iter()
            .zip(choices)
            .map(|(secret, choice)| {
                secret
                    .cast_ballot_with_rng(&fixture.survivors, choice, &mut rng)
                    .expect("cast ballot")
            })
            .collect()
    }

    #[test]
    fn fixed_parameter_profile_is_derived_and_cannot_be_wire_selected() {
        let fixture = fixture(6);
        let parameter_hash = timed_ovn_parameter_hash_v1();
        assert_eq!(
            parameter_hash,
            [
                0x4e, 0x2c, 0xa9, 0xb3, 0xd2, 0x09, 0xb7, 0xf4, 0xcb, 0x1e, 0x30, 0x70, 0x60, 0xba,
                0x1b, 0xd3, 0x00, 0x10, 0x31, 0x3e, 0xe1, 0x21, 0x63, 0x44, 0xaf, 0xc8, 0xf7, 0x28,
                0x7e, 0x1c, 0x61, 0x9a,
            ]
        );
        assert_eq!(
            TimedOvnSessionV1::new(
                binding(6),
                binding(9),
                binding(10),
                binding(11),
                binding(12),
                binding(13),
                *fixture.roster.session().tle_master_public_key(),
            ),
            Err(TimedOvnError::ParameterProfileMismatch)
        );
    }

    #[test]
    fn gt_wire_is_canonical_subgroup_checked_and_nonidentity() {
        let generator = target_generator().expect("target generator");
        let bytes = generator.to_bytes();
        assert_eq!(
            GtElement::from_bytes(&bytes, false)
                .expect("canonical GT")
                .to_bytes(),
            bytes
        );

        let identity = GtElement::identity().to_bytes();
        assert_eq!(
            GtElement::from_bytes(&identity, false),
            Err(TimedOvnError::IdentityElement)
        );
        assert!(GtElement::from_bytes(&identity, true).is_ok());

        let mut noncanonical = bytes;
        noncanonical[..FP_BYTES].copy_from_slice(&[
            0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b,
            0xac, 0xd7, 0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0,
            0xf6, 0xb0, 0xf6, 0x24, 0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe,
            0xff, 0xff, 0xff, 0xff, 0xaa, 0xab,
        ]);
        assert!(matches!(
            GtElement::from_bytes(&noncanonical, false),
            Err(TimedOvnError::InvalidTargetGroupElement)
        ));

        let mut malformed = bytes;
        malformed[TIMED_OVN_GT_BYTES_V1 - 1] ^= 1;
        assert!(GtElement::from_bytes(&malformed, false).is_err());
    }

    #[test]
    fn ct_gt_multiplication_matches_public_blstrs_path() {
        let scalar = Scalar::from(0xdead_beef_u64);
        let generator = target_generator().expect("generator");
        let actual = ct_gt_scalar_mul(&generator, &scalar.to_bytes_be());

        let scaled_g1 = (G1Affine::generator() * scalar).to_affine();
        let direct_pairing = pairing_gt(&scaled_g1, &G2Affine::generator()).expect("pairing");
        assert_eq!(actual, direct_pairing);

        let public_product = pairing(&G1Affine::generator(), &G2Affine::generator()) * scalar;
        let public_bilinear = pairing(&scaled_g1, &G2Affine::generator());
        assert_eq!(public_product, public_bilinear);
    }

    #[test]
    fn ct_gt_operation_count_is_scalar_invariant() {
        let generator = target_generator().expect("generator");
        let scalars = [Scalar::from(1_u64), Scalar::from(u64::MAX)];
        let mut observed = Vec::new();
        for scalar in scalars {
            let mut counts = [0_usize; 3];
            let _ = ct_gt_scalar_mul_inner::<true>(&generator, &scalar.to_bytes_be(), &mut counts);
            observed.push(counts);
        }
        assert_eq!(observed[0], observed[1]);
        assert_eq!(
            observed[0],
            [
                TIMED_OVN_CT_SCALAR_BITS_V1,
                TIMED_OVN_CT_SCALAR_BITS_V1,
                TIMED_OVN_CT_SCALAR_BITS_V1 * FP12_LIMBS,
            ]
        );
    }

    #[test]
    fn registration_and_ballot_wires_roundtrip_exactly() {
        let fixture = fixture(11);
        let registration = &fixture.roster.registrations()[0];
        let encoded_registration = registration.to_bytes();
        assert_eq!(encoded_registration.len(), REGISTRATION_WIRE_BYTES_V1);
        assert_eq!(
            TimedOvnRegistrationV1::from_bytes(fixture.roster.session(), &encoded_registration,),
            Ok(registration.clone())
        );
        let cached_registration = TimedOvnCommittedRegistrationCacheV1::from_committed_record(
            fixture.roster.session(),
            &encoded_registration,
        )
        .expect("committed registration cache");
        assert_eq!(cached_registration.to_bytes(), encoded_registration);
        let cached_registrations = fixture
            .roster
            .registrations()
            .iter()
            .map(|registration| {
                TimedOvnCommittedRegistrationCacheV1::from_committed_record(
                    fixture.roster.session(),
                    &registration.to_bytes(),
                )
                .expect("committed registration cache")
            })
            .collect();
        let cached_roster = TimedOvnCommittedRosterCacheV1::from_committed_records(
            fixture.roster.session(),
            cached_registrations,
        )
        .expect("committed roster");
        assert_eq!(cached_roster.roster_root(), fixture.roster.roster_root());
        let cached_survivors = TimedOvnCommittedSurvivorRosterCacheV1::from_committed_roster(
            &cached_roster,
            &fixture
                .roster
                .registrations()
                .iter()
                .map(|registration| *registration.participant_hash())
                .collect::<Vec<_>>(),
            &fixture.survivors.release_identity,
        )
        .expect("committed survivor cache");
        assert_eq!(
            cached_survivors.masking_key_points(),
            fixture.survivors.masking_key_points()
        );
        let mut trailing = encoded_registration.clone();
        trailing.push(0);
        assert_eq!(
            TimedOvnRegistrationV1::from_bytes(fixture.roster.session(), &trailing),
            Err(TimedOvnError::InvalidEncoding)
        );

        let ballot = cast_fixture_ballots(&fixture, 12).remove(0);
        let encoded_ballot = ballot.to_bytes();
        assert_eq!(encoded_ballot.len(), BALLOT_WIRE_BYTES_V1);
        assert_eq!(
            TimedOvnMaskedBallotV1::from_bytes(&fixture.survivors, &encoded_ballot),
            Ok(ballot.clone())
        );
        let context = fixture
            .survivors
            .verification_context_at(0)
            .expect("cached ballot context");
        assert_eq!(
            TimedOvnMaskedBallotV1::from_bytes_with_context(&context, &encoded_ballot),
            Ok(ballot)
        );
        assert_eq!(
            TimedOvnMaskedBallotV1::from_bytes(
                &fixture.survivors,
                &encoded_ballot[..encoded_ballot.len() - 1],
            ),
            Err(TimedOvnError::InvalidEncoding)
        );
    }

    #[test]
    fn committed_registration_cache_cannot_claim_invalid_proof_verification() {
        let fixture = fixture(12);
        let mut encoded = fixture.roster.registrations()[0].to_bytes();
        let first_response = encoded.len() - TIMED_OVN_CHOICE_COUNT_V1 * TIMED_OVN_SCALAR_BYTES_V1;
        encoded[first_response..first_response + TIMED_OVN_SCALAR_BYTES_V1]
            .copy_from_slice(&Scalar::from(1_u64).to_bytes_be());

        assert_eq!(
            TimedOvnRegistrationV1::from_bytes(fixture.roster.session(), &encoded),
            Err(TimedOvnError::InvalidProofOfPossession)
        );
        let cache = TimedOvnCommittedRegistrationCacheV1::from_committed_record(
            fixture.roster.session(),
            &encoded,
        )
        .expect("canonical shape remains cacheable");
        assert_eq!(
            cache.verify(fixture.roster.session()),
            Err(TimedOvnError::InvalidProofOfPossession)
        );
    }

    #[test]
    fn folded_tle_term_opens_only_the_exact_aggregate() {
        let fixture = fixture(13);
        let ballots = cast_fixture_ballots(&fixture, 14);
        let aggregate =
            aggregate_timed_ovn_ballots_v1(&fixture.survivors, &ballots).expect("aggregate");
        assert_eq!(aggregate.accepted_ballots(), 3);
        assert_eq!(
            aggregate.open_and_tally(&fixture.survivors, &fixture.identity_secret),
            Ok(TimedOvnTallyV1 {
                aye: 1,
                nay: 1,
                abstain: 1,
            })
        );

        let common = fixture
            .survivors
            .verification_common()
            .expect("common verification bindings");
        let mut folded_u = *ballots[0].ephemerals();
        let mut folded_c = *ballots[0].commitments();
        for ballot in &ballots[1..] {
            (folded_u, folded_c) = fold_verified_timed_ovn_ballot_v1(&folded_u, &folded_c, ballot)
                .expect("fold verified ballot");
        }
        let cached_aggregate = TimedOvnCommittedAggregateCacheV1::from_committed_accumulator(
            &common, 3, &folded_u, &folded_c,
        )
        .expect("committed aggregate");
        assert_eq!(
            cached_aggregate.accepted_ballots(),
            aggregate.accepted_ballots()
        );
        assert_eq!(
            cached_aggregate.aggregate_ephemerals(),
            aggregate.aggregate_ephemerals()
        );
        assert_eq!(
            cached_aggregate.aggregate_commitments(),
            aggregate.aggregate_commitments()
        );
        assert_eq!(
            cached_aggregate.open_and_tally_with_common(&common, 3, &fixture.identity_secret),
            Ok(TimedOvnTallyV1 {
                aye: 1,
                nay: 1,
                abstain: 1,
            })
        );

        assert_eq!(
            aggregate_timed_ovn_ballots_v1(&fixture.survivors, &ballots[..2]),
            Err(TimedOvnError::NonCanonicalBallotCorpus)
        );
        let other = self::fixture(21);
        assert_eq!(
            aggregate.open_and_tally(&fixture.survivors, &other.identity_secret),
            Err(TimedOvnError::ReleaseFailed)
        );
    }

    #[test]
    fn canonical_identity_aggregates_do_not_create_a_no_result_oracle() {
        let fixture = fixture(22);
        let ballots = cast_fixture_ballots(&fixture, 23);
        let mut aggregate =
            aggregate_timed_ovn_ballots_v1(&fixture.survivors, &ballots).expect("aggregate");
        let identity_g2 = G2Affine::identity().to_compressed();
        let target_identity = GtElement::identity();
        let generator = target_generator().expect("generator");

        // This is the algebraically valid edge reached when the complete
        // corpus' release exponents cancel. It must remain openable even
        // though every individual ballot ephemeral was non-identity.
        aggregate.aggregate_u = [identity_g2; TIMED_OVN_CHOICE_COUNT_V1];
        aggregate.aggregate_c = [
            target_identity.to_bytes(),
            ct_gt_scalar_mul(&generator, &Scalar::from(3_u64).to_bytes_be()).to_bytes(),
            target_identity.to_bytes(),
        ];
        assert_eq!(
            aggregate.open_and_tally(&fixture.survivors, &fixture.identity_secret),
            Ok(TimedOvnTallyV1 {
                aye: 0,
                nay: 3,
                abstain: 0,
            })
        );
    }

    #[test]
    fn malformed_replayed_and_non_one_hot_ballots_fail_closed() {
        let fixture = fixture(15);
        let mut ballot = cast_fixture_ballots(&fixture, 16).remove(0);

        let mut duplicate_ephemeral = ballot.clone();
        duplicate_ephemeral.u[1] = duplicate_ephemeral.u[0];
        assert_eq!(
            duplicate_ephemeral.verify(&fixture.survivors),
            Err(TimedOvnError::DuplicateEphemeral)
        );

        let generator = target_generator().expect("generator");
        let original = GtElement::from_bytes(&ballot.c[1], false).expect("commitment");
        ballot.c[1] = original.multiply(generator).to_bytes();
        assert!(matches!(
            ballot.verify(&fixture.survivors),
            Err(TimedOvnError::InvalidBallotProof | TimedOvnError::IdentityElement)
        ));

        let mut wrong_root = cast_fixture_ballots(&fixture, 17).remove(0);
        wrong_root.survivor_root = binding(99);
        assert_eq!(
            wrong_root.verify(&fixture.survivors),
            Err(TimedOvnError::BindingMismatch)
        );

        let mut malformed_scalar = cast_fixture_ballots(&fixture, 18).remove(0);
        malformed_scalar.proof.challenges[0] = [0xff; TIMED_OVN_SCALAR_BYTES_V1];
        assert_eq!(
            malformed_scalar.verify(&fixture.survivors),
            Err(TimedOvnError::InvalidScalar)
        );
    }

    #[test]
    fn roster_survivor_and_release_bindings_reject_duplicates_and_reordering() {
        let fixture = fixture(19);
        let session = *fixture.roster.session();
        let registrations = fixture.roster.registrations();
        assert_eq!(
            TimedOvnRosterV1::new(
                &session,
                vec![registrations[0].clone(), registrations[0].clone()],
            ),
            Err(TimedOvnError::DuplicateParticipant)
        );
        assert_eq!(
            TimedOvnRosterV1::new(
                &session,
                vec![registrations[1].clone(), registrations[0].clone()],
            ),
            Err(TimedOvnError::NonCanonicalRoster)
        );
        assert_eq!(
            fixture
                .roster
                .prospective_survivor_root(&[binding(50), binding(40)]),
            Err(TimedOvnError::NonCanonicalSurvivorSet)
        );
        assert_eq!(
            fixture
                .roster
                .prospective_survivor_root(&[binding(40), binding(40)]),
            Err(TimedOvnError::NonCanonicalSurvivorSet)
        );

        let identity = fixture.survivors.release_identity;
        let wrong_identity = TleReleaseIdentityV1::new(
            *identity.session(),
            *identity.governance_attempt_id(),
            *identity.body_instance_id(),
            *identity.ballot_attempt_id(),
            binding(98),
            binding(97),
            identity.target_finalized_height(),
            *identity.parameter_hash(),
        )
        .expect("syntactically valid wrong identity");
        assert_eq!(
            TimedOvnSurvivorRosterV1::new(
                &fixture.roster,
                &[binding(40), binding(50), binding(60)],
                &wrong_identity,
            ),
            Err(TimedOvnError::InvalidReleaseIdentity)
        );
    }

    #[test]
    fn aggregate_cancellation_fails_closed() {
        let fixture = fixture(22);
        let ballots = cast_fixture_ballots(&fixture, 23);
        let mut aggregate =
            aggregate_timed_ovn_ballots_v1(&fixture.survivors, &ballots).expect("aggregate");
        let generator = target_generator().expect("generator");
        aggregate.aggregate_c[0] =
            ct_gt_scalar_mul(&generator, &Scalar::from(999_u64).to_bytes_be()).to_bytes();
        assert!(matches!(
            aggregate.open_and_tally(&fixture.survivors, &fixture.identity_secret),
            Err(TimedOvnError::MaskCancellationFailed | TimedOvnError::InvalidTally)
        ));
    }

    #[test]
    fn official_release_audit_manifest_is_exact_signed_and_release_only() {
        // These are synthetic test vectors. They are not an external audit or
        // an approval of any production artifact.
        let OfficialAuditFixture {
            artifacts,
            reviewer,
            reviewer_public_key,
            manifest,
            manifest_bytes,
        } = official_audit_fixture();

        assert_eq!(
            TimedOvnOfficialReleaseAuditManifestV1::from_bytes(&manifest_bytes),
            Ok(manifest)
        );
        assert_eq!(
            validate_timed_ovn_official_release_audit_manifest_bytes_v1(
                &manifest_bytes,
                &artifacts,
                &reviewer_public_key,
            ),
            Ok(manifest)
        );
        assert_eq!(
            TimedOvnOfficialReleaseAuditManifestV1::from_bytes(&[]),
            Err(TimedOvnError::OfficialReleaseAuditEvidenceRequired)
        );

        let mismatched_artifacts = TimedOvnOfficialReleaseAuditArtifactsV1::new(
            b"tampered timed-ovn source archive",
            b"release binary and toolchain manifest test vector",
            b"supported target inventory test vector",
            b"independent side-channel report test vector",
            b"compiler assembly and timing evidence archive test vector",
        )
        .expect("nonempty mismatched artifacts");
        assert_eq!(
            validate_timed_ovn_official_release_audit_manifest_v1(
                &manifest,
                &mismatched_artifacts,
                &reviewer_public_key,
            ),
            Err(TimedOvnError::OfficialReleaseAuditEvidenceMismatch)
        );

        let untrusted_reviewer = ed25519_dalek::SigningKey::from_bytes(&[72_u8; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(
            validate_timed_ovn_official_release_audit_manifest_v1(
                &manifest,
                &artifacts,
                &untrusted_reviewer,
            ),
            Err(TimedOvnError::UntrustedOfficialReleaseAuditReviewer)
        );

        let rejected_statement = TimedOvnOfficialReleaseAuditStatementV1::from_artifacts(
            TimedOvnOfficialReleaseAuditVerdictV1::Rejected,
            &artifacts,
            reviewer_public_key,
        )
        .expect("canonical rejected statement");
        let rejected_signature = reviewer
            .sign(&rejected_statement.signing_bytes())
            .to_bytes();
        let rejected_manifest =
            TimedOvnOfficialReleaseAuditManifestV1::from_statement_and_signature(
                rejected_statement,
                rejected_signature,
            )
            .expect("authentic rejected manifest");
        assert_eq!(
            validate_timed_ovn_official_release_audit_manifest_v1(
                &rejected_manifest,
                &artifacts,
                &reviewer_public_key,
            ),
            Err(TimedOvnError::OfficialReleaseAuditNotApproved)
        );

        let mut tampered_signature = manifest_bytes;
        *tampered_signature.last_mut().expect("fixed manifest") ^= 1;
        assert_eq!(
            TimedOvnOfficialReleaseAuditManifestV1::from_bytes(&tampered_signature),
            Err(TimedOvnError::InvalidOfficialReleaseAuditSignature)
        );

        let mut wrong_magic = manifest_bytes;
        wrong_magic[0] ^= 1;
        assert_eq!(
            TimedOvnOfficialReleaseAuditManifestV1::from_bytes(&wrong_magic),
            Err(TimedOvnError::InvalidOfficialReleaseAuditManifest)
        );
        assert_eq!(
            TimedOvnOfficialReleaseAuditArtifactsV1::new(
                b"",
                b"artifact manifest",
                b"targets",
                b"report",
                b"archive",
            )
            .err(),
            Some(TimedOvnError::OfficialReleaseAuditEvidenceRequired)
        );
    }

    #[test]
    fn zero_rng_and_single_survivor_fail_before_ballot_admission() {
        #[derive(Debug)]
        struct ZeroRng;
        impl rand_core::RngCore for ZeroRng {
            fn next_u32(&mut self) -> u32 {
                0
            }

            fn next_u64(&mut self) -> u64 {
                0
            }

            fn fill_bytes(&mut self, destination: &mut [u8]) {
                destination.fill(0);
            }
        }
        impl rand_core::CryptoRng for ZeroRng {}

        let fixture = fixture(24);
        assert!(matches!(
            TimedOvnRegistrationSecretV1::generate_with_rng(
                fixture.roster.session(),
                binding(70),
                &mut ZeroRng,
            ),
            Err(TimedOvnError::InertRandomness)
        ));
        let single_root = fixture
            .roster
            .prospective_survivor_root(&[binding(40)])
            .expect("prospective root");
        let old_identity = fixture.survivors.release_identity;
        let single_identity = TleReleaseIdentityV1::new(
            *old_identity.session(),
            *old_identity.governance_attempt_id(),
            *old_identity.body_instance_id(),
            *old_identity.ballot_attempt_id(),
            single_root,
            binding(96),
            old_identity.target_finalized_height(),
            *old_identity.parameter_hash(),
        )
        .expect("single identity");
        assert_eq!(
            TimedOvnSurvivorRosterV1::new(&fixture.roster, &[binding(40)], &single_identity,),
            Err(TimedOvnError::IdentityElement)
        );
    }

    #[test]
    fn bounded_decoder_rejects_count_above_limit() {
        let generator = target_generator().expect("generator");
        let point = ct_gt_scalar_mul(&generator, &Scalar::from(1_001_u64).to_bytes_be());
        assert_eq!(bounded_discrete_log(&point, &generator, 1_000), None);
    }
}
