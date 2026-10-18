//! The release-controlled launch gate of binding Parliament ballots (integration decision
//! 0).
//!
//! [`PARLIAMENT_BALLOT_QUALIFICATION_V1`] is `None`. Changing it to `Some(record_digest)` is
//! an owner-approved protocol release: the digest names the canonical bytes of an
//! owner-signed [`BallotQualificationRecordV1`] stored in the repository with a detached
//! Ed25519 signature that release validation verifies against the owner's separately
//! pinned qualification key. No environment variable, Cargo feature, node-local setting
//! or governance instruction asserts qualification, and engineering completion, local
//! tests or this module never constitute it. While the constant is `None`, Core must
//! refuse binding attempt creation, binding registration and sealing, anonymous-ballot
//! admission and inclusion, and binding certification and enactment; that enforcement is
//! wired by the Core integration.

use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use super::{
    Digest512, ParliamentBallotParametersV1, ProofProfileIdV1,
    digests::QUALIFICATION_TAG_V1,
    framing::{AnonymousBallotCodecErrorV1, enc, frame_digest},
};
use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};

/// Digest of the owner-signed qualification record of the V1 anonymous ballot, or `None`
/// while binding production use is disabled. It is `None`: nothing is qualified.
pub const PARLIAMENT_BALLOT_QUALIFICATION_V1: Option<Digest512> = None;

/// Whether binding Parliament ballots are released for production use: exactly whether
/// [`PARLIAMENT_BALLOT_QUALIFICATION_V1`] names a record. This build returns `false`.
#[must_use]
pub const fn parliament_ballot_qualified_v1() -> bool {
    PARLIAMENT_BALLOT_QUALIFICATION_V1.is_some()
}

/// The approved security contract restated by the qualification record
/// (`specs/parliament_ballot_proof_profile.md` §8.8): the numeric ceilings and the digest
/// of the complete contract statement the owner approved, which restates the weakened
/// gate-1 and gate-6 readings, the credential assumptions and the complete ledger.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::BallotSecurityContractV1")]
pub struct BallotSecurityContractV1 {
    /// SHA3-512 of the exact approved contract statement.
    pub statement_digest: Digest512,
    /// `log2` of the quantum-query budget of the complete proven bound (64).
    pub proven_bound_queries_log2: u16,
    /// `log2` of the elementary-gate attack cost of the independent assessment (128).
    pub attack_cost_gates_log2: u16,
    /// Archive horizon in years per network and profile instance (100).
    pub archive_horizon_years: u16,
    /// `log2` of the most body scopes (24).
    pub body_scopes_log2: u16,
    /// Most sealed seats per body (1,000).
    pub sealed_seats_per_body: u16,
    /// `log2` of the most registrations, alternates included (34).
    pub registrations_log2: u16,
    /// `log2` of the most honest prover transcripts per credential (10).
    pub transcripts_per_credential_log2: u16,
    /// `log2` of the most registration plus ballot transcripts (44).
    pub total_transcripts_log2: u16,
    /// Negated `log2` of the unconditional statistical bad-event budget (128).
    pub statistical_budget_neg_log2: u16,
}

/// The qualified envelope of the committed ballot parameters: every committed value must
/// lie between `minimum` and `maximum`, field by field.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(
    name = "iroha_data_model::governance::anonymous_ballot::QualifiedBallotParameterBoundsV1"
)]
pub struct QualifiedBallotParameterBoundsV1 {
    /// Lowest qualified value of every field.
    pub minimum: ParliamentBallotParametersV1,
    /// Highest qualified value of every field.
    pub maximum: ParliamentBallotParametersV1,
}

impl QualifiedBallotParameterBoundsV1 {
    /// Whether every field of `parameters` lies within the qualified bounds.
    #[must_use]
    pub fn contains(&self, parameters: &ParliamentBallotParametersV1) -> bool {
        (self.minimum.vote_notice_ms..=self.maximum.vote_notice_ms)
            .contains(&parameters.vote_notice_ms)
            && (self.minimum.casting_window_ms..=self.maximum.casting_window_ms)
                .contains(&parameters.casting_window_ms)
            && (self.minimum.max_nonterminal_attempts..=self.maximum.max_nonterminal_attempts)
                .contains(&parameters.max_nonterminal_attempts)
            && (self.minimum.max_verification_reservations_per_block
                ..=self.maximum.max_verification_reservations_per_block)
                .contains(&parameters.max_verification_reservations_per_block)
            && (self.minimum.max_verifier_input_bytes_per_block
                ..=self.maximum.max_verifier_input_bytes_per_block)
                .contains(&parameters.max_verifier_input_bytes_per_block)
            && (self.minimum.stamp_difficulty_bits..=self.maximum.stamp_difficulty_bits)
                .contains(&parameters.stamp_difficulty_bits)
    }

    /// Whether both bounds pass the structural parameter ranges and `minimum ≤ maximum`
    /// holds field by field.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.minimum.validate_structure().is_ok()
            && self.maximum.validate_structure().is_ok()
            && self.contains(&self.minimum)
            && self.contains(&self.maximum)
    }
}

/// A qualified service contract: the finite attempt-latency bound and the digest of its
/// statement, which covers every permitted retry, Confirmation, successor-clock block,
/// shared-pass delay and clock margin.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::BallotServiceContractV1")]
pub struct BallotServiceContractV1 {
    /// SHA3-512 of the exact service-contract statement.
    pub statement_digest: Digest512,
    /// Qualified bound on one attempt's latency to a terminal outcome, in milliseconds.
    pub attempt_latency_ms: u64,
}

/// The owner's qualification record (integration decision 0). It authenticates the
/// owner's decision; it does not prove its scientific premises.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(
    name = "iroha_data_model::governance::anonymous_ballot::BallotQualificationRecordV1"
)]
pub struct BallotQualificationRecordV1 {
    /// The qualified candidate profile.
    pub profile_id: ProofProfileIdV1,
    /// Digest of the final production schemas.
    pub schema_digest: Digest512,
    /// Digest of the implementation and dependency manifest.
    pub implementation_manifest_digest: Digest512,
    /// Digest of the evidence manifest.
    pub evidence_manifest_digest: Digest512,
    /// The approved security contract.
    pub security_contract: BallotSecurityContractV1,
    /// The qualified envelope of the committed parameters.
    pub parameter_bounds: QualifiedBallotParameterBoundsV1,
    /// The qualified service and latency contract, if any.
    pub service_contract: Option<BallotServiceContractV1>,
}

impl BallotQualificationRecordV1 {
    /// `H(Frame("PARL/QUALIFICATION/v1"; Enc(record)))`, the value
    /// [`PARLIAMENT_BALLOT_QUALIFICATION_V1`] would name and the owner's detached
    /// signature would sign.
    ///
    /// # Errors
    /// [`AnonymousBallotCodecErrorV1`] if `Enc(self)` cannot be produced.
    pub fn record_digest(&self) -> Result<Digest512, AnonymousBallotCodecErrorV1> {
        frame_digest(QUALIFICATION_TAG_V1, &[&enc(self)?])
    }

    /// Whether the record names the profile this build compiles and well-formed parameter
    /// bounds. Signature and manifest verification belong to release validation.
    #[must_use]
    pub fn matches_compiled_candidate(&self) -> bool {
        self.profile_id.is_v1() && self.parameter_bounds.is_well_formed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::anonymous_ballot::framing::{decode_enc, frame_bytes};

    fn record() -> BallotQualificationRecordV1 {
        let defaults = ParliamentBallotParametersV1::default();
        BallotQualificationRecordV1 {
            profile_id: ProofProfileIdV1::V1,
            schema_digest: Digest512::new([1; 64]),
            implementation_manifest_digest: Digest512::new([2; 64]),
            evidence_manifest_digest: Digest512::new([3; 64]),
            security_contract: BallotSecurityContractV1 {
                statement_digest: Digest512::new([4; 64]),
                proven_bound_queries_log2: 64,
                attack_cost_gates_log2: 128,
                archive_horizon_years: 100,
                body_scopes_log2: 24,
                sealed_seats_per_body: 1_000,
                registrations_log2: 34,
                transcripts_per_credential_log2: 10,
                total_transcripts_log2: 44,
                statistical_budget_neg_log2: 128,
            },
            parameter_bounds: QualifiedBallotParameterBoundsV1 {
                minimum: defaults,
                maximum: ParliamentBallotParametersV1 {
                    stamp_difficulty_bits: 32,
                    ..defaults
                },
            },
            service_contract: None,
        }
    }

    #[test]
    fn the_launch_gate_is_closed() {
        // Release validation must replace this check with the verification of an
        // owner-signed record, its manifests and the compiled candidate before the
        // constant may name a record.
        assert_eq!(PARLIAMENT_BALLOT_QUALIFICATION_V1, None);
        assert!(!parliament_ballot_qualified_v1());
    }

    #[test]
    fn the_record_digest_frames_the_canonical_record() {
        use sha3::{Digest as _, Sha3_512};
        let record = record();
        let bytes = enc(&record).expect("enc");
        let expected: [u8; 64] =
            Sha3_512::digest(frame_bytes(b"PARL/QUALIFICATION/v1", &[&bytes]).expect("frame"))
                .into();
        assert_eq!(record.record_digest(), Ok(Digest512::new(expected)));
        assert_eq!(
            decode_enc::<BallotQualificationRecordV1>(&bytes),
            Ok(record)
        );
        let json = norito::json::to_json(&record).expect("json");
        assert_eq!(
            norito::json::from_str::<BallotQualificationRecordV1>(&json).expect("json"),
            record
        );
        let mut with_service = record;
        with_service.service_contract = Some(BallotServiceContractV1 {
            statement_digest: Digest512::new([5; 64]),
            attempt_latency_ms: 30 * 86_400_000,
        });
        assert_ne!(with_service.record_digest(), record.record_digest());
        assert_eq!(
            decode_enc::<BallotQualificationRecordV1>(&enc(&with_service).expect("enc")),
            Ok(with_service)
        );
    }

    #[test]
    fn the_record_must_name_the_compiled_candidate_and_sound_bounds() {
        let record = record();
        assert!(record.matches_compiled_candidate());
        let defaults = ParliamentBallotParametersV1::default();
        assert!(record.parameter_bounds.contains(&defaults));
        assert!(
            !record
                .parameter_bounds
                .contains(&ParliamentBallotParametersV1 {
                    max_nonterminal_attempts: 5,
                    ..defaults
                })
        );
        let mut foreign = record;
        foreign.profile_id = ProofProfileIdV1::new([0; 64]);
        assert!(!foreign.matches_compiled_candidate());
        let mut inverted = record;
        inverted.parameter_bounds.minimum.stamp_difficulty_bits = 32;
        inverted.parameter_bounds.maximum.stamp_difficulty_bits = 28;
        assert!(!inverted.parameter_bounds.is_well_formed());
        assert!(!inverted.matches_compiled_candidate());
        let mut unstructured = record;
        unstructured.parameter_bounds.minimum.stamp_difficulty_bits = 1;
        assert!(!unstructured.parameter_bounds.is_well_formed());
    }
}
