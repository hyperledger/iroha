//! The release-controlled launch gate of binding Parliament ballots (integration decision
//! 0).
//!
//! [`PARLIAMENT_BALLOT_QUALIFICATION_V1`] is `None`. Changing it to `Some(record_digest)` is
//! an owner-approved protocol release: the digest names the canonical bytes of an
//! owner-signed [`BallotQualificationRecordV1`] stored in the repository with a detached
//! Ed25519 signature that release validation verifies against the owner's separately
//! pinned qualification key. No environment variable, Cargo feature, node-local setting
//! or governance instruction asserts qualification, and engineering completion, local
//! tests or this module never constitute it. The constant records production
//! qualification; it does not prohibit engineering testing of the actual candidate.
//! Core integration is pending, including production enforcement at binding attempt
//! creation, registration, sealing, admission, inclusion, certification and enactment.
//! The local protocol tests run without claiming this record exists.

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

/// The exact semantic security tuple of the approved contract (lifecycle decision K3),
/// `(queries_log2, attack_gates_log2, archive_years, scopes_log2, seats, registrations_log2,
/// transcripts_per_credential_log2, total_transcripts_log2, statistical_budget_neg_log2)`.
///
/// The fields have different semantics and are not interchangeable ceilings: one is the
/// query ceiling of the proven bound, one an attack-cost lower bound, one the archive
/// horizon, five are usage ceilings the deployment must stay within, and one is an error
/// bound.
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
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::BallotSecurityTupleV1")]
pub struct BallotSecurityTupleV1 {
    /// Query ceiling of the proven bound: `log2` of the most quantum oracle queries the
    /// complete proven bound covers (`64`).
    pub queries_log2: u16,
    /// Attack-cost lower bound: `log2` of the fewest elementary gates an attack costs under
    /// the independent assessment (`128`).
    pub attack_gates_log2: u16,
    /// Archive horizon: years for which recorded ballots must stay protected, per network and
    /// profile instance (`100`).
    pub archive_years: u16,
    /// Usage ceiling: `log2` of the most body scopes (`24`).
    pub scopes_log2: u16,
    /// Usage ceiling: the most sealed seats of one body (`1000`).
    pub seats: u16,
    /// Usage ceiling: `log2` of the most registrations, alternates included (`34`).
    pub registrations_log2: u16,
    /// Usage ceiling: `log2` of the most honest prover transcripts per credential (`10`).
    pub transcripts_per_credential_log2: u16,
    /// Usage ceiling: `log2` of the most registration and ballot transcripts in total (`44`).
    pub total_transcripts_log2: u16,
    /// Error bound: the unconditional statistical bad-event probability is at most
    /// `2^-statistical_budget_neg_log2` (`128`).
    pub statistical_budget_neg_log2: u16,
}

impl BallotSecurityTupleV1 {
    /// The tuple of the compiled candidate, `(64, 128, 100, 24, 1000, 34, 10, 44, 128)`.
    pub const CANDIDATE_V1: Self = Self {
        queries_log2: 64,
        attack_gates_log2: 128,
        archive_years: 100,
        scopes_log2: 24,
        seats: 1_000,
        registrations_log2: 34,
        transcripts_per_credential_log2: 10,
        total_transcripts_log2: 44,
        statistical_budget_neg_log2: 128,
    };
}

/// The approved security contract restated by the qualification record
/// (`specs/parliament_ballot_proof_profile.md` §8.8): the exact semantic tuple and the digest
/// of the complete approved contract statement.
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
    /// The exact semantic security tuple.
    pub tuple: BallotSecurityTupleV1,
    /// SHA3-512 of the exact approved contract statement, which binds the complete semantic
    /// contract (the meaning and value of every tuple field, the credential assumptions and
    /// the complete ledger) and both recorded weakenings (the gate-1 and gate-6 readings).
    pub statement_digest: Digest512,
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

/// A qualified service contract: the finite, positive attempt-latency bound and the digest of
/// its statement, which covers every permitted retry, Confirmation, successor-clock block,
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
    /// Qualified bound on one attempt's latency to a terminal outcome, in milliseconds:
    /// positive and finite (`u64::MAX` is refused as an unbounded sentinel).
    pub attempt_latency_ms: u64,
}

impl BallotServiceContractV1 {
    /// Whether the latency bound is positive and finite.
    #[must_use]
    pub const fn has_finite_positive_latency(&self) -> bool {
        self.attempt_latency_ms > 0 && self.attempt_latency_ms < u64::MAX
    }
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
    /// [`PARLIAMENT_BALLOT_QUALIFICATION_V1`] would name. The owner's detached Ed25519
    /// signature signs exactly these 64 digest bytes; signing and keys are outside the data
    /// model.
    ///
    /// # Errors
    /// [`AnonymousBallotCodecErrorV1`] if `Enc(self)` cannot be produced.
    pub fn record_digest(&self) -> Result<Digest512, AnonymousBallotCodecErrorV1> {
        frame_digest(QUALIFICATION_TAG_V1, &[&enc(self)?])
    }

    /// Whether the record describes the candidate this build compiles: the V1 profile, the
    /// exact candidate security tuple ([`BallotSecurityTupleV1::CANDIDATE_V1`]), well-formed
    /// parameter bounds that contain the default committed parameters, and no service
    /// contract or one with a positive finite latency. Signature, statement and manifest
    /// verification belong to release validation.
    #[must_use]
    pub fn matches_compiled_candidate(&self) -> bool {
        self.profile_id.is_v1()
            && self.security_contract.tuple == BallotSecurityTupleV1::CANDIDATE_V1
            && self.parameter_bounds.is_well_formed()
            && self
                .parameter_bounds
                .contains(&ParliamentBallotParametersV1::default())
            && self
                .service_contract
                .is_none_or(|service| service.has_finite_positive_latency())
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
                tuple: BallotSecurityTupleV1::CANDIDATE_V1,
                statement_digest: Digest512::new([4; 64]),
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
    fn the_candidate_tuple_is_the_decided_one() {
        let tuple = BallotSecurityTupleV1::CANDIDATE_V1;
        assert_eq!(
            [
                tuple.queries_log2,
                tuple.attack_gates_log2,
                tuple.archive_years,
                tuple.scopes_log2,
                tuple.seats,
                tuple.registrations_log2,
                tuple.transcripts_per_credential_log2,
                tuple.total_transcripts_log2,
                tuple.statistical_budget_neg_log2,
            ],
            [64, 128, 100, 24, 1_000, 34, 10, 44, 128]
        );
        assert_eq!(
            decode_enc::<BallotSecurityTupleV1>(&enc(&tuple).expect("enc")),
            Ok(tuple)
        );
        let json = norito::json::to_json(&tuple).expect("json");
        assert_eq!(
            norito::json::from_str::<BallotSecurityTupleV1>(&json).expect("json"),
            tuple
        );
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
        // The statement digest and every tuple field are bound by the record digest.
        let mut other_statement = record;
        other_statement.security_contract.statement_digest = Digest512::new([6; 64]);
        assert_ne!(other_statement.record_digest(), record.record_digest());
        let mut other_tuple = record;
        other_tuple.security_contract.tuple.archive_years = 99;
        assert_ne!(other_tuple.record_digest(), record.record_digest());
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
        // Well-formed bounds that exclude the defaults are not the candidate's.
        let mut narrow = record;
        narrow.parameter_bounds.minimum.stamp_difficulty_bits = 30;
        narrow.parameter_bounds.maximum.stamp_difficulty_bits = 32;
        assert!(narrow.parameter_bounds.is_well_formed());
        assert!(!narrow.matches_compiled_candidate());
    }

    /// A named change of one tuple field.
    type TupleChange = (&'static str, fn(&mut BallotSecurityTupleV1));

    #[test]
    fn every_tuple_field_and_the_service_latency_must_match_the_candidate() {
        let mutations: [TupleChange; 9] = [
            ("queries_log2", |t| t.queries_log2 = 65),
            ("attack_gates_log2", |t| t.attack_gates_log2 = 127),
            ("archive_years", |t| t.archive_years = 101),
            ("scopes_log2", |t| t.scopes_log2 = 25),
            ("seats", |t| t.seats = 999),
            ("registrations_log2", |t| t.registrations_log2 = 35),
            ("transcripts_per_credential_log2", |t| {
                t.transcripts_per_credential_log2 = 11;
            }),
            ("total_transcripts_log2", |t| t.total_transcripts_log2 = 45),
            ("statistical_budget_neg_log2", |t| {
                t.statistical_budget_neg_log2 = 127;
            }),
        ];
        for (field, mutate) in mutations {
            let mut mutated = record();
            mutate(&mut mutated.security_contract.tuple);
            assert!(!mutated.matches_compiled_candidate(), "{field}");
        }
        for (latency, accepted) in [
            (0, false),
            (1, true),
            (30 * 86_400_000, true),
            (u64::MAX, false),
        ] {
            let mut serviced = record();
            serviced.service_contract = Some(BallotServiceContractV1 {
                statement_digest: Digest512::new([5; 64]),
                attempt_latency_ms: latency,
            });
            assert_eq!(serviced.matches_compiled_candidate(), accepted, "{latency}");
            assert_eq!(
                serviced
                    .service_contract
                    .is_some_and(|service| service.has_finite_positive_latency()),
                accepted
            );
        }
    }
}
