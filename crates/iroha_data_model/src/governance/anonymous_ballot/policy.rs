//! The frozen ballot-policy snapshot of a binding body (integration decision 7).
//!
//! Chain-derived attempt policy is frozen at admission; the risk tier locks at the first
//! Policy Jury sortition request, where one snapshot per binding body (Policy and
//! Confirmation) and its `policy_hash` are to be materialized before any binding
//! credential is registered (the Core integration implements this). `policy_hash = SHA3-512(Frame("PARL/POLICY/v1"; P16, Enc(policy)))` is the
//! proof crate's. The snapshot excludes node-local settings, mutable counts and observed
//! timings.

use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use super::{
    MAX_SEALED_SEATS_V1, MIN_SEALED_SEATS_V1, MIN_TURNOUT_V1, ParliamentBallotParameterErrorV1,
    ParliamentBallotParametersV1, ParliamentDecisionRuleV1, ProofProfileIdV1,
    context::is_binding_body,
};
use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize,
    governance::types::{
        MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1, MAX_PARLIAMENT_SORTITION_RETRIES_V1,
        PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1, ParliamentBody, RiskTierV1,
    },
    parameter::parliament_ballot::{BallotCastingCapacityV1, parliament_ballot_capacity_v1},
};

/// Why a frozen ballot policy is not a valid V1 snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrozenBallotPolicyErrorV1 {
    /// The governance policy version is not the V1 version.
    #[error("governance policy version {actual} is not the V1 version")]
    PolicyVersion {
        /// Version supplied.
        actual: u64,
    },
    /// The snapshot's body is not a binding jury.
    #[error("{body:?} is not a binding jury")]
    NotBindingBody {
        /// Body supplied.
        body: ParliamentBody,
    },
    /// The proof profile is not [`ProofProfileIdV1::V1`].
    #[error("the proof profile is not the V1 profile")]
    UnknownProfile,
    /// A fixed V1 constant has another value.
    #[error("the V1 constant {field} has another value")]
    Constant {
        /// The field.
        field: &'static str,
    },
    /// A committed parameter or the capacity rule is violated.
    #[error(transparent)]
    Parameter(#[from] ParliamentBallotParameterErrorV1),
    /// The pipeline names no body.
    #[error("the frozen pipeline names no body")]
    NoRequiredBodies,
    /// A pipeline entry is not strictly after its predecessor in canonical body order.
    #[error("pipeline entry {index} is not strictly after the entry before it")]
    RequiredBodyOrder {
        /// Index of the entry.
        index: usize,
    },
    /// A body's decision mode is not its role's (anonymous ballot for juries only).
    #[error("{body:?} has the wrong decision mode")]
    DecisionMode {
        /// The body.
        body: ParliamentBody,
    },
    /// A body's target seats are zero, above 1000, or below 3 for a binding jury.
    #[error("{body:?} has an invalid seat target")]
    TargetSeats {
        /// The body.
        body: ParliamentBody,
    },
    /// A body's alternate cap exceeds 1000.
    #[error("{body:?} has an invalid alternate cap")]
    AlternateCap {
        /// The body.
        body: ParliamentBody,
    },
    /// A binding jury is missing from the pipeline.
    #[error("the frozen pipeline lacks {body:?}")]
    MissingBody {
        /// The missing body.
        body: ParliamentBody,
    },
    /// A sortition field is out of range.
    #[error("the frozen sortition policy's {field} is out of range")]
    Sortition {
        /// The field.
        field: &'static str,
    },
    /// A lifecycle duration is out of range.
    #[error("the frozen lifecycle policy's {field} is out of range")]
    Lifecycle {
        /// The field.
        field: &'static str,
    },
}

/// How a required body decides.
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
#[norito(
    tag = "kind",
    content = "detail",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::BodyDecisionModeV1")]
pub enum BodyDecisionModeV1 {
    /// Account-signed public findings (every body except the binding juries).
    #[codec(index = 0)]
    PublicFinding,
    /// Anonymous on-chain ballot (Policy and Confirmation juries).
    #[codec(index = 1)]
    AnonymousBallot,
}

/// One body of the frozen pipeline: its role, decision mode, seat target and alternate
/// cap.
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::RequiredBodyPolicyV1")]
pub struct RequiredBodyPolicyV1 {
    /// The body's role.
    pub body: ParliamentBody,
    /// How it decides.
    pub decision_mode: BodyDecisionModeV1,
    /// Seat target of each draw: a cap, not a minimum (design §1).
    pub target_seats: u16,
    /// Alternates drawn behind the primaries of each draw.
    pub alternate_cap: u16,
}

/// The frozen sortition parameters of the attempt (design §9).
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
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::FrozenSortitionPolicyV1")]
pub struct FrozenSortitionPolicyV1 {
    /// Minimum lead `d` in blocks between a sortition request and its pulse slot.
    pub pulse_delay_blocks: u64,
    /// Native pulse cadence `L` (the `NPoS` epoch length in blocks) frozen at creation;
    /// pulse heights are those `h` with `(h + 1) % L == 0`.
    pub pulse_cadence_blocks: u64,
    /// Most seats one citizen may hold across the attempt's bodies.
    pub cross_body_assignment_cap: u32,
    /// Ceiling on `NoRoster` sortition retries of one body.
    pub max_sortition_retries: u32,
    /// Ceiling on the proposal-wide fresh-randomness redraws.
    pub max_randomness_redraws: u32,
}

impl FrozenSortitionPolicyV1 {
    /// Check a nonzero cadence and assignment cap and the V1 retry ceilings.
    ///
    /// # Errors
    /// [`FrozenBallotPolicyErrorV1::Sortition`] naming the offending field.
    pub fn validate(&self) -> Result<(), FrozenBallotPolicyErrorV1> {
        let field = if self.pulse_cadence_blocks == 0 {
            "pulse_cadence_blocks"
        } else if self.cross_body_assignment_cap == 0 {
            "cross_body_assignment_cap"
        } else if self.max_sortition_retries > MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
            "max_sortition_retries"
        } else if self.max_randomness_redraws > MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1 {
            "max_randomness_redraws"
        } else {
            return Ok(());
        };
        Err(FrozenBallotPolicyErrorV1::Sortition { field })
    }
}

/// The frozen lifecycle durations of the attempt, in milliseconds of the governance
/// clock.
#[allow(clippy::struct_field_names)] // Each field carries its unit, as the other ballot durations do.
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
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::FrozenLifecyclePolicyV1")]
pub struct FrozenLifecyclePolicyV1 {
    /// Invitation-response window of each body election.
    pub invitation_window_ms: u64,
    /// Deliberation and public-finding window (from Reflection for public-finding bodies).
    pub deliberation_window_ms: u64,
    /// Delay between certification and automatic enactment.
    pub enactment_delay_ms: u64,
}

impl FrozenLifecyclePolicyV1 {
    /// Check nonzero invitation and deliberation windows.
    ///
    /// # Errors
    /// [`FrozenBallotPolicyErrorV1::Lifecycle`] naming the offending field.
    pub fn validate(&self) -> Result<(), FrozenBallotPolicyErrorV1> {
        if self.invitation_window_ms == 0 {
            return Err(FrozenBallotPolicyErrorV1::Lifecycle {
                field: "invitation_window_ms",
            });
        }
        if self.deliberation_window_ms == 0 {
            return Err(FrozenBallotPolicyErrorV1::Lifecycle {
                field: "deliberation_window_ms",
            });
        }
        Ok(())
    }
}

/// The capacity guarantee recorded at admission (integration decision 5): the global
/// limits `K`, `B_work`, `B_bytes` and the block cadence under which the casting window
/// passed the capacity rule. Live committed limits still govern execution; updates may
/// not weaken an outstanding commitment.
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
    name = "iroha_data_model::governance::anonymous_ballot::BallotCapacityCommitmentV1"
)]
pub struct BallotCapacityCommitmentV1 {
    /// `K`: nonterminal attempts admitted concurrently.
    pub max_nonterminal_attempts: u16,
    /// `B_work`: ballot verification reservations per block.
    pub max_verification_reservations_per_block: u32,
    /// `B_bytes`: ballot verifier-input bytes per block.
    pub max_verifier_input_bytes_per_block: u64,
    /// Committed minimum block cadence in milliseconds.
    pub block_cadence_ms: u64,
}

impl BallotCapacityCommitmentV1 {
    /// The commitment of `parameters` at the committed `block_cadence_ms`.
    #[must_use]
    pub const fn from_parameters(
        parameters: &ParliamentBallotParametersV1,
        block_cadence_ms: u64,
    ) -> Self {
        Self {
            max_nonterminal_attempts: parameters.max_nonterminal_attempts,
            max_verification_reservations_per_block: parameters
                .max_verification_reservations_per_block,
            max_verifier_input_bytes_per_block: parameters.max_verifier_input_bytes_per_block,
            block_cadence_ms,
        }
    }

    /// Check the committed ranges and that `casting_window_ms` passes the capacity rule
    /// under this commitment.
    ///
    /// # Errors
    /// [`ParliamentBallotParameterErrorV1`] for a range or capacity violation.
    pub fn validate(
        &self,
        casting_window_ms: u64,
    ) -> Result<BallotCastingCapacityV1, ParliamentBallotParameterErrorV1> {
        ParliamentBallotParametersV1::check_budget_ranges(
            self.max_nonterminal_attempts,
            self.max_verification_reservations_per_block,
            self.max_verifier_input_bytes_per_block,
        )?;
        parliament_ballot_capacity_v1(
            casting_window_ms,
            self.block_cadence_ms,
            self.max_nonterminal_attempts,
            self.max_verification_reservations_per_block,
            self.max_verifier_input_bytes_per_block,
        )
    }
}

/// The frozen policy snapshot of one binding body, in the exact preimage order of
/// integration decision 7.
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::FrozenBallotPolicyV1")]
pub struct FrozenBallotPolicyV1 {
    /// Governance policy version in force at admission.
    pub governance_policy_version: u64,
    /// Risk tier, locked at the first Policy Jury sortition request.
    pub risk_tier: RiskTierV1,
    /// The binding body this snapshot belongs to.
    pub body_role: ParliamentBody,
    /// Every body of the attempt in canonical pipeline order. Both juries are present;
    /// the decision rule draws the Confirmation Jury only after an approved narrow Policy
    /// result.
    pub required_bodies: Vec<RequiredBodyPolicyV1>,
    /// The V1 proof profile.
    pub profile_id: ProofProfileIdV1,
    /// Minimum notice between sealing and casting.
    pub vote_notice_ms: u64,
    /// Casting duration after the successor-block clock.
    pub casting_window_ms: u64,
    /// Leading zero bits the admission stamp's work digest needs.
    pub stamp_difficulty_bits: u8,
    /// Fewest sealed seats, `3`.
    pub minimum_sealed_seats: u16,
    /// Fewest accepted ballots of a quorate ballot, `3`.
    pub minimum_turnout: u16,
    /// Quorum numerator, `2`.
    pub quorum_numerator: u16,
    /// Quorum denominator, `3`; the quorum is the ceiling of `2S/3`.
    pub quorum_denominator: u16,
    /// The decision rule.
    pub decision_rule: ParliamentDecisionRuleV1,
    /// Most sealed seats, `1000`.
    pub maximum_seats: u16,
    /// Frozen sortition parameters.
    pub sortition_policy: FrozenSortitionPolicyV1,
    /// Frozen lifecycle durations.
    pub lifecycle_policy: FrozenLifecyclePolicyV1,
    /// Capacity guarantee recorded at admission.
    pub capacity_commitment: BallotCapacityCommitmentV1,
}

impl FrozenBallotPolicyV1 {
    /// Check every field of the snapshot against the V1 rules, including the capacity
    /// rule of the frozen casting window under the frozen commitment.
    ///
    /// # Errors
    /// The first violated rule as a [`FrozenBallotPolicyErrorV1`].
    pub fn validate(&self) -> Result<(), FrozenBallotPolicyErrorV1> {
        if self.governance_policy_version != PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1 {
            return Err(FrozenBallotPolicyErrorV1::PolicyVersion {
                actual: self.governance_policy_version,
            });
        }
        if !is_binding_body(self.body_role) {
            return Err(FrozenBallotPolicyErrorV1::NotBindingBody {
                body: self.body_role,
            });
        }
        if !self.profile_id.is_v1() {
            return Err(FrozenBallotPolicyErrorV1::UnknownProfile);
        }
        for (field, actual, expected) in [
            (
                "minimum_sealed_seats",
                self.minimum_sealed_seats,
                MIN_SEALED_SEATS_V1,
            ),
            ("minimum_turnout", self.minimum_turnout, MIN_TURNOUT_V1),
            ("quorum_numerator", self.quorum_numerator, 2),
            ("quorum_denominator", self.quorum_denominator, 3),
            ("maximum_seats", self.maximum_seats, MAX_SEALED_SEATS_V1),
        ] {
            if actual != expected {
                return Err(FrozenBallotPolicyErrorV1::Constant { field });
            }
        }
        if self.decision_rule != ParliamentDecisionRuleV1::V1 {
            return Err(FrozenBallotPolicyErrorV1::Constant {
                field: "decision_rule",
            });
        }
        ParliamentBallotParametersV1::check_casting_ranges(
            self.vote_notice_ms,
            self.casting_window_ms,
            self.stamp_difficulty_bits,
        )?;
        self.validate_required_bodies()?;
        self.sortition_policy.validate()?;
        self.lifecycle_policy.validate()?;
        self.capacity_commitment.validate(self.casting_window_ms)?;
        Ok(())
    }

    fn validate_required_bodies(&self) -> Result<(), FrozenBallotPolicyErrorV1> {
        if self.required_bodies.is_empty() {
            return Err(FrozenBallotPolicyErrorV1::NoRequiredBodies);
        }
        if let Some(index) = self
            .required_bodies
            .windows(2)
            .position(|pair| pair[0].body >= pair[1].body)
        {
            return Err(FrozenBallotPolicyErrorV1::RequiredBodyOrder { index: index + 1 });
        }
        for required in &self.required_bodies {
            let binding = is_binding_body(required.body);
            let expected_mode = if binding {
                BodyDecisionModeV1::AnonymousBallot
            } else {
                BodyDecisionModeV1::PublicFinding
            };
            if required.decision_mode != expected_mode {
                return Err(FrozenBallotPolicyErrorV1::DecisionMode {
                    body: required.body,
                });
            }
            let minimum_target = if binding { MIN_SEALED_SEATS_V1 } else { 1 };
            if !(minimum_target..=MAX_SEALED_SEATS_V1).contains(&required.target_seats) {
                return Err(FrozenBallotPolicyErrorV1::TargetSeats {
                    body: required.body,
                });
            }
            if required.alternate_cap > MAX_SEALED_SEATS_V1 {
                return Err(FrozenBallotPolicyErrorV1::AlternateCap {
                    body: required.body,
                });
            }
        }
        for body in [ParliamentBody::PolicyJury, ParliamentBody::ConfirmationJury] {
            if !self
                .required_bodies
                .iter()
                .any(|required| required.body == body)
            {
                return Err(FrozenBallotPolicyErrorV1::MissingBody { body });
            }
        }
        Ok(())
    }

    /// The frozen pipeline entry of `body`, if the pipeline names it.
    #[must_use]
    pub fn required_body(&self, body: ParliamentBody) -> Option<&RequiredBodyPolicyV1> {
        self.required_bodies
            .iter()
            .find(|required| required.body == body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::anonymous_ballot::{
        framing::{decode_enc, enc},
        test_fixtures::policy,
    };

    /// A named change of one field, for table-driven refusal tests.
    type Mutation<T> = (&'static str, fn(&mut T));

    #[test]
    fn the_fixture_policy_is_valid_and_round_trips() {
        let policy = policy();
        assert_eq!(policy.validate(), Ok(()));
        assert_eq!(
            decode_enc::<FrozenBallotPolicyV1>(&enc(&policy).expect("enc")),
            Ok(policy.clone())
        );
        let json = norito::json::to_json(&policy).expect("json");
        assert_eq!(
            norito::json::from_str::<FrozenBallotPolicyV1>(&json).expect("json"),
            policy
        );
        assert_eq!(
            policy
                .required_body(ParliamentBody::PolicyJury)
                .map(|body| body.decision_mode),
            Some(BodyDecisionModeV1::AnonymousBallot)
        );
        assert_eq!(policy.required_body(ParliamentBody::MpcCommittee), None);
        // The confirmation snapshot of the same attempt is valid too.
        let mut confirmation = policy;
        confirmation.body_role = ParliamentBody::ConfirmationJury;
        assert_eq!(confirmation.validate(), Ok(()));
    }

    #[test]
    fn fixed_constants_and_the_profile_are_enforced() {
        let base = policy();
        let mut changed = base.clone();
        changed.governance_policy_version = 2;
        assert_eq!(
            changed.validate(),
            Err(FrozenBallotPolicyErrorV1::PolicyVersion { actual: 2 })
        );
        let mut changed = base.clone();
        changed.body_role = ParliamentBody::OversightCommittee;
        assert_eq!(
            changed.validate(),
            Err(FrozenBallotPolicyErrorV1::NotBindingBody {
                body: ParliamentBody::OversightCommittee
            })
        );
        let mut changed = base.clone();
        changed.profile_id = ProofProfileIdV1::new([0; 64]);
        assert_eq!(
            changed.validate(),
            Err(FrozenBallotPolicyErrorV1::UnknownProfile)
        );
        let mutations: [Mutation<FrozenBallotPolicyV1>; 5] = [
            ("minimum_sealed_seats", |p| p.minimum_sealed_seats = 2),
            ("minimum_turnout", |p| p.minimum_turnout = 4),
            ("quorum_numerator", |p| p.quorum_numerator = 1),
            ("quorum_denominator", |p| p.quorum_denominator = 2),
            ("maximum_seats", |p| p.maximum_seats = 999),
        ];
        for (field, mutate) in mutations {
            let mut changed = base.clone();
            mutate(&mut changed);
            assert_eq!(
                changed.validate(),
                Err(FrozenBallotPolicyErrorV1::Constant { field })
            );
        }
    }

    #[test]
    fn casting_parameters_and_capacity_are_enforced() {
        let base = policy();
        let mut changed = base.clone();
        changed.stamp_difficulty_bits = 27;
        assert!(matches!(
            changed.validate(),
            Err(FrozenBallotPolicyErrorV1::Parameter(
                ParliamentBallotParameterErrorV1::OutOfRange {
                    field: "stamp_difficulty_bits",
                    ..
                }
            ))
        ));
        let mut changed = base.clone();
        changed.vote_notice_ms = 604_800_001;
        assert!(changed.validate().is_err());
        // A window the frozen commitment cannot fill is refused.
        let mut changed = base.clone();
        changed.casting_window_ms = 60_000;
        assert!(matches!(
            changed.validate(),
            Err(FrozenBallotPolicyErrorV1::Parameter(
                ParliamentBallotParameterErrorV1::InsufficientCapacity { .. }
            ))
        ));
        let mut changed = base;
        changed.capacity_commitment.max_nonterminal_attempts = 0;
        assert!(changed.validate().is_err());
    }

    #[test]
    fn the_pipeline_is_ordered_with_both_juries_and_correct_modes() {
        let base = policy();
        let mut changed = base.clone();
        changed.required_bodies.clear();
        assert_eq!(
            changed.validate(),
            Err(FrozenBallotPolicyErrorV1::NoRequiredBodies)
        );
        let mut changed = base.clone();
        changed.required_bodies.swap(0, 1);
        assert_eq!(
            changed.validate(),
            Err(FrozenBallotPolicyErrorV1::RequiredBodyOrder { index: 1 })
        );
        let mut changed = base.clone();
        let repeated = changed.required_bodies[0];
        changed.required_bodies.insert(0, repeated);
        assert_eq!(
            changed.validate(),
            Err(FrozenBallotPolicyErrorV1::RequiredBodyOrder { index: 1 })
        );
        let mut changed = base.clone();
        changed
            .required_bodies
            .retain(|body| body.body != ParliamentBody::ConfirmationJury);
        assert_eq!(
            changed.validate(),
            Err(FrozenBallotPolicyErrorV1::MissingBody {
                body: ParliamentBody::ConfirmationJury
            })
        );
        let mut changed = base.clone();
        changed.required_bodies[0].decision_mode = BodyDecisionModeV1::AnonymousBallot;
        assert_eq!(
            changed.validate(),
            Err(FrozenBallotPolicyErrorV1::DecisionMode {
                body: changed.required_bodies[0].body
            })
        );
        let mut changed = base.clone();
        let last = changed.required_bodies.len() - 1;
        changed.required_bodies[last].decision_mode = BodyDecisionModeV1::PublicFinding;
        assert!(matches!(
            changed.validate(),
            Err(FrozenBallotPolicyErrorV1::DecisionMode { .. })
        ));
        let mut changed = base.clone();
        changed.required_bodies[last].target_seats = 2;
        assert_eq!(
            changed.validate(),
            Err(FrozenBallotPolicyErrorV1::TargetSeats {
                body: ParliamentBody::ConfirmationJury
            })
        );
        let mut changed = base.clone();
        changed.required_bodies[0].target_seats = 0;
        assert!(matches!(
            changed.validate(),
            Err(FrozenBallotPolicyErrorV1::TargetSeats { .. })
        ));
        let mut changed = base;
        changed.required_bodies[0].alternate_cap = 1_001;
        assert!(matches!(
            changed.validate(),
            Err(FrozenBallotPolicyErrorV1::AlternateCap { .. })
        ));
    }

    #[test]
    fn sortition_and_lifecycle_bounds_are_enforced() {
        let base = policy();
        assert_eq!(base.sortition_policy.validate(), Ok(()));
        assert_eq!(base.lifecycle_policy.validate(), Ok(()));
        let mutations: [Mutation<FrozenSortitionPolicyV1>; 4] = [
            ("pulse_cadence_blocks", |s| s.pulse_cadence_blocks = 0),
            ("cross_body_assignment_cap", |s| {
                s.cross_body_assignment_cap = 0;
            }),
            ("max_sortition_retries", |s| s.max_sortition_retries = 17),
            ("max_randomness_redraws", |s| s.max_randomness_redraws = 17),
        ];
        for (field, mutate) in mutations {
            let mut sortition = base.sortition_policy;
            mutate(&mut sortition);
            assert_eq!(
                sortition.validate(),
                Err(FrozenBallotPolicyErrorV1::Sortition { field })
            );
        }
        let mut lifecycle = base.lifecycle_policy;
        lifecycle.invitation_window_ms = 0;
        assert_eq!(
            lifecycle.validate(),
            Err(FrozenBallotPolicyErrorV1::Lifecycle {
                field: "invitation_window_ms"
            })
        );
        let mut lifecycle = base.lifecycle_policy;
        lifecycle.deliberation_window_ms = 0;
        assert!(lifecycle.validate().is_err());
        let mut lifecycle = base.lifecycle_policy;
        lifecycle.enactment_delay_ms = 0;
        assert_eq!(lifecycle.validate(), Ok(()));
        for value in [
            BodyDecisionModeV1::PublicFinding,
            BodyDecisionModeV1::AnonymousBallot,
        ] {
            assert_eq!(
                decode_enc::<BodyDecisionModeV1>(&enc(&value).expect("enc")),
                Ok(value)
            );
        }
        let commitment = base.capacity_commitment;
        assert_eq!(
            decode_enc::<BallotCapacityCommitmentV1>(&enc(&commitment).expect("enc")),
            Ok(commitment)
        );
        assert_eq!(
            BallotCapacityCommitmentV1::from_parameters(
                &ParliamentBallotParametersV1::default(),
                1_000
            ),
            commitment
        );
        let capacity = commitment.validate(86_400_000).expect("capacity");
        assert_eq!(capacity.capacity, 172_798);
    }
}
