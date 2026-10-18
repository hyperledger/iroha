//! The frozen Parliament attempt policy and the binding-ballot policies derived from it
//! (integration decision 7 and the governance-clock lifecycle decisions A and K4 of
//! 2026-10-18).
//!
//! Parliament admission freezes one [`FrozenParliamentAttemptPolicyV1`] from committed chain
//! state ([`FrozenParliamentAttemptPolicyV1::freeze_v1`]): the protocol-defined body pipeline
//! with the seat targets and alternate caps of `gov.parliament_lifecycle`, the lifecycle
//! durations, the sortition policy with the native pulse cadence copied from the
//! genesis-immutable `NPoS` schedule and, for a binding attempt, the binding-ballot policy of
//! `gov.parliament_ballot` at the committed block cadence. Subsequent generations and
//! public-finding bodies use that snapshot; no parameter update changes it.
//!
//! At the first Policy Jury sortition request the risk tier locks and both binding-body
//! snapshots are materialized from the admission snapshot
//! ([`FrozenParliamentAttemptPolicyV1::binding_ballot_policies`]); they differ only by
//! `body_role` and never reread live parameters. A [`FrozenBallotPolicyV1`] is exactly the
//! attempt snapshot, the locked tier, the body role and the fixed V1 ballot constants, and
//! it is validated by the one attempt-policy validator rather than as an independent copy.
//! It is the `policy_hash` preimage:
//! `policy_hash = SHA3-512(Frame("PARL/POLICY/v1"; P16, Enc(policy)))`, which the proof crate
//! computes (through `iroha_parliament_ballot`). The snapshots exclude node-local settings,
//! mutable counts and observed timings.
//!
//! TODO: the Core integration freezes the attempt policy at admission, materializes and
//! stores both ballot policies at the risk lock, and checks a restored ballot policy with
//! [`FrozenBallotPolicyV1::is_derived_from`].

use iroha_primitives::numeric::Quantity;
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
        MAX_PARLIAMENT_BODY_TARGET_SEATS_V1, MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1,
        PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1, ParliamentBody, RiskTierV1,
    },
    parameter::{
        parliament_ballot::{
            BallotCastingCapacityV1, parliament_ballot_capacity_v1, reserved_ballot_slots_v1,
            reserved_ballot_wire_bytes_v1,
        },
        parliament_lifecycle::{
            MAX_PARLIAMENT_BODY_ALTERNATES_V1, MIN_PUBLIC_BODY_TARGET_SEATS_V1,
            ParliamentLifecycleParametersV1, ParliamentSortitionParametersV1,
            check_sortition_fields,
        },
    },
};

/// Why a frozen attempt or ballot policy, or a committed lifecycle parameter, is not a valid
/// V1 value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrozenBallotPolicyErrorV1 {
    /// The governance policy version is not the V1 version.
    #[error("governance policy version {actual} is not the V1 version")]
    PolicyVersion {
        /// Version supplied.
        actual: u64,
    },
    /// A ballot policy's body is not a binding jury.
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
    /// A committed ballot parameter, a capacity reservation or the capacity rule is violated.
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
    /// A binding pipeline lacks one of the two binding juries.
    #[error("the frozen pipeline lacks {body:?}")]
    MissingBody {
        /// The missing body.
        body: ParliamentBody,
    },
    /// A binding pipeline has no binding-ballot policy, or no committed ballot parameters
    /// were supplied to freeze one.
    #[error("a binding pipeline needs a binding-ballot policy")]
    MissingBindingPolicy,
    /// A pipeline without binding juries carries a binding-ballot policy.
    #[error("a pipeline without binding juries carries a binding-ballot policy")]
    UnexpectedBindingPolicy,
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
    /// The committed body table does not have exactly the ten roles.
    #[error("the body table has {actual} entries; exactly the ten roles are required")]
    BodyTableLength {
        /// Entries supplied.
        actual: usize,
    },
    /// A committed body-table entry is not the role at its canonical position (a missing,
    /// duplicate or reordered role).
    #[error("body table entry {index} is {found:?}; {expected:?} is required there")]
    BodyTableRole {
        /// Index of the entry.
        index: usize,
        /// The role required at that position.
        expected: ParliamentBody,
        /// The role found.
        found: ParliamentBody,
    },
}

/// Check a body's seat target and alternate cap against its role's structural ranges:
/// targets `1..=1000` for a public-finding body and `3..=1000` for a binding jury, and
/// `0..=1000` alternates.
///
/// # Errors
/// [`FrozenBallotPolicyErrorV1::TargetSeats`] or [`FrozenBallotPolicyErrorV1::AlternateCap`].
pub fn check_body_size(
    body: ParliamentBody,
    target_seats: u16,
    alternate_cap: u16,
) -> Result<(), FrozenBallotPolicyErrorV1> {
    let minimum = if is_binding_body(body) {
        MIN_SEALED_SEATS_V1
    } else {
        MIN_PUBLIC_BODY_TARGET_SEATS_V1
    };
    if target_seats < minimum || u32::from(target_seats) > MAX_PARLIAMENT_BODY_TARGET_SEATS_V1 {
        return Err(FrozenBallotPolicyErrorV1::TargetSeats { body });
    }
    if alternate_cap > MAX_PARLIAMENT_BODY_ALTERNATES_V1 {
        return Err(FrozenBallotPolicyErrorV1::AlternateCap { body });
    }
    Ok(())
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

impl BodyDecisionModeV1 {
    /// The decision mode of `body`'s role: an anonymous ballot for a binding jury, a public
    /// finding otherwise.
    #[must_use]
    pub fn of(body: ParliamentBody) -> Self {
        if is_binding_body(body) {
            Self::AnonymousBallot
        } else {
            Self::PublicFinding
        }
    }
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

/// The frozen sortition policy of an attempt: the five committed sortition parameters, the
/// native pulse cadence copied from the genesis-immutable `NPoS` schedule, and the fixed V1
/// governance-attempt retry ceiling.
#[derive(
    Clone,
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
    /// Largest cross-body assignment cap the smallest-feasible allocation may choose; the
    /// cap actually chosen is recorded in the generation.
    pub max_cross_body_assignment_cap: u32,
    /// Ceiling on `NoRoster` sortition retries of one body after sequence zero.
    pub max_sortition_retries: u32,
    /// Cumulative proposal-wide ceiling on fresh-randomness redraws; a successor attempt
    /// inherits the lineage ceiling, tightened by its own policy, never increased.
    pub max_randomness_redraws: u32,
    /// Smallest citizenship bond, in whole atoms of the bond asset, that makes a citizen
    /// eligible; Parliament eligibility uses this frozen threshold, never the live
    /// configuration.
    pub minimum_citizenship_bond: Quantity,
    /// Native pulse cadence `L` (the `NPoS` epoch length in blocks); pulse heights are those
    /// `h` with `(h + 1) % L == 0`.
    pub pulse_cadence_blocks: u64,
    /// The fixed V1 ceiling on governance-attempt retries after sequence zero,
    /// [`MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1`]; not an adjustable parameter.
    pub max_governance_attempt_retries: u32,
}

impl FrozenSortitionPolicyV1 {
    /// Smallest native pulse cadence in blocks.
    pub const MIN_PULSE_CADENCE_BLOCKS: u64 = 3;
    /// Largest native pulse cadence in blocks.
    pub const MAX_PULSE_CADENCE_BLOCKS: u64 = 65_536;

    /// Freeze the committed `parameters` with the native pulse cadence of the `NPoS`
    /// schedule and the fixed governance-attempt retry ceiling.
    ///
    /// # Errors
    /// As [`Self::validate`].
    pub fn freeze_v1(
        parameters: &ParliamentSortitionParametersV1,
        pulse_cadence_blocks: u64,
    ) -> Result<Self, FrozenBallotPolicyErrorV1> {
        let policy = Self {
            pulse_delay_blocks: parameters.pulse_delay_blocks,
            max_cross_body_assignment_cap: parameters.max_cross_body_assignment_cap,
            max_sortition_retries: parameters.max_sortition_retries,
            max_randomness_redraws: parameters.max_randomness_redraws,
            minimum_citizenship_bond: parameters.minimum_citizenship_bond.clone(),
            pulse_cadence_blocks,
            max_governance_attempt_retries: MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Check the committed fields' ranges (as [`ParliamentSortitionParametersV1::validate`]),
    /// a pulse cadence in `3..=65,536` and the fixed governance-attempt retry ceiling.
    ///
    /// # Errors
    /// [`FrozenBallotPolicyErrorV1::Sortition`] naming the first offending field.
    pub fn validate(&self) -> Result<(), FrozenBallotPolicyErrorV1> {
        check_sortition_fields(
            self.pulse_delay_blocks,
            self.max_cross_body_assignment_cap,
            self.max_sortition_retries,
            self.max_randomness_redraws,
            &self.minimum_citizenship_bond,
        )?;
        let field = if !(Self::MIN_PULSE_CADENCE_BLOCKS..=Self::MAX_PULSE_CADENCE_BLOCKS)
            .contains(&self.pulse_cadence_blocks)
        {
            "pulse_cadence_blocks"
        } else if self.max_governance_attempt_retries
            != MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1
        {
            "max_governance_attempt_retries"
        } else {
            return Ok(());
        };
        Err(FrozenBallotPolicyErrorV1::Sortition { field })
    }
}

/// The frozen lifecycle durations of an attempt, in milliseconds of the governance clock.
///
/// Every window accepts `1..=604,800,000` ms and the enactment delay `0..=604,800,000` ms;
/// Reflection has no separate generic duration (a binding body's opening deadline uses the
/// ballot notice, a public body's the public-finding window). An authorized early-completion
/// or phase-advance intent may shorten a wait but never removes its deadline.
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
    /// Qualification window from the `StartQualification` anchor; qualification completes
    /// automatically at its deadline.
    pub qualification_window_ms: u64,
    /// Invitation-response window of each body election, from its draw anchor.
    pub invitation_window_ms: u64,
    /// Longest Orientation phase of the current body.
    pub orientation_window_ms: u64,
    /// Longest Evidence phase.
    pub evidence_window_ms: u64,
    /// Longest Questions phase.
    pub questions_window_ms: u64,
    /// Longest Responses phase.
    pub responses_window_ms: u64,
    /// Longest Deliberation phase.
    pub deliberation_window_ms: u64,
    /// Public-finding window of a public body's Reflection, from its Reflection anchor.
    pub public_finding_window_ms: u64,
    /// Delay from the certification anchor to `enact_not_before_ms`; zero permits same-pass
    /// enactment.
    pub enactment_delay_ms: u64,
}

impl Default for FrozenLifecyclePolicyV1 {
    fn default() -> Self {
        Self {
            qualification_window_ms: 3_600_000,
            invitation_window_ms: 3_600_000,
            orientation_window_ms: 3_600_000,
            evidence_window_ms: 86_400_000,
            questions_window_ms: 3_600_000,
            responses_window_ms: 3_600_000,
            deliberation_window_ms: 3_600_000,
            public_finding_window_ms: 3_600_000,
            enactment_delay_ms: 20_000,
        }
    }
}

impl FrozenLifecyclePolicyV1 {
    /// Shortest window: the structural minimum of every network (one millisecond).
    pub const MIN_WINDOW_MS: u64 = 1;
    /// Longest window or enactment delay (seven days).
    pub const MAX_DURATION_MS: u64 = 604_800_000;

    /// The eight windows, each with its field name, in field order.
    #[must_use]
    pub const fn windows(&self) -> [(&'static str, u64); 8] {
        [
            ("qualification_window_ms", self.qualification_window_ms),
            ("invitation_window_ms", self.invitation_window_ms),
            ("orientation_window_ms", self.orientation_window_ms),
            ("evidence_window_ms", self.evidence_window_ms),
            ("questions_window_ms", self.questions_window_ms),
            ("responses_window_ms", self.responses_window_ms),
            ("deliberation_window_ms", self.deliberation_window_ms),
            ("public_finding_window_ms", self.public_finding_window_ms),
        ]
    }

    /// Check every window in `1..=604,800,000` and the enactment delay in
    /// `0..=604,800,000`.
    ///
    /// # Errors
    /// [`FrozenBallotPolicyErrorV1::Lifecycle`] naming the first offending field.
    pub fn validate(&self) -> Result<(), FrozenBallotPolicyErrorV1> {
        for (field, value) in self.windows() {
            if !(Self::MIN_WINDOW_MS..=Self::MAX_DURATION_MS).contains(&value) {
                return Err(FrozenBallotPolicyErrorV1::Lifecycle { field });
            }
        }
        if self.enactment_delay_ms > Self::MAX_DURATION_MS {
            return Err(FrozenBallotPolicyErrorV1::Lifecycle {
                field: "enactment_delay_ms",
            });
        }
        Ok(())
    }
}

/// The capacity guarantee recorded at admission (integration decision 5, lifecycle decision
/// K4): the global limits `K`, `B_work`, `B_bytes`, the honest proposer's ballot
/// reservations derived from them, and the block cadence under which the casting window
/// passed the capacity rule.
///
/// The reservations are derived, not independent knobs:
///
/// ```text
/// b0                                   = min(B_work, floor(B_bytes / 425,984))
/// reserved_ballot_slots_per_block      = b0
/// reserved_ballot_wire_bytes_per_block = b0 × 263,168
/// ```
///
/// Live committed limits still govern execution; updates may not weaken an outstanding
/// commitment.
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
    /// Anonymous-ballot input slots the honest proposer reserves per block, `b0`.
    pub reserved_ballot_slots_per_block: u32,
    /// Complete anonymous-entrypoint wire bytes the honest proposer reserves per block,
    /// `b0 × 263,168`.
    pub reserved_ballot_wire_bytes_per_block: u64,
    /// Committed block cadence in milliseconds.
    pub block_cadence_ms: u64,
}

impl BallotCapacityCommitmentV1 {
    /// The commitment of `parameters` at the committed `block_cadence_ms`, with the
    /// reservations derived from its budgets.
    #[must_use]
    pub fn from_parameters(
        parameters: &ParliamentBallotParametersV1,
        block_cadence_ms: u64,
    ) -> Self {
        let slots = reserved_ballot_slots_v1(
            parameters.max_verification_reservations_per_block,
            parameters.max_verifier_input_bytes_per_block,
        );
        Self {
            max_nonterminal_attempts: parameters.max_nonterminal_attempts,
            max_verification_reservations_per_block: parameters
                .max_verification_reservations_per_block,
            max_verifier_input_bytes_per_block: parameters.max_verifier_input_bytes_per_block,
            reserved_ballot_slots_per_block: slots,
            reserved_ballot_wire_bytes_per_block: reserved_ballot_wire_bytes_v1(slots),
            block_cadence_ms,
        }
    }

    /// Check the committed budget ranges, that both reservations are exactly the values
    /// derived from the budgets, and that `casting_window_ms` passes the capacity rule under
    /// this commitment.
    ///
    /// # Errors
    /// [`ParliamentBallotParameterErrorV1`] for a range, reservation or capacity violation.
    pub fn validate(
        &self,
        casting_window_ms: u64,
    ) -> Result<BallotCastingCapacityV1, ParliamentBallotParameterErrorV1> {
        ParliamentBallotParametersV1::check_budget_ranges(
            self.max_nonterminal_attempts,
            self.max_verification_reservations_per_block,
            self.max_verifier_input_bytes_per_block,
        )?;
        let slots = reserved_ballot_slots_v1(
            self.max_verification_reservations_per_block,
            self.max_verifier_input_bytes_per_block,
        );
        if self.reserved_ballot_slots_per_block != slots
            || self.reserved_ballot_wire_bytes_per_block != reserved_ballot_wire_bytes_v1(slots)
        {
            return Err(ParliamentBallotParameterErrorV1::ReservationMismatch);
        }
        parliament_ballot_capacity_v1(casting_window_ms, self)
    }
}

/// The frozen binding-ballot policy of a binding attempt, from `gov.parliament_ballot` at
/// admission: the profile, the casting timings, the stamp difficulty and the capacity
/// guarantee. Both binding bodies of the attempt use it.
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
    name = "iroha_data_model::governance::anonymous_ballot::FrozenBindingAttemptPolicyV1"
)]
pub struct FrozenBindingAttemptPolicyV1 {
    /// The V1 proof profile.
    pub profile_id: ProofProfileIdV1,
    /// Minimum notice between sealing and casting:
    /// `opening_at_ms = max(reflection_ms, sealed_ms + vote_notice_ms)`.
    pub vote_notice_ms: u64,
    /// Casting duration after the successor-block clock.
    pub casting_window_ms: u64,
    /// Leading zero bits the admission stamp's work digest needs.
    pub stamp_difficulty_bits: u8,
    /// Capacity guarantee recorded at admission.
    pub capacity_commitment: BallotCapacityCommitmentV1,
}

impl FrozenBindingAttemptPolicyV1 {
    /// Freeze the committed ballot `parameters` at the committed `block_cadence_ms`.
    ///
    /// # Errors
    /// [`FrozenBallotPolicyErrorV1::Parameter`] for parameters that fail their structural
    /// ranges or the capacity rule at this cadence.
    pub fn freeze_v1(
        parameters: &ParliamentBallotParametersV1,
        block_cadence_ms: u64,
    ) -> Result<Self, FrozenBallotPolicyErrorV1> {
        parameters.validate(block_cadence_ms)?;
        let policy = Self {
            profile_id: ProofProfileIdV1::V1,
            vote_notice_ms: parameters.vote_notice_ms,
            casting_window_ms: parameters.casting_window_ms,
            stamp_difficulty_bits: parameters.stamp_difficulty_bits,
            capacity_commitment: BallotCapacityCommitmentV1::from_parameters(
                parameters,
                block_cadence_ms,
            ),
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Check the V1 profile, the casting ranges and the capacity commitment under the frozen
    /// casting window.
    ///
    /// # Errors
    /// [`FrozenBallotPolicyErrorV1::UnknownProfile`] or
    /// [`FrozenBallotPolicyErrorV1::Parameter`].
    pub fn validate(&self) -> Result<(), FrozenBallotPolicyErrorV1> {
        if !self.profile_id.is_v1() {
            return Err(FrozenBallotPolicyErrorV1::UnknownProfile);
        }
        ParliamentBallotParametersV1::check_casting_ranges(
            self.vote_notice_ms,
            self.casting_window_ms,
            self.stamp_difficulty_bits,
        )?;
        self.capacity_commitment.validate(self.casting_window_ms)?;
        Ok(())
    }
}

/// The policy of one Parliament attempt, frozen at admission (lifecycle decision A).
///
/// `binding` is present exactly when the protocol-defined pipeline contains the binding
/// juries; a binding pipeline names both the Policy Jury and the conditional Confirmation
/// Jury, whose presence does not mean it is always drawn.
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
#[norito_schema(
    name = "iroha_data_model::governance::anonymous_ballot::FrozenParliamentAttemptPolicyV1"
)]
pub struct FrozenParliamentAttemptPolicyV1 {
    /// Governance policy version in force at admission.
    pub governance_policy_version: u64,
    /// Every body of the attempt in canonical pipeline order, with its frozen size.
    pub required_bodies: Vec<RequiredBodyPolicyV1>,
    /// Frozen sortition policy.
    pub sortition_policy: FrozenSortitionPolicyV1,
    /// Frozen lifecycle durations.
    pub lifecycle_policy: FrozenLifecyclePolicyV1,
    /// Frozen binding-ballot policy of a binding attempt.
    pub binding: Option<FrozenBindingAttemptPolicyV1>,
}

/// Check the parts of an attempt policy: the one validator of both the attempt snapshot and
/// every ballot policy derived from it.
fn validate_attempt_parts(
    governance_policy_version: u64,
    required_bodies: &[RequiredBodyPolicyV1],
    sortition_policy: &FrozenSortitionPolicyV1,
    lifecycle_policy: &FrozenLifecyclePolicyV1,
    binding: Option<&FrozenBindingAttemptPolicyV1>,
) -> Result<(), FrozenBallotPolicyErrorV1> {
    if governance_policy_version != PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1 {
        return Err(FrozenBallotPolicyErrorV1::PolicyVersion {
            actual: governance_policy_version,
        });
    }
    if required_bodies.is_empty() {
        return Err(FrozenBallotPolicyErrorV1::NoRequiredBodies);
    }
    if let Some(index) = required_bodies
        .windows(2)
        .position(|pair| pair[0].body >= pair[1].body)
    {
        return Err(FrozenBallotPolicyErrorV1::RequiredBodyOrder { index: index + 1 });
    }
    for required in required_bodies {
        if required.decision_mode != BodyDecisionModeV1::of(required.body) {
            return Err(FrozenBallotPolicyErrorV1::DecisionMode {
                body: required.body,
            });
        }
        check_body_size(required.body, required.target_seats, required.alternate_cap)?;
    }
    let names = |body| required_bodies.iter().any(|required| required.body == body);
    let binding_pipeline = required_bodies
        .iter()
        .any(|required| is_binding_body(required.body));
    if binding_pipeline {
        for body in [ParliamentBody::PolicyJury, ParliamentBody::ConfirmationJury] {
            if !names(body) {
                return Err(FrozenBallotPolicyErrorV1::MissingBody { body });
            }
        }
        binding
            .ok_or(FrozenBallotPolicyErrorV1::MissingBindingPolicy)?
            .validate()?;
    } else if binding.is_some() {
        return Err(FrozenBallotPolicyErrorV1::UnexpectedBindingPolicy);
    }
    sortition_policy.validate()?;
    lifecycle_policy.validate()
}

impl FrozenParliamentAttemptPolicyV1 {
    /// Freeze the policy of an attempt at admission from committed chain state.
    ///
    /// `pipeline` is the protocol-defined pipeline of the proposal kind in canonical body
    /// order, including the conditional Confirmation Jury of a binding pipeline; callers
    /// cannot choose it. Each body takes its seat target and alternate cap from `lifecycle`;
    /// the native pulse cadence `pulse_cadence_blocks` comes from the genesis-immutable `NPoS`
    /// schedule. A binding pipeline freezes the committed `ballot` parameters at the
    /// committed `block_cadence_ms`; `ballot` is ignored otherwise.
    ///
    /// # Errors
    /// [`FrozenBallotPolicyErrorV1`] for invalid committed parameters, a pipeline that is not
    /// canonical, a binding pipeline without `ballot` parameters
    /// ([`FrozenBallotPolicyErrorV1::MissingBindingPolicy`]) or a capacity violation.
    pub fn freeze_v1(
        pipeline: &[ParliamentBody],
        lifecycle: &ParliamentLifecycleParametersV1,
        ballot: Option<&ParliamentBallotParametersV1>,
        block_cadence_ms: u64,
        pulse_cadence_blocks: u64,
    ) -> Result<Self, FrozenBallotPolicyErrorV1> {
        lifecycle.validate()?;
        // A valid table sizes every role.
        let actual = lifecycle.body_sizes.len();
        let required_bodies = pipeline
            .iter()
            .map(|&body| {
                let sizing = lifecycle
                    .body_sizing(body)
                    .ok_or(FrozenBallotPolicyErrorV1::BodyTableLength { actual })?;
                Ok(RequiredBodyPolicyV1 {
                    body,
                    decision_mode: BodyDecisionModeV1::of(body),
                    target_seats: sizing.target_seats,
                    alternate_cap: sizing.alternate_cap,
                })
            })
            .collect::<Result<Vec<_>, FrozenBallotPolicyErrorV1>>()?;
        let binding = if pipeline.iter().any(|&body| is_binding_body(body)) {
            let parameters = ballot.ok_or(FrozenBallotPolicyErrorV1::MissingBindingPolicy)?;
            Some(FrozenBindingAttemptPolicyV1::freeze_v1(
                parameters,
                block_cadence_ms,
            )?)
        } else {
            None
        };
        let policy = Self {
            governance_policy_version: PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1,
            required_bodies,
            sortition_policy: FrozenSortitionPolicyV1::freeze_v1(
                &lifecycle.sortition,
                pulse_cadence_blocks,
            )?,
            lifecycle_policy: lifecycle.lifecycle,
            binding,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Check the snapshot: the V1 version; a nonempty, strictly ordered pipeline whose
    /// bodies have their roles' decision modes and sizes; a binding pipeline with both
    /// juries and a valid binding policy, or no binding juries and no binding policy; and the
    /// sortition and lifecycle policies.
    ///
    /// # Errors
    /// The first violated rule as a [`FrozenBallotPolicyErrorV1`].
    pub fn validate(&self) -> Result<(), FrozenBallotPolicyErrorV1> {
        validate_attempt_parts(
            self.governance_policy_version,
            &self.required_bodies,
            &self.sortition_policy,
            &self.lifecycle_policy,
            self.binding.as_ref(),
        )
    }

    /// The frozen pipeline entry of `body`, if the pipeline names it.
    #[must_use]
    pub fn required_body(&self, body: ParliamentBody) -> Option<&RequiredBodyPolicyV1> {
        self.required_bodies
            .iter()
            .find(|required| required.body == body)
    }

    /// The ballot policy of the binding jury `body_role` under the locked `risk_tier`: the
    /// snapshot, the tier, the role and the fixed V1 ballot constants. It never rereads live
    /// parameters.
    ///
    /// # Errors
    /// [`FrozenBallotPolicyErrorV1::NotBindingBody`] for another body,
    /// [`FrozenBallotPolicyErrorV1::MissingBindingPolicy`] for an attempt without binding
    /// juries, or the first violated rule of [`FrozenBallotPolicyV1::validate`].
    pub fn ballot_policy(
        &self,
        risk_tier: RiskTierV1,
        body_role: ParliamentBody,
    ) -> Result<FrozenBallotPolicyV1, FrozenBallotPolicyErrorV1> {
        if !is_binding_body(body_role) {
            return Err(FrozenBallotPolicyErrorV1::NotBindingBody { body: body_role });
        }
        let binding = self
            .binding
            .ok_or(FrozenBallotPolicyErrorV1::MissingBindingPolicy)?;
        let policy = FrozenBallotPolicyV1 {
            governance_policy_version: self.governance_policy_version,
            required_bodies: self.required_bodies.clone(),
            sortition_policy: self.sortition_policy.clone(),
            lifecycle_policy: self.lifecycle_policy,
            binding,
            risk_tier,
            body_role,
            minimum_sealed_seats: MIN_SEALED_SEATS_V1,
            minimum_turnout: MIN_TURNOUT_V1,
            quorum_numerator: FrozenBallotPolicyV1::QUORUM_NUMERATOR,
            quorum_denominator: FrozenBallotPolicyV1::QUORUM_DENOMINATOR,
            decision_rule: ParliamentDecisionRuleV1::V1,
            maximum_seats: MAX_SEALED_SEATS_V1,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Both binding-body policies at the risk lock, `[Policy Jury, Confirmation Jury]`; they
    /// differ only by `body_role`.
    ///
    /// # Errors
    /// As [`Self::ballot_policy`].
    pub fn binding_ballot_policies(
        &self,
        risk_tier: RiskTierV1,
    ) -> Result<[FrozenBallotPolicyV1; 2], FrozenBallotPolicyErrorV1> {
        Ok([
            self.ballot_policy(risk_tier, ParliamentBody::PolicyJury)?,
            self.ballot_policy(risk_tier, ParliamentBody::ConfirmationJury)?,
        ])
    }
}

/// The frozen policy snapshot of one binding body: the `policy_hash` preimage.
///
/// Its fields are, in order, the attempt snapshot (every field of
/// [`FrozenParliamentAttemptPolicyV1`], with the binding policy present), the risk tier
/// locked at the first Policy Jury sortition request, the body role, and the fixed V1
/// ballot constants. It is derived with [`FrozenParliamentAttemptPolicyV1::ballot_policy`].
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
    /// Governance policy version of the attempt snapshot.
    pub governance_policy_version: u64,
    /// The attempt's pipeline in canonical order. Both juries are present; the decision rule
    /// draws the Confirmation Jury only after an approved narrow Policy result.
    pub required_bodies: Vec<RequiredBodyPolicyV1>,
    /// The attempt's frozen sortition policy.
    pub sortition_policy: FrozenSortitionPolicyV1,
    /// The attempt's frozen lifecycle durations.
    pub lifecycle_policy: FrozenLifecyclePolicyV1,
    /// The attempt's frozen binding-ballot policy.
    pub binding: FrozenBindingAttemptPolicyV1,
    /// Risk tier, locked at the first Policy Jury sortition request.
    pub risk_tier: RiskTierV1,
    /// The binding body this snapshot belongs to.
    pub body_role: ParliamentBody,
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
}

impl FrozenBallotPolicyV1 {
    /// The V1 quorum numerator.
    pub const QUORUM_NUMERATOR: u16 = 2;
    /// The V1 quorum denominator.
    pub const QUORUM_DENOMINATOR: u16 = 3;

    /// Check the snapshot: a binding-jury role, the fixed V1 ballot constants, and the
    /// attempt snapshot it carries with the one attempt-policy validator (its pipeline,
    /// binding policy and capacity rule, sortition and lifecycle policies).
    ///
    /// # Errors
    /// The first violated rule as a [`FrozenBallotPolicyErrorV1`].
    pub fn validate(&self) -> Result<(), FrozenBallotPolicyErrorV1> {
        if !is_binding_body(self.body_role) {
            return Err(FrozenBallotPolicyErrorV1::NotBindingBody {
                body: self.body_role,
            });
        }
        for (field, actual, expected) in [
            (
                "minimum_sealed_seats",
                self.minimum_sealed_seats,
                MIN_SEALED_SEATS_V1,
            ),
            ("minimum_turnout", self.minimum_turnout, MIN_TURNOUT_V1),
            (
                "quorum_numerator",
                self.quorum_numerator,
                Self::QUORUM_NUMERATOR,
            ),
            (
                "quorum_denominator",
                self.quorum_denominator,
                Self::QUORUM_DENOMINATOR,
            ),
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
        validate_attempt_parts(
            self.governance_policy_version,
            &self.required_bodies,
            &self.sortition_policy,
            &self.lifecycle_policy,
            Some(&self.binding),
        )
    }

    /// The frozen pipeline entry of `body`, if the pipeline names it.
    #[must_use]
    pub fn required_body(&self, body: ParliamentBody) -> Option<&RequiredBodyPolicyV1> {
        self.required_bodies
            .iter()
            .find(|required| required.body == body)
    }

    /// The frozen seat target of this snapshot's own body: the cap of its sealed seats.
    #[must_use]
    pub fn body_target_seats(&self) -> Option<u16> {
        self.required_body(self.body_role)
            .map(|required| required.target_seats)
    }

    /// The attempt snapshot this policy carries.
    #[must_use]
    pub fn attempt_policy(&self) -> FrozenParliamentAttemptPolicyV1 {
        FrozenParliamentAttemptPolicyV1 {
            governance_policy_version: self.governance_policy_version,
            required_bodies: self.required_bodies.clone(),
            sortition_policy: self.sortition_policy.clone(),
            lifecycle_policy: self.lifecycle_policy,
            binding: Some(self.binding),
        }
    }

    /// Whether this policy is exactly the one `attempt` derives for its tier and role: the
    /// restore check that a stored ballot policy belongs to its stored attempt snapshot.
    #[must_use]
    pub fn is_derived_from(&self, attempt: &FrozenParliamentAttemptPolicyV1) -> bool {
        attempt
            .ballot_policy(self.risk_tier, self.body_role)
            .is_ok_and(|derived| derived == *self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        governance::{
            anonymous_ballot::{
                framing::{decode_enc, enc},
                test_fixtures::{attempt_policy, pipeline, policy},
            },
            types::PARLIAMENT_BODIES_V1,
        },
        parameter::parliament_lifecycle::MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1,
    };

    /// A named change of one field, for table-driven refusal tests.
    type Mutation<T> = (&'static str, fn(&mut T));

    #[test]
    fn the_attempt_policy_freezes_the_committed_parameters() {
        let attempt = attempt_policy();
        assert_eq!(attempt.validate(), Ok(()));
        let lifecycle = ParliamentLifecycleParametersV1::default();
        let ballot = ParliamentBallotParametersV1::default();
        assert_eq!(
            attempt.governance_policy_version,
            PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1
        );
        assert_eq!(attempt.lifecycle_policy, lifecycle.lifecycle);
        // Every body takes its committed size and its role's decision mode.
        assert_eq!(
            attempt
                .required_bodies
                .iter()
                .map(|required| required.body)
                .collect::<Vec<_>>(),
            pipeline()
        );
        for required in &attempt.required_bodies {
            let sizing = lifecycle.body_sizing(required.body).expect("sized");
            assert_eq!(required.target_seats, sizing.target_seats);
            assert_eq!(required.alternate_cap, sizing.alternate_cap);
            assert_eq!(
                required.decision_mode,
                BodyDecisionModeV1::of(required.body)
            );
        }
        assert_eq!(
            attempt
                .required_body(ParliamentBody::PolicyJury)
                .map(|r| r.decision_mode),
            Some(BodyDecisionModeV1::AnonymousBallot)
        );
        assert_eq!(attempt.required_body(ParliamentBody::MpcCommittee), None);
        // The sortition policy adds the NPoS cadence and the fixed retry ceiling.
        let sortition = &attempt.sortition_policy;
        assert_eq!(
            sortition.pulse_delay_blocks,
            lifecycle.sortition.pulse_delay_blocks
        );
        assert_eq!(
            sortition.max_cross_body_assignment_cap,
            lifecycle.sortition.max_cross_body_assignment_cap
        );
        assert_eq!(
            sortition.minimum_citizenship_bond,
            lifecycle.sortition.minimum_citizenship_bond
        );
        assert_eq!(sortition.pulse_cadence_blocks, 3_600);
        assert_eq!(sortition.max_governance_attempt_retries, 16);
        // The binding policy freezes the ballot parameters and derives the reservations.
        let binding = attempt.binding.expect("binding pipeline");
        assert_eq!(
            (
                binding.profile_id,
                binding.vote_notice_ms,
                binding.casting_window_ms,
                binding.stamp_difficulty_bits
            ),
            (
                ProofProfileIdV1::V1,
                ballot.vote_notice_ms,
                ballot.casting_window_ms,
                ballot.stamp_difficulty_bits
            )
        );
        assert_eq!(
            binding.capacity_commitment,
            BallotCapacityCommitmentV1::from_parameters(&ballot, 1_000)
        );
        assert_eq!(
            binding.capacity_commitment.reserved_ballot_slots_per_block,
            2
        );
        assert_eq!(
            binding
                .capacity_commitment
                .reserved_ballot_wire_bytes_per_block,
            526_336
        );
        assert_eq!(
            decode_enc::<FrozenParliamentAttemptPolicyV1>(&enc(&attempt).expect("enc")),
            Ok(attempt.clone())
        );
        let json = norito::json::to_json(&attempt).expect("json");
        assert_eq!(
            norito::json::from_str::<FrozenParliamentAttemptPolicyV1>(&json).expect("json"),
            attempt
        );
    }

    #[test]
    fn a_public_pipeline_freezes_without_a_binding_policy() {
        let lifecycle = ParliamentLifecycleParametersV1::default();
        let public = [ParliamentBody::RulesCommittee, ParliamentBody::ReviewPanel];
        let attempt =
            FrozenParliamentAttemptPolicyV1::freeze_v1(&public, &lifecycle, None, 1_000, 3)
                .expect("public attempt");
        assert_eq!(attempt.binding, None);
        assert_eq!(attempt.validate(), Ok(()));
        // Ballot parameters are ignored for a public pipeline.
        assert_eq!(
            FrozenParliamentAttemptPolicyV1::freeze_v1(
                &public,
                &lifecycle,
                Some(&ParliamentBallotParametersV1::default()),
                1_000,
                3
            ),
            Ok(attempt.clone())
        );
        assert_eq!(
            attempt.ballot_policy(RiskTierV1::Standard, ParliamentBody::PolicyJury),
            Err(FrozenBallotPolicyErrorV1::MissingBindingPolicy)
        );
        let mut with_binding = attempt;
        with_binding.binding = attempt_policy().binding;
        assert_eq!(
            with_binding.validate(),
            Err(FrozenBallotPolicyErrorV1::UnexpectedBindingPolicy)
        );
    }

    #[test]
    fn freezing_refuses_incomplete_or_invalid_inputs() {
        let lifecycle = ParliamentLifecycleParametersV1::default();
        let ballot = ParliamentBallotParametersV1::default();
        let freeze = FrozenParliamentAttemptPolicyV1::freeze_v1;
        assert_eq!(
            freeze(&pipeline(), &lifecycle, None, 1_000, 3_600),
            Err(FrozenBallotPolicyErrorV1::MissingBindingPolicy)
        );
        // A binding pipeline names both juries.
        let without_confirmation: Vec<_> = pipeline()
            .into_iter()
            .filter(|body| *body != ParliamentBody::ConfirmationJury)
            .collect();
        assert_eq!(
            freeze(
                &without_confirmation,
                &lifecycle,
                Some(&ballot),
                1_000,
                3_600
            ),
            Err(FrozenBallotPolicyErrorV1::MissingBody {
                body: ParliamentBody::ConfirmationJury
            })
        );
        assert_eq!(
            freeze(
                &[
                    ParliamentBody::RulesCommittee,
                    ParliamentBody::ConfirmationJury
                ],
                &lifecycle,
                Some(&ballot),
                1_000,
                3_600
            ),
            Err(FrozenBallotPolicyErrorV1::MissingBody {
                body: ParliamentBody::PolicyJury
            })
        );
        // The pipeline is canonical: ordered, without repetition, and not empty.
        let mut reversed = pipeline();
        reversed.swap(0, 1);
        assert_eq!(
            freeze(&reversed, &lifecycle, Some(&ballot), 1_000, 3_600),
            Err(FrozenBallotPolicyErrorV1::RequiredBodyOrder { index: 1 })
        );
        assert_eq!(
            freeze(&[], &lifecycle, Some(&ballot), 1_000, 3_600),
            Err(FrozenBallotPolicyErrorV1::NoRequiredBodies)
        );
        // The NPoS cadence is copied and checked: 3..=65,536 blocks.
        assert!(freeze(&pipeline(), &lifecycle, Some(&ballot), 1_000, 3).is_ok());
        assert!(freeze(&pipeline(), &lifecycle, Some(&ballot), 1_000, 65_536).is_ok());
        for cadence in [0, 2, 65_537] {
            assert_eq!(
                freeze(&pipeline(), &lifecycle, Some(&ballot), 1_000, cadence),
                Err(FrozenBallotPolicyErrorV1::Sortition {
                    field: "pulse_cadence_blocks"
                })
            );
        }
        // A cadence the casting window cannot fill fails the capacity rule.
        assert!(matches!(
            freeze(&pipeline(), &lifecycle, Some(&ballot), 43_200, 3_600),
            Err(FrozenBallotPolicyErrorV1::Parameter(
                ParliamentBallotParameterErrorV1::InsufficientCapacity { .. }
            ))
        ));
        // Invalid committed parameters never freeze.
        let mut invalid = lifecycle.clone();
        invalid.lifecycle.questions_window_ms = 0;
        assert_eq!(
            freeze(&pipeline(), &invalid, Some(&ballot), 1_000, 3_600),
            Err(FrozenBallotPolicyErrorV1::Lifecycle {
                field: "questions_window_ms"
            })
        );
        let mut invalid = lifecycle;
        invalid.body_sizes.swap(2, 3);
        assert!(matches!(
            freeze(&pipeline(), &invalid, Some(&ballot), 1_000, 3_600),
            Err(FrozenBallotPolicyErrorV1::BodyTableRole { index: 2, .. })
        ));
        let mut weak = ballot;
        weak.stamp_difficulty_bits = 27;
        assert!(matches!(
            freeze(
                &pipeline(),
                &ParliamentLifecycleParametersV1::default(),
                Some(&weak),
                1_000,
                3_600
            ),
            Err(FrozenBallotPolicyErrorV1::Parameter(
                ParliamentBallotParameterErrorV1::OutOfRange {
                    field: "stamp_difficulty_bits",
                    ..
                }
            ))
        ));
    }

    #[test]
    fn both_ballot_policies_derive_from_the_snapshot_and_differ_only_by_role() {
        let attempt = attempt_policy();
        let [policy_jury, confirmation] = attempt
            .binding_ballot_policies(RiskTierV1::Constitutional)
            .expect("binding attempt");
        assert_eq!(policy_jury.body_role, ParliamentBody::PolicyJury);
        assert_eq!(confirmation.body_role, ParliamentBody::ConfirmationJury);
        let mut relabelled = confirmation.clone();
        relabelled.body_role = ParliamentBody::PolicyJury;
        assert_eq!(relabelled, policy_jury);
        for derived in [&policy_jury, &confirmation] {
            assert_eq!(derived.validate(), Ok(()));
            assert_eq!(derived.risk_tier, RiskTierV1::Constitutional);
            assert_eq!(derived.attempt_policy(), attempt);
            assert!(derived.is_derived_from(&attempt));
        }
        assert_eq!(policy_jury.body_target_seats(), Some(500));
        assert_eq!(confirmation.body_target_seats(), Some(1_000));
        // Any locked tier derives; another snapshot or an edited field does not.
        let mut other_tier = policy_jury.clone();
        other_tier.risk_tier = RiskTierV1::Standard;
        assert!(other_tier.is_derived_from(&attempt));
        let mut other_snapshot = attempt.clone();
        other_snapshot.lifecycle_policy.enactment_delay_ms += 1;
        assert!(!policy_jury.is_derived_from(&other_snapshot));
        let mut edited = policy_jury.clone();
        edited.binding.vote_notice_ms += 1;
        assert!(!edited.is_derived_from(&attempt));
        assert_eq!(
            attempt.ballot_policy(RiskTierV1::Standard, ParliamentBody::ReviewPanel),
            Err(FrozenBallotPolicyErrorV1::NotBindingBody {
                body: ParliamentBody::ReviewPanel
            })
        );
        assert_eq!(
            decode_enc::<FrozenBallotPolicyV1>(&enc(&policy_jury).expect("enc")),
            Ok(policy_jury.clone())
        );
        let json = norito::json::to_json(&policy_jury).expect("json");
        assert_eq!(
            norito::json::from_str::<FrozenBallotPolicyV1>(&json).expect("json"),
            policy_jury
        );
        assert_eq!(
            policy(),
            attempt
                .ballot_policy(RiskTierV1::Standard, ParliamentBody::PolicyJury)
                .expect("derived")
        );
    }

    #[test]
    fn fixed_constants_and_the_role_are_enforced() {
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
        changed.binding.profile_id = ProofProfileIdV1::new([0; 64]);
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
        changed.binding.stamp_difficulty_bits = 27;
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
        changed.binding.vote_notice_ms = 604_800_001;
        assert!(changed.validate().is_err());
        // A window the frozen commitment cannot fill is refused.
        let mut changed = base.clone();
        changed.binding.casting_window_ms = 60_000;
        assert!(matches!(
            changed.validate(),
            Err(FrozenBallotPolicyErrorV1::Parameter(
                ParliamentBallotParameterErrorV1::InsufficientCapacity { .. }
            ))
        ));
        let mut changed = base.clone();
        changed.binding.capacity_commitment.max_nonterminal_attempts = 0;
        assert!(changed.validate().is_err());
        // The reservations are derived from the budgets, never chosen independently.
        let mut changed = base.clone();
        changed
            .binding
            .capacity_commitment
            .reserved_ballot_slots_per_block = 3;
        assert_eq!(
            changed.validate(),
            Err(FrozenBallotPolicyErrorV1::Parameter(
                ParliamentBallotParameterErrorV1::ReservationMismatch
            ))
        );
        let mut changed = base;
        changed
            .binding
            .capacity_commitment
            .reserved_ballot_wire_bytes_per_block -= 1;
        assert_eq!(
            changed.validate(),
            Err(FrozenBallotPolicyErrorV1::Parameter(
                ParliamentBallotParameterErrorV1::ReservationMismatch
            ))
        );
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
        for body in PARLIAMENT_BODIES_V1 {
            assert_eq!(
                BodyDecisionModeV1::of(body) == BodyDecisionModeV1::AnonymousBallot,
                is_binding_body(body)
            );
        }
    }

    #[test]
    fn sortition_bounds_are_enforced_against_their_own_ceilings() {
        let base = policy().sortition_policy;
        assert_eq!(base.validate(), Ok(()));
        assert_eq!(
            FrozenSortitionPolicyV1::freeze_v1(&ParliamentSortitionParametersV1::default(), 3_600),
            Ok(base.clone())
        );
        let mutations: [Mutation<FrozenSortitionPolicyV1>; 8] = [
            ("pulse_delay_blocks", |s| s.pulse_delay_blocks = 0),
            ("pulse_cadence_blocks", |s| s.pulse_cadence_blocks = 2),
            ("max_cross_body_assignment_cap", |s| {
                s.max_cross_body_assignment_cap = 0;
            }),
            ("max_cross_body_assignment_cap", |s| {
                s.max_cross_body_assignment_cap = 11;
            }),
            ("max_sortition_retries", |s| s.max_sortition_retries = 17),
            ("max_randomness_redraws", |s| {
                s.max_randomness_redraws = MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1 + 1;
            }),
            ("max_governance_attempt_retries", |s| {
                s.max_governance_attempt_retries = 15;
            }),
            ("minimum_citizenship_bond", |s| {
                s.minimum_citizenship_bond = Quantity::zero();
            }),
        ];
        for (field, mutate) in mutations {
            let mut sortition = base.clone();
            mutate(&mut sortition);
            assert_eq!(
                sortition.validate(),
                Err(FrozenBallotPolicyErrorV1::Sortition { field })
            );
        }
        let mut retries = base;
        retries.max_sortition_retries = 0;
        retries.max_randomness_redraws = 0;
        assert_eq!(retries.validate(), Ok(()));
    }

    #[test]
    fn lifecycle_bounds_are_enforced_per_window() {
        let base = FrozenLifecyclePolicyV1::default();
        assert_eq!(base.validate(), Ok(()));
        for index in 0..8 {
            for (value, valid) in [
                (0, false),
                (1, true),
                (604_800_000, true),
                (604_800_001, false),
            ] {
                let mut fields = [
                    base.qualification_window_ms,
                    base.invitation_window_ms,
                    base.orientation_window_ms,
                    base.evidence_window_ms,
                    base.questions_window_ms,
                    base.responses_window_ms,
                    base.deliberation_window_ms,
                    base.public_finding_window_ms,
                ];
                fields[index] = value;
                let lifecycle = FrozenLifecyclePolicyV1 {
                    qualification_window_ms: fields[0],
                    invitation_window_ms: fields[1],
                    orientation_window_ms: fields[2],
                    evidence_window_ms: fields[3],
                    questions_window_ms: fields[4],
                    responses_window_ms: fields[5],
                    deliberation_window_ms: fields[6],
                    public_finding_window_ms: fields[7],
                    enactment_delay_ms: base.enactment_delay_ms,
                };
                let field = lifecycle.windows()[index].0;
                assert_eq!(
                    lifecycle.validate(),
                    if valid {
                        Ok(())
                    } else {
                        Err(FrozenBallotPolicyErrorV1::Lifecycle { field })
                    },
                    "{field} = {value}"
                );
            }
        }
        let mut lifecycle = base;
        lifecycle.enactment_delay_ms = 0;
        assert_eq!(lifecycle.validate(), Ok(()));
        lifecycle.enactment_delay_ms = 604_800_000;
        assert_eq!(lifecycle.validate(), Ok(()));
        lifecycle.enactment_delay_ms = 604_800_001;
        assert_eq!(
            lifecycle.validate(),
            Err(FrozenBallotPolicyErrorV1::Lifecycle {
                field: "enactment_delay_ms"
            })
        );
        for value in [
            BodyDecisionModeV1::PublicFinding,
            BodyDecisionModeV1::AnonymousBallot,
        ] {
            assert_eq!(
                decode_enc::<BodyDecisionModeV1>(&enc(&value).expect("enc")),
                Ok(value)
            );
        }
    }

    #[test]
    fn the_capacity_commitment_records_the_derived_reservations() {
        let parameters = ParliamentBallotParametersV1::default();
        let commitment = BallotCapacityCommitmentV1::from_parameters(&parameters, 1_000);
        assert_eq!(
            decode_enc::<BallotCapacityCommitmentV1>(&enc(&commitment).expect("enc")),
            Ok(commitment)
        );
        assert_eq!(policy().binding.capacity_commitment, commitment);
        let capacity = commitment.validate(86_400_000).expect("capacity");
        assert_eq!(
            (capacity.ballots_per_block, capacity.capacity),
            (2, 172_798)
        );
        // b0 is bounded by both budgets.
        for (work, bytes, slots) in [
            (1, 3_407_872, 1),
            (8, 425_984, 1),
            (8, 3_407_872, 8),
            (3, 1_277_951, 2),
        ] {
            let commitment = BallotCapacityCommitmentV1::from_parameters(
                &ParliamentBallotParametersV1 {
                    max_verification_reservations_per_block: work,
                    max_verifier_input_bytes_per_block: bytes,
                    ..parameters
                },
                1_000,
            );
            assert_eq!(commitment.reserved_ballot_slots_per_block, slots);
            assert_eq!(
                commitment.reserved_ballot_wire_bytes_per_block,
                u64::from(slots) * 263_168
            );
        }
        let binding = policy().binding;
        assert_eq!(
            FrozenBindingAttemptPolicyV1::freeze_v1(&parameters, 1_000),
            Ok(binding)
        );
        assert_eq!(
            decode_enc::<FrozenBindingAttemptPolicyV1>(&enc(&binding).expect("enc")),
            Ok(binding)
        );
    }
}
