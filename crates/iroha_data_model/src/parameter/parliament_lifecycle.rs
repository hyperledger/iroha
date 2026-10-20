//! Committed lifecycle, sortition and body-sizing policy of SORA Parliament attempts
//! (`gov.parliament_lifecycle`, custom parameter `parliament_lifecycle_v1`; governance-clock
//! lifecycle decision A of 2026-10-18).
//!
//! Parliament admission freezes this policy into the attempt's
//! [`FrozenParliamentAttemptPolicyV1`]: the lifecycle durations, the sortition parameters
//! (with the native pulse cadence copied from the genesis-immutable `NPoS` schedule) and the
//! seat target and alternate cap of every body of the protocol-defined pipeline. Later
//! generations and public-finding bodies use that snapshot; no parameter update changes an
//! existing deadline, request, roster policy or ballot-policy hash.
//!
//! There is one structural range for every network and no test-mode bypass: every window
//! accepts 1 ms and the enactment delay accepts 0 ms. Production values are the defaults;
//! activated binding configurations must additionally satisfy the owner-signed
//! qualification envelope.
//!
//! Missing or malformed committed state never falls back to node configuration or to these
//! defaults: [`ParliamentLifecycleParametersV1::from_custom_parameter`] refuses another
//! identity, an oversized, malformed, non-canonical or invalid payload.
//!
//! TODO: the Core integration requires this parameter in Parliament-enabled genesis,
//! validates committed updates with [`ParliamentLifecycleParametersV1::from_custom_parameter`],
//! freezes it at admission with [`FrozenParliamentAttemptPolicyV1::freeze_v1`], and deletes
//! the node-local Parliament lifecycle and sizing configuration with its
//! execution-policy-digest contributions, Parliament's use of `min_enactment_delay` and the
//! live `[gov].citizenship_bond_amount` in Parliament eligibility.
//!
//! [`FrozenParliamentAttemptPolicyV1`]:
//!     crate::governance::anonymous_ballot::FrozenParliamentAttemptPolicyV1
//! [`FrozenParliamentAttemptPolicyV1::freeze_v1`]:
//!     crate::governance::anonymous_ballot::FrozenParliamentAttemptPolicyV1::freeze_v1

use iroha_primitives::{json::Json, numeric::Quantity};

use super::{CustomParameter, CustomParameterId};
use crate::governance::{
    anonymous_ballot::{FrozenBallotPolicyErrorV1, FrozenLifecyclePolicyV1, check_body_size},
    types::{MAX_PARLIAMENT_SORTITION_RETRIES_V1, PARLIAMENT_BODIES_V1, ParliamentBody},
};

/// Hard protocol ceiling of the fresh-randomness redraws of one proposal: a cumulative,
/// proposal-wide ceiling that successor attempts inherit and never reset or increase.
pub const MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1: u32 = 16;

/// Most seats one citizen may hold across the bodies of one attempt: one per body of the ten
/// canonical roles.
pub const MAX_PARLIAMENT_CROSS_BODY_ASSIGNMENT_CAP_V1: u32 = 10;

/// Fewest target seats of a public-finding body; a binding jury needs
/// [`MIN_SEALED_SEATS_V1`](crate::governance::anonymous_ballot::MIN_SEALED_SEATS_V1).
pub const MIN_PUBLIC_BODY_TARGET_SEATS_V1: u16 = 1;

/// Most alternates drawn behind the primaries of one body draw.
pub const MAX_PARLIAMENT_BODY_ALTERNATES_V1: u16 = 1_000;

/// Why a committed `gov.parliament_lifecycle` parameter cannot be read or written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParliamentLifecycleParameterErrorV1 {
    /// The decoded value violates a structural range or the body table.
    #[error(transparent)]
    Invalid(#[from] FrozenBallotPolicyErrorV1),
    /// The custom parameter has another identity, is oversized or malformed, or its payload
    /// is not the canonical JSON of its value.
    #[error("invalid Parliament lifecycle parameter: {0}")]
    CustomParameter(&'static str),
}

/// Check the five committed sortition fields against their structural ranges.
///
/// The committed [`ParliamentSortitionParametersV1`] and the frozen
/// [`FrozenSortitionPolicyV1`](crate::governance::anonymous_ballot::FrozenSortitionPolicyV1)
/// share this one check.
///
/// # Errors
/// [`FrozenBallotPolicyErrorV1::Sortition`] naming the first offending field.
pub(crate) fn check_sortition_fields(
    pulse_delay_blocks: u64,
    max_cross_body_assignment_cap: u32,
    max_sortition_retries: u32,
    max_randomness_redraws: u32,
    minimum_citizenship_bond: &Quantity,
) -> Result<(), FrozenBallotPolicyErrorV1> {
    let field = if !(ParliamentSortitionParametersV1::MIN_PULSE_DELAY_BLOCKS
        ..=ParliamentSortitionParametersV1::MAX_PULSE_DELAY_BLOCKS)
        .contains(&pulse_delay_blocks)
    {
        "pulse_delay_blocks"
    } else if !(1..=MAX_PARLIAMENT_CROSS_BODY_ASSIGNMENT_CAP_V1)
        .contains(&max_cross_body_assignment_cap)
    {
        "max_cross_body_assignment_cap"
    } else if max_sortition_retries > MAX_PARLIAMENT_SORTITION_RETRIES_V1 {
        "max_sortition_retries"
    } else if max_randomness_redraws > MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1 {
        "max_randomness_redraws"
    } else if !is_integral_bond(minimum_citizenship_bond) {
        "minimum_citizenship_bond"
    } else {
        return Ok(());
    };
    Err(FrozenBallotPolicyErrorV1::Sortition { field })
}

/// Whether `bond` is a whole number of asset atoms in `1..=u128::MAX`: scale zero (a
/// canonical quantity has no trailing fractional zeros, so scale zero is exactly
/// integrality), nonzero, and at most `u128::MAX`.
fn is_integral_bond(bond: &Quantity) -> bool {
    bond.scale() == 0 && !bond.is_zero() && *bond <= Quantity::from(u128::MAX)
}

/// The committed sortition parameters of Parliament attempts
/// (`gov.parliament_lifecycle.sortition`).
///
/// Admission freezes them, with the native pulse cadence and the fixed governance-attempt
/// retry ceiling, into the attempt's frozen sortition policy.
///
/// `minimum_citizenship_bond` is a [`Quantity`]: the data model's nominal non-negative asset
/// amount, the type of every ledger asset balance and of a citizen record's bond, so Core
/// compares the frozen threshold with bonds directly and exactly. It must be a whole number
/// of asset atoms in `1..=u128::MAX`; a fraction, zero or a larger value is refused.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    norito::Encode,
    norito::Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito_schema(
    name = "iroha_data_model::parameter::parliament_lifecycle::ParliamentSortitionParametersV1"
)]
#[norito(deny_unknown_fields)]
pub struct ParliamentSortitionParametersV1 {
    /// Minimum lead `d` in blocks between a sortition request and its native pulse slot.
    pub pulse_delay_blocks: u64,
    /// Largest cross-body assignment cap the deterministic smallest-feasible allocation may
    /// choose: outstanding primary and alternate invitations and sealed memberships of one
    /// citizen across distinct bodies of the attempt.
    pub max_cross_body_assignment_cap: u32,
    /// Ceiling on the `NoRoster` sortition retries of one body after sequence zero.
    pub max_sortition_retries: u32,
    /// Cumulative proposal-wide ceiling on fresh-randomness redraws.
    pub max_randomness_redraws: u32,
    /// Smallest citizenship bond, in whole atoms of the bond asset, that makes a citizen
    /// eligible for sortition.
    pub minimum_citizenship_bond: Quantity,
}

impl Default for ParliamentSortitionParametersV1 {
    fn default() -> Self {
        Self {
            pulse_delay_blocks: 4,
            max_cross_body_assignment_cap: MAX_PARLIAMENT_CROSS_BODY_ASSIGNMENT_CAP_V1,
            max_sortition_retries: MAX_PARLIAMENT_SORTITION_RETRIES_V1,
            max_randomness_redraws: MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1,
            minimum_citizenship_bond: Quantity::from(150_u32),
        }
    }
}

impl ParliamentSortitionParametersV1 {
    /// Smallest `pulse_delay_blocks`.
    pub const MIN_PULSE_DELAY_BLOCKS: u64 = 1;
    /// Largest `pulse_delay_blocks`.
    pub const MAX_PULSE_DELAY_BLOCKS: u64 = 65_536;

    /// Check every field against its structural range: `pulse_delay_blocks` in
    /// `1..=65,536`, `max_cross_body_assignment_cap` in `1..=10`, `max_sortition_retries` at
    /// most [`MAX_PARLIAMENT_SORTITION_RETRIES_V1`], `max_randomness_redraws` at most
    /// [`MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1`], and a whole-atom bond in `1..=u128::MAX`.
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
        )
    }
}

/// The committed seat target and alternate cap of one body
/// (`gov.parliament_lifecycle.body_sizes`).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::Encode,
    norito::Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::parameter::parliament_lifecycle::ParliamentBodySizingV1")]
#[norito(deny_unknown_fields)]
pub struct ParliamentBodySizingV1 {
    /// The body's role.
    pub body: ParliamentBody,
    /// Seat target of each draw: a cap, not a minimum. `1..=1000` for a public-finding body,
    /// `3..=1000` for a binding jury.
    pub target_seats: u16,
    /// Alternates drawn behind the primaries of each draw, `0..=1000`.
    pub alternate_cap: u16,
}

/// The default seat targets, in [`PARLIAMENT_BODIES_V1`] order; every body draws 21
/// alternates.
const DEFAULT_TARGET_SEATS_V1: [u16; 10] = [50, 150, 12, 150, 150, 50, 50, 50, 500, 1_000];

/// Default alternates of every body.
const DEFAULT_ALTERNATE_CAP_V1: u16 = 21;

/// The committed `gov.parliament_lifecycle` policy, stored as the World custom parameter
/// `parliament_lifecycle_v1` with a canonical key-ordered JSON payload.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::Encode,
    norito::Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito_schema(
    name = "iroha_data_model::parameter::parliament_lifecycle::ParliamentLifecycleParametersV1"
)]
#[norito(deny_unknown_fields)]
pub struct ParliamentLifecycleParametersV1 {
    /// Lifecycle durations frozen by every attempt.
    pub lifecycle: FrozenLifecyclePolicyV1,
    /// Sortition parameters frozen by every attempt.
    pub sortition: ParliamentSortitionParametersV1,
    /// Seat target and alternate cap of each body: exactly the ten roles, in
    /// [`PARLIAMENT_BODIES_V1`] order.
    pub body_sizes: Vec<ParliamentBodySizingV1>,
}

impl Default for ParliamentLifecycleParametersV1 {
    fn default() -> Self {
        Self {
            lifecycle: FrozenLifecyclePolicyV1::default(),
            sortition: ParliamentSortitionParametersV1::default(),
            body_sizes: PARLIAMENT_BODIES_V1
                .into_iter()
                .zip(DEFAULT_TARGET_SEATS_V1)
                .map(|(body, target_seats)| ParliamentBodySizingV1 {
                    body,
                    target_seats,
                    alternate_cap: DEFAULT_ALTERNATE_CAP_V1,
                })
                .collect(),
        }
    }
}

impl ParliamentLifecycleParametersV1 {
    /// Configuration and documentation name of the parameter.
    pub const CONFIGURATION_NAME: &'static str = "gov.parliament_lifecycle";

    /// Largest accepted JSON payload; the largest valid payload is well below it.
    pub const MAX_PAYLOAD_BYTES: usize = 4_096;

    /// The sole canonical custom parameter identity.
    #[must_use]
    pub fn parameter_id() -> &'static CustomParameterId {
        static ID: std::sync::OnceLock<CustomParameterId> = std::sync::OnceLock::new();
        ID.get_or_init(|| {
            "parliament_lifecycle_v1"
                .parse()
                .expect("static parameter identity")
        })
    }

    /// Check every structural range and the body table: the lifecycle durations, the
    /// sortition parameters, and exactly the ten roles in [`PARLIAMENT_BODIES_V1`] order with
    /// their seat-target and alternate ranges (a missing, duplicate, reordered or unknown
    /// role is refused).
    ///
    /// # Errors
    /// The first violated rule as a [`FrozenBallotPolicyErrorV1`].
    pub fn validate(&self) -> Result<(), FrozenBallotPolicyErrorV1> {
        self.lifecycle.validate()?;
        self.sortition.validate()?;
        if self.body_sizes.len() != PARLIAMENT_BODIES_V1.len() {
            return Err(FrozenBallotPolicyErrorV1::BodyTableLength {
                actual: self.body_sizes.len(),
            });
        }
        for (index, (sizing, expected)) in
            self.body_sizes.iter().zip(PARLIAMENT_BODIES_V1).enumerate()
        {
            if sizing.body != expected {
                return Err(FrozenBallotPolicyErrorV1::BodyTableRole {
                    index,
                    expected,
                    found: sizing.body,
                });
            }
            check_body_size(sizing.body, sizing.target_seats, sizing.alternate_cap)?;
        }
        Ok(())
    }

    /// The sizing of `body`, if the table names it (a valid table names every role).
    #[must_use]
    pub fn body_sizing(&self, body: ParliamentBody) -> Option<&ParliamentBodySizingV1> {
        self.body_sizes.iter().find(|sizing| sizing.body == body)
    }

    /// Decode and validate the exact committed parameter, without substituting defaults on
    /// failure.
    ///
    /// # Errors
    /// [`ParliamentLifecycleParameterErrorV1::CustomParameter`] for another identity, more
    /// than [`Self::MAX_PAYLOAD_BYTES`] of JSON, a malformed payload (including a missing or
    /// unknown field or role) or a payload that is not the canonical JSON of its value, and
    /// [`ParliamentLifecycleParameterErrorV1::Invalid`] for a value that fails
    /// [`Self::validate`].
    pub fn from_custom_parameter(
        parameter: &CustomParameter,
    ) -> Result<Self, ParliamentLifecycleParameterErrorV1> {
        if parameter.id() != Self::parameter_id() {
            return Err(ParliamentLifecycleParameterErrorV1::CustomParameter(
                "another parameter identity",
            ));
        }
        let payload = parameter.payload();
        if payload.get().len() > Self::MAX_PAYLOAD_BYTES {
            return Err(ParliamentLifecycleParameterErrorV1::CustomParameter(
                "payload exceeds 4096 bytes",
            ));
        }
        let value: Self = norito::json::from_str(payload.get()).map_err(|_| {
            ParliamentLifecycleParameterErrorV1::CustomParameter("malformed payload")
        })?;
        if Json::try_new(&value).ok().as_ref() != Some(payload) {
            return Err(ParliamentLifecycleParameterErrorV1::CustomParameter(
                "payload is not the canonical JSON of its value",
            ));
        }
        value.validate()?;
        Ok(value)
    }

    /// The committed custom parameter of a valid value, with its canonical key-ordered JSON
    /// payload.
    ///
    /// # Errors
    /// [`ParliamentLifecycleParameterErrorV1::Invalid`] for a value that fails
    /// [`Self::validate`], and [`ParliamentLifecycleParameterErrorV1::CustomParameter`] if the
    /// canonical payload cannot be produced or exceeds [`Self::MAX_PAYLOAD_BYTES`].
    pub fn to_custom_parameter(
        &self,
    ) -> Result<CustomParameter, ParliamentLifecycleParameterErrorV1> {
        self.validate()?;
        let payload = Json::try_new(self).map_err(|_| {
            ParliamentLifecycleParameterErrorV1::CustomParameter("payload cannot be serialized")
        })?;
        if payload.get().len() > Self::MAX_PAYLOAD_BYTES {
            return Err(ParliamentLifecycleParameterErrorV1::CustomParameter(
                "payload exceeds 4096 bytes",
            ));
        }
        Ok(CustomParameter::new(Self::parameter_id().clone(), payload))
    }
}

#[cfg(test)]
mod tests {
    use norito::codec::{Decode, Encode};

    use super::*;
    use crate::governance::anonymous_ballot::MIN_SEALED_SEATS_V1;

    /// A change of the committed parameters, for table-driven refusal tests.
    type Change = fn(&mut ParliamentLifecycleParametersV1);

    /// A change of the committed sortition parameters.
    type SortitionChange = fn(&mut ParliamentSortitionParametersV1);

    #[test]
    fn the_defaults_are_the_decided_table_and_validate() {
        let defaults = ParliamentLifecycleParametersV1::default();
        assert_eq!(defaults.validate(), Ok(()));
        let lifecycle = defaults.lifecycle;
        assert_eq!(
            [
                lifecycle.qualification_window_ms,
                lifecycle.invitation_window_ms,
                lifecycle.orientation_window_ms,
                lifecycle.evidence_window_ms,
                lifecycle.questions_window_ms,
                lifecycle.responses_window_ms,
                lifecycle.deliberation_window_ms,
                lifecycle.public_finding_window_ms,
                lifecycle.enactment_delay_ms,
            ],
            [
                3_600_000, 3_600_000, 3_600_000, 86_400_000, 3_600_000, 3_600_000, 3_600_000,
                3_600_000, 20_000
            ]
        );
        let sortition = &defaults.sortition;
        assert_eq!(
            (
                sortition.pulse_delay_blocks,
                sortition.max_cross_body_assignment_cap,
                sortition.max_sortition_retries,
                sortition.max_randomness_redraws,
            ),
            (4, 10, 16, 16)
        );
        assert_eq!(sortition.minimum_citizenship_bond, Quantity::from(150_u32));
        let table: Vec<_> = defaults
            .body_sizes
            .iter()
            .map(|sizing| (sizing.body, sizing.target_seats, sizing.alternate_cap))
            .collect();
        assert_eq!(
            table,
            [
                (ParliamentBody::RulesCommittee, 50, 21),
                (ParliamentBody::AgendaCouncil, 150, 21),
                (ParliamentBody::InterestPanel, 12, 21),
                (ParliamentBody::ReviewPanel, 150, 21),
                (ParliamentBody::CoordinationCouncil, 150, 21),
                (ParliamentBody::MpcCommittee, 50, 21),
                (ParliamentBody::FmaCommittee, 50, 21),
                (ParliamentBody::OversightCommittee, 50, 21),
                (ParliamentBody::PolicyJury, 500, 21),
                (ParliamentBody::ConfirmationJury, 1_000, 21),
            ]
        );
        assert_eq!(
            defaults
                .body_sizing(ParliamentBody::InterestPanel)
                .map(|sizing| sizing.target_seats),
            Some(12)
        );
        assert_eq!(
            ParliamentLifecycleParametersV1::CONFIGURATION_NAME,
            "gov.parliament_lifecycle"
        );
        assert_eq!(
            usize::try_from(MAX_PARLIAMENT_CROSS_BODY_ASSIGNMENT_CAP_V1).expect("small"),
            PARLIAMENT_BODIES_V1.len()
        );
        // A separately named ceiling for each concept, all sixteen in V1.
        assert_eq!(MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1, 16);
        assert_eq!(MAX_PARLIAMENT_SORTITION_RETRIES_V1, 16);
    }

    #[test]
    fn the_sortition_ranges_are_inclusive_and_checked_per_concept() {
        let valid = ParliamentSortitionParametersV1::default();
        let with = |change: SortitionChange| {
            let mut parameters = valid.clone();
            change(&mut parameters);
            parameters.validate()
        };
        let accepted: [SortitionChange; 10] = [
            |p| p.pulse_delay_blocks = 1,
            |p| p.pulse_delay_blocks = 65_536,
            |p| p.max_cross_body_assignment_cap = 1,
            |p| p.max_cross_body_assignment_cap = 10,
            |p| p.max_sortition_retries = 0,
            |p| p.max_randomness_redraws = 0,
            |p| p.minimum_citizenship_bond = Quantity::from(1_u32),
            |p| p.minimum_citizenship_bond = Quantity::from(u128::MAX),
            |p| p.minimum_citizenship_bond = "150.0".parse().expect("canonicalized"),
            |p| p.max_sortition_retries = 16,
        ];
        for change in accepted {
            assert_eq!(with(change), Ok(()));
        }
        let refused: [(&str, SortitionChange); 9] = [
            ("pulse_delay_blocks", |p| p.pulse_delay_blocks = 0),
            ("pulse_delay_blocks", |p| p.pulse_delay_blocks = 65_537),
            ("max_cross_body_assignment_cap", |p| {
                p.max_cross_body_assignment_cap = 0;
            }),
            ("max_cross_body_assignment_cap", |p| {
                p.max_cross_body_assignment_cap = 11;
            }),
            ("max_sortition_retries", |p| p.max_sortition_retries = 17),
            ("max_randomness_redraws", |p| p.max_randomness_redraws = 17),
            ("minimum_citizenship_bond", |p| {
                p.minimum_citizenship_bond = Quantity::zero();
            }),
            ("minimum_citizenship_bond", |p| {
                p.minimum_citizenship_bond = "150.5".parse().expect("decimal");
            }),
            ("minimum_citizenship_bond", |p| {
                p.minimum_citizenship_bond = Quantity::from(u128::MAX)
                    .try_add(&Quantity::one())
                    .expect("within the 512-bit domain");
            }),
        ];
        for (field, change) in refused {
            assert_eq!(
                with(change),
                Err(FrozenBallotPolicyErrorV1::Sortition { field }),
                "{field}"
            );
        }
    }

    #[test]
    fn the_body_table_needs_exactly_the_ten_roles_in_order() {
        let base = ParliamentLifecycleParametersV1::default();
        let with = |change: Change| {
            let mut parameters = base.clone();
            change(&mut parameters);
            parameters.validate()
        };
        // Missing and duplicate roles change the length.
        assert_eq!(
            with(|p| {
                p.body_sizes.pop();
            }),
            Err(FrozenBallotPolicyErrorV1::BodyTableLength { actual: 9 })
        );
        assert_eq!(
            with(|p| {
                let first = p.body_sizes[0];
                p.body_sizes.push(first);
            }),
            Err(FrozenBallotPolicyErrorV1::BodyTableLength { actual: 11 })
        );
        assert_eq!(
            with(|p| p.body_sizes.clear()),
            Err(FrozenBallotPolicyErrorV1::BodyTableLength { actual: 0 })
        );
        // A duplicate in place of another role, and a reordering.
        assert_eq!(
            with(|p| p.body_sizes[1] = p.body_sizes[0]),
            Err(FrozenBallotPolicyErrorV1::BodyTableRole {
                index: 1,
                expected: ParliamentBody::AgendaCouncil,
                found: ParliamentBody::RulesCommittee,
            })
        );
        assert_eq!(
            with(|p| p.body_sizes.swap(8, 9)),
            Err(FrozenBallotPolicyErrorV1::BodyTableRole {
                index: 8,
                expected: ParliamentBody::PolicyJury,
                found: ParliamentBody::ConfirmationJury,
            })
        );
        // Seat targets: 1..=1000 for public bodies, 3..=1000 for binding juries.
        let accepted: [Change; 5] = [
            |p| p.body_sizes[0].target_seats = 1,
            |p| p.body_sizes[0].target_seats = 1_000,
            |p| p.body_sizes[8].target_seats = 3,
            |p| p.body_sizes[9].alternate_cap = 0,
            |p| p.body_sizes[9].alternate_cap = 1_000,
        ];
        for change in accepted {
            assert_eq!(with(change), Ok(()));
        }
        let refused: [(FrozenBallotPolicyErrorV1, Change); 6] = [
            (
                FrozenBallotPolicyErrorV1::TargetSeats {
                    body: ParliamentBody::RulesCommittee,
                },
                |p| p.body_sizes[0].target_seats = 0,
            ),
            (
                FrozenBallotPolicyErrorV1::TargetSeats {
                    body: ParliamentBody::RulesCommittee,
                },
                |p| p.body_sizes[0].target_seats = 1_001,
            ),
            (
                FrozenBallotPolicyErrorV1::TargetSeats {
                    body: ParliamentBody::PolicyJury,
                },
                |p| p.body_sizes[8].target_seats = MIN_SEALED_SEATS_V1 - 1,
            ),
            (
                FrozenBallotPolicyErrorV1::TargetSeats {
                    body: ParliamentBody::ConfirmationJury,
                },
                |p| p.body_sizes[9].target_seats = 1_001,
            ),
            (
                FrozenBallotPolicyErrorV1::AlternateCap {
                    body: ParliamentBody::MpcCommittee,
                },
                |p| p.body_sizes[5].alternate_cap = 1_001,
            ),
            (
                FrozenBallotPolicyErrorV1::Lifecycle {
                    field: "evidence_window_ms",
                },
                |p| p.lifecycle.evidence_window_ms = 0,
            ),
        ];
        for (expected, change) in refused {
            assert_eq!(with(change), Err(expected));
        }
        assert_eq!(
            with(|p| p.sortition.pulse_delay_blocks = 0),
            Err(FrozenBallotPolicyErrorV1::Sortition {
                field: "pulse_delay_blocks"
            })
        );
    }

    #[test]
    fn the_custom_parameter_round_trips_canonically() {
        let parameters = ParliamentLifecycleParametersV1::default();
        let parameter = parameters.to_custom_parameter().expect("valid");
        assert_eq!(parameter.id().to_string(), "parliament_lifecycle_v1");
        assert_eq!(parameter.payload(), &Json::new(&parameters));
        assert_eq!(
            ParliamentLifecycleParametersV1::from_custom_parameter(&parameter),
            Ok(parameters.clone())
        );
        // The payload is canonical key-ordered JSON and the bond a canonical decimal string.
        let payload = parameter.payload().get();
        assert!(
            payload.starts_with(
                r#"{"body_sizes":[{"alternate_cap":21,"body":"rules-committee","target_seats":50}"#
            ),
            "{payload}"
        );
        assert!(
            payload.contains(r#""minimum_citizenship_bond":"150""#),
            "{payload}"
        );
        assert_eq!(
            ParliamentLifecycleParametersV1::decode(&mut parameters.encode().as_slice())
                .expect("decode"),
            parameters
        );
        // The largest valid payload fits the size bound.
        let mut largest = parameters.clone();
        largest.lifecycle = FrozenLifecyclePolicyV1 {
            qualification_window_ms: FrozenLifecyclePolicyV1::MAX_DURATION_MS,
            invitation_window_ms: FrozenLifecyclePolicyV1::MAX_DURATION_MS,
            orientation_window_ms: FrozenLifecyclePolicyV1::MAX_DURATION_MS,
            evidence_window_ms: FrozenLifecyclePolicyV1::MAX_DURATION_MS,
            questions_window_ms: FrozenLifecyclePolicyV1::MAX_DURATION_MS,
            responses_window_ms: FrozenLifecyclePolicyV1::MAX_DURATION_MS,
            deliberation_window_ms: FrozenLifecyclePolicyV1::MAX_DURATION_MS,
            public_finding_window_ms: FrozenLifecyclePolicyV1::MAX_DURATION_MS,
            enactment_delay_ms: FrozenLifecyclePolicyV1::MAX_DURATION_MS,
        };
        largest.sortition.pulse_delay_blocks = 65_536;
        largest.sortition.minimum_citizenship_bond = Quantity::from(u128::MAX);
        for sizing in &mut largest.body_sizes {
            sizing.target_seats = 1_000;
            sizing.alternate_cap = 1_000;
        }
        let largest_parameter = largest.to_custom_parameter().expect("valid");
        assert!(
            largest_parameter.payload().get().len()
                <= ParliamentLifecycleParametersV1::MAX_PAYLOAD_BYTES / 2
        );
        assert_eq!(
            ParliamentLifecycleParametersV1::from_custom_parameter(&largest_parameter),
            Ok(largest)
        );
    }

    #[test]
    fn foreign_malformed_noncanonical_and_invalid_payloads_are_refused() {
        let parameter = ParliamentLifecycleParametersV1::default()
            .to_custom_parameter()
            .expect("valid");
        let custom = |text: &str| {
            CustomParameter::new(
                ParliamentLifecycleParametersV1::parameter_id().clone(),
                text.parse::<Json>().expect("canonical JSON text"),
            )
        };
        let refused = |parameter: &CustomParameter| {
            ParliamentLifecycleParametersV1::from_custom_parameter(parameter)
        };
        let foreign =
            CustomParameter::new("other".parse().expect("name"), parameter.payload().clone());
        assert_eq!(
            refused(&foreign),
            Err(ParliamentLifecycleParameterErrorV1::CustomParameter(
                "another parameter identity"
            ))
        );
        // A missing field never selects a default.
        assert_eq!(
            refused(&custom("{}")),
            Err(ParliamentLifecycleParameterErrorV1::CustomParameter(
                "malformed payload"
            ))
        );
        let text = parameter.payload().get();
        // An unknown field and an unknown role.
        let unknown_field = text.replacen(r#"{"body_sizes""#, r#"{"a":0,"body_sizes""#, 1);
        assert_eq!(
            refused(&custom(&unknown_field)),
            Err(ParliamentLifecycleParameterErrorV1::CustomParameter(
                "malformed payload"
            ))
        );
        let unknown_role = text.replacen("rules-committee", "rules-council", 1);
        assert_eq!(
            refused(&custom(&unknown_role)),
            Err(ParliamentLifecycleParameterErrorV1::CustomParameter(
                "malformed payload"
            ))
        );
        // A bond spelled as a number rather than its canonical decimal string.
        let numeric_bond = text.replacen(
            r#""minimum_citizenship_bond":"150""#,
            r#""minimum_citizenship_bond":150"#,
            1,
        );
        assert!(refused(&custom(&numeric_bond)).is_err());
        // A valid shape with an invalid value.
        let invalid = text.replacen(r#""pulse_delay_blocks":4"#, r#""pulse_delay_blocks":0"#, 1);
        assert_eq!(
            refused(&custom(&invalid)),
            Err(ParliamentLifecycleParameterErrorV1::Invalid(
                FrozenBallotPolicyErrorV1::Sortition {
                    field: "pulse_delay_blocks"
                }
            ))
        );
        let mut reordered = ParliamentLifecycleParametersV1::default();
        reordered.body_sizes.swap(0, 1);
        assert_eq!(
            reordered.to_custom_parameter(),
            Err(ParliamentLifecycleParameterErrorV1::Invalid(
                FrozenBallotPolicyErrorV1::BodyTableRole {
                    index: 0,
                    expected: ParliamentBody::RulesCommittee,
                    found: ParliamentBody::AgendaCouncil,
                }
            ))
        );
        let oversized = format!(
            r#"{{"padding":"{}"}}"#,
            "x".repeat(ParliamentLifecycleParametersV1::MAX_PAYLOAD_BYTES)
        );
        assert_eq!(
            refused(&custom(&oversized)),
            Err(ParliamentLifecycleParameterErrorV1::CustomParameter(
                "payload exceeds 4096 bytes"
            ))
        );
    }
}
