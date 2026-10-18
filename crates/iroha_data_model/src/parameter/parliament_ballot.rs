//! Committed budgets of the Parliament anonymous ballot (`gov.parliament_ballot`,
//! integration decision 5 of `specs/parliament_private_ballot_design.md`).
//!
//! These are engineering defaults behind the closed launch gate
//! (`governance::anonymous_ballot::PARLIAMENT_BALLOT_QUALIFICATION_V1`); production values
//! must also lie within the owner-signed qualified envelope.
//!
//! The verification unit is one indivisible cold-verification reservation per
//! verification invocation, with the actual copied input bytes charged separately; it is
//! not milliseconds, gas or an operation count. Cache hits are charged identically and an
//! admitted reservation is never refunded.
//!
//! The capacity rule includes the honest proposer's ballot reservations, derived from the
//! budgets (lifecycle decision K4): `b0 = min(B_work, floor(B_bytes / 425,984))` anonymous
//! inputs and `b0 × 263,168` complete entrypoint wire bytes per block. Registration and SCCP
//! reservations are separate.
//!
//! TODO: the Core integration reads this custom parameter, validates updates against the
//! committed block cadence and every outstanding capacity commitment (an update may not
//! reduce `K` below the reservations held, and an increase of `K` revalidates outstanding
//! windows), and wires the reservations into the effective input-count, input-wire, output
//! and complete executed-wire limits (`block.max_transactions`, the FASTPQ input capacity and
//! the block-wire limit) with cross-limit validation that they fit.

use iroha_primitives::json::Json;

use super::{CustomParameter, CustomParameterId};
use crate::governance::anonymous_ballot::{
    ANONYMOUS_BALLOT_ENTRYPOINT_WIRE_MAX_BYTES_V1, BallotCapacityCommitmentV1,
};

/// Largest canonical ballot envelope `E_max` plus authenticated context `C_max`: the
/// verifier-input bytes one verification call can be charged.
const VERIFIER_INPUT_BYTES_PER_CALL: u64 = 425_984;

/// `E_wire`: the reserved wire bytes of one complete canonical anonymous-ballot entrypoint,
/// per-input framing included.
const ENTRYPOINT_WIRE_BYTES: u64 = ANONYMOUS_BALLOT_ENTRYPOINT_WIRE_MAX_BYTES_V1 as u64;

/// Ballots each attempt must be able to cast: the largest sealed list.
const BALLOTS_PER_ATTEMPT: u128 = 1_000;

/// Why committed ballot parameters are invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParliamentBallotParameterErrorV1 {
    /// A field is outside its structural range.
    #[error("{field} = {value} is outside {min}..={max}")]
    OutOfRange {
        /// The field.
        field: &'static str,
        /// Value supplied.
        value: u64,
        /// Smallest permitted value.
        min: u64,
        /// Largest permitted value.
        max: u64,
    },
    /// The block cadence is zero.
    #[error("the block cadence must be positive")]
    ZeroCadence,
    /// The casting window is shorter than one block cadence, so it has no successor
    /// opportunity.
    #[error(
        "a casting window of {casting_window_ms} ms is shorter than the {block_cadence_ms} ms block cadence"
    )]
    WindowShorterThanCadence {
        /// Casting window.
        casting_window_ms: u64,
        /// Block cadence.
        block_cadence_ms: u64,
    },
    /// Fewer ballots fit the casting window than 1,000 for each of `K` attempts.
    #[error("the casting window packs {capacity} ballots but {required} are required")]
    InsufficientCapacity {
        /// Ballots that fit: opportunities × per-block ballots.
        capacity: u128,
        /// Ballots required: `1,000 × K`.
        required: u128,
    },
    /// A capacity commitment's reserved ballot slots or wire bytes are not the values
    /// derived from its budgets.
    #[error("the reserved ballot capacity is not the value derived from the budgets")]
    ReservationMismatch,
    /// The custom parameter has another identity, is oversized or malformed, or its payload is
    /// not the canonical JSON of its value.
    #[error("invalid Parliament ballot parameter: {0}")]
    CustomParameter(&'static str),
}

/// The ballot-packing figures of the capacity rule for one casting window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BallotCastingCapacityV1 {
    /// `b = min(B_work, floor(B_bytes / 425,984), reserved_ballot_slots_per_block,
    /// floor(reserved_ballot_wire_bytes_per_block / 263,168))`: ballots per block.
    pub ballots_per_block: u64,
    /// `floor(casting_window_ms / cadence_ms) − 1`: blocks after the casting clock.
    pub opportunities: u64,
    /// `opportunities × b`.
    pub capacity: u128,
    /// `1,000 × K`.
    pub required: u128,
}

/// The reserved anonymous-ballot input slots per block derived from the budgets:
/// `b0 = min(B_work, floor(B_bytes / 425,984))`.
#[must_use]
pub fn reserved_ballot_slots_v1(
    max_verification_reservations_per_block: u32,
    max_verifier_input_bytes_per_block: u64,
) -> u32 {
    u32::try_from(max_verifier_input_bytes_per_block / VERIFIER_INPUT_BYTES_PER_CALL)
        .map_or(max_verification_reservations_per_block, |calls| {
            calls.min(max_verification_reservations_per_block)
        })
}

/// The reserved complete anonymous-entrypoint wire bytes per block for `slots` reserved
/// inputs: `slots × 263,168`.
#[must_use]
pub fn reserved_ballot_wire_bytes_v1(slots: u32) -> u64 {
    u64::from(slots) * ENTRYPOINT_WIRE_BYTES
}

/// The capacity rule of integration decision 5 and lifecycle decision K4 with checked wide
/// arithmetic, under the admission `commitment`:
///
/// ```text
/// b             = min(B_work,
///                     floor(B_bytes / 425,984),
///                     reserved_ballot_slots_per_block,
///                     floor(reserved_ballot_wire_bytes_per_block / 263,168))
/// opportunities = floor(casting_window_ms / cadence_ms) - 1
/// require b >= 1 and opportunities * b >= 1,000 * K
/// ```
///
/// This is a necessary packing condition, not an inclusion guarantee, and not complete
/// parameter validation: the reservations must also fit the effective block limits, which
/// Core checks.
///
/// # Errors
/// [`ParliamentBallotParameterErrorV1`] for a zero cadence, a window shorter than one
/// cadence, a zero per-block ballot budget or insufficient capacity.
pub fn parliament_ballot_capacity_v1(
    casting_window_ms: u64,
    commitment: &BallotCapacityCommitmentV1,
) -> Result<BallotCastingCapacityV1, ParliamentBallotParameterErrorV1> {
    let block_cadence_ms = commitment.block_cadence_ms;
    if block_cadence_ms == 0 {
        return Err(ParliamentBallotParameterErrorV1::ZeroCadence);
    }
    let opportunities = (casting_window_ms / block_cadence_ms)
        .checked_sub(1)
        .ok_or(ParliamentBallotParameterErrorV1::WindowShorterThanCadence {
            casting_window_ms,
            block_cadence_ms,
        })?;
    let ballots_per_block = u64::from(commitment.max_verification_reservations_per_block)
        .min(commitment.max_verifier_input_bytes_per_block / VERIFIER_INPUT_BYTES_PER_CALL)
        .min(u64::from(commitment.reserved_ballot_slots_per_block))
        .min(commitment.reserved_ballot_wire_bytes_per_block / ENTRYPOINT_WIRE_BYTES);
    let capacity = u128::from(opportunities) * u128::from(ballots_per_block);
    let required = BALLOTS_PER_ATTEMPT * u128::from(commitment.max_nonterminal_attempts);
    if ballots_per_block == 0 || capacity < required {
        return Err(ParliamentBallotParameterErrorV1::InsufficientCapacity { capacity, required });
    }
    Ok(BallotCastingCapacityV1 {
        ballots_per_block,
        opportunities,
        capacity,
        required,
    })
}

/// Check `min ≤ value ≤ max` for the field `field`.
fn check_range(
    field: &'static str,
    value: u64,
    min: u64,
    max: u64,
) -> Result<(), ParliamentBallotParameterErrorV1> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(ParliamentBallotParameterErrorV1::OutOfRange {
            field,
            value,
            min,
            max,
        })
    }
}

/// The committed `gov.parliament_ballot` parameters, stored as a World custom parameter.
#[derive(
    Debug,
    Clone,
    Copy,
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
    name = "iroha_data_model::parameter::parliament_ballot::ParliamentBallotParametersV1"
)]
#[norito(deny_unknown_fields)]
pub struct ParliamentBallotParametersV1 {
    /// Minimum notice between sealing and casting, frozen per attempt.
    pub vote_notice_ms: u64,
    /// Casting duration after the successor-block clock, frozen per attempt.
    pub casting_window_ms: u64,
    /// `K`: nonterminal attempts admitted concurrently; each reserves one casting slot
    /// that Policy and Confirmation use in turn.
    pub max_nonterminal_attempts: u16,
    /// `B_work`: ballot verification reservations per block.
    pub max_verification_reservations_per_block: u32,
    /// `B_bytes`: ballot verifier-input bytes per block, copied context included.
    pub max_verifier_input_bytes_per_block: u64,
    /// Leading zero bits the admission stamp's work digest needs, frozen per attempt.
    pub stamp_difficulty_bits: u8,
}

impl Default for ParliamentBallotParametersV1 {
    fn default() -> Self {
        Self {
            vote_notice_ms: 86_400_000,
            casting_window_ms: 86_400_000,
            max_nonterminal_attempts: 4,
            max_verification_reservations_per_block: 2,
            max_verifier_input_bytes_per_block: 851_968,
            stamp_difficulty_bits: 28,
        }
    }
}

impl ParliamentBallotParametersV1 {
    /// Largest `vote_notice_ms` (seven days); the smallest is zero.
    pub const MAX_VOTE_NOTICE_MS: u64 = 604_800_000;
    /// Smallest `casting_window_ms` (one minute).
    pub const MIN_CASTING_WINDOW_MS: u64 = 60_000;
    /// Largest `casting_window_ms` (seven days).
    pub const MAX_CASTING_WINDOW_MS: u64 = 604_800_000;
    /// Smallest `max_nonterminal_attempts`.
    pub const MIN_NONTERMINAL_ATTEMPTS: u16 = 1;
    /// Largest `max_nonterminal_attempts`.
    pub const MAX_NONTERMINAL_ATTEMPTS: u16 = 16;
    /// Smallest `max_verification_reservations_per_block`.
    pub const MIN_VERIFICATION_RESERVATIONS: u32 = 1;
    /// Largest `max_verification_reservations_per_block`.
    pub const MAX_VERIFICATION_RESERVATIONS: u32 = 8;
    /// Smallest `max_verifier_input_bytes_per_block`: one verification call.
    pub const MIN_VERIFIER_INPUT_BYTES: u64 = VERIFIER_INPUT_BYTES_PER_CALL;
    /// Largest `max_verifier_input_bytes_per_block`: eight verification calls.
    pub const MAX_VERIFIER_INPUT_BYTES: u64 = 8 * VERIFIER_INPUT_BYTES_PER_CALL;
    /// Smallest `stamp_difficulty_bits`.
    pub const MIN_STAMP_DIFFICULTY_BITS: u8 = 28;
    /// Largest `stamp_difficulty_bits`.
    pub const MAX_STAMP_DIFFICULTY_BITS: u8 = 32;

    /// The sole canonical custom parameter identity.
    #[must_use]
    pub fn parameter_id() -> &'static CustomParameterId {
        static ID: std::sync::OnceLock<CustomParameterId> = std::sync::OnceLock::new();
        ID.get_or_init(|| {
            "parliament_ballot_v1"
                .parse()
                .expect("static parameter identity")
        })
    }

    /// Check the frozen casting fields' structural ranges.
    ///
    /// # Errors
    /// [`ParliamentBallotParameterErrorV1::OutOfRange`] naming the first offending field.
    pub fn check_casting_ranges(
        vote_notice_ms: u64,
        casting_window_ms: u64,
        stamp_difficulty_bits: u8,
    ) -> Result<(), ParliamentBallotParameterErrorV1> {
        check_range(
            "vote_notice_ms",
            vote_notice_ms,
            0,
            Self::MAX_VOTE_NOTICE_MS,
        )?;
        check_range(
            "casting_window_ms",
            casting_window_ms,
            Self::MIN_CASTING_WINDOW_MS,
            Self::MAX_CASTING_WINDOW_MS,
        )?;
        check_range(
            "stamp_difficulty_bits",
            u64::from(stamp_difficulty_bits),
            u64::from(Self::MIN_STAMP_DIFFICULTY_BITS),
            u64::from(Self::MAX_STAMP_DIFFICULTY_BITS),
        )
    }

    /// Check the global budget fields' structural ranges.
    ///
    /// # Errors
    /// [`ParliamentBallotParameterErrorV1::OutOfRange`] naming the first offending field.
    pub fn check_budget_ranges(
        max_nonterminal_attempts: u16,
        max_verification_reservations_per_block: u32,
        max_verifier_input_bytes_per_block: u64,
    ) -> Result<(), ParliamentBallotParameterErrorV1> {
        check_range(
            "max_nonterminal_attempts",
            u64::from(max_nonterminal_attempts),
            u64::from(Self::MIN_NONTERMINAL_ATTEMPTS),
            u64::from(Self::MAX_NONTERMINAL_ATTEMPTS),
        )?;
        check_range(
            "max_verification_reservations_per_block",
            u64::from(max_verification_reservations_per_block),
            u64::from(Self::MIN_VERIFICATION_RESERVATIONS),
            u64::from(Self::MAX_VERIFICATION_RESERVATIONS),
        )?;
        check_range(
            "max_verifier_input_bytes_per_block",
            max_verifier_input_bytes_per_block,
            Self::MIN_VERIFIER_INPUT_BYTES,
            Self::MAX_VERIFIER_INPUT_BYTES,
        )
    }

    /// Check every field's structural range, independently of the block cadence.
    ///
    /// # Errors
    /// [`ParliamentBallotParameterErrorV1::OutOfRange`] naming the first offending field.
    pub fn validate_structure(&self) -> Result<(), ParliamentBallotParameterErrorV1> {
        Self::check_casting_ranges(
            self.vote_notice_ms,
            self.casting_window_ms,
            self.stamp_difficulty_bits,
        )?;
        Self::check_budget_ranges(
            self.max_nonterminal_attempts,
            self.max_verification_reservations_per_block,
            self.max_verifier_input_bytes_per_block,
        )
    }

    /// The capacity rule for these parameters at the committed `block_cadence_ms`, with the
    /// reservations derived from the budgets.
    ///
    /// # Errors
    /// As [`parliament_ballot_capacity_v1`].
    pub fn capacity(
        &self,
        block_cadence_ms: u64,
    ) -> Result<BallotCastingCapacityV1, ParliamentBallotParameterErrorV1> {
        parliament_ballot_capacity_v1(
            self.casting_window_ms,
            &BallotCapacityCommitmentV1::from_parameters(self, block_cadence_ms),
        )
    }

    /// Structural validation followed by the capacity rule at `block_cadence_ms`.
    ///
    /// # Errors
    /// As [`Self::validate_structure`] and [`Self::capacity`].
    pub fn validate(
        &self,
        block_cadence_ms: u64,
    ) -> Result<BallotCastingCapacityV1, ParliamentBallotParameterErrorV1> {
        self.validate_structure()?;
        self.capacity(block_cadence_ms)
    }

    /// Decode the exact committed parameter without substituting defaults on failure. The
    /// payload must be the canonical key-ordered JSON of its value. Range and capacity
    /// validation is [`Self::validate`], which needs the committed block cadence.
    ///
    /// # Errors
    /// [`ParliamentBallotParameterErrorV1::CustomParameter`] for another identity, more
    /// than 512 bytes of JSON, a malformed payload (including a missing or unknown field) or
    /// a payload that is not the canonical JSON of its value.
    pub fn from_custom_parameter(
        parameter: &CustomParameter,
    ) -> Result<Self, ParliamentBallotParameterErrorV1> {
        if parameter.id() != Self::parameter_id() {
            return Err(ParliamentBallotParameterErrorV1::CustomParameter(
                "another parameter identity",
            ));
        }
        let payload = parameter.payload();
        if payload.get().len() > 512 {
            return Err(ParliamentBallotParameterErrorV1::CustomParameter(
                "payload exceeds 512 bytes",
            ));
        }
        let value: Self = norito::json::from_str(payload.get())
            .map_err(|_| ParliamentBallotParameterErrorV1::CustomParameter("malformed payload"))?;
        if Json::try_new(value).ok().as_ref() != Some(payload) {
            return Err(ParliamentBallotParameterErrorV1::CustomParameter(
                "payload is not the canonical JSON of its value",
            ));
        }
        Ok(value)
    }

    /// The committed custom parameter of structurally valid parameters, with their canonical
    /// key-ordered JSON payload.
    ///
    /// # Errors
    /// [`ParliamentBallotParameterErrorV1::OutOfRange`] as [`Self::validate_structure`], and
    /// [`ParliamentBallotParameterErrorV1::CustomParameter`] if the payload cannot be
    /// produced.
    pub fn to_custom_parameter(&self) -> Result<CustomParameter, ParliamentBallotParameterErrorV1> {
        self.validate_structure()?;
        let payload = Json::try_new(*self).map_err(|_| {
            ParliamentBallotParameterErrorV1::CustomParameter("payload cannot be serialized")
        })?;
        Ok(CustomParameter::new(Self::parameter_id().clone(), payload))
    }
}

#[cfg(test)]
mod tests {
    use norito::codec::{Decode, Encode};

    use super::*;

    /// A change of one parameter field, for table-driven bound tests.
    type Change = fn(&mut ParliamentBallotParametersV1);

    #[test]
    fn the_defaults_are_the_engineering_defaults_and_fill_the_window() {
        let defaults = ParliamentBallotParametersV1::default();
        assert_eq!(
            (
                defaults.vote_notice_ms,
                defaults.casting_window_ms,
                defaults.max_nonterminal_attempts,
                defaults.max_verification_reservations_per_block,
                defaults.max_verifier_input_bytes_per_block,
                defaults.stamp_difficulty_bits,
            ),
            (86_400_000, 86_400_000, 4, 2, 851_968, 28)
        );
        // At the 1,000 ms cadence: b = min(2, 851,968 / 425,984) = 2,
        // opportunities = 86,400 - 1, capacity = 172,798 >= 1,000 * 4.
        assert_eq!(
            defaults.validate(1_000),
            Ok(BallotCastingCapacityV1 {
                ballots_per_block: 2,
                opportunities: 86_399,
                capacity: 172_798,
                required: 4_000,
            })
        );
    }

    #[test]
    fn every_structural_bound_is_inclusive() {
        let defaults = ParliamentBallotParametersV1::default();
        let with = |change: Change| {
            let mut parameters = defaults;
            change(&mut parameters);
            parameters.validate_structure()
        };
        // Accepted at both ends.
        let accepted: [Change; 12] = [
            |p| p.vote_notice_ms = 0,
            |p| p.vote_notice_ms = 604_800_000,
            |p| p.casting_window_ms = 60_000,
            |p| p.casting_window_ms = 604_800_000,
            |p| p.max_nonterminal_attempts = 1,
            |p| p.max_nonterminal_attempts = 16,
            |p| p.max_verification_reservations_per_block = 1,
            |p| p.max_verification_reservations_per_block = 8,
            |p| p.max_verifier_input_bytes_per_block = 425_984,
            |p| p.max_verifier_input_bytes_per_block = 3_407_872,
            |p| p.stamp_difficulty_bits = 28,
            |p| p.stamp_difficulty_bits = 32,
        ];
        for change in accepted {
            assert_eq!(with(change), Ok(()));
        }
        // Refused one step outside.
        let refused: [(&str, Change); 11] = [
            ("vote_notice_ms", |p| p.vote_notice_ms = 604_800_001),
            ("casting_window_ms", |p| p.casting_window_ms = 59_999),
            ("casting_window_ms", |p| p.casting_window_ms = 604_800_001),
            ("max_nonterminal_attempts", |p| {
                p.max_nonterminal_attempts = 0
            }),
            ("max_nonterminal_attempts", |p| {
                p.max_nonterminal_attempts = 17
            }),
            ("max_verification_reservations_per_block", |p| {
                p.max_verification_reservations_per_block = 0;
            }),
            ("max_verification_reservations_per_block", |p| {
                p.max_verification_reservations_per_block = 9;
            }),
            ("max_verifier_input_bytes_per_block", |p| {
                p.max_verifier_input_bytes_per_block = 425_983;
            }),
            ("max_verifier_input_bytes_per_block", |p| {
                p.max_verifier_input_bytes_per_block = 3_407_873;
            }),
            ("stamp_difficulty_bits", |p| p.stamp_difficulty_bits = 27),
            ("stamp_difficulty_bits", |p| p.stamp_difficulty_bits = 33),
        ];
        for (field, change) in refused {
            assert!(
                matches!(
                    with(change),
                    Err(ParliamentBallotParameterErrorV1::OutOfRange { field: actual, .. })
                        if actual == field
                ),
                "{field}"
            );
        }
    }

    /// The commitment of the budgets `(K, B_work, B_bytes)` at `cadence`, with the derived
    /// reservations.
    fn commitment(
        cadence: u64,
        attempts: u16,
        work: u32,
        bytes: u64,
    ) -> BallotCapacityCommitmentV1 {
        BallotCapacityCommitmentV1::from_parameters(
            &ParliamentBallotParametersV1 {
                max_nonterminal_attempts: attempts,
                max_verification_reservations_per_block: work,
                max_verifier_input_bytes_per_block: bytes,
                ..ParliamentBallotParametersV1::default()
            },
            cadence,
        )
    }

    /// The capacity rule of `window` under [`commitment`].
    fn capacity(
        window: u64,
        cadence: u64,
        attempts: u16,
        work: u32,
        bytes: u64,
    ) -> Result<BallotCastingCapacityV1, ParliamentBallotParameterErrorV1> {
        parliament_ballot_capacity_v1(window, &commitment(cadence, attempts, work, bytes))
    }

    #[test]
    fn the_capacity_rule_uses_checked_arithmetic() {
        // b is bounded by both budgets.
        assert_eq!(
            capacity(86_400_000, 1_000, 1, 8, 425_984).map(|capacity| capacity.ballots_per_block),
            Ok(1)
        );
        assert_eq!(
            capacity(86_400_000, 1_000, 1, 1, 3_407_872).map(|capacity| capacity.ballots_per_block),
            Ok(1)
        );
        // The smallest window holds only a small K at the largest budget.
        assert_eq!(
            capacity(126_000, 1_000, 1, 8, 3_407_872),
            Ok(BallotCastingCapacityV1 {
                ballots_per_block: 8,
                opportunities: 125,
                capacity: 1_000,
                required: 1_000,
            })
        );
        assert_eq!(
            capacity(125_999, 1_000, 1, 8, 3_407_872),
            Err(ParliamentBallotParameterErrorV1::InsufficientCapacity {
                capacity: 992,
                required: 1_000
            })
        );
        assert_eq!(
            capacity(60_000, 1_000, 16, 1, 425_984),
            Err(ParliamentBallotParameterErrorV1::InsufficientCapacity {
                capacity: 59,
                required: 16_000
            })
        );
        assert_eq!(
            capacity(86_400_000, 0, 4, 2, 851_968),
            Err(ParliamentBallotParameterErrorV1::ZeroCadence)
        );
        assert_eq!(
            capacity(999, 1_000, 4, 2, 851_968),
            Err(ParliamentBallotParameterErrorV1::WindowShorterThanCadence {
                casting_window_ms: 999,
                block_cadence_ms: 1_000
            })
        );
        // One cadence leaves no successor opportunity.
        assert!(matches!(
            capacity(1_000, 1_000, 1, 8, 3_407_872),
            Err(ParliamentBallotParameterErrorV1::InsufficientCapacity { capacity: 0, .. })
        ));
        // A zero per-block budget never passes, whatever the window.
        assert!(matches!(
            capacity(u64::MAX, 1, 0, 0, 0),
            Err(ParliamentBallotParameterErrorV1::InsufficientCapacity { .. })
        ));
        // Extreme inputs cannot overflow the wide products.
        assert!(capacity(u64::MAX, 1, u16::MAX, u32::MAX, u64::MAX).is_ok());
        // A slower cadence can fail the same parameters.
        let defaults = ParliamentBallotParametersV1::default();
        assert!(defaults.capacity(1_000).is_ok());
        assert!(defaults.capacity(43_200).is_err());
        // The Parliament-only short fixture of the lifecycle decisions: K = 1, B_work = 8,
        // B_bytes = 3,407,872, a 100 ms cadence and a 60,000 ms window.
        assert_eq!(
            capacity(60_000, 100, 1, 8, 3_407_872),
            Ok(BallotCastingCapacityV1 {
                ballots_per_block: 8,
                opportunities: 599,
                capacity: 4_792,
                required: 1_000,
            })
        );
    }

    #[test]
    fn the_reservations_are_derived_and_bound_the_capacity() {
        // At the defaults: two slots and 526,336 wire bytes.
        let defaults = commitment(1_000, 4, 2, 851_968);
        assert_eq!(defaults.reserved_ballot_slots_per_block, 2);
        assert_eq!(defaults.reserved_ballot_wire_bytes_per_block, 526_336);
        assert_eq!(reserved_ballot_slots_v1(2, 851_968), 2);
        assert_eq!(reserved_ballot_slots_v1(8, 851_967), 1);
        assert_eq!(reserved_ballot_slots_v1(1, 3_407_872), 1);
        assert_eq!(reserved_ballot_slots_v1(u32::MAX, u64::MAX), u32::MAX);
        assert_eq!(reserved_ballot_wire_bytes_v1(3), 3 * 263_168);
        assert_eq!(
            ENTRYPOINT_WIRE_BYTES,
            u64::try_from(ANONYMOUS_BALLOT_ENTRYPOINT_WIRE_MAX_BYTES_V1).expect("small")
        );
        // Smaller reservations bound b in both of their terms.
        let mut fewer_slots = defaults;
        fewer_slots.reserved_ballot_slots_per_block = 1;
        assert_eq!(
            parliament_ballot_capacity_v1(86_400_000, &fewer_slots)
                .map(|capacity| capacity.ballots_per_block),
            Ok(1)
        );
        let mut less_wire = defaults;
        less_wire.reserved_ballot_wire_bytes_per_block = 2 * 263_168 - 1;
        assert_eq!(
            parliament_ballot_capacity_v1(86_400_000, &less_wire)
                .map(|capacity| capacity.ballots_per_block),
            Ok(1)
        );
        less_wire.reserved_ballot_wire_bytes_per_block = 263_167;
        assert!(matches!(
            parliament_ballot_capacity_v1(86_400_000, &less_wire),
            Err(ParliamentBallotParameterErrorV1::InsufficientCapacity { capacity: 0, .. })
        ));
        let mut no_slots = defaults;
        no_slots.reserved_ballot_slots_per_block = 0;
        assert!(parliament_ballot_capacity_v1(u64::MAX, &no_slots).is_err());
        // Larger reservations than the budgets allow do not raise b...
        let mut more = defaults;
        more.reserved_ballot_slots_per_block = 8;
        more.reserved_ballot_wire_bytes_per_block = 8 * 263_168;
        assert_eq!(
            parliament_ballot_capacity_v1(86_400_000, &more)
                .map(|capacity| capacity.ballots_per_block),
            Ok(2)
        );
        // ...and a commitment that records them is refused as not derived.
        assert_eq!(
            more.validate(86_400_000),
            Err(ParliamentBallotParameterErrorV1::ReservationMismatch)
        );
        assert!(defaults.validate(86_400_000).is_ok());
    }

    #[test]
    fn the_custom_parameter_round_trips_exactly() {
        let parameters = ParliamentBallotParametersV1 {
            stamp_difficulty_bits: 30,
            ..ParliamentBallotParametersV1::default()
        };
        assert_eq!(
            ParliamentBallotParametersV1::decode(&mut parameters.encode().as_slice())
                .expect("decode"),
            parameters
        );
        // Custom parameter payloads hold canonical (key-ordered) JSON.
        let parameter = CustomParameter::new(
            ParliamentBallotParametersV1::parameter_id().clone(),
            iroha_primitives::json::Json::new(parameters),
        );
        let json = norito::json::to_json(&parameters).expect("json");
        assert_eq!(
            norito::json::from_str::<ParliamentBallotParametersV1>(&json).expect("json"),
            parameters
        );
        assert_eq!(
            ParliamentBallotParametersV1::from_custom_parameter(&parameter),
            Ok(parameters)
        );
        assert_eq!(parameters.to_custom_parameter(), Ok(parameter.clone()));
        let foreign =
            CustomParameter::new("other".parse().expect("name"), parameter.payload().clone());
        assert_eq!(
            ParliamentBallotParametersV1::from_custom_parameter(&foreign),
            Err(ParliamentBallotParameterErrorV1::CustomParameter(
                "another parameter identity"
            ))
        );
        let malformed = CustomParameter::new(
            ParliamentBallotParametersV1::parameter_id().clone(),
            r#"{"vote_notice_ms":1}"#.parse::<iroha_primitives::json::Json>().expect("json"),
        );
        assert_eq!(
            ParliamentBallotParametersV1::from_custom_parameter(&malformed),
            Err(ParliamentBallotParameterErrorV1::CustomParameter(
                "malformed payload"
            ))
        );
        assert_eq!(
            ParliamentBallotParametersV1::parameter_id().to_string(),
            "parliament_ballot_v1"
        );
        // Unknown fields are refused, and a structurally invalid value is not written.
        let unknown = parameter.payload().get().replacen(
            r#"{"casting_window_ms""#,
            r#"{"a":0,"casting_window_ms""#,
            1,
        );
        let unknown = CustomParameter::new(
            ParliamentBallotParametersV1::parameter_id().clone(),
            unknown
                .parse::<iroha_primitives::json::Json>()
                .expect("json"),
        );
        assert_eq!(
            ParliamentBallotParametersV1::from_custom_parameter(&unknown),
            Err(ParliamentBallotParameterErrorV1::CustomParameter(
                "malformed payload"
            ))
        );
        let invalid = ParliamentBallotParametersV1 {
            stamp_difficulty_bits: 27,
            ..parameters
        };
        assert!(matches!(
            invalid.to_custom_parameter(),
            Err(ParliamentBallotParameterErrorV1::OutOfRange {
                field: "stamp_difficulty_bits",
                ..
            })
        ));
    }
}
