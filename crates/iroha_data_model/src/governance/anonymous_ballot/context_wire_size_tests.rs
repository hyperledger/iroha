//! Independent valid-domain wire arithmetic; these tests make no workspace or proof claim.

use iroha_primitives::numeric::Quantity;

use super::AuthenticatedBallotContextV1;
use crate::governance::{
    anonymous_ballot::{
        ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1, BALLOT_CONTEXT_MAX_BYTES_V1,
        BALLOT_VERIFIER_INPUT_MAX_BYTES_PER_CALL_V1, BallotChoiceV1,
        FrozenParliamentAttemptPolicyV1, ParliamentBallotParametersV1,
        ParliamentLifecycleParametersV1,
        framing::enc,
        test_fixtures::{commitments, context, envelope},
    },
    types::{PARLIAMENT_BODIES_V1, ParliamentBody, RiskTierV1},
};

/// Length of the pinned unsigned LEB128 field prefix, independent of Norito helpers.
fn prefix_bytes(mut length: usize) -> usize {
    let mut bytes = 1;
    while length >= 128 {
        length >>= 7;
        bytes += 1;
    }
    bytes
}

/// Source-derived arithmetic, not a serializer length hint.
///
/// Each commitment is 128 raw bytes plus a two-byte field prefix; each required
/// body is a 16-byte record plus a one-byte prefix. Both vectors have u64 counts.
/// A positive integral bond uses K minimal signed bytes plus BigInt's fixed u32
/// length and Numeric's two field prefixes/four-byte scale: Quantity = 10 + K.
/// Body context = 118; sortition = 49 + K; lifecycle = 81; capacity = 40;
/// binding = 126; frozen policy = 306 + 17N + K + prefix_bytes(8 + 17N).
/// Framing those fields and adding the 40-byte header gives the expression below.
fn context_frame_bytes(seats: usize, required_bodies: usize, bond_signed_bytes: usize) -> usize {
    803 + 130 * seats
        + 17 * required_bodies
        + bond_signed_bytes
        + prefix_bytes(8 + 130 * seats)
        + prefix_bytes(8 + 17 * required_bodies)
}

/// Freeze a structurally valid policy over a canonical subset, always including both juries.
/// The digests are public structural fixtures, not authenticated chain evidence.
fn valid_context(seats: u16, public_body_mask: u8, bond: u128) -> AuthenticatedBallotContextV1 {
    let pipeline = PARLIAMENT_BODIES_V1
        .into_iter()
        .enumerate()
        .filter(|(index, _)| *index >= 8 || public_body_mask & (1_u8 << *index) != 0)
        .map(|(_, body)| body)
        .collect::<Vec<_>>();
    let mut lifecycle = ParliamentLifecycleParametersV1::default();
    lifecycle.sortition.minimum_citizenship_bond = Quantity::from(bond);
    let attempt = FrozenParliamentAttemptPolicyV1::freeze_v1(
        &pipeline,
        &lifecycle,
        Some(&ParliamentBallotParametersV1::default()),
        1_000,
        3_600,
    )
    .expect("valid frozen policy");
    let mut value = context();
    value.body_context.body_role = ParliamentBody::ConfirmationJury;
    value.policy = attempt
        .ballot_policy(RiskTierV1::Standard, ParliamentBody::ConfirmationJury)
        .expect("default confirmation target admits every permitted roster size");
    value.seats = seats;
    value.commitments = commitments(seats);
    value.validate().expect("valid structural fixture");
    value
}

#[test]
fn source_formula_is_monotone_over_the_complete_valid_size_domain() {
    assert_eq!(prefix_bytes(127), 1);
    assert_eq!(prefix_bytes(128), 2);
    assert_eq!(prefix_bytes(16_383), 2);
    assert_eq!(prefix_bytes(16_384), 3);
    // Policy validation bounds N by the ten distinct ordered enum values and
    // requires both juries. The integral bond is in 1..=u128::MAX, hence K <= 17.
    for seats in 3..=1_000 {
        for bodies in 2..=10 {
            for bond_bytes in 1..=17 {
                let size = context_frame_bytes(seats, bodies, bond_bytes);
                assert!(size <= 130_995);
                if seats > 3 {
                    assert!(size > context_frame_bytes(seats - 1, bodies, bond_bytes));
                }
                if bodies > 2 {
                    assert!(size > context_frame_bytes(seats, bodies - 1, bond_bytes));
                }
                if bond_bytes > 1 {
                    assert!(size > context_frame_bytes(seats, bodies, bond_bytes - 1));
                }
            }
        }
    }
    assert_eq!(context_frame_bytes(1_000, 10, 17), 130_995);
}

#[test]
fn canonical_sizes_match_both_vector_prefix_transitions() {
    // The roster field crosses 2^14 between S=125 and 126. The policy's body
    // vector crosses 2^7 between N=7 and 8. Other policy fields keep fixed widths.
    for seats in [3, 125, 126, 1_000] {
        for (mask, bodies) in [(0, 2), (0x1f, 7), (0x3f, 8), (0xff, 10)] {
            for (bond, bond_bytes) in [(1, 1), (150, 2), (u128::MAX, 17)] {
                let value = valid_context(seats, mask, bond);
                let bytes = enc(&value).expect("canonical context");
                assert_eq!(
                    bytes.len(),
                    context_frame_bytes(usize::from(seats), bodies, bond_bytes),
                    "S={seats}, N={bodies}, K={bond_bytes}"
                );
            }
        }
    }
}

#[test]
fn every_canonical_body_subset_has_the_predicted_width() {
    for mask in 0..=u8::MAX {
        let value = valid_context(3, mask, 150);
        let bodies = 2 + mask.count_ones() as usize;
        assert_eq!(value.policy.required_bodies.len(), bodies);
        assert_eq!(
            enc(&value).expect("canonical body subset").len(),
            context_frame_bytes(3, bodies, 2)
        );
    }
}

#[test]
fn integral_bond_signed_length_boundaries_match_the_formula() {
    // Positive two's-complement values need a new byte at 2^(8K-1), including
    // the sign byte at 2^127. No serializer determines the expected K.
    for signed_bytes in 1..=16 {
        let threshold = 1_u128 << (8 * signed_bytes - 1);
        for (bond, expected_bytes) in [(threshold - 1, signed_bytes), (threshold, signed_bytes + 1)]
        {
            let value = valid_context(3, 0, bond);
            assert_eq!(
                enc(&value).expect("canonical integral bond").len(),
                context_frame_bytes(3, 2, expected_bytes)
            );
        }
    }
    assert_eq!(
        enc(&valid_context(3, 0, u128::MAX))
            .expect("largest integral bond")
            .len(),
        context_frame_bytes(3, 2, 17)
    );
}

#[test]
fn maximal_valid_context_fits_and_roundtrips_through_the_typed_decoder() {
    let value = valid_context(1_000, u8::MAX, u128::MAX);
    let bytes = enc(&value).expect("maximal valid context");
    assert_eq!(value.policy.required_bodies.len(), 10);
    assert_eq!(value.policy.body_target_seats(), Some(1_000));
    assert_eq!(bytes.len(), 130_995);
    assert!(bytes.len() < BALLOT_CONTEXT_MAX_BYTES_V1);
    // The outer scope only observes; the typed decoder must supply its own limits.
    // These are cumulative nominal codec charges, not physical heap/workspace bytes.
    let observer =
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX);
    let (decoded, usage) = norito::core::with_decode_limits_measured(observer, || {
        AuthenticatedBallotContextV1::decode_canonical_bounded(&bytes)
    });
    assert_eq!(decoded, Ok(value));
    assert_eq!(usage.total_elements(), 1_010);
    assert!(usage.total_allocated_bytes() <= 327_680);
    assert_eq!(233_455 + bytes.len(), 364_450);
    const { assert!(364_450 < BALLOT_VERIFIER_INPUT_MAX_BYTES_PER_CALL_V1) };
}

#[test]
fn envelope_width_is_fixed_for_every_vote_choice() {
    // Raw field widths and nested field prefixes: ballot=233379, envelope
    // payload=LP(32)+LP(233379)=233415, then its 40-byte header.
    const EXPECTED: usize = 40 + (1 + 32) + (3 + 233_379);
    assert_eq!(EXPECTED, 233_455);
    for (index, vote) in BallotChoiceV1::ALL.into_iter().enumerate() {
        let value = envelope(vote, index as u8);
        assert_eq!(
            value.encode_canonical_bounded().expect("envelope").len(),
            EXPECTED
        );
    }
    const { assert!(EXPECTED < ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1) };
}
