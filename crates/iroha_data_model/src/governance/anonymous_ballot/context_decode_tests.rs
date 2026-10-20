//! Allocation-order controls for the bounded canonical context entry point.

use core::ops::Range;

use super::*;
use crate::governance::anonymous_ballot::{
    framing::{ENC_HEADER_BYTES_V1, ENC_LAYOUT_FLAGS_V1, enc},
    test_fixtures::{commitments, context},
};

fn observe(
    bytes: &[u8],
) -> (
    Result<AuthenticatedBallotContextV1, BallotContextErrorV1>,
    norito::core::DecodeAllocationUsage,
) {
    // This observer must not supply the limits being tested.
    let observer =
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX);
    norito::core::with_decode_limits_measured(observer, || {
        AuthenticatedBallotContextV1::decode_canonical_bounded(bytes)
    })
}

fn codec(error: norito::Error) -> BallotContextErrorV1 {
    AnonymousBallotCodecErrorV1::codec(&error).into()
}

fn field_range(payload: &[u8], index: usize) -> Range<usize> {
    let _flags = norito::core::DecodeFlagsGuard::enter(ENC_LAYOUT_FLAGS_V1);
    let mut offset = 0;
    for field in 0..=index {
        let (length, prefix) = norito::core::inspect_len_from_slice(&payload[offset..])
            .expect("retained canonical field prefix");
        let start = offset + prefix;
        let end = start + length;
        assert!(end <= payload.len());
        if field == index {
            return start..end;
        }
        offset = end;
    }
    unreachable!("the requested field is visited")
}

fn refresh_checksum(frame: &mut [u8]) {
    let checksum = norito::hardware_crc64(&frame[ENC_HEADER_BYTES_V1..]);
    frame[31..39].copy_from_slice(&checksum.to_le_bytes());
}

fn forged_count(frame: &[u8], fields: &[usize], count: u64) -> Vec<u8> {
    let mut changed = frame.to_vec();
    let mut range = ENC_HEADER_BYTES_V1..changed.len();
    for &index in fields {
        let inner = field_range(&changed[range.clone()], index);
        range = range.start + inner.start..range.start + inner.end;
    }
    changed[range.start..range.start + 8].copy_from_slice(&count.to_le_bytes());
    refresh_checksum(&mut changed);
    // Validate the outer schema, length and checksum, so the refusal below must
    // reach the inner collection count rather than fail on stale framing.
    norito::canonical_frame_payload::<AuthenticatedBallotContextV1>(&changed, ENC_LAYOUT_FLAGS_V1)
        .expect("the adversarial frame has authentic outer framing");
    changed
}

fn commitment_charge(count: usize) -> usize {
    count
        * (1 + core::mem::size_of::<norito::core::SequenceSpan>()
            + CredentialCommitmentV1::LENGTH
            + core::mem::size_of::<CredentialCommitmentV1>())
}

#[test]
fn outer_cap_and_declared_frame_length_refuse_before_graph_allocation() {
    let bytes = vec![0; BALLOT_CONTEXT_MAX_BYTES_V1 + 1];
    let (result, usage) = observe(&bytes);
    assert_eq!(
        result,
        Err(AnonymousBallotCodecErrorV1::TooLarge {
            kind: AuthenticatedBallotContextV1::KIND,
            actual: bytes.len(),
            max: BALLOT_CONTEXT_MAX_BYTES_V1,
        }
        .into())
    );
    assert_eq!(usage.total_allocated_bytes(), 0);
    assert_eq!(usage.total_elements(), 0);

    let mut frame = enc(&context()).expect("context frame");
    frame[23..31].copy_from_slice(&u64::MAX.to_le_bytes());
    let (result, usage) = observe(&frame);
    assert!(matches!(result, Err(BallotContextErrorV1::Codec(_))));
    assert_eq!(usage.total_allocated_bytes(), 0);
}

#[test]
fn malformed_record_length_refuses_before_graph_allocation() {
    let mut frame = enc(&context()).expect("context frame");
    // An over-wide first field with a valid outer checksum must be rejected by
    // the original checked field-prefix decoder, before any owned field exists.
    frame[ENC_HEADER_BYTES_V1..ENC_HEADER_BYTES_V1 + 9].fill(0xff);
    frame[ENC_HEADER_BYTES_V1 + 9] = 1;
    refresh_checksum(&mut frame);
    norito::canonical_frame_payload::<AuthenticatedBallotContextV1>(&frame, ENC_LAYOUT_FLAGS_V1)
        .expect("outer framing");
    let (result, usage) = observe(&frame);
    assert!(matches!(result, Err(BallotContextErrorV1::Codec(_))));
    assert_eq!(usage.total_allocated_bytes(), 0);
    assert_eq!(usage.total_elements(), 0);
}

#[test]
fn excessive_roster_counts_refuse_before_sequence_allocation() {
    let mut value = context();
    value.commitments = commitments(MAX_SEALED_SEATS_V1);
    value.seats = MAX_SEALED_SEATS_V1;
    let frame = enc(&value).expect("well-framed context");
    // Canonical defaults are entered before the schema's limits, both inside
    // classification. 1,001 passes the frame-derived default and reaches the
    // schema's 1,000 ceiling; u64::MAX is refused by the default first.
    let default_count_limit = 8 * frame.len() as u64;
    assert_eq!(
        norito::canonical_decode_limits(frame.len()).max_sequence_elements() as u64,
        default_count_limit
    );
    for (count, limit) in [(1_001, 1_000), (u64::MAX, default_count_limit)] {
        let (result, usage) = observe(&forged_count(&frame, &[5], count));
        assert_eq!(
            result,
            Err(codec(norito::Error::SequenceLengthExceeded {
                length: count,
                limit,
            }))
        );
        assert_eq!(usage.total_allocated_bytes(), 0);
        assert_eq!(usage.total_elements(), 0);
    }
}

#[test]
fn excessive_policy_counts_refuse_before_policy_sequence_allocation() {
    let value = context();
    let frame = enc(&value).expect("context frame");
    // As above, preserve the first protocol layer that actually refuses the
    // count instead of relabelling both refusals with the tightest ceiling.
    let default_count_limit = 8 * frame.len() as u64;
    assert_eq!(
        norito::canonical_decode_limits(frame.len()).max_sequence_elements() as u64,
        default_count_limit
    );
    for (count, limit) in [(1_001, 1_000), (u64::MAX, default_count_limit)] {
        let (result, usage) = observe(&forged_count(&frame, &[7, 1], count));
        assert_eq!(
            result,
            Err(codec(norito::Error::SequenceLengthExceeded {
                length: count,
                limit,
            }))
        );
        assert_eq!(
            usage.total_allocated_bytes(),
            commitment_charge(value.commitments.len()),
            "only the preceding roster was charged"
        );
    }
}

#[test]
fn individually_bounded_sequences_cannot_exceed_the_combined_count() {
    let mut value = context();
    value.commitments = commitments(MAX_SEALED_SEATS_V1);
    value.seats = MAX_SEALED_SEATS_V1;
    let repeated = value.policy.required_bodies[0];
    value.policy.required_bodies.resize(11, repeated);
    let frame = enc(&value).expect("canonical encoding of structurally invalid value");
    let (result, usage) = observe(&frame);
    assert_eq!(
        result,
        Err(codec(norito::Error::TotalElementsExceeded {
            attempted: 1_011,
            limit: 1_010,
        }))
    );
    assert_eq!(usage.total_allocated_bytes(), commitment_charge(1_000));
}

#[test]
fn smaller_excess_policy_lists_still_fail_structural_validation() {
    let mut value = context();
    let repeated = value.policy.required_bodies[0];
    value.policy.required_bodies.resize(11, repeated);
    let frame = enc(&value).expect("canonical encoding of structurally invalid value");
    let (result, usage) = observe(&frame);
    assert!(matches!(
        result,
        Err(BallotContextErrorV1::Policy(
            FrozenBallotPolicyErrorV1::RequiredBodyOrder { .. }
        ))
    ));
    assert!(usage.total_allocated_bytes() < 2 * BALLOT_CONTEXT_MAX_BYTES_V1);
}

#[test]
fn narrower_enclosing_limits_survive_and_failed_decode_restores_scope() {
    let value = context();
    let frame = enc(&value).expect("context frame");
    let limits = norito::DecodeLimits::new(1_000, BALLOT_CONTEXT_MAX_BYTES_V1, 1_010, 0, 32);
    let (result, usage) = norito::core::with_decode_limits_measured(limits, || {
        AuthenticatedBallotContextV1::decode_canonical_bounded(&frame)
    });
    let Err(BallotContextErrorV1::Codec(AnonymousBallotCodecErrorV1::DecodeUnavailable(refusal))) =
        result
    else {
        panic!("an original enclosing budget refusal must remain local unavailability");
    };
    assert_eq!(
        refusal.kind(),
        norito::core::DecodeLocalRefusalKind::EnclosingLimit
    );
    assert_eq!(
        refusal.resource_error(),
        norito::core::DecodeResourceError::TotalAllocationExceeded {
            attempted: value.commitments.len() as u64,
            limit: 0,
        }
    );
    assert_eq!(usage.total_allocated_bytes(), 0);
    assert_eq!(
        AuthenticatedBallotContextV1::decode_canonical_bounded(&frame),
        Ok(value)
    );
}

#[test]
fn binary_list_carrier_retains_the_original_inner_budget_refusal() {
    let list = context().sealed_list().expect("valid fixture list");
    let value = SealedCredentialListBytesV1::from_list(&list).expect("published list");
    let bytes = enc(&value).expect("canonical carrier");
    let count = value.as_bytes().len();
    // decode_vec_from_slice_with specializes Vec<u8>: read_seq_len_slice
    // charges one count unit per byte, then try_decode_vec_with_capacity
    // charges the owned raw bytes. It allocates no generic sequence spans.
    let carrier_charge = 2 * count;
    let unrestricted =
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX);
    let (decoded, usage) = norito::core::with_decode_limits_measured(unrestricted, || {
        norito::decode_canonical_for_admission::<SealedCredentialListBytesV1>(&bytes, unrestricted)
    });
    assert_eq!(decoded.expect("carrier roundtrip"), value);
    assert_eq!(usage.total_elements(), count + list.commitments.len());
    assert_eq!(
        usage.total_allocated_bytes(),
        carrier_charge + commitment_charge(list.commitments.len())
    );

    let enclosing = norito::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        carrier_charge,
        usize::MAX,
    );
    let (refused, usage) = norito::core::with_decode_limits_measured(enclosing, || {
        norito::decode_canonical_for_admission::<SealedCredentialListBytesV1>(&bytes, unrestricted)
    });
    let refused = refused.expect_err("the outer bytes fit, but the inner list cannot be admitted");
    assert_eq!(
        refused.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert_eq!(
        refused.error().decode_resource_error(),
        Some(norito::core::DecodeResourceError::TotalAllocationExceeded {
            attempted: (carrier_charge + list.commitments.len()) as u64,
            limit: carrier_charge as u64,
        })
    );
    assert_eq!(usage.total_allocated_bytes(), carrier_charge);
    assert_eq!(usage.total_elements(), count + list.commitments.len());
    assert_eq!(
        norito::decode_canonical::<SealedCredentialListBytesV1>(&bytes).expect("fresh scope"),
        value
    );
}

#[test]
fn json_list_carrier_retains_the_original_inner_budget_refusal() {
    let list = context().sealed_list().expect("valid fixture list");
    let value = SealedCredentialListBytesV1::from_list(&list).expect("published list");
    let text = norito::json::to_json(&value).expect("carrier JSON");
    let unrestricted =
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX);
    let (decoded, baseline) = norito::core::with_decode_limits_measured(unrestricted, || {
        norito::json::from_str::<SealedCredentialListBytesV1>(&text)
    });
    assert_eq!(decoded.expect("JSON roundtrip"), value);
    // The complete Fields parser precedes the inner list validation. Its
    // measured charge selects this regression's boundary; it is not a bound
    // for arbitrary JSON parsing or physical allocation.
    let parser_charge =
        baseline.total_allocated_bytes() - commitment_charge(list.commitments.len());
    assert!(parser_charge > 0);
    let enclosing = norito::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        parser_charge,
        usize::MAX,
    );
    let (refused, usage) = norito::core::with_decode_limits_measured(enclosing, || {
        norito::core::classify_decode_attempt(|| {
            norito::json::from_str::<SealedCredentialListBytesV1>(&text)
                .map_err(norito::json::Error::into_core_error)
        })
    });
    let refused = refused.expect_err("the JSON bytes fit, but the inner list cannot be admitted");
    assert_eq!(
        refused.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert_eq!(
        refused.error().decode_resource_error(),
        Some(norito::core::DecodeResourceError::TotalAllocationExceeded {
            attempted: (parser_charge + list.commitments.len()) as u64,
            limit: parser_charge as u64,
        })
    );
    assert_eq!(usage.total_allocated_bytes(), parser_charge);
    assert_eq!(
        norito::json::from_str::<SealedCredentialListBytesV1>(&text).expect("fresh scope"),
        value
    );
}
