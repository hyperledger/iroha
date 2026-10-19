//! Fixed-envelope decode budgets and adversarial framing; no physical workspace claim.

use super::*;
use crate::governance::anonymous_ballot::{
    framing::{ENC_HEADER_BYTES_V1, ENC_LAYOUT_FLAGS_V1, enc},
    test_fixtures::envelope,
};

fn observe(
    bytes: &[u8],
) -> (
    Result<AnonymousBallotEnvelopeV1, AnonymousBallotCodecErrorV1>,
    norito::core::DecodeAllocationUsage,
) {
    // The observer imposes no limit: only the public entry supplies its budget.
    let observer =
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX);
    norito::core::with_decode_limits_measured(observer, || {
        AnonymousBallotEnvelopeV1::decode_canonical_bounded(bytes)
    })
}

/// Inspect only retained canonical positional records, never a mutated record.
fn fields(payload: &[u8]) -> Vec<&[u8]> {
    let _flags = norito::core::DecodeFlagsGuard::enter(ENC_LAYOUT_FLAGS_V1);
    let mut offset = 0;
    let mut fields = Vec::new();
    while offset < payload.len() {
        let (length, prefix) = norito::core::inspect_len_from_slice(&payload[offset..])
            .expect("retained canonical field length");
        let start = offset + prefix;
        offset = start + length;
        fields.push(payload.get(start..offset).expect("retained field"));
    }
    assert_eq!(offset, payload.len());
    fields
}

/// Encode the pinned unsigned LEB128 prefix independently of the decoder.
fn push_field(output: &mut Vec<u8>, bytes: &[u8]) {
    let mut length = bytes.len();
    while length >= 128 {
        output.push((length as u8 & 0x7f) | 0x80);
        length >>= 7;
    }
    output.push(length as u8);
    output.extend_from_slice(bytes);
}

/// Rebuild ancestor field lengths so a malicious leaf reaches its actual decoder.
fn replace_field(payload: &[u8], path: &[usize], replacement: &[u8]) -> Vec<u8> {
    let Some((&selected, rest)) = path.split_first() else {
        return replacement.to_vec();
    };
    let original = fields(payload);
    assert!(selected < original.len());
    let mut output = Vec::new();
    for (index, field) in original.into_iter().enumerate() {
        if index == selected {
            push_field(&mut output, &replace_field(field, rest, replacement));
        } else {
            push_field(&mut output, field);
        }
    }
    output
}

fn reframe(original: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut frame = original[..ENC_HEADER_BYTES_V1].to_vec();
    frame[23..31].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    frame[31..39].copy_from_slice(&norito::hardware_crc64(payload).to_le_bytes());
    frame.extend_from_slice(payload);
    // Real schema, layout, declared payload length and checksum all agree.
    norito::canonical_frame_payload::<AnonymousBallotEnvelopeV1>(&frame, ENC_LAYOUT_FLAGS_V1)
        .expect("valid outer framing of the adversarial payload");
    frame
}

#[test]
fn every_vote_decodes_with_one_exact_proof_charge_and_no_sequence_elements() {
    for vote in BallotChoiceV1::ALL {
        let value = envelope(vote, vote.proof_code());
        let bytes = value
            .encode_canonical_bounded()
            .expect("canonical envelope");
        assert_eq!(bytes.len(), 233_455);
        let (result, usage) = observe(&bytes);
        assert_eq!(result, Ok(value));
        assert_eq!(usage.total_elements(), 0);
        assert_eq!(usage.total_allocated_bytes(), BallotProofBytesV1::LENGTH);
    }
}

#[test]
fn outer_cap_and_unusable_frame_lengths_refuse_before_the_proof_charge() {
    let bytes = vec![0; ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1 + 1];
    let (result, usage) = observe(&bytes);
    assert_eq!(
        result,
        Err(AnonymousBallotCodecErrorV1::TooLarge {
            kind: "anonymous ballot envelope",
            actual: bytes.len(),
            max: ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1,
        })
    );
    assert_eq!(usage.total_allocated_bytes(), 0);
    assert_eq!(usage.total_elements(), 0);

    let original = envelope(BallotChoiceV1::Aye, 1)
        .encode_canonical_bounded()
        .expect("canonical envelope");
    let mut oversized_length = original.clone();
    oversized_length[23..31].copy_from_slice(&u64::MAX.to_le_bytes());
    for bytes in [
        &[][..],
        &original[..ENC_HEADER_BYTES_V1 - 1],
        &oversized_length,
    ] {
        let (result, usage) = observe(bytes);
        assert!(result.is_err());
        assert_eq!(usage.total_allocated_bytes(), 0);
        assert_eq!(usage.total_elements(), 0);
    }
}

#[test]
fn wrong_fixed_field_lengths_with_valid_outer_framing_never_copy_the_proof() {
    let original = envelope(BallotChoiceV1::Aye, 1)
        .encode_canonical_bounded()
        .expect("canonical envelope");
    // Network, scope, vote discriminant, nullifier, authorization, profile and nonce.
    let paths: &[(&[usize], usize)] = &[
        (&[0], 32),
        (&[1, 0], 64),
        (&[1, 1], 4),
        (&[1, 2], 128),
        (&[1, 3], 64),
        (&[1, 4], 64),
        (&[1, 5, 0], 32),
    ];
    for &(path, width) in paths {
        let mut original_field = &original[ENC_HEADER_BYTES_V1..];
        for &index in path {
            original_field = fields(original_field)[index];
        }
        assert_eq!(original_field.len(), width);
        for length in [width - 1, width + 1] {
            let mut replacement = original_field.to_vec();
            replacement.resize(length, 0);
            let payload = replace_field(&original[ENC_HEADER_BYTES_V1..], path, &replacement);
            let bytes = reframe(&original, &payload);
            let (result, usage) = observe(&bytes);
            assert!(
                matches!(result, Err(AnonymousBallotCodecErrorV1::Codec(_))),
                "field {path:?}, width {length}"
            );
            assert_eq!(usage.total_allocated_bytes(), 0);
            assert_eq!(usage.total_elements(), 0);
        }
    }
}

#[test]
fn wrong_proof_lengths_with_valid_outer_framing_refuse_before_allocation() {
    let original = envelope(BallotChoiceV1::Nay, 1)
        .encode_canonical_bounded()
        .expect("canonical envelope");
    for length in [
        0,
        BallotProofBytesV1::LENGTH - 1,
        BallotProofBytesV1::LENGTH + 1,
    ] {
        let payload = replace_field(
            &original[ENC_HEADER_BYTES_V1..],
            &[1, 6],
            &vec![0x6b; length],
        );
        let bytes = reframe(&original, &payload);
        let (result, usage) = observe(&bytes);
        assert!(
            matches!(result, Err(AnonymousBallotCodecErrorV1::Codec(_))),
            "proof width {length}"
        );
        assert_eq!(usage.total_allocated_bytes(), 0);
        assert_eq!(usage.total_elements(), 0);
    }
}

#[test]
fn malformed_prefixes_and_unknown_vote_tags_fail_before_the_proof_charge() {
    let original = envelope(BallotChoiceV1::Aye, 1)
        .encode_canonical_bounded()
        .expect("canonical envelope");
    let mut malformed = original[ENC_HEADER_BYTES_V1..].to_vec();
    malformed[..9].fill(0xff);
    malformed[9] = 1;
    let unknown = replace_field(
        &original[ENC_HEADER_BYTES_V1..],
        &[1, 1],
        &u32::MAX.to_le_bytes(),
    );
    for payload in [malformed, unknown] {
        let bytes = reframe(&original, &payload);
        let (result, usage) = observe(&bytes);
        assert!(matches!(result, Err(AnonymousBallotCodecErrorV1::Codec(_))));
        assert_eq!(usage.total_allocated_bytes(), 0);
        assert_eq!(usage.total_elements(), 0);
    }
}

#[test]
fn a_stricter_enclosing_budget_refuses_before_copy_and_is_restored_afterward() {
    let value = envelope(BallotChoiceV1::Abstain, 1);
    let bytes = value
        .encode_canonical_bounded()
        .expect("canonical envelope");
    let limit = BallotProofBytesV1::LENGTH - 1;
    let limits = norito::DecodeLimits::new(0, usize::MAX, 0, limit, usize::MAX);
    let (result, usage) = norito::core::with_decode_limits_measured(limits, || {
        AnonymousBallotEnvelopeV1::decode_canonical_bounded(&bytes)
    });
    let Err(AnonymousBallotCodecErrorV1::DecodeUnavailable(refusal)) = result else {
        panic!("the original enclosing-budget refusal must remain unavailable");
    };
    assert_eq!(
        refusal.kind(),
        norito::core::DecodeLocalRefusalKind::EnclosingLimit
    );
    assert_eq!(
        refusal.resource_error(),
        norito::core::DecodeResourceError::TotalAllocationExceeded {
            attempted: BallotProofBytesV1::LENGTH as u64,
            limit: limit as u64,
        }
    );
    assert_eq!(refusal.allocation_bytes(), None);
    assert_eq!(usage.total_allocated_bytes(), 0);
    assert_eq!(usage.total_elements(), 0);
    assert_eq!(observe(&bytes).0, Ok(value));
}

#[test]
fn post_proof_failure_returns_no_value_and_does_not_refund_nominal_charges() {
    let value = envelope(BallotChoiceV1::Aye, 1);
    let original = value
        .encode_canonical_bounded()
        .expect("canonical envelope");
    let payload = &original[ENC_HEADER_BYTES_V1..];
    let mut ballot_suffix = fields(payload)[1].to_vec();
    ballot_suffix.push(0);
    let inner_failure = replace_field(payload, &[1], &ballot_suffix);
    let mut outer_failure = payload.to_vec();
    outer_failure.push(0);
    for payload in [inner_failure, outer_failure] {
        let bytes = reframe(&original, &payload);
        let (result, usage) = observe(&bytes);
        assert!(matches!(result, Err(AnonymousBallotCodecErrorV1::Codec(_))));
        assert_eq!(usage.total_elements(), 0);
        assert_eq!(usage.total_allocated_bytes(), BallotProofBytesV1::LENGTH);

        // Failed value construction drops its owners, but cumulative nominal
        // charges are never refunded. This does not measure physical deallocation.
        let limits =
            norito::DecodeLimits::new(0, usize::MAX, 0, BallotProofBytesV1::LENGTH, usize::MAX);
        let (second, usage) = norito::core::with_decode_limits_measured(limits, || {
            assert!(matches!(
                AnonymousBallotEnvelopeV1::decode_canonical_bounded(&bytes),
                Err(AnonymousBallotCodecErrorV1::Codec(_))
            ));
            AnonymousBallotEnvelopeV1::decode_canonical_bounded(&original)
        });
        let Err(AnonymousBallotCodecErrorV1::DecodeUnavailable(refusal)) = second else {
            panic!("the consumed enclosing budget must remain unavailable");
        };
        assert_eq!(
            refusal.kind(),
            norito::core::DecodeLocalRefusalKind::EnclosingLimit
        );
        assert_eq!(
            refusal.resource_error(),
            norito::core::DecodeResourceError::TotalAllocationExceeded {
                attempted: (2 * BallotProofBytesV1::LENGTH) as u64,
                limit: BallotProofBytesV1::LENGTH as u64,
            }
        );
        assert_eq!(refusal.allocation_bytes(), None);
        assert_eq!(usage.total_allocated_bytes(), BallotProofBytesV1::LENGTH);
        // A fresh call restores all failed-decode scopes and still roundtrips.
        assert_eq!(observe(&original).0, Ok(value.clone()));
    }
}

#[test]
fn binary_carrier_keeps_the_original_inner_proof_budget_refusal() {
    let value =
        CanonicalAnonymousBallotEnvelopeV1::from_envelope(&envelope(BallotChoiceV1::Aye, 1))
            .expect("canonical carrier");
    let bytes = enc(&value).expect("framed carrier");
    let count = value.as_bytes().len();
    assert_eq!(count, 233_455);
    // decode_vec_from_slice_with specializes Vec<u8> as u64 count + raw bytes:
    // read_seq_len_slice charges count metadata, then try_decode_vec_with_capacity
    // charges count owned bytes. It never enters the generic span/element planner.
    let carrier_charge = 2 * count;
    let complete_charge = carrier_charge + BallotProofBytesV1::LENGTH;
    assert_eq!(complete_charge, 699_922);
    let unrestricted =
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX);
    let (decoded, usage) = norito::core::with_decode_limits_measured(unrestricted, || {
        norito::decode_canonical_for_admission::<CanonicalAnonymousBallotEnvelopeV1>(
            &bytes,
            unrestricted,
        )
    });
    assert_eq!(decoded.expect("carrier roundtrip"), value);
    assert_eq!(usage.total_elements(), count);
    assert_eq!(usage.total_allocated_bytes(), complete_charge);

    let limit = complete_charge - 1;
    let enclosing =
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, limit, usize::MAX);
    let (refused, usage) = norito::core::with_decode_limits_measured(enclosing, || {
        norito::decode_canonical_for_admission::<CanonicalAnonymousBallotEnvelopeV1>(
            &bytes,
            unrestricted,
        )
    });
    let refused = refused.expect_err("the inner proof exceeds the enclosing budget");
    assert_eq!(
        refused.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert_eq!(
        refused.error().decode_resource_error(),
        Some(norito::core::DecodeResourceError::TotalAllocationExceeded {
            attempted: complete_charge as u64,
            limit: limit as u64,
        })
    );
    assert_eq!(usage.total_elements(), count);
    assert_eq!(usage.total_allocated_bytes(), carrier_charge);
}

#[test]
fn json_carrier_keeps_the_original_inner_proof_budget_refusal() {
    let value =
        CanonicalAnonymousBallotEnvelopeV1::from_envelope(&envelope(BallotChoiceV1::Nay, 1))
            .expect("canonical carrier");
    let text = norito::json::to_json(&value).expect("carrier JSON");
    let unrestricted =
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX);
    let (decoded, baseline) = norito::core::with_decode_limits_measured(unrestricted, || {
        norito::json::from_str::<CanonicalAnonymousBallotEnvelopeV1>(&text)
    });
    assert_eq!(decoded.expect("JSON roundtrip"), value);
    // Parsing the complete Fields record precedes its envelope validation hook.
    // Observe the parser's actual nominal charges, then leave exactly one byte
    // too little for the final inner proof copy. This is a regression fixture,
    // not an analytic bound for the JSON parser or physical allocation.
    let complete_charge = baseline.total_allocated_bytes();
    let parser_charge = complete_charge - BallotProofBytesV1::LENGTH;
    assert!(parser_charge > 0);
    let limit = complete_charge - 1;
    let enclosing =
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, limit, usize::MAX);
    let (refused, usage) = norito::core::with_decode_limits_measured(enclosing, || {
        norito::core::classify_decode_attempt(|| {
            norito::json::from_str::<CanonicalAnonymousBallotEnvelopeV1>(&text)
                .map_err(norito::json::Error::into_core_error)
        })
    });
    let refused = refused.expect_err("the inner proof exceeds the enclosing budget");
    assert_eq!(
        refused.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert_eq!(
        refused.error().decode_resource_error(),
        Some(norito::core::DecodeResourceError::TotalAllocationExceeded {
            attempted: complete_charge as u64,
            limit: limit as u64,
        })
    );
    assert_eq!(usage.total_allocated_bytes(), parser_charge);
}
