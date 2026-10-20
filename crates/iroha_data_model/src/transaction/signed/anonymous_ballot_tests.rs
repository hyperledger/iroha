//! Signerless entrypoint representation controls; fixtures do not assert proof validity.

use super::*;
use crate::governance::anonymous_ballot::{
    BallotChoiceV1, BallotProofBytesV1, CanonicalAnonymousBallotEnvelopeV1, test_fixtures,
};
use iroha_version::codec::{DecodeVersioned as _, EncodeVersioned as _};
use norito::{
    codec::DecodeAll as _,
    core::{DecodeAttemptErrorKind, DecodeFlagsGuard, DecodeResourceError},
    json::JsonSerialize as _,
};

fn carrier(vote: BallotChoiceV1) -> CanonicalAnonymousBallotEnvelopeV1 {
    CanonicalAnonymousBallotEnvelopeV1::from_envelope(&test_fixtures::envelope(vote, 7))
        .expect("canonical codec fixture; not a valid-proof claim")
}

fn entrypoint(vote: BallotChoiceV1) -> TransactionEntrypoint {
    TransactionEntrypoint::AnonymousBallot(carrier(vote))
}

fn limits(bytes: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}

/// Independent default-layout field framing for exact bytes and malformed carriers.
fn field(bytes: &[u8]) -> Vec<u8> {
    assert_eq!(
        norito::core::default_encode_flags(),
        norito::core::header_flags::COMPACT_LEN
    );
    let mut result = Vec::new();
    let mut length = bytes.len();
    while length >= 128 {
        result.push((length as u8 & 0x7f) | 0x80);
        length >>= 7;
    }
    result.push(length as u8);
    result.extend_from_slice(bytes);
    result
}

/// Test-only wire construction bypasses the private carrier solely to test refusal.
fn unchecked_wire(envelope: &[u8]) -> Vec<u8> {
    let mut sequence = (envelope.len() as u64).to_le_bytes().to_vec();
    sequence.extend_from_slice(envelope);
    let mut result = vec![1];
    result.extend_from_slice(&4_u32.to_le_bytes());
    result.extend_from_slice(&field(&field(&sequence)));
    result
}

#[test]
fn anonymous_ballot_entrypoint_tag_and_schema_leave_retired_three_unassigned() {
    let schema = TransactionEntrypoint::schema();
    let iroha_schema::Metadata::Enum(metadata) = schema
        .get::<TransactionEntrypoint>()
        .expect("entrypoint schema")
    else {
        panic!("entrypoint is an enum");
    };
    assert_eq!(
        metadata
            .variants
            .iter()
            .map(|variant| (variant.tag.as_str(), variant.discriminant))
            .collect::<Vec<_>>(),
        [
            ("External", 0),
            ("SealedCommitment", 1),
            ("SealedReveal", 2),
            ("AnonymousBallot", 4),
        ]
    );
    assert_eq!(
        metadata.variants[3].ty,
        Some(core::any::TypeId::of::<CanonicalAnonymousBallotEnvelopeV1>())
    );
    let _flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    assert_eq!(
        entrypoint(BallotChoiceV1::Aye).encode()[..4],
        4_u32.to_le_bytes()
    );
    for tag in [3_u32, 5, u32::MAX] {
        assert!(TransactionEntrypoint::decode_all(&mut &tag.to_le_bytes()[..]).is_err());
    }
}

#[test]
fn anonymous_ballot_entrypoint_preserves_exact_envelope_in_every_binary_form() {
    for vote in BallotChoiceV1::ALL {
        let carrier = carrier(vote);
        let original = carrier.as_bytes().to_vec();
        let entry = TransactionEntrypoint::from(carrier.clone());
        let wire = entry.encode_wire_v1().expect("fixed V1 wire");
        assert_eq!(wire, unchecked_wire(&original));
        assert_eq!(wire, entry.encode_versioned());
        assert_eq!(entry.wire_plan_v1().unwrap().wire_length(), wire.len());
        assert_eq!(entry.wire_plan_v1().unwrap().into_vec().unwrap(), wire);
        let decoded = TransactionEntrypoint::decode_all_versioned(&wire).unwrap();
        assert_eq!(decoded, entry);
        let decoded_carrier: CanonicalAnonymousBallotEnvelopeV1 = decoded.try_into().unwrap();
        assert_eq!(decoded_carrier.as_bytes(), original);
        assert_eq!(decoded_carrier.digest().unwrap(), carrier.digest().unwrap());
        let frame = norito::encode_canonical(&entry).unwrap();
        assert_eq!(
            norito::decode_canonical::<TransactionEntrypoint>(&frame).unwrap(),
            entry
        );
        let _flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        assert_eq!(
            TransactionEntrypoint::decode_from_slice(&wire[1..]).unwrap(),
            (entry, wire.len() - 1)
        );
    }
}

#[test]
fn anonymous_ballot_entrypoint_json_delegates_to_checked_carrier_and_exact_writer() {
    let entry = entrypoint(BallotChoiceV1::Nay);
    let carrier = carrier(BallotChoiceV1::Nay);
    let expected = format!(
        "{{\"AnonymousBallot\":{}}}",
        norito::json::to_json(&carrier).unwrap()
    );
    assert_eq!(norito::json::to_json(&entry).unwrap(), expected);
    assert_eq!(
        norito::json::from_str::<TransactionEntrypoint>(&expected).unwrap(),
        entry
    );
    assert_eq!(
        norito::json::to_json_bounded(&entry, expected.len()).unwrap(),
        expected
    );
    for cap in [0, 1, 18, expected.len() / 2, expected.len() - 1] {
        let mut sink = crate::checked_container_refusal_controls::OriginalSink::new(cap);
        assert_eq!(
            entry.json_serialize_to(&mut sink),
            Err(norito::json::BoundedJsonError::BodyTooLarge)
        );
        assert_eq!(
            sink.depth,
            crate::checked_container_refusal_controls::ORIGINAL_DEPTH
        );
        assert!(expected.starts_with(&sink.text));
    }
    for malformed in [
        r#"{"Time":null}"#.to_owned(),
        r#"{"AnonymousBallot":{"bytes":""}}"#.to_owned(),
        expected.replacen("\"AnonymousBallot\"", "\"anonymous_ballot\"", 1),
        format!("{},\"External\":null}}", &expected[..expected.len() - 1]),
        format!(
            "{},\"AnonymousBallot\":null}}",
            &expected[..expected.len() - 1]
        ),
        expected.replacen("\"bytes\":", "\"authority\":null,\"bytes\":", 1),
    ] {
        assert!(norito::json::from_str::<TransactionEntrypoint>(&malformed).is_err());
    }
}

#[test]
fn anonymous_ballot_entrypoint_refuses_bad_inner_frames_versions_and_suffixes() {
    let entry = entrypoint(BallotChoiceV1::Abstain);
    let original = carrier(BallotChoiceV1::Abstain).as_bytes().to_vec();
    let mut corrupt_magic = original.clone();
    corrupt_magic[0] ^= 1;
    let mut inner_suffix = original.clone();
    inner_suffix.push(0);
    for malformed in [
        Vec::new(),
        original[..original.len() - 1].to_vec(),
        corrupt_magic,
        inner_suffix,
    ] {
        let error = TransactionEntrypoint::decode_all_versioned(&unchecked_wire(&malformed))
            .expect_err("carrier hook must refuse malformed canonical envelope");
        assert!(!error.is_local_resource_refusal());
    }
    let wire = entry.encode_wire_v1().unwrap();
    for tag in [3_u32, 5, u32::MAX] {
        let mut changed = wire.clone();
        changed[1..5].copy_from_slice(&tag.to_le_bytes());
        assert!(TransactionEntrypoint::decode_all_versioned(&changed).is_err());
    }
    for version in [0, 2, u8::MAX] {
        let mut changed = wire.clone();
        changed[0] = version;
        assert!(matches!(
            TransactionEntrypoint::decode_all_versioned(&changed),
            Err(iroha_version::error::Error::UnsupportedVersion(_))
        ));
    }
    let mut suffix = wire.clone();
    suffix.push(0);
    assert!(TransactionEntrypoint::decode_all_versioned(&suffix).is_err());
    assert!(TransactionEntrypoint::decode_all_versioned(&wire[..wire.len() - 1]).is_err());
    assert_eq!(
        TransactionEntrypoint::decode_all_versioned(&wire).unwrap(),
        entry
    );
}

#[test]
fn anonymous_ballot_entrypoint_fixed_v1_ignores_and_restores_ambient_layout() {
    let entry = entrypoint(BallotChoiceV1::Aye);
    let canonical = entry.encode_wire_v1().unwrap();
    let _outer = DecodeFlagsGuard::enter(0);
    let alternate_length = norito::core::encoded_payload_len(&entry).unwrap();
    assert_ne!(alternate_length + 1, canonical.len());
    assert_eq!(entry.encode_wire_v1().unwrap(), canonical);
    assert_eq!(entry.wire_plan_v1().unwrap().into_vec().unwrap(), canonical);
    assert_eq!(
        TransactionEntrypoint::decode_all_versioned(&canonical).unwrap(),
        entry
    );
    assert_eq!(norito::core::effective_decode_flags(), Some(0));
    let mut alternate = vec![1];
    norito::core::serialize_to_buffer(&entry, &mut alternate).unwrap();
    assert!(TransactionEntrypoint::decode_all_versioned(&alternate).is_err());
    assert_eq!(norito::core::effective_decode_flags(), Some(0));
}

#[test]
fn anonymous_ballot_entrypoint_has_no_signed_authority_or_metadata_and_hashes_full_carrier() {
    let entry = entrypoint(BallotChoiceV1::Aye);
    assert_eq!(entry.authority_opt(), None);
    assert_eq!(entry.creation_time_ms(), None);
    assert_eq!(entry.metadata(), None);
    assert_eq!(entry.hash(), HashOf::new(&entry));
    assert_eq!(entry.execution_call_hash(), entry.hash());
    let original = test_fixtures::envelope(BallotChoiceV1::Aye, 7);
    let mut changed = original.clone();
    changed.ballot.proof = BallotProofBytesV1::new(vec![0xA5; BallotProofBytesV1::LENGTH]).unwrap();
    let changed = TransactionEntrypoint::AnonymousBallot(
        CanonicalAnonymousBallotEnvelopeV1::from_envelope(&changed).unwrap(),
    );
    assert_ne!(changed.hash(), entry.hash());
    assert_ne!(entrypoint(BallotChoiceV1::Nay).hash(), entry.hash());
    let signed = wire_v1_test_support::signed("advance");
    let external = TransactionEntrypoint::External(signed.clone());
    assert_eq!(external.authority_opt(), Some(signed.authority()));
    assert_eq!(external.creation_time_ms(), Some(42_001));
    assert_eq!(external.metadata(), Some(signed.metadata()));
    assert_eq!(external.hash(), signed.hash_as_entrypoint());
}

#[test]
fn anonymous_ballot_entrypoint_binary_retains_the_inner_local_refusal() {
    let entry = entrypoint(BallotChoiceV1::Aye);
    let wire = entry.encode_wire_v1().unwrap();
    let (decoded, baseline) = norito::core::with_decode_limits_measured(limits(usize::MAX), || {
        iroha_version::codec::decode_exact_versioned::<TransactionEntrypoint>(&wire)
    });
    assert_eq!(decoded.unwrap(), entry);
    let complete = baseline.total_allocated_bytes();
    let limit = complete - 1;
    let (refused, usage) = norito::core::with_decode_limits_measured(limits(limit), || {
        TransactionEntrypoint::decode_all_versioned(&wire)
    });
    let error = refused.expect_err("inner proof cannot fit the remaining enclosing allowance");
    assert!(error.is_local_resource_refusal());
    let iroha_version::error::Error::NoritoResourceLimit(ref attempt) = error else {
        panic!("inner refusal must retain its original codec owner: {error:?}");
    };
    assert_eq!(attempt.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert_eq!(
        attempt.error().decode_resource_error(),
        Some(DecodeResourceError::TotalAllocationExceeded {
            attempted: complete as u64,
            limit: limit as u64,
        })
    );
    assert_eq!(
        usage.total_allocated_bytes(),
        complete - BallotProofBytesV1::LENGTH
    );
    assert_eq!(
        TransactionEntrypoint::decode_all_versioned(&wire).unwrap(),
        entry
    );
}

#[test]
fn anonymous_ballot_entrypoint_json_retains_the_inner_local_refusal() {
    let entry = entrypoint(BallotChoiceV1::Nay);
    let text = norito::json::to_json(&entry).unwrap();
    let (decoded, baseline) = norito::core::with_decode_limits_measured(limits(usize::MAX), || {
        norito::json::from_str::<TransactionEntrypoint>(&text)
    });
    assert_eq!(decoded.unwrap(), entry);
    let complete = baseline.total_allocated_bytes();
    let limit = complete - 1;
    let (refused, usage) = norito::core::with_decode_limits_measured(limits(limit), || {
        norito::core::classify_decode_attempt(|| {
            norito::json::from_str::<TransactionEntrypoint>(&text)
                .map_err(norito::json::Error::into_core_error)
        })
    });
    let error = refused.expect_err("inner proof exceeds enclosing JSON allowance");
    assert_eq!(error.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert_eq!(
        error.error().decode_resource_error(),
        Some(DecodeResourceError::TotalAllocationExceeded {
            attempted: complete as u64,
            limit: limit as u64,
        })
    );
    assert_eq!(
        usage.total_allocated_bytes(),
        complete - BallotProofBytesV1::LENGTH
    );
    assert_eq!(
        norito::json::from_str::<TransactionEntrypoint>(&text).unwrap(),
        entry
    );
}
