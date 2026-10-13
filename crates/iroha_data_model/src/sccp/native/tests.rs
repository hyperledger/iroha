//! Codec and structural controls for native SCCP DATA; these do not certify signatures.

use super::*;
use crate::sccp::deployment::SccpCommitteePinV1;
use crate::{
    block::consensus::{
        EvidenceAttribution, EvidencePenaltyStatus, EvidenceRecord, EvidenceScope,
        RecordedEvidenceV1,
    },
    isi::sccp::SubmitSccpForgeryEvidenceV1,
    sccp::test_support::{assert_rejects_unknown_field, roundtrip},
};
use iroha_crypto::{Algorithm, KeyPair};
use norito::codec::DecodeAll;

fn account(seed: u8) -> AccountId {
    let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("fixture key");
    AccountId::new(key.public_key().clone())
}

fn pin() -> SccpCommitteePinV1 {
    SccpCommitteePinV1 {
        generation: 7,
        committee_root: [9; 32],
        start_height: 23,
        until_ms: 90_000,
    }
}

fn anchor() -> SccpAnchorWitnessV1 {
    SccpAnchorWitnessV1 {
        core_hash: [0; 32],
        result: [0; 32],
        path: [[7; 32]; 12],
    }
}

fn submission() -> SubmitSccpForgeryEvidenceV1 {
    // Deliberately syntax-only DATA, not a signature fixture or admission assertion.
    SubmitSccpForgeryEvidenceV1 {
        qc: [0xa1; 116],
        header: [0xb2; 221],
        aggregate_signature: [0xc3; 96],
        anchor: Some(anchor()),
    }
}

fn record() -> SccpForgeryRecordV1 {
    SccpForgeryRecordV1 {
        evidence: submission(),
        rule: SccpForgeryRuleV1::E4,
        generation: 7,
        start_height: 23,
        offenders: vec![SccpForgeryOffenderV1 {
            signer: 0,
            lane_id: LaneId::new(1),
            validator: account(3),
            activation_height: 19,
        }],
    }
}

#[test]
fn native_data_roundtrips_exact_original_bytes_and_closed_json() {
    let pin = pin();
    roundtrip(&pin);
    assert_rejects_unknown_field(&pin, &[]);
    let anchor = anchor();
    roundtrip(&anchor);
    assert_rejects_unknown_field(&anchor, &[]);
    let record = record();
    roundtrip(&record);
    assert_eq!(record.validate_shape(), Ok(()));
    for path in [
        &[][..],
        &["evidence"],
        &["evidence", "anchor"],
        &["offenders", "0"],
    ] {
        assert_rejects_unknown_field(&record, path);
    }
    let frame = norito::to_bytes(&record).expect("frame");
    let decoded: SccpForgeryRecordV1 = norito::decode_from_bytes(&frame).expect("decode");
    assert_eq!(decoded, record);
    assert_eq!(norito::to_bytes(&decoded).expect("exact frame"), frame);
    // Raw result all-zero bytes are retained, never normalized through iroha_crypto::Hash.
    assert_eq!(decoded.evidence.anchor.expect("anchor").result, [0; 32]);
    for rule in [
        SccpForgeryRuleV1::E1,
        SccpForgeryRuleV1::E2,
        SccpForgeryRuleV1::E3,
        SccpForgeryRuleV1::E4,
    ] {
        roundtrip(&rule);
    }
    let quarantine = SccpQuarantineV1 {
        certificate_id: [4; 32],
        since_height: 101,
    };
    roundtrip(&quarantine);
    assert_rejects_unknown_field(&quarantine, &[]);
}

#[test]
fn pin_checks_all_required_coordinates_without_claiming_authentication() {
    assert_eq!(pin().validate_shape(), Ok(()));
    for broken in [
        SccpCommitteePinV1 {
            generation: 0,
            ..pin()
        },
        SccpCommitteePinV1 {
            start_height: 0,
            ..pin()
        },
        SccpCommitteePinV1 {
            until_ms: 0,
            ..pin()
        },
    ] {
        assert_eq!(
            broken.validate_shape(),
            Err(SccpNativeDataError::ZeroPinCoordinate)
        );
    }
    assert_eq!(
        SccpCommitteePinV1 {
            committee_root: [0; 32],
            ..pin()
        }
        .validate_shape(),
        Err(SccpNativeDataError::ZeroCommitteeRoot)
    );
    // Retained-state equality and deadline margins are intentionally not a DATA predicate.
    assert_eq!(
        SccpCommitteePinV1 {
            until_ms: u64::MAX,
            ..pin()
        }
        .validate_shape(),
        Ok(())
    );
}

#[test]
fn forgery_record_preserves_new_offender_subset_and_rejects_bad_attribution_shape() {
    let good = record();
    assert_eq!(good.offenders.len(), 1); // not a replacement for the exact certificate quorum
    assert_eq!(good.validate_shape(), Ok(()));
    let mut bad = good.clone();
    bad.generation = 0;
    assert_eq!(
        bad.validate_shape(),
        Err(SccpNativeDataError::ZeroGenerationCoordinate)
    );
    bad = good.clone();
    bad.start_height = 0;
    assert_eq!(
        bad.validate_shape(),
        Err(SccpNativeDataError::ZeroGenerationCoordinate)
    );
    bad = good.clone();
    bad.offenders.clear();
    assert_eq!(
        bad.validate_shape(),
        Err(SccpNativeDataError::OffenderCount)
    );
    bad = good.clone();
    bad.offenders = vec![good.offenders[0].clone(); 32];
    assert_eq!(
        bad.validate_shape(),
        Err(SccpNativeDataError::OffenderCount)
    );
    bad = good.clone();
    bad.offenders[0].signer = 31;
    assert_eq!(
        bad.validate_shape(),
        Err(SccpNativeDataError::SignerOutOfRange)
    );
    for activation_height in [0, good.start_height + 1] {
        bad = good.clone();
        bad.offenders[0].activation_height = activation_height;
        assert_eq!(
            bad.validate_shape(),
            Err(SccpNativeDataError::ActivationHeight)
        );
    }
    bad = good.clone();
    bad.offenders.push(good.offenders[0].clone());
    assert_eq!(
        bad.validate_shape(),
        Err(SccpNativeDataError::OffenderOrder)
    );
    bad.offenders[1].signer = 1;
    assert_eq!(
        bad.validate_shape(),
        Err(SccpNativeDataError::DuplicateOffender)
    );
    bad.offenders[1].lane_id = LaneId::new(2);
    assert_eq!(bad.validate_shape(), Ok(())); // deduplication key includes lane
    bad.offenders.swap(0, 1);
    assert_eq!(
        bad.validate_shape(),
        Err(SccpNativeDataError::OffenderOrder)
    );
    let mut largest = good;
    largest.offenders = (0..31)
        .map(|i| SccpForgeryOffenderV1 {
            signer: i,
            lane_id: LaneId::new(i),
            validator: account(3),
            activation_height: 23,
        })
        .collect();
    assert_eq!(largest.validate_shape(), Ok(()));
    roundtrip(&largest);
}

#[test]
fn evidence_material_and_scope_are_closed_and_keep_penalty_timing_separate() {
    let original = record();
    let value = EvidenceRecord {
        evidence: RecordedEvidenceV1::SccpForgery(Box::new(original.clone())),
        attribution: EvidenceAttribution {
            scope: EvidenceScope::SccpGeneration {
                generation: original.generation,
            },
            instance: [1; 32],
            height: original.start_height,
            epoch: 9,
            context_id: [2; 32],
            authority_generation: pin().committee_root,
            offenders: vec![],
            safety_violation: true,
        },
        recorded_at_height: 101,
        recorded_at_view: 3,
        recorded_at_ms: 105_000,
        penalty_status: EvidencePenaltyStatus::Pending,
    };
    roundtrip(&value);
    let frame = norito::to_bytes(&value).expect("frame");
    let restored: EvidenceRecord = norito::decode_from_bytes(&frame).expect("decode");
    assert_eq!(restored, value);
    assert_ne!(restored.recorded_at_height, restored.attribution.height);
    assert!(!restored.penalty_status.is_terminal());
    for path in [&[][..], &["evidence"], &["attribution", "scope"]] {
        assert_rejects_unknown_field(&value, path);
    }
    // Neither a bare forgery record nor an unknown union alternative is accepted.
    assert!(
        norito::decode_from_bytes::<RecordedEvidenceV1>(
            &norito::to_bytes(&original).expect("bare record frame")
        )
        .is_err()
    );
    let mut json = norito::json::to_value(&value.evidence).expect("JSON");
    json.as_object_mut().expect("union").insert(
        "kind".to_owned(),
        norito::json::Value::String("bridge_attestation".to_owned()),
    );
    assert!(
        norito::json::from_json::<RecordedEvidenceV1>(
            &norito::json::to_json(&json).expect("JSON text")
        )
        .is_err()
    );
}

#[test]
fn native_schema_frames_and_exact_fixed_array_lengths_reject_substitution() {
    let submission = submission();
    roundtrip(&submission);
    roundtrip(&SubmitSccpForgeryEvidenceV1 {
        anchor: None,
        ..submission.clone()
    });
    let frame = norito::to_bytes(&submission).expect("frame");
    assert!(norito::decode_from_bytes::<SccpAnchorWitnessV1>(&frame).is_err());
    assert_ne!(
        norito::schema::identity::frame_hash::<SubmitSccpForgeryEvidenceV1>(),
        norito::schema::identity::frame_hash::<SccpAnchorWitnessV1>()
    );
    let mut trailing = submission.encode();
    trailing.push(0);
    assert!(SubmitSccpForgeryEvidenceV1::decode_all(&mut trailing.as_slice()).is_err());
    for (field, length) in [("qc", 116), ("header", 221), ("aggregate_signature", 96)] {
        for bad_length in [length - 1, length + 1] {
            let mut value = norito::json::to_value(&submission).expect("JSON");
            value.as_object_mut().expect("object").insert(
                field.to_owned(),
                norito::json::Value::Array(vec![norito::json::Value::from(1_u8); bad_length]),
            );
            assert!(
                norito::json::from_json::<SubmitSccpForgeryEvidenceV1>(
                    &norito::json::to_json(&value).expect("JSON text")
                )
                .is_err(),
                "{field} accepts {bad_length} bytes"
            );
        }
    }
    let mut value = norito::json::to_value(&submission).expect("JSON");
    value.as_object_mut().expect("object").remove("anchor");
    assert!(
        norito::json::from_json::<SubmitSccpForgeryEvidenceV1>(
            &norito::json::to_json(&value).expect("JSON text")
        )
        .is_err()
    );
    for length in [11, 13] {
        let mut value = norito::json::to_value(&anchor()).expect("JSON");
        let path = value
            .as_object_mut()
            .unwrap()
            .get_mut("path")
            .unwrap()
            .as_array_mut()
            .unwrap();
        path.resize(
            length,
            norito::json::to_value(&[7_u8; 32]).expect("sibling"),
        );
        assert!(
            norito::json::from_json::<SccpAnchorWitnessV1>(
                &norito::json::to_json(&value).expect("JSON text")
            )
            .is_err()
        );
    }
}

#[test]
fn closed_union_keeps_the_existing_native_evidence_parser() {
    use crate::block::consensus::Evidence;
    use iroha_sumeragi::{
        message::{Evidence as NativeEvidence, Vote, VoteKind},
        types::{EpochId, Hash32, Signature},
    };
    // Canonical native syntax only: these DATA signatures are not cryptographically verified.
    let first = Vote {
        kind: VoteKind::Commit,
        instance: Hash32([1; 32]),
        epoch: EpochId {
            epoch: 2,
            context: Hash32([3; 32]),
        },
        height: 4,
        view: 5,
        block_hash: Hash32([6; 32]),
        result: Hash32([7; 32]),
        signer: 0,
        sig: Signature([8; 96]),
    };
    let second = Vote {
        block_hash: Hash32([9; 32]),
        ..first
    };
    let original = Evidence::from_native(&NativeEvidence::VoteEquivocation(first, second))
        .expect("canonical native syntax");
    let closed = RecordedEvidenceV1::Native(original.clone());
    roundtrip(&closed);
    let restored: RecordedEvidenceV1 =
        norito::decode_from_bytes(&norito::to_bytes(&closed).expect("frame")).expect("decode");
    let RecordedEvidenceV1::Native(restored) = restored else {
        panic!("native branch retained")
    };
    assert_eq!(restored.native_frame(), original.native_frame());
    assert_eq!(
        restored.decode_native().unwrap(),
        original.decode_native().unwrap()
    );
    assert!(
        norito::decode_from_bytes::<RecordedEvidenceV1>(
            &norito::to_bytes(&original).expect("bare native frame")
        )
        .is_err()
    );
    let malformed = RecordedEvidenceV1::Native(Evidence { native: vec![] });
    assert!(
        norito::decode_from_bytes::<RecordedEvidenceV1>(
            &norito::to_bytes(&malformed).expect("encode DATA")
        )
        .is_err()
    );
}

#[test]
fn anchor_json_requires_twelve_hex_siblings_and_preserves_bounded_output() {
    use norito::json::{self, Value};

    let value = anchor();
    let encoded = json::to_json(&value).expect("anchor JSON");
    assert_eq!(
        json::from_json::<SccpAnchorWitnessV1>(&encoded).expect("fixed path"),
        value
    );
    assert_eq!(
        json::to_json_bounded(&value, encoded.len()).expect("exact byte budget"),
        encoded
    );
    assert!(json::to_json_bounded(&value, encoded.len() - 1).is_err());
    let mut document = json::to_value(&value).expect("anchor DATA");
    let path = document.get("path").unwrap().as_array().unwrap();
    assert_eq!(path.len(), SCCP_ANCHOR_PATH_DEPTH_V1);
    assert!(
        path.iter()
            .all(|sibling| sibling.as_str() == Some(&"07".repeat(32)))
    );
    for count in [0, 11, 13] {
        document.as_object_mut().unwrap().insert(
            "path".to_owned(),
            Value::Array(vec![Value::String("07".repeat(32)); count]),
        );
        let malformed = json::to_json(&document).unwrap();
        assert!(json::from_json::<SccpAnchorWitnessV1>(&malformed).is_err());
    }
    for sibling in [
        Value::String("07".repeat(31)),
        Value::Null,
        Value::Array(vec![]),
    ] {
        let mut path = vec![Value::String("07".repeat(32)); SCCP_ANCHOR_PATH_DEPTH_V1];
        path[11] = sibling;
        document
            .as_object_mut()
            .unwrap()
            .insert("path".to_owned(), Value::Array(path));
        assert!(
            json::from_json::<SccpAnchorWitnessV1>(&json::to_json(&document).unwrap()).is_err()
        );
    }
}

#[test]
fn recorded_evidence_keeps_native_stack_shell_small() {
    // Adding a large forgery witness must not make every ordinary consensus
    // evidence value reserve that inline frame during restore or verification.
    assert!(
        std::mem::size_of::<RecordedEvidenceV1>()
            <= std::mem::size_of::<crate::block::consensus::Evidence>()
                + 2 * std::mem::size_of::<usize>()
    );
}

#[test]
fn recorded_evidence_uses_one_boxed_binary_layout_and_direct_json_record() {
    let original = record();
    let value = RecordedEvidenceV1::SccpForgery(Box::new(original.clone()));
    let record_bytes = original.encode();
    let flags = norito::core::header_flags::COMPACT_LEN;
    assert_eq!(norito::core::default_encode_flags(), flags);
    // The first-release contract is tag 1, the variant-field length, then the
    // owned-record length and exact record bytes. These are distinct prefixes.
    let mut owned = Vec::new();
    norito::core::write_len_to_vec_with_flags(
        &mut owned,
        u64::try_from(record_bytes.len()).unwrap(),
        flags,
    );
    owned.extend_from_slice(&record_bytes);
    let mut expected = 1_u32.to_le_bytes().to_vec();
    norito::core::write_len_to_vec_with_flags(
        &mut expected,
        u64::try_from(owned.len()).unwrap(),
        flags,
    );
    expected.extend_from_slice(&owned);
    assert_eq!(value.encode(), expected);
    assert_eq!(
        RecordedEvidenceV1::decode_all(&mut expected.as_slice()).unwrap(),
        value
    );
    let mut unboxed = 1_u32.to_le_bytes().to_vec();
    norito::core::write_len_to_vec_with_flags(
        &mut unboxed,
        u64::try_from(record_bytes.len()).unwrap(),
        flags,
    );
    unboxed.extend_from_slice(&record_bytes);
    assert!(RecordedEvidenceV1::decode_all(&mut unboxed.as_slice()).is_err());
    expected.push(0);
    assert!(RecordedEvidenceV1::decode_all(&mut expected.as_slice()).is_err());
    let json = norito::json::to_json(&value).unwrap();
    assert_eq!(
        json,
        format!(
            "{{\"kind\":\"sccp_forgery\",\"value\":{}}}",
            norito::json::to_json(&original).unwrap()
        )
    );
    assert_eq!(
        norito::json::from_json::<RecordedEvidenceV1>(&json).unwrap(),
        value
    );
}
