//! Real signed-envelope/private-journal controls only; these construct no native finality claim.

use super::*;
use iroha_crypto::{Algorithm, Hash, HashOf};
use iroha_data_model::{
    isi::{InstructionBox, musubi::AdvanceMusubiPinOutboxV1},
    transaction::FeeChargeKind,
    transaction::FeeChargeLimit,
};
use iroha_primitives::{numeric::Quantity, time::TimeSource};
use std::{collections::BTreeMap, num::NonZeroU32, time::Duration};

fn fixture() -> (KeyPair, SlotRequest, TransactionPayload) {
    let key = KeyPair::from_seed(vec![71; 32], Algorithm::Ed25519);
    let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"native slot codec only",
    )));
    let authority = AccountId::new(key.public_key().clone());
    let action: InstructionBox = AdvanceMusubiPinOutboxV1 {
        network_id: network,
        pin_authority: authority.clone(),
        session_id: [5; 32],
        expected_revision: 0,
        expected_inventory_digest: [0; 32],
        inventory_digest: [6; 32],
    }
    .into();
    let asset: iroha_data_model::asset::AssetDefinitionId =
        crate::musubi_publication_service::native_pin::authorization::test_asset(7);
    let fees = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            asset.clone(),
            Quantity::from(1u64),
        )],
        None,
    );
    let request = SlotRequest {
        network,
        authority: authority.clone(),
        session: [5; 32],
        operation: [7; 32],
        kind: SlotKind::Initialize,
        pin_selected_at_unix_ms: None,
        instruction: encode_frame(&action).unwrap(),
        authorization: NativePinAuthorizationV1 {
            deadline_unix_ms: 200_000,
            max_check_rounds: 4,
            per_transaction: fees.clone(),
            max_total_fees: BTreeMap::from([(asset, Quantity::from(8u64))]),
        },
    };
    let mut builder = TransactionBuilder::new_with_time_source(
        network,
        authority,
        &TimeSource::new_fixed(Duration::from_millis(1_000)),
        fees,
    )
    .with_instructions([action]);
    builder.set_nonce(NonZeroU32::new(91).unwrap());
    (key, request, builder.into_payload().unwrap())
}

#[test]
fn durable_payload_signed_original_and_exposure_reopen_without_requoting_or_resigning() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("control");
    let (key, request, payload) = fixture();
    let expected: norito::json::Value =
        norito::json::from_slice(&norito::json::to_vec(&request).unwrap()).unwrap();
    let mut slot = Slot::create(&path, request).unwrap();
    assert!(slot.payload().unwrap().is_none());
    assert!(slot.signed().is_none());
    slot.retain_payload(&payload).unwrap();
    slot.sign_original(
        &key,
        &mut crate::musubi_publication_service::native_pin::authorization::FixedClock(1_001),
        std::time::Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    let wire = slot.signed().unwrap().encode_wire_v1().unwrap();
    assert!(slot.record_exposure().unwrap());
    assert!(!slot.record_exposure().unwrap());
    drop(slot);
    let expected: SlotRequest =
        norito::json::from_slice(&norito::json::to_vec(&expected).unwrap()).unwrap();
    let slot = Slot::open(&path, &expected).unwrap();
    assert_eq!(slot.signed().unwrap().encode_wire_v1().unwrap(), wire);
    assert_eq!(slot.payload().unwrap().unwrap(), payload);
    assert!(slot.exposed().unwrap());
    assert!(!slot.record_exposure().unwrap());
    assert!(slot.retire_request_only().is_err());
}

#[test]
fn refused_signed_write_retains_original_graph_before_any_later_fallible_work() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("control");
    let (key, request, payload) = fixture();
    let mut slot = Slot::create(&path, request).unwrap();
    slot.retain_payload(&payload).unwrap();
    // A complete but wrong fixed-stage value simulates an occupied conflicting durable name.
    slot.journal
        .write_native(NativeRecord::Operation, &norito::json!({"unexpected":true}))
        .unwrap();
    assert!(
        slot.sign_original(
            &key,
            &mut crate::musubi_publication_service::native_pin::authorization::FixedClock(1_001),
            std::time::Instant::now() + Duration::from_secs(30)
        )
        .is_err()
    );
    let original = slot.signed().unwrap().encode_wire_v1().unwrap();
    let different = KeyPair::from_seed(vec![72; 32], Algorithm::Ed25519);
    assert!(
        slot.sign_original(
            &different,
            &mut crate::musubi_publication_service::native_pin::authorization::FixedClock(1_002),
            std::time::Instant::now() + Duration::from_secs(30)
        )
        .is_err()
    );
    assert_eq!(slot.signed().unwrap().encode_wire_v1().unwrap(), original);
    assert!(!path.join("submission.json").exists());
}

#[test]
fn expiry_and_request_only_retirement_never_prepare_another_payload_or_signature() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("expired");
    let (key, request, payload) = fixture();
    let mut slot = Slot::create(&path, request).unwrap();
    slot.retain_payload(&payload).unwrap();
    assert!(
        slot.sign_original(
            &key,
            &mut crate::musubi_publication_service::native_pin::authorization::FixedClock(101_000),
            std::time::Instant::now() + Duration::from_secs(30)
        )
        .is_err()
    ); // exact original default100s TTL.
    assert!(slot.signed().is_none());
    assert!(!path.join("operation.json").exists());
    let (_, request, payload) = fixture();
    let path = root.path().join("retired");
    let slot = Slot::create(&path, request).unwrap();
    slot.retire_request_only().unwrap();
    assert!(slot.retain_payload(&payload).is_err());
    assert!(!path.join("payload.json").exists());
    assert!(!path.join("submission.json").exists());
}

#[test]
fn full_original_payload_and_request_substitutions_refuse() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("control");
    let (_, request, payload) = fixture();
    let slot = Slot::create(&path, request).unwrap();
    slot.retain_payload(&payload).unwrap();
    for changed in [
        {
            let mut value = payload.clone();
            value.nonce = NonZeroU32::new(92);
            value
        },
        {
            let mut value = payload.clone();
            value.creation_time_ms += 1;
            value
        },
        {
            let mut value = payload.clone();
            value.fee_payment = FeePaymentIntent::authority(vec![], None);
            value
        },
    ] {
        assert!(slot.retain_payload(&changed).is_err());
    }
    drop(slot);
    let (_, mut expected, _) = fixture();
    expected.operation[0] ^= 1;
    assert!(Slot::open(&path, &expected).is_err());
    let (_, mut wrong, _) = fixture();
    wrong.kind = SlotKind::Pin;
    assert!(Slot::create(&root.path().join("wrong-purpose"), wrong).is_err());
    assert!(!root.path().join("wrong-purpose").exists());
}

#[test]
fn moving_exposed_graph_consumes_the_slot_and_reopen_never_creates_another_dispatch() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("control");
    let (key, request, payload) = fixture();
    let mut slot = Slot::create(&path, request).unwrap();
    slot.retain_payload(&payload).unwrap();
    slot.sign_original(
        &key,
        &mut crate::musubi_publication_service::native_pin::authorization::FixedClock(1_001),
        std::time::Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    let original = slot.signed().unwrap().encode_wire_v1().unwrap();
    assert!(slot.record_exposure().unwrap());
    let moved = slot.into_exposed_transaction().unwrap();
    assert_eq!(moved.encode_wire_v1().unwrap(), original);
    let reopened = Slot::open_retained(&path).unwrap();
    assert_eq!(
        reopened.signed().unwrap().encode_wire_v1().unwrap(),
        original
    );
    assert!(!reopened.record_exposure().unwrap());
}

#[test]
fn canonical_frames_reject_substitutions_and_preserve_inherited_raw_allocation_limit() {
    let (_, _, payload) = fixture();
    let frame = encode_frame(&payload).unwrap();
    assert_eq!(decode_frame::<TransactionPayload>(&frame).unwrap(), payload);
    for changed in [
        frame.to_uppercase(),
        format!("{frame}00"),
        frame[..frame.len() - 2].to_owned(),
    ] {
        assert!(decode_frame::<TransactionPayload>(&changed).is_err());
    }
    let zero = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
    for refused in [
        norito::with_decode_limits_scope(zero, || encode_frame(&payload).map(|_| ())),
        norito::with_decode_limits_scope(zero, || {
            decode_frame::<TransactionPayload>(&frame).map(|_| ())
        }),
    ] {
        assert!(matches!(
            refused.unwrap_err().downcast_ref::<norito::Error>(),
            Some(norito::Error::TotalAllocationExceeded { .. })
        ));
    }
    assert_eq!(decode_frame::<TransactionPayload>(&frame).unwrap(), payload);
}

#[test]
fn pin_selection_field_is_explicit_and_controls_cannot_claim_a_pin_time() {
    let (_, request, _) = fixture();
    let json = norito::json::to_json(&request).unwrap();
    assert!(json.contains("\"pin_selected_at_unix_ms\":null"));
    assert_eq!(
        norito::json::from_str::<SlotRequest>(&json).unwrap(),
        request
    );
    let missing = json.replace("\"pin_selected_at_unix_ms\":null,", "");
    assert_ne!(missing, json);
    assert!(norito::json::from_str::<SlotRequest>(&missing).is_err());
    let mut changed: SlotRequest = norito::json::from_str(&json).unwrap();
    changed.pin_selected_at_unix_ms = Some(1_000);
    assert!(changed.validate().is_err());
}

#[test]
fn held_slot_inspection_refuses_missing_or_replaced_request_and_extraneous_later_records() {
    for corruption in [
        "missing",
        "replacement",
        "applied.json",
        "submission.json",
        "retired.json",
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("held");
        let (_, request, _) = fixture();
        let slot = Slot::create(&path, request).unwrap();
        slot.require_path(&path).unwrap();
        match corruption {
            "missing" => std::fs::remove_file(path.join("preparation.json")).unwrap(),
            "replacement" => {
                let (_, mut changed, _) = fixture();
                changed.operation[0] ^= 1;
                iroha_fs::PrivateDirectory::open(&path)
                    .unwrap()
                    .write_atomic(
                        "preparation.json",
                        &norito::json::to_vec(&changed).unwrap(),
                        iroha_fs::PublishMode::Replace,
                    )
                    .unwrap();
            }
            name => iroha_fs::PrivateDirectory::open(&path)
                .unwrap()
                .write_atomic(name, b"{}", iroha_fs::PublishMode::CreateNew)
                .unwrap(),
        }
        assert!(slot.require_path(&path).is_err(), "{corruption}");
        assert!(slot.signed().is_none());
        assert!(!path.join("payload.json").exists());
    }
}

#[test]
fn held_slot_inspection_preserves_pending_signature_but_refuses_lost_persisted_original() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("held");
    let (key, request, payload) = fixture();
    let mut slot = Slot::create(&path, request).unwrap();
    slot.retain_payload(&payload).unwrap();
    slot.journal
        .write_native(NativeRecord::Operation, &norito::json!({"wrong": true}))
        .unwrap();
    assert!(
        slot.sign_original(
            &key,
            &mut crate::musubi_publication_service::native_pin::authorization::FixedClock(1_001),
            Instant::now() + Duration::from_secs(30)
        )
        .is_err()
    );
    let original = slot.signed().unwrap().encode_wire_v1().unwrap();
    assert!(slot.require_path(&path).is_err());
    // Remove only the injected conflict: the still-owned signature has never been durably stored.
    std::fs::remove_file(path.join("operation.json")).unwrap();
    slot.require_path(&path).unwrap();
    assert_eq!(slot.signed().unwrap().encode_wire_v1().unwrap(), original);
    assert!(
        !path.join("operation.json").exists(),
        "inspection does not repair custody"
    );
    slot.persist_signed().unwrap();
    slot.require_path(&path).unwrap();
    std::fs::remove_file(path.join("operation.json")).unwrap();
    assert!(
        slot.require_path(&path).is_err(),
        "a once-persisted signature cannot disappear"
    );
    assert_eq!(slot.signed().unwrap().encode_wire_v1().unwrap(), original);
    assert!(!path.join("submission.json").exists());
}

#[test]
fn held_exposed_slot_revalidates_exact_signature_and_submission_bytes() {
    for name in ["operation.json", "submission.json", "payload.json"] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("held");
        let (key, request, payload) = fixture();
        let mut slot = Slot::create(&path, request).unwrap();
        slot.retain_payload(&payload).unwrap();
        slot.sign_original(
            &key,
            &mut crate::musubi_publication_service::native_pin::authorization::FixedClock(1_001),
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
        slot.record_exposure().unwrap();
        slot.require_path(&path).unwrap();
        let original = slot.signed().unwrap().encode_wire_v1().unwrap();
        iroha_fs::PrivateDirectory::open(&path)
            .unwrap()
            .write_atomic(name, b"{}", iroha_fs::PublishMode::Replace)
            .unwrap();
        assert!(slot.require_path(&path).is_err(), "{name}");
        assert_eq!(slot.signed().unwrap().encode_wire_v1().unwrap(), original);
    }
}

#[test]
fn slot_frame_charges_one_raw_frame_and_its_distinct_hex_destination() {
    let value = vec![0x37_u8; 64];
    let canonical = norito::encode_canonical(&value).unwrap();
    let expected = hex::encode(&canonical);
    let length = canonical.len();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, length * 3, 128);
    norito::with_decode_limits_scope(limits, || {
        assert_eq!(encode_frame(&value).unwrap(), expected);
        let error = encode_frame(&value).unwrap_err();
        assert!(matches!(error.downcast_ref::<norito::Error>(),
            Some(norito::Error::TotalAllocationExceeded { attempted, limit })
                if *attempted == (length * 4) as u64 && *limit == (length * 3) as u64));
    });
}
