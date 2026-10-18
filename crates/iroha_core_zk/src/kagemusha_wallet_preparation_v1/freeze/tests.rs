//! Private assembly/codec checks. Fixture sigma bytes never reach an admission verifier.

use super::*;

fn capsule() -> KagemushaWalletRecoveryCapsuleV1 {
    let all: norito::json::Value = norito::json::from_str(include_str!(
        "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .unwrap();
    let row = all["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| {
            row["type"].as_str() == Some("KagemushaWalletRecoveryCapsuleV1")
                && row["variant"].as_str() == Some("Receive")
        })
        .unwrap();
    norito::decode_from_bytes(&hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap())
        .unwrap()
}
fn credential(capsule: &KagemushaWalletRecoveryCapsuleV1) -> KagemushaWalletCredentialV1 {
    let original = retained_original(
        &capsule.body().retained_inputs,
        KagemushaWalletRetainedInputRoleV1::Request,
    )
    .unwrap();
    let request: KagemushaWalletRequestV1 = norito::decode_from_bytes(original).unwrap();
    request.receiver_credential
}
fn input(capsule: &KagemushaWalletRecoveryCapsuleV1) -> CapsuleFields<'_> {
    CapsuleFields {
        manifest: [7; 32],
        source: capsule.body().predecessor_capsule_digest,
        state: &capsule.body().successor_state,
        statement: &capsule.body().statement,
        predecessor: None,
        payment: capsule.body().payment_digest,
        openings: capsule.body().map_openings.clone(),
        retained: capsule.body().retained_inputs.clone(),
    }
}
#[test]
fn private_receive_assembly_preserves_all_originals_and_derives_identity_and_output() {
    let original = capsule();
    let frozen = assemble(
        &credential(&original),
        input(&original),
        original.body().step_proof.clone(),
    )
    .unwrap();
    assert_eq!(frozen.body.body(), original.body());
    frozen
        .require_matches(&FrozenTransition {
            credential: credential(&original),
            capsule: original.clone(),
        })
        .unwrap();
    assert_eq!(
        norito::encode_canonical(frozen.body.body()).unwrap(),
        norito::encode_canonical(original.body()).unwrap()
    );
}
#[test]
fn private_assembly_rejects_missing_role_and_wrong_payment_source_or_credential() {
    let original = capsule();
    let owner = credential(&original);
    let mut fields = input(&original);
    fields.retained.clear();
    assert!(assemble(&owner, fields, original.body().step_proof.clone()).is_err());
    let mut fields = input(&original);
    fields.payment = [0; 32];
    assert!(assemble(&owner, fields, original.body().step_proof.clone()).is_err());
    let mut fields = input(&original);
    fields.source = [0; 32];
    assert!(assemble(&owner, fields, original.body().step_proof.clone()).is_err());
    let mut wrong = owner;
    wrong.body.wallet_id[0] ^= 1;
    assert!(assemble(&wrong, input(&original), original.body().step_proof.clone()).is_err());
}
#[test]
fn prepared_native_insertions_retain_exact_low_and_intermediate_empty_openings() {
    let mut tree = KagemushaWalletIndexedTreeV1::new();
    let mut model = vec![];
    let mut native = vec![];
    for (key, value) in [(11, 13), (3, 5), (17, 19)] {
        let insert = tree
            .insert(Fp::from(key).to_repr(), Fp::from(value).to_repr())
            .unwrap();
        model.extend([
            insert.low_opening.leaf_transcript(&insert.low),
            insert.slot_opening.empty_transcript(),
        ]);
        native.push(monetary::insertion(&insert).unwrap());
    }
    assert_eq!(map_openings(&native), model);
    assert!(map_openings(&[]).is_empty());
    for original in model {
        KagemushaWalletIndexedOpeningV1::from_transcript(&original).unwrap();
    }
}

#[test]
fn zero_send_fee_noop_preserves_exact_canonical_body_bytes() {
    // Codec projection only; the vector's fixture proof never reaches admission.
    // Preserve every body field while comparing the exact map_openings generated
    // by a pending-only Send before and after adding the transient fold witness.
    let mut pending_tree = KagemushaWalletIndexedTreeV1::new();
    let pending = pending_tree
        .insert(Fp::from(211).to_repr(), Fp::from(223).to_repr())
        .unwrap();
    let pending_originals = vec![
        pending.low_opening.leaf_transcript(&pending.low),
        pending.slot_opening.empty_transcript(),
    ];
    let original = capsule();
    let mut original_body = original.body().clone();
    original_body.map_openings = pending_originals.clone();
    let original_bytes = norito::encode_canonical(&original_body).unwrap();
    for populated in [false, true] {
        let mut fee_tree = KagemushaWalletIndexedTreeV1::new();
        if populated {
            fee_tree
                .insert(Fp::from(3).to_repr(), Fp::from(5).to_repr())
                .unwrap();
        }
        let root = fee_tree.root();
        let fee = KagemushaWalletFeeClaimLeafV1 {
            credit_id: Fp::from(233).to_repr(),
            fee: 0,
            fee_schedule_digest: Fp::from(19).to_repr(),
        };
        let slot = u32::from(populated);
        let leaf = fee_tree.leaf_at(slot).unwrap();
        let opening = fee_tree.opening(slot);
        let (_, transient) =
            monetary::send_fee_map(&root, fee, &SendFeeMapV1::Preserve { leaf, opening }).unwrap();
        let insertions = monetary::send_insertions(&pending, fee.fee, &transient).unwrap();
        assert_eq!(insertions.len(), 1);
        let mut regenerated = original_body.clone();
        regenerated.map_openings = map_openings(&insertions);
        assert_eq!(regenerated.map_openings, pending_originals);
        assert_eq!(
            norito::encode_canonical(&regenerated).unwrap(),
            original_bytes
        );
        // Pin the actual defect: adding a no-op as a second canonical insertion
        // changes complete body bytes even though the fee root did not change.
        let mut wrong = original_body.clone();
        wrong.map_openings = map_openings(&[insertions[0], transient]);
        assert_ne!(norito::encode_canonical(&wrong).unwrap(), original_bytes);
        assert_eq!(fee_tree.root(), root);
    }
}

#[test]
fn positive_send_fee_retains_both_exact_canonical_insertions() {
    let mut pending_tree = KagemushaWalletIndexedTreeV1::new();
    let pending = pending_tree
        .insert(Fp::from(211).to_repr(), Fp::from(223).to_repr())
        .unwrap();
    let mut fee_tree = KagemushaWalletIndexedTreeV1::new();
    let root = fee_tree.root();
    let fee = KagemushaWalletFeeClaimLeafV1 {
        credit_id: Fp::from(233).to_repr(),
        fee: 11,
        fee_schedule_digest: Fp::from(19).to_repr(),
    };
    let inserted = fee_tree
        .insert(fee.key(), fee.leaf_value().unwrap())
        .unwrap();
    let (_, witness) = monetary::send_fee_map(&root, fee, &SendFeeMapV1::Insert(inserted)).unwrap();
    let actual = map_openings(&monetary::send_insertions(&pending, fee.fee, &witness).unwrap());
    let expected = vec![
        pending.low_opening.leaf_transcript(&pending.low),
        pending.slot_opening.empty_transcript(),
        inserted.low_opening.leaf_transcript(&inserted.low),
        inserted.slot_opening.empty_transcript(),
    ];
    assert_eq!(actual, expected);
    assert_eq!(
        norito::encode_canonical(&actual).unwrap(),
        norito::encode_canonical(&expected).unwrap()
    );
}
