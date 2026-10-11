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
        &capsule.retained_inputs,
        KagemushaWalletRetainedInputRoleV1::Request,
    )
    .unwrap();
    let request: KagemushaWalletRequestV1 = norito::decode_from_bytes(original).unwrap();
    request.receiver_credential
}
fn input(capsule: &KagemushaWalletRecoveryCapsuleV1) -> CapsuleFields<'_> {
    CapsuleFields {
        manifest: [7; 32],
        source: capsule.predecessor_capsule_digest,
        state: &capsule.successor_state,
        statement: &capsule.statement,
        predecessor: None,
        payment: capsule.payment_digest,
        openings: capsule.map_openings.clone(),
        retained: capsule.retained_inputs.clone(),
    }
}
#[test]
fn private_receive_assembly_preserves_all_originals_and_derives_identity_and_output() {
    let original = capsule();
    let frozen = assemble(
        credential(&original),
        input(&original),
        original.step_proof.clone(),
    )
    .unwrap();
    assert_eq!(frozen.capsule, original);
    frozen.validate().unwrap();
    assert_eq!(
        norito::encode_canonical(&frozen.capsule).unwrap(),
        norito::encode_canonical(&original).unwrap()
    );
}
#[test]
fn private_assembly_rejects_missing_role_and_wrong_payment_source_or_credential() {
    let original = capsule();
    let owner = credential(&original);
    let mut fields = input(&original);
    fields.retained.clear();
    assert!(assemble(owner, fields, original.step_proof.clone()).is_err());
    let mut fields = input(&original);
    fields.payment = [0; 32];
    assert!(assemble(owner, fields, original.step_proof.clone()).is_err());
    let mut fields = input(&original);
    fields.source = [0; 32];
    assert!(assemble(owner, fields, original.step_proof.clone()).is_err());
    let mut wrong = owner;
    wrong.body.wallet_id[0] ^= 1;
    assert!(assemble(wrong, input(&original), original.step_proof.clone()).is_err());
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
