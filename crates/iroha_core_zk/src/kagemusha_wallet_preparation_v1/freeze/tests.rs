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
        credential(&original),
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
    assert!(assemble(owner, fields, original.body().step_proof.clone()).is_err());
    let mut fields = input(&original);
    fields.payment = [0; 32];
    assert!(assemble(owner, fields, original.body().step_proof.clone()).is_err());
    let mut fields = input(&original);
    fields.source = [0; 32];
    assert!(assemble(owner, fields, original.body().step_proof.clone()).is_err());
    let mut wrong = owner;
    wrong.body.wallet_id[0] ^= 1;
    assert!(assemble(wrong, input(&original), original.body().step_proof.clone()).is_err());
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
fn opening_sampler_accepts_zero_and_canonical_field_edge_without_reduction() {
    let zero = sample_opening(|out| {
        *out = [0; 32];
        Ok(())
    })
    .unwrap();
    assert_eq!(*zero, [0; 32]);
    let mut high_zero = [0; 32];
    high_zero[31] = 0x80;
    assert_eq!(
        *sample_opening(|out| {
            *out = high_zero;
            Ok(())
        })
        .unwrap(),
        [0; 32]
    );
    let lower = Fp::from(19).to_repr();
    let mut high = lower;
    high[31] |= 0x80;
    assert_eq!(
        *sample_opening(|out| {
            *out = high;
            Ok(())
        })
        .unwrap(),
        lower
    );
    let edge = (-Fp::from(1)).to_repr();
    assert_eq!(
        *sample_opening(|out| {
            *out = edge;
            Ok(())
        })
        .unwrap(),
        edge
    );
}

#[test]
fn opening_sampler_rejects_noncanonical_candidates_and_stops_at128_or_first_error() {
    let mut modulus = (-Fp::from(1)).to_repr();
    let mut carry = true;
    for byte in &mut modulus {
        let (sum, overflow) = byte.overflowing_add(u8::from(carry));
        *byte = sum;
        carry = overflow;
    }
    assert!(!carry);
    let mut above = modulus;
    above[0] += 1;
    for rejected in [modulus, above, [255; 32]] {
        let mut fills = 0;
        let actual = sample_opening(|out| {
            fills += 1;
            *out = if fills == 1 { rejected } else { [0; 32] };
            Ok(())
        })
        .unwrap();
        assert_eq!(
            fills, 2,
            "noncanonical candidate must be rejected, not reduced"
        );
        assert_eq!(*actual, [0; 32]);
    }
    let mut calls = 0;
    assert!(matches!(
        sample_opening(|out| {
            calls += 1;
            *out = [255; 32];
            Ok(())
        }),
        Err(Error::Entropy)
    ));
    assert_eq!(calls, 128);
    calls = 0;
    assert!(matches!(
        sample_opening(|_| {
            calls += 1;
            Err(Error::Entropy)
        }),
        Err(Error::Entropy)
    ));
    assert_eq!(calls, 1);
    calls = 0;
    let actual = sample_opening(|out| {
        calls += 1;
        *out = if calls == 1 { [255; 32] } else { [0; 32] };
        Ok(())
    })
    .unwrap();
    assert_eq!(calls, 2);
    assert_eq!(*actual, [0; 32]);
}

#[test]
fn retained_verification_reconstructs_only_body_and_preserves_exact_wrapper() {
    let original = capsule();
    let body = assemble(
        credential(&original),
        input(&original),
        original.body().step_proof.clone(),
    )
    .unwrap();
    let held = FrozenTransition {
        credential: credential(&original),
        capsule: original.clone(),
    };
    let exact = held.capsule.to_canonical_bytes();
    for _ in 0..2 {
        body.require_matches(&held).unwrap();
    }
    assert_eq!(held.capsule.to_canonical_bytes(), exact);
    assert_eq!(held.capsule.custody_digest(), original.custody_digest());
    assert_eq!(
        held.capsule.receipt_commitment(),
        original.receipt_commitment()
    );
    let mut other = held;
    let mut wrong = other.capsule.body().clone();
    wrong.step_proof.bytes.push(1);
    wrong.output = KagemushaWalletOutputDescriptorV1::for_transition(
        &wrong.statement,
        &wrong.proof_digest().unwrap(),
        &wrong.payment_digest,
    )
    .unwrap();
    other.capsule = wrong.freeze().unwrap().seal([0; 32]).unwrap();
    assert!(body.require_matches(&other).is_err());
}
