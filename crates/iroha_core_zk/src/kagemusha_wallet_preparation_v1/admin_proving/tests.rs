//! Exact adapter bindings only; stand-in fixture bytes never reach a verifier.

use ff::Field;

use super::*;
use crate::kagemusha_wallet_artifacts_v1::ArtifactOriginalV1;

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
                && row["variant"].as_str() == Some("QuotaShare, 64 retained predecessor slots")
        })
        .unwrap();
    let bytes = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
    norito::decode_from_bytes(&bytes).unwrap()
}

#[test]
fn admin_statement_binds_exact_all_fields_and_operation() {
    let capsule = capsule();
    let statement = capsule.statement;
    let original = fields::<26>(statement.field_items().unwrap()).unwrap();
    assert!(bind_statement(capsule.kind, &original, &statement).is_ok());
    for kind in [
        KagemushaWalletOperationKindV1::Bootstrap,
        KagemushaWalletOperationKindV1::Load,
        KagemushaWalletOperationKindV1::Unload,
        KagemushaWalletOperationKindV1::Retiring,
        KagemushaWalletOperationKindV1::ArchiveSent,
    ] {
        assert_eq!(
            bind_statement(kind, &original, &statement),
            Err(Error::Authority)
        );
    }
    for i in 0..26 {
        let mut wrong = original;
        wrong[i] += Fp::ONE;
        assert_eq!(
            bind_statement(capsule.kind, &wrong, &statement),
            Err(Error::Authority)
        );
    }
}

#[test]
fn original_match_requires_every_descriptor_and_key_byte() {
    // Opaque equality component only: these bytes are not key or installation evidence.
    let original = ArtifactOriginalV1 {
        descriptor: vec![1, 2, 3],
        verifying_key: vec![4, 5, 6],
    };
    assert!(bind_original(&original, &original.descriptor, &original.verifying_key).is_ok());
    for i in 0..3 {
        let mut descriptor = original.descriptor.clone();
        descriptor[i] ^= 1;
        assert_eq!(
            bind_original(&original, &descriptor, &original.verifying_key),
            Err(Error::Profile)
        );
        let mut key = original.verifying_key.clone();
        key[i] ^= 1;
        assert_eq!(
            bind_original(&original, &original.descriptor, &key),
            Err(Error::Profile)
        );
    }
    for count in 0..3 {
        assert!(
            bind_original(
                &original,
                &original.descriptor[..count],
                &original.verifying_key
            )
            .is_err()
        );
        assert!(
            bind_original(
                &original,
                &original.descriptor,
                &original.verifying_key[..count]
            )
            .is_err()
        );
    }
}

#[test]
fn proof_result_requires_single_exact_derived_statement_instance() {
    let capsule = capsule();
    let digest = fields::<1>(vec![capsule.statement.statement_digest().unwrap()]).unwrap()[0];
    let proof = AdminSigmaProof {
        bytes: capsule.step_proof.bytes.clone(),
        instances: [vec![digest]],
    };
    // This helper only frames the result. admin_result must still verify it
    // against the installed original; the fixture's stand-in is never accepted.
    assert_eq!(
        bind_result(&capsule.statement, proof.clone()).unwrap(),
        capsule.step_proof
    );
    for instances in [vec![], vec![digest + Fp::ONE], vec![digest, digest]] {
        let mut wrong = proof.clone();
        wrong.instances[0] = instances;
        assert_eq!(bind_result(&capsule.statement, wrong), Err(Error::Proof));
    }
    let mut wrong = proof;
    wrong.bytes.clear();
    assert!(bind_result(&capsule.statement, wrong).is_err());
}
