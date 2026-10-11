//! Native transfer proof binding checks and explicit production rejection.
//! These tests do not qualify credential-linked ballots or sound election tallies.
#![cfg(feature = "zk-tests")]
#[path = "common/governance_closed_state.rs"]
mod closed_state;
#[path = "zk_testkit.rs"]
mod zk_testkit;
use iroha_core::{smartcontracts::Execute, state::WorldReadOnly};
use iroha_core_zk as zk;
use iroha_data_model::{
    block::BlockHeader,
    isi::{
        error::{InstructionExecutionError, InvalidParameterError},
        verifying_keys::RegisterVerifyingKey,
        zk::VerifyProof,
    },
    proof::{ProofAttachment, ProofBox},
    zk::{NativePipaRProofV1, OpenVerifyEnvelope},
};
use iroha_test_samples::ALICE_ID;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
fn assert_closed_registry(error: InstructionExecutionError) {
    assert_eq!(
        error,
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            "native PIPA-R circuit_id is not in the compiled circuit registry".into()
        ))
    );
}
#[test]
fn native_transfer_proof_verifies() {
    let bundle = zk_testkit::unqualified_native_ballot_bundle();
    assert!(bundle.verify_native(bundle.native_transcript(), bundle.commit, bundle.root));
}
#[test]
fn native_transfer_proof_rejects_commit_tampering() {
    let bundle = zk_testkit::unqualified_native_ballot_bundle();
    assert!(!bundle.verify_native(
        bundle.native_transcript(),
        {
            let mut changed = bundle.commit;
            changed[0] ^= 1;
            changed
        },
        bundle.root
    ));
}
#[test]
fn native_transfer_proof_rejects_root_tampering() {
    let bundle = zk_testkit::unqualified_native_ballot_bundle();
    assert!(
        !bundle.verify_native(bundle.native_transcript(), bundle.commit, {
            let mut changed = bundle.root;
            changed[0] ^= 1;
            changed
        })
    );
}
#[test]
fn native_transfer_proof_rejects_transcript_tampering() {
    let bundle = zk_testkit::unqualified_native_ballot_bundle();
    let mut proof = bundle.native_transcript().to_vec();
    proof[0] ^= 1;
    assert!(!bundle.verify_native(&proof, bundle.commit, bundle.root));
    assert!(!bundle.verify_native(&proof[..proof.len() / 2], bundle.commit, bundle.root));
}
#[test]
fn relabelled_native_proof_is_rejected_by_production_dispatch() {
    let bundle = zk_testkit::unqualified_native_ballot_bundle();
    let key = bundle.vk_record.key.as_ref().unwrap();
    let proof = ProofBox::new(bundle.backend.into(), bundle.proof_bytes.clone());
    assert!(!zk::verify_backend(bundle.backend, &proof, Some(key)));
}
#[test]
fn unadmitted_native_key_and_schema_mutation_cannot_register() {
    let state = closed_state::state();
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let bundle = zk_testkit::unqualified_native_ballot_bundle();
    for mutated_schema in [false, true] {
        let mut transaction = block.transaction();
        closed_state::grant_permissions(&mut transaction, "unadmitted-native-role");
        let mut record = bundle.vk_record.clone();
        if mutated_schema {
            record.public_inputs_schema_hash[0] ^= 1;
        }
        assert_closed_registry(
            RegisterVerifyingKey {
                id: bundle.vk_id.clone(),
                record,
            }
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("unadmitted key must not register"),
        );
        assert!(
            transaction
                .world
                .verifying_keys()
                .get(&bundle.vk_id)
                .is_none()
        );
        assert!(transaction.world.take_external_events().is_empty());
    }
}
#[test]
fn unadmitted_native_verify_isi_rejects_missing_and_retained_keys() {
    let state = closed_state::state();
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let bundle = zk_testkit::unqualified_native_ballot_bundle();
    // Preserve both original public-input mutation controls without attributing registry
    // rejection to a fictitious schema verifier. Actual raw-proof binding is tested above.
    for tamper_row in [None, Some(0_usize), Some(6)] {
        for retained_key in [false, true] {
            let mut transaction = block.transaction();
            let mut envelope: OpenVerifyEnvelope =
                norito::decode_from_bytes(&bundle.proof_bytes).unwrap();
            if let Some(row) = tamper_row {
                let mut inner: NativePipaRProofV1 =
                    norito::decode_from_bytes(&envelope.proof_bytes).unwrap();
                inner.public_inputs[row][0] ^= 1;
                envelope.proof_bytes = norito::to_bytes(&inner).unwrap();
            }
            let proof = ProofBox::new(bundle.backend.into(), norito::to_bytes(&envelope).unwrap());
            if retained_key {
                // Explicit adversarial retained state, never successful registration.
                transaction
                    .world
                    .verifying_keys_mut_for_testing()
                    .insert(bundle.vk_id.clone(), bundle.vk_record.clone());
            }
            let proof_id = iroha_data_model::proof::ProofId {
                backend: bundle.backend.into(),
                proof_hash: zk::hash_proof(&proof),
            };
            let mut attachment =
                ProofAttachment::new_ref(bundle.backend.into(), proof, bundle.vk_id.clone());
            attachment.vk_commitment = Some(bundle.vk_record.commitment);
            assert_closed_registry(
                VerifyProof::new(attachment)
                    .execute(&ALICE_ID, &mut transaction)
                    .expect_err("unadmitted envelope must stay outside VerifyProof"),
            );
            assert!(transaction.world.proofs().get(&proof_id).is_none());
            assert!(transaction.world.take_external_events().is_empty());
        }
    }
}
