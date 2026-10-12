//! Bridge-proof admission and retention tests.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
use iroha_core::{
    executor::Executor,
    kura::Kura,
    query::{insert_proof_record_for_test, store::LiveQueryStore},
    smartcontracts::Execute,
    state::{State, WorldReadOnly},
};
use iroha_data_model::{
    bridge::BridgeProofRecord,
    prelude::*,
    proof::{ProofBox, ProofId, ProofRecord, ProofStatus},
};
use iroha_test_samples::ALICE_ID;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
#[path = "common/root_scope_fixture.rs"]
mod root_scope_fixture;
fn bridge_proof_id(proof: &BridgeProof) -> ProofId {
    let encoded = norito::to_bytes(proof).expect("encode bridge proof");
    let backend = proof.backend_label();
    let proof = ProofBox::new(backend.clone(), encoded);
    ProofId {
        backend,
        proof_hash: iroha_core_zk::hash_proof(&proof),
    }
}
fn make_ics_proof(leaf_fill: u8, range: (u64, u64)) -> BridgeProof {
    let leaves = vec![[leaf_fill; 32], [leaf_fill.wrapping_add(1); 32]];
    let tree = iroha_crypto::MerkleTree::<[u8; 32]>::from_hashed_leaves_sha256(leaves.clone());
    let root_bytes: [u8; 32] = *tree.root().expect("root").as_ref();
    let proof = tree.get_proof(0).expect("proof");
    BridgeProof {
        range: BridgeProofRange {
            start_height: range.0,
            end_height: range.1,
        },
        payload: BridgeProofPayload::Ics(BridgeIcsProof {
            verifier_manifest_hash: [0xAA; 32],
            state_root: root_bytes,
            leaf_hash: leaves[0],
            proof,
            hash_function: BridgeHashFunction::Sha256,
        }),
    }
}
fn make_transparent_proof(range: (u64, u64)) -> BridgeProof {
    BridgeProof {
        range: BridgeProofRange {
            start_height: range.0,
            end_height: range.1,
        },
        payload: BridgeProofPayload::TransparentZk(BridgeTransparentProof {
            verifier_manifest_hash: [0xBB; 32],
            proof: ProofBox::new("halo2/mock".into(), vec![0xDE, 0xAD, 0xBE, 0xEF]),
            recursion_depth: Some(1),
        }),
    }
}
/// A test State whose first height commits the Global root scope: instruction execution
/// requires committed root authority, so every test executes at height two or later.
fn state_for_test() -> State {
    let state = State::new_for_testing(
        iroha_core::state::World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    root_scope_fixture::commit_global_root_scope(&state);
    state
}
fn execute_bridge_proof(proof: BridgeProof) -> Result<(), String> {
    let state = state_for_test();
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let submit: InstructionBox =
        iroha_data_model::isi::bridge::SubmitBridgeProof::new(proof).into();
    Executor::default()
        .execute_instruction(&mut stx, &ALICE_ID.clone(), submit)
        .map_err(|error| format!("{error:?}"))
}
#[test]
fn generic_proof_variants_require_authoritative_on_chain_verifiers() {
    for (label, proof) in [
        ("ICS", make_ics_proof(0x11, (1, 1))),
        ("transparent", make_transparent_proof((1, 1))),
    ] {
        let error = execute_bridge_proof(proof)
            .expect_err("caller-supplied generic proof must not be trusted");
        assert!(
            error.contains("authoritative on-chain verifier"),
            "unexpected {label} rejection: {error}"
        );
    }
}
#[test]
fn rejected_generic_proof_does_not_mutate_proof_registry() {
    let state = state_for_test();
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let proof = make_ics_proof(0x12, (1, 1));
    let expected_id = bridge_proof_id(&proof);
    let submit: InstructionBox =
        iroha_data_model::isi::bridge::SubmitBridgeProof::new(proof).into();
    let error = Executor::default()
        .execute_instruction(&mut stx, &ALICE_ID.clone(), submit)
        .expect_err("generic proof admission must reject");
    assert!(format!("{error:?}").contains("authoritative on-chain verifier"));
    assert!(stx.world.proofs().get(&expected_id).is_none());
    assert!(stx.world.take_external_events().is_empty());
}
#[test]
fn bridge_range_and_binding_shape_are_checked_before_backend_admission() {
    let mut reversed = make_ics_proof(0x13, (2, 1));
    let error = execute_bridge_proof(reversed.clone()).expect_err("reversed range must reject");
    assert!(error.contains("start_height <= end_height"));
    reversed.range = BridgeProofRange {
        start_height: 1,
        end_height: 1,
    };
    let BridgeProofPayload::Ics(ics) = &mut reversed.payload else {
        unreachable!("ICS fixture")
    };
    ics.verifier_manifest_hash = [0; 32];
    let error = execute_bridge_proof(reversed).expect_err("zero verifier binding must reject");
    assert!(error.contains("binding must not be all zeros"));
}
#[test]
fn bridge_range_length_cap_enforced() {
    let mut state = state_for_test();
    state
        .edit_zk_for_testing(|zk| zk.bridge_proof_max_range_len = 2)
        .expect("fixture ZK settings install");
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(10_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let submit: InstructionBox =
        iroha_data_model::isi::bridge::SubmitBridgeProof::new(make_ics_proof(0x44, (5, 10))).into();
    let error = Executor::default()
        .execute_instruction(&mut stx, &ALICE_ID.clone(), submit)
        .expect_err("range cap should reject long bridge proofs");
    assert!(
        format!("{error:?}").contains("range too large"),
        "unexpected error: {error:?}"
    );
}
#[test]
fn bridge_height_window_respected_before_generic_backend_rejection() {
    let mut state = state_for_test();
    let executor = Executor::default();
    state
        .edit_zk_for_testing(|zk| zk.bridge_proof_max_future_drift_blocks = 1)
        .expect("fixture ZK settings install");
    let header_future =
        iroha_data_model::block::BlockHeader::new(nonzero!(5_u64), None, None, 0, 0);
    let mut block_future = state.block(header_future);
    let mut stx_future = block_future.transaction();
    let submit_future: InstructionBox =
        iroha_data_model::isi::bridge::SubmitBridgeProof::new(make_ics_proof(0x55, (7, 7))).into();
    let error = executor
        .execute_instruction(&mut stx_future, &ALICE_ID.clone(), submit_future)
        .expect_err("future drift guard should reject proof ahead of window");
    assert!(format!("{error:?}").contains("future window"));
    drop(stx_future);
    drop(block_future);
    state
        .edit_zk_for_testing(|zk| zk.bridge_proof_max_future_drift_blocks = 10)
        .expect("fixture ZK settings install");
    state
        .edit_zk_for_testing(|zk| zk.bridge_proof_max_past_age_blocks = 2)
        .expect("fixture ZK settings install");
    let header_past = iroha_data_model::block::BlockHeader::new(nonzero!(10_u64), None, None, 0, 0);
    let mut block_past = state.block(header_past);
    let mut stx_past = block_past.transaction();
    let submit_past: InstructionBox =
        iroha_data_model::isi::bridge::SubmitBridgeProof::new(make_ics_proof(0x66, (1, 7))).into();
    let error = executor
        .execute_instruction(&mut stx_past, &ALICE_ID.clone(), submit_past)
        .expect_err("past window should reject stale proof");
    assert!(format!("{error:?}").contains("past window"));
}
fn proof_record(proof: BridgeProof, verified_at_height: u64) -> (ProofId, ProofRecord) {
    let id = bridge_proof_id(&proof);
    let encoded = norito::to_bytes(&proof).expect("encode retained proof");
    let record = ProofRecord {
        id: id.clone(),
        vk_ref: None,
        vk_commitment: None,
        status: ProofStatus::Verified,
        verified_at_height: Some(verified_at_height),
        bridge: Some(BridgeProofRecord {
            proof,
            commitment: id.proof_hash,
            size_bytes: u32::try_from(encoded.len()).expect("test proof length fits u32"),
        }),
    };
    (id, record)
}
#[test]
fn manual_prune_has_no_caller_controlled_retention_bypass() {
    let mut state = state_for_test();
    state
        .edit_zk_for_testing(|zk| zk.proof_history_cap = 1)
        .expect("fixture ZK settings install");
    state
        .edit_zk_for_testing(|zk| zk.proof_retention_grace_blocks = 0)
        .expect("fixture ZK settings install");
    state
        .edit_zk_for_testing(|zk| zk.proof_prune_batch = 10)
        .expect("fixture ZK settings install");
    let (older_id, older) = proof_record(make_ics_proof(0x23, (1, 1)), 1);
    let (newer_id, newer) = proof_record(make_ics_proof(0x34, (2, 2)), 2);
    insert_proof_record_for_test(&mut state, older_id.clone(), older);
    insert_proof_record_for_test(&mut state, newer_id.clone(), newer);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(3_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    // TODO: applied directly because the Initial executor admits no transaction that
    // carries `zk::PruneProofs` (see the note in zk_proof_retention.rs; owner F.1 and the
    // roadmap). Submit it through the executor once it has an admission class.
    iroha_data_model::isi::zk::PruneProofs::new(Some("bridge/ics23".to_owned()))
        .execute(&ALICE_ID, &mut stx)
        .expect("manual bridge prune");
    assert!(stx.world.proofs().get(&older_id).is_none());
    assert!(stx.world.proofs().get(&newer_id).is_some());
}
