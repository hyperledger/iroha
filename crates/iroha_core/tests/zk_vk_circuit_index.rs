#![doc = "Verifying-key registry indexing by `(circuit_id, version)`."]
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![cfg(feature = "zk-tests")]
//! Verifying-key registry indexing by `(circuit_id, version)`.
#[path = "common/native_genesis.rs"]
mod native_genesis;
#[path = "common/zk_components.rs"]
mod zk_components;
use iroha_core::{smartcontracts::Execute, state::WorldReadOnly};
use iroha_core_zk::hash_vk;
use iroha_core_zk::{
    confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID as TRANSFER,
    native_pipa_r::{self, NativeRelationV1},
    test_utils::native_confidential_fixture_envelope,
};
use zk_components::execute_isi_component;
const FULL: &str = "pipa-r/pasta/confidential-unshield-full-v1";
use iroha_data_model::{
    ValidationFail,
    confidential::ConfidentialStatus,
    isi::{
        Grant,
        error::{InstructionExecutionError, InvalidParameterError},
        verifying_keys,
    },
    permission::Permission,
    prelude::InstructionBox,
    proof::{VerifyingKeyId, VerifyingKeyRecord},
    zk::{BackendTag, OpenVerifyEnvelope},
};
use iroha_primitives::json::Json;
use iroha_test_samples::ALICE_ID;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
#[path = "common/world_fixture.rs"]
mod test_world;
fn grant_manage_vk(block: &mut iroha_core::state::StateBlock<'_>) {
    let mut stx = block.transaction();
    let perm = Permission::new(
        "CanManageVerifyingKeys".parse().expect("permission id"),
        Json::new(()),
    );
    Grant::account_permission(perm, ALICE_ID.clone())
        .execute(&ALICE_ID.clone(), &mut stx)
        .expect("grant manage vk");
    stx.apply();
}
fn register_vk(
    block: &mut iroha_core::state::StateBlock<'_>,
    id: &VerifyingKeyId,
    record: &VerifyingKeyRecord,
) {
    let mut stx = block.transaction();
    let instr: InstructionBox = verifying_keys::RegisterVerifyingKey {
        id: id.clone(),
        record: record.clone(),
    }
    .into();
    execute_isi_component(&mut stx, &ALICE_ID.clone(), instr).expect("register vk");
    stx.apply();
}
fn base_record(circuit: &str, version: u32) -> VerifyingKeyRecord {
    let mut rec = VerifyingKeyRecord::new(
        version,
        circuit.to_string(),
        BackendTag::NativePipaRPasta,
        "vesta",
        iroha_crypto::Hash::new(native_pipa_r::public_schema(
            native_pipa_r::relation("pipa-r/pasta", circuit).unwrap(),
        ))
        .into(),
        [0xBB; 32],
    );
    rec.status = ConfidentialStatus::Active;
    rec.gas_schedule_id = Some("native_pipa_r_default".into());
    rec.max_proof_bytes = 4096;
    rec
}
#[test]
fn duplicate_circuit_version_registration_rejected() {
    let world = test_world::world_with_test_accounts();
    let state = native_genesis::certified_state(world);
    let header = iroha_data_model::block::BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        1,
        0,
    );
    let mut block = state.block(header);
    grant_manage_vk(&mut block);
    let id_primary = VerifyingKeyId::new("pipa-r/pasta", "vk_primary");
    let rec_primary = base_record(TRANSFER, 1);
    register_vk(&mut block, &id_primary, &rec_primary);
    let mut stx = block.transaction();
    let id_secondary = VerifyingKeyId::new("pipa-r/pasta", "vk_secondary");
    let rec_secondary = base_record(TRANSFER, 1);
    let instr: InstructionBox = verifying_keys::RegisterVerifyingKey {
        id: id_secondary.clone(),
        record: rec_secondary,
    }
    .into();
    let err = execute_isi_component(&mut stx, &ALICE_ID.clone(), instr)
        .expect_err("duplicate circuit/version must be rejected");
    match err {
        ValidationFail::InstructionFailed(InstructionExecutionError::InvariantViolation(msg)) => {
            assert!(msg.contains("circuit/version"), "unexpected message: {msg}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
#[test]
fn update_rotates_circuit_version_index() {
    let world = test_world::world_with_test_accounts();
    let state = native_genesis::certified_state(world);
    let header = iroha_data_model::block::BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        1,
        0,
    );
    let mut block = state.block(header);
    grant_manage_vk(&mut block);
    let id = VerifyingKeyId::new("pipa-r/pasta", "vk_upgrade");
    let rec_current = base_record(FULL, 1);
    register_vk(&mut block, &id, &rec_current);
    // Upgrade to version 2
    let mut stx = block.transaction();
    let rec_v2 = base_record(FULL, 2);
    let update: InstructionBox = verifying_keys::UpdateVerifyingKey {
        id: id.clone(),
        record: rec_v2,
    }
    .into();
    execute_isi_component(&mut stx, &ALICE_ID.clone(), update).expect("update vk");
    stx.apply();
    let map = block.world.verifying_keys_by_circuit();
    let key_old = (String::from(FULL), 1);
    let key_new = (String::from(FULL), 2);
    assert!(
        map.get(&key_new).is_some(),
        "new version missing from index"
    );
    assert!(map.get(&key_old).is_none(), "old version still indexed");
}
fn register_native_vk(
    block: &mut iroha_core::state::StateBlock<'_>,
    name: &str,
) -> (VerifyingKeyId, [u8; 32]) {
    let id = VerifyingKeyId::new("pipa-r/pasta", name);
    let mut record = base_record(TRANSFER, 1);
    let vk_box = native_confidential_fixture_envelope()
        .vk_box("pipa-r/pasta")
        .unwrap();
    record.key = Some(vk_box.clone());
    record.commitment = hash_vk(&vk_box);
    record.vk_len = u32::try_from(vk_box.bytes.len()).expect("bounded native key");
    register_vk(block, &id, &record);
    (id, record.commitment)
}
fn execute_verify_proof(
    block: &mut iroha_core::state::StateBlock<'_>,
    mut attachment: iroha_data_model::proof::ProofAttachment,
    vk_commitment: [u8; 32],
) -> Result<(), ValidationFail> {
    attachment.vk_commitment = Some(vk_commitment);
    let mut stx = block.transaction();
    let isi: InstructionBox = iroha_data_model::isi::zk::VerifyProof::new(attachment).into();
    let res = isi
        .execute(&ALICE_ID, &mut stx)
        .map_err(ValidationFail::InstructionFailed);
    if res.is_ok() {
        stx.apply();
    }
    res
}
#[test]
fn verify_proof_rejects_circuit_mismatch() {
    let world = test_world::world_with_test_accounts();
    let state = native_genesis::certified_state(world);
    let header = iroha_data_model::block::BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        1,
        0,
    );
    let mut block = state.block(header);
    grant_manage_vk(&mut block);
    let public_inputs =
        native_pipa_r::public_schema(NativeRelationV1::ConfidentialTransfer).to_vec();
    let (vk_id, vk_commitment) = register_native_vk(&mut block, "vk_main");
    let envelope = OpenVerifyEnvelope {
        backend: BackendTag::NativePipaRPasta,
        circuit_id: FULL.into(),
        vk_hash: vk_commitment,
        public_inputs: public_inputs.clone(),
        proof_bytes: vec![9, 9, 9],
        aux: Vec::new(),
    };
    let proof_bytes = norito::to_bytes(&envelope).expect("serialize envelope");
    let proof_box = iroha_data_model::proof::ProofBox::new("pipa-r/pasta".into(), proof_bytes);
    let attachment =
        iroha_data_model::proof::ProofAttachment::new_ref("pipa-r/pasta".into(), proof_box, vk_id);
    let err = execute_verify_proof(&mut block, attachment, vk_commitment).expect_err("must fail");
    match err {
        ValidationFail::InstructionFailed(InstructionExecutionError::InvariantViolation(msg)) => {
            assert!(msg.contains("circuit mismatch"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
#[test]
fn verify_proof_rejects_schema_hash_mismatch() {
    let world = test_world::world_with_test_accounts();
    let state = native_genesis::certified_state(world);
    let header = iroha_data_model::block::BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        1,
        0,
    );
    let mut block = state.block(header);
    grant_manage_vk(&mut block);
    let mut public_inputs =
        native_pipa_r::public_schema(NativeRelationV1::ConfidentialTransfer).to_vec();
    public_inputs[0] ^= 1;
    let (vk_id, vk_commitment) = register_native_vk(&mut block, "vk_main");
    let envelope = OpenVerifyEnvelope {
        backend: BackendTag::NativePipaRPasta,
        circuit_id: TRANSFER.into(),
        vk_hash: vk_commitment,
        public_inputs: public_inputs.clone(),
        proof_bytes: vec![10, 10, 10],
        aux: Vec::new(),
    };
    let proof_bytes = norito::to_bytes(&envelope).expect("serialize envelope");
    let proof_box = iroha_data_model::proof::ProofBox::new("pipa-r/pasta".into(), proof_bytes);
    let attachment =
        iroha_data_model::proof::ProofAttachment::new_ref("pipa-r/pasta".into(), proof_box, vk_id);
    let err = execute_verify_proof(&mut block, attachment, vk_commitment).expect_err("must fail");
    match err {
        ValidationFail::InstructionFailed(InstructionExecutionError::InvariantViolation(msg)) => {
            assert!(msg.contains("schema hash"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
#[test]
fn verify_proof_records_matching_metadata_with_invalid_proof_as_rejected() {
    let world = test_world::world_with_test_accounts();
    let state = native_genesis::certified_state(world);
    let header = iroha_data_model::block::BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        1,
        0,
    );
    let mut block = state.block(header);
    grant_manage_vk(&mut block);
    let public_inputs =
        native_pipa_r::public_schema(NativeRelationV1::ConfidentialTransfer).to_vec();
    let (vk_id, commitment) = register_native_vk(&mut block, "vk_main");
    let envelope = OpenVerifyEnvelope {
        backend: BackendTag::NativePipaRPasta,
        circuit_id: TRANSFER.into(),
        vk_hash: commitment,
        public_inputs: public_inputs.clone(),
        proof_bytes: vec![1, 2, 3, 4],
        aux: Vec::new(),
    };
    let proof_bytes = norito::to_bytes(&envelope).expect("serialize envelope");
    let proof_box = iroha_data_model::proof::ProofBox::new("pipa-r/pasta".into(), proof_bytes);
    let attachment =
        iroha_data_model::proof::ProofAttachment::new_ref("pipa-r/pasta".into(), proof_box, vk_id);
    let proof_id = iroha_data_model::proof::ProofId {
        backend: attachment.backend.clone(),
        proof_hash: iroha_core_zk::hash_proof(&attachment.proof),
    };
    execute_verify_proof(&mut block, attachment, commitment)
        .expect("invalid proof result should be recorded");
    let record = block
        .world
        .proofs()
        .get(&proof_id)
        .expect("proof record must exist");
    assert_eq!(
        record.status,
        iroha_data_model::proof::ProofStatus::Rejected,
        "matching metadata must not substitute for cryptographic verification"
    );
}
#[test]
fn register_requires_circuit_and_schema_hash() {
    let world = test_world::world_with_test_accounts();
    let state = native_genesis::certified_state(world);
    let header = iroha_data_model::block::BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        1,
        0,
    );
    let mut block = state.block(header);
    grant_manage_vk(&mut block);
    let mut rec = base_record(TRANSFER, 1);
    rec.circuit_id.clear();
    let id = VerifyingKeyId::new("pipa-r/pasta", "vk_bad");
    let mut stx = block.transaction();
    let instr: InstructionBox = verifying_keys::RegisterVerifyingKey {
        id: id.clone(),
        record: rec.clone(),
    }
    .into();
    let err = execute_isi_component(&mut stx, &ALICE_ID.clone(), instr)
        .expect_err("empty circuit_id must be rejected");
    match err {
        ValidationFail::InstructionFailed(InstructionExecutionError::InvalidParameter(
            InvalidParameterError::SmartContract(msg),
        )) => {
            assert!(
                msg.contains("circuit_id"),
                "unexpected message for circuit guard: {msg}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
    drop(stx);
    rec.circuit_id = TRANSFER.into();
    rec.public_inputs_schema_hash = [0u8; 32];
    let mut stx2 = block.transaction();
    let instr2: InstructionBox = verifying_keys::RegisterVerifyingKey { id, record: rec }.into();
    let err2 = execute_isi_component(&mut stx2, &ALICE_ID.clone(), instr2)
        .expect_err("zero schema hash must be rejected");
    match err2 {
        ValidationFail::InstructionFailed(InstructionExecutionError::InvalidParameter(
            InvalidParameterError::SmartContract(msg),
        )) => {
            assert!(
                msg.contains("public_inputs_schema_hash"),
                "unexpected message for schema guard: {msg}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
