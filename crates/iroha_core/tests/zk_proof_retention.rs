#![doc = "Ensure proof registry retention cap is enforced per backend."]
#![cfg(feature = "zk-tests")]
//! Ensure proof registry retention cap is enforced per backend.
#[path = "common/zk_components.rs"]
mod zk_components;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, WorldReadOnly},
};
use iroha_data_model::prelude::*;
use iroha_test_samples::ALICE_ID;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
#[path = "common/root_scope_fixture.rs"]
mod root_scope_fixture;
use zk_components::execute_isi_component;
#[path = "common/world_fixture.rs"]
mod test_world;
fn native_pipa_r_vk_record(
    circuit_id: String,
    vk_box: iroha_data_model::proof::VerifyingKeyBox,
    public_inputs: &[u8],
) -> iroha_data_model::proof::VerifyingKeyRecord {
    let mut record = iroha_data_model::proof::VerifyingKeyRecord::new(
        1,
        circuit_id,
        iroha_data_model::zk::BackendTag::NativePipaRPasta,
        "vesta",
        iroha_crypto::Hash::new(public_inputs).into(),
        iroha_core_zk::hash_vk(&vk_box),
    );
    record.vk_len = vk_box.bytes.len() as u32;
    record.status = iroha_data_model::confidential::ConfidentialStatus::Active;
    record.key = Some(vk_box);
    record.gas_schedule_id = Some("native_pipa_r_default".into());
    record
}
fn rejected_native_pipa_r_proof(
    circuit_id: String,
    vk_box: &iroha_data_model::proof::VerifyingKeyBox,
    public_inputs: Vec<u8>,
    seed: u8,
) -> iroha_data_model::proof::ProofBox {
    let envelope = iroha_data_model::zk::OpenVerifyEnvelope::new(
        iroha_data_model::zk::BackendTag::NativePipaRPasta,
        circuit_id,
        iroha_core_zk::hash_vk(vk_box),
        public_inputs,
        vec![seed.saturating_add(1)],
    );
    iroha_data_model::proof::ProofBox::new(
        "pipa-r/pasta".into(),
        norito::to_bytes(&envelope).expect("encode OpenVerifyEnvelope"),
    )
}
fn grant_manage_verifying_keys(stx: &mut iroha_core::state::StateTransaction<'_, '_>) {
    let perm = Permission::new(
        "CanManageVerifyingKeys".parse().unwrap(),
        iroha_primitives::json::Json::new(()),
    );
    Grant::account_permission(perm, ALICE_ID.clone())
        .execute(&ALICE_ID.clone(), stx)
        .expect("grant manage vk");
}
// TODO: stale fixture. The test registers its verifying key at the first height without the
// committed root scope and stops at "genesis instruction execution requires its
// authenticated source capability"; `manual_prune_instruction_applies_new_cap` below shows
// the repaired form.
#[test]
fn proof_records_pruned_to_cap_per_backend() {
    let world = test_world::world_with_test_accounts();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(world, kura, query_handle);
    // Set small retention cap
    let mut zk = state.installed_zk().clone();
    zk.proof_history_cap = 3;
    state
        .set_zk(zk)
        .expect("empty state accepts retention test configuration");
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    grant_manage_verifying_keys(&mut stx);
    stx.apply();
    // Prepare 5 different rejected proof attachments for the same no-trusted-setup backend.
    let backend = "pipa-r/pasta".to_string();
    let fixture = iroha_core_zk::test_utils::native_confidential_fixture_envelope();
    for i in 0u8..5 {
        let vk_box = fixture.vk_box(&backend).expect("compiled native key");
        let vk_id =
            iroha_data_model::proof::VerifyingKeyId::new(backend.clone(), format!("vk_{i}"));
        let circuit_id =
            iroha_core_zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID.to_owned();
        let public_inputs = fixture.public_inputs.clone();
        let proof_box =
            rejected_native_pipa_r_proof(circuit_id.clone(), &vk_box, public_inputs.clone(), i);
        let mut vk_record = native_pipa_r_vk_record(circuit_id, vk_box, &public_inputs);
        vk_record.version = u32::from(i) + 1;
        let mut stx = block.transaction();
        let reg_vk: InstructionBox = iroha_data_model::isi::verifying_keys::RegisterVerifyingKey {
            id: vk_id.clone(),
            record: vk_record,
        }
        .into();
        execute_isi_component(&mut stx, &ALICE_ID.clone(), reg_vk).expect("register vk");
        let attachment =
            iroha_data_model::proof::ProofAttachment::new_ref(backend.clone(), proof_box, vk_id);
        let verify: InstructionBox = iroha_data_model::isi::zk::VerifyProof::new(attachment).into();
        execute_isi_component(&mut stx, &ALICE_ID.clone(), verify).expect("verify proof");
        stx.apply();
    }
    block
        .commit_empty_block_for_testing()
        .expect("commit block");
    // After insertions, retained proof records for this backend should be <= cap
    let view = state.view();
    let count_native_pipa_r = view
        .world()
        .proofs()
        .iter()
        .filter(|(id, _)| id.backend.as_str() == backend.as_str())
        .count();
    assert!(
        count_native_pipa_r <= 3,
        "retained {count_native_pipa_r} > cap"
    );
}
#[test]
fn manual_prune_instruction_applies_new_cap() {
    let world = test_world::world_with_test_accounts();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(world, kura, query_handle);
    // Start with a high cap so inserts do not prune.
    let mut zk = state.installed_zk().clone();
    zk.proof_history_cap = 10;
    zk.proof_retention_grace_blocks = 0;
    zk.proof_prune_batch = 10;
    state
        .set_zk(zk)
        .expect("empty state accepts retention test configuration");
    // Instruction execution requires committed root authority: the first height commits
    // the Global root scope and the fixture executes from the second height on.
    root_scope_fixture::commit_global_root_scope(&state);
    let backend = "pipa-r/pasta".to_string();
    // A proof record enters the registry when a proof of a production circuit is verified,
    // and a verifying key through the governed lifecycle. Retention does not depend on
    // either: the fixture seeds four retained records of the backend directly.
    for i in 0u8..4 {
        let vk_box = iroha_data_model::proof::VerifyingKeyBox::new(backend.clone(), vec![i; 8]);
        let proof_box = rejected_native_pipa_r_proof(
            iroha_core_zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID.to_owned(),
            &vk_box,
            vec![0x5A, i],
            i,
        );
        let id = iroha_data_model::proof::ProofId {
            backend: proof_box.backend.clone(),
            proof_hash: iroha_core_zk::hash_proof(&proof_box),
        };
        let record = iroha_data_model::proof::ProofRecord {
            id: id.clone(),
            vk_ref: None,
            vk_commitment: None,
            status: iroha_data_model::proof::ProofStatus::Rejected,
            verified_at_height: Some(u64::from(i) + 1),
            bridge: None,
        };
        iroha_core::query::insert_proof_record_for_test(&mut state, id, record);
    }
    assert_eq!(
        state
            .view()
            .world()
            .proofs()
            .iter()
            .filter(|(id, _)| id.backend.as_str() == backend.as_str())
            .count(),
        4,
        "the fixture retains four records before the cap is tightened"
    );
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    grant_manage_verifying_keys(&mut stx);
    stx.apply();
    // The fixture height follows no certified parent, so its World overlay is committed
    // without pretending that a block was finalized.
    block
        .commit_world_overlay_for_testing()
        .expect("commit fixture overlay");
    // Tighten retention policy and prune explicitly.
    let mut zk = state.installed_zk().clone();
    zk.proof_history_cap = 1;
    zk.proof_retention_grace_blocks = 0;
    zk.proof_prune_batch = 0;
    state
        .set_zk(zk)
        .expect("empty state accepts retention test configuration");
    let prune_header =
        iroha_data_model::block::BlockHeader::new(nonzero!(10_u64), None, None, 0, 0);
    let mut prune_block = state.block(prune_header);
    let mut stx = prune_block.transaction();
    let prune: InstructionBox =
        iroha_data_model::isi::zk::PruneProofs::new(Some(backend.clone())).into();
    execute_isi_component(&mut stx, &ALICE_ID.clone(), prune).expect("prune proofs");
    stx.apply();
    prune_block
        .commit_world_overlay_for_testing()
        .expect("commit prune fixture overlay");
    let view = state.view();
    let remaining = view
        .world()
        .proofs()
        .iter()
        .filter(|(id, _)| id.backend.as_str() == backend.as_str())
        .count();
    assert!(
        remaining <= 1,
        "pruning did not enforce new cap, remaining={remaining}"
    );
}
