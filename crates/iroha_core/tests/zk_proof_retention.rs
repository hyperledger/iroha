#![doc = "Ensure proof registry retention cap is enforced per backend."]
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![cfg(feature = "zk-tests")]
//! Ensure proof registry retention cap is enforced per backend.
use iroha_core::{
    executor::Executor,
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
#[path = "common/world_fixture.rs"]
mod test_world;
fn halo2_ipa_vk_record(
    circuit_id: String,
    vk_box: iroha_data_model::proof::VerifyingKeyBox,
    public_inputs: &[u8],
) -> iroha_data_model::proof::VerifyingKeyRecord {
    let mut record = iroha_data_model::proof::VerifyingKeyRecord::new(
        1,
        circuit_id,
        iroha_data_model::zk::BackendTag::Halo2IpaPasta,
        "pallas",
        iroha_crypto::Hash::new(public_inputs).into(),
        iroha_core_zk::hash_vk(&vk_box),
    );
    record.vk_len = vk_box.bytes.len() as u32;
    record.status = iroha_data_model::confidential::ConfidentialStatus::Active;
    record.key = Some(vk_box);
    record.gas_schedule_id = Some("halo2_default".into());
    record
}
fn rejected_halo2_ipa_proof(
    circuit_id: String,
    vk_box: &iroha_data_model::proof::VerifyingKeyBox,
    public_inputs: Vec<u8>,
    seed: u8,
) -> iroha_data_model::proof::ProofBox {
    let envelope = iroha_data_model::zk::OpenVerifyEnvelope::new(
        iroha_data_model::zk::BackendTag::Halo2IpaPasta,
        circuit_id,
        iroha_core_zk::hash_vk(vk_box),
        public_inputs,
        vec![seed],
    );
    iroha_data_model::proof::ProofBox::new(
        "halo2/ipa".into(),
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
    let exec = Executor::default();
    let mut stx = block.transaction();
    grant_manage_verifying_keys(&mut stx);
    stx.apply();
    // Prepare 5 different rejected proof attachments for the same no-trusted-setup backend.
    let backend = "halo2/ipa".to_string();
    for i in 0u8..5 {
        let vk_box = iroha_data_model::proof::VerifyingKeyBox::new(backend.clone(), vec![i; 8]);
        let vk_id =
            iroha_data_model::proof::VerifyingKeyId::new(backend.clone(), format!("vk_{i}"));
        let circuit_id = format!("halo2/ipa:retention:{i}");
        let public_inputs = vec![0xA5, i];
        let proof_box =
            rejected_halo2_ipa_proof(circuit_id.clone(), &vk_box, public_inputs.clone(), i);
        let vk_record = halo2_ipa_vk_record(circuit_id, vk_box, &public_inputs);
        let mut stx = block.transaction();
        let reg_vk: InstructionBox = iroha_data_model::isi::verifying_keys::RegisterVerifyingKey {
            id: vk_id.clone(),
            record: vk_record,
        }
        .into();
        exec.execute_instruction(&mut stx, &ALICE_ID.clone(), reg_vk)
            .expect("register vk");
        let attachment =
            iroha_data_model::proof::ProofAttachment::new_ref(backend.clone(), proof_box, vk_id);
        let verify: InstructionBox = iroha_data_model::isi::zk::VerifyProof::new(attachment).into();
        exec.execute_instruction(&mut stx, &ALICE_ID.clone(), verify)
            .expect("verify proof");
        stx.apply();
    }
    block
        .commit_empty_block_for_testing()
        .expect("commit block");
    // After insertions, retained proof records for this backend should be <= cap
    let view = state.view();
    let count_halo2_ipa = view
        .world()
        .proofs()
        .iter()
        .filter(|(id, _)| id.backend.as_str() == backend.as_str())
        .count();
    assert!(count_halo2_ipa <= 3, "retained {count_halo2_ipa} > cap");
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
    let backend = "halo2/ipa".to_string();
    // A proof record enters the registry when a proof of a production circuit is verified,
    // and a verifying key through the governed lifecycle. Retention does not depend on
    // either: the fixture seeds four retained records of the backend directly.
    for i in 0u8..4 {
        let vk_box = iroha_data_model::proof::VerifyingKeyBox::new(backend.clone(), vec![i; 8]);
        let proof_box = rejected_halo2_ipa_proof(
            format!("halo2/ipa:manual-retention:{i}"),
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
    // The Initial executor admits native instructions from a closed allowlist that does not
    // name `PruneProofs`, so the fixture applies the instruction itself, as the bridge
    // retention test does. What is asserted is the cap the instruction applies.
    // TODO: `zk::PruneProofs` is dispatched without an Initial-executor admission class
    // (crates/iroha_core/src/smartcontracts/isi/mod.rs), so no transaction can carry it,
    // while the CLI (crates/iroha_cli/src/zk.rs) still builds one and specs/zk_operation_inventory.json
    // records "any signed account may apply". Owner: the admission-route inventory (F.1)
    // and the roadmap decide whether it is admitted or removed; this fixture then submits
    // it through the executor again.
    iroha_data_model::isi::zk::PruneProofs::new(Some(backend.clone()))
        .execute(&ALICE_ID, &mut stx)
        .expect("prune proofs");
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
