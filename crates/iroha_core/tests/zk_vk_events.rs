#![doc = "Verifying-key registry lifecycle event tests."]
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![cfg(feature = "zk-tests")]
//! Tests for `VerifyingKey` registry lifecycle events.
#![allow(clippy::items_after_statements)]
#[path = "common/zk_components.rs"]
mod zk_components;
use iroha_core::{kura::Kura, query::store::LiveQueryStore, smartcontracts::Execute, state::State};
use iroha_data_model::{
    confidential::ConfidentialStatus,
    events::data::{DataEvent, verifying_keys::VerifyingKeyEvent as VKEvent},
    prelude::*,
    zk::BackendTag,
};
use iroha_test_samples::ALICE_ID;
use nonzero_ext::nonzero;
use zk_components::execute_isi_component;
#[path = "common/world_fixture.rs"]
mod test_world;
#[test]
fn vk_register_update_emit_events() {
    // Minimal node state and block context
    let world = test_world::world_with_test_accounts();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    // Grant CanManageVerifyingKeys to ALICE using a generic permission token
    use iroha_data_model::{permission::Permission, prelude::Grant};
    let perm = Permission::new(
        "CanManageVerifyingKeys".parse().unwrap(),
        iroha_primitives::json::Json::new(()),
    );
    Grant::account_permission(perm, ALICE_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("grant vk manage");
    // The permission grant emits an account-level event; clear it so we only
    // assert on verifying-key lifecycle events below.
    stx.world.take_external_events();
    // Prepare a VK record and Register
    let id = iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "vk_test");
    let fixture = iroha_core_zk::test_utils::native_confidential_fixture_envelope();
    let vk_box = fixture.vk_box("pipa-r/pasta").expect("compiled native key");
    let commitment = iroha_core_zk::hash_vk(&vk_box);
    let mut rec = iroha_data_model::proof::VerifyingKeyRecord::new(
        1,
        iroha_core_zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
        BackendTag::NativePipaRPasta,
        "vesta",
        fixture.schema_hash,
        commitment,
    );
    rec.vk_len = u32::try_from(vk_box.bytes.len()).unwrap();
    rec.key = Some(vk_box.clone());
    rec.status = ConfidentialStatus::Active;
    rec.gas_schedule_id = Some("native_pipa_r_default".into());
    let reg_insn: InstructionBox = iroha_data_model::isi::verifying_keys::RegisterVerifyingKey {
        id: id.clone(),
        record: rec.clone(),
    }
    .into();
    execute_isi_component(&mut stx, &ALICE_ID.clone(), reg_insn).expect("register vk");
    // Update to version 2
    let mut rec2 = iroha_data_model::proof::VerifyingKeyRecord::new(
        2,
        iroha_core_zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
        BackendTag::NativePipaRPasta,
        "vesta",
        fixture.schema_hash,
        commitment,
    );
    rec2.vk_len = u32::try_from(vk_box.bytes.len()).unwrap();
    rec2.key = Some(vk_box);
    rec2.status = ConfidentialStatus::Active;
    rec2.gas_schedule_id = Some("native_pipa_r_default".into());
    let upd: InstructionBox = iroha_data_model::isi::verifying_keys::UpdateVerifyingKey {
        id: id.clone(),
        record: rec2.clone(),
    }
    .into();
    execute_isi_component(&mut stx, &ALICE_ID.clone(), upd).expect("update vk");
    // Apply and extract events
    stx.apply();
    let mut events = block.world.take_external_events();
    // We expect two events: Registered, Updated (in that order)
    assert_eq!(events.len(), 2);
    // Registered
    match events.remove(0).into_shared_data_event() {
        Ok(event) => match event.as_ref() {
            DataEvent::VerifyingKey(VKEvent::Registered(ev)) => {
                assert_eq!(ev.id, id);
                assert_eq!(ev.record.version, 1);
                assert_eq!(ev.record.commitment, commitment);
            }
            other => panic!("unexpected first event: {other:?}"),
        },
        Err(other) => panic!("unexpected first event: {other:?}"),
    }
    // Updated
    match events.remove(0).into_shared_data_event() {
        Ok(event) => match event.as_ref() {
            DataEvent::VerifyingKey(VKEvent::Updated(ev)) => {
                assert_eq!(ev.id, id);
                assert_eq!(ev.record.version, 2);
                assert_eq!(ev.record.commitment, commitment);
            }
            other => panic!("unexpected second event: {other:?}"),
        },
        Err(other) => panic!("unexpected second event: {other:?}"),
    }
}
