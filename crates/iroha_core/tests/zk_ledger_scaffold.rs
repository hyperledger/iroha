//! Scaffold tests for ZK asset registration and authenticated commitment-tree state.

#![cfg(feature = "zk-tests")]
#[path = "common/zk_components.rs"]
mod zk_components;
use iroha_config::parameters::defaults;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, StateTransaction, World, WorldReadOnly},
};
use iroha_core_zk::confidential_v2;
use iroha_crypto::Hash;
use iroha_data_model::{
    account::NewAccount,
    asset::definition::{
        AssetConfidentialPolicy, ConfidentialPolicyMode, ConfidentialPolicyTransition,
    },
    permission::Permission,
    prelude::*,
    proof::VerifyingKeyId,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;
use iroha_test_samples::gen_account_in;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
use std::{num::NonZeroU64, str::FromStr};
#[path = "common/root_scope_fixture.rs"]
mod root_scope_fixture;
use zk_components::execute_isi_component;
const NATIVE_PIPA_R_BACKEND: &str = "pipa-r/pasta";
fn set_confidential_policy_mode(
    state_transaction: &mut StateTransaction<'_, '_>,
    asset_definition_id: &AssetDefinitionId,
    mode: ConfidentialPolicyMode,
) {
    let asset_definition = state_transaction
        .world
        .asset_definition_mut(asset_definition_id)
        .expect("asset definition exists");
    let mut policy = *asset_definition.confidential_policy();
    policy.mode = mode;
    asset_definition.set_confidential_policy(policy);
}
#[test]
fn register_zk_asset_writes_policy_metadata() {
    // Minimal state and transaction
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::new(), kura, query);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    // Setup: domain and asset def
    let domain_id: DomainId = DomainId::try_new("zkd", "universal").unwrap();
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("zkd", "universal").unwrap(),
            "zcoin".parse().unwrap(),
        );
    let (owner, _owner_key) = gen_account_in("zkd");
    for instr in [
        Register::domain(Domain::new(domain_id.clone())).into(),
        Register::account(NewAccount::new(owner.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            asset_def_id.clone(),
            "zcoin".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .into(),
    ] {
        execute_isi_component(&mut stx, &owner, instr).unwrap();
    }
    // Register zk policy
    let reg = iroha_data_model::isi::zk::RegisterZkAsset::new(asset_def_id.clone(), None);
    let ib: InstructionBox = reg.into();
    execute_isi_component(&mut stx, &owner, ib).unwrap();
    stx.apply();
    block
        .commit_empty_block_for_testing()
        .expect("commit setup block");
    // Verify metadata key exists
    let view_policy = state.view();
    let def = view_policy
        .world
        .asset_definitions()
        .get(&asset_def_id)
        .unwrap();
    assert_eq!(
        def.confidential_policy().mode(),
        ConfidentialPolicyMode::TransparentOnly
    );
    assert!(def.confidential_policy().vk_set_hash().is_none());
    assert_eq!(
        def.confidential_policy().poseidon_params_id(),
        defaults::confidential::POSEIDON_PARAMS_ID
    );
    assert_eq!(
        def.confidential_policy().pedersen_params_id(),
        defaults::confidential::PEDERSEN_PARAMS_ID
    );
    let policy_key = Name::from_str("zk.policy").unwrap();
    let val = def.metadata().get(&policy_key);
    assert!(val.is_some());
    let policy_json: norito::json::Value = val.unwrap().try_into_any_norito().expect("json decode");
    let digest_hex = policy_json
        .get("features_digest")
        .and_then(|v| v.as_str())
        .expect("features_digest present");
    assert_eq!(
        digest_hex,
        hex::encode(def.confidential_policy().features_digest().as_ref())
    );
}
#[test]
fn register_zk_asset_without_shielding_sets_transparent_policy() {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::new(), kura, query);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let domain_id: DomainId = DomainId::try_new("zkd", "universal").unwrap();
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("zkd", "universal").unwrap(),
            "desk".parse().unwrap(),
        );
    let (owner, _owner_key) = gen_account_in("zkd");
    for instr in [
        Register::domain(Domain::new(domain_id.clone())).into(),
        Register::account(NewAccount::new(owner.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            asset_def_id.clone(),
            "desk".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .into(),
    ] {
        execute_isi_component(&mut stx, &owner, instr).unwrap();
    }
    let reg = iroha_data_model::isi::zk::RegisterZkAsset::new(asset_def_id.clone(), None);
    execute_isi_component(&mut stx, &owner, InstructionBox::from(reg)).unwrap();
    stx.apply();
    block
        .commit_empty_block_for_testing()
        .expect("commit setup block");
    let view_policy = state.view();
    let def = view_policy
        .world
        .asset_definitions()
        .get(&asset_def_id)
        .unwrap();
    assert_eq!(
        def.confidential_policy().mode(),
        ConfidentialPolicyMode::TransparentOnly
    );
    assert!(def.confidential_policy().vk_set_hash().is_none());
    assert_eq!(
        def.confidential_policy().poseidon_params_id(),
        defaults::confidential::POSEIDON_PARAMS_ID
    );
    assert_eq!(
        def.confidential_policy().pedersen_params_id(),
        defaults::confidential::PEDERSEN_PARAMS_ID
    );
    let policy_key = Name::from_str("zk.policy").unwrap();
    let val = def.metadata().get(&policy_key).unwrap();
    let policy_json: norito::json::Value = val.try_into_any_norito().expect("json decode");
    assert!(policy_json.get("vk_shield").is_none());
    assert!(policy_json.get("vk_shield_commitment").is_none());
    let digest_hex = policy_json
        .get("features_digest")
        .and_then(|v| v.as_str())
        .expect("features_digest present");
    assert_eq!(
        digest_hex,
        hex::encode(def.confidential_policy().features_digest().as_ref())
    );
}
#[test]
fn register_zk_asset_rejects_noncanonical_unshield_verifier() {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::new(), kura, query);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let domain_id = DomainId::try_new("zkd", "universal").expect("domain id");
    let asset_def_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "wrong_unshield_vk".parse().expect("asset name"),
    );
    let (owner, _owner_key) = gen_account_in("zkd");
    let wrong_vk_name = "transfer_key_misbound_as_unshield";
    let wrong_vk_id = VerifyingKeyId::new(NATIVE_PIPA_R_BACKEND, wrong_vk_name);
    let wrong_vk_record = confidential_v2::confidential_transfer_v2_vk_record(wrong_vk_name, 1)
        .expect("canonical transfer verifier");
    for instruction in [
        Register::domain(Domain::new(domain_id)).into(),
        Register::account(NewAccount::new(owner.clone())).into(),
        Grant::account_permission(
            Permission::new("CanManageVerifyingKeys".parse().unwrap(), Json::new(())),
            owner.clone(),
        )
        .into(),
        Register::asset_definition(AssetDefinition::numeric(
            asset_def_id.clone(),
            "wrong_unshield_vk".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .into(),
        iroha_data_model::isi::verifying_keys::RegisterVerifyingKey {
            id: wrong_vk_id.clone(),
            record: wrong_vk_record,
        }
        .into(),
    ] {
        execute_isi_component(&mut stx, &owner, instruction)
            .expect("set up verifier-binding fixture");
    }
    let registration =
        iroha_data_model::isi::zk::RegisterZkAsset::new(asset_def_id.clone(), Some(wrong_vk_id));
    let error = execute_isi_component(&mut stx, &owner, registration.into())
        .expect_err("a transfer circuit cannot define unshield tree semantics");
    assert!(
        format!("{error:?}").contains("vk_unshield"),
        "unexpected verifier-binding error: {error:?}"
    );
    assert!(
        stx.world.zk_assets().get(&asset_def_id).is_none(),
        "failed registration must not create confidential state"
    );
}
#[test]
fn schedule_confidential_policy_transition_records_pending() {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::new(), kura, query);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    // Setup base entities.
    let domain_id: DomainId = DomainId::try_new("zkd", "universal").unwrap();
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("zkd", "universal").unwrap(),
            "schedule".parse().unwrap(),
        );
    let (owner, _owner_key) = gen_account_in("zkd");
    for instr in [
        Register::domain(Domain::new(domain_id.clone())).into(),
        Register::account(NewAccount::new(owner.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            asset_def_id.clone(),
            "schedule".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .into(),
    ] {
        execute_isi_component(&mut stx, &owner, instr).unwrap();
    }
    // Register asset with convertible policy (allow shield/unshield).
    let reg = iroha_data_model::isi::zk::RegisterZkAsset::new(asset_def_id.clone(), None);
    execute_isi_component(&mut stx, &owner, reg.into()).unwrap();
    set_confidential_policy_mode(&mut stx, &asset_def_id, ConfidentialPolicyMode::Convertible);
    stx.apply();
    block
        .commit_empty_block_for_testing()
        .expect("commit setup block");
    // New block for scheduling the transition.
    let header2 = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block2 = state.block(header2);
    let mut stx2 = block2.transaction();
    let delay = defaults::confidential::POLICY_TRANSITION_DELAY_BLOCKS;
    let window_blocks = defaults::confidential::POLICY_TRANSITION_WINDOW_BLOCKS;
    let effective_height = stx2.block_height() + delay + window_blocks;
    let transition_id = Hash::new(b"convert-to-shielded");
    let schedule = iroha_data_model::isi::zk::ScheduleConfidentialPolicyTransition::new(
        asset_def_id.clone(),
        ConfidentialPolicyMode::ShieldedOnly,
        effective_height,
        transition_id.clone(),
        Some(defaults::confidential::POLICY_TRANSITION_WINDOW_BLOCKS),
    );
    execute_isi_component(&mut stx2, &owner, schedule.into()).unwrap();
    stx2.apply();
    block2
        .commit_empty_block_for_testing()
        .expect("commit schedule block");
    let view = state.view();
    let def = view
        .world
        .asset_definitions()
        .get(&asset_def_id)
        .expect("asset definition present");
    assert_eq!(
        def.confidential_policy().mode(),
        ConfidentialPolicyMode::Convertible
    );
    let pending = def
        .confidential_policy()
        .pending_transition()
        .expect("pending transition scheduled");
    assert_eq!(pending.new_mode(), ConfidentialPolicyMode::ShieldedOnly);
    assert_eq!(pending.effective_height(), effective_height);
    assert_eq!(pending.transition_id(), &transition_id);
    let policy_key = Name::from_str("zk.policy").unwrap();
    let policy_json: norito::json::Value = def
        .metadata()
        .get(&policy_key)
        .expect("policy metadata present")
        .try_into_any_norito()
        .expect("policy metadata decodes");
    assert!(
        policy_json
            .get("pending_transition")
            .and_then(|value| value.as_object())
            .is_some(),
        "metadata should capture pending transition summary"
    );
}
#[test]
fn stale_confidential_downgrade_is_discarded_and_metadata_remains_coherent() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let domain_id = DomainId::try_new("zkd", "universal").expect("valid domain");
    let asset_def_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "irreversible".parse().expect("valid asset name"),
    );
    let (owner, _owner_key) = gen_account_in("zkd");
    for instruction in [
        Register::domain(Domain::new(domain_id)).into(),
        Register::account(NewAccount::new(owner.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            asset_def_id.clone(),
            "irreversible".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .into(),
        iroha_data_model::isi::zk::RegisterZkAsset::new(asset_def_id.clone(), None).into(),
    ] {
        execute_isi_component(&mut stx, &owner, instruction).expect("setup instruction succeeds");
    }
    let transition = ConfidentialPolicyTransition {
        new_mode: ConfidentialPolicyMode::TransparentOnly,
        effective_height: 2,
        previous_mode: ConfidentialPolicyMode::Convertible,
        transition_id: Hash::new(b"retired-confidential-downgrade"),
        conversion_window: None,
    };
    let mut policy = AssetConfidentialPolicy::convertible();
    policy.pending_transition = Some(transition);
    stx.world
        .asset_definition_mut(&asset_def_id)
        .expect("asset definition exists")
        .set_confidential_policy(policy);
    stx.world.track_confidential_policy_transition_for_testing(
        &asset_def_id,
        transition.effective_height(),
    );
    stx.apply();
    block
        .commit_empty_block_for_testing()
        .expect("commit stale pending transition");
    let transition_header =
        iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    state
        .block(transition_header)
        .commit_empty_block_for_testing()
        .expect("commit defensive transition sweep");
    let view = state.view();
    let definition = view
        .world
        .asset_definitions()
        .get(&asset_def_id)
        .expect("asset definition remains");
    assert_eq!(
        definition.confidential_policy().mode(),
        ConfidentialPolicyMode::Convertible,
        "a stale transition must never disable confidentiality"
    );
    assert!(
        definition
            .confidential_policy()
            .pending_transition()
            .is_none(),
        "the invalid pending transition must be cleared"
    );
    let policy_key = Name::from_str("zk.policy").expect("valid policy metadata key");
    let policy_json: norito::json::Value = definition
        .metadata()
        .get(&policy_key)
        .expect("policy metadata present")
        .try_into_any_norito()
        .expect("policy metadata decodes");
    assert_eq!(
        policy_json
            .get("mode")
            .and_then(norito::json::Value::as_str),
        Some("Convertible")
    );
    assert!(
        policy_json
            .get("pending_transition")
            .is_some_and(norito::json::Value::is_null),
        "persisted metadata must clear the rejected transition"
    );
}
#[test]
fn confidential_policy_transition_applies_at_effective_height() {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::new(), kura, query);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let domain_id: DomainId = DomainId::try_new("zkd", "universal").unwrap();
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("zkd", "universal").unwrap(),
            "transition".parse().unwrap(),
        );
    let (owner, _owner_key) = gen_account_in("zkd");
    for instr in [
        Register::domain(Domain::new(domain_id.clone())).into(),
        Register::account(NewAccount::new(owner.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            asset_def_id.clone(),
            "transition".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .into(),
    ] {
        execute_isi_component(&mut stx, &owner, instr).unwrap();
    }
    let reg = iroha_data_model::isi::zk::RegisterZkAsset::new(asset_def_id.clone(), None);
    execute_isi_component(&mut stx, &owner, reg.into()).unwrap();
    set_confidential_policy_mode(&mut stx, &asset_def_id, ConfidentialPolicyMode::Convertible);
    stx.apply();
    block
        .commit_empty_block_for_testing()
        .expect("commit setup block");
    let header2 = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block2 = state.block(header2);
    let mut stx2 = block2.transaction();
    let delay = defaults::confidential::POLICY_TRANSITION_DELAY_BLOCKS;
    let window_blocks = defaults::confidential::POLICY_TRANSITION_WINDOW_BLOCKS;
    let effective_height = stx2.block_height() + delay + window_blocks;
    let transition_id = Hash::new(b"convert->shielded");
    let schedule = iroha_data_model::isi::zk::ScheduleConfidentialPolicyTransition::new(
        asset_def_id.clone(),
        ConfidentialPolicyMode::ShieldedOnly,
        effective_height,
        transition_id.clone(),
        Some(defaults::confidential::POLICY_TRANSITION_WINDOW_BLOCKS),
    );
    execute_isi_component(&mut stx2, &owner, schedule.into()).unwrap();
    stx2.apply();
    block2
        .commit_empty_block_for_testing()
        .expect("commit schedule block");
    // New block at the scheduled effective height.
    let header3 = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(effective_height).unwrap(),
        None,
        None,
        0,
        0,
    );
    let mut block3 = state.block(header3);
    let mut stx3 = block3.transaction();
    let next_effective = stx3.block_height() + delay + 4;
    let transition_id_2 = Hash::new(b"shielded->convertible");
    let reschedule = iroha_data_model::isi::zk::ScheduleConfidentialPolicyTransition::new(
        asset_def_id.clone(),
        ConfidentialPolicyMode::Convertible,
        next_effective,
        transition_id_2.clone(),
        None,
    );
    execute_isi_component(&mut stx3, &owner, reschedule.into()).unwrap();
    stx3.apply();
    block3
        .commit_world_overlay_for_testing()
        .expect("commit effective block");
    let view = state.view();
    let def = view
        .world
        .asset_definitions()
        .get(&asset_def_id)
        .expect("asset definition present");
    assert_eq!(
        def.confidential_policy().mode(),
        ConfidentialPolicyMode::ShieldedOnly,
        "previous transition should have activated"
    );
    let pending = def
        .confidential_policy()
        .pending_transition()
        .expect("new pending transition set");
    assert_eq!(pending.new_mode(), ConfidentialPolicyMode::Convertible);
    assert_eq!(pending.transition_id(), &transition_id_2);
    assert_eq!(pending.effective_height(), next_effective);
}
#[test]
fn cancel_confidential_policy_transition_clears_pending() {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::new(), kura, query);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let domain_id: DomainId = DomainId::try_new("zkd", "universal").unwrap();
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("zkd", "universal").unwrap(),
            "cancel".parse().unwrap(),
        );
    let (owner, _owner_key) = gen_account_in("zkd");
    for instr in [
        Register::domain(Domain::new(domain_id.clone())).into(),
        Register::account(NewAccount::new(owner.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            asset_def_id.clone(),
            "cancel".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .into(),
    ] {
        execute_isi_component(&mut stx, &owner, instr).unwrap();
    }
    let reg = iroha_data_model::isi::zk::RegisterZkAsset::new(asset_def_id.clone(), None);
    execute_isi_component(&mut stx, &owner, reg.into()).unwrap();
    set_confidential_policy_mode(&mut stx, &asset_def_id, ConfidentialPolicyMode::Convertible);
    stx.apply();
    block
        .commit_empty_block_for_testing()
        .expect("commit setup block");
    let header2 = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block2 = state.block(header2);
    let mut stx2 = block2.transaction();
    let delay = defaults::confidential::POLICY_TRANSITION_DELAY_BLOCKS;
    let window_blocks = defaults::confidential::POLICY_TRANSITION_WINDOW_BLOCKS;
    let effective_height = stx2.block_height() + delay + window_blocks;
    let transition_id = Hash::new(b"pending-cancel");
    let schedule = iroha_data_model::isi::zk::ScheduleConfidentialPolicyTransition::new(
        asset_def_id.clone(),
        ConfidentialPolicyMode::ShieldedOnly,
        effective_height,
        transition_id.clone(),
        Some(defaults::confidential::POLICY_TRANSITION_WINDOW_BLOCKS),
    );
    execute_isi_component(&mut stx2, &owner, schedule.into()).unwrap();
    let cancel = iroha_data_model::isi::zk::CancelConfidentialPolicyTransition::new(
        asset_def_id.clone(),
        transition_id.clone(),
    );
    execute_isi_component(&mut stx2, &owner, cancel.into()).unwrap();
    stx2.apply();
    block2
        .commit_empty_block_for_testing()
        .expect("commit cancel block");
    let view = state.view();
    let def = view
        .world
        .asset_definitions()
        .get(&asset_def_id)
        .expect("asset definition present");
    assert!(def.confidential_policy().pending_transition().is_none());
    assert_eq!(
        def.confidential_policy().mode(),
        ConfidentialPolicyMode::Convertible
    );
    let policy_key = Name::from_str("zk.policy").unwrap();
    let policy_json: norito::json::Value = def
        .metadata()
        .get(&policy_key)
        .expect("policy metadata present")
        .try_into_any_norito()
        .expect("policy metadata decodes");
    assert!(
        policy_json
            .get("pending_transition")
            .map(|value| value.is_null())
            .unwrap_or(true),
        "pending transition metadata should be cleared"
    );
}
#[test]
fn zk_roots_are_bounded_in_world_state() {
    use iroha_config::parameters::{actual as cfg, defaults};
    use iroha_core::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use nonzero_ext::nonzero;
    // Create state and set a small ZK cap
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    // Domains, accounts and asset definitions are registered at genesis only, so the
    // fixture seeds them in the initial World.
    let domain_id: DomainId = DomainId::try_new("zkd", "universal").unwrap();
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("zkd", "universal").unwrap(),
            "zcoin".parse().unwrap(),
        );
    let (owner, _owner_key) = gen_account_in("zkd");
    let world = World::with(
        [Domain::new(domain_id.clone()).build(&owner)],
        [Account::new(owner.clone()).build(&owner)],
        [AssetDefinition::numeric(
            asset_def_id.clone(),
            "zcoin".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&owner)],
    );
    let mut state = State::new_for_testing(world, kura, query);
    state
        .set_zk(cfg::Zk {
            pipa_r: iroha_config::parameters::actual::PipaR::default(),
            trace: iroha_config::parameters::actual::DiagnosticTrace::default(),
            ipa_commitment: iroha_config::parameters::actual::IpaCommitment::default(),
            max_verify_batch: iroha_config::parameters::defaults::zk::MAX_VERIFY_BATCH,
            fastpq: cfg::Fastpq {
                producer: iroha_config::parameters::actual::FastpqProducer::default(),
                execution_mode: cfg::FastpqExecutionMode::Cpu,
                poseidon_mode: cfg::FastpqPoseidonMode::Cpu,
                proof_sidecar_queue_cap: defaults::zk::fastpq::PROOF_SIDECAR_QUEUE_CAP,
                proof_sidecar_max_bytes: defaults::zk::fastpq::PROOF_SIDECAR_MAX_BYTES,
                proof_sidecar_max_retries: defaults::zk::fastpq::PROOF_SIDECAR_MAX_RETRIES,
                device_class: None,
                chip_family: None,
                gpu_kind: None,
                metal_queue_fanout: None,
                metal_queue_column_threshold: None,
                metal_max_in_flight: None,
                metal_threadgroup_width: None,
                metal_trace: defaults::zk::fastpq::METAL_TRACE,
                metal_debug_enum: defaults::zk::fastpq::METAL_DEBUG_ENUM,
            },
            stark: cfg::Stark::default(),
            sccp: cfg::Sccp::default(),
            ballot_history_cap: defaults::zk::vote::BALLOT_HISTORY_CAP,
            preverify_max_bytes: defaults::zk::preverify::MAX_BYTES,
            preverify_budget_bytes: defaults::zk::preverify::BUDGET_BYTES,
            proof_history_cap: defaults::zk::proof::RECORD_HISTORY_CAP,
            proof_retention_grace_blocks: defaults::zk::proof::RETENTION_GRACE_BLOCKS,
            proof_prune_batch: defaults::zk::proof::PRUNE_BATCH_SIZE,
            bridge_proof_max_range_len: defaults::zk::proof::BRIDGE_MAX_RANGE_LEN,
            bridge_proof_max_past_age_blocks: defaults::zk::proof::BRIDGE_MAX_PAST_AGE_BLOCKS,
            bridge_proof_max_future_drift_blocks:
                defaults::zk::proof::BRIDGE_MAX_FUTURE_DRIFT_BLOCKS,
            poseidon_params_id: defaults::confidential::POSEIDON_PARAMS_ID,
            pedersen_params_id: defaults::confidential::PEDERSEN_PARAMS_ID,
            kaigi_authorization_vk: None,

            kaigi_usage_vk: None,
            max_proof_size_bytes: defaults::confidential::MAX_PROOF_SIZE_BYTES,
            max_nullifiers_per_tx: defaults::confidential::MAX_NULLIFIERS_PER_TX,
            max_commitments_per_tx: 32,
            max_confidential_ops_per_block: 32,
            verify_timeout: defaults::confidential::VERIFY_TIMEOUT,
            max_anchor_age_blocks: defaults::confidential::MAX_ANCHOR_AGE_BLOCKS,
            max_proof_bytes_block: defaults::confidential::MAX_PROOF_BYTES_BLOCK,
            max_verify_calls_per_tx: defaults::confidential::MAX_VERIFY_CALLS_PER_TX,
            max_verify_calls_per_block: defaults::confidential::MAX_VERIFY_CALLS_PER_BLOCK,
            max_public_inputs: defaults::confidential::MAX_PUBLIC_INPUTS,
            reorg_depth_bound: defaults::confidential::REORG_DEPTH_BOUND,
            policy_transition_delay_blocks: defaults::confidential::POLICY_TRANSITION_DELAY_BLOCKS,
            policy_transition_window_blocks:
                defaults::confidential::POLICY_TRANSITION_WINDOW_BLOCKS,
            policy_transition_max_per_height:
                defaults::confidential::POLICY_TRANSITION_MAX_PER_HEIGHT,
            tree_roots_history_len: nonzero!(4_usize),
            tree_frontier_checkpoint_interval:
                defaults::confidential::TREE_FRONTIER_CHECKPOINT_INTERVAL,
            registry_max_vk_entries: defaults::confidential::REGISTRY_MAX_VK_ENTRIES,
            registry_max_params_entries: defaults::confidential::REGISTRY_MAX_PARAMS_ENTRIES,
            registry_max_delta_per_block: defaults::confidential::REGISTRY_MAX_DELTA_PER_BLOCK,
            gas: cfg::ConfidentialGas {
                proof_base: defaults::confidential::gas::PROOF_BASE,
                per_public_input: defaults::confidential::gas::PER_PUBLIC_INPUT,
                per_proof_byte: defaults::confidential::gas::PER_PROOF_BYTE,
                per_nullifier: defaults::confidential::gas::PER_NULLIFIER,
                per_commitment: defaults::confidential::gas::PER_COMMITMENT,
            },
        })
        .expect("empty state accepts bounded-roots test configuration");
    // Instruction execution requires committed root authority: the first height commits
    // the Global root scope and the fixture executes from the second height on.
    root_scope_fixture::commit_global_root_scope(&state);
    // Begin block/transaction
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    // Mint and register the ZK policy (Hybrid; allow shield). Registering a ZK asset is an
    // administrative instruction of the governed lifecycle, so the fixture applies the two
    // instructions directly; the subject of the test is the bound of the root history.
    {
        use iroha_core::smartcontracts::Execute as _;
        Mint::asset_quantity(10_000u64, AssetId::of(asset_def_id.clone(), owner.clone()))
            .execute(&owner, &mut stx)
            .expect("mint the fixture balance");
        iroha_data_model::isi::zk::RegisterZkAsset::new(asset_def_id.clone(), None)
            .execute(&owner, &mut stx)
            .expect("register the fixture ZK asset");
    }
    // Seed many authenticated commitment transitions to exceed the root-history cap.
    let mut zk_state = stx
        .world
        .zk_assets()
        .get(&asset_def_id)
        .cloned()
        .expect("registered confidential asset state");
    for i in 0..16u8 {
        let mut note = [0u8; 32];
        note[0] = i + 1;
        zk_state
            .push_commitment(note, nonzero!(4_usize))
            .expect("seed bounded root transition");
    }
    stx.world
        .zk_assets_mut_for_testing()
        .remove(asset_def_id.clone());
    stx.world
        .zk_assets_mut_for_testing()
        .insert(asset_def_id.clone(), zk_state);
    stx.apply();
    // The fixture height follows no certified parent, so its World overlay is committed
    // without pretending that a block was finalized.
    block
        .commit_world_overlay_for_testing()
        .expect("commit bounded root-history fixture");
    // Assert bounded roots in world state
    let view = state.view();
    let zk_state = view.world.zk_assets().get(&asset_def_id).expect("zk state");
    assert!(zk_state.root_history.len() <= 4);
    assert_eq!(zk_state.root_history.len(), 4);
}
#[test]
fn frontier_checkpoints_respect_reorg_depth_bound() {
    use iroha_config::parameters::{actual as cfg, defaults};
    use iroha_core::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use nonzero_ext::nonzero;
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(World::new(), kura, query);
    state
        .set_zk(cfg::Zk {
            pipa_r: iroha_config::parameters::actual::PipaR::default(),
            trace: iroha_config::parameters::actual::DiagnosticTrace::default(),
            ipa_commitment: iroha_config::parameters::actual::IpaCommitment::default(),
            max_verify_batch: iroha_config::parameters::defaults::zk::MAX_VERIFY_BATCH,
            fastpq: cfg::Fastpq {
                producer: iroha_config::parameters::actual::FastpqProducer::default(),
                execution_mode: cfg::FastpqExecutionMode::Cpu,
                poseidon_mode: cfg::FastpqPoseidonMode::Cpu,
                proof_sidecar_queue_cap: defaults::zk::fastpq::PROOF_SIDECAR_QUEUE_CAP,
                proof_sidecar_max_bytes: defaults::zk::fastpq::PROOF_SIDECAR_MAX_BYTES,
                proof_sidecar_max_retries: defaults::zk::fastpq::PROOF_SIDECAR_MAX_RETRIES,
                device_class: None,
                chip_family: None,
                gpu_kind: None,
                metal_queue_fanout: None,
                metal_queue_column_threshold: None,
                metal_max_in_flight: None,
                metal_threadgroup_width: None,
                metal_trace: defaults::zk::fastpq::METAL_TRACE,
                metal_debug_enum: defaults::zk::fastpq::METAL_DEBUG_ENUM,
            },
            stark: cfg::Stark::default(),
            sccp: cfg::Sccp::default(),
            ballot_history_cap: defaults::zk::vote::BALLOT_HISTORY_CAP,
            preverify_max_bytes: defaults::zk::preverify::MAX_BYTES,
            preverify_budget_bytes: defaults::zk::preverify::BUDGET_BYTES,
            proof_history_cap: defaults::zk::proof::RECORD_HISTORY_CAP,
            proof_retention_grace_blocks: defaults::zk::proof::RETENTION_GRACE_BLOCKS,
            proof_prune_batch: defaults::zk::proof::PRUNE_BATCH_SIZE,
            bridge_proof_max_range_len: defaults::zk::proof::BRIDGE_MAX_RANGE_LEN,
            bridge_proof_max_past_age_blocks: defaults::zk::proof::BRIDGE_MAX_PAST_AGE_BLOCKS,
            bridge_proof_max_future_drift_blocks:
                defaults::zk::proof::BRIDGE_MAX_FUTURE_DRIFT_BLOCKS,
            poseidon_params_id: defaults::confidential::POSEIDON_PARAMS_ID,
            pedersen_params_id: defaults::confidential::PEDERSEN_PARAMS_ID,
            kaigi_authorization_vk: None,

            kaigi_usage_vk: None,
            max_proof_size_bytes: defaults::confidential::MAX_PROOF_SIZE_BYTES,
            max_nullifiers_per_tx: defaults::confidential::MAX_NULLIFIERS_PER_TX,
            max_commitments_per_tx: defaults::confidential::MAX_COMMITMENTS_PER_TX,
            max_confidential_ops_per_block: defaults::confidential::MAX_CONFIDENTIAL_OPS_PER_BLOCK,
            verify_timeout: defaults::confidential::VERIFY_TIMEOUT,
            max_anchor_age_blocks: defaults::confidential::MAX_ANCHOR_AGE_BLOCKS,
            max_proof_bytes_block: defaults::confidential::MAX_PROOF_BYTES_BLOCK,
            max_verify_calls_per_tx: defaults::confidential::MAX_VERIFY_CALLS_PER_TX,
            max_verify_calls_per_block: defaults::confidential::MAX_VERIFY_CALLS_PER_BLOCK,
            max_public_inputs: defaults::confidential::MAX_PUBLIC_INPUTS,
            reorg_depth_bound: 3,
            policy_transition_delay_blocks: defaults::confidential::POLICY_TRANSITION_DELAY_BLOCKS,
            policy_transition_window_blocks:
                defaults::confidential::POLICY_TRANSITION_WINDOW_BLOCKS,
            policy_transition_max_per_height:
                defaults::confidential::POLICY_TRANSITION_MAX_PER_HEIGHT,
            tree_roots_history_len: nonzero!(8_usize),
            tree_frontier_checkpoint_interval: 1,
            registry_max_vk_entries: defaults::confidential::REGISTRY_MAX_VK_ENTRIES,
            registry_max_params_entries: defaults::confidential::REGISTRY_MAX_PARAMS_ENTRIES,
            registry_max_delta_per_block: defaults::confidential::REGISTRY_MAX_DELTA_PER_BLOCK,
            gas: cfg::ConfidentialGas {
                proof_base: defaults::confidential::gas::PROOF_BASE,
                per_public_input: defaults::confidential::gas::PER_PUBLIC_INPUT,
                per_proof_byte: defaults::confidential::gas::PER_PROOF_BYTE,
                per_nullifier: defaults::confidential::gas::PER_NULLIFIER,
                per_commitment: defaults::confidential::gas::PER_COMMITMENT,
            },
        })
        .expect("empty state accepts checkpoint test configuration");
    let domain_id: DomainId = DomainId::try_new("zkd", "universal").unwrap();
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("zkd", "universal").unwrap(),
            "zcoin".parse().unwrap(),
        );
    let (owner, _owner_key) = gen_account_in("zkd");
    // Block 1: bootstrap domain/account/asset and register policy.
    {
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        for instr in [
            Register::domain(Domain::new(domain_id.clone())).into(),
            Register::account(NewAccount::new(owner.clone())).into(),
            Register::asset_definition(AssetDefinition::numeric(
                asset_def_id.clone(),
                "zcoin".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            ))
            .into(),
            iroha_data_model::isi::zk::RegisterZkAsset::new(asset_def_id.clone(), None).into(),
        ] {
            execute_isi_component(&mut stx, &owner, instr).unwrap();
        }
        stx.apply();
        block
            .commit_empty_block_for_testing()
            .expect("commit setup block");
    }
    // Subsequent blocks append one authenticated commitment and advance frontiers.
    for h in 2_u64..=8 {
        let header = iroha_data_model::block::BlockHeader::new(
            NonZeroU64::new(h).expect("block height must be non-zero"),
            None,
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let mut commitment = [0u8; 32];
        commitment[0] = h as u8;
        let mut zk_state = stx
            .world
            .zk_assets()
            .get(&asset_def_id)
            .cloned()
            .expect("registered confidential asset state");
        zk_state
            .push_commitment(commitment, nonzero!(8_usize))
            .expect("append authenticated commitment");
        zk_state
            .record_frontier_checkpoint(h, 1, 3)
            .expect("record bounded frontier checkpoint");
        stx.world
            .zk_assets_mut_for_testing()
            .remove(asset_def_id.clone());
        stx.world
            .zk_assets_mut_for_testing()
            .insert(asset_def_id.clone(), zk_state);
        stx.apply();
        block
            .commit_empty_block_for_testing()
            .expect("commit frontier checkpoint block");
    }
    let view = state.view();
    let zk_state = view.world.zk_assets().get(&asset_def_id).expect("zk state");
    assert_eq!(zk_state.frontier_checkpoints.len(), 4);
    assert_eq!(
        zk_state.frontier_checkpoints.first().map(|cp| cp.height),
        Some(5)
    );
    assert_eq!(
        zk_state.frontier_checkpoints.last().map(|cp| cp.height),
        Some(8)
    );
}
