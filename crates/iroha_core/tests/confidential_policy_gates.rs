//! Tests covering confidential policy gating for transparent asset instructions.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
use iroha_config::parameters::defaults;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, StateTransaction, World, WorldReadOnly},
    tx::ValidationFail,
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    asset::{
        AssetDefinition, AssetId,
        definition::{AssetConfidentialPolicy, ConfidentialPolicyMode},
    },
    isi::{
        InstructionBox, Mint, Register, Transfer, error::InstructionExecutionError,
        zk::RegisterZkAsset,
    },
    prelude::*,
};
use iroha_model_base::domain::DomainId;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
use std::num::NonZeroU64;
fn checked_random_confidential_policy_keypair() -> KeyPair {
    KeyPair::try_random().expect("generate checked confidential policy keypair")
}
fn checked_random_confidential_policy_account_id() -> AccountId {
    AccountId::new(
        checked_random_confidential_policy_keypair()
            .public_key()
            .clone(),
    )
}
#[test]
fn confidential_policy_fixture_uses_checked_randomness() {
    let key_pair = checked_random_confidential_policy_keypair();
    assert_eq!(key_pair.public_key().algorithm(), Algorithm::Ed25519);
}
fn init_state() -> (
    State,
    iroha_data_model::block::BlockHeader,
    AccountId,
    DomainId,
    AssetDefinitionId,
) {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::new(), kura, query);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let domain_id: DomainId = DomainId::try_new("zkdomain", "universal").expect("domain id");
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("zkdomain", "universal").unwrap(),
            "shielded".parse().unwrap(),
        );
    let owner = checked_random_confidential_policy_account_id();
    (state, header, owner, domain_id, asset_def_id)
}
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
fn transparent_mint_rejected_for_shielded_only_policy() {
    let (state, header, owner, domain_id, asset_def_id) = init_state();
    let mut block = state.block(header);
    let mut stx = block.transaction();
    // Seed the universal account and explicit domain-owned asset definition.
    for instr in [
        Register::account(Account::new(owner.clone())).into(),
        Register::domain(Domain::new(domain_id.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            asset_def_id.clone(),
            "shielded".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(domain_id.clone()),
        ))
        .into(),
    ] {
        stx.world
            .executor()
            .clone()
            .execute_instruction(&mut stx, &owner, instr)
            .expect("setup instruction should succeed");
    }
    // Register the first-release hybrid ledger, then emulate a completed
    // governance transition to ShieldedOnly.
    let reg = RegisterZkAsset::new(asset_def_id.clone(), None);
    stx.world
        .executor()
        .clone()
        .execute_instruction(&mut stx, &owner, InstructionBox::from(reg))
        .expect("register zk asset");
    {
        let asset_def = stx
            .world
            .asset_definition_mut(&asset_def_id)
            .expect("asset definition exists");
        let previous_policy = *asset_def.confidential_policy();
        let mut policy = AssetConfidentialPolicy::shielded_only();
        policy.vk_set_hash = *previous_policy.vk_set_hash();
        policy.poseidon_params_id = previous_policy.poseidon_params_id();
        policy.pedersen_params_id = previous_policy.pedersen_params_id();
        asset_def.set_confidential_policy(policy);
    }
    // Attempt to mint transparently; should be rejected by policy gate.
    let asset_id = AssetId::new(asset_def_id.clone(), owner.clone());
    let mint = Mint::asset_quantity(10_u32, asset_id);
    let result = stx.world.executor().clone().execute_instruction(
        &mut stx,
        &owner,
        InstructionBox::from(mint),
    );
    let err = result.expect_err("mint expected to fail");
    match err {
        ValidationFail::InstructionFailed(InstructionExecutionError::InvariantViolation(msg)) => {
            assert!(
                msg.contains("transparent mint not permitted by policy"),
                "unexpected error message: {msg}"
            )
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
#[test]
fn transparent_transfer_rejected_after_policy_switch_to_shielded_only() {
    let (state, header, owner, domain_id, asset_def_id) = init_state();
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let recipient = checked_random_confidential_policy_account_id();
    for instr in [
        Register::account(Account::new(owner.clone())).into(),
        Register::domain(Domain::new(domain_id.clone())).into(),
        Register::account(Account::new(recipient.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            asset_def_id.clone(),
            "shielded".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(domain_id.clone()),
        ))
        .into(),
    ] {
        stx.world
            .executor()
            .clone()
            .execute_instruction(&mut stx, &owner, instr)
            .expect("setup instruction should succeed");
    }
    // Start in convertible mode so transparent mint succeeds.
    let reg = RegisterZkAsset::new(asset_def_id.clone(), None);
    stx.world
        .executor()
        .clone()
        .execute_instruction(&mut stx, &owner, InstructionBox::from(reg))
        .expect("register convertible zk asset");
    let asset_id = AssetId::new(asset_def_id.clone(), owner.clone());
    stx.world
        .executor()
        .clone()
        .execute_instruction(
            &mut stx,
            &owner,
            InstructionBox::from(Mint::asset_quantity(25_u32, asset_id.clone())),
        )
        .expect("initial mint should succeed");
    // Flip policy to ShieldedOnly to emulate a governance transition becoming effective.
    {
        let asset_def = stx
            .world
            .asset_definition_mut(&asset_def_id)
            .expect("asset definition exists");
        let previous_policy = *asset_def.confidential_policy();
        let mut policy = AssetConfidentialPolicy::shielded_only();
        policy.vk_set_hash = *previous_policy.vk_set_hash();
        policy.poseidon_params_id = previous_policy.poseidon_params_id();
        policy.pedersen_params_id = previous_policy.pedersen_params_id();
        asset_def.set_confidential_policy(policy);
    }
    // Attempt a transparent transfer; policy gate should reject it.
    let transfer = Transfer::asset_quantity(asset_id, 5_u32, recipient);
    let result = stx.world.executor().clone().execute_instruction(
        &mut stx,
        &owner,
        InstructionBox::from(transfer),
    );
    let err = result.expect_err("transfer expected to fail");
    match err {
        ValidationFail::InstructionFailed(InstructionExecutionError::InvariantViolation(msg)) => {
            assert!(
                msg.contains("transparent transfer not permitted by policy"),
                "unexpected error message: {msg}"
            )
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
#[test]
fn schedule_shielded_only_requires_window() {
    let (state, header, owner, domain_id, asset_def_id) = init_state();
    let mut block = state.block(header);
    let mut stx = block.transaction();
    for instr in [
        Register::account(Account::new(owner.clone())).into(),
        Register::domain(Domain::new(domain_id.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            asset_def_id.clone(),
            "shielded".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(domain_id.clone()),
        ))
        .into(),
    ] {
        stx.world
            .executor()
            .clone()
            .execute_instruction(&mut stx, &owner, instr)
            .expect("setup instruction should succeed");
    }
    let reg = RegisterZkAsset::new(asset_def_id.clone(), None);
    stx.world
        .executor()
        .clone()
        .execute_instruction(&mut stx, &owner, InstructionBox::from(reg))
        .expect("register confidential asset state");
    set_confidential_policy_mode(&mut stx, &asset_def_id, ConfidentialPolicyMode::Convertible);
    stx.apply();
    block
        .commit_empty_block_for_testing()
        .expect("commit setup block");
    let header2 = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block2 = state.block(header2);
    let mut stx2 = block2.transaction();
    let delay = defaults::confidential::POLICY_TRANSITION_DELAY_BLOCKS;
    let notice = defaults::confidential::POLICY_TRANSITION_WINDOW_BLOCKS;
    let current_height = stx2.block_height();
    let lead_time = delay.max(notice) + 1;
    let effective_height = current_height + lead_time;
    let schedule = iroha_data_model::isi::zk::ScheduleConfidentialPolicyTransition::new(
        asset_def_id.clone(),
        ConfidentialPolicyMode::ShieldedOnly,
        effective_height,
        Hash::new(b"missing-window"),
        None,
    );
    let result = schedule.execute(&owner, &mut stx2);
    let err = result.expect_err("transition without window must fail");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("conversion window is required"),
        "unexpected error message: {msg}"
    );
}
#[test]
fn shielded_transition_abort_retains_active_confidential_mode_when_supply_is_non_zero() {
    let (state, header, owner, domain_id, asset_def_id) = init_state();
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let recipient = checked_random_confidential_policy_account_id();
    for instr in [
        Register::account(Account::new(owner.clone())).into(),
        Register::domain(Domain::new(domain_id.clone())).into(),
        Register::account(Account::new(recipient.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            asset_def_id.clone(),
            "shielded".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(domain_id.clone()),
        ))
        .into(),
    ] {
        stx.world
            .executor()
            .clone()
            .execute_instruction(&mut stx, &owner, instr)
            .expect("setup instruction should succeed");
    }
    let reg = iroha_data_model::isi::zk::RegisterZkAsset::new(asset_def_id.clone(), None);
    stx.world
        .executor()
        .clone()
        .execute_instruction(&mut stx, &owner, InstructionBox::from(reg))
        .expect("register confidential asset state");
    set_confidential_policy_mode(&mut stx, &asset_def_id, ConfidentialPolicyMode::Convertible);
    let asset_id = AssetId::new(asset_def_id.clone(), owner.clone());
    stx.world
        .executor()
        .clone()
        .execute_instruction(
            &mut stx,
            &owner,
            InstructionBox::from(Mint::asset_quantity(10_u32, asset_id.clone())),
        )
        .expect("mint should succeed");
    stx.apply();
    block
        .commit_empty_block_for_testing()
        .expect("commit setup block");
    let header2 = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block2 = state.block(header2);
    let mut stx2 = block2.transaction();
    let delay = defaults::confidential::POLICY_TRANSITION_DELAY_BLOCKS;
    let notice = defaults::confidential::POLICY_TRANSITION_WINDOW_BLOCKS;
    let current_height = stx2.block_height();
    let lead_time = delay.max(notice) + 3;
    let effective_height = current_height + lead_time;
    let schedule = iroha_data_model::isi::zk::ScheduleConfidentialPolicyTransition::new(
        asset_def_id.clone(),
        ConfidentialPolicyMode::ShieldedOnly,
        effective_height,
        Hash::new(b"abort-shielded"),
        Some(defaults::confidential::POLICY_TRANSITION_WINDOW_BLOCKS),
    );
    schedule
        .execute(&owner, &mut stx2)
        .expect("schedule transition");
    // Model a transition whose conversion window opened from TransparentOnly:
    // the active mode is already Convertible, while the audit record retains
    // the pre-window mode. Aborting finalization must never strand commitments
    // by restoring that earlier transparent mode.
    let mut policy = *stx2
        .world
        .asset_definition(&asset_def_id)
        .expect("asset definition exists")
        .confidential_policy();
    let mut pending = policy
        .pending_transition
        .expect("scheduled transition is present");
    pending.previous_mode = ConfidentialPolicyMode::TransparentOnly;
    policy.pending_transition = Some(pending);
    stx2.world
        .asset_definition_mut(&asset_def_id)
        .expect("asset definition exists")
        .set_confidential_policy(policy);
    stx2.apply();
    block2
        .commit_empty_block_for_testing()
        .expect("commit scheduling block");
    let header3 = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(effective_height).unwrap(),
        None,
        None,
        0,
        0,
    );
    let mut block3 = state.block(header3);
    let stx3 = block3.transaction();
    stx3.apply();
    block3
        .commit_world_overlay_for_testing()
        .expect("commit transition block");
    let view = state.view();
    let def = view
        .world
        .asset_definitions()
        .get(&asset_def_id)
        .expect("asset definition present");
    assert_eq!(
        def.confidential_policy().mode(),
        ConfidentialPolicyMode::Convertible,
        "transition should abort because transparent supply is non-zero"
    );
    assert!(
        def.confidential_policy().pending_transition().is_none(),
        "pending transition must be cleared after abort"
    );
}
#[test]
fn policy_transition_reaches_shielded_only_on_schedule() {
    let (mut state, header, owner, domain_id, asset_def_id) = init_state();
    let mut zk_cfg = state.installed_zk().clone();
    zk_cfg.policy_transition_delay_blocks = 1;
    zk_cfg.policy_transition_window_blocks = 1;
    state
        .set_zk(zk_cfg)
        .expect("empty state accepts policy test configuration");
    let mut block = state.block(header);
    let mut stx = block.transaction();
    for instr in [
        Register::account(Account::new(owner.clone())).into(),
        Register::domain(Domain::new(domain_id.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            asset_def_id.clone(),
            "shielded".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(domain_id.clone()),
        ))
        .into(),
    ] {
        stx.world
            .executor()
            .clone()
            .execute_instruction(&mut stx, &owner, instr)
            .expect("setup instruction should succeed");
    }
    let reg = RegisterZkAsset::new(asset_def_id.clone(), None);
    stx.world
        .executor()
        .clone()
        .execute_instruction(&mut stx, &owner, InstructionBox::from(reg))
        .expect("register confidential asset state");
    set_confidential_policy_mode(&mut stx, &asset_def_id, ConfidentialPolicyMode::Convertible);
    stx.apply();
    block
        .commit_empty_block_for_testing()
        .expect("commit setup block");
    let header2 = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block2 = state.block(header2);
    let mut stx2 = block2.transaction();
    let effective_height = stx2.block_height() + 2;
    let schedule = iroha_data_model::isi::zk::ScheduleConfidentialPolicyTransition::new(
        asset_def_id.clone(),
        ConfidentialPolicyMode::ShieldedOnly,
        effective_height,
        Hash::new(b"auto-apply"),
        Some(1),
    );
    schedule
        .execute(&owner, &mut stx2)
        .expect("schedule transition");
    stx2.apply();
    block2
        .commit_empty_block_for_testing()
        .expect("commit scheduling block");
    let transition_height =
        NonZeroU64::new(effective_height).expect("effective height must be non-zero");
    let header_transition =
        iroha_data_model::block::BlockHeader::new(transition_height, None, None, 0, 0);
    let block_transition = state.block(header_transition);
    block_transition
        .commit_world_overlay_for_testing()
        .expect("commit transition block");
    let view = state.view();
    let def = view
        .world
        .asset_definitions()
        .get(&asset_def_id)
        .expect("asset definition exists");
    assert_eq!(
        def.confidential_policy().mode(),
        ConfidentialPolicyMode::ShieldedOnly,
        "transition should elevate policy to ShieldedOnly"
    );
    assert!(
        def.confidential_policy().pending_transition().is_none(),
        "pending transition must clear after application"
    );
}
