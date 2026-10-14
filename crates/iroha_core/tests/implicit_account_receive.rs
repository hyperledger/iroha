//! End-to-end regressions for global implicit account receive admission.

use iroha_core::{
    governance::manifest::LaneManifestRegistry,
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    smartcontracts::ivm::cache::IvmCache,
    state::{State, World, WorldReadOnly},
    tx::AcceptedTransaction,
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::{AccountAdmissionMode, AccountAdmissionPolicy},
    executor::ValidationFail,
    isi::error::{
        AccountAdmissionDefaultRoleError, AccountAdmissionError, AccountAdmissionQuotaExceeded,
        AccountAdmissionQuotaScope, InstructionExecutionError,
    },
    prelude::*,
    transaction::error::TransactionRejectionReason,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;
use mv::storage::StorageReadOnly;
use std::{num::NonZeroU64, sync::Arc};
fn balance(state: &State, id: &AssetId) -> Quantity {
    state
        .view()
        .world()
        .assets()
        .get(id)
        .map_or_else(Quantity::zero, |value| value.clone().into_inner())
}
fn test_state(world: World) -> State {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query);
    let nexus = state.nexus_snapshot();
    state.install_lane_manifests_for_testing(&Arc::new(
        LaneManifestRegistry::empty().rebind(&nexus.lane_catalog, &nexus.governance),
    ));
    state
}
fn seeded_account(seed_byte: u8) -> (AccountId, KeyPair) {
    let key_pair = KeyPair::try_from_seed(vec![seed_byte; 32], Algorithm::Ed25519)
        .expect("seeded implicit account receive keypair should be valid");
    let account_id = AccountId::new(key_pair.public_key().clone());
    (account_id, key_pair)
}
fn build_account_in_domain(
    account_id: AccountId,
    _domain_id: DomainId,
    authority: &AccountId,
) -> Account {
    Account::new(account_id.clone()).build(authority)
}
fn block_header(height: u64, timestamp_ms: u64) -> BlockHeader {
    BlockHeader::new(
        NonZeroU64::new(height).expect("height"),
        None,
        None,
        timestamp_ms,
        0,
    )
}
fn accept_transaction(state: &State, tx: SignedTransaction) -> AcceptedTransaction<'static> {
    let network_id = *state.network_id_ref();
    let max_clock_drift = state
        .view()
        .world()
        .parameters()
        .sumeragi()
        .max_clock_drift();
    let tx_params = state.view().world().parameters().transaction();
    let crypto = state.crypto.read().clone();
    AcceptedTransaction::accept(tx, &network_id, max_clock_drift, tx_params, crypto.as_ref())
        .expect("transaction admission must succeed")
}
fn prepare_state(
    policy: Option<AccountAdmissionPolicy>,
    alice_balance: Quantity,
) -> (State, AccountId, KeyPair, AssetDefinitionId, AssetId) {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let (alice_id, alice_kp) = seeded_account(1);
    let domain = Domain::new(domain_id.clone()).build(&alice_id);
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let asset_def = AssetDefinition::numeric(
        asset_def_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&alice_id);
    let alice_asset_id = AssetId::new(asset_def_id.clone(), alice_id.clone());
    let alice_asset = Asset::new(alice_asset_id.clone(), alice_balance);
    let alice_account = build_account_in_domain(alice_id.clone(), domain_id, &alice_id);
    let world = World::with_assets([domain], [alice_account], [asset_def], [alice_asset], []);
    let state = test_state(world);
    if let Some(policy) = policy {
        install_global_policy(&state, &alice_id, policy);
    }
    (state, alice_id, alice_kp, asset_def_id, alice_asset_id)
}
fn install_global_policy(state: &State, authority: &AccountId, policy: AccountAdmissionPolicy) {
    let mut block = state.block(block_header(1, 1_699_999_999_000));
    let mut stx = block.transaction();
    SetParameter::new(Parameter::Custom(policy.into_custom_parameter()))
        .execute(authority, &mut stx)
        .expect("set global account admission policy");
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit policy update");
}
#[test]
fn transfer_to_missing_account_creates_account_by_default() {
    let (state, alice_id, alice_kp, asset_def_id, alice_asset_id) =
        prepare_state(None, Quantity::from(50_u32));
    let network_id = *state.network_id_ref();
    let (dest, _) = seeded_account(2);
    let tx = TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Transfer::asset_quantity(
        alice_asset_id.clone(),
        10_u32,
        dest.clone(),
    )])
    .sign(alice_kp.private_key());
    let accepted = accept_transaction(&state, tx);
    let mut state_block = state.block(block_header(1, 1_700_000_000_000));
    let mut ivm_cache = IvmCache::new();
    let result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut state_block,
        accepted,
        &mut ivm_cache,
        None,
    );
    assert!(result.is_ok(), "transfer must succeed: {result:?}");
    state_block
        .commit_world_overlay_for_testing()
        .expect("commit state");
    let created_via_key: Name = "iroha:created_via".parse().expect("metadata key");
    let details = state
        .view()
        .world()
        .accounts()
        .get(&dest)
        .expect("destination account must exist after receipt")
        .clone()
        .into_inner();
    assert_eq!(
        details
            .metadata()
            .get(&created_via_key)
            .expect("implicit account must be tagged"),
        &Json::new("implicit")
    );
    let dest_asset_id = AssetId::new(asset_def_id, dest.clone());
    assert_eq!(balance(&state, &dest_asset_id), Quantity::from(10_u32));
    assert_eq!(balance(&state, &alice_asset_id), Quantity::from(40_u32));
}
#[test]
fn transfer_to_missing_account_rejected_in_explicit_domain() {
    let policy = AccountAdmissionPolicy {
        mode: AccountAdmissionMode::ExplicitOnly,
        ..AccountAdmissionPolicy::default()
    };
    let (state, alice_id, alice_kp, _asset_def_id, alice_asset_id) =
        prepare_state(Some(policy), Quantity::from(50_u32));
    let network_id = *state.network_id_ref();
    let (dest, _) = seeded_account(2);
    let tx = TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Transfer::asset_quantity(
        alice_asset_id.clone(),
        10_u32,
        dest.clone(),
    )])
    .sign(alice_kp.private_key());
    let accepted = accept_transaction(&state, tx);
    let mut state_block = state.block(block_header(1, 1_700_000_000_000));
    let mut ivm_cache = IvmCache::new();
    let result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut state_block,
        accepted,
        &mut ivm_cache,
        None,
    );
    let err = result.expect_err("transfer must be rejected in ExplicitOnly domain");
    assert!(
        matches!(
            err,
            TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
                InstructionExecutionError::AccountAdmission(
                    AccountAdmissionError::ImplicitAccountCreationDisabled
                )
            ))
        ),
        "unexpected error: {err:?}"
    );
    state_block
        .commit_world_overlay_for_testing()
        .expect("commit state");
    assert_eq!(balance(&state, &alice_asset_id), Quantity::from(50_u32));
    assert!(
        state.view().world().accounts().get(&dest).is_none(),
        "destination must not exist after rejected transfer"
    );
}
#[test]
fn multiple_receipts_in_one_tx_create_account_once() {
    let (state, alice_id, alice_kp, asset_def_id, alice_asset_id) =
        prepare_state(None, Quantity::from(50_u32));
    let network_id = *state.network_id_ref();
    let (dest, _) = seeded_account(2);
    let tx = TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([
        Transfer::asset_quantity(alice_asset_id.clone(), 5_u32, dest.clone()),
        Transfer::asset_quantity(alice_asset_id.clone(), 7_u32, dest.clone()),
    ])
    .sign(alice_kp.private_key());
    let accepted = accept_transaction(&state, tx);
    let mut state_block = state.block(block_header(1, 1_700_000_000_000));
    let mut ivm_cache = IvmCache::new();
    let result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut state_block,
        accepted,
        &mut ivm_cache,
        None,
    );
    assert!(result.is_ok(), "transfer must succeed: {result:?}");
    state_block
        .commit_world_overlay_for_testing()
        .expect("commit state");
    let dest_asset_id = AssetId::new(asset_def_id, dest.clone());
    assert_eq!(balance(&state, &dest_asset_id), Quantity::from(12_u32));
    assert_eq!(balance(&state, &alice_asset_id), Quantity::from(38_u32));
    let account_count = state.view().world().accounts().iter().count();
    assert_eq!(account_count, 2, "account should be created once");
}
#[test]
fn transaction_quota_limits_implicit_accounts() {
    let policy = AccountAdmissionPolicy {
        max_implicit_creations_per_tx: Some(1),
        ..AccountAdmissionPolicy::default()
    };
    let (state, alice_id, alice_kp, _asset_def_id, alice_asset_id) =
        prepare_state(Some(policy), Quantity::from(40_u32));
    let network_id = *state.network_id_ref();
    let (dest1, _) = seeded_account(2);
    let (dest2, _) = seeded_account(3);
    let tx = TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([
        Transfer::asset_quantity(alice_asset_id.clone(), 5_u32, dest1.clone()),
        Transfer::asset_quantity(alice_asset_id.clone(), 5_u32, dest2.clone()),
    ])
    .sign(alice_kp.private_key());
    let accepted = accept_transaction(&state, tx);
    let mut state_block = state.block(block_header(1, 1_700_000_100_000));
    let mut ivm_cache = IvmCache::new();
    let result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut state_block,
        accepted,
        &mut ivm_cache,
        None,
    );
    let err = result.expect_err("tx should be rejected by per-tx quota");
    assert!(
        matches!(
            err,
            TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
                InstructionExecutionError::AccountAdmission(AccountAdmissionError::QuotaExceeded(
                    AccountAdmissionQuotaExceeded {
                        scope: AccountAdmissionQuotaScope::Transaction,
                        ..
                    }
                ))
            ))
        ),
        "unexpected error: {err:?}"
    );
    state_block
        .commit_world_overlay_for_testing()
        .expect("commit state");
    assert_eq!(balance(&state, &alice_asset_id), Quantity::from(40_u32));
    assert!(
        state.view().world().accounts().get(&dest1).is_none(),
        "dest1 must not be created on rejection"
    );
    assert!(
        state.view().world().accounts().get(&dest2).is_none(),
        "dest2 must not be created on rejection"
    );
}
#[test]
fn block_quota_limits_creations_across_transactions() {
    let policy = AccountAdmissionPolicy {
        max_implicit_creations_per_block: Some(1),
        ..AccountAdmissionPolicy::default()
    };
    let (state, alice_id, alice_kp, asset_def_id, alice_asset_id) =
        prepare_state(Some(policy), Quantity::from(60_u32));
    let network_id = *state.network_id_ref();
    let (dest1, _) = seeded_account(2);
    let (dest2, _) = seeded_account(3);
    let tx1 = TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Transfer::asset_quantity(
        alice_asset_id.clone(),
        10_u32,
        dest1.clone(),
    )])
    .sign(alice_kp.private_key());
    let accepted1 = accept_transaction(&state, tx1);
    let tx2 = TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Transfer::asset_quantity(
        alice_asset_id.clone(),
        3_u32,
        dest2.clone(),
    )])
    .sign(alice_kp.private_key());
    let accepted2 = accept_transaction(&state, tx2);
    let mut state_block = state.block(block_header(1, 1_700_000_200_000));
    let mut ivm_cache = IvmCache::new();
    let res1 = iroha_core::tx::execute_component_transaction_for_testing(
        &mut state_block,
        accepted1,
        &mut ivm_cache,
        None,
    );
    assert!(res1.is_ok(), "first tx should succeed: {res1:?}");
    let res2 = iroha_core::tx::execute_component_transaction_for_testing(
        &mut state_block,
        accepted2,
        &mut ivm_cache,
        None,
    );
    let err = res2.expect_err("second tx must be rejected by block quota");
    assert!(
        matches!(
            err,
            TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
                InstructionExecutionError::AccountAdmission(AccountAdmissionError::QuotaExceeded(
                    AccountAdmissionQuotaExceeded {
                        scope: AccountAdmissionQuotaScope::Block,
                        ..
                    }
                ))
            ))
        ),
        "unexpected error: {err:?}"
    );
    state_block
        .commit_world_overlay_for_testing()
        .expect("commit state");
    let dest1_asset_id = AssetId::new(asset_def_id.clone(), dest1.clone());
    assert_eq!(balance(&state, &dest1_asset_id), Quantity::from(10_u32));
    assert!(
        state.view().world().accounts().get(&dest2).is_none(),
        "second account must not be created"
    );
    assert_eq!(balance(&state, &alice_asset_id), Quantity::from(50_u32));
}
#[test]
fn missing_default_role_rejects_in_pipeline() {
    let role_id: RoleId = "missing".parse().expect("role id");
    let policy = AccountAdmissionPolicy {
        default_role_on_create: Some(role_id.clone()),
        ..AccountAdmissionPolicy::default()
    };
    let (state, alice_id, alice_kp, _asset_def_id, alice_asset_id) =
        prepare_state(Some(policy), Quantity::from(25_u32));
    let network_id = *state.network_id_ref();
    let (dest, _) = seeded_account(11);
    let tx = TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Transfer::asset_quantity(
        alice_asset_id.clone(),
        5_u32,
        dest.clone(),
    )])
    .sign(alice_kp.private_key());
    let accepted = accept_transaction(&state, tx);
    let mut state_block = state.block(block_header(1, 1_700_000_400_000));
    let mut ivm_cache = IvmCache::new();
    let result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut state_block,
        accepted,
        &mut ivm_cache,
        None,
    );
    let err = result.expect_err("tx should fail when default role is missing");
    assert!(
        matches!(
            err,
            TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
                InstructionExecutionError::AccountAdmission(
                    AccountAdmissionError::DefaultRoleError(AccountAdmissionDefaultRoleError {
                        ref role,
                        ..
                    })
                )
            )) if role == &role_id
        ),
        "unexpected error: {err:?}"
    );
    state_block
        .commit_world_overlay_for_testing()
        .expect("commit state");
    assert!(
        state.view().world().accounts().get(&dest).is_none(),
        "account must not be created on failure"
    );
    assert_eq!(balance(&state, &alice_asset_id), Quantity::from(25_u32));
}
#[test]
fn implicit_account_can_spend_without_roles() {
    let (state, alice_id, alice_kp, asset_def_id, alice_asset_id) =
        prepare_state(None, Quantity::from(20_u32));
    let network_id = *state.network_id_ref();
    let (bob_id, bob_kp) = seeded_account(5);
    let tx1 = TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Transfer::asset_quantity(
        alice_asset_id.clone(),
        7_u32,
        bob_id.clone(),
    )])
    .sign(alice_kp.private_key());
    let accepted1 = accept_transaction(&state, tx1);
    let mut block1 = state.block(block_header(1, 1_700_000_500_000));
    let mut ivm_cache = IvmCache::new();
    let res1 = iroha_core::tx::execute_component_transaction_for_testing(
        &mut block1,
        accepted1,
        &mut ivm_cache,
        None,
    );
    assert!(res1.is_ok(), "first transfer should succeed: {res1:?}");
    block1
        .commit_world_overlay_for_testing()
        .expect("commit first block");
    let bob_asset_id = AssetId::new(asset_def_id.clone(), bob_id.clone());
    assert_eq!(balance(&state, &bob_asset_id), Quantity::from(7_u32));
    assert_eq!(balance(&state, &alice_asset_id), Quantity::from(13_u32));
    let tx2 = TransactionBuilder::new(
        network_id,
        bob_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Transfer::asset_quantity(
        bob_asset_id.clone(),
        5_u32,
        alice_id.clone(),
    )])
    .sign(bob_kp.private_key());
    let accepted2 = accept_transaction(&state, tx2);
    let mut block2 = state.block(block_header(2, 1_700_000_600_000));
    let mut ivm_cache2 = IvmCache::new();
    let res2 = iroha_core::tx::execute_component_transaction_for_testing(
        &mut block2,
        accepted2,
        &mut ivm_cache2,
        None,
    );
    assert!(
        res2.is_ok(),
        "implicit account should be able to spend: {res2:?}"
    );
    block2
        .commit_world_overlay_for_testing()
        .expect("commit second block");
    assert_eq!(balance(&state, &bob_asset_id), Quantity::from(2_u32));
    assert_eq!(balance(&state, &alice_asset_id), Quantity::from(18_u32));
}
#[test]
fn multi_receipts_within_transaction_succeed_in_open_domain() {
    let (state, alice_id, alice_kp, asset_def_id, alice_asset_id) =
        prepare_state(None, Quantity::from(50_u32));
    let network_id = *state.network_id_ref();
    let (dest1, _) = seeded_account(2);
    let (dest2, _) = seeded_account(3);
    let tx = TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([
        Transfer::asset_quantity(alice_asset_id.clone(), 5_u32, dest1.clone()),
        Transfer::asset_quantity(alice_asset_id.clone(), 7_u32, dest2.clone()),
    ])
    .sign(alice_kp.private_key());
    let accepted = accept_transaction(&state, tx);
    let mut state_block = state.block(block_header(1, 1_700_000_000_000));
    let mut ivm_cache = IvmCache::new();
    let result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut state_block,
        accepted,
        &mut ivm_cache,
        None,
    );
    assert!(result.is_ok(), "batched transfers must succeed: {result:?}");
    state_block
        .commit_world_overlay_for_testing()
        .expect("commit state");
    let created_via_key: Name = "iroha:created_via".parse().expect("metadata key");
    for dest in [&dest1, &dest2] {
        let details = state
            .view()
            .world()
            .accounts()
            .get(dest)
            .expect("destination account must exist after receipt")
            .clone()
            .into_inner();
        assert_eq!(
            details.metadata().get(&created_via_key),
            Some(&Json::new("implicit"))
        );
    }
    let dest1_asset_id = AssetId::new(asset_def_id.clone(), dest1.clone());
    let dest2_asset_id = AssetId::new(asset_def_id, dest2.clone());
    assert_eq!(balance(&state, &dest1_asset_id), Quantity::from(5_u32));
    assert_eq!(balance(&state, &dest2_asset_id), Quantity::from(7_u32));
    assert_eq!(balance(&state, &alice_asset_id), Quantity::from(38_u32));
}
#[test]
fn tx_cap_rejects_multiple_implicit_creations() {
    let policy = AccountAdmissionPolicy {
        max_implicit_creations_per_tx: Some(1),
        ..AccountAdmissionPolicy::default()
    };
    let (state, alice_id, alice_kp, _asset_def_id, alice_asset_id) =
        prepare_state(Some(policy), Quantity::from(50_u32));
    let network_id = *state.network_id_ref();
    let (dest1, _) = seeded_account(2);
    let (dest2, _) = seeded_account(3);
    let tx = TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([
        Transfer::asset_quantity(alice_asset_id.clone(), 1_u32, dest1.clone()),
        Transfer::asset_quantity(alice_asset_id.clone(), 1_u32, dest2.clone()),
    ])
    .sign(alice_kp.private_key());
    let accepted = accept_transaction(&state, tx);
    let mut state_block = state.block(block_header(1, 1_700_000_000_000));
    let mut ivm_cache = IvmCache::new();
    let result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut state_block,
        accepted,
        &mut ivm_cache,
        None,
    );
    let err = result.expect_err("cap should reject second implicit creation");
    assert!(
        matches!(
            err,
            TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
                InstructionExecutionError::AccountAdmission(AccountAdmissionError::QuotaExceeded(
                    AccountAdmissionQuotaExceeded {
                        scope: AccountAdmissionQuotaScope::Transaction,
                        ..
                    }
                ))
            ))
        ),
        "unexpected error: {err:?}"
    );
    state_block
        .commit_world_overlay_for_testing()
        .expect("commit state");
    assert!(
        state.view().world().accounts().get(&dest1).is_none(),
        "dest1 must not exist after rejection"
    );
    assert!(
        state.view().world().accounts().get(&dest2).is_none(),
        "dest2 must not exist after rejection"
    );
    assert_eq!(balance(&state, &alice_asset_id), Quantity::from(50_u32));
}
