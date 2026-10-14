//! Integration tests covering settlement admission and overlay execution paths.

#![allow(clippy::unwrap_used)]
use iroha_core::{
    pipeline::overlay::TxOverlay,
    state::{World, WorldReadOnly},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_data_model::{
    Registrable,
    account::Account,
    asset::{
        Asset, AssetDefinition,
        prelude::{AssetDefinitionId, AssetId},
    },
    block::BlockHeader,
    domain::Domain,
    isi::{
        Grant, InstructionBox,
        error::{InstructionExecutionError, MathError},
        settlement::{
            DvpIsi, PvpIsi, SettlementAtomicity, SettlementExecutionOrder, SettlementId,
            SettlementLeg, SettlementPlan,
        },
    },
    permission::Permission,
    prelude::{AccountId, NumericSpec, Quantity, ValidationFail},
};
use iroha_executor_data_model::permission::settlement::CanExecuteSettlement;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
use std::str::FromStr as _;
fn settlement_state() -> (
    Box<CertifiedTestChain>,
    AssetDefinitionId,
    AssetDefinitionId,
) {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let alice = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let bob = Account::new(BOB_ID.clone()).build(&ALICE_ID);
    let delivery_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "bond".parse().unwrap(),
        );
    let payment_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "usd".parse().unwrap(),
        );
    let delivery_def = AssetDefinition::numeric(
        delivery_def_id.clone(),
        "bond".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&ALICE_ID);
    let payment_def = AssetDefinition::numeric(
        payment_def_id.clone(),
        "usd".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&ALICE_ID);
    let alice_delivery = Asset::new(
        AssetId::new(delivery_def_id.clone(), ALICE_ID.clone()),
        Quantity::from(10u32),
    );
    let bob_payment = Asset::new(
        AssetId::new(payment_def_id.clone(), BOB_ID.clone()),
        Quantity::from(1_000u32),
    );
    let world = World::with_assets(
        [domain],
        [alice, bob],
        [delivery_def, payment_def],
        [alice_delivery, bob_payment],
        [],
    );
    let chain = Box::new(
        CertifiedTestChain::start(TestChainConfig::new(world, 0))
            .expect("apply original signed settlement genesis"),
    );
    (chain, delivery_def_id, payment_def_id)
}
fn settlement_state_with_payment_spec(
    payment_spec: NumericSpec,
) -> (
    Box<CertifiedTestChain>,
    AssetDefinitionId,
    AssetDefinitionId,
) {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let alice = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let bob = Account::new(BOB_ID.clone()).build(&ALICE_ID);
    let delivery_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "bond".parse().unwrap(),
        );
    let payment_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "usd".parse().unwrap(),
        );
    let delivery_def = AssetDefinition::new(
        delivery_def_id.clone(),
        "bond".to_owned(),
        NumericSpec::integer(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&ALICE_ID);
    let payment_def = AssetDefinition::new(
        payment_def_id.clone(),
        "usd".to_owned(),
        payment_spec,
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&ALICE_ID);
    let alice_delivery = Asset::new(
        AssetId::new(delivery_def_id.clone(), ALICE_ID.clone()),
        Quantity::from(5u32),
    );
    let bob_payment = Asset::new(
        AssetId::new(payment_def_id.clone(), BOB_ID.clone()),
        Quantity::from(2u32),
    );
    let world = World::with_assets(
        [domain],
        [alice, bob],
        [delivery_def, payment_def],
        [alice_delivery, bob_payment],
        [],
    );
    let chain = Box::new(
        CertifiedTestChain::start(TestChainConfig::new(world, 0))
            .expect("apply original signed settlement genesis"),
    );
    (chain, delivery_def_id, payment_def_id)
}
fn apply_overlay(
    stx: &mut iroha_core::state::StateTransaction<'_, '_>,
    authority: &AccountId,
    instructions: Vec<InstructionBox>,
) -> Result<(), ValidationFail> {
    TxOverlay::from_instructions(instructions).apply(stx, authority)
}
fn asset_balance(
    stx: &iroha_core::state::StateTransaction<'_, '_>,
    definition: &AssetDefinitionId,
    account: &AccountId,
) -> Quantity {
    WorldReadOnly::assets(&stx.world)
        .get(&AssetId::new(definition.clone(), account.clone()))
        .map_or_else(Quantity::zero, |owned| owned.0.clone())
}
fn grant_exact_settlement_consent(
    stx: &mut iroha_core::state::StateTransaction<'_, '_>,
    debited_asset: AssetId,
    instruction_id: &SettlementId,
    intent_hash: iroha_data_model::prelude::Hash,
) {
    let permission = Permission::from(CanExecuteSettlement {
        debited_asset,
        settlement_id: instruction_id.clone(),
        intent_hash,
    });
    apply_overlay(
        stx,
        &BOB_ID,
        vec![InstructionBox::from(Grant::account_permission(
            permission,
            ALICE_ID.clone(),
        ))],
    )
    .expect("counterparty should grant exact settlement consent");
}
#[test]
fn dvp_overlay_rejects_underfunded_leg() {
    let (chain, delivery_def_id, payment_def_id) = settlement_state();
    let state = chain.state();
    let view = state.view();
    assert_eq!(
        view.height(),
        1,
        "the original genesis must already be applied"
    );
    assert_eq!(
        view.latest_block_hash(),
        Some(chain.genesis().header().hash())
    );
    let time = chain
        .genesis()
        .header()
        .creation_time_ms
        .checked_add(1)
        .expect("fixture time");
    let header = BlockHeader::new(nonzero!(2_u64), view.latest_block_hash(), None, time, 0);
    drop(view);
    let mut block = state.block(header);
    // This bounded component owner exercises TxOverlay admission directly. It
    // grants no authenticated Network input, block publication, or finality.
    let mut stx = block
        .transaction_for_fastpq_testing(iroha_crypto::Hash::new(b"settlement-overlay-component"));
    let instruction = DvpIsi {
        settlement_id: SettlementId::new(ALICE_ID.clone(), "overlay_underfunded".parse().unwrap()),
        delivery_leg: SettlementLeg::new(
            delivery_def_id.clone(),
            Quantity::from(5u32),
            ALICE_ID.clone(),
            BOB_ID.clone(),
        ),
        payment_leg: SettlementLeg::new(
            payment_def_id.clone(),
            Quantity::from(2_000u32),
            BOB_ID.clone(),
            ALICE_ID.clone(),
        ),
        plan: SettlementPlan::new(
            SettlementExecutionOrder::PaymentThenDelivery,
            SettlementAtomicity::AllOrNothing,
        ),
        metadata: Metadata::default(),
    };
    grant_exact_settlement_consent(
        &mut stx,
        AssetId::new(payment_def_id.clone(), BOB_ID.clone()),
        instruction.settlement_id(),
        instruction.intent_hash(),
    );
    let err = apply_overlay(&mut stx, &ALICE_ID, vec![InstructionBox::from(instruction)])
        .expect_err("insufficient payment leg should fail admission");
    assert_eq!(
        err,
        ValidationFail::InstructionFailed(InstructionExecutionError::Math(
            MathError::NotEnoughQuantity
        )),
        "the original numeric preflight must reject the underfunded payment leg"
    );
    // Ensure balances remain unchanged
    let alice_bond = AssetId::new(delivery_def_id, ALICE_ID.clone());
    let bob_cash = AssetId::new(payment_def_id, BOB_ID.clone());
    let alice_balance = WorldReadOnly::assets(&stx.world)
        .get(&alice_bond)
        .map_or_else(Quantity::zero, |owned| owned.0.clone());
    let bob_balance = WorldReadOnly::assets(&stx.world)
        .get(&bob_cash)
        .map_or_else(Quantity::zero, |owned| owned.0.clone());
    assert_eq!(alice_balance, Quantity::from(10u32));
    assert_eq!(bob_balance, Quantity::from(1_000u32));
}
#[test]
fn pvp_overlay_executes_when_funded() {
    let (chain, primary_def_id, counter_def_id) = settlement_state();
    let state = chain.state();
    let view = state.view();
    assert_eq!(
        view.height(),
        1,
        "the original genesis must already be applied"
    );
    assert_eq!(
        view.latest_block_hash(),
        Some(chain.genesis().header().hash())
    );
    let time = chain
        .genesis()
        .header()
        .creation_time_ms
        .checked_add(1)
        .expect("fixture time");
    let header = BlockHeader::new(nonzero!(2_u64), view.latest_block_hash(), None, time, 0);
    drop(view);
    let mut block = state.block(header);
    // This bounded component owner exercises TxOverlay admission directly. It
    // grants no authenticated Network input, block publication, or finality.
    let mut stx = block
        .transaction_for_fastpq_testing(iroha_crypto::Hash::new(b"settlement-overlay-component"));
    let instruction = PvpIsi {
        settlement_id: SettlementId::new(ALICE_ID.clone(), "overlay_funded_fx".parse().unwrap()),
        primary_leg: SettlementLeg::new(
            primary_def_id.clone(),
            Quantity::from(5u32),
            ALICE_ID.clone(),
            BOB_ID.clone(),
        ),
        counter_leg: SettlementLeg::new(
            counter_def_id.clone(),
            Quantity::from(500u32),
            BOB_ID.clone(),
            ALICE_ID.clone(),
        ),
        plan: SettlementPlan::default(),
        metadata: Metadata::default(),
    };
    grant_exact_settlement_consent(
        &mut stx,
        AssetId::new(counter_def_id.clone(), BOB_ID.clone()),
        instruction.settlement_id(),
        instruction.intent_hash(),
    );
    apply_overlay(&mut stx, &ALICE_ID, vec![InstructionBox::from(instruction)])
        .expect("funded PvP overlay should succeed");
    assert_eq!(
        asset_balance(&stx, &primary_def_id, &ALICE_ID),
        Quantity::from(5u32)
    );
    assert_eq!(
        asset_balance(&stx, &primary_def_id, &BOB_ID),
        Quantity::from(5u32)
    );
    assert_eq!(
        asset_balance(&stx, &counter_def_id, &ALICE_ID),
        Quantity::from(500u32)
    );
    assert_eq!(
        asset_balance(&stx, &counter_def_id, &BOB_ID),
        Quantity::from(500u32)
    );
}
#[test]
fn dvp_overlay_delivery_first_rejects_invalid_precision_without_moving_assets() {
    let (chain, delivery_def_id, payment_def_id) =
        settlement_state_with_payment_spec(NumericSpec::fractional(2));
    let state = chain.state();
    let view = state.view();
    assert_eq!(
        view.height(),
        1,
        "the original genesis must already be applied"
    );
    assert_eq!(
        view.latest_block_hash(),
        Some(chain.genesis().header().hash())
    );
    let time = chain
        .genesis()
        .header()
        .creation_time_ms
        .checked_add(1)
        .expect("fixture time");
    let header = BlockHeader::new(nonzero!(2_u64), view.latest_block_hash(), None, time, 0);
    drop(view);
    let mut block = state.block(header);
    // This bounded component owner exercises TxOverlay admission directly. It
    // grants no authenticated Network input, block publication, or finality.
    let mut stx = block
        .transaction_for_fastpq_testing(iroha_crypto::Hash::new(b"settlement-overlay-component"));
    let instruction = DvpIsi {
        settlement_id: SettlementId::new(
            ALICE_ID.clone(),
            "overlay_precision_delivery_first".parse().unwrap(),
        ),
        delivery_leg: SettlementLeg::new(
            delivery_def_id.clone(),
            Quantity::from(5u32),
            ALICE_ID.clone(),
            BOB_ID.clone(),
        ),
        payment_leg: SettlementLeg::new(
            payment_def_id.clone(),
            Quantity::from_str("1.001").expect("numeric"),
            BOB_ID.clone(),
            ALICE_ID.clone(),
        ),
        plan: SettlementPlan::new(
            SettlementExecutionOrder::DeliveryThenPayment,
            SettlementAtomicity::AllOrNothing,
        ),
        metadata: Metadata::default(),
    };
    grant_exact_settlement_consent(
        &mut stx,
        AssetId::new(payment_def_id.clone(), BOB_ID.clone()),
        instruction.settlement_id(),
        instruction.intent_hash(),
    );
    let err = apply_overlay(&mut stx, &ALICE_ID, vec![InstructionBox::from(instruction)])
        .expect_err("invalid payment precision must fail admission");
    match err {
        ValidationFail::InstructionFailed(InstructionExecutionError::Evaluate(
            iroha_data_model::isi::error::InstructionEvaluationError::Type(_),
        )) => {}
        ValidationFail::InstructionFailed(exec_err) => panic!("unexpected error: {exec_err:?}"),
        other => panic!("unexpected validation error: {other:?}"),
    }
    let alice_delivery = asset_balance(&stx, &delivery_def_id, &ALICE_ID);
    let bob_delivery = asset_balance(&stx, &delivery_def_id, &BOB_ID);
    let alice_cash = asset_balance(&stx, &payment_def_id, &ALICE_ID);
    let bob_cash = asset_balance(&stx, &payment_def_id, &BOB_ID);
    assert_eq!(alice_delivery, Quantity::from(5u32));
    assert_eq!(bob_delivery, Quantity::zero());
    assert_eq!(alice_cash, Quantity::zero());
    assert_eq!(bob_cash, Quantity::from(2u32));
}
#[test]
fn dvp_overlay_payment_first_rejects_invalid_precision_without_moving_assets() {
    let (chain, delivery_def_id, payment_def_id) =
        settlement_state_with_payment_spec(NumericSpec::fractional(2));
    let state = chain.state();
    let view = state.view();
    assert_eq!(
        view.height(),
        1,
        "the original genesis must already be applied"
    );
    assert_eq!(
        view.latest_block_hash(),
        Some(chain.genesis().header().hash())
    );
    let time = chain
        .genesis()
        .header()
        .creation_time_ms
        .checked_add(1)
        .expect("fixture time");
    let header = BlockHeader::new(nonzero!(2_u64), view.latest_block_hash(), None, time, 0);
    drop(view);
    let mut block = state.block(header);
    // This bounded component owner exercises TxOverlay admission directly. It
    // grants no authenticated Network input, block publication, or finality.
    let mut stx = block
        .transaction_for_fastpq_testing(iroha_crypto::Hash::new(b"settlement-overlay-component"));
    let alice_delivery_before = asset_balance(&stx, &delivery_def_id, &ALICE_ID);
    let bob_delivery_before = asset_balance(&stx, &delivery_def_id, &BOB_ID);
    let bob_cash_before = asset_balance(&stx, &payment_def_id, &BOB_ID);
    let instruction = DvpIsi {
        settlement_id: SettlementId::new(
            ALICE_ID.clone(),
            "overlay_precision_payment_first".parse().unwrap(),
        ),
        delivery_leg: SettlementLeg::new(
            delivery_def_id.clone(),
            Quantity::from(5u32),
            ALICE_ID.clone(),
            BOB_ID.clone(),
        ),
        payment_leg: SettlementLeg::new(
            payment_def_id.clone(),
            Quantity::from_str("1.001").expect("numeric"),
            BOB_ID.clone(),
            ALICE_ID.clone(),
        ),
        plan: SettlementPlan::new(
            SettlementExecutionOrder::PaymentThenDelivery,
            SettlementAtomicity::AllOrNothing,
        ),
        metadata: Metadata::default(),
    };
    grant_exact_settlement_consent(
        &mut stx,
        AssetId::new(payment_def_id.clone(), BOB_ID.clone()),
        instruction.settlement_id(),
        instruction.intent_hash(),
    );
    let err = apply_overlay(&mut stx, &ALICE_ID, vec![InstructionBox::from(instruction)])
        .expect_err("invalid payment precision must fail admission");
    match err {
        ValidationFail::InstructionFailed(InstructionExecutionError::Evaluate(
            iroha_data_model::isi::error::InstructionEvaluationError::Type(_),
        )) => {}
        ValidationFail::InstructionFailed(exec_err) => panic!("unexpected error: {exec_err:?}"),
        other => panic!("unexpected validation error: {other:?}"),
    }
    assert_eq!(
        asset_balance(&stx, &delivery_def_id, &ALICE_ID),
        alice_delivery_before,
        "delivery leg should roll back",
    );
    assert_eq!(
        asset_balance(&stx, &delivery_def_id, &BOB_ID),
        bob_delivery_before,
        "buyer delivery balance should remain unchanged",
    );
    assert_eq!(
        asset_balance(&stx, &payment_def_id, &BOB_ID),
        bob_cash_before,
        "payer cash balance should stay intact",
    );
}
