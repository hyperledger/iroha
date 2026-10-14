//! Ensure scheduler ready-queue heap vs per-wave sort produce identical outcomes.

use crate::synthetic_state_snapshots as snapshots;
use iroha_core::{
    state::WorldReadOnly,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_data_model::prelude::*;
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use mv::storage::StorageReadOnly;
use std::sync::Arc;
fn build_chain(ready_heap: bool, alice_id: &AccountId, bob_id: &AccountId) -> CertifiedTestChain {
    // Build world: two accounts, one asset def, balances seeded
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain: Domain = Domain::new(domain_id.clone()).build(alice_id);
    let ad: AssetDefinition = AssetDefinition::new(
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "coin".parse().unwrap(),
        ),
        "coin".to_owned(),
        NumericSpec::default(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(alice_id);
    let acc_a = Account::new(alice_id.clone()).build(alice_id);
    let acc_b = Account::new(bob_id.clone()).build(alice_id);
    // Seed asset balances
    let a_coin = AssetId::of(ad.id().clone(), alice_id.clone());
    let b_coin = AssetId::of(ad.id().clone(), bob_id.clone());
    let a0 = Asset::new(a_coin.clone(), Quantity::from(60_u64));
    let b0 = Asset::new(b_coin.clone(), Quantity::from(10_u64));
    let world = iroha_core::state::World::with_assets([domain], [acc_a, acc_b], [ad], [a0, b0], []);
    let mut config = TestChainConfig::new(world, 1000);
    config.chain_id = ChainId::from("scheduler_ready_queue_heap_parity");
    config.pipeline.ready_queue_heap = ready_heap;
    CertifiedTestChain::start(config).unwrap()
}
fn run(
    mut chain: CertifiedTestChain,
    txs: Vec<SignedTransaction>,
) -> (String, Arc<iroha_core::state::State>) {
    chain.commit(txs);
    let events = chain
        .take_events()
        .expect("complete actual publication event delivery");
    (
        snapshots::events_json_filtered(&events),
        Arc::clone(chain.state()),
    )
}
#[test]
fn scheduler_ready_queue_heap_vs_wave_sort_parity() {
    let (alice_id, alice_keypair) = iroha_test_samples::gen_account_in("wonderland");
    let (bob_id, _) = iroha_test_samples::gen_account_in("wonderland");
    let first = build_chain(true, &alice_id, &bob_id);
    let second = build_chain(false, &alice_id, &bob_id);
    let network_id = first.network_id();
    assert_eq!(
        network_id,
        second.network_id(),
        "local execution optimization preserves signed genesis identity"
    );
    let rose: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "coin".parse().unwrap(),
        );
    let a_coin = AssetId::of(rose.clone(), alice_id.clone());
    let b_coin = AssetId::of(rose.clone(), bob_id.clone());
    // Build a set of independent txs so scheduler ordering/tie-breakers apply
    let txs = vec![
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Mint::asset_quantity(5_u32, a_coin.clone())])
        .sign(alice_keypair.private_key()),
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Transfer::asset_quantity(
            a_coin.clone(),
            3_u32,
            bob_id.clone(),
        )])
        .sign(alice_keypair.private_key()),
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Burn::asset_quantity(1_u32, b_coin.clone())])
        .sign(alice_keypair.private_key()),
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([SetKeyValue::account(
            alice_id.clone(),
            "k".parse().unwrap(),
            iroha_primitives::json::Json::new("v"),
        )])
        .sign(alice_keypair.private_key()),
    ];
    let (json_heap, state_heap) = run(first, txs.clone());
    let (json_wave, state_wave) = run(second, txs);
    assert_eq!(json_heap, json_wave, "event sequences must match");
    let bal = |state: &iroha_core::state::State, id: &AssetId| {
        state
            .view()
            .world()
            .assets()
            .get(id)
            .map_or_else(Quantity::zero, |v| v.clone().into_inner())
    };
    assert_eq!(bal(&state_heap, &a_coin), bal(&state_wave, &a_coin));
    assert_eq!(bal(&state_heap, &b_coin), bal(&state_wave, &b_coin));
}
