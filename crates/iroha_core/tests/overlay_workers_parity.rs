//! Ensure overlay construction with different `pipeline.workers` settings yields

//! identical outcomes (events and final state), preserving determinism.
use crate::synthetic_state_snapshots as snapshots;
use iroha_core::{
    state::WorldReadOnly,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_data_model::prelude::*;
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use mv::storage::StorageReadOnly;
use std::sync::Arc; // trait for .get()
fn build_chain(workers: usize, alice_id: &AccountId, bob_id: &AccountId) -> CertifiedTestChain {
    // Build a fresh world with a domain, two accounts, and a numeric asset definition
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
    let world = iroha_core::state::World::with([domain], [acc_a, acc_b], [ad]);
    let mut config = TestChainConfig::new(world, 1000);
    config.chain_id = ChainId::from("overlay_workers_parity");
    config.pipeline.parallel_overlay = true;
    config.pipeline.workers = workers;
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
fn overlay_parallel_workers_parity() {
    let (alice_id, alice_keypair) = iroha_test_samples::gen_account_in("wonderland");
    let (bob_id, _) = iroha_test_samples::gen_account_in("wonderland");
    let first = build_chain(0, &alice_id, &bob_id);
    let second = build_chain(2, &alice_id, &bob_id);
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
    // Build a mixed set of instruction-only transactions to exercise overlay builder
    let txs: Vec<SignedTransaction> = vec![
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([SetKeyValue::account(
            alice_id.clone(),
            "k1".parse().unwrap(),
            iroha_primitives::json::Json::new("v1"),
        )])
        .sign(alice_keypair.private_key()),
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([SetKeyValue::domain(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "dk".parse().unwrap(),
            iroha_primitives::json::Json::new(3u32),
        )])
        .sign(alice_keypair.private_key()),
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Mint::asset_quantity(7_u32, a_coin.clone())])
        .sign(alice_keypair.private_key()),
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Burn::asset_quantity(2_u32, b_coin.clone())])
        .sign(alice_keypair.private_key()),
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Transfer::asset_quantity(
            a_coin.clone(),
            5_u32,
            bob_id.clone(),
        )])
        .sign(alice_keypair.private_key()),
    ];
    // Run with workers=0 (Rayon default) and workers=2
    let (json0, state0) = run(first, txs.clone());
    let (json2, state2) = run(second, txs);
    // Compare event JSON and balances
    assert_eq!(
        json0, json2,
        "events must be identical across worker settings"
    );
    let bal = |state: &iroha_core::state::State, id: &AssetId| {
        state
            .view()
            .world()
            .assets()
            .get(id)
            .map_or_else(iroha_primitives::numeric::Quantity::zero, |v| {
                v.clone().into_inner()
            })
    };
    assert_eq!(bal(&state0, &a_coin), bal(&state2, &a_coin));
    assert_eq!(bal(&state0, &b_coin), bal(&state2, &b_coin));
}
