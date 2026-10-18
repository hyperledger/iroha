//! GPU key-bucket parity: enabling `pipeline.gpu_key_bucket` must not change

//! scheduling outcomes or final state. This toggles the knob and compares events
//! and balances for a mixed set of transactions.
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
fn build_chain(
    gpu_key_bucket: bool,
    alice_id: &AccountId,
    bob_id: &AccountId,
) -> CertifiedTestChain {
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
    config.chain_id = ChainId::from("scheduler_gpu_key_bucket_parity");
    config.pipeline.gpu_key_bucket = gpu_key_bucket;
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
fn scheduler_gpu_key_bucket_parity() {
    let (alice_id, alice_keypair) = iroha_test_samples::gen_account_in("wonderland");
    let (bob_id, _) = iroha_test_samples::gen_account_in("wonderland");
    let first = build_chain(false, &alice_id, &bob_id);
    let second = build_chain(true, &alice_id, &bob_id);
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
    // Mixed instruction set to exercise scheduler prepass and DSU unions
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
        // Mint/Transfer on same asset to induce a dependency edge
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
        .with_instructions([Transfer::asset_quantity(
            a_coin.clone(),
            5_u32,
            bob_id.clone(),
        )])
        .sign(alice_keypair.private_key()),
        // Burn on bob to touch a different key
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Burn::asset_quantity(2_u32, b_coin.clone())])
        .sign(alice_keypair.private_key()),
    ];
    // Compare with gpu_key_bucket OFF vs ON
    let (json_off, state_off) = run(first, txs.clone());
    let (json_on, state_on) = run(second, txs);
    assert_eq!(
        json_off, json_on,
        "events must match with/without gpu_key_bucket"
    );
    let bal = |state: &iroha_core::state::State, id: &AssetId| {
        state
            .view()
            .world()
            .assets()
            .get(id)
            .map_or_else(Quantity::zero, |v| v.clone().into_inner())
    };
    assert_eq!(bal(&state_off, &a_coin), bal(&state_on, &a_coin));
    assert_eq!(bal(&state_off, &b_coin), bal(&state_on, &b_coin));
}
