//! Canonical execution retains one owner for either parallel-apply setting.

//!
//! Actual published transactions must not report work from the retired detached DAG.
use iroha_core::{
    state::StateReadOnly,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_data_model::prelude::*;
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
fn build_world(parallel_apply: bool) -> (CertifiedTestChain, AccountId, iroha_crypto::KeyPair) {
    let chain_id = ChainId::from("chain");
    let (alice_id, alice_kp) = iroha_test_samples::gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain: Domain = Domain::new(domain_id.clone()).build(&alice_id);
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
    .build(&alice_id);
    let acc_a = Account::new(alice_id.clone()).build(&alice_id);
    let world = iroha_core::state::World::with([domain], [acc_a], [ad]);
    let mut config = TestChainConfig::new(world, 1000);
    config.chain_id = chain_id;
    config.pipeline.parallel_apply = parallel_apply;
    let chain = CertifiedTestChain::start(config).unwrap();
    (chain, alice_id, alice_kp)
}
fn apply_work(chain: &mut CertifiedTestChain, alice_id: &AccountId, kp: &iroha_crypto::KeyPair) {
    // Two simple instructions to ensure a non-empty overlay
    let asset = AssetId::of(
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "coin".parse().unwrap(),
        ),
        alice_id.clone(),
    );
    let instrs: Vec<InstructionBox> = vec![
        Mint::asset_quantity(5_u32, asset).into(),
        SetKeyValue::account(
            alice_id.clone(),
            "k".parse().unwrap(),
            iroha_primitives::json::Json::new("v"),
        )
        .into(),
    ];
    let tx = chain.sign(kp, instrs, 2000);
    assert_eq!(chain.commit(vec![tx]), vec![true]);
    let committed = chain.committed(2);
    assert_eq!(committed.block().output_results().count(), 1);
    assert!(committed.block().output_error(0).is_none());
}
#[test]
#[cfg(feature = "telemetry")]
fn canonical_output_owner_does_not_allocate_detached_journals() {
    // Sequential mode: expect detached counters to be zero
    let (mut chain_seq, alice_id, kp) = build_world(false);
    apply_work(&mut chain_seq, &alice_id, &kp);
    let (prep_s, merged_s, fallback_s) = chain_seq
        .state()
        .view()
        .metrics()
        .pipeline_detached_counts();

    assert_eq!(prep_s, 0, "sequential: prepared must be zero");
    assert_eq!(merged_s, 0, "sequential: merged must be zero");
    assert_eq!(fallback_s, 0, "sequential: fallback must be zero");
    // The parallel setting must retain the same canonical execution owner.
    let (mut chain_par, alice_id, kp) = build_world(true);
    apply_work(&mut chain_par, &alice_id, &kp);
    let (prep_p, _merged_p, _fallback_p) = chain_par
        .state()
        .view()
        .metrics()
        .pipeline_detached_counts();

    assert_eq!(prep_p, 0, "canonical owner retains its original journal");
}
#[test]
#[cfg(not(feature = "telemetry"))]
fn parallel_apply_knob_compiles_without_telemetry() {
    // Smoke test: ensure code path compiles and runs without telemetry; no metrics assertions.
    for &flag in &[false, true] {
        let (mut chain, alice_id, kp) = build_world(flag);
        apply_work(&mut chain, &alice_id, &kp);
    }
}
