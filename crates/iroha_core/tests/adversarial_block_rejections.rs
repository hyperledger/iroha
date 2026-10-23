//! Adversarial block validation regressions for forged/invalid transactions.

use crate::native_validation;
use iroha_core::{
    block::BlockValidationError,
    governance::manifest::LaneManifestRegistry,
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::ivm::cache::IvmCache,
    state::{State, World, WorldReadOnly},
    tx::AcceptedTransaction,
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    block::{BlockHeader, builder::BlockBuilder as ModelBlockBuilder},
    prelude::*,
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::NumericSpec;
use iroha_test_samples::gen_account_in;
use mv::storage::StorageReadOnly;
use std::{num::NonZeroU64, sync::Arc};
fn checked_random_adversarial_bls_keypair() -> KeyPair {
    KeyPair::try_random_with_algorithm(Algorithm::BlsNormal)
        .expect("generate checked adversarial BLS keypair")
}
#[test]
fn adversarial_block_fixture_uses_checked_bls_randomness() {
    let key_pair = checked_random_adversarial_bls_keypair();
    assert_eq!(key_pair.public_key().algorithm(), Algorithm::BlsNormal);
}
fn balance(state: &State, id: &AssetId) -> Quantity {
    state
        .view()
        .world()
        .assets()
        .get(id)
        .map_or_else(Quantity::zero, |value| value.clone().into_inner())
}
struct AdversarialSetup {
    state: State,
    alice_id: AccountId,
    alice_kp: KeyPair,
    bob_id: AccountId,
    alice_asset_id: AssetId,
    bob_asset_id: AssetId,
}
fn setup_world() -> AdversarialSetup {
    let (alice_id, alice_kp) = gen_account_in("wonderland");
    let (bob_id, _) = gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
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
    let alice_account = Account::new(alice_id.clone()).build(&alice_id);
    let bob_account = Account::new(bob_id.clone()).build(&alice_id);
    let alice_asset_id = AssetId::of(ad.id().clone(), alice_id.clone());
    let bob_asset_id = AssetId::of(ad.id().clone(), bob_id.clone());
    let alice_asset = Asset::new(alice_asset_id.clone(), Quantity::from(50_u64));
    let bob_asset = Asset::new(bob_asset_id.clone(), Quantity::from(0_u64));
    let world = World::with_assets(
        [domain],
        [alice_account, bob_account],
        [ad],
        [alice_asset, bob_asset],
        [],
    );
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let chain_id = ChainId::from("adversarial-block-rejections");
    let state = State::new_with_chain_for_testing(world, kura, query, chain_id);
    let nexus = state.nexus_snapshot();
    state.install_lane_manifests_for_testing(&Arc::new(
        LaneManifestRegistry::empty().rebind(&nexus.lane_catalog, &nexus.governance),
    ));
    AdversarialSetup {
        state,
        alice_id,
        alice_kp,
        bob_id,
        alice_asset_id,
        bob_asset_id,
    }
}
#[test]
fn adversarial_transactions_rejected_without_state_mutation() {
    let AdversarialSetup {
        state,
        alice_id,
        alice_kp,
        bob_id,
        alice_asset_id,
        bob_asset_id,
    } = setup_world();
    // Both hostile and valid transactions execute beneath the same authenticated root.
    let chain = crate::block::tests::component_chain(state);
    let state = Arc::clone(chain.state());
    let network_id = chain.network_id();
    let max_clock_drift = state
        .view()
        .world()
        .parameters()
        .sumeragi()
        .max_clock_drift();
    let tx_params = state.view().world().parameters().transaction();
    let mut state_block = state.block(BlockHeader::new(
        NonZeroU64::new(chain.height() + 1).expect("successor height"),
        state.view().latest_block_hash(),
        None,
        1_700_000_000_000,
        0,
    ));
    let mut ivm_cache = IvmCache::new();
    let ghost_def: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "ghost".parse().unwrap(),
        );
    let ghost_asset_id = AssetId::of(ghost_def, alice_id.clone());
    let forged_transfer = TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Transfer::asset_quantity(
        ghost_asset_id.clone(),
        5_u32,
        bob_id.clone(),
    )])
    .sign(alice_kp.private_key());
    let forged_transfer = AcceptedTransaction::accept(
        forged_transfer,
        &network_id,
        max_clock_drift,
        tx_params,
        &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
            iroha_crypto::Algorithm::Ed25519,
            iroha_crypto::Algorithm::Secp256k1,
        ])
        .expect("this stateless fixture explicitly selects Ed25519 and Secp256k1"),
    )
    .expect("admission should pass for forged transfer");
    let missing_burn = TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Burn::asset_quantity(5_u32, ghost_asset_id.clone())])
    .sign(alice_kp.private_key());
    let missing_burn = AcceptedTransaction::accept(
        missing_burn,
        &network_id,
        max_clock_drift,
        tx_params,
        &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
            iroha_crypto::Algorithm::Ed25519,
            iroha_crypto::Algorithm::Secp256k1,
        ])
        .expect("this stateless fixture explicitly selects Ed25519 and Secp256k1"),
    )
    .expect("admission should pass for missing-asset burn");
    let valid_transfer = TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Transfer::asset_quantity(
        alice_asset_id.clone(),
        10_u32,
        bob_id.clone(),
    )])
    .sign(alice_kp.private_key());
    let valid_transfer = AcceptedTransaction::accept(
        valid_transfer,
        &network_id,
        max_clock_drift,
        tx_params,
        &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
            iroha_crypto::Algorithm::Ed25519,
            iroha_crypto::Algorithm::Secp256k1,
        ])
        .expect("this stateless fixture explicitly selects Ed25519 and Secp256k1"),
    )
    .expect("admission should pass for valid transfer");
    let forged_result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut state_block,
        forged_transfer,
        &mut ivm_cache,
        None,
    );
    assert!(
        forged_result.is_err(),
        "transfer from missing asset should be rejected"
    );
    let burn_result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut state_block,
        missing_burn,
        &mut ivm_cache,
        None,
    );
    assert!(
        burn_result.is_err(),
        "burn on missing asset should be rejected"
    );
    let valid_result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut state_block,
        valid_transfer,
        &mut ivm_cache,
        None,
    );
    assert!(valid_result.is_ok(), "well-formed transfer should succeed");
    state_block
        .commit_world_overlay_for_testing()
        .expect("commit state");
    // Only the valid transfer applies: Alice loses 10, Bob gains 10.
    assert_eq!(balance(&state, &alice_asset_id), Quantity::from(40_u64));
    assert_eq!(balance(&state, &bob_asset_id), Quantity::from(10_u64));
}
#[test]
fn block_history_tamper_rejected_without_mutation() {
    let AdversarialSetup {
        state,
        alice_id,
        alice_kp,
        alice_asset_id,
        bob_asset_id,
        ..
    } = setup_world();
    let mut chain = crate::block::tests::component_chain(state);
    let network_id = chain.network_id();
    let state = Arc::clone(chain.state());
    let peer_key = checked_random_adversarial_bls_keypair();
    // Commit ordinary work after genesis so rewinds have a stable checkpoint.
    let baseline_tx = TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Mint::asset_quantity(5_u32, bob_asset_id.clone())])
    .sign(alice_kp.private_key());
    chain.commit(vec![baseline_tx]);
    let baseline = chain.committed(chain.height());
    assert!(
        baseline.block().output_error(0).is_none(),
        "{:?}",
        baseline.block().output_error(0)
    );
    let height_after_baseline = state.view().height();
    assert_eq!(height_after_baseline, 2, "baseline block follows genesis");
    assert_eq!(balance(&state, &alice_asset_id), Quantity::from(50_u64));
    assert_eq!(balance(&state, &bob_asset_id), Quantity::from(5_u64));
    // Forge a successor with a conflicting previous hash and extra mint.
    let rewind_tx = TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Mint::asset_quantity(25_u32, bob_asset_id.clone())])
    .sign(alice_kp.private_key());
    let signed_rewind = native_validation::proposal(&chain, vec![rewind_tx]);
    let mut tampered_header = signed_rewind.header();
    tampered_header.set_prev_block_hash(None);
    let mut tampered_builder = ModelBlockBuilder::new(tampered_header);
    tampered_builder.set_execution_context(signed_rewind.execution_context().cloned());
    tampered_builder.set_da_proof_policies(signed_rewind.da_proof_policies().cloned());
    for tx in signed_rewind.external_transactions().cloned() {
        tampered_builder.push_transaction(tx);
    }
    let signed_rewind = tampered_builder.build_with_signature(0, peer_key.private_key());
    println!("attempting rewind validation");
    let expected_height = state
        .view()
        .height()
        .checked_add(1)
        .expect("height should increment safely");
    let actual_height = usize::try_from(signed_rewind.header().height().get()).unwrap();
    assert_eq!(
        expected_height, actual_height,
        "tampered block kept the expected height"
    );
    let expected_prev = state.view().latest_block_hash();
    let actual_prev = signed_rewind.header().prev_block_hash();
    assert_ne!(
        expected_prev, actual_prev,
        "prev hash tamper should be observable"
    );
    let reason = native_validation::validate(&chain, signed_rewind)
        .expect_err("native validation rejects foreign parent hash");
    // The native source authenticates its original parent cut before generic header checks.
    assert!(
        matches!(reason.as_ref(), BlockValidationError::ExecutionContextInvalid(message)
            if message == "invalid native epoch: native successor differs from its original committed header/parent cut"),
        "unexpected rejection: {reason}"
    );
    // State stays on the canonical head.
    assert_eq!(state.view().height(), height_after_baseline);
    assert_eq!(balance(&state, &alice_asset_id), Quantity::from(50_u64));
    assert_eq!(balance(&state, &bob_asset_id), Quantity::from(5_u64));
    let summary = format!(
        "{{\"scenario\":\"prev_hash_tamper\",\"expected_prev_hash\":{},\"canonical_height\":{},\"alice_balance\":\"{}\",\"bob_balance\":\"{}\"}}",
        expected_prev.is_some(),
        height_after_baseline,
        balance(&state, &alice_asset_id),
        balance(&state, &bob_asset_id)
    );
    println!("adversarial_block_rejections::{summary}");
}
