//! Integration checks for BLS batching + `PoP` gating on transaction admission.

use crate::native_validation;
use core::time::Duration;
use iroha_core::{
    block::BlockValidationError,
    kura::Kura,
    prelude::*,
    query::store::LiveQueryStore,
    state::{State, StateReadOnly},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    NetworkId, Registrable,
    block::builder::BlockBuilder,
    prelude::{
        Account, AccountId, AssetDefinition, Domain, Level, Log, SignedTransaction,
        TransactionBuilder,
    },
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
fn checked_random_bls_batch_keypair() -> KeyPair {
    KeyPair::try_random_with_algorithm(Algorithm::BlsNormal)
        .expect("generate checked BLS batch keypair")
}
#[test]
fn bls_batch_fixture_uses_checked_bls_randomness() {
    let key_pair = checked_random_bls_batch_keypair();
    assert_eq!(key_pair.public_key().algorithm(), Algorithm::BlsNormal);
}
fn mk_state_with_bls_batch() -> (State, NetworkId, AccountId, KeyPair) {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    // Seed world with an account
    let kp = checked_random_bls_batch_keypair();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let account_id = AccountId::of(kp.public_key().clone());
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = Account::new(account_id.clone()).build(&account_id);
    let world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    {
        let mut block = world.block();
        let policy = iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
            Algorithm::BlsNormal,
        ])
        .unwrap();
        block
            .parameters
            .set_parameter(policy.into_parameter().unwrap())
            .unwrap();
        block.commit();
    }
    let mut state =
        State::new_with_chain_for_testing(world, kura, query_handle, ChainId::from("chain"));
    let network_id = *state.network_id_ref();
    let mut pipeline = state.view().pipeline().clone();
    pipeline.signature_batch_max_bls = 4;
    state.set_pipeline(pipeline);
    (state, network_id, account_id, kp)
}
fn make_tx(
    network_id: &NetworkId,
    authority: &AccountId,
    kp: &KeyPair,
    with_pop: bool,
) -> SignedTransaction {
    let mut builder = TransactionBuilder::new(
        *network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "msg".to_string())]);
    if with_pop {
        let pop = iroha_crypto::bls_normal_pop_prove(kp.private_key()).expect("pop");
        let mut meta = Metadata::default();
        meta.insert(
            "bls_pop".parse().unwrap(),
            iroha_primitives::json::Json::new(hex::encode_upper(pop)),
        );
        builder = builder.with_metadata(meta);
    }
    // Use a creation timestamp earlier than the block to satisfy future-time checks in validation.
    builder.set_creation_time(Duration::ZERO);
    builder.sign(kp.private_key())
}
#[test]
fn bls_batch_block_validates_with_pop() {
    let (state, _, account, kp) = mk_state_with_bls_batch();
    let chain = crate::block::tests::component_chain(state);
    let tx = make_tx(&chain.network_id(), &account, &kp, true);
    native_validation::validate(&chain, native_validation::proposal(&chain, vec![tx]))
        .expect("BLS block with verified PoP must validate");
}
#[test]
fn bls_batch_block_validates_without_pop_fallback() {
    let (state, _, account, kp) = mk_state_with_bls_batch();
    let chain = crate::block::tests::component_chain(state);
    let tx = make_tx(&chain.network_id(), &account, &kp, false);
    native_validation::validate(&chain, native_validation::proposal(&chain, vec![tx]))
        .expect("BLS block without PoP must validate via individual signatures");
}
#[test]
fn bls_batch_block_rejects_missing_proof_policies() {
    let (state, _, account, kp) = mk_state_with_bls_batch();
    let chain = crate::block::tests::component_chain(state);
    let tx = make_tx(&chain.network_id(), &account, &kp, true);
    let original = native_validation::proposal(&chain, vec![tx.clone()]);
    let mut header = original.header();
    header.set_da_proof_policies_hash(None);
    let mut builder = BlockBuilder::new(header);
    builder.set_execution_context(original.execution_context().cloned());
    builder.push_transaction(tx);
    let proposal = builder
        .build_with_signature(0, kp.private_key())
        .canonical_resultless_proposal()
        .expect("valid fixture proposal projection");
    let error = native_validation::validate(&chain, proposal)
        .expect_err("mandatory DA policy must reject before batching");
    assert!(
        matches!(
            *error,
            BlockValidationError::DaProofPolicySidecarHashMismatch {
                expected: None,
                actual: None
            }
        ),
        "{error:?}"
    );
}
