//! Canonical execution is independent of local advisory DAG sidecars.

//! Advisory metadata cannot add consensus-visible warning events.
use iroha_core::kura::{PipelineDagSnapshot, PipelineRecoverySidecar, PipelineTxSnapshot};
use iroha_data_model::{events::EventBox, prelude::*};
use iroha_model_base::domain::DomainId;
use iroha_sumeragi::types::ControlWitness;
use std::sync::Arc;
// unused
#[test]
fn canonical_execution_ignores_mismatching_local_dag_sidecar() {
    // Minimal world: one domain, two accounts, one asset def
    let (alice_id, alice_keypair) = iroha_test_samples::gen_account_in("wonderland");
    let (bob_id, bob_keypair) = iroha_test_samples::gen_account_in("wonderland");
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
    let acc_b = Account::new(bob_id.clone()).build(&alice_id);
    let world = iroha_core::state::World::with([domain], [acc_a, acc_b], [ad]);
    let mut chain = iroha_core::sumeragi::test_chain::CertifiedTestChain::start(
        iroha_core::sumeragi::test_chain::TestChainConfig::new(world, 0),
    )
    .expect("native chain with isolated persistent Kura");
    let network_id = chain.network_id();
    let kura = Arc::clone(chain.kura());
    chain.take_events().unwrap();
    // Build a block with two txs (independent)
    let rose: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "coin".parse().unwrap(),
        );
    let a_coin = AssetId::of(rose.clone(), alice_id.clone());
    let tx1 = TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Mint::asset_quantity(5_u32, a_coin.clone())])
    .sign(alice_keypair.private_key());
    let tx2 = TransactionBuilder::new(
        network_id,
        bob_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([SetKeyValue::account(
        bob_id.clone(),
        "k".parse().unwrap(),
        iroha_primitives::json::Json::new("v"),
    )])
    .sign(bob_keypair.private_key());
    let new_block = chain.proposal(None, vec![tx1, tx2]);
    // Inject a mismatching sidecar for this block height before validation
    let height = new_block.header().height().get();
    let block_hash = new_block.header().hash();
    let mut fingerprint = [0u8; 32];
    fingerprint[..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let sidecar_txs: Vec<PipelineTxSnapshot> = new_block
        .external_transactions()
        .map(|tx| PipelineTxSnapshot::compact(tx.hash_as_entrypoint(), 0, 0))
        .collect();
    let sidecar = PipelineRecoverySidecar::new(
        height,
        block_hash,
        PipelineDagSnapshot {
            fingerprint,
            key_count: 0,
        },
        sidecar_txs,
    );
    kura.write_pipeline_metadata(&sidecar);
    // Publish canonical outputs; local DAG metadata has no consensus authority.
    let cb = chain.commit_proposal(
        new_block,
        iroha_core::sumeragi::test_chain::Signers::Quorum,
        ControlWitness::default(),
    );
    assert!(
        cb.block()
            .output_results()
            .all(|result| result.as_ref().is_ok())
    );
    let events = chain
        .take_events()
        .expect("original native publication events");
    assert!(
        !events.is_empty(),
        "publication must emit the transaction events"
    );
    let warned = events.iter().any(|e| match e {
        EventBox::Pipeline(iroha_data_model::events::pipeline::PipelineEventBox::Warning(w)) => {
            w.kind == "dag_fingerprint_mismatch"
        }
        EventBox::PipelineBatch(batch) => batch.iter().any(|event| {
            matches!(
                event,
                iroha_data_model::events::pipeline::PipelineEventBox::Warning(w)
                    if w.kind == "dag_fingerprint_mismatch"
            )
        }),
        _ => false,
    });
    assert!(
        !warned,
        "local DAG mismatch must not affect canonical events"
    );
}
#[test]
fn pipeline_warning_ignored_for_stale_sidecar() {
    // Minimal world: one domain, two accounts, one asset def
    let (alice_id, alice_keypair) = iroha_test_samples::gen_account_in("wonderland");
    let (bob_id, bob_keypair) = iroha_test_samples::gen_account_in("wonderland");
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
    let acc_b = Account::new(bob_id.clone()).build(&alice_id);
    let world = iroha_core::state::World::with([domain], [acc_a, acc_b], [ad]);
    let mut chain = iroha_core::sumeragi::test_chain::CertifiedTestChain::start(
        iroha_core::sumeragi::test_chain::TestChainConfig::new(world, 0),
    )
    .expect("native chain with isolated persistent Kura");
    let network_id = chain.network_id();
    let kura = Arc::clone(chain.kura());
    chain.take_events().unwrap();
    // Build a block with two txs (independent)
    let rose: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "coin".parse().unwrap(),
        );
    let a_coin = AssetId::of(rose.clone(), alice_id.clone());
    let tx1 = TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Mint::asset_quantity(5_u32, a_coin.clone())])
    .sign(alice_keypair.private_key());
    let tx2 = TransactionBuilder::new(
        network_id,
        bob_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([SetKeyValue::account(
        bob_id.clone(),
        "k".parse().unwrap(),
        iroha_primitives::json::Json::new("v"),
    )])
    .sign(bob_keypair.private_key());
    let new_block = chain.proposal(None, vec![tx1, tx2]);
    // Inject a stale sidecar (no tx hashes for this block height) before validation
    let height = new_block.header().height().get();
    let block_hash = new_block.header().hash();
    let mut fingerprint = [0u8; 32];
    fingerprint[..4].copy_from_slice(&[0xBA, 0xAD, 0xF0, 0x0D]);
    let sidecar = PipelineRecoverySidecar::new(
        height,
        block_hash,
        PipelineDagSnapshot {
            fingerprint,
            key_count: 0,
        },
        Vec::new(),
    );
    kura.write_pipeline_metadata(&sidecar);
    // Validate and apply; expect no DAG mismatch warning when sidecar txs do not match the block
    let cb = chain.commit_proposal(
        new_block,
        iroha_core::sumeragi::test_chain::Signers::Quorum,
        ControlWitness::default(),
    );
    assert!(
        cb.block()
            .output_results()
            .all(|result| result.as_ref().is_ok())
    );
    let events = chain
        .take_events()
        .expect("original native publication events");
    assert!(
        !events.is_empty(),
        "publication must emit the transaction events"
    );
    let warned = events.iter().any(|e| match e {
        EventBox::Pipeline(iroha_data_model::events::pipeline::PipelineEventBox::Warning(w)) => {
            w.kind == "dag_fingerprint_mismatch"
        }
        EventBox::PipelineBatch(batch) => batch.iter().any(|event| {
            matches!(
                event,
                iroha_data_model::events::pipeline::PipelineEventBox::Warning(w)
                    if w.kind == "dag_fingerprint_mismatch"
            )
        }),
        _ => false,
    });
    assert!(!warned, "expected no pipeline warning for stale sidecar");
}
