//! Quarantine lane: classification + explicit overflow rejection test.

#![allow(clippy::items_after_statements)]
// no nonzero macro used in this file
use iroha_core::sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig};
use iroha_data_model::prelude::*;
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
fn quarantine_metadata() -> Metadata {
    let mut metadata = Metadata::default();
    metadata.insert(
        "quarantine"
            .parse()
            .expect("canonical quarantine metadata key"),
        true,
    );
    metadata
}
#[test]
fn quarantine_overflow_rejects_one_tx() {
    // Set up a minimal world with one domain and an authority account.
    let chain_id: ChainId = "chain".parse().unwrap();
    let (authority_id, kp) = iroha_test_samples::gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain: Domain = Domain::new(domain_id.clone()).build(&authority_id);
    let account = Account::new(authority_id.clone()).build(&authority_id);
    let world = iroha_core::state::World::with([domain], [account], []);
    // Bind quarantine configuration before the original signed genesis is applied.
    let mut config = TestChainConfig::new(world, 0);
    config.chain_id = chain_id;
    config.pipeline.quarantine_max_txs_per_block = 1;
    config.pipeline.quarantine_tx_max_cycles = 0;
    let mut chain =
        Box::new(CertifiedTestChain::start(config).expect("authenticated quarantine genesis"));
    let network_id = chain.network_id();
    // Build two transactions whose signed metadata opts into the quarantine lane.
    let tx1 = TransactionBuilder::new(
        network_id,
        authority_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "q1".to_string())])
    .with_metadata(quarantine_metadata())
    .sign(kp.private_key());
    let tx2 = TransactionBuilder::new(
        network_id,
        authority_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "q2".to_string())])
    .with_metadata(quarantine_metadata())
    .sign(kp.private_key());
    // The same original inputs pass native payload execution and three-of-four
    // certification. The fixture does not author transaction results.
    let proposal = chain.proposal(None, vec![tx1, tx2]);
    let committed = chain.commit_proposal(proposal, Signers::Quorum, Default::default());
    let block = committed.block();
    assert_eq!(block.external_transactions().count(), 2);
    // Exactly one approved input and one explicit quarantine overflow remain.
    let mut approved = 0usize;
    let mut rejected_overflow = 0usize;
    for (idx, _tx) in block.external_transactions().enumerate() {
        let result = &block
            .network_output_at(u32::try_from(idx).expect("input index fits u32"))
            .expect("validated transaction has an output")
            .1
            .result;
        match result.as_ref().err() {
            Some(iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                iroha_data_model::ValidationFail::NotPermitted(msg),
            )) if msg == "quarantine overflow" => {
                rejected_overflow += 1;
            }
            None => {
                approved += 1;
            }
            _ => {}
        }
    }
    assert_eq!(approved, 1, "one tx must be approved");
    assert_eq!(rejected_overflow, 1, "one tx must be rejected as overflow");
}
