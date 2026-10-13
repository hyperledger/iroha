//! Native source fixture for queue and materialization controls; no supplied-array authority.
use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig},
};
use iroha_data_model::prelude::*;
use iroha_model_base::domain::DomainId;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID};

pub(crate) fn original_source(
    balance: Quantity,
    amounts: &[u32],
) -> (CertifiedTestChain, FinalizedFastpqSource) {
    let domain_id = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let definition_id =
        AssetDefinitionId::derive_from_components(domain_id, "finalized_job".parse().unwrap());
    let definition = AssetDefinition::new(
        definition_id.clone(),
        "finalized job".to_owned(),
        NumericSpec::default(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&ALICE_ID);
    let source = AssetId::new(definition_id.clone(), ALICE_ID.clone());
    let destination = AssetId::new(definition_id, BOB_ID.clone());
    let world = World::with_assets(
        [domain],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&ALICE_ID),
        ],
        [definition],
        [
            Asset::new(source.clone(), balance),
            Asset::new(destination, Quantity::from(10_u32)),
        ],
        [],
    );
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, 1_000)).unwrap();
    let created_ms = chain.committed(1).block_time_ms();
    let transactions = amounts
        .iter()
        .copied()
        .map(|amount| {
            chain.sign(
                &ALICE_KEYPAIR,
                [Transfer::asset_quantity(source.clone(), amount, BOB_ID.clone()).into()],
                created_ms,
            )
        })
        .collect();
    let proposal = chain.proposal(None, transactions);
    let mut pending = chain
        .begin_proposal(proposal, iroha_sumeragi::types::ControlWitness::default())
        .unwrap();

    // Only observation escapes before publication; the protected wire never clones
    // into a job and both unpublished and prepared states refuse the real handoff.
    assert!(pending.take_finalized_fastpq_source().is_err());
    let count = amounts.len();
    pending
        .inspect(move |execution| {
            assert!(execution.block.as_ref().failed_outputs().next().is_none());
            assert_eq!(execution.witness.fastpq_transcripts.len(), count);
        })
        .unwrap();
    pending.prepare(Signers::Quorum).unwrap();
    assert!(pending.take_finalized_fastpq_source().is_err());
    pending.publish(Signers::Quorum).unwrap();
    let source = pending.take_finalized_fastpq_source().unwrap();
    assert!(
        pending.take_finalized_fastpq_source().is_err(),
        "original source moves once"
    );
    assert!(
        pending.publish(Signers::Quorum).is_ok(),
        "source handoff does not repeat or disable publication"
    );
    drop(pending);
    assert_eq!(chain.height(), 2);
    (chain, source)
}
