//! Borrowed projection controls using genuinely authenticated genesis execution.

use super::*;
use crate::{
    state::{World, storage_transactions::TransactionsBlockError},
    sumeragi::{
        network_topology::Topology,
        test_chain::{CertifiedTestChain, PreparedTestChainConfig, TestChainConfig},
    },
};
use iroha_crypto::{Hash, SignatureOf};
use iroha_data_model::{block::BlockSignature, prelude::*};
use iroha_primitives::time::TimeSource;
use iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_KEYPAIR;

fn fixture() -> PreparedTestChainConfig {
    CertifiedTestChain::prepare(TestChainConfig::new(World::new(), 1000)).unwrap()
}
fn execute(prepared: &PreparedTestChainConfig) -> (ValidBlock, Box<StateBlock<'_>>) {
    let topology = Topology::new(
        prepared
            .validator_keys
            .iter()
            .map(|key| iroha_model_base::peer::PeerId::new(key.public_key().clone())),
    );
    let account = AccountId::new(prepared.genesis.public_key().clone());
    let epoch = crate::sumeragi::epoch::authenticated_genesis(prepared.genesis.block())
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    ValidBlock::validate_signed_genesis(
        prepared.genesis.block().clone(),
        &topology,
        &account,
        &TimeSource::new_system(),
        &prepared.state,
        epoch.mode,
    )
    .unpack(|_| {})
    .unwrap_or_else(|(_, error)| panic!("actual native genesis execution: {error}"))
}

#[test]
fn retained_execution_projection_matches_canonical_consensus_projection_without_publication() {
    let prepared = fixture();
    let (valid, staged) = execute(&prepared);
    let expected = commitment::execution_commitment(
        staged.exec_witness.as_ref().unwrap(),
        valid.as_ref(),
        &staged.world_state_transition().unwrap(),
    )
    .unwrap();
    assert_eq!(
        staged.execution_commitment_for_testing(&valid).unwrap(),
        expected
    );
    assert_eq!(
        staged.execution_commitment_for_testing(&valid).unwrap(),
        expected
    );
    assert!(
        staged.exec_witness.is_some(),
        "projection only borrows the actual witness"
    );
    staged.verify_execution_output_seal(valid.as_ref()).unwrap();
    assert!(matches!(
        staged.execution_output_plan.as_ref(),
        Some(crate::state::output_capacity::ExecutionOutputPlanState::Sealed(_))
    ));
    assert!(
        matches!(
            (*staged).commit().unwrap_err(),
            TransactionsBlockError::ExecutionOutputCapacity
        ),
        "a projected commitment is not the unfinished State publication authority"
    );
}

#[test]
fn retained_execution_projection_requires_the_actual_cached_witness() {
    let prepared = fixture();
    let (valid, mut staged) = execute(&prepared);
    let before = staged.execution_commitment_for_testing(&valid).unwrap();
    let witness = staged.exec_witness.take();
    assert_eq!(
        staged.execution_commitment_for_testing(&valid).unwrap_err(),
        "test projection requires a captured execution witness"
    );
    staged.verify_execution_output_seal(valid.as_ref()).unwrap();
    staged.exec_witness = witness;
    assert_eq!(
        staged.execution_commitment_for_testing(&valid).unwrap(),
        before
    );
}

#[test]
fn retained_execution_projection_rejects_foreign_proposals_and_same_proposal_wire_substitution() {
    let prepared = fixture();
    let (valid, staged) = execute(&prepared);
    let expected = staged.execution_commitment_for_testing(&valid).unwrap();
    let mut foreign = valid.as_ref().clone();
    let mut header = foreign.header();
    header.creation_time_ms += 1;
    foreign.replace_header_for_testing(header);
    assert_ne!(foreign.hash(), valid.as_ref().hash());
    assert!(
        staged
            .execution_commitment_for_testing(&ValidBlock::new_unverified_for_tests(foreign))
            .is_err()
    );
    let mut changed_wire = valid.as_ref().clone();
    changed_wire
        .add_signature(BlockSignature::new(
            1,
            SignatureOf::from_hash(
                SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key(),
                changed_wire.hash(),
            ),
        ))
        .unwrap();
    assert_eq!(changed_wire.hash(), valid.as_ref().hash());
    assert_ne!(
        Hash::new(changed_wire.encode_wire().unwrap()),
        Hash::new(valid.as_ref().encode_wire().unwrap())
    );
    assert!(
        staged
            .execution_commitment_for_testing(&ValidBlock::new_unverified_for_tests(changed_wire))
            .is_err()
    );
    assert_eq!(
        staged.execution_commitment_for_testing(&valid).unwrap(),
        expected
    );
    assert!(
        staged.exec_witness.is_some(),
        "rejection does not clear retained owners"
    );
}
