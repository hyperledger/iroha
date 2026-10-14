//! Original State authority at root startup, before any publication or store mutation.

use super::*;

#[test]
fn prepared_root_uses_original_state_store() {
    let chain = chain(4, 200);
    let original = Kura::blank_kura_for_testing();
    let foreign = Kura::blank_kura_for_testing();
    let state = empty_state(&chain.chain_id, &chain.genesis, &original);
    let budget = state.ivm_execution_budget();
    let prepared = prepare(PrepareInputs {
        state: Arc::clone(&state),
        events: tokio::sync::broadcast::channel(16).0,
        genesis: Some(chain.genesis.clone()),
        genesis_account: SAMPLE_GENESIS_ACCOUNT_ID.clone(),
        consensus_mode: ConsensusMode::Permissioned,
    })
    .expect("valid original State genesis");
    assert_eq!(
        state.view().height(),
        usize::try_from(GENESIS_HEIGHT).expect("fixture value fits usize")
    );
    assert_eq!(
        original.blocks_count(),
        usize::try_from(GENESIS_HEIGHT).expect("fixture value fits usize")
    );
    assert_eq!(foreign.blocks_count(), 0);
    assert!(prepared.state.ivm_execution_budget().same_pool(&budget));
    assert_eq!(
        prepared.lane_stores.root(),
        original.store_root().join("lanes"),
        "retained lane storage must share the original State store root"
    );
    assert_eq!(
        prepared.blocks.height(),
        GENESIS_HEIGHT,
        "the consensus store must be the original State store"
    );
    assert_eq!(
        prepared.instance(),
        root_instance(&chain.genesis, state.chain_id.as_ref()).unwrap()
    );
}

#[test]
fn foreign_network_rejection_precedes_genesis_publication() {
    let chain = chain(4, 200);
    let original = Kura::blank_kura_for_testing();
    let foreign_network = crate::unit_test_support::synthetic_network_id("foreign-root-genesis");
    let state = Arc::new(State::new_with_chain_and_network_id_for_testing(
        initial_world(),
        Arc::clone(&original),
        LiveQueryStore::start_test(),
        chain.chain_id.clone(),
        foreign_network,
    ));
    let result = prepare(PrepareInputs {
        state: Arc::clone(&state),
        events: tokio::sync::broadcast::channel(16).0,
        genesis: Some(chain.genesis),
        genesis_account: SAMPLE_GENESIS_ACCOUNT_ID.clone(),
        consensus_mode: ConsensusMode::Permissioned,
    });
    assert!(
        result.is_err(),
        "a foreign genesis is not the authenticated State root"
    );
    assert_eq!(
        state.view().height(),
        0,
        "rejection must precede publication"
    );
    assert_eq!(
        original.blocks_count(),
        0,
        "rejection must precede canonical persistence"
    );
    assert!(
        !original.store_root().join("native-contexts").exists(),
        "rejection must precede original-context archive creation"
    );
}

#[test]
fn prepared_root_uses_original_state_chain_identity() {
    let chain = chain(4, 200);
    let original = Kura::blank_kura_for_testing();
    let configured_chain = ChainId::from("original-state-root-chain");
    let state = empty_state(&configured_chain, &chain.genesis, &original);
    let prepared = prepare(PrepareInputs {
        state: Arc::clone(&state),
        events: tokio::sync::broadcast::channel(16).0,
        genesis: Some(chain.genesis.clone()),
        genesis_account: SAMPLE_GENESIS_ACCOUNT_ID.clone(),
        consensus_mode: ConsensusMode::Permissioned,
    })
    .expect("one original configured chain identity");
    assert_eq!(prepared.chain_id, configured_chain.to_string());
    assert_eq!(
        prepared.instance(),
        root_instance(&chain.genesis, configured_chain.as_ref()).unwrap()
    );
    assert_ne!(
        prepared.instance(),
        root_instance(&chain.genesis, chain.chain_id.as_ref()).unwrap()
    );
    assert_eq!(state.view().height(), 1);
    assert_eq!(original.blocks_count(), 1);
}
