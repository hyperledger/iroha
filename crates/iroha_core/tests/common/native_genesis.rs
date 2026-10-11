//! Genuine signed genesis for native proof admission and contract-binding fixtures.
use iroha_core::{
    state::{State, World},
    sumeragi::{
        startup,
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_data_model::prelude::AccountId;

/// Apply original signed genesis before any StateExecutor retains the fixture State.
pub(crate) fn certified_state(world: World) -> State {
    let config = TestChainConfig::new(world, 0);
    let account = AccountId::new(config.genesis_key.public_key().clone());
    let mode = config.consensus_mode;
    let prepared = CertifiedTestChain::prepare(config).expect("prepare authenticated genesis");
    let state = std::sync::Arc::try_unwrap(prepared.state)
        .unwrap_or_else(|_| panic!("unpublished fixture State is unique"));
    startup::apply_genesis(
        &state,
        prepared.genesis.block().clone(),
        &account,
        mode.into(),
        None,
    )
    .expect("apply authenticated genesis");
    state
}
