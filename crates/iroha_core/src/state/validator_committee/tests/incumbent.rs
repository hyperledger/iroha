//! The incumbent authority and the scheduling epochs come from committed World state.

use super::*;
use crate::{kura::Kura, query::store::LiveQueryStore, state::State};
use iroha_data_model::parameter::{
    custom::CustomParameter,
    system::{
        ConsensusFingerprint, ConsensusHandshakeMetadata, SumeragiConsensusMode, consensus_metadata,
    },
};
use iroha_primitives::json::Json;
use std::num::NonZeroU64;

fn handshake_metadata() -> Parameter {
    let metadata = ConsensusHandshakeMetadata {
        mode: SumeragiConsensusMode::Permissioned,
        block_cadence_ms: NonZeroU64::new(1_000).unwrap(),
        wire_protocol_version: u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION),
        consensus_fingerprint: ConsensusFingerprint::new([0xA5; 32]),
        sumeragi_context:
            iroha_data_model::block::consensus::SumeragiGenesisContextParameters::recommended(),
    };
    metadata.validate().unwrap();
    let value = norito::json::value::to_value(&metadata).unwrap();
    Parameter::Custom(CustomParameter::new(
        consensus_metadata::handshake_meta_id(),
        Json::from_norito_value_ref(&value).unwrap(),
    ))
}

fn state_on(network: iroha_data_model::NetworkId, world: World) -> State {
    State::new_with_chain_and_network_id_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        iroha_model_base::chain::ChainId::from("validator-committee-incumbent"),
        network,
    )
}

fn network_id_of(tag: &[u8]) -> iroha_data_model::NetworkId {
    iroha_data_model::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(tag)))
}

#[test]
fn incumbent_authority_is_the_authenticated_genesis_generation_bound_to_this_network() {
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
        .expect("execute independently signed genesis");
    let view = chain.state().view();
    let (authority, authorization) = current_authority(&view).unwrap();
    let scheduled = view.world().consensus_schedule().ready(2).unwrap();
    assert_eq!(authority.network_id, chain.network_id());
    assert_eq!(authority, scheduled.epoch.generation());
    assert_eq!(authorization, scheduled.epoch.authorization);
    assert_eq!(authorization.beacon, BeaconEpochBindingV1::Bootstrap);
}

#[test]
fn incumbent_authority_requires_authenticated_history_even_with_local_metadata() {
    for with_metadata in [false, true] {
        let world = World::new();
        if with_metadata {
            let mut parameters = world.parameters.block();
            parameters.set_parameter(handshake_metadata());
            parameters.commit();
        }
        let state = state_on(network_id_of(b"uncertified-metadata"), world);
        assert!(current_authority(&state.view()).is_err());
    }
}
