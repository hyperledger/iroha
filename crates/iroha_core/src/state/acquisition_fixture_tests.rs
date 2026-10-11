//! Physical State custody tests use an actual signed four-validator genesis source.
//! The fixture retains the original uncommitted State to exercise height-zero acquisition.

use super::*;
use crate::{
    block::ValidBlock, query::store::LiveQueryStore, sumeragi::network_topology::Topology,
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::block::consensus::{ConsensusMode, SumeragiGenesisContextParameters};
use iroha_genesis::{GenesisBuilder, GenesisTopologyEntry};
use iroha_model_base::{chain::ChainId, peer::PeerId};
use iroha_primitives::time::TimeSource;
use iroha_test_samples::{SAMPLE_GENESIS_ACCOUNT_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};

fn genesis(
    parameters: SumeragiGenesisContextParameters,
    instructions: &[InstructionBox],
    nexus: &iroha_config::parameters::actual::Nexus,
) -> (SignedBlock, Topology) {
    iroha_genesis::init_instruction_registry();
    let mut keys = (0_u8..4)
        .map(|index| KeyPair::try_from_seed(vec![0xB0 + index; 32], Algorithm::BlsNormal).unwrap())
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
    let entries = keys
        .iter()
        .map(|key| {
            GenesisTopologyEntry::new(
                PeerId::new(key.public_key().clone()),
                iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let topology = Topology::new(entries.iter().map(|entry| entry.peer.clone()));
    let mut builder =
        GenesisBuilder::new_without_executor(ChainId::from("carrier-preparation"), ".")
            .set_topology(entries)
            .with_sumeragi_context_parameters(parameters);
    for instruction in instructions {
        builder = builder.append_instruction(instruction.clone());
    }
    let mut nexus = nexus.clone();
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    let proof_policies = crate::da::active_proof_policy_bundle_at_height(&nexus, 1);
    let genesis = builder
        .build_raw()
        .unwrap()
        .with_consensus_meta()
        .expect("valid fixture consensus parameters")
        .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
            &SAMPLE_GENESIS_ACCOUNT_KEYPAIR,
            Some(proof_policies),
            None,
            1_000,
        )
        .unwrap()
        .0;
    (genesis, topology)
}

#[inline(never)]
fn state_for(genesis: &SignedBlock, nexus: &iroha_config::parameters::actual::Nexus) -> Box<State> {
    let account = SAMPLE_GENESIS_ACCOUNT_ID.clone();
    let world = World::with(
        [Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&account)],
        [Account::new(account.clone()).build(&account)],
        [],
    );
    // Authenticate the supplied catalog before creating its physical lanes.
    // Runtime reconfiguration cannot replace the immutable pre-genesis baseline.
    let (state, _) = State::new_with_chain_and_network_id_and_pre_genesis_nexus_for_testing(
        world,
        nexus.clone(),
        LiveQueryStore::start_test(),
        ChainId::from("carrier-preparation"),
        NetworkId::from_genesis_hash(genesis.hash()),
    );
    let state = Box::new(state);
    let nexus = state.nexus_snapshot();
    state.install_lane_manifests_for_testing(&Arc::new(
        LaneManifestRegistry::empty().rebind(&nexus.lane_catalog, &nexus.governance),
    ));
    state
}

fn signed_genesis_execution<'state>(
    state: &'state State,
    genesis: SignedBlock,
    topology: &Topology,
) -> (ValidBlock, Box<StateBlock<'state>>) {
    ValidBlock::validate_signed_genesis(
        genesis,
        topology,
        &SAMPLE_GENESIS_ACCOUNT_ID,
        &TimeSource::new_system(),
        state,
        ConsensusMode::Permissioned,
    )
    .unpack(|_| {})
    .unwrap_or_else(|(failed, error)| {
        panic!(
            "authenticated genesis execution: {error}; outputs: {:?}",
            failed.execution_outputs()
        )
    })
}

fn fixture_with_topology() -> (Box<State>, SignedBlock, Topology) {
    let nexus = iroha_config::parameters::actual::Nexus::default();
    let mut parameters = SumeragiGenesisContextParameters::recommended();
    {
        // Like kagami's signer, the provisional execution reports the exact staged policies;
        // native validation still refuses the provisional source itself.
        let (proposal, topology) = genesis(parameters, &[], &nexus);
        let state = state_for(&proposal, &nexus);
        if let Some((execution, nexus_amx)) = crate::sumeragi::test_chain::staged_genesis_policies(
            proposal,
            &topology,
            &SAMPLE_GENESIS_ACCOUNT_ID,
            &state,
            ConsensusMode::Permissioned,
        )
        .expect("provisional genesis executes")
        {
            parameters.execution_policy_hash = execution.into();
            parameters.nexus_amx_context_hash = nexus_amx.into();
        }
    }
    let (proposal, topology) = genesis(parameters, &[], &nexus);
    let state = state_for(&proposal, &nexus);
    assert_eq!(topology.as_ref().len(), 4);
    // Verify the final signed source through actual genesis execution, then drop its
    // unpublished overlay. The same original State remains empty for custody tests.
    drop(signed_genesis_execution(
        &state,
        proposal.clone(),
        &topology,
    ));
    assert_eq!(state.committed_height(), 0);
    (state, proposal, topology)
}

pub(super) fn fixture() -> (Box<State>, SignedBlock) {
    let (state, proposal, _) = fixture_with_topology();
    (state, proposal)
}

#[path = "direct_commit_musubi_scratch_tests.rs"]
mod direct_commit_musubi_scratch_tests;
#[path = "direct_commit_refusal_tests.rs"]
mod direct_commit_refusal_tests;
#[path = "state_acquisition_drop_tests.rs"]
mod state_acquisition_drop_tests;
