//! Shared fixture: a committed Global root scope for component tests that execute
//! instructions through the executor.
//!
//! Instruction execution reads its authority from the original genesis capability or from
//! immutable committed consensus metadata (`executor::root_scope`). A component test that
//! runs an instruction on a bare test State therefore commits the metadata first, as a
//! World overlay, and executes from the second height on. The overlay holds synthetic
//! Global scope metadata: it applies no signed genesis and establishes no authenticated
//! root or network finality.
use iroha_core::state::State;
use iroha_data_model::{
    block::{
        BlockHeader,
        consensus::{SumeragiGenesisContextParameters, SumeragiRootScope},
    },
    parameter::{
        Parameter,
        custom::CustomParameter,
        system::{
            ConsensusFingerprint, ConsensusHandshakeMetadata, SumeragiConsensusMode,
            consensus_metadata,
        },
    },
};
use iroha_primitives::json::Json;
use std::num::NonZeroU64;

/// The consensus handshake metadata parameter with a Global root scope.
pub(crate) fn global_root_scope_parameter() -> Parameter {
    let context = SumeragiGenesisContextParameters::recommended();
    assert_eq!(context.root_scope, SumeragiRootScope::Global);
    let metadata = ConsensusHandshakeMetadata {
        mode: SumeragiConsensusMode::Permissioned,
        block_cadence_ms: NonZeroU64::new(1_000).expect("nonzero cadence"),
        wire_protocol_version: u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION),
        consensus_fingerprint: ConsensusFingerprint::new([0xA5; 32]),
        sumeragi_context: context,
    };
    metadata
        .validate()
        .expect("valid global root scope fixture metadata");
    Parameter::Custom(CustomParameter::new(
        consensus_metadata::handshake_meta_id(),
        Json::new(metadata),
    ))
}

/// Commit the Global root scope as the World overlay of height one. Instructions of the
/// calling test then execute in a block of height two or later.
pub(crate) fn commit_global_root_scope(state: &State) {
    let header = BlockHeader::new(NonZeroU64::MIN, None, None, 0, 0);
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    transaction
        .world
        .parameters_mut_for_testing()
        .get_mut()
        .set_parameter(global_root_scope_parameter())
        .expect("valid fixture parameters");
    transaction.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit the root scope overlay");
    assert_eq!(
        iroha_core::sumeragi::lanes::routing::committed_root_scope(
            state
                .block(BlockHeader::new(
                    NonZeroU64::new(2).expect("nonzero height"),
                    None,
                    None,
                    0,
                    0
                ))
                .world()
        ),
        Some(SumeragiRootScope::Global)
    );
}
