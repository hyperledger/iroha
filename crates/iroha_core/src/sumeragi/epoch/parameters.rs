//! Signed NPoS scheduling and penalty parameters read from committed state.
//!
//! Consensus randomness is supplied exclusively by finalized global
//! threshold-beacon pulses. The pre-release commit/reveal VRF lifecycle and
//! its peer messages are not part of the first-release protocol.

use crate::{execution_attempt::ExecutionAttemptError as Attempt, state::WorldReadOnly};
use iroha_data_model::parameter::system::ConsensusMode;
use thiserror::Error;

/// Failure while resolving or validating first-release NPoS consensus state.
#[derive(Debug, Error)]
pub(crate) enum NposParameterError {
    /// The committed policy is malformed or outside its intrinsic bounds.
    #[error("invalid NPoS parameters: {0}")]
    Invalid(String),
    /// NPoS requires the signed genesis/on-chain parameter snapshot.
    #[error("NPoS requires committed sumeragi_npos_parameters")]
    MissingCommittedParameters,
}

/// Resolve the committed epoch length used by the first-release NPoS schedule.
pub(crate) fn committed_epoch_length_blocks(
    world: &impl WorldReadOnly,
) -> Result<u64, Attempt<NposParameterError>> {
    world
        .sumeragi_npos_parameters()
        .map_err(|error| error.map_rejection(NposParameterError::Invalid))?
        .map(|params| params.epoch_length_blocks().get())
        .ok_or(NposParameterError::MissingCommittedParameters.into())
}

/// Resolve the signed on-chain delay before consensus-evidence penalties apply.
pub(crate) fn resolve_npos_slashing_delay_blocks_from_world(
    world: &impl WorldReadOnly,
) -> Result<Option<u64>, Attempt<String>> {
    Ok(world
        .sumeragi_npos_parameters()?
        .map(|params| params.slashing_delay_blocks()))
}
/// Resolve the epoch index for a height under an authenticated frozen mode.
///
/// Permissioned consensus has one unbounded epoch and does not require NPoS
/// parameters. NPoS must derive its schedule from committed parameters; their
/// absence or invalidity is a consensus error rather than a default schedule.
pub(crate) fn epoch_for_height_from_world(
    world: &impl WorldReadOnly,
    height: u64,
    frozen_mode: ConsensusMode,
) -> Result<u64, Attempt<NposParameterError>> {
    match frozen_mode {
        ConsensusMode::Permissioned => Ok(0),
        ConsensusMode::Npos => {
            let epoch_length = committed_epoch_length_blocks(world)?;
            Ok(height.saturating_sub(1) / epoch_length)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_data_model::parameter::{Parameter, system::SumeragiNposParameters};
    use std::num::NonZeroU64;

    #[test]
    fn npos_epoch_schedule_uses_committed_epoch_length() {
        let state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut parameters = SumeragiNposParameters::default();
        parameters.epoch_length_blocks = NonZeroU64::new(7).expect("non-zero epoch length");
        parameters.evidence_horizon_blocks = 14;
        parameters.slashing_delay_blocks = 7;
        parameters
            .validate()
            .expect("test NPoS parameters must be internally consistent");
        {
            let mut block = state.world.parameters.block();
            block
                .set_parameter(Parameter::Custom(parameters.into_custom_parameter()))
                .expect("valid fixture parameters");
            block.commit();
        }
        let world = state.world_view();
        assert_eq!(
            epoch_for_height_from_world(&world, 0, ConsensusMode::Npos).expect("valid schedule"),
            0
        );
        assert_eq!(
            epoch_for_height_from_world(&world, 1, ConsensusMode::Npos).expect("valid schedule"),
            0
        );
        assert_eq!(
            epoch_for_height_from_world(&world, 7, ConsensusMode::Npos).expect("valid schedule"),
            0
        );
        assert_eq!(
            epoch_for_height_from_world(&world, 8, ConsensusMode::Npos).expect("valid schedule"),
            1
        );
        assert_eq!(
            epoch_for_height_from_world(&world, 15, ConsensusMode::Npos).expect("valid schedule"),
            2
        );
    }

    #[test]
    fn permissioned_epoch_is_zero_without_npos_parameters_at_all_boundaries() {
        let state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let world = state.world_view();
        for height in [0, 1, 3_600, 3_601, u64::MAX] {
            assert_eq!(
                epoch_for_height_from_world(&world, height, ConsensusMode::Permissioned)
                    .expect("permissioned mode does not require an NPoS schedule"),
                0
            );
        }
    }

    #[test]
    fn npos_epoch_rejects_missing_committed_parameters() {
        let state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let world = state.world_view();
        assert!(matches!(
            epoch_for_height_from_world(&world, 1, ConsensusMode::Npos),
            Err(Attempt::Rejected(
                NposParameterError::MissingCommittedParameters
            ))
        ));
    }
}
