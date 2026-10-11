//! Authenticated native height inputs for the SCCP post-execution roster hook.
//!
//! The original output finalizer advances the World consensus schedule before SCCP reads it.
//! Each ready slot retains the exact epoch authorization and ordered committee. At an epoch
//! boundary, the next roster must also be authorized; a pending slot fails closed. Neither
//! registration state nor unauthenticated staged genesis writes can create voting authority.

use crate::state::WorldReadOnly;
use iroha_data_model::parameter::system::ConsensusMode;
use iroha_model_base::peer::PeerId;

/// Consensus inputs of one height for the SCCP roster rule (§4.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SccpHeightInputsV1 {
    /// Consensus mode that selected the roster.
    pub mode: ConsensusMode,
    /// Executing height `h`.
    pub height: u64,
    /// Epoch of `h`.
    pub epoch: u64,
    /// Last height of the epoch of `h`; `h` is a boundary iff it equals `height`.
    pub epoch_end_height: u64,
    /// Voting roster of `h`, in canonical consensus order.
    pub roster: Vec<PeerId>,
    /// Voting roster of the next epoch, present exactly at a boundary.
    pub next_roster: Option<Vec<PeerId>>,
}

/// Where block validation takes the SCCP height inputs of the block it executes.
#[derive(Debug, Clone, Copy)]
pub enum SccpHeightSourceV1 {
    /// A component execution without independently authenticated consensus authority.
    Unauthenticated,
    /// The lag-2 schedule of the Sumeragi core, read after the block advanced it.
    SumeragiSchedule {
        /// The chain's genesis height.
        genesis_height: u64,
        /// Consensus mode of the chain.
        mode: ConsensusMode,
    },
}

/// Why the Sumeragi schedule does not yield the inputs of a height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SccpHeightInputsError {
    /// The height precedes the genesis height.
    #[error("height {height} precedes the genesis height {genesis_height}")]
    BeforeGenesis {
        /// Executing height.
        height: u64,
        /// Genesis height.
        genesis_height: u64,
    },
    /// The stored schedule has no configuration for a needed height.
    #[error("the consensus schedule has no configuration for height {0}")]
    Unscheduled(u64),
    /// The scheduled epoch length is zero.
    #[error("the scheduled epoch length of height {0} is zero")]
    ZeroEpochLength(u64),
    /// A height does not fit `u64`.
    #[error("height arithmetic overflows")]
    Overflow,
}

impl SccpHeightInputsV1 {
    /// Build the inputs of `height` from the Sumeragi core's lag-2 schedule in `world`.
    ///
    /// `world` must hold the schedule after the block of `height` advanced it, which the SCCP
    /// hook sees because the schedule step precedes it in the output-seal finalizer.
    ///
    /// # Errors
    ///
    /// Fails when `height` precedes genesis, the schedule lacks `height` (or `height + 1` at a
    /// boundary), or a required epoch is still pending boundary authorization.
    pub fn from_sumeragi_schedule(
        world: &(impl WorldReadOnly + ?Sized),
        height: u64,
        genesis_height: u64,
        mode: ConsensusMode,
    ) -> Result<Self, SccpHeightInputsError> {
        if height < genesis_height {
            return Err(SccpHeightInputsError::BeforeGenesis {
                height,
                genesis_height,
            });
        }
        let schedule = world.consensus_schedule();
        let current = schedule
            .ready(height)
            .map_err(|_| SccpHeightInputsError::Unscheduled(height))?;
        let epoch = current.epoch.authorization.epoch;
        let epoch_end_height = current.epoch.authorization.last_height;
        let next_roster = if height == epoch_end_height {
            let next_height = height
                .checked_add(1)
                .ok_or(SccpHeightInputsError::Overflow)?;
            let next = schedule
                .ready(next_height)
                .map_err(|_| SccpHeightInputsError::Unscheduled(next_height))?;
            Some(
                next.epoch
                    .committee
                    .iter()
                    .map(|member| member.validator.clone())
                    .collect(),
            )
        } else {
            None
        };
        Ok(Self {
            mode,
            height,
            epoch,
            epoch_end_height,
            roster: current
                .epoch
                .committee
                .iter()
                .map(|member| member.validator.clone())
                .collect(),
            next_roster,
        })
    }

    /// Return whether the height is the last one of its epoch (§4.3.2 boundary).
    #[must_use]
    pub fn is_boundary(&self) -> bool {
        self.height == self.epoch_end_height
    }
}

/// Return `(epoch, epoch_end_height)` of `height` for fixed-length Sumeragi-core epochs of
/// `epoch_length` heights after the genesis height (`specs/sumeragi.md` §11.7). The genesis
/// block and the first `epoch_length` heights after it form epoch 0.
///
/// # Errors
///
/// Fails on a zero epoch length, a height below genesis or an unrepresentable epoch end.
pub fn sumeragi_epoch(
    height: u64,
    genesis_height: u64,
    epoch_length: u64,
) -> Result<(u64, u64), SccpHeightInputsError> {
    if epoch_length == 0 {
        return Err(SccpHeightInputsError::ZeroEpochLength(height));
    }
    if height < genesis_height {
        return Err(SccpHeightInputsError::BeforeGenesis {
            height,
            genesis_height,
        });
    }
    let first = genesis_height
        .checked_add(1)
        .ok_or(SccpHeightInputsError::Overflow)?;
    let epoch = height.saturating_sub(first) / epoch_length;
    let end = epoch
        .checked_add(1)
        .and_then(|epochs| epochs.checked_mul(epoch_length))
        .and_then(|offset| genesis_height.checked_add(offset))
        .ok_or(SccpHeightInputsError::Overflow)?;
    Ok((epoch, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        smartcontracts::isi::sccp::test_support::{blank_state, header},
        sumeragi::schedule::{ChainParamsRecord, ConsensusSchedule, ScheduledConfig},
    };

    #[test]
    fn sumeragi_epochs_start_after_genesis_and_have_fixed_length() {
        assert_eq!(sumeragi_epoch(1, 1, 4), Ok((0, 5)), "genesis is in epoch 0");
        assert_eq!(sumeragi_epoch(2, 1, 4), Ok((0, 5)));
        assert_eq!(
            sumeragi_epoch(5, 1, 4),
            Ok((0, 5)),
            "the boundary of epoch 0"
        );
        assert_eq!(sumeragi_epoch(6, 1, 4), Ok((1, 9)));
        assert_eq!(sumeragi_epoch(9, 1, 4), Ok((1, 9)));
        assert_eq!(sumeragi_epoch(2, 1, 1), Ok((0, 2)));
        assert_eq!(sumeragi_epoch(3, 1, 1), Ok((1, 3)));
        assert_eq!(
            sumeragi_epoch(3, 1, 0),
            Err(SccpHeightInputsError::ZeroEpochLength(3))
        );
        assert_eq!(
            sumeragi_epoch(0, 1, 4),
            Err(SccpHeightInputsError::BeforeGenesis {
                height: 0,
                genesis_height: 1
            })
        );
        assert_eq!(
            sumeragi_epoch(u64::MAX, 1, u64::MAX),
            Err(SccpHeightInputsError::Overflow)
        );
    }

    #[test]
    fn schedule_inputs_reject_an_unauthorized_successor_at_the_boundary() {
        use crate::sumeragi::schedule::{RetainedConsensusSchedule, ScheduledSlot};
        let state = blank_state();
        let signed = crate::sumeragi::epoch::tests::genesis_fixture(
            iroha_data_model::parameter::system::SumeragiConsensusMode::Npos,
            5,
            false,
        );
        let epoch = crate::sumeragi::epoch::authenticated_genesis(&signed)
            .map(|genesis| genesis.into_parts().0)
            .unwrap();
        let roster = epoch
            .committee
            .iter()
            .map(|member| member.validator.clone())
            .collect::<Vec<_>>();
        let params = ChainParamsRecord::from_parameters(&Default::default());
        let graph = ConsensusSchedule::from_owned_entries(vec![
            ScheduledSlot::Ready(ScheduledConfig {
                height: 4,
                epoch: epoch.clone(),
                params,
            }),
            ScheduledSlot::Ready(ScheduledConfig {
                height: 5,
                epoch: epoch.clone(),
                params,
            }),
            ScheduledSlot::PendingBoundary {
                height: 6,
                boundary_height: 5,
                predecessor_context_id: epoch.context_id().unwrap(),
                params,
            },
        ])
        .unwrap();
        let retained =
            RetainedConsensusSchedule::admit(&graph, &state.ivm_execution_budget()).unwrap();
        let mut block = state.block(header(4));
        *block.world.consensus_schedule.get_mut() = retained;
        let inner =
            SccpHeightInputsV1::from_sumeragi_schedule(&block.world, 4, 1, ConsensusMode::Npos)
                .unwrap();
        assert_eq!(inner.roster, roster);
        assert_eq!(inner.epoch, 0);
        assert_eq!(inner.epoch_end_height, 5);
        assert_eq!(inner.next_roster, None);
        assert!(!inner.is_boundary());
        assert_eq!(
            SccpHeightInputsV1::from_sumeragi_schedule(&block.world, 5, 1, ConsensusMode::Npos),
            Err(SccpHeightInputsError::Unscheduled(6)),
            "only a certified boundary installs successor authority"
        );
        assert_eq!(
            SccpHeightInputsV1::from_sumeragi_schedule(&block.world, 7, 1, ConsensusMode::Npos),
            Err(SccpHeightInputsError::Unscheduled(7))
        );
    }
}
