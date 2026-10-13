//! SCCP v1 consensus parameters (`specs/sccp.md` §4.1). Owner: ws31.
//!
//! `SccpParametersV1` lives in dedicated world state written only by the genesis-only
//! `InitializeSccpV1` and the Parliament-enacted `SetParameters`. SCCP exists on a network iff
//! the parameters are present. `enabled = false` stops only value-moving effects.

use super::store;
use crate::state::WorldReadOnly;
use iroha_data_model::sccp::params::{
    SCCP_MIN_EPOCH_MS_V1, SccpParameterContextV1, SccpParametersError, SccpParametersV1,
};
use mv::storage::StorageReadOnly;

/// A deterministic violation of SCCP's epoch or genesis-pinned staking policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SccpPolicyError {
    /// An intrinsic parameter or current liability-window bound failed.
    #[error(transparent)]
    Parameters(#[from] SccpParametersError),
    /// The configured staking duration cannot be represented by the protocol clock.
    #[error("SCCP staking unbonding delay exceeds the u64 millisecond clock")]
    UnbondingDelayOverflow,
    /// A slashable committee requires a nonzero pinned slash rate.
    #[error("SCCP requires pinned nexus.staking.max_slash_bps >= 1")]
    ZeroSlashRate,
    /// An already retained generation remains liable beyond the proposed staking delay.
    #[error(
        "SCCP generation {generation} validity {validity_ms} + grace {grace_ms} exceeds unbonding delay {unbonding_delay_ms}"
    )]
    RetainedLiability {
        /// Original generation identifier.
        generation: u64,
        /// Original snapshotted validity interval.
        validity_ms: u64,
        /// Original snapshotted evidence grace.
        grace_ms: u64,
        /// Genesis-pinned staking delay.
        unbonding_delay_ms: u64,
    },
    /// The effective epoch is shorter than the one-hour SCCP floor.
    #[error(
        "SCCP requires epoch_length_blocks {blocks} * block_cadence_ms {cadence_ms} >= {SCCP_MIN_EPOCH_MS_V1}"
    )]
    EpochTooShort {
        /// Prospective epoch length.
        blocks: u64,
        /// Signed-genesis block cadence.
        cadence_ms: u64,
    },
    /// Epoch duration arithmetic cannot be represented by the protocol clock.
    #[error("SCCP epoch duration overflows: {blocks} * {cadence_ms}")]
    EpochOverflow {
        /// Prospective epoch length.
        blocks: u64,
        /// Signed-genesis block cadence.
        cadence_ms: u64,
    },
}

/// Validate the §4.2 epoch floor using checked protocol-clock arithmetic.
///
/// # Errors
/// Returns the exact too-short or overflowing epoch operands.
pub fn validate_epoch(blocks: u64, cadence_ms: u64) -> Result<(), SccpPolicyError> {
    let duration = blocks
        .checked_mul(cadence_ms)
        .ok_or(SccpPolicyError::EpochOverflow { blocks, cadence_ms })?;
    if duration < SCCP_MIN_EPOCH_MS_V1 {
        return Err(SccpPolicyError::EpochTooShort { blocks, cadence_ms });
    }
    Ok(())
}

/// Validate proposed parameters and every retained generation against pinned staking (§4.8 L1).
/// This also applies when SCCP's value-moving switch is disabled.
///
/// # Errors
/// Returns the first invalid current parameter, pinned staking value or retained liability.
pub fn validate_staking_policy(
    world: &(impl WorldReadOnly + ?Sized),
    parameters: &SccpParametersV1,
    staking: &iroha_config::parameters::actual::NexusStaking,
) -> Result<(), SccpPolicyError> {
    let unbonding_delay_ms = u64::try_from(staking.unbonding_delay.as_millis())
        .map_err(|_| SccpPolicyError::UnbondingDelayOverflow)?;
    if staking.max_slash_bps == 0 {
        return Err(SccpPolicyError::ZeroSlashRate);
    }
    parameters.validate_against(&SccpParameterContextV1 {
        // TODO: WP-S5 supplies the authenticated Parliament attempt latency at launch.
        parliament_sccp_attempt_latency_ms: None,
        unbonding_delay_ms,
    })?;
    for (generation, owner) in world.sccp_committee_generations().iter() {
        if owner
            .validity_ms
            .checked_add(owner.grace_ms)
            .is_none_or(|liability| liability > unbonding_delay_ms)
        {
            return Err(SccpPolicyError::RetainedLiability {
                generation: *generation,
                validity_ms: owner.validity_ms,
                grace_ms: owner.grace_ms,
                unbonding_delay_ms,
            });
        }
    }
    Ok(())
}

/// Return the SCCP parameters, or `None` when SCCP does not exist on this network.
#[must_use]
pub fn parameters(world: &(impl WorldReadOnly + ?Sized)) -> Option<SccpParametersV1> {
    *store::parameters::get(world)
}

/// Return whether SCCP exists on this network (its parameters are present).
#[must_use]
pub fn exists(world: &(impl WorldReadOnly + ?Sized)) -> bool {
    store::parameters::get(world).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{blank_state, header};

    #[test]
    fn absent_parameters_mean_sccp_does_not_exist() {
        let state = blank_state();
        let view = state.world_view();
        assert_eq!(parameters(&view), None);
        assert!(!exists(&view));
    }

    #[test]
    fn parameters_follow_the_stored_switch() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let mut stored = SccpParametersV1::taira_default();
        store::parameters::set(&mut stx, Some(stored));
        assert!(exists(&*stx.world));
        assert_eq!(parameters(&*stx.world), Some(stored));
        assert_eq!(parameters(&*stx.world).map(|p| p.enabled), Some(true));
        stored.enabled = false;
        store::parameters::set(&mut stx, Some(stored));
        assert!(exists(&*stx.world));
        assert_eq!(parameters(&*stx.world).map(|p| p.enabled), Some(false));
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use crate::state::World;
    use iroha_config::parameters::actual::NexusStaking;
    use std::time::Duration;

    #[test]
    fn epoch_floor_exact_one_below_and_overflow_are_distinct() {
        validate_epoch(3600, 1000).unwrap();
        validate_epoch(3601, 1000).unwrap();
        assert_eq!(
            validate_epoch(3599, 1000),
            Err(SccpPolicyError::EpochTooShort {
                blocks: 3599,
                cadence_ms: 1000
            })
        );
        assert_eq!(
            validate_epoch(u64::MAX, 2),
            Err(SccpPolicyError::EpochOverflow {
                blocks: u64::MAX,
                cadence_ms: 2
            })
        );
    }

    #[test]
    fn pinned_staking_exact_delay_zero_slash_and_delay_overflow() {
        let world = World::default();
        let world = world.view();
        let parameters = SccpParametersV1::taira_default();
        let exact = parameters.committee_validity_ms + parameters.forgery_evidence_grace_ms;
        let mut staking = NexusStaking::default();
        staking.unbonding_delay = Duration::from_millis(exact);
        staking.max_slash_bps = 1;
        validate_staking_policy(&world, &parameters, &staking).unwrap();
        staking.unbonding_delay = Duration::from_millis(exact - 1);
        assert_eq!(
            validate_staking_policy(&world, &parameters, &staking),
            Err(SccpPolicyError::Parameters(
                SccpParametersError::UnbondingDelayTooShort
            ))
        );
        staking.unbonding_delay = Duration::from_millis(exact);
        staking.max_slash_bps = 0;
        assert_eq!(
            validate_staking_policy(&world, &parameters, &staking),
            Err(SccpPolicyError::ZeroSlashRate)
        );
        staking.max_slash_bps = 1;
        staking.unbonding_delay = Duration::from_secs(u64::MAX);
        assert_eq!(
            validate_staking_policy(&world, &parameters, &staking),
            Err(SccpPolicyError::UnbondingDelayOverflow)
        );
    }
}
