//! Startup SCCP liability floor against the genesis-pinned staking policy.

use iroha_config::parameters::actual::NexusStaking;
use iroha_core::{smartcontracts::isi::sccp::params, state::WorldReadOnly};

/// Refuse an unsafe current or retained liability window before installing startup policy.
/// Chains without SCCP keep the ordinary staking defaults.
pub(crate) fn validate(
    world: &(impl WorldReadOnly + ?Sized),
    staking: &NexusStaking,
) -> Result<(), params::SccpPolicyError> {
    if let Some(parameters) = params::parameters(world) {
        params::validate_staking_policy(world, &parameters, staking)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_core::{
        kura::Kura,
        query::store::LiveQueryStore,
        smartcontracts::isi::sccp::store,
        state::{State, World},
    };
    use iroha_data_model::{block::BlockHeader, sccp::params::SccpParametersV1};
    use std::{num::NonZeroU64, time::Duration};

    #[test]
    fn absent_sccp_keeps_default_staking_but_present_disabled_sccp_retains_floor() {
        let state = State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut block = state.block(BlockHeader::new(NonZeroU64::MIN, None, None, 1, 0));
        let mut stx = block.transaction();
        let mut staking = NexusStaking::default();
        staking.unbonding_delay = Duration::ZERO;
        staking.max_slash_bps = 0;
        validate(&*stx.world, &staking).unwrap();
        let mut parameters = SccpParametersV1::taira_default();
        parameters.enabled = false;
        store::parameters::set(&mut stx, Some(parameters));
        assert_eq!(
            validate(&*stx.world, &staking),
            Err(params::SccpPolicyError::ZeroSlashRate)
        );
        staking.max_slash_bps = 1;
        assert!(validate(&*stx.world, &staking).is_err());
        staking.unbonding_delay = Duration::from_millis(
            parameters.committee_validity_ms + parameters.forgery_evidence_grace_ms,
        );
        validate(&*stx.world, &staking).unwrap();
    }
}
