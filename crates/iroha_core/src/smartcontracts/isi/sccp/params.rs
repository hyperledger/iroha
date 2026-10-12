//! SCCP v1 consensus parameters (`specs/sccp.md` §4.1). Owner: ws31.
//!
//! `SccpParametersV1` lives in dedicated world state written only by the genesis-only
//! `InitializeSccpV1` and the Parliament-enacted `SetParameters`. SCCP exists on a network iff
//! the parameters are present. `enabled = false` stops only value-moving effects.

use super::{Error, store};
use crate::state::{StateTransaction, WorldReadOnly};
use iroha_data_model::sccp::params::{
    SCCP_MIN_EPOCH_MS_V1, SccpParameterContextV1, SccpParametersV1,
};
use std::num::NonZeroU64;

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

fn refuse(reason: impl core::fmt::Display) -> Error {
    Error::InvariantViolation(format!("SCCP parameters: {reason}").into())
}

/// Enforce the epoch-duration floor against the immutable block cadence (§4.2).
///
/// # Errors
///
/// Refuses an epoch shorter than one hour. Multiplication is widened to preserve the exact
/// comparison even for otherwise admissible large parameter values.
pub(crate) fn validate_epoch_duration(
    epoch_length_blocks: NonZeroU64,
    block_cadence_ms: NonZeroU64,
) -> Result<(), Error> {
    let duration = u128::from(epoch_length_blocks.get()) * u128::from(block_cadence_ms.get());
    if duration < u128::from(SCCP_MIN_EPOCH_MS_V1) {
        return Err(refuse(
            "epoch_length_blocks × block_cadence_ms must be at least SCCP_MIN_EPOCH_MS (3 600 000)",
        ));
    }
    Ok(())
}

/// Validate a complete new SCCP parameter value against committed consensus policy (§4.1 L1).
///
/// The staking configuration is authenticated by the genesis Nexus policy digest. No local
/// wall clock participates. The unavailable Parliament latency seam is explicitly `None`,
/// which defers that one bound; it does not establish launch or route eligibility.
///
/// # Errors
///
/// Refuses an invalid parameter value, short epoch, unrepresentable staking delay, disabled
/// slashing, or any retained generation whose captured validity and grace exceed that delay.
pub(crate) fn validate_next(
    state_transaction: &StateTransaction<'_, '_>,
    next: &SccpParametersV1,
) -> Result<(), Error> {
    let consensus = state_transaction.world.parameters().sumeragi();
    validate_epoch_duration(consensus.epoch_length_blocks, consensus.block_cadence_ms)?;
    let staking = &state_transaction.nexus.staking;
    let unbonding_delay_ms = u64::try_from(staking.unbonding_delay.as_millis())
        .map_err(|_| refuse("staking unbonding_delay does not fit u64 milliseconds"))?;
    let context = SccpParameterContextV1 {
        // TODO: WP-S5: obtain the full attempt latency from the committed Parliament seam
        // and require it before the launch gate may open; never substitute zero.
        parliament_sccp_attempt_latency_ms: None,
        unbonding_delay_ms,
    };
    next.validate_against(&context).map_err(refuse)?;
    if staking.max_slash_bps == 0 {
        return Err(refuse("nexus.staking.max_slash_bps must be at least 1"));
    }
    for (generation, record) in store::committee_generations::iter(&*state_transaction.world) {
        if record
            .validity_ms
            .checked_add(record.grace_ms)
            .is_none_or(|window| window > unbonding_delay_ms)
        {
            return Err(refuse(format_args!(
                "retained generation {generation} validity_ms + grace_ms exceeds staking unbonding_delay_ms"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{blank_state, header, sample_generation};
    use std::time::Duration;

    fn configure_policy(stx: &mut StateTransaction<'_, '_>) {
        stx.nexus.staking.unbonding_delay = Duration::from_secs(21 * 86_400);
        stx.nexus.staking.max_slash_bps = 1;
        let consensus = &mut stx.world.parameters.get_mut().sumeragi;
        consensus.epoch_length_blocks = NonZeroU64::new(3_600).expect("nonzero epoch");
        consensus.block_cadence_ms = NonZeroU64::new(1_000).expect("nonzero cadence");
    }

    #[test]
    fn epoch_duration_has_an_inclusive_floor_without_multiplication_overflow() {
        let nz = |n| NonZeroU64::new(n).expect("nonzero");
        validate_epoch_duration(nz(3_600), nz(1_000)).expect("exact floor");
        validate_epoch_duration(nz(1), nz(SCCP_MIN_EPOCH_MS_V1)).expect("one slow block");
        validate_epoch_duration(nz(u64::MAX), nz(u64::MAX)).expect("wide exact product");
        validate_epoch_duration(nz(3_599), nz(1_000)).expect_err("below floor");
    }

    #[test]
    fn next_parameters_require_the_pinned_delay_and_nonzero_slashing() {
        let state = blank_state();
        let mut block = state.block(header(1));
        let mut stx = block.transaction();
        configure_policy(&mut stx);
        let next = SccpParametersV1::taira_default();
        validate_next(&stx, &next).expect("21 day floor and explicit deferred latency");
        stx.nexus.staking.unbonding_delay -= Duration::from_millis(1);
        assert!(
            validate_next(&stx, &next)
                .expect_err("short delay")
                .to_string()
                .contains("unbonding_delay")
        );
        configure_policy(&mut stx);
        stx.nexus.staking.max_slash_bps = 0;
        assert!(
            validate_next(&stx, &next)
                .expect_err("no slashing")
                .to_string()
                .contains("max_slash_bps")
        );
        assert_eq!(store::parameters::get(&*stx.world), &None);
    }

    #[test]
    fn lowering_current_parameters_cannot_shorten_retained_generation_liability() {
        let state = blank_state();
        let mut block = state.block(header(1));
        let mut stx = block.transaction();
        configure_policy(&mut stx);
        let mut retained = sample_generation(1, 1);
        retained.grace_ms += 1;
        retained.liable_until_lc += 1;
        store::committee_generations::insert(&mut stx, 1, retained.clone())
            .expect("retained generation");
        let next = SccpParametersV1::taira_default();
        let error = validate_next(&stx, &next).expect_err("retained floor");
        assert!(
            error.to_string().contains("retained generation 1"),
            "{error}"
        );
        assert_eq!(
            store::committee_generations::get(&*stx.world, &1),
            Some(&retained)
        );
        stx.nexus.staking.unbonding_delay += Duration::from_millis(1);
        validate_next(&stx, &next).expect("exact retained floor");
        assert_eq!(store::parameters::get(&*stx.world), &None);
    }

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
