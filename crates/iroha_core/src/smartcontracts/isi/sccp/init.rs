//! Genesis-only `InitializeSccpV1` (`specs/sccp.md` §4.1, §4.15, §4.18). Owner: ws31.
//!
//! Validates that it executes inside the genesis block under NPoS with `max_validators` in
//! 4..=31, checks the §4.1 parameter table with the staking floor L1 ([`check_parameters`]),
//! stores the parameters and the nonzero reset nonce, creates the three route escrow accounts
//! and an empty registry, and no route. SCCP exists on a network iff `sccp_parameters` is
//! present, so a second initialization is refused.
//!
//! TODO: WP-S2: create committee generation 1 (§4.2.2 G1) and check the epoch-duration guard
//! (`epoch_length_blocks × block_cadence_ms ≥ SCCP_MIN_EPOCH_MS`, §4.2.2).

use super::{Error, escrow, parliament_iface, store};
use crate::state::{StateTransaction, WorldReadOnly};
use iroha_data_model::{
    account::AccountId,
    isi::sccp::InitializeSccpV1,
    sccp::params::{SccpParameterContextV1, SccpParametersError, SccpParametersV1},
};
use iroha_sccp::v1::committee::{MAX_COMMITTEE_SIZE, MIN_COMMITTEE_SIZE};

fn refuse(reason: impl core::fmt::Display) -> Error {
    Error::InvariantViolation(format!("SCCP: InitializeSccpV1 refused: {reason}").into())
}

/// Check `parameters` against the §4.1 table, as `InitializeSccpV1` and the Parliament's
/// `SetParameters` do against the complete new value.
///
/// Every field's own bound and every joint rule is checked. Two rules read a value from
/// outside the table:
///
/// * the staking floor L1 (§4.8), `committee_validity_ms + forgery_evidence_grace_ms ≤
///   unbonding_delay_ms`, reads `nexus.staking.unbonding_delay` of the node's genesis-pinned
///   staking policy. The global default delay is 0, so SCCP initializes only under a staking
///   profile that sets it (21 d for the Taira defaults);
/// * the lower bound of `fast_pause_hold_ms` reads the Parliament attempt latency through
///   [`parliament_iface::parliament_sccp_attempt_latency_ms`]; while the Parliament pipeline
///   provides none, that bound is deferred, never treated as met by a zero latency.
///
/// TODO: WP-S5: require the attempt latency when the launch gate opens (§10.2).
///
/// TODO: WP-S6: the rest of L1: `validity_ms + grace_ms` of every retained committee
/// generation, and `nexus.staking.max_slash_bps ≥ 1`.
///
/// # Errors
///
/// Returns the first violated rule of the table.
pub fn check_parameters(
    state_transaction: &StateTransaction<'_, '_>,
    parameters: &SccpParametersV1,
) -> Result<(), SccpParametersError> {
    let unbonding_delay = state_transaction.nexus.staking.unbonding_delay;
    parameters.validate_against(&SccpParameterContextV1 {
        parliament_sccp_attempt_latency_ms: parliament_iface::parliament_sccp_attempt_latency_ms(),
        unbonding_delay_ms: u64::try_from(unbonding_delay.as_millis()).unwrap_or(u64::MAX),
    })
}

/// Execute `InitializeSccpV1`.
///
/// # Errors
///
/// Refuses outside the genesis block, when SCCP already exists, without NPoS parameters or
/// with `max_validators` outside 4..=31, with a parameter set that breaks a §4.1 rule or the
/// staking floor L1, or with a zero `reset_nonce`; propagates an escrow creation failure.
pub fn execute_initialize(
    instruction: InitializeSccpV1,
    _authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    if !state_transaction._curr_block.is_genesis() {
        return Err(refuse("valid only inside the genesis block"));
    }
    if store::parameters::get(&*state_transaction.world).is_some() {
        return Err(refuse("SCCP is already initialized"));
    }
    let max_validators = state_transaction
        .world
        .sumeragi_npos_parameters()
        .map_err(|error| match error {
            crate::execution_attempt::ExecutionAttemptError::Rejected(message) => refuse(
                format_args!("NPoS consensus parameters are invalid: {message}"),
            ),
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                let _ = state_transaction.defer_execution(reason);
                refuse("local NPoS read did not complete")
            }
        })?
        .ok_or_else(|| refuse("NPoS consensus parameters are required"))?
        .max_validators();
    if !usize::try_from(max_validators)
        .is_ok_and(|max| (MIN_COMMITTEE_SIZE..=MAX_COMMITTEE_SIZE).contains(&max))
    {
        return Err(refuse(format_args!(
            "NPoS max_validators {max_validators} is outside {MIN_COMMITTEE_SIZE}..={MAX_COMMITTEE_SIZE}"
        )));
    }
    check_parameters(state_transaction, &instruction.parameters).map_err(refuse)?;
    if instruction.reset_nonce == [0; 32] {
        return Err(refuse("reset_nonce must be nonzero"));
    }
    store::parameters::set(state_transaction, Some(instruction.parameters));
    store::reset_nonce::set(state_transaction, Some(instruction.reset_nonce));
    escrow::create_route_escrows(state_transaction)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{
        SCCP_UNBONDING_DELAY_MS, SampleInstructions, authority, blank_state, header,
        set_sccp_staking_profile,
    };
    use iroha_data_model::{
        bridge::SccpNetworkV1,
        parameter::{Parameter, system::SumeragiNposParameters},
        sccp::registry::SCCP_ROUTE_NETWORKS_V1,
    };

    fn set_max_validators(stx: &mut StateTransaction<'_, '_>, max_validators: Option<u32>) {
        let Some(max_validators) = max_validators else {
            return;
        };
        let npos = SumeragiNposParameters {
            max_validators,
            ..SumeragiNposParameters::default()
        };
        stx.world
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(npos.into_custom_parameter()));
    }

    fn initialize(
        height: u64,
        max_validators: Option<u32>,
        instruction: InitializeSccpV1,
    ) -> Result<(), Error> {
        let state = blank_state();
        let mut block = state.block(header(height));
        let mut stx = block.transaction();
        set_max_validators(&mut stx, max_validators);
        set_sccp_staking_profile(&mut stx);
        execute_initialize(instruction, &authority(1), &mut stx)
    }

    fn refusal(result: Result<(), Error>) -> String {
        result.expect_err("refused").to_string()
    }

    #[test]
    fn genesis_initialization_stores_parameters_nonce_and_empty_routes() {
        let state = blank_state();
        let mut block = state.block(header(1));
        let mut stx = block.transaction();
        set_max_validators(&mut stx, Some(31));
        set_sccp_staking_profile(&mut stx);
        let instruction = SampleInstructions::initialize();
        execute_initialize(instruction.clone(), &authority(1), &mut stx).expect("initialize");
        assert_eq!(
            store::parameters::get(&*stx.world).as_ref(),
            Some(&instruction.parameters)
        );
        assert_eq!(
            *store::reset_nonce::get(&*stx.world),
            Some(instruction.reset_nonce)
        );
        assert_eq!(SCCP_ROUTE_NETWORKS_V1.len(), 3, "three route escrows");
        for network in SCCP_ROUTE_NETWORKS_V1 {
            let route = store::routes::get(&*stx.world, &network).expect("route");
            assert!(route.revisions.is_empty(), "genesis registers no route");
        }
        assert_eq!(store::routes::len(&*stx.world), 3);
        assert!(store::routes::get(&*stx.world, &SccpNetworkV1::SoraTaira).is_none());
        let again = refusal(execute_initialize(instruction, &authority(1), &mut stx));
        assert!(again.contains("already initialized"), "{again}");
    }

    #[test]
    fn initialization_is_genesis_only() {
        let error = refusal(initialize(2, Some(31), SampleInstructions::initialize()));
        assert!(error.contains("genesis"), "{error}");
    }

    #[test]
    fn initialization_requires_npos_with_a_bounded_committee() {
        let error = refusal(initialize(1, None, SampleInstructions::initialize()));
        assert!(error.contains("NPoS"), "{error}");
        initialize(1, Some(4), SampleInstructions::initialize()).expect("minimum committee");
        // NPoS validation already bounds the committee, so an unbounded ceiling reads as absent.
        let error = refusal(initialize(1, Some(1), SampleInstructions::initialize()));
        assert!(error.contains("NPoS"), "{error}");
    }

    #[test]
    fn initialization_checks_every_parameter_rule_and_the_nonce() {
        // One field's own bound, one joint rule and the retired exempt-cap floor of 94.
        let mut instruction = SampleInstructions::initialize();
        instruction.parameters.committee_heartbeat_ms = 1;
        let error = refusal(initialize(1, Some(31), instruction));
        assert!(error.contains("committee_heartbeat_ms"), "{error}");

        let mut instruction = SampleInstructions::initialize();
        instruction.parameters.committee_validity_ms = instruction.parameters.fast_pause_hold_ms;
        let error = refusal(initialize(1, Some(31), instruction));
        assert!(error.contains("committee_validity_ms"), "{error}");

        let mut instruction = SampleInstructions::initialize();
        instruction.parameters.max_exempt_transactions_per_block = 8;
        initialize(1, Some(31), instruction).expect("the smallest exempt cap");
        let mut instruction = SampleInstructions::initialize();
        instruction.parameters.max_exempt_transactions_per_block = 7;
        let error = refusal(initialize(1, Some(31), instruction));
        assert!(
            error.contains("max_exempt_transactions_per_block"),
            "{error}"
        );

        let mut instruction = SampleInstructions::initialize();
        instruction.reset_nonce = [0; 32];
        let error = refusal(initialize(1, Some(31), instruction));
        assert!(error.contains("reset_nonce"), "{error}");
    }

    #[test]
    fn initialization_checks_the_staking_floor_against_the_node_policy() {
        use core::time::Duration;
        let with_delay = |delay_ms: u64| {
            let state = blank_state();
            let mut block = state.block(header(1));
            let mut stx = block.transaction();
            set_max_validators(&mut stx, Some(31));
            stx.nexus.staking.unbonding_delay = Duration::from_millis(delay_ms);
            execute_initialize(SampleInstructions::initialize(), &authority(1), &mut stx)
        };
        // L1: the Taira defaults need 14 d + 7 d of unbonding delay.
        assert_eq!(SCCP_UNBONDING_DELAY_MS, 21 * 86_400_000);
        with_delay(SCCP_UNBONDING_DELAY_MS).expect("the staking profile meets L1");
        for short in [SCCP_UNBONDING_DELAY_MS - 1, 0] {
            let error = refusal(with_delay(short));
            assert!(error.contains("unbonding_delay_ms"), "{short}: {error}");
        }
    }

    #[test]
    fn the_parameter_table_defers_only_the_parliament_latency() {
        let state = blank_state();
        let mut block = state.block(header(1));
        let mut stx = block.transaction();
        set_sccp_staking_profile(&mut stx);
        let defaults = SccpParametersV1::taira_default();
        assert_eq!(check_parameters(&stx, &defaults), Ok(()));
        // The hold's own ceiling and the joint validity floor are checked here.
        let mut long_hold = defaults;
        long_hold.fast_pause_hold_ms = u64::MAX;
        assert_eq!(
            check_parameters(&stx, &long_hold),
            Err(SccpParametersError::FastPauseHoldTooLong)
        );
        let mut short_validity = defaults;
        short_validity.committee_validity_ms = short_validity.fast_pause_hold_ms;
        assert_eq!(
            check_parameters(&stx, &short_validity),
            Err(SccpParametersError::CommitteeValidityTooShort)
        );
        // L1 reads the staking policy of the node.
        let mut long_grace = defaults;
        long_grace.forgery_evidence_grace_ms += 1;
        assert_eq!(
            check_parameters(&stx, &long_grace),
            Err(SccpParametersError::UnbondingDelayTooShort)
        );
        // The Parliament latency is unavailable: the lower bound of the hold is deferred, so
        // the smallest hold the other rules admit passes.
        assert_eq!(parliament_iface::parliament_sccp_attempt_latency_ms(), None);
        let mut short_hold = defaults;
        short_hold.fast_pause_hold_ms = 2 * short_hold.fast_pause_renew_lead_ms;
        assert_eq!(check_parameters(&stx, &short_hold), Ok(()));
    }
}
