//! Genesis-only `InitializeSccpV1` (`specs/sccp.md` §4.1, §4.15, §4.18). Owner: ws31.
//!
//! Validates that it executes inside the genesis block under NPoS with `max_validators` in
//! 4..=31, checks every §4.1 parameter rule, stores the parameters and the nonzero reset nonce,
//! creates the three route escrow accounts and an empty registry. SCCP exists on a network iff
//! `sccp_parameters` is present, so a second initialization is refused.

use super::{Error, escrow, store};
use crate::state::{StateTransaction, WorldReadOnly};
use iroha_data_model::{account::AccountId, isi::sccp::InitializeSccpV1};
use iroha_sccp::v1::constants::{MAX_ROSTER_MEMBERS, MIN_ROSTER_MEMBERS};

fn refuse(reason: impl core::fmt::Display) -> Error {
    Error::InvariantViolation(format!("SCCP: InitializeSccpV1 refused: {reason}").into())
}

/// Execute `InitializeSccpV1`.
///
/// # Errors
///
/// Refuses outside the genesis block, when SCCP already exists, without NPoS parameters or
/// with `max_validators` outside 4..=31, with a parameter set that breaks a §4.1 rule, or with
/// a zero `reset_nonce`; propagates an escrow creation failure.
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
        .is_ok_and(|max| (MIN_ROSTER_MEMBERS..=MAX_ROSTER_MEMBERS).contains(&max))
    {
        return Err(refuse(format_args!(
            "NPoS max_validators {max_validators} is outside {MIN_ROSTER_MEMBERS}..={MAX_ROSTER_MEMBERS}"
        )));
    }
    instruction.parameters.validate().map_err(refuse)?;
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
        SampleInstructions, authority, blank_state, header,
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
        for network in SCCP_ROUTE_NETWORKS_V1 {
            let route = store::routes::get(&*stx.world, &network).expect("route");
            assert!(route.revisions.is_empty());
        }
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
        let mut instruction = SampleInstructions::initialize();
        instruction.parameters.roster_max_age_ms = 1;
        let error = refusal(initialize(1, Some(31), instruction));
        assert!(error.contains("roster_max_age_ms"), "{error}");

        let mut instruction = SampleInstructions::initialize();
        instruction.reset_nonce = [0; 32];
        let error = refusal(initialize(1, Some(31), instruction));
        assert!(error.contains("reset_nonce"), "{error}");
    }
}
