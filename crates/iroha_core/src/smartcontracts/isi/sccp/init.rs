//! Genesis-only `InitializeSccpV1` (`specs/sccp.md` §4.1, §4.15, §4.18). Owner: ws31.
//!
//! Validates that it executes inside the genesis block under NPoS with `max_validators` in
//! the exact `3f + 1` range 4..=31, checks the epoch and pinned staking policy plus every
//! §4.1 parameter rule, stores the parameters and the nonzero reset nonce,
//! creates the three route escrow accounts and an empty registry. SCCP exists on a network iff
//! `sccp_parameters` is present, so a second initialization is refused.
//!
//! TODO: align the specification's synchronous G1 wording with the authenticated genesis
//! finalizer. The original block owner captures the signed committee before execution, but
//! publishes its schedule only after reconciling the executed genesis. Generation 1 is then
//! created by the SCCP hook in that same output seal; this instruction cannot read the private
//! captured owner and must not reconstruct authority from authored genesis registrations.

use super::{Error, escrow, params, store};
use crate::state::{StateTransaction, WorldReadOnly};
use iroha_data_model::{
    account::AccountId, block::consensus::SumeragiRootScope, isi::sccp::InitializeSccpV1,
};

fn refuse(reason: impl core::fmt::Display) -> Error {
    Error::InvariantViolation(format!("SCCP: InitializeSccpV1 refused: {reason}").into())
}

/// Execute `InitializeSccpV1`.
///
/// # Errors
///
/// Refuses outside the original authenticated Global genesis, when SCCP already exists,
/// without NPoS parameters or with an invalid exact `3f + 1` committee size, epoch or
/// staking policy, a parameter set that breaks a §4.1 rule, or a zero `reset_nonce`.
/// Propagates an escrow creation failure and preserves local read deferral ownership.
pub fn execute_initialize(
    instruction: InitializeSccpV1,
    _authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    if !state_transaction._curr_block.is_genesis() {
        return Err(refuse("valid only inside the genesis block"));
    }
    // A height-one header or mutable metadata cannot authorize a global bridge. Preserve
    // any local decoder/admission refusal recorded by the common scope owner.
    let scope = match crate::executor::root_scope::execution_root_scope(state_transaction) {
        Ok(scope) => scope,
        Err(_) => {
            if let Some(original) = state_transaction.execution_deferral() {
                return Err(state_transaction.attempt_error_to_instruction_error(
                    crate::execution_attempt::ExecutionAttemptError::Deferred(original),
                ));
            }
            return Err(refuse("requires the original authenticated Global genesis"));
        }
    };
    if scope != SumeragiRootScope::Global {
        return Err(refuse("requires the original authenticated Global genesis"));
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
        .is_ok_and(iroha_data_model::block::consensus::is_valid_committee_size)
    {
        return Err(refuse(format_args!(
            "NPoS max_validators {max_validators} must be exactly 3f + 1 in 4..=31"
        )));
    }
    params::validate_next(state_transaction, &instruction.parameters)?;
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
        stx.nexus.staking.unbonding_delay = std::time::Duration::from_secs(21 * 86_400);
        stx.nexus.staking.max_slash_bps = 1;
        let consensus = &mut stx.world.parameters.get_mut().sumeragi;
        consensus.epoch_length_blocks = std::num::NonZeroU64::new(3_600).expect("epoch");
        consensus.block_cadence_ms = std::num::NonZeroU64::new(1_000).expect("cadence");
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

    // Authenticate the exact singleton instruction without executing it during fixture
    // preparation: the negative policy cases must reach the real initializer themselves.
    // This grants component bootstrap scope, not a certified output or valid NPoS policy.
    fn with_original_initialize<T>(
        instruction: InitializeSccpV1,
        scope: SumeragiRootScope,
        action: impl FnOnce(&mut StateTransaction<'_, '_>) -> T,
    ) -> T {
        use crate::{
            kura::Kura,
            query::store::LiveQueryStore,
            state::{State, World},
        };
        use iroha_data_model::{NetworkId, isi::InstructionBox};
        use iroha_model_base::chain::ChainId;
        use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
        iroha_genesis::init_instruction_registry();
        let chain = ChainId::from("sccp-original-initialize");
        let mut context =
            iroha_data_model::block::consensus::SumeragiGenesisContextParameters::recommended();
        context.root_scope = scope;
        let original: InstructionBox = instruction.into();
        let source = iroha_genesis::GenesisBuilder::new_without_executor(chain.clone(), ".")
            .set_topology(
                crate::sumeragi::test_chain::fixture_validators()
                    .into_iter()
                    .map(|(peer, pop)| iroha_genesis::GenesisTopologyEntry::new(peer, pop))
                    .collect::<Vec<_>>(),
            )
            .with_sumeragi_context_parameters(context)
            .next_transaction()
            .append_instruction(original.clone())
            .build_raw()
            .unwrap()
            .with_consensus_meta()
            .unwrap()
            .build_and_sign(&ALICE_KEYPAIR)
            .unwrap()
            .0;
        let state = State::new_with_chain_and_network_id_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            chain,
            NetworkId::from_genesis_hash(source.hash()),
        );
        let index = source
            .external_transactions()
            .position(|signed| {
                matches!(signed.instructions(),
                    iroha_data_model::transaction::Executable::Instructions(instructions)
                        if instructions.iter().eq(core::iter::once(&original))
                )
            })
            .expect("exact original singleton Initialize");
        let mut block = state
            .block_with_pristine_carrier_stage(&source, |_| Ok::<_, String>(()))
            .expect("original signed carrier");
        let mut stx = block
            .transaction_for_original_genesis_testing(&source, index, &ALICE_ID, &original)
            .expect("original signed Initialize scope");
        assert_eq!(
            crate::executor::root_scope::execution_root_scope(&mut stx).unwrap(),
            scope
        );
        action(&mut stx)
    }

    fn initialize(
        height: u64,
        max_validators: Option<u32>,
        instruction: InitializeSccpV1,
    ) -> Result<(), Error> {
        if height != 1 {
            let state = blank_state();
            let mut block = state.block(header(height));
            let mut stx = block.transaction();
            set_max_validators(&mut stx, max_validators);
            return execute_initialize(instruction, &authority(1), &mut stx);
        }
        with_original_initialize(instruction.clone(), SumeragiRootScope::Global, |stx| {
            set_max_validators(stx, max_validators);
            execute_initialize(instruction, &authority(1), stx)
        })
    }

    fn refusal(result: Result<(), Error>) -> String {
        result.expect_err("refused").to_string()
    }

    #[test]
    fn genesis_initialization_stores_parameters_nonce_and_empty_routes() {
        let instruction = SampleInstructions::initialize();
        with_original_initialize(instruction.clone(), SumeragiRootScope::Global, |stx| {
            set_max_validators(stx, Some(31));
            execute_initialize(instruction.clone(), &authority(1), stx).expect("initialize");
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
            let again = refusal(execute_initialize(instruction, &authority(1), stx));
            assert!(again.contains("already initialized"), "{again}");
        });
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
        for size in (4..=31).step_by(3) {
            initialize(1, Some(size), SampleInstructions::initialize()).expect("exact committee");
        }
        for size in [0, 3, 5, 6, 8, 32] {
            let error = refusal(initialize(1, Some(size), SampleInstructions::initialize()));
            assert!(error.contains("NPoS"), "{error}");
        }
        // NPoS validation already bounds the committee, so an unbounded ceiling reads as absent.
        let error = refusal(initialize(1, Some(1), SampleInstructions::initialize()));
        assert!(error.contains("NPoS"), "{error}");
    }

    #[test]
    fn initialization_checks_every_parameter_rule_and_the_nonce() {
        let mut instruction = SampleInstructions::initialize();
        instruction.parameters.committee_heartbeat_ms = 1;
        let error = refusal(initialize(1, Some(31), instruction));
        assert!(error.contains("committee_heartbeat_ms"), "{error}");

        let mut instruction = SampleInstructions::initialize();
        instruction.reset_nonce = [0; 32];
        let error = refusal(initialize(1, Some(31), instruction));
        assert!(error.contains("reset_nonce"), "{error}");
    }

    #[test]
    fn initialization_policy_refusals_write_no_sccp_state() {
        for bad_policy in 0..3 {
            let instruction = SampleInstructions::initialize();
            with_original_initialize(instruction.clone(), SumeragiRootScope::Global, |stx| {
                set_max_validators(stx, Some(4));
                let expected = match bad_policy {
                    0 => {
                        stx.world.parameters.get_mut().sumeragi.epoch_length_blocks =
                            std::num::NonZeroU64::new(3_599).expect("epoch");
                        "SCCP_MIN_EPOCH_MS"
                    }
                    1 => {
                        stx.nexus.staking.unbonding_delay -= std::time::Duration::from_millis(1);
                        "unbonding_delay"
                    }
                    _ => {
                        stx.nexus.staking.max_slash_bps = 0;
                        "max_slash_bps"
                    }
                };
                let error = refusal(execute_initialize(instruction, &authority(1), stx));
                assert!(error.contains(expected), "{error}");
                assert_eq!(store::parameters::get(&*stx.world), &None);
                assert_eq!(store::reset_nonce::get(&*stx.world), &None);
                assert_eq!(store::routes::len(&*stx.world), 0);
            });
        }
    }

    #[test]
    fn initialization_refuses_unauthenticated_or_dataspace_genesis_without_writes() {
        let state = blank_state();
        let mut block = state.block(header(1));
        let mut stx = block.transaction();
        set_max_validators(&mut stx, Some(4));
        let error = refusal(execute_initialize(
            SampleInstructions::initialize(),
            &authority(1),
            &mut stx,
        ));
        assert!(error.contains("authenticated Global genesis"), "{error}");
        assert_eq!(store::parameters::get(&*stx.world), &None);
        assert_eq!(store::reset_nonce::get(&*stx.world), &None);
        assert_eq!(store::routes::len(&*stx.world), 0);
        drop(stx);
        drop(block);
        let scope = SumeragiRootScope::Dataspace {
            parent_network_id: state.network_id,
            dataspace_id: iroha_model_base::topology::DataSpaceId::new(7),
        };
        let instruction = SampleInstructions::initialize();
        with_original_initialize(instruction.clone(), scope, |stx| {
            set_max_validators(stx, Some(4));
            let error = refusal(execute_initialize(instruction, &authority(1), stx));
            assert!(error.contains("authenticated Global genesis"), "{error}");
            assert_eq!(store::parameters::get(&*stx.world), &None);
            assert_eq!(store::reset_nonce::get(&*stx.world), &None);
            assert_eq!(store::routes::len(&*stx.world), 0);
        });
    }
    #[test]
    fn initialization_keeps_a_local_scope_refusal_retryable() {
        let state = blank_state();
        let mut block = state.block(header(1));
        let mut stx = block.transaction();
        let original = crate::execution_attempt::ExecutionDeferred::from(
            ivm::error::ExecutionDeferral::AllocationUnavailable,
        );
        let _ = stx.defer_execution(original.clone());
        let error = refusal(execute_initialize(
            SampleInstructions::initialize(),
            &authority(1),
            &mut stx,
        ));
        assert!(
            error.contains("local instruction read did not complete"),
            "{error}"
        );
        assert_eq!(stx.execution_deferral(), Some(original));
        assert_eq!(store::parameters::get(&*stx.world), &None);
        assert_eq!(store::reset_nonce::get(&*stx.world), &None);
        assert_eq!(store::routes::len(&*stx.world), 0);
    }
}
