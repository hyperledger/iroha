//! Genesis-only `InitializeSccpV1` (`specs/sccp.md` §4.1, §4.15, §4.18). Owner: ws31.
//!
//! Validates that it executes inside the genesis block under NPoS with `max_validators` in
//! 4..=31, checks the §4.1 parameter table with the staking floor L1 ([`check_parameters`]),
//! stores the parameters and the nonzero reset nonce, creates the three route escrow accounts
//! and an empty registry, and no route. SCCP exists on a network iff `sccp_parameters` is
//! present, so a second initialization is refused.
//!
//! Generation 1 uses the original Global NPoS genesis context; staged World writes cannot
//! manufacture it. The epoch guard and pinned slash policy are checked before publication.

use super::{Error, escrow, generations, parliament_iface, store};
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
/// Retained generations keep their original validity and grace; a new parameter set cannot
/// make those existing liabilities exceed the pinned staking delay.
///
/// # Errors
///
/// Returns the first violated rule of the table.
pub fn check_parameters(
    state_transaction: &StateTransaction<'_, '_>,
    parameters: &SccpParametersV1,
) -> Result<(), SccpParametersError> {
    let unbonding_delay = state_transaction.nexus.staking.unbonding_delay;
    let delay_ms = u64::try_from(unbonding_delay.as_millis()).unwrap_or(u64::MAX);
    if store::committee_generations::iter(&*state_transaction.world).any(|(_, generation)| {
        generation
            .validity_ms
            .checked_add(generation.grace_ms)
            .is_none_or(|required| required > delay_ms)
    }) {
        return Err(SccpParametersError::UnbondingDelayTooShort);
    }
    parameters.validate_against(&SccpParameterContextV1 {
        parliament_sccp_attempt_latency_ms: parliament_iface::parliament_sccp_attempt_latency_ms(),
        unbonding_delay_ms: delay_ms,
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
    let timing = state_transaction.world.parameters().sumeragi();
    if super::params::validate_epoch(
        timing.epoch_length_blocks.get(),
        timing.block_cadence_ms().get(),
    )
    .is_err()
    {
        return Err(refuse(
            "epoch duration is below SCCP_MIN_EPOCH_MS or exceeds the u64 clock",
        ));
    }
    if state_transaction.nexus.staking.max_slash_bps == 0 {
        return Err(refuse("max_slash_bps must be at least one"));
    }
    let generation = generations::prepare_genesis(state_transaction, &instruction.parameters)
        .map_err(|error| match error {
            generations::GenerationError::Degraded(reason) => refuse(format_args!(
                "original genesis generation unavailable: {reason:?}"
            )),
            generations::GenerationError::Deferred(original) => {
                let _ = state_transaction.defer_execution(original);
                refuse("local genesis generation admission did not complete")
            }
        })?;
    store::parameters::set(state_transaction, Some(instruction.parameters));
    store::reset_nonce::set(state_transaction, Some(instruction.reset_nonce));
    escrow::create_route_escrows(state_transaction)?;
    generations::install_genesis(state_transaction, generation).map_err(|original| {
        state_transaction.arm_local_storage_refusal(original);
        refuse("local genesis generation map admission did not complete")
    })?;
    Ok(())
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
    use mv::storage::StorageReadOnly as _;

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
            .set_parameter(Parameter::Custom(npos.into_custom_parameter()))
            .expect("fixture NPoS parameters");
    }

    fn original_genesis_context() -> iroha_data_model::sumeragi::epoch::ValidatorEpochContextV1 {
        use iroha_data_model::{
            parameter::system::SumeragiConsensusMode,
            sumeragi_finality::{authenticated_genesis, test_fixtures::NativeFinalityFixture},
        };
        let fixture = NativeFinalityFixture::start_with_mode(
            "sccp-init-original-context",
            SumeragiConsensusMode::Npos,
        );
        authenticated_genesis(fixture.genesis())
            .expect("signed genesis")
            .into_parts()
            .0
    }

    fn seed_genesis_members(
        stx: &mut StateTransaction<'_, '_>,
        context: &iroha_data_model::sumeragi::epoch::ValidatorEpochContextV1,
    ) {
        use iroha_data_model::nexus::{PublicLaneValidatorRecord, PublicLaneValidatorStatus};
        use iroha_model_base::{metadata::Metadata, topology::LaneId};
        for member in &context.committee {
            let validator = AccountId::new(member.validator.public_key().clone());
            let record = PublicLaneValidatorRecord {
                lane_id: LaneId::SINGLE,
                validator: validator.clone(),
                peer_id: member.validator.clone(),
                stake_account: validator.clone(),
                total_stake: 1_u64.into(),
                self_stake: 1_u64.into(),
                metadata: Metadata::default(),
                status: PublicLaneValidatorStatus::Active,
                activation_height: 1,
                election_exit_height: None,
                deactivation_height: None,
            };
            stx.world
                .public_lane_validators
                .insert((LaneId::SINGLE, validator), record);
        }
    }

    #[test]
    fn sccp_genesis_requires_every_original_signer_to_have_one_staking_binding() {
        use iroha_model_base::topology::LaneId;
        let original = original_genesis_context();
        let state = blank_state();
        let mut block = state.block(header(1));
        let mut stx = block.transaction();
        stx.native_genesis_context = Some(&original);
        set_max_validators(&mut stx, Some(4));
        set_sccp_staking_profile(&mut stx);
        seed_genesis_members(&mut stx, &original);
        let key = (
            LaneId::SINGLE,
            AccountId::new(original.committee[0].validator.public_key().clone()),
        );
        let record = stx.world.public_lane_validators.get(&key).unwrap().clone();
        stx.world.public_lane_validators.remove(key.clone());
        let before_events = stx.world.internal_event_buf.len();
        assert!(
            execute_initialize(SampleInstructions::initialize(), &authority(1), &mut stx).is_err(),
            "SCCP genesis must refuse any signer without its original global staking binding"
        );
        assert!(store::parameters::get(&*stx.world).is_none());
        assert!(store::committee_generations::is_empty(&*stx.world));
        assert_eq!(stx.world.internal_event_buf.len(), before_events);
        stx.world.public_lane_validators.insert(key, record);
        execute_initialize(SampleInstructions::initialize(), &authority(1), &mut stx).unwrap();
        assert!(
            store::committee_generations::get(&*stx.world, &1)
                .unwrap()
                .members
                .iter()
                .all(Option::is_some)
        );
    }

    fn initialize(
        height: u64,
        max_validators: Option<u32>,
        instruction: InitializeSccpV1,
    ) -> Result<(), Error> {
        let original = original_genesis_context();
        let state = blank_state();
        let mut block = state.block(header(height));
        let mut stx = block.transaction();
        stx.native_genesis_context = Some(&original);
        seed_genesis_members(&mut stx, &original);
        set_max_validators(&mut stx, max_validators);
        set_sccp_staking_profile(&mut stx);
        execute_initialize(instruction, &authority(1), &mut stx)
    }

    fn refusal(result: Result<(), Error>) -> String {
        result.expect_err("refused").to_string()
    }

    #[test]
    fn genesis_initialization_stores_parameters_nonce_and_empty_routes() {
        let original = original_genesis_context();
        let state = blank_state();
        let mut block = state.block(header(1));
        let mut stx = block.transaction();
        set_max_validators(&mut stx, Some(31));
        set_sccp_staking_profile(&mut stx);
        stx.native_genesis_context = Some(&original);
        seed_genesis_members(&mut stx, &original);
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
        assert_eq!(*store::committee_current::get(&*stx.world), 1);
        let generation = store::committee_generations::get(&*stx.world, &1).expect("G1");
        assert_eq!(
            generation.cause,
            iroha_data_model::sccp::generation::SccpGenerationCauseV1::Genesis
        );
        assert_eq!(
            (
                generation.start_height,
                generation.start_timestamp_ms,
                generation.start_lc
            ),
            (1, 4_000, 4_000)
        );
        assert_eq!(generation.keys.len(), original.committee.len());
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
        let original = original_genesis_context();
        let with_delay = |delay_ms: u64| {
            let state = blank_state();
            let mut block = state.block(header(1));
            let mut stx = block.transaction();
            set_max_validators(&mut stx, Some(31));
            stx.native_genesis_context = Some(&original);
            seed_genesis_members(&mut stx, &original);
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
    #[test]
    fn signed_genesis_refuses_partially_registered_initial_committee() {
        use crate::{
            smartcontracts::isi::sccp::forgery::tests::{keys, register_genesis_members},
            sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
        };
        use iroha_data_model::parameter::system::{
            SumeragiConsensusMode, SumeragiNposParameters, SumeragiParameter,
        };
        let keys = keys();
        for registered in [0, 2] {
            let mut config = TestChainConfig::new(crate::state::World::new(), 1_000);
            config.validator_keys = Some(keys.clone());
            config.consensus_mode = SumeragiConsensusMode::Npos;
            config.genesis_block_cadence_ms = std::num::NonZeroU64::new(1_000).unwrap();
            let npos = SumeragiNposParameters {
                epoch_length_blocks: std::num::NonZeroU64::new(3_600).unwrap(),
                max_validators: 4,
                ..SumeragiNposParameters::default()
            };
            config.genesis_parameters.extend([
                Parameter::Sumeragi(SumeragiParameter::EpochLengthBlocks(
                    npos.epoch_length_blocks,
                )),
                Parameter::Custom(npos.into_custom_parameter()),
            ]);
            let mut nexus = iroha_config::parameters::actual::Nexus::default();
            nexus.staking.unbonding_delay = std::time::Duration::from_secs(21 * 86_400);
            nexus.staking.max_slash_bps = 1;
            register_genesis_members(&mut config, &keys[..registered], &nexus.staking);
            config.nexus = Some(nexus);
            config
                .genesis_instructions
                .push(SampleInstructions::initialize().into());
            let Err(error) = CertifiedTestChain::start(config) else {
                panic!("G1 requires every original registration");
            };
            assert!(
                format!("{error:?}").contains("InvalidGeneration"),
                "{registered}: {error:?}"
            );
        }
    }

    #[test]
    fn initialization_refuses_missing_original_scope_zero_slash_and_short_epoch_without_writes() {
        use iroha_data_model::parameter::system::SumeragiParameter;
        let original = original_genesis_context();
        for case in 0..3 {
            let state = blank_state();
            let mut block = state.block(header(1));
            let mut stx = block.transaction();
            set_max_validators(&mut stx, Some(4));
            set_sccp_staking_profile(&mut stx);
            if case != 0 {
                stx.native_genesis_context = Some(&original);
            }
            if case == 1 {
                stx.nexus.staking.max_slash_bps = 0;
            }
            if case == 2 {
                stx.world
                    .parameters
                    .get_mut()
                    .set_parameter(Parameter::Sumeragi(SumeragiParameter::EpochLengthBlocks(
                        std::num::NonZeroU64::new(1).unwrap(),
                    )))
                    .expect("fixture short epoch");
            }
            let error = refusal(execute_initialize(
                SampleInstructions::initialize(),
                &authority(1),
                &mut stx,
            ));
            assert!(
                error.contains(match case {
                    0 => "MissingInputs",
                    1 => "max_slash_bps",
                    _ => "epoch duration",
                }),
                "{case}: {error}"
            );
            assert!(store::parameters::get(&*stx.world).is_none());
            assert!(store::committee_generations::is_empty(&*stx.world));
            assert!(store::routes::is_empty(&*stx.world));
            assert_eq!(*store::committee_current::get(&*stx.world), 0);
        }
    }
    #[test]
    fn parameter_update_keeps_every_retained_generation_inside_pinned_unbonding_delay() {
        use crate::{
            smartcontracts::isi::sccp::{
                generation_record::RetainedSccpGeneration, test_support::sample_generation,
            },
            state::StateReadOnly,
        };
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        set_sccp_staking_profile(&mut stx);
        let defaults = SccpParametersV1::taira_default();
        assert_eq!(check_parameters(&stx, &defaults), Ok(()));
        let mut source = sample_generation(1);
        source.validity_ms += 1;
        source.deadline_ms += 1;
        source.liable_until_lc += 1;
        let original = RetainedSccpGeneration::admit(&source, &stx.execution_budget()).unwrap();
        store::committee_generations::insert(&mut stx, 1, original).unwrap();
        assert_eq!(
            check_parameters(&stx, &defaults),
            Err(SccpParametersError::UnbondingDelayTooShort)
        );
        stx.nexus.staking.unbonding_delay += std::time::Duration::from_millis(1);
        assert_eq!(check_parameters(&stx, &defaults), Ok(()));
    }
}
