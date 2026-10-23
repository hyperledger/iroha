// The sole native genesis execution must reproduce every signed deterministic policy.
impl ValidBlock {
    fn validate_native_genesis_policy(
        block: &SignedBlock,
        state: &StateBlock<'_>,
    ) -> Result<(), BlockValidationError> {
        if !block.header().is_genesis() {
            return Ok(());
        }
        crate::state::parliament_candidate_testing::validate_genesis_output(block, state)
            .map_err(Self::execution_context_error)?;
        let metadata =
            iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(block).map_err(
                |error| match crate::execution_attempt::genesis_read_attempt_error(error, |error| {
                    Self::execution_context_error(error.to_string())
                }) {
                    crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
                    crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                        BlockValidationError::ExecutionDeferred(reason)
                    }
                },
            )?;
        // Exactly one original instruction owns the complete initial policy. Comparing
        // its existing payload with the executed slot introduces no second policy decoder.
        let fee_id = iroha_data_model::block::consensus::RootFeePolicy::parameter_id();
        let mut originals = block
            .external_transactions()
            .filter_map(|transaction| match transaction.instructions() {
                iroha_data_model::transaction::Executable::Instructions(instructions) => {
                    Some(instructions)
                }
                _ => None,
            })
            .flat_map(|instructions| instructions.iter())
            .filter_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<iroha_data_model::isi::SetParameter>()
            })
            .filter_map(|set| match set.inner() {
                iroha_data_model::parameter::Parameter::Custom(custom)
                    if custom.id() == &fee_id =>
                {
                    Some(custom)
                }
                _ => None,
            });
        let original = originals.next().ok_or_else(|| {
            Self::execution_context_error("signed genesis omits its root fee policy")
        })?;
        if (!cfg!(all(test, sumeragi_core_mutation = "HC398")) && originals.next().is_some())
            || state.world().parameters().custom().get(&fee_id) != Some(original)
        {
            return Err(Self::execution_context_error(
                "signed genesis must execute exactly one original root fee policy",
            ));
        }
        let fees = state.world().parameters().root_fees().ok_or_else(|| {
            Self::execution_context_error("signed genesis root fee policy is absent")
        })?;
        fees.validate_for_scope(&metadata.sumeragi_context.root_scope)
            .map_err(|error| Self::execution_context_error(error.to_string()))?;
        if matches!(
            metadata.sumeragi_context.root_scope,
            iroha_data_model::block::consensus::SumeragiRootScope::Global
        ) && resolve_network_xor_asset_definition(
            state.world(),
            &fees.fee_asset_id.canonical_address(),
            0,
        )
        .map_err(BlockValidationError::ExecutionDeferred)?
            != Some(fees.fee_asset_id.clone())
        {
            return Err(Self::execution_context_error(
                "Global genesis fee currency differs from its signed network XOR",
            ));
        }
        let actual_execution = crate::sumeragi::staged_genesis_execution_policy_hash(state)
            .map_err(|error| Self::execution_context_error(error.to_string()))?;
        let actual_nexus = crate::sumeragi::staged_genesis_nexus_amx_context_hash(state);
        Self::require_native_genesis_policy(
            Hash::prehashed(metadata.sumeragi_context.execution_policy_hash),
            actual_execution,
            Hash::prehashed(metadata.sumeragi_context.nexus_amx_context_hash),
            actual_nexus,
        )?;
        // Startup consumes this original execution instead of executing a disposable second
        // genesis. Preserve its exact H1 cadence check before any durable publication.
        let actual_cadence = state
            .world()
            .parameters()
            .sumeragi()
            .block_cadence_ms()
            .get();
        let signed_cadence = metadata.block_cadence_ms.get();
        if actual_cadence != signed_cadence {
            return Err(Self::execution_context_error(format!(
                "staged genesis cadence {actual_cadence} ms differs from authenticated signed cadence {signed_cadence} ms"
            )));
        }
        state
            .world()
            .parameters()
            .sumeragi()
            .validate_clock_policy()
            .map_err(|error| Self::execution_context_error(error.to_string()))?;
        iroha_data_model::sumeragi_amx::amx_max_time_window_ms(actual_cadence)
            .map_err(|error| Self::execution_context_error(error.to_string()))?;
        Ok(())
    }

    fn require_native_genesis_policy(
        expected_execution: Hash,
        actual_execution: Hash,
        expected_nexus: Hash,
        actual_nexus: Hash,
    ) -> Result<(), BlockValidationError> {
        if expected_execution != actual_execution || expected_nexus != actual_nexus {
            return Err(BlockValidationError::GenesisPolicyMismatch {
                expected_execution,
                actual_execution,
                expected_nexus,
                actual_nexus,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod native_genesis_policy_tests {
    use super::*;

    fn explicit_staking_config() -> crate::sumeragi::test_chain::TestChainConfig {
        use iroha_data_model::{
            asset::AssetDefinitionId, block::consensus::PublicLaneStakingPolicy,
            parameter::Parameter,
        };
        let mut config =
            crate::sumeragi::test_chain::TestChainConfig::new(crate::state::World::new(), 1_000);
        // Author the monetary policy in the signed original parameter vector; these
        // policy references do not assert that any account or stake is funded.
        let staking = PublicLaneStakingPolicy {
            min_validator_stake: 1_000_u64.into(),
            max_stake_shares_per_validator: std::num::NonZeroU32::new(7).unwrap(),
            max_pending_unbonds_per_share: std::num::NonZeroU32::new(3).unwrap(),
            unbonding_delay_ms: 43_210,
            max_slash_bps: 1_001,
            stake_asset_id: AssetDefinitionId::derive_from_components(
                iroha_model_base::domain::DomainId::parse_fully_qualified("app.acme").unwrap(),
                "stake".parse().unwrap(),
            ),
            stake_escrow_account_id: iroha_test_samples::ALICE_ID.clone(),
            slash_sink_account_id: iroha_test_samples::BOB_ID.clone(),
        };
        let mut original_slots = config.genesis_parameters.iter_mut().filter(|parameter| {
            matches!(parameter, Parameter::Custom(custom)
                if custom.id() == &PublicLaneStakingPolicy::parameter_id())
        });
        let slot = original_slots
            .next()
            .expect("the fixture authors one staking policy");
        *slot = Parameter::Custom(staking.into_custom_parameter().unwrap());
        assert!(
            original_slots.next().is_none(),
            "one canonical staking authority"
        );
        config
    }

    #[test]
    fn signed_genesis_requires_both_exact_policy_commitments() {
        let execution = Hash::new(b"original execution policy");
        let nexus = Hash::new(b"original Nexus policy");
        assert!(
            ValidBlock::require_native_genesis_policy(execution, execution, nexus, nexus).is_ok()
        );
        let foreign = Hash::new(b"substituted policy");
        for (actual_execution, actual_nexus) in
            [(foreign, nexus), (execution, foreign), (foreign, foreign)]
        {
            let error = ValidBlock::require_native_genesis_policy(
                execution,
                actual_execution,
                nexus,
                actual_nexus,
            )
            .unwrap_err();
            assert!(
                matches!(error, BlockValidationError::GenesisPolicyMismatch {
                expected_execution, actual_execution: retained_execution,
                expected_nexus, actual_nexus: retained_nexus,
            } if expected_execution == execution && expected_nexus == nexus
                && retained_execution == actual_execution && retained_nexus == actual_nexus)
            );
        }
    }

    #[test]
    fn native_signed_genesis_ignores_local_fraud_policy_and_transport() {
        use crate::sumeragi::{network_topology::Topology, test_chain::CertifiedTestChain};
        use iroha_config::parameters::actual::FraudMonitoring;
        use iroha_data_model::fraud::FraudRiskBandV1;
        use iroha_primitives::time::TimeSource;
        use std::{sync::Arc, time::Duration};

        let fraud = FraudMonitoring {
            policy: iroha_data_model::fraud::FraudAdmissionPolicyV1 {
                enabled: true,
                required_minimum_band: Some(FraudRiskBandV1::Low),
                missing_assessment_permitted: false,
                ..iroha_data_model::fraud::FraudAdmissionPolicyV1::protocol_default()
            },
            ..FraudMonitoring::default()
        };
        let mut config = explicit_staking_config();
        config.fraud_monitoring = fraud.clone();
        let authority = AccountId::new(config.genesis_key.public_key().clone());
        let mut prepared =
            CertifiedTestChain::prepare(config).expect("original signed genesis fixture");
        let genesis = prepared.genesis.block().clone();
        let original_hash = genesis.hash();
        let topology = Topology::new(
            prepared
                .validator_keys
                .iter()
                .map(|key| PeerId::new(key.public_key().clone())),
        );
        let validate = |state: &crate::state::State| {
            let result = ValidBlock::validate_signed_genesis(
                genesis.clone(),
                &topology,
                &authority,
                &TimeSource::new_system(),
                state,
                iroha_data_model::parameter::system::ConsensusMode::Permissioned,
                iroha_data_model::block::consensus::SumeragiRootScope::Global,
            )
            .unpack(|_| {});
            match result {
                Ok(staged) => drop(staged),
                Err((_, error)) => panic!(
                    "the unchanged signed genesis must use committed fraud policy, not node settings: {error}"
                ),
            }
        };
        validate(&prepared.state);

        let mut local = fraud;
        local.service_endpoints = vec!["https://unavailable.invalid/assess".parse().unwrap()];
        local.connect_timeout = Duration::from_millis(1);
        local.request_timeout = Duration::from_millis(2);
        Arc::get_mut(&mut prepared.state)
            .expect("the unapplied fixture retains its sole State owner")
            .install_node_fraud_monitoring(local.clone());
        validate(&prepared.state);

        // A caller can mutate this effective test projection, but node installation
        // discards its semantic fields and derives them from committed parameters.
        // The authored genesis policy therefore remains the only admission authority.
        local.policy.missing_assessment_permitted = true;
        Arc::get_mut(&mut prepared.state)
            .expect("validation releases its original State borrow")
            .install_node_fraud_monitoring(local);
        validate(&prepared.state);
        assert_eq!(prepared.genesis.block().hash(), original_hash);
        assert_eq!(prepared.state.committed_height(), 0);
        assert_eq!(prepared.kura.exact_durable_blocks_count().unwrap(), 0);
    }

    #[test]
    fn native_final_genesis_policy_requires_exact_executed_cadence_before_publication() {
        use crate::{
            state::WorldReadOnly as _,
            sumeragi::{network_topology::Topology, test_chain::CertifiedTestChain},
        };
        use iroha_primitives::time::TimeSource;

        let config = explicit_staking_config();
        let authority = AccountId::new(config.genesis_key.public_key().clone());
        let prepared =
            CertifiedTestChain::prepare(config).expect("original signed genesis fixture");
        let genesis = prepared.genesis.block();
        let metadata =
            iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(genesis)
                .expect("original signed consensus metadata");
        let topology = Topology::new(
            prepared
                .validator_keys
                .iter()
                .map(|key| PeerId::new(key.public_key().clone())),
        );
        let (valid, sealed) = ValidBlock::validate_signed_genesis(
            genesis.clone(),
            &topology,
            &authority,
            &TimeSource::new_system(),
            &prepared.state,
            iroha_data_model::parameter::system::ConsensusMode::Permissioned,
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        )
        .unpack(|_| {})
        .unwrap_or_else(|(_, error)| panic!("original native genesis: {error}"));
        assert_eq!(prepared.state.committed_height(), 0);
        assert_eq!(prepared.kura.exact_durable_blocks_count().unwrap(), 0);
        ValidBlock::validate_native_genesis_policy(genesis, &sealed)
            .expect("the actual original staged state matches its signed metadata");
        // A completed native execution is immutable. Retain the full native
        // positive control above, then execute the same authenticated inputs on
        // their pristine owner and stop at the real pre-seal policy boundary.
        // Negative probes must never reopen or mutate a completed execution.
        drop(sealed);
        let mut profile = ConsensusValidationProfile::SumeragiGenesis {
            consensus_mode: iroha_data_model::parameter::system::ConsensusMode::Permissioned,
            root_scope: metadata.sumeragi_context.root_scope,
        };
        let generation = prepared.state.state_view_generation();
        let source = PristineNativeSource {
            state: &prepared.state,
            generation,
            header: genesis.header(),
            staking: crate::sumeragi::evidence::prepare(&prepared.state, genesis, generation)
                .expect("the original authenticated genesis staking inputs"),
        };
        let authenticated = authenticate_genesis_block_intents(genesis, &authority)
            .expect("the same original signed genesis inputs");
        let mut genesis_policies = Some(
            authenticated
                .initial_policies(genesis)
                .expect("both original signed genesis policies"),
        );
        let (mut staged, _recording) = ValidBlock::state_block_for_execution(
            genesis,
            &prepared.state,
            source,
            &profile,
            &mut genesis_policies,
        )
        .expect("the original pristine genesis execution owner");
        assert!(
            genesis_policies.is_none(),
            "installation moves both original policy owners"
        );
        staged.request_sumeragi_lanes(profile.take_sumeragi_lanes().unwrap());
        staged.reserve_ordinary_execution_outputs(genesis).unwrap();
        staged
            .execute_ordinary_output_plan(genesis, Some(&authenticated))
            .unwrap();
        let outputs = staged.retained_execution_outputs_for_test().unwrap();
        assert_eq!(outputs.len(), valid.as_ref().execution_outputs().len());
        assert!(GenesisOutputRejection::first(outputs).is_none());
        staged.advance_requested_sumeragi_schedule().unwrap();
        staged.advance_requested_sumeragi_lanes().unwrap();
        staged.advance_sumeragi_amx().unwrap();
        ValidBlock::validate_native_genesis_policy(genesis, &staged)
            .expect("the same genuine execution matches before the immutable seal");

        let original_cadence = staged.world().parameters().sumeragi().block_cadence_ms();
        assert_eq!(original_cadence, metadata.block_cadence_ms);
        let changed =
            std::num::NonZeroU64::new(original_cadence.get().checked_add(1).unwrap()).unwrap();
        {
            let parameters = staged.world.parameters.get_mut();
            let mut consensus = parameters.sumeragi().clone();
            consensus.block_cadence_ms = changed;
            parameters.set_sumeragi(consensus);
        }
        let error = ValidBlock::validate_native_genesis_policy(genesis, &staged)
            .expect_err("signed metadata cannot bless a different final executed H1 cadence");
        let expected = format!(
            "staged genesis cadence {} ms differs from authenticated signed cadence {} ms",
            changed.get(),
            original_cadence.get()
        );
        assert!(
            matches!(error, BlockValidationError::ExecutionContextInvalid(ref reason) if reason == &expected),
            "{error}"
        );
        assert_eq!(prepared.state.committed_height(), 0);
        assert_eq!(prepared.kura.exact_durable_blocks_count().unwrap(), 0);
        {
            let parameters = staged.world.parameters.get_mut();
            let mut consensus = parameters.sumeragi().clone();
            consensus.block_cadence_ms = original_cadence;
            parameters.set_sumeragi(consensus);
        }
        ValidBlock::validate_native_genesis_policy(genesis, &staged)
            .expect("restoring the exact original staged cadence restores acceptance");
        let original_clock = staged.world().parameters().sumeragi().clone();
        // The signed fixture chooses its own cadence (currently 1 ms). Derive
        // the CT5 boundary from the actual executed inputs, not an assumed
        // 1,000 ms cadence that would make a fixed 5,999 ms lag invalid.
        let minimum_lag = original_clock
            .max_clock_drift_ms()
            .checked_mul(2)
            .and_then(|drift| {
                original_cadence
                    .get()
                    .checked_mul(4)
                    .and_then(|cadence| drift.checked_add(cadence))
            })
            .expect("the original signed CT5 margin fits");
        {
            let parameters = staged.world.parameters.get_mut();
            let mut consensus = original_clock.clone();
            consensus.due_work_max_lag_ms = std::num::NonZeroU64::new(minimum_lag).unwrap();
            parameters.set_sumeragi(consensus);
        }
        ValidBlock::validate_native_genesis_policy(genesis, &staged)
            .expect("the exact combined CT5 margin is valid before publication");
        let below_minimum = minimum_lag.checked_sub(1).unwrap();
        {
            let parameters = staged.world.parameters.get_mut();
            let mut consensus = original_clock.clone();
            consensus.due_work_max_lag_ms = std::num::NonZeroU64::new(below_minimum).unwrap();
            parameters.set_sumeragi(consensus);
        }
        let error = ValidBlock::validate_native_genesis_policy(genesis, &staged)
            .expect_err("the final executed policy must preserve the combined CT5 margin");
        assert!(
            matches!(error, BlockValidationError::ExecutionContextInvalid(ref reason) if reason.contains("due_work_max_lag_ms")),
            "{error}"
        );
        let expected = format!(
            "due_work_max_lag_ms {below_minimum} is below the committed minimum {minimum_lag}"
        );
        assert!(
            matches!(error, BlockValidationError::ExecutionContextInvalid(ref reason) if reason == &expected),
            "{error}"
        );
        assert_eq!(prepared.state.committed_height(), 0);
        assert_eq!(prepared.kura.exact_durable_blocks_count().unwrap(), 0);
        staged
            .world
            .parameters
            .get_mut()
            .set_sumeragi(original_clock);
        ValidBlock::validate_native_genesis_policy(genesis, &staged)
            .expect("the exact original signed execution remains valid after the negative probe");
        assert_eq!(prepared.state.committed_height(), 0);
        assert_eq!(prepared.kura.exact_durable_blocks_count().unwrap(), 0);
    }
    #[test]
    fn native_h1_rejects_missing_or_duplicate_original_root_fee_slots() {
        use crate::sumeragi::{network_topology::Topology, test_chain::CertifiedTestChain};
        use iroha_data_model::{
            block::consensus::{RootFeePolicy, SumeragiRootScope},
            isi::SetParameter,
            parameter::Parameter,
            transaction::{Executable, FeePaymentIntent, TransactionBuilder},
        };
        use iroha_primitives::time::TimeSource;
        use std::sync::Arc;

        for copies in [0_usize, 2] {
            let config = explicit_staking_config();
            let key = config.genesis_key.clone();
            let authority = AccountId::new(key.public_key().clone());
            let mut prepared = CertifiedTestChain::prepare(config).unwrap();
            let original = prepared.genesis.block();
            let topology = Topology::new(
                prepared
                    .validator_keys
                    .iter()
                    .map(|key| PeerId::new(key.public_key().clone())),
            );
            let transactions = original
                .external_transactions()
                .map(|transaction| {
                    let Executable::Instructions(instructions) = transaction.instructions() else {
                        panic!("original native genesis has instruction batches")
                    };
                    let instructions = instructions
                        .iter()
                        .flat_map(|instruction| {
                            let is_fee = instruction
                                .as_any()
                                .downcast_ref::<SetParameter>()
                                .is_some_and(|set| {
                                    matches!(set.inner(), Parameter::Custom(custom)
                            if custom.id() == &RootFeePolicy::parameter_id())
                                });
                            std::iter::repeat_n(
                                instruction.clone(),
                                if is_fee { copies } else { 1 },
                            )
                        })
                        .collect::<Vec<_>>();
                    let mut builder = TransactionBuilder::new_genesis(
                        authority.clone(),
                        FeePaymentIntent::authority(Vec::new(), None),
                    )
                    .with_instructions(instructions)
                    .with_metadata(transaction.metadata().clone());
                    builder.set_creation_time(transaction.creation_time());
                    builder.try_sign(key.private_key()).unwrap()
                })
                .collect();
            let malformed = SignedBlock::try_genesis_with_da_proof_policies(
                transactions,
                key.private_key(),
                None,
                None,
                None,
            )
            .unwrap();
            iroha_data_model::sumeragi_finality::authenticated_genesis(&malformed)
                .expect("the malformed policy inventory retains genuine original signatures");
            // A fresh bootstrap State belongs to this exact signed H1 identity. It has
            // no committed effects, and every original instruction still executes below.
            Arc::get_mut(&mut prepared.state).unwrap().network_id =
                iroha_data_model::NetworkId::from_genesis_hash(malformed.hash());
            let result = ValidBlock::validate_signed_genesis(
                malformed,
                &topology,
                &authority,
                &TimeSource::new_system(),
                &prepared.state,
                iroha_data_model::parameter::system::ConsensusMode::Permissioned,
                SumeragiRootScope::Global,
            )
            .unpack(|_| {});
            let error = match result {
                Ok(_) => {
                    panic!("native H1 must refuse missing or duplicate original root fee slots")
                }
                Err((_, error)) => error,
            };
            let expected = if copies == 0 {
                "signed genesis omits its root fee policy"
            } else {
                "signed genesis must execute exactly one original root fee policy"
            };
            assert!(
                matches!(*error, BlockValidationError::ExecutionContextInvalid(ref reason)
                if reason == expected),
                "unexpected native rejection: {error}"
            );
            assert_eq!(prepared.state.committed_height(), 0);
            assert_eq!(prepared.kura.exact_durable_blocks_count().unwrap(), 0);
        }
    }
}
