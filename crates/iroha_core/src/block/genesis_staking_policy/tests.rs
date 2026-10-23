//! Actual configured-root genesis selection and unpublished original-State controls.

use super::*;
use crate::{
    block::authenticate_genesis_block_intents,
    state::{State, StateBlockStartError, World},
};
use iroha_data_model::{
    isi::{InstructionBox, Log},
    prelude::*,
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use iroha_test_samples::{SAMPLE_GENESIS_ACCOUNT_ID, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};

fn policy(minimum: u64) -> PublicLaneStakingPolicy {
    PublicLaneStakingPolicy {
        min_validator_stake: minimum.into(),
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
    }
}

fn parameter(minimum: u64) -> Parameter {
    Parameter::Custom(policy(minimum).into_custom_parameter().unwrap())
}

fn instruction(minimum: u64) -> InstructionBox {
    SetParameter::new(parameter(minimum)).into()
}

fn source(batches: Vec<Vec<InstructionBox>>) -> SignedBlock {
    let transactions = batches
        .into_iter()
        .map(|instructions| {
            TransactionBuilder::new_genesis(
                SAMPLE_GENESIS_ACCOUNT_ID.clone(),
                FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions(instructions)
            .sign(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key())
        })
        .collect();
    SignedBlock::genesis(
        transactions,
        SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key(),
        None,
        None,
    )
    .canonical_resultless_proposal()
    .unwrap()
}

fn state() -> State {
    State::new_for_testing(
        World::new(),
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    )
}

fn assert_original_zero_refusal(owner: crate::execution_attempt::ExecutionDeferred) {
    let original = owner
        .decode_refusal()
        .expect("original scoped staking decoder refusal")
        .clone();
    assert_eq!(
        original.kind(),
        norito::core::DecodeLocalRefusalKind::EnclosingLimit
    );
    assert!(matches!(
        original.resource_error(),
        norito::core::DecodeResourceError::TotalAllocationExceeded {
            attempted,
            limit: 0,
        } if attempted > 0
    ));
    assert!(owner.allocation_refusal().is_none());
    let restored =
        crate::execution_attempt::ExecutionDeferred::try_from_vm_error(owner.into_vm_error())
            .unwrap();
    assert_eq!(restored.decode_refusal(), Some(&original));
}

#[test]
fn configured_root_selects_staking_policy_from_later_input() {
    let block = source(vec![
        vec![Log::new(Level::INFO, "before policy".into()).into()],
        vec![instruction(2_000)],
    ]);
    let original = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    let initial = original.initial_staking_policy(&block).unwrap();
    assert_eq!(initial.coordinate, (1, 0));
    assert_eq!(initial.policy, policy(2_000));
    assert_ne!(initial.policy, policy(1_000));
    for transaction in block.external_transactions() {
        crate::tx::AcceptedTransaction::validate_genesis_with_now(
            transaction,
            std::time::Duration::from_secs(1),
            &SAMPLE_GENESIS_ACCOUNT_ID,
            block.header().creation_time(),
        )
        .unwrap();
    }
}

#[test]
fn initial_policy_rejects_missing_and_equal_or_conflicting_duplicates_across_all_inputs() {
    for batches in [
        vec![vec![Log::new(Level::INFO, "missing".into()).into()]],
        vec![vec![instruction(1_000), instruction(1_000)]],
        vec![vec![instruction(1_000)], vec![instruction(1_000)]],
        vec![vec![instruction(1_000)], vec![instruction(2_000)]],
    ] {
        let block = source(batches);
        let original =
            authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
        assert!(matches!(
            original.initial_staking_policy(&block),
            Err(BlockValidationError::InvalidGenesis(
                InvalidGenesisError::StakingPolicy(_)
            ))
        ));
    }
}

#[test]
fn policy_capability_cannot_switch_original_source_or_configured_root() {
    let block = source(vec![vec![instruction(1_000)]]);
    let other = source(vec![vec![instruction(2_000)]]);
    let original = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    assert!(original.initial_staking_policy(&other).is_err());
    assert!(authenticate_genesis_block_intents(&block, &iroha_test_samples::ALICE_ID).is_err());
}

#[test]
fn initial_policy_decoder_refusal_retains_original_and_retries_same_source() {
    let block = source(vec![vec![instruction(1_000)]]);
    let original = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    let before = block.canonical_wire().unwrap();
    let zero = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        0,
        usize::MAX,
    ));
    let error = zero
        .with(|| original.initial_staking_policy(&block))
        .unwrap_err();
    let BlockValidationError::ExecutionDeferred(original_error) = error else {
        panic!("original decoder refusal required")
    };
    assert_original_zero_refusal(original_error);
    assert_eq!(
        block.canonical_wire().unwrap().as_framed(),
        before.as_framed()
    );
    let retry = original.initial_staking_policy(&block).unwrap();
    assert_eq!(retry.policy, policy(1_000));
}

#[test]
fn pristine_initialization_is_recorded_and_failed_bootstrap_leaves_full_original_state_unchanged() {
    let state = state();
    let block = source(vec![vec![instruction(1_000)]]);
    let original = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    let mut initial = Some(original.initial_staking_policy(&block).unwrap());
    let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
    let generation = state.state_view_generation();
    let result = state.block_with_recorded_pristine_carrier_stage(
        &block,
        |overlay| {
            GenesisStakingPolicy::install(&mut initial, &block, overlay, &state, generation)?;
            overlay.require_original_execution_recorder().unwrap();
            assert!(initial.is_none());
            assert!(overlay.genesis_staking_policy.is_some());
            assert_eq!(
                overlay.transaction().staking_monetary_policy().unwrap(),
                &policy(1_000)
            );
            assert_eq!(
                overlay.world.parameters.get().staking_policy(),
                Some(&policy(1_000))
            );
            overlay
                .genesis_staking_policy
                .as_ref()
                .unwrap()
                .require_unchanged(overlay)?;
            // A failed later bootstrap step cannot publish this already initialized overlay.
            Err::<(), BlockValidationError>(invalid("deliberate later bootstrap refusal"))
        },
        invalid,
    );
    assert!(matches!(
        result,
        Err(StateBlockStartError::Stage(
            BlockValidationError::InvalidGenesis(InvalidGenesisError::StakingPolicy(_))
        ))
    ));
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(&state),
        before
    );
    assert_eq!(state.state_view_generation(), generation);
    assert!(
        state
            .world
            .view()
            .transaction_admission_parameters()
            .staking_policy()
            .is_none()
    );
}

#[test]
fn installation_decoder_refusal_keeps_original_state_and_changed_overlay_cannot_finalize() {
    let state = state();
    let block = source(vec![vec![instruction(1_000)]]);
    let original = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    let mut initial = Some(original.initial_staking_policy(&block).unwrap());
    let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
    let generation = state.state_view_generation();
    let zero = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        0,
        usize::MAX,
    ));
    let result = state.block_with_recorded_pristine_carrier_stage(
        &block,
        |overlay| {
            let error = zero
                .with(|| {
                    GenesisStakingPolicy::install(&mut initial, &block, overlay, &state, generation)
                })
                .unwrap_err();
            let BlockValidationError::ExecutionDeferred(original_error) = error else {
                panic!("original initialization decoder refusal required")
            };
            assert_original_zero_refusal(original_error);
            assert!(overlay.world.parameters.get().staking_policy().is_none());
            assert!(initial.is_some());
            assert!(overlay.genesis_staking_policy.is_none());
            GenesisStakingPolicy::install(&mut initial, &block, overlay, &state, generation)?;
            overlay
                .world
                .parameters
                .get_mut()
                .set_parameter(parameter(2_000))
                .unwrap();
            assert!(overlay.transaction().staking_monetary_policy().is_err());
            {
                let transaction = overlay.transaction();
                assert!(transaction.staking_monetary_policy().is_err());
            }
            overlay
                .genesis_staking_policy
                .as_ref()
                .unwrap()
                .require_unchanged(overlay)
        },
        invalid,
    );
    assert!(matches!(
        result,
        Err(StateBlockStartError::Stage(
            BlockValidationError::InvalidGenesis(InvalidGenesisError::StakingPolicy(_))
        ))
    ));
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(&state),
        before
    );
    assert_eq!(state.state_view_generation(), generation);
}

#[test]
fn initial_policy_installation_rejects_another_owner_generation_and_source_without_effects() {
    let different_state = state();
    let state = state();
    let block = source(vec![vec![instruction(1_000)]]);
    let different_source = source(vec![vec![instruction(2_000)]]);
    let original = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    let mut initial = Some(original.initial_staking_policy(&block).unwrap());
    let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
    let generation = state.state_view_generation();
    let result = state.block_with_recorded_pristine_carrier_stage(
        &block,
        |overlay| {
            assert!(
                GenesisStakingPolicy::install(
                    &mut initial,
                    &block,
                    overlay,
                    &different_state,
                    generation
                )
                .is_err()
            );
            assert!(
                GenesisStakingPolicy::install(
                    &mut initial,
                    &block,
                    overlay,
                    &state,
                    generation + 1
                )
                .is_err()
            );
            assert!(
                GenesisStakingPolicy::install(
                    &mut initial,
                    &different_source,
                    overlay,
                    &state,
                    generation
                )
                .is_err()
            );
            assert!(overlay.world.parameters.get().staking_policy().is_none());
            assert!(initial.is_some());
            assert!(overlay.genesis_staking_policy.is_none());
            GenesisStakingPolicy::install(&mut initial, &block, overlay, &state, generation)?;
            overlay
                .genesis_staking_policy
                .as_ref()
                .unwrap()
                .require_unchanged(overlay)?;
            Err::<(), BlockValidationError>(invalid("end unpublished ownership control"))
        },
        invalid,
    );
    assert!(matches!(result, Err(StateBlockStartError::Stage(_))));
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(&state),
        before
    );
}

#[test]
fn actual_genesis_parameter_instruction_only_repeats_the_authenticated_initial_policy() {
    use crate::smartcontracts::Execute as _;
    let state = state();
    let block = source(vec![vec![instruction(1_000)]]);
    let original = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    let mut initial = Some(original.initial_staking_policy(&block).unwrap());
    let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
    let generation = state.state_view_generation();
    let result = state.block_with_recorded_pristine_carrier_stage(
        &block,
        |overlay| {
            GenesisStakingPolicy::install(&mut initial, &block, overlay, &state, generation)?;
            {
                let mut transaction = overlay.transaction();
                assert_eq!(
                    transaction.staking_monetary_policy().unwrap(),
                    &policy(1_000)
                );
                let parameters_before = transaction.world.parameters.get().clone();
                let changed = SetParameter::new(parameter(2_000));
                assert!(
                    changed
                        .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut transaction)
                        .is_err()
                );
                assert_eq!(transaction.world.parameters.get(), &parameters_before);
                let same = SetParameter::new(parameter(1_000));
                same.execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut transaction)
                    .unwrap();
                assert_eq!(
                    transaction.world.parameters.get().staking_policy(),
                    Some(&policy(1_000))
                );
                // This is an unpublished instruction boundary control; dropping the
                // transaction also rolls back its configuration event.
            }
            overlay
                .genesis_staking_policy
                .as_ref()
                .unwrap()
                .require_unchanged(overlay)?;
            Err::<(), BlockValidationError>(invalid("end unpublished instruction control"))
        },
        invalid,
    );
    assert!(matches!(result, Err(StateBlockStartError::Stage(_))));
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(&state),
        before
    );
}

#[test]
fn installation_rejects_changed_nonpolicy_body_and_da_with_same_original_header() {
    let block = source(vec![vec![
        instruction(1_000),
        Log::new(Level::INFO, "original non-policy input".into()).into(),
    ]]);
    let original = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    let mut changed_body = source(vec![vec![
        instruction(1_000),
        Log::new(Level::INFO, "substituted non-policy input".into()).into(),
    ]]);
    changed_body.replace_header_for_testing(block.header());
    let mut changed_da = block.clone();
    changed_da.set_da_proof_policies(Some(
        iroha_data_model::da::commitment::DaProofPolicyBundle::new(Vec::new()),
    ));
    changed_da.replace_header_for_testing(block.header());
    for substituted in [changed_body, changed_da] {
        let mut initial = Some(original.initial_staking_policy(&block).unwrap());
        assert_eq!(substituted.header(), block.header());
        assert!(substituted.validate_proposal_commitments().is_err());
        let state = state();
        let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
        let generation = state.state_view_generation();
        let result = state.block_with_recorded_pristine_carrier_stage(
            &block,
            |overlay| {
                let error = GenesisStakingPolicy::install(
                    &mut initial,
                    &substituted,
                    overlay,
                    &state,
                    generation,
                )
                .unwrap_err();
                assert!(matches!(
                    error,
                    BlockValidationError::InvalidGenesis(InvalidGenesisError::StakingPolicy(_))
                ));
                assert!(overlay.world.parameters.get().staking_policy().is_none());
                GenesisStakingPolicy::install(&mut initial, &block, overlay, &state, generation)?;
                overlay
                    .genesis_staking_policy
                    .as_ref()
                    .unwrap()
                    .require_unchanged(overlay)?;
                Err::<(), BlockValidationError>(invalid(
                    "end unpublished source substitution control",
                ))
            },
            invalid,
        );
        assert!(matches!(result, Err(StateBlockStartError::Stage(_))));
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_bytes(&state),
            before
        );
        assert_eq!(state.state_view_generation(), generation);
    }
}

#[test]
fn header_and_unpublished_current_policy_cannot_replace_retained_genesis_authority() {
    use crate::smartcontracts::Execute as _;
    let state = state();
    let block = source(vec![vec![instruction(1_000)]]);
    let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
    {
        let mut overlay = state.block(block.header());
        overlay
            .world
            .parameters
            .get_mut()
            .set_parameter(parameter(1_000))
            .unwrap();
        assert!(overlay.genesis_staking_policy.is_none());
        assert!(overlay.world.parameters.get().staking_policy().is_some());
        assert!(overlay.transaction().staking_monetary_policy().is_err());
        let mut transaction = overlay.transaction();
        assert!(transaction.staking_monetary_policy().is_err());
        let before = transaction.world.parameters.get().clone();
        // Even an equal current value cannot manufacture the source capability.
        assert!(
            SetParameter::new(parameter(1_000))
                .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut transaction)
                .is_err()
        );
        assert_eq!(transaction.world.parameters.get(), &before);
    }
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(&state),
        before
    );
}

#[test]
fn selected_staking_policy_rejects_wrong_identity_and_malformed_payload_as_invalidity() {
    for parameter in [
        CustomParameter::new(
            "different_policy".parse().unwrap(),
            policy(1_000)
                .into_custom_parameter()
                .unwrap()
                .payload()
                .clone(),
        ),
        CustomParameter::new(
            PublicLaneStakingPolicy::parameter_id(),
            iroha_primitives::json::Json::try_new(norito::json!({})).unwrap(),
        ),
    ] {
        let block = source(vec![vec![
            SetParameter::new(Parameter::Custom(parameter)).into(),
        ]]);
        let original =
            authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
        assert!(matches!(
            original.initial_staking_policy(&block),
            Err(BlockValidationError::InvalidGenesis(
                InvalidGenesisError::StakingPolicy(_)
            ))
        ));
    }
}

#[test]
fn authenticated_staking_reader_borrows_installed_owner_under_zero_decode_budget() {
    let state = state();
    let block = source(vec![vec![instruction(1_000)]]);
    let original = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    let mut initial = Some(original.initial_staking_policy(&block).unwrap());
    let generation = state.state_view_generation();
    let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
    let result = state.block_with_recorded_pristine_carrier_stage(
        &block,
        |overlay| {
            GenesisStakingPolicy::install(&mut initial, &block, overlay, &state, generation)?;
            let tx = overlay.transaction();
            let expected = tx.world.parameters.get().staking_policy().unwrap();
            let zero = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
                usize::MAX,
                usize::MAX,
                usize::MAX,
                0,
                usize::MAX,
            ));
            zero.with(|| {
                assert!(std::ptr::eq(
                    tx.staking_monetary_policy().unwrap(),
                    expected
                ));
                assert_eq!(
                    tx.staking_monetary_policy().unwrap().min_validator_stake,
                    1_000_u64.into()
                );
                assert_eq!(zero.consumed_allocated_bytes(), 0);
            });
            drop(tx);
            Err::<(), BlockValidationError>(invalid("unpublished borrowing control"))
        },
        invalid,
    );
    assert!(matches!(result, Err(StateBlockStartError::Stage(_))));
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(&state),
        before
    );
}

fn combined_source() -> SignedBlock {
    let crypto = iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
        iroha_crypto::Algorithm::Ed25519,
    ])
    .unwrap()
    .into_parameter()
    .unwrap();
    source(vec![vec![
        SetParameter::new(crypto).into(),
        instruction(1_000),
    ]])
}

#[test]
fn production_combined_bootstrap_installs_crypto_and_staking_at_one_pristine_cut() {
    use crate::{block::genesis_policies::GenesisPolicies, smartcontracts::Execute as _};
    let state = state();
    let block = combined_source();
    let source = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    let mut initial = Some(source.initial_policies(&block).unwrap());
    let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
    let generation = state.state_view_generation();
    let result = state.block_with_recorded_pristine_carrier_stage(
        &block,
        |overlay| {
            // This is the exact combined call used by state_block_for_execution.
            GenesisPolicies::install(&mut initial, &block, overlay, &state, generation)?;
            assert!(initial.is_none());
            assert!(overlay.genesis_crypto_policy.is_some());
            assert!(overlay.genesis_staking_policy.is_some());
            let mut transaction = overlay.transaction();
            assert!(
                transaction
                    .crypto_admission_policy()
                    .unwrap()
                    .allows(iroha_crypto::Algorithm::Ed25519)
            );
            assert_eq!(
                transaction.staking_monetary_policy().unwrap(),
                &policy(1_000)
            );
            for input in block.external_transactions() {
                let Executable::Instructions(instructions) = input.instructions() else {
                    panic!("explicit original instructions");
                };
                for instruction in instructions.iter() {
                    instruction
                        .as_any()
                        .downcast_ref::<SetParameter>()
                        .unwrap()
                        .clone()
                        .execute(&SAMPLE_GENESIS_ACCOUNT_ID, &mut transaction)
                        .unwrap();
                }
            }
            drop(transaction);
            overlay
                .genesis_crypto_policy
                .as_ref()
                .unwrap()
                .require_unchanged(overlay)?;
            overlay
                .genesis_staking_policy
                .as_ref()
                .unwrap()
                .require_unchanged(overlay)?;
            Err::<(), BlockValidationError>(invalid("unpublished combined bootstrap control"))
        },
        invalid,
    );
    assert!(matches!(result, Err(StateBlockStartError::Stage(_))));
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(&state),
        before
    );
    assert_eq!(state.state_view_generation(), generation);
}

#[test]
fn second_policy_decoder_refusal_keeps_both_original_capabilities_and_pristine_state_for_retry() {
    use crate::block::genesis_policies::GenesisPolicies;
    let state = state();
    let block = combined_source();
    let source = authenticate_genesis_block_intents(&block, &SAMPLE_GENESIS_ACCOUNT_ID).unwrap();
    let mut initial = Some(source.initial_policies(&block).unwrap());
    let crypto = source.initial_crypto_policy(&block).unwrap();
    let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
    let generation = state.state_view_generation();
    let result = state.block_with_recorded_pristine_carrier_stage(
        &block,
        |overlay| {
            let warm = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
                usize::MAX,
                usize::MAX,
                usize::MAX,
                usize::MAX,
                usize::MAX,
            ));
            let mut scratch = overlay.world.parameters.get().clone();
            warm.with(|| crypto.initialize_candidate(&mut scratch))
                .unwrap();
            assert!(scratch.crypto_policy().is_some());
            assert!(scratch.staking_policy().is_none());
            let crypto_bytes = warm.consumed_allocated_bytes();
            assert!(crypto_bytes > 0);
            drop(scratch);
            let bounded = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
                usize::MAX,
                usize::MAX,
                usize::MAX,
                usize::try_from(crypto_bytes).unwrap(),
                usize::MAX,
            ));
            let error = bounded
                .with(|| {
                    GenesisPolicies::install(&mut initial, &block, overlay, &state, generation)
                })
                .unwrap_err();
            let BlockValidationError::ExecutionDeferred(owner) = error else {
                panic!("actual original second-policy decoder refusal required")
            };
            let cause = owner.decode_refusal().unwrap().clone();
            assert_eq!(
                cause.kind(),
                norito::core::DecodeLocalRefusalKind::EnclosingLimit
            );
            assert!(matches!(
                cause.resource_error(),
                norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit }
                    if limit == crypto_bytes && attempted > limit
            ));
            let moved = crate::execution_attempt::ExecutionDeferred::try_from_vm_error(
                owner.into_vm_error(),
            )
            .unwrap();
            assert_eq!(moved.decode_refusal(), Some(&cause));
            assert!(initial.is_some());
            assert!(overlay.genesis_crypto_policy.is_none());
            assert!(overlay.genesis_staking_policy.is_none());
            assert!(overlay.world.parameters.get().crypto_policy().is_none());
            assert!(overlay.world.parameters.get().staking_policy().is_none());
            // This production invariant still rejects every dirty overlay. Passing
            // it here proves the failed first candidate was never installed.
            overlay
                .validate_native_pristine_control_owner(&state, generation, &block.header())
                .unwrap();
            GenesisPolicies::install(&mut initial, &block, overlay, &state, generation)?;
            assert!(initial.is_none());
            assert_eq!(
                overlay.transaction().staking_monetary_policy().unwrap(),
                &policy(1_000)
            );
            Err::<(), BlockValidationError>(invalid("unpublished combined retry control"))
        },
        invalid,
    );
    assert!(matches!(result, Err(StateBlockStartError::Stage(_))));
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(&state),
        before
    );
    assert_eq!(state.state_view_generation(), generation);
}
