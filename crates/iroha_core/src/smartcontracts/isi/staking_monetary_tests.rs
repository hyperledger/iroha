// Mandatory signed monetary bindings and bounded non-forfeiting claims.
#[test]
fn monetary_plan_context_binds_genesis_network_and_governed_expiry() {
    let mut state = setup_state();
    set_epoch_length(&mut state, 6);
    let mut block = state.block(block_header_with_height(2));
    let stx = block.transaction_for_callback_testing();
    let network = PublicLaneMonetaryScopeV1::Network(*stx.network_id());
    for expiry in [2, 8] {
        effects::validate_plan_context(&stx, &network, expiry).unwrap();
    }
    for expiry in [0, 1, 9] {
        assert!(effects::validate_plan_context(&stx, &network, expiry).is_err());
    }
    assert!(effects::validate_plan_context(&stx, &PublicLaneMonetaryScopeV1::Genesis, 2).is_err());
    let foreign =
        PublicLaneMonetaryScopeV1::Network(iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::from_untyped_unchecked(Hash::new(b"other network")),
        ));
    assert!(effects::validate_plan_context(&stx, &foreign, 2).is_err());
    drop(stx);
    drop(block);
    let mut genesis = state.block(block_header_with_height(1));
    effects::validate_plan_context(
        &genesis.transaction_for_callback_testing(),
        &PublicLaneMonetaryScopeV1::Genesis,
        1,
    )
    .unwrap();
    drop(genesis);
    let mut overflow = state.block(block_header_with_height(u64::MAX));
    assert!(
        effects::validate_plan_context(
            &overflow.transaction_for_callback_testing(),
            &network,
            u64::MAX
        )
        .unwrap_err()
        .to_string()
        .contains("overflow")
    );
    let empty_state = State::new_with_nexus_for_testing(
        World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []),
        iroha_config::parameters::actual::Nexus::default(),
        LiveQueryStore::start_test(),
    );
    let mut empty_block = empty_state.block(block_header_with_height(1));
    let empty_transaction = empty_block.transaction_for_callback_testing();
    effects::validate_plan_context(&empty_transaction, &PublicLaneMonetaryScopeV1::Genesis, 1)
        .expect("genesis scope is exactly height-bound, independently of the election schedule");
    for expiry in [0, 2] {
        assert!(
            effects::validate_plan_context(
                &empty_transaction,
                &PublicLaneMonetaryScopeV1::Genesis,
                expiry
            )
            .is_err()
        );
    }
    // Actual monetary execution independently requires the committed XOR identity;
    // genesis scope never supplies a default or substitute currency.
    assert!(
        ensure_committed_xor_asset(
            &empty_transaction.world,
            &SumeragiNposParameters::default().xor_asset_definition_id
        )
        .is_err()
    );
}

#[test]
fn registration_monetary_plan_rejects_every_changed_effect_before_custody_writes() {
    let state = setup_state();
    let mut block = state.block(block_header_with_height(1));
    let mut stx = block.transaction_for_callback_testing();
    let (validator, delegator, escrow, definition) = prepare_accounts(&mut stx);
    let lane = LaneId::new(42);
    let base = RegisterPublicLaneValidator::new(
        lane,
        validator.clone(),
        validator_peer_id(&validator),
        validator.clone(),
        1_000_u64.into(),
        Metadata::default(),
        fixture_registration_plan(&stx, lane, &validator, &1_000_u64.into()),
    );
    let original = stx
        .world
        .assets
        .get(&AssetId::new(definition.clone(), validator.clone()))
        .cloned();
    for change in 0..5 {
        let mut instruction = base.clone();
        let plan = &mut instruction.monetary_plan;
        match change {
            0 => plan.source_asset = AssetId::new(definition.clone(), delegator.clone()),
            1 => plan.destination_asset = AssetId::new(definition.clone(), delegator.clone()),
            2 => plan.amount = 999_u64.into(),
            3 => {
                plan.precondition = PublicLaneMonetaryPreconditionV1::Registration(
                    iroha_data_model::nexus::PublicLaneMonetaryRegistrationV1 {
                        activation_height: 2,
                    },
                )
            }
            _ => plan.valid_until_height = 0,
        }
        assert!(
            instruction
                .execute(&validator, &mut stx)
                .unwrap_err()
                .to_string()
                .contains("monetary plan")
        );
        assert_eq!(
            stx.world
                .assets
                .get(&AssetId::new(definition.clone(), validator.clone())),
            original.as_ref()
        );
        assert!(
            stx.world
                .public_lane_stake_custody
                .get(&(lane, validator.clone()))
                .is_none()
        );
        assert!(
            stx.world
                .assets
                .get(&AssetId::new(definition.clone(), escrow.clone()))
                .is_none()
        );
    }
    base.execute(&validator, &mut stx).unwrap();
}

#[test]
fn staking_asset_resolution_requires_the_exact_committed_network_currency() {
    let state = setup_state();
    let mut block = state.block(block_header_with_height(1));
    let mut stx = block.transaction_for_callback_testing();
    let (validator, _, _, definition) = prepare_accounts(&mut stx);
    ensure_committed_xor_asset(&stx.world, &definition).unwrap();
    let other = AssetDefinitionId::derive_from_components(
        DomainId::try_new("nexus", "universal").unwrap(),
        "unrelated-currency".parse().unwrap(),
    );
    assert!(
        ensure_committed_xor_asset(&stx.world, &other)
            .unwrap_err()
            .to_string()
            .contains("committed network XOR")
    );
    let mut parameters = stx
        .world
        .sumeragi_npos_parameters()
        .expect("original policy decoder completes")
        .unwrap();
    parameters.xor_asset_definition_id = other;
    stx.world
        .parameters
        .get_mut()
        .set_parameter(Parameter::Custom(parameters.into_custom_parameter()));
    assert!(
        stake_context(
            &stx.world,
            &stx.nexus.dataspace_catalog,
            &stx.nexus.staking,
            &validator,
            stx.block_unix_timestamp_ms()
        )
        .is_err()
    );
    let world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
    assert!(
        ensure_committed_xor_asset(&world.view(), &definition)
            .unwrap_err()
            .to_string()
            .contains("committed network XOR")
    );
}

#[test]
fn staking_registration_rejects_wrong_xor_shape_with_transaction_rollback() {
    use iroha_data_model::asset::AssetBalancePolicy;
    use iroha_primitives::numeric::NumericSpec;
    for (spec, scope) in [
        (NumericSpec::default(), AssetBalancePolicy::Global),
        (NumericSpec::fractional(18), AssetBalancePolicy::Global),
        (
            NumericSpec::fractional(9),
            AssetBalancePolicy::DataspaceRestricted,
        ),
    ] {
        let state = setup_state();
        let mut block = state.block(block_header_with_height(1));
        let (validator, definition, nexus, registration, source, before) = {
            let mut stx = block.transaction_for_callback_testing();
            let (validator, _, _, definition) = prepare_accounts(&mut stx);
            let amount = Quantity::from(1_000_u64);
            let registration = RegisterPublicLaneValidator {
                lane_id: LaneId::new(42),
                validator: validator.clone(),
                peer_id: validator_peer_id(&validator),
                stake_account: validator.clone(),
                initial_stake: amount.clone(),
                metadata: Metadata::default(),
                monetary_plan: fixture_registration_plan(&stx, LaneId::new(42), &validator, amount),
            };
            let source = AssetId::new(definition.clone(), validator.clone());
            let before = stx.world.assets.get(&source).unwrap().clone();
            let nexus = stx.nexus.clone();
            stx.apply();
            (validator, definition, nexus, registration, source, before)
        };
        {
            let mut rejected = block.transaction_for_callback_testing();
            rejected.nexus = nexus.clone();
            let currency = rejected
                .world
                .asset_definitions
                .get_mut(&definition)
                .unwrap();
            currency.spec = spec;
            currency.balance_scope_policy = scope;
            let error = registration
                .clone()
                .execute(&validator, &mut rejected)
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("global network XOR with scale nine"),
                "{error}"
            );
            assert_eq!(rejected.world.assets.get(&source), Some(&before));
            assert!(
                rejected
                    .world
                    .public_lane_stake_custody
                    .iter()
                    .next()
                    .is_none()
            );
            assert!(
                rejected
                    .world
                    .public_lane_stake_reserves
                    .iter()
                    .next()
                    .is_none()
            );
            // Dropping the actual transaction also removes the malformed definition.
        }
        let mut accepted = block.transaction_for_callback_testing();
        accepted.nexus = nexus;
        assert_eq!(
            accepted
                .world
                .asset_definitions
                .get(&definition)
                .unwrap()
                .spec(),
            NumericSpec::fractional(9)
        );
        assert_eq!(accepted.world.assets.get(&source), Some(&before));
        registration.execute(&validator, &mut accepted).unwrap();
        assert_eq!(
            accepted
                .world
                .public_lane_stake_custody
                .get(&(LaneId::new(42), validator))
                .unwrap()
                .1,
            Quantity::from(1_000_u64)
        );
    }
}

#[test]
fn staking_configuration_and_reward_custody_reject_registered_xor_lookalike() {
    let state = setup_state();
    let mut block = state.block(block_header_with_height(1));
    let mut stx = block.transaction_for_callback_testing();
    let (validator, _, _, committed_xor) = prepare_accounts(&mut stx);
    let lookalike = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").unwrap(),
        "xor".parse().unwrap(),
    );
    assert_ne!(lookalike, committed_xor);
    Register::asset_definition(AssetDefinition::numeric(
        lookalike.clone(),
        "XOR".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    ))
    .execute(&ALICE_ID, &mut stx)
    .unwrap();
    // An existing numeric asset with the same public name still has no network-currency
    // authority. Staking and funded reward custody both require the committed identity.
    for configured in [&committed_xor, &lookalike] {
        stx.nexus.staking.stake_asset_id = configured.to_string();
        stx.nexus.fees.fee_asset_id = configured.to_string();
        let stake = stake_context(
            &stx.world,
            &stx.nexus.dataspace_catalog,
            &stx.nexus.staking,
            &validator,
            stx.block_unix_timestamp_ms(),
        );
        let rewards = crate::state::validate_network_xor_asset(&stx.world, configured);
        if configured == &committed_xor {
            assert_eq!(stake.unwrap().asset_definition, committed_xor);
            rewards.unwrap();
        } else {
            for error in [
                crate::execution_attempt::expect_completed_rejection(stake.unwrap_err()),
                crate::execution_attempt::expect_completed_rejection(rewards.unwrap_err()),
            ] {
                assert!(error.to_string().contains("committed network XOR"));
            }
        }
        assert_eq!(
            stx.world
                .sumeragi_npos_parameters()
                .expect("original policy decoder completes")
                .unwrap()
                .xor_asset_definition_id,
            committed_xor,
        );
    }
}

#[test]
fn final_unbond_rejects_changed_signed_request_without_releasing_custody() {
    let state = setup_state();
    let lane = LaneId::new(42);
    let request_id = Hash::new(b"signed-unbond-preimage");
    let (validator, request, nexus) = {
        let mut block = state.block(block_header_with_height(1));
        let mut stx = block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        stx.nexus.staking.unbonding_delay = Duration::ZERO;
        RegisterPublicLaneValidator::new(
            lane,
            validator.clone(),
            validator_peer_id(&validator),
            validator.clone(),
            1_000_u64.into(),
            Metadata::default(),
            fixture_registration_plan(&stx, lane, &validator, &1_000_u64.into()),
        )
        .execute(&validator, &mut stx)
        .unwrap();
        SchedulePublicLaneUnbond {
            lane_id: lane,
            validator: validator.clone(),
            staker: validator.clone(),
            request_id,
            amount: 100_u64.into(),
            release_at_ms: stx.block_unix_timestamp_ms(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        let request = stx
            .world
            .public_lane_stake_shares
            .get(&stake_key(lane, &validator, &validator))
            .unwrap()
            .pending_unbonds[&request_id]
            .clone();
        let nexus = stx.nexus.clone();
        stx.apply();
        block.commit_world_overlay_for_testing().unwrap();
        (validator, request, nexus)
    };
    let block =
        new_block_with_height_and_time(request.liability_release_height, request.release_at_ms);
    let mut state_block = state.block(block.as_ref().header());
    let mut stx = state_block.transaction_for_fastpq_testing(Hash::prehashed([0xE3; Hash::LENGTH]));
    stx.nexus = nexus;
    let good = fixture_unbond_plan(&stx, lane, &validator, &validator, &request_id);
    let reserve_before = stx
        .world
        .public_lane_stake_reserves
        .get(&good.source_asset)
        .cloned();
    let balances_before = (
        stx.world.assets.get(&good.source_asset).cloned(),
        stx.world.assets.get(&good.destination_asset).cloned(),
    );
    let mut wrong = good.clone();
    wrong.precondition = PublicLaneMonetaryPreconditionV1::Unbond(
        iroha_data_model::nexus::PublicLaneMonetaryUnbondV1 {
            activation_height: 1,
            request_hash: Hash::new(b"different request state"),
        },
    );
    let instruction = FinalizePublicLaneUnbond {
        lane_id: lane,
        validator: validator.clone(),
        staker: validator.clone(),
        request_id,
        monetary_plan: wrong,
    };
    assert!(
        instruction
            .execute(&validator, &mut stx)
            .unwrap_err()
            .to_string()
            .contains("monetary plan")
    );
    assert_eq!(
        stx.world.public_lane_stake_reserves.get(&good.source_asset),
        reserve_before.as_ref()
    );
    assert_eq!(
        (
            stx.world.assets.get(&good.source_asset).cloned(),
            stx.world.assets.get(&good.destination_asset).cloned()
        ),
        balances_before
    );
    assert_eq!(
        stx.world
            .public_lane_stake_shares
            .get(&stake_key(lane, &validator, &validator))
            .unwrap()
            .pending_unbonds[&request_id],
        request
    );
    FinalizePublicLaneUnbond {
        lane_id: lane,
        validator: validator.clone(),
        staker: validator.clone(),
        request_id,
        monetary_plan: good,
    }
    .execute(&validator, &mut stx)
    .unwrap();
}

#[test]
fn final_unbond_rejects_mismatched_share_identity_and_rolls_back_transaction() {
    let state = setup_state();
    let lane = LaneId::new(42);
    let request_id = Hash::new(b"unbond-share-identity");
    let (validator, delegator, request, nexus) = {
        let mut block = state.block(block_header_with_height(1));
        let mut stx = block.transaction_for_callback_testing();
        let (validator, delegator, _, _) = prepare_accounts(&mut stx);
        stx.nexus.staking.unbonding_delay = Duration::ZERO;
        RegisterPublicLaneValidator::new(
            lane,
            validator.clone(),
            validator_peer_id(&validator),
            validator.clone(),
            1_000_u64.into(),
            Metadata::default(),
            fixture_registration_plan(&stx, lane, &validator, &1_000_u64.into()),
        )
        .execute(&validator, &mut stx)
        .unwrap();
        SchedulePublicLaneUnbond {
            lane_id: lane,
            validator: validator.clone(),
            staker: validator.clone(),
            request_id,
            amount: 100_u64.into(),
            release_at_ms: stx.block_unix_timestamp_ms(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        let request = stx
            .world
            .public_lane_stake_shares
            .get(&stake_key(lane, &validator, &validator))
            .unwrap()
            .pending_unbonds[&request_id]
            .clone();
        let nexus = stx.nexus.clone();
        stx.apply();
        block.commit_world_overlay_for_testing().unwrap();
        (validator, delegator, request, nexus)
    };
    let block =
        new_block_with_height_and_time(request.liability_release_height, request.release_at_ms);
    let mut state_block = state.block(block.as_ref().header());
    let share_key = stake_key(lane, &validator, &validator);
    let validator_key = validator_storage_key(lane, &validator);
    let (plan, share_before, validator_before, custody_before, reserve_before, balances_before) = {
        let mut stx = state_block.transaction_for_callback_testing();
        stx.nexus = nexus.clone();
        let plan = fixture_unbond_plan(&stx, lane, &validator, &validator, &request_id);
        let balances = (
            stx.world.assets.get(&plan.source_asset).cloned(),
            stx.world.assets.get(&plan.destination_asset).cloned(),
        );
        (
            plan.clone(),
            stx.world
                .public_lane_stake_shares
                .get(&share_key)
                .unwrap()
                .clone(),
            stx.world
                .public_lane_validators
                .get(&validator_key)
                .cloned(),
            stx.world
                .public_lane_stake_custody
                .get(&validator_key)
                .cloned(),
            stx.world
                .public_lane_stake_reserves
                .get(&plan.source_asset)
                .cloned(),
            balances,
        )
    };
    for changed_identity in 0..3 {
        let mut stx =
            state_block.transaction_for_fastpq_testing(Hash::prehashed([0xE4; Hash::LENGTH]));
        stx.nexus = nexus.clone();
        let mut malformed = share_before.clone();
        match changed_identity {
            0 => malformed.lane_id = LaneId::new(43),
            1 => malformed.validator = delegator.clone(),
            _ => malformed.staker = delegator.clone(),
        }
        stx.world
            .public_lane_stake_shares
            .insert(share_key.clone(), malformed.clone());
        let error = FinalizePublicLaneUnbond {
            lane_id: lane,
            validator: validator.clone(),
            staker: validator.clone(),
            request_id,
            monetary_plan: plan.clone(),
        }
        .execute(&validator, &mut stx)
        .expect_err("a different share identity cannot authorize a withdrawal");
        assert!(
            error
                .to_string()
                .contains("stake share does not match its storage key")
        );
        assert_eq!(
            stx.world.public_lane_stake_shares.get(&share_key),
            Some(&malformed)
        );
        assert_eq!(
            stx.world.public_lane_stake_custody.get(&validator_key),
            custody_before.as_ref()
        );
        assert_eq!(
            stx.world.public_lane_stake_reserves.get(&plan.source_asset),
            reserve_before.as_ref()
        );
        assert_eq!(
            (
                stx.world.assets.get(&plan.source_asset).cloned(),
                stx.world.assets.get(&plan.destination_asset).cloned()
            ),
            balances_before,
        );
        // Reject the whole transaction, including any lifecycle work performed
        // before validation. Reopening it must recover the exact preimages.
        drop(stx);
        let reopened = state_block.transaction_for_callback_testing();
        assert_eq!(
            reopened.world.public_lane_stake_shares.get(&share_key),
            Some(&share_before)
        );
        assert_eq!(
            reopened.world.public_lane_validators.get(&validator_key),
            validator_before.as_ref()
        );
        assert_eq!(
            reopened.world.public_lane_stake_custody.get(&validator_key),
            custody_before.as_ref()
        );
        assert_eq!(
            reopened
                .world
                .public_lane_stake_reserves
                .get(&plan.source_asset),
            reserve_before.as_ref()
        );
        assert_eq!(
            (
                reopened.world.assets.get(&plan.source_asset).cloned(),
                reopened.world.assets.get(&plan.destination_asset).cloned()
            ),
            balances_before,
        );
    }

    let mut stx = state_block.transaction_for_fastpq_testing(Hash::prehashed([0xE5; Hash::LENGTH]));
    stx.nexus = nexus;
    FinalizePublicLaneUnbond {
        lane_id: lane,
        validator: validator.clone(),
        staker: validator.clone(),
        request_id,
        monetary_plan: plan.clone(),
    }
    .execute(&validator, &mut stx)
    .expect("the canonical matured share remains withdrawable");
    assert!(
        !stx.world
            .public_lane_stake_shares
            .get(&share_key)
            .unwrap()
            .pending_unbonds
            .contains_key(&request_id)
    );
    assert_eq!(
        stx.world.public_lane_stake_reserves.get(&plan.source_asset),
        Some(&quantity_sub(reserve_before.unwrap(), request.amount.clone()).unwrap()),
    );
    assert_eq!(
        stx.world.assets.get(&plan.source_asset).unwrap().as_ref(),
        &quantity_sub(
            balances_before.0.unwrap().as_ref().clone(),
            request.amount.clone()
        )
        .unwrap(),
    );
    assert_eq!(
        stx.world
            .assets
            .get(&plan.destination_asset)
            .unwrap()
            .as_ref(),
        &quantity_add(balances_before.1.unwrap().as_ref().clone(), request.amount).unwrap(),
    );
}
