// Original parameter-cut controls for the actual registration minimum consumer.

fn committed_staking_fixture_policy() -> iroha_data_model::block::consensus::PublicLaneStakingPolicy
{
    iroha_data_model::block::consensus::PublicLaneStakingPolicy {
        min_validator_stake: 1_u64.into(),
        max_stake_shares_per_validator: nonzero!(256_u32),
        max_pending_unbonds_per_share: nonzero!(8_u32),
        unbonding_delay_ms: 0,
        max_slash_bps: 10_000,
        stake_asset_id: SumeragiNposParameters::default().xor_asset_definition_id,
        stake_escrow_account_id: ALICE_ID.clone(),
        slash_sink_account_id: ALICE_ID.clone(),
    }
}

#[test]
fn registration_uses_committed_minimum_despite_stricter_local_configuration() {
    let mut state = setup_state();
    state.nexus.get_mut().staking.min_validator_stake = u64::MAX.into();
    let mut parameters = state.world.parameters.block();
    let mut policy = committed_staking_fixture_policy();
    policy.min_validator_stake = 1_000_u64.into();
    parameters
        .set_parameter(Parameter::Custom(policy.into_custom_parameter().unwrap()))
        .unwrap();
    parameters.commit();
    let mut block = state.block(block_header_with_height(1));
    let mut transaction = block.transaction_for_callback_testing();
    let (validator, _, _, _) = prepare_accounts(&mut transaction);
    RegisterPublicLaneValidator {
        monetary_plan: fixture_registration_plan(
            &transaction,
            LaneId::new(3),
            &validator,
            Quantity::from(1_000_u64),
        ),
        lane_id: LaneId::new(3),
        peer_id: validator_peer_id(&validator),
        validator: validator.clone(),
        stake_account: validator.clone(),
        initial_stake: Quantity::from(1_000_u64),
        metadata: Metadata::default(),
    }
    .execute(&validator, &mut transaction)
    .expect("the explicit committed minimum controls registration");
    assert!(
        transaction
            .world
            .public_lane_validators
            .get(&(LaneId::new(3), validator))
            .is_some()
    );
}

#[test]
fn staking_monetary_reader_keeps_original_cut_across_applied_and_aborted_updates() {
    let state = setup_state();
    let original = committed_staking_fixture_policy();
    let mut successor = original.clone();
    successor.min_validator_stake = 2_000_u64.into();
    let successor_parameter = Parameter::Custom(successor.clone().into_custom_parameter().unwrap());
    let mut block = state.block(block_header_with_height(2));
    {
        let mut transaction = block.transaction_for_callback_testing();
        transaction
            .world
            .parameters
            .get_mut()
            .set_parameter(successor_parameter.clone())
            .unwrap();
        assert_eq!(transaction.staking_monetary_policy().unwrap(), &original);
        assert_eq!(
            transaction
                .world
                .parameters
                .get()
                .require_staking_policy()
                .unwrap(),
            &successor
        );
        // Aborting preserves the original, including its canonical source value.
    }
    {
        let mut transaction = block.transaction_for_callback_testing();
        assert_eq!(
            transaction
                .world
                .parameters
                .get()
                .require_staking_policy()
                .unwrap(),
            &original
        );
        transaction
            .world
            .parameters
            .get_mut()
            .set_parameter(successor_parameter)
            .unwrap();
        transaction.apply();
    }
    {
        let transaction = block.transaction_for_callback_testing();
        let pointer: *const iroha_data_model::block::consensus::PublicLaneStakingPolicy =
            transaction.staking_monetary_policy().unwrap();
        norito::with_decode_limits_scope(norito::DecodeLimits::new(0, 0, 0, 0, 0), || {
            assert_eq!(transaction.staking_monetary_policy().unwrap(), &original);
            assert!(core::ptr::eq(
                transaction.staking_monetary_policy().unwrap(),
                pointer
            ));
        });
        assert_eq!(
            transaction
                .world
                .parameters
                .get()
                .require_staking_policy()
                .unwrap(),
            &successor
        );
    }
    // Commit only the component World overlay. This is not block publication
    // or evidence for full signed execution/replay.
    block.commit_world_overlay_for_testing().unwrap();
    let mut next = state.block(block_header_with_height(3));
    let transaction = next.transaction_for_callback_testing();
    assert_eq!(transaction.staking_monetary_policy().unwrap(), &successor);
}

#[test]
fn staking_monetary_reader_cannot_initialize_from_transaction_or_local_defaults() {
    let state = State::new_with_nexus_for_testing(
        World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []),
        iroha_config::parameters::actual::Nexus::default(),
        LiveQueryStore::start_test(),
    );
    let mut block = state.block(block_header_with_height(2));
    {
        let mut transaction = block.transaction_for_callback_testing();
        assert!(matches!(
            transaction.staking_monetary_policy(),
            Err(iroha_data_model::block::consensus::PublicLaneStakingPolicyError::MissingParameter)
        ));
        transaction
            .world
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(
                committed_staking_fixture_policy()
                    .into_custom_parameter()
                    .unwrap(),
            ))
            .unwrap();
        assert!(matches!(
            transaction.staking_monetary_policy(),
            Err(iroha_data_model::block::consensus::PublicLaneStakingPolicyError::MissingParameter)
        ));
        transaction.apply();
    }
    let transaction = block.transaction_for_callback_testing();
    assert!(matches!(
        transaction.staking_monetary_policy(),
        Err(iroha_data_model::block::consensus::PublicLaneStakingPolicyError::MissingParameter)
    ));
}
