#[test]
fn staking_instructions_change_only_future_reward_exposure() {
    use std::collections::{BTreeMap, BTreeSet};

    use iroha_data_model::validation_fee_rewards::{
        ValidationFeeExposurePage, ValidationFeeRewardExposure, allocate_page,
    };

    use crate::validation_fee_rewards::reward_exposure_before_block_for_testing;

    let mut state = setup_state();
    set_epoch_length(&mut state, 100);
    let lane = LaneId::new(13);
    let first = new_block_with_height_and_time(2, 1_000);
    let mut first_block = state.block(first.as_ref().header());
    let mut stx = first_block.transaction_for_callback_testing();
    let (validator, nominator, escrow, definition) = prepare_accounts(&mut stx);
    RegisterPublicLaneValidator {
        monetary_plan: fixture_registration_plan(&stx, lane, &validator, Quantity::from(1_000_u64)),
        lane_id: lane,
        peer_id: validator_peer_id(&validator),
        validator: validator.clone(),
        stake_account: validator.clone(),
        initial_stake: Quantity::from(1_000_u64),
        metadata: Metadata::default(),
    }
    .execute(&validator, &mut stx)
    .expect("register genuine bonded self-stake");
    BondPublicLaneStake {
        monetary_plan: fixture_bond_plan(
            &stx,
            lane,
            &validator,
            &nominator,
            Quantity::from(500_u64),
        ),
        lane_id: lane,
        validator: validator.clone(),
        staker: nominator.clone(),
        amount: Quantity::from(500_u64),
        metadata: Metadata::default(),
    }
    .execute(&nominator, &mut stx)
    .expect("bond genuine nomination");
    let activation_height = stx
        .world
        .public_lane_validators
        .get(&(lane, validator.clone()))
        .unwrap()
        .activation_height;
    assert!(stx.block_height() + 1 < activation_height);
    assert_eq!(
        stx.world
            .public_lane_validators
            .get(&(lane, validator.clone()))
            .unwrap()
            .status,
        PublicLaneValidatorStatus::PendingActivation(activation_height)
    );
    let replacement_key = checked_keypair();
    let replacement_peer = PeerId::new(replacement_key.public_key().clone());
    let _ = stx.world.peers.push(replacement_peer.clone());
    seed_participant_consensus_key(&mut stx, &replacement_peer);
    rebind_for_test(&stx, lane, &validator, &replacement_peer, &replacement_key)
        .execute(&validator, &mut stx)
        .expect("peer consent rebind succeeds before the activation freeze");
    stx.apply();
    first_block.commit_world_overlay_for_testing().unwrap();

    let selected = BTreeMap::from([(lane, BTreeSet::from([validator.clone()]))]);
    let identity = (lane, validator.clone());
    let second = new_block_with_height_and_time(activation_height + 1, 2_000);
    let mut second_block = state.block(second.as_ref().header());
    let original = reward_exposure_before_block_for_testing(&second_block, &selected).unwrap();
    assert_eq!(
        original[&identity],
        BTreeMap::from([
            (validator.clone(), Quantity::from(1_000_u64)),
            (nominator.clone(), Quantity::from(500_u64)),
        ])
    );
    let original_page = ValidationFeeExposurePage {
        earning_period_start_ms: 0,
        validator: validator.clone(),
        page_index: 0,
        exposure: vec![ValidationFeeRewardExposure {
            service_blocks: 1,
            stakes: original[&identity].clone(),
        }],
    };
    let mut stx = second_block.transaction_for_callback_testing();
    stx.nexus.staking.stake_asset_id = definition.to_string();
    set_fixture_xor_identity(&mut stx, &definition);
    stx.nexus.staking.stake_escrow_account_id = escrow.to_string();
    stx.nexus.staking.slash_sink_account_id = nominator.to_string();
    BondPublicLaneStake {
        monetary_plan: fixture_bond_plan(
            &stx,
            lane,
            &validator,
            &nominator,
            Quantity::from(300_u64),
        ),
        lane_id: lane,
        validator: validator.clone(),
        staker: nominator.clone(),
        amount: Quantity::from(300_u64),
        metadata: Metadata::default(),
    }
    .execute(&nominator, &mut stx)
    .expect("later deposit must not capture earlier service");
    let request_id = Hash::new("historical-reward-unbond");
    SchedulePublicLaneUnbond {
        lane_id: lane,
        validator: validator.clone(),
        staker: nominator.clone(),
        request_id,
        amount: Quantity::from(200_u64),
        release_at_ms: stx.block_unix_timestamp_ms()
            + duration_millis(stx.nexus.staking.unbonding_delay),
    }
    .execute(&nominator, &mut stx)
    .expect("schedule unbond while retaining slashable custody");
    SlashPublicLaneValidator {
        monetary_plan: fixture_slash_plan(
            &stx,
            lane,
            &validator,
            stx.block_height(),
            Quantity::from(400_u64),
        ),
        lane_id: lane,
        validator: validator.clone(),
        offence_height: stx.block_height(),
        slash_id: Hash::new("historical-reward-slash"),
        amount: Quantity::from(400_u64),
        reason_code: "evidence".to_owned(),
        metadata: Metadata::default(),
    }
    .execute(&ALICE_ID, &mut stx)
    .expect("slash reduces only future eligible self-stake");
    let nomination = stx
        .world
        .public_lane_stake_shares
        .get(&(lane, validator.clone(), nominator.clone()))
        .unwrap();
    assert_eq!(nomination.bonded, Quantity::from(600_u64));
    assert_eq!(
        nomination.pending_unbonds[&request_id].amount,
        Quantity::from(200_u64)
    );
    assert_eq!(
        stx.world
            .public_lane_validators
            .get(&identity)
            .unwrap()
            .peer_id,
        replacement_peer
    );
    stx.apply();
    assert_eq!(
        reward_exposure_before_block_for_testing(&second_block, &selected).unwrap(),
        original,
        "current-block instructions cannot rewrite authenticated parent service exposure"
    );
    second_block.commit_world_overlay_for_testing().unwrap();

    let third = new_block_with_height_and_time(activation_height + 2, 3_000);
    let mut third_block = state.block(third.as_ref().header());
    let changed = reward_exposure_before_block_for_testing(&third_block, &selected).unwrap();
    assert_eq!(
        changed[&identity],
        BTreeMap::from([
            (validator.clone(), Quantity::from(600_u64)),
            (nominator.clone(), Quantity::from(600_u64)),
        ]),
        "committed unbonded custody stops earning and committed slashing lowers future exposure"
    );
    let mut stx = third_block.transaction_for_callback_testing();
    ExitPublicLaneValidator {
        lane_id: lane,
        validator: validator.clone(),
        release_at_ms: stx.block_unix_timestamp_ms(),
    }
    .execute(&validator, &mut stx)
    .expect("exit preserves retained bonded exposure until its service boundary");
    assert!(matches!(
        stx.world
            .public_lane_validators
            .get(&identity)
            .unwrap()
            .status,
        PublicLaneValidatorStatus::Exiting(_)
    ));
    stx.apply();
    assert_eq!(
        reward_exposure_before_block_for_testing(&third_block, &selected).unwrap(),
        changed
    );
    third_block.commit_world_overlay_for_testing().unwrap();
    let fourth = new_block_with_height_and_time(activation_height + 3, 4_000);
    let fourth_block = state.block(fourth.as_ref().header());
    assert_eq!(
        reward_exposure_before_block_for_testing(&fourth_block, &selected).unwrap(),
        changed,
        "an exiting retained signer still earns on its committed bonded positions"
    );
    assert_eq!(
        allocate_page(150, 1, 0, &original_page).unwrap(),
        BTreeMap::from([(validator.clone(), 100), (nominator.clone(), 50)]),
        "delayed original service allocation survives later deposits, unbonding, slash, and exit after a valid peer rebind"
    );
    let changed_page = ValidationFeeExposurePage {
        earning_period_start_ms: 0,
        validator: validator.clone(),
        page_index: 1,
        exposure: vec![ValidationFeeRewardExposure {
            service_blocks: 1,
            stakes: changed[&identity].clone(),
        }],
    };
    assert_eq!(
        allocate_page(150, 1, 0, &changed_page).unwrap(),
        BTreeMap::from([(validator, 75), (nominator, 75)])
    );
}
