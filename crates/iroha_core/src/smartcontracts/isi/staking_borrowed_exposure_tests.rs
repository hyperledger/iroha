// Indexed offence-height exposure reads current rows without owning share copies.

#[test]
fn indexed_exposure_borrows_ordered_rows_and_skips_consumed_share() {
    let state = setup_state();
    let block = new_block();
    let mut state_block = state.block(block.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    let (validator, delegator, _, _) = prepare_accounts(&mut stx);
    let lane_id = LaneId::new(42);
    let record = PublicLaneValidatorRecord {
        lane_id,
        validator: validator.clone(),
        peer_id: validator_peer_id(&validator),
        stake_account: validator.clone(),
        total_stake: Quantity::from(120_u64),
        self_stake: Quantity::from(100_u64),
        metadata: Metadata::default(),
        status: PublicLaneValidatorStatus::Active,
        activation_height: 1,
        election_exit_height: None,
        deactivation_height: None,
    };
    let self_key = (lane_id, validator.clone(), validator.clone());
    let delegated_key = (lane_id, validator.clone(), delegator.clone());
    let request_id = Hash::new("borrowed-indexed-exposure-unbond");
    let mut pending_unbonds = BTreeMap::new();
    pending_unbonds.insert(
        request_id,
        PublicLaneUnbonding {
            request_id,
            amount: Quantity::from(30_u64),
            release_at_ms: 0,
            slashable_through_height: 8,
            liability_release_height: 8,
        },
    );
    stx.world.public_lane_stake_shares.insert(
        self_key.clone(),
        PublicLaneStakeShare {
            lane_id,
            validator: validator.clone(),
            staker: validator.clone(),
            bonded: Quantity::from(100_u64),
            pending_unbonds: BTreeMap::new(),
            metadata: Metadata::default(),
        },
    );
    stx.world.public_lane_stake_shares.insert(
        delegated_key.clone(),
        PublicLaneStakeShare {
            lane_id,
            validator: validator.clone(),
            staker: delegator.clone(),
            bonded: Quantity::from(20_u64),
            pending_unbonds,
            metadata: Metadata::default(),
        },
    );
    let mut keys = [self_key, delegated_key.clone()];
    keys.sort();
    assert_eq!(
        indexed_slashable_validator_exposure(
            &stx.world,
            lane_id,
            &validator,
            &record,
            ConsensusSlashLiability::Root(8),
            &keys
        )
        .unwrap(),
        Quantity::from(150_u64)
    );
    assert_eq!(
        indexed_slashable_validator_exposure(
            &stx.world,
            lane_id,
            &validator,
            &record,
            ConsensusSlashLiability::Root(9),
            &keys
        )
        .unwrap(),
        Quantity::from(120_u64)
    );

    let mut reversed = keys.clone();
    reversed.reverse();
    assert!(matches!(
        indexed_slashable_validator_exposure(&stx.world, lane_id, &validator, &record, ConsensusSlashLiability::Root(8), &reversed),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(Error::InvariantViolation(message))) if message.contains("not canonical")
    ));
    let foreign = [(lane_id, delegator.clone(), delegator)];
    assert!(matches!(
        indexed_slashable_validator_exposure(&stx.world, lane_id, &validator, &record, ConsensusSlashLiability::Root(8), &foreign),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(Error::InvariantViolation(message))) if message.contains("another validator")
    ));

    let last_key = keys.last().unwrap();
    let original = stx
        .world
        .public_lane_stake_shares
        .get(last_key)
        .unwrap()
        .clone();
    let mut malformed = original.clone();
    malformed.lane_id = LaneId::new(43);
    stx.world
        .public_lane_stake_shares
        .insert((*last_key).clone(), malformed);
    assert!(matches!(
        indexed_slashable_validator_exposure(&stx.world, lane_id, &validator, &record, ConsensusSlashLiability::Root(8), &keys),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(Error::InvariantViolation(message))) if message.contains("does not match its storage key")
    ));
    stx.world
        .public_lane_stake_shares
        .insert((*last_key).clone(), original);

    stx.world.public_lane_stake_shares.remove(delegated_key);
    assert!(matches!(
        indexed_slashable_validator_exposure(&stx.world, lane_id, &validator, &record, ConsensusSlashLiability::Root(8), &keys),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(Error::InvariantViolation(message))) if message.contains("totals do not match")
    ));
    let record_after = PublicLaneValidatorRecord {
        total_stake: Quantity::from(100_u64),
        ..record
    };
    assert_eq!(
        indexed_slashable_validator_exposure(
            &stx.world,
            lane_id,
            &validator,
            &record_after,
            ConsensusSlashLiability::Root(8),
            &keys,
        )
        .unwrap(),
        Quantity::from(100_u64)
    );
}
