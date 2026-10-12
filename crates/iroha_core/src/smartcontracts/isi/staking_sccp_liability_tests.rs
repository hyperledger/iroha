// L3 component controls use admitted DATA generation fixtures, not forged cryptographic
// authority. The existing native monetary-plan and lifecycle helpers remain unchanged.
fn fixture_sccp_liability_generation(
    stx: &mut StateTransaction<'_, '_>,
    record: &PublicLaneValidatorRecord,
) {
    use crate::smartcontracts::isi::sccp::{
        committee_storage::CommitteeFixtureStorage as _, test_support::sample_generation_at,
    };
    use iroha_data_model::sccp::generation::SccpGenerationMemberV1;
    let number = if record.activation_height == 1 { 1 } else { 7 };
    let mut generation = sample_generation_at(number, record.activation_height);
    generation.members[0] = Some(SccpGenerationMemberV1 {
        lane_id: record.lane_id,
        validator: record.validator.clone(),
        activation_height: record.activation_height,
    });
    assert!(generation.is_well_formed());
    stx.world
        .sccp_committee_generations
        .insert(number, generation);
    *stx.world.sccp_committee_current.get_mut() = number;
}

#[test]
fn sccp_liable_unbond_keeps_exact_pending_request_and_both_balances() {
    let mut state = setup_state();
    set_epoch_length(&mut state, 4);
    let nexus = state.nexus_snapshot();
    let state = original_staking_state(
        state,
        nexus,
        iroha_data_model::parameter::system::SumeragiConsensusMode::Npos,
    );
    let block = new_block_with_height_and_time(2, 0);
    let mut state_block = state.block(block.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    let (validator, _, escrow, asset_definition) = prepare_accounts(&mut stx);
    set_test_npos_penalty_windows(&mut stx, 1, 1);
    let lane_id = LaneId::SINGLE;
    // A signed candidate may fund a future tenure without joining the current
    // topology. The default one-block key lead fits before the H4 boundary.
    let peer_key = checked_keypair_with_algorithm(Algorithm::BlsNormal);
    let candidate = signed_candidate(&stx, &validator, &peer_key, 500, lane_id);
    assert_eq!(candidate.activation_height, 9);
    candidate.execute(&validator, &mut stx).unwrap();
    stx.apply();
    state_block.commit_world_overlay_for_testing().unwrap();

    // The boundary schedules withdrawal after the admitted future tenure starts,
    // so the retained SCCP generation lies inside this request's liability range.
    let block = new_block_with_height_and_time(4, 0);
    let mut state_block = state.block(block.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    stx.nexus.staking.stake_asset_id = asset_definition.to_string();
    set_fixture_xor_identity(&mut stx, &asset_definition);
    stx.nexus.staking.stake_escrow_account_id = escrow.to_string();
    stx.nexus.staking.slash_sink_account_id = escrow.to_string();
    let request_id = Hash::new("sccp-held-unbond");
    SchedulePublicLaneUnbond {
        lane_id,
        validator: validator.clone(),
        staker: validator.clone(),
        request_id,
        amount: Quantity::from(500_u64),
        release_at_ms: stx.block_unix_timestamp_ms(),
    }
    .execute(&validator, &mut stx)
    .unwrap();
    ExitPublicLaneValidator {
        lane_id,
        validator: validator.clone(),
        release_at_ms: stx.block_unix_timestamp_ms(),
    }
    .execute(&validator, &mut stx)
    .unwrap();
    let record = stx
        .world
        .public_lane_validators
        .get(&(lane_id, validator.clone()))
        .unwrap()
        .clone();
    fixture_sccp_liability_generation(&mut stx, &record);
    let request = &stx
        .world
        .public_lane_stake_shares
        .get(&stake_key(lane_id, &validator, &validator))
        .unwrap()
        .pending_unbonds[&request_id];
    assert!(request.slashable_through_height >= record.activation_height);
    let release_height = request.liability_release_height;
    stx.apply();
    state_block.commit_world_overlay_for_testing().unwrap();

    let block = new_block_with_height_and_time(release_height, 0);
    let mut state_block = state.block(block.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    stx.nexus.staking.stake_asset_id = asset_definition.to_string();
    set_fixture_xor_identity(&mut stx, &asset_definition);
    stx.nexus.staking.stake_escrow_account_id = escrow.to_string();
    stx.nexus.staking.slash_sink_account_id = escrow.to_string();
    finalize_validator_lifecycle(&mut stx).unwrap();
    let key = stake_key(lane_id, &validator, &validator);
    let share_before = stx
        .world
        .public_lane_stake_shares
        .get(&key)
        .unwrap()
        .clone();
    let validator_before = stx
        .world
        .public_lane_validators
        .get(&(lane_id, validator.clone()))
        .unwrap()
        .clone();
    assert!(!has_global_committee_obligation(&stx, &validator_before));
    assert!(
        stx.block_height() >= share_before.pending_unbonds[&request_id].liability_release_height
    );
    let source = AssetId::new(asset_definition.clone(), escrow);
    let destination = AssetId::new(asset_definition, validator.clone());
    let source_before = stx.world.assets.get(&source).unwrap().clone();
    let destination_before = stx.world.assets.get(&destination).unwrap().clone();
    let error = FinalizePublicLaneUnbond {
        monetary_plan: fixture_unbond_plan(&stx, lane_id, &validator, &validator, request_id),
        lane_id,
        validator: validator.clone(),
        staker: validator.clone(),
        request_id,
    }
    .execute(&validator, &mut stx)
    .unwrap_err();
    assert!(
        matches!(&error, Error::InvariantViolation(message) if message.starts_with("SccpLiabilityActive:")),
        "unexpected withdrawal or replacement refusal: {error}"
    );
    assert_eq!(
        stx.world.public_lane_stake_shares.get(&key),
        Some(&share_before)
    );
    assert_eq!(
        stx.world.public_lane_validators.get(&(lane_id, validator)),
        Some(&validator_before)
    );
    assert_eq!(stx.world.assets.get(&source), Some(&source_before));
    assert_eq!(
        stx.world.assets.get(&destination),
        Some(&destination_before)
    );
    assert!(
        stx.require_storage_admission().is_ok(),
        "a protocol hold is not a local resource refusal"
    );
}

#[test]
fn sccp_liable_zero_custody_registration_survives_pruning_and_replacement() {
    let mut state = setup_state();
    set_epoch_length(&mut state, 3);
    let nexus = state.nexus_snapshot();
    let state = original_staking_state(
        state,
        nexus,
        iroha_data_model::parameter::system::SumeragiConsensusMode::Npos,
    );
    let block = new_block_with_height_and_time(2, 0);
    let mut state_block = state.block(block.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    let (validator, _, escrow, asset_definition) = prepare_accounts(&mut stx);
    let lane_id = LaneId::SINGLE;
    let record = PublicLaneValidatorRecord {
        lane_id,
        validator: validator.clone(),
        peer_id: validator_peer_id(&validator),
        stake_account: validator.clone(),
        total_stake: Quantity::zero(),
        self_stake: Quantity::zero(),
        metadata: Metadata::default(),
        status: PublicLaneValidatorStatus::Exited,
        activation_height: 1,
        election_exit_height: Some(2),
        deactivation_height: Some(2),
    };
    fixture_sccp_liability_generation(&mut stx, &record);
    stx.world
        .public_lane_validators
        .insert((lane_id, validator.clone()), record.clone());
    stx.apply();
    state_block.commit_world_overlay_for_testing().unwrap();

    let block = new_block_with_height_and_time(3, 0);
    let mut state_block = state.block(block.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    stx.nexus.staking.stake_asset_id = asset_definition.to_string();
    set_fixture_xor_identity(&mut stx, &asset_definition);
    stx.nexus.staking.stake_escrow_account_id = escrow.to_string();
    stx.nexus.staking.slash_sink_account_id = escrow.to_string();
    prune_zero_custody_exited_validators(&mut stx).unwrap();
    assert_eq!(
        stx.world
            .public_lane_validators
            .get(&(lane_id, validator.clone())),
        Some(&record)
    );
    let asset = AssetId::new(asset_definition, validator.clone());
    let balance = stx.world.assets.get(&asset).unwrap().clone();
    let peer_key = checked_keypair_with_algorithm(Algorithm::BlsNormal);
    let candidate = signed_candidate(&stx, &validator, &peer_key, 500, lane_id);
    assert_eq!(candidate.activation_height, 10);
    let error = candidate.execute(&validator, &mut stx).unwrap_err();
    assert!(
        matches!(&error, Error::InvariantViolation(message) if message.starts_with("SccpLiabilityActive:")),
        "unexpected withdrawal or replacement refusal: {error}"
    );
    assert_eq!(
        stx.world.public_lane_validators.get(&(lane_id, validator)),
        Some(&record)
    );
    assert_eq!(stx.world.assets.get(&asset), Some(&balance));
    assert!(stx.require_storage_admission().is_ok());
}

#[test]
fn sccp_liability_does_not_refuse_exit_or_change_the_captured_registration() {
    let mut state = setup_state();
    set_epoch_length(&mut state, 3);
    let nexus = state.nexus_snapshot();
    let state = original_staking_state(
        state,
        nexus,
        iroha_data_model::parameter::system::SumeragiConsensusMode::Npos,
    );
    let block = new_block_with_height_and_time(2, 0);
    let mut state_block = state.block(block.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    let (validator, _, _, _) = prepare_accounts(&mut stx);
    let lane_id = LaneId::SINGLE;
    let record = PublicLaneValidatorRecord {
        lane_id,
        validator: validator.clone(),
        peer_id: validator_peer_id(&validator),
        stake_account: validator.clone(),
        total_stake: Quantity::zero(),
        self_stake: Quantity::zero(),
        metadata: Metadata::default(),
        status: PublicLaneValidatorStatus::Active,
        activation_height: 1,
        election_exit_height: None,
        deactivation_height: None,
    };
    fixture_sccp_liability_generation(&mut stx, &record);
    stx.world
        .public_lane_validators
        .insert((lane_id, validator.clone()), record.clone());
    stx.apply();
    state_block.commit_world_overlay_for_testing().unwrap();

    let block = new_block_with_height_and_time(3, 0);
    let mut state_block = state.block(block.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    assert_eq!(
        sccp_liability_release(&stx, &record, None).unwrap(),
        Some(crate::smartcontracts::isi::sccp::liability::ReleaseBlocker::LiabilityActive)
    );
    ExitPublicLaneValidator {
        lane_id,
        validator: validator.clone(),
        release_at_ms: 0,
    }
    .execute(&validator, &mut stx)
    .unwrap();
    let exited = stx
        .world
        .public_lane_validators
        .get(&(lane_id, validator))
        .unwrap();
    assert!(matches!(
        exited.status,
        PublicLaneValidatorStatus::Exiting(_)
    ));
    assert_eq!(exited.activation_height, record.activation_height);
    assert_eq!(exited.peer_id, record.peer_id);
    assert_eq!(exited.total_stake, Quantity::zero());
    assert!(stx.require_storage_admission().is_ok());
}

#[test]
fn sccp_release_resource_refusal_is_original_and_sticky_after_inner_error() {
    use crate::state::{StateStorageAdmissionError, sccp_forgery_custody::ForgeryStorageError};
    let state = setup_state();
    let block = new_block();
    let mut state_block = state.block(block.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    let pool = iroha_allocation::AllocationBudget::new(1);
    let occupied = pool.try_reserve_bytes(1).unwrap();
    let refusal = pool.try_reserve_bytes(1).unwrap_err();
    let source =
        ForgeryStorageError::Storage(mv::storage::AdmittedStorageError::Allocation(refusal));
    let expected = StateStorageAdmissionError::SccpForgery(source.clone());
    retain_sccp_release_result(&mut stx, Err(source)).unwrap_err();
    assert_eq!(stx.require_storage_admission(), Err(expected.clone()));
    retain_sccp_release_result(&mut stx, Ok(None)).unwrap();
    assert_eq!(stx.require_storage_admission(), Err(expected.clone()));
    stx.apply();
    drop(occupied);
    assert_eq!(state_block.require_storage_admission(), Err(expected));
    assert!(state_block.commit_world_overlay_for_testing().is_err());
}
