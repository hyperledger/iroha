// SCCP penalty-kernel DATA uses a genuine executed NPoS policy/monetary State.
// The preinstalled record has an invalid signature and is explicitly not evidence
// admission or Execute authority; those boundaries have independent source owners.
fn sccp_penalty_fixture(start_height: u64) -> (State, Hash, AccountId) {
    use iroha_data_model::block::consensus::RecordedEvidenceV1;
    use iroha_data_model::sumeragi_finality::certified_result::{
        FLAG_ACTIVE, SccpFinalityHeaderFieldsV1, SccpFinalityHeaderV1,
    };
    let state = native_penalty_state();
    install_one_block_delay_npos(&state);
    let validator = add_validator_record(&state, &roster()[1]);
    let mut data = crate::sumeragi::evidence::record::sccp_storage_claim_for_testing();
    let RecordedEvidenceV1::SccpForgery(material) = &mut data.evidence else {
        unreachable!()
    };
    material.start_height = start_height;
    material.offenders[0].validator = validator.clone();
    material.offenders[0].signer = 1;
    material.evidence.header = *SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
        network_id: [1; 32],
        height: 1_000,
        timestamp_ms: 1_000_000,
        flags: FLAG_ACTIVE,
        generation: material.generation,
        committee_root: [3; 32],
        ..Default::default()
    })
    .unwrap()
    .as_bytes();
    data.attribution.height = start_height;
    data.attribution.offenders[0].signer = 1;
    data.attribution.offenders[0].peer_id = roster()[1].clone();
    data.recorded_at_height = start_height;
    data.recorded_at_ms = start_height * 1_000;
    let text = norito::json::to_json(&data).unwrap();
    let owner = crate::sumeragi::evidence::record::parse_record(
        &mut norito::json::Parser::new(&text),
        state.evidence_preparation_budget(),
    )
    .unwrap();
    let key = Hash::prehashed(owner.sccp_evidence_id().unwrap());
    let mut records = state.world.consensus_evidence.block();
    records.insert(key, owner);
    records.commit();
    (state, key, validator)
}

#[test]
fn sccp_penalty_uses_captured_tuple_start_and_record_delay_without_generation_or_peer_map() {
    let (state, key, validator) = sccp_penalty_fixture(1);
    // The signed attacker's height 1000 is outside this original tenure.
    let mut registrations = state.world.public_lane_validators.block();
    registrations
        .get_mut(&(LaneId::SINGLE, validator.clone()))
        .unwrap()
        .deactivation_height = Some(5);
    registrations.commit();
    let view = state.view();
    assert!(view.world().sccp_committee_generations().is_empty());
    let owner = view.world().consensus_evidence().get(&key).unwrap();
    let before = state.evidence_preparation_budget().reserved_bytes();
    let snapshot = PenaltyApplier::parent_snapshot(
        &view,
        2,
        state.evidence_preparation_budget(),
        state.stake_index_budget(),
    )
    .unwrap();
    assert!(snapshot.validator_map.rows.as_slice().is_empty());
    assert_eq!(snapshot.pending.as_slice().len(), 1);
    assert!(snapshot.pending.as_slice()[0].0.5.is_none());
    assert!(
        snapshot.sccp_pending.as_slice()[0]
            .record
            .shares_body(owner)
    );
    assert_eq!(
        state.evidence_preparation_budget().reserved_bytes(),
        before
            + std::mem::size_of::<PendingPenaltyEvidence>()
            + std::mem::size_of::<sccp::Pending>()
    );
    drop(snapshot);
    assert_eq!(state.evidence_preparation_budget().reserved_bytes(), before);
    drop(view);
    let applier = PenaltyApplier::new(&state, None);
    assert!(
        applier
            .derive_npos_penalty_actions(&penalty_header(1))
            .unwrap()
            .0
            .is_empty()
    );
    let result = applier.derive_npos_penalty_actions(&penalty_header(2));
    assert!(
        result.as_ref().is_ok_and(|(actions, _)| actions.len() == 2),
        "SC21 forged height cannot replace original generation liability start"
    );
    let (actions, index) = result.unwrap();
    assert!(
        matches!(&actions[0], NposPenaltyAction::ConsensusSlash(slash)
        if slash.evidence_key == key && slash.validator == validator
            && slash.lane_id == LaneId::SINGLE && slash.signer == 1
            && slash.amount == Quantity::from(10_000_u64))
    );
    let (_, _, sink) = penalty_staking_ids();
    let asset = AssetId::new(penalty_staking_ids().0, sink);
    let sink_before = state
        .view()
        .world()
        .assets()
        .get(&asset)
        .map_or_else(Quantity::zero, |value| value.as_ref().clone());
    let mut block = state
        .consensus_effects_probe_block(penalty_header(2))
        .unwrap();
    {
        let mut tx = block.consensus_effects_transaction().unwrap();
        let outcome = apply_npos_consensus_effects_to_transaction(
            &mut tx,
            &NposConsensusEffects {
                parent_service_commit_qc: None,
                evidence_admissions: Vec::new(),
                penalty_actions: actions,
            },
            Some(&index),
            &[],
            &[],
            2,
            0,
            2_000,
        )
        .unwrap();
        assert_eq!((outcome.applied, outcome.slashed), (1, 1));
        assert_eq!(
            tx.world
                .consensus_evidence
                .get(&key)
                .unwrap()
                .penalty_status,
            EvidencePenaltyStatus::Applied { height: 2 }
        );
        assert_eq!(
            tx.world
                .assets
                .get(&asset)
                .unwrap()
                .as_ref()
                .checked_sub(&sink_before)
                .unwrap(),
            Quantity::from(10_000_u64)
        );
        // Dropping the whole child preserves Pending and every original balance.
    }
    assert_eq!(
        block
            .world
            .consensus_evidence
            .get(&key)
            .unwrap()
            .penalty_status,
        EvidencePenaltyStatus::Pending
    );
    assert_eq!(
        block
            .world
            .assets
            .get(&asset)
            .map_or_else(Quantity::zero, |value| value.as_ref().clone()),
        sink_before
    );
}

#[test]
fn sccp_penalty_ignores_late_peer_mapping_and_keeps_original_g6_custody() {
    let (state, key, original) = sccp_penalty_fixture(1);
    let late = add_validator_record(&state, &roster()[2]);
    let mut registrations = state.world.public_lane_validators.block();
    registrations
        .get_mut(&(LaneId::SINGLE, original.clone()))
        .unwrap()
        .peer_id = roster()[3].clone();
    let replacement = registrations
        .get_mut(&(LaneId::SINGLE, late.clone()))
        .unwrap();
    replacement.peer_id = roster()[1].clone();
    replacement.activation_height = 20;
    registrations.commit();
    let result = PenaltyApplier::new(&state, None).derive_npos_penalty_actions(&penalty_header(2));
    assert!(
        matches!(result.as_ref().ok().and_then(|(actions, _)| actions.first()),
        Some(NposPenaltyAction::ConsensusSlash(slash))
        if slash.evidence_key == key && slash.validator == original
            && slash.validator != late && slash.amount == Quantity::from(10_000_u64)),
        "SC21 only the original captured registration remains slashable"
    );
}

#[test]
fn sccp_penalty_missing_or_replaced_g6_registration_stays_pending() {
    for mutation in 0..3 {
        let (state, key, validator) = sccp_penalty_fixture(1);
        let mut rows = state.world.public_lane_validators.block();
        let locator = (LaneId::SINGLE, validator);
        match mutation {
            0 => {
                rows.remove(locator);
            }
            1 => {
                rows.get_mut(&locator).unwrap().activation_height = 2;
            }
            2 => {
                rows.get_mut(&locator).unwrap().validator =
                    AccountId::new(roster()[2].public_key().clone());
            }
            _ => unreachable!(),
        }
        rows.commit();
        assert!(
            PenaltyApplier::new(&state, None)
                .derive_npos_penalty_actions(&penalty_header(2))
                .is_err()
        );
        assert_eq!(
            state
                .world
                .consensus_evidence
                .view()
                .get(&key)
                .unwrap()
                .penalty_status,
            EvidencePenaltyStatus::Pending
        );
    }
}

#[test]
fn sccp_penalty_original_pool_refusal_and_retry_share_the_same_record_graph() {
    let (state, key, _) = sccp_penalty_fixture(1);
    let budget = state.evidence_preparation_budget();
    let baseline = budget.reserved_bytes();
    let original = state
        .world
        .consensus_evidence
        .view()
        .get(&key)
        .unwrap()
        .clone();
    let hold = budget
        .try_reserve_bytes(budget.limit_bytes() - baseline)
        .unwrap();
    let error = PenaltyApplier::new(&state, None)
        .derive_npos_penalty_actions(&penalty_header(2))
        .err()
        .unwrap();
    let refusal = error.downcast_ref::<EvidencePreparationError>().unwrap();
    assert!(matches!(
        refusal,
        EvidencePreparationError::Admission(AllocationRefusal::Capacity { .. })
    ));
    assert!(refusal.release_wait().is_some());
    assert!(
        state
            .world
            .consensus_evidence
            .view()
            .get(&key)
            .unwrap()
            .shares_body(&original)
    );
    assert_eq!(
        state
            .world
            .consensus_evidence
            .view()
            .get(&key)
            .unwrap()
            .penalty_status,
        EvidencePenaltyStatus::Pending
    );
    drop(hold);
    assert_eq!(budget.reserved_bytes(), baseline);
    let (actions, index) = PenaltyApplier::new(&state, None)
        .derive_npos_penalty_actions(&penalty_header(2))
        .unwrap();
    assert_eq!(actions.len(), 2);
    drop(index);
    assert_eq!(budget.reserved_bytes(), baseline);
    assert!(
        state
            .world
            .consensus_evidence
            .view()
            .get(&key)
            .unwrap()
            .shares_body(&original)
    );
}

#[test]
fn sccp_penalty_root_start_filters_pending_unbonds_inclusively() {
    let (state, key, validator) = sccp_penalty_fixture(5);
    let locator = (LaneId::SINGLE, validator.clone());
    let share_key = (LaneId::SINGLE, validator.clone(), validator);
    let mut validators = state.world.public_lane_validators.block();
    let row = validators.get_mut(&locator).unwrap();
    row.total_stake = Quantity::from(4_000_u64);
    row.self_stake = Quantity::from(4_000_u64);
    validators.commit();
    let mut shares = state.world.public_lane_stake_shares.block();
    let share = shares.get_mut(&share_key).unwrap();
    share.bonded = Quantity::from(4_000_u64);
    for (seed, end) in [(0u8, 4), (1, 5)] {
        let id = Hash::new([seed]);
        share.pending_unbonds.insert(
            id,
            PublicLaneUnbonding {
                request_id: id,
                amount: Quantity::from(3_000_u64),
                release_at_ms: 10_000,
                slashable_through_height: end,
                liability_release_height: end + 2,
            },
        );
    }
    shares.commit();
    let (actions, _) = PenaltyApplier::new(&state, None)
        .derive_npos_penalty_actions(&penalty_header(6))
        .unwrap();
    assert!(
        matches!(&actions[0], NposPenaltyAction::ConsensusSlash(slash)
        if slash.evidence_key == key && slash.amount == Quantity::from(7_000_u64))
    );
}

#[test]
fn sccp_penalty_rejects_action_tuple_and_identity_substitution_before_movement() {
    let (state, key, _) = sccp_penalty_fixture(1);
    let (actions, _) = PenaltyApplier::new(&state, None)
        .derive_npos_penalty_actions(&penalty_header(2))
        .unwrap();
    let NposPenaltyAction::ConsensusSlash(original) = &actions[0] else {
        panic!("slash first")
    };
    let view = state.view();
    let record = view.world().consensus_evidence().get(&key).unwrap();
    assert!(sccp::action_liability(view.world(), record, original).is_ok());
    for mutation in 0..6 {
        let mut action = original.clone();
        match mutation {
            0 => action.lane_id = LaneId::new(42),
            1 => action.validator = AccountId::new(roster()[2].public_key().clone()),
            2 => action.signer = 0,
            3 => action.peer_id = roster()[2].clone(),
            4 => action.slash_id = Hash::new(b"foreign slash id"),
            5 => action.evidence_key = Hash::new(b"foreign evidence id"),
            _ => unreachable!(),
        }
        assert!(
            sccp::action_liability(view.world(), record, &action).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn sccp_penalty_later_sink_failure_rolls_back_slash_and_applied_marker() {
    let (state, key, validator) = sccp_penalty_fixture(1);
    let (actions, _) = PenaltyApplier::new(&state, None)
        .derive_npos_penalty_actions(&penalty_header(2))
        .unwrap();
    let (definition, _, _) = penalty_staking_ids();
    let mut block = state
        .consensus_effects_probe_block(penalty_header(2))
        .unwrap();
    // A post-plan custody definition loss must reject the whole child, not mark Applied.
    {
        let mut tx = block.transaction();
        tx.world.asset_definitions.remove(definition);
        tx.apply();
    }
    assert!(
        validate_npos_consensus_effects_after_execution(
            &mut block,
            &NposConsensusEffects {
                parent_service_commit_qc: None,
                evidence_admissions: Vec::new(),
                penalty_actions: actions
            },
            &[],
            &[],
            2,
            0,
            2_000
        )
        .is_err()
    );
    assert_eq!(
        block
            .world
            .consensus_evidence
            .get(&key)
            .unwrap()
            .penalty_status,
        EvidencePenaltyStatus::Pending
    );
    assert_eq!(
        block
            .world
            .public_lane_validators
            .get(&(LaneId::SINGLE, validator))
            .unwrap()
            .total_stake,
        Quantity::from(10_000_u64)
    );
}

#[test]
fn sccp_penalty_multiple_generations_share_remaining_exposure_without_double_slash() {
    use iroha_data_model::block::consensus::RecordedEvidenceV1;
    use iroha_data_model::sumeragi_finality::certified_result::SccpFinalityHeaderV1;
    let (state, first, validator) = sccp_penalty_fixture(1);
    let mut data = state
        .world
        .consensus_evidence
        .view()
        .get(&first)
        .unwrap()
        .canonical_projection();
    let RecordedEvidenceV1::SccpForgery(material) = &mut data.evidence else {
        unreachable!()
    };
    material.generation += 1;
    let mut fields = SccpFinalityHeaderV1::parse(&material.evidence.header)
        .unwrap()
        .fields();
    fields.generation = material.generation;
    material.evidence.header = *SccpFinalityHeaderV1::from_fields(&fields)
        .unwrap()
        .as_bytes();
    data.attribution.scope = EvidenceScope::SccpGeneration {
        generation: material.generation,
    };
    let text = norito::json::to_json(&data).unwrap();
    let second = crate::sumeragi::evidence::record::parse_record(
        &mut norito::json::Parser::new(&text),
        state.evidence_preparation_budget(),
    )
    .unwrap();
    let second_key = Hash::prehashed(second.sccp_evidence_id().unwrap());
    assert_ne!(first, second_key);
    let mut rows = state.world.consensus_evidence.block();
    rows.insert(second_key, second);
    rows.commit();
    let (actions, _) = PenaltyApplier::new(&state, None)
        .derive_npos_penalty_actions(&penalty_header(2))
        .unwrap();
    let slashes = actions
        .iter()
        .filter_map(|action| match action {
            NposPenaltyAction::ConsensusSlash(slash) => Some(slash),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(slashes.len(), 1);
    assert_eq!(slashes[0].amount, Quantity::from(10_000_u64));
    assert_eq!(slashes[0].validator, validator);
    let mut marked = actions
        .iter()
        .filter_map(|action| match action {
            NposPenaltyAction::MarkConsensusEvidenceApplied(marker) => Some(marker.evidence_key),
            _ => None,
        })
        .collect::<Vec<_>>();
    marked.sort();
    let mut expected = [first, second_key];
    expected.sort();
    assert_eq!(marked, expected);
    assert!(
        state
            .world
            .consensus_evidence
            .view()
            .iter()
            .all(|(_, r)| r.penalty_status == EvidencePenaltyStatus::Pending)
    );
    assert_eq!(
        state
            .world
            .public_lane_validators
            .view()
            .get(&(LaneId::SINGLE, validator))
            .unwrap()
            .total_stake,
        Quantity::from(10_000_u64)
    );
}

#[test]
fn sccp_penalty_late_marker_refusal_rolls_back_prior_child_monetary_effects() {
    let (state, key, validator) = sccp_penalty_fixture(1);
    let (mut actions, index) = PenaltyApplier::new(&state, None)
        .derive_npos_penalty_actions(&penalty_header(2))
        .unwrap();
    let NposPenaltyAction::MarkConsensusEvidenceApplied(marker) = &mut actions[1] else {
        panic!("marker follows slash")
    };
    marker.height = 3;
    let mut block = state
        .consensus_effects_probe_block(penalty_header(2))
        .unwrap();
    {
        let mut tx = block.consensus_effects_transaction().unwrap();
        let result = apply_npos_consensus_effects_to_transaction(
            &mut tx,
            &NposConsensusEffects {
                parent_service_commit_qc: None,
                evidence_admissions: Vec::new(),
                penalty_actions: actions,
            },
            Some(&index),
            &[],
            &[],
            2,
            0,
            2_000,
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("wrong block height")
        );
        assert_eq!(
            tx.world
                .public_lane_validators
                .get(&(LaneId::SINGLE, validator.clone()))
                .unwrap()
                .total_stake,
            Quantity::zero(),
            "first monetary effect happened only in the failed child"
        );
    }
    assert_eq!(
        block
            .world
            .public_lane_validators
            .get(&(LaneId::SINGLE, validator))
            .unwrap()
            .total_stake,
        Quantity::from(10_000_u64)
    );
    assert_eq!(
        block
            .world
            .consensus_evidence
            .get(&key)
            .unwrap()
            .penalty_status,
        EvidencePenaltyStatus::Pending
    );
}
