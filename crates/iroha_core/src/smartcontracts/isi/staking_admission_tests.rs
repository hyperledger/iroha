// Initial-dispatch fixtures retain the component World and its explicit Nexus,
// then authenticate an original signed genesis before ordinary H2 execution.
// This grants no authority to a synthetic header or unretained source hash.
fn original_staking_state(
    component: State,
    nexus: iroha_config::parameters::actual::Nexus,
) -> State {
    use crate::sumeragi::{
        startup,
        test_chain::{CertifiedTestChain, TestChainConfig},
    };
    let mut config = TestChainConfig::new(component.world, 0);
    config.chain_id = component.chain_id;
    config.nexus = Some(nexus);
    config.governance = Some(component.gov);
    let account = AccountId::new(config.genesis_key.public_key().clone());
    let mode = config.consensus_mode;
    let prepared = CertifiedTestChain::prepare(config).expect("original signed staking genesis");
    let state = std::sync::Arc::try_unwrap(prepared.state)
        .unwrap_or_else(|_| panic!("unpublished staking State is unique"));
    startup::apply_genesis(
        &state,
        prepared.genesis.block().clone(),
        &account,
        mode.into(),
        None,
    )
    .expect("apply original authenticated staking genesis");
    state
}

fn original_staking_header(state: &State) -> iroha_data_model::block::BlockHeader {
    iroha_data_model::block::BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        1,
        0,
    )
}

#[test]
fn staking_initial_fixture_owns_original_root_and_retains_epoch_policy() {
    let mut component = setup_state();
    set_epoch_length(&mut component, 6);
    let nexus = component.nexus_snapshot();
    let original_lanes = nexus.lane_catalog.clone();
    let state = original_staking_state(component, nexus);
    let parent = state
        .view()
        .latest_block_hash()
        .expect("committed original genesis");
    assert_eq!(state.network_id_ref().into_genesis_hash(), parent);
    let header = original_staking_header(&state);
    assert_eq!(header.prev_block_hash(), Some(parent));
    let mut block = state.block(header);
    let mut stx = block.transaction_for_callback_testing();
    assert!(crate::executor::root_scope::execution_root_scope(&mut stx).is_ok());
    assert_eq!(
        stx.world
            .sumeragi_npos_parameters()
            .expect("original policy decoder completes")
            .expect("retained epoch policy")
            .epoch_length_blocks
            .get(),
        6
    );
    assert_eq!(stx.nexus.lane_catalog, original_lanes);
    drop(stx);
    drop(block);
    let component = setup_state();
    let mut block = component.block(original_staking_header(&component));
    let mut stx = block.transaction_for_callback_testing();
    assert!(crate::executor::root_scope::execution_root_scope(&mut stx).is_err());
}

// Exact candidate-consent, account-authority, and transaction rollback controls.
fn signed_candidate(
    stx: &StateTransaction<'_, '_>,
    validator: &AccountId,
    peer_key: &KeyPair,
    stake: u64,
    lane_id: LaneId,
) -> RegisterPublicLaneCandidate {
    let mut registration = RegisterPublicLaneValidator::new(
        lane_id,
        validator.clone(),
        PeerId::new(peer_key.public_key().clone()),
        validator.clone(),
        Quantity::from(stake),
        Metadata::default(),
        fixture_registration_plan(&stx, lane_id, &validator, Quantity::from(stake)),
    );
    let registered = stx
        .world
        .peers
        .iter()
        .any(|peer| peer == &registration.peer_id);
    let key_height = if registered || stx._curr_block.is_genesis() {
        stx.block_height()
    } else {
        stx.block_height()
            + stx
                .world
                .parameters
                .get()
                .sumeragi
                .key_activation_lead_blocks
    };
    let activation_height = next_unfrozen_election_height(
        key_height,
        stx.world
            .sumeragi_npos_parameters()
            .expect("original policy decoder completes")
            .expect("NPoS schedule")
            .epoch_length_blocks
            .get(),
    )
    .expect("election height");
    registration.monetary_plan.precondition =
        PublicLaneMonetaryPreconditionV1::Registration(PublicLaneMonetaryRegistrationV1 {
            activation_height,
        });
    let authorization = PublicLaneCandidateAuthorization::new(
        *stx.network_id(),
        registration.clone(),
        activation_height,
    );
    RegisterPublicLaneCandidate {
        registration,
        activation_height,
        proof_of_possession: iroha_crypto::bls_normal_pop_prove(peer_key.private_key())
            .expect("candidate PoP"),
        peer_signature: iroha_crypto::SignatureOf::try_new(peer_key.private_key(), &authorization)
            .expect("candidate consent"),
    }
}

#[test]
fn initial_executor_candidate_bonds_after_key_lead_without_joining_current_topology() {
    let mut state = setup_state();
    set_epoch_length(&mut state, 6);
    let nexus = state.nexus_snapshot();
    let state = original_staking_state(state, nexus);
    let mut block = state.block(original_staking_header(&state));
    let mut stx = block.transaction_for_callback_testing();
    let (validator, _, escrow, definition) = prepare_accounts(&mut stx);
    stx.world
        .parameters
        .get_mut()
        .sumeragi
        .key_activation_lead_blocks = 7;
    let peer_key = checked_keypair_with_algorithm(Algorithm::BlsNormal);
    let candidate = signed_candidate(&stx, &validator, &peer_key, 1000, LaneId::new(42));
    let peer = candidate.registration.peer_id.clone();
    let prior_topology = stx.commit_topology.get().clone();
    crate::executor::Executor::Initial
        .execute_instruction(&mut stx, &validator, candidate.into())
        .expect("ordinary stake owner can register a candidate without peer administration");
    let record = stx
        .world
        .public_lane_validators
        .get(&(LaneId::new(42), validator.clone()))
        .expect("candidate record");
    assert_eq!(record.activation_height, 19);
    assert_eq!(
        record.status,
        PublicLaneValidatorStatus::PendingActivation(19)
    );
    assert!(!validator_election_eligible_at_height(record, 18));
    assert!(validator_election_eligible_at_height(record, 19));
    assert_eq!(stx.commit_topology.get(), &prior_topology);
    assert!(!stx.commit_topology.iter().any(|voter| voter == &peer));
    assert_eq!(
        peer_consensus_key_gate_for_lane(&stx.world, &peer, 2, LaneId::new(42)),
        ConsensusKeyGate::NotYetActive
    );
    assert_eq!(
        peer_consensus_key_gate_for_lane(&stx.world, &peer, 19, LaneId::new(42)),
        ConsensusKeyGate::Live
    );
    assert!(
        !crate::state::peer_has_live_consensus_key_for_role(
            &stx.world,
            &peer,
            19,
            ConsensusKeyRole::Validator
        ),
        "participant enrollment cannot create a global voting key"
    );
    let escrow_asset = stx
        .world
        .assets
        .get(&AssetId::new(definition, escrow))
        .expect("stake escrow");
    assert_eq!(escrow_asset.as_ref(), &Quantity::from(1000_u64));
}

#[test]
fn candidate_rejects_other_authority_tampered_consent_and_invalid_pop() {
    let state = setup_state();
    let mut block = state.block(block_header_with_height(2));
    let mut stx = block.transaction_for_callback_testing();
    let (validator, intruder, _, _) = prepare_accounts(&mut stx);
    let peer_key = checked_keypair_with_algorithm(Algorithm::BlsNormal);
    let candidate = signed_candidate(&stx, &validator, &peer_key, 1000, LaneId::new(42));
    let peer = candidate.registration.peer_id.clone();
    assert!(candidate.clone().execute(&intruder, &mut stx).is_err());
    let mut tampered = candidate.clone();
    tampered.registration.initial_stake = Quantity::from(2000_u64);
    assert!(tampered.execute(&validator, &mut stx).is_err());
    let mut invalid_pop = candidate;
    invalid_pop.proof_of_possession = vec![0; 96];
    assert!(invalid_pop.execute(&validator, &mut stx).is_err());
    assert!(!stx.world.peers.iter().any(|id| id == &peer));
    assert!(
        stx.world
            .public_lane_validators
            .get(&(LaneId::new(42), validator.clone()))
            .is_none()
    );
}

#[test]
fn failed_candidate_transaction_rolls_back_peer_key_and_stake() {
    let component = setup_state();
    let nexus = component.nexus_snapshot();
    let state = original_staking_state(component, nexus);
    let mut block = state.block(original_staking_header(&state));
    let (validator, delegator, escrow, definition, nexus) = {
        let mut stx = block.transaction_for_callback_testing();
        let (validator, delegator, escrow, definition) = prepare_accounts(&mut stx);
        let nexus = stx.nexus.clone();
        stx.apply();
        (validator, delegator, escrow, definition, nexus)
    };
    let peer_key = checked_keypair_with_algorithm(Algorithm::BlsNormal);
    let peer = PeerId::new(peer_key.public_key().clone());
    {
        let mut stx = block.transaction_for_callback_testing();
        stx.nexus = nexus.clone();
        let lane = LaneId::new(42);
        let candidate = signed_candidate(&stx, &validator, &peer_key, 1_000, lane);
        crate::executor::Executor::Initial
            .execute_instruction(&mut stx, &validator, candidate.into())
            .expect("first transaction instruction bonds the candidate");
        assert!(
            stx.world.peers.iter().any(|id| id == &peer),
            "the rejected transaction must contain a successful peer write"
        );
        assert!(
            stx.world
                .public_lane_stake_custody
                .get(&(lane, validator.clone()))
                .is_some(),
            "the rejected transaction must contain a successful custody write"
        );
        let unauthorized_bond = BondPublicLaneStake {
            monetary_plan: fixture_bond_plan(&stx, lane, &validator, &delegator, &Quantity::one()),
            lane_id: lane,
            validator: validator.clone(),
            staker: delegator.clone(),
            amount: Quantity::one(),
            metadata: Metadata::default(),
        };
        let error = crate::executor::Executor::Initial
            .execute_instruction(&mut stx, &validator, unauthorized_bond.into())
            .expect_err("a later unauthorized bond rejects the whole transaction");
        assert!(matches!(
            error,
            iroha_data_model::executor::ValidationFail::InstructionFailed(
                Error::InvariantViolation(message)
            ) if message.contains("authority must match staker")
        ));
        // A rejected multi-instruction transaction drops its entire StateTransaction.
    }
    let mut stx = block.transaction_for_callback_testing();
    stx.nexus = nexus;
    assert!(!stx.world.peers.iter().any(|id| id == &peer));
    assert!(
        stx.world
            .consensus_keys_by_pk()
            .get(&peer.public_key().to_string())
            .is_none()
    );
    assert!(
        stx.world
            .public_lane_validators
            .get(&(LaneId::new(42), validator.clone()))
            .is_none()
    );
    assert!(
        stx.world
            .assets
            .get(&AssetId::new(definition.clone(), escrow))
            .is_none()
    );
    assert_eq!(
        stx.world
            .assets
            .get(&AssetId::new(definition, validator))
            .expect("candidate's source balance after rollback")
            .as_ref(),
        &Quantity::from(10_000_u64)
    );
}

#[test]
fn activation_requires_validator_authority_after_genesis() {
    let state = setup_state();
    let mut block = state.block(block_header_with_height(2));
    let mut stx = block.transaction_for_callback_testing();
    let (validator, intruder, _, _) = prepare_accounts(&mut stx);
    let lane_id = LaneId::new(42);
    RegisterPublicLaneValidator::new(
        lane_id,
        validator.clone(),
        validator_peer_id(&validator),
        validator.clone(),
        Quantity::from(1000_u64),
        Metadata::default(),
        fixture_registration_plan(&stx, lane_id, &validator, Quantity::from(1000_u64)),
    )
    .execute(&validator, &mut stx)
    .expect("registration");
    let instruction = ActivatePublicLaneValidator::new(lane_id, validator.clone());
    let error = instruction
        .clone()
        .execute(&intruder, &mut stx)
        .expect_err("foreign activation");
    assert!(error.to_string().contains("authority must match validator"));
    let error = instruction
        .execute(&validator, &mut stx)
        .expect_err("future boundary");
    assert!(error.to_string().contains("activation height not reached"));
}

#[test]
fn registered_participant_peer_requires_consent_even_for_the_validator_owner() {
    let state = setup_state();
    let mut block = state.block(block_header_with_height(2));
    let mut stx = block.transaction_for_callback_testing();
    let (validator, _, _, _) = prepare_accounts(&mut stx);
    let peer_key = checked_keypair_with_algorithm(Algorithm::BlsNormal);
    let peer = PeerId::new(peer_key.public_key().clone());
    stx.world.peers.push(peer.clone());
    stx.commit_topology.get_mut().push(peer.clone());
    seed_validator_consensus_key(&mut stx, &peer, ConsensusKeyStatus::Active);
    let key_id = crate::state::derive_committee_key_id(peer.public_key());
    stx.world
        .consensus_keys
        .get_mut(&key_id)
        .expect("live key")
        .pop = Some(iroha_crypto::bls_normal_pop_prove(peer_key.private_key()).expect("PoP"));
    let lane_id = LaneId::new(42);
    let candidate = signed_candidate(&stx, &validator, &peer_key, 1000, lane_id);
    let error = candidate
        .registration
        .clone()
        .execute(&validator, &mut stx)
        .expect_err("plain registration cannot squat another consensus identity");
    assert!(error.to_string().contains("network-bound consent"));
    candidate
        .execute(&validator, &mut stx)
        .expect("signed participant candidate owns its existing peer binding");
    assert_eq!(
        stx.world
            .public_lane_validators
            .get(&(lane_id, validator.clone()))
            .expect("registered participant")
            .peer_id,
        peer
    );
}

#[test]
fn pending_rebind_requires_network_bound_replacement_peer_consent() {
    let mut state = setup_state();
    set_epoch_length(&mut state, 6);
    let mut block = state.block(block_header_with_height(2));
    let mut stx = block.transaction_for_callback_testing();
    let (validator, _, _, _) = prepare_accounts(&mut stx);
    let lane_id = LaneId::new(42);
    RegisterPublicLaneValidator::new(
        lane_id,
        validator.clone(),
        validator_peer_id(&validator),
        validator.clone(),
        Quantity::from(1000_u64),
        Metadata::default(),
        fixture_registration_plan(&stx, lane_id, &validator, Quantity::from(1000_u64)),
    )
    .execute(&validator, &mut stx)
    .expect("register owner-bound peer");
    let replacement_key = checked_keypair_with_algorithm(Algorithm::BlsNormal);
    let replacement = PeerId::new(replacement_key.public_key().clone());
    stx.world.peers.push(replacement.clone());
    seed_validator_consensus_key(&mut stx, &replacement, ConsensusKeyStatus::Active);
    let activation_height = stx
        .world
        .public_lane_validators
        .get(&(lane_id, validator.clone()))
        .expect("registered validator")
        .activation_height;
    let payload = PublicLanePeerBindingAuthorization::new(
        *stx.network_id(),
        lane_id,
        validator.clone(),
        replacement.clone(),
        activation_height,
        validator_peer_id(&validator),
    );
    let mut stale_payload = payload.clone();
    stale_payload.activation_height += 6;
    let stale_signature =
        iroha_crypto::SignatureOf::try_new(replacement_key.private_key(), &stale_payload)
            .expect("future-tenure signature");
    let error = RebindPublicLaneValidatorPeer::new(
        lane_id,
        validator.clone(),
        replacement.clone(),
        stale_signature,
    )
    .execute(&validator, &mut stx)
    .expect_err("consent from another validator tenure");
    assert!(error.to_string().contains("replacement peer signature"));
    let mut wrong_previous = payload.clone();
    wrong_previous.previous_peer_id = replacement.clone();
    let stale_signature =
        iroha_crypto::SignatureOf::try_new(replacement_key.private_key(), &wrong_previous)
            .expect("wrong-binding signature");
    assert!(
        RebindPublicLaneValidatorPeer::new(
            lane_id,
            validator.clone(),
            replacement.clone(),
            stale_signature,
        )
        .execute(&validator, &mut stx)
        .is_err()
    );
    let mut wrong_network = payload.clone();
    wrong_network.network_id = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"another-network")),
    );
    let wrong_network_signature =
        iroha_crypto::SignatureOf::try_new(replacement_key.private_key(), &wrong_network)
            .expect("wrong-network signature");
    assert!(
        RebindPublicLaneValidatorPeer::new(
            lane_id,
            validator.clone(),
            replacement.clone(),
            wrong_network_signature,
        )
        .execute(&validator, &mut stx)
        .is_err()
    );
    let signature = iroha_crypto::SignatureOf::try_new(replacement_key.private_key(), &payload)
        .expect("replacement consent");
    let replay_signature = signature.clone();
    RebindPublicLaneValidatorPeer::new(lane_id, validator.clone(), replacement.clone(), signature)
        .execute(&validator, &mut stx)
        .expect("consenting replacement");
    let replay = RebindPublicLaneValidatorPeer::new(
        lane_id,
        validator.clone(),
        replacement.clone(),
        replay_signature,
    )
    .execute(&validator, &mut stx)
    .expect_err("old-binding consent cannot authorize a same-peer replay");
    assert!(replay.to_string().contains("replacement peer signature"));
    assert_eq!(
        stx.world
            .public_lane_validators
            .get(&(lane_id, validator))
            .expect("validator")
            .peer_id,
        replacement
    );
}

#[test]
fn global_candidate_without_authenticated_schedule_fails_before_any_write() {
    let state = setup_state();
    let mut block = state.block(block_header_with_height(2));
    let (validator, escrow, definition, nexus) = {
        let mut stx = block.transaction_for_callback_testing();
        let (validator, _, escrow, definition) = prepare_accounts(&mut stx);
        let nexus = stx.nexus.clone();
        stx.apply();
        (validator, escrow, definition, nexus)
    };
    let mut stx = block.transaction_for_callback_testing();
    stx.nexus = nexus.clone();
    let peer_key = checked_keypair_with_algorithm(Algorithm::BlsNormal);
    let mut candidate = signed_candidate(&stx, &validator, &peer_key, 1000, LaneId::new(42));
    candidate.registration.lane_id = LaneId::SINGLE;
    let authorization = PublicLaneCandidateAuthorization::new(
        *stx.network_id(),
        candidate.registration.clone(),
        candidate.activation_height,
    );
    candidate.peer_signature =
        iroha_crypto::SignatureOf::try_new(peer_key.private_key(), &authorization)
            .expect("exact candidate consent");
    let error = candidate
        .execute(&validator, &mut stx)
        .expect_err("global admission needs the exact committed finality anchor");
    assert!(matches!(
        error,
        Error::InvariantViolation(message)
            if message.as_ref() == "height 0 is not committed in this view"
    ));
    // Reject the actual transaction, then inspect the independent next overlay.
    drop(stx);
    let mut stx = block.transaction_for_callback_testing();
    stx.nexus = nexus;
    assert!(
        !stx.world
            .peers
            .iter()
            .any(|peer| peer.public_key() == peer_key.public_key())
    );
    assert!(
        stx.world
            .consensus_keys_by_pk()
            .get(&peer_key.public_key().to_string())
            .is_none()
    );
    assert!(
        stx.world
            .public_lane_validators
            .get(&(LaneId::SINGLE, validator))
            .is_none()
    );
    assert!(
        stx.world
            .assets
            .get(&AssetId::new(definition, escrow))
            .is_none()
    );
}

#[test]
fn candidate_requires_committed_schedule_and_rejects_expired_tenure_consent() {
    let state = setup_state();
    let mut block = state.block(block_header_with_height(2));
    let mut stx = block.transaction_for_callback_testing();
    let (validator, _, _, _) = prepare_accounts(&mut stx);
    let peer_key = checked_keypair_with_algorithm(Algorithm::BlsNormal);
    let candidate = signed_candidate(&stx, &validator, &peer_key, 1000, LaneId::new(42));
    let mut stale = candidate.clone();
    stale.activation_height += 1;
    let error = stale
        .execute(&validator, &mut stx)
        .expect_err("consent for another boundary");
    assert!(
        error
            .to_string()
            .contains("consent targets activation height")
    );
    stx.world
        .parameters
        .get_mut()
        .custom
        .remove(&SumeragiNposParameters::parameter_id());
    let error = candidate
        .execute(&validator, &mut stx)
        .expect_err("missing committed schedule");
    assert!(
        error
            .to_string()
            .contains("committed NPoS election parameters")
    );
    assert!(
        !stx.world
            .peers
            .iter()
            .any(|peer| peer.public_key() == peer_key.public_key())
    );
}

#[test]
fn participant_binding_does_not_enter_global_pool_even_with_validator_key() {
    let state = setup_state();
    let mut block = state.block(block_header_with_height(2));
    let mut stx = block.transaction_for_callback_testing();
    let (validator, _, escrow, definition) = prepare_accounts(&mut stx);
    stx.commit_topology
        .get_mut()
        .push(validator_peer_id(&validator));
    let peer_key = checked_keypair_with_algorithm(Algorithm::BlsNormal);
    let peer = PeerId::new(peer_key.public_key().clone());
    let _ = stx.world.peers.push(peer.clone());
    seed_validator_consensus_key(&mut stx, &peer, ConsensusKeyStatus::Active);
    let committee_key = crate::state::derive_committee_key_id(peer.public_key());
    stx.world
        .consensus_keys
        .get_mut(&committee_key)
        .expect("participant consensus key")
        .pop = Some(iroha_crypto::bls_normal_pop_prove(peer_key.private_key()).expect("PoP"));
    let candidate = signed_candidate(&stx, &validator, &peer_key, 1000, LaneId::new(42));
    candidate
        .execute(&validator, &mut stx)
        .expect("participant candidate can retain its own signed peer binding");
    assert!(
        stx.world
            .public_lane_validators
            .get(&(LaneId::new(42), validator))
            .is_some()
    );
    assert_eq!(
        stx.world
            .assets
            .get(&AssetId::new(definition, escrow))
            .expect("participant stake escrow")
            .as_ref(),
        &Quantity::from(1000_u64)
    );
    let global_candidates = crate::state::epoch_validator_candidate_peer_ids_from_world(
        &stx.world,
        stx.commit_topology.iter().cloned(),
        stx.block_height(),
        &stx.nexus,
        None,
    );
    assert!(!global_candidates.contains(&peer));
}

#[test]
fn participant_exit_and_unbonds_keep_reserved_custody_until_liability_ends() {
    let mut state = setup_state();
    set_epoch_length(&mut state, 6);
    let mut block = state.block(block_header_with_height(2));
    let mut stx = block.transaction_for_callback_testing();
    let (validator, delegator, escrow, definition) = prepare_accounts(&mut stx);
    let lane_id = LaneId::new(42);
    stx.nexus.staking.min_validator_stake = 1000_u64.into();
    stx.nexus.staking.unbonding_delay = Duration::ZERO;
    RegisterPublicLaneValidator::new(
        lane_id,
        validator.clone(),
        validator_peer_id(&validator),
        validator.clone(),
        2000_u64.into(),
        Metadata::default(),
        fixture_registration_plan(&stx, lane_id, &validator, Quantity::from(2000_u64)),
    )
    .execute(&validator, &mut stx)
    .expect("seed retained validator before topology freeze");
    BondPublicLaneStake {
        monetary_plan: fixture_bond_plan(
            &stx,
            lane_id,
            &(validator.clone()),
            &(delegator.clone()),
            &(100_u64.into()),
        ),
        lane_id,
        validator: validator.clone(),
        staker: delegator.clone(),
        amount: 100_u64.into(),
        metadata: Metadata::default(),
    }
    .execute(&delegator, &mut stx)
    .expect("delegation is admitted before the exit request");
    let release_at_ms = stx.block_unix_timestamp_ms();
    ExitPublicLaneValidator {
        lane_id,
        validator: validator.clone(),
        release_at_ms,
    }
    .execute(&validator, &mut stx)
    .expect("participant exit records a future election cutoff");
    let unbond = |staker: &AccountId, amount, label| SchedulePublicLaneUnbond {
        lane_id,
        validator: validator.clone(),
        staker: staker.clone(),
        amount: Quantity::from(amount),
        request_id: Hash::new(label),
        release_at_ms,
    };
    unbond(&validator, 1000_u64, "participant-self-unbond-a")
        .execute(&validator, &mut stx)
        .expect("owner may schedule a slashable withdrawal");
    unbond(&validator, 1000_u64, "participant-self-unbond-b")
        .execute(&validator, &mut stx)
        .expect(
            "a participant may schedule the rest of its self stake while custody stays reserved",
        );
    let nexus = stx.nexus.clone();
    let delegator_asset = AssetId::new(definition.clone(), delegator.clone());
    let delegator_before = stx
        .world
        .assets
        .get(&delegator_asset)
        .unwrap()
        .as_ref()
        .clone();
    stx.apply();
    let mut stx = block.transaction_for_callback_testing();
    stx.nexus = nexus.clone();
    let error = BondPublicLaneStake {
        monetary_plan: fixture_bond_plan(
            &stx,
            lane_id,
            &validator,
            &delegator,
            Quantity::from(100_u64),
        ),
        lane_id,
        validator: validator.clone(),
        staker: delegator.clone(),
        amount: 100_u64.into(),
        metadata: Metadata::default(),
    }
    .execute(&delegator, &mut stx)
    .expect_err("an exit request rejects new stake even in a participant lane");
    assert!(matches!(
        error,
        Error::InvariantViolation(message) if message.contains("does not accept new stake")
    ));
    // Drop the rejected transaction; all existing withdrawal liabilities survive.
    drop(stx);
    let mut stx = block.transaction_for_callback_testing();
    stx.nexus = nexus;
    assert_eq!(
        stx.world.assets.get(&delegator_asset).unwrap().as_ref(),
        &delegator_before
    );
    unbond(&delegator, 100_u64, "global-safe-delegator-unbond")
        .execute(&delegator, &mut stx)
        .expect("delegator may schedule a slashable withdrawal");
    let key = (lane_id, validator.clone());
    let record = stx
        .world
        .public_lane_validators
        .get(&key)
        .expect("retained validator");
    assert!(record.self_stake.is_zero());
    assert!(record.election_exit_height.is_some());
    assert!(record.deactivation_height.is_some());
    let share = stx
        .world
        .public_lane_stake_shares
        .get(&(lane_id, validator.clone(), validator))
        .expect("retained pending self stake");
    assert_eq!(share.pending_unbonds.len(), 2);
    assert!(
        share
            .pending_unbonds
            .values()
            .all(|pending| { pending.liability_release_height > pending.slashable_through_height })
    );
    let escrow_balance = stx
        .world
        .assets
        .get(&AssetId::new(definition, escrow))
        .expect("principal remains in escrow");
    assert_eq!(escrow_balance.as_ref(), &Quantity::from(2100_u64));
}

#[test]
fn self_bond_restores_minimum_without_rewriting_candidate_identity() {
    let mut state = setup_state();
    set_epoch_length(&mut state, 6);
    let mut block = state.block(block_header_with_height(2));
    let mut stx = block.transaction_for_callback_testing();
    let (validator, _, _, _) = prepare_accounts(&mut stx);
    let lane_id = LaneId::new(42);
    RegisterPublicLaneValidator::new(
        lane_id,
        validator.clone(),
        validator_peer_id(&validator),
        validator.clone(),
        1000_u64.into(),
        Metadata::default(),
        fixture_registration_plan(&stx, lane_id, &validator, Quantity::from(1000_u64)),
    )
    .execute(&validator, &mut stx)
    .expect("seed retained validator");
    let original_peer = stx
        .world
        .public_lane_validators
        .get(&(lane_id, validator.clone()))
        .expect("candidate")
        .peer_id
        .clone();
    // A governance minimum increase may be met by a further exact self bond.
    stx.nexus.staking.min_validator_stake = 2000_u64.into();
    BondPublicLaneStake {
        monetary_plan: fixture_bond_plan(
            &stx,
            lane_id,
            &validator,
            &validator,
            Quantity::from(1000_u64),
        ),
        lane_id,
        validator: validator.clone(),
        staker: validator.clone(),
        amount: 1000_u64.into(),
        metadata: Metadata::default(),
    }
    .execute(&validator, &mut stx)
    .expect("owner may restore the minimum without changing the peer binding");
    assert_eq!(
        stx.world
            .public_lane_validators
            .get(&(lane_id, validator.clone()))
            .expect("validator")
            .self_stake,
        Quantity::from(2000_u64)
    );
    assert_eq!(
        stx.world
            .public_lane_validators
            .get(&(lane_id, validator.clone()))
            .expect("candidate")
            .peer_id,
        original_peer
    );
}

#[test]
fn frozen_global_binding_allows_requests_but_rejects_tenure_or_peer_rewrites() {
    let state = setup_state();
    let mut block = state.block(block_header_with_height(2));
    let mut stx = block.transaction_for_callback_testing();
    let (validator, delegator, _, _) = prepare_accounts(&mut stx);
    let original = PublicLaneValidatorRecord {
        lane_id: LaneId::SINGLE,
        validator: validator.clone(),
        peer_id: validator_peer_id(&validator),
        stake_account: validator.clone(),
        total_stake: Quantity::from(1000_u64),
        self_stake: Quantity::from(1000_u64),
        metadata: Metadata::default(),
        status: PublicLaneValidatorStatus::Active,
        activation_height: 1,
        election_exit_height: None,
        deactivation_height: None,
    };
    let key = (LaneId::SINGLE, validator);
    stx.world
        .public_lane_validators
        .insert(key.clone(), original.clone());
    stx.commit_topology.get_mut().push(original.peer_id.clone());
    let mut requested = original.clone();
    requested.election_exit_height = Some(13);
    requested.status = PublicLaneValidatorStatus::Exiting(0);
    ensure_frozen_validator_binding_preserved(&stx, &requested, "request_exit")
        .expect("an exit request cannot revoke the authenticated tenure");
    for mutation in 0..3 {
        let mut replacement = requested.clone();
        match mutation {
            0 => replacement.peer_id = validator_peer_id(&delegator),
            1 => replacement.activation_height += 1,
            _ => replacement.deactivation_height = Some(13),
        }
        let error = ensure_frozen_validator_binding_preserved(&stx, &replacement, "rewrite")
            .expect_err("the current seat must retain its peer and actual tenure");
        assert!(
            error
                .to_string()
                .contains("current or frozen validator binding")
        );
        assert_eq!(stx.world.public_lane_validators.get(&key), Some(&original));
    }
}

#[test]
fn requested_exit_excludes_future_elections_without_ending_voting_or_slashing_tenure() {
    let owner = ALICE_ID.clone();
    let mut record = PublicLaneValidatorRecord {
        lane_id: LaneId::SINGLE,
        validator: owner.clone(),
        peer_id: validator_peer_id(&owner),
        stake_account: owner,
        total_stake: Quantity::from(1000_u64),
        self_stake: Quantity::from(1000_u64),
        metadata: Metadata::default(),
        status: PublicLaneValidatorStatus::Exiting(0),
        activation_height: 1,
        election_exit_height: None,
        deactivation_height: None,
    };
    schedule_validator_deactivation(&mut record, 13, true).unwrap();
    assert!(validator_election_eligible_at_height(&record, 12));
    assert!(!validator_election_eligible_at_height(&record, 13));
    assert!(validator_tenure_contains_height(&record, 100).unwrap());
    assert_eq!(record.deactivation_height, None);
    schedule_validator_deactivation(&mut record, 19, false).unwrap();
    assert_eq!(record.election_exit_height, Some(13));
    assert_eq!(record.deactivation_height, Some(19));
    assert!(validator_tenure_contains_height(&record, 18).unwrap());
    assert!(!validator_tenure_contains_height(&record, 19).unwrap());
}
