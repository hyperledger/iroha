// Current metadata topology publication and rollback invariants.
state_test! { sync apply_without_execution_preserves_supplied_committee_without_world_peer_append
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::default(), kura, query);
    let keypairs = configure_commit_topology(&state, 4);
    let_row! { base_topology: Vec<_> = keypairs .iter() .map(|kp| PeerId::new(kp.public_key().clone())) .collect() };
    let_row! { new_peer = PeerId::new( crate::state::checked_keypair_with_algorithm(Algorithm::BlsNormal) .public_key() .clone(), ) };
    {
        let mut world_block = state.world.block();
        {
            let mut peers = world_block.peers_mut_for_testing().transaction();
            peers.clear();
            peers.extend(base_topology.clone());
            peers.push(new_peer.clone());
            peers.apply();
        }
        world_block.commit();
    }
    // This fixture tests metadata topology selection, with no executable Network sources.
    let signed_block = empty_signed_block_after(None, 1);
    store_block_for_state_commit(&state.kura, &signed_block);
    let mut state_block = state.block(signed_block.header());
    let valid = ValidBlock::new_unverified_for_tests(signed_block);
    let committed = valid.commit_unchecked(crate::block::reserve_block_for_tests()).unpack(|_| {});
    let prev_hash = committed.as_ref().hash();
    let _ = state_block.apply_without_execution(&committed, base_topology.clone());
    state_block.commit().expect("commit state block");
    let mut expected_topology = Topology::new(base_topology.clone());
    expected_topology.block_committed(base_topology.clone(), prev_hash);
    let expected = expected_topology.as_ref().to_vec();
    let view = state.view();
    let actual: Vec<_> = view.commit_topology().iter().cloned().collect();
    assert_eq!(actual, expected);
    assert!(!actual.contains(&new_peer), "a World peer cannot join the supplied native committee");
    assert!(view.world.peers().iter().any(|peer| peer == &new_peer));
    let prev: Vec<_> = view.prev_commit_topology().iter().cloned().collect();
    assert_eq!(prev, base_topology);
}
state_test! { sync height_mismatch_does_not_publish_staged_commit_topology
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::default(), kura, query);
    let keypairs = configure_commit_topology(&state, 4);
    let_row! { base_topology: Vec<_> = keypairs .iter() .map(|kp| PeerId::new(kp.public_key().clone())) .collect() };
    assert_eq!(state.commit_topology_snapshot(), base_topology);
    assert!(
        state.prev_commit_topology_snapshot().is_empty(),
        "test setup should start with no previous commit topology"
    );
    let_row! { new_peer = PeerId::new( crate::state::checked_keypair_with_algorithm(Algorithm::BlsNormal) .public_key() .clone(), ) };
    {
        let mut world_block = state.world.block();
        {
            let mut peers = world_block.peers_mut_for_testing().transaction();
            peers.clear();
            peers.extend(base_topology.clone());
            peers.push(new_peer.clone());
            peers.apply();
        }
        world_block.commit();
    }
    let first_block = empty_signed_block_after(None, 1);
    let second_block = empty_signed_block_after(Some(&first_block), 2);
    state.kura.store_block(crate::block::reserve_block_for_tests().initialize(first_block)).expect("retain exact predecessor");
    seed_committed_height_for_state_test(&state, 1);
    store_block_for_state_commit(&state.kura, &second_block);
    let mut state_block = state.block(second_block.header());
    let valid = ValidBlock::new_unverified_for_tests(second_block);
    let committed = valid.commit_unchecked(crate::block::reserve_block_for_tests()).unpack(|_| {});
    let _ = state_block.apply_without_execution(&committed, base_topology.clone());
    assert_eq!(state_block.prev_commit_topology.iter().cloned().collect::<Vec<_>>(), base_topology,
        "metadata preparation must stage the old topology before publication fails");
    assert_eq!(state_block.commit_topology.iter().cloned().collect::<Vec<_>>(), base_topology,
        "the rejected overlay must retain the exact supplied native committee");
    let_row! { err = state_block .commit() .expect_err("height mismatch must abort staged topology updates") };
    assert!(matches!(
        err,
        TransactionsBlockError::HeightMismatch {
            expected_current_height: 1,
            actual_current_height: 2
        }
    ));
    assert_eq!(
        state.commit_topology_snapshot(),
        base_topology,
        "height mismatch must not publish staged commit topology updates"
    );
    assert!(
        state.prev_commit_topology_snapshot().is_empty(),
        "height mismatch must not publish staged previous-topology updates"
    );
}
state_test! { sync apply_without_execution_keeps_world_peer_append_scoped_to_checkpoint_lanes
    use iroha_config::parameters::actual::LaneValidatorMode;
    use iroha_data_model::nexus::{LaneCatalog, LaneConfig as CatalogLaneConfig, LaneVisibility};
    let restricted_dataspace = DataSpaceId::new(1);
    let query = LiveQueryStore::start_test();
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    {
        let_row! { lane_catalog = LaneCatalog::new( NonZeroU32::new(2).expect("nonzero lane count"), vec![ CatalogLaneConfig::default(), CatalogLaneConfig { id: LaneId::new(1), dataspace_id: restricted_dataspace, alias: "restricted".to_string(), visibility: LaneVisibility::Restricted, ..CatalogLaneConfig::default() }, ], ) .expect("lane catalog") };
        nexus.lane_catalog = lane_catalog.clone();
        nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&lane_catalog);
        nexus.dataspace_catalog = dataspace_catalog_with_extra(restricted_dataspace);
        nexus.staking.public_validator_mode = LaneValidatorMode::StakeElected;
        nexus.staking.restricted_validator_mode = LaneValidatorMode::StakeElected;
        nexus.staking.min_validator_stake = 100_u64.into();
    }
    let state = State::new_with_nexus_for_testing(World::default(), nexus, query);
    let_row! { public_keypairs: Vec<_> = (0..4) .map(|_| crate::state::checked_keypair_with_algorithm(Algorithm::BlsNormal)) .collect() };
    let_row! { restricted_keypairs: Vec<_> = (0..4) .map(|_| crate::state::checked_keypair_with_algorithm(Algorithm::BlsNormal)) .collect() };
    let_row! { base_topology: Vec<_> = public_keypairs .iter() .map(|kp| PeerId::new(kp.public_key().clone())) .collect() };
    {
        let mut topo = state.commit_topology.block();
        topo.clear();
        for peer in &base_topology {
            topo.push(peer.clone());
        }
        topo.commit();
    }
    {
        let mut world_block = state.world.block();
        {
            let mut peers = world_block.peers_mut_for_testing().transaction();
            peers.clear();
            peers.extend(base_topology.clone());
            peers.extend(
                restricted_keypairs
                    .iter()
                    .map(|kp| PeerId::new(kp.public_key().clone())),
            );
            peers.apply();
        }
        for kp in &public_keypairs {
            let validator = AccountId::new(kp.public_key().clone());
            world_block.public_lane_validators.insert(
                (LaneId::SINGLE, validator.clone()),
                PublicLaneValidatorRecord {
                    lane_id: LaneId::SINGLE,
                    validator: validator.clone(),
                    peer_id: PeerId::new(kp.public_key().clone()),
                    stake_account: validator,
                    total_stake: iroha_primitives::numeric::Quantity::from(1_000_u32),
                    self_stake: iroha_primitives::numeric::Quantity::from(1_000_u32),
                    metadata: Metadata::default(),
                    status: PublicLaneValidatorStatus::Active,
                    activation_height: 1,
                    election_exit_height: None,
                    deactivation_height: None,
                },
            );
        }
        for kp in &restricted_keypairs {
            let validator = AccountId::new(kp.public_key().clone());
            world_block.public_lane_validators.insert(
                (LaneId::new(1), validator.clone()),
                PublicLaneValidatorRecord {
                    lane_id: LaneId::new(1),
                    validator: validator.clone(),
                    peer_id: PeerId::new(kp.public_key().clone()),
                    stake_account: validator,
                    total_stake: iroha_primitives::numeric::Quantity::from(1_000_u32),
                    self_stake: iroha_primitives::numeric::Quantity::from(1_000_u32),
                    metadata: Metadata::default(),
                    status: PublicLaneValidatorStatus::Active,
                    activation_height: 1,
                    election_exit_height: None,
                    deactivation_height: None,
                },
            );
        }
        world_block.commit();
    }
    seed_consensus_keys_with_pops(
        &state,
        &public_keypairs
            .iter()
            .chain(restricted_keypairs.iter())
            .cloned()
            .collect::<Vec<_>>(),
    );
    // This fixture tests metadata topology selection, with no executable Network sources.
    let signed_block = empty_signed_block_after(None, 1);
    store_block_for_state_commit(&state.kura, &signed_block);
    let mut state_block = state.block(signed_block.header());
    let valid = ValidBlock::new_unverified_for_tests(signed_block);
    let committed = valid.commit_unchecked(crate::block::reserve_block_for_tests()).unpack(|_| {});
    let prev_hash = committed.as_ref().hash();
    let _ = state_block.apply_without_execution(&committed, base_topology.clone());
    state_block.commit().expect("commit state block");
    let mut expected_topology = Topology::new(base_topology.clone());
    expected_topology.block_committed(base_topology.clone(), prev_hash);
    let expected = expected_topology.as_ref().to_vec();
    let view = state.view();
    let actual: Vec<_> = view.commit_topology().iter().cloned().collect();
    assert_eq!(actual, expected);
    let prev: Vec<_> = view.prev_commit_topology().iter().cloned().collect();
    assert_eq!(prev, base_topology);
}
state_test! { sync apply_without_execution_keeps_npos_commit_topology_without_world_peer_append
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::default(), kura, query);
    {
        let mut params = state.world.parameters.block();
        params.set_parameter(Parameter::Custom(
            SumeragiNposParameters::default().into_custom_parameter(),
        )).expect("valid fixture parameters");
        params.commit();
    }
    let keypairs = configure_commit_topology(&state, 4);
    let_row! { base_topology: Vec<_> = keypairs .iter() .map(|kp| PeerId::new(kp.public_key().clone())) .collect() };
    let_row! { new_peer = PeerId::new( crate::state::checked_keypair_with_algorithm(Algorithm::BlsNormal) .public_key() .clone(), ) };
    // This fixture tests metadata topology selection, with no executable Network sources.
    let signed_block = empty_signed_block_after(None, 1);
    store_block_for_state_commit(&state.kura, &signed_block);
    let mut state_block = state.block(signed_block.header());
    {
        let mut peers = state_block.world.peers_mut_for_testing().transaction();
        peers.clear();
        peers.extend(base_topology.clone());
        peers.push(new_peer);
        peers.apply();
    }
    let valid = ValidBlock::new_unverified_for_tests(signed_block);
    let committed = valid.commit_unchecked(crate::block::reserve_block_for_tests()).unpack(|_| {});
    let prev_hash = committed.as_ref().hash();
    let _ = state_block.apply_without_execution(&committed, base_topology.clone());
    state_block.commit().expect("commit state block");
    let mut expected_topology = Topology::new(base_topology.clone());
    expected_topology.block_committed(base_topology.clone(), prev_hash);
    let expected = expected_topology.as_ref().to_vec();
    let view = state.view();
    let actual: Vec<_> = view.commit_topology().iter().cloned().collect();
    assert_eq!(actual, expected);
    let prev: Vec<_> = view.prev_commit_topology().iter().cloned().collect();
    assert_eq!(prev, base_topology);
}
state_test! { sync apply_without_execution_keeps_active_candidate_outside_supplied_npos_committee
    use iroha_config::parameters::actual::LaneValidatorMode;
    use iroha_data_model::parameter::system::{Parameter, SumeragiNposParameters};
    let query = LiveQueryStore::start_test();
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.staking.public_validator_mode = LaneValidatorMode::StakeElected;
    nexus.staking.min_validator_stake = 100_u64.into();
    let state = State::new_with_nexus_for_testing(World::default(), nexus, query);
    {
        let mut params = state.world.parameters.block();
        params.set_parameter(Parameter::Custom(
            SumeragiNposParameters::default().into_custom_parameter(),
        )).expect("valid fixture parameters");
        params.commit();
    }
    let keypairs = configure_commit_topology(&state, 4);
    let missing_keypair = crate::state::checked_keypair_with_algorithm(Algorithm::BlsNormal);
    let_row! { base_topology: Vec<_> = keypairs .iter() .map(|kp| PeerId::new(kp.public_key().clone())) .collect() };
    let missing_peer = PeerId::new(missing_keypair.public_key().clone());
    {
        let mut world_block = state.world.block();
        {
            let mut peers = world_block.peers_mut_for_testing().transaction();
            peers.clear();
            peers.extend(base_topology.clone());
            peers.push(missing_peer.clone());
            peers.apply();
        }
        for keypair in keypairs.iter().chain(core::iter::once(&missing_keypair)) {
            let validator = AccountId::new(keypair.public_key().clone());
            world_block.public_lane_validators.insert(
                (LaneId::SINGLE, validator.clone()),
                PublicLaneValidatorRecord {
                    lane_id: LaneId::SINGLE,
                    validator: validator.clone(),
                    peer_id: PeerId::new(keypair.public_key().clone()),
                    stake_account: validator,
                    total_stake: iroha_primitives::numeric::Quantity::from(1_000_u32),
                    self_stake: iroha_primitives::numeric::Quantity::from(1_000_u32),
                    metadata: Metadata::default(),
                    status: PublicLaneValidatorStatus::Active,
                    activation_height: 1,
                    election_exit_height: None,
                    deactivation_height: None,
                },
            );
        }
        world_block.commit();
    }
    seed_consensus_keys_with_pops(
        &state,
        &keypairs
            .iter()
            .chain(core::iter::once(&missing_keypair))
            .cloned()
            .collect::<Vec<_>>(),
    );
    // This fixture tests metadata topology selection, with no executable Network sources.
    let signed_block = empty_signed_block_after(None, 1);
    store_block_for_state_commit(&state.kura, &signed_block);
    let mut state_block = state.block(signed_block.header());
    let valid = ValidBlock::new_unverified_for_tests(signed_block);
    let committed = valid.commit_unchecked(crate::block::reserve_block_for_tests()).unpack(|_| {});
    let prev_hash = committed.as_ref().hash();
    let _ = state_block.apply_without_execution(&committed, base_topology.clone());
    state_block.commit().expect("commit state block");
    let mut expected_topology = Topology::new(base_topology.clone());
    expected_topology.block_committed(base_topology.clone(), prev_hash);
    let expected = expected_topology.as_ref().to_vec();
    let view = state.view();
    let actual: Vec<_> = view.commit_topology().iter().cloned().collect();
    assert_eq!(actual, expected);
    assert!(!actual.contains(&missing_peer), "an active candidate cannot vote outside the supplied committee");
    assert!(view.world.peers().iter().any(|peer| peer == &missing_peer));
    assert_eq!(actual.len(), 4, "the authoritative committee retains exact 3f+1 membership");
    let prev: Vec<_> = view.prev_commit_topology().iter().cloned().collect();
    assert_eq!(prev, base_topology);
}
state_test! { sync apply_without_execution_uses_npos_parameters_for_commit_topology
    use iroha_data_model::parameter::system::{Parameter, SumeragiNposParameters};
    // Simulate stale status metadata (permissioned tag) while NPoS parameters are present.
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::default(), kura, query);
    {
        let mut params = state.world.parameters.block();
        params.set_parameter(Parameter::Custom(
            SumeragiNposParameters::default().into_custom_parameter(),
        )).expect("valid fixture parameters");
        params.commit();
    }
    let keypairs = configure_commit_topology(&state, 4);
    let_row! { base_topology: Vec<_> = keypairs .iter() .map(|kp| PeerId::new(kp.public_key().clone())) .collect() };
    let_row! { new_peer = PeerId::new( crate::state::checked_keypair_with_algorithm(Algorithm::BlsNormal) .public_key() .clone(), ) };
    // This fixture tests metadata topology selection, with no executable Network sources.
    let signed_block = empty_signed_block_after(None, 1);
    store_block_for_state_commit(&state.kura, &signed_block);
    let mut state_block = state.block(signed_block.header());
    {
        let mut peers = state_block.world.peers_mut_for_testing().transaction();
        peers.clear();
        peers.extend(base_topology.clone());
        peers.push(new_peer);
        peers.apply();
    }
    let valid = ValidBlock::new_unverified_for_tests(signed_block);
    let committed = valid.commit_unchecked(crate::block::reserve_block_for_tests()).unpack(|_| {});
    let prev_hash = committed.as_ref().hash();
    let _ = state_block.apply_without_execution(&committed, base_topology.clone());
    state_block.commit().expect("commit state block");
    let mut expected_topology = Topology::new(base_topology.clone());
    expected_topology.block_committed(base_topology.clone(), prev_hash);
    let expected = expected_topology.as_ref().to_vec();
    let view = state.view();
    let actual: Vec<_> = view.commit_topology().iter().cloned().collect();
    assert_eq!(actual, expected);
    let prev: Vec<_> = view.prev_commit_topology().iter().cloned().collect();
    assert_eq!(prev, base_topology);
}
state_test! { sync apply_without_execution_does_not_invent_committee_when_roster_missing
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::default(), kura, query);
    let keypairs = configure_commit_topology(&state, 4);
    let_row! { base_topology: Vec<_> = keypairs .iter() .map(|kp| PeerId::new(kp.public_key().clone())) .collect() };
    let_row! { new_peer = PeerId::new( crate::state::checked_keypair_with_algorithm(Algorithm::BlsNormal) .public_key() .clone(), ) };
    // This fixture tests metadata topology selection, with no executable Network sources.
    let signed_block = empty_signed_block_after(None, 1);
    store_block_for_state_commit(&state.kura, &signed_block);
    let mut state_block = state.block(signed_block.header());
    {
        let mut peers = state_block.world.peers_mut_for_testing().transaction();
        peers.clear();
        peers.extend(base_topology.clone());
        peers.push(new_peer.clone());
        peers.apply();
    }
    let valid = ValidBlock::new_unverified_for_tests(signed_block);
    let committed = valid.commit_unchecked(crate::block::reserve_block_for_tests()).unpack(|_| {});
    let _ = state_block.apply_without_execution(&committed, Vec::new());
    state_block.commit().expect("commit state block");
    // This is an isolated metadata preparation component, not native consensus
    // admission. A missing caller roster must never infer voters from World.
    let expected = Vec::<PeerId>::new();
    let view = state.view();
    let actual: Vec<_> = view.commit_topology().iter().cloned().collect();
    assert_eq!(actual, expected);
    assert!(view.world.peers().iter().any(|peer| peer == &new_peer));
    assert_eq!(view.world.peers().len(), base_topology.len() + 1);
    let prev: Vec<_> = view.prev_commit_topology().iter().cloned().collect();
    assert_eq!(prev, base_topology);
}
state_test! { sync apply_without_execution_prefers_checkpoint_topology_when_world_peers_incomplete
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::default(), kura, query);
    let keypairs = configure_commit_topology(&state, 4);
    let_row! { base_topology: Vec<_> = keypairs .iter() .map(|kp| PeerId::new(kp.public_key().clone())) .collect() };
    // This fixture tests metadata topology selection, with no executable Network sources.
    let signed_block = empty_signed_block_after(None, 1);
    store_block_for_state_commit(&state.kura, &signed_block);
    let mut state_block = state.block(signed_block.header());
    {
        let mut peers = state_block.world.peers_mut_for_testing().transaction();
        peers.clear();
        peers.push(base_topology[0].clone());
        peers.apply();
    }
    let valid = ValidBlock::new_unverified_for_tests(signed_block);
    let committed = valid.commit_unchecked(crate::block::reserve_block_for_tests()).unpack(|_| {});
    let block_hash = committed.as_ref().hash();
    let _ = state_block.apply_without_execution(&committed, base_topology.clone());
    state_block.commit().expect("commit state block");
    let mut expected_topology = Topology::new(base_topology.clone());
    expected_topology.block_committed(base_topology.clone(), block_hash);
    let expected = expected_topology.as_ref().to_vec();
    let view = state.view();
    let actual: Vec<_> = view.commit_topology().iter().cloned().collect();
    assert_eq!(actual, expected);
    let prev: Vec<_> = view.prev_commit_topology().iter().cloned().collect();
    assert_eq!(prev, base_topology);
}
