#[test]
fn gossip_batch_returns_routing_metadata() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(config_factory(), &time_source);
    let tx = accepted_tx_by_someone(&time_source);
    let hash = tx.as_ref().hash_as_entrypoint();
    queue
        .push(tx, state.view())
        .expect("enqueue accepted transaction");
    let batch = queue.gossip_batch(1, &state.view());
    assert_eq!(batch.len(), 1);
    let entry = &batch[0];
    assert_eq!(entry.tx.as_ref().hash_as_entrypoint(), hash);
    let expected_payload =
        ncore::to_bytes(entry.tx.entrypoint()).expect("encode transaction entrypoint");
    assert_eq!(entry.payload.as_slice(), expected_payload.as_slice());
    assert_eq!(entry.routing.lane_id, LaneId::SINGLE);
    assert_eq!(entry.routing.dataspace_id, DataSpaceId::UNIVERSAL);
}
#[test]
fn ordinary_gossip_and_selection_follow_committed_routing_across_policy_change() {
    let query_handle = LiveQueryStore::start_test();
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let refreshed = RoutingDecision::new(LaneId::new(3), DataSpaceId::UNIVERSAL);
    let (fresh_lanes, fresh_dataspaces) = Queue::test_catalogs_for_routes(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (refreshed.lane_id, refreshed.dataspace_id),
    ]);
    let mut nexus = Nexus::default();
    nexus.autoscale.enabled = false;
    nexus.lane_catalog = (*fresh_lanes).clone();
    nexus.dataspace_catalog = (*fresh_dataspaces).clone();
    let mut state =
        State::new_with_nexus_for_testing(world_with_test_domains(), nexus, query_handle);
    install_single_validator_topology_for_queue_test(&mut state, 0xE1);
    let queue = Queue::test(config_factory(), &time_source);
    let (account_id, key_pair) = gen_account_in("wonderland");
    register_test_authority(&state, &account_id);
    let tx = accepted_tx_with(
        account_id,
        &key_pair,
        &time_source,
        vec![InstructionBox::from(Log::new(
            Level::INFO,
            "fresh gossip route".into(),
        ))],
        Metadata::default(),
    );
    let hash = tx.as_ref().hash_as_entrypoint();
    let original_input = tx.entrypoint_bytes().to_vec();
    queue.push(tx.clone(), state.view()).expect("push tx");
    assert!(queue.contains_entrypoint_hash(hash));
    assert_eq!(
        queue
            .routing_plans
            .get(&hash)
            .map(|entry| entry.value().coordinator_route()),
        Some(RoutingDecision::default())
    );
    let original_hint = queue.routing_plan_hint(&hash).unwrap();
    let mut nexus = state.nexus_snapshot();
    nexus.routing_policy.default_lane = refreshed.lane_id;
    nexus.routing_policy.default_dataspace = refreshed.dataspace_id;
    let expected_current = evaluate_policy_plan_with_nexus_and_world_at_block_height(
        &nexus,
        &tx,
        &state.world_view(),
        0,
        state_height_for_routing(&state),
    )
    .expect("independent current routing policy");
    assert_eq!(expected_current.coordinator_route(), refreshed);
    state.set_nexus(nexus).expect("apply fresh Nexus state");
    let current_route = queue
        .route_plan_with_state(&tx, &state)
        .map(|plan| plan.coordinator_route())
        .expect("Ordinary routing should follow committed state");
    assert_eq!(current_route, refreshed);
    let batch = queue.gossip_batch_with_state(1, &state);
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].routing, refreshed);
    assert_eq!(
        queue
            .routing_plans
            .get(&hash)
            .map(|entry| entry.value().coordinator_route()),
        Some(expected_current.coordinator_route())
    );
    assert_eq!(
        queue
            .routing_plan_hint(&hash)
            .map(|plan| plan.coordinator_route()),
        Some(expected_current.coordinator_route())
    );
    assert_eq!(
        original_hint,
        RoutingPlan::single(RoutingDecision::default())
    );
    assert_eq!(
        queue
            .txs
            .get(&hash)
            .unwrap()
            .as_accepted()
            .entrypoint_bytes()
            .as_slice(),
        original_input.as_slice()
    );
    assert_eq!((queue.active_len(), queue.queued_len()), (1, 1));
    assert!(!queue.accepted_work_validation_faulted());
    let selected = Arc::new(queue)
        .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
        .unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].entrypoint(), tx.entrypoint());
}

#[test]
fn temporarily_unroutable_ordinary_input_does_not_fault_the_queue() {
    let mut state = State::new(
        world_with_test_domains(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let router = Arc::new(MutableRouter::new(RoutingDecision::default()));
    let queue =
        Queue::test_with_router_for_routes(config_factory(), &time_source, router.clone(), &[]);
    let tx = accepted_tx_by_someone(&time_source);
    register_accepted_tx_authority_for_queue_test(&mut state, &tx);
    let hash = tx.hash_as_entrypoint();
    queue
        .push_with_lane_with_state(tx.clone(), &state)
        .expect("admit signed Ordinary input on the initial route");
    router.set_unknown_dataspace(DataSpaceId::new(91));
    assert!(matches!(
        queue.route_plan_with_state(&tx, &state),
        Err(RoutingResolveError::OrdinaryRouteUnavailable { .. })
    ));
    assert!(queue.gossip_batch_with_state(1, &state).is_empty());
    assert!(queue.contains_entrypoint_hash(hash));
    assert!(!queue.accepted_work_validation_faulted());
    router.set(RoutingDecision::default());
    assert_eq!(queue.gossip_batch_with_state(1, &state).len(), 1);
    assert!(!queue.accepted_work_validation_faulted());
}

#[test]
fn gossip_skips_an_unavailable_ordinary_route_without_blocking_later_input() {
    let state = State::new(
        world_with_test_domains(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(config_factory(), &time_source);
    let (account_id, key_pair) = gen_account_in("wonderland");
    register_test_authority(&state, &account_id);
    let make_tx = |message: &str| {
        accepted_tx_with(
            account_id.clone(),
            &key_pair,
            &time_source,
            vec![InstructionBox::from(Log::new(Level::INFO, message.into()))],
            Metadata::default(),
        )
    };
    let first = make_tx("temporarily unavailable");
    let second = make_tx("independent later input");
    let first_hash = first.hash_as_entrypoint();
    let second_hash = second.hash_as_entrypoint();
    queue
        .push(first, state.view())
        .expect("enqueue first input");
    queue
        .push(second, state.view())
        .expect("enqueue second input");
    let batch = queue.gossip_batch_inner(
        1,
        |_, _| GossipEntryState::Pending,
        |hash, _| {
            if hash == first_hash {
                Err(RoutingResolveError::OrdinaryRouteUnavailable {
                    reason: "route temporarily unavailable".to_owned(),
                })
            } else {
                Ok(Some(RoutingPlan::single(RoutingDecision::default())))
            }
        },
        None,
    );
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].tx.hash_as_entrypoint(), second_hash);
    assert!(queue.contains_entrypoint_hash(first_hash));
    assert!(!queue.accepted_work_validation_faulted());
    let retried = queue.gossip_batch_inner(
        1,
        |_, _| GossipEntryState::Pending,
        |_, _| Ok(Some(RoutingPlan::single(RoutingDecision::default()))),
        None,
    );
    assert_eq!(retried.len(), 1);
    assert_eq!(retried[0].tx.hash_as_entrypoint(), first_hash);
}
