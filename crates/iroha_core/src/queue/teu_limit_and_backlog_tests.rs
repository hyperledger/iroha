#[tokio::test]
async fn push_tx() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(config_factory(), &time_source);
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("Failed to push tx into queue");
}
#[cfg(feature = "telemetry")]
#[test]
fn queue_backlog_reports_available_lane_headroom() {
    use std::num::NonZeroU32;

    let query_handle = LiveQueryStore::start_test();
    let metrics = Arc::new(Metrics::default());
    let telemetry = StateTelemetry::new(metrics.clone(), true);
    let test_lane = LaneId::new(13);
    let test_dataspace = DataSpaceId::new(9);
    let test_dataspace_alias = "dataspace9";
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let first_tx = accepted_tx_in_dataspace_by_someone(test_dataspace_alias, &time_source);
    let second_tx = accepted_tx_in_dataspace_by_someone(test_dataspace_alias, &time_source);
    let first_teu = Queue::compute_proposal_gas_cost(&first_tx, &crate::gas::DEFAULT_ZK_GAS)
        .expect("admitted proposal cost");
    let second_teu = Queue::compute_proposal_gas_cost(&second_tx, &crate::gas::DEFAULT_ZK_GAS)
        .expect("admitted proposal cost");
    let lane_capacity = first_teu.saturating_mul(10);
    assert!(
        lane_capacity > first_teu,
        "expected lane capacity to exceed TEU"
    );
    let lane_metadata = LaneConfig {
        id: test_lane,
        dataspace_id: test_dataspace,
        alias: "lane13".to_string(),
        scheduler: Some(LaneSchedulerPolicy::new(
            Some(NonZeroU64::new(lane_capacity).expect("positive lane capacity")),
            None,
        )),
        ..LaneConfig::default()
    };
    let dataspace_metadata = DataSpaceMetadata {
        id: test_dataspace,
        alias: test_dataspace_alias.to_string(),
        description: None,
        fault_tolerance: 1,
    };
    let lane_catalog = LaneCatalog::new(
        NonZeroU32::new(16).expect("nonzero lane count"),
        vec![lane_metadata.clone()],
    )
    .expect("valid lane catalog");
    let dataspace_catalog =
        DataSpaceCatalog::new(vec![dataspace_metadata.clone()]).expect("valid dataspace catalog");
    telemetry.set_nexus_catalogs(&lane_catalog, &dataspace_catalog);

    let mut nexus = Nexus::default();
    let state_lane_catalog = LaneCatalog::new(
        NonZeroU32::new(16).expect("nonzero lane count"),
        vec![LaneConfig::default(), lane_metadata.clone()],
    )
    .expect("valid state lane catalog");
    let state_dataspace_catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        dataspace_metadata.clone(),
    ])
    .expect("valid state dataspace catalog");
    nexus.lane_catalog = state_lane_catalog;
    nexus.lane_config = LaneGeometry::from_catalog(&nexus.lane_catalog);
    nexus.dataspace_catalog = state_dataspace_catalog;
    nexus.routing_policy.default_lane = test_lane;
    nexus.routing_policy.default_dataspace = test_dataspace;
    let state = new_queue_test_state_with_telemetry(
        world_with_test_domains(),
        nexus,
        query_handle,
        telemetry.clone(),
    );
    let state = Arc::new(state);
    let router: Arc<dyn LaneRouter> = Arc::new(StaticRouter {
        lane: test_lane,
        dataspace: test_dataspace,
    });
    let scheduling = LaneSchedulingLimits::new(lane_capacity, 0);
    let queue_inner = Queue::test_with_router_for_routes(
        config_factory(),
        &time_source,
        router,
        &[(test_lane, test_dataspace)],
    );
    *queue_inner.nexus_limits.write() = QueueLimits {
        fallback: scheduling,
        per_lane: BTreeMap::from([(test_lane, scheduling)]),
    };
    queue_inner
        .lane_teu_pending
        .insert(test_lane, PendingTeu::default());
    queue_inner
        .dataspace_teu_pending
        .insert((test_lane, test_dataspace), PendingTeu::default());
    let queue = Arc::new(queue_inner);
    queue
        .push(first_tx, state.view())
        .expect("first push should succeed");
    queue
        .push(second_tx, state.view())
        .expect("second push should succeed");
    let pending_teu = first_teu.saturating_add(second_teu);
    let expected_committed = pending_teu.min(lane_capacity);
    let expected_headroom = lane_capacity.saturating_sub(expected_committed);
    let lane_label = test_lane.as_u32().to_string();
    let headroom_events = metrics
        .nexus_scheduler_lane_headroom_events_total
        .with_label_values(&[lane_label.as_str()])
        .get();
    assert_eq!(
        headroom_events, 0,
        "backlog snapshots should not emit warnings"
    );
    let lane_snapshots = metrics
        .nexus_scheduler_lane_teu_status
        .read()
        .expect("lane TEU cache poisoned");
    let snapshot = lane_snapshots
        .get(&test_lane.as_u32())
        .expect("lane snapshot missing");
    assert_eq!(snapshot.committed, expected_committed);
    assert_eq!(snapshot.buckets.headroom, expected_headroom);
}
