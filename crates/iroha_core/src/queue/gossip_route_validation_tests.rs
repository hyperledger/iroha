#[test]
fn route_for_gossip_with_state_uses_router_decision() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let expected_lane = LaneId::SINGLE;
    let expected_dataspace = DataSpaceId::UNIVERSAL;
    let queue = Queue::test_with_router(
        config_factory(),
        &time_source,
        Arc::new(StaticRouter {
            lane: expected_lane,
            dataspace: expected_dataspace,
        }),
    );
    let tx = accepted_tx_by_someone(&time_source);
    let routing = queue
        .route_plan_for_gossip_with_state(&tx, state.as_ref())
        .map(|plan| plan.coordinator_route())
        .expect("route should resolve with configured catalogs");
    assert_eq!(routing.lane_id, expected_lane);
    assert_eq!(routing.dataspace_id, expected_dataspace);
}
#[test]
fn route_for_gossip_with_state_prefers_no_state_router_path() {
    struct PanicOnViewRouter {
        lane: LaneId,
        dataspace: DataSpaceId,
    }
    impl LaneRouter for PanicOnViewRouter {
        fn try_route(
            &self,
            _tx: &dyn TransactionRoutingView,
        ) -> Result<RoutingDecision, RoutingResolveError> {
            Ok(RoutingDecision::new(self.lane, self.dataspace))
        }
        fn try_route_without_state(
            &self,
            _tx: &dyn TransactionRoutingView,
        ) -> Result<Option<RoutingDecision>, RoutingResolveError> {
            Ok(Some(RoutingDecision::new(self.lane, self.dataspace)))
        }
    }
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let expected_lane = LaneId::SINGLE;
    let expected_dataspace = DataSpaceId::UNIVERSAL;
    let queue = Queue::test_with_router(
        config_factory(),
        &time_source,
        Arc::new(PanicOnViewRouter {
            lane: expected_lane,
            dataspace: expected_dataspace,
        }),
    );
    let tx = accepted_tx_by_someone(&time_source);
    let routing = queue
        .route_plan_for_gossip_with_state(&tx, state.as_ref())
        .map(|plan| plan.coordinator_route())
        .expect("route should resolve with configured catalogs");
    assert_eq!(routing.lane_id, expected_lane);
    assert_eq!(routing.dataspace_id, expected_dataspace);
}
#[test]
fn state_backed_queue_routes_reject_unknown_dataspace() {
    let state = State::new(
        world_with_test_domains(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );

    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let dynamic_dataspace = DataSpaceId::new(4_242);
    let queue = Queue::test_with_router(
        config_factory(),
        &time_source,
        Arc::new(StaticRouter {
            lane: LaneId::SINGLE,
            dataspace: dynamic_dataspace,
        }),
    );
    queue.install_test_router_metadata_for_nexus(&state.nexus_snapshot());
    let tx = accepted_tx_by_someone(&time_source);
    crate::queue::router::assert_completed_routing_error_eq(
        &(queue.route_plan_with_state(&tx, &state))
            .as_ref()
            .expect_err("expected completed routing rejection"),
        &(RoutingResolveError::UnknownDataspace {
            dataspace_id: dynamic_dataspace,
        }),
        format_args!("completed routing rejection"),
    );
    crate::queue::router::assert_completed_routing_error_eq(
        &(queue.route_plan_for_gossip_with_state(&tx, &state))
            .as_ref()
            .expect_err("expected completed routing rejection"),
        &(RoutingResolveError::UnknownDataspace {
            dataspace_id: dynamic_dataspace,
        }),
        format_args!("completed routing rejection"),
    );
}
