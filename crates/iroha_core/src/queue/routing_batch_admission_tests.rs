#[test]
fn push_with_gossip_payload_with_state_and_routing_validates_precomputed_plan() {
    struct CountingRouter {
        calls: Arc<AtomicUsize>,
    }
    impl LaneRouter for CountingRouter {
        fn try_route(
            &self,
            _tx: &dyn TransactionRoutingView,
        ) -> Result<RoutingDecision, RoutingResolveError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL))
        }
    }
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let queue = Queue::test_with_router(
        config_factory(),
        &time_source,
        Arc::new(CountingRouter {
            calls: Arc::clone(&calls),
        }),
    );
    let tx = accepted_tx_by_someone(&time_source);
    let hash = tx.hash_as_entrypoint();
    let payload = tx.entrypoint_bytes();
    queue
        .push_with_gossip_payload_with_state_and_routing_plan(
            tx,
            state.as_ref(),
            RoutingPlan::single(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)),
            Some(Arc::clone(&payload)),
        )
        .expect("push with precomputed routing should succeed");
    assert!(
        calls.load(Ordering::Relaxed) > 0,
        "precomputed plan admission should validate against current routing"
    );
    let routing = queue
        .routing_plans
        .get(&hash)
        .expect("routing plan should exist")
        .coordinator_route();
    assert_eq!(routing.lane_id, LaneId::SINGLE);
    assert_eq!(routing.dataspace_id, DataSpaceId::UNIVERSAL);
    assert_eq!(
        queue.tx_gossip.pop(),
        Some(hash),
        "successful gossip admission should still enqueue the gossip side channel"
    );
}
