#[cfg(feature = "telemetry")]
#[tokio::test]
async fn push_records_teu_using_router_assignment() {
    struct StaticRouter {
        lane: LaneId,
        dataspace: DataSpaceId,
    }
    impl LaneRouter for StaticRouter {
        fn try_route(
            &self,
            _tx: &dyn TransactionRoutingView,
        ) -> Result<RoutingDecision, RoutingResolveError> {
            Ok(RoutingDecision::new(self.lane, self.dataspace))
        }
    }
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let test_lane = LaneId::new(7);
    let test_dataspace = DataSpaceId::new(42);
    let mut nexus = test_nexus_for_routes(&[(test_lane, test_dataspace)]);
    nexus.routing_policy.default_lane = test_lane;
    nexus.routing_policy.default_dataspace = test_dataspace;
    let state = State::new_with_nexus_for_testing(
        world_with_test_domains(),
        nexus,
        LiveQueryStore::start_test(),
    );
    let state = Arc::new(state);
    let router = Arc::new(StaticRouter {
        lane: test_lane,
        dataspace: test_dataspace,
    });
    let queue = Arc::new(Queue::test_with_router_for_routes(
        config_factory(),
        &time_source,
        router,
        &[(test_lane, test_dataspace)],
    ));
    let (account_id, key_pair) = gen_account_in("wonderland");
    register_test_authority(&state, &account_id);
    let domain_name = unique_test_domain_name("tagged");
    let unregister =
        Unregister::domain(DomainId::try_new(&domain_name, "test-dataspace-42").unwrap());
    let tx = TransactionBuilder::new_with_time_source(
        state.network_id,
        account_id,
        &time_source,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([unregister])
    .sign(key_pair.private_key());
    let default_limits = TransactionParameters::default();
    let tx_limits = TransactionParameters::with_max_signatures(
        nonzero!(16_u64),
        nonzero!(4096_u64),
        nonzero!(1024_u64),
        default_limits.max_tx_bytes(),
        default_limits.max_decompressed_bytes(),
        default_limits.max_metadata_depth(),
    );
    let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
    let tx = AcceptedTransaction::accept_with_time_source(
        tx,
        state.network_id_ref(),
        Duration::from_secs(60),
        tx_limits,
        &crypto_cfg,
        &time_source,
    )
    .expect("Failed to accept transaction.");
    let hash = tx.hash_as_entrypoint();
    queue
        .push(tx, state.view())
        .expect("Failed to push tx into queue");
    let teu_info = queue
        .tx_teu
        .get(&hash)
        .expect("TEU info missing for routed transaction");
    assert_eq!(teu_info.lane_id, test_lane);
    assert_eq!(teu_info.dataspace_id, test_dataspace);
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn push_records_teu_from_ivm_metadata() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Arc::new(Queue::test(config_factory(), &time_source));
    let (account_id, key_pair) = gen_account_in("wonderland");
    register_test_authority(&state, &account_id);
    let max_cycles = 42_000_u64;
    let tx = accepted_ivm_tx_by(account_id, &key_pair, &time_source, max_cycles);
    let hash = tx.hash_as_entrypoint();
    queue
        .push(tx, state.view())
        .expect("Failed to enqueue IVM transaction");
    let info = queue
        .tx_teu
        .get(&hash)
        .expect("TEU info missing for IVM transaction");
    assert_eq!(info.teu, max_cycles);
}

#[test]
fn expired_event_uses_the_authoritative_full_plan() {
    let expected = RoutingDecision::new(LaneId::new(5), DataSpaceId::new(13));
    let mut nexus = test_nexus_for_routes(&[(expected.lane_id, expected.dataspace_id)]);
    nexus.routing_policy.default_lane = expected.lane_id;
    nexus.routing_policy.default_dataspace = expected.dataspace_id;
    let state = State::new_with_nexus_for_testing(
        world_with_test_domains(),
        nexus,
        LiveQueryStore::start_test(),
    );
    let state = Arc::new(state);
    let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let mut queue = Queue::test_with_router_for_routes(
        Config {
            transaction_time_to_live: Duration::from_millis(10),
            // Expiry precedes maintenance; the independent zero-interval test
            // covers immediate culling instead.
            expired_cull_interval: Duration::from_millis(100),
            ..config_factory()
        },
        &time_source,
        Arc::new(MutableRouter::new(expected)),
        &[(expected.lane_id, expected.dataspace_id)],
    );
    let (event_sender, mut event_receiver) = tokio::sync::broadcast::channel(8);
    queue.events_sender = event_sender;
    let queue = Arc::new(queue);
    let tx = accepted_tx_with(
        AccountId::new(ALICE_KEYPAIR.public_key().clone()),
        &ALICE_KEYPAIR,
        &time_source,
        vec![Log::new(Level::INFO, "expire original routed input".into()).into()],
        Metadata::default(),
    );
    let signed_hash = tx
        .external()
        .expect("fixture authors an external input")
        .hash();
    let hash = tx.hash_as_entrypoint();
    let original = tx.clone();
    queue.push(tx, state.view()).expect("push tx");
    assert_eq!(
        queue.routing_plan_hint(&hash),
        Some(RoutingPlan::single(expected))
    );
    while event_receiver.try_recv().is_ok() {}
    time_handle.advance(Duration::from_millis(11));
    assert!(
        queue.is_expired(&original),
        "the original ten-millisecond TTL has elapsed"
    );
    assert_eq!(
        queue.cull_expired_entries_if_due(),
        0,
        "the maintenance interval has not elapsed"
    );
    assert_eq!(queue.active_len(), 1);
    time_handle.advance(queue.expired_cull_interval);
    let guards = queue
        .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
        .unwrap();
    assert!(guards.is_empty());
    assert_eq!(queue.active_len(), 0);
    assert_eq!(queue.routing_plan_hint(&hash), None);
    let mut saw_expired = false;
    while let Ok(event) = event_receiver.try_recv() {
        let EventBox::Pipeline(PipelineEventBox::Transaction(event)) = event else {
            continue;
        };
        if event.hash != signed_hash {
            continue;
        }
        if !matches!(event.status, TransactionStatus::Expired) {
            continue;
        }
        assert_eq!(event.lane_id, expected.lane_id);
        assert_eq!(event.dataspace_id, expected.dataspace_id);
        saw_expired = true;
        break;
    }
    assert!(
        saw_expired,
        "expected expired event to carry full-plan route"
    );
}
