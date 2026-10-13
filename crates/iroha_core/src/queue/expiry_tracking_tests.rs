#[test]
fn expired_cull_compacts_hash_queue() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let mut cfg = config_factory();
    cfg.capacity = nonzero!(2_usize);
    cfg.capacity_per_user = nonzero!(2_usize);
    cfg.transaction_time_to_live = Duration::from_secs(1);
    cfg.expired_cull_interval = Duration::from_secs(1);
    let queue = Queue::test(cfg, &time_source);
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("push succeeds");
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("push succeeds");
    assert_eq!(queue.queued_len(), 2, "hash queue tracks queued txs");
    queue.assert_pressure_counters_consistent_for_tests();
    time_handle.advance(Duration::from_secs(2));
    let culled = queue.cull_expired_entries_if_due();
    assert_eq!(culled, 2, "expired transactions should be culled");
    assert_eq!(queue.queued_len(), 0, "hash queue compacted after cull");
    queue.assert_pressure_counters_consistent_for_tests();
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("push after compaction succeeds");
    assert_eq!(queue.queued_len(), 1, "hash queue accepts new txs");
    queue.assert_pressure_counters_consistent_for_tests();
}
#[test]
fn expired_cull_respects_batch_limit() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let mut cfg = config_factory();
    cfg.transaction_time_to_live = Duration::from_millis(1);
    cfg.expired_cull_interval = Duration::from_millis(1);
    cfg.expired_cull_batch = nonzero!(1_usize);
    let queue = Queue::test(cfg, &time_source);
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("push succeeds");
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("push succeeds");
    time_handle.advance(Duration::from_millis(2));
    let culled = queue.cull_expired_entries_if_due();
    assert_eq!(culled, 1, "batch-limited sweep culls one tx");
    assert_eq!(queue.active_len(), 1, "one tx remains after first sweep");
    queue.assert_pressure_counters_consistent_for_tests();
    time_handle.advance(Duration::from_millis(2));
    let culled = queue.cull_expired_entries_if_due();
    assert_eq!(culled, 1, "second sweep culls remaining tx");
    assert_eq!(queue.active_len(), 0, "all expired txs removed");
    queue.assert_pressure_counters_consistent_for_tests();
}
#[test]
fn remove_committed_hashes_clears_expiry_tracking() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(config_factory(), &time_source);
    let tx = accepted_tx_by_someone(&time_source);
    let hash = tx.hash_as_entrypoint();
    queue.push(tx, state.view()).expect("push succeeds");
    assert!(
        queue.expiry_ring_members.contains_key(&hash),
        "expiry tracking is set on push"
    );
    let removed = queue.remove_committed_hashes([hash], None);
    assert_eq!(removed, 1, "committed hash should be removed");
    assert_eq!(queue.active_len(), 0, "queue no longer tracks tx");
    queue.assert_pressure_counters_consistent_for_tests();
    assert!(
        !queue.expiry_ring_members.contains_key(&hash),
        "expiry tracking cleared on commit removal"
    );
    assert!(!queue.queued_tx_enqueued_at_ms.contains_key(&hash));
    assert!(queue.queued_age_ring.lock().is_empty());
}
#[tokio::test]
async fn custom_expired_transaction_is_rejected() {
    const TTL_MS: u64 = 200;
    const SWEEP_MS: u64 = 1_000;
    let max_txs_in_block = nonzero!(2_usize);
    let (alice_id, alice_keypair) = gen_account_in("wonderland");
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    register_test_authority(&state, &alice_id);
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let mut config = config_factory();
    config.expired_cull_interval = Duration::from_millis(SWEEP_MS);
    let mut queue = Queue::test(config, &time_source);
    let (event_sender, mut event_receiver) = tokio::sync::broadcast::channel(1);
    queue.events_sender = event_sender;
    // Use a simple instruction to avoid exercising heavy decode paths
    // unrelated to queue TTL behavior.
    let instructions = [Log::new(iroha_logger::Level::INFO, "ttl".into())];
    let mut tx = TransactionBuilder::new_with_time_source(
        state.network_id,
        alice_id,
        &time_source,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions);
    tx.set_ttl(Duration::from_millis(TTL_MS));
    let tx = tx.sign(alice_keypair.private_key());
    let signed_tx_hash = tx.hash();
    let tx = {
        let crypto_cfg = state.crypto();
        AcceptedTransaction::accept_with_time_source(
            tx,
            state.network_id_ref(),
            max_clock_drift,
            tx_limits,
            &crypto_cfg,
            &time_source,
        )
        .expect("Failed to accept Transaction.")
    };
    queue
        .push(tx, state.view())
        .expect("Failed to push tx into queue");
    // Avoid indefinite hang if events are not delivered
    let queued_tx_event = tokio::time::timeout(Duration::from_secs(2), event_receiver.recv())
        .await
        .expect("timed out waiting for queued event")
        .unwrap();
    assert_eq!(
        queued_tx_event,
        TransactionEvent {
            hash: signed_tx_hash,
            block_height: None,
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
            status: TransactionStatus::Queued,
        }
        .into()
    );
    time_handle.advance(Duration::from_millis(TTL_MS + 1));
    let queue = Arc::new(queue);
    let txs = queue
        .bounded_pending_snapshot(&state.view(), max_txs_in_block)
        .unwrap();
    assert!(
        txs.is_empty(),
        "expired input is excluded before the sweep is due"
    );
    assert_eq!(
        queue.active_len(),
        1,
        "throttled sweeps retain queue ownership"
    );
    assert!(matches!(
        event_receiver.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    // Event publication follows actual reclamation at the configured sweep deadline.
    time_handle.advance(Duration::from_millis(SWEEP_MS - TTL_MS - 1));
    let swept = queue
        .bounded_pending_snapshot(&state.view(), max_txs_in_block)
        .expect("deadline sweep keeps queue healthy");
    assert!(swept.is_empty());
    assert_eq!(queue.active_len(), 0);
    let expired_tx_event = tokio::time::timeout(Duration::from_secs(2), event_receiver.recv())
        .await
        .expect("timed out waiting for expired event")
        .unwrap();
    assert!(txs.is_empty());
    assert_eq!(
        expired_tx_event,
        TransactionEvent {
            hash: signed_tx_hash,
            block_height: None,
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
            status: TransactionStatus::Expired,
        }
        .into()
    )
}
#[test]
fn expired_cull_sweeps_reduce_active_len() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(
        Config {
            transaction_time_to_live: Duration::from_secs(1),
            expired_cull_interval: Duration::from_secs(1),
            ..config_factory()
        },
        &time_source,
    );
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("push succeeds");
    assert_eq!(queue.active_len(), 1, "tx tracked before expiration");
    queue.assert_pressure_counters_consistent_for_tests();
    time_handle.advance(Duration::from_secs(2));
    let culled = queue.cull_expired_entries_if_due();
    assert_eq!(culled, 1, "expired transaction should be culled");
    assert_eq!(
        queue.active_len(),
        0,
        "expired tx removed from active count"
    );
    queue.assert_pressure_counters_consistent_for_tests();
}
#[test]
fn zero_expired_cull_interval_runs_on_every_call() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(
        Config {
            transaction_time_to_live: Duration::from_secs(1),
            expired_cull_interval: Duration::ZERO,
            ..config_factory()
        },
        &time_source,
    );
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("push succeeds");
    time_handle.advance(Duration::from_secs(2));
    assert_eq!(
        queue.cull_expired_entries_if_due(),
        1,
        "a zero interval must mean unthrottled reclamation"
    );
    assert_eq!(queue.active_len(), 0);
    assert_eq!(queue.queued_len(), 0);
    queue.assert_pressure_counters_consistent_for_tests();
}
#[test]
fn pending_snapshot_runs_bounded_expiry_sweep() {
    let state = State::new(
        world_with_test_domains(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Arc::new(Queue::test(
        Config {
            transaction_time_to_live: Duration::from_secs(1),
            expired_cull_interval: Duration::from_secs(1),
            ..config_factory()
        },
        &time_source,
    ));
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("push transaction");
    time_handle.advance(Duration::from_secs(2));
    let pending = queue
        .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
        .expect("selection remains healthy");
    assert!(pending.is_empty());
    assert_eq!(queue.active_len(), 0);
    assert_eq!(queue.queued_len(), 0);
}
#[test]
fn sampling_culls_expired_input_while_fifo_has_live_work() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Arc::new(Queue::test(
        Config {
            transaction_time_to_live: Duration::from_millis(5),
            expired_cull_interval: Duration::from_millis(1),
            ..config_factory()
        },
        &time_source,
    ));
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("old transaction push succeeds");
    let old_sample = queue
        .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
        .unwrap();
    assert_eq!(old_sample.len(), 1);
    time_handle.advance(Duration::from_millis(4));
    let live_tx = accepted_tx_by_someone(&time_source);
    let live_hash = live_tx.hash_as_entrypoint();
    queue
        .push(live_tx, state.view())
        .expect("live transaction push succeeds");
    time_handle.advance(Duration::from_millis(2));
    assert_eq!(queue.active_len(), 2);
    let selected = queue
        .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
        .unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].hash_as_entrypoint(), live_hash);
    assert_eq!(
        queue.active_len(),
        1,
        "the cadence sweep must cull the expired input even while the FIFO returns live work"
    );
    queue.assert_pressure_counters_consistent_for_tests();
    drop(old_sample);
    assert_eq!(
        queue.active_len(),
        1,
        "dropping an already-culled sample cannot change pending ownership"
    );
    drop(selected);
    assert_eq!(queue.active_len(), 1);
    assert_eq!(queue.remove_committed_hashes([live_hash], None), 1);
    assert_eq!(queue.active_len(), 0);
    queue.assert_pressure_counters_consistent_for_tests();
}
