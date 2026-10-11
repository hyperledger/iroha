// Queue pressure, resynchronization, and requeue regression tests.
#[test]
fn lane_limits_respect_typed_overrides() {
    let fallback = LaneSchedulingLimits::new(6_000, 120);
    let mut lane = LaneConfig {
        id: LaneId::new(3),
        alias: "custom".to_string(),
        scheduler: Some(LaneSchedulerPolicy::new(
            Some(NonZeroU64::new(8_192).expect("positive TEU capacity")),
            Some(NonZeroU64::new(42).expect("positive starvation bound")),
        )),
        ..LaneConfig::default()
    };
    let limits = QueueLimits::lane_limits_from_policy(&lane, fallback);
    assert_eq!(limits.teu_capacity, 8_192);
    assert_eq!(limits.starvation_bound_slots, 42);
    lane.scheduler = Some(LaneSchedulerPolicy::new(
        None,
        Some(NonZeroU64::new(11).expect("positive starvation bound")),
    ));
    let limits = QueueLimits::lane_limits_from_policy(&lane, fallback);
    assert_eq!(limits.teu_capacity, fallback.teu_capacity);
    assert_eq!(limits.starvation_bound_slots, 11);
}
#[tokio::test]
async fn backpressure_state_tracks_queue_load() {
    let capacity = nonzero!(2_usize);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Arc::new(Queue::test(
        Config {
            capacity,
            ..config_factory()
        },
        &time_source,
    ));
    let mut rx = queue.backpressure_handle().subscribe();
    assert!(!rx.borrow().is_saturated());
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("first push succeeds");
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("second push reaches capacity");
    rx.changed().await.expect("backpressure update to saturate");
    assert!(rx.borrow().is_saturated());
    let selected = queue
        .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
        .unwrap();
    assert_eq!(selected.len(), 1);
    queue.remove_committed_hashes([selected[0].hash_as_entrypoint()], None);
    rx.changed().await.expect("backpressure update to healthy");
    assert!(!rx.borrow().is_saturated());
}
#[tokio::test]
async fn queue_pressure_snapshot_tracks_oldest_age_across_enqueue_and_dequeue() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Arc::new(Queue::test(config_factory(), &time_source));
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("first push succeeds");
    time_handle.advance(Duration::from_millis(10));
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("second push succeeds");
    let initial = queue.pressure_snapshot();
    assert_eq!(initial.tracked_tx_count, 2);
    assert_eq!(initial.queued_tx_count, 2);
    assert_eq!(initial.oldest_queued_tx_age_ms, 10);
    let selected = queue
        .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
        .unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(
        queue.pressure_snapshot(),
        initial,
        "native selection leaves pending ownership intact"
    );
    queue.remove_committed_hashes([selected[0].hash_as_entrypoint()], None);
    let after_drop = queue.pressure_snapshot();
    assert_eq!(after_drop.tracked_tx_count, 1);
    assert_eq!(after_drop.queued_tx_count, 1);
    assert_eq!(after_drop.oldest_queued_tx_age_ms, 0);
}
#[tokio::test]
async fn queue_pressure_snapshot_clears_oldest_age_after_expiry() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(
        Config {
            transaction_time_to_live: Duration::from_millis(1),
            expired_cull_interval: Duration::from_millis(1),
            ..config_factory()
        },
        &time_source,
    );
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("push succeeds");
    assert_eq!(queue.pressure_snapshot().oldest_queued_tx_age_ms, 0);
    time_handle.advance(Duration::from_millis(2));
    assert_eq!(queue.cull_expired_entries_if_due(), 1);
    let snapshot = queue.pressure_snapshot();
    assert_eq!(snapshot.tracked_tx_count, 0);
    assert_eq!(snapshot.queued_tx_count, 0);
    assert_eq!(snapshot.oldest_queued_tx_age_ms, 0);
}
#[tokio::test]
async fn backpressure_state_ignores_oldest_queue_age_without_capacity_pressure() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Arc::new(Queue::test(config_factory(), &time_source));
    queue.set_pressure_age_budget_for_tests(Duration::from_millis(5));
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("push succeeds");
    time_handle.advance(Duration::from_millis(6));
    let snapshot = queue.pressure_snapshot();
    assert!(!snapshot.saturated_by_count);
    assert!(snapshot.saturated_by_age);
    assert!(!queue.current_backpressure().is_saturated());

    // Retire a different actual queued owner while the original aged transaction
    // remains pending. Its final reader must refund residence without replacing
    // the richer age evidence or changing the existing coarse admission policy.
    let retiring = accepted_tx_by_someone(&time_source);
    let retiring_hash = retiring.hash_as_entrypoint();
    queue.push(retiring, state.view()).expect("second input fits original capacity");
    let detached = queue.txs.get(&retiring_hash).unwrap().value().clone();
    let retired_cost = Queue::retained_byte_cost(detached.entrypoint_bytes().len());
    assert_eq!(queue.remove_committed_hashes([retiring_hash], None), 1);
    let held = queue.pressure_snapshot();
    assert_eq!(held.tracked_tx_count, 1);
    assert_eq!(held.queued_tx_count, 1);
    assert_eq!(held.oldest_queued_tx_age_ms, snapshot.oldest_queued_tx_age_ms);
    assert!(held.saturated_by_age);
    assert!(!queue.current_backpressure().is_saturated());
    let budget = state.ivm_execution_budget();
    assert!(queue.resident_accounting.get().unwrap().belongs_to(&budget));
    let occupied = budget.reserved_bytes();
    let mut pressure = queue.backpressure_handle().subscribe();
    drop(detached);
    let refunded = queue.pressure_snapshot();
    assert_eq!(refunded.retained_bytes, held.retained_bytes - retired_cost);
    assert_eq!(refunded.tracked_tx_count, held.tracked_tx_count);
    assert_eq!(refunded.queued_tx_count, held.queued_tx_count);
    assert_eq!(refunded.oldest_queued_tx_age_ms, held.oldest_queued_tx_age_ms);
    assert!(refunded.saturated_by_age);
    assert!(!pressure.has_changed().unwrap());
    assert!(!pressure.borrow_and_update().is_saturated());
    assert_eq!(
        budget.reserved_bytes(),
        occupied - iroha_allocation::shared::Shared::<
            CheckedTransaction<'static>, resident_owner::QueueResidentCharge,
        >::layout().size(),
        "only the actual last original shell refunds while its Queue ledger stays alive"
    );
}
#[tokio::test]
async fn backdate_queued_transactions_for_tests_updates_age_pressure() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::from_millis(10));
    let queue = Arc::new(Queue::test(config_factory(), &time_source));
    queue.set_pressure_age_budget_for_tests(Duration::from_millis(5));
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("push succeeds");
    let snapshot = queue.backdate_queued_transactions_for_tests(Duration::from_millis(6));
    assert_eq!(snapshot.oldest_queued_tx_age_ms, 6);
    assert!(snapshot.saturated_by_age);
    assert!(!queue.current_backpressure().is_saturated());
}
#[tokio::test]
async fn queue_pressure_counters_track_committed_removal_before_hash_drain() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Arc::new(Queue::test(config_factory(), &time_source));
    let first = accepted_tx_by_someone(&time_source);
    let first_hash = first.as_ref().hash_as_entrypoint();
    queue
        .push(first, state.view())
        .expect("first push succeeds");
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("second push succeeds");
    assert_eq!(queue.active_len(), 2);
    assert_eq!(queue.queued_len(), 2);
    queue.assert_pressure_counters_consistent_for_tests();
    assert_eq!(queue.remove_committed_hashes([first_hash], None), 1);
    let snapshot = queue.pressure_snapshot();
    assert_eq!(snapshot.tracked_tx_count, 1);
    assert_eq!(snapshot.queued_tx_count, 1);
    assert_eq!(queue.active_len(), queue.txs.len());
    assert_eq!(queue.queued_len(), queue.queued_tx_enqueued_at_ms.len());
    queue.assert_pressure_counters_consistent_for_tests();
}
#[tokio::test]
async fn queue_pressure_counters_restore_age_after_enqueue_compaction_retry() {
    let capacity = nonzero!(1_usize);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Arc::new(Queue::test(
        Config {
            capacity,
            ..config_factory()
        },
        &time_source,
    ));
    let first = accepted_tx_by_someone(&time_source);
    let first_hash = first.as_ref().hash_as_entrypoint();
    queue
        .push(first, state.view())
        .expect("first push succeeds");
    assert_eq!(queue.remove_committed_hashes([first_hash], None), 1);
    assert_eq!(queue.active_len(), 0);
    assert_eq!(queue.queued_len(), 0);
    queue.assert_pressure_counters_consistent_for_tests();
    let second = accepted_tx_by_someone(&time_source);
    let second_hash = second.as_ref().hash_as_entrypoint();
    queue
        .push(second, state.view())
        .expect("second push compacts stale hash and succeeds");
    assert_eq!(queue.active_len(), 1);
    assert_eq!(queue.queued_len(), 1);
    assert!(queue.queued_tx_enqueued_at_ms.contains_key(&second_hash));
    assert_eq!(queue.pressure_snapshot().queued_tx_count, 1);
    queue.assert_pressure_counters_consistent_for_tests();
}
#[tokio::test]
async fn queue_pressure_counters_stay_consistent_under_sustained_backlog() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Arc::new(Queue::test(
        Config {
            capacity: nonzero!(64_usize),
            ..config_factory()
        },
        &time_source,
    ));
    let target_backlog = 8usize;
    for _ in 0..target_backlog {
        queue
            .push(accepted_tx_by_someone(&time_source), state.view())
            .expect("prefill push succeeds");
        time_handle.advance(Duration::from_millis(1));
    }
    queue.assert_pressure_counters_consistent_for_tests();
    assert_eq!(queue.pressure_snapshot().queued_tx_count, target_backlog);
    for _ in 0..32 {
        queue
            .push(accepted_tx_by_someone(&time_source), state.view())
            .expect("sustained push succeeds");
        queue.assert_pressure_counters_consistent_for_tests();
        let selected = queue
            .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
            .unwrap();
        assert_eq!(selected.len(), 1);
        let pending = queue.pressure_snapshot();
        assert_eq!(pending.tracked_tx_count, target_backlog + 1);
        assert_eq!(pending.queued_tx_count, target_backlog + 1);
        queue.assert_pressure_counters_consistent_for_tests();
        queue.remove_committed_hashes([selected[0].hash_as_entrypoint()], None);
        let after_drop = queue.pressure_snapshot();
        assert_eq!(after_drop.tracked_tx_count, target_backlog);
        assert_eq!(after_drop.queued_tx_count, target_backlog);
        queue.assert_pressure_counters_consistent_for_tests();
        time_handle.advance(Duration::from_millis(1));
    }
}
#[tokio::test]
async fn get_available_txs() {
    let max_txs_in_block = nonzero!(2_usize);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(
        Config {
            transaction_time_to_live: Duration::from_secs(100),
            ..config_factory()
        },
        &time_source,
    );
    let queue = Arc::new(queue);
    for _ in 0..5 {
        queue
            .push(accepted_tx_by_someone(&time_source), state.view())
            .expect("Failed to push tx into queue");
        time_handle.advance(Duration::from_millis(10));
    }
    let available = queue
        .bounded_pending_snapshot(&state.view(), max_txs_in_block)
        .unwrap();
    assert_eq!(available.len(), max_txs_in_block.get());
}
#[tokio::test]
async fn push_tx_already_in_blockchain() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(world_with_test_domains(), kura, query_handle);
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let tx = accepted_tx_by_someone(&time_source);
    let (_, private_key) = checked_random_queue_keypair().into_parts();
    let unverified_block: SignedBlock =
        ValidBlock::new_dummy_and_modify_header(&private_key, |header| {
            header.height = nonzero!(1_u64);
        })
        .into();
    let mut state_block = state.block(unverified_block.header());
    let block_height: NonZeroUsize = unverified_block
        .header()
        .height()
        .try_into()
        .expect("block height should fit into usize");
    state_block
        .transactions
        .insert_block_with_single_tx(tx.as_ref().hash_as_entrypoint(), block_height);
    state_block.block_hashes.push(unverified_block.hash());
    state_block.commit().unwrap();
    let queue = Queue::test(config_factory(), &time_source);
    assert!(matches!(
        queue.push(tx, state.view()),
        Err(Failure {
            err: Error::InBlockchain,
            ..
        })
    ));
    assert_eq!(queue.txs.len(), 0);
}
#[tokio::test]
async fn push_expired_tx_already_in_blockchain() {
    let (alice_id, alice_keypair) = gen_account_in("wonderland");
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(world_with_test_domains(), kura, query_handle);
    register_test_authority(&state, &alice_id);
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let ok_instruction = Log::new(iroha_logger::Level::INFO, "pass".into());
    let mut tx = TransactionBuilder::new_with_time_source(
        state.network_id,
        alice_id,
        &time_source,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([ok_instruction]);
    tx.set_ttl(Duration::from_millis(100));
    let tx = tx.sign(alice_keypair.private_key());
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
    let (_, private_key) = checked_random_queue_keypair().into_parts();
    let unverified_block: SignedBlock =
        ValidBlock::new_dummy_and_modify_header(&private_key, |header| {
            header.height = nonzero!(1_u64);
        })
        .into();
    let mut state_block = state.block(unverified_block.header());
    let block_height: NonZeroUsize = unverified_block
        .header()
        .height()
        .try_into()
        .expect("block height should fit into usize");
    state_block
        .transactions
        .insert_block_with_single_tx(tx.as_ref().hash_as_entrypoint(), block_height);
    state_block.block_hashes.push(unverified_block.hash());
    state_block.commit().unwrap();
    let queue = Queue::test(config_factory(), &time_source);
    time_handle.advance(Duration::from_secs(100));
    assert!(matches!(
        queue.push(tx, state.view()),
        Err(Failure {
            err: Error::InBlockchain,
            ..
        })
    ));
    assert_eq!(queue.txs.len(), 0);
}
#[tokio::test]
async fn native_sampling_omits_committed_input_until_exact_cleanup() {
    let max_txs_in_block = nonzero!(2_usize);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(world_with_test_domains(), kura, query_handle);
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let tx = accepted_tx_by_someone(&time_source);
    let tx_hash = tx.as_ref().hash_as_entrypoint();
    let queue = Queue::test(config_factory(), &time_source);
    let queue = Arc::new(queue);
    queue.push(tx, state.view()).unwrap();
    let (_, private_key) = checked_random_queue_keypair().into_parts();
    let unverified_block: SignedBlock =
        ValidBlock::new_dummy_and_modify_header(&private_key, |header| {
            header.height = nonzero!(1_u64);
        })
        .into();
    let mut state_block = state.block(unverified_block.header());
    let block_height: NonZeroUsize = unverified_block
        .header()
        .height()
        .try_into()
        .expect("block height should fit into usize");
    state_block
        .transactions
        .insert_block_with_single_tx(tx_hash, block_height);
    state_block.block_hashes.push(unverified_block.hash());
    state_block.commit().unwrap();
    assert_eq!(
        queue
            .bounded_pending_snapshot(&state.view(), max_txs_in_block)
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        queue.txs.len(),
        1,
        "sampling does not own committed cleanup"
    );
    assert_eq!(queue.remove_committed_hashes([tx_hash], None), 1);
    assert!(queue.txs.is_empty());
}
#[tokio::test]
async fn get_available_txs_with_timeout() {
    let max_txs_in_block = nonzero!(6_usize);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(
        Config {
            transaction_time_to_live: Duration::from_millis(200),
            ..config_factory()
        },
        &time_source,
    );
    let queue = Arc::new(queue);
    for _ in 0..(max_txs_in_block.get() - 1) {
        queue
            .push(accepted_tx_by_someone(&time_source), state.view())
            .expect("Failed to push tx into queue");
        time_handle.advance(Duration::from_millis(100));
    }
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("Failed to push tx into queue");
    time_handle.advance(Duration::from_millis(101));
    assert_eq!(
        queue
            .bounded_pending_snapshot(&state.view(), max_txs_in_block)
            .unwrap()
            .len(),
        1
    );
    queue
        .push(accepted_tx_by_someone(&time_source), state.view())
        .expect("Failed to push tx into queue");
    time_handle.advance(Duration::from_millis(210));
    assert_eq!(
        queue
            .bounded_pending_snapshot(&state.view(), max_txs_in_block)
            .unwrap()
            .len(),
        0
    );
}
