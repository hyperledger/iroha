#[test]
fn sampling_keeps_pending_and_active_counts_until_application() {
    let state = State::new(
        world_with_test_domains(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let (_, time) = TimeSource::new_mock(Duration::default());
    let queue = Arc::new(Queue::test(config_factory(), &time));
    let tx = accepted_tx_by_someone(&time);
    let hash = tx.hash_as_entrypoint();
    queue.push(tx, state.view()).unwrap();
    let sample = queue
        .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
        .unwrap();
    assert_eq!(sample.len(), 1);
    assert_eq!(sample[0].hash_as_entrypoint(), hash);
    assert_eq!((queue.active_len(), queue.queued_len()), (1, 1));
    queue.assert_pressure_counters_consistent_for_tests();
    drop(sample);
    assert_eq!((queue.active_len(), queue.queued_len()), (1, 1));
    assert_eq!(queue.remove_committed_hashes([hash], None), 1);
    assert_eq!((queue.active_len(), queue.queued_len()), (0, 0));
    queue.assert_pressure_counters_consistent_for_tests();
}
#[test]
fn expiry_culls_pending_while_an_owned_sample_cannot_resurrect_it() {
    let state = State::new(
        world_with_test_domains(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let (clock, time) = TimeSource::new_mock(Duration::default());
    let queue = Arc::new(Queue::test(
        Config {
            transaction_time_to_live: Duration::from_millis(1),
            expired_cull_interval: Duration::from_millis(1),
            ..config_factory()
        },
        &time,
    ));
    let tx = accepted_tx_by_someone(&time);
    let hash = tx.hash_as_entrypoint();
    queue.push(tx, state.view()).unwrap();
    let sample = queue
        .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
        .unwrap();
    assert_eq!(sample[0].hash_as_entrypoint(), hash);
    clock.advance(Duration::from_millis(2));
    assert_eq!(queue.cull_expired_entries_if_due(), 1);
    assert_eq!((queue.active_len(), queue.queued_len()), (0, 0));
    assert!(!queue.txs.contains_key(&hash));
    assert!(!queue.routing_plans.contains_key(&hash));
    drop(sample);
    assert_eq!(queue.remove_committed_hashes([hash], None), 0);
    assert!(
        queue
            .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
            .unwrap()
            .is_empty()
    );
    queue.assert_pressure_counters_consistent_for_tests();
}
#[test]
fn remove_committed_hashes_tolerates_missing_per_user_counter() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(config_factory(), &time_source);
    let tx = accepted_tx_by_someone(&time_source);
    let hash = tx.hash_as_entrypoint();
    let authority = tx.authority_opt().expect("signed queue fixture").clone();
    queue.push(tx, state.view()).expect("push succeeds");
    assert_eq!(queue.queued_tx_count_for_user(&authority), 1);
    queue.txs_per_user.clear();
    let removed = queue.remove_committed_hashes([hash], None);
    assert_eq!(removed, 1, "committed hash should still be removed");
    assert_eq!(queue.active_len(), 0, "queue no longer tracks tx");
    assert_eq!(queue.queued_tx_count_for_user(&authority), 0);
    queue.assert_pressure_counters_consistent_for_tests();
}
