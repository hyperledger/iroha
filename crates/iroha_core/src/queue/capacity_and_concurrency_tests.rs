#[test]
fn applied_cleanup_releases_exact_fifo_metadata_while_sample_remains_owned() {
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
    assert_eq!(sample[0].hash_as_entrypoint(), hash);
    assert!(queue.queued_tx_enqueued_at_ms.contains_key(&hash));
    assert_eq!(queue.remove_committed_hashes([hash], None), 1);
    assert_eq!((queue.active_len(), queue.queued_len()), (0, 0));
    assert!(queue.tx_hashes.is_empty());
    assert!(queue.queued_age_ring.lock().is_empty());
    assert!(!queue.queued_tx_enqueued_at_ms.contains_key(&hash));
    assert!(!queue.routing_plans.contains_key(&hash));
    drop(sample);
    assert_eq!(queue.remove_committed_hashes([hash], None), 0);
}
#[tokio::test]
async fn push_tx_overflow() {
    let capacity = nonzero!(10_usize);
    let kura: Arc<Kura> = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(
        Config {
            transaction_time_to_live: Duration::from_secs(100),
            capacity,
            ..Config::default()
        },
        &time_source,
    );
    for _ in 0..capacity.get() {
        queue
            .push(accepted_tx_by_someone(&time_source), state.view())
            .expect("Failed to push tx into queue");
        time_handle.advance(Duration::from_millis(10));
    }
    assert!(matches!(
        queue.push(accepted_tx_by_someone(&time_source), state.view()),
        Err(Failure {
            err: Error::Full,
            ..
        })
    ));
}
#[test]
fn empty_pending_snapshot_does_not_preallocate_for_scan_limit() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(world_with_test_domains(), kura, query_handle);
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Arc::new(Queue::test(config_factory(), &time_source));
    let pending = queue
        .bounded_pending_snapshot(
            &state.view(),
            NonZeroUsize::new(usize::MAX).expect("non-zero scan bound"),
        )
        .expect("empty queue remains selectable with a large scan bound");
    assert!(pending.is_empty());
    assert_eq!((queue.active_len(), queue.queued_len()), (0, 0));
}

#[tokio::test]
async fn concurrent_stress_test() {
    let max_txs_in_block = nonzero!(10_usize);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Arc::new(Queue::test(
        Config {
            transaction_time_to_live: Duration::from_secs(100),
            capacity: 100_000_000.try_into().unwrap(),
            ..Config::default()
        },
        &time_source,
    ));
    let start_time = std::time::Instant::now();
    let run_for = Duration::from_secs(5);
    let push_handles: Vec<_> = (0..4)
        .map(|_| {
            let queue_arc_clone = Arc::clone(&queue);
            let state = state.clone();
            let time_source = time_source.clone();
            thread::spawn(move || {
                while start_time.elapsed() < run_for {
                    let tx = accepted_tx_by_someone(&time_source);
                    match queue_arc_clone.push(tx, state.view()) {
                        Ok(())
                        | Err(Failure {
                            err: Error::Full | Error::MaximumTransactionsPerUser,
                            ..
                        }) => (),
                        Err(Failure { err, .. }) => panic!("{err}"),
                    }
                }
            })
        })
        .collect();
    // Concurrent native sampling and exact application-notification cleanup.
    let get_txs_handle = {
        let queue = Arc::clone(&queue);
        let state = Arc::clone(&state);
        thread::spawn(move || {
            let mut height = nonzero!(1usize);
            while start_time.elapsed() < run_for {
                {
                    let state_view = state.view();
                    let transactions = queue
                        .bounded_pending_snapshot(&state_view, max_txs_in_block)
                        .unwrap();
                    let hashes = transactions
                        .iter()
                        .map(AcceptedTransaction::hash_as_entrypoint)
                        .collect::<Vec<_>>();
                    drop(state_view);
                    queue.remove_committed_hashes(hashes, None);
                    drop(transactions);
                }
                height = height.checked_add(1).unwrap();
                let delay = Duration::from_millis((height.get() as u64 * 17) % 25);
                thread::sleep(delay);
                time_handle.advance(delay);
            }
        })
    };
    for handle in push_handles {
        handle.join().unwrap();
    }
    get_txs_handle.join().unwrap();
    // Validate the queue state.
    let array_queue: Vec<_> = core::iter::from_fn(|| queue.tx_hashes.pop()).collect();
    assert_eq!(array_queue.len(), queue.txs.len());
    for tx in array_queue {
        assert!(queue.txs.contains_key(&tx));
    }
    assert_eq!(queue.vacant_entry_warnings.load(Ordering::Relaxed), 0);
}
#[tokio::test]
async fn queue_throttling() {
    let kura = Kura::blank_kura_for_testing();
    let (alice_id, alice_keypair) = gen_account_in("wonderland");
    let (bob_id, bob_keypair) = gen_account_in("wonderland");
    let world = {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("Valid");
        let domain = Domain::new(domain_id.clone()).build(&alice_id);
        let alice_account = Account::new(alice_id.clone()).build(&alice_id);
        let bob_account = Account::new(bob_id.clone()).build(&bob_id);
        World::with([domain], [alice_account, bob_account], [])
    };
    // Explicit Global metadata belongs to this admission component fixture;
    // it does not authenticate genesis or certified native history.
    let mut parameters = world.parameters.block();
    parameters
        .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        ))
        .expect("valid fixture parameters");
    parameters.commit();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_handle);
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(
        Config {
            transaction_time_to_live: Duration::from_secs(100),
            capacity: 100.try_into().unwrap(),
            capacity_per_user: 1.try_into().unwrap(),
            ..Config::default()
        },
        &time_source,
    );
    let queue = Arc::new(queue);
    // First push by Alice should be fine
    queue
        .push(
            accepted_tx_by(alice_id.clone(), &alice_keypair, &time_source),
            state.view(),
        )
        .expect("Failed to push tx into queue");
    // Second push by Alice excide limit and will be rejected
    let result = queue.push(
        accepted_tx_by(alice_id.clone(), &alice_keypair, &time_source),
        state.view(),
    );
    assert!(
        matches!(
            result,
            Err(Failure {
                tx: _,
                err: Error::MaximumTransactionsPerUser
            }),
        ),
        "Failed to match: {result:?}",
    );
    // First push by Bob should be fine despite previous Alice error
    queue
        .push(
            accepted_tx_by(bob_id.clone(), &bob_keypair, &time_source),
            state.view(),
        )
        .expect("Failed to push tx into queue");
    let transactions = queue
        .bounded_pending_snapshot(&state.view(), nonzero!(10_usize))
        .unwrap();
    assert_eq!(transactions.len(), 2);
    let block_header = ValidBlock::new_dummy(&checked_random_queue_keypair().into_parts().1)
        .as_ref()
        .header();
    let mut state_block = state.block(block_header);
    // Put transaction hashes into state as if they were in the blockchain
    let transaction_hashes = transactions
        .iter()
        .map(AcceptedTransaction::hash_as_entrypoint)
        .collect::<HashSet<_>>();
    state_block
        .transactions
        .insert_block(transaction_hashes.clone(), nonzero!(1_usize));
    state_block.block_hashes.push(block_header.hash());
    state_block.commit().unwrap();
    // Apply the queue cleanup notification only after committing the transaction index.
    assert_eq!(queue.remove_committed_hashes(transaction_hashes, None), 2);
    let transactions = queue
        .bounded_pending_snapshot(&state.view(), nonzero!(10_usize))
        .unwrap();
    assert!(transactions.is_empty());
    // After cleanup Alice and Bob pushes should work fine
    queue
        .push(
            accepted_tx_by(alice_id, &alice_keypair, &time_source),
            state.view(),
        )
        .expect("Failed to push tx into queue");
    queue
        .push(
            accepted_tx_by(bob_id, &bob_keypair, &time_source),
            state.view(),
        )
        .expect("Failed to push tx into queue");
}
