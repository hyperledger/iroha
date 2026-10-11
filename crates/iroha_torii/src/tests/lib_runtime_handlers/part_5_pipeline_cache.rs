// Pipeline-status cache admission and pruning regressions.
#[test]
fn pipeline_status_merge_prefers_committed_success_over_cached_rejection() {
    let now = Instant::now();
    let rejection = TransactionRejectionReason::Validation(ValidationFail::TooComplex);
    let mut entry = PipelineStatusEntry::at_time(
        PipelineStatusKind::Rejected,
        None,
        Some(pipeline_rejection_summary(&rejection)),
        now,
    );
    entry.merge_from_event(PipelineStatusEntry::at_time(
        PipelineStatusKind::Committed,
        NonZeroU64::new(7),
        None,
        now + Duration::from_secs(1),
    ));
    assert_eq!(entry.kind, PipelineStatusKind::Committed);
    assert_eq!(entry.block_height, NonZeroU64::new(7));
    assert!(entry.rejection.is_none());
    entry.merge_from_event(PipelineStatusEntry::at_time(
        PipelineStatusKind::Applied,
        NonZeroU64::new(7),
        None,
        now + Duration::from_secs(2),
    ));
    assert_eq!(entry.kind, PipelineStatusKind::Applied);
    assert_eq!(entry.block_height, NonZeroU64::new(7));
    assert!(entry.rejection.is_none());
}
#[test]
fn pipeline_status_cache_records_transaction_event() {
    let cache = PipelineStatusCache::new();
    let (block, _) = make_signed_block(1, None);
    let tx_hash = block.external_transactions().next().expect("tx").hash();
    let height = NonZeroU64::new(2).expect("height");
    let event = TransactionEvent {
        hash: tx_hash,
        block_height: Some(height),
        lane_id: LaneId::new(1),
        dataspace_id: DataSpaceId::new(1),
        status: TransactionStatus::Approved,
    };
    cache.record_transaction_event(&event);
    let stored = cache.lookup(&tx_hash).expect("entry");
    assert_eq!(stored.kind, PipelineStatusKind::Approved);
    assert_eq!(stored.block_height, Some(height));
    assert!(stored.rejection.is_none());
}
#[test]
fn pipeline_status_cache_ignores_candidate_rejection() {
    let cache = PipelineStatusCache::new();
    let (block, _) = make_signed_block(1, None);
    let tx_hash = block.external_transactions().next().expect("tx").hash();
    let event = TransactionEvent {
        hash: tx_hash,
        block_height: NonZeroU64::new(2),
        lane_id: LaneId::new(1),
        dataspace_id: DataSpaceId::new(1),
        status: TransactionStatus::Rejected(Box::new(TransactionRejectionReason::Validation(
            ValidationFail::TooComplex,
        ))),
    };
    cache.record_transaction_event(&event);
    assert!(
        cache.lookup(&tx_hash).is_none(),
        "candidate execution must not become a terminal status"
    );
}
#[test]
fn pipeline_status_cache_stops_serving_hints_after_lag() {
    let cache = PipelineStatusCache::new();
    let (block, _) = make_signed_block(1, None);
    let tx_hash = block.external_transactions().next().expect("tx").hash();
    cache.record_entry(
        tx_hash,
        PipelineStatusEntry::fresh(PipelineStatusKind::Approved, None, None),
    );
    assert!(cache.lookup(&tx_hash).is_some());
    cache.invalidate_event_hints();
    assert!(cache.lookup(&tx_hash).is_none());

    let event = TransactionEvent {
        hash: tx_hash,
        block_height: None,
        lane_id: LaneId::new(1),
        dataspace_id: DataSpaceId::new(1),
        status: TransactionStatus::Queued,
    };
    cache.record_transaction_event(&event);
    assert!(cache.lookup(&tx_hash).is_none());
}
#[tokio::test]
async fn pipeline_status_cache_records_block_event() {
    let (app, tx_hash, chain) = canonical_outcome_test_fixture(false);
    let header = chain.committed(2).block().header();
    let event = BlockEvent {
        header,
        status: BlockStatus::Applied,
    };
    app.pipeline_status_cache
        .record_block_event(&event, &app.state);
    let stored = app.pipeline_status_cache.lookup(&tx_hash).expect("entry");
    assert_eq!(stored.kind, PipelineStatusKind::Applied);
    assert_eq!(stored.block_height, NonZeroU64::new(2));
}
#[tokio::test]
async fn pipeline_status_cache_refreshes_pending_block() {
    let unavailable = mk_app_state_for_tests();
    let (app, tx_hash, chain) = canonical_outcome_test_fixture(false);
    let event = BlockEvent {
        header: chain.committed(2).block().header(),
        status: BlockStatus::Committed,
    };
    // The original event remains pending until its exact certified native
    // carrier is visible to the reader; raw custody is insufficient.
    app.pipeline_status_cache
        .record_block_event(&event, &unavailable.state);
    assert!(app.pipeline_status_cache.lookup(&tx_hash).is_none());
    assert_eq!(app.pipeline_status_cache.pending_blocks.len(), 1);
    let outcome = reconcile_pending_pipeline_transaction(&app, &tx_hash)
        .unwrap()
        .unwrap();
    assert!(matches!(
        outcome,
        CanonicalTransactionOutcome::Applied { .. }
    ));
    let stored = app.pipeline_status_cache.lookup(&tx_hash).expect("entry");
    assert_eq!(stored.kind, PipelineStatusKind::Committed);
    assert_eq!(stored.block_height, NonZeroU64::new(2));
    assert!(app.pipeline_status_cache.pending_blocks.is_empty());
}
#[tokio::test]
async fn pipeline_status_cache_rejects_uncertified_block_custody() {
    let app = mk_app_state_for_tests();
    let (block, _) = make_signed_block(1, None);
    let header = block.header();
    let tx_hash = block.external_transactions().next().expect("tx").hash();
    let block_hash = store_block(&app, block);
    record_committed_block_hash_for_test(&app, header.clone(), block_hash);
    let event = BlockEvent {
        header,
        status: BlockStatus::Applied,
    };
    app.pipeline_status_cache
        .record_block_event(&event, &app.state);
    assert!(
        reconcile_pending_pipeline_transaction(&app, &tx_hash)
            .unwrap()
            .is_none()
    );
    assert!(app.pipeline_status_cache.lookup(&tx_hash).is_none());
    assert_eq!(app.pipeline_status_cache.pending_blocks.len(), 1);
}
#[test]
fn pipeline_status_cache_prunes_stale_entries() {
    let cache = PipelineStatusCache::with_limits(10, Duration::from_secs(1));
    let (block, _) = make_signed_block(1, None);
    let tx_hash = block.external_transactions().next().expect("tx").hash();
    let now = Instant::now();
    let stale = now
        .checked_sub(Duration::from_secs(5))
        .expect("time subtraction");
    cache.record_entry(
        tx_hash,
        PipelineStatusEntry::at_time(PipelineStatusKind::Queued, None, None, stale),
    );
    cache.prune(now);
    assert!(cache.lookup(&tx_hash).is_none());
}
#[test]
fn pipeline_status_cache_eviction_respects_capacity() {
    let cache = PipelineStatusCache::with_limits(1, Duration::from_secs(60));
    let (block_a, _) = make_signed_block(1, None);
    let hash_a = block_a.external_transactions().next().expect("tx").hash();
    let hash_b = checked_torii_test_transaction(
        TransactionBuilder::new(
            signed_query_test_network_id(),
            ALICE_ID.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(
            Level::INFO,
            "distinct cache eviction input".to_owned(),
        )]),
        &iroha_test_samples::ALICE_KEYPAIR,
        "sign the independent cache eviction input",
    )
    .hash();
    assert_ne!(
        hash_a, hash_b,
        "capacity eviction requires distinct original inputs"
    );
    let now = Instant::now();
    let stale = now
        .checked_sub(Duration::from_secs(5))
        .expect("time subtraction");
    cache.record_entry(
        hash_a,
        PipelineStatusEntry::at_time(PipelineStatusKind::Queued, None, None, stale),
    );
    cache.record_entry(
        hash_b,
        PipelineStatusEntry::at_time(PipelineStatusKind::Queued, None, None, now),
    );
    cache.prune(now);
    assert!(cache.lookup(&hash_a).is_none());
    assert!(cache.lookup(&hash_b).is_some());
}
#[test]
fn pipeline_status_cache_live_counts_track_entries_and_pending_blocks() {
    let cache = PipelineStatusCache::with_limits(1, Duration::from_secs(60));
    let (block_a, _) = make_signed_block(1, None);
    let (block_b, _) = make_signed_block(2, None);
    let hash_a = block_a.external_transactions().next().expect("tx").hash();
    let hash_b = checked_torii_test_transaction(
        TransactionBuilder::new(
            signed_query_test_network_id(),
            ALICE_ID.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(
            Level::INFO,
            "distinct live-count cache input".to_owned(),
        )]),
        &iroha_test_samples::ALICE_KEYPAIR,
        "sign independent live-count cache input",
    )
    .hash();
    assert_ne!(
        hash_a, hash_b,
        "live counts require two distinct original inputs"
    );
    let height_a = NonZeroU64::new(1).expect("height");
    let now = Instant::now();
    cache.record_entry(
        hash_a,
        PipelineStatusEntry::at_time(PipelineStatusKind::Queued, None, None, now),
    );
    cache.record_entry(
        hash_a,
        PipelineStatusEntry::at_time(PipelineStatusKind::Approved, None, None, now),
    );
    assert_eq!(cache.entry_count.load(Ordering::Relaxed), 1);
    assert_eq!(cache.entry_order.lock().len(), 1);
    cache.record_entry(
        hash_b,
        PipelineStatusEntry::at_time(
            PipelineStatusKind::Queued,
            None,
            None,
            now + Duration::from_secs(1),
        ),
    );
    cache.prune(now + Duration::from_secs(1));
    assert_eq!(
        cache.entry_count.load(Ordering::Relaxed),
        cache.entries.len()
    );
    assert!(cache.lookup(&hash_a).is_none());
    assert!(cache.lookup(&hash_b).is_some());
    cache.record_pending_block(
        height_a,
        PendingBlockStatus {
            kind: PipelineStatusKind::Committed,
            block_hash: block_a.header().hash(),
            observed_at: now,
            deferred: None,
        },
    );
    cache.record_pending_block(
        height_a,
        PendingBlockStatus {
            kind: PipelineStatusKind::Applied,
            block_hash: block_b.header().hash(),
            observed_at: now + Duration::from_secs(1),
            deferred: None,
        },
    );
    assert_eq!(cache.pending_count.load(Ordering::Relaxed), 1);
    assert_eq!(cache.pending_order.lock().len(), 1);
    assert!(cache.remove_pending_by_height(&height_a));
    assert_eq!(cache.pending_count.load(Ordering::Relaxed), 0);
}
#[test]
fn pipeline_status_cache_updates_do_not_accumulate_markers_or_extend_retention() {
    let cache = PipelineStatusCache::with_limits(10, Duration::from_secs(1));
    let (block, _) = make_signed_block(1, None);
    let tx_hash = block.external_transactions().next().expect("tx").hash();
    let now = Instant::now();
    let stale = now
        .checked_sub(Duration::from_secs(5))
        .expect("time subtraction");
    cache.record_entry(
        tx_hash,
        PipelineStatusEntry::at_time(PipelineStatusKind::Queued, None, None, stale),
    );
    cache.record_entry(
        tx_hash,
        PipelineStatusEntry::at_time(PipelineStatusKind::Queued, None, None, now),
    );
    assert_eq!(cache.entry_order.lock().len(), 1);
    cache.prune(now);
    assert!(cache.lookup(&tx_hash).is_none());
}
#[test]
fn pipeline_status_cache_pending_blocks_prune_by_ttl_and_capacity() {
    let cache = PipelineStatusCache::with_limits(1, Duration::from_secs(1));
    let (block_a, _) = make_signed_block(1, None);
    let (block_b, _) = make_signed_block(2, None);
    let height_a = NonZeroU64::new(1).expect("height");
    let height_b = NonZeroU64::new(2).expect("height");
    let now = Instant::now();
    let stale = now
        .checked_sub(Duration::from_secs(5))
        .expect("time subtraction");
    cache.record_pending_block(
        height_a,
        PendingBlockStatus {
            kind: PipelineStatusKind::Committed,
            block_hash: block_a.header().hash(),
            observed_at: stale,
            deferred: None,
        },
    );
    cache.record_pending_block(
        height_b,
        PendingBlockStatus {
            kind: PipelineStatusKind::Applied,
            block_hash: block_b.header().hash(),
            observed_at: now,
            deferred: None,
        },
    );
    cache.prune(now);
    assert!(cache.pending_blocks.get(&height_a).is_none());
    assert!(cache.pending_blocks.get(&height_b).is_some());
}

#[tokio::test]
async fn original_history_pool_refusal_preserves_pending_status_and_refuses_visibility_and_health()
{
    use futures::FutureExt as _;
    use iroha_core::execution_attempt::ExecutionAttemptError;
    let (app, tx_hash, chain) = canonical_outcome_test_fixture(false);
    let block = chain.committed(2).block().clone();
    let header = block.header();
    let height = NonZeroUsize::new(2).unwrap();
    app.kura.forget_cached_block_for_testing(height).unwrap();
    let pool = app.state.ivm_execution_budget();
    let occupied = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
        .unwrap();
    let expected = pool.try_reserve_bytes(1).unwrap_err();
    let iroha_allocation::AllocationRefusal::Capacity {
        release: expected_release,
        ..
    } = &expected
    else {
        panic!("original finite pool is temporarily occupied");
    };
    let event = TransactionEvent {
        hash: tx_hash,
        block_height: NonZeroU64::new(2),
        lane_id: LaneId::new(0),
        dataspace_id: DataSpaceId::new(0),
        status: TransactionStatus::Approved,
    };
    let Err(ExecutionAttemptError::Deferred(reason)) =
        ToriiDataspaceReadContext::transaction_event_scope(&app.kura, &event, &pool)
    else {
        panic!("occupied history cannot become global-reader fallback or absent scope");
    };
    let Some(iroha_allocation::AllocationRefusal::Capacity { release, .. }) =
        reason.allocation_refusal()
    else {
        panic!("read must retain the original allocation release source");
    };
    assert_eq!(release, expected_release);
    assert_eq!(
        app.kura.get_block_hash(height),
        Some(block.hash()),
        "refusal cannot poison or delete original history"
    );

    let cache = &app.pipeline_status_cache;
    cache.record_block_event(
        &BlockEvent {
            header,
            status: BlockStatus::Applied,
        },
        &app.state,
    );
    assert!(cache.lookup(&tx_hash).is_none());
    let pending = cache
        .pending_blocks
        .get(&NonZeroU64::new(2).unwrap())
        .unwrap();
    assert!(
        pending.deferred.is_some(),
        "local capacity remains distinct from missing history"
    );
    assert_eq!(pending.block_hash, block.hash());
    drop(pending);
    // Off-chain Explorer reads retain their actual query owner, independently
    // of the execution pool used by status and event-visibility reads above.
    let reservation = try_acquire_new_query_fanout_memory(&app)
        .expect("fund original Explorer query working set");
    let admission = COLLECTION_READ_MEMORY_RESERVATION
        .scope(reservation, acquire_query_admission(&app, true))
        .await
        .expect("admit original Explorer read");
    let owner = crate::history_producer::HistoryProducerOwner::from_admission(&admission)
        .expect("retain original Explorer query owner");
    let cold_pool = owner.cold_frames();
    let occupied_cold = cold_pool
        .try_reserve_bytes(cold_pool.limit_bytes() - cold_pool.reserved_bytes())
        .expect("occupy the original Explorer cold-frame pool");
    let error = owner
        .scope(|| {
            routing::handle_v1_explorer_health(
                app.state.clone(),
                routing::MaybeTelemetry::disabled(),
            )
            .now_or_never()
            .expect("health production completes synchronously inside its owner")
        })
        .expect_err("health may not replace resource refusal with a null timestamp");
    assert_eq!(
        error.into_response().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        routing::handle_version(app.state.clone()).await.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "latest-version read cannot report missing genesis under capacity pressure"
    );
    let detail = routing::handle_v1_explorer_block_detail_admitted(
        app.state.clone(),
        routing::MaybeTelemetry::disabled(),
        routing::DataspaceReadVisibility::all_for_tests(),
        "2".to_owned(),
        admission,
    )
    .await
    .expect_err("capacity cannot authorize hash-only Explorer fallback");
    assert_eq!(
        detail.into_response().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let outcome = canonical_transaction_outcome(&app.state, &tx_hash)
        .expect_err("terminal status waits for history capacity");
    assert_eq!(
        outcome.into_response().status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    drop(occupied);
    drop(occupied_cold);
    let outcome = owner
        .scope(|| reconcile_pending_pipeline_transaction(&app, &tx_hash))
        .expect("retry uses the original admitted query owner and exact pending source")
        .unwrap();
    assert!(matches!(
        outcome,
        CanonicalTransactionOutcome::Applied { .. }
    ));
    assert!(cache.pending_blocks.is_empty());
    assert_eq!(
        cache.lookup(&tx_hash).unwrap().kind,
        PipelineStatusKind::Applied
    );
    assert!(ToriiDataspaceReadContext::transaction_event_scope(&app.kura, &event, &pool).is_ok());
    assert_eq!(
        owner
            .scope(|| {
                routing::handle_v1_explorer_health(
                    app.state.clone(),
                    routing::MaybeTelemetry::disabled(),
                )
                .now_or_never()
                .expect("health retry completes synchronously inside its owner")
            })
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn pipeline_block_event_reads_recent_original_carrier_and_preserves_refused_event() {
    let (app, _, mut chain) = canonical_outcome_test_fixture(false);
    chain.commit(Vec::new());
    chain.commit(Vec::new());
    let key = checked_torii_test_ed25519_keypair(0x24, "native history authority");
    let mut builder = TransactionBuilder::new(
        chain.network_id(),
        AccountId::new(key.public_key().clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(Duration::from_millis(5_000));
    let transaction = builder
        .with_instructions([Log::new(
            Level::INFO,
            "original recent block-event carrier".into(),
        )])
        .sign(key.private_key());
    let hash = transaction.hash();
    assert_eq!(chain.commit(vec![transaction]), [true]);
    assert_eq!(chain.height(), 5);
    let original = chain.committed(5).block().clone();
    let event = BlockEvent {
        header: original.header(),
        status: BlockStatus::Applied,
    };
    let pool = app.state.ivm_execution_budget();
    let reserved = pool.reserved_bytes();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - reserved)
        .unwrap();
    app.pipeline_status_cache
        .record_block_event(&event, &app.state);
    assert!(app.pipeline_status_cache.lookup(&hash).is_none());
    let pending = app
        .pipeline_status_cache
        .pending_blocks
        .get(&NonZeroU64::new(5).unwrap())
        .unwrap();
    assert_eq!(pending.block_hash, original.hash());
    assert_eq!(pending.kind, PipelineStatusKind::Applied);
    assert!(pending.deferred.is_some());
    let observed_at = pending.observed_at;
    drop(pending);
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    drop(blocker);
    // Re-delivery of the actual event retries the same immutable source; the
    // event projection grants no query admission, output authority or State mutation.
    app.pipeline_status_cache
        .record_block_event(&event, &app.state);
    let stored = app
        .pipeline_status_cache
        .lookup(&hash)
        .expect("actual recent Network result");
    assert_eq!(stored.kind, PipelineStatusKind::Applied);
    assert_eq!(stored.block_height, NonZeroU64::new(5));
    assert!(stored.observed_at >= observed_at);
    assert!(app.pipeline_status_cache.pending_blocks.is_empty());
    assert!(stored.rejection.is_none());
    assert_eq!(pool.reserved_bytes(), reserved);
}

#[tokio::test]
async fn pipeline_block_event_keeps_exact_writer_refusal_and_returns_before_publication() {
    let (app, hash, chain) = canonical_outcome_test_fixture(false);
    let original = chain.committed(2).block().clone();
    let event = BlockEvent {
        header: original.header(),
        status: BlockStatus::Applied,
    };
    let state = app.state.clone();
    let cache = app.pipeline_status_cache.clone();
    let unrelated_height = NonZeroU64::new(99).unwrap();
    let unrelated_hash =
        HashOf::from_untyped_unchecked(Hash::new(b"unrelated event writer refusal source"));
    let observed_at = Instant::now();
    cache.record_pending_block(
        unrelated_height,
        PendingBlockStatus {
            kind: PipelineStatusKind::Committed,
            block_hash: unrelated_hash,
            observed_at,
            deferred: None,
        },
    );
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let mut job = None;
    let (expected, returned) = state.with_held_view_publication_for_reader_test(|wait| {
        let source = state.clone();
        let pending = cache.clone();
        job = Some(std::thread::spawn(move || {
            pending.record_block_event(&event, &source);
            done_tx.send(()).unwrap();
        }));
        (wait, done_rx.recv_timeout(Duration::from_secs(2)))
    });
    job.unwrap().join().unwrap();
    assert!(
        returned.is_ok(),
        "pending block event must return its original writer refusal"
    );
    assert!(cache.lookup(&hash).is_none());
    let height = NonZeroU64::new(2).unwrap();
    let pending = cache.pending_blocks.get(&height).unwrap();
    assert_eq!(pending.kind, PipelineStatusKind::Applied);
    assert_eq!(pending.block_hash, original.hash());
    assert_eq!(
        pending.deferred,
        Some(PendingBlockDeferral::StateViewBusy(expected))
    );
    let original_observed_at = pending.observed_at;
    drop(pending);
    let unrelated = cache.pending_blocks.get(&unrelated_height).unwrap();
    assert_eq!(unrelated.block_hash, unrelated_hash);
    assert_eq!(unrelated.observed_at, observed_at);
    assert!(unrelated.deferred.is_none());
    drop(unrelated);
    cache.record_block_event(
        &BlockEvent {
            header: original.header(),
            status: BlockStatus::Applied,
        },
        &state,
    );
    let stored = cache.lookup(&hash).unwrap();
    assert_eq!(stored.kind, PipelineStatusKind::Applied);
    assert!(stored.observed_at >= original_observed_at);
    assert!(cache.pending_blocks.get(&height).is_none());
    assert!(cache.pending_blocks.get(&unrelated_height).is_some());
}
