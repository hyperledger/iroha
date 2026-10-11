// Native actor/State/Kura controls. The included parent owns the real unit fixture.
use iroha_torii_shared::status::BuildStatus;

async fn pause_actor(sut: &SystemUnderTest) -> oneshot::Sender<()> {
    let (entered, ready) = oneshot::channel();
    let (resume, wait) = oneshot::channel();
    sut.telemetry
        .actor
        .send(Message::TestBarrier {
            entered,
            resume: wait,
        })
        .await
        .unwrap_or_else(|_| panic!("live actor"));
    ready.await.expect("actor entered barrier");
    resume
}

fn request(sut: &SystemUnderTest) -> oneshot::Receiver<Result<OwnedStatus, StatusSnapshotError>> {
    let (reply, response) = oneshot::channel();
    sut.telemetry
        .actor
        .try_send(Message::Status {
            build: BuildStatus::default(),
            deadline: tokio::time::Instant::now() + METRICS_SYNC_TIMEOUT,
            reply,
        })
        .unwrap_or_else(|_| panic!("status mailbox admission"));
    response
}

fn replace_tip(sut: &SystemUnderTest, hash: HashOf<BlockHeader>) {
    let mut journal = sut.state.block_hashes.block_and_revert();
    journal.push_for_tests(hash);
    journal.commit_for_tests();
}

#[tokio::test(start_paused = true)]
async fn queued_status_captures_the_publication_after_its_admission_barrier() {
    let sut = SystemUnderTest::new_native();
    let resume = pause_actor(&sut).await;
    let pre_await_height = sut.state.committed_height();
    let response = request(&sut);
    let block = sut.commit_block(sut.create_block());
    let external = u64::try_from(
        block.block().external_transactions().len()
            + sut
                .native_chain
                .lock()
                .expect("native chain mutex")
                .as_ref()
                .unwrap()
                .genesis()
                .external_transactions()
                .len(),
    )
    .unwrap();
    resume.send(()).unwrap();
    let (status, height) = response.await.unwrap().unwrap().into_parts();
    assert_eq!(pre_await_height, 1);
    assert_eq!(height, pre_await_height as u64 + 1);
    assert_eq!(height, 2);
    assert_eq!(status.blocks, height);
    assert_eq!(status.blocks_non_empty, 2);
    assert_eq!(status.txs_approved + status.txs_rejected, external);
    assert!(status.nexus.is_some());
}

#[tokio::test(start_paused = true)]
async fn owned_status_bytes_remain_immutable_after_later_classification() {
    let sut = SystemUnderTest::new_native();
    sut.commit_block(sut.create_block());
    let (first, first_height) = sut
        .telemetry
        .status_snapshot(&BuildStatus::default())
        .await
        .unwrap()
        .into_parts();
    let original = norito::to_bytes(&first).unwrap();
    sut.mock_time_handle.advance(Duration::from_millis(10));
    sut.commit_block(sut.create_block());
    let (second, second_height) = sut
        .telemetry
        .status_snapshot(&BuildStatus::default())
        .await
        .unwrap()
        .into_parts();
    assert_eq!((first_height, second_height), (2, 3));
    assert_eq!((first.blocks, second.blocks), (2, 3));
    assert_eq!(norito::to_bytes(&first).unwrap(), original);
}

#[tokio::test(start_paused = true)]
async fn missing_applied_kura_block_cannot_publish_any_classified_counter() {
    let sut = SystemUnderTest::new();
    let mut journal = sut.state.block_hashes.block();
    journal.push_for_tests(HashOf::from_untyped_unchecked(Hash::new(
        b"missing status body",
    )));
    journal.commit_for_tests();
    let result = sut.telemetry.status_snapshot(&BuildStatus::default()).await;
    assert!(matches!(result, Err(StatusSnapshotError::MissingBlock)));
    assert_eq!(sut.telemetry.metrics.block_height.get(), 0);
    assert_eq!(sut.telemetry.metrics.block_height_non_empty.get(), 0);
    assert_eq!(
        sut.telemetry
            .metrics
            .txs
            .with_label_values(&["total"])
            .get(),
        0
    );
}

#[tokio::test(start_paused = true)]
async fn substituted_kura_sequence_retires_staged_counters_and_retries_exactly_once() {
    let sut = SystemUnderTest::new_native();
    let block = sut.commit_block(sut.create_block());
    let actual = block.block().header().hash();
    let other = HashOf::from_untyped_unchecked(Hash::new(b"substituted status journal"));
    replace_tip(&sut, other);
    let result = sut.telemetry.status_snapshot(&BuildStatus::default()).await;
    assert!(matches!(result, Err(StatusSnapshotError::JournalMismatch)));
    assert_eq!(sut.telemetry.metrics.block_height.get(), 0);
    assert_eq!(
        sut.telemetry
            .metrics
            .txs
            .with_label_values(&["total"])
            .get(),
        0
    );
    assert_eq!(sut.telemetry.metrics.last_block_committed_at_ms.get(), 0);
    replace_tip(&sut, actual);
    let (status, height) = sut
        .telemetry
        .status_snapshot(&BuildStatus::default())
        .await
        .unwrap()
        .into_parts();
    assert_eq!(height, 2);
    assert_eq!(status.blocks_non_empty, 2);
    let total = sut
        .telemetry
        .metrics
        .txs
        .with_label_values(&["total"])
        .get();
    sut.telemetry
        .status_snapshot(&BuildStatus::default())
        .await
        .unwrap();
    assert_eq!(
        sut.telemetry
            .metrics
            .txs
            .with_label_values(&["total"])
            .get(),
        total
    );
    replace_tip(&sut, other);
    assert!(matches!(
        sut.telemetry.status_snapshot(&BuildStatus::default()).await,
        Err(StatusSnapshotError::CheckpointChanged)
    ));
    assert_eq!(sut.telemetry.metrics.block_height.get(), 2);
}

#[tokio::test(start_paused = true)]
async fn expired_active_status_finishes_its_finite_target_and_keeps_chunk_progress() {
    let sut = SystemUnderTest::new_native();
    for _ in 0..64 {
        sut.mock_time_handle.advance(Duration::from_millis(1));
        sut.commit_block(sut.create_block());
    }
    let (entered, ready) = oneshot::channel();
    let (resume, wait) = oneshot::channel();
    sut.telemetry
        .actor
        .send(Message::TestChunkBarrier {
            entered,
            resume: wait,
        })
        .await
        .unwrap_or_else(|_| panic!("live actor"));
    let response = request(&sut);
    assert_eq!(ready.await.unwrap(), 64);
    assert_eq!(sut.telemetry.metrics.block_height.get(), 64);
    // A later publication must not extend this active request's fixed target.
    sut.mock_time_handle.advance(Duration::from_millis(1));
    let extra = sut.commit_block(sut.create_block());
    let extra_count = u64::try_from(extra.block().external_transactions().len()).unwrap();
    assert_eq!(sut.state.telemetry_status_target().unwrap().height, 66);
    tokio::time::advance(METRICS_SYNC_TIMEOUT).await;
    resume.send(()).unwrap();
    assert!(matches!(
        response.await.unwrap(),
        Err(StatusSnapshotError::DeadlineElapsed)
    ));
    assert_eq!(sut.telemetry.metrics.block_height.get(), 65);
    let before = sut
        .telemetry
        .metrics
        .txs
        .with_label_values(&["total"])
        .get();
    let (status, height) = sut
        .telemetry
        .status_snapshot(&BuildStatus::default())
        .await
        .unwrap()
        .into_parts();
    assert_eq!(height, 66);
    assert_eq!(status.blocks, 66);
    assert_eq!(
        sut.telemetry
            .metrics
            .txs
            .with_label_values(&["total"])
            .get(),
        before + extra_count
    );
    sut.telemetry
        .status_snapshot(&BuildStatus::default())
        .await
        .unwrap();
    assert_eq!(
        sut.telemetry
            .metrics
            .txs
            .with_label_values(&["total"])
            .get(),
        before + extra_count
    );
}

#[tokio::test(start_paused = true)]
async fn dropping_http_waiter_does_not_drop_active_actor_work() {
    let sut = SystemUnderTest::new_native();
    sut.commit_block(sut.create_block());
    let (entered, ready) = oneshot::channel();
    let (resume, wait) = oneshot::channel();
    sut.telemetry
        .actor
        .send(Message::TestChunkBarrier {
            entered,
            resume: wait,
        })
        .await
        .unwrap_or_else(|_| panic!("live actor"));
    let response = request(&sut);
    assert_eq!(ready.await.unwrap(), 2);
    drop(response);
    let (entered, mut next) = oneshot::channel();
    let (release_next, wait_next) = oneshot::channel();
    sut.telemetry
        .actor
        .send(Message::TestBarrier {
            entered,
            resume: wait_next,
        })
        .await
        .unwrap_or_else(|_| panic!("live actor"));
    assert!(matches!(
        next.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    resume.send(()).unwrap();
    next.await.unwrap();
    assert_eq!(sut.telemetry.metrics.block_height.get(), 2);
    release_next.send(()).unwrap();
    assert_eq!(
        sut.telemetry
            .status_snapshot(&BuildStatus::default())
            .await
            .unwrap()
            .into_parts()
            .1,
        2
    );
}

#[tokio::test(start_paused = true)]
async fn status_queue_wait_uses_original_500ms_deadline_and_does_not_start_expired_work() {
    let sut = SystemUnderTest::new();
    let resume = pause_actor(&sut).await;
    let start = tokio::time::Instant::now();
    let error = sut.telemetry.status_snapshot(&BuildStatus::default()).await;
    assert!(matches!(error, Err(StatusSnapshotError::DeadlineElapsed)));
    assert_eq!(tokio::time::Instant::now() - start, METRICS_SYNC_TIMEOUT);
    resume.send(()).unwrap();
    let resume = pause_actor(&sut).await;
    assert_eq!(sut.telemetry.metrics.block_height.get(), 0);
    resume.send(()).unwrap();
}

#[tokio::test(start_paused = true)]
async fn status_mailbox_full_closed_and_disabled_are_explicit() {
    let sut = SystemUnderTest::new();
    let resume = pause_actor(&sut).await;
    for _ in 0..CHANNEL_CAPACITY {
        sut.telemetry
            .actor
            .try_send(Message::Sync { reply: None })
            .unwrap_or_else(|_| panic!("exact bounded mailbox"));
    }
    assert!(matches!(
        sut.telemetry.status_snapshot(&BuildStatus::default()).await,
        Err(StatusSnapshotError::MailboxUnavailable)
    ));
    resume.send(()).unwrap();
    let closed = Telemetry::new(Arc::new(Metrics::default()), true);
    assert!(matches!(
        closed.status_snapshot(&BuildStatus::default()).await,
        Err(StatusSnapshotError::MailboxUnavailable)
    ));
    let disabled = Telemetry::new(Arc::new(Metrics::default()), false);
    assert!(matches!(
        disabled.status_snapshot(&BuildStatus::default()).await,
        Err(StatusSnapshotError::Disabled)
    ));
}

#[tokio::test(start_paused = true)]
async fn checked_metrics_sync_and_status_refuse_substituted_counter_height() {
    let sut = SystemUnderTest::new();
    sut.telemetry.metrics.block_height.inc();
    assert!(matches!(
        sut.telemetry.status_snapshot(&BuildStatus::default()).await,
        Err(StatusSnapshotError::CounterMismatch)
    ));
    assert!(sut.telemetry.metrics_fresh_checked().await.is_err());
}

#[tokio::test(start_paused = true)]
async fn cold_status_history_refusal_retains_original_pool_and_unpublished_counters() {
    use iroha_allocation::{AllocationBudget, AllocationRefusal};
    use iroha_data_model::block::SharedSignedBlock;
    use std::{
        future::Future as _,
        pin::pin,
        task::{Context, Waker},
    };

    let sut = SystemUnderTest::new_native();
    sut.commit_block(sut.create_block());
    let original_wire = sut
        .kura
        .canonical_block_wire_bytes_for_testing(NonZeroUsize::MIN)
        .unwrap();
    sut.kura
        .forget_cached_block_for_testing(NonZeroUsize::MIN)
        .unwrap();
    let budget = sut.state.ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let layout = SharedSignedBlock::allocation_layout();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let expected = budget.try_reserve(layout).unwrap_err();
    let response = sut.telemetry.status_snapshot(&BuildStatus::default()).await;
    let Err(StatusSnapshotError::Deferred(reason)) = response else {
        panic!("cold status must return its original local refusal");
    };
    assert_eq!(reason.allocation_refusal(), Some(&expected));
    let AllocationRefusal::Capacity { release, .. } = expected else {
        panic!("occupied original history pool");
    };
    let mut released = pin!(release.wait_for_release(&mut registration));
    let mut context = Context::from_waker(Waker::noop());
    assert!(released.as_mut().poll(&mut context).is_pending());
    assert_eq!(sut.telemetry.metrics.block_height.get(), 0);
    assert_eq!(sut.telemetry.metrics.block_height_non_empty.get(), 0);
    assert_eq!(
        sut.telemetry
            .metrics
            .txs
            .with_label_values(&["total"])
            .get(),
        0
    );
    assert_eq!(sut.telemetry.metrics.last_block_committed_at_ms.get(), 0);
    assert_eq!(
        sut.kura
            .canonical_block_wire_bytes_for_testing(NonZeroUsize::MIN)
            .unwrap(),
        original_wire
    );
    let unrelated = AllocationBudget::new(layout.size());
    drop(unrelated.try_reserve(layout).unwrap());
    assert!(released.as_mut().poll(&mut context).is_pending());
    drop(occupied);
    assert!(released.as_mut().poll(&mut context).is_ready());
    let (status, height) = sut
        .telemetry
        .status_snapshot(&BuildStatus::default())
        .await
        .expect("same actor and canonical source retry after original refund")
        .into_parts();
    assert_eq!(height, 2);
    assert_eq!(status.blocks, 2);
    let total = sut
        .telemetry
        .metrics
        .txs
        .with_label_values(&["total"])
        .get();
    assert!(total > 0);
    sut.telemetry
        .status_snapshot(&BuildStatus::default())
        .await
        .unwrap();
    assert_eq!(
        sut.telemetry
            .metrics
            .txs
            .with_label_values(&["total"])
            .get(),
        total
    );
}

#[tokio::test(start_paused = true)]
async fn cold_genesis_uptime_refusal_remains_deferred_after_classified_prefix() {
    use iroha_data_model::block::SharedSignedBlock;

    let sut = SystemUnderTest::new_native();
    let (_, height) = sut
        .telemetry
        .status_snapshot(&BuildStatus::default())
        .await
        .unwrap()
        .into_parts();
    assert_eq!(height, 1);
    let total = sut
        .telemetry
        .metrics
        .txs
        .with_label_values(&["total"])
        .get();
    let uptime = sut.telemetry.metrics.uptime_since_genesis_ms.get();
    sut.kura
        .forget_cached_block_for_testing(NonZeroUsize::MIN)
        .unwrap();
    let budget = sut.state.ivm_execution_budget();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let expected = budget
        .try_reserve(SharedSignedBlock::allocation_layout())
        .unwrap_err();
    let response = sut.telemetry.status_snapshot(&BuildStatus::default()).await;
    assert!(
        matches!(response, Err(StatusSnapshotError::Deferred(reason)) if reason.allocation_refusal() == Some(&expected))
    );
    assert_eq!(sut.telemetry.metrics.block_height.get(), 1);
    assert_eq!(
        sut.telemetry
            .metrics
            .txs
            .with_label_values(&["total"])
            .get(),
        total
    );
    assert_eq!(sut.telemetry.metrics.uptime_since_genesis_ms.get(), uptime);
    drop(occupied);
    let (_, recovered_height) = sut
        .telemetry
        .status_snapshot(&BuildStatus::default())
        .await
        .unwrap()
        .into_parts();
    assert_eq!(recovered_height, 1);
    assert_eq!(
        sut.telemetry
            .metrics
            .txs
            .with_label_values(&["total"])
            .get(),
        total
    );
}

// Test-owned real publisher lifetime. Cleanup releases and joins on every outcome.
struct HeldStatusPublication {
    release: Option<std::sync::mpsc::Sender<()>>,
    writer: Option<std::thread::JoinHandle<()>>,
}

impl HeldStatusPublication {
    fn release_and_join(mut self) -> std::thread::Result<()> {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        self.writer
            .take()
            .expect("original publisher thread")
            .join()
    }
}

impl Drop for HeldStatusPublication {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

async fn hold_original_status_publication(
    state: &Arc<State>,
) -> (
    HeldStatusPublication,
    iroha_allocation::release::ReleaseWait,
) {
    let (entered, ready) = oneshot::channel();
    let (release, resume) = std::sync::mpsc::channel();
    let original = Arc::clone(state);
    let writer = std::thread::spawn(move || {
        original.with_held_view_publication_for_reader_test(|wait| {
            entered.send(wait).expect("original publication entered");
            let _ = resume.recv();
        });
    });
    let held = HeldStatusPublication {
        release: Some(release),
        writer: Some(writer),
    };
    let wait = ready.await.expect("actual publisher handshake");
    (held, wait)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_prelude_refuses_original_publication_before_service_deadline() {
    let sut = SystemUnderTest::new_native();
    // Complete actual actor startup and canonical classification before contention.
    let (warm, warm_height) = sut
        .telemetry
        .status_snapshot(&BuildStatus::default())
        .await
        .expect("current native status before held publication")
        .into_parts();
    assert_eq!(
        warm_height,
        u64::try_from(sut.state.committed_height()).unwrap()
    );
    let budget = sut.state.ivm_execution_budget();
    let charged = budget.reserved_bytes();
    let (held, original_wait) = hold_original_status_publication(&sut.state).await;
    let exact_original = matches!(
        sut.state.try_view_once(),
        Err(crate::state::StateViewError::Busy(wait)) if wait == original_wait
    );
    let start = tokio::time::Instant::now();
    let result = sut.telemetry.status_snapshot(&BuildStatus::default()).await;
    let elapsed = start.elapsed();
    let held_charge = budget.reserved_bytes();
    // Both old and repaired paths release and physically join before assertions.
    let joined = held.release_and_join();
    let (after, height) = sut
        .telemetry
        .status_snapshot(&BuildStatus::default())
        .await
        .expect("current native classification after original publisher release")
        .into_parts();
    assert!(joined.is_ok(), "original status publisher must join");
    assert!(
        exact_original,
        "test holds the actual State publication refusal"
    );
    assert_eq!(held_charge, charged);
    assert_eq!(budget.reserved_bytes(), charged);
    assert_eq!(height, u64::try_from(sut.state.committed_height()).unwrap());
    assert_eq!(height, warm_height);
    assert_eq!(after.blocks, height);
    assert_eq!(after.txs_approved, warm.txs_approved);
    assert_eq!(after.txs_rejected, warm.txs_rejected);
    assert_eq!(
        after.sumeragi.unwrap().mode_tag,
        warm.sumeragi.unwrap().mode_tag
    );
    assert!(
        matches!(result, Err(StatusSnapshotError::StateBusy)),
        "status prelude must return the original State busy refusal without waiting for publication: observed {result:?}"
    );
    assert!(
        elapsed < METRICS_SYNC_TIMEOUT,
        "original status deadline is unchanged"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_final_world_sample_refuses_publication_after_verified_chunk() {
    let sut = SystemUnderTest::new_native();
    sut.telemetry
        .status_snapshot(&BuildStatus::default())
        .await
        .expect("current native genesis classification");
    let block = sut.commit_block(sut.create_block());
    let expected_height = usize::try_from(block.height()).unwrap();
    let (entered, ready) = oneshot::channel();
    let (resume, wait) = oneshot::channel();
    sut.telemetry
        .actor
        .send(Message::TestChunkBarrier {
            entered,
            resume: wait,
        })
        .await
        .expect("original status actor mailbox");
    let telemetry = sut.telemetry.clone();
    let response =
        tokio::spawn(async move { telemetry.status_snapshot(&BuildStatus::default()).await });
    let at = tokio::time::timeout(METRICS_SYNC_TIMEOUT, ready).await;
    if !matches!(at, Ok(Ok(_))) {
        let _ = resume.send(());
        let result = response.await;
        panic!("actual classified status chunk did not reach its barrier: {at:?}; {result:?}");
    }
    let at = at.unwrap().unwrap();
    let classified = sut.telemetry.metrics.block_height.get();
    let accepted = sut
        .telemetry
        .metrics
        .txs
        .with_label_values(&["accepted"])
        .get();
    let budget = sut.state.ivm_execution_budget();
    let charged = budget.reserved_bytes();
    let (held, original_wait) = hold_original_status_publication(&sut.state).await;
    let exact_original = matches!(
        sut.state.try_view_once(),
        Err(crate::state::StateViewError::Busy(wait)) if wait == original_wait
    );
    let _ = resume.send(());
    let result = response.await;
    let held_charge = budget.reserved_bytes();
    let joined = held.release_and_join();
    let (after, height) = sut
        .telemetry
        .status_snapshot(&BuildStatus::default())
        .await
        .expect("current native status after final-sample writer release")
        .into_parts();
    assert!(joined.is_ok(), "original final-sample writer must join");
    assert!(
        exact_original,
        "final sample holds the actual State publication"
    );
    assert_eq!(at, expected_height);
    assert_eq!(classified, u64::try_from(expected_height).unwrap());
    assert_eq!(held_charge, charged);
    assert_eq!(budget.reserved_bytes(), charged);
    assert_eq!(height, classified);
    assert_eq!(after.blocks, classified);
    assert_eq!(after.txs_approved, accepted);
    assert!(
        matches!(result, Ok(Err(StatusSnapshotError::StateBusy))),
        "status final World sample must refuse the original publication after retaining its verified chunk: observed {result:?}"
    );
}

#[tokio::test]
async fn status_state_view_error_mapping_keeps_existing_busy_and_terminal_categories() {
    let sut = SystemUnderTest::new();
    sut.state.with_held_header_for_reader_test(|original| {
        let error = match sut.state.try_view_once() {
            Ok(_) => panic!("actual held header writer must refuse status sampling"),
            Err(error) => error,
        };
        assert!(matches!(
            &error,
            crate::state::StateViewError::Busy(wait) if wait == &original
        ));
        assert!(matches!(
            StatusSnapshotError::from(error),
            StatusSnapshotError::StateBusy
        ));
    });
    for error in [
        crate::state::StateViewError::Changed,
        crate::state::StateViewError::Poisoned,
        crate::state::StateViewError::Runtime(crate::state::LaneLifecycleError::Storage(
            "invalid original runtime projection".to_owned(),
        )),
    ] {
        assert!(matches!(
            StatusSnapshotError::from(error),
            StatusSnapshotError::StateUnavailable
        ));
    }
    assert!(sut.state.try_view_once().is_ok());
}
