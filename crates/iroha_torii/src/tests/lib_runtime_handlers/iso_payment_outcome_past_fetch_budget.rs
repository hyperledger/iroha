// Native height-501 controls for the ISO projection worker, a background reader with no
// request: it reads State/checkpoint ancestry under its own background owner.

impl IsoPaymentOutcomeFixture {
    /// The ISO payment follows history up to the shipped fetch budget (500), so it commits at
    /// 501. A committed fixture also certifies an empty executed tip at 502.
    fn past_fetch_budget(committed: bool) -> Self {
        let work = routing::app_query_limits().max_fetch_size;
        assert_eq!(
            work, 500,
            "exercise the shipped default without changing global limits"
        );
        let mut fixture = Self::with_payment_after_history(false, committed, work, 1_000);
        if committed {
            assert_eq!(fixture.chain.height(), 501);
            fixture.chain.commit(Vec::new());
            fixture.assert_full_prefix_refuses_payment();
        } else {
            assert_eq!(fixture.chain.height(), 500);
        }
        fixture
    }

    /// The deterministic full-prefix reader keeps its fetch budget at the payment height.
    fn assert_full_prefix_refuses_payment(&self) {
        use iroha_core::execution_attempt::ExecutionAttemptError;
        use iroha_data_model::query::error::QueryExecutionFail;

        let work = routing::app_query_limits().max_fetch_size;
        assert!(matches!(
            self.app.state.read_finalized_execution_carrier(
                NonZeroUsize::new(501).unwrap(),
                work,
                iroha_core::smartcontracts::isi::tx::transaction_history_byte_limit(work),
            ),
            Err(ExecutionAttemptError::Rejected(
                QueryExecutionFail::GasBudgetExceeded
            ))
        ));
    }

    fn canonical_payment_time(&self) -> Option<SystemTime> {
        SystemTime::UNIX_EPOCH
            .checked_add(self.chain.committed(501).block().header().creation_time())
    }

    fn applied_block_event(&self, height: u64) -> EventBox {
        iroha_data_model::events::pipeline::BlockEvent {
            header: self.chain.committed(height).block().header(),
            status: iroha_data_model::events::pipeline::BlockStatus::Applied,
        }
        .into()
    }
}

async fn wait_for_iso_payment_code(runtime: &Iso20022BridgeRuntime, code: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while runtime
            .message_status("outcome-payment")
            .unwrap()
            .pacs002_code()
            != code
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the ISO projection worker records the canonical outcome");
}

#[tokio::test]
async fn iso_projection_worker_reconciles_payment_past_fetch_budget_without_exiting() {
    let mut fixture = IsoPaymentOutcomeFixture::past_fetch_budget(false);
    let runtime = fixture.app.iso_bridge.as_ref().unwrap().clone();
    let events = tokio::sync::broadcast::channel(8).0;
    let shutdown = ShutdownSignal::new();
    let worker = start_iso_bridge_projection_worker(
        runtime.clone(),
        fixture.app.clone(),
        &events,
        shutdown.clone(),
    )
    .unwrap();
    let transaction = fixture.pending_payment.take().unwrap();
    assert_eq!(fixture.chain.commit(vec![transaction]), vec![true]);
    assert_eq!(fixture.chain.height(), 501);
    fixture.chain.commit(Vec::new());
    fixture.assert_full_prefix_refuses_payment();
    assert_eq!(
        runtime
            .message_status("outcome-payment")
            .unwrap()
            .status_label(),
        "Accepted"
    );
    let available = fixture.app.query_fanout_inflight.available_bytes();
    events
        .send(fixture.applied_block_event(502))
        .expect("the worker is subscribed");
    wait_for_iso_payment_code(&runtime, "ACSC").await;
    let payment = runtime.message_status("outcome-payment").unwrap();
    assert_eq!(payment.settled_at(), fixture.canonical_payment_time());
    let native = payment.native_payment_json();
    assert_eq!(native["carrier"]["height"].as_u64(), Some(501));
    assert_eq!(native["carrier"]["applied"].as_bool(), Some(true));
    assert_eq!(
        native["business_settlement"]["transaction_hash"].as_str(),
        Some(fixture.transaction_hash.to_string().as_str())
    );
    assert!(
        !worker.is_finished(),
        "the worker keeps running past the fetch budget"
    );
    assert_eq!(
        fixture.app.query_fanout_inflight.available_bytes(),
        available,
        "each background read releases its owner"
    );
    shutdown.send();
    assert!(matches!(
        worker.await.unwrap(),
        ToriiCriticalWorkerExit::StoppedByShutdown
    ));

    // After a restart past the fetch budget, startup reconciliation re-authenticates the
    // journal's settlement at 501 instead of failing Torii startup.
    let restored = Arc::new(
        Iso20022BridgeRuntime::from_config(&fixture.config)
            .unwrap()
            .unwrap(),
    );
    assert_eq!(
        restored
            .message_status("outcome-payment")
            .unwrap()
            .pacs002_code(),
        "PDNG"
    );
    let shutdown = ShutdownSignal::new();
    let worker = start_iso_bridge_projection_worker(
        restored.clone(),
        fixture.app.clone(),
        &events,
        shutdown.clone(),
    )
    .expect("startup reconciliation reads 501 through checkpoint ancestry");
    let recovered = restored.message_status("outcome-payment").unwrap();
    assert_eq!(recovered.pacs002_code(), "ACSC");
    assert_eq!(recovered.settled_at(), fixture.canonical_payment_time());
    assert_eq!(recovered.native_payment_json(), native);
    assert_eq!(fixture.chain.height(), 502);
    shutdown.send();
    assert!(matches!(
        worker.await.unwrap(),
        ToriiCriticalWorkerExit::StoppedByShutdown
    ));
}

#[tokio::test]
async fn iso_projection_worker_retries_a_busy_history_pool_instead_of_exiting() {
    let fixture = IsoPaymentOutcomeFixture::past_fetch_budget(true);
    let runtime = fixture.app.iso_bridge.as_ref().unwrap().clone();
    let mut held = Vec::new();
    while let Ok(reservation) = try_acquire_new_query_fanout_memory(&fixture.app) {
        held.push(reservation);
    }
    assert!(!held.is_empty());
    // HTTP readers hold the whole pool: the pass defers without publishing, rejecting or
    // failing the payment.
    assert_eq!(
        reconcile_iso_bridge_transactions(&runtime, &fixture.app).unwrap(),
        IsoBridgeReconciliation::Deferred
    );
    assert_eq!(
        runtime
            .message_status("outcome-payment")
            .unwrap()
            .status_label(),
        "Accepted"
    );
    let events = tokio::sync::broadcast::channel(8).0;
    let shutdown = ShutdownSignal::new();
    let worker = start_iso_bridge_projection_worker(
        runtime.clone(),
        fixture.app.clone(),
        &events,
        shutdown.clone(),
    )
    .expect("a deferred startup pass is retried by the worker, not a startup failure");
    events
        .send(fixture.applied_block_event(502))
        .expect("the worker is subscribed");
    tokio::time::sleep(ISO_BRIDGE_PROJECTION_RETRY_INTERVAL * 8).await;
    assert!(!worker.is_finished(), "a busy pool never stops the worker");
    let pending = runtime.message_status("outcome-payment").unwrap();
    assert_eq!(pending.status_label(), "Accepted");
    assert!(pending.settled_at().is_none());
    // No later block or notification arrives: the worker's own retry completes it.
    drop(held);
    wait_for_iso_payment_code(&runtime, "ACSC").await;
    assert_eq!(
        runtime
            .message_status("outcome-payment")
            .unwrap()
            .settled_at(),
        fixture.canonical_payment_time()
    );
    assert_eq!(fixture.chain.height(), 502);
    shutdown.send();
    assert!(matches!(
        worker.await.unwrap(),
        ToriiCriticalWorkerExit::StoppedByShutdown
    ));
}

// G24 geometry: a block whose whole carrier one background owner cannot hold. The worker reads
// the payment's outcome through bounded windows. The business settlement needs the whole
// carrier, whose refusal Core leaves unclassified (retryable capacity): it stays unresolved and
// unpublished, is retried, and never stops the worker.
#[tokio::test]
async fn iso_projection_worker_keeps_running_when_a_block_exceeds_the_whole_carrier_budget() {
    let mut fixture = IsoPaymentOutcomeFixture::with_payment_after_history(false, false, 1, 100);
    let runtime = fixture.app.iso_bridge.as_ref().unwrap().clone();
    let signer = checked_torii_test_ed25519_keypair(0x24, "ISO payment authority");
    let payment = fixture.pending_payment.take().unwrap();
    let oversized = sized_log_transaction(&fixture.chain, &signer, 1_500_000, 7);
    assert_eq!(
        fixture.chain.commit_at(10_000, vec![payment, oversized]),
        vec![true, true]
    );
    let refused =
        read_background_execution_carrier(&fixture.app, NonZeroUsize::new(2).unwrap()).map(|_| ());
    assert!(
        matches!(
            refused,
            Err(Error::Query(ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
            )))
        ),
        "the whole carrier does not fit one background owner: {refused:?}"
    );
    assert!(matches!(
        canonical_transaction_outcome_in_background(&fixture.app, &fixture.transaction_hash),
        Ok(Some(CanonicalTransactionOutcome::Applied { .. }))
    ));
    assert_eq!(
        reconcile_iso_bridge_transactions(&runtime, &fixture.app).unwrap(),
        IsoBridgeReconciliation::Deferred,
        "an unclassified whole-carrier refusal is retried, never fatal"
    );
    assert_eq!(
        runtime
            .message_status("outcome-payment")
            .unwrap()
            .status_label(),
        "Accepted"
    );
    let available = fixture.app.query_fanout_inflight.available_bytes();
    let events = tokio::sync::broadcast::channel(8).0;
    let shutdown = ShutdownSignal::new();
    let worker = start_iso_bridge_projection_worker(
        runtime.clone(),
        fixture.app.clone(),
        &events,
        shutdown.clone(),
    )
    .expect("an oversized block is not a startup failure");
    events
        .send(fixture.applied_block_event(2))
        .expect("the worker is subscribed");
    tokio::time::sleep(ISO_BRIDGE_PROJECTION_RETRY_INTERVAL * 8).await;
    assert!(
        !worker.is_finished(),
        "one oversized block never stops the worker"
    );
    let pending = runtime.message_status("outcome-payment").unwrap();
    assert_eq!(pending.status_label(), "Accepted");
    assert!(pending.settled_at().is_none());
    assert_eq!(
        fixture.app.query_fanout_inflight.available_bytes(),
        available
    );
    shutdown.send();
    assert!(matches!(
        worker.await.unwrap(),
        ToriiCriticalWorkerExit::StoppedByShutdown
    ));
}
