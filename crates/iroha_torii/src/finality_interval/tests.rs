//! Genuine public source, charged response framing and detached physical-worker controls.

use super::*;
use iroha_core::{
    state::World,
    sumeragi::{
        finality::build_proof,
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use tower::ServiceExt as _;

#[test]
fn borrowed_interval_identity_projects_only_its_root_to_the_owned_sequence() {
    use norito::{NoritoSchema as _, schema::identity::frame_hash};

    assert_eq!(
        BorrowedInterval::nominal_name(),
        "iroha_torii::finality_interval::BorrowedInterval<'_>"
    );
    assert_ne!(
        BorrowedInterval::nominal_name(),
        Vec::<SumeragiFinalityProof>::nominal_name()
    );
    assert_eq!(
        BorrowedInterval::frame_name(),
        Vec::<SumeragiFinalityProof>::frame_name()
    );
    assert_eq!(
        frame_hash::<BorrowedInterval<'_>>(),
        frame_hash::<Vec<SumeragiFinalityProof>>()
    );
    assert_ne!(
        frame_hash::<Option<BorrowedInterval<'_>>>(),
        frame_hash::<Option<Vec<SumeragiFinalityProof>>>()
    );
}

fn admission() -> (
    QueryAdmissionPermit,
    ByteWeightedMemoryPool,
    Arc<tokio::sync::Semaphore>,
) {
    let working = 48_000_000;
    let pool = ByteWeightedMemoryPool::new(working).unwrap();
    let reservation = QueryFanoutMemoryReservation::from_admitted_fanout(
        pool.try_acquire_parts([working as u64]).unwrap(),
        QueryFanoutMemoryEnvelope::for_body_admission(working).unwrap(),
        pool.generation(),
    )
    .unwrap();
    let query = Arc::new(tokio::sync::Semaphore::new(1));
    (
        QueryAdmissionPermit {
            _query: Arc::clone(&query).try_acquire_owned().unwrap(),
            _heavy: None,
            _body: None,
            _fanout_memory: Some(reservation),
        },
        pool,
        query,
    )
}
#[test]
fn query_admission_retires_original_resources_before_waking_next_worker() {
    use std::task::{Context, Poll, Wake, Waker};

    struct ObserveWake {
        pool: ByteWeightedMemoryPool,
        metadata: iroha_allocation::AllocationBudget,
        heavy: Arc<tokio::sync::Semaphore>,
        body: Arc<tokio::sync::Semaphore>,
        observed: std::sync::atomic::AtomicU8,
    }
    impl Wake for ObserveWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            // Semaphore release invokes this synchronously. Observe the actual
            // retirement boundary without sleeps, thread scheduling or a retry.
            let state = u8::from(self.pool.available_bytes() == 48_000_000)
                | (u8::from(self.metadata.reserved_bytes() == 0) << 1)
                | (u8::from(self.heavy.available_permits() == 1) << 2)
                | (u8::from(self.body.available_permits() == 1) << 3);
            self.observed.store(state, Ordering::SeqCst);
        }
    }

    let (mut admission, pool, query) = admission();
    let heavy = Arc::new(tokio::sync::Semaphore::new(1));
    let body = Arc::new(tokio::sync::Semaphore::new(1));
    admission._heavy = Some(Arc::clone(&heavy).try_acquire_owned().unwrap());
    admission._body = Some(Arc::clone(&body).try_acquire_owned().unwrap());
    let owner = history_producer::HistoryProducerOwner::from_admission(&admission).unwrap();
    let metadata = owner.response_metadata().clone();
    drop(owner);
    assert_eq!(pool.available_bytes(), 0);
    assert!(metadata.reserved_bytes() > 0);
    let observed = Arc::new(ObserveWake {
        pool: pool.clone(),
        metadata,
        heavy,
        body,
        observed: std::sync::atomic::AtomicU8::new(u8::MAX),
    });
    let waker = Waker::from(Arc::clone(&observed));
    let mut context = Context::from_waker(&waker);
    let mut next = Box::pin(Arc::clone(&query).acquire_owned());
    assert!(std::future::Future::poll(next.as_mut(), &mut context).is_pending());
    drop(admission);
    let next_permit = match std::future::Future::poll(next.as_mut(), &mut context) {
        Poll::Ready(Ok(permit)) => permit,
        _ => panic!("the original query permit must wake its actual next worker"),
    };
    drop(next_permit);
    drop(next);
    assert_eq!(
        observed.observed.load(Ordering::SeqCst),
        0b1111,
        "query wake must follow native allocation, byte credit, body and heavy permit retirement",
    );
    assert_eq!(query.available_permits(), 1);
    assert_eq!(pool.available_bytes(), 48_000_000);
}

#[inline(never)]
fn chain() -> CertifiedTestChain {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 10_000)).unwrap();
    while chain.height() < 4 {
        chain.commit(Vec::new());
    }
    chain
}
fn deadline() -> Instant {
    Instant::now() + route_timeout_for_path("/v1/bridge/finality/interval/1/4")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_and_interval_responses_keep_original_charged_bytes_and_query_credit_through_last_slice()
 {
    let chain = chain();
    let expected = (1..=4)
        .map(|height| build_proof(&chain.state().view(), height).unwrap())
        .collect::<Vec<_>>();
    for selection in [Selection::Single(4), Selection::Interval { from: 1, to: 4 }] {
        let (admission, pool, query) = admission();
        let owner = history_producer::HistoryProducerOwner::from_admission(&admission).unwrap();
        let frames = owner.cold_frames().clone();
        let limit = owner.response_bytes();
        drop(owner);
        let prepared = prepare(
            Arc::clone(chain.state()),
            selection,
            ResponseFormat::Norito,
            admission,
            limit,
            deadline(),
        )
        .await
        .unwrap();
        assert_eq!(prepared.response.status(), StatusCode::OK);
        let extent = match selection {
            Selection::Single(_) => norito::canonical_frame_len(&expected[3]).unwrap(),
            Selection::Interval { .. } => norito::canonical_frame_len(&expected).unwrap(),
        };
        assert_eq!(prepared.bytes, extent);
        assert_eq!(
            frames.reserved_bytes(),
            prepared.bytes,
            "only the exact canonical response remains after the physical prefix/DTO owners retire"
        );
        assert_eq!(
            query.available_permits(),
            1,
            "physical CPU admission retires at worker completion"
        );
        let bytes = axum::body::to_bytes(prepared.response.into_body(), limit)
            .await
            .unwrap();
        match selection {
            Selection::Single(_) => assert_eq!(
                norito::decode_canonical::<SumeragiFinalityProof>(&bytes).unwrap(),
                expected[3]
            ),
            Selection::Interval { .. } => assert_eq!(
                norito::decode_canonical::<Vec<SumeragiFinalityProof>>(&bytes).unwrap(),
                expected
            ),
        }
        let last = bytes.slice(..);
        drop(bytes);
        assert!(
            pool.try_acquire_parts([48_000_000]).is_none(),
            "single and interval last response slices must retain the actual original query memory credit"
        );
        assert!(frames.reserved_bytes() > 0);
        drop(last);
        assert_eq!(frames.reserved_bytes(), 0);
        assert!(pool.try_acquire_parts([48_000_000]).is_some());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interval_route_uses_real_state_and_counts_complete_outer_framing_for_both_formats() {
    let chain = chain();
    let expected = (1..=4)
        .map(|height| build_proof(&chain.state().view(), height).unwrap())
        .collect::<Vec<_>>();
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests();
    let fixture = Arc::get_mut(&mut app).unwrap();
    fixture.state = Arc::clone(chain.state());
    fixture.kura = Arc::clone(chain.kura());
    let router = axum::Router::new()
        .route(
            iroha_torii_shared::route_catalog::sumeragi::BRIDGE_FINALITY_INTERVAL.path(),
            axum::routing::get(handler_bridge_finality_interval),
        )
        .route(
            iroha_torii_shared::route_catalog::sumeragi::BRIDGE_FINALITY.path(),
            axum::routing::get(handler_bridge_finality_proof),
        )
        .layer(axum::middleware::from_fn(enforce_route_timeout))
        .with_state(app);
    for format in [ResponseFormat::Norito, ResponseFormat::Json] {
        let request = axum::http::Request::builder()
            .uri("/v1/bridge/finality/interval/1/4")
            .header(
                axum::http::header::ACCEPT,
                match format {
                    ResponseFormat::Norito => "application/x-norito",
                    ResponseFormat::Json => "application/json",
                },
            )
            .body(Body::empty())
            .unwrap();
        let mut request = request;
        request
            .extensions_mut()
            .insert(crate::loopback_connect_info());
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap();
        match format {
            ResponseFormat::Norito => assert_eq!(
                norito::decode_canonical::<Vec<SumeragiFinalityProof>>(&bytes).unwrap(),
                expected
            ),
            ResponseFormat::Json => assert_eq!(
                norito::json::from_slice::<Vec<SumeragiFinalityProof>>(&bytes).unwrap(),
                expected
            ),
        }
        let mut request = axum::http::Request::builder()
            .uri("/v1/bridge/finality/4")
            .header(
                axum::http::header::ACCEPT,
                match format {
                    ResponseFormat::Norito => "application/x-norito",
                    ResponseFormat::Json => "application/json",
                },
            )
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(crate::loopback_connect_info());
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap();
        let actual = match format {
            ResponseFormat::Norito => {
                norito::decode_canonical::<SumeragiFinalityProof>(&bytes).unwrap()
            }
            ResponseFormat::Json => {
                norito::json::from_slice::<SumeragiFinalityProof>(&bytes).unwrap()
            }
        };
        assert_eq!(
            actual, expected[3],
            "the single-proof route must use the same funded native producer without changing its standalone schema"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interval_outer_frame_refusal_has_no_partial_body_and_refunds_original_destination() {
    let chain = chain();
    let expected = vec![build_proof(&chain.state().view(), 1).unwrap()];
    let extent = norito::canonical_frame_len(&expected).unwrap();
    let (admission, pool, _) = admission();
    let owner = history_producer::HistoryProducerOwner::from_admission(&admission).unwrap();
    let frames = owner.cold_frames().clone();
    drop(owner);
    let result = prepare(
        Arc::clone(chain.state()),
        Selection::Interval { from: 1, to: 1 },
        ResponseFormat::Norito,
        admission,
        extent - 1,
        deadline(),
    )
    .await;
    assert!(
        matches!(
            result,
            Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::CapacityLimit,
            )))
        ),
        "outer canonical header and sequence must fit the original response admission"
    );
    assert_eq!(frames.reserved_bytes(), 0);
    assert!(pool.try_acquire_parts([48_000_000]).is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_interval_http_future_keeps_original_worker_credit_until_physical_retirement() {
    let chain = chain();
    let state = Arc::clone(chain.state());
    let (admission, pool, query) = admission();
    let owner = history_producer::HistoryProducerOwner::from_admission(&admission).unwrap();
    let frames = owner.cold_frames().clone();
    let (started, entered) = tokio::sync::oneshot::channel();
    let (release, held) = std::sync::mpsc::channel();
    let (finished, result) = tokio::sync::oneshot::channel();
    let request = tokio::spawn(run_with_stop(admission, owner, move |owner, cancelled| {
        started.send(()).unwrap();
        held.recv().unwrap();
        let limits = NativeFinalityProofIntervalLimits::new(
            NonZeroU64::new(1).unwrap(),
            NonZeroU64::new(4).unwrap(),
            NonZeroUsize::new(MAX_FINALITY_BLOCK_BYTES).unwrap(),
            NonZeroUsize::new(owner.response_bytes()).unwrap(),
            deadline(),
        )
        .unwrap();
        let stopped = matches!(
            state.read_finality_proof_interval(
                &owner.canonical_history_budget(),
                &limits,
                &cancelled,
            ),
            Err(FinalityProofIntervalReadError::Proof(
                NativeFinalityProofIntervalError::Cancelled
            ))
        );
        let codec_debit = owner.allocation_context().consumed_allocated_bytes();
        finished.send((stopped, codec_debit)).unwrap();
        Ok(())
    }));
    entered.await.unwrap();
    request.abort(); // Cancel only this test's HTTP future; the native worker is never aborted.
    let cancelled_request = request.await.unwrap_err().is_cancelled();
    let physical_held =
        pool.try_acquire_parts([48_000_000]).is_none() && query.available_permits() == 0;
    release.send(()).unwrap();
    let (stopped, codec_debit) = result.await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while query.available_permits() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(cancelled_request && physical_held);
    assert!(
        stopped,
        "cancelled original interval must stop before native acquisition"
    );
    assert_eq!(codec_debit, 0);
    assert_eq!(frames.reserved_bytes(), 0);
    assert!(pool.try_acquire_parts([48_000_000]).is_some());
}

#[tokio::test]
async fn expired_interval_route_deadline_returns_original_timeout_without_native_work() {
    let chain = chain();
    let (admission, pool, query) = admission();
    let owner = history_producer::HistoryProducerOwner::from_admission(&admission).unwrap();
    let limit = owner.response_bytes();
    let prepared = prepare(
        Arc::clone(chain.state()),
        Selection::Interval { from: 1, to: 4 },
        ResponseFormat::Norito,
        admission,
        limit,
        Instant::now(),
    )
    .await
    .unwrap();
    assert_eq!(prepared.response.status(), StatusCode::REQUEST_TIMEOUT);
    assert_eq!(prepared.bytes, 0);
    assert_eq!(owner.allocation_context().consumed_allocated_bytes(), 0);
    drop(owner);
    assert_eq!(query.available_permits(), 1);
    assert!(pool.try_acquire_parts([48_000_000]).is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_and_timed_out_workers_keep_original_credit_until_unpolled_stop_control_retires() {
    struct JoinCompleted(std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>);
    impl std::task::Wake for JoinCompleted {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            if let Some(completed) = self.0.lock().unwrap().take() {
                let _ = completed.send(());
            }
        }
    }

    let chain = chain();
    for expired in [false, true] {
        let (admission, pool, query) = admission();
        let owner = history_producer::HistoryProducerOwner::from_admission(&admission).unwrap();
        // A subpool observation retains no byte-weighted query permit.
        let metadata = owner.response_metadata().clone();
        let state = Arc::clone(chain.state());
        let (started, entered) = tokio::sync::oneshot::channel();
        let (release, held) = std::sync::mpsc::channel();
        let (completed, notified) = tokio::sync::oneshot::channel();
        let waker = std::task::Waker::from(Arc::new(JoinCompleted(std::sync::Mutex::new(Some(
            completed,
        )))));
        let mut request = Box::pin(run_with_stop(admission, owner, move |owner, cancelled| {
            let _ = started.send(());
            let _ = held.recv();
            let height = if expired { 4 } else { 5 };
            let limits = NativeFinalityProofIntervalLimits::new(
                NonZeroU64::new(height).unwrap(),
                NonZeroU64::new(height).unwrap(),
                NonZeroUsize::new(MAX_FINALITY_BLOCK_BYTES).unwrap(),
                NonZeroUsize::new(owner.response_bytes()).unwrap(),
                if expired { Instant::now() } else { deadline() },
            )
            .unwrap();
            // Exercise the actual native missing-height or original deadline refusal.
            match state.read_finality_proof_interval(
                &owner.canonical_history_budget(),
                &limits,
                &cancelled,
            ) {
                Err(FinalityProofIntervalReadError::Proof(
                    NativeFinalityProofIntervalError::Deadline,
                )) => Ok(PreparedResponse::deadline(ResponseFormat::Norito)),
                Err(error) => Err(source_error(error)),
                Ok(_) => Err(Error::Query(
                    iroha_data_model::ValidationFail::InternalError(
                        "the native refusal control unexpectedly completed".to_owned(),
                    ),
                )),
            }
        }));
        let initial = {
            let mut context = std::task::Context::from_waker(&waker);
            match std::future::Future::poll(request.as_mut(), &mut context) {
                std::task::Poll::Pending => None,
                std::task::Poll::Ready(result) => Some(result),
            }
        };
        let initially_pending = initial.is_none();
        let entered = tokio::time::timeout(std::time::Duration::from_secs(2), entered).await;
        let released = release.send(()).is_ok();
        // This is the sole JoinHandle's completion wake, after the physical operation
        // and run_admitted_blocking's admission/TLS owners have retired. The HTTP
        // future is deliberately not polled again until after the observations.
        let physically_closed = initially_pending
            && matches!(
                tokio::time::timeout(std::time::Duration::from_secs(2), notified).await,
                Ok(Ok(()))
            );
        let control_charge = metadata.reserved_bytes();
        let original_credit_held = pool.try_acquire_parts([48_000_000]).is_none();
        let cpu_credit_retired = query.available_permits() == 1;
        // Always join/retire the original future and its result before any assertion.
        let result = match initial {
            Some(result) => result,
            None => request.await,
        };
        let precise_result = if expired {
            matches!(&result, Ok(response) if response.bytes == 0 && response.response.status() == StatusCode::REQUEST_TIMEOUT)
        } else {
            matches!(
                &result,
                Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                    iroha_data_model::query::error::QueryExecutionFail::NotFound,
                )))
            )
        };
        drop(result);
        let fully_refunded =
            metadata.reserved_bytes() == 0 && pool.try_acquire_parts([48_000_000]).is_some();
        assert!(
            initially_pending && matches!(entered, Ok(Ok(()))) && released && physically_closed
        );
        assert!(
            precise_result,
            "the control must retain the exact native refusal or original 408"
        );
        assert!(
            cpu_credit_retired,
            "physical worker admission must retire at actual completion"
        );
        assert!(control_charge >= ChargedShared::<AtomicBool>::allocation_layout().size());
        assert!(
            original_credit_held,
            "native worker error must retain original query credit until the unpolled HTTP stop control retires"
        );
        assert!(
            fully_refunded,
            "observing the original result must retire all stop-control storage and query credit"
        );
    }
}
