// Actual issuance handlers retain physical-worker admission across cancellation. These use
// independently signed custody/receipt/observer simulations, not hardware qualification.

struct StorageTokenIssuanceGate {
    release: Option<std::sync::mpsc::Sender<()>>,
    worker: Option<std::thread::JoinHandle<bool>>,
    watchdog_fired: Arc<std::sync::atomic::AtomicBool>,
}

impl StorageTokenIssuanceGate {
    fn hold(fixture: Arc<SignedFixture>) -> Self {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let watchdog_fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed_watchdog = Arc::clone(&watchdog_fired);
        let worker = std::thread::spawn(move || {
            // The actual signed fixture increments `calls` immediately before taking this
            // mutex. This blocks real issuance without replacing its custody or proof checks.
            let held = fixture
                .signing_payloads
                .lock()
                .expect("fixture payload gate");
            ready_tx.send(()).expect("announce held gate");
            let released = release_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .is_ok();
            observed_watchdog.store(!released, std::sync::atomic::Ordering::SeqCst);
            drop(held);
            released
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("physical gate must become ready");
        Self {
            release: Some(release_tx),
            worker: Some(worker),
            watchdog_fired,
        }
    }

    fn assert_held(&self, fixture: &SignedFixture) {
        assert!(fixture.signing_payloads.try_lock().is_err());
        assert!(
            !self
                .watchdog_fired
                .load(std::sync::atomic::Ordering::SeqCst),
            "the async executor must progress before the independent watchdog releases issuance"
        );
    }

    fn release(mut self) {
        self.release.take().unwrap().send(()).unwrap();
        assert!(self.worker.take().unwrap().join().unwrap());
    }
}

impl Drop for StorageTokenIssuanceGate {
    fn drop(&mut self) {
        // A failed assertion or cancelled test still releases the real worker; the independent
        // receive timeout also bounds the old inline-handler regression on a stalled executor.
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn storage_token_worker_context(mode: TestSignerMode) -> (TokenTestContext, Arc<SignedFixture>) {
    let mut context = token_test_context();
    let fixture = SignedFixture::for_api([0xAB; 32], 7, mode);
    let issuer = fixture
        .issuer()
        .expect("independently authenticated startup");
    assert_eq!(
        hex::encode(issuer.verifying_key_bytes()),
        context.verifying_key_hex
    );
    let mut app = Arc::try_unwrap(context.app)
        .unwrap_or_else(|_| panic!("exclusive worker-test application"));
    app.stream_token_issuer = Some(Arc::new(issuer));
    app.query_inflight = Arc::new(tokio::sync::Semaphore::new(1));
    app.query_heavy_inflight = Arc::new(tokio::sync::Semaphore::new(1));
    app.query_queue_timeout = std::time::Duration::ZERO;
    context.app = Arc::new(app);
    (context, fixture)
}

fn storage_token_worker_headers(context: &TokenTestContext) -> HeaderMap {
    let mut headers = HeaderMap::new();
    insert_api_test_header(&mut headers, HEADER_SORA_CLIENT, &context.client_id);
    insert_static_api_test_header(&mut headers, HEADER_SORA_NONCE, "physical-issuance-worker");
    headers
}

async fn await_storage_token_worker(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("bounded issuance worker condition");
}

fn assert_storage_token_worker_permits(state: &SharedAppState, available: usize) {
    assert_eq!(state.query_inflight.available_permits(), available);
    assert_eq!(state.query_heavy_inflight.available_permits(), available);
}

#[tokio::test(flavor = "current_thread")]
async fn storage_token_issuance_worker_keeps_single_thread_executor_responsive() {
    let (context, fixture) = storage_token_worker_context(TestSignerMode::Sign);
    let gate = StorageTokenIssuanceGate::hold(Arc::clone(&fixture));
    let app = Arc::clone(&context.app);
    let headers = storage_token_worker_headers(&context);
    let request = context.token_request(TokenOverrides::default());
    let issuance = tokio::spawn(async move {
        handle_post_sorafs_storage_token_authenticated(
            Some(test_stream_token_operator()),
            State(app),
            headers,
            JsonOnly(request),
        )
        .await
    });
    await_storage_token_worker(|| fixture.calls.load(std::sync::atomic::Ordering::SeqCst) == 1)
        .await;
    gate.assert_held(&fixture);
    assert!(!issuance.is_finished());
    assert_storage_token_worker_permits(&context.app, 0);
    let executor_thread = std::thread::current().id();
    let heartbeat = tokio::spawn(async {
        tokio::task::yield_now().await;
        std::thread::current().id()
    });
    assert_eq!(heartbeat.await.unwrap(), executor_thread);
    gate.assert_held(&fixture);
    gate.release();
    let response = issuance.await.expect("request task joins");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        api_test_header_str(response.headers(), HEADER_SORA_NONCE),
        Some("physical-issuance-worker")
    );
    assert_eq!(
        api_test_header_str(response.headers(), HEADER_SORA_ISSUANCE_QUOTA_REMAINING),
        Some("2")
    );
    assert_eq!(
        api_test_header_str(response.headers(), CACHE_CONTROL),
        Some("no-store")
    );
    let value = api_test_response_json(response).await;
    let token = decode_token_base64(value.json_str(&["token_base64"]).unwrap()).unwrap();
    token
        .verify(
            context
                .app
                .stream_token_issuer
                .as_ref()
                .unwrap()
                .verifying_key(),
        )
        .expect("actual signed token survives the async boundary");
    assert_eq!(token.body.provider_id, [0xAB; 32]);
    assert_eq!(token.body.token_pk_version, 7);
    fixture.assert_original_receipt_retained();
    assert_storage_token_worker_permits(&context.app, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn storage_token_issuance_cancellation_retains_general_and_heavy_permits() {
    let (context, fixture) = storage_token_worker_context(TestSignerMode::Sign);
    let gate = StorageTokenIssuanceGate::hold(Arc::clone(&fixture));
    let app = Arc::clone(&context.app);
    let headers = storage_token_worker_headers(&context);
    let request = context.token_request(TokenOverrides::default());
    let issuance = tokio::spawn(async move {
        handle_post_sorafs_storage_token_authenticated(
            Some(test_stream_token_operator()),
            State(app),
            headers,
            JsonOnly(request),
        )
        .await
    });
    await_storage_token_worker(|| fixture.calls.load(std::sync::atomic::Ordering::SeqCst) == 1)
        .await;
    gate.assert_held(&fixture);
    issuance.abort();
    assert!(issuance.await.unwrap_err().is_cancelled());
    tokio::task::yield_now().await;
    gate.assert_held(&fixture);
    assert_storage_token_worker_permits(&context.app, 0);
    let observed_before = fixture
        .observer_calls
        .load(std::sync::atomic::Ordering::SeqCst);
    let rejected = handle_post_sorafs_storage_token_authenticated(
        Some(test_stream_token_operator()),
        State(Arc::clone(&context.app)),
        storage_token_worker_headers(&context),
        JsonOnly(context.token_request(TokenOverrides::default())),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(fixture.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .observer_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        observed_before
    );
    assert_storage_token_worker_permits(&context.app, 0);
    gate.release();
    await_storage_token_worker(|| {
        context.app.query_inflight.available_permits() == 1
            && context.app.query_heavy_inflight.available_permits() == 1
    })
    .await;
    fixture.assert_original_receipt_retained();
    assert!(
        fixture
            .observer_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            > observed_before
    );
    assert_eq!(
        fixture
            .recover_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    let next = handle_post_sorafs_storage_token_authenticated(
        Some(test_stream_token_operator()),
        State(Arc::clone(&context.app)),
        storage_token_worker_headers(&context),
        JsonOnly(context.token_request(TokenOverrides::default())),
    )
    .await;
    assert_eq!(next.status(), StatusCode::OK);
    assert_eq!(
        api_test_header_str(next.headers(), HEADER_SORA_ISSUANCE_QUOTA_REMAINING),
        Some("1"),
        "cancelling a dispatched issuance neither refunds its quota nor charges rejected admission"
    );
    assert_eq!(fixture.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_storage_token_worker_permits(&context.app, 1);
}

#[tokio::test]
async fn storage_token_issuance_admission_rejects_before_custody_or_provider_work() {
    for occupy_heavy in [false, true] {
        let (context, fixture) = storage_token_worker_context(TestSignerMode::Sign);
        let occupied = if occupy_heavy {
            Arc::clone(&context.app.query_heavy_inflight)
        } else {
            Arc::clone(&context.app.query_inflight)
        };
        let permit = occupied.try_acquire_owned().unwrap();
        let observed_before = fixture
            .observer_calls
            .load(std::sync::atomic::Ordering::SeqCst);
        let expected = crate::Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit,
        ))
        .into_response();
        let response = handle_post_sorafs_storage_token_authenticated(
            Some(test_stream_token_operator()),
            State(Arc::clone(&context.app)),
            storage_token_worker_headers(&context),
            JsonOnly(context.token_request(TokenOverrides::default())),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers(), expected.headers());
        assert_eq!(
            api_test_response_body(response).await,
            api_test_response_body(expected).await
        );
        assert_eq!(fixture.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            fixture
                .recover_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            fixture
                .observer_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            observed_before
        );
        drop(permit);
        assert_storage_token_worker_permits(&context.app, 1);
        let response = handle_post_sorafs_storage_token_authenticated(
            Some(test_stream_token_operator()),
            State(Arc::clone(&context.app)),
            storage_token_worker_headers(&context),
            JsonOnly(context.token_request(TokenOverrides::default())),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            api_test_header_str(response.headers(), HEADER_SORA_ISSUANCE_QUOTA_REMAINING),
            Some("2")
        );
        assert_eq!(fixture.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_storage_token_worker_permits(&context.app, 1);
    }
}

#[tokio::test]
async fn storage_token_issuance_worker_preserves_unavailable_response_and_releases_permits() {
    let (context, fixture) = storage_token_worker_context(TestSignerMode::Unavailable);
    let response = handle_post_sorafs_storage_token_authenticated(
        Some(test_stream_token_operator()),
        State(Arc::clone(&context.app)),
        storage_token_worker_headers(&context),
        JsonOnly(context.token_request(TokenOverrides::default())),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        api_test_header_str(response.headers(), RETRY_AFTER),
        Some("1")
    );
    assert!(response.headers().get(HEADER_SORA_TOKEN_ID).is_none());
    assert!(response.headers().get(HEADER_SORA_VERIFYING_KEY).is_none());
    let value = api_test_response_json(response).await;
    assert_json_fields!(value; json_str ["error"] => Some("stream token issuance is temporarily unavailable"));
    assert_eq!(fixture.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .recover_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_storage_token_worker_permits(&context.app, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn account_token_rejects_missing_auth_and_missing_native_policy_before_signing() {
    let (context, fixture) = storage_token_worker_context(TestSignerMode::Sign);
    let rejected = handle_post_sorafs_storage_account_token(
        None,
        State(context.app.clone()),
        storage_token_worker_headers(&context),
        JsonOnly(context.token_request(TokenOverrides::default())),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    let key = iroha_crypto::KeyPair::from_seed(vec![92; 32], iroha_crypto::Algorithm::Ed25519);
    let account = AccountId::new(key.public_key().clone());
    let authenticated = crate::app_auth::VerifiedCanonicalRequest {
        account,
        signer: key.public_key().clone(),
        verified_signers: vec![key.public_key().clone()],
    };
    // This fixture has an operational signed custody service, but no native admitted
    // account-read policy. Authenticating a wallet must not grant operator issuance.
    let rejected = handle_post_sorafs_storage_account_token(
        Some(Extension(authenticated)),
        State(context.app.clone()),
        storage_token_worker_headers(&context),
        JsonOnly(context.token_request(TokenOverrides::default())),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    assert_eq!(fixture.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_storage_token_worker_permits(&context.app, 1);
}
