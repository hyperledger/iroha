#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_post_transaction_entrypoint_uses_authenticated_api_token_rate_limit_key() {
    let first_keypair =
        checked_torii_test_ed25519_keypair(0xc7, "derive first entrypoint API-token fixture key");
    let second_keypair =
        checked_torii_test_ed25519_keypair(0xc8, "derive second entrypoint API-token fixture key");
    let mut app = native_ingress_app_for_test(&[&first_keypair, &second_keypair]);
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        app_mut.high_load_tx_threshold = usize::MAX;
        app_mut.tx_preauth_rate_limiter = limits::RateLimiter::new_without_refill_for_tests(
            std::num::NonZeroU32::new(1).expect("positive token identity test burst"),
        );
        app_mut.fee_policy = FeePolicy::Disabled;
        app_mut.require_api_token = true;
        app_mut.api_token_digests =
            Arc::new(limits::ApiTokenDigestSet::from_tokens(["entrypoint-token"]));
    }
    let network_id = *app.state.network_id_ref();
    let tx1 = signed_log_transaction_for_test(
        network_id,
        AccountId::new(first_keypair.public_key().clone()),
        "entrypoint-token-rate-limit-1",
        &first_keypair,
    );
    let tx2 = signed_log_transaction_for_test(
        network_id,
        AccountId::new(second_keypair.public_key().clone()),
        "entrypoint-token-rate-limit-2",
        &second_keypair,
    );
    let mut headers = HeaderMap::new();
    headers.insert("x-api-token", HeaderValue::from_static("entrypoint-token"));
    let first =
        post_external_transaction_entrypoint_for_test(app.clone(), headers.clone(), tx1.clone())
            .await
            .expect("first token-keyed entrypoint accepted");
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert_native_pending_for_test(&app, &tx1);
    let err = match post_external_transaction_entrypoint_for_test(app.clone(), headers, tx2).await {
        Ok(_) => panic!("expected shared token rate limit"),
        Err(err) => err,
    };
    assert_eq!(err.into_response().status(), StatusCode::TOO_MANY_REQUESTS);
}
#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_post_transaction_entrypoint_reports_full_queue_before_rate_limit() {
    let keypair = checked_torii_test_ed25519_keypair(
        0xcf,
        "derive entrypoint queue-before-rate-limit fixture key",
    );
    let mut app = native_ingress_app_for_test(&[&keypair]);
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        app_mut.tx_rate_limiter = limits::RateLimiter::new_without_refill_for_tests(
            std::num::NonZeroU32::new(1).expect("positive admission test burst"),
        );
        app_mut.fee_policy = FeePolicy::Disabled;
    }
    install_single_slot_transaction_queue(&mut app);
    let authority = AccountId::new(keypair.public_key().clone());
    let network_id = *app.state.network_id_ref();
    let tx1 = signed_log_transaction_for_test(
        network_id,
        authority.clone(),
        "entrypoint-queue-before-rate-1",
        &keypair,
    );
    let tx2 = signed_log_transaction_for_test(
        network_id,
        authority,
        "entrypoint-queue-before-rate-2",
        &keypair,
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-api-token",
        HeaderValue::from_static("entrypoint-queue-before-rate"),
    );
    let first =
        post_external_transaction_entrypoint_for_test(app.clone(), headers.clone(), tx1.clone())
            .await
            .expect("first entrypoint should fill the queue");
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert_native_pending_for_test(&app, &tx1);
    let err = match post_external_transaction_entrypoint_for_test(app.clone(), headers, tx2).await {
        Ok(_) => panic!("expected queue full before token rate limit"),
        Err(err) => err,
    };
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        torii_response_header(&response, "x-iroha-reject-code"),
        Some("PRTRY:QUEUE_FULL")
    );
}
#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_post_transaction_honors_prefer_return_minimal() {
    let keypair = checked_torii_test_ed25519_keypair(
        0xc9,
        "derive minimal post-transaction response fixture key",
    );
    let mut app = native_ingress_app_for_test(&[&keypair]);
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .high_load_tx_threshold = usize::MAX;
    let authority = AccountId::new(keypair.public_key().clone());
    let transaction = signed_log_transaction_for_test(
        *app.state.network_id_ref(),
        authority,
        "minimal-submit-response",
        &keypair,
    );
    let submitted_hash = transaction.hash().to_string();
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("prefer"),
        HeaderValue::from_static("respond-async, return=minimal"),
    );
    let response = post_signed_transaction_for_test(app.clone(), headers, &transaction)
        .await
        .expect("accepted");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_native_pending_for_test(&app, &transaction);
    assert_eq!(
        torii_response_header(&response, "preference-applied"),
        Some(PREFER_RETURN_MINIMAL)
    );
    assert_eq!(
        torii_response_header(&response, "x-iroha-entrypoint-hash"),
        Some(submitted_hash.as_str())
    );
    let body = torii_body_bytes(response, "body").await;
    assert!(
        body.is_empty(),
        "minimal response should not sign a receipt body"
    );
}
fn transaction_batch_body_for_test(
    payloads: Vec<Vec<u8>>,
) -> crate::utils::extractors::NoritoBytes {
    crate::utils::extractors::NoritoBytes(Bytes::from(
        norito::to_bytes(&payloads).expect("encode transaction batch envelope"),
    ))
}
#[test]
fn transaction_ingress_compute_corridor_enforces_configured_parallelism() {
    let limiter = Arc::new(tokio::sync::Semaphore::new(2));
    let first = try_acquire_transaction_ingress_compute(&limiter).expect("first permit");
    let second = try_acquire_transaction_ingress_compute(&limiter).expect("second permit");
    let error = match try_acquire_transaction_ingress_compute(&limiter) {
        Ok(_) => panic!("configured parallelism must reject excess physical work"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        Error::AppServiceUnavailable {
            code: "transaction_ingress_compute_saturated",
            ..
        }
    ));
    drop(first);
    let replacement = try_acquire_transaction_ingress_compute(&limiter).expect("released capacity");
    drop((second, replacement));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_transaction_ingress_worker_retains_physical_capacity() {
    let limiter = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = try_acquire_transaction_ingress_compute(&limiter).expect("compute permit");
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let request = tokio::spawn(run_transaction_ingress_compute_job(
        permit,
        "fixture_worker_failed",
        move || {
            started_tx.send(()).expect("announce physical start");
            release_rx.recv().expect("release physical worker");
            Ok(())
        },
    ));
    started_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("physical worker started");
    request.abort();
    let _ = request.await;
    let retained_after_cancellation = try_acquire_transaction_ingress_compute(&limiter).is_err();
    release_tx.send(()).expect("release physical worker");
    let replacement = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(permit) = try_acquire_transaction_ingress_compute(&limiter) {
                break permit;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("physical completion releases capacity");
    drop(replacement);
    assert!(
        retained_after_cancellation,
        "HTTP cancellation must not free capacity while physical work continues"
    );
}
#[test]
fn transaction_batch_body_limit_rejects_before_decode() {
    let body = transaction_batch_body_for_test(vec![vec![0_u8; 16]]).0;
    let error = validate_transaction_batch_body_size(&body, body.len() - 1)
        .expect_err("wire bytes over the configured limit must be rejected");
    assert!(matches!(
        error,
        Error::AppQueryValidation {
            code: "transaction_batch_payload_too_large",
            ..
        }
    ));
}
#[test]
fn transaction_batch_declared_decoded_limit_rejects_compressed_expansion() {
    let payloads = vec![vec![0_u8; 64 * 1024]];
    let mut encoded = Vec::new();
    norito::serialize_into(&mut encoded, &payloads, norito::Compression::Zstd)
        .expect("encode compressed transaction batch envelope");
    let body = Bytes::from(encoded);
    let header = norito::core::Header::read(std::io::Cursor::new(body.as_ref()))
        .expect("read compressed envelope header");
    assert!(
        header.length > u64::try_from(body.len()).unwrap_or(u64::MAX),
        "fixture must expand beyond its encoded length"
    );
    let error = validate_transaction_batch_body_size(&body, body.len())
        .expect_err("declared decoded bytes over the limit must be rejected");
    assert!(matches!(
        error,
        Error::AppQueryValidation {
            code: "transaction_batch_payload_too_large",
            ..
        }
    ));
}
#[tokio::test]
async fn transaction_batch_count_limit_rejects_before_transaction_decode() {
    let mut app = mk_app_state_for_tests();
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .transaction_batch_max_transactions = 1;
    let body = transaction_batch_body_for_test(vec![vec![0xff], vec![0xff]]);
    let error =
        match super::handler_post_transactions_batch(State(app.clone()), HeaderMap::new(), body)
            .await
        {
            Ok(_) => panic!("oversized batch must be rejected"),
            Err(error) => error,
        };
    assert!(matches!(
        error,
        Error::AppQueryValidation {
            code: "transaction_batch_too_large",
            ..
        }
    ));
    assert_eq!(
        app.queue.active_len(),
        0,
        "count rejection must not push a valid prefix"
    );
}
#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread")]
async fn transaction_batch_authenticates_before_fresh_capacity_and_preserves_custody() {
    let key = checked_torii_test_ed25519_keypair(0xaf, "batch capacity signer");
    let mut app = native_ingress_app_for_test(&[&key]);
    install_single_slot_transaction_queue(&mut app);
    let transaction = signed_log_transaction_for_test(
        *app.state.network_id_ref(),
        AccountId::new(key.public_key().clone()),
        "batch-capacity",
        &key,
    );
    let response = super::handler_post_transactions_batch(
        State(app.clone()),
        HeaderMap::new(),
        transaction_batch_body_for_test(vec![
            iroha_version::codec::EncodeVersioned::encode_versioned(&transaction),
        ]),
    )
    .await
    .expect("native batch admission");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_native_pending_for_test(&app, &transaction);
    let error = super::handler_post_transactions_batch(
        State(app.clone()),
        HeaderMap::new(),
        transaction_batch_body_for_test(vec![vec![0xff]]),
    )
    .await
    .err()
    .expect("bad canonical bytes");
    assert!(matches!(
        error,
        Error::AppQueryValidation {
            code: "invalid_transaction_batch_payload",
            ..
        }
    ));
    assert_eq!(app.queue.active_len(), 1);
    assert_native_pending_for_test(&app, &transaction);
}

#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread")]
async fn handler_post_transactions_batch_accepts_multiple_payloads() {
    let key = checked_torii_test_ed25519_keypair(0xca, "batch submit signer");
    let app = native_ingress_app_for_test(&[&key]);
    let authority = AccountId::new(key.public_key().clone());
    let tx1 = signed_log_transaction_for_test(
        *app.state.network_id_ref(),
        authority.clone(),
        "batch-one",
        &key,
    );
    let tx2 =
        signed_log_transaction_for_test(*app.state.network_id_ref(), authority, "batch-two", &key);
    let response = super::handler_post_transactions_batch(
        State(app.clone()),
        HeaderMap::new(),
        transaction_batch_body_for_test(
            [&tx1, &tx2]
                .into_iter()
                .map(iroha_version::codec::EncodeVersioned::encode_versioned)
                .collect(),
        ),
    )
    .await
    .expect("native batch submission");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        torii_response_header(&response, "x-iroha-transactions-accepted"),
        Some("2")
    );
    assert_eq!(app.queue.active_len(), 2);
    assert_native_pending_for_test(&app, &tx1);
    assert_native_pending_for_test(&app, &tx2);
}

#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread")]
async fn transaction_batch_duplicate_reuses_custody_at_full_capacity_without_charging_again() {
    let key = checked_torii_test_ed25519_keypair(0xcd, "duplicate batch signer");
    let mut app = native_ingress_app_for_test(&[&key]);
    install_single_slot_transaction_queue(&mut app);
    Arc::get_mut(&mut app).unwrap().tx_rate_limiter =
        limits::RateLimiter::new_without_refill_for_tests(
            std::num::NonZeroU32::new(1).expect("positive admission test burst"),
        );
    let tx = signed_log_transaction_for_test(
        *app.state.network_id_ref(),
        AccountId::new(key.public_key().clone()),
        "duplicate-batch",
        &key,
    );
    let payload = iroha_version::codec::EncodeVersioned::encode_versioned(&tx);
    let response = super::handler_post_transactions_batch(
        State(app.clone()),
        HeaderMap::new(),
        transaction_batch_body_for_test(vec![payload.clone(), payload]),
    )
    .await
    .expect("duplicate entries retain the first pending entry");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        torii_response_header(&response, "x-iroha-transactions-accepted"),
        Some("2")
    );
    assert_eq!(app.queue.active_len(), 1);
    assert_native_pending_for_test(&app, &tx);
    let original_pending = lifecycle_pending_wire(&app);
    let retry = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &tx)
        .await
        .expect("single-submit retry bypasses fresh capacity and quota");
    assert_eq!(retry.status(), StatusCode::ACCEPTED);
    assert_eq!(lifecycle_pending_wire(&app), original_pending);
    assert_eq!(app.queue.active_len(), 1);
}

#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread")]
async fn transaction_batch_partial_admission_preserves_exact_ordered_outcomes() {
    use iroha_data_model::transaction::receipt::TransactionBatchEntryOutcome;
    let key = checked_torii_test_ed25519_keypair(0xcf, "partial batch signer");
    let mut app = native_ingress_app_for_test(&[&key]);
    Arc::get_mut(&mut app).unwrap().tx_rate_limiter =
        limits::RateLimiter::new_without_refill_for_tests(
            std::num::NonZeroU32::new(1).expect("positive admission test burst"),
        );
    let authority = AccountId::new(key.public_key().clone());
    let tx1 = signed_log_transaction_for_test(
        *app.state.network_id_ref(),
        authority.clone(),
        "partial-one",
        &key,
    );
    let tx2 = signed_log_transaction_for_test(
        *app.state.network_id_ref(),
        authority,
        "partial-two",
        &key,
    );
    let response = super::handler_post_transactions_batch(
        State(app.clone()),
        HeaderMap::new(),
        transaction_batch_body_for_test(
            [&tx1, &tx2]
                .into_iter()
                .map(iroha_version::codec::EncodeVersioned::encode_versioned)
                .collect(),
        ),
    )
    .await
    .expect("dispatched batch must return every outcome");
    assert_eq!(response.status(), StatusCode::MULTI_STATUS);
    assert_eq!(
        torii_response_header(&response, "x-iroha-transactions-accepted"),
        Some("1")
    );
    let outcomes: Vec<TransactionBatchEntryOutcome> =
        norito::json::from_slice(&torii_body_bytes(response, "batch outcomes").await).unwrap();
    assert_eq!(outcomes.len(), 2);
    assert_eq!(outcomes[0].signed_transaction_hash, tx1.hash());
    assert_eq!(outcomes[0].status, 202);
    assert_eq!(outcomes[1].signed_transaction_hash, tx2.hash());
    assert_eq!(outcomes[1].status, 429);
    assert_native_pending_for_test(&app, &tx1);
    assert!(
        !app.queue
            .contains_pending_hash(tx2.hash_as_entrypoint(), &app.state)
    );
}

#[cfg(feature = "connect")]
#[tokio::test]
async fn transaction_batch_cannot_bypass_ordinary_economic_admission() {
    use iroha_data_model::transaction::receipt::TransactionBatchEntryOutcome;

    let app = mk_app_state_for_tests();
    let key = checked_torii_test_ed25519_keypair(0xce, "ordinary batch signer");
    let tx = signed_log_transaction_for_test(
        *app.state.network_id_ref(),
        AccountId::new(key.public_key().clone()),
        "ordinary bypass",
        &key,
    );
    let response = super::handler_post_transactions_batch(
        State(app.clone()),
        HeaderMap::new(),
        transaction_batch_body_for_test(vec![
            iroha_version::codec::EncodeVersioned::encode_versioned(&tx),
        ]),
    )
    .await
    .expect("ordinary batch returns one classified economic outcome");
    assert_eq!(
        torii_response_header(&response, "x-iroha-transactions-accepted"),
        Some("0")
    );
    let outcomes: Vec<TransactionBatchEntryOutcome> =
        norito::json::from_slice(&torii_body_bytes(response, "batch outcomes").await).unwrap();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].signed_transaction_hash, tx.hash());
    assert_ne!(outcomes[0].status, 202);
    assert_eq!(app.queue.active_len(), 0);
}
#[tokio::test]
async fn handler_post_transactions_batch_rate_limits_api_token_as_single_key_batch() {
    let mut app = mk_app_state_for_tests();
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        app_mut.high_load_tx_threshold = usize::MAX;
        app_mut.tx_preauth_rate_limiter = limits::RateLimiter::new(Some(1), Some(2));
        app_mut.require_api_token = true;
        app_mut.api_token_digests =
            Arc::new(limits::ApiTokenDigestSet::from_tokens(["batch-token"]));
    }
    let keypair =
        checked_torii_test_ed25519_keypair(0xcb, "derive post-transaction batch token fixture key");
    let authority = AccountId::new(keypair.public_key().clone());
    let network_id = *app.state.network_id_ref();
    let payloads = (0..3)
        .map(|index| {
            let tx = signed_log_transaction_for_test(
                network_id,
                authority.clone(),
                format!("batch-token-rate-limit-{index}"),
                &keypair,
            );
            iroha_version::codec::EncodeVersioned::encode_versioned(&tx)
        })
        .collect();
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::HeaderName::from_static("x-api-token"),
        HeaderValue::from_static("batch-token"),
    );
    let err = match super::handler_post_transactions_batch(
        State(app.clone()),
        headers,
        transaction_batch_body_for_test(payloads),
    )
    .await
    {
        Ok(_) => panic!("expected token rate limit"),
        Err(err) => err,
    };
    assert_eq!(err.into_response().status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(app.queue.active_len(), 0);
    let token_key =
        transaction_api_token_preauth_key(limits::ApiTokenPrincipal::from_token("batch-token"));
    assert!(
        app.tx_preauth_rate_limiter
            .allow_repeated(&token_key, 2)
            .await,
        "a refused atomic preauth charge preserves the entire burst"
    );
    assert!(
        !app.tx_preauth_rate_limiter.allow(&token_key).await,
        "successful charging exhausts this same shared token bucket"
    );
}
#[test]
fn transaction_api_token_preauth_key_never_contains_raw_token_text() {
    let raw_token = "transaction-preauth-secret-material";
    let key = transaction_api_token_preauth_key(limits::ApiTokenPrincipal::from_token(raw_token));
    assert!(!key.contains(raw_token));
    assert!(key.starts_with("v1/transaction:preauth:api-token:"));
}
#[tokio::test]
async fn handler_post_transactions_batch_uses_authenticated_token_for_distinct_authorities() {
    let mut app = mk_app_state_for_tests();
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        app_mut.high_load_tx_threshold = usize::MAX;
        app_mut.tx_preauth_rate_limiter = limits::RateLimiter::new(Some(1), Some(2));
        app_mut.require_api_token = true;
        app_mut.api_token_digests = Arc::new(limits::ApiTokenDigestSet::from_tokens([
            "batch-distinct-token",
        ]));
    }
    let network_id = *app.state.network_id_ref();
    let payloads = (0..3)
        .map(|index| {
            let keypair = checked_torii_test_ed25519_keypair(
                0xcc_u8.wrapping_add(index as u8),
                "derive distinct-authority batch token fixture key",
            );
            let authority = AccountId::new(keypair.public_key().clone());
            let tx = signed_log_transaction_for_test(
                network_id,
                authority,
                format!("batch-token-distinct-authority-{index}"),
                &keypair,
            );
            iroha_version::codec::EncodeVersioned::encode_versioned(&tx)
        })
        .collect();
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::HeaderName::from_static("x-api-token"),
        HeaderValue::from_static("batch-distinct-token"),
    );
    let err = match super::handler_post_transactions_batch(
        State(app.clone()),
        headers,
        transaction_batch_body_for_test(payloads),
    )
    .await
    {
        Ok(_) => panic!("expected token rate limit"),
        Err(err) => err,
    };
    assert_eq!(err.into_response().status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(app.queue.active_len(), 0);
    let token_key = transaction_api_token_preauth_key(limits::ApiTokenPrincipal::from_token(
        "batch-distinct-token",
    ));
    assert!(
        app.tx_preauth_rate_limiter
            .allow_repeated(&token_key, 2)
            .await,
        "a refused atomic preauth charge preserves the entire burst"
    );
    assert!(
        !app.tx_preauth_rate_limiter.allow(&token_key).await,
        "successful charging exhausts this same shared token bucket"
    );
}
#[tokio::test]
async fn handler_post_transactions_batch_rejects_invalid_ed25519_precheck_without_partial_push() {
    let mut app = mk_app_state_for_tests();
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .high_load_tx_threshold = usize::MAX;
    let keypair =
        checked_torii_test_ed25519_keypair(0xd0, "derive invalid precheck batch fixture key");
    let authority = AccountId::new(keypair.public_key().clone());
    let network_id = *app.state.network_id_ref();
    let tx1 = signed_log_transaction_for_test(
        network_id,
        authority.clone(),
        "batch-valid-before-invalid",
        &keypair,
    );
    let tx2 =
        signed_log_transaction_for_test(network_id, authority, "batch-invalid-signature", &keypair);
    let tx2 = transaction_with_invalid_signature_for_test(tx2);
    let payloads = vec![
        iroha_version::codec::EncodeVersioned::encode_versioned(&tx1),
        iroha_version::codec::EncodeVersioned::encode_versioned(&tx2),
    ];
    let err = match super::handler_post_transactions_batch(
        State(app.clone()),
        HeaderMap::new(),
        transaction_batch_body_for_test(payloads),
    )
    .await
    {
        Ok(_) => panic!("expected invalid signature rejection"),
        Err(err) => err,
    };
    let response = err.into_response();
    assert_eq!(
        torii_response_header(&response, "x-iroha-reject-code"),
        Some(SignatureRejectionCode::InvalidSignature.as_str())
    );
    assert_eq!(app.queue.active_len(), 0);
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_post_transaction_rejects_unfunded_nexus_fee_tx_before_history() {
    let keypair =
        checked_torii_test_ed25519_keypair(0xd1, "derive unfunded fee fixture authority key");
    let authority = AccountId::new(keypair.public_key().clone());
    let fee_sink_keypair =
        checked_torii_test_ed25519_keypair(0xd2, "derive unfunded fee fixture sink key");
    let fee_sink = AccountId::new(fee_sink_keypair.public_key().clone());
    let domain_id =
        DomainId::parse_fully_qualified("universal.universal").expect("canonical XOR domain id");
    let fee_asset_id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "xor".parse().expect("asset name"),
    );
    let domain = Domain::new(domain_id).build(&authority);
    let account = Account::new(authority.clone()).build(&authority);
    let fee_sink_account = Account::new(fee_sink.clone()).build(&fee_sink);
    let fee_asset_definition = iroha_data_model::asset::AssetDefinition::numeric(
        fee_asset_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority);
    let world = World::with(
        [domain.clone()],
        [account.clone(), fee_sink_account.clone()],
        [fee_asset_definition.clone()],
    );
    let mut app = native_ingress_app_with_world_for_test(world);
    configure_nexus_fee_admission_for_test(&mut app, &fee_asset_id, &fee_sink);
    let tx = TransactionBuilder::new(
        *app.state.network_id_ref(),
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(
            vec![iroha_data_model::transaction::FeeChargeLimit::new(
                iroha_data_model::transaction::FeeChargeKind::Nexus,
                fee_asset_id,
                Quantity::from(1_u32),
            )],
            None,
        ),
    )
    .with_instructions([Log::new(Level::INFO, "fee-insolvent".to_owned())])
    .sign(keypair.private_key());
    let tx_hash = tx.hash();
    let tx_hash_hex = tx_hash.to_string();
    let transaction = TransactionEntrypoint::External(tx.clone());
    let routing_plan =
        RoutingPlan::single(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL));
    let sender = app.local_peer_id.clone().expect("native fixture validator");
    let receiver_response = super::execute_incoming_torii_proxy_request(
        &app,
        ToriiProxyRequestV1 {
            schema_version: TORII_PROXY_REQUEST_VERSION_V1,
            request_id: Hash::new(b"unfunded native ingress"),
            deadline_unix_ms: super::torii_proxy_test_deadline_unix_ms(),
            hop_count: 1,
            max_hops: 3,
            visited_peer_ids: vec![sender.clone()],
            request: ToriiProxyRequestKindV1::SubmitTransaction {
                transaction,
                expected_plan: ToriiRoutingPlanHintV1::from(routing_plan),
            },
        },
        Some(sender),
    )
    .await;
    assert_eq!(receiver_response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        torii_response_header(&receiver_response, "x-iroha-reject-code"),
        Some("PRTRY:NEXUS_FEE_ADMISSION_REJECTED")
    );
    let response = match post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &tx).await
    {
        Ok(response) => response,
        Err(err) => err.into_response(),
    };
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        torii_response_header(&response, "x-iroha-reject-code"),
        Some("PRTRY:NEXUS_FEE_ADMISSION_REJECTED")
    );
    assert_eq!(app.queue.active_len(), 0);
    assert!(
        !app.state.has_committed_entrypoint(tx.hash_as_entrypoint()),
        "ingress rejection should not create committed history"
    );
    let explorer_uri: axum::http::Uri = format!("/v1/explorer/transactions/{tx_hash_hex}")
        .parse()
        .expect("valid Explorer transaction URI");
    let explorer = super::handler_explorer_transaction_detail(
        State(app),
        HeaderMap::new(),
        axum::http::Method::GET,
        explorer_uri,
        crate::loopback_connect_info(),
        axum::extract::Path(tx_hash_hex),
    )
    .await
    .expect("explorer detail response");
    assert_eq!(explorer.status(), StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn handler_policy_reports_tx_rate_limit_as_always_enforced() {
    let mut app = mk_app_state_for_tests();
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        app_mut.fee_policy = FeePolicy::Disabled;
        app_mut.high_load_tx_threshold = usize::MAX;
    }
    let response =
        super::handler_policy(State(app), HeaderMap::new(), crate::loopback_connect_info())
            .await
            .expect("policy response")
            .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let json = decode_torii_json(response, "policy body", "valid policy json").await;
    assert_eq!(
        json.get("rate_limit_enforced"),
        Some(&norito::json::Value::Bool(true))
    );
}
#[tokio::test]
async fn handler_policy_reports_required_token_even_when_configuration_is_unavailable() {
    let mut app = mk_app_state_for_tests();
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        app_mut.require_api_token = true;
        app_mut.api_token_digests = Arc::new(limits::ApiTokenDigestSet::default());
        app_mut.api_rate_limit_bypass_nets = Arc::new(vec![
            limits::parse_cidr("127.0.0.0/8").expect("loopback CIDR"),
        ]);
    }
    let response =
        super::handler_policy(State(app), HeaderMap::new(), crate::loopback_connect_info())
            .await
            .expect("allowlisted policy response")
            .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let json = decode_torii_json(response, "policy body", "valid policy JSON").await;
    assert_eq!(
        json.get("require_api_token"),
        Some(&norito::json::Value::Bool(true))
    );
    assert_eq!(
        json.get("token_required"),
        Some(&norito::json::Value::Bool(true))
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn kaigi_signal_history_rate_bypass_still_requires_heavy_query_admission() {
    let mut app = mk_app_state_for_tests();
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        app_mut.api_rate_limit_bypass_nets = Arc::new(vec![
            limits::parse_cidr("127.0.0.0/8").expect("loopback CIDR"),
        ]);
        app_mut.require_api_token = true;
        app_mut.api_token_digests = Arc::new(limits::ApiTokenDigestSet::default());
        app_mut.query_heavy_inflight = Arc::new(tokio::sync::Semaphore::new(0));
        app_mut.query_queue_timeout = Duration::ZERO;
    }
    let error = match super::handler_kaigi_call_signals(
        State(app),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        AxPath("not-a-call".to_owned()),
        AxQuery(routing::KaigiCallSignalsParams::default()),
    )
    .await
    {
        Ok(_) => panic!("saturated heavy admission must reject a rate-bypass caller"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
        ))
    ));
}
#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_post_transaction_high_load_threshold_does_not_reject_before_enqueue() {
    let keypair =
        checked_torii_test_ed25519_keypair(0xd3, "derive high-load threshold fixture key");
    let mut app = native_ingress_app_for_test(&[&keypair]);
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .high_load_tx_threshold = 1;
    let authority = AccountId::new(keypair.public_key().clone());
    let network_id = *app.state.network_id_ref();
    let tx1 =
        signed_log_transaction_for_test(network_id, authority.clone(), "early-shed-1", &keypair);
    let tx2 = signed_log_transaction_for_test(network_id, authority, "early-shed-2", &keypair);
    let first = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &tx1)
        .await
        .expect("first transaction should be accepted");
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert_native_pending_for_test(&app, &tx1);
    assert_eq!(app.queue.active_len(), 1);
    let second = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &tx2)
        .await
        .expect("second transaction should not be rejected");
    assert_eq!(second.status(), StatusCode::ACCEPTED);
    assert_native_pending_for_test(&app, &tx2);
    assert_eq!(app.queue.active_len(), 2);
}
#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_post_transaction_allows_enqueue_when_queue_age_saturates() {
    let keypair =
        checked_torii_test_ed25519_keypair(0xd4, "derive queue-age saturation fixture key");
    let mut app = native_ingress_app_for_test(&[&keypair]);
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .high_load_tx_threshold = usize::MAX;
    let authority = AccountId::new(keypair.public_key().clone());
    let network_id = *app.state.network_id_ref();
    let tx1 =
        signed_log_transaction_for_test(network_id, authority.clone(), "age-shed-1", &keypair);
    let tx2 = signed_log_transaction_for_test(network_id, authority, "age-shed-2", &keypair);
    let first = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &tx1)
        .await
        .expect("first transaction should be accepted");
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert_native_pending_for_test(&app, &tx1);
    assert_eq!(app.queue.active_len(), 1);
    let snapshot = app
        .queue
        .backdate_queued_transactions_for_tests(Duration::from_secs(3));
    assert!(
        snapshot.saturated_by_age,
        "test setup should make queue age saturation observable"
    );
    let pressure = app.queue.pressure_snapshot();
    assert!(
        pressure.saturated_by_age,
        "age saturation should still be observable in queue pressure telemetry"
    );
    assert!(
        !app.queue.current_backpressure().is_saturated(),
        "age-only queue pressure must not reject ingress before capacity"
    );
    let second = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &tx2)
        .await
        .expect("second transaction should not be age-shed");
    assert_eq!(second.status(), StatusCode::ACCEPTED);
    assert_native_pending_for_test(&app, &tx2);
    assert_eq!(app.queue.active_len(), 2);
}
#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_post_transaction_returns_queue_full_only_for_real_capacity_overflow() {
    let keypair = checked_torii_test_ed25519_keypair(0xd5, "derive queue capacity fixture key");
    let mut app = native_ingress_app_for_test(&[&keypair]);
    install_single_slot_transaction_queue(&mut app);
    let authority = AccountId::new(keypair.public_key().clone());
    let network_id = *app.state.network_id_ref();
    let tx1 =
        signed_log_transaction_for_test(network_id, authority.clone(), "queue-full-1", &keypair);
    let tx2 = signed_log_transaction_for_test(network_id, authority, "queue-full-2", &keypair);
    let first = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &tx1)
        .await
        .expect("first transaction should be accepted");
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert_native_pending_for_test(&app, &tx1);
    let err = match post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &tx2).await {
        Ok(_) => panic!("expected real queue overflow"),
        Err(err) => err,
    };
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        torii_response_header(&response, "x-iroha-reject-code"),
        Some("PRTRY:QUEUE_FULL")
    );
}
#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_post_transaction_does_not_age_shed_retained_native_candidate() {
    // Native candidate selection retains the exact signed input until global application.
    let (mut app, keypair, _, certificate) = lifecycle_ordinary_fixture(true);
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .high_load_tx_threshold = usize::MAX;
    let tx1 = lifecycle_transaction_with_nonce_for_test(&app, &keypair, &certificate, 1);
    let tx2 = lifecycle_transaction_with_nonce_for_test(&app, &keypair, &certificate, 2);
    assert_ne!(
        tx1.hash(),
        tx2.hash(),
        "both actual lifecycle inputs have distinct signed identities"
    );
    let _ = app
        .queue
        .refresh_pressure_budget_from_block_time(Duration::ZERO);
    let first = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &tx1)
        .await
        .expect("first transaction should be accepted");
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let candidates = app
        .queue
        .bounded_pending_snapshot_for_testing(&app.state.view(), NonZeroUsize::new(1).unwrap())
        .expect("healthy candidate snapshot");
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        app.queue.active_len(),
        1,
        "candidate retains queue ownership"
    );
    std::thread::sleep(Duration::from_millis(2_100));
    let second = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &tx2)
        .await
        .expect("second transaction should not be age-shed");
    assert_eq!(second.status(), StatusCode::ACCEPTED);
    assert_eq!(
        app.queue.active_len(),
        2,
        "both original native inputs remain pending"
    );
    assert_eq!(candidates[0].hash(), tx1.hash());
}
#[test]
fn signed_query_scope_classifies_trigger_inventory_queries_as_local_replicated() {
    let key_pair =
        checked_torii_test_ed25519_keypair(0xd7, "derive trigger inventory query fixture key");
    let authority = AccountId::new(key_pair.public_key().clone());
    let find_triggers = signed_find_triggers_query_for_test(authority.clone(), &key_pair);
    assert_eq!(
        super::signed_query_scope(&find_triggers.payload),
        super::SignedQueryScope::LocalReplicated
    );
    let find_active_ids = signed_find_active_trigger_ids_query_for_test(authority, &key_pair);
    assert_eq!(
        super::signed_query_scope(&find_active_ids.payload),
        super::SignedQueryScope::LocalReplicated
    );
}
#[test]
fn signed_query_scope_classifies_exact_peer_inventory_as_public_control_plane() {
    let authority =
        checked_torii_test_account_id(0xf6, "derive peer inventory authority fixture key");
    let request = request_for_test(
        &authority,
        iroha_data_model::query::QueryRequest::Start(build_find_peers_query_for_test()),
    );
    assert_eq!(
        super::signed_query_scope(&request),
        super::SignedQueryScope::PublicControlPlane
    );
}
#[test]
fn signed_query_scope_rejects_cross_kind_target_payload_collisions() {
    let authority = checked_torii_test_account_id(
        0xf7,
        "derive cross-kind query collision authority fixture key",
    );
    let domain_id =
        iroha_model_base::domain::DomainId::try_new("hbl", "restricted").expect("domain id");
    let asset_definition_id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        domain_id,
        "asset-definition".parse().expect("asset definition name"),
    );
    let mut history_with_target_payload =
        build_find_accounts_with_asset_query_for_test(asset_definition_id);
    history_with_target_payload.item = iroha_data_model::query::QueryItemKind::CommittedTransaction;
    let mut global_roles_with_account_payload =
        build_find_roles_by_account_query_for_test(authority.clone());
    global_roles_with_account_payload.item = iroha_data_model::query::QueryItemKind::Role;
    for query in [
        history_with_target_payload,
        global_roles_with_account_payload,
    ] {
        assert_eq!(
            super::signed_query_scope(&request_for_test(
                &authority,
                iroha_data_model::query::QueryRequest::Start(query),
            )),
            super::SignedQueryScope::CrossDataspaceFanout,
            "a payload from a narrower query must not downscope a different global item kind",
        );
    }
}
#[test]
fn peer_inventory_scope_requires_exact_canonical_payload() {
    let authority = checked_torii_test_account_id(
        0xf8,
        "derive malformed peer inventory authority fixture key",
    );
    let mut trailing = build_find_peers_query_for_test();
    trailing.query_payload.push(0xa5);
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Start(trailing),
        )),
        super::SignedQueryScope::CrossDataspaceFanout
    );
}
#[test]
fn signed_query_scope_uses_escrow_party_discriminants() {
    use iroha_data_model::{
        escrow::AssetEscrowStatus,
        query::{
            QueryItemKind, QueryWithParams,
            escrow::prelude::{
                FindAssetEscrowsByBuyer, FindAssetEscrowsBySeller, FindAssetEscrowsByStatus,
            },
            parameters::QueryParams,
        },
    };
    let authority =
        checked_torii_test_account_id(0xfa, "derive escrow query routing authority fixture key");
    let target = checked_torii_test_account_id(0xfb, "derive escrow query target fixture key");
    let seller_query = QueryWithParams {
        query: (),
        query_payload: norito::codec::Encode::encode(&FindAssetEscrowsBySeller {
            seller: target.clone(),
        }),
        item: QueryItemKind::AssetEscrowsBySeller,
        predicate_bytes: Vec::new(),
        selector_bytes: Vec::new(),
        params: QueryParams::default(),
    };
    let scope_limits = super::QueryScopeMemoryLimits {
        decode_allocated_bytes: 64 * 1024,
        canonical_encoded_bytes: 64 * 1024,
    };
    assert_eq!(
        super::target_account_iterable_query_bounded(&seller_query, scope_limits)
            .expect("bounded seller query classification"),
        Some(target.clone())
    );
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Start(seller_query),
        )),
        super::SignedQueryScope::TargetAccount(target.clone())
    );
    let buyer_query = QueryWithParams {
        query: (),
        query_payload: norito::codec::Encode::encode(&FindAssetEscrowsByBuyer {
            buyer: target.clone(),
        }),
        item: QueryItemKind::AssetEscrowsByBuyer,
        predicate_bytes: Vec::new(),
        selector_bytes: Vec::new(),
        params: QueryParams::default(),
    };
    assert_eq!(
        super::target_account_iterable_query_bounded(&buyer_query, scope_limits)
            .expect("bounded buyer query classification"),
        Some(target.clone())
    );
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Start(buyer_query),
        )),
        super::SignedQueryScope::TargetAccount(target.clone())
    );
    let legacy_item_tag = QueryWithParams {
        query: (),
        query_payload: norito::codec::Encode::encode(&FindAssetEscrowsBySeller {
            seller: target.clone(),
        }),
        item: QueryItemKind::AssetEscrowRecord,
        predicate_bytes: Vec::new(),
        selector_bytes: Vec::new(),
        params: QueryParams::default(),
    };
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Start(legacy_item_tag),
        )),
        super::SignedQueryScope::CrossDataspaceFanout
    );
    let status_query = QueryWithParams {
        query: (),
        query_payload: norito::codec::Encode::encode(&FindAssetEscrowsByStatus {
            status: AssetEscrowStatus::PaymentSent,
        }),
        item: QueryItemKind::AssetEscrowsByStatus,
        predicate_bytes: Vec::new(),
        selector_bytes: Vec::new(),
        params: QueryParams::default(),
    };
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Start(status_query),
        )),
        super::SignedQueryScope::CrossDataspaceFanout
    );
}
#[tokio::test]
async fn peer_inventory_requires_ledger_permission_and_executes_locally() {
    let key_pair = checked_torii_test_ed25519_keypair(
        0xf9,
        "derive public peer inventory handler fixture key",
    );
    let authority = AccountId::new(key_pair.public_key().clone());
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account(&authority),
        crate::tests_runtime_handlers::private_ingress_with_offline_foreign_nexus_for_test(),
    );
    configure_private_ingress_with_offline_foreign_route_for_test(&mut app);
    assert!(
        super::torii_all_dataspace_routes(app.as_ref()).len() > 1,
        "test requires multiple restricted dataspace routes",
    );
    let signed = authorize_query_for_test(
        iroha_data_model::query::QueryRequest::Start(build_find_peers_query_for_test()),
        authority.clone(),
    )
    .sign(&key_pair);
    let denied = super::handler_signed_query(
        State(app.clone()),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        None,
        crate::NoritoQuery(QueryOptions::default()),
        versioned_query_for_test(signed),
    )
    .await;
    assert!(matches!(
        denied,
        Err(Error::Query(ValidationFail::NotPermitted(message)))
            if message.contains("CanReadAllLedgerData")
    ));
    grant_account_permission_for_test(&app, &authority, CanReadAllLedgerData.into());
    let signed = authorize_query_for_test(
        iroha_data_model::query::QueryRequest::Start(build_find_peers_query_for_test()),
        authority,
    )
    .sign(&key_pair);
    let response = super::handler_signed_query(
        State(app),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        None,
        crate::NoritoQuery(QueryOptions::default()),
        versioned_query_for_test(signed),
    )
    .await
    .expect("authorized peer inventory should execute locally")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("x-iroha-routed-by").is_none());
}
#[test]
fn account_id_inventory_does_not_collide_with_trigger_inventory_scope() {
    let authority =
        checked_torii_test_account_id(0xf0, "derive account inventory authority fixture key");
    let request = request_for_test(
        &authority,
        iroha_data_model::query::QueryRequest::Start(build_find_account_ids_query_for_test()),
    );
    assert_eq!(
        super::signed_query_scope(&request),
        super::SignedQueryScope::CrossDataspaceFanout
    );
}
#[test]
fn query_scope_payload_matching_rejects_malformed_and_trailing_bytes() {
    use iroha_data_model::query::transaction::prelude::FindTransactions;
    let mut payload = norito::codec::Encode::encode(&FindTransactions::new());
    assert!(super::payload_matches_query::<FindTransactions>(&payload));
    payload.push(0xa5);
    assert!(
        !super::payload_matches_query::<FindTransactions>(&payload),
        "a valid prefix with trailing bytes must not inherit history-query routing"
    );
    assert!(
        !super::payload_matches_query::<FindTransactions>(&[0xff, 0x00]),
        "malformed bytes must not inherit a privileged routing scope"
    );
}
#[test]
fn iterable_target_account_query_builders_capture_target_payload() {
    let account_id =
        checked_torii_test_account_id(0xd8, "derive iterable account target fixture key");
    let domains_query = build_find_domains_by_account_query_for_test(account_id.clone());
    assert_domains_query_targets_account(&domains_query, &account_id);
    let assets_query = build_find_assets_by_account_query_for_test(account_id.clone());
    assert_assets_query_targets_account(&assets_query, &account_id);
    let nfts_query = build_find_nfts_by_account_query_for_test(account_id.clone());
    assert_nfts_query_targets_account(&nfts_query, &account_id);
    let permissions_query = build_find_permissions_by_account_query_for_test(account_id.clone());
    assert_permissions_query_targets_account(&permissions_query, &account_id);
    let roles_query = build_find_roles_by_account_query_for_test(account_id.clone());
    assert_roles_query_targets_account(&roles_query, &account_id);
}
#[test]
fn iterable_target_domain_query_builders_capture_target_payload() {
    let domain_id =
        iroha_model_base::domain::DomainId::try_new("hbl", "restricted").expect("domain id");
    let asset_definition_id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        domain_id,
        "asset-definition".parse().expect("asset definition name"),
    );
    let accounts_query = build_find_accounts_with_asset_query_for_test(asset_definition_id.clone());
    assert_accounts_with_asset_query_targets_domain(&accounts_query, &asset_definition_id);
}
#[tokio::test]
async fn global_asset_definition_and_own_balance_ignore_unrelated_restricted_routes() {
    use iroha_core::sumeragi::test_chain::TestChainConfig;
    let definition: iroha_data_model::asset::AssetDefinitionId = "6TEAJqbb8oEPmLncoNiMRbLEK6tw"
        .parse()
        .expect("canonical XOR id");
    let caller_key =
        checked_torii_test_ed25519_keypair(0xc0, "derive existing asset-query validator authority");
    let caller = AccountId::new(caller_key.public_key().clone());
    let mut nexus = private_ingress_nexus_for_test();
    let fee_asset: AssetDefinitionId = nexus
        .fees
        .fee_asset_id
        .parse()
        .expect("canonical Nexus fee currency");
    assert_eq!(
        fee_asset, definition,
        "the global XOR fixture uses its original fee currency"
    );
    let fee_sink = checked_torii_test_account_id(0xc1, "independent global-asset fee sink");
    assert_ne!(
        fee_sink, *ALICE_ID,
        "the configured sink is independent from the original payer"
    );
    nexus.fees.fee_sink_account_id = fee_sink.to_string();
    // The original native Mint costs 150 gas plus one instruction at the
    // unchanged default Nexus schedule; Core quotes the actual signed limit below.
    let original_fee: Quantity = "0.0085".parse().expect("exact original Mint fee");
    assert!(!original_fee.is_zero());
    let world = World::with_assets(
        [Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&ALICE_ID)],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(caller.clone()).build(&caller),
            Account::new(fee_sink.clone()).build(&fee_sink),
        ],
        [iroha_data_model::asset::AssetDefinition::numeric(
            definition.clone(),
            "XOR".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID)],
        [Asset::new(
            AssetId::new(fee_asset.clone(), ALICE_ID.clone()),
            original_fee.clone(),
        )],
        [],
    );
    let asset = iroha_data_model::asset::AssetId::new(definition.clone(), ALICE_ID.clone());
    let initial_supply = world
        .view()
        .asset_definitions()
        .get(&definition)
        .expect("original global fee currency")
        .total_quantity()
        .clone();
    assert_eq!(initial_supply, original_fee);
    let mut config = TestChainConfig::new(world, 1_000);
    config.nexus = Some(nexus);
    let (mut app, _funded_hash, chain) = executed_history_test_fixture(
        config,
        &iroha_test_samples::ALICE_KEYPAIR,
        vec![iroha_data_model::isi::Mint::asset_quantity(77_u32, asset.clone()).into()],
        true,
    );
    assert_eq!(
        chain.committed(2).block().external_transactions().count(),
        1
    );
    assert_eq!(
        chain
            .committed(2)
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result
            .is_ok(),
        true
    );
    Arc::get_mut(&mut app).unwrap().local_peer_id = Some(chain.validators()[0].0.clone());
    let committed = chain.committed(2);
    let input = committed.block().external_transactions().next().unwrap();
    let limits = input.fee_payment_intent().charge_limits();
    assert_eq!(limits.len(), 1, "one original signed native fee component");
    assert_eq!(
        limits[0].kind(),
        iroha_data_model::transaction::FeeChargeKind::Nexus
    );
    assert_eq!(limits[0].asset_definition_id(), &fee_asset);
    assert_eq!(limits[0].max_amount(), &original_fee);
    let view = app.state.view();
    let sink_balance = view
        .world()
        .assets()
        .get(&AssetId::new(fee_asset.clone(), fee_sink))
        .map_or_else(Quantity::zero, |value| value.as_ref().clone());
    assert_eq!(
        sink_balance,
        Quantity::zero(),
        "ordinary native Nexus fees burn instead of crediting the configured sink"
    );
    let supply_after = view
        .world()
        .asset_definitions()
        .get(&fee_asset)
        .unwrap()
        .total_quantity();
    let minted = Quantity::from(77_u32);
    let before_burn = initial_supply.checked_add(&minted).unwrap();
    assert_eq!(
        before_burn
            .checked_sub(supply_after)
            .expect("original supply covers its charged fee"),
        original_fee.clone(),
        "the original native fee reduces actual total supply by its signed amount"
    );
    let payer_after = view.world().assets().get(&asset).unwrap().as_ref();
    assert_eq!(
        before_burn
            .checked_sub(payer_after)
            .expect("original payer balance covers its charged fee"),
        original_fee,
        "the original payer alone funds the native fee burn"
    );
    assert_eq!(payer_after, &minted);
    assert_eq!(supply_after, &minted);
    drop(view);
    let global_route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let committee = app
        .state
        .resolve_route_authority(super::lane_authority_route(global_route))
        .expect("funded fixture has active global authority");
    assert_eq!(committee.validators().len(), 4);
    assert!(super::should_execute_route_locally(
        app.as_ref(),
        global_route
    ));
    assert!(super::torii_all_dataspace_routes(app.as_ref()).len() > 1);
    for query in [
        iroha_data_model::query::SingularQueryBox::from(
            iroha_data_model::query::asset::prelude::FindAssetDefinitionById::new(
                definition.clone(),
            ),
        ),
        iroha_data_model::query::SingularQueryBox::from(
            iroha_data_model::query::asset::prelude::FindAssetById::new(asset.clone()),
        ),
    ] {
        let request = request_for_test(
            &ALICE_ID,
            iroha_data_model::query::QueryRequest::Singular(query.clone()),
        );
        let scope = super::signed_query_scope_for_app(app.as_ref(), &request);
        let routes = super::torii_authorized_signed_query_routes(app.as_ref(), &request, &scope)
            .expect("exact public asset lookup does not request unrelated restricted data");
        assert!(
            routes
                .iter()
                .all(|route| route.dataspace_id == DataSpaceId::UNIVERSAL)
        );
        let mut request = authorize_query_for_test(
            iroha_data_model::query::QueryRequest::Singular(query),
            ALICE_ID.clone(),
        );
        request.network_id = *app.state.network_id_ref();
        let signed = request.sign(&iroha_test_samples::ALICE_KEYPAIR);
        let response = super::handler_signed_query(
            State(app.clone()),
            HeaderMap::new(),
            crate::loopback_connect_info(),
            None,
            crate::NoritoQuery(QueryOptions::default()),
            versioned_query_for_test(signed),
        )
        .await
        .expect("ordinary signed wallet query")
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
    for granted in [false, true] {
        if granted {
            grant_account_permission_for_test(
                &app,
                &caller,
                iroha_executor_data_model::permission::query::CanReadAccountData {
                    account: ALICE_ID.clone(),
                }
                .into(),
            );
        }
        let mut request = authorize_query_for_test(
            iroha_data_model::query::QueryRequest::Singular(
                iroha_data_model::query::asset::prelude::FindAssetById::new(asset.clone()).into(),
            ),
            caller.clone(),
        );
        request.network_id = *app.state.network_id_ref();
        let signed = request.sign(&caller_key);
        let response = super::handler_signed_query(
            State(app.clone()),
            HeaderMap::new(),
            crate::loopback_connect_info(),
            Some(crate::utils::extractors::ExtractAccept(
                axum::http::HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
            )),
            crate::NoritoQuery(QueryOptions::default()),
            versioned_query_for_test(signed),
        )
        .await
        .unwrap_or_else(IntoResponse::into_response);
        assert_eq!(
            response.status(),
            if granted {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            },
            "universal routing must preserve the native exact-holder permission gate"
        );
        if granted {
            let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .expect("exact balance response");
            let decoded: iroha_data_model::query::QueryResponse =
                norito::decode_from_bytes(&body).expect("decode native balance response");
            let iroha_data_model::query::QueryResponse::Singular(
                iroha_data_model::query::SingularQueryOutputBox::Asset(actual),
            ) = decoded
            else {
                panic!("exact balance query must return one asset");
            };
            assert_eq!(actual.id, asset);
            assert_eq!(actual.value, Quantity::from(77_u32));
        }
    }
}

#[tokio::test]
async fn global_asset_balance_route_requires_exact_holder_scope_and_known_policy() {
    use iroha_data_model::{
        asset::{AssetBalanceScope, AssetDefinition, AssetDefinitionId, AssetId},
        query::{QueryRequest, asset::prelude::FindAssetById},
    };
    let private_home = DomainId::try_new("cash", "restricted").expect("private owning domain");
    let definition = |name: &str| {
        AssetDefinitionId::derive_from_components(private_home.clone(), name.parse().unwrap())
    };
    let global = definition("global");
    let private_global = definition("private-global");
    let restricted = definition("restricted");
    let world = World::with(
        [Domain::new(private_home.clone()).build(&ALICE_ID)],
        [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
        [
            AssetDefinition::numeric(global.clone(), "global", AssetBalancePolicy::Global, None)
                .build(&ALICE_ID),
            AssetDefinition::numeric(
                private_global.clone(),
                "private-global",
                AssetBalancePolicy::Global,
                Some(private_home.clone()),
            )
            .build(&ALICE_ID),
            AssetDefinition::numeric(
                restricted.clone(),
                "restricted",
                AssetBalancePolicy::DataspaceRestricted,
                Some(private_home.clone()),
            )
            .build(&ALICE_ID),
        ],
    );
    let app = mk_app_state_for_tests_with_world_and_nexus(world, private_ingress_nexus_for_test());
    let request = |id, scope| {
        request_for_test(
            &ALICE_ID,
            QueryRequest::Singular(
                FindAssetById::new(AssetId::with_scope(id, ALICE_ID.clone(), scope)).into(),
            ),
        )
    };
    let known = request(global.clone(), AssetBalanceScope::Global);
    assert!(super::is_known_global_asset_balance_query(
        &app, &known, &ALICE_ID
    ));
    assert!(!super::is_known_global_asset_balance_query(
        &app,
        &known,
        &checked_torii_test_account_id(0xd9, "different balance holder"),
    ));
    assert!(
        super::is_known_global_asset_balance_query(
            &app,
            &request(private_global, AssetBalanceScope::Global),
            &ALICE_ID,
        ),
        "a global balance does not inherit its definition's private owning-domain route"
    );
    for (id, scope) in [
        (definition("unknown"), AssetBalanceScope::Global),
        (global, AssetBalanceScope::Dataspace(DataSpaceId::new(10))),
        (restricted, AssetBalanceScope::Global),
    ] {
        assert!(!super::is_known_global_asset_balance_query(
            &app,
            &request(id, scope),
            &ALICE_ID
        ));
    }
    let account_query = request_for_test(
        &ALICE_ID,
        QueryRequest::Singular(
            iroha_data_model::query::account::prelude::FindAccountById::new(ALICE_ID.clone())
                .into(),
        ),
    );
    assert!(!super::is_known_global_asset_balance_query(
        &app,
        &account_query,
        &ALICE_ID
    ));
}

#[test]
fn signed_query_scope_classifies_find_asset_by_id_as_target_account() {
    let account_id = checked_torii_test_account_id(0xd9, "derive asset-by-id account fixture key");
    let authority = checked_torii_test_account_id(0xda, "derive asset-by-id authority fixture key");
    let domain_id =
        iroha_model_base::domain::DomainId::try_new("hbl", "restricted").expect("domain id");
    let asset_definition_id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "asset-definition".parse().expect("asset definition name"),
    );
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Singular(
                iroha_data_model::query::SingularQueryBox::FindAssetById(
                    iroha_data_model::query::asset::prelude::FindAssetById::new(
                        iroha_data_model::asset::AssetId::new(
                            asset_definition_id,
                            account_id.clone(),
                        ),
                    ),
                ),
            ),
        )),
        super::SignedQueryScope::TargetAccount(account_id)
    );
}
#[test]
fn signed_query_scope_classifies_find_asset_definition_by_id_as_target_domain() {
    let authority =
        checked_torii_test_account_id(0xdb, "derive asset-definition scope authority key");
    let domain_id =
        iroha_model_base::domain::DomainId::try_new("hbl", "governance").expect("domain id");
    let asset_definition_id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "asset-definition".parse().expect("asset definition name"),
    );
    let app = mk_app_state_for_tests_with_world_and_nexus(
        World::default(),
        private_ingress_nexus_for_test(),
    );
    let request = request_for_test(
        &authority,
        iroha_data_model::query::QueryRequest::Singular(
            iroha_data_model::query::SingularQueryBox::FindAssetDefinitionById(
                iroha_data_model::query::asset::prelude::FindAssetDefinitionById::new(
                    asset_definition_id.clone(),
                ),
            ),
        ),
    );
    assert_eq!(
        super::signed_query_scope(&request),
        super::SignedQueryScope::CrossDataspaceFanout
    );
    assert_eq!(
        super::signed_query_scope_for_app(app.as_ref(), &request),
        super::SignedQueryScope::CrossDataspaceFanout,
        "an opaque ID cannot invent absent ledger ownership"
    );
    seed_asset_definition_for_test(&app, &asset_definition_id, Some(&domain_id));
    assert_eq!(
        super::signed_query_scope_for_app(app.as_ref(), &request),
        super::SignedQueryScope::TargetDomain(domain_id)
    );
}
#[tokio::test]
async fn signed_query_scope_for_app_keeps_opaque_find_asset_by_id_targeted_to_account() {
    let account_id =
        checked_torii_test_account_id(0xdc, "derive opaque asset-by-id account fixture key");
    let authority =
        checked_torii_test_account_id(0xdd, "derive opaque asset-by-id authority fixture key");
    let domain_id =
        iroha_model_base::domain::DomainId::try_new("hbl", "governance").expect("domain id");
    let asset_definition_id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "asset-definition".parse().expect("asset definition name"),
    );
    let app = mk_app_state_for_tests_with_world_and_nexus(
        World::default(),
        private_ingress_nexus_for_test(),
    );
    seed_asset_definition_for_test(&app, &asset_definition_id, Some(&domain_id));
    let request = roundtrip_request_for_test(
        &authority,
        iroha_data_model::query::QueryRequest::Singular(
            iroha_data_model::query::SingularQueryBox::FindAssetById(
                iroha_data_model::query::asset::prelude::FindAssetById::new(
                    iroha_data_model::asset::AssetId::new(asset_definition_id, account_id.clone()),
                ),
            ),
        ),
    );
    assert_eq!(
        super::signed_query_scope(&request),
        super::SignedQueryScope::TargetAccount(account_id.clone())
    );
    assert_eq!(
        super::signed_query_scope_for_app(app.as_ref(), &request),
        super::SignedQueryScope::TargetAccount(account_id)
    );
}
#[tokio::test]
async fn signed_query_scope_for_app_classifies_opaque_find_asset_definition_by_id_as_target_domain()
{
    let authority =
        checked_torii_test_account_id(0xde, "derive opaque asset-definition authority fixture key");
    let domain_id =
        iroha_model_base::domain::DomainId::try_new("hbl", "governance").expect("domain id");
    let asset_definition_id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "asset-definition".parse().expect("asset definition name"),
    );
    let app = mk_app_state_for_tests_with_world_and_nexus(
        World::default(),
        private_ingress_nexus_for_test(),
    );
    seed_asset_definition_for_test(&app, &asset_definition_id, Some(&domain_id));
    let request = roundtrip_request_for_test(
        &authority,
        iroha_data_model::query::QueryRequest::Singular(
            iroha_data_model::query::SingularQueryBox::FindAssetDefinitionById(
                iroha_data_model::query::asset::prelude::FindAssetDefinitionById::new(
                    asset_definition_id,
                ),
            ),
        ),
    );
    assert_eq!(
        super::signed_query_scope(&request),
        super::SignedQueryScope::CrossDataspaceFanout
    );
    assert_eq!(
        super::signed_query_scope_for_app(app.as_ref(), &request),
        super::SignedQueryScope::TargetDomain(domain_id)
    );
}
#[tokio::test]
async fn signed_query_scope_for_app_classifies_opaque_find_accounts_with_asset_as_target_domain() {
    let authority =
        checked_torii_test_account_id(0xdf, "derive accounts-with-asset authority fixture key");
    let domain_id =
        iroha_model_base::domain::DomainId::try_new("hbl", "governance").expect("domain id");
    let asset_definition_id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "asset-definition".parse().expect("asset definition name"),
    );
    let app = mk_app_state_for_tests_with_world_and_nexus(
        World::default(),
        private_ingress_nexus_for_test(),
    );
    seed_asset_definition_for_test(&app, &asset_definition_id, Some(&domain_id));
    let request = roundtrip_request_for_test(
        &authority,
        iroha_data_model::query::QueryRequest::Start(
            build_find_accounts_with_asset_query_for_test(asset_definition_id),
        ),
    );
    assert_eq!(
        super::signed_query_scope(&request),
        super::SignedQueryScope::CrossDataspaceFanout
    );
    assert_eq!(
        super::signed_query_scope_for_app(app.as_ref(), &request),
        super::SignedQueryScope::TargetDomain(domain_id)
    );
}
#[tokio::test]
async fn resolve_signed_query_routing_for_app_uses_target_domain_route() {
    let authority_key_pair = checked_torii_test_ed25519_keypair(
        0xe0,
        "derive target-domain routing authority fixture key",
    );
    let authority = AccountId::new(authority_key_pair.public_key().clone());
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        iroha_core::state::World::default(),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    let (restricted_lane, restricted_dataspace) =
        configure_private_ingress_routes_for_test(&mut app);
    let query = authorize_query_for_test(
        iroha_data_model::query::QueryRequest::Singular(
            iroha_data_model::query::SingularQueryBox::FindDomainById(
                iroha_data_model::query::domain::prelude::FindDomainById::new(
                    iroha_model_base::domain::DomainId::try_new("hbl", "restricted")
                        .expect("domain id"),
                ),
            ),
        ),
        authority,
    )
    .sign(&authority_key_pair);
    assert_eq!(
        super::resolve_signed_query_routing_for_app(app.as_ref(), &query)
            .expect("target-domain signed query should resolve a routed dataspace"),
        RoutingDecision::new(restricted_lane, restricted_dataspace)
    );
}
#[tokio::test]
async fn resolve_signed_query_routing_for_app_uses_target_domain_route_for_opaque_asset_definition_query()
 {
    let authority_key_pair = checked_torii_test_ed25519_keypair(
        0xe1,
        "derive opaque asset-definition routing authority fixture key",
    );
    let authority = AccountId::new(authority_key_pair.public_key().clone());
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        iroha_core::state::World::default(),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    configure_private_ingress_routes_for_test(&mut app);
    let domain_id =
        iroha_model_base::domain::DomainId::try_new("hbl", "governance").expect("domain id");
    let asset_definition_id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "asset-definition".parse().expect("asset definition name"),
    );
    seed_asset_definition_for_test(&app, &asset_definition_id, Some(&domain_id));
    let query = authorize_query_for_test(
        iroha_data_model::query::QueryRequest::Singular(
            iroha_data_model::query::SingularQueryBox::FindAssetDefinitionById(
                iroha_data_model::query::asset::prelude::FindAssetDefinitionById::new(
                    asset_definition_id,
                ),
            ),
        ),
        authority,
    )
    .sign(&authority_key_pair);
    assert_eq!(
        super::resolve_signed_query_routing_for_app(app.as_ref(), &query)
            .expect("opaque asset-definition signed query should resolve a routed dataspace"),
        RoutingDecision::new(LaneId::new(1), DataSpaceId::new(1))
    );
}
#[tokio::test]
async fn resolve_signed_query_routing_for_app_uses_target_alias_route() {
    let authority_key_pair = checked_torii_test_ed25519_keypair(
        0xe2,
        "derive target-alias routing authority fixture key",
    );
    let authority = AccountId::new(authority_key_pair.public_key().clone());
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        iroha_core::state::World::default(),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    let (restricted_lane, restricted_dataspace) =
        configure_private_ingress_routes_for_test(&mut app);
    let alias = iroha_data_model::account::AccountAlias::domainless(
        "banking".parse().expect("alias label"),
        restricted_dataspace,
    );
    let query = authorize_query_for_test(
        iroha_data_model::query::QueryRequest::Singular(
            iroha_data_model::query::SingularQueryBox::FindAccountByAlias(
                iroha_data_model::query::account::prelude::FindAccountByAlias::new(alias),
            ),
        ),
        authority,
    )
    .sign(&authority_key_pair);
    assert_eq!(
        super::resolve_signed_query_routing_for_app(app.as_ref(), &query)
            .expect("target-alias signed query should resolve a routed dataspace"),
        RoutingDecision::new(restricted_lane, restricted_dataspace)
    );
}
#[test]
fn signed_query_scope_classifies_target_account_queries() {
    let account_id = checked_torii_test_account_id(0xe3, "derive target-account scope fixture key");
    let authority =
        checked_torii_test_account_id(0xe4, "derive target-account authority fixture key");
    let alias = iroha_data_model::account::AccountAlias::domainless(
        "banking".parse().expect("alias label"),
        DataSpaceId::new(10),
    );
    let domain_id =
        iroha_model_base::domain::DomainId::try_new("hbl", "governance").expect("domain id");
    let asset_definition_id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "asset-definition".parse().expect("asset definition name"),
    );
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Singular(
                iroha_data_model::query::SingularQueryBox::FindAccountById(
                    iroha_data_model::query::account::prelude::FindAccountById::new(
                        account_id.clone(),
                    ),
                ),
            ),
        )),
        super::SignedQueryScope::TargetAccount(account_id.clone())
    );
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Singular(
                iroha_data_model::query::SingularQueryBox::FindAliasesByAccountId(
                    iroha_data_model::query::account::prelude::FindAliasesByAccountId::new(
                        account_id.clone(),
                        None,
                        None,
                    ),
                ),
            ),
        )),
        super::SignedQueryScope::TargetAccount(account_id.clone())
    );
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Singular(
                iroha_data_model::query::SingularQueryBox::FindAssetById(
                    iroha_data_model::query::asset::prelude::FindAssetById::new(
                        iroha_data_model::asset::AssetId::new(
                            asset_definition_id.clone(),
                            account_id.clone(),
                        ),
                    ),
                ),
            ),
        )),
        super::SignedQueryScope::TargetAccount(account_id.clone())
    );
    let app = mk_app_state_for_tests_with_world_and_nexus(
        World::default(),
        private_ingress_nexus_for_test(),
    );
    let definition_request = request_for_test(
        &authority,
        iroha_data_model::query::QueryRequest::Singular(
            iroha_data_model::query::SingularQueryBox::FindAssetDefinitionById(
                iroha_data_model::query::asset::prelude::FindAssetDefinitionById::new(
                    asset_definition_id.clone(),
                ),
            ),
        ),
    );
    assert_eq!(
        super::signed_query_scope(&definition_request),
        super::SignedQueryScope::CrossDataspaceFanout
    );
    assert_eq!(
        super::signed_query_scope_for_app(app.as_ref(), &definition_request),
        super::SignedQueryScope::CrossDataspaceFanout,
        "a source-free opaque definition must not inherit a domain"
    );
    seed_asset_definition_for_test(&app, &asset_definition_id, Some(&domain_id));
    assert_eq!(
        super::signed_query_scope_for_app(app.as_ref(), &definition_request),
        super::SignedQueryScope::TargetDomain(domain_id.clone())
    );
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Start(
                build_find_domains_by_account_query_for_test(account_id.clone()),
            ),
        )),
        super::SignedQueryScope::TargetAccount(account_id.clone())
    );
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Start(
                build_find_assets_by_account_query_for_test(account_id.clone()),
            ),
        )),
        super::SignedQueryScope::TargetAccount(account_id.clone())
    );
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Start(
                build_find_nfts_by_account_query_for_test(account_id.clone()),
            ),
        )),
        super::SignedQueryScope::TargetAccount(account_id.clone())
    );
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Start(
                build_find_roles_by_account_query_for_test(account_id.clone()),
            ),
        )),
        super::SignedQueryScope::TargetAccount(account_id)
    );
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Singular(
                iroha_data_model::query::SingularQueryBox::FindAccountByAlias(
                    iroha_data_model::query::account::prelude::FindAccountByAlias::new(
                        alias.clone(),
                    ),
                ),
            ),
        )),
        super::SignedQueryScope::TargetAlias(alias.clone())
    );
    assert_eq!(
            super::signed_query_scope(&request_for_test(
                &authority,
                iroha_data_model::query::QueryRequest::Singular(
                    iroha_data_model::query::SingularQueryBox::FindAccountRecoveryPolicyByAlias(
                        iroha_data_model::query::account::prelude::FindAccountRecoveryPolicyByAlias::new(
                            alias.clone(),
                        ),
                    ),
                ),
            )),
            super::SignedQueryScope::TargetAlias(alias.clone())
        );
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Singular(
                iroha_data_model::query::SingularQueryBox::FindDomainById(
                    iroha_data_model::query::domain::prelude::FindDomainById::new(
                        domain_id.clone(),
                    ),
                ),
            ),
        )),
        super::SignedQueryScope::TargetDomain(domain_id)
    );
}
#[test]
fn signed_query_scope_classifies_account_permissions_queries_as_target_account() {
    let account_id =
        checked_torii_test_account_id(0xe5, "derive account permissions target fixture key");
    let authority =
        checked_torii_test_account_id(0xe6, "derive account permissions authority fixture key");
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Start(
                build_find_permissions_by_account_query_for_test(account_id.clone()),
            ),
        )),
        super::SignedQueryScope::TargetAccount(account_id)
    );
}
#[tokio::test]
async fn signed_query_scope_for_app_classifies_account_permissions_queries_as_target_account() {
    let account_id =
        checked_torii_test_account_id(0xe7, "derive app account permissions target fixture key");
    let authority =
        checked_torii_test_account_id(0xe8, "derive app account permissions authority fixture key");
    let app = mk_app_state_for_tests();
    assert_eq!(
        super::signed_query_scope_for_app(
            app.as_ref(),
            &request_for_test(
                &authority,
                iroha_data_model::query::QueryRequest::Start(
                    build_find_permissions_by_account_query_for_test(account_id.clone()),
                ),
            ),
        ),
        super::SignedQueryScope::TargetAccount(account_id)
    );
}
#[test]
fn signed_query_scope_classifies_find_transactions_as_authority_routed() {
    let authority =
        checked_torii_test_account_id(0xe9, "derive transactions authority fixture key");
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Start(build_find_transactions_query_for_test(),),
        )),
        super::SignedQueryScope::AuthorityRouted
    );
}
#[tokio::test]
async fn signed_query_authorization_allows_exact_self_target_without_broad_read_grant() {
    let authority = checked_torii_test_account_id(0xf1, "derive self-read authority fixture key");
    let restricted_dataspace = DataSpaceId::new(10);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::signed-query-self-read"));
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account_bound_to_dataspace(&authority, uaid, restricted_dataspace),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    configure_private_ingress_routes_for_test(&mut app);
    let request = request_for_test(
        &authority,
        iroha_data_model::query::QueryRequest::Singular(
            iroha_data_model::query::account::prelude::FindAccountById::new(authority.clone())
                .into(),
        ),
    );
    let scope = super::signed_query_scope_for_app(app.as_ref(), &request);
    let routes = super::torii_authorized_signed_query_routes(app.as_ref(), &request, &scope)
        .expect("an account may read its exact identity routes");
    assert!(
        routes
            .iter()
            .any(|route| route.dataspace_id == restricted_dataspace)
    );
}
#[tokio::test]
async fn signed_query_authorization_denies_foreign_restricted_account_without_exact_grant() {
    let target = checked_torii_test_account_id(0xf2, "derive foreign-read target fixture key");
    let authority =
        checked_torii_test_account_id(0xf3, "derive foreign-read authority fixture key");
    let restricted_dataspace = DataSpaceId::new(10);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::foreign-read-target"));
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_target_and_caller_bound_to_dataspace(
            &target,
            &authority,
            uaid,
            restricted_dataspace,
        ),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    configure_private_ingress_routes_for_test(&mut app);
    let request = request_for_test(
        &authority,
        iroha_data_model::query::QueryRequest::Singular(
            iroha_data_model::query::account::prelude::FindAccountById::new(target.clone()).into(),
        ),
    );
    let scope = super::signed_query_scope_for_app(app.as_ref(), &request);
    let response = super::torii_authorized_signed_query_routes(app.as_ref(), &request, &scope)
        .expect_err("foreign restricted account reads require an exact grant");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        torii_response_header(&response, "x-iroha-reject-code"),
        Some("permission_denied")
    );
    grant_account_permission_for_test(
        &app,
        &authority,
        CanReadRestrictedDataspace {
            dataspace: restricted_dataspace,
        }
        .into(),
    );
    let routes = super::torii_authorized_signed_query_routes(app.as_ref(), &request, &scope)
        .expect("the exact restricted dataspace grant should allow the target read");
    assert!(
        routes
            .iter()
            .any(|route| route.dataspace_id == restricted_dataspace)
    );
}

#[tokio::test]
async fn signed_query_authorization_exact_account_grant_reads_only_its_restricted_target() {
    let target = checked_torii_test_account_id(0xb1, "derive delegated-read target fixture key");
    let authority =
        checked_torii_test_account_id(0xb2, "derive delegated-read authority fixture key");
    let other = checked_torii_test_account_id(0xb3, "derive delegated-read unrelated fixture key");
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::exact-account-private-read"));
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_target_and_caller_bound_to_dataspace(
            &target,
            &authority,
            uaid,
            DataSpaceId::new(10),
        ),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    let (_, restricted_dataspace) = configure_private_ingress_routes_for_test(&mut app);
    let requests = [
        request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Start(
                build_account_bound_exact_transaction_query_for_test(target.clone()),
            ),
        ),
        request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Singular(
                iroha_data_model::query::account::prelude::FindAccountById::new(target.clone())
                    .into(),
            ),
        ),
        request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Singular(
                iroha_data_model::query::asset::prelude::FindAssetById::new(
                    iroha_data_model::asset::AssetId::with_scope(
                        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                            DomainId::try_new("boi", "is2").expect("DS owning domain"),
                            "DS".parse().expect("DS asset name"),
                        ),
                        target.clone(),
                        iroha_data_model::asset::AssetBalanceScope::Dataspace(restricted_dataspace),
                    ),
                )
                .into(),
            ),
        ),
        request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Start(
                build_find_assets_by_account_query_for_test(target.clone()),
            ),
        ),
    ];
    let other_permission: Permission =
        iroha_executor_data_model::permission::query::CanReadAccountData { account: other }.into();
    grant_account_permission_for_test(&app, &authority, other_permission);
    for request in &requests {
        let scope = super::signed_query_scope_for_app(app.as_ref(), request);
        assert!(
            super::torii_authorized_signed_query_routes(app.as_ref(), request, &scope).is_err(),
            "a different account grant must not open this target's private route"
        );
    }
    let permission: Permission = iroha_executor_data_model::permission::query::CanReadAccountData {
        account: target.clone(),
    }
    .into();
    grant_account_permission_for_test(&app, &authority, permission.clone());
    for request in &requests {
        let scope = super::signed_query_scope_for_app(app.as_ref(), request);
        let routes = super::torii_authorized_signed_query_routes(app.as_ref(), request, &scope)
            .expect("exact account read permission must apply to private account data");
        assert!(
            routes
                .iter()
                .any(|route| route.dataspace_id == restricted_dataspace)
        );
    }
    for query in [
        iroha_data_model::query::QueryRequest::Start(build_find_transactions_query_for_test()),
        iroha_data_model::query::QueryRequest::Singular(
            iroha_data_model::query::account::prelude::FindAccountByAlias::new(
                iroha_data_model::account::AccountAlias::domainless(
                    "private".parse().expect("alias label"),
                    restricted_dataspace,
                ),
            )
            .into(),
        ),
    ] {
        let request = request_for_test(&authority, query);
        let scope = super::signed_query_scope_for_app(app.as_ref(), &request);
        assert!(
            super::torii_authorized_signed_query_routes(app.as_ref(), &request, &scope).is_err(),
            "account permission must not authorize history or alias reads"
        );
    }
    let next_height = app
        .state
        .latest_block_header_fast()
        .map_or(1, |header| header.height().get() + 1);
    let mut block = app.state.block(BlockHeader::new(
        NonZeroU64::new(next_height).expect("height"),
        None,
        None,
        0,
        0,
    ));
    let mut tx = block.transaction();
    assert!(
        tx.world_mut_for_testing()
            .remove_account_permission(&authority, &permission)
    );
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit exact account read revocation");
    for request in &requests {
        let scope = super::signed_query_scope_for_app(app.as_ref(), request);
        assert!(
            super::torii_authorized_signed_query_routes(app.as_ref(), request, &scope).is_err(),
            "a retained signed query must not keep revoked account access"
        );
    }
}
#[tokio::test]
async fn signed_alias_query_requires_exact_alias_permission_not_broad_read_access() {
    let authority = checked_torii_test_account_id(0xfa, "derive alias query authority fixture key");
    let restricted_dataspace = DataSpaceId::new(10);
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account(&authority),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    configure_private_ingress_routes_for_test(&mut app);
    let alias = iroha_data_model::account::AccountAlias::domainless(
        "recipient".parse().expect("alias label"),
        restricted_dataspace,
    );
    let request = request_for_test(
        &authority,
        iroha_data_model::query::QueryRequest::Singular(
            iroha_data_model::query::account::prelude::FindAccountByAlias::new(alias.clone())
                .into(),
        ),
    );
    let scope = super::signed_query_scope_for_app(app.as_ref(), &request);
    let response = super::torii_authorized_signed_query_routes(app.as_ref(), &request, &scope)
        .expect_err("an alias query without its exact permission must fail closed");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    grant_account_permission_for_test(
        &app,
        &authority,
        CanReadRestrictedDataspace {
            dataspace: restricted_dataspace,
        }
        .into(),
    );
    super::torii_authorized_signed_query_routes(app.as_ref(), &request, &scope)
        .expect_err("broad restricted-data read access must not substitute for alias access");
    grant_account_permission_for_test(
        &app,
        &authority,
        CanResolveAccountAlias {
            scope: AccountAliasPermissionScope::Dataspace(restricted_dataspace),
        }
        .into(),
    );
    let routes = super::torii_authorized_signed_query_routes(app.as_ref(), &request, &scope)
        .expect("the exact alias permission should authorize its route");
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].dataspace_id, restricted_dataspace);
}
#[tokio::test]
async fn signed_query_authorization_gates_global_history_and_replicated_inventories() {
    let authority = checked_torii_test_account_id(0xf4, "derive global-read authority fixture key");
    let restricted_dataspace = DataSpaceId::new(10);
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account(&authority),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    configure_private_ingress_routes_for_test(&mut app);
    let history = request_for_test(
        &authority,
        iroha_data_model::query::QueryRequest::Start(build_find_transactions_query_for_test()),
    );
    let triggers = request_for_test(
        &authority,
        iroha_data_model::query::QueryRequest::Start(build_find_triggers_query_for_test()),
    );
    for request in [&history, &triggers] {
        let scope = super::signed_query_scope_for_app(app.as_ref(), request);
        let response = super::torii_authorized_signed_query_routes(app.as_ref(), request, &scope)
            .expect_err("global restricted reads must fail without exact grants");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    grant_account_permission_for_test(
        &app,
        &authority,
        CanReadRestrictedDataspace {
            dataspace: restricted_dataspace,
        }
        .into(),
    );
    for request in [&history, &triggers] {
        let scope = super::signed_query_scope_for_app(app.as_ref(), request);
        super::torii_authorized_signed_query_routes(app.as_ref(), request, &scope)
            .expect("an exact grant for every restricted route should allow a global read");
    }
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn torii_target_scope_routes_resolve_alias_and_domain_dataspaces() {
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        iroha_core::state::World::default(),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    let (_restricted_lane, restricted_dataspace) =
        configure_private_ingress_routes_for_test(&mut app);
    let alias = iroha_data_model::account::AccountAlias::domainless(
        "banking".parse().expect("alias label"),
        restricted_dataspace,
    );
    let alias_routes =
        super::torii_target_alias_routes(app.as_ref(), &alias).expect("alias routes");
    assert_eq!(alias_routes.len(), 1);
    assert_eq!(alias_routes[0].dataspace_id, restricted_dataspace);
    let domain_id =
        iroha_model_base::domain::DomainId::try_new("hbl", "restricted").expect("domain id");
    let domain_routes =
        super::torii_target_domain_routes(app.as_ref(), &domain_id).expect("domain routes");
    assert_eq!(domain_routes.len(), 1);
    assert_eq!(domain_routes[0].dataspace_id, restricted_dataspace);
}
#[cfg(feature = "app_api")]
#[derive(Clone, Copy)]
enum AccountRouteMatrixCase {
    AccountSigned,
    AccountUnsigned,
    AccountAssets,
    PermissionsSigned,
    PermissionsUnsigned,
    TargetUnknown,
    NexusTargetUnknown,
}
#[cfg(feature = "app_api")]
fn run_account_route_matrix_case(case: AccountRouteMatrixCase) {
    let (authority_seed, authority_context) = match case {
        AccountRouteMatrixCase::AccountSigned => (
            0xea,
            "derive target-account read routing authority fixture key",
        ),
        AccountRouteMatrixCase::AccountUnsigned => (
            0xeb,
            "derive public account read routing authority fixture key",
        ),
        AccountRouteMatrixCase::AccountAssets => {
            (0xec, "derive account asset fanout authority fixture key")
        }
        AccountRouteMatrixCase::PermissionsSigned => (
            0xee,
            "derive signed account permissions fanout authority fixture key",
        ),
        AccountRouteMatrixCase::PermissionsUnsigned => (
            0xef,
            "derive public account permissions fanout authority fixture key",
        ),
        AccountRouteMatrixCase::TargetUnknown => (
            0xf0,
            "derive unknown target-account routes authority fixture key",
        ),
        AccountRouteMatrixCase::NexusTargetUnknown => (
            0xf1,
            "derive Nexus target-account fanout authority fixture key",
        ),
    };
    let authority = checked_torii_test_account_id(authority_seed, authority_context);
    let governance_dataspace = DataSpaceId::new(1);
    let restricted_dataspace = DataSpaceId::new(10);
    let mut app = match case {
        AccountRouteMatrixCase::AccountSigned => {
            crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
                world_with_account_bound_to_dataspace(
                    &authority,
                    UniversalAccountId::from_hash(Hash::new(b"torii::target-account-routes")),
                    restricted_dataspace,
                ),
                crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
            )
        }
        AccountRouteMatrixCase::AccountUnsigned => {
            crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
                world_with_account_bound_to_dataspace(
                    &authority,
                    UniversalAccountId::from_hash(Hash::new(b"torii::public-account-routes")),
                    restricted_dataspace,
                ),
                crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
            )
        }
        AccountRouteMatrixCase::AccountAssets => {
            crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
                world_with_account(&authority),
                crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
            )
        }
        AccountRouteMatrixCase::PermissionsSigned => {
            crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
                world_with_account_bound_to_dataspace(
                    &authority,
                    UniversalAccountId::from_hash(Hash::new(b"torii::permissions-account-routes")),
                    restricted_dataspace,
                ),
                crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
            )
        }
        AccountRouteMatrixCase::PermissionsUnsigned => {
            crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
                world_with_account_bound_to_dataspace(
                    &authority,
                    UniversalAccountId::from_hash(Hash::new(
                        b"torii::permissions-public-account-routes",
                    )),
                    restricted_dataspace,
                ),
                crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
            )
        }
        AccountRouteMatrixCase::TargetUnknown | AccountRouteMatrixCase::NexusTargetUnknown => {
            crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
                iroha_core::state::World::default(),
                crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
            )
        }
    };
    let (_restricted_lane, configured_restricted_dataspace) =
        configure_private_ingress_routes_for_test(&mut app);
    assert_eq!(configured_restricted_dataspace, restricted_dataspace);
    let routes = match case {
        AccountRouteMatrixCase::AccountSigned => {
            super::torii_account_read_routes(app.as_ref(), &authority, None, true)
                .expect("target-account routes should resolve")
        }
        AccountRouteMatrixCase::AccountUnsigned => {
            super::torii_account_read_routes(app.as_ref(), &authority, None, false)
                .expect("public visibility routes should resolve")
        }
        AccountRouteMatrixCase::AccountAssets => {
            super::torii_account_assets_read_routes(app.as_ref(), &authority, None)
                .expect("public account-assets routes should resolve")
        }
        AccountRouteMatrixCase::PermissionsSigned => super::torii_account_permissions_read_routes(
            app.as_ref(),
            &authority,
            Some(&authority),
            true,
        )
        .expect("target-account permissions routes should resolve"),
        AccountRouteMatrixCase::PermissionsUnsigned => {
            super::torii_account_permissions_read_routes(app.as_ref(), &authority, None, false)
                .expect("public visibility routes should resolve")
        }
        AccountRouteMatrixCase::TargetUnknown => {
            super::torii_target_account_routes(app.as_ref(), &authority)
                .expect("unknown target-account scope should fall back to all configured routes")
        }
        AccountRouteMatrixCase::NexusTargetUnknown => super::torii_fanout_scope_routes(
            app.as_ref(),
            &ToriiFanoutRouteScopeV1::TargetAccount {
                account_id: authority.to_string(),
                caller_account_id: None,
            },
        )
        .expect("Nexus fanout target-account routes should resolve"),
    };
    let dataspaces = routes
        .into_iter()
        .map(|route| route.dataspace_id)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = match case {
        AccountRouteMatrixCase::AccountUnsigned
        | AccountRouteMatrixCase::AccountAssets
        | AccountRouteMatrixCase::PermissionsUnsigned => {
            std::collections::BTreeSet::from([DataSpaceId::UNIVERSAL, governance_dataspace])
        }
        _ => std::collections::BTreeSet::from([
            DataSpaceId::UNIVERSAL,
            governance_dataspace,
            restricted_dataspace,
        ]),
    };
    let diagnostic = match case {
        AccountRouteMatrixCase::AccountSigned => {
            "signed/internal account reads should fan out across the target account scope plus public dataspaces"
        }
        AccountRouteMatrixCase::AccountUnsigned => {
            "unsigned public reads should stay on caller/public visibility routes"
        }
        AccountRouteMatrixCase::AccountAssets => {
            "unsigned account asset reads must stay on public visibility routes"
        }
        AccountRouteMatrixCase::PermissionsSigned => {
            "signed/internal permissions reads must fan out across all configured dataspaces to include dataspace-scoped grants"
        }
        AccountRouteMatrixCase::PermissionsUnsigned => {
            "unsigned permissions reads should stay on caller/public visibility routes"
        }
        AccountRouteMatrixCase::TargetUnknown => {
            "target-account queries with unknown local scope should fan out across all configured dataspace routes"
        }
        AccountRouteMatrixCase::NexusTargetUnknown => {
            "Nexus must recompute unknown target-account fanout from its own dataspace catalog"
        }
    };
    assert_eq!(dataspaces, expected, "{diagnostic}");
    match case {
        AccountRouteMatrixCase::AccountSigned => assert!(
            dataspaces.contains(&governance_dataspace),
            "public dataspaces must remain visible in target-account routing",
        ),
        AccountRouteMatrixCase::AccountUnsigned => assert!(
            !dataspaces.contains(&restricted_dataspace),
            "unsigned public reads must not automatically gain private dataspace visibility",
        ),
        AccountRouteMatrixCase::PermissionsSigned => assert_eq!(
            super::torii_account_permissions_route_scope(&authority, Some(&authority), true),
            ToriiFanoutRouteScopeV1::TargetAccount {
                account_id: authority.to_string(),
                caller_account_id: Some(authority.to_string()),
            },
            "permissions fanout must retain the exact authenticated principal on every route",
        ),
        AccountRouteMatrixCase::PermissionsUnsigned => {
            assert!(
                !dataspaces.contains(&restricted_dataspace),
                "unsigned permissions reads must not automatically gain private dataspace visibility",
            );
            assert_eq!(
                super::torii_account_permissions_route_scope(&authority, None, false),
                ToriiFanoutRouteScopeV1::VisibleAccount {
                    caller_account_id: None
                }
            );
        }
        AccountRouteMatrixCase::AccountAssets
        | AccountRouteMatrixCase::TargetUnknown
        | AccountRouteMatrixCase::NexusTargetUnknown => {}
    }
}
#[cfg(feature = "app_api")]
#[test]
fn internal_fanout_account_scopes_reject_surrounding_whitespace() {
    let app = mk_app_state_for_tests();
    let account_id = checked_torii_test_account_id(
        0xf2,
        "derive padded internal fanout account scope fixture key",
    );
    for scope in [
        ToriiFanoutRouteScopeV1::TargetAccount {
            account_id: format!(" {account_id}"),
            caller_account_id: None,
        },
        ToriiFanoutRouteScopeV1::VisibleAccount {
            caller_account_id: Some(format!("{account_id} ")),
        },
    ] {
        let response = super::torii_fanout_scope_routes(app.as_ref(), &scope)
            .expect_err("padded internal fanout account scope must fail closed");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get("x-iroha-reject-code")
                .and_then(|value| value.to_str().ok()),
            Some("invalid_proxy_request")
        );
    }
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn torii_account_read_routes_use_target_account_scope_for_signed_and_internal_reads() {
    run_account_route_matrix_case(AccountRouteMatrixCase::AccountSigned);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn torii_account_read_routes_keep_unsigned_public_reads_on_visible_routes() {
    run_account_route_matrix_case(AccountRouteMatrixCase::AccountUnsigned);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn torii_account_assets_read_routes_keep_unsigned_reads_public() {
    run_account_route_matrix_case(AccountRouteMatrixCase::AccountAssets);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn signed_foreign_account_reads_do_not_gain_target_routes_without_a_grant() {
    let target = checked_torii_test_account_id(0xd8, "derive app-read target fixture key");
    let caller = checked_torii_test_account_id(0xd9, "derive app-read caller fixture key");
    let restricted_dataspace = DataSpaceId::new(10);
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_target_and_caller_bound_to_dataspace(
            &target,
            &caller,
            UniversalAccountId::from_hash(Hash::new(b"torii::app-read-target")),
            restricted_dataspace,
        ),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    configure_private_ingress_routes_for_test(&mut app);

    assert!(!super::torii_should_use_target_account_routes(
        app.as_ref(),
        &target,
        Some(&caller),
    ));
    let denied = super::torii_account_assets_read_routes(app.as_ref(), &target, Some(&caller))
        .expect_err("a foreign signed account-assets read must not report a false zero");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    grant_account_permission_for_test(
        &app,
        &caller,
        CanReadRestrictedDataspace {
            dataspace: restricted_dataspace,
        }
        .into(),
    );
    let granted = super::torii_account_assets_read_routes(app.as_ref(), &target, Some(&caller))
        .expect("granted visible routes");
    assert!(
        granted
            .iter()
            .any(|route| route.dataspace_id == restricted_dataspace)
    );
    assert!(super::torii_should_use_target_account_routes(
        app.as_ref(),
        &target,
        Some(&target),
    ));
    assert!(!super::torii_should_use_target_account_routes(
        app.as_ref(),
        &target,
        Some(&caller),
    ));
}

#[cfg(feature = "app_api")]
#[test]
fn delegated_account_assets_recheck_exact_grant_and_reject_sibling_and_scope_mismatch() {
    let target = checked_torii_test_account_id(0xa1, "delegated assets target");
    let sibling = checked_torii_test_account_id(0xa2, "delegated assets sibling");
    let caller = checked_torii_test_account_id(0xa3, "delegated assets caller");
    let uaid = UniversalAccountId::from_hash(Hash::new(b"delegated-account-assets-subject"));
    let sibling_uaid =
        UniversalAccountId::from_hash(Hash::new(b"delegated-account-assets-sibling"));
    assert_ne!(uaid, sibling_uaid);
    let restricted_dataspace = DataSpaceId::new(10);
    let domain =
        Domain::new(DomainId::try_new("wonderland", "universal").expect("domain")).build(&target);
    let mut world = World::with(
        [domain],
        [
            Account::new(target.clone())
                .with_uaid(Some(uaid))
                .build(&target),
            Account::new(sibling.clone())
                .with_uaid(Some(sibling_uaid))
                .build(&sibling),
            Account::new(caller.clone()).build(&caller),
        ],
        [],
    );
    bind_uaid_to_dataspace_manifest_for_test(&mut world, uaid, restricted_dataspace);
    bind_uaid_to_dataspace_manifest_for_test(&mut world, sibling_uaid, restricted_dataspace);
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world,
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    configure_private_ingress_routes_for_test(&mut app);
    assert_eq!(
        super::torii_account_assets_read_routes(app.as_ref(), &target, Some(&caller))
            .expect_err("ungranted private target must fail")
            .status(),
        StatusCode::FORBIDDEN,
    );
    let permission: Permission = iroha_executor_data_model::permission::query::CanReadAccountData {
        account: target.clone(),
    }
    .into();
    grant_account_permission_for_test(&app, &caller, permission.clone());
    let route = super::torii_account_assets_read_routes(app.as_ref(), &target, Some(&caller))
        .expect("exact grant opens target routes")
        .into_iter()
        .find(|route| route.dataspace_id == restricted_dataspace)
        .expect("target has private route");
    assert_eq!(
        super::torii_account_assets_read_routes(app.as_ref(), &sibling, Some(&caller))
            .expect_err("same-dataspace sibling requires its own grant")
            .status(),
        StatusCode::FORBIDDEN,
    );
    let scope = ToriiFanoutRouteScopeV1::TargetAccount {
        account_id: target.to_string(),
        caller_account_id: Some(caller.to_string()),
    };
    let visibility = super::torii_account_assets_route_visibility(
        app.as_ref(),
        &scope,
        &target.to_string(),
        route,
    )
    .expect("producer rechecks exact target grant");
    let world = app.state.world_view();
    assert!(visibility.allows_account(&world, &target));
    assert!(!visibility.allows_account(&world, &sibling));
    assert_eq!(
        super::torii_account_assets_route_visibility(
            app.as_ref(),
            &scope,
            &sibling.to_string(),
            route,
        )
        .expect_err("proxy path must match authenticated target scope")
        .status(),
        StatusCode::BAD_REQUEST,
    );
    drop(world);
    let next_height = app
        .state
        .latest_block_header_fast()
        .map_or(1, |header| header.height().get().saturating_add(1));
    let mut block = app.state.block(BlockHeader::new(
        NonZeroU64::new(next_height).expect("non-zero height"),
        None,
        None,
        0,
        0,
    ));
    let mut tx = block.transaction();
    assert!(
        tx.world_mut_for_testing()
            .remove_account_permission(&caller, &permission)
    );
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit revocation");
    assert_eq!(
        super::torii_account_assets_route_visibility(
            app.as_ref(),
            &scope,
            &target.to_string(),
            route,
        )
        .expect_err("retained routed request must fail after revocation")
        .status(),
        StatusCode::FORBIDDEN,
    );
}

#[cfg(feature = "app_api")]
#[test]
fn delegated_account_assets_role_grant_is_rechecked_after_role_revocation() {
    let target = checked_torii_test_account_id(0xa4, "role asset-read target");
    let caller = checked_torii_test_account_id(0xa5, "role asset-read caller");
    let uaid = UniversalAccountId::from_hash(Hash::new(b"delegated-role-assets-subject"));
    let restricted_dataspace = DataSpaceId::new(10);
    let role_id: iroha_data_model::role::RoleId = "delegated_asset_reader".parse().expect("role");
    let permission: Permission = iroha_executor_data_model::permission::query::CanReadAccountData {
        account: target.clone(),
    }
    .into();
    let role = iroha_data_model::role::Role::new(role_id.clone(), caller.clone())
        .add_permission(permission)
        .build(&caller);
    let domain =
        Domain::new(DomainId::try_new("wonderland", "universal").expect("domain")).build(&target);
    let mut world = World::with_assets_and_roles(
        [domain],
        [
            Account::new(target.clone())
                .with_uaid(Some(uaid))
                .build(&target),
            Account::new(caller.clone()).build(&caller),
        ],
        [],
        [],
        [],
        [role],
    );
    bind_uaid_to_dataspace_manifest_for_test(&mut world, uaid, restricted_dataspace);
    world.grant_role_for_tests(caller.clone(), role_id);
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world,
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    configure_private_ingress_routes_for_test(&mut app);
    let route = super::torii_account_assets_read_routes(app.as_ref(), &target, Some(&caller))
        .expect("effective role permission opens the exact target")
        .into_iter()
        .find(|route| route.dataspace_id == restricted_dataspace)
        .expect("private route");
    let scope = ToriiFanoutRouteScopeV1::TargetAccount {
        account_id: target.to_string(),
        caller_account_id: Some(caller.clone().to_string()),
    };
    super::torii_account_assets_route_visibility(app.as_ref(), &scope, &target.to_string(), route)
        .expect("producer accepts current role grant");
    let next_height = app
        .state
        .latest_block_header_fast()
        .map_or(1, |header| header.height().get().saturating_add(1));
    let mut block = app.state.block(BlockHeader::new(
        NonZeroU64::new(next_height).expect("non-zero height"),
        None,
        None,
        0,
        0,
    ));
    let mut tx = block.transaction();
    tx.world_mut_for_testing().remove_account_roles(&caller);
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit role revocation");
    assert_eq!(
        super::torii_account_assets_route_visibility(
            app.as_ref(),
            &scope,
            &target.to_string(),
            route,
        )
        .expect_err("producer rejects revoked effective role permission")
        .status(),
        StatusCode::FORBIDDEN,
    );
}

#[cfg(feature = "app_api")]
#[tokio::test]
async fn can_read_all_ledger_data_expands_every_dataspace_read_route() {
    let caller = checked_torii_test_account_id(0xda, "derive global reader fixture key");
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account(&caller),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    let (_, restricted_dataspace) = configure_private_ingress_routes_for_test(&mut app);

    let public_only = super::torii_visible_account_read_routes(app.as_ref(), Some(&caller));
    assert!(
        public_only
            .iter()
            .all(|route| route.dataspace_id != restricted_dataspace)
    );

    grant_account_permission_for_test(&app, &caller, CanReadAllLedgerData.into());
    let all_routes = super::torii_visible_account_read_routes(app.as_ref(), Some(&caller));
    assert!(
        all_routes
            .iter()
            .any(|route| route.dataspace_id == restricted_dataspace)
    );
    assert!(super::torii_dataspace_read_visibility(app.as_ref(), Some(&caller)).can_read_all());
}

#[cfg(feature = "app_api")]
#[test]
fn long_lived_dataspace_context_rechecks_permission_revocation() {
    let caller = checked_torii_test_account_id(0xdb, "derive revocable stream reader fixture key");
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account(&caller),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    let (_, restricted_dataspace) = configure_private_ingress_routes_for_test(&mut app);
    let permission: Permission = CanReadRestrictedDataspace {
        dataspace: restricted_dataspace,
    }
    .into();
    grant_account_permission_for_test(&app, &caller, permission.clone());
    let context = super::ToriiAccountReadVisibility::Signed(caller.clone())
        .into_dataspace_context(app.clone());

    assert!(
        context
            .current_visibility()
            .allows_dataspace(restricted_dataspace)
    );
    assert!(context.authorization_is_current());

    let next_height = app
        .state
        .latest_block_header_fast()
        .map_or(1, |header| header.height().get().saturating_add(1));
    let header = BlockHeader::new(
        NonZeroU64::new(next_height).expect("non-zero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = app.state.block(header);
    let mut tx = block.transaction();
    assert!(
        tx.world_mut_for_testing()
            .remove_account_permission(&caller, &permission),
        "seeded permission must be removed"
    );
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit permission revocation");

    assert!(
        !context
            .current_visibility()
            .allows_dataspace(restricted_dataspace),
        "an established stream/read context must not retain a revoked grant"
    );
    assert!(
        !context.authorization_is_current(),
        "a long-lived stream must terminate after losing any admitted route"
    );
}

#[cfg(feature = "app_api")]
#[tokio::test]
async fn handler_account_assets_reports_selected_route_and_keeps_restricted_rows_private() {
    let authority = checked_torii_test_account_id(
        0xed,
        "derive account asset collection authority fixture key",
    );
    let missing =
        checked_torii_test_account_id(0xee, "derive missing account asset collection fixture key");
    let restricted_dataspace = DataSpaceId::new(10);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::assets-known-scope"));
    let app = native_ingress_app_with_world_and_nexus_for_test(
        world_with_account_bound_to_dataspace(&authority, uaid, restricted_dataspace),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    assert_initial_nexus_catalog_for_test(&app.state, &private_ingress_nexus_for_test());
    assert!(
        super::torii_all_dataspace_routes(app.as_ref())
            .iter()
            .any(|route| route.dataspace_id == restricted_dataspace)
    );
    let routes = super::torii_visible_account_read_routes(app.as_ref(), None);
    assert!(
        routes.len() > 1,
        "the collection scope has multiple public routes"
    );
    let selected = super::collection_execution_route(app.as_ref(), &routes)
        .expect("one visible collection execution route");
    assert!(routes.contains(&selected));
    assert!(super::should_execute_route_locally(app.as_ref(), selected));
    let uri: axum::http::Uri = format!("/v1/accounts/{authority}/assets")
        .parse()
        .expect("valid account assets uri");
    let response = super::handler_account_assets(
        State(app.clone()),
        axum::http::Method::GET,
        uri,
        HeaderMap::new(),
        crate::loopback_connect_info(),
        AxPath(authority.to_string()),
    )
    .await
    .expect("account assets should execute")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        torii_response_header(&response, "x-iroha-routed-by"),
        Some("local")
    );
    assert_eq!(
        torii_response_header(&response, "x-iroha-route-lane-id"),
        Some(selected.lane_id.to_string().as_str()),
        "the one chosen route identifies where the complete collection executed",
    );
    assert_eq!(
        torii_response_header(&response, "x-iroha-route-dataspace-id"),
        Some(selected.dataspace_id.to_string().as_str()),
    );
    assert!(
        response
            .headers()
            .get("x-iroha-fanout-routes-attempted")
            .is_none(),
        "one complete-visibility query must not claim per-dataspace scans",
    );
    let restricted_json =
        decode_torii_json(response, "restricted account assets", "account assets json").await;
    assert!(
        restricted_json["items"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );

    let missing_uri: axum::http::Uri = format!("/v1/accounts/{missing}/assets")
        .parse()
        .expect("valid missing account assets uri");
    let missing_response = super::handler_account_assets(
        State(app),
        axum::http::Method::GET,
        missing_uri,
        HeaderMap::new(),
        crate::loopback_connect_info(),
        AxPath(missing.to_string()),
    )
    .await
    .expect("missing account assets should preserve the empty public response")
    .into_response();
    assert_eq!(missing_response.status(), StatusCode::OK);
    let missing_json = decode_torii_json(
        missing_response,
        "missing account assets",
        "account assets json",
    )
    .await;
    assert!(missing_json["items"].as_array().is_some_and(Vec::is_empty));
    assert_eq!(restricted_json["total"], missing_json["total"]);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn torii_account_permissions_read_routes_fan_out_across_all_dataspaces_for_signed_and_internal_reads()
 {
    run_account_route_matrix_case(AccountRouteMatrixCase::PermissionsSigned);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn fanout_routed_by_uses_attempted_routes_even_when_only_local_payloads_survive() {
    let (app, local_route, stale_route) =
        native_account_read_with_stale_route_for_test(World::default());
    assert_eq!(super::routed_by_for_routes(&app, &[local_route]), "local");
    assert_eq!(
        super::routed_by_for_routes(&app, &[local_route, stale_route]),
        "proxy",
        "fanout responses must report proxy routing when any attempted route is non-local"
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn torii_account_permissions_read_routes_keep_unsigned_public_reads_visible() {
    run_account_route_matrix_case(AccountRouteMatrixCase::PermissionsUnsigned);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn torii_target_account_routes_fan_out_when_local_scope_is_unknown() {
    run_account_route_matrix_case(AccountRouteMatrixCase::TargetUnknown);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn nexus_fanout_recomputes_unknown_target_account_routes_from_catalog() {
    run_account_route_matrix_case(AccountRouteMatrixCase::NexusTargetUnknown);
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[test]
fn nexus_fanout_proxy_variants_use_route_budget() {
    let query_request = ToriiProxyRequestKindV1::SignedQueryFanout {
        query_bytes: Vec::new(),
        response_format: ToriiProxyResponseFormatV1::Norito,
    };
    assert_eq!(
        super::torii_proxy_attempt_timeout(&query_request),
        DEFAULT_ROUTE_TIMEOUT + Duration::from_secs(5)
    );
    assert_eq!(
        super::torii_proxy_request_kind_name(&query_request),
        "signed_query_fanout"
    );
    let read_request = ToriiProxyRequestKindV1::ReadFanout(super::torii_read_fanout_request(
        ToriiReadEndpointV1::AccountGet,
        ToriiFanoutRouteScopeV1::AllDataspaces,
        ToriiReadFanoutMergeV1::Account,
        vec![
            checked_torii_test_account_id(0xf2, "derive read fanout proxy account fixture key")
                .to_string(),
        ],
        None,
        Vec::new(),
        ToriiProxyResponseFormatV1::Json,
    ));
    assert_eq!(
        super::torii_proxy_attempt_timeout(&read_request),
        DEFAULT_ROUTE_TIMEOUT + Duration::from_secs(5)
    );
    assert_eq!(
        super::torii_proxy_request_kind_name(&read_request),
        "read_fanout"
    );
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[test]
fn http_route_timeout_covers_read_fanout_proxy_budget() {
    let fanout_budget = super::torii_proxy_attempt_timeout(&ToriiProxyRequestKindV1::ReadFanout(
        super::torii_read_fanout_request(
            ToriiReadEndpointV1::AccountPermissionsGet,
            ToriiFanoutRouteScopeV1::AllDataspaces,
            ToriiReadFanoutMergeV1::List,
            vec![
                checked_torii_test_account_id(
                    0xf3,
                    "derive read fanout HTTP budget account fixture key",
                )
                .to_string(),
            ],
            None,
            Vec::new(),
            ToriiProxyResponseFormatV1::Json,
        ),
    ));
    assert!(
        super::route_timeout_for_path("/v1/accounts/example/permissions") >= fanout_budget,
        "outer HTTP timeout must not expire before the read-fanout proxy budget"
    );
}
#[cfg(all(feature = "app_api", feature = "connect"))]
#[test]
fn client_default_timeout_covers_nexus_fanout_http_budget() {
    let fanout_http_budget = super::route_timeout_for_path("/v1/accounts/example/permissions");
    assert!(
        iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT >= fanout_http_budget,
        "client default timeout {:?} must cover routed fanout HTTP budget {:?}",
        iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT,
        fanout_http_budget,
    );
}
#[tokio::test]
async fn handler_signed_query_executes_find_triggers_locally_with_multiple_dataspaces() {
    let key_pair =
        checked_torii_test_ed25519_keypair(0xf4, "derive find triggers authority fixture key");
    let authority = AccountId::new(key_pair.public_key().clone());
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account(&authority),
        crate::tests_runtime_handlers::multiple_dataspace_nexus_for_test(),
    );
    configure_multiple_dataspace_routes_for_test(&mut app);
    assert!(
        super::torii_all_dataspace_routes(app.as_ref()).len() > 1,
        "test requires multiple dataspace routes"
    );
    let denied = super::handler_signed_query(
        State(app.clone()),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        None,
        crate::NoritoQuery(QueryOptions::default()),
        versioned_query_for_test(signed_find_triggers_query_for_test(
            authority.clone(),
            &key_pair,
        )),
    )
    .await;
    assert!(
        matches!(denied, Err(Error::Query(ValidationFail::NotPermitted(message)))
        if message.contains("CanReadAllLedgerData"))
    );
    grant_account_permission_for_test(&app, &authority, CanReadAllLedgerData.into());
    let response = super::handler_signed_query(
        State(app),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        None,
        crate::NoritoQuery(QueryOptions::default()),
        versioned_query_for_test(signed_find_triggers_query_for_test(authority, &key_pair)),
    )
    .await
    .expect("find triggers query should execute")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get("x-iroha-routed-by").is_none(),
        "local trigger queries should not fan out"
    );
    assert!(
        response.headers().get("x-iroha-route-lane-id").is_none(),
        "local trigger queries should not publish a routed lane"
    );
}
#[tokio::test]
async fn handler_signed_query_executes_find_active_trigger_ids_locally_with_multiple_dataspaces() {
    let key_pair = checked_torii_test_ed25519_keypair(
        0xf5,
        "derive find active trigger ids authority fixture key",
    );
    let authority = AccountId::new(key_pair.public_key().clone());
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account(&authority),
        crate::tests_runtime_handlers::multiple_dataspace_nexus_for_test(),
    );
    configure_multiple_dataspace_routes_for_test(&mut app);
    assert!(
        super::torii_all_dataspace_routes(app.as_ref()).len() > 1,
        "test requires multiple dataspace routes"
    );
    let denied = super::handler_signed_query(
        State(app.clone()),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        None,
        crate::NoritoQuery(QueryOptions::default()),
        versioned_query_for_test(signed_find_active_trigger_ids_query_for_test(
            authority.clone(),
            &key_pair,
        )),
    )
    .await;
    assert!(
        matches!(denied, Err(Error::Query(ValidationFail::NotPermitted(message)))
        if message.contains("CanReadAllLedgerData"))
    );
    grant_account_permission_for_test(&app, &authority, CanReadAllLedgerData.into());
    let response = super::handler_signed_query(
        State(app),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        None,
        crate::NoritoQuery(QueryOptions::default()),
        versioned_query_for_test(signed_find_active_trigger_ids_query_for_test(
            authority, &key_pair,
        )),
    )
    .await
    .expect("find active trigger ids query should execute")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get("x-iroha-routed-by").is_none(),
        "local trigger queries should not fan out"
    );
    assert!(
        response
            .headers()
            .get("x-iroha-route-dataspace-id")
            .is_none(),
        "local trigger queries should not publish a routed dataspace"
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn anonymous_accounts_list_excludes_restricted_private_ingress_route() {
    let restricted =
        checked_torii_test_account_id(0xfd, "derive restricted account list fixture key");
    let public = checked_torii_test_account_id(0xfe, "derive public account list fixture key");
    let restricted_dataspace = DataSpaceId::new(10);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::anonymous-account-list"));
    let app = native_ingress_app_with_world_and_nexus_for_test(
        world_with_target_and_caller_bound_to_dataspace(
            &restricted,
            &public,
            uaid,
            restricted_dataspace,
        ),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    let routes = super::torii_visible_account_read_routes(app.as_ref(), None);
    assert_eq!(
        routes
            .iter()
            .map(|route| route.dataspace_id)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([DataSpaceId::UNIVERSAL, DataSpaceId::new(1)]),
        "anonymous account listings must omit the configured restricted route",
    );
    assert!(
        super::torii_all_dataspace_routes(app.as_ref())
            .iter()
            .any(|route| route.dataspace_id == restricted_dataspace),
        "the negative fixture must contain the restricted route",
    );
    let selected = super::collection_execution_route(app.as_ref(), &routes)
        .expect("one visible collection execution route");
    assert!(routes.contains(&selected));
    assert!(super::should_execute_route_locally(app.as_ref(), selected));
    let response = super::handler_accounts_list(
        State(app),
        axum::http::Method::GET,
        "/v1/accounts".parse().expect("valid accounts list uri"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
    )
    .await
    .expect("accounts list should execute")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        torii_response_header(&response, "x-iroha-routed-by"),
        Some("local"),
        "visible account listings should still execute locally",
    );
    // A collection executes once on one route under the complete caller scope;
    // its response does not claim the old per-dataspace fanout scan.
    assert!(
        response
            .headers()
            .get("x-iroha-fanout-routes-attempted")
            .is_none(),
    );
    let json = decode_torii_json(response, "anonymous account list", "account list JSON").await;
    let items = json["items"].as_array().expect("account items");
    let public_id = public.to_string();
    let restricted_id = restricted.to_string();
    assert!(
        items
            .iter()
            .any(|item| item["id"].as_str() == Some(public_id.as_str())),
        "one visible local execution must return the public account",
    );
    assert!(
        items
            .iter()
            .all(|item| item["id"].as_str() != Some(restricted_id.as_str())),
        "the same global World must not expose the restricted account's row",
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn handler_account_assets_selects_one_route_for_complete_visible_collection() {
    let authority = checked_torii_test_account_id(
        0xf6,
        "derive visible account assets collection authority fixture key",
    );
    let app = native_ingress_app_with_world_and_nexus_for_test(
        world_with_account(&authority),
        crate::tests_runtime_handlers::multiple_dataspace_nexus_for_test(),
    );
    let routes = super::torii_visible_account_read_routes(app.as_ref(), None);
    assert!(
        routes.len() > 1,
        "the collection scope has multiple public routes"
    );
    let selected = super::collection_execution_route(app.as_ref(), &routes)
        .expect("one visible collection execution route");
    assert!(routes.contains(&selected));
    assert!(super::should_execute_route_locally(app.as_ref(), selected));
    let uri: axum::http::Uri = format!("/v1/accounts/{authority}/assets")
        .parse()
        .expect("valid account assets uri");
    let response = super::handler_account_assets(
        State(app),
        axum::http::Method::GET,
        uri,
        HeaderMap::new(),
        crate::loopback_connect_info(),
        AxPath(authority.to_string()),
    )
    .await
    .expect("account assets should execute")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        torii_response_header(&response, "x-iroha-routed-by"),
        Some("local"),
        "account asset reads should still execute locally in unit tests",
    );
    assert_eq!(
        torii_response_header(&response, "x-iroha-route-lane-id"),
        Some(selected.lane_id.to_string().as_str()),
        "the one chosen route identifies where the complete collection executed",
    );
    assert_eq!(
        torii_response_header(&response, "x-iroha-route-dataspace-id"),
        Some(selected.dataspace_id.to_string().as_str()),
    );
    assert!(
        response
            .headers()
            .get("x-iroha-fanout-routes-attempted")
            .is_none(),
        "one complete-visibility query must not claim per-dataspace scans",
    );
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn handler_transactions_query_executes_once_on_selected_visible_route() {
    let app = native_ingress_app_with_world_and_nexus_for_test(
        iroha_core::state::World::default(),
        crate::tests_runtime_handlers::multiple_dataspace_nexus_for_test(),
    );
    assert!(
        super::torii_all_dataspace_routes(app.as_ref()).len() > 1,
        "test requires multiple dataspace routes"
    );
    let routes = super::torii_visible_account_read_routes(app.as_ref(), None);
    assert!(
        routes.len() > 1,
        "the transaction scope has multiple public routes"
    );
    let selected = super::collection_execution_route(app.as_ref(), &routes)
        .expect("one visible transaction execution route");
    assert!(super::should_execute_route_locally(app.as_ref(), selected));
    let response = super::handler_transactions_query(
        State(app),
        Extension(super::ToriiAccountReadVisibility::None),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        crate::JsonOnly(norito::json!({ "limit": 10 })),
    )
    .await
    .expect("transactions query should execute")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        torii_response_header(&response, "x-iroha-routed-by"),
        Some("local")
    );
    assert_eq!(
        torii_response_header(&response, "x-iroha-route-lane-id"),
        Some(selected.lane_id.to_string().as_str()),
        "the one chosen route identifies where the complete collection executed",
    );
    assert_eq!(
        torii_response_header(&response, "x-iroha-route-dataspace-id"),
        Some(selected.dataspace_id.to_string().as_str()),
    );
    assert!(
        response
            .headers()
            .get("x-iroha-fanout-routes-attempted")
            .is_none(),
        "one complete-visibility query must not claim per-dataspace scans",
    );
    let json = decode_torii_json(response, "transaction collection", "transaction page JSON").await;
    assert!(
        json["items"]
            .as_array()
            .is_some_and(|items| items.len() <= 10)
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn public_dataspace_upstream_cannot_replace_authoritative_account_assets() {
    let captured = Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
    let captured_for_route = Arc::clone(&captured);
    let upstream = Router::new().route(
            "/v1/accounts/{account_id}/assets",
            get(
                move |axum::extract::Path(account_id): axum::extract::Path<String>,
                      uri: Uri| {
                    let captured = Arc::clone(&captured_for_route);
                    async move {
                        captured
                            .lock()
                            .expect("capture lock")
                            .push((account_id, uri.query().unwrap_or_default().to_owned()));
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(axum::http::header::CONTENT_TYPE, "application/json")
                            .body(Body::from(
                                br#"{"items":[{"asset":"xor#universal","quantity":"74.7664","scope":"global"}],"total":1}"#
                                    .to_vec(),
                            ))
                            .expect("upstream response")
                    }
                },
            ),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let addr = listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, upstream.into_make_service())
            .await
            .expect("serve upstream");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let authority = checked_torii_test_account_id(0xf7, "protected account asset authority");
    let mut app = native_ingress_app_with_world_for_test(world_with_account(&authority));
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .public_dataspace_upstreams = Arc::new(BTreeMap::from([(
        DataSpaceId::UNIVERSAL,
        format!("http://{addr}"),
    )]));
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let account_id = authority.to_string();
    let request = torii_read_request(
        ToriiReadEndpointV1::AccountAssetsGet,
        ToriiFanoutRouteScopeV1::VisibleAccount {
            caller_account_id: None,
        },
        route,
        vec![account_id.clone()],
        Some("limit=500".to_owned()),
        Vec::new(),
    );
    let response = execute_torii_read_for_route(&app, route, request, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        torii_response_header(&response, "x-iroha-routed-by"),
        Some("local"),
    );
    let body = torii_body_bytes(response, "body").await;
    let json: Value = norito::json::from_slice(&body).expect("json response");
    assert!(
        json["items"]
            .as_array()
            .expect("local asset rows")
            .is_empty()
    );
    assert!(
        captured.lock().expect("capture lock").is_empty(),
        "a protected account asset read never contacts the unauthenticated upstream"
    );
    upstream_task.abort();
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn public_dataspace_upstream_preserves_valid_reject_classification() {
    let upstream = Router::new().route(
        "/v1/accounts/{account_id}/assets",
        get(|| async {
            Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("x-iroha-reject-code", "route_unavailable")
                .body(Body::from("temporarily unavailable"))
                .expect("upstream response")
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let addr = listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, upstream.into_make_service())
            .await
            .expect("serve upstream");
    });
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let request = torii_read_request(
        ToriiReadEndpointV1::AccountAssetsGet,
        ToriiFanoutRouteScopeV1::AllDataspaces,
        route,
        vec![
            checked_torii_test_account_id(
                0xf6,
                "derive rejected public upstream account fixture key",
            )
            .to_string(),
        ],
        None,
        Vec::new(),
    );
    let response = execute_torii_read_via_public_dataspace_upstream(
        format!("http://{addr}"),
        route,
        request,
        1_024,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("route_unavailable")
    );
    upstream_task.abort();
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn public_dataspace_upstream_drops_ambiguous_reject_classification() {
    let upstream = Router::new().route(
        "/v1/accounts/{account_id}/assets",
        get(|| async {
            Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("x-iroha-reject-code", "route_unavailable")
                .header("x-iroha-reject-code", "query_failed")
                .body(Body::from("temporarily unavailable"))
                .expect("upstream response")
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let addr = listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, upstream.into_make_service())
            .await
            .expect("serve upstream");
    });
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let request = torii_read_request(
        ToriiReadEndpointV1::AccountAssetsGet,
        ToriiFanoutRouteScopeV1::AllDataspaces,
        route,
        vec![
            checked_torii_test_account_id(
                0xf7,
                "derive ambiguous public upstream account fixture key",
            )
            .to_string(),
        ],
        None,
        Vec::new(),
    );
    let response = execute_torii_read_via_public_dataspace_upstream(
        format!("http://{addr}"),
        route,
        request,
        1_024,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("x-iroha-reject-code"));
    upstream_task.abort();
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn public_dataspace_upstream_drops_reject_classification_on_success() {
    let upstream = Router::new().route(
        "/v1/accounts/{account_id}/assets",
        get(|| async {
            Response::builder()
                .status(StatusCode::OK)
                .header("x-iroha-reject-code", "route_unavailable")
                .body(Body::from("success"))
                .expect("upstream response")
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let addr = listener.local_addr().expect("upstream addr");
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, upstream.into_make_service())
            .await
            .expect("serve upstream");
    });
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let request = torii_read_request(
        ToriiReadEndpointV1::AccountAssetsGet,
        ToriiFanoutRouteScopeV1::AllDataspaces,
        route,
        vec![
            checked_torii_test_account_id(
                0xf5,
                "derive successful public upstream account fixture key",
            )
            .to_string(),
        ],
        None,
        Vec::new(),
    );
    let response = execute_torii_read_via_public_dataspace_upstream(
        format!("http://{addr}"),
        route,
        request,
        1_024,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key("x-iroha-reject-code"));
    upstream_task.abort();
}
#[tokio::test]
#[cfg(feature = "app_api")]
async fn handler_account_get_fan_outs_across_global_dataspaces() {
    let authority = checked_torii_test_account_id(
        0xf8,
        "derive global account get fanout authority fixture key",
    );
    let app = native_ingress_app_with_world_and_nexus_for_test(
        world_with_account(&authority),
        crate::tests_runtime_handlers::multiple_dataspace_nexus_for_test(),
    );
    let uri: axum::http::Uri = format!("/v1/accounts/{authority}")
        .parse()
        .expect("valid account uri");
    let response = super::handler_account_get(
        State(app),
        axum::http::Method::GET,
        uri,
        HeaderMap::new(),
        crate::loopback_connect_info(),
        None,
        AxPath(authority.to_string()),
    )
    .await
    .expect("account get should execute");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        torii_response_header(&response, "x-iroha-routed-by"),
        Some("local"),
        "global account reads should still execute locally in unit tests",
    );
    assert!(
        response.headers().get("x-iroha-route-lane-id").is_none(),
        "global account fanout should not expose a singular route lane",
    );
    assert!(
        response
            .headers()
            .get("x-iroha-route-dataspace-id")
            .is_none(),
        "global account fanout should not expose a singular dataspace",
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn routing_space_directory_manifests_reports_inactive_pending_and_uncataloged_expired_rows() {
    let authority = checked_torii_test_account_id(
        0xf9,
        "derive space directory manifest authority fixture key",
    );
    let uaid =
        UniversalAccountId::from_hash(Hash::new(b"torii::space-directory-manifest-inactive"));
    let pending_dataspace = DataSpaceId::new(10);
    let expired_dataspace = DataSpaceId::new(11);
    let world = world_with_account(&authority);
    let mut bindings = iroha_core::nexus::space_directory::UaidDataspaceBindings::default();
    bindings.bind_account(pending_dataspace, authority.clone());
    let pending_manifest = iroha_data_model::nexus::AssetPermissionManifest {
        version: iroha_data_model::nexus::ManifestVersion::V1,
        uaid,
        dataspace: pending_dataspace,
        issued_ms: 1_710_000_000_000,
        activation_epoch: 10,
        expiry_epoch: None,
        entries: Vec::new(),
    };
    let pending_record =
        iroha_core::nexus::space_directory::SpaceDirectoryManifestRecord::new(pending_manifest);
    let expired_manifest = iroha_data_model::nexus::AssetPermissionManifest {
        version: iroha_data_model::nexus::ManifestVersion::V1,
        uaid,
        dataspace: expired_dataspace,
        issued_ms: 1_710_000_000_100,
        activation_epoch: 20,
        expiry_epoch: Some(30),
        entries: Vec::new(),
    };
    let mut expired_record =
        iroha_core::nexus::space_directory::SpaceDirectoryManifestRecord::new(expired_manifest);
    expired_record.lifecycle.mark_activated(21);
    expired_record.lifecycle.mark_expired(31);
    let mut set = iroha_core::nexus::space_directory::SpaceDirectoryManifestSet::default();
    set.upsert(pending_record);
    set.upsert(expired_record);
    let mut app =
        mk_app_state_for_tests_with_world_and_nexus(world, private_ingress_nexus_for_test());
    assert_initial_nexus_catalog_for_test(&app.state, &private_ingress_nexus_for_test());
    // State startup rebuilds derived bindings from authoritative active manifests,
    // and runtime catalog installation prunes uncataloged manifests. Install this
    // projection fixture's archived rows and matching binding after both steps.
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique manifest fixture app");
        let state = Arc::get_mut(&mut app_mut.state).expect("unique manifest fixture state");
        state
            .world
            .space_directory_manifests_mut_for_testing()
            .insert(uaid, set);
        state
            .world
            .uaid_dataspaces_mut_for_testing()
            .insert(uaid, bindings);
    }
    {
        let view = app.state.view();
        let bindings = view
            .world()
            .uaid_dataspaces()
            .get(&uaid)
            .expect("archived fixture account binding");
        assert_eq!(bindings.iter().count(), 1);
        assert!(bindings.is_bound_to(pending_dataspace, &authority));
        assert!(!bindings.is_bound_to(expired_dataspace, &authority));
        let manifests = view
            .world()
            .space_directory_manifests()
            .get(&uaid)
            .expect("both archived fixture manifest rows");
        assert_eq!(manifests.iter().count(), 2);
        assert!(
            !manifests
                .get(&pending_dataspace)
                .expect("pending row")
                .is_active()
        );
        assert!(
            manifests
                .get(&expired_dataspace)
                .expect("expired row")
                .lifecycle
                .expired_epoch
                .is_some()
        );
        assert!(
            view.world()
                .dataspace_catalog()
                .by_id(expired_dataspace)
                .is_none(),
            "the expired archival row must remain genuinely uncataloged"
        );
    }
    let response = routing::handle_v1_space_directory_manifests(
        app.state.clone(),
        AxPath(uaid.to_string()),
        crate::NoritoQuery(
            iroha_torii_shared::list_query::ListQuery::from_json_value(norito::json!({
                "filter": "status != \"Active\"", "include_total": true,
            }))
            .expect("manifest collection query"),
        ),
        app.telemetry.clone(),
    )
    .await
    .expect("inactive manifest read should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let json =
        decode_torii_json(response, "inactive manifest body", "inactive manifest json").await;
    assert_eq!(json["total"].as_u64(), Some(2));
    let manifests = json["items"].as_array().expect("manifests array");
    assert_eq!(manifests.len(), 2);
    let pending = manifests
        .iter()
        .find(|row| row["dataspace_id"].as_u64() == Some(pending_dataspace.as_u64()))
        .expect("pending manifest row");
    assert_eq!(pending["status"].as_str(), Some("Pending"));
    assert_eq!(pending["dataspace_alias"].as_str(), Some("restricted"));
    assert_eq!(
        pending["accounts"]
            .as_array()
            .expect("pending accounts")
            .len(),
        1,
    );
    assert_eq!(
        pending["accounts"][0].as_str(),
        Some(authority.to_string().as_str())
    );
    let expired = manifests
        .iter()
        .find(|row| row["dataspace_id"].as_u64() == Some(expired_dataspace.as_u64()))
        .expect("expired manifest row");
    assert_eq!(expired["status"].as_str(), Some("Expired"));
    assert!(expired["dataspace_alias"].is_null());
    assert_eq!(
        expired["accounts"]
            .as_array()
            .expect("expired accounts array")
            .len(),
        0,
        "uncataloged/unbound dataspaces should report empty account bindings",
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn routed_uaid_handlers_reject_invalid_inputs_before_routing() {
    let app = mk_app_state_for_tests();
    let invalid_portfolio = match super::handler_accounts_portfolio(
        State(app.clone()),
        axum::http::Method::GET,
        "/v1/accounts/uaid:1234/portfolio"
            .parse()
            .expect("valid portfolio uri"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        AxPath("uaid:1234".to_owned()),
        AxQuery(super::AccountsPortfolioQuery { asset_id: None }),
    )
    .await
    {
        Ok(_) => panic!("an invalid portfolio UAID must fail before fanout"),
        Err(error) => error.into_response(),
    };
    assert_eq!(invalid_portfolio.status(), StatusCode::BAD_REQUEST);

    let invalid_binding = match super::handler_space_directory_bindings(
        State(app.clone()),
        axum::http::Method::GET,
        "/v1/space-directory/uaids/uaid:1234"
            .parse()
            .expect("valid bindings uri"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        AxPath("uaid:1234".to_owned()),
        AxQuery(routing::SpaceDirectoryBindingsQuery::default()),
    )
    .await
    {
        Ok(_) => panic!("an invalid binding UAID must fail before fanout"),
        Err(error) => error.into_response(),
    };
    assert_eq!(invalid_binding.status(), StatusCode::BAD_REQUEST);

    let invalid_uaid = match super::handler_space_directory_manifests(
        State(app.clone()),
        axum::http::Method::GET,
        "/v1/space-directory/uaids/uaid:1234/manifests"
            .parse()
            .expect("valid manifests uri"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        AxPath("uaid:1234".to_owned()),
    )
    .await
    {
        Ok(_) => panic!("an invalid UAID must fail before fanout"),
        Err(error) => error.into_response(),
    };
    assert_eq!(invalid_uaid.status(), StatusCode::BAD_REQUEST);

    let uaid = UniversalAccountId::from_hash(Hash::new(b"manifest-preflight"));
    let invalid_status = match super::handler_space_directory_manifests(
        State(app),
        axum::http::Method::GET,
        format!("/v1/space-directory/uaids/{uaid}/manifests?status=retired")
            .parse()
            .expect("valid manifests uri"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        AxPath(uaid.to_string()),
    )
    .await
    {
        Ok(_) => panic!("an invalid status must fail before fanout"),
        Err(error) => error.into_response(),
    };
    assert_eq!(invalid_status.status(), StatusCode::BAD_REQUEST);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn anonymous_space_directory_manifest_selector_hides_restricted_route() {
    let authority = checked_torii_test_account_id(
        0xfa,
        "derive routed space-directory manifest authority fixture key",
    );
    let restricted_dataspace = DataSpaceId::new(10);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::space-directory-manifest-route"));
    let mut world = world_with_account_bound_to_dataspace(&authority, uaid, restricted_dataspace);
    let mut bindings = iroha_core::nexus::space_directory::UaidDataspaceBindings::default();
    bindings.bind_account(restricted_dataspace, authority.clone());
    world
        .uaid_dataspaces_mut_for_testing()
        .insert(uaid, bindings);
    let app = native_ingress_app_with_world_and_nexus_for_test(
        world,
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    assert_initial_nexus_catalog_for_test(&app.state, &private_ingress_nexus_for_test());
    assert!(
        super::torii_all_dataspace_routes(app.as_ref())
            .iter()
            .any(|route| route.dataspace_id == restricted_dataspace)
    );
    let response = super::handler_space_directory_manifests(
        State(app),
        axum::http::Method::GET,
        format!(
            "/v1/space-directory/uaids/{uaid}/manifests?filter=dataspace_id%20%3D%2010%20and%20status%20%3D%20%22Active%22&limit=1&include_total=true"
        )
        .parse()
        .expect("valid restricted manifest selector uri"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        AxPath(uaid.to_string()),
    )
    .await
    .expect("manifest handler should execute")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        torii_response_header(&response, "x-iroha-routed-by"),
        Some("local"),
        "configured dataspace route should execute locally in unit tests",
    );
    let json = decode_torii_json(response, "manifest handler body", "manifest handler json").await;
    assert!(
        json.get("total")
            .is_none_or(|total| total.as_u64() == Some(0))
    );
    let manifests = json["items"].as_array().expect("manifests array");
    assert!(manifests.is_empty());
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn anonymous_loopback_cannot_read_restricted_or_missing_explorer_accounts() {
    let authority =
        checked_torii_test_account_id(0xfb, "derive explorer account detail authority fixture key");
    let missing =
        checked_torii_test_account_id(0xfc, "derive missing explorer account detail fixture key");
    let restricted_dataspace = DataSpaceId::new(10);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::explorer-account-detail-routes"));
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account_bound_to_dataspace(&authority, uaid, restricted_dataspace),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    let (_restricted_lane, configured_restricted_dataspace) =
        configure_private_ingress_routes_for_test(&mut app);
    assert_eq!(configured_restricted_dataspace, restricted_dataspace);
    for account in [&authority, &missing] {
        let error = super::handler_explorer_account_detail(
            State(app.clone()),
            axum::http::Method::GET,
            format!("/v1/explorer/accounts/{account}")
                .parse()
                .expect("valid explorer account uri"),
            HeaderMap::new(),
            crate::loopback_connect_info(),
            AxPath(account.to_string()),
        )
        .await
        .expect_err("anonymous loopback must not distinguish a restricted account from absence");
        assert_eq!(error.into_response().status(), StatusCode::NOT_FOUND);
    }
}

fn build_account_bound_exact_transaction_query_for_test(
    target: AccountId,
) -> iroha_data_model::query::QueryWithParams {
    use iroha_data_model::query::{
        CommittedTransaction, CommittedTxFilters, Query, QueryWithParams,
        dsl::{CompoundPredicate, SelectorTuple},
        parameters::QueryParams,
        transaction::prelude::FindTransactions,
    };
    use norito::codec::Encode;
    let query = FindTransactions::new();
    QueryWithParams {
        query: (),
        query_payload: query.dyn_encode(),
        item: query.query_item_kind(),
        predicate_bytes: CompoundPredicate::from_filters(CommittedTxFilters {
            authority_eq: Some(target),
            entry_eq: Some(HashOf::from_untyped_unchecked(Hash::new(
                b"scoped-recovery-fixture",
            ))),
            ..CommittedTxFilters::default()
        })
        .encode(),
        selector_bytes: SelectorTuple::<CommittedTransaction>::default().encode(),
        params: QueryParams::default(),
    }
}

#[test]
fn signed_query_scope_exact_transaction_recovery_is_shared_and_bounded() {
    let target = checked_torii_test_account_id(0xa7, "exact transaction target");
    let authority = checked_torii_test_account_id(0xa8, "exact transaction reader");
    let query = build_account_bound_exact_transaction_query_for_test(target.clone());
    let limits = super::QueryScopeMemoryLimits {
        decode_allocated_bytes: 64 * 1024,
        canonical_encoded_bytes: 64 * 1024,
    };
    assert_eq!(
        super::target_account_iterable_query_bounded(&query, limits).unwrap(),
        Some(target.clone())
    );
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Start(query.clone())
        )),
        super::SignedQueryScope::TargetAccount(target)
    );
    let insufficient = super::QueryScopeMemoryLimits {
        decode_allocated_bytes: 1,
        canonical_encoded_bytes: 1,
    };
    assert_eq!(
        super::target_account_iterable_query_bounded(&query, insufficient)
            .expect_err("scope inspection must preserve admitted memory bounds")
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let mut malformed = query;
    malformed.predicate_bytes.push(0);
    assert_eq!(
        super::target_account_iterable_query_bounded(&malformed, limits).unwrap(),
        None
    );
    assert_eq!(
        super::signed_query_scope(&request_for_test(
            &authority,
            iroha_data_model::query::QueryRequest::Start(malformed)
        )),
        super::SignedQueryScope::AuthorityRouted
    );
    let continuation = iroha_data_model::query::QueryRequest::Continue(
        iroha_data_model::query::parameters::ForwardCursor {
            query: "a".repeat(64),
            cursor: NonZeroU64::new(1).unwrap(),
            gas_budget: None,
        },
    );
    assert_eq!(
        super::signed_query_scope(&request_for_test(&authority, continuation)),
        super::SignedQueryScope::AuthorityRouted
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn account_assets_reject_invalid_queries_before_routing() {
    let authority =
        checked_torii_test_account_id(0xf7, "derive account assets validation fixture key");
    // The minimal app has no visible route for this account, which used to
    // answer every query, valid or not, with an empty page.
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let uri: axum::http::Uri =
        format!("/v1/accounts/{authority}/assets?filter=unknown_field%20%3D%201")
            .parse()
            .expect("valid account assets uri");
    let error = super::handler_account_assets(
        State(app),
        axum::http::Method::GET,
        uri,
        HeaderMap::new(),
        crate::loopback_connect_info(),
        AxPath(authority.to_string()),
    )
    .await
    .err()
    .expect("an unknown filter field is rejected before routing");
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        torii_response_header(&response, "x-iroha-reject-code"),
        Some("invalid_filter")
    );
}

#[tokio::test]
async fn dpn_domain_enrollment_routes_only_exact_identity_and_permission_queries() {
    use iroha_data_model::{
        nexus::UniversalAccountId,
        query::{QueryRequest, account::prelude::FindAccountById},
    };
    use iroha_executor_data_model::permission::dpn::CanGrantDpnUserForAccountDomain;
    let authority = checked_torii_test_account_id(0x51, "DPN enrollment registrar");
    let customer = checked_torii_test_account_id(0x52, "DPN enrollment customer");
    let uaid = UniversalAccountId::from_hash(iroha_crypto::Hash::new(b"dpn-route-enrollment"));
    let mut world = World::with(
        [],
        [
            Account::new(authority.clone()).build(&authority),
            Account::new(customer.clone())
                .with_uaid(Some(uaid))
                .build(&customer),
        ],
        [],
    );
    world.account_permissions_mut_for_testing().insert(
        authority.clone(),
        std::collections::BTreeSet::from([Permission::from(CanGrantDpnUserForAccountDomain {
            domain: iroha_model_base::domain::DomainId::try_new("nevo", "universal").unwrap(),
        })]),
    );
    let mut app =
        mk_app_state_for_tests_with_world_and_nexus(world, private_ingress_nexus_for_test());
    configure_private_ingress_routes_for_test(&mut app);
    // Install authoritative binding, reverse index, rekey record and active SNS lease together.
    bind_account_alias_for_test(&app, &customer, "customer@nevo.universal");
    let routes = super::torii_all_dataspace_routes(app.as_ref());
    let scope = super::SignedQueryScope::TargetAccount(customer.clone());
    for query in [
        QueryRequest::Singular(FindAccountById::new(customer.clone()).into()),
        QueryRequest::Start(build_find_permissions_by_account_query_for_test(
            customer.clone(),
        )),
    ] {
        let request = request_for_test(&authority, query);
        assert_eq!(
            super::torii_authorize_signed_query_routes(
                app.as_ref(),
                &request,
                &scope,
                routes.clone()
            )
            .unwrap()
            .len(),
            routes.len()
        );
    }
    let role_request = request_for_test(
        &authority,
        QueryRequest::Start(build_find_roles_by_account_query_for_test(customer)),
    );
    assert!(
        super::torii_authorize_signed_query_routes(
            app.as_ref(),
            &role_request,
            &scope,
            routes.clone()
        )
        .is_err()
    );
    let broad = request_for_test(
        &authority,
        QueryRequest::Start(build_find_account_ids_query_for_test()),
    );
    assert!(
        super::torii_authorize_signed_query_routes(
            app.as_ref(),
            &broad,
            &super::SignedQueryScope::CrossDataspaceFanout,
            routes
        )
        .is_err()
    );
}
