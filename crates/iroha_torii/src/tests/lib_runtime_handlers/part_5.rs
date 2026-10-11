include!("part_5_pipeline_cache.rs");
include!("part_5_committed_retry.rs");
async fn pipeline_status_response(
    app: SharedAppState,
    hash: String,
    scope: Option<&str>,
    diagnostic: &'static str,
) -> Response {
    super::handler_pipeline_transaction_status(
        State(app),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            HeaderValue::from_static("application/json"),
        )),
        crate::NoritoStringQuery(PipelineStatusQuery {
            hash: Some(hash),
            scope: scope.map(str::to_owned),
        }),
    )
    .await
    .expect(diagnostic)
}
#[test]
#[ignore = "load profile; run explicitly with --ignored --nocapture"]
fn pipeline_status_cache_prune_load_profile() {
    const WARMUP_SAMPLES: usize = 4;
    const SAMPLES: usize = 32;
    const CACHE_ITEMS: u64 = 2_048;
    let fixtures = (1..=CACHE_ITEMS)
        .map(|height| {
            let (block, _) = make_signed_block(height, None);
            let header = block.header();
            let tx_hash = block.external_transactions().next().expect("tx").hash();
            (header.height(), header.hash(), tx_hash)
        })
        .collect::<Vec<_>>();
    let run_iteration = |sample_index: usize| {
        let cache = PipelineStatusCache::with_limits(512, Duration::from_secs(1));
        let now = Instant::now();
        let stale = now
            .checked_sub(Duration::from_secs(5))
            .expect("time subtraction");
        for (index, (height, block_hash, tx_hash)) in fixtures.iter().enumerate() {
            let observed_at = if index % 2 == 0 {
                stale
            } else {
                now + Duration::from_nanos((index + sample_index) as u64)
            };
            cache.record_entry_inner(
                *tx_hash,
                PipelineStatusEntry::at_time(
                    PipelineStatusKind::Queued,
                    Some(*height),
                    None,
                    observed_at,
                ),
            );
            cache.record_pending_block(
                *height,
                PendingBlockStatus {
                    kind: PipelineStatusKind::Committed,
                    block_hash: *block_hash,
                    observed_at,
                    deferred: None,
                },
            );
        }
        let start = Instant::now();
        cache.prune(now);
        let elapsed = start.elapsed();
        std::hint::black_box((cache.entries.len(), cache.pending_blocks.len()));
        elapsed
    };
    for sample_index in 0..WARMUP_SAMPLES {
        std::hint::black_box(run_iteration(sample_index));
    }
    let mut samples = Vec::with_capacity(SAMPLES);
    let wall_start = Instant::now();
    for sample_index in 0..SAMPLES {
        samples.push(run_iteration(sample_index + WARMUP_SAMPLES));
    }
    crate::profile_stats::print_profile(
        "hot_path",
        "pipeline_status_cache_prune_pressure",
        samples,
        WARMUP_SAMPLES,
        1,
        wall_start.elapsed(),
    );
}
#[test]
fn parse_signed_transaction_hash_rejects_invalid() {
    assert!(parse_signed_transaction_hash("not-a-hash").is_err());
    let canonical = HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::new(
        b"pipeline-status-exact-hash",
    ))
    .to_string();
    assert!(parse_signed_transaction_hash(&canonical).is_ok());
    for retired in [
        canonical.to_ascii_uppercase(),
        format!(" {canonical}"),
        format!("{canonical} "),
        format!("{}0", &canonical[..63]),
    ] {
        assert!(
            parse_signed_transaction_hash(&retired).is_err(),
            "noncanonical hash spelling must fail: {retired:?}"
        );
    }

    let unknown_query = format!(r#"{{"hash":"{canonical}","legacy_scope":"auto"}}"#);
    assert!(
        norito::json::from_str::<PipelineStatusQuery>(&unknown_query).is_err(),
        "pipeline status query must reject unknown compatibility fields"
    );
}
#[tokio::test]
async fn pipeline_status_string_query_preserves_decimal_hash_and_whitespace() {
    use axum::extract::FromRequestParts as _;
    let hash = "11".repeat(32);
    let padded_hash = format!(" {hash} ");
    let request = axum::http::Request::builder()
        .uri(format!(
            "/v1/pipeline/transactions/status?hash=+{hash}+&scope=+local+"
        ))
        .body(())
        .expect("pipeline status request");
    let (mut parts, _) = request.into_parts();
    let crate::NoritoStringQuery(query) =
        crate::NoritoStringQuery::<PipelineStatusQuery>::from_request_parts(&mut parts, &())
            .await
            .expect("pipeline status string query should decode");
    assert_eq!(query.hash.as_deref(), Some(padded_hash.as_str()));
    assert_eq!(query.scope.as_deref(), Some(" local "));
}
#[tokio::test]
async fn pipeline_status_handler_returns_queued() {
    let keypair =
        checked_torii_test_ed25519_keypair(0x28, "derive Torii queued-status fixture key");
    let authority = AccountId::new(keypair.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let tx = checked_torii_test_transaction(
        TransactionBuilder::new(
            *app.state.network_id_ref(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log {
            level: Level::INFO,
            msg: "queued".to_string(),
        }]),
        &keypair,
        "sign Torii queued-status fixture transaction",
    );
    let params = app.state.world.view().parameters().clone();
    let max_clock_drift = params.sumeragi().max_clock_drift();
    let tx_limits = params.transaction();
    let crypto_cfg = app.state.crypto();
    let accepted = AcceptedTransaction::accept(
        tx.clone(),
        app.state.network_id_ref(),
        max_clock_drift,
        tx_limits,
        crypto_cfg.as_ref(),
    )
    .expect("accepted");
    app.queue
        .push(accepted, app.state.view())
        .expect("queue push");
    for hash in [tx.hash().to_string(), tx.hash_as_entrypoint().to_string()] {
        for scope in ["local", "global"] {
            let response = execute_pipeline_status_local_read(
                &app,
                &PipelineStatusQuery {
                    hash: Some(hash.clone()),
                    scope: Some(scope.into()),
                },
                ResponseFormat::Json,
                None,
            )
            .expect("an admitted routed input remains visible in either scope");
            assert_eq!(response.status(), StatusCode::OK);
            let payload = torii_json_body(response).await;
            assert_eq!(
                payload.get("hash").and_then(norito::json::Value::as_str),
                Some(hash.as_str())
            );
            assert_eq!(
                payload.get("scope").and_then(norito::json::Value::as_str),
                Some(scope)
            );
            assert_eq!(
                payload
                    .get("status")
                    .and_then(|status| status.get("kind"))
                    .and_then(norito::json::Value::as_str),
                Some("Queued"),
                "an accepted input must block exact absence before its signed TTL",
            );
        }
    }
}
#[tokio::test]
async fn pipeline_status_handler_returns_typed_norito_when_requested() {
    use iroha_torii_shared::PipelineTransactionStatusResponse;
    let keypair = checked_torii_test_ed25519_keypair(0x29, "derive Torii typed-status fixture key");
    let authority = AccountId::new(keypair.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let tx = checked_torii_test_transaction(
        TransactionBuilder::new(
            *app.state.network_id_ref(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log {
            level: Level::INFO,
            msg: "queued".to_string(),
        }]),
        &keypair,
        "sign Torii typed-status fixture transaction",
    );
    let params = app.state.world.view().parameters().clone();
    let max_clock_drift = params.sumeragi().max_clock_drift();
    let tx_limits = params.transaction();
    let crypto_cfg = app.state.crypto();
    let accepted = AcceptedTransaction::accept(
        tx.clone(),
        app.state.network_id_ref(),
        max_clock_drift,
        tx_limits,
        crypto_cfg.as_ref(),
    )
    .expect("accepted");
    app.queue
        .push(accepted, app.state.view())
        .expect("queue push");
    let resp = super::handler_pipeline_transaction_status(
        State(app),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
        )),
        crate::NoritoStringQuery(PipelineStatusQuery {
            hash: Some(tx.hash().to_string()),
            scope: Some("local".to_owned()),
        }),
    )
    .await
    .expect("ok");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(crate::utils::NORITO_MIME_TYPE)
    );
    let bytes = torii_body_bytes(resp, "body").await;
    let payload: PipelineTransactionStatusResponse =
        norito::decode_from_bytes(&bytes).expect("typed norito response");
    assert_eq!(payload.status.kind, "Queued");
    assert_eq!(payload.resolved_from, "queue");
}
#[tokio::test]
async fn pipeline_preflight_handler_returns_json_snapshot() {
    let app = mk_app_state_for_tests();
    let expected_block_cadence_ms = app
        .state
        .world_view()
        .parameters()
        .sumeragi()
        .block_cadence_ms()
        .get();
    let resp = super::handler_pipeline_preflight(
        State(app),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            HeaderValue::from_static("application/json"),
        )),
    )
    .await
    .expect("ok");
    assert_eq!(resp.status(), StatusCode::OK);
    let payload = torii_json_body(resp).await;
    assert_eq!(
        payload.get("schema_version"),
        Some(&norito::json::Value::from(1_u64))
    );
    assert_eq!(
        payload
            .get("sumeragi")
            .and_then(|value| value.get("block_cadence_ms")),
        Some(&norito::json::Value::from(expected_block_cadence_ms))
    );
    assert_eq!(
        payload.get("queue").and_then(|value| value.get("size")),
        Some(&norito::json::Value::from(0_u64))
    );
    let pipeline = payload
        .get("pipeline")
        .and_then(norito::json::Value::as_object)
        .expect("preflight payload should expose pipeline settings");
    assert!(
        pipeline.get("signature_batch_max").is_none(),
        "preflight payload must not expose the retired aggregate signature-batch field"
    );
    for field in [
        "signature_batch_max_ed25519",
        "signature_batch_max_secp256k1",
        "signature_batch_max_pqc",
        "signature_batch_max_bls",
    ] {
        assert!(
            pipeline.get(field).is_some(),
            "preflight payload must expose {field}"
        );
    }
    assert!(
        payload
            .get("fees")
            .and_then(norito::json::Value::as_object)
            .is_some(),
        "preflight payload should expose Nexus fee settings"
    );
}
#[tokio::test]
async fn pipeline_preflight_handler_returns_typed_norito_when_requested() {
    let app = mk_app_state_for_tests();
    let expected_block_cadence_ms = app
        .state
        .world_view()
        .parameters()
        .sumeragi()
        .block_cadence_ms()
        .get();
    let resp = super::handler_pipeline_preflight(
        State(app.clone()),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
        )),
    )
    .await
    .expect("ok");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(crate::utils::NORITO_MIME_TYPE)
    );
    let bytes = torii_body_bytes(resp, "body").await;
    let payload: routing::PipelinePreflightResponse =
        norito::decode_from_bytes(&bytes).expect("typed norito response");
    assert_eq!(payload.schema_version, 1);
    assert_eq!(payload.queue.size, 0);
    assert_eq!(payload.sumeragi.block_cadence_ms, expected_block_cadence_ms);
    assert!(
        payload
            .fees
            .successful_claim_fee_exempt_authorities
            .is_empty()
    );
    assert_eq!(
        payload.pipeline.ivm_max_cycles_upper_bound,
        app.state
            .pipeline_snapshot()
            .ivm_max_cycles_upper_bound
            .get()
    );
    assert_eq!(
        payload.pipeline.ivm_admission_cycle_limit,
        app.state.ivm_admission_cycle_limit().get()
    );
}
#[tokio::test]
async fn pipeline_status_global_read_evicts_stale_queued_cache() {
    let app = mk_app_state_for_tests();
    let tx_hash =
        HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed([0x74; Hash::LENGTH]));
    app.pipeline_status_cache.record_entry(
        tx_hash,
        PipelineStatusEntry::fresh(PipelineStatusKind::Queued, None, None),
    );
    let response = execute_pipeline_status_local_read(
        &app,
        &PipelineStatusQuery {
            hash: Some(tx_hash.to_string()),
            scope: Some("global".to_owned()),
        },
        ResponseFormat::Json,
        None,
    )
    .expect("global local observation");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(app.pipeline_status_cache.lookup(&tx_hash).is_none());
    for scope in [
        PipelineStatusReadScope::Global,
        PipelineStatusReadScope::Local,
    ] {
        for format in [ResponseFormat::Json, ResponseFormat::Norito] {
            use axum::{Router, routing::get};
            use tower::ServiceExt as _;
            let response = execute_pipeline_status_local_read(
                &app,
                &PipelineStatusQuery {
                    hash: Some(tx_hash.to_string()),
                    scope: Some(scope.as_str().to_owned()),
                },
                format,
                None,
            )
            .expect("exact absence");
            let response = Arc::new(parking_lot::Mutex::new(Some(response)));
            let router = Router::new()
                .route(
                    "/status",
                    get(move || {
                        let response = response.lock().take().expect("one request");
                        async move { response }
                    }),
                )
                .layer(axum::middleware::from_fn(
                    crate::enforce_typed_error_contract,
                ));
            let accept = if matches!(format, ResponseFormat::Json) {
                "application/json"
            } else {
                crate::utils::NORITO_MIME_TYPE
            };
            let response = router
                .oneshot(
                    axum::http::Request::builder()
                        .uri("/status")
                        .header("Accept", accept)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("middleware");
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .expect("body");
            let envelope: ErrorEnvelope = if matches!(format, ResponseFormat::Json) {
                norito::json::from_slice(&body).expect("JSON")
            } else {
                norito::decode_from_bytes(&body).expect("native")
            };
            assert_eq!(
                envelope.code(),
                iroha_torii_shared::PIPELINE_TRANSACTION_STATUS_NOT_FOUND_CODE
            );
            assert!(
                envelope
                    .details
                    .unwrap()
                    .pipeline_transaction_status_not_found
                    .unwrap()
                    .matches(&tx_hash, scope.as_str())
            );
        }
    }
}
#[test]
fn pipeline_status_local_read_evicts_stale_queued_cache() {
    let app = mk_app_state_for_tests();
    let tx_hash =
        HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed([0x75; Hash::LENGTH]));
    app.pipeline_status_cache.record_entry(
        tx_hash,
        PipelineStatusEntry::fresh(PipelineStatusKind::Queued, None, None),
    );
    let response = execute_pipeline_status_local_read(
        &app,
        &PipelineStatusQuery {
            hash: Some(tx_hash.to_string()),
            scope: Some("local".to_owned()),
        },
        ResponseFormat::Json,
        None,
    )
    .expect("local absence observation");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(app.pipeline_status_cache.lookup(&tx_hash).is_none());
}
#[cfg(feature = "connect")]
fn lifecycle_transaction_with_nonce_for_test(
    app: &SharedAppState,
    key: &KeyPair,
    certificate: &ThresholdKeyLifecycleCertificateV1,
    nonce: u32,
) -> SignedTransaction {
    let mut builder = TransactionBuilder::new(
        *app.state.network_id_ref(),
        AccountId::new(key.public_key().clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([ApplyThresholdKeyLifecycleCertificateV1 {
        certificate: certificate.clone(),
    }]);
    builder.set_nonce(NonZeroU32::new(nonce).expect("distinct nonzero fixture nonce"));
    builder.sign(key.private_key())
}
#[cfg(feature = "connect")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_status_local_read_keeps_live_pending_queued_cache() {
    let key = checked_torii_test_ed25519_keypair(0xd8, "live pending native authority");
    let app = native_ingress_app_for_test(&[&key]);
    let transaction = signed_log_transaction_for_test(
        *app.state.network_id_ref(),
        AccountId::new(key.public_key().clone()),
        "native live pending status",
        &key,
    );
    let tx_hash = transaction.hash();
    let response = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &transaction)
        .await
        .expect("native public handler admission");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_native_pending_for_test(&app, &transaction);
    app.pipeline_status_cache.record_entry(
        tx_hash.clone(),
        PipelineStatusEntry::fresh(PipelineStatusKind::Queued, None, None),
    );
    let response = execute_pipeline_status_local_read(
        &app,
        &PipelineStatusQuery {
            hash: Some(tx_hash.to_string()),
            scope: Some("local".to_owned()),
        },
        ResponseFormat::Json,
        None,
    )
    .expect("local reads should keep genuinely pending queued cache entries");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(app.pipeline_status_cache.lookup(&tx_hash).is_some());
}
#[test]
fn pipeline_status_both_scopes_keep_approved_cache() {
    let app = mk_app_state_for_tests();
    let tx_hash =
        HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed([0x75; Hash::LENGTH]));
    app.pipeline_status_cache.record_entry(
        tx_hash,
        PipelineStatusEntry::fresh(PipelineStatusKind::Approved, None, None),
    );
    for scope in ["local", "global"] {
        let response = execute_pipeline_status_local_read(
            &app,
            &PipelineStatusQuery {
                hash: Some(tx_hash.to_string()),
                scope: Some(scope.to_owned()),
            },
            ResponseFormat::Json,
            None,
        )
        .expect("both scopes must keep block-pipeline cache entries");
        assert_eq!(response.status(), StatusCode::OK);
    }
}
#[tokio::test]
async fn pipeline_status_handler_uses_dedicated_rate_limiter() {
    let (mut app, tx_hash, _chain) = canonical_outcome_test_fixture(false);
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        app_mut.rate_limiter = limits::RateLimiter::new(Some(1), Some(1));
        app_mut.pipeline_status_rate_limiter = limits::RateLimiter::new(Some(2), Some(2));
    }
    let headers = HeaderMap::new();
    let remote_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let rate_key = rate_limit_key(
        &headers,
        Some(remote_ip),
        "v1/pipeline/transactions/status",
        app.authenticated_api_token_principal(&headers),
    );
    assert!(limits::allow_conditionally(&app.rate_limiter, &rate_key, true).await);
    assert!(!limits::allow_conditionally(&app.rate_limiter, &rate_key, true).await);
    let resp = super::handler_pipeline_transaction_status(
        State(app),
        headers,
        crate::loopback_connect_info(),
        None,
        crate::NoritoStringQuery(PipelineStatusQuery {
            hash: Some(tx_hash.to_string()),
            scope: Some("local".to_owned()),
        }),
    )
    .await
    .expect("pipeline status should bypass the general query limiter");
    assert_eq!(resp.status(), StatusCode::OK);
}
#[tokio::test]
async fn pipeline_status_handler_cache_hit_ignores_tx_rate_limiter_pressure() {
    let mut app = mk_app_state_for_tests();
    let tx_hash =
        HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed([0x72; Hash::LENGTH]));
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        app_mut.tx_rate_limiter = limits::RateLimiter::new(Some(1), Some(1));
        app_mut.pipeline_status_cache.record_entry(
            tx_hash,
            PipelineStatusEntry::fresh(PipelineStatusKind::Expired, None, None),
        );
    }
    assert!(app.tx_rate_limiter.allow("pipeline-status-test").await);
    assert!(!app.tx_rate_limiter.allow("pipeline-status-test").await);
    let resp = pipeline_status_response(
        app,
        tx_hash.to_string(),
        Some("local"),
        "cached pipeline status should stay available under tx-ingress pressure",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}
#[tokio::test]
async fn pipeline_status_handler_charges_cache_hits_before_local_reads() {
    let mut app = mk_app_state_for_tests();
    let tx_hash =
        HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed([0x73; Hash::LENGTH]));
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app state");
        app_mut.pipeline_status_rate_limiter = limits::RateLimiter::new(Some(1), Some(1));
        app_mut.pipeline_status_cache.record_entry(
            tx_hash,
            PipelineStatusEntry::fresh(PipelineStatusKind::Applied, None, None),
        );
    }
    let headers = HeaderMap::new();
    let remote_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let rate_key = rate_limit_key(
        &headers,
        Some(remote_ip),
        "v1/pipeline/transactions/status",
        app.authenticated_api_token_principal(&headers),
    );
    assert!(limits::allow_conditionally(&app.pipeline_status_rate_limiter, &rate_key, true).await);
    assert!(!limits::allow_conditionally(&app.pipeline_status_rate_limiter, &rate_key, true).await);
    let error = super::handler_pipeline_transaction_status(
        State(app),
        headers,
        crate::loopback_connect_info(),
        None,
        crate::NoritoStringQuery(PipelineStatusQuery {
            hash: Some(tx_hash.to_string()),
            scope: Some("local".to_owned()),
        }),
    )
    .await
    .expect_err("cached pipeline status must not bypass the pipeline-status limiter");
    assert_eq!(
        error.into_response().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}
#[test]
fn pipeline_fastpq_recovery_batch_is_canonical_and_budgeted_under_ambient_flags() {
    use base64::Engine as _;

    let mut batch = fastpq_prover::TransitionBatch::new(
        fastpq_prover::AXT_DEFAULT_PARAMETER,
        fastpq_prover::PublicInputs::default(),
    );
    batch.push(fastpq_prover::StateTransition::new(
        b"metadata/key".to_vec(),
        b"before".to_vec(),
        b"after".to_vec(),
        fastpq_prover::OperationKind::MetaSet,
    ));
    let model = fastpq_prover::transition_batch_to_model(&batch);
    let canonical = norito::encode_canonical(&model).unwrap();
    let expected_base64 = base64::engine::general_purpose::STANDARD.encode(&canonical);
    for flags in
        (u8::MIN..=u8::MAX).filter(|&flags| norito::core::validate_header_flags(flags).is_ok())
    {
        let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
        for reconstructed in [false, true] {
            let mut used = PIPELINE_FASTPQ_RECOVERY_MAX_ARTIFACT_BYTES - canonical.len();
            let (encoded, actual_reconstructed) =
                encode_fastpq_recovery_batch(&batch, reconstructed, &mut used).unwrap();
            assert_eq!(encoded, expected_base64);
            assert_eq!(actual_reconstructed, reconstructed);
            assert_eq!(used, PIPELINE_FASTPQ_RECOVERY_MAX_ARTIFACT_BYTES);
            assert_eq!(norito::core::effective_decode_flags(), Some(flags));
        }
        let initial = PIPELINE_FASTPQ_RECOVERY_MAX_ARTIFACT_BYTES - canonical.len() + 1;
        let mut used = initial;
        let error = encode_fastpq_recovery_batch(&batch, false, &mut used).unwrap_err();
        assert!(matches!(
            error,
            Error::AppServiceUnavailable {
                code: "pipeline_recovery_fastpq_artifact_too_large",
                ..
            }
        ));
        assert_eq!(used, initial);
        assert_eq!(norito::core::effective_decode_flags(), Some(flags));
    }
}
#[test]
fn pipeline_fastpq_recovery_page_enforces_explicit_bounds() {
    assert_eq!(
        PipelineFastpqRecoveryPage::parse(&PipelineFastpqRecoveryQuery::default())
            .expect("default FASTPQ page"),
        PipelineFastpqRecoveryPage {
            offset: 0,
            limit: PIPELINE_FASTPQ_RECOVERY_DEFAULT_LIMIT,
        }
    );
    for limit in [0, PIPELINE_FASTPQ_RECOVERY_MAX_LIMIT as u64 + 1] {
        let error = PipelineFastpqRecoveryPage::parse(&PipelineFastpqRecoveryQuery {
            offset: None,
            limit: Some(limit),
        })
        .expect_err("out-of-range FASTPQ page limit must fail closed");
        assert!(query_conversion_message(&error).is_some());
    }
}
#[test]
fn pipeline_fastpq_recovery_artifact_budget_is_cumulative() {
    let mut used = 0;
    charge_fastpq_recovery_artifact_bytes(&mut used, PIPELINE_FASTPQ_RECOVERY_MAX_ARTIFACT_BYTES)
        .expect("exact FASTPQ artifact budget is admissible");
    let error = charge_fastpq_recovery_artifact_bytes(&mut used, 1)
        .expect_err("FASTPQ artifact budget overflow must fail closed");
    assert!(matches!(
        error,
        Error::AppServiceUnavailable {
            code: "pipeline_recovery_fastpq_artifact_too_large",
            ..
        }
    ));
}
#[test]
fn pipeline_fastpq_recovery_builder_paginates_and_bounds_encoding() {
    let app = mk_app_state_for_tests();
    let height = 1;
    let (block, _) = make_signed_block(height, None);
    let block_hash = block.hash();
    let mut sidecar = iroha_core::kura::PipelineRecoverySidecar::new(
        height,
        block_hash,
        iroha_core::kura::PipelineDagSnapshot {
            fingerprint: [0; 32],
            key_count: 0,
        },
        Vec::new(),
    );
    for batch_index in 0..2 {
        let proof = vec![batch_index as u8 + 1];
        sidecar
            .fastpq_proofs
            .push(iroha_core::kura::FastpqProofSnapshot {
                height,
                block_hash,
                entry_hash: Hash::prehashed([batch_index as u8 + 1; Hash::LENGTH]),
                batch_index,
                transition_count: 0,
                public_inputs: iroha_data_model::fastpq::FastpqPublicInputs {
                    dsid: [0; 16],
                    slot: 0,
                    old_root: [0; 32],
                    new_root: [0; 32],
                    perm_root: [0; 32],
                    tx_set_hash: [0; 32],
                },
                ordering_hash: [0; 32],
                artifact_identity: iroha_data_model::fastpq::FastpqArtifactIdentityDescriptionV1 {
                    proof_kind: iroha_data_model::fastpq::FastpqProofKindV1::OrdinaryCompact,
                    profile_id: fastpq_prover::offline_compact::quantity_profile_id(),
                    public_statement_digest: Hash::new(b"recovery statement").into(),
                    artifact_digest: Hash::new(&proof).into(),
                    inner_bundle_digest: Hash::new(b"recovery inner bundle").into(),
                    artifact_bytes: proof.len() as u64,
                    commitments:
                        iroha_data_model::fastpq::FastpqCommitmentDescriptionV1::OrderedCompactAir(
                            iroha_data_model::fastpq::FastpqOrderedCompactAirCommitmentsV1 {
                                segment_count: 1,
                                segment_air_row_roots: vec![
                                    iroha_data_model::fastpq::FastpqCommitmentV1::from_bytes(
                                        [u8::try_from(batch_index)
                                            .expect("fixture batch index fits u8")
                                            + 1; 32],
                                    ),
                                ],
                            },
                        ),
                },
            });
    }
    app.kura.write_pipeline_metadata(&sidecar);
    assert!(
        app.kura.read_pipeline_metadata(height).is_none(),
        "a sidecar without its canonical block must remain unavailable"
    );
    assert!(matches!(
        build_pipeline_recovery_fastpq_response(
            &app.kura,
            height,
            PipelineFastpqRecoveryPage {
                offset: 0,
                limit: 1
            },
        ),
        Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::NotFound
        )))
    ));
    assert_eq!(store_block(&app, block), block_hash);
    assert_eq!(
        app.kura
            .read_pipeline_metadata(height)
            .map(|stored| stored.block_hash),
        Some(block_hash),
        "the exact persisted block must authenticate its recovery sidecar"
    );
    let serialized = build_pipeline_recovery_fastpq_response(
        &app.kura,
        height,
        PipelineFastpqRecoveryPage {
            offset: 0,
            limit: 1,
        },
    )
    .expect("bounded FASTPQ recovery page");
    assert!(serialized.len() <= PIPELINE_FASTPQ_RECOVERY_MAX_RESPONSE_BYTES);
    let value: norito::json::Value =
        norito::json::from_str(&serialized).expect("decode FASTPQ recovery page");
    assert_eq!(value.get("total_proofs").and_then(|v| v.as_u64()), Some(2));
    assert_eq!(value.get("next_offset").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(
        value.get("proofs").and_then(|v| v.as_array()).map(Vec::len),
        Some(1)
    );
    let batch = fastpq_prover::TransitionBatch::new(
        "fastpq-state-transition-stark-v1",
        fastpq_prover::PublicInputs::default(),
    );
    let mut artifact_bytes = 0;
    let (encoded, reconstructed) = encode_fastpq_recovery_batch(&batch, false, &mut artifact_bytes)
        .expect("bounded FASTPQ batch encoding");
    assert!(!encoded.is_empty());
    assert!(!reconstructed);
    assert!(artifact_bytes > 0);
}
#[test]
fn pipeline_fastpq_recovery_emits_only_the_canonical_model_frame() {
    use base64::Engine as _;
    let mut batch = fastpq_prover::TransitionBatch::new(
        "fastpq-state-transition-stark-v1",
        fastpq_prover::PublicInputs::default(),
    );
    batch.push(fastpq_prover::StateTransition::new(
        b"metadata/recovery".to_vec(),
        b"before".to_vec(),
        b"after".to_vec(),
        fastpq_prover::OperationKind::MetaSet,
    ));
    let model = fastpq_prover::transition_batch_to_model(&batch);
    let expected = norito::encode_canonical(&model).expect("canonical public batch");
    for flags in [0, 1, 2, 3, 4, 5, 6, 7, 0x1b, 0x3f] {
        let _layout = norito::core::DecodeFlagsGuard::enter(flags);
        let effective_flags = norito::core::get_decode_flags();
        let mut used = 0;
        let (encoded, reconstructed) = encode_fastpq_recovery_batch(&batch, true, &mut used)
            .expect("canonical recovery batch");
        let actual = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(actual, expected);
        assert!(reconstructed);
        assert_eq!(used, actual.len());
        assert_eq!(
            norito::decode_canonical::<iroha_data_model::fastpq::FastpqTransitionBatch>(&actual)
                .unwrap(),
            model
        );
        assert!(norito::decode_canonical::<fastpq_prover::TransitionBatch>(&actual).is_err());
        assert_eq!(norito::core::get_decode_flags(), effective_flags);
    }
    let mut exact = PIPELINE_FASTPQ_RECOVERY_MAX_ARTIFACT_BYTES - expected.len();
    encode_fastpq_recovery_batch(&batch, false, &mut exact).expect("exact aggregate budget");
    assert_eq!(exact, PIPELINE_FASTPQ_RECOVERY_MAX_ARTIFACT_BYTES);
    assert!(encode_fastpq_recovery_batch(&batch, false, &mut exact).is_err());
    assert_eq!(exact, PIPELINE_FASTPQ_RECOVERY_MAX_ARTIFACT_BYTES);
}
#[test]
fn pipeline_fastpq_recovery_rejects_oversized_rows_before_model_conversion() {
    let mut batch = fastpq_prover::TransitionBatch::new(
        "fastpq-state-transition-stark-v1",
        fastpq_prover::PublicInputs::default(),
    );
    batch.metadata.insert(
        "oversized".to_owned(),
        vec![0; PIPELINE_FASTPQ_RECOVERY_MAX_BATCH_BYTES],
    );
    let mut used = 7;
    let error = encode_fastpq_recovery_batch(&batch, false, &mut used)
        .expect_err("oversized source must fail before cloning its row buffers");
    assert!(matches!(
        error,
        Error::AppServiceUnavailable {
            code: "pipeline_recovery_fastpq_artifact_too_large",
            ..
        }
    ));
    assert_eq!(used, 7);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn account_get_handler_supports_json_and_norito() {
    use iroha_torii_shared::AccountReadResponse;
    let keypair = checked_torii_test_ed25519_keypair(0x2a, "derive Torii account-get fixture key");
    let account_id = AccountId::new(keypair.public_key().clone());
    let world = world_with_account(&account_id);
    let app = native_ingress_app_with_world_for_test(world);
    let json_resp = super::handler_account_get(
        State(app.clone()),
        axum::http::Method::GET,
        format!("/v1/accounts/{account_id}")
            .parse()
            .expect("valid account get uri"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        None,
        AxPath(account_id.to_string()),
    )
    .await
    .expect("json account get");
    assert_eq!(json_resp.status(), StatusCode::OK);
    assert_eq!(
        torii_response_header(&json_resp, "content-type"),
        Some("application/json")
    );
    let json_bytes = torii_body_bytes(json_resp, "json body").await;
    let json_value: norito::json::Value =
        norito::json::from_slice(&json_bytes).expect("json account payload value");
    let json_payload: AccountReadResponse =
        norito::json::from_slice(&json_bytes).expect("json account payload");
    assert_eq!(json_payload.account_id, account_id);
    assert!(
        json_value.get("linked_domains").is_none(),
        "account read payload should not expose linked_domains"
    );
    let norito_resp = super::handler_account_get(
        State(app),
        axum::http::Method::GET,
        format!("/v1/accounts/{account_id}")
            .parse()
            .expect("valid account get uri"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
        )),
        AxPath(account_id.to_string()),
    )
    .await
    .expect("norito account get");
    assert_eq!(norito_resp.status(), StatusCode::OK);
    assert_eq!(
        torii_response_header(&norito_resp, "content-type"),
        Some(crate::utils::NORITO_MIME_TYPE)
    );
    let norito_bytes = torii_body_bytes(norito_resp, "norito body").await;
    let norito_payload: AccountReadResponse =
        norito::decode_from_bytes(&norito_bytes).expect("norito account payload");
    assert_eq!(norito_payload.account_id, account_id);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn account_get_handler_returns_not_found_for_missing_account() {
    let app = native_ingress_app_with_world_for_test(World::default());
    let missing =
        checked_torii_test_account_id(0x2b, "derive Torii missing account-get fixture key");
    let resp = super::handler_account_get(
        State(app),
        axum::http::Method::GET,
        format!("/v1/accounts/{missing}")
            .parse()
            .expect("valid missing account uri"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        None,
        AxPath(missing.to_string()),
    )
    .await
    .expect("missing account response");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
/// Retain genuine global authority while attempting a stale coordinate outside the current catalog.
#[cfg(feature = "app_api")]
fn native_account_read_with_stale_route_for_test(
    world: World,
) -> (SharedAppState, RoutingDecision, RoutingDecision) {
    let app = native_ingress_with_offline_foreign_app_for_test(world);
    let local_route = RoutingDecision::new(LaneId::new(1), DataSpaceId::new(10));
    let manifest_route = RoutingDecision::new(LaneId::new(2), DataSpaceId::new(12));
    let stale_route = RoutingDecision::new(LaneId::new(3), DataSpaceId::new(12));
    let local = app
        .state
        .resolve_route_authority(super::lane_authority_route(local_route))
        .expect("the active local route retains genuine global authority");
    let manifest = app
        .state
        .resolve_route_authority(super::lane_authority_route(manifest_route))
        .expect("another active label retains the same global authority");
    assert_eq!(local.authority_height(), 3);
    assert_eq!(manifest.authority_height(), local.authority_height());
    assert_eq!(local.validators(), manifest.validators());
    assert!(
        local.validators().contains(
            app.local_peer_id
                .as_ref()
                .expect("the original local validator")
        )
    );
    assert!(super::should_execute_route_locally(&app, local_route));
    assert!(super::should_execute_route_locally(&app, manifest_route));
    {
        let view = app.state.view();
        assert!(matches!(
            iroha_core::queue::resolve_routing_decision(
                stale_route,
                &view.nexus().lane_catalog,
                &view.nexus().dataspace_catalog,
            ),
            Err(iroha_core::queue::RoutingResolveError::UnknownLane { lane_id })
                if lane_id == stale_route.lane_id
        ));
    }
    assert!(matches!(
        app.state
            .resolve_route_authority(super::lane_authority_route(stale_route)),
        Err(iroha_core::state::LaneAuthorityError::InactiveRoute {
            lane_id,
            dataspace_id,
            authority_height: 3,
        }) if lane_id == stale_route.lane_id && dataspace_id == stale_route.dataspace_id
    ));
    assert!(!super::should_execute_route_locally(&app, stale_route));
    (app, local_route, stale_route)
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn account_read_for_routes_skips_route_unavailable_until_success() {
    let keypair =
        checked_torii_test_ed25519_keypair(0x2c, "derive Torii routed account-read fixture key");
    let account_id = AccountId::new(keypair.public_key().clone());
    let (app, local_route, stale_route) =
        native_account_read_with_stale_route_for_test(world_with_account(&account_id));
    let memory = super::try_acquire_query_fanout_memory(&app)
        .expect("the original query pool admits the complete fanout");
    let response = super::COLLECTION_READ_MEMORY_RESERVATION
        .scope(
            memory,
            super::execute_torii_account_read_for_resolved_routes(
                &app,
                vec![stale_route, local_route],
                super::ToriiFanoutRouteScopeV1::TargetAccount {
                    account_id: account_id.to_string(),
                    caller_account_id: Some(account_id.to_string()),
                },
                account_id.to_string(),
                ResponseFormat::Json,
                None,
            ),
        )
        .await;
    assert_eq!(
        torii_response_header(&response, "x-iroha-fanout-routes-attempted"),
        Some("2"),
    );
    assert_eq!(
        torii_response_header(&response, "x-iroha-fanout-routes-unavailable"),
        Some("1"),
        "the stale route is actually attempted and classified as unavailable",
    );
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        torii_response_header(&response, "x-iroha-routed-by"),
        Some("proxy"),
        "mixed local/proxy fanout should report proxy routing",
    );
    let body = torii_body_bytes(response, "account read body").await;
    let payload: AccountReadResponse =
        norito::json::from_slice(&body).expect("account read payload");
    assert_eq!(payload.account_id, account_id);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn trusted_internal_account_handler_rejects_credentials_from_untrusted_sources() {
    let authority = checked_torii_test_account_id(
        0x2a,
        "derive trusted internal account authorization fixture key",
    );
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("domain id"),
        "rose".parse().expect("asset name"),
    );
    let mut app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("x-api-token"),
        HeaderValue::from_static("valid-looking-api-token"),
    );
    headers.insert(
        axum::http::header::AUTHORIZATION,
        HeaderValue::from_static("Bearer valid-looking-jwt"),
    );
    let external = axum::extract::ConnectInfo(std::net::SocketAddr::from(([203, 0, 113, 8], 443)));
    let response = super::handler_internal_account_get(
        State(app.clone()),
        headers.clone(),
        external,
        None,
        AxPath(authority.to_string()),
    )
    .await
    .expect("untrusted request should return a typed rejection");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        torii_response_header(&response, "x-iroha-reject-code"),
        Some("trusted_network_required")
    );
    headers.insert(
        HeaderName::from_static(crate::limits::REMOTE_ADDR_HEADER),
        HeaderValue::from_static("127.0.0.1"),
    );
    assert!(
        !super::trusted_internal_read_source(app.as_ref(), &headers, external.0.ip()),
        "an untrusted peer must not forge the ingress-owned effective-address header",
    );
    let forged_asset_response = super::handler_internal_account_asset_get(
        State(app.clone()),
        format!(
            "/v1/internal/accounts/{authority}/assets/{asset_definition_id}?scope=dataspace:10"
        )
        .parse()
        .expect("valid internal asset URI"),
        headers.clone(),
        external,
        None,
        AxPath((authority.to_string(), asset_definition_id.to_string())),
    )
    .await
    .expect("forged external asset request should return a typed rejection");
    assert_eq!(forged_asset_response.status(), StatusCode::FORBIDDEN);
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .trusted_proxy_nets = Arc::new(crate::limits::parse_cidrs(&["127.0.0.0/8".to_owned()]));
    let mut nginx_headers = HeaderMap::new();
    nginx_headers.insert(
        HeaderName::from_static(crate::limits::FORWARDED_FOR_HEADER),
        HeaderValue::from_static("127.0.0.1, 198.51.100.9"),
    );
    // The proxy-observed external address must win over both a forged prefix
    // and the ingress-owned header supplied by that external caller.
    nginx_headers.insert(
        HeaderName::from_static(crate::limits::REMOTE_ADDR_HEADER),
        HeaderValue::from_static("127.0.0.1"),
    );
    assert!(
        !super::trusted_internal_read_source(
            app.as_ref(),
            &nginx_headers,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        ),
        "a configured loopback proxy must not make its external client a trusted loopback caller",
    );
    let proxied_response = super::handler_internal_account_get(
        State(app.clone()),
        nginx_headers,
        crate::loopback_connect_info(),
        None,
        AxPath(authority.to_string()),
    )
    .await
    .expect("external caller behind nginx should return a typed rejection");
    assert_eq!(proxied_response.status(), StatusCode::FORBIDDEN);
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .api_rate_limit_bypass_nets =
        Arc::new(crate::limits::parse_cidrs(&["203.0.113.0/24".to_owned()]));
    assert!(crate::limits::is_allowed_by_cidr(
        &HeaderMap::new(),
        Some(external.0.ip()),
        &app.api_rate_limit_bypass_nets,
    ));
    assert!(
        !super::trusted_internal_read_source(app.as_ref(), &HeaderMap::new(), external.0.ip()),
        "a broad rate-limit bypass must not confer internal-read trust",
    );
    assert!(super::trusted_internal_read_source(
        app.as_ref(),
        &HeaderMap::new(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    ));
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .internal_api_trusted_nets =
        Arc::new(crate::limits::parse_cidrs(&["203.0.113.8/32".to_owned()]));
    assert!(super::trusted_internal_read_source(
        app.as_ref(),
        &HeaderMap::new(),
        external.0.ip(),
    ));
    assert!(!super::trusted_internal_read_source(
        app.as_ref(),
        &HeaderMap::new(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9)),
    ));
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn trusted_internal_account_handler_emits_exact_json_and_norito_projection() {
    let authority = checked_torii_test_account_id(
        0x2b,
        "derive trusted internal account projection fixture key",
    );
    let uaid = UniversalAccountId::from_hash(Hash::new(b"trusted-internal-account"));
    let mut metadata = iroha_model_base::metadata::Metadata::default();
    metadata.insert(
        "tier".parse().expect("metadata key"),
        Json::new("regulated"),
    );
    let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id).build(&authority);
    let account = Account::new(authority.clone())
        .with_metadata(metadata.clone())
        .with_uaid(Some(uaid))
        .build(&authority);
    let app = native_ingress_app_with_world_for_test(World::with([domain], [account], []));
    let json_response = super::handler_internal_account_get(
        State(app.clone()),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            HeaderValue::from_static("application/json"),
        )),
        AxPath(authority.to_string()),
    )
    .await
    .expect("loopback JSON account read");
    assert_eq!(json_response.status(), StatusCode::OK);
    let json_body = torii_body_bytes(json_response, "JSON account body").await;
    let json: Value = norito::json::from_slice(&json_body).expect("valid account JSON");
    let object = json.as_object().expect("account JSON object");
    assert_eq!(
        object.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from(["id", "metadata", "opaque_ids", "uaid"]),
        "the trusted projection must not expose account aliases or the legacy label field",
    );
    let decoded_json: super::InternalAccountReadResponse =
        norito::json::from_slice(&json_body).expect("decode typed account JSON");
    assert_eq!(decoded_json.id, authority);
    assert_eq!(decoded_json.metadata, metadata);
    assert_eq!(decoded_json.uaid, Some(uaid));
    assert!(decoded_json.opaque_ids.is_empty());
    let norito_response = super::handler_internal_account_get(
        State(app),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
        )),
        AxPath(authority.to_string()),
    )
    .await
    .expect("loopback Norito account read");
    assert_eq!(norito_response.status(), StatusCode::OK);
    assert_eq!(
        norito_response
            .headers()
            .get(axum::http::header::CONTENT_TYPE),
        Some(&HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE))
    );
    let norito_body = torii_body_bytes(norito_response, "Norito account body").await;
    let decoded_norito: super::InternalAccountReadResponse =
        norito::decode_from_bytes(&norito_body).expect("decode typed account Norito");
    assert_eq!(decoded_norito, decoded_json);
}
#[cfg(feature = "app_api")]
#[test]
fn trusted_internal_path_literals_must_be_exactly_canonical() {
    let authority = checked_torii_test_account_id(
        0x2c,
        "derive trusted internal canonical literal fixture key",
    );
    let account_literal = authority.to_string();
    assert!(super::parse_exact_account_id_literal(&account_literal).is_ok());
    assert!(
        super::parse_exact_account_id_literal(&format!(" {account_literal}")).is_err(),
        "whitespace normalization is forbidden",
    );
    let entrypoint_hash = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::new(
        b"trusted-internal-canonical-hash",
    ));
    let hash_literal = entrypoint_hash.to_string();
    assert!(super::parse_exact_entrypoint_hash_literal(&hash_literal).is_ok());
    assert!(
        super::parse_exact_entrypoint_hash_literal(&hash_literal.to_ascii_uppercase()).is_err(),
        "uppercase hash aliases are forbidden",
    );
    assert!(
        super::parse_exact_entrypoint_hash_literal(&format!("{hash_literal} ")).is_err(),
        "hash whitespace normalization is forbidden",
    );
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("domain id"),
        "rose".parse().expect("asset name"),
    );
    let definition_literal = asset_definition_id.to_string();
    assert!(super::parse_exact_asset_definition_id_literal(&definition_literal).is_ok());
    assert!(
        super::parse_exact_asset_definition_id_literal(&format!("{definition_literal} ")).is_err(),
        "asset-definition whitespace normalization is forbidden",
    );
    for scope in ["global", "dataspace:0", "dataspace:10"] {
        assert!(super::parse_exact_asset_balance_scope_literal(scope).is_ok());
        assert!(
            super::parse_exact_internal_asset_scope_query(Some(&format!("scope={scope}"))).is_ok()
        );
    }
    for scope in ["Global", "dataspace:010", "dataspace:+10", "dataspace:10 "] {
        assert!(
            super::parse_exact_asset_balance_scope_literal(scope).is_err(),
            "noncanonical asset scope `{scope}` must fail",
        );
    }
    for query in [
        None,
        Some(""),
        Some("asset=dataspace:10"),
        Some("scope=dataspace:10&scope=dataspace:10"),
        Some("scope=dataspace:10&extra=1"),
    ] {
        assert!(
            super::parse_exact_internal_asset_scope_query(query).is_err(),
            "missing, duplicate, or alternate asset-scope query keys must fail",
        );
    }
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn trusted_internal_transaction_read_requires_exact_hash_and_account_involvement() {
    let keypair = checked_torii_test_ed25519_keypair(
        0x24,
        "derive trusted internal transaction authority fixture key",
    );
    let authority = AccountId::new(keypair.public_key().clone());
    let unrelated = checked_torii_test_account_id(
        0x2d,
        "derive trusted internal unrelated account fixture key",
    );
    let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id).build(&authority);
    let (app, signed_hash, _chain) = executed_history_test_fixture(
        iroha_core::sumeragi::test_chain::TestChainConfig::new(
            World::with(
                [domain],
                [
                    Account::new(authority.clone()).build(&authority),
                    Account::new(unrelated.clone()).build(&authority),
                ],
                [],
            ),
            1_000,
        ),
        &keypair,
        vec![Log::new(Level::INFO, "trusted internal native history".into()).into()],
        true,
    );
    let entrypoint_hash = iroha_core::tx::external_entrypoint_hash_from_signed_hash(signed_hash);
    let expected = crate::routing::committed_transactions_snapshot(app.state.as_ref())
        .expect("committed transaction snapshot")
        .into_iter()
        .find(|transaction| transaction.entrypoint_hash() == &entrypoint_hash)
        .expect("stored transaction");
    let response = super::execute_trusted_internal_account_transaction_local_read(
        &app,
        &authority.to_string(),
        &entrypoint_hash.to_string(),
        ResponseFormat::Json,
    );
    assert_eq!(response.status(), StatusCode::OK);
    let body = torii_body_bytes(response, "committed transaction JSON body").await;
    let decoded: iroha_data_model::query::CommittedTransaction =
        norito::json::from_slice(&body).expect("full committed transaction JSON");
    assert_eq!(
        decoded, expected,
        "the response must preserve every proof field"
    );
    let norito_response = super::execute_trusted_internal_account_transaction_local_read(
        &app,
        &authority.to_string(),
        &entrypoint_hash.to_string(),
        ResponseFormat::Norito,
    );
    assert_eq!(norito_response.status(), StatusCode::OK);
    let norito_body = torii_body_bytes(norito_response, "committed transaction Norito body").await;
    let decoded_norito: iroha_data_model::query::CommittedTransaction =
        norito::decode_from_bytes(&norito_body)
            .expect("full committed transaction Norito response");
    assert_eq!(decoded_norito, expected);
    let non_involved = super::execute_trusted_internal_account_transaction_local_read(
        &app,
        &unrelated.to_string(),
        &entrypoint_hash.to_string(),
        ResponseFormat::Json,
    );
    assert_eq!(non_involved.status(), StatusCode::NOT_FOUND);
    let missing_hash = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::new(
        b"trusted-internal-missing-hash",
    ));
    let missing = super::execute_trusted_internal_account_transaction_local_read(
        &app,
        &authority.to_string(),
        &missing_hash.to_string(),
        ResponseFormat::Json,
    );
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn trusted_internal_asset_read_is_exactly_scoped_bound_and_conflict_safe() {
    let authority =
        checked_torii_test_account_id(0x2e, "derive trusted internal asset authority fixture key");
    let unrelated = checked_torii_test_account_id(
        0x2f,
        "derive trusted internal asset unrelated-account fixture key",
    );
    let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let asset_definition_id =
        AssetDefinitionId::derive_from_components(domain_id, "rose".parse().expect("asset name"));
    let asset_definition = AssetDefinition::numeric(
        asset_definition_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority);
    let asset_id = AssetId::with_scope(
        asset_definition_id.clone(),
        authority.clone(),
        AssetBalanceScope::Dataspace(DataSpaceId::new(10)),
    );
    let expected = Asset::new(asset_id.clone(), Quantity::from(42_u32));
    let app = native_ingress_app_with_world_and_nexus_for_test(
        World::with_assets(
            [domain],
            [
                Account::new(authority.clone()).build(&authority),
                Account::new(unrelated.clone()).build(&authority),
            ],
            [asset_definition],
            [expected.clone()],
            [],
        ),
        private_ingress_nexus_for_test(),
    );
    let json_response = super::handler_internal_account_asset_get(
        State(app.clone()),
        format!(
            "/v1/internal/accounts/{authority}/assets/{asset_definition_id}?scope=dataspace:10"
        )
        .parse()
        .expect("valid internal asset URI"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            HeaderValue::from_static("application/json"),
        )),
        AxPath((authority.to_string(), asset_definition_id.to_string())),
    )
    .await
    .expect("exact JSON asset read");
    assert_eq!(json_response.status(), StatusCode::OK);
    let json_body = torii_body_bytes(json_response, "asset JSON body").await;
    let json_value: Value = norito::json::from_slice(&json_body).expect("valid asset JSON");
    assert_eq!(
        json_value
            .as_object()
            .expect("asset JSON object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["id", "value"]),
    );
    let decoded_json: Asset = norito::json::from_slice(&json_body).expect("typed asset JSON");
    assert_eq!(decoded_json, expected);
    let norito_response = super::handler_internal_account_asset_get(
        State(app.clone()),
        format!(
            "/v1/internal/accounts/{authority}/assets/{asset_definition_id}?scope=dataspace:10"
        )
        .parse()
        .expect("valid internal asset URI"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
        )),
        AxPath((authority.to_string(), asset_definition_id.to_string())),
    )
    .await
    .expect("exact Norito asset read");
    assert_eq!(norito_response.status(), StatusCode::OK);
    let norito_body = torii_body_bytes(norito_response, "asset Norito body").await;
    let decoded_norito: Asset =
        norito::decode_from_bytes(&norito_body).expect("typed asset Norito");
    assert_eq!(decoded_norito, expected);
    let missing_json_response = super::handler_internal_account_asset_get(
        State(app.clone()),
        format!("/v1/internal/accounts/{authority}/assets/{asset_definition_id}?scope=global")
            .parse()
            .expect("valid missing internal asset URI"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            HeaderValue::from_static("application/json"),
        )),
        AxPath((authority.to_string(), asset_definition_id.to_string())),
    )
    .await
    .expect("missing JSON asset read");
    assert_eq!(missing_json_response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        missing_json_response
            .headers()
            .get(axum::http::header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("application/json")),
    );
    assert_eq!(
        torii_response_header(&missing_json_response, "x-iroha-reject-code"),
        Some("not_found"),
    );
    let missing_json_body =
        torii_body_bytes(missing_json_response, "missing asset JSON body").await;
    let missing_envelope: ErrorEnvelope =
        norito::json::from_slice(&missing_json_body).expect("typed missing asset JSON");
    assert_eq!(missing_envelope.code, "not_found");
    for (account, scope) in [
        (authority.clone(), "global"),
        (authority.clone(), "dataspace:11"),
        (unrelated, "dataspace:10"),
    ] {
        let response = super::execute_trusted_internal_account_asset_local_read(
            &app,
            &account.to_string(),
            &asset_definition_id.to_string(),
            scope,
            ResponseFormat::Json,
        );
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "wrong scope or account binding must not resolve the asset",
        );
    }
    let conflicting = Asset::new(asset_id, Quantity::from(43_u32));
    let owner = super::try_acquire_query_fanout_memory(&app).expect("complete source owner");
    let mut budget = super::COLLECTION_READ_MEMORY_RESERVATION
        .sync_scope(owner.clone(), || {
            super::torii_local_routed_read_budget(&app)
        })
        .expect("local routed-read budget");
    let expected =
        super::torii_bounded_routed_read_source_payload::<Asset, _>(&expected, &mut budget)
            .expect("bound expected asset payload");
    let conflicting =
        super::torii_bounded_routed_read_source_payload::<Asset, _>(&conflicting, &mut budget)
            .expect("bound conflicting asset payload");
    let conflict = match super::merged_trusted_internal_read_response(
        vec![expected, conflicting],
        ResponseFormat::Json,
        "local",
        budget,
    ) {
        Ok(_) => panic!("conflicting route payloads must fail closed"),
        Err(response) => response,
    };
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        torii_response_header(&conflict, "x-iroha-reject-code"),
        Some("route_conflict"),
    );
    assert_eq!(
        conflict.headers().get(axum::http::header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("application/json")),
    );
    let conflict_body = torii_body_bytes(conflict, "route-conflict JSON body").await;
    let conflict_envelope: ErrorEnvelope =
        norito::json::from_slice(&conflict_body).expect("typed route-conflict JSON");
    assert_eq!(conflict_envelope.code, "route_conflict");
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn account_read_for_routes_prefers_not_found_over_route_unavailable_when_missing() {
    let missing =
        checked_torii_test_account_id(0x2d, "derive Torii missing routed account-read fixture key");
    let (app, local_route, stale_route) =
        native_account_read_with_stale_route_for_test(World::default());
    let memory = super::try_acquire_query_fanout_memory(&app)
        .expect("the original query pool admits the complete fanout");
    let response = super::COLLECTION_READ_MEMORY_RESERVATION
        .scope(
            memory,
            super::execute_torii_account_read_for_resolved_routes(
                &app,
                vec![stale_route, local_route],
                super::ToriiFanoutRouteScopeV1::TargetAccount {
                    account_id: missing.to_string(),
                    caller_account_id: Some(missing.to_string()),
                },
                missing.to_string(),
                ResponseFormat::Json,
                None,
            ),
        )
        .await;
    assert_eq!(
        torii_response_header(&response, "x-iroha-fanout-routes-attempted"),
        Some("2"),
    );
    assert_eq!(
        torii_response_header(&response, "x-iroha-fanout-routes-unavailable"),
        Some("1"),
        "the stale route is actually attempted and classified as unavailable",
    );
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_ne!(
        torii_response_header(&response, "x-iroha-reject-code"),
        Some("route_unavailable"),
        "a definitive missing-account response should outrank an unrelated unavailable route",
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn account_read_for_routes_returns_route_unavailable_when_only_unavailable() {
    let missing = checked_torii_test_account_id(
        0x2e,
        "derive Torii unavailable routed account-read fixture key",
    );
    let (app, _local_route, stale_route) =
        native_account_read_with_stale_route_for_test(World::default());
    let memory = super::try_acquire_query_fanout_memory(&app)
        .expect("the original query pool admits the complete fanout");
    let response = super::COLLECTION_READ_MEMORY_RESERVATION
        .scope(
            memory,
            super::execute_torii_account_read_for_resolved_routes(
                &app,
                vec![stale_route],
                super::ToriiFanoutRouteScopeV1::TargetAccount {
                    account_id: missing.to_string(),
                    caller_account_id: Some(missing.to_string()),
                },
                missing.to_string(),
                ResponseFormat::Json,
                None,
            ),
        )
        .await;
    assert_eq!(
        torii_response_header(&response, "x-iroha-fanout-routes-attempted"),
        Some("1"),
    );
    assert_eq!(
        torii_response_header(&response, "x-iroha-fanout-routes-unavailable"),
        Some("1"),
        "the stale route is actually attempted and classified as unavailable",
    );
    assert_route_unavailable_response(&response);
}
// This fixture obtains callbacks from actual H2 execution, including normal signed-genesis
// trigger registration. Only the independent visitor unit test below constructs structural rows.
fn executed_data_trigger_history_fixture() -> (
    SharedAppState,
    PersistedDataTriggerCompletionBlock,
    iroha_core::sumeragi::test_chain::CertifiedTestChain,
) {
    use iroha_core::sumeragi::test_chain::TestChainConfig;
    use iroha_data_model::{
        events::data::prelude::{AccountEventFilter, AccountEventSet, DataEventFilter},
        isi::{Register, SetKeyValue},
        trigger::{
            Trigger,
            action::{Action, Repeats},
        },
    };
    let key = checked_torii_test_ed25519_keypair(0x24, "native data-trigger history authority");
    let authority = AccountId::new(key.public_key().clone());
    let trigger_id: TriggerId = "persisted_data_trigger".parse().unwrap();
    let trigger = Trigger::new(
        trigger_id.clone(),
        Action::new(
            vec![iroha_data_model::isi::InstructionBox::from(Log::new(
                Level::INFO,
                "native persisted data callback".into(),
            ))],
            Repeats::Exactly(1),
            authority.clone(),
            DataEventFilter::Account(
                AccountEventFilter::new()
                    .for_account(authority.clone())
                    .for_events(AccountEventSet::MetadataInserted),
            ),
        )
        .unwrap(),
    );
    let mut config = TestChainConfig::new(world_with_account(&authority), 1_000);
    config
        .genesis_instructions
        .push(Register::trigger(trigger).into());
    let (app, tx_hash, chain) = executed_history_test_fixture(
        config,
        &key,
        vec![
            SetKeyValue::account(
                authority,
                "history_callback".parse().unwrap(),
                "actual source event",
            )
            .into(),
        ],
        true,
    );
    let block = chain.committed(2).block().as_ref().clone();
    let entrypoint_hash = iroha_core::tx::external_entrypoint_hash_from_signed_hash(tx_hash);
    let trigger_execution_hash = block
        .network_entrypoint_at(0)
        .unwrap()
        .execution_call_hash();
    let (_, output) = block.network_output_at(0).unwrap();
    assert_eq!(output.completions.len(), 1, "one actual data invocation");
    assert_eq!(output.completions[0].trigger_id, trigger_id);
    assert_eq!(
        output.completions[0].outcome,
        TriggerCompletedOutcome::Success
    );
    assert_eq!(output.result.as_ref().unwrap().len(), 1);
    let sample = PersistedDataTriggerCompletionBlock {
        block,
        tx_hash,
        entrypoint_hash,
        trigger_execution_hash,
        trigger_id,
    };
    (app, sample, chain)
}

#[test]
fn trigger_completion_query_projects_only_authenticated_persisted_calls() {
    let (app, sample, _chain) = executed_data_trigger_history_fixture();
    let response = super::trigger_completion_query_response(
        &app,
        &TriggerCompletionQuery {
            id: None,
            entrypoint_hash: Some(sample.entrypoint_hash.to_string()),
            outcome: None,
            from_height: Some(2),
            to_height: Some(2),
            limit: Some(10),
            scan_limit_blocks: Some(1),
        },
    )
    .expect("query response");
    assert_eq!(response.completions.len(), 1);
    let record = response.completions.first().expect("completion");
    assert_eq!(record.source, "execution_output");
    assert_eq!(record.block_height, 2);
    assert_eq!(record.entrypoint_index, Some(0));
    assert_eq!(record.completion.trigger_id, sample.trigger_id.to_string());
    assert_eq!(
        record.completion.trigger_execution_hash,
        sample.entrypoint_hash.to_string()
    );
    let missing_call = super::trigger_completion_query_response(
        &app,
        &TriggerCompletionQuery {
            id: None,
            entrypoint_hash: Some(Hash::new(b"missing execution call").to_string()),
            outcome: None,
            from_height: Some(2),
            to_height: Some(2),
            limit: Some(10),
            scan_limit_blocks: Some(1),
        },
    )
    .expect("query response");
    assert!(missing_call.completions.is_empty());
    let persisted_response = super::trigger_completion_query_response(
        &app,
        &TriggerCompletionQuery {
            id: None,
            entrypoint_hash: Some(sample.trigger_execution_hash.to_string()),
            outcome: None,
            from_height: Some(2),
            to_height: Some(2),
            limit: Some(10),
            scan_limit_blocks: Some(1),
        },
    )
    .expect("query response");
    assert_eq!(persisted_response.completions.len(), 1);
    let persisted = persisted_response.completions.first().expect("completion");
    assert_eq!(persisted.source, "execution_output");
    assert_eq!(
        persisted.completion.trigger_execution_hash,
        sample.trigger_execution_hash.to_string()
    );
}
#[test]
fn trigger_completion_record_visit_stops_without_buffering_the_block() {
    let mut sample = make_persisted_data_trigger_completion_block(1, None);
    use iroha_data_model::block::execution_output::{ExecutionOutputV1, InvocationCompletionV1};
    let mut rows = sample.block.execution_outputs().to_vec();
    let ExecutionOutputV1::Network(row) = &mut rows[0] else {
        unreachable!()
    };
    let step = DataTriggerStep {
        id: sample.trigger_id.clone(),
        instructions: ExecutionStep(ConstVec::new_empty()),
    };
    row.result =
        iroha_data_model::transaction::TransactionResult::new(Ok(vec![step.clone(), step]));
    row.completions.push(InvocationCompletionV1 {
        trigger_id: sample.trigger_id.clone(),
        callback_index: 1,
        outcome: TriggerCompletedOutcome::Success,
    });
    crate::test_utils::attach_fixture_execution_outputs(&mut sample.block, rows);
    let mut visited = 0_u8;
    let completed = super::visit_trigger_completion_records_for_block(&sample.block, 1, |_| {
        visited = visited.saturating_add(1);
        false
    })
    .unwrap();
    assert!(!completed);
    assert_eq!(
        visited, 1,
        "the visitor must stop before building later records"
    );
}
#[test]
fn trigger_completion_query_caps_explicit_from_height() {
    let (app, sample, mut chain) = executed_data_trigger_history_fixture();
    // Append unrelated real work at H3..H5 through the same execution/certification owner.
    for _ in 3..=5 {
        chain.commit(Vec::new());
    }
    assert_eq!(chain.height(), 5);
    let bounded_window = super::trigger_completion_query_response(
        &app,
        &TriggerCompletionQuery {
            id: Some(sample.trigger_id.to_string()),
            entrypoint_hash: None,
            outcome: None,
            from_height: None,
            to_height: Some(5),
            limit: Some(10),
            scan_limit_blocks: Some(2),
        },
    )
    .expect("query response");
    assert_eq!(bounded_window.from_height, 4);
    assert_eq!(bounded_window.scanned_blocks, 2);
    assert!(bounded_window.completions.is_empty());
    let explicit_history = super::trigger_completion_query_response(
        &app,
        &TriggerCompletionQuery {
            id: Some(sample.trigger_id.to_string()),
            entrypoint_hash: None,
            outcome: None,
            from_height: Some(1),
            to_height: Some(5),
            limit: Some(10),
            scan_limit_blocks: Some(2),
        },
    )
    .expect("query response");
    assert_eq!(explicit_history.from_height, 4);
    assert_eq!(explicit_history.scanned_blocks, 2);
    assert!(explicit_history.completions.is_empty());
}
fn native_ingress_app_for_test(keys: &[&KeyPair]) -> SharedAppState {
    let accounts = keys
        .iter()
        .map(|key| AccountId::new(key.public_key().clone()))
        .map(|authority| Account::new(authority.clone()).build(&authority));
    native_ingress_app_with_world_for_test(World::with([], accounts, []))
}

/// Build a local authoritative reader from an executed four-validator genesis.
pub(crate) fn native_ingress_app_with_world_for_test(world: World) -> SharedAppState {
    native_ingress_app_with_world_at_time_for_test(world, 1_000)
}

/// Build the reader at an actual certified genesis timestamp for lease observations.
pub(crate) fn native_ingress_app_with_world_at_time_for_test(
    world: World,
    genesis_time_ms: u64,
) -> SharedAppState {
    native_ingress_app_with_config_for_test(iroha_core::sumeragi::test_chain::TestChainConfig::new(
        world,
        genesis_time_ms,
    ))
}

/// Bind physical routing labels to the same genuine signed global committee.
pub(crate) fn native_ingress_app_with_world_and_nexus_for_test(
    world: World,
    nexus: iroha_config::parameters::actual::Nexus,
) -> SharedAppState {
    let mut config = iroha_core::sumeragi::test_chain::TestChainConfig::new(world, 1_000);
    config.nexus = Some(nexus);
    native_ingress_app_with_config_for_test(config)
}

fn native_ingress_app_with_config_for_test(
    config: iroha_core::sumeragi::test_chain::TestChainConfig,
) -> SharedAppState {
    use iroha_core::sumeragi::test_chain::CertifiedTestChain;
    let prepared =
        CertifiedTestChain::prepare(config).expect("prepare signed native ingress genesis");
    let validator = prepared.validator_keys[0].clone();
    let chain =
        CertifiedTestChain::from_prepared(prepared).expect("execute signed native ingress genesis");
    let mut app = mk_app_state_for_tests();
    let unique = Arc::get_mut(&mut app).unwrap();
    unique.chain_id = Arc::new(chain.state().view().chain_id().clone());
    unique.state = chain.state().clone();
    unique.kura = chain.kura().clone();
    {
        let view = unique.state.view();
        unique.queue.reconfigure_nexus(view.nexus(), &view, None);
    }
    unique.local_peer_id = Some(PeerId::new(validator.public_key().clone()));
    unique.torii_proxy_bridge_signer = validator;
    unique.signed_query_admission = Arc::new(
        routing::SignedQueryAdmission::new(
            chain.network_id(),
            Duration::from_secs(1),
            Duration::from_secs(120),
            NonZeroUsize::new(1_024).unwrap(),
        )
        .expect("native genesis query admission"),
    );
    app
}

/// Execute genuine four-seat genesis plus paid H2/H3 registrations without retaining a fixture driver.
fn native_ingress_with_registered_route_peers_for_test(
    world: World,
    nexus: iroha_config::parameters::actual::Nexus,
    members: &[(AccountId, KeyPair)],
    labels: &[String],
) -> SharedAppState {
    native_ingress_with_registered_route_peers_and_chain_for_test(
        world,
        nexus,
        members,
        labels,
        Vec::new(),
    )
    .0
}

/// Execute four genesis voters, then register and mature additional route peers through paid H2/H3 work.
fn native_ingress_with_registered_route_peers_and_chain_for_test(
    world: World,
    nexus: iroha_config::parameters::actual::Nexus,
    members: &[(AccountId, KeyPair)],
    labels: &[String],
    genesis_parameters: Vec<iroha_data_model::parameter::Parameter>,
) -> (
    SharedAppState,
    iroha_core::sumeragi::test_chain::CertifiedTestChain,
    KeyPair,
) {
    use iroha_core::sumeragi::test_chain::TestChainConfig;
    assert!(
        members.len() > 4,
        "this fixture has post-genesis route peers"
    );
    assert_eq!(labels.len(), members.len());
    let fee_asset: AssetDefinitionId = nexus.fees.fee_asset_id.parse().expect("original fee asset");
    assert!(
        world.view().asset_definition(&fee_asset).is_err(),
        "fixture fee currency is seeded once"
    );
    let mut config = TestChainConfig::new(world, 1_000);
    config.nexus = Some(nexus);
    config.genesis_parameters.extend(genesis_parameters);
    config.validator_keys = Some(members[..4].iter().map(|(_, key)| key.clone()).collect());
    let genesis_key = config.genesis_key.clone();
    let genesis = AccountId::new(genesis_key.public_key().clone());
    config.genesis_instructions.push(
        Grant::account_permission(Permission::from(CanManageConsensusKeys), genesis.clone()).into(),
    );
    config.genesis_instructions.push(
        Grant::account_permission(
            Permission::from(iroha_executor_data_model::permission::peer::CanManagePeers),
            genesis.clone(),
        )
        .into(),
    );
    config.genesis_instructions.push(
        Register::asset_definition(iroha_data_model::asset::AssetDefinition::numeric(
            fee_asset.clone(),
            "XOR".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .into(),
    );
    config.genesis_instructions.push(
        iroha_data_model::isi::Mint::asset_quantity(
            1_u32,
            AssetId::new(fee_asset.clone(), genesis.clone()),
        )
        .into(),
    );
    let mut additional_peers = Vec::new();
    for (index, ((validator, key), label)) in members.iter().zip(labels).enumerate() {
        config
            .genesis_instructions
            .push(Register::account(Account::new(validator.clone())).into());
        config.genesis_instructions.push(
            Grant::account_permission(Permission::from(CanManageConsensusKeys), validator.clone())
                .into(),
        );
        let pop =
            iroha_crypto::bls_normal_pop_prove(key.private_key()).expect("original route peer PoP");
        if index >= 4 {
            additional_peers.push(
                RegisterPeerWithPop::new(PeerId::new(key.public_key().clone()), pop.clone()).into(),
            );
        }
        // Additional identities are introduced after registration, preserving the
        // one-block activation lead in their actual signed H2 instructions.
        for role in [ConsensusKeyRole::Validator, ConsensusKeyRole::Committee] {
            let id = ConsensusKeyId::new(role, label.as_str());
            let instruction = RegisterConsensusKey {
                id: id.clone(),
                record: ConsensusKeyRecord {
                    id,
                    public_key: key.public_key().clone(),
                    pop: Some(pop.clone()),
                    activation_height: if index < 4 { 1 } else { 3 },
                    expiry_height: None,
                    replaces: None,
                    status: if index < 4 {
                        ConsensusKeyStatus::Active
                    } else {
                        ConsensusKeyStatus::Pending
                    },
                },
            }
            .into();
            if index < 4 {
                config.genesis_instructions.push(instruction);
            } else {
                additional_peers.push(instruction);
            }
        }
    }
    let (mut app, original_hash, mut chain) =
        executed_history_test_fixture(config, &genesis_key, additional_peers, true);
    assert_original_paid_registration_receipt_for_test(&app, &chain, original_hash, &fee_asset);
    assert_eq!(
        chain
            .state()
            .view()
            .world()
            .parameters()
            .sumeragi
            .key_activation_lead_blocks,
        1
    );
    let mut next = TransactionBuilder::new(
        chain.network_id(),
        AccountId::new(genesis_key.public_key().clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    next.set_creation_time(Duration::from_millis(1_002));
    next = next.with_instructions([Log::new(
        Level::INFO,
        "mature original registered route keys".to_owned(),
    )]);
    let draft = next.clone().sign(genesis_key.private_key());
    let quote = {
        let view = chain.state().view();
        iroha_core::executor::quote_nexus_fee_admission_draft(
            view.world(),
            view.nexus(),
            view.pipeline(),
            draft.payload(),
            1_002,
            3,
            Some(DataSpaceId::UNIVERSAL),
        )
        .expect("actual H3 work receives the unchanged native fee quote")
    };
    assert_eq!(quote.quote.charges.len(), 1);
    let transaction = next
        .with_fee_payment_intent(quote.recommended_intent)
        .sign(genesis_key.private_key());
    let entrypoint = transaction.hash_as_entrypoint();
    assert_eq!(
        chain.commit(vec![transaction]),
        vec![true],
        "genuine paid H3 maturity work"
    );
    assert!(app.state.has_committed_entrypoint(entrypoint));
    assert!(
        chain
            .committed(3)
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result
            .is_ok()
    );
    let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let committee = app
        .state
        .resolve_route_authority(super::lane_authority_route(route))
        .expect("genuine H3 retains the original four-seat global authority");
    assert_eq!(committee.authority_height(), 3);
    let mut original = members[..4]
        .iter()
        .map(|(_, key)| PeerId::new(key.public_key().clone()))
        .collect::<Vec<_>>();
    original.sort();
    assert_eq!(committee.into_validators(), original);
    let view = app.state.view();
    for (validator, key) in members {
        assert!(view.world().account(validator).is_ok());
        assert!(
            view.world()
                .peers()
                .iter()
                .any(|peer| peer == &PeerId::new(key.public_key().clone()))
        );
    }
    let payer_asset = AssetId::new(fee_asset.clone(), genesis);
    let balance = view
        .world()
        .assets()
        .get(&payer_asset)
        .expect("original funded payer")
        .as_ref()
        .clone();
    let supply = view
        .world()
        .asset_definition(&fee_asset)
        .unwrap()
        .total_quantity()
        .clone();
    assert!(
        balance < Quantity::from(1_u32),
        "ordinary Nexus fee was charged"
    );
    assert_eq!(balance, supply, "the original fee burns its exact supply");
    drop(view);
    let unique = Arc::get_mut(&mut app).expect("unique genuinely executed fixture");
    unique.chain_id = Arc::new(chain.state().view().chain_id().clone());
    unique.local_peer_id = Some(PeerId::new(members[0].1.public_key().clone()));
    unique.torii_proxy_bridge_signer = members[0].1.clone();
    let view = unique.state.view();
    unique.queue.reconfigure_nexus(view.nexus(), &view, None);
    drop(view);
    (app, chain, genesis_key)
}

/// Advance the original executed fixture with a genuinely quoted, paid transaction at each height.
#[cfg(feature = "connect")]
fn advance_registered_route_fixture_for_test(
    chain: &mut iroha_core::sumeragi::test_chain::CertifiedTestChain,
    genesis_key: &KeyPair,
    target_height: u64,
) {
    assert!(target_height > chain.height());
    while chain.height() < target_height {
        let height = chain.height() + 1;
        let created_ms = 1_000 + height - 1;
        let mut next = TransactionBuilder::new(
            chain.network_id(),
            AccountId::new(genesis_key.public_key().clone()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        next.set_creation_time(Duration::from_millis(created_ms));
        next = next.with_instructions([Log::new(
            Level::INFO,
            format!("advance original route fixture to height {height}"),
        )]);
        let draft = next.clone().sign(genesis_key.private_key());
        let quote = {
            let view = chain.state().view();
            iroha_core::executor::quote_nexus_fee_admission_draft(
                view.world(),
                view.nexus(),
                view.pipeline(),
                draft.payload(),
                created_ms,
                height,
                Some(DataSpaceId::UNIVERSAL),
            )
            .expect("actual original paid route advancement quote")
        };
        assert_eq!(quote.quote.charges.len(), 1);
        let transaction = next
            .with_fee_payment_intent(quote.recommended_intent)
            .sign(genesis_key.private_key());
        let entrypoint = transaction.hash_as_entrypoint();
        assert_eq!(chain.commit(vec![transaction]), vec![true]);
        assert!(chain.state().has_committed_entrypoint(entrypoint));
        assert_eq!(chain.height(), height);
        assert!(
            chain
                .committed(height)
                .block()
                .network_output_at(0)
                .unwrap()
                .1
                .result
                .is_ok()
        );
    }
}

/// Check the original H2 receipt in a separate completed read before producing H3 work.
fn assert_original_paid_registration_receipt_for_test(
    app: &SharedAppState,
    chain: &iroha_core::sumeragi::test_chain::CertifiedTestChain,
    original_hash: HashOf<SignedTransaction>,
    fee_asset: &AssetDefinitionId,
) {
    let receipt = chain.committed(2);
    assert_eq!(receipt.block().external_transactions().count(), 1);
    assert_eq!(
        receipt
            .block()
            .external_transactions()
            .next()
            .unwrap()
            .hash(),
        original_hash
    );
    assert!(
        receipt
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result
            .is_ok()
    );
    assert!(
        app.state.has_committed_entrypoint(
            receipt
                .block()
                .external_transactions()
                .next()
                .unwrap()
                .hash_as_entrypoint(),
        )
    );
    let original_intent = receipt
        .block()
        .external_transactions()
        .next()
        .unwrap()
        .fee_payment_intent();
    assert_eq!(original_intent.charge_limits().len(), 1);
    assert_eq!(
        original_intent.charge_limits()[0].asset_definition_id(),
        fee_asset
    );
    assert_eq!(
        original_intent.charge_limits()[0].kind(),
        iroha_data_model::transaction::FeeChargeKind::Nexus
    );
}

fn assert_native_pending_for_test(app: &SharedAppState, transaction: &SignedTransaction) {
    use iroha_version::codec::EncodeVersioned as _;
    assert!(
        app.queue
            .contains_pending_hash(transaction.hash_as_entrypoint(), &app.state)
    );
    assert!(
        lifecycle_pending_wire(app)
            .contains(&TransactionEntrypoint::External(transaction.clone()).encode_versioned())
    );
    assert!(
        !app.state
            .has_committed_entrypoint(transaction.hash_as_entrypoint())
    );
}

fn executed_history_test_fixture(
    config: iroha_core::sumeragi::test_chain::TestChainConfig,
    key: &KeyPair,
    instructions: Vec<iroha_data_model::isi::InstructionBox>,
    expected_applied: bool,
) -> (
    SharedAppState,
    HashOf<SignedTransaction>,
    iroha_core::sumeragi::test_chain::CertifiedTestChain,
) {
    use iroha_core::sumeragi::test_chain::CertifiedTestChain;
    let creation_time = config.genesis_time_ms.checked_add(1).unwrap();
    let nexus = config.nexus.clone();
    let mut chain = CertifiedTestChain::start(config).unwrap();
    let mut builder = TransactionBuilder::new(
        chain.network_id(),
        AccountId::new(key.public_key().clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(Duration::from_millis(creation_time));
    builder = builder.with_instructions(instructions);
    if let Some(nexus) = nexus {
        let draft = builder.clone().sign(key.private_key());
        let view = chain.state().view();
        let quote = iroha_core::executor::quote_nexus_fee_admission_draft(
            view.world(),
            &nexus,
            view.pipeline(),
            draft.payload(),
            creation_time,
            2,
            Some(DataSpaceId::UNIVERSAL),
        )
        .expect("the original funded fixture receives Core's exact fee intent");
        assert_eq!(
            quote.quote.charges.len(),
            1,
            "one original native Nexus fee component"
        );
        builder = builder.with_fee_payment_intent(quote.recommended_intent);
    }
    let transaction = builder.sign(key.private_key());
    let hash = transaction.hash();
    let observed = chain.commit(vec![transaction]);
    assert_eq!(
        observed,
        vec![expected_applied],
        "original native result: {:?}",
        chain
            .committed(2)
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result
    );
    let mut app = mk_app_state_for_tests();
    let unique = Arc::get_mut(&mut app).unwrap();
    unique.state = chain.state().clone();
    unique.kura = chain.kura().clone();
    unique.signed_query_admission = Arc::new(
        routing::SignedQueryAdmission::new(
            chain.network_id(),
            Duration::from_secs(1),
            Duration::from_secs(120),
            NonZeroUsize::new(1_024).unwrap(),
        )
        .expect("signed queries use the original native genesis network"),
    );
    (app, hash, chain)
}

fn canonical_outcome_test_fixture(
    rejected: bool,
) -> (
    SharedAppState,
    HashOf<SignedTransaction>,
    iroha_core::sumeragi::test_chain::CertifiedTestChain,
) {
    use iroha_core::sumeragi::test_chain::TestChainConfig;
    let key = checked_torii_test_ed25519_keypair(0x24, "native history authority");
    let authority = AccountId::new(key.public_key().clone());
    let instruction: iroha_data_model::isi::InstructionBox = if rejected {
        iroha_data_model::isi::Unregister::domain(
            DomainId::try_new("missing_history_domain", "universal").unwrap(),
        )
        .into()
    } else {
        Log::new(Level::INFO, "native canonical history".into()).into()
    };
    executed_history_test_fixture(
        TestChainConfig::new(world_with_account(&authority), 1_000),
        &key,
        vec![instruction],
        !rejected,
    )
}

fn append_canonical_outcome_test_block(
    chain: &mut iroha_core::sumeragi::test_chain::CertifiedTestChain,
    anchor: CanonicalTransactionAnchor,
    rebind_transaction: bool,
) {
    // Execute unrelated real work through the same native owner. Only the negative case
    // subsequently corrupts the membership index; no duplicate transaction is certified.
    chain.commit(Vec::new());
    let height = NonZeroUsize::new(usize::try_from(chain.height()).unwrap()).unwrap();
    assert_eq!(height.get(), anchor.height.get() + 1);
    if rebind_transaction {
        let mut membership = chain.state().transactions.block_and_revert();
        membership.insert_block([anchor.entrypoint_hash].into_iter().collect(), height);
        membership
            .commit()
            .expect("adversarially rebind the original membership to another genuine carrier");
    }
}
#[tokio::test]
async fn canonical_outcome_releases_state_snapshot_before_kura_authentication() {
    let (app, hash, chain) = canonical_outcome_test_fixture(false);
    let expected_settled_at = UNIX_EPOCH
        .checked_add(chain.committed(2).block().header().creation_time())
        .expect("the genuine carrier has a representable settlement time");
    // Give this State a unique configuration allocation, then prove a real
    // StateView retains it. No timer, reclamation schedule, or global counter
    // is involved in the release assertion at the actual auth handoff.
    let crypto = Arc::new((*app.state.crypto()).clone());
    *app.state.crypto.write() = crypto.clone();
    let baseline = Arc::strong_count(&crypto);
    assert_eq!(
        baseline, 2,
        "only State and this test own the unique snapshot"
    );
    let view = app.state.view();
    assert_eq!(Arc::strong_count(&crypto), baseline + 1);
    drop(view);
    assert_eq!(Arc::strong_count(&crypto), baseline);
    let mut calls = 0;
    let outcome = canonical_transaction_outcome_with_authenticator(&app.state, &hash, |anchor| {
        calls += 1;
        assert_eq!(
            Arc::strong_count(&crypto),
            baseline,
            "the complete StateView must be dropped before Kura/authentication"
        );
        let outcome = authenticate_canonical_transaction_outcome(&app.state, &hash, anchor)?;
        assert_eq!(Arc::strong_count(&crypto), baseline);
        Ok(outcome)
    })
    .expect("stable canonical binding")
    .expect("indexed transaction");
    assert_eq!(calls, 1);
    assert!(matches!(
        outcome,
        CanonicalTransactionOutcome::Applied { height, settled_at }
            if height.get() == 2 && settled_at == expected_settled_at
    ));
    assert_eq!(Arc::strong_count(&crypto), baseline);
}
#[tokio::test]
async fn canonical_outcome_preserves_exact_committed_rejection() {
    let (app, hash, chain) = canonical_outcome_test_fixture(true);
    let reason = chain
        .committed(2)
        .block()
        .network_output_at(0)
        .unwrap()
        .1
        .result
        .as_ref()
        .unwrap_err()
        .clone();
    let outcome = canonical_transaction_outcome(&app.state, &hash)
        .expect("stable rejection binding")
        .expect("indexed rejected transaction");
    assert!(matches!(
        outcome,
        CanonicalTransactionOutcome::Rejected { height, reason: actual }
            if height.get() == 2 && actual == reason
    ));
}
#[tokio::test]
async fn canonical_outcome_absent_membership_never_authenticates() {
    let app = mk_app_state_for_tests();
    let hash = HashOf::from_untyped_unchecked(Hash::new(b"unindexed canonical outcome"));
    let result = canonical_transaction_outcome_with_authenticator(&app.state, &hash, |_| {
        panic!("absent State membership must not enter Kura/authentication")
    })
    .expect("absence is not an inconsistent projection");
    assert!(result.is_none());
}
#[tokio::test]
async fn canonical_outcome_accepts_unrelated_state_append_after_authentication() {
    let (app, hash, mut chain) = canonical_outcome_test_fixture(false);
    let mut calls = 0;
    let outcome = canonical_transaction_outcome_with_authenticator(&app.state, &hash, |anchor| {
        calls += 1;
        let outcome = authenticate_canonical_transaction_outcome(&app.state, &hash, anchor)?;
        append_canonical_outcome_test_block(&mut chain, anchor, false);
        assert_eq!(app.state.view().block_hashes().len(), 3);
        assert_eq!(
            canonical_transaction_anchor(&app.state, &hash)?,
            Some(anchor)
        );
        Ok(outcome)
    })
    .expect("an unrelated append preserves the exact committed carrier")
    .expect("indexed transaction");
    assert_eq!(calls, 1, "height progress must not restart authentication");
    assert!(
        matches!(outcome, CanonicalTransactionOutcome::Applied { height, .. } if height.get() == 2)
    );
}
#[tokio::test]
async fn canonical_outcome_rejects_removed_membership_after_authentication() {
    for rejected in [false, true] {
        let (app, hash, _chain) = canonical_outcome_test_fixture(rejected);
        let mut calls = 0;
        let result =
            canonical_transaction_outcome_with_authenticator(&app.state, &hash, |anchor| {
                calls += 1;
                let outcome =
                    authenticate_canonical_transaction_outcome(&app.state, &hash, anchor)?;
                assert_eq!(
                    matches!(outcome, CanonicalTransactionOutcome::Rejected { .. }),
                    rejected
                );
                // Mutate the actual indexed store, not a detached State clone.
                let mut membership = app.state.transactions.block_and_revert();
                membership.insert_block(HashSet::new(), anchor.height);
                membership
                    .commit()
                    .expect("remove latest fixture membership");
                assert!(canonical_transaction_anchor(&app.state, &hash)?.is_none());
                Ok(outcome)
            });
        let error = result.expect_err("neither terminal disposition survives removal");
        assert!(
            query_conversion_message(&error)
                .expect("projection error")
                .contains("canonical binding changed during outcome authentication")
        );
        assert_eq!(calls, 1, "a changed binding fails closed without retry");
    }
}
#[tokio::test]
async fn canonical_outcome_rejects_rebound_membership_after_authentication() {
    let (app, hash, mut chain) = canonical_outcome_test_fixture(false);
    let result = canonical_transaction_outcome_with_authenticator(&app.state, &hash, |anchor| {
        let outcome = authenticate_canonical_transaction_outcome(&app.state, &hash, anchor)?;
        append_canonical_outcome_test_block(&mut chain, anchor, true);
        let rebound = canonical_transaction_anchor(&app.state, &hash)?.expect("rebound membership");
        assert_eq!(rebound.entrypoint_hash, anchor.entrypoint_hash);
        assert_eq!(rebound.height.get(), 3);
        assert_ne!(rebound.block_hash, anchor.block_hash);
        Ok(outcome)
    });
    let error = result.expect_err("the old carrier is no longer the indexed authority");
    assert!(
        query_conversion_message(&error)
            .expect("projection error")
            .contains("canonical binding changed during outcome authentication")
    );
}
#[tokio::test]
async fn canonical_outcome_rejects_replaced_journal_after_authentication() {
    let (app, hash, _chain) = canonical_outcome_test_fixture(false);
    let result = canonical_transaction_outcome_with_authenticator(&app.state, &hash, |anchor| {
        let outcome = authenticate_canonical_transaction_outcome(&app.state, &hash, anchor)?;
        let replacement = HashOf::from_untyped_unchecked(Hash::new(b"replaced outcome carrier"));
        assert_ne!(replacement, anchor.block_hash);
        let mut journal = app.state.block_hashes.block_and_revert();
        journal.push_for_tests(replacement);
        journal.commit_for_tests();
        let rebound =
            canonical_transaction_anchor(&app.state, &hash)?.expect("retained membership");
        assert_eq!(rebound.height, anchor.height);
        assert_eq!(rebound.block_hash, replacement);
        Ok(outcome)
    });
    let error = result.expect_err("same-height journal replacement invalidates the result");
    assert!(
        query_conversion_message(&error)
            .expect("projection error")
            .contains("canonical binding changed during outcome authentication")
    );
}
#[tokio::test]
async fn canonical_outcome_rejects_missing_journal_after_authentication() {
    let (app, hash, _chain) = canonical_outcome_test_fixture(false);
    let result = canonical_transaction_outcome_with_authenticator(&app.state, &hash, |anchor| {
        let outcome = authenticate_canonical_transaction_outcome(&app.state, &hash, anchor)?;
        app.state.block_hashes.block_and_revert().commit_for_tests();
        assert_eq!(
            app.state.view().block_hashes().len(),
            1,
            "genesis remains, but the exact H2 carrier journal entry is absent"
        );
        Ok(outcome)
    });
    let error = result.expect_err("an incomplete State journal cannot authenticate the outcome");
    assert!(
        query_conversion_message(&error)
            .expect("projection error")
            .contains("indexed beyond the committed block-hash journal")
    );
}
#[tokio::test]
async fn canonical_outcome_rejects_result_substitution_under_the_same_header_hash() {
    let (app, hash, _chain) = canonical_outcome_test_fixture(false);
    let anchor = canonical_transaction_anchor(&app.state, &hash)
        .expect("consistent State")
        .expect("indexed transaction");
    let canonical = app
        .kura
        .get_block(anchor.height, &app.state.ivm_execution_budget())
        .expect("admit canonical block")
        .expect("canonical block");
    let mut replacement = canonical.as_ref().clone();
    crate::test_utils::attach_fixture_execution_outputs(
        &mut replacement,
        vec![
            iroha_data_model::block::execution_output::ExecutionOutputV1::Network(
                iroha_data_model::block::execution_output::NetworkExecutionOutputV1 {
                    input_index: 0,
                    result: iroha_data_model::transaction::TransactionResult::new(Err(
                        TransactionRejectionReason::Validation(ValidationFail::TooComplex),
                    )),
                    completions: vec![],
                },
            ),
        ],
    );
    assert_eq!(
        replacement.hash(),
        canonical.hash(),
        "header hash omits execution results"
    );
    assert_ne!(
        replacement.output_merkle_commitment(),
        canonical.output_merkle_commitment()
    );
    assert_ne!(
        replacement.encode_wire().expect("replacement wire"),
        canonical.encode_wire().expect("canonical wire")
    );
    assert!(matches!(
        app.kura.store_block(
            iroha_data_model::block::SharedSignedBlock::try_new(
                replacement.clone(),
                &app.state.ivm_execution_budget()
            )
            .expect("fund deliberate replacement fixture")
        ),
        Err(iroha_core::kura::Error::CanonicalBlockWireMismatch { height: 2 })
    ));
    let outcome = canonical_transaction_outcome(&app.state, &hash)
        .expect("rejected mutations preserve canonical authority")
        .expect("indexed transaction");
    assert!(
        matches!(outcome, CanonicalTransactionOutcome::Applied { height, .. } if height.get() == 2)
    );
}
#[tokio::test]
async fn canonical_outcome_authentication_error_cannot_fall_back_to_terminal_cache() {
    let (app, hash, _chain) = canonical_outcome_test_fixture(false);
    app.pipeline_status_cache.record_entry(
        hash,
        PipelineStatusEntry::fresh(
            PipelineStatusKind::Applied,
            Some(NonZeroU64::new(2).expect("height")),
            None,
        ),
    );
    let mut journal = app.state.block_hashes.block_and_revert();
    journal.push_for_tests(HashOf::from_untyped_unchecked(Hash::new(
        b"mismatched State authority",
    )));
    journal.commit_for_tests();
    let error = pipeline_status_terminal_or_state_entry(&app, &hash)
        .expect_err("a cached terminal result must not mask canonical authentication failure");
    assert_eq!(
        query_conversion_message(&error).expect("projection error"),
        "native execution parent contradicts State hash at 2",
        "an unavailable exact canonical hash cannot inherit a cached terminal result",
    );
    assert_eq!(
        app.pipeline_status_cache
            .lookup(&hash)
            .expect("retained test cache")
            .kind,
        PipelineStatusKind::Applied
    );
}
#[tokio::test]
async fn pipeline_status_handler_returns_applied_from_state() {
    let (app, tx_hash, _chain) = canonical_outcome_test_fixture(false);
    let tx_entry_hash = iroha_core::tx::external_entrypoint_hash_from_signed_hash(tx_hash);
    let resp = pipeline_status_response(app.clone(), tx_hash.to_string(), None, "ok").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let payload = torii_json_body(resp).await;
    let status_kind = payload
        .get("status")
        .and_then(|status| status.get("kind"))
        .and_then(norito::json::Value::as_str);
    assert_eq!(status_kind, Some("Applied"));
    let resp_entry =
        pipeline_status_response(app.clone(), tx_entry_hash.to_string(), None, "ok").await;
    assert_eq!(resp_entry.status(), StatusCode::OK);
    let payload_entry = torii_json_body(resp_entry).await;
    let status_kind_entry = payload_entry
        .get("status")
        .and_then(|status| status.get("kind"))
        .and_then(norito::json::Value::as_str);
    assert_eq!(status_kind_entry, Some("Applied"));
}
#[tokio::test]
async fn pipeline_status_handler_rejects_inconsistent_committed_membership() {
    let (app, _hash, _chain) = canonical_outcome_test_fixture(false);
    let bogus_hash = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::prehashed(
        [0x76; Hash::LENGTH],
    ));
    // Corrupt only membership after the original H2 execution and certification.
    let mut membership = app.state.transactions.block_and_revert();
    membership.insert_block(
        [bogus_hash].into_iter().collect(),
        NonZeroUsize::new(2).unwrap(),
    );
    membership
        .commit()
        .expect("commit inconsistent fixture membership");
    let result = super::handler_pipeline_transaction_status(
        State(app),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            HeaderValue::from_static("application/json"),
        )),
        crate::NoritoStringQuery(PipelineStatusQuery {
            hash: Some(bogus_hash.to_string()),
            scope: Some("local".to_owned()),
        }),
    )
    .await;
    let Err(super::Error::Query(ValidationFail::QueryFailed(
        iroha_data_model::query::error::QueryExecutionFail::Conversion(message),
    ))) = result
    else {
        panic!("inconsistent committed membership must fail closed");
    };
    assert_eq!(
        message,
        format!(
            "committed transaction status projection is inconsistent: transaction {bogus_hash} is absent from its finalized carrier"
        ),
        "authenticated output absence must not be confused with missing finality",
    );
}
#[tokio::test]
async fn public_pipeline_status_never_hydrates_trigger_completion_details() {
    let (app, sample, _chain) = executed_data_trigger_history_fixture();
    let resp = pipeline_status_response(app.clone(), sample.tx_hash.to_string(), None, "ok").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let payload = torii_json_body(resp).await;
    assert_eq!(
        payload
            .get("status")
            .and_then(|status| status.get("kind"))
            .and_then(norito::json::Value::as_str),
        Some("Applied")
    );
    assert!(payload.get("trigger_completions").is_none());
    assert!(payload.get("batch_transfer_outcomes").is_none());
    let encoded = norito::json::to_json(&payload).expect("public status JSON");
    assert!(!encoded.contains(&sample.trigger_id.to_string()));
}
fn transaction_details_test_world(accounts: &[AccountId]) -> World {
    let owner = accounts.first().expect("at least one test account");
    let domain = Domain::new(
        DomainId::try_new("wonderland", "universal").expect("transaction-details test domain"),
    )
    .build(owner);
    let accounts = accounts
        .iter()
        .cloned()
        .map(|account_id| Account::new(account_id).build(owner));
    World::with([domain], accounts, [])
}
// Deliberately omit native certification: raw custody and an index are not finality.
fn store_unverified_transaction_details_block(
    app: &SharedAppState,
    block: SignedBlock,
    entrypoint_hash: HashOf<TransactionEntrypoint>,
) -> HashOf<SignedTransaction> {
    let signed_hash = block
        .external_transactions()
        .next()
        .expect("transaction-details fixture contains an external transaction")
        .hash();
    assert_eq!(
        iroha_core::tx::external_entrypoint_hash_from_signed_hash(signed_hash),
        entrypoint_hash,
    );
    let header = block.header();
    let height = NonZeroUsize::new(
        usize::try_from(header.height().get()).expect("transaction-details height fits usize"),
    )
    .expect("transaction-details height is nonzero");
    let block_hash = store_block(app, block);
    let mut state_block = app.state.block(header.clone());
    state_block.block_hashes.push_for_tests(block_hash);
    state_block
        .transactions
        .insert_block([entrypoint_hash].into_iter().collect(), height);
    state_block
        .commit()
        .expect("commit transaction-details membership index");
    app.state.update_latest_block_header_cache_for_tests(header);
    signed_hash
}
fn signed_transaction_details_query(
    app: &SharedAppState,
    key_pair: &KeyPair,
    entrypoint_hash: HashOf<TransactionEntrypoint>,
) -> SignedQuery {
    let mut request = authorize_query_for_test(
        iroha_data_model::query::QueryRequest::Start(
            build_exact_transaction_details_query_for_test(entrypoint_hash),
        ),
        AccountId::new(key_pair.public_key().clone()),
    );
    request.network_id = *app.state.network_id_ref();
    request.sign(key_pair)
}
#[tokio::test]
async fn transaction_details_http_sdk_preserves_exact_absence_and_authorization() {
    use axum::{
        Router,
        routing::{get, post},
    };
    use iroha_data_model::query::error::QueryExecutionFail;
    let sender_key = checked_torii_test_ed25519_keypair(0x24, "exact proof HTTP sender");
    let reader_key = checked_torii_test_ed25519_keypair(0x45, "exact proof HTTP registered reader");
    let unknown_key = checked_torii_test_ed25519_keypair(0x46, "exact proof HTTP unknown signer");
    let (app, signed_hash, _chain) = executed_history_test_fixture(
        iroha_core::sumeragi::test_chain::TestChainConfig::new(
            transaction_details_test_world(&[
                AccountId::new(sender_key.public_key().clone()),
                AccountId::new(reader_key.public_key().clone()),
            ]),
            1_000,
        ),
        &sender_key,
        vec![Log::new(Level::INFO, "native HTTP transaction details".into()).into()],
        true,
    );
    let committed_hash = iroha_core::tx::external_entrypoint_hash_from_signed_hash(signed_hash);
    let missing_hash =
        HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::new(b"absent exact proof"));
    let network_id = *app.state.network_id_ref();
    let router = Router::new()
        .route(
            route_catalog::pipeline::TRANSACTION_DETAILS.path(),
            post(super::handler_pipeline_transaction_details),
        )
        .route(
            "/v1/node/capabilities",
            get(super::handler_node_capabilities),
        )
        .fallback(super::handler_route_not_found)
        .layer(axum::middleware::from_fn(super::capture_response_format))
        .layer(axum::middleware::from_fn(
            super::enforce_typed_error_contract,
        ))
        .with_state(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind exact proof fixture");
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("serve exact proof fixture");
    });
    for (key_pair, hash, expected_missing, expected_success) in [
        (reader_key.clone(), missing_hash, true, false),
        (unknown_key, missing_hash, false, false),
        (reader_key, committed_hash, false, false),
        (sender_key, committed_hash, false, true),
    ] {
        let config = iroha::config::Config {
            chain: "exact-proof-fixture".into(),
            network_id,
            account: AccountId::new(key_pair.public_key().clone()),
            account_chain_discriminant: iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT,
            key_pair,
            basic_auth: None,
            api_token: None,
            torii_api_url: format!("http://{address}/").parse().unwrap(),
            torii_request_timeout: Duration::from_secs(5),
            transaction_ttl: Duration::from_secs(30),
            transaction_status_timeout: Duration::from_secs(5),
            transaction_add_nonce: false,
            sorafs_alias_cache: iroha::config::AliasCache::default().into_policy(),
            sorafs_anonymity_policy: Default::default(),
            sorafs_rollout_phase: Default::default(),
        };
        // `spawn_blocking` still enters Tokio's runtime context, which the synchronous
        // SDK correctly rejects. A plain thread plus an async result channel lets the
        // actual HTTP server keep progressing without bypassing that SDK guard.
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let worker = std::thread::spawn(move || {
            assert!(tokio::runtime::Handle::try_current().is_err());
            let result = iroha::client::Client::builder(config)
                .build()
                .expect("exact SDK fixture")
                .get_transaction_details(hash);
            assert!(
                result_tx.send(result).is_ok(),
                "SDK fixture result receiver"
            );
        });
        let result = result_rx.await.expect("SDK exact proof worker response");
        worker.join().expect("SDK exact proof worker");
        let failure = result
            .as_ref()
            .err()
            .map(|error| format!("{error:?}").chars().take(2_048).collect::<String>());
        assert_eq!(
            result.is_ok(),
            expected_success,
            "actual Torii→HTTP→SDK success contract: {failure:?}"
        );
        assert_eq!(
            matches!(
                &result,
                Err(iroha::query::QueryError::Validation(
                    ValidationFail::QueryFailed(QueryExecutionFail::NotFound)
                ))
            ),
            expected_missing,
            "only a registered authority's exact missing proof may become typed absence: {failure:?}"
        );
    }
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn transaction_details_http_preserves_original_receipt_after_cold_body_read() {
    use iroha_core::smartcontracts::isi::tx::{
        TransactionHistoryWorkLimits, committed_transactions_indexed_snapshot,
        transaction_history_byte_limit,
    };
    use iroha_data_model::query::{
        CommittedTransaction, CommittedTxFilters, dsl::CompoundPredicate,
    };
    use tower::ServiceExt as _;

    let sender_key = checked_torii_test_ed25519_keypair(0x24, "cold receipt sender");
    let reader_key = checked_torii_test_ed25519_keypair(0x45, "cold receipt unrelated reader");
    let unknown_key = checked_torii_test_ed25519_keypair(0x46, "cold receipt unknown signer");
    for applied in [true, false] {
        let instruction: iroha_data_model::isi::InstructionBox = if applied {
            Log::new(Level::INFO, "cold receipt original execution".into()).into()
        } else {
            iroha_data_model::isi::Unregister::domain(
                DomainId::try_new("missing_cold_receipt_domain", "universal").unwrap(),
            )
            .into()
        };
        let (app, signed_hash, chain) = executed_history_test_fixture(
            iroha_core::sumeragi::test_chain::TestChainConfig::new(
                transaction_details_test_world(&[
                    AccountId::new(sender_key.public_key().clone()),
                    AccountId::new(reader_key.public_key().clone()),
                ]),
                1_000,
            ),
            &sender_key,
            vec![instruction],
            applied,
        );
        let height = NonZeroUsize::new(2).unwrap();
        let entrypoint_hash =
            iroha_core::tx::external_entrypoint_hash_from_signed_hash(signed_hash);
        let original = chain.committed(2);
        let original_wire = original.block().encode_wire().unwrap();
        let original_result = original
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result
            .clone();
        let indexed_before = app
            .kura
            .get_block_heights_by_entrypoint_hash(entrypoint_hash);
        assert_eq!(indexed_before, Some([height].into_iter().collect()));
        assert_eq!(
            app.state.committed_entrypoint_height(&entrypoint_hash),
            Some(height)
        );

        let router = axum::Router::new()
            .route(
                route_catalog::pipeline::TRANSACTION_DETAILS.path(),
                axum::routing::post(super::handler_pipeline_transaction_details),
            )
            .with_state(app.clone());
        let request = |key: &KeyPair, hash| {
            let signed = signed_transaction_details_query(&app, key, hash);
            axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri(route_catalog::pipeline::TRANSACTION_DETAILS.path())
                .header(
                    axum::http::header::CONTENT_TYPE,
                    crate::utils::NORITO_MIME_TYPE,
                )
                .header(axum::http::header::ACCEPT, crate::utils::NORITO_MIME_TYPE)
                .extension(crate::loopback_connect_info())
                .body(Body::from(
                    iroha_version::codec::EncodeVersioned::encode_versioned(&signed),
                ))
                .unwrap()
        };
        let warm = router
            .clone()
            .oneshot(request(&sender_key, entrypoint_hash))
            .await
            .unwrap();
        assert_eq!(warm.status(), StatusCode::OK);
        let warm_bytes = torii_body_bytes(warm, "warm original receipt").await;

        assert!(
            app.kura
                .forget_cached_block_for_testing(NonZeroUsize::new(3).unwrap())
                .is_err(),
            "the test hook must reject an absent durable frame"
        );
        app.kura.forget_cached_block_for_testing(height).unwrap();
        assert_eq!(
            app.kura
                .get_block_heights_by_entrypoint_hash(entrypoint_hash),
            indexed_before,
            "forgetting a body must not modify secondary-index authority"
        );
        assert!(
            app.kura.forget_cached_block_for_testing(height).is_err(),
            "the hook must require an actual cached body"
        );
        let cold = app
            .kura
            .get_block(height, &app.state.ivm_execution_budget())
            .expect("admit original durable frame")
            .expect("read original durable frame");
        assert_eq!(cold.encode_wire().unwrap(), original_wire);
        assert_eq!(
            app.kura
                .get_block_heights_by_entrypoint_hash(entrypoint_hash),
            None,
            "an ordinary cold read must not authenticate the transaction index"
        );
        let work = routing::app_query_limits().max_fetch_size;
        let bytes = transaction_history_byte_limit(work);
        let previous_selector_error = committed_transactions_indexed_snapshot(
            &app.state.view(),
            CompoundPredicate::<CommittedTransaction>::from_filters(CommittedTxFilters {
                entry_eq: Some(entrypoint_hash),
                ..CommittedTxFilters::default()
            }),
            TransactionHistoryWorkLimits {
                max_carrier_work: work,
                max_total_work: work,
                max_bytes: bytes,
            },
            1,
            bytes,
        )
        .expect_err("the retired entry-only receipt selector cannot use a partial index");
        assert!(
            previous_selector_error
                .to_string()
                .contains("require a positive indexed filter")
        );

        let response = router
            .clone()
            .oneshot(request(&sender_key, entrypoint_hash))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_TYPE],
            crate::utils::NORITO_MIME_TYPE
        );
        let cold_bytes = torii_body_bytes(response, "cold original receipt").await;
        assert_eq!(
            cold_bytes, warm_bytes,
            "cold reads preserve the complete original receipt bytes"
        );
        let details: iroha_torii_shared::PipelineTransactionDetailsResponse =
            norito::decode_canonical_with_limits(
                &cold_bytes,
                norito::canonical_decode_limits(cold_bytes.len()),
            )
            .unwrap();
        assert_eq!(details.transaction.entrypoint_hash(), &entrypoint_hash);
        assert_eq!(details.transaction.result(), &original_result);
        assert_eq!(details.transaction.result().is_ok(), applied);

        let missing = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::new(
            b"cold receipt absent identity",
        ));
        assert!(
            canonical_transaction_details_for_indexed_identity(app.as_ref(), height, &missing)
                .is_err()
        );
        assert!(
            canonical_transaction_details_for_indexed_identity(
                app.as_ref(),
                NonZeroUsize::new(1).unwrap(),
                &entrypoint_hash
            )
            .is_err()
        );
        for (key, hash, expected) in [
            (&sender_key, missing, StatusCode::NOT_FOUND),
            (&reader_key, entrypoint_hash, StatusCode::FORBIDDEN),
            (&unknown_key, entrypoint_hash, StatusCode::FORBIDDEN),
        ] {
            let response = router.clone().oneshot(request(key, hash)).await.unwrap();
            assert_eq!(response.status(), expected);
        }
        assert_eq!(
            app.state.committed_entrypoint_height(&entrypoint_hash),
            Some(height)
        );
        assert_eq!(
            app.kura
                .get_block_heights_by_entrypoint_hash(entrypoint_hash),
            None
        );
        assert_eq!(
            app.kura
                .get_block(height, &app.state.ivm_execution_budget())
                .unwrap()
                .unwrap()
                .encode_wire()
                .unwrap(),
            original_wire
        );
    }
}

#[tokio::test]
async fn transaction_details_allows_sender_and_batch_recipient_but_rejects_other_accounts() {
    use iroha_data_model::events::data::prelude::{
        AssetBatchTransferLegStatus, AssetBatchTransferOutcome,
    };
    let sender_key =
        checked_torii_test_ed25519_keypair(0x24, "derive transaction-details sender key");
    let recipient_key =
        checked_torii_test_ed25519_keypair(0x35, "derive transaction-details recipient key");
    let unrelated_key =
        checked_torii_test_ed25519_keypair(0x36, "derive transaction-details unrelated key");
    let sender = AccountId::new(sender_key.public_key().clone());
    let recipient = AccountId::new(recipient_key.public_key().clone());
    let unrelated = AccountId::new(unrelated_key.public_key().clone());
    let asset_definition = iroha_data_model::parameter::system::SumeragiNposParameters::default()
        .xor_asset_definition_id;
    let source_asset = AssetId::new(asset_definition.clone(), sender.clone());
    let destination_asset = AssetId::new(asset_definition.clone(), recipient.clone());
    let world = World::with_assets(
        [],
        [sender.clone(), recipient.clone(), unrelated].map(|id| Account::new(id).build(&sender)),
        [AssetDefinition::numeric(
            asset_definition.clone(),
            "XOR".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&sender)],
        [Asset::new(source_asset.clone(), Quantity::from(10_u32))],
        [],
    );
    let transfer = iroha_data_model::isi::transfer::TransferAssetBatch::new(vec![
        iroha_data_model::isi::transfer::TransferAssetBatchEntry::with_leg_id(
            "private-receipt",
            sender.clone(),
            recipient.clone(),
            asset_definition,
            7_u32,
        ),
    ]);
    let (app, signed_hash, chain) = executed_history_test_fixture(
        iroha_core::sumeragi::test_chain::TestChainConfig::new(world, 1_000),
        &sender_key,
        vec![transfer.into()],
        true,
    );
    let entrypoint_hash = iroha_core::tx::external_entrypoint_hash_from_signed_hash(signed_hash);
    let block = chain.committed(2).block().clone();
    let (_, output) = block.network_output_at(0).unwrap();
    assert_eq!(output.input_index, 0);
    assert_eq!(
        block.network_entrypoint_at(0).unwrap().hash(),
        entrypoint_hash
    );
    let outcome = AssetBatchTransferOutcome {
        leg_index: 0,
        leg_id: "private-receipt".to_owned(),
        asset: source_asset.clone(),
        destination: recipient.clone(),
        amount: Quantity::from(7_u32),
        status: AssetBatchTransferLegStatus::Applied,
    };
    assert_eq!(output.result.batch_transfer_outcomes(), &[outcome.clone()]);
    {
        let view = app.state.view();
        assert_eq!(
            view.world()
                .asset(&source_asset)
                .unwrap()
                .value()
                .clone()
                .into_inner(),
            Quantity::from(3_u32),
        );
        assert_eq!(
            view.world()
                .asset(&destination_asset)
                .unwrap()
                .value()
                .clone()
                .into_inner(),
            Quantity::from(7_u32),
        );
    }
    let public = pipeline_status_response(
        app.clone(),
        signed_hash.to_string(),
        Some("local"),
        "public status projection",
    )
    .await;
    let public_json = decode_torii_json(public, "public status body", "public status JSON").await;
    assert!(public_json.get("batch_transfer_outcomes").is_none());
    assert!(public_json.get("transaction").is_none());
    let public_text = norito::json::to_json(&public_json).expect("render public status JSON");
    assert!(!public_text.contains("private-receipt"));
    assert!(!public_text.contains(&recipient.to_string()));
    for (label, key_pair) in [("sender", &sender_key), ("recipient", &recipient_key)] {
        let response = super::handler_pipeline_transaction_details(
            State(app.clone()),
            HeaderMap::new(),
            crate::loopback_connect_info(),
            Some(crate::utils::extractors::ExtractAccept(
                axum::http::HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
            )),
            versioned_query_for_test(signed_transaction_details_query(
                &app,
                key_pair,
                entrypoint_hash,
            )),
        )
        .await
        .unwrap_or_else(|error| {
            panic!("{label} should read involved transaction details: {error}")
        });
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_TYPE],
            crate::utils::NORITO_MIME_TYPE,
        );
        let body = torii_body_bytes(response, "transaction-details response body").await;
        let details: iroha_torii_shared::PipelineTransactionDetailsResponse =
            norito::decode_canonical_with_limits(
                &body,
                norito::canonical_decode_limits(body.len()),
            )
            .expect("typed transaction-details canonical Norito");
        assert_eq!(details.transaction.entrypoint_hash(), &entrypoint_hash);
        let iroha_data_model::block::execution_output::ExecutionOutputV1::Network(output) =
            details.transaction.output()
        else {
            panic!("transaction details must carry a Network output");
        };
        assert_eq!(
            output.input_index,
            details.transaction.entrypoint_proof().leaf_index()
        );
        assert_eq!(
            output.input_index,
            details.transaction.output_proof().leaf_index()
        );
        let details_json = norito::json::to_value(&details).unwrap();
        assert_eq!(details_json.as_object().unwrap().len(), 2);
        assert!(details_json.get("trigger_completions").is_none());
        assert_eq!(
            details.transaction.result().batch_transfer_outcomes(),
            &[outcome.clone()]
        );
    }
    let error = match super::handler_pipeline_transaction_details(
        State(app.clone()),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            axum::http::HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
        )),
        versioned_query_for_test(signed_transaction_details_query(
            &app,
            &unrelated_key,
            entrypoint_hash,
        )),
    )
    .await
    {
        Ok(_) => panic!("an uninvolved account must not read transaction details"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        super::Error::Query(ValidationFail::NotPermitted(_))
    ));
}
#[tokio::test]
async fn transaction_details_authenticates_executed_native_registration_and_transfer_beneficiaries()
{
    use iroha_core::sumeragi::test_chain::TestChainConfig;
    use iroha_data_model::isi::{InstructionBox, Register, Transfer};
    let sender_key = checked_torii_test_ed25519_keypair(0x24, "native beneficiary sender");
    let beneficiary_key = checked_torii_test_ed25519_keypair(0x37, "native beneficiary recipient");
    let unrelated_key = checked_torii_test_ed25519_keypair(0x38, "native beneficiary unrelated");
    let sender = AccountId::new(sender_key.public_key().clone());
    let beneficiary = AccountId::new(beneficiary_key.public_key().clone());
    let unrelated = AccountId::new(unrelated_key.public_key().clone());
    for register in [true, false] {
        for applied in [true, false] {
            let asset_definition =
                iroha_data_model::parameter::system::SumeragiNposParameters::default()
                    .xor_asset_definition_id;
            let mut accounts = vec![sender.clone(), unrelated.clone()];
            if !register || !applied {
                accounts.push(beneficiary.clone());
            }
            let world = World::with_assets(
                [],
                accounts
                    .into_iter()
                    .map(|id| Account::new(id).build(&sender)),
                [AssetDefinition::numeric(
                    asset_definition.clone(),
                    "XOR".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
                .build(&sender)],
                [Asset::new(
                    AssetId::new(asset_definition.clone(), sender.clone()),
                    Quantity::from(10_u32),
                )],
                [],
            );
            let instruction: InstructionBox = if register {
                Register::account(Account::new(beneficiary.clone())).into()
            } else {
                Transfer::asset_quantity(
                    AssetId::new(asset_definition, sender.clone()),
                    Quantity::from(if applied { 7_u32 } else { 11_u32 }),
                    beneficiary.clone(),
                )
                .into()
            };
            let (app, hash, chain) = executed_history_test_fixture(
                TestChainConfig::new(world, 1_000),
                &sender_key,
                vec![instruction],
                applied,
            );
            let entrypoint_hash = iroha_core::tx::external_entrypoint_hash_from_signed_hash(hash);
            let committed = chain.committed(2);
            assert_eq!(
                committed
                    .block()
                    .network_output_at(0)
                    .unwrap()
                    .1
                    .result
                    .is_ok(),
                applied
            );
            let (output_index, output) = committed.block().network_output_at(0).unwrap();
            eprintln!(
                "original beneficiary register={register} applied={applied}: result={:?}; result_hint={:?}; output_hint={:?}",
                output.result,
                norito::core::SerializePayload::encoded_len_exact(&output.result),
                norito::core::SerializePayload::encoded_len_exact(
                    &committed.block().execution_outputs()[output_index as usize]
                )
            );
            for (label, key, allowed) in [
                ("sender", &sender_key, true),
                ("beneficiary", &beneficiary_key, applied),
                ("unrelated", &unrelated_key, false),
            ] {
                let response = super::handler_pipeline_transaction_details(
                    State(app.clone()),
                    HeaderMap::new(),
                    crate::loopback_connect_info(),
                    Some(crate::utils::extractors::ExtractAccept(
                        axum::http::HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
                    )),
                    versioned_query_for_test(signed_transaction_details_query(
                        &app,
                        key,
                        entrypoint_hash,
                    )),
                )
                .await;
                if allowed {
                    let response = response.unwrap_or_else(|error| {
                        panic!("register={register} applied={applied} {label}: {error:?}")
                    });
                    assert_eq!(response.status(), StatusCode::OK);
                    let body =
                        torii_body_bytes(response, "executed native beneficiary details").await;
                    let details: iroha_torii_shared::PipelineTransactionDetailsResponse =
                        norito::decode_canonical_with_limits(
                            &body,
                            norito::canonical_decode_limits(body.len()),
                        )
                        .unwrap();
                    assert_eq!(details.transaction.entrypoint().hash(), entrypoint_hash);
                    assert_eq!(details.transaction.result().is_ok(), applied);
                } else {
                    assert!(
                        matches!(response, Err(Error::Query(ValidationFail::NotPermitted(_)))),
                        "register={register} applied={applied} {label}: native beneficiary isolation"
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn transaction_details_rejects_uncertified_native_beneficiary_claims() {
    use iroha_data_model::{
        alias_setup::{
            AccountAliasRoleV1, AccountProvisionV1, AliasAccountIntentV1, AliasIntentV1,
            AliasLeaseAcquisitionV1, AliasQuoteGuardV1, ResolvedAccountAliasV1,
        },
        isi::{InstructionBox, Log, Register, Transfer, alias_setup::EnsureAlias},
    };
    let sender_key = checked_torii_test_ed25519_keypair(0x24, "native details sender");
    let beneficiary_key = checked_torii_test_ed25519_keypair(0x37, "native details beneficiary");
    let unrelated_key = checked_torii_test_ed25519_keypair(0x38, "native details unrelated");
    let sender = AccountId::new(sender_key.public_key().clone());
    let beneficiary = AccountId::new(beneficiary_key.public_key().clone());
    let unrelated = AccountId::new(unrelated_key.public_key().clone());
    let asset_definition = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("asset domain"),
        Name::from_str("rose").expect("asset name"),
    );
    let instructions = [
        (
            "account creation without alias",
            InstructionBox::from(Register::account(Account::new(beneficiary.clone()))),
            true,
        ),
        (
            "account alias",
            InstructionBox::from(EnsureAlias::new(
                AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
                    alias: ResolvedAccountAliasV1::new(
                        "nativebeneficiary@universal"
                            .parse()
                            .expect("beneficiary alias"),
                        DataSpaceId::UNIVERSAL,
                    ),
                    target_account: beneficiary.clone(),
                    provision: AccountProvisionV1::Create,
                    role: AccountAliasRoleV1::Primary,
                }),
                AliasLeaseAcquisitionV1::new(1, None),
                AliasQuoteGuardV1 {
                    expected_policy_version: 1,
                    expected_payment_asset: asset_definition.clone(),
                    max_amount: Quantity::from(1_u32),
                    valid_until_ms: u64::MAX,
                },
            )),
            true,
        ),
        (
            "ordinary faucet transfer",
            InstructionBox::from(Transfer::asset_quantity(
                AssetId::new(asset_definition, sender.clone()),
                Quantity::from(7_u32),
                beneficiary.clone(),
            )),
            true,
        ),
        (
            "unrelated payload naming the account",
            InstructionBox::from(Log::new(
                iroha_data_model::Level::INFO,
                beneficiary.to_string(),
            )),
            false,
        ),
    ];
    for (label, instruction, _) in instructions {
        for applied in [true, false] {
            let mut app =
                crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
                    transaction_details_test_world(&[
                        sender.clone(),
                        beneficiary.clone(),
                        unrelated.clone(),
                    ]),
                    crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
                );
            let (_, restricted_dataspace) = configure_private_ingress_routes_for_test(&mut app);
            assert!(
                torii_all_dataspace_routes(app.as_ref())
                    .iter()
                    .any(|route| route.dataspace_id == restricted_dataspace)
            );
            let transaction = checked_torii_test_transaction(
                TransactionBuilder::new(
                    signed_query_test_network_id(),
                    sender.clone(),
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
                .with_instructions([instruction.clone()]),
                &sender_key,
                "sign native beneficiary details fixture",
            );
            let entrypoint_hash = transaction.hash_as_entrypoint();
            // The same equality predicate still cannot be used as a global inventory read.
            let request = request_for_test(
                &beneficiary,
                iroha_data_model::query::QueryRequest::Start(
                    build_exact_transaction_details_query_for_test(entrypoint_hash),
                ),
            );
            let scope = signed_query_scope_for_app(app.as_ref(), &request);
            assert_eq!(scope, SignedQueryScope::AuthorityRouted);
            let denied = torii_authorized_signed_query_routes(app.as_ref(), &request, &scope)
                .expect_err("exact filters must not bypass restricted global history admission");
            assert_eq!(denied.status(), StatusCode::FORBIDDEN);
            app.pipeline_status_cache.record_entry(
                transaction.hash(),
                PipelineStatusEntry::fresh(PipelineStatusKind::Queued, None, None),
            );
            assert!(
                matches!(
                    pipeline_transaction_details_response(&app, &beneficiary, entrypoint_hash),
                    Err(Error::AppNotFound {
                        code: "transaction_details_not_found",
                        ..
                    })
                ),
                "{label}: a queued target must not establish committed read authority"
            );
            let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
            let mut builder = iroha_data_model::block::builder::BlockBuilder::new(header);
            builder.push_transaction(transaction);
            let mut block = builder.build_with_signature(0, sender_key.private_key());
            let result = if applied {
                Ok(DataTriggerSequence::default())
            } else {
                Err(TransactionRejectionReason::Validation(
                    ValidationFail::NotPermitted("native beneficiary fixture rejected".to_owned()),
                ))
            };
            crate::test_utils::attach_fixture_execution_outputs(
                &mut block,
                vec![
                    iroha_data_model::block::execution_output::ExecutionOutputV1::Network(
                        iroha_data_model::block::execution_output::NetworkExecutionOutputV1 {
                            input_index: 0,
                            result: iroha_data_model::transaction::TransactionResult::new(result),
                            completions: vec![],
                        },
                    ),
                ],
            );
            store_unverified_transaction_details_block(&app, block, entrypoint_hash);
            for (caller_label, key_pair) in [
                ("sender", &sender_key),
                ("beneficiary", &beneficiary_key),
                ("unrelated", &unrelated_key),
            ] {
                let response = super::handler_pipeline_transaction_details(
                    State(app.clone()),
                    HeaderMap::new(),
                    crate::loopback_connect_info(),
                    Some(crate::utils::extractors::ExtractAccept(
                        axum::http::HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
                    )),
                    versioned_query_for_test(signed_transaction_details_query(
                        &app,
                        key_pair,
                        entrypoint_hash,
                    )),
                )
                .await;
                assert!(
                    response.is_err(),
                    "{label}/{caller_label}/{applied}: uncertified stored outputs cannot authorize history"
                );
            }
        }
    }
}

#[tokio::test]
async fn transaction_details_allows_operator_and_rejects_wrong_network_and_replay() {
    let sender_key =
        checked_torii_test_ed25519_keypair(0x24, "derive operator fixture transaction sender");
    let operator_key =
        checked_torii_test_ed25519_keypair(0x37, "derive transaction-details operator key");
    let sender = AccountId::new(sender_key.public_key().clone());
    let operator = AccountId::new(operator_key.public_key().clone());
    let mut config = iroha_core::sumeragi::test_chain::TestChainConfig::new(
        transaction_details_test_world(&[sender, operator.clone()]),
        1_000,
    );
    config.genesis_instructions.push(
        iroha_data_model::isi::Grant::account_permission(CanReadAllLedgerData, operator.clone())
            .into(),
    );
    let (app, signed_hash, _chain) = executed_history_test_fixture(
        config,
        &sender_key,
        vec![Log::new(Level::INFO, "native operator transaction details".into()).into()],
        true,
    );
    let entrypoint_hash = iroha_core::tx::external_entrypoint_hash_from_signed_hash(signed_hash);
    let signed = signed_transaction_details_query(&app, &operator_key, entrypoint_hash);
    let signed_bytes = norito::to_bytes(&signed).expect("encode replayable signed-query fixture");
    let first: SignedQuery =
        norito::decode_from_bytes(&signed_bytes).expect("decode first signed-query fixture");
    let replayed: SignedQuery =
        norito::decode_from_bytes(&signed_bytes).expect("decode replayed signed-query fixture");
    let response = super::handler_pipeline_transaction_details(
        State(app.clone()),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            axum::http::HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
        )),
        versioned_query_for_test(first),
    )
    .await
    .expect("operator capability should authorize transaction details");
    assert_eq!(response.status(), StatusCode::OK);
    let replay = match super::handler_pipeline_transaction_details(
        State(app.clone()),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            axum::http::HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
        )),
        versioned_query_for_test(replayed),
    )
    .await
    {
        Ok(_) => panic!("the same signed-query nonce must be one-shot"),
        Err(error) => error,
    };
    assert!(format!("{replay:?}").contains("nonce already used"));
    let mut wrong_network = authorize_query_for_test(
        iroha_data_model::query::QueryRequest::Start(
            build_exact_transaction_details_query_for_test(entrypoint_hash),
        ),
        operator,
    );
    wrong_network.network_id = NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x38; Hash::LENGTH])),
    );
    let wrong_network = wrong_network.sign(&operator_key);
    let error = match super::handler_pipeline_transaction_details(
        State(app.clone()),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            axum::http::HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
        )),
        versioned_query_for_test(wrong_network),
    )
    .await
    {
        Ok(_) => panic!("a transaction-details query cannot cross network lineages"),
        Err(error) => error,
    };
    assert!(format!("{error:?}").contains("different network genesis"));
}
#[test]
fn transaction_details_rejects_unsigned_and_broadened_queries() {
    let key_pair = checked_torii_test_ed25519_keypair(0x39, "derive transaction-details shape key");
    let authority = AccountId::new(key_pair.public_key().clone());
    let entrypoint_hash = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::new(
        b"transaction-details-shape",
    ));
    let unsigned = authorize_query_for_test(
        iroha_data_model::query::QueryRequest::Start(
            build_exact_transaction_details_query_for_test(entrypoint_hash),
        ),
        authority.clone(),
    );
    let bytes = norito::to_bytes(&unsigned).expect("encode unsigned query request");
    assert!(
        norito::decode_from_bytes::<SignedQuery>(&bytes).is_err(),
        "the signed-query endpoint must not decode an unsigned request as an admission witness",
    );
    let broadened = authorize_query_for_test(
        iroha_data_model::query::QueryRequest::Start(build_find_transactions_query_for_test()),
        authority,
    );
    assert!(
        exact_transaction_details_query_hash(&broadened).is_err(),
        "unbounded transaction history must not qualify as an exact details query",
    );
}
fn commit_native_history_entrypoint(
    chain: &mut iroha_core::sumeragi::test_chain::CertifiedTestChain,
    entrypoint: TransactionEntrypoint,
) -> iroha_core::sumeragi::certified_chain::CommittedBlock {
    chain.commit_entrypoints(vec![entrypoint])
}

#[tokio::test]
async fn pipeline_status_resolves_native_executed_sealed_reveal_and_signed_alias() {
    use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    use iroha_data_model::transaction::signed::{
        SealedTransactionCommitmentPayload, SignedSealedTransactionCommitment,
    };
    let key = checked_torii_test_ed25519_keypair(0x26, "native sealed history authority");
    let authority = AccountId::new(key.public_key().clone());
    let mut chain =
        CertifiedTestChain::start(TestChainConfig::new(world_with_account(&authority), 1_000))
            .unwrap();
    let mut builder = TransactionBuilder::new(
        chain.network_id(),
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(Duration::from_millis(1_001));
    let signed = builder
        .with_instructions([Log::new(Level::INFO, "native sealed history".into())])
        .sign(key.private_key());
    let signed_hash = signed.hash();
    let salt = [0xA7; 32];
    let commitment = compute_sealed_transaction_commitment(&chain.network_id(), &signed, salt, 4);
    let sealed = SignedSealedTransactionCommitment::sign(
        SealedTransactionCommitmentPayload::new(
            chain.network_id(),
            signed.authority().clone(),
            commitment,
            3,
            4,
            None,
        ),
        key.private_key(),
    );
    let committed = commit_native_history_entrypoint(
        &mut chain,
        TransactionEntrypoint::SealedCommitment(sealed),
    );
    assert!(
        committed
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result
            .is_ok()
    );
    let reveal =
        TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(commitment, signed, salt));
    let reveal_hash = reveal.hash();
    let committed = commit_native_history_entrypoint(&mut chain, reveal);
    assert!(
        committed
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result
            .is_ok()
    );
    let mut app = mk_app_state_for_tests();
    let unique = Arc::get_mut(&mut app).unwrap();
    unique.state = chain.state().clone();
    unique.kura = chain.kura().clone();
    let signed_alias = iroha_core::tx::external_entrypoint_hash_from_signed_hash(signed_hash);
    for identity in [reveal_hash, signed_alias] {
        assert_eq!(
            canonical_transaction_details_for_indexed_identity(
                app.as_ref(),
                NonZeroUsize::new(3).unwrap(),
                &identity,
            )
            .unwrap()
            .entrypoint_hash,
            reveal_hash
        );
    }
    for hash in [reveal_hash.to_string(), signed_hash.to_string()] {
        let response =
            pipeline_status_response(app.clone(), hash, None, "native sealed history").await;
        assert_eq!(response.status(), StatusCode::OK);
        let payload = torii_json_body(response).await;
        assert_eq!(payload["status"]["kind"].as_str(), Some("Applied"));
        assert_eq!(payload["resolved_from"].as_str(), Some("state"));
    }
}

#[tokio::test]
async fn pipeline_status_rejects_uncertified_sealed_reveal_carrier_and_signed_alias() {
    let app = mk_app_state_for_tests();
    let (block, reveal_entry_hash) = make_sealed_reveal_block(1, None);
    let signed_hash = block
        .external_transactions()
        .next()
        .expect("sealed reveal carries one signed transaction")
        .hash();
    let signed_entrypoint_alias =
        iroha_core::tx::external_entrypoint_hash_from_signed_hash(signed_hash.clone());
    let header = block.header();
    let block_hash = store_block(&app, block);
    let height = header.height();
    let height_usize = usize::try_from(height.get()).expect("height usize");
    let height_nz = NonZeroUsize::new(height_usize).expect("height");
    let mut state_block = app.state.block(header.clone());
    state_block.block_hashes.push_for_tests(block_hash);
    let entrypoint_hashes: HashSet<_> = [reveal_entry_hash, signed_entrypoint_alias]
        .into_iter()
        .collect();
    state_block
        .transactions
        .insert_block(entrypoint_hashes, height_nz);
    state_block.commit().expect("commit");
    app.state.update_latest_block_header_cache_for_tests(header);
    for identity in [reveal_entry_hash, signed_entrypoint_alias] {
        assert!(
            canonical_transaction_details_for_indexed_identity(app.as_ref(), height_nz, &identity)
                .is_err(),
            "an indexed synthetic reveal must not replace a native commit certificate"
        );
    }
}

#[tokio::test]
async fn pipeline_status_handler_prefers_state_over_stale_queued_cache() {
    let (app, tx_hash, _chain) = canonical_outcome_test_fixture(false);
    app.pipeline_status_cache.record_entry(
        tx_hash,
        PipelineStatusEntry::fresh(PipelineStatusKind::Queued, None, None),
    );
    let resp = pipeline_status_response(app.clone(), tx_hash.to_string(), None, "ok").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let payload = torii_json_body(resp).await;
    assert_eq!(
        payload
            .get("status")
            .and_then(|status| status.get("kind"))
            .and_then(norito::json::Value::as_str),
        Some("Applied")
    );
    assert_eq!(
        payload
            .get("resolved_from")
            .and_then(norito::json::Value::as_str),
        Some("state")
    );
}
#[tokio::test]
async fn pipeline_status_handler_prefers_state_over_stale_rejected_cache() {
    let (app, tx_hash, _chain) = canonical_outcome_test_fixture(false);
    let rejection = TransactionRejectionReason::Validation(ValidationFail::TooComplex);
    app.pipeline_status_cache.record_entry(
        tx_hash,
        PipelineStatusEntry::fresh(
            PipelineStatusKind::Rejected,
            None,
            Some(pipeline_rejection_summary(&rejection)),
        ),
    );
    let resp = pipeline_status_response(app.clone(), tx_hash.to_string(), None, "ok").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let payload = torii_json_body(resp).await;
    assert_eq!(
        payload
            .get("status")
            .and_then(|status| status.get("kind"))
            .and_then(norito::json::Value::as_str),
        Some("Applied")
    );
    assert_eq!(
        payload
            .get("resolved_from")
            .and_then(norito::json::Value::as_str),
        Some("state")
    );
}
#[tokio::test]
async fn public_pipeline_status_does_not_expose_rejection_details() {
    let app = mk_app_state_for_tests();
    let (block, _) = make_signed_block(1, None);
    let tx_hash = block.external_transactions().next().expect("tx").hash();
    let reason = TransactionRejectionReason::Validation(ValidationFail::TooComplex);
    app.pipeline_status_cache.record_entry(
        tx_hash,
        PipelineStatusEntry::fresh(
            PipelineStatusKind::Rejected,
            None,
            Some(pipeline_rejection_summary(&reason)),
        ),
    );
    let resp =
        pipeline_status_response(app.clone(), tx_hash.to_string(), Some("local"), "ok").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let payload = torii_json_body(resp).await;
    assert_eq!(
        payload
            .get("status")
            .and_then(|status| status.get("kind"))
            .and_then(norito::json::Value::as_str),
        Some("Rejected")
    );
    assert!(
        payload
            .get("status")
            .and_then(|status| status.get("rejection_reason"))
            .is_none()
    );
    let encoded = norito::json::to_json(&payload).expect("public status JSON");
    assert!(!encoded.contains(&reason.to_string()));
}
#[tokio::test]
async fn ledger_headers_respect_from_and_limit() {
    let app = mk_app_state_for_tests();
    let (block1, _) = make_signed_block(1, None);
    let first_header = block1.header();
    let first_hash = store_block(&app, block1);
    record_committed_block_hash_for_test(&app, first_header, first_hash);
    let (block2, _) = make_signed_block(2, Some(first_hash));
    let second_header = block2.header();
    let second_hash = store_block(&app, block2);
    record_committed_block_hash_for_test(&app, second_header, second_hash);
    let resp = super::handler_ledger_headers(
        State(app.clone()),
        crate::NoritoQuery(routing::HistoryWindowQuery {
            from: Some(2),
            limit: Some(1),
        }),
        HeaderMap::from_iter([(
            axum::http::header::ACCEPT,
            HeaderValue::from_static("application/json"),
        )]),
    )
    .await
    .expect("ok");
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .map(HeaderValue::as_bytes),
        Some(b"application/json".as_slice())
    );
    let bytes = torii_body_bytes(resp, "body bytes").await;
    let headers: Vec<BlockHeader> = norito::json::from_slice(&bytes).expect("json decode");
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].height().get(), 2);
    let norito_resp = super::handler_ledger_headers(
        State(app),
        crate::NoritoQuery(routing::HistoryWindowQuery {
            from: Some(2),
            limit: Some(2),
        }),
        {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::ACCEPT,
                HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
            );
            headers
        },
    )
    .await
    .expect("ok");
    let norito_bytes = torii_body_bytes(norito_resp, "norito body").await;
    let archived = norito::from_bytes::<Vec<BlockHeader>>(&norito_bytes).expect("archive");
    let decoded: Vec<BlockHeader> = norito::core::DeserializePayload::deserialize(archived);
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].height().get(), 2);
    assert_eq!(decoded[1].height().get(), 1);
}
fn native_ledger_state_app(
    signers: iroha_core::sumeragi::test_chain::Signers,
) -> (SharedAppState, SignedBlock) {
    use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    let mut chain =
        CertifiedTestChain::start(TestChainConfig::new(iroha_core::state::World::new(), 1_000))
            .unwrap();
    chain.commit_with(None, Vec::new(), signers);
    let block = chain.committed(2).block().as_ref().clone();
    let mut app = mk_app_state_for_tests();
    let unique = Arc::get_mut(&mut app).unwrap();
    unique.state = chain.state().clone();
    unique.kura = chain.kura().clone();
    (app, block)
}

// Replace only the existing native frame in the disposable store. Re-encoding
// preserves valid canonical checksums so failure exercises certificate bindings.
fn tamper_native_ledger_certificate(
    app: &SharedAppState,
    mut block: SignedBlock,
    mutate: impl FnOnce(&mut iroha_sumeragi::message::Qc),
) {
    use iroha_data_model::block::CommitCertificate;
    let original = block.encode_wire().unwrap();
    let certificate = block.commit_certificate().unwrap();
    let header = certificate.consensus_header().to_vec();
    let result = certificate.result_preimage().to_vec();
    let availability = certificate.availability().to_vec();
    let mut qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
    mutate(&mut qc);
    block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        header,
        norito::encode_canonical(&qc).unwrap(),
        result,
        availability,
    )));
    let changed = block.encode_wire().unwrap();
    assert_eq!(
        original.len(),
        changed.len(),
        "retain the exact occupied slot"
    );
    let path =
        iroha_core::kura::Kura::canonical_storage_path(&app.kura.store_root()).join("blocks.data");
    let mut data = std::fs::read(&path).unwrap();
    let offsets = data
        .windows(original.len())
        .enumerate()
        .filter_map(|(at, bytes)| (bytes == original.as_slice()).then_some(at))
        .collect::<Vec<_>>();
    assert_eq!(offsets.len(), 1, "one original canonical block frame");
    data[offsets[0]..offsets[0] + changed.len()].copy_from_slice(&changed);
    std::fs::write(path, data).unwrap();
}

#[tokio::test]
async fn ledger_state_endpoints_return_exact_native_finality_in_json_and_norito() {
    let (app, _) = native_ledger_state_app(iroha_core::sumeragi::test_chain::Signers::Quorum);
    let expected_proof = iroha_core::sumeragi::finality::build_proof(&app.state.view(), 2).unwrap();
    let expected_root = expected_proof
        .decode_checked()
        .unwrap()
        .execution()
        .post_state_root;
    let result_root = app
        .state
        .block_by_height(NonZeroUsize::new(2).expect("nonzero height"))
        .expect("funded canonical history read")
        .expect("committed fixture block")
        .output_merkle_commitment()
        .map(|commitment| Hash::prehashed(*commitment.root().as_ref()))
        .expect("fixture output root");
    assert_ne!(
        expected_root, result_root,
        "the result Merkle root must be an adversarially distinct fallback candidate"
    );
    let mut json_accept = HeaderMap::new();
    json_accept.insert(
        axum::http::header::ACCEPT,
        HeaderValue::from_static("application/json"),
    );
    let resp = handler_ledger_state_root(
        State(Arc::clone(&app)),
        axum::extract::Path(2),
        json_accept.clone(),
    )
    .await
    .expect("authenticated state-root response");
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .map(HeaderValue::as_bytes),
        Some(b"application/json".as_slice())
    );
    let bytes = torii_body_bytes(resp, "json body").await;
    let value: norito::json::Value = norito::json::from_slice(&bytes).expect("JSON value");
    let mut fields = value
        .as_object()
        .expect("state finality object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "block_hash",
            "block_header",
            "finality_proof",
            "height",
            "witnessed_post_state_root",
        ]
    );
    for retired in ["source", "commit_qc", "state_root", "finality_artifact"] {
        let mut hostile = value.clone();
        hostile
            .as_object_mut()
            .expect("state finality object")
            .insert(retired.to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<StateFinalityResponse>(hostile).is_err(),
            "closed first-release response accepted retired field {retired}"
        );
    }
    let payload: StateFinalityResponse =
        norito::json::from_slice(&bytes).expect("typed state finality JSON");
    assert_eq!(payload.height, 2);
    assert_eq!(payload.block_hash, expected_proof.block_header.hash());
    assert_eq!(
        payload.block_header.hash(),
        expected_proof.block_header.hash()
    );
    assert_eq!(payload.witnessed_post_state_root, expected_root);
    assert_eq!(payload.finality_proof, expected_proof);
    let mut accept = HeaderMap::new();
    accept.insert(
        axum::http::header::ACCEPT,
        HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
    );
    let norito_resp = handler_ledger_state_root(
        State(Arc::clone(&app)),
        axum::extract::Path(2),
        accept.clone(),
    )
    .await
    .expect("authenticated state-root Norito response");
    let norito_bytes = torii_body_bytes(norito_resp, "norito body").await;
    let archived =
        norito::from_bytes::<StateFinalityResponse>(&norito_bytes).expect("state root archive");
    let decoded: StateFinalityResponse = norito::core::DeserializePayload::deserialize(archived);
    assert_eq!(decoded.witnessed_post_state_root, expected_root);
    assert_eq!(decoded.finality_proof, expected_proof);
    let resp =
        handler_ledger_state_proof(State(Arc::clone(&app)), axum::extract::Path(2), json_accept)
            .await
            .expect("authenticated state-proof JSON response");
    assert_eq!(
        resp.headers().get(axum::http::header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("application/json"))
    );
    let body = torii_body_bytes(resp, "body").await;
    let proof: StateFinalityResponse = norito::json::from_slice(&body).expect("JSON proof");
    assert_eq!(proof.height, 2);
    assert_eq!(proof.block_hash, expected_proof.block_header.hash());
    assert_eq!(proof.witnessed_post_state_root, expected_root);
    assert_eq!(proof.finality_proof, expected_proof);
    let norito_resp = handler_ledger_state_proof(State(app), axum::extract::Path(2), accept)
        .await
        .expect("authenticated state-proof Norito response");
    let norito_bytes = torii_body_bytes(norito_resp, "bytes").await;
    let archived =
        norito::from_bytes::<StateFinalityResponse>(&norito_bytes).expect("state proof archive");
    let decoded: StateFinalityResponse = norito::core::DeserializePayload::deserialize(archived);
    assert_eq!(decoded.witnessed_post_state_root, expected_root);
    assert_eq!(decoded.finality_proof, expected_proof);
}
#[tokio::test]
async fn state_proof_http_roundtrip_supports_json_and_norito() {
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::get,
    };
    use tower::ServiceExt as _;
    let (app, _) = native_ledger_state_app(iroha_core::sumeragi::test_chain::Signers::Quorum);
    let expected_proof = iroha_core::sumeragi::finality::build_proof(&app.state.view(), 2).unwrap();
    let expected_root = expected_proof
        .decode_checked()
        .unwrap()
        .execution()
        .post_state_root;
    let router = Router::new()
        .route(
            route_catalog::core::LEDGER_STATE_PROOF.path(),
            get(handler_ledger_state_proof),
        )
        .with_state(app.clone());
    let request = Request::builder()
        .uri("/v1/ledger/state-proof/2")
        .header(axum::http::header::ACCEPT, "application/json")
        .body(Body::empty())
        .expect("request");
    let response = router.clone().oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(axum::http::header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("application/json"))
    );
    let bytes = torii_body_bytes(response, "body").await;
    let proof: StateFinalityResponse = norito::json::from_slice(&bytes).expect("JSON proof");
    assert_eq!(proof.height, 2);
    assert_eq!(proof.block_hash, expected_proof.block_header.hash());
    assert_eq!(proof.witnessed_post_state_root, expected_root);
    assert_eq!(proof.finality_proof, expected_proof);
    let request = Request::builder()
        .uri("/v1/ledger/state-proof/2")
        .header(axum::http::header::ACCEPT, crate::utils::NORITO_MIME_TYPE)
        .body(Body::empty())
        .expect("request");
    let response = router.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(axum::http::header::CONTENT_TYPE),
        Some(&HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE))
    );
    let bytes = torii_body_bytes(response, "body").await;
    let archived =
        norito::from_bytes::<StateFinalityResponse>(&bytes).expect("archived state proof");
    let proof: StateFinalityResponse = norito::core::DeserializePayload::deserialize(archived);
    let canonical = crate::frame_test_support::assert_current_frame(
        &proof,
        "iroha_torii::ledger_state_finality::StateFinalityResponse",
    );
    assert_eq!(canonical.as_slice(), bytes.as_ref());
    assert_eq!(proof.height, 2);
    assert_eq!(proof.block_hash, expected_proof.block_header.hash());
    assert_eq!(proof.witnessed_post_state_root, expected_root);
    assert_eq!(proof.finality_proof, expected_proof);
}
fn assert_ledger_state_handler_status(error: Error, expected: StatusCode) {
    assert_eq!(error.into_response().status(), expected);
}
#[tokio::test]
async fn ledger_state_endpoints_require_exact_native_quorum() {
    let (app, block) = native_ledger_state_app(iroha_core::sumeragi::test_chain::Signers::Quorum);
    // Original admission must succeed. Corrupt the durable QC after publication
    // so this tests the read boundary rather than failing fixture construction.
    tamper_native_ledger_certificate(&app, block, |qc| {
        qc.signers = iroha_sumeragi::types::Bitmap::from_indices(4, [0, 1]).unwrap();
    });
    for proof in [false, true] {
        let error = if proof {
            handler_ledger_state_proof(State(app.clone()), axum::extract::Path(2), HeaderMap::new())
                .await
        } else {
            handler_ledger_state_root(State(app.clone()), axum::extract::Path(2), HeaderMap::new())
                .await
        }
        .expect_err("a below-quorum native certificate must fail closed");
        assert_ledger_state_handler_status(error, StatusCode::INTERNAL_SERVER_ERROR);
    }
}

#[tokio::test]
async fn ledger_state_endpoints_reject_wrong_height_native_certificate() {
    let (app, block) = native_ledger_state_app(iroha_core::sumeragi::test_chain::Signers::Quorum);
    // Warm the actual reader first: later disk corruption must not use a cached proof.
    handler_ledger_state_root(State(app.clone()), axum::extract::Path(2), HeaderMap::new())
        .await
        .unwrap();
    tamper_native_ledger_certificate(&app, block, |qc| qc.height = 1);
    let error =
        handler_ledger_state_root(State(app.clone()), axum::extract::Path(2), HeaderMap::new())
            .await
            .expect_err("wrong-height native finality must fail closed");
    assert_ledger_state_handler_status(error, StatusCode::INTERNAL_SERVER_ERROR);
    let error = handler_ledger_state_proof(State(app), axum::extract::Path(2), HeaderMap::new())
        .await
        .expect_err("wrong-height native proof must fail closed");
    assert_ledger_state_handler_status(error, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn ledger_state_endpoints_reject_forged_native_signature() {
    let (app, block) = native_ledger_state_app(iroha_core::sumeragi::test_chain::Signers::Quorum);
    handler_ledger_state_proof(State(app.clone()), axum::extract::Path(2), HeaderMap::new())
        .await
        .unwrap();
    tamper_native_ledger_certificate(&app, block, |qc| qc.agg_sig.0[0] ^= 1);
    let error =
        handler_ledger_state_root(State(app.clone()), axum::extract::Path(2), HeaderMap::new())
            .await
            .expect_err("forged native signature must fail closed");
    assert_ledger_state_handler_status(error, StatusCode::INTERNAL_SERVER_ERROR);
    let error = handler_ledger_state_proof(State(app), axum::extract::Path(2), HeaderMap::new())
        .await
        .expect_err("forged native proof must fail closed");
    assert_ledger_state_handler_status(error, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn ledger_state_endpoints_reject_zero_and_uncommitted_heights() {
    let (app, _) = native_ledger_state_app(iroha_core::sumeragi::test_chain::Signers::Quorum);
    for (height, status) in [
        (0, StatusCode::BAD_REQUEST),
        (1, StatusCode::BAD_REQUEST),
        (3, StatusCode::NOT_FOUND),
    ] {
        let error = handler_ledger_state_root(
            State(app.clone()),
            axum::extract::Path(height),
            HeaderMap::new(),
        )
        .await
        .expect_err("unavailable committed height");
        assert_ledger_state_handler_status(error, status);
        let error = handler_ledger_state_proof(
            State(app.clone()),
            axum::extract::Path(height),
            HeaderMap::new(),
        )
        .await
        .expect_err("unavailable committed height");
        assert_ledger_state_handler_status(error, status);
    }
}
include!("committed_network_proof_support.rs");

#[test]
fn block_proof_handler_emits_norito() {
    run_executed_block_wire_handler_test("block-proof-native", || async {
        use iroha_data_model::block::{
            execution_output::ExecutionOutputV1,
            proofs::{BlockProofs, TrustedBlockProofAnchor},
        };
        let (app, block, verified) = committed_network_proof_app_for_test();
        let expected_entry_commitment = block.network_input_merkle_commitment().unwrap();
        let expected_output_commitment = block.output_merkle_commitment().unwrap();
        assert_eq!(expected_entry_commitment.leaf_count().get(), 2);
        assert_eq!(expected_output_commitment.leaf_count().get(), 4);
        for (index, entry) in block.network_entrypoints().enumerate() {
            let entry_hash = entry.hash();
            let entry_hex = hex::encode(entry_hash.as_ref());
            let resp = super::block_proof_response(
                State(Arc::clone(&app)),
                axum::extract::Path((2, entry_hex)),
            )
            .await
            .expect("exact finalized Network proof");
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                resp.headers()
                    .get(axum::http::header::CONTENT_TYPE)
                    .map(HeaderValue::as_bytes),
                Some(crate::utils::NORITO_MIME_TYPE.as_bytes())
            );
            let bytes = torii_body_bytes(resp, "norito payload").await;
            let proofs: BlockProofs =
                norito::decode_canonical(&bytes).expect("canonical proof frame");
            assert_eq!(proofs.block_height.get(), 2);
            assert_eq!(proofs.block_hash, block.hash());
            assert_eq!(
                proofs.executed_block_wire_hash,
                block.executed_block_wire_hash().unwrap()
            );
            assert_eq!(proofs.entry_hash, entry_hash);
            assert_eq!(proofs.entry_commitment, expected_entry_commitment);
            assert!(proofs.entry_proof.verify(&expected_entry_commitment));
            assert_eq!(proofs.output_commitment, expected_output_commitment);
            assert!(proofs.output_proof.verify(&expected_output_commitment));
            assert_eq!(
                proofs.output_proof.output(),
                &block.execution_outputs()[index]
            );
            let ExecutionOutputV1::Network(row) = proofs.output_proof.output() else {
                panic!("Network proof")
            };
            assert_eq!(usize::try_from(row.input_index).unwrap(), index);
            assert_eq!(proofs.entry_proof.proof().leaf_index(), row.input_index);
            assert_eq!(proofs.output_proof.proof().leaf_index(), row.input_index);
            assert_eq!(row.result.is_err(), index == 1);
            assert!(proofs.fastpq_transcripts.is_empty());
            let anchor =
                TrustedBlockProofAnchor::from_verified_finality(&block, &verified, &entry_hash)
                    .unwrap();
            assert!(proofs.verify(&anchor));
        }
    });
}
const EXECUTED_BLOCK_WIRE_TEST_OWNER_STACK_BYTES: usize = 8 * 1024 * 1024;
fn run_executed_block_wire_handler_test<F, Fut>(name: &'static str, test: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + 'static,
{
    let owner = std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(EXECUTED_BLOCK_WIRE_TEST_OWNER_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build executed-block handler test runtime")
                .block_on(test());
        })
        .expect("spawn executed-block handler test owner");
    if let Err(payload) = owner.join() {
        std::panic::resume_unwind(payload);
    }
}
#[test]
fn executed_block_wire_handler_returns_the_exact_finalized_canonical_wire() {
    run_executed_block_wire_handler_test("executed-wire-canonical", || async {
        let (app, block, verified) = committed_network_proof_app_for_test();
        let expected_wire = block.encode_wire().expect("canonical executed wire");
        let commitment = verified.execution();
        let executed_wire = verified.canonical_executed_wire().unwrap();
        assert_ne!(
            expected_wire, executed_wire,
            "the transport retains original native certificate bytes"
        );
        assert_eq!(
            commitment.executed_block_wire_hash,
            Hash::new(&executed_wire)
        );
        assert_eq!(
            commitment.executed_block_wire_len,
            u64::try_from(executed_wire.len()).unwrap()
        );
        let response =
            super::ledger_executed_block_wire_response(State(app), axum::extract::Path(2))
                .await
                .expect("finalized block wire");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .map(HeaderValue::as_bytes),
            Some(crate::utils::NORITO_MIME_TYPE.as_bytes())
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::X_CONTENT_TYPE_OPTIONS)
                .map(HeaderValue::as_bytes),
            Some(b"nosniff".as_slice())
        );
        let actual_wire = torii_body_bytes(response, "wire body").await;
        assert_eq!(actual_wire.as_ref(), expected_wire.as_slice());
        let restored =
            iroha_data_model::block::decode_framed_signed_block(actual_wire.as_ref()).unwrap();
        assert_eq!(restored.commit_certificate(), block.commit_certificate());
        assert_eq!(
            restored.executed_block_wire_hash().unwrap(),
            commitment.executed_block_wire_hash
        );
    });
}
#[test]
fn executed_block_wire_handler_rejects_missing_and_unfinalized_heights() {
    run_executed_block_wire_handler_test("executed-wire-negative-heights", || async {
        let app = mk_app_state_for_tests();
        let (staged, _) = make_signed_block(1, None);
        store_block(&app, staged);
        for height in [1_u64, 2] {
            let error = super::ledger_executed_block_wire_response(
                State(app.clone()),
                axum::extract::Path(height),
            )
            .await
            .expect_err("unfinalized or missing block must fail");
            assert_eq!(error.into_response().status(), StatusCode::NOT_FOUND);
        }
        let error =
            super::ledger_executed_block_wire_response(State(app.clone()), axum::extract::Path(0))
                .await
                .expect_err("zero height must fail");
        assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
        const SMALL_HANDLER_STACK_BYTES: usize = 256 * 1024;
        let small_stack_app = app.clone();
        let caller = std::thread::Builder::new()
            .name("executed-wire-small-handler".to_owned())
            .stack_size(SMALL_HANDLER_STACK_BYTES)
            .spawn(move || {
                for height in [1_u64, 2] {
                    let error =
                        futures::executor::block_on(super::ledger_executed_block_wire_response(
                            State(small_stack_app.clone()),
                            axum::extract::Path(height),
                        ))
                        .expect_err("small-stack staged or missing block must fail");
                    assert_eq!(error.into_response().status(), StatusCode::NOT_FOUND);
                }
                let error =
                    futures::executor::block_on(super::ledger_executed_block_wire_response(
                        State(small_stack_app),
                        axum::extract::Path(0),
                    ))
                    .expect_err("small-stack zero height must fail");
                assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
            })
            .expect("spawn small-stack executed-block handler caller");
        if let Err(payload) = caller.join() {
            std::panic::resume_unwind(payload);
        }
    });
}
#[test]
fn executed_block_wire_handler_fails_closed_on_hash_and_execution_shape_drift() {
    run_executed_block_wire_handler_test("executed-wire-fail-closed", || async {
        let mismatched = mk_app_state_for_tests();
        let (block, _) = make_signed_block(1, None);
        let header = block.header();
        store_block(&mismatched, block);
        let other_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            b"different finalized block hash",
        ));
        record_committed_block_hash_for_test(&mismatched, header, other_hash);
        let error =
            super::ledger_executed_block_wire_response(State(mismatched), axum::extract::Path(1))
                .await
                .expect_err("state/Kura hash drift must fail");
        assert_eq!(
            error.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let resultless = mk_app_state_for_tests();
        let (block, _) = make_signed_block(1, None);
        let block = block
            .canonical_resultless_proposal()
            .expect("valid original proposal");
        let header = block.header();
        let block_hash = store_block(&resultless, block);
        record_committed_block_hash_for_test(&resultless, header, block_hash);
        let error =
            super::ledger_executed_block_wire_response(State(resultless), axum::extract::Path(1))
                .await
                .expect_err("resultless proposal must not be exposed as executed wire");
        assert_eq!(
            error.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    });
}
#[test]
fn block_proof_capacity_responses_distinguish_work_from_bytes() {
    for resource in [
        BlockProofResource::BlockWireBytes,
        BlockProofResource::ResponseBytes,
    ] {
        assert_eq!(
            super::block_proof_capacity_response(resource, 33, 32).status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
    assert_eq!(
        super::block_proof_capacity_response(BlockProofResource::WorkItems, 7, 6).status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        super::executed_block_wire_too_large_response(NonZeroU64::new(1).unwrap()).status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}
#[test]
fn block_proof_limits_use_the_configured_query_work_ceiling() {
    let app = mk_app_state_for_tests();
    let limits = super::block_proof_limits(&app.state);
    assert_eq!(
        limits.max_work_items,
        app.state.pipeline_snapshot().query_max_fetch_size
    );
    assert_eq!(
        limits.max_block_wire_bytes,
        iroha_data_model::block::proofs::AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1 as u64
    );
    assert_eq!(limits.max_response_bytes, limits.max_block_wire_bytes);
}
#[test]
fn block_proof_errors_distinguish_absence_from_persisted_corruption() {
    let height = NonZeroU64::new(7).expect("non-zero height");
    let other_height = NonZeroU64::new(8).expect("non-zero height");
    let entry_hash = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::new(
        b"missing block proof entrypoint",
    ));
    for error in [
        BlockProofError::BlockNotFound(height),
        BlockProofError::EntrypointNotFound {
            entry_hash,
            block_height: height,
        },
    ] {
        assert_eq!(
            super::map_block_proof_error(error).into_response().status(),
            StatusCode::NOT_FOUND
        );
    }
    for error in [
        BlockProofError::BlockHashMismatch {
            block_height: height,
            expected: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                b"expected committed block hash",
            )),
            actual: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                b"mismatched Kura body hash",
            )),
        },
        BlockProofError::BlockHeightMismatch {
            requested: height,
            actual: other_height,
        },
        BlockProofError::Storage {
            block_height: height,
            reason: "bad finalized wire".into(),
        },
        BlockProofError::InvalidOutputs {
            block_height: height,
            reason: "bad complete source join".into(),
        },
        BlockProofError::MissingResults(height),
    ] {
        assert_eq!(
            super::map_block_proof_error(error).into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}

include!("part_5b_finalized_block.rs");

#[cfg(feature = "connect")]
include!("part_5_threshold_key_lifecycle.rs");

#[tokio::test]
async fn full_ledger_carrier_authentication_precedes_height_or_hash_lookup() {
    let app = mk_app_state_for_tests();
    let wire = super::handler_ledger_executed_block_wire(
        State(Arc::clone(&app)),
        axum::extract::Path(0),
        HeaderMap::new(),
        Method::GET,
        "/v1/ledger/block/0".parse().unwrap(),
    )
    .await
    .expect_err("unsigned request cannot inspect height validity");
    assert_eq!(wire.into_response().status(), StatusCode::UNAUTHORIZED);
    let proof = super::handler_block_proof(
        State(app),
        axum::extract::Path((0, "invalid-hash".to_owned())),
        HeaderMap::new(),
        Method::GET,
        "/v1/ledger/block/0/proof/invalid-hash".parse().unwrap(),
    )
    .await
    .expect_err("unsigned request cannot inspect proof selectors");
    assert_eq!(proof.into_response().status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn full_ledger_carrier_rejects_account_and_dataspace_grants_and_rechecks_revocation() {
    use iroha_executor_data_model::permission::query::CanReadAccountData;
    let key = checked_torii_test_ed25519_keypair(0xc4, "full carrier caller");
    let account = AccountId::new(key.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&account));
    let uri: Uri = "/v1/ledger/block/1".parse().unwrap();
    let authenticate = || {
        let headers = signed_network_app_headers(
            app.state.network_id_ref(),
            &account,
            &key,
            &Method::GET,
            &uri,
            &[],
        );
        super::authenticate_full_ledger_carrier_reader(&app, &headers, &Method::GET, &uri)
    };
    assert!(authenticate().is_err());
    grant_account_permission_for_test(
        &app,
        &account,
        CanReadAccountData {
            account: account.clone(),
        }
        .into(),
    );
    assert!(
        authenticate().is_err(),
        "one account does not authorize unrelated outputs"
    );
    grant_account_permission_for_test(
        &app,
        &account,
        CanReadRestrictedDataspace {
            dataspace: DataSpaceId::new(2),
        }
        .into(),
    );
    assert!(
        authenticate().is_err(),
        "one dataspace does not authorize a mixed carrier"
    );
    let permission: Permission = CanReadAllLedgerData.into();
    grant_account_permission_for_test(&app, &account, permission.clone());
    assert_eq!(authenticate().unwrap(), account);
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut block = app.state.block(header);
    let mut tx = block.transaction();
    assert!(
        tx.world_mut_for_testing()
            .remove_account_permission(&account, &permission)
    );
    tx.apply();
    block.commit_world_overlay_for_testing().unwrap();
    assert!(
        authenticate().is_err(),
        "committed revocation applies to the next read"
    );
}

#[test]
fn full_ledger_carrier_rejects_foreign_network_and_changed_path() {
    let uri: Uri = "/v1/ledger/block/1".parse().unwrap();
    let (app, headers) = foreign_network_signed_app_fixture(&Method::GET, &uri, &[], 0xc5, 0xc7);
    let foreign_key = checked_torii_test_ed25519_keypair(0xc5, "foreign carrier caller");
    let foreign_account = AccountId::new(foreign_key.public_key().clone());
    grant_account_permission_for_test(&app, &foreign_account, CanReadAllLedgerData.into());
    assert!(
        super::authenticate_full_ledger_carrier_reader(&app, &headers, &Method::GET, &uri).is_err()
    );
    let key = checked_torii_test_ed25519_keypair(0xc6, "bound carrier request");
    let account = AccountId::new(key.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&account));
    grant_account_permission_for_test(&app, &account, CanReadAllLedgerData.into());
    let headers = signed_network_app_headers(
        app.state.network_id_ref(),
        &account,
        &key,
        &Method::GET,
        &uri,
        &[],
    );
    let altered: Uri = "/v1/ledger/block/2".parse().unwrap();
    assert!(
        super::authenticate_full_ledger_carrier_reader(&app, &headers, &Method::GET, &altered)
            .is_err()
    );
}

#[test]
fn full_ledger_carrier_honors_exact_role_and_role_revocation() {
    use iroha_data_model::role::{Role, RoleId};
    let key = checked_torii_test_ed25519_keypair(0xc8, "role-bound carrier reader");
    let account = AccountId::new(key.public_key().clone());
    let role_id: RoleId = "full_carrier_reader".parse().unwrap();
    let role = Role::new(role_id.clone(), account.clone())
        .add_permission(CanReadAllLedgerData)
        .build(&account);
    let mut world = World::with_assets_and_roles(
        [],
        [Account::new(account.clone()).build(&account)],
        [],
        [],
        [],
        [role],
    );
    world.grant_role_for_tests(account.clone(), role_id);
    let app = mk_app_state_for_tests_with_world(world);
    assert!(super::require_full_ledger_carrier_permission(&app, &account).is_ok());
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut block = app.state.block(header);
    let mut tx = block.transaction();
    tx.world_mut_for_testing().remove_account_roles(&account);
    tx.apply();
    block.commit_world_overlay_for_testing().unwrap();
    assert!(super::require_full_ledger_carrier_permission(&app, &account).is_err());
}

// Local pending custody only: a submission receipt does not promise restart durability.
fn lifecycle_pending_wire(app: &SharedAppState) -> Vec<Vec<u8>> {
    use iroha_version::codec::EncodeVersioned as _;
    let view = app.state.view();
    app.queue
        .all_transactions(&view)
        .map(|transaction| transaction.entrypoint().encode_versioned())
        .collect()
}

// Derive the genuine metadata-only prefix through the same original source and codec owner.
// The occupied frame pool refuses the actual shared shell before source bytes/body decoding.
// This is a non-authorizing test preflight: its work remains on the original cumulative owner.
fn pipeline_status_original_marker_refusal_work(
    app: &SharedAppState,
    owner: &crate::history_producer::HistoryProducerOwner,
    height: std::num::NonZeroUsize,
) -> u64 {
    let frames = owner.cold_frames();
    assert_eq!(frames.reserved_bytes(), frames.limit_bytes());
    let expected = frames
        .try_reserve(iroha_data_model::block::SharedSignedBlock::allocation_layout())
        .unwrap_err();
    assert!(matches!(
        expected,
        iroha_allocation::AllocationRefusal::Capacity { .. }
    ));
    let before = owner.allocation_context().consumed_allocated_bytes();
    let budget = owner.canonical_history_budget();
    match owner.scope(|| app.state.read_canonical_history_block(height, &budget)) {
        Err(iroha_core::execution_attempt::ExecutionAttemptError::Deferred(original)) => {
            assert_eq!(original.allocation_refusal(), Some(&expected));
        }
        other => {
            panic!("original metadata preflight must stop at the occupied shared shell: {other:?}")
        }
    }
    assert_eq!(frames.reserved_bytes(), frames.limit_bytes());
    let marker_work = owner
        .allocation_context()
        .consumed_allocated_bytes()
        .checked_sub(before)
        .unwrap();
    assert!(
        marker_work > 0,
        "the original durable marker genuinely decodes before shell admission"
    );
    marker_work
}

#[tokio::test]
async fn pipeline_status_authentication_keeps_original_admitted_query_pool_on_refusal() {
    let (app, hash, _chain) = canonical_outcome_test_fixture(false);
    let owner = crate::history_producer::HistoryProducerOwner::authentication_read(&app).unwrap();
    let frames = owner.cold_frames();
    assert_eq!(frames.reserved_bytes(), 0);
    let blocker = frames.try_reserve_bytes(frames.limit_bytes()).unwrap();
    let marker_work = pipeline_status_original_marker_refusal_work(
        &app,
        &owner,
        std::num::NonZeroUsize::new(2).unwrap(),
    );
    let before_status = owner.allocation_context().consumed_allocated_bytes();
    app.pipeline_status_cache.record_entry(
        hash,
        PipelineStatusEntry::fresh(
            PipelineStatusKind::Applied,
            Some(NonZeroU64::new(2).unwrap()),
            None,
        ),
    );
    let result = owner.scope(|| pipeline_status_terminal_or_state_entry(&app, &hash));
    assert!(
        matches!(
            result,
            Err(Error::Query(ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
            )))
        ),
        "committed status must retain its original admitted query pool: {result:?}"
    );
    assert_eq!(frames.reserved_bytes(), frames.limit_bytes());
    assert_eq!(
        owner.allocation_context().consumed_allocated_bytes(),
        before_status.checked_add(marker_work).unwrap(),
        "only the original durable marker decodes before the refused status shell"
    );
    let refused_work = owner.allocation_context().consumed_allocated_bytes();
    assert_eq!(
        app.pipeline_status_cache.lookup(&hash).unwrap().kind,
        PipelineStatusKind::Applied
    );
    drop(blocker);
    let (entry, source) = owner
        .scope(|| pipeline_status_terminal_or_state_entry(&app, &hash))
        .expect("retry reuses the same original source pool and cumulative owner")
        .unwrap();
    assert_eq!(entry.kind, PipelineStatusKind::Applied);
    assert_eq!(entry.block_height, Some(NonZeroU64::new(2).unwrap()));
    assert_eq!(source, "state");
    assert!(owner.allocation_context().consumed_allocated_bytes() > refused_work);
    assert_eq!(
        frames.reserved_bytes(),
        0,
        "the scalar status retires its actual carrier before returning"
    );
}

#[tokio::test]
async fn pipeline_status_checkpoint_reader_preserves_exact_rejection_and_publication_bracket() {
    for rejected in [false, true] {
        let (app, hash, mut chain) = canonical_outcome_test_fixture(rejected);
        let original = canonical_transaction_outcome(&app.state, &hash)
            .unwrap()
            .unwrap();
        let observed =
            canonical_transaction_outcome_with_authenticator(&app.state, &hash, |anchor| {
                let outcome = authenticate_pipeline_transaction_outcome(&app, &hash, anchor)?;
                append_canonical_outcome_test_block(&mut chain, anchor, false);
                Ok(outcome)
            })
            .expect("an unrelated committed append keeps the exact target source")
            .unwrap();
        match (original, observed) {
            (
                CanonicalTransactionOutcome::Applied {
                    height: old_height,
                    settled_at: old_time,
                },
                CanonicalTransactionOutcome::Applied { height, settled_at },
            ) => {
                assert_eq!(height, old_height);
                assert_eq!(settled_at, old_time);
            }
            (
                CanonicalTransactionOutcome::Rejected {
                    height: old_height,
                    reason: old_reason,
                },
                CanonicalTransactionOutcome::Rejected { height, reason },
            ) => {
                assert_eq!(height, old_height);
                assert_eq!(reason, old_reason);
            }
            changed => panic!(
                "checkpoint authentication cannot substitute the original outcome: {changed:?}"
            ),
        }
        let anchor = canonical_transaction_anchor(&app.state, &hash)
            .unwrap()
            .unwrap();
        let error =
            canonical_transaction_outcome_with_authenticator(&app.state, &hash, |captured| {
                let outcome = authenticate_pipeline_transaction_outcome(&app, &hash, captured)?;
                let mut membership = app.state.transactions.block_and_revert();
                membership.insert_block(
                    [anchor.entrypoint_hash].into_iter().collect(),
                    NonZeroUsize::new(usize::try_from(chain.height()).unwrap()).unwrap(),
                );
                membership.commit().unwrap();
                Ok(outcome)
            })
            .expect_err(
                "a replaced original membership must refuse despite successful authentication",
            );
        assert!(
            query_conversion_message(&error)
                .unwrap()
                .contains("canonical binding changed during outcome authentication")
        );
    }
}

#[tokio::test]
async fn pipeline_status_rejects_foreign_query_owner_but_absent_membership_needs_no_history_admission()
 {
    let (app, hash, _chain) = canonical_outcome_test_fixture(false);
    let foreign = crate::history_producer::HistoryProducerOwner::for_test();
    let error = foreign
        .scope(|| pipeline_status_terminal_or_state_entry(&app, &hash))
        .expect_err("equal local credits cannot substitute the original request generation");
    assert!(matches!(
        error,
        Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
        ))
    ));
    let absent = HashOf::from_untyped_unchecked(Hash::new(b"not in original committed membership"));
    assert!(
        foreign
            .scope(|| pipeline_status_terminal_or_state_entry(&app, &absent))
            .expect("absence must not manufacture or require a history query owner")
            .is_none()
    );
}

#[tokio::test]
async fn pipeline_status_checkpoint_outcome_rejects_duplicate_original_borrowed_rows() {
    let (app, hash, _chain) = canonical_outcome_test_fixture(false);
    let anchor = canonical_transaction_anchor(&app.state, &hash)
        .unwrap()
        .unwrap();
    let owner = crate::history_producer::HistoryProducerOwner::authentication_read(&app).unwrap();
    let error = owner
        .scope(|| {
            let carrier = app
                .state
                .read_executed_carrier_from_checkpoints(
                    anchor.height,
                    1_000,
                    1 << 40,
                    &owner.canonical_history_budget(),
                )
                .unwrap();
            canonical_transaction_outcome_from_reader(&hash, anchor, |visitor| {
                carrier
                    .visit_network_transactions(anchor.block_hash, &mut *visitor)
                    .map_err(|error| crate::canonical_history::query_attempt_error(error.into()))?;
                carrier
                    .visit_network_transactions(anchor.block_hash, visitor)
                    .map_err(|error| crate::canonical_history::query_attempt_error(error.into()))
            })
        })
        .expect_err("even the same original certified row cannot be counted twice");
    assert_eq!(
        query_conversion_message(&error).unwrap(),
        format!(
            "committed transaction status projection is inconsistent: transaction {hash} occurs more than once in its finalized carrier"
        )
    );
}

#[tokio::test]
async fn pipeline_status_genesis_requires_actual_h2_and_refuses_substituted_successor() {
    use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let hash = chain
        .genesis()
        .external_transactions()
        .next()
        .expect("original signed genesis transaction")
        .hash();
    let mut app = mk_app_state_for_tests();
    let unique = Arc::get_mut(&mut app).unwrap();
    unique.state = chain.state().clone();
    unique.kura = chain.kura().clone();
    let anchor = canonical_transaction_anchor(&app.state, &hash)
        .unwrap()
        .expect("the original genesis transaction has committed membership");
    assert_eq!(anchor.height, NonZeroUsize::MIN);
    app.pipeline_status_cache.record_entry(
        hash,
        PipelineStatusEntry::fresh(PipelineStatusKind::Applied, Some(NonZeroU64::MIN), None),
    );
    let error = pipeline_status_terminal_or_state_entry(&app, &hash)
        .expect_err("cached Applied and opaque G1 State cannot replace original H2 authentication");
    assert!(
        query_conversion_message(&error)
            .unwrap()
            .contains("height 2 is not committed in this view")
    );
    chain.commit(Vec::new());
    let (entry, source) = pipeline_status_terminal_or_state_entry(&app, &hash)
        .unwrap()
        .unwrap();
    assert_eq!(entry.kind, PipelineStatusKind::Applied);
    assert_eq!(entry.block_height, Some(NonZeroU64::MIN));
    assert_eq!(source, "state");
    let replacement = HashOf::from_untyped_unchecked(Hash::new(b"substituted HTTP status H2"));
    assert_ne!(replacement, chain.committed(2).block().hash());
    let mut journal = app.state.block_hashes.block_and_revert();
    journal.push_for_tests(replacement);
    journal.commit_for_tests();
    let ordinary = canonical_transaction_outcome(&app.state, &hash)
        .expect_err("original full-prefix status refuses H2 substitution");
    let error = pipeline_status_terminal_or_state_entry(&app, &hash)
        .expect_err("the HTTP G1 branch must retain the same original H2 requirement");
    assert_eq!(
        query_conversion_message(&error),
        query_conversion_message(&ordinary)
    );
    assert_eq!(
        app.pipeline_status_cache.lookup(&hash).unwrap().kind,
        PipelineStatusKind::Applied
    );
}

#[tokio::test]
async fn pipeline_status_cached_applied_refuses_removed_original_membership() {
    let (app, hash, chain) = canonical_outcome_test_fixture(false);
    let original = chain.committed(2);
    let original_wire = original.block().encode_wire().unwrap();
    let original_body: *const SignedBlock = original.block().as_ref();
    let (entry, source) = pipeline_status_terminal_or_state_entry(&app, &hash)
        .unwrap()
        .unwrap();
    assert_eq!(entry.kind, PipelineStatusKind::Applied);
    assert_eq!(source, "state");
    let cached = app.pipeline_status_cache.lookup(&hash).unwrap();
    assert_eq!(cached.block_height, Some(NonZeroU64::new(2).unwrap()));
    let mut membership = app.state.transactions.block_and_revert();
    membership.insert_block(HashSet::new(), NonZeroUsize::new(2).unwrap());
    membership
        .commit()
        .expect("remove only the actual latest membership generation");
    assert!(
        canonical_transaction_anchor(&app.state, &hash)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        app.state.block_hashes.view().get(1).copied(),
        Some(original.block().hash())
    );
    let result = pipeline_status_terminal_or_state_entry(&app, &hash);
    let Err(Error::Query(ValidationFail::QueryFailed(
        iroha_data_model::query::error::QueryExecutionFail::Conversion(message),
    ))) = result
    else {
        panic!("cached Applied must retain its original canonical membership: {result:?}");
    };
    assert_eq!(
        message,
        format!(
            "committed transaction status projection is inconsistent: transaction {hash} has cached Applied without its exact canonical binding"
        )
    );
    let retained = app.pipeline_status_cache.lookup(&hash).unwrap();
    assert_eq!(
        (
            retained.kind,
            retained.block_height,
            retained.rejection,
            retained.observed_at
        ),
        (
            cached.kind,
            cached.block_height,
            cached.rejection,
            cached.observed_at
        )
    );
    assert!(std::ptr::eq(original.block().as_ref(), original_body));
    assert_eq!(original.block().encode_wire().unwrap(), original_wire);
}

#[cfg(any(feature = "app_api", feature = "connect"))]
#[tokio::test]
async fn prepared_submit_outcome_cached_applied_refuses_removed_original_membership() {
    let (app, hash, chain) = canonical_outcome_test_fixture(false);
    let original = chain.committed(2);
    let original_wire = original.block().encode_wire().unwrap();
    let original_body: *const SignedBlock = original.block().as_ref();
    let transaction = original.block().external_transactions().next().unwrap();
    assert_eq!(transaction.hash(), hash);
    assert_eq!(
        routing::prepared_submit_outcome(&app, transaction).unwrap(),
        Some("Applied")
    );
    pipeline_status_terminal_or_state_entry(&app, &hash)
        .unwrap()
        .unwrap();
    let cached = app.pipeline_status_cache.lookup(&hash).unwrap();
    let mut membership = app.state.transactions.block_and_revert();
    membership.insert_block(HashSet::new(), NonZeroUsize::new(2).unwrap());
    membership
        .commit()
        .expect("remove the original transaction membership without altering its carrier");
    assert!(
        canonical_transaction_anchor(&app.state, &hash)
            .unwrap()
            .is_none()
    );
    let result = routing::prepared_submit_outcome(&app, transaction);
    let Err(Error::Query(ValidationFail::QueryFailed(
        iroha_data_model::query::error::QueryExecutionFail::Conversion(message),
    ))) = result
    else {
        panic!(
            "prepared submission cache must retain its original canonical membership: {result:?}"
        );
    };
    assert_eq!(
        message,
        format!(
            "committed transaction status projection is inconsistent: transaction {hash} has cached Applied without its exact canonical binding"
        )
    );
    let retained = app.pipeline_status_cache.lookup(&hash).unwrap();
    assert_eq!(
        (
            retained.kind,
            retained.block_height,
            retained.rejection,
            retained.observed_at
        ),
        (
            cached.kind,
            cached.block_height,
            cached.rejection,
            cached.observed_at
        )
    );
    assert!(std::ptr::eq(original.block().as_ref(), original_body));
    assert_eq!(original.block().encode_wire().unwrap(), original_wire);
}

#[tokio::test]
async fn pipeline_status_cached_block_outcomes_require_binding_even_without_height_metadata() {
    let app = mk_app_state_for_tests();
    let cases = [
        (PipelineStatusKind::Applied, None),
        (PipelineStatusKind::Applied, Some(NonZeroU64::MIN)),
        (PipelineStatusKind::Committed, None),
        (PipelineStatusKind::Committed, Some(NonZeroU64::MIN)),
        (PipelineStatusKind::Rejected, Some(NonZeroU64::MIN)),
        (PipelineStatusKind::Expired, Some(NonZeroU64::MIN)),
    ];
    for (index, (kind, height)) in cases.into_iter().enumerate() {
        let hash = HashOf::from_untyped_unchecked(Hash::new(
            format!("absent canonical cache outcome {index}").as_bytes(),
        ));
        app.pipeline_status_cache
            .record_entry(hash, PipelineStatusEntry::fresh(kind, height, None));
        let original = app.pipeline_status_cache.lookup(&hash).unwrap();
        assert!(
            canonical_transaction_anchor(&app.state, &hash)
                .unwrap()
                .is_none()
        );
        let error = pipeline_status_local_entry_checked(&app, &hash).expect_err(
            "neither a terminal nor second local cache lookup may promote a block hint",
        );
        assert_eq!(
            query_conversion_message(&error).unwrap(),
            format!(
                "committed transaction status projection is inconsistent: transaction {hash} has cached {} without its exact canonical binding",
                kind.as_str(),
            )
        );
        let retained = app.pipeline_status_cache.lookup(&hash).unwrap();
        assert_eq!(
            (
                retained.kind,
                retained.block_height,
                retained.rejection,
                retained.observed_at
            ),
            (
                original.kind,
                original.block_height,
                original.rejection,
                original.observed_at
            )
        );
    }
}

#[tokio::test]
async fn pipeline_status_cache_only_local_rejection_expiry_and_candidate_hints_remain_available() {
    let app = mk_app_state_for_tests();
    let cases = [
        (
            PipelineStatusKind::Rejected,
            None,
            Some("Transaction validation failed."),
        ),
        (PipelineStatusKind::Expired, None, None),
        (PipelineStatusKind::Approved, Some(NonZeroU64::MIN), None),
    ];
    let foreign = crate::history_producer::HistoryProducerOwner::for_test();
    for (index, (kind, height, rejection)) in cases.into_iter().enumerate() {
        let hash = HashOf::from_untyped_unchecked(Hash::new(
            format!("local cache-only hint {index}").as_bytes(),
        ));
        app.pipeline_status_cache
            .record_entry(hash, PipelineStatusEntry::fresh(kind, height, rejection));
        assert!(
            canonical_transaction_anchor(&app.state, &hash)
                .unwrap()
                .is_none()
        );
        let (observed, source) = foreign
            .scope(|| pipeline_status_local_entry_checked(&app, &hash))
            .expect("local hints need no fabricated history admission")
            .unwrap();
        assert_eq!(
            (observed.kind, observed.block_height, observed.rejection),
            (kind, height, rejection)
        );
        assert_eq!(source, "cache");
        assert!(!matches!(
            observed.kind,
            PipelineStatusKind::Applied | PipelineStatusKind::Committed
        ));
    }
}

#[cfg(any(feature = "app_api", feature = "connect"))]
#[tokio::test]
async fn prepared_submit_outcome_preserves_local_rejection_expiry_and_candidate_hints() {
    for (kind, height, expected) in [
        (PipelineStatusKind::Rejected, None, "Rejected"),
        (PipelineStatusKind::Expired, None, "Rejected"),
        (
            PipelineStatusKind::Approved,
            Some(NonZeroU64::MIN),
            "Pending",
        ),
    ] {
        let (app, hash, chain) = canonical_outcome_test_fixture(false);
        let original = chain.committed(2);
        let transaction = original.block().external_transactions().next().unwrap();
        assert_eq!(transaction.hash(), hash);
        let mut membership = app.state.transactions.block_and_revert();
        membership.insert_block(HashSet::new(), NonZeroUsize::new(2).unwrap());
        membership.commit().unwrap();
        assert!(
            canonical_transaction_anchor(&app.state, &hash)
                .unwrap()
                .is_none()
        );
        app.pipeline_status_cache
            .record_entry(hash, PipelineStatusEntry::fresh(kind, height, None));
        assert_eq!(
            routing::prepared_submit_outcome(&app, transaction).unwrap(),
            Some(expected)
        );
        assert_ne!(expected, "Applied");
        assert_eq!(app.pipeline_status_cache.lookup(&hash).unwrap().kind, kind);
    }
}

#[tokio::test]
async fn pipeline_status_pending_refresh_retains_original_query_refusal_and_pending_source() {
    let (app, hash, chain) = canonical_outcome_test_fixture(false);
    let original = chain.committed(2);
    let original_wire = original.block().encode_wire().unwrap();
    let original_body: *const SignedBlock = original.block().as_ref();
    let height = NonZeroU64::new(2).unwrap();
    let observed_at = Instant::now();
    app.pipeline_status_cache.record_pending_block(
        height,
        PendingBlockStatus {
            kind: PipelineStatusKind::Applied,
            block_hash: original.block().hash(),
            observed_at,
            deferred: None,
        },
    );
    assert!(app.pipeline_status_cache.lookup(&hash).is_none());
    let owner = crate::history_producer::HistoryProducerOwner::authentication_read(&app).unwrap();
    let frames = owner.cold_frames();
    let blocker = frames.try_reserve_bytes(frames.limit_bytes()).unwrap();
    let marker_work = pipeline_status_original_marker_refusal_work(
        &app,
        &owner,
        std::num::NonZeroUsize::new(2).unwrap(),
    );
    let before_status = owner.allocation_context().consumed_allocated_bytes();
    let result = owner.scope(|| pipeline_status_terminal_or_state_entry(&app, &hash));
    assert!(matches!(
        result,
        Err(Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
        )))
    ));
    assert!(
        app.pipeline_status_cache.lookup(&hash).is_none(),
        "pending cache refresh must not bypass the original query refusal with execution capacity"
    );
    let pending = app
        .pipeline_status_cache
        .pending_blocks
        .get(&height)
        .unwrap();
    assert_eq!(pending.kind, PipelineStatusKind::Applied);
    assert_eq!(pending.block_hash, original.block().hash());
    assert_eq!(pending.observed_at, observed_at);
    assert_eq!(frames.reserved_bytes(), frames.limit_bytes());
    assert_eq!(
        owner.allocation_context().consumed_allocated_bytes(),
        before_status.checked_add(marker_work).unwrap(),
        "only the original durable marker decodes before the refused status shell"
    );
    let refused_work = owner.allocation_context().consumed_allocated_bytes();
    assert!(std::ptr::eq(original.block().as_ref(), original_body));
    assert_eq!(original.block().encode_wire().unwrap(), original_wire);
    drop(pending);
    drop(blocker);
    let (entry, source) = owner
        .scope(|| pipeline_status_terminal_or_state_entry(&app, &hash))
        .expect("the same original query owner can retry")
        .unwrap();
    assert_eq!(entry.kind, PipelineStatusKind::Applied);
    assert_eq!(source, "state");
    assert_eq!(frames.reserved_bytes(), 0);
    assert!(owner.allocation_context().consumed_allocated_bytes() > refused_work);
    assert!(
        app.pipeline_status_cache
            .pending_blocks
            .get(&height)
            .is_none()
    );
    assert_eq!(
        app.pipeline_status_cache
            .pending_count
            .load(AtomicOrdering::Relaxed),
        0
    );
}

#[tokio::test]
async fn pipeline_status_pending_completion_reuses_original_carrier_and_leaves_other_sources() {
    let (app, hash, chain) = canonical_outcome_test_fixture(false);
    let anchor = canonical_transaction_anchor(&app.state, &hash)
        .unwrap()
        .unwrap();
    let height = chain.committed(2).block().header().height();
    let unrelated_height = NonZeroU64::new(3).unwrap();
    let unrelated_hash =
        HashOf::from_untyped_unchecked(Hash::new(b"unrelated pending original source"));
    let observed_at = Instant::now();
    let owner = crate::history_producer::HistoryProducerOwner::authentication_read(&app).unwrap();
    let frames = owner.cold_frames();
    let blocker = frames.try_reserve_bytes(frames.limit_bytes()).unwrap();
    let refusal = frames.try_reserve_bytes(1).unwrap_err();
    let deferred: iroha_core::execution_attempt::ExecutionDeferred = refusal.into();
    drop(blocker);
    for (pending_height, block_hash) in [
        (height, anchor.block_hash),
        (unrelated_height, unrelated_hash),
    ] {
        app.pipeline_status_cache.record_pending_block(
            pending_height,
            PendingBlockStatus {
                kind: PipelineStatusKind::Committed,
                block_hash,
                observed_at,
                deferred: Some(deferred.clone().into()),
            },
        );
    }
    let original = owner
        .scope(|| read_pipeline_transaction_carrier(&app, anchor))
        .unwrap();
    let body: *const SignedBlock = original.carrier.block().as_ref();
    let wire = original.carrier.block().encode_wire().unwrap();
    let consumed = owner.allocation_context().consumed_allocated_bytes();
    assert!(consumed > 0);
    assert!(frames.reserved_bytes() > 0);
    // Same admitted pool, no more frame capacity: completion must use its retained source.
    let remaining = frames.limit_bytes() - frames.reserved_bytes();
    let blocker = frames.try_reserve_bytes(remaining).unwrap();
    original
        .owner
        .scope(|| {
            app.pipeline_status_cache
                .complete_pending_from_carrier(&original.carrier, anchor.block_hash)
        })
        .unwrap();
    assert!(std::ptr::eq(original.carrier.block().as_ref(), body));
    assert_eq!(original.carrier.block().encode_wire().unwrap(), wire);
    assert_eq!(
        owner.allocation_context().consumed_allocated_bytes(),
        consumed,
        "pending completion must not decode a second original carrier"
    );
    assert_eq!(frames.reserved_bytes(), frames.limit_bytes());
    assert!(
        app.pipeline_status_cache
            .pending_blocks
            .get(&height)
            .is_none()
    );
    let pending = app
        .pipeline_status_cache
        .pending_blocks
        .get(&unrelated_height)
        .unwrap();
    assert_eq!(pending.kind, PipelineStatusKind::Committed);
    assert_eq!(pending.block_hash, unrelated_hash);
    assert_eq!(pending.observed_at, observed_at);
    assert_eq!(pending.deferred, Some(deferred.into()));
    assert_eq!(
        app.pipeline_status_cache.lookup(&hash).unwrap().kind,
        PipelineStatusKind::Committed
    );
    assert_eq!(
        app.pipeline_status_cache
            .pending_count
            .load(AtomicOrdering::Relaxed),
        1
    );
    drop(pending);
    drop(blocker);
    assert!(frames.reserved_bytes() > 0);
    drop(original);
    assert_eq!(
        frames.reserved_bytes(),
        0,
        "carrier retirement precedes original query-owner release"
    );
}

#[tokio::test]
async fn pipeline_status_pending_foreign_or_absent_query_keeps_exact_deferred_source() {
    let (app, hash, chain) = canonical_outcome_test_fixture(false);
    let original = chain.committed(2);
    let height = original.block().header().height();
    let observed_at = Instant::now();
    let owner = crate::history_producer::HistoryProducerOwner::authentication_read(&app).unwrap();
    let frames = owner.cold_frames();
    let blocker = frames.try_reserve_bytes(frames.limit_bytes()).unwrap();
    let deferred: iroha_core::execution_attempt::ExecutionDeferred =
        frames.try_reserve_bytes(1).unwrap_err().into();
    app.pipeline_status_cache.record_pending_block(
        height,
        PendingBlockStatus {
            kind: PipelineStatusKind::Applied,
            block_hash: original.block().hash(),
            observed_at,
            deferred: Some(deferred.clone().into()),
        },
    );
    let foreign = crate::history_producer::HistoryProducerOwner::for_test();
    let result = foreign.scope(|| pipeline_status_terminal_or_state_entry(&app, &hash));
    assert!(matches!(
        result,
        Err(Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
        )))
    ));
    let absent = HashOf::from_untyped_unchecked(Hash::new(b"unknown pending-query transaction"));
    let mut reads = 0;
    assert!(
        foreign
            .scope(
                || pipeline_status_terminal_or_state_entry_with_carrier_reader(
                    &app,
                    &absent,
                    |anchor| {
                        reads += 1;
                        read_pipeline_transaction_carrier(&app, anchor)
                    },
                )
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        reads, 0,
        "absent membership must not acquire a pending or query producer"
    );
    assert!(app.pipeline_status_cache.lookup(&hash).is_none());
    let pending = app
        .pipeline_status_cache
        .pending_blocks
        .get(&height)
        .unwrap();
    assert_eq!(pending.kind, PipelineStatusKind::Applied);
    assert_eq!(pending.block_hash, original.block().hash());
    assert_eq!(pending.observed_at, observed_at);
    assert_eq!(pending.deferred, Some(deferred.into()));
    assert_eq!(owner.allocation_context().consumed_allocated_bytes(), 0);
    assert_eq!(foreign.allocation_context().consumed_allocated_bytes(), 0);
    assert_eq!(frames.reserved_bytes(), frames.limit_bytes());
    drop(pending);
    drop(blocker);
}

#[tokio::test]
async fn pipeline_status_pending_recheck_refuses_changed_membership_without_cache_effects() {
    let (app, hash, chain) = canonical_outcome_test_fixture(false);
    let original = chain.committed(2);
    let height = original.block().header().height();
    let observed_at = Instant::now();
    app.pipeline_status_cache.record_pending_block(
        height,
        PendingBlockStatus {
            kind: PipelineStatusKind::Applied,
            block_hash: original.block().hash(),
            observed_at,
            deferred: None,
        },
    );
    let owner = crate::history_producer::HistoryProducerOwner::authentication_read(&app).unwrap();
    let mut reads = 0;
    let error = owner
        .scope(|| {
            pipeline_status_terminal_or_state_entry_with_carrier_reader(&app, &hash, |anchor| {
                reads += 1;
                let retained = read_pipeline_transaction_carrier(&app, anchor)?;
                let mut membership = app.state.transactions.block_and_revert();
                membership.insert_block(HashSet::new(), NonZeroUsize::new(2).unwrap());
                membership.commit().unwrap();
                Ok(retained)
            })
        })
        .expect_err("authenticated bytes cannot outlive a changed original canonical membership");
    assert_eq!(reads, 1);
    assert!(
        query_conversion_message(&error)
            .unwrap()
            .contains("canonical binding changed during outcome authentication")
    );
    assert!(app.pipeline_status_cache.lookup(&hash).is_none());
    let pending = app
        .pipeline_status_cache
        .pending_blocks
        .get(&height)
        .unwrap();
    assert_eq!(pending.kind, PipelineStatusKind::Applied);
    assert_eq!(pending.block_hash, original.block().hash());
    assert_eq!(pending.observed_at, observed_at);
    assert_eq!(pending.deferred, None);
    assert_eq!(
        app.pipeline_status_cache
            .pending_count
            .load(AtomicOrdering::Relaxed),
        1
    );
    assert_eq!(owner.cold_frames().reserved_bytes(), 0);
    assert!(owner.allocation_context().consumed_allocated_bytes() > 0);
}

#[tokio::test]
async fn pipeline_status_pending_replacement_and_foreign_carrier_cannot_retire_original_entry() {
    let (app, hash, chain) = canonical_outcome_test_fixture(false);
    let anchor = canonical_transaction_anchor(&app.state, &hash)
        .unwrap()
        .unwrap();
    let height = chain.committed(2).block().header().height();
    let observed_at = Instant::now();
    app.pipeline_status_cache.record_pending_block(
        height,
        PendingBlockStatus {
            kind: PipelineStatusKind::Applied,
            block_hash: anchor.block_hash,
            observed_at,
            deferred: None,
        },
    );
    let changed =
        HashOf::from_untyped_unchecked(Hash::new(b"replaced pending source at same height"));
    let owner = crate::history_producer::HistoryProducerOwner::authentication_read(&app).unwrap();
    let mut reads = 0;
    let (entry, source) = owner
        .scope(|| {
            pipeline_status_terminal_or_state_entry_with_carrier_reader(&app, &hash, |captured| {
                reads += 1;
                let retained = read_pipeline_transaction_carrier(&app, captured)?;
                let error = app
                    .pipeline_status_cache
                    .complete_pending_from_carrier(&retained.carrier, changed)
                    .expect_err(
                        "a foreign source cannot populate or retire the original pending cache",
                    );
                assert!(
                    query_conversion_message(&error)
                        .unwrap()
                        .contains("pending completion carrier differs from its canonical binding")
                );
                assert!(app.pipeline_status_cache.lookup(&hash).is_none());
                app.pipeline_status_cache.record_pending_block(
                    height,
                    PendingBlockStatus {
                        kind: PipelineStatusKind::Committed,
                        block_hash: changed,
                        observed_at: Instant::now(),
                        deferred: None,
                    },
                );
                Ok(retained)
            })
        })
        .unwrap()
        .unwrap();
    assert_eq!(reads, 1);
    assert_eq!(entry.kind, PipelineStatusKind::Applied);
    assert_eq!(source, "state");
    let pending = app
        .pipeline_status_cache
        .pending_blocks
        .get(&height)
        .unwrap();
    assert_eq!(pending.kind, PipelineStatusKind::Committed);
    assert_eq!(pending.block_hash, changed);
    assert_eq!(pending.observed_at, observed_at);
    assert_eq!(pending.deferred, None);
    assert_eq!(
        app.pipeline_status_cache
            .pending_count
            .load(AtomicOrdering::Relaxed),
        1
    );
    assert_eq!(owner.cold_frames().reserved_bytes(), 0);
}
