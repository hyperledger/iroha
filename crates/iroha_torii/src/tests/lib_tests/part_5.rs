#[test]
fn handler_local_api_token_checks_use_the_canonical_evaluator() {
    let source = include_str!("../../lib.rs");
    let mcp_source = include_str!("../../mcp.rs");
    let retired_raw_set = ["api_tokens_", "set"].concat();
    let direct_membership_check = ["configured_tokens.", "contains"].concat();
    assert!(
        !source.contains(&retired_raw_set) && !mcp_source.contains(&retired_raw_set),
        "runtime API-token policy must not retain the retired raw-token set"
    );
    assert!(
        !source.contains(&direct_membership_check),
        "handler-local API-token checks must use evaluate_api_token"
    );
}
#[test]
fn norito_rpc_canary_rejects_duplicate_api_token_headers() {
    let cfg = actual::NoritoRpcTransport {
        enabled: true,
        require_mtls: false,
        stage: actual::NoritoRpcStage::Canary,
        allowed_clients: vec!["allowed-canary".into()],
        mtls_trusted_proxy_cidrs: Vec::new(),
    };
    let mut headers = HeaderMap::new();
    headers.append(HEADER_API_TOKEN, HeaderValue::from_static("allowed-canary"));
    headers.append(
        HEADER_API_TOKEN,
        HeaderValue::from_static("attacker-choice"),
    );
    let allowed_client_digests =
        limits::ApiTokenDigestSet::from_tokens(cfg.allowed_clients.iter().map(String::as_str));

    assert_eq!(
        evaluate_norito_rpc_gate(&cfg, &allowed_client_digests, &[], &headers, None),
        Err(NoritoRpcGateFailure::CanaryDenied)
    );
}
#[tokio::test]
#[cfg(feature = "telemetry")]
async fn norito_rpc_gate_records_metrics() {
    let cfg = actual::NoritoRpcTransport {
            enabled: true,
            require_mtls: false,
            stage: actual::NoritoRpcStage::Canary,
            allowed_clients: vec!["ok".into()],
            mtls_trusted_proxy_cidrs:
                iroha_config::parameters::defaults::torii::transport::norito_rpc::mtls_trusted_proxy_cidrs(),
        };
    let app = mk_norito_rpc_test_harness(cfg.clone()).await;
    let metrics = app.telemetry.metrics();
    let trusted_remote = Some("127.0.0.1".parse().expect("trusted proxy"));
    let untrusted_remote = Some("198.51.100.10".parse().expect("untrusted proxy"));
    let mut headers = HeaderMap::new();
    headers.insert(HEADER_API_TOKEN, HeaderValue::from_static("ok"));
    app.check_norito_rpc_allowed(&headers, trusted_remote)
        .expect("canary token should be allowed");
    assert_eq!(
        metrics
            .torii_norito_rpc_gate_total
            .with_label_values(&[cfg.stage.label(), "allowed"])
            .get(),
        1
    );
    let missing_token_headers = HeaderMap::new();
    assert!(
        app.check_norito_rpc_allowed(&missing_token_headers, trusted_remote)
            .is_err()
    );
    assert_eq!(
        metrics
            .torii_norito_rpc_gate_total
            .with_label_values(&[cfg.stage.label(), "canary_missing_token"])
            .get(),
        1
    );
    let mut wrong_token_headers = HeaderMap::new();
    wrong_token_headers.insert(HEADER_API_TOKEN, HeaderValue::from_static("wrong"));
    assert!(
        app.check_norito_rpc_allowed(&wrong_token_headers, trusted_remote)
            .is_err()
    );
    assert_eq!(
        metrics
            .torii_norito_rpc_gate_total
            .with_label_values(&[cfg.stage.label(), "canary_denied"])
            .get(),
        1
    );
    let mtls_cfg = actual::NoritoRpcTransport {
            enabled: true,
            require_mtls: true,
            stage: actual::NoritoRpcStage::Ga,
            allowed_clients: Vec::new(),
            mtls_trusted_proxy_cidrs:
                iroha_config::parameters::defaults::torii::transport::norito_rpc::mtls_trusted_proxy_cidrs(),
        };
    let mtls_app = mk_norito_rpc_test_harness(mtls_cfg.clone()).await;
    let mtls_metrics = mtls_app.telemetry.metrics();
    assert!(
        mtls_app
            .check_norito_rpc_allowed(&HeaderMap::new(), trusted_remote)
            .is_err()
    );
    assert_eq!(
        mtls_metrics
            .torii_norito_rpc_gate_total
            .with_label_values(&[mtls_cfg.stage.label(), "mtls_required"])
            .get(),
        1
    );
    let mut mtls_headers = HeaderMap::new();
    mtls_headers.insert(HEADER_MTLS_FORWARD, HeaderValue::from_static("present"));
    mtls_app
        .check_norito_rpc_allowed(&mtls_headers, trusted_remote)
        .expect("mtls header should allow RPC");
    assert_eq!(
        mtls_metrics
            .torii_norito_rpc_gate_total
            .with_label_values(&[mtls_cfg.stage.label(), "allowed"])
            .get(),
        1
    );
    assert!(
        mtls_app
            .check_norito_rpc_allowed(&mtls_headers, untrusted_remote)
            .is_err()
    );
    assert_eq!(
        mtls_metrics
            .torii_norito_rpc_gate_total
            .with_label_values(&[mtls_cfg.stage.label(), "mtls_required"])
            .get(),
        2
    );
    let disabled_cfg = actual::NoritoRpcTransport {
        enabled: false,
        stage: actual::NoritoRpcStage::Disabled,
        ..Default::default()
    };
    let disabled_app = mk_norito_rpc_test_harness(disabled_cfg.clone()).await;
    let disabled_metrics = disabled_app.telemetry.metrics();
    assert!(
        disabled_app
            .check_norito_rpc_allowed(&HeaderMap::new(), trusted_remote)
            .is_err()
    );
    assert_eq!(
        disabled_metrics
            .torii_norito_rpc_gate_total
            .with_label_values(&[actual::NoritoRpcStage::Disabled.label(), "disabled"])
            .get(),
        1
    );
}
#[tokio::test]
async fn soracloud_signed_mutation_middleware_strips_internal_identity_and_rejects_replay() {
    use axum::{Router, body::Bytes, routing::post};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    async fn probe(headers: HeaderMap, body: Bytes) -> axum::response::Response {
        let verified_account = headers
            .get(axum::http::HeaderName::from_static(
                soracloud::VERIFIED_ACCOUNT_HEADER,
            ))
            .and_then(|value| std::str::from_utf8(value.as_bytes()).ok());
        let verified_signer = headers
            .get(axum::http::HeaderName::from_static(
                soracloud::VERIFIED_SIGNER_HEADER,
            ))
            .and_then(|value| value.to_str().ok());
        let verified_signers = headers
            .get(axum::http::HeaderName::from_static(
                soracloud::VERIFIED_SIGNERS_HEADER,
            ))
            .and_then(|value| value.to_str().ok());
        let client_identity_was_removed = [verified_account, verified_signer, verified_signers]
            .into_iter()
            .flatten()
            .all(|value| value != "attacker");
        axum::response::Response::builder()
            .status(
                if verified_account.is_some()
                    && verified_signer.is_some()
                    && verified_signers.is_some()
                    && client_identity_was_removed
                {
                    StatusCode::OK
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                },
            )
            .body(Body::from(body))
            .expect("response")
    }
    let _guard = crate::tests_runtime_handlers::app_auth_test_guard(
        crate::app_auth::CanonicalRequestAuthConfig::default(),
    );
    let key_pair = checked_torii_test_ed25519_keypair(
        0x23,
        "derive Soracloud signed mutation replay fixture key",
    );
    let account_id = AccountId::new(key_pair.public_key().clone());
    let app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(
        crate::tests_runtime_handlers::world_with_account(&account_id),
    );
    let router = Router::new()
        .route("/v1/soracloud/test", post(probe))
        .layer(axum::middleware::from_fn_with_state(
            app.clone(),
            enforce_soracloud_signed_mutation_request,
        ))
        .with_state(app);
    let unsigned = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("/v1/soracloud/test")
        .body(Body::from(br#"{"op":"unsigned"}"#.to_vec()))
        .expect("unsigned request");
    let unsigned_response = router.clone().oneshot(unsigned).await.expect("response");
    assert_eq!(unsigned_response.status(), StatusCode::FORBIDDEN);
    let unsigned_body = unsigned_response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    assert!(
        String::from_utf8_lossy(&unsigned_body).contains("signed account headers are required")
    );
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/soracloud/test".parse().expect("uri");
    let body = br#"{"op":"signed"}"#;
    let headers = crate::tests_runtime_handlers::signed_app_headers(
        &account_id,
        &key_pair,
        &method,
        &uri,
        body,
    );
    let mut signed_builder = axum::http::Request::builder()
        .method(method.clone())
        .uri(uri.to_string())
        .header(soracloud::VERIFIED_ACCOUNT_HEADER, "attacker")
        .header(soracloud::VERIFIED_SIGNER_HEADER, "attacker")
        .header(soracloud::VERIFIED_SIGNERS_HEADER, "attacker");
    for (name, value) in &headers {
        signed_builder = signed_builder.header(name, value);
    }
    let signed = signed_builder
        .body(Body::from(body.to_vec()))
        .expect("signed request");
    let signed_response = router.clone().oneshot(signed).await.expect("response");
    assert_eq!(signed_response.status(), StatusCode::OK);
    let mut replay_builder = axum::http::Request::builder()
        .method(method)
        .uri(uri.to_string());
    for (name, value) in &headers {
        replay_builder = replay_builder.header(name, value);
    }
    let replay = replay_builder
        .body(Body::from(body.to_vec()))
        .expect("replay request");
    let replay_response = router.oneshot(replay).await.expect("response");
    assert_eq!(replay_response.status(), StatusCode::FORBIDDEN);
    let replay_body = replay_response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    assert!(String::from_utf8_lossy(&replay_body).contains("nonce already used"));
}
#[tokio::test]
async fn soracloud_signed_mutation_middleware_applies_one_body_cap_before_auth() {
    use axum::{Router, routing::post};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    async fn probe() -> axum::response::Response {
        StatusCode::OK.into_response()
    }
    let account_id = checked_torii_test_account_id(
        0x40,
        "derive Soracloud signed mutation body-cap fixture key",
    );
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(
        crate::tests_runtime_handlers::world_with_account(&account_id),
    );
    let app_state = Arc::get_mut(&mut app).expect("test owns app state");
    app_state.soracloud_mutation_max_body_bytes = 8;
    let router = Router::new()
        .route("/v1/soracloud/test", post(probe))
        .route("/v1/soracloud/model/upload/register", post(probe))
        .layer(axum::middleware::from_fn_with_state(
            app.clone(),
            enforce_soracloud_signed_mutation_request,
        ))
        .with_state(app);
    let body = vec![b'x'; 32];
    let oversized = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("/v1/soracloud/test")
        .body(Body::from(body.clone()))
        .expect("request");
    let oversized_response = router.clone().oneshot(oversized).await.expect("response");
    assert_eq!(oversized_response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let oversized_body = oversized_response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    assert!(String::from_utf8_lossy(&oversized_body).contains("mutation request body exceeds"));
    let upload = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("/v1/soracloud/model/upload/register")
        .body(Body::from(body))
        .expect("request");
    let upload_response = router.oneshot(upload).await.expect("response");
    assert_eq!(upload_response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
#[tokio::test]
async fn soracloud_signed_mutation_middleware_rate_limits_account_across_caller_origins() {
    use axum::{Router, routing::post};
    use tower::ServiceExt as _;
    async fn probe() -> axum::response::Response {
        StatusCode::OK.into_response()
    }
    let _guard = crate::tests_runtime_handlers::app_auth_test_guard(
        crate::app_auth::CanonicalRequestAuthConfig::default(),
    );
    let key_pair = checked_torii_test_ed25519_keypair(
        0x41,
        "derive Soracloud signed mutation rate-limit fixture key",
    );
    let account_id = AccountId::new(key_pair.public_key().clone());
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(
        crate::tests_runtime_handlers::world_with_account(&account_id),
    );
    Arc::get_mut(&mut app)
        .expect("test owns app state")
        .soracloud_mutation_rate_limiter = limits::RateLimiter::new(Some(1), Some(1));
    let router = Router::new()
        .route("/v1/soracloud/hf/lease/join", post(probe))
        .layer(axum::middleware::from_fn_with_state(
            app.clone(),
            enforce_soracloud_signed_mutation_request,
        ))
        .with_state(app);
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/soracloud/hf/lease/join".parse().expect("uri");
    let body = br#"{"model":"test"}"#;
    let mut statuses = Vec::new();
    for origin in ["https://wallet-a.test", "https://wallet-b.test"] {
        let headers = crate::tests_runtime_handlers::signed_app_headers(
            &account_id,
            &key_pair,
            &method,
            &uri,
            body,
        );
        let mut builder = axum::http::Request::builder()
            .method(method.clone())
            .uri(uri.to_string())
            .header(axum::http::header::ORIGIN, origin);
        for (name, value) in &headers {
            builder = builder.header(name, value);
        }
        let response = router
            .clone()
            .oneshot(
                builder
                    .body(Body::from(body.to_vec()))
                    .expect("signed request"),
            )
            .await
            .expect("response");
        statuses.push(response.status());
    }
    assert_eq!(statuses, [StatusCode::OK, StatusCode::TOO_MANY_REQUESTS]);
}
#[test]
fn soracloud_signed_mutation_route_groups_cover_load_gate_paths() {
    let account_id = checked_torii_test_account_id(
        0x42,
        "derive Soracloud signed mutation route-group fixture key",
    );
    assert_eq!(
        super::soracloud_signed_mutation_route_group("/v1/soracloud/deploy"),
        "mutation"
    );
    assert_eq!(
        super::soracloud_signed_mutation_route_group("/v1/soracloud/model/session/start"),
        "model"
    );
    assert_eq!(
        super::soracloud_signed_mutation_route_group("/v1/soracloud/model/upload/register"),
        "upload"
    );
    assert_eq!(
        super::soracloud_signed_mutation_route_group("/v1/soracloud/hf/lease/join"),
        "hf"
    );
    let model_key = super::soracloud_signed_mutation_rate_key(&account_id, "model");
    let hf_key = super::soracloud_signed_mutation_rate_key(&account_id, "hf");
    assert_ne!(model_key, hf_key);
    assert!(!model_key.contains("origin:"));
    assert!(hf_key.contains("soracloud:hf:account:"));
}
#[tokio::test]
async fn soracloud_signed_mutation_middleware_enforces_global_inflight_limit() {
    use axum::{Router, routing::post};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    async fn probe() -> axum::response::Response {
        StatusCode::OK.into_response()
    }
    let _guard = crate::tests_runtime_handlers::app_auth_test_guard(
        crate::app_auth::CanonicalRequestAuthConfig::default(),
    );
    let key_pair = checked_torii_test_ed25519_keypair(
        0x43,
        "derive Soracloud signed mutation inflight fixture key",
    );
    let account_id = AccountId::new(key_pair.public_key().clone());
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(
        crate::tests_runtime_handlers::world_with_account(&account_id),
    );
    Arc::get_mut(&mut app)
        .expect("test owns app state")
        .soracloud_mutation_inflight = Arc::new(tokio::sync::Semaphore::new(0));
    let router = Router::new()
        .route("/v1/soracloud/model/session/start", post(probe))
        .layer(axum::middleware::from_fn_with_state(
            app.clone(),
            enforce_soracloud_signed_mutation_request,
        ))
        .with_state(app);
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/soracloud/model/session/start".parse().expect("uri");
    let body = br#"{"session":"test"}"#;
    let headers = crate::tests_runtime_handlers::signed_app_headers(
        &account_id,
        &key_pair,
        &method,
        &uri,
        body,
    );
    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(uri.to_string());
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }
    let response = router
        .oneshot(
            builder
                .body(Body::from(body.to_vec()))
                .expect("signed request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let response_body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    assert!(
        String::from_utf8_lossy(&response_body)
            .contains("Soracloud model request concurrency limit exceeded")
    );
}
#[tokio::test]
async fn soracloud_public_runtime_rate_and_inflight_limits_fail_closed() {
    use std::net::{IpAddr, Ipv4Addr};
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests();
    let app_state = Arc::get_mut(&mut app).expect("test owns app state");
    app_state.soracloud_public_rate_limiter = limits::RateLimiter::new(Some(1), Some(1));
    let method = axum::http::Method::GET;
    let uri: axum::http::Uri = "/healthz".parse().expect("uri");
    let remote_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::HOST,
        HeaderValue::from_static("portal.sora.test"),
    );
    let first = super::execute_soracloud_public_runtime_request(
        app.clone(),
        method.clone(),
        uri.clone(),
        headers.clone(),
        remote_ip,
        Bytes::new(),
    )
    .await;
    assert_eq!(first.status(), StatusCode::NOT_FOUND);
    let second = super::execute_soracloud_public_runtime_request(
        app.clone(),
        method.clone(),
        uri.clone(),
        headers.clone(),
        remote_ip,
        Bytes::new(),
    )
    .await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    let mut busy_app = crate::tests_runtime_handlers::mk_app_state_for_tests();
    let busy_state = Arc::get_mut(&mut busy_app).expect("test owns app state");
    busy_state.soracloud_public_rate_limiter = limits::RateLimiter::new(None, None);
    busy_state.soracloud_public_inflight = Arc::new(tokio::sync::Semaphore::new(0));
    let busy = super::execute_soracloud_public_runtime_request(
        busy_app,
        method,
        uri,
        headers,
        remote_ip,
        Bytes::new(),
    )
    .await;
    assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
}
#[tokio::test]
async fn zk_attachment_route_authenticates_before_decode_and_rejects_replay() {
    use axum::{Extension, Router, routing::post};
    use tower::ServiceExt as _;
    async fn probe(
        Extension(_verified): Extension<crate::app_auth::VerifiedCanonicalRequest>,
        crate::utils::extractors::JsonOnly(_body): crate::utils::extractors::JsonOnly<
            norito::json::Value,
        >,
    ) -> StatusCode {
        StatusCode::NO_CONTENT
    }
    let _guard = crate::tests_runtime_handlers::app_auth_test_guard(
        crate::app_auth::CanonicalRequestAuthConfig::default(),
    );
    let key_pair =
        checked_torii_test_ed25519_keypair(0x44, "derive ZK attachment tenant fixture key");
    let account_id = AccountId::new(key_pair.public_key().clone());
    let app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(
        crate::tests_runtime_handlers::world_with_account(&account_id),
    );
    let router = Router::new()
        .route("/v1/zk/attachments", post(probe))
        .layer(axum::middleware::from_fn_with_state(
            CanonicalAccountBodyAuthState {
                app: app.clone(),
                max_body_bytes: 1024,
                missing_auth_code: "canonical_authentication_required",
                missing_auth_message: "canonical account request authentication is required",
            },
            enforce_canonical_account_body_authentication,
        ));
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/zk/attachments".parse().expect("uri");
    let body = br#"{"attachment":"test"}"#;
    let headers = crate::tests_runtime_handlers::signed_app_headers(
        &account_id,
        &key_pair,
        &method,
        &uri,
        body,
    );
    let unsigned = router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method(method.clone())
                .uri(uri.clone())
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from("{"))
                .expect("unsigned malformed attachment request"),
        )
        .await
        .expect("unsigned attachment response");
    assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED);
    let unsigned_body = unsigned
        .into_body()
        .collect()
        .await
        .expect("unsigned response body")
        .to_bytes();
    let unsigned_error = norito::decode_from_bytes::<super::ErrorEnvelope>(&unsigned_body)
        .expect("unsigned response error envelope");
    assert_eq!(unsigned_error.code(), "canonical_authentication_required");
    let contract_router = Router::new()
        .route("/v1/gov/contracts/test", post(probe))
        .layer(axum::middleware::from_fn_with_state(
            CanonicalAccountBodyAuthState {
                app: app.clone(),
                max_body_bytes: 1024,
                missing_auth_code: "contract_code_auth_required",
                missing_auth_message:
                    "signed account headers are required to read governed contract metadata",
            },
            enforce_canonical_account_body_authentication,
        ));
    let contract_response = contract_router
        .oneshot(
            axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri("/v1/gov/contracts/test")
                .body(Body::from("{"))
                .expect("unsigned governed-contract request"),
        )
        .await
        .expect("unsigned governed-contract response");
    assert_eq!(contract_response.status(), StatusCode::UNAUTHORIZED);
    let contract_body = contract_response
        .into_body()
        .collect()
        .await
        .expect("governed-contract response body")
        .to_bytes();
    let contract_error = norito::decode_from_bytes::<super::ErrorEnvelope>(&contract_body)
        .expect("governed-contract error envelope");
    assert_eq!(contract_error.code(), "contract_code_auth_required");
    let signed_request = || {
        let mut request = axum::http::Request::builder()
            .method(method.clone())
            .uri(uri.clone())
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_vec()))
            .expect("signed attachment request");
        request.headers_mut().extend(headers.clone());
        request
    };
    let mut admitted_request = signed_request();
    let body_polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed_body_polls = Arc::clone(&body_polls);
    *admitted_request.body_mut() = Body::from_stream(futures::stream::poll_fn(
        move |_| -> std::task::Poll<Option<Result<Bytes, std::convert::Infallible>>> {
            observed_body_polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            panic!("admitted canonical body must not be polled a second time")
        },
    ));
    admitted_request
        .extensions_mut()
        .insert(AdmittedAppRoutedReadBody {
            bytes: Bytes::copy_from_slice(body),
            destination_bytes: body.len(),
        });
    let reservation = try_acquire_new_query_fanout_memory(&app).expect("test fanout reservation");
    let admission = AppRoutedReadHttpAdmission {
        reservation: reservation.clone(),
        decode_plan: torii_routed_read_request_preflight_plan(&app).expect("test decode plan"),
        canonical_auth: std::sync::Arc::new(std::sync::OnceLock::new()),
    };
    let accepted = APP_ROUTED_READ_HTTP_ADMISSION
        .scope(admission, router.clone().oneshot(admitted_request))
        .await
        .expect("admitted attachment response");
    assert_eq!(body_polls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(accepted.status(), StatusCode::NO_CONTENT);
    drop(accepted);
    drop(reservation);
    let replayed = router
        .oneshot(signed_request())
        .await
        .expect("replayed attachment response");
    assert_eq!(replayed.status(), StatusCode::FORBIDDEN);
    let replayed_body = replayed
        .into_body()
        .collect()
        .await
        .expect("replayed response body")
        .to_bytes();
    let replayed_error = norito::decode_from_bytes::<super::ErrorEnvelope>(&replayed_body)
        .expect("replayed response error envelope");
    assert_eq!(replayed_error.code(), "query_validation_failed");
}
#[tokio::test]
async fn optional_canonical_body_auth_rejects_partial_headers_before_decode() {
    use axum::{Extension, Router, routing::post};
    use tower::ServiceExt as _;

    async fn probe(
        Extension(visibility): Extension<ToriiAccountReadVisibility>,
        Extension(calls): Extension<Arc<std::sync::atomic::AtomicUsize>>,
        crate::utils::extractors::JsonOnly(_body): crate::utils::extractors::JsonOnly<
            norito::json::Value,
        >,
    ) -> StatusCode {
        assert!(!visibility.is_signed());
        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        StatusCode::NO_CONTENT
    }

    let app = crate::tests_runtime_handlers::mk_app_state_for_tests();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let router = Router::new()
        .route("/v1/accounts/query", post(probe))
        .layer(Extension(Arc::clone(&calls)))
        .layer(axum::middleware::from_fn_with_state(
            OptionalCanonicalAccountBodyAuthState {
                app,
                max_body_bytes: 1024,
            },
            enforce_optional_canonical_account_body_authentication,
        ));

    let anonymous = router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri("/v1/accounts/query")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .expect("anonymous query request"),
        )
        .await
        .expect("anonymous query response");
    assert_eq!(anonymous.status(), StatusCode::NO_CONTENT);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    let partial = router
        .oneshot(
            axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri("/v1/accounts/query")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .header(HEADER_ACCOUNT, iroha_test_samples::ALICE_ID.to_string())
                .body(Body::from("{"))
                .expect("partial-auth malformed query request"),
        )
        .await
        .expect("partial-auth query response");
    assert_eq!(partial.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}
#[tokio::test]
async fn oversized_retail_fee_quote_keeps_canonical_account_private_cache_headers() {
    use axum::{Router, routing::post};
    use tower::ServiceExt as _;

    async fn unreachable_handler() -> StatusCode {
        panic!("oversized retail fee quote must be rejected before handler dispatch")
    }

    let app = crate::tests_runtime_handlers::mk_app_state_for_tests();
    let max_body_bytes = 256 * 1024;
    let router = Router::new()
        .route("/v1/validation-fee/quote", post(unreachable_handler))
        .layer(axum::middleware::from_fn_with_state(
            CanonicalAccountBodyAuthState {
                app,
                max_body_bytes,
                missing_auth_code: "canonical_authentication_required",
                missing_auth_message: "canonical account request authentication is required",
            },
            enforce_canonical_account_body_authentication,
        ));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri("/v1/validation-fee/quote")
                .body(Body::from(vec![0_u8; max_body_bytes + 1]))
                .expect("oversized retail fee quote request"),
        )
        .await
        .expect("oversized retail fee quote response");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        response.headers().get(axum::http::header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("private, no-store"))
    );
    assert_eq!(
        response.headers().get(axum::http::header::VARY),
        Some(&HeaderValue::from_static(
            crate::content::CANONICAL_CONTENT_AUTH_VARY
        ))
    );
    assert_eq!(
        response.headers().get("x-iroha-reject-code"),
        Some(&HeaderValue::from_static("request_payload_too_large"))
    );
    assert_eq!(
        response.headers().get(axum::http::header::CONTENT_TYPE),
        Some(&HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE))
    );
    let body = response
        .into_body()
        .collect()
        .await
        .expect("oversized retail fee quote error body")
        .to_bytes();
    let envelope = norito::decode_from_bytes::<super::ErrorEnvelope>(&body)
        .expect("oversized retail fee quote ErrorEnvelope");
    assert_eq!(envelope.code(), "request_payload_too_large");
}
#[tokio::test]
async fn zk_attachment_admission_precedes_body_polling_and_covers_handler_work() {
    use axum::{Extension, Router, routing::post};
    use tower::ServiceExt as _;

    let _guard = crate::tests_runtime_handlers::app_auth_test_guard(
        crate::app_auth::CanonicalRequestAuthConfig::default(),
    );
    let key_pair = checked_torii_test_ed25519_keypair(0x45, "ZK attachment admission fixture key");
    let account_id = AccountId::new(key_pair.public_key().clone());
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(
        crate::tests_runtime_handlers::world_with_account(&account_id),
    );
    let app_state = Arc::get_mut(&mut app).expect("unique attachment admission app state");
    app_state.proof_body_inflight = Arc::new(tokio::sync::Semaphore::new(1));
    app_state.proof_limits.body_read_timeout = Duration::from_millis(30);

    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let probe_entered = Arc::clone(&entered);
    let probe_release = Arc::clone(&release);
    let router = Router::new()
        .route(
            "/v1/zk/attachments",
            post(
                move |Extension(_verified): Extension<
                    crate::app_auth::VerifiedCanonicalRequest,
                >,
                      Extension(_admission): Extension<ProofBodyAdmissionLease>,
                      _body: Bytes| {
                    let entered = Arc::clone(&probe_entered);
                    let release = Arc::clone(&probe_release);
                    async move {
                        entered.notify_one();
                        release.notified().await;
                        StatusCode::NO_CONTENT
                    }
                },
            ),
        )
        .layer(axum::middleware::from_fn_with_state(
            CanonicalAccountBodyAuthState {
                app: app.clone(),
                max_body_bytes: 1024,
                missing_auth_code: "canonical_authentication_required",
                missing_auth_message: "canonical account request authentication is required",
            },
            enforce_canonical_account_body_authentication,
        ))
        .layer(axum::middleware::from_fn_with_state(
            ProofBodyAdmissionState::new(app.clone(), 1024),
            proof_body_admission_middleware,
        ));
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/zk/attachments".parse().expect("attachment URI");
    let body = br#"{"attachment":"test"}"#;
    let signed_request = || {
        let headers = crate::tests_runtime_handlers::signed_app_headers(
            &account_id,
            &key_pair,
            &method,
            &uri,
            body,
        );
        let mut request = axum::http::Request::builder()
            .method(method.clone())
            .uri(uri.clone())
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_vec()))
            .expect("signed attachment request");
        request.headers_mut().extend(headers);
        request
    };

    let first_request = signed_request();
    let first_router = router.clone();
    let first = tokio::spawn(async move {
        first_router
            .oneshot(first_request)
            .await
            .expect("first attachment response")
    });
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("first attachment must reach handler work");
    assert_eq!(app.proof_body_inflight.available_permits(), 0);

    let body_that_must_not_be_polled = Body::from_stream(futures::stream::poll_fn(
        |_context| -> std::task::Poll<Option<Result<Bytes, std::convert::Infallible>>> {
            panic!("saturated attachment admission polled the request body")
        },
    ));
    let saturated = router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method(method.clone())
                .uri(uri.clone())
                .body(body_that_must_not_be_polled)
                .expect("saturated attachment request"),
        )
        .await
        .expect("saturated attachment response");
    assert_eq!(saturated.status(), StatusCode::TOO_MANY_REQUESTS);

    release.notify_one();
    assert_eq!(
        first.await.expect("first attachment task").status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(app.proof_body_inflight.available_permits(), 1);

    let oversized = router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method(method.clone())
                .uri(uri.clone())
                .body(Body::from(vec![0_u8; 1025]))
                .expect("oversized attachment request"),
        )
        .await
        .expect("oversized attachment response");
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let stalled =
        futures::stream::pending::<std::result::Result<Bytes, std::convert::Infallible>>();
    let timed_out = router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method(method.clone())
                .uri(uri.clone())
                .body(Body::from_stream(stalled))
                .expect("stalled attachment request"),
        )
        .await
        .expect("stalled attachment response");
    assert_eq!(timed_out.status(), StatusCode::REQUEST_TIMEOUT);

    release.notify_one();
    let accepted = router
        .oneshot(signed_request())
        .await
        .expect("accepted attachment response");
    assert_eq!(accepted.status(), StatusCode::NO_CONTENT);

    let worker_entered = Arc::new(tokio::sync::Notify::new());
    let worker_release = Arc::new(tokio::sync::Notify::new());
    let worker_finished = Arc::new(tokio::sync::Notify::new());
    let probe_worker_entered = Arc::clone(&worker_entered);
    let probe_worker_release = Arc::clone(&worker_release);
    let probe_worker_finished = Arc::clone(&worker_finished);
    let cancellation_router = Router::new()
        .route(
            "/v1/zk/attachments",
            post(
                move |Extension(_verified): Extension<
                    crate::app_auth::VerifiedCanonicalRequest,
                >,
                      Extension(admission): Extension<ProofBodyAdmissionLease>,
                      _body: Bytes| {
                    let entered = Arc::clone(&probe_worker_entered);
                    let release = Arc::clone(&probe_worker_release);
                    let finished = Arc::clone(&probe_worker_finished);
                    async move {
                        let runtime = tokio::runtime::Handle::current();
                        tokio::task::spawn_blocking(move || {
                            entered.notify_one();
                            runtime.block_on(release.notified());
                            drop(admission);
                            finished.notify_one();
                        })
                        .await
                        .expect("physical attachment worker");
                        StatusCode::NO_CONTENT
                    }
                },
            ),
        )
        .layer(axum::middleware::from_fn_with_state(
            CanonicalAccountBodyAuthState {
                app: app.clone(),
                max_body_bytes: 1024,
                missing_auth_code: "canonical_authentication_required",
                missing_auth_message: "canonical account request authentication is required",
            },
            enforce_canonical_account_body_authentication,
        ))
        .layer(axum::middleware::from_fn_with_state(
            ProofBodyAdmissionState::new(app.clone(), 1024),
            proof_body_admission_middleware,
        ));
    let cancellation_request = signed_request();
    let cancellation = tokio::spawn(async move {
        cancellation_router
            .oneshot(cancellation_request)
            .await
            .expect("cancelled attachment response")
    });
    tokio::time::timeout(Duration::from_secs(1), worker_entered.notified())
        .await
        .expect("physical attachment worker must start");
    assert_eq!(app.proof_body_inflight.available_permits(), 0);
    cancellation.abort();
    assert!(
        cancellation
            .await
            .expect_err("request must be cancelled")
            .is_cancelled()
    );
    assert_eq!(
        app.proof_body_inflight.available_permits(),
        0,
        "HTTP cancellation must not release physical admission while detached work runs"
    );
    worker_release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), worker_finished.notified())
        .await
        .expect("physical attachment worker must finish");
    assert_eq!(app.proof_body_inflight.available_permits(), 1);
}
#[tokio::test]
async fn cancelled_attachment_request_retains_admission_in_real_sanitizer_workers() {
    use axum::{Router, routing::post};
    use tower::ServiceExt as _;

    let _data_dir = crate::test_utils::TestDataDirGuard::new();
    let _auth_guard = crate::tests_runtime_handlers::app_auth_test_guard(
        crate::app_auth::CanonicalRequestAuthConfig::default(),
    );
    let key_pair = checked_torii_test_ed25519_keypair(0x46, "ZK sanitizer cancellation key");
    let account_id = AccountId::new(key_pair.public_key().clone());
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(
        crate::tests_runtime_handlers::world_with_account(&account_id),
    );
    let app_state = Arc::get_mut(&mut app).expect("unique sanitizer cancellation app state");
    app_state.proof_body_inflight = Arc::new(tokio::sync::Semaphore::new(1));
    app_state.proof_limits.body_read_timeout = Duration::from_secs(1);
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/zk/attachments".parse().expect("attachment URI");
    let body = br#"{"attachment":"cancel-real-sanitizer"}"#;
    let missing_sanitizer = _data_dir.path().join("missing-attachment-sanitizer");

    for (mode, executable) in [
        (
            iroha_config::parameters::actual::AttachmentSanitizerMode::InProcess,
            None,
        ),
        (
            iroha_config::parameters::actual::AttachmentSanitizerMode::Subprocess,
            Some(missing_sanitizer.clone()),
        ),
    ] {
        let _mode_guard = crate::zk_attachments::set_sanitizer_mode_for_test(mode, executable);
        let worker_entered = Arc::new(tokio::sync::Notify::new());
        let (worker_release, release_rx) = std::sync::mpsc::channel();
        let _worker_gate = crate::zk_attachments::install_sanitizer_worker_test_gate(
            Arc::clone(&worker_entered),
            release_rx,
        );
        let router = Router::new()
            .route("/v1/zk/attachments", post(handler_zk_attachments_create))
            .with_state(app.clone())
            .layer(axum::middleware::from_fn_with_state(
                CanonicalAccountBodyAuthState {
                    app: app.clone(),
                    max_body_bytes: 1024,
                    missing_auth_code: "canonical_authentication_required",
                    missing_auth_message: "canonical account request authentication is required",
                },
                enforce_canonical_account_body_authentication,
            ))
            .layer(axum::middleware::from_fn_with_state(
                ProofBodyAdmissionState::new(app.clone(), 1024),
                proof_body_admission_middleware,
            ));
        let headers = crate::tests_runtime_handlers::signed_app_headers(
            &account_id,
            &key_pair,
            &method,
            &uri,
            body,
        );
        let mut request = axum::http::Request::builder()
            .method(method.clone())
            .uri(uri.clone())
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_vec()))
            .expect("signed attachment request");
        request.headers_mut().extend(headers);
        request.extensions_mut().insert(axum::extract::ConnectInfo(
            "127.0.0.1:8080"
                .parse::<std::net::SocketAddr>()
                .expect("loopback socket"),
        ));

        let request_task = tokio::spawn(async move {
            router
                .oneshot(request)
                .await
                .expect("cancelled attachment response")
        });
        tokio::time::timeout(Duration::from_secs(1), worker_entered.notified())
            .await
            .expect("real sanitizer worker must start");
        assert_eq!(app.proof_body_inflight.available_permits(), 0);
        request_task.abort();
        assert!(
            request_task
                .await
                .expect_err("attachment request must be cancelled")
                .is_cancelled()
        );
        assert_eq!(
            app.proof_body_inflight.available_permits(),
            0,
            "{mode:?} worker must retain admission after HTTP cancellation"
        );
        worker_release
            .send(())
            .expect("release real sanitizer worker");
        tokio::time::timeout(Duration::from_secs(2), async {
            while app.proof_body_inflight.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("real sanitizer worker must eventually release admission");
        assert_eq!(app.proof_body_inflight.available_permits(), 1);
    }
}
#[tokio::test]
async fn cancelled_attachment_get_retains_admission_in_real_sanitizer_worker() {
    use std::io::Write as _;

    use axum::{Router, response::IntoResponse as _, routing::get};
    use flate2::{Compression, write::GzEncoder};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    let _data_dir = crate::test_utils::TestDataDirGuard::new();
    let _auth_guard = crate::tests_runtime_handlers::app_auth_test_guard(
        crate::app_auth::CanonicalRequestAuthConfig::default(),
    );
    let key_pair = checked_torii_test_ed25519_keypair(0x47, "ZK export cancellation key");
    let account_id = AccountId::new(key_pair.public_key().clone());
    let tenant = crate::zk_attachments::AttachmentTenant::from_account(&account_id);
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(
        crate::tests_runtime_handlers::world_with_account(&account_id),
    );
    let app_state = Arc::get_mut(&mut app).expect("unique export cancellation app state");
    app_state.proof_body_inflight = Arc::new(tokio::sync::Semaphore::new(1));
    app_state.proof_limits.body_read_timeout = Duration::from_secs(1);
    let _mode_guard = crate::zk_attachments::set_sanitizer_mode_for_test(
        iroha_config::parameters::actual::AttachmentSanitizerMode::InProcess,
        None,
    );

    let payload = br#"{"attachment":"compressed-export-cancellation"}"#;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(payload).expect("compress attachment");
    let compressed = encoder.finish().expect("finish attachment compression");
    let mut upload_headers = HeaderMap::new();
    upload_headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let upload = crate::zk_attachments::handle_post_attachment(
        tenant,
        upload_headers,
        Bytes::from(compressed),
    )
    .await
    .into_response();
    assert_eq!(upload.status(), StatusCode::CREATED);
    let upload_body = upload
        .into_body()
        .collect()
        .await
        .expect("attachment metadata response")
        .to_bytes();
    let metadata = norito::json::from_json::<crate::zk_attachments::AttachmentMeta>(
        std::str::from_utf8(&upload_body).expect("attachment metadata UTF-8"),
    )
    .expect("decode attachment metadata");
    assert!(
        metadata
            .provenance
            .as_ref()
            .is_some_and(|provenance| provenance.sanitizer.archive_depth > 0),
        "fixture must exercise export re-sanitization"
    );

    let worker_entered = Arc::new(tokio::sync::Notify::new());
    let (worker_release, release_rx) = std::sync::mpsc::channel();
    let _worker_gate = crate::zk_attachments::install_sanitizer_worker_test_gate(
        Arc::clone(&worker_entered),
        release_rx,
    );
    let router = Router::new()
        .route("/v1/zk/attachments/{id}", get(handler_zk_attachment_get))
        .with_state(app.clone())
        .layer(axum::middleware::from_fn_with_state(
            CanonicalAccountBodyAuthState {
                app: app.clone(),
                max_body_bytes: 0,
                missing_auth_code: "canonical_authentication_required",
                missing_auth_message: "canonical account request authentication is required",
            },
            enforce_canonical_account_body_authentication,
        ))
        .layer(axum::middleware::from_fn_with_state(
            ProofBodyAdmissionState::new(app.clone(), 0),
            proof_body_admission_middleware,
        ));
    let method = axum::http::Method::GET;
    let uri: axum::http::Uri = format!("/v1/zk/attachments/{}", metadata.id)
        .parse()
        .expect("attachment export URI");
    let headers = crate::tests_runtime_handlers::signed_app_headers(
        &account_id,
        &key_pair,
        &method,
        &uri,
        b"",
    );
    let mut request = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .expect("signed attachment export request");
    request.headers_mut().extend(headers);
    request.extensions_mut().insert(axum::extract::ConnectInfo(
        "127.0.0.1:8080"
            .parse::<std::net::SocketAddr>()
            .expect("loopback socket"),
    ));

    let request_task = tokio::spawn(async move {
        router
            .oneshot(request)
            .await
            .expect("cancelled attachment export response")
    });
    tokio::time::timeout(Duration::from_secs(1), worker_entered.notified())
        .await
        .expect("real export sanitizer worker must start");
    assert_eq!(app.proof_body_inflight.available_permits(), 0);
    request_task.abort();
    assert!(
        request_task
            .await
            .expect_err("attachment export request must be cancelled")
            .is_cancelled()
    );
    assert_eq!(
        app.proof_body_inflight.available_permits(),
        0,
        "export sanitizer must retain admission after HTTP cancellation"
    );
    worker_release
        .send(())
        .expect("release real export sanitizer worker");
    tokio::time::timeout(Duration::from_secs(2), async {
        while app.proof_body_inflight.available_permits() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("real export sanitizer worker must eventually release admission");
    assert_eq!(app.proof_body_inflight.available_permits(), 1);
}
#[tokio::test]
async fn rpc_capabilities_reflect_transport_config() {
    let cfg = actual::NoritoRpcTransport {
            enabled: true,
            require_mtls: true,
            stage: actual::NoritoRpcStage::Canary,
            allowed_clients: vec!["alpha".into(), "beta".into()],
            mtls_trusted_proxy_cidrs:
                iroha_config::parameters::defaults::torii::transport::norito_rpc::mtls_trusted_proxy_cidrs(),
        };
    let app = mk_app_state_for_tests_with_options(None, None, Some(cfg.clone()), None);
    let response = app.rpc_capabilities();
    assert!(response.norito_rpc.enabled);
    assert!(response.norito_rpc.require_mtls);
    assert_eq!(
        response.norito_rpc.stage,
        cfg.stage.label(),
        "stage label should match config"
    );
    assert_eq!(
        response.norito_rpc.canary_allowlist_size,
        cfg.allowed_clients.len()
    );
}
#[tokio::test]
async fn rpc_ping_reuses_capabilities_advert() {
    let cfg = actual::NoritoRpcTransport {
            enabled: false,
            require_mtls: false,
            stage: actual::NoritoRpcStage::Ga,
            allowed_clients: Vec::new(),
            mtls_trusted_proxy_cidrs:
                iroha_config::parameters::defaults::torii::transport::norito_rpc::mtls_trusted_proxy_cidrs(),
        };
    let app = mk_app_state_for_tests_with_options(None, None, Some(cfg.clone()), None);
    let response = app.rpc_ping();
    assert!(response.ok);
    assert!(response.unix_time_ms > 0);
    assert_eq!(
        response.norito_rpc.stage,
        cfg.stage.label(),
        "ping should advertise the same stage"
    );
    assert_eq!(response.norito_rpc.canary_allowlist_size, 0);
}
#[tokio::test]
async fn error_response_contains_details() {
    let mismatch = iroha_data_model::isi::error::Mismatch {
        expected: iroha_data_model::transaction::TransactionDomain::Network(
            crate::test_utils::signed_query_network_id(),
        ),
        actual: iroha_data_model::transaction::TransactionDomain::Genesis,
    };
    let expected_message = format!(
        "failed to accept transaction: Signed transaction domain does not match the admitted domain: {mismatch}"
    );
    let err = Error::AcceptTransaction(
        iroha_core::tx::AcceptTransactionFail::TransactionDomainMismatch(mismatch),
    );
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .map(|value| value.to_str().unwrap())
        .expect("content-type header present");
    assert_eq!(content_type, super::utils::NORITO_MIME_TYPE);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let payload = norito::decode_from_bytes::<super::ErrorEnvelope>(&body).unwrap();
    assert_eq!(payload.code(), "transaction_rejected");
    assert_eq!(payload.message(), expected_message);
}
#[test]
fn start_server_maps_to_internal_server_error() {
    assert_eq!(
        Error::StartServer.status_code(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}
#[test]
fn failed_exit_maps_to_internal_server_error() {
    assert_eq!(
        Error::FailedExit.status_code(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}
#[test]
fn contract_rejection_maps_to_unprocessable_entity() {
    let rejection = iroha_data_model::executor::ContractRejection {
        contract: "BoiFiLiquidity".into(),
        error_type: "FiLiquidityError".to_owned(),
        schema_hash: [0; 32],
        name: "BelowMinimum".to_owned(),
        code: 18,
        message: None,
    };
    assert_eq!(
        Error::Query(ValidationFail::ContractRejected(rejection)).status_code(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
}
#[test]
fn settlement_replay_maps_to_conflict_without_claiming_new_success() {
    use iroha_data_model::executor::settlement::{
        SettlementReplayDispositionV1, SettlementReplayV1,
    };
    let payer = iroha_data_model::account::AccountId::new(
        iroha_crypto::KeyPair::from_seed(vec![0x72; 32], iroha_crypto::Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    for disposition in [
        SettlementReplayDispositionV1::AlreadySettled,
        SettlementReplayDispositionV1::ConflictingIntent,
    ] {
        let replay = SettlementReplayV1 {
            settlement_id: iroha_data_model::isi::SettlementId::new(
                payer.clone(),
                "customer-payment-9".parse().unwrap(),
            ),
            disposition,
            committed_block_height: 42,
            committed_block_hash: iroha_crypto::HashOf::from_untyped_unchecked(
                iroha_crypto::Hash::new(b"original settlement"),
            ),
        };
        assert_eq!(
            Error::Query(ValidationFail::SettlementReplay(Box::new(replay))).status_code(),
            StatusCode::CONFLICT,
        );
    }
}

#[tokio::test]
async fn optional_canonical_body_auth_busy_source_preserves_capacity_and_nonce() {
    use axum::{Extension, Router, routing::post};
    use tower::ServiceExt as _;
    use std::sync::{atomic::{AtomicUsize, Ordering}, mpsc};

    async fn probe(
        Extension(visibility): Extension<ToriiAccountReadVisibility>,
        Extension(calls): Extension<Arc<AtomicUsize>>,
    ) -> StatusCode {
        assert!(visibility.is_signed(), "capacity must never select anonymous visibility");
        calls.fetch_add(1, Ordering::SeqCst);
        StatusCode::NO_CONTENT
    }
    let app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(
        crate::tests_runtime_handlers::world_with_account(&iroha_test_samples::ALICE_ID),
    );
    let method = Method::POST;
    let uri: Uri = "/v1/accounts/query".parse().expect("query URI");
    let body = b"{}";
    let headers = crate::tests_runtime_handlers::signed_app_headers(
        &iroha_test_samples::ALICE_ID,
        &iroha_test_samples::ALICE_KEYPAIR,
        &method, &uri, body,
    );
    let request = || {
        let mut request = axum::http::Request::builder()
            .method(method.clone()).uri(uri.clone())
            .body(Body::from(body.as_slice())).expect("canonical request");
        *request.headers_mut() = headers.clone();
        request
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let router = Router::new()
        .route("/v1/accounts/query", post(probe))
        .layer(Extension(Arc::clone(&calls)))
        .layer(axum::middleware::from_fn_with_state(
            OptionalCanonicalAccountBodyAuthState { app: app.clone(), max_body_bytes: 1024 },
            enforce_optional_canonical_account_body_authentication,
        ));
    let (held_tx, held_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
    let state = app.state.clone();
    let holder = std::thread::spawn(move || state.with_held_header_for_reader_test(|_| {
        held_tx.send(()).expect("notify original writer acquired");
        let _ = release_rx.recv();
    }));
    held_rx.recv_timeout(std::time::Duration::from_secs(5)).expect("original header writer");
    let refused = router.clone().oneshot(request()).await.expect("capacity response");
    drop(release_tx);
    holder.join().expect("release original writer");
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS,
        "real source contention cannot become invalid credentials");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let accepted = router.clone().oneshot(request()).await.expect("same request after release");
    assert_eq!(accepted.status(), StatusCode::NO_CONTENT);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let replayed = router.oneshot(request()).await.expect("replay response");
    assert_eq!(replayed.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
