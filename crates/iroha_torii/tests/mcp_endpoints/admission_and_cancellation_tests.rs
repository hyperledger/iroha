// Admission debit, transport rejection, and authenticated cancellation regressions.
// Included in the endpoint test crate to share the real router lifecycle helpers.

fn authenticated_rate_limited_mcp_config(
    tokens: impl IntoIterator<Item = String>,
    burst: u32,
) -> iroha_config::parameters::actual::Root {
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    cfg.torii.mcp.profile = iroha_config::parameters::actual::ToriiMcpProfile::Writer;
    cfg.torii.mcp.rate_per_minute = Some(NonZeroU32::new(1).expect("nonzero rate"));
    cfg.torii.mcp.burst = Some(NonZeroU32::new(burst).expect("nonzero burst"));
    cfg.torii.require_api_token = true;
    cfg.torii.api_tokens = tokens.into_iter().collect::<Vec<_>>().into();
    cfg
}
fn authenticated_mcp_request(payload: &Value, token: &str) -> Request<Body> {
    current_mcp_http_request(payload.clone(), &[("x-api-token", token)])
}
fn authenticated_mcp_request_bytes(body: impl Into<Body>, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION)
        .header("x-api-token", token)
        .body(body.into())
        .expect("valid authenticated MCP request")
}
fn cancellation_notification(request_id: Value, nonce: &str) -> Value {
    norito::json!({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {
            "requestId": (request_id),
            "reason": "integration test",
            "_meta": { "iroha/cancellationNonce": (nonce) }
        }
    })
}
async fn assert_mcp_rate_limited_response(response: axum::response::Response) {
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-mcp-error")
            .and_then(|value| value.to_str().ok()),
        Some("rate_limited")
    );
    assert_eq!(
        response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("private, no-store")
    );
    let body = read_json_body(response).await;
    assert!(body.get("id").is_none());
    assert_eq!(
        body.pointer("/error/code").and_then(Value::as_i64),
        Some(1_029)
    );
    assert_eq!(
        body.pointer("/error/data/error").and_then(Value::as_str),
        Some("rate_limited")
    );
}
async fn exhaust_authenticated_ordinary_bucket(app: &axum::Router, token: &str) {
    let response = call_app(
        app,
        authenticated_mcp_request(
            &norito::json!({
                "jsonrpc": "2.0",
                "id": "consume-ordinary",
                "method": "server/discover"
            }),
            token,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}
async fn assert_invalid_fallback_consumes_control(
    label: &str,
    token: &str,
    invalid_request: Request<Body>,
) {
    let app = build_router(authenticated_rate_limited_mcp_config([token.to_owned()], 1));
    exhaust_authenticated_ordinary_bucket(&app, token).await;
    let invalid_response = call_app(&app.clone(), invalid_request).await;
    assert_eq!(
        invalid_response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "{label} must retain the ordinary rate-limit response"
    );
    assert_mcp_rate_limited_response(invalid_response).await;
    let nonce = B64.encode([0x7d; 32]);
    let denied_after_invalid = call_app(
        &app,
        authenticated_mcp_request(
            &cancellation_notification(Value::String("after-invalid".to_owned()), &nonce),
            token,
        ),
    )
    .await;
    assert_eq!(
        denied_after_invalid.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "{label} must spend its cancellation-control permit"
    );
    assert_mcp_rate_limited_response(denied_after_invalid).await;
    app.shutdown().await;
}
async fn assert_initial_ordinary_debit_is_not_refunded(
    cfg: iroha_config::parameters::actual::Root,
    token: &str,
    rejected_request: Request<Body>,
    expected_status: StatusCode,
) {
    let app = build_router(cfg);
    let rejected = call_app(&app, rejected_request).await;
    assert_eq!(rejected.status(), expected_status);

    let first_nonce = B64.encode([0x6e; 32]);
    let accepted_control = call_app(
        &app.clone(),
        authenticated_mcp_request(
            &cancellation_notification(
                Value::String("after-rejected-request".to_owned()),
                &first_nonce,
            ),
            token,
        ),
    )
    .await;
    assert_eq!(accepted_control.status(), StatusCode::ACCEPTED);
    assert_eq!(
        accepted_control
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("private, no-store")
    );
    assert!(read_body_bytes(accepted_control).await.is_empty());

    let second_nonce = B64.encode([0x6f; 32]);
    let denied_after_control = call_app(
        &app,
        authenticated_mcp_request(
            &cancellation_notification(
                Value::String("after-control-spent".to_owned()),
                &second_nonce,
            ),
            token,
        ),
    )
    .await;
    assert_eq!(
        denied_after_control.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a refunded ordinary permit would admit this second cancellation"
    );
    assert_mcp_rate_limited_response(denied_after_control).await;
    app.shutdown().await;
}

#[tokio::test]
async fn mcp_jsonrpc_authenticated_cancellation_stops_exact_live_call() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let app = build_router(authenticated_rate_limited_mcp_config(
        ["cancellation-client-00000000000000000000000000000000".to_owned()],
        1,
    ));
    let cancellation_nonce = B64.encode([0x42; 32]);
    let call_request = authenticated_mcp_request(
        &norito::json!({
            "jsonrpc": "2.0",
            "id": "cancel-me",
            "method": "tools/call",
            "params": {
                "name": "iroha.transactions.wait",
                "arguments": {
                    "query": { "hash": ("ab".repeat(32)) },
                    "timeout_ms": 10_000,
                    "poll_interval_ms": 50
                },
                "_meta": { "iroha/cancellationNonce": (cancellation_nonce.clone()) }
            }
        }),
        "cancellation-client-00000000000000000000000000000000",
    );
    let call_app_clone = app.clone();
    let live_call = tokio::spawn(async move { call_app(&call_app_clone, call_request).await });
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !live_call.is_finished(),
        "long poll must be live before its single cancellation attempt"
    );

    let cancellation_app = app.clone();
    let cancellation = call_app(
        &cancellation_app,
        authenticated_mcp_request(
            &cancellation_notification(Value::String("cancel-me".to_owned()), &cancellation_nonce),
            "cancellation-client-00000000000000000000000000000000",
        ),
    )
    .await;
    assert_eq!(cancellation.status(), StatusCode::ACCEPTED);
    assert_eq!(
        cancellation
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("private, no-store")
    );
    assert!(read_body_bytes(cancellation).await.is_empty());

    let cancelled = tokio::time::timeout(Duration::from_secs(2), live_call)
        .await
        .expect("single cancellation reaches the registered request")
        .expect("live request task joins");
    assert_eq!(cancelled.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        cancelled
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("private, no-store")
    );
    assert!(read_body_bytes(cancelled).await.is_empty());

    let replacement_nonce = B64.encode([0x43; 32]);
    assert_mcp_rate_limited_response(
        call_app(
            &app,
            authenticated_mcp_request(
                &cancellation_notification(
                    Value::String("fresh-request".to_owned()),
                    &replacement_nonce,
                ),
                "cancellation-client-00000000000000000000000000000000",
            ),
        )
        .await,
    )
    .await;
    app.shutdown().await;
}
#[tokio::test]
async fn mcp_rate_limited_cancellation_fallback_rejects_inexact_bodies() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let nonce = B64.encode([0x51; 32]);
    let padded_nonce = format!("{nonce}=");
    let short_nonce = B64.encode([0x51; 31]);
    let invalid_payloads = [
        (
            "top-level-id",
            norito::json!({
                "jsonrpc": "2.0",
                "id": "not-a-notification",
                "method": "notifications/cancelled",
                "params": {
                    "requestId": "target",
                    "_meta": { "iroha/cancellationNonce": (nonce.clone()) }
                }
            }),
        ),
        (
            "wrong-method",
            norito::json!({
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": {
                    "requestId": "target",
                    "_meta": { "iroha/cancellationNonce": (nonce.clone()) }
                }
            }),
        ),
        (
            "extra-param",
            norito::json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {
                    "requestId": "target",
                    "unexpected": true,
                    "_meta": { "iroha/cancellationNonce": (nonce.clone()) }
                }
            }),
        ),
        (
            "non-string-reason",
            norito::json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {
                    "requestId": "target",
                    "reason": 7,
                    "_meta": { "iroha/cancellationNonce": (nonce.clone()) }
                }
            }),
        ),
        (
            "fractional-id",
            norito::json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {
                    "requestId": 1.5,
                    "_meta": { "iroha/cancellationNonce": (nonce.clone()) }
                }
            }),
        ),
        (
            "extra-meta-field",
            norito::json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {
                    "requestId": "target",
                    "_meta": {
                        "iroha/cancellationNonce": (nonce.clone()),
                        "unexpected": true
                    }
                }
            }),
        ),
        (
            "padded-nonce",
            cancellation_notification(Value::String("target".to_owned()), &padded_nonce),
        ),
        (
            "wrong-length-nonce",
            cancellation_notification(Value::String("target".to_owned()), &short_nonce),
        ),
    ];
    for (index, (label, payload)) in invalid_payloads.into_iter().enumerate() {
        let token = format!("inexact-body-{index}-00000000000000000000000000000000");
        assert_invalid_fallback_consumes_control(
            label,
            &token,
            authenticated_mcp_request(&payload, &token),
        )
        .await;
    }

    let malformed_token = "inexact-body-malformed-json-00000000000000000000000000000000";
    assert_invalid_fallback_consumes_control(
        "malformed-json",
        malformed_token,
        authenticated_mcp_request_bytes("{".as_bytes().to_vec(), malformed_token),
    )
    .await;
}
#[tokio::test]
async fn mcp_rate_limited_cancellation_fallback_rejects_inexact_transport() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let nonce = B64.encode([0x52; 32]);
    for (case, label) in [
        "missing-content-type",
        "wrong-content-type",
        "missing-protocol",
        "duplicate-protocol",
        "unsupported-protocol",
    ]
    .into_iter()
    .enumerate()
    {
        let token = format!("inexact-transport-{label}-00000000000000000000000000000000");
        let mut request = authenticated_mcp_request(
            &cancellation_notification(Value::String("target".to_owned()), &nonce),
            &token,
        );
        match case {
            0 => {
                request.headers_mut().remove(header::CONTENT_TYPE);
            }
            1 => {
                request
                    .headers_mut()
                    .insert(header::CONTENT_TYPE, "text/plain".parse().expect("header"));
            }
            2 => {
                request.headers_mut().remove("mcp-protocol-version");
            }
            3 => {
                request.headers_mut().append(
                    "mcp-protocol-version",
                    "2025-06-18".parse().expect("header"),
                );
            }
            4 => {
                request.headers_mut().insert(
                    "mcp-protocol-version",
                    "2024-11-05".parse().expect("header"),
                );
            }
            _ => unreachable!(),
        }
        assert_invalid_fallback_consumes_control(label, &token, request).await;
    }
}
#[tokio::test]
async fn mcp_authenticated_rejections_do_not_refund_the_initial_ordinary_debit() {
    let _data_dir = test_utils::TestDataDirGuard::new();

    let malformed_token = "malformed-spends-initial-00000000000000000000000000000000";
    assert_initial_ordinary_debit_is_not_refunded(
        authenticated_rate_limited_mcp_config([malformed_token.to_owned()], 1),
        malformed_token,
        authenticated_mcp_request_bytes("{".as_bytes().to_vec(), malformed_token),
        StatusCode::BAD_REQUEST,
    )
    .await;

    let oversized_token = "oversized-spends-initial-00000000000000000000000000000000";
    let mut oversized_cfg = authenticated_rate_limited_mcp_config([oversized_token.to_owned()], 1);
    oversized_cfg.torii.mcp.max_request_bytes = 512;
    assert_initial_ordinary_debit_is_not_refunded(
        oversized_cfg,
        oversized_token,
        authenticated_mcp_request(
            &norito::json!({
                "jsonrpc": "2.0",
                "id": ("oversized".repeat(128)),
                "method": "server/discover"
            }),
            oversized_token,
        ),
        StatusCode::PAYLOAD_TOO_LARGE,
    )
    .await;

    let rejected_token = "protocol-rejection-spends-initial-00000000000000000000000000000000";
    let mut rejected_request = authenticated_mcp_request(
        &norito::json!({
            "jsonrpc": "2.0",
            "id": "unsupported-protocol",
            "method": "server/discover"
        }),
        rejected_token,
    );
    rejected_request.headers_mut().insert(
        "mcp-protocol-version",
        "2024-11-05".parse().expect("header"),
    );
    assert_initial_ordinary_debit_is_not_refunded(
        authenticated_rate_limited_mcp_config([rejected_token.to_owned()], 1),
        rejected_token,
        rejected_request,
        StatusCode::BAD_REQUEST,
    )
    .await;
}
#[tokio::test]
async fn mcp_cancellation_control_buckets_are_isolated_by_authenticated_token() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let app = build_router(authenticated_rate_limited_mcp_config(
        [
            "principal-a-00000000000000000000000000000000".to_owned(),
            "principal-b-00000000000000000000000000000000".to_owned(),
        ],
        1,
    ));
    for token in [
        "principal-a-00000000000000000000000000000000",
        "principal-b-00000000000000000000000000000000",
    ] {
        exhaust_authenticated_ordinary_bucket(&app, token).await;
    }
    for (token, nonce_byte) in [
        ("principal-a-00000000000000000000000000000000", 0x61),
        ("principal-b-00000000000000000000000000000000", 0x62),
    ] {
        let nonce = B64.encode([nonce_byte; 32]);
        let response = call_app(
            &app.clone(),
            authenticated_mcp_request(
                &cancellation_notification(Value::String(format!("{token}-first")), &nonce),
                token,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert!(read_body_bytes(response).await.is_empty());
    }
    for (token, nonce_byte) in [
        ("principal-a-00000000000000000000000000000000", 0x63),
        ("principal-b-00000000000000000000000000000000", 0x64),
    ] {
        let nonce = B64.encode([nonce_byte; 32]);
        assert_mcp_rate_limited_response(
            call_app(
                &app,
                authenticated_mcp_request(
                    &cancellation_notification(Value::String(format!("{token}-second")), &nonce),
                    token,
                ),
            )
            .await,
        )
        .await;
    }
    app.shutdown().await;
}
#[tokio::test]
async fn mcp_cancellation_fallback_requires_one_exact_configured_token() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let token = "configured-cancellation-principal";
    let app = build_router(authenticated_rate_limited_mcp_config([token.to_owned()], 1));
    let nonce = B64.encode([0x66; 32]);
    let payload = cancellation_notification(Value::String("auth-gated".to_owned()), &nonce);

    let mut missing = authenticated_mcp_request(&payload, token);
    missing.headers_mut().remove("x-api-token");
    let wrong = authenticated_mcp_request(&payload, "not-configured");
    let mut duplicate = authenticated_mcp_request(&payload, token);
    duplicate
        .headers_mut()
        .append("x-api-token", token.parse().expect("header"));
    for (label, request) in [
        ("missing", missing),
        ("unknown", wrong),
        ("duplicate", duplicate),
    ] {
        let response = call_app(&app.clone(), request).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{label}");
        assert!(
            response.headers().contains_key(header::WWW_AUTHENTICATE),
            "{label} authentication failure must advertise the token challenge"
        );
    }

    let ordinary = call_app(
        &app.clone(),
        authenticated_mcp_request(
            &norito::json!({
                "jsonrpc": "2.0",
                "id": "valid-after-invalid-auth",
                "method": "server/discover"
            }),
            token,
        ),
    )
    .await;
    assert_eq!(ordinary.status(), StatusCode::OK);

    let control = call_app(&app, authenticated_mcp_request(&payload, token)).await;
    assert_eq!(control.status(), StatusCode::ACCEPTED);
    assert!(read_body_bytes(control).await.is_empty());
    app.shutdown().await;
}
#[tokio::test]
async fn mcp_anonymous_rate_limit_has_no_cancellation_control_fallback() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    cfg.torii.mcp.rate_per_minute = Some(NonZeroU32::new(1).expect("nonzero rate"));
    cfg.torii.mcp.burst = Some(NonZeroU32::new(1).expect("nonzero burst"));
    let app = build_router(cfg);
    let (status, _) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": "consume-anonymous",
            "method": "server/discover"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let nonce = B64.encode([0x65; 32]);
    assert_mcp_rate_limited_response(
        call_app(
            &app.clone(),
            authenticated_mcp_request(
                &cancellation_notification(Value::String("anonymous".to_owned()), &nonce),
                "caller-supplied-but-disabled",
            ),
        )
        .await,
    )
    .await;
    app.shutdown().await;
}

#[tokio::test]
async fn mcp_jsonrpc_enforces_rate_limit() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    cfg.torii.mcp.rate_per_minute = Some(NonZeroU32::new(1).expect("nonzero rate"));
    cfg.torii.mcp.burst = Some(NonZeroU32::new(1).expect("nonzero burst"));
    let app = build_router(cfg);
    let request = modern_request("rate-limit", "server/discover", norito::json!({}));
    let (status, _) = post_mcp(&app, request.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = post_mcp(&app, request).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        body.get("error")
            .and_then(|value| value.get("code"))
            .and_then(Value::as_i64),
        Some(1_029)
    );
    app.shutdown().await;
}
#[tokio::test]
async fn mcp_jsonrpc_charges_each_inner_tool_batch_dispatch() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let app = build_router(authenticated_rate_limited_mcp_config(
        ["batch-principal".to_owned()],
        2,
    ));
    let (status, body) = post_mcp_with_headers(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": "two-inner-dispatches",
            "method": "tools/call_batch",
            "params": {
                "calls": [
                    { "name": "iroha.health", "arguments": {} },
                    { "name": "iroha.health", "arguments": {} }
                ]
            }
        }),
        &[("x-api-token", "batch-principal")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("result").is_some(),
        "batch should consume its two-token budget"
    );

    let (status, body) = post_mcp_with_headers(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": "after-inner-dispatches",
            "method": "server/discover"
        }),
        &[("x-api-token", "batch-principal")],
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        body.get("error")
            .and_then(|value| value.get("code"))
            .and_then(Value::as_i64),
        Some(1_029)
    );
    app.shutdown().await;
}
#[tokio::test]
async fn mcp_batch_additional_debit_denial_preserves_cancellation_control_bucket() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let token = "batch-additional-denial-00000000000000000000000000000000";
    let app = build_router(authenticated_rate_limited_mcp_config([token.to_owned()], 1));
    let denied_batch = call_app(
        &app.clone(),
        authenticated_mcp_request(
            &norito::json!({
                "jsonrpc": "2.0",
                "id": "two-inner-dispatches-with-one-permit",
                "method": "tools/call_batch",
                "params": {
                    "calls": [
                        { "name": "iroha.health", "arguments": {} },
                        { "name": "iroha.health", "arguments": {} }
                    ]
                }
            }),
            token,
        ),
    )
    .await;
    assert_mcp_rate_limited_response(denied_batch).await;

    let first_nonce = B64.encode([0x71; 32]);
    let cancellation = call_app(
        &app.clone(),
        authenticated_mcp_request(
            &cancellation_notification(
                Value::String("control-survives-additional-denial".to_owned()),
                &first_nonce,
            ),
            token,
        ),
    )
    .await;
    assert_eq!(cancellation.status(), StatusCode::ACCEPTED);
    assert!(read_body_bytes(cancellation).await.is_empty());

    let second_nonce = B64.encode([0x72; 32]);
    assert_mcp_rate_limited_response(
        call_app(
            &app,
            authenticated_mcp_request(
                &cancellation_notification(
                    Value::String("control-now-spent".to_owned()),
                    &second_nonce,
                ),
                token,
            ),
        )
        .await,
    )
    .await;
    app.shutdown().await;
}
#[tokio::test]
async fn mcp_one_per_minute_rate_does_not_round_up_to_one_per_second() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    cfg.torii.mcp.rate_per_minute = Some(NonZeroU32::new(1).expect("nonzero rate"));
    cfg.torii.mcp.burst = Some(NonZeroU32::new(1).expect("nonzero burst"));
    let app = build_router(cfg);
    let request = norito::json!({
        "jsonrpc": "2.0",
        "id": "one-per-minute",
        "method": "server/discover"
    });
    let (status, _) = post_mcp(&app, request.clone()).await;
    assert_eq!(status, StatusCode::OK);

    tokio::time::sleep(Duration::from_millis(1_100)).await;

    let (status, body) = post_mcp(&app, request).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        body.get("error")
            .and_then(|value| value.get("code"))
            .and_then(Value::as_i64),
        Some(1_029)
    );
    app.shutdown().await;
}
#[tokio::test]
async fn mcp_jsonrpc_rejects_oversized_payload() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    cfg.torii.mcp.max_request_bytes = 32;
    let app = build_router(cfg);
    let request_body =
        norito::json::to_vec(&initialize_request(1)).expect("serialize initialize request");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(request_body))
                .expect("valid request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = read_json_body(response).await;
    assert_eq!(
        body.get("error")
            .and_then(|value| value.get("code"))
            .and_then(Value::as_i64),
        Some(-32600)
    );
    assert_eq!(
        body.get("error")
            .and_then(|value| value.get("data"))
            .and_then(|value| value.get("max_request_bytes"))
            .and_then(Value::as_u64),
        Some(32)
    );
    assert_eq!(
        body.get("error")
            .and_then(|value| value.get("data"))
            .and_then(|value| value.get("error_code"))
            .and_then(Value::as_str),
        Some("request_payload_too_large")
    );
    app.shutdown().await;
}
