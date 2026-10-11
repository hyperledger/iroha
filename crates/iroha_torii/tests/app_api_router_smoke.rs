#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Smoke test for App API routes wiring.
#![allow(clippy::too_many_lines)]
//!
//! Builds a minimal Torii instance and checks that a couple of App API
//! endpoints are reachable via the consolidated helper-built router.
use axum::http::{Request, StatusCode, Uri, header::CONTENT_TYPE};
use std::sync::Arc;
// use iroha_config::base::WithOrigin; // unused in this smoke test
use iroha_core::{
    kiso::KisoHandle, kura::Kura, prelude::World, query::store::LiveQueryStore, state::State,
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::peer::PeerId;
use tower::ServiceExt as _; // for Router::oneshot
// use iroha_primitives::addr::socket_addr; // unused in this smoke test
#[path = "fixtures.rs"]
mod fixtures;
// Minimal root config for starting Kiso and wiring Torii
fn mk_minimal_root_cfg() -> iroha_config::parameters::actual::Root {
    iroha_torii::test_utils::mk_minimal_root_cfg()
}
async fn assert_route_is_not_auth_denied(
    app: axum::Router,
    request: Request<axum::body::Body>,
) -> StatusCode {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    assert!(
        !matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
        "route unexpectedly denied access with {status}"
    );
    status
}
#[tokio::test]
async fn app_api_router_smoke() {
    // Start Kiso and minimal components for Torii
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let mut cfg = mk_minimal_root_cfg();
    cfg.torii.webhooks_enabled = true;
    cfg.torii.operator_signatures.enabled = true;
    cfg.torii.operator_signatures.allow_node_key = true;
    let (kiso, _child) = KisoHandle::start(cfg.clone());
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let local_peer_id = PeerId::new(cfg.common.key_pair.public_key().clone());
    let mut world = World::default();
    fixtures::seed_peer(&mut world, local_peer_id.clone());
    let state = Arc::new(State::new_for_testing(world, kura.clone(), query));
    let queue_cfg = iroha_config::parameters::actual::Queue::default();
    let events_sender: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue = Arc::new(iroha_core::queue::Queue::from_config(
        queue_cfg,
        events_sender,
    ));
    let (peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let _ = peers_tx;
    let da_receipt_signer = cfg.common.key_pair.clone();
    let torii = iroha_torii::Torii::new(
        build_identity_test_fixture::build_identity(),
        ChainId::from("test-chain"),
        iroha_torii::test_utils::signed_query_network_id(),
        kiso,
        cfg.torii.clone(),
        queue,
        tokio::sync::broadcast::channel(1).0,
        LiveQueryStore::start_test(),
        kura,
        state,
        da_receipt_signer,
        iroha_torii::OnlinePeersProvider::new(peers_rx),
    )
    .expect("valid Torii app API fixture");
    let runtime = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let app = runtime.router();
    for path in ["/v1/soracloud/status", "/v1/soracloud/apps/status"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(axum::body::Body::empty())
                    .expect("unsigned Soracloud GET"),
            )
            .await
            .expect("Soracloud auth response");
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{path} must reject missing canonical account authentication"
        );
    }
    for retired_path in [
        "/v1/soracloud/model/upload/encryption-recipient",
        "/v1/soracloud/model/upload/private/receipts",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(retired_path)
                    .body(axum::body::Body::empty())
                    .expect("retired uploaded private-model GET"),
            )
            .await
            .expect("router response");
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "retired uploaded private-model route `{retired_path}` must remain unmatched"
        );
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/soracloud/model/upload/private/execute")
                .header(CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    r#"{"model":{"weights_i8":[127]},"plaintext_input_i32":[2147483647]"#,
                ))
                .expect("retired uploaded private-model execute request"),
        )
        .await
        .expect("router response");
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "retired uploaded private-model execute route must reject before body deserialization"
    );
    // The v1 alias VOPRF-shaped hash helper was retired before release because it was
    // neither keyed nor verifiable. Every legacy request shape must remain unroutable,
    // including malformed input, a replay, cross-domain material, and wrong-key/proof fields.
    let retired_alias_voprf_attempts = [
        ("malformed", "{"),
        ("replay-first", r#"{"blinded_element_hex":"deadbeef"}"#),
        ("replay-second", r#"{"blinded_element_hex":"deadbeef"}"#),
        (
            "cross-domain",
            r#"{"blinded_element_hex":"deadbeef","domain":"other-ledger"}"#,
        ),
        (
            "wrong-key",
            r#"{"blinded_element_hex":"deadbeef","key_id":"wrong","proof":"00"}"#,
        ),
    ];
    for (case, body) in retired_alias_voprf_attempts {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/aliases/voprf/evaluate")
                    .header(CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(body))
                    .expect("legacy alias VOPRF request"),
            )
            .await
            .expect("router response");
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "retired alias VOPRF route accepted {case} request"
        );
    }
    // 1) App API: GET /v1/accounts/{account_id}/assets — use a bogus id to avoid
    // state setup; we only care that the route exists and responds deterministically.
    assert_route_is_not_auth_denied(
        app.clone(),
        Request::builder()
            .uri(Uri::from_static(
                "/v1/accounts/bogus_account_id/assets?offset=0",
            ))
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    // 2) App API: GET /v1/events/sse — endpoint exists; allow OK or 429 depending on rate limits
    let resp_sse = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(Uri::from_static("/v1/events/sse"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(!matches!(
        resp_sse.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ));
    if resp_sse.status() == StatusCode::OK {
        let ct = resp_sse
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        assert!(ct.contains("text/event-stream"));
    }
    // 2b) App API: GET /v1/explorer/blocks/stream — endpoint exists; allow OK or 429.
    let resp_blocks_sse = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(Uri::from_static("/v1/explorer/blocks/stream"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(!matches!(
        resp_blocks_sse.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ));
    if resp_blocks_sse.status() == StatusCode::OK {
        let ct = resp_blocks_sse
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        assert!(ct.contains("text/event-stream"));
    }
    // 2c) App API: GET /v1/gov/stream — endpoint exists; allow OK/429.
    let resp_gov_sse = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(Uri::from_static("/v1/gov/stream"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(!matches!(
        resp_gov_sse.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ));
    if resp_gov_sse.status() == StatusCode::OK {
        let ct = resp_gov_sse
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        assert!(ct.contains("text/event-stream"));
    }
    // 2d) App API: GET /v1/telemetry/live — endpoint exists; allow OK/429/403.
    let resp_telemetry_live = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(Uri::from_static("/v1/telemetry/live"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    #[cfg(feature = "telemetry")]
    {
        assert!(matches!(
            resp_telemetry_live.status(),
            StatusCode::OK | StatusCode::TOO_MANY_REQUESTS | StatusCode::FORBIDDEN
        ));
        if resp_telemetry_live.status() == StatusCode::OK {
            let ct = resp_telemetry_live
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            assert!(ct.contains("text/event-stream"));
        }
    }
    #[cfg(not(feature = "telemetry"))]
    {
        assert!(!matches!(
            resp_telemetry_live.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ));
    }
    // 2e) App API: GET /v1/telemetry/propagation — endpoint exists; allow OK/429/403.
    let resp_telemetry_propagation = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(Uri::from_static("/v1/telemetry/propagation"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    #[cfg(feature = "telemetry")]
    {
        assert!(matches!(
            resp_telemetry_propagation.status(),
            StatusCode::OK | StatusCode::TOO_MANY_REQUESTS | StatusCode::FORBIDDEN
        ));
    }
    #[cfg(not(feature = "telemetry"))]
    {
        assert!(!matches!(
            resp_telemetry_propagation.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ));
    }
    // 3) App API: GET /v1/webhooks — operator auth runs before route dispatch.
    let unsigned_webhooks_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(Uri::from_static("/v1/webhooks"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        unsigned_webhooks_response.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_route_is_not_auth_denied(
        app.clone(),
        fixtures::operator_signed_request(
            &cfg.common.key_pair,
            Request::builder()
                .uri(Uri::from_static("/v1/webhooks"))
                .body(axum::body::Body::empty())
                .unwrap(),
            &[],
        ),
    )
    .await;
    // 4) App API: GET /v1/assets/{definition_id}/holders — use percent-encoded '#'
    // in the definition id (bogus#wonderland) to ensure parsing is exercised.
    assert_route_is_not_auth_denied(
        app.clone(),
        Request::builder()
            .uri(Uri::from_static(
                "/v1/assets/bogus%23wonderland/holders?offset=0",
            ))
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    // 5) App API: POST /v1/webhooks — create a webhook (write path)
    let body = r#"{
  "url": "https://example.com/callback",
  "secret": null,
  "active": true
}"#;
    assert_route_is_not_auth_denied(
        app.clone(),
        fixtures::operator_signed_request(
            &cfg.common.key_pair,
            Request::builder()
                .method("POST")
                .uri(Uri::from_static("/v1/webhooks"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body))
                .unwrap(),
            body.as_bytes(),
        ),
    )
    .await;
    assert_route_is_not_auth_denied(
        app.clone(),
        Request::builder()
            .uri(Uri::from_static(
                "/v1/contracts/rollups/swaps/fills?authority=not-a-real-authority",
            ))
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    assert_route_is_not_auth_denied(
        app.clone(),
        Request::builder()
            .uri(Uri::from_static(
                "/v1/contracts/rollups/swaps/candles?authority=not-a-real-authority",
            ))
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    assert_route_is_not_auth_denied(
        app.clone(),
        Request::builder()
            .uri(Uri::from_static(
                "/v1/contracts/rollups/uranai/markets/history?market_id=not-a-real-market",
            ))
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    assert_route_is_not_auth_denied(
        app.clone(),
        Request::builder()
            .uri(Uri::from_static(
                "/v1/contracts/rollups/trader/activity?authority=not-a-real-authority",
            ))
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    for path in [
        "/v1/contracts/rollups/swaps/fills?authority=not-a-real-authority",
        "/v1/contracts/rollups/swaps/candles?authority=not-a-real-authority",
        "/v1/contracts/rollups/uranai/markets/history?market_id=not-a-real-market",
        "/v1/contracts/rollups/trader/activity",
        "/v1/contracts/rollups/trader/account?authority=not-a-real-authority",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("x-iroha-account", "incomplete-canonical-identity")
                    .body(axum::body::Body::empty())
                    .expect("partial canonical rollup request"),
            )
            .await
            .expect("rollup authentication response");
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{path} must reject partial canonical request identity"
        );
    }
    for path in [
        "/v1/contracts/rollups/intents",
        "/v1/contracts/rollups/vaults/positions",
        "/v1/contracts/rollups/operators/status",
        "/v1/contracts/rollups/margin/health",
        "/v1/contracts/rollups/rwa/lots",
        "/v1/contracts/rollups/dlmm/hooks",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "retired synthetic route {path}"
        );
    }
    assert_route_is_not_auth_denied(
        app,
        Request::builder()
            .uri(Uri::from_static(
                "/v1/contracts/rollups/trader/account?authority=not-a-real-authority",
            ))
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    runtime.shutdown().await;
}
#[tokio::test]
async fn contract_routes_honor_api_token_requirement() {
    const API_TOKEN: &str = "test-token-0000000000000000000000";
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let mut cfg = mk_minimal_root_cfg();
    cfg.torii.require_api_token = true;
    cfg.torii.api_tokens = vec![API_TOKEN.to_owned()].into();
    let (kiso, _child) = KisoHandle::start(cfg.clone());
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let local_peer_id = PeerId::new(cfg.common.key_pair.public_key().clone());
    let mut world = World::default();
    fixtures::seed_peer(&mut world, local_peer_id.clone());
    let state = Arc::new(State::new_for_testing(world, kura.clone(), query));
    let queue_cfg = iroha_config::parameters::actual::Queue::default();
    let events_sender: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue = Arc::new(iroha_core::queue::Queue::from_config(
        queue_cfg,
        events_sender,
    ));
    let (peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let _ = peers_tx;
    let da_receipt_signer = cfg.common.key_pair.clone();
    let torii = iroha_torii::Torii::new(
        build_identity_test_fixture::build_identity(),
        ChainId::from("test-chain"),
        iroha_torii::test_utils::signed_query_network_id(),
        kiso,
        cfg.torii.clone(),
        queue,
        tokio::sync::broadcast::channel(1).0,
        LiveQueryStore::start_test(),
        kura,
        state,
        da_receipt_signer,
        iroha_torii::OnlinePeersProvider::new(peers_rx),
    )
    .expect("valid Torii app API fixture");
    let runtime = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let app = runtime.router();
    for (method, path) in [
        ("POST", "/v1/contracts/deploy"),
        ("POST", "/v1/contracts/deploy-bundle"),
        (
            "GET",
            "/v1/contracts/deploy-bundles/not-a-real-bundle-digest",
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("x-api-token", API_TOKEN)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "path {path}");
    }
    assert_route_is_not_auth_denied(
        app.clone(),
        Request::builder()
            .method("POST")
            .uri(Uri::from_static("/v1/contracts/call"))
            .header("x-api-token", API_TOKEN)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from("{}"))
            .unwrap(),
    )
    .await;
    assert_route_is_not_auth_denied(
        app.clone(),
        Request::builder()
            .method("POST")
            .uri(Uri::from_static("/v1/contracts/view"))
            .header("x-api-token", API_TOKEN)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from("{}"))
            .unwrap(),
    )
    .await;
    assert_route_is_not_auth_denied(
        app.clone(),
        Request::builder()
            .method("POST")
            .uri(Uri::from_static("/v1/contracts/view/batch"))
            .header("x-api-token", API_TOKEN)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from("{}"))
            .unwrap(),
    )
    .await;
    assert_route_is_not_auth_denied(
        app.clone(),
        Request::builder()
            .uri(Uri::from_static("/v1/contracts/state"))
            .header("x-api-token", API_TOKEN)
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    runtime.shutdown().await;
}

#[path = "../src/build_identity_test_fixture.rs"]
mod build_identity_test_fixture;
