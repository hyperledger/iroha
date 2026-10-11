//! Integration coverage for the single, first-release Torii API surface.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![cfg(feature = "app_api")]
use axum::http::Request;
use http::{
    HeaderMap, HeaderValue, Method, StatusCode,
    header::{ACCEPT, ALLOW, CONTENT_TYPE, VARY},
};
use http_body_util::BodyExt as _;
use iroha_core::{
    kiso::KisoHandle,
    kura::Kura,
    query::store::LiveQueryStore,
    queue::Queue,
    state::{State, World},
};
use iroha_torii::{OnlinePeersProvider, Torii, test_utils};
use iroha_torii_shared::ErrorEnvelope;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tower::ServiceExt as _;
fn local_connect_info() -> axum::extract::connect_info::ConnectInfo<SocketAddr> {
    axum::extract::connect_info::ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
}
fn header_contains_token(headers: &HeaderMap, name: http::header::HeaderName, token: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|value| value.trim().eq_ignore_ascii_case(token))
}
async fn decode_error_response(
    response: axum::response::Response,
) -> (StatusCode, HeaderMap, ErrorEnvelope) {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("collect error response")
        .to_bytes();
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .expect("typed fallback content type");
    let envelope = if content_type.starts_with("application/json") {
        norito::json::from_slice(&body).expect("decode JSON error envelope")
    } else {
        assert_eq!(content_type, "application/x-norito");
        norito::decode_from_bytes(&body).expect("decode Norito error envelope")
    };
    (status, headers, envelope)
}
async fn assert_canonical_early_error(
    response: axum::response::Response,
    expected_status: StatusCode,
    expected_content_type: &str,
    expected_code: &str,
    expected_request_id: &str,
) {
    assert_eq!(response.status(), expected_status);
    let headers = response.headers().clone();
    assert_eq!(
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(expected_content_type)
    );
    assert_eq!(
        headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some(expected_request_id)
    );
    assert!(header_contains_token(&headers, VARY, "Accept"));
    let body = response
        .into_body()
        .collect()
        .await
        .expect("collect early error response")
        .to_bytes();
    assert_eq!(
        headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok()),
        Some(body.len())
    );
    let envelope: ErrorEnvelope = if expected_content_type.starts_with("application/json") {
        norito::json::from_slice(&body).expect("decode canonical early JSON error")
    } else {
        norito::decode_from_bytes(&body).expect("decode canonical early Norito error")
    };
    assert_eq!(envelope.code(), expected_code);
}
#[tokio::test]
async fn unknown_routes_use_negotiated_typed_error_envelopes() {
    let runtime = build_router();
    let router = runtime.router();
    for accept in ["application/json", "application/x-norito"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/route-that-does-not-exist")
                    .extension(local_connect_info())
                    .header(ACCEPT, accept)
                    .body(axum::body::Body::empty())
                    .expect("unknown-route request"),
            )
            .await
            .expect("unknown-route response");
        let (status, headers, envelope) = decode_error_response(response).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "Accept: {accept}");
        assert_eq!(envelope.code(), "route_not_found", "Accept: {accept}");
        assert!(header_contains_token(&headers, VARY, "Accept"));
    }
    runtime.shutdown().await;
}
#[tokio::test]
async fn retired_legacy_finality_routes_are_absent() {
    let runtime = build_router();
    let router = runtime.router();
    for path in [
        "/v1/sumeragi/commit-certificates",
        "/v1/sumeragi/commit-qcs/00",
        "/v1/sumeragi/validator-sets",
        "/v1/sumeragi/validator-sets/1",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .extension(local_connect_info())
                    .header(ACCEPT, "application/json")
                    .body(axum::body::Body::empty())
                    .expect("retired-route request"),
            )
            .await
            .expect("retired-route response");
        let (status, _, envelope) = decode_error_response(response).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "path={path}");
        assert_eq!(envelope.code(), "route_not_found", "path={path}");
    }
    runtime.shutdown().await;
}
#[tokio::test]
async fn assembled_router_canonicalizes_early_path_and_accept_failures() {
    let runtime = build_router();
    let router = runtime.router();
    let invalid_path = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1//route-that-does-not-exist")
                .extension(local_connect_info())
                .header(ACCEPT, "application/json")
                .header("x-request-id", "early-path-400")
                .body(axum::body::Body::empty())
                .expect("invalid-path request"),
        )
        .await
        .expect("invalid-path response");
    assert_canonical_early_error(
        invalid_path,
        StatusCode::BAD_REQUEST,
        "application/json; charset=utf-8",
        "request_path_invalid",
        "early-path-400",
    )
    .await;
    let trailing_slash = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health/")
                .extension(local_connect_info())
                .header(ACCEPT, "application/x-norito")
                .header("x-request-id", "early-path-404")
                .body(axum::body::Body::empty())
                .expect("trailing-slash request"),
        )
        .await
        .expect("trailing-slash response");
    assert_canonical_early_error(
        trailing_slash,
        StatusCode::NOT_FOUND,
        "application/x-norito",
        "route_not_found",
        "early-path-404",
    )
    .await;
    let mut malformed_accept = Request::builder()
        .uri(iroha_torii_shared::route_catalog::core::HEALTH.path())
        .extension(local_connect_info())
        .header("x-request-id", "early-accept-406")
        .body(axum::body::Body::empty())
        .expect("malformed-Accept request");
    malformed_accept
        .headers_mut()
        .append(ACCEPT, HeaderValue::from_static("application/json"));
    malformed_accept.headers_mut().append(
        ACCEPT,
        HeaderValue::from_bytes(&[0xff]).expect("opaque invalid-ASCII Accept value"),
    );
    let malformed_accept = router
        .oneshot(malformed_accept)
        .await
        .expect("malformed-Accept response");
    assert_canonical_early_error(
        malformed_accept,
        StatusCode::NOT_ACCEPTABLE,
        "application/json; charset=utf-8",
        "response_not_acceptable",
        "early-accept-406",
    )
    .await;
    runtime.shutdown().await;
}
#[tokio::test]
async fn retired_kagemusha_routes_are_absent() {
    let runtime = build_router();
    let router = runtime.router();
    for (method, path) in [
        (Method::GET, "/v1/kagemusha/readiness"),
        (Method::POST, "/v1/kagemusha/top-up"),
        (Method::POST, "/v1/kagemusha/redeem"),
        (Method::GET, "/v1/kagemusha/operations/11"),
        (Method::POST, "/v1/kagemusha/ordinary/current-wallet"),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri(path)
                    .extension(local_connect_info())
                    .header(ACCEPT, "application/json")
                    .header(CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from("{"))
                    .expect("retired-route request"),
            )
            .await
            .expect("retired-route response");
        let (status, _, envelope) = decode_error_response(response).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(envelope.code(), "route_not_found", "{method} {path}");
    }
    runtime.shutdown().await;
}
#[tokio::test]
async fn wrong_methods_use_negotiated_typed_errors_and_retain_allow() {
    let runtime = build_router();
    let router = runtime.router();
    for accept in ["application/json", "application/x-norito"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(iroha_torii_shared::route_catalog::core::HEALTH.path())
                    .extension(local_connect_info())
                    .header(ACCEPT, accept)
                    .body(axum::body::Body::empty())
                    .expect("wrong-method request"),
            )
            .await
            .expect("wrong-method response");
        let (status, headers, envelope) = decode_error_response(response).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "Accept: {accept}");
        assert_eq!(envelope.code(), "method_not_allowed", "Accept: {accept}");
        assert!(header_contains_token(&headers, ALLOW, "GET"));
        assert!(header_contains_token(&headers, ALLOW, "HEAD"));
        assert!(header_contains_token(&headers, VARY, "Accept"));
    }
    runtime.shutdown().await;
}
#[tokio::test]
async fn unsupported_por_routes_are_unregistered_and_cannot_mutate_state() {
    async fn por_status_snapshot(router: &axum::Router) -> Vec<u8> {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/sorafs/por/status?limit=1000&max_bytes=4194304")
                    .extension(local_connect_info())
                    .body(axum::body::Body::empty())
                    .expect("PoR status request"),
            )
            .await
            .expect("PoR status response");
        assert_eq!(response.status(), StatusCode::OK);
        response
            .into_body()
            .collect()
            .await
            .expect("collect PoR status")
            .to_bytes()
            .to_vec()
    }
    let runtime = build_router();
    let router = runtime.router();
    let before = por_status_snapshot(&router).await;
    let unsupported = [
        "/v1/sorafs/capacity/por-challenge",
        "/v1/sorafs/capacity/por",
        "/v1/sorafs/por/trigger",
        "/v1/sorafs/storage/por-challenge",
        "/v1/sorafs/storage/por-proof",
        "/v1/sorafs/storage/por-verdict",
        // Canonicalization variants must remain unregistered too.
        "/v1/sorafs/capacity/por-challenge/",
        "/v1/SoraFS/capacity/por-challenge",
        "/v1/sorafs/capacity/por-challenge/arbitrary",
        "/v1/sorafs/storage/por-proof/arbitrary",
    ];
    for path in unsupported {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .extension(local_connect_info())
                    .header(ACCEPT, "application/json")
                    .header(CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        r#"{"challenge_b64":"forged","proof_b64":"forged","verdict_b64":"forged","success":true}"#,
                    ))
                    .expect("unsupported PoR request"),
            )
            .await
            .expect("unsupported PoR response");
        let (status, _, envelope) = decode_error_response(response).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "POST {path}");
        assert_eq!(envelope.code(), "route_not_found", "POST {path}");
        assert_eq!(
            por_status_snapshot(&router).await,
            before,
            "unregistered route changed PoR state: POST {path}"
        );
    }
    for active_path in [
        "/v1/sorafs/capacity/por-proof",
        "/v1/sorafs/capacity/por-verdict",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(active_path)
                    .extension(local_connect_info())
                    .header(CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from("{}"))
                    .expect("active PoR route request"),
            )
            .await
            .expect("active PoR route response");
        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "active route was removed: POST {active_path}"
        );
    }
    runtime.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn canonical_sumeragi_spellings_reach_their_resource_handlers() {
    let runtime = build_router();
    let router = runtime.router();
    for path in ["/v1/sumeragi/bls-keys"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .extension(local_connect_info())
                    .header(ACCEPT, "application/json")
                    .body(axum::body::Body::empty())
                    .expect("canonical Sumeragi request"),
            )
            .await
            .expect("canonical Sumeragi response");
        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "canonical route must resolve: {path}"
        );
    }
    runtime.shutdown().await;
}
fn build_router() -> iroha_torii::TestApiRouterRuntime {
    let cfg = test_utils::mk_minimal_root_cfg();
    let (kiso, _child) = KisoHandle::start(cfg.clone());
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = Arc::new(State::new_for_testing(
        World::default(),
        kura.clone(),
        query,
    ));
    let queue_cfg = iroha_config::parameters::actual::Queue::default();
    let events_sender: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue = Arc::new(Queue::from_config(queue_cfg, events_sender));
    let (peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let _ = peers_tx;
    let torii = Torii::new_with_handle(
        cfg.common.chain.clone(),
        iroha_torii::test_utils::signed_query_network_id(),
        kiso,
        cfg.torii.clone(),
        queue,
        tokio::sync::broadcast::channel(1).0,
        LiveQueryStore::start_test(),
        kura,
        state,
        cfg.common.key_pair.clone(),
        OnlinePeersProvider::new(peers_rx),
        None,
        iroha_torii::ToriiRuntimeDeps::new(
            build_identity_test_fixture::build_identity(),
            iroha_torii::MaybeTelemetry::disabled(),
        ),
    )
    .expect("valid first-release Torii fixture");
    torii
        .api_router_for_tests()
        .expect("test Torii router initializes")
}

#[path = "../src/build_identity_test_fixture.rs"]
mod build_identity_test_fixture;
