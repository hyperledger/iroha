//! Profile gate test for `/v1/sumeragi/status/sse`.
#![cfg(feature = "telemetry")]
use axum::http::Request;
use http::StatusCode;
use iroha_config::parameters::actual::TelemetryProfile;
use iroha_core::{
    kiso::KisoHandle,
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_model_base::chain::ChainId;
use iroha_torii::{MaybeTelemetry, Torii};
use std::sync::Arc;
use tower::ServiceExt as _;
fn mk_minimal_root_cfg() -> iroha_config::parameters::actual::Root {
    iroha_torii::test_utils::mk_minimal_root_cfg()
}
fn build_torii(profile: TelemetryProfile) -> Torii {
    let cfg = mk_minimal_root_cfg();
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
    let queue = Arc::new(iroha_core::queue::Queue::from_config(
        queue_cfg,
        events_sender,
    ));
    let (_peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let telemetry = MaybeTelemetry::for_tests().with_profile(profile);
    Torii::new_with_handle(
        ChainId::from("test-chain"),
        iroha_torii::test_utils::signed_query_network_id(),
        kiso,
        cfg.torii.clone(),
        queue,
        tokio::sync::broadcast::channel(1).0,
        LiveQueryStore::start_test(),
        kura,
        state,
        cfg.common.key_pair.clone(),
        iroha_torii::OnlinePeersProvider::new(peers_rx),
        None,
        iroha_torii::ToriiRuntimeDeps::new(
            build_identity_test_fixture::build_identity(),
            telemetry,
        ),
    )
    .expect("valid Torii Sumeragi-SSE fixture")
}
#[tokio::test]
async fn status_sse_allowed_under_extended_profile() {
    let torii = build_torii(TelemetryProfile::Extended);
    let runtime = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let resp = runtime
        .router()
        .oneshot(
            Request::builder()
                .uri("/v1/sumeragi/status/sse")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("text/event-stream"));
    runtime.shutdown().await;
}
#[tokio::test]
async fn status_sse_restricted_under_operator_profile() {
    let torii = build_torii(TelemetryProfile::Operator);
    let runtime = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let resp = runtime
        .router()
        .oneshot(
            Request::builder()
                .uri("/v1/sumeragi/status/sse")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    runtime.shutdown().await;
}

#[path = "../src/build_identity_test_fixture.rs"]
mod build_identity_test_fixture;
