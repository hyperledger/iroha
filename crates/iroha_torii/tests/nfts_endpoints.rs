//! Smoke tests for Torii NFT endpoints.
#![cfg(feature = "app_api")]
use axum::{body::Body, http::Request};
use http::StatusCode;
use iroha_core::{
    kiso::KisoHandle,
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_torii::Torii;
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceExt as _;
async fn call_app(app: &axum::Router, request: Request<Body>) -> axum::response::Response {
    let service = app
        .clone()
        .into_make_service_with_connect_info::<SocketAddr>()
        .oneshot(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("nft make service");
    service.oneshot(request).await.expect("nft response")
}
#[tokio::test]
async fn nfts_endpoints_exist() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
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
    let (peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let _ = peers_tx;
    let torii = Torii::new_with_handle(
        iroha_model_base::chain::ChainId::from("test-chain"),
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
            iroha_torii::MaybeTelemetry::disabled(),
        ),
    )
    .expect("valid Torii NFT fixture");
    let runtime = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let app = runtime.router();
    // GET /v1/nfts
    let resp = call_app(
        &app,
        Request::builder()
            .uri("/v1/nfts?offset=0")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert!(matches!(
        resp.status(),
        StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
    ));
    // POST /v1/nfts/query
    let resp = call_app(
        &app,
        Request::builder()
            .method("POST")
            .uri("/v1/nfts/query")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await;
    assert!(matches!(
        resp.status(),
        StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
    ));
    runtime.shutdown().await;
}

#[path = "../src/build_identity_test_fixture.rs"]
mod build_identity_test_fixture;
