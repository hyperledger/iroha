//! Smoke test that Webhooks endpoints are exposed via the merged sub-router.
#![cfg(feature = "app_api")]
use axum::http::Request;
use http::StatusCode;
use iroha_core::{
    kiso::KisoHandle,
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_model_base::peer::PeerId;
use iroha_torii::Torii;
use std::sync::Arc;
use tower::ServiceExt as _;
#[path = "fixtures.rs"]
mod fixtures;
#[tokio::test]
async fn webhooks_endpoints_exposed_by_default() {
    // Minimal Torii setup
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.operator_signatures.enabled = true;
    cfg.torii.operator_signatures.allow_node_key = true;
    let (kiso, _child) = KisoHandle::start(cfg.clone());
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let local_peer_id = PeerId::new(cfg.common.key_pair.public_key().clone());
    let mut world = World::default();
    fixtures::seed_peer(&mut world, local_peer_id.clone());
    let chain_id = cfg.common.chain.clone();
    let network_id = iroha_data_model::NetworkId::from_genesis_hash(cfg.genesis.expected_hash);
    let state = Arc::new(State::new_with_chain_and_network_id_for_testing(
        world,
        kura.clone(),
        query,
        chain_id.clone(),
        network_id,
    ));
    let queue_cfg = iroha_config::parameters::actual::Queue::default();
    let events_sender: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue = Arc::new(iroha_core::queue::Queue::from_config(
        queue_cfg,
        events_sender,
    ));
    let (peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let _ = peers_tx;
    let da_receipt_signer = cfg.common.key_pair.clone();
    let torii = Torii::new(
        build_identity_test_fixture::build_identity(),
        chain_id,
        network_id,
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
    .expect("valid Torii webhook fixture");
    let runtime = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let app = runtime.router();
    // Webhook registry routes reject requests before dispatch unless operator
    // authentication succeeds.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/webhooks")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // POST /v1/webhooks — create a webhook
    let body = r#"{"url":"https://example.com/webhook","active":true}"#;
    let resp = app
        .clone()
        .oneshot(fixtures::operator_signed_request(
            &cfg.common.key_pair,
            Request::builder()
                .method("POST")
                .uri("/v1/webhooks")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body))
                .unwrap(),
            body.as_bytes(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        resp.status(),
        StatusCode::CREATED | StatusCode::TOO_MANY_REQUESTS
    ));
    // GET /v1/webhooks — list webhooks
    let resp = app
        .oneshot(fixtures::operator_signed_request(
            &cfg.common.key_pair,
            Request::builder()
                .uri("/v1/webhooks")
                .body(axum::body::Body::empty())
                .unwrap(),
            &[],
        ))
        .await
        .unwrap();
    assert!(matches!(
        resp.status(),
        StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
    ));
    runtime.shutdown().await;
}
#[tokio::test]
async fn webhooks_endpoints_hidden_when_disabled() {
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.webhooks_enabled = false;
    cfg.torii.operator_signatures.enabled = true;
    cfg.torii.operator_signatures.allow_node_key = true;
    let (kiso, _child) = KisoHandle::start(cfg.clone());
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let local_peer_id = PeerId::new(cfg.common.key_pair.public_key().clone());
    let mut world = World::default();
    fixtures::seed_peer(&mut world, local_peer_id.clone());
    let chain_id = cfg.common.chain.clone();
    let network_id = iroha_data_model::NetworkId::from_genesis_hash(cfg.genesis.expected_hash);
    let state = Arc::new(State::new_with_chain_and_network_id_for_testing(
        world,
        kura.clone(),
        query,
        chain_id.clone(),
        network_id,
    ));
    let queue_cfg = iroha_config::parameters::actual::Queue::default();
    let events_sender: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue = Arc::new(iroha_core::queue::Queue::from_config(
        queue_cfg,
        events_sender,
    ));
    let (peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let _ = peers_tx;
    let da_receipt_signer = cfg.common.key_pair.clone();
    let torii = Torii::new(
        build_identity_test_fixture::build_identity(),
        chain_id,
        network_id,
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
    .expect("valid Torii webhook fixture");
    let runtime = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let app = runtime.router();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/webhooks")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // Authentication precedes the feature-disabled handler, so an authorized
    // request reaches the stable not-found response.
    let resp = app
        .oneshot(fixtures::operator_signed_request(
            &cfg.common.key_pair,
            Request::builder()
                .uri("/v1/webhooks")
                .body(axum::body::Body::empty())
                .unwrap(),
            &[],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    runtime.shutdown().await;
}

#[path = "../src/build_identity_test_fixture.rs"]
mod build_identity_test_fixture;
