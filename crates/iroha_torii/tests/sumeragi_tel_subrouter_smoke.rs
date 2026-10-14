//! Smoke test that Torii does not expose retired Sumeragi telemetry routes.
#![cfg(feature = "telemetry")]
use axum::{extract::ConnectInfo, http::Request};
use http::StatusCode;
use iroha_config::parameters::actual::TelemetryProfile;
use iroha_core::{
    kiso::KisoHandle,
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_torii::{MaybeTelemetry, Torii};
use std::sync::Arc;
use tower::ServiceExt as _;
mod fixtures;
fn signed_loopback_get(
    cfg: &iroha_config::parameters::actual::Root,
    uri: &'static str,
) -> Request<axum::body::Body> {
    let request = Request::builder()
        .uri(uri)
        .body(axum::body::Body::empty())
        .unwrap();
    let mut request = fixtures::operator_signed_request(&cfg.common.key_pair, request, &[]);
    request
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))));
    request
}
#[tokio::test]
async fn sumeragi_tel_subrouter_rejects_retired_endpoints() {
    // Minimal Torii setup with telemetry enabled
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
    let telemetry_handle = MaybeTelemetry::for_tests().with_profile(TelemetryProfile::Full);
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
            telemetry_handle,
        ),
    )
    .expect("valid Torii Sumeragi-telemetry fixture");
    let runtime = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let app = runtime.router();
    for retired in [
        "/v1/sumeragi/pacemaker",
        "/v1/sumeragi/rbc",
        "/v1/sumeragi/phases",
        "/v1/sumeragi/telemetry",
        "/v1/sumeragi/rbc/delivered/0/0",
        "/v1/sumeragi/rbc/sessions",
        "/v1/sumeragi/rbc/sample",
        "/v1/sumeragi/collectors",
    ] {
        let response = app
            .clone()
            .oneshot(signed_loopback_get(&cfg, retired))
            .await
            .expect("retired route response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{retired}");
    }
    runtime.shutdown().await;
}

#[path = "../src/build_identity_test_fixture.rs"]
mod build_identity_test_fixture;
