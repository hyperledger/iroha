//! Router-level regression tests for `/v1/configuration`.
#[path = "fixtures.rs"]
mod fixtures;
#[path = "common/norito_rpc_harness.rs"]
mod norito_rpc_harness;
use axum::http::Request;
use http::StatusCode;
use http_body_util::BodyExt as _;
use iroha_config::parameters::actual::{NodeRole, NoritoRpcStage};
use iroha_torii_shared::configuration::Configuration;
use norito_rpc_harness::NoritoRpcHarness;
use tower::ServiceExt as _;
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn configuration_endpoint_includes_transport_summary() {
    let harness = NoritoRpcHarness::new(|cfg| {
        cfg.torii.transport.norito_rpc.enabled = true;
        cfg.torii.transport.norito_rpc.require_mtls = true;
        cfg.torii.transport.norito_rpc.allowed_clients =
            vec!["alpha-canary".into(), "beta-canary".into()];
        cfg.torii.transport.norito_rpc.stage = NoritoRpcStage::Ga;
    });
    let cfg = &harness.cfg;
    let expected_stage = harness
        .cfg
        .torii
        .transport
        .norito_rpc
        .stage
        .label()
        .to_string();
    let expected_allowlist = cfg.torii.transport.norito_rpc.allowed_clients.len();
    let mut req = fixtures::operator_signed_request(
        &harness.cfg.common.key_pair,
        Request::builder()
            .uri(iroha_torii_shared::route_catalog::core::CONFIGURATION_GET.path())
            .body(axum::body::Body::empty())
            .unwrap(),
        &[],
    );
    req.extensions_mut()
        .insert(norito_rpc_harness::loopback_connect_info());
    let response = harness.app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let dto: Configuration = norito::json::from_slice(&body).expect("valid configuration payload");
    let summary = dto.transport.norito_rpc;
    assert!(summary.enabled, "expected Norito-RPC flag to propagate");
    assert!(summary.require_mtls, "require_mtls flag missing");
    assert_eq!(
        summary.stage, expected_stage,
        "stage label differs from config"
    );
    assert_eq!(
        summary.canary_allowlist_size, expected_allowlist,
        "allowlist size must match config"
    );
    let expected_role = match cfg.sumeragi.role {
        NodeRole::Validator => "validator",
        NodeRole::Observer => "observer",
    };
    assert_eq!(
        dto.consensus.protocol_version,
        u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION),
        "the fixed first-release consensus protocol should be surfaced"
    );
    assert_eq!(
        dto.consensus.role, expected_role,
        "the node-local consensus role should propagate"
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn configuration_endpoint_rejects_runtime_mutation() {
    let harness = NoritoRpcHarness::new(|_| {});
    let mut req = fixtures::operator_signed_request(
        &harness.cfg.common.key_pair,
        Request::builder()
            .method(http::Method::POST)
            .uri(iroha_torii_shared::route_catalog::core::CONFIGURATION_GET.path())
            .body(axum::body::Body::empty())
            .unwrap(),
        &[],
    );
    req.extensions_mut()
        .insert(norito_rpc_harness::loopback_connect_info());

    let response = harness.app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    harness.shutdown().await;
}
