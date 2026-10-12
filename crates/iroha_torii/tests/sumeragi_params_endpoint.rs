#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Router-level test for GET /v1/sumeragi/params
#[cfg(feature = "telemetry")]
#[path = "fixtures.rs"]
mod fixtures;
#[cfg(feature = "telemetry")]
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
#[cfg(feature = "telemetry")]
use http_body_util::BodyExt as _;
use iroha_config::parameters::actual::{ConfidentialGas, Root, TelemetryProfile};
#[cfg(feature = "telemetry")]
use iroha_torii_shared::{configuration::Configuration, route_catalog};
#[cfg(feature = "telemetry")]
use tower::ServiceExt as _;
#[cfg(feature = "telemetry")]
struct ToriiTestHarness {
    cfg: Root,
    app: iroha_torii::TestApiRouterRuntime,
    _kiso_child: iroha_futures::supervisor::Child,
}
#[cfg(feature = "telemetry")]
impl ToriiTestHarness {
    async fn shutdown(self) {
        self.app.shutdown().await;
    }
}
#[cfg(feature = "telemetry")]
fn torii_test_harness(cfg: Root) -> ToriiTestHarness {
    torii_test_harness_with_zk_policy(cfg, None)
}
/// The verification gas schedule of a chain that commits no ZK validity policy.
#[cfg(feature = "telemetry")]
fn protocol_default_gas() -> ConfidentialGas {
    iroha_core::state::default_zk_config().gas
}
#[cfg(feature = "telemetry")]
fn torii_test_harness_with_zk_policy(
    cfg: Root,
    policy: Option<iroha_core::zk_validity_policy::ZkValidityPolicyV1>,
) -> ToriiTestHarness {
    let (kiso, kiso_child) = iroha_core::kiso::KisoHandle::start(cfg.clone());
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let world = iroha_core::state::World::default();
    if let Some(policy) = policy {
        let mut block = world.block();
        block
            .parameters
            .get_mut()
            .set_parameter(iroha_data_model::parameter::Parameter::Custom(
                policy.into_custom_parameter(),
            ));
        block.commit();
    }
    // The State carries the same genesis-derived network identity Torii is given.
    let state = std::sync::Arc::new(
        iroha_core::state::State::new_with_chain_and_network_id_for_testing(
            world,
            kura.clone(),
            iroha_core::query::store::LiveQueryStore::start_test(),
            iroha_model_base::chain::ChainId::from("test-chain"),
            iroha_torii::test_utils::signed_query_network_id(),
        ),
    );
    let queue_cfg = iroha_config::parameters::actual::Queue::default();
    let events: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue = std::sync::Arc::new(iroha_core::queue::Queue::from_config(queue_cfg, events));
    let (_peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let telemetry_handle =
        iroha_torii::MaybeTelemetry::for_tests().with_profile(TelemetryProfile::Full);
    let torii = iroha_torii::Torii::new_with_handle(
        iroha_model_base::chain::ChainId::from("test-chain"),
        iroha_torii::test_utils::signed_query_network_id(),
        kiso,
        cfg.torii.clone(),
        queue,
        tokio::sync::broadcast::channel(1).0,
        iroha_core::query::store::LiveQueryStore::start_test(),
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
    .expect("valid Torii Sumeragi-parameters fixture");
    ToriiTestHarness {
        cfg,
        app: torii
            .api_router_for_tests()
            .expect("test Torii router initializes"),
        _kiso_child: kiso_child,
    }
}
#[cfg(feature = "telemetry")]
async fn collect_body(response: axum::response::Response) -> axum::body::Bytes {
    response.into_body().collect().await.unwrap().to_bytes()
}
#[cfg(feature = "telemetry")]
async fn signed_get_configuration(harness: &ToriiTestHarness) -> axum::response::Response {
    let req = fixtures::operator_signed_request(
        &harness.cfg.common.key_pair,
        Request::builder()
            .uri(route_catalog::core::CONFIGURATION_GET.path())
            .body(Body::empty())
            .unwrap(),
        &[],
    );
    harness.app.clone().oneshot(req).await.unwrap()
}
#[cfg(feature = "telemetry")]
async fn get_sumeragi_params(
    harness: &ToriiTestHarness,
    accept: Option<&'static str>,
) -> axum::response::Response {
    let mut builder = Request::builder().uri("/v1/sumeragi/params");
    if let Some(accept) = accept {
        builder = builder.header(header::ACCEPT, accept);
    }
    harness
        .app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}
#[cfg(feature = "telemetry")]
fn assert_content_type_starts_with(response: &axum::response::Response, expected: &str) {
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .expect("response content type");
    assert!(
        content_type.starts_with(expected),
        "expected content type prefix `{expected}`, got `{content_type}`"
    );
}
#[cfg(feature = "telemetry")]
fn assert_confidential_gas_matches(
    actual: iroha_torii_shared::configuration::ConfidentialGas,
    expected: ConfidentialGas,
) {
    assert_eq!(actual.proof_base, expected.proof_base);
    assert_eq!(actual.per_public_input, expected.per_public_input);
    assert_eq!(actual.per_proof_byte, expected.per_proof_byte);
    assert_eq!(actual.per_nullifier, expected.per_nullifier);
    assert_eq!(actual.per_commitment, expected.per_commitment);
}
#[cfg(feature = "telemetry")]
fn checked_configuration_outsider_fixture() -> iroha_crypto::KeyPair {
    iroha_crypto::KeyPair::try_random()
        .expect("generate checked Sumeragi params outsider fixture keypair")
}
#[cfg(feature = "telemetry")]
#[test]
fn configuration_outsider_fixture_uses_checked_ed25519_key_generation() {
    let key_pair = checked_configuration_outsider_fixture();
    let algorithm = key_pair
        .public_key()
        .try_algorithm()
        .expect("fixture outsider public key has a valid algorithm");
    assert_eq!(algorithm, iroha_crypto::Algorithm::Ed25519);
}
#[cfg(feature = "telemetry")]
fn configuration_update_body(gas: ConfidentialGas) -> Vec<u8> {
    format!(
        r#"{{"logger":{{"level":"INFO","filter":null}},"confidential_gas":{{"proof_base":{},"per_public_input":{},"per_proof_byte":{},"per_nullifier":{},"per_commitment":{}}}}}"#,
        gas.proof_base,
        gas.per_public_input,
        gas.per_proof_byte,
        gas.per_nullifier,
        gas.per_commitment
    )
    .into_bytes()
}
#[cfg(feature = "telemetry")]
fn configuration_update_without_logger_body() -> Vec<u8> {
    b"{}".to_vec()
}
#[cfg(feature = "telemetry")]
fn configuration_update_with_logger_level_body(level: &str) -> Vec<u8> {
    format!(r#"{{"logger":{{"level":"{level}","filter":null}}}}"#).into_bytes()
}
#[cfg(feature = "telemetry")]
fn configuration_update_missing_per_commitment_body(gas: ConfidentialGas) -> Vec<u8> {
    format!(
        r#"{{"logger":{{"level":"INFO","filter":null}},"confidential_gas":{{"proof_base":{},"per_public_input":{},"per_proof_byte":{},"per_nullifier":{}}}}}"#,
        gas.proof_base, gas.per_public_input, gas.per_proof_byte, gas.per_nullifier
    )
    .into_bytes()
}
#[cfg(feature = "telemetry")]
fn signed_post_configuration(
    harness: &ToriiTestHarness,
    body_bytes: Vec<u8>,
    signature_body_bytes: &[u8],
    content_type: &'static str,
) -> Request<Body> {
    fixtures::operator_signed_request(
        &harness.cfg.common.key_pair,
        Request::builder()
            .method("POST")
            .uri(route_catalog::core::CONFIGURATION_GET.path())
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(body_bytes))
            .unwrap(),
        signature_body_bytes,
    )
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn sumeragi_params_endpoint_shape() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let resp = get_sumeragi_params(&harness, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = collect_body(resp).await;
    let v: norito::json::Value = norito::json::from_slice(&body).unwrap();
    // Presence checks only (defaults come from configuration and may change)
    for k in [
        "block_time_ms",
        "commit_time_ms",
        "max_clock_drift_ms",
        "collectors_k",
        "redundant_send_r",
        "da_enabled",
        "chain_height",
    ] {
        assert!(v.get(k).is_some(), "missing key {k}");
    }
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn sumeragi_params_endpoint_honors_norito_accept_header() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let resp = get_sumeragi_params(&harness, Some("application/x-norito")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE),
        Some(&header::HeaderValue::from_static("application/x-norito"))
    );
    let body = collect_body(resp).await;
    assert!(!body.is_empty(), "Norito response body should not be empty");
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn sumeragi_params_endpoint_prefers_json_when_quality_is_higher() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let resp = get_sumeragi_params(
        &harness,
        Some("application/x-norito;q=0.2, application/json;q=0.8"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_content_type_starts_with(&resp, "application/json");
    let body = collect_body(resp).await;
    let v: norito::json::Value = norito::json::from_slice(&body).unwrap();
    assert!(v.get("block_time_ms").is_some());
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn sumeragi_params_endpoint_prefers_norito_on_equal_quality() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let resp = get_sumeragi_params(
        &harness,
        Some("application/json;q=0.5, application/x-norito;q=0.5"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE),
        Some(&header::HeaderValue::from_static("application/x-norito"))
    );
    let body = collect_body(resp).await;
    assert!(!body.is_empty(), "Norito response body should not be empty");
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn sumeragi_params_endpoint_treats_wildcard_accept_as_json() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let resp = get_sumeragi_params(&harness, Some("*/*")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_content_type_starts_with(&resp, "application/json");
    let body = collect_body(resp).await;
    let v: norito::json::Value = norito::json::from_slice(&body).unwrap();
    assert!(v.get("commit_time_ms").is_some());
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn sumeragi_params_endpoint_rejects_zero_quality_supported_formats() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let resp = get_sumeragi_params(
        &harness,
        Some("application/json;q=0, application/x-norito;q=0"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
    let body = collect_body(resp).await;
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("unsupported Accept header"));
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn sumeragi_params_endpoint_rejects_invalid_accept_quality() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let resp = get_sumeragi_params(&harness, Some("application/json;q=bogus")).await;
    assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
    let body = collect_body(resp).await;
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("invalid q-value"));
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn sumeragi_params_endpoint_rejects_unsupported_accept_header() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let resp = get_sumeragi_params(&harness, Some("text/plain")).await;
    assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
    let body = collect_body(resp).await;
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("unsupported Accept header"));
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_includes_confidential_gas() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let resp = signed_get_configuration(&harness).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = collect_body(resp).await;
    let v: norito::json::Value = norito::json::from_slice(&body).unwrap();
    let gas = v
        .get("confidential_gas")
        .and_then(|value| value.as_object())
        .expect("confidential_gas JSON object present");
    for key in [
        "proof_base",
        "per_public_input",
        "per_proof_byte",
        "per_nullifier",
        "per_commitment",
    ] {
        assert!(gas.get(key).is_some(), "confidential_gas missing key {key}");
    }
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_rejects_unsigned_requests() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let resp = harness
        .app
        .router()
        .oneshot(
            Request::builder()
                .uri(route_catalog::core::CONFIGURATION_GET.path())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = collect_body(resp).await;
    let v: norito::json::Value = norito::json::from_slice(&body).unwrap();
    assert_eq!(
        v.get("code").and_then(norito::json::Value::as_str),
        Some("operator_signature_missing")
    );
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_rejects_replayed_operator_signature() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let signed = fixtures::operator_signed_request(
        &harness.cfg.common.key_pair,
        Request::builder()
            .uri(route_catalog::core::CONFIGURATION_GET.path())
            .body(Body::empty())
            .unwrap(),
        &[],
    );
    let replay_headers = signed.headers().clone();
    let first = harness.app.clone().oneshot(signed).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let mut replay = Request::builder()
        .uri(route_catalog::core::CONFIGURATION_GET.path())
        .body(Body::empty())
        .unwrap();
    *replay.headers_mut() = replay_headers;
    let resp = harness.app.clone().oneshot(replay).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = collect_body(resp).await;
    let v: norito::json::Value = norito::json::from_slice(&body).unwrap();
    assert_eq!(
        v.get("code").and_then(norito::json::Value::as_str),
        Some("operator_signature_replay")
    );
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_rejects_non_node_operator_key() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let outsider = checked_configuration_outsider_fixture();
    let req = fixtures::operator_signed_request(
        &outsider,
        Request::builder()
            .uri(route_catalog::core::CONFIGURATION_GET.path())
            .body(Body::empty())
            .unwrap(),
        &[],
    );
    let resp = harness.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = collect_body(resp).await;
    let v: norito::json::Value = norito::json::from_slice(&body).unwrap();
    assert_eq!(
        v.get("code").and_then(norito::json::Value::as_str),
        Some("operator_key_not_allowed")
    );
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_rejects_invalid_operator_timestamp_header() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let mut req = fixtures::operator_signed_request(
        &harness.cfg.common.key_pair,
        Request::builder()
            .uri(route_catalog::core::CONFIGURATION_GET.path())
            .body(Body::empty())
            .unwrap(),
        &[],
    );
    req.headers_mut().insert(
        "x-iroha-operator-timestamp-ms",
        "not-a-number".parse().unwrap(),
    );
    let resp = harness.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = collect_body(resp).await;
    let v: norito::json::Value = norito::json::from_slice(&body).unwrap();
    assert_eq!(
        v.get("code").and_then(norito::json::Value::as_str),
        Some("operator_signature_invalid")
    );
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_accepts_query_when_signature_covers_query() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let req = fixtures::operator_signed_request(
        &harness.cfg.common.key_pair,
        Request::builder()
            .uri("/v1/configuration?view=full")
            .body(Body::empty())
            .unwrap(),
        &[],
    );
    let resp = harness.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = collect_body(resp).await;
    let dto: Configuration = norito::json::from_slice(&body).unwrap();
    assert_confidential_gas_matches(dto.confidential_gas, protocol_default_gas());
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_rejects_signature_bound_to_different_query() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let signed = fixtures::operator_signed_request(
        &harness.cfg.common.key_pair,
        Request::builder()
            .uri(route_catalog::core::CONFIGURATION_GET.path())
            .body(Body::empty())
            .unwrap(),
        &[],
    );
    let mut mismatched = Request::builder()
        .uri("/v1/configuration?view=full")
        .body(Body::empty())
        .unwrap();
    *mismatched.headers_mut() = signed.headers().clone();
    let resp = harness.app.clone().oneshot(mismatched).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = collect_body(resp).await;
    let v: norito::json::Value = norito::json::from_slice(&body).unwrap();
    assert_eq!(
        v.get("code").and_then(norito::json::Value::as_str),
        Some("operator_signature_bad")
    );
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_rejects_signature_bound_to_different_method() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let signed = fixtures::operator_signed_request(
        &harness.cfg.common.key_pair,
        Request::builder()
            .uri(route_catalog::core::CONFIGURATION_GET.path())
            .body(Body::empty())
            .unwrap(),
        &[],
    );
    let mut mismatched = Request::builder()
        .method("POST")
        .uri(route_catalog::core::CONFIGURATION_GET.path())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::empty())
        .unwrap();
    *mismatched.headers_mut() = signed.headers().clone();
    let resp = harness.app.clone().oneshot(mismatched).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = collect_body(resp).await;
    let v: norito::json::Value = norito::json::from_slice(&body).unwrap();
    assert_eq!(
        v.get("code").and_then(norito::json::Value::as_str),
        Some("operator_signature_bad")
    );
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_unversioned_path_is_not_registered() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let req = fixtures::operator_signed_request(
        &harness.cfg.common.key_pair,
        Request::builder()
            .uri("/configuration")
            .body(Body::empty())
            .unwrap(),
        &[],
    );
    let resp = harness.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_reports_the_committed_confidential_gas_schedule() {
    // The schedule a node reports is the one State charges: the committed ZK
    // validity policy, not a value of the node configuration.
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let mut policy = iroha_core::zk_validity_policy::ZkValidityPolicyV1::protocol_default();
    policy.gas.proof_base = 11;
    policy.gas.per_public_input = 22;
    policy.gas.per_proof_byte = 33;
    policy.gas.per_nullifier = 44;
    policy.gas.per_commitment = 55;
    let expected = ConfidentialGas {
        proof_base: 11,
        per_public_input: 22,
        per_proof_byte: 33,
        per_nullifier: 44,
        per_commitment: 55,
    };
    let harness = torii_test_harness_with_zk_policy(cfg, Some(policy));
    let resp = signed_get_configuration(&harness).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_content_type_starts_with(&resp, "application/json");
    let body = collect_body(resp).await;
    let dto: Configuration = norito::json::from_slice(&body).unwrap();
    assert_confidential_gas_matches(dto.confidential_gas, expected);
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_rejects_confidential_gas_update_via_post() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let initial_gas = protocol_default_gas();
    let harness = torii_test_harness(cfg);
    let updated = ConfidentialGas {
        proof_base: 101,
        per_public_input: 202,
        per_proof_byte: 303,
        per_nullifier: 404,
        per_commitment: 505,
    };
    let body_bytes = configuration_update_body(updated);
    let req = signed_post_configuration(
        &harness,
        body_bytes.clone(),
        &body_bytes,
        "application/json",
    );
    let resp = harness.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = signed_get_configuration(&harness).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = collect_body(resp).await;
    let dto: Configuration = norito::json::from_slice(&body).unwrap();
    assert_confidential_gas_matches(dto.confidential_gas, initial_gas);
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_accepts_vendor_json_content_type() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let body_bytes = configuration_update_with_logger_level_body("DEBUG");
    let req = signed_post_configuration(
        &harness,
        body_bytes.clone(),
        &body_bytes,
        "application/merge-patch+json",
    );
    let resp = harness.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let resp = signed_get_configuration(&harness).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = collect_body(resp).await;
    let dto: Configuration = norito::json::from_slice(&body).unwrap();
    assert_eq!(dto.logger.level, iroha_data_model::Level::DEBUG);
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_accepts_json_update_without_content_type() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let body_bytes = configuration_update_with_logger_level_body("DEBUG");
    let req = fixtures::operator_signed_request(
        &harness.cfg.common.key_pair,
        Request::builder()
            .method("POST")
            .uri(route_catalog::core::CONFIGURATION_GET.path())
            .body(Body::from(body_bytes.clone()))
            .unwrap(),
        &body_bytes,
    );
    let resp = harness.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let resp = signed_get_configuration(&harness).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = collect_body(resp).await;
    let dto: Configuration = norito::json::from_slice(&body).unwrap();
    assert_eq!(dto.logger.level, iroha_data_model::Level::DEBUG);
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_rejects_post_body_tampering() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let signed = configuration_update_with_logger_level_body("INFO");
    let tampered = configuration_update_with_logger_level_body("DEBUG");
    let req = signed_post_configuration(&harness, tampered, &signed, "application/json");
    let resp = harness.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = collect_body(resp).await;
    let v: norito::json::Value = norito::json::from_slice(&body).unwrap();
    assert_eq!(
        v.get("code").and_then(norito::json::Value::as_str),
        Some("operator_signature_bad")
    );
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_rejects_signed_non_json_content_type() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let harness = torii_test_harness(cfg);
    let body_bytes = configuration_update_with_logger_level_body("INFO");
    let req = signed_post_configuration(&harness, body_bytes.clone(), &body_bytes, "text/plain");
    let resp = harness.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_rejects_update_without_required_logger() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let initial_gas = protocol_default_gas();
    let harness = torii_test_harness(cfg);
    let body_bytes = configuration_update_without_logger_body();
    let req = signed_post_configuration(
        &harness,
        body_bytes.clone(),
        &body_bytes,
        "application/json",
    );
    let resp = harness.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = signed_get_configuration(&harness).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = collect_body(resp).await;
    let dto: Configuration = norito::json::from_slice(&body).unwrap();
    assert_confidential_gas_matches(dto.confidential_gas, initial_gas);
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_rejects_invalid_logger_level_and_preserves_gas() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let initial_gas = protocol_default_gas();
    let harness = torii_test_harness(cfg);
    let body_bytes = configuration_update_with_logger_level_body("VERBOSE");
    let req = signed_post_configuration(
        &harness,
        body_bytes.clone(),
        &body_bytes,
        "application/json",
    );
    let resp = harness.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = signed_get_configuration(&harness).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = collect_body(resp).await;
    let dto: Configuration = norito::json::from_slice(&body).unwrap();
    assert_confidential_gas_matches(dto.confidential_gas, initial_gas);
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_rejects_incomplete_confidential_gas_and_preserves_state() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let initial_gas = protocol_default_gas();
    let harness = torii_test_harness(cfg);
    let body_bytes = configuration_update_missing_per_commitment_body(ConfidentialGas {
        proof_base: 31,
        per_public_input: 32,
        per_proof_byte: 33,
        per_nullifier: 34,
        per_commitment: 35,
    });
    let req = signed_post_configuration(
        &harness,
        body_bytes.clone(),
        &body_bytes,
        "application/json",
    );
    let resp = harness.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = signed_get_configuration(&harness).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = collect_body(resp).await;
    let dto: Configuration = norito::json::from_slice(&body).unwrap();
    assert_confidential_gas_matches(dto.confidential_gas, initial_gas);
    harness.shutdown().await;
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn configuration_endpoint_rejects_malformed_json_update() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let initial_gas = protocol_default_gas();
    let harness = torii_test_harness(cfg);
    let body_bytes = b"{".to_vec();
    let req = signed_post_configuration(
        &harness,
        body_bytes.clone(),
        &body_bytes,
        "application/json",
    );
    let resp = harness.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = signed_get_configuration(&harness).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = collect_body(resp).await;
    let dto: Configuration = norito::json::from_slice(&body).unwrap();
    assert_confidential_gas_matches(dto.confidential_gas, initial_gas);
    harness.shutdown().await;
}

#[path = "../src/build_identity_test_fixture.rs"]
mod build_identity_test_fixture;
