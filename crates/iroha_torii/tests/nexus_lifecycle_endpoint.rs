#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Router-level regressions for the read-only Nexus lifecycle status surface.
#![cfg(feature = "app_api")]
use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use http_body_util::BodyExt as _;
use iroha_config::parameters::actual::Queue as QueueConfig;
use iroha_core::{
    EventsSender,
    query::store::LiveQueryStore,
    queue::{ConfigLaneRouter, Queue, QueueLimits},
    state::State,
};
use iroha_data_model::nexus::LaneLifecycleStatusV1;
use iroha_model_base::topology::LaneId;
use iroha_torii_shared::route_catalog::core::NEXUS_LIFECYCLE_GET;
use std::{collections::BTreeSet, sync::Arc};
#[path = "fixtures.rs"]
mod fixtures;
struct NexusHarness {
    app: iroha_torii::TestApiRouterRuntime,
    queue: Arc<Queue>,
    state: Arc<State>,
}
impl NexusHarness {
    async fn shutdown(self) {
        self.app.shutdown().await;
    }
}
fn build_app() -> NexusHarness {
    build_app_with_api_token(None)
}
fn build_app_with_api_token(api_token: Option<&str>) -> NexusHarness {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    if let Some(api_token) = api_token {
        cfg.torii.require_api_token = true;
        cfg.torii.api_tokens = vec![api_token.to_owned()].into();
    }
    let world = iroha_core::prelude::World::with(
        Vec::new(),
        Vec::new(),
        Vec::<iroha_data_model::asset::AssetDefinition>::new(),
    );
    // Core and Torii must share the fixture's explicit genesis-derived identity.
    let network_id = iroha_data_model::NetworkId::from_genesis_hash(cfg.genesis.expected_hash);
    let (mut state, kura) = State::new_with_chain_and_network_id_and_pre_genesis_nexus_for_testing(
        world,
        cfg.nexus.clone(),
        LiveQueryStore::start_test(),
        cfg.common.chain.clone(),
        network_id,
    );
    state
        .set_nexus(cfg.nexus.clone())
        .expect("restore the fixture's exact Nexus runtime configuration");
    let state = Arc::new(state);
    let events_sender: EventsSender = tokio::sync::broadcast::channel(64).0;
    let router = Arc::new(ConfigLaneRouter::new(
        cfg.nexus.routing_policy.clone(),
        cfg.nexus.dataspace_catalog.clone(),
        cfg.nexus.lane_catalog.clone(),
    ));
    let queue = Arc::new(Queue::from_config_with_router_limits_and_catalogs(
        QueueConfig::default(),
        events_sender.clone(),
        router,
        QueueLimits::from_nexus(&cfg.nexus),
        &Arc::new(cfg.nexus.lane_catalog.clone()),
        &Arc::new(cfg.nexus.dataspace_catalog.clone()),
        None,
    ));
    {
        let view = state.view();
        queue.reconfigure_nexus(&state.nexus_snapshot(), &view, None);
    }
    let torii =
        fixtures::ToriiHarness::new_without_telemetry(&cfg, &kura, &state, &queue, events_sender);
    NexusHarness {
        app: torii.router(),
        queue,
        state,
    }
}
async fn response_bytes(response: Response) -> Vec<u8> {
    response
        .into_body()
        .collect()
        .await
        .expect("collect response body")
        .to_bytes()
        .to_vec()
}
#[tokio::test]
async fn lifecycle_get_returns_valid_exact_json_status() {
    let harness = build_app();
    let response = fixtures::request(
        &harness.app,
        Request::builder()
            .uri(NEXUS_LIFECYCLE_GET.path())
            .header("accept", "application/json")
            .body(Body::empty())
            .expect("request"),
    )
    .await
    .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/json; charset=utf-8")
    );
    let body = response_bytes(response).await;
    let json = std::str::from_utf8(&body).expect("status JSON is UTF-8");
    let value: norito::json::Value =
        norito::json::from_slice(&body).expect("decode lifecycle status JSON value");
    let fields = value
        .as_object()
        .expect("lifecycle status is a JSON object")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_fields = [
        "catalog_hash",
        "incarnation_root",
        "incarnations",
        "lane_count",
        "lanes",
        "runtime_catalog_hash",
        "version",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    assert_eq!(
        fields, expected_fields,
        "endpoint must emit the exact current lifecycle status layout"
    );
    assert!(!json.contains("nexus_enabled"));
    let status: LaneLifecycleStatusV1 =
        norito::json::from_slice(&body).expect("decode status JSON");
    assert_eq!(status.runtime_catalog_hash, None);
    assert!(json.contains("\"runtime_catalog_hash\":null"));
    assert_eq!(
        status.validate().expect("validate status"),
        harness.state.nexus_snapshot().lane_catalog
    );
    harness.shutdown().await;
}
#[tokio::test]
async fn lifecycle_get_returns_valid_exact_norito_status() {
    let harness = build_app();
    let response = fixtures::request(
        &harness.app,
        Request::builder()
            .uri(NEXUS_LIFECYCLE_GET.path())
            .header("accept", "application/x-norito")
            .body(Body::empty())
            .expect("request"),
    )
    .await
    .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let status =
        norito::decode_from_bytes::<LaneLifecycleStatusV1>(&response_bytes(response).await)
            .expect("decode status Norito");
    assert_eq!(status.runtime_catalog_hash, None);
    assert_eq!(
        status.validate().expect("validate status"),
        harness.state.nexus_snapshot().lane_catalog
    );
    harness.shutdown().await;
}
#[tokio::test]
async fn lifecycle_get_returns_exact_present_runtime_root_in_both_formats() {
    use iroha_crypto::Hash;
    use iroha_data_model::{nexus::NexusRuntimeCatalogV1, parameter::Parameter};
    let harness = build_app();
    let runtime = NexusRuntimeCatalogV1 {
        version: NexusRuntimeCatalogV1::VERSION,
        baseline_dataspaces_hash: iroha_data_model::nexus::dataspace_catalog_hash(
            &harness.state.nexus_snapshot().configured_dataspace_catalog,
        ),
        baseline_manifests_hash: Hash::prehashed(
            harness
                .state
                .lane_manifests
                .read()
                .baseline_consensus_policy_digest(),
        ),
        dataspaces: Vec::new(),
        manifests: Vec::new(),
    };
    let expected = runtime.canonical_hash().unwrap();
    let mut world = harness.state.world.block();
    world
        .parameters
        .get_mut()
        .set_parameter(Parameter::Custom(runtime.into_custom_parameter().unwrap()))
        .expect("install the committed runtime catalog fixture");
    world.commit();
    for accept in ["application/json", "application/x-norito"] {
        let response = fixtures::request(
            &harness.app,
            Request::builder()
                .uri(NEXUS_LIFECYCLE_GET.path())
                .header("accept", accept)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response_bytes(response).await;
        let status: LaneLifecycleStatusV1 = if accept == "application/json" {
            norito::json::from_slice(&bytes).unwrap()
        } else {
            norito::decode_from_bytes(&bytes).unwrap()
        };
        status.validate().unwrap();
        assert_eq!(status.runtime_catalog_hash, Some(expected));
    }
    harness.shutdown().await;
}
#[tokio::test]
async fn lifecycle_get_honors_api_token_access_policy() {
    const API_TOKEN: &str = "lifecycle-status-token-00000000000";
    let harness = build_app_with_api_token(Some(API_TOKEN));
    for supplied_token in [None, Some("wrong-token")] {
        let mut request = Request::builder()
            .uri(NEXUS_LIFECYCLE_GET.path())
            .header("accept", "application/json");
        if let Some(token) = supplied_token {
            request = request.header("x-api-token", token);
        }
        let response =
            fixtures::request(&harness.app, request.body(Body::empty()).expect("request"))
                .await
                .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = fixtures::request(
        &harness.app,
        Request::builder()
            .uri(NEXUS_LIFECYCLE_GET.path())
            .header("accept", "application/json")
            .header("x-api-token", API_TOKEN)
            .body(Body::empty())
            .expect("request"),
    )
    .await
    .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    harness.shutdown().await;
}
#[tokio::test]
async fn lifecycle_post_and_normalization_variants_are_unregistered_without_mutation() {
    let harness = build_app();
    let lane = LaneId::new(1);
    let before_catalog = harness.state.nexus_snapshot().lane_catalog;
    let before_limits = harness.queue.queue_limits().for_lane(lane);
    let body = r#"{"additions":[{"id":1,"dataspace_id":0,"alias":"forbidden-local","description":null,"visibility":"public","lane_type":null,"governance":null,"settlement":null,"storage":"full_replica","proof_scheme":"merkle_sha256","metadata":{}}],"retire":[]}"#;
    for (method, path, expected_status) in [
        (
            "POST",
            NEXUS_LIFECYCLE_GET.path(),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            "HEAD",
            NEXUS_LIFECYCLE_GET.path(),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        ("POST", "/v1/nexus/lifecycle/", StatusCode::NOT_FOUND),
        ("POST", "/v1/Nexus/lifecycle", StatusCode::NOT_FOUND),
        (
            "POST",
            "/v1/nexus/lifecycle/arbitrary",
            StatusCode::NOT_FOUND,
        ),
        ("POST", "/v1/nexus//lifecycle", StatusCode::BAD_REQUEST),
        (
            "POST",
            "/v1/nexus/lifecycle%2Farbitrary",
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let response = fixtures::request(
            &harness.app,
            Request::builder()
                .method(method)
                .uri(path)
                .header("accept", "application/json")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("response");
        assert_eq!(response.status(), expected_status, "{method} {path}");
        if path == NEXUS_LIFECYCLE_GET.path() {
            let allow = response
                .headers()
                .get("allow")
                .and_then(|value| value.to_str().ok())
                .expect("registered route must advertise its exact catalog method");
            assert_eq!(allow, "GET");
        }
        assert_eq!(harness.state.nexus_snapshot().lane_catalog, before_catalog);
        assert_eq!(harness.queue.queue_limits().for_lane(lane), before_limits);
    }
    harness.shutdown().await;
}
