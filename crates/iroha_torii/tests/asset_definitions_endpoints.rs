//! Smoke tests for Torii asset definitions endpoints.
#![cfg(feature = "app_api")]
use axum::extract::connect_info::ConnectInfo;
use axum::http::Request;
use http::StatusCode;
use http_body_util::BodyExt as _;
use iroha_core::{
    kiso::KisoHandle,
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::Registrable as _;
use iroha_data_model::isi::SetAssetDefinitionAlias;
use iroha_data_model::prelude as dm;
use iroha_model_base::domain::DomainId;
use iroha_torii::Torii;
use std::num::NonZeroU64;
use std::sync::Arc;
use tower::ServiceExt as _;
fn checked_asset_definition_ed25519_key_fixture() -> KeyPair {
    KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
        .expect("generate checked asset-definition Ed25519 fixture keypair")
}
#[test]
fn asset_definition_authority_fixture_uses_checked_ed25519_key_generation() {
    let key_pair = checked_asset_definition_ed25519_key_fixture();
    let algorithm = key_pair
        .public_key()
        .try_algorithm()
        .expect("fixture asset-definition public key has a valid algorithm");
    assert_eq!(algorithm, Algorithm::Ed25519);
}
fn seeded_state() -> (Arc<State>, dm::AssetDefinitionId, dm::AssetDefinitionId) {
    let authority = dm::AccountId::new(
        checked_asset_definition_ed25519_key_fixture()
            .public_key()
            .clone(),
    );
    let domain_id: iroha_model_base::domain::DomainId =
        DomainId::try_new("wonderland", "universal").expect("valid domain");
    let domain = dm::Domain::new(domain_id.clone()).build(&authority);
    let account = dm::Account::new(authority.clone()).build(&authority);
    let cbdc_id = dm::AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("domain id"),
        "cbdc".parse().expect("asset name"),
    );
    let cbdc = dm::AssetDefinition::numeric(
        cbdc_id.clone(),
        "CBDC".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority);
    let usd_id = dm::AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("domain id"),
        "usd".parse().expect("asset name"),
    );
    let usd = dm::AssetDefinition::numeric(
        usd_id.clone(),
        "USD".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority);
    let state = Arc::new(State::new_for_testing(
        World::with([domain], [account], [cbdc, usd]),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    ));
    let header = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(1).expect("non-zero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut tx = block.transaction();
    SetAssetDefinitionAlias::bind(
        cbdc_id.clone(),
        "cbdc#centralbank".parse().expect("asset alias"),
        None,
    )
    .execute(&authority, &mut tx)
    .expect("bind permanent asset alias");
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit permanent asset alias");
    (state, cbdc_id, usd_id)
}
fn build_app(state: Arc<State>) -> iroha_torii::TestApiRouterRuntime {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let (kiso, _child) = KisoHandle::start(cfg.clone());
    let kura = Kura::blank_kura_for_testing();
    let queue_cfg = iroha_config::parameters::actual::Queue::default();
    let events_sender: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue = Arc::new(iroha_core::queue::Queue::from_config(
        queue_cfg,
        events_sender,
    ));
    let (peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let _ = peers_tx;
    Torii::new_with_handle(
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
    .expect("valid Torii asset-definition fixture")
    .api_router_for_tests()
    .expect("test Torii router initializes")
}
fn loopback_connect_info() -> ConnectInfo<std::net::SocketAddr> {
    ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
}
fn commit_alias_lease(
    state: &Arc<State>,
    authority: &dm::AccountId,
    definition_id: &dm::AssetDefinitionId,
    alias: &str,
    lease_expiry_ms: u64,
    height: u64,
    creation_time_ms: u64,
) {
    let header = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(height).expect("non-zero height"),
        None,
        None,
        creation_time_ms,
        0,
    );
    let mut block = state.block(header);
    let mut tx = block.transaction();
    SetAssetDefinitionAlias::bind(
        definition_id.clone(),
        alias.parse().expect("valid asset alias"),
        Some(lease_expiry_ms),
    )
    .execute(authority, &mut tx)
    .expect("bind leased alias");
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit alias lease");
}
#[tokio::test]
async fn asset_definitions_endpoints_return_name_and_alias() {
    let (state, cbdc_id, _) = seeded_state();
    let runtime = build_app(state);
    let app = runtime.router();
    // GET /v1/assets/definitions
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/assets/definitions?offset=0")
                .extension(loopback_connect_info())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        resp.status(),
        StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
    ));
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let doc: norito::json::Value = norito::json::from_slice(&body).expect("valid json");
    let items = doc["items"].as_array().expect("items");
    assert_eq!(doc["total"].as_u64(), Some(2));
    assert!(items.iter().any(|item| {
        item["name"].as_str() == Some("CBDC")
            && item["alias"].as_str() == Some("cbdc#centralbank")
            && item["alias_binding"]["status"].as_str() == Some("permanent")
    }));
    assert!(items.iter().any(|item| {
        item["name"].as_str() == Some("USD")
            && item["alias"].is_null()
            && item["alias_binding"].is_null()
    }));
    // GET /v1/assets/definitions/{asset}
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/assets/definitions/{cbdc_id}"))
                .extension(loopback_connect_info())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        resp.status(),
        StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
    ));
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let doc: norito::json::Value = norito::json::from_slice(&body).expect("valid json");
    let cbdc_literal = cbdc_id.to_string();
    assert_eq!(doc["id"].as_str(), Some(cbdc_literal.as_str()));
    assert_eq!(doc["name"].as_str(), Some("CBDC"));
    assert_eq!(doc["alias"].as_str(), Some("cbdc#centralbank"));
    assert_eq!(
        doc["alias_binding"]["alias"].as_str(),
        Some("cbdc#centralbank")
    );
    assert_eq!(doc["alias_binding"]["status"].as_str(), Some("permanent"));
    // POST /v1/assets/definitions/query
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/assets/definitions/query")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .extension(loopback_connect_info())
                .body(axum::body::Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        resp.status(),
        StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
    ));
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let doc: norito::json::Value = norito::json::from_slice(&body).expect("valid json");
    let items = doc["items"].as_array().expect("items");
    assert_eq!(doc["total"].as_u64(), Some(2));
    assert!(items.iter().any(|item| {
        item["name"].as_str() == Some("CBDC")
            && item["alias"].as_str() == Some("cbdc#centralbank")
            && item["alias_binding"]["status"].as_str() == Some("permanent")
    }));
    assert!(items.iter().any(|item| {
        item["name"].as_str() == Some("USD")
            && item["alias"].is_null()
            && item["alias_binding"].is_null()
    }));
    runtime.shutdown().await;
}
#[tokio::test]
async fn asset_definitions_query_supports_alias_binding_sort() {
    let authority = dm::AccountId::new(
        checked_asset_definition_ed25519_key_fixture()
            .public_key()
            .clone(),
    );
    let domain_id: iroha_model_base::domain::DomainId =
        DomainId::try_new("wonderland", "universal").expect("valid domain");
    let domain = dm::Domain::new(domain_id.clone()).build(&authority);
    let account = dm::Account::new(authority.clone()).build(&authority);
    let cbdc_id = dm::AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "cbdc".parse().expect("asset name"),
    );
    let cbdc = dm::AssetDefinition::numeric(
        cbdc_id.clone(),
        "CBDC".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority);
    let usd_id = dm::AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "usd".parse().expect("asset name"),
    );
    let usd = dm::AssetDefinition::numeric(
        usd_id.clone(),
        "usd".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority);
    let state = Arc::new(State::new_for_testing(
        World::with([domain], [account], [cbdc, usd]),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    ));
    let header = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(1).expect("non-zero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut tx = block.transaction();
    SetAssetDefinitionAlias::bind(
        cbdc_id.clone(),
        "cbdc#centralbank".parse().expect("asset alias"),
        None,
    )
    .execute(&authority, &mut tx)
    .expect("bind permanent asset alias");
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit permanent asset alias");
    commit_alias_lease(&state, &authority, &usd_id, "usd#lease", 5_000, 2, 1_000);
    let runtime = build_app(state);
    let app = runtime.router();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/assets/definitions/query")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .extension(loopback_connect_info())
                .body(axum::body::Body::from(
                    r#"{
                        "sort":[{"key":"alias_binding.bound_at_ms","order":"desc"}]
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    if status != StatusCode::OK {
        panic!(
            "unexpected status {status}: {}",
            String::from_utf8_lossy(body.as_ref())
        );
    }
    let doc: norito::json::Value = norito::json::from_slice(&body).expect("valid json");
    let items = doc["items"].as_array().expect("items");
    let usd_literal = usd_id.to_string();
    assert_eq!(
        items.first().and_then(|item| item["id"].as_str()),
        Some(usd_literal.as_str())
    );
    assert_eq!(
        items
            .first()
            .and_then(|item| item["alias_binding"]["status"].as_str()),
        Some("leased_active")
    );
    runtime.shutdown().await;
}

#[path = "../src/build_identity_test_fixture.rs"]
mod build_identity_test_fixture;
