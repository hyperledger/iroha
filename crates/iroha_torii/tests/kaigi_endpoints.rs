//! Telemetry integration tests covering Kaigi relay endpoints.
#![cfg(feature = "telemetry")]
use axum::{
    body::Body,
    http::{HeaderValue, Request, StatusCode, header::CONTENT_TYPE},
    response::Response,
};
use http_body_util::BodyExt;
use iroha_core::{kiso::KisoHandle, kura::Kura, query::store::LiveQueryStore, state::State};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    NetworkId, Registrable,
    account::{
        Account, AccountAddress,
        rekey::{AccountAlias, AccountAliasDomain, AccountRekeyRecord},
    },
    domain::Domain,
    kaigi::{
        KaigiId, KaigiRecord, KaigiRelayFeedback, KaigiRelayHealthStatus, KaigiRelayRegistration,
        NewKaigi, kaigi_metadata_key, kaigi_relay_feedback_key, kaigi_relay_metadata_key,
    },
    prelude::AccountId,
    sns::{NameControllerV1, NameRecordV1},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;
use iroha_primitives::{json::Json, time::TimeSource};
use std::{collections::BTreeSet, str::FromStr, sync::Arc};
use tower::ServiceExt;
#[path = "fixtures.rs"]
mod fixtures;
const NORITO_MIME_TYPE: &str = "application/x-norito";
const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";
fn checked_kaigi_ed25519_key_fixture() -> KeyPair {
    KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
        .expect("generate checked Kaigi Ed25519 fixture keypair")
}
fn seed_relay_primary_alias(
    world: &mut iroha_core::prelude::World,
    domain_id: &DomainId,
    relay_id: &AccountId,
) {
    let alias = AccountAlias::new(
        Name::from_str("relay").expect("relay alias label"),
        Some(AccountAliasDomain::new(domain_id.name().clone())),
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    );
    let catalog = iroha_data_model::nexus::DataSpaceCatalog::default();
    let selector = iroha_core::sns::selector_for_account_alias(&alias, &catalog)
        .expect("relay alias selector");
    let address = AccountAddress::from_account_id(relay_id).expect("relay account address");
    let lease = NameRecordV1::new(
        selector.clone(),
        relay_id.clone(),
        vec![NameControllerV1::account(&address)],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        Metadata::default(),
    );
    let mut block = world.block();
    let mut transaction = block
        .transaction_without_telemetry(iroha_config::parameters::actual::LaneConfig::default(), 0);
    transaction
        .account_mut(relay_id)
        .expect("relay account")
        .set_label(Some(alias.clone()));
    transaction
        .account_aliases_mut_for_testing()
        .insert(alias.clone(), relay_id.clone());
    transaction
        .account_aliases_by_account_mut_for_testing()
        .insert(relay_id.clone(), BTreeSet::from([alias.clone()]));
    transaction
        .replace_account_rekey_record_for_testing(AccountRekeyRecord::new(alias, relay_id.clone()));
    transaction.smart_contract_state_mut_for_testing().insert(
        iroha_core::sns::record_storage_key(&selector),
        norito::codec::Encode::encode(&lease),
    );
    transaction.apply();
    block.commit();
}
#[test]
fn kaigi_ed25519_fixture_uses_checked_key_generation() {
    let key_pair = checked_kaigi_ed25519_key_fixture();
    let algorithm = key_pair
        .public_key()
        .try_algorithm()
        .expect("fixture Kaigi public key has a valid algorithm");
    assert_eq!(algorithm, Algorithm::Ed25519);
}
fn build_app() -> (
    iroha_torii::TestApiRouterRuntime,
    AccountId,
    AccountId,
    KeyPair,
    iroha_torii::test_utils::TestDataDirGuard,
) {
    let (app, relay, owner, operator, data_dir, _network, _owner_key) =
        build_app_with_stream_signer();
    (app, relay, owner, operator, data_dir)
}
fn build_app_with_stream_signer() -> (
    iroha_torii::TestApiRouterRuntime,
    AccountId,
    AccountId,
    KeyPair,
    iroha_torii::test_utils::TestDataDirGuard,
    NetworkId,
    KeyPair,
) {
    let data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let chain_id = cfg.common.chain.clone();
    let network_id = NetworkId::from_genesis_hash(cfg.genesis.expected_hash);
    let (kiso, _child) = KisoHandle::start(cfg.clone());
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let local_peer_id = PeerId::new(cfg.common.key_pair.public_key().clone());
    // Prepare domain, accounts, and metadata.
    let domain_id: DomainId = DomainId::try_new("kaigi", "universal").expect("domain id");
    let owner_kp = checked_kaigi_ed25519_key_fixture();
    let owner_id = AccountId::new(owner_kp.public_key().clone());
    let owner = Account::new(owner_id.clone()).build(&owner_id);
    let relay_kp = checked_kaigi_ed25519_key_fixture();
    let relay_id = AccountId::new(relay_kp.public_key().clone());
    let relay = Account::new(relay_id.clone()).build(&owner_id);
    let registration = KaigiRelayRegistration {
        relay_id: relay_id.clone(),
        hpke_public_key: vec![0xAA, 0xBB],
        bandwidth_class: 5,
    };
    let feedback = KaigiRelayFeedback {
        relay_id: relay_id.clone(),
        call: KaigiId::new(
            domain_id.clone(),
            Name::from_str("demo").expect("call name"),
        ),
        reported_by: owner_id.clone(),
        status: KaigiRelayHealthStatus::Healthy,
        reported_at_ms: 1_650_000,
        notes: Some("operational".to_string()),
    };
    let mut metadata = Metadata::default();
    let call = NewKaigi::with_defaults(feedback.call.clone(), owner_id.clone());
    metadata.insert(
        kaigi_metadata_key(&call.id.call_name).expect("call metadata key"),
        Json::try_new(KaigiRecord::from_new(&call, 0)).expect("call JSON"),
    );
    metadata.insert(
        kaigi_relay_metadata_key(&relay_id).expect("metadata key"),
        Json::try_new(registration).expect("registration json"),
    );
    metadata.insert(
        kaigi_relay_feedback_key(&relay_id).expect("feedback key"),
        Json::try_new(feedback).expect("feedback json"),
    );
    let domain = Domain::new(domain_id.clone())
        .with_metadata(metadata)
        .build(&owner_id);
    let mut world = iroha_core::prelude::World::with(
        [domain],
        [owner, relay],
        Vec::<iroha_data_model::asset::AssetDefinition>::new(),
    );
    seed_relay_primary_alias(&mut world, &domain_id, &relay_id);
    fixtures::seed_peer(&mut world, local_peer_id.clone());
    let state = Arc::new(State::new_with_chain_and_network_id_for_testing(
        world,
        kura.clone(),
        query,
        chain_id.clone(),
        network_id,
    ));
    let queue_cfg = iroha_config::parameters::actual::Queue::default();
    let events_sender: iroha_core::EventsSender = tokio::sync::broadcast::channel(64).0;
    let queue = Arc::new(iroha_core::queue::Queue::from_config(
        queue_cfg,
        events_sender,
    ));
    let (peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let _ = peers_tx;
    let metrics = fixtures::shared_metrics();
    let domain_label = domain_id.to_string();
    metrics
        .kaigi_relay_registered_total
        .with_label_values(&[domain_label.as_str()])
        .inc();
    metrics
        .kaigi_relay_health_reports_total
        .with_label_values(&[domain_label.as_str(), "healthy"])
        .inc();
    metrics
        .kaigi_relay_health_reports_by_domain_total
        .with_label_values(&[domain_label.as_str()])
        .inc();
    metrics
        .kaigi_relay_health_state
        .with_label_values(&[domain_label.as_str(), relay_id.to_string().as_str()])
        .set(KaigiRelayHealthStatus::Healthy.metric_value());
    let (_time_handle, time_source) = TimeSource::new_mock(core::time::Duration::from_secs(0));
    let telemetry_handle = iroha_core::telemetry::start(
        metrics,
        state.clone(),
        kura.clone(),
        queue.clone(),
        peers_rx.clone(),
        local_peer_id,
        time_source,
        false,
    )
    .expect("test telemetry resource registration")
    .0;
    let operator_key_pair = cfg.common.key_pair.clone();
    let da_receipt_signer = operator_key_pair.clone();
    let torii = iroha_torii::Torii::new_with_handle(
        chain_id,
        network_id,
        kiso,
        cfg.torii.clone(),
        queue,
        tokio::sync::broadcast::channel(64).0,
        LiveQueryStore::start_test(),
        kura,
        state,
        da_receipt_signer,
        iroha_torii::OnlinePeersProvider::new(peers_rx),
        None,
        iroha_torii::ToriiRuntimeDeps::new(
            build_identity_test_fixture::build_identity(),
            iroha_torii::MaybeTelemetry::from_profile(
                Some(telemetry_handle),
                iroha_config::parameters::actual::TelemetryProfile::Operator,
            ),
        ),
    )
    .expect("valid Torii Kaigi fixture");
    (
        torii
            .api_router_for_tests()
            .expect("test Torii router initializes"),
        relay_id,
        owner_id,
        operator_key_pair,
        data_dir,
        network_id,
        owner_kp,
    )
}
async fn get_kaigi(
    app: &axum::Router,
    operator_key_pair: &KeyPair,
    uri: impl Into<String>,
    accept: Option<&str>,
) -> Response {
    let mut builder = Request::builder().uri(uri.into());
    if let Some(accept) = accept {
        builder = builder.header("Accept", accept);
    }
    let request = fixtures::operator_signed_request(
        operator_key_pair,
        builder.body(Body::empty()).unwrap(),
        &[],
    );
    app.clone().oneshot(request).await.unwrap()
}
async fn json_body(resp: Response) -> norito::json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    norito::json::from_slice(&bytes).unwrap()
}
async fn norito_json_body(resp: Response) -> norito::json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let payload: String = norito::decode_from_bytes(&bytes).unwrap();
    norito::json::from_str(&payload).unwrap()
}
async fn text_body(resp: Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}
#[tokio::test]
async fn kaigi_endpoints_report_metadata() {
    let (app, relay_account, _owner_account, operator_key_pair, _data_dir) = build_app();
    let relay_literal = relay_account.to_string();
    // Summary endpoint
    let resp = get_kaigi(&app, &operator_key_pair, "/v1/kaigi/relays", None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let summary = norito_json_body(resp).await;
    assert_eq!(summary["total"].as_u64(), Some(1));
    assert_eq!(
        summary["items"][0]["relay_id"].as_str().unwrap(),
        relay_literal
    );
    assert_eq!(
        summary["items"][0]["hpke_fingerprint_hex"].as_str(),
        Some("b9a7b866cdb0df5d6eacf2c0f43ab30a7940cf259b1beaaa954bb79d89fab58f")
    );
    assert_eq!(summary["items"][0]["status"].as_str(), Some("healthy"));
    // Detail endpoint
    let detail_path = format!("/v1/kaigi/relays/{relay_literal}");
    let detail_resp = get_kaigi(&app, &operator_key_pair, detail_path, None).await;
    assert_eq!(detail_resp.status(), StatusCode::OK);
    let detail = norito_json_body(detail_resp).await;
    assert_eq!(
        detail["relay"]["hpke_fingerprint_hex"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(detail["relay"]["status"].as_str(), Some("healthy"));
    assert_eq!(detail["hpke_public_key_b64"].as_str().unwrap(), "qrs=");
    // Health snapshot
    let health_resp = get_kaigi(&app, &operator_key_pair, "/v1/kaigi/relays/health", None).await;
    assert_eq!(health_resp.status(), StatusCode::OK);
    let health = norito_json_body(health_resp).await;
    assert_eq!(health["healthy_total"].as_u64(), Some(1));
    assert!(!health["domains"].as_array().unwrap().is_empty());
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_endpoints_emit_i105_literals() {
    let (app, relay_account, owner_account, operator_key_pair, _data_dir) = build_app();
    let relay_literal = relay_account.to_string();
    let owner_literal = owner_account.to_string();
    let resp = get_kaigi(&app, &operator_key_pair, "/v1/kaigi/relays", None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let summary = norito_json_body(resp).await;
    assert_eq!(
        summary["items"][0]["relay_id"].as_str(),
        Some(relay_literal.as_str())
    );
    assert_eq!(summary["items"][0]["status"].as_str(), Some("healthy"));
    let detail_path = format!("/v1/kaigi/relays/{relay_literal}");
    let detail_resp = get_kaigi(&app, &operator_key_pair, detail_path, None).await;
    assert_eq!(detail_resp.status(), StatusCode::OK);
    let detail = norito_json_body(detail_resp).await;
    assert_eq!(
        detail["relay"]["relay_id"].as_str(),
        Some(relay_literal.as_str())
    );
    assert_eq!(detail["relay"]["status"].as_str(), Some("healthy"));
    assert_eq!(detail["reported_by"].as_str(), Some(owner_literal.as_str()));
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_endpoints_honor_json_accept_header() {
    let (app, relay_account, _owner_account, operator_key_pair, _data_dir) = build_app();
    let relay_literal = relay_account.to_string();
    let resp = get_kaigi(
        &app,
        &operator_key_pair,
        "/v1/kaigi/relays",
        Some("application/json"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static(JSON_CONTENT_TYPE))
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let summary: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    assert_eq!(
        summary["items"][0]["relay_id"].as_str(),
        Some(relay_literal.as_str())
    );
    assert_eq!(summary["items"][0]["status"].as_str(), Some("healthy"));
    let detail_path = format!("/v1/kaigi/relays/{relay_literal}");
    let detail_resp = get_kaigi(
        &app,
        &operator_key_pair,
        detail_path,
        Some("application/json"),
    )
    .await;
    assert_eq!(detail_resp.status(), StatusCode::OK);
    assert_eq!(
        detail_resp.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static(JSON_CONTENT_TYPE))
    );
    let detail_bytes = detail_resp.into_body().collect().await.unwrap().to_bytes();
    let detail: norito::json::Value = norito::json::from_slice(&detail_bytes).unwrap();
    assert_eq!(
        detail["relay"]["relay_id"].as_str(),
        Some(relay_literal.as_str())
    );
    let health_resp = get_kaigi(
        &app,
        &operator_key_pair,
        "/v1/kaigi/relays/health",
        Some("application/json"),
    )
    .await;
    assert_eq!(health_resp.status(), StatusCode::OK);
    assert_eq!(
        health_resp.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static(JSON_CONTENT_TYPE))
    );
    let health = json_body(health_resp).await;
    assert_eq!(health["healthy_total"].as_u64(), Some(1));
    assert!(!health["domains"].as_array().unwrap().is_empty());
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_endpoints_honor_norito_accept_header() {
    let (app, relay_account, _owner_account, operator_key_pair, _data_dir) = build_app();
    let relay_literal = relay_account.to_string();
    let resp = get_kaigi(
        &app,
        &operator_key_pair,
        "/v1/kaigi/relays",
        Some(NORITO_MIME_TYPE),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static(NORITO_MIME_TYPE))
    );
    let summary = norito_json_body(resp).await;
    assert_eq!(summary["total"].as_u64(), Some(1));
    assert_eq!(
        summary["items"][0]["relay_id"].as_str(),
        Some(relay_literal.as_str())
    );
    let detail_path = format!("/v1/kaigi/relays/{relay_literal}");
    let detail_resp = get_kaigi(
        &app,
        &operator_key_pair,
        detail_path,
        Some(NORITO_MIME_TYPE),
    )
    .await;
    assert_eq!(detail_resp.status(), StatusCode::OK);
    assert_eq!(
        detail_resp.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static(NORITO_MIME_TYPE))
    );
    let detail = norito_json_body(detail_resp).await;
    assert_eq!(
        detail["relay"]["relay_id"].as_str(),
        Some(relay_literal.as_str())
    );
    assert_eq!(detail["relay"]["status"].as_str(), Some("healthy"));
    assert_eq!(detail["hpke_public_key_b64"].as_str(), Some("qrs="));
    let health_resp = get_kaigi(
        &app,
        &operator_key_pair,
        "/v1/kaigi/relays/health",
        Some(NORITO_MIME_TYPE),
    )
    .await;
    assert_eq!(health_resp.status(), StatusCode::OK);
    assert_eq!(
        health_resp.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static(NORITO_MIME_TYPE))
    );
    let health = norito_json_body(health_resp).await;
    assert_eq!(health["healthy_total"].as_u64(), Some(1));
    assert!(health["reports_total"].as_u64().unwrap() >= 1);
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_endpoints_reject_unsupported_accept_header() {
    let (app, relay_account, _owner_account, operator_key_pair, _data_dir) = build_app();
    let detail_path = format!("/v1/kaigi/relays/{relay_account}");
    for uri in [
        "/v1/kaigi/relays".to_owned(),
        detail_path,
        "/v1/kaigi/relays/health".to_owned(),
    ] {
        let resp = get_kaigi(&app, &operator_key_pair, uri, Some("text/plain")).await;
        assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
        let body = text_body(resp).await;
        assert!(body.contains("unsupported Accept header"), "{body}");
    }
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_endpoints_reject_invalid_accept_quality() {
    let (app, _relay_account, _owner_account, operator_key_pair, _data_dir) = build_app();
    let resp = get_kaigi(
        &app,
        &operator_key_pair,
        "/v1/kaigi/relays",
        Some("application/json;q=bogus"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
    let body = text_body(resp).await;
    assert!(body.contains("invalid q-value in Accept header"), "{body}");
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_endpoints_reject_out_of_range_accept_quality() {
    let (app, _relay_account, _owner_account, operator_key_pair, _data_dir) = build_app();
    for accept in [
        "application/json;q=1.1",
        "application/json;q=-0.1",
        "application/json;q=NaN",
    ] {
        let resp = get_kaigi(&app, &operator_key_pair, "/v1/kaigi/relays", Some(accept)).await;
        assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE, "{accept}");
        let body = text_body(resp).await;
        assert!(
            body.contains("invalid q-value in Accept header"),
            "{accept}: {body}"
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_endpoints_reject_when_supported_media_types_have_zero_quality() {
    let (app, _relay_account, _owner_account, operator_key_pair, _data_dir) = build_app();
    let resp = get_kaigi(
        &app,
        &operator_key_pair,
        "/v1/kaigi/relays",
        Some("application/json;q=0, application/x-norito;q=0"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
    let body = text_body(resp).await;
    assert!(body.contains("unsupported Accept header"), "{body}");
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_endpoints_reject_retired_text_json_alias() {
    let (app, _relay_account, _owner_account, operator_key_pair, _data_dir) = build_app();
    let response = get_kaigi(
        &app,
        &operator_key_pair,
        "/v1/kaigi/relays",
        Some("text/json"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_endpoints_accept_json_compatible_media_ranges() {
    let (app, relay_account, _owner_account, operator_key_pair, _data_dir) = build_app();
    let relay_literal = relay_account.to_string();
    for accept in [
        "*/*",
        "application/*",
        "application/problem+json",
        "text/plain, , application/json",
    ] {
        let resp = get_kaigi(&app, &operator_key_pair, "/v1/kaigi/relays", Some(accept)).await;
        assert_eq!(resp.status(), StatusCode::OK, "{accept}");
        assert_eq!(
            resp.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static(JSON_CONTENT_TYPE)),
            "{accept}"
        );
        let summary = json_body(resp).await;
        assert_eq!(summary["total"].as_u64(), Some(1), "{accept}");
        assert_eq!(
            summary["items"][0]["relay_id"].as_str(),
            Some(relay_literal.as_str()),
            "{accept}"
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_endpoints_accept_case_insensitive_media_types_with_parameters() {
    let (app, relay_account, _owner_account, operator_key_pair, _data_dir) = build_app();
    let relay_literal = relay_account.to_string();
    let json_resp = get_kaigi(
        &app,
        &operator_key_pair,
        "/v1/kaigi/relays",
        Some("Application/JSON; Charset=UTF-8"),
    )
    .await;
    assert_eq!(json_resp.status(), StatusCode::OK);
    assert_eq!(
        json_resp.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static(JSON_CONTENT_TYPE))
    );
    let summary = json_body(json_resp).await;
    assert_eq!(
        summary["items"][0]["relay_id"].as_str(),
        Some(relay_literal.as_str())
    );
    let norito_resp = get_kaigi(
        &app,
        &operator_key_pair,
        "/v1/kaigi/relays",
        Some("Application/X-Norito; Version=1"),
    )
    .await;
    assert_eq!(norito_resp.status(), StatusCode::OK);
    assert_eq!(
        norito_resp.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static(NORITO_MIME_TYPE))
    );
    let summary = norito_json_body(norito_resp).await;
    assert_eq!(
        summary["items"][0]["relay_id"].as_str(),
        Some(relay_literal.as_str())
    );
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_endpoints_select_response_format_by_accept_quality() {
    let (app, relay_account, _owner_account, operator_key_pair, _data_dir) = build_app();
    let relay_literal = relay_account.to_string();
    let json_preferred = get_kaigi(
        &app,
        &operator_key_pair,
        "/v1/kaigi/relays",
        Some("application/x-norito;q=0.4, application/json;q=0.8"),
    )
    .await;
    assert_eq!(json_preferred.status(), StatusCode::OK);
    assert_eq!(
        json_preferred.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static(JSON_CONTENT_TYPE))
    );
    let summary = json_body(json_preferred).await;
    assert_eq!(
        summary["items"][0]["relay_id"].as_str(),
        Some(relay_literal.as_str())
    );
    let tie_prefers_norito = get_kaigi(
        &app,
        &operator_key_pair,
        "/v1/kaigi/relays",
        Some("application/json;q=0.7, application/x-norito;q=0.7"),
    )
    .await;
    assert_eq!(tie_prefers_norito.status(), StatusCode::OK);
    assert_eq!(
        tie_prefers_norito.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static(NORITO_MIME_TYPE))
    );
    let summary = norito_json_body(tie_prefers_norito).await;
    assert_eq!(
        summary["items"][0]["relay_id"].as_str(),
        Some(relay_literal.as_str())
    );
    let zero_quality_norito = get_kaigi(
        &app,
        &operator_key_pair,
        "/v1/kaigi/relays",
        Some("application/x-norito;q=0, application/json;q=0.6"),
    )
    .await;
    assert_eq!(zero_quality_norito.status(), StatusCode::OK);
    assert_eq!(
        zero_quality_norito.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static(JSON_CONTENT_TYPE))
    );
    let summary = json_body(zero_quality_norito).await;
    assert_eq!(
        summary["items"][0]["relay_id"].as_str(),
        Some(relay_literal.as_str())
    );
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_relay_detail_rejects_invalid_relay_path_literal() {
    let (app, _relay_account, _owner_account, operator_key_pair, _data_dir) = build_app();
    let resp = get_kaigi(
        &app,
        &operator_key_pair,
        "/v1/kaigi/relays/not-an-account",
        Some("application/json"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static(JSON_CONTENT_TYPE))
    );
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_relay_detail_returns_not_found_for_unregistered_relay() {
    let (app, _relay_account, _owner_account, operator_key_pair, _data_dir) = build_app();
    let unregistered = AccountId::new(checked_kaigi_ed25519_key_fixture().public_key().clone());
    let resp = get_kaigi(
        &app,
        &operator_key_pair,
        format!("/v1/kaigi/relays/{unregistered}"),
        Some("application/json"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        resp.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static(JSON_CONTENT_TYPE))
    );
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_sse_accepts_i105_relay_filter() {
    let (app, relay_account, owner_account, _operator, _data_dir, network_id, owner_key) =
        build_app_with_stream_signer();
    let uri = format!("/v1/kaigi/relays/events?relay={relay_account}");
    let unsigned = app
        .clone()
        .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED);
    let request = fixtures::app_signed_request(
        &network_id,
        &owner_account,
        &owner_key,
        Request::builder().uri(uri).body(Body::empty()).unwrap(),
        &[],
    );
    let resp = app.clone().oneshot(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static("text/event-stream"))
    );
    drop(resp);
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_sse_rejects_invalid_relay_filter() {
    let (app, _relay, owner_account, _operator, _data_dir, network_id, owner_key) =
        build_app_with_stream_signer();
    let request = fixtures::app_signed_request(
        &network_id,
        &owner_account,
        &owner_key,
        Request::builder()
            .uri("/v1/kaigi/relays/events?relay=sorainvalid@kaigi")
            .body(Body::empty())
            .unwrap(),
        &[],
    );
    let resp = app.clone().oneshot(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    app.shutdown().await;
}

#[path = "../src/build_identity_test_fixture.rs"]
mod build_identity_test_fixture;
