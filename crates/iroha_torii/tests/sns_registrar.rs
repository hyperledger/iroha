#![cfg(feature = "app_api")]
//! Integration tests exercising the SNS registrar API surface.
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt as _;
use iroha_core::state::World;
use iroha_crypto::PublicKey;
use iroha_data_model::{
    account::{AccountAddress, AccountId},
    sns::{
        DOMAIN_NAME_SUFFIX_ID, NameControllerV1, NameFrozenStateV1, NameRecordV1, NameSelectorV1,
        NameStatus,
    },
};
use iroha_model_base::metadata::Metadata;
use iroha_torii::test_utils;
use norito::codec::Encode as _;
#[path = "fixtures.rs"]
mod torii_fixtures;
struct SeededDomainRecord {
    literal: String,
    status: NameStatus,
}
fn test_router() -> iroha_torii::TestApiRouterRuntime {
    test_router_with_domain_records(Vec::new())
}
fn test_router_with_domain_records(
    records: Vec<SeededDomainRecord>,
) -> iroha_torii::TestApiRouterRuntime {
    let cfg = test_utils::mk_minimal_root_cfg();
    let mut world = World::default();
    for record in records {
        seed_domain_name_record(&mut world, record);
    }
    let torii = torii_fixtures::StandardToriiHarness::new(&cfg, world);
    torii.router()
}
fn sample_owner() -> AccountId {
    let public_key: PublicKey =
        "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245"
            .parse()
            .expect("key parses");
    AccountId::new(public_key)
}
fn controller_for(owner: &AccountId) -> NameControllerV1 {
    let address = AccountAddress::from_account_id(owner).expect("address encode");
    NameControllerV1::account(&address)
}
fn seeded_domain_record(label: &str, status: NameStatus) -> SeededDomainRecord {
    SeededDomainRecord {
        literal: domain_literal(label),
        status,
    }
}
fn seed_domain_name_record(world: &mut World, seeded: SeededDomainRecord) {
    let owner = sample_owner();
    let selector =
        NameSelectorV1::new(DOMAIN_NAME_SUFFIX_ID, seeded.literal).expect("domain selector");
    let mut record = NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![controller_for(&owner)],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        Metadata::default(),
    );
    record.status = seeded.status;
    world.smart_contract_state_mut_for_testing().insert(
        iroha_core::sns::record_storage_key(&selector),
        record.encode(),
    );
}
async fn request_empty(
    app: &Router,
    method: &str,
    uri: impl AsRef<str>,
) -> axum::response::Response {
    torii_fixtures::request(
        &app,
        Request::builder()
            .uri(uri.as_ref())
            .method(method)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .expect("json response")
}
async fn get(app: &Router, uri: impl AsRef<str>) -> axum::response::Response {
    torii_fixtures::request(&app, torii_fixtures::get_request(&(uri.as_ref())))
        .await
        .expect("get response")
}
fn domain_name_path(label: &str) -> String {
    format!("/v1/sns/names/domain/{}", domain_literal(label))
}
fn domain_literal(label: &str) -> String {
    format!("{label}.universal")
}
#[tokio::test]
async fn sns_fetch_seeded_record_and_policy_round_trip() {
    let app =
        test_router_with_domain_records(vec![seeded_domain_record("makoto", NameStatus::Active)]);
    let record_resp = get(&app, domain_name_path("makoto")).await;
    assert_eq!(record_resp.status(), StatusCode::OK);
    let record: NameRecordV1 =
        norito::json::from_slice(&record_resp.into_body().collect().await.unwrap().to_bytes())
            .expect("decode record");
    assert_eq!(record.selector.normalized_label(), domain_literal("makoto"));
    assert!(matches!(record.status, NameStatus::Active));
    let policy_resp = get(&app, format!("/v1/sns/policies/{DOMAIN_NAME_SUFFIX_ID}")).await;
    assert_eq!(policy_resp.status(), StatusCode::OK);
    app.shutdown().await;
}
#[tokio::test]
async fn sns_fetch_accepts_noncanonical_domain_path_literal() {
    let app =
        test_router_with_domain_records(vec![seeded_domain_record("casepath", NameStatus::Active)]);
    let record_resp = get(&app, "/v1/sns/names/domain/CASEPATH.UNIVERSAL").await;
    assert_eq!(record_resp.status(), StatusCode::OK);
    let record: NameRecordV1 =
        norito::json::from_slice(&record_resp.into_body().collect().await.unwrap().to_bytes())
            .expect("decode record");
    assert_eq!(record.selector.normalized_label(), "casepath.universal");
    app.shutdown().await;
}
#[tokio::test]
async fn sns_fetch_returns_seeded_frozen_status() {
    let app = test_router_with_domain_records(vec![seeded_domain_record(
        "frozen",
        NameStatus::Frozen(NameFrozenStateV1 {
            reason: "audit".into(),
            until_ms: u64::MAX,
        }),
    )]);
    let record_resp = get(&app, domain_name_path("frozen")).await;
    assert_eq!(record_resp.status(), StatusCode::OK);
    let record: NameRecordV1 =
        norito::json::from_slice(&record_resp.into_body().collect().await.unwrap().to_bytes())
            .expect("decode record");
    assert!(matches!(record.status, NameStatus::Frozen(_)));
    app.shutdown().await;
}
#[tokio::test]
async fn sns_fetch_rejects_bare_domain_literal() {
    let app = test_router();
    let record_resp = get(&app, "/v1/sns/names/domain/lookupcanon").await;
    assert_eq!(record_resp.status(), StatusCode::BAD_REQUEST);
    app.shutdown().await;
}
#[tokio::test]
async fn sns_fetch_missing_name_returns_not_found() {
    let app = test_router();
    let record_resp = get(&app, "/v1/sns/names/domain/missing.universal").await;
    assert_eq!(record_resp.status(), StatusCode::NOT_FOUND);
    app.shutdown().await;
}
#[tokio::test]
async fn sns_fetch_rejects_unknown_namespace() {
    let app = test_router();
    let record_resp = get(&app, "/v1/sns/names/not-a-namespace/casepath.universal").await;
    assert_eq!(record_resp.status(), StatusCode::BAD_REQUEST);
    app.shutdown().await;
}
#[tokio::test]
async fn sns_missing_policy_returns_not_found() {
    let app = test_router();
    let policy_resp = get(&app, "/v1/sns/policies/65535").await;
    assert_eq!(policy_resp.status(), StatusCode::NOT_FOUND);
    app.shutdown().await;
}
#[tokio::test]
async fn sns_mutation_routes_are_absent() {
    let app = test_router();
    for (method, path) in [
        ("POST", "/v1/sns/names"),
        ("POST", "/v1/sns/names/domain/missing.universal/renew"),
        ("POST", "/v1/sns/names/domain/missing.universal/transfer"),
        ("POST", "/v1/sns/names/domain/missing.universal/controllers"),
        ("POST", "/v1/sns/names/domain/missing.universal/freeze"),
        ("DELETE", "/v1/sns/names/domain/missing.universal/freeze"),
    ] {
        let response = request_empty(&app, method, path).await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "obsolete SNS mutation route must be absent: {method} {path}"
        );
    }
    app.shutdown().await;
}
