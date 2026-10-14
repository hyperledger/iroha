//! Smoke test that Torii exposes account query routes via the merged sub-router.
#![cfg(feature = "app_api")]
use axum::extract::connect_info::ConnectInfo;
use axum::http::Request;
use http::StatusCode;
use iroha_core::state::World;
use iroha_data_model::{Registrable, account::Account, domain::Domain};
use iroha_model_base::domain::DomainId;
use iroha_test_samples::ALICE_ID;
#[path = "fixtures.rs"]
mod fixtures;
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn account_query_subrouter_exposes_endpoints() {
    // Minimal Torii setup
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let account_id = ALICE_ID.clone();
    let domain_id: iroha_model_base::domain::DomainId =
        DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = Account::new(account_id.clone()).build(&account_id);
    let torii = fixtures::StandardToriiHarness::new(&cfg, World::with([domain], [account], []));
    let app = torii.router();
    let account_segment = fixtures::TX_QUERY_ACCOUNT.canonical.clone();
    // GET assets
    let resp = fixtures::request(
        &app,
        Request::builder()
            .uri(format!("/v1/accounts/{account_segment}/assets"))
            .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))))
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(matches!(
        resp.status(),
        StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
    ));
    // POST assets/query
    let resp = fixtures::request(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/v1/accounts/{account_segment}/assets/query"))
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))))
            .body(axum::body::Body::from("{}"))
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(matches!(
        resp.status(),
        StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
    ));
    // POST transactions/query
    let resp = fixtures::request(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/v1/accounts/{account_segment}/transactions/query"))
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))))
            .body(axum::body::Body::from("{}"))
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(matches!(
        resp.status(),
        StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
    ));
    // GET permissions
    let resp = fixtures::request(
        &app,
        Request::builder()
            .uri(format!(
                "/v1/accounts/{account_segment}/permissions?limit=10"
            ))
            .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))))
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(matches!(
        resp.status(),
        StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
    ));
    app.shutdown().await;
}
