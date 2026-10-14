//! Smoke tests for Torii accounts endpoints.
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
#[allow(clippy::too_many_lines)] // test builds complex state; splitting would reduce clarity
async fn accounts_endpoints_exist() {
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let domain_id: iroha_model_base::domain::DomainId =
        DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let torii = fixtures::StandardToriiHarness::new(
        &cfg,
        World::with_assets([domain], [account], [], [], []),
    );
    let app = torii.router();
    // GET /v1/accounts
    let resp = fixtures::request(
        &app,
        Request::builder()
            .uri("/v1/accounts?offset=0")
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
    // POST /v1/accounts/query
    let resp = fixtures::request(
        &app,
        Request::builder()
            .method("POST")
            .uri("/v1/accounts/query")
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
    // GET /v1/accounts/{account}/permissions
    let canonical_account = &fixtures::TX_QUERY_ACCOUNT.canonical;
    let resp = fixtures::request(
        &app,
        Request::builder()
            .uri(format!(
                "/v1/accounts/{canonical_account}/permissions?offset=0"
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
