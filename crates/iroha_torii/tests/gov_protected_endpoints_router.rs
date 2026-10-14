//! Router-level tests for protected-namespaces endpoints.
#![allow(clippy::redundant_closure_for_method_calls)]
#![cfg(all(feature = "app_api", feature = "ws_integration_tests"))]
#![allow(unexpected_cfgs)]
use axum::{Router, routing::get};
use http_body_util::BodyExt as _;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use norito::json;
use std::sync::Arc;
use tower::ServiceExt as _; // for Router::oneshot
#[tokio::test]
async fn protected_namespaces_endpoints_work() {
    if std::env::var("IROHA_RUN_IGNORED").ok().as_deref() != Some("1") {
        eprintln!(
            "Skipping: router-level protected endpoints test gated. Set IROHA_RUN_IGNORED=1 to run."
        );
        return;
    }
    // Minimal in-memory state
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = Arc::new(State::new_for_testing(World::default(), kura, query));
    // Wire routes for GET and POST
    let app = Router::new().route(
        "/v1/gov/protected-namespaces",
        get({
            let state = state.clone();
            move || async move { iroha_torii::handle_gov_protected_get(state).await }
        })
        .post({
            let state = state.clone();
            move |req: iroha_torii::NoritoJson<iroha_torii::ProtectedNamespacesDto>| {
                let state = state.clone();
                async move {
                    iroha_torii::handle_gov_protected_set(
                        state,
                        iroha_torii::MaybeTelemetry::disabled(),
                        req,
                    )
                    .await
                }
            }
        }),
    );
    // GET should return found=false
    let req_get0 = http::Request::builder()
        .method("GET")
        .uri("/v1/gov/protected-namespaces")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp0 = app.clone().oneshot(req_get0).await.unwrap();
    assert_eq!(resp0.status(), http::StatusCode::OK);
    let body0 = resp0.into_body().collect().await.unwrap().to_bytes();
    let v0: norito::json::Value = norito::json::from_slice(&body0).unwrap();
    assert_eq!(v0.get("found").and_then(|x| x.as_bool()), Some(false));
    // POST apply namespaces
    let body_value = iroha_torii::json_object(vec![iroha_torii::json_entry(
        "namespaces",
        iroha_torii::json_array(vec!["apps", "system"]),
    )]);
    let body = json::to_string(&body_value).expect("serialize namespaces");
    let req_post = http::Request::builder()
        .method("POST")
        .uri("/v1/gov/protected-namespaces")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp1 = app.clone().oneshot(req_post).await.unwrap();
    assert_eq!(resp1.status(), http::StatusCode::OK);
    // GET now returns found=true with namespaces
    let req_get1 = http::Request::builder()
        .method("GET")
        .uri("/v1/gov/protected-namespaces")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp2 = app.clone().oneshot(req_get1).await.unwrap();
    assert_eq!(resp2.status(), http::StatusCode::OK);
    let body2 = resp2.into_body().collect().await.unwrap().to_bytes();
    let v2: norito::json::Value = norito::json::from_slice(&body2).unwrap();
    assert_eq!(v2.get("found").and_then(|x| x.as_bool()), Some(true));
    let arr = v2
        .get("namespaces")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let set: std::collections::BTreeSet<String> = arr
        .into_iter()
        .filter_map(|x| x.as_str().map(|s| s.to_string()))
        .collect();
    let exp: std::collections::BTreeSet<String> = ["apps".to_string(), "system".to_string()]
        .into_iter()
        .collect();
    assert_eq!(set, exp);
}
