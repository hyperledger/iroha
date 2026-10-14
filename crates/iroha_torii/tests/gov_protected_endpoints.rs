//! Torii tests for protected-namespaces GET/POST endpoints.
#![cfg(all(feature = "app_api", feature = "ws_integration_tests"))]
#![allow(unexpected_cfgs, clippy::redundant_closure_for_method_calls)]
use axum::response::IntoResponse;
use http_body_util::BodyExt as _;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
#[tokio::test]
async fn protected_namespaces_get_post_cycle() {
    if std::env::var("IROHA_RUN_IGNORED").ok().as_deref() != Some("1") {
        eprintln!(
            "Skipping: protected namespaces endpoints test gated. Set IROHA_RUN_IGNORED=1 to run."
        );
        return;
    }
    let state = std::sync::Arc::new(State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    ));
    // GET before setting: found=false
    let resp0 = iroha_torii::handle_gov_protected_get(state.clone())
        .await
        .expect("ok")
        .into_response();
    let body0 = resp0
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    let v0: norito::json::Value = norito::json::from_slice(&body0).expect("json parse");
    assert_eq!(v0.get("found").and_then(|x| x.as_bool()), Some(false));
    // POST to set namespaces
    let req = iroha_torii::ProtectedNamespacesDto {
        namespaces: vec!["apps".to_string(), "system".to_string()],
        authority: None,
    };
    let resp1 = iroha_torii::handle_gov_protected_set(
        state.clone(),
        iroha_torii::MaybeTelemetry::disabled(),
        iroha_torii::NoritoJson(req),
    )
    .await
    .expect("ok")
    .into_response();
    let body1 = resp1
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    let v1: norito::json::Value = norito::json::from_slice(&body1).expect("json parse");
    assert_eq!(v1.get("ok").and_then(|x| x.as_bool()), Some(true));
    // GET after setting: found=true and includes both namespaces
    let resp2 = iroha_torii::handle_gov_protected_get(state)
        .await
        .expect("ok")
        .into_response();
    let body2 = resp2
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    let v2: norito::json::Value = norito::json::from_slice(&body2).expect("json parse");
    assert_eq!(v2.get("found").and_then(|x| x.as_bool()), Some(true));
    let arr = v2
        .get("namespaces")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let vals: std::collections::BTreeSet<String> = arr
        .into_iter()
        .filter_map(|x| x.as_str().map(|s| s.to_string()))
        .collect();
    let expected: std::collections::BTreeSet<String> = ["apps".to_string(), "system".to_string()]
        .into_iter()
        .collect();
    assert_eq!(vals, expected);
}
