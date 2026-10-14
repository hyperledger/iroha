//! Basic shape test for `/v1/sumeragi/status/sse`
#![cfg(feature = "telemetry")]
#![allow(unexpected_cfgs)]
#[tokio::test]
async fn sumeragi_status_sse_content_type() {
    use axum::{Router, routing::get};
    use iroha_core::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use std::sync::Arc;
    use tower::ServiceExt;
    let state = Arc::new(State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    ));
    let app = Router::new().route(
        "/v1/sumeragi/status/sse",
        get(move || {
            let state = state.clone();
            async move { iroha_torii::handle_v1_sumeragi_status_sse(state, 200, None) }
        }),
    );
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/v1/sumeragi/status/sse")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("text/event-stream"));
}
