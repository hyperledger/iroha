#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Assert `ProofRejected` SSE JSON includes `proof_hash`, `call_hash`, `vk_ref`, `vk_commitment`.
#![cfg(feature = "app_api")]
#[path = "common/proof_events.rs"]
mod proof_events;
use axum::{Router, routing::get};
use futures_util::StreamExt as _;
// use http_body_util::BodyExt as _;
use proof_events::ProofEventFixture;
use tower::ServiceExt as _;
#[tokio::test]
async fn proof_rejected_fields() {
    let events: iroha_core::EventsSender = tokio::sync::broadcast::channel(8).0;
    let app = Router::new().route(
        "/v1/events/sse",
        get({
            let events = events.clone();
            move |q| async move { iroha_torii::handle_v1_events_sse_for_tests(events, q) }
        }),
    );
    // No filter
    let req = http::Request::builder()
        .method("GET")
        .uri("/v1/events/sse")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let ev = ProofEventFixture::new("pipa-r/pasta", [0x44; 32])
        .with_vk("vk_r", [0x77; 32])
        .with_call_hash(Some([0xBB; 32]))
        .rejected();
    let _ = events.send(ev);
    // Consume until data line
    let mut body_stream = resp.into_body().into_data_stream();
    let mut data_json: Option<String> = None;
    while let Some(chunk) = body_stream.next().await {
        let bytes = chunk.unwrap();
        let s = String::from_utf8(bytes.to_vec()).unwrap();
        if let Some(line) = s.lines().find(|l| l.starts_with("data:")) {
            data_json = Some(line.trim_start_matches("data:").to_string());
            break;
        }
    }
    let json = data_json.expect("data line present");
    let v: norito::json::Value = norito::json::from_str(&json).expect("json parse");
    assert_eq!(
        v.get("event").and_then(|x| x.as_str()),
        Some("ProofRejected")
    );
    assert_eq!(
        v.get("backend").and_then(|x| x.as_str()),
        Some("pipa-r/pasta")
    );
    assert_eq!(
        v.get("call_hash").and_then(|x| x.as_str()),
        Some(hex::encode([0xBBu8; 32]).as_str())
    );
    assert_eq!(
        v.get("vk_ref").and_then(|x| x.as_str()),
        Some("pipa-r/pasta::vk_r")
    );
    assert_eq!(
        v.get("vk_commitment").and_then(|x| x.as_str()),
        Some(hex::encode([0x77u8; 32]).as_str())
    );
}
