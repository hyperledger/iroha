#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Assert SSE filtering by `proof_envelope_hash` works and JSON contains the field.
#![cfg(feature = "app_api")]
#![allow(clippy::items_after_statements)]
#[path = "common/proof_events.rs"]
mod proof_events;
use axum::{Router, routing::get};
use futures_util::StreamExt as _;
// use http_body_util::BodyExt as _;
use proof_events::ProofEventFixture;
use tower::ServiceExt as _;
#[tokio::test]
async fn sse_filters_by_proof_envelope_hash() {
    let events: iroha_core::EventsSender = tokio::sync::broadcast::channel(8).0;
    let app = Router::new().route(
        "/v1/events/sse",
        get({
            let events = events.clone();
            move |q| async move { iroha_torii::handle_v1_events_sse_for_tests(events, q) }
        }),
    );
    // Filter by envelope hash (hex, 64 chars)
    let want_hex = hex::encode([0xCCu8; 32]);
    let filter_value = iroha_torii::json_object(vec![
        iroha_torii::json_entry("op", "eq"),
        iroha_torii::json_entry(
            "args",
            iroha_torii::json_array(vec!["proof_envelope_hash", want_hex.as_str()]),
        ),
    ]);
    let filter = iroha_torii::filter::FilterExpr::from_json_value(filter_value)
        .expect("valid filter")
        .to_string();
    let uri = format!("/v1/events/sse?filter={}", urlencoding::encode(&filter));
    let req = http::Request::builder()
        .method("GET")
        .uri(uri)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    // Send a non-matching event (different envelope_hash)
    let ev_bad = ProofEventFixture::new("pipa-r/pasta", [0x12; 32])
        .without_vk()
        .with_envelope_hash(Some([0xDD; 32]))
        .verified();
    let _ = events.send(ev_bad);
    // Negative path: ensure no data frame is produced for the non-matching event
    // Read a couple of chunks with timeout and assert none contain a data: line
    let mut body_stream = resp.into_body().into_data_stream();
    for _ in 0..3 {
        if let Ok(Some(chunk)) =
            tokio::time::timeout(core::time::Duration::from_millis(50), body_stream.next()).await
        {
            let bytes = chunk.unwrap();
            let s = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(
                !s.lines().any(|l| l.starts_with("data:")),
                "non-matching event must not yield data frame"
            );
        } else {
            // no chunk within timeout — acceptable
            break;
        }
    }
    // Send a matching event with the exact envelope hash
    let ev_ok = ProofEventFixture::new("pipa-r/pasta", [0x13; 32])
        .without_vk()
        .with_envelope_hash(Some([0xCC; 32]))
        .verified();
    let _ = events.send(ev_ok);
    // Read until a data frame appears; validate envelope_hash field
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
        Some("ProofVerified")
    );
    assert_eq!(
        v.get("envelope_hash").and_then(|x| x.as_str()),
        Some(hex::encode([0xCCu8; 32]).as_str())
    );
}
