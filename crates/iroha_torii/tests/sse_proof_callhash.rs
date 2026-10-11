#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Assert that SSE event JSON for Proof events includes `call_hash`.
#![cfg(feature = "app_api")]
#![allow(clippy::items_after_statements)]
#[path = "common/proof_events.rs"]
mod proof_events;
use axum::{Router, routing::get};
use proof_events::ProofEventFixture;
// use http_body_util::BodyExt as _; // not needed, we stream SSE
use tower::ServiceExt as _;
#[tokio::test]
async fn proof_event_json_includes_call_hash() {
    // Create a sender and build a router exposing /v1/events/sse
    let events: iroha_core::EventsSender = tokio::sync::broadcast::channel(8).0;
    let app = Router::new().route(
        "/v1/events/sse",
        get({
            let events = events.clone();
            move |q| async move { iroha_torii::handle_v1_events_sse_for_tests(events, q) }
        }),
    );
    // Spawn request to SSE endpoint
    let req = http::Request::builder()
        .method("GET")
        .uri("/v1/events/sse")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    // Send a single Proof::Rejected event with a known call_hash
    let call_hash = [0xABu8; 32];
    let ev = ProofEventFixture::new("pipa-r/pasta", [0x11; 32])
        .with_call_hash(Some(call_hash))
        .rejected();
    let _ = events.send(ev);
    // Read the first SSE frame body and parse as JSON
    use futures_util::StreamExt as _;
    let mut body_stream = resp.into_body().into_data_stream();
    // First chunk should be an SSE event; find `data:` payload line
    let first = body_stream.next().await.expect("some chunk").unwrap();
    let s = String::from_utf8(first.to_vec()).expect("utf8");
    // Extract the first data line; simplistic split-ok for test
    // Example chunk: "data:{...}\n\n"
    let json_str = s
        .lines()
        .find_map(|l| l.strip_prefix("data:"))
        .unwrap_or("{}");
    let v: norito::json::Value = norito::json::from_str(json_str).expect("json");
    // Verify call_hash is present and equals hex(call_hash)
    let got = v.get("call_hash").and_then(|x| x.as_str()).unwrap_or("");
    assert_eq!(got, hex::encode(call_hash));
}
