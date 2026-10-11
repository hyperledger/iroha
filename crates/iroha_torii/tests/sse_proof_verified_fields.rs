#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Assert `ProofVerified` SSE JSON includes `proof_hash`, `call_hash`, `vk_ref`, `vk_commitment`, and filtering works.
#![cfg(feature = "app_api")]
#[path = "common/proof_events.rs"]
mod proof_events;
use axum::{Router, routing::get};
use futures_util::StreamExt as _;
use norito::json;
// use http_body_util::BodyExt as _;
use proof_events::ProofEventFixture;
use tower::ServiceExt as _;
/// Build the SSE endpoint URI with the proof filter used in the test.
fn proof_verified_filter_uri() -> String {
    let filter_value = iroha_torii::json_object(vec![
        iroha_torii::json_entry("op", "and"),
        iroha_torii::json_entry(
            "args",
            iroha_torii::json_array(vec![
                iroha_torii::json_object(vec![
                    iroha_torii::json_entry("op", "eq"),
                    iroha_torii::json_entry(
                        "args",
                        iroha_torii::json_array(vec![
                            json::Value::from("proof_backend"),
                            json::Value::from("pipa-r/pasta"),
                        ]),
                    ),
                ]),
                iroha_torii::json_object(vec![
                    iroha_torii::json_entry("op", "eq"),
                    iroha_torii::json_entry(
                        "args",
                        iroha_torii::json_array(vec![
                            json::Value::from("proof_call_hash"),
                            json::Value::from(
                                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            ),
                        ]),
                    ),
                ]),
            ]),
        ),
    ]);
    let filter = iroha_torii::filter::FilterExpr::from_json_value(filter_value)
        .expect("valid filter")
        .to_string();
    format!("/v1/events/sse?filter={}", urlencoding::encode(&filter))
}
/// Emit a non-matching and matching proof verification event into the broadcast channel.
fn emit_sample_proof_events(events: &iroha_core::EventsSender) {
    let ev_bad = ProofEventFixture::new("groth16", [0x22; 32])
        .without_vk()
        .verified();
    let _ = events.send(ev_bad);
    let ev_ok = ProofEventFixture::new("pipa-r/pasta", [0x33; 32])
        .with_vk("vk_name", [0x55; 32])
        .with_envelope_hash(Some([0x10; 32]))
        .verified();
    let _ = events.send(ev_ok);
}
/// Consume the SSE response until a `data:` line is observed and return the parsed JSON payload.
async fn first_data_json(resp: axum::response::Response<axum::body::Body>) -> norito::json::Value {
    let mut body_stream = resp.into_body().into_data_stream();
    while let Some(chunk) = body_stream.next().await {
        let bytes = chunk.expect("sse chunk");
        let s = String::from_utf8(bytes.to_vec()).expect("utf8 chunk");
        if let Some(line) = s.lines().find(|l| l.starts_with("data:")) {
            let json = line.trim_start_matches("data:").to_string();
            return json::from_str(&json).expect("json parse");
        }
    }
    panic!("no data line in SSE stream");
}
#[tokio::test]
async fn proof_verified_fields_and_filtering() {
    let events: iroha_core::EventsSender = tokio::sync::broadcast::channel(8).0;
    let app = Router::new().route(
        "/v1/events/sse",
        get({
            let events = events.clone();
            move |q| async move { iroha_torii::handle_v1_events_sse_for_tests(events, q) }
        }),
    );
    // SSE with filter on proof_backend and proof_call_hash
    let uri = proof_verified_filter_uri();
    let req = http::Request::builder()
        .method("GET")
        .uri(uri)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    emit_sample_proof_events(&events);
    let v = first_data_json(resp).await;
    assert_eq!(
        v.get("event").and_then(|x| x.as_str()),
        Some("ProofVerified")
    );
    assert_eq!(
        v.get("backend").and_then(|x| x.as_str()),
        Some("pipa-r/pasta")
    );
    assert_eq!(
        v.get("call_hash").and_then(|x| x.as_str()),
        Some(hex::encode([0xAAu8; 32]).as_str())
    );
    assert_eq!(
        v.get("vk_ref").and_then(|x| x.as_str()),
        Some("pipa-r/pasta::vk_name")
    );
    assert_eq!(
        v.get("vk_commitment").and_then(|x| x.as_str()),
        Some(hex::encode([0x55u8; 32]).as_str())
    );
}
