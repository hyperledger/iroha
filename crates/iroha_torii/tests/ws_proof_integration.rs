#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Integration (ignored) test: start a WS endpoint, subscribe, and assert Proof JSON frames.
#![cfg(feature = "app_api")]
#[cfg(feature = "ws_integration_tests")]
#[path = "common/proof_events.rs"]
mod proof_events;
#[cfg(feature = "ws_integration_tests")]
use axum::{Router, routing::get};
#[cfg(feature = "ws_integration_tests")]
use futures_util::{SinkExt as _, StreamExt as _};
#[cfg(feature = "ws_integration_tests")]
use proof_events::ProofEventFixture;
#[cfg(feature = "ws_integration_tests")]
use std::io::ErrorKind;
#[cfg(feature = "ws_integration_tests")]
use tokio::net::TcpListener;
#[cfg(feature = "ws_integration_tests")]
use tokio_tungstenite::tungstenite::Message;
#[cfg(feature = "ws_integration_tests")]
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn ws_proof_json_integration() {
    use iroha_data_model::{
        events::{EventBox, data::proof::ProofEvent, stream::EventMessage},
        prelude::DataEvent,
    };
    // Setup broadcast sender and WS route
    let events: iroha_core::EventsSender = tokio::sync::broadcast::channel(16).0;
    let app = Router::new().route(
        "/ws",
        get({
            let events = events.clone();
            move |ws: axum::extract::ws::WebSocketUpgrade| async move {
                ws.on_upgrade(move |ws| async move {
                    let _ = iroha_torii::handle_events_stream(events, ws).await;
                })
            }
        }),
    );
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(e) if e.kind() == ErrorKind::PermissionDenied => return,
        Err(e) => panic!("tcp bind failed: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    // Connect client
    let (mut ws_stream, _resp) =
        match tokio_tungstenite::connect_async(format!("ws://{addr}/ws")).await {
            Ok(pair) => pair,
            Err(tokio_tungstenite::tungstenite::Error::Io(io_err))
                if io_err.kind() == ErrorKind::PermissionDenied =>
            {
                return;
            }
            Err(e) => panic!("ws connect failed: {e}"),
        };
    // Send EventSubscriptionRequest (Any + proof backend filter)
    let sub = iroha_data_model::events::stream::EventSubscriptionRequest {
        filters: vec![iroha_data_model::events::EventFilterBox::Data(
            iroha_data_model::prelude::DataEventFilter::Any,
        )],
        proof_backend: Some(vec!["pipa-r/pasta".into()]),
        proof_call_hash: None,
        proof_envelope_hash: None,
    };
    let sub_bytes = norito::to_bytes(&sub).expect("subscription encode");
    ws_stream
        .send(tokio_tungstenite::tungstenite::Message::Binary(
            sub_bytes.into(),
        ))
        .await
        .unwrap();
    // Send events (one rejected backend; one verified matching backend)
    let ev_bad = ProofEventFixture::new("groth16", [0x20; 32])
        .without_vk()
        .verified();
    events
        .send(ev_bad)
        .expect("events stream subscriber to be ready for non-matching backend");
    let ev_ok = ProofEventFixture::new("pipa-r/pasta", [0x21; 32])
        .with_vk("vk", [0x55; 32])
        .with_envelope_hash(Some([0x20; 32]))
        .verified();
    events
        .send(ev_ok)
        .expect("events stream subscriber to be ready for matching backend");
    // Read frames until we get a ProofVerified event (wire may be JSON text or Norito binary).
    let mut matched = false;
    while let Some(msg) = ws_stream.next().await {
        match msg.expect("ws message") {
            Message::Text(s) => {
                let v: norito::json::Value = norito::json::from_str(&s).expect("json parse");
                if v.get("event").and_then(|x| x.as_str()) == Some("ProofVerified")
                    && v.get("backend").and_then(|x| x.as_str()) == Some("pipa-r/pasta")
                {
                    matched = true;
                    break;
                }
            }
            Message::Binary(bytes) => {
                let EventMessage(event) = norito::decode_from_bytes(&bytes).expect("event message");
                if let EventBox::Data(data) = event
                    && let DataEvent::Proof(ProofEvent::Verified(verified)) = data.as_ref()
                {
                    assert_eq!(verified.id.backend, "pipa-r/pasta");
                    matched = true;
                    break;
                }
            }
            Message::Close(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }
    assert!(matched, "proof verified event");
}
