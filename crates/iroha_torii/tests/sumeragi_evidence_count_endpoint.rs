#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Router-level test for GET /v1/sumeragi/evidence/count
#![cfg(feature = "telemetry")]
use super::sumeragi_evidence::{make_phase_vote_attribution, make_phase_vote_evidence};
use axum::{Router, extract::State, routing::get};
use http_body_util::BodyExt as _;
use iroha_core::{
    kura::Kura,
    query::{insert_evidence_record_for_test, store::LiveQueryStore},
    state::{State as CoreState, World},
    telemetry::StateTelemetry,
};
use iroha_data_model::block::consensus::{EvidencePenaltyStatus, EvidenceRecord};
use iroha_torii::handle_v1_sumeragi_evidence_count;
use iroha_torii_shared::sumeragi_evidence_api::{
    SUMERAGI_EVIDENCE_COUNT_RESPONSE_MAX_BYTES, SumeragiEvidenceCountResponse,
};
use std::sync::Arc;
use tower::ServiceExt as _; // for Router::oneshot
fn assert_exact_count_response_shape(value: &norito::json::Value) {
    let object = value.as_object().expect("evidence count response object");
    assert_eq!(object.len(), 1);
    assert!(object.contains_key("count"));
}
#[tokio::test]
async fn evidence_count_endpoint_reports_increase() {
    let kura = Arc::new(Kura::blank_kura_for_testing());
    let query = LiveQueryStore::start_test();
    let mut state = Arc::new(CoreState::with_telemetry(
        World::default(),
        Arc::clone(&kura),
        query,
        StateTelemetry::default(),
    ));
    {
        let app = Router::new()
            .route(
                "/v1/sumeragi/evidence/count",
                get(
                    |state: State<Arc<CoreState>>, headers: http::HeaderMap| async move {
                        let accept = headers.get(http::header::ACCEPT).cloned();
                        handle_v1_sumeragi_evidence_count(state, accept).await
                    },
                ),
            )
            .with_state(state.clone());
        let req0 = http::Request::builder()
            .method("GET")
            .uri("/v1/sumeragi/evidence/count")
            .header(http::header::ACCEPT, "application/json")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp0 = app.clone().oneshot(req0).await.unwrap();
        assert_eq!(resp0.status(), http::StatusCode::OK);
        assert_eq!(
            resp0
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        let body0 = resp0.into_body().collect().await.unwrap().to_bytes();
        let v0: norito::json::Value = norito::json::from_slice(&body0).unwrap();
        assert_exact_count_response_shape(&v0);
        let c0 = v0
            .get("count")
            .and_then(norito::json::Value::as_u64)
            .unwrap_or(0);
        assert_eq!(c0, 0);
    }
    let state_mut = Arc::get_mut(&mut state).expect("state Arc should be uniquely owned here");
    // Insert two WSV-backed evidence records
    for (idx, seed) in [0x11u8, 0x22].iter().enumerate() {
        let ev = make_phase_vote_evidence((idx + 1) as u64, *seed);
        let record = EvidenceRecord {
            evidence: ev,
            attribution: make_phase_vote_attribution((idx + 1) as u64, *seed),
            recorded_at_height: (idx + 1) as u64,
            recorded_at_view: 0,
            recorded_at_ms: 0,
            penalty_status: EvidencePenaltyStatus::Pending,
        };
        insert_evidence_record_for_test(state_mut, record);
    }
    let app = Router::new()
        .route(
            "/v1/sumeragi/evidence/count",
            get(
                |state: State<Arc<CoreState>>, headers: http::HeaderMap| async move {
                    let accept = headers.get(http::header::ACCEPT).cloned();
                    handle_v1_sumeragi_evidence_count(state, accept).await
                },
            ),
        )
        .with_state(state.clone());
    let req1 = http::Request::builder()
        .method("GET")
        .uri("/v1/sumeragi/evidence/count")
        .header(http::header::ACCEPT, "application/json")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp1 = app.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), http::StatusCode::OK);
    assert_eq!(
        resp1
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body1 = resp1.into_body().collect().await.unwrap().to_bytes();
    let v1j: norito::json::Value = norito::json::from_slice(&body1).unwrap();
    assert_exact_count_response_shape(&v1j);
    let c1 = v1j
        .get("count")
        .and_then(norito::json::Value::as_u64)
        .unwrap_or(0);
    assert_eq!(c1, 2);

    let default_request = http::Request::builder()
        .method("GET")
        .uri("/v1/sumeragi/evidence/count")
        .body(axum::body::Body::empty())
        .unwrap();
    let default_response = app.clone().oneshot(default_request).await.unwrap();
    assert_eq!(default_response.status(), http::StatusCode::OK);
    assert_eq!(
        default_response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let default_body = default_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert!(default_body.len() <= SUMERAGI_EVIDENCE_COUNT_RESPONSE_MAX_BYTES);
    let default_json: norito::json::Value =
        norito::json::from_slice(&default_body).expect("decode default JSON count response");
    assert_exact_count_response_shape(&default_json);
    assert_eq!(
        default_json
            .get("count")
            .and_then(norito::json::Value::as_u64),
        Some(2)
    );

    let norito_request = http::Request::builder()
        .method("GET")
        .uri("/v1/sumeragi/evidence/count")
        .header(http::header::ACCEPT, "application/x-norito")
        .body(axum::body::Body::empty())
        .unwrap();
    let norito_response = app.oneshot(norito_request).await.unwrap();
    assert_eq!(norito_response.status(), http::StatusCode::OK);
    assert_eq!(
        norito_response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/x-norito")
    );
    let norito_body = norito_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert!(norito_body.len() <= SUMERAGI_EVIDENCE_COUNT_RESPONSE_MAX_BYTES);
    let decoded: SumeragiEvidenceCountResponse = norito::decode_from_bytes(&norito_body)
        .expect("decode explicitly requested Norito count response");
    assert_eq!(decoded.count, 2);
}
