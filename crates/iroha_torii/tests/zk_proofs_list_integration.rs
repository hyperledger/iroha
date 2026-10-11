#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Integration tests for /v1/zk/proofs and /v1/zk/proofs/count.
#![cfg(feature = "app_api")]
#![allow(clippy::too_many_lines)]
use axum::{Router, routing::get};
use http_body_util::BodyExt as _;
use iroha_config::parameters::defaults;
use iroha_core::{
    kura::Kura,
    query::{insert_proof_tags_for_test, store::LiveQueryStore},
    state::{State, World},
};
use iroha_data_model::proof::{ProofId, ProofRecord, ProofStatus};
use std::{sync::Arc, time::Duration};
use tower::ServiceExt as _;
#[tokio::test]
async fn proofs_list_and_count_with_filters() {
    // Build minimal state
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(World::new(), kura, query);
    // Seed proofs through the helper so derived indexes such as proofs_by_status stay consistent.
    let backend = "pipa-r/pasta";
    let id1 = ProofId {
        backend: backend.into(),
        proof_hash: [0x01; 32],
    };
    let rec1 = ProofRecord {
        id: id1.clone(),
        vk_ref: None,
        vk_commitment: None,
        status: ProofStatus::Verified,
        verified_at_height: Some(1),
        bridge: None,
    };
    iroha_core::query::insert_proof_record_for_test(&mut state, id1.clone(), rec1);
    let id2 = ProofId {
        backend: backend.into(),
        proof_hash: [0x02; 32],
    };
    let rec2 = ProofRecord {
        id: id2.clone(),
        vk_ref: None,
        vk_commitment: None,
        status: ProofStatus::Rejected,
        verified_at_height: Some(2),
        bridge: None,
    };
    iroha_core::query::insert_proof_record_for_test(&mut state, id2, rec2);
    let id3 = ProofId {
        backend: backend.into(),
        proof_hash: [0x03; 32],
    };
    let rec3 = ProofRecord {
        id: id3.clone(),
        vk_ref: None,
        vk_commitment: None,
        status: ProofStatus::Submitted,
        verified_at_height: None,
        bridge: None,
    };
    iroha_core::query::insert_proof_record_for_test(&mut state, id3, rec3);
    insert_proof_tags_for_test(&mut state, id1.clone(), vec![*b"PROF", *b"I10P"]);
    let state = Arc::new(state);
    let limits = iroha_torii::ProofApiLimits::default();
    let telemetry = iroha_torii::MaybeTelemetry::disabled();
    let app = Router::new()
        .route(
            "/v1/zk/proofs",
            get({
                let state = state.clone();
                let telemetry = telemetry.clone();
                move |q: iroha_torii::NoritoQuery<iroha_torii::ProofListQuery>| async move {
                    iroha_torii::handle_list_proofs(state, limits, telemetry, q).await
                }
            }),
        )
        .route(
            "/v1/zk/proofs/count",
            get({
                let state = state.clone();
                let telemetry = telemetry.clone();
                move |q: iroha_torii::NoritoQuery<iroha_torii::ProofListQuery>| async move {
                    iroha_torii::handle_count_proofs(state, limits, telemetry, q).await
                }
            }),
        );
    // List all
    let resp_all = app
        .clone()
        .oneshot(
            http::Request::builder()
                .method("GET")
                .uri("/v1/zk/proofs")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_all.status(), http::StatusCode::OK);
    let arr_all: Vec<norito::json::Value> =
        norito::json::from_slice(&resp_all.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(arr_all.len(), 3);
    // Count with status filter
    let resp_cnt = app
        .clone()
        .oneshot(
            http::Request::builder()
                .method("GET")
                .uri("/v1/zk/proofs/count?status=Verified")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_cnt.status(), http::StatusCode::OK);
    let vcnt: norito::json::Value =
        norito::json::from_slice(&resp_cnt.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(
        vcnt.get("count").and_then(norito::json::Value::as_u64),
        Some(1)
    );
    // List with has_tag=PROF should return only id1
    let resp_tag = app
        .clone()
        .oneshot(
            http::Request::builder()
                .method("GET")
                .uri("/v1/zk/proofs?has_tag=PROF&ids_only=true")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_tag.status(), http::StatusCode::OK);
    let id_values: Vec<norito::json::Value> =
        norito::json::from_slice(&resp_tag.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(id_values.len(), 1);
    let backend_s = id_values[0]
        .get("backend")
        .and_then(norito::json::Value::as_str)
        .unwrap();
    let hash_s = id_values[0]
        .get("hash")
        .and_then(norito::json::Value::as_str)
        .unwrap();
    assert_eq!(backend_s, backend);
    assert_eq!(hash_s, hex::encode([0x01u8; 32]));
    // Height lower-bound filter should return only proofs verified at or above height 2
    let resp_min = app
        .clone()
        .oneshot(
            http::Request::builder()
                .method("GET")
                .uri("/v1/zk/proofs?verified_from_height=2&ids_only=true")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_min.status(), http::StatusCode::OK);
    let arr_min: Vec<norito::json::Value> =
        norito::json::from_slice(&resp_min.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(arr_min.len(), 1);
    assert_eq!(
        arr_min[0]
            .get("hash")
            .and_then(norito::json::Value::as_str)
            .unwrap(),
        hex::encode([0x02u8; 32])
    );
    // Upper-bound filter should limit results to the earliest verified proof
    let resp_max = app
        .clone()
        .oneshot(
            http::Request::builder()
                .method("GET")
                .uri("/v1/zk/proofs?verified_until_height=1&ids_only=true")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_max.status(), http::StatusCode::OK);
    let arr_max: Vec<norito::json::Value> =
        norito::json::from_slice(&resp_max.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(arr_max.len(), 1);
    assert_eq!(
        arr_max[0]
            .get("hash")
            .and_then(norito::json::Value::as_str)
            .unwrap(),
        hex::encode([0x01u8; 32])
    );
    // Invalid range should yield a bad request.
    let resp_err = app
        .clone()
        .oneshot(
            http::Request::builder()
                .method("GET")
                .uri("/v1/zk/proofs?verified_from_height=10&verified_until_height=5")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_err.status(), http::StatusCode::BAD_REQUEST);

    for uri in [
        "/v1/zk/proofs?status=Unknown",
        "/v1/zk/proofs?has_tag=%C3%A9%C3%A9",
        "/v1/zk/proofs?order=sideways",
        "/v1/zk/proofs/count?status=Unknown",
        "/v1/zk/proofs/count?has_tag=%C3%A9%C3%A9",
        "/v1/zk/proofs/count?limit=1",
        "/v1/zk/proofs/count?offset=1",
        "/v1/zk/proofs/count?order=asc",
        "/v1/zk/proofs/count?ids_only=false",
    ] {
        let response = app
            .clone()
            .oneshot(
                http::Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST, "{uri}");
    }
}
#[tokio::test]
async fn proofs_list_rejects_zero_and_over_limit() {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::new(), kura, query);
    let state = Arc::new(state);
    let limits = iroha_torii::ProofApiLimits::new(
        5,
        Duration::from_millis(50),
        Duration::from_secs(defaults::torii::PROOF_CACHE_MAX_AGE_SECS),
        Duration::from_secs(defaults::torii::PROOF_RETRY_AFTER_SECS),
        usize::try_from(defaults::torii::PROOF_MAX_BODY_BYTES.get())
            .expect("default proof body limit fits usize"),
        Duration::from_millis(defaults::torii::PROOF_BODY_READ_TIMEOUT_MS),
    );
    for limit in [0, 50] {
        let result = iroha_torii::handle_list_proofs(
            state.clone(),
            limits,
            iroha_torii::MaybeTelemetry::disabled(),
            iroha_torii::NoritoQuery(iroha_torii::ProofListQuery {
                limit: Some(limit),
                ..Default::default()
            }),
        )
        .await;
        assert!(
            result.is_err(),
            "invalid proof page limit {limit} must fail"
        );
    }
}

#[tokio::test]
async fn proofs_list_rejects_excessive_ordered_window() {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = Arc::new(State::new_for_testing(World::new(), kura, query));
    let limits = iroha_torii::ProofApiLimits::new(
        5,
        Duration::from_millis(50),
        Duration::from_secs(defaults::torii::PROOF_CACHE_MAX_AGE_SECS),
        Duration::from_secs(defaults::torii::PROOF_RETRY_AFTER_SECS),
        usize::try_from(defaults::torii::PROOF_MAX_BODY_BYTES.get())
            .expect("default proof body limit fits usize"),
        Duration::from_millis(defaults::torii::PROOF_BODY_READ_TIMEOUT_MS),
    );
    let result = iroha_torii::handle_list_proofs(
        state,
        limits,
        iroha_torii::MaybeTelemetry::disabled(),
        iroha_torii::NoritoQuery(iroha_torii::ProofListQuery {
            offset: Some(
                u32::try_from(iroha_core::torii::zk::proofs::MAX_PROOF_QUERY_WINDOW)
                    .expect("proof query window fits u32"),
            ),
            limit: Some(1),
            ..Default::default()
        }),
    )
    .await;
    assert!(result.is_err(), "excessive ordered window must fail closed");
}
