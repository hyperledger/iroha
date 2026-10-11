#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Integration tests for GET /v1/zk/vk/{backend}/{name} (`app_api`).
#![allow(clippy::similar_names)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![cfg(feature = "app_api")]
use axum::{Router, routing::get};
use base64::Engine as _;
use http_body_util::BodyExt;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_data_model::{
    confidential::ConfidentialStatus,
    proof::{VerifyingKeyBox, VerifyingKeyId, VerifyingKeyRecord},
    zk::BackendTag,
};
use nonzero_ext::nonzero;
use std::{convert::TryFrom, sync::Arc};
use tower::ServiceExt as _;
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn zk_vk_get_returns_record_with_key() {
    // Build minimal state
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::new(), kura, query);
    let mut state = state;
    // Insert a verifying key record directly into WSV via a block transaction
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let stx = block.transaction();
    let backend = "pipa-r/pasta";
    let name = "vk_add".to_string();
    let vk_bytes = vec![1, 2, 3, 4, 5];
    let vk = VerifyingKeyBox::new(backend.into(), vk_bytes.clone());
    let commitment = iroha_core_zk::hash_vk(&vk);
    let mut rec = VerifyingKeyRecord::new(
        1,
        format!("{backend}:{name}"),
        BackendTag::NativePipaRPasta,
        "vesta",
        [0x11; 32],
        commitment,
    );
    rec.vk_len = u32::try_from(vk_bytes.len()).expect("verifying key too large for u32");
    rec.key = Some(vk);
    rec.status = ConfidentialStatus::Active;
    rec.gas_schedule_id = Some("test_schedule".into());
    rec.namespace = "confidential".into();
    rec.owner_manifest_id = Some("builtin:pipa-r/pasta/confidential-unshield-change-v1".into());
    rec.activation_height = Some(10);
    rec.withdraw_height = Some(20);
    let expected_record = rec.clone();
    let id = VerifyingKeyId::new(backend, name.clone());
    // Drop block view before mutating state via helper to avoid borrow conflict
    drop(stx);
    drop(block);
    iroha_core::query::insert_verifying_key_record_for_test(&mut state, id.clone(), rec);
    let state = Arc::new(state);
    let app = Router::new().route(
        "/v1/zk/vk/{backend}/{name}",
        get({
            let state = state.clone();
            move |path: axum::extract::Path<(String, String)>| async move {
                iroha_torii::handle_get_vk(state, path).await
            }
        }),
    );
    // Encode backend with '/'
    let backend_enc = urlencoding::encode(backend);
    let uri = format!("/v1/zk/vk/{backend_enc}/{name}");
    let req = http::Request::builder()
        .method("GET")
        .uri(uri)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let (parts, body) = resp.into_parts();
    let content_type = parts
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(content_type.contains("application/json"));
    let bytes = body.collect().await.unwrap().to_bytes();
    let v: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    let id_obj = v.get("id").and_then(|x| x.as_object()).expect("id object");
    assert_eq!(
        id_obj.get("backend").and_then(|x| x.as_str()),
        Some(backend)
    );
    assert_eq!(
        id_obj.get("name").and_then(|x| x.as_str()),
        Some(name.as_str())
    );
    let record = v
        .get("record")
        .and_then(|x| x.as_object())
        .expect("record object");
    assert_eq!(record.get("version").and_then(|x| x.as_u64()), Some(1));
    assert_eq!(
        record
            .get("circuit_id")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        Some(format!("{backend}:{name}"))
    );
    let got_commit = record.get("commitment").and_then(|x| x.as_str()).unwrap();
    assert_eq!(got_commit, hex::encode(commitment));
    assert_eq!(
        record.get("status").and_then(|x| x.as_str()),
        Some("Active")
    );
    assert_eq!(
        record.get("namespace").and_then(|x| x.as_str()),
        Some(expected_record.namespace.as_str())
    );
    assert_eq!(
        record.get("owner_manifest_id").and_then(|x| x.as_str()),
        expected_record.owner_manifest_id.as_deref()
    );
    assert_eq!(
        record.get("activation_height").and_then(|x| x.as_u64()),
        expected_record.activation_height
    );
    assert_eq!(
        record.get("withdraw_height").and_then(|x| x.as_u64()),
        expected_record.withdraw_height
    );
    // key section
    let key = record
        .get("key")
        .and_then(|x| x.as_object())
        .expect("key obj");
    assert_eq!(key.get("backend").and_then(|x| x.as_str()), Some(backend));
    let b64 = key.get("bytes_b64").and_then(|x| x.as_str()).unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap();
    assert_eq!(decoded, vk_bytes);
    let record_b64 = v
        .get("record_norito_base64")
        .and_then(|x| x.as_str())
        .expect("record_norito_base64");
    let record_archive = base64::engine::general_purpose::STANDARD
        .decode(record_b64)
        .expect("decode canonical verifier-record archive");
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(&record_archive),
        record_b64
    );
    assert_eq!(
        record_archive,
        norito::to_bytes(&expected_record).expect("encode expected verifier record")
    );
    let decoded_record: VerifyingKeyRecord =
        norito::decode_from_bytes(&record_archive).expect("decode stored verifier-record archive");
    assert_eq!(decoded_record, expected_record);
    assert_eq!(
        decoded_record.key.as_ref().map(|key| key.bytes.as_slice()),
        Some(vk_bytes.as_slice())
    );
    assert_eq!(decoded_record.activation_height, Some(10));
    assert_eq!(decoded_record.withdraw_height, Some(20));
}
#[tokio::test]
async fn zk_vk_get_not_found() {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::new(), kura, query);
    let state = Arc::new(state);
    let app = Router::new().route(
        "/v1/zk/vk/{backend}/{name}",
        get({
            let state = state.clone();
            move |path: axum::extract::Path<(String, String)>| async move {
                iroha_torii::handle_get_vk(state, path).await
            }
        }),
    );
    let backend_enc = urlencoding::encode("pipa-r/pasta");
    let uri = format!("/v1/zk/vk/{}/{}", backend_enc, "missing");
    let req = http::Request::builder()
        .method("GET")
        .uri(uri)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}
