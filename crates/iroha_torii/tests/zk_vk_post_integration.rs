#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Integration tests for POST VK registry endpoints (`app_api`).
#![cfg(feature = "app_api")]
#![allow(clippy::too_many_lines)]
use axum::{Router, routing::post};
use base64::Engine as _;
use http_body_util::BodyExt as _;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    queue::Queue,
    state::{State, World},
};
use iroha_data_model::{account::AccountId, transaction::TransactionBuilder};
use iroha_torii::NoritoJson;
use nonzero_ext::nonzero;
use norito::json;
use std::sync::Arc;
use tower::ServiceExt as _;
fn checked_vk_post_authority_fixture() -> iroha_crypto::KeyPair {
    iroha_crypto::KeyPair::try_random()
        .expect("generate checked ZK VK POST authority fixture keypair")
}
#[test]
fn vk_post_authority_fixture_uses_checked_ed25519_key_generation() {
    let key_pair = checked_vk_post_authority_fixture();
    let algorithm = key_pair
        .public_key()
        .try_algorithm()
        .expect("fixture VK POST public key has a valid algorithm");
    assert_eq!(algorithm, iroha_crypto::Algorithm::Ed25519);
}
#[tokio::test]
async fn vk_register_update_return_unsigned_local_signing_drafts() {
    // Minimal state and queue
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::new(), kura.clone(), query);
    let state = Arc::new(state);
    let queue_cfg = iroha_config::parameters::actual::Queue {
        capacity: nonzero!(8usize),
        capacity_per_user: nonzero!(8usize),
        transaction_time_to_live: core::time::Duration::from_mins(1),
        ..Default::default()
    };
    let events_sender: iroha_core::EventsSender = tokio::sync::broadcast::channel(4).0;
    let queue = Arc::new(Queue::from_config(queue_cfg, events_sender));
    // Build routes that capture the queue and CoreState network identity.
    let app = Router::new()
        .route(
            "/v1/zk/vk/register",
            post({
                let queue = queue.clone();
                let state = state.clone();
                move |req: NoritoJson<iroha_torii::ZkVkRegisterDto>| {
                    let queue = queue.clone();
                    let state = state.clone();
                    async move { iroha_torii::handle_post_vk_register(queue, state, req).await }
                }
            }),
        )
        .route(
            "/v1/zk/vk/update",
            post({
                let queue = queue.clone();
                let state = state.clone();
                move |req: NoritoJson<iroha_torii::ZkVkUpdateDto>| {
                    let queue = queue.clone();
                    let state = state.clone();
                    async move { iroha_torii::handle_post_vk_update(queue, state, req).await }
                }
            }),
        );
    // Helper: build headers
    let _json_ct = {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        h
    };
    // Prepare a keypair whose public key matches the authority account id.
    let kp = checked_vk_post_authority_fixture();
    let exposed = iroha_crypto::ExposedPrivateKey(kp.private_key().clone());
    let authority = AccountId::new(kp.public_key().clone());
    // 1) Register (vk_bytes omitted; provide commitment_hex only)
    let body_reg_value = iroha_torii::json_object(vec![
        iroha_torii::json_entry("authority", authority.clone()),
        iroha_torii::json_entry("backend", "pipa-r/pasta"),
        iroha_torii::json_entry("name", "vk_add"),
        iroha_torii::json_entry("version", 1u64),
        iroha_torii::json_entry(
            "circuit_id",
            iroha_core_zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
        ),
        iroha_torii::json_entry(
            "public_inputs_schema_hash_hex",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        iroha_torii::json_entry("gas_schedule_id", "native_pipa_r_default"),
        iroha_torii::json_entry("vk_len", 1024u64),
        iroha_torii::json_entry(
            "commitment_hex",
            "1111111111111111111111111111111111111111111111111111111111111111",
        ),
    ]);
    let body_reg = json::to_json(&body_reg_value).unwrap();
    let req_reg = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/vk/register")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body_reg))
        .unwrap();
    let resp_reg = app.clone().oneshot(req_reg).await.unwrap();
    assert_eq!(resp_reg.status(), http::StatusCode::OK);
    let resp_reg_bytes = resp_reg.into_body().collect().await.unwrap().to_bytes();
    let resp_reg_json: json::Value = json::from_slice(&resp_reg_bytes).unwrap();
    assert_eq!(
        resp_reg_json
            .get("submitted")
            .and_then(json::Value::as_bool),
        Some(false)
    );
    let reg_payload = base64::engine::general_purpose::STANDARD
        .decode(
            resp_reg_json
                .get("transaction_payload_b64")
                .and_then(json::Value::as_str)
                .expect("register payload"),
        )
        .expect("decode register payload");
    let reg_builder = TransactionBuilder::decode_payload(&reg_payload).expect("register draft");
    assert_eq!(reg_builder.payload().authority, authority.clone());
    let reg_signing_message = base64::engine::general_purpose::STANDARD
        .decode(
            resp_reg_json
                .get("signing_message_b64")
                .and_then(json::Value::as_str)
                .expect("register signing message"),
        )
        .expect("decode register signing message");
    assert_eq!(
        reg_signing_message,
        iroha_crypto::HashOf::new(reg_builder.payload())
            .as_ref()
            .to_vec()
    );
    // 2) Update (version increments)
    let body_upd_value = iroha_torii::json_object(vec![
        iroha_torii::json_entry("authority", authority.clone()),
        iroha_torii::json_entry("backend", "pipa-r/pasta"),
        iroha_torii::json_entry("name", "vk_add"),
        iroha_torii::json_entry("version", 2u64),
        iroha_torii::json_entry(
            "circuit_id",
            iroha_core_zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
        ),
        iroha_torii::json_entry(
            "public_inputs_schema_hash_hex",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
        iroha_torii::json_entry("gas_schedule_id", "native_pipa_r_default"),
        iroha_torii::json_entry("vk_len", 1024u64),
        iroha_torii::json_entry(
            "commitment_hex",
            "1111111111111111111111111111111111111111111111111111111111111111",
        ),
    ]);
    let body_upd = json::to_json(&body_upd_value).unwrap();
    let req_upd = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/vk/update")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body_upd))
        .unwrap();
    let resp_upd = app.clone().oneshot(req_upd).await.unwrap();
    assert_eq!(resp_upd.status(), http::StatusCode::OK);
    let resp_upd_bytes = resp_upd.into_body().collect().await.unwrap().to_bytes();
    let resp_upd_json: json::Value = json::from_slice(&resp_upd_bytes).unwrap();
    assert_eq!(
        resp_upd_json
            .get("submitted")
            .and_then(json::Value::as_bool),
        Some(false)
    );
    let update_payload = base64::engine::general_purpose::STANDARD
        .decode(
            resp_upd_json
                .get("transaction_payload_b64")
                .and_then(json::Value::as_str)
                .expect("update payload"),
        )
        .expect("decode update payload");
    let update_builder = TransactionBuilder::decode_payload(&update_payload).expect("update draft");
    assert_eq!(update_builder.payload().authority, authority.clone());
    let update_signing_message = base64::engine::general_purpose::STANDARD
        .decode(
            resp_upd_json
                .get("signing_message_b64")
                .and_then(json::Value::as_str)
                .expect("update signing message"),
        )
        .expect("decode update signing message");
    assert_eq!(
        update_signing_message,
        iroha_crypto::HashOf::new(update_builder.payload())
            .as_ref()
            .to_vec()
    );
    let legacy_body = json::to_json(&iroha_torii::json_object(vec![
        iroha_torii::json_entry("authority", authority),
        iroha_torii::json_entry("private_key", exposed),
        iroha_torii::json_entry("backend", "pipa-r/pasta"),
        iroha_torii::json_entry("name", "legacy"),
        iroha_torii::json_entry("version", 1_u64),
        iroha_torii::json_entry(
            "circuit_id",
            iroha_core_zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
        ),
        iroha_torii::json_entry(
            "public_inputs_schema_hash_hex",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        iroha_torii::json_entry("gas_schedule_id", "native_pipa_r_default"),
        iroha_torii::json_entry("vk_len", 1024_u64),
        iroha_torii::json_entry(
            "commitment_hex",
            "1111111111111111111111111111111111111111111111111111111111111111",
        ),
    ]))
    .expect("encode legacy private-key request");
    let legacy_response = app
        .oneshot(
            http::Request::builder()
                .method("POST")
                .uri("/v1/zk/vk/register")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(legacy_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(legacy_response.status(), http::StatusCode::BAD_REQUEST);
    assert_eq!(queue.queued_len(), 0);
}
