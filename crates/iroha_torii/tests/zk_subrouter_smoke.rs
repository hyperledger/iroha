//! Smoke test that ZK endpoints (verify, attachments) are exposed via the merged sub-router.
#![cfg(feature = "app_api")]
use axum::http::Request;
use http::StatusCode;
use http_body_util::BodyExt as _;
use iroha_core::state::World;
use iroha_data_model::{
    Registrable,
    account::{Account, AccountId},
    domain::Domain,
};
use iroha_model_base::domain::DomainId;
use iroha_torii_shared::ErrorEnvelope;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tower::ServiceExt as _;
#[path = "fixtures.rs"]
mod fixtures;
fn attachments_smoke_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("attachments smoke lock")
}
fn attachment_router(
    torii: &fixtures::StandardToriiHarness,
    cfg: &iroha_config::parameters::actual::Root,
) -> iroha_torii::TestApiRouterRuntime {
    if cfg.torii.zk_attachments_enabled {
        // The test router does not run Torii::start; retain its real durable
        // attachment initialization before exercising requests on an empty store.
        iroha_torii::zk_attachments::init_persistence()
            .expect("initialize the configured attachment store");
    }
    torii.router()
}
fn request_with_headers(
    method: &str,
    uri: &str,
    headers: &axum::http::HeaderMap,
    body: &[u8],
) -> Request<axum::body::Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder.body(axum::body::Body::from(body.to_vec())).unwrap()
}
fn assert_error_message(body: &[u8], expected_code: &str, expected_message: &str) {
    let envelope: ErrorEnvelope = norito::decode_from_bytes(body).expect("error envelope payload");
    assert_eq!(envelope.code(), expected_code);
    assert!(
        envelope.message().contains(expected_message),
        "unexpected error envelope: {envelope:?}"
    );
}
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn zk_verify_and_attachments_endpoints_exposed_by_default() {
    let _guard = attachments_smoke_lock();
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    // Minimal Torii setup (no telemetry requirement for these endpoints)
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let account_id = AccountId::new(cfg.common.key_pair.public_key().clone());
    let domain = Domain::new(DomainId::try_new("wonderland", "universal").expect("domain id"))
        .build(&account_id);
    let account = Account::new(account_id.clone()).build(&account_id);
    let torii = fixtures::StandardToriiHarness::new(&cfg, World::with([domain], [account], []));
    let app = attachment_router(&torii, &cfg);
    for retired_path in ["/v1/zk/verify", "/v1/zk/submit-proof"] {
        let resp = fixtures::request(
            &app,
            fixtures::post_json_request(&(retired_path), axum::body::Body::from("{}")),
        )
        .await
        .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{retired_path} must not expose a decode-only success surface"
        );
    }
    // GET /v1/zk/attachments (signed; empty list by default); accept OK or 429
    let request = fixtures::app_signed_request(
        torii.state.network_id_ref(),
        &account_id,
        &cfg.common.key_pair,
        fixtures::get_request(&("/v1/zk/attachments")),
        &[],
    );
    let resp = fixtures::request(&app, request).await.unwrap();
    assert!(matches!(
        resp.status(),
        StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
    ));
    // GET /v1/zk/attachments/{id} with a placeholder id; signed request accepts 404 or 429.
    let request = fixtures::app_signed_request(
        torii.state.network_id_ref(),
        &account_id,
        &cfg.common.key_pair,
        fixtures::get_request(&("/v1/zk/attachments/placeholder-id")),
        &[],
    );
    let resp = app.router().oneshot(request).await.unwrap();
    assert!(matches!(
        resp.status(),
        StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST | StatusCode::TOO_MANY_REQUESTS
    ));
    app.shutdown().await;
}
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn zk_attachments_endpoints_report_unavailable_when_disabled() {
    let _guard = attachments_smoke_lock();
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.zk_attachments_enabled = false;
    let account_id = AccountId::new(cfg.common.key_pair.public_key().clone());
    let domain = Domain::new(DomainId::try_new("wonderland", "universal").expect("domain id"))
        .build(&account_id);
    let account = Account::new(account_id.clone()).build(&account_id);
    let torii = fixtures::StandardToriiHarness::new(&cfg, World::with([domain], [account], []));
    let app = attachment_router(&torii, &cfg);
    for request in [
        fixtures::get_request(&("/v1/zk/attachments")),
        fixtures::get_request(&("/v1/zk/attachments/count")),
        fixtures::get_request(&(format!("/v1/zk/attachments/{}", "0".repeat(64)))),
        Request::builder()
            .method("DELETE")
            .uri(format!("/v1/zk/attachments/{}", "0".repeat(64)))
            .body(axum::body::Body::empty())
            .unwrap(),
    ] {
        let request = fixtures::app_signed_request(
            torii.state.network_id_ref(),
            &account_id,
            &cfg.common.key_pair,
            request,
            &[],
        );
        let resp = fixtures::request(&app, request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
    app.shutdown().await;
}
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn zk_attachments_count_and_delete_endpoints_exposed_for_signed_requests() {
    let _guard = attachments_smoke_lock();
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.zk_attachments_enabled = true;
    let account_id = AccountId::new(cfg.common.key_pair.public_key().clone());
    let domain = Domain::new(DomainId::try_new("wonderland", "universal").expect("domain id"))
        .build(&account_id);
    let account = Account::new(account_id.clone()).build(&account_id);
    let torii = fixtures::StandardToriiHarness::new(&cfg, World::with([domain], [account], []));
    let app = attachment_router(&torii, &cfg);
    let count_request = fixtures::app_signed_request(
        torii.state.network_id_ref(),
        &account_id,
        &cfg.common.key_pair,
        fixtures::get_request(&("/v1/zk/attachments/count")),
        &[],
    );
    let count_resp = fixtures::request(&app, count_request).await.unwrap();
    assert_eq!(count_resp.status(), StatusCode::OK);
    let body = count_resp.into_body().collect().await.unwrap().to_bytes();
    let json: norito::json::Value = norito::json::from_slice(&body).expect("json count body");
    assert_eq!(json.get("count").and_then(|value| value.as_u64()), Some(0));
    let missing_id = "0".repeat(64);
    let delete_request = fixtures::app_signed_request(
        torii.state.network_id_ref(),
        &account_id,
        &cfg.common.key_pair,
        Request::builder()
            .method("DELETE")
            .uri(format!("/v1/zk/attachments/{missing_id}"))
            .body(axum::body::Body::empty())
            .unwrap(),
        &[],
    );
    let delete_resp = app.router().oneshot(delete_request).await.unwrap();
    let status = delete_resp.status();
    let body = delete_resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "{}",
        String::from_utf8_lossy(&body)
    );
    app.shutdown().await;
}
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn zk_attachments_create_roundtrip_and_replay_rejected_for_signed_requests() {
    let _guard = attachments_smoke_lock();
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.zk_attachments_enabled = true;
    cfg.torii.attachments_sanitizer_mode =
        iroha_config::parameters::actual::AttachmentSanitizerMode::InProcess;
    let account_id = AccountId::new(cfg.common.key_pair.public_key().clone());
    let domain = Domain::new(DomainId::try_new("wonderland", "universal").expect("domain id"))
        .build(&account_id);
    let account = Account::new(account_id.clone()).build(&account_id);
    let torii = fixtures::StandardToriiHarness::new(&cfg, World::with([domain], [account], []));
    let app = attachment_router(&torii, &cfg);
    let body = br#"{"backend":"demo","proof":{"bytes":[7,8,9]}}"#;
    let signed_request = fixtures::app_signed_request(
        torii.state.network_id_ref(),
        &account_id,
        &cfg.common.key_pair,
        fixtures::post_json_request(
            &("/v1/zk/attachments"),
            axum::body::Body::from(body.to_vec()),
        ),
        body,
    );
    let signed_headers = signed_request.headers().clone();
    let create_resp = fixtures::request(
        &app,
        request_with_headers("POST", "/v1/zk/attachments", &signed_headers, body),
    )
    .await
    .unwrap();
    assert_eq!(create_resp.status(), StatusCode::CREATED);
    let create_body = create_resp.into_body().collect().await.unwrap().to_bytes();
    let meta: norito::json::Value = norito::json::from_slice(&create_body).expect("json meta");
    let id = meta
        .get("id")
        .and_then(|value| value.as_str())
        .expect("attachment id")
        .to_owned();
    assert_eq!(
        meta.get("content_type").and_then(|value| value.as_str()),
        Some("application/json")
    );
    let replay_resp = fixtures::request(
        &app,
        request_with_headers("POST", "/v1/zk/attachments", &signed_headers, body),
    )
    .await
    .unwrap();
    assert_eq!(replay_resp.status(), StatusCode::FORBIDDEN);
    let replay_body = replay_resp.into_body().collect().await.unwrap().to_bytes();
    assert_error_message(
        &replay_body,
        "query_validation_failed",
        "nonce already used",
    );
    let get_request = fixtures::app_signed_request(
        torii.state.network_id_ref(),
        &account_id,
        &cfg.common.key_pair,
        fixtures::get_request(&(format!("/v1/zk/attachments/{id}"))),
        &[],
    );
    let get_resp = fixtures::request(&app, get_request).await.unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);
    assert!(
        get_resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/json")),
        "unexpected content type: {:?}",
        get_resp.headers().get(axum::http::header::CONTENT_TYPE)
    );
    let get_body = get_resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        String::from_utf8(get_body.to_vec()).unwrap(),
        std::str::from_utf8(body).unwrap()
    );
    let delete_request = fixtures::app_signed_request(
        torii.state.network_id_ref(),
        &account_id,
        &cfg.common.key_pair,
        Request::builder()
            .method("DELETE")
            .uri(format!("/v1/zk/attachments/{id}"))
            .body(axum::body::Body::empty())
            .unwrap(),
        &[],
    );
    let delete_resp = fixtures::request(&app, delete_request).await.unwrap();
    assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);
    let get_after_delete_request = fixtures::app_signed_request(
        torii.state.network_id_ref(),
        &account_id,
        &cfg.common.key_pair,
        fixtures::get_request(&(format!("/v1/zk/attachments/{id}"))),
        &[],
    );
    let get_after_delete_resp = app
        .router()
        .oneshot(get_after_delete_request)
        .await
        .unwrap();
    assert_eq!(get_after_delete_resp.status(), StatusCode::NOT_FOUND);
    app.shutdown().await;
}
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn zk_attachments_endpoints_require_signed_headers_when_enabled() {
    let _guard = attachments_smoke_lock();
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.zk_attachments_enabled = true;
    let torii = fixtures::StandardToriiHarness::new(&cfg, World::default());
    let app = attachment_router(&torii, &cfg);
    for request in [
        fixtures::get_request(&("/v1/zk/attachments")),
        fixtures::get_request(&("/v1/zk/attachments/count")),
        Request::builder()
            .method("DELETE")
            .uri(format!("/v1/zk/attachments/{}", "0".repeat(64)))
            .body(axum::body::Body::empty())
            .unwrap(),
    ] {
        let response = fixtures::request(&app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_error_message(
            &body,
            "canonical_authentication_required",
            "canonical account request authentication is required",
        );
    }
    app.shutdown().await;
}
