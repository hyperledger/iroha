//! Integration tests for /v1/zk/attachments endpoints (`app_api`).
#![cfg(all(feature = "app_api", feature = "ws_integration_tests"))]
#![allow(unexpected_cfgs)]
use axum::{
    Router,
    response::IntoResponse,
    routing::{get, post},
};
use http_body_util::BodyExt as _;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use std::{convert::TryFrom, sync::Once};
use tower::ServiceExt as _;
fn ensure_quota_config() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let mut allowed =
            iroha_config::parameters::defaults::torii::attachments_allowed_mime_types();
        allowed.push("application/octet-stream".to_string());
        iroha_torii::zk_attachments::configure(
            iroha_config::parameters::defaults::torii::ATTACHMENTS_TTL_SECS,
            iroha_config::parameters::defaults::torii::ATTACHMENTS_MAX_BYTES,
            iroha_config::parameters::defaults::torii::ATTACHMENTS_PER_TENANT_MAX_COUNT,
            8 * 1024 * 1024, // tighten per-tenant bytes to keep tests lightweight
            iroha_config::parameters::defaults::torii::ATTACHMENTS_GLOBAL_MAX_COUNT,
            iroha_config::parameters::defaults::torii::ATTACHMENTS_GLOBAL_MAX_BYTES,
            allowed,
            iroha_config::parameters::defaults::torii::ATTACHMENTS_MAX_EXPANDED_BYTES,
            iroha_config::parameters::defaults::torii::ATTACHMENTS_MAX_ARCHIVE_DEPTH,
            iroha_config::parameters::actual::AttachmentSanitizerMode::InProcess,
            iroha_config::parameters::defaults::torii::ATTACHMENTS_SANITIZE_TIMEOUT_MS,
            None,
            iroha_torii::MaybeTelemetry::disabled(),
        );
    });
}
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn attachments_post_get_list_delete_roundtrip() {
    // Use a temp dir for persistence
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    ensure_quota_config();
    iroha_torii::zk_attachments::init_persistence().expect("attachment persistence preflight");
    // Account-specific uploads should hash tenant identity and remain distinct.
    let tenant_token_a = iroha_torii::zk_attachments::AttachmentTenant::from_account(&ALICE_ID);
    let meta_token_a: norito::json::Value = {
        let resp = iroha_torii::zk_attachments::handle_post_attachment(
            tenant_token_a.clone(),
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from_static(b"token-a"),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), http::StatusCode::CREATED);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        norito::json::from_slice(&bytes).unwrap()
    };
    let tenant_token_b = iroha_torii::zk_attachments::AttachmentTenant::from_account(&BOB_ID);
    let meta_token_b: norito::json::Value = {
        let resp = iroha_torii::zk_attachments::handle_post_attachment(
            tenant_token_b.clone(),
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from_static(b"token-b"),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), http::StatusCode::CREATED);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        norito::json::from_slice(&bytes).unwrap()
    };
    let tenant_a = meta_token_a
        .get("tenant")
        .and_then(norito::json::Value::as_str)
        .expect("tenant field present");
    let tenant_b = meta_token_b
        .get("tenant")
        .and_then(norito::json::Value::as_str)
        .expect("tenant field present");
    assert_eq!(tenant_a, tenant_token_a.as_str());
    assert_eq!(tenant_b, tenant_token_b.as_str());
    assert_ne!(tenant_a, tenant_b);
    // Cleanup account-scoped attachments so quota tests operate on a clean slate.
    let id_a = meta_token_a
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let id_b = meta_token_b
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    // Cross-tenant access should be denied by storage isolation.
    let wrong_get = iroha_torii::zk_attachments::handle_get_attachment(
        tenant_token_b.clone(),
        axum::extract::Path(id_a.clone()),
    )
    .await
    .into_response();
    assert_eq!(wrong_get.status(), http::StatusCode::NOT_FOUND);
    let wrong_del = iroha_torii::zk_attachments::handle_delete_attachment(
        tenant_token_b.clone(),
        axum::extract::Path(id_a.clone()),
    )
    .await
    .into_response();
    assert_eq!(wrong_del.status(), http::StatusCode::NOT_FOUND);
    let _ = iroha_torii::zk_attachments::handle_delete_attachment(
        tenant_token_a.clone(),
        axum::extract::Path(id_a),
    )
    .await
    .into_response();
    let _ = iroha_torii::zk_attachments::handle_delete_attachment(
        tenant_token_b.clone(),
        axum::extract::Path(id_b),
    )
    .await
    .into_response();
    // Router with attachments handlers
    let anon_tenant = iroha_torii::zk_attachments::AttachmentTenant::anonymous();
    let app = Router::new()
        .route(
            "/v1/zk/attachments",
            post({
                let anon_tenant = anon_tenant.clone();
                move |headers: axum::http::HeaderMap, body: axum::body::Bytes| async move {
                    let tenant = anon_tenant.clone();
                    Ok::<_, iroha_torii::Error>(
                        iroha_torii::zk_attachments::handle_post_attachment(tenant, headers, body)
                            .await,
                    )
                }
            })
            .get({
                let anon_tenant = anon_tenant.clone();
                move || async move {
                    Ok::<_, iroha_torii::Error>(
                        iroha_torii::zk_attachments::handle_list_attachments(anon_tenant.clone())
                            .await,
                    )
                }
            }),
        )
        .route(
            "/v1/zk/attachments/{id}",
            get({
                let anon_tenant = anon_tenant.clone();
                move |id: axum::extract::Path<String>| async move {
                    Ok::<_, iroha_torii::Error>(
                        iroha_torii::zk_attachments::handle_get_attachment(anon_tenant.clone(), id)
                            .await,
                    )
                }
            })
            .delete({
                let anon_tenant = anon_tenant.clone();
                move |id: axum::extract::Path<String>| async move {
                    Ok::<_, iroha_torii::Error>(
                        iroha_torii::zk_attachments::handle_delete_attachment(
                            anon_tenant.clone(),
                            id,
                        )
                        .await,
                    )
                }
            }),
        );
    // POST JSON attachment
    let body_json_value = iroha_torii::json_object(vec![
        iroha_torii::json_entry("backend", "demo"),
        iroha_torii::json_entry(
            "proof",
            iroha_torii::json_object(vec![iroha_torii::json_entry("bytes", vec![7u8, 8u8, 9u8])]),
        ),
    ]);
    let body_json = norito::json::to_string(&body_json_value).expect("serialize attachment json");
    let req_post = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/attachments")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body_json.clone()))
        .unwrap();
    let resp_post = app.clone().oneshot(req_post).await.unwrap();
    assert_eq!(resp_post.status(), http::StatusCode::CREATED);
    let bytes = resp_post.into_body().collect().await.unwrap().to_bytes();
    let meta: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    let id = meta.get("id").and_then(|v| v.as_str()).unwrap().to_string();
    // GET by id
    let req_get = http::Request::builder()
        .method("GET")
        .uri(format!("/v1/zk/attachments/{id}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp_get = app.clone().oneshot(req_get).await.unwrap();
    assert_eq!(resp_get.status(), http::StatusCode::OK);
    assert_eq!(
        resp_get
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap(),
        "application/json"
    );
    let got_body = resp_get.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(String::from_utf8(got_body.to_vec()).unwrap(), body_json);
    // LIST
    let req_list = http::Request::builder()
        .method("GET")
        .uri("/v1/zk/attachments")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp_list = app.clone().oneshot(req_list).await.unwrap();
    assert_eq!(resp_list.status(), http::StatusCode::OK);
    let list_bytes = resp_list.into_body().collect().await.unwrap().to_bytes();
    let arr: Vec<norito::json::Value> = norito::json::from_slice(&list_bytes).unwrap();
    assert!(
        arr.iter()
            .any(|m| m.get("id").and_then(|v| v.as_str()) == Some(&id))
    );
    // DELETE
    let req_del = http::Request::builder()
        .method("DELETE")
        .uri(format!("/v1/zk/attachments/{id}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp_del = app.clone().oneshot(req_del).await.unwrap();
    assert_eq!(resp_del.status(), http::StatusCode::NO_CONTENT);
    // GET after delete -> 404
    let req_get2 = http::Request::builder()
        .method("GET")
        .uri(format!("/v1/zk/attachments/{id}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp_get2 = app.clone().oneshot(req_get2).await.unwrap();
    assert_eq!(resp_get2.status(), http::StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn attachments_enforce_per_tenant_quota() {
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    ensure_quota_config();
    iroha_torii::zk_attachments::init_persistence().expect("attachment persistence preflight");
    // Seed enough attachments to exceed the per-tenant count limit (default 128)
    let mut ids = Vec::new();
    for i in 0..130u32 {
        let resp = iroha_torii::zk_attachments::handle_post_attachment(
            iroha_torii::zk_attachments::AttachmentTenant::anonymous(),
            {
                let mut h = axum::http::HeaderMap::new();
                h.insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/octet-stream"),
                );
                h
            },
            axum::body::Bytes::from(vec![u8::try_from(i).expect("attachment byte fits")]),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), http::StatusCode::CREATED);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let meta: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
        ids.push(meta.get("id").and_then(|v| v.as_str()).unwrap().to_string());
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    // Oldest entries should have been evicted (count capped at 128)
    let list_resp = iroha_torii::zk_attachments::handle_list_attachments(
        iroha_torii::zk_attachments::AttachmentTenant::anonymous(),
    )
    .await
    .into_response();
    let metas_bytes = list_resp.into_body().collect().await.unwrap().to_bytes();
    let metas: Vec<iroha_torii::zk_attachments::AttachmentMeta> =
        norito::json::from_slice(&metas_bytes).unwrap();
    assert_eq!(metas.len(), 128);
    // Ensure the two oldest ids are gone and the rest remain
    assert!(!metas.iter().any(|m| m.id == ids[0] || m.id == ids[1]));
    assert!(metas.iter().any(|m| m.id == ids[2]));
    assert!(metas.iter().any(|m| m.id == *ids.last().unwrap()));
    // Exceed the per-tenant byte ceiling (8 MiB) with 1 MiB chunks
    let mut large_ids = Vec::new();
    for i in 0..10u32 {
        let resp = iroha_torii::zk_attachments::handle_post_attachment(
            iroha_torii::zk_attachments::AttachmentTenant::anonymous(),
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from(vec![
                u8::try_from(i).expect("attachment byte fits");
                1 << 20
            ]),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), http::StatusCode::CREATED);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let meta: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
        large_ids.push(meta.get("id").and_then(|v| v.as_str()).unwrap().to_string());
    }
    let metas_bytes = iroha_torii::zk_attachments::handle_list_attachments(
        iroha_torii::zk_attachments::AttachmentTenant::anonymous(),
    )
    .await
    .into_response()
    .into_body()
    .collect()
    .await
    .unwrap()
    .to_bytes();
    let metas: Vec<iroha_torii::zk_attachments::AttachmentMeta> =
        norito::json::from_slice(&metas_bytes).unwrap();
    // Aggregated history should keep the most recent ~8 entries of 1 MiB each
    assert!(metas.len() <= 8);
    let total_bytes: u64 = metas.iter().map(|m| m.size).sum();
    assert!(total_bytes <= 8 * 1024 * 1024);
    // Earliest two large attachments evicted
    assert!(
        !metas
            .iter()
            .any(|m| m.id == large_ids[0] || m.id == large_ids[1])
    );
    assert!(metas.iter().any(|m| m.id == *large_ids.last().unwrap()));
}
