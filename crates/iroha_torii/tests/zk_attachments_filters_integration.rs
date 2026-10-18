//! Integration tests for /v1/zk/attachments filters and count.
#![cfg(all(feature = "app_api", feature = "ws_integration_tests"))]
#![allow(
    unexpected_cfgs,
    clippy::too_many_lines,
    clippy::needless_borrows_for_generic_args,
    clippy::uninlined_format_args
)]
#![allow(clippy::redundant_closure_for_method_calls)]
use axum::{Router, response::IntoResponse, routing::get};
use http_body_util::BodyExt as _;
use std::sync::Once;
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
            8 * 1024 * 1024,
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
async fn attachments_list_filters_and_count() {
    let _data_dir = iroha_torii::test_utils::TestDataDirGuard::new();
    ensure_quota_config();
    iroha_torii::zk_attachments::init_persistence().expect("attachment persistence preflight");
    let tenant = iroha_torii::zk_attachments::AttachmentTenant::anonymous();
    let app = Router::new()
        .route(
            "/v1/zk/attachments",
            get({
                let tenant = tenant.clone();
                move |_headers: axum::http::HeaderMap,
                      q: iroha_torii::NoritoQuery<
                    iroha_torii::zk_attachments::AttachmentListQuery,
                >| async move {
                    iroha_torii::zk_attachments::handle_list_attachments_filtered(tenant.clone(), q)
                        .await
                }
            }),
        )
        .route(
            "/v1/zk/attachments/count",
            get({
                let tenant = tenant.clone();
                move |q: iroha_torii::NoritoQuery<
                    iroha_torii::zk_attachments::AttachmentListQuery,
                >| async move {
                    iroha_torii::zk_attachments::handle_count_attachments(tenant.clone(), q).await
                }
            }),
        );
    // Seed two different attachments by calling POST handler directly
    let id1 = {
        let body_value = iroha_torii::json_object(vec![("k", 1u64)]);
        let body = norito::json::to_string(&body_value).expect("serialize attachment seed");
        let resp = iroha_torii::zk_attachments::handle_post_attachment(
            tenant.clone(),
            {
                let mut h = axum::http::HeaderMap::new();
                h.insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/json"),
                );
                h
            },
            axum::body::Bytes::from(body),
        )
        .await
        .into_response();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let meta: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
        meta.get("id").and_then(|v| v.as_str()).unwrap().to_string()
    };
    let id2 = {
        let body = vec![0u8, 1, 2, 3];
        let resp = iroha_torii::zk_attachments::handle_post_attachment(
            tenant.clone(),
            {
                let mut h = axum::http::HeaderMap::new();
                h.insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/octet-stream"),
                );
                h
            },
            axum::body::Bytes::from(body),
        )
        .await
        .into_response();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let meta: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
        meta.get("id").and_then(|v| v.as_str()).unwrap().to_string()
    };
    // Seed a ZK1 envelope attachment (Norito) with PROF tag
    let id3 = {
        let mut env = Vec::new();
        env.extend_from_slice(b"ZK1\0");
        // TLV: tag=PROF, len=3, payload=[7,7,7]
        env.extend_from_slice(b"PROF");
        env.extend_from_slice(&(3u32).to_le_bytes());
        env.extend_from_slice(&[7u8, 7, 7]);
        let resp = iroha_torii::zk_attachments::handle_post_attachment(
            tenant.clone(),
            {
                let mut h = axum::http::HeaderMap::new();
                h.insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/x-zk1"),
                );
                h
            },
            axum::body::Bytes::from(env),
        )
        .await
        .into_response();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let meta: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
        meta.get("id").and_then(|v| v.as_str()).unwrap().to_string()
    };
    // List with content_type filter json
    let req = http::Request::builder()
        .method("GET")
        .uri("/v1/zk/attachments?content_type=application/json&ids_only=true")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let arr: Vec<String> =
        norito::json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0], id1);
    // Count all
    let req2 = http::Request::builder()
        .method("GET")
        .uri("/v1/zk/attachments/count")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), http::StatusCode::OK);
    let v: norito::json::Value =
        norito::json::from_slice(&resp2.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(v.get("count").and_then(|x| x.as_u64()), Some(3));
    // Count one by id
    let req3 = http::Request::builder()
        .method("GET")
        .uri(&format!("/v1/zk/attachments/count?id={id2}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp3 = app.clone().oneshot(req3).await.unwrap();
    assert_eq!(resp3.status(), http::StatusCode::OK);
    let v3: norito::json::Value =
        norito::json::from_slice(&resp3.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(v3.get("count").and_then(|x| x.as_u64()), Some(1));
    // List has_tag=PROF (should return only ZK1 envelope id)
    let req4 = http::Request::builder()
        .method("GET")
        .uri("/v1/zk/attachments?has_tag=PROF&ids_only=true")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp4 = app.clone().oneshot(req4).await.unwrap();
    assert_eq!(resp4.status(), http::StatusCode::OK);
    let ids_only: Vec<String> =
        norito::json::from_slice(&resp4.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(ids_only, vec![id3]);
}
