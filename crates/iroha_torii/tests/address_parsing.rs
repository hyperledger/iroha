#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Ensure Torii account endpoints accept canonical I105 account path segments.
#![cfg(all(feature = "app_api", feature = "telemetry"))]
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt as _;
use iroha_core::{kiso::KisoHandle, query::store::LiveQueryStore, state::World};
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::{
    account::{Account, AccountAddressErrorCode, AccountId},
    asset::AssetDefinition,
    domain::Domain,
};
use iroha_model_base::domain::DomainId;
use iroha_primitives::time::TimeSource;
use iroha_telemetry::metrics::Metrics;
use iroha_torii::{
    Torii,
    filter::{FieldPath, FilterExpr, ListQuery},
};
use norito::json;
use prometheus::core::Collector;
use std::sync::Arc;
use tower::ServiceExt as _;
use urlencoding::encode;
#[path = "fixtures.rs"]
mod fixtures;
const ACCOUNT_SIGNATORY: &str =
    "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245";
const I105_PREFIX: u16 = 0x002A;
const EMPTY_QUERY_ENVELOPE: &str = r#"{"limit": 1}"#;
const ACCOUNTS_TRANSACTIONS_CTX: &str = "/v1/accounts/{account_id}/transactions";
const ACCOUNTS_TRANSACTIONS_QUERY_CTX: &str = "/v1/accounts/{account_id}/transactions/query";
const ACCOUNTS_PERMISSIONS_CTX: &str = "/v1/accounts/{account_id}/permissions";
const ACCOUNTS_ASSETS_CTX: &str = "/v1/accounts/{account_id}/assets";
const ACCOUNTS_ASSETS_QUERY_CTX: &str = "/v1/accounts/{account_id}/assets/query";
const KAIGI_RELAY_DETAIL_CTX: &str = "/v1/kaigi/relays/{relay_id}";
const NEXUS_PUBLIC_LANE_STAKE_CTX: &str = "/v1/nexus/public-lanes/{lane_id}/stake";
const REPO_AGREEMENTS_ENDPOINT: &str = "/v1/repo/agreements";
fn query_envelope_with_account_filter(field: &str, literal: &str) -> Vec<u8> {
    let filter = FilterExpr::Eq(FieldPath(field.to_string()), json::Value::from(literal));
    let query = ListQuery::new().filter(filter).limit(1);
    norito::json::to_vec(&query.to_json_value()).expect("serialize collection query")
}
fn encode_query_value(value: &str) -> String {
    encode(value).into_owned()
}
#[tokio::test]
async fn transactions_endpoint_accepts_encoded_account_segments() {
    let app = test_router();
    for segment in accepted_account_segments() {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/accounts/{segment}/transactions"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                resp.status(),
                StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
            ),
            "unexpected status {} for segment {segment}",
            resp.status()
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn transactions_endpoint_rejects_invalid_account_segment() {
    let app = test_router();
    let literal = "not-an-i105@banka.dataspace";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/accounts/{literal}/transactions"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    app.shutdown().await;
}
#[tokio::test]
async fn transactions_endpoint_accepts_default_domain_without_suffix() {
    let app = test_router();
    for segment in accepted_default_domain_segments() {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/accounts/{segment}/transactions"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                resp.status(),
                StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
            ),
            "unexpected status {} for default-domain segment {segment}",
            resp.status()
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn transactions_query_accepts_default_domain_without_suffix() {
    let app = test_router();
    for segment in accepted_default_domain_segments() {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/accounts/{segment}/transactions/query"))
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(EMPTY_QUERY_ENVELOPE))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                resp.status(),
                StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
            ),
            "unexpected status {} for default-domain transactions/query segment {segment}",
            resp.status()
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn transactions_endpoint_rejects_public_key_segments() {
    let (app, metrics) = test_router_with_metrics();
    let literal = format!("{ACCOUNT_SIGNATORY}@banka.dataspace");
    let reason = AccountId::parse_encoded(&literal)
        .expect_err("public-key literal must fail to parse")
        .code_str();
    let counter = metrics
        .torii_address_invalid_total
        .with_label_values(&[ACCOUNTS_TRANSACTIONS_CTX, reason]);
    let before = counter.get();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/accounts/{literal}/transactions"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        counter.get(),
        before + 1,
        "public-key segments must increment invalid counter"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn invalid_account_segments_increment_metric() {
    let (app, metrics) = test_router_with_metrics();
    let literal = "sorabaddigest";
    let reason = AccountId::parse_encoded(literal)
        .expect_err("literal must fail to parse")
        .code_str();
    let before = metrics
        .torii_address_invalid_total
        .with_label_values(&[ACCOUNTS_TRANSACTIONS_CTX, reason])
        .get();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/accounts/{literal}/transactions"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let after = metrics
        .torii_address_invalid_total
        .with_label_values(&[ACCOUNTS_TRANSACTIONS_CTX, reason])
        .get();
    assert_eq!(
        after,
        before + 1,
        "torii_address_invalid_total delta mismatch"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn malformed_segments_increment_invalid_metric() {
    let (app, metrics) = test_router_with_metrics();
    let literal = "sn1short";
    let reason = AccountId::parse_encoded(literal)
        .expect_err("malformed literal must fail to parse")
        .code_str();
    let before_invalid = metrics
        .torii_address_invalid_total
        .with_label_values(&[ACCOUNTS_TRANSACTIONS_CTX, reason])
        .get();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/accounts/{literal}/transactions"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let after_invalid = metrics
        .torii_address_invalid_total
        .with_label_values(&[ACCOUNTS_TRANSACTIONS_CTX, reason])
        .get();
    assert_eq!(
        after_invalid,
        before_invalid + 1,
        "torii_address_invalid_total delta mismatch for malformed input"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn transactions_query_endpoint_accepts_encoded_account_segments() {
    let app = test_router();
    for segment in accepted_account_segments() {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/accounts/{segment}/transactions/query"))
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(EMPTY_QUERY_ENVELOPE))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                resp.status(),
                StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
            ),
            "unexpected status {} for transactions/query segment {segment}",
            resp.status()
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn transactions_query_endpoint_rejects_invalid_account_segment() {
    let app = test_router();
    let literal = "sorainvalid";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/accounts/{literal}/transactions/query"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(EMPTY_QUERY_ENVELOPE))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    app.shutdown().await;
}
#[tokio::test]
async fn transactions_query_invalid_segments_increment_metric() {
    let (app, metrics) = test_router_with_metrics();
    let literal = "sorabaddigest";
    let reason = AccountId::parse_encoded(literal)
        .expect_err("literal must fail to parse")
        .code_str();
    let before = metrics
        .torii_address_invalid_total
        .with_label_values(&[ACCOUNTS_TRANSACTIONS_QUERY_CTX, reason])
        .get();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/accounts/{literal}/transactions/query"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(EMPTY_QUERY_ENVELOPE))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let after = metrics
        .torii_address_invalid_total
        .with_label_values(&[ACCOUNTS_TRANSACTIONS_QUERY_CTX, reason])
        .get();
    assert_eq!(
        after,
        before + 1,
        "torii_address_invalid_total delta mismatch for transactions/query"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn transactions_query_rejects_checksum_mismatch() {
    let (app, metrics) = test_router_with_metrics();
    let bad_literal = tampered_tx_query_literal();
    let reason = AccountAddressErrorCode::ChecksumMismatch.as_str();
    let counter = metrics
        .torii_address_invalid_total
        .with_label_values(&[ACCOUNTS_TRANSACTIONS_QUERY_CTX, reason]);
    let before = counter.get();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/accounts/{bad_literal}/transactions/query"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(EMPTY_QUERY_ENVELOPE))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        counter.get(),
        before + 1,
        "checksum mismatches should increment invalid counter"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn transactions_query_placeholder_literal_rejected_without_shim() {
    let (app, metrics) = test_router_with_metrics();
    let literal = "ignored@banka.dataspace";
    let reason = AccountId::parse_encoded(literal)
        .expect_err("placeholder literal should fail checksum validation")
        .code_str();
    let counter = metrics
        .torii_address_invalid_total
        .with_label_values(&[ACCOUNTS_TRANSACTIONS_QUERY_CTX, reason]);
    let before = counter.get();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/accounts/{literal}/transactions/query"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(EMPTY_QUERY_ENVELOPE))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        counter.get(),
        before + 1,
        "placeholder literal should be treated as invalid"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn transactions_query_valid_literals_do_not_bump_invalid_metrics() {
    let (app, metrics) = test_router_with_metrics();
    let envelope =
        query_envelope_with_account_filter("authority", &fixtures::TX_QUERY_ACCOUNT.canonical);
    let before = counter_total(&metrics.torii_address_invalid_total);
    for segment in [fixtures::TX_QUERY_ACCOUNT.canonical.clone()] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/accounts/{segment}/transactions/query"))
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(envelope.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                resp.status(),
                StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
            ),
            "valid literal should not be rejected: segment={segment}, status={}",
            resp.status()
        );
    }
    let after = counter_total(&metrics.torii_address_invalid_total);
    assert_eq!(
        after, before,
        "valid tx query literals must not increment invalid counter"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn transactions_query_endpoint_rejects_public_key_segment() {
    let (app, metrics) = test_router_with_metrics();
    let literal = format!("{ACCOUNT_SIGNATORY}@banka.dataspace");
    let reason = AccountId::parse_encoded(&literal)
        .expect_err("public-key literal must fail to parse")
        .code_str();
    let counter = metrics
        .torii_address_invalid_total
        .with_label_values(&[ACCOUNTS_TRANSACTIONS_QUERY_CTX, reason]);
    let before = counter.get();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/accounts/{literal}/transactions/query"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(EMPTY_QUERY_ENVELOPE))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        counter.get(),
        before + 1,
        "public-key transactions/query segment must increment invalid counter"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn assets_endpoint_accepts_encoded_account_segments() {
    let app = test_router();
    for segment in accepted_account_segments() {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/accounts/{segment}/assets?limit=1"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                resp.status(),
                StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
            ),
            "unexpected status {} for assets segment {segment}",
            resp.status()
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn assets_endpoint_accepts_default_domain_without_suffix() {
    let app = test_router();
    for segment in accepted_default_domain_segments() {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/accounts/{segment}/assets?limit=1"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                resp.status(),
                StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
            ),
            "unexpected status {} for default-domain assets segment {segment}",
            resp.status()
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn assets_endpoint_rejects_invalid_segment() {
    let app = test_router();
    let literal = "sorainvalid";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/accounts/{literal}/assets?limit=1"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    app.shutdown().await;
}
#[tokio::test]
async fn assets_endpoint_invalid_segments_increment_metric() {
    let (app, metrics) = test_router_with_metrics();
    let literal = "sorabaddigest";
    let reason = AccountId::parse_encoded(literal)
        .expect_err("literal must fail to parse")
        .code_str();
    let before = metrics
        .torii_address_invalid_total
        .with_label_values(&[ACCOUNTS_ASSETS_CTX, reason])
        .get();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/accounts/{literal}/assets?limit=1"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let after = metrics
        .torii_address_invalid_total
        .with_label_values(&[ACCOUNTS_ASSETS_CTX, reason])
        .get();
    assert_eq!(
        after,
        before + 1,
        "torii_address_invalid_total delta mismatch for assets endpoint"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn assets_endpoint_rejects_public_key_segments() {
    let (app, metrics) = test_router_with_metrics();
    let literal = format!("{ACCOUNT_SIGNATORY}@banka.dataspace");
    let reason = AccountId::parse_encoded(&literal)
        .expect_err("public-key literal must fail to parse")
        .code_str();
    let counter = metrics
        .torii_address_invalid_total
        .with_label_values(&[ACCOUNTS_ASSETS_CTX, reason]);
    let before = counter.get();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/accounts/{literal}/assets?limit=1"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        counter.get(),
        before + 1,
        "public-key asset segments must increment invalid counter"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn assets_query_endpoint_accepts_encoded_account_segments() {
    let app = test_router();
    for segment in accepted_account_segments() {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/accounts/{segment}/assets/query"))
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(EMPTY_QUERY_ENVELOPE))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                resp.status(),
                StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
            ),
            "unexpected status {} for assets/query segment {segment}",
            resp.status()
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn assets_query_endpoint_invalid_segments_increment_metric() {
    let (app, metrics) = test_router_with_metrics();
    let literal = "sorabaddigest";
    let reason = AccountId::parse_encoded(literal)
        .expect_err("literal must fail to parse")
        .code_str();
    let before = metrics
        .torii_address_invalid_total
        .with_label_values(&[ACCOUNTS_ASSETS_QUERY_CTX, reason])
        .get();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/accounts/{literal}/assets/query"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(EMPTY_QUERY_ENVELOPE))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let after = metrics
        .torii_address_invalid_total
        .with_label_values(&[ACCOUNTS_ASSETS_QUERY_CTX, reason])
        .get();
    assert_eq!(
        after,
        before + 1,
        "torii_address_invalid_total delta mismatch for assets/query"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn assets_query_endpoint_rejects_public_key_segments() {
    let (app, metrics) = test_router_with_metrics();
    let literal = format!("{ACCOUNT_SIGNATORY}@banka.dataspace");
    let reason = AccountId::parse_encoded(&literal)
        .expect_err("public-key literal must fail to parse")
        .code_str();
    let counter = metrics
        .torii_address_invalid_total
        .with_label_values(&[ACCOUNTS_ASSETS_QUERY_CTX, reason]);
    let before = counter.get();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/accounts/{literal}/assets/query"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(EMPTY_QUERY_ENVELOPE))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        counter.get(),
        before + 1,
        "public-key assets/query segments must increment invalid counter"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn permissions_endpoint_accepts_encoded_account_segments() {
    let app = test_router();
    for segment in accepted_account_segments() {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/accounts/{segment}/permissions?limit=1"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                resp.status(),
                StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
            ),
            "unexpected status {} for permissions segment {segment}",
            resp.status()
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn permissions_endpoint_accepts_default_domain_without_suffix() {
    let app = test_router();
    for segment in accepted_default_domain_segments() {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/accounts/{segment}/permissions?limit=1"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                resp.status(),
                StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
            ),
            "unexpected status {} for default-domain permissions segment {segment}",
            resp.status()
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn permissions_endpoint_invalid_segments_increment_metric() {
    let (app, metrics) = test_router_with_metrics();
    let literal = "sorabaddigest";
    let reason = AccountId::parse_encoded(literal)
        .expect_err("literal must fail to parse")
        .code_str();
    let before = metrics
        .torii_address_invalid_total
        .with_label_values(&[ACCOUNTS_PERMISSIONS_CTX, reason])
        .get();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/accounts/{literal}/permissions?limit=1"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let after = metrics
        .torii_address_invalid_total
        .with_label_values(&[ACCOUNTS_PERMISSIONS_CTX, reason])
        .get();
    assert_eq!(
        after,
        before + 1,
        "torii_address_invalid_total delta mismatch for permissions endpoint"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn explorer_domains_query_accepts_encoded_account_params() {
    let app = test_router();
    for literal in accepted_account_segments() {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/explorer/domains?limit=1&filter={}",
                        encode_query_value(&format!("owned_by = \"{literal}\""))
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                resp.status(),
                StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
            ),
            "unexpected status {} for explorer domains owned_by literal {literal}",
            resp.status()
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn explorer_domains_query_invalid_account_param_records_metric() {
    let (app, metrics) = test_router_with_metrics();
    let literal = "sorainvalid";
    let reason = AccountId::parse_encoded(literal)
        .expect_err("literal must fail to parse")
        .code_str();
    let context = "/v1/explorer?filter";
    let before = metrics
        .torii_address_invalid_total
        .with_label_values(&[context, reason])
        .get();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/explorer/domains?limit=1&filter={}",
                    encode_query_value(&format!("owned_by = \"{literal}\""))
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let after = metrics
        .torii_address_invalid_total
        .with_label_values(&[context, reason])
        .get();
    assert_eq!(
        after,
        before + 1,
        "torii_address_invalid_total delta mismatch for explorer domains query"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn explorer_account_detail_accepts_encoded_account_segments() {
    let app = test_router();
    for literal in accepted_account_segments() {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/explorer/accounts/{literal}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                resp.status(),
                StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
            ),
            "unexpected status {} for explorer accounts literal {literal}",
            resp.status()
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn explorer_account_detail_invalid_segments_increment_metric() {
    let (app, metrics) = test_router_with_metrics();
    let literal = "sorainvalid";
    let reason = AccountId::parse_encoded(literal)
        .expect_err("literal must fail to parse")
        .code_str();
    let context = "/v1/explorer/accounts/{account_id}";
    let before = metrics
        .torii_address_invalid_total
        .with_label_values(&[context, reason])
        .get();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/explorer/accounts/{literal}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let after = metrics
        .torii_address_invalid_total
        .with_label_values(&[context, reason])
        .get();
    assert_eq!(
        after,
        before + 1,
        "torii_address_invalid_total delta mismatch for explorer account detail"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn explorer_account_qr_returns_svg_literal() {
    let app = test_router();
    let (canonical, _) = account_segments();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/explorer/accounts/{canonical}/qr"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    if resp.status() == StatusCode::TOO_MANY_REQUESTS {
        app.shutdown().await;
        return;
    }
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("qr response body")
        .to_bytes();
    let parsed: json::Value = json::from_slice(&body).expect("qr payload json");
    let literal = parsed
        .get("literal")
        .and_then(json::Value::as_str)
        .expect("literal field");
    assert_eq!(literal, canonical);
    let svg = parsed
        .get("svg")
        .and_then(json::Value::as_str)
        .expect("svg field");
    assert!(
        svg.trim_start().starts_with("<svg"),
        "qr response should include svg payload"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn repo_agreements_query_filter_accepts_encoded_literals() {
    let app = test_router();
    for literal in accepted_account_segments() {
        let body = query_envelope_with_account_filter("initiator", &literal);
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/repo/agreements/query")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                resp.status(),
                StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
            ),
            "unexpected status {} for initiator literal {literal}",
            resp.status()
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn repo_agreements_query_filter_accepts_default_domain_literals() {
    let app = test_router();
    for literal in accepted_default_domain_segments() {
        let body = query_envelope_with_account_filter("initiator", &literal);
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/repo/agreements/query")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                resp.status(),
                StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
            ),
            "unexpected status {} for default-domain initiator literal {literal}",
            resp.status()
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn repo_agreements_query_filter_rejects_invalid_literal() {
    let (app, metrics) = test_router_with_metrics();
    let literal = "sorabaddigest";
    let reason = AccountId::parse_encoded(literal)
        .expect_err("literal must fail")
        .code_str();
    let counter = metrics
        .torii_address_invalid_total
        .with_label_values(&[REPO_AGREEMENTS_ENDPOINT, reason]);
    let before = counter.get();
    let body = query_envelope_with_account_filter("initiator", literal);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/repo/agreements/query")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        counter.get(),
        before + 1,
        "invalid repo filter literal should increment torii_address_invalid_total"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn repo_agreements_query_filter_rejects_malformed_literal() {
    let (app, metrics) = test_router_with_metrics();
    let literal = "sn1short";
    let reason = AccountId::parse_encoded(literal)
        .expect_err("literal must fail")
        .code_str();
    let invalid_counter = metrics
        .torii_address_invalid_total
        .with_label_values(&[REPO_AGREEMENTS_ENDPOINT, reason]);
    let invalid_before = invalid_counter.get();
    let body = query_envelope_with_account_filter("initiator", literal);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/repo/agreements/query")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        invalid_counter.get(),
        invalid_before + 1,
        "invalid repo filter literal should increment torii_address_invalid_total"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_relay_detail_accepts_encoded_segments() {
    let (app, operator_key_pair) = test_router_with_operator_key();
    for literal in accepted_account_segments() {
        let request = Request::builder()
            .uri(format!("/v1/kaigi/relays/{literal}"))
            .body(Body::empty())
            .unwrap();
        let resp = app
            .clone()
            .oneshot(app.operator_signed_request(&operator_key_pair, request, &[]))
            .await
            .unwrap();
        assert!(
            matches!(
                resp.status(),
                StatusCode::NOT_FOUND | StatusCode::TOO_MANY_REQUESTS
            ),
            "expected kaigi relay detail to accept literal {literal}, got {}",
            resp.status()
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_relay_detail_rejects_invalid_segment() {
    let (app, operator_key_pair) = test_router_with_operator_key();
    let literal = "sorainvalid";
    let request = Request::builder()
        .uri(format!("/v1/kaigi/relays/{literal}"))
        .body(Body::empty())
        .unwrap();
    let resp = app
        .clone()
        .oneshot(app.operator_signed_request(&operator_key_pair, request, &[]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_relay_detail_invalid_segment_increments_metric() {
    let (app, metrics, operator_key_pair) = build_test_router();
    let literal = "sorainvalid";
    let reason = AccountId::parse_encoded(literal)
        .expect_err("literal must fail to parse")
        .code_str();
    let counter = metrics
        .torii_address_invalid_total
        .with_label_values(&[KAIGI_RELAY_DETAIL_CTX, reason]);
    let before = counter.get();
    let request = Request::builder()
        .uri(format!("/v1/kaigi/relays/{literal}"))
        .body(Body::empty())
        .unwrap();
    let resp = app
        .clone()
        .oneshot(app.operator_signed_request(&operator_key_pair, request, &[]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(counter.get(), before + 1);
    app.shutdown().await;
}
#[tokio::test]
async fn kaigi_relay_detail_malformed_segment_increments_invalid_metric() {
    let (app, metrics, operator_key_pair) = build_test_router();
    let literal = "sn1short";
    let reason = AccountId::parse_encoded(literal)
        .expect_err("literal must fail to parse")
        .code_str();
    let invalid_counter = metrics
        .torii_address_invalid_total
        .with_label_values(&[KAIGI_RELAY_DETAIL_CTX, reason]);
    let invalid_before = invalid_counter.get();
    let request = Request::builder()
        .uri(format!("/v1/kaigi/relays/{literal}"))
        .body(Body::empty())
        .unwrap();
    let resp = app
        .clone()
        .oneshot(app.operator_signed_request(&operator_key_pair, request, &[]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(invalid_counter.get(), invalid_before + 1);
    app.shutdown().await;
}
#[tokio::test]
async fn nexus_public_lane_stake_accepts_validator_literals() {
    let app = test_router();
    for literal in accepted_account_segments() {
        let encoded = encode_query_value(&literal);
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/nexus/public-lanes/0/stake?validator={encoded}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                resp.status(),
                StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
            ),
            "unexpected status {} for validator literal {literal}",
            resp.status()
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn nexus_public_lane_stake_rejects_invalid_validator_literal() {
    let app = test_router();
    let literal = "sorainvalid";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/nexus/public-lanes/0/stake?validator={literal}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    app.shutdown().await;
}
#[tokio::test]
async fn nexus_public_lane_stake_accepts_default_domain_validator_literals() {
    let app = test_router();
    for literal in accepted_default_domain_segments() {
        let encoded = encode_query_value(&literal);
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/nexus/public-lanes/0/stake?validator={encoded}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                resp.status(),
                StatusCode::OK | StatusCode::TOO_MANY_REQUESTS
            ),
            "unexpected status {} for default-domain validator literal {literal}",
            resp.status()
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn nexus_public_lane_stake_rejects_public_key_validator() {
    let (app, metrics) = test_router_with_metrics();
    let literal = format!("{ACCOUNT_SIGNATORY}@banka.dataspace");
    let encoded = encode_query_value(&literal);
    let reason = AccountId::parse_encoded(&literal)
        .expect_err("public-key literal must fail to parse")
        .code_str();
    let counter = metrics
        .torii_address_invalid_total
        .with_label_values(&[NEXUS_PUBLIC_LANE_STAKE_CTX, reason]);
    let before = counter.get();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/nexus/public-lanes/0/stake?validator={encoded}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        counter.get(),
        before + 1,
        "public-key validator literals must increment invalid counter"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn nexus_public_lane_stake_invalid_literal_increments_metric() {
    let (app, metrics) = test_router_with_metrics();
    let literal = "sorainvalid";
    let encoded = encode_query_value(literal);
    let reason = AccountId::parse_encoded(literal)
        .expect_err("literal must fail")
        .code_str();
    let counter = metrics
        .torii_address_invalid_total
        .with_label_values(&[NEXUS_PUBLIC_LANE_STAKE_CTX, reason]);
    let before = counter.get();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/nexus/public-lanes/0/stake?validator={encoded}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(counter.get(), before + 1);
    app.shutdown().await;
}
#[tokio::test]
async fn nexus_public_lane_stake_malformed_literal_increments_invalid_metric() {
    let (app, metrics) = test_router_with_metrics();
    let literal = "sn1short";
    let encoded = encode_query_value(literal);
    let reason = AccountId::parse_encoded(literal)
        .expect_err("literal must fail")
        .code_str();
    let invalid_counter = metrics
        .torii_address_invalid_total
        .with_label_values(&[NEXUS_PUBLIC_LANE_STAKE_CTX, reason]);
    let invalid_before = invalid_counter.get();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/nexus/public-lanes/0/stake?validator={encoded}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(invalid_counter.get(), invalid_before + 1);
    app.shutdown().await;
}
fn test_router() -> fixtures::CommittedToriiRouterRuntime {
    build_test_router().0
}
fn test_router_with_metrics() -> (fixtures::CommittedToriiRouterRuntime, Arc<Metrics>) {
    let (router, metrics, _operator_key_pair) = build_test_router();
    (router, metrics)
}
fn test_router_with_operator_key() -> (fixtures::CommittedToriiRouterRuntime, KeyPair) {
    let (router, _metrics, operator_key_pair) = build_test_router();
    (router, operator_key_pair)
}
fn build_test_router() -> (fixtures::CommittedToriiRouterRuntime, Arc<Metrics>, KeyPair) {
    use iroha_data_model::Registrable;
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain parses");
    let signatory: PublicKey = ACCOUNT_SIGNATORY.parse().expect("key parses");
    let account_id = AccountId::new(signatory);
    let account = Account::new(account_id.clone()).build(&account_id);
    let domain = Domain::new(domain_id).build(&account_id);
    let world = World::with([domain], [account], Vec::<AssetDefinition>::new());
    let native_chain = fixtures::commit_genesis_fixture(
        world,
        cfg.common.chain.clone(),
        &cfg.common.key_pair,
        Vec::new(),
        None,
        TimeSource::new_system(),
    );
    let state = native_chain.state().clone();
    let kura = native_chain.kura().clone();
    let network_id = native_chain.network_id();
    let local_peer_id = native_chain.validators()[0].0.clone();
    cfg.genesis.expected_hash = native_chain.genesis().hash();
    cfg.genesis.public_key = cfg.common.key_pair.public_key().clone();
    let (kiso, _child) = KisoHandle::start(cfg.clone());
    let queue_cfg = iroha_config::parameters::actual::Queue::default();
    let events_sender: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue = Arc::new(iroha_core::queue::Queue::from_config(
        queue_cfg,
        events_sender,
    ));
    let (peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let _ = peers_tx;
    let metrics = fixtures::reset_shared_metrics();
    let telemetry = {
        use iroha_core::telemetry as core_telemetry;
        let (_mh, ts) = TimeSource::new_mock(core::time::Duration::default());
        core_telemetry::start(
            Arc::clone(&metrics),
            state.clone(),
            kura.clone(),
            queue.clone(),
            peers_rx.clone(),
            local_peer_id.clone(),
            ts,
            true,
        )
        .expect("test telemetry resource registration")
        .0
    };
    let operator_key_pair = cfg.common.key_pair.clone();
    let da_receipt_signer = operator_key_pair.clone();
    let torii = Torii::new_with_handle(
        cfg.common.chain.clone(),
        network_id,
        kiso,
        cfg.torii.clone(),
        queue,
        tokio::sync::broadcast::channel(1).0,
        LiveQueryStore::start_test(),
        kura,
        state,
        da_receipt_signer,
        iroha_torii::OnlinePeersProvider::new(peers_rx),
        None,
        iroha_torii::ToriiRuntimeDeps::new(
            build_identity_test_fixture::build_identity(),
            iroha_torii::MaybeTelemetry::from_profile(
                Some(telemetry),
                iroha_config::parameters::actual::TelemetryProfile::Operator,
            ),
        ),
    )
    .expect("valid Torii address-parsing fixture")
    .with_local_peer_id(local_peer_id);
    (
        fixtures::CommittedToriiRouterRuntime::new(
            torii
                .api_router_for_tests()
                .expect("test Torii router initializes"),
            native_chain,
        ),
        metrics,
        operator_key_pair,
    )
}
#[tokio::test]
async fn address_parsing_fixture_has_applied_global_root_authority() {
    use iroha_core::state::StateReadOnly as _;
    let app = test_router();
    assert_eq!(app.state().view().height(), 1);
    assert_eq!(
        iroha_core::sumeragi::lanes::routing::committed_root_scope(app.state().view().world()),
        Some(iroha_data_model::block::consensus::SumeragiRootScope::Global),
    );
    app.shutdown().await;
}
fn account_segments() -> (String, String) {
    use iroha_crypto::PublicKey;
    use iroha_data_model::account::{AccountAddress, AccountId};
    let public_key: PublicKey = ACCOUNT_SIGNATORY.parse().expect("key parses");
    let account = AccountId::new(public_key);
    let address = AccountAddress::from_account_id(&account).expect("address encode");
    let canonical = account.to_string();
    let i105 = address.to_i105().expect("i105 encode");
    (canonical, i105)
}
fn accepted_account_segments() -> [String; 1] {
    [account_segments().0]
}
fn default_domain_segments_without_domain() -> (String, String) {
    use iroha_crypto::PublicKey;
    use iroha_data_model::account::{AccountAddress, AccountId};
    let public_key: PublicKey = ACCOUNT_SIGNATORY.parse().expect("key parses");
    let account = AccountId::new(public_key);
    let address = AccountAddress::from_account_id(&account).expect("address encode");
    let canonical = account.to_string();
    let i105 = address
        .to_i105_for_discriminant(I105_PREFIX)
        .expect("i105 encode");
    (canonical, i105)
}
fn accepted_default_domain_segments() -> [String; 1] {
    [default_domain_segments_without_domain().0]
}
fn tampered_tx_query_literal() -> String {
    let mut mutated = fixtures::TX_QUERY_ACCOUNT.canonical.clone();
    let last = mutated.pop().unwrap_or('0');
    let replacement = if last == 'a' { 'b' } else { 'a' };
    mutated.push(replacement);
    mutated
}
fn counter_total(counter: &prometheus::IntCounterVec) -> u64 {
    counter
        .collect()
        .iter()
        .flat_map(prometheus::proto::MetricFamily::get_metric)
        .map(|metric| {
            let value = metric.get_counter().get_value();
            let rounded = value.round();
            assert!(
                rounded.is_finite() && rounded >= 0.0,
                "counter value must be finite and non-negative: {value}"
            );
            rounded
                .to_string()
                .parse::<u64>()
                .unwrap_or_else(|_| panic!("counter value {value} must be integral"))
        })
        .sum()
}

#[path = "../src/build_identity_test_fixture.rs"]
mod build_identity_test_fixture;
