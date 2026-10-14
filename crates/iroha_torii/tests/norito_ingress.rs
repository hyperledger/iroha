//! Tests covering Norito-RPC ingress policies and Content-Type enforcement.

#![cfg(feature = "app_api")]
#[path = "common/norito_rpc_harness.rs"]
mod norito_rpc_harness;
use axum::http::{StatusCode, header::RETRY_AFTER};
use iroha_config::parameters::actual::NoritoRpcStage;
use iroha_torii_shared::{ErrorEnvelope, route_catalog};
use norito_rpc_harness::NoritoRpcHarness;
const ERROR_HEADER: &str = "x-iroha-error-code";
fn default_alias_policy() -> sorafs_manifest::alias_cache::AliasCachePolicy {
    sorafs_manifest::alias_cache::AliasCachePolicy::new(
        std::time::Duration::from_secs(
            iroha_service_model::sorafs::DEFAULT_ALIAS_POSITIVE_TTL_SECS,
        ),
        std::time::Duration::from_secs(
            iroha_service_model::sorafs::DEFAULT_ALIAS_REFRESH_WINDOW_SECS,
        ),
        std::time::Duration::from_secs(iroha_service_model::sorafs::DEFAULT_ALIAS_HARD_EXPIRY_SECS),
        std::time::Duration::from_secs(
            iroha_service_model::sorafs::DEFAULT_ALIAS_NEGATIVE_TTL_SECS,
        ),
        std::time::Duration::from_secs(
            iroha_service_model::sorafs::DEFAULT_ALIAS_REVOCATION_TTL_SECS,
        ),
        std::time::Duration::from_secs(
            iroha_service_model::sorafs::DEFAULT_ALIAS_ROTATION_MAX_AGE_SECS,
        ),
        std::time::Duration::from_secs(
            iroha_service_model::sorafs::DEFAULT_ALIAS_SUCCESSOR_GRACE_SECS,
        ),
        std::time::Duration::from_secs(
            iroha_service_model::sorafs::DEFAULT_ALIAS_GOVERNANCE_GRACE_SECS,
        ),
    )
}
async fn post_ga_norito(path: &str, body: impl Into<axum::body::Body>) -> axum::response::Response {
    use axum::http::{Request, header::CONTENT_TYPE};
    use tower::ServiceExt as _;
    let harness = NoritoRpcHarness::new(|cfg| {
        cfg.torii.transport.norito_rpc.stage = NoritoRpcStage::Ga;
    });
    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(CONTENT_TYPE, "application/x-norito")
                .extension(norito_rpc_harness::loopback_connect_info())
                .body(body.into())
                .expect("request"),
        )
        .await
        .expect("response");
    harness.shutdown().await;
    response
}
async fn response_text(resp: axum::response::Response) -> String {
    use http_body_util::BodyExt;
    let body = BodyExt::collect(resp.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    String::from_utf8(body.to_vec()).expect("response text")
}
async fn response_error_envelope(resp: axum::response::Response) -> ErrorEnvelope {
    use http_body_util::BodyExt;
    let body = BodyExt::collect(resp.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    norito::decode_from_bytes(&body).expect("decode error envelope")
}
fn checked_norito_ingress_client_fixture() -> iroha_crypto::KeyPair {
    iroha_crypto::KeyPair::try_random()
        .expect("generate checked Norito ingress client fixture keypair")
}
#[test]
fn norito_ingress_client_fixture_uses_checked_ed25519_key_generation() {
    let key_pair = checked_norito_ingress_client_fixture();
    let algorithm = key_pair
        .public_key()
        .try_algorithm()
        .expect("fixture Norito ingress client public key has a valid algorithm");
    assert_eq!(algorithm, iroha_crypto::Algorithm::Ed25519);
}
#[tokio::test]
async fn removed_unversioned_norito_routes_are_not_registered() {
    for path in [
        "/transaction",
        "/transaction/entrypoint",
        "/transactions/batch",
        "/query",
    ] {
        let resp = post_ga_norito(path, Vec::new()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "path {path}");
    }
}
fn assert_versioned_decode_rejection_without_panic(text: &str) {
    assert!(
        text.contains("Could not decode versioned request"),
        "unexpected error body: {text}"
    );
    assert!(
        !text.contains("panic during decode"),
        "unexpected decode panic response: {text}"
    );
}
fn assert_transaction_decode_rejection_without_panic(envelope: &ErrorEnvelope) {
    assert_eq!(envelope.code(), "invalid_transaction_payload");
    assert!(
        envelope
            .message()
            .contains("transaction payload could not be decoded"),
        "unexpected error envelope: {envelope:?}"
    );
    assert!(
        !envelope.message().contains("panic during decode"),
        "unexpected decode panic response: {}",
        envelope.message()
    );
}
#[tokio::test]
async fn missing_content_type_is_rejected() {
    let harness = NoritoRpcHarness::new(|cfg| {
        cfg.torii.transport.norito_rpc.stage = NoritoRpcStage::Ga;
    });
    let resp = harness.post_transaction(false, &[]).await;
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    harness.shutdown().await;
}
#[tokio::test]
async fn disabled_stage_blocks_norito_requests() {
    let harness = NoritoRpcHarness::new(|cfg| {
        cfg.torii.transport.norito_rpc.stage = NoritoRpcStage::Disabled;
    });
    let resp = harness.post_transaction(true, &[]).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        resp.headers()
            .get(ERROR_HEADER)
            .map(|v| v.to_str().unwrap()),
        Some("norito_rpc_disabled")
    );
    assert_eq!(
        resp.headers().get(RETRY_AFTER).map(|v| v.to_str().unwrap()),
        Some("300")
    );
    harness.shutdown().await;
}
#[tokio::test]
async fn canary_stage_enforces_allowlist() {
    let allowlist_token = "norito-canary";
    let harness = NoritoRpcHarness::new(|cfg| {
        cfg.torii.transport.norito_rpc.stage = NoritoRpcStage::Canary;
        cfg.torii.transport.norito_rpc.allowed_clients = vec![allowlist_token.to_string()];
    });
    let denied = harness.post_transaction(true, &[]).await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        denied
            .headers()
            .get(ERROR_HEADER)
            .map(|v| v.to_str().unwrap()),
        Some("norito_rpc_canary_denied")
    );
    assert_eq!(
        denied
            .headers()
            .get(RETRY_AFTER)
            .map(|v| v.to_str().unwrap()),
        Some("300")
    );
    let allowed = harness
        .post_transaction(true, &[("x-api-token", allowlist_token)])
        .await;
    assert_ne!(allowed.status(), StatusCode::FORBIDDEN);
    assert!(allowed.headers().get(ERROR_HEADER).is_none());
    harness.shutdown().await;
}
#[tokio::test]
async fn norito_transaction_returns_submission_receipt() {
    use axum::body::Body;
    use axum::http::{Request, header::CONTENT_TYPE};
    use http_body_util::BodyExt;
    use iroha_data_model::transaction::{SignedTransaction, TransactionSubmissionReceipt};
    use iroha_version::codec::DecodeVersioned as _;
    use tower::ServiceExt as _;
    let harness = NoritoRpcHarness::new(|cfg| {
        cfg.torii.transport.norito_rpc.stage = NoritoRpcStage::Ga;
    });
    let tx_bytes = norito_rpc_harness::sample_transaction_bytes();
    let tx = SignedTransaction::decode_all_versioned(&tx_bytes).expect("decode transaction");
    let expected_hash = tx.hash();
    let resp = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(route_catalog::pipeline::TRANSACTION.path())
                .header(CONTENT_TYPE, "application/x-norito")
                .extension(norito_rpc_harness::loopback_connect_info())
                .body(Body::from(tx_bytes))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = BodyExt::collect(resp.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    let receipt: TransactionSubmissionReceipt =
        norito::decode_from_bytes(&body).expect("decode receipt");
    assert!(receipt.verify().is_ok());
    assert_eq!(
        receipt.payload.entrypoint_hash,
        iroha_core::tx::external_entrypoint_hash_from_signed_hash(expected_hash)
    );
    assert_eq!(receipt.payload.signed_transaction_hash, Some(expected_hash));
    assert_eq!(
        receipt.payload.signer,
        harness.cfg.common.key_pair.public_key().clone()
    );
    harness.shutdown().await;
}
#[tokio::test]
async fn norito_transaction_rejects_invalid_signature_without_decode_panic() {
    use axum::body::Body;
    use axum::http::{Request, header::CONTENT_TYPE};
    use http_body_util::BodyExt;
    use iroha_core::tx::SignatureRejectionCode;
    use tower::ServiceExt as _;
    let harness = NoritoRpcHarness::new(|cfg| {
        cfg.torii.transport.norito_rpc.stage = NoritoRpcStage::Ga;
    });
    let resp = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(route_catalog::pipeline::TRANSACTION.path())
                .header(CONTENT_TYPE, "application/x-norito")
                .extension(norito_rpc_harness::loopback_connect_info())
                .body(Body::from(
                    norito_rpc_harness::sample_invalid_signature_transaction_bytes(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some(SignatureRejectionCode::InvalidSignature.as_str())
    );
    let body = BodyExt::collect(resp.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    let envelope: ErrorEnvelope = norito::decode_from_bytes(&body).expect("decode error envelope");
    assert_eq!(
        envelope.code(),
        SignatureRejectionCode::InvalidSignature.as_str()
    );
    assert!(envelope.message().contains("failed to accept transaction"));
    assert!(
        !envelope.message().contains("panic during decode"),
        "unexpected decode panic response: {}",
        envelope.message()
    );
    harness.shutdown().await;
}
#[tokio::test]
async fn public_transaction_route_rejects_internal_entrypoint_payload() {
    use axum::body::Body;
    use axum::http::{Request, header::CONTENT_TYPE};
    use tower::ServiceExt as _;
    let harness = NoritoRpcHarness::new(|cfg| {
        cfg.torii.transport.norito_rpc.stage = NoritoRpcStage::Ga;
    });
    let resp = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(route_catalog::pipeline::TRANSACTION.path())
                .header(CONTENT_TYPE, "application/x-norito")
                .extension(norito_rpc_harness::loopback_connect_info())
                .body(Body::from(
                    norito_rpc_harness::sample_transaction_entrypoint_bytes(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let envelope = response_error_envelope(resp).await;
    assert_transaction_decode_rejection_without_panic(&envelope);
    harness.shutdown().await;
}
#[tokio::test]
async fn public_transaction_route_rejects_bare_signed_transaction_payload() {
    use axum::body::Body;
    use axum::http::{Request, header::CONTENT_TYPE};
    use tower::ServiceExt as _;
    let harness = NoritoRpcHarness::new(|cfg| {
        cfg.torii.transport.norito_rpc.stage = NoritoRpcStage::Ga;
    });
    let resp = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(route_catalog::pipeline::TRANSACTION.path())
                .header(CONTENT_TYPE, "application/x-norito")
                .extension(norito_rpc_harness::loopback_connect_info())
                .body(Body::from(
                    norito_rpc_harness::sample_bare_transaction_bytes(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let envelope = response_error_envelope(resp).await;
    assert_transaction_decode_rejection_without_panic(&envelope);
    harness.shutdown().await;
}
#[tokio::test]
async fn public_transaction_route_rejects_unsupported_version_without_decode_panic() {
    use axum::body::Body;
    use axum::http::{Request, header::CONTENT_TYPE};
    use tower::ServiceExt as _;
    let harness = NoritoRpcHarness::new(|cfg| {
        cfg.torii.transport.norito_rpc.stage = NoritoRpcStage::Ga;
    });
    let mut bytes = norito_rpc_harness::sample_transaction_bytes();
    bytes[0] = 2;
    let resp = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(route_catalog::pipeline::TRANSACTION.path())
                .header(CONTENT_TYPE, "application/x-norito")
                .extension(norito_rpc_harness::loopback_connect_info())
                .body(Body::from(bytes))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let envelope = response_error_envelope(resp).await;
    assert_transaction_decode_rejection_without_panic(&envelope);
    assert!(
        envelope.message().contains("version") || envelope.message().contains("Version"),
        "version failure should be visible in response: {}",
        envelope.message()
    );
    harness.shutdown().await;
}
#[tokio::test]
async fn public_transaction_route_rejects_empty_body_without_decode_panic() {
    let resp = post_ga_norito(route_catalog::pipeline::TRANSACTION.path(), Vec::new()).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("invalid_transaction_payload")
    );
    let envelope = response_error_envelope(resp).await;
    assert_transaction_decode_rejection_without_panic(&envelope);
}
#[tokio::test]
async fn public_transaction_route_rejects_malformed_json_with_exact_decode_code() {
    use axum::{
        body::Body,
        http::{Request, header::ACCEPT, header::CONTENT_TYPE},
    };
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    let harness = NoritoRpcHarness::new(|cfg| {
        cfg.torii.transport.norito_rpc.stage = NoritoRpcStage::Ga;
    });
    let mut request = Request::builder()
        .method("POST")
        .uri(route_catalog::pipeline::TRANSACTION.path())
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .body(Body::from(r#"{"version":1,"content":{}}"#))
        .expect("request");
    request
        .extensions_mut()
        .insert(norito_rpc_harness::loopback_connect_info());
    let response = harness
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("invalid_transaction_payload")
    );
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json; charset=utf-8")
    );
    let body = response
        .into_body()
        .collect()
        .await
        .expect("collect response body")
        .to_bytes();
    let envelope: ErrorEnvelope =
        norito::json::from_slice(&body).expect("decode JSON error envelope");
    assert_transaction_decode_rejection_without_panic(&envelope);
    harness.shutdown().await;
}
#[tokio::test]
async fn public_transaction_route_rejects_version_only_body_without_decode_panic() {
    let resp = post_ga_norito(route_catalog::pipeline::TRANSACTION.path(), vec![1_u8]).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let envelope = response_error_envelope(resp).await;
    assert_transaction_decode_rejection_without_panic(&envelope);
}
#[tokio::test]
async fn norito_query_accepts_versioned_signed_query_payload() {
    use axum::body::Body;
    use axum::http::{Request, header::CONTENT_TYPE};
    use http_body_util::BodyExt;
    use tower::ServiceExt as _;
    let harness = NoritoRpcHarness::new(|cfg| {
        cfg.torii.transport.norito_rpc.stage = NoritoRpcStage::Ga;
    });
    let resp = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(route_catalog::pipeline::QUERY.path())
                .header(CONTENT_TYPE, "application/x-norito")
                .extension(norito_rpc_harness::loopback_connect_info())
                .body(Body::from(norito_rpc_harness::sample_query_bytes()))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let body = BodyExt::collect(resp.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert_eq!(status, StatusCode::OK, "unexpected error body: {text}");
    harness.shutdown().await;
}
#[tokio::test]
async fn norito_query_rejects_invalid_signature_without_decode_panic() {
    use axum::body::Body;
    use axum::http::{Request, header::CONTENT_TYPE};
    use http_body_util::BodyExt;
    use tower::ServiceExt as _;
    let harness = NoritoRpcHarness::new(|cfg| {
        cfg.torii.transport.norito_rpc.stage = NoritoRpcStage::Ga;
    });
    let resp = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(route_catalog::pipeline::QUERY.path())
                .header(CONTENT_TYPE, "application/x-norito")
                .extension(norito_rpc_harness::loopback_connect_info())
                .body(Body::from(
                    norito_rpc_harness::sample_invalid_signature_query_bytes(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = BodyExt::collect(resp.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    let text = String::from_utf8(body.to_vec()).expect("response text");
    assert!(
        text.contains("Query request signature is not valid"),
        "unexpected error body: {text}"
    );
    assert!(
        !text.contains("panic during decode"),
        "unexpected decode panic response: {text}"
    );
    harness.shutdown().await;
}
#[tokio::test]
async fn public_query_route_rejects_bare_signed_query_payload() {
    use axum::body::Body;
    use axum::http::{Request, header::CONTENT_TYPE};
    use http_body_util::BodyExt;
    use tower::ServiceExt as _;
    let harness = NoritoRpcHarness::new(|cfg| {
        cfg.torii.transport.norito_rpc.stage = NoritoRpcStage::Ga;
    });
    let resp = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(route_catalog::pipeline::QUERY.path())
                .header(CONTENT_TYPE, "application/x-norito")
                .extension(norito_rpc_harness::loopback_connect_info())
                .body(Body::from(norito_rpc_harness::sample_bare_query_bytes()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = BodyExt::collect(resp.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    let text = String::from_utf8(body.to_vec()).expect("response text");
    assert!(text.contains("versioned"), "unexpected error body: {text}");
    assert!(
        !text.contains("panic during decode"),
        "unexpected decode panic response: {text}"
    );
    harness.shutdown().await;
}
#[tokio::test]
async fn public_query_route_rejects_unsupported_version_without_decode_panic() {
    use axum::body::Body;
    use axum::http::{Request, header::CONTENT_TYPE};
    use http_body_util::BodyExt;
    use tower::ServiceExt as _;
    let harness = NoritoRpcHarness::new(|cfg| {
        cfg.torii.transport.norito_rpc.stage = NoritoRpcStage::Ga;
    });
    let mut bytes = norito_rpc_harness::sample_query_bytes();
    bytes[0] = 2;
    let resp = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(route_catalog::pipeline::QUERY.path())
                .header(CONTENT_TYPE, "application/x-norito")
                .extension(norito_rpc_harness::loopback_connect_info())
                .body(Body::from(bytes))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = BodyExt::collect(resp.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    let text = String::from_utf8(body.to_vec()).expect("response text");
    assert!(
        text.contains("Could not decode versioned request"),
        "unexpected error body: {text}"
    );
    assert!(
        text.contains("version") || text.contains("Version"),
        "version failure should be visible in response: {text}"
    );
    assert!(
        !text.contains("panic during decode"),
        "unexpected decode panic response: {text}"
    );
    harness.shutdown().await;
}
#[tokio::test]
async fn public_query_route_rejects_empty_body_without_decode_panic() {
    let resp = post_ga_norito(route_catalog::pipeline::QUERY.path(), Vec::new()).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let text = response_text(resp).await;
    assert_versioned_decode_rejection_without_panic(&text);
}
#[tokio::test]
async fn public_query_route_rejects_version_only_body_without_decode_panic() {
    let resp = post_ga_norito(route_catalog::pipeline::QUERY.path(), vec![1_u8]).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let text = response_text(resp).await;
    assert_versioned_decode_rejection_without_panic(&text);
}
#[tokio::test]
async fn iroha_client_submit_transaction_succeeds_against_torii_public_signed_transaction_ingress()
{
    use iroha::{client::Client, config::Config};
    use iroha_data_model::{account::AccountId, isi::Log, transaction::TransactionBuilder};
    use iroha_logger::Level;
    use iroha_model_base::chain::ChainId;
    use tokio::net::TcpListener;
    let harness = NoritoRpcHarness::new(|cfg| {
        cfg.torii.transport.norito_rpc.stage = NoritoRpcStage::Ga;
    });
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("listener addr");
    let app = harness.app.clone();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test Torii");
    });
    let chain: ChainId = harness.cfg.common.chain.clone();
    let key_pair = checked_norito_ingress_client_fixture();
    let account = AccountId::of(key_pair.public_key().clone());
    let network_id = harness.network_id;
    let client = Client::builder(Config {
        chain: chain.clone(),
        network_id,
        account: account.clone(),
        account_chain_discriminant: iroha_config::parameters::defaults::common::chain_discriminant(
        ),
        key_pair: key_pair.clone(),
        basic_auth: None,
        api_token: None,
        http_transport_policy: iroha::config::HttpTransportPolicy::Ordinary,
        torii_api_url: format!("http://{addr}/").parse().expect("torii url"),
        torii_request_timeout: iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT,
        transaction_ttl: std::time::Duration::from_secs(5),
        transaction_status_timeout: std::time::Duration::from_secs(10),
        transaction_add_nonce: false,
        sorafs_alias_cache: default_alias_policy(),
        sorafs_anonymity_policy: iroha_service_model::soranet::AnonymityPolicy::GuardPq,
        sorafs_rollout_phase: iroha_service_model::soranet::RolloutPhase::Canary,
    })
    .build()
    .expect("valid test client configuration");
    let tx = TransactionBuilder::new(
        network_id,
        account,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "client submit e2e".to_owned())])
    .sign(key_pair.private_key());
    let expected_hash = tx.hash();
    let actual_hash = client
        .account_client()
        .expect("valid account authority context")
        .submit_transaction(&tx)
        .await
        .expect("submit transaction");
    assert_eq!(actual_hash, expected_hash);
    harness.shutdown().await;
}
