//! Integration test for /v1/zk/verify-batch JSON handler (base64 of Norito envelopes).
#![cfg(all(feature = "app_api", feature = "zk-verify-batch"))]
use axum::{Router, routing::post};
use base64::Engine;
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;
#[tokio::test]
async fn zk_verify_batch_endpoint_accepts_json_b64_vec() {
    use h2::norito_helpers as nh;
    use iroha_zkp_halo2 as h2;
    use iroha_zkp_halo2::backend::pallas::PallasBackend;
    let app = Router::new().route(
        "/v1/zk/verify-batch",
        post(
            |headers: axum::http::HeaderMap, body: axum::body::Bytes| async move {
                iroha_torii::handle_v1_zk_verify_batch_with_limits(
                    headers,
                    body,
                    iroha_zkp_halo2::OpenVerifyLimits::default(),
                    4 * 1024 * 1024,
                    16,
                    1024 * 1024,
                    false,
                )
                .await
            },
        ),
    );
    // Build two envelopes: ok and bad (flip t)
    let params = h2::Params::new(8).unwrap();
    let coeffs: Vec<h2::PrimeField64> = (0u64..8).map(|i| h2::PrimeField64::from(i + 1)).collect();
    let poly = h2::Polynomial::from_coeffs(coeffs);
    let mut tr = h2::Transcript::new("torii-batch-json");
    let p_g = poly.commit(&params).unwrap();
    let z = h2::PrimeField64::from(5u64);
    let (proof, t) = poly.open(&params, &mut tr, z, p_g).unwrap();
    let env_ok = h2::OpenVerifyEnvelope {
        params: nh::params_to_wire(&params),
        public: nh::poly_open_public::<PallasBackend>(params.n(), z, t, p_g),
        proof: nh::proof_to_wire(&proof),
        transcript_label: "torii-batch-json".to_string(),
        vk_commitment: None,
        public_inputs_schema_hash: None,
        domain_tag: None,
    };
    let mut bad_pub = env_ok.public.clone();
    bad_pub.t[0] = bad_pub.t[0].wrapping_add(1);
    let env_bad = h2::OpenVerifyEnvelope {
        public: bad_pub,
        ..env_ok.clone()
    };
    let ok_bytes = norito::to_bytes(&env_ok).expect("encode ok");
    let bad_bytes = norito::to_bytes(&env_bad).expect("encode bad");
    let arr = iroha_torii::json_array(vec![
        base64::engine::general_purpose::STANDARD.encode(ok_bytes),
        base64::engine::general_purpose::STANDARD.encode(bad_bytes),
    ]);
    let body_json = norito::json::to_vec(&arr).unwrap();
    let req = http::Request::builder()
        .method("POST")
        .uri("/v1/zk/verify-batch")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body_json))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    assert_eq!(v.get("ok").and_then(|x| x.as_bool()), Some(true));
    let statuses = v
        .get("statuses")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    assert_eq!(statuses.len(), 2);
    assert_eq!(
        statuses[0]
            .get("status")
            .and_then(norito::json::Value::as_str),
        Some("verified")
    );
    assert_eq!(
        statuses[1]
            .get("status")
            .and_then(norito::json::Value::as_str),
        Some("invalid")
    );
    assert!(statuses[0].get("code").is_none());
    assert!(statuses[1].get("code").is_none());
}
