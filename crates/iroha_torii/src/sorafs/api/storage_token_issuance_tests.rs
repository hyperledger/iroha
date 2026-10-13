// Token issuance regressions.

#[tokio::test]
async fn storage_token_issues_signed_response() {
    let context = token_test_context();
    let mut headers = HeaderMap::new();
    insert_static_api_test_header(&mut headers, HEADER_SORA_NONCE, "nonce-token-1");
    insert_api_test_header(&mut headers, HEADER_SORA_CLIENT, &context.client_id);

    let request = context.token_request(TokenOverrides::default());
    let response =
        api_test_route!(post_storage_token; State(context.app.clone()); headers; JsonOnly(request));
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    assert_eq!(
        api_test_header_str(&headers, HEADER_SORA_NONCE),
        Some("nonce-token-1")
    );
    assert_eq!(
        api_test_header_str(&headers, HEADER_SORA_CLIENT),
        Some(context.client_id.as_str())
    );
    assert_eq!(
        api_test_header_str(&headers, HEADER_SORA_VERIFYING_KEY),
        Some(context.verifying_key_hex.as_str())
    );
    let token_id = headers
        .get(HEADER_SORA_TOKEN_ID)
        .and_then(|value| value.to_str().ok())
        .expect("token id header");
    assert!(!token_id.is_empty());
    assert_eq!(
        api_test_header_str(&headers, HEADER_SORA_ISSUANCE_QUOTA_REMAINING),
        Some("2")
    );
    assert_eq!(
        api_test_header_str(&headers, CACHE_CONTROL),
        Some("no-store")
    );

    let value = api_test_response_json(response).await;
    let token_obj = value.json_object(&["token"]).expect("token object");
    let signature_hex = token_obj
        .json_str(&["signature_hex"])
        .expect("signature hex");
    assert_eq!(signature_hex.len(), 64 * 2);
    assert!(signature_hex.chars().all(|c| c.is_ascii_hexdigit()));
    let body_obj = token_obj.json_object(&["body"]).expect("token body");
    assert!(
        body_obj.json_str(&["token_id"]).is_some(),
        "token body must include token_id"
    );
    let token_base64 = value
        .json_str(&["token_base64"])
        .expect("token base64 present");
    assert!(!token_base64.is_empty());
    let decoded = decode_token_base64(token_base64).expect("decode token base64");
    assert_eq!(
        decoded.body.token_id,
        body_obj.json_str(&["token_id"]).expect("token id"),
    );
    decoded
        .verify(
            context
                .app
                .stream_token_issuer
                .as_ref()
                .expect("issuer configured")
                .verifying_key(),
        )
        .expect("runtime-signed token must verify");
}
#[tokio::test]
async fn storage_token_runtime_signer_failures_are_payload_free_and_fail_closed() {
    async fn issue_with_mode(mode: ApiTestStreamTokenSignerMode) -> axum::response::Response {
        let context = token_test_context_with_payload_and_signer_mode(
            b"runtime signer failure fixture".to_vec(),
            mode,
        );
        let mut headers = HeaderMap::new();
        insert_static_api_test_header(&mut headers, HEADER_SORA_NONCE, "runtime-signer-failure");
        insert_static_api_test_header(
            &mut headers,
            HEADER_SORA_CLIENT,
            "gateway-runtime-signer-test",
        );
        let request = StreamTokenRequestDto {
            manifest_id_hex: context.manifest_id_hex,
            provider_id_hex: context.provider_id_hex,
            ttl_secs: None,
            max_streams: None,
            rate_limit_bytes: None,
            requests_per_minute: None,
        };
        api_test_route!(post_storage_token; State(context.app); headers; JsonOnly(request))
    }
    let unavailable = issue_with_mode(ApiTestStreamTokenSignerMode::Unavailable).await;
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        api_test_header_str(unavailable.headers(), RETRY_AFTER),
        Some("1")
    );
    let unavailable_value = api_test_response_json(unavailable).await;
    assert_json_fields!(unavailable_value; json_str ["error"] => Some("stream token issuance is temporarily unavailable"));
    let drifted = issue_with_mode(ApiTestStreamTokenSignerMode::QualificationDrift).await;
    assert_eq!(drifted.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        api_test_header_str(drifted.headers(), RETRY_AFTER),
        Some("1")
    );
    let drifted_body = api_test_response_body(drifted).await;
    let drifted_value: Value =
        norito::json::from_slice(&drifted_body).expect("decode drifted response");
    assert_json_fields!(drifted_value; json_str ["error"] => Some("stream token issuance is temporarily unavailable"));
    assert!(!String::from_utf8_lossy(&drifted_body).contains("qualification"));
    for mode in [
        ApiTestStreamTokenSignerMode::Refused,
        ApiTestStreamTokenSignerMode::WrongSignature,
    ] {
        let response = issue_with_mode(mode).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(response.headers().get(RETRY_AFTER).is_none());
        let response_body = api_test_response_body(response).await;
        let response_value: Value =
            norito::json::from_slice(&response_body).expect("decode signer failure response");
        assert_json_fields!(response_value; json_str ["error"] => Some("failed to issue stream token"));
        let rendered = String::from_utf8_lossy(&response_body);
        assert!(!rendered.contains("pkcs11:"));
        assert!(!rendered.contains("runtime signer"));
        assert!(!rendered.contains("signature"));
    }
}
#[tokio::test]
async fn storage_token_requires_nonce_header() {
    let context = token_test_context();
    let request = context.token_request(TokenOverrides::default());
    let response = api_test_route!(post_storage_token; State(context.app.clone()); { let mut headers = HeaderMap::new(); insert_api_test_header(&mut headers, HEADER_SORA_CLIENT, &context.client_id); headers }; JsonOnly(request));
    let value = api_test_response_json_with_status(response, StatusCode::BAD_REQUEST).await;
    let error_message = value.json_str(&["error"]).expect("error string");
    assert!(
        error_message.contains("missing X-SoraFS-Nonce"),
        "unexpected error message: {error_message}"
    );
}
#[tokio::test]
async fn storage_token_rejects_noncanonical_or_oversized_request_fields() {
    let context = token_test_context();
    let request = || context.token_request(TokenOverrides::default());
    for (name, value) in [
        (HEADER_SORA_CLIENT, "x".repeat(MAX_CLIENT_ID_BYTES + 1)),
        (HEADER_SORA_CLIENT, "client with spaces".to_string()),
        (HEADER_SORA_NONCE, "x".repeat(MAX_NONCE_BYTES + 1)),
        (HEADER_SORA_NONCE, "nonce with spaces".to_string()),
    ] {
        let mut headers = HeaderMap::new();
        insert_static_api_test_header(&mut headers, HEADER_SORA_CLIENT, "client-a");
        insert_static_api_test_header(&mut headers, HEADER_SORA_NONCE, "nonce-a");
        headers.insert(
            header::HeaderName::from_static(name),
            HeaderValue::from_str(&value).expect("test header"),
        );
        let response = api_test_route!(post_storage_token; State(context.app.clone()); headers; JsonOnly(request()));
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "value={value:?}"
        );
    }
    let mut headers = HeaderMap::new();
    insert_static_api_test_header(&mut headers, HEADER_SORA_CLIENT, "client-a");
    insert_static_api_test_header(&mut headers, HEADER_SORA_NONCE, "nonce-a");
    let mut noncanonical_manifest = request();
    noncanonical_manifest.manifest_id_hex.push('A');
    let response = api_test_route!(post_storage_token; State(context.app.clone()); headers.clone(); JsonOnly(noncanonical_manifest));
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let mut noncanonical_provider = request();
    noncanonical_provider.provider_id_hex.make_ascii_uppercase();
    let response = api_test_route!(post_storage_token; State(context.app.clone()); headers; JsonOnly(noncanonical_provider));
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
#[tokio::test]
async fn storage_token_rejects_provider_mismatch_and_unsafe_overrides() {
    let context = token_test_context();
    let headers = || {
        let mut headers = HeaderMap::new();
        insert_static_api_test_header(&mut headers, HEADER_SORA_CLIENT, "client-a");
        insert_static_api_test_header(&mut headers, HEADER_SORA_NONCE, "nonce-a");
        headers
    };
    let request = |provider_id_hex: String, overrides: TokenOverrides| StreamTokenRequestDto {
        manifest_id_hex: context.manifest_id_hex.clone(),
        provider_id_hex,
        ttl_secs: overrides.ttl_secs,
        max_streams: overrides.max_streams,
        rate_limit_bytes: overrides.rate_limit_bytes,
        requests_per_minute: overrides.requests_per_minute,
    };
    for provider in [[0_u8; 32], [0xAC; 32]] {
        let response = api_test_route!(post_storage_token; State(context.app.clone()); headers(); JsonOnly(request(hex::encode(provider), TokenOverrides::default())));
        assert!(
            matches!(
                response.status(),
                StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN
            ),
            "unexpected provider-binding status: {}",
            response.status()
        );
    }
    for overrides in [
        TokenOverrides {
            ttl_secs: Some(0),
            ..TokenOverrides::default()
        },
        TokenOverrides {
            max_streams: Some(0),
            ..TokenOverrides::default()
        },
        TokenOverrides {
            rate_limit_bytes: Some(0),
            ..TokenOverrides::default()
        },
        TokenOverrides {
            requests_per_minute: Some(0),
            ..TokenOverrides::default()
        },
        TokenOverrides {
            requests_per_minute: Some(4),
            ..TokenOverrides::default()
        },
    ] {
        let response = api_test_route!(post_storage_token; State(context.app.clone()); headers(); JsonOnly(request(context.provider_id_hex.clone(), overrides)));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
#[tokio::test]
async fn stream_token_enforcement_rejects_temporal_policy_and_binding_attacks() {
    let context = token_test_context();
    let manifest = context.manifest();
    let valid_encoded = issue_token_base64(&context, TokenOverrides::default()).await;
    let valid = decode_token_base64(&valid_encoded).expect("decode issued token");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let mut cases = Vec::new();
    let mut body = valid.body.clone();
    body.issued_at = now + sorafs_manifest::token::STREAM_TOKEN_MAX_FUTURE_SKEW_SECS_V1 + 10;
    body.ttl_epoch = body.issued_at + 60;
    cases.push((body, StatusCode::UNAUTHORIZED));
    let mut body = valid.body.clone();
    body.issued_at = now.saturating_sub(60);
    body.ttl_epoch = now;
    cases.push((body, StatusCode::UNAUTHORIZED));
    let mut body = valid.body.clone();
    body.ttl_epoch = body.issued_at;
    cases.push((body, StatusCode::BAD_REQUEST));
    let mut body = valid.body.clone();
    body.max_streams = 0;
    cases.push((body, StatusCode::BAD_REQUEST));
    let mut body = valid.body.clone();
    body.token_pk_version += 1;
    cases.push((body, StatusCode::UNAUTHORIZED));
    let mut body = valid.body.clone();
    body.provider_id = [0xAC; 32];
    cases.push((body, StatusCode::FORBIDDEN));
    for (body, expected_status) in cases {
        let encoded = signed_test_token(body);
        let response = enforce_stream_token_for_request(
            &context.app,
            &enforcement_headers(&encoded),
            &manifest,
            "test-enforcement-nonce",
            enforcement_route(1),
        )
        .await
        .expect_err("adversarial token must be rejected");
        assert_eq!(response.status(), expected_status);
    }
    let mut tampered = valid;
    tampered.signature[0] ^= 0x80;
    let tampered = encode_token_base64(&tampered).expect("encode tampered token");
    let response = enforce_stream_token_for_request(
        &context.app,
        &enforcement_headers(&tampered),
        &manifest,
        "test-enforcement-nonce",
        enforcement_route(1),
    )
    .await
    .expect_err("tampered signature rejected");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let oversized = "A".repeat(MAX_STREAM_TOKEN_BASE64_BYTES + 1);
    let response = enforce_stream_token_for_request(
        &context.app,
        &enforcement_headers(&oversized),
        &manifest,
        "test-enforcement-nonce",
        enforcement_route(1),
    )
    .await
    .expect_err("oversized token header rejected");
    assert_eq!(
        response.status(),
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );
    let response = enforce_stream_token_for_request(
        &context.app,
        &enforcement_headers("not-base64"),
        &manifest,
        "test-enforcement-nonce",
        enforcement_route(1),
    )
    .await
    .expect_err("malformed token header rejected");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let mut duplicate_headers = enforcement_headers(&valid_encoded);
    duplicate_headers.append(
        header::HeaderName::from_static(HEADER_SORA_STREAM_TOKEN),
        header_value(&valid_encoded, "X-SoraFS-Stream-Token"),
    );
    let response = enforce_stream_token_for_request(
        &context.app,
        &duplicate_headers,
        &manifest,
        "test-duplicate-token-header",
        enforcement_route(1),
    )
    .await
    .expect_err("duplicate token headers must be rejected before admission");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
#[tokio::test]
async fn storage_token_requires_an_authenticated_operator_identity() {
    let context = token_test_context();
    let request = || context.token_request(TokenOverrides::default());
    let mut headers = HeaderMap::new();
    insert_static_api_test_header(&mut headers, HEADER_SORA_CLIENT, "operator-auth-test");
    insert_static_api_test_header(&mut headers, HEADER_SORA_NONCE, "operator-auth-nonce");
    let missing = api_test_route!(post_storage_token_authenticated; None; State(context.app.clone()); headers.clone(); JsonOnly(request()));
    assert_eq!(missing.status(), StatusCode::FORBIDDEN);
    let valid = api_test_route!(post_storage_token_authenticated; Some(test_stream_token_operator()); State(context.app.clone()); headers; JsonOnly(request()));
    assert_eq!(valid.status(), StatusCode::OK);
    assert_eq!(
        api_test_header_str(valid.headers(), HEADER_SORA_ISSUANCE_QUOTA_REMAINING),
        Some("2"),
        "rejected unauthenticated calls must not consume operator quota"
    );
}
#[tokio::test]
async fn storage_token_client_label_rotation_cannot_escape_operator_quota() {
    let context = token_test_context();
    let request_builder = || context.token_request(TokenOverrides::default());
    let expected = ["2", "1", "0"];
    for (idx, quota_remaining) in expected.into_iter().enumerate() {
        let mut headers = HeaderMap::new();
        insert_api_test_header(
            &mut headers,
            HEADER_SORA_NONCE,
            format!("nonce-quota-{idx}"),
        );
        insert_api_test_header(
            &mut headers,
            HEADER_SORA_CLIENT,
            format!("rotating-label-{idx}"),
        );
        let response = api_test_route!(post_storage_token; State(context.app.clone()); headers; JsonOnly(request_builder()));
        assert_eq!(response.status(), StatusCode::OK);
        let remaining = response
            .headers()
            .get(HEADER_SORA_ISSUANCE_QUOTA_REMAINING)
            .and_then(|value| value.to_str().ok())
            .expect("quota header");
        assert_eq!(remaining, quota_remaining);
    }
    let mut headers = HeaderMap::new();
    insert_api_test_header(&mut headers, HEADER_SORA_NONCE, "nonce-quota-3");
    insert_static_api_test_header(&mut headers, HEADER_SORA_CLIENT, "fresh-label-after-quota");

    let response = api_test_route!(post_storage_token; State(context.app.clone()); headers; JsonOnly(request_builder()));
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after = response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .expect("retry-after header");
    assert!(retry_after.parse::<u64>().unwrap_or(0) > 0);
    let quota_header = response
        .headers()
        .get(HEADER_SORA_ISSUANCE_QUOTA_REMAINING)
        .and_then(|value| value.to_str().ok())
        .expect("quota header on 429");
    assert_eq!(quota_header, "0");
}
#[tokio::test]
async fn storage_token_returns_not_found_when_disabled() {
    let mut app = Arc::try_unwrap(mk_app_state_for_tests())
        .unwrap_or_else(|_| panic!("exclusive app state required"));
    let (node, _dir) = sorafs_node_with_temp_storage();
    let payload = b"disabled issuer payload";
    let manifest = manifest_for_payload(0x17, payload);
    let plan = CarBuildPlan::single_file(payload).expect("plan");
    let mut reader = &payload[..];
    let manifest_id_hex = node
        .ingest_manifest(&manifest, &plan, &mut reader)
        .expect("ingest manifest");
    app.sorafs_node = node;
    // Leave stream_token_issuer unset to emulate disabled tokens.
    let state = Arc::new(app);
    let mut headers = HeaderMap::new();
    insert_static_api_test_header(&mut headers, HEADER_SORA_NONCE, "nonce-disabled");
    insert_static_api_test_header(&mut headers, HEADER_SORA_CLIENT, "gateway-disabled");
    let request = StreamTokenRequestDto {
        manifest_id_hex,
        provider_id_hex: hex::encode([0xEF; 32]),
        ttl_secs: None,
        max_streams: None,
        rate_limit_bytes: None,
        requests_per_minute: None,
    };
    let response = api_test_route!(post_storage_token; State(state); headers; JsonOnly(request));
    let value = api_test_response_json_with_status(response, StatusCode::NOT_FOUND).await;
    let error_message = value.json_str(&["error"]).expect("error string");
    assert!(
        error_message.contains("stream token issuance is not enabled"),
        "unexpected error: {error_message}"
    );
}
#[tokio::test]
async fn storage_token_requires_client_header() {
    let (app, _dir, manifest_id) = token_enabled_state();
    let mut headers = HeaderMap::new();
    insert_static_api_test_header(&mut headers, HEADER_SORA_NONCE, "nonce-test");
    let request = StreamTokenRequestDto {
        manifest_id_hex: manifest_id,
        provider_id_hex: hex::encode([0x55; 32]),
        ttl_secs: None,
        max_streams: None,
        rate_limit_bytes: None,
        requests_per_minute: None,
    };
    let response = api_test_route!(post_storage_token; State(app); headers; JsonOnly(request));
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
#[tokio::test]
async fn storage_token_emits_expected_headers() {
    let (app, _dir, manifest_id) = token_enabled_state();
    let verifying_hex = {
        let issuer = app
            .stream_token_issuer
            .as_ref()
            .expect("issuer configured for tests");
        hex::encode(issuer.verifying_key_bytes())
    };
    let mut headers = HeaderMap::new();
    insert_static_api_test_header(&mut headers, HEADER_SORA_NONCE, "nonce-123");
    insert_static_api_test_header(&mut headers, HEADER_SORA_CLIENT, "gateway-alpha");

    let request = StreamTokenRequestDto {
        manifest_id_hex: manifest_id,
        provider_id_hex: hex::encode([0x66; 32]),
        ttl_secs: Some(900),
        max_streams: Some(3),
        rate_limit_bytes: Some(1_048_576),
        requests_per_minute: Some(2),
    };
    let response =
        api_test_route!(post_storage_token; State(app.clone()); headers; JsonOnly(request));
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    assert_eq!(
        api_test_header_str(&headers, HEADER_SORA_NONCE),
        Some("nonce-123")
    );
    assert_eq!(
        api_test_header_str(&headers, HEADER_SORA_CLIENT),
        Some("gateway-alpha")
    );
    assert!(
        api_test_header_str(&headers, HEADER_SORA_TOKEN_ID).is_some(),
        "token id header must be present"
    );
    assert_eq!(
        api_test_header_str(&headers, HEADER_SORA_VERIFYING_KEY),
        Some(verifying_hex.as_str())
    );
    assert_eq!(
        api_test_header_str(&headers, HEADER_SORA_ISSUANCE_QUOTA_REMAINING),
        Some("2")
    );
    assert_eq!(
        api_test_header_str(&headers, CACHE_CONTROL),
        Some("no-store")
    );

    let value = api_test_response_json(response).await;
    assert!(
        value.get("token").is_some(),
        "response should contain token payload"
    );
}
