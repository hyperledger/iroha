// Token issuance fixtures.

struct TokenTestContext {
    app: SharedAppState,
    manifest_id_hex: String,
    provider_id_hex: String,
    verifying_key_hex: String,
    client_id: String,
    _storage_dir: TempDir,
}

impl TokenTestContext {
    fn manifest(&self) -> sorafs_node::store::StoredManifest {
        self.app
            .sorafs_node
            .manifest_metadata(&self.manifest_id_hex)
            .expect("manifest")
    }

    fn token_request(&self, overrides: TokenOverrides) -> StreamTokenRequestDto {
        StreamTokenRequestDto {
            manifest_id_hex: self.manifest_id_hex.clone(),
            provider_id_hex: self.provider_id_hex.clone(),
            ttl_secs: overrides.ttl_secs,
            max_streams: overrides.max_streams,
            rate_limit_bytes: overrides.rate_limit_bytes,
            requests_per_minute: overrides.requests_per_minute,
        }
    }

    async fn car_range(&self, headers: HeaderMap, port: u16) -> Response {
        api_test_route!(get_storage_car_range; State(self.app.clone()); Path(self.manifest_id_hex.clone()); headers; ConnectInfo(SocketAddr::from(([127, 0, 0, 1], port))))
    }
}

fn token_test_context() -> TokenTestContext {
    token_test_context_with_payload(b"stream token payload fixture".to_vec())
}
#[cfg(feature = "telemetry")]
fn isolated_test_telemetry() -> crate::routing::MaybeTelemetry {
    let metrics = Arc::new(iroha_telemetry::metrics::Metrics::default());
    let telemetry = iroha_core::telemetry::Telemetry::new(metrics, true);
    crate::routing::MaybeTelemetry::from_profile(
        Some(telemetry),
        iroha_config::parameters::actual::TelemetryProfile::Full,
    )
}
fn token_test_context_with_payload(payload: Vec<u8>) -> TokenTestContext {
    token_test_context_with_payload_and_signer_mode(payload, ApiTestStreamTokenSignerMode::Sign)
}
fn token_test_context_with_payload_and_signer_mode(
    payload: Vec<u8>,
    signer_mode: ApiTestStreamTokenSignerMode,
) -> TokenTestContext {
    let provider_id = [0xAB; 32];
    let provider = make_signed_advert_with_host_and_provider("storage.example.test", provider_id);
    // Range requests authenticate the provider's signed range capabilities before
    // exercising token quotas, payload verification or manifest-envelope policy.
    let mut app = Arc::try_unwrap(app_state_with_seeded_cache(&provider))
        .unwrap_or_else(|_| panic!("exclusive app state required"));
    #[cfg(feature = "telemetry")]
    {
        app.telemetry = isolated_test_telemetry();
    }
    let (node, storage_dir) = sorafs_node_with_temp_storage();
    let manifest = manifest_for_payload(0x42, &payload);
    let plan = CarBuildPlan::single_file(&payload).expect("plan");
    let mut reader = payload.as_slice();
    let manifest_id_hex = node
        .ingest_manifest(&manifest, &plan, &mut reader)
        .expect("ingest manifest");
    app.sorafs_node = node;
    let provider_id_hex = hex::encode(provider_id);
    // Tests exercise manifest envelope gating explicitly; disable by default here
    // so individual cases can opt in to stricter enforcement.
    app.sorafs_gateway_config.require_manifest_envelope = false;
    let issuer = stream_token_issuer_for_tests_with_mode(signer_mode, provider_id, 7);
    let issuer = Arc::new(issuer);
    let verifying_key_hex = hex::encode(issuer.verifying_key_bytes());
    app.stream_token_issuer = Some(issuer);
    let chunker_handle = format!(
        "{}.{}@{}",
        manifest.chunking.namespace, manifest.chunking.name, manifest.chunking.semver
    );
    seed_capacity_declaration(&app.sorafs_node, provider_id, &chunker_handle);
    app.sorafs_gateway_config.enforce_admission = false;
    refresh_api_test_gateway_security(&mut app);

    let client_id = "gateway-beta".to_string();
    let app = Arc::new(app);
    TokenTestContext {
        app,
        manifest_id_hex,
        provider_id_hex,
        verifying_key_hex,
        client_id,
        _storage_dir: storage_dir,
    }
}
async fn issue_token_base64(context: &TokenTestContext, overrides: TokenOverrides) -> String {
    let mut headers = HeaderMap::new();
    insert_api_test_header(&mut headers, HEADER_SORA_CLIENT, &context.client_id);
    insert_static_api_test_header(&mut headers, HEADER_SORA_NONCE, "issuer-nonce");

    let request = context.token_request(overrides);
    let response =
        api_test_route!(post_storage_token; State(context.app.clone()); headers; JsonOnly(request));
    assert_eq!(response.status(), StatusCode::OK);
    let (_, body) = response.into_parts();
    let body_bytes = body::to_bytes(body, usize::MAX)
        .await
        .expect("collect token body");
    let value: Value = norito::json::from_slice(&body_bytes).expect("decode token response");
    value
        .json_str(&["token_base64"])
        .expect("token base64 present")
        .to_string()
}
