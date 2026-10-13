// MCP catalog, policy, authentication, and schema regressions.
use super::*;
use crate::McpDispatchRouterOwner;
use crate::tests_runtime_handlers::{
    app_auth_test_guard, checked_torii_test_ed25519_keypair, mk_app_state_for_tests,
    mk_app_state_for_tests_with_world, signed_app_headers, world_with_account,
};
use iroha_config::parameters::actual::ToriiMcpProfile;
const TEST_ACCOUNT_I105: &str = "sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE";

fn test_account_header_hex() -> String {
    AccountAddress::parse_encoded(TEST_ACCOUNT_I105, None)
        .expect("canonical I105 fixture")
        .canonical_hex()
        .expect("canonical account-header hex")
}

fn canonical_test_witness_header() -> String {
    let subject_account = AccountAddress::parse_encoded(TEST_ACCOUNT_I105, None)
        .expect("canonical I105 fixture")
        .to_account_id()
        .expect("fixture account id");
    let signer = checked_torii_test_ed25519_keypair(0x73, "derive MCP witness fixture signer");
    crate::app_auth::witness_header_value(&iroha_data_model::soracloud::CanonicalRequestWitnessV1 {
        schema_version: iroha_data_model::soracloud::CANONICAL_REQUEST_WITNESS_VERSION_V1,
        subject_account,
        timestamp_ms: 1,
        nonce: "bounded-mcp-witness".to_owned(),
        canonical_request_hash: iroha_crypto::Hash::new(b"bounded MCP witness fixture"),
        signatures: vec![
            iroha_data_model::soracloud::CanonicalRequestSignatureWitnessV1 {
                signer: signer.public_key().clone(),
                signature: iroha_crypto::Signature::new(
                    signer.private_key(),
                    b"bounded MCP witness fixture signature",
                ),
            },
        ],
    })
    .expect("bounded canonical witness header")
}
const TEST_ASSET_ID: &str = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";

fn test_faucet_runtime_config() -> iroha_config::parameters::actual::ToriiFaucet {
    iroha_config::parameters::actual::ToriiFaucet {
        authority: AccountAddress::parse_encoded(TEST_ACCOUNT_I105, None)
            .expect("canonical faucet authority")
            .to_account_id()
            .expect("faucet authority account id"),
        private_key_file: "/runtime-only/mcp-test-faucet.key".into(),
        signer: checked_torii_test_ed25519_keypair(0x7a, "derive MCP faucet test signer"),
        asset_definition_id: TEST_ASSET_ID.to_owned(),
        amount: 1_u32.into(),
        pow_difficulty_bits: std::num::NonZeroU8::new(1).expect("nonzero"),
        pow_scrypt_log_n: 1,
        pow_scrypt_r: 1,
        pow_scrypt_p: 1,
        pow_max_anchor_age_blocks: std::num::NonZeroU64::new(1).expect("nonzero"),
        pow_adaptive_lookback_blocks: 1,
        pow_adaptive_claims_per_extra_bit: 1,
        pow_adaptive_max_extra_bits: 1,
        pow_beacon_seed_enabled: false,
    }
}

#[test]
fn catalog_dispatch_matching_handles_exact_parameters_and_wildcards() {
    assert!(route_template_matches(
        "/v1/gov/proposals/{id}",
        "/v1/gov/proposals/abc123"
    ));
    assert!(!route_template_matches(
        "/v1/gov/proposals/{id}",
        "/v1/gov/proposals"
    ));
    assert!(route_template_matches(
        "/v1/app-api/cid/{cid}/{*path}",
        "/v1/app-api/cid/bafy/path/to/resource"
    ));
    assert!(!route_template_matches(
        "/v1/app-api/cid/{cid}/{*path}",
        "/v1/app-api/cid/bafy"
    ));
    assert!(!route_template_matches(
        "/v1/gov/proposals/{id}",
        "/v1/gov/proposals/abc123/extra"
    ));
}
#[test]
fn catalog_dispatch_prefers_exact_paths_and_rejects_ambiguous_templates() {
    const ROUTES: &[RouteDescriptor] = &[
        RouteDescriptor::new(
            "test.dispatch.exact",
            CatalogHttpMethod::Get,
            "/v1/test/fixed",
            ApiSurface::Public,
            route_catalog::Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        ),
        RouteDescriptor::new(
            "test.dispatch.parameter_a",
            CatalogHttpMethod::Get,
            "/v1/test/{id}",
            ApiSurface::Public,
            route_catalog::Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        ),
        RouteDescriptor::new(
            "test.dispatch.parameter_b",
            CatalogHttpMethod::Get,
            "/v1/test/{name}",
            ApiSurface::Public,
            route_catalog::Listener::Torii,
            RouteEffect::ReadOnly,
            AdmissionPolicy::Public,
        ),
    ];
    let groups = [CatalogProjectionGroup {
        routes: ROUTES,
        enabled_features: EnabledFeatures::none(),
    }];
    let exact = catalog_descriptor_for_dispatch(&groups, &Method::GET, "/v1/test/fixed")
        .expect("exact static route wins");
    assert_eq!(exact.stable_route_id(), "test.dispatch.exact");
    assert!(catalog_descriptor_for_dispatch(&groups, &Method::GET, "/v1/test/other").is_err());
}
#[test]
fn target_policy_requires_inner_canonical_proof_only_for_canonical_route() {
    assert_eq!(
        target_extra_header_policy(&Method::GET, "/v1/node/capabilities")
            .expect("cataloged public bootstrap route"),
        ExtraHeaderPolicy::Default
    );
    assert_eq!(
        target_extra_header_policy(&Method::GET, "/v1/privacy/capabilities")
            .expect("cataloged account route"),
        ExtraHeaderPolicy::CanonicalAccountAuthentication
    );
    assert_eq!(
        target_extra_header_policy(&Method::GET, "/v1/explorer/transactions")
            .expect("cataloged dataspace route"),
        ExtraHeaderPolicy::OptionalCanonicalAccountAuthentication
    );
    assert_eq!(
        target_extra_header_policy(&Method::GET, "/health").expect("cataloged public route"),
        ExtraHeaderPolicy::Default
    );
    assert!(target_extra_header_policy(&Method::POST, "/v1/mcp").is_err());
    assert!(target_extra_header_policy(&Method::POST, "/v1/not-cataloged").is_err());
}

#[test]
fn every_catalog_canonical_auth_tool_publishes_a_strict_required_envelope() {
    let cfg = iroha_config::parameters::actual::ToriiMcp::default();
    let tools = build_tool_specs(&cfg);
    let mut covered = 0_usize;
    for tool in &tools {
        let Some((_, method, path_template)) = tool.route_backing() else {
            continue;
        };
        let Some(descriptor) =
            catalog_descriptor_for_method_path(CATALOG_PROJECTION_GROUPS, method, path_template)
        else {
            continue;
        };
        if descriptor.authentication() == AuthenticationPolicy::CanonicalAccountSignature {
            covered += 1;
            validate_canonical_auth_tool_schema(tool).unwrap_or_else(|error| {
                panic!(
                    "{} {} failed schema validation: {error}",
                    method, path_template
                )
            });
        }
    }
    assert!(
        covered > 0,
        "canonical-auth catalog projection is non-empty"
    );
}
#[test]
fn every_catalog_optional_canonical_auth_tool_publishes_a_strict_optional_envelope() {
    let cfg = iroha_config::parameters::actual::ToriiMcp::default();
    let tools = build_tool_specs(&cfg);
    let mut covered = 0_usize;
    for tool in &tools {
        let Some((_, method, path_template)) = tool.route_backing() else {
            continue;
        };
        let Some(descriptor) =
            catalog_descriptor_for_method_path(CATALOG_PROJECTION_GROUPS, method, path_template)
        else {
            continue;
        };
        if descriptor.authentication() == AuthenticationPolicy::OptionalCanonicalAccountSignature {
            covered += 1;
            validate_optional_canonical_auth_tool_schema(tool).unwrap_or_else(|error| {
                panic!(
                    "{} {} failed optional schema validation: {error}",
                    method, path_template
                )
            });
            let schema = tool.input_schema.as_object().expect("root object schema");
            assert!(
                !schema_requires(schema, "headers"),
                "{} must preserve anonymous dispatch",
                tool.name
            );
        }
    }
    assert!(
        covered > 0,
        "optional canonical-auth projection is non-empty"
    );
}
#[test]
fn every_catalog_operator_auth_tool_publishes_a_strict_required_tuple() {
    let cfg = iroha_config::parameters::actual::ToriiMcp {
        profile: ToriiMcpProfile::Operator,
        expose_operator_routes: true,
        ..Default::default()
    };
    let tools = build_tool_specs(&cfg);
    let mut covered = 0_usize;
    for tool in &tools {
        let Some((_, method, path_template)) = tool.route_backing() else {
            continue;
        };
        let Some(descriptor) =
            catalog_descriptor_for_method_path(CATALOG_PROJECTION_GROUPS, method, path_template)
        else {
            continue;
        };
        if descriptor.authentication() == AuthenticationPolicy::OperatorSignature {
            covered += 1;
            validate_operator_auth_tool_schema(tool).unwrap_or_else(|error| {
                panic!(
                    "{} {} failed operator schema validation: {error}",
                    method, path_template
                )
            });
        }
    }
    assert!(covered > 0, "operator-auth catalog projection is non-empty");
}
#[test]
fn every_catalog_tool_descriptor_publishes_exact_route_auth_metadata() {
    let cfg = iroha_config::parameters::actual::ToriiMcp {
        profile: ToriiMcpProfile::Operator,
        expose_operator_routes: true,
        ..Default::default()
    };
    let tools = build_tool_specs(&cfg);
    let mut covered = 0_usize;
    for tool in &tools {
        let Some((_, method, path_template)) = tool.route_backing() else {
            continue;
        };
        let Some(descriptor) =
            catalog_descriptor_for_method_path(CATALOG_PROJECTION_GROUPS, method, path_template)
        else {
            continue;
        };
        covered += 1;
        let published = tool.descriptor();
        assert_eq!(
            published["_meta"]["iroha/routeAuth"],
            norito::json!({
                "schemaVersion": (descriptor.auth_metadata_schema_version()),
                "stableRouteId": (descriptor.stable_route_id()),
                "authentication": (descriptor.authentication().as_str()),
                "admission": (descriptor.admission().as_str())
            }),
            "{} {} route-auth metadata",
            method,
            path_template
        );
    }
    assert!(
        covered > 0,
        "catalog-backed MCP tool projection is non-empty"
    );
}
#[test]
fn canonical_target_headers_require_one_complete_unambiguous_proof() {
    let complete = norito::json!({
        "X-Iroha-Account": "operator@sora",
        "X-Iroha-Signature": "AQ==",
        "X-Iroha-Timestamp-Ms": "1725000000123",
        "X-Iroha-Nonce": "nonce"
    });
    let mut out = HeaderMap::new();
    apply_extra_headers_with_policy(
        &mut out,
        Some(&complete),
        ExtraHeaderPolicy::CanonicalAccountAuthentication,
    )
    .expect("complete inner proof");
    assert_eq!(
        out.get(HEADER_X_IROHA_NONCE)
            .and_then(|value| value.to_str().ok()),
        Some("nonce")
    );
    for invalid in [
        norito::json!({
            "X-Iroha-Account": "operator@sora",
            "X-Iroha-Signature": "AQ=="
        }),
        norito::json!({
            "X-Iroha-Witness": "witness",
            "X-Iroha-Signature": "conflict"
        }),
        norito::json!({
            "X-Iroha-Account": "operator@sora",
            "x-iroha-account": "case alias",
            "X-Iroha-Signature": "AQ==",
            "X-Iroha-Timestamp-Ms": "1725000000123",
            "X-Iroha-Nonce": "nonce"
        }),
    ] {
        apply_extra_headers_with_policy(
            &mut HeaderMap::new(),
            Some(&invalid),
            ExtraHeaderPolicy::CanonicalAccountAuthentication,
        )
        .expect_err("ambiguous or incomplete target proof must fail closed");
    }
}

#[test]
fn optional_canonical_target_headers_allow_absence_but_reject_partial_proofs() {
    let mut outer = HeaderMap::new();
    outer.insert(
        HEADER_X_IROHA_ACCOUNT,
        HeaderValue::from_static("outer-account"),
    );
    apply_extra_headers_with_policy(
        &mut outer,
        None,
        ExtraHeaderPolicy::OptionalCanonicalAccountAuthentication,
    )
    .expect("anonymous dataspace dispatch");
    assert!(
        !outer.contains_key(HEADER_X_IROHA_ACCOUNT),
        "outer canonical identity must not bleed into the target request"
    );
    apply_extra_headers_with_policy(
        &mut HeaderMap::new(),
        Some(&norito::json!({})),
        ExtraHeaderPolicy::OptionalCanonicalAccountAuthentication,
    )
    .expect_err("a supplied but empty authentication envelope must fail closed");
    apply_extra_headers_with_policy(
        &mut HeaderMap::new(),
        Some(&norito::json!({ "X-Iroha-Account": "operator@sora" })),
        ExtraHeaderPolicy::OptionalCanonicalAccountAuthentication,
    )
    .expect_err("partial optional authentication must fail closed");

    let witness = canonical_test_witness_header();
    let mut authenticated = HeaderMap::new();
    apply_extra_headers_with_policy(
        &mut authenticated,
        Some(&norito::json!({ "X-Iroha-Witness": witness })),
        ExtraHeaderPolicy::OptionalCanonicalAccountAuthentication,
    )
    .expect("complete optional witness");
    assert!(authenticated.contains_key(HEADER_X_IROHA_WITNESS));
}

#[test]
fn canonical_target_headers_reject_noncanonical_wire_values_before_dispatch() {
    let complete = |account: Value, signature: Value, timestamp: Value, nonce: Value| {
        norito::json!({
            "X-Iroha-Account": account,
            "X-Iroha-Signature": signature,
            "X-Iroha-Timestamp-Ms": timestamp,
            "X-Iroha-Nonce": nonce
        })
    };
    let oversized_signature =
        "A".repeat(crate::app_auth::CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1.div_ceil(3) * 4 + 4);
    for invalid in [
        complete(
            Value::String(TEST_ACCOUNT_I105.to_owned()),
            Value::String("AQ==".to_owned()),
            Value::String("1725000000123".to_owned()),
            Value::String("nonce".to_owned()),
        ),
        complete(
            Value::String("not-an-alias".to_owned()),
            Value::String("AQ==".to_owned()),
            Value::String("1725000000123".to_owned()),
            Value::String("nonce".to_owned()),
        ),
        complete(
            Value::String("Operator@sora".to_owned()),
            Value::String("AQ==".to_owned()),
            Value::String("1725000000123".to_owned()),
            Value::String("nonce".to_owned()),
        ),
        complete(
            Value::String("operator@sora".to_owned()),
            Value::String("AA==".to_owned()),
            Value::String("1725000000123".to_owned()),
            Value::String("nonce".to_owned()),
        ),
        complete(
            Value::String("operator@sora".to_owned()),
            Value::String("not-base64".to_owned()),
            Value::String("1725000000123".to_owned()),
            Value::String("nonce".to_owned()),
        ),
        complete(
            Value::String("operator@sora".to_owned()),
            Value::String(oversized_signature),
            Value::String("1725000000123".to_owned()),
            Value::String("nonce".to_owned()),
        ),
        complete(
            Value::String("operator@sora".to_owned()),
            Value::String("AQ==".to_owned()),
            Value::String("01".to_owned()),
            Value::String("nonce".to_owned()),
        ),
        complete(
            Value::String("operator@sora".to_owned()),
            Value::String("AQ==".to_owned()),
            Value::String("18446744073709551616".to_owned()),
            Value::String("nonce".to_owned()),
        ),
        complete(
            Value::String("operator@sora".to_owned()),
            Value::String("AQ==".to_owned()),
            Value::from(1_u64),
            Value::String("nonce".to_owned()),
        ),
        complete(
            Value::String("operator@sora".to_owned()),
            Value::String("AQ==".to_owned()),
            Value::String("1725000000123".to_owned()),
            Value::String("contains space".to_owned()),
        ),
        complete(
            Value::String("operator@sora".to_owned()),
            Value::String("AQ==".to_owned()),
            Value::String("1725000000123".to_owned()),
            Value::String("n".repeat(257)),
        ),
        norito::json!({ "X-Iroha-Witness": "not-base64" }),
        norito::json!({
            "X-Iroha-Witness": ("A".repeat(
                crate::app_auth::CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1.div_ceil(3) * 4
                    + 4
            ))
        }),
    ] {
        apply_extra_headers_with_policy(
            &mut HeaderMap::new(),
            Some(&invalid),
            ExtraHeaderPolicy::CanonicalAccountAuthentication,
        )
        .expect_err("noncanonical target proof must fail before dispatch");
    }

    let witness = canonical_test_witness_header();
    let valid_witness = norito::json!({ "X-Iroha-Witness": (witness.clone()) });
    let mut forwarded = HeaderMap::new();
    apply_extra_headers_with_policy(
        &mut forwarded,
        Some(&valid_witness),
        ExtraHeaderPolicy::CanonicalAccountAuthentication,
    )
    .expect("bounded canonical witness must pass forwarding preflight");
    assert_eq!(
        forwarded
            .get(crate::HEADER_WITNESS)
            .and_then(|value| value.to_str().ok()),
        Some(witness.as_str())
    );
}
#[test]
fn outer_mcp_account_headers_are_never_reused_as_inner_route_proof() {
    let mut inbound = HeaderMap::new();
    inbound.insert(
        HEADER_X_IROHA_ACCOUNT,
        HeaderValue::from_static("outer-account"),
    );
    inbound.insert(
        HEADER_X_IROHA_SIGNATURE,
        HeaderValue::from_static("outer-signature"),
    );
    inbound.insert(
        HEADER_X_API_TOKEN,
        HeaderValue::from_static("outer-api-token"),
    );
    let mut dispatched = HeaderMap::new();
    forward_auth_headers(&mut dispatched, &inbound).expect("transport credentials");
    assert!(!dispatched.contains_key(HEADER_X_IROHA_ACCOUNT));
    assert!(!dispatched.contains_key(HEADER_X_IROHA_SIGNATURE));
    assert!(dispatched.contains_key(HEADER_X_API_TOKEN));
}
#[test]
fn outer_transport_credentials_reject_ambiguous_duplicate_headers() {
    for name in [
        header::AUTHORIZATION,
        HeaderName::from_static(HEADER_X_API_TOKEN),
    ] {
        let mut inbound = HeaderMap::new();
        inbound.append(name.clone(), HeaderValue::from_static("first"));
        inbound.append(name, HeaderValue::from_static("second"));
        assert!(forward_auth_headers(&mut HeaderMap::new(), &inbound).is_err());
    }
}
#[test]
fn operator_target_headers_are_complete_and_cannot_leak_to_public_routes() {
    let key_pair =
        checked_torii_test_ed25519_keypair(0x77, "derive generic operator-auth forwarding fixture");
    let public_key = key_pair
        .public_key()
        .try_to_multihash_string()
        .expect("canonical operator public key");
    let signature_bytes = iroha_crypto::Signature::new(
        key_pair.private_key(),
        b"generic operator-auth forwarding fixture",
    );
    let signature = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signature_bytes.payload(),
    );
    let headers = norito::json!({
        "X-Iroha-Operator-Public-Key": (public_key.clone()),
        "X-Iroha-Operator-Timestamp-Ms": "1725000000123",
        "X-Iroha-Operator-Nonce": "nonce",
        "X-Iroha-Operator-Signature": (signature.clone())
    });
    let mut operator = HeaderMap::new();
    apply_extra_headers_with_policy(
        &mut operator,
        Some(&headers),
        ExtraHeaderPolicy::OperatorAuthentication,
    )
    .expect("complete operator proof");
    assert_eq!(
        operator
            .get(HEADER_X_IROHA_OPERATOR_PUBLIC_KEY)
            .and_then(|value| value.to_str().ok()),
        Some(public_key.as_str())
    );
    assert_eq!(
        operator
            .get(HEADER_X_IROHA_OPERATOR_SIGNATURE)
            .and_then(|value| value.to_str().ok()),
        Some(signature.as_str())
    );
    let mut public = HeaderMap::new();
    apply_extra_headers_with_policy(&mut public, Some(&headers), ExtraHeaderPolicy::Default)
        .expect("public route ignores reserved authentication headers");
    assert!(!public.contains_key(HEADER_X_IROHA_OPERATOR_PUBLIC_KEY));
    assert!(!public.contains_key(HEADER_X_IROHA_OPERATOR_TIMESTAMP_MS));
    assert!(!public.contains_key(HEADER_X_IROHA_OPERATOR_NONCE));
    assert!(!public.contains_key(HEADER_X_IROHA_OPERATOR_SIGNATURE));
}

#[test]
fn generic_operator_target_headers_reject_noncanonical_or_unbounded_wire_values() {
    let key_pair =
        checked_torii_test_ed25519_keypair(0x78, "derive rejected generic operator-auth fixture");
    let public_key = key_pair
        .public_key()
        .try_to_multihash_string()
        .expect("canonical operator public key");
    let signature_bytes = iroha_crypto::Signature::new(
        key_pair.private_key(),
        b"rejected generic operator-auth fixture",
    );
    let signature = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signature_bytes.payload(),
    );
    let oversized_signature =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0x11_u8; 65]);
    let all_zero_signature =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0_u8; 64]);
    let complete = |public_key: Value, timestamp_ms: Value, nonce: Value, signature: Value| {
        norito::json!({
            "X-Iroha-Operator-Public-Key": public_key,
            "X-Iroha-Operator-Timestamp-Ms": timestamp_ms,
            "X-Iroha-Operator-Nonce": nonce,
            "X-Iroha-Operator-Signature": signature
        })
    };
    for invalid in [
        complete(
            Value::from(1_u64),
            Value::String("1725000000123".to_owned()),
            Value::String("nonce".to_owned()),
            Value::String(signature.clone()),
        ),
        complete(
            Value::String(public_key.clone()),
            Value::from(1_u64),
            Value::String("nonce".to_owned()),
            Value::String(signature.clone()),
        ),
        complete(
            Value::String(public_key.clone()),
            Value::String("1725000000123".to_owned()),
            Value::from(1_u64),
            Value::String(signature.clone()),
        ),
        complete(
            Value::String(public_key.clone()),
            Value::String("1725000000123".to_owned()),
            Value::String("nonce".to_owned()),
            Value::from(1_u64),
        ),
        complete(
            Value::String("A".repeat(OPERATOR_PUBLIC_KEY_MAX_LITERAL_BYTES + 1)),
            Value::String("1725000000123".to_owned()),
            Value::String("nonce".to_owned()),
            Value::String(signature.clone()),
        ),
        complete(
            Value::String("ed0120AABB".to_owned()),
            Value::String("1725000000123".to_owned()),
            Value::String("nonce".to_owned()),
            Value::String(signature.clone()),
        ),
        complete(
            Value::String(public_key.clone()),
            Value::String("01".to_owned()),
            Value::String("nonce".to_owned()),
            Value::String(signature.clone()),
        ),
        complete(
            Value::String(public_key.clone()),
            Value::String("1725000000123".to_owned()),
            Value::String("contains space".to_owned()),
            Value::String(signature.clone()),
        ),
        complete(
            Value::String(public_key.clone()),
            Value::String("1725000000123".to_owned()),
            Value::String("nonce".to_owned()),
            Value::String("not-base64".to_owned()),
        ),
        complete(
            Value::String(public_key.clone()),
            Value::String("1725000000123".to_owned()),
            Value::String("nonce".to_owned()),
            Value::String(oversized_signature),
        ),
        complete(
            Value::String(public_key),
            Value::String("1725000000123".to_owned()),
            Value::String("nonce".to_owned()),
            Value::String(all_zero_signature),
        ),
    ] {
        apply_extra_headers_with_policy(
            &mut HeaderMap::new(),
            Some(&invalid),
            ExtraHeaderPolicy::OperatorAuthentication,
        )
        .expect_err("invalid generic operator wire values must fail before dispatch");
    }
}
#[test]
fn every_mcp_post_response_is_private_and_non_cacheable() {
    let response = private_no_store_response(StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("private, no-store"))
    );
}
fn checked_submission_receipt_signer_fixture() -> iroha_crypto::KeyPair {
    iroha_crypto::KeyPair::try_random()
        .expect("generate checked MCP submission-receipt fixture signer keypair")
}
#[test]
fn submission_receipt_signer_fixture_uses_checked_ed25519_key_generation() {
    let key_pair = checked_submission_receipt_signer_fixture();
    let algorithm = key_pair
        .public_key()
        .try_algorithm()
        .expect("fixture submission-receipt signer public key has a valid algorithm");
    assert_eq!(algorithm, iroha_crypto::Algorithm::Ed25519);
}
fn sample_tool(name: &str, method: Method, effect: ToolEffect) -> ToolSpec {
    ToolSpec::route(
        name.to_owned(),
        "sample".to_owned(),
        effect,
        method,
        "/v1/sample".to_owned(),
        norito::json!({ "type": "object" }),
    )
}
fn sample_tool_at(name: &str, method: Method, path_template: &str, effect: ToolEffect) -> ToolSpec {
    ToolSpec::route(
        name.to_owned(),
        "sample".to_owned(),
        effect,
        method,
        path_template.to_owned(),
        norito::json!({ "type": "object" }),
    )
}
fn schema_value_at<'a>(schema: &'a Value, path: &[&str]) -> &'a Value {
    path.iter().fold(schema, |value, key| {
        value
            .get(*key)
            .unwrap_or_else(|| panic!("missing schema path segment `{key}` in {path:?}"))
    })
}
fn remote_addr_probe_payload(
    headers: &HeaderMap,
    remote: SocketAddr,
    allow: &[crate::limits::IpNet],
) -> Value {
    let header_remote = headers
        .get(crate::limits::REMOTE_ADDR_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .map(Value::String)
        .unwrap_or(Value::Null);
    let mut payload = Map::new();
    payload.insert(
        "allowed_header_only".into(),
        Value::Bool(crate::limits::is_allowed_by_cidr(headers, None, allow)),
    );
    payload.insert(
        "allowed_with_remote".into(),
        Value::Bool(crate::limits::is_allowed_by_cidr(
            headers,
            Some(remote.ip()),
            allow,
        )),
    );
    payload.insert("remote".into(), Value::String(remote.ip().to_string()));
    payload.insert("header".into(), header_remote);
    Value::Object(payload)
}
fn install_remote_addr_probe_router(app: &mut SharedAppState) -> McpDispatchRouterOwner {
    let allow = vec![crate::limits::parse_cidr("127.0.0.0/8").expect("loopback cidr")];
    let router: axum::Router = axum::Router::new().route(
        iroha_torii_shared::route_catalog::core::HEALTH.path(),
        axum::routing::get_service(tower::service_fn(move |req: Request<Body>| {
            let allow = allow.clone();
            async move {
                let headers = req.headers().clone();
                let remote = req
                    .extensions()
                    .get::<axum::extract::ConnectInfo<SocketAddr>>()
                    .map(|connect| connect.0)
                    .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
                let payload = remote_addr_probe_payload(&headers, remote, &allow);
                let body =
                    Body::from(norito::json::to_string(&payload).expect("encode probe payload"));
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(body)
                        .expect("response"),
                )
            }
        })),
    );
    app.mcp_dispatch_router.install(router)
}
fn install_request_counting_router(
    app: &mut SharedAppState,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> McpDispatchRouterOwner {
    let router: axum::Router =
        axum::Router::new().fallback_service(tower::service_fn(move |_request: Request<Body>| {
            let calls = std::sync::Arc::clone(&calls);
            async move {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(Body::empty())
                        .expect("response"),
                )
            }
        }));
    app.mcp_dispatch_router.install(router)
}
fn install_api_token_probe_router(
    app: &mut SharedAppState,
    configured_tokens: &[&str],
) -> McpDispatchRouterOwner {
    let state = std::sync::Arc::get_mut(app).expect("unique app state");
    state.require_api_token = true;
    state.api_token_digests = std::sync::Arc::new(limits::ApiTokenDigestSet::from_tokens(
        configured_tokens.iter().copied(),
    ));
    let router = axum::Router::new()
        .route(
            iroha_torii_shared::route_catalog::core::HEALTH.path(),
            axum::routing::get(|| async { StatusCode::NO_CONTENT }),
        )
        .layer(axum::middleware::from_fn_with_state(
            std::sync::Arc::clone(app),
            crate::enforce_api_token,
        ));
    app.mcp_dispatch_router.install(router)
}
#[tokio::test]
async fn tool_dispatch_fails_fast_when_inflight_capacity_is_exhausted() {
    let mut app = mk_app_state_for_tests();
    let semaphore = {
        let state = std::sync::Arc::get_mut(&mut app).expect("unique app state");
        state.mcp.max_inflight_dispatches = std::num::NonZeroUsize::new(1).expect("nonzero");
        state.mcp_tools = std::sync::Arc::new(vec![iroha_health_tool()]);
        state.mcp_dispatch_inflight = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        std::sync::Arc::clone(&state.mcp_dispatch_inflight)
    };
    let _held = semaphore
        .try_acquire_owned()
        .expect("test holds the only dispatch permit");
    let response = handle_named_tool_call(
        Some(Value::from(1_u64)),
        app,
        &HeaderMap::new(),
        "iroha.health",
        &Map::new(),
    )
    .await;
    assert_eq!(
        response
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(Value::as_i64),
        Some(MCP_DISPATCH_CAPACITY_EXHAUSTED)
    );
    assert_eq!(
        response
            .get("error")
            .and_then(|error| error.get("data"))
            .and_then(|data| data.get("error_code"))
            .and_then(Value::as_str),
        Some("dispatch_capacity_exhausted")
    );
}
#[tokio::test]
async fn long_poll_quota_preserves_capacity_for_bounded_tools() {
    assert_eq!(long_poll_dispatch_capacity(32), 8);
    assert_eq!(long_poll_dispatch_capacity(1), 0);
    let mut app = mk_app_state_for_tests();
    let long_poll = {
        let state = std::sync::Arc::get_mut(&mut app).expect("unique app state");
        state.mcp.max_inflight_dispatches = std::num::NonZeroUsize::new(2).expect("nonzero");
        state.mcp.profile = ToriiMcpProfile::Writer;
        state.mcp_tools = std::sync::Arc::new(vec![
            iroha_health_tool(),
            iroha_transactions_wait_tool(),
            iroha_transactions_submit_and_wait_tool(),
            iroha_contracts_call_and_wait_tool(),
        ]);
        state.mcp_dispatch_inflight = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
        state.mcp_long_poll_inflight = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        std::sync::Arc::clone(&state.mcp_long_poll_inflight)
    };
    let _held = long_poll
        .try_acquire_owned()
        .expect("test holds the only long-poll permit");
    // Schema-valid arguments, so the long-poll admission check is what rejects each call.
    for (id, name, arguments) in [
        (
            1_u64,
            "iroha.transactions.wait",
            norito::json!({ "query": { "hash": ("ab".repeat(32)) } }),
        ),
        (
            2,
            "iroha.transactions.submit_and_wait",
            norito::json!({ "body_base64": "AA==" }),
        ),
        (
            3,
            "iroha.contracts.call_and_wait",
            norito::json!({ "body": {} }),
        ),
    ] {
        let arguments = arguments.as_object().expect("object arguments");
        let wait_response = handle_named_tool_call(
            Some(Value::from(id)),
            std::sync::Arc::clone(&app),
            &HeaderMap::new(),
            name,
            arguments,
        )
        .await;
        assert_eq!(
            wait_response
                .get("error")
                .and_then(|error| error.get("data"))
                .and_then(|data| data.get("error_code"))
                .and_then(Value::as_str),
            Some("long_poll_capacity_exhausted"),
            "long-poll tool {name} escaped its reserved quota"
        );
    }
    let health_response = handle_named_tool_call(
        Some(Value::from(4_u64)),
        app,
        &HeaderMap::new(),
        "iroha.health",
        &Map::new(),
    )
    .await;
    assert!(
        health_response.get("result").is_some(),
        "bounded health tool remains dispatchable: {health_response:?}"
    );
}

#[tokio::test]
async fn real_long_poll_cannot_starve_bounded_dispatch_and_releases_both_permits() {
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let block_first_status_poll = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let router_started = std::sync::Arc::clone(&started);
    let router_release = std::sync::Arc::clone(&release);
    let router_block_first_status_poll = std::sync::Arc::clone(&block_first_status_poll);
    let router =
        axum::Router::new().fallback_service(tower::service_fn(move |request: Request<Body>| {
            let started = std::sync::Arc::clone(&router_started);
            let release = std::sync::Arc::clone(&router_release);
            let block_first_status_poll = std::sync::Arc::clone(&router_block_first_status_poll);
            async move {
                if request
                    .uri()
                    .path()
                    .contains("/pipeline/transactions/status")
                {
                    if block_first_status_poll.swap(false, std::sync::atomic::Ordering::SeqCst) {
                        started.notify_one();
                        release.notified().await;
                    }
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Body::empty())
                            .expect("pending status response"),
                    )
                } else {
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::NO_CONTENT)
                            .body(Body::empty())
                            .expect("bounded response"),
                    )
                }
            }
        }));
    let mut app = mk_app_state_for_tests();
    let (global, long_poll, _mcp_dispatch_router_owner) = {
        let state = std::sync::Arc::get_mut(&mut app).expect("unique app state");
        state.mcp.max_inflight_dispatches = std::num::NonZeroUsize::new(2).expect("nonzero");
        state.mcp.profile = ToriiMcpProfile::Writer;
        state.mcp_tools =
            std::sync::Arc::new(vec![iroha_health_tool(), iroha_transactions_wait_tool()]);
        state.mcp_dispatch_inflight = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
        state.mcp_long_poll_inflight = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let owner = state.mcp_dispatch_router.install(router);
        (
            std::sync::Arc::clone(&state.mcp_dispatch_inflight),
            std::sync::Arc::clone(&state.mcp_long_poll_inflight),
            owner,
        )
    };
    let wait_arguments = norito::json!({
        "query": { "hash": ("ab".repeat(32)) },
        "timeout_ms": 1,
        "poll_interval_ms": 100
    });
    let wait_arguments = wait_arguments.as_object().expect("wait arguments").clone();
    let wait_app = std::sync::Arc::clone(&app);
    let first_wait = tokio::spawn(async move {
        handle_named_tool_call(
            Some(Value::from(1_u64)),
            wait_app,
            &HeaderMap::new(),
            "iroha.transactions.wait",
            &wait_arguments,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), started.notified())
        .await
        .expect("first long poll reaches nested status route");
    assert_eq!(global.available_permits(), 1);
    assert_eq!(long_poll.available_permits(), 0);

    let second_wait_arguments = norito::json!({
        "query": { "hash": ("cd".repeat(32)) },
        "timeout_ms": 1,
        "poll_interval_ms": 100
    });
    let second_wait = handle_named_tool_call(
        Some(Value::from(2_u64)),
        std::sync::Arc::clone(&app),
        &HeaderMap::new(),
        "iroha.transactions.wait",
        second_wait_arguments
            .as_object()
            .expect("second wait arguments"),
    )
    .await;
    assert_eq!(
        second_wait
            .get("error")
            .and_then(|error| error.get("data"))
            .and_then(|data| data.get("error_code"))
            .and_then(Value::as_str),
        Some("long_poll_capacity_exhausted")
    );
    let health = handle_named_tool_call(
        Some(Value::from(3_u64)),
        std::sync::Arc::clone(&app),
        &HeaderMap::new(),
        "iroha.health",
        &Map::new(),
    )
    .await;
    assert!(health.get("result").is_some());

    release.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(2), first_wait)
        .await
        .expect("released long poll finishes")
        .expect("long-poll task joins");
    assert_eq!(global.available_permits(), 2);
    assert_eq!(long_poll.available_permits(), 1);
}

#[tokio::test]
async fn cancelling_real_long_poll_releases_both_quotas_and_allows_reentry() {
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let route_release = std::sync::Arc::clone(&release);
    let router =
        axum::Router::new().fallback_service(tower::service_fn(move |_request: Request<Body>| {
            let started_tx = started_tx.clone();
            let release = std::sync::Arc::clone(&route_release);
            async move {
                let _ = started_tx.send(());
                release.notified().await;
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Body::empty())
                        .expect("pending status response"),
                )
            }
        }));
    let mut app = mk_app_state_for_tests();
    let (global, long_poll, _mcp_dispatch_router_owner) = {
        let state = std::sync::Arc::get_mut(&mut app).expect("unique app state");
        state.require_api_token = true;
        state.api_token_digests =
            std::sync::Arc::new(limits::ApiTokenDigestSet::from_tokens(["client"]));
        state.mcp.max_inflight_dispatches = std::num::NonZeroUsize::new(2).expect("nonzero");
        state.mcp_tools = std::sync::Arc::new(vec![iroha_transactions_wait_tool()]);
        state.mcp_dispatch_inflight = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
        state.mcp_long_poll_inflight = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let owner = state.mcp_dispatch_router.install(router);
        (
            std::sync::Arc::clone(&state.mcp_dispatch_inflight),
            std::sync::Arc::clone(&state.mcp_long_poll_inflight),
            owner,
        )
    };
    let wait_arguments = norito::json!({
        "query": { "hash": ("ab".repeat(32)) },
        "timeout_ms": 1,
        "poll_interval_ms": 100
    });
    let cancellation_nonce = cancellation_test_nonce(0x41);
    let wait_request = norito::json!({
        "jsonrpc": (JSONRPC_VERSION),
        "id": "cancel-long-poll",
        "method": "tools/call",
        "params": {
            "name": "iroha.transactions.wait",
            "arguments": (wait_arguments.clone()),
            "_meta": { "iroha/cancellationNonce": (cancellation_nonce.as_str()) }
        }
    });
    let wait_app = std::sync::Arc::clone(&app);
    let wait_headers = cancellation_test_headers("client");
    let first_wait = tokio::spawn(async move {
        handle_tool_call_request(wait_app, &wait_headers, wait_request).await
    });
    tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
        .await
        .expect("first long poll reaches nested status route")
        .expect("nested status router remains live");
    assert_eq!(global.available_permits(), 1);
    assert_eq!(long_poll.available_permits(), 0);

    handle_cancelled_notification(
        &app,
        &cancellation_test_headers("client"),
        &cancel_notification(Value::String("cancel-long-poll".to_owned())),
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), first_wait)
            .await
            .expect("cancelled long poll completes")
            .expect("long-poll task joins"),
        JsonRpcRequestOutcome::Cancelled
    ));
    assert_eq!(global.available_permits(), 2);
    assert_eq!(long_poll.available_permits(), 1);

    let replacement_request = norito::json!({
        "jsonrpc": (JSONRPC_VERSION),
        "id": "replacement-long-poll",
        "method": "tools/call",
        "params": {
            "name": "iroha.transactions.wait",
            "arguments": (wait_arguments),
            "_meta": { "iroha/cancellationNonce": (cancellation_nonce.as_str()) }
        }
    });
    let second_app = std::sync::Arc::clone(&app);
    let second_headers = cancellation_test_headers("client");
    let second_wait = tokio::spawn(async move {
        handle_tool_call_request(second_app, &second_headers, replacement_request).await
    });
    tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
        .await
        .expect("replacement long poll reaches nested status route")
        .expect("nested status router remains live");
    assert_eq!(global.available_permits(), 1);
    assert_eq!(long_poll.available_permits(), 0);
    handle_cancelled_notification(
        &app,
        &cancellation_test_headers("client"),
        &cancel_notification(Value::String("replacement-long-poll".to_owned())),
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), second_wait)
            .await
            .expect("replacement long poll cancellation completes")
            .expect("replacement long-poll task joins"),
        JsonRpcRequestOutcome::Cancelled
    ));
    assert_eq!(global.available_permits(), 2);
    assert_eq!(long_poll.available_permits(), 1);
    drop(release);
}

#[tokio::test]
async fn faucet_tools_dispatch_only_exact_json_bodies_to_exact_routes() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let route_seen = std::sync::Arc::clone(&seen);
    let router =
        axum::Router::new().fallback_service(tower::service_fn(move |request: Request<Body>| {
            let seen = std::sync::Arc::clone(&route_seen);
            async move {
                assert_eq!(request.method(), Method::POST);
                assert_eq!(
                    request
                        .headers()
                        .get(header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok()),
                    Some("application/json")
                );
                let path = request.uri().path().to_owned();
                let bytes = axum::body::to_bytes(request.into_body(), 64 * 1024)
                    .await
                    .expect("nested faucet request body");
                let body: Value = json::from_slice(&bytes).expect("nested faucet JSON");
                seen.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((path, body));
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(Body::empty())
                        .expect("response"),
                )
            }
        }));
    let app = mk_app_state_for_tests();
    let _mcp_dispatch_router_owner = app.mcp_dispatch_router.install(router);
    let prepare_body = norito::json!({
        "schema": "iroha.accounts.faucet.prepare.v1",
        "binding": {},
        "claim": {},
        "fee_payment": {}
    });
    let prepare = norito::json!({ "body": (prepare_body.clone()) });
    dispatch_iroha_accounts_faucet_prepare(
        &app,
        &HeaderMap::new(),
        prepare.as_object().expect("prepare arguments"),
    )
    .await
    .expect("prepare dispatch");

    let submit_body = norito::json!({
        "schema": "iroha.prepared-transaction.v1",
        "binding": {},
        "operation": "faucet",
        "claim": {},
        "semantic_hash_hex": ("ab".repeat(32)),
        "account_id": TEST_ACCOUNT_I105,
        "asset_definition_id": TEST_ASSET_ID,
        "asset_id": TEST_ASSET_ID,
        "amount": "1",
        "transaction_hash_hex": ("cd".repeat(32)),
        "signed_transaction_wire_hex": "00",
        "signed_transaction_wire_sha256": ("ef".repeat(32)),
        "fee_payment": {},
        "server_signature": "AA"
    });
    let submit = norito::json!({ "body": (submit_body.clone()) });
    dispatch_iroha_accounts_faucet_submit(
        &app,
        &HeaderMap::new(),
        submit.as_object().expect("submit arguments"),
    )
    .await
    .expect("submit dispatch");

    assert_eq!(
        *seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        vec![
            ("/v1/accounts/faucet/prepare".to_owned(), prepare_body),
            ("/v1/accounts/faucet".to_owned(), submit_body),
        ]
    );
}

#[tokio::test]
async fn faucet_tools_reject_noncanonical_argument_shapes_before_dispatch() {
    let dispatches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let route_dispatches = std::sync::Arc::clone(&dispatches);
    let router =
        axum::Router::new().fallback_service(tower::service_fn(move |_request: Request<Body>| {
            route_dispatches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move {
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(Body::empty())
                        .expect("response"),
                )
            }
        }));
    let mut app = mk_app_state_for_tests();
    let _mcp_dispatch_router_owner = {
        let state = std::sync::Arc::get_mut(&mut app).expect("unique app state");
        state.mcp.profile = ToriiMcpProfile::Writer;
        state.account_faucet = Some(test_faucet_runtime_config());
        state.mcp_tools = std::sync::Arc::new(build_tool_specs(&state.mcp));
        state.mcp_dispatch_router.install(router)
    };
    for (name, invalid_arguments) in [
        (
            "iroha.accounts.faucet.prepare",
            norito::json!({
                "schema": "iroha.accounts.faucet.prepare.v1",
                "binding": {},
                "claim": {},
                "fee_payment": {}
            }),
        ),
        (
            "iroha.accounts.faucet.prepare",
            norito::json!({
                "body": {
                    "schema": "iroha.accounts.faucet.prepare.v1",
                    "binding": {},
                    "claim": {},
                    "fee_payment": {},
                    "unexpected": true
                }
            }),
        ),
        (
            "iroha.accounts.faucet.submit",
            norito::json!({
                "body": {},
                "headers": { "authorization": "must-not-be-forwarded" }
            }),
        ),
        (
            "iroha.accounts.faucet.submit",
            norito::json!({ "body": {}, "schema": "dual-shape" }),
        ),
    ] {
        let response = handle_named_tool_call(
            Some(Value::String(format!("invalid-{name}"))),
            std::sync::Arc::clone(&app),
            &HeaderMap::new(),
            name,
            invalid_arguments
                .as_object()
                .expect("invalid arguments object"),
        )
        .await;
        assert_eq!(
            response
                .pointer("/error/data/error_code")
                .and_then(Value::as_str),
            Some("tool_schema_validation_failed"),
            "noncanonical faucet arguments reached dispatch: {response:?}"
        );
    }
    assert_eq!(
        dispatches.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "schema-invalid faucet calls must not reach the nested router"
    );
}

fn cancellation_test_headers(token: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(HEADER_X_API_TOKEN, HeaderValue::from_static(token));
    headers
}

fn cancellation_test_nonce(fill: u8) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([fill; 32])
}

fn cancellable_health_request(id: Value) -> Value {
    cancellable_health_request_with_nonce(id, cancellation_test_nonce(0x41).as_str())
}

fn cancellable_health_request_with_nonce(id: Value, cancellation_nonce: &str) -> Value {
    norito::json!({
        "jsonrpc": (JSONRPC_VERSION),
        "id": (id),
        "method": "tools/call",
        "params": {
            "name": "iroha.health",
            "arguments": {},
            "_meta": { "iroha/cancellationNonce": (cancellation_nonce) }
        }
    })
}

fn cancel_notification(id: Value) -> Value {
    cancel_notification_with_nonce(id, cancellation_test_nonce(0x41).as_str())
}

fn cancel_notification_with_nonce(id: Value, cancellation_nonce: &str) -> Value {
    norito::json!({
        "jsonrpc": (JSONRPC_VERSION),
        "method": "notifications/cancelled",
        "params": {
            "requestId": (id),
            "reason": "test cancellation",
            "_meta": { "iroha/cancellationNonce": (cancellation_nonce) }
        }
    })
}

#[test]
fn cancellation_keys_preserve_lossless_json_id_representation() {
    let signed = ExactJsonRpcId::from_value(&Value::Number(json::native::Number::I64(7)))
        .expect("signed id");
    let unsigned = ExactJsonRpcId::from_value(&Value::Number(json::native::Number::U64(7)))
        .expect("unsigned id");
    let string = ExactJsonRpcId::from_value(&Value::String("7".to_owned())).expect("string id");
    assert_ne!(signed, unsigned);
    assert_ne!(signed, string);
    assert_ne!(unsigned, string);

    let fractional: Value = json::from_str("7.5").expect("fractional JSON id");
    assert!(ExactJsonRpcId::from_value(&fractional).is_none());
    let oversized_a: Value = json::from_str("18446744073709551616").expect("oversized JSON id A");
    let oversized_b: Value = json::from_str("18446744073709551617").expect("oversized JSON id B");
    assert_ne!(
        oversized_a, oversized_b,
        "wide integer JSON values must remain exact"
    );
    assert!(ExactJsonRpcId::from_value(&oversized_a).is_none());
    assert!(ExactJsonRpcId::from_value(&oversized_b).is_none());

    let valid_nonce = cancellation_test_nonce(0x5a);
    let params = norito::json!({
        "_meta": { "iroha/cancellationNonce": (valid_nonce.clone()) }
    });
    assert_eq!(
        cancellation_nonce_from_params(params.as_object().expect("params")),
        Ok(Some([0x5a; 32]))
    );
    for invalid in [
        norito::json!({ "_meta": "not-an-object" }),
        norito::json!({ "_meta": { "iroha/cancellationNonce": 7 } }),
        norito::json!({ "_meta": { "iroha/cancellationNonce": "short" } }),
        norito::json!({
            "_meta": { "iroha/cancellationNonce": (format!("{valid_nonce}=")) }
        }),
    ] {
        assert_eq!(
            cancellation_nonce_from_params(invalid.as_object().expect("params")),
            Err(())
        );
    }
}

#[tokio::test]
async fn malformed_authenticated_cancellation_nonce_is_rejected() {
    let mut app = mk_app_state_for_tests();
    {
        let state = std::sync::Arc::get_mut(&mut app).expect("unique app state");
        state.require_api_token = true;
        state.api_token_digests =
            std::sync::Arc::new(limits::ApiTokenDigestSet::from_tokens(["client"]));
    }
    let request = cancellable_health_request_with_nonce(
        Value::String("invalid-nonce".to_owned()),
        "not-canonical",
    );
    let outcome =
        handle_tool_call_request(app, &cancellation_test_headers("client"), request).await;
    let JsonRpcRequestOutcome::Response(response) = outcome else {
        panic!("malformed cancellation nonce must return a JSON-RPC error");
    };
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(JSONRPC_INVALID_PARAMS)
    );
    assert_eq!(
        response
            .pointer("/error/data/error_code")
            .and_then(Value::as_str),
        Some("invalid_cancellation_nonce")
    );
}

#[test]
fn authenticated_call_without_nonce_remains_non_cancellable() {
    let mut app = mk_app_state_for_tests();
    {
        let state = std::sync::Arc::get_mut(&mut app).expect("unique app state");
        state.require_api_token = true;
        state.api_token_digests =
            std::sync::Arc::new(limits::ApiTokenDigestSet::from_tokens(["client"]));
    }
    let params = norito::json!({ "name": "iroha.health", "arguments": {} });
    assert!(matches!(
        register_authenticated_inflight_request(
            &app,
            &cancellation_test_headers("client"),
            Some(&Value::String("ordinary".to_owned())),
            params.as_object().expect("params"),
        ),
        Ok(None)
    ));
}

#[tokio::test]
async fn oversized_numeric_ids_cannot_enter_or_target_cancellation_registry() {
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let dispatches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let route_started = std::sync::Arc::clone(&started);
    let route_release = std::sync::Arc::clone(&release);
    let route_dispatches = std::sync::Arc::clone(&dispatches);
    let router =
        axum::Router::new().fallback_service(tower::service_fn(move |_request: Request<Body>| {
            let started = std::sync::Arc::clone(&route_started);
            let release = std::sync::Arc::clone(&route_release);
            let dispatches = std::sync::Arc::clone(&route_dispatches);
            async move {
                dispatches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                started.notify_one();
                release.notified().await;
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(Body::empty())
                        .expect("response"),
                )
            }
        }));
    let mut app = mk_app_state_for_tests();
    let _mcp_dispatch_router_owner = {
        let state = std::sync::Arc::get_mut(&mut app).expect("unique app state");
        state.require_api_token = true;
        state.api_token_digests =
            std::sync::Arc::new(limits::ApiTokenDigestSet::from_tokens(["client"]));
        state.mcp_tools = std::sync::Arc::new(vec![iroha_health_tool()]);
        state.mcp_dispatch_router.install(router)
    };
    let cancellation_nonce = cancellation_test_nonce(0x41);
    let request_json = r#"{"jsonrpc":"2.0","id":18446744073709551616,"method":"tools/call","params":{"name":"iroha.health","arguments":{},"_meta":{"iroha/cancellationNonce":"__NONCE__"}}}"#
        .replace("__NONCE__", &cancellation_nonce);
    let request: Value = json::from_str(&request_json).expect("oversized-id request");
    let headers = cancellation_test_headers("client");
    let JsonRpcRequestOutcome::Response(response) =
        handle_tool_call_request(std::sync::Arc::clone(&app), &headers, request).await
    else {
        panic!("an oversized numeric request id cannot become cancellable")
    };
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(JSONRPC_INVALID_REQUEST)
    );
    assert_eq!(
        dispatches.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an out-of-range JSON-RPC id must be rejected before tool dispatch"
    );

    let call_app = std::sync::Arc::clone(&app);
    let call_headers = cancellation_test_headers("client");
    let call = tokio::spawn(async move {
        handle_tool_call_request(
            call_app,
            &call_headers,
            cancellable_health_request(Value::Number(json::native::Number::U64(u64::MAX))),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), started.notified())
        .await
        .expect("largest supported numeric id reaches dispatch");

    let notification_json = r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":18446744073709551617,"_meta":{"iroha/cancellationNonce":"__NONCE__"}}}"#
        .replace("__NONCE__", &cancellation_nonce);
    let notification: Value =
        json::from_str(&notification_json).expect("oversized cancellation notification");
    handle_cancelled_notification(&app, &cancellation_test_headers("client"), &notification);
    tokio::task::yield_now().await;
    assert!(
        !call.is_finished(),
        "an out-of-range numeric cancellation must not target a valid live request"
    );
    release.notify_one();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), call)
            .await
            .expect("released request completes")
            .expect("request task joins"),
        JsonRpcRequestOutcome::Response(_)
    ));
    assert_eq!(
        dispatches.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "only the valid numeric-id request may reach tool dispatch"
    );
}

#[tokio::test]
async fn cancellation_is_bound_to_authenticated_client_exact_id_and_nonce() {
    let started_a = std::sync::Arc::new(tokio::sync::Notify::new());
    let started_b = std::sync::Arc::new(tokio::sync::Notify::new());
    let release_a = std::sync::Arc::new(tokio::sync::Notify::new());
    let release_b = std::sync::Arc::new(tokio::sync::Notify::new());
    let route_started_a = std::sync::Arc::clone(&started_a);
    let route_started_b = std::sync::Arc::clone(&started_b);
    let route_release_a = std::sync::Arc::clone(&release_a);
    let route_release_b = std::sync::Arc::clone(&release_b);
    let router =
        axum::Router::new().fallback_service(tower::service_fn(move |request: Request<Body>| {
            let token = request
                .headers()
                .get(HEADER_X_API_TOKEN)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let started_a = std::sync::Arc::clone(&route_started_a);
            let started_b = std::sync::Arc::clone(&route_started_b);
            let release_a = std::sync::Arc::clone(&route_release_a);
            let release_b = std::sync::Arc::clone(&route_release_b);
            async move {
                match token.as_str() {
                    "client-a" => {
                        started_a.notify_one();
                        release_a.notified().await;
                    }
                    "client-b" => {
                        started_b.notify_one();
                        release_b.notified().await;
                    }
                    _ => panic!("unexpected nested authentication principal"),
                }
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(Body::empty())
                        .expect("response"),
                )
            }
        }));
    let mut app = mk_app_state_for_tests();
    let (global, _mcp_dispatch_router_owner) = {
        let state = std::sync::Arc::get_mut(&mut app).expect("unique app state");
        state.require_api_token = true;
        state.api_token_digests = std::sync::Arc::new(limits::ApiTokenDigestSet::from_tokens([
            "client-a", "client-b",
        ]));
        state.mcp.max_inflight_dispatches = std::num::NonZeroUsize::new(4).expect("nonzero");
        state.mcp_tools = std::sync::Arc::new(vec![iroha_health_tool()]);
        state.mcp_dispatch_inflight = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
        let owner = state.mcp_dispatch_router.install(router);
        (std::sync::Arc::clone(&state.mcp_dispatch_inflight), owner)
    };
    let shared_id = Value::String("shared".to_owned());
    let app_a = std::sync::Arc::clone(&app);
    let headers_a = cancellation_test_headers("client-a");
    let request_a = cancellable_health_request(shared_id.clone());
    let call_a =
        tokio::spawn(async move { handle_tool_call_request(app_a, &headers_a, request_a).await });
    let app_b = std::sync::Arc::clone(&app);
    let headers_b = cancellation_test_headers("client-b");
    let request_b = cancellable_health_request(shared_id.clone());
    let call_b =
        tokio::spawn(async move { handle_tool_call_request(app_b, &headers_b, request_b).await });
    tokio::time::timeout(Duration::from_secs(2), started_a.notified())
        .await
        .expect("client A dispatch starts");
    tokio::time::timeout(Duration::from_secs(2), started_b.notified())
        .await
        .expect("client B dispatch starts");

    let duplicate = handle_tool_call_request(
        std::sync::Arc::clone(&app),
        &cancellation_test_headers("client-a"),
        cancellable_health_request_with_nonce(
            shared_id.clone(),
            cancellation_test_nonce(0x42).as_str(),
        ),
    )
    .await;
    let JsonRpcRequestOutcome::Response(duplicate) = duplicate else {
        panic!("duplicate live id must fail without cancelling its incumbent");
    };
    assert_eq!(
        duplicate
            .get("error")
            .and_then(|error| error.get("data"))
            .and_then(|data| data.get("error_code"))
            .and_then(Value::as_str),
        Some("request_id_in_use")
    );

    handle_cancelled_notification(
        &app,
        &cancellation_test_headers("client-a"),
        &cancel_notification(shared_id.clone()),
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), call_a)
            .await
            .expect("client A cancellation completes")
            .expect("client A task joins"),
        JsonRpcRequestOutcome::Cancelled
    ));
    assert!(
        !call_b.is_finished(),
        "client A cancellation must not affect client B's identical id"
    );
    handle_cancelled_notification(
        &app,
        &cancellation_test_headers("client-b"),
        &cancel_notification(shared_id.clone()),
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), call_b)
            .await
            .expect("client B cancellation completes")
            .expect("client B task joins"),
        JsonRpcRequestOutcome::Cancelled
    ));
    assert_eq!(global.available_permits(), 4);

    let replacement_nonce = cancellation_test_nonce(0x43);
    let reused_app = std::sync::Arc::clone(&app);
    let reused_headers = cancellation_test_headers("client-a");
    let reused_request =
        cancellable_health_request_with_nonce(shared_id.clone(), replacement_nonce.as_str());
    let reused = tokio::spawn(async move {
        handle_tool_call_request(reused_app, &reused_headers, reused_request).await
    });
    tokio::time::timeout(Duration::from_secs(2), started_a.notified())
        .await
        .expect("reused id with a new nonce starts after cleanup");
    handle_cancelled_notification(
        &app,
        &cancellation_test_headers("client-a"),
        &cancel_notification(shared_id.clone()),
    );
    {
        let key = McpInflightKey {
            client_fingerprint: authenticated_cancellation_client_fingerprint(
                &app,
                &cancellation_test_headers("client-a"),
            )
            .expect("authenticated client fingerprint"),
            request_id: ExactJsonRpcId::from_value(&shared_id).expect("exact shared id"),
        };
        let entries = app
            .mcp_inflight_requests
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = entries.get(&key).expect("replacement remains registered");
        assert_eq!(entry.cancellation_nonce, [0x43; 32]);
        assert!(
            !*entry.cancellation.borrow(),
            "a delayed cancellation for the retired nonce must not affect ID reuse"
        );
    }
    handle_cancelled_notification(
        &app,
        &cancellation_test_headers("client-a"),
        &cancel_notification_with_nonce(shared_id, replacement_nonce.as_str()),
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), reused)
            .await
            .expect("replacement nonce cancellation completes")
            .expect("replacement request task joins"),
        JsonRpcRequestOutcome::Cancelled
    ));
    assert_eq!(global.available_permits(), 4);
    drop((release_a, release_b));
}

#[tokio::test]
async fn cancellation_registry_capacity_rejects_overflow_and_recovers_after_drop() {
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let route_release = std::sync::Arc::clone(&release);
    let router =
        axum::Router::new().fallback_service(tower::service_fn(move |_request: Request<Body>| {
            let started_tx = started_tx.clone();
            let release = std::sync::Arc::clone(&route_release);
            async move {
                let _ = started_tx.send(());
                release.notified().await;
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(Body::empty())
                        .expect("response"),
                )
            }
        }));
    let mut app = mk_app_state_for_tests();
    let (global, _mcp_dispatch_router_owner) = {
        let state = std::sync::Arc::get_mut(&mut app).expect("unique app state");
        state.require_api_token = true;
        state.api_token_digests =
            std::sync::Arc::new(limits::ApiTokenDigestSet::from_tokens(["client"]));
        state.mcp.max_inflight_dispatches = std::num::NonZeroUsize::new(2).expect("nonzero");
        state.mcp_tools = std::sync::Arc::new(vec![iroha_health_tool()]);
        state.mcp_dispatch_inflight = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
        let owner = state.mcp_dispatch_router.install(router);
        (std::sync::Arc::clone(&state.mcp_dispatch_inflight), owner)
    };
    let first_app = std::sync::Arc::clone(&app);
    let first_headers = cancellation_test_headers("client");
    let first = tokio::spawn(async move {
        handle_tool_call_request(
            first_app,
            &first_headers,
            cancellable_health_request(Value::String("one".to_owned())),
        )
        .await
    });
    let second_app = std::sync::Arc::clone(&app);
    let second_headers = cancellation_test_headers("client");
    let second = tokio::spawn(async move {
        handle_tool_call_request(
            second_app,
            &second_headers,
            cancellable_health_request(Value::String("two".to_owned())),
        )
        .await
    });
    for label in ["first", "second"] {
        tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
            .await
            .unwrap_or_else(|_| panic!("{label} request reaches nested route"))
            .expect("nested router remains live");
    }
    assert_eq!(global.available_permits(), 0);

    let overflow_id = Value::String("overflow".to_owned());
    let overflow = handle_tool_call_request(
        std::sync::Arc::clone(&app),
        &cancellation_test_headers("client"),
        cancellable_health_request(overflow_id.clone()),
    )
    .await;
    let JsonRpcRequestOutcome::Response(overflow) = overflow else {
        panic!("capacity overflow must return a JSON-RPC error");
    };
    assert_eq!(overflow.get("id"), Some(&overflow_id));
    assert_eq!(
        overflow.pointer("/error/code").and_then(Value::as_i64),
        Some(MCP_DISPATCH_CAPACITY_EXHAUSTED)
    );
    assert_eq!(
        overflow
            .pointer("/error/data/error_code")
            .and_then(Value::as_str),
        Some("cancellation_registry_capacity_exhausted")
    );
    assert_eq!(
        overflow
            .pointer("/error/data/max_inflight_dispatches")
            .and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        overflow
            .pointer("/error/data/retryable")
            .and_then(Value::as_bool),
        Some(true)
    );

    handle_cancelled_notification(
        &app,
        &cancellation_test_headers("client"),
        &cancel_notification(Value::String("one".to_owned())),
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), first)
            .await
            .expect("first cancellation completes")
            .expect("first request task joins"),
        JsonRpcRequestOutcome::Cancelled
    ));
    assert_eq!(global.available_permits(), 1);

    let replacement_app = std::sync::Arc::clone(&app);
    let replacement_headers = cancellation_test_headers("client");
    let replacement = tokio::spawn(async move {
        handle_tool_call_request(
            replacement_app,
            &replacement_headers,
            cancellable_health_request(Value::String("replacement".to_owned())),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
        .await
        .expect("replacement request reaches nested route")
        .expect("nested router remains live");
    assert_eq!(global.available_permits(), 0);

    for request_id in ["two", "replacement"] {
        handle_cancelled_notification(
            &app,
            &cancellation_test_headers("client"),
            &cancel_notification(Value::String(request_id.to_owned())),
        );
    }
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), second)
            .await
            .expect("second cancellation completes")
            .expect("second request task joins"),
        JsonRpcRequestOutcome::Cancelled
    ));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), replacement)
            .await
            .expect("replacement cancellation completes")
            .expect("replacement request task joins"),
        JsonRpcRequestOutcome::Cancelled
    ));
    assert_eq!(global.available_permits(), 2);
    drop(release);
}

#[test]
fn anonymous_or_invalid_tokens_have_no_cancellation_identity() {
    let mut app = mk_app_state_for_tests();
    assert!(authenticated_cancellation_client_fingerprint(&app, &HeaderMap::new()).is_none());
    let state = std::sync::Arc::get_mut(&mut app).expect("unique app state");
    state.require_api_token = true;
    state.api_token_digests =
        std::sync::Arc::new(limits::ApiTokenDigestSet::from_tokens(["valid"]));
    assert!(
        authenticated_cancellation_client_fingerprint(&app, &cancellation_test_headers("invalid"))
            .is_none()
    );
}
#[test]
fn stateless_discovery_includes_toolset_version() {
    let tool = sample_tool("iroha.health", Method::GET, ToolEffect::Read);
    let refs = vec![&tool];
    let payload = modern_discovery_payload(&refs);
    let toolset_version = payload
        .get("capabilities")
        .and_then(|caps| caps.get("extensions"))
        .and_then(|extensions| extensions.get("org.hyperledger.iroha/tools"))
        .and_then(|tools| tools.get("toolsetVersion"))
        .and_then(Value::as_str)
        .expect("toolsetVersion");
    assert!(
        !toolset_version.is_empty(),
        "toolsetVersion must not be empty"
    );
    assert_eq!(
        payload.get("supportedVersions"),
        Some(&norito::json!([(protocol::MODERN_PROTOCOL_VERSION)]))
    );
}
#[test]
fn origin_and_protocol_headers_reject_ambiguous_values() {
    let allowed = [HeaderValue::from_static("https://trusted.example")];
    let mut headers = HeaderMap::new();
    assert!(origin_is_allowed(&headers, &allowed));
    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://trusted.example"),
    );
    assert!(origin_is_allowed(&headers, &allowed));
    headers.append(
        header::ORIGIN,
        HeaderValue::from_static("https://trusted.example"),
    );
    assert!(!origin_is_allowed(&headers, &allowed));

    let mut headers = HeaderMap::new();
    assert!(!protocol_version_is_supported(&headers));
    headers.insert(
        HEADER_MCP_PROTOCOL_VERSION,
        HeaderValue::from_static(protocol::MODERN_PROTOCOL_VERSION),
    );
    assert!(protocol_version_is_supported(&headers));
    headers.append(
        HEADER_MCP_PROTOCOL_VERSION,
        HeaderValue::from_static(protocol::MODERN_PROTOCOL_VERSION),
    );
    assert!(!protocol_version_is_supported(&headers));
}
#[test]
fn sanitize_tool_input_schema_preserves_top_level_combinators() {
    let schema = norito::json!({
        "type": "object",
        "additionalProperties": false,
        "anyOf": [
            {
                "properties": {
                    "alpha": { "type": "string" }
                },
                "required": ["alpha"]
            },
            {
                "properties": {
                    "beta": { "type": "string" }
                },
                "required": ["beta"]
            }
        ],
        "properties": {
            "path": {
                "type": "object",
                "properties": {
                    "alpha": { "type": "string" },
                    "beta": { "type": "string" }
                }
            }
        }
    });
    let sanitized = sanitize_tool_input_schema(&schema);
    let sanitized_obj = sanitized.as_object().expect("sanitized object schema");
    assert_eq!(
        sanitized_obj.get("type").and_then(Value::as_str),
        Some("object")
    );
    assert_eq!(
        sanitized_obj
            .get("anyOf")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(2)
    );
    let properties = sanitized_obj
        .get("properties")
        .and_then(Value::as_object)
        .expect("properties object");
    assert!(properties.contains_key("path"));
    let path_schema = properties
        .get("path")
        .and_then(Value::as_object)
        .expect("path schema");
    assert_eq!(
        path_schema
            .get("additionalProperties")
            .and_then(Value::as_bool),
        Some(false)
    );
}
#[test]
fn tool_argument_schema_validation_enforces_security_relevant_keywords() {
    let mut tool = sample_tool("iroha.schema-test", Method::POST, ToolEffect::Write);
    tool.input_schema = norito::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["label", "count"],
        "properties": {
            "label": { "type": "string", "pattern": "^[a-z]+$", "minLength": 2 },
            "count": { "type": "integer", "minimum": 1, "maximum": 3 },
            "alpha": { "type": "string" },
            "beta": { "type": "string" }
        },
        "oneOf": [
            { "required": ["alpha"] },
            { "required": ["beta"] }
        ]
    });
    let valid = norito::json!({ "label": "ok", "count": 2, "alpha": "yes" });
    assert!(validate_tool_arguments(&tool, valid.as_object().expect("object")).is_ok());
    for invalid in [
        norito::json!({ "label": "UP", "count": 2, "alpha": "yes" }),
        norito::json!({ "label": "ok", "count": 4, "alpha": "yes" }),
        norito::json!({ "label": "ok", "count": 2, "alpha": "yes", "beta": "yes" }),
        norito::json!({ "label": "ok", "count": 2, "alpha": "yes", "hidden": true }),
    ] {
        assert!(
            validate_tool_arguments(&tool, invalid.as_object().expect("object")).is_err(),
            "invalid arguments passed: {invalid:?}"
        );
    }
}
#[test]
fn conditional_schema_validation_selects_nested_or_flat_branch() {
    let mut tool = sample_tool("iroha.schema-test", Method::POST, ToolEffect::Write);
    tool.input_schema = norito::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["headers"],
        "properties": {
            "body": {
                "type": "object",
                "properties": { "value": { "type": "string" } }
            },
            "value": { "type": "string" },
            "headers": {
                "type": "object",
                "additionalProperties": false
            }
        },
        "if": { "required": ["body"] },
        "then": {
            "properties": {
                "body": { "required": ["value"] }
            }
        },
        "else": { "required": ["value"] }
    });
    for valid in [
        norito::json!({ "body": { "value": "nested" }, "headers": {} }),
        norito::json!({ "value": "flat", "headers": {} }),
    ] {
        validate_tool_arguments(&tool, valid.as_object().expect("object"))
            .unwrap_or_else(|error| panic!("valid conditional branch failed: {error}"));
    }
    for invalid in [
        norito::json!({ "body": {}, "headers": {} }),
        norito::json!({ "headers": {} }),
    ] {
        assert!(
            validate_tool_arguments(&tool, invalid.as_object().expect("object")).is_err(),
            "invalid conditional branch passed: {invalid:?}"
        );
    }
}
#[test]
fn nonzero_hex_pattern_is_enforced_without_regex_lookaround() {
    let mut tool = sample_tool("iroha.schema-test", Method::POST, ToolEffect::Write);
    tool.input_schema = norito::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["signature"],
        "properties": {
            "signature": { "type": "string", "pattern": NONZERO_UPPER_HEX_PATTERN }
        }
    });
    for invalid in ["0000", "0A0", "0a0b", "GG"] {
        let arguments = norito::json!({ "signature": invalid });
        assert!(
            validate_tool_arguments(&tool, arguments.as_object().expect("object")).is_err(),
            "invalid signature passed: {invalid}"
        );
    }
    let valid = norito::json!({ "signature": "000A" });
    assert!(validate_tool_arguments(&tool, valid.as_object().expect("object")).is_ok());
}
#[test]
fn unsupported_schema_pattern_fails_registry_validation() {
    let mut tool = sample_tool("iroha.schema-test", Method::POST, ToolEffect::Write);
    tool.input_schema = norito::json!({
        "type": "object",
        "properties": {
            "value": { "type": "string", "pattern": "(?=unsupported)" }
        }
    });
    assert!(
        validate_tool_registry(&[tool], &[])
            .expect_err("unsupported schema regex must fail closed")
            .contains("unsupported regex")
    );
}
#[test]
fn unresolved_input_schema_ref_fails_registry_validation() {
    let mut tool = sample_tool("iroha.schema-test", Method::POST, ToolEffect::Write);
    tool.input_schema = norito::json!({
        "type": "object",
        "properties": {
            "body": { "$ref": "#/components/schemas/Missing" }
        }
    });
    let error = validate_tool_registry(&[tool], &[])
        .expect_err("an advertised schema must not retain OpenAPI references");
    assert!(error.contains("unresolved OpenAPI reference"));
}
#[test]
fn patterned_array_validation_compiles_each_schema_regex_once() {
    let pattern = "^mcp-regex-cache-regression-[a-z]+$";
    ADVERTISED_REGEX_CACHE
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(pattern);
    ADVERTISED_REGEX_COMPILE_COUNTS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(pattern);
    let schema = norito::json!({
        "type": "array",
        "items": { "type": "string", "pattern": pattern }
    });
    let values = Value::Array(
        (0..2_048)
            .map(|_| Value::String("mcp-regex-cache-regression-safe".to_owned()))
            .collect(),
    );
    validate_json_schema_value(&schema, &values, "arguments.namespaces")
        .expect("homogeneous patterned array validates");
    assert_eq!(
        ADVERTISED_REGEX_COMPILE_COUNTS
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(pattern),
        Some(&1),
        "one schema pattern must be compiled once regardless of item count"
    );
}
#[test]
fn generic_request_body_rejects_dual_representations() {
    let arguments = norito::json!({
        "body": { "reviewed": true },
        "body_base64": "ZXhlY3V0ZWQ="
    });
    let error = build_request_body(arguments.as_object().expect("object"), None)
        .expect_err("dual body representations must not pick a hidden winner");
    assert!(error.contains("mutually exclusive"));
}

#[test]
fn generic_xml_request_body_uses_exact_text_bytes_and_media_type() {
    let xml = "<Document><MsgId>exact</MsgId></Document>";
    let arguments = norito::json!({ "body": xml });
    let (body, content_type) = build_request_body(
        arguments.as_object().expect("object"),
        Some("application/xml"),
    )
    .expect("XML body");

    assert_eq!(body, xml.as_bytes());
    assert_eq!(content_type, Some("application/xml"));
}

#[test]
fn generated_iso_tool_advertises_raw_xml_as_its_default_media_type() {
    let cfg = iroha_config::parameters::actual::ToriiMcp {
        profile: ToriiMcpProfile::Operator,
        expose_operator_routes: true,
        ..Default::default()
    };
    let tools = build_tool_specs(&cfg);
    let tool = tools
        .iter()
        .find(|tool| tool.name == "torii.post_v1_iso20022_pacs008")
        .expect("OpenAPI-derived pacs.008 tool");
    let properties = tool
        .input_schema
        .get("properties")
        .and_then(Value::as_object)
        .expect("tool properties");

    assert_eq!(
        properties
            .get("content_type")
            .and_then(|schema| schema.get("const"))
            .and_then(Value::as_str),
        Some("application/xml")
    );
    assert_eq!(
        properties
            .get("body")
            .and_then(|schema| schema.get("type"))
            .and_then(Value::as_str),
        Some("string")
    );
}
#[test]
fn sanitize_tool_input_schema_keeps_only_raw_body_open() {
    let schema = norito::json!({
        "type": "object",
        "properties": {
            "headers": {
                "type": "object",
                "properties": {
                    "x-api-token": { "type": "string" }
                },
                "additionalProperties": true
            },
            "body": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "payload": {
                        "type": "object",
                        "additionalProperties": false
                    }
                }
            }
        }
    });
    let sanitized = sanitize_tool_input_schema(&schema);
    let properties = sanitized
        .get("properties")
        .and_then(Value::as_object)
        .expect("properties");
    let headers = properties
        .get("headers")
        .and_then(Value::as_object)
        .expect("headers schema");
    assert_eq!(
        headers.get("additionalProperties").and_then(Value::as_bool),
        Some(false)
    );
    let body = properties
        .get("body")
        .and_then(Value::as_object)
        .expect("body schema");
    assert_eq!(
        body.get("additionalProperties").and_then(Value::as_bool),
        Some(true)
    );
    let payload = body
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|props| props.get("payload"))
        .and_then(Value::as_object)
        .expect("payload schema");
    assert_eq!(
        payload.get("additionalProperties").and_then(Value::as_bool),
        Some(true)
    );
}
#[test]
fn sanitize_tool_input_schema_preserves_closed_typed_bodies() {
    let schema = norito::json!({
        "type": "object",
        "x-iroha-mcp-strict-body": true,
        "required": ["body"],
        "properties": {
            "body": {
                "type": "object",
                "additionalProperties": true,
                "required": ["payload"],
                "properties": {
                    "payload": {
                        "type": "object",
                        "properties": {
                            "revision": { "type": "integer" }
                        }
                    }
                }
            },
            "headers": {
                "type": "object",
                "additionalProperties": { "type": "string" }
            }
        }
    });
    let sanitized = sanitize_tool_input_schema(&schema);
    let root = sanitized.as_object().expect("sanitized object schema");
    assert!(!root.contains_key(MCP_STRICT_BODY_SCHEMA_EXTENSION));
    assert_eq!(
        root.get("additionalProperties").and_then(Value::as_bool),
        Some(false)
    );
    let properties = root
        .get("properties")
        .and_then(Value::as_object)
        .expect("properties");
    let body = properties
        .get("body")
        .and_then(Value::as_object)
        .expect("body schema");
    assert_eq!(
        body.get("additionalProperties").and_then(Value::as_bool),
        Some(false)
    );
    let payload = body
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("payload"))
        .and_then(Value::as_object)
        .expect("payload schema");
    assert_eq!(
        payload.get("additionalProperties").and_then(Value::as_bool),
        Some(false)
    );
    let headers = properties
        .get("headers")
        .and_then(Value::as_object)
        .expect("headers schema");
    assert_eq!(
        headers.get("additionalProperties").and_then(Value::as_bool),
        Some(false)
    );
}
#[test]
fn whole_catalog_publishes_self_contained_input_schemas() {
    let cfg = iroha_config::parameters::actual::ToriiMcp {
        profile: ToriiMcpProfile::Operator,
        expose_operator_routes: true,
        ..Default::default()
    };
    let tools = build_tool_specs(&cfg);
    assert!(!tools.is_empty(), "the MCP catalog must not be empty");
    for tool in tools {
        let descriptor = tool.descriptor();
        let input_schema = descriptor
            .get("inputSchema")
            .expect("tool descriptor inputSchema");
        let input_schema = expand_advertised_schema_refs(input_schema);
        assert_eq!(
            input_schema,
            sanitize_tool_input_schema(&tool.input_schema),
            "tool `{}` advertised references must preserve every input constraint",
            tool.name
        );
        reject_unresolved_schema_refs(
            &input_schema,
            &format!("tool `{}` advertised inputSchema", tool.name),
        )
        .unwrap_or_else(|error| panic!("{error}"));
    }
}

#[tokio::test]
async fn disabled_faucet_tools_are_omitted_and_rejected_at_runtime() {
    let mut app = mk_app_state_for_tests();
    let state = std::sync::Arc::get_mut(&mut app).expect("unique app state");
    assert!(state.account_faucet.is_none());
    state.mcp.profile = ToriiMcpProfile::Writer;
    state.mcp_tools = std::sync::Arc::new(vec![
        iroha_health_tool(),
        iroha_accounts_faucet_policy_tool(),
        iroha_accounts_faucet_prepare_tool(),
        iroha_accounts_faucet_submit_tool(),
    ]);
    let visible = visible_tools_for_app(&app);
    assert_eq!(
        visible
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        vec!["iroha.health"]
    );
    for name in [
        "iroha.accounts.faucet.policy",
        "iroha.accounts.faucet.prepare",
        "iroha.accounts.faucet.submit",
    ] {
        let response = handle_named_tool_call(
            Some(Value::String(format!("disabled-{name}"))),
            std::sync::Arc::clone(&app),
            &HeaderMap::new(),
            name,
            &Map::new(),
        )
        .await;
        assert_eq!(
            response
                .pointer("/error/data/error_code")
                .and_then(Value::as_str),
            Some(MCP_TOOL_UNAVAILABLE)
        );
    }
}

#[test]
fn unreviewed_manual_tool_names_fail_closed_to_write() {
    for name in [
        "iroha.future.get",
        "iroha.future.list",
        "iroha.future.query",
        "iroha.future.telemetry",
        "iroha.future.wait",
    ] {
        assert_eq!(
            manual_tool_effect_from_name(name),
            ToolEffect::Write,
            "unreviewed name `{name}` must not gain read-only policy access from its suffix"
        );
    }
}

#[test]
fn raw_body_tool_requires_the_body_object() {
    let tool = simple_manual_raw_body_post_tool(
        "iroha.test.raw",
        "test raw body",
        "/v1/test/raw",
        "test payload",
    );
    let advertised = sanitize_tool_input_schema(&tool.input_schema);
    assert_eq!(
        advertised
            .get("additionalProperties")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(advertised.get("required"), Some(&norito::json!(["body"])));
    let payload = norito::json!({
        "manifest": { "payload_hash": "ABC" },
        "chunk": [1, 2, 3]
    });
    validate_tool_arguments(&tool, payload.as_object().expect("object"))
        .expect_err("top-level payload fields are not a request body");
    let arguments = norito::json!({ "body": (payload.clone()) });
    let arguments = arguments.as_object().expect("object");
    validate_tool_arguments(&tool, arguments).expect("body matches advertised schema");
    let body = build_required_object_body(arguments).expect("body is an object");
    let encoded = encode_mcp_json_body(&body, "test body").expect("encode body");
    let decoded: Value = json::from_slice(&encoded).expect("decode body");
    assert_eq!(decoded, payload);
}
#[test]
fn descriptor_publishes_canonical_connect_sid_schema() {
    let tool = ToolSpec::route(
        "iroha.connect.session.delete".to_owned(),
        "Delete/purge an Iroha Connect session by SID.".to_owned(),
        ToolEffect::Write,
        Method::DELETE,
        "/v1/connect/session/{sid}".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "sid": {
                    "type": "string",
                    "pattern": "^[A-Za-z0-9_-]{43}$"
                }
            },
            "required": ["sid"]
        }),
    );
    let descriptor = tool.descriptor();
    let schema = descriptor
        .get("inputSchema")
        .and_then(Value::as_object)
        .expect("inputSchema object");
    assert_eq!(schema.get("type").and_then(Value::as_str), Some("object"));
    assert!(!schema.contains_key("oneOf"));
    assert!(!schema.contains_key("anyOf"));
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .expect("properties object");
    assert!(properties.contains_key("sid"));
    assert!(!properties.contains_key("session_id"));
    assert_eq!(
        schema
            .get("required")
            .and_then(Value::as_array)
            .and_then(|required| required.first())
            .and_then(Value::as_str),
        Some("sid")
    );
}
#[test]
fn jsonrpc_error_response_adds_stable_error_code() {
    let payload = jsonrpc_error_response(None, JSONRPC_INVALID_PARAMS, "bad input", None);
    let code = payload
        .get("error")
        .and_then(|err| err.get("data"))
        .and_then(|data| data.get("code"))
        .and_then(Value::as_str)
        .expect("error envelope code");
    assert_eq!(code, "invalid_params");
}
#[test]
fn jsonrpc_error_response_preserves_legacy_data_fields() {
    let payload = jsonrpc_error_response(
        None,
        JSONRPC_INVALID_REQUEST,
        "too large",
        Some(norito::json!({
            "error_code": "payload_too_large",
            "max_request_bytes": 32
        })),
    );
    let data = payload
        .get("error")
        .and_then(|err| err.get("data"))
        .and_then(Value::as_object)
        .expect("error data");
    assert_eq!(
        data.get("code").and_then(Value::as_str),
        Some("payload_too_large")
    );
    assert_eq!(
        data.get("error_code").and_then(Value::as_str),
        Some("payload_too_large")
    );
    assert_eq!(
        data.get("max_request_bytes").and_then(Value::as_u64),
        Some(32)
    );
}
#[test]
fn read_only_policy_blocks_mutating_tools() {
    let cfg = iroha_config::parameters::actual::ToriiMcp {
        profile: ToriiMcpProfile::ReadOnly,
        ..Default::default()
    };
    let read_tool = sample_tool("iroha.accounts.get", Method::GET, ToolEffect::Read);
    let instruction_builder_tool = sample_tool(
        "iroha.musubi.instructions.release_yank_set",
        Method::POST,
        ToolEffect::BuildInstruction,
    );
    let write_tool = sample_tool("iroha.transactions.submit", Method::POST, ToolEffect::Write);
    let name_only_query_tool = sample_tool("iroha.fake.query", Method::POST, ToolEffect::Write);
    let explicit_query_tool = sample_tool_at(
        "iroha.queries.submit",
        Method::POST,
        iroha_torii_shared::route_catalog::pipeline::QUERY.path(),
        ToolEffect::Read,
    );
    assert!(is_tool_allowed_by_policy(&cfg, &read_tool));
    assert!(is_tool_allowed_by_policy(&cfg, &instruction_builder_tool));
    assert!(is_tool_allowed_by_policy(&cfg, &explicit_query_tool));
    assert!(!is_tool_allowed_by_policy(&cfg, &name_only_query_tool));
    assert!(!is_tool_allowed_by_policy(&cfg, &write_tool));
}
#[test]
fn openapi_tool_effects_drive_policy() {
    let cfg = iroha_config::parameters::actual::ToriiMcp {
        profile: ToriiMcpProfile::Operator,
        expose_operator_routes: true,
        ..Default::default()
    };
    let tools = build_tool_specs(&cfg);
    let mut read_only_cfg = cfg.clone();
    read_only_cfg.profile = ToriiMcpProfile::ReadOnly;
    let query = tools
        .iter()
        .find(|tool| {
            tool.route_backing()
                .is_some_and(|(_, method, path_template)| {
                    method == Method::POST
                        && path_template
                            == iroha_torii_shared::route_catalog::pipeline::QUERY.path()
                })
        })
        .expect("query tool");
    let (query_effect, _, _) = query.route_backing().expect("query tool is route-backed");
    assert_eq!(query_effect, ToolEffect::Read);
    assert!(is_tool_allowed_by_policy(&read_only_cfg, query));
    let protected_update = tools
        .iter()
        .find(|tool| {
            tool.route_backing()
                .is_some_and(|(_, method, path_template)| {
                    method == Method::POST && path_template == "/v1/gov/protected-namespaces"
                })
        })
        .expect("protected namespace update tool");
    let (protected_update_effect, _, _) = protected_update
        .route_backing()
        .expect("protected namespace update tool is route-backed");
    assert_eq!(protected_update_effect, ToolEffect::Operator);
    assert!(!is_tool_allowed_by_policy(&read_only_cfg, protected_update));
}
#[test]
fn get_tools_follow_exact_catalog_operator_authorization() {
    let cfg = iroha_config::parameters::actual::ToriiMcp {
        profile: ToriiMcpProfile::Operator,
        expose_operator_routes: true,
        ..Default::default()
    };
    let tools = build_tool_specs(&cfg);
    for tool in &tools {
        let Some((effect, method, path_template)) = tool.route_backing() else {
            continue;
        };
        if method != Method::GET {
            continue;
        }
        let catalog_requires_operator =
            catalog_descriptor_for_method_path(CATALOG_PROJECTION_GROUPS, method, path_template)
                .is_some_and(catalog_route_requires_operator);
        let expected = catalog_requires_operator || effect == ToolEffect::Operator;
        assert_eq!(tool_requires_operator(tool), expected, "{}", tool.name);
    }
    for route in CATALOG_PROJECTION_GROUPS
        .iter()
        .flat_map(|group| {
            RouteCatalog::new(group.routes).project(CatalogProjection::Mcp, group.enabled_features)
        })
        .filter(|route| {
            route.method() == CatalogHttpMethod::Get && catalog_route_requires_operator(route)
        })
    {
        assert!(
            tools.iter().any(|tool| {
                tool.route_backing()
                    .is_some_and(|(_, method, path_template)| {
                        method == Method::GET
                            && path_template == route.path()
                            && tool_requires_operator(tool)
                    })
            }),
            "compiled operator GET is missing an operator-only MCP tool: {}",
            route.path()
        );
    }
}
#[test]
fn mcp_policy_keeps_operator_tools_operator_only() {
    let protected_update = sample_tool_at(
        "iroha.gov.protected_namespaces.update",
        Method::POST,
        "/v1/gov/protected-namespaces",
        ToolEffect::Operator,
    );
    let mut cfg = iroha_config::parameters::actual::ToriiMcp {
        profile: ToriiMcpProfile::ReadOnly,
        ..Default::default()
    };
    assert!(!is_tool_allowed_by_policy(&cfg, &protected_update));
    cfg.profile = ToriiMcpProfile::Writer;
    assert!(!is_tool_allowed_by_policy(&cfg, &protected_update));
    cfg.profile = ToriiMcpProfile::Operator;
    assert!(!is_tool_allowed_by_policy(&cfg, &protected_update));
    cfg.expose_operator_routes = true;
    assert!(is_tool_allowed_by_policy(&cfg, &protected_update));
}
#[test]
fn signer_backed_prepare_and_submit_tools_are_mutating() {
    let mut cfg = iroha_config::parameters::actual::ToriiMcp {
        profile: ToriiMcpProfile::Operator,
        expose_operator_routes: true,
        ..Default::default()
    };
    let tools = build_tool_specs(&cfg);
    let effect = |name: &str| {
        let tool = tools
            .iter()
            .find(|tool| tool.name == name)
            .unwrap_or_else(|| panic!("missing tool {name}"));
        let Some((effect, _, _)) = tool.route_backing() else {
            panic!("tool {name} must be route-backed")
        };
        effect
    };
    assert_eq!(effect("iroha.accounts.onboard.prepare"), ToolEffect::Write);
    assert_eq!(effect("iroha.accounts.faucet.prepare"), ToolEffect::Write);
    assert_eq!(effect("iroha.accounts.faucet.submit"), ToolEffect::Write);

    cfg.profile = ToriiMcpProfile::ReadOnly;
    cfg.expose_operator_routes = false;
    let restricted = build_tool_specs(&cfg);
    for name in [
        "iroha.accounts.onboard.prepare",
        "iroha.accounts.faucet.prepare",
        "iroha.accounts.faucet.submit",
    ] {
        assert!(
            restricted.iter().all(|tool| {
                !is_tool_allowed_by_policy(&cfg, tool) || tool.name.as_str() != name
            })
        );
    }
}
#[test]
fn operator_sumeragi_snapshot_tools_are_absent_from_mcp() {
    let cfg = iroha_config::parameters::actual::ToriiMcp {
        profile: ToriiMcpProfile::Operator,
        expose_operator_routes: true,
        ..Default::default()
    };
    let tools = build_tool_specs(&cfg);
    for retired_name in [
        "iroha.sumeragi.commit_certificates",
        "iroha.sumeragi.validator_sets.list",
        "iroha.sumeragi.validator_sets.get",
        "iroha.sumeragi.params",
        "iroha.sumeragi.status",
        "iroha.sumeragi.leader",
        "iroha.sumeragi.qc",
        "iroha.sumeragi.checkpoints",
        "iroha.sumeragi.consensus_keys",
        "iroha.sumeragi.bls_keys",
        "iroha.sumeragi.telemetry",
        "iroha.sumeragi.commit_qc.get",
        "iroha.sumeragi.evidence.count",
        "iroha.sumeragi.evidence.list",
        "iroha.sumeragi.vrf.penalties",
        "iroha.sumeragi.vrf.epoch",
        "iroha.sumeragi.evidence.submit",
        "iroha.sumeragi.vrf.commit",
        "iroha.sumeragi.vrf.reveal",
    ] {
        assert!(
            tools.iter().all(|tool| tool.name != retired_name),
            "operator-only Sumeragi route remains exposed through public MCP: {retired_name}"
        );
    }
}
#[test]
fn canonical_account_and_pipeline_tools_use_first_class_routes() {
    let account_tool = iroha_accounts_get_tool();
    let (_, _, account_path) = account_tool
        .route_backing()
        .expect("account lookup tool is route-backed");
    assert_eq!(account_path, "/v1/accounts/{account_id}");
    let status_tool = iroha_transactions_status_tool();
    let (_, _, status_path) = status_tool
        .route_backing()
        .expect("transaction status tool is route-backed");
    assert_eq!(status_path, "/v1/pipeline/transactions/status");
    assert!(
        status_tool.description.contains("typed pipeline status"),
        "status tool description should advertise the typed contract"
    );
}
#[test]
fn transaction_wait_descriptors_are_closed_and_use_exact_canonical_hashes() {
    const HASH_PATTERN: &str = "^[0-9a-f]{63}[13579bdf]$";
    for tool in [
        iroha_contracts_call_and_wait_tool(),
        iroha_transactions_submit_and_wait_tool(),
        iroha_transactions_wait_tool(),
        iroha_transactions_status_tool(),
    ] {
        let schema = tool.input_schema.as_object().expect("input schema object");
        assert_eq!(
            schema.get("additionalProperties").and_then(Value::as_bool),
            Some(false),
            "{} must reject unknown root arguments",
            tool.name
        );
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("input properties");
        assert!(
            !properties.contains_key("terminal_statuses"),
            "{} must not expose configurable terminal outcomes",
            tool.name
        );
        let hash = if matches!(
            tool.name.as_str(),
            "iroha.transactions.wait" | "iroha.transactions.status"
        ) {
            properties
                .get("query")
                .and_then(|query| query.get("properties"))
                .and_then(|properties| properties.get("hash"))
        } else {
            properties.get("hash")
        }
        .and_then(Value::as_object)
        .expect("exact hash schema");
        assert_eq!(hash.get("minLength").and_then(Value::as_u64), Some(64));
        assert_eq!(hash.get("maxLength").and_then(Value::as_u64), Some(64));
        assert_eq!(
            hash.get("pattern").and_then(Value::as_str),
            Some(HASH_PATTERN)
        );
        if matches!(
            tool.name.as_str(),
            "iroha.contracts.call_and_wait"
                | "iroha.transactions.submit_and_wait"
                | "iroha.transactions.wait"
        ) {
            assert!(
                tool.description
                    .contains("decodes only exact HTTP 200 payloads"),
                "{} must document the only body-bearing status response",
                tool.name
            );
            assert!(
                tool.description.contains("only HTTP 404 as pending"),
                "{} must document the only pending status response",
                tool.name
            );
            assert!(
                tool.description.contains("rejects every other HTTP status"),
                "{} must document fail-closed status polling",
                tool.name
            );
        }
    }
}
#[test]
fn tool_descriptor_sanitizes_top_level_function_schema_keywords() {
    let tool = ToolSpec::route(
        "iroha.test.invalid_schema".to_owned(),
        "sample".to_owned(),
        ToolEffect::Write,
        Method::POST,
        "/v1/test".to_owned(),
        norito::json!({
            "oneOf": [{ "type": "string" }, { "type": "null" }],
            "enum": ["bad"],
            "not": { "type": "null" }
        }),
    );
    let descriptor = tool.descriptor();
    let schema = descriptor
        .get("inputSchema")
        .and_then(Value::as_object)
        .expect("sanitized input schema object");
    assert_eq!(schema.get("type").and_then(Value::as_str), Some("object"));
    assert!(
        !schema.contains_key("anyOf")
            && !schema.contains_key("oneOf")
            && !schema.contains_key("allOf")
            && !schema.contains_key("enum")
            && !schema.contains_key("not"),
        "descriptor should strip OpenAI-incompatible top-level schema keywords"
    );
    assert!(
        schema.get("properties").is_some_and(Value::is_object),
        "descriptor should always emit an object properties map"
    );
}
#[test]
fn apply_body_projection_keeps_requested_fields() {
    let structured = norito::json!({
        "status": 200,
        "body": {
            "id": 1,
            "name": "alice",
            "extra": true
        }
    });
    let projection = norito::json!(["id", "name"]);
    let projected = apply_body_projection(structured, Some(&projection));
    let body = projected
        .get("body")
        .and_then(Value::as_object)
        .expect("projected body object");
    assert!(body.contains_key("id"));
    assert!(body.contains_key("name"));
    assert!(!body.contains_key("extra"));
}
#[test]
fn generated_projection_schema_bounds_selector_work() {
    let schema = build_input_schema(&norito::json!({}), "/v1/test", &[], None);
    let project_schema = schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("project"))
        .expect("generated project schema");
    assert_eq!(
        project_schema.get("maxItems").and_then(Value::as_u64),
        Some(MAX_MCP_PROJECTION_KEYS as u64)
    );
    assert_eq!(
        project_schema.get("uniqueItems").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        project_schema
            .get("items")
            .and_then(|items| items.get("maxLength"))
            .and_then(Value::as_u64),
        Some(MAX_MCP_PROJECTION_KEY_CHARS as u64)
    );

    let mut tool = sample_tool("iroha.projection-test", Method::GET, ToolEffect::Read);
    tool.input_schema = schema;
    let validate_projection = |projection| {
        let mut arguments = Map::new();
        arguments.insert("project".to_owned(), projection);
        validate_tool_arguments(&tool, &arguments)
    };
    assert!(validate_projection(norito::json!(["id", "name"])).is_ok());
    assert!(validate_projection(norito::json!(["id", "id"])).is_err());
    let too_many = Value::Array(
        (0..=MAX_MCP_PROJECTION_KEYS)
            .map(|index| Value::String(format!("field_{index}")))
            .collect(),
    );
    assert!(validate_projection(too_many).is_err());
    let too_long = Value::Array(vec![Value::String(
        "x".repeat(MAX_MCP_PROJECTION_KEY_CHARS + 1),
    )]);
    assert!(validate_projection(too_long).is_err());
}
#[path = "catalog_and_policy_tests/registry_security.rs"]
mod registry_security;

#[test]
fn manual_descriptor_embedded_asset_preserves_all_fields_at_exact_byte_limit() {
    assert!(MANUAL_STATIC_TOOL_ASSET.len() <= MANUAL_STATIC_TOOL_ASSET_MAX_BYTES);
    let embedded = parse_manual_static_tool_descriptors(MANUAL_STATIC_TOOL_ASSET);
    assert_eq!(embedded.len(), MANUAL_STATIC_TOOL_ASSET_DESCRIPTOR_COUNT);
    let mut padded = MANUAL_STATIC_TOOL_ASSET.to_vec();
    padded.resize(MANUAL_STATIC_TOOL_ASSET_MAX_BYTES, b' ');
    assert_eq!(padded.len(), MANUAL_STATIC_TOOL_ASSET_MAX_BYTES);
    let boundary = parse_manual_static_tool_descriptors(&padded);
    assert_eq!(boundary.len(), embedded.len());
    for (function, original) in &embedded {
        assert!(!original.name.is_empty());
        assert!(original.input_schema.is_object());
        let actual = boundary.get(function).expect("same descriptor function");
        assert_eq!(actual.name, original.name);
        assert_eq!(actual.effect, original.effect);
        assert_eq!(actual.description, original.description);
        assert_eq!(actual.method, original.method);
        assert_eq!(actual.path_template, original.path_template);
        assert_eq!(actual.input_schema, original.input_schema);
    }
}

#[test]
fn manual_descriptor_loader_accepts_content_updates_and_preserves_policy() {
    let Value::Object(mut root) =
        json::from_slice::<Value>(MANUAL_STATIC_TOOL_ASSET).expect("embedded descriptor JSON")
    else {
        panic!("descriptor root")
    };
    let Value::Array(mut descriptors) = root.remove("descriptors").expect("descriptors") else {
        panic!("descriptor array")
    };
    let Value::Object(record) = &mut descriptors[0] else {
        panic!("descriptor record")
    };
    let function = record
        .get("function")
        .and_then(Value::as_str)
        .expect("function")
        .to_owned();
    record.insert(
        "description".into(),
        Value::from("Updated public tool documentation."),
    );
    root.insert("descriptors".into(), Value::Array(descriptors));
    let updated = json::to_vec(&Value::Object(root.clone())).expect("updated descriptor JSON");
    assert_ne!(updated.len(), MANUAL_STATIC_TOOL_ASSET.len());
    let loaded = parse_manual_static_tool_descriptors(&updated);
    assert_eq!(loaded.len(), MANUAL_STATIC_TOOL_ASSET_DESCRIPTOR_COUNT);
    assert_eq!(
        loaded[&function].description,
        "Updated public tool documentation."
    );

    root.insert("schema_version".into(), Value::from(2_u64));
    let unsupported = json::to_vec(&Value::Object(root)).expect("unsupported descriptor JSON");
    assert!(
        std::panic::catch_unwind(|| parse_manual_static_tool_descriptors(&unsupported)).is_err()
    );
    let oversized = vec![b' '; MANUAL_STATIC_TOOL_ASSET_MAX_BYTES + 1];
    let mut valid_json_oversized = MANUAL_STATIC_TOOL_ASSET.to_vec();
    valid_json_oversized.resize(MANUAL_STATIC_TOOL_ASSET_MAX_BYTES + 1, b' ');
    assert!(json::from_slice::<Value>(&valid_json_oversized).is_ok());
    for oversized in [oversized, valid_json_oversized] {
        assert!(
            std::panic::catch_unwind(|| parse_manual_static_tool_descriptors(&oversized)).is_err()
        );
    }
}

#[test]
fn faucet_policy_tool_is_read_only_and_runtime_gated() {
    let cfg = iroha_config::parameters::actual::ToriiMcp {
        profile: ToriiMcpProfile::ReadOnly,
        ..Default::default()
    };
    let tools = build_tool_specs(&cfg);
    let policy = tools
        .iter()
        .find(|tool| tool.name == "iroha.accounts.faucet.policy")
        .expect("compiled faucet policy discovery tool");
    let (effect, method, path) = policy.route_backing().expect("route-backed policy");
    assert_eq!(effect, ToolEffect::Read);
    assert_eq!(method, &Method::GET);
    assert_eq!(path, "/v1/accounts/faucet/policy");
    assert!(is_tool_allowed_by_policy(&cfg, policy));
    assert!(validate_tool_arguments(policy, &Map::new()).is_ok());
    for field in ["authority", "private_key", "amount", "body", "url"] {
        let mut arguments = Map::new();
        arguments.insert(field.to_owned(), Value::String("untrusted".to_owned()));
        assert!(
            validate_tool_arguments(policy, &arguments).is_err(),
            "{field}"
        );
    }
    let mut app = mk_app_state_for_tests();
    assert!(!tool_is_runtime_available(&app, policy));
    std::sync::Arc::get_mut(&mut app)
        .expect("unique app state")
        .account_faucet = Some(test_faucet_runtime_config());
    assert!(tool_is_runtime_available(&app, policy));
}

#[tokio::test]
async fn faucet_policy_tool_dispatches_only_get_without_body() {
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let route_seen = std::sync::Arc::clone(&seen);
    let router =
        axum::Router::new().fallback_service(tower::service_fn(move |request: Request<Body>| {
            let seen = std::sync::Arc::clone(&route_seen);
            async move {
                assert_eq!(request.method(), Method::GET);
                assert_eq!(request.uri().path(), "/v1/accounts/faucet/policy");
                assert!(request.uri().query().is_none());
                let bytes = axum::body::to_bytes(request.into_body(), 1)
                    .await
                    .expect("empty discovery request");
                assert!(bytes.is_empty());
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(Body::empty())
                        .expect("response"),
                )
            }
        }));
    let app = mk_app_state_for_tests();
    let _owner = app.mcp_dispatch_router.install(router);
    dispatch_iroha_accounts_faucet_policy(&app, &HeaderMap::new(), &Map::new())
        .await
        .expect("read-only policy dispatch");
    assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 1);
}
