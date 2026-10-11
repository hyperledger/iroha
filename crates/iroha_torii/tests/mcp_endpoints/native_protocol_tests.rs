#[tokio::test]
async fn mcp_native_2026_discovery_list_and_call_are_self_describing() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    let app = build_router(cfg);

    let (status, discover) = post_mcp_with_exact_headers(
        &app,
        modern_request("discover", "server/discover", norito::json!({})),
        &[
            ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "server/discover"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_modern_success_metadata(&discover, true);
    assert_eq!(
        discover
            .get("result")
            .and_then(|result| result.get("supportedVersions")),
        Some(&norito::json!([MODERN_MCP_PROTOCOL_VERSION]))
    );
    assert_eq!(
        discover
            .get("result")
            .and_then(|result| result.get("capabilities"))
            .and_then(|capabilities| capabilities.get("resources")),
        Some(&norito::json!({ "listChanged": false }))
    );

    let (status, list) = post_mcp_with_exact_headers(
        &app,
        modern_request("list", "tools/list", norito::json!({})),
        &[
            ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "tools/list"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_modern_success_metadata(&list, true);
    let tools = list
        .get("result")
        .and_then(|result| result.get("tools"))
        .and_then(Value::as_array)
        .filter(|tools| !tools.is_empty())
        .expect("tools/list must publish at least one tool");
    for (name, operation, requires_external_signature) in [
        ("iroha.transactions.prepare", "construct", true),
        ("iroha.transactions.inspect", "observe", false),
    ] {
        let tool = tools
            .iter()
            .find(|tool| tool.get("name").and_then(Value::as_str) == Some(name))
            .unwrap_or_else(|| panic!("missing in-process transaction tool {name}"));
        assert_eq!(
            tool.pointer("/annotations/readOnlyHint"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            tool.pointer("/annotations/destructiveHint"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            tool.pointer("/annotations/idempotentHint"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            tool.pointer("/annotations/openWorldHint"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            tool.pointer("/_meta/iroha~1semantics/operation")
                .and_then(Value::as_str),
            Some(operation)
        );
        assert_eq!(
            tool.pointer("/_meta/iroha~1semantics/requiresExternalSignature"),
            Some(&Value::Bool(requires_external_signature))
        );
        assert!(
            tool.pointer("/_meta/iroha~1routeAuth").is_none(),
            "pure in-process tools must not pretend to target a Torii route"
        );
    }

    let (status, call) = post_mcp_with_exact_headers(
        &app,
        modern_request(
            "call",
            "tools/call",
            norito::json!({
                "name": "iroha.health",
                "arguments": {}
            }),
        ),
        &[
            ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "iroha.health"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!tool_is_error(&call), "iroha.health must dispatch");
    assert_modern_success_metadata(&call, false);
    app.shutdown().await;
}

#[tokio::test]
async fn mcp_native_2026_batch_requires_request_scoped_extension_negotiation() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    let app = build_router(cfg);
    let mut request = modern_request(
        "batch-negotiation",
        "tools/call_batch",
        norito::json!({
            "calls": [{ "name": "iroha.health", "arguments": {} }]
        }),
    );

    let (status, body) = post_mcp_with_exact_headers(
        &app,
        request.clone(),
        &[
            ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "tools/call_batch"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_jsonrpc_error_code(&body, -32021);
    assert_eq!(
        body.pointer("/error/data/requiredCapabilities/extensions/org.hyperledger.iroha~1tools",),
        Some(&norito::json!({}))
    );

    request
        .pointer_mut("/params/_meta/io.modelcontextprotocol~1clientCapabilities")
        .expect("client capabilities")
        .clone_from(&norito::json!({
            "extensions": { "org.hyperledger.iroha/tools": {} }
        }));
    let (status, body) = post_mcp_with_exact_headers(
        &app,
        request,
        &[
            ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "tools/call_batch"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_modern_success_metadata(&body, false);
    let results = body
        .pointer("/result/results")
        .and_then(Value::as_array)
        .expect("batch results");
    assert_eq!(results.len(), 1);
    assert!(results[0].get("result").is_some());
    app.shutdown().await;
}

#[tokio::test]
async fn mcp_native_2026_rejects_client_response_objects() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    let app = build_router(cfg);
    let (status, body) = post_mcp_with_exact_headers(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": "not-a-native-request",
            "result": {}
        }),
        &[
            ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "tools/list"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_jsonrpc_error_code(&body, -32600);
    app.shutdown().await;
}

#[tokio::test]
async fn mcp_legacy_response_objects_require_an_explicit_legacy_header() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    let app = build_router(cfg);
    let (status, body) = post_mcp_with_exact_headers(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": "unversioned-response",
            "result": {}
        }),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_jsonrpc_error_code(&body, -32600);
    app.shutdown().await;
}

#[tokio::test]
async fn mcp_native_2026_resources_list_is_exact_complete_and_private() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    let app = build_router(cfg);

    let (status, body) = post_mcp_with_exact_headers(
        &app,
        modern_request("resources-list", "resources/list", norito::json!({})),
        &[
            ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "resources/list"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_modern_success_metadata(&body, true);

    let resources = body
        .get("result")
        .and_then(|result| result.get("resources"))
        .and_then(Value::as_array)
        .expect("resources/list result array");
    let mut expected = vec![
        norito::json!({
            "uri": "iroha://node/health",
            "name": "iroha-node-health",
            "title": "Iroha node health",
            "description": "Torii liveness reported by the canonical health route.",
            "mimeType": "application/json"
        }),
        norito::json!({
            "uri": "iroha://node/api-version",
            "name": "iroha-node-api-version",
            "title": "Iroha node API version",
            "description": "Torii API and build version information.",
            "mimeType": "application/json"
        }),
        norito::json!({
            "uri": "iroha://chain/head",
            "name": "iroha-chain-head",
            "title": "Iroha chain head",
            "description": "The newest canonical ledger header visible to Torii.",
            "mimeType": "application/json"
        }),
    ];
    #[cfg(feature = "app_api")]
    expected.push(norito::json!({
        "uri": "iroha://chain/parameters",
        "name": "iroha-chain-parameters",
        "title": "Iroha chain parameters",
        "description": "The effective on-chain application parameters.",
        "mimeType": "application/json"
    }));
    expected.push(norito::json!({
        "uri": "iroha://runtime/abi/hash",
        "name": "iroha-runtime-abi-hash",
        "title": "Iroha runtime ABI hash",
        "description": "The hash of the runtime ABI accepted by this node.",
        "mimeType": "application/json"
    }));
    assert_eq!(resources, &expected);
    assert!(
        body.get("result")
            .is_some_and(|result| result.get("nextCursor").is_none()),
        "the fixed complete resource catalogue must not issue a cursor"
    );
    app.shutdown().await;
}

#[tokio::test]
async fn mcp_native_2026_resources_read_routes_through_torii() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    let app = build_router(cfg);
    let uri = "iroha://node/health";
    let mirrored_uri = iroha_torii_shared::mcp::encode_mirrored_header_value(uri);

    let (status, body) = post_mcp_with_exact_headers(
        &app,
        modern_request(
            "resource-read",
            "resources/read",
            norito::json!({ "uri": uri }),
        ),
        &[
            ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "resources/read"),
            ("Mcp-Name", mirrored_uri.as_str()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let result = body
        .get("result")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("expected resources/read result object, got {body:?}"));
    assert_eq!(
        result.get("resultType").and_then(Value::as_str),
        Some("complete")
    );
    assert_eq!(result.get("ttlMs").and_then(Value::as_u64), Some(0));
    assert_eq!(
        result.get("cacheScope").and_then(Value::as_str),
        Some("private")
    );
    assert!(
        result
            .get("_meta")
            .and_then(|meta| meta.get("io.modelcontextprotocol/serverInfo"))
            .is_some(),
        "modern resource results must identify the Torii MCP implementation"
    );
    let contents = result
        .get("contents")
        .and_then(Value::as_array)
        .expect("resource contents array");
    assert_eq!(contents.len(), 1);
    let content = contents[0].as_object().expect("resource content object");
    assert_eq!(content.get("uri").and_then(Value::as_str), Some(uri));
    assert_eq!(
        content.get("mimeType").and_then(Value::as_str),
        Some("application/json")
    );
    let text = content
        .get("text")
        .and_then(Value::as_str)
        .expect("JSON resource text");
    assert_eq!(
        norito::json::from_str::<Value>(text).expect("valid JSON resource text"),
        Value::String("Healthy".to_owned())
    );
    app.shutdown().await;
}

#[tokio::test]
async fn mcp_native_2026_resources_reject_unknown_uris_and_unissued_cursors() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    let app = build_router(cfg);
    let unknown_uri = "iroha://unknown/resource";
    let mirrored_uri = iroha_torii_shared::mcp::encode_mirrored_header_value(unknown_uri);

    let (status, body) = post_mcp_with_exact_headers(
        &app,
        modern_request(
            "resource-unknown",
            "resources/read",
            norito::json!({ "uri": unknown_uri }),
        ),
        &[
            ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "resources/read"),
            ("Mcp-Name", mirrored_uri.as_str()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_jsonrpc_error_code(&body, -32602);

    let (status, body) = post_mcp_with_exact_headers(
        &app,
        modern_request(
            "resource-cursor",
            "resources/list",
            norito::json!({ "cursor": "not-issued-by-torii" }),
        ),
        &[
            ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "resources/list"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_jsonrpc_error_code(&body, -32602);
    app.shutdown().await;
}

#[tokio::test]
async fn mcp_native_2026_rejects_invalid_routing_headers() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    let app = build_router(cfg);
    let list_request = modern_request("routing", "tools/list", norito::json!({}));

    for (label, headers) in [
        (
            "missing protocol version",
            vec![("Mcp-Method", "tools/list")],
        ),
        (
            "mismatched protocol version",
            vec![
                ("MCP-Protocol-Version", "2025-06-18"),
                ("Mcp-Method", "tools/list"),
            ],
        ),
        (
            "duplicate protocol version",
            vec![
                ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
                ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
                ("Mcp-Method", "tools/list"),
            ],
        ),
        (
            "missing method",
            vec![("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION)],
        ),
        (
            "mismatched method",
            vec![
                ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
                ("Mcp-Method", "tools/call"),
            ],
        ),
        (
            "duplicate method",
            vec![
                ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
                ("Mcp-Method", "tools/list"),
                ("Mcp-Method", "tools/list"),
            ],
        ),
    ] {
        let (status, body) =
            post_mcp_with_exact_headers(&app, list_request.clone(), &headers).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}");
        assert_jsonrpc_error_code(&body, -32020);
    }

    let call_request = modern_request(
        "routing-name",
        "tools/call",
        norito::json!({
            "name": "iroha.health",
            "arguments": {}
        }),
    );
    for (label, headers) in [
        (
            "missing name",
            vec![
                ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
                ("Mcp-Method", "tools/call"),
            ],
        ),
        (
            "mismatched name",
            vec![
                ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
                ("Mcp-Method", "tools/call"),
                ("Mcp-Name", "iroha.parameters.get"),
            ],
        ),
        (
            "duplicate name",
            vec![
                ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
                ("Mcp-Method", "tools/call"),
                ("Mcp-Name", "iroha.health"),
                ("Mcp-Name", "iroha.health"),
            ],
        ),
    ] {
        let (status, body) =
            post_mcp_with_exact_headers(&app, call_request.clone(), &headers).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}");
        assert_jsonrpc_error_code(&body, -32020);
    }
    app.shutdown().await;
}

#[tokio::test]
async fn mcp_native_2026_rejects_invalid_metadata_versions_and_methods() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    let app = build_router(cfg);

    for (label, payload) in [
        (
            "missing _meta",
            norito::json!({
                "jsonrpc": "2.0",
                "id": "missing-meta",
                "method": "tools/list",
                "params": {}
            }),
        ),
        (
            "missing client capabilities",
            norito::json!({
                "jsonrpc": "2.0",
                "id": "missing-capabilities",
                "method": "tools/list",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": MODERN_MCP_PROTOCOL_VERSION
                    }
                }
            }),
        ),
    ] {
        let (status, body) = post_mcp_with_exact_headers(
            &app,
            payload,
            &[
                ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
                ("Mcp-Method", "tools/list"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}");
        assert_jsonrpc_error_code(&body, -32602);
    }

    const UNSUPPORTED_VERSION: &str = "2099-01-01";
    let (status, body) = post_mcp_with_exact_headers(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": "unsupported",
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": UNSUPPORTED_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        }),
        &[
            ("MCP-Protocol-Version", UNSUPPORTED_VERSION),
            ("Mcp-Method", "tools/list"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_jsonrpc_error_code(&body, -32022);
    assert_eq!(
        body.get("error")
            .and_then(|error| error.get("data"))
            .and_then(|data| data.get("supported")),
        Some(&norito::json!([MODERN_MCP_PROTOCOL_VERSION]))
    );

    for method in ["initialize", "ping", "experimental/unknown"] {
        let (status, body) = post_mcp_with_exact_headers(
            &app,
            modern_request("unsupported-method", method, norito::json!({})),
            &[
                ("MCP-Protocol-Version", MODERN_MCP_PROTOCOL_VERSION),
                ("Mcp-Method", method),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method}");
        assert_jsonrpc_error_code(&body, -32601);
    }
    app.shutdown().await;
}

#[tokio::test]
async fn mcp_retired_2025_initialize_and_tool_call_are_rejected() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    let app = build_router(cfg);

    let (status, initialize) = post_mcp_with_exact_headers(
        &app,
        initialize_request(1),
        &[("MCP-Protocol-Version", "2025-06-18")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_jsonrpc_error_code(&initialize, -32602);

    let (status, call) = post_mcp_with_exact_headers(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": "legacy-call",
            "method": "tools/call",
            "params": {
                "name": "iroha.health",
                "arguments": {}
            }
        }),
        &[("MCP-Protocol-Version", "2025-06-18")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_jsonrpc_error_code(&call, -32602);
    app.shutdown().await;
}
