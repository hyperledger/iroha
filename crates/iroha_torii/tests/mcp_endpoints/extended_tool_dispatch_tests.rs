#[tokio::test]
async fn mcp_jsonrpc_tools_call_agent_alias_subscriptions_plans_list_accepts_flat_query_fields() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    let app = build_router(cfg);
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 1062231,
            "method": "tools/call",
            "params": {
                "name": "iroha.subscriptions.plans.list",
                "arguments": {
                    "limit": 1
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let structured = structured_content(&call);
    assert!(
        structured.get("status").and_then(Value::as_u64).is_some(),
        "subscriptions plans list alias should dispatch and return a status code"
    );
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_agent_alias_subscriptions_plans_create_accepts_body() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    enable_writer_mcp(&mut cfg);
    let authority_key_pair = cfg.common.key_pair.clone();
    let app = build_router(cfg);
    let arguments = authenticated_mcp_target_arguments(
        &app,
        &authority_key_pair,
        "POST",
        "/v1/subscriptions/plans",
        norito::json!({ "body": {} }),
        McpTargetAuthentication::CanonicalAccount,
    );
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 10622315,
            "method": "tools/call",
            "params": {
                "name": "iroha.subscriptions.plans.create",
                "arguments": arguments
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let structured = structured_content(&call);
    assert_mcp_target_authentication_not_rejected(structured, "iroha.subscriptions.plans.create");
    assert!(
        structured.get("status").and_then(Value::as_u64).is_some(),
        "subscriptions plans create alias should dispatch and return a status code"
    );
    app.shutdown().await;
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_agent_alias_subscriptions_list_accepts_flat_query_fields() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    let app = build_router(cfg);
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 1062232,
            "method": "tools/call",
            "params": {
                "name": "iroha.subscriptions.list",
                "arguments": {
                    "limit": 1
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let structured = structured_content(&call);
    assert!(
        structured.get("status").and_then(Value::as_u64).is_some(),
        "subscriptions list alias should dispatch and return a status code"
    );
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_agent_alias_subscriptions_create_accepts_body() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    enable_writer_mcp(&mut cfg);
    let authority_key_pair = cfg.common.key_pair.clone();
    let app = build_router(cfg);
    let arguments = authenticated_mcp_target_arguments(
        &app,
        &authority_key_pair,
        "POST",
        "/v1/subscriptions",
        norito::json!({ "body": {} }),
        McpTargetAuthentication::CanonicalAccount,
    );
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 10622325,
            "method": "tools/call",
            "params": {
                "name": "iroha.subscriptions.create",
                "arguments": arguments
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let structured = structured_content(&call);
    assert_mcp_target_authentication_not_rejected(structured, "iroha.subscriptions.create");
    assert!(
        structured.get("status").and_then(Value::as_u64).is_some(),
        "subscriptions create alias should dispatch and return a status code"
    );
    app.shutdown().await;
}
mcp_alias_dispatch_test! {
    #[tokio::test]
    async fn mcp_jsonrpc_tools_call_agent_alias_subscriptions_get_accepts_canonical_path => error(
        1062233,
        "iroha.subscriptions.get",
        InvalidSubscriptionId,
        "invalid subscription id should be marked as MCP tool error for subscription detail alias",
        "expected invalid subscription id to be rejected by subscription detail alias",
    )
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_agent_alias_subscriptions_cancel_accepts_exact_subscription_id() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    enable_writer_mcp(&mut cfg);
    let app = build_router(cfg);
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 10622335,
            "method": "tools/call",
            "params": {
                "name": "iroha.subscriptions.cancel",
                "arguments": {
                    "subscription_id": "not-a-subscription-id",
                    "body": {}
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_tool_schema_error(
        &call,
        "invalid subscription id must be rejected before subscription cancel dispatch",
    );
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_subscription_draft_actions_use_exact_id() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    enable_writer_mcp(&mut cfg);
    let app = build_router(cfg);
    for (id, tool_name) in [
        (10622341, "iroha.subscriptions.pause"),
        (10622342, "iroha.subscriptions.resume"),
        (10622343, "iroha.subscriptions.keep"),
        (10622345, "iroha.subscriptions.charge_now"),
    ] {
        let (status, call) = post_mcp(
            &app,
            norito::json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": {
                        "subscription_id": "not-a-subscription-id",
                        "body": {}
                    }
                }
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_tool_schema_error(
            &call,
            &format!("invalid subscription id must be rejected before `{tool_name}` dispatch"),
        );
    }
}
mcp_alias_dispatch_test! {
    #[tokio::test]
    async fn mcp_jsonrpc_tools_call_agent_alias_subscription_usage_accepts_canonical_path => schema_error(
        10622344,
        "iroha.subscriptions.usage",
        InvalidSubscriptionId,
        "invalid canonical subscription path must fail advertised-schema validation",
    )
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_agent_alias_asset_definitions_accepts_flat_query_fields() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    let app = build_router(cfg);
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 106224,
            "method": "tools/call",
            "params": {
                "name": "iroha.assets.definitions",
                "arguments": {
                    "filter": "unknown_field = 1"
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        tool_is_error(&call),
        "a filter on a field asset definitions do not expose should be marked as MCP tool error: {call:?}"
    );
    let structured = structured_content(&call);
    assert!(
        structured
            .get("status")
            .and_then(Value::as_u64)
            .is_some_and(|status| status >= 400),
        "expected Torii to reject the unknown asset-definition field: {call:?}"
    );
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 1062242,
            "method": "tools/call",
            "params": {
                "name": "iroha.assets.definitions",
                "arguments": {
                    "sort": "name,id",
                    "select": "id,name",
                    "limit": 2
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !tool_is_error(&call),
        "a valid asset-definition collection query should dispatch successfully: {call:?}"
    );
    assert_eq!(
        structured_content(&call)
            .get("status")
            .and_then(Value::as_u64),
        Some(200)
    );
}
mcp_alias_dispatch_test! {
    #[tokio::test]
    async fn mcp_jsonrpc_tools_call_agent_alias_asset_definitions_get_accepts_canonical_path => error(
        1062241,
        "iroha.assets.definitions.get",
        InvalidDefinitionId,
        "invalid definition id should be marked as MCP tool error for definition detail alias",
        "expected invalid definition id to be rejected by explorer definition detail alias",
    )
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_agent_alias_asset_definitions_query_accepts_flat_envelope_fields() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    let app = build_router(cfg);
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 106225,
            "method": "tools/call",
            "params": {
                "name": "iroha.assets.definitions.query",
                "arguments": {
                    "limit": 2
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !tool_is_error(&call),
        "asset definitions query alias with flat envelope fields should dispatch successfully"
    );
    let structured = structured_content(&call);
    assert_eq!(structured.get("status").and_then(Value::as_u64), Some(200));
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_agent_alias_asset_holders_accepts_canonical_path() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    let app = build_router(cfg);
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 106226,
            "method": "tools/call",
            "params": {
                "name": "iroha.assets.holders",
                "arguments": {
                    "path": {
                        "definition_id": "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
                    },
                    "filter": "unknown_field = 1"
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        tool_is_error(&call),
        "a filter on a field asset holders do not expose should be marked as MCP tool error: {call:?}"
    );
    let structured = structured_content(&call);
    assert!(
        structured
            .get("status")
            .and_then(Value::as_u64)
            .is_some_and(|status| status >= 400),
        "expected Torii to reject the unknown asset-holder field: {call:?}"
    );
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 1062261,
            "method": "tools/call",
            "params": {
                "name": "iroha.assets.holders",
                "arguments": {
                    "path": {
                        "definition_id": "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
                    },
                    "pagination": { "limit": 2, "offset": 0 }
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_tool_schema_error(
        &call,
        "offset pagination is retired; collections page with `limit` and `cursor`",
    );
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_agent_alias_asset_holders_query_accepts_canonical_path() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    let app = build_router(cfg);
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 106227,
            "method": "tools/call",
            "params": {
                "name": "iroha.assets.holders.query",
                "arguments": {
                    "path": {
                        "definition_id": "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
                    },
                    "limit": 2
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let structured = structured_content(&call);
    let http_status = structured.get("status").and_then(Value::as_u64);
    assert!(
        http_status.is_some(),
        "asset holders query alias should return an HTTP status"
    );
    if tool_is_error(&call) {
        assert!(
            http_status.is_some_and(|status| status >= 400),
            "asset holders query alias should surface downstream lookup failures: {call:?}"
        );
    } else {
        assert_eq!(
            http_status,
            Some(200),
            "asset holders query alias should return HTTP 200 when holders lookup succeeds"
        );
    }
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_agent_aliases_resolve_dispatches_body() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    enable_writer_mcp(&mut cfg);
    let app = build_router(cfg);
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 10631,
            "method": "tools/call",
            "params": {
                "name": "iroha.aliases.resolve",
                "arguments": {
                    "body": { "alias": "missing-alias" }
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let structured = structured_content(&call);
    let http_status = structured.get("status").and_then(Value::as_u64);
    assert!(
        http_status.is_some(),
        "alias resolve alias should return an HTTP status"
    );
    if tool_is_error(&call) {
        assert!(
            http_status.is_some_and(|status| status >= 400),
            "alias resolve alias should surface non-2xx errors when alias is missing/unavailable"
        );
    } else {
        assert_eq!(
            http_status,
            Some(200),
            "alias resolve alias should return HTTP 200 when alias lookup succeeds"
        );
    }
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_agent_aliases_resolve_index_dispatches_body() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    enable_writer_mcp(&mut cfg);
    let authority_key_pair = cfg.common.key_pair.clone();
    let app = build_router(cfg);
    let arguments = authenticated_mcp_target_arguments(
        &app,
        &authority_key_pair,
        "POST",
        "/v1/aliases/resolve-index",
        norito::json!({ "body": { "index": 0 } }),
        McpTargetAuthentication::CanonicalAccount,
    );
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 10632,
            "method": "tools/call",
            "params": {
                "name": "iroha.aliases.resolve_index",
                "arguments": arguments
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let structured = structured_content(&call);
    assert_mcp_target_authentication_not_rejected(structured, "iroha.aliases.resolve_index");
    let http_status = structured.get("status").and_then(Value::as_u64);
    assert!(
        http_status.is_some(),
        "alias resolve-index alias should return an HTTP status"
    );
    if tool_is_error(&call) {
        assert!(
            http_status.is_some_and(|status| status >= 400),
            "alias resolve-index alias should surface non-2xx errors when index is missing/unavailable"
        );
    } else {
        assert_eq!(
            http_status,
            Some(200),
            "alias resolve-index alias should return HTTP 200 when alias index lookup succeeds"
        );
    }
    app.shutdown().await;
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_canonical_transaction_submit_dispatches_binary_payload() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    cfg.torii.mcp.profile = iroha_config::parameters::actual::ToriiMcpProfile::Operator;
    let app = build_router(cfg);
    let tool_name = "iroha.transactions.submit";
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 112,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": {
                    "body_base64": "AQIDBA"
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        tool_is_error(&call),
        "invalid signed transaction bytes should be marked as MCP tool error for `{tool_name}`"
    );
    let structured = structured_content(&call);
    assert!(
        structured
            .get("status")
            .and_then(Value::as_u64)
            .is_some_and(|status| status >= 400),
        "expected invalid Norito transaction bytes to be rejected for `{tool_name}`"
    );
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_canonical_transaction_submit_rejects_unknown_payload_field() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    cfg.torii.mcp.profile = iroha_config::parameters::actual::ToriiMcpProfile::Operator;
    let app = build_router(cfg);
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 1131,
            "method": "tools/call",
            "params": {
                "name": "iroha.transactions.submit",
                "arguments": {
                    "wire_hex": "01020304"
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let message = assert_tool_schema_error(
        &call,
        "unknown signed transaction payload field must fail advertised-schema validation",
    );
    assert!(message.contains("body_base64"));
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_agent_alias_query_submit_dispatches_binary_payload() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    cfg.torii.mcp.profile = iroha_config::parameters::actual::ToriiMcpProfile::Operator;
    let app = build_router(cfg);
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 1133,
            "method": "tools/call",
            "params": {
                "name": "iroha.queries.submit",
                "arguments": {
                    "body_base64": "AQIDBA=="
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_tool_error(
        &call,
        "invalid signed query bytes should be marked as MCP tool error",
    );
    let structured = structured_content(&call);
    assert!(
        structured
            .get("status")
            .and_then(Value::as_u64)
            .is_some_and(|status| status >= 400),
        "expected invalid Norito query bytes to be rejected"
    );
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_agent_alias_query_submit_rejects_unknown_payload_field() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    cfg.torii.mcp.profile = iroha_config::parameters::actual::ToriiMcpProfile::Operator;
    let app = build_router(cfg);
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 1134,
            "method": "tools/call",
            "params": {
                "name": "iroha.queries.submit",
                "arguments": {
                    "wire_hex": "01020304"
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let message = assert_tool_schema_error(
        &call,
        "unknown signed query payload field must fail advertised-schema validation",
    );
    assert!(message.contains("body_base64"));
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_iso20022_pacs008_rejects_retired_message_xml() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    cfg.torii.mcp.profile = iroha_config::parameters::actual::ToriiMcpProfile::Operator;
    cfg.torii.mcp.expose_operator_routes = true;
    let app = build_router(cfg);
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 1135,
            "method": "tools/call",
            "params": {
                "name": "iroha.iso20022.pacs008.submit",
                "arguments": {
                    "message_xml": "<Document/>"
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_tool_schema_error(&call, "retired message_xml must fail closed");
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_iso20022_pacs009_rejects_retired_xml() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    cfg.torii.mcp.profile = iroha_config::parameters::actual::ToriiMcpProfile::Operator;
    cfg.torii.mcp.expose_operator_routes = true;
    let app = build_router(cfg);
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 1136,
            "method": "tools/call",
            "params": {
                "name": "iroha.iso20022.pacs009.submit",
                "arguments": {
                    "xml": "<Document/>"
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_tool_schema_error(&call, "retired xml must fail closed");
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_iso20022_status_rejects_retired_message_id() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    cfg.torii.mcp.profile = iroha_config::parameters::actual::ToriiMcpProfile::Operator;
    cfg.torii.mcp.expose_operator_routes = true;
    let app = build_router(cfg);
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 1137,
            "method": "tools/call",
            "params": {
                "name": "iroha.iso20022.status.get",
                "arguments": {
                    "message_id": "msg-001"
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_tool_schema_error(&call, "retired message_id must fail closed");
}
#[tokio::test]
async fn mcp_jsonrpc_tools_call_agent_alias_submit_and_wait_surfaces_submit_error() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    cfg.torii.mcp.enabled = true;
    cfg.torii.mcp.profile = iroha_config::parameters::actual::ToriiMcpProfile::Operator;
    let app = build_router(cfg);
    let (status, call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 1132,
            "method": "tools/call",
            "params": {
                "name": "iroha.transactions.submit_and_wait",
                "arguments": {
                    "wire_hex": "01020304",
                    "timeout_ms": 1000,
                    "poll_interval_ms": 100
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let message = assert_tool_schema_error(
        &call,
        "unknown signed transaction payload field must fail advertised-schema validation",
    );
    assert!(message.contains("body_base64"));
}
