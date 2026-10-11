// MCP Connect session lifecycle regression.
#[tokio::test]
async fn mcp_jsonrpc_connect_session_lifecycle_dispatches_routes() {
    let _data_dir = test_utils::TestDataDirGuard::new();
    let mut cfg = test_utils::mk_minimal_root_cfg();
    enable_writer_mcp(&mut cfg);
    cfg.torii.connect.enabled = true;
    let app = build_router(cfg);
    let network_id = app.network_id().to_string();
    let (status, create_call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 108,
            "method": "tools/call",
            "params": {
                "name": "iroha.connect.session.create",
                "arguments": {
                    "network_id": (network_id),
                    "app_pk": "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU",
                    "nonce": "VlZWVlZWVlZWVlZWVlZWVg"
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !tool_is_error(&create_call),
        "session creation should not be an MCP tool error"
    );
    let create_structured = structured_content(&create_call);
    assert_eq!(
        create_structured.get("status").and_then(Value::as_u64),
        Some(200)
    );
    let create_body = create_structured
        .get("body")
        .and_then(Value::as_object)
        .expect("session create body");
    let sid = create_body
        .get("sid")
        .and_then(Value::as_str)
        .expect("canonical session sid")
        .to_owned();
    assert!(
        create_body
            .get("token_app")
            .and_then(Value::as_str)
            .is_some_and(|token| !token.is_empty()),
        "session create response should contain token_app"
    );
    assert!(
        create_body
            .get("token_wallet")
            .and_then(Value::as_str)
            .is_some_and(|token| !token.is_empty()),
        "session create response should contain token_wallet"
    );
    assert!(
        create_body
            .get("token_management")
            .and_then(Value::as_str)
            .is_some_and(|token| !token.is_empty()),
        "session create response should contain token_management"
    );
    let token_app = create_body
        .get("token_app")
        .and_then(Value::as_str)
        .expect("token_app present")
        .to_owned();
    let token_wallet = create_body
        .get("token_wallet")
        .and_then(Value::as_str)
        .expect("token_wallet present")
        .to_owned();
    let token_management = create_body
        .get("token_management")
        .and_then(Value::as_str)
        .expect("token_management present")
        .to_owned();
    let (status, ws_ticket_app_call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 109,
            "method": "tools/call",
            "params": {
                "name": "iroha.connect.ws.ticket",
                "arguments": {
                    "sid": sid,
                    "role": "app",
                    "token_app": token_app,
                    "node_url": "https://node.example"
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !tool_is_error(&ws_ticket_app_call),
        "ticket generation should not be an MCP tool error"
    );
    let ws_ticket_app = structured_content(&ws_ticket_app_call);
    assert_eq!(
        ws_ticket_app.get("ws_url").and_then(Value::as_str),
        Some(format!("wss://node.example/v1/connect/ws?sid={sid}&role=app").as_str())
    );
    assert_eq!(
        ws_ticket_app
            .get("authorization_header")
            .and_then(Value::as_str),
        Some(format!("Bearer {token_app}").as_str())
    );
    assert_eq!(
        ws_ticket_app
            .get("sec_websocket_protocol")
            .and_then(Value::as_str),
        Some(
            format!(
                "iroha-connect.token.v1.{}",
                B64.encode(token_app.as_bytes())
            )
            .as_str()
        )
    );
    let (status, ws_ticket_wallet_call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 110,
            "method": "tools/call",
            "params": {
                "name": "iroha.connect.ws.ticket",
                "arguments": {
                    "sid": sid,
                    "role": "wallet",
                    "token_wallet": token_wallet,
                    "node_url": "https://node.example"
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !tool_is_error(&ws_ticket_wallet_call),
        "wallet ticket generation should not be an MCP tool error"
    );
    let ws_ticket_wallet = structured_content(&ws_ticket_wallet_call);
    assert_eq!(
        ws_ticket_wallet
            .get("authorization_header")
            .and_then(Value::as_str),
        Some(format!("Bearer {token_wallet}").as_str())
    );
    let (status, status_call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 111,
            "method": "tools/call",
            "params": {
                "name": "iroha.connect.session.status",
                "arguments": {
                    "sid": sid,
                    "token_management": token_management
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !tool_is_error(&status_call),
        "connect session status should not be an MCP tool error"
    );
    let status_structured = structured_content(&status_call);
    assert_eq!(
        status_structured.get("status").and_then(Value::as_u64),
        Some(200)
    );
    let (status, delete_call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 112,
            "method": "tools/call",
            "params": {
                "name": "iroha.connect.session.delete",
                "arguments": {
                    "sid": sid,
                    "token_management": token_management
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !tool_is_error(&delete_call),
        "successful delete should not be an MCP tool error"
    );
    let delete_structured = structured_content(&delete_call);
    assert_eq!(
        delete_structured.get("status").and_then(Value::as_u64),
        Some(204)
    );
    let (status, delete_again_call) = post_mcp(
        &app,
        norito::json!({
            "jsonrpc": "2.0",
            "id": 113,
            "method": "tools/call",
            "params": {
                "name": "iroha.connect.session.delete",
                "arguments": {
                    "sid": sid,
                    "token_management": token_management
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        tool_is_error(&delete_again_call),
        "404 delete should be marked as MCP tool error"
    );
    let delete_again_structured = structured_content(&delete_again_call);
    assert_eq!(
        delete_again_structured
            .get("status")
            .and_then(Value::as_u64),
        Some(404)
    );
}
