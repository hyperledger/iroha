#![cfg(feature = "app_api")]
//! Public-contract tests for the chain-authoritative SoraFS repair API.
use iroha_torii::openapi::generate_spec;
use iroha_torii_shared::route_catalog::contracts_and_verification_keys as routes;
use norito::json::Value;
#[test]
fn repair_route_catalog_exposes_only_the_v1_native_ledger_surface() {
    let expected = [
        (
            routes::SORAFS_AUDIT_REPAIR_REPORT_POST,
            "/v1/sorafs/audit/repair/report",
        ),
        (
            routes::SORAFS_AUDIT_REPAIR_SLASH_POST,
            "/v1/sorafs/audit/repair/slash",
        ),
        (
            routes::SORAFS_AUDIT_REPAIR_CLAIM_POST,
            "/v1/sorafs/audit/repair/claim",
        ),
        (
            routes::SORAFS_AUDIT_REPAIR_HEARTBEAT_POST,
            "/v1/sorafs/audit/repair/heartbeat",
        ),
        (
            routes::SORAFS_AUDIT_REPAIR_COMPLETE_POST,
            "/v1/sorafs/audit/repair/complete",
        ),
        (
            routes::SORAFS_AUDIT_REPAIR_FAIL_POST,
            "/v1/sorafs/audit/repair/fail",
        ),
        (
            routes::SORAFS_AUDIT_REPAIR_APPEAL_POST,
            "/v1/sorafs/audit/repair/appeal",
        ),
        (
            routes::SORAFS_AUDIT_REPAIR_STATUS_GET,
            "/v1/sorafs/audit/repair/status",
        ),
        (
            routes::SORAFS_AUDIT_REPAIR_TASKS_GET,
            "/v1/sorafs/audit/repair/tasks",
        ),
        (
            routes::SORAFS_AUDIT_REPAIR_TASKS_BY_TICKET_ID_GET,
            "/v1/sorafs/audit/repair/tasks/{ticket_id}",
        ),
        (
            routes::SORAFS_AUDIT_REPAIR_EVENTS_GET,
            "/v1/sorafs/audit/repair/events",
        ),
    ];
    for (route, path) in expected {
        assert_eq!(route.path(), path);
    }
    let paths = routes::ROUTES
        .iter()
        .map(|route| route.path())
        .collect::<Vec<_>>();
    for removed in [
        "/v1/sorafs/audit/repair/status/{manifest_hex}",
        "/v1/sorafs/audit/repair/events/stream",
        "/v1/sorafs/audit/repair/events/ws",
    ] {
        assert!(
            !paths.contains(&removed),
            "obsolete repair route remains: {removed}"
        );
    }
}
#[test]
fn repair_openapi_requires_signed_transactions_and_finalized_cursors() {
    let spec = generate_spec();
    let paths = spec
        .get("paths")
        .and_then(Value::as_object)
        .expect("OpenAPI paths");
    let command_requirements = [
        ("/v1/sorafs/audit/repair/report", "SubmitSorafsRepairTask"),
        (
            "/v1/sorafs/audit/repair/slash",
            "ApplySorafsRepairTaskAction::Escalate",
        ),
        (
            "/v1/sorafs/audit/repair/claim",
            "ApplySorafsRepairTaskAction::Claim",
        ),
        (
            "/v1/sorafs/audit/repair/heartbeat",
            "ApplySorafsRepairTaskAction::Renew",
        ),
        (
            "/v1/sorafs/audit/repair/complete",
            "ApplySorafsRepairTaskAction::Complete",
        ),
        (
            "/v1/sorafs/audit/repair/fail",
            "ApplySorafsRepairTaskAction::Fail",
        ),
        ("/v1/sorafs/audit/repair/appeal", "SubmitSorafsRepairAppeal"),
    ];
    for (path, required_instruction) in command_requirements {
        let post = paths
            .get(path)
            .and_then(Value::as_object)
            .and_then(|path| path.get("post"))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing repair POST operation {path}"));
        assert!(
            post.get("description")
                .and_then(Value::as_str)
                .is_some_and(|description| description.contains(required_instruction))
        );
        assert!(
            post.get("responses")
                .and_then(Value::as_object)
                .is_some_and(|responses| responses.contains_key("202"))
        );
        let request_schema = post
            .get("requestBody")
            .and_then(Value::as_object)
            .and_then(|body| body.get("content"))
            .and_then(Value::as_object)
            .and_then(|content| content.get("application/json"))
            .and_then(Value::as_object)
            .and_then(|media| media.get("schema"))
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("$ref"))
            .and_then(Value::as_str);
        assert_eq!(
            request_schema,
            Some("#/components/schemas/VersionedSignedTransactionJson")
        );
    }
    let task_parameters = operation_parameter_names(paths, "/v1/sorafs/audit/repair/tasks", "get");
    for required in [
        "limit",
        "expected_finalized_height",
        "expected_finalized_block_hash_hex",
        "after_task_id_hex",
    ] {
        assert!(task_parameters.contains(&required));
    }
    let event_parameters =
        operation_parameter_names(paths, "/v1/sorafs/audit/repair/events", "get");
    for required in [
        "limit",
        "expected_finalized_height",
        "expected_finalized_block_hash_hex",
        "after_sequence",
        "after_block_height",
        "after_block_hash_hex",
        "after_event_index",
    ] {
        assert!(event_parameters.contains(&required));
    }
    assert!(!event_parameters.contains(&"since"));
    assert!(!paths.contains_key("/v1/sorafs/audit/repair/events/stream"));
    assert!(!paths.contains_key("/v1/sorafs/audit/repair/events/ws"));
}
fn operation_parameter_names<'a>(
    paths: &'a norito::json::Map,
    path: &str,
    method: &str,
) -> Vec<&'a str> {
    paths
        .get(path)
        .and_then(Value::as_object)
        .and_then(|path| path.get(method))
        .and_then(Value::as_object)
        .and_then(|operation| operation.get("parameters"))
        .and_then(Value::as_array)
        .expect("operation parameters")
        .iter()
        .filter_map(|parameter| parameter.get("name").and_then(Value::as_str))
        .collect()
}
