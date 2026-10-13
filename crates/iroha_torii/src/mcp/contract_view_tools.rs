//! Bounded, authenticated read-only contract views through the canonical Torii route.

use super::{
    HeaderMap, Map, Method, SharedAppState, ToolSpec, Value, canonical_account_auth_headers_schema,
    dispatch_route, manual_tool_effect_from_name, reject_unknown_arguments,
};
use iroha_data_model::{
    account::AccountId,
    smart_contract::{ContractAddress, ContractAlias},
};

const TOOL: &str = "iroha.contracts.view";
const ROUTE: &str = "/v1/contracts/view";
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_GAS: u64 = 10_000_000;
const MAX_SELECTOR_BYTES: usize = 255;

fn bounded_string<'a>(body: &'a Map, field: &str, maximum: usize) -> Result<&'a str, String> {
    body.get(field)
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= maximum
                && value.trim() == *value
                && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            format!("`{field}` must be a non-empty canonical string of at most {maximum} bytes")
        })
}

fn encode_contract_view(arguments: &Map) -> Result<Vec<u8>, String> {
    reject_unknown_arguments(arguments, &["body", "headers"], TOOL)?;
    let body_value = arguments.get("body").ok_or("`body` is required")?;
    let body = body_value.as_object().ok_or("`body` must be an object")?;
    reject_unknown_arguments(
        body,
        &[
            "authority",
            "contract_address",
            "contract_alias",
            "entrypoint",
            "payload",
            "gas_limit",
        ],
        "contract view body",
    )?;
    let authority = bounded_string(body, "authority", MAX_BODY_BYTES)?;
    AccountId::parse_encoded(authority)
        .map_err(|_| "`authority` must be a canonical account identity")?;
    bounded_string(body, "entrypoint", MAX_SELECTOR_BYTES)?;
    match (body.get("contract_address"), body.get("contract_alias")) {
        (Some(_), None) => {
            bounded_string(body, "contract_address", MAX_SELECTOR_BYTES)?
                .parse::<ContractAddress>()
                .map_err(|_| "invalid canonical contract address")?;
        }
        (None, Some(_)) => {
            let text = bounded_string(body, "contract_alias", MAX_SELECTOR_BYTES)?;
            let alias = text
                .parse::<ContractAlias>()
                .map_err(|_| "invalid canonical contract alias")?;
            if alias.as_ref() != text {
                return Err("contract alias must be canonical".to_owned());
            }
        }
        _ => {
            return Err("provide exactly one of `contract_address` or `contract_alias`".to_owned());
        }
    }
    if !body
        .get("gas_limit")
        .and_then(Value::as_u64)
        .is_some_and(|gas| (1..=MAX_GAS).contains(&gas))
    {
        return Err(format!(
            "`gas_limit` must be an integer from 1 to {MAX_GAS}"
        ));
    }
    // Borrow the decoded payload and cap allocation before encoding. Never clone a source-sized
    // JSON tree or infer another body spelling after the external signer has authorized it.
    norito::json::to_json_bounded_boxed(body_value, MAX_BODY_BYTES)
        .map(<[u8]>::into_vec)
        .map_err(|error| format!("contract view body exceeds its bounded encoding policy: {error}"))
}

pub(super) async fn dispatch_contract_view(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let body = encode_contract_view(arguments)?;
    // Catalog authentication requires a fresh signature/witness for this exact inner route.
    // The route verifies body.authority against that proof; MCP never signs or supplies a signer.
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        ROUTE,
        arguments.get("headers"),
        body,
        Some("application/json".to_owned()),
        Some("application/json".to_owned()),
    )
    .await
}

pub(super) fn iroha_contracts_view_tool() -> ToolSpec {
    ToolSpec::route(
        TOOL.to_owned(),
        "Execute one read-only view of a deployed contract. Requires an external canonical signature or witness for the exact POST body and matching authority. The body is limited to 65536 bytes and execution to 10000000 gas; this creates no transaction or finality receipt.".to_owned(),
        manual_tool_effect_from_name(TOOL), Method::POST, ROUTE.to_owned(),
        norito::json!({
            "type": "object", "additionalProperties": false,
            "required": ["body", "headers"],
            "properties": {
                "body": {
                    "type": "object", "additionalProperties": false,
                    "required": ["authority", "entrypoint", "gas_limit"],
                    "oneOf": [
                        {"required": ["contract_address"], "not": {"required": ["contract_alias"]}},
                        {"required": ["contract_alias"], "not": {"required": ["contract_address"]}}
                    ],
                    "properties": {
                        "authority": {"type": "string", "minLength": 1, "maxLength": (MAX_BODY_BYTES)},
                        "contract_address": {"type": "string", "minLength": 1, "maxLength": (MAX_SELECTOR_BYTES)},
                        "contract_alias": {"type": "string", "minLength": 1, "maxLength": (MAX_SELECTOR_BYTES)},
                        "entrypoint": {"type": "string", "minLength": 1, "maxLength": (MAX_SELECTOR_BYTES)},
                        "payload": {},
                        "gas_limit": {"type": "integer", "minimum": 1, "maximum": (MAX_GAS)}
                    }
                },
                "headers": (canonical_account_auth_headers_schema("External signature tuple or witness for POST /v1/contracts/view and the exact bounded body; authority must match the verified signer context."))
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::{
        AuthorityClass, CATALOG_PROJECTION_GROUPS, OperationKind, ToolEffect,
        apply_catalog_auth_schemas_to_tools, tool_semantics, validate_tool_registry,
    };

    fn arguments() -> Map {
        norito::json!({"body": {
            "authority": (iroha_test_samples::ALICE_ID.to_string()),
            "contract_alias": "coffee-club::universal", "entrypoint": "quote",
            "payload": {"coffees": "3"}, "gas_limit": 1_500_000
        }})
        .as_object()
        .expect("arguments")
        .clone()
    }

    #[test]
    fn contract_view_preserves_exact_body_and_rejects_alternate_shapes() {
        let mut args = arguments();
        let encoded = encode_contract_view(&args).expect("valid view");
        assert_eq!(
            norito::json::from_slice::<Value>(&encoded).expect("body"),
            args["body"]
        );
        args.insert("private_key".to_owned(), Value::String("secret".to_owned()));
        assert!(encode_contract_view(&args).is_err());
        args.remove("private_key");
        let body = args.get_mut("body").unwrap().as_object_mut().unwrap();
        body.insert("contract_address".to_owned(), Value::Null);
        assert!(encode_contract_view(&args).is_err());
        args.get_mut("body")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("contract_alias");
        assert!(encode_contract_view(&args).is_err());
    }

    #[test]
    fn contract_view_rejects_unbounded_work_and_invalid_identity() {
        for value in [
            Value::from(0u64),
            Value::from(MAX_GAS + 1),
            Value::from("3"),
        ] {
            let mut args = arguments();
            args.get_mut("body")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("gas_limit".to_owned(), value);
            assert!(encode_contract_view(&args).is_err());
        }
        for field in ["authority", "entrypoint", "contract_alias"] {
            let mut args = arguments();
            args.get_mut("body")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), Value::from(" "));
            assert!(encode_contract_view(&args).is_err());
        }
        let mut args = arguments();
        args.get_mut("body")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "payload".to_owned(),
                Value::String("x".repeat(MAX_BODY_BYTES)),
            );
        assert!(encode_contract_view(&args).is_err());
    }

    #[test]
    fn contract_view_catalog_is_read_only_and_requires_external_signer_context() {
        let mut tools = vec![iroha_contracts_view_tool()];
        apply_catalog_auth_schemas_to_tools(&mut tools, CATALOG_PROJECTION_GROUPS);
        validate_tool_registry(&tools, CATALOG_PROJECTION_GROUPS).expect("audited view registry");
        let tool = &tools[0];
        let (effect, method, path) = tool.route_backing().expect("route");
        assert_eq!(
            (effect, method, path),
            (ToolEffect::Read, &Method::POST, ROUTE)
        );
        assert_eq!(tool_semantics(tool).operation(), OperationKind::Observe);
        assert_eq!(tool_semantics(tool).authority(), AuthorityClass::Account);
        assert_eq!(
            tool.input_schema["additionalProperties"],
            Value::Bool(false)
        );
        assert!(
            tool.input_schema["required"]
                .as_array()
                .unwrap()
                .contains(&Value::from("headers"))
        );
        let mut headers = HeaderMap::new();
        assert!(
            crate::mcp::apply_extra_headers_with_policy(
                &mut headers,
                None,
                crate::mcp::ExtraHeaderPolicy::CanonicalAccountAuthentication,
            )
            .is_err()
        );
    }
}
