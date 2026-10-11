//! OpenAPI schema construction and package authority tests.

use super::*;
use crate::utils;
use iroha_torii_shared::{
    route_catalog::{self, ApiSurface, musubi as musubi_routes},
    sorafs_hedging_billing_api::{
        BILLING_ACKNOWLEDGEMENT_PROOF_SCHEMA_HASH_HEX_V1,
        BILLING_ACKNOWLEDGEMENT_PROOF_SCHEMA_NAME_V1,
    },
    sorafs_moderation_api::{
        SORAFS_MODERATION_DEAD_LETTER_APPLY_REQUEST_MAX_BYTES_V1,
        SORAFS_MODERATION_DEAD_LETTER_PREPARE_REQUEST_MAX_BYTES_V1,
        SORAFS_MODERATION_DEAD_LETTER_RESOLUTION_MAX_BASE64_BYTES_V1,
    },
};
use sorafs_node::evidence_viewer::EVIDENCE_VIEWER_MAX_OPAQUE_TOKEN_BYTES_V1;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[cfg(feature = "app_api")]
#[test]
fn explorer_feeds_share_list_query_and_page_contract() {
    let spec = compiled_spec();
    for feed in [
        "accounts",
        "domains",
        "asset-definitions",
        "assets",
        "nfts",
        "rwas",
        "blocks",
        "transactions",
        "transactions/latest",
        "instructions",
        "instructions/latest",
    ] {
        let path = format!("/v1/explorer/{feed}");
        let get = &spec["paths"][path.as_str()]["get"];
        let query_path = format!("{path}/query");
        let post = &spec["paths"][query_path.as_str()]["post"];
        let parameters = get["parameters"].as_array().expect("GET controls");
        assert_eq!(
            parameters
                .iter()
                .map(|value| value["name"].as_str().unwrap())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["filter", "select", "limit", "cursor"])
        );
        assert_eq!(
            post["requestBody"]["content"]["application/json"]["schema"]["$ref"].as_str(),
            Some("#/components/schemas/ExplorerListQuery")
        );
        let reference = get["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
            .as_str()
            .expect("page schema");
        let page = &spec["components"]["schemas"]
            [reference.strip_prefix("#/components/schemas/").unwrap()];
        assert_eq!(
            page["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["items", "next_cursor"])
        );
        assert!(page["properties"].get("pagination").is_none());
        assert_eq!(post["x-iroha-tool-effect"].as_str(), Some("read"));
    }
    assert!(
        spec["components"]["schemas"]
            .get("ExplorerCursorMeta")
            .is_none()
    );
    assert!(
        spec["components"]["schemas"]
            .get("ExplorerHistoryCursorMeta")
            .is_none()
    );
}

#[test]
fn canonical_output_contract_has_one_details_owner_and_header_without_result_root() {
    let schemas = openapi_schemas();
    let details = &schemas["PipelineTransactionDetailsResponse"];
    let expected = BTreeSet::from(["hash", "transaction"]);
    assert_eq!(details["additionalProperties"].as_bool(), Some(false));
    assert_eq!(
        details["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        expected
    );
    assert_eq!(
        details["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| field.as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        expected
    );

    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(1).unwrap(),
        None,
        None,
        0,
        0,
    );
    let encoded = norito::json::to_value(&header).unwrap();
    let actual = encoded
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert!(!actual.contains("result_merkle_root"));
    let contract = &schemas["BlockHeader"];
    assert_eq!(contract["additionalProperties"].as_bool(), Some(false));
    assert_eq!(
        contract["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        actual
    );
    assert_eq!(
        contract["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| field.as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        actual
    );
}

const GOVERNANCE_LOWER_HEX32_PATTERN: &str = "^[0-9a-f]{64}$";
const GOVERNANCE_EXACT_TOKEN_PATTERN: &str = r"^[^\s\u0000-\u001F\u007F-\u009F]+$";
const GOVERNANCE_SELECTOR_V1_PATTERN: &str =
    iroha_data_model::governance::GOVERNANCE_SELECTOR_V1_PATTERN;
const GOVERNANCE_U64_DECIMAL_PATTERN: &str = concat!(
    "^(?:0|[1-9][0-9]{0,18}|",
    "1[0-7][0-9]{18}|18[0-3][0-9]{17}|184[0-3][0-9]{16}|",
    "1844[0-5][0-9]{15}|18446[0-6][0-9]{14}|184467[0-3][0-9]{13}|",
    "1844674[0-3][0-9]{12}|184467440[0-6][0-9]{10}|",
    "1844674407[0-2][0-9]{9}|18446744073[0-6][0-9]{8}|",
    "1844674407370[0-8][0-9]{6}|18446744073709[0-4][0-9]{5}|",
    "184467440737095[0-4][0-9]{4}|18446744073709550[0-9]{3}|",
    "18446744073709551[0-5][0-9]{2}|1844674407370955160[0-9]|",
    "1844674407370955161[0-4]|18446744073709551615)$"
);
const TRANSACTION_ACCEPTANCE_BAD_REQUEST_REJECT_CODES: &[&str] = &[
    "transaction_rejected",
    "PRTRY:NTS_UNHEALTHY",
    "PRTRY:TX_UNSUPPORTED_AUTHORITY",
    "PRTRY:TX_SIGNATURE_ALGO_DENIED",
    "PRTRY:TX_SIGNATURE_INVALID",
    "PRTRY:TX_SIGNATURE_MALFORMED",
    "PRTRY:TX_SIGNATURE_MISSING",
    "PRTRY:TX_SIGNATURE_UNKNOWN_SIGNER",
    "PRTRY:TX_SIGNATURE_INSUFFICIENT",
    "ED07",
    "PRTRY:ROUTE_UNRESOLVED",
];
const TRANSACTION_SUBMISSION_FORBIDDEN_REJECT_CODES: &[&str] = &[
    "PRTRY:QUEUE_GOVERNANCE_REJECTED",
    "PRTRY:QUEUE_LANE_COMPLIANCE_DENIED",
    "PRTRY:QUEUE_LANE_PRIVACY_PROOF_REJECTED",
    "PRTRY:NEXUS_FEE_ADMISSION_REJECTED",
];
const TRANSACTION_SUBMISSION_CONFLICT_REJECT_CODES: &[&str] =
    &["PRTRY:ALREADY_COMMITTED", "PRTRY:ALREADY_ENQUEUED"];
const TRANSACTION_SUBMISSION_RATE_LIMIT_REJECT_CODES: &[&str] = &[
    "PRTRY:QUEUE_FULL",
    "PRTRY:QUEUE_LATENCY",
    "PRTRY:QUEUE_RATE",
];
const TRANSACTION_SUBMISSION_UNAVAILABLE_REJECT_CODES: &[&str] = &[
    "transaction_admission_worker_failed",
    "route_unavailable",
    "transaction_dispatch_outcome_unknown",
];
fn transaction_submission_bad_request_reject_codes() -> Vec<&'static str> {
    let mut codes = vec!["invalid_transaction_payload"];
    codes.extend_from_slice(TRANSACTION_ACCEPTANCE_BAD_REQUEST_REJECT_CODES);
    codes
}
fn canonical_document() -> Value {
    norito::json::from_str(CANONICAL_OPENAPI_JSON)
        .expect("package-local OpenAPI authority must parse")
}
fn openapi_schemas() -> Map {
    component_schemas(&canonical_document()).clone()
}
fn sccp_schemas() -> Map {
    openapi_schemas()
        .into_iter()
        .filter(|(name, _)| name.starts_with("Sccp"))
        .collect()
}
fn schema_ref(name: &str) -> Value {
    norito::json!({ "$ref": (format!("#/components/schemas/{name}")) })
}
fn tags_section() -> Value {
    canonical_document()
        .get("tags")
        .cloned()
        .expect("package-local OpenAPI authority must contain tags")
}
fn subscription_paths() -> Map {
    canonical_document()
        .get("paths")
        .and_then(Value::as_object)
        .expect("package-local OpenAPI authority paths")
        .iter()
        .filter(|(path, _)| path.starts_with("/v1/subscriptions"))
        .map(|(path, item)| (path.clone(), item.clone()))
        .collect()
}
fn subscription_schemas(schemas: &mut Map) {
    schemas.extend(
        openapi_schemas()
            .into_iter()
            .filter(|(name, _)| name.starts_with("Subscription")),
    );
}
const COMPONENT_REF_PREFIX: &str = "#/components/";
const COMPONENT_SCHEMA_REF_PREFIX: &str = "#/components/schemas/";
#[derive(Clone, Copy)]
enum ComponentRefContext {
    Document,
    Components,
    SchemaMap,
    Schema,
    HeaderMap,
    Header,
}
impl ComponentRefContext {
    fn child(self, key: &str) -> Self {
        match self {
            Self::Schema | Self::SchemaMap => Self::Schema,
            Self::HeaderMap => Self::Header,
            Self::Components => match key {
                "schemas" => Self::SchemaMap,
                "headers" => Self::HeaderMap,
                _ => Self::Document,
            },
            Self::Document if key == "components" => Self::Components,
            Self::Document if key == "headers" => Self::HeaderMap,
            Self::Document | Self::Header if key == "schema" || key.ends_with("-schema") => {
                Self::Schema
            }
            Self::Document => Self::Document,
            Self::Header => Self::Header,
        }
    }
    fn expected_component(self) -> Option<&'static str> {
        match self {
            Self::Schema => Some("schemas"),
            Self::Header => Some("headers"),
            _ => None,
        }
    }
}
fn documented_reject_codes<'a>(responses: &'a Map, status: &str) -> Vec<&'a str> {
    responses
        .get(status)
        .and_then(Value::as_object)
        .and_then(|response| response.get("headers"))
        .and_then(Value::as_object)
        .and_then(|headers| headers.get("x-iroha-reject-code"))
        .and_then(Value::as_object)
        .and_then(|header| header.get("schema"))
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("enum"))
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("HTTP {status} x-iroha-reject-code enum"))
        .iter()
        .map(|code| code.as_str().expect("reject-code enum value"))
        .collect()
}
fn response_documents_reject_code(responses: &Map, status: &str) -> bool {
    responses
        .get(status)
        .and_then(Value::as_object)
        .and_then(|response| response.get("headers"))
        .and_then(Value::as_object)
        .is_some_and(|headers| headers.contains_key("x-iroha-reject-code"))
}
fn component_schemas(document: &Value) -> &Map {
    component_collections(document)
        .get("schemas")
        .and_then(Value::as_object)
        .expect("component schemas")
}
fn component_collections(document: &Value) -> &Map {
    document
        .get("components")
        .and_then(Value::as_object)
        .expect("OpenAPI components")
}
fn openapi_operation<'a>(document: &'a Value, path: &str, method: &str) -> &'a Map {
    document
        .get("paths")
        .and_then(Value::as_object)
        .and_then(|paths| paths.get(path))
        .and_then(Value::as_object)
        .and_then(|path_item| path_item.get(method))
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{method} {path} operation"))
}
fn assert_canonical_auth_required_response(
    operation: &Map,
    path: &str,
    expected_reject_code: &str,
) {
    let responses = operation
        .get("responses")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("POST {path} responses"));
    assert_eq!(
        documented_reject_codes(responses, "401"),
        vec![expected_reject_code],
        "POST {path} exact 401 reject code"
    );
    let challenge = responses
        .get("401")
        .and_then(Value::as_object)
        .and_then(|response| response.get("headers"))
        .and_then(Value::as_object)
        .and_then(|headers| headers.get("WWW-Authenticate"))
        .and_then(Value::as_object)
        .and_then(|header| header.get("schema"))
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("const"))
        .and_then(Value::as_str);
    assert_eq!(challenge, Some("Signature"), "POST {path} challenge");
}
fn assert_alias_auth_required_response(operation: &Map, path: &str) {
    assert_canonical_auth_required_response(operation, path, "alias_auth_required");
}
fn operation_request_schema_ref<'a>(operation: &'a Map, path: &str) -> &'a str {
    operation
        .get("requestBody")
        .and_then(Value::as_object)
        .and_then(|body| body.get("content"))
        .and_then(Value::as_object)
        .and_then(|content| content.get("application/json"))
        .and_then(Value::as_object)
        .and_then(|media| media.get("schema"))
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("$ref"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("request schema for {path}"))
}
fn operation_response_schema_ref<'a>(operation: &'a Map, status: &str, path: &str) -> &'a str {
    operation
        .get("responses")
        .and_then(Value::as_object)
        .and_then(|responses| responses.get(status))
        .and_then(Value::as_object)
        .and_then(|response| response.get("content"))
        .and_then(Value::as_object)
        .and_then(|content| content.get("application/json"))
        .and_then(Value::as_object)
        .and_then(|media| media.get("schema"))
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("$ref"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("HTTP {status} response schema for {path}"))
}
fn assert_strict_object_schema(
    schemas: &Map,
    name: &str,
    required_fields: &[&str],
    optional_fields: &[&str],
) {
    let schema = schemas
        .get(name)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{name} schema"));
    assert_eq!(
        schema.get("additionalProperties"),
        Some(&Value::Bool(false)),
        "{name} must reject unknown fields"
    );
    let actual_required = schema
        .get("required")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{name} required fields"))
        .iter()
        .map(|field| field.as_str().expect("required field name"))
        .collect::<BTreeSet<_>>();
    let expected_required = required_fields.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(actual_required, expected_required, "{name} required fields");
    let actual_properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{name} properties"))
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_properties = required_fields
        .iter()
        .chain(optional_fields)
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_properties, expected_properties, "{name} properties");
}
fn catalog_openapi_route_enabled(method: CatalogHttpMethod, path: &str) -> bool {
    RouteCatalog::new(CATALOGED_ROUTES)
        .project(
            CatalogProjection::OpenApi,
            crate::router::builder::compiled_route_features(),
        )
        .into_iter()
        .any(|route| route.method() == method && route.path() == path)
}
fn expected_operation_effect(method: &str, path: &str) -> &'static str {
    if expected_operator_operation(method, path) {
        return "operator";
    }
    if method == "post"
        && matches!(
            path,
            "/v1/sorafs/provider/source"
                | "/v1/sorafs/provider/attestation"
                | "/v1/sorafs/publish/prepare"
                | "/v1/sorafs/publish/proof"
                | "/v1/sorafs/repair/source"
        )
    {
        return "expensive";
    }
    if method == "post" && path.starts_with("/v1/musubi/instructions/") {
        return "build_instruction";
    }
    if expected_read_operation(method, path) {
        return "read";
    }
    "write"
}
fn expected_operator_operation(method: &str, path: &str) -> bool {
    let catalog_method = match method {
        "get" => Some(CatalogHttpMethod::Get),
        "post" => Some(CatalogHttpMethod::Post),
        "put" => Some(CatalogHttpMethod::Put),
        "patch" => Some(CatalogHttpMethod::Patch),
        "delete" => Some(CatalogHttpMethod::Delete),
        _ => None,
    };
    if catalog_method.is_some_and(|method| {
        RouteCatalog::new(CATALOGED_ROUTES)
            .routes()
            .iter()
            .any(|route| {
                route.method() == method
                    && route.path() == path
                    && (route.surface() == ApiSurface::Operator
                        || route.authentication() == AuthenticationPolicy::OperatorSignature)
            })
    }) {
        return true;
    }
    if method == "get" {
        return false;
    }
    path.starts_with("/v1/operator/")
        || path == route_catalog::core::CONFIGURATION_GET.path()
        || matches!(
            path,
            "/v1/internal/torii/proxy"
                | "/v1/nexus/lifecycle"
                | "/v1/nexus/lane-lifecycle"
                | "/v1/gov/protected-namespaces"
        )
}
fn expected_read_operation(method: &str, path: &str) -> bool {
    matches!(method, "get" | "head" | "options")
        || (method == "post" && path.starts_with("/v1/musubi/queries/"))
        || (method == "post" && path == route_catalog::pipeline::QUERY.path())
        || (method == "post"
            && matches!(
                path,
                "/v1/accounts/query"
                    | "/v1/accounts/{account_id}/assets/query"
                    | "/v1/assets/{definition_id}/holders/query"
                    | "/v1/transactions/query"
                    | "/v1/accounts/{account_id}/transactions/query"
                    | "/v1/repo/agreements/query"
                    | "/v1/accounts/{account_id}/permissions/query"
                    | "/v1/subscriptions/plans/query"
                    | "/v1/subscriptions/query"
                    | "/v1/space-directory/uaids/{uaid}/manifests/query"
                    | "/v1/accounts/{account_id}/history/query"
                    | "/v1/contracts/activity/query"
                    | "/v1/contracts/events/query"
                    | "/v1/ledger/authority-originals"
                    | "/v1/explorer/accounts/query"
                    | "/v1/explorer/asset-definitions/query"
                    | "/v1/explorer/assets/query"
                    | "/v1/explorer/blocks/query"
                    | "/v1/explorer/domains/query"
                    | "/v1/explorer/instructions/latest/query"
                    | "/v1/explorer/instructions/query"
                    | "/v1/explorer/nfts/query"
                    | "/v1/explorer/rwas/query"
                    | "/v1/explorer/transactions/latest/query"
                    | "/v1/explorer/transactions/query"
                    | "/v1/accounts/faucet/prepare"
                    | "/v1/accounts/onboard/plan"
                    | "/v1/accounts/onboard/prepare"
                    | "/v1/accounts/onboarding/current-state"
                    | "/v1/aliases/by-account"
                    | "/v1/aliases/setup/plan"
                    | "/v1/aliases/lease/renew/plan"
                    | "/v1/aliases/auto-renew/plan"
                    | "/v1/aliases/resolve"
                    | "/v1/aliases/resolve-index"
                    | "/v1/retail/recipients/lookup"
                    | "/v1/retail/recipients/route"
                    | "/v1/fee-sponsor-programs/by-id"
                    | "/v1/fee-sponsor-enrollments/by-id"
                    | "/v1/fees/quote"
                    | "/v1/validation-fee/accounts/{account_id}/statement"
                    | "/v1/validation-fee/quote"
                    | "/v1/assets/aliases/resolve"
                    | "/v1/assets/definitions/query"
                    | "/v1/assets/holders/query"
                    | "/v1/assets/query"
                    | "/v1/contracts/aliases/resolve"
                    | "/v1/contracts/deployment-state"
                    | "/v1/contracts/view"
                    | "/v1/contracts/view/batch"
                    | "/v1/controls/asset-transfer/query"
                    | "/v1/da/commitments"
                    | "/v1/da/commitments/prove"
                    | "/v1/da/commitments/verify"
                    | "/v1/da/pin-intents"
                    | "/v1/da/pin-intents/prove"
                    | "/v1/da/pin-intents/verify"
                    | "/v1/domains/query"
                    | "/v1/accounts/recovery/status"
                    | "/v1/multisig/proposals/query"
                    | "/v1/multisig/proposals/resolve"
                    | "/v1/multisig/spec"
                    | "/v1/nexus/private-settlements/legs/{payload_digest}/audit-capsule"
                    | "/v1/nexus/staking/prepare"
                    | "/v1/nfts/query"
                    | "/v1/proofs/query"
                    | "/v1/rwas/query"
                    | "/v1/soracloud/ciphertext/query"
                    | "/v1/pipeline/transactions/status"
                    | "/v1/pipeline/transactions/details"
                    | "/v1/zk/merkle-path"
                    | "/v1/zk/roots"
                    | "/v1/zk/verify-batch"
                    | "/v1/zk/vote/tally"
            ))
}
fn operation_header_requirements(operation: &Map) -> Vec<(String, bool)> {
    operation
        .get("parameters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|parameter| parameter.get("in").and_then(Value::as_str) == Some("header"))
        .map(|parameter| {
            (
                parameter
                    .get("name")
                    .and_then(Value::as_str)
                    .expect("header parameter name")
                    .to_owned(),
                parameter
                    .get("required")
                    .and_then(Value::as_bool)
                    .expect("header required flag"),
            )
        })
        .collect()
}
fn assert_no_retired_vpn_fee_fields(value: &Value, location: &str) {
    match value {
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                assert_no_retired_vpn_fee_fields(value, &format!("{location}[{index}]"));
            }
        }
        Value::Object(object) => {
            for (key, value) in object {
                assert!(
                    !matches!(
                        key.as_str(),
                        "lease_fee_nanos" | "earned_fee_nanos" | "refunded_fee_nanos"
                    ),
                    "retired VPN fee field {key} at {location}"
                );
                assert_no_retired_vpn_fee_fields(value, &format!("{location}.{key}"));
            }
        }
        _ => {}
    }
}
fn assert_component_refs_resolve(
    value: &Value,
    components: &Map,
    location: &str,
    context: ComponentRefContext,
    reference_count: &mut usize,
) {
    match value {
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                assert_component_refs_resolve(
                    value,
                    components,
                    &format!("{location}[{index}]"),
                    context,
                    reference_count,
                );
            }
        }
        Value::Object(object) => {
            for (key, value) in object {
                let child_location = format!("{location}.{key}");
                if key == "$ref" {
                    *reference_count += 1;
                    let reference = value.as_str().unwrap_or_else(|| {
                        panic!("OpenAPI $ref at {child_location} must be a string")
                    });
                    let component_path = reference
                        .strip_prefix(COMPONENT_REF_PREFIX)
                        .unwrap_or_else(|| {
                            panic!(
                                "OpenAPI $ref at {child_location} must target a local component root: {reference}"
                            )
                        });
                    let mut segments = component_path.split('/');
                    let kind = segments.next().unwrap_or_default();
                    let name = segments.next().unwrap_or_default();
                    assert!(
                        !kind.is_empty() && !name.is_empty(),
                        "OpenAPI $ref at {child_location} has no component kind or name"
                    );
                    assert!(
                        segments.next().is_none(),
                        "OpenAPI $ref at {child_location} must not target a nested component path: {reference}"
                    );
                    let expected_kind = context.expected_component().unwrap_or_else(|| {
                        panic!(
                            "OpenAPI $ref at {child_location} is not permitted at this location: {reference}"
                        )
                    });
                    assert_eq!(
                        kind, expected_kind,
                        "OpenAPI $ref at {child_location} targets {kind}, but this location requires {expected_kind}"
                    );
                    let collection = components
                        .get(kind)
                        .and_then(Value::as_object)
                        .unwrap_or_else(|| {
                            panic!(
                                "OpenAPI $ref at {child_location} targets missing component collection {kind}"
                            )
                        });
                    assert!(
                        collection.contains_key(name),
                        "OpenAPI $ref at {child_location} targets missing component {kind}/{name}"
                    );
                }
                assert_component_refs_resolve(
                    value,
                    components,
                    &child_location,
                    context.child(key),
                    reference_count,
                );
            }
        }
        _ => {}
    }
}
fn component_properties<'a>(schemas: &'a Map, name: &str) -> &'a Map {
    schemas
        .get(name)
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{name} properties"))
}
fn component_required<'a>(schemas: &'a Map, name: &str) -> Vec<&'a str> {
    schemas
        .get(name)
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("required"))
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{name} required fields"))
        .iter()
        .map(|field| field.as_str().expect("required field name"))
        .collect()
}
fn property_ref<'a>(schemas: &'a Map, owner: &str, property: &str) -> &'a str {
    component_properties(schemas, owner)
        .get(property)
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("$ref"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{owner}.{property} schema reference"))
}
fn nullable_property_ref<'a>(schemas: &'a Map, owner: &str, property: &str) -> &'a str {
    let schema = component_properties(schemas, owner)
        .get(property)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{owner}.{property} property schema"));
    let one_of = schema.get("oneOf").and_then(Value::as_array);
    let any_of = schema.get("anyOf").and_then(Value::as_array);
    assert!(
        one_of.is_some() ^ any_of.is_some(),
        "{owner}.{property} must use exactly one nullable union keyword"
    );
    let variants = one_of.or(any_of).expect("checked nullable union");
    assert_eq!(
        variants.len(),
        2,
        "{owner}.{property} nullable union must have exactly two variants"
    );
    assert_eq!(
        variants
            .get(1)
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("type"))
            .and_then(Value::as_str),
        Some("null"),
        "{owner}.{property} second variant must be null"
    );
    variants
        .first()
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("$ref"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{owner}.{property} typed nullable reference"))
}
fn collect_component_refs(value: &Value, refs: &mut BTreeSet<String>) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_component_refs(value, refs);
            }
        }
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                let component = reference
                    .strip_prefix(COMPONENT_SCHEMA_REF_PREFIX)
                    .unwrap_or_else(|| panic!("schema has a non-component reference: {reference}"));
                refs.insert(component.to_owned());
            }
            for value in object.values() {
                collect_component_refs(value, refs);
            }
        }
        _ => {}
    }
}
#[test]
fn openapi_authorities_have_only_resolvable_component_refs() {
    for (label, document) in [
        ("package-local", canonical_document()),
        ("compiled", generate_spec()),
    ] {
        let components = component_collections(&document);
        let mut reference_count = 0;
        assert_component_refs_resolve(
            &document,
            components,
            "$",
            ComponentRefContext::Document,
            &mut reference_count,
        );
        assert!(
            reference_count > 0,
            "{label} OpenAPI document unexpectedly contains no component references"
        );
    }
}
#[test]
fn package_openapi_authority_is_canonical_norito_json() {
    let parsed = canonical_document();
    let rendered = norito::json::to_string_pretty(&parsed)
        .expect("serialize package-local Torii OpenAPI authority");
    assert_eq!(
        rendered.as_bytes(),
        CANONICAL_OPENAPI_JSON.as_bytes(),
        "package-local OpenAPI authority must use canonical pretty Norito JSON bytes"
    );
}
#[test]
fn privacy_proposed_lifecycle_schema_matches_explicit_governance_payload() {
    use iroha_data_model::privacy::{PrivacyProposedLifecycleV1, PrivacyProtocolLifecycleV1};

    let lifecycle = PrivacyProtocolLifecycleV1::Proposed(PrivacyProposedLifecycleV1 {
        proposed_at_height: 7,
    });
    let encoded = norito::json::to_json(&lifecycle).expect("serialize pending proposal");
    let payload: Value = norito::json::from_str(&encoded).expect("parse typed proposal JSON");
    assert_eq!(payload["state"].as_str(), Some("proposed"));
    let payload_fields = payload["record"]
        .as_object()
        .expect("typed proposal record")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(payload_fields, BTreeSet::from(["proposed_at_height"]));
    assert_eq!(payload["record"]["proposed_at_height"].as_u64(), Some(7));
    assert_eq!(
        norito::json::from_str::<PrivacyProtocolLifecycleV1>(&encoded)
            .expect("decode typed pending proposal"),
        lifecycle
    );

    for (label, document) in [
        ("authored", canonical_document()),
        ("compiled", generate_spec()),
    ] {
        let variants = component_schemas(&document)["PrivacyProtocolLifecycleV1"]["oneOf"]
            .as_array()
            .expect("privacy lifecycle alternatives");
        let proposed = variants
            .iter()
            .filter(|variant| variant["properties"]["state"]["const"] == payload["state"])
            .collect::<Vec<_>>();
        assert_eq!(proposed.len(), 1, "{label}: one typed Proposed alternative");
        let record = &proposed[0]["properties"]["record"];
        assert_eq!(record["type"].as_str(), Some("object"), "{label}");
        assert_eq!(
            record["additionalProperties"].as_bool(),
            Some(false),
            "{label}"
        );
        let properties = record["properties"]
            .as_object()
            .expect("proposal properties");
        assert_eq!(
            properties
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            payload_fields,
            "{label}: authored properties must match the typed payload"
        );
        let required = record["required"]
            .as_array()
            .expect("required proposal fields")
            .iter()
            .map(|value| value.as_str().expect("required field name"))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            required, payload_fields,
            "{label}: required typed payload fields"
        );
        assert_eq!(
            properties["proposed_at_height"]["type"].as_str(),
            Some("integer")
        );
        assert_eq!(
            properties["proposed_at_height"]["format"].as_str(),
            Some("uint64")
        );
        assert_eq!(
            properties["proposed_at_height"]["minimum"].as_u64(),
            Some(1)
        );
    }

    for removed in [
        r#"{"state":"proposed","record":{"proposed_at_height":7,"activate_at_height":7}}"#,
        r#"{"state":"proposed","record":{"proposed_at_height":7,"activate_at_height":307}}"#,
    ] {
        assert!(norito::json::from_str::<PrivacyProtocolLifecycleV1>(removed).is_err());
    }
}

#[test]
fn standalone_ballot_drafts_publish_one_exact_success_and_standard_bad_request() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    assert_strict_object_schema(
        schemas,
        "GovernanceBallotDraftResponseV1",
        &["drafted", "tx_instructions"],
        &[],
    );
    let response = component_properties(schemas, "GovernanceBallotDraftResponseV1");
    assert_eq!(response["drafted"]["const"].as_bool(), Some(true));
    assert_eq!(response["tx_instructions"]["minItems"].as_u64(), Some(1));
    assert_eq!(response["tx_instructions"]["maxItems"].as_u64(), Some(1));
    assert_eq!(
        response["tx_instructions"]["items"]["$ref"].as_str(),
        Some("#/components/schemas/GovernanceBallotInstructionDraftV1")
    );
    assert_strict_object_schema(
        schemas,
        "GovernanceBallotInstructionDraftV1",
        &["wire_id", "payload_hex"],
        &[],
    );

    for path in [
        "/v1/gov/ballots/plain",
        "/v1/gov/ballots/zk-v1",
        "/v1/gov/ballots/zk-v1/ballot-proof",
    ] {
        let operation = openapi_operation(&document, path, "post");
        assert_eq!(
            operation_response_schema_ref(operation, "200", path),
            "#/components/schemas/GovernanceBallotDraftResponseV1"
        );
        assert_eq!(
            operation_response_schema_ref(operation, "400", path),
            "#/components/schemas/ErrorEnvelope"
        );
    }
}
#[test]
fn account_onboarding_current_state_openapi_is_one_closed_v1_observation() {
    const PATH: &str = "/v1/accounts/onboarding/current-state";
    const REQUEST: &str = "AccountOnboardingCurrentStateRequest";
    const RESPONSE: &str = "AccountOnboardingCurrentStateResponse";

    let document = canonical_document();
    let schemas = component_schemas(&document);
    assert_strict_object_schema(schemas, REQUEST, &["version", "account_id", "alias"], &[]);

    assert_strict_object_schema(
        schemas,
        RESPONSE,
        &[
            "version",
            "network_id",
            "account_id",
            "alias",
            "account_exists",
            "alias_target_account_id",
            "observed_block_height",
            "observed_block_hash",
        ],
        &[],
    );
    for owner in [REQUEST, RESPONSE] {
        let version = component_properties(schemas, owner)
            .get("version")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{owner}.version schema"));
        assert_eq!(version.get("type").and_then(Value::as_str), Some("integer"));
        assert_eq!(version.get("const").and_then(Value::as_u64), Some(1));
    }
    assert_eq!(
        property_ref(schemas, RESPONSE, "network_id"),
        "#/components/schemas/NetworkId"
    );
    assert_eq!(
        property_ref(schemas, RESPONSE, "observed_block_hash"),
        "#/components/schemas/Hash"
    );
    let height = component_properties(schemas, RESPONSE)
        .get("observed_block_height")
        .and_then(Value::as_object)
        .expect("atomic onboarding observed height schema");
    assert_eq!(height.get("type").and_then(Value::as_str), Some("integer"));
    assert_eq!(height.get("format").and_then(Value::as_str), Some("uint64"));
    assert_eq!(height.get("minimum").and_then(Value::as_u64), Some(1));
    let alias_target = component_properties(schemas, RESPONSE)
        .get("alias_target_account_id")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("oneOf"))
        .and_then(Value::as_array)
        .expect("atomic onboarding alias target nullable union");
    assert_eq!(alias_target.len(), 2);
    assert_eq!(
        alias_target[0].get("type").and_then(Value::as_str),
        Some("string")
    );
    assert_eq!(
        alias_target[1].get("type").and_then(Value::as_str),
        Some("null")
    );

    let operation = openapi_operation(&document, PATH, "post");
    assert_eq!(
        operation_request_schema_ref(operation, PATH),
        "#/components/schemas/AccountOnboardingCurrentStateRequest"
    );
    assert_eq!(
        operation_response_schema_ref(operation, "200", PATH),
        "#/components/schemas/AccountOnboardingCurrentStateResponse"
    );
    assert_eq!(
        operation.get(TOOL_EFFECT_EXTENSION).and_then(Value::as_str),
        Some("read")
    );
    let parameters = operation
        .get("parameters")
        .and_then(Value::as_array)
        .expect("atomic onboarding auth headers");
    assert_eq!(parameters.len(), 5);
    let parameter_names = parameters
        .iter()
        .map(|parameter| {
            let parameter = parameter.as_object().expect("auth header parameter");
            assert_eq!(parameter.get("in").and_then(Value::as_str), Some("header"));
            assert_eq!(parameter.get("required"), Some(&Value::Bool(false)));
            parameter
                .get("name")
                .and_then(Value::as_str)
                .expect("auth header name")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        parameter_names,
        BTreeSet::from([
            "X-Iroha-Account",
            "X-Iroha-Nonce",
            "X-Iroha-Signature",
            "X-Iroha-Timestamp-Ms",
            "X-Iroha-Witness",
        ])
    );
    let responses = operation
        .get("responses")
        .and_then(Value::as_object)
        .expect("atomic onboarding responses");
    assert_eq!(
        responses
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "200", "400", "401", "403", "408", "409", "413", "415", "429", "500", "502", "503",
        ])
    );
    assert_eq!(
        documented_reject_codes(responses, "401"),
        vec!["alias_auth_required", "alias_auth_invalid"]
    );
    assert_eq!(
        documented_reject_codes(responses, "409"),
        vec!["alias.catalog.mapping_conflict", "route_conflict"]
    );
    let challenges = responses
        .get("401")
        .and_then(Value::as_object)
        .and_then(|response| response.get("headers"))
        .and_then(Value::as_object)
        .and_then(|headers| headers.get("WWW-Authenticate"))
        .and_then(Value::as_object)
        .and_then(|header| header.get("schema"))
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("enum"))
        .and_then(Value::as_array)
        .expect("atomic onboarding authentication challenges")
        .iter()
        .map(|challenge| challenge.as_str().expect("authentication challenge"))
        .collect::<Vec<_>>();
    assert_eq!(
        challenges,
        vec!["IrohaApiToken realm=\"torii\"", "Signature"]
    );
}
#[test]
fn connect_status_openapi_separates_session_and_operator_aggregate() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    assert_strict_object_schema(
        schemas,
        "ConnectSessionStatus",
        &[
            "sid",
            "app_attached",
            "wallet_attached",
            "approved",
            "buffered_frames",
            "buffered_bytes",
            "last_seq_app_to_wallet",
            "last_seq_wallet_to_app",
            "origin",
        ],
        &[],
    );
    assert_strict_object_schema(
        schemas,
        "ConnectPolicyStatus",
        &[
            "ws_max_sessions",
            "ws_per_ip_max_sessions",
            "ws_rate_per_ip_per_min",
            "session_ttl_ms",
            "frame_max_bytes",
            "session_buffer_max_bytes",
            "relay_enabled",
            "relay_strategy",
            "relay_effective_strategy",
            "relay_p2p_attached",
            "p2p_ttl_hops",
            "heartbeat_interval_ms",
            "heartbeat_miss_tolerance",
            "heartbeat_min_interval_ms",
        ],
        &[],
    );
    assert_strict_object_schema(
        schemas,
        "ConnectStatus",
        &[
            "enabled",
            "sessions_total",
            "sessions_active",
            "per_ip_sessions",
            "buffered_sessions",
            "total_buffer_bytes",
            "dedupe_size",
            "policy",
            "frames_in_total",
            "frames_out_total",
            "ciphertext_total",
            "dedupe_drops_total",
            "buffer_drops_total",
            "plaintext_control_drops_total",
            "monotonic_drops_total",
            "sequence_violation_closes_total",
            "role_direction_mismatch_total",
            "ping_miss_total",
            "p2p_rebroadcasts_total",
            "p2p_rebroadcast_skipped_total",
            "p2p_auth_failures_total",
            "p2p_ttl_drops_total",
            "p2p_unknown_session_drops_total",
            "p2p_session_claims_in_total",
            "p2p_session_claims_installed_total",
            "p2p_session_claim_conflicts_total",
            "p2p_role_consumed_total",
            "p2p_session_terminated_total",
        ],
        &[],
    );
    assert_eq!(
        property_ref(schemas, "ConnectStatus", "policy"),
        "#/components/schemas/ConnectPolicyStatus"
    );

    let session = openapi_operation(&document, "/v1/connect/status", "get");
    assert_eq!(
        operation_response_schema_ref(session, "200", "Connect session status"),
        "#/components/schemas/ConnectSessionStatus"
    );
    let session_parameters = session
        .get("parameters")
        .and_then(Value::as_array)
        .expect("Connect session status parameters");
    assert_eq!(session_parameters.len(), 2);
    for parameter in session_parameters {
        let parameter = parameter
            .as_object()
            .expect("Connect session status parameter");
        assert_eq!(parameter.get("required"), Some(&Value::Bool(true)));
    }
    assert_eq!(
        session_parameters
            .iter()
            .map(|parameter| parameter["name"].as_str().expect("parameter name"))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["Authorization", "sid"])
    );

    let aggregate = openapi_operation(&document, "/v1/connect/status/aggregate", "get");
    assert_eq!(
        operation_response_schema_ref(aggregate, "200", "Connect aggregate status"),
        "#/components/schemas/ConnectStatus"
    );
    assert_eq!(
        aggregate.get(TOOL_EFFECT_EXTENSION).and_then(Value::as_str),
        Some("operator")
    );
    let operator_headers = aggregate
        .get("parameters")
        .and_then(Value::as_array)
        .expect("Connect aggregate operator headers");
    assert_eq!(operator_headers.len(), 4);
    for parameter in operator_headers {
        let parameter = parameter
            .as_object()
            .expect("Connect aggregate operator header");
        assert_eq!(parameter.get("in").and_then(Value::as_str), Some("header"));
        assert_eq!(parameter.get("required"), Some(&Value::Bool(true)));
    }
    assert_eq!(
        operator_headers
            .iter()
            .map(|parameter| parameter["name"].as_str().expect("operator header name"))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "X-Iroha-Operator-Nonce",
            "X-Iroha-Operator-Public-Key",
            "X-Iroha-Operator-Signature",
            "X-Iroha-Operator-Timestamp-Ms",
        ])
    );
}
#[test]
fn retired_apartment_execution_history_is_absent() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    for retired in [
        "AgentRuntimeExecutionSummary",
        "AgentRuntimeWorkflowStepSummary",
    ] {
        assert!(
            !schemas.contains_key(retired),
            "retired schema {retired} must not remain in the first-release authority"
        );
    }
    let apartment_status = schemas
        .get("AgentApartmentStatusEntry")
        .and_then(Value::as_object)
        .expect("AgentApartmentStatusEntry schema");
    let properties = apartment_status
        .get("properties")
        .and_then(Value::as_object)
        .expect("AgentApartmentStatusEntry properties");
    assert!(!properties.contains_key("runtime_recent_runs"));
    assert!(
        apartment_status
            .get("required")
            .and_then(Value::as_array)
            .expect("AgentApartmentStatusEntry required fields")
            .iter()
            .all(|field| field.as_str() != Some("runtime_recent_runs"))
    );
}
#[test]
fn uploaded_private_model_runtime_openapi_surface_is_absent() {
    let document = generate_spec();
    let paths = document["paths"].as_object().expect("OpenAPI paths object");
    for retired_path in [
        "/v1/soracloud/model/upload/encryption-recipient",
        "/v1/soracloud/model/upload/private/execute",
        "/v1/soracloud/model/upload/private/receipts",
    ] {
        assert!(
            !paths.contains_key(retired_path),
            "retired uploaded private-model path `{retired_path}` must not be advertised"
        );
    }

    for retained_path in [
        "/v1/soracloud/model/upload/register",
        "/v1/soracloud/model/upload/status",
    ] {
        assert!(
            paths.contains_key(retained_path),
            "registry-only uploaded-model path `{retained_path}` must remain advertised"
        );
    }

    let schemas = component_schemas(&document);
    for retired_schema in [
        "UploadedModelEncryptionRecipientResponse",
        "PrivateUploadedModelExecuteRequest",
        "PrivateUploadedModelExecuteResponse",
        "PrivateUploadedModelQuantizedCpuModelDto",
        "PrivateUploadedModelReceiptListResponse",
        "SoraPrivateModelArtifactRefV1",
        "SoraPrivateUploadedModelExecutionReceiptV1",
        "SoraUploadedModelKeyEncapsulationV1",
        "SoraUploadedModelKeyWrapAeadV1",
        "SoraUploadedModelEncryptionRecipientV1",
        "SoraUploadedModelWrappedKeyV1",
        "SoraUploadedModelRuntimeFormatV1",
    ] {
        assert!(
            !schemas.contains_key(retired_schema),
            "retired uploaded private-model schema `{retired_schema}` must not be registered"
        );
    }
    for retained_schema in ["SoraUploadedModelBundleV1", "UploadedModelStatusResponse"] {
        assert!(
            schemas.contains_key(retained_schema),
            "registry-only uploaded-model schema `{retained_schema}` must remain registered"
        );
    }

    assert_strict_object_schema(
        schemas,
        "SoraHfSourceRecordV1",
        &[
            "schema_version",
            "source_id",
            "repo_id",
            "resolved_revision",
            "created_at_ms",
            "updated_at_ms",
        ],
        &[],
    );
    let hf_source_properties = schemas["SoraHfSourceRecordV1"]["properties"]
        .as_object()
        .expect("SoraHfSourceRecordV1 properties");
    for retired_field in [
        "model_name",
        "adapter_id",
        "normalized_runtime_hash",
        "resource_profile",
        "source_artifact_hash",
        "source_profile",
        "status",
        "last_error",
    ] {
        assert!(
            !hf_source_properties.contains_key(retired_field),
            "registry metadata must not revive retired field `{retired_field}`"
        );
    }
    for retired_schema in [
        "SoraHfBackendFamilyV1",
        "SoraHfModelFormatV1",
        "SoraHfModelSizeBucketV1",
        "SoraHfResourceProfileV1",
        "SoraHfSourceProfileV1",
        "SoraHfSourceStatusV1",
    ] {
        assert!(
            !schemas.contains_key(retired_schema),
            "derived runtime/tariff classification `{retired_schema}` must stay retired"
        );
    }
    let runtime_snapshot = schemas
        .get("SoracloudRuntimeSnapshot")
        .and_then(Value::as_object)
        .expect("SoracloudRuntimeSnapshot schema");
    assert!(
        !runtime_snapshot
            .get("properties")
            .and_then(Value::as_object)
            .is_some_and(|properties| properties.contains_key("hf_sources")),
        "generated Hugging Face imports are storage records, not runtime plans"
    );
    assert!(
        runtime_snapshot
            .get("required")
            .and_then(Value::as_array)
            .is_some_and(|required| required
                .iter()
                .all(|field| field.as_str() != Some("hf_sources"))),
        "SoracloudRuntimeSnapshot must not require a retired HF runtime field"
    );

    let soracloud_tag = document["tags"]
        .as_array()
        .expect("OpenAPI tags")
        .iter()
        .find(|tag| tag["name"].as_str() == Some("Soracloud"))
        .expect("Soracloud OpenAPI tag");
    assert_eq!(
        soracloud_tag["description"].as_str(),
        Some("Soracloud service, model registry, and Inrou runtime endpoints.")
    );
}
#[test]
fn soracloud_release_openapi_matches_the_exact_closed_catalog_surface() {
    use iroha_torii_shared::route_catalog::{AdmissionPolicy, AuthenticationPolicy, RouteEffect};

    fn method_name(method: CatalogHttpMethod) -> &'static str {
        match method {
            CatalogHttpMethod::Get => "get",
            CatalogHttpMethod::Post => "post",
            CatalogHttpMethod::Put => "put",
            CatalogHttpMethod::Patch => "patch",
            CatalogHttpMethod::Delete => "delete",
            CatalogHttpMethod::Any => {
                panic!("ANY gateways cannot enter the Soracloud OpenAPI surface")
            }
        }
    }
    fn assert_closed_exact_schema(value: &Value, location: &str) {
        match value {
            Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    assert_closed_exact_schema(value, &format!("{location}/{index}"));
                }
            }
            Value::Object(schema) => {
                assert!(
                    !schema.contains_key("default"),
                    "body schema {location} must not infer an omitted default"
                );
                if schema.get("additionalProperties") == Some(&Value::Bool(true)) {
                    assert_eq!(
                        location,
                        format!("{COMPONENT_SCHEMA_REF_PREFIX}JsonValue"),
                        "only the explicitly dynamic JSON value may remain open"
                    );
                }
                if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
                    assert_eq!(
                        schema.get("type").and_then(Value::as_str),
                        Some("object"),
                        "typed property inventory at {location} must be an object"
                    );
                    assert_eq!(
                        schema.get("additionalProperties"),
                        Some(&Value::Bool(false)),
                        "typed body object {location} must reject unknown fields"
                    );
                    let required = schema
                        .get("required")
                        .and_then(Value::as_array)
                        .unwrap_or_else(|| panic!("typed body object {location} required fields"))
                        .iter()
                        .map(|field| field.as_str().expect("required body field"))
                        .collect::<BTreeSet<_>>();
                    let declared = properties
                        .keys()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>();
                    assert_eq!(
                        required, declared,
                        "typed body object {location} must require every V1 field, including nullable fields"
                    );
                } else if schema.get("type").and_then(Value::as_str) == Some("object") {
                    let additional = schema.get("additionalProperties");
                    assert!(
                        location == format!("{COMPONENT_SCHEMA_REF_PREFIX}JsonValue")
                            || matches!(
                                additional,
                                Some(Value::Object(_)) | Some(Value::Bool(false))
                            ),
                        "map object {location} must type its values or be closed"
                    );
                }
                for (key, value) in schema {
                    assert_closed_exact_schema(value, &format!("{location}/{key}"));
                }
            }
            _ => {}
        }
    }

    let document = generate_spec();
    let schemas = component_schemas(&document);
    let routes = CATALOGED_ROUTES
        .iter()
        .filter(|route| {
            route.surface() == ApiSurface::Public && route.path().starts_with("/v1/soracloud/")
        })
        .collect::<Vec<_>>();
    assert_eq!(routes.len(), 51, "canonical Soracloud release inventory");

    let expected = routes
        .iter()
        .map(|route| {
            assert!(route.projections().openapi(), "{}", route.path());
            assert!(route.projections().sdk(), "{}", route.path());
            (
                route.path().replace("{*", "{"),
                method_name(route.method()).to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .expect("canonical OpenAPI paths");
    let actual = paths
        .iter()
        .filter(|(path, _)| path.starts_with("/v1/soracloud/"))
        .flat_map(|(path, item)| {
            let item = item.as_object().expect("Soracloud path item");
            ["get", "post", "put", "patch", "delete"]
                .into_iter()
                .filter_map(move |method| {
                    item.contains_key(method)
                        .then(|| (path.clone(), method.to_owned()))
                })
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(actual.len(), 51, "canonical Soracloud OpenAPI inventory");
    assert_eq!(
        actual, expected,
        "Soracloud OpenAPI/catalog method-path equality"
    );

    let exact_contracts = [
        ("/v1/soracloud/status", "get", None, "SoracloudStatusV1"),
        (
            "/v1/soracloud/services/{service_name}/public-discovery",
            "get",
            None,
            "ServicePublicDiscoveryResponse",
        ),
        (
            "/v1/soracloud/services/{service_name}/revisions/{service_version}/public-discovery",
            "get",
            None,
            "ServicePublicDiscoveryResponse",
        ),
        (
            "/v1/soracloud/deploy",
            "post",
            Some("SignedBundleRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/upgrade",
            "post",
            Some("SignedBundleRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/apps/deploy",
            "post",
            Some("SignedAppInfraRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/apps/upgrade",
            "post",
            Some("SignedAppInfraRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/apps/status",
            "get",
            None,
            "AppInfraStatusResponse",
        ),
        (
            "/v1/soracloud/apps/{app_name}/status",
            "get",
            None,
            "AppInfraStatusResponse",
        ),
        (
            "/v1/soracloud/rollback",
            "post",
            Some("SignedRollbackRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/rollout",
            "post",
            Some("SignedRolloutAdvanceRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/state/mutate",
            "post",
            Some("SignedStateMutationRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/service/config/set",
            "post",
            Some("SignedServiceConfigSetRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/service/config/delete",
            "post",
            Some("SignedServiceConfigDeleteRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/service/config/status",
            "get",
            None,
            "ServiceConfigStatusResponse",
        ),
        (
            "/v1/soracloud/service/secret/set",
            "post",
            Some("SignedServiceSecretSetRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/service/secret/delete",
            "post",
            Some("SignedServiceSecretDeleteRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/service/secret/status",
            "get",
            None,
            "ServiceSecretStatusResponse",
        ),
        (
            "/v1/soracloud/fhe/job/run",
            "post",
            Some("SignedFheJobRunRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/decrypt/request",
            "post",
            Some("SignedDecryptionRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/health/access/request",
            "post",
            Some("SignedDecryptionRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/health/compliance/report",
            "get",
            None,
            "HealthComplianceReportResponse",
        ),
        (
            "/v1/soracloud/ciphertext/query",
            "post",
            Some("SignedCiphertextQueryRequest"),
            "CiphertextQueryResponse",
        ),
        (
            "/v1/soracloud/training/job/start",
            "post",
            Some("SignedTrainingJobStartRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/training/job/checkpoint",
            "post",
            Some("SignedTrainingJobCheckpointRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/training/job/retry",
            "post",
            Some("SignedTrainingJobRetryRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/training/job/status",
            "get",
            None,
            "TrainingJobStatusResponse",
        ),
        (
            "/v1/soracloud/model/weight/register",
            "post",
            Some("SignedModelWeightRegisterRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/model/weight/promote",
            "post",
            Some("SignedModelWeightPromoteRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/model/weight/rollback",
            "post",
            Some("SignedModelWeightRollbackRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/model/weight/status",
            "get",
            None,
            "ModelWeightStatusResponse",
        ),
        (
            "/v1/soracloud/model/artifact/register",
            "post",
            Some("SignedModelArtifactRegisterRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/model/artifact/status",
            "get",
            None,
            "ModelArtifactStatusResponse",
        ),
        (
            "/v1/soracloud/model/upload/register",
            "post",
            Some("SignedUploadedModelRegisterRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/model/upload/status",
            "get",
            None,
            "UploadedModelStatusResponse",
        ),
        (
            "/v1/soracloud/hf/lease/join",
            "post",
            Some("SignedHfSharedLeaseJoinRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/hf/lease/status",
            "get",
            None,
            "HfSharedLeaseStatusResponse",
        ),
        (
            "/v1/soracloud/hf/lease/leave",
            "post",
            Some("SignedHfLeaseLeaveRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/hf/lease/renew",
            "post",
            Some("SignedHfLeaseRenewRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/agent/deploy",
            "post",
            Some("SignedAgentDeployRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/agent/lease/renew",
            "post",
            Some("SignedAgentLeaseRenewRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/agent/restart",
            "post",
            Some("SignedAgentRestartRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/agent/status",
            "get",
            None,
            "AgentStatusResponse",
        ),
        (
            "/v1/soracloud/agent/wallet/spend",
            "post",
            Some("SignedAgentWalletSpendRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/agent/wallet/approve",
            "post",
            Some("SignedAgentWalletApproveRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/agent/policy/revoke",
            "post",
            Some("SignedAgentPolicyRevokeRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/agent/message/send",
            "post",
            Some("SignedAgentMessageSendRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/agent/message/ack",
            "post",
            Some("SignedAgentMessageAckRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/agent/mailbox/status",
            "get",
            None,
            "AgentMailboxStatusResponse",
        ),
        (
            "/v1/soracloud/agent/autonomy/allow",
            "post",
            Some("SignedAgentArtifactAllowRequest"),
            "SoracloudMutationDraftResponse",
        ),
        (
            "/v1/soracloud/agent/autonomy/status",
            "get",
            None,
            "AgentAutonomyStatusResponse",
        ),
    ];
    assert_eq!(exact_contracts.len(), 51);
    assert_eq!(
        exact_contracts
            .iter()
            .map(|(path, method, _, _)| ((*path).to_owned(), (*method).to_owned()))
            .collect::<BTreeSet<_>>(),
        actual,
        "every canonical Soracloud operation must have one explicit schema contract"
    );
    for (path, method, request, response) in exact_contracts {
        let operation = openapi_operation(&document, path, method);
        if let Some(request) = request {
            assert_eq!(
                operation_request_schema_ref(operation, path),
                format!("{COMPONENT_SCHEMA_REF_PREFIX}{request}"),
                "{method} {path} request root"
            );
        } else {
            assert!(
                operation.get("requestBody").is_none(),
                "{method} {path} must not infer a request body"
            );
        }
        assert_eq!(
            operation_response_schema_ref(operation, "200", path),
            format!("{COMPONENT_SCHEMA_REF_PREFIX}{response}"),
            "{method} {path} response root"
        );
    }

    let mut roots = BTreeSet::new();
    for route in routes {
        let path = route.path().replace("{*", "{");
        let method = method_name(route.method());
        let operation = openapi_operation(&document, &path, method);
        let expected_effect = if route.effect() == RouteEffect::ReadOnly {
            "read"
        } else {
            "write"
        };
        assert_eq!(
            operation.get(TOOL_EFFECT_EXTENSION).and_then(Value::as_str),
            Some(expected_effect),
            "{method} {path} effect"
        );
        let expected_headers = match (route.authentication(), route.admission()) {
            (
                AuthenticationPolicy::CanonicalAccountSignature,
                AdmissionPolicy::AuthenticatedAccount,
            ) => canonical_account_header_requirements(false),
            (AuthenticationPolicy::ToriiDefault, AdmissionPolicy::Public) => Vec::new(),
            pair => panic!("unexpected Soracloud authentication/admission {pair:?} at {path}"),
        };
        let headers = operation_header_requirements(operation);
        assert_eq!(headers, expected_headers, "{method} {path} auth headers");
        assert!(
            headers
                .iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("x-iroha-internal-soracloud-account")),
            "{method} {path} exposes the internal local-read account header"
        );

        let response = operation_response_schema_ref(operation, "200", &path);
        let response_root = response
            .strip_prefix(COMPONENT_SCHEMA_REF_PREFIX)
            .unwrap_or_else(|| panic!("{method} {path} response must use a component schema"));
        assert_ne!(
            response_root, "JsonValue",
            "{method} {path} untyped response"
        );
        roots.insert(response_root.to_owned());
        if route.method() == CatalogHttpMethod::Post {
            let request = operation_request_schema_ref(operation, &path);
            let request_root = request
                .strip_prefix(COMPONENT_SCHEMA_REF_PREFIX)
                .unwrap_or_else(|| panic!("POST {path} request must use a component schema"));
            assert_ne!(request_root, "JsonValue", "POST {path} untyped request");
            roots.insert(request_root.to_owned());
        } else {
            assert!(
                operation.get("requestBody").is_none(),
                "GET {path} must not infer a request body"
            );
        }
    }

    let mut pending = roots.into_iter().collect::<VecDeque<_>>();
    let mut reachable = BTreeSet::new();
    let mut dynamic_json_parents = BTreeSet::new();
    while let Some(name) = pending.pop_front() {
        if !reachable.insert(name.clone()) {
            continue;
        }
        let schema = schemas
            .get(&name)
            .unwrap_or_else(|| panic!("Soracloud component reference does not resolve: {name}"));
        assert_closed_exact_schema(schema, &format!("{COMPONENT_SCHEMA_REF_PREFIX}{name}"));
        let mut references = BTreeSet::new();
        collect_component_refs(schema, &mut references);
        if references.contains("JsonValue") {
            dynamic_json_parents.insert(name.clone());
        }
        pending.extend(references);
    }
    assert_eq!(
        dynamic_json_parents,
        BTreeSet::from([
            "ServiceConfigSetRequest".to_owned(),
            "ServiceConfigStatusEntry".to_owned(),
            "SignedBundleRequest".to_owned(),
            "SoraServiceConfigEntryV1".to_owned(),
        ]),
        "only explicitly dynamic configuration JSON fields may use JsonValue"
    );
    assert!(reachable.contains("JsonValue"));

    assert_strict_object_schema(
        schemas,
        "SoracloudLocalReadBinding",
        &[
            "binding_name",
            "state_key",
            "payload_commitment",
            "artifact_hash",
        ],
        &[],
    );
    let serialized = norito::json::to_string(&document).expect("serialize Soracloud authority");
    for retired in [
        "cap-bound-local-signing",
        "SoracloudHfSharedLeaseJoinDraftV1",
        "PrivateUploadedModelArtifactRef\"",
        "PrivateUploadedModelQuantizedCpuModel\"",
        "PrivateUploadedModelReceipt\"",
        "SoracloudTxInstr\"",
        "x-iroha-internal-soracloud-account",
    ] {
        assert!(
            !serialized.contains(retired),
            "retired or internal Soracloud compatibility surface remains: {retired}"
        );
    }
}
#[test]
fn pipeline_preflight_schema_exposes_only_per_scheme_signature_batch_caps() {
    let document = generate_spec();
    let schemas = component_schemas(&document);
    let pipeline = component_properties(schemas, "PipelinePreflightResponse")
        .get("pipeline")
        .and_then(Value::as_object)
        .expect("PipelinePreflightResponse.pipeline schema");
    let properties = pipeline
        .get("properties")
        .and_then(Value::as_object)
        .expect("PipelinePreflightResponse.pipeline properties");
    let required = pipeline
        .get("required")
        .and_then(Value::as_array)
        .expect("PipelinePreflightResponse.pipeline required fields");

    assert!(properties.get("signature_batch_max").is_none());
    assert!(
        !required
            .iter()
            .any(|field| field.as_str() == Some("signature_batch_max"))
    );
    for field in [
        "signature_batch_max_ed25519",
        "signature_batch_max_secp256k1",
        "signature_batch_max_pqc",
        "signature_batch_max_bls",
    ] {
        assert!(
            properties.get(field).is_some(),
            "missing schema for {field}"
        );
        assert!(
            required
                .iter()
                .any(|required_field| required_field.as_str() == Some(field)),
            "{field} must be required"
        );
    }
}
#[test]
fn checked_openapi_assets_match_package_authority() {
    let latest = include_str!("../../../../artifacts/openapi/torii.json");
    let current = include_str!("../../../../artifacts/openapi/versions/current/torii.json");
    let package = CANONICAL_OPENAPI_JSON;
    assert_eq!(
        latest.as_bytes(),
        current.as_bytes(),
        "latest/current artifact drift"
    );
    assert_eq!(
        latest.as_bytes(),
        package.as_bytes(),
        "release/package authority drift"
    );
}
#[test]
fn public_lane_reward_claim_schema_requires_exact_fee_consent() {
    use iroha_data_model::{
        asset::AssetId,
        nexus::{
            PublicLaneFeeRewardClaimV1, PublicLaneMonetaryScopeV1, PublicLaneRewardClaimPlanV1,
        },
        parameter::system::SumeragiNposParameters,
    };
    use iroha_test_samples::{ALICE_ID, BOB_ID};

    let schemas = openapi_schemas();
    let plan_fields = ["network_scope", "valid_until_height", "fee_claim"];
    let claim_fields = [
        "lifecycle_seal",
        "beneficiary_id",
        "beneficiary_revision",
        "source_asset",
        "destination_asset",
        "amount",
        "expected_claim_sequence",
    ];
    assert_strict_object_schema(&schemas, "PublicLaneRewardClaimPlanV1", &plan_fields, &[]);
    assert_strict_object_schema(&schemas, "PublicLaneFeeRewardClaimV1", &claim_fields, &[]);
    assert_eq!(
        schemas["PublicLaneRewardClaimPlanV1"]["properties"]["fee_claim"],
        norito::json!({"$ref": "#/components/schemas/PublicLaneFeeRewardClaimV1"})
    );
    assert_eq!(
        schemas["PublicLaneFeeRewardClaimV1"]["properties"]["lifecycle_seal"],
        norito::json!({
            "type": "string", "minLength": 64, "maxLength": 64,
            "pattern": "^[0-9A-Fa-f]{64}$"
        })
    );
    let xor = SumeragiNposParameters::default().xor_asset_definition_id;
    let claim = PublicLaneFeeRewardClaimV1 {
        lifecycle_seal: [0xA5; 32],
        beneficiary_id: ALICE_ID.clone(),
        beneficiary_revision: u64::MAX,
        source_asset: AssetId::new(xor.clone(), BOB_ID.clone()),
        destination_asset: AssetId::new(xor, ALICE_ID.clone()),
        amount: "0.000000001".parse().unwrap(),
        expected_claim_sequence: u64::MAX,
    };
    assert!(claim.has_canonical_shape(&ALICE_ID));
    {
        let fee_claim = claim;
        let plan = PublicLaneRewardClaimPlanV1 {
            network_scope: PublicLaneMonetaryScopeV1::Genesis,
            valid_until_height: 1,
            fee_claim,
        };
        let encoded = norito::json::to_value(&plan).unwrap();
        assert_eq!(
            encoded
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(plan_fields)
        );
        {
            assert_eq!(
                encoded["fee_claim"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from(claim_fields)
            );
            assert_eq!(
                encoded["fee_claim"]["lifecycle_seal"],
                Value::String("A5".repeat(32))
            );
        }
        assert_eq!(
            norito::json::from_value::<PublicLaneRewardClaimPlanV1>(encoded.clone()).unwrap(),
            plan
        );
        let mut omitted = encoded;
        omitted.as_object_mut().unwrap().remove("fee_claim");
        assert!(norito::json::from_value::<PublicLaneRewardClaimPlanV1>(omitted).is_err());
    }
}

#[test]
fn public_lane_staking_schema_closes_status_variants_and_unbond_cutoff() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    let status = schemas["PublicLaneValidatorStatus"]
        .as_object()
        .expect("public-lane validator status schema");
    assert_eq!(
        status
            .get("discriminator")
            .and_then(Value::as_object)
            .and_then(|value| value.get("propertyName"))
            .and_then(Value::as_str),
        Some("type")
    );
    let variants = status
        .get("oneOf")
        .and_then(Value::as_array)
        .expect("closed public-lane validator status variants");
    let expected = BTreeMap::from([
        ("Active", BTreeSet::from(["type"])),
        ("Exited", BTreeSet::from(["type"])),
        ("Exiting", BTreeSet::from(["releases_at_ms", "type"])),
        (
            "PendingActivation",
            BTreeSet::from(["activates_at_height", "type"]),
        ),
        ("Slashed", BTreeSet::from(["slash_id", "type"])),
    ]);
    let mut observed = BTreeMap::new();
    for variant in variants {
        let variant = variant.as_object().expect("status variant object");
        assert_eq!(variant.get("type").and_then(Value::as_str), Some("object"));
        assert_eq!(
            variant.get("additionalProperties").and_then(Value::as_bool),
            Some(false)
        );
        let properties = variant
            .get("properties")
            .and_then(Value::as_object)
            .expect("status variant properties");
        let tag = properties["type"]
            .get("const")
            .and_then(Value::as_str)
            .expect("status variant discriminator constant");
        let property_names = properties
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let required = variant
            .get("required")
            .and_then(Value::as_array)
            .expect("status variant required fields")
            .iter()
            .map(|field| field.as_str().expect("required field name"))
            .collect::<BTreeSet<_>>();
        assert_eq!(required, property_names, "{tag} payload must be exact");
        assert!(observed.insert(tag, property_names).is_none());
    }
    assert_eq!(observed, expected);

    for name in [
        "PublicLaneValidatorRecord",
        "PublicLaneManifestValidatorRecord",
    ] {
        let validator = schemas[name]
            .as_object()
            .expect("validator projection schema");
        let fields = validator["properties"].as_object().unwrap();
        assert!(
            fields.contains_key("election_exit_height"),
            "{name} must distinguish election eligibility"
        );
        assert!(
            validator["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field.as_str() == Some("election_exit_height"))
        );
    }

    let unbonding = schemas["PublicLaneUnbonding"]
        .as_object()
        .expect("public-lane unbonding schema");
    let properties = unbonding["properties"]
        .as_object()
        .expect("public-lane unbonding properties");
    assert!(properties.contains_key("slashable_through_height"));
    assert!(!properties.contains_key("scheduled_at_height"));
    assert!(
        unbonding["required"]
            .as_array()
            .expect("public-lane unbonding required fields")
            .iter()
            .any(|field| field.as_str() == Some("slashable_through_height"))
    );
}
#[cfg(all(
    feature = "node-api",
    feature = "ws_integration_tests",
    feature = "telemetry",
    feature = "profiling",
    feature = "schema",
    feature = "zk-verify-batch"
))]
#[test]
fn compiled_projection_matches_served_bytes() {
    let generated = norito::json::to_string_pretty(&generate_spec())
        .expect("serialize compiled release Torii OpenAPI");
    let served = compiled_spec_json();
    assert_eq!(
        generated.as_bytes(),
        served.as_bytes(),
        "compiled/served document drift"
    );
}
#[test]
fn transaction_payload_schema_requires_closed_domain_and_positive_ttl() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    assert_strict_object_schema(
        schemas,
        "TransactionPayload",
        &openapi_contract_strings("openapi.transaction_payload.required").collect::<Vec<_>>(),
        &["nonce"],
    );
    let properties = schemas["TransactionPayload"]["properties"]
        .as_object()
        .expect("TransactionPayload properties");
    for retired in ["chain", "chain_id", "chainId"] {
        assert!(
            !properties.contains_key(retired),
            "retired transaction identity key `{retired}` must be absent"
        );
    }
    assert_eq!(
        properties["domain"].get("$ref").and_then(Value::as_str),
        Some("#/components/schemas/TransactionDomain")
    );
    assert!(
        !properties.contains_key("admission_intent"),
        "retired admission intent is not part of first-release transactions"
    );
    assert_eq!(
        properties["time_to_live_ms"]
            .get("minimum")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        schemas["NetworkId"]["allOf"][0]
            .get("$ref")
            .and_then(Value::as_str),
        Some("#/components/schemas/Hash")
    );
    let variants = schemas["TransactionDomain"]["oneOf"]
        .as_array()
        .expect("TransactionDomain variants");
    assert_eq!(variants.len(), 2);
    for variant in variants {
        assert_eq!(
            variant.get("additionalProperties").and_then(Value::as_bool),
            Some(false)
        );
    }
    assert_eq!(
        variants[0]["properties"]["kind"]
            .get("const")
            .and_then(Value::as_str),
        Some("network")
    );
    assert_eq!(
        variants[0]["properties"]["value"]
            .get("$ref")
            .and_then(Value::as_str),
        Some("#/components/schemas/NetworkId")
    );
    assert_eq!(
        variants[1]["properties"]["kind"]
            .get("const")
            .and_then(Value::as_str),
        Some("genesis")
    );
    assert!(variants[1]["properties"].get("value").is_none());

    assert!(!schemas.contains_key("TransactionAdmissionIntent"));
}
#[test]
fn authenticated_transaction_nullable_fields_are_required_and_nullable() {
    let document = canonical_document();
    let schemas = component_schemas(&document);

    let payload = &schemas["TransactionPayload"];
    assert!(
        payload["required"]
            .as_array()
            .expect("TransactionPayload required fields")
            .iter()
            .any(|field| field.as_str() == Some("attachments"))
    );
    assert_eq!(
        payload["properties"]["attachments"]["type"],
        norito::json!(["string", "null"])
    );

    for variant in schemas["FeePaymentIntent"]["oneOf"]
        .as_array()
        .expect("fee-payment variants")
    {
        let value = &variant["properties"]["value"];
        assert_eq!(
            value.get("additionalProperties").and_then(Value::as_bool),
            Some(false)
        );
        assert!(
            value["required"]
                .as_array()
                .expect("fee-payment required fields")
                .iter()
                .any(|field| field.as_str() == Some("gas_limit"))
        );
        assert_eq!(
            value["properties"]["gas_limit"]["type"],
            norito::json!(["integer", "null"])
        );
    }

    let receipt_payload = &schemas["TransactionSubmissionReceipt"]["properties"]["payload"];
    assert_eq!(
        receipt_payload
            .get("additionalProperties")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert!(
        receipt_payload["required"]
            .as_array()
            .expect("receipt-payload required fields")
            .iter()
            .any(|field| field.as_str() == Some("signed_transaction_hash"))
    );
    assert_eq!(
        receipt_payload["properties"]["signed_transaction_hash"]["type"],
        norito::json!(["string", "null"])
    );
}
#[test]
fn incoming_static_openapi_contracts_remain_bound_to_runtime_routes() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    for [name, network_property, retired_property, target] in openapi_contract_fixed_rows::<4>(
        "openapi.incoming_static_openapi_contracts_remain_bound_to_runtime_routes.rows.1",
    ) {
        let properties = schemas[name]["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{name} properties"));
        assert!(!properties.contains_key(retired_property), "{name}");
        assert_eq!(
            property_ref(schemas, name, network_property),
            format!("{COMPONENT_SCHEMA_REF_PREFIX}{target}"),
            "{name}.{network_property} reference drift"
        );
    }
    assert!(!schemas.contains_key("KagemushaUnshieldPublicInputs"));
    assert!(document["paths"].get("/v1/kagemusha/unshield").is_none());
    for (path, schema) in [
        ("/v1/games/capabilities", "GameCapabilitiesV1"),
        ("/v1/games/sessions", "GameSessionListResponseV1"),
        ("/v1/games/sessions/{session_id}", "GameSessionRecordV1"),
        ("/v1/nft-offers/capabilities", "NftOfferCapabilitiesV1"),
        ("/v1/nft-offers", "NftOfferListResponseV1"),
        ("/v1/nft-offers/{offer_id}", "NftSaleRecordV1"),
        (
            "/v1/assets/definitions/{asset}/registration",
            "OfflineAssetRegistrationV1",
        ),
    ] {
        assert_eq!(
            document["paths"][path]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
                ["$ref"],
            Value::from(format!("{COMPONENT_SCHEMA_REF_PREFIX}{schema}")),
            "{path} response type"
        );
        assert!(
            schemas.contains_key(schema),
            "missing response schema {schema}"
        );
    }
    assert_strict_object_schema(
        schemas,
        "OfflineAssetRegistrationV1",
        &[
            "version",
            "network_id",
            "asset_definition_id",
            "asset_incarnation_hex",
            "scale",
            "committed_height",
            "committed_block_hash_hex",
            "committed_at_ms",
        ],
        &[],
    );
    for name in openapi_contract_strings(
        "openapi.incoming_static_openapi_contracts_remain_bound_to_runtime_routes.strings.1",
    ) {
        assert!(schemas.contains_key(name), "missing static schema {name}");
    }
    assert!(!schemas.contains_key("PrivacyCapabilityRowV1"));
    assert!(!schemas.contains_key("PrivacyCapabilitySnapshotV1"));
    let protocols = schemas["PrivacyExact12CapabilityManifestV1"]["properties"]["protocols"]
        .as_object()
        .expect("Exact12 protocols schema");
    assert_eq!(protocols["minItems"].as_u64(), Some(12));
    assert_eq!(protocols["maxItems"].as_u64(), Some(12));
    assert_eq!(
        protocols["prefixItems"]
            .as_array()
            .expect("Exact12 positional schemas")
            .len(),
        12
    );
    assert_eq!(protocols["items"].as_bool(), Some(false));
    let row_properties = schemas["PrivacyExact12CapabilityRowV1"]["properties"]
        .as_object()
        .expect("Exact12 row properties");
    assert_eq!(
        row_properties
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "activation",
            "compiled_profile",
            "execution_mode",
            "operation_schema",
            "privacy_feature_mask",
            "protocol_id",
            "readiness",
        ])
    );
    let readiness_variants = schemas["PrivacyCapabilityReadinessV1"]["oneOf"]
        .as_array()
        .expect("Exact12 readiness variants");
    assert_eq!(
        readiness_variants
            .iter()
            .map(|variant| {
                variant["properties"]["readiness"]["const"]
                    .as_str()
                    .expect("Exact12 readiness tag")
            })
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["production-qualified", "unavailable"])
    );
    let activation_properties = schemas["PrivacyProtocolActivationRecordV1"]["properties"]
        .as_object()
        .expect("privacy activation properties");
    assert!(!activation_properties.contains_key("production_qualification"));
    assert!(!activation_properties.contains_key("assurance"));
    for retired in [
        "PrivacyAssuranceV1",
        "PrivacyCapabilityActivationStateV1",
        "PrivacyCapabilityLimitationV1",
    ] {
        assert!(
            !schemas.contains_key(retired),
            "retired pre-release privacy schema remains: {retired}"
        );
    }
    let unavailable_variants = schemas["PrivacyCapabilityUnavailableReasonV1"]["oneOf"]
        .as_array()
        .expect("Exact12 unavailable-reason variants");
    assert_eq!(
        unavailable_variants
            .iter()
            .map(|variant| {
                variant["properties"]["reason"]["const"]
                    .as_str()
                    .expect("Exact12 unavailable-reason tag")
            })
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "compiled-profile",
            "invalid-production-qualification",
            "missing-production-qualification",
            "not-registered",
            "proposed",
            "retired",
            "suspended",
        ])
    );
    let qualification = schemas["PrivacyExact12QualificationRecordV1"]["properties"]
        .as_object()
        .expect("production qualification properties");
    assert_eq!(
        qualification
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["deployment_qualification", "release_manifest",])
    );
    let manifest_properties = schemas["PrivacyExact12CapabilityManifestV1"]["properties"]
        .as_object()
        .expect("Exact12 manifest properties");
    assert!(manifest_properties.contains_key("qualification"));
    assert!(!schemas.contains_key("PrivacyProtocolProductionQualificationV1"));
    let security_claim = schemas["PrivacySecurityClaimV1"]["properties"]
        .as_object()
        .expect("security claim properties");
    assert_eq!(
        security_claim
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "achieved_security_bits",
            "audit_bundle_digest",
            "catalog_commitment",
            "parameter_digest",
            "protocol_id",
            "reduction_digest",
            "security_model",
            "target_security_bits",
            "verifier_digest",
        ])
    );
    assert_eq!(
        schemas["PrivacySecurityModelV1"]["properties"]["security_model"]["enum"]
            .as_array()
            .expect("closed privacy security models")
            .iter()
            .map(|value| value.as_str().expect("security-model label"))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["classical-rom", "pq-qrom"])
    );
    let catalog_commitment = schemas["PrivacyExact12CatalogCommitmentV1"]["const"]
        .as_array()
        .expect("pinned Exact12 catalog commitment")
        .iter()
        .map(|byte| {
            u8::try_from(byte.as_u64().expect("catalog commitment byte"))
                .expect("catalog commitment byte fits u8")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        catalog_commitment,
        iroha_data_model::privacy::PrivacyExact12CatalogCommitmentV1::canonical()
            .digest()
            .to_le_bytes()
    );
    let details = openapi_operation(&document, "/v1/pipeline/transactions/details", "post");
    assert_eq!(
        operation_request_schema_ref(details, "transaction details"),
        "#/components/schemas/VersionedSignedQueryJson"
    );
    assert_eq!(
        operation_response_schema_ref(details, "200", "transaction details"),
        "#/components/schemas/PipelineTransactionDetailsResponse"
    );
    assert_eq!(
        details.get(TOOL_EFFECT_EXTENSION).and_then(Value::as_str),
        Some("read")
    );
    let connect = openapi_operation(&document, "/v1/connect/session", "post");
    assert_eq!(
        operation_request_schema_ref(connect, "Connect session"),
        "#/components/schemas/ConnectSessionCreateRequest"
    );
    assert_eq!(
        operation_response_schema_ref(connect, "200", "Connect session"),
        "#/components/schemas/ConnectSessionCreateResponse"
    );
    for [path, request_schema] in openapi_contract_fixed_rows::<2>(
        "openapi.incoming_static_openapi_contracts_remain_bound_to_runtime_routes.rows.2",
    ) {
        let operation = openapi_operation(&document, path, "post");
        assert_eq!(
            operation_request_schema_ref(operation, path),
            format!("{COMPONENT_SCHEMA_REF_PREFIX}{request_schema}")
        );
        assert!(operation.contains_key("security"), "POST {path}");
        assert!(
            operation_header_requirements(operation)
                .iter()
                .any(|(name, _)| name == "X-Iroha-Account"),
            "POST {path} must publish account authentication"
        );
    }
    let pin = openapi_operation(&document, "/v1/sorafs/pin", "get");
    let pin_parameters = pin["parameters"]
        .as_array()
        .expect("pin list parameters")
        .iter()
        .filter_map(|parameter| parameter.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert_eq!(
        pin_parameters,
        [
            "expected_finalized_height",
            "expected_finalized_block_hash_hex",
            "limit",
            "max_bytes",
            "after_digest_hex",
            "status",
        ]
    );
    assert_eq!(
        operation_response_schema_ref(pin, "200", "pin list"),
        "#/components/schemas/PinManifestPageV1"
    );
    let axt_properties = schemas["AxtErrorDetails"]["properties"]
        .as_object()
        .expect("AXT error details properties");
    assert!(axt_properties.contains_key("active_handle_era"));
    assert!(axt_properties.contains_key("next_handle_counter"));
    assert!(!axt_properties.contains_key("next_min_handle_era"));
    assert!(!axt_properties.contains_key("next_min_sub_nonce"));
    let error_details_properties = schemas["ErrorDetails"]["properties"]
        .as_object()
        .expect("error details properties");
    assert!(error_details_properties.contains_key("entrypoint_hash"));
    assert!(error_details_properties.contains_key("tx_hash"));
}
#[test]
fn static_account_operations_publish_exact_auth_and_private_responses() {
    let document = canonical_document();
    assert!(document["paths"].get("/v1/gov/council/current").is_none());
    let public = openapi_operation(&document, "/v1/node/capabilities", "get");
    assert_eq!(
        public["security"],
        norito::json!([{}, {"IrohaApiToken": []}])
    );
    assert!(operation_header_requirements(public).is_empty());
    assert!(!public.contains_key("x-iroha-canonical-auth-v1"));
    assert!(
        document["paths"]
            .get("/v1/validation-fee/proposals/{proposal_id}/plain-ballot/draft")
            .is_none()
    );
    for (path, methods) in openapi_contract_rows(
        "openapi.static_account_operations_publish_exact_auth_and_private_responses.method_rows",
    )
    .iter()
    .map(|row| {
        let (path, methods) = row.split_first().expect("account operation contract row");
        (path.as_str(), methods.iter().map(String::as_str))
    }) {
        for method in methods {
            let operation = openapi_operation(&document, path, method);
            assert!(operation.contains_key("security"), "{method} {path}");
            assert!(
                operation.contains_key("x-iroha-canonical-auth-v1"),
                "{method} {path}"
            );
            let header_names = operation_header_requirements(operation)
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>();
            for name in openapi_contract_strings(
                "openapi.static_account_operations_publish_exact_auth_and_private_responses.strings.1",
            ) {
                assert_eq!(
                    header_names
                        .iter()
                        .filter(|actual| actual.as_str() == name)
                        .count(),
                    1,
                    "{method} {path} must publish one {name} header"
                );
            }
            assert!(
                operation["responses"]
                    .as_object()
                    .expect("operation responses")
                    .values()
                    .all(|response| {
                        response["headers"]["Cache-Control"]["schema"]["const"].as_str()
                            == Some("private, no-store")
                    }),
                "{method} {path} must publish private no-store responses"
            );
        }
    }
    for [path, method] in openapi_contract_fixed_rows::<2>(
        "openapi.static_account_operations_publish_exact_auth_and_private_responses.rows.1",
    ) {
        let operation = openapi_operation(&document, path, method);
        assert!(
            !operation_header_requirements(operation)
                .iter()
                .any(|(name, _)| name == "X-Iroha-Account"),
            "{method} {path} must retain its non-account admission contract"
        );
    }
}
#[test]
fn compiled_private_cache_contract_follows_the_route_catalog() {
    let document = generate_spec();
    for route in RouteCatalog::new(CATALOGED_ROUTES)
        .project(
            CatalogProjection::OpenApi,
            crate::router::builder::compiled_route_features(),
        )
        .into_iter()
        .filter(|route| {
            route.requires_private_no_store() && route.method() != CatalogHttpMethod::Any
        })
    {
        let path = route.path().replace("{*", "{");
        let method = catalog_method_name(route.method());
        let operation = openapi_operation(&document, &path, method);
        let responses = operation
            .get("responses")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{method} {path} responses"));
        assert!(!responses.is_empty(), "{method} {path} responses");
        for (status, response) in responses {
            assert_eq!(
                response["headers"]["Cache-Control"]["schema"]["const"].as_str(),
                Some("private, no-store"),
                "{method} {path} response {status} must follow authentication {:?}",
                route.authentication(),
            );
        }
    }
}
#[test]
fn operator_credential_management_contract_is_closed_and_two_factor() {
    const INVENTORY_PATH: &str = "/v1/operator/auth/credentials";
    const DELETE_PATH: &str = "/v1/operator/auth/credentials/{credential_id}";
    let document = generate_spec();
    let schemas = component_schemas(&document);
    let inventory = openapi_operation(&document, INVENTORY_PATH, "get");
    let deletion = openapi_operation(&document, DELETE_PATH, "delete");

    for (operation, stable_route_id) in [
        (inventory, "operator.authentication.credentials"),
        (deletion, "operator.authentication.credential_delete"),
    ] {
        assert_eq!(
            operation_header_requirements(operation),
            [
                "X-Iroha-Operator-Public-Key",
                "X-Iroha-Operator-Timestamp-Ms",
                "X-Iroha-Operator-Nonce",
                "X-Iroha-Operator-Signature",
                "X-Iroha-Operator-Session",
            ]
            .into_iter()
            .map(|name| (name.to_owned(), true))
            .collect::<Vec<_>>()
        );
        let session_parameter = operation["parameters"]
            .as_array()
            .expect("credential-management parameters")
            .iter()
            .find(|parameter| {
                parameter.get("name").and_then(Value::as_str) == Some("X-Iroha-Operator-Session")
            })
            .expect("operator session header parameter");
        assert_eq!(session_parameter["schema"]["minLength"].as_u64(), Some(43));
        assert_eq!(session_parameter["schema"]["maxLength"].as_u64(), Some(43));
        assert_eq!(
            session_parameter["schema"]["pattern"].as_str(),
            Some("^[A-Za-z0-9_-]{43}$")
        );
        let security = operation
            .get("security")
            .and_then(Value::as_array)
            .expect("operator credential-management security requirements");
        assert_eq!(security.len(), 1);
        let signature_headers = security[0]
            .as_object()
            .expect("conjunctive operator-signature requirement")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            signature_headers,
            [
                "IrohaOperatorNonce",
                "IrohaOperatorPublicKey",
                "IrohaOperatorSignature",
                "IrohaOperatorTimestampMs",
            ]
            .into_iter()
            .collect()
        );
        let route_auth = operation
            .get(ROUTE_AUTH_EXTENSION)
            .and_then(Value::as_object)
            .expect("catalog route-auth metadata");
        assert_eq!(
            route_auth.get("stableRouteId").and_then(Value::as_str),
            Some(stable_route_id)
        );
        assert_eq!(
            route_auth.get("authentication").and_then(Value::as_str),
            Some("operator_signature")
        );
        assert!(
            operation["responses"]
                .as_object()
                .expect("credential-management responses")
                .values()
                .all(|response| {
                    response["headers"]["Cache-Control"]["schema"]["const"].as_str()
                        == Some("private, no-store")
                })
        );
    }

    assert_eq!(
        inventory["responses"]
            .as_object()
            .expect("credential inventory responses")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        ["200", "401", "403", "429", "500"].into_iter().collect()
    );
    assert_eq!(
        operation_response_schema_ref(inventory, "200", INVENTORY_PATH),
        "#/components/schemas/OperatorWebAuthnCredentialListResponse"
    );
    assert!(
        inventory["responses"]["500"]["description"]
            .as_str()
            .is_some_and(|description| {
                description.contains("operator_webauthn_state_unavailable")
                    && !description.contains("capacity")
            })
    );

    assert_eq!(
        deletion["responses"]
            .as_object()
            .expect("credential deletion responses")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        ["200", "400", "401", "403", "404", "409", "429", "500"]
            .into_iter()
            .collect()
    );
    assert_eq!(
        operation_response_schema_ref(deletion, "200", DELETE_PATH),
        "#/components/schemas/OperatorWebAuthnCredentialDeleteResponse"
    );
    for (status, code) in [
        ("404", "operator_webauthn_credential_not_found"),
        ("409", "operator_webauthn_last_credential"),
    ] {
        assert!(
            deletion["responses"][status]["description"]
                .as_str()
                .is_some_and(|description| description.contains(code)),
            "DELETE {DELETE_PATH} HTTP {status} must document {code}"
        );
    }
    let delete_internal_error = deletion["responses"]["500"]["description"]
        .as_str()
        .expect("credential deletion internal-error description");
    assert!(delete_internal_error.contains("operator_webauthn_state_unavailable"));
    assert!(delete_internal_error.contains("operator_webauthn_persist_failed"));

    assert_strict_object_schema(
        schemas,
        "OperatorWebAuthnCredentialListResponse",
        &["credentials", "credentials_total"],
        &[],
    );
    assert_strict_object_schema(
        schemas,
        "OperatorWebAuthnCredentialMetadata",
        &["credential_id", "algorithm", "sign_count", "created_at_ms"],
        &[],
    );
    assert_strict_object_schema(
        schemas,
        "OperatorWebAuthnCredentialDeleteResponse",
        &["status", "credential_id", "credentials_total"],
        &[],
    );
    let metadata_properties = schemas["OperatorWebAuthnCredentialMetadata"]["properties"]
        .as_object()
        .expect("credential metadata properties");
    assert!(!metadata_properties.contains_key("public_key"));
    assert!(!metadata_properties.contains_key("verification_key"));
    assert_eq!(
        schemas["OperatorWebAuthnAlgorithm"]["enum"]
            .as_array()
            .expect("credential algorithms"),
        &[Value::from("es256"), Value::from("ed25519")]
    );
    assert_eq!(
        schemas["OperatorWebAuthnCredentialId"]["minLength"].as_u64(),
        Some(1)
    );
    assert_eq!(
        schemas["OperatorWebAuthnCredentialId"]["maxLength"].as_u64(),
        Some(1366)
    );
}
#[test]
fn musubi_provider_bundle_attestation_and_exact_release_contract_is_static() {
    const PROVIDER_ATTESTATION_WIRE_ID: &str =
        "iroha.musubi.v1.provider_bundle_attestation.register";
    const PROVIDER_QUERY_PATH: &str = "/v1/musubi/queries/provider-bundle-attestation";
    const PROVIDER_REGISTER_PATH: &str =
        "/v1/musubi/instructions/provider-bundle-attestation-register";
    let document = canonical_document();
    let schemas = component_schemas(&document);
    for (name, required, properties) in
        openapi_contract_rows("openapi.musubi_provider_bundle_attestation.schema_rows")
            .iter()
            .map(|row| {
                let required_len = row[1].parse::<usize>().expect("required-field count");
                let required = row[2..2 + required_len]
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                let properties = row[2 + required_len..]
                    .chunks_exact(2)
                    .map(|pair| (pair[0].as_str(), pair[1].as_str()));
                (row[0].as_str(), required, properties)
            })
    {
        let schema = schemas
            .get(name)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing {name} schema"));
        assert_eq!(
            schema.get("additionalProperties").and_then(Value::as_bool),
            Some(false),
            "{name} must remain closed"
        );
        assert_eq!(component_required(schemas, name), required);
        for (property, target) in properties {
            assert_eq!(
                property_ref(schemas, name, property),
                format!("{COMPONENT_SCHEMA_REF_PREFIX}{target}"),
                "{name}.{property} reference drift"
            );
        }
    }
    for (path, request_type, response_type, effect) in [
        (
            PROVIDER_REGISTER_PATH,
            "RegisterMusubiProviderBundleAttestationV1",
            "MusubiInstructionEnvelopeV1",
            "build_instruction",
        ),
        (
            PROVIDER_QUERY_PATH,
            "MusubiProviderBundleAttestationKeyV1",
            "MusubiProviderBundleAttestationRecordV1",
            "read",
        ),
        (
            "/v1/musubi/queries/exact-release",
            "MusubiExactReleaseQueryV1",
            "MusubiExactReleaseSnapshotV1",
            "read",
        ),
    ] {
        let path_item = document
            .get("paths")
            .and_then(Value::as_object)
            .and_then(|paths| paths.get(path))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing static Musubi path {path}"));
        assert_eq!(
            path_item.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["post"],
            "{path} must expose only POST"
        );
        let operation = openapi_operation(&document, path, "post");
        assert_eq!(
            operation
                .get("x-iroha-norito-request-type")
                .and_then(Value::as_str),
            Some(request_type)
        );
        assert_eq!(
            operation
                .get("x-iroha-norito-response-type")
                .and_then(Value::as_str),
            Some(response_type)
        );
        assert_eq!(
            operation.get(TOOL_EFFECT_EXTENSION).and_then(Value::as_str),
            Some(effect)
        );
        assert_eq!(
            operation
                .get("requestBody")
                .and_then(|body| body.get("content"))
                .and_then(|content| content.get("application/json"))
                .and_then(|media| media.get("schema"))
                .and_then(|schema| schema.get("$ref"))
                .and_then(Value::as_str),
            Some(format!("{COMPONENT_SCHEMA_REF_PREFIX}{request_type}").as_str())
        );
        assert_eq!(
            operation
                .get("responses")
                .and_then(|responses| responses.get("200"))
                .and_then(|response| response.get("content"))
                .and_then(|content| content.get("application/json"))
                .and_then(|media| media.get("schema"))
                .and_then(|schema| schema.get("$ref"))
                .and_then(Value::as_str),
            Some(format!("{COMPONENT_SCHEMA_REF_PREFIX}{response_type}").as_str())
        );
    }
    let wire_ids = component_properties(schemas, "MusubiInstructionEnvelopeV1")
        .get("wire_id")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("enum"))
        .and_then(Value::as_array)
        .expect("Musubi instruction wire-id enum")
        .iter()
        .map(|wire_id| wire_id.as_str().expect("Musubi wire id"))
        .collect::<Vec<_>>();
    let provider_index = wire_ids
        .iter()
        .position(|wire_id| *wire_id == PROVIDER_ATTESTATION_WIRE_ID)
        .expect("provider bundle-attestation wire id");
    assert_eq!(
        wire_ids
            .iter()
            .filter(|wire_id| **wire_id == PROVIDER_ATTESTATION_WIRE_ID)
            .count(),
        1
    );
    assert_eq!(
        wire_ids.get(provider_index.wrapping_sub(1)),
        Some(&"iroha.musubi.v1.archive.register")
    );
    assert_eq!(
        wire_ids.get(provider_index + 1),
        Some(&"iroha.musubi.v1.archive_location.add")
    );
    let preview_variants = schemas
        .get("MusubiInstructionPreviewV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("oneOf"))
        .and_then(Value::as_array)
        .expect("Musubi instruction preview variants");
    let provider_variants = preview_variants
        .iter()
        .filter(|variant| {
            variant
                .get("properties")
                .and_then(|properties| properties.get("wire_id"))
                .and_then(|wire_id| wire_id.get("const"))
                .and_then(Value::as_str)
                == Some(PROVIDER_ATTESTATION_WIRE_ID)
        })
        .collect::<Vec<_>>();
    assert_eq!(provider_variants.len(), 1);
    assert_eq!(
        provider_variants[0]
            .get("properties")
            .and_then(|properties| properties.get("payload"))
            .and_then(|payload| payload.get("$ref"))
            .and_then(Value::as_str),
        Some("#/components/schemas/RegisterMusubiProviderBundleAttestationV1")
    );
}
// The shared typed contract macros must precede every lexical consumer.
include!("tests/sorafs_contracts.rs");
include!("tests/sorafs_publication_contracts.rs");
include!("tests/diagnostics_schemas.rs");
include!("tests/fee_quote_contract.rs");
include!("tests/finality_app_contracts.rs");
include!("tests/retail_fee_contract.rs");
include!("tests/iso20022_auth.rs");
include!("tests/json_value_contract.rs");
include!("tests/prepared_account_contracts.rs");
include!("tests/public_contract_call.rs");
include!("tests/private_settlement_contract.rs");
include!("tests/soracloud_lease_contracts.rs");
include!("tests/sns_contract.rs");
include!("tests/query_asset_absence_contract.rs");
include!("tests/sorafs_pop_contracts.rs");
include!("tests/vpn_da.rs");
include!("tests/sumeragi_lanes_contract.rs");
mod catalog_and_contracts;

#[test]
fn openapi_uint64_bounds_keep_exact_integer_tokens_recursively() {
    fn check(value: &Value, path: &str, checked: &mut usize) {
        match value {
            Value::Object(object) => {
                if object.get("format").and_then(Value::as_str) == Some("uint64") {
                    for name in ["minimum", "maximum"] {
                        let Some(bound) = object.get(name) else {
                            continue;
                        };
                        // Native as_u64 requires the unsigned range and refuses every
                        // float. Preserve exact integer tokens, including smaller caps.
                        let integer = bound.as_u64().unwrap_or_else(|| {
                            panic!("{path}.{name} must be an exact unsigned u64 integer")
                        });
                        assert_eq!(
                            norito::json::to_json(bound).expect("serialize exact u64 bound"),
                            integer.to_string(),
                            "{path}.{name} token"
                        );
                        *checked += 1;
                    }
                }
                for (key, child) in object {
                    check(child, &format!("{path}/{key}"), checked);
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    check(child, &format!("{path}/{index}"), checked);
                }
            }
            _ => {}
        }
    }

    for (owner, document) in [
        ("authored", canonical_document()),
        ("compiled", generate_spec()),
    ] {
        let mut checked = 0;
        check(&document, owner, &mut checked);
        assert!(
            checked >= 110,
            "{owner}: expected the retained u64 bound corpus"
        );
    }

    // Prove the check's numeric accessor cannot silently round the old token.
    let rounded: Value = norito::json::from_str("1.8446744073709552e+19")
        .expect("the old rounded token is syntactically valid JSON");
    assert!(rounded.as_u64().is_none());
    let exact: Value =
        norito::json::from_str("18446744073709551615").expect("u64::MAX is an exact JSON integer");
    assert_eq!(exact.as_u64(), Some(u64::MAX));
}

#[path = "tests/privacy_release_qualification.rs"]
mod privacy_release_qualification;
#[path = "tests/validator_committee_contract.rs"]
mod validator_committee_contract;
