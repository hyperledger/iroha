//! OpenAPI catalog, capability, and transport contract tests.

use super::*;

#[test]
fn static_authority_is_the_complete_catalog_projection_with_exact_effects() {
    fn method_name(method: CatalogHttpMethod) -> &'static str {
        match method {
            CatalogHttpMethod::Get => "get",
            CatalogHttpMethod::Post => "post",
            CatalogHttpMethod::Put => "put",
            CatalogHttpMethod::Patch => "patch",
            CatalogHttpMethod::Delete => "delete",
            CatalogHttpMethod::Any => {
                panic!("ANY protocol gateways cannot enter the OpenAPI projection")
            }
        }
    }
    let document = canonical_document();
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .expect("static OpenAPI authority paths");
    let expected: BTreeSet<_> = RouteCatalog::new(CATALOGED_ROUTES)
        .routes()
        .iter()
        .filter(|route| route.projections().openapi())
        .map(|route| {
            (
                route.path().replace("{*", "{"),
                method_name(route.method()).to_owned(),
            )
        })
        .collect();
    let actual: BTreeSet<_> = paths
        .iter()
        .flat_map(|(path, item)| {
            let methods = item.as_object().expect("static OpenAPI path item");
            ["get", "post", "put", "patch", "delete"]
                .into_iter()
                .filter_map(move |method| {
                    methods
                        .contains_key(method)
                        .then(|| (path.clone(), method.to_owned()))
                })
        })
        .collect();
    assert_eq!(
        actual, expected,
        "static OpenAPI authority must be the feature-independent catalog superset"
    );
    for (path, method) in actual {
        let operation = paths
            .get(&path)
            .and_then(Value::as_object)
            .and_then(|path_item| path_item.get(&method))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing static operation {method} {path}"));
        assert_eq!(
            operation.get(TOOL_EFFECT_EXTENSION).and_then(Value::as_str),
            Some(expected_operation_effect(&method, &path)),
            "static tool effect drift for {method} {path}"
        );
        let descriptor = RouteCatalog::new(CATALOGED_ROUTES)
            .routes()
            .iter()
            .find(|descriptor| {
                descriptor.projections().openapi()
                    && descriptor.path().replace("{*", "{") == path
                    && method_name(descriptor.method()) == method
            })
            .unwrap_or_else(|| panic!("missing catalog descriptor for {method} {path}"));
        assert_eq!(
            operation.get(ROUTE_AUTH_EXTENSION),
            Some(&route_auth_metadata(*descriptor)),
            "static route-auth metadata drift for {method} {path}"
        );
        if let Some(expected_security) = standard_security_requirements(descriptor.authentication())
        {
            assert_eq!(
                operation.get("security"),
                Some(&expected_security),
                "static standard security drift for {method} {path}"
            );
        }
    }
}
#[test]
fn sccp_schema_serialization_excludes_secret_fields() {
    assert_eq!(
        iroha_data_model::parliament_types::FIRST_RELEASE_MAX_EXACT_JSON_U64,
        9_007_199_254_740_991
    );
    let schemas = sccp_schemas();
    let proposal_properties = schemas
        .get("SccpGovernanceProposalV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .expect("SCCP governance proposal properties");
    for forbidden in ["private_key", "secret", "signer", "seed", "mnemonic"] {
        assert!(
            !proposal_properties.contains_key(forbidden),
            "the SCCP governance proposal must not advertise `{forbidden}`"
        );
    }
    let serialized =
        norito::json::to_string(&Value::Object(schemas)).expect("serialize SCCP schemas");
    for forbidden in openapi_contract_strings(
        "openapi.sccp_schema_serialization_excludes_secret_fields.strings.1",
    ) {
        assert!(
            !serialized.contains(forbidden),
            "secret SCCP field `{forbidden}` must not be serialized"
        );
    }
}
#[test]
fn sccp_governance_openapi_tracks_the_v1_parliament_proposal() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    for (schema_name, field) in [
        ("SccpRouteGovernanceProposalDraftRequestV1", "proposal"),
        (
            "GovernanceParliamentProposalPayloadSccpRouteGovernanceV1",
            "proposal",
        ),
        ("ExplorerSccpRouteGovernanceInstructionValue", "proposal"),
    ] {
        let schema = schemas
            .get(schema_name)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{schema_name} schema"));
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{schema_name} properties"));
        assert_eq!(
            properties.keys().map(String::as_str).collect::<Vec<_>>(),
            [field],
            "{schema_name} must carry exactly the v1 proposal"
        );
        assert_eq!(
            properties.get(field),
            Some(&schema_ref("SccpGovernanceProposalV1")),
            "{schema_name}.{field}"
        );
    }
    let proposal = schemas
        .get("SccpGovernanceProposalV1")
        .and_then(Value::as_object)
        .expect("SCCP governance proposal schema");
    let actions = proposal
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("actions"))
        .and_then(Value::as_object)
        .expect("proposal actions schema");
    assert_eq!(actions.get("minItems").and_then(Value::as_u64), Some(1));
    assert_eq!(actions.get("maxItems").and_then(Value::as_u64), Some(16));
    let tags = schemas
        .get("SccpGovernanceActionV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("oneOf"))
        .and_then(Value::as_array)
        .expect("closed SCCP governance action variants")
        .iter()
        .map(|variant| {
            variant
                .get("properties")
                .and_then(Value::as_object)
                .and_then(|properties| properties.get("action"))
                .and_then(Value::as_object)
                .and_then(|action| action.get("const"))
                .and_then(Value::as_str)
                .expect("closed SCCP governance action tag")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        tags,
        [
            "register_route",
            "activate_revision",
            "switch_revision",
            "deactivate_outbound",
            "retire_revision",
            "remove_staged",
            "release_stranded",
            "set_taira_paused",
            "set_destination_paused",
            "initialize_light_client",
            "install_trusted_checkpoint",
            "freeze_light_client",
            "set_parameters",
            "clear_bridge_key_fault",
        ]
    );
    let ton = schemas
        .get("SccpTonDeploymentV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("required"))
        .and_then(Value::as_array)
        .expect("TON deployment required fields")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        ton,
        [
            "master_account",
            "minter_code",
            "wallet_code",
            "bucket_code"
        ]
    );
}
#[test]
fn production_constants_embedded_in_openapi_remain_frozen() {
    fn at<'a>(mut value: &'a Value, path: &[&str]) -> &'a Value {
        for component in path {
            value = value
                .get(*component)
                .unwrap_or_else(|| panic!("missing OpenAPI authority path {path:?}"));
        }
        value
    }
    fn u64_at(value: &Value, path: &[&str]) -> u64 {
        at(value, path)
            .as_u64()
            .unwrap_or_else(|| panic!("OpenAPI authority path {path:?} is not a u64"))
    }
    let document = canonical_document();
    let schema_length = |name: &str| {
        u64_at(
            &document,
            &["components", "schemas", name, "x-iroha-exact-byte-length"],
        )
    };
    assert_eq!(
        (
            schema_length("BootleLanternIssuanceAuthorizeRequestV1"),
            schema_length("BootleLanternIssuanceAuthorizationWireV1"),
            schema_length("BootleLanternIssuanceIssueRequestV1"),
            schema_length("BootleLanternIssuanceResponseWireV1"),
        ),
        (0, 320, 71_896, 3_176)
    );
    assert_eq!(
        u64_at(
            &document,
            &[
                "paths",
                "/v1/ledger/block/{height}",
                "get",
                "responses",
                "200",
                "content",
                "application/x-norito",
                "schema",
                "x-iroha-max-bytes",
            ],
        ),
        u64::try_from(
            iroha_data_model::block::proofs::AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1,
        )
        .expect("authenticated block proof byte limit fits u64")
    );
    assert_eq!(
        (
            u64_at(
                &document,
                &[
                    "components",
                    "schemas",
                    "ErrorEnvelope",
                    "properties",
                    "message",
                    "maxLength",
                ],
            ),
            u64_at(
                &document,
                &[
                    "components",
                    "schemas",
                    "ErrorDetails",
                    "properties",
                    "hint",
                    "maxLength",
                ],
            ),
            u64_at(
                &document,
                &[
                    "components",
                    "schemas",
                    "ErrorDetails",
                    "properties",
                    "reject_code",
                    "maxLength",
                ],
            ),
        ),
        (
            u64::try_from(utils::MAX_ERROR_MESSAGE_CHARACTERS).expect("message bound"),
            u64::try_from(utils::MAX_ERROR_DETAIL_CHARACTERS).expect("detail bound"),
            u64::try_from(utils::MAX_REJECT_CODE_BYTES).expect("reject-code bound"),
        )
    );
    #[cfg(feature = "app_api")]
    let multisig_limit = at(
        &document,
        &[
            "components",
            "schemas",
            "MultisigProposalsQueryRequest",
            "properties",
            "limit",
            "oneOf",
        ],
    )
    .as_array()
    .and_then(|variants| variants.first())
    .and_then(|variant| variant.get("maximum"))
    .and_then(Value::as_u64)
    .expect("multisig proposal query maximum");
    #[cfg(feature = "app_api")]
    assert_eq!(
        multisig_limit,
        crate::routing::MULTISIG_PROPOSALS_MAX_PAGE_LIMIT
    );
}
// Textual inclusion preserves the original OpenAPI test-module paths.
#[test]
fn openapi_route_auth_metadata_matches_enabled_catalog_projection() {
    let document = generate_spec();
    let projected = RouteCatalog::new(CATALOGED_ROUTES).project(
        CatalogProjection::OpenApi,
        crate::router::builder::compiled_route_features(),
    );
    for descriptor in projected {
        let method = match descriptor.method() {
            CatalogHttpMethod::Get => "get",
            CatalogHttpMethod::Post => "post",
            CatalogHttpMethod::Put => "put",
            CatalogHttpMethod::Patch => "patch",
            CatalogHttpMethod::Delete => "delete",
            CatalogHttpMethod::Any => {
                panic!("ANY protocol gateways cannot enter the OpenAPI projection")
            }
        };
        let path = descriptor.path().replace("{*", "{");
        let operation = openapi_operation(&document, &path, method);
        assert_eq!(
            operation.get(ROUTE_AUTH_EXTENSION),
            Some(&route_auth_metadata(*descriptor)),
            "{method} {path} route-auth metadata"
        );
    }
}
#[test]
fn openapi_standard_security_matches_enabled_catalog_authentication() {
    let document = generate_spec();
    let projected = RouteCatalog::new(CATALOGED_ROUTES).project(
        CatalogProjection::OpenApi,
        crate::router::builder::compiled_route_features(),
    );
    for descriptor in projected {
        let method = match descriptor.method() {
            CatalogHttpMethod::Get => "get",
            CatalogHttpMethod::Post => "post",
            CatalogHttpMethod::Put => "put",
            CatalogHttpMethod::Patch => "patch",
            CatalogHttpMethod::Delete => "delete",
            CatalogHttpMethod::Any => {
                panic!("ANY protocol gateways cannot enter the OpenAPI projection")
            }
        };
        let path = descriptor.path().replace("{*", "{");
        let operation = openapi_operation(&document, &path, method);
        if let Some(expected) = standard_security_requirements(descriptor.authentication()) {
            assert_eq!(
                operation.get("security"),
                Some(&expected),
                "{method} {path} standard security"
            );
        }
    }

    let schemes = document
        .get("components")
        .and_then(|components| components.get("securitySchemes"))
        .and_then(Value::as_object)
        .expect("security schemes");
    for (scheme, header) in [
        ("IrohaOperatorPublicKey", "X-Iroha-Operator-Public-Key"),
        ("IrohaOperatorTimestampMs", "X-Iroha-Operator-Timestamp-Ms"),
        ("IrohaOperatorNonce", "X-Iroha-Operator-Nonce"),
        ("IrohaOperatorSignature", "X-Iroha-Operator-Signature"),
    ] {
        assert_eq!(
            schemes
                .get(scheme)
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str),
            Some(header),
            "operator security scheme {scheme}"
        );
    }
}
#[test]
fn protocol_specific_bootle_bearer_security_is_preserved() {
    let document = generate_spec();
    for path in [
        "/v1/privacy/bootle-lantern/issuance/authorize",
        "/v1/privacy/bootle-lantern/issuance/issue",
    ] {
        assert_eq!(
            openapi_operation(&document, path, "post").get("security"),
            Some(&norito::json!([
                { "BootleLanternIssuanceBearer": [] }
            ])),
            "{path} must retain its protocol-specific bearer scheme"
        );
    }
}
#[test]
fn openapi_operations_equal_the_enabled_catalog_projection() {
    use iroha_torii_shared::route_catalog::{
        CATALOGED_ROUTES, CatalogProjection, HttpMethod, RouteCatalog,
    };
    fn openapi_path(path: &str) -> String {
        // Axum marks a wildcard parameter with `*`; OpenAPI path templates
        // use the same parameter name without the router-specific marker.
        path.replace("{*", "{")
    }
    fn method_name(method: HttpMethod) -> &'static str {
        match method {
            HttpMethod::Get => "get",
            HttpMethod::Post => "post",
            HttpMethod::Put => "put",
            HttpMethod::Patch => "patch",
            HttpMethod::Delete => "delete",
            HttpMethod::Any => {
                panic!("ANY protocol gateways cannot enter the OpenAPI projection")
            }
        }
    }
    let expected: BTreeSet<_> = RouteCatalog::new(CATALOGED_ROUTES)
        .project(
            CatalogProjection::OpenApi,
            crate::router::builder::compiled_route_features(),
        )
        .into_iter()
        .map(|route| {
            (
                openapi_path(route.path()),
                method_name(route.method()).to_owned(),
            )
        })
        .collect();
    #[cfg(all(
        feature = "app_api",
        feature = "telemetry",
        feature = "profiling",
        feature = "schema",
        feature = "connect",
        feature = "zk-verify-batch",
        feature = "push"
    ))]
    assert_eq!(
        expected.len(),
        572,
        "the supported full Torii documentation profile must remain exactly 572 cataloged operations"
    );
    let spec = generate_spec();
    let paths = spec
        .get("paths")
        .and_then(Value::as_object)
        .expect("OpenAPI paths");
    let operation_methods = ["get", "post", "delete", "put", "patch"];
    let actual: BTreeSet<_> = paths
        .iter()
        .flat_map(|(path, item)| {
            let item = item.as_object().expect("OpenAPI path item");
            operation_methods.into_iter().filter_map(move |method| {
                item.contains_key(method)
                    .then(|| (path.clone(), method.to_owned()))
            })
        })
        .collect();
    let missing: Vec<_> = expected.difference(&actual).cloned().collect();
    let undocumented_catalog_extras: Vec<_> = actual.difference(&expected).cloned().collect();
    assert!(
        missing.is_empty() && undocumented_catalog_extras.is_empty(),
        "OpenAPI/catalog projection mismatch; missing from OpenAPI: {missing:#?}; absent from enabled catalog projection: {undocumented_catalog_extras:#?}"
    );
}
#[test]
fn every_operation_uses_one_declared_top_level_tag() {
    let document = generate_spec();
    let declared: BTreeSet<_> = document
        .get("tags")
        .and_then(Value::as_array)
        .expect("top-level tags")
        .iter()
        .map(|tag| {
            tag.get("name")
                .and_then(Value::as_str)
                .expect("top-level tag name")
        })
        .collect();
    assert_eq!(
        declared.len(),
        document
            .get("tags")
            .and_then(Value::as_array)
            .expect("top-level tags")
            .len(),
        "top-level tag names must be unique"
    );
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .expect("OpenAPI paths");
    for (path, path_item) in paths {
        let methods = path_item.as_object().expect("path item");
        for method in ["get", "post", "put", "patch", "delete"] {
            let Some(operation) = methods.get(method).and_then(Value::as_object) else {
                continue;
            };
            let tags = operation
                .get("tags")
                .and_then(Value::as_array)
                .unwrap_or_else(|| panic!("{method} {path} tags"));
            assert_eq!(tags.len(), 1, "{method} {path} must use exactly one tag");
            let tag = tags[0]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} tag name"));
            assert!(
                declared.contains(tag),
                "{method} {path} uses undeclared tag {tag}"
            );
        }
    }
}
#[test]
fn exact_quantity_components_remain_canonical_and_legacy_deal_api_is_absent() {
    let document = generate_spec();
    let schemas = component_schemas(&document);
    for [name, pattern] in openapi_contract_fixed_rows::<2>(
        "openapi.exact_quantity_components_remain_canonical_and_legacy_deal_api_is_absent.rows.1",
    ) {
        let schema = schemas
            .get(name)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{name} schema"));
        assert_eq!(schema.get("type").and_then(Value::as_str), Some("string"));
        assert_eq!(schema.get("pattern").and_then(Value::as_str), Some(pattern));
        assert_eq!(schema.get("maxLength").and_then(Value::as_u64), Some(155));
    }
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .expect("OpenAPI paths");
    for path in openapi_contract_strings(
        "openapi.exact_quantity_components_remain_canonical_and_legacy_deal_api_is_absent.strings.1",
    ) {
        assert!(
            !paths.contains_key(path),
            "retired path leaked into OpenAPI: {path}"
        );
    }
    for schema in openapi_contract_strings(
        "openapi.exact_quantity_components_remain_canonical_and_legacy_deal_api_is_absent.strings.2",
    ) {
        assert!(
            !schemas.contains_key(schema),
            "retired process-local deal schema leaked into OpenAPI: {schema}"
        );
    }
}
#[cfg(feature = "app_api")]
#[test]
fn retired_sorafs_economics_surface_is_absent() {
    let document = generate_spec();
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .expect("OpenAPI paths");
    for path in
        openapi_contract_strings("openapi.retired_sorafs_economics_surface_is_absent.strings.1")
    {
        assert!(
            !paths.contains_key(path),
            "retired process-local economics path leaked into OpenAPI: {path}"
        );
    }
    let schemas = component_schemas(&document);
    for schema in
        openapi_contract_strings("openapi.retired_sorafs_economics_surface_is_absent.strings.2")
    {
        assert!(
            !schemas.contains_key(schema),
            "retired process-local economics schema leaked into OpenAPI: {schema}"
        );
    }
}
#[cfg(feature = "app_api")]
#[test]
fn converted_catalog_families_have_exact_openapi_operations() {
    use iroha_torii_shared::route_catalog::{self, HttpMethod};
    let spec = generate_spec();
    let paths = spec
        .get("paths")
        .and_then(Value::as_object)
        .expect("OpenAPI paths");
    let mut descriptors = route_catalog::aliases::ROUTES
        .iter()
        .chain(route_catalog::operator_authentication::ROUTES)
        .chain(route_catalog::iso20022::ROUTES)
        .chain(route_catalog::data_availability::ROUTES)
        .chain(route_catalog::musubi::ROUTES)
        .chain(route_catalog::mcp_transport::ROUTES)
        .copied()
        .collect::<Vec<_>>();
    descriptors.extend(
        route_catalog::sorafs::ROUTES
            .iter()
            .filter(|descriptor| descriptor.projections().openapi())
            .copied(),
    );
    #[cfg(feature = "connect")]
    descriptors.extend_from_slice(route_catalog::connect::ROUTES);
    for descriptor in descriptors {
        assert!(descriptor.projections().openapi());
        let method = match descriptor.method() {
            HttpMethod::Get => "get",
            HttpMethod::Post => "post",
            HttpMethod::Delete => "delete",
            other => panic!("unexpected converted route method: {other:?}"),
        };
        assert!(
            paths
                .get(descriptor.path())
                .and_then(Value::as_object)
                .is_some_and(|operation| operation.contains_key(method)),
            "missing {method} OpenAPI operation for {} ({})",
            descriptor.stable_route_id(),
            descriptor.path()
        );
    }
    for unsupported_path in openapi_contract_strings(
        "openapi.converted_catalog_families_have_exact_openapi_operations.strings.1",
    ) {
        assert!(
            !paths.contains_key(unsupported_path),
            "unsupported path leaked into OpenAPI: {unsupported_path}"
        );
    }
}
#[cfg(feature = "app_api")]
#[test]
fn soracloud_status_documents_only_the_canonical_routing_count() {
    let document = generate_spec();
    let description = openapi_operation(&document, "/v1/soracloud/status", "get")
        .get("description")
        .and_then(Value::as_str)
        .expect("Soracloud status description");

    assert!(description.contains("`configured_lane_count`"));
    assert!(!description.contains("`lane_count`"));
    assert!(!description.contains("legacy"));
}
#[test]
fn canonical_stream_operations_publish_fail_closed_contract() {
    let document = generate_spec();
    let paths = document["paths"].as_object().expect("paths");
    for path in ["/v1/events/sse", "/v1/contracts/events/sse"] {
        let get = paths[path]["get"].as_object().expect("SSE GET operation");
        assert_eq!(
            get.get("x-iroha-replay-supported").and_then(Value::as_bool),
            Some(false),
            "{path} must not advertise replay"
        );
        assert_eq!(
            get.get("x-iroha-lag-behavior").and_then(Value::as_str),
            Some("terminal_stream_error")
        );
        let responses = get["responses"].as_object().expect("SSE responses");
        assert!(responses.contains_key("200"));
        assert!(responses.contains_key("400"));
    }
    for path in [
        route_catalog::streaming::SUBSCRIPTION_WS.path(),
        route_catalog::streaming::BLOCKS_WS.path(),
    ] {
        let get = paths[path]["get"]
            .as_object()
            .expect("WebSocket GET operation");
        assert_eq!(
            get.get("x-iroha-websocket-subprotocol")
                .and_then(Value::as_str),
            Some(iroha_torii_shared::NORITO_V1_WEBSOCKET_SUBPROTOCOL)
        );
        assert_eq!(
            get.get("x-iroha-max-subscription-message-bytes")
                .and_then(Value::as_u64),
            Some(256 * 1024)
        );
        let responses = get["responses"].as_object().expect("WebSocket responses");
        assert!(responses.contains_key("101"));
        assert!(!responses.contains_key("200"));
        assert!(responses.contains_key("400"));
        assert!(responses.contains_key("401"));
    }
}
#[test]
fn retired_alias_voprf_surface_does_not_reappear() {
    fn assert_absent(surface: &str, source: &str, forbidden: &[&str]) {
        for needle in forbidden {
            assert!(
                !source.contains(needle),
                "retired alias VOPRF surface `{needle}` reappeared in {surface}"
            );
        }
    }
    assert_absent(
        "Torii runtime",
        include_str!("../../lib.rs"),
        &["/v1/aliases/voprf/evaluate", "handler_alias_voprf_evaluate"],
    );
    assert_absent(
        "Torii request DTOs",
        include_str!("../../routing.rs"),
        &[
            "AliasVoprfBackendDto",
            "AliasVoprfEvaluateRequestDto",
            "AliasVoprfEvaluateResponseDto",
        ],
    );
}
#[test]
fn content_route_documents_conditional_cache_and_auth_contract() {
    const PATH: &str = "/v1/content/{bundle}/{path}";
    let document = generate_spec();
    let operation = openapi_operation(&document, PATH, "get");
    let description = operation
        .get("description")
        .and_then(Value::as_str)
        .expect("content operation description");
    for phrase in openapi_contract_strings(
        "openapi.content_route_documents_conditional_cache_and_auth_contract.strings.1",
    ) {
        assert!(
            description.contains(phrase),
            "content operation must document `{phrase}`"
        );
    }
    let parameters = operation
        .get("parameters")
        .and_then(Value::as_array)
        .expect("content parameters");
    let auth_headers = parameters
        .iter()
        .filter(|parameter| parameter.get("in").and_then(Value::as_str) == Some("header"))
        .map(|parameter| {
            (
                parameter
                    .get("name")
                    .and_then(Value::as_str)
                    .expect("content auth header"),
                parameter.get("required").and_then(Value::as_bool),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        auth_headers,
        BTreeSet::from([
            ("X-Iroha-Account", Some(false)),
            ("X-Iroha-Nonce", Some(false)),
            ("X-Iroha-Signature", Some(false)),
            ("X-Iroha-Timestamp-Ms", Some(false)),
            ("X-Iroha-Witness", Some(false)),
        ])
    );
    let responses = operation
        .get("responses")
        .and_then(Value::as_object)
        .expect("content responses");
    let success_headers = responses
        .get("200")
        .and_then(Value::as_object)
        .and_then(|response| response.get("headers"))
        .and_then(Value::as_object)
        .expect("content success cache headers");
    let cache_description = success_headers
        .get("Cache-Control")
        .and_then(Value::as_object)
        .and_then(|header| header.get("description"))
        .and_then(Value::as_str)
        .expect("content cache-control description");
    assert!(cache_description.contains("Public bundles"));
    assert!(cache_description.contains("private, no-store"));
    assert_eq!(
        success_headers
            .get("Vary")
            .and_then(Value::as_object)
            .and_then(|header| header.get("schema"))
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("const"))
            .and_then(Value::as_str),
        Some(crate::content::CANONICAL_CONTENT_AUTH_VARY)
    );
    for [name, expected] in openapi_contract_fixed_rows::<2>(
        "openapi.content_route_documents_conditional_cache_and_auth_contract.rows.1",
    ) {
        assert_eq!(
            success_headers
                .get(name)
                .and_then(Value::as_object)
                .and_then(|header| header.get("schema"))
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("const"))
                .and_then(Value::as_str),
            Some(expected),
            "content response must document the {name} boundary"
        );
    }
    let unauthorized = responses
        .get("401")
        .and_then(Value::as_object)
        .and_then(|response| response.get("description"))
        .and_then(Value::as_str)
        .expect("content unauthorized description");
    assert!(unauthorized.contains("canonical request authentication"));
    let not_found = responses
        .get("404")
        .and_then(Value::as_object)
        .and_then(|response| response.get("description"))
        .and_then(Value::as_str)
        .expect("content not-found description");
    assert!(not_found.contains("unknown or expired"));
    assert!(not_found.contains("authenticate and authorize before revealing"));
}
#[test]
fn ledger_executed_block_wire_cached_loading_is_safe_from_256_kib_callers() {
    const SMALL_CALLER_STACK_BYTES: usize = 256 * 1024;
    let caller = std::thread::Builder::new()
        .name("openapi-small-stack-regression".to_owned())
        .stack_size(SMALL_CALLER_STACK_BYTES)
        .spawn(|| {
            let compiled = generate_spec();
            let rendered = compiled_spec_json();
            let reparsed: Value =
                norito::json::from_str(rendered).expect("cached OpenAPI JSON must parse");
            assert_eq!(reparsed, compiled);
            for (variant, document) in [("owned", &compiled), ("borrowed", compiled_spec())] {
                let operation = openapi_operation(document, "/v1/ledger/block/{height}", "get");
                assert_eq!(
                    operation.get("operationId").and_then(Value::as_str),
                    Some("ledgerExecutedBlockWire"),
                    "missing canonical executed-block operation in {variant} OpenAPI",
                );
            }
            #[cfg(feature = "app_api")]
            {
                for (variant, document) in [("owned", &compiled), ("borrowed", compiled_spec())] {
                    let paths = document
                        .get("paths")
                        .and_then(Value::as_object)
                        .unwrap_or_else(|| panic!("{variant} OpenAPI paths"));
                    assert!(
                        paths.contains_key("/v1/accounts/capabilities"),
                        "app API capability route missing from {variant} OpenAPI",
                    );
                    assert!(
                        paths.contains_key(route_catalog::core::RESOURCE_NAMES_STATE.path()),
                        "ledger original carrier missing from {variant} OpenAPI",
                    );
                }
            }
        })
        .expect("spawn adversarial small-stack OpenAPI caller");
    if let Err(payload) = caller.join() {
        std::panic::resume_unwind(payload);
    }
}
#[cfg(feature = "app_api")]
#[test]
fn account_capabilities_document_exact_public_bootstrap_policy() {
    let document = generate_spec();
    let operation = openapi_operation(&document, "/v1/accounts/capabilities", "get");
    assert_eq!(
        operation["operationId"].as_str(),
        Some("getAccountCapabilities")
    );
    assert!(operation.get("requestBody").is_none());
    assert!(
        operation["parameters"]
            .as_array()
            .expect("parameters")
            .is_empty()
    );
    assert!(
        operation["security"]
            .as_array()
            .expect("security")
            .iter()
            .any(|value| { value.as_object().is_some_and(Map::is_empty) })
    );
    let schemas = component_schemas(&document);
    let schema = &schemas["AccountCapabilitiesV1"];
    assert_eq!(schema["additionalProperties"].as_bool(), Some(false));
    assert_eq!(schema["x-iroha-max-bytes"].as_u64(), Some(4096));
    assert_eq!(
        schema["properties"]["schema_version"]["const"].as_u64(),
        Some(1)
    );
    assert_eq!(
        schema["properties"]["default_signing"]["const"].as_str(),
        Some("ed25519")
    );
    assert_eq!(
        schema["properties"]["network_prefix"]["maximum"].as_u64(),
        Some(65535)
    );
    assert_eq!(schema["required"].as_array().expect("required").len(), 5);
    let node = openapi_operation(&document, "/v1/node/capabilities", "get");
    assert!(
        node["parameters"]
            .as_array()
            .expect("node parameters")
            .is_empty()
    );
    assert!(node.get("x-iroha-canonical-auth-v1").is_none());
    assert!(node["responses"]["200"].get("headers").is_none());
    assert_eq!(
        node["x-iroha-route-auth"]["admission"].as_str(),
        Some("public")
    );
    assert!(
        node["security"]
            .as_array()
            .expect("node security")
            .iter()
            .any(|value| { value.as_object().is_some_and(Map::is_empty) })
    );
}

#[test]
fn generated_spec_includes_documented_paths() {
    let doc = generate_spec();
    if std::env::var("PRINT_TORII_SPEC").is_ok() {
        if let Ok(json) = norito::json::to_string_pretty(&doc) {
            println!("{json}");
        }
    }
    let paths = doc
        .get("paths")
        .and_then(Value::as_object)
        .expect("paths section");
    assert!(!paths.contains_key("/v1/aliases/voprf/evaluate"));
    let schemas = doc
        .get("components")
        .and_then(Value::as_object)
        .and_then(|components| components.get("schemas"))
        .and_then(Value::as_object)
        .expect("schemas section");
    for retired_schema in ["AliasVoprfEvaluateRequest", "AliasVoprfEvaluateResponse"] {
        assert!(
            !schemas.contains_key(retired_schema),
            "retired alias VOPRF schema {retired_schema} reappeared"
        );
    }
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_present.1")
    {
        assert!(paths.contains_key(path));
    }
    assert!(!paths.contains_key("/v1/fee-sponsor-policies/by-id"));
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_present.2")
    {
        assert!(paths.contains_key(path));
    }
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.strings.1")
    {
        assert_eq!(
            paths.contains_key(path),
            catalog_openapi_route_enabled(CatalogHttpMethod::Get, path),
            "{path} presence must follow the enabled catalog OpenAPI projection"
        );
    }
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_present.3")
    {
        assert!(paths.contains_key(path));
    }
    for retired in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.strings.2")
    {
        assert!(
            !paths.contains_key(retired),
            "retired path {retired} leaked"
        );
    }
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_present.5")
    {
        assert!(paths.contains_key(path));
    }
    assert!(paths.contains_key(route_catalog::pipeline::TRANSACTION.path()));
    assert!(paths.contains_key(route_catalog::pipeline::TRANSACTION_ENTRYPOINT.path()));
    assert!(paths.contains_key(route_catalog::pipeline::TRANSACTIONS_BATCH.path()));
    assert!(paths.contains_key(route_catalog::pipeline::QUERY.path()));
    assert!(paths.contains_key(route_catalog::streaming::SUBSCRIPTION_WS.path()));
    #[cfg(feature = "schema")]
    assert!(paths.contains_key(route_catalog::diagnostic::SCHEMA.path()));
    #[cfg(not(feature = "schema"))]
    assert!(!paths.contains_key(route_catalog::diagnostic::SCHEMA.path()));
    #[cfg(feature = "profiling")]
    assert!(paths.contains_key(route_catalog::diagnostic::PROFILE.path()));
    #[cfg(not(feature = "profiling"))]
    assert!(!paths.contains_key(route_catalog::diagnostic::PROFILE.path()));
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_absent.6")
    {
        assert!(!paths.contains_key(path));
    }
    let da_ingest_responses = paths
        .get("/v1/da/ingest")
        .and_then(Value::as_object)
        .and_then(|path| path.get("post"))
        .and_then(Value::as_object)
        .and_then(|post| post.get("responses"))
        .and_then(Value::as_object)
        .expect("DA ingest response map");
    assert!(da_ingest_responses.contains_key("202"));
    assert!(!da_ingest_responses.contains_key("200"));
    #[cfg(feature = "connect")]
    assert!(paths.contains_key("/v1/connect/session"));
    #[cfg(not(feature = "connect"))]
    assert!(!paths.contains_key("/v1/connect/session"));
    assert!(paths.contains_key("/v1/vpn/profile"));
    assert!(paths.contains_key("/v1/vpn/quotes"));
    let vpn_quotes_post_description = paths
        .get("/v1/vpn/quotes")
        .and_then(Value::as_object)
        .and_then(|path| path.get("post"))
        .and_then(Value::as_object)
        .and_then(|post| post.get("description"))
        .and_then(Value::as_str)
        .expect("vpn quote create description");
    assert!(vpn_quotes_post_description.contains("metering_public_key_hex"));
    assert!(vpn_quotes_post_description.contains("OpenVpnLeaseEscrow"));
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_present.7")
    {
        assert!(paths.contains_key(path));
    }
    let vpn_receipts_post_description = paths
        .get("/v1/vpn/receipts")
        .and_then(Value::as_object)
        .and_then(|path| path.get("post"))
        .and_then(Value::as_object)
        .and_then(|post| post.get("description"))
        .and_then(Value::as_str)
        .expect("vpn receipt submit description");
    assert!(vpn_receipts_post_description.contains("settle_lease_instruction"));
    assert!(vpn_receipts_post_description.contains("SettleVpnLease"));
    assert!(paths.contains_key("/v1/mcp"));
    assert!(paths.contains_key("/v1/zk/attachments"));
    let verifying_key_get_description = paths
        .get("/v1/zk/vk/{backend}/{name}")
        .and_then(Value::as_object)
        .and_then(|path| path.get("get"))
        .and_then(Value::as_object)
        .and_then(|get| get.get("description"))
        .and_then(Value::as_str)
        .expect("verifying-key detail description");
    assert!(verifying_key_get_description.contains("record_norito_base64"));
    assert!(verifying_key_get_description.contains("namespace"));
    assert!(verifying_key_get_description.contains("owner_manifest_id"));
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_present.8")
    {
        assert!(paths.contains_key(path));
    }
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_absent.9")
    {
        assert!(!paths.contains_key(path));
    }
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_present.10")
    {
        assert!(paths.contains_key(path));
    }
    assert!(paths.contains_key(route_catalog::runtime_governance::GOV_PROPOSE_SCCP.path()));
    assert!(paths.contains_key(route_catalog::runtime_governance::GOV_CAPABILITIES.path()));
    assert!(paths.contains_key(route_catalog::runtime_governance::GOV_CITIZEN_DRAFT.path()));
    assert!(paths.contains_key("/v1/gov/citizens"));
    assert!(paths.contains_key("/v1/gov/stream"));
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_absent.11")
    {
        assert!(!paths.contains_key(path));
    }
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_present.12")
    {
        assert!(paths.contains_key(path), "missing current route: {path}");
    }
    for retired in [
        "/v1/transactions/history",
        "/v1/node/query/projection/checkpoint/plan",
        "/v1/node/query/projection/checkpoint/publish",
    ] {
        assert!(!paths.contains_key(retired), "retired route: {retired}");
    }
    let reputation_latest = paths
        .get("/v1/sorafs/reputation/latest")
        .and_then(Value::as_object)
        .expect("reputation latest OpenAPI operation");
    assert!(reputation_latest.contains_key("get"));
    assert!(!reputation_latest.contains_key("post"));
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_present.13")
    {
        assert!(paths.contains_key(path));
    }
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_absent.14")
    {
        assert!(!paths.contains_key(path));
    }
    for repair_command_path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.strings.3")
    {
        assert!(paths.contains_key(repair_command_path));
    }
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_present.15")
    {
        assert!(paths.contains_key(path));
    }
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_absent.16")
    {
        assert!(!paths.contains_key(path));
    }
    for unsupported_path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.strings.4")
    {
        assert!(
            !paths.contains_key(unsupported_path),
            "unsupported path leaked into OpenAPI: {unsupported_path}"
        );
    }
    for live_path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.strings.5")
    {
        assert!(
            paths.contains_key(live_path),
            "live PoR route missing from OpenAPI: {live_path}"
        );
    }
    assert!(paths.contains_key("/v1/sorafs/appeals/pricing/config"));
    assert!(paths.contains_key("/v1/sorafs/appeals/pricing/status"));
    let appeal_pricing_status_description = paths
        .get("/v1/sorafs/appeals/pricing/status")
        .and_then(Value::as_object)
        .and_then(|path| path.get("get"))
        .and_then(Value::as_object)
        .and_then(|get| get.get("description"))
        .and_then(Value::as_str)
        .expect("appeal pricing status description");
    assert!(appeal_pricing_status_description.contains("native deposit lifecycle"));
    assert!(
        appeal_pricing_status_description
            .contains("durable finalized-ledger transaction forwarder")
    );
    assert!(appeal_pricing_status_description.contains("runtime-only signer providers"));
    assert!(
        appeal_pricing_status_description
            .contains("hosted dashboard, and four-peer rollout evidence remain promotion gates")
    );
    let stale_pending_runtime_phrase =
        ["still pending runtime escrow", " and ledger integration"].concat();
    assert!(!appeal_pricing_status_description.contains(&stale_pending_runtime_phrase));
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_present.17")
    {
        assert!(paths.contains_key(path));
    }
    for publication_path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.strings.6")
    {
        let operation = paths
            .get(publication_path)
            .and_then(Value::as_object)
            .expect("appeal-finance publication readback path item");
        assert!(operation.contains_key("get"), "{publication_path}");
        let post = operation
            .get("post")
            .and_then(Value::as_object)
            .expect("authenticated appeal-finance publication operation");
        assert!(
            post.get("security")
                .and_then(Value::as_array)
                .is_some_and(|requirements| !requirements.is_empty()),
            "appeal-finance publication must require canonical authentication: {publication_path}"
        );
        let responses = post
            .get("responses")
            .and_then(Value::as_object)
            .expect("appeal-finance publication responses");
        assert!(responses.contains_key("202"), "{publication_path}");
        assert!(!responses.contains_key("200"), "{publication_path}");
    }
    assert!(paths.contains_key("/v1/sorafs/transparency/cycles"));
    assert!(paths.contains_key("/v1/sorafs/transparency/cycles/{cycle_id_hex}"));
    assert!(
        paths.contains_key("/v1/sorafs/transparency/cycles/{cycle_id_hex}/entries/{entry_id_hex}")
    );
    assert!(paths.contains_key("/v1/sorafs/transparency/explorer"));
    assert!(paths.contains_key("/v1/sorafs/transparency/explorer/ui"));
    assert!(!paths.contains_key("/v1/sorafs/transparency/source-entries/{source_kind}"));
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_present.18")
    {
        assert!(paths.contains_key(path));
    }
    assert!(paths.contains_key("/v1/sorafs/moderation/ballots/{case_id}/{round_id}/no-show-plan"));
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_present.19")
    {
        assert!(paths.contains_key(path));
    }
    assert!(
        paths.contains_key("/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/appeal-handoff")
    );
    assert!(
        paths.contains_key("/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/operator-panel")
    );
    assert!(paths.contains_key("/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/object"));
    for evidence_path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.strings.7")
    {
        assert!(
            paths.contains_key(evidence_path),
            "missing production evidence-viewer route {evidence_path}"
        );
    }
    assert!(
        !paths.contains_key("/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/viewer-sessions")
    );
    assert!(
        !paths.contains_key("/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/viewer-access")
    );
    for retired_path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.strings.8")
    {
        assert!(
            !paths.contains_key(retired_path),
            "retired evidence-viewer audit route leaked into OpenAPI: {retired_path}"
        );
    }
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_present.20")
    {
        assert!(paths.contains_key(path));
    }
    assert!(!paths.contains_key("/v1/sns/names"));
    assert!(!paths.contains_key("/v1/sns/names/{namespace}/{literal}/renew"));
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.path_present.21")
    {
        let expected = path != "/v1/soranet/privacy/event" || cfg!(feature = "telemetry");
        assert_eq!(
            paths.contains_key(path),
            expected,
            "feature-pruned path contract drift for {path}"
        );
    }
    for path in
        openapi_contract_strings("openapi.generated_spec_includes_documented_paths.strings.9")
    {
        assert!(
            !paths.contains_key(path),
            "retired KAGEMUSHA transport leaked into OpenAPI: {path}"
        );
    }
    assert!(!paths.contains_key("/v1/attestation/issue"));
}
#[test]
fn openapi_authorities_retire_kagemusha_transport_and_proposal_inputs() {
    for (variant, document) in [
        ("package-local", canonical_document()),
        ("compiled", generate_spec()),
    ] {
        let paths = document
            .get("paths")
            .and_then(Value::as_object)
            .expect("paths section");
        assert!(
            paths.keys().all(|path| !path.starts_with("/v1/kagemusha/")),
            "retired KAGEMUSHA transport remains in {variant} OpenAPI"
        );
        assert!(
            document
                .get("tags")
                .and_then(Value::as_array)
                .expect("tags section")
                .iter()
                .all(|tag| tag
                    .get("name")
                    .and_then(Value::as_str)
                    .is_none_or(|name| !name.eq_ignore_ascii_case("KAGEMUSHA")))
        );
        let retired_product = ["line", "off"].into_iter().rev().collect::<String>();
        for suffix in ["readiness", "top-up", "redeem", "operations/{operation_id}"] {
            let retired_path = format!("/v1/{retired_product}/{suffix}");
            assert!(
                !paths.contains_key(&retired_path),
                "retired product route remains in {variant}: {retired_path}"
            );
        }
        let schemas = component_schemas(&document);
        for retired in [
            "KagemushaReadinessV1",
            "KagemushaOperationStatusV1",
            "KagemushaAuthorityStateV1",
            "KagemushaAuthorityStateRefV1",
            "OrdinaryWalletCurrentOriginalV1",
            "OrdinaryWalletCurrentRequestV1",
            "OrdinaryMintIssuerPurposeOriginalV1",
            "OrdinaryMintIssuerPurposeRequestV1",
            "GovernanceParliamentProposalPayloadKagemushaVerifierPolicyInstallV1",
            "GovernanceParliamentProposalPayloadKagemushaVerifierReleaseInstallV1",
            "GovernanceParliamentProposalPayloadKagemushaVerifierReleaseActivateV1",
            "GovernanceParliamentProposalPayloadKagemushaVerifierReleaseRetireV1",
        ] {
            assert!(
                !schemas.contains_key(retired),
                "retired input/carrier schema remains in {variant}: {retired}"
            );
        }
    }
}

#[test]
fn musubi_v1_openapi_matches_the_complete_catalog_and_declares_models() {
    let document = generate_spec();
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .expect("OpenAPI paths");
    let schemas = component_schemas(&document);
    let actual = paths
        .keys()
        .map(String::as_str)
        .filter(|path| path.starts_with("/v1/musubi/"))
        .collect::<BTreeSet<_>>();
    let expected = musubi_routes::ROUTES
        .iter()
        .map(|route| route.path())
        .collect::<BTreeSet<_>>();
    assert_eq!(musubi_routes::ROUTES.len(), 31);
    assert_eq!(actual, expected);
    let mut schema_roots = BTreeSet::new();
    for route in musubi_routes::ROUTES {
        let path = route.path();
        let path_item = paths
            .get(path)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("Musubi OpenAPI path {path}"));
        assert_eq!(
            path_item.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["post"],
            "{path} must remain POST-only"
        );
        let operation = path_item
            .get("post")
            .and_then(Value::as_object)
            .expect("Musubi POST operation");
        let request_type = operation
            .get("x-iroha-norito-request-type")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{path} exact request type"));
        let response_type = operation
            .get("x-iroha-norito-response-type")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{path} exact response type"));
        let request_schema_reference = operation
            .get("requestBody")
            .and_then(Value::as_object)
            .and_then(|request_body| request_body.get("content"))
            .and_then(Value::as_object)
            .and_then(|content| content.get("application/json"))
            .and_then(Value::as_object)
            .and_then(|media| media.get("schema"))
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("$ref"))
            .and_then(Value::as_str);
        let response_schema_reference = operation
            .get("responses")
            .and_then(Value::as_object)
            .and_then(|responses| responses.get("200"))
            .and_then(Value::as_object)
            .and_then(|response| response.get("content"))
            .and_then(Value::as_object)
            .and_then(|content| content.get("application/json"))
            .and_then(Value::as_object)
            .and_then(|media| media.get("schema"))
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("$ref"))
            .and_then(Value::as_str);
        for (model_type, schema_reference) in [
            (request_type, request_schema_reference),
            (response_type, response_schema_reference),
        ] {
            assert!(model_type.ends_with("V1"), "{path} exact V1 model");
            let expected_reference = format!("{COMPONENT_SCHEMA_REF_PREFIX}{model_type}");
            assert_eq!(
                schema_reference,
                Some(expected_reference.as_str()),
                "{path} must reference its declared exact model"
            );
            let schema = schemas
                .get(model_type)
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("{path} component schema {model_type}"));
            assert_eq!(schema.get("type").and_then(Value::as_str), Some("object"));
            assert_eq!(
                schema.get("additionalProperties").and_then(Value::as_bool),
                Some(false),
                "{path} component schema {model_type} must reject unknown fields"
            );
            schema_roots.insert(model_type.to_owned());
        }
        assert_eq!(
            operation.get(TOOL_EFFECT_EXTENSION).and_then(Value::as_str),
            Some(if path.starts_with("/v1/musubi/queries/") {
                "read"
            } else {
                "build_instruction"
            }),
            "{path} tool effect"
        );
    }
    let mut pending = schema_roots.into_iter().collect::<VecDeque<_>>();
    let mut visited = BTreeSet::new();
    while let Some(schema_name) = pending.pop_front() {
        if !visited.insert(schema_name.clone()) {
            continue;
        }
        assert_ne!(schema_name, "JsonValue", "Musubi schemas must stay typed");
        let schema = schemas
            .get(&schema_name)
            .unwrap_or_else(|| panic!("missing Musubi component schema {schema_name}"));
        let mut values = vec![schema];
        while let Some(value) = values.pop() {
            match value {
                Value::Object(object) => {
                    if object.get("type").and_then(Value::as_str) == Some("object")
                        || object.contains_key("properties")
                    {
                        assert_eq!(
                            object.get("additionalProperties").and_then(Value::as_bool),
                            Some(false),
                            "Musubi schema {schema_name} contains an open object"
                        );
                    }
                    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                        let referenced_name = reference
                            .strip_prefix(COMPONENT_SCHEMA_REF_PREFIX)
                            .unwrap_or_else(|| {
                                panic!(
                                    "Musubi schema {schema_name} uses a non-local reference {reference}"
                                )
                            });
                        assert!(
                            schemas.contains_key(referenced_name),
                            "Musubi schema {schema_name} references missing component {referenced_name}"
                        );
                        pending.push_back(referenced_name.to_owned());
                    }
                    values.extend(object.values());
                }
                Value::Array(items) => values.extend(items),
                _ => {}
            }
        }
    }
}
#[test]
fn musubi_instruction_previews_discriminate_equal_payload_shapes_by_wire_id() {
    use iroha_data_model::isi::musubi::{
        AcceptMusubiPackageMaintainerV1, RevokeMusubiPackageMaintainerInvitationV1,
    };
    let document = generate_spec();
    let schemas = component_schemas(&document);
    let variants = schemas
        .get("MusubiInstructionPreviewV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("oneOf"))
        .and_then(Value::as_array)
        .expect("Musubi instruction preview variants");
    assert_eq!(variants.len(), 19);
    let mut bindings = BTreeSet::new();
    let mut wire_ids = BTreeSet::new();
    for variant in variants {
        let variant = variant.as_object().expect("closed preview variant");
        assert_eq!(
            variant.get("additionalProperties").and_then(Value::as_bool),
            Some(false)
        );
        let properties = variant
            .get("properties")
            .and_then(Value::as_object)
            .expect("preview variant properties");
        let wire_id = properties
            .get("wire_id")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("const"))
            .and_then(Value::as_str)
            .expect("preview variant wire id");
        let payload = properties
            .get("payload")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("$ref"))
            .and_then(Value::as_str)
            .expect("preview variant payload reference");
        assert!(
            bindings.insert((wire_id.to_owned(), payload.to_owned())),
            "preview variants must not repeat a wire-id/payload binding"
        );
        assert!(
            wire_ids.insert(wire_id.to_owned()),
            "preview variants must use distinct wire ids"
        );
    }
    assert!(bindings.contains(&(
        AcceptMusubiPackageMaintainerV1::WIRE_ID.to_owned(),
        format!("{COMPONENT_SCHEMA_REF_PREFIX}AcceptMusubiPackageMaintainerV1"),
    )));
    assert!(bindings.contains(&(
        RevokeMusubiPackageMaintainerInvitationV1::WIRE_ID.to_owned(),
        format!("{COMPONENT_SCHEMA_REF_PREFIX}RevokeMusubiPackageMaintainerInvitationV1"),
    )));
    assert_ne!(
        AcceptMusubiPackageMaintainerV1::WIRE_ID,
        RevokeMusubiPackageMaintainerInvitationV1::WIRE_ID
    );
    let envelope_wire_ids = schemas
        .get("MusubiInstructionEnvelopeV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("wire_id"))
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("enum"))
        .and_then(Value::as_array)
        .expect("Musubi instruction envelope wire ids")
        .iter()
        .map(|wire_id| wire_id.as_str().expect("wire id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(envelope_wire_ids, wire_ids);
}
#[test]
fn musubi_crypto_text_schemas_do_not_impose_single_key_size_limits() {
    let document = generate_spec();
    let schemas = component_schemas(&document);
    let account = schemas
        .get("MusubiAccountIdV1")
        .and_then(Value::as_object)
        .expect("Musubi account schema");
    assert!(
        !account.contains_key("maxLength"),
        "native multisignature AccountIds are bounded by their enclosing body"
    );
    let approval = schemas
        .get("MusubiControllerApprovalV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .expect("Musubi controller approval properties");
    for field in ["public_key", "signature"] {
        assert!(
            approval
                .get(field)
                .and_then(Value::as_object)
                .is_some_and(|schema| !schema.contains_key("maxLength")),
            "Musubi approval {field} must admit native post-quantum text encodings"
        );
    }
    assert_eq!(
        approval
            .get("signature")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("pattern"))
            .and_then(Value::as_str),
        Some("^(?:[0-9A-Fa-f]{2})+$")
    );
    let provider_id = schemas
        .get("MusubiProviderIdV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("items"))
        .and_then(Value::as_object)
        .expect("Musubi provider-id hex item");
    assert_eq!(
        provider_id.get("pattern").and_then(Value::as_str),
        Some("^[0-9A-Fa-f]{64}$")
    );
}
#[test]
fn musubi_cursor_and_ordered_prefix_bounds_match_the_wire_types() {
    let document = generate_spec();
    let schemas = component_schemas(&document);
    let cursor_last_key = schemas
        .get("MusubiFinalizedCursorV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("last_key"))
        .and_then(Value::as_object)
        .expect("Musubi finalized-cursor last-key schema");
    assert_eq!(
        cursor_last_key.get("maxLength").and_then(Value::as_u64),
        Some(
            u64::try_from(iroha_data_model::musubi::MUSUBI_MAX_CURSOR_KEY_BYTES_V1)
                .expect("cursor-key bound fits u64")
        )
    );
    let ordered_prefix = schemas
        .get("MusubiOrderedPrefixV1")
        .and_then(Value::as_object)
        .expect("Musubi ordered-prefix schema");
    assert_eq!(
        ordered_prefix.get("maxLength").and_then(Value::as_u64),
        Some(
            u64::try_from(iroha_data_model::musubi::MUSUBI_MAX_ORDERED_PREFIX_BYTES_V1)
                .expect("ordered-prefix bound fits u64")
        )
    );
}
#[test]
fn musubi_chunker_text_bounds_match_the_wire_type() {
    let document = generate_spec();
    let schemas = component_schemas(&document);
    let chunker = schemas
        .get("MusubiChunkerProfileHandleV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .expect("Musubi chunker-handle properties");
    for field in ["namespace", "name", "semver"] {
        assert_eq!(
            chunker
                .get(field)
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("maxLength"))
                .and_then(Value::as_u64),
            Some(128),
            "the per-field bound must not exclude a valid 128-byte total handle"
        );
    }
}
#[test]
fn multisig_propose_schema_binds_complete_native_retail_assessment() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    let request = &schemas["MultisigProposeRequest"];
    let properties = request["properties"].as_object().unwrap();
    assert_eq!(
        properties["validation_fee_assessment"]["oneOf"][0]["$ref"].as_str(),
        Some("#/components/schemas/RetailFeeAssessmentV1")
    );
    assert_eq!(
        properties["validation_fee_assessment"]["oneOf"][1]["type"].as_str(),
        Some("null")
    );
    assert!(
        !request["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some("validation_fee_assessment"))
    );
    for retired in [
        "validation_fee_policy_version",
        "validation_fee_policy_hash",
        "validation_fee_hijiri_fee_quote_hash",
        "validation_fee_instruction_index",
        "validation_fee_transfer_entry_index",
    ] {
        assert!(
            !properties.contains_key(retired),
            "retired explicit fee field {retired}"
        );
    }
}
#[test]
fn multisig_cancel_response_requires_typed_fee_payment_property() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    let response = schemas
        .get("MultisigCancelResponse")
        .and_then(Value::as_object)
        .expect("MultisigCancelResponse schema");
    let properties = response
        .get("properties")
        .and_then(Value::as_object)
        .expect("MultisigCancelResponse properties");
    let required = response
        .get("required")
        .and_then(Value::as_array)
        .expect("MultisigCancelResponse required fields");

    assert_eq!(
        properties
            .get("fee_payment")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("$ref"))
            .and_then(Value::as_str),
        Some("#/components/schemas/FeePaymentIntent")
    );
    assert!(
        required
            .iter()
            .any(|field| field.as_str() == Some("fee_payment")),
        "MultisigCancelResponse.fee_payment must remain required"
    );
}
#[test]
fn multisig_propose_instruction_schema_matches_native_norito_json() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    let instruction = schemas
        .get("MultisigProposeInstructionInput")
        .and_then(Value::as_object)
        .expect("MultisigProposeInstructionInput schema");

    assert_eq!(
        instruction.get("type").and_then(Value::as_str),
        Some("string")
    );
    assert_eq!(
        instruction.get("contentEncoding").and_then(Value::as_str),
        Some("base64")
    );
    assert_eq!(
        instruction.get("minLength").and_then(Value::as_u64),
        Some(4)
    );
    assert_eq!(
        instruction.get("pattern").and_then(Value::as_str),
        Some("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
    );
}
#[test]
fn generated_operations_declare_tool_effects() {
    let doc = generate_spec();
    let paths = doc
        .get("paths")
        .and_then(Value::as_object)
        .expect("paths section");
    for (path, path_item) in paths {
        let path_map = path_item.as_object().expect("path item object");
        for method in ["get", "post", "put", "patch", "delete", "head", "options"] {
            let Some(operation) = path_map.get(method).and_then(Value::as_object) else {
                continue;
            };
            let effect = operation
                .get(TOOL_EFFECT_EXTENSION)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{method} {path} must declare {TOOL_EFFECT_EXTENSION}"));
            assert!(
                matches!(
                    effect,
                    "read" | "write" | "operator" | "build_instruction" | "expensive"
                ),
                "{method} {path} declared invalid effect {effect}"
            );
        }
    }
    let query = paths
        .get(route_catalog::pipeline::QUERY.path())
        .and_then(Value::as_object)
        .and_then(|path| path.get("post"))
        .and_then(Value::as_object)
        .expect("query post operation");
    assert_eq!(
        query.get(TOOL_EFFECT_EXTENSION).and_then(Value::as_str),
        Some("read")
    );
    for path in
        openapi_contract_strings("openapi.generated_operations_declare_tool_effects.strings.1")
    {
        let operation = paths
            .get(path)
            .and_then(Value::as_object)
            .and_then(|path| path.get("post"))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing multisig proposal read operation: {path}"));
        assert_eq!(
            operation.get(TOOL_EFFECT_EXTENSION).and_then(Value::as_str),
            Some("read"),
            "{path} must retain unsigned/read semantics"
        );
    }
    assert!(!paths.contains_key("/v1/multisig/proposals/list"));
    assert!(!paths.contains_key("/v1/multisig/proposals/get"));
    assert!(!paths.contains_key("/v1/multisig/proposals/search"));
    assert!(!paths.contains_key("/v1/sumeragi/pacemaker"));
    let protected_namespaces = paths
        .get("/v1/gov/protected-namespaces")
        .and_then(Value::as_object)
        .and_then(|path| path.get("post"))
        .and_then(Value::as_object)
        .expect("protected namespaces post operation");
    assert_eq!(
        protected_namespaces
            .get(TOOL_EFFECT_EXTENSION)
            .and_then(Value::as_str),
        Some("operator")
    );
    for route in RouteCatalog::new(CATALOGED_ROUTES)
        .project(
            route_catalog::CatalogProjection::OpenApi,
            crate::router::builder::compiled_route_features(),
        )
        .into_iter()
        .filter(|route| {
            route.method() == CatalogHttpMethod::Get
                && (route.surface() == ApiSurface::Operator
                    || route.authentication() == AuthenticationPolicy::OperatorSignature)
        })
    {
        let operation = paths
            .get(route.path())
            .and_then(Value::as_object)
            .and_then(|path| path.get("get"))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing operator GET operation: {}", route.path()));
        assert_eq!(
            operation.get(TOOL_EFFECT_EXTENSION).and_then(Value::as_str),
            Some("operator"),
            "operator GET must retain operator-only effect: {}",
            route.path()
        );
    }
    let musubi_publish = paths
        .get("/v1/musubi/instructions/release-publish")
        .and_then(Value::as_object)
        .and_then(|path| path.get("post"))
        .and_then(Value::as_object)
        .expect("Musubi publish instruction operation");
    assert_eq!(
        musubi_publish
            .get(TOOL_EFFECT_EXTENSION)
            .and_then(Value::as_str),
        Some("build_instruction")
    );
    let musubi_resolver = paths
        .get("/v1/musubi/queries/resolver-index")
        .and_then(Value::as_object)
        .and_then(|path| path.get("post"))
        .and_then(Value::as_object)
        .expect("Musubi resolver-index query operation");
    assert_eq!(
        musubi_resolver
            .get(TOOL_EFFECT_EXTENSION)
            .and_then(Value::as_str),
        Some("read")
    );
    for legacy_path in
        openapi_contract_strings("openapi.generated_operations_declare_tool_effects.strings.2")
    {
        assert!(
            !paths.contains_key(legacy_path),
            "legacy path survived: {legacy_path}"
        );
    }
}
#[test]
fn sumeragi_evidence_audit_contract_is_closed_and_bounded() {
    use iroha_torii_shared::sumeragi_evidence_api::{
        SUMERAGI_EVIDENCE_COUNT_RESPONSE_MAX_BYTES,
        SUMERAGI_EVIDENCE_COUNT_RESPONSE_SCHEMA_NAME_V1,
        SUMERAGI_EVIDENCE_LIST_JSON_RESPONSE_MAX_BYTES,
        SUMERAGI_EVIDENCE_LIST_NORITO_RESPONSE_MAX_BYTES,
        SUMERAGI_EVIDENCE_LIST_WIRE_RESPONSE_SCHEMA_NAME_V1,
    };

    const LIST_PATH: &str = "/v1/sumeragi/evidence";
    const COUNT_PATH: &str = "/v1/sumeragi/evidence/count";
    let assert_vary_accept = |response: &Value, label: &str| {
        let vary = &response["headers"]["Vary"];
        assert_eq!(vary["required"].as_bool(), Some(true), "{label} Vary");
        assert_eq!(
            vary["schema"]["const"].as_str(),
            Some("Accept"),
            "{label} Vary value"
        );
    };
    let assert_not_acceptable = |operation: &Map, label: &str| {
        let response = &operation["responses"]["406"];
        let content = response["content"]
            .as_object()
            .unwrap_or_else(|| panic!("{label} 406 content"));
        assert_eq!(
            content.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            ["application/json"].into_iter().collect(),
            "{label} 406 media types"
        );
        assert_eq!(
            content["application/json"]["schema"]["$ref"].as_str(),
            Some("#/components/schemas/ErrorEnvelope"),
            "{label} 406 schema"
        );
        assert_vary_accept(response, label);
        assert_eq!(
            response["headers"]["Cache-Control"]["required"].as_bool(),
            Some(true),
            "{label} 406 cache policy"
        );
        assert_eq!(
            response["headers"]["Cache-Control"]["schema"]["const"].as_str(),
            Some("private, no-store"),
            "{label} 406 cache policy value"
        );
    };
    let canonical = canonical_document();
    let compiled = generate_spec();
    for (label, document) in [("canonical", &canonical), ("compiled", &compiled)] {
        let list = openapi_operation(document, LIST_PATH, "get");
        let list_description = list
            .get("description")
            .and_then(Value::as_str)
            .expect("evidence-list description");
        assert!(list_description.contains("committed"));
        assert!(list_description.contains("node-local pending"));
        assert_eq!(
            operation_response_schema_ref(list, "200", LIST_PATH),
            "#/components/schemas/SumeragiEvidenceListResponse",
            "{label} evidence-list response"
        );
        let list_success = &list["responses"]["200"];
        let list_content = list_success["content"]
            .as_object()
            .expect("evidence-list success content");
        assert_eq!(
            list_content
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            ["application/json", "application/x-norito"]
                .into_iter()
                .collect(),
            "{label} evidence-list media types"
        );
        assert_eq!(
            list_content["application/json"]["schema"]["x-iroha-max-bytes"].as_u64(),
            Some(SUMERAGI_EVIDENCE_LIST_JSON_RESPONSE_MAX_BYTES as u64),
            "{label} evidence-list JSON cap"
        );
        let list_norito = &list_content["application/x-norito"]["schema"];
        assert_eq!(list_norito["type"].as_str(), Some("string"));
        assert_eq!(list_norito["format"].as_str(), Some("binary"));
        assert_eq!(
            list_norito["x-iroha-norito-schema"].as_str(),
            Some(SUMERAGI_EVIDENCE_LIST_WIRE_RESPONSE_SCHEMA_NAME_V1)
        );
        assert_eq!(
            list_norito["x-iroha-max-bytes"].as_u64(),
            Some(SUMERAGI_EVIDENCE_LIST_NORITO_RESPONSE_MAX_BYTES as u64)
        );
        assert!(
            list_norito["description"]
                .as_str()
                .is_some_and(|description| description
                    .contains("SumeragiEvidenceListWireResponse")
                    && description.contains("Vec<EvidenceRecord>"))
        );
        assert_vary_accept(list_success, &format!("{label} evidence-list 200"));
        assert_not_acceptable(list, &format!("{label} evidence-list"));
        let parameters = list
            .get("parameters")
            .and_then(Value::as_array)
            .expect("evidence-list query parameters");
        assert_eq!(parameters.len(), 3, "{label} evidence-list parameter count");
        let parameter = |name: &str| {
            parameters
                .iter()
                .find(|parameter| parameter.get("name").and_then(Value::as_str) == Some(name))
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("{label} evidence-list `{name}` parameter"))
        };
        let limit = parameter("limit");
        assert_eq!(limit.get("in").and_then(Value::as_str), Some("query"));
        let limit = limit
            .get("schema")
            .and_then(Value::as_object)
            .expect("evidence-list limit schema");
        assert_eq!(limit.get("minimum").and_then(Value::as_u64), Some(1));
        assert_eq!(limit.get("maximum").and_then(Value::as_u64), Some(1_000));
        assert_eq!(limit.get("default").and_then(Value::as_u64), Some(50));
        let offset = parameter("offset")
            .get("schema")
            .and_then(Value::as_object)
            .expect("evidence-list offset schema");
        assert_eq!(offset.get("minimum").and_then(Value::as_u64), Some(0));
        assert_eq!(offset.get("maximum").and_then(Value::as_u64), Some(10_000));
        assert_eq!(offset.get("default").and_then(Value::as_u64), Some(0));
        let kind = parameter("kind")
            .get("schema")
            .and_then(Value::as_object)
            .expect("evidence-list kind schema");
        assert_eq!(
            kind.get("enum").and_then(Value::as_array),
            Some(&vec![Value::from("NativeSumeragiEvidence")])
        );
        let count = openapi_operation(document, COUNT_PATH, "get");
        let count_description = count
            .get("description")
            .and_then(Value::as_str)
            .expect("evidence-count description");
        assert!(count_description.contains("committed"));
        assert!(count_description.contains("node-local pending"));
        assert_eq!(
            operation_response_schema_ref(count, "200", COUNT_PATH),
            "#/components/schemas/SumeragiEvidenceCountResponse",
            "{label} evidence-count response"
        );
        let count_success = &count["responses"]["200"];
        let count_content = count_success["content"]
            .as_object()
            .expect("evidence-count success content");
        assert_eq!(
            count_content
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            ["application/json", "application/x-norito"]
                .into_iter()
                .collect(),
            "{label} evidence-count media types"
        );
        assert_eq!(
            count_content["application/json"]["schema"]["x-iroha-max-bytes"].as_u64(),
            Some(SUMERAGI_EVIDENCE_COUNT_RESPONSE_MAX_BYTES as u64),
            "{label} evidence-count JSON cap"
        );
        let count_norito = &count_content["application/x-norito"]["schema"];
        assert_eq!(count_norito["type"].as_str(), Some("string"));
        assert_eq!(count_norito["format"].as_str(), Some("binary"));
        assert_eq!(
            count_norito["x-iroha-norito-schema"].as_str(),
            Some(SUMERAGI_EVIDENCE_COUNT_RESPONSE_SCHEMA_NAME_V1)
        );
        assert_eq!(
            count_norito["x-iroha-max-bytes"].as_u64(),
            Some(SUMERAGI_EVIDENCE_COUNT_RESPONSE_MAX_BYTES as u64)
        );
        assert_vary_accept(count_success, &format!("{label} evidence-count 200"));
        assert_not_acceptable(count, &format!("{label} evidence-count"));
    }

    let schemas = component_schemas(&canonical);
    assert_strict_object_schema(
        schemas,
        "SumeragiEvidenceAuditRecord",
        &[
            "kind",
            "class",
            "instance",
            "height",
            "epoch",
            "context_id",
            "authority_generation",
            "offenders",
            "safety_violation",
            "native_frame_hash",
            "recorded_height",
            "recorded_view",
            "recorded_ms",
            "consensus_admitted_height",
            "penalty_status",
        ],
        &[],
    );
    assert_strict_object_schema(
        schemas,
        "SumeragiEvidenceListResponse",
        &["total", "items"],
        &[],
    );
    assert_strict_object_schema(schemas, "SumeragiEvidenceCountResponse", &["count"], &[]);
    assert_strict_object_schema(
        schemas,
        "SumeragiEvidenceOffender",
        &["signer", "peer_id"],
        &[],
    );
    let record = schemas
        .get("SumeragiEvidenceAuditRecord")
        .and_then(Value::as_object)
        .expect("Sumeragi evidence audit schema");
    let properties = record
        .get("properties")
        .and_then(Value::as_object)
        .expect("Sumeragi evidence audit properties");
    assert_eq!(
        properties
            .get("penalty_status")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("$ref"))
            .and_then(Value::as_str),
        Some("#/components/schemas/SumeragiEvidencePenaltyStatus")
    );
    assert_eq!(
        properties
            .get("kind")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("const"))
            .and_then(Value::as_str),
        Some("NativeSumeragiEvidence")
    );
    let classes = properties
        .get("class")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("enum"))
        .and_then(Value::as_array)
        .expect("evidence class enum")
        .iter()
        .map(|class| class.as_str().expect("evidence class string"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        classes,
        [
            "proposal",
            "phase_vote",
            "timeout_vote",
            "invalid_proposal",
            "conflicting_certificates"
        ]
        .into_iter()
        .collect()
    );
    for hash in [
        "instance",
        "context_id",
        "authority_generation",
        "native_frame_hash",
    ] {
        assert_eq!(
            properties
                .get(hash)
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("pattern"))
                .and_then(Value::as_str),
            Some("^[0-9a-f]{64}$"),
            "{hash} must remain canonical lowercase hex"
        );
    }
    for retired in [
        "penalty_applied",
        "penalty_cancelled",
        "penalty_cancelled_at_height",
        "penalty_applied_at_height",
        "consensus_admitted_at_height",
    ] {
        assert!(
            !properties.contains_key(retired),
            "retired evidence field `{retired}` remains documented"
        );
    }
    let list_items = schemas
        .get("SumeragiEvidenceListResponse")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("items"))
        .and_then(Value::as_object)
        .expect("evidence-list items schema");
    assert_eq!(
        list_items.get("maxItems").and_then(Value::as_u64),
        Some(1_000)
    );
    assert_eq!(
        list_items
            .get("items")
            .and_then(Value::as_object)
            .and_then(|items| items.get("$ref"))
            .and_then(Value::as_str),
        Some("#/components/schemas/SumeragiEvidenceAuditRecord")
    );

    let variants = schemas
        .get("SumeragiEvidencePenaltyStatus")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("oneOf"))
        .and_then(Value::as_array)
        .expect("closed pending and applied evidence penalty variants");
    assert_eq!(variants.len(), 2);
    for status in ["pending", "applied"] {
        let variant = variants
            .iter()
            .find(|variant| {
                variant
                    .get("properties")
                    .and_then(Value::as_object)
                    .and_then(|properties| properties.get("status"))
                    .and_then(Value::as_object)
                    .and_then(|status| status.get("const"))
                    .and_then(Value::as_str)
                    == Some(status)
            })
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing `{status}` evidence penalty variant"));
        assert_eq!(
            variant.get("additionalProperties"),
            Some(&Value::Bool(false))
        );
        let required = variant
            .get("required")
            .and_then(Value::as_array)
            .expect("penalty variant required fields")
            .iter()
            .map(|field| field.as_str().expect("required field"))
            .collect::<BTreeSet<_>>();
        assert_eq!(required, ["status", "details"].into_iter().collect());
        let details = variant
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|properties| properties.get("details"))
            .and_then(Value::as_object)
            .expect("penalty variant details");
        if status == "pending" {
            assert_eq!(details.get("type").and_then(Value::as_str), Some("null"));
        } else {
            assert_eq!(
                details.get("additionalProperties"),
                Some(&Value::Bool(false))
            );
            assert_eq!(
                details.get("required").and_then(Value::as_array),
                Some(&vec![Value::from("height")])
            );
        }
    }
}
#[test]
fn retired_sumeragi_vrf_surfaces_are_absent() {
    for (surface, source) in [
        ("Torii runtime handlers", include_str!("../../routing.rs")),
        ("Torii router mounts", include_str!("../../lib.rs")),
    ] {
        assert!(
            !source.contains("handle_v1_sumeragi_vrf_"),
            "retired Sumeragi VRF handler reappeared in {surface}"
        );
        assert!(
            !source.contains("/v1/sumeragi/vrf/"),
            "retired Sumeragi VRF route reappeared in {surface}"
        );
    }
    let canonical = canonical_document();
    let paths = canonical
        .get("paths")
        .and_then(Value::as_object)
        .expect("canonical paths section");
    let evidence = paths
        .get("/v1/sumeragi/evidence")
        .and_then(Value::as_object)
        .expect("retained evidence-list path");
    assert!(evidence.contains_key("get"));
    assert!(
        !evidence.contains_key("post"),
        "retired evidence submission operation remains documented"
    );
    for retired_path in [
        "/v1/sumeragi/vrf/commit",
        "/v1/sumeragi/vrf/epoch/{epoch}",
        "/v1/sumeragi/vrf/penalties/{epoch}",
        "/v1/sumeragi/vrf/reveal",
    ] {
        assert!(
            !paths.contains_key(retired_path),
            "retired Sumeragi VRF path remains in the canonical full-profile document: {retired_path}"
        );
    }
    assert!(
        paths
            .keys()
            .all(|path| !path.starts_with("/v1/sumeragi/vrf/")),
        "canonical full-profile document must not expose any retired Sumeragi VRF path"
    );
    let compiled_paths = generate_spec()
        .get("paths")
        .and_then(Value::as_object)
        .expect("compiled paths section")
        .clone();
    assert!(
        compiled_paths
            .keys()
            .all(|path| !path.starts_with("/v1/sumeragi/vrf/")),
        "compiled OpenAPI profile must not expose retired Sumeragi VRF paths"
    );
    let schemas = canonical
        .get("components")
        .and_then(Value::as_object)
        .and_then(|components| components.get("schemas"))
        .and_then(Value::as_object)
        .expect("canonical schemas section");
    for retired_schema in [
        "SumeragiVrfCommitRequest",
        "SumeragiVrfRevealRequest",
        "SumeragiVrfPenaltiesReport",
    ] {
        assert!(
            !schemas.contains_key(retired_schema),
            "retired Sumeragi VRF schema remains documented: {retired_schema}"
        );
    }
}
#[test]
fn validation_fee_plaintext_contracts_stay_retired_and_parliament_capabilities_are_exact() {
    const RETIRED_PATH: &str = "/v1/validation-fee/proposals/{proposal_id}/plain-ballot/draft";
    for (surface, source) in [
        (
            "Torii validation-fee implementation",
            include_str!("../../validation_fee_api.rs"),
        ),
        ("Torii router mounts", include_str!("../../lib.rs")),
        (
            "canonical route catalog",
            include_str!("../../../../iroha_torii_shared/src/route_catalog.rs"),
        ),
    ] {
        assert!(
            !source.contains(RETIRED_PATH),
            "retired validation-fee PLAIN ballot draft reappeared in {surface}"
        );
        assert!(
            !source.contains("ValidationFeePlain"),
            "retired validation-fee plaintext type reappeared in {surface}"
        );
    }
    for (label, document) in [
        ("canonical", canonical_document()),
        ("compiled", generate_spec()),
    ] {
        let paths = document
            .get("paths")
            .and_then(Value::as_object)
            .expect("OpenAPI paths section");
        assert!(
            !paths.contains_key(RETIRED_PATH),
            "retired validation-fee PLAIN ballot draft remains in {label} OpenAPI"
        );
        assert!(
            paths.keys().all(|path| {
                !path.starts_with("/v1/validation-fee/") || !path.contains("plain")
            }),
            "retired validation-fee plaintext route remains in {label} OpenAPI"
        );
        let schemas = document
            .get("components")
            .and_then(Value::as_object)
            .and_then(|components| components.get("schemas"))
            .and_then(Value::as_object)
            .expect("OpenAPI schemas section");
        for retired_schema in [
            "ValidationFeePlainBallotDraftRequestV1",
            "ValidationFeePlainBallotDraftResponseV1",
            "ValidationFeePlainElectorateMemberV1",
            "ValidationFeePlainElectorateRulesV1",
            "ValidationFeePlainElectorateSnapshotV1",
        ] {
            assert!(
                !schemas.contains_key(retired_schema),
                "retired schema {retired_schema} remains in {label} OpenAPI"
            );
        }
        assert!(
            schemas
                .keys()
                .all(|name| !name.starts_with("ValidationFeePlain")),
            "retired validation-fee plaintext schema remains in {label} OpenAPI"
        );

        assert_strict_object_schema(
            schemas,
            "GovernanceCapabilitiesV1",
            &[
                "schema",
                "version",
                "network_id",
                "current_height",
                "network_prefix",
                "abi_version",
                "data_model_version",
                "approval_mode",
                "private_ballot_protocol",
                "mandatory_private_ballots",
                "proposal_backed_referendum_ballots_supported",
                "standalone_plain_ballots_supported",
                "standalone_zk_ballots_supported",
                "citizenship_asset_id",
                "citizenship_bond_amount",
                "citizenship_escrow_account",
                "voting_asset_id",
                "min_bond_amount",
                "bond_escrow_account",
                "min_enactment_delay",
                "invitation_phase_blocks",
                "registration_phase_blocks",
                "survivor_freeze_phase_blocks",
                "commitment_phase_blocks",
                "release_delay_blocks",
                "opening_phase_blocks",
                "max_ballot_retries",
                "max_corpus_entries",
                "target_body_sizes",
                "supported_proposal_kinds",
                "supported_routes",
            ],
            &[],
        );
        let capabilities = component_properties(schemas, "GovernanceCapabilitiesV1");
        for retired_field in [
            "approval_threshold_denominator",
            "approval_threshold_numerator",
            "auto_finalize_plain",
            "auto_finalize_plain_scope",
            "conviction_step_blocks",
            "max_conviction",
            "min_turnout",
            "plain_voting_enabled",
            "validation_fee_plain_electorate_rules",
            "validation_fee_plain_requires_explicit_finalization",
            "window_span",
        ] {
            assert!(
                !capabilities.contains_key(retired_field),
                "retired GovernanceCapabilitiesV1 field {retired_field} remains in {label} OpenAPI"
            );
        }
        assert_eq!(
            capabilities["approval_mode"]["const"].as_str(),
            Some("PARLIAMENT_ATTEMPT_TIMED_OVN_V1")
        );
        assert_eq!(
            capabilities["private_ballot_protocol"]["const"].as_str(),
            Some("TIMED_OVN_TLE_THRESHOLD_BLS_V1")
        );
        assert_eq!(
            capabilities["mandatory_private_ballots"]["const"].as_bool(),
            Some(true)
        );
        assert_eq!(
            capabilities["proposal_backed_referendum_ballots_supported"]["const"].as_bool(),
            Some(false)
        );
        assert_eq!(
            capabilities["standalone_zk_ballots_supported"]["const"].as_bool(),
            Some(true)
        );
    }
}
#[test]
fn pipeline_fastpq_recovery_documents_operator_auth_and_bounds() {
    use iroha_torii_shared::route_catalog::{ApiSurface, AuthenticationPolicy};
    let route = route_catalog::pipeline::RECOVERY_FASTPQ_PROOFS;
    assert_eq!(route.surface(), ApiSurface::Operator);
    assert_eq!(
        route.authentication(),
        AuthenticationPolicy::OperatorSignature
    );
    let document = generate_spec();
    let operation = openapi_operation(
        &document,
        "/v1/pipeline/recovery/{height}/fastpq-proofs",
        "get",
    );
    assert_eq!(
        operation_header_requirements(operation)
            .into_iter()
            .map(|(name, required)| {
                assert!(required, "operator signature headers must be required");
                name
            })
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "X-Iroha-Operator-Public-Key".to_owned(),
            "X-Iroha-Operator-Timestamp-Ms".to_owned(),
            "X-Iroha-Operator-Nonce".to_owned(),
            "X-Iroha-Operator-Signature".to_owned(),
        ])
    );
    let parameters = operation
        .get("parameters")
        .and_then(Value::as_array)
        .expect("FASTPQ recovery parameters");
    let parameter = |name: &str| {
        parameters
            .iter()
            .find(|parameter| parameter.get("name").and_then(Value::as_str) == Some(name))
            .unwrap_or_else(|| panic!("missing FASTPQ recovery `{name}` parameter"))
    };
    let limit_schema = parameter("limit")
        .get("schema")
        .and_then(Value::as_object)
        .expect("FASTPQ recovery limit schema");
    assert_eq!(limit_schema.get("minimum").and_then(Value::as_u64), Some(1));
    assert_eq!(
        limit_schema.get("maximum").and_then(Value::as_u64),
        Some(crate::PIPELINE_FASTPQ_RECOVERY_MAX_LIMIT as u64)
    );
    assert!(
        operation
            .get("description")
            .and_then(Value::as_str)
            .is_some_and(|description| {
                description.contains("operator-only")
                    && description.contains("replay-resistant")
                    && description.contains("Heavy reconstruction")
                    && description.contains("byte caps")
            })
    );
}
#[test]
fn signed_transaction_submission_documents_exact_preadmission_contract() {
    let document = generate_spec();
    let responses = document
        .get("paths")
        .and_then(Value::as_object)
        .and_then(|paths| paths.get(route_catalog::pipeline::TRANSACTION.path()))
        .and_then(Value::as_object)
        .and_then(|path| path.get("post"))
        .and_then(Value::as_object)
        .and_then(|post| post.get("responses"))
        .and_then(Value::as_object)
        .expect("signed transaction submission responses");
    assert_eq!(
        documented_reject_codes(responses, "400"),
        transaction_submission_bad_request_reject_codes()
    );
    assert_eq!(
        documented_reject_codes(responses, "403"),
        TRANSACTION_SUBMISSION_FORBIDDEN_REJECT_CODES
    );
    assert_eq!(
        documented_reject_codes(responses, "409"),
        TRANSACTION_SUBMISSION_CONFLICT_REJECT_CODES
    );
    assert_eq!(
        documented_reject_codes(responses, "429"),
        TRANSACTION_SUBMISSION_RATE_LIMIT_REJECT_CODES
    );
    assert_eq!(
        documented_reject_codes(responses, "503"),
        TRANSACTION_SUBMISSION_UNAVAILABLE_REJECT_CODES
    );
    for status in ["413", "415", "500", "502", "504"] {
        assert!(
            !response_documents_reject_code(responses, status),
            "transaction submission HTTP {status} must not claim a canonical reject code"
        );
    }
    let conflict_description = responses
        .get("409")
        .and_then(Value::as_object)
        .and_then(|response| response.get("description"))
        .and_then(Value::as_str)
        .expect("transaction submission 409 description");
    assert!(
        conflict_description.contains("already committed")
            && conflict_description.contains("already present"),
        "a duplicate response must be documented as existing admission state"
    );
}
#[test]
fn transaction_submission_503s_document_exact_outcome_unknown_identity() {
    let document = canonical_document();
    for path in [
        route_catalog::pipeline::TRANSACTION.path(),
        route_catalog::pipeline::TRANSACTION_ENTRYPOINT.path(),
    ] {
        let operation = openapi_operation(&document, path, "post");
        assert_eq!(
            operation_response_schema_ref(operation, "503", path),
            "#/components/schemas/ErrorEnvelope"
        );
        let unavailable = operation
            .get("responses")
            .and_then(Value::as_object)
            .and_then(|responses| responses.get("503"))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("POST {path} HTTP 503 response"));
        let description = unavailable
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("POST {path} HTTP 503 description"));
        for required_text in [
            "transaction_dispatch_outcome_unknown",
            "ErrorEnvelope.details.entrypoint_hash",
            "ErrorEnvelope.details.tx_hash",
            "does not fabricate queue-pressure",
        ] {
            assert!(
                description.contains(required_text),
                "POST {path} HTTP 503 must document {required_text}"
            );
        }
        let headers = unavailable
            .get("headers")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("POST {path} HTTP 503 headers"));
        for (header_name, detail_name) in [
            ("x-iroha-entrypoint-hash", "entrypoint_hash"),
            ("x-iroha-signed-transaction-hash", "tx_hash"),
        ] {
            let header = headers
                .get(header_name)
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("POST {path} HTTP 503 {header_name}"));
            let header_description = header
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("POST {path} HTTP 503 {header_name} description"));
            assert!(
                header_description
                    .contains("Present exactly once only for transaction_dispatch_outcome_unknown")
                    && header_description.contains(detail_name),
                "POST {path} HTTP 503 {header_name} must document its conditional exact body binding"
            );
            if path == route_catalog::pipeline::TRANSACTION_ENTRYPOINT.path()
                && header_name == "x-iroha-signed-transaction-hash"
            {
                assert!(
                    header_description.contains("External or SealedReveal")
                        && header_description.contains("inner SignedTransaction"),
                    "POST {path} HTTP 503 signed identity must be conditional on an inner signed transaction"
                );
            }
            assert_eq!(
                header
                    .get("schema")
                    .and_then(Value::as_object)
                    .and_then(|schema| schema.get("pattern"))
                    .and_then(Value::as_str),
                Some("^[0-9a-f]{64}$"),
                "POST {path} HTTP 503 {header_name} exact hash syntax"
            );
        }
    }
}
#[test]
fn signed_transaction_reject_code_inventory_matches_runtime_metadata() {
    use iroha_core::{queue::Error as QueueError, tx::SignatureRejectionCode};
    let mut acceptance_codes = vec!["transaction_rejected", "PRTRY:NTS_UNHEALTHY"];
    acceptance_codes.extend(
        [
            SignatureRejectionCode::UnsupportedAuthority,
            SignatureRejectionCode::AlgorithmNotPermitted,
            SignatureRejectionCode::InvalidSignature,
            SignatureRejectionCode::MalformedSignature,
            SignatureRejectionCode::MissingSignatures,
            SignatureRejectionCode::UnknownSigner,
            SignatureRejectionCode::InsufficientWeight,
        ]
        .map(SignatureRejectionCode::as_str),
    );
    acceptance_codes.extend([
        "ED07",
        "PRTRY:KAGEMUSHA_V1_OPERATION_CARRIER_REJECTED",
        "PRTRY:ROUTE_UNRESOLVED",
    ]);
    assert_eq!(
        acceptance_codes,
        TRANSACTION_ACCEPTANCE_BAD_REQUEST_REJECT_CODES
    );
    let forbidden = [
        QueueError::GovernanceNotPermitted {
            alias: "lane".to_owned(),
            reason: "policy".to_owned(),
        },
        QueueError::LaneComplianceDenied {
            alias: "lane".to_owned(),
            reason: "compliance".to_owned(),
        },
        QueueError::LanePrivacyProofRejected {
            alias: "lane".to_owned(),
            reason: "privacy".to_owned(),
        },
        QueueError::NexusFeeAdmissionRejected {
            code: iroha_data_model::nexus::FeeRejectionCode::BeneficiaryNotEligible,
            reason: "fee".to_owned(),
        },
    ];
    assert_eq!(
        forbidden
            .iter()
            .map(|error| crate::queue_rejection_metadata(error).0)
            .collect::<Vec<_>>(),
        TRANSACTION_SUBMISSION_FORBIDDEN_REJECT_CODES
    );
    for (errors, expected) in [
        (
            vec![QueueError::InBlockchain, QueueError::IsInQueue],
            &TRANSACTION_SUBMISSION_CONFLICT_REJECT_CODES[..2],
        ),
        (
            vec![
                QueueError::Full,
                QueueError::LatencySaturated,
                QueueError::MaximumTransactionsPerUser,
            ],
            TRANSACTION_SUBMISSION_RATE_LIMIT_REJECT_CODES,
        ),
    ] {
        assert_eq!(
            errors
                .iter()
                .map(|error| crate::queue_rejection_metadata(error).0)
                .collect::<Vec<_>>(),
            expected
        );
    }
}
#[test]
fn openapi_schemas_include_system_keys() {
    let schemas = openapi_schemas();
    for key in openapi_contract_strings("openapi.openapi_schemas_include_system_keys.strings.1") {
        assert!(schemas.contains_key(key), "schema missing {key}");
    }
    for retired in openapi_contract_strings("openapi.openapi_schemas_include_system_keys.retired") {
        assert!(
            !schemas.contains_key(retired),
            "retired schema remains: {retired}"
        );
    }
}
#[test]
fn scoped_native_original_reads_match_canonical_media_and_resource_bounds() {
    use iroha_torii_shared::{
        authority_originals::{
            NATIVE_AUTHORITY_ORIGINALS_MAX_BYTES_V1,
            NATIVE_AUTHORITY_ORIGINALS_REQUEST_MAX_BYTES_V1,
        },
        resource_names_state::NATIVE_RESOURCE_NAMES_STATE_MAX_BYTES_V1,
    };
    let document = canonical_document();
    for (descriptor, method, request_bound, response_bound) in [
        (
            route_catalog::core::RESOURCE_NAMES_STATE,
            "get",
            None,
            NATIVE_RESOURCE_NAMES_STATE_MAX_BYTES_V1,
        ),
        (
            route_catalog::core::AUTHORITY_ORIGINALS,
            "post",
            Some(NATIVE_AUTHORITY_ORIGINALS_REQUEST_MAX_BYTES_V1),
            NATIVE_AUTHORITY_ORIGINALS_MAX_BYTES_V1,
        ),
    ] {
        let operation = openapi_operation(&document, descriptor.path(), method);
        assert!(descriptor.stable_route_id().starts_with("ledger."));
        assert_eq!(
            operation
                .get("tags")
                .and_then(Value::as_array)
                .map(|tags| tags.iter().filter_map(Value::as_str).collect::<Vec<_>>()),
            Some(vec!["Ledger"]),
            "{} is a generic ledger original carrier",
            descriptor.path()
        );
        assert_eq!(
            operation.get(TOOL_EFFECT_EXTENSION).and_then(Value::as_str),
            Some("read")
        );
        assert_eq!(
            operation.get(ROUTE_AUTH_EXTENSION),
            Some(&route_auth_metadata(descriptor))
        );
        assert_eq!(
            operation.get("security"),
            standard_security_requirements(descriptor.authentication()).as_ref()
        );
        assert_eq!(
            operation
                .get("x-iroha-max-response-bytes")
                .and_then(Value::as_u64),
            Some(u64::try_from(response_bound).expect("native response ceiling")),
            "{} response bound",
            descriptor.path()
        );
        if let Some(bound) = request_bound {
            assert_eq!(
                operation
                    .get("x-iroha-max-request-bytes")
                    .and_then(Value::as_u64),
                Some(u64::try_from(bound).expect("native request ceiling"))
            );
            let content = operation
                .get("requestBody")
                .and_then(|value| value.get("content"))
                .and_then(Value::as_object)
                .expect("native request content");
            assert_eq!(
                content.keys().map(String::as_str).collect::<Vec<_>>(),
                ["application/x-norito"]
            );
            assert_eq!(
                content
                    .get("application/x-norito")
                    .and_then(|value| value.get("schema"))
                    .and_then(|value| value.get("maxLength"))
                    .and_then(Value::as_u64),
                Some(u64::try_from(bound).expect("native request frame ceiling"))
            );
        } else {
            assert!(!operation.contains_key("requestBody"));
        }
        let responses = operation
            .get("responses")
            .and_then(Value::as_object)
            .expect("native responses");
        let content = responses
            .get("200")
            .and_then(|value| value.get("content"))
            .and_then(Value::as_object)
            .expect("native original content");
        assert_eq!(
            content.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["application/json", "application/x-norito"]
        );
        assert_eq!(
            content
                .get("application/x-norito")
                .and_then(|value| value.get("schema"))
                .and_then(|value| value.get("maxLength"))
                .and_then(Value::as_u64),
            Some(u64::try_from(response_bound).expect("native output frame ceiling"))
        );
        assert!(!responses.contains_key("202"));
    }
}
