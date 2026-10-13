const OPENAPI_STATIC_CONTRACT_ASSET_VERSION: &str = "IROHA_STATIC_CONTRACT_ROWS_V1";
const OPENAPI_STATIC_CONTRACT_ASSET_LEN: usize = 95_972;
const OPENAPI_STATIC_CONTRACT_ASSET_SHA256: &str =
    "20ba8ee235447dec0c07ec0ef0996ef06b5a96c207f33b4d00130226ad2e8c71";
const OPENAPI_STATIC_CONTRACT_ASSET: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/openapi/tests/openapi_static_contracts_v1.txt"
));

fn openapi_static_contracts() -> &'static std::collections::BTreeMap<String, Vec<Vec<String>>> {
    use sha2::{Digest as _, Sha256};
    static CONTRACTS: std::sync::LazyLock<std::collections::BTreeMap<String, Vec<Vec<String>>>> =
        std::sync::LazyLock::new(|| {
            assert_eq!(
                OPENAPI_STATIC_CONTRACT_ASSET.len(),
                OPENAPI_STATIC_CONTRACT_ASSET_LEN
            );
            assert_eq!(
                hex::encode(Sha256::digest(OPENAPI_STATIC_CONTRACT_ASSET)),
                OPENAPI_STATIC_CONTRACT_ASSET_SHA256,
                "OpenAPI static contract asset digest drift"
            );
            let source = std::str::from_utf8(OPENAPI_STATIC_CONTRACT_ASSET)
                .expect("OpenAPI static contract asset must be UTF-8");
            let mut lines = source.lines();
            assert_eq!(lines.next(), Some(OPENAPI_STATIC_CONTRACT_ASSET_VERSION));
            let mut contracts = std::collections::BTreeMap::<String, Vec<Vec<String>>>::new();
            let mut closed = std::collections::BTreeSet::new();
            let mut active = "";
            for line in lines {
                let mut fields = line.split('\t');
                let id = fields.next().expect("contract section id");
                assert!(!id.is_empty(), "empty contract section id");
                if id != active {
                    assert!(closed.insert(active), "contract section is not contiguous");
                    assert!(!closed.contains(id), "duplicate contract section {id}");
                    active = id;
                }
                let row = fields
                    .map(|encoded| {
                        assert!(
                            !encoded.is_empty()
                                && encoded.bytes().all(|byte| {
                                    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
                                }),
                            "contract values must use lowercase hexadecimal"
                        );
                        String::from_utf8(hex::decode(encoded).expect("contract value hex"))
                            .expect("contract value UTF-8")
                    })
                    .collect::<Vec<_>>();
                assert!(!row.is_empty() && row.iter().all(|cell| !cell.is_empty()));
                contracts.entry(id.to_owned()).or_default().push(row);
            }
            assert!(!contracts.is_empty(), "contract asset must not be empty");
            contracts
        });
    std::sync::LazyLock::force(&CONTRACTS)
}

fn openapi_contract_rows(id: &str) -> &'static [Vec<String>] {
    openapi_static_contracts()
        .get(id)
        .unwrap_or_else(|| panic!("missing OpenAPI static contract section `{id}`"))
}

fn openapi_contract_fixed_rows<const N: usize>(
    id: &str,
) -> impl Iterator<Item = [&'static str; N]> {
    openapi_contract_rows(id).iter().map(move |row| {
        assert_eq!(row.len(), N, "OpenAPI contract row width in `{id}`");
        std::array::from_fn(|index| row[index].as_str())
    })
}

fn openapi_contract_strings(id: &str) -> impl Iterator<Item = &'static str> {
    openapi_contract_fixed_rows::<1>(id).map(|[value]| value)
}

#[test]
fn vpn_openapi_paths_are_typed_signed_and_use_runtime_success_statuses() {
    let document = generate_spec();
    let cases = openapi_contract_fixed_rows::<6>(
        "vpn.vpn_openapi_paths_are_typed_signed_and_use_runtime_success_statuses.rows.1",
    )
    .map(
        |[
            path,
            method,
            request_ref,
            success_status,
            response_ref,
            signed,
        ]| {
            (
                path,
                method,
                (request_ref != "-").then_some(request_ref),
                success_status,
                response_ref,
                signed.parse::<bool>().expect("VPN signed-route flag"),
            )
        },
    );
    let expected_auth_headers = openapi_contract_strings(
        "vpn.vpn_openapi_paths_are_typed_signed_and_use_runtime_success_statuses.strings.1",
    )
    .collect::<Vec<_>>()
    .into_iter()
    .collect::<BTreeSet<_>>();
    for (path, method, request_ref, success_status, response_ref, signed) in cases {
        let operation = openapi_operation(&document, path, method);
        match request_ref {
            Some(expected) => {
                assert_eq!(operation_request_schema_ref(operation, path), expected);
                assert_eq!(
                    operation
                        .get("requestBody")
                        .and_then(Value::as_object)
                        .and_then(|body| body.get("required")),
                    Some(&Value::Bool(true)),
                    "{method} {path} request body"
                );
            }
            None => assert!(
                operation.get("requestBody").is_none(),
                "{method} {path} must not advertise a request body"
            ),
        }
        assert_eq!(
            operation_response_schema_ref(operation, success_status, path),
            response_ref,
            "{method} {path} response"
        );
        let responses = operation
            .get("responses")
            .and_then(Value::as_object)
            .expect("operation responses");
        assert!(
            responses.contains_key(success_status),
            "{method} {path} must advertise HTTP {success_status}"
        );
        if method == "post" {
            assert!(
                !responses.contains_key("200"),
                "{method} {path} must not advertise the retired creation status"
            );
        }
        let auth_headers = operation
            .get("parameters")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|parameter| parameter.get("in").and_then(Value::as_str) == Some("header"))
            .map(|parameter| {
                parameter
                    .get("name")
                    .and_then(Value::as_str)
                    .expect("header parameter name")
            })
            .collect::<BTreeSet<_>>();
        if signed {
            assert_eq!(auth_headers, expected_auth_headers, "{method} {path} auth");
        } else {
            assert!(
                auth_headers.is_empty(),
                "{method} {path} must remain a public route"
            );
        }
    }
    let session_operations = document
        .get("paths")
        .and_then(Value::as_object)
        .and_then(|paths| paths.get("/v1/vpn/sessions/{session_id}"))
        .and_then(Value::as_object)
        .expect("VPN session detail operations");
    assert!(
        !session_operations.contains_key("delete"),
        "Torii must not publish a local-only deletion operation that cannot revoke the relay ticket or on-chain lease"
    );
    let operation = openapi_operation(&document, "/v1/vpn/sessions/{session_id}", "get");
    let session_id = operation
        .get("parameters")
        .and_then(Value::as_array)
        .and_then(|parameters| {
            parameters.iter().find(|parameter| {
                parameter.get("name").and_then(Value::as_str) == Some("session_id")
                    && parameter.get("in").and_then(Value::as_str) == Some("path")
            })
        })
        .expect("session_id path parameter");
    assert_eq!(
        session_id
            .get("schema")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("pattern"))
            .and_then(Value::as_str),
        Some("^[0-9a-f]{32}$"),
        "GET session id must use the canonical lowercase 16-byte hex form"
    );
}
#[test]
fn vpn_openapi_schemas_are_strict_and_use_canonical_quantities() {
    let document = generate_spec();
    let schemas = component_schemas(&document);
    assert_strict_object_schema(
        schemas,
        "VpnTxInstruction",
        &["wire_id", "payload_hex"],
        &[],
    );
    assert_strict_object_schema(
        schemas,
        "VpnQuoteCreateRequest",
        &["metering_public_key_hex"],
        &["exit_class"],
    );
    assert_strict_object_schema(
        schemas,
        "VpnSessionCreateRequest",
        &["quote_id", "payment_tx_hash", "metering_public_key_hex"],
        &["exit_class"],
    );
    assert_strict_object_schema(
        schemas,
        "VpnReceiptSubmitRequest",
        &["relay_receipt_hex", "client_voucher_hex"],
        &["lease_id_hex"],
    );
    let profile_fields = openapi_contract_strings(
        "vpn.vpn_openapi_schemas_are_strict_and_use_canonical_quantities.strings.1",
    )
    .collect::<Vec<_>>();
    assert_strict_object_schema(schemas, "VpnProfileResponse", &profile_fields, &[]);
    let quote_fields = openapi_contract_strings(
        "vpn.vpn_openapi_schemas_are_strict_and_use_canonical_quantities.strings.2",
    )
    .collect::<Vec<_>>();
    assert_strict_object_schema(schemas, "VpnQuoteResponse", &quote_fields, &[]);
    let session_fields = openapi_contract_strings(
        "vpn.vpn_openapi_schemas_are_strict_and_use_canonical_quantities.strings.3",
    )
    .collect::<Vec<_>>();
    assert_strict_object_schema(schemas, "VpnSessionResponse", &session_fields, &[]);
    for [schema_name, field] in openapi_contract_fixed_rows::<2>(
        "vpn.vpn_openapi_schemas_are_strict_and_use_canonical_quantities.rows.1",
    ) {
        let pattern = schemas
            .get(schema_name)
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .and_then(|properties| properties.get(field))
            .and_then(Value::as_object)
            .and_then(|property| property.get("pattern"))
            .and_then(Value::as_str);
        assert_eq!(
            pattern,
            Some("^[0-9a-f]{64}$"),
            "{schema_name}.{field} must advertise canonical lowercase hex"
        );
    }
    for [schema_name, field, pattern] in openapi_contract_fixed_rows::<3>(
        "vpn.vpn_openapi_schemas_are_strict_and_use_canonical_quantities.rows.2",
    ) {
        let actual = schemas
            .get(schema_name)
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .and_then(|properties| properties.get(field))
            .and_then(Value::as_object)
            .and_then(|property| property.get("pattern"))
            .and_then(Value::as_str);
        assert_eq!(
            actual,
            Some(pattern),
            "{schema_name}.{field} must continue accepting mixed-case prefixed input"
        );
    }
    let profile_mldsa = schemas
        .get("VpnProfileResponse")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("relay_mldsa65_public_key_hex"))
        .and_then(Value::as_object)
        .expect("VPN profile ML-DSA-65 trust schema");
    assert_eq!(
        profile_mldsa.get("pattern").and_then(Value::as_str),
        Some("^(?:|[0-9a-f]{3904})$")
    );
    assert_eq!(
        profile_mldsa.get("maxLength").and_then(Value::as_u64),
        Some(3904)
    );
    for schema_name in ["VpnQuoteResponse", "VpnSessionResponse"] {
        let mldsa = schemas
            .get(schema_name)
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .and_then(|properties| properties.get("relay_mldsa65_public_key_hex"))
            .and_then(Value::as_object)
            .expect("VPN ML-DSA-65 trust schema");
        assert_eq!(
            mldsa.get("pattern").and_then(Value::as_str),
            Some("^[0-9a-f]{3904}$"),
            "{schema_name} must advertise canonical ML-DSA-65 public-key hex"
        );
        assert_eq!(mldsa.get("minLength").and_then(Value::as_u64), Some(3904));
        assert_eq!(mldsa.get("maxLength").and_then(Value::as_u64), Some(3904));
    }
    let helper_ticket = schemas
        .get("VpnSessionResponse")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("helper_ticket_hex"))
        .and_then(Value::as_object)
        .expect("VPN helper ticket schema");
    assert_eq!(
        helper_ticket.get("pattern").and_then(Value::as_str),
        Some("^[0-9a-f]{1576}$")
    );
    assert_eq!(
        helper_ticket.get("minLength").and_then(Value::as_u64),
        Some(1576)
    );
    assert_eq!(
        helper_ticket.get("maxLength").and_then(Value::as_u64),
        Some(1576)
    );
    let receipt_fields = openapi_contract_strings(
        "vpn.vpn_openapi_schemas_are_strict_and_use_canonical_quantities.strings.4",
    )
    .collect::<Vec<_>>();
    assert_strict_object_schema(schemas, "VpnReceiptResponse", &receipt_fields, &[]);
    assert_strict_object_schema(schemas, "VpnReceiptListResponse", &["items", "total"], &[]);
    for schema_name in ["VpnSessionResponse", "VpnReceiptResponse"] {
        assert_eq!(
            schemas
                .get(schema_name)
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("properties"))
                .and_then(Value::as_object)
                .and_then(|properties| properties.get("session_id"))
                .and_then(Value::as_object)
                .and_then(|property| property.get("pattern"))
                .and_then(Value::as_str),
            Some("^[0-9a-f]{32}$"),
            "{schema_name}.session_id must advertise canonical lowercase 16-byte hex"
        );
    }
    for [schema_name, field] in openapi_contract_fixed_rows::<2>(
        "vpn.vpn_openapi_schemas_are_strict_and_use_canonical_quantities.rows.3",
    ) {
        assert_eq!(
            schemas
                .get(schema_name)
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("properties"))
                .and_then(Value::as_object)
                .and_then(|properties| properties.get(field))
                .and_then(Value::as_object)
                .and_then(|property| property.get("minLength"))
                .and_then(Value::as_u64),
            Some(1),
            "{schema_name}.{field} must reject empty runtime identifiers"
        );
    }
    for [schema_name, field] in openapi_contract_fixed_rows::<2>(
        "vpn.vpn_openapi_schemas_are_strict_and_use_canonical_quantities.rows.4",
    ) {
        assert_eq!(
            schemas
                .get(schema_name)
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("properties"))
                .and_then(Value::as_object)
                .and_then(|properties| properties.get(field))
                .and_then(Value::as_object)
                .and_then(|property| property.get("minimum"))
                .and_then(Value::as_u64),
            Some(0),
            "{schema_name}.{field} must advertise its unsigned lower bound"
        );
    }
    let quantity = schemas
        .get("Quantity")
        .and_then(Value::as_object)
        .expect("Quantity schema");
    assert_eq!(quantity.get("type").and_then(Value::as_str), Some("string"));
    for row in openapi_contract_rows(
        "vpn.vpn_openapi_schemas_are_strict_and_use_canonical_quantities.rows.6",
    ) {
        let (schema_name, fee_fields) = row.split_first().expect("VPN fee-field contract row");
        let properties = schemas
            .get(schema_name)
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{schema_name} properties"));
        for field in fee_fields {
            assert_eq!(
                properties
                    .get(field)
                    .and_then(Value::as_object)
                    .and_then(|property| property.get("$ref"))
                    .and_then(Value::as_str),
                Some("#/components/schemas/Quantity"),
                "{schema_name}.{field}"
            );
        }
    }
    for name in openapi_contract_strings(
        "vpn.vpn_openapi_schemas_are_strict_and_use_canonical_quantities.strings.5",
    ) {
        assert_no_retired_vpn_fee_fields(
            schemas.get(name).unwrap_or_else(|| panic!("{name} schema")),
            name,
        );
    }
    let vpn_paths = document
        .get("paths")
        .and_then(Value::as_object)
        .expect("paths");
    for (path, path_item) in vpn_paths {
        if path.starts_with("/v1/vpn/") {
            assert_no_retired_vpn_fee_fields(path_item, path);
        }
    }
}
#[test]
fn sorafs_tag_documents_exact_canonical_quantity_contract() {
    let tags = tags_section().as_array().expect("tags array").clone();
    let description = tags
        .iter()
        .find(|tag| tag.get("name").and_then(Value::as_str) == Some("SoraFS"))
        .and_then(|tag| tag.get("description"))
        .and_then(Value::as_str)
        .expect("SoraFS tag description");
    for required in openapi_contract_strings(
        "vpn.sorafs_tag_documents_exact_canonical_quantity_contract.strings.1",
    ) {
        assert!(
            description.contains(required),
            "SoraFS quantity contract must document {required}"
        );
    }
}
#[test]
fn tags_section_includes_push_tag() {
    let tags = match tags_section() {
        Value::Array(tags) => tags,
        _ => panic!("tags section should be an array"),
    };
    let mut has_push = false;
    let mut has_soracloud = false;
    let mut has_vpn = false;
    for tag in tags {
        let Some(obj) = tag.as_object() else { continue };
        if obj.get("name").and_then(Value::as_str) == Some("Push") {
            has_push = true;
        }
        if obj.get("name").and_then(Value::as_str) == Some("Soracloud") {
            has_soracloud = true;
        }
        if obj.get("name").and_then(Value::as_str) == Some("VPN") {
            has_vpn = true;
        }
    }
    assert!(has_push, "tags should include Push");
    assert!(has_soracloud, "tags should include Soracloud");
    assert!(has_vpn, "tags should include VPN");
}
#[test]
fn detached_asset_transfer_openapi_is_strict_and_two_phase() {
    let doc = generate_spec();
    let operation = doc
        .get("paths")
        .and_then(Value::as_object)
        .and_then(|paths| paths.get("/v1/assets/transfer"))
        .and_then(Value::as_object)
        .and_then(|path| path.get("post"))
        .and_then(Value::as_object)
        .expect("detached asset transfer POST operation");
    let request_ref = operation
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
        request_ref,
        Some("#/components/schemas/AssetTransferRequest")
    );
    let response_ref = operation
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
    assert_eq!(
        response_ref,
        Some("#/components/schemas/AssetTransferResponse")
    );
    assert!(
        operation
            .get("description")
            .and_then(Value::as_str)
            .is_some_and(
                |description| description.contains("exact signed transaction is idempotent")
            ),
        "asset transfer operation must document exact signed replay semantics"
    );
    let schemas = doc
        .get("components")
        .and_then(Value::as_object)
        .and_then(|components| components.get("schemas"))
        .and_then(Value::as_object)
        .expect("schemas");
    let request = schemas
        .get("AssetTransferRequest")
        .and_then(Value::as_object)
        .expect("asset transfer request schema");
    assert_eq!(
        request.get("additionalProperties"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        request.get("oneOf").and_then(Value::as_array).map(Vec::len),
        Some(2)
    );
    let properties = request
        .get("properties")
        .and_then(Value::as_object)
        .expect("asset transfer request properties");
    for field in openapi_contract_strings(
        "vpn.detached_asset_transfer_openapi_is_strict_and_two_phase.strings.1",
    ) {
        assert!(properties.contains_key(field), "missing `{field}`");
    }
    for forbidden in openapi_contract_strings(
        "vpn.detached_asset_transfer_openapi_is_strict_and_two_phase.strings.2",
    ) {
        assert!(
            !properties.contains_key(forbidden),
            "legacy signing field `{forbidden}` must not be documented"
        );
    }
    assert_eq!(
        schemas
            .get("AssetTransferResponse")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("additionalProperties")),
        Some(&Value::Bool(false))
    );
    let receipt_statuses = schemas
        .get("AssetTransferReceipt")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("status"))
        .and_then(Value::as_object)
        .and_then(|status| status.get("enum"))
        .and_then(Value::as_array)
        .expect("asset transfer receipt status enum");
    for status in ["pending_signature", "submitted", "applied"] {
        assert!(
            receipt_statuses
                .iter()
                .any(|value| value.as_str() == Some(status)),
            "asset transfer receipt status enum must include `{status}`"
        );
    }
}
#[test]
fn retired_ivm_binding_preparation_and_proof_jobs_are_absent_from_openapi() {
    let doc = generate_spec();
    let paths = doc.get("paths").and_then(Value::as_object).expect("paths");
    assert!(!paths.contains_key("/v1/zk/ivm/derive"));
    assert!(!paths.contains_key("/v1/zk/ivm/prove"));
    assert!(!paths.contains_key("/v1/zk/ivm/prove/{job_id}"));
    let schemas = doc
        .get("components")
        .and_then(Value::as_object)
        .and_then(|components| components.get("schemas"))
        .and_then(Value::as_object)
        .expect("schemas");
    for retired in [
        "ZkIvmProveRequest",
        "ZkIvmProveJob",
        "ZkIvmProveJobDone",
        "ZkIvmCompactProof",
    ] {
        assert!(!schemas.contains_key(retired), "retired schema {retired}");
    }
}
#[test]
fn retired_server_contract_deployment_paths_are_absent() {
    let document = generate_spec();
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .expect("OpenAPI paths");
    for retired_path in openapi_contract_strings(
        "vpn.retired_server_contract_deployment_paths_are_absent.strings.1",
    ) {
        assert!(
            !paths.contains_key(retired_path),
            "retired server-side contract deployment path leaked into OpenAPI: {retired_path}"
        );
    }
}
#[test]
fn governance_mutation_openapi_is_typed_closed_and_secret_free() {
    let document = generate_spec();
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .expect("OpenAPI paths");
    let schemas = document
        .get("components")
        .and_then(Value::as_object)
        .and_then(|components| components.get("schemas"))
        .and_then(Value::as_object)
        .expect("OpenAPI schemas");
    assert!(
        !paths.contains_key("/v1/gov/ballots/zk"),
        "the legacy ZK ballot route must not enter the first-release OpenAPI"
    );
    assert!(
        !schemas.contains_key("GovernanceZkBallotRequestV1")
            && !schemas.contains_key("GovernanceZkPublicInputsV1"),
        "legacy ZK ballot schemas must not enter the first-release OpenAPI"
    );
    let capabilities_path = route_catalog::runtime_governance::GOV_CAPABILITIES.path();
    let capabilities_operation = openapi_operation(&document, capabilities_path, "get");
    assert_eq!(
        operation_response_schema_ref(capabilities_operation, "200", capabilities_path),
        "#/components/schemas/GovernanceCapabilitiesV1"
    );
    let capability_properties = schemas
        .get("GovernanceCapabilitiesV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .expect("governance capabilities properties");
    assert_eq!(
        capability_properties
            .get("network_id")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("$ref"))
            .and_then(Value::as_str),
        Some("#/components/schemas/NetworkId")
    );
    assert!(!capability_properties.contains_key("chain_id"));
    assert!(!capability_properties.contains_key("genesis_hash"));
    let cases = openapi_contract_rows("vpn.governance_mutation.request_property_rows")
        .iter()
        .map(|row| {
            let [path, schema_name, expected_properties @ ..] = row.as_slice() else {
                panic!("governance request-property contract row")
            };
            (
                path.as_str(),
                schema_name.as_str(),
                expected_properties
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            )
        });
    for path in openapi_contract_strings(
        "vpn.governance_mutation_openapi_is_typed_closed_and_secret_free.strings.1",
    ) {
        let operation = openapi_operation(&document, path, "post");
        assert!(
            operation.get("x-iroha-canonical-auth-v1").is_some(),
            "POST {path} must publish canonical one-shot authentication"
        );
        let description = operation
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(
            description.contains("exact-network request authority"),
            "POST {path} must document exact-network authentication"
        );
        let headers = operation_header_requirements(operation);
        for expected in openapi_contract_strings(
            "vpn.governance_mutation_openapi_is_typed_closed_and_secret_free.strings.2",
        ) {
            assert!(
                headers.iter().any(|(name, _required)| name == expected),
                "POST {path} must document canonical auth header `{expected}`"
            );
        }
    }
    for (path, schema_name, expected_properties) in cases {
        let request_ref = paths
            .get(path)
            .and_then(Value::as_object)
            .and_then(|item| item.get("post"))
            .and_then(Value::as_object)
            .and_then(|operation| operation.get("requestBody"))
            .and_then(Value::as_object)
            .and_then(|body| body.get("content"))
            .and_then(Value::as_object)
            .and_then(|content| content.get("application/json"))
            .and_then(Value::as_object)
            .and_then(|media| media.get("schema"))
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("$ref"))
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing governance request schema for `{path}`"));
        assert_eq!(
            request_ref,
            format!("#/components/schemas/{schema_name}"),
            "{path}"
        );
        let schema = schemas
            .get(schema_name)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing `{schema_name}`"));
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&Value::Bool(false)),
            "{schema_name}"
        );
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing `{schema_name}` properties"));
        let mut actual_properties = properties.keys().map(String::as_str).collect::<Vec<_>>();
        actual_properties.sort_unstable();
        assert_eq!(actual_properties, expected_properties, "{schema_name}");
    }
    for (schema_name, expected_required) in
        openapi_contract_rows("vpn.governance_mutation.required_field_rows")
            .iter()
            .map(|row| {
                let (schema_name, required) = row.split_first().expect("governance required row");
                (
                    schema_name.as_str(),
                    required.iter().map(String::as_str).collect::<Vec<_>>(),
                )
            })
    {
        let schema = schemas
            .get(schema_name)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing `{schema_name}`"));
        let mut actual_required = schema
            .get("required")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("missing `{schema_name}` required set"))
            .iter()
            .map(|value| value.as_str().expect("required field is a string"))
            .collect::<Vec<_>>();
        actual_required.sort_unstable();
        assert_eq!(actual_required, expected_required, "{schema_name}");
    }
    let deploy = schemas
        .get("DeployContractProposalDraftRequestV1")
        .and_then(Value::as_object)
        .expect("deploy request schema");
    assert_eq!(
        deploy.get("oneOf").and_then(Value::as_array).map(Vec::len),
        Some(2),
        "deploy target must be exactly one address or alias"
    );
    for target_case in deploy
        .get("oneOf")
        .and_then(Value::as_array)
        .expect("deploy target variants")
    {
        let target_case = target_case.as_object().expect("deploy target variant");
        let required = target_case
            .get("required")
            .and_then(Value::as_array)
            .and_then(|required| required.first())
            .and_then(Value::as_str)
            .expect("selected deploy target");
        assert_eq!(
            target_case
                .get("properties")
                .and_then(Value::as_object)
                .and_then(|properties| properties.get(required))
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("minLength"))
                .and_then(Value::as_u64),
            Some(1),
            "selected deploy target `{required}` must be nonempty"
        );
    }
    let deploy_properties = deploy
        .get("properties")
        .and_then(Value::as_object)
        .expect("deploy request properties");
    assert_eq!(
        deploy_properties
            .get("abi_version")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("const"))
            .and_then(Value::as_u64),
        Some(1),
        "first-release deploy requests must advertise exactly ABI V1"
    );
    assert!(!deploy_properties.contains_key("window"));
    assert!(!deploy_properties.contains_key("mode"));
    for field in ["code_hash", "abi_hash"] {
        assert_eq!(
            deploy_properties
                .get(field)
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("$ref"))
                .and_then(Value::as_str),
            Some("#/components/schemas/GovernanceProposalHex32V1"),
            "deploy `{field}` must use the exact typed 32-byte hash schema"
        );
    }
    let ballot = schemas
        .get("GovernanceBallotProofV1")
        .and_then(Value::as_object)
        .expect("GovernanceBallotProofV1 schema");
    assert_eq!(
        ballot.get("additionalProperties"),
        Some(&Value::Bool(false))
    );
    let mut ballot_properties = ballot
        .get("properties")
        .and_then(Value::as_object)
        .expect("GovernanceBallotProofV1 properties")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    ballot_properties.sort_unstable();
    assert_eq!(
        ballot_properties,
        [
            "amount",
            "backend",
            "direction",
            "duration_blocks",
            "envelope_bytes",
            "nullifier",
            "owner",
            "root_hint",
        ]
    );
    let u64_maximum = Value::from(u64::MAX);
    for [schema_name, field] in openapi_contract_fixed_rows::<2>(
        "vpn.governance_mutation_openapi_is_typed_closed_and_secret_free.rows.1",
    ) {
        assert_eq!(
            schemas
                .get(schema_name)
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("properties"))
                .and_then(Value::as_object)
                .and_then(|properties| properties.get(field))
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("maximum")),
            Some(&u64_maximum),
            "{schema_name}.{field} must publish the exact u64 maximum"
        );
    }
    assert_eq!(
        schemas
            .get("GovernancePlainBallotRequestV1")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .and_then(|properties| properties.get("duration_blocks"))
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("pattern"))
            .and_then(Value::as_str),
        Some(GOVERNANCE_U64_DECIMAL_PATTERN),
        "plain-ballot duration must publish the exact canonical u64 grammar"
    );
    for schema_name in openapi_contract_strings(
        "vpn.governance_mutation_openapi_is_typed_closed_and_secret_free.strings.3",
    ) {
        assert_eq!(
            schemas
                .get(schema_name)
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("properties"))
                .and_then(Value::as_object)
                .and_then(|properties| properties.get("backend"))
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("pattern"))
                .and_then(Value::as_str),
            Some(GOVERNANCE_EXACT_TOKEN_PATTERN),
            "{schema_name}.backend must be an exact nonempty token"
        );
    }
    for schema_name in openapi_contract_strings(
        "vpn.governance_mutation_openapi_is_typed_closed_and_secret_free.strings.4",
    ) {
        let properties = schemas
            .get(schema_name)
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing `{schema_name}` properties"));
        assert_eq!(
            properties
                .get("network_id")
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("$ref"))
                .and_then(Value::as_str),
            Some("#/components/schemas/NetworkId"),
            "{schema_name}.network_id must use the exact typed network identity"
        );
        assert!(
            !properties.contains_key("chain_id"),
            "{schema_name} must reject the retired chain_id key"
        );
    }
    for [schema_name, field] in openapi_contract_fixed_rows::<2>(
        "vpn.governance_mutation_openapi_is_typed_closed_and_secret_free.rows.2",
    ) {
        assert_eq!(
            schemas
                .get(schema_name)
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("properties"))
                .and_then(Value::as_object)
                .and_then(|properties| properties.get(field))
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("pattern"))
                .and_then(Value::as_str),
            Some(GOVERNANCE_SELECTOR_V1_PATTERN),
            "{schema_name}.{field} must publish the canonical V1 selector grammar"
        );
        assert_eq!(
            schemas
                .get(schema_name)
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("properties"))
                .and_then(Value::as_object)
                .and_then(|properties| properties.get(field))
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("maxLength"))
                .and_then(Value::as_u64),
            Some(iroha_data_model::governance::GOVERNANCE_SELECTOR_V1_MAX_BYTES as u64),
            "{schema_name}.{field} must publish the selector byte ceiling"
        );
    }
    for retired_schema in [
        "GovernanceParliamentBallotRequestV1",
        "GovernanceFinalizeRequestV1",
        "GovernanceEnactRequestV1",
    ] {
        assert!(
            !schemas.contains_key(retired_schema),
            "retired proposal-backed governance schema {retired_schema} must not remain in OpenAPI"
        );
    }
    let provenance_properties = schemas
        .get("GovernanceManifestProvenanceV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .expect("manifest provenance properties");
    for field in ["signer", "signature"] {
        assert_eq!(
            provenance_properties
                .get(field)
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("type"))
                .and_then(Value::as_str),
            Some("string"),
            "manifest provenance `{field}` must be a typed public string"
        );
    }
    assert_eq!(
        schemas
            .get("GovernancePlainBallotRequestV1")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .and_then(|properties| properties.get("duration_blocks"))
            .and_then(Value::as_object)
            .and_then(|duration| duration.get("type"))
            .and_then(Value::as_str),
        Some("string")
    );
    assert_eq!(
        schemas
            .get("GovernanceZkBallotEnvelopeRequestV1")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .and_then(|properties| properties.get("direction"))
            .and_then(Value::as_object)
            .and_then(|direction| direction.get("enum")),
        Some(&norito::json!(["Aye", "Nay", "Abstain", null])),
        "ZK-v1 direction must match the closed runtime ballot enum"
    );
    for schema_name in openapi_contract_strings(
        "vpn.governance_mutation_openapi_is_typed_closed_and_secret_free.strings.5",
    ) {
        let encoded = norito::json::to_json(
            schemas
                .get(schema_name)
                .unwrap_or_else(|| panic!("missing `{schema_name}`")),
        )
        .expect("schema JSON");
        for forbidden in openapi_contract_strings(
            "vpn.governance_mutation_openapi_is_typed_closed_and_secret_free.strings.6",
        ) {
            assert!(
                !encoded.contains(forbidden),
                "`{schema_name}` leaked retired signing field `{forbidden}`"
            );
        }
    }
    for schema_name in openapi_contract_strings(
        "vpn.governance_mutation_openapi_is_typed_closed_and_secret_free.strings.7",
    ) {
        assert!(
            !schemas
                .get(schema_name)
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("properties"))
                .and_then(Value::as_object)
                .is_some_and(|properties| properties.contains_key("authority")),
            "`{schema_name}` must not restore retired server-side authority"
        );
    }
}

#[test]
fn governance_digest_and_parliament_phase_schemas_are_exact() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    let digest = schemas
        .get("GovernanceProposalHex32V1")
        .and_then(Value::as_object)
        .expect("GovernanceProposalHex32V1 schema");
    assert_eq!(digest.get("type").and_then(Value::as_str), Some("string"));
    assert_eq!(digest.get("minLength").and_then(Value::as_u64), Some(64));
    assert_eq!(digest.get("maxLength").and_then(Value::as_u64), Some(64));
    assert_eq!(
        digest.get("pattern").and_then(Value::as_str),
        Some(GOVERNANCE_LOWER_HEX32_PATTERN)
    );

    assert_strict_object_schema(
        schemas,
        "GovernanceParliamentAdvanceBodyPhasePayloadV1",
        &["body_instance_id", "target"],
        &[],
    );
    let properties = component_properties(schemas, "GovernanceParliamentAdvanceBodyPhasePayloadV1");
    assert_eq!(
        properties["body_instance_id"]["$ref"].as_str(),
        Some("#/components/schemas/GovernanceParliamentDigest32V1")
    );
    assert_eq!(
        properties["target"]["$ref"].as_str(),
        Some("#/components/schemas/GovernanceParliamentDeliberationPhaseV1")
    );
    assert!(
        !schemas.contains_key("GovernanceParliamentBallotRequestV1"),
        "retired parliament ballot request alias must not mask the phase-transition payload"
    );
}

#[test]
fn parliament_attempt_openapi_is_closed_authenticated_and_bounded() {
    let document = generate_spec();
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .expect("OpenAPI paths");
    let schemas = document
        .get("components")
        .and_then(Value::as_object)
        .and_then(|components| components.get("schemas"))
        .and_then(Value::as_object)
        .expect("OpenAPI schemas");

    for retired in [
        "/v1/gov/enact",
        "/v1/gov/finalize",
        "/v1/gov/parliament/ballots",
    ] {
        assert!(
            !paths.contains_key(retired),
            "retired proposal-backed path leaked into OpenAPI: {retired}"
        );
    }

    let routes = [
        (
            route_catalog::runtime_governance::GOV_PROPOSE_DEPLOY.path(),
            "post",
            "DeployContractProposalDraftRequestV1",
            "DeployContractProposalDraftResponseV1",
            "write",
        ),
        (
            route_catalog::runtime_governance::GOV_PROPOSE_SCCP.path(),
            "post",
            "SccpRouteGovernanceProposalDraftRequestV1",
            "SccpRouteGovernanceProposalDraftResponseV1",
            "write",
        ),
        (
            route_catalog::runtime_governance::GOV_PARLIAMENT_ATTEMPT_DRAFT.path(),
            "post",
            "GovernanceParliamentAttemptDraftRequestV1",
            "GovernanceParliamentAttemptDraftResponseV1",
            "write",
        ),
        (
            route_catalog::runtime_governance::GOV_PARLIAMENT_ATTEMPT_READ.path(),
            "get",
            "",
            "GovernanceParliamentAttemptReadResponseV1",
            "read",
        ),
        (
            route_catalog::runtime_governance::GOV_PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_READ.path(),
            "get",
            "",
            "GovernanceParliamentTimedOvnCastingContextResponseV1",
            "read",
        ),
        (
            route_catalog::runtime_governance::GOV_PARLIAMENT_TLE_RELEASE_CONTEXT_READ.path(),
            "get",
            "",
            "GovernanceParliamentTleReleaseContextResponseV1",
            "read",
        ),
        (
            route_catalog::runtime_governance::GOV_PARLIAMENT_TLE_PARTIAL_RELEASE.path(),
            "post",
            "",
            "GovernanceParliamentTlePartialReleaseShareV1",
            "write",
        ),
        (
            route_catalog::runtime_governance::GOV_PARLIAMENT_TRANSITION_DRAFT.path(),
            "post",
            "GovernanceParliamentTransitionDraftRequestV1",
            "GovernanceParliamentTransitionDraftResponseV1",
            "write",
        ),
    ];
    for (path, method, request_schema, response_schema, effect) in routes {
        let operation = openapi_operation(&document, path, method);
        assert!(
            operation.get("x-iroha-canonical-auth-v1").is_some(),
            "{method} {path} must publish canonical account authentication"
        );
        assert_eq!(
            operation.get("x-iroha-tool-effect").and_then(Value::as_str),
            Some(effect),
            "{method} {path} effect"
        );
        assert_eq!(
            operation_response_schema_ref(operation, "200", path),
            format!("#/components/schemas/{response_schema}")
        );
        if method == "post" && !request_schema.is_empty() {
            let expected_request_ref = format!("#/components/schemas/{request_schema}");
            assert_eq!(
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
                    .and_then(Value::as_str),
                Some(expected_request_ref.as_str()),
                "{method} {path} request schema"
            );
        } else if method == "post" {
            assert!(
                operation.get("requestBody").is_none(),
                "{method} {path} must have exactly zero request-body bytes"
            );
        }
        let response_headers = operation
            .get("responses")
            .and_then(Value::as_object)
            .and_then(|responses| responses.get("200"))
            .and_then(Value::as_object)
            .and_then(|response| response.get("headers"))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{method} {path} private response headers"));
        assert_eq!(
            response_headers
                .get("Cache-Control")
                .and_then(Value::as_object)
                .and_then(|header| header.get("schema"))
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("const"))
                .and_then(Value::as_str),
            Some("private, no-store")
        );
        assert!(response_headers.contains_key("Vary"));
    }

    let casting_proof_path =
        route_catalog::runtime_governance::GOV_PARLIAMENT_TIMED_OVN_CASTING_PROOF.path();
    let casting_proof = openapi_operation(&document, casting_proof_path, "post");
    assert!(casting_proof.get("x-iroha-canonical-auth-v1").is_some());
    assert_eq!(
        casting_proof
            .get("x-iroha-tool-effect")
            .and_then(Value::as_str),
        Some("write")
    );
    let casting_request = casting_proof
        .get("requestBody")
        .and_then(Value::as_object)
        .and_then(|body| body.get("content"))
        .and_then(Value::as_object)
        .expect("casting-proof request content");
    assert_eq!(
        casting_request
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["application/x-norito"]
    );
    assert_eq!(
        casting_request
            .get("application/x-norito")
            .and_then(Value::as_object)
            .and_then(|media| media.get("schema"))
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("x-iroha-norito-schema"))
            .and_then(Value::as_str),
        Some("iroha.torii.v1.parliament.timed_ovn_casting_proof.request")
    );
    let casting_response = casting_proof
        .get("responses")
        .and_then(Value::as_object)
        .and_then(|responses| responses.get("200"))
        .and_then(Value::as_object)
        .expect("casting-proof success response");
    assert_eq!(
        casting_response
            .get("content")
            .and_then(Value::as_object)
            .and_then(|content| content.get("application/x-norito"))
            .and_then(Value::as_object)
            .and_then(|media| media.get("schema"))
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("x-iroha-norito-schema"))
            .and_then(Value::as_str),
        Some("iroha.torii.v1.parliament.timed_ovn_casting_proof.response")
    );
    let casting_response_headers = casting_response
        .get("headers")
        .and_then(Value::as_object)
        .expect("casting-proof private headers");
    assert!(casting_response_headers.contains_key("Cache-Control"));
    assert!(casting_response_headers.contains_key("Vary"));

    fn assert_no_secret_properties(schema_name: &str, value: &Value) {
        match value {
            Value::Object(object) => {
                if let Some(Value::Object(properties)) = object.get("properties") {
                    for property in properties.keys() {
                        for secret in ["private_key", "privateKey", "seed", "mnemonic"] {
                            assert!(
                                !property.contains(secret),
                                "{schema_name} leaked signing material field {property}"
                            );
                        }
                    }
                }
                for child in object.values() {
                    assert_no_secret_properties(schema_name, child);
                }
            }
            Value::Array(array) => {
                for child in array {
                    assert_no_secret_properties(schema_name, child);
                }
            }
            _ => {}
        }
    }

    for schema_name in [
        "DeployContractProposalDraftRequestV1",
        "DeployContractProposalDraftResponseV1",
        "SccpRouteGovernanceProposalDraftRequestV1",
        "SccpRouteGovernanceProposalDraftResponseV1",
        "GovernanceParliamentAttemptDraftRequestV1",
        "GovernanceParliamentAttemptDraftResponseV1",
        "GovernanceParliamentTransitionDraftRequestV1",
        "GovernanceParliamentTransitionDraftResponseV1",
        "GovernanceParliamentAttemptReadResponseV1",
        "GovernanceParliamentTleAdaptiveDealerCommitmentV1",
        "GovernanceParliamentTleAdaptivePublicShareV1",
        "GovernanceParliamentTleKeySessionBindingV1",
        "GovernanceParliamentTlePartialReleaseShareV1",
        "GovernanceParliamentTimedOvnCastingContextResponseV1",
        "GovernanceParliamentTimedOvnCastingProofRequestV1",
        "GovernanceParliamentTimedOvnCastingProofResponseV1",
        "GovernanceParliamentTimedOvnProgressV1",
        "GovernanceParliamentTimedOvnSessionV1",
        "GovernanceParliamentTimedOvnReleaseIdentityV1",
        "GovernanceParliamentTleReleaseContextResponseV1",
    ] {
        assert_eq!(
            schemas
                .get(schema_name)
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("additionalProperties")),
            Some(&Value::Bool(false)),
            "{schema_name} must reject unknown fields"
        );
        assert_no_secret_properties(
            schema_name,
            schemas
                .get(schema_name)
                .unwrap_or_else(|| panic!("missing {schema_name}")),
        );
    }

    let casting_context = schemas
        .get("GovernanceParliamentTimedOvnCastingContextResponseV1")
        .and_then(Value::as_object)
        .expect("timed-OVN casting-context schema");
    let casting_required = casting_context
        .get("required")
        .and_then(Value::as_array)
        .expect("timed-OVN casting-context required fields");
    for field in [
        "version",
        "current_height",
        "phase",
        "session",
        "registration_opened_at_finalized_height",
        "target_finalized_height",
        "tle_key_session",
        "registration_records_hex",
        "survivor_participant_hashes",
        "release_identity",
        "archive_norito_base64",
    ] {
        assert!(
            casting_required
                .iter()
                .any(|required| required.as_str() == Some(field)),
            "timed-OVN casting context must require {field}"
        );
    }
    assert_eq!(casting_required.len(), 11);
    assert!(
        casting_context
            .get("description")
            .and_then(Value::as_str)
            .is_some_and(|description| description.contains("not consensus-authenticated"))
    );
    let casting_properties = casting_context
        .get("properties")
        .and_then(Value::as_object)
        .expect("timed-OVN casting-context properties");
    let registration_records = casting_properties
        .get("registration_records_hex")
        .and_then(Value::as_object)
        .expect("timed-OVN casting registration records");
    assert_eq!(
        registration_records.get("maxItems").and_then(Value::as_u64),
        Some(1_000)
    );
    assert_eq!(
        registration_records
            .get("uniqueItems")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        registration_records
            .get("items")
            .and_then(Value::as_object)
            .and_then(|items| items.get("$ref"))
            .and_then(Value::as_str),
        Some("#/components/schemas/GovernanceParliamentTimedOvnRegistrationRecordHexV1")
    );
    assert_eq!(
        casting_properties
            .get("survivor_participant_hashes")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("oneOf"))
            .and_then(Value::as_array)
            .and_then(|branches| branches.first())
            .and_then(Value::as_object)
            .and_then(|array| array.get("minItems"))
            .and_then(Value::as_u64),
        Some(1)
    );
    let registration_record = schemas
        .get("GovernanceParliamentTimedOvnRegistrationRecordHexV1")
        .and_then(Value::as_object)
        .expect("timed-OVN registration record schema");
    assert_eq!(
        registration_record.get("minLength").and_then(Value::as_u64),
        Some(7_248)
    );
    assert_eq!(
        registration_record.get("maxLength").and_then(Value::as_u64),
        Some(7_248)
    );
    assert_eq!(
        registration_record.get("pattern").and_then(Value::as_str),
        Some("^[0-9a-f]{7248}$")
    );
    let casting_archive = schemas
        .get("GovernanceParliamentTimedOvnCastingContextArchiveBase64V1")
        .and_then(Value::as_object)
        .expect("timed-OVN casting archive schema");
    assert_eq!(
        casting_archive.get("maxLength").and_then(Value::as_u64),
        Some(5_592_408)
    );
    assert_eq!(
        casting_archive.get("pattern").and_then(Value::as_str),
        Some("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
    );
    assert_eq!(
        schemas
            .get("GovernanceParliamentTimedOvnCastingPhaseV1")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("enum"))
            .and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>()),
        Some(vec!["Registered", "RegistrationClosed", "SurvivorsFrozen"])
    );
    let encoded_casting_context =
        norito::json::to_json(casting_context).expect("encode timed-OVN casting context");
    for forbidden in [
        "account_label",
        "dropout",
        "masked_ballot",
        "secret_share",
        "partial_release",
        "individual_opening",
        "registration_secret",
        "root_seed",
    ] {
        assert!(
            !encoded_casting_context.contains(forbidden),
            "timed-OVN casting context exposed forbidden material {forbidden}"
        );
    }

    let release_context = schemas
        .get("GovernanceParliamentTleReleaseContextResponseV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .expect("TLE release-context properties");
    for forbidden in [
        "registration_records",
        "dropout_participant_hashes",
        "survivor_participant_hashes",
        "ballot_records",
        "secret_share",
        "partial_releases",
        "individual_openings",
    ] {
        assert!(
            !release_context.contains_key(forbidden),
            "TLE release context exposed forbidden field {forbidden}"
        );
    }
    assert_eq!(
        release_context
            .get("status")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .and_then(|properties| properties.get("status"))
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("const"))
            .and_then(Value::as_str),
        Some("Opening")
    );

    let tle_key_session = schemas
        .get("GovernanceParliamentTleKeySessionBindingV1")
        .and_then(Value::as_object)
        .expect("complete TLE public transcript schema");
    let tle_key_session_required = tle_key_session
        .get("required")
        .and_then(Value::as_array)
        .expect("complete TLE public transcript required fields");
    for field in [
        "version",
        "key_session_id",
        "network_id",
        "roster_hash",
        "committee_size",
        "threshold",
        "generator_h",
        "generator_v",
        "qualified_dealers",
        "qualified_dealer_commitments",
        "dkg_event_hash",
        "group_public_key",
        "public_shares",
        "transcript_hash",
    ] {
        assert!(
            tle_key_session_required
                .iter()
                .any(|required| required.as_str() == Some(field)),
            "complete TLE public transcript must require {field}"
        );
    }
    assert_eq!(tle_key_session_required.len(), 14);
    let tle_key_session_properties = tle_key_session
        .get("properties")
        .and_then(Value::as_object)
        .expect("complete TLE public transcript properties");
    for (field, item_ref, min_items) in [
        (
            "qualified_dealer_commitments",
            "#/components/schemas/GovernanceParliamentTleAdaptiveDealerCommitmentV1",
            2,
        ),
        (
            "public_shares",
            "#/components/schemas/GovernanceParliamentTleAdaptivePublicShareV1",
            4,
        ),
    ] {
        let sequence = tle_key_session_properties
            .get(field)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("TLE transcript {field}"));
        assert_eq!(
            sequence.get("minItems").and_then(Value::as_u64),
            Some(min_items)
        );
        assert_eq!(sequence.get("maxItems").and_then(Value::as_u64), Some(31));
        assert_eq!(
            sequence
                .get("items")
                .and_then(Value::as_object)
                .and_then(|items| items.get("$ref"))
                .and_then(Value::as_str),
            Some(item_ref)
        );
    }

    let partial_release = schemas
        .get("GovernanceParliamentTlePartialReleaseShareV1")
        .and_then(Value::as_object)
        .expect("TLE partial-release schema");
    let partial_required = partial_release
        .get("required")
        .and_then(Value::as_array)
        .expect("TLE partial-release required fields");
    for field in [
        "key_session_id",
        "identity_digest",
        "participant_index",
        "sigma",
        "proof_x",
        "proof_y",
        "z_s",
        "z_r",
        "z_u",
    ] {
        assert!(
            partial_required
                .iter()
                .any(|required| required.as_str() == Some(field)),
            "TLE partial release must require {field}"
        );
    }
    assert_eq!(partial_required.len(), 9);

    for schema_name in [
        "GovernanceParliamentTleKeySessionBindingV1",
        "GovernanceParliamentTlePartialReleaseShareV1",
        "GovernanceParliamentTleReleaseContextResponseV1",
    ] {
        let encoded = norito::json::to_json(
            schemas
                .get(schema_name)
                .unwrap_or_else(|| panic!("missing {schema_name}")),
        )
        .expect("encode public TLE schema");
        for forbidden in [
            "secret_share",
            "masked_ballot",
            "individual_opening",
            "registration_secret",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "{schema_name} exposed forbidden TLE material {forbidden}"
            );
        }
    }

    for request_schema in [
        "DeployContractProposalDraftRequestV1",
        "SccpRouteGovernanceProposalDraftRequestV1",
    ] {
        let properties = schemas
            .get(request_schema)
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{request_schema} properties"));
        for retired in ["window", "mode", "authority", "private_key"] {
            assert!(
                !properties.contains_key(retired),
                "{request_schema} restored retired field {retired}"
            );
        }
    }
    for (response_schema, instruction_schema, wire_id) in [
        (
            "DeployContractProposalDraftResponseV1",
            "DeployContractProposalInstructionDraftV1",
            "iroha.instruction.v1::governance::ProposeDeployContract",
        ),
        (
            "SccpRouteGovernanceProposalDraftResponseV1",
            "SccpRouteGovernanceProposalInstructionDraftV1",
            "iroha.instruction.v1::governance::ProposeSccpRouteGovernance",
        ),
    ] {
        let properties = schemas
            .get(response_schema)
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{response_schema} properties"));
        assert!(
            !properties.contains_key("ok"),
            "{response_schema} must not carry a redundant success flag"
        );
        assert_eq!(
            properties
                .get("proposal_id")
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("$ref"))
                .and_then(Value::as_str),
            Some("#/components/schemas/GovernanceProposalHex32V1")
        );
        let instructions = properties
            .get("tx_instructions")
            .and_then(Value::as_object)
            .expect("exact proposal instruction array schema");
        assert_eq!(
            instructions.get("minItems").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            instructions.get("maxItems").and_then(Value::as_u64),
            Some(1)
        );
        let expected_instruction_ref = format!("#/components/schemas/{instruction_schema}");
        assert_eq!(
            instructions
                .get("items")
                .and_then(Value::as_object)
                .and_then(|items| items.get("$ref"))
                .and_then(Value::as_str),
            Some(expected_instruction_ref.as_str())
        );
        let instruction_properties = schemas
            .get(instruction_schema)
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{instruction_schema} properties"));
        assert_eq!(
            instruction_properties
                .get("wire_id")
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("const"))
                .and_then(Value::as_str),
            Some(wire_id)
        );
        assert_eq!(
            instruction_properties
                .get("payload_hex")
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("pattern"))
                .and_then(Value::as_str),
            Some("^(?:[0-9a-f]{2})+$")
        );
    }

    let proposal_variants = schemas
        .get("GovernanceParliamentProposalKindV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("oneOf"))
        .and_then(Value::as_array)
        .expect("Parliament proposal variants");
    let proposal_tags = proposal_variants
        .iter()
        .map(|variant| {
            variant
                .get("properties")
                .and_then(Value::as_object)
                .and_then(|properties| properties.get("kind"))
                .and_then(Value::as_object)
                .and_then(|kind| kind.get("const"))
                .and_then(Value::as_str)
                .expect("closed proposal tag")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        proposal_tags,
        [
            "DeployContract",
            "RuntimeUpgrade",
            "SccpRouteGovernance",
            "ValidationFeePolicy",
            "ValidationFeePayoutLifecycle",
            "MusubiRegistryGovernance",
            "SorafsProviderGovernance",
            "ContractLifecycleGovernance",
            "ContractEmergencyHold",
            "GlobalDataTriggerPermissionGovernance",
        ]
    );
    let proposal_payload_refs = proposal_variants
        .iter()
        .map(|variant| {
            variant
                .get("properties")
                .and_then(Value::as_object)
                .and_then(|properties| properties.get("payload"))
                .and_then(Value::as_object)
                .and_then(|payload| payload.get("$ref"))
                .and_then(Value::as_str)
                .expect("typed Parliament proposal payload reference")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        proposal_payload_refs,
        [
            "#/components/schemas/GovernanceParliamentProposalPayloadDeployContractV1",
            "#/components/schemas/GovernanceParliamentProposalPayloadRuntimeUpgradeV1",
            "#/components/schemas/GovernanceParliamentProposalPayloadSccpRouteGovernanceV1",
            "#/components/schemas/GovernanceParliamentProposalPayloadValidationFeePolicyProposalV1",
            "#/components/schemas/GovernanceParliamentProposalPayloadValidationFeePayoutLifecycleV1",
            "#/components/schemas/GovernanceParliamentProposalPayloadMusubiRegistryActionV1",
            "#/components/schemas/GovernanceParliamentProposalPayloadSorafsProviderV1",
            "#/components/schemas/GovernanceParliamentProposalPayloadContractLifecycleV1",
            "#/components/schemas/GovernanceParliamentProposalPayloadContractEmergencyHoldV1",
            "#/components/schemas/GovernanceParliamentProposalPayloadGlobalDataTriggerPermissionV1",
        ]
    );
    for payload_ref in proposal_payload_refs {
        let root = payload_ref
            .strip_prefix(COMPONENT_SCHEMA_REF_PREFIX)
            .expect("Parliament payload component reference");
        let mut pending = std::collections::VecDeque::from([root.to_owned()]);
        let mut reachable = std::collections::BTreeSet::new();
        while let Some(component) = pending.pop_front() {
            if !reachable.insert(component.clone()) {
                continue;
            }
            assert_ne!(
                component, "JsonValue",
                "Parliament proposal payloads must stay transitively typed"
            );
            let schema = schemas
                .get(&component)
                .unwrap_or_else(|| panic!("missing Parliament payload component {component}"));
            let mut references = std::collections::BTreeSet::new();
            collect_component_refs(schema, &mut references);
            pending.extend(references);
        }
    }

    let contract_lifecycle_action_variants = schemas
        .get("GovernanceParliamentProposalPayloadContractLifecycleActionV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("oneOf"))
        .and_then(Value::as_array)
        .expect("closed contract lifecycle action variants");
    let contract_lifecycle_action_tags = contract_lifecycle_action_variants
        .iter()
        .map(|variant| {
            assert_eq!(
                variant.get("additionalProperties").and_then(Value::as_bool),
                Some(false),
                "each contract lifecycle action must reject unknown fields"
            );
            variant
                .get("properties")
                .and_then(Value::as_object)
                .and_then(|properties| properties.get("action"))
                .and_then(Value::as_object)
                .and_then(|action| action.get("const"))
                .and_then(Value::as_str)
                .expect("closed contract lifecycle action tag")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        contract_lifecycle_action_tags,
        [
            "Activate",
            "Deactivate",
            "OfferOwnership",
            "CancelOwnershipOffer",
            "AcceptParliamentOwnership",
            "CompleteEmergencyHoldRetrospective",
        ]
    );

    let transition_variants = schemas
        .get("GovernanceParliamentLifecycleTransitionV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("oneOf"))
        .and_then(Value::as_array)
        .expect("Parliament lifecycle variants");
    let transition_tags = transition_variants
        .iter()
        .map(|variant| {
            variant
                .get("properties")
                .and_then(Value::as_object)
                .and_then(|properties| properties.get("transition"))
                .and_then(Value::as_object)
                .and_then(|transition| transition.get("const"))
                .and_then(Value::as_str)
                .expect("closed transition tag")
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(transition_tags.len(), 21);
    for required in [
        "EndorsePublicFinding",
        "FailPublicFindingNoResult",
        "RecordInvitationResponse",
        "RegisterBallotParticipant",
        "RecordBallotDropout",
    ] {
        assert!(transition_tags.contains(required));
    }
    for consensus_owned in [
        "ConstructCertificate",
        "MarkEnacted",
        "MarkSuperseded",
        "MarkExecutionFailed",
    ] {
        assert!(
            !transition_tags.contains(consensus_owned),
            "consensus-owned tag must not be submit-able: {consensus_owned}"
        );
    }
    assert_eq!(
        schemas
            .get("GovernanceParliamentTransitionKindV1")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("oneOf"))
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(24),
        "audit kind inventory includes the three automatic outcomes"
    );

    for (schema_name, exact_bytes) in [
        ("GovernanceParliamentRegistrationRecordV1", 3_624_u64),
        ("GovernanceParliamentBallotRecordV1", 2_858_u64),
    ] {
        let schema = schemas
            .get(schema_name)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing {schema_name}"));
        assert_eq!(
            schema.get("minItems").and_then(Value::as_u64),
            Some(exact_bytes)
        );
        assert_eq!(
            schema.get("maxItems").and_then(Value::as_u64),
            Some(exact_bytes)
        );
    }
    let ballot_chunk = schemas
        .get("GovernanceParliamentFreezeTimedOvnCorpusPayloadV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("ballot_records"))
        .and_then(Value::as_object)
        .expect("timed-OVN ballot chunk schema");
    assert_eq!(
        ballot_chunk.get("minItems").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        ballot_chunk.get("maxItems").and_then(Value::as_u64),
        Some(
            u64::try_from(
                iroha_data_model::governance::types::PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1,
            )
            .expect("timed-OVN ballot chunk bound fits u64"),
        )
    );
    assert!(
        ballot_chunk
            .get("description")
            .and_then(Value::as_str)
            .is_some_and(|description| {
                description.contains("contiguous") && description.contains("complete corpus")
            }),
        "timed-OVN ballot chunk schema must distinguish append and full-corpus bounds"
    );
    assert_eq!(
        schemas
            .get("GovernanceParliamentFramedPayloadHexV1")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("maxLength"))
            .and_then(Value::as_u64),
        Some(2 * 16 * 1024 * 1024),
        "framed reducer payload must retain the exact 16 MiB decoded bound"
    );

    let read_certificate_ref = schemas
        .get("GovernanceParliamentAttemptReadResponseV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("certificate"))
        .and_then(Value::as_object)
        .and_then(|certificate| certificate.get("oneOf"))
        .and_then(Value::as_array)
        .and_then(|variants| variants.first())
        .and_then(Value::as_object)
        .and_then(|variant| variant.get("$ref"))
        .and_then(Value::as_str);
    assert_eq!(
        read_certificate_ref,
        Some("#/components/schemas/GovernanceParliamentCertificateV1"),
        "attempt reads must project the complete typed certificate"
    );
    let body_state_schema = schemas
        .get("GovernanceParliamentBodyStateProjectionV1")
        .and_then(Value::as_object)
        .expect("typed Parliament body-state projection");
    assert_eq!(
        body_state_schema.get("additionalProperties"),
        Some(&Value::Bool(false))
    );
    let body_state_fields = body_state_schema
        .get("required")
        .and_then(Value::as_array)
        .expect("body-state fields")
        .iter()
        .filter_map(Value::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        body_state_fields,
        std::collections::BTreeSet::from([
            "body",
            "body_instance_id",
            "status",
            "public_finding_opened_at_height",
            "public_finding_phase_blocks",
            "public_finding_deadline_height",
            "no_result_kind",
            "no_result_height",
            "timed_ovn_progress",
        ])
    );
    let progress_schema = schemas
        .get("GovernanceParliamentTimedOvnProgressV1")
        .and_then(Value::as_object)
        .expect("typed timed-OVN progress projection");
    assert_eq!(
        progress_schema.get("additionalProperties"),
        Some(&Value::Bool(false))
    );
    let progress_fields = progress_schema
        .get("required")
        .and_then(Value::as_array)
        .expect("timed-OVN progress fields")
        .iter()
        .filter_map(Value::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        progress_fields,
        std::collections::BTreeSet::from([
            "ballot_attempt_id",
            "status",
            "frozen_survivor_count",
            "accepted_ballot_prefix_count",
        ])
    );
    let no_result_variants = schemas
        .get("GovernanceParliamentNoResultKindV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("oneOf"))
        .and_then(Value::as_array)
        .expect("no-result audit variants");
    assert_eq!(
        no_result_variants.len(),
        10,
        "no-result audit class must remain closed"
    );
    assert_eq!(
        no_result_variants
            .iter()
            .filter_map(|variant| {
                variant
                    .get("properties")
                    .and_then(Value::as_object)
                    .and_then(|properties| properties.get("reason"))
                    .and_then(Value::as_object)
                    .and_then(|reason| reason.get("const"))
                    .and_then(Value::as_str)
            })
            .collect::<Vec<_>>(),
        vec![
            "PublicFindingQuorumUnreachable",
            "PublicFindingDeadlineExpired",
            "BallotRegistrationDeadlineExpired",
            "BallotSurvivorDeadlineExpired",
            "BallotCommitmentDeadlineExpired",
            "BallotReleasePulseUnavailable",
            "BallotOpeningDeadlineExpired",
            "SortitionRetriesExhausted",
            "ConfirmationJuryCapacityUnavailable",
            "RandomnessRedrawBudgetExhausted",
        ],
        "no-result OpenAPI tags must match the closed codec inventory"
    );
    let read_body_states = schemas
        .get("GovernanceParliamentAttemptReadResponseV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("body_states"))
        .and_then(Value::as_object)
        .expect("attempt read body states");
    assert_eq!(
        read_body_states.get("minItems").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        read_body_states.get("maxItems").and_then(Value::as_u64),
        Some(10)
    );
    let supporter_schema = schemas
        .get("GovernanceParliamentPublicFindingCertificateBindingV1")
        .and_then(Value::as_object)
        .expect("typed public-finding certificate binding");
    assert_eq!(
        supporter_schema.get("additionalProperties"),
        Some(&Value::Bool(false))
    );
    let supporter_properties = supporter_schema
        .get("properties")
        .and_then(Value::as_object)
        .expect("public-finding certificate properties");
    let supporters = supporter_properties
        .get("endorsing_assignments")
        .and_then(Value::as_object)
        .expect("exact endorsing assignment list");
    assert_eq!(supporters.get("minItems").and_then(Value::as_u64), Some(1));
    assert_eq!(
        supporters.get("maxItems").and_then(Value::as_u64),
        Some(1_000)
    );
    assert_eq!(supporters.get("uniqueItems"), Some(&Value::Bool(true)));
    assert_eq!(
        supporter_schema
            .get("required")
            .and_then(Value::as_array)
            .map(|required| {
                required
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<std::collections::BTreeSet<_>>()
            }),
        Some(std::collections::BTreeSet::from([
            "endorsement_root",
            "endorsing_assignments",
            "endorsements",
            "quorum",
        ])),
        "certificate projection must retain the exact supporter sequence and counts"
    );
}

#[test]
fn governance_read_path_parameters_publish_exact_runtime_grammars() {
    let document = generate_spec();
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .expect("OpenAPI paths");
    for [path, method, parameter_name, pattern_kind] in openapi_contract_fixed_rows::<4>(
        "vpn.governance_read_path_parameters_publish_exact_runtime_grammars.rows.1",
    ) {
        let expected_pattern = match pattern_kind {
            "agenda_proposal_id" => "^AC-[0-9]{4}-[0-9]{3}$",
            "lower_hex32" => GOVERNANCE_LOWER_HEX32_PATTERN,
            "selector_v1" => GOVERNANCE_SELECTOR_V1_PATTERN,
            _ => panic!("unknown governance pattern contract `{pattern_kind}`"),
        };
        let parameters = paths
            .get(path)
            .and_then(Value::as_object)
            .and_then(|item| item.get(method))
            .and_then(Value::as_object)
            .and_then(|operation| operation.get("parameters"))
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("missing {method} parameters for `{path}`"));
        let pattern = parameters
            .iter()
            .filter_map(Value::as_object)
            .find(|parameter| parameter.get("name").and_then(Value::as_str) == Some(parameter_name))
            .and_then(|parameter| parameter.get("schema"))
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("pattern"))
            .and_then(Value::as_str);
        assert_eq!(
            pattern,
            Some(expected_pattern),
            "`{path}` must publish the exact runtime selector grammar"
        );
    }
}
#[test]
fn subscription_mutations_publish_exact_unsigned_v1_draft_contract() {
    let paths = subscription_paths();
    for path in openapi_contract_strings(
        "vpn.subscription_mutations_publish_exact_unsigned_v1_draft_contract.strings.1",
    ) {
        let post = paths
            .get(path)
            .and_then(Value::as_object)
            .and_then(|item| item.get("post"))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing subscription draft POST `{path}`"));
        let description = post
            .get("description")
            .and_then(Value::as_str)
            .expect("draft description");
        assert!(description.contains("does not sign or queue"));
    }
    let mut schemas = Map::new();
    subscription_schemas(&mut schemas);
    for request in openapi_contract_strings(
        "vpn.subscription_mutations_publish_exact_unsigned_v1_draft_contract.strings.2",
    ) {
        let schema = schemas
            .get(request)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing `{request}`"));
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&Value::Bool(false))
        );
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("request properties");
        assert!(!properties.contains_key("private_key"));
    }
    for response in openapi_contract_strings(
        "vpn.subscription_mutations_publish_exact_unsigned_v1_draft_contract.strings.3",
    ) {
        let schema = schemas
            .get(response)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing `{response}`"));
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&Value::Bool(false))
        );
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("response properties");
        assert!(properties.contains_key("version"));
        assert!(properties.contains_key("authority"));
        assert!(properties.contains_key("action"));
        assert!(properties.contains_key("tx_instructions"));
        assert!(!properties.contains_key("ok"));
        assert!(!properties.contains_key("tx_hash_hex"));
    }
    let cancel_mode = schemas
        .get("SubscriptionCancelModeV1")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("oneOf"))
        .and_then(Value::as_array)
        .expect("exact cancellation mode cases");
    assert_eq!(cancel_mode.len(), 2);
}
#[test]
fn local_signing_openapi_contracts_are_closed_and_secret_free() {
    let document = generate_spec();
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .expect("OpenAPI paths");
    for path in openapi_contract_strings(
        "vpn.local_signing_openapi_contracts_are_closed_and_secret_free.strings.1",
    ) {
        assert!(
            paths
                .get(path)
                .and_then(Value::as_object)
                .and_then(|item| item.get("post"))
                .is_some(),
            "missing local-signing POST `{path}`",
        );
    }
    let schemas = document
        .get("components")
        .and_then(Value::as_object)
        .and_then(|components| components.get("schemas"))
        .and_then(Value::as_object)
        .expect("OpenAPI schemas");
    for request in openapi_contract_strings(
        "vpn.local_signing_openapi_contracts_are_closed_and_secret_free.strings.2",
    ) {
        let schema = schemas
            .get(request)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing `{request}`"));
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&Value::Bool(false))
        );
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("request properties");
        assert!(
            !properties.contains_key("private_key"),
            "`{request}` must not advertise private_key",
        );
    }
}
#[test]
fn da_proof_openapi_contracts_match_exact_norito_json_wire_shapes() {
    fn operation_responses<'a>(paths: &'a Map, path: &str) -> &'a Map {
        paths
            .get(path)
            .and_then(Value::as_object)
            .and_then(|item| item.get("post"))
            .and_then(Value::as_object)
            .and_then(|operation| operation.get("responses"))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing DA POST responses for `{path}`"))
    }
    fn schema_properties<'a>(schemas: &'a Map, schema: &str) -> &'a Map {
        schemas
            .get(schema)
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing `{schema}` properties"))
    }
    fn operation_schema_ref<'a>(paths: &'a Map, path: &str, request: bool) -> &'a str {
        let operation = paths
            .get(path)
            .and_then(Value::as_object)
            .and_then(|item| item.get("post"))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing DA POST `{path}`"));
        let media = if request {
            operation
                .get("requestBody")
                .and_then(Value::as_object)
                .and_then(|body| body.get("content"))
        } else {
            operation
                .get("responses")
                .and_then(Value::as_object)
                .and_then(|responses| responses.get("200"))
                .and_then(Value::as_object)
                .and_then(|response| response.get("content"))
        };
        media
            .and_then(Value::as_object)
            .and_then(|content| content.get("application/json"))
            .and_then(Value::as_object)
            .and_then(|json| json.get("schema"))
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("$ref"))
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing DA schema reference for `{path}`"))
    }
    let document = generate_spec();
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .expect("OpenAPI paths");
    assert!(!paths.contains_key("/v1/da/proof-policies/snapshot"));
    assert_eq!(
        operation_schema_ref(paths, "/v1/da/commitments", true),
        "#/components/schemas/DaCommitmentListRequest"
    );
    assert_eq!(
        operation_schema_ref(paths, "/v1/da/commitments", false),
        "#/components/schemas/DaCommitmentListResponse"
    );
    assert_eq!(
        operation_schema_ref(paths, "/v1/da/commitments/prove", true),
        "#/components/schemas/DaCommitmentProofRequest"
    );
    assert_eq!(
        operation_schema_ref(paths, "/v1/da/commitments/prove", false),
        "#/components/schemas/DaCommitmentProofResponse"
    );
    assert_eq!(
        operation_schema_ref(paths, "/v1/da/commitments/verify", true),
        "#/components/schemas/DaCommitmentProof"
    );
    assert_eq!(
        operation_schema_ref(paths, "/v1/da/pin-intents", true),
        "#/components/schemas/DaPinIntentListRequest"
    );
    assert_eq!(
        operation_schema_ref(paths, "/v1/da/pin-intents", false),
        "#/components/schemas/DaPinIntentListResponse"
    );
    assert_eq!(
        operation_schema_ref(paths, "/v1/da/pin-intents/prove", true),
        "#/components/schemas/DaPinIntentQueryRequest"
    );
    assert_eq!(
        operation_schema_ref(paths, "/v1/da/pin-intents/prove", false),
        "#/components/schemas/DaPinIntentProofResponse"
    );
    assert_eq!(
        operation_schema_ref(paths, "/v1/da/pin-intents/verify", true),
        "#/components/schemas/DaPinIntentProof"
    );
    for [path, method, operation_id] in openapi_contract_fixed_rows::<3>(
        "vpn.da_proof_openapi_contracts_match_exact_norito_json_wire_shapes.rows.1",
    ) {
        assert_eq!(
            paths
                .get(path)
                .and_then(Value::as_object)
                .and_then(|item| item.get(method))
                .and_then(Value::as_object)
                .and_then(|operation| operation.get("operationId"))
                .and_then(Value::as_str),
            Some(operation_id),
            "{path}"
        );
    }
    for path in openapi_contract_strings(
        "vpn.da_proof_openapi_contracts_match_exact_norito_json_wire_shapes.strings.1",
    ) {
        let responses = operation_responses(paths, path);
        assert!(responses.contains_key("400"), "{path} malformed JSON");
        assert!(responses.contains_key("413"), "{path} 64 KiB body limit");
    }
    for path in ["/v1/da/commitments", "/v1/da/pin-intents"] {
        assert!(
            operation_responses(paths, path).contains_key("409"),
            "{path} mid-read snapshot change"
        );
    }
    for path in openapi_contract_strings(
        "vpn.da_proof_openapi_contracts_match_exact_norito_json_wire_shapes.strings.2",
    ) {
        assert!(
            !operation_responses(paths, path).contains_key("409"),
            "{path} does not issue list snapshots"
        );
    }
    assert!(
        operation_responses(paths, "/v1/da/pin-intents/prove")
            .get("400")
            .and_then(Value::as_object)
            .and_then(|response| response.get("description"))
            .and_then(Value::as_str)
            .is_some_and(|description| description.contains("256 UTF-8 bytes")),
        "pin-intent proof errors must document the alias byte limit"
    );
    let schemas = component_schemas(&document);
    assert!(paths.contains_key("/v1/da/proof-policies"));
    assert!(!paths.contains_key("/v1/da/proof-policies/snapshot"));
    for (request, expected_selectors) in [
        (
            "DaCommitmentProofRequest",
            vec![vec!["manifest_hash"], vec!["lane_id", "epoch", "sequence"]],
        ),
        (
            "DaPinIntentQueryRequest",
            vec![
                vec!["manifest_hash"],
                vec!["storage_ticket"],
                vec!["alias"],
                vec!["lane_id", "epoch", "sequence"],
            ],
        ),
    ] {
        let alternatives = schemas
            .get(request)
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("anyOf"))
            .and_then(Value::as_array)
            .expect("proof requests need a complete selector");
        assert_eq!(alternatives.len(), expected_selectors.len());
        for (alternative, fields) in alternatives.iter().zip(expected_selectors) {
            assert_eq!(
                alternative["required"],
                norito::json::to_value(&fields).unwrap()
            );
            for field in fields {
                assert_eq!(
                    alternative["properties"][field]["not"]["type"].as_str(),
                    Some("null")
                );
            }
        }
    }

    assert!(
        !schemas.contains_key("DaPagination"),
        "offset pagination must not remain in the first-release DA list contract"
    );
    assert!(
        !schemas.contains_key("DaCommitmentWithLocationList"),
        "the commitment list route uses its cursor-bearing page envelope"
    );
    assert!(
        !schemas.contains_key("DaPinIntentWithLocationList"),
        "the pin-intent list route uses its cursor-bearing page envelope"
    );
    for [request, cursor] in openapi_contract_fixed_rows::<2>(
        "vpn.da_proof_openapi_contracts_match_exact_norito_json_wire_shapes.rows.2",
    ) {
        let request_schema = schemas
            .get(request)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing `{request}` schema"));
        assert_eq!(
            request_schema
                .get("additionalProperties")
                .and_then(Value::as_bool),
            Some(false),
            "{request}"
        );
        let properties = schema_properties(schemas, request);
        let mut property_names = properties.keys().map(String::as_str).collect::<Vec<_>>();
        property_names.sort_unstable();
        assert_eq!(property_names, vec!["cursor", "limit"], "{request}");
        let limit = properties
            .get("limit")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing `{request}.limit` schema"));
        assert_eq!(limit.get("minimum").and_then(Value::as_u64), Some(1));
        assert_eq!(
            limit.get("maximum").and_then(Value::as_u64),
            Some(1_000),
            "{request}.limit must reject an excessive raw-row scan budget"
        );
        assert_eq!(limit.get("default").and_then(Value::as_u64), Some(100));
        assert!(
            limit
                .get("description")
                .and_then(Value::as_str)
                .is_some_and(|description| description.contains("values above 1,000 are rejected")),
            "{request}.limit must document the raw-row cap"
        );
        let expected_cursor_ref = format!("#/components/schemas/{cursor}");
        assert_eq!(
            properties
                .get("cursor")
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("anyOf"))
                .and_then(Value::as_array)
                .and_then(|choices| choices.first())
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("$ref"))
                .and_then(Value::as_str),
            Some(expected_cursor_ref.as_str()),
            "{request}"
        );
    }
    for row in openapi_contract_rows(
        "vpn.da_proof_openapi_contracts_match_exact_norito_json_wire_shapes.rows.6",
    ) {
        let (request, expected) = row.split_first().expect("DA request-property contract row");
        let expected = expected.iter().map(String::as_str).collect::<Vec<_>>();
        let mut property_names = schema_properties(schemas, request)
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        property_names.sort_unstable();
        assert_eq!(property_names, expected, "{request}");
    }
    let snapshot = schemas
        .get("DaListSnapshot")
        .and_then(Value::as_object)
        .expect("DA list snapshot schema");
    assert_eq!(
        snapshot
            .get("required")
            .and_then(Value::as_array)
            .map(|required| required
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()),
        Some(vec!["block_height", "block_hash"])
    );
    assert_eq!(
        snapshot
            .get("oneOf")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(2),
        "empty and non-empty canonical snapshot shapes"
    );
    for [cursor, after] in openapi_contract_fixed_rows::<2>(
        "vpn.da_proof_openapi_contracts_match_exact_norito_json_wire_shapes.rows.3",
    ) {
        let properties = schema_properties(schemas, cursor);
        assert_eq!(
            properties
                .get("snapshot")
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("$ref"))
                .and_then(Value::as_str),
            Some("#/components/schemas/DaListSnapshot"),
            "{cursor}"
        );
        let expected_after_ref = format!("#/components/schemas/{after}");
        assert_eq!(
            properties
                .get("after")
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("$ref"))
                .and_then(Value::as_str),
            Some(expected_after_ref.as_str()),
            "{cursor}"
        );
    }
    for [response, items, cursor] in openapi_contract_fixed_rows::<3>(
        "vpn.da_proof_openapi_contracts_match_exact_norito_json_wire_shapes.rows.4",
    ) {
        let response_schema = schemas
            .get(response)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing `{response}` schema"));
        assert!(
            response_schema
                .get("required")
                .and_then(Value::as_array)
                .is_some_and(|required| {
                    required
                        .iter()
                        .any(|field| field.as_str() == Some("next_cursor"))
                }),
            "{response}.next_cursor must be explicit, including null"
        );
        assert!(
            schema_properties(schemas, response).contains_key(items),
            "{response}.{items}"
        );
        let next_cursor = schema_properties(schemas, response)
            .get("next_cursor")
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("anyOf"))
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("missing `{response}.next_cursor` union"));
        let expected_cursor_ref = format!("#/components/schemas/{cursor}");
        assert_eq!(
            next_cursor
                .first()
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("$ref"))
                .and_then(Value::as_str),
            Some(expected_cursor_ref.as_str()),
            "{response}"
        );
        assert_eq!(
            next_cursor
                .get(1)
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("type"))
                .and_then(Value::as_str),
            Some("null"),
            "{response}"
        );
    }
    let digest = schemas
        .get("DaDigest32")
        .and_then(Value::as_object)
        .expect("DA digest schema");
    assert_eq!(digest.get("minItems").and_then(Value::as_u64), Some(1));
    assert_eq!(digest.get("maxItems").and_then(Value::as_u64), Some(1));
    let digest_bytes = digest
        .get("items")
        .and_then(Value::as_object)
        .expect("DA digest byte-array schema");
    assert_eq!(
        digest_bytes.get("minItems").and_then(Value::as_u64),
        Some(32)
    );
    assert_eq!(
        digest_bytes.get("maxItems").and_then(Value::as_u64),
        Some(32)
    );
    assert!(
        !schemas.contains_key("DaBytes48"),
        "removed KZG wire values must not remain in the first-release schema"
    );
    let proof_scheme = schemas
        .get("DaTaggedProofScheme")
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("type"))
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("enum"))
        .and_then(Value::as_array)
        .expect("DA proof-scheme enum");
    assert_eq!(
        proof_scheme
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["MerkleSha256"]
    );
    let commitment_record = schemas
        .get("DaCommitmentRecord")
        .and_then(Value::as_object)
        .expect("DA commitment record schema");
    assert!(
        !commitment_record
            .get("properties")
            .and_then(Value::as_object)
            .is_some_and(|properties| properties.contains_key("kzg_commitment")),
        "removed KZG commitments must not remain in DA record properties"
    );
    assert!(
        !commitment_record
            .get("required")
            .and_then(Value::as_array)
            .is_some_and(|required| {
                required
                    .iter()
                    .any(|field| field.as_str() == Some("kzg_commitment"))
            }),
        "removed KZG commitments must not remain in DA record requirements"
    );
    let direction = schemas
        .get("MerkleDirection")
        .and_then(Value::as_object)
        .expect("DA Merkle direction schema");
    assert_eq!(
        direction.get("type").and_then(Value::as_str),
        Some("object")
    );
    assert_eq!(
        direction
            .get("required")
            .and_then(Value::as_array)
            .map(|required| required
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()),
        Some(vec!["direction", "value"])
    );
    for proof in ["DaCommitmentProof", "DaPinIntentProof"] {
        let properties = schemas
            .get(proof)
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing `{proof}` properties"));
        assert_eq!(
            properties
                .get("bundle_hash")
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("allOf"))
                .and_then(Value::as_array)
                .and_then(|schemas| schemas.first())
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("$ref"))
                .and_then(Value::as_str),
            Some("#/components/schemas/DaIrohaHash")
        );
        assert!(
            properties
                .get("bundle_hash")
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("description"))
                .and_then(Value::as_str)
                .is_some_and(|description| description.contains("tree version")),
            "{proof}.bundle_hash must describe the committed tree descriptor"
        );
        assert_eq!(
            properties
                .get("path")
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("maxItems"))
                .and_then(Value::as_u64),
            Some(32)
        );
    }
    for [schema, field] in openapi_contract_fixed_rows::<2>(
        "vpn.da_proof_openapi_contracts_match_exact_norito_json_wire_shapes.rows.5",
    ) {
        let alias = schemas
            .get(schema)
            .and_then(Value::as_object)
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .and_then(|properties| properties.get(field))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing `{schema}.{field}` schema"));
        assert_eq!(alias.get("maxLength").and_then(Value::as_u64), Some(256));
        assert_eq!(
            alias.get("x-iroha-maxUtf8Bytes").and_then(Value::as_u64),
            Some(256)
        );
    }
    for verify in ["DaCommitmentVerifyResponse", "DaPinIntentVerifyResponse"] {
        assert_eq!(
            schemas
                .get(verify)
                .and_then(Value::as_object)
                .and_then(|schema| schema.get("oneOf"))
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(2),
            "{verify}"
        );
    }
}
