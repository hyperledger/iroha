#[test]
fn pipeline_status_openapi_exposes_only_the_exact_first_release_scope() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    let response = schemas
        .get("PipelineTransactionStatusResponse")
        .and_then(Value::as_object)
        .expect("pipeline transaction status response schema");
    assert_eq!(response.get("type"), Some(&Value::from("object")));
    assert_eq!(
        response.get("additionalProperties"),
        Some(&Value::from(false))
    );
    let properties = response
        .get("properties")
        .and_then(Value::as_object)
        .expect("pipeline transaction status response properties");
    let exact_response_fields = BTreeSet::from(["hash", "resolved_from", "scope", "status"]);
    assert_eq!(
        properties
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        exact_response_fields
    );
    assert_eq!(
        response["required"]
            .as_array()
            .expect("pipeline transaction status required fields")
            .iter()
            .map(|field| {
                field
                    .as_str()
                    .expect("pipeline transaction status required field name")
            })
            .collect::<BTreeSet<_>>(),
        exact_response_fields
    );
    assert_eq!(properties["scope"]["type"], Value::from("string"));
    assert_eq!(
        properties["scope"]["enum"],
        Value::Array(vec![Value::from("local"), Value::from("global")])
    );
    assert_eq!(properties["hash"]["type"], Value::from("string"));
    assert_eq!(properties["hash"]["minLength"], Value::from(64_u64));
    assert_eq!(properties["hash"]["maxLength"], Value::from(64_u64));
    assert_eq!(
        properties["hash"]["pattern"],
        Value::from("^[0-9a-f]{63}[13579bdf]$")
    );
    assert!(
        properties["hash"]["description"]
            .as_str()
            .expect("pipeline response hash description")
            .contains("Iroha hash marker set")
    );

    let operation = &document["paths"]["/v1/pipeline/transactions/status"]["get"];
    assert_eq!(
        operation["responses"]
            .as_object()
            .expect("pipeline status responses")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["200", "404", "413", "429", "503"])
    );
    for status in ["404", "413", "429", "503"] {
        let content = operation["responses"][status]["content"]
            .as_object()
            .expect("typed pipeline error representations");
        assert_eq!(
            content.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            BTreeSet::from(["application/json", "application/x-norito"])
        );
        for media in ["application/json", "application/x-norito"] {
            assert_eq!(content[media]["schema"], schema_ref("ErrorEnvelope"));
        }
    }
    let missing_description = operation["responses"]["404"]["description"]
        .as_str()
        .expect("exact pipeline absence semantics");
    for detail in [
        "pipeline_transaction_status_not_found",
        "details.pipeline_transaction_status_not_found",
        "exact requested",
        "404 alone",
    ] {
        assert!(
            missing_description.contains(detail),
            "missing distinction: {detail}"
        );
    }
    assert!(
        operation["responses"]["503"]["description"]
            .as_str()
            .expect("incomplete global observation semantics")
            .contains("route_unavailable")
    );
    let permanent = &operation["responses"]["413"];
    for detail in [
        "history_read_exceeds_request_budget",
        "details.field",
        "details.actual",
        "details.expected",
    ] {
        assert!(
            permanent["description"]
                .as_str()
                .expect("permanent history-budget refusal")
                .contains(detail),
            "missing budget detail: {detail}"
        );
    }
    assert!(permanent.get("headers").is_none());
    let transient = &operation["responses"]["429"];
    assert!(
        transient["description"]
            .as_str()
            .expect("retryable history-budget refusal")
            .contains("cumulative decoder exhaustion")
    );
    assert_eq!(
        transient["headers"]["Retry-After"]["schema"]["minimum"],
        Value::from(1_u64)
    );
    let detail = &schemas["PipelineTransactionStatusNotFoundV1"];
    assert_eq!(detail["type"], Value::from("object"));
    assert_eq!(detail["additionalProperties"], Value::from(false));
    let absence = iroha_torii_shared::PipelineTransactionStatusNotFoundV1 {
        hash: "ab".repeat(32),
        scope: "global".to_owned(),
    };
    assert!(absence.is_valid());
    let encoded = norito::json::to_vec(&absence).expect("native scoped absence");
    let native: Value = norito::json::from_slice(&encoded).expect("native fields");
    let native_fields = native
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        detail["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| field.as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        native_fields
    );
    let detail_properties = component_properties(schemas, "PipelineTransactionStatusNotFoundV1");
    assert_eq!(
        detail_properties
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        native_fields
    );
    for constraint in ["type", "minLength", "maxLength", "pattern"] {
        assert_eq!(
            detail_properties["hash"][constraint],
            properties["hash"][constraint]
        );
    }
    assert_eq!(
        detail_properties["scope"]["enum"],
        properties["scope"]["enum"]
    );
    assert_eq!(
        component_properties(schemas, "ErrorDetails")["pipeline_transaction_status_not_found"],
        schema_ref("PipelineTransactionStatusNotFoundV1")
    );
    let parameters = operation["parameters"]
        .as_array()
        .expect("pipeline status parameters");
    assert_eq!(
        parameters
            .iter()
            .map(|parameter| {
                parameter["name"]
                    .as_str()
                    .expect("pipeline status parameter name")
            })
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["hash", "scope"])
    );
    assert!(
        parameters
            .iter()
            .all(|parameter| parameter["in"] == Value::from("query"))
    );
    let scope = parameters
        .iter()
        .find(|parameter| parameter["name"].as_str() == Some("scope"))
        .expect("pipeline status scope parameter");
    assert_eq!(scope["required"], Value::from(false));
    assert_eq!(scope["schema"]["type"], Value::from("string"));
    assert_eq!(scope["schema"]["default"], Value::from("global"));
    assert_eq!(
        scope["schema"]["enum"],
        Value::Array(vec![Value::from("local"), Value::from("global")])
    );
    assert!(
        scope["description"]
            .as_str()
            .expect("pipeline status scope description")
            .contains("omission selects `global`")
    );
    let hash = parameters
        .iter()
        .find(|parameter| parameter["name"].as_str() == Some("hash"))
        .expect("pipeline status hash parameter");
    assert_eq!(hash["required"], Value::from(true));
    assert_eq!(hash["schema"]["type"], Value::from("string"));
    assert_eq!(hash["schema"]["minLength"], Value::from(64_u64));
    assert_eq!(hash["schema"]["maxLength"], Value::from(64_u64));
    assert_eq!(
        hash["schema"]["pattern"],
        Value::from("^[0-9a-f]{63}[13579bdf]$")
    );
    assert!(
        hash["description"]
            .as_str()
            .expect("pipeline request hash description")
            .contains("Iroha hash marker set")
    );
}

#[test]
fn npos_schema_excludes_retired_process_local_and_vrf_surfaces() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    let retired = [
        "vrf_penalty_epoch",
        "vrf_committed_no_reveal_total",
        "vrf_no_participation_total",
        "vrf_late_reveals_total",
        "vrf_commit_deadline_offset",
        "vrf_reveal_deadline_offset",
    ];
    let npos = schemas
        .get("SumeragiNposDiagnostics")
        .and_then(Value::as_object)
        .expect("NPoS diagnostics schema");
    let npos_properties = npos
        .get("properties")
        .and_then(Value::as_object)
        .expect("NPoS diagnostics properties");
    assert_eq!(
        npos_properties
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["epoch_length_blocks", "epoch_seed"])
    );
    for field in retired {
        assert!(
            !npos_properties.contains_key(field),
            "retired process-local VRF counter remains in OpenAPI: {field}"
        );
    }
    assert!(
        !schemas.contains_key("SumeragiVrfPenaltiesReport"),
        "retired VRF penalty report schema remains in OpenAPI"
    );
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .expect("OpenAPI paths");
    assert!(
        paths
            .keys()
            .all(|path| !path.starts_with("/v1/sumeragi/vrf/")),
        "retired Sumeragi VRF path remains in OpenAPI"
    );
}

#[test]
fn status_openapi_uses_only_exact_scalar_probe_paths() {
    let document = canonical_document();
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .expect("OpenAPI paths");
    assert_eq!(
        paths
            .keys()
            .filter(|path| path.as_str() == "/status" || path.starts_with("/status/"))
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["/status", "/status/blocks", "/status/peers"])
    );
    assert!(!paths.contains_key("/status/{tail}"));
    assert!(paths.contains_key("/openapi.json"));
    assert!(
        !paths.contains_key("/openapi"),
        "the extensionless pre-release OpenAPI alias must not be documented"
    );
    assert_eq!(
        paths["/status"]["get"]["responses"]["200"]["content"]
            .as_object()
            .expect("full status response content")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["application/json", "application/x-norito"])
    );
    for retired in [
        "/v1/node/query/projection/checkpoint/plan",
        "/v1/node/query/projection/checkpoint/publish",
    ] {
        assert!(
            !paths.contains_key(retired),
            "retired unverified projection route leaked into OpenAPI: {retired}"
        );
    }
    for path in ["/status/blocks", "/status/peers"] {
        let item = paths
            .get(path)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{path} path item"));
        assert_eq!(
            item.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            BTreeSet::from(["get"]),
            "{path} must expose only GET"
        );
        let operation = item
            .get("get")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{path} GET operation"));
        assert!(
            operation.get("parameters").is_none(),
            "exact status probes do not accept path selectors"
        );
        let schema = &operation["responses"]["200"]["content"]["application/json"]["schema"];
        assert_eq!(
            operation["responses"]["200"]["content"]
                .as_object()
                .expect("scalar status response content")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["application/json"])
        );
        assert_eq!(schema["type"], Value::from("integer"));
        assert_eq!(schema["format"], Value::from("uint64"));
        assert_eq!(schema["minimum"], Value::from(0_u64));
    }
}

#[test]
fn operator_webauthn_openapi_is_closed_bounded_and_capacity_aware() {
    fn object_fields<'a>(schema: &'a Value, label: &str) -> BTreeSet<&'a str> {
        schema
            .get("properties")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{label} properties"))
            .keys()
            .map(String::as_str)
            .collect()
    }
    fn required_fields<'a>(schema: &'a Value, label: &str) -> BTreeSet<&'a str> {
        schema
            .get("required")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("{label} required fields"))
            .iter()
            .map(|field| {
                field
                    .as_str()
                    .unwrap_or_else(|| panic!("{label} required field name"))
            })
            .collect()
    }
    let document = canonical_document();
    let schemas = component_schemas(&document);
    let credential_fields = BTreeSet::from(["id", "rawId", "response", "type"]);
    for (request_name, response_name, response_fields) in [
        (
            "OperatorWebAuthnAssertionRequest",
            "OperatorWebAuthnAssertionResponse",
            BTreeSet::from(["authenticatorData", "clientDataJSON", "signature"]),
        ),
        (
            "OperatorWebAuthnAttestationRequest",
            "OperatorWebAuthnAttestationResponse",
            BTreeSet::from(["attestationObject", "clientDataJSON"]),
        ),
    ] {
        let request = schemas
            .get(request_name)
            .unwrap_or_else(|| panic!("{request_name} schema"));
        assert_eq!(request["type"], Value::from("object"));
        assert_eq!(request["additionalProperties"], Value::from(false));
        assert_eq!(object_fields(request, request_name), credential_fields);
        assert_eq!(required_fields(request, request_name), credential_fields);
        assert_eq!(
            request["properties"]["type"]["const"],
            Value::from("public-key")
        );
        for id_field in ["id", "rawId"] {
            assert_eq!(
                request["properties"][id_field]["$ref"],
                Value::from("#/components/schemas/OperatorWebAuthnCredentialId")
            );
        }
        assert_eq!(
            request["properties"]["response"]["$ref"],
            Value::from(format!("#/components/schemas/{response_name}"))
        );
        let response = schemas
            .get(response_name)
            .unwrap_or_else(|| panic!("{response_name} schema"));
        assert_eq!(response["additionalProperties"], Value::from(false));
        assert_eq!(object_fields(response, response_name), response_fields);
        assert_eq!(required_fields(response, response_name), response_fields);
        for field in response_fields {
            assert_eq!(
                response["properties"][field]["$ref"],
                Value::from("#/components/schemas/OperatorWebAuthnBinary")
            );
        }
    }
    let binary = &schemas["OperatorWebAuthnBinary"];
    assert_eq!(binary["minLength"], Value::from(1_u64));
    assert_eq!(binary["maxLength"], Value::from(65_536_u64));
    assert_eq!(
        binary["pattern"],
        Value::from("^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2}|[A-Za-z0-9_-]{3})?$")
    );
    let credential_id = &schemas["OperatorWebAuthnCredentialId"];
    assert_eq!(credential_id["minLength"], Value::from(1_u64));
    assert_eq!(credential_id["maxLength"], Value::from(1_366_u64));
    assert_eq!(
        credential_id["pattern"],
        Value::from("^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2}|[A-Za-z0-9_-]{3})?$")
    );

    let paths = document["paths"].as_object().expect("OpenAPI paths");
    for (path, request_name, expected_responses) in [
        (
            "/v1/operator/auth/login/verify",
            "OperatorWebAuthnAssertionRequest",
            BTreeSet::from(["200", "400", "401", "403", "413", "415", "429", "503"]),
        ),
        (
            "/v1/operator/auth/registration/verify",
            "OperatorWebAuthnAttestationRequest",
            BTreeSet::from([
                "200", "400", "401", "403", "409", "413", "415", "429", "503",
            ]),
        ),
    ] {
        let operation = &paths[path]["post"];
        assert_eq!(
            operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            Value::from(format!("#/components/schemas/{request_name}"))
        );
        assert_eq!(operation["requestBody"]["required"], Value::from(true));
        assert_eq!(
            operation["x-iroha-max-request-bytes"],
            Value::from(65_536_u64)
        );
        let responses = operation["responses"]
            .as_object()
            .unwrap_or_else(|| panic!("{path} responses"));
        assert_eq!(
            responses
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            expected_responses
        );
        assert!(
            responses["413"]["description"]
                .as_str()
                .is_some_and(|description| description.contains("request_payload_too_large"))
        );
        assert!(
            responses["503"]["description"]
                .as_str()
                .is_some_and(|description| {
                    description.contains("operator_auth_state_capacity_exhausted")
                })
        );
    }
    assert!(
        paths["/v1/operator/auth/registration/verify"]["post"]["responses"]["409"]["description"]
            .as_str()
            .is_some_and(|description| {
                description.contains("operator_webauthn_credential_duplicate")
                    && description.contains("operator_webauthn_credential_capacity_exhausted")
            })
    );
    for path in [
        "/v1/operator/auth/login/options",
        "/v1/operator/auth/registration/options",
    ] {
        assert!(
            paths[path]["post"]["responses"]["503"]["description"]
                .as_str()
                .is_some_and(|description| {
                    description.contains("operator_auth_state_capacity_exhausted")
                })
        );
    }

    let metadata = &schemas["OperatorWebAuthnCredentialMetadata"];
    assert_eq!(metadata["additionalProperties"], Value::from(false));
    assert_eq!(
        object_fields(metadata, "OperatorWebAuthnCredentialMetadata"),
        BTreeSet::from(["algorithm", "created_at_ms", "credential_id", "sign_count"])
    );
    assert_eq!(
        required_fields(metadata, "OperatorWebAuthnCredentialMetadata"),
        BTreeSet::from(["algorithm", "created_at_ms", "credential_id", "sign_count"])
    );
    assert_eq!(
        metadata["properties"]["credential_id"]["$ref"],
        Value::from("#/components/schemas/OperatorWebAuthnCredentialId")
    );
    assert_eq!(
        metadata["properties"]["algorithm"]["$ref"],
        Value::from("#/components/schemas/OperatorWebAuthnAlgorithm")
    );
    assert_eq!(
        schemas["OperatorWebAuthnAlgorithm"]["enum"],
        Value::Array(vec![Value::from("es256"), Value::from("ed25519")])
    );
    assert_eq!(
        metadata["properties"]["sign_count"]["format"],
        Value::from("uint32")
    );
    assert_eq!(
        metadata["properties"]["created_at_ms"]["format"],
        Value::from("uint64")
    );

    let list_response = &schemas["OperatorWebAuthnCredentialListResponse"];
    assert_eq!(list_response["additionalProperties"], Value::from(false));
    assert_eq!(
        object_fields(list_response, "OperatorWebAuthnCredentialListResponse"),
        BTreeSet::from(["credentials", "credentials_total"])
    );
    assert_eq!(
        required_fields(list_response, "OperatorWebAuthnCredentialListResponse"),
        BTreeSet::from(["credentials", "credentials_total"])
    );
    assert_eq!(
        list_response["properties"]["credentials"]["items"]["$ref"],
        Value::from("#/components/schemas/OperatorWebAuthnCredentialMetadata")
    );
    assert_eq!(
        list_response["properties"]["credentials"]["maxItems"],
        Value::from(1_024_u64)
    );

    let delete_response = &schemas["OperatorWebAuthnCredentialDeleteResponse"];
    assert_eq!(delete_response["additionalProperties"], Value::from(false));
    assert_eq!(
        object_fields(delete_response, "OperatorWebAuthnCredentialDeleteResponse"),
        BTreeSet::from(["credential_id", "credentials_total", "status"])
    );
    assert_eq!(
        required_fields(delete_response, "OperatorWebAuthnCredentialDeleteResponse"),
        BTreeSet::from(["credential_id", "credentials_total", "status"])
    );
    assert_eq!(
        delete_response["properties"]["status"]["const"],
        Value::from("ok")
    );

    let credential_routes = [
        (
            "/v1/operator/auth/credentials",
            "get",
            "operatorAuthCredentials",
            "OperatorWebAuthnCredentialListResponse",
            BTreeSet::from(["200", "401", "403", "429", "500"]),
        ),
        (
            "/v1/operator/auth/credentials/{credential_id}",
            "delete",
            "operatorAuthCredentialDelete",
            "OperatorWebAuthnCredentialDeleteResponse",
            BTreeSet::from(["200", "400", "401", "403", "404", "409", "429", "500"]),
        ),
    ];
    for (path, method, operation_id, response_schema, expected_responses) in credential_routes {
        let operation = &paths[path][method];
        assert_eq!(operation["operationId"], Value::from(operation_id));
        assert_eq!(
            operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            Value::from(format!("#/components/schemas/{response_schema}"))
        );
        let responses = operation["responses"]
            .as_object()
            .unwrap_or_else(|| panic!("{path} responses"));
        assert_eq!(
            responses
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            expected_responses
        );
        for response in responses.values() {
            assert_eq!(
                response["headers"]["Cache-Control"]["schema"]["const"],
                Value::from("private, no-store"),
                "{path} response must be private and non-cacheable"
            );
        }
        let session = operation["parameters"]
            .as_array()
            .unwrap_or_else(|| panic!("{path} parameters"))
            .iter()
            .find(|parameter| parameter["name"].as_str() == Some("X-Iroha-Operator-Session"))
            .unwrap_or_else(|| panic!("{path} session parameter"));
        assert_eq!(session["in"], Value::from("header"));
        assert_eq!(session["required"], Value::from(true));
        assert_eq!(session["schema"]["minLength"], Value::from(43_u64));
        assert_eq!(session["schema"]["maxLength"], Value::from(43_u64));
    }
    let deletion = &paths["/v1/operator/auth/credentials/{credential_id}"]["delete"];
    let parameters = deletion["parameters"]
        .as_array()
        .expect("credential deletion path parameters");
    assert_eq!(parameters.len(), 6);
    assert_eq!(
        operation_header_requirements(deletion.as_object().expect("credential deletion operation"))
            .into_iter()
            .collect::<BTreeSet<_>>(),
        [
            "X-Iroha-Operator-Public-Key",
            "X-Iroha-Operator-Timestamp-Ms",
            "X-Iroha-Operator-Nonce",
            "X-Iroha-Operator-Signature",
            "X-Iroha-Operator-Session",
        ]
        .into_iter()
        .map(|name| (name.to_owned(), true))
        .collect()
    );
    let credential_id = parameters
        .iter()
        .find(|parameter| parameter["name"].as_str() == Some("credential_id"))
        .expect("credential deletion ID path parameter");
    assert_eq!(credential_id["in"], Value::from("path"));
    assert_eq!(credential_id["required"], Value::from(true));
    assert_eq!(
        credential_id["schema"]["$ref"],
        Value::from("#/components/schemas/OperatorWebAuthnCredentialId")
    );
    assert!(
        paths["/v1/operator/auth/credentials"]["get"]["responses"]["500"]["description"]
            .as_str()
            .is_some_and(|description| description.contains("operator_webauthn_state_unavailable"))
    );
    assert!(
        deletion["responses"]["404"]["description"]
            .as_str()
            .is_some_and(
                |description| description.contains("operator_webauthn_credential_not_found")
            )
    );
    assert!(
        deletion["responses"]["409"]["description"]
            .as_str()
            .is_some_and(|description| description.contains("operator_webauthn_last_credential"))
    );
    assert!(
        deletion["responses"]["500"]["description"]
            .as_str()
            .is_some_and(|description| {
                description.contains("operator_webauthn_state_unavailable")
                    && description.contains("operator_webauthn_persist_failed")
            })
    );
}

#[test]
fn finality_attestation_tip_progress_openapi_matches_native_bindings() {
    use iroha_torii_shared::{
        bridge_attestation::{
            FinalityAttestationFailure, FinalityAttestationFailureReason as Reason,
        },
        bridge_finality::BridgeFinalityAttestationTipMismatchV1,
    };
    let document = generate_spec();
    let path = "/v1/bridge/finality/attestation/{height}";
    let operation = openapi_operation(&document, path, "get");
    let progress_response = &operation["responses"]["409"];
    let description = progress_response["description"].as_str().unwrap();
    for distinction in [
        "FinalityAttestationFailure",
        "tip_mismatch",
        "existing deadline",
        "not finality proof",
        "missing/corrupt proofs",
        "CommitQC",
        "not all equal",
    ] {
        assert!(
            description.contains(distinction),
            "missing progress distinction: {distinction}"
        );
    }
    let content = response_content(operation, "409");
    assert_eq!(
        content.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from(["application/json", "application/x-norito"])
    );
    for media in ["application/json", "application/x-norito"] {
        assert_eq!(content[media]["schema"], schema_ref("ErrorEnvelope"));
    }
    assert!(
        operation["responses"]["404"]["description"]
            .as_str()
            .unwrap()
            .contains("fixed failure")
    );
    let schemas = component_schemas(&document);
    let schema = &schemas["BridgeFinalityAttestationTipMismatchV1"];
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    let key =
        iroha_crypto::KeyPair::try_from_seed(vec![71; 32], iroha_crypto::Algorithm::BlsNormal)
            .unwrap();
    let payload = BridgeFinalityAttestationTipMismatchV1 {
        requested_height: 10,
        applied_height: 9,
        status_height: 10,
        challenge: [7; 32],
        node_id: iroha_model_base::peer::PeerId::new(key.public_key().clone()),
        network_id: iroha_data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                b"OpenAPI progress",
            )),
        ),
    };
    assert!(payload.is_valid());
    let bytes = norito::json::to_vec(&payload).unwrap();
    let value: Value = norito::json::from_slice(&bytes).unwrap();
    let native_fields = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| field.as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        native_fields
    );
    let properties = component_properties(schemas, "BridgeFinalityAttestationTipMismatchV1");
    assert_eq!(
        properties
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        native_fields
    );
    for height in ["requested_height", "applied_height", "status_height"] {
        assert_eq!(properties[height]["minimum"].as_u64(), Some(1));
        assert_eq!(properties[height]["format"].as_str(), Some("uint64"));
    }
    for field in ["challenge", "network_id"] {
        assert_eq!(
            properties[field],
            component_properties(schemas, "SumeragiFinalityAttestationBody")[field]
        );
    }
    assert!(
        component_properties(schemas, "ErrorDetails")
            .get("bridge_finality_attestation_tip_mismatch")
            .is_none()
    );
    assert_eq!(
        component_properties(schemas, "ErrorDetails")["finality_attestation_failure"],
        schema_ref("FinalityAttestationFailure")
    );
    assert_eq!(
        component_properties(schemas, "FinalityAttestationFailure")["tip_mismatch"]["anyOf"][0],
        schema_ref("BridgeFinalityAttestationTipMismatchV1")
    );
    let failure = FinalityAttestationFailure {
        challenge: payload.challenge,
        height: payload.requested_height,
        reason: Reason::TipChanged,
        tip_mismatch: Some(payload),
    };
    let failure_json: Value =
        norito::json::from_slice(&norito::json::to_vec(&failure).unwrap()).unwrap();
    assert_eq!(failure_json["reason"].as_str(), Some("TipChanged"));
    assert_eq!(
        component_properties(schemas, "FinalityAttestationFailure")["reason"],
        schema_ref("FinalityAttestationFailureReason")
    );
    assert_eq!(
        schemas["FinalityAttestationFailureReason"]["type"].as_str(),
        Some("string")
    );
    let failure_fields = failure_json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        component_properties(schemas, "FinalityAttestationFailure")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        failure_fields
    );
    assert_eq!(
        schemas["FinalityAttestationFailure"]["additionalProperties"],
        Value::Bool(false)
    );
    for status in ["409", "503", "500"] {
        let content = response_content(operation, status);
        for media in ["application/json", "application/x-norito"] {
            assert_eq!(content[media]["schema"], schema_ref("ErrorEnvelope"));
        }
    }
    assert_eq!(
        schemas["FinalityAttestationFailureReason"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "ConsensusUninitialized",
            "GenesisUncommitted",
            "RestartRequired",
            "TipChanged",
            "ConflictingState",
            "FinalityUnavailable",
            "InternalFailure"
        ])
    );
    let native_reason_labels = [
        Reason::ConsensusUninitialized,
        Reason::GenesisUncommitted,
        Reason::RestartRequired,
        Reason::TipChanged,
        Reason::ConflictingState,
        Reason::FinalityUnavailable,
        Reason::InternalFailure,
    ]
    .map(|reason| {
        let json: Value =
            norito::json::from_slice(&norito::json::to_vec(&reason).unwrap()).unwrap();
        json.as_str().expect("reason is a scalar string").to_owned()
    });
    assert_eq!(
        schemas["FinalityAttestationFailureReason"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>(),
        native_reason_labels.into_iter().collect::<BTreeSet<_>>()
    );
}
