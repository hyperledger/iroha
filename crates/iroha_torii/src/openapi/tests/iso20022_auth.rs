#[test]
fn iso20022_operations_require_fresh_operator_signatures() {
    let document = generate_spec();
    let expected = BTreeSet::from([
        "X-Iroha-Operator-Public-Key".to_owned(),
        "X-Iroha-Operator-Timestamp-Ms".to_owned(),
        "X-Iroha-Operator-Nonce".to_owned(),
        "X-Iroha-Operator-Signature".to_owned(),
    ]);
    for descriptor in iroha_torii_shared::route_catalog::iso20022::ROUTES {
        let method = match descriptor.method() {
            CatalogHttpMethod::Get => "get",
            CatalogHttpMethod::Post => "post",
            other => panic!("unexpected ISO 20022 method: {other:?}"),
        };
        let all_headers =
            operation_header_requirements(openapi_operation(&document, descriptor.path(), method));
        assert!(
            all_headers
                .iter()
                .all(|(name, _)| name != "X-Iroha-Iso-Profile"),
            "{method} {} retains the unsigned profile selector",
            descriptor.path()
        );
        let headers = all_headers
            .into_iter()
            .filter_map(|(name, required)| {
                name.starts_with("X-Iroha-Operator-").then(|| {
                    assert!(
                        required,
                        "{method} {} {name} must be required",
                        descriptor.path()
                    );
                    name
                })
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(headers, expected, "{method} {}", descriptor.path());
    }
}

#[test]
fn iso20022_openapi_documents_party_scope_durable_admission_and_signed_xml() {
    let document = generate_spec();
    let component_headers = document["components"]["headers"]
        .as_object()
        .expect("OpenAPI component headers");
    assert_eq!(
        component_headers["IsoOutboundSignatureDomainV2"]["schema"]["const"].as_str(),
        Some("iroha.iso20022.outbound.v2")
    );
    assert_eq!(
        component_headers["IsoOutboundSignatureV2"]["schema"]["pattern"].as_str(),
        Some("^[A-Za-z0-9+/]+={0,2}$")
    );
    assert_eq!(
        component_headers["IsoOutboundSignerV2"]["required"].as_bool(),
        Some(true)
    );

    let expected_signature_headers = [
        (
            "X-Iroha-Iso-Signature-Domain",
            "#/components/headers/IsoOutboundSignatureDomainV2",
        ),
        (
            "X-Iroha-Iso-Signature",
            "#/components/headers/IsoOutboundSignatureV2",
        ),
        (
            "X-Iroha-Iso-Signer",
            "#/components/headers/IsoOutboundSignerV2",
        ),
    ];
    for path in [
        "/v1/iso20022/messages/{msg_id}/camt029",
        "/v1/iso20022/messages/{msg_id}/pacs002",
        "/v1/iso20022/messages/{msg_id}/pacs004",
        "/v1/iso20022/messages/{msg_id}/sese024",
        "/v1/iso20022/messages/{msg_id}/sese025",
    ] {
        let operation = openapi_operation(&document, path, "get");
        let description = operation["description"]
            .as_str()
            .expect("ISO XML operation description");
        assert!(description.contains("party-scoped"), "{path}");
        assert!(description.contains("exact response bytes"), "{path}");
        let response = &operation["responses"]["200"];
        assert_eq!(
            response["content"]["application/xml"]["schema"]["$ref"].as_str(),
            Some("#/components/schemas/XmlText"),
            "{path}"
        );
        let headers = response["headers"]
            .as_object()
            .expect("signed XML response headers");
        for (name, expected_ref) in expected_signature_headers {
            assert_eq!(headers[name]["$ref"].as_str(), Some(expected_ref), "{path}");
        }
    }

    let message_description = openapi_operation(&document, "/v1/iso20022/messages/{msg_id}", "get")
        ["description"]
        .as_str()
        .expect("ISO record description");
    assert!(message_description.contains("either original participant"));
    assert!(message_description.contains("audit-admin"));
    let audit_description =
        openapi_operation(&document, "/v1/iso20022/audit/messages", "get")["description"]
            .as_str()
            .expect("ISO audit description");
    assert!(audit_description.contains("originator or counterparty"));
    assert!(audit_description.contains("global read-only"));

    for path in [
        "/v1/iso20022/pacs008",
        "/v1/iso20022/pacs009",
        "/v1/iso20022/pacs002",
        "/v1/iso20022/pacs004",
        "/v1/iso20022/camt056",
        "/v1/iso20022/sese023",
        "/v1/iso20022/sese024",
        "/v1/iso20022/sese025",
        "/v1/iso20022/colr012",
    ] {
        let operation = openapi_operation(&document, path, "post");
        let request_content = operation["requestBody"]["content"]
            .as_object()
            .expect("ISO XML request content");
        assert_eq!(request_content.len(), 1, "{path}");
        assert_eq!(
            request_content["application/xml"]["schema"]["$ref"].as_str(),
            Some("#/components/schemas/XmlText"),
            "{path}"
        );
        assert!(!request_content.contains_key("application/json"), "{path}");
        let responses = operation["responses"]
            .as_object()
            .expect("ISO submission responses");
        assert!(responses.contains_key("202"), "{path}");
        assert!(responses.contains_key("503"), "{path}");
        assert!(!responses.contains_key("200"), "{path}");
    }
}

#[test]
fn iso20022_v2_status_and_audit_responses_are_exact_and_bounded() {
    let document = generate_spec();
    let schemas = component_schemas(&document);

    let message_path = "/v1/iso20022/messages/{msg_id}";
    assert_eq!(
        operation_response_schema_ref(
            openapi_operation(&document, message_path, "get"),
            "200",
            message_path,
        ),
        "#/components/schemas/Iso20022MessageStatusV2"
    );
    let status_fields = [
        "message_id",
        "status",
        "pacs002_code",
        "transaction_hash",
        "detail",
        "hold_reason_code",
        "change_reason_codes",
        "updated_at_ms",
        "ledger_id",
        "source_account_id",
        "source_account_address",
        "target_account_id",
        "target_account_address",
        "asset_definition_id",
        "asset_id",
        "settlement_amount",
        "settlement_currency",
        "settlement_date",
        "settlement_quantity",
        "settlement_movement_type",
        "settlement_payment_type",
        "security_instrument_id",
        "collateral_obligation_id",
        "collateral_original_amount",
        "collateral_original_currency",
        "collateral_original_instrument_id",
        "collateral_substitute_amount",
        "collateral_substitute_currency",
        "collateral_substitute_instrument_id",
        "collateral_effective_date",
        "collateral_substitution_type",
        "collateral_haircut",
        "collateral_reason_code",
        "plan_execution_order",
        "plan_atomicity",
        "reported_return",
        "native_payment",
        "profile_id",
        "message_type",
        "business_service",
        "business_message_id",
        "uetr",
        "payload_hash",
        "reference_snapshot_id",
        "embedded_signature_detected",
        "originator_participant_id",
        "counterparty_participant_id",
        "admitting_participant_id",
        "admitting_operator_key",
        "pinned_profile_id",
        "pinned_signature_policy",
        "status_history",
    ];
    assert_strict_object_schema(schemas, "Iso20022MessageStatusV2", &status_fields, &[]);
    assert!(
        !component_properties(schemas, "Iso20022MessageStatusV2").contains_key("version"),
        "the public status view must not invent a persistence version field"
    );
    let status_properties = component_properties(schemas, "Iso20022MessageStatusV2");
    assert_eq!(
        status_properties["change_reason_codes"]["maxItems"].as_u64(),
        Some(64)
    );
    assert_eq!(
        status_properties["status_history"]["minItems"].as_u64(),
        Some(1)
    );
    assert_eq!(
        status_properties["status_history"]["maxItems"].as_u64(),
        Some(256)
    );

    assert_strict_object_schema(
        schemas,
        "Iso20022StatusHistoryEntryV2",
        &[
            "status",
            "pacs002_code",
            "updated_at_ms",
            "detail",
            "reason_code",
        ],
        &[],
    );
    assert_eq!(
        schemas["Iso20022HistoryTextV2"]["anyOf"][0]["maxLength"].as_u64(),
        Some(262_144)
    );
    assert_eq!(
        schemas["Iso20022ChangeReasonCodeV2"]["maxLength"].as_u64(),
        Some(16_384)
    );

    let audit_path = "/v1/iso20022/audit/messages";
    assert_eq!(
        operation_response_schema_ref(
            openapi_operation(&document, audit_path, "get"),
            "200",
            audit_path,
        ),
        "#/components/schemas/Iso20022AuditIndexV2"
    );
    assert_strict_object_schema(
        schemas,
        "Iso20022AuditIndexV2",
        &["version", "record_count", "records", "index_sha256"],
        &[],
    );
    let audit_properties = component_properties(schemas, "Iso20022AuditIndexV2");
    assert_eq!(audit_properties["version"]["const"].as_u64(), Some(2));
    assert_eq!(
        audit_properties["record_count"]["maximum"].as_u64(),
        Some(1024)
    );
    assert_eq!(audit_properties["records"]["maxItems"].as_u64(), Some(1024));
    assert_eq!(
        audit_properties["records"]["items"]["$ref"].as_str(),
        Some("#/components/schemas/Iso20022AuditIndexEntryV2")
    );
    assert_strict_object_schema(
        schemas,
        "Iso20022AuditIndexEntryV2",
        &[
            "message_id",
            "filename",
            "record_sha256",
            "state",
            "pacs002_code",
            "updated_at_ms",
            "settled_at_ms",
            "transaction_hash",
            "profile_id",
            "message_type",
            "business_message_id",
            "uetr",
            "payload_hash",
            "reference_snapshot_id",
        ],
        &[],
    );
    let audit_entry = component_properties(schemas, "Iso20022AuditIndexEntryV2");
    assert_eq!(
        audit_entry["filename"]["pattern"].as_str(),
        Some("^[0-9a-f]{64}\\.json$")
    );
    assert_eq!(
        schemas["Iso20022Sha256HexV2"]["pattern"].as_str(),
        Some("^[0-9a-f]{64}$")
    );
    assert_eq!(
        schemas["Iso20022RecordStringV2"]["maxLength"].as_u64(),
        Some(1_048_576)
    );
    assert_eq!(schemas["Iso20022U64V2"]["maximum"].as_u64(), Some(u64::MAX));
    for (name, expected) in [
        (
            "Iso20022StatusStateV2",
            &["Pending", "Accepted", "Rejected"][..],
        ),
        (
            "Iso20022Pacs002CodeV2",
            &["ACTC", "ACSP", "ACSC", "ACWC", "PDNG", "RJCT"][..],
        ),
        (
            "Iso20022SignaturePolicyV2",
            &["record_only", "reject_unsupported", "require_verified"][..],
        ),
        (
            "Iso20022MessageTypeV2",
            &[
                "pacs.008", "pacs.009", "pacs.002", "pacs.004", "camt.056", "sese.023", "sese.024",
                "sese.025", "colr.012",
            ][..],
        ),
    ] {
        let actual = schemas[name]["enum"]
            .as_array()
            .unwrap_or_else(|| panic!("{name} enum"))
            .iter()
            .map(|value| value.as_str().expect("ISO enum string"))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "{name} values");
    }
}

#[test]
fn iso_return_report_schema_is_closed_and_separate_from_native_execution() {
    let document = generate_spec();
    let schemas = component_schemas(&document);
    assert_strict_object_schema(
        schemas,
        "Iso20022ReportedReturnV1",
        &[
            "amount",
            "currency",
            "disposition",
            "original_message_id",
            "original_payload_hash",
            "original_transaction_hash",
            "reason_code",
        ],
        &[],
    );
    let report = &schemas["Iso20022ReportedReturnV1"];
    assert_eq!(report["allOf"].as_array().unwrap().len(), 3);
    assert_eq!(
        report["allOf"][1]["then"]["properties"]["original_transaction_hash"]["type"].as_str(),
        Some("string")
    );
    assert_eq!(
        report["allOf"][2]["then"]["properties"]["original_transaction_hash"]["type"].as_str(),
        Some("null")
    );

    assert_eq!(
        report["properties"]["disposition"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "pending_original",
            "external_report",
            "original_rejected",
            "original_not_submitted",
            "invalid_terms"
        ]
    );
    assert!(
        report["properties"]
            .get("reverse_transaction_hash")
            .is_none()
    );
    assert_eq!(
        report["properties"]["original_transaction_hash"]["anyOf"][1]["type"].as_str(),
        Some("null")
    );
}

#[test]
fn iso_native_payment_schema_preserves_distinct_carrier_and_business_evidence() {
    let document = generate_spec();
    let schemas = component_schemas(&document);
    assert_strict_object_schema(
        schemas,
        "Iso20022NativePaymentV1",
        &[
            "intent_frame",
            "carrier",
            "business_settlement",
            "conflicting_intent",
            "verified",
        ],
        &[],
    );
    assert_strict_object_schema(
        schemas,
        "Iso20022NativeCarrierV1",
        &["height", "applied", "rejection"],
        &[],
    );
    assert_strict_object_schema(
        schemas,
        "Iso20022NativeBusinessSettlementV1",
        &["transaction_hash", "receipt_frame", "nexus_fee_frame"],
        &[],
    );
    let payment = &schemas["Iso20022NativePaymentV1"];
    assert_eq!(
        payment["properties"]["intent_frame"]["contentEncoding"].as_str(),
        Some("base64")
    );
    assert_eq!(
        payment["properties"]["intent_frame"]["maxLength"].as_u64(),
        Some(1_048_576)
    );
    assert_eq!(
        payment["properties"]["verified"]["type"].as_str(),
        Some("boolean")
    );
    assert_eq!(
        payment["allOf"][0]["then"]["properties"]["business_settlement"]["type"].as_str(),
        Some("null")
    );
}
