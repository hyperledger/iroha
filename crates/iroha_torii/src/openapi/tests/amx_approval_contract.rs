// The private approval read has a signed binary request and independently verified output.
#[test]
fn amx_debit_approval_openapi_matches_the_route_and_native_bounds() {
    use iroha_data_model::sumeragi_amx::approval_proof::{
        MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1, MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1,
    };

    let route = route_catalog::contracts_and_verification_keys::AMX_DEBIT_APPROVAL_PROOF_POST;
    let document = canonical_document();
    let operation = openapi_operation(&document, route.path(), "post");
    assert_eq!(operation["x-iroha-tool-effect"].as_str(), Some("read"));
    assert_eq!(
        operation["x-iroha-route-auth"]["stableRouteId"].as_str(),
        Some(route.stable_route_id())
    );
    assert_eq!(
        operation["x-iroha-route-auth"]["authentication"].as_str(),
        Some("canonical_account_signature")
    );
    let security = operation["security"].as_array().unwrap();
    assert!(
        security
            .iter()
            .all(|entry| !entry.as_object().unwrap().is_empty())
    );
    assert!(
        security
            .iter()
            .any(|entry| entry.get("IrohaCanonicalAccount").is_some())
    );
    assert!(
        security
            .iter()
            .any(|entry| entry.get("IrohaCanonicalWitness").is_some())
    );
    let request = operation["requestBody"]["content"].as_object().unwrap();
    assert_eq!(
        request.len(),
        1,
        "JSON does not substitute for the signed native frame"
    );
    let frame = &request["application/x-norito"]["schema"];
    assert_eq!(
        frame["maxLength"].as_u64(),
        Some(MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1 as u64)
    );
    assert_eq!(
        operation["x-iroha-max-response-bytes"].as_u64(),
        Some(MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1 as u64)
    );
    let success = &operation["responses"]["200"];
    assert_eq!(
        success["content"]["application/json"]["schema"],
        schema_ref("AmxDebitApprovalProofV1")
    );
    assert_eq!(
        success["content"]["application/x-norito"]["schema"]["maxLength"].as_u64(),
        Some(MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1 as u64)
    );
    for status in ["200", "401", "403", "409", "429"] {
        assert_eq!(
            operation["responses"][status]["headers"]["Cache-Control"]["schema"]["const"].as_str(),
            Some("private, no-store")
        );
    }
    for status in ["409", "429"] {
        let description = operation["responses"][status]["description"]
            .as_str()
            .unwrap();
        assert!(description.contains("amx_approval_read_failure"));
        assert!(description.contains("request"));
    }
    let description = operation["description"].as_str().unwrap();
    assert!(description.contains("current applied certified private-root height"));
    assert!(description.contains("Prepare rechecks"));
    assert!(description.contains("CanReadAllLedgerData"));
    assert!(description.contains("complete World hash inventory"));
    assert!(description.contains("revocation withholds"));
    assert!(
        operation["responses"]["403"]["description"]
            .as_str()
            .unwrap()
            .contains("Exact AMX debit permission alone")
    );
}

#[test]
fn amx_debit_approval_openapi_closed_fields_match_actual_native_json() {
    use iroha_data_model::{
        NetworkId,
        asset::{AssetBalanceScope, AssetDefinitionId, AssetId},
        sumeragi_amx::{AmxDebitApprovalProofV1, AmxDebitApprovalV1},
        sumeragi_finality::WorldStateSnapshotV1,
    };
    use iroha_model_base::{domain::DomainId, topology::DataSpaceId};

    let dataspace = DataSpaceId::new(7);
    let approval = AmxDebitApprovalV1 {
        global_network: NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"parent"),
        )),
        participant_network: NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(b"bank")),
        ),
        participant_instance: [7; 32],
        dataspace,
        transaction_id: [9; 32],
        debited_asset: AssetId::with_scope(
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("bank", "universal").unwrap(),
                "cash".parse().unwrap(),
            ),
            iroha_test_samples::ALICE_ID.clone(),
            AssetBalanceScope::Dataspace(dataspace),
        ),
    };
    approval.validate().unwrap();
    // This data-only fixture tests the exact wire shape, never proof admission.
    let proof = AmxDebitApprovalProofV1 {
        world: WorldStateSnapshotV1 {
            schema_hash: iroha_crypto::Hash::new(b"schema"),
            entries: Vec::new(),
        },
        relay_permissions: BTreeSet::from([approval.permission().unwrap()]),
    };
    let document = canonical_document();
    let schemas = component_schemas(&document);
    for (name, encoded) in [
        (
            "AmxDebitApprovalV1",
            norito::json::to_value(&approval).unwrap(),
        ),
        (
            "AmxDebitApprovalProofV1",
            norito::json::to_value(&proof).unwrap(),
        ),
    ] {
        assert_eq!(
            closed_schema_fields(schemas, name),
            json_fields(&encoded, name)
        );
    }
    assert_eq!(
        schemas["AmxDebitApprovalProofV1"]["properties"]["relay_permissions"]["maxItems"].as_u64(),
        Some(
            iroha_data_model::sumeragi_amx::approval_proof::MAX_AMX_DEBIT_APPROVAL_PERMISSIONS_V1
                as u64
        )
    );
}

#[test]
fn amx_approval_failure_openapi_matches_tagged_json_and_negotiated_frames() {
    use iroha_torii_shared::amx_approval_read::{
        AMX_APPROVAL_READ_FAILURE_MAX_BYTES, AmxApprovalReadFailureV1, AmxApprovalReadReasonV1,
    };

    let document = canonical_document();
    let schemas = component_schemas(&document);
    let failure_schema = &schemas["AmxApprovalReadFailureV1"];
    let reason_schema = &failure_schema["properties"]["reason"];
    assert_eq!(reason_schema["type"].as_str(), Some("object"));
    assert_eq!(reason_schema["additionalProperties"].as_bool(), Some(false));
    assert_eq!(
        reason_schema["required"],
        norito::json!(["kind", "details"]),
    );
    assert_eq!(
        reason_schema["properties"]["details"]["type"].as_str(),
        Some("null")
    );
    assert_eq!(
        reason_schema["properties"]["kind"]["type"].as_str(),
        Some("string")
    );
    assert_eq!(
        reason_schema["properties"]["kind"]["enum"],
        norito::json!(["CutChanged", "Capacity"]),
    );
    for (reason, kind, observed) in [
        (AmxApprovalReadReasonV1::CutChanged, "CutChanged", Some(1)),
        (AmxApprovalReadReasonV1::Capacity, "Capacity", None),
    ] {
        let failure = AmxApprovalReadFailureV1 {
            approval_hash: iroha_crypto::Hash::new(b"original request"),
            relay_header_hash: iroha_crypto::Hash::new(b"original relay"),
            requested_height: 2,
            reason,
            observed_height: observed,
            retry_after_ms: None,
        };
        let value = norito::json::to_value(&failure).unwrap();
        assert_eq!(
            closed_schema_fields(schemas, "AmxApprovalReadFailureV1"),
            json_fields(&value, "AMX failure")
        );
        assert_eq!(
            value["reason"],
            norito::json!({"kind": kind, "details": null})
        );
        let encoded = norito::json::to_json(&failure).unwrap();
        assert_eq!(
            norito::json::from_str::<AmxApprovalReadFailureV1>(&encoded).unwrap(),
            failure
        );
    }
    for retired in [
        r#""Capacity""#,
        r#"{"kind":"Capacity"}"#,
        r#"{"kind":"Capacity","details":null,"extra":0}"#,
    ] {
        assert!(norito::json::from_str::<AmxApprovalReadReasonV1>(retired).is_err());
    }
    let route = route_catalog::contracts_and_verification_keys::AMX_DEBIT_APPROVAL_PROOF_POST;
    let operation = openapi_operation(&document, route.path(), "post");
    for status in ["409", "429"] {
        let content = &operation["responses"][status]["content"];
        assert_eq!(
            content["application/json"]["schema"],
            schema_ref("ErrorEnvelope")
        );
        let wire = &content["application/x-norito"]["schema"];
        assert_eq!(wire["type"].as_str(), Some("string"));
        assert_eq!(wire["format"].as_str(), Some("binary"));
        assert_eq!(
            wire["maxLength"].as_u64(),
            Some(AMX_APPROVAL_READ_FAILURE_MAX_BYTES as u64)
        );
        assert_eq!(
            wire["x-iroha-norito-schema"].as_str(),
            Some("iroha_torii_shared::ErrorEnvelope")
        );
    }
    let unauthorized = operation["responses"]["401"]["description"]
        .as_str()
        .unwrap();
    assert!(!unauthorized.contains("503"));
    assert!(unauthorized.contains("429"));
}
