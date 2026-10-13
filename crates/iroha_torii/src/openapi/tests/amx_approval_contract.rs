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
    for status in ["200", "401", "503"] {
        assert_eq!(
            operation["responses"][status]["headers"]["Cache-Control"]["schema"]["const"].as_str(),
            Some("private, no-store")
        );
    }
    let unavailable = operation["responses"]["503"]["description"]
        .as_str()
        .unwrap();
    assert!(unavailable.contains("amx_debit_approval_authentication_capacity"));
    assert!(unavailable.contains("retryable"));
    let description = operation["description"].as_str().unwrap();
    assert!(description.contains("current applied certified private-root height"));
    assert!(description.contains("Prepare rechecks"));
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
