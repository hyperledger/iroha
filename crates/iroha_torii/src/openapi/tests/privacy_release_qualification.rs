//! Exact native JSON shape and cardinality controls for release qualification metadata.
//! Structural fixtures do not claim valid signatures, audits, deployment or qualification.
use super::*;
use iroha_data_model::privacy::*;

#[test]
fn privacy_release_qualification_records_match_native_json_fields() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    let key = iroha_crypto::KeyPair::try_from_seed(vec![41; 32], iroha_crypto::Algorithm::Ed25519)
        .unwrap();
    let source_identity = PrivacyReleaseSourceIdentityV1 {
        source_tree_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        source_tree_clean: true,
        toolchain_id: "schema-fixture".to_owned(),
        toolchain_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        cargo_lock_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
    };
    let executable_artifact = PrivacyReleaseExecutableArtifactV1 {
        kind: PrivacyReleaseExecutableKindV1::Binary,
        name: "schema-fixture".to_owned(),
        artifact_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
    };
    let protocol_binding = PrivacyReleaseProtocolBindingV1 {
        protocol_id: PrivacyProtocolIdV1::ALL[0],
        proof_system_id: PrivacyProtocolIdV1::ALL[0].expected_proof_system(),
        engine_id: PrivacyProtocolIdV1::ALL[0].expected_engine(),
        parameter_id: PrivacyParameterIdV1::new([1; 32]),
        parameter_digest: PrivacyParameterDigestV1::new([1; 32]),
        verifier_digest: PrivacyVerifierDigestV1::new([1; 32]),
        statement_schema_digest: PrivacyStatementSchemaDigestV1::new([1; 32]),
        engine_manifest_digest: PrivacyEngineManifestDigestV1::new([1; 32]),
        security_claim: PrivacySecurityClaimV1 {
            catalog_commitment: PrivacyExact12CatalogCommitmentV1::canonical(),
            protocol_id: PrivacyProtocolIdV1::ALL[0],
            security_model: PrivacySecurityModelV1::PostQuantumQrom,
            target_security_bits: 128,
            achieved_security_bits: 128,
            parameter_digest: PrivacyParameterDigestV1::new([1; 32]),
            verifier_digest: PrivacyVerifierDigestV1::new([1; 32]),
            reduction_digest: PrivacySecurityReductionDigestV1::new([1; 32]),
            audit_bundle_digest: PrivacyAuditBundleDigestV1::new([1; 32]),
        },
        security_claim_digest: PrivacySecurityClaimDigestV1::new([1; 32]),
    };
    let stage_receipt = PrivacyReleaseStageReceiptV1 {
        stage_ordinal: 1,
        protocol_id: PrivacyProtocolIdV1::ALL[0],
        stage: PrivacyReleaseStageV1::PositiveCanonicalEndToEnd,
        security_claim_digest: PrivacySecurityClaimDigestV1::new([1; 32]),
        parameter_digest: PrivacyParameterDigestV1::new([1; 32]),
        verifier_digest: PrivacyVerifierDigestV1::new([1; 32]),
        engine_manifest_digest: PrivacyEngineManifestDigestV1::new([1; 32]),
        receipt_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
    };
    let proof_artifact = PrivacyReleaseProofArtifactV1 {
        protocol_id: PrivacyProtocolIdV1::ALL[0],
        stage: PrivacyReleaseStageV1::PositiveCanonicalEndToEnd,
        stage_artifact_ordinal: 1,
        stage_receipt_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        security_claim_digest: PrivacySecurityClaimDigestV1::new([1; 32]),
        parameter_digest: PrivacyParameterDigestV1::new([1; 32]),
        verifier_digest: PrivacyVerifierDigestV1::new([1; 32]),
        engine_manifest_digest: PrivacyEngineManifestDigestV1::new([1; 32]),
        artifact_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
    };
    let sdk_package = PrivacyReleaseSdkPackageV1 {
        consumer: PrivacyReleaseSdkConsumerV1::KotlinJvm,
        package_name: "schema-fixture".to_owned(),
        package_version: "schema-fixture".to_owned(),
        package_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        fixture_corpus_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
    };
    let hardware_result = PrivacyReleaseHardwareResultV1 {
        backend: PrivacyReleaseHardwareBackendV1::Scalar,
        tested_binary_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        deterministic_output_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        scalar_reference_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        result_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        runtime_self_test_passed: true,
    };
    let medium_disposition = PrivacyAcceptedMediumDispositionV1 {
        finding_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        disposition_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        release_artifact_set_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        signature: iroha_crypto::Signature::new(key.private_key(), b"schema-only"),
    };
    let audit_record = PrivacyReleaseAuditV1 {
        audit_class: PrivacyReleaseAuditClassV1::Cryptographic,
        report_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        release_artifact_set_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        open_critical_findings: 1,
        open_high_findings: 1,
        accepted_medium_dispositions: Vec::new(),
        auditor: key.public_key().clone(),
        signature: iroha_crypto::Signature::new(key.private_key(), b"schema-only"),
    };
    let release_signature = PrivacyReleaseSignatureV1 {
        role: PrivacyReleaseSignatureRoleV1::ReleaseEngineering,
        signer: key.public_key().clone(),
        signature: iroha_crypto::Signature::new(key.private_key(), b"schema-only"),
    };
    let release_manifest = PrivacyExact12ReleaseManifestV1 {
        version: 1,
        catalog_id: "schema-fixture".to_owned(),
        catalog_commitment: PrivacyExact12CatalogCommitmentV1::canonical(),
        source: source_identity.clone(),
        abi_version: 1,
        abi_hash: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        syscall_list_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        executables: Vec::new(),
        protocols: Vec::new(),
        stage_receipts: Vec::new(),
        proof_artifacts: Vec::new(),
        sdk_packages: Vec::new(),
        hardware_results: Vec::new(),
        release_artifact_set_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        audits: Vec::new(),
        audit_bundle_digest: PrivacyAuditBundleDigestV1::new([1; 32]),
        release_signatures: Vec::new(),
        manifest_digest: PrivacyExact12ReleaseManifestDigestV1::new([1; 32]),
    };
    let activation = PrivacyDeploymentActivationV1 {
        protocol_id: PrivacyProtocolIdV1::ALL[0],
        activation_height: 1,
    };
    let validator_canary = PrivacyDeploymentValidatorCanaryV1 {
        validator_index: 1,
        validator: key.public_key().clone(),
        rollout_wave: 1,
        restart_count: 1,
        pre_restart_height: 1,
        post_restart_height: 1,
        canary_height: 1,
        canary_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        converged_state_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        endpoint_version: "schema-fixture".to_owned(),
    };
    let validator_signature = PrivacyDeploymentValidatorSignatureV1 {
        validator_index: 1,
        signature: iroha_crypto::Signature::new(key.private_key(), b"schema-only"),
    };
    let deployment_qualification = PrivacyExact12DeploymentQualificationV1 {
        version: 1,
        chain_id: iroha_model_base::chain::ChainId::from("schema-fixture"),
        network_id: iroha_data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(b"schema-only")),
        ),
        genesis_hash: [1; 32],
        release_manifest_digest: PrivacyExact12ReleaseManifestDigestV1::new([1; 32]),
        activation_transaction_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        activations: Vec::new(),
        validator_roster_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        endpoint_version: "schema-fixture".to_owned(),
        convergence_height: 1,
        converged_state_digest: PrivacyReleaseArtifactDigestV1::new([1; 32]),
        validator_canaries: Vec::new(),
        validator_signatures: Vec::new(),
        qualification_digest: PrivacyExact12DeploymentQualificationDigestV1::new([1; 32]),
    };
    let qualification_record = PrivacyExact12QualificationRecordV1 {
        release_manifest: release_manifest.clone(),
        deployment_qualification: deployment_qualification.clone(),
    };
    let samples = [
        (
            "PrivacyReleaseSourceIdentityV1",
            norito::json::to_value(&source_identity).unwrap(),
        ),
        (
            "PrivacyReleaseExecutableArtifactV1",
            norito::json::to_value(&executable_artifact).unwrap(),
        ),
        (
            "PrivacyReleaseProtocolBindingV1",
            norito::json::to_value(&protocol_binding).unwrap(),
        ),
        (
            "PrivacyReleaseStageReceiptV1",
            norito::json::to_value(&stage_receipt).unwrap(),
        ),
        (
            "PrivacyReleaseProofArtifactV1",
            norito::json::to_value(&proof_artifact).unwrap(),
        ),
        (
            "PrivacyReleaseSdkPackageV1",
            norito::json::to_value(&sdk_package).unwrap(),
        ),
        (
            "PrivacyReleaseHardwareResultV1",
            norito::json::to_value(&hardware_result).unwrap(),
        ),
        (
            "PrivacyAcceptedMediumDispositionV1",
            norito::json::to_value(&medium_disposition).unwrap(),
        ),
        (
            "PrivacyReleaseAuditV1",
            norito::json::to_value(&audit_record).unwrap(),
        ),
        (
            "PrivacyReleaseSignatureV1",
            norito::json::to_value(&release_signature).unwrap(),
        ),
        (
            "PrivacyExact12ReleaseManifestV1",
            norito::json::to_value(&release_manifest).unwrap(),
        ),
        (
            "PrivacyDeploymentActivationV1",
            norito::json::to_value(&activation).unwrap(),
        ),
        (
            "PrivacyDeploymentValidatorCanaryV1",
            norito::json::to_value(&validator_canary).unwrap(),
        ),
        (
            "PrivacyDeploymentValidatorSignatureV1",
            norito::json::to_value(&validator_signature).unwrap(),
        ),
        (
            "PrivacyExact12DeploymentQualificationV1",
            norito::json::to_value(&deployment_qualification).unwrap(),
        ),
        (
            "PrivacyExact12QualificationRecordV1",
            norito::json::to_value(&qualification_record).unwrap(),
        ),
    ];
    for (name, value) in samples {
        let fields = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_strict_object_schema(schemas, name, &fields, &[]);
    }
}

#[test]
fn privacy_release_qualification_enums_match_native_json_tags() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    let samples = [
        (
            "PrivacyReleaseStageV1",
            "stage",
            PrivacyReleaseStageV1::ALL
                .iter()
                .map(|v| norito::json::to_value(v).unwrap())
                .collect::<Vec<_>>(),
        ),
        (
            "PrivacyReleaseExecutableKindV1",
            "kind",
            [
                PrivacyReleaseExecutableKindV1::Binary,
                PrivacyReleaseExecutableKindV1::ContainerImage,
            ]
            .iter()
            .map(|v| norito::json::to_value(v).unwrap())
            .collect::<Vec<_>>(),
        ),
        (
            "PrivacyReleaseSdkConsumerV1",
            "consumer",
            PrivacyReleaseSdkConsumerV1::ALL
                .iter()
                .map(|v| norito::json::to_value(v).unwrap())
                .collect::<Vec<_>>(),
        ),
        (
            "PrivacyReleaseHardwareBackendV1",
            "backend",
            PrivacyReleaseHardwareBackendV1::ALL
                .iter()
                .map(|v| norito::json::to_value(v).unwrap())
                .collect::<Vec<_>>(),
        ),
        (
            "PrivacyReleaseAuditClassV1",
            "audit_class",
            PrivacyReleaseAuditClassV1::ALL
                .iter()
                .map(|v| norito::json::to_value(v).unwrap())
                .collect::<Vec<_>>(),
        ),
        (
            "PrivacyReleaseSignatureRoleV1",
            "role",
            PrivacyReleaseSignatureRoleV1::ALL
                .iter()
                .map(|v| norito::json::to_value(v).unwrap())
                .collect::<Vec<_>>(),
        ),
    ];
    for (name, tag, values) in samples {
        assert_strict_object_schema(schemas, name, &[tag, "value"], &[]);
        let labels = values
            .iter()
            .map(|value| {
                assert_eq!(value.as_object().unwrap().len(), 2);
                assert!(value["value"].is_null());
                value[tag].clone()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            schemas[name]["properties"][tag]["enum"],
            Value::Array(labels)
        );
        assert_eq!(
            schemas[name]["properties"]["value"]["type"],
            Value::from("null")
        );
    }
}

#[test]
fn privacy_release_qualification_inventory_counts_match_native_contract() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    for (schema, property, count) in [
        (
            "PrivacyExact12ReleaseManifestV1",
            "protocols",
            PrivacyProtocolIdV1::COUNT,
        ),
        (
            "PrivacyExact12ReleaseManifestV1",
            "stage_receipts",
            PRIVACY_EXACT12_RELEASE_STAGE_RECEIPTS_V1,
        ),
        (
            "PrivacyExact12ReleaseManifestV1",
            "proof_artifacts",
            PRIVACY_EXACT12_RELEASE_PROOF_ARTIFACTS_V1,
        ),
        (
            "PrivacyExact12ReleaseManifestV1",
            "sdk_packages",
            PrivacyReleaseSdkConsumerV1::ALL.len(),
        ),
        (
            "PrivacyExact12ReleaseManifestV1",
            "hardware_results",
            PrivacyReleaseHardwareBackendV1::ALL.len(),
        ),
        (
            "PrivacyExact12ReleaseManifestV1",
            "audits",
            PrivacyReleaseAuditClassV1::ALL.len(),
        ),
        (
            "PrivacyExact12ReleaseManifestV1",
            "release_signatures",
            PrivacyReleaseSignatureRoleV1::ALL.len(),
        ),
        (
            "PrivacyExact12DeploymentQualificationV1",
            "activations",
            PrivacyProtocolIdV1::COUNT,
        ),
        (
            "PrivacyExact12DeploymentQualificationV1",
            "validator_canaries",
            PRIVACY_EXACT12_DEPLOYMENT_VALIDATORS_V1,
        ),
        (
            "PrivacyExact12DeploymentQualificationV1",
            "validator_signatures",
            PRIVACY_EXACT12_DEPLOYMENT_SIGNATURES_V1,
        ),
    ] {
        let array = &schemas[schema]["properties"][property];
        assert_eq!(array["minItems"].as_u64(), Some(count as u64));
        assert_eq!(array["maxItems"].as_u64(), Some(count as u64));
    }
    assert_eq!(
        schemas["PrivacyReleaseAuditV1"]["properties"]["accepted_medium_dispositions"]["maxItems"]
            .as_u64(),
        Some(PRIVACY_EXACT12_MAX_MEDIUM_DISPOSITIONS_PER_AUDIT_V1 as u64)
    );
    assert_eq!(
        schemas["PrivacyExact12ReleaseManifestV1"]["properties"]["catalog_id"]["const"]
            .as_str()
            .unwrap()
            .as_bytes(),
        PRIVACY_EXACT12_CATALOG_ID_V1
    );
}

#[test]
fn privacy_release_qualification_is_required_and_explicitly_nullable() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    let manifest = PrivacyExact12CapabilityManifestV1 {
        version: 1,
        committed_height: 0,
        consensus_policy: PrivacyConsensusPolicyV1::default(),
        qualification: None,
        protocols: Vec::new(),
        manifest_digest: PrivacyExact12CapabilityManifestDigestV1::new([1; 32]),
    };
    let native = norito::json::to_value(&manifest).unwrap();
    assert!(native.as_object().unwrap().contains_key("qualification"));
    assert!(native["qualification"].is_null());
    let contract = &schemas["PrivacyExact12CapabilityManifestV1"];
    assert!(
        contract["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("qualification"))
    );
    assert_eq!(
        contract["properties"]["qualification"]["oneOf"],
        norito::json!([
            {"$ref":"#/components/schemas/PrivacyExact12QualificationRecordV1"}, {"type":"null"}
        ])
    );
}
#[test]
fn privacy_release_qualification_keeps_java_source_kotlin_as_one_of_ten_consumers() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    let consumers = &schemas["PrivacyReleaseSdkConsumerV1"];
    assert_eq!(
        consumers["properties"]["consumer"]["enum"],
        norito::json!([
            "kotlin_jvm",
            "kotlin_android",
            "java_source_kotlin",
            "swift_c_bridge",
            "javascript_napi",
            "python_pyo3",
            "csharp",
            "cli",
            "openapi",
            "genesis_tooling",
        ]),
    );
    assert_eq!(PrivacyReleaseSdkConsumerV1::ALL.len(), 10);
    assert_eq!(
        PrivacyReleaseSdkConsumerV1::ALL[2],
        PrivacyReleaseSdkConsumerV1::JavaSourceKotlin,
    );
    assert_eq!(
        schemas["PrivacyExact12ReleaseManifestV1"]["properties"]["sdk_packages"]["minItems"],
        Value::from(10),
    );
    assert_eq!(
        schemas["PrivacyExact12ReleaseManifestV1"]["properties"]["sdk_packages"]["maxItems"],
        Value::from(10),
    );
    let current = norito::json::to_value(&PrivacyReleaseSdkConsumerV1::JavaSourceKotlin).unwrap();
    assert_eq!(
        current,
        norito::json!({"consumer": "java_source_kotlin", "value": null})
    );
    assert!(
        norito::json::from_str::<PrivacyReleaseSdkConsumerV1>(
            r#"{"consumer":"java_android","value":null}"#,
        )
        .is_err()
    );
}
