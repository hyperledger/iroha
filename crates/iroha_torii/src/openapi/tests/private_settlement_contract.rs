#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivateSettlementAuthContract {
    Account,
    Identity(&'static str),
    Public,
}

#[derive(Clone, Copy, Debug)]
struct PrivateSettlementOperationContract {
    path: &'static str,
    method: &'static str,
    request: Option<&'static str>,
    success: &'static str,
    response: &'static str,
    auth: PrivateSettlementAuthContract,
}

const PRIVATE_SETTLEMENT_OPERATION_CONTRACTS: [PrivateSettlementOperationContract; 14] = [
    PrivateSettlementOperationContract {
        path: "/v1/nexus/private-settlements/context/{height}",
        method: "post",
        request: Some("iroha_data_model::nexus::PrivateSettlementContextRequestV1"),
        success: "200",
        response: "#/components/schemas/PrivateSettlementContextsProofV1",
        auth: PrivateSettlementAuthContract::Account,
    },
    PrivateSettlementOperationContract {
        path: "/v1/nexus/private-settlements/legs/availability-shares",
        method: "post",
        request: Some("#/components/schemas/PrivateSettlementAvailabilityShareRequestV1"),
        success: "200",
        response: "#/components/schemas/PrivateSettlementAvailabilityShareResponseV1",
        auth: PrivateSettlementAuthContract::Account,
    },
    PrivateSettlementOperationContract {
        path: "/v1/nexus/private-settlements/phases/prepare-votes",
        method: "post",
        request: Some("#/components/schemas/PrivateSettlementPrepareVoteRequestV1"),
        success: "200",
        response: "#/components/schemas/PrivateSettlementPhaseVoteResponseV1",
        auth: PrivateSettlementAuthContract::Account,
    },
    PrivateSettlementOperationContract {
        path: "/v1/nexus/private-settlements/phases/commit-votes",
        method: "post",
        request: Some("#/components/schemas/PrivateSettlementCommitVoteRequestV1"),
        success: "200",
        response: "#/components/schemas/PrivateSettlementPhaseVoteResponseV1",
        auth: PrivateSettlementAuthContract::Account,
    },
    PrivateSettlementOperationContract {
        path: "/v1/nexus/private-settlements/phases/certificates",
        method: "post",
        request: Some("#/components/schemas/PrivateSettlementPhaseCertificateRequestV1"),
        success: "200",
        response: "#/components/schemas/PrivateSettlementPhaseCertificateResponseV1",
        auth: PrivateSettlementAuthContract::Account,
    },
    PrivateSettlementOperationContract {
        path: "/v1/nexus/private-settlements/legs/{payload_digest}/phase-certificates",
        method: "get",
        request: None,
        success: "200",
        response: "#/components/schemas/PrivateSettlementPhaseCertificatesResponseV1",
        auth: PrivateSettlementAuthContract::Account,
    },
    PrivateSettlementOperationContract {
        path: "/v1/nexus/private-settlements/legs",
        method: "post",
        request: Some("#/components/schemas/PrivateSettlementLegUploadRequestV1"),
        success: "200",
        response: "#/components/schemas/PrivateSettlementLegUploadResponseV1",
        auth: PrivateSettlementAuthContract::Account,
    },
    PrivateSettlementOperationContract {
        path: "/v1/nexus/private-settlements/legs/{payload_digest}/status",
        method: "get",
        request: None,
        success: "200",
        response: "#/components/schemas/PrivateSettlementLegStatusResponseV1",
        auth: PrivateSettlementAuthContract::Account,
    },
    PrivateSettlementOperationContract {
        path: "/v1/nexus/private-settlements/legs/{payload_digest}/committee-proof",
        method: "get",
        request: None,
        success: "200",
        response: "#/components/schemas/PrivateSettlementCommitteeProofResponseV1",
        auth: PrivateSettlementAuthContract::Identity("participant_validator_roster_member"),
    },
    PrivateSettlementOperationContract {
        path: "/v1/nexus/private-settlements/legs/{payload_digest}/audit-capsule",
        method: "post",
        request: Some("#/components/schemas/PrivateSettlementAuditorCapsuleRequestV1"),
        success: "200",
        response: "#/components/schemas/PrivateSettlementAuditorCapsuleResponseV1",
        auth: PrivateSettlementAuthContract::Identity("governed_local_auditor"),
    },
    PrivateSettlementOperationContract {
        path: "/v1/nexus/private-settlements/legs/{payload_digest}/audit-approvals",
        method: "post",
        request: Some("#/components/schemas/PrivateSettlementAuditApprovalRequestV1"),
        success: "200",
        response: "#/components/schemas/PrivateSettlementAuditApprovalResponseV1",
        auth: PrivateSettlementAuthContract::Identity("governed_local_auditor"),
    },
    PrivateSettlementOperationContract {
        path: "/v1/nexus/private-settlements/bundles",
        method: "post",
        request: Some("#/components/schemas/PrivateSettlementBundleSubmitRequestV1"),
        success: "202",
        response: "#/components/schemas/PrivateSettlementBundleSubmitResponseV1",
        auth: PrivateSettlementAuthContract::Account,
    },
    PrivateSettlementOperationContract {
        path: "/v1/nexus/private-settlements/bundles/{bundle_id}",
        method: "get",
        request: None,
        success: "200",
        response: "#/components/schemas/PrivateSettlementBundleStatusResponseV1",
        auth: PrivateSettlementAuthContract::Public,
    },
    PrivateSettlementOperationContract {
        path: "/v1/nexus/private-settlements/bundles/{bundle_id}/receipt",
        method: "get",
        request: None,
        success: "200",
        response: "#/components/schemas/PrivateSettlementBundleReceiptResponseV1",
        auth: PrivateSettlementAuthContract::Public,
    },
];

fn private_settlement_response_is_private_no_store(operation: &Map, status: &str) -> bool {
    operation
        .get("responses")
        .and_then(Value::as_object)
        .and_then(|responses| responses.get(status))
        .and_then(Value::as_object)
        .and_then(|response| response.get("headers"))
        .and_then(Value::as_object)
        .and_then(|headers| headers.get("Cache-Control"))
        .and_then(Value::as_object)
        .and_then(|header| header.get("schema"))
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("const"))
        .and_then(Value::as_str)
        == Some("private, no-store")
}

#[test]
fn private_settlement_openapi_covers_the_exact_catalog_family() {
    use iroha_torii_shared::route_catalog::{
        CatalogProjection, EnabledFeatures, HttpMethod, RouteCatalog, private_settlement,
    };

    let documented = PRIVATE_SETTLEMENT_OPERATION_CONTRACTS
        .iter()
        .map(|contract| (contract.path, contract.method))
        .collect::<BTreeSet<_>>();
    let catalog = RouteCatalog::new(private_settlement::ROUTES)
        .project(
            CatalogProjection::OpenApi,
            EnabledFeatures::new(&["app_api"]),
        )
        .into_iter()
        .map(|descriptor| {
            let method = match descriptor.method() {
                HttpMethod::Get => "get",
                HttpMethod::Post => "post",
                other => panic!("unexpected private-settlement method: {other:?}"),
            };
            (descriptor.path(), method)
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(catalog.len(), 14);
    assert_eq!(documented, catalog);
    assert!(
        !private_settlement::TEST_NETWORK_STATE_COMMITMENT
            .projections()
            .openapi()
    );

    let document = canonical_document();
    let actual = document["paths"]
        .as_object()
        .expect("OpenAPI paths")
        .iter()
        .filter(|(path, _)| path.starts_with("/v1/nexus/private-settlements/"))
        .flat_map(|(path, item)| {
            item.as_object()
                .expect("private-settlement path item")
                .keys()
                .filter(|method| matches!(method.as_str(), "get" | "post"))
                .map(move |method| (path.as_str(), method.as_str()))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, documented);
}

#[test]
fn private_settlement_operations_are_typed_authenticated_and_redacted() {
    let document = canonical_document();
    let account_headers = BTreeSet::from([
        "X-Iroha-Account".to_owned(),
        "X-Iroha-Signature".to_owned(),
        "X-Iroha-Timestamp-Ms".to_owned(),
        "X-Iroha-Nonce".to_owned(),
        "X-Iroha-Witness".to_owned(),
    ]);
    let operator_headers = BTreeSet::from([
        "X-Iroha-Operator-Public-Key".to_owned(),
        "X-Iroha-Operator-Timestamp-Ms".to_owned(),
        "X-Iroha-Operator-Nonce".to_owned(),
        "X-Iroha-Operator-Signature".to_owned(),
    ]);
    for contract in PRIVATE_SETTLEMENT_OPERATION_CONTRACTS {
        let operation = openapi_operation(&document, contract.path, contract.method);
        assert_eq!(operation["tags"][0].as_str(), Some("Nexus"));
        assert_eq!(
            operation["x-iroha-tool-effect"].as_str(),
            Some(
                if contract.method == "get"
                    || contract.path.ends_with("/audit-capsule")
                    || contract.path.ends_with("/context/{height}")
                {
                    "read"
                } else {
                    "write"
                }
            )
        );
        match contract.request {
            Some(request) => {
                if contract.path.ends_with("/context/{height}") {
                    let schema =
                        &operation["requestBody"]["content"]["application/x-norito"]["schema"];
                    assert_eq!(schema["x-iroha-norito-schema"].as_str(), Some(request));
                    assert_eq!(schema["maxLength"].as_u64(), Some(65_536));
                    assert_eq!(
                        operation["x-iroha-max-response-bytes"].as_u64(),
                        Some(33_554_432)
                    );
                } else {
                    assert_eq!(
                        operation_request_schema_ref(operation, contract.path),
                        request
                    );
                }
                assert_eq!(operation["requestBody"]["required"].as_bool(), Some(true));
            }
            None => assert!(operation.get("requestBody").is_none()),
        }
        assert_eq!(
            operation_response_schema_ref(operation, contract.success, contract.path),
            contract.response
        );
        let redaction = operation
            .get("x-iroha-redaction-v1")
            .and_then(Value::as_object)
            .expect("private-settlement redaction contract");
        assert_eq!(
            redaction.get("plaintext_transaction_contents"),
            Some(&Value::String("forbidden".to_owned())),
            "{} {}",
            contract.method,
            contract.path
        );

        let headers = operation_header_requirements(operation);
        let names = headers
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<BTreeSet<_>>();
        match contract.auth {
            PrivateSettlementAuthContract::Account => {
                assert_eq!(names, account_headers, "{}", contract.path);
                assert!(headers.iter().all(|(_, required)| !required));
                let canonical = operation["x-iroha-canonical-auth-v1"]
                    .as_object()
                    .expect("canonical account auth extension");
                assert_eq!(canonical["body_hash_bound"].as_bool(), Some(true));
                assert_eq!(canonical["exact_request_target"].as_bool(), Some(true));
                let modes = canonical["modes"]
                    .as_array()
                    .expect("canonical account auth modes");
                assert_eq!(modes.len(), 2);
                let single = modes
                    .iter()
                    .find(|mode| mode["kind"].as_str() == Some("single_signature"))
                    .expect("single-signature auth mode");
                assert_eq!(
                    single["required_headers"]
                        .as_array()
                        .expect("single-signature required headers")
                        .iter()
                        .map(|header| header.as_str().expect("header name"))
                        .collect::<BTreeSet<_>>(),
                    BTreeSet::from([
                        "X-Iroha-Account",
                        "X-Iroha-Signature",
                        "X-Iroha-Timestamp-Ms",
                        "X-Iroha-Nonce",
                    ])
                );
                assert_eq!(
                    single["forbidden_headers"][0].as_str(),
                    Some("X-Iroha-Witness")
                );
                let witness = modes
                    .iter()
                    .find(|mode| mode["kind"].as_str() == Some("multisig_witness"))
                    .expect("multisig-witness auth mode");
                assert_eq!(
                    witness["required_headers"][0].as_str(),
                    Some("X-Iroha-Witness")
                );
                assert_eq!(
                    witness["optional_headers"][0].as_str(),
                    Some("X-Iroha-Account")
                );
                assert_eq!(
                    witness["forbidden_headers"]
                        .as_array()
                        .expect("witness-forbidden headers")
                        .iter()
                        .map(|header| header.as_str().expect("header name"))
                        .collect::<BTreeSet<_>>(),
                    BTreeSet::from(["X-Iroha-Signature", "X-Iroha-Timestamp-Ms", "X-Iroha-Nonce",])
                );
                let security = operation["security"]
                    .as_array()
                    .expect("canonical account security alternatives");
                assert_eq!(security.len(), 2);
                assert_eq!(
                    security[0]
                        .as_object()
                        .expect("single-signature security requirement")
                        .keys()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>(),
                    BTreeSet::from([
                        "IrohaCanonicalAccount",
                        "IrohaCanonicalNonce",
                        "IrohaCanonicalSignature",
                        "IrohaCanonicalTimestampMs",
                    ])
                );
                assert_eq!(
                    security[1]
                        .as_object()
                        .expect("witness security requirement")
                        .keys()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>(),
                    BTreeSet::from(["IrohaCanonicalWitness"])
                );
                assert!(private_settlement_response_is_private_no_store(
                    operation,
                    contract.success
                ));
            }
            PrivateSettlementAuthContract::Identity(principal) => {
                assert_eq!(names, operator_headers, "{}", contract.path);
                assert!(headers.iter().all(|(_, required)| *required));
                let identity = operation["x-iroha-identity-bound-auth-v1"]
                    .as_object()
                    .expect("identity-bound auth extension");
                assert_eq!(identity["principal"].as_str(), Some(principal));
                assert_eq!(identity["body_hash_bound"].as_bool(), Some(true));
                assert_eq!(identity["exact_request_target"].as_bool(), Some(true));
                assert_eq!(
                    identity["replay_domain"].as_str(),
                    Some("private_settlement_identity_bound_v1")
                );
                assert!(operation.get("security").is_none());
                assert!(private_settlement_response_is_private_no_store(
                    operation,
                    contract.success
                ));
            }
            PrivateSettlementAuthContract::Public => {
                assert!(headers.is_empty(), "{}", contract.path);
                assert_eq!(
                    operation["security"],
                    norito::json!([{}, {"IrohaApiToken": []}])
                );
                assert!(operation.get("x-iroha-canonical-auth-v1").is_none());
                assert!(operation.get("x-iroha-identity-bound-auth-v1").is_none());
                assert!(!private_settlement_response_is_private_no_store(
                    operation,
                    contract.success
                ));
            }
        }

        if let Some(parameter_name) = contract
            .path
            .contains("{payload_digest}")
            .then_some("payload_digest")
            .or_else(|| contract.path.contains("{bundle_id}").then_some("bundle_id"))
        {
            let parameter = operation["parameters"]
                .as_array()
                .expect("operation parameters")
                .iter()
                .find(|parameter| {
                    parameter["in"].as_str() == Some("path")
                        && parameter["name"].as_str() == Some(parameter_name)
                })
                .expect("private-settlement path parameter");
            assert_eq!(parameter["required"].as_bool(), Some(true));
            assert_eq!(
                parameter["schema"]["$ref"].as_str(),
                Some("#/components/schemas/Hash")
            );
        }
    }
}

#[test]
fn private_settlement_top_level_v1_dtos_are_strict() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    for (name, fields) in [
        (
            "PrivateSettlementLegUploadRequestV1",
            &["manifest", "audit_policy", "committee_authority", "payload"][..],
        ),
        (
            "PrivateSettlementAvailabilityShareRequestV1",
            &["material"][..],
        ),
        (
            "PrivateSettlementAvailabilityShareResponseV1",
            &[
                "bundle_id",
                "payload_digest",
                "leg_ordinal",
                "disposition",
                "share",
            ][..],
        ),
        (
            "PrivateSettlementPrepareVoteRequestV1",
            &["manifest", "payload_digest"][..],
        ),
        (
            "PrivateSettlementCommitVoteRequestV1",
            &["payload_digest", "barrier"][..],
        ),
        (
            "PrivateSettlementPhaseVoteResponseV1",
            &["bundle_id", "payload_digest", "leg_ordinal", "vote"][..],
        ),
        (
            "PrivateSettlementPhaseCertificateRequestV1",
            &["manifest", "payload_digest", "certificate"][..],
        ),
        (
            "PrivateSettlementPhaseCertificateResponseV1",
            &[
                "bundle_id",
                "payload_digest",
                "leg_ordinal",
                "phase",
                "lifecycle",
            ][..],
        ),
        (
            "PrivateSettlementPhaseCertificatesResponseV1",
            &[
                "bundle_id",
                "payload_digest",
                "leg_ordinal",
                "lifecycle",
                "prepare_certificate",
                "commit_certificate",
            ][..],
        ),
        (
            "PrivateSettlementLegUploadResponseV1",
            &[
                "bundle_id",
                "payload_digest",
                "leg_ordinal",
                "disposition",
                "lifecycle",
            ][..],
        ),
        (
            "PrivateSettlementLegStatusResponseV1",
            &[
                "bundle_id",
                "payload_digest",
                "leg_ordinal",
                "route",
                "stored_at_height",
                "lifecycle_height",
                "expiry_height",
                "lifecycle",
            ][..],
        ),
        (
            "PrivateSettlementCommitteeProofResponseV1",
            &[
                "manifest",
                "audit_policy",
                "committee_authority",
                "statement",
                "proof",
                "delta",
                "audit_approvals",
                "audit_capsule_digest",
                "availability",
                "lifecycle",
            ][..],
        ),
        (
            "PrivateSettlementAuditorCapsuleResponseV1",
            &[
                "authoritative_height",
                "manifest",
                "audit_policy",
                "access_audit_policy",
                "committee_authority",
                "statement",
                "delta",
                "audit_capsule",
                "availability",
                "lifecycle",
                "responder_attestation",
            ][..],
        ),
        (
            "PrivateSettlementAuditorCapsuleRequestV1",
            &["audit_policy"][..],
        ),
        (
            "PrivateSettlementAuditApprovalRequestV1",
            &["audit_policy", "approval"][..],
        ),
        (
            "PrivateSettlementAuditApprovalResponseV1",
            &[
                "authoritative_height",
                "bundle_id",
                "payload_digest",
                "leg_ordinal",
                "committee_authority",
                "collected",
                "required",
                "newly_recorded",
                "lifecycle",
                "responder_attestation",
            ][..],
        ),
        (
            "PrivateSettlementBundleSubmitRequestV1",
            &["transaction"][..],
        ),
        (
            "PrivateSettlementBundleSubmitResponseV1",
            &["bundle_id", "accepted_at_height", "carrier_id"][..],
        ),
        (
            "PrivateSettlementBundleStatusResponseV1",
            &["manifest", "lifecycle", "finalized_height"][..],
        ),
    ] {
        assert_strict_object_schema(schemas, name, fields, &[]);
    }

    for field in ["manifest", "finalized_height"] {
        let choices =
            schemas["PrivateSettlementBundleStatusResponseV1"]["properties"][field]["oneOf"]
                .as_array()
                .expect("explicit nullable bundle-status field");
        assert!(
            choices
                .iter()
                .any(|choice| choice["type"].as_str() == Some("null"))
        );
    }
    for field in ["prepare_certificate", "commit_certificate"] {
        let choices = schemas["PrivateSettlementPhaseCertificatesResponseV1"]["properties"][field]
            ["oneOf"]
            .as_array()
            .expect("explicit nullable phase-certificate field");
        assert!(
            choices
                .iter()
                .any(|choice| choice["type"].as_str() == Some("null"))
        );
    }
}

#[test]
fn private_settlement_tagged_v1_dtos_have_exact_closed_variants() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    for (schema_name, tag, variants) in [
        (
            "PrivateSettlementLifecycleDtoV1",
            "status",
            &[
                "collecting",
                "audited",
                "prepared",
                "commit_certified",
                "finalized",
                "aborted",
                "expired",
            ][..],
        ),
        (
            "PrivateSettlementLegUploadDispositionV1",
            "result",
            &["stored", "already_stored"][..],
        ),
    ] {
        let choices = schemas[schema_name]["oneOf"]
            .as_array()
            .expect("tagged DTO choices");
        let actual = choices
            .iter()
            .map(|choice| {
                assert_eq!(choice["additionalProperties"].as_bool(), Some(false));
                assert_eq!(
                    choice["required"].as_array().map(Vec::len),
                    Some(2),
                    "{schema_name} requires tag and explicit value"
                );
                assert_eq!(choice["properties"]["value"]["type"].as_str(), Some("null"));
                choice["properties"][tag]["const"]
                    .as_str()
                    .expect("tagged DTO variant")
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, variants.iter().copied().collect::<BTreeSet<_>>());
    }

    let receipt = schemas["PrivateSettlementBundleReceiptResponseV1"]["oneOf"]
        .as_array()
        .expect("receipt variants");
    assert_eq!(receipt.len(), 3);
    let pending = receipt
        .iter()
        .find(|choice| choice["properties"]["status"]["const"].as_str() == Some("pending"))
        .expect("pending receipt variant");
    let pending_value = &pending["properties"]["value"];
    assert_eq!(pending_value["additionalProperties"].as_bool(), Some(false));
    assert_eq!(
        pending_value["properties"]
            .as_object()
            .expect("pending properties")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["bundle_id"])
    );
    assert_eq!(
        pending_value["required"]
            .as_array()
            .expect("pending required")
            .iter()
            .map(|field| field.as_str().expect("required name"))
            .collect::<Vec<_>>(),
        vec!["bundle_id"]
    );
    let typed_pending = iroha_torii_shared::private_settlement_api::PrivateSettlementBundleReceiptResponseV1::Pending {
        bundle_id: iroha_crypto::Hash::new(b"public terminal absence"),
    };
    let typed_pending = norito::json::to_value(&typed_pending).expect("typed pending JSON");
    assert_eq!(typed_pending["status"].as_str(), Some("pending"));
    assert_eq!(
        typed_pending["value"]
            .as_object()
            .expect("typed pending value")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["bundle_id"])
    );
    let statuses = receipt
        .iter()
        .map(|choice| {
            assert_eq!(choice["additionalProperties"].as_bool(), Some(false));
            choice["properties"]["status"]["const"]
                .as_str()
                .expect("receipt status")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        statuses,
        BTreeSet::from(["pending", "finalized", "aborted"])
    );
}
