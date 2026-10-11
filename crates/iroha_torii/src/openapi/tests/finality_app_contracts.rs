#[rustfmt::skip]
mod compact_finality_app_contracts {
use super::*;
fn schema_fields<'a>(schema: &'a Map, key: &str, context: &str) -> &'a Vec<Value> {
    contract_array(schema.get(key), &format!("{context}.{key}"))
}
fn assert_array_bounds(schema: &Map, minimum: u64, maximum: u64, unique: Option<bool>) {
    scalar_contracts! { schema.get("minItems") => Unsigned(minimum); schema.get("maxItems") => Unsigned(maximum); }
    if let Some(unique) = unique {
        scalar_contracts! { schema.get("uniqueItems") => Flag(unique); }
    }
}
fn assert_item_ref(schema: &Map, expected: &str) {
    scalar_contracts! { schema.get("items").and_then(Value::as_object).and_then(|items| items.get("$ref")) => Text(expected); }
}
fn object_field_set(object: &Map) -> BTreeSet<&str> {
    object.keys().map(String::as_str).collect()
}
fn schema_string_field_set<'a>(schema: &'a Map, key: &str, context: &str) -> BTreeSet<&'a str> {
    schema_fields(schema, key, context).iter().map(|value| value.as_str().unwrap_or_else(|| panic!("{context}.{key} contains a non-string value"))).collect()
}
fn assert_exact_closed_required_schema_fields(schemas: &Map, name: &str, expected: &[&str]) {
    let schema = contract_schema(schemas, name);
    scalar_contracts! { schema.get("additionalProperties") => Flag(false); }
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(object_field_set(schema.get("properties").and_then(Value::as_object).unwrap_or_else(|| panic!("{name}.properties"))), expected, "{name} property surface");
    assert_eq!(schema_string_field_set(schema, "required", name), expected, "{name} required-field surface");
}
fn asset_field_set(inventory: &str) -> BTreeSet<&'static str> {
    contract_strings(inventory).into_iter().collect()
}
#[test]
fn inrou_guest_image_schema_requires_one_concrete_published_artifact() {
    let schemas = openapi_schemas();
    assert_exact_closed_required_schema_fields(&schemas, "SoraInrouGuestImageV1", &contract_words("initrd_image_path kernel_image_path published_artifact rootfs_image_path"));
    let published_artifact = contract_property(&schemas, "SoraInrouGuestImageV1", "published_artifact");
    scalar_contracts! { published_artifact.get("$ref") => Text("#/components/schemas/SoraPublishedInrouGuestImageArtifactV1"); }
    assert!(published_artifact.get("anyOf").is_none() && published_artifact.get("oneOf").is_none() && published_artifact.get("nullable").is_none(), "admitted Inrou V1 artifacts must not expose a missing/null compatibility branch");
    assert_exact_closed_required_schema_fields(&schemas, "SoraPublishedInrouGuestImageArtifactV1", &contract_words("content_cid manifest_digest_hex"));
    assert_exact_closed_required_schema_fields(&schemas, "SoraInrouManifestV1", &contract_words("guest_images schema_version"));
    member_contracts! { &schemas; Absent => contract_words("SoraArtifactDistributionPolicyV1 SoraArtifactDistributionTargetV1 SoraInrouGuestOsV1"); }
    for (schema_name, retired_fields) in contract_rows! { "SoraCapabilityPolicyV1", &contract_words("allow_wallet_signing")[..]; "SoraInrouHostCapabilityRecordV1", &contract_words("geography_tags observed_latency_ms")[..]; "SoraInrouReplicaPlacementV1", &contract_words("selected_geography_tag selection_latency_ms")[..]; } {
        let properties = contract_object(contract_schema(&schemas, schema_name).get("properties"), &format!("{schema_name} properties"));
        member_contracts! { properties; Absent => retired_fields; }
    }
}
#[test]
fn inrou_first_release_openapi_matches_block_clock_and_exact_admission() {
    let schemas = openapi_schemas();
    assert_exact_closed_required_schema_fields(&schemas, "SoraHttpServiceEconomicsV1", &contract_words(concat!("schema_version quota_class deployment_deposit prepaid_runtime_balance ", "lease_duration_blocks runtime_price_per_block storage_price_per_gib_block ", "egress_price_per_mib")));
    let economics = contract_schema(&schemas, "SoraHttpServiceEconomicsV1");
    let economics_json = norito::json::to_string(&Value::Object(economics.clone())).expect("serialize economics");
    for retired in contract_words("lease_duration_sequences runtime_price_per_sequence storage_price_per_gib_sequence") {
        assert!(!economics_json.contains(retired), "retired sequence-clock economics field `{retired}`");
    }
    let guest_images = contract_property(&schemas, "SoraInrouManifestV1", "guest_images");
    scalar_contracts! { guest_images.get("minProperties") => Unsigned(1); guest_images.get("maxProperties") => Unsigned(2); guest_images.get("additionalProperties").and_then(Value::as_object).and_then(|items| items.get("$ref")) => Text("#/components/schemas/SoraInrouGuestImageV1"); }
    let admitted_guest_isas = contract_array(guest_images.get("propertyNames").and_then(Value::as_object).and_then(|names| names.get("enum")), "Inrou guest-image property-name enum").iter().map(|value| value.as_str().expect("guest ISA name")).collect::<BTreeSet<_>>();
    set_contracts! { admitted_guest_isas => contract_word_set("aarch64 x86_64"); }
    scalar_contracts! { contract_property(&schemas, "SoraInrouReplicaPlacementV1", "lease_started_height").get("minimum") => Unsigned(1); }
    for schema_name in contract_words("SoraInrouPlacementTargetV1 SoraInrouReplicaPlacementV1") {
        for field in contract_words("validator_account_id peer_id") {
            scalar_contracts! { contract_property(&schemas, schema_name, field) .get("minLength") => Unsigned(1); }
        }
    }
    let exact_resource_bounds = contract_rows! {
        "cpu_millis", u64::from(iroha_data_model::soracloud::SORA_INROU_MIN_CPU_MILLIS_V1), Some(u64::from(iroha_data_model::soracloud::SORA_INROU_CPU_MILLIS_ALIGNMENT_V1));
        "memory_bytes", iroha_data_model::soracloud::SORA_INROU_MIN_MEMORY_BYTES_V1, Some(iroha_data_model::soracloud::SORA_INROU_MEMORY_ALIGNMENT_BYTES_V1);
        "ephemeral_storage_bytes", iroha_data_model::soracloud::SORA_INROU_EPHEMERAL_STORAGE_ALIGNMENT_BYTES_V1, Some(iroha_data_model::soracloud::SORA_INROU_EPHEMERAL_STORAGE_ALIGNMENT_BYTES_V1);
        "max_open_files_per_process", u64::from(iroha_data_model::soracloud::SORA_INROU_MIN_OPEN_FILES_PER_PROCESS_V1), None;
    };
    for (field, minimum, multiple_of) in exact_resource_bounds {
        let property = contract_property(&schemas, "SoraResourceLimitsV1", field);
        scalar_contracts! { property.get("minimum") => Unsigned(minimum); }
        assert_eq!(property.get("multipleOf").and_then(Value::as_u64), multiple_of, "SoraResourceLimitsV1.{field} enforcement unit");
    }
    assert_exact_closed_required_schema_fields(&schemas, "SoraInrouHostCapabilityRecordV1", &contract_words(concat!("schema_version validator_account_id peer_id supported_guest_isas ", "trusted_guest_artifact max_hosted_replica_capacity max_cpu_millis ", "max_memory_bytes max_storage_bytes advertised_at_ms heartbeat_expires_at_ms")));
    assert_exact_closed_required_schema_fields(&schemas, "SoraInrouPlacementTargetV1", &contract_words("validator_account_id peer_id"));
    assert_exact_closed_required_schema_fields(&schemas, "SoraInrouReplicaPlacementV1", &contract_words(concat!("replica_slot economic_clock lease_started_height placement_incarnation ", "host_availability validator_account_id peer_id selected_guest_isa")));
    assert_exact_closed_required_schema_fields(&schemas, "SoracloudRuntimeInrouPlan", &contract_words(concat!("selected_guest_isa kernel_image_path rootfs_image_path initrd_image_path ", "root_volume_name")));
    assert_exact_closed_required_schema_fields(&schemas, "SoracloudRuntimeLeaseVolumePlan", &contract_words(concat!("volume_name kind storage_class mount_path max_total_bytes lease_started_height ", "lease_expires_height authoritative_generation local_materialization_dir")));
    assert_exact_closed_required_schema_fields(&schemas, "SoracloudRuntimeReplicaPlan", &contract_words(concat!("replica_slot lease_started_height placement_incarnation host_availability ", "validator_account_id peer_id materialization_dir health_status listen_base_url ", "pid last_error")));
    assert_exact_closed_required_schema_fields(
        &schemas,
        "SoracloudPublicServiceDiscoveryV1",
        &contract_words(concat!("schema_version service_name service_version execution_plane runtime route_host ", "path_prefix base_url healthcheck_path healthcheck_url service_manifest_hash ", "container_manifest_hash deployment_bundle_hash document_hash content_cid ", "public_discovery_url public_discovery_cid_host_url manifest_digest_hex")),
    );
    let runtime_service = contract_object(contract_schema(&schemas, "SoracloudRuntimeServicePlan").get("properties"), "SoracloudRuntimeServicePlan properties");
    member_contracts! { runtime_service; Present => ["lease_expires_height"]; Absent => contract_words("lease_expires_sequence supports_private_secret_payload_reads"); }
    let control_plane_service = contract_schema(&schemas, "ControlPlaneServiceSnapshot");
    let control_plane_properties = contract_object(control_plane_service.get("properties"), "ControlPlaneServiceSnapshot properties");
    let control_plane_required = schema_string_field_set(control_plane_service, "required", "ControlPlaneServiceSnapshot");
    member_contracts! { control_plane_properties; Present => ["service_lease"]; }
    assert!(control_plane_required.contains("service_lease"));
    for retired in contract_words("quota_class service_lease_status lease_expires_height lease_expires_sequence prepaid_runtime_balance remaining_runtime_balance") {
        member_contracts! { control_plane_properties; Absent => [retired]; }
        assert!(!control_plane_required.contains(retired));
    }
}
#[test]
fn native_finality_schemas_are_exact_closed_and_bounded() {
    let schemas = openapi_schemas();
    assert_exact_closed_required_schema_fields(&schemas, "SumeragiFinalityProof", &contract_strings("bridge.proof.required"));
    assert_exact_closed_required_schema_fields(&schemas, "SumeragiFinalityBundle", &contract_strings("bridge.bundle.required"));
    assert_exact_closed_required_schema_fields(&schemas, "SumeragiFinalityAttestation", &contract_strings("bridge.attestation.required"));
    assert_exact_closed_required_schema_fields(&schemas, "FinalityValidator", &contract_words("public_key proof_of_possession"));
    assert_exact_closed_required_schema_fields(&schemas, "BlockHeader", &contract_strings("block.header.required"));
    for field in contract_strings("block.header.nullable") { let _ = nullable_property_ref(&schemas, "BlockHeader", field); }
    let committee = contract_property(&schemas, "SumeragiFinalityProof", "committee");
    assert_array_bounds(committee, 4, iroha_data_model::block::consensus::MAX_VALIDATORS_PER_HEIGHT as u64, Some(true));
    assert_item_ref(committee, "#/components/schemas/FinalityValidator");
    let wire = contract_property(&schemas, "SumeragiFinalityProof", "block_wire");
    assert_array_bounds(wire, 1, iroha_data_model::sumeragi_finality::MAX_FINALITY_BLOCK_BYTES as u64, None);
    let pop = contract_property(&schemas, "FinalityValidator", "proof_of_possession");
    assert_array_bounds(pop, 96, 96, None);
    for schema in [wire, pop] {
        let byte = contract_object(schema.get("items"), "native byte");
        scalar_contracts! { byte.get("type") => Text("integer"); byte.get("minimum") => Unsigned(0); byte.get("maximum") => Unsigned(255); }
    }
    scalar_contracts! { contract_property(&schemas, "FinalityValidator", "public_key").get("pattern") => Text("^ea0130[0-9A-F]{96}$"); }
    property_refs!(&schemas;
        "SumeragiFinalityProof", "block_header", "#/components/schemas/BlockHeader";
        "SumeragiFinalityBundle", "network_id", "#/components/schemas/Hash";
        "SumeragiFinalityBundle", "finality_proof", "#/components/schemas/SumeragiFinalityProof";
        "SumeragiFinalityAttestation", "body", "#/components/schemas/SumeragiFinalityAttestationBody";
    );
    let signature = contract_property(&schemas, "SumeragiFinalityAttestation", "signature");
    scalar_contracts! { signature.get("minLength") => Unsigned(192); signature.get("maxLength") => Unsigned(192); }
    for name in contract_words("BridgeFinalityProof BridgeCommitment SumeragiV2FinalityArtifact SumeragiV2HeightContext SumeragiV2SnapshotBootstrapAnchor SumeragiV2FinalizedNextEpochSnapshot SumeragiV2ValidatorPower SumeragiV2CommitQuorumCertificate SumeragiV2QuorumCertificate") {
        assert!(!schemas.contains_key(name), "retired bridge component {name}");
    }
    for name in ["GovernanceParliamentTimedOvnCastingProofResponseV1", "ValidationFeeCurrentPolicyProofV1"] {
        assert_item_ref(contract_property(&schemas, name, "finality_chain"), "#/components/schemas/SumeragiFinalityProof");
    }
}
#[cfg(feature = "app_api")]
#[test]
fn native_finality_schema_matches_executed_norito_json_and_rejects_retired_fields() {
    use iroha_core::{state::World, sumeragi::{finality::{build_checkpoint, build_proof}, test_chain::{CertifiedTestChain, TestChainConfig}}};
    use iroha_data_model::{block::{CommitCertificate, decode_framed_signed_block}, parameter::{Parameter, system::{ConsensusMode, SumeragiConsensusMode, SumeragiNposParameters}}, sumeragi_finality::{SumeragiFinalityProof, SumeragiFinalityVerifier}};
    let mut config = TestChainConfig::new(World::new(), 1_000);
    config.consensus_mode = SumeragiConsensusMode::Npos;
    config.genesis_parameters.push(Parameter::Custom(SumeragiNposParameters::default().into_custom_parameter()));
    let mut chain = CertifiedTestChain::start(config).expect("actual signed NPoS genesis");
    chain.commit(Vec::new());
    let view = chain.state().view();
    let checkpoint = build_checkpoint(&view, 1).expect("independently selected original checkpoint");
    let proof = build_proof(&view, 2).expect("actual executed native proof");
    let mut verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(&checkpoint, &checkpoint.network_id(), checkpoint.chain_id()).unwrap();
    let verified = verifier.verify(&proof).expect("full contiguous native BLS proof");
    assert_eq!(verified.commitment().schedule.current.mode, ConsensusMode::Npos);
    let value = norito::json::to_value(&proof).expect("serialize native proof");
    let proof_object = value.as_object().expect("proof object");
    set_contracts! { object_field_set(proof_object) => asset_field_set("bridge.proof.required"); }
    let header = contract_object(proof_object.get("block_header"), "block header");
    set_contracts! { object_field_set(header) => asset_field_set("fixture.header.required"); }
    member_contracts! { header; Absent => ["result_merkle_root", "sccp_commitment_root"]; }
    for field in ["npos_effects_hash", "execution_context_hash"] {
        assert!(header.get(field).is_some_and(|hash| hash.is_null() || hash.is_string()), "required nullable {field}");
    }
    let document = generate_spec(); let schemas = component_schemas(&document);
    assert!(schemas.keys().all(|name| !name.starts_with("SumeragiV2")), "retired consensus components must be absent");
    for name in ["GovernanceParliamentTimedOvnCastingProofResponseV1", "ValidationFeeCurrentPolicyProofV1"] { text_contracts! { property_ref(schemas, name, "evaluated_context_id") => "#/components/schemas/Hash"; } }
    assert_array_bounds(contract_schema(schemas, "Fixed32ByteArray"), 32, 32, None);
    let committee = contract_array(proof_object.get("committee"), "native ordered committee");
    count_contracts! { committee.len() => 4; }
    for (entry, member) in committee.iter().zip(&proof.committee) {
        let entry = entry.as_object().unwrap();
        set_contracts! { object_field_set(entry) => contract_word_set("public_key proof_of_possession"); }
        let key = contract_text(entry.get("public_key"), "BLS key");
        assert_eq!(key, member.public_key.to_string()); assert_eq!(key.len(), 102); assert!(key.starts_with("ea0130"));
        assert!(key[6..].bytes().all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)));
        let pop = contract_array(entry.get("proof_of_possession"), "BLS PoP"); assert_eq!(pop.len(), 96);
        assert!(pop.iter().all(|byte| byte.as_u64().is_some_and(|byte| byte <= 255)));
        iroha_crypto::BlsNormalPopVerifiedKey::new(&member.public_key, &member.proof_of_possession).unwrap();
    }
    let decoded: SumeragiFinalityProof = norito::json::from_value(value.clone()).expect("current JSON roundtrip");
    assert_eq!(decoded, proof);
    let certificate = verified.block().commit_certificate().unwrap();
    let qc: iroha_sumeragi::message::Qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
    assert_eq!(qc.kind, iroha_sumeragi::message::VoteKind::Commit); assert_eq!(qc.signers.count_ones(), 3);
    assert_eq!(qc.agg_sig.0.len(), 96); assert_eq!(qc.result, verified.result()); assert_eq!(qc.block_hash, verified.core_hash());
    let wire = verified.canonical_executed_wire().unwrap();
    assert_eq!(verified.execution().executed_block_wire_len, wire.len() as u64);
    assert_eq!(verified.execution().executed_block_wire_hash, iroha_crypto::Hash::new(&wire));
    let mut missing_result = proof.clone(); let mut block = decode_framed_signed_block(&missing_result.block_wire).unwrap();
    block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(certificate.consensus_header().to_vec(), certificate.commit_qc().to_vec(), Vec::new(), certificate.availability().to_vec())));
    missing_result.block_wire = block.encode_wire().unwrap();
    assert!(verifier.verify_retained_decision(&missing_result).is_err(), "missing canonical execution preimage");
    let mut missing_availability = proof.clone(); let mut block = decode_framed_signed_block(&missing_availability.block_wire).unwrap();
    block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(certificate.consensus_header().to_vec(), certificate.commit_qc().to_vec(), certificate.result_preimage().to_vec(), Vec::new())));
    missing_availability.block_wire = block.encode_wire().unwrap();
    assert!(verifier.verify_retained_decision(&missing_availability).is_err(), "missing signed payload availability");
    let mut forged_qc = proof.clone(); let mut block = decode_framed_signed_block(&forged_qc.block_wire).unwrap();
    let mut qc = qc; qc.agg_sig.0[0] ^= 0x80;
    block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(certificate.consensus_header().to_vec(), norito::encode_canonical(&qc).unwrap(), certificate.result_preimage().to_vec(), certificate.availability().to_vec())));
    forged_qc.block_wire = block.encode_wire().unwrap(); assert!(verifier.verify_retained_decision(&forged_qc).is_err(), "forged exact native QC");
    let mut retired_header = header.clone(); retired_header.insert("result_merkle_root".to_owned(), Value::Null);
    assert!(norito::json::from_value::<iroha_data_model::block::BlockHeader>(Value::Object(retired_header)).is_err());
    for retired in contract_strings("fixture.retired").into_iter().chain(["version", "finality_artifact"]) {
        let mut hostile = value.clone(); hostile.as_object_mut().unwrap().insert(retired.to_owned(), Value::Null);
        assert!(norito::json::from_value::<SumeragiFinalityProof>(hostile).is_err(), "retired proof field {retired}");
    }
    for required in ["block_header", "block_wire", "committee"] {
        let mut missing = value.clone(); assert!(missing.as_object_mut().unwrap().remove(required).is_some());
        assert!(norito::json::from_value::<SumeragiFinalityProof>(missing).is_err(), "missing native proof field {required}");
    }
}
#[test]
fn ledger_state_endpoints_expose_one_closed_authenticated_native_schema() {
    let document = generate_spec();
    let schemas = component_schemas(&document);
    assert_schema_shapes(schemas, &[SchemaShape { name: "StateFinalityResponse", required: "ledger.state_finality.required", optional: None }]);
    property_refs!(schemas;
        "StateFinalityResponse", "block_hash", "#/components/schemas/Hash";
        "StateFinalityResponse", "witnessed_post_state_root", "#/components/schemas/Hash";
        "StateFinalityResponse", "block_header", "#/components/schemas/BlockHeader";
        "StateFinalityResponse", "finality_proof", "#/components/schemas/SumeragiFinalityProof";
    );
    let schema = contract_schema(schemas, "StateFinalityResponse");
    let properties = contract_object(schema.get("properties"), "state finality properties");
    member_contracts! { properties; Absent => contract_strings("ledger.state_finality.retired"); }
    member_contracts! { schemas; Absent => contract_words("StateRootResponse StateProofResponse"); }
    scalar_contracts! { contract_property(schemas, "StateFinalityResponse", "height").get("minimum") => Unsigned(2); }
    for path in contract_words("/v1/ledger/state/{height} /v1/ledger/state-proof/{height}") {
        let operation = openapi_operation(&document, path, "get");
        let description = contract_text(operation.get("description"), "ledger state endpoint description");
        assert!(description.contains("native finality"));
        assert!(description.contains("fails closed"));
        text_contracts! { operation_response_schema_ref(operation, "200", path) => "#/components/schemas/StateFinalityResponse"; }
        let content = response_content(operation, "200");
        set_contracts! { content.keys().map(String::as_str).collect::<BTreeSet<_>>() => contract_word_set("application/json application/x-norito"); }
        let norito = contract_object(content.get("application/x-norito").and_then(|media| media.get("schema")), "Norito response schema");
        scalar_contracts! { norito.get("type") => Text("string"); norito.get("format") => Text("binary"); }
    }
    let paths = contract_object(document.get("paths"), "OpenAPI paths");
    member_contracts! { paths; Absent => contract_strings("ledger.state_finality.retired_paths"); }
    member_contracts! { schemas; Absent => contract_strings("ledger.state_finality.retired_schemas"); }
}
#[test]
fn bridge_finality_operations_describe_current_durable_evidence() {
    let document = generate_spec();
    for contract in response_rows! {
        "/v1/bridge/finality/{height}", "get", "200", "#/components/schemas/SumeragiFinalityProof";
        "/v1/bridge/finality/attestation/{height}", "get", "200", "#/components/schemas/SumeragiFinalityAttestation";
        "/v1/bridge/finality/attestation/latest", "get", "200", "#/components/schemas/SumeragiFinalityAttestation";
        "/v1/bridge/finality/bundle/{height}", "get", "200", "#/components/schemas/SumeragiFinalityBundle";
    } {
        let operation = openapi_operation(&document, contract.path, contract.method);
        let description = contract_text(operation.get("description"), "bridge description");
        assert!(description.contains("current") && description.contains("durable"));
        assert!(!description.contains("Sumeragi-v2") && !description.contains("height-context id"));
        text_contracts! { operation_response_schema_ref(operation, "200", contract.path) => contract.schema_ref; }
        let norito = contract_object(response_content(operation, "200").get("application/x-norito").and_then(|media| media.get("schema")), "Norito response schema");
        scalar_contracts! { norito.get("type") => Text("string"); norito.get("format") => Text("binary"); }
    }
    for path in ["/v1/bridge/finality/attestation/{height}", "/v1/bridge/finality/attestation/latest"] {
        let operation = openapi_operation(&document, path, "get");
        let challenge = operation_parameter(operation, "X-Iroha-Finality-Challenge");
        scalar_contracts! { challenge.get("in") => Text("header"); challenge.get("required") => Flag(true); }
        for status in contract_words("200 400 404 406 409 503") {
            let headers = contract_object(operation_responses(operation).get(status).and_then(|response| response.get("headers")), &format!("{status} headers"));
            let constant = |name| headers.get(name).and_then(|header| header.get("schema")).and_then(|schema| schema.get("const")).and_then(Value::as_str);
            assert_eq!(constant("Cache-Control"), Some("no-store"));
            assert_eq!(constant("Vary"), Some("X-Iroha-Finality-Challenge, Accept"));
            assert_eq!(constant("X-Content-Type-Options"), Some("nosniff"));
        }
    }
    let latest = openapi_operation(&document, "/v1/bridge/finality/attestation/latest", "get");
    let parameters = contract_array(latest.get("parameters"), "latest attestation parameters");
    assert!(parameters.iter().all(|parameter| parameter.get("in").and_then(Value::as_str) != Some("path")), "latest selects the durable tip without a height parameter");
    let height = openapi_operation(&document, "/v1/bridge/finality/attestation/{height}", "get");
    assert_eq!(operation_responses(latest).keys().collect::<BTreeSet<_>>(), operation_responses(height).keys().collect::<BTreeSet<_>>(), "both selectors share one response contract");
}
#[test]
fn finality_interval_openapi_binds_full_proofs_positive_selectors_and_native_count_limit() {
    use std::num::{NonZeroU64, NonZeroUsize};
    use iroha_core::sumeragi::finality::NativeFinalityProofIntervalLimits;
    let document = generate_spec();
    let path = "/v1/bridge/finality/interval/{from}/{to}";
    let operation = openapi_operation(&document, path, "get");
    let single = openapi_operation(&document, "/v1/bridge/finality/{height}", "get");
    assert_eq!(operation.get("security"), single.get("security"), "the interval preserves original Torii authentication");
    let auth = contract_object(operation.get(ROUTE_AUTH_EXTENSION), "interval route authority");
    scalar_contracts! { auth.get("stableRouteId") => Text("bridge.finality_interval.read"); auth.get("authentication") => Text("torii_default"); auth.get("admission") => Text("public"); operation.get(TOOL_EFFECT_EXTENSION) => Text("read"); }
    assert_eq!(operation_parameters(operation).len(), 2, "only the two exact inclusive selectors are accepted");
    for selector in ["from", "to"] {
        let parameter = operation_parameter(operation, selector);
        scalar_contracts! { parameter.get("in") => Text("path"); parameter.get("required") => Flag(true); }
        let schema = parameter_schema(parameter);
        scalar_contracts! { schema.get("type") => Text("integer"); schema.get("format") => Text("uint64"); schema.get("minimum") => Unsigned(1); schema.get("maximum") => Unsigned(u64::MAX); }
    }
    let content = response_content(operation, "200");
    assert_eq!(content.keys().map(String::as_str).collect::<BTreeSet<_>>(), contract_word_set("application/json application/x-norito"));
    let array = contract_object(content.get("application/json").and_then(|media| media.get("schema")), "complete finality proof interval");
    scalar_contracts! { array.get("type") => Text("array"); }
    assert_array_bounds(array, 1, 64, None);
    assert_item_ref(array, "#/components/schemas/SumeragiFinalityProof");
    let norito = contract_object(content.get("application/x-norito").and_then(|media| media.get("schema")), "canonical interval Norito frame");
    scalar_contracts! { norito.get("type") => Text("string"); norito.get("format") => Text("binary"); }
    let bounds = |last| NativeFinalityProofIntervalLimits::new(NonZeroU64::new(1).unwrap(), NonZeroU64::new(last).unwrap(), NonZeroUsize::new(1).unwrap(), NonZeroUsize::new(1).unwrap(), std::time::Instant::now());
    assert!(bounds(64).is_ok(), "the advertised full interval must be accepted by the real native bound");
    assert!(bounds(65).is_err(), "the actual native producer must refuse the first oversized interval");
    assert_eq!(operation_responses(operation).keys().map(String::as_str).collect::<BTreeSet<_>>(), contract_word_set("200 400 403 404 406 408 429 500 503"));
    for status in contract_words("400 403 404 406 408 429 500 503") {
        text_contracts! { operation_response_schema_ref(operation, status, path) => "#/components/schemas/ErrorEnvelope"; }
    }
}
#[test]
fn signed_status_documents_actual_driver_fields() {
    use iroha_data_model::sumeragi::{SumeragiStatus, SumeragiFootprint, SumeragiHaltReason};
    let status = SumeragiStatus {
        protocol_version: iroha_data_model::sumeragi::PROTOCOL_VERSION,
        config_fingerprint: iroha_crypto::Hash::new(b"native status schema fixture"),
        beacon_horizon: None,
        instance: [7; 32], height: 2, view: 0, stage: 0, leader: None, proxy_tail: None,
        high_qc_view: None, level: 0, start_level: 0, t_retx_ms: 500,
        committed_height: 1, applied_height: 1, awaiting: false, signer: None,
        unanchored: false, abstaining: true, halted: Some(SumeragiHaltReason::DriverAnomaly),
        footprint: SumeragiFootprint::default(),
    };
    let native = norito::json::to_value(&status).expect("current status JSON");
    let schemas = openapi_schemas();
    let schema = contract_schema(&schemas, "SumeragiStatusResponse");
    let properties = contract_object(schema.get("properties"), "current status properties");
    assert_eq!(object_field_set(native.as_object().expect("current status object")), object_field_set(properties));
    member_contracts! { properties; Absent => contract_strings("status.absent"); }
    scalar_contracts! { native.get("protocol_version") => Unsigned(u64::from(iroha_data_model::sumeragi::PROTOCOL_VERSION)); }
    assert_eq!(native.get("beacon_horizon"), Some(&Value::Null));
    assert_exact_closed_required_schema_fields(&schemas, "BeaconHorizonStatusV1", &contract_words("epoch_length_blocks next_required_pulse_height active_session_id session_covers_next_pulse local_provider_ready"));
    assert_eq!(native.get("instance").and_then(Value::as_str), Some("07".repeat(32).as_str()));
    let footprint = native.get("footprint").and_then(Value::as_object).unwrap();
    assert_eq!(object_field_set(footprint), object_field_set(contract_object(contract_schema(&schemas, "SumeragiFootprint").get("properties"), "footprint properties")));
}

#[test]
fn current_finality_schemas_match_portable_wire_bounds() {
    let schemas = openapi_schemas();
    let header = contract_schema(&schemas, "BlockHeader");
    assert!(schema_string_field_set(header, "required", "current block header").contains("global_beacon_pulse_hash"));
    let pulse_hash = contract_property(&schemas, "BlockHeader", "global_beacon_pulse_hash");
    assert!(pulse_hash.get("anyOf").and_then(Value::as_array).is_some_and(|alternatives|
        alternatives.iter().any(|value| value.get("$ref").and_then(Value::as_str) == Some("#/components/schemas/Hash"))
        && alternatives.iter().any(|value| value.get("type").and_then(Value::as_str) == Some("null"))));
    let proof = contract_schema(&schemas, "SumeragiFinalityProof");
    scalar_contracts! { proof.get("additionalProperties") => Flag(false); }
    assert_eq!(schema_string_field_set(proof, "required", "proof"), contract_words("block_header block_wire committee").into_iter().collect());
    scalar_contracts! { contract_property(&schemas, "SumeragiFinalityProof", "block_wire").get("maxItems") => Unsigned(iroha_data_model::sumeragi_finality::MAX_FINALITY_BLOCK_BYTES as u64); }
    scalar_contracts! { contract_property(&schemas, "SumeragiFinalityProof", "committee").get("maxItems") => Unsigned(iroha_data_model::block::consensus::MAX_VALIDATORS_PER_HEIGHT as u64); }
    let body = contract_schema(&schemas, "SumeragiFinalityAttestationBody");
    assert_eq!(schema_string_field_set(body, "required", "attestation body"), contract_words("challenge observed_at_unix_ms network_id node_id node_fingerprint build_fingerprint config_fingerprint genesis_block_hash genesis_finality_proof status finality_proof").into_iter().collect());
    let observed = contract_property(&schemas, "SumeragiFinalityAttestationBody", "observed_at_unix_ms");
    scalar_contracts! { observed.get("type") => Text("integer"); observed.get("format") => Text("uint64"); observed.get("minimum") => Unsigned(1); observed.get("maximum") => Unsigned(u64::MAX); }
    property_refs!(&schemas;
        "SumeragiFinalityAttestation", "body", "#/components/schemas/SumeragiFinalityAttestationBody";
        "SumeragiFinalityAttestationBody", "status", "#/components/schemas/SumeragiStatusResponse";
        "SumeragiFinalityAttestationBody", "finality_proof", "#/components/schemas/SumeragiFinalityProof";
    );
    for retired in ["BridgeFinalityAttestationBodyV1", "BridgeFinalityAttestationV1", "BridgeFinalityBundle"] {
        assert!(!schemas.contains_key(retired), "retired HTTP schema {retired}");
    }
}
#[test]
fn generated_spec_documents_read_only_nexus_lifecycle_status() {
    let document = generate_spec();
    let paths = contract_object(document.get("paths"), "paths");
    let path = contract_object(paths.get("/v1/nexus/lifecycle"), "lifecycle path");
    let operation = contract_object(path.get("get"), "lifecycle GET");
    text_contracts! { operation_response_schema_ref(operation, "200", "/v1/nexus/lifecycle") => "#/components/schemas/NexusLaneLifecycleStatusV1"; }
    let content = response_content(operation, "200");
    member_contracts! { content; Present => ["application/json", "application/x-norito"]; }
    member_contracts! { path; Absent => ["post"]; }
    let schemas = component_schemas(&document);
    let schema = contract_schema(schemas, "NexusLaneLifecycleStatusV1");
    assert_eq!(schema.get("additionalProperties"), Some(&Value::Bool(false)));
    assert_required_inventory(schema, "lifecycle.required");
    let properties = contract_object(schema.get("properties"), "lifecycle properties");
    set_contracts! { object_field_set(properties) => contract_words(concat!("catalog_hash incarnation_root incarnations lane_count lanes ", "runtime_catalog_hash version")).into_iter().collect(); }
    scalar_contracts! { properties.get("lanes").and_then(|property| property.get("type")) => Text("array"); }
    member_contracts! { properties; Absent => ["nexus_enabled"]; Present => contract_words("catalog_hash incarnations incarnation_root runtime_catalog_hash"); }
    let runtime_root = properties.get("runtime_catalog_hash").expect("required runtime root");
    assert_eq!(runtime_root.get("type"), Some(&norito::json!(["string", "null"])));
    scalar_contracts! { properties.get("incarnations").and_then(|property| property.get("items")).and_then(|items| items.get("$ref")) => Text("#/components/schemas/NexusLaneLifecycleIncarnationEntry"); }
}
#[test]
fn generated_spec_documents_exact_current_sumeragi_status() {
    let document = generate_spec();
    let schemas = component_schemas(&document);
    for (path, expected, label) in contract_rows! { "/v1/sumeragi/status", "#/components/schemas/SumeragiStatusResponse", "authoritative status"; "/v1/sumeragi/diagnostics", "#/components/schemas/SumeragiDiagnosticsResponse", "operator diagnostics"; } {
        let actual = document.get("paths").and_then(Value::as_object).and_then(|paths| paths.get(path)).and_then(Value::as_object).and_then(|item| item.get("get")).and_then(Value::as_object).map(|operation| operation_response_schema_ref(operation, "200", path));
        assert_eq!(actual, catalog_openapi_route_enabled(CatalogHttpMethod::Get, path).then_some(expected), "{label} catalog projection");
        if path == "/v1/sumeragi/diagnostics" && actual.is_some() {
            let operation = openapi_operation(&document, path, "get");
            text_contracts! { operation_response_schema_ref(operation, "503", path) => "#/components/schemas/ErrorEnvelope"; }
        }
    }
    assert_exact_closed_required_schema_fields(schemas, "SumeragiStatusResponse", &contract_strings("status.required"));
    let properties = contract_object(contract_schema(schemas, "SumeragiStatusResponse").get("properties"), "status properties");
    member_contracts! { properties; Absent => contract_strings("status.absent"); }
    scalar_contracts! { properties.get("footprint").and_then(|schema| schema.get("$ref")) => Text("#/components/schemas/SumeragiFootprint"); }
    let diagnostics = contract_schema(schemas, "SumeragiDiagnosticsResponse");
    scalar_contracts! { diagnostics.get("additionalProperties") => Flag(false); }
    let diagnostics = contract_object(diagnostics.get("properties"), "diagnostics properties");
    member_contracts! { diagnostics; Present => ["npos"]; }
    for (field, expected) in contract_rows! {
        "lane_governance", "#/components/schemas/SumeragiLaneGovernance";
    } {
        scalar_contracts! { diagnostics.get(field).and_then(|schema| schema.get("items")).and_then(|items| items.get("$ref")) => Text(expected); }
    }
    member_contracts! { diagnostics; Absent => contract_words("height view phase leader locked_prepare_qc"); }
    member_contracts! { diagnostics; Absent => contract_words(
        "pipeline_execution lane_commitments dataspace_commitments lane_settlement_commitments lane_relay_envelopes lane_payload_ownerships committed_lane_blocks lane_block_sessions native_amx_participant_applications autonomous_lane_executions"
    ); }
    member_contracts! { schemas; Absent => contract_words(
        "SumeragiPipelineExecutionDiagnostics SumeragiLaneCommitment SumeragiDataspaceCommitment LaneSettlementCommitment LaneRelayEnvelope NativeAmxReceipt SumeragiCommittedLaneBlock SumeragiLaneBlockSessionStatus SumeragiLanePayloadOwnership SumeragiNativeAmxParticipantApplication SumeragiAutonomousLaneExecution"
    ); }

}
#[test]
fn generated_spec_documents_exact_soracloud_priority_contracts() {
    let document = canonical_document();
    let paths = contract_object(document.get("paths"), "paths");
    count_contracts! { paths.keys().filter(|path| path.starts_with("/v1/soracloud/")).count() => 51; }
    member_contracts! { paths; Absent => contract_words(concat!("/v1/soracloud/agent/autonomy/run /v1/soracloud/agent/autonomy/run/finalize ", "/v1/soracloud/model-host/advertise /v1/soracloud/model-host/heartbeat ", "/v1/soracloud/model-host/withdraw /v1/soracloud/model-host/status")); }
    for path in contract_words("/v1/soracloud/deploy /v1/soracloud/upgrade") {
        let operation = openapi_operation(&document, path, "post");
        text_contracts! { operation_request_schema_ref(operation, path) => "#/components/schemas/SignedBundleRequest"; operation_response_schema_ref(operation, "200", path) => "#/components/schemas/SoracloudMutationDraftResponse"; }
    }
    let schemas = component_schemas(&document);
    member_contracts! { schemas; Absent => contract_words("AgentAutonomyRunPayload SignedAgentAutonomyRunRequest AgentAutonomyFinalizeRequest"); }
    inline_shapes! { schemas; "SignedBundleRequest", &contract_words("bundle initial_service_configs initial_service_secrets provenance"), &[]; }
    let status_operation = openapi_operation(&document, "/v1/soracloud/status", "get");
    text_contracts! { operation_response_schema_ref(status_operation, "200", "/v1/soracloud/status") => "#/components/schemas/SoracloudStatusV1"; }
    let status = contract_text(status_operation.get("description"), "Soracloud status description");
    for phrase in ["configured_lane_count", "declared_lane_count", "active lane ids/count", "autoscale-capacity lane ids/count"] {
        assert!(status.contains(phrase));
    }
    let join = openapi_operation(&document, "/v1/soracloud/hf/lease/join", "post");
    text_contracts! { operation_request_schema_ref(join, "/v1/soracloud/hf/lease/join") => "#/components/schemas/SignedHfSharedLeaseJoinRequest"; operation_response_schema_ref(join, "200", "/v1/soracloud/hf/lease/join") => "#/components/schemas/SoracloudMutationDraftResponse"; }
    let headers = operation_parameters(join);
    for name in contract_strings("hf.headers") {
        assert!(headers.iter().any(|parameter| parameter.get("name").and_then(Value::as_str) == Some(name)), "HF shared-lease join missing {name}");
    }
    inline_shapes! { schemas; "SignedHfSharedLeaseJoinRequest", &contract_words("payload provenance"), &[]; "HfSharedLeaseJoinPayload", &contract_words(concat!("repo_id revision service_name apartment_name storage_class lease_term_ms ", "lease_asset_definition_id base_fee")), &[]; }
    let apartment_name = contract_array(contract_property(schemas, "HfSharedLeaseJoinPayload", "apartment_name").get("anyOf"), "HF apartment_name nullable union");
    count_contracts! { apartment_name.len() => 2; }
    scalar_contracts! { apartment_name[0].get("type") => Text("string"); apartment_name[1].get("type") => Text("null"); }
    inline_shapes! { schemas; "SoracloudMutationDraftResponse", &contract_words("ok authority signed_by tx_instructions"), &[]; }
    assert_item_ref(contract_property(schemas, "SoracloudMutationDraftResponse", "tx_instructions"), "#/components/schemas/SoracloudTxInstruction");
    scalar_contracts! { contract_property(schemas, "SoracloudMutationDraftResponse", "tx_instructions").get("minItems") => Unsigned(1); contract_property(schemas, "SoracloudTxInstruction", "payload_hex").get("pattern") => Text("^(?:[0-9a-f]{2})+$"); }
    let wallet_spend = openapi_operation(&document, "/v1/soracloud/agent/wallet/spend", "post");
    text_contracts! { operation_request_schema_ref(wallet_spend, "agent wallet spend") => "#/components/schemas/SignedAgentWalletSpendRequest"; }
    inline_shapes! { schemas; "AgentWalletSpendPayload", &contract_words("apartment_name request_id asset_definition amount"), &[]; "SoracloudStatusV1", &contract_words(concat!("schema_version service_health routing hosted_http_topology resource_pressure ", "failed_admissions runtime_manager control_plane")), &[]; }
    let topology = contract_property(schemas, "SoracloudStatusV1", "hosted_http_topology");
    scalar_contracts! { topology.get("additionalProperties") => Flag(false); }
    let topology_fields = contract_word_set("active_capability_adverts hosted_replica_count placed_host_count unavailable_replica_count");
    assert_eq!(object_field_set(topology.get("properties").and_then(Value::as_object).expect("Soracloud hosted HTTP topology properties")), topology_fields);
    set_contracts! { schema_fields(topology, "required", "Soracloud hosted HTTP topology").iter().map(|field| field.as_str().expect("topology field")).collect::<BTreeSet<_>>() => topology_fields; }
    for field in topology_fields {
        let property = contract_object(topology.get("properties").and_then(Value::as_object).and_then(|properties| properties.get(field)), &format!("hosted topology {field}"));
        scalar_contracts! { property.get("type") => Text("integer"); property.get("format") => Text("uint64"); property.get("minimum") => Unsigned(0); }
    }
    let routing = contract_property(schemas, "SoracloudStatusV1", "routing");
    scalar_contracts! { routing.get("additionalProperties") => Flag(false); }
    let routing_properties = contract_object(routing.get("properties"), "Soracloud status routing properties");
    let routing_fields = contract_word_set("configured_lane_count declared_lane_count active_lane_count active_lane_ids autoscale_capacity_lane_count autoscale_capacity_lane_ids dataspace_count routing_rules default_lane_id default_dataspace_id");
    assert_eq!(object_field_set(routing_properties), routing_fields);
    set_contracts! { schema_fields(routing, "required", "Soracloud status routing").iter().map(|field| field.as_str().expect("routing field")).collect::<BTreeSet<_>>() => routing_fields; }
    text_contracts! { property_ref(schemas, "SoracloudStatusV1", "runtime_manager") => "#/components/schemas/SoracloudStatusRuntimeManagerV1"; }
    assert_exact_closed_required_schema_fields(schemas, "ControlPlaneAuditEvent",
        &contract_words(concat!("sequence action service_name from_version to_version service_manifest_hash ", "container_manifest_hash process_generation config_generation secret_generation ", "config_snapshot_hash secret_snapshot_hash binding_name state_key ",
            "config_mutations secret_mutations governance_tx_hash rollout_state policy_name ", "policy_snapshot_hash jurisdiction_tag consent_evidence_hash break_glass ", "break_glass_reason lease_usage service_lease_commitment ", "lease_reporting_epoch_rollover signed_by")));
    text_contracts! { nullable_property_ref(schemas, "ControlPlaneAuditEvent", "lease_reporting_epoch_rollover") => "#/components/schemas/SoraServiceLeaseReportingEpochRolloverV1"; }
    assert_exact_closed_required_schema_fields(schemas, "SoraServiceLeaseReportingEpochRolloverV1", &contract_words(concat!("schema_version economic_clock lease_started_height previous_reporting_epoch ", "new_reporting_epoch reporter_account_id active_service_version replica_slot ", "placement_incarnation finalized_checkpoint_count settled_egress_bytes_delta ", "settled_egress_bytes")));
    text_contracts! { property_ref(schemas, "SoraServiceLeaseReportingEpochRolloverV1", "economic_clock") => "#/components/schemas/SoraServiceLeaseClockV1"; property_ref(schemas, "SoraServiceLeaseReportingEpochRolloverV1", "placement_incarnation") => "#/components/schemas/Hash"; }
    let action_variants = contract_array(contract_schema(schemas, "SoracloudAction").get("oneOf"), "SoracloudAction variants").iter()
        .map(|variant| contract_text(variant.get("properties").and_then(Value::as_object).and_then(|properties| properties.get("action")).and_then(Value::as_object).and_then(|action| action.get("const")), "SoracloudAction const")).collect::<BTreeSet<_>>();
    set_contracts! { action_variants => contract_word_set("CiphertextQuery ConfigMutation DecryptionRequest Deploy FheJobRun FhePolicyRegister FhePolicyRevoke FhePolicyRotate LeaseUsage LeaseReportingEpochRollover Rollback Rollout SecretMutation StateMutation Upgrade"); }
    for (path, method, request, response) in contract_rows! { "/v1/soracloud/agent/autonomy/allow", "post", Some("#/components/schemas/SignedAgentArtifactAllowRequest"), "#/components/schemas/SoracloudMutationDraftResponse"; "/v1/soracloud/agent/autonomy/status", "get", None, "#/components/schemas/AgentAutonomyStatusResponse"; } {
        let operation = openapi_operation(&document, path, method);
        if let Some(request) = request {
            text_contracts! { operation_request_schema_ref(operation, path) => request; }
        }
        text_contracts! { operation_response_schema_ref(operation, "200", path) => response; }
    }
    inline_shapes! { schemas; "SignedAgentArtifactAllowRequest", &contract_words("payload provenance"), &[]; "AgentArtifactAllowPayload", &contract_words("apartment_name artifact_hash provenance_hash"), &[]; }
    assert_strict_object_schema(
        schemas,
        "AgentAutonomyStatusResponse",
        &contract_words(concat!("apartment_name sequence status lease_expires_height lease_remaining_blocks ", "manifest_hash revoked_policy_capability_count budget_ceiling_units ", "budget_remaining_units allowlist_count run_count process_generation ",
            "process_started_sequence last_active_sequence last_checkpoint_sequence ", "checkpoint_count persistent_state_total_bytes persistent_state_key_count ", "allowlist recent_runs")),
        &[],
    );
}
#[test]
fn generated_spec_documents_collection_pages_and_queries() {
    let document = generate_spec();
    assert_operation_response_contracts(
        &document,
        &response_rows! {
        "/v1/accounts", "get", "200", "#/components/schemas/AccountPage";
        "/v1/accounts/query", "post", "200", "#/components/schemas/AccountPage";
        "/v1/domains", "get", "200", "#/components/schemas/DomainPage";
        "/v1/domains/query", "post", "200", "#/components/schemas/DomainPage";
        "/v1/accounts/{account_id}/assets", "get", "200", "#/components/schemas/AccountAssetPage";
        "/v1/accounts/{account_id}/assets/query", "post", "200", "#/components/schemas/AccountAssetPage";
        "/v1/assets/definitions", "get", "200", "#/components/schemas/AssetDefinitionPage";
        "/v1/assets/definitions/query", "post", "200", "#/components/schemas/AssetDefinitionPage";
        "/v1/assets/{definition_id}/holders", "get", "200", "#/components/schemas/AssetHolderPage";
        "/v1/assets/{definition_id}/holders/query", "post", "200", "#/components/schemas/AssetHolderPage";
        "/v1/nfts", "get", "200", "#/components/schemas/NftPage";
        "/v1/nfts/query", "post", "200", "#/components/schemas/NftPage";
        "/v1/rwas", "get", "200", "#/components/schemas/RwaPage";
        "/v1/rwas/query", "post", "200", "#/components/schemas/RwaPage";
        "/v1/accounts/{account_id}/transactions", "get", "200", "#/components/schemas/TransactionPage";
        "/v1/accounts/{account_id}/transactions/query", "post", "200", "#/components/schemas/TransactionPage";
        "/v1/transactions/query", "post", "200", "#/components/schemas/TransactionPage";
        "/v1/accounts/{account_id}/history", "get", "200", "#/components/schemas/AccountHistoryPage";
        "/v1/accounts/{account_id}/history/query", "post", "200", "#/components/schemas/AccountHistoryPage";
        "/v1/contracts/activity", "get", "200", "#/components/schemas/ContractActivityPage";
        "/v1/contracts/activity/query", "post", "200", "#/components/schemas/ContractActivityPage";
        "/v1/contracts/events", "get", "200", "#/components/schemas/ContractEventPage";
        "/v1/contracts/events/query", "post", "200", "#/components/schemas/ContractEventPage";
        "/v1/repo/agreements", "get", "200", "#/components/schemas/RepoAgreementPage";
        "/v1/repo/agreements/query", "post", "200", "#/components/schemas/RepoAgreementPage";
    },
    );
    let schemas = component_schemas(&document);
    for page in contract_words("AccountPage AccountAssetPage AssetDefinitionPage AssetHolderPage DomainPage NftPage RepoAgreementPage RwaPage TransactionPage AccountHistoryPage ContractActivityPage ContractEventPage") {
        let schema = contract_schema(schemas, page);
        let required = schema_fields(schema, "required", page);
        string_members! { required; Present => &["items", "next_cursor"]; };
        let properties = contract_object(schema.get("properties"), page);
        member_contracts! { properties; Absent => &["has_more", "count_mode", "offset"]; }
    }
    for path in contract_words("/v1/accounts/query /v1/domains/query /v1/repo/agreements/query") {
        text_contracts! { operation_request_schema_ref(openapi_operation(&document, path, "post"), path) => "#/components/schemas/CollectionQuery"; }
    }
    text_contracts! { operation_request_schema_ref(openapi_operation(&document, "/v1/transactions/query", "post"), "/v1/transactions/query") => "#/components/schemas/HistoryQuery"; }
    let query = contract_object(contract_schema(schemas, "CollectionQuery").get("properties"), "collection query properties");
    member_contracts! { query; Present => contract_strings("collection.query.fields"); }
    let history = contract_object(contract_schema(schemas, "HistoryQuery").get("properties"), "history query properties");
    member_contracts! { history; Absent => &["sort", "aggregate", "include_total"]; }
    let metadata = contract_schema(schemas, "AppPageMetadata");
    assert_required_inventory(metadata, "app.page.required");
    let required = schema_fields(metadata, "required", "app page metadata");
    string_members! { required; Absent => &["total"]; };
    let properties = contract_object(metadata.get("properties"), "metadata properties");
    member_contracts! { properties; Present => contract_strings("app.page.properties"); }
    let repo = contract_schema(schemas, "RepoAgreement");
    let repo_required = schema_fields(repo, "required", "repo agreement");
    let repo_properties = contract_object(repo.get("properties"), "repo properties");
    for field in contract_strings("repo.agreement.fields") {
        string_members! { repo_required; Present => &[field]; };
        member_contracts! { repo_properties; Present => [field]; }
    }
}
#[test]
fn alias_openapi_documents_optional_public_and_exact_restricted_auth() {
    let document = generate_spec();
    for path in contract_words("/v1/aliases/resolve-index /v1/aliases/by-account") {
        let operation = openapi_operation(&document, path, "post");
        assert_eq!(operation_header_requirements(operation), canonical_account_header_requirements(false));
        assert_alias_auth_required_response(operation, path);
        assert!(operation_responses(operation).contains_key("403"));
    }
    let lookup = contract_text(openapi_operation(&document, "/v1/aliases/by-account", "post").get("description"), "alias description");
    assert!(lookup.contains("Canonical authentication is optional") && lookup.contains("required for restricted data"));
    let resolve = openapi_operation(&document, "/v1/aliases/resolve", "post");
    assert_eq!(operation_header_requirements(resolve), canonical_account_header_requirements(false));
    assert_alias_auth_required_response(resolve, "/v1/aliases/resolve");
    assert!(resolve.get("description").and_then(Value::as_str).is_some_and(|text| text.contains("Public dataspaces may be read unsigned")));
    assert!(operation_responses(resolve).contains_key("403"));
    for path in contract_words("/v1/aliases/setup/plan /v1/aliases/lease/renew/plan /v1/aliases/auto-renew/plan") {
        let operation = openapi_operation(&document, path, "post");
        assert_eq!(operation_header_requirements(operation), canonical_account_header_requirements(false));
        assert_alias_auth_required_response(operation, path);
        assert!(operation_responses(operation).contains_key("409"));
    }
    for (path, reject, forbidden) in contract_rows! { "/v1/retail/recipients/lookup", "recipient_lookup_signature_required", true; "/v1/retail/recipients/route", "recipient_lookup_signature_required", true; "/v1/fee-sponsor-programs/by-id", "fee_sponsor_program_signature_required", false; "/v1/fees/quote", "fee_quote_signature_required", false; } {
        let operation = openapi_operation(&document, path, "post");
        assert_eq!(operation_header_requirements(operation), canonical_account_header_requirements(false));
        assert_canonical_auth_required_response(operation, path, reject);
        assert_eq!(operation_responses(operation).contains_key("403"), forbidden);
    }
}
#[test]
fn protected_contract_identity_openapi_is_signed_and_exact() {
    let document = generate_spec();
    for (path, method, response_schema, reject, statuses) in contract_rows! {
        "/v1/contracts/aliases/resolve", "post", "#/components/schemas/ContractAliasResolveResponse", "alias_auth_required", &contract_words("200 400 401 404 429 500")[..];
        "/v1/gov/contracts/{contract_address}", "get", "#/components/schemas/GovernedContractResponse", "contract_code_auth_required", &contract_words("200 400 401 404 429 500");
        "/v1/contracts/artifacts/{dataspace_id}/{code_hash}/bytes", "get", "#/components/schemas/ContractArtifactBytesResponse", "contract_code_auth_required", &contract_words("200 400 401 403 404 429");
        "/v1/contracts/artifacts/{dataspace_id}/{code_hash}", "get", "#/components/schemas/ContractArtifactManifestResponse", "canonical_authentication_required", &contract_words("200 400 401 403 404 429");
    } {
        let operation = openapi_operation(&document, path, method);
        assert_eq!(operation_header_requirements(operation), canonical_account_header_requirements(false));
        assert_canonical_auth_required_response(operation, path, reject);
        text_contracts! { operation_response_schema_ref(operation, "200", path) => response_schema; }
        set_contracts! { operation_responses(operation).keys().map(String::as_str).collect::<BTreeSet<_>>() => statuses.iter().copied().collect::<BTreeSet<_>>(); }
    }
    text_contracts! { operation_request_schema_ref(openapi_operation(&document, "/v1/contracts/aliases/resolve", "post"), "/v1/contracts/aliases/resolve") => "#/components/schemas/ContractAliasResolveRequest"; }
    let schemas = component_schemas(&document);
    schema_shapes!(schemas;
        "ContractAliasResolveRequest", "contract.alias.request.required", None;
        "ContractAliasBinding", "contract.alias.binding.required", Some("contract.alias.binding.optional");
        "ContractAliasResolveResponse", "contract.alias.response.required", None;
    );
    let variants = contract_array(contract_schema(schemas, "GovernedContractResponse").get("oneOf"), "governed variants");
    count_contracts! { variants.len() => 3; }
    for (variant, inventory) in variants.iter().zip(["governed.found.fields", "governed.inactive.fields", "governed.missing.fields"]) {
        let variant = variant.as_object().expect("governed variant");
        assert_eq!(variant.get("additionalProperties"), Some(&Value::Bool(false)));
        let expected = asset_field_set(inventory);
        set_contracts! { schema_fields(variant, "required", "governed variant").iter().filter_map(Value::as_str).collect::<BTreeSet<_>>() => expected; }
        assert_eq!(variant.get("properties").and_then(Value::as_object).map(object_field_set), Some(expected));
    }
    for (schema, expected) in contract_rows! {
        "GovernedContractLifecycleV1", contract_words(concat!("version origin origin_account origin_proposal_content_id_hex ", "origin_governance_attempt_id_hex owner pending_owner parliament_delegated ", "active_code_hash_hex retained_code_hash_hex revision emergency_hold")) .into_iter() .collect::<BTreeSet<_>>();
        "GovernedContractEmergencyHoldV1", contract_words(concat!("incident_digest_hex proposal_content_id_hex governance_attempt_id_hex reason ", "imposed_at_height expires_at_height")) .into_iter() .collect::<BTreeSet<_>>();
    } {
        let schema = contract_schema(schemas, schema);
        assert_eq!(schema.get("additionalProperties"), Some(&Value::Bool(false)));
        set_contracts! { schema_fields(schema, "required", "governed lifecycle component") .iter() .filter_map(Value::as_str) .collect::<BTreeSet<_>>() => expected; }
    }
}
#[test]
fn multisig_read_auth_contract_is_path_specific() {
    let document = generate_spec();
    for path in contract_words("/v1/multisig/spec /v1/multisig/proposals/query /v1/multisig/proposals/resolve") {
        let operation = openapi_operation(&document, path, "post");
        assert_eq!(operation_header_requirements(operation), canonical_account_header_requirements(false));
        assert_canonical_auth_required_response(operation, path, "multisig_read_auth_required");
        let description = contract_text(operation.get("description"), "multisig read description");
        for phrase in ["Both canonical `multisig_account_id`", "`multisig_account_alias` selectors require", "body fields never establish signer identity"] {
            assert!(description.contains(phrase));
        }
    }
    for path in contract_words(concat!("/v1/multisig/propose /v1/multisig/approve /v1/multisig/cancel ", "/v1/contracts/call/multisig/propose /v1/contracts/call/multisig/approve")) {
        assert!(operation_header_requirements(openapi_operation(&document, path, "post")).is_empty(), "POST {path} body-authenticated write contract");
    }
}
}

#[test]
fn scoped_artifact_openapi_binds_network_full_dataspace_and_content() {
    let document = generate_spec();
    let schemas = component_schemas(&document);
    for (name, required) in [
        ("ContractArtifactId", &["dataspace_id", "code_hash"][..]),
        (
            "ContractArtifactBytesResponse",
            &["network_id", "artifact_id", "code_b64"][..],
        ),
        (
            "ContractArtifactManifestResponse",
            &["network_id", "artifact_id", "manifest"][..],
        ),
    ] {
        let schema = contract_schema(schemas, name);
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            schema
                .get("required")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>(),
            required.iter().copied().collect::<BTreeSet<_>>()
        );
    }
    let identity = contract_schema(schemas, "ContractArtifactId");
    let properties = identity.get("properties").unwrap().as_object().unwrap();
    assert_eq!(
        properties["dataspace_id"]
            .get("maximum")
            .and_then(Value::as_u64),
        Some(u64::MAX)
    );
    assert_eq!(
        properties["code_hash"].get("$ref").and_then(Value::as_str),
        Some("#/components/schemas/Hash")
    );
    for path in [
        "/v1/contracts/artifacts/{dataspace_id}/{code_hash}",
        "/v1/contracts/artifacts/{dataspace_id}/{code_hash}/bytes",
    ] {
        let operation = openapi_operation(&document, path, "get");
        let parameters = operation.get("parameters").unwrap().as_array().unwrap();
        let dataspace = parameters
            .iter()
            .find(|parameter| parameter.get("name").and_then(Value::as_str) == Some("dataspace_id"))
            .unwrap();
        assert_eq!(dataspace.get("required"), Some(&Value::Bool(true)));
        assert_eq!(dataspace.get("in").and_then(Value::as_str), Some("path"));
        assert_eq!(
            dataspace
                .get("schema")
                .unwrap()
                .get("type")
                .and_then(Value::as_str),
            Some("string")
        );
    }
    for retired in [
        "/v1/contracts/code/{code_hash}",
        "/v1/contracts/code-bytes/{code_hash}",
    ] {
        assert!(document.get("paths").unwrap().get(retired).is_none());
    }
}
