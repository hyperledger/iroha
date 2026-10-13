//! Current SCCP native read and governance OpenAPI contracts.

use super::*;
use iroha_data_model::sccp::generation::SccpGenerationCauseV1;
use iroha_sccp::api::{
    SccpBlockRefV1, SccpCertificateV1, SccpControlProofBundleV1, SccpFinalityConstantsV1,
    SccpGenerationV1, SccpMessageProofBundleV1,
};

fn assert_closed_fields(schemas: &Map, name: &str, actual: &Value) {
    let schema = &schemas[name];
    let fields = actual.as_object().expect("serialized typed DATA object");
    let expected = fields.keys().map(String::as_str).collect::<BTreeSet<_>>();
    assert_eq!(schema["additionalProperties"].as_bool(), Some(false));
    assert_eq!(
        schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        expected,
        "{name} advertised fields"
    );
    assert_eq!(
        schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        expected,
        "{name} required fields"
    );
}

fn assert_hex(schema: &Value, value: &Value, bytes: usize) {
    let length = u64::try_from(bytes * 2).unwrap();
    assert_eq!(schema["type"].as_str(), Some("string"));
    assert_eq!(schema["minLength"].as_u64(), Some(length));
    assert_eq!(schema["maxLength"].as_u64(), Some(length));
    assert_eq!(
        schema["pattern"].as_str(),
        Some(format!("^[0-9A-Fa-f]{{{length}}}$").as_str())
    );
    let encoded = value.as_str().expect("fixed bytes serialize as hex");
    assert_eq!(encoded.len(), bytes * 2);
    assert!(encoded.bytes().all(|byte| byte.is_ascii_hexdigit()));
}

#[test]
fn sccp_native_routes_match_catalog_and_exact_selectors() {
    use iroha_torii_shared::route_catalog::sccp;
    let document = canonical_document();
    let paths = document["paths"].as_object().unwrap();
    let actual = paths
        .keys()
        .filter(|path| path.starts_with("/v1/sccp/"))
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = sccp::ROUTES
        .iter()
        .map(|route| route.path())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    for retired in [
        "/v1/sccp/rosters/current",
        "/v1/sccp/rosters/{generation}",
        "/v1/sccp/rosters/rotations",
    ] {
        assert!(!paths.contains_key(retired));
    }
    for (route, schema) in [
        (sccp::MESSAGE_PROOF, "SccpMessageProofBundleV1"),
        (sccp::CONTROL_PROOF, "SccpControlProofBundleV1"),
        (sccp::FINALITY, "SccpCertificateV1"),
        (sccp::CURRENT_COMMITTEE, "SccpGenerationV1"),
        (sccp::COMMITTEE, "SccpGenerationV1"),
    ] {
        let operation = &paths[route.path()]["get"];
        assert_eq!(operation[ROUTE_AUTH_EXTENSION], route_auth_metadata(route));
        assert_eq!(operation[TOOL_EFFECT_EXTENSION].as_str(), Some("read"));
        assert_eq!(
            operation["responses"]["200"]["content"]["application/json"]["schema"],
            schema_ref(schema)
        );
        assert!(operation["responses"].get("503").is_some());
        assert!(operation["responses"].get("408").is_some());
        assert!(operation["responses"].get("409").is_none());
        assert!(operation["responses"].get("410").is_none());
    }
    for route in [sccp::MESSAGE_PROOF, sccp::CONTROL_PROOF] {
        let parameters = paths[route.path()]["get"]["parameters"].as_array().unwrap();
        let query = parameters
            .iter()
            .filter(|value| value["in"].as_str() == Some("query"))
            .collect::<Vec<_>>();
        assert_eq!(query.len(), 1);
        assert_eq!(query[0]["name"].as_str(), Some("at"));
        assert_eq!(query[0]["schema"]["default"].as_str(), Some("record"));
        assert_eq!(
            query[0]["schema"]["pattern"].as_str(),
            Some("^(record|latest|[2-9]|[1-9][0-9]+)$")
        );
    }
    let rotations = &paths[sccp::COMMITTEE_ROTATIONS.path()]["get"];
    let parameters = rotations["parameters"].as_array().unwrap();
    assert_eq!(parameters[0]["name"].as_str(), Some("after_generation"));
    assert_eq!(parameters[0]["required"].as_bool(), Some(true));
    assert_eq!(parameters[1]["schema"]["default"].as_str(), Some("16"));
    let response = &rotations["responses"]["200"]["content"]["application/json"]["schema"];
    assert_eq!(response["maxItems"].as_u64(), Some(16));
    assert_eq!(response["items"], schema_ref("SccpRotationV1"));
    let expired = &rotations["responses"]["410"];
    assert_eq!(
        expired["content"]["application/json"]["schema"],
        schema_ref("ErrorEnvelope")
    );
    assert!(
        expired["description"]
            .as_str()
            .unwrap()
            .contains("sccp_rotation_pruned")
    );
    assert!(rotations["responses"].get("404").is_some());
    assert!(rotations["responses"].get("503").is_some());
    for route in [
        sccp::CURRENT_COMMITTEE,
        sccp::COMMITTEE,
        sccp::COMMITTEE_ROTATIONS,
    ] {
        let responses = &paths[route.path()]["get"]["responses"];
        assert_eq!(
            responses["200"]["headers"]["Cache-Control"]["schema"]["const"].as_str(),
            Some("no-store")
        );
        assert!(responses["200"]["headers"].get("ETag").is_none());
        assert!(responses.get("304").is_none());
    }
}

#[test]
fn sccp_native_proof_schemas_match_actual_json_and_bounds() {
    let schemas = openapi_schemas();
    // Deliberately invalid signature/committee DATA: these tests check the JSON
    // contract, and must never promote serialization into finality authority.
    let certificate = SccpCertificateV1 {
        height: 2,
        qc: [1; 116],
        aggregate_signature: [2; 96],
        header: [3; 221],
        committee: vec![[4; 48]; 4],
    };
    assert!(certificate.check_shape().is_err());
    let json = norito::json::to_value(&certificate).unwrap();
    assert_closed_fields(&schemas, "SccpCertificateV1", &json);
    for (field, size) in [("qc", 116), ("aggregate_signature", 96), ("header", 221)] {
        assert_hex(
            &schemas["SccpCertificateV1"]["properties"][field],
            &json[field],
            size,
        );
    }
    assert_hex(
        &schemas["SccpCertificateV1"]["properties"]["committee"]["items"],
        &json["committee"][0],
        48,
    );
    assert_eq!(
        schemas["SccpCertificateV1"]["properties"]["committee"]["maxItems"].as_u64(),
        Some(31)
    );
    let block = SccpBlockRefV1 {
        height: 2,
        sccp_root: [5; 32],
        message_count: 1,
        history_index: 0,
        history_path: vec![],
    };
    assert_closed_fields(
        &schemas,
        "SccpBlockRefV1",
        &norito::json::to_value(&block).unwrap(),
    );
    let message = SccpMessageProofBundleV1 {
        message_id: [6; 32],
        payload: vec![1, 2, 3],
        deadline_ms: 7,
        leaf_index: 0,
        path: vec![],
        block: block.clone(),
        certificate: certificate.clone(),
    };
    let json = norito::json::to_value(&message).unwrap();
    assert_closed_fields(&schemas, "SccpMessageProofBundleV1", &json);
    assert_eq!(json["payload"].as_str(), Some("AQID"));
    let control = SccpControlProofBundleV1 {
        network: iroha_data_model::bridge::SccpNetworkV1::EthereumMainnet,
        revision: 1,
        control_nonce: 1,
        track: 2,
        parliament_paused: false,
        fast_pause_until_ms: 9,
        certificate_id: [7; 32],
        effect_hash: [8; 32],
        leaf_index: 0,
        path: vec![],
        block,
        certificate,
    };
    assert_closed_fields(
        &schemas,
        "SccpControlProofBundleV1",
        &norito::json::to_value(&control).unwrap(),
    );
    for name in ["SccpMessageProofBundleV1", "SccpControlProofBundleV1"] {
        assert_eq!(
            schemas[name]["properties"]["path"]["maxItems"].as_u64(),
            Some(9)
        );
        assert_eq!(
            schemas[name]["properties"]["certificate"],
            schema_ref("SccpCertificateV1")
        );
        assert!(schemas[name]["properties"].get("attestation").is_none());
        assert!(schemas[name]["properties"].get("roster").is_none());
    }
    assert_eq!(
        schemas["SccpBlockRefV1"]["properties"]["history_path"]["maxItems"].as_u64(),
        Some(32)
    );
    assert_eq!(
        schemas["SccpMessageProofBundleV1"]["properties"]["payload"]["maxLength"].as_u64(),
        Some(5464)
    );
    let mut malformed = norito::json::to_value(&control).unwrap();
    malformed
        .get_mut("certificate")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("header".to_owned(), Value::String("AA".repeat(220)));
    let encoded = norito::json::to_json(&malformed).unwrap();
    assert!(norito::json::from_json::<SccpControlProofBundleV1>(&encoded).is_err());
}

#[test]
fn sccp_generation_and_constants_schemas_preserve_full_typed_data() {
    let schemas = openapi_schemas();
    assert_eq!(
        schemas["SccpGenerationCauseV1"]["oneOf"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    for (cause, tag) in [
        (SccpGenerationCauseV1::Genesis, "genesis"),
        (SccpGenerationCauseV1::KeyChange, "key_change"),
        (SccpGenerationCauseV1::Heartbeat, "heartbeat"),
        (SccpGenerationCauseV1::Resync, "resync"),
    ] {
        let value = SccpGenerationV1 {
            generation: 1,
            committee_root: [1; 32],
            cause,
            start_height: 1,
            start_timestamp_ms: 2,
            start_lc: 0,
            validity_ms: 3,
            deadline_ms: 5,
            grace_ms: 6,
            progress_cap_ms: 7,
            liable_until_lc: 11,
            dest_cleared_lc: None,
            liable: true,
            end: None,
            keys: vec![[2; 48]; 4],
            members: vec![None; 4],
        };
        let json = norito::json::to_value(&value).unwrap();
        assert_closed_fields(&schemas, "SccpGenerationV1", &json);
        let variant = schemas["SccpGenerationCauseV1"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|schema| schema["properties"]["cause"]["const"] == json["cause"]["cause"])
            .expect("actual cause in closed schema");
        assert_closed_fields(
            &Map::from_iter([("Cause".to_owned(), variant.clone())]),
            "Cause",
            &json["cause"],
        );
        assert_eq!(json["cause"]["cause"].as_str(), Some(tag));
        assert!(json["cause"]["detail"].is_null());
        assert_eq!(
            norito::json::from_value::<SccpGenerationCauseV1>(json["cause"].clone()).unwrap(),
            cause
        );
        assert_eq!(
            norito::json::from_value::<SccpGenerationV1>(json.clone()).unwrap(),
            value
        );
        assert!(json["dest_cleared_lc"].is_null());
        assert!(json["members"][0].is_null());
    }
    let constants = SccpFinalityConstantsV1::current();
    let json = norito::json::to_value(&constants).unwrap();
    assert_closed_fields(&schemas, "SccpFinalityConstantsV1", &json);
    for retired_tag in ["Genesis", "KeyChange", "Heartbeat", "Resync"] {
        let retired = norito::json!({"kind": retired_tag, "value": null});
        assert!(norito::json::from_value::<SccpGenerationCauseV1>(retired).is_err());
        let wrong_tag = norito::json!({"cause": retired_tag, "detail": null});
        assert!(norito::json::from_value::<SccpGenerationCauseV1>(wrong_tag).is_err());
    }
    assert_eq!(
        norito::json::from_value::<SccpFinalityConstantsV1>(json.clone()).unwrap(),
        constants
    );
    for (name, length) in [
        ("x_layout_id", 16),
        ("dst_sig", 43),
        ("result_tag", 24),
        ("result_body_tag", 29),
    ] {
        assert_eq!(
            schemas["SccpFinalityConstantsV1"]["properties"][name]["const"],
            json[name]
        );
        assert_hex(
            &schemas["SccpFinalityConstantsV1"]["properties"][name],
            &json[name],
            length,
        );
        let encoded = json[name].as_str().unwrap();
        for malformed in [
            Value::String(encoded[..encoded.len() - 2].to_owned()),
            Value::String(format!("{encoded}00")),
            Value::String("G".repeat(length * 2)),
            Value::Array(vec![Value::from(0_u64); length]),
        ] {
            let mut wrong = json.clone();
            wrong
                .as_object_mut()
                .unwrap()
                .insert(name.to_owned(), malformed);
            assert!(
                norito::json::from_value::<SccpFinalityConstantsV1>(wrong).is_err(),
                "{name} requires its exact fixed-byte hex representation"
            );
        }
    }
    for retired in [
        "header_length",
        "qc_length",
        "signature_length",
        "signature_dst",
    ] {
        assert!(
            schemas["SccpFinalityConstantsV1"]["properties"]
                .get(retired)
                .is_none()
        );
        let mut wrong = json.clone();
        wrong
            .as_object_mut()
            .unwrap()
            .insert(retired.to_owned(), Value::Null);
        assert!(norito::json::from_value::<SccpFinalityConstantsV1>(wrong).is_err());
    }
    let cap = &schemas["SccpCapabilitiesV1"]["properties"];
    assert!(cap.get("consensus_instance").is_some());
    assert_eq!(cap["finality"], schema_ref("SccpFinalityConstantsV1"));
    for retired in [
        "domain_separator",
        "highest_attested_height",
        "roster_generation",
    ] {
        assert!(cap.get(retired).is_none());
    }
}

#[test]
fn sccp_governance_schema_uses_native_pin_and_current_parameters() {
    use iroha_data_model::sccp::{
        deployment::{SccpCommitteePinV1, SccpDeploymentV1, SccpEvmDeploymentV1},
        governance::SccpRegisterRouteActionV1,
        params::SccpParametersV1,
    };
    let schemas = openapi_schemas();
    let pin = SccpCommitteePinV1 {
        generation: 1,
        committee_root: [1; 32],
        start_height: 1,
        until_ms: 2,
    };
    pin.validate_shape().unwrap();
    assert_closed_fields(
        &schemas,
        "SccpCommitteePinV1",
        &norito::json::to_value(&pin).unwrap(),
    );
    assert_closed_fields(
        &schemas,
        "SccpParametersV1",
        &norito::json::to_value(&SccpParametersV1::taira_default()).unwrap(),
    );
    let registration = SccpRegisterRouteActionV1 {
        network: iroha_data_model::bridge::SccpNetworkV1::EthereumMainnet,
        revision: 1,
        deployment: SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address: [1; 20],
            runtime_code_hash: [2; 32],
        }),
        initial_committee: pin,
        max_wrapped_supply: 1,
    };
    assert_closed_fields(
        &schemas,
        "SccpRegisterRouteActionV1",
        &norito::json::to_value(&registration).unwrap(),
    );
    let register = &schemas["SccpRegisterRouteActionV1"];
    assert_eq!(
        register["properties"]["initial_committee"],
        schema_ref("SccpCommitteePinV1")
    );
    assert!(
        register["properties"]
            .get("initial_roster_generation")
            .is_none()
    );
    assert!(
        register["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field.as_str() == Some("initial_committee"))
    );
    for name in ["SccpClearBridgeKeyFaultActionV1", "SccpFaultRefV1"] {
        assert!(!schemas.contains_key(name));
    }
    let subjects = schemas["SccpGovernanceSubjectV1"]["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|variant| variant["properties"]["subject"]["const"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        subjects,
        BTreeSet::from(["route", "route_control", "light_client", "parameters"])
    );
    // Closed production decoder must reject the removed field, even when a
    // caller also supplies all mandatory native pin coordinates.
    let mut malformed = norito::json::to_value(&registration).unwrap();
    malformed
        .as_object_mut()
        .unwrap()
        .insert("initial_roster_generation".to_owned(), Value::from(1_u64));
    assert!(
        norito::json::from_json::<SccpRegisterRouteActionV1>(
            &norito::json::to_json(&malformed).unwrap()
        )
        .is_err()
    );
}
