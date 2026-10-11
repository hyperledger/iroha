//! Closed OpenAPI contracts for generation authority and frozen committee preparation.

use super::*;

#[test]
fn validator_committee_openapi_is_closed_and_retires_epoch_roster_fields() {
    let schemas = openapi_schemas();
    for (name, fields) in [
        (
            "ValidatorCommitteeStatusV1",
            "network_id target_epoch latest_finality selected pending_beacon_session",
        ),
        (
            "ValidatorCommitteeSelectionStatusV1",
            "transition selecting_finality",
        ),
        (
            "ValidatorCommitteeTransitionV1",
            "preparation credentials readiness outcome",
        ),
        ("ValidatorCommitteeCredentialsV1", "beacon"),
        ("ValidatorGenerationV1", "network_id generation validators"),
        (
            "ValidatorCommitteeSeatReadinessV1",
            "validator_index beacon",
        ),
        (
            "ValidatorSeatReadinessContextV1",
            "version network_id transition_id target_epoch authority_generation authority_id first_height last_height validator_index beacon",
        ),
        (
            "ValidatorEpochAuthorizationV1",
            "version network_id epoch first_height last_height authority_generation authority_id beacon previous_authorization_id transition_id decision",
        ),
    ] {
        let schema = schemas.get(name).unwrap();
        assert_eq!(
            schema.get("additionalProperties").and_then(Value::as_bool),
            Some(false)
        );
        let expected = fields.split_whitespace().collect::<BTreeSet<_>>();
        let properties = schema.get("properties").and_then(Value::as_object).unwrap();
        assert_eq!(
            properties
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            expected
        );
        assert_eq!(
            schema
                .get("required")
                .and_then(Value::as_array)
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect::<BTreeSet<_>>(),
            expected
        );
    }
    for (owner, field) in [
        ("ValidatorCommitteeStatusV1", "latest_finality"),
        ("ValidatorCommitteeSelectionStatusV1", "selecting_finality"),
    ] {
        assert_eq!(
            schemas[owner]["properties"][field]["$ref"].as_str(),
            Some("#/components/schemas/NativeFinalityArtifact")
        );
    }
    let native = &schemas["NativeFinalityArtifact"];
    assert_eq!(native["additionalProperties"].as_bool(), Some(false));
    assert_eq!(
        native["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["block_wire"]
    );
    assert_eq!(native["properties"].as_object().unwrap().len(), 1);
    assert_eq!(
        native["properties"]["block_wire"]["format"].as_str(),
        Some("byte")
    );
    assert_eq!(
        native["properties"]["block_wire"]["maxLength"].as_u64(),
        Some(44_739_244)
    );
    assert_eq!(
        schemas["ValidatorGenerationV1"]["properties"]["validators"]["maxItems"].as_u64(),
        Some(31)
    );
    assert_eq!(
        schemas["ValidatorSeatReadinessContextV1"]["properties"]["beacon"]["$ref"].as_str(),
        Some("#/components/schemas/InstalledBeaconEpochBindingV1")
    );
    assert_eq!(
        schemas["ValidatorSeatReadinessContextV1"]["properties"]["target_epoch"]["minimum"]
            .as_u64(),
        Some(1)
    );
    assert_eq!(
        schemas["ValidatorSeatReadinessContextV1"]["properties"]["first_height"]["minimum"]
            .as_u64(),
        Some(2)
    );
    assert_eq!(
        schemas["ValidatorSeatReadinessContextV1"]["properties"]["validator_index"]["maximum"]
            .as_u64(),
        Some(30)
    );
    assert_eq!(
        schemas["NativeGlobalFeeProgramStateV1"]["properties"]["fee_asset_definition"]["$ref"]
            .as_str(),
        Some("#/components/schemas/AssetDefinition")
    );
    assert!(schemas.keys().all(|name| !name.starts_with("Kagemusha")));
    assert!(!schemas.contains_key("ValidatorCandidateKeysV1"));
    let document = generate_spec();
    let paths = document.get("paths").and_then(Value::as_object).unwrap();
    let operation = paths
        .get("/v1/nexus/validator-committee")
        .unwrap()
        .get("get")
        .unwrap();
    assert_eq!(
        operation.get("x-iroha-tool-effect").and_then(Value::as_str),
        Some("read")
    );
    let response = operation
        .get("responses")
        .unwrap()
        .get("200")
        .unwrap()
        .get("content")
        .unwrap();
    for media in ["application/json", "application/x-norito"] {
        assert_eq!(
            response
                .get(media)
                .unwrap()
                .get("schema")
                .unwrap()
                .get("$ref")
                .and_then(Value::as_str),
            Some("#/components/schemas/ValidatorCommitteeStatusV1")
        );
    }
}
