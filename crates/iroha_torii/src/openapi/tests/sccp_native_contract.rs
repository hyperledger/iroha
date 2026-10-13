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
        (sccp::FORGERY_HOLD, "SccpForgeryHoldViewV1"),
        (sccp::FAST_PAUSE, "SccpFastPauseViewV1"),
        (sccp::EVIDENCE_ANCHOR, "SccpAnchorWitnessBundleV1"),
        (sccp::EVIDENCE, "SccpForgeryEvidenceStatusV1"),
        (sccp::EVIDENCE_PAGE, "SccpForgeryEvidencePageV1"),
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
        assert_eq!(
            operation["responses"].get("410").is_some(),
            route == sccp::EVIDENCE_ANCHOR
        );
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
        sccp::FORGERY_HOLD,
        sccp::FAST_PAUSE,
        sccp::EVIDENCE_ANCHOR,
        sccp::EVIDENCE,
        sccp::EVIDENCE_PAGE,
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
    for penalty_status in [
        iroha_data_model::block::consensus::EvidencePenaltyStatus::Pending,
        iroha_data_model::block::consensus::EvidencePenaltyStatus::Applied { height: 9 },
    ] {
        let row = iroha_sccp::api::SccpForgeryEvidenceStatusV1 {
            evidence_id: [0xab; 32],
            generation: 2,
            height: 99,
            rule: iroha_data_model::sccp::native::SccpForgeryRuleV1::E2,
            offenders: vec![iroha_data_model::sccp::native::SccpForgeryOffenderV1 {
                signer: 0,
                lane_id: iroha_model_base::topology::LaneId::new(0),
                validator: iroha_test_samples::ALICE_ID.clone(),
                activation_height: 1,
            }],
            penalty_status,
            recorded_at_height: 8,
        };
        let json = norito::json::to_value(&row).unwrap();
        assert_closed_fields(&schemas, "SccpForgeryEvidenceStatusV1", &json);
        assert_hex(
            &schemas["SccpForgeryEvidenceStatusV1"]["properties"]["evidence_id"],
            &json["evidence_id"],
            32,
        );
        assert_closed_fields(&schemas, "SccpForgeryOffenderV1", &json["offenders"][0]);
        assert_eq!(
            norito::json::from_value::<iroha_sccp::api::SccpForgeryEvidenceStatusV1>(json.clone())
                .unwrap(),
            row
        );
        assert_eq!(
            schemas["SccpForgeryEvidenceStatusV1"]["properties"]["penalty_status"],
            schema_ref("SumeragiEvidencePenaltyStatus")
        );
        let page = iroha_sccp::api::SccpForgeryEvidencePageV1 {
            records: vec![row],
            next_after: None,
        };
        let json = norito::json::to_value(&page).unwrap();
        assert_closed_fields(&schemas, "SccpForgeryEvidencePageV1", &json);
        assert!(json["next_after"].is_null());
        assert_eq!(
            schemas["SccpForgeryEvidencePageV1"]["properties"]["records"]["maxItems"].as_u64(),
            Some(64)
        );
        assert_eq!(
            norito::json::from_value::<iroha_sccp::api::SccpForgeryEvidencePageV1>(json).unwrap(),
            page
        );
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
    for current in [
        "current_generation",
        "coalition_slashable_floor",
        "liability_clock",
        "forgery_max_generation",
        "pause_panel_ids",
        "parliament_binding_ballot_available",
        "reconciliation_available",
    ] {
        assert!(
            cap.get(current).is_some(),
            "current SCCP capability {current}"
        );
    }
    for retired in [
        "domain_separator",
        "highest_attested_height",
        "roster_generation",
    ] {
        assert!(cap.get(retired).is_none());
    }
}

#[test]
fn sccp_forgery_hold_schema_is_the_typed_scalar_reconciliation_view() {
    use iroha_data_model::{
        bridge::SccpNetworkV1,
        sccp::{
            native::SccpQuarantineV1,
            reconciliation::{SccpReconciliationRatioV1, SccpReconciliationStateV1},
        },
    };
    use iroha_sccp::api::{
        SccpForgeryHoldCursorV1, SccpForgeryHoldRevisionV1, SccpForgeryHoldViewV1,
    };
    let schemas = openapi_schemas();
    let ratio = SccpReconciliationRatioV1 {
        backing: 7,
        denominator: 10,
    };
    let state = SccpReconciliationStateV1 {
        opened_at_ms: 1,
        closes_at_ms: 2,
        forged_supply: 3,
        rho: Some(ratio),
        settled_face: 5,
    };
    let quarantine = SccpQuarantineV1 {
        certificate_id: [7; 32],
        since_height: 1,
    };
    let row = SccpForgeryHoldRevisionV1 {
        network: SccpNetworkV1::EthereumMainnet,
        revision: 1,
        forgery_floor: 2,
        held: false,
        quarantine: Some(quarantine),
        reconciliation: Some(state),
    };
    let view = SccpForgeryHoldViewV1 {
        max_generation: Some(3),
        revisions: vec![row],
        next: None,
    };
    for (name, value) in [
        (
            "SccpForgeryHoldCursorV1",
            norito::json::to_value(&SccpForgeryHoldCursorV1 {
                network: row.network,
                revision: row.revision,
            })
            .unwrap(),
        ),
        (
            "SccpReconciliationRatioV1",
            norito::json::to_value(&ratio).unwrap(),
        ),
        (
            "SccpReconciliationStateV1",
            norito::json::to_value(&state).unwrap(),
        ),
        (
            "SccpQuarantineV1",
            norito::json::to_value(&quarantine).unwrap(),
        ),
        (
            "SccpForgeryHoldRevisionV1",
            norito::json::to_value(&row).unwrap(),
        ),
        (
            "SccpForgeryHoldViewV1",
            norito::json::to_value(&view).unwrap(),
        ),
    ] {
        assert_closed_fields(&schemas, name, &value);
    }
    assert_eq!(
        schemas["SccpForgeryHoldViewV1"]["properties"]["revisions"]["maxItems"].as_u64(),
        Some(64)
    );
}

#[test]
fn sccp_provable_fields_are_required_typed_observations() {
    use iroha_data_model::sccp::control::SccpControlRecordV1;
    use iroha_sccp::api::{SccpControlViewV1, SccpRecordedStateV1};
    let schemas = openapi_schemas();
    let recorded = SccpRecordedStateV1 {
        deadline_ms: 10,
        provable: false,
    };
    let control = SccpControlViewV1 {
        control_nonce: 1,
        record: SccpControlRecordV1 {
            track: 1,
            parliament_paused: true,
            fast_pause_until_ms: 0,
            height: 2,
            commitment_index: 0,
            leaf: [1; 32],
            certificate_id: [2; 32],
            effect_hash: [3; 32],
        },
        provable: true,
    };
    assert_closed_fields(
        &schemas,
        "SccpRecordedStateV1",
        &norito::json::to_value(&recorded).unwrap(),
    );
    assert_closed_fields(
        &schemas,
        "SccpControlViewV1",
        &norito::json::to_value(&control).unwrap(),
    );
    for name in ["SccpRecordedStateV1", "SccpControlViewV1"] {
        assert_eq!(
            schemas[name]["properties"]["provable"]["type"].as_str(),
            Some("boolean")
        );
    }
}

#[test]
fn sccp_fast_pause_and_anchor_schemas_match_original_named_records() {
    use iroha_data_model::{
        account::AccountId,
        bridge::SccpNetworkV1,
        sccp::{fast_pause::*, native::SccpAnchorWitnessV1},
    };
    use iroha_sccp::api::{
        SccpAnchorWitnessBundleV1, SccpFastPauseActiveViewV1, SccpFastPauseRoundViewV1,
        SccpFastPauseSuspendedViewV1, SccpFastPauseViewV1, SccpPauseSeatsV1,
    };
    let schemas = openapi_schemas();
    let members = (1..=15)
        .map(|seed| {
            let pair =
                iroha_crypto::KeyPair::from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519);
            AccountId::new(pair.public_key().clone())
        })
        .collect::<Vec<_>>();
    let panel = SccpPausePanelV1 {
        panel_seq: 1,
        pulse_id: [1; 32],
        seated_height: 1,
        seated_at_ms: 10,
        accept_until_ms: 20,
        term_ends_at_ms: 30,
        accepted: members[..10].iter().cloned().collect(),
        drawn: members.clone(),
        primary_id: [2; 32],
        backup_id: [3; 32],
    };
    let endorsement = SccpFastPauseEndorsementV1 {
        incident_digest: [4; 32],
        recorded_at_height: 2,
    };
    let round = SccpFastPauseRoundV1 {
        panel_id: [2; 32],
        panel_seq: 1,
        head: 0,
        opened_at_ms: 21,
        closes_at_ms: 25,
        endorsers: [(members[0].clone(), endorsement)].into_iter().collect(),
        certify_due: false,
    };
    let pause = SccpFastPauseV1 {
        certificate_id: [5; 32],
        effect_hash: [6; 32],
        panel_id: [2; 32],
        enacted_at: SccpPassPositionV1 {
            height: 3,
            position: 0,
        },
        enacted_at_ms: 22,
        until_ms: 40,
        taira: true,
        revisions: vec![1, 2],
    };
    let network = SccpNetworkV1::EthereumMainnet;
    let seats = SccpPauseSeatsV1 {
        primary: members[..5].to_vec(),
        backup: members[5..10].to_vec(),
    };
    let view = SccpFastPauseViewV1 {
        panel: Some(panel.clone()),
        seats: Some(seats.clone()),
        eligibility_available: true,
        rounds: vec![SccpFastPauseRoundViewV1 {
            network,
            role: SccpPanelRoleV1::Primary,
            round: round.clone(),
        }],
        active: vec![SccpFastPauseActiveViewV1 {
            network,
            pause: pause.clone(),
        }],
        suspended: vec![SccpFastPauseSuspendedViewV1 {
            network,
            until_ms: 50,
        }],
    };
    let anchor = SccpAnchorWitnessBundleV1 {
        height: 1,
        chunk: 0,
        witness: Some(SccpAnchorWitnessV1 {
            core_hash: [1; 32],
            result: [2; 32],
            path: [[3; 32]; 12],
        }),
    };
    for (name, value) in [
        ("SccpPausePanelV1", norito::json::to_value(&panel).unwrap()),
        (
            "SccpFastPauseEndorsementV1",
            norito::json::to_value(&endorsement).unwrap(),
        ),
        (
            "SccpFastPauseRoundV1",
            norito::json::to_value(&round).unwrap(),
        ),
        (
            "SccpPassPositionV1",
            norito::json::to_value(&pause.enacted_at).unwrap(),
        ),
        ("SccpFastPauseV1", norito::json::to_value(&pause).unwrap()),
        ("SccpPauseSeatsV1", norito::json::to_value(&seats).unwrap()),
        (
            "SccpFastPauseRoundViewV1",
            norito::json::to_value(&view.rounds[0]).unwrap(),
        ),
        (
            "SccpFastPauseActiveViewV1",
            norito::json::to_value(&view.active[0]).unwrap(),
        ),
        (
            "SccpFastPauseSuspendedViewV1",
            norito::json::to_value(&view.suspended[0]).unwrap(),
        ),
        (
            "SccpFastPauseViewV1",
            norito::json::to_value(&view).unwrap(),
        ),
        (
            "SccpAnchorWitnessBundleV1",
            norito::json::to_value(&anchor).unwrap(),
        ),
    ] {
        assert_closed_fields(&schemas, name, &value);
    }
    for (index, role) in [SccpPanelRoleV1::Primary, SccpPanelRoleV1::Backup]
        .into_iter()
        .enumerate()
    {
        let value = norito::json::to_value(&role).unwrap();
        let variant = &schemas["SccpPanelRoleV1"]["oneOf"][index];
        assert_closed_fields(
            &Map::from_iter([("role".to_owned(), variant.clone())]),
            "role",
            &value,
        );
        assert_eq!(variant["properties"]["role"]["const"], value["role"]);
    }
    for (field, bound) in [("rounds", 6), ("active", 3), ("suspended", 3)] {
        assert_eq!(
            schemas["SccpFastPauseViewV1"]["properties"][field]["maxItems"].as_u64(),
            Some(bound)
        );
    }
    let mut unavailable = view;
    unavailable.seats = None;
    unavailable.eligibility_available = false;
    let json = norito::json::to_value(&unavailable).unwrap();
    assert!(json["seats"].is_null());
    assert_eq!(
        norito::json::from_value::<SccpFastPauseViewV1>(json).unwrap(),
        unavailable
    );
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

#[test]
fn sccp_governance_readiness_schema_preserves_unavailable_and_exact_native_fields() {
    use iroha_data_model::governance::types::{
        GovernanceAttemptId, GovernanceAttemptStatusV1, GovernanceAttemptV1, GovernanceStageV1,
        ProposalContentId, RiskTierV1,
    };
    use iroha_sccp::api::{
        SccpGovernanceActiveAttemptV1, SccpGovernanceBodySizesV1, SccpGovernanceReadinessV1,
    };
    let document = canonical_document();
    let schemas = component_schemas(&document);
    let body_sizes = SccpGovernanceBodySizesV1 {
        rules_committee: 1,
        agenda_council: 2,
        interest_panel: 3,
        review_panel: 4,
        coordination_council: 5,
        policy_jury: 6,
        confirmation_jury: 7,
        oversight_committee: 8,
        mpc_committee: 9,
        fma_committee: 10,
        alternates: 11,
    };
    let content = ProposalContentId::new([3; 32]);
    let active = SccpGovernanceActiveAttemptV1 {
        attempt: GovernanceAttemptV1 {
            id: GovernanceAttemptId::derive_v1(content, 0),
            proposal_content_id: content,
            sequence: 0,
            risk_tier: RiskTierV1::Standard,
            stage: GovernanceStageV1::Qualification,
            status: GovernanceAttemptStatusV1::Active,
        },
        due_available: false,
        next_due_height: None,
        next_due_timestamp_ms: None,
    };
    let record = SccpGovernanceReadinessV1 {
        committed_height: 42,
        eligible_citizens: None,
        body_sizes,
        active_beacon_session: Some([5; 32]),
        beacon_matches_current_roster: false,
        parliament_binding_ballot_available: false,
        reconciliation_available: false,
        attempt_latency_ms: None,
        active_attempts: vec![active],
    };
    let value = norito::json::to_value(&record).unwrap();
    assert_closed_fields(schemas, "SccpGovernanceReadinessV1", &value);
    assert_closed_fields(schemas, "SccpGovernanceBodySizesV1", &value["body_sizes"]);
    assert_closed_fields(
        schemas,
        "SccpGovernanceActiveAttemptV1",
        &value["active_attempts"][0],
    );
    assert_closed_fields(
        schemas,
        "GovernanceParliamentAttemptProjectionV1",
        &value["active_attempts"][0]["attempt"],
    );
    for field in ["eligible_citizens", "attempt_latency_ms"] {
        assert!(value[field].is_null());
        assert_eq!(
            schemas["SccpGovernanceReadinessV1"]["properties"][field]["anyOf"][1]["type"].as_str(),
            Some("null")
        );
    }
    assert_hex(
        &schemas["SccpGovernanceReadinessV1"]["properties"]["active_beacon_session"]["anyOf"][0],
        &value["active_beacon_session"],
        32,
    );
    let operation = &document["paths"]["/v1/sccp/governance/readiness"]["get"];
    assert_eq!(
        operation["responses"]["200"]["content"]["application/json"]["schema"],
        schema_ref("SccpGovernanceReadinessV1")
    );
    assert_eq!(
        operation["x-iroha-route-auth"]["stableRouteId"].as_str(),
        Some("sccp.governance.readiness")
    );
}
