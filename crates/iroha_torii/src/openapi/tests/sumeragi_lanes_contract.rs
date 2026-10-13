/// One served lane whose record and instance exercise every nested lane schema.
fn sample_lane_status() -> iroha_data_model::sumeragi_lanes::SumeragiLaneStatus {
    use iroha_crypto::{Algorithm, KeyPair, bls_normal_pop_prove};
    use iroha_data_model::{
        parameter::system::SumeragiParameters,
        sumeragi::{PROTOCOL_VERSION, SumeragiFootprint, SumeragiHaltReason, SumeragiStatus},
        sumeragi_lanes::{
            SumeragiLaneFrontier, SumeragiLaneMember, SumeragiLaneRecord, SumeragiLaneStatus,
        },
    };
    use iroha_model_base::{
        peer::PeerId,
        topology::{DataSpaceId, LaneId},
    };

    let pair = KeyPair::from_seed(vec![7; 32], Algorithm::BlsNormal);
    let member = SumeragiLaneMember {
        peer: PeerId::new(pair.public_key().clone()),
        pop: bls_normal_pop_prove(pair.private_key()).expect("BLS-normal lane member PoP"),
    };
    SumeragiLaneStatus {
        record: SumeragiLaneRecord {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            lane: LaneId::new(3),
            dataspace: DataSpaceId::new(9),
            incarnation: [0x11; 32],
            params: SumeragiParameters::default(),
            committee: vec![member],
            created_at: 10,
            active_from: 12,
            closing: Some(40),
            anchor_freshness: 16,
            merged: SumeragiLaneFrontier {
                height: 5,
                block_hash: [0x22; 32],
                result: [0x33; 32],
            },
            merged_at: 30,
            rescued: 1,
        },
        instance: Some(SumeragiStatus {
            protocol_version: PROTOCOL_VERSION,
            config_fingerprint: iroha_crypto::Hash::new(b"lane status schema fixture"),
            beacon_horizon: None,
            instance: [0x44; 32],
            height: 6,
            view: 0,
            stage: 1,
            leader: Some(pair.public_key().clone()),
            proxy_tail: None,
            high_qc_view: Some(0),
            level: 0,
            start_level: 0,
            t_retx_ms: 250,
            committed_height: 5,
            applied_height: 5,
            awaiting: false,
            signer: Some(pair.public_key().clone()),
            unanchored: false,
            abstaining: false,
            halted: Some(SumeragiHaltReason::DriverAnomaly),
            footprint: SumeragiFootprint::default(),
        }),
    }
}

/// Property names of one closed schema, checked against its required list.
#[track_caller]
fn closed_schema_fields(schemas: &Map, name: &str) -> BTreeSet<String> {
    let schema = contract_schema(schemas, name);
    assert_eq!(
        schema.get("additionalProperties"),
        Some(&Value::Bool(false)),
        "{name} must reject unknown fields"
    );
    let properties = contract_object(schema.get("properties"), &format!("{name} properties"))
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let required = contract_array(schema.get("required"), &format!("{name} required"))
        .iter()
        .map(|field| field.as_str().expect("required field name").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        properties, required,
        "{name}: every served field is required"
    );
    properties
}

#[track_caller]
fn json_fields(value: &Value, context: &str) -> BTreeSet<String> {
    contract_object(Some(value), context)
        .keys()
        .cloned()
        .collect()
}

#[test]
fn sumeragi_lanes_operation_projects_the_served_lane_list() {
    let path = route_catalog::sumeragi::LANES.path();
    assert_eq!(path, "/v1/sumeragi/lanes");
    let compiled = generate_spec();
    let compiled_paths = contract_object(compiled.get("paths"), "compiled paths");
    assert_eq!(
        compiled_paths.contains_key(path),
        catalog_openapi_route_enabled(CatalogHttpMethod::Get, path),
        "the lane list follows the telemetry-gated catalog projection"
    );
    let document = canonical_document();
    let operation = openapi_operation(&document, path, "get");
    assert_eq!(
        operation_response_schema_ref(operation, "200", path),
        "#/components/schemas/SumeragiLaneStatusList"
    );
    let norito = contract_object(
        response_content(operation, "200")
            .get("application/x-norito")
            .and_then(|media| media.get("schema")),
        "lane list Norito schema",
    );
    assert_eq!(norito.get("type").and_then(Value::as_str), Some("string"));
    assert_eq!(norito.get("format").and_then(Value::as_str), Some("binary"));
    let responses = contract_object(operation.get("responses"), "lane list responses");
    assert_eq!(
        responses
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["200", "503"])
    );
    let auth = contract_object(operation.get(ROUTE_AUTH_EXTENSION), "lane list route auth");
    assert_eq!(
        auth.get("stableRouteId").and_then(Value::as_str),
        Some(route_catalog::sumeragi::LANES.stable_route_id())
    );
    assert_eq!(
        auth.get("authentication").and_then(Value::as_str),
        Some("operator_signature")
    );
    assert_eq!(
        operation.get(TOOL_EFFECT_EXTENSION).and_then(Value::as_str),
        Some("operator")
    );
    let summary = contract_object(Some(&document), "document")
        .get("paths")
        .and_then(|paths| paths.get("/v1/sumeragi/status"))
        .and_then(|item| item.get("get"))
        .and_then(|operation| operation.get("summary"))
        .and_then(Value::as_str)
        .expect("status summary");
    assert!(
        !summary.contains("v2"),
        "the status route names one Sumeragi protocol"
    );
}

#[test]
fn sumeragi_lane_schemas_match_the_served_rust_dto() {
    let schemas = openapi_schemas();
    let list = contract_schema(&schemas, "SumeragiLaneStatusList");
    assert_eq!(list.get("type").and_then(Value::as_str), Some("array"));
    assert_eq!(
        list.get("items")
            .and_then(|items| items.get("$ref"))
            .and_then(Value::as_str),
        Some("#/components/schemas/SumeragiLaneStatus")
    );

    let served = norito::json::to_value(&vec![sample_lane_status()]).expect("served lane JSON");
    let lane = &contract_array(Some(&served), "served lanes")[0];
    assert_eq!(
        json_fields(lane, "lane status"),
        closed_schema_fields(&schemas, "SumeragiLaneStatus")
    );
    let instance = contract_property(&schemas, "SumeragiLaneStatus", "instance");
    let alternatives = contract_array(instance.get("anyOf"), "nullable lane instance");
    assert!(
        alternatives
            .iter()
            .any(|schema| schema.get("$ref").and_then(Value::as_str)
                == Some("#/components/schemas/SumeragiStatusResponse"))
    );
    assert!(
        alternatives
            .iter()
            .any(|schema| schema.get("type").and_then(Value::as_str) == Some("null"))
    );

    let record = lane.get("record").expect("served record");
    assert_eq!(
        json_fields(record, "lane record"),
        closed_schema_fields(&schemas, "SumeragiLaneRecord")
    );
    let da_layout = record.get("da_layout").expect("signed lane DA layout");
    assert_eq!(
        json_fields(da_layout, "lane DA layout"),
        closed_schema_fields(&schemas, "SumeragiDataAvailabilityLayout")
    );
    assert_eq!(
        da_layout.get("encoding").expect("signed encoding"),
        &norito::json!({"encoding": "reed_solomon16", "details": null})
    );
    assert_eq!(
        json_fields(record.get("params").expect("params"), "lane params"),
        closed_schema_fields(&schemas, "SumeragiParameters")
    );
    assert_eq!(
        json_fields(record.get("merged").expect("merged"), "lane frontier"),
        closed_schema_fields(&schemas, "SumeragiLaneFrontier")
    );
    let member = &contract_array(record.get("committee"), "committee")[0];
    assert_eq!(
        json_fields(member, "lane member"),
        closed_schema_fields(&schemas, "SumeragiLaneMember")
    );
    assert_eq!(
        json_fields(
            lane.get("instance").expect("instance"),
            "lane instance status"
        ),
        closed_schema_fields(&schemas, "SumeragiStatusResponse")
    );

    for (owner, field, value) in [
        (
            "SumeragiLaneRecord",
            "incarnation",
            record.get("incarnation"),
        ),
        (
            "SumeragiLaneFrontier",
            "block_hash",
            record
                .get("merged")
                .and_then(|merged| merged.get("block_hash")),
        ),
        (
            "SumeragiLaneFrontier",
            "result",
            record.get("merged").and_then(|merged| merged.get("result")),
        ),
    ] {
        let text = value.and_then(Value::as_str).expect("served 32-byte hex");
        let pattern = contract_property(&schemas, owner, field)
            .get("pattern")
            .and_then(Value::as_str);
        assert_eq!(pattern, Some("^[0-9A-F]{64}$"), "{owner}.{field}");
        assert!(
            text.len() == 64
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
        );
    }
    let pop = member
        .get("pop")
        .and_then(Value::as_str)
        .expect("served PoP");
    let pop_schema = contract_property(&schemas, "SumeragiLaneMember", "pop");
    assert_eq!(
        pop_schema.get("minLength").and_then(Value::as_u64),
        Some(pop.len() as u64)
    );
    assert_eq!(
        pop_schema.get("maxLength").and_then(Value::as_u64),
        Some(pop.len() as u64)
    );
    assert_eq!(
        contract_property(&schemas, "SumeragiLaneMember", "peer")
            .get("$ref")
            .and_then(Value::as_str),
        Some("#/components/schemas/BlsValidatorId")
    );
    let algorithms = contract_property(&schemas, "SumeragiParameters", "key_allowed_algorithms");
    let admitted = contract_array(
        algorithms.get("items").and_then(|items| items.get("enum")),
        "admitted key algorithms",
    );
    for served in contract_array(
        record
            .get("params")
            .and_then(|params| params.get("key_allowed_algorithms")),
        "served algorithms",
    ) {
        assert!(
            admitted.contains(served),
            "served algorithm {served:?} must be admitted"
        );
    }
    for field in [
        "block_cadence_ms",
        "due_work_max_lag_ms",
        "payload_retry_interval_ms",
        "exec_budget_ms",
        "apply_budget_ms",
        "max_block_bytes",
        "epoch_length_blocks",
        "demotion_window",
    ] {
        assert_eq!(
            contract_property(&schemas, "SumeragiParameters", field)
                .get("minimum")
                .and_then(Value::as_u64),
            Some(1),
            "nonzero SumeragiParameters.{field}"
        );
    }
}
