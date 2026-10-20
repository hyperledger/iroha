// Governance DAG, transparency, and proof-token readback regressions.

fn governance_mirror_fixture() -> (
    SharedAppState,
    TempDir,
    Value,
    GovernanceDagSourceMetadata,
    String,
    String,
    String,
) {
    let (app, temp_dir, _digest_hex, block_cid_hex, node_cid_hex) =
        sorafs_app_state_with_governance_runtime_index();
    let (runtime_index, _runtime_metadata) =
        load_governance_dag_runtime_index(&app).expect("load verified runtime fixture");
    let snapshot = app
        .sorafs_node
        .governance_dag_runtime_snapshot()
        .expect("read typed runtime fixture")
        .expect("published runtime fixture");
    let head_bytes = snapshot.head_bytes();
    let signed_head: GovernanceDagHeadV1 =
        decode_canonical_governance_dag_value(head_bytes, "governance DAG head")
            .unwrap_or_else(|_| panic!("decode canonical governance DAG head"));
    let head_raw_ipfs_cid = governance_dag_raw_ipfs_cid(head_bytes);
    let head_blake3_hex = encode(blake3_hash(head_bytes).as_bytes());
    let runtime_blocks = runtime_index
        .json_array(&["blocks"])
        .expect("generated runtime blocks");

    let mut blocks = Vec::with_capacity(runtime_blocks.len());
    let mut by_block_cid_hex = Map::new();
    let mut by_node_cid_hex = Map::new();
    let mut by_encoded_blake3 = Map::new();
    let mut by_payload_kind = Map::new();
    for (position, runtime_block) in runtime_blocks.iter().enumerate() {
        let position_u64 = u64::try_from(position).expect("mirror position fits u64");
        let block_cid = runtime_block
            .json_str(&["block_cid_hex"])
            .expect("runtime block CID");
        let node_cid = runtime_block
            .json_str(&["node_cid_hex"])
            .expect("runtime node CID");
        let encoded_blake3 = runtime_block
            .json_str(&["encoded_blake3"])
            .expect("verified runtime block digest")
            .to_owned();
        let block_path = runtime_block
            .json_str(&["block_path"])
            .expect("verified runtime block path");
        let block_bytes = read_bounded_governance_dag_file(
            &app,
            &governance_dag_root_dir(&app)
                .unwrap_or_else(|_| panic!("governance DAG root"))
                .join(block_path),
            u64::try_from(GOVERNANCE_DAG_BLOCK_MAX_CANONICAL_BYTES_V1).unwrap_or(u64::MAX),
            "canonical governance DAG block",
        )
        .unwrap_or_else(|_| panic!("read verified runtime block"));
        let payload_kind = runtime_block
            .json_str(&["payload_kind"])
            .expect("runtime payload kind");
        let mut block = Map::new();
        block.insert("position".into(), Value::from(position_u64));
        for field in [
            "sequence",
            "node_cid_hex",
            "block_cid_hex",
            "payload_kind",
            "encoded_len",
            "submission_publisher_account_digest_hex",
            "submission_origin",
        ] {
            block.insert(
                field.to_owned(),
                runtime_block.get(field).cloned().unwrap_or(Value::Null),
            );
        }
        block.insert(
            "timestamp".into(),
            runtime_block
                .get("published_at_unix")
                .cloned()
                .expect("runtime published timestamp"),
        );
        block.insert("blake3".into(), Value::from(encoded_blake3.clone()));
        block.insert(
            "ipfs_cid".into(),
            Value::from(governance_dag_raw_ipfs_cid(&block_bytes)),
        );
        blocks.push(Value::Object(block));
        by_block_cid_hex.insert(block_cid.to_owned(), Value::from(position_u64));
        by_node_cid_hex.insert(node_cid.to_owned(), Value::from(position_u64));
        by_encoded_blake3.insert(encoded_blake3.clone(), Value::from(position_u64));
        append_governance_lookup_position(
            &mut by_payload_kind,
            payload_kind.to_owned(),
            position_u64,
        );
    }

    let mut head = Map::new();
    head.insert(
        "head_block_cid_hex".into(),
        Value::from(encode(&signed_head.head_block_cid)),
    );
    head.insert("block_count".into(), Value::from(signed_head.block_count));
    head.insert("generated_at".into(), Value::from(signed_head.generated_at));
    head.insert("ipfs_cid".into(), Value::from(head_raw_ipfs_cid.clone()));
    head.insert("blake3".into(), Value::from(head_blake3_hex.clone()));

    let mut index = Map::new();
    index.insert(
        "schema".into(),
        Value::from("sorafs.governance_dag.mirror.v1"),
    );
    index.insert("generation".into(), Value::from(7_u64));
    index.insert("generated_at".into(), Value::from(signed_head.generated_at));
    index.insert("head".into(), Value::Object(head));
    index.insert(
        "archive".into(),
        json_object(vec![
            json_entry("generation", Value::from(0_u64)),
            json_entry("archived_block_count", Value::from(0_u64)),
            json_entry("blake3", Value::Null),
            json_entry("ipfs_cid", Value::Null),
        ]),
    );
    index.insert("block_count".into(), Value::from(signed_head.block_count));
    index.insert(
        "indexed_block_count".into(),
        Value::from(u64::try_from(blocks.len()).expect("mirror block count fits u64")),
    );
    index.insert("blocks".into(), Value::Array(blocks));
    index.insert("by_block_cid_hex".into(), Value::Object(by_block_cid_hex));
    index.insert("by_node_cid_hex".into(), Value::Object(by_node_cid_hex));
    index.insert("by_encoded_blake3".into(), Value::Object(by_encoded_blake3));
    index.insert("by_payload_kind".into(), Value::Object(by_payload_kind));
    let index = Value::Object(index);
    let canonical_bytes = json::to_json_pretty(&index)
        .expect("encode canonical mirror fixture")
        .into_bytes();
    let metadata = GovernanceDagSourceMetadata::new(
        GOVERNANCE_DAG_MIRROR_SOURCE_V1,
        (3, [0xA3; 32]),
        &canonical_bytes,
        Some((7, [0xB7; 32])),
    );
    let (index, metadata) = parse_governance_dag_mirror_index(&canonical_bytes, metadata)
        .expect("validate canonical mirror fixture");
    let head_block_cid_hex = encode(&signed_head.head_block_cid);
    (
        app,
        temp_dir,
        index,
        metadata,
        block_cid_hex,
        node_cid_hex,
        head_block_cid_hex,
    )
}

fn assert_governance_source_metadata(
    value: &Value,
    expected_source: &str,
    expect_checkpoint: bool,
) {
    assert_eq!(value.json_str(&["source"]), Some(expected_source));
    assert!(
        value
            .json_u64(&["source_generation"])
            .is_some_and(|generation| generation > 0)
    );
    let record_digest = value
        .json_str(&["source_record_blake3"])
        .expect("source record digest");
    assert!(is_canonical_lower_hex(record_digest, 64));
    assert!(value.get("source_path").is_none());
    assert!(value.get("head_path").is_none());
    if expect_checkpoint {
        assert!(
            value
                .json_u64(&["source_checkpoint_generation"])
                .is_some_and(|generation| generation > 0)
        );
        let revision = value
            .json_str(&["source_checkpoint_revision"])
            .expect("source checkpoint revision");
        assert!(is_canonical_lower_hex(revision, 64));
    } else {
        assert!(value.get("source_checkpoint_generation").is_none());
        assert!(value.get("source_checkpoint_revision").is_none());
    }
}

#[test]
fn governance_dag_source_payload_bytes_uses_external_inner_payload() {
    let encoded_payload = vec![0x4e, 0x52, 0x54, 0x31, 0x01, 0x02, 0x03];
    let payload =
        GovernanceLogPayloadV1::ExternalPayload(sorafs_manifest::GovernanceExternalPayloadV1 {
            version: sorafs_manifest::SORAFS_GOVERNANCE_EXTERNAL_PAYLOAD_VERSION_V1,
            payload_kind: "test_external_payload".to_owned(),
            payload_version: 1,
            encoded_blake3: *blake3::hash(&encoded_payload).as_bytes(),
            encoded_len: u64::try_from(encoded_payload.len())
                .expect("external payload length fits u64"),
            encoded_payload: encoded_payload.clone(),
            metadata: Vec::new(),
        });
    assert_eq!(
        governance_dag_source_payload_bytes(&payload)
            .expect("derive external governance source bytes"),
        encoded_payload
    );
}
#[test]
fn governance_dag_raw_ipfs_cid_commits_exact_bytes() {
    assert_eq!(
        governance_dag_raw_ipfs_cid(b"payload"),
        "bafkreibdt5m62vphg7dxcr6pkwwqygydbnwx5z2iu5bgsuxzxbjnlkjv4u"
    );
    assert_ne!(
        governance_dag_raw_ipfs_cid(b"payload-tampered"),
        governance_dag_raw_ipfs_cid(b"payload")
    );
}
#[test]
fn governance_dag_file_backed_gets_are_admitted_and_offloaded() {
    let source = include_str!("../api.rs");
    for handler_name in [
        "handle_get_sorafs_governance_dag_dashboard",
        "handle_get_sorafs_governance_dag_head",
        "handle_get_sorafs_governance_dag_block",
        "handle_get_sorafs_governance_dag_node",
        "handle_get_sorafs_governance_dag_publish_index",
        "handle_get_sorafs_governance_dag_publish_digest",
        "handle_get_sorafs_governance_dag_publish_kind",
        "handle_get_sorafs_transparency_cycles",
        "handle_get_sorafs_transparency_cycle",
        "handle_get_sorafs_transparency_cycle_entry",
        "handle_get_sorafs_transparency_explorer",
        "handle_get_sorafs_transparency_token_issuances",
        "handle_get_sorafs_appeal_finance_reports",
        "handle_get_sorafs_appeal_finance_weekly_rollups",
        "handle_get_sorafs_appeal_finance_settlement_receipts",
        "handle_get_sorafs_governance_dag_car_queue",
        "handle_get_sorafs_governance_dag_car_queue_digest",
        "handle_get_sorafs_governance_dag_car_queue_kind",
        "handle_get_sorafs_governance_dag_car_queue_archive",
        "handle_get_sorafs_governance_dag_runtime",
        "handle_get_sorafs_governance_dag_runtime_head",
        "handle_get_sorafs_governance_dag_runtime_block",
        "handle_get_sorafs_governance_dag_runtime_node",
        "handle_get_sorafs_governance_dag_runtime_digest",
        "handle_get_sorafs_governance_dag_runtime_kind",
    ] {
        let marker = format!("pub(crate) async fn {handler_name}(");
        let start = source
            .find(&marker)
            .unwrap_or_else(|| panic!("missing file-backed handler `{handler_name}`"));
        let tail = &source[start..];
        let end = tail[marker.len()..]
            .find("\npub(crate) async fn ")
            .map_or(tail.len(), |offset| marker.len() + offset);
        assert!(
            tail[..end].contains("governance_dag_blocking_response("),
            "file-backed handler `{handler_name}` must use heavy admitted blocking I/O"
        );
    }
    let helper_start = source
        .find("async fn governance_dag_blocking_response")
        .expect("governance DAG blocking helper");
    let helper_end = source[helper_start..]
        .find("\nasync fn sorafs_heavy_blocking_task")
        .map(|offset| helper_start + offset)
        .expect("end of governance DAG blocking helper");
    let helper = &source[helper_start..helper_end];
    assert!(helper.contains("acquire_query_admission(state.as_ref(), true)"));
    assert!(helper.contains("crate::panic_recovery::join_recoverable("));
    let worker_start = helper
        .find("crate::panic_recovery::spawn_blocking_recoverable(move || {")
        .expect("file reads must run on the recoverable blocking worker");
    let worker = &helper[worker_start..];
    assert!(worker.contains("let _permit = permit;\n            operation(&state)"));
    let recovery_source = include_str!("../../panic_recovery.rs");
    let blocking_wrapper = recovery_source
        .split("pub fn spawn_blocking_recoverable")
        .nth(1)
        .and_then(|tail| tail.split("pub async fn catch_async_recoverable").next())
        .expect("blocking panic-recovery implementation");
    assert!(blocking_wrapper.contains("tokio::task::spawn_blocking(move ||"));
    assert!(blocking_wrapper.contains("catch_unwind_suppressed(operation)"));
}
#[test]
fn governance_dag_readback_cannot_reintroduce_path_based_file_reads() {
    let source = include_str!("../api.rs");
    let start = source
        .find("fn load_governance_dag_mirror_index")
        .expect("governance DAG loader region");
    let end = source[start..]
        .find("\nfn governance_dag_json_response")
        .map(|offset| start + offset)
        .expect("end of governance DAG readback region");
    let readback = &source[start..end];
    assert!(readback.contains(".read_governance_dag_file(relative, maximum)"));
    for forbidden in [
        "fs::read(",
        "fs::read_to_string(",
        "fs::canonicalize(",
        "fs::symlink_metadata(",
        "File::open(",
        "path.display().to_string()",
        "root.display().to_string()",
    ] {
        assert!(
            !readback.contains(forbidden),
            "governance DAG readback must not use path-based `{forbidden}`"
        );
    }
    let producer = include_str!("../../../../sorafs_node/src/governance.rs");
    assert!(producer.contains("const GOVERNANCE_DAG_LOGICAL_ROOT: &str = \".\";"));
    assert!(
        !producer.contains("JsonValue::from(root.display().to_string())"),
        "public Governance DAG indexes must not persist the host filesystem root"
    );
}
#[test]
fn sorafs_bounded_file_readbacks_stay_on_heavy_workers() {
    assert_eq!(MAX_LOCAL_MANIFEST_RESPONSE_BYTES, 16 * 1024 * 1024);
    assert_eq!(MAX_CAR_RANGE_PAYLOAD_BYTES, 8 * 1024 * 1024);
    assert_eq!(MAX_CAR_RANGE_RESPONSE_BYTES, 16 * 1024 * 1024);
    let source = include_str!("../api.rs");
    for (start_marker, end_marker, io_marker) in [
        (
            "pub(crate) async fn handle_get_sorafs_storage_manifest(",
            "pub(crate) async fn handle_get_sorafs_storage_plan(",
            ".load_manifest_bytes()",
        ),
        (
            "pub(crate) async fn handle_get_sorafs_storage_plan(",
            "pub(crate) async fn handle_get_sorafs_pin_registry(",
            ".load_manifest()",
        ),
        (
            "async fn build_site_file_response(",
            "pub(crate) async fn handle_get_sorafs_site_manifest(",
            ".read_payload_range(",
        ),
        (
            "pub(crate) async fn handle_get_sorafs_site_manifest(",
            "pub(crate) async fn handle_get_sorafs_site_root(",
            ".load_manifest_bytes()",
        ),
        (
            "pub(crate) async fn handle_get_sorafs_storage_car_range(",
            "pub(crate) async fn handle_get_sorafs_storage_chunk(",
            ".load_manifest()",
        ),
    ] {
        let start = source
            .find(start_marker)
            .unwrap_or_else(|| panic!("missing SoraFS handler `{start_marker}`"));
        let tail = &source[start..];
        let end = tail
            .find(end_marker)
            .unwrap_or_else(|| panic!("missing end marker `{end_marker}`"));
        let handler = &tail[..end];
        let worker = handler
            .find("sorafs_heavy_blocking_task(")
            .unwrap_or_else(|| {
                panic!("file-backed SoraFS handler `{start_marker}` is not offloaded")
            });
        let io = handler.find(io_marker).unwrap_or_else(|| {
            panic!("file-backed SoraFS handler `{start_marker}` lost `{io_marker}`")
        });
        assert!(
            worker < io,
            "file-backed SoraFS handler `{start_marker}` performs I/O before entering its heavy worker"
        );
    }
    let car_start = source
        .find("pub(crate) async fn handle_get_sorafs_storage_car_range(")
        .expect("CAR range handler");
    let car_end = source[car_start..]
        .find("pub(crate) async fn handle_get_sorafs_storage_chunk(")
        .map(|offset| car_start + offset)
        .expect("end of CAR range handler");
    let car_handler = &source[car_start..car_end];
    let worker = car_handler
        .find("sorafs_heavy_blocking_task(")
        .expect("CAR range heavy worker");
    assert!(
        car_handler
            .find(".read_payload_range(")
            .is_some_and(|read| worker < read),
        "CAR range payload reads must occur inside the heavy worker"
    );
    for forbidden in [
        "fs::read(stored.manifest_path())",
        "ChunkFilesReader",
        "StreamingBodyWriter",
        "validate_chunk_files_and_payload_digest",
        "tokio::sync::mpsc",
    ] {
        assert!(
            !car_handler.contains(forbidden),
            "CAR range handler must not reintroduce `{forbidden}`"
        );
    }
}
#[tokio::test]
async fn governance_dag_indexes_reject_unknown_host_path_fields() {
    const FORBIDDEN_PATH: &str = "/private/retained/governance/state";
    let (runtime_app, _temp, mut mirror, metadata, ..) = governance_mirror_fixture();
    mirror
        .as_object_mut()
        .expect("mirror index object")
        .insert("host_path".into(), Value::from(FORBIDDEN_PATH));
    let canonical = json::to_json_pretty(&mirror)
        .expect("encode mirror with unknown field")
        .into_bytes();
    let response = parse_governance_dag_mirror_index(&canonical, metadata)
        .expect_err("unknown mirror field must fail")
        .into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body_bytes = api_test_response_body(response).await;
    assert!(!String::from_utf8_lossy(&body_bytes).contains(FORBIDDEN_PATH));
    let runtime_snapshot = runtime_app
        .sorafs_node
        .governance_dag_runtime_snapshot()
        .expect("read typed runtime fixture")
        .expect("published runtime fixture");
    let mut runtime: Value =
        json::from_slice(runtime_snapshot.index_bytes()).expect("decode typed runtime fixture");
    runtime
        .get_mut("blocks")
        .and_then(Value::as_array_mut)
        .and_then(|blocks| blocks.first_mut())
        .and_then(Value::as_object_mut)
        .expect("first runtime block")
        .insert("host_path".into(), Value::from(FORBIDDEN_PATH));
    let response = match verify_and_bind_governance_dag_runtime_index(
        &runtime_app,
        &mut runtime,
        runtime_snapshot.head_bytes(),
    ) {
        Err(response) => response,
        Ok(_) => panic!("unknown runtime field must fail"),
    };
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body_bytes = api_test_response_body(response).await;
    assert!(!String::from_utf8_lossy(&body_bytes).contains(FORBIDDEN_PATH));
    let (publication_app, _temp, _digest, _archive) = sorafs_app_state_with_governance_car_queue();
    let mut state = read_publication_state_fixture(&publication_app);
    publication_state_section_mut(&mut state, "car_queue")
        .get_mut("segments")
        .and_then(Value::as_array_mut)
        .and_then(|segments| segments.first_mut())
        .and_then(Value::as_object_mut)
        .expect("first CAR queue segment")
        .insert("host_path".into(), Value::from(FORBIDDEN_PATH));
    let canonical = json::to_json_pretty(&state)
        .expect("encode publication state with unknown field")
        .into_bytes();
    let metadata = GovernanceDagSourceMetadata::new(
        GOVERNANCE_DAG_PUBLICATION_SOURCE_V1,
        (9, [0xC9; 32]),
        &canonical,
        None,
    );
    let response = match parse_governance_publication_state(&canonical, metadata) {
        Err(response) => response,
        Ok(_) => panic!("unknown CAR field must fail"),
    };
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body_bytes = api_test_response_body(response).await;
    assert!(!String::from_utf8_lossy(&body_bytes).contains(FORBIDDEN_PATH));
}
#[test]
fn governance_dag_pending_car_segment_cannot_hide_an_artifact_path() {
    let (app, _temp, _digest, car_archive_digest) = sorafs_app_state_with_governance_car_queue();
    let mut queue = read_publication_section_fixture(&app, "car_queue");
    let queue_object = queue.as_object_mut().expect("CAR queue object");
    let segment = queue_object
        .get_mut("segments")
        .and_then(Value::as_array_mut)
        .and_then(|segments| segments.first_mut())
        .and_then(Value::as_object_mut)
        .expect("first CAR queue segment");
    segment.insert("status".into(), Value::from("pending"));
    for field in [
        "car_path",
        "plan_path",
        "manifest_path",
        "car_size",
        "car_archive_blake3",
        "car_payload_blake3",
        "car_cid_hex",
        "root_cids_hex",
        "dag_codec",
        "chunk_count",
        "payload_bytes",
        "files",
        "chunk_profile",
    ] {
        segment.remove(field);
    }
    segment.insert(
        "car_path".into(),
        Value::from("/private/retained/substituted.car"),
    );
    queue_object.insert("assembled_count".into(), Value::from(1_u64));
    queue_object.insert("pending_count".into(), Value::from(1_u64));
    queue_object
        .get_mut("by_car_archive_blake3")
        .and_then(Value::as_object_mut)
        .expect("CAR archive lookup")
        .remove(&car_archive_digest);
    let response = validate_governance_dag_car_queue(&queue)
        .expect_err("pending segment cannot smuggle an artifact path");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
#[test]
fn public_conditional_etags_use_case_sensitive_http_entity_tags() {
    let etag = format!("\"{}\"", "ab".repeat(32));
    for matching in [etag.clone(), format!("W/{etag}"), "*".to_owned()] {
        let mut headers = HeaderMap::new();
        headers.insert(
            IF_NONE_MATCH,
            HeaderValue::from_str(&matching).expect("valid matching entity tag"),
        );
        assert!(
            if_none_match_matches(&headers, &etag),
            "valid conditional token did not match: {matching}"
        );
    }
    for non_matching in [
        etag.to_ascii_uppercase(),
        format!("\"{etag}\""),
        format!("{etag}, *"),
        format!("{etag},"),
        format!("w/{etag}"),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(
            IF_NONE_MATCH,
            HeaderValue::from_str(&non_matching).expect("visible conditional token"),
        );
        assert!(
            !if_none_match_matches(&headers, &etag),
            "malformed or nonmatching conditional token was accepted: {non_matching}"
        );
    }
}
#[test]
fn governance_source_etag_commits_record_and_checkpoint_identity() {
    let canonical_bytes = br#"{"schema":"fixture"}"#;
    let base = GovernanceDagSourceMetadata::new(
        GOVERNANCE_DAG_RUNTIME_SOURCE_V1,
        (7, [0x31; 32]),
        canonical_bytes,
        Some((11, [0x41; 32])),
    );
    let changed_record_generation = GovernanceDagSourceMetadata::new(
        GOVERNANCE_DAG_RUNTIME_SOURCE_V1,
        (8, [0x31; 32]),
        canonical_bytes,
        Some((11, [0x41; 32])),
    );
    let changed_record_digest = GovernanceDagSourceMetadata::new(
        GOVERNANCE_DAG_RUNTIME_SOURCE_V1,
        (7, [0x32; 32]),
        canonical_bytes,
        Some((11, [0x41; 32])),
    );
    let changed_checkpoint_generation = GovernanceDagSourceMetadata::new(
        GOVERNANCE_DAG_RUNTIME_SOURCE_V1,
        (7, [0x31; 32]),
        canonical_bytes,
        Some((12, [0x41; 32])),
    );
    let changed_checkpoint_revision = GovernanceDagSourceMetadata::new(
        GOVERNANCE_DAG_RUNTIME_SOURCE_V1,
        (7, [0x31; 32]),
        canonical_bytes,
        Some((11, [0x42; 32])),
    );
    let without_checkpoint = GovernanceDagSourceMetadata::new(
        GOVERNANCE_DAG_RUNTIME_SOURCE_V1,
        (7, [0x31; 32]),
        canonical_bytes,
        None,
    );
    for changed in [
        &changed_record_generation,
        &changed_record_digest,
        &changed_checkpoint_generation,
        &changed_checkpoint_revision,
        &without_checkpoint,
    ] {
        assert_ne!(base.etag, changed.etag);
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        IF_NONE_MATCH,
        HeaderValue::from_str(&base.etag).expect("valid typed-source entity tag"),
    );
    assert!(if_none_match_matches(&headers, &base.etag));
    assert!(
        !if_none_match_matches(&headers, &changed_checkpoint_revision.etag),
        "a stale conditional tag must not conceal changed checkpoint authentication metadata"
    );
}
#[tokio::test]
async fn governance_dag_dashboard_head_and_lookups_project_validated_mirror() {
    let (_app, _temp, index, metadata, block_cid_hex, node_cid_hex, head_block_cid_hex) =
        governance_mirror_fixture();
    let publisher_key = KeyPair::try_from_seed(
        b"torii-governance-runtime-provenance".to_vec(),
        Algorithm::Ed25519,
    )
    .expect("derive runtime provenance account");
    let publisher = AccountId::new(publisher_key.public_key().clone());
    let publisher_digest_hex =
        encode(sorafs_manifest::governance_dag_submission_account_digest_v1(&publisher.encode()));
    let response = governance_dag_dashboard_response_from_index(
        index.clone(),
        metadata.clone(),
        HeaderMap::new(),
    );
    assert_eq!(response.status(), StatusCode::OK);
    let dashboard_etag = response
        .headers()
        .get(ETAG)
        .cloned()
        .expect("dashboard etag");
    let body_bytes = api_test_response_body(response).await;
    let value: Value = json::from_slice(&body_bytes).expect("decode dashboard JSON");
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.governance_dag.dashboard.v1")
    );
    assert_governance_source_metadata(&value, GOVERNANCE_DAG_MIRROR_SOURCE_V1, true);
    assert_eq!(value.json_u64(&["block_count"]), Some(2));
    assert_eq!(value.json_u64(&["first_sequence"]), Some(0));
    assert!(is_current_wall_clock(value.json_u64(&["last_timestamp"])));

    let mut headers = HeaderMap::new();
    headers.insert(IF_NONE_MATCH, dashboard_etag.clone());
    let response =
        governance_dag_dashboard_response_from_index(index.clone(), metadata.clone(), headers);
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    let mut headers = HeaderMap::new();
    headers.insert(IF_NONE_MATCH, dashboard_etag.clone());
    let response =
        governance_dag_head_response_from_index(index.clone(), metadata.clone(), headers);
    assert_eq!(response.status(), StatusCode::OK);
    let head_etag = response.headers().get(ETAG).cloned().expect("head etag");
    assert_ne!(head_etag, dashboard_etag);
    let body_bytes = api_test_response_body(response).await;
    let value: Value = json::from_slice(&body_bytes).expect("decode head JSON");
    assert_governance_source_metadata(&value, GOVERNANCE_DAG_MIRROR_SOURCE_V1, true);
    assert_eq!(
        value.json_str(&["head", "head_block_cid_hex"]),
        Some(head_block_cid_hex.as_str())
    );
    let response = governance_dag_lookup_response_from_index(
        index.clone(),
        metadata.clone(),
        HeaderMap::new(),
        "block",
        "by_block_cid_hex",
        "sorafs.governance_dag.block.lookup.v1",
        block_cid_hex.clone(),
    );
    assert_eq!(response.status(), StatusCode::OK);
    let block_etag = response.headers().get(ETAG).cloned().expect("block etag");
    let body_bytes = api_test_response_body(response).await;
    let value: Value = json::from_slice(&body_bytes).expect("decode block JSON");
    assert_governance_source_metadata(&value, GOVERNANCE_DAG_MIRROR_SOURCE_V1, true);
    assert_eq!(
        value.json_str(&["block", "submission_publisher_account_digest_hex"]),
        Some(publisher_digest_hex.as_str())
    );
    let mut headers = HeaderMap::new();
    headers.insert(IF_NONE_MATCH, block_etag);
    let response = governance_dag_lookup_response_from_index(
        index.clone(),
        metadata.clone(),
        headers,
        "block",
        "by_block_cid_hex",
        "sorafs.governance_dag.block.lookup.v1",
        "ff".repeat(32),
    );
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = governance_dag_lookup_response_from_index(
        index,
        metadata,
        HeaderMap::new(),
        "node",
        "by_node_cid_hex",
        "sorafs.governance_dag.node.lookup.v1",
        node_cid_hex.clone(),
    );
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = api_test_response_body(response).await;
    let value: Value = json::from_slice(&body_bytes).expect("decode node JSON");
    assert_eq!(
        value.json_str(&["block", "node_cid_hex"]),
        Some(node_cid_hex.as_str())
    );
}
#[test]
fn governance_dag_mirror_rejects_history_not_ending_at_head() {
    let (_app, _temp, mut index, _metadata, ..) = governance_mirror_fixture();
    index
        .get_mut("blocks")
        .and_then(Value::as_array_mut)
        .expect("mirror blocks")
        .truncate(1);
    index
        .as_object_mut()
        .expect("mirror root")
        .insert("indexed_block_count".into(), Value::from(1_u64));
    let response = validate_governance_dag_mirror_index(&index)
        .expect_err("truncated mirror history must fail");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
#[test]
fn governance_dag_mirror_rejects_sequence_overflow() {
    let (_app, _temp, mut index, _metadata, ..) = governance_mirror_fixture();
    let blocks = index
        .get_mut("blocks")
        .and_then(Value::as_array_mut)
        .expect("mirror blocks");
    blocks[0]
        .as_object_mut()
        .expect("first mirror block")
        .insert("sequence".into(), Value::from(u64::MAX));
    blocks[1]
        .as_object_mut()
        .expect("second mirror block")
        .insert("sequence".into(), Value::from(0_u64));
    let response = validate_governance_dag_mirror_index(&index)
        .expect_err("overflowing mirror sequence continuity must fail closed");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
#[tokio::test]
async fn governance_dag_lookup_rejects_malformed_and_absent_capability() {
    let (app, _temp, index, metadata, ..) = governance_mirror_fixture();
    let response = handle_get_sorafs_governance_dag_block(
        State(app.clone()),
        HeaderMap::new(),
        Path("not-hex".to_owned()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = handle_get_sorafs_governance_dag_block(
        State(app.clone()),
        HeaderMap::new(),
        Path("ff".to_owned()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response =
        handle_get_sorafs_governance_dag_block(State(app), HeaderMap::new(), Path("ff".repeat(32)))
            .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "a node without an installed mirror capability must fail closed"
    );
    let response = governance_dag_lookup_response_from_index(
        index,
        metadata,
        HeaderMap::new(),
        "block",
        "by_block_cid_hex",
        "sorafs.governance_dag.block.lookup.v1",
        "ff".repeat(32),
    );
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
fn api_test_governance_request_public_key(seed: u8) -> [u8; 32] {
    let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .expect("derive Governance DAG request-auth public key");
    let (algorithm, bytes) = key_pair
        .public_key()
        .try_to_bytes()
        .expect("serialize Governance DAG request-auth public key");
    assert_eq!(algorithm, Algorithm::Ed25519);
    bytes.try_into().expect("Ed25519 public key width")
}
fn api_test_governance_ingress_qualification(
    scope: sorafs_node::GovernanceDagAuthenticationScope,
    endpoint: &str,
    seed: u8,
    provider: GovernanceDagRuntimeProviderQualificationV1,
    max_body_bytes: u64,
) -> GovernanceDagRequestIngressQualificationV1 {
    let binding = sorafs_node::GovernanceDagRequestIngressBindingV1::try_new(
        scope,
        sorafs_node::governance_dag_request_ingress_endpoint_binding_v1(scope, endpoint)
            .expect("derive canonical test request-ingress endpoint binding"),
        api_test_governance_request_public_key(seed),
        max_body_bytes,
        30,
        5,
    )
    .expect("construct canonical test request-ingress binding");
    let scope_tag = match scope {
        sorafs_node::GovernanceDagAuthenticationScope::Ipfs => 0x91,
        sorafs_node::GovernanceDagAuthenticationScope::SignedHead => 0x92,
    };
    GovernanceDagRequestIngressQualificationV1::try_new(
        provider,
        binding,
        [scope_tag; 32],
        [scope_tag.wrapping_add(1); 32],
        [scope_tag.wrapping_add(2); 32],
    )
    .expect("construct live test request-ingress qualification")
}
#[tokio::test]
async fn running_governance_dag_service_installs_authenticated_mirror_for_torii() {
    const IPFS_AUTH_HANDLE: &str = "provider:governance-dag:torii-api-ipfs-ingress";
    const HEAD_AUTH_HANDLE: &str = "provider:governance-dag:torii-api-head-ingress";
    const IPFS_AUTH_SEED: u8 = 0x61;
    const HEAD_AUTH_SEED: u8 = 0x62;
    let temp_dir = tempfile::tempdir().expect("create Governance DAG service temp dir");
    let temp_root = temp_dir
        .path()
        .canonicalize()
        .expect("canonicalize Governance DAG service temp dir");
    let governance_dir = temp_root.join("governance");
    let (mut node, signer, checkpoint_store) = node_with_test_governance_publisher_and_store(
        StorageConfig::builder()
            .enabled(true)
            .data_dir(temp_root.join("storage"))
            .governance_dir(Some(governance_dir.clone())),
        NodeRuntimeDeps::default(),
    );
    let publisher_key = KeyPair::try_from_seed(
        b"torii-running-governance-service-provenance".to_vec(),
        Algorithm::Ed25519,
    )
    .expect("derive Governance DAG publication provenance account");
    let publisher = AccountId::new(publisher_key.public_key().clone());
    node.publish_authenticated_appeal_finance_report(appeal_finance_report_fixture(), publisher)
        .expect("publish signed Governance DAG source block");
    let runtime_snapshot = node
        .governance_dag_runtime_snapshot()
        .expect("read signed local Governance DAG")
        .expect("signed local Governance DAG exists");
    let source_index: Value = json::from_slice(runtime_snapshot.index_bytes())
        .expect("decode signed local Governance DAG index");
    let expected_block_cid_hex = source_index
        .json_first_at(&["blocks"], &["block_cid_hex"])
        .and_then(Value::as_str)
        .expect("signed local Governance DAG block CID")
        .to_owned();
    let expected_head: GovernanceDagHeadV1 = decode_canonical_governance_dag_value(
        runtime_snapshot.head_bytes(),
        "signed local Governance DAG head",
    )
    .expect("decode signed local Governance DAG head");
    let expected_head_cid_hex = encode(expected_head.head_block_cid);
    let (publication_base, publication_state, publication_shutdown, publication_task) =
        spawn_api_test_governance_publication_http().await;
    let signed_head_url = format!("{publication_base}/head");
    let service = SorafsGovernanceDagService {
        enabled: true,
        state_dir: Some(temp_root.join("governance-service-state")),
        ipfs_api_url: Some(publication_base.clone()),
        signed_head_url: Some(signed_head_url.clone()),
        ipfs_authenticator_handle: Some(IPFS_AUTH_HANDLE.to_owned()),
        ipfs_authenticator_revision: Some(1),
        ipfs_authenticator_policy_digest: Some([0xA1; 32]),
        ipfs_request_auth_public_key: Some(api_test_governance_request_public_key(IPFS_AUTH_SEED)),
        head_authenticator_handle: Some(HEAD_AUTH_HANDLE.to_owned()),
        head_authenticator_revision: Some(1),
        head_authenticator_policy_digest: Some([0xA2; 32]),
        head_request_auth_public_key: Some(api_test_governance_request_public_key(HEAD_AUTH_SEED)),
        request_auth_max_envelope_lifetime_secs: 30,
        request_auth_max_future_skew_secs: 5,
        checkpoint_store_handle: Some(ApiTestGovernanceDagCheckpointStore::HANDLE.into()),
        checkpoint_store_revision: Some(
            ApiTestGovernanceDagCheckpointStore::expected_qualification().revision,
        ),
        checkpoint_store_policy_digest: Some(
            ApiTestGovernanceDagCheckpointStore::expected_qualification().policy_digest,
        ),
        publisher_public_key_hex: Some(hex::encode(signer.public_key())),
        poll_interval: Duration::from_secs(4),
        max_future_skew_secs: 100_000_000,
        allow_insecure_http: true,
        allow_private_ipfs_endpoint: true,
        allow_private_head_endpoint: true,
        allow_head_bootstrap: true,
        listen_addr: "127.0.0.1:0".to_owned(),
        ..Default::default()
    };
    let ipfs_provider_qualification =
        GovernanceDagRuntimeProviderQualificationV1::new(1, [0xA1; 32]);
    let head_provider_qualification =
        GovernanceDagRuntimeProviderQualificationV1::new(1, [0xA2; 32]);
    let ipfs_authenticator = ApiTestGovernanceRequestAuthenticator::new(
        IPFS_AUTH_HANDLE,
        IPFS_AUTH_SEED,
        api_test_governance_ingress_qualification(
            sorafs_node::GovernanceDagAuthenticationScope::Ipfs,
            &publication_base,
            IPFS_AUTH_SEED,
            ipfs_provider_qualification,
            sorafs_node::governance_service::authenticated_ipfs_wire_body_max_bytes(
                service.max_request_bytes.0,
            )
            .expect("derive authenticated IPFS wire-body ceiling"),
        ),
    );
    let head_authenticator = ApiTestGovernanceRequestAuthenticator::new(
        HEAD_AUTH_HANDLE,
        HEAD_AUTH_SEED,
        api_test_governance_ingress_qualification(
            sorafs_node::GovernanceDagAuthenticationScope::SignedHead,
            &signed_head_url,
            HEAD_AUTH_SEED,
            head_provider_qualification,
            service.max_request_bytes.0,
        ),
    );
    let view = SorafsGovernanceDagServiceView {
        source_dir: Some(governance_dir),
        producer_publisher_peer_id: Some(
            String::from_utf8(ApiTestGovernanceDagSigner::PEER_ID.to_vec())
                .expect("Governance DAG producer peer id is UTF-8"),
        ),
        producer_signer_handle: Some(ApiTestGovernanceDagSigner::HANDLE.to_owned()),
        producer_signer_revision: Some(
            ApiTestGovernanceDagSigner::expected_qualification().revision,
        ),
        producer_signer_policy_digest: Some(
            ApiTestGovernanceDagSigner::expected_qualification().policy_digest,
        ),
        producer_publisher_public_key_hex: Some(hex::encode(signer.public_key())),
        service,
    };
    let runner = prepare_governance_dag_service_from_view(
        view,
        GovernanceDagServiceRuntimeProviders::default()
            .with_ipfs_authenticator(ipfs_authenticator)
            .with_head_authenticator(head_authenticator)
            .with_checkpoint_store(checkpoint_store),
    )
    .await
    .expect("prepare real Governance DAG service");
    let mirror_reader = runner.mirror_read_handle();
    let (service_shutdown, service_shutdown_rx) = tokio::sync::oneshot::channel();
    let service_task = tokio::spawn(async move {
        Box::pin(runner.run_until(async move {
            let _ = service_shutdown_rx.await;
        }))
        .await
    });
    let mirror_snapshot = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            assert!(
                !service_task.is_finished(),
                "Governance DAG service exited before publishing its mirror"
            );
            match mirror_reader.read() {
                Ok(Some(snapshot)) => break snapshot,
                Ok(None) | Err(GovernanceDagServiceError::Unavailable(_)) => {}
                Err(GovernanceDagServiceError::State(message))
                    if message.contains("active sealed publish intent") => {}
                Err(error) => panic!("Governance DAG mirror failed authentication: {error}"),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Governance DAG service publishes an authenticated mirror");
    let mirror_store_identity = mirror_snapshot.mirror_store_identity();
    let checkpoint_identity = mirror_snapshot.checkpoint_identity();
    let mirror: Value = json::from_slice(mirror_snapshot.canonical_bytes())
        .expect("decode service-owned Governance DAG mirror");
    assert_eq!(
        mirror.json_str(&["head", "head_block_cid_hex"]),
        Some(expected_head_cid_hex.as_str())
    );
    let head_ipfs_cid = mirror
        .json_str(&["head", "ipfs_cid"])
        .expect("authenticated mirror head IPFS CID")
        .to_owned();
    let block_ipfs_cid = mirror
        .json_first_at(&["blocks"], &["ipfs_cid"])
        .and_then(Value::as_str)
        .expect("authenticated mirror block IPFS CID")
        .to_owned();
    assert!(
        publication_state
            .0
            .lock()
            .expect("lock Governance DAG publication state")
            .head
            .is_some(),
        "the running service must commit the public head before exposing the mirror"
    );
    node.install_governance_dag_mirror_read_handle(mirror_reader)
        .expect("install the real service-owned mirror capability into NodeHandle");
    let mut app = mk_app_state_for_tests();
    Arc::get_mut(&mut app)
        .expect("unique Torii app state")
        .sorafs_node = node;
    let response =
        handle_get_sorafs_governance_dag_head(State(app.clone()), HeaderMap::new()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = api_test_response_body(response).await;
    let response: Value =
        json::from_slice(&body_bytes).expect("decode Torii Governance DAG head response");
    assert_eq!(
        response.json_str(&["source"]),
        Some(GOVERNANCE_DAG_MIRROR_SOURCE_V1)
    );
    assert_eq!(
        response.json_u64(&["source_generation"]),
        Some(mirror_store_identity.0)
    );
    assert_eq!(
        response.json_str(&["source_record_blake3"]),
        Some(encode(mirror_store_identity.1).as_str())
    );
    assert_eq!(
        response.json_u64(&["source_checkpoint_generation"]),
        Some(checkpoint_identity.generation())
    );
    assert_eq!(
        response.json_str(&["source_checkpoint_revision"]),
        Some(encode(checkpoint_identity.revision()).as_str())
    );
    assert_eq!(
        response.json_str(&["head", "head_block_cid_hex"]),
        Some(expected_head_cid_hex.as_str())
    );
    let response = handle_get_sorafs_governance_dag_block(
        State(app.clone()),
        HeaderMap::new(),
        Path(expected_block_cid_hex.clone()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = api_test_response_body(response).await;
    let response: Value =
        json::from_slice(&body_bytes).expect("decode Torii Governance DAG block response");
    assert_eq!(
        response.json_str(&["block", "block_cid_hex"]),
        Some(expected_block_cid_hex.as_str())
    );
    assert_eq!(
        response.json_str(&["source_checkpoint_revision"]),
        Some(encode(checkpoint_identity.revision()).as_str())
    );
    {
        let mut state = publication_state
            .0
            .lock()
            .expect("lock Governance DAG publication state for pin loss");
        assert!(state.objects.remove(&head_ipfs_cid).is_some());
        assert!(state.objects.remove(&block_ipfs_cid).is_some());
        assert!(
            state.head.is_some(),
            "the public head remains committed while derived IPFS state is repaired"
        );
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let repaired = {
                let state = publication_state
                    .0
                    .lock()
                    .expect("lock Governance DAG publication repair state");
                state.objects.contains_key(&head_ipfs_cid)
                    && state.objects.contains_key(&block_ipfs_cid)
            };
            if repaired {
                break;
            }
            assert!(
                !service_task.is_finished(),
                "Governance DAG service exited before repairing lost IPFS objects"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("steady reconciliation repairs post-commit IPFS loss");
    service_shutdown
        .send(())
        .expect("request Governance DAG service shutdown");
    tokio::time::timeout(Duration::from_secs(5), service_task)
        .await
        .expect("Governance DAG service shuts down")
        .expect("join Governance DAG service")
        .expect("Governance DAG service exits cleanly");
    let response = handle_get_sorafs_governance_dag_head(State(app), HeaderMap::new()).await;
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "Torii must withdraw a retained mirror capability when its supervising service exits"
    );
    publication_shutdown
        .send(())
        .expect("request Governance DAG publication fixture shutdown");
    tokio::time::timeout(Duration::from_secs(5), publication_task)
        .await
        .expect("Governance DAG publication fixture shuts down")
        .expect("join Governance DAG publication fixture");
}
#[tokio::test]
async fn governance_dag_publish_index_and_lookups_read_local_index() {
    let (app, _temp_dir, digest_hex) = sorafs_app_state_with_governance_publish_index();
    let response = handle_get_sorafs_governance_dag_publish_index(
        State(app.clone()),
        HeaderMap::new(),
        axum::extract::RawQuery(None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let index_etag = response.headers().get(ETAG).cloned().expect("index etag");
    assert_eq!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some(GOVERNANCE_DAG_CACHE_CONTROL)
    );
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.governance_dag.publish_index.v1")
    );
    assert_governance_source_metadata(&value, GOVERNANCE_DAG_PUBLICATION_SOURCE_V1, false);
    assert_eq!(
        value.json_str(&["index", "root"]),
        Some(GOVERNANCE_DAG_LOGICAL_ROOT)
    );
    assert_eq!(value.json_u64(&["entry_count"]), Some(4));
    assert_eq!(value.json_u64(&["indexed_entry_count"]), Some(4));
    assert_eq!(value.json_u64(&["returned_entry_count"]), Some(4));
    assert_eq!(value.json_u64(&["limit"]), Some(DEFAULT_LIST_LIMIT as u64));
    assert_eq!(value.json_bool(&["truncated_entries"]), Some(false));
    assert_eq!(value.json_len(&["index", "entries"]), Some(4));
    assert_eq!(
        value
            .json_object(&["payload_kind_counts"])
            .and_then(|counts| counts.get(APPEAL_FINANCE_REPORT_KIND))
            .and_then(Value::as_u64),
        Some(1)
    );
    let response = handle_get_sorafs_governance_dag_publish_index(
        State(app.clone()),
        HeaderMap::new(),
        axum::extract::RawQuery(Some("limit=1".to_owned())),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let capped_etag = response.headers().get(ETAG).cloned().expect("capped etag");
    assert_ne!(index_etag, capped_etag);
    let value = api_test_response_json(response).await;
    assert_eq!(value.json_u64(&["entry_count"]), Some(4));
    assert_eq!(value.json_u64(&["indexed_entry_count"]), Some(4));
    assert_eq!(value.json_u64(&["returned_entry_count"]), Some(1));
    assert_eq!(value.json_u64(&["limit"]), Some(1));
    assert_eq!(value.json_bool(&["truncated_entries"]), Some(true));
    assert_eq!(value.json_len(&["index", "entries"]), Some(1));

    let mut headers = HeaderMap::new();
    headers.insert(IF_NONE_MATCH, index_etag.clone());
    let response = handle_get_sorafs_governance_dag_publish_index(
        State(app.clone()),
        headers,
        axum::extract::RawQuery(None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(response.headers().get(ETAG), Some(&index_etag));
    let response = handle_get_sorafs_governance_dag_publish_digest(
        State(app.clone()),
        HeaderMap::new(),
        Path(format!("hex:{digest_hex}")),
        axum::extract::RawQuery(None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let digest_lookup_etag = response
        .headers()
        .get(ETAG)
        .cloned()
        .expect("digest lookup etag");
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.governance_dag.publish_index.digest.lookup.v1")
    );
    assert_eq!(value.json_u64(&["count"]), Some(1));
    assert_eq!(
        value
            .json_first_at(&["entries"], &["payload_kind"])
            .and_then(Value::as_str),
        Some(APPEAL_FINANCE_REPORT_KIND)
    );
    let mut headers = HeaderMap::new();
    headers.insert(IF_NONE_MATCH, digest_lookup_etag.clone());
    let response = handle_get_sorafs_governance_dag_publish_kind(
        State(app.clone()),
        headers,
        Path(APPEAL_FINANCE_REPORT_KIND.to_string()),
        axum::extract::RawQuery(None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_ne!(response.headers().get(ETAG), Some(&digest_lookup_etag));
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.governance_dag.publish_index.kind.lookup.v1")
    );
    assert_eq!(
        value
            .json_first_at(&["entries"], &["encoded_blake3"])
            .and_then(Value::as_str),
        Some(digest_hex.as_str())
    );
    let mut headers = HeaderMap::new();
    headers.insert(IF_NONE_MATCH, digest_lookup_etag);
    let response = handle_get_sorafs_governance_dag_publish_digest(
        State(app),
        headers,
        Path(format!("hex:{}", "ff".repeat(32))),
        axum::extract::RawQuery(None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn transparency_proof_token_verify_accepts_signature_and_digest() {
    let signing = SigningKey::from_bytes(&[0x47; 32]);
    let verifying = signing.verifying_key();
    let digest_key = ProofTokenDigestKey::new([0x22; 32]);
    let evidence_digest = [0x44; 32];
    let entries = ["denylist/global"];
    let issued_at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires_at = issued_at + Duration::from_secs(600);
    let mut rng = FixedProofTokenRng { byte: 0xA7 };
    let token = ProofToken::mint(
        &mut rng,
        &digest_key,
        &signing,
        &iroha_crypto::sorafs::proof_token::ProofTokenParams {
            moderation: ProofTokenModerationAction::Block,
            entry_ids: &entries,
            evidence_digest: &evidence_digest,
            issued_at,
            expires_at: Some(expires_at),
        },
    )
    .expect("mint proof token");
    let request = TransparencyProofTokenVerifyRequestDto {
        token_b64: token.encode_base64(),
        verifying_key_hex: hex::encode(verifying.to_bytes()),
        evidence_digest_hex: Some(hex::encode(evidence_digest)),
        digest_key_hex: Some(hex::encode([0x22; 32])),
        now_unix: Some(1_700_000_120),
    };
    let app = mk_app_state_for_tests();
    let response = handle_post_sorafs_transparency_token_verify(
        State(app),
        HeaderMap::new(),
        ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        JsonOnly(request),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.transparency.proof_token_verification.v1")
    );
    assert_eq!(value.json_bool(&["valid"]), Some(true));
    assert_eq!(value.json_bool(&["signature_valid"]), Some(true));
    assert_eq!(value.json_bool(&["digest_checked"]), Some(true));
    assert_eq!(value.json_bool(&["digest_valid"]), Some(true));
    assert_eq!(
        value.json_first(&["entry_ids"]).and_then(Value::as_str),
        Some("denylist/global")
    );
    assert_eq!(value.json_str(&["moderation_action"]), Some("block"));
}
#[tokio::test]
async fn transparency_proof_token_verify_reports_invalid_inputs() {
    let signing = SigningKey::from_bytes(&[0x47; 32]);
    let wrong_signing = SigningKey::from_bytes(&[0x48; 32]);
    let digest_key = ProofTokenDigestKey::new([0x22; 32]);
    let evidence_digest = [0x44; 32];
    let entries = ["denylist/global"];
    let issued_at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let mut rng = FixedProofTokenRng { byte: 0xA8 };
    let token = ProofToken::mint(
        &mut rng,
        &digest_key,
        &signing,
        &iroha_crypto::sorafs::proof_token::ProofTokenParams {
            moderation: ProofTokenModerationAction::Quarantine,
            entry_ids: &entries,
            evidence_digest: &evidence_digest,
            issued_at,
            expires_at: None,
        },
    )
    .expect("mint proof token");
    let request = TransparencyProofTokenVerifyRequestDto {
        token_b64: token.encode_base64(),
        verifying_key_hex: hex::encode(wrong_signing.verifying_key().to_bytes()),
        evidence_digest_hex: Some(hex::encode([0x45; 32])),
        digest_key_hex: Some(hex::encode([0x22; 32])),
        now_unix: Some(1_700_000_120),
    };
    let app = mk_app_state_for_tests();
    let response = handle_post_sorafs_transparency_token_verify(
        State(app.clone()),
        HeaderMap::new(),
        ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        JsonOnly(request),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = api_test_response_json(response).await;
    assert_eq!(value.json_bool(&["valid"]), Some(false));
    assert_eq!(value.json_bool(&["signature_valid"]), Some(false));
    assert_eq!(value.json_bool(&["digest_valid"]), Some(false));

    let request = TransparencyProofTokenVerifyRequestDto {
        token_b64: token.encode_base64(),
        verifying_key_hex: hex::encode(signing.verifying_key().to_bytes()),
        evidence_digest_hex: None,
        digest_key_hex: Some(hex::encode([0x22; 32])),
        now_unix: Some(1_700_000_120),
    };
    let response = handle_post_sorafs_transparency_token_verify(
        State(app.clone()),
        HeaderMap::new(),
        ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        JsonOnly(request),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let request = TransparencyProofTokenVerifyRequestDto {
        token_b64: token.encode_base64(),
        verifying_key_hex: hex::encode([0u8; 32]),
        evidence_digest_hex: None,
        digest_key_hex: None,
        now_unix: Some(1_700_000_120),
    };
    let response = handle_post_sorafs_transparency_token_verify(
        State(app),
        HeaderMap::new(),
        ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        JsonOnly(request),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
#[tokio::test]
async fn transparency_proof_token_verify_rejects_noncanonical_verifying_key() {
    const ED25519_NONCANONICAL_IDENTITY: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    let mut request = valid_transparency_proof_token_verify_request(0xA9);
    request.verifying_key_hex = hex::encode(ED25519_NONCANONICAL_IDENTITY);
    let app = mk_app_state_for_tests();
    let response = handle_post_sorafs_transparency_token_verify(
        State(app),
        HeaderMap::new(),
        ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        JsonOnly(request),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body_bytes = api_test_response_body(response).await;
    let body_text = String::from_utf8_lossy(&body_bytes);
    assert!(
        body_text.contains("non-canonical ed25519 public key encoding"),
        "unexpected proof-token verification error body: {body_text}"
    );
}
#[tokio::test]
async fn transparency_proof_token_verify_uses_proof_rate_limiter() {
    let mut app = mk_app_state_for_tests();
    {
        let state = Arc::get_mut(&mut app).expect("unique app state");
        state.proof_rate_limiter = crate::limits::RateLimiter::new(Some(1), Some(1));
        state.proof_limits.retry_after = Duration::from_secs(7);
    }
    let first = handle_post_sorafs_transparency_token_verify(
        State(app.clone()),
        HeaderMap::new(),
        ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        JsonOnly(valid_transparency_proof_token_verify_request(0xA9)),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = handle_post_sorafs_transparency_token_verify(
        State(app),
        HeaderMap::new(),
        ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        JsonOnly(valid_transparency_proof_token_verify_request(0xAA)),
    )
    .await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        second
            .headers()
            .get(RETRY_AFTER)
            .and_then(|h| h.to_str().ok()),
        Some("7")
    );
}
#[tokio::test]
async fn transparency_proof_token_verify_honors_api_token_enforcement() {
    let mut app = mk_app_state_for_tests();
    {
        let state = Arc::get_mut(&mut app).expect("unique app state");
        state.require_api_token = true;
        state.api_token_digests =
            Arc::new(crate::limits::ApiTokenDigestSet::from_tokens(["secret"]));
    }
    let denied = handle_post_sorafs_transparency_token_verify(
        State(app.clone()),
        HeaderMap::new(),
        ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        JsonOnly(valid_transparency_proof_token_verify_request(0xAB)),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let mut headers = HeaderMap::new();
    headers.insert("x-api-token", HeaderValue::from_static("secret"));
    let allowed = handle_post_sorafs_transparency_token_verify(
        State(app),
        headers,
        ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))),
        JsonOnly(valid_transparency_proof_token_verify_request(0xAC)),
    )
    .await;
    assert_eq!(allowed.status(), StatusCode::OK);
}
#[tokio::test]
async fn transparency_proof_token_issuance_endpoint_requires_canonical_request_auth() {
    let (app, _temp_dir, _auth) = sorafs_app_state_with_appeal_finance_governance_publisher();
    let body = proof_token_issuance_body(transparency_proof_token_issuance_request(0xAD));
    let response = handle_post_sorafs_transparency_token_issuance(
        State(app),
        HeaderMap::new(),
        Method::POST,
        Uri::from_static(TRANSPARENCY_PROOF_TOKEN_ISSUANCES_ROUTE),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn transparency_proof_token_issuance_endpoint_requires_source_publisher_role() {
    let (app, _temp_dir, auth) = sorafs_app_state_with_appeal_finance_governance_publisher();
    let body = proof_token_issuance_body(transparency_proof_token_issuance_request(0xAD));
    let response = post_transparency_proof_token_issuance(app.clone(), &auth.buyer, body).await;
    assert_forbidden_role(response, SORAFS_TRANSPARENCY_SOURCE_PUBLISHER_ROLE).await;
    assert_eq!(app.sorafs_node.pending_governance_publication_count(), 0);
}
#[tokio::test]
async fn transparency_proof_token_issuance_endpoint_publishes_signed_frame() {
    let (app, _temp_dir, auth) = sorafs_app_state_with_appeal_finance_governance_publisher();
    let request = transparency_proof_token_issuance_request(0xAE);
    let signer_key_hex = request.signer_key_hex.clone();
    let response = post_transparency_proof_token_issuance(
        app.clone(),
        &auth.provider,
        proof_token_issuance_body(request),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.transparency.proof_token_issuance.ingest.v1")
    );
    assert_eq!(
        value.json_str(&["publication_status"]),
        Some("published_to_local_governance_dag")
    );
    assert_eq!(
        value.json_str(&["signer_key_hex"]),
        Some(signer_key_hex.as_str())
    );
    assert_eq!(value.json_u64(&["entry_count"]), Some(2));
    assert_eq!(
        value
            .json_object(&["metadata"])
            .and_then(|metadata| metadata.get("feed"))
            .and_then(Value::as_str),
        Some("torii")
    );
    assert_governance_publish_provenance(
        &app,
        PROOF_TOKEN_ISSUANCE_KIND,
        &auth.provider.account,
        "transparency_token_issuance",
    );
    let response = handle_get_sorafs_transparency_token_issuances(
        State(app),
        HeaderMap::new(),
        axum::extract::RawQuery(None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = api_test_response_json(response).await;
    assert_eq!(value.json_u64(&["published_token_count"]), Some(1));
    assert_eq!(value.json_u64(&["distinct_signer_count"]), Some(1));
    assert_eq!(
        value
            .json_first_at(&["entries"], &["labels", "signer_key_hex"])
            .and_then(Value::as_str),
        Some(signer_key_hex.as_str())
    );
}
#[tokio::test]
async fn transparency_proof_token_issuance_endpoint_rejects_bad_signer() {
    let (app, _temp_dir, auth) = sorafs_app_state_with_appeal_finance_governance_publisher();
    let mut request = transparency_proof_token_issuance_request(0xAF);
    let wrong_signing = SigningKey::from_bytes(&[0x48; 32]);
    request.signer_key_hex = hex::encode(wrong_signing.verifying_key().to_bytes());
    let response = post_transparency_proof_token_issuance(
        app,
        &auth.provider,
        proof_token_issuance_body(request),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
#[tokio::test]
async fn transparency_cycle_api_reads_and_verifies_local_publication() {
    let (app, _temp_dir, cycle_id_hex, entry_id_hex, digest_hex) =
        sorafs_app_state_with_transparency_publication();
    let response = handle_get_sorafs_transparency_cycles(
        State(app.clone()),
        HeaderMap::new(),
        axum::extract::RawQuery(None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let etag = response.headers().get(ETAG).cloned().expect("cycles etag");
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.transparency.cycles.v1")
    );
    assert_eq!(value.json_u64(&["published_cycle_count"]), Some(1));
    assert_eq!(value.json_u64(&["returned_cycle_count"]), Some(1));
    assert_eq!(value.json_u64(&["limit"]), Some(50));
    assert_eq!(value.json_bool(&["truncated"]), Some(false));
    assert_eq!(
        value
            .json_first_at(&["cycles"], &["cycle_id_hex"])
            .and_then(Value::as_str),
        Some(cycle_id_hex.as_str())
    );
    let mut headers = HeaderMap::new();
    headers.insert(IF_NONE_MATCH, etag.clone());
    let response = handle_get_sorafs_transparency_cycles(
        State(app.clone()),
        headers,
        axum::extract::RawQuery(None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(response.headers().get(ETAG), Some(&etag));
    let mut headers = HeaderMap::new();
    headers.insert(IF_NONE_MATCH, etag.clone());
    let response = handle_get_sorafs_transparency_cycle(
        State(app.clone()),
        headers,
        Path(format!("hex:{cycle_id_hex}")),
        axum::extract::RawQuery(None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cycle_etag = response.headers().get(ETAG).cloned().expect("cycle etag");
    assert_ne!(cycle_etag, etag);
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.transparency.cycle_publication.v1")
    );
    assert_eq!(
        value.json_str(&["cycle_id_hex"]),
        Some(cycle_id_hex.as_str())
    );
    assert_eq!(
        value.json_str(&["encoded_blake3"]),
        Some(digest_hex.as_str())
    );
    assert_eq!(value.json_bool(&["verification", "valid"]), Some(true));
    assert_eq!(value.json_u64(&["verification", "proof_count"]), Some(2));
    assert_eq!(value.json_u64(&["proof_count"]), Some(2));
    assert_eq!(value.json_u64(&["returned_proof_count"]), Some(2));
    assert_eq!(value.json_u64(&["limit"]), Some(50));
    assert_eq!(value.json_bool(&["truncated_proofs"]), Some(false));

    let response = handle_get_sorafs_transparency_cycle(
        State(app.clone()),
        HeaderMap::new(),
        Path(cycle_id_hex.clone()),
        axum::extract::RawQuery(Some("limit=1".to_owned())),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = api_test_response_json(response).await;
    assert_eq!(value.json_u64(&["proof_count"]), Some(2));
    assert_eq!(value.json_u64(&["returned_proof_count"]), Some(1));
    assert_eq!(value.json_u64(&["limit"]), Some(1));
    assert_eq!(value.json_bool(&["truncated_proofs"]), Some(true));
    let proofs = value
        .json_array(&["publication", "proofs"])
        .expect("bounded publication proofs");
    assert_eq!(proofs.len(), 1);
    assert_eq!(value.json_u64(&["verification", "proof_count"]), Some(2));

    let mut headers = HeaderMap::new();
    headers.insert(IF_NONE_MATCH, cycle_etag);
    let response = handle_get_sorafs_transparency_cycle_entry(
        State(app.clone()),
        headers,
        Path((cycle_id_hex.clone(), entry_id_hex.clone())),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let entry_etag = response.headers().get(ETAG).cloned().expect("entry etag");
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.transparency.entry_proof.v1")
    );
    assert_eq!(
        value.json_str(&["entry_id_hex"]),
        Some(entry_id_hex.as_str())
    );
    assert!(value.get("proof").is_some());
    assert_eq!(
        value.json_bool(&["verification", "all_proofs_verified"]),
        Some(true)
    );
    let mut headers = HeaderMap::new();
    headers.insert(IF_NONE_MATCH, entry_etag);
    let response = handle_get_sorafs_transparency_cycle_entry(
        State(app),
        headers,
        Path((cycle_id_hex, "ff".repeat(16))),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn transparency_cycle_api_rejects_bad_ids_missing_entries_and_path_escape() {
    let (app, temp_dir, cycle_id_hex, _entry_id_hex, _digest_hex) =
        sorafs_app_state_with_transparency_publication();
    let response = handle_get_sorafs_transparency_cycle(
        State(app.clone()),
        HeaderMap::new(),
        Path("abcd".to_string()),
        axum::extract::RawQuery(None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = handle_get_sorafs_transparency_cycle_entry(
        State(app.clone()),
        HeaderMap::new(),
        Path((cycle_id_hex.clone(), "ff".repeat(16))),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let governance_dir = temp_dir.path().join("governance");
    let mut index = read_publication_section_fixture(&app, "publish_index");
    let response = handle_get_sorafs_transparency_cycles(
        State(app.clone()),
        HeaderMap::new(),
        axum::extract::RawQuery(None),
    )
    .await;
    let etag = response
        .headers()
        .get(ETAG)
        .cloned()
        .expect("transparency cycle etag");
    let encoded_path = index
        .json_first_at(&["entries"], &["encoded_path"])
        .and_then(Value::as_str)
        .expect("encoded path")
        .to_owned();
    fs::write(governance_dir.join(encoded_path), b"tampered transparency")
        .expect("tamper encoded publication");
    let mut headers = HeaderMap::new();
    headers.insert(IF_NONE_MATCH, etag);
    let response = handle_get_sorafs_transparency_cycle(
        State(app.clone()),
        headers,
        Path(cycle_id_hex.clone()),
        axum::extract::RawQuery(None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let entries = index
        .get_mut("entries")
        .and_then(Value::as_array_mut)
        .expect("entries");
    let entry = entries[0].as_object_mut().expect("entry object");
    entry.insert("encoded_path".into(), Value::from("../escape.to"));
    let response = validate_governance_dag_publish_index(&index)
        .expect_err("escaping typed publication path must fail");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
