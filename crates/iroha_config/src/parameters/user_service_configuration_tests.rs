// Service configuration tests included in duration_clamp_tests.
#[test]
fn sorafs_publish_discovery_defaults_empty() {
    let actual = load_root(base_table());
    assert!(
        actual
            .torii
            .sorafs_discovery
            .publish
            .gateway_base_url
            .is_none()
    );
    assert!(
        actual
            .torii
            .sorafs_discovery
            .publish
            .pin_torii_urls
            .is_empty()
    );
}
#[test]
fn sorafs_publish_discovery_config_parses() {
    let mut table = base_table();
    let sorafs: Table = toml::from_str(
        r#"
[discovery.publish]
gateway_base_url = "https://taira.sora.org"
pin_torii_urls = [
  "https://taira-validator-1.sora.org",
  "https://taira-validator-2.sora.org",
]
"#,
    )
    .expect("parse sorafs publish discovery");
    table.insert("sorafs".into(), Value::Table(sorafs));
    let actual = load_root(table);
    let publish = actual.torii.sorafs_discovery.publish;
    assert_eq!(
        publish
            .gateway_base_url
            .as_ref()
            .map(actual::SorafsPublishBaseUrl::as_str),
        Some("https://taira.sora.org")
    );
    assert_eq!(
        publish
            .pin_torii_urls
            .iter()
            .map(actual::SorafsPublishBaseUrl::as_str)
            .collect::<Vec<_>>(),
        [
            "https://taira-validator-1.sora.org",
            "https://taira-validator-2.sora.org"
        ]
    );
}
#[test]
fn sorafs_gateway_rejects_all_removed_local_denylist_keys() {
    let removed_keys = [
        ("path", Value::String("./denylist.json".to_owned())),
        (
            "catalog_path",
            Value::String("./denylist-catalog.json".to_owned()),
        ),
        (
            "opt_out_packs",
            Value::Array(vec![Value::String("regional-pack".to_owned())]),
        ),
        (
            "extra_packs",
            Value::Array(vec![Value::String("local-pack".to_owned())]),
        ),
        ("jurisdiction", Value::String("ae".to_owned())),
        ("standard_ttl", Value::String("180d".to_owned())),
        ("emergency_ttl", Value::String("30d".to_owned())),
        ("emergency_review_window", Value::String("7d".to_owned())),
        ("require_governance_reference", Value::Boolean(true)),
    ];
    for (removed_key, removed_value) in removed_keys {
        let mut table = base_table();
        let mut denylist = Table::new();
        denylist.insert(removed_key.to_owned(), removed_value);
        let mut gateway = Table::new();
        gateway.insert("denylist".to_owned(), Value::Table(denylist));
        let mut sorafs = Table::new();
        sorafs.insert("gateway".to_owned(), Value::Table(gateway));
        table.insert("sorafs".to_owned(), Value::Table(sorafs));
        let error = actual::Root::from_toml_source(TomlSource::inline(table))
            .expect_err("removed local gateway denylist key must not parse");
        let report = format!("{error:?}");
        assert!(
            report.contains("denylist"),
            "removed sorafs.gateway.denylist.{removed_key} produced an unrelated error: {report}"
        );
    }
}
#[test]
fn sorafs_storage_rejects_removed_local_orderbook_policy() {
    let mut table = base_table();
    let sorafs: Table = toml::from_str(
        r#"
[storage.orderbook]
min_order_gib = 0
price_tick = "0"
"#,
    )
    .expect("parse sorafs orderbook policy");
    table.insert("sorafs".into(), Value::Table(sorafs));
    assert!(
        std::panic::catch_unwind(|| load_root(table)).is_err(),
        "removed process-local orderbook policy must not be accepted"
    );
}
fn assert_orderbook_workers_eq(
    actual: actual::SorafsOrderbookWorker,
    expected: actual::SorafsOrderbookWorker,
) {
    assert_eq!(actual.enabled, expected.enabled);
    assert_eq!(actual.scan_interval, expected.scan_interval);
    assert_eq!(actual.match_batch_limit, expected.match_batch_limit);
    assert_eq!(
        actual.maintenance_batch_limit,
        expected.maintenance_batch_limit
    );
    assert_eq!(actual.max_pending, expected.max_pending);
    assert_eq!(actual.max_completed, expected.max_completed);
    assert_eq!(actual.max_dead_letters, expected.max_dead_letters);
    assert_eq!(actual.max_attempts, expected.max_attempts);
    assert_eq!(
        actual.checkpoint_max_bytes.0,
        expected.checkpoint_max_bytes.0
    );
}
#[test]
fn sorafs_orderbook_worker_defaults_are_operational_only_and_bounded() {
    use defaults::sorafs::storage::orderbook_worker as worker_defaults;
    let worker = load_root(base_table())
        .torii
        .sorafs_storage
        .orderbook_worker;
    assert_orderbook_workers_eq(worker, actual::SorafsOrderbookWorker::default());
    assert!(!worker.enabled);
    assert_eq!(
        worker.scan_interval,
        Duration::from_millis(worker_defaults::SCAN_INTERVAL_MS.get())
    );
    assert!(worker.match_batch_limit <= ORDERBOOK_MAX_FILLS_PER_EXECUTION_V1);
    assert!(worker.maintenance_batch_limit <= ORDERBOOK_MAX_MAINTENANCE_ITEMS_V1);
    assert!(worker.max_pending <= worker_defaults::MAX_PENDING_LIMIT);
    assert!(worker.max_completed <= worker_defaults::MAX_COMPLETED_LIMIT);
    assert!(worker.max_dead_letters <= worker_defaults::MAX_DEAD_LETTERS_LIMIT);
    assert!(worker.max_attempts <= worker_defaults::MAX_ATTEMPTS_LIMIT);
    assert!(
        (worker_defaults::CHECKPOINT_MIN_BYTES..=worker_defaults::CHECKPOINT_MAX_BYTES_LIMIT)
            .contains(&worker.checkpoint_max_bytes.0)
    );
}
#[test]
fn sorafs_orderbook_worker_accepts_exact_resource_boundaries_without_storage_provider() {
    use defaults::sorafs::storage::orderbook_worker as worker_defaults;
    let mut table = base_table();
    let mut source = format!(
        r"
[storage]
enabled = false

[storage.orderbook_worker]
enabled = true
scan_interval_ms = {}
match_batch_limit = {}
maintenance_batch_limit = {}
max_pending = {}
max_completed = {}
max_dead_letters = {}
max_attempts = {}
checkpoint_max_bytes = {}
",
        worker_defaults::SCAN_INTERVAL_MIN_MS,
        ORDERBOOK_MAX_FILLS_PER_EXECUTION_V1,
        ORDERBOOK_MAX_MAINTENANCE_ITEMS_V1,
        worker_defaults::MAX_PENDING_LIMIT,
        worker_defaults::MAX_COMPLETED_LIMIT,
        worker_defaults::MAX_DEAD_LETTERS_LIMIT,
        worker_defaults::MAX_ATTEMPTS_LIMIT,
        worker_defaults::CHECKPOINT_MIN_BYTES,
    );
    source.push_str(&native_signer_binding_toml(
        "orderbook",
        "orderbook",
        "resource-boundary",
        0x71,
    ));
    let sorafs: Table = toml::from_str(&source).expect("parse bounded orderbook worker policy");
    table.insert("sorafs".into(), Value::Table(sorafs));
    let storage = load_root(table).torii.sorafs_storage;
    assert!(!storage.enabled);
    assert_orderbook_workers_eq(
        storage.orderbook_worker,
        actual::SorafsOrderbookWorker {
            enabled: true,
            scan_interval: Duration::from_millis(worker_defaults::SCAN_INTERVAL_MIN_MS),
            match_batch_limit: ORDERBOOK_MAX_FILLS_PER_EXECUTION_V1,
            maintenance_batch_limit: ORDERBOOK_MAX_MAINTENANCE_ITEMS_V1,
            max_pending: worker_defaults::MAX_PENDING_LIMIT,
            max_completed: worker_defaults::MAX_COMPLETED_LIMIT,
            max_dead_letters: worker_defaults::MAX_DEAD_LETTERS_LIMIT,
            max_attempts: worker_defaults::MAX_ATTEMPTS_LIMIT,
            checkpoint_max_bytes: Bytes(worker_defaults::CHECKPOINT_MIN_BYTES),
        },
    );
}
#[test]
fn sorafs_orderbook_worker_rejects_zero_and_excessive_resource_bounds() {
    use defaults::sorafs::storage::orderbook_worker as worker_defaults;
    let invalid_fields = [
        "scan_interval_ms = 0".to_owned(),
        format!(
            "scan_interval_ms = {}",
            worker_defaults::SCAN_INTERVAL_MIN_MS - 1
        ),
        format!(
            "scan_interval_ms = {}",
            worker_defaults::SCAN_INTERVAL_MAX_MS + 1
        ),
        format!(
            "match_batch_limit = {}",
            ORDERBOOK_MAX_FILLS_PER_EXECUTION_V1 + 1
        ),
        format!(
            "maintenance_batch_limit = {}",
            ORDERBOOK_MAX_MAINTENANCE_ITEMS_V1 + 1
        ),
        format!("max_pending = {}", worker_defaults::MAX_PENDING_LIMIT + 1),
        format!(
            "max_completed = {}",
            worker_defaults::MAX_COMPLETED_LIMIT + 1
        ),
        format!(
            "max_dead_letters = {}",
            worker_defaults::MAX_DEAD_LETTERS_LIMIT + 1
        ),
        format!("max_attempts = {}", worker_defaults::MAX_ATTEMPTS_LIMIT + 1),
        format!(
            "checkpoint_max_bytes = {}",
            worker_defaults::CHECKPOINT_MIN_BYTES - 1
        ),
        format!(
            "checkpoint_max_bytes = {}",
            worker_defaults::CHECKPOINT_MAX_BYTES_LIMIT + 1
        ),
    ];
    for invalid_field in invalid_fields {
        let mut table = base_table();
        let sorafs: Table =
            toml::from_str(&format!("[storage.orderbook_worker]\n{invalid_field}\n"))
                .expect("parse invalid orderbook worker fixture");
        table.insert("sorafs".into(), Value::Table(sorafs));
        assert!(
            actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
            "accepted invalid orderbook worker field: {invalid_field}"
        );
    }
}
fn assert_reserve_workers_eq(
    actual: actual::SorafsReserveWorker,
    expected: actual::SorafsReserveWorker,
) {
    assert_eq!(actual.enabled, expected.enabled);
    assert_eq!(actual.scan_interval, expected.scan_interval);
    assert_eq!(actual.scan_batch_limit, expected.scan_batch_limit);
    assert_eq!(actual.max_pending, expected.max_pending);
    assert_eq!(actual.max_completed, expected.max_completed);
    assert_eq!(actual.max_dead_letters, expected.max_dead_letters);
    assert_eq!(actual.max_attempts, expected.max_attempts);
    assert_eq!(
        actual.checkpoint_max_bytes.0,
        expected.checkpoint_max_bytes.0
    );
}
#[test]
fn sorafs_reserve_worker_defaults_are_operational_only_and_bounded() {
    use defaults::sorafs::storage::reserve_worker as worker_defaults;
    let worker = load_root(base_table()).torii.sorafs_storage.reserve_worker;
    assert_reserve_workers_eq(worker, actual::SorafsReserveWorker::default());
    assert!(!worker.enabled);
    assert_eq!(
        worker.scan_interval,
        Duration::from_millis(worker_defaults::SCAN_INTERVAL_MS.get())
    );
    assert!(worker.scan_batch_limit <= worker_defaults::SCAN_BATCH_LIMIT_MAX);
    assert!(worker.max_pending <= worker_defaults::MAX_PENDING_LIMIT);
    assert!(worker.max_completed <= worker_defaults::MAX_COMPLETED_LIMIT);
    assert!(worker.max_dead_letters <= worker_defaults::MAX_DEAD_LETTERS_LIMIT);
    assert!(worker.max_attempts <= worker_defaults::MAX_ATTEMPTS_LIMIT);
    assert!(
        (worker_defaults::CHECKPOINT_MIN_BYTES..=worker_defaults::CHECKPOINT_MAX_BYTES_LIMIT)
            .contains(&worker.checkpoint_max_bytes.0)
    );
}
#[test]
fn sorafs_reserve_worker_accepts_exact_resource_boundaries_without_storage_provider() {
    use defaults::sorafs::storage::reserve_worker as worker_defaults;
    let mut table = base_table();
    let mut source = format!(
        r"
[storage]
enabled = false

[storage.reserve_worker]
enabled = true
scan_interval_ms = {}
scan_batch_limit = {}
max_pending = {}
max_completed = {}
max_dead_letters = {}
max_attempts = {}
checkpoint_max_bytes = {}
",
        worker_defaults::SCAN_INTERVAL_MIN_MS,
        worker_defaults::SCAN_BATCH_LIMIT_MAX,
        worker_defaults::MAX_PENDING_LIMIT,
        worker_defaults::MAX_COMPLETED_LIMIT,
        worker_defaults::MAX_DEAD_LETTERS_LIMIT,
        worker_defaults::MAX_ATTEMPTS_LIMIT,
        worker_defaults::CHECKPOINT_MIN_BYTES,
    );
    source.push_str(&native_signer_binding_toml(
        "reserve",
        "reserve",
        "resource-boundary",
        0x72,
    ));
    let sorafs: Table = toml::from_str(&source).expect("parse bounded reserve worker policy");
    table.insert("sorafs".into(), Value::Table(sorafs));
    let storage = load_root(table).torii.sorafs_storage;
    assert!(!storage.enabled);
    assert_reserve_workers_eq(
        storage.reserve_worker,
        actual::SorafsReserveWorker {
            enabled: true,
            scan_interval: Duration::from_millis(worker_defaults::SCAN_INTERVAL_MIN_MS),
            scan_batch_limit: worker_defaults::SCAN_BATCH_LIMIT_MAX,
            max_pending: worker_defaults::MAX_PENDING_LIMIT,
            max_completed: worker_defaults::MAX_COMPLETED_LIMIT,
            max_dead_letters: worker_defaults::MAX_DEAD_LETTERS_LIMIT,
            max_attempts: worker_defaults::MAX_ATTEMPTS_LIMIT,
            checkpoint_max_bytes: Bytes(worker_defaults::CHECKPOINT_MIN_BYTES),
        },
    );
}
#[test]
fn sorafs_reserve_worker_rejects_zero_and_excessive_resource_bounds() {
    use defaults::sorafs::storage::reserve_worker as worker_defaults;
    let invalid_fields = [
        "scan_interval_ms = 0".to_owned(),
        format!(
            "scan_interval_ms = {}",
            worker_defaults::SCAN_INTERVAL_MIN_MS - 1
        ),
        format!(
            "scan_interval_ms = {}",
            worker_defaults::SCAN_INTERVAL_MAX_MS + 1
        ),
        "scan_batch_limit = 0".to_owned(),
        format!(
            "scan_batch_limit = {}",
            worker_defaults::SCAN_BATCH_LIMIT_MAX + 1
        ),
        "max_pending = 0".to_owned(),
        format!("max_pending = {}", worker_defaults::MAX_PENDING_LIMIT + 1),
        "max_completed = 0".to_owned(),
        format!(
            "max_completed = {}",
            worker_defaults::MAX_COMPLETED_LIMIT + 1
        ),
        "max_dead_letters = 0".to_owned(),
        format!(
            "max_dead_letters = {}",
            worker_defaults::MAX_DEAD_LETTERS_LIMIT + 1
        ),
        "max_attempts = 0".to_owned(),
        format!("max_attempts = {}", worker_defaults::MAX_ATTEMPTS_LIMIT + 1),
        format!(
            "checkpoint_max_bytes = {}",
            worker_defaults::CHECKPOINT_MIN_BYTES - 1
        ),
        format!(
            "checkpoint_max_bytes = {}",
            worker_defaults::CHECKPOINT_MAX_BYTES_LIMIT + 1
        ),
    ];
    for invalid_field in invalid_fields {
        let mut table = base_table();
        let sorafs: Table = toml::from_str(&format!("[storage.reserve_worker]\n{invalid_field}\n"))
            .expect("parse invalid reserve worker fixture");
        table.insert("sorafs".into(), Value::Table(sorafs));
        assert!(
            actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
            "accepted invalid reserve worker field: {invalid_field}"
        );
    }
}
#[test]
fn sorafs_storage_hedging_billing_policy_path_parses() {
    let mut table = base_table();
    let sorafs: Table = toml::from_str(
        r#"
[storage]
hedging_feed_trust_policy_path = "/run/iroha/sorafs-hedging-policy.to"
"#,
    )
    .expect("parse SoraFS hedging/billing trust-policy path");
    table.insert("sorafs".into(), Value::Table(sorafs));
    let actual = load_root(table).torii.sorafs_storage;
    assert_eq!(
        actual.hedging_feed_trust_policy_path,
        Some(PathBuf::from("/run/iroha/sorafs-hedging-policy.to"))
    );
}
#[test]
fn sorafs_moderation_screening_authority_config_is_digest_bound_and_fail_closed() {
    let mut table = base_table();
    let native_signer_bindings =
        native_signer_bindings_toml("moderation", [0x50, 0x51, 0x52, 0x53]);
    let sorafs: Table = toml::from_str(&format!(
        r#"
[storage]
enabled = true
moderation_screening_enabled = true
moderation_screening_authority_bundle_path = "/etc/iroha/sorafs-screening-authority.to"
moderation_screening_authority_bundle_digest_hex = "{}"
moderation_quarantine_key_provider_handle = "software://sorafs/moderation/quarantine/primary"
moderation_quarantine_key_provider_revision = 7
moderation_quarantine_key_provider_policy_digest_hex = "{}"

{native_signer_bindings}
"#,
        "11".repeat(32),
        "51".repeat(32)
    ))
    .expect("parse moderation screening authority config");
    table.insert("sorafs".into(), Value::Table(sorafs));
    let storage = load_root(table).torii.sorafs_storage;
    assert!(storage.moderation_screening_enabled);
    assert_eq!(
        storage.moderation_screening_authority_bundle_path,
        Some(PathBuf::from("/etc/iroha/sorafs-screening-authority.to"))
    );
    assert_eq!(
        storage.moderation_screening_authority_bundle_digest,
        Some([0x11; 32])
    );
    assert_eq!(
        storage
            .moderation_quarantine_key_provider
            .as_ref()
            .map(|binding| binding.handle.as_str()),
        Some("software://sorafs/moderation/quarantine/primary")
    );
    assert_eq!(
        storage
            .moderation_quarantine_key_provider
            .as_ref()
            .map(|binding| binding.revision),
        Some(7)
    );
    assert_eq!(
        storage
            .moderation_quarantine_key_provider
            .as_ref()
            .map(|binding| binding.policy_digest),
        Some([0x51; 32])
    );
    for invalid_storage in [
        r"
[storage]
enabled = true
moderation_screening_enabled = true
"
        .to_owned(),
        format!(
            r#"
[storage]
enabled = true
moderation_screening_enabled = true
moderation_screening_authority_bundle_path = "/etc/iroha/sorafs-screening-authority.to"
moderation_screening_authority_bundle_digest_hex = "{}"
"#,
            "00".repeat(32)
        ),
        format!(
            r#"
[storage]
enabled = false
moderation_screening_enabled = true
moderation_screening_authority_bundle_path = "/etc/iroha/sorafs-screening-authority.to"
moderation_screening_authority_bundle_digest_hex = "{}"
"#,
            "11".repeat(32)
        ),
        format!(
            r#"
[storage]
enabled = true
moderation_screening_enabled = true
moderation_screening_authority_bundle_path = "relative/sorafs-screening-authority.to"
moderation_screening_authority_bundle_digest_hex = "{}"
"#,
            "11".repeat(32)
        ),
        format!(
            r#"
[storage]
enabled = true
moderation_screening_enabled = true
moderation_screening_authority_bundle_path = "/etc/iroha/sorafs-screening-authority.to"
moderation_screening_authority_bundle_digest_hex = "{}"
moderation_quarantine_key_provider_handle = "software://sorafs/moderation/quarantine/test"
moderation_quarantine_key_provider_revision = 0
moderation_quarantine_key_provider_policy_digest_hex = "{}"
"#,
            "11".repeat(32),
            "AA".repeat(32)
        ),
        r#"
[storage]
enabled = true
moderation_quarantine_key_provider_handle = "software://sorafs/moderation/quarantine/primary"
"#
        .to_owned(),
    ] {
        let mut table = base_table();
        let sorafs: Table =
            toml::from_str(&invalid_storage).expect("parse invalid screening config fixture");
        table.insert("sorafs".into(), Value::Table(sorafs));
        assert!(
            actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
            "invalid screening authority config must fail closed"
        );
    }
}
#[test]
fn sorafs_storage_pdp_policy_parses_governed_bounds() {
    let mut table = base_table();
    let sorafs: Table = toml::from_str(
        r"
[storage]
pdp_sample_window = 37
pdp_tree_memory_limit_bytes = 8388608

[storage.pdp_provider]
max_pending_records = 31
max_terminal_records = 47
checkpoint_max_bytes = 33554432
challenge_max_bytes = 262144
proof_max_bytes = 8388608
min_response_window_secs = 120
max_response_window_secs = 480
max_future_skew_secs = 3
terminal_retention_secs = 7200
",
    )
    .expect("parse SoraFS PDP policy");
    table.insert("sorafs".into(), Value::Table(sorafs));
    let actual = load_root(table);
    let storage = actual.torii.sorafs_storage;
    assert_eq!(storage.pdp_sample_window, 37);
    assert_eq!(storage.pdp_tree_memory_limit_bytes.0, 8_388_608);
    assert_eq!(storage.pdp_provider.max_pending_records, 31);
    assert_eq!(storage.pdp_provider.max_terminal_records, 47);
    assert_eq!(storage.pdp_provider.checkpoint_max_bytes.0, 33_554_432);
    assert_eq!(storage.pdp_provider.challenge_max_bytes.0, 262_144);
    assert_eq!(storage.pdp_provider.proof_max_bytes.0, 8_388_608);
    assert_eq!(storage.pdp_provider.min_response_window_secs, 120);
    assert_eq!(storage.pdp_provider.max_response_window_secs, 480);
    assert_eq!(storage.pdp_provider.max_future_skew_secs, 3);
    assert_eq!(storage.pdp_provider.terminal_retention_secs, 7_200);
}
#[test]
fn sorafs_storage_pdp_policy_rejects_zero_and_over_protocol_window() {
    for (sample_window, memory_limit, expected) in [
        (0, 8_388_608, "pdp_sample_window must be within"),
        (501, 8_388_608, "pdp_sample_window must be within"),
        (
            37,
            0,
            "pdp_tree_memory_limit_bytes must be greater than zero",
        ),
    ] {
        let mut table = base_table();
        let sorafs: Table = toml::from_str(&format!(
                "[storage]\npdp_sample_window = {sample_window}\npdp_tree_memory_limit_bytes = {memory_limit}\n"
            ))
            .expect("parse invalid SoraFS PDP policy fixture");
        table.insert("sorafs".into(), Value::Table(sorafs));
        let error = load_user_root(table)
            .parse()
            .expect_err("invalid PDP policy must fail config parsing");
        let report = format!("{error:?}");
        assert!(report.contains(expected), "{report}");
    }
}
#[test]
fn sorafs_storage_pdp_provider_policy_rejects_adversarial_bounds() {
    for (policy, expected) in [
        (
            "max_pending_records = 0",
            "record limits must be greater than zero",
        ),
        (
            "challenge_max_bytes = 524289",
            "challenge_max_bytes must be within",
        ),
        (
            "proof_max_bytes = 16777217",
            "proof_max_bytes must be within",
        ),
        (
            "checkpoint_max_bytes = 1024",
            "checkpoint_max_bytes must fit one maximum challenge and proof",
        ),
        (
            "min_response_window_secs = 601\nmax_response_window_secs = 600",
            "response and terminal-retention windows are inconsistent",
        ),
        (
            "max_response_window_secs = 90000",
            "response and terminal-retention windows are inconsistent",
        ),
    ] {
        let mut table = base_table();
        let sorafs: Table = toml::from_str(&format!("[storage.pdp_provider]\n{policy}\n"))
            .expect("parse invalid SoraFS PDP provider policy fixture");
        table.insert("sorafs".into(), Value::Table(sorafs));
        let error = load_user_root(table)
            .parse()
            .expect_err("invalid PDP provider policy must fail config parsing");
        let report = format!("{error:?}");
        assert!(report.contains(expected), "{report}");
    }
}
#[test]
fn sorafs_storage_privacy_aggregate_policy_parses_canonical_query() {
    let mut table = base_table();
    let native_signer_bindings = native_signer_bindings_toml("privacy", [0x60, 0x61, 0x62, 0x63]);
    let sorafs: Table = toml::from_str(&format!(
            r#"
[storage]
enabled = true
governance_dag_dir = "/var/lib/iroha/sorafs/governance"
governance_dag_publisher_peer_id = "sorafs-governance-primary"
governance_dag_signer_handle = "software://sorafs/governance-dag/privacy-primary"
governance_dag_signer_revision = 17
governance_dag_signer_policy_digest_hex = "7171717171717171717171717171717171717171717171717171717171717171"
governance_dag_publisher_public_key_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

[storage.governance_dag_service]
enabled = false
checkpoint_store_handle = "sealed://governance-dag/privacy-checkpoint-primary"
checkpoint_store_revision = 31
checkpoint_store_policy_digest_hex = "8181818181818181818181818181818181818181818181818181818181818181"

{native_signer_bindings}

[storage.privacy_aggregates]
enabled = true
cycle_seconds = 60
first_cycle_start_unix = 120
publish_delay_seconds = 17
aggregate_id_prefix = "sfm4c-governed"
query_id_hex = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"
privacy_mode = "differential_privacy_with_suppression"
epsilon_numerator = 4
epsilon_denominator = 5
per_subject_metric_cap = 2
suppression_threshold = 3
policy_digest_hex = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
cycle_prf_provider_handle = "threshold-prf:transparency:primary"
cycle_prf_provider_revision = 7
cycle_prf_provider_policy_digest_hex = "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"
release_anchor_provider_handle = "governance-dag:transparency:primary"
release_anchor_provider_revision = 9
release_anchor_provider_policy_digest_hex = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
leader_lease_provider_handle = "sealed-cas:transparency:leader-primary"
leader_lease_provider_revision = 11
leader_lease_provider_policy_digest_hex = "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1"
fenced_privacy_publisher_handle = "governance-cas:transparency:privacy-primary"
fenced_privacy_publisher_revision = 13
fenced_privacy_publisher_policy_digest_hex = "9191919191919191919191919191919191919191919191919191919191919191"
composition_budget_epsilon_numerator = 12
composition_budget_epsilon_denominator = 1
composition_budget_max_publications = 52

[[storage.privacy_aggregates.population_inventory]]
label = "jurisdiction-a"
digest_hex = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"

[[storage.privacy_aggregates.metric_schema]]
key = "moderation_actions"
unit = "count"
"#
        ))
        .expect("parse sorafs privacy aggregate policy");
    table.insert("sorafs".into(), Value::Table(sorafs));
    let actual = load_root(table);
    let storage = actual.torii.sorafs_storage;
    assert!(storage.enabled);
    assert_eq!(
        storage.governance_dag_dir.as_deref(),
        Some(Path::new("/var/lib/iroha/sorafs/governance"))
    );
    assert_eq!(
        storage.governance_dag_publisher_peer_id.as_deref(),
        Some("sorafs-governance-primary")
    );
    assert_eq!(
        storage.governance_dag_signer_handle.as_deref(),
        Some("software://sorafs/governance-dag/privacy-primary")
    );
    assert_eq!(storage.governance_dag_signer_revision, Some(17));
    assert_eq!(
        storage.governance_dag_signer_policy_digest,
        Some([0x71; 32])
    );
    assert_eq!(
        storage.governance_dag_publisher_public_key_hex.as_deref(),
        Some("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    );
    let schedule = storage.privacy_aggregates;
    assert!(schedule.enabled);
    assert_eq!(schedule.cycle_seconds, 60);
    assert_eq!(schedule.first_cycle_start_unix, 120);
    assert_eq!(schedule.publish_delay_seconds, 17);
    assert_eq!(schedule.aggregate_id_prefix, "sfm4c-governed");
    assert_eq!(schedule.query_id, Some([0xB0; 32]));
    assert_eq!(schedule.population_inventory.len(), 1);
    assert_eq!(schedule.population_inventory[0].label, "jurisdiction-a");
    assert_eq!(schedule.population_inventory[0].digest, [0xA0; 32]);
    assert_eq!(schedule.metric_schema.len(), 1);
    assert_eq!(schedule.metric_schema[0].key, "moderation_actions");
    assert_eq!(schedule.metric_schema[0].unit, "count");
    assert_eq!(
        schedule.privacy_mode,
        "differential_privacy_with_suppression"
    );
    assert_eq!(schedule.epsilon_numerator, 4);
    assert_eq!(schedule.epsilon_denominator, 5);
    assert_eq!(schedule.per_subject_metric_cap, 2);
    assert_eq!(schedule.suppression_threshold, 3);
    assert_eq!(schedule.policy_digest, Some([0xC0; 32]));
    assert_eq!(
        schedule.cycle_prf_provider,
        Some(actual::SorafsTransparencyRuntimeProviderBinding {
            handle: "threshold-prf:transparency:primary".to_owned(),
            revision: 7,
            policy_digest: [0xD1; 32],
        })
    );
    assert_eq!(
        schedule.release_anchor_provider,
        Some(actual::SorafsTransparencyRuntimeProviderBinding {
            handle: "governance-dag:transparency:primary".to_owned(),
            revision: 9,
            policy_digest: [0xE1; 32],
        })
    );
    assert_eq!(
        schedule.leader_lease_provider,
        Some(actual::SorafsTransparencyRuntimeProviderBinding {
            handle: "sealed-cas:transparency:leader-primary".to_owned(),
            revision: 11,
            policy_digest: [0xF1; 32],
        })
    );
    assert_eq!(
        schedule.fenced_privacy_publisher,
        Some(actual::SorafsTransparencyRuntimeProviderBinding {
            handle: "governance-cas:transparency:privacy-primary".to_owned(),
            revision: 13,
            policy_digest: [0x91; 32],
        })
    );
    assert_eq!(schedule.composition_budget_epsilon_numerator, 12);
    assert_eq!(schedule.composition_budget_epsilon_denominator, 1);
    assert_eq!(schedule.composition_budget_max_publications, 52);
}
#[test]
fn sorafs_storage_enabled_privacy_rejects_missing_governance_dag_dir() {
    let mut table = base_table();
    let sorafs: Table = toml::from_str(
        r"
[storage]
enabled = true

[storage.privacy_aggregates]
enabled = true
",
    )
    .expect("parse missing privacy Governance DAG fixture");
    table.insert("sorafs".into(), Value::Table(sorafs));
    let error = load_user_root(table)
        .parse()
        .expect_err("enabled privacy must reject a missing Governance DAG directory");
    let report = format!("{error:?}");
    assert!(
        report.contains(
            "sorafs.storage.privacy_aggregates.enabled requires an explicit governance_dag_dir"
        ),
        "{report}"
    );
}
#[test]
fn sorafs_storage_enabled_privacy_rejects_partial_governance_signer_binding() {
    let mut table = base_table();
    let sorafs: Table = toml::from_str(
        r#"
[storage]
enabled = true
governance_dag_dir = "/var/lib/iroha/sorafs/governance"
governance_dag_publisher_peer_id = "sorafs-governance-primary"
governance_dag_signer_handle = "software://sorafs/governance-dag/privacy-primary"

[storage.privacy_aggregates]
enabled = true
"#,
    )
    .expect("parse partial privacy Governance DAG fixture");
    table.insert("sorafs".into(), Value::Table(sorafs));
    let error = load_user_root(table)
        .parse()
        .expect_err("enabled privacy must reject a partial Governance DAG signer binding");
    let report = format!("{error:?}");
    assert!(
            report.contains(
                "sorafs.storage.privacy_aggregates.enabled requires the complete signed Governance DAG publisher binding"
            ),
            "{report}"
        );
}
#[test]
fn sorafs_storage_privacy_aggregate_policy_rejects_unsafe_config() {
    for (policy, expected) in [
        (
            "enabled = true",
            "policy_digest_hex is required when enabled",
        ),
        ("cycle_seconds = 0", "cycle_seconds must be positive"),
        (
            "epsilon_numerator = 2\nepsilon_denominator = 4",
            "epsilon must be a reduced positive rational",
        ),
        (
            "composition_budget_max_publications = 4097",
            "composition budget is invalid",
        ),
        (
            "policy_digest_hex = \"C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0\"",
            "must be 64 lowercase hex characters",
        ),
    ] {
        let mut table = base_table();
        let sorafs: Table = toml::from_str(&format!("[storage.privacy_aggregates]\n{policy}\n"))
            .expect("parse invalid SoraFS privacy policy fixture");
        table.insert("sorafs".into(), Value::Table(sorafs));
        let error = load_user_root(table)
            .parse()
            .expect_err("invalid privacy aggregate policy must fail config parsing");
        let report = format!("{error:?}");
        assert!(report.contains(expected), "{report}");
    }
}
#[test]
fn sorafs_storage_privacy_runtime_provider_bindings_fail_closed() {
    let cases = [
        (
            true,
            "differential_privacy",
            r#"
cycle_prf_provider_handle = "threshold-prf:transparency:primary"
release_anchor_provider_handle = "governance-dag:transparency:primary"
release_anchor_provider_revision = 9
release_anchor_provider_policy_digest_hex = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
"#,
            "cycle_prf_provider handle, revision, and policy digest are required together",
        ),
        (
            true,
            "differential_privacy",
            r#"
cycle_prf_provider_handle = "mock:threshold-prf:primary"
cycle_prf_provider_revision = 7
cycle_prf_provider_policy_digest_hex = "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"
release_anchor_provider_handle = "governance-dag:transparency:primary"
release_anchor_provider_revision = 9
release_anchor_provider_policy_digest_hex = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
"#,
            "cycle_prf_provider_handle must be a canonical non-test production handle",
        ),
        (
            true,
            "differential_privacy",
            r#"
cycle_prf_provider_handle = "threshold-prf:transparency:primary"
cycle_prf_provider_revision = 0
cycle_prf_provider_policy_digest_hex = "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"
release_anchor_provider_handle = "governance-dag:transparency:primary"
release_anchor_provider_revision = 9
release_anchor_provider_policy_digest_hex = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
"#,
            "cycle_prf_provider_revision must be nonzero",
        ),
        (
            true,
            "differential_privacy",
            r#"
cycle_prf_provider_handle = "threshold-prf:transparency:primary"
cycle_prf_provider_revision = 7
cycle_prf_provider_policy_digest_hex = "D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1"
release_anchor_provider_handle = "governance-dag:transparency:primary"
release_anchor_provider_revision = 9
release_anchor_provider_policy_digest_hex = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
"#,
            "cycle_prf_provider_policy_digest_hex must be 64 lowercase hex characters",
        ),
        (
            true,
            "suppression",
            r#"
cycle_prf_provider_handle = "threshold-prf:transparency:primary"
cycle_prf_provider_revision = 7
cycle_prf_provider_policy_digest_hex = "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"
release_anchor_provider_handle = "governance-dag:transparency:primary"
release_anchor_provider_revision = 9
release_anchor_provider_policy_digest_hex = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
"#,
            "cycle_prf_provider binding fields must be absent when the provider is not required",
        ),
        (
            false,
            "differential_privacy",
            r#"
release_anchor_provider_handle = "governance-dag:transparency:primary"
release_anchor_provider_revision = 9
release_anchor_provider_policy_digest_hex = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
"#,
            "release_anchor_provider binding fields must be absent when the provider is not required",
        ),
        (
            true,
            "suppression",
            r#"
release_anchor_provider_handle = "governance-dag:transparency:primary"
release_anchor_provider_revision = 9
release_anchor_provider_policy_digest_hex = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
leader_lease_provider_handle = "sealed-cas:transparency:leader-primary"
leader_lease_provider_revision = 11
leader_lease_provider_policy_digest_hex = "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1"
fenced_privacy_publisher_handle = "governance-cas:transparency:privacy-primary"
fenced_privacy_publisher_revision = 13
"#,
            "fenced_privacy_publisher handle, revision, and policy digest are required together",
        ),
        (
            true,
            "suppression",
            r#"
release_anchor_provider_handle = "governance-dag:transparency:primary"
release_anchor_provider_revision = 9
release_anchor_provider_policy_digest_hex = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
leader_lease_provider_handle = "sealed-cas:transparency:leader-primary"
leader_lease_provider_revision = 11
leader_lease_provider_policy_digest_hex = "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1"
fenced_privacy_publisher_handle = "governance-cas:transparency:test"
fenced_privacy_publisher_revision = 13
fenced_privacy_publisher_policy_digest_hex = "9191919191919191919191919191919191919191919191919191919191919191"
"#,
            "fenced_privacy_publisher_handle must be a canonical non-test production handle",
        ),
        (
            false,
            "suppression",
            r#"
fenced_privacy_publisher_handle = "governance-cas:transparency:privacy-primary"
fenced_privacy_publisher_revision = 13
fenced_privacy_publisher_policy_digest_hex = "9191919191919191919191919191919191919191919191919191919191919191"
"#,
            "fenced_privacy_publisher binding fields must be absent when the provider is not required",
        ),
    ];
    for (enabled, privacy_mode, bindings, expected) in cases {
        let mut table = base_table();
        let sorafs: Table = toml::from_str(&format!(
            r#"
[storage.privacy_aggregates]
enabled = {enabled}
cycle_seconds = 60
first_cycle_start_unix = 120
query_id_hex = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"
privacy_mode = "{privacy_mode}"
policy_digest_hex = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
{bindings}

[[storage.privacy_aggregates.population_inventory]]
label = "jurisdiction-a"
digest_hex = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"

[[storage.privacy_aggregates.metric_schema]]
key = "moderation_actions"
unit = "count"
"#
        ))
        .expect("parse invalid transparency provider binding fixture");
        table.insert("sorafs".into(), Value::Table(sorafs));
        let error = load_user_root(table)
            .parse()
            .expect_err("invalid transparency provider binding must fail config parsing");
        let report = format!("{error:?}");
        assert!(report.contains(expected), "{report}");
    }
}
#[test]
fn sorafs_storage_evidence_viewer_audit_schedule_parses_and_clamps_cycle() {
    let mut table = base_table();
    let sorafs: Table = toml::from_str(
        r"
[storage.evidence_viewer_audits]
enabled = true
cycle_seconds = 0
publish_delay_seconds = 17
",
    )
    .expect("parse sorafs evidence viewer audit schedule");
    table.insert("sorafs".into(), Value::Table(sorafs));
    let actual = load_root(table);
    let schedule = actual.torii.sorafs_storage.evidence_viewer_audits;
    assert!(schedule.enabled);
    assert_eq!(schedule.cycle_seconds, 1);
    assert_eq!(schedule.publish_delay_seconds, 17);
}
#[test]
fn network_reply_writer_flush_timeout_defaults_and_parses() {
    let default = load_root(base_table());
    assert_eq!(
        default.network.reply_writer_flush_timeout,
        defaults::network::REPLY_WRITER_FLUSH_TIMEOUT
    );
    let mut table = base_table();
    let network = table
        .get_mut("network")
        .and_then(Value::as_table_mut)
        .expect("network table");
    network.insert(
        "reply_writer_flush_timeout_ms".into(),
        Value::Integer(1_234),
    );
    let configured = load_root(table);
    assert_eq!(
        configured.network.reply_writer_flush_timeout,
        StdDuration::from_millis(1_234)
    );
    let mut table = base_table();
    table
        .get_mut("network")
        .and_then(Value::as_table_mut)
        .expect("network table")
        .insert(
            "reply_writer_flush_timeout_ms".into(),
            Value::Integer(i64::MAX),
        );
    let configured = load_root(table);
    assert_eq!(
        configured.network.reply_writer_flush_timeout,
        StdDuration::from_millis(u64::try_from(i64::MAX).expect("positive i64 maximum fits u64"),),
        "the largest TOML integer timeout must not overflow deadline construction"
    );
}
#[test]
fn network_outbound_dial_policy_defaults_and_parses() {
    let default = load_root(base_table());
    assert!(default.network.outbound_dial_allow_cidrs.is_empty());
    assert!(default.network.outbound_dial_deny_cidrs.is_empty());
    assert!(default.network.outbound_dial_allow_dns_suffixes.is_empty());
    assert!(default.network.outbound_dial_deny_dns_suffixes.is_empty());

    let mut table = base_table();
    let network = table
        .get_mut("network")
        .and_then(Value::as_table_mut)
        .expect("network table");
    for (key, values) in [
        ("outbound_dial_allow_cidrs", &["192.0.2.0/24"][..]),
        ("outbound_dial_deny_cidrs", &["127.0.0.0/8"][..]),
        ("outbound_dial_allow_dns_suffixes", &[".example.com"][..]),
        (
            "outbound_dial_deny_dns_suffixes",
            &["blocked.example.com"][..],
        ),
    ] {
        network.insert(
            key.to_owned(),
            Value::Array(
                values
                    .iter()
                    .map(|value| Value::String((*value).to_owned()))
                    .collect(),
            ),
        );
    }
    let configured = load_root(table);
    assert_eq!(
        configured.network.outbound_dial_allow_cidrs,
        ["192.0.2.0/24"]
    );
    assert_eq!(configured.network.outbound_dial_deny_cidrs, ["127.0.0.0/8"]);
    assert_eq!(
        configured.network.outbound_dial_allow_dns_suffixes,
        [".example.com"]
    );
    assert_eq!(
        configured.network.outbound_dial_deny_dns_suffixes,
        ["blocked.example.com"]
    );
}
#[test]
fn network_defaults_apply_transaction_gossip_target_caps() {
    let actual = load_root(base_table());
    assert_eq!(
        actual.transaction_gossiper.dataspace.public_target_cap,
        defaults::network::TX_GOSSIP_PUBLIC_TARGET_CAP
    );
    assert_eq!(
        actual.transaction_gossiper.dataspace.restricted_target_cap,
        defaults::network::TX_GOSSIP_RESTRICTED_TARGET_CAP
    );
}
#[test]
fn execution_proof_transport_overlay_preserves_ordinary_defaults() {
    let default = load_root(base_table());
    assert_eq!(default.network.max_frame_bytes_health, 32_768);
    assert_eq!(default.network.max_frame_bytes_connect, 131_072);
    assert_eq!(default.network.max_frame_bytes_tx_gossip, 17 * 1024 * 1024);
    assert_eq!(default.torii.connect.frame_max_bytes, 64_000);
    let overlay: Table = toml::from_str(include_str!(
        "../../../../configs/soranexus/execution-proof-transport.toml"
    ))
    .expect("execution transport overlay TOML");
    let mut table = base_table();
    for (key, value) in overlay {
        let fields = value.as_table().expect("overlay section");
        let target = table
            .entry(key)
            .or_insert_with(|| Value::Table(Table::new()))
            .as_table_mut()
            .expect("runtime section");
        for (name, value) in fields {
            target.insert(name.clone(), value.clone());
        }
    }
    let configured = load_root(table);
    assert_eq!(configured.network.max_frame_bytes_health, 32_768);
    assert_eq!(configured.network.max_frame_bytes_connect, 8 * 1024 * 1024);
    assert_eq!(
        configured.network.max_frame_bytes_tx_gossip,
        17 * 1024 * 1024
    );
    assert_eq!(
        configured.torii.connect.frame_max_bytes,
        4 * 1024 * 1024 + 4096
    );
    assert_eq!(
        configured.torii.connect.session_buffer_max_bytes,
        8 * 1024 * 1024
    );
    assert_eq!(configured.torii.connect.ws_max_sessions, 16);
}
#[test]
fn trusted_peer_full_fanout_must_fit_the_effective_network_capacity() {
    let set_connection_capacity = |table: &mut Table, capacity: usize| {
        table
            .get_mut("network")
            .and_then(Value::as_table_mut)
            .expect("network table")
            .insert(
                "max_total_connections".into(),
                Value::Integer(i64::try_from(capacity).expect("fixture capacity fits TOML")),
            );
    };

    let mut exact = four_validator_roster_table();
    set_connection_capacity(&mut exact, 3);
    let admitted = load_root(exact);
    assert_eq!(admitted.common.trusted_peers.value().others.len(), 3);
    assert_eq!(
        admitted
            .network
            .max_total_connections
            .map(std::num::NonZeroUsize::get),
        Some(3),
    );

    let mut underbudget = four_validator_roster_table();
    set_connection_capacity(&mut underbudget, 2);
    let error = actual::Root::from_toml_source(TomlSource::inline(underbudget))
        .expect_err("three remote trusted peers cannot fit two protected P2P sources");
    let report = format!("{error:?}");
    assert!(
            report.contains(
                "trusted-peer full fanout requires 3 remote connections, above the effective network connection capacity 2"
            ),
            "{report}",
        );
}
#[test]
fn network_defaults_apply_transaction_gossip_resend_ticks() {
    let actual = load_root(base_table());
    assert_eq!(
        actual.transaction_gossiper.gossip_resend_ticks,
        defaults::network::TRANSACTION_GOSSIP_RESEND_TICKS
    );
}
#[test]
fn network_accepts_canonical_transaction_gossip_size_boundary() {
    let mut table = base_table();
    let network = table
        .get_mut("network")
        .and_then(Value::as_table_mut)
        .expect("network table");
    network.insert(
        "transaction_gossip_size".into(),
        Value::Integer(i64::from(
            defaults::network::TRANSACTION_GOSSIP_MAX_SIZE.get(),
        )),
    );
    let actual = load_root(table);
    assert_eq!(
        actual.transaction_gossiper.gossip_size,
        defaults::network::TRANSACTION_GOSSIP_MAX_SIZE
    );
}
#[test]
#[should_panic(
    expected = "network.transaction_gossip_size must not exceed the canonical per-message maximum"
)]
fn network_rejects_transaction_gossip_size_above_canonical_limit() {
    let mut table = base_table();
    let network = table
        .get_mut("network")
        .and_then(Value::as_table_mut)
        .expect("network table");
    network.insert(
        "transaction_gossip_size".into(),
        Value::Integer(i64::from(
            defaults::network::TRANSACTION_GOSSIP_MAX_SIZE.get() + 1,
        )),
    );
    let _ = load_root(table);
}
#[test]
fn network_deferred_send_byte_caps_default_and_clamp_zero() {
    let actual = load_root(base_table());
    assert_eq!(
        actual.network.deferred_send_max_bytes_per_peer,
        defaults::network::DEFERRED_SEND_MAX_BYTES_PER_PEER
    );
    assert_eq!(
        actual.network.deferred_send_max_bytes_total,
        defaults::network::DEFERRED_SEND_MAX_BYTES_TOTAL
    );
    let mut table = base_table();
    let network = table
        .get_mut("network")
        .and_then(Value::as_table_mut)
        .expect("network table");
    network.insert("deferred_send_max_bytes_per_peer".into(), Value::Integer(0));
    network.insert("deferred_send_max_bytes_total".into(), Value::Integer(0));
    let actual = load_root(table);
    assert_eq!(actual.network.deferred_send_max_bytes_per_peer, 1);
    assert_eq!(actual.network.deferred_send_max_bytes_total, 1);
}
include!("user/kura_and_snapshot_tests.rs");
#[test]
fn snapshot_resource_defaults_fit_decoder_limits() {
    let actual = load_root(base_table());
    assert_eq!(
        actual.snapshot.resources.max_decode_depth.get(),
        norito::core::MAX_VALUE_NESTING_DEPTH
    );
    assert!(
        actual
            .snapshot
            .resources
            .validate(actual.snapshot.max_payload_bytes)
            .is_ok()
    );
}
#[test]
fn snapshot_resource_policy_rejects_incoherent_budgets() {
    let invalid_resources = [
        (
            "max_decode_depth",
            i64::try_from(norito::core::MAX_VALUE_NESTING_DEPTH + 1)
                .expect("Norito depth limit fits i64"),
        ),
        ("max_string_bytes", 65),
        ("max_blob_bytes", 129),
        ("max_transient_bytes", 63),
    ];
    for (field, value) in invalid_resources {
        let mut table = base_table();
        let snapshot = table
            .entry("snapshot")
            .or_insert_with(|| Value::Table(Table::new()))
            .as_table_mut()
            .expect("snapshot table");
        snapshot.insert("max_payload_bytes".into(), Value::Integer(128));
        let mut resources = Table::new();
        resources.insert(
            "max_decode_depth".into(),
            Value::Integer(
                i64::try_from(norito::core::MAX_VALUE_NESTING_DEPTH)
                    .expect("Norito depth limit fits i64"),
            ),
        );
        resources.insert("max_decode_items".into(), Value::Integer(1_024));
        resources.insert("max_string_bytes".into(), Value::Integer(32));
        resources.insert("max_blob_bytes".into(), Value::Integer(64));
        resources.insert("max_transient_bytes".into(), Value::Integer(128));
        resources.insert(field.into(), Value::Integer(value));
        snapshot.insert("resources".into(), Value::Table(resources));
        let error = actual::Root::from_toml_source(TomlSource::inline(table))
            .expect_err("incoherent snapshot resource policy must fail configuration parsing");
        let report = format!("{error:?}");
        assert!(
            report.contains(field),
            "incoherent snapshot resource field {field} must report its own budget violation: {report}"
        );
    }
}
#[test]
fn retired_peer_genesis_bootstrap_config_is_rejected() {
    for (field, value) in [
        ("bootstrap_allowlist", Value::Array(Vec::new())),
        ("bootstrap_max_bytes", Value::Integer(1)),
        ("bootstrap_response_throttle_ms", Value::Integer(1)),
        ("bootstrap_request_timeout_ms", Value::Integer(1)),
        ("bootstrap_retry_interval_ms", Value::Integer(1)),
        ("bootstrap_max_attempts", Value::Integer(1)),
        ("bootstrap_enabled", Value::Boolean(true)),
    ] {
        let mut table = base_table();
        let genesis = table
            .entry("genesis")
            .or_insert_with(|| Value::Table(Table::new()))
            .as_table_mut()
            .expect("genesis table");
        genesis.insert(field.into(), value);
        assert!(
            actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
            "retired genesis.{field} must not be accepted"
        );
    }
}
#[test]
fn genesis_expected_hash_is_required_during_configuration_normalization() {
    let mut table = base_table();
    table
        .get_mut("genesis")
        .and_then(Value::as_table_mut)
        .expect("genesis table")
        .remove("expected_hash");
    assert!(
        actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
        "a signed artifact must not be allowed to select its own startup trust root"
    );
}
#[test]
fn genesis_expected_hash_rejects_raw_genesis_hash() {
    let mut table = base_table();
    table
        .get_mut("genesis")
        .and_then(Value::as_table_mut)
        .expect("genesis table")
        .insert(
            "expected_hash".into(),
            Value::String(
                HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                    b"obsolete inline raw genesis hash identity",
                ))
                .to_string(),
            ),
        );
    assert!(
        actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
        "the first-release inline trust root must reject raw hash compatibility"
    );
}
#[test]
fn genesis_expected_hash_file_supplies_the_exact_trust_root() {
    let expected_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        b"configuration file backed genesis identity",
    ));
    let network_id = NetworkId::from_genesis_hash(expected_hash);
    let identity_dir = TestDir::create("genesis-identity");
    let identity_path = identity_dir.path().join("expected_hash");
    fs::write(&identity_path, format!("{network_id}\n")).expect("write identity");
    let mut table = base_table();
    let genesis = table
        .get_mut("genesis")
        .and_then(Value::as_table_mut)
        .expect("genesis table");
    genesis.remove("expected_hash");
    genesis.insert(
        "expected_hash_file".into(),
        Value::String(identity_path.display().to_string()),
    );
    let root = actual::Root::from_toml_source(TomlSource::inline(table))
        .expect("canonical identity file must be accepted");
    assert_eq!(root.genesis.expected_hash, expected_hash);
}
#[test]
fn genesis_expected_hash_file_rejects_noncanonical_record_bytes() {
    let expected_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        b"validator canonical network identity file bytes",
    ));
    let canonical = NetworkId::from_genesis_hash(expected_hash).to_string();
    for (label, contents) in [
        ("missing final LF", canonical.clone()),
        ("CRLF terminator", format!("{canonical}\r\n")),
        ("leading space", format!(" {canonical}\n")),
        ("trailing space", format!("{canonical} \n")),
        ("extra empty record", format!("{canonical}\n\n")),
        ("multiple records", format!("{canonical}\n{canonical}\n")),
    ] {
        let identity_dir = TestDir::create(label);
        let identity_path = identity_dir.path().join("expected_hash");
        fs::write(&identity_path, contents).expect("write malformed identity");
        let mut table = base_table();
        let genesis = table
            .get_mut("genesis")
            .and_then(Value::as_table_mut)
            .expect("genesis table");
        genesis.remove("expected_hash");
        genesis.insert(
            "expected_hash_file".into(),
            Value::String(identity_path.display().to_string()),
        );
        assert!(
            actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
            "{label} must fail closed"
        );
    }
}
#[test]
fn genesis_expected_hash_file_rejects_raw_genesis_hash() {
    let expected_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        b"obsolete raw genesis hash identity",
    ));
    let identity_dir = TestDir::create("raw-genesis-identity");
    let identity_path = identity_dir.path().join("expected_hash");
    fs::write(&identity_path, format!("{expected_hash}\n")).expect("write raw hash identity");
    let mut table = base_table();
    let genesis = table
        .get_mut("genesis")
        .and_then(Value::as_table_mut)
        .expect("genesis table");
    genesis.remove("expected_hash");
    genesis.insert(
        "expected_hash_file".into(),
        Value::String(identity_path.display().to_string()),
    );
    assert!(
        actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
        "the first-release shared identity file must reject raw hash compatibility"
    );
}
#[test]
fn genesis_rejects_ambiguous_inline_and_file_trust_roots() {
    let identity_dir = TestDir::create("ambiguous-genesis-identity");
    let identity_path = identity_dir.path().join("expected_hash");
    fs::write(
        &identity_path,
        "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E\n",
    )
    .expect("write identity");
    let mut table = base_table();
    table
        .get_mut("genesis")
        .and_then(Value::as_table_mut)
        .expect("genesis table")
        .insert(
            "expected_hash_file".into(),
            Value::String(identity_path.display().to_string()),
        );
    assert!(
        actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
        "two trust-root sources must fail closed"
    );
}
#[test]
fn storage_legacy_budget_name_is_rejected() {
    let mut table = base_table();
    let nexus = table
        .entry("nexus")
        .or_insert_with(|| Value::Table(Table::new()))
        .as_table_mut()
        .expect("nexus table");
    let mut storage = Table::new();
    storage.insert("max_disk_usage_bytes".into(), Value::Integer(1_000));
    nexus.insert("storage".into(), Value::Table(storage));
    assert!(
        actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
        "the pre-release max_disk_usage_bytes alias must not be silently accepted"
    );
}
#[test]
fn storage_local_budget_bytes_applies_after_parse() {
    let mut table = base_table();
    let nexus = table
        .entry("nexus")
        .or_insert_with(|| Value::Table(Table::new()))
        .as_table_mut()
        .expect("nexus table");
    let mut storage = Table::new();
    storage.insert("local_budget_bytes".into(), Value::Integer(1_024));
    storage.insert("max_wsv_memory_bytes".into(), Value::Integer(128));
    let mut weights = Table::new();
    weights.insert("kura_blocks_bps".into(), Value::Integer(3_500));
    weights.insert("wsv_snapshots_bps".into(), Value::Integer(2_000));
    weights.insert("sorafs_bps".into(), Value::Integer(4_500));
    storage.insert("disk_budget_weights".into(), Value::Table(weights));
    nexus.insert("storage".into(), Value::Table(storage));
    let actual = load_root(table);
    assert_eq!(
        actual.nexus.storage.local_budget_bytes.map(Bytes::get),
        Some(1_024)
    );
    assert_eq!(
        actual
            .nexus
            .storage
            .effective_local_budget_bytes
            .map(Bytes::get),
        Some(1_024)
    );
    assert_eq!(actual.kura.max_disk_usage_bytes.get(), 360);
    assert_eq!(actual.tiered_state.hot_retained_bytes.get(), 128);
}
#[test]
fn storage_budget_preserves_parsed_sorafs_cap_before_clamping() {
    const BUDGET_BYTES: u64 = 68_719_476_736;
    const SORAFS_CAP_BYTES: u64 = 13_743_895_347;

    let parse = |configured_cap: Option<u64>| {
        let mut table = base_table();
        let nexus = table
            .entry("nexus")
            .or_insert_with(|| Value::Table(Table::new()))
            .as_table_mut()
            .expect("nexus table");
        let mut storage = Table::new();
        storage.insert(
            "local_budget_bytes".into(),
            Value::Integer(i64::try_from(BUDGET_BYTES).expect("budget fits TOML integer")),
        );
        let mut weights = Table::new();
        weights.insert("kura_blocks_bps".into(), Value::Integer(6_000));
        weights.insert("wsv_snapshots_bps".into(), Value::Integer(2_000));
        weights.insert("sorafs_bps".into(), Value::Integer(2_000));
        storage.insert("disk_budget_weights".into(), Value::Table(weights));
        nexus.insert("storage".into(), Value::Table(storage));

        let mut sorafs_storage = Table::new();
        sorafs_storage.insert("enabled".into(), Value::Boolean(false));
        if let Some(cap) = configured_cap {
            sorafs_storage.insert(
                "max_capacity_bytes".into(),
                Value::Integer(i64::try_from(cap).expect("capacity fits TOML integer")),
            );
        }
        let mut sorafs = Table::new();
        sorafs.insert("storage".into(), Value::Table(sorafs_storage));
        table.insert("sorafs".into(), Value::Table(sorafs));
        load_root(table)
    };

    let cases = [
        (
            "omitted",
            None,
            defaults::sorafs::storage::MAX_CAPACITY_BYTES.get(),
            SORAFS_CAP_BYTES,
        ),
        ("zero", Some(0), 0, SORAFS_CAP_BYTES),
        (
            "larger",
            Some(SORAFS_CAP_BYTES + 1),
            SORAFS_CAP_BYTES + 1,
            SORAFS_CAP_BYTES,
        ),
        (
            "smaller",
            Some(SORAFS_CAP_BYTES - 1),
            SORAFS_CAP_BYTES - 1,
            SORAFS_CAP_BYTES - 1,
        ),
        (
            "exact",
            Some(SORAFS_CAP_BYTES),
            SORAFS_CAP_BYTES,
            SORAFS_CAP_BYTES,
        ),
    ];
    for (label, configured, expected_source, expected_effective) in cases {
        let actual = parse(configured);
        assert_eq!(
            actual
                .nexus
                .storage
                .configured_sorafs_max_capacity_bytes()
                .map(Bytes::get),
            Some(expected_source),
            "{label} source cap"
        );
        assert_eq!(
            actual.torii.sorafs_storage.max_capacity_bytes.get(),
            expected_effective,
            "{label} effective cap"
        );
    }
}
#[test]
fn storage_budget_requests_runtime_derivation_when_left_unset() {
    let actual = load_root(base_table());
    assert!(actual.nexus.storage.local_budget_bytes.is_none());
    assert!(actual.nexus.storage.effective_local_budget_bytes.is_none());
}
#[test]
fn storage_zero_local_budget_is_rejected() {
    let mut table = base_table();
    let nexus = table
        .entry("nexus")
        .or_insert_with(|| Value::Table(Table::new()))
        .as_table_mut()
        .expect("nexus table");
    let mut storage = Table::new();
    storage.insert("local_budget_bytes".into(), Value::Integer(0));
    nexus.insert("storage".into(), Value::Table(storage));
    assert!(
        actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
        "zero would disable downstream enforcement and must fail parsing"
    );
}
#[test]
fn storage_local_budget_rejects_zero_weighted_component_caps() {
    let mut table = base_table();
    let nexus = table
        .entry("nexus")
        .or_insert_with(|| Value::Table(Table::new()))
        .as_table_mut()
        .expect("nexus table");
    let mut storage = Table::new();
    storage.insert("local_budget_bytes".into(), Value::Integer(1));
    nexus.insert("storage".into(), Value::Table(storage));
    assert!(
        actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
        "a zero component cap means unlimited downstream and must fail parsing"
    );
}
macro_rules! assert_all_eq {
        ($($actual:expr => $expected:expr),+ $(,)?) => {
            $(assert_eq!($actual, $expected);)+
        };
    }
fn table_with_soracloud_runtime(source: &str) -> Table {
    let runtime = toml::from_str(source).expect("parse SoraCloud runtime fixture");
    let mut table = base_table();
    table.insert("soracloud_runtime".into(), Value::Table(runtime));
    table
}
#[test]
fn soracloud_runtime_defaults_apply() {
    let actual = load_root(base_table());
    let runtime = &actual.soracloud_runtime;
    let inrou = &runtime.inrou;
    assert_all_eq!(
        runtime.production_mode => defaults::soracloud_runtime::PRODUCTION_MODE,
        runtime.state_dir => defaults::soracloud_runtime::state_dir(),
        runtime.reconcile_interval => StdDuration::from_millis(defaults::soracloud_runtime::RECONCILE_INTERVAL_MS),
        runtime.hydration_concurrency => defaults::soracloud_runtime::HYDRATION_CONCURRENCY,
        runtime.prepared_runtime_cache_capacity => defaults::soracloud_runtime::PREPARED_RUNTIME_CACHE_CAPACITY,
        runtime.cache_budgets.bundle_bytes => defaults::soracloud_runtime::BUNDLE_CACHE_BUDGET_BYTES,
        inrou.enabled => defaults::soracloud_runtime::INROU_ENABLED,
        inrou.guest_image_max_bytes => defaults::soracloud_runtime::INROU_GUEST_IMAGE_MAX_BYTES,
        inrou.max_cpu_millis => defaults::soracloud_runtime::INROU_MAX_CPU_MILLIS,
        inrou.max_memory_bytes => defaults::soracloud_runtime::INROU_MAX_MEMORY_BYTES,
        inrou.max_storage_bytes => defaults::soracloud_runtime::INROU_MAX_STORAGE_BYTES,
        inrou.bundle_archive_max_compressed_bytes => defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_COMPRESSED_BYTES,
        inrou.bundle_archive_max_decoded_bytes => defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_DECODED_BYTES,
        inrou.bundle_archive_max_entries => defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_ENTRIES,
        inrou.bundle_archive_max_file_bytes => defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_FILE_BYTES,
        inrou.bundle_archive_max_total_file_bytes => defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_TOTAL_FILE_BYTES,
        inrou.start_grace => StdDuration::from_millis(defaults::soracloud_runtime::INROU_START_GRACE_MS),
        runtime.egress.default_allow => defaults::soracloud_runtime::EGRESS_DEFAULT_ALLOW,
    );
    assert!(matches!(
        &runtime.submission.fee_payer,
        actual::SoracloudRuntimeFeePayer::Authority
    ));
}
#[test]
fn soracloud_runtime_inrou_lifecycle_grace_rejects_out_of_range_values() {
    for (field, value) in [
        ("start_grace_ms", 99_u64),
        ("start_grace_ms", 600_001),
        ("stop_grace_ms", 99),
        ("stop_grace_ms", 600_001),
    ] {
        let table = table_with_soracloud_runtime(&format!("[inrou]\n{field} = {value}\n"));
        let error = actual::Root::from_toml_source(TomlSource::inline(table))
            .expect_err("an out-of-range Inrou lifecycle grace must fail parsing");
        assert!(
                format!("{error:?}").contains(&format!(
                    "soracloud_runtime.inrou.{field} must be between 100 and 600000 milliseconds inclusive"
                )),
                "unexpected parse error for {field}={value}: {error:?}"
            );
    }
}
#[test]
fn soracloud_runtime_inrou_lifecycle_grace_accepts_exact_bounds() {
    for value in [
        defaults::soracloud_runtime::INROU_LIFECYCLE_GRACE_MIN_MS,
        defaults::soracloud_runtime::INROU_LIFECYCLE_GRACE_MAX_MS,
    ] {
        let actual = load_root(table_with_soracloud_runtime(&format!(
            "[inrou]\nstart_grace_ms = {value}\nstop_grace_ms = {value}\n"
        )));
        assert_eq!(
            actual.soracloud_runtime.inrou.start_grace,
            StdDuration::from_millis(value)
        );
        assert_eq!(
            actual.soracloud_runtime.inrou.stop_grace,
            StdDuration::from_millis(value)
        );
    }
}
#[test]
fn soracloud_runtime_inrou_bundle_archive_limits_allow_equal_file_total_and_decoded() {
    let table = table_with_soracloud_inrou_values(&[
        ("bundle_archive_max_decoded_bytes", 4_096),
        ("bundle_archive_max_file_bytes", 4_096),
        ("bundle_archive_max_total_file_bytes", 4_096),
    ]);
    let actual = load_root(table);
    let inrou = &actual.soracloud_runtime.inrou;
    assert_all_eq!(
        inrou.bundle_archive_max_decoded_bytes.get() => 4_096,
        inrou.bundle_archive_max_file_bytes.get() => 4_096,
        inrou.bundle_archive_max_total_file_bytes.get() => 4_096,
    );
}
#[test]
fn soracloud_runtime_inrou_bundle_archive_limits_reject_invalid_ordering() {
    for (values, description) in [
        (
            [
                ("bundle_archive_max_file_bytes", 2),
                ("bundle_archive_max_total_file_bytes", 1),
                ("bundle_archive_max_decoded_bytes", 3),
            ],
            "per-file limit above aggregate file limit",
        ),
        (
            [
                ("bundle_archive_max_file_bytes", 1),
                ("bundle_archive_max_total_file_bytes", 2),
                ("bundle_archive_max_decoded_bytes", 1),
            ],
            "aggregate file limit above decoded archive limit",
        ),
    ] {
        let table = table_with_soracloud_inrou_values(&values);
        let result = actual::Root::from_toml_source(TomlSource::inline(table));
        assert!(result.is_err(), "{description} must fail closed");
    }
}
#[test]
fn soracloud_runtime_inrou_bundle_archive_limits_reject_entry_count_above_hard_ceiling() {
    let table = table_with_soracloud_inrou_values(&[(
        "bundle_archive_max_entries",
        i64::from(defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_ENTRIES_LIMIT) + 1,
    )]);
    assert!(
        actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
        "entry count above the hard protocol ceiling must fail closed"
    );
}
#[test]
fn soracloud_runtime_inrou_bounded_byte_limits_accept_exact_hard_ceilings() {
    let values = [
        (
            "guest_image_max_bytes",
            defaults::soracloud_runtime::INROU_GUEST_IMAGE_MAX_BYTES_LIMIT,
        ),
        (
            "bundle_archive_max_compressed_bytes",
            defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_COMPRESSED_BYTES_LIMIT,
        ),
        (
            "bundle_archive_max_decoded_bytes",
            defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_DECODED_BYTES_LIMIT,
        ),
        (
            "bundle_archive_max_file_bytes",
            defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_FILE_BYTES_LIMIT,
        ),
        (
            "bundle_archive_max_total_file_bytes",
            defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_TOTAL_FILE_BYTES_LIMIT,
        ),
    ]
    .map(|(field, value)| {
        (
            field,
            i64::try_from(value).expect("Inrou archive hard ceiling fits i64"),
        )
    });
    let actual = load_root(table_with_soracloud_inrou_values(&values));
    let inrou = &actual.soracloud_runtime.inrou;
    assert_all_eq!(
        inrou.guest_image_max_bytes.get() => defaults::soracloud_runtime::INROU_GUEST_IMAGE_MAX_BYTES_LIMIT,
        inrou.bundle_archive_max_compressed_bytes.get() => defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_COMPRESSED_BYTES_LIMIT,
        inrou.bundle_archive_max_decoded_bytes.get() => defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_DECODED_BYTES_LIMIT,
        inrou.bundle_archive_max_file_bytes.get() => defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_FILE_BYTES_LIMIT,
        inrou.bundle_archive_max_total_file_bytes.get() => defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_TOTAL_FILE_BYTES_LIMIT,
    );
}
#[test]
fn soracloud_runtime_inrou_bounded_byte_limits_reject_hard_ceiling_plus_one() {
    for (field, hard_ceiling) in [
        (
            "guest_image_max_bytes",
            defaults::soracloud_runtime::INROU_GUEST_IMAGE_MAX_BYTES_LIMIT,
        ),
        (
            "bundle_archive_max_compressed_bytes",
            defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_COMPRESSED_BYTES_LIMIT,
        ),
        (
            "bundle_archive_max_decoded_bytes",
            defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_DECODED_BYTES_LIMIT,
        ),
        (
            "bundle_archive_max_file_bytes",
            defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_FILE_BYTES_LIMIT,
        ),
        (
            "bundle_archive_max_total_file_bytes",
            defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_TOTAL_FILE_BYTES_LIMIT,
        ),
    ] {
        let value =
            i64::try_from(hard_ceiling + 1).expect("Inrou archive hard ceiling plus one fits i64");
        let table = table_with_soracloud_inrou_values(&[(field, value)]);
        assert!(
            actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
            "{field} above its hard ceiling must fail closed"
        );
    }
}
fn production_soracloud_submission_table() -> Table {
    let key_pair = checked_onboarding_authority_ed25519_key_fixture();
    let authority = AccountId::new(key_pair.public_key().clone());
    let (_, public_key) = key_pair.public_key().to_bytes();
    Table::from_iter([
        ("fee_payer".into(), Value::String("authority".into())),
        (
            "signer".into(),
            Value::Table(Table::from_iter([
                (
                    "handle".into(),
                    Value::String("software://sorafs/ai/runtime-primary".into()),
                ),
                ("authority".into(), Value::String(authority.to_string())),
                ("algorithm".into(), Value::String("ed25519".into())),
                (
                    "public_key_hex".into(),
                    Value::String(hex::encode(public_key)),
                ),
                ("revision".into(), Value::Integer(7)),
                (
                    "policy_digest_hex".into(),
                    Value::String(hex::encode([0xA7; 32])),
                ),
            ])),
        ),
    ])
}
fn production_soracloud_runtime_table(inrou_enabled: Option<bool>, bounded_egress: bool) -> Table {
    use std::fmt::Write as _;

    let mut source = "production_mode = true\n".to_owned();
    if let Some(enabled) = inrou_enabled {
        write!(
                source,
                r#"
[inrou]
enabled = {enabled}
portable_vm_uid = 70000
portable_vm_gid = 70000
trusted_guest_manifest_digest_hex = "3131313131313131313131313131313131313131313131313131313131313131"
trusted_guest_content_cid = "bafyr6ibrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrge"
max_cpu_millis = 8000
max_memory_bytes = 8589934592
max_storage_bytes = 68719476736
start_grace_ms = 30000
stop_grace_ms = 10000
"#,
            )
            .expect("writing to an owned string cannot fail");
    }
    if bounded_egress {
        source.push_str(
            r"
[egress]
default_allow = false
allowed_hosts = []
rate_per_minute = 60
max_bytes_per_minute = 1048576
",
        );
    }
    let mut table = table_with_soracloud_runtime(&source);
    table
        .get_mut("soracloud_runtime")
        .and_then(Value::as_table_mut)
        .expect("soracloud_runtime table")
        .insert(
            "submission".into(),
            Value::Table(production_soracloud_submission_table()),
        );
    table
}
#[test]
#[should_panic(expected = "egress.rate_per_minute")]
fn soracloud_runtime_production_mode_requires_fail_closed_egress_limits() {
    let _ = load_root(production_soracloud_runtime_table(None, false));
}
#[test]
fn soracloud_runtime_production_mode_accepts_bounded_posture() {
    let actual = load_root(production_soracloud_runtime_table(None, true));
    let runtime = actual.soracloud_runtime;
    assert!(runtime.production_mode);
    assert!(!runtime.inrou.enabled);
    assert_eq!(
        runtime.egress.rate_per_minute.expect("rate quota").get(),
        60
    );
    let signer = runtime
        .submission
        .signer
        .expect("production signer binding");
    assert_all_eq!(
        signer.handle => "software://sorafs/ai/runtime-primary",
        signer.algorithm => Algorithm::Ed25519,
        signer.revision => 7,
        signer.policy_digest => [0xA7; 32],
    );
}
#[test]
fn soracloud_runtime_first_release_accepts_exact_portable_vm_v1() {
    let actual = load_root(production_soracloud_runtime_table(Some(true), true));
    let inrou = actual.soracloud_runtime.inrou;
    assert!(inrou.enabled);
    assert_eq!(inrou.portable_vm_uid.expect("PortableVM uid").get(), 70_000);
    assert_eq!(inrou.portable_vm_gid.expect("PortableVM gid").get(), 70_000);
    let trusted_guest = inrou
        .trusted_guest_artifact
        .expect("exact trusted Inrou guest artifact");
    assert_eq!(trusted_guest.manifest_digest_hex, "31".repeat(32));
    assert_eq!(
        trusted_guest.content_cid,
        "bafyr6ibrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrge"
    );
}
#[test]
fn soracloud_runtime_inrou_requires_the_complete_trusted_guest_artifact() {
    for field in [
        "trusted_guest_manifest_digest_hex",
        "trusted_guest_content_cid",
    ] {
        let mut table = production_soracloud_runtime_table(Some(true), true);
        let removed = table
            .get_mut("soracloud_runtime")
            .and_then(Value::as_table_mut)
            .and_then(|runtime| runtime.get_mut("inrou"))
            .and_then(Value::as_table_mut)
            .expect("production Inrou table")
            .remove(field);
        assert!(removed.is_some(), "fixture must contain {field}");
        assert!(
            actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
            "enabled Inrou hosting must reject a missing {field}"
        );
    }
}
#[test]
fn soracloud_runtime_inrou_host_limits_cover_exact_minimum_physical_cost() {
    let minimum_cpu =
        u64::from(SORA_INROU_MIN_CPU_MILLIS_V1) + SORA_INROU_VMM_CPU_OVERHEAD_MILLIS_V1;
    let minimum_memory = SORA_INROU_MIN_MEMORY_BYTES_V1 + SORA_INROU_VMM_MEMORY_OVERHEAD_BYTES_V1;
    let minimum_storage = SORA_INROU_EPHEMERAL_STORAGE_ALIGNMENT_BYTES_V1;

    let mut exact = production_soracloud_runtime_table(Some(true), true);
    let inrou = exact
        .get_mut("soracloud_runtime")
        .and_then(Value::as_table_mut)
        .and_then(|runtime| runtime.get_mut("inrou"))
        .and_then(Value::as_table_mut)
        .expect("production Inrou table");
    inrou.insert(
        "max_cpu_millis".into(),
        Value::Integer(i64::try_from(minimum_cpu).expect("minimum CPU fits i64")),
    );
    inrou.insert(
        "max_memory_bytes".into(),
        Value::Integer(i64::try_from(minimum_memory).expect("minimum memory fits i64")),
    );
    inrou.insert(
        "max_storage_bytes".into(),
        Value::Integer(i64::try_from(minimum_storage).expect("minimum storage fits i64")),
    );
    let actual = actual::Root::from_toml_source(TomlSource::inline(exact))
        .expect("exact physical Inrou minima are sufficient");
    assert_eq!(
        u64::from(actual.soracloud_runtime.inrou.max_cpu_millis.get()),
        minimum_cpu
    );
    assert_eq!(
        actual.soracloud_runtime.inrou.max_memory_bytes.get(),
        minimum_memory
    );

    for (field, below_minimum) in [
        ("max_cpu_millis", minimum_cpu - 1),
        ("max_memory_bytes", minimum_memory - 1),
        ("max_storage_bytes", minimum_storage - 1),
    ] {
        let mut table = production_soracloud_runtime_table(Some(true), true);
        table
            .get_mut("soracloud_runtime")
            .and_then(Value::as_table_mut)
            .and_then(|runtime| runtime.get_mut("inrou"))
            .and_then(Value::as_table_mut)
            .expect("production Inrou table")
            .insert(
                field.into(),
                Value::Integer(
                    i64::try_from(below_minimum).expect("minimum resource bound fits i64"),
                ),
            );
        assert!(
            actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
            "{field} below the exact physical minimum must fail closed"
        );
    }
}
#[test]
fn soracloud_runtime_sponsor_payer_requires_exact_program() {
    let table = table_with_soracloud_runtime("[submission]\nfee_payer = \"sponsor\"\n");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        actual::Root::from_toml_source(TomlSource::inline(table))
    }));
    let error = result
        .expect("missing sponsor fields must produce diagnostics without unwinding")
        .expect_err("a sponsor payer without its exact program must fail closed");
    let report = format!("{error:?}");
    assert!(
        report.contains("sponsor payer requires fee_program_id"),
        "{report}"
    );
    assert!(
        report.contains("sponsor payer requires fee_program_revision"),
        "{report}"
    );
}
#[test]
fn soracloud_runtime_sponsor_payer_parses_exact_program_revision() {
    let sponsor = iroha_data_model::account::AccountId::new(
        checked_onboarding_authority_ed25519_key_fixture()
            .public_key()
            .clone(),
    );
    let program_id = format!("{sponsor}/runtime");
    let actual = load_root(table_with_soracloud_runtime(&format!(
        "[submission]\nfee_payer = \"sponsor\"\nfee_program_id = \"{program_id}\"\nfee_program_revision = 7\n"
    )));
    let actual::SoracloudRuntimeFeePayer::Sponsor {
        program_id: parsed,
        program_revision,
    } = actual.soracloud_runtime.submission.fee_payer
    else {
        panic!("expected exact sponsor payer");
    };
    assert_eq!(parsed.to_string(), program_id);
    assert_eq!(program_revision, 7);
}
#[test]
fn soracloud_runtime_sponsor_payer_rejects_noncanonical_program_literal() {
    let sponsor = iroha_data_model::account::AccountId::new(
        checked_onboarding_authority_ed25519_key_fixture()
            .public_key()
            .clone(),
    );
    let table = table_with_soracloud_runtime(&format!(
        "[submission]\nfee_payer = \"sponsor\"\nfee_program_id = \" {sponsor}/runtime\"\nfee_program_revision = 7\n"
    ));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        actual::Root::from_toml_source(TomlSource::inline(table))
    }));
    let error = result
        .expect("noncanonical sponsor program literals must not unwind")
        .expect_err("noncanonical sponsor program literals must fail closed");
    let report = format!("{error:?}");
    assert!(
        report.contains("invalid soracloud_runtime.submission.fee_program_id"),
        "{report}"
    );
}
#[test]
fn soracloud_runtime_sponsor_field_errors_accumulate_without_unwinding() {
    let table = table_with_soracloud_runtime(
        "[submission]\nfee_payer = \"sponsor\"\nfee_program_id = \"not-a-program\"\nfee_program_revision = 0\n",
    );
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        actual::Root::from_toml_source(TomlSource::inline(table))
    }));
    let error = result
        .expect("invalid sponsor fields must produce diagnostics without unwinding")
        .expect_err("invalid sponsor fields must fail closed");
    let report = format!("{error:?}");
    assert!(
        report.contains("invalid soracloud_runtime.submission.fee_program_id"),
        "{report}"
    );
    assert!(
        report.contains("fee_program_revision must be greater than zero"),
        "{report}"
    );
}
#[test]
fn soracloud_runtime_authority_payer_rejects_sponsor_fields_without_unwinding() {
    let table = table_with_soracloud_runtime(
        "[submission]\nfee_payer = \"authority\"\nfee_program_id = \"not-a-program\"\nfee_program_revision = 7\n",
    );
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        actual::Root::from_toml_source(TomlSource::inline(table))
    }));
    let error = result
        .expect("authority payer field errors must produce diagnostics without unwinding")
        .expect_err("authority payer must reject sponsor-only fields");
    let report = format!("{error:?}");
    assert!(
        report.contains("fee_program_id is only valid when fee_payer = `sponsor`"),
        "{report}"
    );
    assert!(
        report.contains("fee_program_revision is only valid when fee_payer = `sponsor`"),
        "{report}"
    );
}
#[test]
fn soracloud_runtime_portable_vm_requires_dedicated_identity() {
    let result = actual::Root::from_toml_source(TomlSource::inline(table_with_soracloud_runtime(
        r#"
[inrou]
enabled = true
trusted_guest_manifest_digest_hex = "3131313131313131313131313131313131313131313131313131313131313131"
trusted_guest_content_cid = "bafyr6ibrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrge"
max_cpu_millis = 1000
max_memory_bytes = 1073741824
max_storage_bytes = 10737418240
"#,
    )));
    assert!(
        result.is_err(),
        "PortableVM must fail closed without an explicit uid and gid"
    );
}
#[test]
fn soracloud_runtime_portable_vm_rejects_ids_outside_the_four_slots() {
    for id in [65_536_u32, 69_999, 70_004, 524_287, u32::MAX] {
        let identity_fields = format!("portable_vm_uid = {id}\nportable_vm_gid = {id}");
        let result = actual::Root::from_toml_source(TomlSource::inline(
            table_with_soracloud_runtime(&format!(
                r#"
[inrou]
enabled = true
{identity_fields}
trusted_guest_manifest_digest_hex = "3131313131313131313131313131313131313131313131313131313131313131"
trusted_guest_content_cid = "bafyr6ibrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrge"
max_cpu_millis = 1000
max_memory_bytes = 1073741824
max_storage_bytes = 10737418240
"#,
            )),
        ));
        assert!(
            result.is_err(),
            "primary uid/gid values outside the canonical four-slot reservation must fail closed"
        );
    }
}
#[test]
fn soracloud_runtime_portable_vm_rejects_mismatched_slot_ids() {
    for (uid, gid) in [(70_000_u32, 70_001_u32), (70_003, 70_002)] {
        let result = actual::Root::from_toml_source(TomlSource::inline(
            table_with_soracloud_runtime(&format!(
                r#"
[inrou]
enabled = true
portable_vm_uid = {uid}
portable_vm_gid = {gid}
trusted_guest_manifest_digest_hex = "3131313131313131313131313131313131313131313131313131313131313131"
trusted_guest_content_cid = "bafyr6ibrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrge"
max_cpu_millis = 1000
max_memory_bytes = 1073741824
max_storage_bytes = 10737418240
"#,
            )),
        ));
        assert!(result.is_err(), "uid/gid must select the same Inrou slot");
    }
}
#[test]
fn soracloud_runtime_accepts_all_four_canonical_inrou_slots() {
    for slot in 0..defaults::soracloud_runtime::INROU_PORTABLE_VM_ID_SLOT_COUNT {
        let id = defaults::soracloud_runtime::INROU_PORTABLE_VM_ID_BASE + slot;
        let mut table = production_soracloud_runtime_table(Some(true), true);
        let inrou = table
            .get_mut("soracloud_runtime")
            .and_then(Value::as_table_mut)
            .and_then(|runtime| runtime.get_mut("inrou"))
            .and_then(Value::as_table_mut)
            .expect("production Inrou table");
        inrou.insert("portable_vm_uid".into(), Value::Integer(i64::from(id)));
        inrou.insert("portable_vm_gid".into(), Value::Integer(i64::from(id)));
        let runtime = actual::Root::from_toml_source(TomlSource::inline(table))
            .expect("canonical production Inrou identity slot is valid");
        let inrou = runtime.soracloud_runtime.inrou;
        assert!(inrou.enabled);
        assert_eq!(inrou.portable_vm_uid.expect("PortableVM uid").get(), id);
        assert_eq!(inrou.portable_vm_gid.expect("PortableVM gid").get(), id);
    }
}
#[test]
fn soracloud_runtime_rejects_retired_portable_vm_selectors() {
    for retired in [
        "max_concurrent_vms = 1",
        "backends = [\"portable_vm\"]",
        "portable_vm_acceleration = \"kvm\"",
        "portable_vm_supplementary_gids = [108]",
        "portable_vm_control_dir = \"/run/iroha-inrou-test\"",
    ] {
        let field = retired.split_once(' ').expect("retired selector name").0;
        let error = actual::Root::from_toml_source(TomlSource::inline(
                table_with_soracloud_runtime(&format!(
                    r#"
[inrou]
enabled = true
portable_vm_uid = 70000
portable_vm_gid = 70000
trusted_guest_manifest_digest_hex = "3131313131313131313131313131313131313131313131313131313131313131"
trusted_guest_content_cid = "bafyr6ibrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrge"
{retired}
max_cpu_millis = 1000
max_memory_bytes = 1073741824
max_storage_bytes = 10737418240
"#,
                )),
            ))
            .expect_err("retired first-release selector must be unknown");
        let report = format!("{error:?}");
        assert!(
            report.contains(&format!("unknown field `{field}`")),
            "unexpected retired-selector diagnostic: {report}"
        );
    }
}
#[test]
#[should_panic(expected = "inrou.enabled requires soracloud_runtime.production_mode = true")]
fn soracloud_runtime_nonproduction_rejects_exact_portable_vm_v1() {
    let _ = actual::Root::from_toml_source(TomlSource::inline(table_with_soracloud_runtime(
        r#"
[inrou]
enabled = true
portable_vm_uid = 70000
portable_vm_gid = 70000
trusted_guest_manifest_digest_hex = "3131313131313131313131313131313131313131313131313131313131313131"
trusted_guest_content_cid = "bafyr6ibrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrge"
max_cpu_millis = 1000
max_memory_bytes = 1073741824
max_storage_bytes = 10737418240
"#,
    )));
}
#[test]
fn soracloud_runtime_disabled_inrou_keeps_identity_absent() {
    let actual = load_root(table_with_soracloud_runtime(""));
    assert!(!actual.soracloud_runtime.inrou.enabled);
    assert!(actual.soracloud_runtime.inrou.portable_vm_uid.is_none());
    assert!(actual.soracloud_runtime.inrou.portable_vm_gid.is_none());
    assert!(
        actual
            .soracloud_runtime
            .inrou
            .trusted_guest_artifact
            .is_none()
    );
}
#[test]
fn soracloud_runtime_parse_applies_explicit_overrides() {
    let actual = load_root(table_with_soracloud_runtime(
        r#"
state_dir = "./runtime/custom"
reconcile_interval_ms = 2500
hydration_concurrency = 7
prepared_runtime_cache_capacity = 11

[cache_budgets]
bundle_bytes = 1024
static_asset_bytes = 2048
journal_bytes = 3072
checkpoint_bytes = 4096
model_artifact_bytes = 5120
model_weight_bytes = 6144

[inrou]
guest_image_max_bytes = 12345678
max_cpu_millis = 5000
max_memory_bytes = 5368709120
max_storage_bytes = 10737418240
bundle_archive_max_compressed_bytes = 10000
bundle_archive_max_decoded_bytes = 40000
bundle_archive_max_entries = 123
bundle_archive_max_file_bytes = 20000
bundle_archive_max_total_file_bytes = 30000
start_grace_ms = 7500
stop_grace_ms = 9500

[submission]
fee_payer = "authority"

[egress]
default_allow = true
allowed_hosts = ["cdn.sora.test", "api.sora.test"]
rate_per_minute = 120
max_bytes_per_minute = 262144
"#,
    ));
    let runtime = &actual.soracloud_runtime;
    let inrou = &runtime.inrou;
    let egress = &runtime.egress;
    assert!(
        runtime
            .state_dir
            .to_string_lossy()
            .ends_with("runtime/custom"),
        "resolved path should retain configured suffix: {}",
        runtime.state_dir.display()
    );
    assert_all_eq!(
        runtime.reconcile_interval => StdDuration::from_millis(2_500),
        runtime.hydration_concurrency.get() => 7,
        runtime.prepared_runtime_cache_capacity.get() => 11,
        runtime.cache_budgets.bundle_bytes.get() => 1_024,
        runtime.cache_budgets.model_weight_bytes.get() => 6_144,
        inrou.guest_image_max_bytes.get() => 12_345_678,
        inrou.bundle_archive_max_compressed_bytes.get() => 10_000,
        inrou.bundle_archive_max_decoded_bytes.get() => 40_000,
        inrou.bundle_archive_max_entries.get() => 123,
        inrou.bundle_archive_max_file_bytes.get() => 20_000,
        inrou.bundle_archive_max_total_file_bytes.get() => 30_000,
        inrou.start_grace => StdDuration::from_millis(7_500),
        inrou.stop_grace => StdDuration::from_millis(9_500),
        egress.allowed_hosts => vec!["api.sora.test".to_string(), "cdn.sora.test".to_string()],
        egress.rate_per_minute.expect("rate cap").get() => 120,
        egress.max_bytes_per_minute.expect("byte cap").get() => 262_144,
    );
    assert!(!inrou.enabled);
    assert_eq!(inrou.max_cpu_millis.get(), 5_000);
    assert_eq!(inrou.max_memory_bytes.get(), 5_368_709_120);
    assert_eq!(inrou.max_storage_bytes.get(), 10_737_418_240);
    assert_eq!(inrou.portable_vm_uid, None);
    assert_eq!(inrou.portable_vm_gid, None);
    assert!(matches!(
        &runtime.submission.fee_payer,
        actual::SoracloudRuntimeFeePayer::Authority
    ));
    assert!(egress.default_allow);
}
#[test]
fn soracloud_runtime_rejects_noncanonical_runtime_aliases() {
    let cases = [
        "reconcile_interval_ms = 0\n",
        "[submission]\nfee_payer = \" authority \"\n",
        "[egress]\nallowed_hosts = [\" cdn.sora.test\"]\n",
        "[egress]\nallowed_hosts = [\"\"]\n",
        "[egress]\nallowed_hosts = [\"cdn.sora.test\", \"cdn.sora.test\"]\n",
        "[egress]\nrate_per_minute = 0\n",
        "[egress]\nmax_bytes_per_minute = 0\n",
    ];
    for snippet in cases {
        assert!(
            actual::Root::from_toml_source(TomlSource::inline(table_with_soracloud_runtime(
                snippet
            )))
            .is_err(),
            "noncanonical Soracloud runtime configuration must fail closed: {snippet}"
        );
    }
}
#[test]
fn soracloud_runtime_worker_and_cache_limits_are_bounded() {
    for (field, maximum) in [
        (
            "hydration_concurrency",
            defaults::soracloud_runtime::HYDRATION_CONCURRENCY_MAX,
        ),
        (
            "prepared_runtime_cache_capacity",
            defaults::soracloud_runtime::PREPARED_RUNTIME_CACHE_CAPACITY_MAX,
        ),
    ] {
        actual::Root::from_toml_source(TomlSource::inline(table_with_soracloud_runtime(&format!(
            "{field} = {maximum}\n"
        ))))
        .unwrap_or_else(|error| panic!("{field} must accept its V1 ceiling: {error:?}"));

        let rejected = maximum.checked_add(1).expect("V1 limit plus one");
        let error = actual::Root::from_toml_source(TomlSource::inline(
            table_with_soracloud_runtime(&format!("{field} = {rejected}\n")),
        ))
        .expect_err("values above the V1 ceiling must fail closed");
        let report = format!("{error:?}");
        assert!(
            report.contains(field),
            "out-of-range {field} diagnostic must identify the field: {report}"
        );
    }
}
#[test]
fn content_auth_mode_requires_exact_sponsor_uaid() {
    let uaid = UniversalAccountId::from_hash(iroha_crypto::Hash::new(b"content-sponsor"));
    let canonical = format!("sponsor:{uaid}");
    assert!(matches!(
        parse_content_auth_mode(&canonical),
        ContentAuthMode::Sponsor(parsed) if parsed == uaid
    ));
    let hex = uaid.as_hash().to_string();
    for noncanonical in [
        format!("sponsor:{hex}"),
        format!("sponsor:UAID:{hex}"),
        format!(" sponsor:{uaid}"),
        format!("sponsor:{uaid} "),
    ] {
        assert!(
            std::panic::catch_unwind(|| parse_content_auth_mode(&noncanonical)).is_err(),
            "noncanonical sponsor mode must reject: {noncanonical:?}"
        );
    }
}
include!("user/runtime_tail_tests.rs");
