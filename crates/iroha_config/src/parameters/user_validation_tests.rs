// Configuration validation tests, retaining the original module and cfg.
#[cfg(test)]
mod duration_clamp_tests {
    use super::{
        AssetDefinitionId, BTreeSet, ConfidentialComputeMechanism, ContentAuthMode,
        DaManifestPolicy, DomainId, Emitter, NexusFees, NonZeroU64,
        RETIRED_LANE_FUNCTIONAL_METADATA_KEYS, SORA_INROU_EPHEMERAL_STORAGE_ALIGNMENT_BYTES_V1,
        SORA_INROU_MIN_CPU_MILLIS_V1, SORA_INROU_MIN_MEMORY_BYTES_V1,
        SORA_INROU_VMM_CPU_OVERHEAD_MILLIS_V1, SORA_INROU_VMM_MEMORY_OVERHEAD_BYTES_V1,
        UniversalAccountId, Url, parse_content_auth_mode,
    };
    use crate::parameters::{
        actual, defaults,
        user::{LaneValidatorModeConfig, SoracloudRuntime},
    };
    use iroha_config_base::{
        read::ConfigReader,
        toml::TomlSource,
        util::{Bytes, DurationMs},
    };
    use iroha_crypto::{Algorithm, ExposedPrivateKey, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        NetworkId,
        account::AccountId,
        block::BlockHeader,
        sorafs::orderbook::{
            ORDERBOOK_MAX_FILLS_PER_EXECUTION_V1, ORDERBOOK_MAX_MAINTENANCE_ITEMS_V1,
        },
    };
    use iroha_model_base::{name::Name, topology::LaneId};
    use iroha_primitives::numeric::Quantity;
    use std::{
        fs,
        num::NonZeroUsize,
        path::{Path, PathBuf},
        str::FromStr,
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, Duration as StdDuration},
    };
    use toml::{Table, Value};
    static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);
    struct TestDir(PathBuf);
    impl TestDir {
        fn create(label: &str) -> Self {
            for _ in 0..1024 {
                let sequence = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "iroha-config-{label}-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("create test directory {}: {error}", path.display()),
                }
            }
            panic!("could not allocate a unique configuration test directory");
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    const MINIMAL_CONFIG: &str = r#"
chain = "00000000-0000-0000-0000-000000000000"
public_key = "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2"
private_key = "8926201CA347641228C3B79AA43839DEDC85FA51C0E8B9B6A00F6B0D6B0423E902973F"
soranet_transport_public_key = "ed0120D9F6AEF1813164294D1D9C0662FEB9C7F7861B4DFFE385680331093DA4ABD10B"
soranet_transport_private_key = "802620134C4527B3852AE2218A8F079B301C651EAD8C7567B96BD7A9BE8DB366E46B89"
trusted_peers_pop = [
  { public_key = "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2", pop_hex = "8515da750f81182aaba5c22fc9f03a01e81ed85e4495a2ca6b29a71c0c8549537e31e79cddf6ff285b9e22d0d9dc17ce0f46e7d0cf78b2ef9feab50c849a1ea8e1e4f07e966f6113faa8a999317545d9f111b8e08a7273913710b43a20b19c08" }
]

[network]
address = "addr:127.0.0.1:1337#8F78"
public_address = "addr:127.0.0.1:1337#8F78"

[torii]
address = "addr:127.0.0.1:8080#8942"

[genesis]
public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
expected_hash = "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"

[streaming]
identity_public_key = "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB"
identity_private_key = "8026208F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F"
"#;
    fn base_table() -> Table {
        toml::from_str(MINIMAL_CONFIG).expect("parse minimal config")
    }
    include!("user/torii_https_transport_tests.rs");
    fn four_validator_roster_table() -> Table {
        let mut table = base_table();
        let base_public_key = table
            .get("public_key")
            .and_then(Value::as_str)
            .expect("minimal config public key")
            .to_owned();
        let mut trusted_peers = vec![Value::String(format!("{base_public_key}@127.0.0.1:1337"))];
        let trusted_peers_pop = table
            .get_mut("trusted_peers_pop")
            .and_then(Value::as_array_mut)
            .expect("minimal config trusted peer PoP array");
        for (index, seed) in [0x91, 0x92, 0x93].into_iter().enumerate() {
            let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                .expect("deterministic BLS validator fixture");
            let public_key = key_pair.public_key().to_string();
            let pop = iroha_crypto::bls_normal_pop_prove(key_pair.private_key())
                .expect("derive BLS validator PoP");
            trusted_peers.push(Value::String(format!(
                "{public_key}@127.0.0.1:{}",
                1338 + index
            )));
            let mut pop_entry = Table::new();
            pop_entry.insert("public_key".into(), Value::String(public_key));
            pop_entry.insert("pop_hex".into(), Value::String(hex::encode(pop)));
            trusted_peers_pop.push(Value::Table(pop_entry));
        }
        table.insert("trusted_peers".into(), Value::Array(trusted_peers));
        table
    }
    fn load_root(table: Table) -> actual::Root {
        actual::Root::from_toml_source(TomlSource::inline(table)).expect("load minimal config")
    }
    fn load_user_root(table: Table) -> super::Root {
        ConfigReader::new()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<super::Root>()
            .expect("load minimal user config")
    }
    #[test]
    fn runtime_provider_broker_endpoint_is_public_bounded_and_exact() {
        let default = load_root(base_table());
        assert_eq!(
            default.runtime_provider_broker.endpoint_path.as_path(),
            Path::new(defaults::runtime_provider_broker::ENDPOINT_PATH)
        );
        let custom = "/var/iroha-seat-7/runtime-provider-broker-v1.sock";
        let mut table = base_table();
        table.insert(
            "runtime_provider_broker".to_owned(),
            Value::Table(Table::from_iter([(
                "endpoint_path".to_owned(),
                Value::String(custom.to_owned()),
            )])),
        );
        let configured = load_root(table);
        assert_eq!(
            configured.runtime_provider_broker.endpoint_path.as_path(),
            Path::new(custom)
        );
        assert_eq!(
            custom
                .parse::<actual::RuntimeProviderBrokerEndpointPath>()
                .expect("parse standalone endpoint")
                .as_path(),
            Path::new(custom)
        );
        for invalid in [
            "runtime-provider-broker-v1.sock",
            "/var/./runtime-provider-broker-v1.sock",
            "/var/../runtime-provider-broker-v1.sock",
            "/var//runtime-provider-broker-v1.sock",
            "/var/runtime-provider-broker-v1.sock/",
            "/var\\run/runtime-provider-broker-v1.sock",
            "/var/line\nfeed/runtime-provider-broker-v1.sock",
            "/var/other.sock",
        ] {
            assert!(
                invalid
                    .parse::<actual::RuntimeProviderBrokerEndpointPath>()
                    .is_err(),
                "invalid standalone path {invalid:?}"
            );
            let mut table = base_table();
            table.insert(
                "runtime_provider_broker".to_owned(),
                Value::Table(Table::from_iter([(
                    "endpoint_path".to_owned(),
                    Value::String(invalid.to_owned()),
                )])),
            );
            assert!(
                actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
                "invalid config path {invalid:?}"
            );
        }
        let oversized = format!("/{}/runtime-provider-broker-v1.sock", "a".repeat(103));
        assert!(
            oversized
                .parse::<actual::RuntimeProviderBrokerEndpointPath>()
                .is_err()
        );
    }
    #[test]
    fn musubi_private_custody_root_projects_through_user_and_actual_layers() {
        assert_eq!(
            actual::MusubiPublication::default().custody_root,
            PathBuf::from(defaults::musubi_publication::CUSTODY_ROOT),
        );
        let default = load_root(base_table()).musubi_publication.custody_root;
        assert!(default.ends_with("storage/musubi-publication"));

        let mut table = base_table();
        let mut publication = Table::new();
        let configured_path = std::env::current_dir()
            .expect("current directory")
            .join("musubi-private-v1");
        publication.insert(
            "custody_root".into(),
            Value::String(configured_path.to_string_lossy().into_owned()),
        );
        table.insert("musubi_publication".into(), Value::Table(publication));
        let configured = load_root(table).musubi_publication.custody_root;
        assert_eq!(configured, configured_path);
    }
    #[test]
    fn musubi_private_tls_listener_projects_only_non_secret_settings() {
        let default = load_root(base_table()).musubi_publication;
        assert_eq!(
            default.private_tls_bind,
            defaults::musubi_publication::private_tls_bind()
        );
        assert_eq!(
            default.max_inflight_requests,
            defaults::musubi_publication::MAX_INFLIGHT_REQUESTS
        );
        let mut table = base_table();
        let mut publication = Table::new();
        publication.insert(
            "private_tls_bind".into(),
            Value::String("127.0.0.1:18496".to_owned()),
        );
        publication.insert("max_inflight_requests".into(), Value::Integer(3));
        table.insert("musubi_publication".into(), Value::Table(publication));
        let configured = load_root(table).musubi_publication;
        assert_eq!(configured.private_tls_bind.to_string(), "127.0.0.1:18496");
        assert_eq!(configured.max_inflight_requests, 3);
    }
    #[test]
    fn musubi_private_tls_listener_rejects_invalid_public_geometry() {
        for (field, value) in [
            ("private_tls_bind", Value::String("not-a-socket".to_owned())),
            ("max_inflight_requests", Value::Integer(5)),
        ] {
            let mut table = base_table();
            let mut publication = Table::new();
            publication.insert(field.into(), value);
            table.insert("musubi_publication".into(), Value::Table(publication));
            assert!(actual::Root::from_toml_source(TomlSource::inline(table)).is_err());
        }
    }
    #[test]
    fn musubi_private_tls_listener_rejects_retired_mount_configuration() {
        for prefix in ["/private", "/operator", "/"] {
            let mut table = base_table();
            let mut publication = Table::new();
            publication.insert("private_mount_prefix".into(), Value::String(prefix.into()));
            table.insert("musubi_publication".into(), Value::Table(publication));
            let error = actual::Root::from_toml_source(TomlSource::inline(table))
                .expect_err("the dedicated listener has only fixed routes");
            assert!(error.frames().any(|frame| matches!(
                frame.downcast_ref::<iroha_config_base::read::Error>(),
                Some(iroha_config_base::read::Error::UnknownParameters)
            )));
            let unknown: Vec<_> = error
                .frames()
                .filter_map(|frame| {
                    frame.downcast_ref::<iroha_config_base::attach::UnknownParameter>()
                })
                .map(ToString::to_string)
                .collect();
            assert_eq!(
                unknown,
                vec!["unknown parameter: `musubi_publication.private_mount_prefix`".to_owned()]
            );
        }
    }
    #[test]
    fn musubi_publication_resource_and_receipt_policy_comes_from_config() {
        let default = load_root(base_table()).musubi_publication;
        assert_eq!(
            default.journal_max_operations,
            defaults::musubi_publication::JOURNAL_MAX_OPERATIONS
        );
        assert_eq!(
            default.journal_max_authorizations,
            defaults::musubi_publication::JOURNAL_MAX_AUTHORIZATIONS
        );
        assert_eq!(
            default.journal_max_total_response_bytes,
            defaults::musubi_publication::JOURNAL_MAX_TOTAL_RESPONSE_BYTES
        );
        assert_eq!(
            default.journal_max_snapshot_bytes,
            defaults::musubi_publication::JOURNAL_MAX_SNAPSHOT_BYTES
        );
        assert_eq!(
            default.max_seed_records,
            defaults::musubi_publication::MAX_SEED_RECORDS
        );
        assert_eq!(
            default.max_seed_bytes,
            defaults::musubi_publication::MAX_SEED_BYTES
        );
        assert_eq!(
            default.max_future_clock_skew_ms,
            defaults::musubi_publication::MAX_FUTURE_CLOCK_SKEW_MS
        );
        assert_eq!(
            default.receipt_lifetime_ms,
            defaults::musubi_publication::RECEIPT_LIFETIME_MS
        );

        let mut table = base_table();
        let mut publication = Table::new();
        for (field, value) in [
            ("journal_max_operations", 2_048),
            ("journal_max_authorizations", 8_192),
            ("journal_max_total_response_bytes", 24 * 1024 * 1024),
            ("journal_max_snapshot_bytes", 32 * 1024 * 1024),
            ("max_seed_records", 32),
            ("max_seed_bytes", 512 * 1024 * 1024),
            ("max_future_clock_skew_ms", 3_000),
            ("receipt_lifetime_ms", 120_000),
        ] {
            publication.insert(field.into(), Value::Integer(value));
        }
        table.insert("musubi_publication".into(), Value::Table(publication));
        let configured = load_root(table).musubi_publication;
        assert_eq!(configured.journal_max_operations, 2_048);
        assert_eq!(configured.journal_max_authorizations, 8_192);
        assert_eq!(
            configured.journal_max_total_response_bytes,
            24 * 1024 * 1024
        );
        assert_eq!(configured.journal_max_snapshot_bytes, 32 * 1024 * 1024);
        assert_eq!(configured.max_seed_records, 32);
        assert_eq!(configured.max_seed_bytes, 512 * 1024 * 1024);
        assert_eq!(configured.max_future_clock_skew_ms, 3_000);
        assert_eq!(configured.receipt_lifetime_ms, 120_000);
    }
    #[test]
    fn musubi_publication_rejects_invalid_resource_and_receipt_policy() {
        for (field, value) in [
            ("journal_max_operations", 0),
            ("journal_max_operations", 1_000_001),
            ("journal_max_authorizations", 0),
            ("journal_max_authorizations", 1_000_001),
            ("journal_max_total_response_bytes", 16 * 1024 * 1024 - 1),
            ("journal_max_total_response_bytes", 64 * 1024 * 1024 + 1),
            ("journal_max_snapshot_bytes", 32 * 1024 * 1024),
            ("journal_max_snapshot_bytes", 96 * 1024 * 1024 + 1),
            ("max_seed_records", 0),
            ("max_seed_records", 1_025),
            ("max_seed_bytes", 0),
            ("max_seed_bytes", 64 * 1024 * 1024 * 1024 + 1),
            ("max_future_clock_skew_ms", 30_001),
            ("receipt_lifetime_ms", 0),
            ("receipt_lifetime_ms", 24 * 60 * 60 * 1_000 + 1),
        ] {
            let mut table = base_table();
            let mut publication = Table::new();
            publication.insert(field.into(), Value::Integer(value));
            table.insert("musubi_publication".into(), Value::Table(publication));
            assert!(
                actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
                "invalid {field}={value} was accepted"
            );
        }
    }
    #[test]
    fn musubi_paid_pin_policy_projects_exact_public_identity_without_credentials() {
        let default = load_root(base_table()).musubi_publication;
        assert_eq!(
            default.pin_storage_class,
            iroha_data_model::sorafs::pin_registry::StorageClass::Hot,
        );
        assert_eq!(
            default.pin_retention_horizon_secs,
            defaults::musubi_publication::PIN_RETENTION_HORIZON_SECS,
        );
        assert_eq!(
            default.pin_transaction_authority,
            actual::MusubiPinTransactionAuthority::IngressBroker,
        );

        let key = KeyPair::try_from_seed(vec![0x71; 32], Algorithm::Ed25519)
            .expect("pin account fixture");
        let pin_account = AccountId::new(key.public_key().clone());
        let mut table = base_table();
        let mut publication = Table::new();
        publication.insert("pin_storage_class".into(), Value::String("warm".to_owned()));
        publication.insert(
            "pin_retention_horizon_secs".into(),
            Value::Integer(90 * 24 * 60 * 60),
        );
        publication.insert(
            "pin_transaction_authority".into(),
            Value::String(pin_account.to_string()),
        );
        table.insert("musubi_publication".into(), Value::Table(publication));
        let configured = load_root(table).musubi_publication;
        assert_eq!(
            configured.pin_storage_class,
            iroha_data_model::sorafs::pin_registry::StorageClass::Warm,
        );
        assert_eq!(configured.pin_retention_horizon_secs, 90 * 24 * 60 * 60);
        assert_eq!(
            configured.pin_transaction_authority,
            actual::MusubiPinTransactionAuthority::Account(pin_account),
        );
    }
    #[test]
    fn musubi_paid_pin_policy_rejects_noncanonical_or_unfundable_geometry() {
        let deadline = i64::from(
            iroha_data_model::sorafs::pin_registry::SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1,
        );
        for horizon in [
            deadline + 1,
            i64::try_from(defaults::musubi_publication::MAX_PIN_RETENTION_HORIZON_SECS)
                .expect("bounded test value"),
        ] {
            let mut table = base_table();
            let mut publication = Table::new();
            publication.insert("pin_retention_horizon_secs".into(), Value::Integer(horizon));
            table.insert("musubi_publication".into(), Value::Table(publication));
            assert_eq!(
                load_root(table)
                    .musubi_publication
                    .pin_retention_horizon_secs,
                u64::try_from(horizon).expect("positive horizon"),
            );
        }
        for (field, value) in [
            ("pin_storage_class", Value::String("HOT".to_owned())),
            ("pin_storage_class", Value::String(" warm".to_owned())),
            (
                "pin_transaction_authority",
                Value::String("INGRESS_BROKER".to_owned()),
            ),
            (
                "pin_transaction_authority",
                Value::String("alice@wonderland".to_owned()),
            ),
            ("pin_retention_horizon_secs", Value::Integer(deadline)),
            (
                "pin_retention_horizon_secs",
                Value::Integer(
                    i64::try_from(defaults::musubi_publication::MAX_PIN_RETENTION_HORIZON_SECS + 1)
                        .expect("bounded test value"),
                ),
            ),
        ] {
            let mut table = base_table();
            let mut publication = Table::new();
            publication.insert(field.into(), value);
            table.insert("musubi_publication".into(), Value::Table(publication));
            assert!(
                actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
                "invalid Musubi paid-pin {field} was accepted",
            );
        }
    }
    #[test]
    fn network_enum_labels_reject_aliases_without_panicking() {
        for (field, value) in [("lane_profile", "CORE"), ("lane_profile", " core")] {
            let mut table = base_table();
            table
                .get_mut("network")
                .and_then(Value::as_table_mut)
                .expect("network table")
                .insert(field.to_owned(), Value::String(value.to_owned()));
            let result = std::panic::catch_unwind(|| {
                actual::Root::from_toml_source(TomlSource::inline(table))
            });
            let parsed = result.expect("ordinary network config errors must not unwind");
            assert!(parsed.is_err(), "{field}={value:?} must fail closed");
        }
    }
    fn torii_http_table_mut(table: &mut Table) -> &mut Table {
        table
            .get_mut("torii")
            .and_then(Value::as_table_mut)
            .expect("torii table")
            .entry("transport")
            .or_insert_with(|| Value::Table(Table::new()))
            .as_table_mut()
            .expect("torii.transport table")
            .entry("http")
            .or_insert_with(|| Value::Table(Table::new()))
            .as_table_mut()
            .expect("torii.transport.http table")
    }
    fn assert_torii_http_config_rejected(values: &[(&str, i64)], expected: &str) {
        let mut table = base_table();
        let http = torii_http_table_mut(&mut table);
        for (field, value) in values {
            http.insert((*field).to_owned(), Value::Integer(*value));
        }
        let error = actual::Root::from_toml_source(TomlSource::inline(table))
            .expect_err("invalid Torii HTTP transport limits must fail closed");
        let report = format!("{error:?}");
        assert!(report.contains(expected), "{report}");
    }
    fn provider_table_mut<'a>(table: &'a mut Table, section: &str) -> &'a mut Table {
        table
            .entry(section)
            .or_insert_with(|| Value::Table(Table::new()))
            .as_table_mut()
            .expect("provider configuration section")
    }
    fn set_global_beacon_provider_binding(
        table: &mut Table,
        handle: Option<&str>,
        revision: Option<i64>,
        policy_digest_hex: Option<&str>,
    ) {
        let section = provider_table_mut(table, "sumeragi");
        if let Some(handle) = handle {
            section.insert(
                "global_beacon_partial_signer_provider_handle".into(),
                Value::String(handle.to_owned()),
            );
        }
        if let Some(revision) = revision {
            section.insert(
                "global_beacon_partial_signer_provider_revision".into(),
                Value::Integer(revision),
            );
        }
        if let Some(policy_digest_hex) = policy_digest_hex {
            section.insert(
                "global_beacon_partial_signer_provider_policy_digest_hex".into(),
                Value::String(policy_digest_hex.to_owned()),
            );
        }
    }
    #[test]
    fn mint_finality_seed_accepts_only_validator_private_descriptor_199() {
        let mut accepted = base_table();
        provider_table_mut(&mut accepted, "sumeragi")
            .insert("mint_finality_seed_fd".into(), Value::Integer(199));
        assert_eq!(
            load_root(accepted).sumeragi.mint_finality_seed_fd,
            Some(199)
        );
        for fd in [0, 198, 200, 65535] {
            let mut rejected = base_table();
            provider_table_mut(&mut rejected, "sumeragi")
                .insert("mint_finality_seed_fd".into(), Value::Integer(fd));
            assert!(
                actual::Root::from_toml_source(TomlSource::inline(rejected)).is_err(),
                "descriptor {fd} must not become a second seed source"
            );
        }
        let mut observer = base_table();
        let section = provider_table_mut(&mut observer, "sumeragi");
        section.insert("role".into(), Value::String("observer".into()));
        section.insert("mint_finality_seed_fd".into(), Value::Integer(199));
        assert!(actual::Root::from_toml_source(TomlSource::inline(observer)).is_err());
    }
    fn set_parliament_tle_provider_binding(
        table: &mut Table,
        handle: Option<&str>,
        revision: Option<i64>,
        policy_digest_hex: Option<&str>,
    ) {
        let section = provider_table_mut(table, "gov");
        if let Some(handle) = handle {
            section.insert(
                "parliament_tle_partial_release_signer_provider_handle".into(),
                Value::String(handle.to_owned()),
            );
        }
        if let Some(revision) = revision {
            section.insert(
                "parliament_tle_partial_release_signer_provider_revision".into(),
                Value::Integer(revision),
            );
        }
        if let Some(policy_digest_hex) = policy_digest_hex {
            section.insert(
                "parliament_tle_partial_release_signer_provider_policy_digest_hex".into(),
                Value::String(policy_digest_hex.to_owned()),
            );
        }
    }
    #[test]
    fn consensus_signer_provider_bindings_are_exact_and_public_only() {
        let beacon_digest = "11".repeat(32);
        let tle_digest = "22".repeat(32);
        let mut table = base_table();
        set_global_beacon_provider_binding(
            &mut table,
            Some("software://iroha/global-beacon/primary"),
            Some(7),
            Some(&beacon_digest),
        );
        set_parliament_tle_provider_binding(
            &mut table,
            Some("software://iroha/parliament-tle/primary"),
            Some(9),
            Some(&tle_digest),
        );
        let parsed = load_root(table);
        assert_eq!(
            parsed
                .sumeragi
                .global_beacon_partial_signer_provider_handle
                .as_deref(),
            Some("software://iroha/global-beacon/primary")
        );
        assert_eq!(
            parsed
                .sumeragi
                .global_beacon_partial_signer_provider_policy_digest,
            Some([0x11; 32])
        );
        assert_eq!(
            parsed
                .gov
                .parliament_tle_partial_release_signer_provider_handle
                .as_deref(),
            Some("software://iroha/parliament-tle/primary")
        );
        assert_eq!(
            parsed
                .gov
                .parliament_tle_partial_release_signer_provider_policy_digest,
            Some([0x22; 32])
        );
    }
    #[test]
    fn consensus_signer_provider_bindings_reject_partial_inert_and_test_marked_values() {
        let valid_digest = "31".repeat(32);
        for (handle, revision, digest) in [
            (Some("software://iroha/global-beacon/primary"), None, None),
            (None, Some(1), Some(valid_digest.as_str())),
            (Some(""), Some(1), Some(valid_digest.as_str())),
            (Some("   "), Some(1), Some(valid_digest.as_str())),
            (
                Some("software://iroha/global-beacon/test"),
                Some(1),
                Some(valid_digest.as_str()),
            ),
            (
                Some("software://iroha/global-beacon/mock"),
                Some(1),
                Some(valid_digest.as_str()),
            ),
            (
                Some("software://iroha/global-beacon/demo"),
                Some(1),
                Some(valid_digest.as_str()),
            ),
            (
                Some("software://iroha/global-beacon/primary"),
                Some(0),
                Some(valid_digest.as_str()),
            ),
            (
                Some("software://iroha/global-beacon/primary"),
                Some(1),
                Some("00"),
            ),
        ] {
            let mut table = base_table();
            set_global_beacon_provider_binding(&mut table, handle, revision, digest);
            assert!(
                actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
                "invalid beacon provider binding must fail: {handle:?}/{revision:?}/{digest:?}"
            );
        }

        let mut partial_tle = base_table();
        set_parliament_tle_provider_binding(
            &mut partial_tle,
            Some("software://iroha/parliament-tle/primary"),
            Some(1),
            None,
        );
        assert!(actual::Root::from_toml_source(TomlSource::inline(partial_tle)).is_err());
    }
    #[test]
    fn observer_cannot_configure_consensus_share_providers() {
        let digest = "41".repeat(32);
        for configure_tle in [false, true] {
            let mut table = base_table();
            provider_table_mut(&mut table, "sumeragi")
                .insert("role".into(), Value::String("observer".into()));
            if configure_tle {
                set_parliament_tle_provider_binding(
                    &mut table,
                    Some("software://iroha/parliament-tle/primary"),
                    Some(1),
                    Some(&digest),
                );
            } else {
                set_global_beacon_provider_binding(
                    &mut table,
                    Some("software://iroha/global-beacon/primary"),
                    Some(1),
                    Some(&digest),
                );
            }
            assert!(actual::Root::from_toml_source(TomlSource::inline(table)).is_err());
        }
    }
    #[test]
    fn torii_http_per_ip_connection_limit_must_not_exceed_global_limit() {
        assert_torii_http_config_rejected(
            &[("max_connections", 16), ("max_connections_per_ip", 17)],
            "max_connections_per_ip must not exceed max_connections",
        );
    }
    #[test]
    fn torii_http_timeouts_must_be_nonzero() {
        for (field, expected) in [
            (
                "header_read_timeout_ms",
                "header_read_timeout_ms must be greater than zero",
            ),
            (
                "write_timeout_ms",
                "write_timeout_ms must be greater than zero",
            ),
        ] {
            assert_torii_http_config_rejected(&[(field, 0)], expected);
        }
    }
    #[test]
    fn torii_http_parser_limits_are_bounded() {
        for max_header_bytes in [8 * 1024 - 1, 1024 * 1024 + 1] {
            assert_torii_http_config_rejected(
                &[("max_header_bytes", max_header_bytes)],
                "max_header_bytes must be between 8192 and 1048576",
            );
        }
        assert_torii_http_config_rejected(
            &[("max_headers", 1025)],
            "max_headers must not exceed 1024",
        );
    }
    #[test]
    fn torii_preauth_ban_capacity_is_configurable_and_nonzero() {
        let mut table = base_table();
        table
            .get_mut("torii")
            .and_then(Value::as_table_mut)
            .expect("torii table")
            .insert("preauth_ban_capacity".into(), Value::Integer(17));
        let actual = load_root(table);
        assert_eq!(actual.torii.preauth_ban_capacity.get(), 17);
        let mut table = base_table();
        table
            .get_mut("torii")
            .and_then(Value::as_table_mut)
            .expect("torii table")
            .insert("preauth_ban_capacity".into(), Value::Integer(0));
        assert!(
            actual::Root::from_toml_source(TomlSource::inline(table)).is_err(),
            "a zero ban capacity would disable retention and defeat temporary bans"
        );
    }
    #[test]
    fn config_secret_subtree_debug_output_redacts_private_keys() {
        let key_pair = KeyPair::try_from_seed(
            b"iroha:config:test:debug-redaction".to_vec(),
            Algorithm::Ed25519,
        )
        .expect("deterministic private key");
        let private_key = key_pair.private_key().clone();
        let canonical_private_key = ExposedPrivateKey(private_key.clone()).to_string();
        let mut config = load_user_root(base_table());
        config.snapshot.signing_private_key = Some(private_key.clone());
        config.network.soranet_vpn.operator_account_id =
            AccountId::new(key_pair.public_key().clone()).to_string();
        config.network.soranet_vpn.operator_private_key = Some(private_key.clone());
        config.torii.receipt_public_key = Some(key_pair.public_key().clone());
        config.torii.receipt_private_key = Some(private_key.clone());
        config.torii.ram_lfe = Some(super::ToriiRamLfe {
            programs: vec![super::ToriiRamLfeProgram {
                program_id: "phone_retail".to_owned(),
                secret_hex: "01020304".parse().expect("valid RAM-LFE secret"),
                hidden_program_hex: iroha_crypto::default_bfv_programmed_hidden_program(),
                signer_private_key: private_key,
                receipt_ttl_ms: None,
            }],
        });
        let debug_outputs = [
            ("snapshot", format!("{:?}", config.snapshot)),
            ("SoraNet VPN", format!("{:?}", config.network.soranet_vpn)),
            ("torii receipt", format!("{:?}", config.torii)),
            (
                "RAM-LFE program",
                format!(
                    "{:?}",
                    &config
                        .torii
                        .ram_lfe
                        .as_ref()
                        .expect("configured RAM-LFE")
                        .programs[0]
                ),
            ),
        ];
        for (subtree, debug) in debug_outputs {
            assert!(debug.contains("REDACTED"), "{subtree}: {debug}");
            assert!(
                !debug.contains(&canonical_private_key),
                "{subtree} leaked canonical private-key material: {debug}"
            );
        }
        let actual = config.parse().expect("valid secret-bearing configuration");
        for (subtree, debug) in [
            ("actual snapshot", format!("{:?}", actual.snapshot)),
            (
                "actual SoraNet VPN",
                format!("{:?}", actual.network.soranet_vpn),
            ),
            ("actual Torii", format!("{:?}", actual.torii)),
            ("actual RAM-LFE", format!("{:?}", actual.torii.ram_lfe)),
        ] {
            assert!(debug.contains("REDACTED"), "{subtree}: {debug}");
            assert!(
                !debug.contains(&canonical_private_key),
                "{subtree} leaked canonical private-key material: {debug}"
            );
        }
    }
    #[test]
    fn torii_debug_output_redacts_runtime_credentials_and_verifiers() {
        const BANK_BEARER: &str = "torii-bank-bearer-SENTINEL";
        const OPERATOR_BOOTSTRAP: &str = "torii-operator-bootstrap-SENTINEL";
        const RPC_CANARY: &str = "torii-rpc-canary-SENTINEL";
        const TAIKAI_BEARER: &str = "torii-taikai-bearer-SENTINEL";
        const ONBOARDING_VERIFIER: &str = "blake3:torii-onboarding-verifier-SENTINEL";
        const GOVERNANCE_KEY_HEX: &str =
            "a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7";
        const URL_PASSWORD: &str = "torii-url-password-SENTINEL";
        const URL_QUERY_SECRET: &str = "torii-url-query-SENTINEL";

        let key_pair = KeyPair::try_from_seed(
            b"iroha:config:test:torii-secret-debug".to_vec(),
            Algorithm::Ed25519,
        )
        .expect("deterministic Torii debug public key");
        let credential_url = Url::parse(&format!(
            "https://operator:{URL_PASSWORD}@service.example/?token={URL_QUERY_SECRET}"
        ))
        .expect("credential-bearing test URL");

        let mut user = load_user_root(base_table());
        user.torii.peer_telemetry_urls = vec![credential_url.clone()];
        user.torii.peer_geo.endpoint = Some(credential_url.clone());
        user.torii.operator_auth.tokens = vec![OPERATOR_BOOTSTRAP.to_owned()];
        user.torii.transport.norito_rpc.allowed_clients = vec![RPC_CANARY.to_owned()];
        user.torii.da_ingest.governance_metadata_key_hex = Some(GOVERNANCE_KEY_HEX.to_owned());
        user.torii.da_ingest.taikai_anchor = Some(super::DaTaikaiAnchor {
            endpoint: credential_url.to_string(),
            api_token: Some(TAIKAI_BEARER.to_owned()),
            receipt_public_key: key_pair.public_key().clone(),
            poll_interval_secs: 1,
            request_timeout_secs: 1,
        });
        user.torii.push.apns_endpoint = Some(credential_url.to_string());
        user.torii.recipient_lookup = Some(super::ToriiRecipientLookup {
            policy_id: "cbuae_aed_sbp_pkr".to_owned(),
            requests_per_minute: 1,
            request_timeout_ms: DurationMs(Duration::from_millis(1)),
            routes: vec![super::ToriiRecipientLookupRoute {
                fi_id: "hbl.sbp".to_owned(),
                base_url: credential_url.to_string(),
                bearer_token: BANK_BEARER.to_owned(),
            }],
        });
        let user_credential = super::AccountOnboardingCredential {
            id: "debug-credential".to_owned(),
            scope: super::AccountOnboardingCredentialScope {
                domain: None,
                dataspace: Some("debug-dataspace".to_owned()),
            },
            token_hash: ONBOARDING_VERIFIER.to_owned(),
            token: None,
        };
        let user_debug = vec![
            ("user Torii", format!("{:?}", user.torii)),
            (
                "user operator auth",
                format!("{:?}", user.torii.operator_auth),
            ),
            (
                "user Norito-RPC",
                format!("{:?}", user.torii.transport.norito_rpc),
            ),
            (
                "user recipient route",
                format!(
                    "{:?}",
                    &user
                        .torii
                        .recipient_lookup
                        .as_ref()
                        .expect("configured recipient lookup")
                        .routes[0]
                ),
            ),
            ("user DA ingest", format!("{:?}", user.torii.da_ingest)),
            ("user push", format!("{:?}", user.torii.push)),
            ("user onboarding credential", format!("{user_credential:?}")),
        ];

        let mut actual = load_root(base_table());
        actual.torii.peer_telemetry_urls = vec![credential_url.clone()];
        actual.torii.peer_geo.endpoint = Some(credential_url.clone());
        actual.torii.operator_auth.tokens = vec![OPERATOR_BOOTSTRAP.to_owned()];
        actual.torii.transport.norito_rpc.allowed_clients = vec![RPC_CANARY.to_owned()];
        actual.torii.da_ingest.governance_metadata_key = Some([0xa7; 32]);
        actual.torii.da_ingest.taikai_anchor = Some(actual::DaTaikaiAnchor {
            endpoint: credential_url.clone(),
            api_token: Some(TAIKAI_BEARER.to_owned()),
            receipt_public_key: key_pair.public_key().clone(),
            poll_interval: Duration::from_secs(1),
            request_timeout: Duration::from_secs(1),
        });
        actual.torii.push.apns_endpoint = Some(credential_url.clone());
        actual.torii.recipient_lookup.routes = vec![actual::ToriiRecipientLookupRoute {
            fi_id: "hbl.sbp".to_owned(),
            base_url: credential_url,
            bearer_token: BANK_BEARER.to_owned(),
        }];
        let actual_credential = actual::AccountOnboardingCredential {
            id: "debug_credential".parse().expect("valid credential id"),
            scope: actual::AccountOnboardingCredentialScope::Dataspace(
                "debug_dataspace".parse().expect("valid dataspace name"),
            ),
            token_hash: [0xa7; 32],
        };
        let actual_debug = vec![
            ("actual Torii", format!("{:?}", actual.torii)),
            (
                "actual operator auth",
                format!("{:?}", actual.torii.operator_auth),
            ),
            (
                "actual Norito-RPC",
                format!("{:?}", actual.torii.transport.norito_rpc),
            ),
            (
                "actual recipient route",
                format!("{:?}", &actual.torii.recipient_lookup.routes[0]),
            ),
            ("actual DA ingest", format!("{:?}", actual.torii.da_ingest)),
            ("actual push", format!("{:?}", actual.torii.push)),
            (
                "actual onboarding credential",
                format!("{actual_credential:?}"),
            ),
        ];
        let actual_verifier = format!("{:?}", [0xa7_u8; 32]);
        let secrets = [
            BANK_BEARER,
            OPERATOR_BOOTSTRAP,
            RPC_CANARY,
            TAIKAI_BEARER,
            ONBOARDING_VERIFIER,
            GOVERNANCE_KEY_HEX,
            URL_PASSWORD,
            URL_QUERY_SECRET,
            actual_verifier.as_str(),
        ];
        for (subtree, debug) in user_debug.into_iter().chain(actual_debug) {
            assert!(debug.contains("REDACTED"), "{subtree}: {debug}");
            assert!(
                debug.contains("configured"),
                "{subtree} lost useful configuration-presence metadata: {debug}"
            );
            for secret in secrets {
                assert!(
                    !debug.contains(secret),
                    "{subtree} leaked Torii credential material {secret:?}: {debug}"
                );
            }
        }
    }
    fn native_signer_binding_toml(
        role: &str,
        handle_role: &str,
        context: &str,
        seed: u8,
    ) -> String {
        let signer =
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("native signer");
        let public_key_hex = hex::encode(signer.public_key().to_bytes().1);
        let authority = AccountId::new(signer.public_key().clone())
            .to_i105_for_discriminant(defaults::common::CHAIN_DISCRIMINANT)
            .expect("native signer authority");
        let policy_digest_hex = hex::encode([seed; 32]);
        format!(
            r#"
[storage.native_transaction_signers.{role}]
handle = "software://sorafs/{handle_role}/{context}-primary"
authority = "{authority}"
algorithm = "ed25519"
public_key_hex = "{public_key_hex}"
revision = 1
policy_digest_hex = "{policy_digest_hex}"
"#
        )
    }
    fn native_signer_bindings_toml(context: &str, seeds: [u8; 4]) -> String {
        let mut source = String::new();
        for ((role, handle_role), seed) in [
            ("proof_outcome", "proof-outcome"),
            ("repair", "repair"),
            ("reserve", "reserve"),
            ("orderbook", "orderbook"),
        ]
        .into_iter()
        .zip(seeds)
        {
            source.push_str(&native_signer_binding_toml(
                role,
                handle_role,
                context,
                seed,
            ));
        }
        source
    }
    fn table_with_soracloud_inrou_values(values: &[(&str, i64)]) -> Table {
        let mut table = base_table();
        let runtime = table
            .entry("soracloud_runtime")
            .or_insert_with(|| Value::Table(Table::new()))
            .as_table_mut()
            .expect("soracloud_runtime table");
        let inrou = runtime
            .entry("inrou")
            .or_insert_with(|| Value::Table(Table::new()))
            .as_table_mut()
            .expect("soracloud_runtime.inrou table");
        for (field, value) in values {
            inrou.insert((*field).to_owned(), Value::Integer(*value));
        }
        table
    }
    #[test]
    fn pre_release_settlement_enablement_and_catalog_keys_are_rejected() {
        for (key, value) in [
            ("enabled", Value::Boolean(false)),
            ("escrow_required", Value::Boolean(true)),
            ("escrow_accounts", Value::Table(Table::new())),
        ] {
            let mut table = base_table();
            let settlement = table
                .entry("settlement")
                .or_insert_with(|| Value::Table(Table::new()))
                .as_table_mut()
                .expect("settlement table");
            settlement.insert(
                "offline".into(),
                Value::Table(Table::from_iter([(key.into(), value)])),
            );
            let error = actual::Root::from_toml_source(TomlSource::inline(table))
                .expect_err("retired pre-release settlement keys must be rejected");
            assert!(
                format!("{error:?}").contains("`settlement.offline`"),
                "unexpected error: {error:?}"
            );
        }
    }
    #[test]
    fn removed_kagemusha_sections_are_unknown_parameters() {
        for (parent, child, key, value) in [
            (
                "torii",
                "kagemusha_v1_commands",
                "operation_registry_max_entries",
                Value::Integer(4096),
            ),
            (
                "settlement",
                "kagemusha",
                "allow_testnet_experimental_release",
                Value::Boolean(false),
            ),
        ] {
            let mut table = base_table();
            table
                .entry(parent)
                .or_insert_with(|| Value::Table(Table::new()))
                .as_table_mut()
                .expect("parent table")
                .insert(
                    child.into(),
                    Value::Table(Table::from_iter([(key.into(), value)])),
                );
            let error = actual::Root::from_toml_source(TomlSource::inline(table))
                .expect_err("removed KAGEMUSHA configuration must be rejected, not aliased");
            assert!(
                format!("{error:?}").contains(&format!("`{parent}.{child}`")),
                "unexpected error: {error:?}"
            );
        }
    }
    #[test]
    fn zk_prover_scan_budget_must_fit_one_maximum_body() {
        let mut table = base_table();
        let torii = table
            .get_mut("torii")
            .and_then(Value::as_table_mut)
            .expect("torii table");
        let minimum = defaults::torii::ZK_PROVER_ATTACHMENT_BODY_MAX_BYTES_V1;
        torii.insert(
            "zk_prover_max_scan_bytes".into(),
            Value::Integer(i64::try_from(minimum - 1).expect("minimum fits TOML integer")),
        );
        let error = actual::Root::from_toml_source(TomlSource::inline(table))
            .expect_err("sub-body scan budget must fail closed");
        let report = format!("{error:?}");
        assert!(
            report.contains("zk_prover_max_scan_bytes must be at least"),
            "{report}"
        );
        let mut table = base_table();
        table
            .get_mut("torii")
            .and_then(Value::as_table_mut)
            .expect("torii table")
            .insert(
                "zk_prover_max_scan_bytes".into(),
                Value::Integer(i64::try_from(minimum).expect("minimum fits TOML integer")),
            );
        assert_eq!(
            load_root(table).torii.zk_prover_max_scan_bytes,
            minimum,
            "the closed minimum scan budget must remain valid"
        );
    }
    include!("user/zk_prover_report_retention_tests.rs");
    include!("user/zk_attachment_retention_tests.rs");
    include!("user/query_fanout_memory_tests.rs");
    include!("user/app_routed_read_body_timeout_tests.rs");
    include!("user/torii_api_connect_exactness_tests.rs");
    include!("user/operator_signature_body_timeout_tests.rs");
    include!("user/verified_source_ingress_tests.rs");
    include!("user/iso_bridge_store_memory_tests.rs");
    #[test]
    fn absence_of_pre_release_switch_does_not_mask_malformed_settlement_parent() {
        let mut table = base_table();
        table.insert(
            "settlement".into(),
            Value::String("not-a-settlement-table".into()),
        );
        let error = actual::Root::from_toml_source(TomlSource::inline(table))
            .expect_err("a malformed settlement namespace must remain strict");
        assert!(format!("{error:?}").contains("settlement"));
    }
    fn sorafs_table_mut(table: &mut Table) -> &mut Table {
        table
            .entry("sorafs")
            .or_insert_with(|| Value::Table(Table::new()))
            .as_table_mut()
            .expect("sorafs table")
    }
    #[test]
    fn top_level_sorafs_policy_override_reaches_actual_config() {
        let mut table = base_table();
        let sorafs = sorafs_table_mut(&mut table);
        let appeal_finance = sorafs
            .entry("appeal_finance_settlement")
            .or_insert_with(|| Value::Table(Table::new()))
            .as_table_mut()
            .expect("appeal finance table");
        appeal_finance.insert("worker_max_retry_attempts".into(), Value::Integer(17));
        let actual = load_root(table);
        assert_eq!(
            actual
                .torii
                .sorafs_appeal_finance_settlement
                .worker_max_retry_attempts,
            17
        );
    }
    #[test]
    fn legacy_torii_sorafs_config_path_is_rejected() {
        let mut table = base_table();
        let torii = table
            .get_mut("torii")
            .and_then(Value::as_table_mut)
            .expect("torii table");
        let mut appeal_finance = Table::new();
        appeal_finance.insert("worker_max_retry_attempts".into(), Value::Integer(17));
        let mut legacy_sorafs = Table::new();
        legacy_sorafs.insert(
            "appeal_finance_settlement".into(),
            Value::Table(appeal_finance),
        );
        torii.insert("sorafs".into(), Value::Table(legacy_sorafs));
        let error = ConfigReader::new()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<super::Root>()
            .expect_err("legacy torii.sorafs path must be unknown");
        assert!(
            format!("{error:?}").contains("sorafs"),
            "unexpected legacy-path error: {error:?}"
        );
    }
    #[test]
    fn retired_settlement_repo_config_is_rejected() {
        let mut table = base_table();
        let settlement = table
            .entry("settlement")
            .or_insert_with(|| Value::Table(Table::new()))
            .as_table_mut()
            .expect("settlement table");
        settlement.insert(
            "repo".into(),
            Value::Table(Table::from_iter([(
                "default_haircut_bps".into(),
                Value::Integer(1_500),
            )])),
        );
        let error = ConfigReader::new()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<super::Root>()
            .expect_err("retired settlement.repo configuration must be unknown");
        assert!(
            format!("{error:?}").contains("repo"),
            "unexpected retired-config error: {error:?}"
        );
    }
    fn nexus_table_mut(table: &mut Table) -> &mut Table {
        table
            .entry("nexus")
            .or_insert_with(|| Value::Table(Table::new()))
            .as_table_mut()
            .expect("nexus table")
    }
    fn set_valid_autoscale_defaults(nexus: &mut Table) {
        let mut autoscale = Table::new();
        autoscale.insert("enabled".into(), Value::Boolean(true));
        autoscale.insert("min_lane_id".into(), Value::Integer(1));
        autoscale.insert("max_lane_id_exclusive".into(), Value::Integer(3));
        autoscale.insert("target_block_ms".into(), Value::Integer(1_000));
        autoscale.insert("scale_out_latency_ratio".into(), Value::Float(2.0));
        autoscale.insert("scale_in_latency_ratio".into(), Value::Float(0.5));
        autoscale.insert("scale_out_utilization_ratio".into(), Value::Float(0.8));
        autoscale.insert("scale_in_utilization_ratio".into(), Value::Float(0.2));
        autoscale.insert("scale_out_window_blocks".into(), Value::Integer(2));
        autoscale.insert("scale_in_window_blocks".into(), Value::Integer(2));
        autoscale.insert("cooldown_blocks".into(), Value::Integer(1));
        autoscale.insert("per_lane_target_tps".into(), Value::Integer(100));
        nexus.insert("autoscale".into(), Value::Table(autoscale));
    }
    fn set_lane_count(nexus: &mut Table, lane_count: i64) {
        nexus.insert("lane_count".into(), Value::Integer(lane_count));
    }
    fn lane_descriptor(index: i64, alias: &str) -> Value {
        let mut lane = Table::new();
        lane.insert("index".into(), Value::Integer(index));
        lane.insert("alias".into(), Value::String(alias.to_owned()));
        lane.insert("metadata".into(), Value::Table(Table::new()));
        Value::Table(lane)
    }
    fn routing_policy_table(default_lane: i64) -> Value {
        let mut routing = Table::new();
        routing.insert("default_lane".into(), Value::Integer(default_lane));
        routing.insert("rules".into(), Value::Array(Vec::new()));
        Value::Table(routing)
    }
    #[test]
    fn nexus_lane_shard_id_has_one_typed_configuration_surface() {
        let mut table = base_table();
        let nexus = nexus_table_mut(&mut table);
        set_lane_count(nexus, 2);
        let mut sharded = lane_descriptor(1, "sharded");
        {
            let sharded = sharded.as_table_mut().expect("lane descriptor table");
            sharded.insert("shard_id".into(), Value::Integer(9));
        }
        nexus.insert(
            "lane_catalog".into(),
            Value::Array(vec![lane_descriptor(0, "primary"), sharded]),
        );

        let actual = load_root(table);
        let lane_id = iroha_model_base::topology::LaneId::new(1);
        let lane = actual
            .nexus
            .lane_catalog
            .lanes()
            .iter()
            .find(|lane| lane.id == lane_id)
            .expect("configured sharded lane");
        assert_eq!(
            lane.shard_id,
            Some(iroha_model_base::topology::ShardId::new(9)),
            "the typed shard_id field must survive catalog construction"
        );
        assert!(!lane.metadata.contains_key("da_shard_id"));
        assert_eq!(actual.nexus.lane_config.shard_id(lane_id), 9);

        let mut table = base_table();
        let nexus = nexus_table_mut(&mut table);
        let mut lane = lane_descriptor(0, "primary");
        lane.as_table_mut()
            .and_then(|lane| lane.get_mut("metadata"))
            .and_then(Value::as_table_mut)
            .expect("lane metadata table")
            .insert("da_shard_id".into(), Value::String("9".into()));
        nexus.insert("lane_catalog".into(), Value::Array(vec![lane]));
        let error = actual::Root::from_toml_source(TomlSource::inline(table))
            .expect_err("the internal shard metadata key must not be a configuration alias");
        assert!(format!("{error:?}").contains("use the typed `shard_id` field"));
    }
    #[test]
    fn nexus_lane_functional_metadata_fails_closed() {
        for retired_key in RETIRED_LANE_FUNCTIONAL_METADATA_KEYS.into_iter().chain([
            "confidential_future_policy",
            "scheduler.future_policy",
            "settlement.buffer_future_policy",
        ]) {
            let mut table = base_table();
            let nexus = nexus_table_mut(&mut table);
            set_lane_count(nexus, 1);
            let mut lane = lane_descriptor(0, "primary");
            let lane = lane.as_table_mut().expect("lane descriptor table");
            lane.insert(
                "metadata".into(),
                Value::Table(Table::from_iter([(
                    retired_key.into(),
                    Value::String("retired".into()),
                )])),
            );
            nexus.insert(
                "lane_catalog".into(),
                Value::Array(vec![Value::Table(lane.clone())]),
            );
            let error = actual::Root::from_toml_source(TomlSource::inline(table))
                .expect_err("invalid functional lane metadata must fail configuration loading");
            let report = format!("{error:?}");
            assert!(
                report.contains("retired") && report.contains(retired_key),
                "retired key `{retired_key}` produced an unexpected error: {report}"
            );
        }
    }
    #[test]
    fn nexus_lane_typed_functional_policy_loads_from_toml() {
        let mut table = base_table();
        let nexus = nexus_table_mut(&mut table);
        set_lane_count(nexus, 1);
        let mut lane = lane_descriptor(0, "private");
        let lane = lane.as_table_mut().expect("lane descriptor table");
        let settlement_account = AccountId::new(
            KeyPair::try_from_seed(vec![0xA6; 32], Algorithm::Ed25519)
                .expect("settlement account key")
                .public_key()
                .clone(),
        );
        let settlement_asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("settlement", "universal").expect("settlement domain"),
            "xor".parse().expect("asset name"),
        );
        lane.insert("storage".into(), Value::String("split_replica".into()));
        lane.insert("manifest_policy".into(), Value::String("audit".into()));
        lane.insert(
            "confidential_compute".into(),
            Value::Table(Table::from_iter([
                ("mechanism".into(), Value::String("secret_sharing".into())),
                ("key_version".into(), Value::Integer(7)),
                (
                    "allowed_audiences".into(),
                    Value::Array(vec![
                        Value::String("operator".into()),
                        Value::String("auditor".into()),
                        Value::String("operator".into()),
                    ]),
                ),
            ])),
        );
        lane.insert(
            "scheduler".into(),
            Value::Table(Table::from_iter([
                ("teu_capacity".into(), Value::Integer(2048)),
                ("starvation_bound_slots".into(), Value::Integer(6)),
            ])),
        );
        lane.insert(
            "settlement_buffer".into(),
            Value::Table(Table::from_iter([
                (
                    "account_id".into(),
                    Value::String(settlement_account.to_string()),
                ),
                (
                    "asset_definition_id".into(),
                    Value::String(settlement_asset.to_string()),
                ),
                ("capacity".into(), Value::String("1500".into())),
            ])),
        );
        nexus.insert(
            "lane_catalog".into(),
            Value::Array(vec![Value::Table(lane.clone())]),
        );

        let actual = load_root(table);
        let lane = actual
            .nexus
            .lane_catalog
            .lanes()
            .first()
            .expect("configured lane");
        assert_eq!(lane.manifest_policy, DaManifestPolicy::Audit);
        let policy = lane
            .confidential_compute
            .as_ref()
            .expect("typed confidential policy");
        assert_eq!(
            policy.mechanism,
            ConfidentialComputeMechanism::SecretSharing
        );
        assert_eq!(policy.key_version.get(), 7);
        assert_eq!(
            policy.allowed_audiences,
            BTreeSet::from(["auditor".to_owned(), "operator".to_owned()])
        );
        let scheduler = lane.scheduler.as_ref().expect("typed scheduler policy");
        assert_eq!(scheduler.teu_capacity.map(NonZeroU64::get), Some(2048));
        assert_eq!(
            scheduler.starvation_bound_slots.map(NonZeroU64::get),
            Some(6)
        );
        let settlement = lane
            .settlement_buffer
            .as_ref()
            .expect("typed settlement buffer policy");
        assert_eq!(settlement.account_id, settlement_account);
        assert_eq!(settlement.asset_definition_id, settlement_asset);
        assert_eq!(settlement.capacity.to_string(), "1500");
        let derived = actual
            .nexus
            .lane_config
            .entry(LaneId::SINGLE)
            .expect("derived lane entry");
        assert_eq!(derived.scheduler.as_ref(), lane.scheduler.as_ref());
        assert_eq!(
            derived.settlement_buffer.as_ref(),
            lane.settlement_buffer.as_ref()
        );
    }
    #[test]
    fn nexus_lane_scheduler_and_settlement_policy_fail_closed() {
        for (field, value, expected) in [
            (
                "scheduler",
                Value::Table(Table::from_iter([(
                    "teu_capacity".into(),
                    Value::Integer(0),
                )])),
                "positive u64",
            ),
            (
                "settlement_buffer",
                Value::Table(Table::from_iter([(
                    "capacity".into(),
                    Value::String("0".into()),
                )])),
                "must define",
            ),
        ] {
            let mut table = base_table();
            let nexus = nexus_table_mut(&mut table);
            set_lane_count(nexus, 1);
            let mut lane = lane_descriptor(0, "primary");
            lane.as_table_mut()
                .expect("lane descriptor table")
                .insert(field.into(), value);
            nexus.insert("lane_catalog".into(), Value::Array(vec![lane]));
            let error = actual::Root::from_toml_source(TomlSource::inline(table))
                .expect_err("invalid typed lane policy must fail configuration loading");
            assert!(
                format!("{error:?}").contains(expected),
                "unexpected `{field}` error: {error:?}"
            );
        }
    }
    #[test]
    fn nexus_fee_settlement_mode_accepts_direct_and_rejects_retired_modes() {
        {
            let canonical = "direct";
            let mut fees = NexusFees::default();
            fees.settlement_mode = canonical.to_owned();
            let mut emitter = Emitter::new();
            let parsed = fees.parse(&mut emitter);
            assert!(
                parsed.is_some(),
                "canonical settlement mode `{canonical}` must parse"
            );
            assert!(emitter.into_result().is_ok());
        }
        for alias in [
            "lane_relay_burn",
            "lane-relay-burn",
            "Lane_Relay_Burn",
            " direct",
            "direct ",
        ] {
            let mut fees = NexusFees::default();
            fees.settlement_mode = alias.to_owned();
            let mut emitter = Emitter::new();
            let parsed = fees.parse(&mut emitter);
            assert!(
                parsed.is_none(),
                "non-canonical settlement mode `{alias}` must fail closed"
            );
            assert!(emitter.into_result().is_err());
        }
    }
    #[test]
    fn lane_validator_mode_json_roundtrips_canonical_values_only() {
        for (mode, canonical) in [
            (LaneValidatorModeConfig::StakeElected, "stake_elected"),
            (LaneValidatorModeConfig::AdminManaged, "admin_managed"),
        ] {
            let encoded = norito::json::to_string(&mode).expect("serialize validator mode");
            assert_eq!(encoded, format!("\"{canonical}\""));
            assert_eq!(
                norito::json::from_str::<LaneValidatorModeConfig>(&encoded)
                    .expect("deserialize canonical validator mode"),
                mode
            );
        }
        for alias in [
            "stake",
            "stake-elected",
            "staking",
            "admin",
            "admin-managed",
            "peer-admin",
            "permissioned",
            "STAKE_ELECTED",
            " admin_managed",
        ] {
            assert!(
                alias.parse::<LaneValidatorModeConfig>().is_err(),
                "non-canonical alias `{alias}` must be rejected"
            );
            let encoded_alias = format!("\"{alias}\"");
            assert!(
                norito::json::from_str::<LaneValidatorModeConfig>(&encoded_alias).is_err(),
                "JSON must reject non-canonical alias `{alias}`"
            );
        }
    }
    fn checked_onboarding_authority_ed25519_key_fixture() -> iroha_crypto::KeyPair {
        iroha_crypto::KeyPair::try_random_with_algorithm(iroha_crypto::Algorithm::Ed25519)
            .expect("generate checked onboarding authority Ed25519 key fixture")
    }
    #[test]
    fn nexus_lane_catalog_rejects_unimplemented_kzg_proof_scheme() {
        let mut table = base_table();
        let nexus = nexus_table_mut(&mut table);
        let mut lane = lane_descriptor(0, "default");
        lane.as_table_mut()
            .expect("lane descriptor table")
            .insert("proof_scheme".into(), Value::String("kzg_bls12_381".into()));
        nexus.insert("lane_catalog".into(), Value::Array(vec![lane]));
        let error = actual::Root::from_toml_source(TomlSource::inline(table))
            .expect_err("V1 configuration must reject KZG");
        let report = format!("{error:?}");
        assert!(
            report.contains("V1 supports only `merkle_sha256`")
                && report.contains("separately reviewed future protocol version"),
            "{report}"
        );
    }
    #[test]
    fn onboarding_authority_fixture_uses_checked_ed25519_key_generation() {
        let key_pair = checked_onboarding_authority_ed25519_key_fixture();
        let algorithm = key_pair
            .public_key()
            .try_algorithm()
            .expect("onboarding authority fixture key advertises a valid algorithm");
        assert_eq!(algorithm, iroha_crypto::Algorithm::Ed25519);
    }
    #[test]
    fn retired_lane_emergency_configuration_is_always_unknown() {
        for (name, value) in [
            ("enabled", Value::Boolean(false)),
            ("enabled", Value::Boolean(true)),
            ("multisig_threshold", Value::Integer(3)),
            ("multisig_members", Value::Integer(5)),
            ("max_ttl_blocks", Value::Integer(20)),
        ] {
            let mut table = base_table();
            let mut retired = Table::new();
            retired.insert(name.into(), value);
            nexus_table_mut(&mut table)
                .insert("lane_relay_emergency".into(), Value::Table(retired));
            let error = actual::Root::from_toml_source(TomlSource::inline(table))
                .expect_err("retired emergency committee filling has no configuration path");
            let report = format!("{error:?}");
            assert!(report.contains("unknown parameter"), "{report}");
            assert!(report.contains("nexus.lane_relay_emergency"), "{report}");
        }
    }
    #[test]
    fn nexus_enabled_is_rejected_as_an_unknown_parameter() {
        for enabled in [true, false] {
            let mut table = base_table();
            nexus_table_mut(&mut table).insert("enabled".into(), Value::Boolean(enabled));
            let error = actual::Root::from_toml_source(TomlSource::inline(table))
                .expect_err("the retired Nexus runtime switch must be unknown");
            let report = format!("{error:?}");
            assert!(report.contains("unknown parameter"), "{report}");
            assert!(report.contains("nexus.enabled"), "{report}");
        }
    }
    #[test]
    fn nexus_autoscale_parse_rejects_default_lane_inside_elastic_range() {
        let mut table = base_table();
        let nexus = nexus_table_mut(&mut table);
        set_valid_autoscale_defaults(nexus);
        set_lane_count(nexus, 4);
        nexus.insert(
            "lane_catalog".into(),
            Value::Array(vec![
                lane_descriptor(0, "default"),
                lane_descriptor(1, "manual-one"),
                lane_descriptor(3, "governance"),
            ]),
        );
        nexus.insert("routing_policy".into(), routing_policy_table(1));
        let error = actual::Root::from_toml_source(TomlSource::inline(table))
            .expect_err("default lane must be below the autoscale elastic range");
        let report = format!("{error:?}");
        assert!(
            report.contains("nexus.routing_policy.default_lane 1 must be below nexus.autoscale.min_lane_id 1 when autoscale is enabled"),
            "{report}"
        );
    }
    #[test]
    fn nexus_autoscale_parse_rejects_default_lane_above_elastic_range() {
        let mut table = base_table();
        let nexus = nexus_table_mut(&mut table);
        set_valid_autoscale_defaults(nexus);
        set_lane_count(nexus, 4);
        nexus.insert(
            "lane_catalog".into(),
            Value::Array(vec![
                lane_descriptor(0, "default"),
                lane_descriptor(3, "governance"),
            ]),
        );
        nexus.insert("routing_policy".into(), routing_policy_table(3));
        let error = actual::Root::from_toml_source(TomlSource::inline(table))
            .expect_err("high-side default lane must be rejected");
        let report = format!("{error:?}");
        assert!(
            report.contains("nexus.routing_policy.default_lane 3 must be below nexus.autoscale.min_lane_id 1 when autoscale is enabled"),
            "{report}"
        );
    }
    #[test]
    fn nexus_autoscale_parse_rejects_manual_lane_inside_elastic_range() {
        let mut table = base_table();
        let nexus = nexus_table_mut(&mut table);
        set_valid_autoscale_defaults(nexus);
        set_lane_count(nexus, 4);
        nexus.insert(
            "lane_catalog".into(),
            Value::Array(vec![
                lane_descriptor(0, "default"),
                lane_descriptor(1, "manual-one"),
                lane_descriptor(3, "governance"),
            ]),
        );
        let error = actual::Root::from_toml_source(TomlSource::inline(table))
            .expect_err("manual lanes cannot occupy the autoscale elastic range");
        let report = format!("{error:?}");
        assert!(
            report.contains(
                "nexus.lane_catalog lane 1 is inside reserved autoscale elastic lane id range [1, 3)"
            ),
            "{report}"
        );
    }
    fn assert_reserved_autoscale_metadata_rejected(key: &str, value: &str, error_context: &str) {
        let mut table = base_table();
        let nexus = nexus_table_mut(&mut table);
        set_valid_autoscale_defaults(nexus);
        set_lane_count(nexus, 4);
        let mut default_lane = lane_descriptor(0, "default");
        default_lane
            .as_table_mut()
            .and_then(|lane| lane.get_mut("metadata"))
            .and_then(Value::as_table_mut)
            .expect("lane metadata table")
            .insert(key.into(), Value::String(value.to_owned()));
        nexus.insert(
            "lane_catalog".into(),
            Value::Array(vec![default_lane, lane_descriptor(3, "governance")]),
        );
        let error =
            actual::Root::from_toml_source(TomlSource::inline(table)).expect_err(error_context);
        let report = format!("{error:?}");
        assert!(
            report.contains(&format!(
                "metadata key `{key}` is reserved for the consensus autoscaler"
            )),
            "{report}"
        );
    }
    #[test]
    fn nexus_autoscale_parse_rejects_reserved_managed_metadata() {
        assert_reserved_autoscale_metadata_rejected(
            "autoscale.managed",
            "true",
            "operators must not set reserved autoscale metadata",
        );
    }
    #[test]
    fn nexus_autoscale_parse_rejects_reserved_created_height_metadata() {
        assert_reserved_autoscale_metadata_rejected(
            "autoscale.created_height",
            "42",
            "operators must not set reserved autoscale marker metadata",
        );
    }
    #[test]
    fn nexus_autoscale_parse_rejects_reserved_drain_state_metadata() {
        assert_reserved_autoscale_metadata_rejected(
            "autoscale.drain_state",
            "forged",
            "operators must not forge consensus lane drain state",
        );
    }
    #[test]
    fn nexus_autoscale_parse_rejects_reserved_committee_metadata() {
        assert_reserved_autoscale_metadata_rejected(
            "autoscale.committee_v1",
            "forged",
            "operators must not forge an elastic-lane committee pin",
        );
    }
    struct OnboardingKeyFile(PathBuf);
    impl OnboardingKeyFile {
        fn new(key_pair: &KeyPair) -> Self {
            use std::io::Write as _;
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "iroha-config-onboarding-{}-{}.key",
                std::process::id(),
                NEXT_FILE.fetch_add(1, Ordering::Relaxed)
            ));
            let encoded = ExposedPrivateKey(key_pair.private_key().clone())
                .try_to_multihash_string()
                .expect("encode onboarding test private key");
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options
                .open(&path)
                .expect("create private onboarding test key file");
            let owned = Self(path);
            file.write_all(format!("{encoded}\n").as_bytes())
                .expect("write onboarding test key file");
            owned
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for OnboardingKeyFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    fn onboarding_credential(
        id: &str,
        scope_key: &str,
        scope_value: &str,
        token_hash: &str,
    ) -> Value {
        let mut scope = Table::new();
        scope.insert(scope_key.into(), Value::String(scope_value.to_owned()));
        let mut credential = Table::new();
        credential.insert("id".into(), Value::String(id.to_owned()));
        credential.insert("scope".into(), Value::Table(scope));
        credential.insert("token_hash".into(), Value::String(token_hash.to_owned()));
        Value::Table(credential)
    }
    fn table_with_account_onboarding(key_pair: &KeyPair, key_file: &Path) -> Table {
        let authority = AccountId::new(key_pair.public_key().clone());
        let mut auto_renew = Table::new();
        auto_renew.insert("term_years".into(), Value::Integer(2));
        auto_renew.insert("max_amount".into(), Value::String("25".to_owned()));
        auto_renew.insert("renew_before_expiry_ms".into(), Value::Integer(86_400_000));
        auto_renew.insert("retry_backoff_ms".into(), Value::Integer(3_600_000));
        auto_renew.insert("max_failures".into(), Value::Integer(5));
        let mut account_onboarding = Table::new();
        account_onboarding.insert("authority".into(), Value::String(authority.to_string()));
        account_onboarding.insert(
            "private_key_file".into(),
            Value::String(key_file.display().to_string()),
        );
        account_onboarding.insert("lease_term_years".into(), Value::Integer(2));
        account_onboarding.insert(
            "additional_permissions".into(),
            Value::Array(vec![Value::String("CanManagePeers".to_owned())]),
        );
        account_onboarding.insert(
            "fee_sponsor_program_id".into(),
            Value::String(format!("{authority}/retail")),
        );
        account_onboarding.insert(
            "credentials".into(),
            Value::Array(vec![
                onboarding_credential(
                    "local-domain",
                    "domain",
                    "wonderland.universal",
                    &format!("blake3:{}", "ab".repeat(32)),
                ),
                onboarding_credential(
                    "local-dataspace",
                    "dataspace",
                    "universal",
                    &format!("blake3:{}", "cd".repeat(32)),
                ),
            ]),
        );
        account_onboarding.insert("auto_renew".into(), Value::Table(auto_renew));
        let mut table = base_table();
        table
            .get_mut("torii")
            .and_then(Value::as_table_mut)
            .expect("torii table")
            .insert(
                "account_onboarding".into(),
                Value::Table(account_onboarding),
            );
        table
    }
    #[test]
    fn account_onboarding_absence_disables_it() {
        let actual = load_user_root(base_table())
            .parse()
            .expect("parse config without onboarding");
        assert!(actual.torii.account_onboarding.is_none());
    }
    #[test]
    fn account_onboarding_accepts_explicit_dpn_user_permission() {
        let key_pair = checked_onboarding_authority_ed25519_key_fixture();
        let key_file = OnboardingKeyFile::new(&key_pair);
        let mut table = table_with_account_onboarding(&key_pair, key_file.path());
        table
            .get_mut("torii")
            .and_then(Value::as_table_mut)
            .and_then(|torii| torii.get_mut("account_onboarding"))
            .and_then(Value::as_table_mut)
            .expect("account onboarding table")
            .insert(
                "additional_permissions".into(),
                Value::Array(vec![Value::String("DpnUser".to_owned())]),
            );
        let onboarding = load_user_root(table)
            .parse()
            .expect("DpnUser is a supported unscoped onboarding permission")
            .torii
            .account_onboarding
            .expect("account onboarding configured");
        assert_eq!(
            onboarding.additional_permissions,
            vec![Name::from_str("DpnUser").expect("permission name")]
        );
    }
    #[test]
    fn account_onboarding_defaults_to_no_additional_permissions() {
        let key_pair = checked_onboarding_authority_ed25519_key_fixture();
        let key_file = OnboardingKeyFile::new(&key_pair);
        let mut table = table_with_account_onboarding(&key_pair, key_file.path());
        table
            .get_mut("torii")
            .and_then(Value::as_table_mut)
            .and_then(|torii| torii.get_mut("account_onboarding"))
            .and_then(Value::as_table_mut)
            .expect("account onboarding table")
            .remove("additional_permissions");
        let onboarding = load_user_root(table)
            .parse()
            .expect("additional permissions remain opt-in")
            .torii
            .account_onboarding
            .expect("account onboarding configured");
        assert!(onboarding.additional_permissions.is_empty());
    }
    #[test]
    fn account_onboarding_rejects_unsupported_and_scoped_additional_permissions() {
        for unsupported in [
            "CanDoThing",
            "DpnAdmin",
            "DpnInori",
            "CanManageAccountAlias",
            "CanResolveAccountAlias",
            "CanEnrollFeeSponsorProgram",
        ] {
            let mut emitter = Emitter::new();
            assert!(
                super::AccountOnboarding::parse_permissions(
                    vec!["DpnUser".to_owned(), unsupported.to_owned()],
                    &mut emitter,
                )
                .is_none(),
                "unsupported additional permission `{unsupported}` must fail closed"
            );
            let error = emitter
                .into_result()
                .expect_err("invalid permission reported");
            assert!(format!("{error:?}").contains(&format!(
                "additional_permissions[1] `{unsupported}` is not a supported unscoped default permission"
            )));
        }
    }
    #[test]
    fn account_onboarding_rejects_duplicate_dpn_user_permission() {
        let mut emitter = Emitter::new();
        assert!(
            super::AccountOnboarding::parse_permissions(
                vec!["DpnUser".to_owned(), "DpnUser".to_owned()],
                &mut emitter,
            )
            .is_none()
        );
        let error = emitter
            .into_result()
            .expect_err("duplicate permission reported");
        assert!(format!("{error:?}").contains("additional_permissions[1] `DpnUser` is duplicated"));
    }
    #[test]
    fn account_onboarding_parses_structural_credentials_and_native_auto_renew() {
        let key_pair = checked_onboarding_authority_ed25519_key_fixture();
        let key_file = OnboardingKeyFile::new(&key_pair);
        let actual = load_user_root(table_with_account_onboarding(&key_pair, key_file.path()))
            .parse()
            .expect("parse structural account onboarding");
        let onboarding = actual
            .torii
            .account_onboarding
            .expect("account onboarding configured");
        assert_eq!(
            onboarding.authority,
            AccountId::new(key_pair.public_key().clone())
        );
        assert_eq!(onboarding.private_key_file, key_file.path());
        assert_eq!(onboarding.signer, key_pair);
        assert_eq!(onboarding.lease_term_years.get(), 2);
        assert_eq!(
            onboarding.additional_permissions,
            vec![Name::from_str("CanManagePeers").expect("permission name")]
        );
        assert_eq!(onboarding.credentials.len(), 2);
        assert!(matches!(
            onboarding.credentials[0].scope,
            actual::AccountOnboardingCredentialScope::Domain(ref domain)
                if domain.to_string() == "wonderland.universal"
        ));
        assert!(matches!(
            onboarding.credentials[1].scope,
            actual::AccountOnboardingCredentialScope::Dataspace(ref dataspace)
                if dataspace.as_ref() == "universal"
        ));
        assert_eq!(onboarding.credentials[0].token_hash, [0xab; 32]);
        assert_eq!(onboarding.credentials[1].token_hash, [0xcd; 32]);
        let auto_renew = onboarding.auto_renew.expect("native auto-renew configured");
        assert_eq!(auto_renew.term_years.get(), 2);
        assert_eq!(auto_renew.max_amount, Quantity::from(25_u32));
        assert_eq!(
            auto_renew.renew_before_expiry,
            Duration::from_millis(86_400_000)
        );
        assert_eq!(auto_renew.retry_backoff, Duration::from_millis(3_600_000));
        assert_eq!(auto_renew.max_failures.get(), 5);
    }
    #[test]
    fn account_onboarding_retains_distinct_credentials_for_the_same_scope() {
        let key_pair = checked_onboarding_authority_ed25519_key_fixture();
        let key_file = OnboardingKeyFile::new(&key_pair);
        let mut table = table_with_account_onboarding(&key_pair, key_file.path());
        table
            .get_mut("torii")
            .and_then(Value::as_table_mut)
            .and_then(|torii| torii.get_mut("account_onboarding"))
            .and_then(Value::as_table_mut)
            .and_then(|onboarding| onboarding.get_mut("credentials"))
            .and_then(Value::as_array_mut)
            .expect("onboarding credentials")
            .push(onboarding_credential(
                "backup-domain",
                "domain",
                "wonderland.universal",
                &format!("blake3:{}", "ef".repeat(32)),
            ));
        let actual = load_user_root(table)
            .parse()
            .expect("same-scope credentials with distinct identities and digests are valid");
        let credentials = actual
            .torii
            .account_onboarding
            .expect("account onboarding configured")
            .credentials;
        assert_eq!(credentials.len(), 3);
        assert_eq!(credentials[0].scope, credentials[2].scope);
        assert_eq!(credentials[2].token_hash, [0xef; 32]);
    }
    #[test]
    fn account_onboarding_rejects_auto_renew_window_as_long_as_term() {
        let key_pair = checked_onboarding_authority_ed25519_key_fixture();
        let key_file = OnboardingKeyFile::new(&key_pair);
        let mut table = table_with_account_onboarding(&key_pair, key_file.path());
        let auto_renew = table
            .get_mut("torii")
            .and_then(Value::as_table_mut)
            .and_then(|torii| torii.get_mut("account_onboarding"))
            .and_then(Value::as_table_mut)
            .and_then(|onboarding| onboarding.get_mut("auto_renew"))
            .and_then(Value::as_table_mut)
            .expect("account onboarding auto-renew table");
        auto_renew.insert("term_years".into(), Value::Integer(1));
        auto_renew.insert(
            "renew_before_expiry_ms".into(),
            Value::Integer(
                i64::try_from(iroha_data_model::alias_setup::ALIAS_LEASE_YEAR_MS)
                    .expect("lease year fits TOML integer"),
            ),
        );
        let error = load_user_root(table)
            .parse()
            .expect_err("repeated-charge auto-renew timing must fail config validation");
        assert!(
            format!("{error:?}").contains(
                "auto_renew.renew_before_expiry_ms must be shorter than the 31536000000ms renewal term"
            ),
            "{error:?}"
        );
    }
    #[test]
    fn account_onboarding_aggregates_independent_validation_failures() {
        let mut first_scope = Table::new();
        first_scope.insert("domain".into(), Value::String("HBL.sbp".to_owned()));
        first_scope.insert("dataspace".into(), Value::String("universal".to_owned()));
        let mut first = Table::new();
        first.insert("id".into(), Value::String("duplicate".to_owned()));
        first.insert("scope".into(), Value::Table(first_scope));
        first.insert(
            "token_hash".into(),
            Value::String("not-a-digest".to_owned()),
        );
        let digest = format!("blake3:{}", "ab".repeat(32));
        let mut missing_scope = Table::new();
        let mut second = Table::new();
        second.insert("id".into(), Value::String("duplicate".to_owned()));
        second.insert("scope".into(), Value::Table(missing_scope.clone()));
        second.insert("token_hash".into(), Value::String(digest.clone()));
        missing_scope.insert("domain".into(), Value::String("HBL.sbp".to_owned()));
        let mut third = Table::new();
        third.insert("id".into(), Value::String("third".to_owned()));
        third.insert("scope".into(), Value::Table(missing_scope));
        third.insert("token_hash".into(), Value::String(digest));
        let mut auto_renew = Table::new();
        auto_renew.insert("term_years".into(), Value::Integer(0));
        auto_renew.insert("max_amount".into(), Value::String("-1".to_owned()));
        auto_renew.insert("renew_before_expiry_ms".into(), Value::Integer(0));
        auto_renew.insert("retry_backoff_ms".into(), Value::Integer(0));
        auto_renew.insert("max_failures".into(), Value::Integer(0));
        let mut account_onboarding = Table::new();
        account_onboarding.insert(
            "authority".into(),
            Value::String("not-an-account".to_owned()),
        );
        account_onboarding.insert(
            "private_key_file".into(),
            Value::String("/definitely/missing/onboarding.key".to_owned()),
        );
        account_onboarding.insert("lease_term_years".into(), Value::Integer(0));
        account_onboarding.insert(
            "additional_permissions".into(),
            Value::Array(vec![
                Value::String("CanDoThing".to_owned()),
                Value::String("CanDoThing".to_owned()),
                Value::String(String::new()),
            ]),
        );
        account_onboarding.insert(
            "fee_sponsor_program_id".into(),
            Value::String("not-a-program".to_owned()),
        );
        account_onboarding.insert(
            "credentials".into(),
            Value::Array(vec![
                Value::Table(first),
                Value::Table(second),
                Value::Table(third),
            ]),
        );
        account_onboarding.insert("auto_renew".into(), Value::Table(auto_renew));
        let mut table = base_table();
        table
            .get_mut("torii")
            .and_then(Value::as_table_mut)
            .expect("torii table")
            .insert(
                "account_onboarding".into(),
                Value::Table(account_onboarding),
            );
        let error = load_user_root(table)
            .parse()
            .expect_err("all invalid onboarding fields must be reported");
        let report = format!("{error:?}");
        for expected in [
            "authority must be a canonical domainless AccountId",
            "failed to read torii.account_onboarding.private_key_file",
            "lease_term_years must be greater than zero",
            "credentials[0].scope must not set both",
            "credentials[0].token_hash must use",
            "credentials[1].id `duplicate` is duplicated",
            "credentials[1].scope must set exactly one",
            "credentials[2].scope.domain must use canonical form",
            "credentials[2].token_hash reuses another credential digest",
            "additional_permissions[0] `CanDoThing` is not a supported unscoped default permission",
            "additional_permissions[1] `CanDoThing` is duplicated",
            "additional_permissions[2] is not a valid permission name",
            "fee_sponsor_program_id is invalid",
            "auto_renew.term_years must be greater than zero",
            "auto_renew.max_amount must be greater than zero",
            "auto_renew.renew_before_expiry_ms must be greater than zero",
            "auto_renew.retry_backoff_ms must be greater than zero",
            "auto_renew.max_failures must be greater than zero",
        ] {
            assert!(
                report.contains(expected),
                "missing `{expected}` in {report}"
            );
        }
    }
    #[test]
    fn account_onboarding_rejects_signer_authority_mismatch() {
        let signer = checked_onboarding_authority_ed25519_key_fixture();
        let other_authority = checked_onboarding_authority_ed25519_key_fixture();
        let key_file = OnboardingKeyFile::new(&signer);
        let mut table = table_with_account_onboarding(&signer, key_file.path());
        table
            .get_mut("torii")
            .and_then(Value::as_table_mut)
            .and_then(|torii| torii.get_mut("account_onboarding"))
            .and_then(Value::as_table_mut)
            .expect("account onboarding table")
            .insert(
                "authority".into(),
                Value::String(AccountId::new(other_authority.public_key().clone()).to_string()),
            );
        let error = load_user_root(table)
            .parse()
            .expect_err("mismatched signer must fail closed");
        assert!(
            format!("{error:?}").contains("signer does not match authority"),
            "{error:?}"
        );
    }
    #[test]
    fn account_onboarding_requires_at_least_one_credential() {
        let key_pair = checked_onboarding_authority_ed25519_key_fixture();
        let key_file = OnboardingKeyFile::new(&key_pair);
        let mut table = table_with_account_onboarding(&key_pair, key_file.path());
        table
            .get_mut("torii")
            .and_then(Value::as_table_mut)
            .and_then(|torii| torii.get_mut("account_onboarding"))
            .and_then(Value::as_table_mut)
            .expect("account onboarding table")
            .insert("credentials".into(), Value::Array(Vec::new()));
        let error = load_user_root(table)
            .parse()
            .expect_err("empty credentials must fail closed");
        assert!(
            format!("{error:?}").contains("credentials must contain at least one credential"),
            "{error:?}"
        );
    }
    #[test]
    fn account_onboarding_rejects_legacy_and_secret_bearing_fields() {
        let mut legacy_table = base_table();
        legacy_table
            .get_mut("torii")
            .and_then(Value::as_table_mut)
            .expect("torii table")
            .insert("onboarding".into(), Value::Table(Table::new()));
        let legacy_error = actual::Root::from_toml_source(TomlSource::inline(legacy_table))
            .expect_err("legacy onboarding table must be unknown");
        assert!(format!("{legacy_error:?}").contains("onboarding"));
        let key_pair = checked_onboarding_authority_ed25519_key_fixture();
        let key_file = OnboardingKeyFile::new(&key_pair);
        let mut secret_table = table_with_account_onboarding(&key_pair, key_file.path());
        let onboarding = secret_table
            .get_mut("torii")
            .and_then(Value::as_table_mut)
            .and_then(|torii| torii.get_mut("account_onboarding"))
            .and_then(Value::as_table_mut)
            .expect("account onboarding table");
        onboarding.insert(
            "private_key".into(),
            Value::String("must-not-be-accepted".to_owned()),
        );
        onboarding
            .get_mut("credentials")
            .and_then(Value::as_array_mut)
            .and_then(|credentials| credentials.first_mut())
            .and_then(Value::as_table_mut)
            .expect("first credential")
            .insert("token".into(), Value::String("raw-secret".to_owned()));
        let secret_error = actual::Root::from_toml_source(TomlSource::inline(secret_table))
            .expect_err("inline private keys and raw tokens must be unknown");
        let report = format!("{secret_error:?}");
        assert!(report.contains("private_key"), "{report}");
        assert!(report.contains("token"), "{report}");
        assert!(!report.contains("raw-secret"), "secret leaked in {report}");
    }
    include!("user_service_configuration_tests.rs");
}
