//! Compact product templates inherit the same production defaults as explicit settings.

use std::fmt::Debug;

use iroha_config::{
    base::{
        env::MockEnv,
        read::{ConfigReader, ReadConfig},
        toml::TomlSource,
    },
    parameters::user::{Banner, Crypto, DaIngest, Nexus, Nts, SorafsGc, SorafsRepair, Torii},
};
use toml::{Table, Value};

const TAIRA: &str = include_str!("../../../configs/soranexus/taira/config.toml");
const MINAMOTO: &str = include_str!("../../../configs/soranexus/nexus/config.toml");
const NEXUS_EXAMPLE: &str = include_str!("../../../defaults/nexus/config.toml");
const KAGAMI_EXAMPLE: &str = include_str!("../../../defaults/kagami/iroha3-nexus/config.toml");
const KAGAMI_TOPOLOGY: &str =
    include_str!("../../../xtask/src/kagami_profiles/nexus_topology.toml");

fn section(source: &str, path: &str) -> Table {
    let source: Value = toml::from_str(source).expect("valid checked-in template");
    path.split('.')
        .try_fold(&source, |value, key| value.get(key))
        .map_or_else(Table::new, |value| {
            value.as_table().expect("configuration section").clone()
        })
}

fn read<T: ReadConfig>(table: Table) -> T {
    ConfigReader::new()
        .with_env(MockEnv::default())
        .with_toml_source(TomlSource::inline(table))
        .read_and_complete::<T>()
        .expect("template section must load through the production schema")
}

fn merge(table: &mut Table, explicit: Table) {
    for (key, value) in explicit {
        if let (Some(Value::Table(current)), Value::Table(additions)) =
            (table.get_mut(&key), &value)
        {
            merge(current, additions.clone());
        } else {
            table.insert(key, value);
        }
    }
}

fn assert_equivalent<T: ReadConfig + Debug>(compact: Table, explicit: &str) {
    let mut expanded = compact.clone();
    merge(&mut expanded, toml::from_str(explicit).unwrap());
    // These user-level sections lack PartialEq. Comparing their complete parsed
    // values exercises ReadConfig defaults without requiring runtime secret files.
    assert_eq!(
        format!("{:?}", read::<T>(compact)),
        format!("{:?}", read::<T>(expanded))
    );
}

#[test]
fn removed_banner_and_disabled_worker_settings_keep_their_values() {
    for template in [TAIRA, MINAMOTO, NEXUS_EXAMPLE] {
        assert_equivalent::<Banner>(section(template, "ivm.banner"), "show = true\nbeep = true");
    }
    for template in [TAIRA, NEXUS_EXAMPLE] {
        assert_equivalent::<SorafsRepair>(
            section(template, "sorafs.repair"),
            "enabled = false\nclaim_ttl_secs = 900\nheartbeat_interval_secs = 60\nmax_attempts = 3\nworker_concurrency = 4",
        );
        assert_equivalent::<SorafsGc>(
            section(template, "sorafs.gc"),
            "enabled = false\ninterval_secs = 900\nmax_deletions_per_run = 500\nretention_grace_secs = 86400",
        );
    }
}

#[test]
fn taira_time_crypto_and_torii_defaults_keep_their_values() {
    assert_equivalent::<Nts>(
        section(TAIRA, "nts"),
        r"
        sample_interval_ms = 5000
        sample_cap_per_round = 8
        max_rtt_ms = 500
        trim_percent = 10
        per_peer_buffer = 16
        smoothing_enabled = false
        smoothing_alpha = 0.2
        max_adjust_ms_per_min = 50
        min_samples = 3
        max_offset_ms = 1000
        max_confidence_ms = 500
    ",
    );
    assert_equivalent::<Crypto>(
        section(TAIRA, "crypto"),
        r#"
        enable_sm_openssl_preview = false
        default_hash = "blake2b-256"
        sm2_distid_default = "1234567812345678"
    "#,
    );
    // The public template contains deployment-owned faucet/onboarding identities.
    // Parse the changed Torii budgets with its real bind address independently.
    let mut torii = section(TAIRA, "torii");
    torii.retain(|key, _| {
        [
            "address",
            "preauth_ban_capacity",
            "max_content_len",
            "query_max_inflight",
            "query_heavy_max_inflight",
            "query_queue_timeout_ms",
        ]
        .contains(&key)
    });
    let torii = read::<Torii>(torii);
    assert_eq!(torii.preauth_ban_capacity.get(), 4096);
    assert_eq!(torii.max_content_len.get(), 64_000_000);
    assert_eq!(torii.query_max_inflight.get(), 256);
    assert_eq!(torii.query_heavy_max_inflight.get(), 64);
    assert_eq!(torii.query_queue_timeout_ms.get().as_millis(), 30_000);
}

// Fee rates belong to the committed `root_fees_v1` genesis policy, not node configuration.
const NEXUS_DEFAULTS: &str = r"
    [commit]
    window_slots = 2
";

#[test]
fn compact_nexus_policy_preserves_topology_routing_and_effective_defaults() {
    for template in [
        TAIRA,
        MINAMOTO,
        NEXUS_EXAMPLE,
        KAGAMI_EXAMPLE,
        KAGAMI_TOPOLOGY,
    ] {
        let compact = section(template, "nexus");
        let mut expanded = compact.clone();
        for lane in expanded
            .get_mut("lane_catalog")
            .unwrap()
            .as_array_mut()
            .unwrap()
        {
            lane.as_table_mut()
                .unwrap()
                .insert("metadata".into(), Value::Table(Table::new()));
        }
        if [TAIRA, MINAMOTO, NEXUS_EXAMPLE].contains(&template) {
            merge(&mut expanded, toml::from_str(NEXUS_DEFAULTS).unwrap());
        }
        if template == TAIRA {
            merge(
                &mut expanded,
                toml::from_str(
                    r#"
                [fusion]
                observation_slots = 2
                [da.audit]
                interval_ms = 600000
                [da.rotation]
                max_hits_per_window = 4
                seed_tag = "iroha:da:rotate:v1\u0000"
                latency_decay = 0.25
            "#,
                )
                .unwrap(),
            );
        }
        if [MINAMOTO, NEXUS_EXAMPLE].contains(&template) {
            merge(
                &mut expanded,
                toml::from_str(
                    r#"
                [fusion]
                floor_teu = 4000
                exit_teu = 6000
                observation_slots = 2
                max_window_slots = 16
                [da]
                q_in_slot_total = 2048
                q_in_slot_per_ds_min = 8
                sample_size_base = 64
                sample_size_max = 96
                threshold_base = 43
                per_attester_shards = 25
                [da.audit]
                sample_size = 32
                window_count = 20
                interval_ms = 600000
                [da.recovery]
                request_timeout_ms = 86400000
                [da.rotation]
                max_hits_per_window = 4
                window_slots = 64
                seed_tag = "iroha:da:rotate:v1\u0000"
                latency_decay = 0.25
            "#,
                )
                .unwrap(),
            );
        }
        if template == NEXUS_EXAMPLE {
            merge(
                &mut expanded,
                toml::from_str(
                    r"
                [storage]
                budget_enforce_interval_blocks = 10
                max_wsv_memory_bytes = 8589934592
                [storage.disk_budget_weights]
                kura_blocks_bps = 3500
                wsv_snapshots_bps = 2000
                sorafs_bps = 4500
            ",
                )
                .unwrap(),
            );
        }
        assert_eq!(
            format!("{:?}", read::<Nexus>(compact)),
            format!("{:?}", read::<Nexus>(expanded))
        );
    }
    assert_eq!(
        section(KAGAMI_EXAMPLE, "nexus"),
        section(KAGAMI_TOPOLOGY, "nexus")
    );
}

#[test]
fn minamoto_inherits_complete_da_retention_policy() {
    let ingest = read::<DaIngest>(section(MINAMOTO, "torii.da_ingest"));
    let policy = ingest.replication_policy;
    let retention = |value: &iroha_config::parameters::user::DaRetentionTemplate| {
        (
            value.hot_retention_secs,
            value.cold_retention_secs,
            value.required_replicas,
            value.storage_class.clone(),
            value.governance_tag.clone(),
        )
    };
    assert_eq!(
        retention(&policy.default_retention),
        (21600, 2_592_000, 3, "warm".into(), "da.default".into())
    );
    assert_eq!(policy.overrides.len(), 3);
    for (entry, (class, hot, cold, replicas, storage, tag)) in policy.overrides.iter().zip([
        (
            "taikai_segment",
            86400,
            1_209_600,
            5,
            "hot",
            "da.taikai.live",
        ),
        (
            "nexus_lane_sidecar",
            21600,
            604_800,
            4,
            "warm",
            "da.sidecar",
        ),
        (
            "governance_artifact",
            43200,
            15_552_000,
            3,
            "cold",
            "da.governance",
        ),
    ]) {
        assert_eq!(entry.class, class);
        assert_eq!(
            retention(&entry.retention),
            (hot, cold, replicas, storage.into(), tag.into())
        );
    }
    assert_eq!(policy.taikai_availability.len(), 3);
    for (entry, (class, hot, cold, replicas, storage, tag)) in
        policy.taikai_availability.iter().zip([
            ("hot", 86400, 1_209_600, 5, "hot", "da.taikai.live"),
            ("warm", 21600, 2_592_000, 4, "warm", "da.taikai.warm"),
            ("cold", 3600, 15_552_000, 3, "cold", "da.taikai.archive"),
        ])
    {
        assert_eq!(entry.availability_class, class);
        assert_eq!(
            retention(&entry.retention),
            (hot, cold, replicas, storage.into(), tag.into())
        );
    }
}
