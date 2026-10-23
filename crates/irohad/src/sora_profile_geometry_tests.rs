//! Regression coverage for source-selected Sora topology at the daemon config boundary.

use super::*;
use iroha_config::{base::toml::TomlSource, parameters::actual};

fn execution_policy(config: &Config) -> [u8; 32] {
    assert!(!config.nexus.compliance.enabled);
    let manifests = iroha_core::governance::manifest::LaneManifestRegistry::from_config(
        &config.nexus.lane_catalog,
        &config.nexus.governance,
        &config.nexus.registry,
    );
    manifests
        .validate_active_coverage_for_catalog(&config.nexus.lane_catalog)
        .expect("fixture lane policy coverage");
    let nexus = actual::nexus_consensus_policy_digest_with_runtime_policies(
        &config.nexus,
        None,
        Some(manifests.baseline_consensus_policy_digest()),
    )
    .expect("fixture Nexus policy");
    actual::execution_policy_digest_v1(
        &config.pipeline,
        &config.oracle,
        &config.fraud_monitoring,
        &config.gov,
        &config.content,
        &config.settlement,
        nexus,
        iroha_core::state::compute_zk_consensus_policy_hash(&config.zk),
    )
}

fn assert_same_geometry_and_execution_policy(before: &Config, after: &Config) {
    assert_eq!(after.nexus.lane_catalog, before.nexus.lane_catalog);
    assert_eq!(
        after.nexus.configured_lane_catalog,
        before.nexus.configured_lane_catalog
    );
    assert_eq!(after.nexus.lane_config, before.nexus.lane_config);
    assert_eq!(
        after.nexus.dataspace_catalog,
        before.nexus.dataspace_catalog
    );
    assert_eq!(
        after.nexus.configured_dataspace_catalog,
        before.nexus.configured_dataspace_catalog
    );
    assert_eq!(after.nexus.routing_policy, before.nexus.routing_policy);
    assert_eq!(
        after.nexus.dataspace_fee_sponsor_program_ids,
        before.nexus.dataspace_fee_sponsor_program_ids
    );
    assert_eq!(execution_policy(after), execution_policy(before));
}

fn geometry_fixture(source: &str, root: &Path) -> toml::Table {
    let mut table = config_tests::minimal_config_table();
    for (field, name) in [
        (["kura", "store_dir"], "kura"),
        (["snapshot", "store_dir"], "snapshots"),
        (["tiered_state", "cold_store_root"], "cold"),
        (["tiered_state", "da_store_root"], "da"),
    ] {
        iroha_config::base::toml::Writer::new(&mut table).write(
            field,
            root.join(name).to_str().expect("fixture storage path"),
        );
    }
    iroha_config::base::toml::Writer::new(&mut table).write(
        ["sorafs", "storage", "data_dir"],
        root.join("sorafs").to_str().expect("fixture storage path"),
    );
    let topology: toml::Table = source.parse().expect("topology fixture");
    let nexus = table
        .get_mut("nexus")
        .and_then(toml::Value::as_table_mut)
        .expect("minimal Nexus settings");
    if let Some(topology) = topology.get("nexus").and_then(toml::Value::as_table) {
        nexus.extend(topology.clone());
    }
    table
}

fn read_sora_config(
    path: &Path,
    verified: bool,
) -> ReportResult<(Config, Option<GenesisBlock>), ConfigError> {
    let mut args = vec![
        "iroha3d".to_owned(),
        "--sora".to_owned(),
        "--config".to_owned(),
        path.to_str().expect("fixture path").to_owned(),
    ];
    if verified {
        args.extend([
            "--config-blake3".to_owned(),
            blake3::hash(&fs::read(path).expect("config bytes"))
                .to_hex()
                .to_string(),
        ]);
    }
    let args = parse_args_from(test_build_metadata(), args);
    read_config_and_genesis_with_filesystem_space(&args, |_| {
        Some((32 * 1024 * 1024 * 1024, 64 * 1024 * 1024 * 1024))
    })
}

#[test]
fn sora_flag_preserves_explicit_default_topology_and_execution_policy() {
    for source in [
        "[nexus]\nlane_count = 1",
        "[nexus]\nlane_catalog = [{ index = 0, alias = 'default' }]",
        "[nexus]\ndataspace_catalog = [{ alias = 'universal', id = 0 }]",
        "[nexus.routing_policy]\ndefault_lane = 0\ndefault_dataspace = 'universal'\nrules = []",
        "[nexus]\nlane_catalog = []",
        "[nexus]\ndataspace_catalog = []",
        "[nexus.routing_policy]",
        "[nexus]\nlane_count = 1\nlane_catalog = [{ index = 0, alias = 'default' }]\ndataspace_catalog = [{ alias = 'universal', id = 0 }]\n[nexus.routing_policy]\ndefault_lane = 0\ndefault_dataspace = 'universal'\nrules = []",
    ] {
        let directory = tempfile::tempdir().expect("config directory");
        let path = directory.path().join("peer.toml");
        let table = geometry_fixture(source, directory.path());
        let before = Config::from_toml_source(TomlSource::new(path.clone(), table.clone()))
            .expect("parsed explicit geometry");
        assert!(
            !before.nexus.has_lane_overrides(),
            "fixture must equal default geometry: {source}"
        );
        fs::write(&path, toml::to_string(&table).expect("render config")).expect("write config");
        for verified in [false, true] {
            let (after, _) =
                read_sora_config(&path, verified).expect("daemon preserves explicit geometry");
            assert_same_geometry_and_execution_policy(&before, &after);
        }
    }
}

#[test]
fn sora_flag_preserves_inherited_default_topology_and_execution_policy() {
    let directory = tempfile::tempdir().expect("config directory");
    let base = directory.path().join("base.toml");
    let leaf = directory.path().join("peer.toml");
    let table = geometry_fixture(
        "[nexus]\nlane_count = 1\nlane_catalog = []\ndataspace_catalog = []\n[nexus.routing_policy]",
        directory.path(),
    );
    let before = Config::from_toml_source(TomlSource::new(base.clone(), table.clone()))
        .expect("parsed inherited geometry");
    fs::write(
        &base,
        toml::to_string(&table).expect("render inherited config"),
    )
    .expect("write inherited config");
    fs::write(
        &leaf,
        "extends = ['base.toml']\n[sorafs.storage]\nenabled = false\n",
    )
    .expect("write leaf config");
    let (after, _) = read_sora_config(&leaf, false).expect("daemon loads inherited selection");
    assert_same_geometry_and_execution_policy(&before, &after);
    assert!(!after.torii.sorafs_storage.enabled);
    let error =
        read_sora_config(&leaf, true).expect_err("integrity-bound files must remain flattened");
    assert!(format!("{error:?}").contains("cannot use `extends`"));
}

#[test]
fn sora_flag_preserves_custom_single_lane_shard_execution_policy() {
    let directory = tempfile::tempdir().expect("config directory");
    let path = directory.path().join("peer.toml");
    let table = geometry_fixture(
        "[nexus]\nlane_count = 1\nlane_catalog = [{ index = 0, alias = 'default', shard_id = 9 }]",
        directory.path(),
    );
    let before = Config::from_toml_source(TomlSource::new(path.clone(), table.clone()))
        .expect("parsed custom geometry");
    assert!(before.nexus.has_lane_overrides());
    fs::write(&path, toml::to_string(&table).expect("render config")).expect("write config");
    let (after, _) = read_sora_config(&path, false).expect("daemon preserves explicit shard");
    assert_same_geometry_and_execution_policy(&before, &after);
}

#[test]
fn sora_flag_without_topology_still_installs_bundled_geometry() {
    let directory = tempfile::tempdir().expect("config directory");
    let path = directory.path().join("peer.toml");
    let table = geometry_fixture("", directory.path());
    let mut expected = Config::from_toml_source(TomlSource::new(path.clone(), table.clone()))
        .expect("default geometry");
    expected.apply_sora_profile();
    fs::write(&path, toml::to_string(&table).expect("render config")).expect("write config");
    let (after, _) = read_sora_config(&path, false).expect("daemon applies bundled geometry");
    assert_eq!(after.nexus.lane_catalog.lane_count().get(), 3);
    assert_same_geometry_and_execution_policy(&expected, &after);
}
