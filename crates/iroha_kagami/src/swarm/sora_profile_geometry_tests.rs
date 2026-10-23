//! Swarm runtime projection must use the daemon's source-selected Sora geometry.

use super::*;

fn source_config() -> toml::Table {
    include_str!("../../../iroha_config/tests/fixtures/base.toml")
        .parse()
        .expect("shared parsed-admission config fixture")
}

fn execution_policy(config: &actual::Root) -> [u8; 32] {
    let manifests = iroha_core::governance::manifest::LaneManifestRegistry::from_config(
        &config.nexus.lane_catalog,
        &config.nexus.governance,
        &config.nexus.registry,
    );
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

#[test]
fn swarm_runtime_projection_preserves_explicit_default_geometry() {
    let mut table = source_config();
    table.insert(
        "nexus".to_owned(),
        toml::toml! {
            lane_count = 1
            lane_catalog = []
            dataspace_catalog = []
            [routing_policy]
        }
        .into(),
    );
    let before = actual::Root::from_toml_source(TomlSource::inline(table.clone()))
        .expect("explicit default geometry");
    assert!(!before.nexus.has_lane_overrides());
    let (after, requires_sora) = effective_runtime_config(before.clone(), &table);
    assert!(
        requires_sora,
        "fixture explicitly enables admitted discovery"
    );
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
    assert_eq!(execution_policy(&after), execution_policy(&before));
}

#[test]
fn swarm_runtime_projection_installs_bundled_geometry_only_when_omitted() {
    let table = source_config();
    let before = actual::Root::from_toml_source(TomlSource::inline(table.clone()))
        .expect("omitted geometry");
    let mut expected = before.clone();
    expected.apply_sora_profile();
    let (after, requires_sora) = effective_runtime_config(before, &table);
    assert!(requires_sora);
    assert_eq!(after.nexus.lane_catalog.lane_count().get(), 3);
    assert_eq!(execution_policy(&after), execution_policy(&expected));
}

#[test]
fn swarm_runtime_projection_leaves_standard_config_unprofiled() {
    let mut table = source_config();
    table.remove("sorafs");
    let before =
        actual::Root::from_toml_source(TomlSource::inline(table.clone())).expect("standard config");
    let (after, requires_sora) = effective_runtime_config(before.clone(), &table);
    assert!(!requires_sora);
    assert_eq!(after.nexus.lane_catalog.lane_count().get(), 1);
    assert_eq!(execution_policy(&after), execution_policy(&before));
}
