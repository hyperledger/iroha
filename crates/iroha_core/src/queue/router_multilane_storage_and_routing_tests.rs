// Canonical multi-lane storage and routing fixtures, owned by the Core library tests.
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    queue::{ConfigLaneRouter, LaneRouter},
    state::{State, World},
    tx::AcceptedTransaction,
};
use eyre::Result;
use iroha_config::{
    base::WithOrigin,
    kura::FsyncMode,
    parameters::{
        actual::{
            Crypto, Kura as KuraConfig, LaneConfig as LaneDerivedConfig, LaneRoutingMatcher,
            LaneRoutingPolicy, LaneRoutingRule,
        },
        defaults,
    },
};
use iroha_crypto::KeyPair;
use iroha_data_model::{
    da::commitment::DaProofScheme,
    isi::{
        InstructionBox,
        prelude::{Mint, Register},
    },
    nexus::{
        AUTOSCALE_META_CREATED_HEIGHT, AUTOSCALE_META_MANAGED, DataSpaceCatalog, DataSpaceMetadata,
        LaneCatalog, LaneConfig as LaneConfigMetadata, LaneStorageProfile, LaneVisibility,
    },
    prelude::*,
    transaction::TransactionBuilder,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_primitives::time::TimeSource;
use iroha_test_samples::gen_account_in;
use nonzero_ext::nonzero;
use std::{collections::BTreeMap, num::NonZeroU32, sync::Arc, time::Duration};
use tempfile::tempdir;
fn sample_catalogs() -> (LaneCatalog, DataSpaceCatalog, LaneRoutingPolicy) {
    let lane_catalog = LaneCatalog::new(
        NonZeroU32::new(3).expect("non-zero lane count"),
        vec![
            LaneConfigMetadata {
                id: LaneId::new(0),
                shard_id: None,
                dataspace_id: DataSpaceId::UNIVERSAL,
                alias: "core".to_owned(),
                description: Some("Primary execution lane".to_owned()),
                visibility: LaneVisibility::Public,
                lane_type: Some("default_public".to_owned()),
                governance: None,
                settlement: None,
                storage: LaneStorageProfile::FullReplica,
                proof_scheme: DaProofScheme::default(),
                manifest_policy: Default::default(),
                confidential_compute: None,
                scheduler: None,
                settlement_buffer: None,
                metadata: BTreeMap::default(),
            },
            LaneConfigMetadata {
                id: LaneId::new(1),
                shard_id: None,
                dataspace_id: DataSpaceId::UNIVERSAL,
                alias: "governance".to_owned(),
                description: Some("Governance & parliament traffic".to_owned()),
                visibility: LaneVisibility::Public,
                lane_type: Some("governance".to_owned()),
                governance: None,
                settlement: None,
                storage: LaneStorageProfile::FullReplica,
                proof_scheme: DaProofScheme::default(),
                manifest_policy: Default::default(),
                confidential_compute: None,
                scheduler: None,
                settlement_buffer: None,
                metadata: BTreeMap::default(),
            },
            LaneConfigMetadata {
                id: LaneId::new(2),
                shard_id: None,
                dataspace_id: DataSpaceId::UNIVERSAL,
                alias: "zk".to_owned(),
                description: Some("Zero-knowledge attachments".to_owned()),
                visibility: LaneVisibility::Public,
                lane_type: Some("attachments".to_owned()),
                governance: None,
                settlement: None,
                storage: LaneStorageProfile::FullReplica,
                proof_scheme: DaProofScheme::default(),
                manifest_policy: Default::default(),
                confidential_compute: None,
                scheduler: None,
                settlement_buffer: None,
                metadata: BTreeMap::default(),
            },
        ],
    )
    .expect("lane catalog");
    let dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id: DataSpaceId::UNIVERSAL,
        alias: "universal".to_owned(),
        description: Some(
            "Shared public data space for core, governance, and zero-knowledge lanes".to_owned(),
        ),
        fault_tolerance: 1,
    }])
    .expect("dataspace catalog");
    let policy = LaneRoutingPolicy {
        default_lane: LaneId::new(0),
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![
            LaneRoutingRule {
                lane: LaneId::new(1),
                dataspace: Some(DataSpaceId::UNIVERSAL),
                matcher: LaneRoutingMatcher {
                    account: None,
                    instruction: Some("register::domain".to_owned()),
                    description: Some("governance lane for registration".to_owned()),
                },
            },
            LaneRoutingRule {
                lane: LaneId::new(2),
                dataspace: Some(DataSpaceId::UNIVERSAL),
                matcher: LaneRoutingMatcher {
                    account: None,
                    instruction: Some("mint".to_owned()),
                    description: Some("zk lane for mint flows".to_owned()),
                },
            },
        ],
    };
    (lane_catalog, dataspace_catalog, policy)
}
fn autoscale_elastic_lane(id: LaneId, created_height: u64) -> LaneConfigMetadata {
    let mut metadata = BTreeMap::new();
    metadata.insert(AUTOSCALE_META_MANAGED.to_owned(), "true".to_owned());
    metadata.insert(
        AUTOSCALE_META_CREATED_HEIGHT.to_owned(),
        created_height.to_string(),
    );
    let mut lane = LaneConfigMetadata {
        id,
        shard_id: None,
        dataspace_id: DataSpaceId::UNIVERSAL,
        alias: format!("elastic-lane-{}", id.as_u32()),
        description: Some("Consensus-managed elastic lane".to_owned()),
        visibility: LaneVisibility::Public,
        lane_type: Some("autoscale_elastic".to_owned()),
        governance: None,
        settlement: None,
        storage: LaneStorageProfile::FullReplica,
        proof_scheme: DaProofScheme::default(),
        manifest_policy: Default::default(),
        confidential_compute: None,
        scheduler: None,
        settlement_buffer: None,
        metadata,
    };
    crate::state::attach_synthetic_autoscale_committee_for_test(&mut lane);
    lane
}
fn install_state_nexus(
    lane_catalog: LaneCatalog,
    dataspace_catalog: DataSpaceCatalog,
    policy: LaneRoutingPolicy,
    autoscale_range: Option<(u32, u32)>,
) -> Result<State> {
    let kura = Kura::blank_kura_for_testing();
    let state = new_state(kura);
    let mut nexus = iroha_config::parameters::actual::Nexus {
        routing_policy: policy,
        dataspace_catalog,
        lane_config: LaneDerivedConfig::from_catalog(&lane_catalog),
        lane_catalog,
        ..Default::default()
    };
    if let Some((min_lane_id, max_lane_id_exclusive)) = autoscale_range {
        nexus.autoscale.enabled = true;
        nexus.autoscale.min_lane_id =
            NonZeroU32::new(min_lane_id).expect("autoscale min lanes must be nonzero");
        nexus.autoscale.max_lane_id_exclusive =
            NonZeroU32::new(max_lane_id_exclusive).expect("autoscale max lanes must be nonzero");
    }
    state.install_synthetic_routing_snapshot_for_testing(nexus);
    Ok(state)
}
fn new_state(kura: Arc<Kura>) -> State {
    let query = LiveQueryStore::start_test();
    // Keep the exact fallible constructor used by the former dependent-crate fixture;
    // Core's convenience constructor additionally installs synthetic active markers.
    State::try_new(
        crate::state::AllocationBudget::new(defaults::pipeline::IVM_EXECUTION_MAX_BYTES),
        World::default(),
        kura,
        query,
        #[cfg(feature = "telemetry")]
        crate::telemetry::StateTelemetry::default(),
    )
    .expect("test fixture durable State startup journals must validate")
}
fn seed_committed_height(state: &mut State, height: u64) {
    for idx in 0..height {
        state.push_block_hash_for_testing(iroha_crypto::HashOf::<
            iroha_data_model::block::BlockHeader,
        >::from_untyped_unchecked(
            iroha_crypto::Hash::new(idx.to_le_bytes())
        ));
    }
    state.update_latest_block_header_cache_for_tests(iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(height).expect("committed height must be nonzero"),
        None,
        None,
        0,
        0,
    ));
}
fn build_tx(
    network_id: NetworkId,
    authority: &AccountId,
    keypair: &KeyPair,
    instructions: Vec<InstructionBox>,
) -> AcceptedTransaction<'static> {
    let time_source = TimeSource::new_system();
    let tx = TransactionBuilder::new_with_time_source(
        network_id,
        authority.clone(),
        &time_source,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions)
    .with_metadata(Metadata::default())
    .sign(keypair.private_key());
    let default_limits = TransactionParameters::default();
    let params = TransactionParameters::with_max_signatures(
        nonzero!(16_u64),
        nonzero!(4096_u64),
        nonzero!(4096_u64),
        default_limits.max_tx_bytes(),
        default_limits.max_decompressed_bytes(),
        default_limits.max_metadata_depth(),
    );
    let crypto_cfg = Crypto::default();
    AcceptedTransaction::accept(
        tx,
        &network_id,
        Duration::from_secs(30),
        params,
        &crypto_cfg,
    )
    .expect("transaction should be accepted")
}
#[test]
fn multilane_router_provisions_storage_and_routes_rules() -> Result<()> {
    let (lane_catalog, dataspace_catalog, policy) = sample_catalogs();
    let lane_config = LaneDerivedConfig::from_catalog(&lane_catalog);
    let temp = tempdir()?;
    let store_dir = temp.path().join("kura");
    std::fs::create_dir_all(&store_dir)?;
    let kura_cfg = KuraConfig {
        init_mode: iroha_config::kura::InitMode::Strict,
        store_dir: WithOrigin::inline(store_dir.clone()),
        max_disk_usage_bytes: defaults::kura::MAX_DISK_USAGE_BYTES,
        blocks_in_memory: defaults::kura::BLOCKS_IN_MEMORY,
        history_checkpoint_cache_capacity: defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
        debug_output_new_blocks: false,
        fsync_mode: FsyncMode::Batched,
        fsync_interval: defaults::kura::FSYNC_INTERVAL,

        native_context_archive_max_bytes: defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
        block_hash_history_bytes:
            iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
        transaction_history_bytes:
            iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
        fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,

        membership_storage: defaults::kura::MEMBERSHIP_STORAGE_POLICY,
    };
    let (kura, block_count) =
        Kura::new_with_configured_lane_catalog(&kura_cfg, &lane_config, &lane_catalog)?;
    assert_eq!(block_count.0, 0, "fresh store should be empty");
    let mut state = new_state(Arc::clone(&kura));
    state.prepare_configured_primary_geometry_anchor(&lane_catalog)?;
    state.restore_kura_lane_segments_before_startup_replay()?;
    state.set_nexus_from_config(iroha_config::parameters::actual::Nexus {
        lane_catalog: lane_catalog.clone(),
        configured_lane_catalog: lane_catalog.clone(),
        lane_config: lane_config.clone(),
        dataspace_catalog: dataspace_catalog.clone(),
        routing_policy: policy.clone(),
        ..Default::default()
    })?;
    for entry in lane_config.entries() {
        let identity = state
            .lane_storage_identity(entry.lane_id)
            .expect("configured lane has an authenticated storage identity");
        let blocks_dir = identity.blocks_dir(&store_dir);
        assert!(
            blocks_dir.is_dir(),
            "lane {} blocks dir should be created",
            entry.lane_id.as_u32()
        );
        assert_eq!(
            blocks_dir.parent(),
            Some(store_dir.join("blocks/instances").as_path()),
            "lane storage must use the exact instance namespace"
        );
    }
    let router: Arc<dyn LaneRouter> = Arc::new(ConfigLaneRouter::new(
        policy,
        dataspace_catalog,
        lane_catalog,
    ));
    let (authority, keypair) = gen_account_in("nexus");
    let network_id = *state.network_id_ref();
    let governance_tx = build_tx(
        network_id,
        &authority,
        &keypair,
        vec![InstructionBox::from(Register::domain(Domain::new(
            DomainId::try_new("gov", "governance")?,
        )))],
    );
    let zk_tx = build_tx(
        network_id,
        &authority,
        &keypair,
        vec![InstructionBox::from(Mint::asset_quantity(
            1_u32,
            AssetId::new(
                AssetDefinitionId::derive_from_components(
                    DomainId::try_new("nexus", "zk")?,
                    "xor".parse()?,
                ),
                authority.clone(),
            ),
        ))],
    );
    let default_tx = build_tx(
        network_id,
        &authority,
        &keypair,
        vec![InstructionBox::from(Register::asset_definition(
            AssetDefinition::numeric(
                AssetDefinitionId::derive_from_components(
                    DomainId::try_new("nexus", "universal")?,
                    "xor".parse()?,
                ),
                "xor".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            ),
        ))],
    );
    let decision = router
        .try_route(&governance_tx)
        .expect("governance routing should resolve");
    assert_eq!(decision.lane_id, LaneId::new(1));
    assert_eq!(decision.dataspace_id, DataSpaceId::UNIVERSAL);

    let decision = router.try_route(&zk_tx).expect("zk routing should resolve");
    assert_eq!(decision.lane_id, LaneId::new(2));
    assert_eq!(decision.dataspace_id, DataSpaceId::UNIVERSAL);
    let decision = router
        .try_route(&default_tx)
        .expect("default routing should resolve");
    assert_eq!(decision.lane_id, LaneId::new(0));
    assert_eq!(decision.dataspace_id, DataSpaceId::UNIVERSAL);
    drop(kura);
    Ok(())
}
#[test]
fn multilane_router_shards_default_route_over_autoscale_elastic_lanes() -> Result<()> {
    let (base_lane_catalog, dataspace_catalog, policy) = sample_catalogs();
    let mut lanes = base_lane_catalog.lanes().to_vec();
    lanes.push(autoscale_elastic_lane(LaneId::new(3), 7));
    lanes.push(autoscale_elastic_lane(LaneId::new(4), 7));
    let lane_catalog =
        LaneCatalog::new(NonZeroU32::new(5).expect("lane count"), lanes).expect("lane catalog");
    let router: Arc<dyn LaneRouter> = Arc::new(ConfigLaneRouter::new(
        policy.clone(),
        dataspace_catalog.clone(),
        lane_catalog.clone(),
    ));
    let mut state = install_state_nexus(lane_catalog, dataspace_catalog, policy, Some((3, 5)))?;
    seed_committed_height(&mut state, 7);
    let (authority, keypair) = gen_account_in("nexus");
    let network_id = *state.network_id_ref();
    let governance_tx = build_tx(
        network_id,
        &authority,
        &keypair,
        vec![InstructionBox::from(Register::domain(Domain::new(
            DomainId::try_new("governed", "governance")?,
        )))],
    );
    let governance = router
        .try_route_with_view(&governance_tx, &state.view())
        .expect("governance routing should resolve");
    assert_eq!(governance.lane_id, LaneId::new(1));
    assert_eq!(governance.dataspace_id, DataSpaceId::UNIVERSAL);
    let zk_tx = build_tx(
        network_id,
        &authority,
        &keypair,
        vec![InstructionBox::from(Mint::asset_quantity(
            1_u32,
            AssetId::new(
                AssetDefinitionId::derive_from_components(
                    DomainId::try_new("nexus", "zk")?,
                    "xor".parse()?,
                ),
                authority.clone(),
            ),
        ))],
    );
    let zk = router
        .try_route_with_view(&zk_tx, &state.view())
        .expect("zk routing should resolve");
    assert_eq!(zk.lane_id, LaneId::new(2));
    assert_eq!(zk.dataspace_id, DataSpaceId::UNIVERSAL);
    let mut lanes_seen = std::collections::BTreeSet::new();
    for idx in 0..512 {
        let role_id = iroha_data_model::role::RoleId {
            name: format!("elasticroute{idx}")
                .parse()
                .expect("valid role name"),
        };
        let default_tx = build_tx(
            network_id,
            &authority,
            &keypair,
            vec![InstructionBox::from(Register::role(
                iroha_data_model::role::Role::new(role_id, authority.clone()),
            ))],
        );
        let decision = router
            .try_route_with_view(&default_tx, &state.view())
            .expect("default routing should resolve");
        assert_eq!(decision.dataspace_id, DataSpaceId::UNIVERSAL);
        assert!(
            matches!(
                decision.lane_id,
                lane if lane == LaneId::new(0)
                    || lane == LaneId::new(3)
                    || lane == LaneId::new(4)
            ),
            "default-route autoscale sharding chose unexpected lane {:?}",
            decision.lane_id
        );
        lanes_seen.insert(decision.lane_id);
        if lanes_seen.len() == 3 {
            break;
        }
    }
    assert_eq!(
        lanes_seen,
        std::collections::BTreeSet::from([LaneId::new(0), LaneId::new(3), LaneId::new(4)]),
        "default-route traffic should shard across the base lane and autoscale elastic lanes"
    );
    Ok(())
}
#[test]
fn multilane_router_fails_closed_when_elastic_range_contains_corruption() -> Result<()> {
    struct CorruptionCase {
        name: &'static str,
        lane: LaneConfigMetadata,
    }
    let mut malformed_managed = autoscale_elastic_lane(LaneId::new(4), 7);
    malformed_managed.alias = "malformed-elastic-lane".to_owned();
    let mut off_default_managed = autoscale_elastic_lane(LaneId::new(4), 7);
    off_default_managed.dataspace_id = DataSpaceId::new(1);
    let cases = [
        CorruptionCase {
            name: "manual",
            lane: LaneConfigMetadata {
                id: LaneId::new(4),
                shard_id: None,
                dataspace_id: DataSpaceId::UNIVERSAL,
                alias: "manual-elastic-range".to_owned(),
                description: Some("Manual lane occupying autoscale range".to_owned()),
                visibility: LaneVisibility::Public,
                lane_type: Some("manual".to_owned()),
                governance: None,
                settlement: None,
                storage: LaneStorageProfile::FullReplica,
                proof_scheme: DaProofScheme::default(),
                manifest_policy: Default::default(),
                confidential_compute: None,
                scheduler: None,
                settlement_buffer: None,
                metadata: BTreeMap::default(),
            },
        },
        CorruptionCase {
            name: "malformed",
            lane: malformed_managed,
        },
        CorruptionCase {
            name: "offdefault",
            lane: off_default_managed,
        },
    ];
    for case in cases {
        let (base_lane_catalog, dataspace_catalog, policy) = sample_catalogs();
        let mut lanes = base_lane_catalog.lanes().to_vec();
        lanes.push(autoscale_elastic_lane(LaneId::new(3), 7));
        lanes.push(case.lane);
        let lane_catalog = LaneCatalog::new(NonZeroU32::new(5).expect("lane count"), lanes)
            .unwrap_or_else(|err| {
                panic!("{}: corrupted lane catalog should build: {err}", case.name)
            });
        let router: Arc<dyn LaneRouter> = Arc::new(ConfigLaneRouter::new(
            policy.clone(),
            dataspace_catalog.clone(),
            lane_catalog.clone(),
        ));
        let mut state = install_state_nexus(lane_catalog, dataspace_catalog, policy, Some((3, 5)))
            .unwrap_or_else(|err| panic!("{}: install Nexus state: {err}", case.name));
        seed_committed_height(&mut state, 7);
        let (authority, keypair) = gen_account_in("nexus");
        let network_id = *state.network_id_ref();
        let mut lanes_seen = std::collections::BTreeSet::new();
        for idx in 0..128 {
            let role_id = iroha_data_model::role::RoleId {
                name: format!("corrupt{}{}", case.name, idx)
                    .parse()
                    .expect("valid role name"),
            };
            let default_tx = build_tx(
                network_id,
                &authority,
                &keypair,
                vec![InstructionBox::from(Register::role(
                    iroha_data_model::role::Role::new(role_id, authority.clone()),
                ))],
            );
            let decision = router
                .try_route_with_view(&default_tx, &state.view())
                .unwrap_or_else(|err| panic!("{}: default route failed: {err}", case.name));
            assert_eq!(decision.dataspace_id, DataSpaceId::UNIVERSAL);
            lanes_seen.insert(decision.lane_id);
        }
        assert_eq!(
            lanes_seen,
            std::collections::BTreeSet::from([LaneId::new(0)]),
            "{} corruption inside the active autoscale range must keep default traffic on the base lane",
            case.name
        );
    }
    Ok(())
}
#[test]
fn multilane_router_ignores_stale_autoscale_lanes_when_autoscale_disabled() -> Result<()> {
    let (base_lane_catalog, dataspace_catalog, policy) = sample_catalogs();
    let mut lanes = base_lane_catalog.lanes().to_vec();
    lanes.push(autoscale_elastic_lane(LaneId::new(3), 7));
    lanes.push(autoscale_elastic_lane(LaneId::new(4), 7));
    let lane_catalog =
        LaneCatalog::new(NonZeroU32::new(5).expect("lane count"), lanes).expect("lane catalog");
    let router: Arc<dyn LaneRouter> = Arc::new(ConfigLaneRouter::new(
        policy.clone(),
        dataspace_catalog.clone(),
        lane_catalog.clone(),
    ));
    let mut state = install_state_nexus(lane_catalog, dataspace_catalog, policy, Some((3, 5)))?;
    seed_committed_height(&mut state, 7);
    let mut nexus = state.nexus_snapshot();
    nexus.autoscale.enabled = false;
    state.install_synthetic_routing_snapshot_for_testing(nexus);
    let (authority, keypair) = gen_account_in("nexus");
    let network_id = *state.network_id_ref();
    let mut lanes_seen = std::collections::BTreeSet::new();
    for idx in 0..128 {
        let role_id = iroha_data_model::role::RoleId {
            name: format!("staleelasticdisabled{idx}")
                .parse()
                .expect("valid role name"),
        };
        let default_tx = build_tx(
            network_id,
            &authority,
            &keypair,
            vec![InstructionBox::from(Register::role(
                iroha_data_model::role::Role::new(role_id, authority.clone()),
            ))],
        );
        let decision = router
            .try_route_with_view(&default_tx, &state.view())
            .expect("disabled-autoscale default routing should resolve");
        assert_eq!(decision.dataspace_id, DataSpaceId::UNIVERSAL);
        lanes_seen.insert(decision.lane_id);
    }
    assert_eq!(
        lanes_seen,
        std::collections::BTreeSet::from([LaneId::new(0)]),
        "disabled autoscale must keep default-route traffic on the base lane even when stale managed lanes remain in the catalog"
    );
    Ok(())
}
