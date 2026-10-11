#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Multi-lane routing and storage provisioning integration.
use eyre::Result;
use iroha_config::{
    kura::FsyncMode,
    parameters::{
        actual::{
            Crypto, Kura as KuraConfig, LaneConfig as LaneDerivedConfig, LaneRoutingMatcher,
            LaneRoutingPolicy, LaneRoutingRule,
        },
        defaults,
    },
};
use iroha_config_base::WithOrigin;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    queue::{ConfigLaneRouter, LaneRouter, RoutingDecision},
    state::{State, World},
    tx::AcceptedTransaction,
};
use iroha_data_model::{
    da::commitment::DaProofScheme,
    isi::{InstructionBox, prelude::SetKeyValue},
    nexus::{
        DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig as LaneConfigMetadata,
        LaneStorageProfile, LaneVisibility,
    },
    prelude::*,
    transaction::TransactionBuilder,
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_primitives::json::Json;
use iroha_test_samples::gen_account_in;
use nonzero_ext::nonzero;
use std::{collections::BTreeMap, num::NonZeroU32, sync::Arc, time::Duration};
use tempfile::tempdir;
const TEST_CHAIN_ID: &str = "00000000-0000-0000-0000-000000000000";
fn test_chain_id() -> ChainId {
    ChainId::from(TEST_CHAIN_ID)
}
fn test_network_id() -> NetworkId {
    NetworkId::from_genesis_hash(iroha_crypto::HashOf::<BlockHeader>::from_untyped_unchecked(
        iroha_crypto::Hash::new(b"multilane-pipeline-test-genesis"),
    ))
}
fn sample_transaction(
    authority: &AccountId,
    signer: &iroha_crypto::PrivateKey,
    instructions: Vec<InstructionBox>,
) -> AcceptedTransaction<'static> {
    let tx = TransactionBuilder::new(
        test_network_id(),
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions)
    .with_metadata(Metadata::default())
    .sign(signer);
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
        &test_network_id(),
        Duration::from_secs(30),
        params,
        &crypto_cfg,
    )
    .expect("transaction should be accepted")
}
#[test]
#[allow(clippy::too_many_lines)]
fn multilane_catalog_sets_up_storage_and_routing() -> Result<()> {
    let lane_catalog = LaneCatalog::new(
        NonZeroU32::new(3).expect("non-zero lane count"),
        vec![
            LaneConfigMetadata {
                id: LaneId::new(0),
                shard_id: None,
                dataspace_id: DataSpaceId::UNIVERSAL,
                alias: "core".to_string(),
                description: Some("Primary execution lane".to_string()),
                visibility: LaneVisibility::Public,
                lane_type: Some("default_public".to_string()),
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
                dataspace_id: DataSpaceId::new(1),
                alias: "governance".to_string(),
                description: Some("Governance & parliament traffic".to_string()),
                visibility: LaneVisibility::Restricted,
                lane_type: Some("governance".to_string()),
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
                dataspace_id: DataSpaceId::new(2),
                alias: "zk".to_string(),
                description: Some("Zero-knowledge attachments".to_string()),
                visibility: LaneVisibility::Restricted,
                lane_type: Some("attachments".to_string()),
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
    .expect("static multi-lane catalog");
    let lane_config = LaneDerivedConfig::from_catalog(&lane_catalog);
    let dataspace_catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: DataSpaceId::new(1),
            alias: "governance".to_string(),
            description: Some("Governance proposals & manifests".to_string()),
            fault_tolerance: 1,
        },
        DataSpaceMetadata {
            id: DataSpaceId::new(2),
            alias: "zk".to_string(),
            description: Some("Zero-knowledge proofs and attachments".to_string()),
            fault_tolerance: 1,
        },
    ])
    .expect("static multi-dataspace catalog");
    let temp = tempdir()?;
    let kura_cfg = KuraConfig {
        init_mode: iroha_config::kura::InitMode::Strict,
        store_dir: WithOrigin::inline(temp.path().to_path_buf()),
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
    assert_eq!(block_count.0, 0, "fresh Kura should have no blocks");
    let query = LiveQueryStore::start_test();
    let mut state = State::new_with_chain_and_network_id_for_testing(
        World::default(),
        Arc::clone(&kura),
        query,
        test_chain_id(),
        test_network_id(),
    );
    state.prepare_configured_primary_geometry_anchor(&lane_catalog)?;
    state.restore_kura_lane_segments_before_startup_replay()?;
    state.set_nexus_from_config(iroha_config::parameters::actual::Nexus {
        lane_catalog: lane_catalog.clone(),
        configured_lane_catalog: lane_catalog.clone(),
        lane_config: lane_config.clone(),
        dataspace_catalog: dataspace_catalog.clone(),
        routing_policy: LaneRoutingPolicy::default(),
        ..Default::default()
    })?;
    for entry in lane_config.entries() {
        let identity = state
            .lane_storage_identity(entry.lane_id)
            .expect("configured lane has an authenticated storage identity");
        let blocks_dir = identity.blocks_dir(temp.path());
        assert!(
            blocks_dir.is_dir(),
            "expected blocks dir for lane {} at {}",
            entry.alias,
            blocks_dir.display()
        );
    }
    let (core_account, core_keys) = gen_account_in("core");
    let (gov_account, gov_keys) = gen_account_in("governance");
    let (zk_account, zk_keys) = gen_account_in("zk");
    let routing_policy = LaneRoutingPolicy {
        default_lane: LaneId::new(0),
        default_dataspace: DataSpaceId::UNIVERSAL,
        rules: vec![
            LaneRoutingRule {
                lane: LaneId::new(1),
                dataspace: Some(DataSpaceId::new(1)),
                matcher: LaneRoutingMatcher {
                    account: Some(gov_account.to_string()),
                    instruction: None,
                    description: Some("route governance account to lane 1".to_string()),
                },
            },
            LaneRoutingRule {
                lane: LaneId::new(2),
                dataspace: Some(DataSpaceId::new(2)),
                matcher: LaneRoutingMatcher {
                    account: Some(zk_account.to_string()),
                    instruction: None,
                    description: Some("route zk account to lane 2".to_string()),
                },
            },
        ],
    };
    let router: Arc<dyn LaneRouter> = Arc::new(ConfigLaneRouter::new(
        routing_policy.clone(),
        dataspace_catalog,
        lane_catalog.clone(),
    ));
    let tx_core = sample_transaction(
        &core_account,
        core_keys.private_key(),
        vec![InstructionBox::from(SetKeyValue::account(
            core_account.clone(),
            "k0".parse().expect("metadata key"),
            Json::new("v0"),
        ))],
    );
    let tx_gov = sample_transaction(
        &gov_account,
        gov_keys.private_key(),
        vec![InstructionBox::from(SetKeyValue::account(
            gov_account.clone(),
            "gk".parse().expect("metadata key"),
            Json::new("gv"),
        ))],
    );
    let tx_zk = sample_transaction(
        &zk_account,
        zk_keys.private_key(),
        vec![InstructionBox::from(SetKeyValue::account(
            zk_account.clone(),
            "zk".parse().expect("metadata key"),
            Json::new("zv"),
        ))],
    );
    let decision_core = router
        .try_route(&tx_core)
        .expect("core routing should resolve");
    assert_eq!(
        decision_core,
        RoutingDecision::new(LaneId::new(0), DataSpaceId::UNIVERSAL)
    );
    let decision_gov = router
        .try_route(&tx_gov)
        .expect("governance routing should resolve");
    assert_eq!(
        decision_gov,
        RoutingDecision::new(LaneId::new(1), DataSpaceId::new(1))
    );
    let decision_zk = router.try_route(&tx_zk).expect("zk routing should resolve");
    assert_eq!(
        decision_zk,
        RoutingDecision::new(LaneId::new(2), DataSpaceId::new(2))
    );
    Ok(())
}
