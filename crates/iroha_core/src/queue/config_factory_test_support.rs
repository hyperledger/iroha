// Shared queue test configuration factory.

fn config_factory() -> Config {
    Config {
        transaction_time_to_live: Duration::from_secs(100),
        capacity: 100.try_into().unwrap(),
        ..Config::default()
    }
}

/// Construct exact configured geometry with one telemetry sink from its first publication.
#[cfg(feature = "telemetry")]
fn new_queue_test_state_with_telemetry(
    mut world: World,
    mut nexus: Nexus,
    query_handle: crate::query::store::LiveQueryStoreHandle,
    telemetry: StateTelemetry,
) -> State {
    nexus.lane_config = LaneGeometry::from_catalog(&nexus.lane_catalog);
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
    crate::sns::try_seed_default_namespace_policies(
        &mut world,
        &nexus.fees.fee_asset_id.canonical_address(),
    )
    .expect("configured fixture SNS policies");
    let config = iroha_config::parameters::actual::Kura {
        init_mode: iroha_config::kura::InitMode::Strict,
        store_dir: iroha_config::base::WithOrigin::inline(std::path::PathBuf::new()),
        max_disk_usage_bytes: iroha_config::parameters::defaults::kura::MAX_DISK_USAGE_BYTES,
        blocks_in_memory: iroha_config::parameters::defaults::kura::BLOCKS_IN_MEMORY,
        native_context_archive_max_bytes:
            iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
        history_checkpoint_cache_capacity:
            iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
        block_hash_history_bytes:
            iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
        transaction_history_bytes:
            iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
        membership_storage: iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
        fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
        debug_output_new_blocks: false,
        fsync_mode: iroha_config::kura::FsyncMode::Batched,
        fsync_interval: iroha_config::parameters::defaults::kura::FSYNC_INTERVAL,
    };
    let kura = Kura::new_temporary_with_configured_lane_catalog(
        &config,
        &nexus.lane_config,
        &nexus.configured_lane_catalog,
    )
    .expect("open the fixture's exact immutable Kura baseline");
    // State attaches this same sink to Kura and the tiered backend. Reattaching after a
    // default State constructor would leave Kura's OnceLock bound to another sink.
    let mut state = State::try_new(
        world.sccp_committee_generations.allocation_budget().clone(),
        world,
        kura,
        query_handle,
        telemetry,
    )
    .expect("construct State against the authenticated configured Kura");
    state.install_pre_genesis_nexus_for_testing(nexus);
    state.configure_test_runtime_defaults();
    state
}
