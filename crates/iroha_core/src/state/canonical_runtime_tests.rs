//! Runtime owner mechanics through real State scopes; no carrier publication claim.

use super::*;
use crate::query::store::LiveQueryStore;

fn state() -> State {
    State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

#[test]
fn replay_probe_keeps_configured_governance_before_manifest_rebind() {
    let manifest_dir = tempfile::tempdir().expect("governed lane manifest directory");
    std::fs::write(
        manifest_dir.path().join("default.manifest.json"),
        r#"{"lane":"default","governance":"parliament","version":1}"#,
    )
    .expect("write governed primary lane manifest");
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    let mut lane = nexus.lane_catalog.lanes()[0].clone();
    lane.governance = Some("parliament".to_owned());
    let catalog = iroha_data_model::nexus::LaneCatalog::new(
        std::num::NonZeroU32::new(1).unwrap(),
        vec![lane],
    )
    .expect("one governed primary lane");
    nexus.lane_catalog = catalog.clone();
    nexus.configured_lane_catalog = catalog.clone();
    nexus.lane_config = iroha_config::parameters::actual::LaneConfig::from_catalog(&catalog);
    nexus.governance.modules.insert(
        "parliament".to_owned(),
        iroha_config::parameters::actual::GovernanceModule::default(),
    );
    nexus.registry.manifest_directory = Some(manifest_dir.path().to_path_buf());
    let manifests = std::sync::Arc::new(
        crate::governance::manifest::LaneManifestRegistry::from_config(
            &catalog,
            &nexus.governance,
            &nexus.registry,
        ),
    );
    manifests
        .validate_active_coverage_for_catalog(&catalog)
        .expect("configured governance authenticates active manifest");
    let kura_config = iroha_config::parameters::actual::Kura {
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
        &kura_config,
        &nexus.lane_config,
        &catalog,
    )
    .expect("bind governed configured catalog before startup");
    let mut live = State::new_for_testing(
        World::default(),
        std::sync::Arc::clone(&kura),
        LiveQueryStore::start_test(),
    );
    live.install_lane_manifests_for_testing(&manifests);
    live.prepare_configured_primary_geometry_anchor(&catalog)
        .expect("bind configured primary before replay");
    live.restore_kura_lane_segments_before_startup_replay()
        .expect("restore governed lane geometry");
    live.set_nexus_from_config(nexus)
        .expect("install governed local Nexus configuration");
    assert_eq!(live.committed_height(), 0);

    let captured = crate::snapshot::CapturedStateSnapshot::capture(&live)
        .expect("capture exact pre-replay State");
    let unseeded = super::deserialize::KuraSeed {
        execution_budget: live.ivm_execution_budget(),
        kura: std::sync::Arc::clone(&kura),
        lane_manifests: live.lane_manifests.read().clone(),
        query_handle: live.query_handle.clone(),
        #[cfg(feature = "telemetry")]
        telemetry: crate::telemetry::StateTelemetry::default(),
    }
    .into_state_from_json_str_without_durable_recovery(captured.as_json());
    assert!(unseeded.is_err(), "default Nexus loses the required module");
    let isolated = super::deserialize::KuraSeed {
        execution_budget: live.ivm_execution_budget(),
        kura: Arc::clone(&kura),
        lane_manifests: live.lane_manifests.read().clone(),
        query_handle: live.query_handle.clone(),
        #[cfg(feature = "telemetry")]
        telemetry: Default::default(),
    }
    .into_state_from_json_str_with_configured_nexus_without_durable_recovery(
        captured.as_json(),
        live.nexus_snapshot(),
    )
    .expect("configured Nexus survives strict isolated replay construction");
    assert_eq!(isolated.nexus_snapshot().governance.modules.len(), 1);
    assert_eq!(isolated.committed_height(), 0);
}

fn header() -> BlockHeader {
    BlockHeader::new(std::num::NonZeroU64::MIN, None, None, 1, 0)
}

#[test]
fn fixture_dataspace_baseline_is_visible_in_every_canonical_scope() {
    let mut state = state();
    let dataspace = DataSpaceId::new(17);
    let catalog = DataSpaceCatalog::new(vec![
        iroha_data_model::nexus::DataSpaceMetadata::default(),
        iroha_data_model::nexus::DataSpaceMetadata {
            id: dataspace,
            alias: "fixture".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .unwrap();
    state.set_dataspace_catalog_for_testing(catalog.clone());
    assert_eq!(state.nexus_snapshot().dataspace_catalog, catalog);
    assert_eq!(state.view().nexus().dataspace_catalog, catalog);
    let mut block = state.block(header());
    assert_eq!(block.nexus.dataspace_catalog, catalog);
    let tx = block.transaction();
    assert_eq!(tx.world.dataspace_catalog, catalog);
}

#[test]
fn synthetic_routing_snapshot_updates_the_canonical_owner_without_storage() {
    let state = state();
    let before = state.kura.exact_durable_blocks_count().unwrap();
    let mut nexus = state.nexus_snapshot();
    // A deliberately invalid default route is input to fail-closed router tests.
    nexus.routing_policy.default_lane = LaneId::new(99);
    state.install_synthetic_routing_snapshot_for_testing(nexus);
    assert_eq!(
        state.view().nexus().routing_policy.default_lane,
        LaneId::new(99)
    );
    assert_eq!(state.kura.exact_durable_blocks_count().unwrap(), before);
}

#[test]
fn abandoned_runtime_children_and_blocks_do_not_publish() {
    let state = state();
    let original = state.canonical_runtime.view().get().clone();
    {
        let mut block = state.merge_preexecution_block(header());
        {
            let mut transaction = block.transaction();
            // Low-level owner mutation tests rollback, not lifecycle authorization.
            transaction
                .canonical_runtime
                .get_mut()
                .autoscale_last_transition_height = 7;
        }
        assert_eq!(block.canonical_runtime.get(), &original);
        block
            .canonical_runtime
            .get_mut()
            .autoscale_last_transition_height = 9;
    }
    assert_eq!(state.canonical_runtime.view().get(), &original);
    assert!(state.canonical_runtime.predecessor_view().is_none());
}

#[test]
fn actual_replacement_uses_retained_runtime_including_retired_lineage() {
    let state = state();
    let original_runtime = state.canonical_runtime.view();
    let original_view = state.view();
    let predecessor = original_runtime.get().clone();
    assert!(std::ptr::eq(
        original_view.canonical_runtime.get(),
        original_runtime.get()
    ));
    // Explicit retained-metadata fixture: no SignedBlock/finality/publication is fabricated.
    let mut retained = state.canonical_runtime.block();
    retained
        .get_mut()
        .lane_incarnation_lineage
        .push(SnapshotLaneIncarnationLineage {
            lane_id: LaneId::new(7),
            generation: 1,
            incarnation: Hash::new(b"retired runtime lineage"),
            activation_height: 0,
        });
    retained.commit();
    let tip_runtime = state.canonical_runtime.view();
    let tip_view = state.view();
    let tip = tip_runtime.get().clone();
    assert_ne!(tip, predecessor);
    assert_eq!(original_view.canonical_runtime.get(), &predecessor);
    assert!(std::ptr::eq(
        original_view.canonical_runtime.get(),
        original_runtime.get()
    ));
    assert!(std::ptr::eq(
        tip_view.canonical_runtime.get(),
        tip_runtime.get()
    ));
    assert!(!std::ptr::eq(
        tip_view.canonical_runtime.get(),
        original_view.canonical_runtime.get()
    ));
    assert!(
        tip_view
            .canonical_runtime
            .get()
            .lane_incarnation_lineage
            .iter()
            .any(|lineage| lineage.lane_id == LaneId::new(7))
    );
    assert_eq!(
        tip_view.canonical_runtime_predecessor.get(),
        &Some(predecessor.clone())
    );
    {
        let ordinary = state.merge_preexecution_block(header());
        assert_eq!(ordinary.canonical_runtime.get(), &tip);
        assert!(
            ordinary
                .lane_incarnation_lineage
                .contains_key(&LaneId::new(7))
        );
    }
    {
        let replacement = state.block_and_revert(header());
        assert_eq!(replacement.canonical_runtime.get(), &predecessor);
        assert!(
            !replacement
                .lane_incarnation_lineage
                .contains_key(&LaneId::new(7))
        );
    }
    assert_eq!(state.canonical_runtime.view().get(), &tip);
    assert_eq!(
        state.canonical_runtime.predecessor_view().get(),
        &Some(predecessor)
    );
}

#[test]
fn runtime_mv_json_retains_current_undo_and_rejects_retired_record_only_shape() {
    let state = state();
    let predecessor = state.canonical_runtime.view().get().clone();
    let mut retained = state.canonical_runtime.block();
    retained.get_mut().autoscale_last_transition_height = 3;
    retained.commit();
    let json = norito::json::to_json(&state.canonical_runtime).unwrap();
    let decoded: Cell<SnapshotNexusRuntime> = norito::json::from_str(&json).unwrap();
    assert_eq!(decoded.view().get(), state.canonical_runtime.view().get());
    assert_eq!(decoded.predecessor_view().get(), &Some(predecessor.clone()));
    assert_eq!(decoded.block_and_revert().get(), &predecessor);
    let retired = norito::json::to_json(state.canonical_runtime.view().get()).unwrap();
    assert!(norito::json::from_str::<Cell<SnapshotNexusRuntime>>(&retired).is_err());
}

#[test]
fn unowned_runtime_projection_change_cannot_publish() {
    let state = state();
    let original = state.canonical_runtime.view().get().clone();
    let mut block = state.merge_preexecution_block(header());
    block.nexus.autoscale.last_transition_height = 1;
    assert!(block.validate_canonical_runtime_projection().is_err());
    assert!(matches!(
        block.commit(),
        Err(TransactionsBlockError::AutoscaleLaneLifecycle)
    ));
    assert_eq!(state.canonical_runtime.view().get(), &original);
}

#[test]
fn active_runtime_projections_do_not_copy_retired_lineage_trees() {
    let state = state();
    let mut runtime = state.canonical_runtime.view().get().clone();
    let active = runtime.lane_incarnation_lineage[0].clone();
    // Read projection fixture only: these retained entries confer no execution authority.
    for id in 1_u32..=2048 {
        runtime
            .lane_incarnation_lineage
            .push(SnapshotLaneIncarnationLineage {
                lane_id: LaneId::new(id),
                generation: 1,
                incarnation: Hash::new(id.to_be_bytes()),
                activation_height: u64::from(id),
            });
    }
    let mut incarnations = None;
    let incarnation_allocations = crate::test_allocations::allocations_during(|| {
        incarnations = Some(runtime.active_incarnations());
    });
    let mut activations = None;
    let activation_allocations = crate::test_allocations::allocations_during(|| {
        activations = Some(runtime.active_activation_heights());
    });
    assert_eq!(
        incarnations.unwrap().unwrap(),
        BTreeMap::from([(active.lane_id, active.incarnation)])
    );
    assert_eq!(
        activations.unwrap().unwrap(),
        BTreeMap::from([(active.lane_id, active.activation_height)])
    );
    assert_eq!(
        (incarnation_allocations, activation_allocations),
        (1, 1),
        "each one-lane result needs only its own output leaf, regardless of retired history"
    );
    assert_eq!(runtime.lane_incarnation_lineage.len(), 2049);
    assert_eq!(runtime.lane_incarnation_lineage[0], active);
}

#[test]
fn incomplete_runtime_lineage_is_a_fallible_error_and_cannot_replace_owner() {
    let state = state();
    let original = state.canonical_runtime.view().get().clone();
    let mut malformed = original.clone();
    malformed.lane_incarnation_lineage.clear();
    assert!(malformed.active_incarnations().is_err());
    assert!(malformed.active_activation_heights().is_err());
    assert!(
        state
            .project_canonical_runtime(&malformed, &state.world.view())
            .is_err()
    );
    assert!(
        state
            .install_canonical_runtime_projection(
                &state.nexus_snapshot(),
                &BTreeMap::new(),
                &VecDeque::new(),
            )
            .is_err()
    );
    let mut duplicate = original.clone();
    duplicate
        .lane_incarnation_lineage
        .push(duplicate.lane_incarnation_lineage[0].clone());
    let mut unordered = original.clone();
    unordered
        .lane_incarnation_lineage
        .push(SnapshotLaneIncarnationLineage {
            lane_id: LaneId::new(7),
            generation: 1,
            incarnation: Hash::new(b"retained unordered lineage fixture"),
            activation_height: 1,
        });
    unordered.lane_incarnation_lineage.swap(0, 1);
    for invalid in [&duplicate, &unordered] {
        assert!(invalid.active_incarnations().is_err());
        assert!(invalid.active_activation_heights().is_err());
        assert!(
            state
                .project_canonical_runtime(invalid, &state.world.view())
                .is_err()
        );
    }
    assert_eq!(state.canonical_runtime.view().get(), &original);
    assert!(state.canonical_runtime.predecessor_view().is_none());
}

#[test]
fn retained_runtime_policy_is_not_reinterpreted_by_a_later_configured_baseline() {
    let state = state();
    let original = state.canonical_runtime.view().get().clone();
    let mut different_baseline = state.nexus.read().clone();
    different_baseline.autoscale.enabled = !original.owner_policy.autoscale_enabled;
    different_baseline.staking.max_validators =
        std::num::NonZeroU32::new(original.owner_policy.max_validators + 1).unwrap();
    different_baseline.autoscale.scale_out_window_blocks = std::num::NonZeroU16::MAX;
    let projected = original.nexus_projection(&different_baseline).unwrap();
    assert_eq!(
        SnapshotNexusOwnerPolicy::from_nexus(&projected),
        original.owner_policy
    );
    assert_eq!(
        projected.autoscale.scale_out_window_blocks.get(),
        original.autoscale_scale_out_window_blocks
    );
}

#[test]
fn consensus_only_apply_refuses_a_staged_runtime_transition() {
    let state = state();
    let original = state.canonical_runtime.view().get().clone();
    let mut block = state.merge_preexecution_block(header());
    {
        let mut transaction = block.transaction();
        transaction
            .canonical_runtime
            .get_mut()
            .autoscale_last_transition_height = 1;
        transaction.apply_consensus_effects();
    }
    assert_eq!(block.canonical_runtime.get(), &original);
    assert!(matches!(
        block.commit(),
        Err(TransactionsBlockError::ExecutionOutputCapacity)
    ));
    assert_eq!(state.canonical_runtime.view().get(), &original);
}

fn snapshot_capture_test(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(test)
        .expect("spawn bounded-stack State fixture")
        .join()
        .expect("snapshot capture fixture must pass");
}

#[test]
fn snapshot_capture_refuses_active_publisher_without_waiting() {
    snapshot_capture_test(|| {
        let state = state();
        let original_nexus = state.nexus_snapshot();
        let mut publication_notice = state.state_view_publication();
        let publication = publication_notice.begin();
        assert!(state.try_nexus_snapshot_once().unwrap().is_none());
        assert_eq!(
            state.nexus_ownership_projection().lane_catalog,
            original_nexus.lane_catalog
        );
        // Cursor persistence also runs inside lane-geometry publication. Its
        // ownership-only input must not wait on the generation held here.
        state.persist_da_shard_cursor_journal();
        assert!(matches!(
            state.try_view_once(),
            Err(StateViewError::Busy(_))
        ));
        let error = match crate::snapshot::CapturedStateSnapshot::capture(&state) {
            Ok(_) => panic!("odd publication generation cannot yield a snapshot"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            crate::snapshot::SnapshotCaptureError::Read(StateViewError::Busy(_))
        ));
        assert!(matches!(
            MergeLedgerCommitError::from(error),
            MergeLedgerCommitError::StateView(StateViewError::Busy(_))
        ));
        drop(publication);
        drop(publication_notice);
        assert_eq!(
            state
                .try_nexus_snapshot_once()
                .unwrap()
                .expect("completed publication must admit a Nexus snapshot")
                .dataspace_catalog,
            original_nexus.dataspace_catalog
        );
        // Manifest refresh authenticates its catalog binding under the State writer;
        // rejecting an unbound registry publishes no replacement State generation.
        assert!(
            !state.install_lane_manifests_if_consensus_compatible(&Arc::new(
                LaneManifestRegistry::default()
            ))
        );
        assert!(crate::snapshot::CapturedStateSnapshot::capture(&state).is_ok());
    });
}

#[test]
fn snapshot_capture_discards_bytes_after_completed_publication() {
    snapshot_capture_test(|| {
        let state = state();
        let before = crate::snapshot::canonical_state_snapshot_hash(&state).unwrap();
        let error = match crate::snapshot::CapturedStateSnapshot::capture_with_publication_for_test(
            &state,
            || {
                // Even a semantically empty real publication invalidates the observation.
                let mut publication_notice = state.state_view_publication();
                let publication = publication_notice.begin();
                drop(publication);
                drop(publication_notice);
            },
        ) {
            Ok(_) => panic!("changed generation cannot yield the partial capture"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            crate::snapshot::SnapshotCaptureError::Changed(_)
        ));
        assert!(matches!(
            TransactionsBlockError::from(error),
            TransactionsBlockError::PublicationBusy(_)
        ));
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_hash(&state).unwrap(),
            before
        );
    });
}

#[test]
fn snapshot_capture_stable_malformed_runtime_is_fallible_and_read_only() {
    snapshot_capture_test(|| {
        let state = state();
        {
            let mut publication_notice = state.state_view_publication();
            let publication = publication_notice.begin();
            let mut runtime = state.canonical_runtime.block();
            runtime.get_mut().lane_incarnation_lineage.clear();
            runtime.commit();
            drop(publication);
            drop(publication_notice);
        }
        let before = norito::json::to_json(&state.canonical_runtime).unwrap();
        let world_before = norito::json::to_json(&state.world).unwrap();
        let error = match crate::snapshot::CapturedStateSnapshot::capture(&state) {
            Ok(_) => panic!("incomplete lineage must fail the actual projection"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            crate::snapshot::SnapshotCaptureError::Runtime(_)
        ));
        assert!(!error.is_observation_changed());
        assert!(matches!(
            TransactionsBlockError::from(error),
            TransactionsBlockError::SnapshotProjection
        ));
        assert_eq!(
            norito::json::to_json(&state.canonical_runtime).unwrap(),
            before
        );
        assert_eq!(norito::json::to_json(&state.world).unwrap(), world_before);
    });
}

#[test]
fn snapshot_capture_retains_exact_topology_bytes_after_later_publication() {
    snapshot_capture_test(|| {
        let state = state();
        let captured = crate::snapshot::CapturedStateSnapshot::capture(&state).unwrap();
        let original = captured.as_json().to_owned();
        let hash = captured.canonical_hash().unwrap();
        {
            // Explicit topology-owner fixture, not authenticated carrier application.
            let mut publication_notice = state.state_view_publication();
            let publication = publication_notice.begin();
            let mut topology = state.commit_topology.block();
            topology.get_mut().push(iroha_model_base::peer::PeerId::new(
                iroha_test_samples::ALICE_KEYPAIR.public_key().clone(),
            ));
            topology.commit();
            drop(publication);
            drop(publication_notice);
        }
        let current = crate::snapshot::CapturedStateSnapshot::capture(&state).unwrap();
        assert_eq!(captured.as_json(), original);
        assert_ne!(current.as_json(), original);
        assert_eq!(captured.canonical_hash().unwrap(), hash);
        // Consensus topology is deliberately redacted only from the existing WSV hash,
        // while the restart payload must retain both exact topology Cell cuts.
        assert_eq!(current.canonical_hash().unwrap(), hash);
        let encoded: norito::json::Value = norito::json::from_str(current.as_json()).unwrap();
        assert_eq!(
            encoded["commit_topology"]["revert"]["value"],
            norito::json::Value::Array(Vec::new())
        );
        assert_eq!(
            encoded["commit_topology"]["blocks"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    });
}
