// Runtime setter tests exercise catalog authority independently of activation committee eligibility.
use crate::query::store::LiveQueryStore;
use iroha_data_model::nexus::{
    DataSpaceMetadata, NexusRuntimeCatalogV1, RuntimeDataSpaceAdditionV1, dataspace_catalog_hash,
};

fn run_runtime_configuration_test(test: impl FnOnce() + Send + 'static) {
    let result = std::thread::Builder::new()
        .name("runtime-dataspace-setter".to_owned())
        .stack_size(32 * 1024 * 1024)
        .spawn(test)
        .expect("bounded debug State fixture")
        .join();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

fn additional_dataspace() -> RuntimeDataSpaceAdditionV1 {
    let manifest_hash = [0x67; 32];
    RuntimeDataSpaceAdditionV1 {
        descriptor: DataSpaceMetadata {
            id: DataSpaceId::from_hash(&manifest_hash),
            alias: "runtime-dataspace".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
        manifest_hash,
    }
}

#[test]
fn configured_evidence_preparation_pool_preserves_identity_and_refuses_live_replacement() {
    run_runtime_configuration_test(|| {
        let mut state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let one_plan =
            iroha_config::parameters::defaults::nexus::storage::CONSENSUS_EVIDENCE_ONE_PLAN_BYTES;
        let mut one_plan_config = state.nexus_snapshot();
        one_plan_config.storage.consensus_evidence_preparation_bytes = one_plan;
        state
            .set_nexus_from_config(one_plan_config.clone())
            .expect("one complete plan is a valid configured pool");
        assert_eq!(state.evidence_preparation_budget().limit_bytes(), one_plan);
        let charge = state
            .evidence_preparation_budget()
            .try_reserve_bytes(one_plan)
            .expect("hold the original configured pool");
        state
            .set_nexus_from_config(one_plan_config.clone())
            .expect("unchanged configuration retains the original occupied pool");
        assert_eq!(
            state.evidence_preparation_budget().reserved_bytes(),
            one_plan
        );

        let mut changed = one_plan_config.clone();
        changed.storage.consensus_evidence_preparation_bytes = 8 * one_plan;
        assert!(matches!(
            state.set_nexus_from_config(changed.clone()),
            Err(LaneLifecycleError::EvidencePreparationBudgetBusy { reserved_bytes })
                if reserved_bytes == one_plan
        ));
        assert_eq!(
            state
                .nexus_snapshot()
                .storage
                .consensus_evidence_preparation_bytes,
            one_plan
        );
        drop(charge);
        state
            .set_nexus_from_config(changed.clone())
            .expect("released original pool permits a configured replacement");
        assert_eq!(
            state.evidence_preparation_budget().limit_bytes(),
            8 * one_plan
        );
        let mut runtime_update = state.nexus_snapshot();
        runtime_update.storage.consensus_evidence_preparation_bytes = one_plan;
        state
            .set_nexus(runtime_update)
            .expect("runtime catalogs retain process-local evidence custody");
        assert_eq!(
            state.evidence_preparation_budget().limit_bytes(),
            8 * one_plan
        );

        changed.storage.consensus_evidence_preparation_bytes = one_plan - 1;
        assert!(matches!(
            state.set_nexus_from_config(changed),
            Err(LaneLifecycleError::EvidencePreparationBudgetTooSmall { .. })
        ));
        assert_eq!(
            state.evidence_preparation_budget().limit_bytes(),
            8 * one_plan
        );
    });
}

#[test]
fn configured_stake_index_pool_keeps_original_charge_through_reconfiguration() {
    run_runtime_configuration_test(|| {
        let mut state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let minimum =
            iroha_config::parameters::defaults::nexus::storage::CONSENSUS_STAKE_INDEX_MIN_BYTES;
        let mut configured = state.nexus_snapshot();
        configured.storage.consensus_stake_index_bytes = minimum;
        state
            .set_nexus_from_config(configured.clone())
            .expect("one exact flat key is a finite pool");
        let charge = state
            .stake_index_budget()
            .try_reserve_bytes(minimum)
            .expect("hold the original configured pool");
        let mut changed = configured.clone();
        changed.storage.consensus_stake_index_bytes = minimum * 2;
        assert!(matches!(
            state.set_nexus_from_config(changed.clone()),
            Err(LaneLifecycleError::StakeIndexBudgetBusy { reserved_bytes })
                if reserved_bytes == minimum
        ));
        assert_eq!(state.stake_index_budget().reserved_bytes(), minimum);
        drop(charge);
        state
            .set_nexus_from_config(changed)
            .expect("released original permits replacement");
        assert_eq!(state.stake_index_budget().limit_bytes(), minimum * 2);
        let mut invalid = configured;
        invalid.storage.consensus_stake_index_bytes = minimum - 1;
        assert!(matches!(
            state.set_nexus_from_config(invalid),
            Err(LaneLifecycleError::StakeIndexBudgetTooSmall { .. })
        ));
    });
}

#[test]
fn execution_pool_handle_preserves_original_identity_and_reservations() {
    run_runtime_configuration_test(|| {
        let state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let original = state.ivm_execution_budget();
        // State retains its admitted native execution identity in this same pool.
        let retained_bytes = original.reserved_bytes();
        let borrowed = state.ivm_execution_budget();
        assert!(borrowed.same_pool(&original));
        assert_eq!(borrowed.reserved_bytes(), retained_bytes);
        let held = borrowed.try_reserve_bytes(1).expect("original pool charge");
        assert!(held.belongs_to(&original));
        assert_eq!(original.reserved_bytes(), retained_bytes + 1);
        assert_eq!(borrowed.reserved_bytes(), retained_bytes + 1);
        drop(held);
        assert_eq!(original.reserved_bytes(), retained_bytes);
        assert_eq!(borrowed.reserved_bytes(), retained_bytes);
    });
}

#[test]
fn pipeline_execution_pool_is_shared_while_query_and_consensus_caches_stay_isolated() {
    run_runtime_configuration_test(|| {
        let mut state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let retained_bytes = state.ivm_execution_budget().reserved_bytes();
        let mut pipeline = state.pipeline.clone();
        pipeline.ivm_execution_max_bytes = retained_bytes + 137;
        state.set_pipeline(pipeline);
        let prepared = state.pipeline_ivm_prepared_cache.read().clone();
        let trigger = state.trigger_ivm_cache.lock().prepared_contract_cache();
        let query = state
            .contract_query_ivm_cache
            .lock()
            .prepared_contract_cache();
        assert_eq!(
            prepared.execution_budget().limit_bytes(),
            retained_bytes + 137
        );
        let held = prepared.execution_budget().try_reserve_bytes(137).unwrap();
        assert!(held.belongs_to(trigger.execution_budget()));
        assert!(held.belongs_to(query.execution_budget()));
        assert!(matches!(
            query.execution_budget().try_reserve_bytes(1),
            Err(iroha_allocation::AllocationRefusal::Capacity { .. })
        ));
        drop(held);
        assert_eq!(trigger.execution_budget().reserved_bytes(), retained_bytes);
        assert_eq!(query.execution_budget().reserved_bytes(), retained_bytes);
    });
}

#[test]
fn pipeline_reload_keeps_borrowed_execution_pool_across_shrink_and_growth() {
    run_runtime_configuration_test(|| {
        let mut state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let retained_bytes = state.ivm_execution_budget().reserved_bytes();
        let mut pipeline = state.pipeline.clone();
        pipeline.ivm_execution_max_bytes = retained_bytes + 137;
        state.set_pipeline(pipeline.clone());
        let borrowed_cache = state.pipeline_ivm_prepared_cache.read().clone();
        let original_budget = borrowed_cache.execution_budget().clone();
        let held = original_budget.try_reserve_bytes(120).unwrap();
        assert!(held.belongs_to(&state.ivm_execution_budget()));

        pipeline.ivm_execution_max_bytes = retained_bytes + 80;
        state.set_pipeline(pipeline.clone());
        assert!(held.belongs_to(&state.ivm_execution_budget()));
        let fresh_cache = state.pipeline_ivm_prepared_cache.read().clone();
        let trigger = state.trigger_ivm_cache.lock().prepared_contract_cache();
        let query = state
            .contract_query_ivm_cache
            .lock()
            .prepared_contract_cache();
        for budget in [
            fresh_cache.execution_budget(),
            trigger.execution_budget(),
            query.execution_budget(),
        ] {
            assert!(held.belongs_to(budget));
            assert_eq!(budget.limit_bytes(), retained_bytes + 80);
            assert_eq!(budget.reserved_bytes(), retained_bytes + 120);
            assert!(matches!(
                budget.try_reserve_bytes(1),
                Err(iroha_allocation::AllocationRefusal::Capacity {
                    requested_bytes: 1,
                    reserved_bytes,
                    limit_bytes,
                    ..
                }) if reserved_bytes == retained_bytes + 120 && limit_bytes == retained_bytes + 80
            ));
        }
        assert_eq!(original_budget.limit_bytes(), retained_bytes + 80);
        drop(held);
        let within_shrunken_limit = original_budget.try_reserve_bytes(80).unwrap();
        assert!(within_shrunken_limit.belongs_to(fresh_cache.execution_budget()));

        pipeline.ivm_execution_max_bytes = retained_bytes + 160;
        state.set_pipeline(pipeline);
        assert!(within_shrunken_limit.belongs_to(&state.ivm_execution_budget()));
        let enlarged = state.pipeline_ivm_prepared_cache.read().clone();
        assert!(within_shrunken_limit.belongs_to(enlarged.execution_budget()));
        let newly_available = enlarged.execution_budget().try_reserve_bytes(80).unwrap();
        assert_eq!(
            enlarged.execution_budget().reserved_bytes(),
            retained_bytes + 160
        );
        drop(within_shrunken_limit);
        drop(newly_available);
        assert_eq!(
            borrowed_cache.execution_budget().reserved_bytes(),
            retained_bytes
        );
    });
}

#[test]
fn settlement_setter_rebuilds_the_exact_state_owned_router_engine() {
    run_runtime_configuration_test(|| {
        let mut state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let original = state.settlement().clone();
        assert!(
            state
                .settlement_engine
                .matches_router_config(&original.router)
        );

        let mut changed = original.clone();
        changed.router.epsilon_bps += 1;
        changed.router.buffer_halt_pct += 1;
        assert!(
            !state
                .settlement_engine
                .matches_router_config(&changed.router)
        );
        state.set_settlement(changed);
        assert!(
            state
                .settlement_engine
                .matches_router_config(&state.settlement().router)
        );
        assert!(
            !state
                .settlement_engine
                .matches_router_config(&original.router)
        );
    });
}

#[test]
fn runtime_nexus_setter_preserves_configured_dataspaces_and_rejects_post_genesis_drift() {
    run_runtime_configuration_test(|| {
        let mut state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let original = state.nexus_snapshot();
        let mut expanded = original.dataspace_catalog.entries().to_vec();
        expanded.push(additional_dataspace().descriptor);
        let expanded = DataSpaceCatalog::new(expanded).unwrap();
        let mut requested = original.clone();
        requested.configured_dataspace_catalog = expanded.clone();
        state
            .set_nexus(requested)
            .expect("ordinary setter preserves baseline");
        assert_eq!(
            state.nexus_snapshot().configured_dataspace_catalog,
            original.configured_dataspace_catalog
        );

        let mut hashes = state.block_hashes.block();
        hashes.push(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0x23; 32]),
        ));
        hashes.commit();
        let mut requested = state.nexus_snapshot();
        requested.dataspace_catalog = expanded;
        assert!(matches!(
            state.set_nexus(requested),
            Err(LaneLifecycleError::RuntimeCatalog(_))
        ));
        assert_eq!(
            state.nexus_snapshot().dataspace_catalog,
            original.dataspace_catalog
        );
        assert_eq!(
            state.nexus_snapshot().configured_dataspace_catalog,
            original.configured_dataspace_catalog
        );
    });
}

#[test]
fn runtime_nexus_setter_requires_exact_protected_dataspace_projection() {
    run_runtime_configuration_test(|| {
        let mut state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let original = state.nexus_snapshot();
        let runtime = NexusRuntimeCatalogV1 {
            version: NexusRuntimeCatalogV1::VERSION,
            baseline_dataspaces_hash: dataspace_catalog_hash(
                &original.configured_dataspace_catalog,
            ),
            baseline_manifests_hash: Hash::prehashed(
                state
                    .lane_manifests
                    .read()
                    .baseline_consensus_policy_digest(),
            ),
            dataspaces: vec![additional_dataspace()],
            manifests: vec![],
        };
        let expected =
            runtime_catalog_dataspaces(&original.configured_dataspace_catalog, Some(&runtime))
                .unwrap();
        let mut world = state.world.block();
        world
            .parameters
            .get_mut()
            .set_parameter(iroha_data_model::parameter::Parameter::Custom(
                runtime
                    .into_custom_parameter()
                    .expect("bounded cumulative DS fixture"),
            ));
        world.commit();
        assert!(matches!(
            state.try_nexus_snapshot_once(),
            Err(LaneLifecycleError::RuntimeCatalog(ref reason))
                if reason == "canonical runtime ownership differs from its scoped World catalog"
        ));

        let mut requested = original.clone();
        requested.dataspace_catalog = expected.clone();
        // Complete this metadata-only fixture before exercising the ordinary setter.
        // A World-only catalog is not a published canonical runtime transition.
        state
            .install_canonical_runtime_projection(
                &requested,
                &state.lane_incarnation_lineage_snapshot(),
                &state.autoscale_sample_history_snapshot(),
            )
            .expect("matching canonical runtime metadata fixture");
        assert_eq!(state.nexus_snapshot().dataspace_catalog, expected);
        let runtime_before = state.canonical_runtime.view().get().clone();
        let predecessor_before = state.canonical_runtime.predecessor_view().get().clone();
        let world_before = norito::json::to_json(&state.world).unwrap();
        let cache_before = state.nexus.read().clone();
        let geometry_before = state.kura.lane_geometry_journal_state_for_test().unwrap();
        let error = state
            .set_nexus(original.clone())
            .expect_err("omitting the committed DS must fail before mutation");
        assert!(
            matches!(error, LaneLifecycleError::RuntimeCatalog(ref reason)
                if reason == "runtime Nexus setter cannot change committed physical dataspaces")
        );
        assert_eq!(state.canonical_runtime.view().get(), &runtime_before);
        assert_eq!(
            state.canonical_runtime.predecessor_view().get(),
            &predecessor_before
        );
        assert_eq!(norito::json::to_json(&state.world).unwrap(), world_before);
        {
            let cache = state.nexus.read();
            assert_eq!(cache.lane_catalog, cache_before.lane_catalog);
            assert_eq!(
                cache.configured_lane_catalog,
                cache_before.configured_lane_catalog
            );
            assert_eq!(cache.dataspace_catalog, cache_before.dataspace_catalog);
            assert_eq!(
                cache.configured_dataspace_catalog,
                cache_before.configured_dataspace_catalog
            );
            assert_eq!(cache.routing_policy, cache_before.routing_policy);
        }
        assert_eq!(
            state.kura.lane_geometry_journal_state_for_test().unwrap(),
            geometry_before
        );
        assert_eq!(state.nexus_snapshot().dataspace_catalog, expected);
        state
            .set_nexus(requested)
            .expect("exact protected DS projection");
        assert_eq!(state.nexus_snapshot().dataspace_catalog, expected);
        assert_eq!(
            state.nexus_snapshot().configured_dataspace_catalog,
            original.configured_dataspace_catalog
        );
    });
}

#[test]
fn ordinary_nexus_setter_rejects_pre_genesis_dataspace_drift_before_publication() {
    run_runtime_configuration_test(|| {
        let mut state = State::new_with_pre_genesis_nexus_for_testing(
            World::new(),
            Default::default(),
            LiveQueryStore::start_test(),
        );
        assert_eq!(state.committed_height(), 0);
        let before = crate::snapshot::canonical_state_snapshot_bytes_for_tests(&state);
        let runtime_before = state.canonical_runtime.view().get().clone();
        let predecessor_before = state.canonical_runtime.predecessor_view().get().clone();
        let geometry_before = state.kura.lane_geometry_journal_state_for_test().unwrap();
        let installed = state.nexus_snapshot();
        let mut entries = installed.dataspace_catalog.entries().to_vec();
        entries.push(additional_dataspace().descriptor);
        let expanded = DataSpaceCatalog::new(entries).unwrap();
        for also_claim_baseline in [false, true] {
            let mut requested = installed.clone();
            requested.dataspace_catalog = expanded.clone();
            if also_claim_baseline {
                requested.configured_dataspace_catalog = expanded.clone();
            }
            let error = state
                .set_nexus(requested)
                .expect_err("ordinary setter cannot replace canonical baseline at height zero");
            assert!(
                matches!(error, LaneLifecycleError::RuntimeCatalog(ref reason)
                if reason == "ordinary Nexus setter cannot change the physical dataspace baseline; use set_nexus_from_config before genesis")
            );
            let view = state.view();
            assert_eq!(view.nexus.dataspace_catalog, installed.dataspace_catalog);
            assert_eq!(
                view.nexus.configured_dataspace_catalog,
                installed.configured_dataspace_catalog
            );
            drop(view);
            let query = state.query_view();
            assert_eq!(query.nexus.dataspace_catalog, installed.dataspace_catalog);
            drop(query);
            assert_eq!(state.canonical_runtime.view().get(), &runtime_before);
            assert_eq!(
                state.canonical_runtime.predecessor_view().get(),
                &predecessor_before
            );
            assert_eq!(
                state.kura.lane_geometry_journal_state_for_test().unwrap(),
                geometry_before
            );
            assert_eq!(
                crate::snapshot::canonical_state_snapshot_bytes_for_tests(&state),
                before
            );
        }
    });
}

#[test]
fn configured_nexus_installer_establishes_one_valid_pre_genesis_dataspace_baseline() {
    run_runtime_configuration_test(|| {
        let mut configured = iroha_config::parameters::actual::Nexus::default();
        let mut entries = configured.dataspace_catalog.entries().to_vec();
        entries.push(additional_dataspace().descriptor);
        let expected = DataSpaceCatalog::new(entries).unwrap();
        configured.dataspace_catalog = expected.clone();
        configured.configured_dataspace_catalog = expected.clone();
        // This fixture runs the actual authenticated Kura primary anchor and
        // set_nexus_from_config startup path; it does not install a raw runtime map.
        let mut state = State::new_with_pre_genesis_nexus_for_testing(
            World::new(),
            configured.clone(),
            LiveQueryStore::start_test(),
        );
        assert_eq!(state.committed_height(), 0);
        state
            .set_nexus_from_config(configured)
            .expect("validated baseline reinstallation remains idempotent");
        let view = state.view();
        assert_eq!(view.nexus.dataspace_catalog, expected);
        assert_eq!(view.nexus.configured_dataspace_catalog, expected);
        assert_eq!(
            view.canonical_runtime.get().owner_policy,
            SnapshotNexusOwnerPolicy::from_nexus(&view.nexus)
        );
        drop(view);
        assert!(
            state.canonical_runtime.predecessor_view().is_none(),
            "same-cut startup cannot invent a height-zero predecessor"
        );
        state
            .set_nexus(state.nexus_snapshot())
            .expect("ordinary setter accepts the installed exact projection");
        assert_eq!(state.query_view().nexus.dataspace_catalog, expected);
    });
}

/// Structural setter controls: flags and height markers select admission branches.
/// These fixtures neither create finality nor qualify snapshot authentication/replay.
fn assert_retained_dataspace_configuration_guard(restored: bool, committed: bool) {
    let mut configured = iroha_config::parameters::actual::Nexus::default();
    let retained_unused = additional_dataspace().descriptor;
    let mut entries = configured.dataspace_catalog.entries().to_vec();
    entries.push(retained_unused.clone());
    configured.configured_dataspace_catalog = DataSpaceCatalog::new(entries).unwrap();
    configured.dataspace_catalog = configured.configured_dataspace_catalog.clone();
    let mut state = Box::new(State::new_with_pre_genesis_nexus_for_testing(
        World::new(),
        configured.clone(),
        LiveQueryStore::start_test(),
    ));
    state.nexus_runtime_restored_from_snapshot = restored;
    if committed {
        // Only a structural nonzero-height marker for this setter guard. No body,
        // QC, signed snapshot, or synthetic runtime predecessor is fabricated.
        let mut hashes = state.block_hashes.block();
        hashes.push(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            b"configured dataspace setter height marker",
        )));
        hashes.commit();
    }
    assert!(
        runtime_catalog_from_world(&state.world.view())
            .unwrap()
            .is_none()
    );
    assert_eq!(state.committed_height(), usize::from(committed));

    for reinstalled in [false, true] {
        if reinstalled {
            state
                .set_nexus_from_config(configured.clone())
                .expect("exact retained configuration remains admissible");
        }
        let before = crate::snapshot::canonical_state_snapshot_bytes_for_tests(&state);
        let runtime_before = state.canonical_runtime.view().get().clone();
        let predecessor_before = state.canonical_runtime.predecessor_view().get().clone();
        let geometry_before = state.kura.lane_geometry_journal_state_for_test().unwrap();
        for change in ["add", "remove", "alias", "fault_tolerance"] {
            let mut entries = configured.configured_dataspace_catalog.entries().to_vec();
            match change {
                "add" => entries.push(DataSpaceMetadata {
                    id: DataSpaceId::from_hash(&[0x68; 32]),
                    alias: "uncommitted-dataspace".to_owned(),
                    description: None,
                    fault_tolerance: 1,
                }),
                "remove" => entries.retain(|entry| entry.id != retained_unused.id),
                "alias" => {
                    entries
                        .iter_mut()
                        .find(|entry| entry.id == retained_unused.id)
                        .unwrap()
                        .alias = "renamed-dataspace".to_owned();
                }
                "fault_tolerance" => {
                    entries
                        .iter_mut()
                        .find(|entry| entry.id == retained_unused.id)
                        .unwrap()
                        .fault_tolerance += 1;
                }
                _ => unreachable!("fixed structural mutation list"),
            }
            let mut requested = configured.clone();
            requested.configured_dataspace_catalog = DataSpaceCatalog::new(entries).unwrap();
            // Match daemon startup: effective topology still names the retained
            // snapshot while the process-configured baseline claims a change.
            assert_eq!(requested.lane_catalog, state.nexus_snapshot().lane_catalog);
            assert_eq!(requested.dataspace_catalog, configured.dataspace_catalog);
            for install in [false, true] {
                let result = if install {
                    state.set_nexus_from_config(requested.clone())
                } else {
                    state
                        .nexus_with_committed_catalog(requested.clone())
                        .map(|_| ())
                };
                let error = result.expect_err("retained physical authority must reject drift");
                assert!(
                    matches!(error, LaneLifecycleError::RuntimeCatalog(ref reason)
                    if reason == "configured catalog differs from retained physical dataspace authority"),
                    "{change}, restored={restored}, committed={committed}, install={install}: {error}"
                );
                assert_eq!(
                    state.nexus_snapshot().dataspace_catalog,
                    configured.dataspace_catalog
                );
                assert_eq!(
                    state.nexus_snapshot().configured_dataspace_catalog,
                    configured.configured_dataspace_catalog
                );
                assert_eq!(state.canonical_runtime.view().get(), &runtime_before);
                assert_eq!(
                    state.canonical_runtime.predecessor_view().get(),
                    &predecessor_before
                );
                assert_eq!(
                    state.kura.lane_geometry_journal_state_for_test().unwrap(),
                    geometry_before
                );
                assert_eq!(
                    crate::snapshot::canonical_state_snapshot_bytes_for_tests(&state),
                    before,
                    "all World stores and retained runtime cuts must remain unchanged"
                );
            }
        }
    }
    let projected = state
        .nexus_with_committed_catalog(configured.clone())
        .unwrap();
    assert_eq!(projected.dataspace_catalog, configured.dataspace_catalog);
    state
        .set_nexus_from_config(configured)
        .expect("exact policy remains admissible after negative controls");
}

#[test]
fn configured_dataspace_projection_rejects_restored_h0_drift_without_overlay() {
    run_runtime_configuration_test(|| assert_retained_dataspace_configuration_guard(true, false));
}

#[test]
fn configured_dataspace_projection_rejects_committed_drift_without_overlay() {
    run_runtime_configuration_test(|| {
        assert_retained_dataspace_configuration_guard(false, true);
        assert_retained_dataspace_configuration_guard(true, true);
    });
}

#[test]
fn configured_dataspace_projection_preserves_description_only_identity() {
    run_runtime_configuration_test(|| {
        let mut state = State::new_with_pre_genesis_nexus_for_testing(
            World::new(),
            Default::default(),
            LiveQueryStore::start_test(),
        );
        // Select the restored-state guard without claiming a signed import.
        state.nexus_runtime_restored_from_snapshot = true;
        let before = crate::snapshot::canonical_state_snapshot_bytes_for_tests(&state);
        let runtime_before = state.canonical_runtime.view().get().clone();
        let predecessor_before = state.canonical_runtime.predecessor_view().get().clone();
        let geometry_before = state.kura.lane_geometry_journal_state_for_test().unwrap();
        let mut requested = state.nexus_snapshot();
        let mut entries = requested.configured_dataspace_catalog.entries().to_vec();
        entries[0].description = Some("local operator description".to_owned());
        requested.configured_dataspace_catalog = DataSpaceCatalog::new(entries).unwrap();
        let projected = state
            .nexus_with_committed_catalog(requested.clone())
            .unwrap();
        assert_eq!(
            projected.dataspace_catalog.entries()[0]
                .description
                .as_deref(),
            Some("local operator description")
        );
        state
            .set_nexus_from_config(requested)
            .expect("descriptions do not change physical dataspace authority");
        assert_eq!(state.canonical_runtime.view().get(), &runtime_before);
        assert_eq!(
            state.canonical_runtime.predecessor_view().get(),
            &predecessor_before
        );
        assert_eq!(
            state.kura.lane_geometry_journal_state_for_test().unwrap(),
            geometry_before
        );
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_bytes_for_tests(&state),
            before
        );
    });
}

#[test]
fn restore_adopts_original_startup_pool_before_runtime_configuration() {
    if crate::unit_test_support::run_in_isolated_harness(
        "state::runtime_configuration_tests::restore_adopts_original_startup_pool_before_runtime_configuration",
    ) {
        return;
    }
    run_runtime_configuration_test(|| {
        let state = State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let snapshot = norito::json::to_value(&state).unwrap();
        let restore = |execution_budget, snapshot| {
            deserialize::KuraSeed {
                execution_budget,
                lane_manifests: state.lane_manifests.read().clone(),
                kura: state.kura_handle(),
                query_handle: state.query_handle.clone(),
                #[cfg(feature = "telemetry")]
                telemetry: StateTelemetry::default(),
            }
            .into_state_from_json(snapshot)
        };
        // A restored State retains scalar, native-tip and AMX owners in the same
        // startup pool. Measure the retained owners and transient restore
        // demand independently, preserving the original exact 137-byte window
        // above the real peak while the startup reservation remains held.
        let probe_budget = iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        );
        assert_eq!(probe_budget.reserved_bytes(), 0);
        let probe = restore(probe_budget.clone(), snapshot.clone()).unwrap();
        let retained_bytes = probe_budget.reserved_bytes();
        let restore_peak = probe_budget.peak_reserved_bytes();
        let retained_layout_bytes = mv::cell::CellInitialization::<u64>::allocation_layouts()
            .into_iter()
            .chain(mv::cell::CellInitialization::<Option<NativeExecutionTip>>::allocation_layouts())
            .chain(mv::cell::CellInitialization::<
                crate::sumeragi::amx::RetainedNativeAmx,
            >::allocation_layouts())
            .map(|layout| layout.size())
            .sum::<usize>();
        let retired_ebr_bytes =
            Cell::<u64, iroha_allocation::AllocationCharge>::allocation_layouts()
                .into_iter()
                .chain(native_execution_tip::TipCell::allocation_layouts())
                .chain(Cell::<
                    crate::sumeragi::amx::RetainedNativeAmx,
                    iroha_allocation::AllocationCharge,
                >::allocation_layouts())
                .map(|layout| layout.size())
                .sum::<usize>();
        let lock_releases = [
            probe.latest_block_header.observe_release(),
            probe.da_commitments.observe_release(),
            probe.da_confidential_compute.observe_release(),
            probe.da_receipt_cursors.observe_release(),
            probe.da_shard_cursors.observe_release(),
            probe.da_pin_intents.observe_release(),
            probe.lane_manifests.observe_release(),
            probe.lane_privacy_registry.observe_release(),
            probe.da_indexes_hydrated.observe_release(),
            probe.pipeline_ivm_prepared_cache.observe_release(),
            probe.nexus.observe_release(),
            probe.crypto.observe_release(),
            probe.state_write_lock.observe_release(),
        ];
        let notification_bytes = lock_releases.len()
            * iroha_allocation::release::ReleaseNotification::allocation_layout::<
                iroha_allocation::AllocationCharge,
            >()
            .size();
        // Count every actual admitted lock control without retaining a release
        // observation across State retirement.
        drop(lock_releases);
        assert_eq!(retained_bytes, retained_layout_bytes + notification_bytes);
        assert!(retired_ebr_bytes > 0);
        assert!(retired_ebr_bytes < retained_bytes);
        assert!(restore_peak >= retained_bytes);
        // The scalar, native-tip and AMX EBR generations remain charged while this
        // reader pin prevents reclamation. Unborrowed publication identities
        // and notification owners free with State and refund their own charges.
        let retirement_pin = crossbeam_epoch::pin();
        drop(probe);
        retirement_pin.flush();
        assert_eq!(probe_budget.reserved_bytes(), retired_ebr_bytes);
        drop(retirement_pin);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while probe_budget.reserved_bytes() != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "original restored owners were not reclaimed after their readers released"
            );
            crossbeam_epoch::pin().flush();
            std::thread::yield_now();
        }
        assert_eq!(probe_budget.reserved_bytes(), 0);
        let budget = iroha_allocation::AllocationBudget::new(restore_peak + 137);
        let held = budget.try_reserve_bytes(120).unwrap();
        let mut restored = restore(budget.clone(), snapshot).unwrap();
        assert_eq!(budget.peak_reserved_bytes(), restore_peak + 120);
        let prepared = restored.pipeline_ivm_prepared_cache.read().clone();
        let trigger = restored.trigger_ivm_cache.lock().prepared_contract_cache();
        let query = restored
            .contract_query_ivm_cache
            .lock()
            .prepared_contract_cache();
        for owner in [
            prepared.execution_budget(),
            trigger.execution_budget(),
            query.execution_budget(),
        ] {
            assert!(held.belongs_to(owner));
            assert_eq!(owner.reserved_bytes(), retained_bytes + 120);
            assert_eq!(owner.limit_bytes(), restore_peak + 137);
        }
        let mut pipeline = restored.pipeline.clone();
        pipeline.ivm_execution_max_bytes = retained_bytes + 80;
        restored.set_pipeline(pipeline);
        assert!(held.belongs_to(&restored.ivm_execution_budget()));
        assert!(
            restored
                .ivm_execution_budget()
                .try_reserve_bytes(1)
                .is_err()
        );
        drop(held);
        assert_eq!(budget.reserved_bytes(), retained_bytes);
        let retry = restored
            .ivm_execution_budget()
            .try_reserve_bytes(80)
            .unwrap();
        assert!(retry.belongs_to(&budget));
    });
}

#[test]
fn cold_execution_pool_handle_needs_no_cache_lock_or_thread_allocation() {
    run_runtime_configuration_test(|| {
        let state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let original = state
            .pipeline_ivm_prepared_cache
            .read()
            .execution_budget()
            .clone();
        let before = original.reserved_bytes();
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let mut retained = None;
                    assert_eq!(
                        crate::test_allocations::allocations_during(|| {
                            retained = Some(state.ivm_execution_budget());
                        }),
                        0,
                        "the original finite pool must be available on a cold thread",
                    );
                    let retained = retained.unwrap();
                    assert!(retained.same_pool(&original));
                    assert_eq!(retained.reserved_bytes(), before);
                    let reservation = retained.try_reserve_bytes(1).unwrap();
                    assert!(reservation.belongs_to(&original));
                    assert_eq!(original.reserved_bytes(), before + 1);
                    drop(reservation);
                    assert_eq!(original.reserved_bytes(), before);
                    assert_eq!(
                        crate::test_allocations::allocations_during(|| drop(retained)),
                        0
                    );
                })
                .join()
                .unwrap();
        });
    });
}
