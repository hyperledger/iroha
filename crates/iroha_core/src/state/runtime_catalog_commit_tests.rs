fn catalog_test_header(state: &State) -> BlockHeader {
    let original = state
        .kura_handle()
        .get_block(
            std::num::NonZeroUsize::new(1).unwrap(),
            &state.ivm_execution_budget(),
        )
        .expect("completed original State read")
        .expect("catalog components retain their actual original signed genesis");
    let time_ms = u64::try_from(original.header().creation_time().as_millis())
        .unwrap()
        .checked_add(1)
        .expect("fixture parent time has a successor");
    BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        Some(original.hash()),
        None,
        time_ms,
        0,
    )
}

fn staged_catalog_fixture(
    state: &State,
    keys: &[iroha_crypto::KeyPair],
) -> (
    iroha_config::parameters::actual::Nexus,
    PendingAutoscaleLaneLifecycle,
) {
    let payload = catalog_payload(state, keys);
    let mut block = state.block(catalog_test_header(state));
    let mut transaction = block.transaction();
    transaction
        .stage_consensus_catalog_transition(&payload)
        .unwrap();
    (
        transaction.nexus.clone(),
        transaction.pending_lane_lifecycle.clone().unwrap(),
    )
}

fn install_fixture_runtime(state: &State, runtime: NexusRuntimeCatalogV1) {
    let mut world = state.world.block();
    world
        .parameters
        .get_mut()
        .set_parameter(iroha_data_model::parameter::Parameter::Custom(
            runtime.into_custom_parameter().unwrap(),
        ));
    world.commit();
}

#[test]
fn runtime_catalog_readback_tracks_committed_state_and_rejects_malformed_parameter() {
    run_catalog_test(|| {
        let (state, keys) = catalog_fixture(InvalidMember::None);
        assert_eq!(state.view().runtime_catalog_hash().unwrap(), None);
        let payload = catalog_payload(&state, &keys);
        let (runtime, retained_runtime) = {
            let mut block = state.block(catalog_test_header(&state));
            let mut transaction = block.transaction();
            transaction
                .stage_consensus_catalog_transition(&payload)
                .unwrap();
            let runtime = runtime_catalog_from_world(&transaction.world)
                .unwrap()
                .unwrap();
            assert_eq!(
                state.view().runtime_catalog_hash().unwrap(),
                None,
                "an uncommitted transaction cannot become public readback"
            );
            (runtime, transaction.canonical_runtime.get().clone())
        };
        assert_eq!(state.view().runtime_catalog_hash().unwrap(), None);
        let first = runtime.canonical_hash().unwrap();
        install_fixture_runtime(&state, runtime.clone());
        // Explicit metadata publication fixture: retain the actual runtime
        // record staged by the accepted transaction alongside its World catalog.
        // This does not claim carrier execution, finality, or State publication.
        let mut owner = state.canonical_runtime.block();
        *owner.get_mut() = retained_runtime;
        owner.commit();
        assert_eq!(state.view().runtime_catalog_hash().unwrap(), Some(first));
        let mut changed = runtime;
        changed.dataspaces[0].descriptor.description = Some("changed committed description".into());
        let second = changed.canonical_hash().unwrap();
        assert_ne!(first, second);
        install_fixture_runtime(&state, changed);
        assert_eq!(state.view().runtime_catalog_hash().unwrap(), Some(second));
        let mut world = state.world.block();
        world
            .parameters
            .get_mut()
            .set_parameter(iroha_data_model::parameter::Parameter::Custom(
                iroha_data_model::parameter::CustomParameter::new(
                    NexusRuntimeCatalogV1::parameter_id(),
                    iroha_primitives::json::Json::new(norito::json!({"version": 255})),
                ),
            ));
        world.commit();
        let malformed_world = norito::json::to_json(&state.world).unwrap();
        let retained_owner = norito::json::to_json(&state.canonical_runtime).unwrap();
        assert!(runtime_catalog_root_from_world(&state.world.view()).is_err());
        assert!(matches!(
            state.try_view(),
            Err(LaneLifecycleError::RuntimeCatalog(_))
        ));
        assert_eq!(
            norito::json::to_json(&state.world).unwrap(),
            malformed_world
        );
        assert_eq!(
            norito::json::to_json(&state.canonical_runtime).unwrap(),
            retained_owner
        );
    });
}

#[test]
fn runtime_catalog_readback_binds_next_transition_and_rejects_stale_root() {
    run_catalog_test(|| {
        let (state, keys) = catalog_fixture(InvalidMember::None);
        let (after, pending) = staged_catalog_fixture(&state, &keys);
        let runtime = pending.runtime_catalog.clone().unwrap();
        install_fixture_runtime(&state, runtime.clone());
        // Restore one complete committed fixture before reading the next transition's inputs.
        *state.nexus.write() = after;
        state
            .install_canonical_runtime_projection(
                &state.nexus.read(),
                &pending.catalog_update.updated_lane_incarnation_lineage,
                &state.autoscale_sample_history_snapshot(),
            )
            .expect("install complete authenticated runtime fixture");
        state.install_lane_manifests_for_testing(&pending.updated_lane_manifests);
        let status = {
            let view = state.view();
            iroha_data_model::nexus::LaneLifecycleStatusV1::new(
                &view.nexus.lane_catalog,
                &view.lane_incarnations,
                view.runtime_catalog_hash().unwrap(),
            )
            .unwrap()
        };
        assert_eq!(
            status.runtime_catalog_hash,
            Some(runtime.canonical_hash().unwrap())
        );
        let mut payload = catalog_payload(&state, &keys);
        payload.expected_catalog_hash = status.catalog_hash;
        payload.expected_incarnation_root = status.incarnation_root;
        payload.expected_runtime_catalog_hash = status.runtime_catalog_hash;
        let manifest_hash = [0x68; 32];
        let dataspace_id = DataSpaceId::from_hash(&manifest_hash);
        payload.dataspace_additions[0].descriptor.id = dataspace_id;
        payload.dataspace_additions[0].descriptor.alias = "second-catalog-ds".into();
        payload.dataspace_additions[0].manifest_hash = manifest_hash;
        payload.lane_additions[0].id = LaneId::new(6);
        payload.lane_additions[0].alias = "second-catalog-lane".into();
        payload.lane_additions[0].dataspace_id = dataspace_id;
        payload.manifest_additions = vec![catalog_manifest(
            LaneId::new(6),
            "second-catalog-lane",
            &keys,
        )];
        for stale in [None, Some(Hash::new(b"stale runtime overlay"))] {
            let mut invalid = payload.clone();
            invalid.expected_runtime_catalog_hash = stale;
            let mut block = state.block(catalog_test_header(&state));
            let mut transaction = block.transaction();
            let error = transaction
                .stage_consensus_catalog_transition(&invalid)
                .expect_err("stale overlay guard must reject a second transition");
            assert!(error.to_string().contains("expected runtime catalog root"));
        }
        let mut block = state.block(catalog_test_header(&state));
        let mut transaction = block.transaction();
        transaction
            .stage_consensus_catalog_transition(&payload)
            .expect("native readback must bind the next additive transition");
        let next = runtime_catalog_from_world(&transaction.world)
            .unwrap()
            .unwrap();
        assert_eq!(next.dataspaces.len(), 2);
        assert_eq!(next.manifests.len(), 2);
        assert_ne!(
            Some(next.canonical_hash().unwrap()),
            status.runtime_catalog_hash
        );
        assert_eq!(
            state.view().runtime_catalog_hash().unwrap(),
            status.runtime_catalog_hash
        );
    });
}

#[test]
fn runtime_catalog_final_overlay_rejects_unstaged_changed_and_removed_parameter() {
    run_catalog_test(|| {
        let (state, keys) = catalog_fixture(InvalidMember::None);
        let payload = catalog_payload(&state, &keys);
        let mut block = state.block(catalog_test_header(&state));
        let mut transaction = block.transaction();
        transaction
            .stage_consensus_catalog_transition(&payload)
            .unwrap();
        let pending = transaction.pending_lane_lifecycle.clone().unwrap();
        validate_runtime_catalog_block_overlay(
            transaction.world.parameters.get_before_block(),
            &transaction.world,
            &state.network_id,
            &state.nexus_snapshot(),
            Some(&pending),
            2,
        )
        .expect("exact accepted catalog and live committee");
        assert!(
            validate_runtime_catalog_block_overlay(
                transaction.world.parameters.get_before_block(),
                &transaction.world,
                &state.network_id,
                &state.nexus_snapshot(),
                None,
                2
            )
            .is_err()
        );
        let mut changed = pending.runtime_catalog.clone().unwrap();
        changed.dataspaces[0].descriptor.description = Some("late catalog change".to_owned());
        transaction.world.parameters.get_mut().set_parameter(
            iroha_data_model::parameter::Parameter::Custom(
                changed.into_custom_parameter().unwrap(),
            ),
        );
        assert!(
            validate_runtime_catalog_block_overlay(
                transaction.world.parameters.get_before_block(),
                &transaction.world,
                &state.network_id,
                &state.nexus_snapshot(),
                Some(&pending),
                2
            )
            .is_err()
        );
        transaction
            .world
            .parameters
            .get_mut()
            .custom
            .remove(&NexusRuntimeCatalogV1::parameter_id());
        assert!(
            validate_runtime_catalog_block_overlay(
                transaction.world.parameters.get_before_block(),
                &transaction.world,
                &state.network_id,
                &state.nexus_snapshot(),
                Some(&pending),
                2
            )
            .is_err()
        );
    });
}

#[test]
fn runtime_catalog_applied_transaction_publishes_manifest_to_next_transaction() {
    run_catalog_test(|| {
        let (state, keys) = catalog_fixture(InvalidMember::None);
        let payload = catalog_payload(&state, &keys);
        let mut block = state.block(catalog_test_header(&state));
        let mut transaction = block.transaction();
        transaction
            .stage_consensus_catalog_transition(&payload)
            .unwrap();
        let expected_manifest_digest = transaction.lane_manifests.consensus_policy_digest();
        assert!(
            transaction
                .lane_privacy_registry
                .lane(LaneId::new(5))
                .is_some()
        );
        transaction.apply();
        assert_eq!(
            block.lane_manifests.consensus_policy_digest(),
            expected_manifest_digest
        );
        assert!(block.lane_manifests.has_manifest(LaneId::new(5)));
        assert!(block.lane_privacy_registry.lane(LaneId::new(5)).is_some());
        let next = block.transaction();
        assert_eq!(
            next.lane_manifests.consensus_policy_digest(),
            expected_manifest_digest
        );
        validate_runtime_catalog_committee(
            &next.world,
            &next.network_id,
            &next.nexus,
            &next.lane_manifests,
            &payload.lane_additions[0],
            3,
        )
        .expect("later transaction sees the accepted manifest and live committee");
        let privacy = next.lane_privacy_registry.lane(LaneId::new(5)).unwrap();
        assert_eq!(
            privacy.dataspace_id(),
            payload.lane_additions[0].dataspace_id
        );
        assert_eq!(privacy.commitments().count(), 1);
        assert!(runtime_catalog_from_world(&next.world).unwrap().is_some());
        drop(next);
        drop(block);
        assert!(
            !state.lane_manifests.read().has_manifest(LaneId::new(5)),
            "dropping the parent block does not publish process runtime state"
        );
        assert!(
            state
                .lane_privacy_registry
                .read()
                .lane(LaneId::new(5))
                .is_none()
        );
        assert!(
            runtime_catalog_from_world(&state.world.view())
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn runtime_catalog_final_overlay_rechecks_late_validator_invalidation() {
    run_catalog_test(|| {
        for case in 0..5 {
            let (state, keys) = catalog_fixture(InvalidMember::None);
            let payload = catalog_payload(&state, &keys);
            let mut block = state.block(catalog_test_header(&state));
            let mut transaction = block.transaction();
            transaction
                .stage_consensus_catalog_transition(&payload)
                .unwrap();
            let pending = transaction.pending_lane_lifecycle.clone().unwrap();
            validate_runtime_catalog_block_overlay(
                transaction.world.parameters.get_before_block(),
                &transaction.world,
                &state.network_id,
                &state.nexus_snapshot(),
                Some(&pending),
                2,
            )
            .unwrap();
            let id = derive_committee_key_id(keys[0].public_key());
            match case {
                0 => {
                    transaction
                        .world
                        .accounts
                        .remove(AccountId::new(keys[0].public_key().clone()));
                }
                1 => {
                    transaction.world.consensus_keys.remove(id);
                }
                _ => {
                    let mut record = transaction.world.consensus_keys.get(&id).unwrap().clone();
                    match case {
                        2 => record.status = ConsensusKeyStatus::Disabled,
                        3 => record.pop.as_mut().unwrap()[0] ^= 1,
                        _ => record.expiry_height = Some(3),
                    }
                    transaction.world.consensus_keys.insert(id, record);
                }
            }
            assert!(
                validate_runtime_catalog_block_overlay(
                    transaction.world.parameters.get_before_block(),
                    &transaction.world,
                    &state.network_id,
                    &state.nexus_snapshot(),
                    Some(&pending),
                    2
                )
                .is_err(),
                "late authority invalidation case {case}"
            );
        }
    });
}

#[test]
fn runtime_catalog_final_overlay_rejects_removal_and_unchanged_malformed_state() {
    run_catalog_test(|| {
        let (state, keys) = catalog_fixture(InvalidMember::None);
        // This validator consumes frozen policy and explicit World versions, not
        // a new public State snapshot after deliberately partial metadata writes.
        let original_nexus = state.nexus_snapshot();
        let (_, pending) = staged_catalog_fixture(&state, &keys);
        install_fixture_runtime(&state, pending.runtime_catalog.unwrap());
        let runtime_before = state.canonical_runtime.view().get().clone();
        let predecessor_before = state.canonical_runtime.predecessor_view().get().clone();
        let world_before = norito::json::to_json(&state.world).unwrap();
        let mut block = state.world.block();
        validate_runtime_catalog_block_overlay(
            block.parameters.get_before_block(),
            &block,
            &state.network_id,
            &original_nexus,
            None,
            3,
        )
        .unwrap();
        block
            .parameters
            .get_mut()
            .custom
            .remove(&NexusRuntimeCatalogV1::parameter_id());
        let removed_parameters = block.parameters.get().clone();
        let original_parameters = block.parameters.get_before_block().clone();
        let error = validate_runtime_catalog_block_overlay(
            block.parameters.get_before_block(),
            &block,
            &state.network_id,
            &original_nexus,
            None,
            3,
        )
        .expect_err("removing a protected catalog requires a staged transition");
        assert!(
            matches!(error, LaneLifecycleError::RuntimeCatalog(ref reason)
                if reason == "protected runtime catalog changed without a staged catalog transition")
        );
        assert_eq!(block.parameters.get(), &removed_parameters);
        assert_eq!(block.parameters.get_before_block(), &original_parameters);
        drop(block);
        assert_eq!(norito::json::to_json(&state.world).unwrap(), world_before);
        let mut world = state.world.block();
        world
            .parameters
            .get_mut()
            .set_parameter(iroha_data_model::parameter::Parameter::Custom(
                iroha_data_model::parameter::CustomParameter::new(
                    NexusRuntimeCatalogV1::parameter_id(),
                    iroha_primitives::json::Json::new(norito::json!({"version": 255})),
                ),
            ));
        world.commit();
        let malformed_world = norito::json::to_json(&state.world).unwrap();
        let accepted = state.world.block();
        let malformed_parameters = accepted.parameters.get().clone();
        assert_eq!(
            accepted.parameters.get_before_block(),
            &malformed_parameters
        );
        let error = validate_runtime_catalog_block_overlay(
            accepted.parameters.get_before_block(),
            &accepted,
            &state.network_id,
            &original_nexus,
            None,
            3,
        )
        .expect_err("an unchanged malformed catalog cannot pass equality validation");
        assert!(
            matches!(error, LaneLifecycleError::RuntimeCatalog(ref reason)
                if reason.contains("Nexus runtime catalog codec"))
        );
        assert_eq!(accepted.parameters.get(), &malformed_parameters);
        assert_eq!(
            accepted.parameters.get_before_block(),
            &malformed_parameters
        );
        drop(accepted);
        assert_eq!(
            norito::json::to_json(&state.world).unwrap(),
            malformed_world
        );
        assert_eq!(state.canonical_runtime.view().get(), &runtime_before);
        assert_eq!(
            state.canonical_runtime.predecessor_view().get(),
            &predecessor_before
        );
    });
}

#[test]
fn runtime_catalog_startup_reconstructs_manifest_without_files_and_preserves_policy() {
    run_catalog_test(|| {
        let (mut state, keys) = catalog_fixture(InvalidMember::None);
        let configured = state.nexus_snapshot();
        let baseline_registry = state.lane_manifests.read().clone();
        let execution_before = state.execution_policy_digest_v1().unwrap();
        let (after, pending) = staged_catalog_fixture(&state, &keys);
        let runtime = pending.runtime_catalog.clone().unwrap();
        install_fixture_runtime(&state, runtime.clone());
        // Model the geometry already restored by an authenticated snapshot. Startup receives the
        // original configured baseline plus that restored lane catalog, never new local DS rows.
        *state.nexus.write() = after.clone();
        state
            .install_canonical_runtime_projection(
                &state.nexus.read(),
                &pending.catalog_update.updated_lane_incarnation_lineage,
                &state.autoscale_sample_history_snapshot(),
            )
            .expect("install complete authenticated runtime fixture");
        state.nexus_runtime_restored_from_snapshot = true;
        let mut startup = configured.clone();
        startup.lane_catalog = after.lane_catalog.clone();
        startup.lane_config = after.lane_config.clone();
        let restored = state.nexus_with_committed_catalog(startup.clone()).unwrap();
        assert_eq!(restored.dataspace_catalog, after.dataspace_catalog);
        assert_eq!(
            restored.configured_dataspace_catalog,
            configured.configured_dataspace_catalog
        );
        let manifests = state
            .lane_manifests_with_committed_catalog(&baseline_registry, &restored)
            .unwrap();
        assert!(manifests.has_manifest(LaneId::new(5)));
        assert!(
            manifests
                .status(LaneId::new(5))
                .unwrap()
                .manifest_path
                .is_none()
        );
        assert_eq!(
            manifests.consensus_policy_digest(),
            pending.updated_lane_manifests.consensus_policy_digest()
        );
        state.install_lane_manifests_for_testing(&manifests);
        assert_eq!(
            state.execution_policy_digest_v1().unwrap(),
            execution_before
        );
        assert_eq!(
            runtime_catalog_root_from_world(&state.world.view()).unwrap(),
            Some(runtime.canonical_hash().unwrap())
        );
        let restored_again = state.nexus_with_committed_catalog(startup).unwrap();
        let manifests_again = state
            .lane_manifests_with_committed_catalog(&baseline_registry, &restored_again)
            .unwrap();
        assert_eq!(restored_again.dataspace_catalog, restored.dataspace_catalog);
        assert_eq!(
            manifests_again.consensus_policy_digest(),
            manifests.consensus_policy_digest()
        );
        let retired = after
            .lane_catalog
            .apply_lifecycle(&iroha_data_model::nexus::LaneLifecyclePlan {
                additions: Vec::new(),
                retire: vec![LaneId::new(5)],
            })
            .unwrap();
        assert!(
            ensure_runtime_catalog_lanes_preserved(
                &state.world.view(),
                &after.lane_catalog,
                &retired
            )
            .is_err()
        );
        let mut drift = restored.clone();
        drift.configured_dataspace_catalog = restored.dataspace_catalog.clone();
        assert!(state.nexus_with_committed_catalog(drift).is_err());
        let mut foreign = runtime;
        foreign.baseline_manifests_hash = Hash::new(b"foreign startup manifest baseline");
        install_fixture_runtime(&state, foreign);
        assert!(
            state
                .lane_manifests_with_committed_catalog(&baseline_registry, &restored)
                .is_err()
        );
        let mut world = state.world.block();
        world
            .parameters
            .get_mut()
            .set_parameter(iroha_data_model::parameter::Parameter::Custom(
                iroha_data_model::parameter::CustomParameter::new(
                    NexusRuntimeCatalogV1::parameter_id(),
                    iroha_primitives::json::Json::new(norito::json!({"version": 255})),
                ),
            ));
        world.commit();
        let malformed_world = norito::json::to_json(&state.world).unwrap();
        let retained_owner = norito::json::to_json(&state.canonical_runtime).unwrap();
        assert!(state.nexus_with_committed_catalog(configured).is_err());
        assert_eq!(
            norito::json::to_json(&state.world).unwrap(),
            malformed_world
        );
        assert_eq!(
            norito::json::to_json(&state.canonical_runtime).unwrap(),
            retained_owner,
            "failed recovery cannot change current runtime or retained undo"
        );
    });
}

#[test]
fn runtime_catalog_replacement_uses_its_retained_parameter_predecessor() {
    run_catalog_test(|| {
        let (state, keys) = catalog_fixture(InvalidMember::None);
        let (after, pending) = staged_catalog_fixture(&state, &keys);
        install_fixture_runtime(&state, pending.runtime_catalog.clone().unwrap());
        // The tip's World catalog and runtime owner are one scoped publication.
        *state.nexus.write() = after;
        state
            .install_canonical_runtime_projection(
                &state.nexus.read(),
                &pending.catalog_update.updated_lane_incarnation_lineage,
                &state.autoscale_sample_history_snapshot(),
            )
            .expect("install the matching runtime owner for the retained catalog");
        state.install_lane_manifests_for_testing(&pending.updated_lane_manifests);
        let live = runtime_catalog_from_world(&state.world.view()).unwrap();
        assert!(live.is_some());
        let mut replacement = state.world.block_and_revert();
        assert!(runtime_catalog_from_world(&replacement).unwrap().is_none());
        let nexus = state.nexus_snapshot();
        validate_runtime_catalog_block_overlay(
            replacement.parameters.get_before_block(),
            &replacement,
            &state.network_id,
            &nexus,
            None,
            2,
        )
        .expect("an untouched replacement retains its actual pre-catalog predecessor");
        replacement.parameters.get_mut().set_parameter(
            iroha_data_model::parameter::Parameter::Custom(
                live.clone().unwrap().into_custom_parameter().unwrap(),
            ),
        );
        assert!(
            validate_runtime_catalog_block_overlay(
                replacement.parameters.get_before_block(),
                &replacement,
                &state.network_id,
                &nexus,
                None,
                2,
            )
            .is_err(),
            "matching the discarded live tip does not authorize an unstaged catalog"
        );
        drop(replacement);
        assert_eq!(
            runtime_catalog_from_world(&state.world.view()).unwrap(),
            live
        );
    });
}

#[test]
fn runtime_catalog_owned_overlay_ignores_later_policy_cache_mutation() {
    run_catalog_test(|| {
        let (state, keys) = catalog_fixture(InvalidMember::None);
        let payload = catalog_payload(&state, &keys);
        let original = state.nexus_snapshot();
        let mut block = state.block(catalog_test_header(&state));
        let mut transaction = block.transaction();
        transaction
            .stage_consensus_catalog_transition(&payload)
            .unwrap();
        transaction.apply();
        block.validate_owned_runtime_catalog_overlay().unwrap();
        state.nexus.write().staking.public_validator_mode =
            iroha_config::parameters::actual::LaneValidatorMode::StakeElected;
        block
            .validate_owned_runtime_catalog_overlay()
            .expect("the captured AdminManaged policy owns this accepted overlay");
        let key_id = derive_committee_key_id(keys[0].public_key());
        block.world.consensus_keys.remove(key_id);
        assert!(
            block.validate_owned_runtime_catalog_overlay().is_err(),
            "captured policy still requires every accepted live key"
        );
        drop(block);
        *state.nexus.write() = original;
        assert!(
            runtime_catalog_from_world(&state.world.view())
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn runtime_catalog_merge_validation_owns_its_captured_policy() {
    run_catalog_test(|| {
        let (state, keys) = catalog_fixture(InvalidMember::None);
        let payload = catalog_payload(&state, &keys);
        let original_nexus = state.nexus_snapshot();
        let original_manifests = Arc::clone(&state.lane_manifests.read());
        let mut block = state.block(catalog_test_header(&state));
        let mut transaction = block.transaction();
        transaction
            .stage_consensus_catalog_transition(&payload)
            .unwrap();
        transaction.apply();
        block.validate_owned_runtime_catalog_overlay().unwrap();

        // These physical caches are no longer this carrier's predecessor.
        state.nexus.write().fees.base_fee = Quantity::from(99_u32);
        *state.lane_manifests.write() = Arc::new(LaneManifestRegistry::empty());
        block
            .validate_owned_runtime_catalog_overlay()
            .expect("captured policy and original journals own the accepted transition");
        block.nexus.fees.base_fee = Quantity::from(99_u32);
        assert!(
            block.validate_owned_runtime_catalog_overlay().is_err(),
            "matching a later physical cache cannot authorize policy substitution"
        );
        block.nexus.fees.base_fee = original_nexus.fees.base_fee.clone();
        block.validate_owned_runtime_catalog_overlay().unwrap();
        block.zk.pipa_r.enabled = !block.zk.pipa_r.enabled;
        assert!(
            block.validate_owned_runtime_catalog_overlay().is_err(),
            "the captured ZK policy still binds the accepted overlay"
        );
        drop(block);
        *state.nexus.write() = original_nexus;
        *state.lane_manifests.write() = original_manifests;
        assert!(
            runtime_catalog_from_world(&state.world.view())
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn runtime_catalog_merge_replacement_uses_actual_world_and_runtime_undo() {
    run_catalog_test(|| {
        let (state, keys) = catalog_fixture(InvalidMember::None);
        let payload = catalog_payload(&state, &keys);
        let (runtime, owner) = {
            let mut block = state.block(catalog_test_header(&state));
            let mut transaction = block.transaction();
            transaction
                .stage_consensus_catalog_transition(&payload)
                .unwrap();
            transaction.apply();
            block.validate_owned_runtime_catalog_overlay().unwrap();
            (
                runtime_catalog_from_world(&block.world).unwrap().unwrap(),
                block.canonical_runtime.get().clone(),
            )
        };
        // Publish only the paired metadata fixture. No execution/finality or
        // complete State publication is claimed by this replacement test.
        install_fixture_runtime(&state, runtime.clone());
        let mut published_runtime = state.canonical_runtime.block();
        *published_runtime.get_mut() = owner;
        published_runtime.commit();
        let before = crate::snapshot::canonical_state_snapshot_hash(&state).unwrap();
        let mut replacement = state.block_and_revert(catalog_test_header(&state));
        assert!(
            runtime_catalog_from_world(&replacement.world)
                .unwrap()
                .is_none()
        );
        assert!(!replacement.lane_manifests.has_manifest(LaneId::new(5)));
        replacement
            .validate_owned_runtime_catalog_overlay()
            .expect("the discarded live catalog is not the replacement's predecessor");
        let mut transaction = replacement.transaction();
        transaction
            .stage_consensus_catalog_transition(&payload)
            .unwrap();
        transaction.apply();
        replacement
            .validate_owned_runtime_catalog_overlay()
            .expect("the same addition is valid against the actual pre-catalog undo");
        replacement
            .pending_autoscale_lifecycle
            .as_mut()
            .unwrap()
            .catalog_update
            .previous_lane_incarnations
            .clear();
        assert!(
            replacement
                .validate_owned_runtime_catalog_overlay()
                .is_err(),
            "the captured policy does not excuse a forged dynamic predecessor"
        );
        drop(replacement);
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_hash(&state).unwrap(),
            before
        );
        assert_eq!(
            runtime_catalog_from_world(&state.world.view()).unwrap(),
            Some(runtime)
        );
    });
}

#[test]
fn runtime_catalog_owned_validation_rejects_staged_journal_substitution() {
    run_catalog_test(|| {
        let (state, keys) = catalog_fixture(InvalidMember::None);
        let before = crate::snapshot::canonical_state_snapshot_hash(&state).unwrap();
        let payload = catalog_payload(&state, &keys);
        let mut block = state.block(catalog_test_header(&state));
        let mut transaction = block.transaction();
        transaction
            .stage_consensus_catalog_transition(&payload)
            .unwrap();
        transaction.apply();
        block.validate_owned_runtime_catalog_overlay().unwrap();
        let original = block.pending_autoscale_lifecycle.clone().unwrap();
        for mutation in [
            "previous incarnations",
            "previous lineage",
            "previous activations",
            "previous catalog",
            "previous dataspaces",
            "previous routing",
            "previous autoscale",
            "updated incarnations",
            "updated lineage",
            "updated activations",
            "updated catalog",
            "updated dataspaces",
            "reset lanes",
            "replaced lanes",
            "transition height",
            "expected incarnation root",
        ] {
            let pending = block.pending_autoscale_lifecycle.as_mut().unwrap();
            match mutation {
                "previous incarnations" => {
                    pending.catalog_update.previous_lane_incarnations.clear()
                }
                "previous lineage" => pending
                    .catalog_update
                    .previous_lane_incarnation_lineage
                    .clear(),
                "previous activations" => pending
                    .catalog_update
                    .previous_lane_incarnation_activation_heights
                    .clear(),
                "previous catalog" => {
                    pending.catalog_update.previous_catalog =
                        original.catalog_update.updated_catalog.clone()
                }
                "previous dataspaces" => {
                    pending.catalog_update.previous_dataspace_catalog =
                        original.catalog_update.updated_dataspace_catalog.clone()
                }
                "previous routing" => {
                    pending.catalog_update.previous_routing_policy.default_lane = LaneId::new(5)
                }
                "previous autoscale" => {
                    pending.catalog_update.previous_autoscale.enabled =
                        !original.catalog_update.previous_autoscale.enabled
                }
                "updated incarnations" => pending.catalog_update.updated_lane_incarnations.clear(),
                "updated lineage" => pending
                    .catalog_update
                    .updated_lane_incarnation_lineage
                    .clear(),
                "updated activations" => pending
                    .catalog_update
                    .updated_lane_incarnation_activation_heights
                    .clear(),
                "updated catalog" => {
                    pending.catalog_update.updated_catalog =
                        original.catalog_update.previous_catalog.clone()
                }
                "updated dataspaces" => {
                    pending.catalog_update.updated_dataspace_catalog =
                        original.catalog_update.previous_dataspace_catalog.clone()
                }
                "reset lanes" => {
                    pending.catalog_update.lanes_to_reset.insert(LaneId::new(0));
                }
                "replaced lanes" => {
                    pending
                        .catalog_update
                        .replaced_lane_ids
                        .insert(LaneId::new(0));
                }
                "transition height" => pending.transition_height += 1,
                "expected incarnation root" => {
                    pending.expected_incarnation_root = Hash::new(b"forged predecessor")
                }
                _ => unreachable!(),
            }
            assert!(
                block.validate_owned_runtime_catalog_overlay().is_err(),
                "retained original journals refuse {mutation} substitution"
            );
            block.pending_autoscale_lifecycle = Some(original.clone());
            block.validate_owned_runtime_catalog_overlay().unwrap();
        }
        drop(block);
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_hash(&state).unwrap(),
            before
        );
    });
}

#[test]
fn runtime_catalog_owned_validation_binds_policy_without_a_staged_transition() {
    run_catalog_test(|| {
        let (state, _) = catalog_fixture(InvalidMember::None);
        let before = crate::snapshot::canonical_state_snapshot_hash(&state).unwrap();
        let mut block = state.block(catalog_test_header(&state));
        assert!(block.pending_autoscale_lifecycle.is_none());
        block.validate_owned_runtime_catalog_overlay().unwrap();
        let original_fee = block.nexus.fees.base_fee.clone();
        block.nexus.fees.base_fee = Quantity::from(99_u32);
        assert!(block.validate_owned_runtime_catalog_overlay().is_err());
        block.nexus.fees.base_fee = original_fee;
        block.validate_owned_runtime_catalog_overlay().unwrap();
        block.zk.pipa_r.enabled = !block.zk.pipa_r.enabled;
        assert!(block.validate_owned_runtime_catalog_overlay().is_err());
        block.zk.pipa_r.enabled = !block.zk.pipa_r.enabled;
        block.validate_owned_runtime_catalog_overlay().unwrap();
        drop(block);
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_hash(&state).unwrap(),
            before
        );
    });
}

fn assert_runtime_catalog_frozen_policy_refuses_refreshed_projection(staged: bool) {
    run_catalog_test(move || {
        let (state, keys) = catalog_fixture(InvalidMember::None);
        let before = crate::snapshot::canonical_state_snapshot_hash(&state).unwrap();
        let payload = catalog_payload(&state, &keys);
        let mut block = state.block(catalog_test_header(&state));
        if staged {
            let mut transaction = block.transaction();
            transaction
                .stage_consensus_catalog_transition(&payload)
                .unwrap();
            transaction.apply();
        }
        assert_eq!(block.pending_autoscale_lifecycle.is_some(), staged);
        block.validate_owned_runtime_catalog_overlay().unwrap();
        let original_routing = block.nexus.routing_policy.clone();
        let original_autoscale = block.nexus.autoscale;
        // Lane one and the unchanged universal dataspace are both retained by
        // this fixture: the forgery is valid routing geometry, not a missing lane.
        assert!(block.nexus.lane_catalog.lanes().iter().any(|lane| {
            lane.id == LaneId::new(1) && lane.dataspace_id == original_routing.default_dataspace
        }));
        assert_ne!(original_routing.default_lane, LaneId::new(1));
        block.nexus.routing_policy.default_lane = LaneId::new(1);
        block.refresh_canonical_runtime();
        block
            .validate_canonical_runtime_projection()
            .expect("forged routing matches its refreshed actual working runtime owner");
        let error = block.validate_owned_runtime_catalog_overlay().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("working policy differs from its captured authority")
        );
        block.nexus.routing_policy = original_routing;
        block.refresh_canonical_runtime();
        block.validate_owned_runtime_catalog_overlay().unwrap();

        // A positive target duration remains well formed, and only its static
        // policy differs. Rebuilding the runtime projection cannot authorize it.
        block.nexus.autoscale.target_block_ms = NonZeroU64::new(
            original_autoscale
                .target_block_ms
                .get()
                .checked_add(1)
                .unwrap(),
        )
        .unwrap();
        block.refresh_canonical_runtime();
        block
            .validate_canonical_runtime_projection()
            .expect("forged autoscale matches its refreshed actual working runtime owner");
        let error = block.validate_owned_runtime_catalog_overlay().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("working policy differs from its captured authority")
        );
        block.nexus.autoscale = original_autoscale;
        block.refresh_canonical_runtime();
        block.validate_owned_runtime_catalog_overlay().unwrap();
        drop(block);
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_hash(&state).unwrap(),
            before
        );
    });
}

#[test]
fn runtime_catalog_owned_validation_binds_refreshed_routing_and_autoscale_without_transition() {
    assert_runtime_catalog_frozen_policy_refuses_refreshed_projection(false);
}

#[test]
fn runtime_catalog_owned_validation_binds_refreshed_routing_and_autoscale_with_transition() {
    assert_runtime_catalog_frozen_policy_refuses_refreshed_projection(true);
}

fn assert_runtime_catalog_serialized_autoscale_policy_refuses_refreshed_owner(staged: bool) {
    run_catalog_test(move || {
        let (state, keys) = catalog_fixture(InvalidMember::None);
        let before = crate::snapshot::canonical_state_snapshot_hash(&state).unwrap();
        let payload = catalog_payload(&state, &keys);
        let mut block = state.block(catalog_test_header(&state));
        if staged {
            let mut transaction = block.transaction();
            transaction
                .stage_consensus_catalog_transition(&payload)
                .unwrap();
            transaction.apply();
        }
        assert_eq!(block.pending_autoscale_lifecycle.is_some(), staged);
        block.validate_owned_runtime_catalog_overlay().unwrap();
        let original = block.canonical_runtime.get().clone();
        let enabled = block.nexus.autoscale.enabled;
        block.nexus.autoscale.enabled = !enabled;
        block.refresh_canonical_runtime();
        assert_ne!(block.canonical_runtime.get(), &original);
        assert_eq!(
            block.canonical_runtime.get().owner_policy.autoscale_enabled,
            !enabled
        );
        block
            .validate_canonical_runtime_projection()
            .expect("the forged serialized policy matches its refreshed actual MV owner");
        let error = block.validate_owned_runtime_catalog_overlay().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("working policy differs from its captured authority")
        );
        block.nexus.autoscale.enabled = enabled;
        block.refresh_canonical_runtime();
        assert_eq!(block.canonical_runtime.get(), &original);
        block.validate_owned_runtime_catalog_overlay().unwrap();
        drop(block);
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_hash(&state).unwrap(),
            before
        );
    });
}

#[test]
fn runtime_catalog_owned_validation_binds_changed_serialized_autoscale_with_and_without_transition()
{
    assert_runtime_catalog_serialized_autoscale_policy_refuses_refreshed_owner(false);
    assert_runtime_catalog_serialized_autoscale_policy_refuses_refreshed_owner(true);
}

#[test]
fn runtime_catalog_owned_validation_retains_unstaged_geometry_while_samples_advance() {
    run_catalog_test(|| {
        let (state, _) = catalog_fixture(InvalidMember::None);
        let before = crate::snapshot::canonical_state_snapshot_hash(&state).unwrap();
        let mut block = state.block(catalog_test_header(&state));
        assert!(block.pending_autoscale_lifecycle.is_none());
        block.validate_owned_runtime_catalog_overlay().unwrap();
        let old_runtime = block.canonical_runtime.get().clone();
        // Exercise the same bounded append primitive as ordinary sample staging.
        // This is a metadata component scope, not carrier/finality publication.
        let fields = block.fields.as_mut().expect("original executing fixture");
        append_autoscale_sample_record(
            &mut fields.autoscale_sample_history,
            AutoscaleSampleRecord {
                block_height: fields._curr_block.height().get(),
                block_hash: fields._curr_block.hash(),
                creation_time_ms: fields._curr_block.creation_time_ms,
                work_count: 0,
            },
            autoscale_sample_history_cap(&fields.nexus.autoscale),
        );
        block.autoscale_sample_history_dirty = true;
        block.autoscale_evaluated_committed_fragment_count = Some(0);
        block.refresh_canonical_runtime();
        assert_ne!(block.canonical_runtime.get(), &old_runtime);
        block.validate_canonical_runtime_projection().unwrap();
        block
            .validate_owned_runtime_catalog_overlay()
            .expect("advancing samples do not replace their original geometry owner");
        let original_nexus = block.nexus.clone();
        let original_incarnations = block.lane_incarnations.clone();
        let original_activation = block.lane_incarnation_activation_heights.clone();
        let original_lineage = block.lane_incarnation_lineage.clone();
        let sampled_runtime = block.canonical_runtime.get().clone();
        let lane = LaneId::new(1);
        for mutation in [
            "effective alias",
            "incarnation",
            "activation",
            "lineage generation",
            "transition cursor",
        ] {
            match mutation {
                "effective alias" => {
                    let mut lanes = block.nexus.lane_catalog.lanes().to_vec();
                    let entry = lanes.iter_mut().find(|entry| entry.id == lane).unwrap();
                    entry.alias = "forged-unstaged-existing-lane".to_owned();
                    block.nexus.lane_catalog =
                        LaneCatalog::new(block.nexus.lane_catalog.lane_count(), lanes).unwrap();
                    block.nexus.lane_config =
                        iroha_config::parameters::actual::LaneConfig::from_catalog(
                            &block.nexus.lane_catalog,
                        );
                }
                "incarnation" => {
                    let forged = Hash::new(b"forged unstaged lane incarnation");
                    assert_ne!(original_incarnations[&lane], forged);
                    block.lane_incarnations.insert(lane, forged);
                    block
                        .lane_incarnation_lineage
                        .get_mut(&lane)
                        .unwrap()
                        .incarnation = forged;
                }
                "activation" => {
                    let height = original_activation[&lane].checked_add(1).unwrap();
                    block
                        .lane_incarnation_activation_heights
                        .insert(lane, height);
                    block
                        .lane_incarnation_lineage
                        .get_mut(&lane)
                        .unwrap()
                        .activation_height = height;
                }
                "lineage generation" => {
                    let lineage = block.lane_incarnation_lineage.get_mut(&lane).unwrap();
                    lineage.generation = lineage.generation.checked_add(1).unwrap();
                }
                "transition cursor" => {
                    block.nexus.autoscale.last_transition_height = original_nexus
                        .autoscale
                        .last_transition_height
                        .checked_add(1)
                        .unwrap();
                }
                _ => unreachable!(),
            }
            block.refresh_canonical_runtime();
            assert_ne!(block.canonical_runtime.get(), &sampled_runtime);
            block
                .validate_canonical_runtime_projection()
                .expect("forged fields are structurally valid and self-consistent");
            let error = block.validate_owned_runtime_catalog_overlay().unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("unstaged runtime geometry differs from its retained original owner"),
                "{mutation}: {error}"
            );
            block.nexus = original_nexus.clone();
            block.lane_incarnations = original_incarnations.clone();
            block.lane_incarnation_activation_heights = original_activation.clone();
            block.lane_incarnation_lineage = original_lineage.clone();
            block.refresh_canonical_runtime();
            assert_eq!(block.canonical_runtime.get(), &sampled_runtime);
            block.validate_owned_runtime_catalog_overlay().unwrap();
        }
        drop(block);
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_hash(&state).unwrap(),
            before
        );
    });
}
