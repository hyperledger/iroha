#[test]
fn reconcile_once_prunes_cache_buckets_by_authoritative_sequence_and_refreshes_snapshot()
-> Result<()> {
    let mut state = test_state()?;
    let mut active_bundle = load_deployment_bundle_fixture()?;
    let mut canary_bundle = active_bundle.clone();
    canary_bundle.service.service_version = "2026.03.0".to_string();
    canary_bundle.container.bundle_path = "/bundles/web_portal_canary.to".to_string();
    let active_bundle_bytes = simple_soracloud_contract_artifact(&["entry_active"]);
    let canary_bundle_bytes = simple_soracloud_contract_artifact(&["entry_canary"]);
    active_bundle.container.bundle_hash = Hash::new(&active_bundle_bytes);
    active_bundle.service.container.manifest_hash = active_bundle.container_manifest_hash();
    canary_bundle.container.bundle_hash = Hash::new(&canary_bundle_bytes);
    canary_bundle.service.container.manifest_hash = canary_bundle.container_manifest_hash();
    let active_asset_bytes = b"active-asset".to_vec();
    let canary_asset_bytes = b"canary-asset".to_vec();
    active_bundle.service.artifacts[0].artifact_hash = Hash::new(&active_asset_bytes);
    active_bundle.service.artifacts[0].artifact_path = "/public/active.html".to_string();
    canary_bundle.service.artifacts[0].artifact_hash = Hash::new(&canary_asset_bytes);
    canary_bundle.service.artifacts[0].artifact_path = "/public/canary.html".to_string();
    let mut deployment = sample_deployment_state(&canary_bundle);
    deployment.revision_count = 2;
    deployment.active_rollout = Some(SoraServiceRolloutStateV1 {
        schema_version: SORA_SERVICE_ROLLOUT_STATE_VERSION_V1,
        rollout_handle: "rollout-2026-03".to_string(),
        baseline_version: active_bundle.service.service_version.clone(),
        candidate_version: canary_bundle.service.service_version.clone(),
        canary_percent: 20,
        traffic_percent: 20,
        stage: SoraRolloutStageV1::Canary,
        health_failures: 0,
        max_health_failures: 3,
        health_window_secs: 60,
        created_sequence: 17,
        updated_sequence: 29,
    });
    deployment.last_rollout = deployment.active_rollout.clone();
    let runtime = sample_runtime_state(&active_bundle);
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &active_bundle);
        insert_service_revision_fixture(world, &canary_bundle);
        insert_service_deployment_fixture(world, &active_bundle, deployment);
        insert_service_runtime_fixture(world, &active_bundle, runtime);
    }
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let artifacts_root = temp_dir.path().join("artifacts");
    fs::create_dir_all(&artifacts_root)?;
    fs::write(
        artifacts_root.join(hash_cache_name(active_bundle.container.bundle_hash)),
        &active_bundle_bytes,
    )?;
    fs::write(
        artifacts_root.join(hash_cache_name(canary_bundle.container.bundle_hash)),
        &canary_bundle_bytes,
    )?;
    fs::write(
        artifacts_root.join(hash_cache_name(
            active_bundle.service.artifacts[0].artifact_hash,
        )),
        &active_asset_bytes,
    )?;
    fs::write(
        artifacts_root.join(hash_cache_name(
            canary_bundle.service.artifacts[0].artifact_hash,
        )),
        &canary_asset_bytes,
    )?;
    let mut config = test_runtime_manager_config(temp_dir.path().to_path_buf());
    config.cache_budgets.bundle_bytes = std::num::NonZeroU64::new(
        u64::try_from(active_bundle_bytes.len().max(canary_bundle_bytes.len()))
            .expect("bundle size fits in u64"),
    )
    .expect("nonzero bundle budget");
    config.cache_budgets.static_asset_bytes = std::num::NonZeroU64::new(
        u64::try_from(active_asset_bytes.len().max(canary_asset_bytes.len()))
            .expect("asset size fits in u64"),
    )
    .expect("nonzero asset budget");
    {
        let view = state.view();
        let registry = collect_service_revision_registry(&view);
        let build = |registry: &BTreeMap<(String, String), SoraDeploymentBundleV1>| {
            build_runtime_snapshot(
                &view,
                registry,
                &config.state_dir,
                artifacts_root.clone(),
                &config.cache_budgets,
                None,
                None,
                false,
            )
        };
        let snapshot = build(&registry)?;
        assert_eq!(snapshot.services["web_portal"].len(), 2);
        assert!(
            snapshot.services["web_portal"]
                .values()
                .all(|plan| plan.lease_volumes.is_empty())
        );
        let current_key = (
            "web_portal".to_owned(),
            canary_bundle.service.service_version.clone(),
        );
        let mut missing_current = registry.clone();
        missing_current.remove(&current_key);
        assert_report_contains(
            build(&missing_current).expect_err("missing current authority"),
            "missing current admitted revision",
        );
        let mut substituted_current = registry.clone();
        substituted_current
            .get_mut(&current_key)
            .unwrap()
            .service
            .artifacts[0]
            .artifact_hash = Hash::new(b"substituted-current-artifact");
        assert_report_contains(
            build(&substituted_current).expect_err("current manifest binding"),
            "current_service_manifest_hash",
        );
        let mut aliased_baseline = registry.clone();
        aliased_baseline.insert(
            (
                "web_portal".to_owned(),
                active_bundle.service.service_version.clone(),
            ),
            canary_bundle.clone(),
        );
        assert_report_contains(
            build(&aliased_baseline).expect_err("valid bundle under another revision key"),
            "registry key does not match admitted revision identity",
        );
        let mut invalid_baseline = registry.clone();
        invalid_baseline
            .get_mut(&(
                "web_portal".to_owned(),
                active_bundle.service.service_version.clone(),
            ))
            .unwrap()
            .service
            .container
            .manifest_hash = Hash::new(b"substituted-baseline-container");
        assert_report_contains(
            build(&invalid_baseline).expect_err("baseline admission binding"),
            "service.container.manifest_hash",
        );
    }
    let manager = SoracloudRuntimeManager::new(config, Arc::clone(&state));
    manager.reconcile_once()?;
    let snapshot = manager.snapshot.read().clone();
    let active_plan = snapshot
        .services
        .get("web_portal")
        .and_then(|versions| versions.get("2026.02.0"))
        .expect("active service plan present");
    let canary_plan = snapshot
        .services
        .get("web_portal")
        .and_then(|versions| versions.get("2026.03.0"))
        .expect("canary service plan present");
    let active_asset_plan = active_plan
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == SoraArtifactKindV1::StaticAsset)
        .expect("active static asset plan");
    let canary_asset_plan = canary_plan
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == SoraArtifactKindV1::StaticAsset)
        .expect("canary static asset plan");
    assert!(!active_plan.bundle_available_locally);
    assert!(canary_plan.bundle_available_locally);
    assert!(!active_asset_plan.available_locally);
    assert!(canary_asset_plan.available_locally);
    assert!(
        !artifacts_root
            .join(hash_cache_name(active_bundle.container.bundle_hash))
            .exists()
    );
    assert!(
        artifacts_root
            .join(hash_cache_name(canary_bundle.container.bundle_hash))
            .exists()
    );
    assert!(
        !artifacts_root
            .join(hash_cache_name(
                active_bundle.service.artifacts[0].artifact_hash
            ))
            .exists()
    );
    assert!(
        artifacts_root
            .join(hash_cache_name(
                canary_bundle.service.artifacts[0].artifact_hash
            ))
            .exists()
    );
    Ok(())
}
#[test]
fn reconcile_once_prunes_tied_cache_candidates_by_stable_key() -> Result<()> {
    let state = test_state()?;
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let journals_root = temp_dir.path().join("journals");
    fs::create_dir_all(&journals_root)?;
    let first_hash = Hash::new(b"journal-alpha");
    let second_hash = Hash::new(b"journal-omega");
    let payload = b"journal-entry".to_vec();
    let first_name = hash_cache_name(first_hash);
    let second_name = hash_cache_name(second_hash);
    let first_path = journals_root.join(&first_name);
    let second_path = journals_root.join(&second_name);
    fs::write(&first_path, &payload)?;
    fs::write(&second_path, &payload)?;
    let mut config = test_runtime_manager_config(temp_dir.path().to_path_buf());
    config.cache_budgets.journal_bytes =
        std::num::NonZeroU64::new(u64::try_from(payload.len()).expect("payload size fits"))
            .expect("nonzero journal budget");
    let manager = SoracloudRuntimeManager::new(config, Arc::clone(&state));
    manager.reconcile_once()?;
    let (removed, retained) = if first_name <= second_name {
        (first_path, second_path)
    } else {
        (second_path, first_path)
    };
    assert!(!removed.exists());
    assert!(retained.exists());
    Ok(())
}
#[test]
fn reconcile_once_hydrates_missing_artifacts_from_committed_sorafs_store() -> Result<()> {
    let mut state = test_state()?;
    let mut bundle = load_deployment_bundle_fixture()?;
    let bundle_bytes = simple_soracloud_contract_artifact(&["update", "ciphertext_update"]);
    let artifact_payloads =
        assign_fixture_artifact_hashes(&mut bundle, &bundle_bytes, "hydrated-from-sorafs");
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, sample_deployment_state(&bundle));
        insert_service_runtime_fixture(world, &bundle, sample_runtime_state(&bundle));
    }
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let sorafs_node = test_sorafs_node(&temp_dir);
    let mut committed_manifests = vec![ingest_sorafs_payload(&sorafs_node, &bundle_bytes)?];
    for payload in &artifact_payloads {
        committed_manifests.push(ingest_sorafs_payload(&sorafs_node, payload)?);
    }
    approve_sorafs_manifests(&state, &sorafs_node, &committed_manifests)?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    )
    .with_sorafs_node(sorafs_node);
    manager.reconcile_once()?;
    let snapshot = manager.snapshot.read().clone();
    let plan = snapshot
        .services
        .get("web_portal")
        .and_then(|versions| versions.get("2026.02.0"))
        .expect("hydrated service plan");
    assert!(plan.bundle_available_locally);
    assert_eq!(plan.health_status, SoraServiceHealthStatusV1::Healthy);
    assert!(
        plan.artifacts
            .iter()
            .all(|artifact| artifact.available_locally)
    );
    assert_eq!(
        fs::read(
            temp_dir
                .path()
                .join("artifacts")
                .join(hash_cache_name(bundle.container.bundle_hash))
        )?,
        bundle_bytes
    );
    for (artifact, payload) in bundle.service.artifacts.iter().zip(artifact_payloads) {
        assert_eq!(
            fs::read(
                temp_dir
                    .path()
                    .join("artifacts")
                    .join(hash_cache_name(artifact.artifact_hash))
            )?,
            payload
        );
    }
    Ok(())
}
#[test]
fn generic_ivm_hydration_preserves_committed_remote_sorafs_fallback() -> Result<()> {
    let mut state = test_state()?;
    let mut bundle = load_deployment_bundle_fixture()?;
    bundle.service.artifacts.truncate(1);
    let bundle_bytes = simple_soracloud_contract_artifact(&["update"]);
    let artifact_payloads =
        assign_fixture_artifact_hashes(&mut bundle, &bundle_bytes, "remote-provider");
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, sample_deployment_state(&bundle));
        insert_service_runtime_fixture(world, &bundle, sample_runtime_state(&bundle));
    }
    let provider_id = [0x11; 32];
    let remote_payloads = std::iter::once(bundle_bytes.clone())
        .chain(artifact_payloads.iter().cloned())
        .collect::<Vec<_>>();
    let remote_fixtures = remote_payloads
        .iter()
        .enumerate()
        .map(|(index, payload)| {
            build_remote_manifest_fixture(
                payload,
                provider_id,
                u8::try_from(index + 1).expect("fixture index fits in u8"),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    approve_remote_hydration_sources(&state, &remote_fixtures)?;
    let server = spawn_remote_hydration_fixture(&remote_fixtures)?;
    let provider_cache = test_provider_cache(&server.base_url, provider_id)?;
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let config = test_runtime_manager_config(temp_dir.path().to_path_buf());
    let manager = SoracloudRuntimeManager::new(config.clone(), Arc::clone(&state))
        .with_test_remote_stream_token_operator(*state.network_id_ref())
        .with_sorafs_provider_cache(provider_cache);
    let initial_snapshot = {
        let view = state.view();
        let bundle_registry = collect_service_revision_registry(&view);
        build_runtime_snapshot(
            &view,
            &bundle_registry,
            &config.state_dir,
            config.state_dir.join("artifacts"),
            &config.cache_budgets,
            None,
            None,
            false,
        )?
    };
    {
        let view = state.view();
        manager.hydrate_missing_artifacts(&view, &initial_snapshot)?;
    }
    let snapshot = {
        let view = state.view();
        let bundle_registry = collect_service_revision_registry(&view);
        build_runtime_snapshot(
            &view,
            &bundle_registry,
            &config.state_dir,
            config.state_dir.join("artifacts"),
            &config.cache_budgets,
            None,
            None,
            false,
        )?
    };
    let plan = snapshot
        .services
        .get("web_portal")
        .and_then(|versions| versions.get("2026.02.0"))
        .expect("hydrated service plan");
    assert_eq!(plan.runtime, SoraContainerRuntimeV1::Ivm);
    assert!(plan.bundle_available_locally);
    assert_eq!(plan.health_status, SoraServiceHealthStatusV1::Healthy);
    assert!(
        plan.artifacts
            .iter()
            .all(|artifact| artifact.available_locally)
    );
    assert_eq!(
        fs::read(
            temp_dir
                .path()
                .join("artifacts")
                .join(hash_cache_name(bundle.container.bundle_hash))
        )?,
        bundle_bytes
    );
    for (artifact, payload) in bundle.service.artifacts.iter().zip(artifact_payloads) {
        assert_eq!(
            fs::read(
                temp_dir
                    .path()
                    .join("artifacts")
                    .join(hash_cache_name(artifact.artifact_hash))
            )?,
            payload
        );
    }
    Ok(())
}
#[test]
fn locally_assigned_inrou_hydration_rejects_remote_only_and_shared_cache_fallback() -> Result<()> {
    let mut state = test_state()?;
    let mut bundle = sample_inrou_test_bundle()?;
    bundle.service.artifacts.clear();
    let bundle_bytes = b"assigned-inrou-bundle-must-be-operator-preseeded".to_vec();
    bundle.container.bundle_hash = Hash::new(&bundle_bytes);
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    bundle.validate_for_admission()?;
    let deployment_state = sample_deployment_state(&bundle);
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, deployment_state);
    }
    let local_peer_id = canonical_inrou_test_peer_id();
    let selected_guest_isa =
        current_host_inrou_guest_isa().expect("tests require a supported Inrou host ISA");
    insert_local_inrou_service_placement_fixture(
        &mut state,
        &bundle,
        local_peer_id,
        selected_guest_isa,
    );
    insert_local_inrou_host_capability_fixture(
        &mut state,
        &bundle,
        local_peer_id,
        selected_guest_isa,
    );
    push_committed_test_block_hash(&mut state, 1)?;

    let provider_id = [0x59; 32];
    let remote_fixture = build_remote_manifest_fixture(&bundle_bytes, provider_id, 1)?;
    approve_remote_hydration_sources(&state, std::slice::from_ref(&remote_fixture))?;
    let server = spawn_remote_hydration_fixture(std::slice::from_ref(&remote_fixture))?;
    let provider_cache = test_provider_cache(&server.base_url, provider_id)?;
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let config = test_runtime_manager_config(temp_dir.path().to_path_buf())
        .with_local_host_identity(ALICE_ID.clone(), local_peer_id);
    let snapshot = {
        let view = state.view();
        let bundle_registry = collect_service_revision_registry(&view);
        build_runtime_snapshot(
            &view,
            &bundle_registry,
            &config.state_dir,
            config.state_dir.join("artifacts"),
            &config.cache_budgets,
            config.local_validator_account_id.as_ref(),
            config.local_peer_id.as_deref(),
            true,
        )?
    };
    let plan = snapshot
        .services
        .get(bundle.service.service_name.as_ref())
        .and_then(|versions| versions.get(&bundle.service.service_version))
        .expect("locally assigned Inrou plan");
    assert_eq!(plan.runtime, SoraContainerRuntimeV1::Inrou);
    assert_eq!(plan.local_replica_slots, vec![1]);
    let manager = SoracloudRuntimeManager::new(config, Arc::clone(&state))
        .with_test_remote_stream_token_operator(*state.network_id_ref())
        .with_sorafs_provider_cache(provider_cache);

    let error = {
        let view = state.view();
        manager
            .hydrate_missing_artifacts(&view, &snapshot)
            .expect_err("a remote provider must not satisfy an assigned Inrou artifact")
    };
    assert_report_contains(error, "remote hydration fallback is forbidden");
    let cache_path = temp_dir
        .path()
        .join("artifacts")
        .join(hash_cache_name(bundle.container.bundle_hash));
    assert!(!cache_path.exists());

    fs::create_dir_all(cache_path.parent().expect("cache path parent"))?;
    fs::write(&cache_path, &bundle_bytes)?;
    let error = {
        let view = state.view();
        manager
            .hydrate_missing_artifacts(&view, &snapshot)
            .expect_err("an unqualified shared cache hit must not satisfy assigned Inrou")
    };
    assert_report_contains(error, "remote hydration fallback is forbidden");
    assert_eq!(fs::read(cache_path)?, bundle_bytes);
    Ok(())
}
#[test]
fn reconcile_once_skips_remote_sorafs_payloads_that_do_not_match_expected_hash() -> Result<()> {
    let mut state = test_state()?;
    let mut bundle = load_deployment_bundle_fixture()?;
    bundle.service.artifacts.clear();
    let bundle_bytes = simple_soracloud_contract_artifact(&["update"]);
    bundle.container.bundle_hash = Hash::new(&bundle_bytes);
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, sample_deployment_state(&bundle));
        insert_service_runtime_fixture(world, &bundle, sample_runtime_state(&bundle));
    }
    let provider_id = [0x11; 32];
    let remote_fixture = build_remote_manifest_fixture(b"wrong-remote-bundle", provider_id, 1)?;
    approve_remote_hydration_sources(&state, std::slice::from_ref(&remote_fixture))?;
    let server = spawn_remote_hydration_fixture(std::slice::from_ref(&remote_fixture))?;
    let provider_cache = test_provider_cache(&server.base_url, provider_id)?;
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    )
    .with_test_remote_stream_token_operator(*state.network_id_ref())
    .with_sorafs_provider_cache(provider_cache);
    manager.reconcile_once()?;
    let snapshot = manager.snapshot.read().clone();
    let plan = snapshot
        .services
        .get("web_portal")
        .and_then(|versions| versions.get("2026.02.0"))
        .expect("service plan");
    assert!(!plan.bundle_available_locally);
    assert_eq!(plan.health_status, SoraServiceHealthStatusV1::Hydrating);
    assert!(
        !temp_dir
            .path()
            .join("artifacts")
            .join(hash_cache_name(bundle.container.bundle_hash))
            .exists()
    );
    Ok(())
}
#[test]
fn reconcile_once_requires_completed_ingest_for_hash_matched_local_artifacts() -> Result<()> {
    let mut state = test_state()?;
    let mut bundle = load_deployment_bundle_fixture()?;
    let bundle_bytes = simple_soracloud_contract_artifact(&["update"]);
    let artifact_payloads =
        assign_fixture_artifact_hashes(&mut bundle, &bundle_bytes, "uncommitted-sorafs");
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, sample_deployment_state(&bundle));
        insert_service_runtime_fixture(world, &bundle, sample_runtime_state(&bundle));
    }
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let sorafs_node = test_sorafs_node(&temp_dir);
    let mut committed_manifests = vec![ingest_sorafs_payload(&sorafs_node, &bundle_bytes)?];
    for payload in &artifact_payloads {
        committed_manifests.push(ingest_sorafs_payload(&sorafs_node, payload)?);
    }
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    )
    .with_sorafs_node(sorafs_node.clone());
    manager.reconcile_once()?;
    {
        let snapshot = manager.snapshot.read();
        let plan = &snapshot.services["web_portal"]["2026.02.0"];
        assert!(!plan.bundle_available_locally);
        assert!(
            plan.artifacts
                .iter()
                .all(|artifact| !artifact.available_locally)
        );
        assert!(
            !temp_dir
                .path()
                .join("artifacts")
                .join(hash_cache_name(bundle.container.bundle_hash))
                .exists()
        );
    }
    // Hash-matched local bytes become eligible only after the committed
    // pin and exact completed ingest authority have both been installed.
    approve_sorafs_manifests(&state, &sorafs_node, &committed_manifests)?;
    manager.reconcile_once()?;
    let snapshot = manager.snapshot.read().clone();
    let plan = snapshot
        .services
        .get("web_portal")
        .and_then(|versions| versions.get("2026.02.0"))
        .expect("service plan");
    assert!(plan.bundle_available_locally);
    assert_eq!(plan.health_status, SoraServiceHealthStatusV1::Healthy);
    assert!(
        plan.artifacts
            .iter()
            .all(|artifact| artifact.available_locally)
    );
    assert_eq!(
        fs::read(
            temp_dir
                .path()
                .join("artifacts")
                .join(hash_cache_name(bundle.container.bundle_hash))
        )?,
        bundle_bytes
    );
    for (artifact, payload) in bundle.service.artifacts.iter().zip(artifact_payloads) {
        assert_eq!(
            fs::read(
                temp_dir
                    .path()
                    .join("artifacts")
                    .join(hash_cache_name(artifact.artifact_hash))
            )?,
            payload
        );
    }
    Ok(())
}
#[test]
fn restore_persisted_snapshot_rehydrates_missing_artifacts_from_committed_sorafs_store()
-> Result<()> {
    let mut state = test_state()?;
    let mut bundle = load_deployment_bundle_fixture()?;
    let bundle_bytes = simple_soracloud_contract_artifact(&["update", "ciphertext_update"]);
    let artifact_payloads =
        assign_fixture_artifact_hashes(&mut bundle, &bundle_bytes, "restart-rehydrate");
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, sample_deployment_state(&bundle));
        insert_service_runtime_fixture(world, &bundle, sample_runtime_state(&bundle));
    }
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let sorafs_node = test_sorafs_node(&temp_dir);
    let mut committed_manifests = vec![ingest_sorafs_payload(&sorafs_node, &bundle_bytes)?];
    for payload in &artifact_payloads {
        committed_manifests.push(ingest_sorafs_payload(&sorafs_node, payload)?);
    }
    approve_sorafs_manifests(&state, &sorafs_node, &committed_manifests)?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    )
    .with_sorafs_node(sorafs_node.clone());
    manager.reconcile_once()?;
    let bundle_cache_path = temp_dir
        .path()
        .join("artifacts")
        .join(hash_cache_name(bundle.container.bundle_hash));
    let artifact_cache_paths = bundle
        .service
        .artifacts
        .iter()
        .map(|artifact| {
            temp_dir
                .path()
                .join("artifacts")
                .join(hash_cache_name(artifact.artifact_hash))
        })
        .collect::<Vec<_>>();
    fs::remove_file(&bundle_cache_path)?;
    for path in &artifact_cache_paths {
        fs::remove_file(path)?;
    }
    let restarted_manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    )
    .with_sorafs_node(sorafs_node);
    assert!(restarted_manager.restore_persisted_snapshot()?);
    restarted_manager.reconcile_once()?;
    let snapshot = restarted_manager.snapshot.read().clone();
    let plan = snapshot
        .services
        .get("web_portal")
        .and_then(|versions| versions.get("2026.02.0"))
        .expect("restarted service plan");
    assert!(plan.bundle_available_locally);
    assert!(
        plan.artifacts
            .iter()
            .all(|artifact| artifact.available_locally)
    );
    assert_eq!(fs::read(bundle_cache_path)?, bundle_bytes);
    for (path, payload) in artifact_cache_paths.iter().zip(artifact_payloads) {
        assert_eq!(fs::read(path)?, payload);
    }
    Ok(())
}
#[test]
fn startup_rejects_invalid_persisted_snapshot_before_returning_handle() -> Result<()> {
    let state = test_state()?;
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    fs::write(
        temp_dir.path().join("runtime_snapshot.json"),
        b"{not-valid-json",
    )?;
    let mut config = test_runtime_manager_config(temp_dir.path().to_path_buf());
    config.production_mode = false;
    config.inrou.enabled = false;
    config.inrou.portable_vm_uid = None;
    config.inrou.portable_vm_gid = None;
    config.inrou.trusted_guest_artifact = None;
    let manager = SoracloudRuntimeManager::new(config, state);
    let result = manager.start(ShutdownSignal::new());
    let Err(error) = result else {
        panic!("invalid persisted state must not yield a runtime handle");
    };
    assert!(
        error
            .to_string()
            .contains("restore persisted Soracloud runtime-manager snapshot"),
        "unexpected startup error: {error:?}"
    );
    Ok(())
}
#[test]
fn read_json_optional_treats_only_a_missing_file_as_absent() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let path = temp_dir.path().join("runtime_snapshot.json");
    let absent = read_json_optional::<SoracloudRuntimeSnapshot>(
        &path,
        SORACLOUD_RUNTIME_SNAPSHOT_MAX_BYTES,
        "test Soracloud runtime snapshot",
    )?;
    assert!(absent.is_none());

    fs::write(&path, b"")?;
    let error = read_json_optional::<SoracloudRuntimeSnapshot>(
        &path,
        SORACLOUD_RUNTIME_SNAPSHOT_MAX_BYTES,
        "test Soracloud runtime snapshot",
    )
    .expect_err("an existing empty state file must fail closed");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(
        error.to_string().contains("is empty"),
        "unexpected error: {error:?}"
    );
    Ok(())
}
#[test]
fn restore_persisted_snapshot_rejects_non_v1_schema() -> Result<()> {
    let state = test_state()?;
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let mut persisted = SoracloudRuntimeSnapshot::default();
    persisted.schema_version = SORACLOUD_RUNTIME_SNAPSHOT_VERSION_V1 + 1;
    write_json_atomic_bounded(
        &temp_dir.path().join("runtime_snapshot.json"),
        &persisted,
        SORACLOUD_RUNTIME_SNAPSHOT_MAX_BYTES,
        "test Soracloud runtime snapshot",
    )?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        state,
    );

    let error = manager
        .restore_persisted_snapshot()
        .expect_err("a non-V1 runtime snapshot must fail closed");
    assert!(
        error
            .to_string()
            .contains("unsupported Soracloud runtime snapshot schema version"),
        "unexpected error: {error:?}"
    );
    assert_eq!(
        manager.snapshot.read().clone(),
        SoracloudRuntimeSnapshot::default(),
        "a rejected snapshot must not replace the in-memory state"
    );
    Ok(())
}
#[test]
fn hosted_http_runtime_state_rejects_non_v1_schema() {
    let runtime_state = SoracloudHostedHttpRuntimeStateV1 {
        schema_version: SORACLOUD_HOSTED_HTTP_RUNTIME_STATE_VERSION_V1 + 1,
        service_name: "service".to_owned(),
        service_version: "1.0.0".to_owned(),
        process_generation: 1,
        health_status: SoraServiceHealthStatusV1::Degraded,
        listen_base_url: None,
        pid: None,
        accounted_egress_bytes: 0,
        replicas: Vec::new(),
        last_error: None,
        updated_at_ms: 1,
    };

    let error = validate_hosted_http_runtime_state_bounds(&runtime_state)
        .expect_err("a non-V1 hosted HTTP runtime state must fail closed");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(
        error
            .to_string()
            .contains("unsupported Soracloud hosted HTTP runtime state schema version")
    );
}
#[test]
fn production_startup_rejects_missing_or_unqualified_mutation_sink() -> Result<()> {
    let state = test_state()?;
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let mut config = test_runtime_manager_config(temp_dir.path().to_path_buf());
    config.production_mode = true;
    config.inrou.enabled = false;
    config.inrou.portable_vm_uid = None;
    config.inrou.portable_vm_gid = None;
    config.inrou.trusted_guest_artifact = None;
    let manager = SoracloudRuntimeManager::new(config.clone(), Arc::clone(&state));
    let Err(error) = manager.start(ShutdownSignal::new()) else {
        panic!("production startup without a sink must fail");
    };
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("requires a qualified mutation sink"),
        "unexpected startup error: {rendered}"
    );
    let manager = SoracloudRuntimeManager::new(config, state)
        .with_mutation_sink(Arc::new(RecordingRuntimeMutationSink::default()));
    let Err(error) = manager.start(ShutdownSignal::new()) else {
        panic!("production startup with a recording sink must fail");
    };
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("not backed by a qualified production signer"),
        "unexpected startup error: {rendered}"
    );
    Ok(())
}
#[test]
fn restore_persisted_snapshot_preserves_last_snapshot_if_reconcile_fails() -> Result<()> {
    let mut state = test_state()?;
    let bundle = load_deployment_bundle_fixture()?;
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_deployment_fixture(world, &bundle, sample_deployment_state(&bundle));
    }
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let expected_snapshot = SoracloudRuntimeSnapshot {
        schema_version: SoracloudRuntimeSnapshot::default().schema_version,
        observed_height: 77,
        observed_block_hash: Some(Hash::prehashed([0x55; Hash::LENGTH]).to_string()),
        local_peer_id: None,
        services: BTreeMap::from([(
            "restored_service".to_string(),
            BTreeMap::from([(
                "2026.03.0".to_string(),
                SoracloudRuntimeServicePlan {
                    service_name: "restored_service".to_string(),
                    service_version: "2026.03.0".to_string(),
                    role: SoracloudRuntimeRevisionRole::Active,
                    traffic_percent: 100,
                    runtime: SoraContainerRuntimeV1::Ivm,
                    execution_plane:
                        iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::DeterministicService,
                    bundle_hash: Hash::prehashed([0x33; Hash::LENGTH]).to_string(),
                    bundle_path: "sorafs://restored.bundle".to_string(),
                    entrypoint: "main".to_string(),
                    inrou: None,
                    bundle_cache_path: temp_dir
                        .path()
                        .join("artifacts/restored_bundle")
                        .display()
                        .to_string(),
                    bundle_available_locally: true,
                    process_generation: Some(9),
                    desired_replica_count: 1,
                    local_replica_slots: Vec::new(),
                    local_replicas: Vec::new(),
                    health_status: SoraServiceHealthStatusV1::Healthy,
                    load_factor_bps: 250,
                    authoritative_pending_mailbox_messages: 2,
                    rollout_handle: None,
                    config_generation: 0,
                    secret_generation: 0,
                    quota_class: None,
                    service_lease_status: None,
                    lease_expires_height: None,
                    remaining_runtime_balance: None,
                    config_entry_count: 0,
                    secret_entry_count: 0,
                    config_exports: Vec::new(),
                    supports_host_read_config: true,
                    supports_host_read_secret_envelope: true,
                    materialization_dir: temp_dir
                        .path()
                        .join("services/restored_service/2026.03.0")
                        .display()
                        .to_string(),
                    config_materialization_dir: temp_dir
                        .path()
                        .join("services/restored_service/2026.03.0/configs")
                        .display()
                        .to_string(),
                    effective_env: BTreeMap::new(),
                    effective_env_materialization_path: temp_dir
                        .path()
                        .join("services/restored_service/2026.03.0/effective_env.json")
                        .display()
                        .to_string(),
                    config_exports_materialization_dir: temp_dir
                        .path()
                        .join("services/restored_service/2026.03.0/config_exports")
                        .display()
                        .to_string(),
                    secret_envelopes_materialization_dir: temp_dir
                        .path()
                        .join("services/restored_service/2026.03.0/secret_envelopes")
                        .display()
                        .to_string(),
                    lease_volumes: Vec::new(),
                    mailboxes: Vec::new(),
                    artifacts: Vec::new(),
                },
            )]),
        )]),
        apartments: BTreeMap::new(),
    };
    write_json_atomic(
        temp_dir.path().join("runtime_snapshot.json").as_path(),
        &expected_snapshot,
    )?;
    let manager = Arc::new(SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    ));
    let error = manager
        .initialize_for_startup()
        .expect_err("startup must fail without the admitted revision bundle");
    let error_detail = format!("{error:#}");
    assert!(
        error_detail.contains("references missing current admitted revision"),
        "unexpected reconcile error: {error:?}"
    );
    assert_eq!(manager.snapshot.read().clone(), expected_snapshot);
    Ok(())
}
#[test]
fn execute_local_read_serves_hydrated_asset_with_committed_binding() -> Result<()> {
    let mut state = test_state()?;
    let mut bundle = load_deployment_bundle_fixture()?;
    let bundle_bytes = b"ivm bundle bytes".to_vec();
    let asset_bytes = b"<html><body>portal</body></html>".to_vec();
    bundle.container.bundle_hash = Hash::new(&bundle_bytes);
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    bundle.service.artifacts[0].artifact_hash = Hash::new(&asset_bytes);
    let deployment = sample_deployment_state(&bundle);
    let runtime = sample_runtime_state(&bundle);
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let artifacts_root = temp_dir.path().join("artifacts");
    fs::create_dir_all(&artifacts_root)?;
    fs::write(
        artifacts_root.join(hash_cache_name(bundle.container.bundle_hash)),
        &bundle_bytes,
    )?;
    fs::write(
        artifacts_root.join(hash_cache_name(bundle.service.artifacts[0].artifact_hash)),
        &asset_bytes,
    )?;
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, deployment);
        insert_service_runtime_fixture(world, &bundle, runtime);
    }
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    );
    manager.reconcile_once()?;
    let handle = test_runtime_handle(&manager, Arc::clone(&state));
    let response = handle
        .execute_local_read(SoracloudLocalReadRequest {
            observed_height: 0,
            observed_block_hash: None,
            service_name: bundle.service.service_name.to_string(),
            service_version: bundle.service.service_version.clone(),
            handler_name: "assets".to_owned(),
            handler_class: iroha_core::soracloud_runtime::SoracloudLocalReadKind::Asset,
            request_method: "GET".to_owned(),
            request_path: "/app/assets".to_owned(),
            handler_path: "/".to_owned(),
            request_query: None,
            request_headers: BTreeMap::new(),
            request_body: Vec::new(),
            request_commitment: Hash::new(b"asset-request"),
        })
        .map_err(|error| eyre::eyre!("{error:?}"))?;
    assert_eq!(response.response_bytes, asset_bytes);
    assert_eq!(
        response.content_type.as_deref(),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        response.certified_by,
        SoraCertifiedResponsePolicyV1::StateCommitment
    );
    assert!(response.runtime_receipt.is_none());
    assert_eq!(response.bindings.len(), 1);
    assert_eq!(
        response.bindings[0].artifact_hash,
        Some(bundle.service.artifacts[0].artifact_hash)
    );
    Ok(())
}
#[test]
fn execute_local_read_rejects_internal_service_route() -> Result<()> {
    let mut state = test_state()?;
    let mut bundle = load_deployment_bundle_fixture()?;
    let bundle_bytes = b"ivm bundle bytes".to_vec();
    let asset_bytes = b"<html><body>portal</body></html>".to_vec();
    bundle.container.bundle_hash = Hash::new(&bundle_bytes);
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    bundle.service.artifacts[0].artifact_hash = Hash::new(&asset_bytes);
    bundle
        .service
        .route
        .as_mut()
        .expect("fixture route")
        .visibility = iroha_data_model::soracloud::SoraRouteVisibilityV1::Internal;
    let deployment = sample_deployment_state(&bundle);
    let runtime = sample_runtime_state(&bundle);
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let artifacts_root = temp_dir.path().join("artifacts");
    fs::create_dir_all(&artifacts_root)?;
    fs::write(
        artifacts_root.join(hash_cache_name(bundle.container.bundle_hash)),
        &bundle_bytes,
    )?;
    fs::write(
        artifacts_root.join(hash_cache_name(bundle.service.artifacts[0].artifact_hash)),
        &asset_bytes,
    )?;
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, deployment);
        insert_service_runtime_fixture(world, &bundle, runtime);
    }
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    );
    manager.reconcile_once()?;
    let handle = test_runtime_handle(&manager, Arc::clone(&state));
    let error = handle
        .execute_local_read(SoracloudLocalReadRequest {
            observed_height: 0,
            observed_block_hash: None,
            service_name: bundle.service.service_name.to_string(),
            service_version: bundle.service.service_version.clone(),
            handler_name: "assets".to_owned(),
            handler_class: iroha_core::soracloud_runtime::SoracloudLocalReadKind::Asset,
            request_method: "GET".to_owned(),
            request_path: "/app/assets".to_owned(),
            handler_path: "/".to_owned(),
            request_query: None,
            request_headers: BTreeMap::new(),
            request_body: Vec::new(),
            request_commitment: Hash::new(b"asset-request"),
        })
        .expect_err("internal routes must not execute through public local-read");
    assert_eq!(
        error.kind,
        SoracloudRuntimeExecutionErrorKind::InvalidRequest
    );
    assert!(error.message.contains("local-read route is not public"));
    Ok(())
}
#[test]
fn execute_local_read_runs_query_handler_from_admitted_ivm_bundle() -> Result<()> {
    let mut state = test_state()?;
    let mut bundle = load_deployment_bundle_fixture()?;
    let query_entrypoint = bundle_handler(&bundle, "query").entrypoint;
    let query_json = Json::from_norito_value_ref(&norito::json!({ "ok": true }))?;
    let query_body = make_pointer_tlv(PointerType::Json, &norito::to_bytes(&query_json)?);
    let bundle_bytes = soracloud_query_echo_artifact(query_entrypoint.as_str(), false);
    bundle.container.bundle_hash = Hash::new(&bundle_bytes);
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    let deployment = sample_deployment_state(&bundle);
    let runtime = sample_runtime_state(&bundle);
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let artifacts_root = temp_dir.path().join("artifacts");
    fs::create_dir_all(&artifacts_root)?;
    fs::write(
        artifacts_root.join(hash_cache_name(bundle.container.bundle_hash)),
        &bundle_bytes,
    )?;
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, deployment);
        insert_service_runtime_fixture(world, &bundle, runtime);
        world
            .soracloud_service_state_entries_mut_for_testing()
            .insert(
                (
                    bundle.service.service_name.to_string(),
                    "session_store".to_owned(),
                    "/state/session/alice".to_owned(),
                ),
                SoraServiceStateEntryV1 {
                    schema_version:
                        iroha_data_model::soracloud::SORA_SERVICE_STATE_ENTRY_VERSION_V1,
                    service_name: bundle.service.service_name.clone(),
                    service_version: bundle.service.service_version.clone(),
                    binding_name: "session_store".parse().expect("valid binding"),
                    state_key: "/state/session/alice".to_owned(),
                    encryption:
                        iroha_data_model::soracloud::SoraStateEncryptionV1::ClientCiphertext,
                    payload: b"alice-session".to_vec(),
                    payload_bytes: std::num::NonZeroU64::new(13).expect("nonzero"),
                    payload_commitment: Hash::new(b"alice-session"),
                    fhe_public_key_digest: None,
                    fhe_residual_multiple_bound: None,
                    fhe_bound_mode: None,
                    last_update_sequence: 4,
                    governance_tx_hash: Hash::new(b"gov-session"),
                    source_action: SoraServiceLifecycleActionV1::StateMutation,
                },
            );
    }
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    );
    manager.reconcile_once()?;
    let handle = test_runtime_handle(&manager, Arc::clone(&state));
    let request = SoracloudLocalReadRequest {
        observed_height: 0,
        observed_block_hash: None,
        service_name: bundle.service.service_name.to_string(),
        service_version: bundle.service.service_version.clone(),
        handler_name: "query".to_owned(),
        handler_class: iroha_core::soracloud_runtime::SoracloudLocalReadKind::Query,
        request_method: "GET".to_owned(),
        request_path: "/app/query".to_owned(),
        handler_path: "/".to_owned(),
        request_query: None,
        request_headers: BTreeMap::new(),
        request_body: query_body,
        request_commitment: Hash::new(b"query-request"),
    };
    let response = handle
        .execute_local_read(request.clone())
        .map_err(|error| eyre::eyre!("{error:?}"))?;
    assert_eq!(response.response_bytes, br#"{"ok":true}"#);
    assert_eq!(response.content_type.as_deref(), Some("application/json"));
    assert_eq!(
        response.certified_by,
        SoraCertifiedResponsePolicyV1::AuditReceipt
    );
    assert!(response.runtime_receipt.is_some());
    assert!(response.bindings.is_empty());
    let cold = handle.ivm_runtime_cache_stats();
    assert_eq!(cold.artifact_reads, 1);
    assert_eq!(cold.artifact_hashes, 1);
    assert_eq!(cold.contract_preparations, 1);
    assert_eq!(cold.runtime_allocations, 1);
    assert_eq!(cold.prepared_loads, 1);
    assert_eq!(cold.template_builds, 1);
    assert_eq!(cold.runtime_reuses, 0);
    assert_eq!(cold.idle_runtimes, 1);
    let warm_response = handle
        .execute_local_read(request)
        .map_err(|error| eyre::eyre!("{error:?}"))?;
    assert_eq!(warm_response.response_bytes, response.response_bytes);
    let warm = handle.ivm_runtime_cache_stats();
    assert_eq!(warm.artifact_reads, cold.artifact_reads);
    assert_eq!(warm.artifact_hashes, cold.artifact_hashes);
    assert_eq!(warm.contract_preparations, cold.contract_preparations);
    assert_eq!(warm.runtime_allocations, cold.runtime_allocations);
    assert_eq!(warm.prepared_loads, cold.prepared_loads);
    assert_eq!(warm.template_builds, cold.template_builds);
    assert_eq!(warm.runtime_reuses, 1);
    assert_eq!(warm.dirty_resets, 2);
    assert_eq!(warm.runtime_returns, 2);
    assert_eq!(warm.idle_runtimes, 1);
    Ok(())
}
#[test]
fn execute_local_read_passes_query_metadata_in_canonical_argument_table() -> Result<()> {
    let mut state = test_state()?;
    let mut bundle = load_deployment_bundle_fixture()?;
    let query_entrypoint = bundle_handler(&bundle, "query").entrypoint;
    let bundle_bytes = soracloud_query_echo_artifact(query_entrypoint.as_str(), true);
    bundle.container.bundle_hash = Hash::new(&bundle_bytes);
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    let deployment = sample_deployment_state(&bundle);
    let runtime = sample_runtime_state(&bundle);
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let artifacts_root = temp_dir.path().join("artifacts");
    fs::create_dir_all(&artifacts_root)?;
    fs::write(
        artifacts_root.join(hash_cache_name(bundle.container.bundle_hash)),
        &bundle_bytes,
    )?;
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, deployment);
        insert_service_runtime_fixture(world, &bundle, runtime);
    }
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    );
    manager.reconcile_once()?;
    let handle = test_runtime_handle(&manager, Arc::clone(&state));
    let response = handle
        .execute_local_read(SoracloudLocalReadRequest {
            observed_height: 0,
            observed_block_hash: None,
            service_name: bundle.service.service_name.to_string(),
            service_version: bundle.service.service_version.clone(),
            handler_name: "query".to_owned(),
            handler_class: iroha_core::soracloud_runtime::SoracloudLocalReadKind::Query,
            request_method: "POST".to_owned(),
            request_path: "/app/query/profile".to_owned(),
            handler_path: "/profile".to_owned(),
            request_query: Some("verbose=1".to_owned()),
            request_headers: BTreeMap::from([("accept".to_owned(), "application/json".to_owned())]),
            request_body: br#"{"hello":"world"}"#.to_vec(),
            request_commitment: Hash::new(b"query-request-argument-table"),
        })
        .map_err(|error| eyre::eyre!("{error:?}"))?;
    assert_eq!(response.content_type.as_deref(), Some("application/json"));
    let decoded: norito::json::Value = norito::json::from_slice(&response.response_bytes)?;
    assert_eq!(
        decoded
            .get("request_path")
            .and_then(norito::json::Value::as_str),
        Some("/app/query/profile")
    );
    assert_eq!(
        decoded
            .get("handler_path")
            .and_then(norito::json::Value::as_str),
        Some("/profile")
    );
    assert_eq!(
        decoded
            .get("request_query")
            .and_then(norito::json::Value::as_str),
        Some("verbose=1")
    );
    assert_eq!(
        decoded
            .get("request_body_is_tlv")
            .and_then(norito::json::Value::as_bool),
        Some(false)
    );
    Ok(())
}
#[test]
fn execute_ordered_mailbox_requires_matching_authoritative_runtime_state() -> Result<()> {
    let state = test_state()?;
    let bundle = load_deployment_bundle_fixture()?;
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    );
    let handle = test_runtime_handle(&manager, state);
    let request = sample_ordered_mailbox_request(
        &bundle,
        "update",
        sample_mailbox_message(&bundle, "update", b"authoritative-state".to_vec()),
    );

    let mut missing = request.clone();
    missing.runtime_state = None;
    let error = handle
        .execute_ordered_mailbox(missing)
        .expect_err("missing authoritative runtime state must fail closed");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    assert!(error.message.contains("no authoritative runtime state"));

    let mut mismatched = request;
    mismatched
        .runtime_state
        .as_mut()
        .expect("fixture runtime state")
        .materialized_bundle_hash = Hash::new(b"substituted-bundle");
    let error = handle
        .execute_ordered_mailbox(mismatched)
        .expect_err("substituted authoritative runtime state must fail closed");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Internal);
    assert!(error.message.contains("materialized_bundle_hash"));
    Ok(())
}
#[test]
fn execute_ordered_mailbox_runs_update_handler_from_admitted_ivm_bundle() -> Result<()> {
    let state = test_state()?;
    let mut bundle = load_deployment_bundle_fixture()?;
    let artifact_bytes = soracloud_update_artifact(&["apply_update", "apply_ciphertext_update"]);
    bundle.container.bundle_hash = Hash::new(&artifact_bytes);
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let artifacts_root = temp_dir.path().join("artifacts");
    fs::create_dir_all(&artifacts_root)?;
    fs::write(
        artifacts_root.join(hash_cache_name(bundle.container.bundle_hash)),
        &artifact_bytes,
    )?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    );
    let handle = test_runtime_handle(&manager, Arc::clone(&state));
    let request = sample_ordered_mailbox_request(
        &bundle,
        "update",
        sample_mailbox_message(&bundle, "update", b"hello-update".to_vec()),
    );
    let result = handle
        .execute_ordered_mailbox(request.clone())
        .map_err(|error| eyre::eyre!("{error:?}"))?;
    assert!(result.state_mutations.is_empty());
    assert!(result.outbound_mailbox_messages.is_empty());
    let runtime_state = result.runtime_state.expect("runtime state");
    assert_eq!(
        runtime_state.health_status,
        SoraServiceHealthStatusV1::Healthy
    );
    assert_eq!(
        result.runtime_receipt.handler_class,
        SoraServiceHandlerClassV1::Update
    );
    assert_eq!(
        result.runtime_receipt.request_commitment,
        request.mailbox_message.payload_commitment
    );
    assert_eq!(
        result.runtime_receipt.mailbox_message_id,
        Some(request.mailbox_message.message_id)
    );
    assert_ne!(
        result.runtime_receipt.result_commitment,
        Hash::prehashed([0; Hash::LENGTH])
    );
    let cold = handle.ivm_runtime_cache_stats();
    assert_eq!(cold.artifact_reads, 1);
    assert_eq!(cold.artifact_hashes, 1);
    assert_eq!(cold.contract_preparations, 1);
    assert_eq!(cold.runtime_allocations, 1);
    assert_eq!(cold.prepared_loads, 1);
    assert_eq!(cold.template_builds, 1);
    assert_eq!(cold.runtime_reuses, 0);
    assert_eq!(cold.idle_runtimes, 1);
    let warm = handle
        .execute_ordered_mailbox(request)
        .map_err(|error| eyre::eyre!("{error:?}"))?;
    assert_eq!(
        warm.runtime_state
            .expect("warm runtime state")
            .health_status,
        SoraServiceHealthStatusV1::Healthy
    );
    let warm_stats = handle.ivm_runtime_cache_stats();
    assert_eq!(warm_stats.artifact_reads, cold.artifact_reads);
    assert_eq!(warm_stats.artifact_hashes, cold.artifact_hashes);
    assert_eq!(warm_stats.contract_preparations, cold.contract_preparations);
    assert_eq!(warm_stats.runtime_allocations, cold.runtime_allocations);
    assert_eq!(warm_stats.prepared_loads, cold.prepared_loads);
    assert_eq!(warm_stats.template_builds, cold.template_builds);
    assert_eq!(warm_stats.runtime_reuses, 1);
    assert_eq!(warm_stats.dirty_resets, 2);
    assert_eq!(warm_stats.runtime_returns, 2);
    assert_eq!(warm_stats.idle_runtimes, 1);
    Ok(())
}
#[test]
fn failed_ordered_mailbox_execution_returns_the_warmed_runtime() -> Result<()> {
    let state = test_state()?;
    let mut bundle = load_deployment_bundle_fixture()?;
    let mut body = vec![
        // Admission succeeds before the deterministic guest trap.
        ivm::encoding::wide::encode_rr(ivm::instruction::wide::arithmetic::DIVU, 3, 0, 0),
    ];
    body.extend(soracloud_unit_return_words());
    let artifact_bytes = soracloud_contract_artifact_with_functions(vec![(
        soracloud_entrypoint("apply_update", 0),
        body,
    )]);
    bundle.container.bundle_hash = Hash::new(&artifact_bytes);
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let artifacts_root = temp_dir.path().join("artifacts");
    fs::create_dir_all(&artifacts_root)?;
    fs::write(
        artifacts_root.join(hash_cache_name(bundle.container.bundle_hash)),
        &artifact_bytes,
    )?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    );
    let handle = test_runtime_handle(&manager, Arc::clone(&state));
    let payload = vec![0xA5; 16];
    let request = sample_ordered_mailbox_request(
        &bundle,
        "update",
        sample_mailbox_message(&bundle, "update", payload),
    );
    for expected_reuses in [0, 1] {
        let result = handle
            .execute_ordered_mailbox(request.clone())
            .map_err(|error| eyre::eyre!("{error:?}"))?;
        assert_eq!(
            result
                .runtime_state
                .expect("failure runtime state")
                .health_status,
            SoraServiceHealthStatusV1::Degraded
        );
        let stats = handle.ivm_runtime_cache_stats();
        assert_eq!(stats.runtime_allocations, 1);
        assert_eq!(stats.prepared_loads, 1);
        assert_eq!(stats.runtime_reuses, expected_reuses);
        assert_eq!(stats.idle_runtimes, 1);
    }
    let stats = handle.ivm_runtime_cache_stats();
    assert_eq!(stats.artifact_reads, 1);
    assert_eq!(stats.artifact_hashes, 1);
    assert_eq!(stats.contract_preparations, 1);
    assert_eq!(stats.dirty_resets, 2);
    assert_eq!(stats.runtime_returns, 2);
    Ok(())
}
#[test]
fn ivm_host_public_runtime_reads_authoritative_service_config_entry() -> Result<()> {
    let mut bundle = load_deployment_bundle_fixture()?;
    bundle.container.capabilities.network = SoraNetworkPolicyV1::Allowlist(Vec::new());
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let value_json = Json::from(norito::json!({
        "featureFlag": true,
        "theme": "dawn"
    }));
    let expected_payload = value_json.get().as_bytes().to_vec();
    let mut public_request = sample_ordered_mailbox_request(
        &bundle,
        "update",
        sample_mailbox_message(&bundle, "update", b"public".to_vec()),
    );
    public_request.deployment.service_configs.insert(
        "ui/settings".to_string(),
        SoraServiceConfigEntryV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_CONFIG_ENTRY_VERSION_V1,
            config_name: "ui/settings".to_string(),
            value_hash: Hash::new(&expected_payload),
            value_json,
            last_update_sequence: 22,
        },
    );
    let public_host = SoracloudIvmHost::new(
        public_request,
        temp_dir.path().to_path_buf(),
        BTreeMap::new(),
    );
    let response = public_host.read_service_config("ui/settings")?;
    assert!(response.found);
    assert_eq!(response.payload_bytes, expected_payload);
    Ok(())
}
#[test]
fn local_read_public_inputs_use_only_canonical_names_and_encode_trigger_event_json() {
    let body_tlv = make_pointer_tlv(PointerType::Blob, br#"{"hello":"world"}"#);
    let metadata_value = norito::json::Value::Object(norito::json::Map::from([
        (
            "request_path".to_owned(),
            norito::json::Value::from("/api/auth/me"),
        ),
        (
            "request_method".to_owned(),
            norito::json::Value::from("GET"),
        ),
    ]));
    let metadata_json = Json::from_norito_value_ref(&metadata_value).expect("metadata JSON value");
    let metadata_bytes = norito::to_bytes(&metadata_json).expect("metadata norito bytes");
    let metadata_tlv = make_pointer_tlv(PointerType::Json, &metadata_bytes);
    let inputs = local_read_public_inputs(&body_tlv, &metadata_tlv, 42).expect("public inputs");
    let actual_names = inputs
        .keys()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_names,
        [
            "_request_body",
            "_request_meta",
            "observed_height",
            "trigger_event_json",
        ]
        .map(str::to_owned)
        .into_iter()
        .collect()
    );
    for retired_alias in [
        "event",
        "entrypoint_payload",
        "request_body",
        "body",
        "payload",
        "arg0",
        "param0",
        "request_meta",
        "metadata",
        "meta",
        "arg1",
        "param1",
        "height",
        "arg2",
        "param2",
    ] {
        assert!(
            !inputs.contains_key(&public_input_name(retired_alias).expect("retired alias name")),
            "retired public-input alias `{retired_alias}` must be rejected"
        );
    }
    let trigger_event_tlv = inputs
        .get(&public_input_name("trigger_event_json").expect("input name"))
        .expect("trigger event public input");
    let trigger_event_tlv =
        ivm::pointer_abi::validate_tlv_bytes(trigger_event_tlv).expect("valid JSON TLV");
    assert_eq!(trigger_event_tlv.type_id, PointerType::Json);
    let trigger_json: Json =
        norito::decode_from_bytes(trigger_event_tlv.payload).expect("JSON wrapper");
    let trigger_value: norito::json::Value = trigger_json
        .try_into_any_norito()
        .expect("trigger event JSON value");
    assert_eq!(
        trigger_value
            .get("_request_body")
            .and_then(norito::json::Value::as_str),
        Some("7b2268656c6c6f223a22776f726c64227d")
    );
    assert_eq!(
        trigger_value
            .get("_request_meta")
            .and_then(|metadata| metadata.get("request_path"))
            .and_then(norito::json::Value::as_str),
        Some("/api/auth/me")
    );
    assert_eq!(
        trigger_value
            .get("observed_height")
            .and_then(norito::json::Value::as_u64),
        Some(42)
    );
}
#[test]
fn ordered_mailbox_public_inputs_use_only_canonical_names() {
    let payload_tlv = make_pointer_tlv(PointerType::Blob, b"ordered-payload");
    let inputs = ordered_mailbox_public_inputs(&payload_tlv, 7, 42).expect("public inputs");
    let actual_names = inputs
        .keys()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_names,
        [
            "_request_body",
            "observed_sequence",
            "observed_height",
            "trigger_event_json",
        ]
        .map(str::to_owned)
        .into_iter()
        .collect()
    );
    for retired_alias in [
        "event",
        "entrypoint_payload",
        "request_body",
        "body",
        "payload",
        "arg0",
        "param0",
        "execution_sequence",
        "sequence",
        "arg1",
        "param1",
        "height",
        "arg2",
        "param2",
    ] {
        assert!(
            !inputs.contains_key(&public_input_name(retired_alias).expect("retired alias name")),
            "retired public-input alias `{retired_alias}` must be rejected"
        );
    }
}
#[test]
fn soracloud_json_pointer_abi_rejects_unframed_json_payloads() {
    let raw_json = br#"{"hello":"world"}"#;
    let input_tlv = make_pointer_tlv(PointerType::Json, raw_json);
    assert!(matches!(
        json_value_from_tlv(&input_tlv),
        Err(VMError::DecodeError)
    ));
    assert!(matches!(
        json_pointer_response_payload(raw_json),
        Err(VMError::DecodeError)
    ));
    assert!(
        soracloud_echo_vm(&input_tlv, EntrypointValueKindV1::Json).is_err(),
        "a Json call leaf must reject unframed bytes before guest execution or result publication"
    );
}
#[test]
fn ivm_host_public_runtime_reads_authoritative_service_secret_envelope() -> Result<()> {
    let mut bundle = load_deployment_bundle_fixture()?;
    bundle.container.capabilities.network = SoraNetworkPolicyV1::Allowlist(Vec::new());
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let envelope = SecretEnvelopeV1 {
        schema_version: SECRET_ENVELOPE_VERSION_V1,
        encryption: SecretEnvelopeEncryptionV1::ClientCiphertext,
        key_id: "kms/runtime/test".to_string(),
        key_version: std::num::NonZeroU32::new(1).expect("non-zero"),
        nonce: vec![1, 2, 3, 4],
        ciphertext: b"enveloped-secret".to_vec(),
        commitment: Hash::new(b"enveloped-secret"),
        aad_digest: None,
    };
    let mut public_request = sample_ordered_mailbox_request(
        &bundle,
        "update",
        sample_mailbox_message(&bundle, "update", b"public".to_vec()),
    );
    public_request.deployment.service_secrets.insert(
        "db/password".to_string(),
        SoraServiceSecretEntryV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_SECRET_ENTRY_VERSION_V1,
            secret_name: "db/password".to_string(),
            envelope: envelope.clone(),
            last_update_sequence: 23,
        },
    );
    let public_host = SoracloudIvmHost::new(
        public_request,
        temp_dir.path().to_path_buf(),
        BTreeMap::new(),
    );
    let response = public_host.read_service_secret_envelope("db/password");
    assert_eq!(response.envelope, Some(envelope));
    Ok(())
}
#[test]
fn ivm_host_query_runtime_tracks_committed_state_read_bindings() -> Result<()> {
    let bundle = load_deployment_bundle_fixture()?;
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let query_request = sample_ordered_mailbox_request(
        &bundle,
        "query",
        sample_mailbox_message(&bundle, "query", b"public-query".to_vec()),
    );
    let entry = SoraServiceStateEntryV1 {
        schema_version: iroha_data_model::soracloud::SORA_SERVICE_STATE_ENTRY_VERSION_V1,
        service_name: bundle.service.service_name.clone(),
        service_version: bundle.service.service_version.clone(),
        binding_name: "session_store".parse().expect("valid binding"),
        state_key: "/state/session/alice".to_owned(),
        encryption: iroha_data_model::soracloud::SoraStateEncryptionV1::ClientCiphertext,
        payload: b"alice-session".to_vec(),
        payload_bytes: std::num::NonZeroU64::new(13).expect("non-zero"),
        payload_commitment: Hash::new(b"alice-session"),
        fhe_public_key_digest: None,
        fhe_residual_multiple_bound: None,
        fhe_bound_mode: None,
        last_update_sequence: 4,
        governance_tx_hash: Hash::new(b"gov-session"),
        source_action: SoraServiceLifecycleActionV1::StateMutation,
    };
    let mut committed_entries = BTreeMap::new();
    committed_entries.insert(
        (
            "session_store".to_owned(),
            "/state/session/alice".to_owned(),
        ),
        entry.clone(),
    );
    let mut host = SoracloudIvmHost::new(
        query_request,
        temp_dir.path().to_path_buf(),
        committed_entries,
    );
    let request_envelope = SoracloudHostRequestEnvelopeV1 {
        schema_version: iroha_data_model::soracloud::SORACLOUD_HOST_REQUEST_VERSION_V1,
        operation: SoracloudHostOperationV1::ReadCommittedState,
        payload: SoracloudHostRequestPayloadV1::ReadCommittedState(
            iroha_data_model::soracloud::SoracloudReadCommittedStateRequestV1 {
                binding_name: "session_store".parse().expect("valid binding"),
                state_key: "/state/session/alice".to_owned(),
            },
        ),
    };
    let request_payload = norito::to_bytes(&request_envelope)?;
    let request_tlv = make_pointer_tlv(PointerType::SoracloudRequest, &request_payload);
    let mut vm = IVM::new(u64::MAX);
    let request_ptr = vm.alloc_input_tlv(&request_tlv)?;
    vm.set_register(10, request_ptr);
    let quoted = host.prepare_syscall(SYSCALL_SORACLOUD_READ_COMMITTED_STATE, &vm)?;
    assert!(
        host.local_read_bindings().is_empty(),
        "syscall preparation must not record a committed-state observation"
    );
    assert_eq!(host.metering_query_count(), 0);
    assert_eq!(host.metering_allocation_count(), 0);
    let actual = host.syscall(SYSCALL_SORACLOUD_READ_COMMITTED_STATE, &mut vm)?;
    assert!(quoted >= actual);
    let bindings = host.local_read_bindings();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0], state_entry_binding(&entry));
    assert_eq!(host.metering_query_count(), 1);
    assert_eq!(host.metering_allocation_count(), 1);
    Ok(())
}
#[test]
fn ivm_host_out_of_gas_does_not_query_or_allocate_public_input() -> Result<()> {
    let bundle = load_deployment_bundle_fixture()?;
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let request = sample_ordered_mailbox_request(
        &bundle,
        "query",
        sample_mailbox_message(&bundle, "query", b"public-query".to_vec()),
    );
    let input_name: Name = "_request_body".parse()?;
    let input_name_payload = norito::to_bytes(&input_name)?;
    let mut host = SoracloudIvmHost::new(request, temp_dir.path().to_path_buf(), BTreeMap::new())
        .with_public_inputs(BTreeMap::from([(input_name, b"private-input".to_vec())]));
    let error = run_low_gas_soracloud_syscall(
        &mut host,
        ivm_syscalls::SYSCALL_GET_PUBLIC_INPUT,
        PointerType::Name,
        &input_name_payload,
    )?;
    assert_eq!(error, VMError::OutOfGas);
    assert_eq!(host.metering_query_count(), 0);
    assert_eq!(host.metering_allocation_count(), 0);
    assert!(host.local_read_bindings().is_empty());
    assert!(!host.has_local_read_side_effects());
    Ok(())
}
#[test]
fn ivm_host_out_of_gas_does_not_query_state_or_materialize_side_effects() -> Result<()> {
    let bundle = load_deployment_bundle_fixture()?;
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let request = sample_ordered_mailbox_request(
        &bundle,
        "update",
        sample_mailbox_message(&bundle, "update", b"public".to_vec()),
    );
    let mut host = SoracloudIvmHost::new(request, temp_dir.path().to_path_buf(), BTreeMap::new());
    let requests = [
        (
            SYSCALL_SORACLOUD_READ_COMMITTED_STATE,
            SoracloudHostRequestPayloadV1::ReadCommittedState(
                iroha_data_model::soracloud::SoracloudReadCommittedStateRequestV1 {
                    binding_name: "session_store".parse()?,
                    state_key: "/state/session/alice".to_owned(),
                },
            ),
        ),
        (
            SYSCALL_SORACLOUD_READ_CONFIG,
            SoracloudHostRequestPayloadV1::ReadConfig(
                iroha_data_model::soracloud::SoracloudReadConfigRequestV1 {
                    config_name: "ui/settings".to_owned(),
                },
            ),
        ),
        (
            SYSCALL_SORACLOUD_READ_SECRET_ENVELOPE,
            SoracloudHostRequestPayloadV1::ReadSecretEnvelope(
                iroha_data_model::soracloud::SoracloudReadSecretEnvelopeRequestV1 {
                    secret_name: "db/password".to_owned(),
                },
            ),
        ),
        (
            SYSCALL_SORACLOUD_APPEND_JOURNAL,
            SoracloudHostRequestPayloadV1::AppendJournal(
                iroha_data_model::soracloud::SoracloudAppendJournalRequestV1 {
                    artifact_path: "/journals/test.bin".to_owned(),
                    payload_bytes: b"must-not-stage".to_vec(),
                },
            ),
        ),
    ];
    for (syscall, payload) in requests {
        let envelope = SoracloudHostRequestEnvelopeV1 {
            schema_version: iroha_data_model::soracloud::SORACLOUD_HOST_REQUEST_VERSION_V1,
            operation: payload.operation(),
            payload,
        };
        let request_payload = norito::to_bytes(&envelope)?;
        let error = run_low_gas_soracloud_syscall(
            &mut host,
            syscall,
            PointerType::SoracloudRequest,
            &request_payload,
        )?;
        assert_eq!(error, VMError::OutOfGas, "syscall {syscall:#x}");
        assert_eq!(host.metering_query_count(), 0, "syscall {syscall:#x}");
        assert_eq!(host.metering_allocation_count(), 0, "syscall {syscall:#x}");
        assert!(host.local_read_bindings().is_empty());
        assert!(!host.has_local_read_side_effects());
    }
    Ok(())
}
#[test]
fn inrou_v1_network_policy_accepts_only_isolated() -> Result<()> {
    let _ = validate_inrou_v1_network_policy(&SoraNetworkPolicyV1::Open)
        .expect_err("Inrou V1 must reject unrestricted egress");
    let _ = validate_inrou_v1_network_policy(&SoraNetworkPolicyV1::Allowlist(vec![
        SoraNetworkAllowlistEntryV1::new("8.8.8.8", [443]),
    ]))
    .expect_err("Inrou V1 must reject unmetered allowlist egress");
    validate_inrou_v1_network_policy(&SoraNetworkPolicyV1::Isolated)?;
    Ok(())
}
#[test]
fn inrou_runtime_topology_rejects_replica_count_over_release_limit() -> Result<()> {
    let mut bundle = sample_inrou_test_bundle()?;
    bundle.service.replicas = std::num::NonZeroU16::new(5).expect("nonzero");
    let error = validate_inrou_runtime_topology(&bundle, "web_portal", "2026.02.0")
        .expect_err("runtime reconciliation must distrust malformed admitted state");
    assert!(error.to_string().contains("exceeds the 4-replica"));
    Ok(())
}
#[test]
fn portable_vm_network_plan_has_no_selectable_alternate_backend() -> Result<()> {
    let isolated = build_portable_vm_network_plan(8080)?;
    assert_eq!(
        isolated.netdev,
        format!(
            "user,id=net0,ipv6=off,restrict=on,hostfwd=tcp:127.0.0.1:{}-:8080",
            isolated.expected_backend.port()
        )
    );
    for forbidden in ["tap", "bridge", "socket", "fd=", "vhost"] {
        assert!(
            !isolated.netdev.contains(forbidden),
            "alternate QEMU network backend escaped into release plan: {forbidden}"
        );
    }
    assert!(isolated.listen_base_url.starts_with("http://127.0.0.1:"));
    let public_address = isolated.public_listener.local_addr()?;
    assert_eq!(
        isolated.backend_reservation.local_addr()?,
        isolated.expected_backend
    );
    assert_ne!(public_address, isolated.expected_backend);
    assert!(
        TcpListener::bind(public_address).is_err(),
        "the supervisor must retain the public port from allocation through bridge startup"
    );
    assert!(
        TcpListener::bind(isolated.expected_backend).is_err(),
        "the supervisor must retain the private-net QEMU port until the sealed command is ready"
    );
    Ok(())
}
#[cfg(target_os = "linux")]
#[test]
fn inrou_loopback_owner_rule_targets_the_dedicated_chain() {
    let chain = SORACLOUD_INROU_IPTABLES_CHAIN_SPECS[2];
    let insert = planned_inrou_loopback_owner_rule(chain, 41_231, 0);
    assert_eq!(
        insert,
        [
            "-w",
            "5",
            "-I",
            "IROHA_INROU_S2_V1",
            "1",
            "-o",
            "lo",
            "-p",
            "tcp",
            "-d",
            "127.0.0.1",
            "--dport",
            "41231",
            "-m",
            "owner",
            "!",
            "--uid-owner",
            "0",
            "-j",
            "REJECT",
            "--reject-with",
            "tcp-reset",
        ]
        .map(ToOwned::to_owned)
    );
}
#[cfg(target_os = "linux")]
#[test]
fn inrou_owned_chain_commands_reconcile_only_one_canonical_slot() {
    let chain = SORACLOUD_INROU_IPTABLES_CHAIN_SPECS[2];
    assert_eq!(
        inrou_iptables_output_jump_args(chain, "-I", true),
        ["-w", "5", "-I", "OUTPUT", "1", "-j", "IROHA_INROU_S2_V1"].map(ToOwned::to_owned)
    );
    assert_eq!(
        inrou_iptables_output_jump_args(chain, "-D", false),
        ["-w", "5", "-D", "OUTPUT", "-j", "IROHA_INROU_S2_V1"].map(ToOwned::to_owned)
    );
    assert_eq!(
        inrou_iptables_chain_marker_args(chain, "-A"),
        [
            "-w",
            "5",
            "-A",
            "IROHA_INROU_S2_V1",
            "-m",
            "comment",
            "--comment",
            "iroha-inrou-owned-v1-slot-2",
            "-j",
            "RETURN",
        ]
        .map(ToOwned::to_owned)
    );
    assert_eq!(
        SORACLOUD_INROU_RETIRED_IPTABLES_CHAIN_SPEC.name,
        "IROHA_INROU_V1"
    );
    assert!(
        SORACLOUD_INROU_IPTABLES_CHAIN_SPECS
            .iter()
            .all(|candidate| candidate.name != SORACLOUD_INROU_RETIRED_IPTABLES_CHAIN_SPEC.name)
    );
    assert_eq!(
        SORACLOUD_INROU_IPTABLES_CHAIN_SPECS
            .iter()
            .map(|candidate| candidate.name)
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
    assert_eq!(
        SORACLOUD_INROU_IPTABLES_LOCK_PATHS
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
}
#[cfg(target_os = "linux")]
#[test]
fn inrou_owner_firewall_setup_drains_preexisting_public_connections() -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let mut client = TcpStream::connect(listener.local_addr()?)?;
    drain_inrou_pre_firewall_connections(&listener)?;
    assert_eq!(
        listener
            .accept()
            .expect_err("the accept queue must be empty")
            .kind(),
        io::ErrorKind::WouldBlock
    );
    client.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut byte = [0_u8; 1];
    match client.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            ) => {}
        outcome => panic!("drained connection remained usable: {outcome:?}"),
    }
    Ok(())
}
#[test]
fn inrou_qmp_usernet_parser_requires_one_exact_loopback_forward() -> Result<()> {
    let valid = concat!(
        "VLAN -1 (net0):\n",
        "  Protocol[State]    FD  Source Address  Port   Dest. Address  Port RecvQ SendQ\n",
        "  TCP[HOST_FORWARD]  13  127.0.0.1       41231  10.0.2.15     8080 0     0\n",
    );
    assert_eq!(
        parse_inrou_qmp_usernet_forward(valid, 8080)?,
        "127.0.0.1:41231".parse::<SocketAddr>()?
    );

    let duplicate = format!(
        "{valid}  TCP[HOST_FORWARD]  14  127.0.0.1       41232  10.0.2.15     8080 0     0\n"
    );
    assert_eyre_error_contains(
        parse_inrou_qmp_usernet_forward(&duplicate, 8080)
            .expect_err("multiple forwards must fail closed"),
        "exactly one process-owned TCP host forward",
    );
    assert_eyre_error_contains(
        parse_inrou_qmp_usernet_forward(
            "TCP[HOST_FORWARD] 13 0.0.0.0 41231 10.0.2.15 8080 0 0\n",
            8080,
        )
        .expect_err("a non-loopback forward must fail closed"),
        "outside its exact binding",
    );
    assert_eyre_error_contains(
        parse_inrou_qmp_usernet_forward(valid, 8081)
            .expect_err("a forward to the wrong guest port must fail closed"),
        "outside its exact binding",
    );
    Ok(())
}
#[test]
fn inrou_lifecycle_grace_uses_the_greater_declared_minimum_without_a_hidden_floor() {
    assert_eq!(
        effective_inrou_lifecycle_grace(Duration::from_millis(100), 1),
        Duration::from_secs(1)
    );
    assert_eq!(
        effective_inrou_lifecycle_grace(Duration::from_secs(45), 30),
        Duration::from_secs(45)
    );
    assert_eq!(
        effective_inrou_lifecycle_grace(Duration::from_secs(30), 60),
        Duration::from_secs(60)
    );
}
#[cfg(target_os = "linux")]
#[test]
fn inrou_qmp_system_powerdown_uses_exact_command_and_requires_ack() -> Result<()> {
    const EXPECTED_REQUEST: &[u8] =
        b"{\"execute\":\"system_powerdown\",\"id\":\"inrou-system-powerdown\"}\n";
    let (supervisor_qmp, mut qemu_qmp) = UnixStream::pair()?;
    let qemu = thread::spawn(move || -> io::Result<()> {
        qemu_qmp.set_read_timeout(Some(Duration::from_secs(1)))?;
        let mut request = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            qemu_qmp.read_exact(&mut byte)?;
            request.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        if request != EXPECTED_REQUEST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "supervisor emitted a noncanonical system_powerdown request",
            ));
        }
        qemu_qmp.write_all(b"{\"return\":{},\"id\":\"inrou-system-powerdown\"}\n")
    });
    let mut control = PortableVmQmpControl {
        reader: io::BufReader::new(supervisor_qmp),
    };
    request_inrou_qmp_system_powerdown(&mut control, Duration::from_secs(1))?;
    qemu.join().expect("QMP fixture")?;

    let (supervisor_qmp, mut qemu_qmp) = UnixStream::pair()?;
    let qemu = thread::spawn(move || -> io::Result<()> {
        let mut request = vec![0_u8; EXPECTED_REQUEST.len()];
        qemu_qmp.read_exact(&mut request)?;
        qemu_qmp.write_all(
            b"{\"error\":{\"class\":\"GenericError\",\"desc\":\"denied\"},\"id\":\"inrou-system-powerdown\"}\n",
        )
    });
    let mut control = PortableVmQmpControl {
        reader: io::BufReader::new(supervisor_qmp),
    };
    let _powerdown_rejection_error =
        request_inrou_qmp_system_powerdown(&mut control, Duration::from_secs(1))
            .expect_err("a rejected system_powerdown request must fail closed");
    qemu.join().expect("QMP rejection fixture")?;
    Ok(())
}
#[cfg(target_os = "linux")]
#[test]
fn inrou_qemu_proc_status_requires_exact_sandboxed_identity() -> Result<()> {
    let identity = PortableVmChildIdentity {
        uid: 60_001,
        gid: 60_002,
        supplementary_gids: vec![108, 109],
    };
    let valid = concat!(
        "Name:\tqemu-system-x86\n",
        "Uid:\t60001\t60001\t60001\t60001\n",
        "Gid:\t60002\t60002\t60002\t60002\n",
        "Groups:\t108 109\n",
        "CapInh:\t0000000000000000\n",
        "CapPrm:\t0000000000000000\n",
        "CapEff:\t0000000000000000\n",
        "CapBnd:\t0000000000000000\n",
        "CapAmb:\t0000000000000000\n",
        "NoNewPrivs:\t1\n",
        "Seccomp:\t2\n",
    );
    assert!(inrou_proc_status_matches_identity(valid, &identity)?);
    assert!(inrou_proc_status_matches_identity(
        valid,
        &PortableVmChildIdentity {
            uid: 70_001,
            gid: identity.gid,
            supplementary_gids: Vec::new(),
        },
    )?);
    assert!(inrou_proc_status_matches_identity(
        valid,
        &PortableVmChildIdentity {
            uid: 70_001,
            gid: 109,
            supplementary_gids: Vec::new(),
        },
    )?);
    assert!(!inrou_proc_status_matches_identity(
        valid,
        &PortableVmChildIdentity {
            uid: 70_001,
            gid: 70_002,
            supplementary_gids: Vec::new(),
        },
    )?);
    validate_inrou_qemu_proc_status(valid, &identity)?;
    assert_eyre_error_contains(
        validate_inrou_qemu_proc_status(
            &valid.replace("CapBnd:\t0000000000000000", "CapBnd:\t1"),
            &identity,
        )
        .expect_err("a retained bounding capability must fail closed"),
        "retained capabilities in `CapBnd`",
    );
    assert_eyre_error_contains(
        validate_inrou_qemu_proc_status(
            &valid.replace("Groups:\t108 109", "Groups:\t108 110"),
            &identity,
        )
        .expect_err("supplementary group drift must fail closed"),
        "exact supplementary groups",
    );
    assert_eyre_error_contains(
        validate_inrou_qemu_proc_status(&valid.replace("Seccomp:\t2", "Seccomp:\t0"), &identity)
            .expect_err("QEMU must enter seccomp filter mode before QMP is trusted"),
        "seccomp filter mode",
    );
    Ok(())
}
struct TestPartialWriter {
    maximum_write_bytes: usize,
    fail_after_bytes: Option<usize>,
    bytes: Vec<u8>,
}
impl io::Write for TestPartialWriter {
    fn write(&mut self, payload: &[u8]) -> io::Result<usize> {
        let remaining_before_failure = self
            .fail_after_bytes
            .map_or(usize::MAX, |limit| limit.saturating_sub(self.bytes.len()));
        if remaining_before_failure == 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected writer failure",
            ));
        }
        let written = payload
            .len()
            .min(self.maximum_write_bytes)
            .min(remaining_before_failure);
        self.bytes.extend_from_slice(&payload[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn portable_vm_loopback_bridge_forwards_through_supervisor_listener() -> Result<()> {
    let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let backend_address = backend.local_addr()?;
    let backend_worker = thread::spawn(move || -> io::Result<()> {
        let (mut stream, _) = backend.accept()?;
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request)?;
        if request != *b"ping" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bridge changed the request",
            ));
        }
        stream.write_all(b"pong")
    });
    let public = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let public_address = public.local_addr()?;
    let egress_accounting =
        PortableVmReplicaEgressAccounting::new(PortableVmEgressAccounting::new(11), 0);
    let mut bridge = PortableVmLoopbackBridge::start_with_connector(
        public,
        backend_address,
        egress_accounting.clone(),
        Arc::new(|backend, _| TcpStream::connect_timeout(&backend, Duration::from_secs(1)).ok()),
    )?;
    let mut client = TcpStream::connect(public_address)?;
    client.set_read_timeout(Some(Duration::from_secs(2)))?;
    client.write_all(b"ping")?;
    let mut response = [0_u8; 4];
    client.read_exact(&mut response)?;
    assert_eq!(&response, b"pong");
    drop(client);
    bridge.stop();
    backend_worker.join().expect("backend worker")?;
    assert_eq!(egress_accounting.revision_accounted_egress_bytes(), 15);
    assert_eq!(egress_accounting.reporter_accounted_egress_bytes(), 4);
    Ok(())
}
#[test]
fn inrou_bridge_buffer_scrub_erases_full_capacity() {
    let mut buffer = [0xA5_u8; 16 * 1024];
    scrub_inrou_bridge_buffer(&mut buffer);
    assert!(buffer.iter().all(|byte| *byte == 0));
}
#[test]
fn inrou_egress_accounting_bounds_prepaid_overcharge_after_partial_failure() {
    let accounting = PortableVmReplicaEgressAccounting::new(PortableVmEgressAccounting::new(19), 7);
    let global_stop = AtomicBool::new(false);
    let session_stop = AtomicBool::new(false);
    let mut writer = TestPartialWriter {
        maximum_write_bytes: 2,
        fail_after_bytes: Some(5),
        bytes: Vec::new(),
    };
    let payload = vec![0x5a; SORACLOUD_INROU_EGRESS_RESERVATION_BYTES + 100];

    write_inrou_bridge_buffer_bounded(
        &mut writer,
        &payload,
        &global_stop,
        &session_stop,
        Some(&accounting),
    )
    .expect_err("the injected writer failure must terminate the buffered write");

    assert_eq!(writer.bytes.len(), 5);
    assert_eq!(
        accounting.revision_accounted_egress_bytes(),
        19 + SORACLOUD_INROU_EGRESS_RESERVATION_BYTES as u64
    );
    assert_eq!(
        accounting.reporter_accounted_egress_bytes(),
        7 + SORACLOUD_INROU_EGRESS_RESERVATION_BYTES as u64
    );
    assert!(
        accounting.reporter_accounted_egress_bytes() - 7 - writer.bytes.len() as u64
            <= SORACLOUD_INROU_EGRESS_RESERVATION_BYTES as u64
    );
    assert!(!global_stop.load(AtomicOrdering::Acquire));
}
#[test]
fn hosted_http_worker_launch_requires_exact_open_reporter_checkpoint() {
    let open = |accounted_egress_bytes| HostedHttpReporterCheckpointState {
        lease_started_height: 11,
        reporting_epoch: 17,
        accounted_egress_bytes,
        finalize_reporter: false,
    };
    assert!(hosted_http_reporter_checkpoint_is_current_open(
        Some(open(100)),
        11,
        17,
        100
    ));
    assert!(!hosted_http_reporter_checkpoint_is_current_open(
        None, 11, 17, 0
    ));
    assert!(!hosted_http_reporter_checkpoint_is_current_open(
        Some(open(50)),
        11,
        17,
        100
    ));
    assert!(!hosted_http_reporter_checkpoint_is_current_open(
        Some(open(100)),
        11,
        18,
        100
    ));
    assert!(!hosted_http_reporter_checkpoint_is_current_open(
        Some(open(100)),
        12,
        17,
        100
    ));
    assert!(!hosted_http_reporter_checkpoint_is_current_open(
        Some(HostedHttpReporterCheckpointState {
            lease_started_height: 11,
            reporting_epoch: 17,
            accounted_egress_bytes: 100,
            finalize_reporter: true,
        }),
        11,
        17,
        100
    ));
}
#[test]
fn terminal_reporter_retirement_discards_only_unadmitted_zero_usage() {
    assert_eq!(
        hosted_http_terminal_reporter_action(None, 0).expect("zero unadmitted reporter"),
        HostedHttpTerminalReporterAction::Retire
    );
    hosted_http_terminal_reporter_action(None, 1)
        .expect_err("nonzero usage without admission must fail closed");
    assert_eq!(
        hosted_http_terminal_reporter_action(
            Some(HostedHttpReporterCheckpointState {
                lease_started_height: 11,
                reporting_epoch: 17,
                accounted_egress_bytes: 4,
                finalize_reporter: false,
            }),
            5,
        )
        .expect("open admitted reporter"),
        HostedHttpTerminalReporterAction::Submit
    );
    assert_eq!(
        hosted_http_terminal_reporter_action(
            Some(HostedHttpReporterCheckpointState {
                lease_started_height: 11,
                reporting_epoch: 17,
                accounted_egress_bytes: 5,
                finalize_reporter: true,
            }),
            5,
        )
        .expect("observed terminal reporter"),
        HostedHttpTerminalReporterAction::Retire
    );
    hosted_http_terminal_reporter_action(
        Some(HostedHttpReporterCheckpointState {
            lease_started_height: 11,
            reporting_epoch: 17,
            accounted_egress_bytes: 4,
            finalize_reporter: true,
        }),
        5,
    )
    .expect_err("a sealed stale checkpoint must not be advanced by a former reporter");
}
#[cfg(unix)]
#[test]
fn durable_inrou_egress_checkpoint_accepts_relative_state_root() -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let temp_dir = tempfile::Builder::new()
        .prefix(".soracloud-relative-state-")
        .tempdir_in(".")?;
    let relative_root = Path::new(".").join(temp_dir.path().file_name().expect("fixture name"));
    assert!(
        !relative_root.is_absolute(),
        "fixture must exercise a relative state root"
    );
    assert_eq!(
        fs::canonicalize(&relative_root)?,
        fs::canonicalize(temp_dir.path())?
    );
    let state_dir = relative_root.join("runtime");
    fs::create_dir(&state_dir)?;

    let checkpoint_dir = prepare_inrou_egress_checkpoint_dir(
        &state_dir.join(SORACLOUD_INROU_EGRESS_CHECKPOINT_DIR),
    )?;
    let metadata = fs::symlink_metadata(&checkpoint_dir)?;

    assert!(checkpoint_dir.is_absolute());
    assert_eq!(
        checkpoint_dir,
        fs::canonicalize(state_dir.join(SORACLOUD_INROU_EGRESS_CHECKPOINT_DIR))?
    );
    assert!(metadata.is_dir());
    assert_eq!(metadata.mode() & 0o077, 0);
    Ok(())
}
#[cfg(unix)]
#[test]
fn durable_inrou_egress_checkpoint_recovers_precharge_and_rejects_deletion() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let durable = InrouDurableEgressCheckpoint::load_or_create(
        &state_dir,
        "portal",
        11,
        17,
        "1.0.0",
        1,
        &Hash::new(b"placement-1"),
        &ALICE_ID,
        None,
    )?;
    let checkpoint_path = durable.path.clone();
    let revision = PortableVmEgressAccounting::new(0);
    let reporter = PortableVmEgressAccounting::new_durable_with_gate(
        0,
        Arc::clone(&revision.update_gate),
        durable,
    )?;
    let accounting = PortableVmReplicaEgressAccounting::from_shared(revision, reporter)?;
    let global_stop = AtomicBool::new(false);
    let session_stop = AtomicBool::new(false);
    let mut writer = TestPartialWriter {
        maximum_write_bytes: 3,
        fail_after_bytes: None,
        bytes: Vec::new(),
    };
    write_inrou_bridge_buffer_bounded(
        &mut writer,
        b"durable-response",
        &global_stop,
        &session_stop,
        Some(&accounting),
    )?;
    let durable_value = accounting.reporter_accounted_egress_bytes();
    assert_eq!(durable_value, b"durable-response".len() as u64);
    drop(accounting);

    let recovered = InrouDurableEgressCheckpoint::load_or_create(
        &state_dir,
        "portal",
        11,
        17,
        "1.0.0",
        1,
        &Hash::new(b"placement-1"),
        &ALICE_ID,
        Some(HostedHttpReporterCheckpointState {
            lease_started_height: 11,
            reporting_epoch: 17,
            accounted_egress_bytes: 0,
            finalize_reporter: false,
        }),
    )?;
    assert_eq!(recovered.accounted_egress_bytes(), durable_value);
    drop(recovered);
    fs::remove_file(&checkpoint_path)?;
    InrouDurableEgressCheckpoint::load_or_create(
        &state_dir,
        "portal",
        11,
        17,
        "1.0.0",
        1,
        &Hash::new(b"placement-1"),
        &ALICE_ID,
        Some(HostedHttpReporterCheckpointState {
            lease_started_height: 11,
            reporting_epoch: 17,
            accounted_egress_bytes: 0,
            finalize_reporter: true,
        }),
    )
    .expect_err("an admitted reporter's deleted durable checkpoint must fail closed");
    Ok(())
}
#[cfg(unix)]
#[test]
fn durable_inrou_egress_checkpoint_separates_leases_epochs_and_placements() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let first = InrouDurableEgressCheckpoint::load_or_create(
        &state_dir,
        "portal",
        11,
        17,
        "1.0.0",
        1,
        &Hash::new(b"placement-1"),
        &ALICE_ID,
        None,
    )?;
    first.advance_to(9)?;
    let renewed = InrouDurableEgressCheckpoint::load_or_create(
        &state_dir,
        "portal",
        12,
        17,
        "1.0.0",
        1,
        &Hash::new(b"placement-1"),
        &ALICE_ID,
        None,
    )?;
    let second = InrouDurableEgressCheckpoint::load_or_create(
        &state_dir,
        "portal",
        11,
        18,
        "1.0.0",
        1,
        &Hash::new(b"placement-1"),
        &ALICE_ID,
        None,
    )?;
    let replacement = InrouDurableEgressCheckpoint::load_or_create(
        &state_dir,
        "portal",
        11,
        17,
        "1.0.0",
        1,
        &Hash::new(b"placement-2"),
        &ALICE_ID,
        None,
    )?;
    assert_ne!(first.path, second.path);
    assert_ne!(first.path, renewed.path);
    assert_ne!(first.path, replacement.path);
    assert_eq!(first.accounted_egress_bytes(), 9);
    assert_eq!(renewed.accounted_egress_bytes(), 0);
    assert_eq!(second.accounted_egress_bytes(), 0);
    assert_eq!(replacement.accounted_egress_bytes(), 0);
    InrouDurableEgressCheckpoint::load_or_create(
        &state_dir,
        "portal",
        11,
        19,
        "1.0.0",
        1,
        &Hash::new(b"placement-1"),
        &ALICE_ID,
        Some(HostedHttpReporterCheckpointState {
            lease_started_height: 11,
            reporting_epoch: 17,
            accounted_egress_bytes: 0,
            finalize_reporter: false,
        }),
    )
    .expect_err("a durable key must not accept another reporting epoch's checkpoint");
    Ok(())
}
#[cfg(unix)]
#[test]
fn durable_inrou_egress_persistence_failure_exposes_no_response_bytes() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let durable = InrouDurableEgressCheckpoint::load_or_create(
        &state_dir,
        "portal",
        11,
        17,
        "1.0.0",
        1,
        &Hash::new(b"placement-1"),
        &ALICE_ID,
        None,
    )?;
    let checkpoint_dir = durable
        .path
        .parent()
        .expect("checkpoint parent")
        .to_path_buf();
    fs::remove_file(&durable.path)?;
    fs::remove_dir(&checkpoint_dir)?;
    fs::write(&checkpoint_dir, b"block atomic checkpoint writes")?;
    let revision = PortableVmEgressAccounting::new(0);
    let reporter = PortableVmEgressAccounting::new_durable_with_gate(
        0,
        Arc::clone(&revision.update_gate),
        durable,
    )?;
    let accounting = PortableVmReplicaEgressAccounting::from_shared(revision, reporter)?;
    let global_stop = AtomicBool::new(false);
    let session_stop = AtomicBool::new(false);
    let mut writer = TestPartialWriter {
        maximum_write_bytes: usize::MAX,
        fail_after_bytes: None,
        bytes: Vec::new(),
    };
    write_inrou_bridge_buffer_bounded(
        &mut writer,
        b"must-not-be-exposed",
        &global_stop,
        &session_stop,
        Some(&accounting),
    )
    .expect_err("checkpoint persistence failure must stop the bridge before writing");
    assert!(writer.bytes.is_empty());
    assert_eq!(accounting.reporter_accounted_egress_bytes(), 0);
    assert!(global_stop.load(AtomicOrdering::Acquire));
    Ok(())
}
#[cfg(unix)]
#[test]
fn durable_inrou_egress_checkpoint_rejects_rollback_and_corruption() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let durable = InrouDurableEgressCheckpoint::load_or_create(
        &state_dir,
        "portal",
        11,
        17,
        "1.0.0",
        1,
        &Hash::new(b"placement-1"),
        &ALICE_ID,
        None,
    )?;
    let checkpoint_path = durable.path.clone();
    let reporter_key_digest = durable.reporter_key_digest;
    drop(durable);
    write_inrou_durable_egress_checkpoint(&checkpoint_path, &reporter_key_digest, 5)?;
    InrouDurableEgressCheckpoint::load_or_create(
        &state_dir,
        "portal",
        11,
        17,
        "1.0.0",
        1,
        &Hash::new(b"placement-1"),
        &ALICE_ID,
        Some(HostedHttpReporterCheckpointState {
            lease_started_height: 11,
            reporting_epoch: 17,
            accounted_egress_bytes: 10,
            finalize_reporter: false,
        }),
    )
    .expect_err("a valid but stale durable checkpoint must be treated as rollback");
    fs::write(&checkpoint_path, b"corrupt")?;
    InrouDurableEgressCheckpoint::load_or_create(
        &state_dir,
        "portal",
        11,
        17,
        "1.0.0",
        1,
        &Hash::new(b"placement-1"),
        &ALICE_ID,
        Some(HostedHttpReporterCheckpointState {
            lease_started_height: 11,
            reporting_epoch: 17,
            accounted_egress_bytes: 0,
            finalize_reporter: false,
        }),
    )
    .expect_err("a corrupt durable checkpoint must fail closed");
    Ok(())
}
#[cfg(unix)]
#[test]
fn durable_inrou_egress_checkpoint_rejects_symlinked_state_ancestor() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let redirected = state_dir.join("redirected");
    fs::create_dir(&redirected)?;
    let state_link = state_dir.join("state-link");
    symlink(&redirected, &state_link)?;
    let error = InrouDurableEgressCheckpoint::load_or_create(
        &state_link,
        "portal",
        11,
        17,
        "1.0.0",
        1,
        &Hash::new(b"placement-1"),
        &ALICE_ID,
        None,
    )
    .expect_err("a symlinked state ancestor must fail before checkpoint creation");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(
        error
            .to_string()
            .contains(state_link.to_string_lossy().as_ref()),
        "unexpected symlink rejection: {error}"
    );
    assert!(fs::read_dir(&redirected)?.next().is_none());
    Ok(())
}
#[test]
fn durable_inrou_egress_gc_rejects_active_rollout() -> Result<()> {
    let mut state = test_state()?;
    let bundle = sample_inrou_test_bundle()?;
    let mut deployment = sample_deployment_state(&bundle);
    deployment.active_rollout = Some(SoraServiceRolloutStateV1 {
        schema_version: SORA_SERVICE_ROLLOUT_STATE_VERSION_V1,
        rollout_handle: "retired-inrou-canary".to_owned(),
        baseline_version: "2026.01.0".to_owned(),
        candidate_version: bundle.service.service_version.clone(),
        canary_percent: 25,
        traffic_percent: 25,
        stage: SoraRolloutStageV1::Canary,
        health_failures: 0,
        max_health_failures: 3,
        health_window_secs: 30,
        created_sequence: 7,
        updated_sequence: 7,
    });
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, deployment);
    }
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(canonical_test_runtime_state_dir(&temp_dir)?),
        Arc::clone(&state),
    );
    let view = state.view();

    let error = manager
        .reconcile_inrou_egress_checkpoint_files(&view)
        .expect_err("first-release Inrou checkpoint GC must reject an active rollout");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(
        error
            .to_string()
            .contains("unsupported active Inrou canary"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn durable_inrou_egress_gc_removes_retired_revision_reporter_file() -> Result<()> {
    let mut state = test_state()?;
    let bundle = sample_inrou_test_bundle()?;
    let mut deployment = sample_deployment_state(&bundle);
    let lease = deployment
        .service_lease
        .as_mut()
        .expect("hosted service lease");
    let retired_version = "2026.01.0";
    let placement_incarnation = Hash::new(b"retired-placement");
    lease.egress_reporter_checkpoints.push(
        iroha_data_model::soracloud::SoraServiceLeaseEgressCheckpointV1 {
            reporting_epoch: lease.reporting_epoch,
            assignment: iroha_data_model::soracloud::SoraServiceLeaseReporterAssignmentV1 {
                schema_version:
                    iroha_data_model::soracloud::SORA_SERVICE_LEASE_REPORTER_ASSIGNMENT_VERSION_V1,
                service_version: retired_version.to_owned(),
                placement: SoraInrouReplicaPlacementV1 {
                    replica_slot: 1,
                    economic_clock: SoraServiceLeaseClockV1::CanonicalBlockHeight,
                    lease_started_height: lease.lease_started_height,
                    placement_incarnation,
                    host_availability: SoraInrouReplicaHostAvailabilityV1::Available,
                    validator_account_id: ALICE_ID.clone(),
                    peer_id: canonical_inrou_test_peer_id().to_owned(),
                    selected_guest_isa: current_host_inrou_guest_isa()
                        .expect("supported Inrou host ISA"),
                },
                placement_reconciled_at_ms: 1,
            },
            accounted_egress_bytes: 7,
            last_updated_height: 1,
            finalize_reporter: true,
        },
    );
    lease.accounted_egress_bytes = 7;
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, deployment);
    }

    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let retired = InrouDurableEgressCheckpoint::load_or_create(
        &state_dir,
        bundle.service.service_name.as_ref(),
        1,
        1,
        retired_version,
        1,
        &placement_incarnation,
        &ALICE_ID,
        None,
    )?;
    retired.advance_to(7)?;
    let retired_path = retired.path.clone();
    drop(retired);
    assert!(retired_path.is_file());

    let manager =
        SoracloudRuntimeManager::new(test_runtime_manager_config(state_dir), Arc::clone(&state));
    let view = state.view();
    manager.reconcile_inrou_egress_checkpoint_files(&view)?;
    assert!(
        !retired_path.exists(),
        "a reporter file for a non-current Inrou revision must not survive GC"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn durable_inrou_egress_checkpoint_accepts_fresh_relative_state_dir() -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};

    let current_dir = fs::canonicalize(".")?;
    let temp_dir = tempfile::Builder::new()
        .prefix("soracloud-relative-state-")
        .tempdir_in(&current_dir)?;
    let state_dir = temp_dir.path().join("storage/soracloud_runtime");
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(&state_dir)?;
    let checkpoint_dir = state_dir.join(SORACLOUD_INROU_EGRESS_CHECKPOINT_DIR);
    assert!(!checkpoint_dir.exists());
    let relative_state_dir = state_dir
        .strip_prefix(&current_dir)
        .wrap_err("derive relative Soracloud runtime state directory")?;
    assert!(relative_state_dir.is_relative());

    assert_eq!(
        reconcile_inrou_egress_checkpoint_directory(relative_state_dir, &BTreeSet::new(), 8,)?,
        0
    );
    let checkpoint_metadata = fs::symlink_metadata(&checkpoint_dir)?;
    assert!(checkpoint_metadata.is_dir());
    assert_eq!(checkpoint_metadata.mode() & 0o077, 0);
    assert!(fs::read_dir(&checkpoint_dir)?.next().is_none());
    Ok(())
}
#[cfg(unix)]
#[test]
fn durable_inrou_egress_gc_retains_current_and_ahead_reporters() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let checkpoint_dir = prepare_inrou_egress_checkpoint_dir(
        &state_dir.join(SORACLOUD_INROU_EGRESS_CHECKPOINT_DIR),
    )?;
    let current = [0x11; 32];
    let locally_ahead = [0x22; 32];
    let old_epoch = [0x33; 32];
    for (digest, bytes) in [(current, 7), (locally_ahead, 11), (old_epoch, 5)] {
        write_inrou_durable_egress_checkpoint(
            &checkpoint_dir.join(format!("{}.bin", hex::encode(digest))),
            &digest,
            bytes,
        )?;
    }
    let retained = BTreeSet::from([current, locally_ahead]);
    assert_eq!(
        reconcile_inrou_egress_checkpoint_directory(&state_dir, &retained, 8)?,
        1
    );
    assert!(
        checkpoint_dir
            .join(format!("{}.bin", hex::encode(current)))
            .is_file()
    );
    assert!(
        checkpoint_dir
            .join(format!("{}.bin", hex::encode(locally_ahead)))
            .is_file()
    );
    assert!(
        !checkpoint_dir
            .join(format!("{}.bin", hex::encode(old_epoch)))
            .exists()
    );
    Ok(())
}

#[test]
fn soracloud_canonical_argument_tables_preserve_full_width_context_and_reject_unknown_fields()
-> Result<()> {
    let artifact = soracloud_update_artifact(&["update"]);
    let contract = prepare_contract(Arc::from(artifact))?;
    let body = ivm::pointer_abi::encode_tlv(PointerType::Blob, b"exact request body")?;
    let mut vm = IVM::new(u64::MAX);
    vm.load_prepared(&contract)?;
    let (arguments, output_kind) = prepare_soracloud_invocation(
        &mut vm,
        &contract,
        "update",
        SoracloudInvocationInput {
            body_tlv: &body,
            metadata_tlv: None,
            execution_sequence: Some(u64::MAX),
            observed_height: u64::MAX - 1,
        },
    )?;
    assert!(matches!(output_kind, SoracloudOutputKind::Unit));
    let arguments = arguments.expect("three authenticated template fields");
    let record: EntrypointArgumentRecordV1 = norito::decode_canonical(arguments.canonical_bytes())?;
    assert_eq!(record.atoms.len(), 3);
    let ivm::EntrypointValueAtomV1::Pointer(body_copy) = &record.atoms[0] else {
        panic!("template body is a Blob pointer");
    };
    assert_eq!(body_copy, &body);
    for (atom, expected) in record.atoms[1..].iter().zip([u64::MAX, u64::MAX - 1]) {
        let ivm::EntrypointValueAtomV1::Pointer(bytes) = atom else {
            panic!("full-width context is an Int pointer");
        };
        assert_eq!(
            ivm::numeric_tlv::decode_int_bytes(bytes)?,
            iroha_primitives::bigint::BigInt::from(expected)
        );
    }
    for value in [0, i64::MAX as u64, i64::MAX as u64 + 1, u64::MAX] {
        assert_eq!(
            ivm::numeric_tlv::decode_int_bytes(&public_input_int_tlv(value)?)?,
            iroha_primitives::bigint::BigInt::from(value)
        );
    }
    let unknown = soracloud_contract_artifact_with_functions(vec![(
        soracloud_typed_entrypoint(
            "unknown",
            &[("invented", EntrypointValueKindV1::Blob)],
            ivm::EntrypointValueTypeV1 {
                nodes: vec![EntrypointValueTypeNodeV1::Unit],
            },
        ),
        soracloud_unit_return_words(),
    )]);
    let unknown = prepare_contract(Arc::from(unknown))?;
    let mut denied = IVM::new(u64::MAX);
    denied.load_prepared(&unknown)?;
    assert!(matches!(
        prepare_soracloud_invocation(
            &mut denied,
            &unknown,
            "unknown",
            SoracloudInvocationInput {
                body_tlv: &body,
                metadata_tlv: None,
                execution_sequence: Some(7),
                observed_height: 11
            }
        ),
        Err(VMError::DecodeError)
    ));
    assert!(denied.call_result_word_count().is_err());
    Ok(())
}

#[test]
fn soracloud_completed_result_tables_reject_raw_registers_and_corrupt_unit_words() -> Result<()> {
    let mut raw = IVM::new(u64::MAX);
    let body = ivm::pointer_abi::encode_tlv(PointerType::Blob, b"old register response")?;
    let pointer = raw.alloc_input_tlv(&body)?;
    raw.set_register(10, pointer);
    let error = decode_vm_output(&raw, SoracloudOutputKind::Blob, "query", "raw", "svc", "v1")
        .expect_err("raw r10 without protected completion is not a response");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Internal);
    let artifact = simple_soracloud_contract_artifact(&["unit"]);
    let contract = prepare_contract(Arc::from(artifact))?;
    let mut vm = IVM::new(u64::MAX);
    vm.load_prepared(&contract)?;
    vm.select_entrypoint("unit")?;
    vm.run()?;
    assert_eq!(vm.call_result_word_count()?, 1);
    assert_eq!(vm.public_call_result_word(0)?, 0);
    assert_eq!(
        decode_vm_output(
            &vm,
            SoracloudOutputKind::Unit,
            "update",
            "unit",
            "svc",
            "v1"
        )?
        .0,
        Vec::<u8>::new()
    );
    vm.memory.store_u64(vm.register(10), 1)?;
    assert!(
        decode_vm_output(
            &vm,
            SoracloudOutputKind::Unit,
            "update",
            "unit",
            "svc",
            "v1"
        )
        .is_err(),
        "completed unit words must stay canonical zero"
    );
    vm.memory.store_u64(vm.register(10), 0)?;
    assert!(
        decode_vm_output(
            &vm,
            SoracloudOutputKind::Unit,
            "update",
            "unit",
            "svc",
            "v1"
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn soracloud_completed_json_decode_refusal_stays_unavailable_without_mailbox_failure_receipt()
-> Result<()> {
    let json = Json::from(norito::json!({"exact": "original response"}));
    let frame = norito::encode_canonical(&json)?;
    let body = ivm::pointer_abi::encode_tlv(PointerType::Json, &frame)?;
    let (vm, output_kind) = soracloud_echo_vm(&body, EntrypointValueKindV1::Json)?;
    let bundle = load_deployment_bundle_fixture()?;
    let request = sample_ordered_mailbox_request(
        &bundle,
        "query",
        sample_mailbox_message(&bundle, "query", b"original".to_vec()),
    );
    let pool = iroha_allocation::AllocationBudget::new(32 * 1024 * 1024);
    let context = norito::core::DecodeBudgetContext::try_new_owned(
        norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX),
        &pool,
    )?;
    let baseline = pool.reserved_bytes();
    let result = context.with(|| {
        let error = norito::core::with_decode_limits_scope(
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || decode_ordered_mailbox_vm_output(&vm, output_kind, &request),
        )
        .expect_err("actual completed JSON output decoder must honor enclosing quota");
        assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
        let error = ordered_mailbox_output_failure(request.clone(), error)
            .expect_err("local decoder refusal must never create a deterministic mailbox receipt");
        assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
        assert_eq!(pool.reserved_bytes(), baseline);
        let (output, content_type) = decode_ordered_mailbox_vm_output(&vm, output_kind, &request)?;
        assert_eq!(output, json.get().as_bytes());
        assert_eq!(content_type.as_deref(), Some("application/json"));
        Ok::<_, SoracloudRuntimeExecutionError>(())
    });
    result?;
    drop(context);
    assert_eq!(pool.reserved_bytes(), 0);
    let mut corrupt = frame;
    corrupt[0] ^= 1;
    assert!(matches!(
        json_pointer_response_payload(&corrupt),
        Err(VMError::DecodeError)
    ));
    Ok(())
}

// Original Soracloud public-input JSON refusal and same-source retry controls.

#[test]
fn soracloud_public_input_json_refusal_is_local_and_retryable() -> Result<()> {
    let bundle = load_deployment_bundle_fixture()?;
    let request = sample_ordered_mailbox_request(
        &bundle,
        "query",
        sample_mailbox_message(&bundle, "query", b"original".to_vec()),
    );
    let body = ivm::pointer_abi::encode_tlv(PointerType::Blob, b"original request")?;
    let expected = ordered_mailbox_public_inputs(&body, u64::MAX, 17)?;
    let value = norito::json!({"original": "metadata", "height": 17});
    let json = Json::from_norito_value_ref(&value)?;
    let frame = norito::encode_canonical(&json)?;
    let metadata = ivm::pointer_abi::encode_tlv(PointerType::Json, &frame)?;
    let pool = iroha_allocation::AllocationBudget::new(32 * 1024 * 1024);
    let unlimited =
        norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX);
    // Calibrate only the genuine frame decoder outside the tested attempt.
    // The oracle owns its counter backing in the same original physical pool.
    let oracle = norito::core::DecodeBudgetContext::try_new_owned(unlimited, &pool)?;
    let decoded =
        oracle.with(|| soracloud_codec_attempt(|| norito::decode_canonical::<Json>(&frame)))?;
    assert_eq!(decoded, json);
    let frame_demand = usize::try_from(oracle.consumed_allocated_bytes())?;
    assert!(frame_demand > 0);
    drop(decoded);
    drop(oracle);
    assert_eq!(pool.reserved_bytes(), 0);
    let context = norito::core::DecodeBudgetContext::try_new_owned(unlimited, &pool)?;
    let baseline = pool.reserved_bytes();
    context.with(|| {
        let error = norito::core::with_decode_limits_scope(
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || ordered_mailbox_public_inputs(&body, u64::MAX, 17),
        )
        .expect_err("original trigger JSON destination honors the enclosing quota");
        assert!(matches!(
            error,
            VMError::ExecutionDeferred(ivm::ExecutionDeferral::ActiveMemoryCapacity)
        ));
        let error = ordered_mailbox_vm_failure(request.clone(), &error)
            .expect_err("public-input refusal cannot create a deterministic mailbox receipt");
        assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
        assert_eq!(pool.reserved_bytes(), baseline);
        let error = norito::core::with_decode_limits_scope(
            norito::core::DecodeLimits::new(
                usize::MAX,
                usize::MAX,
                usize::MAX,
                frame_demand,
                usize::MAX,
            ),
            || json_value_from_tlv(&metadata),
        )
        .expect_err("exact frame debit leaves no credit for its subsequent Value parse");
        assert!(matches!(
            error,
            VMError::ExecutionDeferred(ivm::ExecutionDeferral::ActiveMemoryCapacity)
        ));
        assert_eq!(pool.reserved_bytes(), baseline);
        assert_eq!(json_value_from_tlv(&metadata)?, value);
        assert_eq!(
            ordered_mailbox_public_inputs(&body, u64::MAX, 17)?,
            expected
        );
        let mut invalid_frame = frame.clone();
        invalid_frame[0] ^= 1;
        let invalid = ivm::pointer_abi::encode_tlv(PointerType::Json, &invalid_frame)?;
        let invalid = json_value_from_tlv(&invalid).expect_err("corrupt framing stays terminal");
        assert!(matches!(invalid, VMError::DecodeError));
        assert!(ordered_mailbox_vm_failure(request.clone(), &invalid).is_ok());
        Ok::<_, eyre::Report>(())
    })?;
    drop(context);
    assert_eq!(pool.reserved_bytes(), 0);
    Ok(())
}

#[test]
fn soracloud_query_metadata_json_refusal_is_local_and_retryable() -> Result<()> {
    let request = SoracloudLocalReadRequest {
        observed_height: u64::MAX,
        observed_block_hash: None,
        service_name: "original-service".to_owned(),
        service_version: "original-version".to_owned(),
        handler_name: "query".to_owned(),
        handler_class: iroha_core::soracloud_runtime::SoracloudLocalReadKind::Query,
        request_method: "GET".to_owned(),
        request_path: "/query".to_owned(),
        handler_path: "/".to_owned(),
        request_query: Some("original=1".to_owned()),
        request_headers: BTreeMap::from([("original".to_owned(), "header".to_owned())]),
        request_body: b"original body".to_vec(),
        request_commitment: Hash::new(b"original request"),
    };
    let expected = local_read_request_metadata_tlv_bytes(&request)?;
    let pool = iroha_allocation::AllocationBudget::new(32 * 1024 * 1024);
    let context = norito::core::DecodeBudgetContext::try_new_owned(
        norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX),
        &pool,
    )?;
    let baseline = pool.reserved_bytes();
    context.with(|| {
        let error = norito::core::with_decode_limits_scope(
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || local_read_request_metadata_tlv_bytes(&request),
        )
        .expect_err("original query metadata destination honors the enclosing quota");
        assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
        assert_eq!(pool.reserved_bytes(), baseline);
        assert_eq!(local_read_request_metadata_tlv_bytes(&request)?, expected);
        Ok::<_, eyre::Report>(())
    })?;
    drop(context);
    assert_eq!(pool.reserved_bytes(), 0);
    Ok(())
}
