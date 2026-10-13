impl SoracloudRuntimeMutationSink for RecordingRuntimeMutationSink {
    fn submit_instruction(
        &self,
        instruction: InstructionBox,
        _endpoint: &'static str,
    ) -> eyre::Result<()> {
        self.instructions.lock().push(instruction);
        Ok(())
    }
    fn submit_inrou_host_capability(
        &self,
        capability: &SoraInrouHostCapabilityRecordV1,
    ) -> eyre::Result<()> {
        let payload = encode_inrou_host_advertise_provenance_payload(capability)?;
        self.instructions.lock().push(InstructionBox::from(
            iroha_data_model::isi::soracloud::AdvertiseSoracloudInrouHost {
                capability: capability.clone(),
                provenance: ManifestProvenance {
                    signer: ALICE_KEYPAIR.public_key().clone(),
                    signature: sign_soracloud_runtime_provenance(
                        &ALICE_KEYPAIR,
                        &payload,
                        "sign test Inrou host advert provenance",
                    )?,
                },
            },
        ));
        Ok(())
    }
    fn submit_inrou_host_withdrawal(&self, validator_account_id: &AccountId) -> eyre::Result<()> {
        let payload = encode_inrou_host_withdraw_provenance_payload(validator_account_id)?;
        self.instructions.lock().push(InstructionBox::from(
            iroha_data_model::isi::soracloud::WithdrawSoracloudInrouHost {
                validator_account_id: validator_account_id.clone(),
                provenance: ManifestProvenance {
                    signer: ALICE_KEYPAIR.public_key().clone(),
                    signature: sign_soracloud_runtime_provenance(
                        &ALICE_KEYPAIR,
                        &payload,
                        "sign test Inrou host withdrawal provenance",
                    )?,
                },
            },
        ));
        Ok(())
    }
}
#[derive(Default)]
struct StartupQualifiedSmokeRuntimeMutationSink {
    inner: RecordingRuntimeMutationSink,
}
impl SoracloudRuntimeMutationSink for StartupQualifiedSmokeRuntimeMutationSink {
    fn ensure_production_qualified(&self) -> eyre::Result<()> {
        Ok(())
    }

    fn submit_instruction(
        &self,
        instruction: InstructionBox,
        endpoint: &'static str,
    ) -> eyre::Result<()> {
        self.inner.submit_instruction(instruction, endpoint)
    }

    fn submit_inrou_host_capability(
        &self,
        capability: &SoraInrouHostCapabilityRecordV1,
    ) -> eyre::Result<()> {
        self.inner.submit_inrou_host_capability(capability)
    }

    fn submit_inrou_host_withdrawal(&self, validator_account_id: &AccountId) -> eyre::Result<()> {
        self.inner
            .submit_inrou_host_withdrawal(validator_account_id)
    }
}
fn insert_service_revision_fixture(world: &mut World, bundle: &SoraDeploymentBundleV1) {
    world.soracloud_service_revisions_mut_for_testing().insert(
        (
            bundle.service.service_name.to_string(),
            bundle.service.service_version.clone(),
        ),
        bundle.clone(),
    );
}
fn insert_service_deployment_fixture(
    world: &mut World,
    bundle: &SoraDeploymentBundleV1,
    deployment: SoraServiceDeploymentStateV1,
) {
    let lifecycle_lower_bound = deployment_lifecycle_sequence_lower_bound(&deployment);
    let audit_sequence = world
        .soracloud_service_audit_events_mut_for_testing()
        .view()
        .iter()
        .map(|(sequence, _event)| *sequence)
        .max()
        .map_or(lifecycle_lower_bound, |head| {
            head.saturating_add(1).max(lifecycle_lower_bound)
        });
    world
        .soracloud_service_deployments_mut_for_testing()
        .insert(bundle.service.service_name.clone(), deployment);
    world
        .soracloud_service_audit_events_mut_for_testing()
        .insert(
            audit_sequence,
            sample_service_audit_event(bundle, audit_sequence),
        );
}
fn insert_service_runtime_fixture(
    world: &mut World,
    bundle: &SoraDeploymentBundleV1,
    runtime: SoraServiceRuntimeStateV1,
) {
    world
        .soracloud_service_runtime_mut_for_testing()
        .insert(bundle.service.service_name.clone(), runtime);
}
fn assign_fixture_artifact_hashes(
    bundle: &mut SoraDeploymentBundleV1,
    bundle_bytes: &[u8],
    label: &str,
) -> Vec<Vec<u8>> {
    let service_name = bundle.service.service_name.to_string();
    bundle.container.bundle_hash = Hash::new(bundle_bytes);
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    let mut payloads = Vec::with_capacity(bundle.service.artifacts.len());
    for (index, artifact) in bundle.service.artifacts.iter_mut().enumerate() {
        let payload =
            format!("{label}:{service_name}:{index}:{}", artifact.artifact_path).into_bytes();
        artifact.artifact_hash = Hash::new(&payload);
        payloads.push(payload);
    }
    payloads
}
fn seed_local_artifact_cache(
    artifacts_root: &Path,
    bundle_hash: Hash,
    bundle_bytes: &[u8],
    artifact_hashes_and_bytes: impl IntoIterator<Item = (Hash, Vec<u8>)>,
) -> Result<()> {
    fs::create_dir_all(artifacts_root)?;
    fs::write(
        artifacts_root.join(hash_cache_name(bundle_hash)),
        bundle_bytes,
    )?;
    for (artifact_hash, payload) in artifact_hashes_and_bytes {
        fs::write(artifacts_root.join(hash_cache_name(artifact_hash)), payload)?;
    }
    Ok(())
}
fn test_sorafs_node(temp_dir: &tempfile::TempDir) -> NodeHandle {
    NodeHandle::new(
        StorageConfig::builder()
            .enabled(true)
            .data_dir(temp_dir.path().join("sorafs-storage"))
            .build(),
    )
}
fn test_operator_preseed_store(temp_dir: &tempfile::TempDir) -> Arc<StorageBackend> {
    let canonical_temp_root =
        fs::canonicalize(temp_dir.path()).expect("canonicalize operator-preseed fixture root");
    Arc::new(
        StorageBackend::new(
            StorageConfig::builder()
                .enabled(false)
                .data_dir(canonical_temp_root.join("operator-preseed-storage"))
                .build(),
        )
        .expect("operator-preseed storage fixture"),
    )
}
fn qualified_test_operator_preseed_manifests(store: &StorageBackend) -> BTreeSet<[u8; 32]> {
    store
        .manifests()
        .into_iter()
        .map(|manifest| *manifest.manifest_digest())
        .collect()
}
fn ingest_operator_preseed_payload(
    store: &StorageBackend,
    plan: &CarBuildPlan,
    manifest: &sorafs_manifest::ManifestV1,
    payload: &[u8],
) -> Result<StoredManifest> {
    let mut reader = payload;
    let manifest_id = store.ingest_manifest(manifest, plan, &mut reader)?;
    store
        .manifest(&manifest_id)
        .ok_or_else(|| eyre::eyre!("ingested operator-preseed manifest is missing"))
}
fn build_sorafs_manifest(payload: &[u8]) -> Result<(CarBuildPlan, sorafs_manifest::ManifestV1)> {
    let plan = CarBuildPlan::single_file(payload)?;
    let manifest = build_sorafs_manifest_from_plan(&plan, payload)?;
    Ok((plan, manifest))
}
fn build_sorafs_manifest_from_plan(
    plan: &CarBuildPlan,
    payload: &[u8],
) -> Result<sorafs_manifest::ManifestV1> {
    let stats = CarWriter::new(plan, payload)?.write_to(io::sink())?;
    let por_root = sorafs_car::compute_por_root(payload, plan)?;
    Ok(ManifestBuilder::new()
        .root_cid(
            stats
                .root_cids
                .first()
                .cloned()
                .ok_or_else(|| eyre::eyre!("fixture CAR writer produced no root CID"))?,
        )
        .dag_codec(DagCodecId(stats.dag_codec))
        .chunking_from_profile(plan.chunk_profile, BLAKE3_256_MULTIHASH_CODE)
        .chunk_digest_sha3_256(compute_chunk_plan_digest_sha3(&plan.chunks))
        .por_root(por_root)
        .content_length(plan.content_length)
        .car_digest(*stats.car_archive_digest.as_bytes())
        .car_size(stats.car_size)
        .pin_policy(ManifestPinPolicy {
            min_replicas: 1,
            storage_class: sorafs_manifest::StorageClass::Warm,
            retention_epoch: 601,
        })
        .build()?)
}
fn ingest_sorafs_payload(node: &NodeHandle, payload: &[u8]) -> Result<StoredManifest> {
    let (plan, manifest) = build_sorafs_manifest(payload)?;
    let mut reader = payload;
    let manifest_id = node.ingest_manifest(&manifest, &plan, &mut reader)?;
    node.manifest_metadata(&manifest_id).map_err(Into::into)
}
fn approve_sorafs_manifests(
    state: &Arc<State>,
    node: &NodeHandle,
    manifests: &[StoredManifest],
) -> Result<()> {
    let fixtures = manifests
        .iter()
        .enumerate()
        .map(|(index, stored)| {
            let payload = node.read_payload_range(
                stored.manifest_id(),
                0,
                usize::try_from(stored.content_length())?,
            )?;
            let fixture =
                build_remote_manifest_fixture(&payload, [0xB4; 32], u8::try_from(index + 1)?)?;
            // The common completed-ingest fixture must identify exactly the
            // manifest and bytes already held by the real local storage owner.
            assert_eq!(fixture.manifest_digest.as_bytes(), stored.manifest_digest());
            assert_eq!(fixture.manifest_root_cid.as_bytes(), stored.manifest_cid());
            let manifest = stored.load_manifest()?;
            assert_eq!(
                fixture.chunk_digest_sha3_256,
                manifest.chunk_digest_sha3_256
            );
            assert_eq!(fixture.por_root, manifest.por_root);
            Ok(fixture)
        })
        .collect::<Result<Vec<_>>>()?;
    approve_remote_hydration_sources(state, &fixtures)?;
    let view = state.view();
    let sources = collect_remote_hydration_sources(&view, state)?;
    for fixture in &fixtures {
        assert!(
            sources.iter().any(|source| source.manifest_digest_hex
                == hex::encode(fixture.manifest_digest.as_bytes())
                && source.manifest_cid_hex == hex::encode(fixture.manifest_root_cid.as_bytes())
                && source.provider_ids == vec![fixture.provider_id]),
            "completed local ingest must produce its exact admitted hydration source"
        );
    }
    Ok(())
}
#[test]
fn manager_config_uses_explicit_soracloud_runtime_settings() {
    let runtime = iroha_config::parameters::actual::SoracloudRuntime {
        production_mode: false,
        state_dir: PathBuf::from("/tmp/iroha-soracloud-runtime-config"),
        reconcile_interval: Duration::from_secs(17),
        hydration_concurrency: std::num::NonZeroUsize::new(7)
            .expect("nonzero hydration concurrency"),
        prepared_runtime_cache_capacity: std::num::NonZeroUsize::new(11)
            .expect("nonzero prepared runtime cache capacity"),
        cache_budgets: iroha_config::parameters::actual::SoracloudRuntimeCacheBudgets {
            bundle_bytes: std::num::NonZeroU64::new(1_024).expect("nonzero"),
            static_asset_bytes: std::num::NonZeroU64::new(2_048).expect("nonzero"),
            journal_bytes: std::num::NonZeroU64::new(3_072).expect("nonzero"),
            checkpoint_bytes: std::num::NonZeroU64::new(4_096).expect("nonzero"),
            model_artifact_bytes: std::num::NonZeroU64::new(5_120).expect("nonzero"),
            model_weight_bytes: std::num::NonZeroU64::new(6_144).expect("nonzero"),
        },
        inrou: iroha_config::parameters::actual::SoracloudRuntimeInrou {
            enabled: false,
            portable_vm_uid: None,
            portable_vm_gid: None,
            trusted_guest_artifact: None,
            guest_image_max_bytes: std::num::NonZeroU64::new(4 * 1024 * 1024 * 1024)
                .expect("nonzero guest-image bound"),
            max_cpu_millis: std::num::NonZeroU32::new(2_000).expect("nonzero CPU budget"),
            max_memory_bytes: std::num::NonZeroU64::new(2 * 1024 * 1024 * 1024)
                .expect("nonzero memory budget"),
            max_storage_bytes: std::num::NonZeroU64::new(16 * 1024 * 1024 * 1024)
                .expect("nonzero storage budget"),
            bundle_archive_max_compressed_bytes: std::num::NonZeroU64::new(8_192)
                .expect("nonzero compressed archive bound"),
            bundle_archive_max_decoded_bytes: std::num::NonZeroU64::new(32_768)
                .expect("nonzero decoded archive bound"),
            bundle_archive_max_entries: std::num::NonZeroU32::new(17)
                .expect("nonzero archive entry bound"),
            bundle_archive_max_file_bytes: std::num::NonZeroU64::new(16_384)
                .expect("nonzero archive file bound"),
            bundle_archive_max_total_file_bytes: std::num::NonZeroU64::new(24_576)
                .expect("nonzero archive total-file bound"),
            start_grace: Duration::from_secs(11),
            stop_grace: Duration::from_secs(13),
        },
        submission: iroha_config::parameters::actual::SoracloudRuntimeSubmission {
            fee_payer: iroha_config::parameters::actual::SoracloudRuntimeFeePayer::Authority,
            signer: Some(
                iroha_config::parameters::actual::SoracloudRuntimeMutationSignerBinding {
                    handle: "provider://soracloud/runtime-primary".to_owned(),
                    authority: AccountId::new(ALICE_KEYPAIR.public_key().clone()),
                    algorithm: iroha_crypto::Algorithm::Ed25519,
                    public_key: ALICE_KEYPAIR.public_key().clone(),
                    revision: 7,
                    policy_digest: [0xA7; 32],
                },
            ),
        },
        egress: iroha_config::parameters::actual::SoracloudRuntimeEgress {
            default_allow: false,
            allowed_hosts: vec!["cdn.sora.test".to_string()],
            rate_per_minute: std::num::NonZeroU32::new(120),
            max_bytes_per_minute: std::num::NonZeroU64::new(262_144),
        },
    };
    let manager = SoracloudRuntimeManagerConfig::from_runtime_config(&runtime);
    assert_eq!(manager.state_dir, runtime.state_dir);
    assert_eq!(manager.production_mode, runtime.production_mode);
    assert_eq!(manager.reconcile_interval, runtime.reconcile_interval);
    assert_eq!(manager.hydration_concurrency, runtime.hydration_concurrency);
    assert_eq!(
        manager.prepared_runtime_cache_capacity,
        runtime.prepared_runtime_cache_capacity
    );
    assert_eq!(manager.cache_budgets, runtime.cache_budgets);
    assert_eq!(manager.inrou, runtime.inrou);
    assert_eq!(manager.submission, runtime.submission);
    assert_eq!(manager.egress, runtime.egress);
}
#[test]
#[should_panic(expected = "egress.default_allow = false")]
fn manager_config_rejects_unsafe_direct_actual_production_posture() {
    let mut runtime = iroha_config::parameters::actual::SoracloudRuntime {
        production_mode: true,
        ..Default::default()
    };
    runtime.egress.default_allow = true;
    runtime.egress.rate_per_minute = std::num::NonZeroU32::new(60);
    runtime.egress.max_bytes_per_minute = std::num::NonZeroU64::new(1_048_576);
    let _ = SoracloudRuntimeManagerConfig::from_runtime_config(&runtime);
}
#[test]
#[should_panic(
    expected = "soracloud_runtime.hydration_concurrency exceeds the first-release worker limit"
)]
fn manager_config_rejects_direct_actual_hydration_workers_above_v1_limit() {
    let runtime = iroha_config::parameters::actual::SoracloudRuntime {
        hydration_concurrency: NonZeroUsize::new(
            iroha_config::parameters::defaults::soracloud_runtime::HYDRATION_CONCURRENCY_MAX + 1,
        )
        .expect("V1 hydration limit plus one is nonzero"),
        ..Default::default()
    };
    let _ = SoracloudRuntimeManagerConfig::from_runtime_config(&runtime);
}
#[test]
#[should_panic(
    expected = "soracloud_runtime.prepared_runtime_cache_capacity exceeds the first-release idle-runtime limit"
)]
fn manager_config_rejects_direct_actual_prepared_cache_above_v1_limit() {
    let runtime = iroha_config::parameters::actual::SoracloudRuntime { prepared_runtime_cache_capacity: NonZeroUsize::new(
        iroha_config::parameters::defaults::soracloud_runtime::PREPARED_RUNTIME_CACHE_CAPACITY_MAX
            + 1,
    )
    .expect("V1 prepared-runtime cache limit plus one is nonzero"), ..Default::default() };
    let _ = SoracloudRuntimeManagerConfig::from_runtime_config(&runtime);
}
#[test]
#[should_panic(expected = "inrou.enabled requires soracloud_runtime.production_mode = true")]
fn manager_config_rejects_nonproduction_direct_actual_portable_vm_v1() {
    let mut runtime = iroha_config::parameters::actual::SoracloudRuntime {
        production_mode: false,
        ..Default::default()
    };
    runtime.inrou.enabled = true;
    runtime.inrou.portable_vm_uid = std::num::NonZeroU32::new(70_000);
    runtime.inrou.portable_vm_gid = std::num::NonZeroU32::new(70_000);
    runtime.inrou.trusted_guest_artifact = Some(sample_published_inrou_guest_image_artifact(0x41));
    let _ = SoracloudRuntimeManagerConfig::from_runtime_config(&runtime);
}
#[test]
fn programmatic_manager_rejects_out_of_range_inrou_lifecycle_grace() {
    let runtime = iroha_config::parameters::actual::SoracloudRuntime::default();
    let config = SoracloudRuntimeManagerConfig::from_runtime_config(&runtime);
    assert_eq!(
        iroha_config::parameters::defaults::soracloud_runtime::INROU_LIFECYCLE_GRACE_MAX_MS,
        u64::from(iroha_data_model::soracloud::SORA_INROU_LIFECYCLE_GRACE_MAX_SECS_V1) * 1_000,
        "the operator and signed-workload Inrou V1 ceilings must remain identical"
    );

    let mut below_minimum = config.clone();
    below_minimum.inrou.start_grace = Duration::from_millis(99);
    let error = validate_soracloud_runtime_manager_posture(&below_minimum)
        .expect_err("a sub-minimum operator startup grace must fail closed");
    assert!(error.to_string().contains("start_grace must be between"));

    let mut above_maximum = config;
    above_maximum.inrou.stop_grace = Duration::from_millis(600_001);
    let error = validate_soracloud_runtime_manager_posture(&above_maximum)
        .expect_err("an above-maximum operator shutdown grace must fail closed");
    assert!(error.to_string().contains("stop_grace must be between"));
}
#[test]
fn programmatic_manager_rejects_worker_and_cache_limits_above_v1_maximum() {
    let runtime = iroha_config::parameters::actual::SoracloudRuntime::default();
    let config = SoracloudRuntimeManagerConfig::from_runtime_config(&runtime);

    let mut hydration = config.clone();
    hydration.hydration_concurrency = NonZeroUsize::new(
        iroha_config::parameters::defaults::soracloud_runtime::HYDRATION_CONCURRENCY_MAX + 1,
    )
    .expect("V1 hydration limit plus one is nonzero");
    let error = validate_soracloud_runtime_manager_posture(&hydration)
        .expect_err("programmatic hydration workers must respect the V1 ceiling");
    assert!(error.to_string().contains("hydration worker count"));

    let mut prepared = config;
    prepared.prepared_runtime_cache_capacity = NonZeroUsize::new(
        iroha_config::parameters::defaults::soracloud_runtime::PREPARED_RUNTIME_CACHE_CAPACITY_MAX
            + 1,
    )
    .expect("V1 prepared-runtime cache limit plus one is nonzero");
    let error = validate_soracloud_runtime_manager_posture(&prepared)
        .expect_err("programmatic prepared-runtime caching must respect the V1 ceiling");
    assert!(
        error
            .to_string()
            .contains("prepared-runtime cache capacity")
    );
}
#[test]
fn programmatic_manager_rejects_nonproduction_inrou_before_writes() {
    let runtime = iroha_config::parameters::actual::SoracloudRuntime::default();
    let mut config = SoracloudRuntimeManagerConfig::from_runtime_config(&runtime);
    let temp_dir = canonical_runtime_fixture_tempdir().expect("temporary posture directory");
    config.state_dir = temp_dir.path().join("must-not-materialize");
    config.production_mode = false;
    config.inrou.enabled = true;
    config.inrou.portable_vm_uid = std::num::NonZeroU32::new(70_000);
    config.inrou.portable_vm_gid = std::num::NonZeroU32::new(70_000);
    config.inrou.trusted_guest_artifact = Some(sample_published_inrou_guest_image_artifact(0x41));

    let error = validate_soracloud_runtime_manager_posture(&config)
        .expect_err("programmatic config must not bypass production posture");
    assert!(error.to_string().contains("production_mode = true"));
    let error = InrouStartupCapabilitySnapshot::qualify(&config)
        .expect_err("startup qualification must reject posture before live host effects");
    assert!(error.to_string().contains("production_mode = true"));

    let manager = SoracloudRuntimeManager::new(config, test_state());
    let error = manager
        .reconcile_once()
        .expect_err("reconcile must enforce PortableVM V1 posture before writes");
    assert!(error.to_string().contains("PortableVM V1 posture"));
    assert!(!temp_dir.path().join("must-not-materialize").exists());
}
#[test]
fn programmatic_manager_rejects_incomplete_production_posture() {
    let temp_dir = canonical_runtime_fixture_tempdir().expect("temporary posture directory");
    let canonical = test_runtime_manager_config(temp_dir.path().to_path_buf());

    let mut open_egress = canonical.clone();
    open_egress.egress.default_allow = true;
    assert!(
        validate_soracloud_runtime_manager_posture(&open_egress)
            .expect_err("production egress must default closed")
            .to_string()
            .contains("fail-closed default egress")
    );

    let mut unbounded_egress = canonical.clone();
    unbounded_egress.egress.rate_per_minute = None;
    assert!(
        validate_soracloud_runtime_manager_posture(&unbounded_egress)
            .expect_err("production egress must have explicit finite limits")
            .to_string()
            .contains("request-rate and byte-rate")
    );

    let mut unsigned = canonical;
    unsigned.submission.signer = None;
    assert!(
        validate_soracloud_runtime_manager_posture(&unsigned)
            .expect_err("production runtime mutations must bind a signer")
            .to_string()
            .contains("mutation-signer binding")
    );
}
#[test]
#[should_panic(expected = "bundle_archive_max_compressed_bytes exceeds its hard ceiling")]
fn manager_config_rejects_direct_actual_archive_limit_above_hard_ceiling() {
    let mut runtime = iroha_config::parameters::actual::SoracloudRuntime {
        production_mode: true,
        ..Default::default()
    };
    runtime.inrou.bundle_archive_max_compressed_bytes = std::num::NonZeroU64::new(
        iroha_config::parameters::defaults::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_COMPRESSED_BYTES_LIMIT
            + 1,
    )
    .expect("hard ceiling plus one is nonzero");
    let _ = SoracloudRuntimeManagerConfig::from_runtime_config(&runtime);
}
#[test]
fn programmatic_inrou_guest_image_limit_is_inclusive_at_its_hard_ceiling() {
    let hard_ceiling =
        iroha_config::parameters::defaults::soracloud_runtime::INROU_GUEST_IMAGE_MAX_BYTES_LIMIT;
    let mut config = iroha_config::parameters::actual::SoracloudRuntimeInrou {
        guest_image_max_bytes: NonZeroU64::new(hard_ceiling)
            .expect("guest-image hard ceiling is nonzero"),
        ..Default::default()
    };
    validate_inrou_portable_vm_v1_config(&config)
        .expect("the exact guest-image hard ceiling must remain admissible");

    config.guest_image_max_bytes = NonZeroU64::new(
        hard_ceiling
            .checked_add(1)
            .expect("guest-image hard ceiling has room for the rejection boundary"),
    )
    .expect("hard ceiling plus one is nonzero");
    assert_report_contains(
        &validate_inrou_portable_vm_v1_config(&config)
            .expect_err("one byte above the guest-image hard ceiling must fail"),
        "guest_image_max_bytes exceeds its",
    );
}
#[test]
fn inrou_archive_protocol_ceilings_match_config_hard_ceilings() {
    use iroha_config::parameters::defaults::soracloud_runtime as config_limits;
    use sorafs_car::bundle_archive::{
        BUNDLE_ARCHIVE_PROTOCOL_MAX_COMPRESSED_BYTES, BUNDLE_ARCHIVE_PROTOCOL_MAX_DECODED_BYTES,
        BUNDLE_ARCHIVE_PROTOCOL_MAX_ENTRIES, BUNDLE_ARCHIVE_PROTOCOL_MAX_FILE_BYTES,
        BUNDLE_ARCHIVE_PROTOCOL_MAX_TOTAL_FILE_BYTES,
    };
    assert_eq!(
        config_limits::INROU_BUNDLE_ARCHIVE_MAX_COMPRESSED_BYTES_LIMIT,
        BUNDLE_ARCHIVE_PROTOCOL_MAX_COMPRESSED_BYTES
    );
    assert_eq!(
        config_limits::INROU_BUNDLE_ARCHIVE_MAX_DECODED_BYTES_LIMIT,
        BUNDLE_ARCHIVE_PROTOCOL_MAX_DECODED_BYTES
    );
    assert_eq!(
        config_limits::INROU_BUNDLE_ARCHIVE_MAX_ENTRIES_LIMIT,
        BUNDLE_ARCHIVE_PROTOCOL_MAX_ENTRIES
    );
    assert_eq!(
        config_limits::INROU_BUNDLE_ARCHIVE_MAX_FILE_BYTES_LIMIT,
        BUNDLE_ARCHIVE_PROTOCOL_MAX_FILE_BYTES
    );
    assert_eq!(
        config_limits::INROU_BUNDLE_ARCHIVE_MAX_TOTAL_FILE_BYTES_LIMIT,
        BUNDLE_ARCHIVE_PROTOCOL_MAX_TOTAL_FILE_BYTES
    );
}
#[test]
fn current_host_inrou_guest_isa_never_aliases_unsupported_hardware() {
    let actual = current_host_inrou_guest_isa();
    #[cfg(target_arch = "x86_64")]
    assert_eq!(actual, Some(SoraInrouGuestIsaV1::X8664));
    #[cfg(target_arch = "aarch64")]
    assert_eq!(actual, Some(SoraInrouGuestIsaV1::Aarch64));
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    assert_eq!(actual, None);
}
#[test]
fn inrou_v1_hosted_capacity_is_an_unconditional_runtime_fact() {
    assert_eq!(SORA_INROU_HOSTED_REPLICA_CAPACITY_V1, 1);
}
#[test]
fn inrou_startup_probe_uses_production_machine_shape_without_guest_artifact() {
    let netdev = "user,id=net0,ipv6=off,restrict=on,hostfwd=tcp:127.0.0.1:32000-:9";
    for (guest_isa, machine) in [
        (SoraInrouGuestIsaV1::X8664, "q35"),
        (SoraInrouGuestIsaV1::Aarch64, "virt"),
    ] {
        let mut command = Command::new("qemu-system-test");
        let probe = iroha_config::parameters::inrou_startup_probe::InrouStartupProbeShapeV1::from_host_envelope(1_000, 768 * 1024 * 1024).unwrap();
        append_inrou_startup_probe_qemu_args(&mut command, guest_isa, netdev, probe);
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            arguments,
            vec![
                "-object".to_owned(),
                "memory-backend-ram,id=vmmem,size=512M,share=on".to_owned(),
                "-machine".to_owned(),
                format!("{machine},accel=kvm,memory-backend=vmmem"),
                "-cpu".to_owned(),
                "host".to_owned(),
                "-smp".to_owned(),
                "1".to_owned(),
                "-S".to_owned(),
                "-nodefaults".to_owned(),
                "-display".to_owned(),
                "none".to_owned(),
                "-monitor".to_owned(),
                "none".to_owned(),
                "-netdev".to_owned(),
                netdev.to_owned(),
            ]
        );
        for forbidden in ["-kernel", "-initrd", "-drive", "-device", "-bios"] {
            assert!(!arguments.iter().any(|argument| argument == forbidden));
        }
    }
}
#[cfg(target_os = "linux")]
#[test]
fn inrou_stock_self_exec_custody_predicate_is_exact() {
    for target in ["/usr/bin/iroha3d", "/usr/bin/iroha3d_taira"] {
        assert!(inrou_stock_self_executable_custody_is_admitted(
            Path::new(target),
            true,
            0,
            1,
            0o100_755,
        ));
    }

    for (target, is_regular_file, owner_uid, link_count, mode) in [
        ("iroha3d", true, 0, 1, 0o100_755),
        ("/usr/bin/iroha3", true, 0, 1, 0o100_755),
        ("/usr/bin/iroha3d", false, 0, 1, 0o120_777),
        ("/usr/bin/iroha3d", true, 1, 1, 0o100_755),
        ("/usr/bin/iroha3d", true, 0, 0, 0o100_755),
        ("/usr/bin/iroha3d", true, 0, 2, 0o100_755),
        ("/usr/bin/iroha3d", true, 0, 1, 0o100_600),
        ("/usr/bin/iroha3d", true, 0, 1, 0o100_775),
        ("/usr/bin/iroha3d", true, 0, 1, 0o100_757),
    ] {
        assert!(!inrou_stock_self_executable_custody_is_admitted(
            Path::new(target),
            is_regular_file,
            owner_uid,
            link_count,
            mode,
        ));
    }
}
#[cfg(target_os = "linux")]
#[test]
fn inrou_external_test_wrapper_cannot_arm_stock_self_exec() {
    assert!(!inrou_stock_self_executable_is_admitted());
    assert!(require_inrou_self_exec_dispatch_armed().is_err());
}
#[cfg(target_os = "linux")]
#[test]
fn inrou_launcher_duplicates_retained_sources_above_stdio_without_fixed_targets() -> Result<()> {
    let source = fs::File::open("/dev/null")?;
    let mut minimum = 3;
    let first = duplicate_inrou_launcher_descriptor(&source, &mut minimum)?;
    let second = duplicate_inrou_launcher_descriptor(&source, &mut minimum)?;
    assert!(first.as_raw_fd() > 2);
    assert!(second.as_raw_fd() > first.as_raw_fd());
    assert_eq!(minimum, second.as_raw_fd() + 1);
    assert_eq!(
        rustix::io::fcntl_getfd(&first)?,
        rustix::io::FdFlags::CLOEXEC
    );
    assert_eq!(
        rustix::io::fcntl_getfd(&second)?,
        rustix::io::FdFlags::CLOEXEC
    );
    Ok(())
}
#[cfg(target_os = "linux")]
#[test]
#[allow(unsafe_code)]
fn inrou_launcher_normalizes_a_source_opened_on_closed_stdio() -> Result<()> {
    use std::os::fd::IntoRawFd as _;

    const CHILD_MODE: &str = "IROHA_INROU_CLOSED_STDIO_CHILD_V1";
    if std::env::var_os(CHILD_MODE).as_deref() == Some(OsStr::new("1")) {
        // SAFETY: this branch runs only in the dedicated subprocess below.
        // It deliberately retires that process's inherited stdio before
        // recreating it from /dev/null; no owning Rust descriptor exists.
        unsafe {
            rustix::io::close(0);
            rustix::io::close(1);
            rustix::io::close(2);
        }
        let source = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")?;
        eyre::ensure!(source.as_raw_fd() == 0, "closed stdin was not reused");
        let stdout = rustix::io::fcntl_dupfd_cloexec(&source, 1)?;
        let stderr = rustix::io::fcntl_dupfd_cloexec(&source, 2)?;
        eyre::ensure!(stdout.as_raw_fd() == 1 && stderr.as_raw_fd() == 2);

        let mut minimum = 3;
        let retained = duplicate_inrou_launcher_descriptor(&source, &mut minimum)?;
        eyre::ensure!(retained.as_raw_fd() >= 3);
        let _ = source.into_raw_fd();
        let _ = stdout.into_raw_fd();
        let _ = stderr.into_raw_fd();
        return Ok(());
    }

    let status = Command::new(std::env::current_exe()?)
        .arg("inrou_launcher_normalizes_a_source_opened_on_closed_stdio")
        .env(CHILD_MODE, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    assert!(status.success(), "closed-stdio launcher subprocess failed");
    Ok(())
}
#[test]
fn inrou_startup_probe_uses_the_configured_ceiling_including_vmm_overhead() {
    let mut config = iroha_config::parameters::actual::SoracloudRuntimeInrou {
        max_cpu_millis: std::num::NonZeroU32::new(1_000).unwrap(),
        max_memory_bytes: std::num::NonZeroU64::new(768 * 1024 * 1024).unwrap(),
        ..Default::default()
    };
    let probe = inrou_startup_probe_shape(&config).unwrap();
    assert_eq!(
        probe.resources().checked_inrou_host_cpu_millis(),
        Some(1_000)
    );
    assert_eq!(
        probe.resources().checked_inrou_host_memory_bytes(),
        Some(768 * 1024 * 1024)
    );
    assert_eq!(probe.vcpus(), 1);
    assert_eq!(probe.memory_mib(), 512);
    config.max_cpu_millis = std::num::NonZeroU32::new(250).unwrap();
    assert!(inrou_startup_probe_shape(&config).is_err());
}
#[test]
fn inrou_vcpu_mapping_rejects_instead_of_clamping_above_v1() -> Result<()> {
    let config = iroha_config::parameters::actual::SoracloudRuntimeInrou::default();
    let baseline = inrou_startup_probe_shape(&config)?.resources();
    for (cpu_millis, expected_vcpus) in [(10, 1), (1_000, 1), (1_010, 2), (4_000, 4)] {
        let resources = SoraResourceLimitsV1 {
            cpu_millis: std::num::NonZeroU32::new(cpu_millis).expect("nonzero CPU"),
            ..baseline
        };
        assert_eq!(portable_vm_vcpu_count(&resources)?, expected_vcpus);
    }
    let above_v1 = SoraResourceLimitsV1 {
        cpu_millis: std::num::NonZeroU32::new(4_010).expect("nonzero CPU"),
        ..baseline
    };
    let _ = portable_vm_vcpu_count(&above_v1)
        .expect_err("Inrou V1 CPU values above the qualified boundary must fail closed");
    Ok(())
}
#[test]
fn inrou_qmp_kvm_attestation_requires_one_exact_enabled_record() -> Result<()> {
    validate_inrou_qmp_kvm_info(&norito::json!({
        "enabled": true,
        "present": true,
    }))?;
    for rejected in [
        norito::json!({"enabled": false, "present": true}),
        norito::json!({"enabled": true, "present": false}),
        norito::json!({"enabled": true}),
        norito::json!({"enabled": true, "present": true, "fallback": "tcg"}),
        norito::json!([true, true]),
    ] {
        let _ = validate_inrou_qmp_kvm_info(&rejected)
            .expect_err("non-exact KVM status must fail qualification");
    }
    Ok(())
}
#[test]
fn enabled_inrou_portable_vm_config_requires_one_canonical_identity_slot() -> Result<()> {
    let mut config = iroha_config::parameters::actual::SoracloudRuntimeInrou {
        enabled: true,
        portable_vm_uid: std::num::NonZeroU32::new(70_000),
        portable_vm_gid: std::num::NonZeroU32::new(70_000),
        trusted_guest_artifact: Some(sample_published_inrou_guest_image_artifact(0x41)),
        ..Default::default()
    };

    validate_inrou_portable_vm_v1_config(&config)?;
    config.portable_vm_gid = std::num::NonZeroU32::new(70_001);
    let _ = validate_inrou_portable_vm_v1_config(&config)
        .expect_err("PortableVM uid/gid must select the same canonical slot");
    Ok(())
}
#[test]
fn disabled_inrou_config_rejects_stale_identity() {
    let config = iroha_config::parameters::actual::SoracloudRuntimeInrou {
        portable_vm_uid: std::num::NonZeroU32::new(70_000),
        ..Default::default()
    };
    let error = validate_inrou_portable_vm_v1_config(&config)
        .expect_err("disabled Inrou must not retain an identity");
    assert!(
        error
            .to_string()
            .contains("must not retain a PortableVM identity")
    );
}
#[test]
fn inrou_archive_limits_use_the_tighter_bundle_cache_bound() {
    let config = iroha_config::parameters::actual::SoracloudRuntimeInrou {
        bundle_archive_max_compressed_bytes: std::num::NonZeroU64::new(8_192)
            .expect("nonzero archive bound"),
        ..Default::default()
    };
    assert_eq!(
        inrou_bundle_archive_limits(&config, 4_096).max_compressed_bytes,
        4_096
    );
    assert_eq!(
        inrou_bundle_archive_limits(&config, 16_384).max_compressed_bytes,
        8_192
    );
}
#[test]
fn hosted_http_concurrency_limit_uses_single_portable_vm_budget() {
    let config = test_runtime_manager_config(PathBuf::from("/tmp/test-soracloud-runtime-limit"));
    let manager = inrou_capability_unit_test_manager(config, test_state());
    assert_eq!(manager.hosted_http_concurrency_limit(), 1);
}
#[test]
fn inrou_startup_qualification_rejects_configuration_drift() {
    let mut config =
        test_runtime_manager_config(PathBuf::from("/tmp/test-soracloud-runtime-prequalified"));
    config.production_mode = false;
    config.inrou = iroha_config::parameters::actual::SoracloudRuntimeInrou::default();
    let mut manager = SoracloudRuntimeManager::new(config.clone(), test_state())
        .preflight_startup()
        .expect("disabled Inrou needs no host launcher");
    manager
        .qualify_inrou_startup_capability()
        .expect("the same configuration retains its qualification");
    manager.config.state_dir.push("changed-after-qualification");
    let error = manager
        .qualify_inrou_startup_capability()
        .expect_err("an earlier qualification cannot authorize changed configuration");
    assert!(
        error
            .to_string()
            .contains("changed after startup qualification")
    );
    assert_eq!(manager.inrou_startup_qualified_config, Some(config));
}
#[test]
fn inrou_startup_qualification_failure_never_publishes_a_qualification() {
    let mut config = test_runtime_manager_config(PathBuf::from(
        "/tmp/test-soracloud-runtime-preflight-failure",
    ));
    config.production_mode = true;
    config.egress.default_allow = true;
    let mut manager = SoracloudRuntimeManager::new(config, test_state());
    assert!(manager.qualify_inrou_startup_capability().is_err());
    assert!(manager.inrou_startup_qualified_config.is_none());
    assert!(manager.inrou_startup_capability.is_none());
}
#[test]
fn inrou_capability_activates_only_after_exact_host_preflight() {
    let config = test_runtime_manager_config(PathBuf::from(
        "/tmp/test-soracloud-runtime-capability-preflight",
    ))
    .with_local_host_identity(ALICE_ID.clone(), "12D3KooWRuntimeHostPreflight");
    let mut manager = SoracloudRuntimeManager::new(config, test_state());
    assert!(manager.inrou_startup_capability.is_none());
    match manager.qualify_inrou_startup_capability() {
        Ok(()) => assert!(manager.inrou_startup_capability.is_some()),
        Err(_) => assert!(manager.inrou_startup_capability.is_none()),
    }
}
#[test]
fn inrou_host_advertises_canonical_v1_capacity() {
    let mut config =
        test_runtime_manager_config(PathBuf::from("/tmp/test-soracloud-runtime-capacity"));
    config.inrou.max_cpu_millis = std::num::NonZeroU32::new(7_000).expect("CPU budget");
    config.inrou.max_memory_bytes =
        std::num::NonZeroU64::new(14 * 1024 * 1024 * 1024).expect("memory budget");
    config.inrou.max_storage_bytes =
        std::num::NonZeroU64::new(70 * 1024 * 1024 * 1024).expect("storage budget");
    config = config.with_local_host_identity(ALICE_ID.clone(), "12D3KooWRuntimeHostAdvertCapacity");
    let manager = inrou_capability_unit_test_manager(config, test_state());
    assert_eq!(manager.hosted_http_concurrency_limit(), 1);
    let capability = manager
        .build_local_inrou_host_capability_record(123)
        .expect("host identity configured");
    assert_eq!(capability.max_hosted_replica_capacity, 1);
    assert_eq!(capability.max_cpu_millis, 7_000);
    assert_eq!(capability.max_memory_bytes, 14 * 1024 * 1024 * 1024);
    assert_eq!(capability.max_storage_bytes, 70 * 1024 * 1024 * 1024);
}
#[test]
fn disabled_inrou_host_does_not_advertise_or_host() {
    let mut config =
        test_runtime_manager_config(PathBuf::from("/tmp/test-soracloud-runtime-disabled"));
    config.inrou.enabled = false;
    config.inrou.portable_vm_uid = None;
    config.inrou.portable_vm_gid = None;
    config.inrou.trusted_guest_artifact = None;
    config = config.with_local_host_identity(ALICE_ID.clone(), "12D3KooWDisabledRuntimeHostAdvert");
    let state = test_state();
    let manager = SoracloudRuntimeManager::new(config, Arc::clone(&state));
    assert_eq!(manager.hosted_http_concurrency_limit(), 0);
    assert!(
        manager
            .build_local_inrou_host_capability_record(123)
            .is_none()
    );
    let view = state.view();
    assert!(
        manager
            .local_inrou_host_capability_refresh_candidate(&view)
            .is_none()
    );
}
#[test]
fn inrou_host_heartbeat_ttl_tolerates_public_taira_queue_lag() {
    let config = test_runtime_manager_config(PathBuf::from(
        "/tmp/test-soracloud-runtime-inrou-heartbeat-ttl",
    ));
    let now_ms = 1_000;
    assert_eq!(
        desired_inrou_host_heartbeat_expiry_ms(now_ms, &config),
        now_ms + INROU_HOST_HEARTBEAT_TTL_FLOOR_MS
    );
}
#[test]
fn inrou_host_capability_refresh_waits_until_heartbeat_margin() {
    let config = test_runtime_manager_config(PathBuf::from(
        "/tmp/test-soracloud-runtime-inrou-refresh-margin",
    ))
    .with_local_host_identity(ALICE_ID.clone(), "12D3KooWInrouRefreshMarginHost");
    let manager = inrou_capability_unit_test_manager(config.clone(), test_state());
    let now_ms = 1_000_000;
    let desired = manager
        .build_local_inrou_host_capability_record(now_ms)
        .expect("host identity configured");
    let ttl_ms = inrou_host_heartbeat_ttl_ms(&config);
    let margin_ms = inrou_host_heartbeat_refresh_margin_ms(&config);
    assert!(ttl_ms > margin_ms.saturating_add(5_000));
    let mut existing = desired.clone();
    existing.advertised_at_ms = now_ms.saturating_sub(5_000);
    existing.heartbeat_expires_at_ms = desired.heartbeat_expires_at_ms.saturating_sub(5_000);
    assert!(existing.heartbeat_expires_at_ms < desired.heartbeat_expires_at_ms);
    assert!(!inrou_host_capability_refresh_needed(
        Some(&existing),
        &desired,
        now_ms,
        &config
    ));
    existing.heartbeat_expires_at_ms = now_ms.saturating_add(margin_ms);
    assert!(inrou_host_capability_refresh_needed(
        Some(&existing),
        &desired,
        now_ms,
        &config
    ));
    existing.heartbeat_expires_at_ms = now_ms.saturating_add(ttl_ms);
    existing.supported_guest_isas.clear();
    assert!(inrou_host_capability_refresh_needed(
        Some(&existing),
        &desired,
        now_ms,
        &config
    ));
}
#[test]
fn inrou_host_capability_refresh_candidate_respects_authoritative_state() {
    let mut state = test_state();
    let config = test_runtime_manager_config(PathBuf::from(
        "/tmp/test-soracloud-runtime-host-refresh-candidate",
    ))
    .with_local_host_identity(ALICE_ID.clone(), "12D3KooWRuntimeHostRefreshCandidate");
    let mut capability = {
        let manager = inrou_capability_unit_test_manager(config.clone(), Arc::clone(&state));
        manager
            .build_local_inrou_host_capability_record(123)
            .expect("host identity configured")
    };
    capability.heartbeat_expires_at_ms = u64::MAX;
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        world
            .soracloud_inrou_host_capabilities_mut_for_testing()
            .insert(ALICE_ID.clone(), capability);
    }
    let manager = inrou_capability_unit_test_manager(config, Arc::clone(&state));
    *manager.pending_inrou_host_capability_advert.lock() = Some(
        manager
            .build_local_inrou_host_capability_record(456)
            .expect("host identity configured"),
    );
    let view = state.view();
    assert!(
        manager
            .local_inrou_host_capability_refresh_candidate(&view)
            .is_none()
    );
    assert!(
        manager
            .pending_inrou_host_capability_advert
            .lock()
            .is_none()
    );
}
#[test]
fn refresh_local_inrou_host_capability_submits_candidate() {
    let config =
        test_runtime_manager_config(PathBuf::from("/tmp/test-soracloud-runtime-host-refresh"));
    let config =
        config.with_local_host_identity(ALICE_ID.clone(), "12D3KooWRuntimeHostRefreshSubmit");
    let state = test_state();
    let mutation_sink = Arc::new(RecordingRuntimeMutationSink::default());
    let manager = inrou_capability_unit_test_manager(config, Arc::clone(&state));
    let manager = manager.with_mutation_sink(mutation_sink.clone());
    let candidate = {
        let view = state.view();
        manager.local_inrou_host_capability_refresh_candidate(&view)
    };
    manager.refresh_local_inrou_host_capability_if_needed(candidate);
    let capabilities = mutation_sink.submitted_inrou_host_capabilities();
    assert_eq!(capabilities.len(), 1);
    assert_eq!(capabilities[0].capability.max_hosted_replica_capacity, 1);
}
#[test]
fn refresh_local_inrou_host_capability_suppresses_pending_duplicate() {
    let config = test_runtime_manager_config(PathBuf::from(
        "/tmp/test-soracloud-runtime-host-refresh-pending-duplicate",
    ));
    let config =
        config.with_local_host_identity(ALICE_ID.clone(), "12D3KooWRuntimeHostRefreshPending");
    let state = test_state();
    let mutation_sink = Arc::new(RecordingRuntimeMutationSink::default());
    let manager = inrou_capability_unit_test_manager(config, Arc::clone(&state));
    let manager = manager.with_mutation_sink(mutation_sink.clone());
    let first_candidate = {
        let view = state.view();
        manager.local_inrou_host_capability_refresh_candidate(&view)
    };
    manager.refresh_local_inrou_host_capability_if_needed(first_candidate);
    let first_capability = mutation_sink.submitted_inrou_host_capabilities()[0]
        .capability
        .clone();
    *manager.last_inrou_host_advert_attempt_ms.lock() = Some(
        soracloud_runtime_observed_at_ms()
            .saturating_sub(INROU_HOST_ADVERT_ATTEMPT_COOLDOWN_MS + 1),
    );
    let second_candidate = manager
        .build_local_inrou_host_capability_record(
            first_capability
                .advertised_at_ms
                .saturating_add(INROU_HOST_ADVERT_ATTEMPT_COOLDOWN_MS + 1),
        )
        .expect("host identity configured");
    assert_ne!(
        first_capability.heartbeat_expires_at_ms,
        second_candidate.heartbeat_expires_at_ms
    );
    manager.refresh_local_inrou_host_capability_if_needed(Some(second_candidate));
    assert_eq!(mutation_sink.submitted_inrou_host_capabilities().len(), 1);
}
#[test]
fn refresh_local_inrou_host_capability_allows_pending_refresh_near_expiry() {
    let config = test_runtime_manager_config(PathBuf::from(
        "/tmp/test-soracloud-runtime-host-refresh-pending-expiry",
    ));
    let config =
        config.with_local_host_identity(ALICE_ID.clone(), "12D3KooWRuntimeHostRefreshExpiry");
    let state = test_state();
    let mutation_sink = Arc::new(RecordingRuntimeMutationSink::default());
    let manager = inrou_capability_unit_test_manager(config.clone(), Arc::clone(&state));
    let manager = manager.with_mutation_sink(mutation_sink.clone());
    let now_ms = soracloud_runtime_observed_at_ms();
    let mut pending_capability = manager
        .build_local_inrou_host_capability_record(now_ms)
        .expect("host identity configured");
    pending_capability.heartbeat_expires_at_ms =
        now_ms.saturating_add(inrou_host_heartbeat_refresh_margin_ms(&config));
    *manager.pending_inrou_host_capability_advert.lock() = Some(pending_capability);
    *manager.last_inrou_host_advert_attempt_ms.lock() =
        Some(now_ms.saturating_sub(INROU_HOST_ADVERT_ATTEMPT_COOLDOWN_MS + 1));
    let candidate = manager
        .build_local_inrou_host_capability_record(now_ms)
        .expect("host identity configured");
    manager.refresh_local_inrou_host_capability_if_needed(Some(candidate));
    assert_eq!(mutation_sink.submitted_inrou_host_capabilities().len(), 1);
}
#[test]
fn inrou_placement_reconcile_request_obeys_needed_flag_and_cooldown() {
    let config = test_runtime_manager_config(PathBuf::from(
        "/tmp/test-soracloud-runtime-placement-reconcile",
    ));
    let state = test_state();
    let mutation_sink = Arc::new(RecordingRuntimeMutationSink::default());
    let manager =
        SoracloudRuntimeManager::new(config, state).with_mutation_sink(mutation_sink.clone());
    manager.request_inrou_placement_reconcile_if_needed(false);
    assert_eq!(mutation_sink.submitted_inrou_placement_reconciles(), 0);
    manager.request_inrou_placement_reconcile_if_needed(true);
    manager.request_inrou_placement_reconcile_if_needed(true);
    assert_eq!(mutation_sink.submitted_inrou_placement_reconciles(), 1);
}
#[test]
fn unavailable_inrou_host_withdrawal_requests_placement_reconcile() {
    let mut state = test_state();
    let config =
        test_runtime_manager_config(PathBuf::from("/tmp/test-soracloud-runtime-host-withdraw"))
            .with_local_host_identity(ALICE_ID.clone(), "12D3KooWRuntimeHostWithdraw");
    let capability = {
        let manager = inrou_capability_unit_test_manager(config.clone(), Arc::clone(&state));
        manager
            .build_local_inrou_host_capability_record(123)
            .expect("host identity configured")
    };
    Arc::get_mut(&mut state)
        .expect("unique test state")
        .world
        .soracloud_inrou_host_capabilities_mut_for_testing()
        .insert(ALICE_ID.clone(), capability);
    let mutation_sink = Arc::new(RecordingRuntimeMutationSink::default());
    let manager = inrou_capability_unit_test_manager(config, Arc::clone(&state))
        .with_mutation_sink(mutation_sink.clone());
    let view = state.view();
    manager.withdraw_local_inrou_host_if_needed(&view);
    assert_eq!(mutation_sink.submitted_inrou_host_withdrawals(), 1);
    assert_eq!(mutation_sink.submitted_inrou_placement_reconciles(), 1);
}
#[test]
fn disabled_inrou_reconcile_withdraws_existing_local_host_advert() -> Result<()> {
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let mut state = test_state();
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let enabled_config = test_runtime_manager_config(state_dir)
        .with_local_host_identity(ALICE_ID.clone(), "12D3KooWDisabledHostWithdraw");
    let capability = {
        let enabled_manager =
            inrou_capability_unit_test_manager(enabled_config.clone(), Arc::clone(&state));
        enabled_manager
            .build_local_inrou_host_capability_record(123)
            .expect("enabled fixture has a qualified local Inrou host capability")
    };
    Arc::get_mut(&mut state)
        .expect("unique test state")
        .world
        .soracloud_inrou_host_capabilities_mut_for_testing()
        .insert(ALICE_ID.clone(), capability);

    let mut disabled_config = enabled_config;
    disabled_config.inrou.enabled = false;
    disabled_config.inrou.portable_vm_uid = None;
    disabled_config.inrou.portable_vm_gid = None;
    disabled_config.inrou.trusted_guest_artifact = None;
    let mutation_sink = Arc::new(RecordingRuntimeMutationSink::default());
    let manager = SoracloudRuntimeManager::new(disabled_config, Arc::clone(&state))
        .with_mutation_sink(mutation_sink.clone());
    manager.reconcile_once()?;

    assert_eq!(mutation_sink.submitted_inrou_host_withdrawals(), 1);
    assert_eq!(mutation_sink.submitted_inrou_placement_reconciles(), 1);
    Ok(())
}
#[test]
fn reconcile_once_persists_active_service_and_apartment_materializations() -> Result<()> {
    let mut state = test_state();
    let mut bundle = load_deployment_bundle_fixture()?;
    bundle.container.required_config_names = vec!["ui/settings".to_string()];
    bundle.container.config_exports = vec![
        iroha_data_model::soracloud::SoraConfigExportV1 {
            config_name: "ui/settings".to_string(),
            target: SoraConfigExportTargetV1::Env("UI_SETTINGS_JSON".to_string()),
        },
        iroha_data_model::soracloud::SoraConfigExportV1 {
            config_name: "ui/settings".to_string(),
            target: SoraConfigExportTargetV1::File("runtime/ui_settings.json".to_string()),
        },
    ];
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    let bundle_bytes = simple_soracloud_contract_artifact(&["update", "ciphertext_update"]);
    let artifact_payloads =
        assign_fixture_artifact_hashes(&mut bundle, &bundle_bytes, "persist-materialization");
    let config_value = Json::new("https://api.example.test");
    let service_secret_ciphertext = b"authoritative-db-password".to_vec();
    let mut deployment = sample_deployment_state(&bundle);
    deployment.config_generation = 4;
    deployment.secret_generation = 3;
    deployment.service_configs.insert(
        "ui/settings".to_string(),
        SoraServiceConfigEntryV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_CONFIG_ENTRY_VERSION_V1,
            config_name: "ui/settings".to_string(),
            value_hash: Hash::new(config_value.get().as_bytes()),
            value_json: config_value.clone(),
            last_update_sequence: 12,
        },
    );
    deployment.service_secrets.insert(
        "db/password".to_string(),
        SoraServiceSecretEntryV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_SECRET_ENTRY_VERSION_V1,
            secret_name: "db/password".to_string(),
            envelope: SecretEnvelopeV1 {
                schema_version: SECRET_ENVELOPE_VERSION_V1,
                encryption: SecretEnvelopeEncryptionV1::ClientCiphertext,
                key_id: "kms/runtime/test".to_string(),
                key_version: std::num::NonZeroU32::new(1).expect("non-zero"),
                nonce: vec![7, 8, 9, 10],
                ciphertext: service_secret_ciphertext.clone(),
                commitment: Hash::new(&service_secret_ciphertext),
                aad_digest: None,
            },
            last_update_sequence: 13,
        },
    );
    let runtime = sample_runtime_state(&bundle);
    let apartment = sample_agent_record()?;
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, deployment);
        insert_service_runtime_fixture(world, &bundle, runtime);
        world
            .soracloud_agent_apartments_mut_for_testing()
            .insert(apartment.manifest.apartment_name.to_string(), apartment);
    }
    let fixture = RuntimeFixture::new(&state)?;
    seed_local_artifact_cache(
        &fixture.path().join("artifacts"),
        bundle.container.bundle_hash,
        &bundle_bytes,
        bundle
            .service
            .artifacts
            .iter()
            .zip(artifact_payloads)
            .map(|(artifact, payload)| (artifact.artifact_hash, payload)),
    )?;
    fixture.manager.reconcile_once()?;
    let snapshot = fixture.manager.snapshot.read().clone();
    let service_versions = snapshot
        .services
        .get("web_portal")
        .expect("service snapshot present");
    let plan = service_versions
        .get("2026.02.0")
        .expect("service version snapshot present");
    let mut plan_json = norito::json::to_value(plan)?;
    let plan_object = plan_json
        .as_object_mut()
        .expect("runtime service plan JSON object");
    assert!(!plan_object.contains_key("secret_payload_materialization_dir"));
    plan_object.insert(
        "secret_payload_materialization_dir".to_owned(),
        norito::json::Value::from("/retired/raw-ciphertext-tree"),
    );
    assert!(
        norito::json::from_value::<SoracloudRuntimeServicePlan>(plan_json).is_err(),
        "the first-release runtime plan must reject the retired raw ciphertext tree field"
    );
    assert_eq!(plan.runtime, SoraContainerRuntimeV1::Ivm);
    assert_eq!(plan.health_status, SoraServiceHealthStatusV1::Healthy);
    assert_eq!(plan.authoritative_pending_mailbox_messages, 0);
    assert_eq!(plan.config_generation, 4);
    assert_eq!(plan.secret_generation, 3);
    assert_eq!(plan.config_entry_count, 1);
    assert_eq!(plan.secret_entry_count, 1);
    assert_eq!(plan.config_exports.len(), 2);
    assert_eq!(
        plan.effective_env
            .get("UI_SETTINGS_JSON")
            .expect("exported env var"),
        config_value.get()
    );
    assert_eq!(
        snapshot
            .apartments
            .get("ops_agent")
            .expect("apartment snapshot present")
            .process_generation,
        7
    );
    assert!(fixture.path().join("runtime_snapshot.json").exists());
    let service_dir = PathBuf::from(&plan.materialization_dir);
    assert!(service_dir.join("runtime_plan.json").exists());
    assert!(service_dir.join("deployment_bundle.json").exists());
    assert_eq!(
        fs::read_to_string(PathBuf::from(&plan.config_materialization_dir).join(
            sanitized_relative_material_path("ui/settings").expect("valid config material path"),
        ),)?,
        config_value.get().clone(),
    );
    let effective_env: BTreeMap<String, String> = read_json_optional(
        &PathBuf::from(&plan.effective_env_materialization_path),
        SORACLOUD_RUNTIME_SNAPSHOT_MAX_BYTES,
        "test effective environment",
    )?
    .expect("effective env should exist");
    assert_eq!(
        effective_env
            .get("UI_SETTINGS_JSON")
            .expect("exported env var"),
        config_value.get()
    );
    assert_eq!(
        fs::read_to_string(
            PathBuf::from(&plan.config_exports_materialization_dir)
                .join("runtime/ui_settings.json"),
        )?,
        config_value.get().clone(),
    );
    let materialized_secret_entry: SoraServiceSecretEntryV1 = read_json_optional(
        &PathBuf::from(&plan.secret_envelopes_materialization_dir).join(
            sanitized_relative_material_path("db/password").expect("valid secret material path"),
        ),
        SORACLOUD_RUNTIME_SNAPSHOT_MAX_BYTES,
        "test materialized secret envelope",
    )?
    .expect("materialized secret envelope should exist");
    assert_eq!(materialized_secret_entry.secret_name, "db/password");
    assert_eq!(
        materialized_secret_entry.envelope.ciphertext,
        service_secret_ciphertext
    );
    assert!(fixture.path().join("journals").exists());
    assert!(fixture.path().join("checkpoints").exists());
    assert!(!fixture.path().join("secrets").exists());
    let apartment_dir = fixture
        .path()
        .join("apartments")
        .join(storage_path_component("ops_agent"));
    assert!(apartment_dir.join("runtime_plan.json").exists());
    assert!(apartment_dir.join("apartment_manifest.json").exists());
    Ok(())
}
#[test]
fn reconcile_once_prunes_stale_authoritative_service_materializations() -> Result<()> {
    let mut state = test_state();
    let mut bundle = load_deployment_bundle_fixture()?;
    let bundle_bytes = simple_soracloud_contract_artifact(&["update", "ciphertext_update"]);
    let artifact_payloads =
        assign_fixture_artifact_hashes(&mut bundle, &bundle_bytes, "prune-materialization");
    let config_value = Json::new(true);
    let mut deployment = sample_deployment_state(&bundle);
    deployment.config_generation = 1;
    deployment.secret_generation = 1;
    deployment.service_configs.insert(
        "runtime/feature_flag".to_string(),
        SoraServiceConfigEntryV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_CONFIG_ENTRY_VERSION_V1,
            config_name: "runtime/feature_flag".to_string(),
            value_hash: Hash::new(config_value.get().as_bytes()),
            value_json: config_value.clone(),
            last_update_sequence: 3,
        },
    );
    deployment.service_secrets.insert(
        "db/password".to_string(),
        SoraServiceSecretEntryV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_SECRET_ENTRY_VERSION_V1,
            secret_name: "db/password".to_string(),
            envelope: SecretEnvelopeV1 {
                schema_version: SECRET_ENVELOPE_VERSION_V1,
                encryption: SecretEnvelopeEncryptionV1::ClientCiphertext,
                key_id: "kms/runtime/test".to_string(),
                key_version: std::num::NonZeroU32::new(1).expect("non-zero"),
                nonce: vec![1, 2, 3, 4],
                ciphertext: b"prune-me".to_vec(),
                commitment: Hash::new(b"prune-me"),
                aad_digest: None,
            },
            last_update_sequence: 4,
        },
    );
    let runtime = sample_runtime_state(&bundle);
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, deployment);
        insert_service_runtime_fixture(world, &bundle, runtime);
    }
    let fixture = RuntimeFixture::new(&state)?;
    seed_local_artifact_cache(
        &fixture.path().join("artifacts"),
        bundle.container.bundle_hash,
        &bundle_bytes,
        bundle
            .service
            .artifacts
            .iter()
            .zip(artifact_payloads)
            .map(|(artifact, payload)| (artifact.artifact_hash, payload)),
    )?;
    fixture.manager.reconcile_once()?;
    let service_dir = fixture
        .path()
        .join("services")
        .join(storage_path_component("web_portal"))
        .join(storage_path_component("2026.02.0"));
    let config_path = service_dir.join("configs").join(
        sanitized_relative_material_path("runtime/feature_flag")
            .expect("valid config material path"),
    );
    let secret_envelope_path = service_dir
        .join("secret_envelopes")
        .join(sanitized_relative_material_path("db/password").expect("valid secret material path"));
    let runtime_path = fixture.path().to_path_buf();
    assert!(config_path.exists());
    assert!(secret_envelope_path.exists());
    assert!(!fixture.path().join("secrets").exists());
    drop(fixture.manager);
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        let deployments = world.soracloud_service_deployments_mut_for_testing();
        let mut deployment = deployments
            .view()
            .get(&bundle.service.service_name)
            .cloned()
            .expect("deployment state should remain present");
        deployment.config_generation = 2;
        deployment.secret_generation = 2;
        deployment.service_configs.clear();
        deployment.service_secrets.clear();
        deployments.insert(bundle.service.service_name.clone(), deployment);
    }
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(runtime_path),
        Arc::clone(&state),
    );
    manager.reconcile_once()?;
    let snapshot = manager.snapshot.read().clone();
    let plan = snapshot
        .services
        .get("web_portal")
        .and_then(|versions| versions.get("2026.02.0"))
        .expect("service version snapshot present");
    assert_eq!(plan.config_entry_count, 0);
    assert_eq!(plan.secret_entry_count, 0);
    assert_eq!(plan.config_generation, 2);
    assert_eq!(plan.secret_generation, 2);
    assert!(!config_path.exists());
    assert!(!secret_envelope_path.exists());
    assert!(!manager.config.state_dir.join("secrets").exists());
    Ok(())
}
#[test]
fn reconcile_once_prunes_stale_materializations_and_reports_missing_bundle_cache() -> Result<()> {
    let mut state = test_state();
    let mut bundle = load_deployment_bundle_fixture()?;
    let bundle_bytes = simple_soracloud_contract_artifact(&["update"]);
    let _artifact_payloads =
        assign_fixture_artifact_hashes(&mut bundle, &bundle_bytes, "missing-bundle");
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, sample_deployment_state(&bundle));
        insert_service_runtime_fixture(world, &bundle, sample_runtime_state(&bundle));
    }
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let stale_dir = temp_dir.path().join("services/stale_service/stale_version");
    fs::create_dir_all(&stale_dir)?;
    fs::write(stale_dir.join("runtime_plan.json"), "{}")?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    );
    manager.reconcile_once()?;
    let snapshot = manager.snapshot.read().clone();
    let bundle_plan = snapshot
        .services
        .get("web_portal")
        .and_then(|versions| versions.get("2026.02.0"))
        .expect("bundle plan present");
    assert!(!bundle_plan.bundle_available_locally);
    assert_eq!(
        bundle_plan.health_status,
        SoraServiceHealthStatusV1::Hydrating
    );
    assert!(
        bundle_plan
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == SoraArtifactKindV1::Bundle
                && !artifact.available_locally)
    );
    assert!(!temp_dir.path().join("services/stale_service").exists());
    Ok(())
}
#[test]
fn reconcile_once_marks_hydrated_ivm_service_healthy_without_runtime_state() -> Result<()> {
    let mut state = test_state();
    let mut bundle = load_deployment_bundle_fixture()?;
    bundle.service.artifacts.clear();
    let bundle_bytes = simple_soracloud_contract_artifact(&["query"]);
    bundle.container.bundle_hash = Hash::new(&bundle_bytes);
    bundle.service.container.manifest_hash = bundle.container_manifest_hash();
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, sample_deployment_state(&bundle));
    }
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let artifacts_root = temp_dir.path().join("artifacts");
    fs::create_dir_all(&artifacts_root)?;
    fs::write(
        artifacts_root.join(hash_cache_name(bundle.container.bundle_hash)),
        &bundle_bytes,
    )?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    );
    manager.reconcile_once()?;
    let snapshot = manager.snapshot.read().clone();
    let plan = snapshot
        .services
        .get(bundle.service.service_name.as_ref())
        .and_then(|versions| versions.get(&bundle.service.service_version))
        .expect("hydrated IVM service plan");
    assert_eq!(plan.runtime, SoraContainerRuntimeV1::Ivm);
    assert!(plan.bundle_available_locally);
    assert_eq!(plan.health_status, SoraServiceHealthStatusV1::Healthy);
    assert!(
        plan.artifacts
            .iter()
            .all(|artifact| artifact.available_locally)
    );
    Ok(())
}
#[test]
fn build_runtime_snapshot_projects_authoritative_inrou_placement() -> Result<()> {
    let mut state = test_state();
    let bundle = sample_inrou_test_bundle()?;
    bundle.validate_for_admission()?;
    let deployment_state = sample_deployment_state(&bundle);
    let expected_process_generation = deployment_state.process_generation;
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
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let config = test_runtime_manager_config(state_dir)
        .with_local_host_identity(ALICE_ID.clone(), local_peer_id);
    let view = state.view();
    let bundle_registry = collect_service_revision_registry(&view);
    let snapshot = build_runtime_snapshot(
        &view,
        &bundle_registry,
        (&config.state_dir, &config.state_dir.join("artifacts")),
        &config.cache_budgets,
        config.local_validator_account_id.as_ref(),
        config.local_peer_id.as_deref(),
        true,
    )?;
    let plan = snapshot
        .services
        .get(bundle.service.service_name.as_ref())
        .and_then(|versions| versions.get(&bundle.service.service_version))
        .expect("Inrou runtime plan present");
    assert_eq!(plan.runtime, SoraContainerRuntimeV1::Inrou);
    assert_eq!(plan.process_generation, Some(expected_process_generation));
    assert_eq!(plan.desired_replica_count, bundle.service.replicas.get());
    assert_eq!(plan.local_replica_slots, vec![1]);
    let replica = plan
        .local_replicas
        .first()
        .expect("authoritative local replica projection");
    assert_eq!(replica.replica_slot, 1);
    assert_eq!(replica.lease_started_height, 1);
    assert_eq!(replica.validator_account_id, ALICE_ID.to_string());
    assert_eq!(replica.peer_id, local_peer_id);
    assert_eq!(
        plan.inrou
            .as_ref()
            .expect("Inrou runtime projection")
            .selected_guest_isa,
        selected_guest_isa
    );
    assert_eq!(plan.health_status, SoraServiceHealthStatusV1::Hydrating);
    Ok(())
}
#[test]
fn materialize_inrou_replica_plan_rejects_stale_manifest_hash() -> Result<()> {
    let mut bundle = sample_inrou_test_bundle()?;
    bundle.container.args.push("stale-after-seal".to_owned());

    let error = materialize_inrou_replica_plan_for_tests(&bundle)
        .expect_err("a container mutation without resealing must fail admission");
    assert!(
        error
            .to_string()
            .contains("service.container.manifest_hash"),
        "unexpected error: {error:?}"
    );
    Ok(())
}
#[test]
fn build_runtime_snapshot_rejects_corrupt_hosted_http_runtime_state() -> Result<()> {
    let mut state = test_state();
    let bundle = sample_inrou_test_bundle()?;
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
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let config = test_runtime_manager_config(state_dir)
        .with_local_host_identity(ALICE_ID.clone(), local_peer_id);
    let service_dir = config
        .state_dir
        .join("services")
        .join(storage_path_component(bundle.service.service_name.as_ref()))
        .join(storage_path_component(&bundle.service.service_version));
    fs::create_dir_all(&service_dir)?;
    fs::write(
        hosted_http_runtime_state_path(&service_dir),
        b"{not-valid-json",
    )?;
    let view = state.view();
    let bundle_registry = collect_service_revision_registry(&view);

    let error = build_runtime_snapshot(
        &view,
        &bundle_registry,
        (&config.state_dir, &config.state_dir.join("artifacts")),
        &config.cache_budgets,
        config.local_validator_account_id.as_ref(),
        config.local_peer_id.as_deref(),
        true,
    )
    .expect_err("corrupt hosted-HTTP runtime state must fail snapshot construction");
    assert!(
        error.to_string().contains(
            "read hosted-HTTP runtime state for service `web_portal` revision `2026.02.0`"
        ),
        "unexpected error: {error:?}"
    );
    Ok(())
}
#[test]
fn reconcile_once_stamps_snapshot_with_local_peer_identity() -> Result<()> {
    let mut state = test_state();
    let bundle = load_deployment_bundle_fixture()?;
    bundle.validate_for_admission()?;
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, sample_deployment_state(&bundle));
    }
    let local_peer_id = canonical_inrou_test_peer_id();
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(state_dir)
            .with_local_host_identity(ALICE_ID.clone(), local_peer_id),
        Arc::clone(&state),
    );
    manager.reconcile_once()?;
    let snapshot = manager.snapshot.read().clone();
    assert_eq!(snapshot.local_peer_id.as_deref(), Some(local_peer_id));
    Ok(())
}

#[cfg(unix)]
#[test]
fn reconcile_error_quarantines_existing_inrou_worker_and_snapshot_plan() -> Result<()> {
    let mut state = test_state();
    let bundle = sample_inrou_test_bundle()?;
    let deployment = sample_deployment_state(&bundle);
    let reporting_epoch = deployment
        .service_lease
        .as_ref()
        .expect("hosted service lease")
        .reporting_epoch;
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, deployment);
    }
    let local_peer_id = canonical_inrou_test_peer_id();
    insert_inrou_service_placement_fixture(&mut state, &bundle, local_peer_id, [1]);
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = temp_dir.path().join("blocked-runtime-state");
    let config = test_runtime_manager_config(state_dir.clone())
        .with_local_host_identity(ALICE_ID.clone(), local_peer_id);
    let snapshot = {
        let view = state.view();
        let bundle_registry = collect_service_revision_registry(&view);
        build_runtime_snapshot(
            &view,
            &bundle_registry,
            (&config.state_dir, &config.state_dir.join("artifacts")),
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
        .expect("local Inrou plan");
    let replica = plan.local_replicas.first().expect("local replica plan");
    let reporter_key = (
        bundle.service.service_name.to_string(),
        bundle.service.service_version.clone(),
        replica.lease_started_height,
        reporting_epoch,
        replica.replica_slot,
        replica.placement_incarnation.clone(),
    );
    let cache_key = HostedHttpWorkerCacheKey {
        runtime: SoraContainerRuntimeV1::Inrou,
        guest_isa: plan.inrou.as_ref().map(|inrou| inrou.selected_guest_isa),
        service_name: bundle.service.service_name.to_string(),
        service_version: bundle.service.service_version.clone(),
        replica_slot: replica.replica_slot,
        lease_started_height: replica.lease_started_height,
        placement_incarnation: replica.placement_incarnation.clone(),
        validator_account_id: replica.validator_account_id.clone(),
        peer_id: replica.peer_id.clone(),
        bundle_hash: plan.bundle_hash.clone(),
        bundle_path: plan.bundle_path.clone(),
        entrypoint: plan.entrypoint.clone(),
        process_generation: plan.process_generation.expect("process generation"),
        args: bundle.container.args.clone(),
        effective_env: plan.effective_env.clone(),
        healthcheck_path: bundle.container.lifecycle.healthcheck_path.clone(),
        service_data_dir: build_native_service_data_dir(
            &config.state_dir,
            bundle.service.service_name.as_ref(),
        ),
    };
    let child = Command::new("/bin/sleep")
        .arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let child_pid = child.id();
    let worker = HostedHttpWorker {
        cache_key,
        child,
        log_drains: Vec::new(),
        listen_base_url: "http://127.0.0.1:1/".to_owned(),
        egress_accounting: PortableVmReplicaEgressAccounting::new(
            PortableVmEgressAccounting::new(0),
            0,
        ),
        stderr_log_path: config.state_dir.join("worker.stderr.log"),
        stop_grace: Duration::ZERO,
        port_forward: None,
        qmp_control: None,
        #[cfg(target_os = "linux")]
        loopback_firewall: None,
        #[cfg(target_os = "linux")]
        cgroup: None,
    };
    let manager = SoracloudRuntimeManager::new(config, Arc::clone(&state));
    *manager.snapshot.write() = snapshot;
    manager
        .hosted_http_workers
        .lock()
        .insert(reporter_key, Arc::new(parking_lot::Mutex::new(worker)));
    fs::write(&state_dir, b"not a directory")?;

    let _reconcile_error = manager
        .reconcile_once()
        .expect_err("an unusable runtime state directory must fail reconciliation");
    assert!(manager.hosted_http_workers.lock().is_empty());
    assert!(
        manager.snapshot.read().services.values().all(|versions| {
            versions
                .values()
                .all(|plan| plan.runtime != SoraContainerRuntimeV1::Inrou)
        }),
        "a failed reconcile must withdraw every locally served Inrou plan"
    );
    let still_running = Command::new("sh")
        .arg("-c")
        .arg(format!("kill -0 {child_pid} 2>/dev/null"))
        .status()?;
    assert!(
        !still_running.success(),
        "a worker present before the reconcile error must be stopped and reaped"
    );
    Ok(())
}

#[test]
fn build_runtime_snapshot_rejects_active_inrou_canary() -> Result<()> {
    let mut state = test_state();
    let mut active_bundle = sample_inrou_test_bundle()?;
    let mut canary_bundle = active_bundle.clone();
    canary_bundle.service.service_version = "2026.03.0".to_string();
    canary_bundle.container.bundle_path = "/bundles/web_portal_canary.to".to_string();
    let active_bundle_bytes = simple_soracloud_contract_artifact(&["entry_active"]);
    let canary_bundle_bytes = simple_soracloud_contract_artifact(&["entry_canary"]);
    active_bundle.container.bundle_hash = Hash::new(&active_bundle_bytes);
    active_bundle.service.container.manifest_hash = active_bundle.container_manifest_hash();
    canary_bundle.container.bundle_hash = Hash::new(&canary_bundle_bytes);
    canary_bundle.service.container.manifest_hash = canary_bundle.container_manifest_hash();
    active_bundle.service.container.manifest_hash = active_bundle.container_manifest_hash();
    canary_bundle.service.container.manifest_hash = canary_bundle.container_manifest_hash();
    active_bundle.validate_for_admission()?;
    canary_bundle.validate_for_admission()?;
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
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &active_bundle);
        insert_service_revision_fixture(world, &canary_bundle);
        insert_service_deployment_fixture(world, &canary_bundle, deployment);
    }
    let local_peer_id = canonical_inrou_test_peer_id();
    insert_inrou_service_placement_fixture(&mut state, &active_bundle, local_peer_id, [1_u16]);
    insert_inrou_service_placement_fixture(&mut state, &canary_bundle, local_peer_id, [1_u16]);
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let config = test_runtime_manager_config(state_dir)
        .with_local_host_identity(ALICE_ID.clone(), local_peer_id);
    let view = state.view();
    let bundle_registry = collect_service_revision_registry(&view);
    let error = build_runtime_snapshot(
        &view,
        &bundle_registry,
        (&config.state_dir, &config.state_dir.join("artifacts")),
        &config.cache_budgets,
        config.local_validator_account_id.as_ref(),
        config.local_peer_id.as_deref(),
        true,
    )
    .expect_err("active Inrou canaries must fail closed");
    assert!(
        error
            .to_string()
            .contains("carries an unsupported active canary"),
        "unexpected error: {error:?}"
    );
    Ok(())
}

#[test]
fn persisted_and_synthetic_inrou_snapshots_require_current_exact_revision() -> Result<()> {
    let mut state = test_state();
    let bundle = sample_inrou_test_bundle()?;
    let mut ivm_bundle = load_deployment_bundle_fixture()?;
    ivm_bundle.service.service_name = "deterministic_sidecar".parse()?;
    ivm_bundle.validate_for_admission()?;
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, sample_deployment_state(&bundle));
        insert_service_revision_fixture(world, &ivm_bundle);
        insert_service_deployment_fixture(world, &ivm_bundle, sample_deployment_state(&ivm_bundle));
    }
    let local_peer_id = canonical_inrou_test_peer_id();
    insert_inrou_service_placement_fixture(&mut state, &bundle, local_peer_id, [1]);
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let config = test_runtime_manager_config(state_dir)
        .with_local_host_identity(ALICE_ID.clone(), local_peer_id);
    let view = state.view();
    let bundle_registry = collect_service_revision_registry(&view);
    let mut snapshot = build_runtime_snapshot(
        &view,
        &bundle_registry,
        (&config.state_dir, &config.state_dir.join("artifacts")),
        &config.cache_budgets,
        config.local_validator_account_id.as_ref(),
        config.local_peer_id.as_deref(),
        true,
    )?;
    let plan = snapshot
        .services
        .get_mut(bundle.service.service_name.as_ref())
        .and_then(|versions| versions.get_mut(&bundle.service.service_version))
        .expect("current Inrou runtime plan");
    plan.role = SoracloudRuntimeRevisionRole::CanaryCandidate;
    plan.traffic_percent = 25;
    let manager = SoracloudRuntimeManager::new(config.clone(), Arc::clone(&state));

    let error = manager
        .submit_http_service_runtime_state_updates(&view, &snapshot)
        .expect_err("runtime-state publication must reject a candidate Inrou snapshot");
    assert!(error.to_string().contains("sole active revision"));
    let error = manager
        .desired_hosted_http_worker_keys(&view, &snapshot)
        .expect_err("worker selection must reject a candidate Inrou snapshot");
    assert!(error.to_string().contains("sole active revision"));
    let error = manager
        .reconcile_hosted_http_workers(&view, &snapshot)
        .expect_err("worker reconciliation must reject a candidate Inrou snapshot");
    assert!(error.to_string().contains("sole active revision"));

    write_json_atomic(&manager.runtime_snapshot_path(), &snapshot)?;
    assert!(
        manager.restore_persisted_snapshot()?,
        "an existing snapshot must be handled"
    );
    let restored = manager.snapshot.read().clone();
    assert!(
        restored.services.values().all(|versions| {
            versions
                .values()
                .all(|plan| plan.runtime != SoraContainerRuntimeV1::Inrou)
        }),
        "non-authoritative persisted Inrou plans must be discarded before startup reconciliation"
    );
    let persisted = read_json_optional::<SoracloudRuntimeSnapshot>(
        &manager.runtime_snapshot_path(),
        SORACLOUD_RUNTIME_SNAPSHOT_MAX_BYTES,
        "test Soracloud runtime snapshot",
    )?
    .expect("scrubbed runtime snapshot remains persisted");
    assert_eq!(persisted, restored, "the scrub must be durable");
    assert_eq!(
        restored
            .services
            .get(ivm_bundle.service.service_name.as_ref()),
        snapshot
            .services
            .get(ivm_bundle.service.service_name.as_ref()),
        "scrubbing stale Inrou state must preserve generic deterministic-IVM plans"
    );

    let versions = snapshot
        .services
        .get_mut(bundle.service.service_name.as_ref())
        .expect("Inrou versions");
    let current_plan = versions
        .get_mut(&bundle.service.service_version)
        .expect("current plan");
    current_plan.role = SoracloudRuntimeRevisionRole::Active;
    current_plan.traffic_percent = 100;

    let signed_inrou_plan = current_plan.inrou.take();
    current_plan.runtime = SoraContainerRuntimeV1::Ivm;
    current_plan.execution_plane = SoraServiceExecutionPlaneV1::DeterministicService;
    let error = manager
        .desired_hosted_http_worker_keys(&view, &snapshot)
        .expect_err("relabeling a local Inrou replica plan as IVM must fail closed");
    assert!(
        error
            .to_string()
            .contains("does not match its admitted bundle")
    );
    let current_plan = snapshot
        .services
        .get_mut(bundle.service.service_name.as_ref())
        .and_then(|versions| versions.get_mut(&bundle.service.service_version))
        .expect("current Inrou runtime plan");
    current_plan.runtime = SoraContainerRuntimeV1::Inrou;
    current_plan.execution_plane = SoraServiceExecutionPlaneV1::HttpService;
    current_plan.inrou = signed_inrou_plan;

    let expected_process_generation = current_plan.process_generation;
    current_plan.process_generation = Some(
        expected_process_generation
            .expect("local Inrou plan generation")
            .saturating_add(1),
    );
    let error = manager
        .desired_hosted_http_worker_keys(&view, &snapshot)
        .expect_err("a stale Inrou process generation must be rejected");
    assert!(error.to_string().contains("authoritative process"));
    snapshot
        .services
        .get_mut(bundle.service.service_name.as_ref())
        .and_then(|versions| versions.get_mut(&bundle.service.service_version))
        .expect("current Inrou runtime plan")
        .process_generation = expected_process_generation;

    let versions = snapshot
        .services
        .get_mut(bundle.service.service_name.as_ref())
        .expect("Inrou versions");
    let mut stale_plan = versions
        .remove(&bundle.service.service_version)
        .expect("current plan");
    stale_plan.service_version = "2026.03.0".to_owned();
    versions.insert(stale_plan.service_version.clone(), stale_plan);
    let error = manager
        .desired_hosted_http_worker_keys(&view, &snapshot)
        .expect_err("a non-current sole Inrou revision must be rejected");
    assert!(
        error
            .to_string()
            .contains("not the authoritative current revision")
    );
    let versions = snapshot
        .services
        .get_mut(bundle.service.service_name.as_ref())
        .expect("Inrou versions");
    let mut current_plan = versions.remove("2026.03.0").expect("stale plan");
    current_plan.service_version = bundle.service.service_version.clone();
    versions.insert(bundle.service.service_version.clone(), current_plan);

    snapshot.observed_height = snapshot.observed_height.saturating_add(1);
    let error = manager
        .desired_hosted_http_worker_keys(&view, &snapshot)
        .expect_err("an Inrou plan from another block height must be rejected");
    assert!(error.to_string().contains("not authoritative height"));
    snapshot.observed_height = u64::try_from(view.height()).unwrap_or(u64::MAX);

    let versions = snapshot
        .services
        .get_mut(bundle.service.service_name.as_ref())
        .expect("Inrou versions");
    let current_plan = versions
        .get(&bundle.service.service_version)
        .expect("current plan");
    let mut second_plan = current_plan.clone();
    second_plan.service_version = "2026.03.0".to_owned();
    versions.insert(second_plan.service_version.clone(), second_plan);
    let error = collect_single_revision_inrou_runtime_plans(&snapshot)
        .expect_err("an Inrou snapshot must never carry a second revision");
    assert!(error.to_string().contains("exactly one revision"));
    Ok(())
}

#[test]
fn startup_rebuilds_snapshot_after_atomic_inrou_revision_switch() -> Result<()> {
    let mut state = test_state();
    let retired_bundle = sample_inrou_test_bundle()?;
    retired_bundle.validate_for_admission()?;
    let retired_deployment = sample_deployment_state(&retired_bundle);
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &retired_bundle);
        insert_service_deployment_fixture(world, &retired_bundle, retired_deployment.clone());
        insert_inrou_service_placement_record_fixture(world, &retired_bundle, Vec::new());
    }
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let local_peer_id = canonical_inrou_test_peer_id();
    let config = test_runtime_manager_config(state_dir)
        .with_local_host_identity(ALICE_ID.clone(), local_peer_id);
    let retired_snapshot = {
        let view = state.view();
        let bundle_registry = collect_service_revision_registry(&view);
        build_runtime_snapshot(
            &view,
            &bundle_registry,
            (&config.state_dir, &config.state_dir.join("artifacts")),
            &config.cache_budgets,
            config.local_validator_account_id.as_ref(),
            config.local_peer_id.as_deref(),
            false,
        )?
    };
    assert!(
        retired_snapshot
            .services
            .get(retired_bundle.service.service_name.as_ref())
            .is_some_and(|versions| {
                versions.contains_key(&retired_bundle.service.service_version)
            })
    );
    write_json_atomic_bounded(
        &config.state_dir.join("runtime_snapshot.json"),
        &retired_snapshot,
        SORACLOUD_RUNTIME_SNAPSHOT_MAX_BYTES,
        "test Soracloud runtime snapshot",
    )?;

    let mut current_bundle = retired_bundle.clone();
    current_bundle.service.service_version = "2026.03.0".to_owned();
    current_bundle.container.bundle_path = "/bundles/web_portal_2026_03.to".to_owned();
    current_bundle.container.bundle_hash = Hash::new(b"atomic-inrou-revision-2026.03.0");
    current_bundle.service.container.manifest_hash = current_bundle.container_manifest_hash();
    current_bundle.validate_for_admission()?;
    let mut current_deployment = retired_deployment;
    current_deployment.current_service_version = current_bundle.service.service_version.clone();
    current_deployment.current_service_manifest_hash = current_bundle.service_manifest_hash();
    current_deployment.current_container_manifest_hash = current_bundle.container_manifest_hash();
    current_deployment.revision_count = current_deployment.revision_count.saturating_add(1);
    current_deployment.process_generation = current_deployment.process_generation.saturating_add(1);
    current_deployment.process_started_sequence = current_deployment
        .process_started_sequence
        .saturating_add(1);
    current_deployment.last_rollout = Some(SoraServiceRolloutStateV1 {
        schema_version: SORA_SERVICE_ROLLOUT_STATE_VERSION_V1,
        rollout_handle: "atomic-inrou-upgrade-2026-03".to_owned(),
        baseline_version: retired_bundle.service.service_version.clone(),
        candidate_version: current_bundle.service.service_version.clone(),
        canary_percent: current_bundle.service.rollout.canary_percent,
        traffic_percent: 100,
        stage: SoraRolloutStageV1::Promoted,
        health_failures: 0,
        max_health_failures: current_bundle
            .service
            .rollout
            .automatic_rollback_failures
            .get(),
        health_window_secs: current_bundle.service.rollout.health_window_secs.get(),
        created_sequence: current_deployment.process_started_sequence,
        updated_sequence: current_deployment.process_started_sequence,
    });
    current_deployment.active_rollout = None;
    current_deployment.validate_against_active_bundle(&current_bundle)?;
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &current_bundle);
        insert_service_deployment_fixture(world, &current_bundle, current_deployment);
    }

    let scrub_probe = SoracloudRuntimeManager::new(config.clone(), Arc::clone(&state));
    assert!(scrub_probe.restore_persisted_snapshot()?);
    let scrubbed = scrub_probe.snapshot.read().clone();
    assert!(
        !scrubbed
            .services
            .contains_key(retired_bundle.service.service_name.as_ref()),
        "restore must discard the retired Inrou revision before reconciliation"
    );
    let persisted_scrubbed = read_json_optional::<SoracloudRuntimeSnapshot>(
        &scrub_probe.runtime_snapshot_path(),
        SORACLOUD_RUNTIME_SNAPSHOT_MAX_BYTES,
        "test Soracloud runtime snapshot",
    )?
    .expect("scrubbed runtime snapshot");
    assert_eq!(
        persisted_scrubbed, scrubbed,
        "restore scrub must be durable"
    );

    // Reinstall the stale derived file so the real startup sequence independently proves
    // restore -> scrub -> reconcile -> exact-current publication.
    write_json_atomic_bounded(
        &config.state_dir.join("runtime_snapshot.json"),
        &retired_snapshot,
        SORACLOUD_RUNTIME_SNAPSHOT_MAX_BYTES,
        "test Soracloud runtime snapshot",
    )?;
    let restarted_manager = Arc::new(SoracloudRuntimeManager::new(
        config.clone(),
        Arc::clone(&state),
    ));
    restarted_manager.initialize_for_startup()?;
    let rebuilt = restarted_manager.snapshot.read().clone();
    let versions = rebuilt
        .services
        .get(current_bundle.service.service_name.as_ref())
        .expect("current Inrou service must be rebuilt");
    assert_eq!(versions.len(), 1);
    let current_plan = versions
        .get(&current_bundle.service.service_version)
        .expect("atomic current Inrou revision");
    assert_eq!(current_plan.runtime, SoraContainerRuntimeV1::Inrou);
    assert_eq!(current_plan.role, SoracloudRuntimeRevisionRole::Active);
    assert_eq!(current_plan.traffic_percent, 100);
    assert!(current_plan.rollout_handle.is_none());
    assert!(!versions.contains_key(&retired_bundle.service.service_version));
    let view = state.view();
    assert!(
        view.world()
            .soracloud_service_revisions()
            .get(&(
                retired_bundle.service.service_name.to_string(),
                retired_bundle.service.service_version.clone(),
            ))
            .is_some(),
        "retired admitted metadata may remain without becoming a serving fallback"
    );
    assert!(
        view.world()
            .soracloud_inrou_service_placements()
            .get(&(
                retired_bundle.service.service_name.to_string(),
                retired_bundle.service.service_version.clone(),
            ))
            .is_some(),
        "retired placement metadata may remain without becoming a serving fallback"
    );
    drop(view);
    let persisted_rebuilt = read_json_optional::<SoracloudRuntimeSnapshot>(
        &restarted_manager.runtime_snapshot_path(),
        SORACLOUD_RUNTIME_SNAPSHOT_MAX_BYTES,
        "test Soracloud runtime snapshot",
    )?
    .expect("rebuilt runtime snapshot");
    assert_eq!(persisted_rebuilt, rebuilt);
    Ok(())
}

#[test]
fn submit_http_service_runtime_state_retries_until_authoritative_state_catches_up() -> Result<()> {
    let mut state = test_state();
    let bundle = sample_inrou_test_bundle()?;
    bundle.validate_for_admission()?;
    let deployment_state = sample_deployment_state(&bundle);
    let reporting_epoch = deployment_state
        .service_lease
        .as_ref()
        .expect("hosted service lease")
        .reporting_epoch;
    let local_peer_id = canonical_inrou_test_peer_id();
    let selected_guest_isa =
        current_host_inrou_guest_isa().expect("tests require a supported Inrou host ISA");
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, deployment_state);
        let retired_version = "2026.01.0".to_owned();
        world
            .soracloud_inrou_replica_runtime_mut_for_testing()
            .insert(
                (
                    bundle.service.service_name.to_string(),
                    retired_version.clone(),
                    "1".to_owned(),
                ),
                SoraInrouReplicaRuntimeStateV1 {
                    schema_version: SORA_INROU_REPLICA_RUNTIME_STATE_VERSION_V1,
                    service_name: bundle.service.service_name.clone(),
                    service_version: retired_version,
                    replica_slot: 1,
                    placement_incarnation: Hash::new(b"placement-1"),
                    validator_account_id: ALICE_ID.clone(),
                    peer_id: local_peer_id.to_owned(),
                    selected_guest_isa,
                    health_status: SoraServiceHealthStatusV1::Degraded,
                    load_factor_bps: 0,
                    materialized_bundle_hash: bundle.container.bundle_hash,
                    reporting_epoch,
                    accounted_egress_bytes: 0,
                    updated_at_ms: 1,
                    last_error: Some("retired revision".to_owned()),
                },
            );
    }
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
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let config = test_runtime_manager_config(state_dir)
        .with_local_host_identity(ALICE_ID.clone(), local_peer_id);
    let mutation_sink = Arc::new(RecordingRuntimeMutationSink::default());
    let manager = SoracloudRuntimeManager::new(config.clone(), Arc::clone(&state))
        .with_mutation_sink(mutation_sink.clone());
    let snapshot = {
        let view = state.view();
        let bundle_registry = collect_service_revision_registry(&view);
        build_runtime_snapshot(
            &view,
            &bundle_registry,
            (&config.state_dir, &config.state_dir.join("artifacts")),
            &config.cache_budgets,
            config.local_validator_account_id.as_ref(),
            config.local_peer_id.as_deref(),
            true,
        )?
    };
    {
        let view = state.view();
        manager.submit_http_service_runtime_state_updates(&view, &snapshot)?;
        manager.submit_http_service_runtime_state_updates(&view, &snapshot)?;
    }
    assert_eq!(
        mutation_sink.submitted_inrou_replica_runtime_states().len(),
        1,
        "a missing authoritative row must not enqueue a duplicate inside the bounded retry window"
    );
    let submission_key = (
        bundle.service.service_name.to_string(),
        bundle.service.service_version.clone(),
        1,
        Hash::new(b"placement-1").to_string(),
    );
    manager
        .last_runtime_state_submission_commitments
        .lock()
        .get_mut(&submission_key)
        .expect("recorded missing-row submission attempt")
        .attempted_at_ms = 0;
    {
        let view = state.view();
        manager.submit_http_service_runtime_state_updates(&view, &snapshot)?;
    }
    let submitted_states = mutation_sink.submitted_inrou_replica_runtime_states();
    assert_eq!(
        submitted_states.len(),
        2,
        "a missing authoritative row must retry after the bounded window"
    );
    let submitted_clears = mutation_sink.submitted_inrou_replica_runtime_state_clears();
    assert_eq!(
        submitted_clears.len(),
        3,
        "a retired runtime-state row must be cleared on every reconcile until WSV catches up"
    );
    assert_eq!(submitted_clears[0].service_version, "2026.01.0");
    assert_eq!(submitted_clears[0].replica_slot, 1);
    assert_eq!(
        submitted_clears[0].expected_placement_incarnation,
        Hash::new(b"placement-1")
    );
    let submitted_state = &submitted_states[0].state;
    assert_eq!(submitted_state.service_name, bundle.service.service_name);
    assert_eq!(
        submitted_state.service_version,
        bundle.service.service_version
    );
    assert_eq!(submitted_state.replica_slot, 1);
    assert_eq!(submitted_state.validator_account_id, *ALICE_ID);
    assert_eq!(submitted_state.peer_id, local_peer_id);
    assert_eq!(
        submitted_state.materialized_bundle_hash,
        bundle.container.bundle_hash
    );

    let next_height = state
        .latest_block_header_fast()
        .map_or(1, |header| header.height().get().saturating_add(1));
    let header = BlockHeader::new(
        NonZeroU64::new(next_height).expect("non-zero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut tx = block.transaction();
    isi::soracloud::SetSoracloudInrouReplicaRuntimeState {
        state: submitted_state.clone(),
    }
    .execute(&ALICE_ID, &mut tx)?;
    tx.apply();
    block.commit_world_overlay_for_testing()?;

    {
        let view = state.view();
        let bundle_registry = collect_service_revision_registry(&view);
        let snapshot_after_catch_up = build_runtime_snapshot(
            &view,
            &bundle_registry,
            (&config.state_dir, &config.state_dir.join("artifacts")),
            &config.cache_budgets,
            config.local_validator_account_id.as_ref(),
            config.local_peer_id.as_deref(),
            true,
        )?;
        manager.submit_http_service_runtime_state_updates(&view, &snapshot_after_catch_up)?;
    }
    assert_eq!(
        mutation_sink.submitted_inrou_replica_runtime_states().len(),
        2,
        "no runtime-state mutation should be submitted after authoritative catch-up"
    );
    assert_eq!(
        mutation_sink
            .submitted_inrou_replica_runtime_state_clears()
            .len(),
        4,
        "a stale clear must remain retryable independently of current-state catch-up"
    );
    assert!(
        !manager
            .last_runtime_state_submission_commitments
            .lock()
            .contains_key(&submission_key),
        "authoritative catch-up must clear the local retry commitment"
    );
    Ok(())
}
#[test]
fn submit_http_service_runtime_state_retries_stale_row_after_cooldown() -> Result<()> {
    let mut state = test_state();
    let bundle = sample_inrou_test_bundle()?;
    bundle.validate_for_admission()?;
    let deployment_state = sample_deployment_state(&bundle);
    let reporting_epoch = deployment_state
        .service_lease
        .as_ref()
        .expect("hosted service lease")
        .reporting_epoch;
    let local_peer_id = canonical_inrou_test_peer_id();
    let selected_guest_isa =
        current_host_inrou_guest_isa().expect("tests require a supported Inrou host ISA");
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_revision_fixture(world, &bundle);
        insert_service_deployment_fixture(world, &bundle, deployment_state);
    }
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
    Arc::get_mut(&mut state)
        .expect("unique test state")
        .world
        .soracloud_inrou_replica_runtime_mut_for_testing()
        .insert(
            (
                bundle.service.service_name.to_string(),
                bundle.service.service_version.clone(),
                "1".to_owned(),
            ),
            SoraInrouReplicaRuntimeStateV1 {
                schema_version: SORA_INROU_REPLICA_RUNTIME_STATE_VERSION_V1,
                service_name: bundle.service.service_name.clone(),
                service_version: bundle.service.service_version.clone(),
                replica_slot: 1,
                placement_incarnation: Hash::new(b"placement-1"),
                validator_account_id: ALICE_ID.clone(),
                peer_id: local_peer_id.to_owned(),
                selected_guest_isa,
                health_status: SoraServiceHealthStatusV1::Unavailable,
                load_factor_bps: 0,
                materialized_bundle_hash: bundle.container.bundle_hash,
                reporting_epoch,
                accounted_egress_bytes: 0,
                updated_at_ms: 1,
                last_error: Some("stale authoritative runtime state".to_owned()),
            },
        );

    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let state_dir = canonical_test_runtime_state_dir(&temp_dir)?;
    let config = test_runtime_manager_config(state_dir)
        .with_local_host_identity(ALICE_ID.clone(), local_peer_id);
    let mutation_sink = Arc::new(RecordingRuntimeMutationSink::default());
    let manager = SoracloudRuntimeManager::new(config.clone(), Arc::clone(&state))
        .with_mutation_sink(mutation_sink.clone());
    let snapshot = {
        let view = state.view();
        let bundle_registry = collect_service_revision_registry(&view);
        build_runtime_snapshot(
            &view,
            &bundle_registry,
            (&config.state_dir, &config.state_dir.join("artifacts")),
            &config.cache_budgets,
            config.local_validator_account_id.as_ref(),
            config.local_peer_id.as_deref(),
            true,
        )?
    };
    let submission_key = (
        bundle.service.service_name.to_string(),
        bundle.service.service_version.clone(),
        1,
        Hash::new(b"placement-1").to_string(),
    );

    {
        let view = state.view();
        manager.submit_http_service_runtime_state_updates(&view, &snapshot)?;
        manager.submit_http_service_runtime_state_updates(&view, &snapshot)?;
    }
    assert_eq!(
        mutation_sink.submitted_inrou_replica_runtime_states().len(),
        1,
        "an identical stale-row update should be suppressed only inside the bounded retry window"
    );
    manager
        .last_runtime_state_submission_commitments
        .lock()
        .get_mut(&submission_key)
        .expect("recorded stale-row submission attempt")
        .attempted_at_ms = 0;
    {
        let view = state.view();
        manager.submit_http_service_runtime_state_updates(&view, &snapshot)?;
    }
    let submitted_states = mutation_sink.submitted_inrou_replica_runtime_states();
    assert_eq!(
        submitted_states.len(),
        2,
        "an enqueued update must retry after the bounded window while WSV remains stale"
    );
    let caught_up_state = submitted_states
        .last()
        .expect("retried runtime-state submission")
        .state
        .clone();

    let next_height = state
        .latest_block_header_fast()
        .map_or(1, |header| header.height().get().saturating_add(1));
    let header = BlockHeader::new(
        NonZeroU64::new(next_height).expect("non-zero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut tx = block.transaction();
    isi::soracloud::SetSoracloudInrouReplicaRuntimeState {
        state: caught_up_state,
    }
    .execute(&ALICE_ID, &mut tx)?;
    tx.apply();
    block.commit_world_overlay_for_testing()?;

    {
        let view = state.view();
        manager.submit_http_service_runtime_state_updates(&view, &snapshot)?;
    }
    assert_eq!(
        mutation_sink.submitted_inrou_replica_runtime_states().len(),
        2,
        "the exact authoritative catch-up must stop runtime-state retries"
    );
    assert!(
        !manager
            .last_runtime_state_submission_commitments
            .lock()
            .contains_key(&submission_key),
        "authoritative catch-up must clear the bounded retry attempt"
    );
    Ok(())
}
#[test]
fn submit_http_service_lease_usage_binds_lease_opens_zero_and_retries() -> Result<()> {
    let mut state = test_state();
    let mut bundle = load_deployment_bundle_fixture()?;
    bundle.container.runtime = SoraContainerRuntimeV1::Inrou;
    bundle.service.execution_plane =
        iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::HttpService;
    bundle.service.state_bindings.clear();
    bundle.service.handlers.clear();
    let deployment_state = sample_deployment_state(&bundle);
    let reporting_epoch = deployment_state
        .service_lease
        .as_ref()
        .expect("hosted service lease")
        .reporting_epoch;
    let lease_started_height = deployment_state
        .service_lease
        .as_ref()
        .expect("hosted service lease")
        .lease_started_height;
    let placement_incarnation = Hash::new(b"placement-1");
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        insert_service_deployment_fixture(world, &bundle, deployment_state.clone());
    }
    let temp_dir = canonical_runtime_fixture_tempdir()?;
    let mutation_sink = Arc::new(RecordingRuntimeMutationSink::default());
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf()),
        Arc::clone(&state),
    )
    .with_mutation_sink(mutation_sink.clone());
    let view = state.view();
    let stale_lease_started_height = lease_started_height.saturating_add(1);
    manager.submit_http_service_lease_usage_update(
        &view,
        (
            bundle.service.service_name.as_ref(),
            &bundle.service.service_version,
        ),
        (stale_lease_started_height, reporting_epoch),
        (1, placement_incarnation),
        8 * 1024 * 1024,
        false,
    );
    assert!(mutation_sink.submitted_service_lease_usage().is_empty());
    assert!(
        manager
            .last_service_lease_usage_submission_bytes
            .lock()
            .is_empty()
    );
    manager
        .last_service_lease_usage_submission_bytes
        .lock()
        .insert(
            (
                bundle.service.service_name.as_ref().to_owned(),
                bundle.service.service_version.clone(),
                stale_lease_started_height,
                reporting_epoch,
                1,
                placement_incarnation.to_string(),
            ),
            HostedHttpLeaseUsageSubmissionAttempt {
                accounted_egress_bytes: 0,
                finalize_reporter: false,
                attempted_at_ms: soracloud_runtime_observed_at_ms(),
            },
        );
    manager.submit_http_service_lease_usage_update(
        &view,
        (
            bundle.service.service_name.as_ref(),
            &bundle.service.service_version,
        ),
        (lease_started_height, reporting_epoch),
        (1, placement_incarnation),
        8 * 1024 * 1024,
        false,
    );
    manager.submit_http_service_lease_usage_update(
        &view,
        (
            bundle.service.service_name.as_ref(),
            &bundle.service.service_version,
        ),
        (lease_started_height, reporting_epoch),
        (1, placement_incarnation),
        8 * 1024 * 1024,
        false,
    );
    let submission_key = (
        bundle.service.service_name.as_ref().to_owned(),
        bundle.service.service_version.clone(),
        lease_started_height,
        reporting_epoch,
        1,
        placement_incarnation.to_string(),
    );
    manager
        .last_service_lease_usage_submission_bytes
        .lock()
        .get_mut(&submission_key)
        .expect("recorded usage submission")
        .attempted_at_ms = 0;
    manager.submit_http_service_lease_usage_update(
        &view,
        (
            bundle.service.service_name.as_ref(),
            &bundle.service.service_version,
        ),
        (lease_started_height, reporting_epoch),
        (1, placement_incarnation),
        8 * 1024 * 1024,
        false,
    );
    drop(view);
    let submitted_usage = mutation_sink.submitted_service_lease_usage();
    assert_eq!(
        submitted_usage.len(),
        2,
        "identical lease-usage reports should retry after the bounded suppression window"
    );
    assert_eq!(submitted_usage[0].replica_slot, 1);
    assert_eq!(
        submitted_usage[0].lease_started_height,
        lease_started_height
    );
    assert_eq!(submitted_usage[0].reporting_epoch, reporting_epoch);
    assert!(!submitted_usage[0].finalize_reporter);
    assert_eq!(
        submitted_usage[0].replica_accounted_egress_bytes, 0,
        "a recovered nonzero durable counter must first open its reporter identity at zero"
    );
    let mut opened_state = test_state();
    let mut opened_deployment = deployment_state.clone();
    let opened_lease = opened_deployment.service_lease.as_mut().expect("lease");
    opened_lease.egress_reporter_checkpoints = vec![sample_lease_egress_checkpoint(
        (reporting_epoch, lease_started_height),
        bundle.service.service_version.clone(),
        1,
        placement_incarnation,
        ALICE_ID.clone(),
        0,
        false,
    )];
    opened_lease
        .refresh_accounted_egress_bytes()
        .expect("exact opened reporter aggregate");
    {
        let world = &mut Arc::get_mut(&mut opened_state)
            .expect("unique opened test state")
            .world;
        insert_service_deployment_fixture(world, &bundle, opened_deployment);
    }
    let opened_manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf())
            .with_local_host_identity(ALICE_ID.clone(), "12D3KooWUsageReporter"),
        Arc::clone(&opened_state),
    )
    .with_mutation_sink(mutation_sink.clone());
    let opened_view = opened_state.view();
    opened_manager.submit_http_service_lease_usage_update(
        &opened_view,
        (
            bundle.service.service_name.as_ref(),
            &bundle.service.service_version,
        ),
        (lease_started_height, reporting_epoch),
        (1, placement_incarnation),
        8 * 1024 * 1024,
        false,
    );
    drop(opened_view);
    let submitted_usage = mutation_sink.submitted_service_lease_usage();
    assert_eq!(submitted_usage.len(), 3);
    assert_eq!(
        submitted_usage[2].replica_accounted_egress_bytes,
        8 * 1024 * 1024,
        "preserved usage must follow the authoritative zero opener"
    );

    let mut caught_up_state = test_state();
    let mut caught_up_deployment = deployment_state;
    let caught_up_lease = caught_up_deployment.service_lease.as_mut().expect("lease");
    caught_up_lease.egress_reporter_checkpoints = vec![sample_lease_egress_checkpoint(
        (reporting_epoch, lease_started_height),
        bundle.service.service_version.clone(),
        1,
        placement_incarnation,
        ALICE_ID.clone(),
        8 * 1024 * 1024,
        false,
    )];
    caught_up_lease
        .refresh_accounted_egress_bytes()
        .expect("exact caught-up reporter aggregate");
    {
        let world = &mut Arc::get_mut(&mut caught_up_state)
            .expect("unique caught-up test state")
            .world;
        insert_service_deployment_fixture(world, &bundle, caught_up_deployment);
    }
    let caught_up_manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(temp_dir.path().to_path_buf())
            .with_local_host_identity(ALICE_ID.clone(), "12D3KooWUsageReporter"),
        Arc::clone(&caught_up_state),
    )
    .with_mutation_sink(mutation_sink.clone());
    let caught_up_view = caught_up_state.view();
    caught_up_manager.submit_http_service_lease_usage_update(
        &caught_up_view,
        (
            bundle.service.service_name.as_ref(),
            &bundle.service.service_version,
        ),
        (lease_started_height, reporting_epoch),
        (1, placement_incarnation),
        8 * 1024 * 1024,
        false,
    );
    drop(caught_up_view);
    assert_eq!(
        mutation_sink.submitted_service_lease_usage().len(),
        3,
        "no additional lease-usage report should be submitted once authoritative state matches"
    );
    Ok(())
}
