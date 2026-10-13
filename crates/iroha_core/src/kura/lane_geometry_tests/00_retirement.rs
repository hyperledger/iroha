///
/// macOS exposes its temporary hierarchy through `/var` while canonical paths use
/// `/private/var`.  Geometry tests pass paths back into a Kura instance after startup, so the
/// harness must retain the canonical spelling selected by `Kura::new_inner`; otherwise exact
/// containment and test-hook identity comparisons fail before exercising the intended gate.
struct TempDir {
    _inner: RawTempDir,
    canonical_path: PathBuf,
}
impl TempDir {
    fn new() -> std::io::Result<Self> {
        let inner = RawTempDir::new()?;
        let canonical_path = fs::canonicalize(inner.path())?;
        Ok(Self {
            _inner: inner,
            canonical_path,
        })
    }
    fn path(&self) -> &Path {
        &self.canonical_path
    }
}
fn open_kura(root: &Path, lane_config: &RuntimeLaneConfig) -> Arc<Kura> {
    let config = kura_config(root);
    let kura = Kura::open_test_kura_with_configured_lane_config(&config, lane_config)
        .expect("open canonical-only test Kura")
        .0;
    kura.bind_lane_storage_network(geometry_fixture_network_id())
        .expect("bind the fixture's explicit network");
    kura
}
/// Resolve one exact fixture instance without consulting the current LaneId map.
fn geometry_fixture_blocks(
    kura: &Kura,
    entry: &LaneConfigEntry,
    incarnations: &BTreeMap<LaneId, Hash>,
    activations: &BTreeMap<LaneId, u64>,
) -> PathBuf {
    kura.binding_blocks_path(
        &kura
            .geometry_binding(entry, incarnations, activations)
            .expect("complete fixture instance identity"),
    )
}
fn wait_for_total_usage_scan_pause(kura: &Kura) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !kura.total_disk_usage_scan_paused_for_tests() {
        if Instant::now() >= deadline {
            kura.resume_total_disk_usage_scan_for_tests();
            panic!("disk-usage scan did not reach its deterministic publication barrier");
        }
        thread::yield_now();
    }
}
fn kura_config(root: &Path) -> KuraConfig {
    KuraConfig {
        init_mode: iroha_config::kura::InitMode::Strict,
        store_dir: WithOrigin::inline(root.to_path_buf()),
        max_disk_usage_bytes: MAX_DISK_USAGE_BYTES,
        blocks_in_memory: BLOCKS_IN_MEMORY,
        debug_output_new_blocks: false,
        fsync_mode: FsyncMode::Always,
        fsync_interval: FSYNC_INTERVAL,
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
    }
}
fn configured_primary_catalog(alias: &str) -> LaneCatalog {
    LaneCatalog::new(
        nonzero!(1_u32),
        vec![ModelLaneConfig {
            alias: alias.to_owned(),
            ..ModelLaneConfig::default()
        }],
    )
    .expect("configured primary-lane catalog")
}
fn assert_lane_paths_absent(root: &Path, _lane_config: &RuntimeLaneConfig) {
    assert!(
        !root.join("blocks/instances").exists(),
        "rejected pre-State startup must not create any instance block path"
    );
    assert!(
        !root.join("merge_ledger/instances").exists(),
        "rejected pre-State startup must not create any instance merge path"
    );
}
fn initial_and_extended_configs() -> (RuntimeLaneConfig, RuntimeLaneConfig) {
    let lane0 = ModelLaneConfig::default();
    let lane1 = ModelLaneConfig {
        id: LaneId::new(1),
        alias: "elastic-one".to_owned(),
        ..ModelLaneConfig::default()
    };
    let lane_count = NonZeroU32::new(2).expect("non-zero lane count");
    let initial = LaneCatalog::new(lane_count, vec![lane0.clone()]).expect("initial catalog");
    let extended = LaneCatalog::new(lane_count, vec![lane0, lane1]).expect("extended catalog");
    (
        RuntimeLaneConfig::from_catalog(&initial),
        RuntimeLaneConfig::from_catalog(&extended),
    )
}
fn initial_geometry() -> (BTreeMap<LaneId, Hash>, BTreeMap<LaneId, u64>) {
    (
        BTreeMap::from([(LaneId::SINGLE, Hash::prehashed([0x11; Hash::LENGTH]))]),
        BTreeMap::from([(LaneId::SINGLE, 0)]),
    )
}
fn extended_geometry() -> (BTreeMap<LaneId, Hash>, BTreeMap<LaneId, u64>) {
    (
        BTreeMap::from([
            (LaneId::SINGLE, Hash::prehashed([0x11; Hash::LENGTH])),
            (LaneId::new(1), Hash::prehashed([0x22; Hash::LENGTH])),
        ]),
        BTreeMap::from([(LaneId::SINGLE, 0), (LaneId::new(1), 9)]),
    )
}
fn persist_create_intent(
    kura: &Kura,
    previous: &RuntimeLaneConfig,
    updated: &RuntimeLaneConfig,
    previous_incarnations: &BTreeMap<LaneId, Hash>,
    updated_incarnations: &BTreeMap<LaneId, Hash>,
    previous_activations: &BTreeMap<LaneId, u64>,
    updated_activations: &BTreeMap<LaneId, u64>,
) -> LaneGeometryOperation {
    authenticate_transition_fixture_primary(kura, previous, previous_incarnations);
    let previous_bindings = kura
        .geometry_bindings(previous, previous_incarnations, previous_activations)
        .expect("previous geometry bindings");
    let updated_bindings = kura
        .geometry_bindings(updated, updated_incarnations, updated_activations)
        .expect("updated geometry bindings");
    let previous_catalog = geometry_catalog_fingerprint(&previous_bindings);
    let updated_catalog = geometry_catalog_fingerprint(&updated_bindings);
    let previous_lineage_root = unscoped_lineage_root(&previous_bindings);
    let updated_lineage_root = unscoped_lineage_root(&updated_bindings);
    let transition_id = geometry_transition_id(
        0,
        0,
        previous_catalog,
        previous_lineage_root,
        updated_catalog,
        updated_lineage_root,
    );
    let operations = kura
        .build_geometry_operations(
            transition_id,
            &previous_bindings,
            &updated_bindings,
            &BTreeSet::new(),
        )
        .expect("create operation");
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0].kind, LaneGeometryOperationKind::Create);
    let operation = operations[0].clone();
    let mut journal = kura
        .read_lane_geometry_journal()
        .expect("retain admitted H0 journal");
    assert!(
        journal.records.is_empty(),
        "fixture starts before its first intent"
    );
    journal.records.push(LaneGeometryIntent {
        transition_id,
        transition_sequence: 0,
        transition_height: 0,
        previous_catalog,
        previous_lineage_root,
        updated_catalog,
        updated_lineage_root,
        previous_bindings,
        updated_bindings,
        phase: LaneGeometryPhase::Intent,
        operations,
    });
    kura.write_lane_geometry_journal(&journal)
        .expect("persist create intent");
    operation
}
#[test]
fn before_first_height_cursor_replays_same_height_transitions_in_sequence() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("kura");
    let lane_count = nonzero!(3_u32);
    let primary = ModelLaneConfig::default();
    let second = ModelLaneConfig {
        id: LaneId::new(1),
        alias: "same-height-a".to_owned(),
        ..ModelLaneConfig::default()
    };
    let third = ModelLaneConfig {
        id: LaneId::new(2),
        alias: "same-height-b".to_owned(),
        ..second.clone()
    };
    let initial_catalog =
        LaneCatalog::new(lane_count, vec![primary.clone()]).expect("initial catalog");
    let added_catalog =
        LaneCatalog::new(lane_count, vec![primary.clone(), second.clone()]).expect("added catalog");
    let expanded_catalog =
        LaneCatalog::new(lane_count, vec![primary, second, third]).expect("expanded catalog");
    let initial = RuntimeLaneConfig::from_catalog(&initial_catalog);
    let added = RuntimeLaneConfig::from_catalog(&added_catalog);
    let expanded = RuntimeLaneConfig::from_catalog(&expanded_catalog);
    let initial_incarnations =
        BTreeMap::from([(LaneId::SINGLE, Hash::prehashed([0x51; Hash::LENGTH]))]);
    let added_incarnations = BTreeMap::from([
        (LaneId::SINGLE, initial_incarnations[&LaneId::SINGLE]),
        (LaneId::new(1), Hash::prehashed([0x52; Hash::LENGTH])),
    ]);
    let mut expanded_incarnations = added_incarnations.clone();
    expanded_incarnations.insert(LaneId::new(2), Hash::prehashed([0x53; Hash::LENGTH]));
    let initial_activations = BTreeMap::from([(LaneId::SINGLE, 0)]);
    let added_activations = BTreeMap::from([(LaneId::SINGLE, 0), (LaneId::new(1), 7)]);
    let mut expanded_activations = added_activations.clone();
    expanded_activations.insert(LaneId::new(2), 7);
    let kura = open_kura(&root, &initial);
    authenticate_transition_fixture_primary(&kura, &initial, &initial_incarnations);
    kura.apply_lane_geometry_transition_at_height(
        &initial,
        &added,
        &initial_incarnations,
        &added_incarnations,
        &initial_activations,
        &added_activations,
        &BTreeSet::new(),
        7,
    )
    .expect("apply first height-seven transition");
    kura.mark_lane_geometry_catalog_published(
        &added,
        &added_incarnations,
        &added_activations,
        None,
    )
    .expect("publish first height-seven transition");
    kura.apply_lane_geometry_transition_at_height(
        &added,
        &expanded,
        &added_incarnations,
        &expanded_incarnations,
        &added_activations,
        &expanded_activations,
        &BTreeSet::new(),
        7,
    )
    .expect("apply second height-seven transition");
    kura.mark_lane_geometry_catalog_published(
        &expanded,
        &expanded_incarnations,
        &expanded_activations,
        None,
    )
    .expect("publish second height-seven transition");
    let original = kura
        .read_lane_geometry_journal()
        .expect("published journal");
    let cursors = original
        .records
        .iter()
        .map(|record| (record.transition_id, record.transition_sequence))
        .collect::<Vec<_>>();
    assert_eq!(original.records.len(), 2);
    kura.recover_lane_geometry_journal_before_first_transition_at_height(
        &initial,
        &initial_incarnations,
        &initial_activations,
        7,
    )
    .expect("restore cursor before every transition at height seven");
    assert!(
        kura.read_lane_geometry_journal()
            .expect("rolled-back journal")
            .records
            .iter()
            .all(|record| record.phase == LaneGeometryPhase::RolledBack)
    );
    kura.apply_lane_geometry_transition_at_height(
        &initial,
        &added,
        &initial_incarnations,
        &added_incarnations,
        &initial_activations,
        &added_activations,
        &BTreeSet::new(),
        7,
    )
    .expect("retry first transition in sequence");
    kura.mark_lane_geometry_catalog_published(
        &added,
        &added_incarnations,
        &added_activations,
        None,
    )
    .expect("republish first transition");
    kura.apply_lane_geometry_transition_at_height(
        &added,
        &expanded,
        &added_incarnations,
        &expanded_incarnations,
        &added_activations,
        &expanded_activations,
        &BTreeSet::new(),
        7,
    )
    .expect("retry second transition in sequence");
    kura.mark_lane_geometry_catalog_published(
        &expanded,
        &expanded_incarnations,
        &expanded_activations,
        None,
    )
    .expect("republish second transition");
    let replayed = kura.read_lane_geometry_journal().expect("replayed journal");
    assert_eq!(
        replayed
            .records
            .iter()
            .map(|record| (record.transition_id, record.transition_sequence))
            .collect::<Vec<_>>(),
        cursors
    );
    assert!(
        replayed
            .records
            .iter()
            .all(|record| record.phase == LaneGeometryPhase::CatalogPublished)
    );
}
fn open_configured_anchor_for_publication_test(
    root: &Path,
    catalog: &LaneCatalog,
    primary_incarnation: Hash,
) -> Arc<Kura> {
    let baseline = LaneLifecycleParameterV1::catalog_hash(catalog);
    let lane_config = RuntimeLaneConfig::from_catalog(catalog);
    let (kura, _) =
        Kura::new_with_configured_lane_catalog(&kura_config(root), &lane_config, catalog)
            .expect("open the exact authenticated configured catalog");
    kura.bind_lane_storage_network(geometry_fixture_network_id())
        .expect("bind the exact configured fixture network");
    kura.establish_or_verify_configured_primary_geometry_anchor(
        lane_config.primary(),
        primary_incarnation,
        baseline,
    )
    .expect("anchor configured primary before catalog publication");
    kura
}
#[test]
fn post_write_publication_failure_restores_anchored_description_only_journal() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("kura");
    let mut lanes = LaneCatalog::default().lanes().to_vec();
    lanes[0].description = Some("operator-only catalog description".to_owned());
    let catalog = LaneCatalog::new(nonzero!(1_u32), lanes).expect("description-only lane catalog");
    let config = RuntimeLaneConfig::from_catalog(&catalog);
    let baseline = iroha_data_model::nexus::LaneLifecycleParameterV1::catalog_hash(&catalog);
    let (incarnations, activation_heights) = initial_geometry();
    let kura =
        open_configured_anchor_for_publication_test(&root, &catalog, incarnations[&LaneId::SINGLE]);
    let journal_path = kura.lane_geometry_journal_path();
    let prior_bytes = fs::read(&journal_path).expect("anchored journal");
    kura.apply_lane_geometry_transition(
        &config,
        &config,
        &incarnations,
        &incarnations,
        &activation_heights,
        &activation_heights,
        &BTreeSet::new(),
    )
    .expect("description-only catalog has no physical geometry transition");
    assert_eq!(
        fs::read(&journal_path).expect("unchanged journal"),
        prior_bytes
    );
    kura.fail_next_lane_geometry_publication_after_write_for_test();
    let error = kura
        .mark_lane_geometry_catalog_published(
            &config,
            &incarnations,
            &activation_heights,
            Some(baseline),
        )
        .expect_err("failure after target replacement must restore prior absence");
    assert!(
        !matches!(&error, Error::LaneGeometryPublicationRestoreFailed { .. }),
        "exact restoration should preserve the original injected publication error: {error}"
    );
    assert_eq!(
        fs::read(&journal_path).expect("restored anchored journal"),
        prior_bytes
    );
    let (restored_baseline, phases, has_temp) = kura
        .lane_geometry_journal_state_for_test()
        .expect("read restored absent journal state");
    assert_eq!(restored_baseline, Some(baseline));
    assert!(phases.is_empty());
    assert!(!has_temp, "rollback must not leave owned temp files");
    kura.mark_lane_geometry_catalog_published(
        &config,
        &incarnations,
        &activation_heights,
        Some(baseline),
    )
    .expect("one-shot failure permits an exact corrected retry");
    let (retried_baseline, phases, has_temp) = kura
        .lane_geometry_journal_state_for_test()
        .expect("read corrected publication");
    assert_eq!(retried_baseline, Some(baseline));
    assert!(phases.is_empty());
    assert!(!has_temp);
}
#[test]
fn publication_temp_recovery_consumes_only_an_exact_preexisting_value() {
    let catalog = LaneCatalog::default();
    let config = RuntimeLaneConfig::from_catalog(&catalog);
    let baseline = iroha_data_model::nexus::LaneLifecycleParameterV1::catalog_hash(&catalog);
    let (incarnations, activation_heights) = initial_geometry();
    let unrelated_temp = TempDir::new().expect("temporary directory");
    let unrelated_root = unrelated_temp.path().join("kura");
    let unrelated_kura = open_configured_anchor_for_publication_test(
        &unrelated_root,
        &catalog,
        incarnations[&LaneId::SINGLE],
    );
    let publication_temp = unrelated_root.join(JOURNAL_TEMP_FILE_NAME);
    fs::write(&publication_temp, b"operator-owned-temp").expect("seed unrelated temp");
    let error = unrelated_kura
        .mark_lane_geometry_catalog_published(
            &config,
            &incarnations,
            &activation_heights,
            Some(baseline),
        )
        .expect_err("an unrelated preexisting temp must fail closed");
    assert!(
        !matches!(&error, Error::LaneGeometryPublicationRestoreFailed { .. }),
        "an untouched preexisting temp does not make prior-target restoration ambiguous: {error}"
    );
    assert_eq!(
        fs::read(&publication_temp).expect("unrelated temp retained"),
        b"operator-owned-temp"
    );
    assert!(
        unrelated_kura.lane_geometry_journal_path().is_file(),
        "a temp collision must retain the authenticated target"
    );
    let resumable_temp = TempDir::new().expect("temporary directory");
    let resumable_root = resumable_temp.path().join("kura");
    let resumable_kura = open_configured_anchor_for_publication_test(
        &resumable_root,
        &catalog,
        incarnations[&LaneId::SINGLE],
    );
    let expected_journal = resumable_kura
        .read_lane_geometry_journal()
        .expect("anchored resumable journal");
    let publication_temp = resumable_root.join(JOURNAL_TEMP_FILE_NAME);
    fs::write(&publication_temp, expected_journal.encode()).expect("seed exact resume temp");
    resumable_kura.fail_next_lane_geometry_publication_after_write_for_test();
    let error = resumable_kura
        .mark_lane_geometry_catalog_published(
            &config,
            &incarnations,
            &activation_heights,
            Some(baseline),
        )
        .expect_err("inject failure after consuming exact resume temp");
    assert!(!matches!(
        &error,
        Error::LaneGeometryPublicationRestoreFailed { .. }
    ));
    assert!(
        !publication_temp.exists(),
        "an exact resumable temp is consumed by target replacement"
    );
    assert!(
        fs::read(resumable_kura.lane_geometry_journal_path())
            .expect("post-write rollback restores the authenticated target")
            == expected_journal.encode(),
        "post-write rollback must restore the exact authenticated target"
    );
}
#[test]
fn post_write_publication_failure_restores_exact_files_applied_journal() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("kura");
    let (initial, extended) = initial_and_extended_configs();
    let (initial_incarnations, initial_activations) = initial_geometry();
    let (extended_incarnations, extended_activations) = extended_geometry();
    let catalog = LaneCatalog::default();
    let baseline = LaneLifecycleParameterV1::catalog_hash(&catalog);
    let kura = open_configured_anchor_for_publication_test(
        &root,
        &catalog,
        initial_incarnations[&LaneId::SINGLE],
    );
    kura.apply_lane_geometry_transition(
        &initial,
        &extended,
        &initial_incarnations,
        &extended_incarnations,
        &initial_activations,
        &extended_activations,
        &BTreeSet::new(),
    )
    .expect("prepare files-applied geometry intent");
    let journal_path = kura.lane_geometry_journal_path();
    let prior_bytes = fs::read(&journal_path).expect("capture exact files-applied journal");
    let prior_journal =
        decode_exact::<LaneGeometryJournal>(&prior_bytes).expect("decode files-applied journal");
    assert_eq!(prior_journal.configured_catalog_hash, Some(baseline));
    assert_eq!(
        prior_journal.records.last().map(|record| record.phase),
        Some(LaneGeometryPhase::FilesApplied)
    );
    kura.fail_next_lane_geometry_publication_after_write_for_test();
    let error = kura
        .mark_lane_geometry_catalog_published(
            &extended,
            &extended_incarnations,
            &extended_activations,
            Some(baseline),
        )
        .expect_err("inject failure after replacing an existing journal");
    assert!(!matches!(
        &error,
        Error::LaneGeometryPublicationRestoreFailed { .. }
    ));
    assert_eq!(
        fs::read(&journal_path).expect("read restored journal"),
        prior_bytes,
        "rollback must restore the exact prior encoding, including FilesApplied phase"
    );
    let (restored_baseline, phases, has_temp) = kura
        .lane_geometry_journal_state_for_test()
        .expect("read exact restored journal state");
    assert_eq!(restored_baseline, Some(baseline));
    assert_eq!(phases, vec!["files_applied"]);
    assert!(!has_temp);
    kura.recover_lane_geometry_journal(&initial, &initial_incarnations, &initial_activations)
        .expect("restored FilesApplied intent remains available for State geometry rollback");
    assert_eq!(
        kura.read_lane_geometry_journal()
            .expect("journal after State-equivalent rollback")
            .records
            .last()
            .map(|record| record.phase),
        Some(LaneGeometryPhase::RolledBack)
    );
}
#[test]
fn publication_restore_failure_is_distinct_and_leaves_published_journal_fail_closed() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("kura");
    let (initial, extended) = initial_and_extended_configs();
    let (initial_incarnations, initial_activations) = initial_geometry();
    let (extended_incarnations, extended_activations) = extended_geometry();
    let catalog = LaneCatalog::default();
    let baseline = LaneLifecycleParameterV1::catalog_hash(&catalog);
    let kura = open_configured_anchor_for_publication_test(
        &root,
        &catalog,
        initial_incarnations[&LaneId::SINGLE],
    );
    kura.apply_lane_geometry_transition(
        &initial,
        &extended,
        &initial_incarnations,
        &extended_incarnations,
        &initial_activations,
        &extended_activations,
        &BTreeSet::new(),
    )
    .expect("prepare files-applied geometry intent");
    let prior_bytes =
        fs::read(kura.lane_geometry_journal_path()).expect("capture exact files-applied journal");
    let restore_temp = root.join(JOURNAL_RESTORE_TEMP_FILE_NAME);
    fs::write(&restore_temp, b"operator-owned-restore-temp").expect("seed restore-temp collision");
    kura.fail_next_lane_geometry_publication_after_write_for_test();
    let error = kura
        .mark_lane_geometry_catalog_published(
            &extended,
            &extended_incarnations,
            &extended_activations,
            Some(baseline),
        )
        .expect_err("restore-temp collision must prevent claiming exact restoration");
    assert!(matches!(
        &error,
        Error::LaneGeometryPublicationRestoreFailed { .. }
    ));
    assert_eq!(
        fs::read(&restore_temp).expect("restore collision retained"),
        b"operator-owned-restore-temp"
    );
    assert_ne!(
        fs::read(kura.lane_geometry_journal_path()).expect("published journal remains"),
        prior_bytes,
        "restore failure must not be reported as if the prior journal were restored"
    );
    let journal = kura
        .read_lane_geometry_journal()
        .expect("published journal remains internally valid");
    assert_eq!(journal.configured_catalog_hash, Some(baseline));
    assert_eq!(
        journal.records.last().map(|record| record.phase),
        Some(LaneGeometryPhase::CatalogPublished),
        "State must stop instead of rolling geometry back under a published journal"
    );
}
#[test]
fn startup_recovers_only_empty_instances_owned_by_exact_durable_intent() {
    for cut in 0..4 {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("kura");
        let (initial, extended) = initial_and_extended_configs();
        let (initial_incarnations, initial_activations) = initial_geometry();
        let (extended_incarnations, extended_activations) = extended_geometry();
        let kura = open_kura(&root, &initial);
        let operation = persist_create_intent(
            &kura,
            &initial,
            &extended,
            &initial_incarnations,
            &extended_incarnations,
            &initial_activations,
            &extended_activations,
        );
        let binding = &operation.created;
        let blocks = kura.binding_blocks_path(binding);
        if cut >= 1 {
            fs::create_dir_all(&blocks).unwrap();
        }
        if cut >= 2 {
            BlockStore::new(&blocks)
                .create_files_if_they_do_not_exist()
                .unwrap();
        }
        if cut >= 3 {
            kura.write_lane_marker(binding).unwrap();
        }
        let journal = fs::read(kura.lane_geometry_journal_path()).unwrap();
        drop(kura);
        let reopened =
            Kura::open_test_kura_with_configured_lane_config(&kura_config(&root), &initial)
                .expect("strict startup resumes admitted empty physical creation")
                .0;
        assert!(
            reopened.lane_storage_entries.lock().is_empty(),
            "physical repair grants no active producer"
        );
        reopened
            .require_exact_empty_journal_owned_storage_at(binding, &blocks)
            .unwrap();
        assert_eq!(
            fs::read(reopened.lane_geometry_journal_path()).unwrap(),
            journal,
            "physical recovery must not select or publish a catalog phase"
        );
    }
}

#[test]
fn startup_refuses_missing_completed_instance_even_without_auxiliary_namespace() {
    for phase in [
        LaneGeometryPhase::FilesApplied,
        LaneGeometryPhase::CatalogPublished,
        LaneGeometryPhase::RolledBack,
    ] {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("kura");
        let (initial, extended) = initial_and_extended_configs();
        let (initial_incarnations, initial_activations) = initial_geometry();
        let (extended_incarnations, extended_activations) = extended_geometry();
        let kura = open_kura(&root, &initial);
        let operation = persist_create_intent(
            &kura,
            &initial,
            &extended,
            &initial_incarnations,
            &extended_incarnations,
            &initial_activations,
            &extended_activations,
        );
        let binding = &operation.created;
        kura.prepare_journal_owned_lane_instance(
            binding,
            GeometryEvidencePolicy::AllowJournalIntentProvisioning,
        )
        .unwrap();
        let mut journal = kura.read_lane_geometry_journal().unwrap();
        journal.records[0].phase = phase;
        kura.write_lane_geometry_journal(&journal).unwrap();
        let blocks = kura.binding_blocks_path(binding);
        fs::remove_dir_all(&blocks).unwrap();
        let journal_bytes = fs::read(kura.lane_geometry_journal_path()).unwrap();
        drop(kura);
        Kura::open_test_kura_with_configured_lane_config(&kura_config(&root), &initial).expect_err(
            "a completed or rolled-back exact reference cannot manufacture missing storage",
        );
        assert!(!blocks.exists());
        assert_eq!(
            fs::read(root.join(JOURNAL_FILE_NAME)).unwrap(),
            journal_bytes
        );
    }
}

#[test]
fn journal_instance_recovery_refuses_occupied_and_unauthorized_targets_without_writes() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("kura");
    let (initial, extended) = initial_and_extended_configs();
    let (initial_incarnations, initial_activations) = initial_geometry();
    let (extended_incarnations, extended_activations) = extended_geometry();
    let kura = open_kura(&root, &initial);
    let operation = persist_create_intent(
        &kura,
        &initial,
        &extended,
        &initial_incarnations,
        &extended_incarnations,
        &initial_activations,
        &extended_activations,
    );
    let binding = &operation.created;
    let blocks = kura.binding_blocks_path(binding);
    let before = fs::read(kura.lane_geometry_journal_path()).unwrap();
    kura.canonical_storage_poisoned
        .store(true, Ordering::Release);
    let refused = kura.recover_journal_owned_lane_instances_on_startup();
    kura.canonical_storage_poisoned
        .store(false, Ordering::Release);
    assert!(matches!(refused, Err(Error::CanonicalStoragePoisoned)));
    assert!(
        !blocks.exists(),
        "ordinary recovery cannot use poisoned canonical state"
    );
    fs::create_dir_all(&blocks).unwrap();
    let foreign = blocks.join("foreign-unowned-data");
    fs::write(&foreign, b"must remain unchanged").unwrap();
    kura.recover_journal_owned_lane_instances_on_startup()
        .expect_err("intent cannot adopt occupied target");
    assert_eq!(fs::read(&foreign).unwrap(), b"must remain unchanged");
    assert!(!blocks.join(MARKER_FILE_NAME).exists());
    assert_eq!(fs::read(kura.lane_geometry_journal_path()).unwrap(), before);
}

#[test]
fn startup_rejects_nonempty_instance_scaffolding_without_repair() {
    // These files are temporary empty scaffolding, not a second canonical store.
    // Their removal remains a separate connected schema change.
    for role in 0..4 {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("kura");
        let (initial, _) = initial_and_extended_configs();
        let kura = open_kura(&root, &initial);
        authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
        let entry = kura.lane_storage_entry(LaneId::SINGLE).unwrap();
        let blocks = entry.blocks_dir(&root);
        let path = match role {
            0 => blocks.join(DATA_FILE_NAME),
            1 => blocks.join(INDEX_FILE_NAME),
            2 => blocks.join(HASHES_FILE_NAME),
            _ => blocks.join(COUNT_FILE_NAME),
        };
        let journal_path = kura.lane_geometry_journal_path();
        let journal = fs::read(&journal_path).unwrap();
        drop(kura);
        let bytes = b"foreign nonempty instance base";
        fs::write(&path, bytes).unwrap();
        assert!(
            Kura::open_test_kura_with_configured_lane_config(&kura_config(&root), &initial)
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::read(&journal_path).unwrap(), journal);
    }
}

fn assert_geometry_io_error(error: &Error, expected_kind: ErrorKind, expected_message: &str) {
    let Error::IO(source, _) = error else {
        panic!("unexpected lane geometry error: {error:?}");
    };
    assert_eq!(source.kind(), expected_kind, "lane geometry error: {error}");
    assert_eq!(source.to_string(), expected_message);
}

// Structural storage identity only: these outputs never mint native execution authority.
fn store_structural_geometry_chain(kura: &Kura, height: u64) -> (HashOf<BlockHeader>, Hash) {
    assert!(height > 0, "storage test chain must contain a block");
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
        .expect("original native fixture execution");
    while chain.height() < height {
        chain.commit(Vec::new());
    }
    let current = u64::try_from(kura.exact_durable_blocks_count().unwrap()).unwrap();
    for retained in 1..=current {
        assert_eq!(
            kura.get_durable_block_hash(
                NonZeroUsize::new(usize::try_from(retained).expect("fixture value fits usize"))
                    .unwrap()
            ),
            Some(chain.committed(retained).block_hash()),
            "retain original fixture prefix"
        );
    }
    for next in current + 1..=height {
        kura.store_block(chain.committed(next).block().clone())
            .expect("store original executed native carrier");
    }
    let height_usize = NonZeroUsize::new(usize::try_from(height).expect("height fits usize"))
        .expect("non-zero height");
    let block_hash = kura
        .get_durable_block_hash(height_usize)
        .expect("structural storage fixture block hash");
    let state_hash = Hash::new([0xC0, u8::try_from(height).unwrap_or(u8::MAX)]);
    (block_hash, state_hash)
}

#[test]
fn completed_instance_missing_marker_cannot_resume_provisioning() {
    for phase in [
        LaneGeometryPhase::FilesApplied,
        LaneGeometryPhase::CatalogPublished,
        LaneGeometryPhase::RolledBack,
    ] {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("kura");
        let (initial, extended) = initial_and_extended_configs();
        let (initial_incarnations, initial_activations) = initial_geometry();
        let (extended_incarnations, extended_activations) = extended_geometry();
        let kura = open_kura(&root, &initial);
        let operation = persist_create_intent(
            &kura,
            &initial,
            &extended,
            &initial_incarnations,
            &extended_incarnations,
            &initial_activations,
            &extended_activations,
        );
        kura.prepare_journal_owned_lane_instance(
            &operation.created,
            GeometryEvidencePolicy::AllowJournalIntentProvisioning,
        )
        .unwrap();
        let mut journal = kura.read_lane_geometry_journal().unwrap();
        journal.records[0].phase = phase;
        kura.write_lane_geometry_journal(&journal).unwrap();
        let blocks = kura.binding_blocks_path(&operation.created);
        fs::remove_file(blocks.join(MARKER_FILE_NAME)).unwrap();
        let original_files = [
            DATA_FILE_NAME,
            INDEX_FILE_NAME,
            HASHES_FILE_NAME,
            COUNT_FILE_NAME,
        ]
        .map(|name| fs::read(blocks.join(name)).unwrap());
        let original_journal = fs::read(kura.lane_geometry_journal_path()).unwrap();
        drop(kura);
        assert!(
            Kura::open_test_kura_with_configured_lane_config(&kura_config(&root), &initial)
                .is_err()
        );
        assert!(!blocks.join(MARKER_FILE_NAME).exists());
        assert_eq!(
            [
                DATA_FILE_NAME,
                INDEX_FILE_NAME,
                HASHES_FILE_NAME,
                COUNT_FILE_NAME
            ]
            .map(|name| fs::read(blocks.join(name)).unwrap()),
            original_files
        );
        assert_eq!(
            fs::read(root.join(JOURNAL_FILE_NAME)).unwrap(),
            original_journal
        );
    }
}
