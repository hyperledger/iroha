// Exact prepared journal phase ownership, independent of finality authorization.

fn unpersisted_create_journal(kura: &Kura) -> LaneGeometryJournal {
    let (previous, updated) = initial_and_extended_configs();
    let (previous_incarnations, previous_activations) = initial_geometry();
    let (updated_incarnations, updated_activations) = extended_geometry();
    let previous_bindings = kura
        .geometry_bindings(&previous, &previous_incarnations, &previous_activations)
        .unwrap();
    let updated_bindings = kura
        .geometry_bindings(&updated, &updated_incarnations, &updated_activations)
        .unwrap();
    let previous_catalog = geometry_catalog_fingerprint(&previous_bindings);
    let updated_catalog = geometry_catalog_fingerprint(&updated_bindings);
    let previous_lineage_root = unscoped_lineage_root(&previous_bindings);
    let updated_lineage_root = unscoped_lineage_root(&updated_bindings);
    let transition_id = geometry_transition_id(
        0,
        9,
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
        .unwrap();
    let mut journal = kura.read_lane_geometry_journal().unwrap();
    assert!(journal.records.is_empty());
    journal.records.push(LaneGeometryIntent {
        transition_id,
        transition_sequence: 0,
        transition_height: 9,
        previous_catalog,
        previous_lineage_root,
        updated_catalog,
        updated_lineage_root,
        previous_bindings,
        updated_bindings,
        phase: LaneGeometryPhase::Intent,
        operations,
    });
    journal
}

#[test]
fn prepared_geometry_journal_has_exact_phases_and_drop_writes_nothing() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("kura");
    let (initial, extended) = initial_and_extended_configs();
    let kura = open_kura(&root, &initial);
    authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
    let before = fs::read(kura.lane_geometry_journal_path()).unwrap();
    let journal = unpersisted_create_journal(&kura);
    let mut prepared =
        PreparedGeometryJournalTransition::prepare(&kura, journal.clone(), 0).unwrap();
    let retained = prepared.retained_allocation_bytes().unwrap();
    assert!(retained <= MAX_GEOMETRY_JOURNAL_BYTES);
    let phases = [
        LaneGeometryPhase::Intent,
        LaneGeometryPhase::FilesApplied,
        LaneGeometryPhase::CatalogPublished,
        LaneGeometryPhase::RolledBack,
    ];
    // Exercise every direction, including resetting a different phase patch
    // before applying the next one to the sole retained encoding buffer.
    for from in phases {
        prepared.bytes(from);
        for phase in phases {
            let mut expected = journal.clone();
            expected.records[0].phase = phase;
            assert_eq!(prepared.bytes(phase), expected.encode());
            assert_eq!(
                decode_exact::<LaneGeometryJournal>(prepared.bytes(phase)).unwrap(),
                expected
            );
            assert_eq!(prepared.retained_allocation_bytes(), Some(retained));
            prepared.bytes(from);
        }
    }
    assert_eq!(prepared.operations(), journal.records[0].operations);
    drop(prepared);
    assert_eq!(fs::read(kura.lane_geometry_journal_path()).unwrap(), before);
    assert!(
        !geometry_fixture_blocks(
            &kura,
            extended.entry(LaneId::new(1)).unwrap(),
            &extended_geometry().0,
            &extended_geometry().1
        )
        .exists()
    );
}

#[test]
fn prepared_geometry_journal_bare_encoding_obeys_exact_admission_boundary() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("kura");
    let (initial, _) = initial_and_extended_configs();
    let kura = open_kura(&root, &initial);
    authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
    let before = fs::read(kura.lane_geometry_journal_path()).unwrap();
    let journal = unpersisted_create_journal(&kura);
    let encoded_len = journal.encoded_len();
    let canonical = journal.encode();
    assert_eq!(encoded_len, canonical.len());
    assert_eq!(
        prepared_journal::encode_bounded_geometry_journal(
            &root,
            &journal,
            u64::try_from(encoded_len).unwrap(),
        )
        .unwrap()
        .as_slice(),
        canonical.as_slice()
    );
    let refusal = prepared_journal::encode_bounded_geometry_journal(
        &root,
        &journal,
        u64::try_from(encoded_len - 1).unwrap(),
    )
    .unwrap_err();
    assert!(matches!(refusal, Error::IO(error, _) if error.kind() == ErrorKind::InvalidInput));
    assert_eq!(fs::read(kura.lane_geometry_journal_path()).unwrap(), before);
}

#[test]
fn prepared_geometry_journal_rejects_identity_and_capacity_before_writes() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("kura");
    let (initial, _) = initial_and_extended_configs();
    let kura = open_kura(&root, &initial);
    authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
    let before = fs::read(kura.lane_geometry_journal_path()).unwrap();
    let journal = unpersisted_create_journal(&kura);
    assert!(
        PreparedGeometryJournalTransition::prepare_phases(&root, journal.clone(), 0, 1).is_err()
    );
    assert!(PreparedGeometryJournalTransition::prepare(&kura, journal.clone(), 1).is_err());
    let prepared = PreparedGeometryJournalTransition::prepare(&kura, journal.clone(), 0).unwrap();
    let aggregate = prepared.retained_allocation_bytes().unwrap();
    assert!(aggregate > u64::try_from(journal.encode().len()).unwrap());
    let phase_only = PreparedGeometryJournalTransition::prepare_phases(
        &root,
        journal.clone(),
        0,
        MAX_GEOMETRY_JOURNAL_BYTES,
    )
    .unwrap()
    .retained_allocation_bytes()
    .unwrap();
    assert!(
        aggregate > phase_only,
        "the original predecessor has retained storage too"
    );
    assert!(
        PreparedGeometryJournalTransition::prepare_phases(
            &root,
            journal.clone(),
            0,
            phase_only - 1,
        )
        .is_err(),
        "the journal alone fitting cannot omit retained operations and phase changes"
    );
    let mut forged = journal;
    forged.records[0].transition_height += 1;
    assert!(PreparedGeometryJournalTransition::prepare(&kura, forged, 0).is_err());
    assert_eq!(fs::read(kura.lane_geometry_journal_path()).unwrap(), before);
}

#[test]
fn prepared_geometry_journal_finishes_renamed_phase_without_replacing_it() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("kura");
    let (initial, _) = initial_and_extended_configs();
    let kura = open_kura(&root, &initial);
    authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
    let journal = unpersisted_create_journal(&kura);
    let mut prepared = PreparedGeometryJournalTransition::prepare(&kura, journal, 0).unwrap();
    crate::kura::fail_bound_progress_intent_directory_sync_for_tests(0, 0);
    assert!(prepared.persist(&kura, LaneGeometryPhase::Intent).is_err());
    let path = kura.lane_geometry_journal_path();
    let renamed = secure_file_metadata::from_path(&path).unwrap();
    assert!(!root.join(JOURNAL_TEMP_FILE_NAME).exists());
    assert!(
        prepared
            .persist(&kura, LaneGeometryPhase::FilesApplied)
            .is_err()
    );
    // A retry must use the original promoted descriptor even if the temporary
    // name is now occupied. The occupant is not this attempt's object.
    let temporary = root.join(JOURNAL_TEMP_FILE_NAME);
    fs::write(&temporary, b"unrelated occupant").unwrap();
    prepared.persist(&kura, LaneGeometryPhase::Intent).unwrap();
    assert!(Kura::sidecar_metadata_same_object(
        &renamed,
        &secure_file_metadata::from_path(&path).unwrap()
    ));
    assert_eq!(fs::read(&temporary).unwrap(), b"unrelated occupant");
    assert_eq!(
        fs::read(&path).unwrap(),
        prepared.bytes(LaneGeometryPhase::Intent)
    );
    prepared.persist(&kura, LaneGeometryPhase::Intent).unwrap();
    assert!(Kura::sidecar_metadata_same_object(
        &renamed,
        &secure_file_metadata::from_path(&path).unwrap()
    ));
}

#[test]
fn prepared_geometry_journal_reattests_already_current_phase_without_replacement() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("kura");
    let (initial, _) = initial_and_extended_configs();
    let kura = open_kura(&root, &initial);
    authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
    let journal = unpersisted_create_journal(&kura);
    let mut first = PreparedGeometryJournalTransition::prepare(&kura, journal.clone(), 0).unwrap();
    first.persist(&kura, LaneGeometryPhase::Intent).unwrap();
    drop(first);

    let path = kura.lane_geometry_journal_path();
    let original = secure_file_metadata::from_path(&path).unwrap();
    let before = native_observation_tree(&root);
    let mut prepared = PreparedGeometryJournalTransition::prepare(&kura, journal, 0).unwrap();
    crate::kura::fail_bound_progress_intent_directory_sync_for_tests(0, 0);
    let error = prepared
        .persist(&kura, LaneGeometryPhase::Intent)
        .expect_err("an already-current phase must complete its directory durability barrier");
    assert!(
        error
            .to_string()
            .contains("injected bound progress append-intent directory sync failure"),
        "unexpected publication failure: {error:?}",
    );
    assert_eq!(native_observation_tree(&root), before);
    assert!(Kura::sidecar_metadata_same_object(
        &original,
        &secure_file_metadata::from_path(&path).unwrap(),
    ));
    assert!(!root.join(JOURNAL_TEMP_FILE_NAME).exists());

    prepared.persist(&kura, LaneGeometryPhase::Intent).unwrap();
    drop(prepared);
    assert_eq!(native_observation_tree(&root), before);
    assert!(Kura::sidecar_metadata_same_object(
        &original,
        &secure_file_metadata::from_path(&path).unwrap(),
    ));
    assert!(!root.join(JOURNAL_TEMP_FILE_NAME).exists());
}

#[test]
fn prepared_geometry_journal_rejects_same_bytes_pending_temp_replacement() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("kura");
    let (initial, _) = initial_and_extended_configs();
    let kura = open_kura(&root, &initial);
    authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
    let path = kura.lane_geometry_journal_path();
    let prior = fs::read(&path).unwrap();
    let original_target = secure_file_metadata::from_path(&path).unwrap();
    let journal = unpersisted_create_journal(&kura);
    let mut prepared = PreparedGeometryJournalTransition::prepare(&kura, journal, 0).unwrap();
    let intended = prepared.bytes(LaneGeometryPhase::Intent).to_vec();
    crate::kura::fail_next_bound_progress_intent_file_sync_for_tests();
    let error = prepared
        .persist(&kura, LaneGeometryPhase::Intent)
        .expect_err("file synchronization fails before publishing the pending temporary");
    assert!(
        error
            .to_string()
            .contains("injected retained geometry journal file sync failure"),
        "unexpected publication failure: {error:?}",
    );
    let temporary = root.join(JOURNAL_TEMP_FILE_NAME);
    assert_eq!(fs::read(&temporary).unwrap(), intended);
    assert_eq!(fs::read(&path).unwrap(), prior);
    assert!(Kura::sidecar_metadata_same_object(
        &original_target,
        &secure_file_metadata::from_path(&path).unwrap(),
    ));

    let original_temp = secure_file_metadata::from_path(&temporary).unwrap();
    let displaced = temp.path().join("retained-pending-temporary");
    fs::rename(&temporary, &displaced).unwrap();
    fs::write(&temporary, &intended).unwrap();
    let occupant = secure_file_metadata::from_path(&temporary).unwrap();
    assert!(!Kura::sidecar_metadata_same_object(
        &original_temp,
        &occupant
    ));
    let before = native_observation_tree(&root);
    prepared
        .persist(&kura, LaneGeometryPhase::Intent)
        .expect_err("retry cannot adopt a new temporary with the same bytes");
    drop(prepared);
    assert_eq!(native_observation_tree(&root), before);
    assert_eq!(fs::read(&displaced).unwrap(), intended);
    assert_eq!(fs::read(&path).unwrap(), prior);
    assert!(Kura::sidecar_file_metadata_unchanged(
        &original_target,
        &secure_file_metadata::from_path(&path).unwrap(),
    ));
    assert!(Kura::sidecar_file_metadata_unchanged(
        &occupant,
        &secure_file_metadata::from_path(&temporary).unwrap(),
    ));
}

#[test]
fn prepared_geometry_journal_rejects_same_bytes_predecessor_replacement() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("kura");
    let (initial, _) = initial_and_extended_configs();
    let kura = open_kura(&root, &initial);
    authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
    let path = kura.lane_geometry_journal_path();
    let prior = fs::read(&path).unwrap();
    let original_metadata = secure_file_metadata::from_path(&path).unwrap();
    let journal = unpersisted_create_journal(&kura);
    let mut prepared = PreparedGeometryJournalTransition::prepare(&kura, journal, 0).unwrap();

    let displaced = temp.path().join("original-journal");
    fs::rename(&path, &displaced).unwrap();
    fs::write(&path, &prior).unwrap();
    let replacement_metadata = secure_file_metadata::from_path(&path).unwrap();
    assert!(!Kura::sidecar_metadata_same_object(
        &original_metadata,
        &replacement_metadata,
    ));
    let before = native_observation_tree(&root);
    prepared
        .persist(&kura, LaneGeometryPhase::Intent)
        .expect_err("identical bytes in another file cannot replace the retained predecessor");
    drop(prepared);
    assert_eq!(native_observation_tree(&root), before);
    assert_eq!(fs::read(&displaced).unwrap(), prior);
    assert!(Kura::sidecar_file_metadata_unchanged(
        &replacement_metadata,
        &secure_file_metadata::from_path(&path).unwrap(),
    ));
    assert!(!root.join(JOURNAL_TEMP_FILE_NAME).exists());
}

#[test]
fn prepared_geometry_journal_rejects_parent_directory_replacement() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("kura");
    let (initial, _) = initial_and_extended_configs();
    let kura = open_kura(&root, &initial);
    authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
    let prior = fs::read(kura.lane_geometry_journal_path()).unwrap();
    let journal = unpersisted_create_journal(&kura);
    let mut prepared = PreparedGeometryJournalTransition::prepare(&kura, journal, 0).unwrap();

    let displaced = temp.path().join("original-kura-root");
    fs::rename(&root, &displaced).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(root.join(JOURNAL_FILE_NAME), &prior).unwrap();
    fs::write(root.join("replacement-owner"), b"unrelated directory").unwrap();
    let original_before = native_observation_tree(&displaced);
    let replacement_before = native_observation_tree(&root);
    prepared
        .persist(&kura, LaneGeometryPhase::Intent)
        .expect_err("publication must retain the captured parent directory");
    drop(prepared);
    assert_eq!(native_observation_tree(&displaced), original_before);
    assert_eq!(native_observation_tree(&root), replacement_before);
    assert!(!root.join(JOURNAL_TEMP_FILE_NAME).exists());
    assert!(!displaced.join(JOURNAL_TEMP_FILE_NAME).exists());
}

#[test]
fn prepared_geometry_journal_rejects_occupied_captured_absence() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("kura");
    let (initial, _) = initial_and_extended_configs();
    let kura = open_kura(&root, &initial);
    authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
    let journal = unpersisted_create_journal(&kura);
    let mut prepared = PreparedGeometryJournalTransition::prepare(&kura, journal, 0).unwrap();
    let intended = prepared.bytes(LaneGeometryPhase::Intent).to_vec();
    drop(prepared);
    let path = kura.lane_geometry_journal_path();
    // Opening Kura establishes its bootstrap journal. Remove only that file to
    // exercise captured absence while retaining the fixture's other storage.
    fs::remove_file(&path).expect("remove bootstrap journal for explicit absent-target fixture");
    assert!(
        !path.exists(),
        "fixture starts without an authenticated journal"
    );
    // An absent journal cannot authenticate a transition's predecessor. Exercise
    // the prepared writer's absence custody directly using already validated bytes.
    let mut writer =
        super::retained_journal::RetainedGeometryJournal::capture(&kura, intended.len()).unwrap();

    fs::write(&path, &intended).unwrap();
    let occupant_metadata = secure_file_metadata::from_path(&path).unwrap();
    let before = native_observation_tree(&root);
    writer
        .persist(&kura, LaneGeometryPhase::Intent, &intended)
        .expect_err("an occupied absent slot cannot become this owner's prior publication");
    drop(writer);
    assert_eq!(native_observation_tree(&root), before);
    assert_eq!(fs::read(&path).unwrap(), intended);
    assert!(Kura::sidecar_file_metadata_unchanged(
        &occupant_metadata,
        &secure_file_metadata::from_path(&path).unwrap(),
    ));
    assert!(!root.join(JOURNAL_TEMP_FILE_NAME).exists());
}

#[test]
fn prepared_geometry_journal_retry_uses_retained_bytes() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("kura");
    let (initial, _) = initial_and_extended_configs();
    let kura = open_kura(&root, &initial);
    authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
    let journal = unpersisted_create_journal(&kura);
    let mut prepared =
        PreparedGeometryJournalTransition::prepare(&kura, journal.clone(), 0).unwrap();
    let temporary = root.join(JOURNAL_TEMP_FILE_NAME);
    fs::create_dir(&temporary).unwrap();
    assert!(prepared.persist(&kura, LaneGeometryPhase::Intent).is_err());
    fs::remove_dir(&temporary).unwrap();
    for phase in [
        LaneGeometryPhase::Intent,
        LaneGeometryPhase::FilesApplied,
        LaneGeometryPhase::CatalogPublished,
    ] {
        let mut expected = journal.clone();
        expected.records[0].phase = phase;
        for _ in 0..2 {
            prepared.persist(&kura, phase).unwrap();
            let persisted = fs::read(kura.lane_geometry_journal_path()).unwrap();
            assert_eq!(persisted, expected.encode());
            assert_eq!(persisted, prepared.bytes(phase));
            assert_eq!(
                decode_exact::<LaneGeometryJournal>(&persisted).unwrap(),
                expected
            );
            assert!(!temporary.exists());
        }
    }
}

#[test]
fn prepared_geometry_non_tail_retry_preserves_rolled_back_successor_history() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("kura");
    let (initial, extended) = initial_and_extended_configs();
    let (initial_incarnations, initial_activations) = initial_geometry();
    let (extended_incarnations, extended_activations) = extended_geometry();
    let third = RuntimeLaneConfig::from_catalog(
        &LaneCatalog::new(
            nonzero!(3_u32),
            vec![
                ModelLaneConfig::default(),
                ModelLaneConfig {
                    id: LaneId::new(1),
                    alias: "elastic-one".to_owned(),
                    ..ModelLaneConfig::default()
                },
                ModelLaneConfig {
                    id: LaneId::new(2),
                    alias: "elastic-two".to_owned(),
                    ..ModelLaneConfig::default()
                },
            ],
        )
        .unwrap(),
    );
    let mut third_incarnations = extended_incarnations.clone();
    third_incarnations.insert(LaneId::new(2), Hash::prehashed([0x33; Hash::LENGTH]));
    let mut third_activations = extended_activations.clone();
    third_activations.insert(LaneId::new(2), 10);
    let configs = [&initial, &extended, &third];
    let incarnations = [
        &initial_incarnations,
        &extended_incarnations,
        &third_incarnations,
    ];
    let activations = [
        &initial_activations,
        &extended_activations,
        &third_activations,
    ];
    let kura = open_kura(&root, &initial);
    for index in 0..2 {
        kura.apply_lane_geometry_transition_at_height(
            configs[index],
            configs[index + 1],
            incarnations[index],
            incarnations[index + 1],
            activations[index],
            activations[index + 1],
            &BTreeSet::new(),
            9 + index as u64,
        )
        .unwrap();
        kura.mark_lane_geometry_catalog_published(
            configs[index + 1],
            incarnations[index + 1],
            activations[index + 1],
            None,
        )
        .unwrap();
    }
    // An earlier record cannot become uncertain while a later one is published.
    // The production retry must first reconcile the actual durable history.
    let published = kura.read_lane_geometry_journal().unwrap();
    assert!(PreparedGeometryJournalTransition::prepare(&kura, published, 0).is_err());
    kura.recover_lane_geometry_journal(&initial, &initial_incarnations, &initial_activations)
        .unwrap();
    let rolled_back = kura.read_lane_geometry_journal().unwrap();
    assert_eq!(rolled_back.records.len(), 2);
    assert!(
        rolled_back
            .records
            .iter()
            .all(|record| record.phase == LaneGeometryPhase::RolledBack)
    );
    let before = fs::read(kura.lane_geometry_journal_path()).unwrap();
    let mut prepared =
        PreparedGeometryJournalTransition::prepare(&kura, rolled_back.clone(), 0).unwrap();
    for phase in [
        LaneGeometryPhase::Intent,
        LaneGeometryPhase::FilesApplied,
        LaneGeometryPhase::CatalogPublished,
        LaneGeometryPhase::RolledBack,
    ] {
        let decoded = decode_exact::<LaneGeometryJournal>(prepared.bytes(phase)).unwrap();
        validate_lane_geometry_journal_structure(&root, &decoded).unwrap();
        assert_eq!(decoded.records[0].phase, phase);
        assert_eq!(decoded.records[1], rolled_back.records[1]);
    }
    drop(prepared);
    assert_eq!(fs::read(kura.lane_geometry_journal_path()).unwrap(), before);
    for index in 0..2 {
        // These exact-height calls exercise the production existing-index branch,
        // including the newly prepared non-tail phase bytes on the first retry.
        kura.apply_lane_geometry_transition_at_height(
            configs[index],
            configs[index + 1],
            incarnations[index],
            incarnations[index + 1],
            activations[index],
            activations[index + 1],
            &BTreeSet::new(),
            9 + index as u64,
        )
        .unwrap();
        let replayed = kura.read_lane_geometry_journal().unwrap();
        assert_eq!(
            replayed.records[index].phase,
            LaneGeometryPhase::FilesApplied
        );
        if index == 0 {
            assert_eq!(replayed.records[1], rolled_back.records[1]);
        }
        kura.mark_lane_geometry_catalog_published(
            configs[index + 1],
            incarnations[index + 1],
            activations[index + 1],
            None,
        )
        .unwrap();
    }
    let replayed = kura.read_lane_geometry_journal().unwrap();
    assert_eq!(replayed.records.len(), 2);
    assert!(
        replayed
            .records
            .iter()
            .all(|record| record.phase == LaneGeometryPhase::CatalogPublished)
    );
}

#[test]
fn creation_journal_roundtrip_rejects_foreign_binding_and_missing_history_prefix() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("kura");
    let (initial, _) = initial_and_extended_configs();
    let kura = open_kura(&root, &initial);
    authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
    let journal = unpersisted_create_journal(&kura);
    assert_eq!(
        decode_exact::<LaneGeometryJournal>(&journal.encode()).unwrap(),
        journal
    );
    validate_lane_geometry_journal_structure(&root, &journal).unwrap();
    let before = fs::read(kura.lane_geometry_journal_path()).unwrap();
    for variant in 0..4 {
        let mut forged = journal.clone();
        let record = &mut forged.records[0];
        match variant {
            0 => record.operations[0].created.incarnation = Hash::new(b"foreign creation"),
            1 => {
                record.updated_bindings.remove(0);
            }
            2 => {
                record.transition_sequence = 1;
                record.transition_id = geometry_transition_id(
                    record.transition_sequence,
                    record.transition_height,
                    record.previous_catalog,
                    record.previous_lineage_root,
                    record.updated_catalog,
                    record.updated_lineage_root,
                );
            }
            _ => forged.configured_primary_binding = None,
        }
        assert!(PreparedGeometryJournalTransition::prepare(&kura, forged, 0).is_err());
        assert_eq!(fs::read(kura.lane_geometry_journal_path()).unwrap(), before);
    }
}

#[test]
fn exact_active_marker_rejects_each_foreign_identity_without_repair() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("kura");
    let (initial, _) = initial_and_extended_configs();
    let kura = open_kura(&root, &initial);
    authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
    let binding = kura
        .geometry_binding(
            initial.primary(),
            &initial_geometry().0,
            &initial_geometry().1,
        )
        .unwrap();
    let entry = LaneStorageEntry {
        identity: binding.identity(),
    };
    let path = entry.blocks_dir(&root).join(MARKER_FILE_NAME);
    let original = kura.read_lane_marker(&path).unwrap();
    assert_eq!(
        decode_exact::<LaneIncarnationMarker>(&original.encode()).unwrap(),
        original
    );
    assert_eq!(
        kura.active_lane_incarnation_marker(&entry).unwrap(),
        (binding.incarnation, 0)
    );
    kura.require_active_lane_incarnation(&entry, binding.incarnation, 1)
        .unwrap();
    assert!(
        kura.require_active_lane_incarnation(&entry, binding.incarnation, 0)
            .is_err()
    );
    for variant in 0..6 {
        let mut marker = original.clone();
        match variant {
            0 => marker.version -= 1,
            1 => marker.network_id = test_network_id(b"foreign marker network"),
            2 => marker.dataspace_id = DataSpaceId::new(99),
            3 => marker.lane_id = LaneId::new(99),
            4 => marker.incarnation = Hash::new(b"foreign marker incarnation"),
            _ => marker.activation_height += 1,
        }
        let bytes = marker.encode();
        fs::write(&path, &bytes).unwrap();
        assert!(kura.active_lane_incarnation_marker(&entry).is_err());
        assert!(
            kura.require_active_lane_incarnation(&entry, binding.incarnation, 2)
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}
