#[test]
fn unjournaled_nonzero_activation_without_marker_fails_closed_before_intent() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("kura");
    let (initial, extended) = initial_and_extended_configs();
    let (incarnations, activations) = extended_geometry();
    let kura = open_kura(&root, &initial);
    authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
    let binding = kura
        .geometry_binding(
            extended.entry(LaneId::new(1)).unwrap(),
            &incarnations,
            &activations,
        )
        .unwrap();
    kura.provision_geometry_binding(&binding).unwrap();
    let blocks = kura.binding_blocks_path(&binding);
    fs::remove_file(blocks.join(MARKER_FILE_NAME)).unwrap();
    let before = fs::read(kura.lane_geometry_journal_path()).unwrap();
    assert!(
        kura.ensure_authoritative_lane_markers(&extended, &incarnations, &activations)
            .is_err()
    );
    assert_eq!(fs::read(kura.lane_geometry_journal_path()).unwrap(), before);
    assert!(blocks.is_dir());
    assert!(!blocks.join(MARKER_FILE_NAME).exists());
}

#[test]
fn zero_file_create_intent_retains_exact_instance_through_rollback_and_replay() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("kura");
    let (initial, extended) = initial_and_extended_configs();
    let (initial_incarnations, initial_activations) = initial_geometry();
    let (extended_incarnations, extended_activations) = extended_geometry();
    let kura = open_kura(&root, &initial);
    authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
    let operation = persist_create_intent(
        &kura,
        &initial,
        &extended,
        &initial_incarnations,
        &extended_incarnations,
        &initial_activations,
        &extended_activations,
    );
    let updated = &operation.created;
    let live_blocks = kura.binding_blocks_path(updated);
    assert_eq!(
        kura.resolve_relative_path(&operation.created.blocks_path)
            .unwrap(),
        live_blocks
    );
    assert!(!live_blocks.exists());
    for _ in 0..2 {
        kura.recover_lane_geometry_journal(&initial, &initial_incarnations, &initial_activations)
            .expect("zero-file Intent rollback is idempotent");
        kura.require_complete_geometry_binding_at(updated, &live_blocks)
            .expect("rollback completes only its exact journal-owned empty storage");
        kura.require_lane_marker_value(
            &kura
                .read_lane_marker(&live_blocks.join(MARKER_FILE_NAME))
                .unwrap(),
            &live_blocks,
            updated,
        )
        .unwrap();
        assert!(
            !kura
                .lane_storage_entries
                .lock()
                .contains_key(&LaneId::new(1))
        );
        assert_eq!(
            kura.read_lane_geometry_journal().unwrap().records[0].phase,
            LaneGeometryPhase::RolledBack
        );
    }
    let marker_bytes = fs::read(live_blocks.join(MARKER_FILE_NAME)).unwrap();
    kura.recover_lane_geometry_journal(&extended, &extended_incarnations, &extended_activations)
        .expect("replay publishes the original retained instance reference");
    kura.require_complete_geometry_binding_at(updated, &live_blocks)
        .expect("created lane is complete after reference replay");
    assert!(!root.join("merge_ledger").exists());
    let unexpected = live_blocks.join("unexpected.norito");
    fs::write(&unexpected, b"foreign").expect("inject foreign storage entry");
    let error = preflight_empty_block_store_without_marker(&live_blocks, Some(updated), true)
        .expect_err("unexpected contents must fail empty-image preflight");
    assert_geometry_io_error(
        &error,
        ErrorKind::InvalidData,
        "unbound configured primary block store contains an unexpected entry",
    );
    assert_eq!(fs::read(&unexpected).unwrap(), b"foreign");
    fs::remove_file(&unexpected).expect("restore exact storage image");
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let data = live_blocks.join(DATA_FILE_NAME);
        let displaced = root.join("displaced-direct-data");
        fs::rename(&data, &displaced).expect("retain original direct file");
        symlink(&displaced, &data).expect("inject data symlink");
        let error = preflight_empty_block_store_without_marker(&live_blocks, Some(updated), true)
            .expect_err("symlinked canonical file must fail empty-image preflight");
        assert_geometry_io_error(
            &error,
            ErrorKind::InvalidData,
            "unbound configured primary block store contains an unsafe entry",
        );
        assert_eq!(fs::metadata(&displaced).unwrap().len(), 0);
        fs::remove_file(&data).expect("remove symlink");
        fs::rename(&displaced, &data).expect("restore original direct file");
    }
    assert_eq!(
        kura.read_lane_geometry_journal().unwrap().records[0].phase,
        LaneGeometryPhase::CatalogPublished
    );
    for _ in 0..2 {
        kura.recover_lane_geometry_journal(&initial, &initial_incarnations, &initial_activations)
            .expect("rollback removes the reference without relocating the owned storage");
        assert!(
            !kura
                .lane_storage_entries
                .lock()
                .contains_key(&LaneId::new(1))
        );
        kura.require_complete_geometry_binding_at(updated, &live_blocks)
            .expect("rollback cannot discard the owned instance");
        assert_eq!(
            fs::read(live_blocks.join(MARKER_FILE_NAME)).unwrap(),
            marker_bytes
        );
        kura.recover_lane_geometry_journal(
            &extended,
            &extended_incarnations,
            &extended_activations,
        )
        .expect("reference replay remains idempotent");
        assert_eq!(
            kura.lane_storage_entries.lock()[&LaneId::new(1)].identity,
            updated.identity()
        );
        assert_eq!(
            fs::read(live_blocks.join(MARKER_FILE_NAME)).unwrap(),
            marker_bytes
        );
        assert_eq!(
            kura.read_lane_geometry_journal().unwrap().records[0].phase,
            LaneGeometryPhase::CatalogPublished
        );
    }
}

#[test]
fn create_intent_repairs_authenticated_blocks_before_marker_for_rollback_and_replay() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("kura");
    let (initial, extended) = initial_and_extended_configs();
    let (initial_incarnations, initial_activations) = initial_geometry();
    let (extended_incarnations, extended_activations) = extended_geometry();
    let kura = open_kura(&root, &initial);
    authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
    let operation = persist_create_intent(
        &kura,
        &initial,
        &extended,
        &initial_incarnations,
        &extended_incarnations,
        &initial_activations,
        &extended_activations,
    );
    let updated = &operation.created;
    let staged = updated.clone();
    let staged_blocks = kura.binding_blocks_path(&staged);
    kura.provision_geometry_binding(&staged)
        .expect("provision journal-owned staging");
    fs::remove_file(staged_blocks.join(MARKER_FILE_NAME))
        .expect("inject crash before completion marker publication");
    assert!(!staged_blocks.join(MARKER_FILE_NAME).exists());
    kura.recover_lane_geometry_journal(&initial, &initial_incarnations, &initial_activations)
        .expect("rollback repairs authenticated partial provisioning");
    kura.require_complete_geometry_binding_at(updated, &staged_blocks)
        .expect("repaired rollback instance is complete at its original address");
    kura.require_lane_marker_value(
        &kura
            .read_lane_marker(&staged_blocks.join(MARKER_FILE_NAME))
            .unwrap(),
        &staged_blocks,
        updated,
    )
    .unwrap();
    kura.recover_lane_geometry_journal(&extended, &extended_incarnations, &extended_activations)
        .expect("replay consumes the repaired image");
    kura.require_complete_geometry_binding_at(updated, &kura.binding_blocks_path(updated))
        .expect("created binding is complete after replay");
}

#[test]
fn create_intent_rejects_marker_only_target_without_adopting_it() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("kura");
    let (initial, extended) = initial_and_extended_configs();
    let (initial_incarnations, initial_activations) = initial_geometry();
    let (extended_incarnations, extended_activations) = extended_geometry();
    let kura = open_kura(&root, &initial);
    authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
    let operation = persist_create_intent(
        &kura,
        &initial,
        &extended,
        &initial_incarnations,
        &extended_incarnations,
        &initial_activations,
        &extended_activations,
    );
    let staged_blocks = kura
        .resolve_relative_path(&operation.created.blocks_path)
        .expect("staged blocks");
    fs::create_dir_all(&staged_blocks).expect("create incomplete target");
    kura.write_lane_marker(&operation.created)
        .expect("inject marker-only target");
    let original_marker = fs::read(staged_blocks.join(MARKER_FILE_NAME)).unwrap();
    kura.recover_lane_geometry_journal(&extended, &extended_incarnations, &extended_activations)
        .expect_err("a completion marker without the original base files must fail closed");
    assert_eq!(
        fs::read(staged_blocks.join(MARKER_FILE_NAME)).unwrap(),
        original_marker
    );
    for name in [
        DATA_FILE_NAME,
        INDEX_FILE_NAME,
        HASHES_FILE_NAME,
        COUNT_FILE_NAME,
    ] {
        assert!(!staged_blocks.join(name).exists());
    }
    assert_eq!(
        kura.read_lane_geometry_journal().expect("journal").records[0].phase,
        LaneGeometryPhase::Intent
    );
}

#[test]
fn create_intent_rejects_complete_unsealed_foreign_storage() {
    for location in ["unexpected", "data"] {
        let temp = TempDir::new().expect("temporary directory");
        let root = temp.path().join(format!("kura-{location}"));
        let (initial, extended) = initial_and_extended_configs();
        let (initial_incarnations, initial_activations) = initial_geometry();
        let (extended_incarnations, extended_activations) = extended_geometry();
        let kura = open_kura(&root, &initial);
        authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
        let operation = persist_create_intent(
            &kura,
            &initial,
            &extended,
            &initial_incarnations,
            &extended_incarnations,
            &initial_activations,
            &extended_activations,
        );
        let updated = &operation.created;
        let injected = updated.clone();
        kura.provision_geometry_binding(&injected)
            .expect("provision valid-looking unsealed storage");
        let injected_blocks = kura.binding_blocks_path(&injected);
        let sentinel = if location == "unexpected" {
            injected_blocks.join("foreign-intent-payload")
        } else {
            injected_blocks.join(DATA_FILE_NAME)
        };
        fs::write(&sentinel, b"must-not-be-adopted").expect("inject foreign storage payload");
        let error = kura
            .recover_lane_geometry_journal(&extended, &extended_incarnations, &extended_activations)
            .expect_err("an unsealed nonempty storage must not gain authority from Intent");
        assert_geometry_io_error(
            &error,
            ErrorKind::InvalidData,
            if location == "unexpected" {
                "unbound configured primary block store contains an unexpected entry"
            } else {
                "unbound configured primary block store is not empty"
            },
        );
        assert_eq!(
            fs::read(&sentinel).expect("foreign payload retained for diagnosis"),
            b"must-not-be-adopted"
        );
        assert_eq!(
            kura.read_lane_geometry_journal().expect("journal").records[0].phase,
            LaneGeometryPhase::Intent
        );
    }
}

#[test]
fn terminal_geometry_replay_never_reauthorizes_empty_provisioning() {
    // A failed rollback of a published transition must retain `CatalogPublished`; otherwise a
    // restart could reinterpret it as a first-application Intent and manufacture empty state.
    {
        let temp = TempDir::new().expect("temporary directory");
        let root = temp.path().join("kura");
        let (initial, extended) = initial_and_extended_configs();
        let (initial_incarnations, initial_activations) = initial_geometry();
        let (extended_incarnations, extended_activations) = extended_geometry();
        let kura = open_kura(&root, &initial);
        authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
        kura.apply_lane_geometry_transition(
            &initial,
            &extended,
            &initial_incarnations,
            &extended_incarnations,
            &initial_activations,
            &extended_activations,
            &BTreeSet::new(),
        )
        .expect("apply create transition");
        kura.mark_lane_geometry_catalog_published(
            &extended,
            &extended_incarnations,
            &extended_activations,
            None,
        )
        .expect("publish create transition");
        let operation = kura
            .read_lane_geometry_journal()
            .expect("published journal")
            .records[0]
            .operations[0]
            .clone();
        let updated = &operation.created;
        fs::remove_dir_all(kura.binding_blocks_path(updated))
            .expect("simulate loss of published blocks");
        for _ in 0..2 {
            let error = kura
                .recover_lane_geometry_journal(
                    &initial,
                    &initial_incarnations,
                    &initial_activations,
                )
                .expect_err("missing published evidence must fail on every retry");
            assert_geometry_io_error(
                &error,
                ErrorKind::NotFound,
                "durable lane instance evidence is missing; refusing empty provisioning",
            );
            assert_eq!(
                kura.read_lane_geometry_journal().expect("journal").records[0].phase,
                LaneGeometryPhase::CatalogPublished
            );
            assert!(
                !kura
                    .resolve_relative_path(&operation.created.blocks_path)
                    .expect("unpublished blocks")
                    .exists()
            );
        }
    }
    // The inverse direction must likewise retain `RolledBack` when its authenticated retained
    // image disappears; replay is not authority to create a replacement from nothing.
    {
        let temp = TempDir::new().expect("temporary directory");
        let root = temp.path().join("kura");
        let (initial, extended) = initial_and_extended_configs();
        let (initial_incarnations, initial_activations) = initial_geometry();
        let (extended_incarnations, extended_activations) = extended_geometry();
        let kura = open_kura(&root, &initial);
        authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
        kura.apply_lane_geometry_transition(
            &initial,
            &extended,
            &initial_incarnations,
            &extended_incarnations,
            &initial_activations,
            &extended_activations,
            &BTreeSet::new(),
        )
        .expect("apply create transition");
        kura.recover_lane_geometry_journal(&initial, &initial_incarnations, &initial_activations)
            .expect("roll transition back to its retained image");
        let operation = kura
            .read_lane_geometry_journal()
            .expect("rolled-back journal")
            .records[0]
            .operations[0]
            .clone();
        let unpublished_blocks = kura
            .resolve_relative_path(&operation.created.blocks_path)
            .expect("unpublished blocks");
        fs::remove_dir_all(&unpublished_blocks).expect("simulate loss of retained block image");
        for _ in 0..2 {
            let error = kura
                .recover_lane_geometry_journal(
                    &extended,
                    &extended_incarnations,
                    &extended_activations,
                )
                .expect_err("missing retained evidence must fail on every retry");
            assert_geometry_io_error(
                &error,
                ErrorKind::NotFound,
                "durable lane instance evidence is missing; refusing empty provisioning",
            );
            assert_eq!(
                kura.read_lane_geometry_journal().expect("journal").records[0].phase,
                LaneGeometryPhase::RolledBack
            );
            assert!(!unpublished_blocks.exists());
        }
    }
}

#[test]
fn recovery_completes_partial_create_then_switches_references_idempotently() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("kura");
    let (initial, extended) = initial_and_extended_configs();
    let (initial_incarnations, initial_activations) = initial_geometry();
    let (extended_incarnations, extended_activations) = extended_geometry();
    let kura = open_kura(&root, &initial);
    authenticate_transition_fixture_primary(&kura, &initial, &initial_geometry().0);
    let operation = persist_create_intent(
        &kura,
        &initial,
        &extended,
        &initial_incarnations,
        &extended_incarnations,
        &initial_activations,
        &extended_activations,
    );
    let updated = &operation.created;
    kura.provision_geometry_binding(updated)
        .expect("provision authenticated empty storage");
    let blocks = kura.binding_blocks_path(updated);
    fs::remove_file(blocks.join(MARKER_FILE_NAME))
        .expect("crash after exact base file publication before completion marker");
    assert!(!blocks.join(MARKER_FILE_NAME).exists());
    for _ in 0..2 {
        kura.recover_lane_geometry_journal(&initial, &initial_incarnations, &initial_activations)
            .expect("idempotent rollback completes its interrupted creation");
        kura.require_complete_geometry_binding_at(updated, &blocks)
            .expect("all original base files are retained");
        assert!(
            !kura
                .lane_storage_entries
                .lock()
                .contains_key(&LaneId::new(1))
        );
    }
    let marker_bytes = fs::read(blocks.join(MARKER_FILE_NAME)).unwrap();
    for _ in 0..2 {
        kura.recover_lane_geometry_journal(
            &extended,
            &extended_incarnations,
            &extended_activations,
        )
        .expect("committed catalog selects the same retained instance");
        assert_eq!(
            kura.lane_storage_entries.lock()[&LaneId::new(1)].identity,
            updated.identity()
        );
        assert_eq!(
            fs::read(blocks.join(MARKER_FILE_NAME)).unwrap(),
            marker_bytes
        );
        assert!(blocks.join(MARKER_FILE_NAME).is_file());
    }
    assert_eq!(
        kura.read_lane_geometry_journal().unwrap().records[0].phase,
        LaneGeometryPhase::CatalogPublished
    );
}

#[test]
fn lane_instance_open_rejects_targets_materialized_after_preflight() {
    for directory in [true, false] {
        let temp = TempDir::new().expect("temporary directory");
        let root = temp.path().join("kura");
        let (initial, _) = initial_and_extended_configs();
        let kura = open_kura(&root, &initial);
        let binding = LaneGeometryBinding::from_identity(LaneStorageIdentity {
            network_id: geometry_fixture_network_id(),
            lane_id: LaneId::new(7),
            dataspace_id: ModelLaneConfig::default().dataspace_id,
            incarnation: Hash::new(b"post-preflight-collision"),
            activation_height: 1,
        });
        let mut open = kura
            .preflight_lane_instance_open(&binding)
            .expect("capture absent exact targets");
        kura.prepare_lane_instance_parents(&mut open)
            .expect("prepare authenticated parents");
        let path = kura.binding_blocks_path(&binding);
        if directory {
            fs::create_dir(&path).unwrap();
            fs::write(path.join("sentinel"), b"racing-foreign-directory").unwrap();
        } else {
            fs::write(&path, b"racing-foreign-file").unwrap();
        }
        Kura::reverify_storage_open_path(&mut open.paths, &path, false)
            .expect_err("the production pre-open boundary must reject a post-preflight occupant");
        if directory {
            assert_eq!(
                fs::read(path.join("sentinel")).unwrap(),
                b"racing-foreign-directory"
            );
            assert!(!path.join(MARKER_FILE_NAME).exists());
        } else {
            assert_eq!(fs::read(&path).unwrap(), b"racing-foreign-file");
            assert!(path.is_file());
        }
    }
}

#[cfg(unix)]
#[test]
fn lane_instance_provisioning_rejects_a_symlinked_target_parent() {
    use std::os::unix::fs::symlink;
    for parent_kind in ["blocks", "blocks/instances"] {
        let temp = TempDir::new().expect("temporary directory");
        let root = temp.path().join("kura");
        let (initial, _) = initial_and_extended_configs();
        let kura = open_kura(&root, &initial);
        let parent = root.join(parent_kind);
        fs::create_dir_all(parent.parent().unwrap()).unwrap();
        if parent.exists() {
            fs::rename(&parent, root.join("displaced-parent")).expect("retain original parent");
        }
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, &parent).expect("substitute the instance target parent");
        let binding = LaneGeometryBinding::from_identity(LaneStorageIdentity {
            network_id: geometry_fixture_network_id(),
            lane_id: LaneId::new(7),
            dataspace_id: ModelLaneConfig::default().dataspace_id,
            incarnation: Hash::new(b"symlinked-instance-parent"),
            activation_height: 1,
        });
        kura.provision_geometry_binding(&binding).expect_err(
            "instance provisioning must reject an ancestor symlink before opening children",
        );
        assert_eq!(
            fs::read_dir(&outside).unwrap().count(),
            0,
            "provisioning must not publish outside authenticated instance storage"
        );
        assert!(!kura.binding_blocks_path(&binding).exists());
    }
}
