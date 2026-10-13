// Actual geometry mutation under one retained publication boundary.

fn held_geometry_transition<'input>(
    kura: &'input Kura,
    previous: &'input LaneConfig,
    updated: &'input LaneConfig,
    previous_incarnations: &'input BTreeMap<LaneId, Hash>,
    updated_incarnations: &'input BTreeMap<LaneId, Hash>,
    previous_activations: &'input BTreeMap<LaneId, u64>,
    updated_activations: &'input BTreeMap<LaneId, u64>,
    replaced: &'input BTreeSet<LaneId>,
) -> (
    crate::kura::publication_lease::KuraPublicationLease<'input>,
    RawGeometryAttempt,
) {
    let lease = kura.try_publication_lease().unwrap();
    let previous_bindings = kura
        .geometry_bindings(previous, previous_incarnations, previous_activations)
        .unwrap();
    let updated_bindings = kura
        .geometry_bindings(updated, updated_incarnations, updated_activations)
        .unwrap();
    let request = GeometryBindingRequest {
        previous,
        updated,
        previous_incarnations,
        updated_incarnations,
        previous_activation_heights: previous_activations,
        updated_activation_heights: updated_activations,
        previous_lineage_root: unscoped_lineage_root(&previous_bindings),
        updated_lineage_root: unscoped_lineage_root(&updated_bindings),
        transition_height: 9,
    };
    let prepared = lease
        .begin_raw_geometry_attempt(&request, replaced)
        .unwrap();
    (lease, prepared)
}

fn held_geometry_catalog(
    kura: &Kura,
    config: &LaneConfig,
    incarnations: &BTreeMap<LaneId, Hash>,
    activations: &BTreeMap<LaneId, u64>,
) -> guarded_publication::PreparedLaneGeometryCatalog {
    let bindings = kura
        .geometry_bindings(config, incarnations, activations)
        .unwrap();
    guarded_publication::PreparedLaneGeometryCatalog {
        fingerprint: geometry_catalog_fingerprint(&bindings),
        lineage_root: unscoped_lineage_root(&bindings),
        bindings,
        configured_baseline: None,
        journal: kura.read_lane_geometry_journal().unwrap(),
    }
}

fn assert_geometry_fences_owned(kura: &Kura) {
    for lock in [
        &kura.prune_lock,
        &kura.canonical_chain_lock,
        &kura.lane_geometry_lock,
        &kura.sidecar_lock,
    ] {
        assert!(lock.try_lock_or_wait().is_err());
    }
}

#[test]
fn guarded_geometry_apply_and_catalog_retry_keep_one_physical_boundary() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("kura");
    let (previous, updated) = initial_and_extended_configs();
    let (previous_incarnations, previous_activations) = initial_geometry();
    let (updated_incarnations, updated_activations) = extended_geometry();
    let kura = open_kura(&root, &previous);
    authenticate_transition_fixture_primary(&kura, &previous, &previous_incarnations);
    let replaced = BTreeSet::new();
    let (lease, mut prepared) = held_geometry_transition(
        &kura,
        &previous,
        &updated,
        &previous_incarnations,
        &updated_incarnations,
        &previous_activations,
        &updated_activations,
        &replaced,
    );
    assert!(std::ptr::eq(lease.original_kura(), &raw const *kura));
    assert_geometry_fences_owned(&kura);
    prepared.resume_under(&lease).unwrap();
    assert_geometry_fences_owned(&kura);
    let files_applied = kura.read_lane_geometry_journal().unwrap();
    assert_eq!(files_applied.records.len(), 1);
    assert_eq!(
        files_applied.records[0].phase,
        LaneGeometryPhase::FilesApplied
    );
    let exact_transition = files_applied.records[0].transition_id;
    let before = fs::read(kura.lane_geometry_journal_path()).unwrap();
    let new_binding = &files_applied.records[0].updated_bindings[1];
    kura.require_lane_marker(new_binding).unwrap();
    kura.fail_next_lane_geometry_publication_after_write_for_test();
    let error = prepared
        .publish_catalog_under(&lease, None)
        .expect_err("post-replacement failure retains the original catalog publication owner");
    assert!(error.to_string().contains("after journal replacement"));
    assert_eq!(prepared.phase(), RawGeometryPhase::PublishingCatalog);
    assert_ne!(fs::read(kura.lane_geometry_journal_path()).unwrap(), before);
    assert_geometry_fences_owned(&kura);
    let written = fs::read(kura.lane_geometry_journal_path()).unwrap();
    prepared.publish_catalog_under(&lease, None).unwrap();
    assert_eq!(
        fs::read(kura.lane_geometry_journal_path()).unwrap(),
        written
    );
    assert_eq!(prepared.phase(), RawGeometryPhase::CatalogPublished);
    let published = kura.read_lane_geometry_journal().unwrap();
    assert_eq!(published.records.len(), 1);
    assert_eq!(published.records[0].transition_id, exact_transition);
    assert_eq!(
        published.records[0].phase,
        LaneGeometryPhase::CatalogPublished
    );
    assert_geometry_fences_owned(&kura);
    drop(lease);
    drop(
        kura.try_publication_lease()
            .expect("all original fences released"),
    );
    // Structural fixture retry reaches the same retained operation implementation.
    kura.apply_lane_geometry_transition_at_height(
        &previous,
        &updated,
        &previous_incarnations,
        &updated_incarnations,
        &previous_activations,
        &updated_activations,
        &replaced,
        9,
    )
    .unwrap();
    assert_eq!(kura.read_lane_geometry_journal().unwrap(), published);
}

#[test]
fn guarded_geometry_foreign_catalog_refusal_preserves_files_and_releases_on_drop() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("kura");
    let (previous, updated) = initial_and_extended_configs();
    let (previous_incarnations, previous_activations) = initial_geometry();
    let (updated_incarnations, updated_activations) = extended_geometry();
    let kura = open_kura(&root, &previous);
    authenticate_transition_fixture_primary(&kura, &previous, &previous_incarnations);
    let replaced = BTreeSet::new();
    let (lease, mut prepared) = held_geometry_transition(
        &kura,
        &previous,
        &updated,
        &previous_incarnations,
        &updated_incarnations,
        &previous_activations,
        &updated_activations,
        &replaced,
    );
    prepared.resume_under(&lease).unwrap();
    // This structural catalog fixture intentionally surrenders a complete
    // durable FilesApplied phase before testing its independent recovery path.
    prepared.surrender_structural_fixture();
    let original = fs::read(kura.lane_geometry_journal_path()).unwrap();
    lease
        .publish_prepared_lane_geometry_catalog(held_geometry_catalog(
            &kura,
            &previous,
            &previous_incarnations,
            &previous_activations,
        ))
        .expect_err("predecessor is not the exact uncertain successor");
    assert_eq!(
        fs::read(kura.lane_geometry_journal_path()).unwrap(),
        original
    );
    assert_geometry_fences_owned(&kura);
    drop(lease);
    drop(
        kura.try_publication_lease()
            .expect("refusal did not leak guards"),
    );
    kura.mark_lane_geometry_catalog_published(
        &updated,
        &updated_incarnations,
        &updated_activations,
        None,
    )
    .expect("structural fixture can finish the exact retained transition");
}
