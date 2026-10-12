//! Final publication must rejoin the original completed physical geometry owners.

use super::*;
use crate::kura::{RawGeometryAttempt, RawGeometryPhase};
use std::{fs, os::unix::fs::MetadataExt as _, path::Path};

fn with_retained_publication(
    completed: bool,
    test: impl FnOnce(&mut State, &Arc<Kura>, &LaneCatalog, &Path, &Path, Hash),
) {
    let temporary = tempfile::tempdir().expect("temporary geometry storage");
    let store_root = temporary.path().join("kura");
    let cold_root = temporary.path().join("cold");
    let configured = configured_baseline_test_catalog("retained-completion", None);
    let baseline = iroha_data_model::nexus::LaneLifecycleParameterV1::catalog_hash(&configured);
    let (kura, mut state) =
        authenticated_startup_state_for_testing(store_root.clone(), &configured);
    state
        .set_tiered_backend(&tiered_state_config!(cold_root.clone()))
        .expect("prepare the original tiered backend");
    kura.fail_next_lane_geometry_publication_for_test();
    let refusal = state
        .set_nexus_from_config(startup_nexus_for_catalog(configured.clone()))
        .expect_err("retain the actual startup operation before catalog publication");
    assert!(matches!(refusal, LaneLifecycleError::GeometryStorage(_)));
    {
        let mut slot = state.geometry_publication.lock();
        let original = slot
            .as_mut()
            .expect("the original publication remains owned");
        assert!(original.tiered.as_ref().unwrap().is_applied());
        assert!(original.cursors_updated);
        let raw = original.raw.as_mut().unwrap();
        assert_eq!(raw.phase(), RawGeometryPhase::FilesApplied);
        if completed {
            // Expose the real publication/retirement boundary without replacing
            // an owner or manufacturing a phase or a completion receipt.
            let lease = kura
                .try_publication_lease()
                .expect("original publication lease");
            raw.publish_catalog_under(&lease, Some(baseline))
                .expect("complete this original raw owner's durable publication");
            assert_eq!(raw.phase(), RawGeometryPhase::CatalogPublished);
            assert!(!raw.has_pending_journal_write());
        }
    }
    assert!(state.lane_storage_identity(LaneId::new(1)).is_none());
    assert_ne!(state.nexus_snapshot().lane_catalog, configured);
    test(
        &mut state,
        &kura,
        &configured,
        &store_root,
        &cold_root,
        baseline,
    );
}

fn original_owners(
    state: &State,
) -> (
    *const RawGeometryAttempt,
    *const tiered::TieredGeometryAttempt,
) {
    let slot = state.geometry_publication.lock();
    let original = slot.as_ref().expect("retain the original publication");
    (
        std::ptr::from_ref(original.raw.as_ref().unwrap()),
        std::ptr::from_ref(original.tiered.as_ref().unwrap()),
    )
}

fn finish_original(
    state: &State,
    baseline: Option<Hash>,
) -> Result<(), LaneGeometryCatalogPublicationFailure> {
    let (current, incarnations, activation_heights, lineage_root) = {
        let slot = state.geometry_publication.lock();
        let original = slot
            .as_ref()
            .expect("read the original requested coordinates");
        (
            original.current.clone(),
            original.current_incarnations.clone(),
            original.current_activation_heights.clone(),
            original.current_lineage_root,
        )
    };
    state.finish_lane_geometry_publication(
        &current,
        &incarnations,
        &activation_heights,
        lineage_root,
        baseline,
    )
}

fn assert_retained(
    state: &State,
    owners: (
        *const RawGeometryAttempt,
        *const tiered::TieredGeometryAttempt,
    ),
    phase: RawGeometryPhase,
) {
    assert_eq!(
        original_owners(state),
        owners,
        "retain both exact original owners"
    );
    let slot = state.geometry_publication.lock();
    let original = slot.as_ref().unwrap();
    assert_eq!(original.raw.as_ref().unwrap().phase(), phase);
    assert!(!original.raw.as_ref().unwrap().has_pending_journal_write());
    assert!(
        original.tiered.as_ref().unwrap().is_applied(),
        "completed tiered refusal preserves original forward progress"
    );
    assert!(original.cursors_updated);
    assert!(state.lane_storage_identity(LaneId::new(1)).is_none());
}

fn retry_original(state: &mut State, configured: &LaneCatalog, kura: &Kura, baseline: Hash) {
    state
        .set_nexus_from_config(startup_nexus_for_catalog(configured.clone()))
        .expect("the original exact operation succeeds after restoring its physical source");
    assert!(state.geometry_publication.lock().is_none());
    let published = state.nexus_snapshot();
    assert_eq!(published.lane_catalog, *configured);
    assert_eq!(published.configured_lane_catalog, *configured);
    assert!(state.lane_storage_identity(LaneId::new(1)).is_some());
    let (actual_baseline, phases, has_temp) = kura.lane_geometry_journal_state_for_test().unwrap();
    assert_eq!(actual_baseline, Some(baseline));
    assert_eq!(phases, vec!["catalog_published"]);
    assert!(!has_temp);
}

#[test]
fn completed_publication_refuses_substituted_journal_namespace_and_retries_original_owner() {
    with_retained_publication(true, |state, kura, configured, store_root, _, baseline| {
        let owners = original_owners(state);
        let journal = store_root.join("lane_geometry_journal.norito");
        let original_bytes = fs::read(&journal).unwrap();
        let original_metadata = fs::metadata(&journal).unwrap();
        let displaced = store_root.with_extension("original");
        // Move the containing namespace so the original journal's ctime, bytes,
        // and inode remain unchanged and an exact restoration is possible.
        fs::rename(store_root, &displaced).unwrap();
        fs::create_dir(store_root).unwrap();
        fs::write(&journal, &original_bytes).unwrap();
        assert_ne!(
            fs::metadata(&journal).unwrap().ino(),
            original_metadata.ino()
        );
        let result = finish_original(state, Some(baseline));
        assert!(
            result.is_err(),
            "completed publication refuses a substituted original journal namespace"
        );
        let failure = result.err().unwrap();
        assert!(matches!(
            failure.error,
            LaneLifecycleError::GeometryStorage(_)
        ));
        assert!(!failure.rollback_safe);
        assert_retained(state, owners, RawGeometryPhase::CatalogPublished);
        assert_eq!(fs::read(&journal).unwrap(), original_bytes);
        assert_ne!(state.nexus_snapshot().lane_catalog, *configured);
        fs::remove_file(&journal).unwrap();
        fs::remove_dir(store_root).unwrap();
        fs::rename(&displaced, store_root).unwrap();
        let restored = fs::metadata(&journal).unwrap();
        assert_eq!(restored.ino(), original_metadata.ino());
        assert_eq!(restored.dev(), original_metadata.dev());
        assert_eq!(restored.ctime(), original_metadata.ctime());
        assert_eq!(restored.ctime_nsec(), original_metadata.ctime_nsec());
        assert_eq!(fs::read(&journal).unwrap(), original_bytes);
        assert_retained(state, owners, RawGeometryPhase::CatalogPublished);
        retry_original(state, configured, kura, baseline);
        assert_eq!(
            fs::metadata(&journal).unwrap().ino(),
            original_metadata.ino()
        );
        assert_eq!(fs::read(&journal).unwrap(), original_bytes);
    });
}

fn substituted_tiered_path(completed: bool, resume_before_finish: bool) {
    with_retained_publication(
        completed,
        |state, kura, configured, store_root, cold_root, baseline| {
            let owners = original_owners(state);
            let phase = if completed {
                RawGeometryPhase::CatalogPublished
            } else {
                RawGeometryPhase::FilesApplied
            };
            let config = RuntimeLaneConfig::from_catalog(configured);
            let entry = config.entry(LaneId::new(1)).unwrap();
            let lane = cold_root.join("lanes").join(&entry.kura_segment);
            let displaced = lane.with_extension("original");
            let identity = fs::metadata(&lane).unwrap();
            let journal = store_root.join("lane_geometry_journal.norito");
            let before_journal = fs::read(&journal).unwrap();
            fs::rename(&lane, &displaced).unwrap();
            fs::create_dir(&lane).unwrap();
            assert_ne!(fs::metadata(&lane).unwrap().ino(), identity.ino());
            if resume_before_finish {
                let error = state
                    .set_nexus_from_config(startup_nexus_for_catalog(configured.clone()))
                    .expect_err("completed retry refuses substituted original tiered paths");
                assert!(matches!(error, LaneLifecycleError::Storage(_)));
            } else {
                let result = finish_original(state, Some(baseline));
                assert!(
                    result.is_err(),
                    "publication refuses a substituted original tiered directory"
                );
                let failure = result.err().unwrap();
                assert!(matches!(failure.error, LaneLifecycleError::Storage(_)));
                assert!(!failure.rollback_safe);
            }
            assert_retained(state, owners, phase);
            assert_eq!(fs::read(&journal).unwrap(), before_journal);
            assert_ne!(state.nexus_snapshot().lane_catalog, *configured);
            fs::remove_dir(&lane).unwrap();
            fs::rename(&displaced, &lane).unwrap();
            assert_eq!(fs::metadata(&lane).unwrap().ino(), identity.ino());
            assert_retained(state, owners, phase);
            retry_original(state, configured, kura, baseline);
            assert_eq!(fs::metadata(&lane).unwrap().ino(), identity.ino());
            if completed {
                assert_eq!(fs::read(&journal).unwrap(), before_journal);
            }
        },
    );
}

#[test]
fn prepublication_refuses_substituted_tiered_directory_and_retries_original_owner() {
    substituted_tiered_path(false, false);
}

#[test]
fn completed_publication_refuses_substituted_tiered_directory_and_retries_original_owner() {
    substituted_tiered_path(true, false);
}

#[test]
fn completed_retry_preserves_original_applied_progress_on_tiered_identity_refusal() {
    substituted_tiered_path(true, true);
}

#[test]
fn completed_publication_refuses_changed_baseline_and_retries_original_owner() {
    with_retained_publication(true, |state, kura, configured, store_root, _, baseline| {
        let owners = original_owners(state);
        let journal = store_root.join("lane_geometry_journal.norito");
        let original_bytes = fs::read(&journal).unwrap();
        let foreign = Hash::new(b"another configured catalog");
        assert_ne!(foreign, baseline);
        for changed in [None, Some(foreign)] {
            let result = finish_original(state, changed);
            assert!(
                result.is_err(),
                "completed publication refuses a changed original configured baseline"
            );
            let failure = result.err().unwrap();
            assert!(matches!(
                failure.error,
                LaneLifecycleError::GeometryStorage(_)
            ));
            assert!(!failure.rollback_safe);
            assert_retained(state, owners, RawGeometryPhase::CatalogPublished);
            assert_eq!(fs::read(&journal).unwrap(), original_bytes);
            assert_ne!(state.nexus_snapshot().lane_catalog, *configured);
        }
        retry_original(state, configured, kura, baseline);
        assert_eq!(fs::read(&journal).unwrap(), original_bytes);
    });
}
