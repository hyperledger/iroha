//! Exact operation custody and retry controls for tiered lane geometry.

use super::*;
use iroha_data_model::nexus::{LaneCatalog, LaneConfig as CatalogLane};
use iroha_model_base::topology::LaneId;
use std::num::NonZeroU32;

fn configuration(alias: &str) -> LaneConfig {
    LaneConfig::from_catalog(
        &LaneCatalog::new(
            NonZeroU32::new(1).expect("one lane"),
            vec![CatalogLane {
                alias: alias.into(),
                ..CatalogLane::default()
            }],
        )
        .expect("lane catalog"),
    )
}

fn backend(root: &Path) -> TieredStateBackend {
    TieredStateBackend::new(true, 0, 0, 0, Some(root.to_path_buf()), None, 0, 0)
}

fn lane_path(root: &Path, config: &LaneConfig) -> PathBuf {
    lane_snapshot_dir(
        &root.join("lanes"),
        config.entry(LaneId::SINGLE).expect("lane"),
    )
}

fn provision(backend: &mut TieredStateBackend, config: &LaneConfig) {
    backend
        .prepare_lane_geometry_attempt(config, config, &[], &[])
        .expect("capture initial geometry")
        .resume(backend)
        .expect("provision geometry");
}

#[test]
fn startup_configuration_defers_all_root_creation_to_retained_attempt() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = temp.path().join("cold").join("nested");
    let da_root = temp.path().join("da");
    // A baseline from another root must not authorize incremental-only snapshots.
    let mut backend = TieredStateBackend {
        snapshot_baseline_ready: true,
        ..TieredStateBackend::default()
    };
    assert!(backend.reconfigure_without_storage_effects(
        true,
        3,
        41,
        2,
        Some(root.clone()),
        Some(da_root.clone()),
        4,
        97,
    ));
    assert!(!root.exists());
    assert!(!da_root.exists());
    assert!(!backend.snapshot_baseline_ready);
    assert_eq!(backend.hot_retained_keys, 3);
    assert_eq!(backend.hot_retained_bytes, 41);
    let config = configuration("initial");
    let mut attempt = backend
        .prepare_lane_geometry_attempt(&config, &config, &[], &[])
        .expect("capture startup directories");
    assert!(!root.exists());
    assert!(!da_root.exists());
    attempt
        .resume(&mut backend)
        .expect("publish original startup directories");
    assert!(lane_path(&root, &config).is_dir());
    assert!(da_root.is_dir());
    attempt
        .rollback(&mut backend)
        .expect("reverse only owned startup directories");
    assert!(!root.parent().expect("cold parent").exists());
    assert!(!da_root.exists());
}

#[test]
fn capture_has_no_filesystem_effects() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = temp.path().join("not-created").join("nested");
    let mut backend = backend(&root);
    // The backend constructor prepares roots. Remove the empty root to test pure capture.
    fs::remove_dir(&root).expect("remove constructor root");
    fs::remove_dir(root.parent().expect("nested parent")).expect("remove constructor parent");
    let config = configuration("initial");
    let mut attempt = backend
        .prepare_lane_geometry_attempt(&config, &config, &[], &[])
        .expect("capture missing directories");
    assert!(!root.exists());
    attempt
        .resume(&mut backend)
        .expect("apply captured operations");
    assert!(attempt.is_applied());
    assert!(lane_path(&root, &config).is_dir());
    attempt
        .rollback(&mut backend)
        .expect("reverse owned operations");
    assert!(attempt.is_rolled_back());
    assert!(!root.exists());
    assert!(!root.parent().expect("nested parent").exists());
}

#[test]
fn rename_sync_retry_retains_exact_archive_and_original_directory() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = temp.path();
    let mut backend = backend(root);
    let config = configuration("original");
    provision(&mut backend, &config);
    let live = lane_path(root, &config);
    fs::write(live.join("state"), b"original bytes").expect("original state");
    let original = Directory::capture(&live).expect("original directory identity");
    let entry = config.entry(LaneId::SINGLE).expect("lane");
    let mut attempt = backend
        .prepare_lane_geometry_attempt(&config, &config, &[(entry, entry)], &[])
        .expect("capture replacement");
    let rename_index = attempt
        .operations
        .iter()
        .position(|operation| matches!(operation.kind, OperationKind::Rename { .. }))
        .expect("retirement rename");
    for operation in &mut attempt.operations[..rename_index] {
        operation
            .resume(&mut attempt.faults)
            .expect("prepare archive parents");
    }
    attempt.cursor = rename_index;
    attempt.faults.remaining = Some(0);
    let _ = attempt
        .resume(&mut backend)
        .expect_err("fail sync after successful rename");
    assert_eq!(
        attempt.operations[rename_index].phase,
        OperationPhase::Changed
    );
    let archive = match &attempt.operations[rename_index].kind {
        OperationKind::Rename { target, .. } => target.clone(),
        _ => unreachable!(),
    };
    original
        .authenticate(&archive)
        .expect("same original archive object");
    assert!(!live.exists());
    attempt
        .resume(&mut backend)
        .expect("retry same directory sync then provision replacement");
    assert!(attempt.is_applied());
    original
        .authenticate(&archive)
        .expect("original was retained once");
    assert!(live.is_dir());
    assert_eq!(
        fs::read_dir(root.join("retired/lanes"))
            .expect("archives")
            .count(),
        1
    );
    assert_eq!(
        fs::read(archive.join("state")).expect("archived state"),
        b"original bytes"
    );
    attempt
        .rollback(&mut backend)
        .expect("remove own replacement and return original");
    original
        .authenticate(&live)
        .expect("rollback restores exact physical original");
    assert!(!archive.exists());
    assert!(attempt.is_rolled_back());
}

#[test]
fn retry_refuses_foreign_same_name_source_after_rename() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = temp.path();
    let mut backend = backend(root);
    let old = configuration("old");
    let new = configuration("new");
    provision(&mut backend, &old);
    let old_entry = old.entry(LaneId::SINGLE).expect("old lane");
    let new_entry = new.entry(LaneId::SINGLE).expect("new lane");
    let mut attempt = backend
        .prepare_lane_geometry_attempt(&old, &new, &[], &[(old_entry, new_entry)])
        .expect("capture relabel");
    attempt.faults.remaining = Some(0);
    let _ = attempt
        .resume(&mut backend)
        .expect_err("fail sync after rename");
    fs::create_dir(lane_path(root, &old)).expect("insert foreign replacement");
    fs::write(lane_path(root, &old).join("foreign"), b"unowned").expect("foreign marker");
    let error = attempt
        .resume(&mut backend)
        .expect_err("must not adopt replacement");
    assert!(error.to_string().contains("occupied"), "{error:?}");
    let _ = attempt
        .rollback(&mut backend)
        .expect_err("must not overwrite foreign replacement");
    assert_eq!(
        fs::read(lane_path(root, &old).join("foreign")).expect("untouched marker"),
        b"unowned"
    );
    assert!(lane_path(root, &new).is_dir());
}

#[test]
fn retry_refuses_replaced_archive_even_when_contents_match() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = temp.path();
    let mut backend = backend(root);
    let old = configuration("old");
    let new = configuration("new");
    provision(&mut backend, &old);
    let old_entry = old.entry(LaneId::SINGLE).expect("old lane");
    let new_entry = new.entry(LaneId::SINGLE).expect("new lane");
    let mut attempt = backend
        .prepare_lane_geometry_attempt(&old, &new, &[], &[(old_entry, new_entry)])
        .expect("capture relabel");
    attempt.faults.remaining = Some(0);
    let _ = attempt
        .resume(&mut backend)
        .expect_err("fail sync after rename");
    let target = lane_path(root, &new);
    fs::rename(&target, root.join("displaced")).expect("move original aside");
    fs::create_dir(&target).expect("same-name empty replacement");
    let error = attempt
        .resume(&mut backend)
        .expect_err("physical identity mismatch");
    assert!(error.to_string().contains("replaced"), "{error:?}");
    assert!(root.join("displaced").is_dir());
    assert!(target.is_dir());
}

#[test]
fn applied_authentication_preserves_completion_across_identity_refusal_and_restoration() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = temp.path();
    let mut backend = backend(root);
    let old = configuration("old");
    let new = configuration("new");
    provision(&mut backend, &old);
    let mut attempt = backend
        .prepare_lane_geometry_attempt(
            &old,
            &new,
            &[],
            &[(
                old.entry(LaneId::SINGLE).expect("old lane"),
                new.entry(LaneId::SINGLE).expect("new lane"),
            )],
        )
        .expect("capture relabel");
    let _ = attempt
        .authenticate_applied(&backend)
        .expect_err("capture alone is not completed geometry");
    attempt.resume(&mut backend).expect("complete relabel");
    let cursor = attempt.cursor;
    let phases: Vec<_> = attempt
        .operations
        .iter()
        .map(|operation| operation.phase)
        .collect();
    // Terminal authentication must not perform directory syncs or consume faults.
    attempt.faults.remaining = Some(0);
    attempt
        .authenticate_applied(&backend)
        .expect("completed original geometry");
    let target = lane_path(root, &new);
    let displaced = root.join("displaced");
    fs::rename(&target, &displaced).expect("retain exact original aside");
    fs::create_dir(&target).expect("foreign same-name directory");
    fs::write(target.join("foreign"), b"unowned").expect("foreign marker");
    let error = attempt
        .authenticate_applied(&backend)
        .expect_err("physical identity mismatch");
    assert!(error.to_string().contains("replaced"), "{error:?}");
    assert!(
        attempt.is_applied(),
        "refusal retains completed forward progress"
    );
    assert_eq!(attempt.cursor, cursor);
    assert!(attempt.rollback_cursor.is_none());
    assert_eq!(
        attempt
            .operations
            .iter()
            .map(|operation| operation.phase)
            .collect::<Vec<_>>(),
        phases
    );
    assert_eq!(attempt.faults.remaining, Some(0));
    assert_eq!(
        fs::read(target.join("foreign")).expect("untouched foreign marker"),
        b"unowned"
    );
    fs::rename(&target, root.join("foreign-preserved")).expect("preserve foreign directory");
    fs::rename(&displaced, &target).expect("restore exact original identity");
    attempt
        .authenticate_applied(&backend)
        .expect("same completed owner succeeds after exact restoration");
    assert!(attempt.is_applied());
    assert_eq!(attempt.cursor, cursor);
    assert_eq!(attempt.faults.remaining, Some(0));
    assert!(
        !lane_path(root, &old).exists(),
        "authentication never reverses a rename"
    );
}

#[test]
fn rollback_sync_retry_uses_original_reverse_progress() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = temp.path();
    let mut backend = backend(root);
    let old = configuration("old");
    let new = configuration("new");
    provision(&mut backend, &old);
    let original = Directory::capture(&lane_path(root, &old)).expect("original directory");
    let mut attempt = backend
        .prepare_lane_geometry_attempt(
            &old,
            &new,
            &[],
            &[(
                old.entry(LaneId::SINGLE).expect("old"),
                new.entry(LaneId::SINGLE).expect("new"),
            )],
        )
        .expect("capture relabel");
    attempt.resume(&mut backend).expect("forward rename");
    attempt.faults.remaining = Some(0);
    let _ = attempt
        .rollback(&mut backend)
        .expect_err("reverse rename succeeded, sync failed");
    original
        .authenticate(&lane_path(root, &old))
        .expect("original already restored");
    assert!(!lane_path(root, &new).exists());
    let _ = attempt
        .resume(&mut backend)
        .expect_err("cannot restart forward after rollback");
    attempt.rollback(&mut backend).expect("retry reverse sync");
    attempt
        .rollback(&mut backend)
        .expect("terminal rollback is idempotent");
    assert!(attempt.is_rolled_back());
    original
        .authenticate(&lane_path(root, &old))
        .expect("same directory after retry");
}

#[test]
fn retained_attempt_rejects_changed_backend_roots_and_root_identity() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = temp.path().join("cold");
    let mut backend = backend(&root);
    let config = configuration("initial");
    let mut attempt = backend
        .prepare_lane_geometry_attempt(&config, &config, &[], &[])
        .expect("capture geometry");
    let mut foreign =
        TieredStateBackend::new(true, 0, 0, 0, Some(temp.path().join("other")), None, 0, 0);
    let _ = attempt
        .resume(&mut foreign)
        .expect_err("foreign backend roots");
    fs::rename(&root, temp.path().join("original-root")).expect("displace original root");
    fs::create_dir(&root).expect("foreign root at original path");
    let error = attempt
        .resume(&mut backend)
        .expect_err("same-path physical root replacement");
    assert!(error.to_string().contains("replaced"), "{error:?}");
    assert!(!root.join("lanes").exists());
}
