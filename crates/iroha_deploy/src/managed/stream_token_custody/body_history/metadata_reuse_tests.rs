//! Exact fresh native images reuse only immutable terminal parsing, never current authority.
use super::*;
use crate::managed::native_operation::attempts::metadata;
use std::cell::Cell;

thread_local! { static ORIGINAL: Cell<bool> = const { Cell::new(false) }; }
pub(in crate::managed) fn original_recipe() -> bool {
    ORIGINAL.get()
}
pub(in crate::managed) fn with_original_recipe<T>(read: impl FnOnce() -> T) -> T {
    recipe(true, read)
}
fn recipe<T>(original: bool, read: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            ORIGINAL.set(self.0);
        }
    }
    let _restore = Restore(ORIGINAL.replace(original));
    read()
}
fn native_work<T>(read: impl FnOnce() -> T) -> (T, iroha_fs::CustodyWorkV1) {
    let before = iroha_fs::CustodyWorkV1::current_thread();
    let result = read();
    (
        result,
        iroha_fs::CustodyWorkV1::current_thread().since(before),
    )
}
fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        MAX_BODY_BYTES,
        MAX_ALL_BODY_BYTES,
        MAX_ALL_BODY_BYTES,
        allocation,
        64,
    )
}
fn outcome(result: Result<()>) -> std::result::Result<(), String> {
    result.map_err(|error| error.to_string())
}

#[test]
fn terminal_image_reuse_keeps_fresh_reads_and_inventory_order_with_fewer_actual_decoders() {
    let _resources = crate::managed::native_test_guard();
    let (_fixture, history) = shared_snapshot_tests::history_with_bodies(2);
    let native = history
        .current_history()
        .unwrap()
        .test_oldest_retained_history();
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    let run = |original| {
        recipe(original, || {
            let capture = finish_timing::Capture::start();
            let measured = native_work(|| {
                operation_scope_tests::observe_leaves(
                    |_| Ok(()),
                    || History::test_operation_records(|| native.test_local_census(&snapshot)),
                )
            });
            (measured, capture.finish())
        })
    };
    let ((((old, old_records), old_leaves), old_native), old_timing) = run(true);
    let ((((new, new_records), new_leaves), new_native), new_timing) = run(false);
    old.unwrap();
    new.unwrap();
    assert_eq!(old_native, new_native);
    assert_eq!(old_leaves, new_leaves);
    use operation_scope_tests::Point as Leaf;
    assert_eq!(
        new_leaves,
        [
            Leaf::Inventory,
            Leaf::Semantic,
            Leaf::Metadata,
            Leaf::Metadata,
            Leaf::Semantic,
            Leaf::Inventory
        ]
    );
    assert_eq!(old_records[0], new_records[0]);
    assert!(new_records[0] >= 2);
    assert!(old_records[1] > 0);
    assert_eq!(new_records[1], 0);
    assert_eq!(&old_records[2..], &new_records[2..]);
    assert_eq!(
        old_timing
            .sample(finish_timing::Phase::MetadataEnvelopeDecode)
            .0,
        2
    );
    assert_eq!(
        new_timing
            .sample(finish_timing::Phase::MetadataEnvelopeDecode)
            .0,
        0
    );
    assert_eq!(
        new_timing
            .sample(finish_timing::Phase::MetadataImageMatch)
            .0,
        2
    );
    assert_eq!(
        old_timing
            .sample(finish_timing::Phase::AttemptScopedRecordRead)
            .0,
        new_timing
            .sample(finish_timing::Phase::AttemptScopedRecordRead)
            .0
    );

    // The final signed mutable head has no dispatch or attempt yet: its empty typed
    // components need no decoder. Its two fresh metadata envelopes still use the full
    // original decoder, even when every native byte matches the owned in-memory image.
    let head = history.current_history().unwrap();
    assert!(head.last().is_none());
    let run_head = |original| {
        recipe(original, || {
            let capture = finish_timing::Capture::start();
            let measured = native_work(|| {
                History::test_operation_records(|| outcome(head.test_local_census(&snapshot)))
            });
            (measured, capture.finish())
        })
    };
    let (old_head, old_timing) = run_head(true);
    let (new_head, new_timing) = run_head(false);
    assert_eq!(old_head, new_head);
    assert_eq!(new_head.0.0, Ok(()));
    assert_eq!(
        new_head.0.1[1], 0,
        "the pristine head has no typed child record"
    );
    assert!(
        new_head.0.1[0] >= 2,
        "both metadata images are freshly read"
    );
    for timing in [&old_timing, &new_timing] {
        assert_eq!(
            timing
                .sample(finish_timing::Phase::MetadataEnvelopeDecode)
                .0,
            2
        );
    }

    // The envelope borrows geometry and this pristine head has no typed child frames.
    // An inherited allocation budget therefore charges zero and succeeds even at zero;
    // the actual full envelope decoder still runs at both original read positions.
    let bounded_head = |original, allocation| {
        recipe(original, || {
            let capture = finish_timing::Capture::start();
            let measured = norito::core::with_decode_limits_measured(limits(allocation), || {
                native_work(|| {
                    History::test_operation_records(|| outcome(head.test_local_census(&snapshot)))
                })
            });
            (
                measured,
                capture
                    .finish()
                    .sample(finish_timing::Phase::MetadataEnvelopeDecode)
                    .0,
            )
        })
    };
    for allocation in [0, 1, usize::MAX] {
        let (old, old_envelopes) = bounded_head(true, allocation);
        let (new, new_envelopes) = bounded_head(false, allocation);
        assert_eq!(old, new);
        let (((result, records), _native), usage) = new;
        assert_eq!(result, Ok(()));
        assert_eq!(records[1], 0);
        assert!(records[0] >= 2);
        assert_eq!(usage.total_allocated_bytes(), 0);
        assert_eq!((old_envelopes, new_envelopes), (2, 2));
    }
}

#[test]
fn terminal_image_inherited_and_late_decode_owners_keep_original_accounting() {
    let _resources = crate::managed::native_test_guard();
    let (_fixture, history) = shared_snapshot_tests::history_with_bodies(2);
    let native = history
        .current_history()
        .unwrap()
        .test_oldest_retained_history();
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    let run = |original, allocation| {
        recipe(original, || {
            norito::core::with_decode_limits_measured(limits(allocation), || {
                native_work(|| {
                    History::test_operation_records(|| outcome(native.test_local_census(&snapshot)))
                })
            })
        })
    };
    let full = run(true, usize::MAX);
    assert!(full.0.0.0.is_ok());
    assert_eq!(full, run(false, usize::MAX));
    let exact = full.1.total_allocated_bytes();
    assert!(exact > 1);
    for allocation in [0, 1, exact / 2, exact - 1, exact] {
        let old = run(true, allocation);
        assert_eq!(old, run(false, allocation));
        if allocation <= 1 {
            assert!(old.0.0.0.is_err());
        }
        let late = native
            .test_local_census_after_admission(&snapshot, |read| {
                norito::core::with_decode_limits_measured(limits(allocation), || {
                    native_work(|| History::test_operation_records(|| outcome(read())))
                })
            })
            .unwrap();
        assert_eq!(old, late);
    }
    // Here the owner becomes active after exact native-image equality, not merely after
    // the surrounding native census was admitted. Its typed decoder still charges/refuses.
    metadata::test_late_image_decoder(native);
    native.test_local_census(&snapshot).unwrap();
}

#[test]
fn terminal_image_changed_native_bytes_keep_original_decode_errors_and_recovery() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(2);
    let native = history
        .current_history()
        .unwrap()
        .test_oldest_retained_history();
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    let directory = &history.bodies[0].directory;
    let original = directory.read("operation.nrt", MAX_ALL_BODY_BYTES).unwrap();
    let attempt = native.last().unwrap();
    let cases = [
        b"malformed canonical image".to_vec(),
        metadata::test_changed_dispatch_image(&original).unwrap(),
        metadata::test_changed_image(&original, None, "closed.nrt", Some(b"bad closure")).unwrap(),
        metadata::test_changed_image(
            &original,
            Some(attempt.ordinal()),
            "authorization.nrt",
            Some(b"bad authorization"),
        )
        .unwrap(),
        metadata::test_changed_image(
            &original,
            Some(attempt.ordinal()),
            "authorization.nrt",
            None,
        )
        .unwrap(),
    ];
    for changed in cases {
        directory
            .write_atomic("operation.nrt", &changed, PublishMode::Replace)
            .unwrap();
        let run = |original| {
            recipe(original, || {
                native_work(|| {
                    operation_scope_tests::observe_leaves(
                        |_| Ok(()),
                        || {
                            History::test_operation_records(|| {
                                outcome(native.test_local_census(&snapshot))
                            })
                        },
                    )
                })
            })
        };
        let old = run(true);
        let new = run(false);
        directory
            .write_atomic("operation.nrt", &original, PublishMode::Replace)
            .unwrap();
        assert!(old.0.0.0.is_err());
        assert_eq!(old, new);
        native.test_local_census(&snapshot).unwrap();
    }
    let path = directory.path().join("operation.nrt");
    let saved = fixture.temporary.path().join("held-operation.nrt");
    std::fs::rename(&path, &saved).unwrap();
    let old = recipe(true, || outcome(native.test_local_census(&snapshot)));
    let new = recipe(false, || outcome(native.test_local_census(&snapshot)));
    std::fs::rename(&saved, &path).unwrap();
    assert!(old.is_err());
    assert_eq!(old, new);
    native.test_local_census(&snapshot).unwrap();
}

#[cfg(unix)]
#[test]
fn terminal_image_native_owner_and_exit_refusals_survive_reuse_and_restore() {
    use std::{fs, os::unix::fs::PermissionsExt as _};
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(2);
    let native = history
        .current_history()
        .unwrap()
        .test_oldest_retained_history();
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    let directory = Arc::clone(&history.bodies[0].directory);
    let path = directory.path().to_path_buf();
    let saved = fixture.temporary.path().join("held-image-owner");
    fs::rename(&path, &saved).unwrap();
    drop(PrivateDirectory::open_or_create(&path).unwrap());
    let old = recipe(true, || outcome(native.test_local_census(&snapshot)));
    let new = recipe(false, || outcome(native.test_local_census(&snapshot)));
    fs::remove_dir(&path).unwrap();
    fs::rename(&saved, &path).unwrap();
    assert!(old.is_err());
    assert_eq!(old, new);
    native.test_local_census(&snapshot).unwrap();

    // Refusal occurs after a successful fresh match. The operation's original ordinary
    // error exit still overrides the semantic error with persistent custody refusal.
    for original in [true, false] {
        let target = Arc::clone(&directory);
        let permissions = fs::metadata(&path).unwrap().permissions();
        let mut changed = false;
        let (result, _) = recipe(original, || {
            operation_scope_tests::observe_leaves(
                move |point| {
                    if point == operation_scope_tests::Point::Metadata && !changed {
                        changed = true;
                        fs::set_permissions(target.path(), fs::Permissions::from_mode(0o755))?;
                        return Err(invalid("inner metadata inspection refused"));
                    }
                    Ok(())
                },
                || native.test_local_census(&snapshot),
            )
        });
        fs::set_permissions(&path, permissions).unwrap();
        assert!(matches!(result, Err(crate::managed::Error::Io(error))
            if error.kind() == std::io::ErrorKind::PermissionDenied));
        native.test_local_census(&snapshot).unwrap();
    }
}
