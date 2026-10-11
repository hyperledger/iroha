//! Graph-only Original coverage retains fresh mutable work, callback boundaries and source exits.

use super::*;
use crate::managed::Error;
use std::{cell::Cell, rc::Rc};

thread_local! {
    static ORIGINAL: Cell<bool> = const { Cell::new(false) };
    static COUNTS: Cell<Option<[usize; 2]>> = const { Cell::new(None) };
}
pub(in crate::managed) fn original_recipe() -> bool {
    ORIGINAL.get()
}
pub(in crate::managed) fn record_original_read() {
    record(0);
}
pub(in crate::managed) fn record_covered() {
    record(1);
}
fn record(index: usize) {
    if let Some(mut counts) = COUNTS.get() {
        counts[index] += 1;
        COUNTS.set(Some(counts));
    }
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
// Only the independent operation-scope grouping regression requests this test-only control.
// The integrated tests below keep both shipping production optimizations enabled together.
pub(super) fn with_original_reads<T>(read: impl FnOnce() -> T) -> T {
    recipe(true, read)
}
fn counted<T>(original: bool, read: impl FnOnce() -> T) -> (T, [usize; 2]) {
    struct Restore(Option<[usize; 2]>);
    impl Drop for Restore {
        fn drop(&mut self) {
            COUNTS.set(self.0);
        }
    }
    let _restore = Restore(COUNTS.replace(Some([0; 2])));
    let result = recipe(original, read);
    (result, COUNTS.get().unwrap())
}
// Observe the shipping graph coverage without changing its read-selection recipe.
pub(super) fn observe_reads<T>(read: impl FnOnce() -> T) -> (T, [usize; 2]) {
    counted(false, read)
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
struct RestoreOriginal {
    directory: Arc<PrivateDirectory>,
    bytes: zeroize::Zeroizing<Vec<u8>>,
}
impl RestoreOriginal {
    fn new(directory: &Arc<PrivateDirectory>) -> Self {
        Self {
            directory: Arc::clone(directory),
            bytes: directory
                .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
                .unwrap(),
        }
    }
}
impl Drop for RestoreOriginal {
    fn drop(&mut self) {
        self.directory
            .write_atomic("original.nrt", &self.bytes, PublishMode::Replace)
            .unwrap();
    }
}

#[test]
fn graph_originals_share_only_closed_exact_bodies_and_preserve_mutable_work_and_admission() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history.current_history().unwrap();
    let read = |original| {
        counted(original, || {
            operation_scope_tests::observe_leaves(
                |_| Ok(()),
                || {
                    shared_snapshot_tests::snapshot_work(|| {
                        History::test_operation_records(|| native.test_require_current(6))
                    })
                },
            )
        })
    };
    let (((((old, old_visits), old_records), old_snapshot), old_leaves), old_reads) = read(true);
    let (((((new, new_visits), new_records), new_snapshot), new_leaves), new_reads) = read(false);
    old.unwrap();
    new.unwrap();
    assert_eq!((old_reads, new_reads), ([12, 0], [0, 12]));
    assert_eq!(old_records, new_records);
    assert!(old_records[0] > 0 && old_records[1] > 0);
    assert_eq!((old_visits.visits, new_visits.visits), (6, 6));
    assert_eq!(
        (old_visits.native_tree_visits, new_visits.native_tree_visits),
        (6, 6)
    );
    assert_eq!(
        (old_visits.distinct_histories, new_visits.distinct_histories),
        (3, 3)
    );
    assert_eq!(old_snapshot, new_snapshot);
    assert_eq!(new_snapshot, (2 * (3 + 4 * 3), 2 * (2 + 3)));
    use operation_scope_tests::Point;
    assert_eq!(
        old_leaves,
        [
            Point::Inventory,
            Point::Semantic,
            Point::Metadata,
            Point::Metadata,
            Point::Semantic,
            Point::Inventory
        ]
        .repeat(6)
    );
    assert_eq!(
        new_leaves,
        [
            Point::Inventory,
            Point::Metadata,
            Point::Metadata,
            Point::Inventory
        ]
        .repeat(6)
    );
    assert_eq!(
        old_leaves
            .into_iter()
            .filter(|point| *point != Point::Semantic)
            .collect::<Vec<_>>(),
        new_leaves
    );

    let run = |original, allocation| {
        norito::core::with_decode_limits_measured(limits(allocation), || {
            counted(original, || {
                operation_scope_tests::observe_leaves(
                    |_| Ok(()),
                    || {
                        History::test_operation_records(|| {
                            outcome(native.test_require_current(6).0)
                        })
                    },
                )
            })
        })
    };
    let old = run(true, usize::MAX);
    let new = run(false, usize::MAX);
    assert_eq!(old, new);
    assert!(old.0.0.0.0.is_ok());
    let exact = old.1.total_allocated_bytes();
    assert!(exact > 1);
    for allocation in [1, exact / 2, exact - 1, exact] {
        let old = run(true, allocation);
        let new = run(false, allocation);
        assert_eq!(old, new);
        if allocation == 1 {
            assert!(old.0.0.0.0.is_err());
        }
        if allocation == exact {
            assert!(old.0.0.0.0.is_ok());
        }
    }

    // The zero-predecessor path never constructs coverage, even for a genuine body.
    let oldest = native.test_oldest_retained_history();
    let ((result, census), reads) = counted(false, || oldest.test_require_current(1));
    result.unwrap();
    assert_eq!(census.visits, 1);
    assert_eq!(reads, [2, 0]);
    // None still performs the original two semantic reads inside one local census.
    let (result, reads) = counted(false, || native.test_original_local(None));
    result.unwrap();
    assert_eq!(reads, [2, 0]);

    let head = &history.bodies.last().unwrap().snapshots;
    let snapshot = SnapshotReadPass { head };
    let evidence = native.test_enrollment_evidence().unwrap();
    let semantic = evidence.binding().semantic;
    let purpose = evidence.binding().purpose;
    let body = &history.bodies.last().unwrap().directory;
    assert!(native.test_original_binding(&snapshot, body, purpose, semantic));
    assert!(!native.test_original_binding(&snapshot, &history.root, purpose, semantic));
    assert!(!native.test_original_binding(
        &snapshot,
        body,
        attempts::Purpose::ReservePolicy,
        semantic
    ));
    let mut different = semantic;
    different[0] ^= 1;
    assert!(!native.test_original_binding(&snapshot, body, purpose, different));
    assert!(!native.test_fixed_original_binding(&snapshot));
    norito::core::with_decode_limits_scope(limits(usize::MAX), || {
        // Snapshot token existed before this inherited owner; active admission still wins.
        assert!(!native.test_original_binding(&snapshot, body, purpose, semantic));
    });
    let reopened = history.read_current(&fixture.owner).unwrap();
    let foreign_snapshot = SnapshotReadPass {
        head: &reopened.bodies.last().unwrap().snapshots,
    };
    assert!(!native.test_original_binding(&foreign_snapshot, body, purpose, semantic));
    foreign_snapshot.head.revalidate().unwrap();
    let (result, reads) = counted(false, || {
        native.test_original_local(Some(&foreign_snapshot))
    });
    foreign_snapshot.head.revalidate().unwrap();
    result.unwrap();
    assert_eq!(reads, [2, 0]);
    ineligible_original_snapshots(&history);
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn graph_original_source_exit_wins_mutation_errors_and_parser_callbacks_keep_fresh_reads() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history.current_history().unwrap();
    for index in [0, 2] {
        for ordinary_error in [false, true] {
            let restore = RestoreOriginal::new(&history.bodies[index].directory);
            let directory = Arc::clone(&restore.directory);
            let mut changed = restore.bytes.to_vec();
            changed[0] ^= 1;
            let ((result, census), reads) = counted(false, || {
                native.test_require_current_after_forward(6, move || {
                    directory.write_atomic("original.nrt", &changed, PublishMode::Replace)?;
                    if ordinary_error {
                        Err(Error::NativeDeadline)
                    } else {
                        Ok(())
                    }
                })
            });
            drop(restore);
            assert!(matches!(result, Err(Error::Invalid(message))
                if message == "retained enrollment body material changed"));
            let visits = if ordinary_error { 3 } else { 6 };
            assert_eq!(census.visits, visits);
            assert_eq!(reads, [0, 2 * visits]);
            // No coverage escapes the completed graph; the next call reads fresh snapshots.
            native.test_require_current(6).0.unwrap();
        }
    }
    // Mutable metadata remains outside Original coverage. Both directions still decode it.
    let first = Arc::clone(&history.bodies[0].directory);
    let closed = first
        .read("closed.nrt", attempts::MAX_RECORD_BYTES)
        .unwrap();
    let changed_directory = Arc::clone(&first);
    let (result, census) = native.test_require_current_after_forward(6, move || {
        changed_directory.write_atomic("closed.nrt", b"changed closure", PublishMode::Replace)?;
        Ok(())
    });
    first
        .write_atomic("closed.nrt", &closed, PublishMode::Replace)
        .unwrap();
    assert!(result.is_err());
    assert!(census.visits > 3);
    native.test_require_current(6).0.unwrap();

    // Parser-local checks cannot borrow graph-only coverage. A changed Original must be
    // refused at the next local check even if restored before the whole parser pass closes.
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    EnrollmentReadPass::run(&snapshot, |pass| {
        // A fresh pass must reject skipping the oldest genuine predecessor. Remembering
        // the complete chain in parser order makes the same three-body fixture valid.
        assert!(matches!(
            pass.test_remember_immediate_predecessor(native),
            Err(Error::Invalid(message))
                if message == "parser predecessor closure changed its exact chain"
        ));
        pass.test_retain_predecessor(native)?;
        // Replaying the oldest closure after its descendant must still refuse; neither
        // failed ordering check may replace the correctly retained predecessor chain.
        assert!(matches!(
            pass.test_retain_predecessor(native),
            Err(Error::Invalid(message))
                if message == "parser predecessor closure changed its exact chain"
        ));
        pass.test_validate(native)?;
        let restore = RestoreOriginal::new(&history.bodies.last().unwrap().directory);
        restore.directory.write_atomic(
            "original.nrt",
            b"changed original",
            PublishMode::Replace,
        )?;
        let (result, reads) = counted(false, || pass.test_validate(native));
        drop(restore);
        assert!(matches!(result, Err(Error::Invalid(_))));
        assert_eq!(reads, [1, 0]);
        pass.test_validate(native)
    })
    .unwrap();
    // Actual wallet-inspection callbacks keep the same before/after guards with both
    // production optimizations enabled; a changed Original cannot reach the next callback.
    let calls = Rc::new(Cell::new(0));
    let observed = Rc::clone(&calls);
    let restore = RestoreOriginal::new(&history.bodies[0].directory);
    let directory = Arc::clone(&restore.directory);
    let result = parser_handle_tests::with_hook(
        move |point| {
            if let parser_handle_tests::Point::WalletInspected(_) = point {
                observed.set(observed.get() + 1);
                directory.write_atomic(
                    "original.nrt",
                    b"changed at wallet boundary",
                    PublishMode::Replace,
                )?;
            }
            Ok(())
        },
        || history.read_current(&fixture.owner),
    );
    drop(restore);
    assert!(result.is_err());
    assert_eq!(calls.get(), 1);
    history.read_current(&fixture.owner).unwrap();
    #[cfg(unix)]
    native_source_mutations(&history);
    assert_eq!(fixture.native.chain.height(), 4);
}

#[cfg(unix)]
fn native_source_mutations(history: &BodyHistory) {
    use operation_scope_tests::Point;
    use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf};
    struct Permissions {
        path: PathBuf,
        original: fs::Permissions,
    }
    impl Drop for Permissions {
        fn drop(&mut self) {
            fs::set_permissions(&self.path, self.original.clone()).unwrap();
        }
    }
    let native = history.current_history().unwrap();
    let body = &history.bodies[0].directory;
    // The grouped operation leaf sequence runs with Original-read coverage. Prefix, suffix and Original
    // leaf custody each override a typed inner error on the unchanged full-source exit.
    for path in [
        history.root.path().to_owned(),
        body.path().to_owned(),
        body.path().join("original.nrt"),
    ] {
        for ordinary_error in [false, true] {
            let restore = Permissions {
                original: fs::metadata(&path).unwrap().permissions(),
                path: path.clone(),
            };
            let is_leaf = path.ends_with("original.nrt");
            let changed_path = path.clone();
            let mut changed = false;
            let ((result, records), leaves) = operation_scope_tests::observe_leaves(
                move |point| {
                    if !changed && point == Point::Inventory {
                        fs::set_permissions(
                            &changed_path,
                            fs::Permissions::from_mode(if is_leaf { 0o644 } else { 0o755 }),
                        )?;
                        changed = true;
                        if ordinary_error {
                            return Err(Error::NativeDeadline);
                        }
                    }
                    Ok(())
                },
                || History::test_operation_records(|| native.test_require_current(6).0),
            );
            drop(restore);
            assert!(
                matches!(result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied)
            );
            if ordinary_error {
                assert_eq!(records, [0; 4]);
                assert_eq!(leaves, [Point::Inventory]);
            } else if is_leaf {
                // The former interior Original read is deliberately gone. Mutable decoders
                // run, but no result escapes the fresh full snapshot's native leaf refusal.
                assert!(records[0] > 0 && records[1] > 0);
                assert!(!leaves.contains(&Point::Semantic));
            }
            native.test_require_current(6).0.unwrap();
        }
    }
    // Same-path body replacement must not inherit either the original native owner or its
    // immutable snapshot identity, even if the replacement carries identical Original bytes.
    struct DirectoryRestore {
        path: PathBuf,
        held: PathBuf,
        changed: Rc<Cell<bool>>,
        _temporary: tempfile::TempDir,
    }
    impl Drop for DirectoryRestore {
        fn drop(&mut self) {
            if self.changed.get() {
                if self.path.exists() {
                    let original = self.path.join("original.nrt");
                    if original.exists() {
                        fs::remove_file(original).unwrap();
                    }
                    fs::remove_dir(&self.path).unwrap();
                }
                fs::rename(&self.held, &self.path).unwrap();
            }
        }
    }
    for ordinary_error in [false, true] {
        let temporary = tempfile::tempdir().unwrap();
        let changed = Rc::new(Cell::new(false));
        let restore = DirectoryRestore {
            path: body.path().to_owned(),
            held: temporary.path().join("held-body"),
            changed: Rc::clone(&changed),
            _temporary: temporary,
        };
        let path = restore.path.clone();
        let held = restore.held.clone();
        let original = body
            .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap();
        let (result, _) = native.test_require_current_after_forward(6, move || {
            fs::rename(&path, &held)?;
            changed.set(true);
            let replacement = PrivateDirectory::open_or_create(&path)?;
            replacement.write_atomic("original.nrt", &original, PublishMode::CreateNew)?;
            if ordinary_error {
                Err(Error::NativeDeadline)
            } else {
                Ok(())
            }
        });
        drop(restore);
        assert!(matches!(result, Err(Error::Io(_))));
        native.test_require_current(6).0.unwrap();
    }
    // Explicit temporal limit: an Original changed after inventory and restored after the
    // metadata read can evade the consolidated immutable observations, without a callback,
    // effect or receipt leaving the graph. The old interior leaf recipe still refuses.
    for original_recipe in [true, false] {
        let restore = RestoreOriginal::new(body);
        let directory = Arc::clone(body);
        let original = restore.bytes.to_vec();
        let mut stage = 0;
        let ((result, _), _) = counted(original_recipe, || {
            operation_scope_tests::observe_leaves(
                move |point| {
                    if stage == 0 && point == Point::Inventory {
                        directory.write_atomic(
                            "original.nrt",
                            b"interior replacement",
                            PublishMode::Replace,
                        )?;
                        stage = 1;
                    } else if stage == 1 && point == Point::Metadata {
                        directory.write_atomic("original.nrt", &original, PublishMode::Replace)?;
                        stage = 2;
                    }
                    Ok(())
                },
                || native.test_require_current(6).0,
            )
        });
        drop(restore);
        if original_recipe {
            assert!(result.is_err());
        } else {
            result.unwrap();
        }
    }
    native.test_require_current(6).0.unwrap();
}

fn ineligible_original_snapshots(history: &BodyHistory) {
    let body = history.bodies.last().unwrap();
    let native = history.current_history().unwrap();
    let original = native.test_enrollment_evidence().unwrap();
    let binding = original.binding();
    // Deliberately malformed private snapshots are negative membership inputs only. They
    // never manufacture a successful History, native proof, callback result or receipt.
    for variant in 0..9 {
        let mut records: Vec<_> = body
            .snapshots
            .records
            .iter()
            .map(|record| RecordSnapshot {
                directory: Arc::clone(&record.directory),
                name: record.name.clone(),
                maximum: record.maximum,
                observed: record.observed,
            })
            .collect();
        let mut root = None;
        let mut previous = body.snapshots.previous.as_ref().map(Arc::clone);
        match variant {
            0 => records[1].observed = None,
            1 => records[1].directory = Arc::clone(&history.root),
            2 => records[1].name = "reserved.nrt".into(),
            3 => records[1].maximum -= 1,
            4 => records[1].observed.as_mut().unwrap().0 = 0,
            5 => records[1].observed.as_mut().unwrap().1[0] ^= 1,
            6 => root = Some(Arc::clone(&history.root)),
            7 => {
                records.remove(1);
            }
            8 => previous = None,
            _ => unreachable!(),
        }
        let snapshots = Arc::new(Snapshot {
            previous,
            records,
            names: vec![],
            root,
        });
        let evidence = ScopeEvidence {
            root: Arc::clone(&history.root),
            body: Arc::clone(&body.directory),
            binding: EnrollmentScopeBinding {
                outer_intent: binding.outer_intent,
                body_selection: binding.body_selection,
                purpose: binding.purpose,
                semantic: binding.semantic,
                predecessor_closure: binding.predecessor_closure,
            },
            fees: original.fees().clone(),
            snapshots: Arc::clone(&snapshots),
            active: false,
        };
        let pass = SnapshotReadPass { head: &snapshots };
        assert!(!evidence.covers_semantic_original(&pass, binding.semantic));
    }
}
