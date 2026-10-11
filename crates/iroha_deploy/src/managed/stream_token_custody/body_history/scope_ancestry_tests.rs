//! Genuine graph scope checks share native ancestry without sharing inventory or authority.

use super::*;
use crate::managed::Error;
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Point {
    Full,
    Tree,
    Inventory,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Boundary {
    InventoryRead,
    RootClosed,
    BodyClosed,
}
#[derive(Debug, Default, PartialEq, Eq)]
struct Counts {
    full: usize,
    tree: usize,
    inventories: usize,
    points: Vec<Point>,
}
type Hook = Box<dyn FnMut(Boundary) -> Result<()>>;
struct State {
    original: bool,
    counts: Counts,
    hook: Option<Hook>,
}
thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}
pub(super) fn original_recipe() -> bool {
    STATE.with(|state| state.borrow().as_ref().is_some_and(|state| state.original))
}
pub(super) fn record(point: Point) {
    STATE.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            match point {
                Point::Full => state.counts.full += 1,
                Point::Tree => state.counts.tree += 1,
                Point::Inventory => state.counts.inventories += 1,
            }
            state.counts.points.push(point);
        }
    });
}
pub(super) fn hit(boundary: Boundary) -> Result<()> {
    let mut hook = STATE.with(|state| {
        state
            .borrow_mut()
            .as_mut()
            .and_then(|state| state.hook.take())
    });
    let result = hook.as_mut().map_or(Ok(()), |hook| hook(boundary));
    STATE.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            state.hook = hook;
        }
    });
    result
}
fn counted<T>(original: bool, hook: Option<Hook>, read: impl FnOnce() -> T) -> (T, Counts) {
    struct Restore(Option<State>);
    impl Drop for Restore {
        fn drop(&mut self) {
            STATE.with(|state| state.replace(self.0.take()));
        }
    }
    let _restore = Restore(STATE.with(|state| {
        state.replace(Some(State {
            original,
            counts: Counts::default(),
            hook,
        }))
    }));
    let result = read();
    let counts = STATE.with(|state| state.take().unwrap().counts);
    (result, counts)
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
fn graph_scope_ancestry_keeps_combined_census_order_and_inherited_admission() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history.current_history().unwrap();
    let read = |original| {
        counted(original, None, || {
            graph_original_tests::observe_reads(|| {
                operation_scope_tests::observe_leaves(
                    |_| Ok(()),
                    || {
                        shared_snapshot_tests::snapshot_work(|| {
                            History::test_operation_records(|| native.test_require_current(6))
                        })
                    },
                )
            })
        })
    };
    let (
        (((((old, old_visits), old_records), old_snapshot), old_leaves), old_originals),
        old_scope,
    ) = read(true);
    let (
        (((((new, new_visits), new_records), new_snapshot), new_leaves), new_originals),
        new_scope,
    ) = read(false);
    old.unwrap();
    new.unwrap();
    assert_eq!(
        (old_scope.full, old_scope.tree, old_scope.inventories),
        (14, 0, 14)
    );
    assert_eq!(
        (new_scope.full, new_scope.tree, new_scope.inventories),
        (2, 12, 14)
    );
    assert_eq!(old_scope.points, [Point::Full, Point::Inventory].repeat(14));
    let mut expected = vec![Point::Full, Point::Inventory];
    expected.extend([Point::Tree, Point::Inventory].repeat(12));
    expected.extend([Point::Full, Point::Inventory]);
    assert_eq!(new_scope.points, expected);
    assert_eq!(old_records, new_records);
    assert!(new_records[0] > 0 && new_records[1] > 0);
    assert_eq!(old_snapshot, new_snapshot);
    assert_eq!(new_snapshot, (30, 10));
    assert_eq!(old_originals, new_originals);
    assert_eq!(new_originals, [0, 12]);
    assert_eq!(old_leaves, new_leaves);
    use operation_scope_tests::Point as Leaf;
    assert_eq!(
        new_leaves,
        [
            Leaf::Inventory,
            Leaf::Metadata,
            Leaf::Metadata,
            Leaf::Inventory
        ]
        .repeat(6)
    );
    assert_eq!((old_visits.visits, new_visits.visits), (6, 6));
    assert_eq!(
        (old_visits.native_tree_visits, new_visits.native_tree_visits),
        (6, 6)
    );
    assert_eq!(
        (old_visits.distinct_histories, new_visits.distinct_histories),
        (3, 3)
    );

    let run = |original, allocation| {
        norito::core::with_decode_limits_measured(limits(allocation), || {
            counted(original, None, || {
                History::test_operation_records(|| outcome(native.test_require_current(6).0))
            })
        })
    };
    let old = run(true, usize::MAX);
    let new = run(false, usize::MAX);
    assert_eq!(old, new);
    assert!(old.0.0.0.is_ok());
    assert_eq!(old.0.1.tree, 0);
    let exact = old.1.total_allocated_bytes();
    assert!(exact > 1);
    for allocation in [1, exact / 2, exact - 1, exact] {
        let old = run(true, allocation);
        let new = run(false, allocation);
        assert_eq!(old, new);
        if allocation == 1 {
            assert!(old.0.0.0.is_err());
        }
        if allocation == exact {
            assert!(old.0.0.0.is_ok());
        }
    }
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn graph_scope_ancestry_preserves_missing_foreign_and_parser_scope_recipes() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history.current_history().unwrap();
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    let evidence = native.test_enrollment_evidence().unwrap();
    // A genuine zero-predecessor graph and the explicit missing pass keep full checks.
    for original in [true, false] {
        let (result, counts) = counted(original, None, || {
            native
                .test_oldest_retained_history()
                .test_require_current(1)
                .0
        });
        result.unwrap();
        assert_eq!((counts.full, counts.tree, counts.inventories), (2, 0, 2));
        let (result, counts) = counted(original, None, || native.test_original_local(None));
        result.unwrap();
        assert_eq!((counts.full, counts.tree, counts.inventories), (2, 0, 2));
    }
    // Equal bytes from another genuine parser do not supply this evidence's Snapshot owner.
    let reopened = history.read_current(&fixture.owner).unwrap();
    let foreign = SnapshotReadPass {
        head: &reopened.bodies.last().unwrap().snapshots,
    };
    foreign.head.revalidate().unwrap();
    let (result, counts) = counted(false, None, || native.test_original_local(Some(&foreign)));
    foreign.head.revalidate().unwrap();
    result.unwrap();
    assert_eq!((counts.full, counts.tree, counts.inventories), (2, 0, 2));
    // The parser's borrowed pass never supplies the graph-only scope-selection capability.
    EnrollmentReadPass::run(&snapshot, |pass| {
        pass.test_retain_predecessor(native)?;
        let (result, counts) = counted(false, None, || pass.test_validate(native));
        result?;
        assert_eq!((counts.full, counts.tree, counts.inventories), (2, 0, 2));
        Ok(())
    })
    .unwrap();
    // Recheck active admission after both borrowed owners already exist.
    let run = |original| {
        history.root.read_tree_scope(|tree| {
            let result = norito::core::with_decode_limits_measured(limits(usize::MAX), || {
                counted(original, None, || {
                    outcome(evidence.revalidate_in_tree(Some(&snapshot), tree, None))
                })
            });
            Ok::<_, Error>(result)
        })
    };
    let old = run(true).unwrap();
    let new = run(false).unwrap();
    assert_eq!(old, new);
    assert!(new.0.0.is_ok());
    assert_eq!((new.0.1.full, new.0.1.tree), (1, 0));
    // Names retain the original allowed-subset semantics and exact unknown-material error.
    assert!(require_allowed_names(&[], &SCOPE_ROOT_NAMES).is_ok());
    let allowed: Vec<_> = SCOPE_ROOT_NAMES
        .iter()
        .map(|name| std::ffi::OsString::from(*name))
        .collect();
    assert!(require_allowed_names(&allowed, &SCOPE_ROOT_NAMES).is_ok());
    assert!(
        matches!(require_allowed_names(&["foreign".into()], &SCOPE_ROOT_NAMES), Err(Error::Invalid(message)) if message == "enrollment body contains unknown material")
    );
    assert_eq!(fixture.native.chain.height(), 4);
}

#[cfg(unix)]
struct Permissions {
    path: std::path::PathBuf,
    original: std::fs::Permissions,
}
#[cfg(unix)]
impl Permissions {
    fn new(path: &std::path::Path) -> Self {
        Self {
            path: path.to_owned(),
            original: std::fs::metadata(path).unwrap().permissions(),
        }
    }
}
#[cfg(unix)]
impl Drop for Permissions {
    fn drop(&mut self) {
        std::fs::set_permissions(&self.path, self.original.clone()).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn graph_scope_ancestry_closes_native_mutations_and_every_ordinary_result() {
    use std::{fs, os::unix::fs::PermissionsExt as _};
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history.current_history().unwrap();
    for boundary in [
        Boundary::InventoryRead,
        Boundary::RootClosed,
        Boundary::BodyClosed,
    ] {
        for target in [
            history.root.path().to_owned(),
            history.root.path().join("bodies"),
            history.bodies[0].directory.path().to_owned(),
        ] {
            for ordinary_error in [false, true] {
                let restore = Permissions::new(&target);
                let changed_path = target.clone();
                let mut changed = false;
                let hook: Hook = Box::new(move |point| {
                    if !changed && point == boundary {
                        fs::set_permissions(&changed_path, fs::Permissions::from_mode(0o755))?;
                        changed = true;
                        if ordinary_error {
                            return Err(Error::NativeDeadline);
                        }
                    }
                    Ok(())
                });
                let (result, counts) =
                    counted(false, Some(hook), || native.test_require_current(6).0);
                drop(restore);
                assert!(
                    matches!(result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied)
                );
                assert!(counts.tree > 0);
                native.test_require_current(6).0.unwrap();
            }
        }
    }
    // Body/ancestor mutation after a complete forward pass still fails before any result escapes.
    for target in [
        history.root.path().to_owned(),
        history.bodies[2].directory.path().to_owned(),
    ] {
        for ordinary_error in [false, true] {
            let restore = Permissions::new(&target);
            let path = target.clone();
            let (result, _) = native.test_require_current_after_forward(6, move || {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
                if ordinary_error {
                    Err(Error::NativeDeadline)
                } else {
                    Ok(())
                }
            });
            drop(restore);
            assert!(
                matches!(result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied)
            );
            native.test_require_current(6).0.unwrap();
        }
    }
    // Native sharing requires original handles, not equal paths. A shared original tree
    // may miss a root change restored between its fences; a reopened tree must retain the
    // body's complete native ancestry and refuse before the restoring boundary is reached.
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    let evidence = native.test_enrollment_evidence().unwrap();
    let reopened_root = PrivateDirectory::open(history.root.path()).unwrap();
    for reopened in [false, true] {
        let restore = Permissions::new(history.root.path());
        let path = restore.path.clone();
        let original = restore.original.clone();
        let mut changed = false;
        let hook: Hook = Box::new(move |point| {
            if !changed && point == Boundary::RootClosed {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
                changed = true;
            } else if changed && point == Boundary::BodyClosed {
                fs::set_permissions(&path, original.clone())?;
            }
            Ok(())
        });
        let anchor = if reopened {
            &reopened_root
        } else {
            history.root.as_ref()
        };
        let (result, counts) = counted(false, Some(hook), || {
            anchor.read_tree_scope(|tree| evidence.revalidate_in_tree(Some(&snapshot), tree, None))
        });
        drop(restore);
        assert_eq!((counts.full, counts.tree, counts.inventories), (0, 1, 1));
        if reopened {
            assert!(
                matches!(result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied)
            );
        } else {
            result.unwrap();
        }
        native.test_require_current(6).0.unwrap();
    }
    // The root inventory is still actual native input, not a remembered namespace verdict.
    let mut added = false;
    let root = Arc::clone(&history.root);
    let hook: Hook = Box::new(move |point| {
        if !added && point == Boundary::BodyClosed {
            root.write_atomic("foreign", b"unknown material", PublishMode::CreateNew)?;
            added = true;
        }
        Ok(())
    });
    let (result, _) = counted(false, Some(hook), || native.test_require_current(6).0);
    fs::remove_file(history.root.path().join("foreign")).unwrap();
    assert!(result.is_err());
    native.test_require_current(6).0.unwrap();
    // A plain typed inner refusal is preserved when every genuine source remains unchanged.
    let mut refused = false;
    let hook: Hook = Box::new(move |point| {
        if !refused && point == Boundary::InventoryRead {
            refused = true;
            return Err(Error::NativeDeadline);
        }
        Ok(())
    });
    let (result, _) = counted(false, Some(hook), || native.test_require_current(6).0);
    assert!(matches!(result, Err(Error::NativeDeadline)));
    native.test_require_current(6).0.unwrap();
    assert_eq!(fixture.native.chain.height(), 4);
}
