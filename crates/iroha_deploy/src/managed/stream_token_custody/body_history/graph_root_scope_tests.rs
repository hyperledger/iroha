//! Exact graph roots share ancestry brackets while every native inventory stays fresh.

use super::*;
use crate::managed::Error;
use std::cell::RefCell;

#[derive(Clone, Copy)]
pub(in crate::managed) enum Point {
    DirectionBracket,
    InventoryBracket,
    SharedInventory,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Boundary {
    InventoryRead,
    BodyClosed,
}
#[derive(Debug, Default, PartialEq, Eq)]
struct Counts {
    directions: usize,
    inventories: usize,
    shared: usize,
    boundaries: Vec<Boundary>,
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
pub(in crate::managed) fn original_recipe() -> bool {
    STATE.with(|state| state.borrow().as_ref().is_some_and(|state| state.original))
}
pub(in crate::managed) fn record(point: Point) {
    STATE.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            match point {
                Point::DirectionBracket => state.counts.directions += 1,
                Point::InventoryBracket => state.counts.inventories += 1,
                Point::SharedInventory => state.counts.shared += 1,
            }
        }
    });
}
pub(super) fn hit(boundary: Boundary) -> Result<()> {
    let mut hook = STATE.with(|state| {
        state.borrow_mut().as_mut().and_then(|state| {
            state.counts.boundaries.push(boundary);
            state.hook.take()
        })
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
fn graph_root_scope_keeps_all_material_and_collapses_only_same_owner_brackets() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history.current_history().unwrap();
    let prior = native.test_owned_predecessor_closure_history().unwrap();
    for (native, bodies) in [(native, 3), (&prior, 2)] {
        let read = |original| {
            counted(original, None, || {
                shared_snapshot_tests::snapshot_work(|| {
                    History::test_operation_records(|| native.test_require_current(2 * bodies))
                })
            })
        };
        let ((((old, old_visits), old_records), old_snapshots), old_counts) = read(true);
        let ((((new, new_visits), new_records), new_snapshots), new_counts) = read(false);
        old.unwrap();
        new.unwrap();
        assert_eq!(old_records, new_records);
        assert!(new_records[0] > 0 && new_records[1] > 0);
        assert_eq!(old_snapshots, new_snapshots);
        assert_eq!(new_snapshots, (6 + 8 * bodies, 4 + 2 * bodies));
        assert_eq!(
            (old_visits.visits, new_visits.visits),
            (2 * bodies, 2 * bodies)
        );
        assert_eq!(
            (old_visits.native_tree_visits, new_visits.native_tree_visits),
            (2 * bodies, 2 * bodies)
        );
        assert_eq!(
            (
                old_counts.directions,
                old_counts.inventories,
                old_counts.shared
            ),
            (0, 4 * bodies, 0)
        );
        assert_eq!(
            (
                new_counts.directions,
                new_counts.inventories,
                new_counts.shared
            ),
            (2, 0, 4 * bodies)
        );
        assert_eq!(old_counts.boundaries, new_counts.boundaries);
        assert_eq!(
            new_counts.boundaries,
            [Boundary::InventoryRead, Boundary::BodyClosed].repeat(4 * bodies)
        );
        // These are actual reached brackets, not a stopwatch or synthetic large history.
        // Each old inventory bracket validates H ancestry links twice: 8*B*H in total.
        // Two new direction brackets validate the same H links twice each: 4*H.
        assert_eq!(2 * old_counts.inventories, 8 * bodies);
        assert_eq!(2 * new_counts.directions, 4);
    }
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn graph_root_scope_retains_active_missing_and_foreign_owner_recipes() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history.current_history().unwrap();
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
    let exact = old.1.total_allocated_bytes();
    assert!(exact > 1);
    for allocation in [0, 1, exact / 2, exact - 1, exact] {
        let old = run(true, allocation);
        let new = run(false, allocation);
        assert_eq!(old, new);
        if allocation == exact {
            assert!(new.0.0.0.is_ok());
        }
        if allocation <= 1 {
            assert!(new.0.0.0.is_err());
        }
    }
    let (result, counts) = counted(false, None, || {
        native
            .test_oldest_retained_history()
            .test_require_current(1)
            .0
    });
    result.unwrap();
    assert_eq!((counts.directions, counts.shared), (0, 0));
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    let evidence = native.test_enrollment_evidence().unwrap();
    let reopened = PrivateDirectory::open(history.root.path()).unwrap();
    let retained_copy = history.root.retain().unwrap();
    for root in [history.root.as_ref(), &reopened, &retained_copy] {
        let exact_owner = std::ptr::eq(root, history.root.as_ref());
        let (result, counts) = counted(false, None, || {
            history.root.read_tree_scope(|tree| {
                History::test_graph_root_scope(root, |read| {
                    assert_eq!(read.covers(&history.root), exact_owner);
                    evidence.revalidate_in_tree(Some(&snapshot), tree, Some(read))
                })
            })
        });
        result.unwrap();
        assert_eq!(
            (counts.inventories, counts.shared),
            if exact_owner { (0, 1) } else { (1, 0) }
        );
    }
    // Installing a decoder after the real reader exists must still take the old body path.
    history
        .root
        .read_tree_scope(|tree| {
            History::test_graph_root_scope(&history.root, |read| {
                let (result, measured) =
                    norito::core::with_decode_limits_measured(limits(usize::MAX), || {
                        counted(false, None, || {
                            assert!(!read.covers(&history.root));
                            evidence.revalidate_in_tree(Some(&snapshot), tree, Some(read))
                        })
                    });
                result.0?;
                assert_eq!((result.1.inventories, result.1.shared), (0, 0));
                assert_eq!(measured.total_allocated_bytes(), 0);
                Ok::<_, Error>(())
            })
        })
        .unwrap();
    assert_eq!(fixture.native.chain.height(), 4);
}

#[cfg(unix)]
struct RestorePermissions(std::path::PathBuf, std::fs::Permissions);
#[cfg(unix)]
impl RestorePermissions {
    fn new(path: &std::path::Path) -> Self {
        Self(
            path.to_owned(),
            std::fs::metadata(path).unwrap().permissions(),
        )
    }
}
#[cfg(unix)]
impl Drop for RestorePermissions {
    fn drop(&mut self) {
        std::fs::set_permissions(&self.0, self.1.clone()).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn graph_root_scope_closes_persistent_changes_and_keeps_fresh_inventory_errors() {
    use std::{fs, os::unix::fs::PermissionsExt as _};
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history.current_history().unwrap();
    for boundary in [Boundary::InventoryRead, Boundary::BodyClosed] {
        for occurrence in [1, 7, 12] {
            for ordinary in [false, true] {
                let restore = RestorePermissions::new(history.root.path());
                let path = restore.0.clone();
                let mut seen = 0;
                let hook: Hook = Box::new(move |point| {
                    if point == boundary {
                        seen += 1;
                    }
                    if point == boundary && seen == occurrence {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
                        if ordinary {
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
                assert_eq!(counts.directions, if occurrence <= 6 { 1 } else { 2 });
                native.test_require_current(6).0.unwrap();
            }
        }
    }
    // A physical same-name replacement is refused, even if the body also returns an error.
    for ordinary in [false, true] {
        let original = history.root.path().to_owned();
        let moved = original.with_extension("1082-moved");
        struct RestoreRoot {
            original: std::path::PathBuf,
            moved: std::path::PathBuf,
        }
        impl Drop for RestoreRoot {
            fn drop(&mut self) {
                if self.moved.exists() {
                    if self.original.exists() {
                        fs::remove_dir(&self.original).unwrap();
                    }
                    fs::rename(&self.moved, &self.original).unwrap();
                }
            }
        }
        let restore = RestoreRoot {
            original: original.clone(),
            moved: moved.clone(),
        };
        let original_hook = original.clone();
        let moved_hook = moved.clone();
        let mut changed = false;
        let hook: Hook = Box::new(move |point| {
            if !changed && point == Boundary::InventoryRead {
                fs::rename(&original_hook, &moved_hook)?;
                fs::create_dir(&original_hook)?;
                fs::set_permissions(&original_hook, fs::Permissions::from_mode(0o700))?;
                changed = true;
                if ordinary {
                    return Err(Error::NativeDeadline);
                }
            }
            Ok(())
        });
        let (result, _) = counted(false, Some(hook), || native.test_require_current(6).0);
        drop(restore);
        assert!(matches!(result, Err(Error::Io(_))));
        native.test_require_current(6).0.unwrap();
    }
    // No inventory verdict is reused: added material is noticed at the next actual census.
    let root = Arc::clone(&history.root);
    let mut changed = false;
    let hook: Hook = Box::new(move |point| {
        if !changed && point == Boundary::BodyClosed {
            root.write_atomic("foreign", b"unknown", PublishMode::CreateNew)?;
            changed = true;
        }
        Ok(())
    });
    let (result, counts) = counted(false, Some(hook), || native.test_require_current(6).0);
    fs::remove_file(history.root.path().join("foreign")).unwrap();
    assert!(result.is_err());
    assert!(counts.shared >= 2);
    let hook: Hook = Box::new(|_| Err(Error::NativeDeadline));
    let (result, counts) = counted(false, Some(hook), || native.test_require_current(6).0);
    assert!(matches!(result, Err(Error::NativeDeadline)));
    assert_eq!((counts.directions, counts.shared), (1, 1));
    native.test_require_current(6).0.unwrap();
    assert_eq!(fixture.native.chain.height(), 4);
}

#[cfg(unix)]
#[test]
fn graph_root_scope_documents_restored_root_timing_without_reusing_later_verdicts() {
    use std::{fs, os::unix::fs::PermissionsExt as _};
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history.current_history().unwrap();
    for original in [true, false] {
        let restore = RestorePermissions::new(history.root.path());
        let path = restore.0.clone();
        let permissions = restore.1.clone();
        let mut changed = false;
        let hook: Hook = Box::new(move |point| {
            if !changed && point == Boundary::InventoryRead {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
                changed = true;
            } else if changed && point == Boundary::BodyClosed {
                fs::set_permissions(&path, permissions.clone())?;
            }
            Ok(())
        });
        let (result, _) = counted(original, Some(hook), || native.test_require_current(6).0);
        drop(restore);
        if original {
            assert!(
                matches!(result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied)
            );
        } else {
            result.unwrap();
        }
        native.test_require_current(6).0.unwrap();
    }
    assert_eq!(fixture.native.chain.height(), 4);
}
