//! Genuine local censuses retain every leaf and callback fence while sharing ancestry.
use super::*;
use crate::managed::Error;
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::managed) enum Point {
    RootBracket,
    OperationBracket,
    SeparateRootBracket,
    SeparateOperationBracket,
    SeparateOperationValidation,
}
#[derive(Default, Debug, PartialEq, Eq)]
struct Counts {
    root: usize,
    operation: usize,
    separate_root: usize,
    separate_operation: usize,
    separate_validation: usize,
}
type Hook = Box<dyn FnMut() -> Result<()>>;
struct State {
    original: bool,
    counts: Counts,
    exit: Option<Hook>,
}
thread_local! { static STATE: RefCell<Option<State>> = const { RefCell::new(None) }; }
pub(in crate::managed) fn original_recipe() -> bool {
    STATE.with(|state| state.borrow().as_ref().is_some_and(|state| state.original))
}
pub(in crate::managed) fn record(point: Point) {
    STATE.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            match point {
                Point::RootBracket => state.counts.root += 1,
                Point::OperationBracket => state.counts.operation += 1,
                Point::SeparateRootBracket => state.counts.separate_root += 1,
                Point::SeparateOperationBracket => state.counts.separate_operation += 1,
                Point::SeparateOperationValidation => state.counts.separate_validation += 1,
            }
        }
    });
}
pub(in crate::managed) fn before_exit(result: Result<()>) -> Result<()> {
    let mut hook = STATE.with(|state| {
        state
            .borrow_mut()
            .as_mut()
            .and_then(|state| state.exit.take())
    });
    let exit = hook.as_mut().map_or(Ok(()), |hook| hook());
    STATE.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            state.exit = hook;
        }
    });
    exit?;
    result
}
fn observe<T>(original: bool, exit: Option<Hook>, read: impl FnOnce() -> T) -> (T, Counts) {
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
            exit,
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
fn outcome(value: Result<()>) -> std::result::Result<(), String> {
    value.map_err(|error| error.to_string())
}

#[test]
fn local_census_keeps_native_leaf_order_and_reduces_actual_ancestry_brackets() {
    let _resources = crate::managed::native_test_guard();
    let (_fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history
        .current_history()
        .unwrap()
        .test_owned_predecessor_closure_history()
        .unwrap();
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    let run = |original| {
        observe(original, None, || {
            operation_scope_tests::observe_leaves(
                |_| Ok(()),
                || History::test_operation_records(|| native.test_local_census(&snapshot)),
            )
        })
    };
    let (((old, old_records), old_leaves), old_counts) = run(true);
    let (((new, new_records), new_leaves), new_counts) = run(false);
    old.unwrap();
    new.unwrap();
    assert_eq!(old_records, new_records);
    assert!(new_records[0] > 0 && new_records[1] > 0);
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
    // Each count is attached to an actual native scope or validation invocation.
    assert_eq!(
        old_counts,
        Counts {
            separate_root: 2,
            separate_operation: 2,
            separate_validation: 1,
            ..Counts::default()
        }
    );
    assert_eq!(
        new_counts,
        Counts {
            root: 1,
            operation: 1,
            ..Counts::default()
        }
    );
    let foreign = SnapshotReadPass {
        head: &history.bodies[0].snapshots,
    };
    let (result, counts) = observe(false, None, || native.test_local_census(&foreign));
    result.unwrap();
    assert_eq!((counts.root, counts.operation), (0, 0));
}

#[test]
fn local_census_inherited_and_late_decode_owners_keep_original_work_and_errors() {
    let _resources = crate::managed::native_test_guard();
    let (_fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history
        .current_history()
        .unwrap()
        .test_owned_predecessor_closure_history()
        .unwrap();
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    fn with_native_work<T>(read: impl FnOnce() -> T) -> (T, iroha_fs::CustodyWorkV1) {
        let before = iroha_fs::CustodyWorkV1::current_thread();
        let result = read();
        (
            result,
            iroha_fs::CustodyWorkV1::current_thread().since(before),
        )
    }
    let run = |original, allocation| {
        norito::core::with_decode_limits_measured(limits(allocation), || {
            with_native_work(|| {
                observe(original, None, || {
                    History::test_operation_records(|| outcome(native.test_local_census(&snapshot)))
                })
            })
        })
    };
    let full = run(true, usize::MAX);
    assert!(full.0.0.0.0.is_ok());
    assert_eq!(full, run(false, usize::MAX));
    let exact = full.1.total_allocated_bytes();
    for allocation in [0, 1, exact / 2, exact.saturating_sub(1), exact] {
        let old = run(true, allocation);
        assert_eq!(old, run(false, allocation));
        if allocation <= 1 {
            assert!(old.0.0.0.0.is_err());
        }
        let late = native
            .test_local_census_after_admission(&snapshot, |read| {
                norito::core::with_decode_limits_measured(limits(allocation), || {
                    with_native_work(|| {
                        observe(false, None, || {
                            History::test_operation_records(|| outcome(read()))
                        })
                    })
                })
            })
            .unwrap();
        assert_eq!(old, late);
    }
}

#[cfg(unix)]
#[test]
fn local_census_persistent_original_owners_override_ordinary_result_and_restore() {
    use std::{fs, os::unix::fs::PermissionsExt as _};
    let _resources = crate::managed::native_test_guard();
    let (_fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history.current_history().unwrap();
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    for directory in [&history.root, &history.bodies.last().unwrap().directory] {
        for attack in ["permission", "missing", "replacement"] {
            for semantic_error in [false, true] {
                let path = directory.path().to_owned();
                let moved = path.with_file_name(format!(
                    "{}-local-census-moved",
                    path.file_name().unwrap().to_string_lossy()
                ));
                let changed = path.clone();
                let displaced = moved.clone();
                let hook: Hook = Box::new(move || {
                    match attack {
                        "permission" => {
                            fs::set_permissions(&changed, fs::Permissions::from_mode(0o755))
                                .unwrap()
                        }
                        _ => {
                            fs::rename(&changed, &displaced).unwrap();
                            if attack == "replacement" {
                                fs::create_dir(&changed).unwrap();
                                fs::set_permissions(&changed, fs::Permissions::from_mode(0o700))
                                    .unwrap();
                            }
                        }
                    }
                    if semantic_error {
                        Err(invalid("local census semantic refusal"))
                    } else {
                        Ok(())
                    }
                });
                let (result, counts) =
                    observe(false, Some(hook), || native.test_local_census(&snapshot));
                match attack {
                    "permission" => {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap()
                    }
                    _ => {
                        if attack == "replacement" {
                            fs::remove_dir(&path).unwrap();
                        }
                        fs::rename(&moved, &path).unwrap();
                    }
                }
                assert_eq!((counts.root, counts.operation), (1, 1));
                assert!(matches!(result, Err(Error::Io(_))), "{attack}: {result:?}");
                native.test_local_census(&snapshot).unwrap();
            }
        }
    }
    let hook: Hook = Box::new(|| Err(invalid("local census semantic refusal")));
    let (result, _) = observe(false, Some(hook), || native.test_local_census(&snapshot));
    assert_eq!(
        result.unwrap_err().to_string(),
        invalid("local census semantic refusal").to_string()
    );
}

#[cfg(unix)]
#[test]
fn local_census_keeps_fresh_metadata_and_leaf_custody_and_wallet_fences() {
    use std::rc::Rc;
    use std::{fs, os::unix::fs::PermissionsExt as _};
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history.current_history().unwrap();
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    let path = history
        .bodies
        .last()
        .unwrap()
        .directory
        .path()
        .join("operation.nrt");
    let original = fs::read(&path).unwrap();
    let changed = path.clone();
    let mut once = false;
    let ((result, _), _) = observe(false, None, || {
        operation_scope_tests::observe_leaves(
            move |point| {
                if !once && point == operation_scope_tests::Point::Metadata {
                    once = true;
                    let mut bytes = fs::read(&changed).unwrap();
                    bytes[0] ^= 1;
                    fs::write(&changed, bytes).unwrap();
                }
                Ok(())
            },
            || native.test_local_census(&snapshot),
        )
    });
    fs::write(&path, &original).unwrap();
    assert!(result.is_err());
    native.test_local_census(&snapshot).unwrap();
    let original_leaf = history
        .bodies
        .last()
        .unwrap()
        .directory
        .path()
        .join("original.nrt");
    let changed = original_leaf.clone();
    let ((result, leaves), _) = observe(false, None, || {
        operation_scope_tests::observe_leaves(
            move |point| {
                if point == operation_scope_tests::Point::Inventory {
                    fs::set_permissions(&changed, fs::Permissions::from_mode(0o644)).unwrap();
                }
                Ok(())
            },
            || native.test_local_census(&snapshot),
        )
    });
    fs::set_permissions(&original_leaf, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        matches!(result, Err(Error::Io(ref error)) if error.kind() == std::io::ErrorKind::PermissionDenied)
    );
    assert_eq!(
        leaves,
        [
            operation_scope_tests::Point::Inventory,
            operation_scope_tests::Point::Semantic
        ]
    );
    for original_recipe in [true, false] {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let captured = Rc::clone(&calls);
        let (result, _) = observe(original_recipe, None, || {
            parser_handle_tests::with_hook(
                move |point| {
                    if let parser_handle_tests::Point::WalletInspected(index) = point {
                        captured.borrow_mut().push(index);
                    }
                    Ok(())
                },
                || history.read_current(&fixture.owner),
            )
        });
        result.unwrap();
        assert_eq!(*calls.borrow(), [0, 0, 1, 1]);
    }
}

#[test]
fn local_census_root_reader_removes_two_actual_root_walks_without_changing_records() {
    use iroha_fs::CustodyWorkV1;
    let _resources = crate::managed::native_test_guard();
    let (_fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history
        .current_history()
        .unwrap()
        .test_owned_predecessor_closure_history()
        .unwrap();
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    let before = CustodyWorkV1::current_thread();
    history.root.revalidate().unwrap();
    let root_walk = CustodyWorkV1::current_thread().since(before);
    assert_eq!(root_walk.ancestry_walks, 1);
    let run = |nested| {
        let before = CustodyWorkV1::current_thread();
        let result = observe(false, None, || {
            operation_scope_tests::observe_leaves(
                |_| Ok(()),
                || {
                    History::test_operation_records(|| {
                        if nested {
                            native.test_local_census_nested_root_reference(&snapshot)
                        } else {
                            native.test_local_census(&snapshot)
                        }
                    })
                },
            )
        });
        (result, CustodyWorkV1::current_thread().since(before))
    };
    let ((((nested, nested_records), nested_leaves), nested_counts), nested_work) = run(true);
    let ((((shared, shared_records), shared_leaves), shared_counts), shared_work) = run(false);
    nested.unwrap();
    shared.unwrap();
    assert_eq!(nested_records, shared_records);
    assert_eq!(nested_leaves, shared_leaves);
    assert_eq!(nested_counts, shared_counts);
    assert_eq!((shared_counts.root, shared_counts.operation), (1, 1));
    assert_eq!(nested_work.ancestry_walks, shared_work.ancestry_walks + 2);
    assert_eq!(
        nested_work.ancestry_opens,
        shared_work.ancestry_opens + 2 * root_walk.ancestry_opens
    );
}
