//! Genuine graph checks consolidate only adjacent operation suffix observations.

use super::*;
use crate::managed::Error;
use std::{cell::RefCell, rc::Rc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::managed) enum Point {
    Inventory,
    Semantic,
    Metadata,
}
#[derive(Default, Debug, PartialEq, Eq)]
struct Counts {
    brackets: usize,
    leaves: Vec<Point>,
}
type Hook = Box<dyn FnMut(Point) -> Result<()>>;
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
pub(in crate::managed) fn bracket() {
    STATE.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            state.counts.brackets += 1;
        }
    });
}
pub(in crate::managed) fn after_leaf(point: Point) -> Result<()> {
    let mut hook = STATE.with(|state| {
        state.borrow_mut().as_mut().and_then(|state| {
            state.counts.leaves.push(point);
            state.hook.take()
        })
    });
    let result = hook.as_mut().map_or(Ok(()), |hook| hook(point));
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
fn operation_trios_keep_genuine_graph_leaf_order_active_recipe_and_callback_boundaries() {
    // Isolate operation-scope grouping with the original Original-read recipe.
    // Combined operation-scope grouping and Original-read coverage belongs to graph_original_tests.
    graph_original_tests::with_original_reads(operation_trios_with_original_reads);
}
fn operation_trios_with_original_reads() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history.current_history().unwrap();
    let (((old_result, old_visits), old_records), old) = counted(true, None, || {
        History::test_operation_records(|| native.test_require_current(6))
    });
    old_result.unwrap();
    let (((new_result, new_visits), new_records), new) = counted(false, None, || {
        History::test_operation_records(|| native.test_require_current(6))
    });
    new_result.unwrap();
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
    assert_eq!(old.leaves, new.leaves);
    assert_eq!(
        old.leaves,
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
    // Counts are the actual changed operation read_scope calls, not estimated syscalls.
    assert_eq!((old.brackets, new.brackets), (36, 12));

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
    // A tree borrowed before a later active owner must still take the literal None recipe.
    for allocation in [1, usize::MAX] {
        let run = |original| {
            native
                .test_native_read_tree(|tree| {
                    assert!(tree.is_some());
                    Ok(norito::core::with_decode_limits_measured(
                        limits(allocation),
                        || {
                            counted(original, None, || {
                                outcome(native.test_current_local_in_tree(tree))
                            })
                        },
                    ))
                })
                .unwrap()
        };
        assert_eq!(run(true), run(false));
    }

    let callbacks = Rc::new(RefCell::new(Vec::new()));
    let mut previous = None;
    for original in [true, false] {
        let observed = Rc::clone(&callbacks);
        let ((result, records), _) = counted(original, None, || {
            parser_handle_tests::with_hook(
                move |point| {
                    if let parser_handle_tests::Point::WalletInspected(index) = point {
                        observed.borrow_mut().push(index);
                    }
                    Ok(())
                },
                || History::test_operation_records(|| history.read_current(&fixture.owner)),
            )
        });
        let result = result.unwrap();
        assert!(Arc::ptr_eq(&result.root, &history.root));
        assert_eq!(
            result.selection.digest().unwrap(),
            history.selection.digest().unwrap()
        );
        assert_eq!(callbacks.take(), [0, 0, 1, 1]);
        if let Some(previous) = previous {
            assert_eq!(records, previous);
        }
        previous = Some(records);
    }

    // Independently reopened ancestry must retain the filesystem's full-owner fallback.
    let reopened = PrivateDirectory::open(history.root.path()).unwrap();
    for tree in [None, Some(&reopened)] {
        let run = |original| {
            counted(original, None, || {
                History::test_operation_records(|| match tree {
                    Some(directory) => directory
                        .read_tree_scope(|tree| native.test_current_local_in_tree(Some(tree))),
                    None => native.test_current_local_in_tree(None),
                })
            })
        };
        let ((old, old_records), old_counts) = run(true);
        let ((new, new_records), new_counts) = run(false);
        old.unwrap();
        new.unwrap();
        assert_eq!(old_records, new_records);
        assert_eq!(old_counts.leaves, new_counts.leaves);
        assert_eq!(
            (old_counts.brackets, new_counts.brackets),
            if tree.is_some() { (6, 2) } else { (2, 2) }
        );
    }

    let first = Arc::clone(&history.bodies[0].directory);
    first
        .write_atomic("foreign.nrt", b"foreign", PublishMode::CreateNew)
        .unwrap();
    for original in [true, false] {
        let ((result, records), counts) = counted(original, None, || {
            History::test_operation_records(|| native.test_require_current(6).0)
        });
        assert!(
            matches!(result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput)
        );
        assert_eq!(records, [0, 0, 0, 0]);
        assert_eq!(counts.leaves, [Point::Inventory]);
    }
    std::fs::remove_file(first.path().join("foreign.nrt")).unwrap();
    native.test_require_current(6).0.unwrap();

    // Change the real first dispatch only after immutable/source entry. The first decoder
    // error must stop closing/closed and all later attempts, preserving exact lazy counts.
    let dispatch = first
        .read(
            "dispatch.nrt",
            crate::managed::native_operation::attempts::MAX_RECORD_BYTES,
        )
        .unwrap();
    for original in [true, false] {
        let path = first.path().join("dispatch.nrt");
        let hook: Hook = Box::new(move |point| {
            if point == Point::Inventory {
                std::fs::write(&path, b"not canonical").unwrap();
            }
            Ok(())
        });
        let ((result, records), counts) = counted(original, Some(hook), || {
            History::test_operation_records(|| native.test_require_current(6).0)
        });
        first
            .write_atomic("dispatch.nrt", &dispatch, PublishMode::Replace)
            .unwrap();
        assert!(
            matches!(result, Err(Error::Invalid(message)) if message == "invalid canonical dispatch custody record")
        );
        assert_eq!(records, [1, 0, 0, 0]);
        assert_eq!(
            counts.leaves,
            [Point::Inventory, Point::Semantic, Point::Metadata]
        );
        native.test_require_current(6).0.unwrap();
    }

    #[cfg(unix)]
    native_mutations(&history);
    assert_eq!(fixture.native.chain.height(), 4);
}

#[cfg(unix)]
fn native_mutations(history: &BodyHistory) {
    use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf};
    struct Restore {
        path: PathBuf,
        permissions: fs::Permissions,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            fs::set_permissions(&self.path, self.permissions.clone()).unwrap();
        }
    }
    let native = history.current_history().unwrap();
    let operation = &history.bodies[0].directory;
    // Persistent original prefix/suffix custody wins both successful reads and an ordinary
    // error. The root and complete immutable snapshot still close outside this local scope.
    for path in [history.root.path(), operation.path()] {
        for metadata_at in [1, 2] {
            for ordinary_error in [false, true] {
                for original in [true, false] {
                    let restore = Restore {
                        path: path.to_owned(),
                        permissions: fs::metadata(path).unwrap().permissions(),
                    };
                    let changed = path.to_owned();
                    let mut seen = 0;
                    let hook: Hook = Box::new(move |point| {
                        if point == Point::Metadata {
                            seen += 1;
                        }
                        if point == Point::Metadata && seen == metadata_at {
                            fs::set_permissions(&changed, fs::Permissions::from_mode(0o755))
                                .unwrap();
                            if ordinary_error {
                                return Err(invalid("ordinary trio body refusal"));
                            }
                        }
                        Ok(())
                    });
                    let (result, _) =
                        counted(original, Some(hook), || native.test_require_current(6).0);
                    drop(restore);
                    assert!(
                        matches!(result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied)
                    );
                    native.test_require_current(6).0.unwrap();
                }
            }
        }
    }
    // A real leaf permission change after the inventory still refuses at the unchanged
    // next native Original read. Neither path reaches the first metadata decoder.
    let leaf = operation.path().join("original.nrt");
    for original in [true, false] {
        let restore = Restore {
            path: leaf.clone(),
            permissions: fs::metadata(&leaf).unwrap().permissions(),
        };
        let changed = leaf.clone();
        let hook: Hook = Box::new(move |point| {
            if point == Point::Inventory {
                fs::set_permissions(&changed, fs::Permissions::from_mode(0o644)).unwrap();
            }
            Ok(())
        });
        let ((result, records), counts) = counted(original, Some(hook), || {
            History::test_operation_records(|| native.test_require_current(6).0)
        });
        drop(restore);
        assert!(
            matches!(result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied)
        );
        assert_eq!(records, [0, 0, 0, 0]);
        assert_eq!(counts.leaves, [Point::Inventory, Point::Semantic]);
    }
    // Document the deliberately larger unobserved interval: exact restored suffix changes
    // inside one read-only trio need not be detected. No effect or receipt crosses it.
    for original in [true, false] {
        let path = operation.path().to_owned();
        let restore = Restore {
            path: path.clone(),
            permissions: fs::metadata(&path).unwrap().permissions(),
        };
        let saved = restore.permissions.clone();
        let mut stage = 0;
        let hook: Hook = Box::new(move |point| {
            if stage == 0 && point == Point::Inventory {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
                stage = 1;
            } else if stage == 1 && point == Point::Semantic {
                fs::set_permissions(&path, saved.clone()).unwrap();
                stage = 2;
            }
            Ok(())
        });
        let (result, _) = counted(original, Some(hook), || native.test_require_current(6).0);
        drop(restore);
        if original {
            assert!(result.is_err());
        } else {
            result.unwrap();
        }
    }
    native.test_require_current(6).0.unwrap();
}

// Observe genuine operation points with production suffix grouping enabled. This carries
// only test counters/hooks; the graph Original-read tests control coverage independently.
pub(super) fn observe_leaves<T>(
    hook: impl FnMut(Point) -> Result<()> + 'static,
    read: impl FnOnce() -> T,
) -> (T, Vec<Point>) {
    let (result, counts) = counted(false, Some(Box::new(hook)), read);
    (result, counts.leaves)
}
