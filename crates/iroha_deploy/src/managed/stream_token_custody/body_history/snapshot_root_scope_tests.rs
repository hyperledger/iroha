//! Genuine snapshot roots consolidate adjacent native brackets, never leaves or authority.

use super::*;
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Point {
    Inventory,
    Original,
    Anchor,
}
#[derive(Debug, Default, PartialEq, Eq)]
struct Counts {
    original_scopes: usize,
    combined_scopes: usize,
    order: Vec<Point>,
}
type Hook = Box<dyn FnMut(Point) -> Result<()>>;
struct State {
    original: bool,
    root: Arc<PrivateDirectory>,
    counts: Counts,
    hook: Option<Hook>,
}
thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}
pub(super) fn original_recipe() -> bool {
    STATE.with(|state| state.borrow().as_ref().is_some_and(|state| state.original))
}
pub(super) fn root_scope(combined: bool) {
    STATE.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            if combined {
                state.counts.combined_scopes += 1;
            } else {
                state.counts.original_scopes += 1;
            }
        }
    });
}
fn hit(directory: &PrivateDirectory, point: Point) -> Result<()> {
    let (selected, mut hook) = STATE.with(|state| {
        let mut state = state.borrow_mut();
        match state.as_mut() {
            Some(state) if std::ptr::eq(state.root.as_ref(), directory) => {
                state.counts.order.push(point);
                (true, state.hook.take())
            }
            _ => (false, None),
        }
    });
    let result = hook.as_mut().map_or(Ok(()), |hook| hook(point));
    if selected {
        STATE.with(|state| state.borrow_mut().as_mut().unwrap().hook = hook);
    }
    result
}
pub(super) fn after_inventory(directory: &PrivateDirectory) -> Result<()> {
    hit(directory, Point::Inventory)
}
pub(super) fn after_record(record: &RecordSnapshot) -> Result<()> {
    match record.name.as_str() {
        "original.nrt" => hit(&record.directory, Point::Original),
        "anchor.nrt" => hit(&record.directory, Point::Anchor),
        _ => Ok(()),
    }
}
fn observe<T>(
    original: bool,
    root: &Arc<PrivateDirectory>,
    hook: Option<Hook>,
    read: impl FnOnce() -> T,
) -> (T, Counts) {
    struct Restore(Option<State>);
    impl Drop for Restore {
        fn drop(&mut self) {
            STATE.with(|state| state.replace(self.0.take()));
        }
    }
    let _restore = Restore(STATE.with(|state| {
        state.replace(Some(State {
            original,
            root: Arc::clone(root),
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
fn copy_snapshot(snapshot: &Snapshot) -> Snapshot {
    Snapshot {
        previous: snapshot.previous.as_ref().map(Arc::clone),
        records: snapshot
            .records
            .iter()
            .map(|record| RecordSnapshot {
                directory: Arc::clone(&record.directory),
                name: record.name.clone(),
                maximum: record.maximum,
                observed: record.observed,
            })
            .collect(),
        names: snapshot
            .names
            .iter()
            .map(|names| NamesSnapshot {
                directory: Arc::clone(&names.directory),
                maximum: names.maximum,
                names: names.names.clone(),
            })
            .collect(),
        root: snapshot.root.as_ref().map(Arc::clone),
    }
}

#[test]
fn genuine_root_scope_keeps_graph_leaves_layout_gates_and_exact_active_recipe() {
    let _resources = crate::managed::native_test_guard();
    let (_fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history.current_history().unwrap();
    let head = &history.bodies.last().unwrap().snapshots;
    assert!(head.tree_root().is_some());
    let read = |original| {
        observe(original, &history.root, None, || {
            shared_snapshot_tests::snapshot_work(|| native.test_require_current(6))
        })
    };
    let (((old, old_graph), old_leaves), old_scope) = read(true);
    let (((new, new_graph), new_leaves), new_scope) = read(false);
    old.unwrap();
    new.unwrap();
    assert_eq!(old_leaves, new_leaves);
    assert_eq!(new_leaves, (30, 10));
    assert_eq!((old_graph.visits, new_graph.visits), (6, 6));
    assert_eq!(
        (old_graph.native_tree_visits, new_graph.native_tree_visits),
        (6, 6)
    );
    assert_eq!(
        (old_graph.distinct_histories, new_graph.distinct_histories),
        (3, 3)
    );
    assert_eq!(
        (old_scope.original_scopes, old_scope.combined_scopes),
        (2, 0)
    );
    assert_eq!(
        (new_scope.original_scopes, new_scope.combined_scopes),
        (0, 2)
    );
    assert_eq!(old_scope.order, new_scope.order);
    assert_eq!(
        new_scope.order,
        [Point::Inventory, Point::Original, Point::Anchor].repeat(2)
    );
    // Original: explicit revalidate + entries entry/exit + pair scope entry/exit = five
    // root walks. Combined: one existing scope entry/exit = two. These counters identify
    // executed recipes; they are not syscall or elapsed-time measurements.

    let (result, counts) = observe(false, &history.root, None, || {
        history
            .root
            .read_tree_scope(|tree| head.revalidate_in_tree(Some(tree)))
    });
    result.unwrap(); // Tree presence without the exact-layout witness is insufficient.
    assert_eq!((counts.original_scopes, counts.combined_scopes), (1, 0));
    let mut base = head.as_ref();
    while let Some(previous) = &base.previous {
        base = previous;
    }
    assert!(base.tree_root().is_none());
    let (result, counts) = observe(false, &history.root, None, || base.revalidate());
    result.unwrap();
    assert_eq!((counts.original_scopes, counts.combined_scopes), (1, 0));
    let reopened = PrivateDirectory::open(history.root.path()).unwrap();
    let (result, counts) = observe(false, &history.root, None, || {
        history
            .root
            .read_tree_scope(|tree| head.revalidate_in_tree_with_root(Some(tree), Some(&reopened)))
    });
    result.unwrap();
    assert_eq!((counts.original_scopes, counts.combined_scopes), (1, 0));

    for change in ["name", "bound", "owner", "extra", "root"] {
        let mut changed = copy_snapshot(head);
        match change {
            "name" => changed.records[0].name = "unrecognized.nrt".into(),
            "bound" => changed.records[0].maximum -= 1,
            "owner" => changed.records[0].directory = Arc::clone(&history.root),
            "extra" => changed.records.push(copy_snapshot(base).records.remove(0)),
            "root" => changed.root = Some(Arc::clone(&history.root)),
            _ => unreachable!(),
        }
        assert!(changed.tree_root().is_none(), "{change}");
        let old = observe(true, &history.root, None, || outcome(changed.revalidate()));
        let new = observe(false, &history.root, None, || outcome(changed.revalidate()));
        assert_eq!(old, new, "{change}");
        assert_eq!(new.1.combined_scopes, 0);
    }
    let mut excessive = Arc::clone(head);
    for _ in history.bodies.len()..=usize::from(MAX_BODIES) {
        let mut next = copy_snapshot(head);
        next.previous = Some(excessive);
        excessive = Arc::new(next);
    }
    assert!(excessive.tree_root().is_none());

    let run = |original, allocation| {
        norito::core::with_decode_limits_measured(limits(allocation), || {
            observe(original, &history.root, None, || {
                shared_snapshot_tests::snapshot_work(|| outcome(native.test_require_current(6).0))
            })
        })
    };
    let old = run(true, usize::MAX);
    let new = run(false, usize::MAX);
    assert_eq!(old, new);
    assert!(old.0.0.0.is_ok());
    assert_eq!(old.0.1.combined_scopes, 0);
    let exact = old.1.total_allocated_bytes();
    assert!(exact > 1);
    for allocation in [1, exact / 2, exact - 1, exact] {
        let old = run(true, allocation);
        let new = run(false, allocation);
        assert_eq!(old, new);
        assert_eq!(new.0.1.combined_scopes, 0);
        if allocation == 1 {
            assert!(new.0.0.0.is_err());
        }
        if allocation == exact {
            assert!(new.0.0.0.is_ok());
        }
    }
    let run = |original| {
        history.root.read_tree_scope(|tree| {
            Ok::<_, crate::managed::Error>(norito::core::with_decode_limits_measured(
                limits(usize::MAX),
                || {
                    observe(original, &history.root, None, || {
                        outcome(head.revalidate_in_tree_with_root(Some(tree), Some(&history.root)))
                    })
                },
            ))
        })
    };
    let old = run(true).unwrap();
    let new = run(false).unwrap();
    assert_eq!(old, new); // Budget installed after tree and original owner acquisition.
    assert!(new.0.0.is_ok());
    assert_eq!(new.0.1.combined_scopes, 0);
}

#[test]
fn genuine_root_scope_preserves_changed_records_and_independent_reference_errors() {
    let _resources = crate::managed::native_test_guard();
    let (_fixture, history) = shared_snapshot_tests::history();
    let head = &history.bodies.last().unwrap().snapshots;
    history
        .root
        .write_atomic("foreign.nrt", b"unexpected", PublishMode::CreateNew)
        .unwrap();
    let old = observe(true, &history.root, None, || outcome(head.revalidate()));
    let new = observe(false, &history.root, None, || outcome(head.revalidate()));
    std::fs::remove_file(history.root.path().join("foreign.nrt")).unwrap();
    assert_eq!(old.0, new.0);
    assert!(new.0.is_err());
    assert!(!old.1.order.contains(&Point::Original));
    assert!(!new.1.order.contains(&Point::Original));
    head.revalidate().unwrap();
    for (name, maximum) in [
        ("original.nrt", MAX_SELECTION_BYTES),
        ("anchor.nrt", MAX_BODY_BYTES),
    ] {
        let bytes = history.root.read(name, maximum).unwrap();
        history
            .root
            .write_atomic(name, b"changed", PublishMode::Replace)
            .unwrap();
        let old = observe(true, &history.root, None, || outcome(head.revalidate()));
        let new = observe(false, &history.root, None, || outcome(head.revalidate()));
        history
            .root
            .write_atomic(name, &bytes, PublishMode::Replace)
            .unwrap();
        assert_eq!(old.0, new.0);
        assert_eq!(old.1.order, new.1.order);
        assert!(
            new.0
                .unwrap_err()
                .contains("retained enrollment body material changed")
        );
        head.revalidate().unwrap();
    }
    let mut base = head.as_ref();
    while let Some(previous) = &base.previous {
        base = previous;
    }
    let reference = &base.records[2];
    let bytes = reference
        .directory
        .read(&reference.name, reference.maximum)
        .unwrap();
    reference
        .directory
        .write_atomic(&reference.name, b"changed", PublishMode::Replace)
        .unwrap();
    let old = observe(true, &history.root, None, || outcome(head.revalidate()));
    let new = observe(false, &history.root, None, || outcome(head.revalidate()));
    reference
        .directory
        .write_atomic(&reference.name, &bytes, PublishMode::Replace)
        .unwrap();
    assert_eq!(old.0, new.0);
    assert!(
        new.0
            .unwrap_err()
            .contains("retained enrollment body material changed")
    );
    assert_eq!(
        new.1.order,
        [Point::Inventory, Point::Original, Point::Anchor]
    );
    head.revalidate().unwrap();
    for point in [Point::Inventory, Point::Original, Point::Anchor] {
        for original in [true, false] {
            let hook = Box::new(move |observed| {
                if observed == point {
                    Err(invalid("ordinary root inspection refused"))
                } else {
                    Ok(())
                }
            });
            let (result, _) = observe(original, &history.root, Some(hook), || {
                outcome(head.revalidate())
            });
            assert!(
                result
                    .unwrap_err()
                    .contains("ordinary root inspection refused")
            );
            head.revalidate().unwrap();
        }
    }
}

#[cfg(unix)]
#[test]
fn genuine_root_scope_closes_original_identity_and_errors_with_explicit_interior_timing() {
    use std::{fs, os::unix::fs::PermissionsExt as _};
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history();
    let head = &history.bodies.last().unwrap().snapshots;
    let path = history.root.path().to_owned();
    let held = fixture._temporary.path().join("displaced-snapshot-root");
    for original in [true, false] {
        fs::rename(&path, &held).unwrap();
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let (result, counts) = observe(original, &history.root, None, || head.revalidate());
        fs::remove_dir(&path).unwrap();
        fs::rename(&held, &path).unwrap();
        assert!(result.is_err());
        assert!(counts.order.is_empty());
        head.revalidate().unwrap();
    }
    for point in [Point::Inventory, Point::Original, Point::Anchor] {
        for ordinary_error in [false, true] {
            for original in [true, false] {
                let changed = path.clone();
                let hook = Box::new(move |observed| {
                    if observed == point {
                        fs::set_permissions(&changed, fs::Permissions::from_mode(0o755))?;
                        if ordinary_error {
                            return Err(invalid("ordinary root inspection refused"));
                        }
                    }
                    Ok(())
                });
                let (result, _) =
                    observe(original, &history.root, Some(hook), || head.revalidate());
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                assert!(matches!(result, Err(crate::managed::Error::Io(error))
                    if error.kind() == std::io::ErrorKind::PermissionDenied));
                head.revalidate().unwrap();
            }
        }
    }
    for original in [true, false] {
        let changed = path.clone();
        let displaced = held.clone();
        let hook = Box::new(move |point| {
            if point == Point::Anchor {
                fs::rename(&changed, &displaced)?;
                fs::create_dir(&changed)?;
                fs::set_permissions(&changed, fs::Permissions::from_mode(0o700))?;
                return Err(invalid("ordinary root inspection refused"));
            }
            Ok(())
        });
        let (result, _) = observe(original, &history.root, Some(hook), || {
            outcome(head.revalidate())
        });
        fs::remove_dir(&path).unwrap();
        fs::rename(&held, &path).unwrap();
        assert!(result.is_err());
        assert!(
            !result
                .unwrap_err()
                .contains("ordinary root inspection refused")
        );
        head.revalidate().unwrap();
    }
    // Interior permission changes restored within this read-only bracket may be unseen.
    // No value or effect leaves the parser while the original root is temporarily changed.
    for original in [true, false] {
        let changed = path.clone();
        let hook = Box::new(move |point| {
            match point {
                Point::Inventory => {
                    fs::set_permissions(&changed, fs::Permissions::from_mode(0o755))?
                }
                Point::Original => {
                    fs::set_permissions(&changed, fs::Permissions::from_mode(0o700))?
                }
                Point::Anchor => {}
            }
            Ok(())
        });
        let (result, counts) = observe(original, &history.root, Some(hook), || head.revalidate());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        if original {
            assert!(matches!(result, Err(crate::managed::Error::Io(error))
                if error.kind() == std::io::ErrorKind::PermissionDenied));
            assert_eq!(counts.order, [Point::Inventory]);
        } else {
            result.unwrap();
            assert_eq!(
                counts.order,
                [Point::Inventory, Point::Original, Point::Anchor]
            );
        }
        head.revalidate().unwrap();
    }
}
