//! Same-parse canonical Original reuse preserves active budgets and complete native exits.

use super::*;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

#[derive(Clone, Copy)]
pub(super) enum Point {
    Length,
    ReadDigest,
    HistoryDigest,
}
thread_local! {
    static ORIGINAL_RECIPE: Cell<bool> = const { Cell::new(false) };
    static RECOMPUTED: Cell<Option<[usize; 3]>> = const { Cell::new(None) };
}
pub(super) fn original_recipe() -> bool {
    ORIGINAL_RECIPE.with(Cell::get)
}
pub(super) fn recomputed(point: Point) {
    RECOMPUTED.with(|state| {
        if let Some(mut counts) = state.get() {
            counts[point as usize] += 1;
            state.set(Some(counts));
        }
    });
}
fn counted<T>(original: bool, action: impl FnOnce() -> T) -> (T, [usize; 3]) {
    struct Restore(bool, Option<[usize; 3]>);
    impl Drop for Restore {
        fn drop(&mut self) {
            ORIGINAL_RECIPE.with(|state| state.set(self.0));
            RECOMPUTED.with(|state| state.set(self.1));
        }
    }
    let _restore = Restore(
        ORIGINAL_RECIPE.with(|state| state.replace(original)),
        RECOMPUTED.with(|state| state.replace(Some([0; 3]))),
    );
    let value = action();
    (value, RECOMPUTED.with(|state| state.get().unwrap()))
}
fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
}
fn same(actual: &BodyHistory, expected: &BodyHistory) {
    assert!(Arc::ptr_eq(&actual.root, &expected.root));
    assert_eq!(actual.bodies.len(), expected.bodies.len());
    assert_eq!(actual.anchor.completed, expected.anchor.completed);
    for (actual, expected) in actual.bodies.iter().zip(&expected.bodies) {
        assert!(Arc::ptr_eq(&actual.directory, &expected.directory));
        assert_eq!(actual.semantic, expected.semantic);
        assert_eq!(
            actual.reservation.digest().unwrap(),
            expected.reservation.digest().unwrap()
        );
        assert_eq!(
            actual.original.as_ref().unwrap().digest().unwrap(),
            expected.original.as_ref().unwrap().digest().unwrap()
        );
    }
    assert_eq!(
        actual
            .current_history()
            .unwrap()
            .cumulative_reserved_count(),
        expected
            .current_history()
            .unwrap()
            .cumulative_reserved_count()
    );
}
struct ChangedOriginal {
    directory: Arc<PrivateDirectory>,
    bytes: zeroize::Zeroizing<Vec<u8>>,
}
impl ChangedOriginal {
    fn apply(directory: Arc<PrivateDirectory>) -> Self {
        let bytes = directory
            .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap();
        directory
            .write_atomic(
                "original.nrt",
                b"changed after decode",
                PublishMode::Replace,
            )
            .unwrap();
        Self { directory, bytes }
    }
}
impl Drop for ChangedOriginal {
    fn drop(&mut self) {
        self.directory
            .write_atomic("original.nrt", &self.bytes, PublishMode::Replace)
            .unwrap();
    }
}

#[test]
fn canonical_original_observations_remove_only_recomputation_and_preserve_active_admission() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    assert_eq!(history.bodies.len(), 3);
    for body in &history.bodies {
        let (original, bytes) = journal::read_body_intent(&body.directory).unwrap().unwrap();
        let snapshot = body
            .snapshots
            .records
            .iter()
            .find(|record| record.name == "original.nrt")
            .unwrap();
        assert_eq!(norito::canonical_frame_len(&original).unwrap(), bytes.len());
        assert_eq!(
            original.digest().unwrap(),
            *Hash::new(bytes.as_slice()).as_ref()
        );
        assert_eq!(
            snapshot.observed,
            Some((bytes.len(), original.digest().unwrap()))
        );
        assert_eq!(body.semantic, Some(original.digest().unwrap()));
    }
    let callbacks = Rc::new(Cell::new(0));
    let observe = || {
        let calls = Rc::clone(&callbacks);
        move |point| {
            if matches!(point, parser_handle_tests::Point::WalletInspected(_)) {
                calls.set(calls.get() + 1);
            }
            Ok(())
        }
    };
    let ((old, old_work), old_counts) = counted(true, || {
        parser_handle_tests::with_hook(observe(), || {
            History::test_handle_work(|| history.read_current(&fixture.owner))
        })
    });
    let old = old.unwrap();
    assert_eq!(callbacks.replace(0), 4);
    let ((new, new_work), new_counts) = counted(false, || {
        parser_handle_tests::with_hook(observe(), || {
            History::test_handle_work(|| history.read_current(&fixture.owner))
        })
    });
    same(&new.unwrap(), &old);
    assert_eq!(callbacks.replace(0), 4);
    // These counters sit immediately before the real size/digest producers at only the
    // three changed call sites. Other Original encoding/validation remains untouched.
    assert_eq!(old_counts, [3, 3, 6]);
    assert_eq!(new_counts, [0, 0, 0]);
    assert_eq!(old_work.history_order.len(), new_work.history_order.len());
    assert_eq!(
        old_work.descendant_order.len(),
        new_work.descendant_order.len()
    );
    assert_eq!(old_work.tree_brackets, new_work.tree_brackets);
    assert_eq!(old_work.full_operations, new_work.full_operations);
    assert_eq!(old_work.tree_operations, new_work.tree_operations);
    assert_eq!(old_work.operation_exits, new_work.operation_exits);

    let ((old, old_counts), old_usage) =
        norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            counted(true, || {
                parser_handle_tests::with_hook(observe(), || history.read_current(&fixture.owner))
            })
        });
    let old = old.unwrap();
    let old_callbacks = callbacks.replace(0);
    let ((new, new_counts), new_usage) =
        norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            counted(false, || {
                parser_handle_tests::with_hook(observe(), || history.read_current(&fixture.owner))
            })
        });
    same(&new.unwrap(), &old);
    assert_eq!(callbacks.replace(0), old_callbacks);
    assert_eq!((old_counts, new_counts), ([3, 3, 6], [3, 3, 6]));
    assert_eq!(old_usage, new_usage);
    let exact = old_usage.total_allocated_bytes();
    assert!(exact > 1);
    for allocation in [0, 1, exact - 1, exact] {
        let ((old, old_counts), old_usage) =
            norito::core::with_decode_limits_measured(limits(allocation), || {
                counted(true, || {
                    parser_handle_tests::with_hook(observe(), || {
                        history.read_current(&fixture.owner)
                    })
                })
            });
        let old_callbacks = callbacks.replace(0);
        let ((new, new_counts), new_usage) =
            norito::core::with_decode_limits_measured(limits(allocation), || {
                counted(false, || {
                    parser_handle_tests::with_hook(observe(), || {
                        history.read_current(&fixture.owner)
                    })
                })
            });
        assert_eq!(callbacks.replace(0), old_callbacks);
        assert_eq!(old_counts, new_counts);
        assert_eq!(old_usage, new_usage);
        match (old, new) {
            (Ok(old), Ok(new)) if allocation == exact => same(&new, &old),
            (Err(old), Err(new)) if allocation < exact => {
                assert_eq!(old.to_string(), new.to_string())
            }
            _ => panic!("active original encoding recipe changed"),
        }
    }

    // Malformed current bytes still fail the sole canonical decoder before any shortcut.
    let changed = ChangedOriginal::apply(Arc::clone(&history.bodies[0].directory));
    let old = counted(true, || history.read_current(&fixture.owner))
        .0
        .err()
        .unwrap();
    let new = counted(false, || history.read_current(&fixture.owner))
        .0
        .err()
        .unwrap();
    assert_eq!(old.to_string(), new.to_string());
    drop(changed);

    // A persistent old Original mutation at the last real wallet callback must still
    // close the old native owner and override an ordinary callback error identically.
    let original_head = std::ptr::from_ref(history.current_history().unwrap()) as usize;
    for original in [true, false] {
        for ordinary_error in [false, true] {
            for mutate in [false, true] {
                let changed = Rc::new(RefCell::new(None));
                let mutation = Rc::clone(&changed);
                let directory = Arc::clone(&history.bodies[0].directory);
                let calls = Rc::clone(&callbacks);
                let ((result, work), _) = counted(original, || {
                    parser_handle_tests::with_hook(
                        move |point| {
                            if matches!(point, parser_handle_tests::Point::WalletInspected(_)) {
                                calls.set(calls.get() + 1);
                                if calls.get() == 4 {
                                    if mutate {
                                        *mutation.borrow_mut() =
                                            Some(ChangedOriginal::apply(Arc::clone(&directory)));
                                    }
                                    if ordinary_error {
                                        return Err(crate::managed::Error::NativeDeadline);
                                    }
                                }
                            }
                            Ok(())
                        },
                        || History::test_handle_work(|| history.read_current(&fixture.owner)),
                    )
                });
                assert_eq!(callbacks.replace(0), 4);
                if mutate {
                    assert!(matches!(
                        result,
                        Err(crate::managed::Error::Bootstrap(
                            ManagedBootstrapFailure::RetainedMaterial
                        ))
                    ));
                } else if ordinary_error {
                    assert!(matches!(result, Err(crate::managed::Error::NativeDeadline)));
                } else {
                    same(&result.unwrap(), &history);
                }
                assert_eq!(
                    work.history_order
                        .iter()
                        .filter(|&&owner| owner == original_head)
                        .count(),
                    if mutate || ordinary_error { 3 } else { 4 }
                );
                drop(changed.borrow_mut().take());
            }
        }
    }
    history.read_current(&fixture.owner).unwrap();
    assert_eq!(fixture.native.chain.height(), 4);
}
