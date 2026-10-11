//! Local successor hashes preserve the genuine parser's sources, callbacks and admission.

use super::*;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

#[derive(Clone, Copy)]
pub(super) enum Point {
    Outer,
    Body,
}
thread_local! {
    static ORIGINAL_RECIPE: Cell<bool> = const { Cell::new(false) };
    static RECOMPUTED: Cell<Option<[usize; 2]>> = const { Cell::new(None) };
}
pub(super) fn original_recipe() -> bool {
    ORIGINAL_RECIPE.get()
}
pub(super) fn recomputed(point: Point) {
    if let Some(mut counts) = RECOMPUTED.get() {
        counts[point as usize] += 1;
        RECOMPUTED.set(Some(counts));
    }
}
fn counted<T>(original: bool, action: impl FnOnce() -> T) -> (T, [usize; 2]) {
    struct Restore(bool, Option<[usize; 2]>);
    impl Drop for Restore {
        fn drop(&mut self) {
            ORIGINAL_RECIPE.set(self.0);
            RECOMPUTED.set(self.1);
        }
    }
    let _restore = Restore(
        ORIGINAL_RECIPE.replace(original),
        RECOMPUTED.replace(Some([0; 2])),
    );
    let result = action();
    (result, RECOMPUTED.get().unwrap())
}
fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
}
fn same(actual: &BodyHistory, expected: &BodyHistory) {
    assert!(Arc::ptr_eq(&actual.root, &expected.root));
    assert_eq!(actual.bodies.len(), expected.bodies.len());
    assert_eq!(
        actual.selection.digest().unwrap(),
        expected.selection.digest().unwrap()
    );
    assert_eq!(actual.anchor.completed, expected.anchor.completed);
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
    for (actual, expected) in actual.bodies.iter().zip(&expected.bodies) {
        assert!(Arc::ptr_eq(&actual.directory, &expected.directory));
        assert_eq!(
            actual.reservation.digest().unwrap(),
            expected.reservation.digest().unwrap()
        );
        assert_eq!(actual.semantic, expected.semantic);
    }
}
struct ChangedReservation {
    directory: Arc<PrivateDirectory>,
    bytes: zeroize::Zeroizing<Vec<u8>>,
}
impl ChangedReservation {
    fn apply(directory: Arc<PrivateDirectory>, malformed: bool) -> Self {
        let bytes = directory.read("reserved.nrt", MAX_BODY_BYTES).unwrap();
        let changed = if malformed {
            b"malformed current reservation".to_vec()
        } else {
            let mut value: Reservation = decode(&bytes, MAX_BODY_BYTES).unwrap();
            value.unsigned.selected_at_unix_ms += 1;
            encode(&value, MAX_BODY_BYTES).unwrap()
        };
        directory
            .write_atomic("reserved.nrt", &changed, PublishMode::Replace)
            .unwrap();
        Self { directory, bytes }
    }
}
impl Drop for ChangedReservation {
    fn drop(&mut self) {
        self.directory
            .write_atomic("reserved.nrt", &self.bytes, PublishMode::Replace)
            .unwrap();
    }
}

#[test]
fn exact_local_targets_avoid_only_duplicate_hashing_and_keep_active_and_native_fences() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let original_head = std::ptr::from_ref(history.current_history().unwrap()) as usize;
    for index in 0..3 {
        match history.successor(index).unwrap() {
            Some(successor) => {
                assert!(index < 2);
                assert_eq!(successor.target.outer, history.selection.digest().unwrap());
                assert_eq!(
                    successor.target.previous_body,
                    history.bodies[index].reservation.digest().unwrap()
                );
            }
            None => assert_eq!(index, 2),
        }
    }
    let callbacks = Rc::new(RefCell::new(Vec::new()));
    let observe = || {
        let callbacks = Rc::clone(&callbacks);
        move |point| {
            if let parser_handle_tests::Point::WalletInspected(index) = point {
                callbacks.borrow_mut().push(index);
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
    assert_eq!(callbacks.take(), [0, 0, 1, 1]);
    let ((new, new_work), new_counts) = counted(false, || {
        parser_handle_tests::with_hook(observe(), || {
            History::test_handle_work(|| history.read_current(&fixture.owner))
        })
    });
    same(&new.unwrap(), &old);
    assert_eq!(callbacks.take(), [0, 0, 1, 1]);
    // Only changed-site producers are counted. The final body has no successor and keeps
    // both original outer digests plus its original body digest. No call is hoisted.
    assert_eq!(old_counts, [6, 3]);
    assert_eq!(new_counts, [2, 1]);
    assert_eq!(old_work.history_order.len(), new_work.history_order.len());
    assert_eq!(
        old_work
            .history_order
            .iter()
            .map(|owner| *owner == original_head)
            .collect::<Vec<_>>(),
        new_work
            .history_order
            .iter()
            .map(|owner| *owner == original_head)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        old_work
            .descendant_order
            .iter()
            .map(|(attempt, _)| *attempt)
            .collect::<Vec<_>>(),
        new_work
            .descendant_order
            .iter()
            .map(|(attempt, _)| *attempt)
            .collect::<Vec<_>>()
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
    let old_callbacks = callbacks.take();
    let ((new, new_counts), new_usage) =
        norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            counted(false, || {
                parser_handle_tests::with_hook(observe(), || history.read_current(&fixture.owner))
            })
        });
    same(&new.unwrap(), &old);
    assert_eq!(callbacks.take(), old_callbacks);
    assert_eq!((old_counts, new_counts), ([6, 3], [6, 3]));
    assert_eq!(old_usage, new_usage);
    let exact = old_usage.total_allocated_bytes();
    assert!(exact > 1);
    for allocation in [1, exact / 2, exact - 1, exact] {
        let ((old, old_counts), old_usage) =
            norito::core::with_decode_limits_measured(limits(allocation), || {
                counted(true, || {
                    parser_handle_tests::with_hook(observe(), || {
                        history.read_current(&fixture.owner)
                    })
                })
            });
        let old_callbacks = callbacks.take();
        let ((new, new_counts), new_usage) =
            norito::core::with_decode_limits_measured(limits(allocation), || {
                counted(false, || {
                    parser_handle_tests::with_hook(observe(), || {
                        history.read_current(&fixture.owner)
                    })
                })
            });
        assert_eq!(callbacks.take(), old_callbacks);
        assert_eq!(old_counts, new_counts);
        assert_eq!(old_usage, new_usage);
        if allocation == 1 {
            assert!(old.is_err());
        }
        if allocation == exact {
            assert!(old.is_ok());
        }
        match (old, new) {
            (Ok(old), Ok(new)) => same(&new, &old),
            (Err(old), Err(new)) => assert_eq!(old.to_string(), new.to_string()),
            _ => panic!("active target hashing recipe changed"),
        }
    }

    let changed = ChangedReservation::apply(Arc::clone(&history.bodies[0].directory), true);
    for original in [true, false] {
        let (result, counts) = counted(original, || {
            parser_handle_tests::with_hook(observe(), || history.read_current(&fixture.owner))
        });
        assert!(matches!(
            result,
            Err(crate::managed::Error::Bootstrap(
                ManagedBootstrapFailure::RetainedMaterial
            ))
        ));
        assert_eq!(counts, [0, 0]);
        assert!(callbacks.take().is_empty());
    }
    drop(changed);

    for original in [true, false] {
        for (mutate, ordinary_error) in [(false, true), (true, false), (true, true)] {
            let changed = Rc::new(RefCell::new(None));
            let mutation = Rc::clone(&changed);
            let directory = Arc::clone(&history.bodies[0].directory);
            let calls = Rc::clone(&callbacks);
            let ((result, work), _) = counted(original, || {
                parser_handle_tests::with_hook(
                    move |point| {
                        if let parser_handle_tests::Point::WalletInspected(index) = point {
                            let mut calls = calls.borrow_mut();
                            calls.push(index);
                            if calls.len() == 4 {
                                if mutate {
                                    *mutation.borrow_mut() = Some(ChangedReservation::apply(
                                        Arc::clone(&directory),
                                        false,
                                    ));
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
            assert_eq!(callbacks.take(), [0, 0, 1, 1]);
            if mutate {
                assert!(matches!(
                    result,
                    Err(crate::managed::Error::Bootstrap(
                        ManagedBootstrapFailure::RetainedMaterial
                    ))
                ));
            } else {
                assert!(matches!(result, Err(crate::managed::Error::NativeDeadline)));
            }
            assert_eq!(
                work.history_order
                    .iter()
                    .filter(|&&owner| owner == original_head)
                    .count(),
                3
            );
            drop(changed.borrow_mut().take());
        }
    }
    history.read_current(&fixture.owner).unwrap();
    assert_eq!(fixture.native.chain.height(), 4);
}
