//! Genuine pure parser ownership, physical handle work, and mandatory custody exits.

use super::*;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Point {
    BeforeBody(usize),
    WalletInspected(usize),
}
type Hook = Box<dyn FnMut(Point) -> Result<()>>;
thread_local! {
    static ORIGINAL_RECIPE: Cell<bool> = const { Cell::new(false) };
    static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
}
pub(super) fn original_recipe() -> bool {
    ORIGINAL_RECIPE.with(Cell::get)
}
pub(super) fn hit(point: Point) -> Result<()> {
    HOOK.with(|hook| {
        hook.borrow_mut()
            .as_mut()
            .map_or(Ok(()), |hook| hook(point))
    })
}
fn with_recipe<T>(original: bool, action: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            ORIGINAL_RECIPE.with(|state| state.set(self.0));
        }
    }
    let _restore = Restore(ORIGINAL_RECIPE.with(|state| state.replace(original)));
    action()
}
pub(super) fn with_hook<T>(
    hook: impl FnMut(Point) -> Result<()> + 'static,
    action: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<Hook>);
    impl Drop for Restore {
        fn drop(&mut self) {
            HOOK.with(|state| {
                state.replace(self.0.take());
            });
        }
    }
    let _restore = Restore(HOOK.with(|state| state.replace(Some(Box::new(hook)))));
    action()
}
fn same(actual: &BodyHistory, expected: &BodyHistory) {
    assert_eq!(
        actual.selection.digest().unwrap(),
        expected.selection.digest().unwrap()
    );
    assert_eq!(actual.bodies.len(), expected.bodies.len());
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
        assert_eq!(actual.semantic, expected.semantic);
        assert_eq!(
            actual.reservation.digest().unwrap(),
            expected.reservation.digest().unwrap()
        );
    }
}
fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
}

#[cfg(unix)]
struct Replacement {
    path: std::path::PathBuf,
    held: std::path::PathBuf,
}
#[cfg(unix)]
impl Replacement {
    fn apply(path: &std::path::Path) -> Self {
        let value = Self {
            path: path.to_owned(),
            held: path.with_extension("parser-owner-original"),
        };
        assert!(!value.held.exists());
        std::fs::rename(&value.path, &value.held).unwrap();
        PrivateDirectory::open_or_create(&value.path).unwrap();
        value
    }
}
#[cfg(unix)]
impl Drop for Replacement {
    fn drop(&mut self) {
        std::fs::remove_dir(&self.path).expect("remove only empty test replacement");
        std::fs::rename(&self.held, &self.path).expect("restore exact original native directory");
    }
}

#[test]
fn sealed_parser_bounds_handle_censuses_and_closes_original_owners_on_every_result() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let n = history.bodies.len();
    assert_eq!(n, 3);
    assert_eq!(
        history
            .current_history()
            .unwrap()
            .cumulative_reserved_count(),
        2
    );
    let callbacks = Rc::new(Cell::new(0));
    let observe = || {
        let callbacks = Rc::clone(&callbacks);
        move |point| {
            if matches!(point, Point::WalletInspected(_)) {
                callbacks.set(callbacks.get() + 1);
            }
            Ok(())
        }
    };
    let (full, before) = with_recipe(true, || {
        with_hook(observe(), || {
            History::test_handle_work(|| history.read_current(&fixture.owner))
        })
    });
    let full = full.unwrap();
    assert_eq!(
        callbacks.replace(0),
        4,
        "two actual retired requests each inspected twice"
    );
    let (parsed, after) = with_hook(observe(), || {
        History::test_handle_work(|| history.read_current(&fixture.owner))
    });
    let parsed = parsed.unwrap();
    assert_eq!(callbacks.replace(0), 4);
    same(&parsed, &full);
    // Replace 2*N old-graph censuses and two whole predecessor censuses per closure
    // with two original-owner censuses and one additional complete latest-owner exit.
    // Each current body's local operation/attempt census remains in place.
    assert_eq!(
        before.history_order.len() - after.history_order.len(),
        (n - 1) * (3 * n - 1)
    );
    assert!(
        after.full_operations + after.tree_operations
            < before.full_operations + before.tree_operations
    );
    let owner = history.current_history().unwrap();
    let owner_ptr = std::ptr::from_ref(owner) as usize;
    // Outer BodyHistory entry/exit and the lexical parser entry/exit each visit the
    // exact old head once, irrespective of how many new bodies the parser reads.
    assert_eq!(
        after
            .history_order
            .iter()
            .filter(|&&ptr| ptr == owner_ptr)
            .count(),
        4
    );
    assert_eq!(
        before
            .history_order
            .iter()
            .filter(|&&ptr| ptr == owner_ptr)
            .count(),
        2 + 2 * n
    );

    // An independently parsed equal graph cannot borrow the old owner's coverage.
    // Its two complete retained censuses still run, including every predecessor.
    let foreign = full.current_history().unwrap();
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    let (result, work) = History::test_handle_work(|| {
        EnrollmentReadPass::test_retained_identity_and_fallback(&snapshot, owner, foreign)
    });
    result.unwrap();
    assert_eq!(work.history_order.len(), 2 * n);

    // Decode owners enter the original complete parser directly. Cumulative charges,
    // physical handle recipe, wallet callbacks and low-budget errors remain identical.
    let ((old, old_work), old_usage) = with_recipe(true, || {
        with_hook(observe(), || {
            norito::core::with_decode_limits_measured(limits(usize::MAX), || {
                History::test_handle_work(|| history.read_current(&fixture.owner))
            })
        })
    });
    let old = old.unwrap();
    let old_callbacks = callbacks.replace(0);
    let ((new, new_work), new_usage) = with_hook(observe(), || {
        norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            History::test_handle_work(|| history.read_current(&fixture.owner))
        })
    });
    same(&new.unwrap(), &old);
    assert_eq!(callbacks.replace(0), old_callbacks);
    assert_eq!(old_usage, new_usage);
    assert_eq!(old_work.history_order.len(), new_work.history_order.len());
    assert_eq!(old_work.full_operations, new_work.full_operations);
    assert_eq!(old_work.tree_operations, new_work.tree_operations);
    let exact = old_usage.total_allocated_bytes();
    assert!(exact > 1);
    for capacity in [0, 1, exact - 1] {
        let old = with_recipe(true, || {
            with_hook(observe(), || {
                norito::with_decode_limits_scope(limits(capacity), || {
                    history.read_current(&fixture.owner)
                })
            })
        })
        .err()
        .expect("original finite owner refuses");
        let old_callbacks = callbacks.replace(0);
        let new = with_hook(observe(), || {
            norito::with_decode_limits_scope(limits(capacity), || {
                history.read_current(&fixture.owner)
            })
        })
        .err()
        .expect("sealed parser preserves finite refusal");
        assert_eq!(old.to_string(), new.to_string());
        assert_eq!(callbacks.replace(0), old_callbacks);
    }
    let (exact_read, usage) = norito::core::with_decode_limits_measured(limits(exact), || {
        history.read_current(&fixture.owner)
    });
    same(&exact_read.unwrap(), &old);
    assert_eq!(usage, old_usage);

    // Even an ordinary early-body error before the first closure is remembered closes
    // the entire borrowed original graph, including later siblings not yet visited.
    let unchanged = with_hook(
        |point| {
            if point == Point::BeforeBody(0) {
                Err(crate::managed::Error::NativeDeadline)
            } else {
                Ok(())
            }
        },
        || history.read_current(&fixture.owner),
    );
    assert!(matches!(
        unchanged,
        Err(crate::managed::Error::NativeDeadline)
    ));

    #[cfg(unix)]
    {
        let first_attempt = history.bodies[0].directory.path().join("attempts/0001");
        let later_attempt = history.bodies[1].directory.path().join("attempts/0001");
        assert!(first_attempt.is_dir() && later_attempt.is_dir());
        // Replace a not-yet-read sibling after the complete entry and return an error
        // immediately. Its original native handle, never its equal path, closes exit.
        let changed = Rc::new(RefCell::new(None));
        let mutation = Rc::clone(&changed);
        let path = later_attempt.clone();
        let (result, work) = with_hook(
            move |point| {
                if point == Point::BeforeBody(0) {
                    *mutation.borrow_mut() = Some(Replacement::apply(&path));
                    return Err(crate::managed::Error::NativeDeadline);
                }
                Ok(())
            },
            || History::test_handle_work(|| history.read_current(&fixture.owner)),
        );
        assert!(changed.borrow().is_some());
        assert!(matches!(
            result,
            Err(crate::managed::Error::Bootstrap(
                ManagedBootstrapFailure::RetainedMaterial
            ))
        ));
        assert!(
            work.history_order
                .iter()
                .filter(|&&ptr| ptr == owner_ptr)
                .count()
                >= 3,
            "old graph is closed even when no new closure exists"
        );
        drop(changed.borrow_mut().take());
        history.read_current(&fixture.owner).unwrap();

        // A changed current attempt is refused immediately after its first actual wallet
        // callback, before the same body's second tail inspection can occur.
        let changed = Rc::new(RefCell::new(None));
        let mutation = Rc::clone(&changed);
        let calls = Rc::clone(&callbacks);
        let path = first_attempt.clone();
        let result = with_hook(
            move |point| {
                if let Point::WalletInspected(_) = point {
                    calls.set(calls.get() + 1);
                    if calls.get() == 1 {
                        *mutation.borrow_mut() = Some(Replacement::apply(&path));
                    }
                }
                Ok(())
            },
            || history.read_current(&fixture.owner),
        );
        assert_eq!(callbacks.replace(0), 1);
        assert!(changed.borrow().is_some() && result.is_err());
        drop(changed.borrow_mut().take());
        history.read_current(&fixture.owner).unwrap();

        // Read-only predecessor siblings may now fail at the unconditional full exit.
        // The last body-1 wallet callback mutates body-0 and returns an ordinary error;
        // both successful callback return and ordinary refusal must lose to custody.
        for ordinary_error in [false, true] {
            let changed = Rc::new(RefCell::new(None));
            let mutation = Rc::clone(&changed);
            let calls = Rc::clone(&callbacks);
            let path = first_attempt.clone();
            let result = with_hook(
                move |point| {
                    if let Point::WalletInspected(_) = point {
                        calls.set(calls.get() + 1);
                        if calls.get() == 4 {
                            assert_eq!(point, Point::WalletInspected(1));
                            *mutation.borrow_mut() = Some(Replacement::apply(&path));
                            if ordinary_error {
                                return Err(crate::managed::Error::NativeDeadline);
                            }
                        }
                    }
                    Ok(())
                },
                || history.read_current(&fixture.owner),
            );
            assert_eq!(callbacks.replace(0), 4);
            assert!(changed.borrow().is_some());
            assert!(matches!(
                result,
                Err(crate::managed::Error::Bootstrap(
                    ManagedBootstrapFailure::RetainedMaterial
                ))
            ));
            drop(changed.borrow_mut().take());
            history.read_current(&fixture.owner).unwrap();
        }

        // Permissions on the original older attempt are also a native custody failure.
        use std::os::unix::fs::PermissionsExt as _;
        struct Permissions(std::path::PathBuf, std::fs::Permissions);
        impl Drop for Permissions {
            fn drop(&mut self) {
                std::fs::set_permissions(&self.0, self.1.clone()).unwrap();
            }
        }
        let restore = Permissions(
            first_attempt.clone(),
            std::fs::metadata(&first_attempt).unwrap().permissions(),
        );
        let path = first_attempt.clone();
        let calls = Rc::clone(&callbacks);
        let result = with_hook(
            move |point| {
                if let Point::WalletInspected(_) = point {
                    calls.set(calls.get() + 1);
                    if calls.get() == 4 {
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
                        return Err(crate::managed::Error::NativeDeadline);
                    }
                }
                Ok(())
            },
            || history.read_current(&fixture.owner),
        );
        assert_eq!(callbacks.replace(0), 4);
        assert!(matches!(
            result,
            Err(crate::managed::Error::Bootstrap(
                ManagedBootstrapFailure::RetainedMaterial
            ))
        ));
        drop(restore);
        history.read_current(&fixture.owner).unwrap();
    }
    assert_eq!(
        fixture.native.chain.height(),
        4,
        "read-only parser performs no native effect"
    );
}
