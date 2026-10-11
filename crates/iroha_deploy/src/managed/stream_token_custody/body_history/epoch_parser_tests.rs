//! Genuine three-body parser compares original epoch work, selected custody and all exits.

use super::parser_handle_tests::{Point, with_hook};
use super::*;
use crate::managed::native_operation::authorization::EpochReader;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

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
fn retained_refusal(result: Result<BodyHistory>) {
    assert!(matches!(
        result,
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::RetainedMaterial
        ))
    ));
}
struct Leaf {
    root: Arc<PrivateDirectory>,
    name: &'static str,
    original: Option<Vec<u8>>,
}
impl Leaf {
    fn replace(root: Arc<PrivateDirectory>, name: &'static str) -> Self {
        let original = root
            .read_optional(name, attempts::MAX_RECORD_BYTES)
            .unwrap()
            .map(|bytes| bytes.to_vec());
        root.write_atomic(
            name,
            b"changed by the read-only parser test",
            PublishMode::Replace,
        )
        .unwrap();
        Self {
            root,
            name,
            original,
        }
    }
}
impl Drop for Leaf {
    fn drop(&mut self) {
        match &self.original {
            Some(bytes) => {
                self.root
                    .write_atomic(self.name, bytes, PublishMode::Replace)
                    .unwrap();
            }
            None => {
                std::fs::remove_file(self.root.path().join(self.name)).unwrap();
            }
        }
    }
}
#[cfg(unix)]
struct Directory {
    current: std::path::PathBuf,
    original: std::path::PathBuf,
}
#[cfg(unix)]
impl Directory {
    fn replace(path: &std::path::Path) -> Self {
        let value = Self {
            current: path.to_owned(),
            original: path.with_extension("epoch-parser-original"),
        };
        assert!(!value.original.exists());
        std::fs::rename(&value.current, &value.original).unwrap();
        PrivateDirectory::open_or_create(&value.current).unwrap();
        value
    }
}
#[cfg(unix)]
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir(&self.current).unwrap();
        std::fs::rename(&self.original, &self.current).unwrap();
    }
}

#[test]
fn exact_epoch_parser_bounds_real_work_and_closes_custody_after_all_ordinary_results() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let epochs = Arc::new(history.root.open_child_optional("epochs").unwrap().unwrap());
    assert_eq!(history.bodies.len(), 3);
    assert!(history.bodies.iter().all(|body| body.original.is_some()));
    assert!(
        epochs
            .read_optional("0003.nrt", attempts::MAX_RECORD_BYTES)
            .unwrap()
            .is_some()
    );
    assert!(
        epochs
            .read_optional("0004.nrt", attempts::MAX_RECORD_BYTES)
            .unwrap()
            .is_none()
    );
    let original_head = std::ptr::from_ref(history.current_history().unwrap()) as usize;
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
    let (old, before) = EpochReader::test_original_body_censuses(|| {
        with_hook(observe(), || {
            EpochReader::test_epoch_work(|| history.read_current(&fixture.owner))
        })
    });
    let old = old.unwrap();
    assert_eq!(
        callbacks.replace(0),
        4,
        "two genuine retired requests inspected twice"
    );
    let (new, after) = with_hook(observe(), || {
        EpochReader::test_epoch_work(|| history.read_current(&fixture.owner))
    });
    same(&new.unwrap(), &old);
    assert_eq!(callbacks.replace(0), 4);
    assert_eq!(
        before.0,
        4 * 7,
        "initial plus one complete census per Original body"
    );
    assert_eq!(before.3, 8);
    assert_eq!(
        after.0,
        3 * 7 + 2 * 2,
        "initial, full scope entry and full exit plus both selected origins"
    );
    assert_eq!(after.3, 6);
    assert_eq!(
        (after.1, after.2),
        (before.1, before.2),
        "same original canonical images and digests"
    );

    // A bad selected epoch OR its optional claim refuses before that body's wallet use.
    for name in ["0002.nrt", "0002-replacement.nrt"] {
        let changed = Rc::new(RefCell::new(None));
        let mutation = Rc::clone(&changed);
        let root = Arc::clone(&epochs);
        let calls = Rc::clone(&callbacks);
        let result = with_hook(
            move |point| {
                if point == Point::BeforeBody(1) {
                    *mutation.borrow_mut() = Some(Leaf::replace(Arc::clone(&root), name));
                }
                if matches!(point, Point::WalletInspected(_)) {
                    calls.set(calls.get() + 1);
                }
                Ok(())
            },
            || history.read_current(&fixture.owner),
        );
        retained_refusal(result);
        assert!(changed.borrow().is_some());
        assert_eq!(callbacks.replace(0), 2);
        drop(changed.borrow_mut().take());
        history.read_current(&fixture.owner).unwrap();
    }

    // Intentional temporal semantics: a no-longer-selected earlier sibling can refuse
    // at full exit after later read-only wallet inspections. No signing/publication
    // callback exists in this parser. Both success and ordinary inner error close it.
    for original in [true, false] {
        for ordinary_error in [false, true] {
            let changed = Rc::new(RefCell::new(None));
            let mutation = Rc::clone(&changed);
            let root = Arc::clone(&epochs);
            let calls = Rc::clone(&callbacks);
            let action = || {
                with_hook(
                    move |point| {
                        if point == Point::BeforeBody(1) {
                            *mutation.borrow_mut() =
                                Some(Leaf::replace(Arc::clone(&root), "0001.nrt"));
                        }
                        if matches!(point, Point::WalletInspected(_)) {
                            calls.set(calls.get() + 1);
                            if ordinary_error && calls.get() == 4 {
                                return Err(crate::managed::Error::NativeDeadline);
                            }
                        }
                        Ok(())
                    },
                    || history.read_current(&fixture.owner),
                )
            };
            let (result, handles) = History::test_handle_work(|| {
                if original {
                    EpochReader::test_original_body_censuses(action)
                } else {
                    action()
                }
            });
            retained_refusal(result);
            assert_eq!(
                handles
                    .history_order
                    .iter()
                    .filter(|&&owner| owner == original_head)
                    .count(),
                3,
                "outer retained entry and810 entry/exit run even when epoch exit refuses"
            );
            assert_eq!(callbacks.replace(0), if original { 2 } else { 4 });
            assert!(changed.borrow().is_some());
            drop(changed.borrow_mut().take());
            history.read_current(&fixture.owner).unwrap();
        }
    }

    // This is a closed observation interval, not an atomic filesystem snapshot. An
    // earlier sibling changed then restored before full exit need not be observed by
    // the new scope; the old intermediate full census sees it. Selected body2 sources
    // stay exact and all original wallet inspections remain read-only in both cases.
    for original in [true, false] {
        let changed = Rc::new(RefCell::new(None));
        let mutation = Rc::clone(&changed);
        let root = Arc::clone(&epochs);
        let calls = Rc::clone(&callbacks);
        let action = || {
            with_hook(
                move |point| {
                    if point == Point::BeforeBody(1) {
                        *mutation.borrow_mut() = Some(Leaf::replace(Arc::clone(&root), "0001.nrt"));
                    }
                    if point == Point::BeforeBody(2) {
                        drop(mutation.borrow_mut().take());
                    }
                    if matches!(point, Point::WalletInspected(_)) {
                        calls.set(calls.get() + 1);
                    }
                    Ok(())
                },
                || history.read_current(&fixture.owner),
            )
        };
        let result = if original {
            EpochReader::test_original_body_censuses(action)
        } else {
            action()
        };
        if original {
            retained_refusal(result);
        } else {
            same(&result.unwrap(), &old);
        }
        assert_eq!(callbacks.replace(0), if original { 2 } else { 4 });
        drop(changed.borrow_mut().take());
    }

    // Even an early error before any wallet call completes the entire original epoch
    // exit, so a changed not-yet-selected final epoch overrides that ordinary error.
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
    let changed = Rc::new(RefCell::new(None));
    let mutation = Rc::clone(&changed);
    let root = Arc::clone(&epochs);
    let calls = Rc::clone(&callbacks);
    let (result, handles) = with_hook(
        move |point| {
            if matches!(point, Point::WalletInspected(_)) {
                calls.set(calls.get() + 1);
            }
            if point == Point::BeforeBody(0) {
                *mutation.borrow_mut() = Some(Leaf::replace(Arc::clone(&root), "0003.nrt"));
                return Err(crate::managed::Error::NativeDeadline);
            }
            Ok(())
        },
        || History::test_handle_work(|| history.read_current(&fixture.owner)),
    );
    retained_refusal(result);
    assert_eq!(
        handles
            .history_order
            .iter()
            .filter(|&&owner| owner == original_head)
            .count(),
        3,
        "early epoch refusal cannot skip810's original graph exit"
    );
    assert_eq!(callbacks.replace(0), 0);
    assert!(changed.borrow().is_some());
    drop(changed.borrow_mut().take());
    history.read_current(&fixture.owner).unwrap();

    #[cfg(unix)]
    {
        // Retain the original directory object through both entry and exit. Replacing
        // its equal pathname with an empty private directory grants no fresh coverage.
        let changed = Rc::new(RefCell::new(None));
        let mutation = Rc::clone(&changed);
        let path = epochs.path().to_owned();
        let result = with_hook(
            move |point| {
                if point == Point::BeforeBody(0) {
                    *mutation.borrow_mut() = Some(Directory::replace(&path));
                    return Err(crate::managed::Error::NativeDeadline);
                }
                Ok(())
            },
            || history.read_current(&fixture.owner),
        );
        retained_refusal(result);
        assert!(changed.borrow().is_some());
        drop(changed.borrow_mut().take());
        history.read_current(&fixture.owner).unwrap();
    }

    // Exact physical source counts, canonical allocation admission and real wallet
    // callbacks stay on the original complete recipe for every active Norito owner.
    let ((old, old_counts), old_usage) = EpochReader::test_original_body_censuses(|| {
        with_hook(observe(), || {
            norito::core::with_decode_limits_measured(limits(usize::MAX), || {
                EpochReader::test_epoch_work(|| history.read_current(&fixture.owner))
            })
        })
    });
    let old = old.unwrap();
    let old_callbacks = callbacks.replace(0);
    let ((new, new_counts), new_usage) = with_hook(observe(), || {
        norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            EpochReader::test_epoch_work(|| history.read_current(&fixture.owner))
        })
    });
    same(&new.unwrap(), &old);
    assert_eq!(new_counts, old_counts);
    assert_eq!(new_usage, old_usage);
    assert_eq!(callbacks.replace(0), old_callbacks);
    let exact = old_usage.total_allocated_bytes();
    assert!(exact > 1);
    for capacity in [0, 1, exact - 1, exact] {
        let ((old, old_counts), old_usage) = EpochReader::test_original_body_censuses(|| {
            with_hook(observe(), || {
                norito::core::with_decode_limits_measured(limits(capacity), || {
                    EpochReader::test_epoch_work(|| history.read_current(&fixture.owner))
                })
            })
        });
        let old_callbacks = callbacks.replace(0);
        let ((new, new_counts), new_usage) = with_hook(observe(), || {
            norito::core::with_decode_limits_measured(limits(capacity), || {
                EpochReader::test_epoch_work(|| history.read_current(&fixture.owner))
            })
        });
        assert_eq!(new_counts, old_counts);
        assert_eq!(new_usage, old_usage);
        assert_eq!(callbacks.replace(0), old_callbacks);
        if capacity == exact {
            same(&new.unwrap(), &old.unwrap());
        } else {
            assert_eq!(
                new.err().expect("finite owner refuses").to_string(),
                old.err()
                    .expect("original finite owner refuses")
                    .to_string()
            );
        }
    }
    assert!(!norito::core::decode_limits_active());
    history.read_current(&fixture.owner).unwrap();
    assert_eq!(
        fixture.native.chain.height(),
        4,
        "parser performs no native write"
    );
}
