//! Genuine signed histories bound pure plan comparisons and close original profile custody.

use super::*;
use crate::managed::{
    native_operation::test_support::{UnavailablePeers, provider_id},
    service_authority::{CheckpointImports, profile_validation_test_support::count},
};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

type Hook = Box<dyn FnMut(u8) -> Result<()>>;
thread_local! {
    static ORIGINAL_RECIPE: Cell<bool> = const { Cell::new(false) };
    static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
}
pub(super) fn original_recipe() -> bool {
    ORIGINAL_RECIPE.with(Cell::get)
}
pub(super) fn hit(ordinal: u8) -> Result<()> {
    HOOK.with(|hook| {
        hook.borrow_mut()
            .as_mut()
            .map_or(Ok(()), |hook| hook(ordinal))
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
fn with_hook<T>(hook: impl FnMut(u8) -> Result<()> + 'static, action: impl FnOnce() -> T) -> T {
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
fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
}
fn same(actual: &BodyHistory, expected: &BodyHistory) {
    assert_eq!(
        actual.selection.digest().unwrap(),
        expected.selection.digest().unwrap()
    );
    assert_eq!(actual.bodies.len(), expected.bodies.len());
    assert!(Arc::ptr_eq(&actual.root, &expected.root));
    for (actual, expected) in actual.bodies.iter().zip(&expected.bodies) {
        assert_eq!(actual.semantic, expected.semantic);
        assert_eq!(
            actual.reservation.digest().unwrap(),
            expected.reservation.digest().unwrap()
        );
        assert_eq!(
            actual
                .original
                .as_ref()
                .map(Original::digest)
                .transpose()
                .unwrap(),
            expected
                .original
                .as_ref()
                .map(Original::digest)
                .transpose()
                .unwrap(),
        );
    }
}

// The canonical read entry with real original reference, retained root, producer and imports.
// Bypass only read_current's public retained-error mapping to assert internal precedence.
fn raw_read(history: &BodyHistory, owner: &ManagedStreamTokenCustody) -> Result<BodyHistory> {
    let reference = read_reference(owner, history.purpose)?;
    let plan = owner.authority.provider_plan()?;
    let mut validation = EpochValidationScope::new();
    BodyHistory::read(
        owner,
        history.purpose,
        Arc::clone(&history.root),
        reference,
        Some(history),
        plan,
        &mut CheckpointImports::new(&owner.authority, Some(&mut validation)),
    )
}
struct ChangedProfile {
    generation: Arc<PrivateDirectory>,
    original: zeroize::Zeroizing<Vec<u8>>,
}
impl ChangedProfile {
    fn apply(generation: Arc<PrivateDirectory>) -> Self {
        let original = generation.read("peer3.toml", 1024 * 1024).unwrap();
        let mut changed = original.to_vec();
        changed.extend_from_slice(b"\n# scoped parser profile mutation\n");
        generation
            .write_atomic("peer3.toml", &changed, PublishMode::Replace)
            .unwrap();
        Self {
            generation,
            original,
        }
    }
}
impl Drop for ChangedProfile {
    fn drop(&mut self) {
        self.generation
            .write_atomic("peer3.toml", &self.original, PublishMode::Replace)
            .unwrap();
    }
}
fn profile_refusal(result: Result<BodyHistory>) {
    assert!(
        matches!(result, Err(crate::managed::Error::Invalid(message))
        if message == "retained service profile input custody differs")
    );
}

#[test]
fn genuine_signed_originals_share_only_the_exact_parser_plan_and_preserve_active_recipe() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let peers = UnavailablePeers::start(&fixture.prepared);
    assert_eq!(history.bodies.len(), 3);
    assert!(history.bodies.iter().all(|body| body.original.is_some()));
    let callbacks = Rc::new(Cell::new(0));
    let observe = || {
        let callbacks = Rc::clone(&callbacks);
        move |point| {
            if matches!(point, parser_handle_tests::Point::WalletInspected(_)) {
                callbacks.set(callbacks.get() + 1);
            }
            Ok(())
        }
    };
    let (old, before) = with_recipe(true, || {
        parser_handle_tests::with_hook(observe(), || count(|| history.read_current(&fixture.owner)))
    });
    let old = old.unwrap();
    assert_eq!(callbacks.replace(0), 4);
    let (new, after) = parser_handle_tests::with_hook(observe(), || {
        count(|| history.read_current(&fixture.owner))
    });
    same(&new.unwrap(), &old);
    assert_eq!(callbacks.replace(0), 4);
    assert_eq!(before, 2 + history.bodies.len());
    assert_eq!(
        after, 2,
        "complete original entry and unconditional full profile exit"
    );

    // Genuine canonical Original validation has one semantic implementation. The sealed
    // borrow removes only a repeated full-profile producer at its late interval comparison.
    let original = history.original().unwrap().unwrap();
    let plan = fixture.owner.authority.provider_plan().unwrap();
    let borrowed = BodyOriginalPlan {
        owner: &fixture.owner,
        plan: &plan,
    };
    let validate = |original: &Original, borrowed: Option<&BodyOriginalPlan<'_>>| {
        let mut imports = CheckpointImports::new(&fixture.owner.authority, None);
        match borrowed {
            Some(plan) => fixture.owner.validate_original_in_body_read(
                original,
                history.purpose,
                &mut imports,
                plan,
            ),
            None => fixture.owner.validate_original_with_imports(
                original,
                history.purpose,
                &mut imports,
            ),
        }
    };
    let (result, full) = count(|| validate(original, None));
    result.unwrap();
    assert_eq!(full, 1);
    let (result, shared) = count(|| validate(original, Some(&borrowed)));
    result.unwrap();
    assert_eq!(shared, 0);

    // Moving the real Original's observation by one millisecond preserves its signed
    // statement but must fail the same exact interval comparison under both producers.
    let mut changed = original.clone();
    let Action::Enroll {
        selected_at_unix_ms,
        ..
    } = &mut changed.action
    else {
        panic!("genuine renewal Original");
    };
    *selected_at_unix_ms += 1;
    changed.validate().unwrap();
    let (old_error, full) = count(|| validate(&changed, None));
    let (new_error, shared) = count(|| validate(&changed, Some(&borrowed)));
    let old_error = old_error.err().unwrap();
    let new_error = new_error.err().unwrap();
    assert!(
        old_error
            .to_string()
            .contains("renewal differs from original finite interval")
    );
    assert_eq!(old_error.to_string(), new_error.to_string());
    assert_eq!((full, shared), (1, 0));

    // A distinct real owner and its actual provider plan cannot supply this owner's plan.
    let foreign =
        ManagedStreamTokenCustody::open(&fixture.prepared, provider_id(&fixture.prepared, 1))
            .unwrap();
    let foreign_plan = foreign.authority.provider_plan().unwrap();
    let foreign_borrow = BodyOriginalPlan {
        owner: &foreign,
        plan: &foreign_plan,
    };
    assert!(foreign_borrow.for_owner(&fixture.owner).is_none());
    let (result, fallback) = count(|| validate(original, Some(&foreign_borrow)));
    result.unwrap();
    assert_eq!(fallback, 1);
    drop(foreign);

    // A budget activated after construction still takes the unchanged full producer.
    let ((baseline, old_count), old_usage) =
        norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            count(|| validate(original, None))
        });
    baseline.unwrap();
    let ((scoped, new_count), new_usage) =
        norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            count(|| validate(original, Some(&borrowed)))
        });
    scoped.unwrap();
    assert_eq!((old_count, new_count), (1, 1));
    assert_eq!(old_usage, new_usage);

    // Entry-active complete parsers preserve physical profile calls, cumulative Norito
    // charges, wallet observations and both exact and below-budget outcomes.
    let ((old, old_count), old_usage) = with_recipe(true, || {
        parser_handle_tests::with_hook(observe(), || {
            norito::core::with_decode_limits_measured(limits(usize::MAX), || {
                count(|| history.read_current(&fixture.owner))
            })
        })
    });
    let old = old.unwrap();
    let old_callbacks = callbacks.replace(0);
    let ((new, new_count), new_usage) = parser_handle_tests::with_hook(observe(), || {
        norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            count(|| history.read_current(&fixture.owner))
        })
    });
    same(&new.unwrap(), &old);
    assert_eq!(callbacks.replace(0), old_callbacks);
    assert_eq!((old_count, new_count), (before, before));
    assert_eq!(old_usage, new_usage);
    let exact = old_usage.total_allocated_bytes();
    assert!(exact > 1);
    for capacity in [0, 1, exact - 1, exact] {
        let ((old, old_count), old_usage) = with_recipe(true, || {
            norito::core::with_decode_limits_measured(limits(capacity), || {
                count(|| history.read_current(&fixture.owner))
            })
        });
        let ((new, new_count), new_usage) =
            norito::core::with_decode_limits_measured(limits(capacity), || {
                count(|| history.read_current(&fixture.owner))
            });
        assert_eq!(old_count, new_count);
        assert_eq!(old_usage, new_usage);
        match (old, new) {
            (Ok(old), Ok(new)) if capacity == exact => same(&new, &old),
            (Err(old), Err(new)) if capacity < exact => {
                assert_eq!(old.to_string(), new.to_string())
            }
            _ => panic!("active original budget outcome changed"),
        }
    }
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
}

#[test]
fn profile_exit_closes_ordinary_errors_and_retains_independent_native_graph_exits() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let peers = UnavailablePeers::start(&fixture.prepared);
    let generation = Arc::new(
        PrivateDirectory::open_exact(fixture.prepared.context.client_config.parent().unwrap())
            .unwrap(),
    );
    let original_head = std::ptr::from_ref(history.current_history().unwrap()) as usize;

    // Even before the first Original comparison, an ordinary inner error receives the
    // full original profile exit. Its persistent source error deliberately takes precedence.
    // Entry-active owners retain the old error precedence and the old physical recipe.
    for active in [false, true] {
        for original in [true, false] {
            for mutate in [false, true] {
                let changed = Rc::new(RefCell::new(None));
                let mutation = Rc::clone(&changed);
                let source = Arc::clone(&generation);
                let action = || {
                    with_recipe(original, || {
                        with_hook(
                            move |ordinal| {
                                assert_eq!(ordinal, 1);
                                if mutate {
                                    *mutation.borrow_mut() =
                                        Some(ChangedProfile::apply(Arc::clone(&source)));
                                }
                                Err(crate::managed::Error::NativeDeadline)
                            },
                            || count(|| raw_read(&history, &fixture.owner)),
                        )
                    })
                };
                let (result, calls) = if active {
                    norito::with_decode_limits_scope(limits(usize::MAX), action)
                } else {
                    action()
                };
                assert_eq!(calls, if original || active { 1 } else { 2 });
                if mutate && !original && !active {
                    profile_refusal(result);
                } else {
                    assert!(matches!(result, Err(crate::managed::Error::NativeDeadline)));
                }
                drop(changed.borrow_mut().take());
            }
        }
    }

    // A real malformed record also returns through the full exit; no synthetic Original
    // or alternate decoder supplies this error. Restore the exact bytes before reuse.
    let first = &history.bodies[0].directory;
    let original = first
        .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
        .unwrap();
    first
        .write_atomic(
            "original.nrt",
            b"not canonical Norito",
            PublishMode::Replace,
        )
        .unwrap();
    let (old, old_count) = with_recipe(true, || count(|| raw_read(&history, &fixture.owner)));
    let (new, new_count) = count(|| raw_read(&history, &fixture.owner));
    first
        .write_atomic("original.nrt", &original, PublishMode::Replace)
        .unwrap();
    assert_eq!(
        old.err().unwrap().to_string(),
        new.err().unwrap().to_string()
    );
    assert_eq!((old_count, new_count), (1, 2));

    // Once the real History parser starts, its old retained graph entry/exit remains
    // independent. The later profile failure cannot short-circuit810's original closure.
    for ordinary_error in [false, true] {
        let changed = Rc::new(RefCell::new(None));
        let mutation = Rc::clone(&changed);
        let source = Arc::clone(&generation);
        let callbacks = Rc::new(Cell::new(0));
        let calls = Rc::clone(&callbacks);
        let ((result, profile_count), handles) = parser_handle_tests::with_hook(
            move |point| {
                if point == parser_handle_tests::Point::BeforeBody(0) {
                    *mutation.borrow_mut() = Some(ChangedProfile::apply(Arc::clone(&source)));
                    if ordinary_error {
                        return Err(crate::managed::Error::NativeDeadline);
                    }
                }
                if matches!(point, parser_handle_tests::Point::WalletInspected(_)) {
                    calls.set(calls.get() + 1);
                }
                Ok(())
            },
            || History::test_handle_work(|| count(|| history.read_current(&fixture.owner))),
        );
        assert!(matches!(
            result,
            Err(crate::managed::Error::Bootstrap(
                ManagedBootstrapFailure::RetainedMaterial
            ))
        ));
        assert_eq!(profile_count, 2);
        assert_eq!(callbacks.get(), if ordinary_error { 0 } else { 4 });
        assert_eq!(
            handles
                .history_order
                .iter()
                .filter(|&&owner| owner == original_head)
                .count(),
            3
        );
        drop(changed.borrow_mut().take());
        history.read_current(&fixture.owner).unwrap();
    }

    // Temporal semantics are explicit: persistent mutation is refused after the later
    // read-only wallet inspections. The removed intermediate producer saw a transient
    // change; the entry/exit interval can accept it once exactly restored. No plan or
    // freshness verdict enters a wallet callback or leaves the concrete parser.
    for restore_before_exit in [false, true] {
        for original in [true, false] {
            let changed = Rc::new(RefCell::new(None));
            let mutation = Rc::clone(&changed);
            let source = Arc::clone(&generation);
            let seen = Rc::new(Cell::new(0));
            let calls = Rc::clone(&seen);
            let wallets = Rc::new(Cell::new(0));
            let inspections = Rc::clone(&wallets);
            let result = with_recipe(original, || {
                with_hook(
                    move |ordinal| {
                        calls.set(calls.get() + 1);
                        if ordinal == 1 {
                            *mutation.borrow_mut() =
                                Some(ChangedProfile::apply(Arc::clone(&source)));
                        }
                        if ordinal == 2 && restore_before_exit {
                            drop(mutation.borrow_mut().take());
                        }
                        Ok(())
                    },
                    || {
                        parser_handle_tests::with_hook(
                            move |point| {
                                if matches!(point, parser_handle_tests::Point::WalletInspected(_)) {
                                    inspections.set(inspections.get() + 1);
                                }
                                Ok(())
                            },
                            || raw_read(&history, &fixture.owner),
                        )
                    },
                )
            });
            if original || !restore_before_exit {
                profile_refusal(result);
            } else {
                same(&result.unwrap(), &history);
            }
            assert_eq!(seen.get(), if original { 1 } else { 3 });
            assert_eq!(wallets.get(), if original { 0 } else { 4 });
            drop(changed.borrow_mut().take());
        }
    }
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
}
