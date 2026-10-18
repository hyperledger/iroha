//! Genuine current/active reads close mutable predecessors before their caller can publish.
use super::*;
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::managed) enum Point {
    Call,
    BeforeActive,
    BeforeClose,
}
type Hook = Box<dyn FnMut(Point) -> Result<()>>;
struct State {
    original: bool,
    calls: usize,
    hook: Option<Hook>,
}
thread_local! { static STATE: RefCell<Option<State>> = const { RefCell::new(None) }; }
pub(in crate::managed) fn original_recipe() -> bool {
    STATE.with(|state| state.borrow().as_ref().is_some_and(|state| state.original))
}
pub(in crate::managed) fn hit(point: Point) -> Result<()> {
    let Some(mut hook) = STATE.with(|state| {
        let mut state = state.borrow_mut();
        let state = state.as_mut()?;
        state.calls += usize::from(point == Point::Call);
        Some(state.hook.take())
    }) else {
        return Ok(());
    };
    let result = hook.as_mut().map_or(Ok(()), |hook| hook(point));
    STATE.with(|state| state.borrow_mut().as_mut().unwrap().hook = hook);
    result
}
fn observe<T>(original: bool, hook: Option<Hook>, read: impl FnOnce() -> T) -> (T, usize) {
    struct Restore(Option<State>);
    impl Drop for Restore {
        fn drop(&mut self) {
            STATE.with(|state| state.replace(self.0.take()));
        }
    }
    let _restore = Restore(STATE.with(|state| {
        state.replace(Some(State {
            original,
            calls: 0,
            hook,
        }))
    }));
    let result = read();
    let calls = STATE.with(|state| state.take().unwrap().calls);
    (result, calls)
}
fn outcome(result: Result<()>) -> std::result::Result<(), String> {
    result.map_err(|error| error.to_string())
}
fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
}

#[test]
fn current_active_closes_one_complete_graph_and_reduces_snapshot_reads() {
    let _resources = crate::managed::native_test_guard();
    let (_fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history.current_history().unwrap();
    let run = |original| {
        let timing = finish_timing::Capture::start();
        let ((result, visits), _) = observe(original, None, || {
            History::test_validation_work(usize::MAX, || native.test_current_and_active())
        });
        let timing = timing.finish();
        result.unwrap();
        (
            visits.visits,
            visits.distinct_histories,
            timing.sample(finish_timing::Phase::GraphValidate).0,
            timing.sample(finish_timing::Phase::SnapshotRevalidate).0,
        )
    };
    let old = run(true);
    let new = run(false);
    assert_eq!(old.1, 3);
    assert_eq!(new.1, old.1);
    assert_eq!(old.2, 2);
    assert_eq!(new.2, 1);
    assert_eq!(old.3, 7);
    assert_eq!(new.3, 2);
    assert_eq!(old.0 - new.0, 3);
    let timing = finish_timing::Capture::start();
    native.test_current_active_foreign_scope().unwrap();
    let timing = timing.finish();
    assert_eq!(timing.sample(finish_timing::Phase::GraphValidate).0, 1);
    assert_eq!(timing.sample(finish_timing::Phase::SnapshotRevalidate).0, 7);
}

#[test]
fn current_active_all_three_production_call_sites_close_before_publication() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history.current_history().unwrap();
    let (closing, calls) = observe(false, None, || native.test_closing_current_only());
    closing.unwrap();
    assert_eq!(
        calls, 0,
        "closure-only path must not require active enrollment"
    );
    let terms = Terms::new(now_ms().unwrap() + 8_000, &fixture.options).unwrap();
    let (result, calls) = observe(false, None, || native.test_current_active_transition(terms));
    result.unwrap();
    assert_eq!(
        calls, 3,
        "reserve_pending, finish_reserved(false), retain_root"
    );
    let refreshed = history.read_current(&fixture.owner).unwrap();
    let selected = refreshed.current_history().unwrap();
    assert_eq!(selected.reserved_attempt_count(), 1);
    assert!(selected.last().unwrap().observation().is_err());
    assert!(!selected.last().unwrap().is_committed());
    assert!(
        !selected
            .last()
            .unwrap()
            .directory()
            .path()
            .join("transaction")
            .exists()
    );
}

#[test]
fn current_active_inherited_and_late_decoder_owners_keep_original_cost_and_retry() {
    let _resources = crate::managed::native_test_guard();
    let (_fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let native = history.current_history().unwrap();
    let run = |native: &History, original, allocation| {
        norito::core::with_decode_limits_measured(limits(allocation), || {
            observe(original, None, || {
                History::test_operation_records(|| outcome(native.test_current_and_active()))
            })
            .0
        })
    };
    let full = run(native, true, usize::MAX);
    assert!(full.0.0.is_ok());
    assert_eq!(full, run(native, false, usize::MAX));
    let exact = full.1.total_allocated_bytes();
    for allocation in [0, 1, exact / 2, exact.saturating_sub(1), exact] {
        let old = run(native, true, allocation);
        assert_eq!(old, run(native, false, allocation));
        let late = native
            .test_current_active_late(|read| {
                norito::core::with_decode_limits_measured(limits(allocation), || {
                    History::test_operation_records(|| outcome(read()))
                })
            })
            .unwrap();
        assert_eq!(old, late);
    }
    native.test_current_and_active().unwrap();
    // The oldest genuine retained body has no predecessor. It keeps the literal recipe,
    // including its inactive-scope refusal and all physical decoding charges.
    let prior = native.test_owned_predecessor_closure_history().unwrap();
    let oldest = prior.test_owned_predecessor_closure_history().unwrap();
    let no_prior = |original| {
        let timing = finish_timing::Capture::start();
        let (result, _) = observe(original, None, || oldest.test_current_and_active());
        let timing = timing.finish();
        (
            outcome(result),
            timing.sample(finish_timing::Phase::GraphValidate).0,
            timing.sample(finish_timing::Phase::SnapshotRevalidate).0,
        )
    };
    assert_eq!(no_prior(true), no_prior(false));
    let old = run(&oldest, true, usize::MAX);
    assert!(old.0.0.is_err());
    assert_eq!(old, run(&oldest, false, usize::MAX));
    for allocation in [0, 1, old.1.total_allocated_bytes()] {
        assert_eq!(
            run(&oldest, true, allocation),
            run(&oldest, false, allocation)
        );
    }
}

#[test]
fn current_active_final_graph_refuses_oldest_metadata_and_inventory_then_retries() {
    let _resources = crate::managed::native_test_guard();
    let (_fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let current = history.current_history().unwrap();
    let inactive = current.test_owned_predecessor_closure_history().unwrap();
    let oldest = &history.bodies[0].directory;
    let metadata = oldest.path().join("operation.nrt");
    let original = std::fs::read(&metadata).unwrap();
    for native in [current, &inactive] {
        let clean = outcome(native.test_current_and_active());
        for ordinary_error in [false, true] {
            for inventory in [false, true] {
                let changed_metadata = metadata.clone();
                let rogue = oldest.path().join("attempts").join("foreign");
                let changed = rogue.clone();
                let hook: Hook = Box::new(move |point| {
                    if point == Point::BeforeActive {
                        if inventory {
                            std::fs::create_dir(&changed).unwrap();
                        } else {
                            let mut bytes = std::fs::read(&changed_metadata).unwrap();
                            bytes[0] ^= 1;
                            std::fs::write(&changed_metadata, bytes).unwrap();
                        }
                    }
                    if ordinary_error && point == Point::BeforeClose {
                        return Err(invalid("current active ordinary refusal"));
                    }
                    Ok(())
                });
                let (result, _) = observe(false, Some(hook), || native.test_current_and_active());
                if inventory {
                    std::fs::remove_dir(&rogue).unwrap();
                } else {
                    std::fs::write(&metadata, &original).unwrap();
                }
                let message = result.unwrap_err().to_string();
                assert_ne!(
                    message,
                    invalid("current active ordinary refusal").to_string()
                );
                assert_ne!(Some(&message), clean.as_ref().err());
                assert_eq!(outcome(native.test_current_and_active()), clean);
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn current_active_original_scope_exit_overrides_ordinary_and_inactive_errors() {
    use std::{fs, os::unix::fs::PermissionsExt as _};
    let _resources = crate::managed::native_test_guard();
    let (_fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let current = history.current_history().unwrap();
    let inactive = current.test_owned_predecessor_closure_history().unwrap();
    let pending = inactive.test_current_and_active().unwrap_err().to_string();
    assert_eq!(
        pending,
        crate::managed::Error::from(ManagedBootstrapFailure::TransitionPending).to_string()
    );
    for native in [current, &inactive] {
        for ordinary_error in [false, true] {
            let root = history.root.path().to_owned();
            let changed = root.clone();
            let hook: Hook = Box::new(move |point| {
                if point == Point::BeforeClose {
                    fs::set_permissions(&changed, fs::Permissions::from_mode(0o755)).unwrap();
                    if ordinary_error {
                        return Err(invalid("current active ordinary refusal"));
                    }
                }
                Ok(())
            });
            let (result, _) = observe(false, Some(hook), || native.test_current_and_active());
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(matches!(result, Err(crate::managed::Error::Io(_))));
            if std::ptr::eq(native, current) {
                native.test_current_and_active().unwrap();
            } else {
                assert_eq!(
                    native.test_current_and_active().unwrap_err().to_string(),
                    pending
                );
            }
        }
    }
}
