//! Actual Kura release callbacks follow every enclosing State publication owner.

use super::*;
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Wake, Waker},
};

struct CallbackProbe {
    state: Arc<State>,
    calls: AtomicUsize,
    blocked: AtomicUsize,
}
impl Wake for CallbackProbe {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let state = &self.state;
        let free = state.state_write_lock.try_lock().is_some()
            && state.state_commit_lock.try_lock().is_some()
            && state.lane_lifecycle_lock.try_lock().is_some()
            && state.latest_block_header.try_write().is_some()
            && state.da_commitments.try_write().is_some()
            && state.da_confidential_compute.try_write().is_some()
            && state.da_receipt_cursors.try_write().is_some()
            && state.da_shard_cursors.try_write().is_some()
            && state.da_pin_intents.try_write().is_some()
            && state.lane_manifests.try_write().is_some()
            && state.lane_privacy_registry.try_write().is_some()
            && state.da_indexes_hydrated.try_write().is_some()
            && state
                .kura
                .publication_fences_for_test()
                .iter()
                .all(|(_, fence)| fence.try_lock().is_some());
        self.blocked.fetch_add(usize::from(!free), Ordering::SeqCst);
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

fn check_kura_release(partial: bool, unwind: bool) {
    let chain = manual_lane_lifecycle_test_chain(World::default());
    let state = Arc::clone(chain.state());
    let budget = state.kura.transaction_history_budget();
    let reserved = budget.reserved_bytes();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let probe = Arc::new(CallbackProbe {
        state: Arc::clone(&state),
        calls: AtomicUsize::new(0),
        blocked: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&probe));
    let fences = state.kura.publication_fences_for_test();
    let held = fences[0].1.lock();
    let wait = fences[0]
        .1
        .try_lock_or_wait()
        .err()
        .expect("original held prune fence");
    let original_release = held.release_deferred();
    assert!(
        registration
            .poll_wait(&wait, &mut Context::from_waker(&waker))
            .is_pending()
    );
    let mut original = crate::kura::KuraPublicationSlot::new(&state.kura);
    let mut effects = effect_publication::StateEffectLocks::new(&state);
    let mut prefix_probes = std::array::from_fn::<_, 3, _>(|_| None);
    let mut final_probes = std::array::from_fn::<_, 4, _>(|_| None);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _commit = state.state_commit_lock.lock();
        let _lifecycle = state.lane_lifecycle_lock.lock();
        let _writer = state.state_write_lock.lock();
        let mut effect_scope = effects.physical_scope();
        effect_scope
            .try_prepare()
            .expect("actual sibling effect writers");
        let blocker = partial.then(|| fences[3].1.lock());
        {
            let mut scope = original.physical_scope();
            if partial {
                match scope.try_prepare() {
                    Err(crate::kura::KuraPublicationPreparationError::Busy {
                        field,
                        wait: actual,
                    }) => {
                        assert_eq!(field, "sidecar_lock");
                        let expected = fences[3].1.try_lock_or_wait().err().unwrap();
                        assert_eq!(actual, expected);
                    }
                    other => panic!("expected the original last-fence refusal: {other:?}"),
                }
                for ((_, lock), probe) in fences[..3].iter().zip(&mut prefix_probes) {
                    *probe = lock.try_lock().map(|guard| guard.release_deferred());
                }
                assert!(prefix_probes.iter().all(Option::is_some));
            } else {
                scope
                    .try_prepare()
                    .expect("original Kura publication boundary");
                assert!(scope.lease().belongs_to(&state.kura));
                assert!(fences.iter().all(|(_, lock)| lock.try_lock().is_none()));
            }
            if unwind {
                std::panic::resume_unwind(Box::new(
                    "injected after the original Kura scope acquired its real fences",
                ));
            }
        }
        drop(blocker);
        for ((_, lock), probe) in fences.iter().zip(&mut final_probes) {
            *probe = lock.try_lock().map(|guard| guard.release_deferred());
        }
        assert!(final_probes.iter().all(Option::is_some));
    }));
    assert_eq!(
        probe.calls.load(Ordering::SeqCst),
        0,
        "original Kura notifications must wait for complete State cleanup"
    );
    assert_eq!(outcome.is_err(), unwind);
    if unwind {
        assert_eq!(
            outcome
                .as_ref()
                .err()
                .and_then(|payload| payload.downcast_ref::<&'static str>()),
            Some(&"injected after the original Kura scope acquired its real fences"),
            "the exact original unwind payload must survive physical cleanup",
        );
    }
    original.retire_notices();
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        probe.blocked.load(Ordering::SeqCst),
        0,
        "original Kura callbacks must follow all State and Kura physical owners"
    );
    assert!(
        registration
            .poll_wait(&wait, &mut Context::from_waker(&waker))
            .is_ready()
    );
    original.retire_notices();
    assert_eq!(
        probe.calls.load(Ordering::SeqCst),
        1,
        "empty original batches never fabricate a release"
    );
    drop(original_release);
    drop(prefix_probes);
    drop(final_probes);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), reserved);
}

#[test]
fn original_kura_partial_refusal_callbacks_follow_all_state_siblings() {
    check_kura_release(true, false);
}

#[test]
fn original_kura_success_callbacks_follow_all_state_siblings() {
    check_kura_release(false, false);
}

#[test]
fn original_kura_unwind_callbacks_follow_all_state_siblings() {
    check_kura_release(false, true);
}

#[test]
fn geometry_reuses_only_the_exact_original_kura_lease() {
    let kura = Kura::blank_kura_for_testing();
    let other = Kura::blank_kura_for_testing();
    let mut releases = crate::kura::KuraPublicationReleases::new(&kura);
    let original = kura.try_publication_lease().expect("actual source Kura");
    assert!(
        geometry_scoped_lease(&kura, Some(&original), &mut releases)
            .unwrap()
            .is_none()
    );
    let error = geometry_scoped_lease(&other, Some(&original), &mut releases)
        .err()
        .expect("foreign Kura cannot substitute");
    assert!(
        matches!(error, LaneLifecycleError::Storage(ref cause) if cause == "geometry lease belongs to another Kura")
    );
    assert!(
        kura.publication_fences_for_test()
            .iter()
            .all(|(_, lock)| lock.try_lock().is_none())
    );
    assert!(
        other
            .publication_fences_for_test()
            .iter()
            .all(|(_, lock)| lock.try_lock().is_some())
    );
    drop(original);
    let foreign_fences = other.publication_fences_for_test();
    let foreign_prune = foreign_fences[0].1.lock();
    let refusal = match geometry_scoped_lease(&other, None, &mut releases) {
        Err(error) => error,
        Ok(_) => panic!("foreign cleanup must refuse before acquiring any physical fence"),
    };
    assert!(
        matches!(refusal, LaneLifecycleError::GeometryStorage(crate::kura::Error::IO(ref error, _))
        if error.kind() == std::io::ErrorKind::InvalidInput && error.to_string() == "geometry cleanup belongs to another Kura")
    );
    drop(foreign_prune);
    assert!(
        kura.publication_fences_for_test()
            .iter()
            .all(|(_, lock)| lock.try_lock().is_some())
    );
    assert!(
        other
            .publication_fences_for_test()
            .iter()
            .all(|(_, lock)| lock.try_lock().is_some())
    );
    let scoped = geometry_scoped_lease(&kura, None, &mut releases)
        .unwrap()
        .expect("standalone owner keeps its original lease");
    assert!(scoped.belongs_to(&kura));
}
