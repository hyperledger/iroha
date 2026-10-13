//! Hydration retries may reenter only after the entire rebuild has unlocked.

use super::*;
use std::{
    future::Future,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Wake, Waker},
};

struct Probe {
    state: Arc<State>,
    running: AtomicBool,
    calls: AtomicUsize,
    blocked: AtomicUsize,
}

impl Wake for Probe {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        let fences_free = self.state.da_index_hydration_fence.try_lock().is_some()
            && self.state.state_write_lock.try_lock().is_some();
        let mut indexes = effect_publication::StateEffectLocks::new(&self.state);
        let indexes_free = indexes.try_prepare().is_ok();
        drop(indexes);
        if !fences_free || !indexes_free {
            self.blocked.fetch_add(1, Ordering::SeqCst);
        }
        self.running.store(false, Ordering::SeqCst);
    }
}

fn state() -> Arc<State> {
    Arc::new(State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    ))
}

#[test]
fn hydration_source_reader_callbacks_follow_rebuild_fences_on_success_and_failure() {
    for mode in 0..3 {
        let state = state();
        let budget = state.ivm_execution_budget();
        let mut registrations: Vec<_> = (0..6)
            .map(|_| crate::unit_test_support::release_registration(&budget))
            .collect();
        if mode == 2 {
            let mut hashes = state.block_hashes.block();
            hashes.push_for_tests(HashOf::from_untyped_unchecked(Hash::new(
                b"missing source-reader hydration body",
            )));
            hashes.commit_for_tests();
        }
        let probe = Arc::new(Probe {
            state: Arc::clone(&state),
            running: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            blocked: AtomicUsize::new(0),
        });
        let waker = Waker::from(Arc::clone(&probe));
        let mut context = Context::from_waker(&waker);
        let mut observations = vec![
            state.nexus.observe_release(),
            state.block_hashes.map().unwrap().observe_reader_release(),
        ];
        // The State's immutable budget does not require a cache read, so this
        // unrelated physical source must stay asleep throughout reconstruction.
        let mut cache_registration = crate::unit_test_support::release_registration(&budget);
        let mut cache_wait = Box::pin(
            state
                .pipeline_ivm_prepared_cache
                .observe_release()
                .wait_for_release(&mut cache_registration),
        );
        assert!(cache_wait.as_mut().poll(&mut context).is_pending());
        if mode == 0 {
            observations.extend([
                state
                    .world
                    .da_pin_intents_by_ticket
                    .observe_reader_release(),
                state.world.da_pin_intents_by_alias.observe_reader_release(),
            ]);
        }
        let mut pending: Vec<_> = observations
            .into_iter()
            .zip(registrations.iter_mut())
            .map(|(wait, registration)| Box::pin(wait.wait_for_release(registration)))
            .collect();
        for wait in &mut pending {
            assert!(wait.as_mut().poll(&mut context).is_pending());
        }
        let result = if mode == 0 {
            state.ensure_da_indexes_hydrated()
        } else {
            state.rewind_da_indexes_to_height(u64::from(mode == 2))
        };
        if mode == 2 {
            assert!(matches!(
                result,
                Err(DaIndexHydrationError::MissingBlock { .. })
            ));
        } else {
            assert_eq!(result, Ok(()));
        }
        assert_eq!(probe.blocked.load(Ordering::SeqCst), 0);
        assert_eq!(probe.calls.load(Ordering::SeqCst), pending.len());
        assert!(cache_wait.as_mut().poll(&mut context).is_pending());
        for wait in &mut pending {
            assert!(wait.as_mut().poll(&mut context).is_ready());
        }
    }
}

#[test]
fn hydration_and_rewind_release_every_index_and_fence_before_retry_callbacks() {
    for rewind in [false, true] {
        let state = state();
        let budget = state.ivm_execution_budget();
        let mut registrations: Vec<_> = (0..6)
            .map(|_| crate::unit_test_support::release_registration(&budget))
            .collect();
        let probe = Arc::new(Probe {
            state: Arc::clone(&state),
            running: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            blocked: AtomicUsize::new(0),
        });
        let waker = Waker::from(Arc::clone(&probe));
        let mut context = Context::from_waker(&waker);
        let mut pending = Vec::new();
        let mut original_releases = Vec::new();
        let mut registrations = registrations.iter_mut();
        macro_rules! watch {
            ($field:ident) => {{
                let held = state.$field.read();
                let wait = state
                    .$field
                    .try_write_or_wait()
                    .err()
                    .expect("actual held reader");
                original_releases.push(held.release_deferred());
                let mut future = Box::pin(wait.wait_for_release(registrations.next().unwrap()));
                assert!(future.as_mut().poll(&mut context).is_pending());
                pending.push(future);
            }};
        }
        watch!(da_commitments);
        watch!(da_confidential_compute);
        watch!(da_receipt_cursors);
        watch!(da_shard_cursors);
        watch!(da_pin_intents);
        // Ensure's initial cache probe precedes every enclosing fence and may
        // notify immediately. Rewind instead clears this marker under its fence.
        if rewind {
            watch!(da_indexes_hydrated);
        }
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
        let result = if rewind {
            state.rewind_da_indexes_to_height(0)
        } else {
            state.ensure_da_indexes_hydrated()
        };
        assert_eq!(result, Ok(()));
        assert!(probe.calls.load(Ordering::SeqCst) > 0);
        assert_eq!(probe.blocked.load(Ordering::SeqCst), 0);
        assert!(
            pending
                .iter_mut()
                .all(|f| f.as_mut().poll(&mut context).is_ready())
        );
        assert_eq!(*state.da_indexes_hydrated.read(), Some(Ok(())));
        let journal = state.da_shard_cursor_journal_path();
        assert!(
            journal.is_file(),
            "rebuild persists the captured cursor journal"
        );
        DaShardCursorJournal::load(&state.nexus_snapshot().lane_config, &journal)
            .expect("published hydration journal");
        drop(original_releases);
    }
}

#[test]
fn failed_rewind_releases_its_status_and_state_fences_before_retry() {
    let state = state();
    let mut registration =
        crate::unit_test_support::release_registration(&state.ivm_execution_budget());
    let mut hashes = state.block_hashes.block();
    hashes.push_for_tests(HashOf::from_untyped_unchecked(Hash::new(
        b"missing DA body",
    )));
    hashes.commit_for_tests();
    let probe = Arc::new(Probe {
        state: Arc::clone(&state),
        running: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
        blocked: AtomicUsize::new(0),
    });
    let held = state.da_indexes_hydrated.read();
    let wait = state
        .da_indexes_hydrated
        .try_write_or_wait()
        .expect_err("held original marker");
    let original_release = held.release_deferred();
    let waker = Waker::from(Arc::clone(&probe));
    let mut context = Context::from_waker(&waker);
    let mut pending = Box::pin(wait.wait_for_release(&mut registration));
    assert!(pending.as_mut().poll(&mut context).is_pending());
    let result = state.rewind_da_indexes_to_height(1);
    assert!(matches!(
        result,
        Err(DaIndexHydrationError::MissingBlock { .. })
    ));
    assert_eq!(*state.da_indexes_hydrated.read(), Some(result));
    assert!(pending.as_mut().poll(&mut context).is_ready());
    assert!(probe.calls.load(Ordering::SeqCst) > 0);
    assert_eq!(probe.blocked.load(Ordering::SeqCst), 0);
    drop(original_release);
}

/// Probe only physical ownership; a decoder limit must not look like a held writer.
struct RefundProbe {
    state: Arc<State>,
    expected_poison: bool,
    calls: AtomicUsize,
    blocked: AtomicUsize,
    poison_mismatches: AtomicUsize,
    running: AtomicBool,
}

impl Wake for RefundProbe {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        let fences_free = self.state.da_index_hydration_fence.try_lock().is_some()
            && self.state.state_write_lock.try_lock().is_some()
            && self.state.state_commit_lock.try_lock().is_some();
        let parameters = self
            .state
            .world
            .parameters
            .probe_original_writers_for_testing();
        let runtime = self
            .state
            .canonical_runtime
            .probe_original_writers_for_testing();
        // Probe both actual physical mutexes independently. Undo poison must not
        // short-circuit the Current probe or disguise an unreleased writer.
        let cells_released = parameters
            .iter()
            .chain(&runtime)
            .all(|writer| writer.acquired);
        if parameters
            .iter()
            .chain(&runtime)
            .any(|writer| writer.poisoned != self.expected_poison)
        {
            self.poison_mismatches.fetch_add(1, Ordering::SeqCst);
        }
        let mut indexes = effect_publication::StateEffectLocks::new(&self.state);
        let indexes_free = indexes.try_prepare().is_ok();
        drop(indexes);
        if !(fences_free && cells_released && indexes_free) {
            eprintln!(
                "cold DA refund: fences={fences_free} indexes={indexes_free} world={parameters:?} runtime={runtime:?} expected_poison={}",
                self.expected_poison
            );
            self.blocked.fetch_add(1, Ordering::SeqCst);
        }
        self.running.store(false, Ordering::SeqCst);
    }
}

fn projection(state: &State) -> [String; 5] {
    [
        format!("{:?}", state.da_commitments.read()),
        format!("{:?}", state.da_confidential_compute.read()),
        format!("{:?}", state.da_receipt_cursors.read()),
        format!("{:?}", state.da_shard_cursors.read()),
        format!("{:?}", state.da_pin_intents.read()),
    ]
}

#[test]
fn original_cold_da_refunds_follow_all_rebuild_and_rewind_writers() {
    use crate::{execution_attempt::ExecutionAttemptError, sumeragi::test_chain::*};
    use iroha_allocation::AllocationRefusal;
    use std::{num::NonZeroUsize, pin::Pin};

    // Direct success/refusal and retained replacement success/refusal/unwind all
    // read the same genuine signed genesis through the cold Kura owner.
    for mode in 0..5 {
        // Retired State generations use the process-wide epoch collector. Pin
        // before this fixture creates its original pool so another thread cannot
        // refund those generations into the cold-DA waiter while writers remain
        // held. The synchronous Kura scratch owner still exercises the actual
        // refund batch and every physical-release assertion below.
        let retirement_pin = crossbeam_epoch::pin();
        let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
            .expect("genuine signed root for cold DA reconstruction");
        let state = chain.state();
        state.ensure_da_indexes_hydrated().unwrap();
        let published = projection(state);
        let journal = state.da_shard_cursor_journal_path();
        let journal_before = std::fs::read(&journal).unwrap();
        let tip = state.latest_block_hash_fast();
        *state.da_indexes_hydrated.write() = None;
        let height = NonZeroUsize::new(1).unwrap();
        chain
            .kura()
            .forget_cached_block_for_testing(height)
            .unwrap();
        let budget = state.ivm_execution_budget();
        let mut registration = crate::unit_test_support::release_registration(&budget);
        let decode_limits =
            || norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        let decode_refusal = norito::with_decode_limits_scope(decode_limits(), || {
            chain.kura().get_block(height, &budget).unwrap_err()
        });
        let ExecutionAttemptError::Deferred(expected) = decode_refusal else {
            panic!("the actual cold frame must retain its bounded decoder refusal");
        };
        let mut acquired = (mode >= 2).then(|| {
            state
                .acquire_canonical_runtime_block(true)
                .expect("original replacement writers")
        });
        // This failed admission observes occupied capacity without consuming the
        // free headroom needed by the real cold decode. No artificial hold is
        // dropped after registration to manufacture the wake under test.
        let AllocationRefusal::Capacity { release, .. } =
            budget.try_reserve_bytes(budget.limit_bytes()).unwrap_err()
        else {
            panic!("the original State pool has actual retained owners");
        };
        let probe = Arc::new(RefundProbe {
            state: Arc::clone(state),
            expected_poison: mode == 4,
            calls: AtomicUsize::new(0),
            blocked: AtomicUsize::new(0),
            poison_mismatches: AtomicUsize::new(0),
            running: AtomicBool::new(false),
        });
        let waker = Waker::from(Arc::clone(&probe));
        let mut context = Context::from_waker(&waker);
        let mut pending = release.wait_for_release(&mut registration);
        assert!(Pin::new(&mut pending).poll(&mut context).is_pending());
        let failed = mode == 1 || mode == 3;
        let mut rebuild = || {
            if let Some(acquired) = acquired.as_mut() {
                acquired.rewind_da_indexes_to_height(1)
            } else {
                state.ensure_da_indexes_hydrated()
            }
        };
        let result = if failed {
            norito::with_decode_limits_scope(decode_limits(), rebuild)
        } else {
            rebuild()
        };
        if failed {
            assert_eq!(result, Err(DaIndexHydrationError::Deferred(expected)));
            assert!(state.da_indexes_hydrated.read().is_none());
            assert_eq!(projection(state), published);
            assert_eq!(std::fs::read(&journal).unwrap(), journal_before);
        } else {
            assert_eq!(result, Ok(()));
            assert_eq!(projection(state), published);
        }
        if let Some(original) = acquired.take() {
            assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
            assert!(Pin::new(&mut pending).poll(&mut context).is_pending());
            if mode == 4 {
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                        let _original = original;
                        panic!("unwind the original replacement owner after cold DA read");
                    }))
                    .is_err()
                );
            } else {
                drop(original);
            }
        }
        assert!(Pin::new(&mut pending).poll(&mut context).is_ready());
        assert!(probe.calls.load(Ordering::SeqCst) > 0);
        assert_eq!(probe.blocked.load(Ordering::SeqCst), 0);
        assert_eq!(
            probe.poison_mismatches.load(Ordering::SeqCst),
            0,
            "unwind poison stays terminal and distinct from actual writer contention",
        );
        drop(pending);
        registration.cancel();
        // No refund waiter remains armed when unrelated State generations can
        // finish their actual epoch retirement.
        drop(retirement_pin);
        if failed {
            state.ensure_da_indexes_hydrated().unwrap();
        }
        assert_eq!(projection(state), published);
        assert_eq!(std::fs::read(&journal).unwrap(), journal_before);
        assert_eq!(state.latest_block_hash_fast(), tip);
        assert_eq!(*state.da_indexes_hydrated.read(), Some(Ok(())));
    }
}
