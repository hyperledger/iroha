//! Actual State reader contention and enclosing release custody.

use super::*;
use crate::{kura::Kura, query::store::LiveQueryStore};
use std::{
    future::Future,
    sync::atomic::AtomicBool,
    task::{Context, Poll, Wake, Waker},
};

fn state() -> Arc<State> {
    Arc::new(State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    ))
}

fn busy(state: &State) -> ReleaseWait {
    match state.try_view_once() {
        Err(StateViewError::Busy(wait)) => wait,
        Err(error) => panic!("unexpected original reader failure: {error}"),
        Ok(_) => panic!("held physical reader owner must refuse immediately"),
    }
}

#[test]
fn nonblocking_state_view_retains_exact_header_and_configuration_release_sources() {
    let state = state();
    let budget = state.ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let occupied = budget.reserved_bytes();
    let context = &mut Context::from_waker(Waker::noop());
    macro_rules! check {
        ($field:ident) => {{
            let held = state.$field.write();
            let first = busy(&state);
            assert_eq!(first, busy(&state));
            let mut pending = std::pin::pin!(first.wait_for_release(&mut registration));
            assert!(pending.as_mut().poll(context).is_pending());
            drop(state.latest_block_header.read());
            assert!(pending.as_mut().poll(context).is_pending());
            drop(held);
            assert_eq!(pending.as_mut().poll(context), Poll::Ready(()));
            assert!(state.try_view_once().is_ok());
        }};
    }
    {
        // Header itself uses a distinct foreign release as the negative control.
        let held = state.latest_block_header.write();
        let wait = busy(&state);
        drop(state.crypto.read());
        let mut pending = std::pin::pin!(wait.wait_for_release(&mut registration));
        assert!(pending.as_mut().poll(context).is_pending());
        drop(held);
        assert_eq!(pending.as_mut().poll(context), Poll::Ready(()));
    }
    check!(nexus);
    check!(crypto);
    check!(pipeline_ivm_prepared_cache);
    check!(lane_manifests);
    assert_eq!(
        budget.reserved_bytes(),
        occupied,
        "reader probes reuse original prepaid controls"
    );
}

#[test]
fn state_view_generation_busy_retains_its_actual_writer_release() {
    let state = state();
    let mut registration =
        crate::unit_test_support::release_registration(&state.ivm_execution_budget());
    let mut notice = state.state_view_publication();
    let held = state.state_write_lock.lock();
    let publication = notice.begin();
    let wait = busy(&state);
    assert_eq!(wait, state.state_write_lock.observe_release());
    let mut pending = std::pin::pin!(wait.wait_for_release(&mut registration));
    let context = &mut Context::from_waker(Waker::noop());
    assert!(pending.as_mut().poll(context).is_pending());
    drop(publication);
    drop(notice);
    assert!(
        pending.as_mut().poll(context).is_pending(),
        "generation completion is not physical writer release"
    );
    drop(held);
    assert!(pending.as_mut().poll(context).is_ready());
    assert!(state.try_view_once().is_ok());
}

struct Probe {
    state: Arc<State>,
    called: AtomicBool,
}
impl Wake for Probe {
    fn wake(self: Arc<Self>) {
        assert!(self.state.state_write_lock.try_lock().is_some());
        assert!(self.state.state_commit_lock.try_lock().is_some());
        self.called.store(true, Ordering::SeqCst);
    }
}

#[test]
fn complete_state_view_defers_world_and_configuration_callbacks_beyond_fences() {
    for unwind in [false, true] {
        let state = state();
        let mut world_registration =
            crate::unit_test_support::release_registration(&state.ivm_execution_budget());
        let mut config_registration =
            crate::unit_test_support::release_registration(&state.ivm_execution_budget());
        let world_probe = Arc::new(Probe {
            state: state.clone(),
            called: AtomicBool::new(false),
        });
        let config_probe = Arc::new(Probe {
            state: state.clone(),
            called: AtomicBool::new(false),
        });
        let world_waker = Waker::from(world_probe.clone());
        let config_waker = Waker::from(config_probe.clone());
        let mut world_context = Context::from_waker(&world_waker);
        let mut config_context = Context::from_waker(&config_waker);
        let mut world_wait = std::pin::pin!(
            state
                .world
                .accounts
                .observe_reader_release()
                .wait_for_release(&mut world_registration)
        );
        let mut config_wait = std::pin::pin!(
            state
                .crypto
                .observe_release()
                .wait_for_release(&mut config_registration)
        );
        assert!(world_wait.as_mut().poll(&mut world_context).is_pending());
        assert!(config_wait.as_mut().poll(&mut config_context).is_pending());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut releases = StateViewReleases::new(&state);
            let _commit = state.state_commit_lock.lock();
            let _writer = state.state_write_lock.lock();
            drop(releases.try_view_once().unwrap());
            assert!(!world_probe.called.load(Ordering::SeqCst));
            assert!(!config_probe.called.load(Ordering::SeqCst));
            if unwind {
                panic!("exercise reader release through the original outer fences");
            }
        }));
        assert_eq!(result.is_err(), unwind);
        assert!(world_probe.called.load(Ordering::SeqCst));
        assert!(config_probe.called.load(Ordering::SeqCst));
        assert!(world_wait.as_mut().poll(&mut world_context).is_ready());
        assert!(config_wait.as_mut().poll(&mut config_context).is_ready());
    }
}

#[test]
fn execution_pool_lookup_does_not_acquire_or_release_the_configuration_reader() {
    let state = state();
    let budget = state.ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let held_credit = budget.try_reserve_bytes(1).unwrap();
    let _writer = state.pipeline_ivm_prepared_cache.write();
    let mut pending = Box::pin(
        state
            .pipeline_ivm_prepared_cache
            .observe_release()
            .wait_for_release(&mut registration),
    );
    let owner = state.ivm_execution_budget();
    assert!(held_credit.belongs_to(&owner));
    assert!(
        pending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
}

#[test]
fn snapshot_runtime_adapters_preserve_original_decoder_refusal() {
    use crate::{
        execution_attempt::{ExecutionAttemptError as Attempt, norito_decode_attempt_error},
        snapshot::SnapshotCaptureError,
        state::storage_transactions::TransactionsBlockError,
    };
    let original = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        || {
            let error = norito::core::reserve_decode_allocation(1).unwrap_err();
            let Attempt::Deferred(reason) =
                norito_decode_attempt_error(error, |error| error.to_string())
            else {
                panic!("the actual bounded decoder must refuse locally");
            };
            reason
        },
    );
    let failure = || {
        SnapshotCaptureError::Runtime(Box::new(LaneLifecycleError::NposPolicy(Attempt::Deferred(
            original.clone(),
        ))))
    };
    assert!(matches!(MergeLedgerCommitError::from(failure()),
        MergeLedgerCommitError::StateView(StateViewError::Runtime(LaneLifecycleError::NposPolicy(Attempt::Deferred(reason)))) if reason == original));
    assert!(matches!(TransactionsBlockError::from(failure()),
        TransactionsBlockError::ExecutionDeferred(reason) if reason == original));
    assert!(matches!(
        TransactionsBlockError::from(SnapshotCaptureError::Runtime(Box::new(
            LaneLifecycleError::Storage("completed invalid runtime".into())
        ))),
        TransactionsBlockError::SnapshotProjection
    ));
}

/// The actual generated owner retains each read-only-excluded table's original notifications
/// until every enclosing fence is gone. The event cell keeps its original lock-free pin and
/// zero-sized release slot; no table or cell is retired to avoid an unread-field diagnostic.
#[test]
fn generated_world_held_release_slots_keep_exact_sources_beyond_state_fences() {
    use iroha_allocation::release::ReleaseRegistration;
    for unwind in [false, true] {
        let state = state();
        let budget = state.ivm_execution_budget();
        let mut registrations: [ReleaseRegistration; 8] =
            std::array::from_fn(|_| crate::unit_test_support::release_registration(&budget));
        let sources = [
            state.world.privacy_pgc_accounts.observe_reader_release(),
            state
                .world
                .privacy_pgc_pool_invariants
                .observe_reader_release(),
            state.world.privacy_nullifiers.observe_reader_release(),
            state.world.privacy_roots.observe_reader_release(),
            state.world.privacy_root_heads.observe_reader_release(),
            state
                .world
                .confidential_policy_transition_index
                .observe_reader_release(),
            state
                .world
                .confidential_policy_transition_counts
                .observe_reader_release(),
            state
                .world
                .parliament_timed_ovn_resource_reservations
                .observe_reader_release(),
        ];
        let probes: [Arc<Probe>; 8] = std::array::from_fn(|_| {
            Arc::new(Probe {
                state: state.clone(),
                called: AtomicBool::new(false),
            })
        });
        let wakers = probes.each_ref().map(|probe| Waker::from(probe.clone()));
        for ((registration, source), waker) in registrations.iter_mut().zip(&sources).zip(&wakers) {
            assert_eq!(
                registration.poll_wait(source, &mut Context::from_waker(waker)),
                Poll::Pending
            );
        }
        let occupied = budget.reserved_bytes();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut releases = WorldReadReleases::new(&state.world);
            let _commit = state.state_commit_lock.lock();
            let _writer = state.state_write_lock.lock();
            macro_rules! read_original {
                ($field:ident, $slot:ident) => {
                    drop(
                        StateFieldReader::try_read_field(&state.world.$field, &mut releases.$slot)
                            .expect("generated slot belongs to this exact original table"),
                    );
                };
            }
            read_original!(privacy_pgc_accounts, _privacy_pgc_accounts);
            read_original!(privacy_pgc_pool_invariants, _privacy_pgc_pool_invariants);
            read_original!(privacy_nullifiers, _privacy_nullifiers);
            read_original!(privacy_roots, _privacy_roots);
            read_original!(privacy_root_heads, _privacy_root_heads);
            read_original!(
                confidential_policy_transition_index,
                _confidential_policy_transition_index
            );
            read_original!(
                confidential_policy_transition_counts,
                _confidential_policy_transition_counts
            );
            read_original!(
                parliament_timed_ovn_resource_reservations,
                _parliament_timed_ovn_resource_reservations
            );
            let original = state.world.external_event_buf.view();
            let actual = StateFieldReader::try_read_field(
                &state.world.external_event_buf,
                &mut releases._external_event_buf,
            )
            .expect("the original cell needs no table release control");
            assert!(std::ptr::eq(original.get(), actual.get()));
            assert!(actual.get().is_empty());
            assert_eq!(std::mem::size_of_val(&releases._external_event_buf), 0);
            drop(actual);
            drop(original);
            assert!(
                probes
                    .iter()
                    .all(|probe| !probe.called.load(Ordering::SeqCst))
            );
            assert_eq!(budget.reserved_bytes(), occupied);
            if unwind {
                panic!("retire the exact generated owners after the original fences unwind");
            }
        }));
        assert_eq!(result.is_err(), unwind);
        assert!(
            probes
                .iter()
                .all(|probe| probe.called.load(Ordering::SeqCst))
        );
        for ((registration, source), waker) in registrations.iter_mut().zip(&sources).zip(&wakers) {
            assert_eq!(
                registration.poll_wait(source, &mut Context::from_waker(waker)),
                Poll::Ready(())
            );
        }
        assert_eq!(budget.reserved_bytes(), occupied);
        drop(registrations);
        assert_eq!(
            budget.reserved_bytes(),
            occupied - 8 * ReleaseRegistration::allocation_layout().size()
        );
    }
}
