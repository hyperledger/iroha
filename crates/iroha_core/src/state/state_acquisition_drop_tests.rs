//! Actual State acquisition must jointly retire original World and membership writers.
//!
//! Register this child under acquisition_fixture_tests.rs to reuse its original
//! four-validator fixture without widening any production or test API.

use super::fixture;
use crate::state::{State, StateBlockStartError, storage_transactions};
use mv::{PublicationCleanup, PublicationPreparationError};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Wake, Waker},
};

// Membership uses a parking_lot writer: an actual Cell unwind can poison its
// physical mutex while this original membership writer remains healthy.
struct MembershipProbe<Cleanup> {
    journal: Option<storage_transactions::DetachedTransactionsBlock>,
    cleanup: Option<Cleanup>,
}

enum MembershipProbeResult {
    Acquired,
    Busy,
    Other,
}

struct ProbeMembershipOnWorldRelease<Cleanup, Inspect> {
    state: Arc<State>,
    original: Mutex<MembershipProbe<Cleanup>>,
    inspect: Inspect,
    calls: AtomicUsize,
    acquired: AtomicUsize,
    busy: AtomicUsize,
    other: AtomicUsize,
    unavailable: AtomicUsize,
}

trait MembershipProbeWitness: Wake {
    fn observations(&self) -> [usize; 5];
    // Called only outside Wake. The opaque native abort cleanup is deliberately
    // retained in the callback owner, then destroyed after its mutex is free.
    fn take_original(&self) -> storage_transactions::DetachedTransactionsBlock;
}

impl<Cleanup, Inspect> Wake for ProbeMembershipOnWorldRelease<Cleanup, Inspect>
where
    Cleanup: Send + 'static,
    Inspect: Fn(
            storage_transactions::DetachedTransactionsBlock,
            &State,
        ) -> (
            storage_transactions::DetachedTransactionsBlock,
            Option<Cleanup>,
            MembershipProbeResult,
        ) + Send
        + Sync
        + 'static,
{
    fn wake(self: Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let Ok(mut original) = self.original.try_lock() else {
            self.unavailable.fetch_add(1, Ordering::SeqCst);
            return;
        };
        if original.cleanup.is_some() {
            self.unavailable.fetch_add(1, Ordering::SeqCst);
            return;
        }
        let Some(journal) = original.journal.take() else {
            self.unavailable.fetch_add(1, Ordering::SeqCst);
            return;
        };
        let (journal, cleanup, result) = (self.inspect)(journal, &self.state);
        original.journal = Some(journal);
        original.cleanup = cleanup;
        match result {
            MembershipProbeResult::Acquired => &self.acquired,
            MembershipProbeResult::Busy => &self.busy,
            MembershipProbeResult::Other => &self.other,
        }
        .fetch_add(1, Ordering::SeqCst);
    }
}

impl<Cleanup, Inspect> MembershipProbeWitness for ProbeMembershipOnWorldRelease<Cleanup, Inspect>
where
    Cleanup: Send + 'static,
    Inspect: Fn(
            storage_transactions::DetachedTransactionsBlock,
            &State,
        ) -> (
            storage_transactions::DetachedTransactionsBlock,
            Option<Cleanup>,
            MembershipProbeResult,
        ) + Send
        + Sync
        + 'static,
{
    fn observations(&self) -> [usize; 5] {
        [
            self.calls.load(Ordering::SeqCst),
            self.acquired.load(Ordering::SeqCst),
            self.busy.load(Ordering::SeqCst),
            self.other.load(Ordering::SeqCst),
            self.unavailable.load(Ordering::SeqCst),
        ]
    }

    fn take_original(&self) -> storage_transactions::DetachedTransactionsBlock {
        let (journal, cleanup) = {
            let mut original = self.original.lock().unwrap();
            (original.journal.take().unwrap(), original.cleanup.take())
        };
        drop(cleanup);
        journal
    }
}

fn membership_probe_before_stage(state: &State) -> storage_transactions::DetachedTransactionsBlock {
    let mut block = state.transactions.block();
    block.insert_block(
        std::collections::BTreeSet::new(),
        std::num::NonZeroUsize::new(state.transactions.latest_height() + 1).unwrap(),
    );
    block.prepare_commit().unwrap().detach()
}

fn membership_probe_callback(
    state: &Arc<State>,
    journal: storage_transactions::DetachedTransactionsBlock,
) -> Arc<impl MembershipProbeWitness + use<>> {
    // Infer the private native abort-cleanup type from its actual constructor;
    // no erased Box or test-only visibility expansion is needed.
    let inspect =
        |journal: storage_transactions::DetachedTransactionsBlock, state: &State| match journal
            .try_prepare_publication(&state.transactions, |_, _| Ok::<_, ()>(()))
        {
            Ok(prepared) => {
                let (journal, cleanup) = prepared.abort();
                (journal, Some(cleanup), MembershipProbeResult::Acquired)
            }
            Err((journal, error, cleanup)) => {
                let result = if matches!(error, PublicationPreparationError::Busy(_)) {
                    MembershipProbeResult::Busy
                } else {
                    MembershipProbeResult::Other
                };
                (journal, Some(cleanup), result)
            }
        };
    Arc::new(ProbeMembershipOnWorldRelease {
        state: Arc::clone(state),
        original: Mutex::new(MembershipProbe {
            journal: Some(journal),
            cleanup: None,
        }),
        inspect,
        calls: AtomicUsize::new(0),
        acquired: AtomicUsize::new(0),
        busy: AtomicUsize::new(0),
        other: AtomicUsize::new(0),
        unavailable: AtomicUsize::new(0),
    })
}

fn held_cell_observation<V: mv::Value>(
    target: &mv::cell::Cell<V>,
    journal: mv::cell::Detached<V, ()>,
) -> (
    mv::cell::Detached<V, ()>,
    iroha_allocation::release::ReleaseWait,
    PublicationCleanup<()>,
) {
    let physical_admissions = AtomicUsize::new(0);
    let (journal, error, cleanup) = journal
        .try_prepare_publication(target, |_, _| {
            physical_admissions.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>(())
        })
        .err()
        .expect("actual original Cell writer is held");
    assert_eq!(physical_admissions.load(Ordering::SeqCst), 1);
    let PublicationPreparationError::Busy(wait) = error else {
        panic!("expected original physical Cell contention");
    };
    (journal, wait, cleanup)
}

fn held_membership_observation(
    state: &State,
    journal: storage_transactions::DetachedTransactionsBlock,
) -> (
    storage_transactions::DetachedTransactionsBlock,
    iroha_allocation::release::ReleaseWait,
) {
    let (journal, error, _cleanup) = journal
        .try_prepare_publication(&state.transactions, |_, _| Ok::<_, ()>(()))
        .err()
        .expect("actual original membership writer is held");
    let PublicationPreparationError::Busy(wait) = error else {
        panic!("expected original physical membership contention");
    };
    (journal, wait)
}

#[derive(Clone, Copy)]
enum StateExit {
    PristineStageRefusal,
    PristineStagePanic,
    CompleteBlockDrop,
}

fn assert_state_exit_releases_all_original_writers(exit: StateExit) {
    let (state, proposal) = fixture();
    let state: Arc<State> = Arc::from(state);
    let mut registration =
        crate::unit_test_support::release_registration(&state.ivm_execution_budget());
    let before = crate::snapshot::canonical_state_snapshot_hash(&state).unwrap();
    let mut parameters = Some(
        state
            .world
            .parameters
            .block()
            .try_detach(|_| Ok::<_, ()>(()))
            .unwrap(),
    );
    let mut membership = Some(membership_probe_before_stage(&state));
    let mut observed = None;
    let stages = AtomicUsize::new(0);
    {
        let mut register = || {
            // The production constructor already owns every actual State writer.
            // Both Busy observations come from the original journals and targets.
            let (parameters, wait, refused) = held_cell_observation(
                &state.world.parameters,
                parameters.take().expect("one original World probe"),
            );
            let (membership, membership_wait) = held_membership_observation(
                &state,
                membership.take().expect("one original membership probe"),
            );
            assert!(!wait.is_poisoned());
            assert!(!membership_wait.is_poisoned());
            let callback = membership_probe_callback(&state, membership);
            let waker = Waker::from(Arc::clone(&callback));
            let future = wait.clone();
            assert!(
                registration
                    .poll_wait(&future, &mut Context::from_waker(&waker))
                    .is_pending()
            );
            assert_eq!(callback.observations(), [0; 5]);
            observed = Some((parameters, wait, refused, membership_wait, callback, future));
        };
        match exit {
            StateExit::PristineStageRefusal => {
                let error = state
                    .block_with_pristine_stage(proposal.header(), |_| {
                        stages.fetch_add(1, Ordering::SeqCst);
                        register();
                        Err::<(), _>("original pristine-stage refusal")
                    })
                    .err()
                    .expect("the actual State pristine stage refused");
                assert!(matches!(
                    error,
                    StateBlockStartError::Stage("original pristine-stage refusal")
                ));
            }
            StateExit::PristineStagePanic => {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    state.block_with_pristine_stage(
                        proposal.header(),
                        |_| -> Result<(), &'static str> {
                            stages.fetch_add(1, Ordering::SeqCst);
                            register();
                            panic!("injected actual pristine-stage panic");
                        },
                    )
                }));
                assert!(result.is_err());
            }
            StateExit::CompleteBlockDrop => {
                let block = state
                    .block_with_pristine_stage(proposal.header(), |_| {
                        stages.fetch_add(1, Ordering::SeqCst);
                        Ok::<(), &'static str>(())
                    })
                    .unwrap_or_else(|error| panic!("actual complete State block: {error:?}"));
                register();
                // No PreparedCarrier wrapper masks ordinary StateBlock cleanup.
                drop(block);
            }
        }
    }
    assert_eq!(stages.load(Ordering::SeqCst), 1);
    let (parameters, wait, refused, membership_wait, callback, future) =
        observed.expect("the actual original State writers were observed");
    let waker = Waker::from(Arc::clone(&callback));
    assert!(
        registration
            .poll_wait(&future, &mut Context::from_waker(&waker))
            .is_ready()
    );
    // Actual std Cell poison survives unwind; parking_lot membership stays healthy.
    assert_eq!(
        wait.is_poisoned(),
        matches!(exit, StateExit::PristineStagePanic)
    );
    assert!(!membership_wait.is_poisoned());
    // The native callback only recorded nonblocking observations. All assertions
    // and destruction of its actual acquired abort cleanup happen outside Wake.
    assert_eq!(callback.observations(), [1, 1, 0, 0, 0]);
    let membership = callback.take_original();
    drop(refused);
    assert_eq!(
        membership.observe_predecessor(&state.transactions),
        storage_transactions::MembershipPredecessorStatus::Current
    );
    assert!(parameters.matches_current(&state.world.parameters));
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_hash(&state).unwrap(),
        before
    );
    // Keep both exact original journals through every source/image assertion.
    drop((membership, parameters));
}

#[test]
fn pristine_stage_refusal_releases_membership_before_world_notification() {
    assert_state_exit_releases_all_original_writers(StateExit::PristineStageRefusal);
}

#[test]
fn complete_state_block_drop_releases_membership_before_world_notification() {
    assert_state_exit_releases_all_original_writers(StateExit::CompleteBlockDrop);
}

#[test]
fn pristine_stage_panic_releases_healthy_membership_before_world_notification() {
    assert_state_exit_releases_all_original_writers(StateExit::PristineStagePanic);
}

#[test]
fn acquired_runtime_result_drop_releases_membership_before_world_notification() {
    let (state, _proposal) = fixture();
    let state: Arc<State> = Arc::from(state);
    let mut registration =
        crate::unit_test_support::release_registration(&state.ivm_execution_budget());
    let before = crate::snapshot::canonical_state_snapshot_hash(&state).unwrap();
    let parameters = state
        .world
        .parameters
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap();
    let membership = membership_probe_before_stage(&state);

    // This is the actual acquisition result, before any StateBlock wrapper can
    // mask its own abandonment order. No synthetic guard or release is minted.
    let acquired = state.acquire_canonical_runtime_block(false).unwrap();
    let (parameters, wait, refused) = held_cell_observation(&state.world.parameters, parameters);
    let (membership, membership_wait) = held_membership_observation(&state, membership);
    assert!(!wait.is_poisoned());
    assert!(!membership_wait.is_poisoned());
    let callback = membership_probe_callback(&state, membership);
    let waker = Waker::from(Arc::clone(&callback));
    let mut future = wait.clone().wait_for_release(&mut registration);
    assert!(
        Pin::new(&mut future)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(callback.observations(), [0; 5]);

    drop(acquired);

    assert!(
        Pin::new(&mut future)
            .poll(&mut Context::from_waker(&waker))
            .is_ready()
    );
    assert!(!wait.is_poisoned());
    assert!(!membership_wait.is_poisoned());
    // Wake only recorded actual nonblocking physical acquisition. Retire the
    // returned native cleanup and assert source images outside that callback.
    assert_eq!(callback.observations(), [1, 1, 0, 0, 0]);
    let membership = callback.take_original();
    drop(refused);
    assert_eq!(
        membership.observe_predecessor(&state.transactions),
        storage_transactions::MembershipPredecessorStatus::Current
    );
    assert!(parameters.matches_current(&state.world.parameters));
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_hash(&state).unwrap(),
        before
    );
    drop((membership, parameters));
}

#[test]
fn runtime_index_snapshots_notify_before_acquiring_original_writers() {
    for replacement in [false, true] {
        let (state, _proposal) = fixture();
        let state: Arc<State> = Arc::from(state);
        let mut registration =
            crate::unit_test_support::release_registration(&state.ivm_execution_budget());
        let membership = membership_probe_before_stage(&state);
        let callback = membership_probe_callback(&state, membership);
        let waker = Waker::from(Arc::clone(&callback));
        let mut context = Context::from_waker(&waker);
        // Observe an actual blocked index acquisition, then physically
        // unlock while retaining that release. The constructor's own read
        // must deliver the first notification while membership is still free.
        let held = state.lane_manifests.read();
        let wait = state.lane_manifests.try_write_or_wait().err().unwrap();
        let original_release = held.release_deferred();
        let mut future = Box::pin(wait.wait_for_release(&mut registration));
        assert!(future.as_mut().poll(&mut context).is_pending());
        let acquired = state.acquire_canonical_runtime_block(replacement).unwrap();
        assert!(future.as_mut().poll(&mut context).is_ready());
        assert_eq!(callback.observations(), [1, 1, 0, 0, 0]);
        drop(acquired);
        drop(callback.take_original());
        drop(original_release);
    }
}

#[path = "da_rewind_release_tests.rs"]
mod da_rewind_release_tests;
