//! Actual State publication defers effect-index contention before visibility.

use super::{fixture, staged_block};
use crate::state::{State, StatePublicationOutcome, storage_transactions::TransactionsBlockError};
use iroha_allocation::release::ReleaseWait;
use mv::storage::StorageReadOnly;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    task::{Context, Wake, Waker},
    time::Duration,
};

fn original_writers_are_free(state: &State) -> bool {
    let fences = state.state_write_lock.try_lock().is_some()
        && state.state_commit_lock.try_lock().is_some()
        && state.lane_lifecycle_lock.try_lock().is_some();
    let parameters = state.world.parameters.probe_original_writers_for_testing();
    let runtime = state.canonical_runtime.probe_original_writers_for_testing();
    let fields = parameters
        .iter()
        .chain(&runtime)
        .all(|probe| probe.acquired && !probe.poisoned);
    let indexes = state.latest_block_header.try_write().is_some()
        && state.da_commitments.try_write().is_some()
        && state.da_confidential_compute.try_write().is_some()
        && state.da_receipt_cursors.try_write().is_some()
        && state.da_shard_cursors.try_write().is_some()
        && state.da_pin_intents.try_write().is_some()
        && state.lane_manifests.try_write().is_some()
        && state.lane_privacy_registry.try_write().is_some();
    fences && fields && indexes
}

struct OriginalReleaseProbe {
    state: Arc<State>,
    calls: AtomicUsize,
    blocked: AtomicUsize,
}
impl Wake for OriginalReleaseProbe {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.blocked.fetch_add(
            usize::from(!original_writers_are_free(&self.state)),
            Ordering::SeqCst,
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Debug)]
struct Attempt {
    outcome: StatePublicationOutcome,
    same_original: bool,
    preparation: (usize, usize, bool),
    row: Option<usize>,
}

fn check_original_index_contention(writer: bool) {
    let (state, proposal) = fixture();
    let state: Arc<State> = Arc::from(state);
    let budget = state.ivm_execution_budget();
    let generation = state.state_view_generation();
    let height = proposal.header().height();
    let hash = proposal.hash();
    let probe = Arc::new(OriginalReleaseProbe {
        state: Arc::clone(&state),
        calls: AtomicUsize::new(0),
        blocked: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&probe));
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let mut observations = Vec::new();
    let mut unchanged = Vec::new();
    let mut waits: Vec<ReleaseWait> = Vec::new();
    let mut returned_before_release = true;
    let mut original_wait_ready = false;
    let mut original_wait_pending = false;
    let mut staged = false;
    let mut expected = None;
    let mut joined = false;
    std::thread::scope(|scope| {
        let (ready, staged_rx) = mpsc::channel();
        let (commands, command_rx) = mpsc::channel();
        let (responses, response_rx) = mpsc::channel();
        let worker_state = Arc::clone(&state);
        let worker = scope.spawn(move || {
            let mut original =
                Box::new(staged_block(&worker_state, proposal.header(), false, true));
            let owner = std::ptr::from_ref(&*original);
            let _ = ready.send(());
            while command_rx.recv() == Ok(()) {
                let outcome = original.try_publish();
                let row = matches!(outcome, StatePublicationOutcome::Deferred(_)).then(|| {
                    std::ptr::from_ref(
                        original
                            .world
                            .musubi_public_directory
                            .iter()
                            .next()
                            .unwrap()
                            .1,
                    ) as usize
                });
                let observation = Attempt {
                    outcome,
                    same_original: std::ptr::from_ref(&*original) == owner,
                    preparation: original.publication_identity_for_test(),
                    row,
                };
                if responses.send(observation).is_err() {
                    break;
                }
            }
        });
        staged = staged_rx.recv_timeout(Duration::from_secs(5)).is_ok();
        if staged {
            // These are the actual last publication index's ordinary guards.
            // Stage first so the blocker cannot alter execution or hydration.
            let reader = (!writer).then(|| state.da_indexes_hydrated.read());
            let exclusive = writer.then(|| state.da_indexes_hydrated.write());
            expected = state.da_indexes_hydrated.try_write_or_wait().err();
            for _ in 0..3 {
                if commands.send(()).is_err() {
                    break;
                }
                match response_rx.recv_timeout(Duration::from_secs(5)) {
                    Ok(observation) => {
                        if let StatePublicationOutcome::Deferred(
                            TransactionsBlockError::PublicationBusy(wait),
                        ) = &observation.outcome
                        {
                            waits.push(wait.clone());
                        }
                        observations.push(observation);
                        unchanged.push(
                            original_writers_are_free(&state)
                                && state.state_view_generation() == generation
                                && state.transactions.latest_height() == 0
                                && state.world.musubi_public_directory.view().is_empty()
                                && state.world.try_block(&budget).is_ok()
                                && budget.same_pool(&state.ivm_execution_budget()),
                        );
                    }
                    Err(_) => {
                        returned_before_release = false;
                        break;
                    }
                }
            }
            let mut pending = expected
                .as_ref()
                .map(|wait| wait.clone().wait_for_release(&mut registration));
            if let Some(pending) = pending.as_mut() {
                original_wait_pending = Pin::new(pending)
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending();
            }
            // Never assert while another thread may be blocked in the old path.
            drop(reader);
            drop(exclusive);
            if let Some(pending) = pending.as_mut() {
                original_wait_ready = Pin::new(pending)
                    .poll(&mut Context::from_waker(&waker))
                    .is_ready();
            }
            if returned_before_release {
                // Publish once, then exercise the original completed owner again.
                for _ in 0..2 {
                    if commands.send(()).is_err() {
                        break;
                    }
                    if let Ok(observation) = response_rx.recv_timeout(Duration::from_secs(5)) {
                        observations.push(observation);
                    }
                }
            } else if let Ok(observation) = response_rx.recv_timeout(Duration::from_secs(5)) {
                observations.push(observation);
            }
        }
        drop(commands);
        joined = worker.join().is_ok();
    });
    assert!(staged, "actual signed fixture must finish staging");
    assert!(joined, "the original worker must retire naturally");
    assert!(
        matches!(
            observations.first().map(|attempt| &attempt.outcome),
            Some(StatePublicationOutcome::Deferred(
                TransactionsBlockError::PublicationBusy(_)
            ))
        ),
        "the original index blocker must defer before visibility\nobservations: {observations:?}",
    );
    assert!(
        returned_before_release,
        "publication must not wait under sibling writers"
    );
    assert_eq!(observations.len(), 5);
    assert_eq!(waits.len(), 3);
    assert!(waits.iter().all(|wait| Some(wait) == expected.as_ref()));
    assert!(unchanged.into_iter().all(|same| same));
    assert!(observations.iter().all(|attempt| attempt.same_original));
    assert_ne!(observations[0].preparation.0, 0);
    assert!(observations[0].preparation.2);
    assert!(observations[0].row.is_some());
    assert!(
        observations[..3].windows(2).all(|pair| {
            pair[0].preparation == pair[1].preparation && pair[0].row == pair[1].row
        })
    );
    assert!(
        observations[3..]
            .iter()
            .all(|attempt| { matches!(attempt.outcome, StatePublicationOutcome::Published) })
    );
    assert!(original_wait_pending);
    assert!(original_wait_ready);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert_eq!(probe.blocked.load(Ordering::SeqCst), 0);
    assert!(original_writers_are_free(&state));
    assert!(state.da_indexes_hydrated.try_write().is_some());
    assert_eq!(state.state_view_generation(), generation + 2);
    assert_eq!(
        state.transactions.latest_height(),
        usize::try_from(height.get()).unwrap()
    );
    assert_eq!(state.latest_block_hash_fast(), Some(hash));
    assert!(!state.world.musubi_public_directory.view().is_empty());
}

#[test]
fn actual_state_effect_reader_refusal_retains_original_and_retries_after_release() {
    check_original_index_contention(false);
}

#[test]
fn actual_state_effect_writer_refusal_retains_original_and_retries_after_release() {
    check_original_index_contention(true);
}
