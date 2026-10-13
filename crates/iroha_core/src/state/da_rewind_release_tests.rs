//! Replacement rewind notices stay with the original acquisition, execution, and capture owners.

use super::*;
use crate::state::{da_hydration, storage_transactions::TransactionsBlockError};
use iroha_data_model::prelude::*;
use std::{collections::HashSet, num::NonZeroUsize};

fn seed_committed_prefix(state: &State, header: BlockHeader) {
    // The rewind truncates to zero, so no Kura body is fabricated or needed.
    let mut membership = state.transactions.block();
    membership.insert_block(HashSet::new(), NonZeroUsize::new(1).unwrap());
    membership.commit().unwrap();
    let mut hashes = state.block_hashes.block();
    hashes.push_for_tests(header.hash());
    hashes.commit_for_tests();
}

fn observe_rewind_source(
    state: &State,
    state_write: bool,
) -> (
    iroha_allocation::release::ReleaseWait,
    iroha_allocation::release::DeferredRelease,
) {
    if state_write {
        let guard = state.state_write_lock.lock();
        let wait = state.state_write_lock.try_lock_or_wait().err().unwrap();
        return (wait, guard.release_deferred());
    }
    let reader = state.da_indexes_hydrated.read();
    let wait = state.da_indexes_hydrated.try_write_or_wait().err().unwrap();
    let original = reader.release_deferred();
    (wait, original)
}

#[test]
fn replacement_rewind_retains_notifications_through_acquisition_execution_and_refusal() {
    // Cover the actual replacement constructor before-start exits, the common
    // completed owner handoff, and direct commit's genuine membership refusal.
    for (exit, state_write) in
        (0..6).flat_map(|exit| [false, true].map(move |source| (exit, source)))
    {
        let (state, proposal) = fixture();
        let state: Arc<State> = Arc::from(state);
        let mut registration =
            crate::unit_test_support::release_registration(&state.ivm_execution_budget());
        seed_committed_prefix(&state, proposal.header());
        let journal = membership_probe_before_stage(&state);
        let callback = membership_probe_callback(&state, journal);
        let (wait, original_release) = observe_rewind_source(&state, state_write);
        let waker = Waker::from(Arc::clone(&callback));
        let mut context = Context::from_waker(&waker);
        let mut future = wait.clone().wait_for_release(&mut registration);
        assert!(Pin::new(&mut future).poll(&mut context).is_pending());
        if exit >= 4 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                state.block_and_revert_with_pristine_stage(proposal.header(), |_| {
                    assert_eq!(callback.observations(), [0; 5]);
                    assert!(exit != 5, "original replacement pristine-stage unwind");
                    Err::<(), _>("original replacement pristine-stage refusal")
                })
            }));
            if exit == 5 {
                assert!(result.is_err());
            } else {
                assert!(matches!(
                    result.unwrap(),
                    Err(StateBlockStartError::Stage(_))
                ));
            }
        } else if exit == 1 || exit == 2 {
            let block = state
                .block_and_revert_with_pristine_stage(proposal.header(), |_| {
                    assert_eq!(callback.observations(), [0; 5]);
                    Ok::<_, std::convert::Infallible>(())
                })
                .expect("actual fully initialized replacement owner");
            assert_eq!(callback.observations(), [0; 5]);
            assert!(Pin::new(&mut future).poll(&mut context).is_pending());
            if exit == 1 {
                drop(block);
            } else {
                assert!(matches!(
                    block.commit(),
                    Err(TransactionsBlockError::MissingInsertBlock)
                ));
            }
        } else {
            let mut acquired = state.acquire_canonical_runtime_block(true).unwrap();
            let result = acquired.rewind_da_indexes_to_height(u64::from(exit == 3));
            if exit == 3 {
                assert!(matches!(
                    result,
                    Err(da_hydration::DaIndexHydrationError::MissingBlock { .. })
                ));
            } else {
                assert_eq!(result, Ok(()));
            }
            assert_eq!(callback.observations(), [0; 5]);
            assert!(Pin::new(&mut future).poll(&mut context).is_pending());
            drop(acquired);
        }
        assert!(Pin::new(&mut future).poll(&mut context).is_ready());
        assert!(!wait.is_poisoned());
        assert_eq!(callback.observations(), [1, 1, 0, 0, 0]);
        let journal = callback.take_original();
        assert_eq!(
            journal.observe_predecessor(&state.transactions),
            storage_transactions::MembershipPredecessorStatus::Current
        );
        assert_eq!(state.transactions.latest_height(), 1);
        assert_eq!(state.block_hashes.committed_height(), 1);
        drop((journal, original_release));
    }
}

#[test]
fn replacement_rewind_retains_notifications_through_original_capture_refusal_and_unwind() {
    for (exit, state_write) in
        (0..3).flat_map(|exit| [false, true].map(move |source| (exit, source)))
    {
        let (state, proposal, topology) = super::super::fixture_with_topology();
        let state: Arc<State> = Arc::from(state);
        let mut registration =
            crate::unit_test_support::release_registration(&state.ivm_execution_budget());
        let journal = membership_probe_before_stage(&state);
        let callback = membership_probe_callback(&state, journal);
        let (valid, mut carrier) =
            super::super::signed_genesis_execution(&state, proposal, &topology);
        let (wait, original_release) = observe_rewind_source(&state, state_write);
        let waker = Waker::from(Arc::clone(&callback));
        let mut task = Context::from_waker(&waker);
        let mut future = wait.clone().wait_for_release(&mut registration);
        assert!(Pin::new(&mut future).poll(&mut task).is_pending());
        // Install the exact owner before the same borrowed rewind kernel. This
        // isolates capture custody on a genuine authenticated ordinary carrier;
        // it does not manufacture replacement or membership authority.
        {
            let fields = carrier.fields.as_mut().unwrap();
            fields._da_rewind_releases = Some(da_hydration::DaRewindReleases::new(&state));
            state
                .rewind_da_indexes_to_height_with_releases(
                    0,
                    fields._da_rewind_releases.as_mut().unwrap(),
                )
                .unwrap();
        }
        assert_eq!(callback.observations(), [0; 5]);
        let original = std::ptr::from_ref(&*carrier);
        // Repeated capture validates the already-drained original recorder
        // under the same exclusive guard required by the capture owner.
        let _capture_guard = crate::exec_witness::exec_witness_guard();
        carrier
            .capture_exec_witness()
            .expect("actual original output capture");
        assert_eq!(std::ptr::from_ref(&*carrier), original);
        assert_eq!(callback.observations(), [0; 5]);
        assert!(Pin::new(&mut future).poll(&mut task).is_pending());
        if exit == 0 {
            drop(carrier);
        } else if exit == 1 {
            let mut foreign = valid.as_ref().header();
            foreign.creation_time_ms += 1;
            let events = carrier.world.external_event_buf.clone();
            let error = carrier
                .prepare_carrier_publication_events(foreign)
                .unwrap_err();
            assert!(error.to_string().contains("different carrier"));
            assert_eq!(carrier.world.external_event_buf, events);
            assert_eq!(std::ptr::from_ref(&*carrier), original);
            assert_eq!(callback.observations(), [0; 5]);
            assert!(Pin::new(&mut future).poll(&mut task).is_pending());
            drop(carrier);
        } else {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _original = carrier;
                panic!("actual original output-capture unwind");
            }));
            assert!(result.is_err());
        }
        assert!(Pin::new(&mut future).poll(&mut task).is_ready());
        assert!(!wait.is_poisoned());
        assert_eq!(callback.observations(), [1, 1, 0, 0, 0]);
        let journal = callback.take_original();
        assert_eq!(
            journal.observe_predecessor(&state.transactions),
            storage_transactions::MembershipPredecessorStatus::Current
        );
        drop((journal, original_release));
    }
}
