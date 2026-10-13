//! Direct commit refusal must retire original State writers before membership wakes.
//!
//! Register beneath acquisition_fixture_tests to reuse the actual four-validator
//! fixture. This exercises public StateBlock::commit, not a test commit surrogate.

use super::fixture;
use crate::state::{State, StateParameters, storage_transactions};
use iroha_allocation::release::DeferredRelease;
use mv::{PublicationCleanup, PublicationPreparationError};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Wake, Waker},
};

#[derive(Debug, Default, PartialEq, Eq)]
struct PhysicalObservations {
    world_admitted: usize,
    world_acquired: usize,
    world_busy: usize,
    world_changed: usize,
    world_other: usize,
    commit_free: usize,
    commit_busy: usize,
    write_free: usize,
    write_busy: usize,
    generation_odd: usize,
}

struct OriginalProbe {
    parameters: Option<mv::cell::Detached<StateParameters, ()>>,
    world_cleanup: Option<PublicationCleanup<()>>,
    fence_cleanup: [Option<DeferredRelease>; 2],
    observed: PhysicalObservations,
}

struct ProbeOriginalStateOnMembershipRelease {
    state: Arc<State>,
    original: Mutex<OriginalProbe>,
    calls: AtomicUsize,
    unavailable: AtomicUsize,
}

impl Wake for ProbeOriginalStateOnMembershipRelease {
    fn wake(self: Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let Ok(mut original) = self.original.try_lock() else {
            self.unavailable.fetch_add(1, Ordering::SeqCst);
            return;
        };
        if original.world_cleanup.is_some() {
            self.unavailable.fetch_add(1, Ordering::SeqCst);
            return;
        }
        let Some(parameters) = original.parameters.take() else {
            self.unavailable.fetch_add(1, Ordering::SeqCst);
            return;
        };
        // The admission callback records that the exact original predecessor was
        // joined. Subsequent Busy is the native physical writer, not a fake wait.
        match parameters.try_prepare_publication(&self.state.world.parameters, |_, _| {
            original.observed.world_admitted += 1;
            Ok::<_, ()>(())
        }) {
            Ok(prepared) => {
                original.observed.world_acquired += 1;
                let (parameters, cleanup) = prepared.abort();
                original.parameters = Some(parameters);
                original.world_cleanup = Some(cleanup);
            }
            Err((parameters, error, cleanup)) => {
                if matches!(error, PublicationPreparationError::Busy(_)) {
                    original.observed.world_busy += 1;
                } else if matches!(error, PublicationPreparationError::Changed) {
                    original.observed.world_changed += 1;
                } else {
                    original.observed.world_other += 1;
                }
                original.parameters = Some(parameters);
                original.world_cleanup = Some(cleanup);
            }
        }
        match self.state.state_commit_lock.try_lock() {
            Some(guard) => {
                original.observed.commit_free += 1;
                original.fence_cleanup[0] = Some(guard.release_deferred());
            }
            None => original.observed.commit_busy += 1,
        }
        match self.state.state_write_lock.try_lock() {
            Some(guard) => {
                original.observed.write_free += 1;
                original.fence_cleanup[1] = Some(guard.release_deferred());
            }
            None => original.observed.write_busy += 1,
        }
        original.observed.generation_odd +=
            usize::from(!self.state.state_view_generation().is_multiple_of(2));
        // No assertions or cleanup notifications occur here. Abort physically
        // unlocks the probe, and every returned release stays in this owner.
    }
}

fn original_membership_probe(state: &State) -> storage_transactions::DetachedTransactionsBlock {
    let mut block = state.transactions.block();
    block.insert_block(
        BTreeSet::new(),
        NonZeroUsize::new(state.transactions.latest_height() + 1).unwrap(),
    );
    block.prepare_commit().unwrap().detach()
}

#[derive(Clone, Copy)]
enum CommitCase {
    MissingMembership,
    InvalidWorldTail,
    Publish,
}

#[test]
fn missing_membership_commit_refusal_releases_world_and_state_fences_before_notification() {
    check_commit_retirement(
        CommitCase::MissingMembership,
        NotificationSource::Membership,
    );
}

#[test]
fn late_world_commit_refusal_releases_membership_and_state_fences_before_notification() {
    check_commit_retirement(CommitCase::InvalidWorldTail, NotificationSource::Membership);
}

#[test]
fn successful_commit_retires_membership_after_state_fences_and_changes_original_predecessors() {
    check_commit_retirement(CommitCase::Publish, NotificationSource::Membership);
}

#[derive(Clone, Copy)]
enum NotificationSource {
    Membership,
    Commit,
    Write,
}

#[test]
fn original_state_commit_fence_never_notifies_under_sibling_writers() {
    for case in [
        CommitCase::MissingMembership,
        CommitCase::InvalidWorldTail,
        CommitCase::Publish,
    ] {
        check_commit_retirement(case, NotificationSource::Commit);
    }
}

#[test]
fn original_state_write_fence_never_notifies_under_sibling_writers() {
    for case in [
        CommitCase::MissingMembership,
        CommitCase::InvalidWorldTail,
        CommitCase::Publish,
    ] {
        check_commit_retirement(case, NotificationSource::Write);
    }
}

fn check_commit_retirement(case: CommitCase, source: NotificationSource) {
    let (state, proposal) = fixture();
    let state: Arc<State> = Arc::from(state);
    let mut registration =
        crate::unit_test_support::release_registration(&state.ivm_execution_budget());
    let before = crate::snapshot::canonical_state_snapshot_hash(&state).unwrap();
    let before_height = state.transactions.latest_height();
    let parameters = state
        .world
        .parameters
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap();
    let membership = original_membership_probe(&state);

    // Construct the ordinary block through its actual start phases. Publication
    // and late refusal stage the exact empty membership/hash; the missing case
    // intentionally leaves membership unstaged. No finality permit is fabricated.
    let mut block = state
        .block_with_pristine_stage(proposal.header(), |_| Ok::<(), &'static str>(()))
        .unwrap_or_else(|error| panic!("actual State start: {error:?}"));
    assert!(!block.transactions.has_staged_block());
    assert!(matches!(
        block.transactions.validate_commit(),
        Err(storage_transactions::TransactionsBlockError::MissingInsertBlock)
    ));
    // These are the real earlier publication guards, left intact. The final
    // exact error assertion below also excludes any intervening guard failure.
    block.verify_execution_output_publication().unwrap();
    block.validate_canonical_runtime_projection().unwrap();
    block.verify_sumeragi_lane_state_publication().unwrap();
    assert!(block.fastpq_source_inventory.is_none());

    let carrier_hash = proposal.header().hash();
    if !matches!(case, CommitCase::MissingMembership) {
        // Genesis fixture admission must precede staging the first hash, just as
        // commit_empty_block_for_testing does in the original State fixture API.
        block.finalize_axt_asset_incarnations().unwrap();
        block.transactions.insert_block(
            BTreeSet::new(),
            NonZeroUsize::new(before_height + 1).unwrap(),
        );
        block.transactions.validate_commit().unwrap();
        block.block_hashes.push(carrier_hash);
    }
    if matches!(case, CommitCase::InvalidWorldTail) {
        block.pending_da_pin_intents = Some(crate::state::PendingDaPinIntentBundle {
            block_height: proposal.header().height().get() + 1,
            intents: Vec::new(),
            quota_writes: BTreeMap::new(),
        });
    }

    let physical_admissions = AtomicUsize::new(0);
    let (parameters, error, initial_world_cleanup) = parameters
        .try_prepare_publication(&state.world.parameters, |_, _| {
            physical_admissions.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>(())
        })
        .err()
        .expect("the original State owns the actual World writer");
    assert_eq!(physical_admissions.load(Ordering::SeqCst), 1);
    let PublicationPreparationError::Busy(world_wait) = error else {
        panic!("expected real World writer contention");
    };
    assert!(!world_wait.is_poisoned());

    let (membership, error, _membership_cleanup) = membership
        .try_prepare_publication(&state.transactions, |_, _| Ok::<_, ()>(()))
        .err()
        .expect("the original State owns the actual membership writer");
    let PublicationPreparationError::Busy(membership_wait) = error else {
        panic!("expected real membership writer contention");
    };
    assert!(!membership_wait.is_poisoned());
    let callback = Arc::new(ProbeOriginalStateOnMembershipRelease {
        state: Arc::clone(&state),
        original: Mutex::new(OriginalProbe {
            parameters: Some(parameters),
            world_cleanup: None,
            fence_cleanup: [None, None],
            observed: PhysicalObservations::default(),
        }),
        calls: AtomicUsize::new(0),
        unavailable: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&callback));
    let initial_fence_release;
    let wait = match source {
        NotificationSource::Membership => {
            initial_fence_release = None;
            membership_wait.clone()
        }
        NotificationSource::Commit | NotificationSource::Write => {
            let fence = if matches!(source, NotificationSource::Commit) {
                &state.state_commit_lock
            } else {
                &state.state_write_lock
            };
            let original = fence.lock();
            let wait = fence
                .try_lock_or_wait()
                .err()
                .expect("original physical fence");
            initial_fence_release = Some(original.release_deferred());
            wait
        }
    };
    let mut released = wait.wait_for_release(&mut registration);
    assert!(
        Pin::new(&mut released)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(callback.calls.load(Ordering::SeqCst), 0);

    // Exact production outcomes prove neither earlier guards nor a test-only
    // surrogate masked the consuming operation under test.
    let result = block.commit();
    match case {
        CommitCase::MissingMembership => assert!(
            matches!(
                result,
                Err(storage_transactions::TransactionsBlockError::MissingInsertBlock)
            ),
            "must reach consuming membership refusal, got {result:?}"
        ),
        CommitCase::InvalidWorldTail => assert!(
            matches!(
                result,
                Err(storage_transactions::TransactionsBlockError::WorldCommitPreparation)
            ),
            "must reach late World preparation refusal, got {result:?}"
        ),
        CommitCase::Publish => result.expect("the exact empty carrier commits"),
    }
    assert!(
        Pin::new(&mut released)
            .poll(&mut Context::from_waker(&waker))
            .is_ready()
    );
    assert!(!membership_wait.is_poisoned());
    assert!(!world_wait.is_poisoned());

    // Move all opaque cleanup out of the callback owner and destroy it only now,
    // after the original consuming commit has returned. Keep the exact journals.
    let (parameters, world_cleanup, fence_cleanup, observed) = {
        let mut original = callback.original.lock().unwrap();
        (
            original.parameters.take().unwrap(),
            original.world_cleanup.take(),
            std::mem::take(&mut original.fence_cleanup),
            std::mem::take(&mut original.observed),
        )
    };
    drop((world_cleanup, fence_cleanup, initial_world_cleanup));
    assert_eq!(callback.calls.load(Ordering::SeqCst), 1);
    assert_eq!(callback.unavailable.load(Ordering::SeqCst), 0);
    assert_eq!(state.state_view_generation() % 2, 0);
    if matches!(case, CommitCase::Publish) {
        assert_eq!(state.transactions.latest_height(), before_height + 1);
        assert_eq!(state.latest_block_hash_fast(), Some(carrier_hash));
        assert_eq!(
            membership.observe_predecessor(&state.transactions),
            storage_transactions::MembershipPredecessorStatus::Changed
        );
        assert!(!parameters.matches_current(&state.world.parameters));
        assert_ne!(
            crate::snapshot::canonical_state_snapshot_hash(&state).unwrap(),
            before
        );
        // Changed identity correctly refuses the old World journal before its
        // physical writer probe. The success control checks State fences only;
        // it does not mislabel stale identity as evidence of a free World writer.
        assert_eq!(
            observed,
            PhysicalObservations {
                world_changed: 1,
                commit_free: 1,
                write_free: 1,
                ..PhysicalObservations::default()
            }
        );
    } else {
        assert_eq!(state.transactions.latest_height(), before_height);
        assert_eq!(
            membership.observe_predecessor(&state.transactions),
            storage_transactions::MembershipPredecessorStatus::Current
        );
        assert!(parameters.matches_current(&state.world.parameters));
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_hash(&state).unwrap(),
            before
        );
        assert_eq!(
            observed,
            PhysicalObservations {
                world_admitted: 1,
                world_acquired: 1,
                commit_free: 1,
                write_free: 1,
                ..PhysicalObservations::default()
            },
            "membership release must follow every original writer and State fence"
        );
    }
    drop((membership, parameters, initial_fence_release));
}

include!("direct_commit_execution_refund_tests.rs");
