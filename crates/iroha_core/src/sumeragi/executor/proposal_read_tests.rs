//! One actual global build owns lane read refusal across retries and explicit lifecycle changes.

use super::*;
use crate::sumeragi::driver::traits::BlockStore as _;
use crate::sumeragi::lanes::{ProposalReadScope, merge::LaneBlockSource as _};
use iroha_model_base::topology::LaneId;

fn refuse_actual_batch(worker: &mut Worker<'_>, height: u64, view: u64) {
    let mut rows = Vec::<TransactionEntrypoint>::new();
    rows.try_reserve(1).unwrap();
    let layout = std::alloc::Layout::array::<TransactionEntrypoint>(rows.capacity()).unwrap();
    drop(rows);
    let (result, refused) = crate::test_allocations::refuse_one_layout_during(layout, || {
        worker.build(height, view, 1 << 20, 100)
    });
    assert!(
        refused,
        "the original certified lane batch destination actually refuses"
    );
    assert!(
        matches!(result, Err(PublicationError::Deferred(_))),
        "original native batch refusal: {result:?}"
    );
    assert!(worker.assembly_parent_service.is_none());
    assert!(worker.payload_build.is_none());
    assert!(worker.completed_payload.is_none());
}

#[test]
fn original_lane_read_request_survives_refusal_busy_state_and_incidental_publication() {
    let observed = Arc::new(std::sync::Mutex::new(None));
    let result = observed.clone();
    lanes::merge::with_original_lane_merge_fixture(move |chain, stores, certify, [first, _]| {
        certify(1, chain.height(), vec![first]);
        publication_tests::with_worker_chain(
            chain,
            ConsensusMode::Permissioned,
            stores.clone(),
            |chain, worker, _blocks, _events| {
                let _epoch = crossbeam_epoch::pin();
                let height = chain.height() + 1;
                let state = worker.state;
                let budget = state.ivm_execution_budget();
                refuse_actual_batch(worker, height, 0);
                let original = worker
                    .proposal_reads
                    .as_ref()
                    .unwrap()
                    .1
                    .observation_for_test();
                let charged = budget.reserved_bytes();
                refuse_actual_batch(worker, height, 0);
                let repeated = original.matches(&worker.proposal_reads.as_ref().unwrap().1)
                    && budget.reserved_bytes() == charged;
                let generation = state.state_view_generation();
                let applied = worker.applied;
                state.with_held_view_publication_for_reader_test(|_| {
                    assert!(matches!(
                        worker.build(height, 0, 1 << 20, 100),
                        Err(PublicationError::Deferred(_))
                    ));
                    assert_eq!(worker.applied, applied);
                });
                assert_ne!(state.state_view_generation(), generation);
                assert_eq!(worker.applied, applied);
                refuse_actual_batch(worker, height, 0);
                let same = original.matches(&worker.proposal_reads.as_ref().unwrap().1)
                    && !original.cancelled()
                    && budget.reserved_bytes() == charged;
                // A rejection of another view is not this request's withdrawal.
                worker.reject(height, 1, Hash32::ZERO);
                let unrelated_kept = original.matches(&worker.proposal_reads.as_ref().unwrap().1);
                worker.reject(height, 0, Hash32::ZERO);
                let cancelled = original.cancelled() && worker.proposal_reads.is_none();
                drop(original);
                let read = stores
                    .block(
                        LaneId::new(2),
                        &state
                            .view()
                            .world()
                            .sumeragi_lanes()
                            .lane(LaneId::new(2))
                            .unwrap()
                            .incarnation,
                        1,
                    )
                    .unwrap()
                    .unwrap();
                assert!(read.batch.is_some());
                drop(read);
                *result.lock().unwrap() =
                    Some((budget, repeated && same && unrelated_kept && cancelled));
            },
        );
    });
    let (budget, correct) = observed.lock().unwrap().take().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while budget.reserved_bytes() != 0 && std::time::Instant::now() < deadline {
        crossbeam_epoch::pin().flush();
        std::thread::yield_now();
    }
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        correct,
        "the original lane read request must survive refusal and incidental publication until explicit cancellation"
    );
}

#[test]
fn final_global_worker_drop_cancels_its_actual_ready_lane_read_without_a_runner_tick() {
    let observed = Arc::new(std::sync::Mutex::new(None));
    let result = observed.clone();
    lanes::merge::with_original_lane_merge_fixture(move |chain, stores, certify, [first, _]| {
        certify(1, chain.height(), vec![first]);
        let budget = chain.state().ivm_execution_budget();
        let epoch = crossbeam_epoch::pin();
        let incarnation = chain
            .state()
            .view()
            .world()
            .sumeragi_lanes()
            .lane(LaneId::new(2))
            .unwrap()
            .incarnation;
        // Hold the exact source store independently, so this test observes read cleanup,
        // not a wholesale registry/fixture destructor that could conceal a retained slot.
        let store = stores.store(LaneId::new(2), &incarnation).unwrap();
        let mut original = None;
        publication_tests::with_worker_chain(
            chain,
            ConsensusMode::Permissioned,
            stores.clone(),
            |_chain, worker, _blocks, _events| {
                let height = worker.applied.0 + 1;
                refuse_actual_batch(worker, height, 0);
                original = Some(
                    worker
                        .proposal_reads
                        .as_ref()
                        .unwrap()
                        .1
                        .observation_for_test(),
                );
            },
        );
        let original = original.unwrap();
        let cancelled = original.cancelled();
        // The only source owner left is the actual registry/fixture. An admitted read of
        // another height must no longer be blocked by the abandoned proposal batch.
        let no_pending = !store.has_pending_work_for_test();
        let held = budget.reserved_bytes();
        drop(original);
        assert_eq!(
            budget.reserved_bytes(),
            held - ProposalReadScope::admission_bytes()
        );
        drop((store, epoch));
        *result.lock().unwrap() = Some((budget, cancelled && no_pending));
    });
    let (budget, correct) = observed.lock().unwrap().take().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while budget.reserved_bytes() != 0 && std::time::Instant::now() < deadline {
        crossbeam_epoch::pin().flush();
        std::thread::yield_now();
    }
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        correct,
        "final global worker drop must cancel its original lane read without successor traffic"
    );
}

#[test]
fn successful_parent_commit_cancels_proposal_read_only_after_original_publication() {
    let observed = Arc::new(std::sync::Mutex::new(None));
    let result = observed.clone();
    lanes::merge::with_original_lane_merge_fixture(move |chain, stores, certify, [first, _]| {
        certify(1, chain.height(), vec![first]);
        publication_tests::with_worker_chain(
            chain,
            ConsensusMode::Permissioned,
            stores,
            |chain, worker, blocks, _events| {
                let height = chain.height() + 1;
                refuse_actual_batch(worker, height, 0);
                let original = worker
                    .proposal_reads
                    .as_ref()
                    .unwrap()
                    .1
                    .observation_for_test();
                // This helper assembles its standalone signed transaction directly; it
                // does not steal the refused lane read through another proposal scope.
                let (block, qc) = publication_tests::executed(chain, worker);
                worker.prepare(&block, &qc).unwrap();
                blocks.append(&block, &qc).unwrap();
                assert!(!original.cancelled());
                let state = worker.state;
                let refused =
                    state.with_publication_blocked_for_test(|| worker.commit(&block, &qc));
                assert!(matches!(refused, Err(PublicationError::Deferred(_))));
                assert!(
                    !original.cancelled(),
                    "pending physical publication is not a committed parent"
                );
                worker.commit(&block, &qc).unwrap();
                assert_eq!(worker.applied, (height, qc.block_hash));
                assert!(original.cancelled());
                assert!(worker.proposal_reads.is_none());
                *result.lock().unwrap() = Some(state.ivm_execution_budget());
            },
        );
    });
    let budget = observed.lock().unwrap().take().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while budget.reserved_bytes() != 0 && std::time::Instant::now() < deadline {
        crossbeam_epoch::pin().flush();
        std::thread::yield_now();
    }
    assert_eq!(budget.reserved_bytes(), 0);
}
