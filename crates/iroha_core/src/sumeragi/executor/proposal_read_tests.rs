//! Original global requests own lane read refusal across retries and explicit lifecycle changes.

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

/// Refuse only the actual incoming merge read; all source authority and native storage stay real.
struct IncomingReadRefusal {
    stores: Arc<lanes::registry::LaneStores>,
    armed: std::sync::atomic::AtomicBool,
    refused: std::sync::atomic::AtomicBool,
}

impl lanes::merge::LaneBlockSource for IncomingReadRefusal {
    fn tip(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
    ) -> Result<Option<u64>, crate::execution_attempt::ExecutionAttemptError<std::io::Error>> {
        self.stores.tip(lane, incarnation)
    }

    fn block(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
    ) -> Result<
        Option<lanes::merge::CommittedLaneBlock>,
        crate::execution_attempt::ExecutionAttemptError<std::io::Error>,
    > {
        self.stores.block(lane, incarnation, height)
    }
    fn execution_wait_for(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        timeout: Duration,
        request: &crate::sumeragi::lanes::ProposalReadScope,
    ) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<std::io::Error>> {
        self.stores
            .execution_wait_for(lane, incarnation, height, timeout, request)
    }
    fn execution_block(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        request: &crate::sumeragi::lanes::ProposalReadScope,
    ) -> Result<
        Option<lanes::merge::CommittedLaneBlock>,
        crate::execution_attempt::ExecutionAttemptError<std::io::Error>,
    > {
        if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            let mut rows = Vec::<TransactionEntrypoint>::new();
            rows.try_reserve(1).unwrap();
            let layout =
                std::alloc::Layout::array::<TransactionEntrypoint>(rows.capacity()).unwrap();
            drop(rows);
            let (result, refused) =
                crate::test_allocations::refuse_one_layout_during(layout, || {
                    self.stores
                        .execution_block(lane, incarnation, height, request)
                });
            self.refused
                .store(refused, std::sync::atomic::Ordering::SeqCst);
            result
        } else {
            self.stores
                .execution_block(lane, incarnation, height, request)
        }
    }

    fn proposal_block(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        request: &ProposalReadScope,
    ) -> Result<
        Option<lanes::merge::CommittedLaneBlock>,
        crate::execution_attempt::ExecutionAttemptError<std::io::Error>,
    > {
        self.stores
            .proposal_block(lane, incarnation, height, request)
    }

    fn release_cancelled_proposal_reads(&self) {
        self.stores.release_cancelled_proposal_reads();
    }

    fn wait_for(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        timeout: Duration,
    ) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<std::io::Error>> {
        self.stores.wait_for(lane, incarnation, height, timeout)
    }
}

#[test]
fn discarded_incoming_execution_releases_its_original_lane_read_after_keep_exclusion() {
    let observed = Arc::new(std::sync::Mutex::new(None));
    let result = observed.clone();
    lanes::merge::with_original_lane_merge_fixture(move |chain, stores, certify, [first, _]| {
        let lane_hash = certify(1, chain.height(), vec![first]);
        let source = Arc::new(IncomingReadRefusal {
            stores: stores.clone(),
            armed: std::sync::atomic::AtomicBool::new(true),
            refused: std::sync::atomic::AtomicBool::new(false),
        });
        publication_tests::with_worker_chain(
            chain,
            ConsensusMode::Permissioned,
            source.clone(),
            |chain, worker, _blocks, events| {
                let _epoch = crossbeam_epoch::pin();
                let budget = worker.state.ivm_execution_budget();
                let height = chain.height() + 1;
                let incarnation = worker
                    .state
                    .view()
                    .world()
                    .sumeragi_lanes()
                    .lane(LaneId::new(2))
                    .unwrap()
                    .incarnation;
                let store = stores.store(LaneId::new(2), &incarnation).unwrap();
                assert!(!store.has_pending_work_for_test());
                let proposal = chain.proposal(None, Vec::new());
                let merge = &proposal
                    .lane_merge()
                    .expect("actual certified lane work")
                    .merges[0];
                assert_eq!((merge.lane, merge.from, merge.to), (LaneId::new(2), 1, 1));
                assert_eq!(merge.tip_hash, lane_hash.0);
                chain.set_execution_time(proposal.header().creation_time());
                let bytes = payload::encode(&proposal).unwrap();
                drop(proposal);
                let scheduled = worker.scheduled(height).unwrap().height_config().unwrap();
                let parent = chain.committed(chain.height());
                let body = chain.author_payload(
                    iroha_sumeragi::message::BlockHeader {
                        instance: chain.instance(),
                        epoch: scheduled.epoch.id,
                        height,
                        origin_view: 0,
                        parent_hash: parent.core_hash(),
                        parent_result: parent.result(),
                        payload_hash: iroha_sumeragi::preimage::payload_hash(
                            &**worker.context.crypto.as_ref().unwrap(),
                            &bytes,
                        ),
                        payload_len: u32::try_from(bytes.len()).unwrap(),
                        availability_digest: Hash32::ZERO,
                        proposer: 0,
                        skipped_leaders: Vec::new(),
                        control_witness: ControlWitness::empty(),
                    },
                    bytes,
                );
                let hash = body.hash(&**worker.context.crypto.as_ref().unwrap());
                assert!(body.admitted_to(&budget));
                // Finish the genuine original global decoding before injecting refusal in the
                // separate actual lane read. Execution still rechecks its ordinary authority.
                drop(worker.recover_proposal_admission(&body).unwrap());
                let execution = worker.execute(&body, hash, false);
                assert!(source.refused.load(std::sync::atomic::Ordering::SeqCst));
                assert!(
                    matches!(execution, Err(PublicationError::Deferred(_))),
                    "the actual incoming lane read must refuse locally: {execution:?}"
                );
                drop(execution);
                assert!(
                    worker.proposal_reads.is_none(),
                    "no local build request owns this read"
                );
                assert!(store.has_pending_work_for_test());
                assert!(worker.live.is_none());
                assert!(worker.finishing.is_none());
                assert!(worker.recovery.is_none());
                assert!(!worker.results.contains_key(&hash));
                assert!(events.try_recv().is_err());
                let original = worker.signature_decode.as_ref().unwrap();
                assert_eq!(original.source, body);
                let decoded = std::ptr::from_ref(original.decoded.as_ref().unwrap());
                let charged = budget.reserved_bytes();
                source
                    .armed
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                source
                    .refused
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                let retry = worker.execute(&body, hash, false);
                assert!(source.refused.load(std::sync::atomic::Ordering::SeqCst));
                assert!(matches!(retry, Err(PublicationError::Deferred(_))));
                drop(retry);
                assert_eq!(
                    std::ptr::from_ref(
                        worker
                            .signature_decode
                            .as_ref()
                            .unwrap()
                            .decoded
                            .as_ref()
                            .unwrap()
                    ),
                    decoded
                );
                assert_eq!(budget.reserved_bytes(), charged);
                assert!(store.has_pending_work_for_test());

                // This is the native boundary of DiscardExecution. A high-PQC keep entry
                // retains the exact original attempt; exclusion withdraws the pending job.
                worker.discard(height, &[hash]);
                assert_eq!(
                    std::ptr::from_ref(
                        worker
                            .signature_decode
                            .as_ref()
                            .unwrap()
                            .decoded
                            .as_ref()
                            .unwrap()
                    ),
                    decoded
                );
                assert!(store.has_pending_work_for_test());
                assert_eq!(budget.reserved_bytes(), charged);
                worker.discard(height, &[]);
                let decoded_retired = worker.signature_decode.is_none();
                let read_retired = !store.has_pending_work_for_test();
                assert_eq!(worker.applied.0, chain.height());
                assert!(worker.live.is_none());
                assert!(worker.recovery.is_none());
                assert!(events.try_recv().is_err());

                // Record the no-successor verdict first. Complete any still-retained native
                // source for diagnostic cleanup, then let every real worker/fixture owner end.
                let replay = stores
                    .block(LaneId::new(2), &incarnation, 1)
                    .unwrap()
                    .unwrap();
                assert_eq!(replay.block_hash, lane_hash);
                assert!(replay.batch.is_some());
                assert!(!store.has_pending_work_for_test());
                drop((replay, body, store));
                *result.lock().unwrap() = Some((budget, decoded_retired, read_retired));
            },
        );
    });
    let (budget, decoded_retired, read_retired) = observed.lock().unwrap().take().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while budget.reserved_bytes() != 0 && std::time::Instant::now() < deadline {
        crossbeam_epoch::pin().flush();
        std::thread::yield_now();
    }
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        read_retired,
        "discarded incoming execution must release its own actual lane read without successor traffic"
    );
    assert!(
        decoded_retired,
        "discarded incoming execution must release its original signed decode after keep exclusion"
    );
}

#[test]
fn authenticated_incoming_execution_moves_the_original_local_lane_request_without_reopening() {
    let observed = Arc::new(std::sync::Mutex::new(None));
    let result = observed.clone();
    lanes::merge::with_original_lane_merge_fixture(move |chain, stores, certify, [first, _]| {
        let lane_hash = certify(1, chain.height(), vec![first]);
        let source = Arc::new(IncomingReadRefusal {
            stores: stores.clone(),
            armed: std::sync::atomic::AtomicBool::new(true),
            refused: std::sync::atomic::AtomicBool::new(false),
        });
        publication_tests::with_worker_chain(
            chain,
            ConsensusMode::Permissioned,
            source.clone(),
            |chain, worker, _blocks, events| {
                let _epoch = crossbeam_epoch::pin();
                let budget = worker.state.ivm_execution_budget();
                let height = chain.height() + 1;
                let incarnation = worker
                    .state
                    .view()
                    .world()
                    .sumeragi_lanes()
                    .lane(LaneId::new(2))
                    .unwrap()
                    .incarnation;
                let store = stores.store(LaneId::new(2), &incarnation).unwrap();
                let proposal = chain.proposal(None, Vec::new());
                let merge = &proposal
                    .lane_merge()
                    .expect("actual certified lane work")
                    .merges[0];
                assert_eq!((merge.lane, merge.from, merge.to), (LaneId::new(2), 1, 1));
                assert_eq!(merge.tip_hash, lane_hash.0);
                chain.set_execution_time(proposal.header().creation_time());
                let bytes = payload::encode(&proposal).unwrap();
                drop(proposal);
                let scheduled = worker.scheduled(height).unwrap().height_config().unwrap();
                let parent = chain.committed(chain.height());
                let body = chain.author_payload(
                    iroha_sumeragi::message::BlockHeader {
                        instance: chain.instance(),
                        epoch: scheduled.epoch.id,
                        height,
                        origin_view: 0,
                        parent_hash: parent.core_hash(),
                        parent_result: parent.result(),
                        payload_hash: iroha_sumeragi::preimage::payload_hash(
                            &**worker.context.crypto.as_ref().unwrap(),
                            &bytes,
                        ),
                        payload_len: u32::try_from(bytes.len()).unwrap(),
                        availability_digest: Hash32::ZERO,
                        proposer: 0,
                        skipped_leaders: Vec::new(),
                        control_witness: ControlWitness::empty(),
                    },
                    bytes,
                );
                let hash = body.hash(&**worker.context.crypto.as_ref().unwrap());
                assert!(body.admitted_to(&budget));
                // Finish the genuine original global decoding before injecting refusal in the
                // separate actual lane read. Execution still rechecks its ordinary authority.
                drop(worker.recover_proposal_admission(&body).unwrap());

                // Author the incoming candidate before local refusal: its helper may read
                // lane history, which must not promote the pending request in this control.
                refuse_actual_batch(worker, height, 0);
                let original = worker
                    .proposal_reads
                    .as_ref()
                    .unwrap()
                    .1
                    .observation_for_test();
                let execution = worker.execute(&body, hash, false);
                let transferred = source.refused.load(std::sync::atomic::Ordering::SeqCst)
                    && matches!(execution, Err(PublicationError::Deferred(_)))
                    && worker.proposal_reads.is_none()
                    && worker.incoming_lane_reads.as_ref().is_some_and(|incoming| {
                        incoming.instance == body.header().instance
                            && incoming.height == body.header().height
                            && incoming.view == body.header().origin_view
                            && incoming.block_hash == hash
                            && original.matches(&incoming.scope)
                    })
                    && !original.cancelled();
                // The fixed cancellation key owns no duplicate body/header/source graph.
                // Complete authority remains in the original authenticated decoder owner.
                assert_eq!(worker.signature_decode.as_ref().unwrap().source, body);
                drop(execution);
                assert!(store.has_pending_work_for_test());
                assert!(events.try_recv().is_err());
                worker.discard(height, &[]);
                // Mutation diagnostic cleanup cancels both owners after recording the verdict.
                worker.cancel_proposal_reads();
                worker.cancel_incoming_lane_reads();
                assert!(original.cancelled());
                assert!(!store.has_pending_work_for_test());
                drop((original, body, store));
                *result.lock().unwrap() = Some((budget, transferred));
            },
        );
    });
    let (budget, transferred) = observed.lock().unwrap().take().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while budget.reserved_bytes() != 0 && std::time::Instant::now() < deadline {
        crossbeam_epoch::pin().flush();
        std::thread::yield_now();
    }
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        transferred,
        "authenticated incoming execution must move the exact original local lane request and continue its native source"
    );
}
