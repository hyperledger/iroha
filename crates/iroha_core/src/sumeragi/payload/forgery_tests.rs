//! Genuine native certificate rechecks preserve input ownership and refuse stale claims.
use super::*;
use crate::{
    smartcontracts::isi::sccp::forgery::tests::{active_member_chain, future, original},
    sumeragi::test_chain::CertifiedTestChain,
};
use iroha_data_model::{
    isi::sccp::SubmitSccpForgeryEvidenceV1,
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
use mv::storage::StorageReadOnly as _;

fn carrier(
    chain: &CertifiedTestChain,
    evidence: SubmitSccpForgeryEvidenceV1,
    created_ms: u64,
) -> AcceptedTransaction<'static> {
    let mut builder = TransactionBuilder::new(
        chain.network_id(),
        ALICE_ID.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([evidence]);
    builder.set_creation_time(Duration::from_millis(created_ms));
    let (_, clock) = TimeSource::new_mock(Duration::from_millis(created_ms + 1));
    AcceptedTransaction::accept_with_time_source(
        builder.sign(ALICE_KEYPAIR.private_key()),
        &chain.network_id(),
        Duration::from_secs(1),
        chain.state().view().world().parameters().transaction(),
        &iroha_config::parameters::actual::Crypto::default(),
        &clock,
    )
    .unwrap()
}

#[test]
fn valid_forgery_keeps_exact_original_inputs_and_uses_canonical_candidate_time() {
    let (chain, keys) = active_member_chain();
    let view = chain.state().view();
    let parent = view.latest_block().unwrap().unwrap();
    let assembly = Assembly {
        parent: &parent,
        view: 4,
        cadence: Duration::from_millis(1_000),
        proposed_time: std::time::Duration::ZERO,
    };
    let evidence = future(&chain, &keys);
    let mut selected = vec![carrier(&chain, evidence, 3_100)];
    let hash = selected[0].hash_as_entrypoint();
    let encoded = selected[0].entrypoint_bytes();
    let budget = view.execution_budget();
    let baseline = budget.reserved_bytes();
    recheck_sccp_forgery_for_proposal(&view, assembly, &mut selected, &MergeProposal::default())
        .unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].hash_as_entrypoint(), hash);
    assert!(std::sync::Arc::ptr_eq(
        &encoded,
        &selected[0].entrypoint_bytes()
    ));
    assert_eq!(budget.reserved_bytes(), baseline);
    let proposal = assemble(chain.state(), assembly, &selected).unwrap();
    assert_eq!(
        proposal.header().creation_time(),
        Duration::from_millis(3_101)
    );
    assert_eq!(proposal.external_entrypoints_slice()[0].hash(), hash);
    assert_eq!(chain.height(), 2);
}

#[test]
fn genuine_after_tip_advance_is_dropped_before_any_empty_proposal() {
    let (mut chain, _) = active_member_chain();
    let state = std::sync::Arc::clone(chain.state());
    let lagging = state.view();
    let old_parent = lagging.latest_block().unwrap().unwrap();
    chain.commit_at(3_000, Vec::new());
    let evidence = original(&chain);
    let mut selected = vec![carrier(&chain, evidence, 3_100)];
    let before = selected[0].hash_as_entrypoint();
    recheck_sccp_forgery_for_proposal(
        &lagging,
        Assembly {
            parent: &old_parent,
            view: 0,
            cadence: Duration::from_millis(1_000),
            proposed_time: std::time::Duration::ZERO,
        },
        &mut selected,
        &MergeProposal::default(),
    )
    .unwrap();
    assert_eq!(selected[0].hash_as_entrypoint(), before);
    let current = state.view();
    let parent = current.latest_block().unwrap().unwrap();
    let assembly = Assembly {
        parent: &parent,
        view: 0,
        cadence: Duration::from_millis(1_000),
        proposed_time: std::time::Duration::ZERO,
    };
    recheck_sccp_forgery_for_proposal(&current, assembly, &mut selected, &MergeProposal::default())
        .unwrap();
    assert!(selected.is_empty());
    assert!(matches!(
        assemble(&state, assembly, &selected),
        Err(PayloadError::EmptyBlock)
    ));
    assert_eq!(chain.height(), 3);
}

#[test]
fn malformed_signature_drops_only_its_carrier_and_quota_keeps_fifo_order() {
    let (chain, keys) = active_member_chain();
    let view = chain.state().view();
    let parent = view.latest_block().unwrap().unwrap();
    let assembly = Assembly {
        parent: &parent,
        view: 0,
        cadence: Duration::from_millis(1_000),
        proposed_time: std::time::Duration::ZERO,
    };
    let evidence = future(&chain, &keys);
    let mut malformed = evidence.clone();
    malformed.aggregate_signature[0] ^= 1;
    let mut selected = vec![
        carrier(&chain, malformed, 2_100),
        carrier(&chain, evidence.clone(), 2_101),
        carrier(&chain, evidence, 2_102),
    ];
    let retained = selected[1].hash_as_entrypoint();
    recheck_sccp_forgery_for_proposal(&view, assembly, &mut selected, &MergeProposal::default())
        .unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].hash_as_entrypoint(), retained);
    assert_eq!(chain.height(), 2);
}

#[test]
fn original_pool_refusal_retains_selected_work_and_retries_after_release() {
    let (chain, keys) = active_member_chain();
    let view = chain.state().view();
    let parent = view.latest_block().unwrap().unwrap();
    let assembly = Assembly {
        parent: &parent,
        view: 0,
        cadence: Duration::from_millis(1_000),
        proposed_time: std::time::Duration::ZERO,
    };
    let mut selected = vec![carrier(&chain, future(&chain, &keys), 2_100)];
    let hash = selected[0].hash_as_entrypoint();
    let budget = view.execution_budget();
    let baseline = budget.reserved_bytes();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - baseline)
        .unwrap();
    let error = recheck_sccp_forgery_for_proposal(
        &view,
        assembly,
        &mut selected,
        &MergeProposal::default(),
    )
    .unwrap_err();
    let PayloadError::SccpForgeryPreparation(original) = error else {
        panic!("original local resource failure must remain typed: {error:?}");
    };
    assert!(
        original.release_wait().is_some(),
        "actual finite pool refusal has its release owner"
    );
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].hash_as_entrypoint(), hash);
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    drop(occupied);
    recheck_sccp_forgery_for_proposal(&view, assembly, &mut selected, &MergeProposal::default())
        .unwrap();
    assert_eq!(selected[0].hash_as_entrypoint(), hash);
    assert_eq!(budget.reserved_bytes(), baseline);
    assert_eq!(chain.height(), 2);
}

#[test]
fn foreign_parent_is_local_recovery_and_never_drops_signed_input() {
    let (chain, keys) = active_member_chain();
    let view = chain.state().view();
    let parent = view.latest_block().unwrap().unwrap();
    let mut changed = parent.header();
    changed.creation_time_ms += 1;
    let foreign = iroha_data_model::block::builder::BlockBuilder::new(changed)
        .build(iroha_data_model::block::BlockSignatures::default());
    let mut selected = vec![carrier(&chain, future(&chain, &keys), 2_100)];
    let hash = selected[0].hash_as_entrypoint();
    let result = recheck_sccp_forgery_for_proposal(
        &view,
        Assembly {
            parent: &foreign,
            view: 0,
            cadence: Duration::from_millis(1_000),
            proposed_time: std::time::Duration::ZERO,
        },
        &mut selected,
        &MergeProposal::default(),
    );
    assert!(matches!(
        result,
        Err(PayloadError::SccpForgeryPreparation(
            crate::state::StateStorageAdmissionError::SccpForgery(
                crate::state::sccp_forgery_custody::ForgeryStorageError::Invalid
            )
        ))
    ));
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].hash_as_entrypoint(), hash);
}

fn on_selection_stack(name: &str, work: impl FnOnce() + Send + 'static) {
    let worker = crate::sumeragi::threads::sumeragi_thread_builder(name)
        .spawn(work)
        .expect("spawn actual native selection fixture");
    if let Err(error) = worker.join() {
        std::panic::resume_unwind(error);
    }
}

fn queued_genuine_then_future(
    maximum: std::num::NonZeroU64,
) -> (
    CertifiedTestChain,
    std::sync::Arc<Queue>,
    AcceptedTransaction<'static>,
    AcceptedTransaction<'static>,
) {
    use crate::smartcontracts::isi::sccp::forgery::tests::active_member_chain_with_max_transactions;
    let (mut chain, keys) = active_member_chain_with_max_transactions(maximum);
    let state = std::sync::Arc::clone(chain.state());
    // Retain a genuine earlier committed view. The first QC is E2 relative to this
    // actual source, then is genuine at the next source. No retained header is edited.
    let lagging = state.view();
    chain.commit_at(3_000, Vec::new());
    let genuine_now = carrier(&chain, original(&chain), 3_100);
    let still_future = carrier(&chain, future(&chain, &keys), 3_101);
    // Clone shares an initialized canonical-byte Arc; an empty OnceLock is cloned
    // empty. Materialize both originals before the queue takes its owned clones.
    let _ = genuine_now.entrypoint_bytes();
    let _ = still_future.entrypoint_bytes();
    let (_, clock) = TimeSource::new_mock(Duration::from_millis(3_102));
    let queue = std::sync::Arc::new(Queue::test(
        iroha_config::parameters::actual::Queue::default(),
        &clock,
    ));
    queue
        .push(genuine_now.clone(), lagging)
        .expect("actual earlier source admits E2");
    queue
        .push(still_future.clone(), state.view())
        .expect("current source admits distinct E2");
    assert_eq!((queue.active_len(), queue.queued_len()), (2, 2));
    (chain, queue, genuine_now, still_future)
}

#[test]
fn stale_fifo_forgery_spends_no_count_bytes_or_quota_and_retains_original_lease() {
    on_selection_stack("sccp-select-stale", || {
        let _retirement_pin = crossbeam_epoch::pin();
        let (chain, queue, outdated, valid) = queued_genuine_then_future(std::num::NonZeroU64::MIN);
        let state = chain.state();
        let view = state.view();
        assert_eq!(
            view.world().parameters().block().max_transactions().get(),
            1
        );
        let budget = valid.encoded_len();
        assert!(outdated.encoded_len() <= budget, "first row fits by itself");
        let original_bytes = valid.entrypoint_bytes();
        let resident = queue.retained_bytes();
        let hashes = [outdated.hash_as_entrypoint(), valid.hash_as_entrypoint()];
        let snapshot = queue
            .bounded_pending_snapshot(&view, MAX_QUEUE_SCAN)
            .unwrap();
        assert_eq!(
            snapshot
                .iter()
                .map(AcceptedTransaction::hash_as_entrypoint)
                .collect::<Vec<_>>(),
            hashes
        );
        assert!(std::sync::Arc::ptr_eq(
            &outdated.entrypoint_bytes(),
            &snapshot[0].entrypoint_bytes()
        ));
        assert!(std::sync::Arc::ptr_eq(
            &original_bytes,
            &snapshot[1].entrypoint_bytes()
        ));
        drop(snapshot);
        let parent = view.latest_block().unwrap().unwrap();
        for _ in 0..2 {
            let selection = queue
                .begin_pending_payload_selection(state, state.state_view_generation())
                .unwrap();
            let mut selected = select(
                &view,
                &queue,
                budget,
                &MergeProposal::default(),
                Duration::from_millis(3_102),
            )
            .unwrap();
            assert_eq!(
                selected.len(),
                1,
                "later valid evidence is reachable with one slot"
            );
            assert_eq!(selected[0].hash_as_entrypoint(), hashes[1]);
            assert!(std::sync::Arc::ptr_eq(
                &original_bytes,
                &selected[0].entrypoint_bytes()
            ));
            let assembly = Assembly {
                parent: &parent,
                view: 0,
                cadence: Duration::from_millis(1_000),
                proposed_time: std::time::Duration::ZERO,
            };
            recheck_sccp_forgery_for_proposal(
                &view,
                assembly,
                &mut selected,
                &MergeProposal::default(),
            )
            .unwrap();
            let lease = queue
                .capture_pending_payload_lease(
                    state,
                    selection,
                    &view,
                    &selected,
                    &view.execution_budget(),
                )
                .unwrap()
                .unwrap();
            assert!(queue.pending_payload_lease_is_current(state, &view, &lease));
            assert_eq!(selected[0].hash_as_entrypoint(), hashes[1]);
            assert_eq!(queue.retained_bytes(), resident);
            assert_eq!((queue.active_len(), queue.queued_len()), (2, 2));
            for hash in hashes {
                assert!(queue.contains_entrypoint_hash(hash));
            }
        }
        assert!(
            select(
                &view,
                &queue,
                budget - 1,
                &MergeProposal::default(),
                Duration::from_millis(3_102)
            )
            .unwrap()
            .is_empty()
        );
        assert_eq!(
            chain.height(),
            3,
            "selection publishes neither a block nor an offence"
        );
        assert!(view.world().sccp_forgery_offences().is_empty());
    });
}

#[test]
fn proposal_selection_local_refusal_never_retires_queued_claims_and_retries_original_pool() {
    on_selection_stack("sccp-select-resource", || {
        let _retirement_pin = crossbeam_epoch::pin();
        let (chain, queue, outdated, valid) = queued_genuine_then_future(std::num::NonZeroU64::MIN);
        let view = chain.state().view();
        let parent = view.latest_block().unwrap().unwrap();
        let pool = view.execution_budget();
        let baseline = pool.reserved_bytes();
        let occupied = pool
            .try_reserve_bytes(pool.limit_bytes() - baseline)
            .unwrap();
        let resident = queue.retained_bytes();
        let error = select(
            &view,
            &queue,
            valid.encoded_len(),
            &MergeProposal::default(),
            Duration::from_millis(3_102),
        )
        .unwrap_err();
        match error {
            PayloadError::SccpForgeryPreparation(original) => {
                assert!(original.release_wait().is_some())
            }
            PayloadError::RoutingDeferred(original) => {
                assert!(matches!(
                    original.allocation_refusal(),
                    Some(iroha_allocation::AllocationRefusal::Capacity { .. })
                ));
            }
            other => panic!("original local pool owner was erased: {other:?}"),
        }
        assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
        assert_eq!(queue.retained_bytes(), resident);
        assert_eq!((queue.active_len(), queue.queued_len()), (2, 2));
        assert!(queue.contains_entrypoint_hash(outdated.hash_as_entrypoint()));
        assert!(queue.contains_entrypoint_hash(valid.hash_as_entrypoint()));
        drop(occupied);
        let selected = select(
            &view,
            &queue,
            valid.encoded_len(),
            &MergeProposal::default(),
            Duration::from_millis(3_102),
        )
        .unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].hash_as_entrypoint(), valid.hash_as_entrypoint());
        assert_eq!(pool.reserved_bytes(), baseline);
        assert_eq!(parent.header().height().get(), 3);
        assert!(view.world().sccp_forgery_offences().is_empty());
    });
}

#[test]
fn current_parent_selection_keeps_exact_one_valid_forgery() {
    on_selection_stack("sccp-select-quota", || {
        use crate::smartcontracts::isi::sccp::forgery::tests::{change_header, resign};
        let (chain, keys) = active_member_chain();
        let mut second = future(&chain, &keys);
        change_header(&mut second, |header| header.height += 1);
        resign(&mut second, &keys, chain.instance());
        let first = carrier(&chain, future(&chain, &keys), 2_100);
        let second = carrier(&chain, second, 2_101);
        let (_, clock) = TimeSource::new_mock(Duration::from_millis(2_102));
        let queue = std::sync::Arc::new(Queue::test(
            iroha_config::parameters::actual::Queue::default(),
            &clock,
        ));
        queue.push(first.clone(), chain.state().view()).unwrap();
        queue.push(second.clone(), chain.state().view()).unwrap();
        let view = chain.state().view();
        let snapshot = queue
            .bounded_pending_snapshot(&view, MAX_QUEUE_SCAN)
            .unwrap();
        assert_eq!(snapshot.len(), 2, "snapshot does not spend forgery quota");
        let selected = select(
            &view,
            &queue,
            first.encoded_len() + second.encoded_len(),
            &MergeProposal::default(),
            clock.now(),
        )
        .unwrap();
        assert_eq!(
            selected.len(),
            1,
            "verified evidence still obeys one-per-block quota"
        );
        assert_eq!(selected[0].hash_as_entrypoint(), first.hash_as_entrypoint());
        assert!(queue.contains_entrypoint_hash(second.hash_as_entrypoint()));
        assert!(view.world().sccp_forgery_offences().is_empty());
    });
}

#[test]
fn only_now_genuine_queued_evidence_cannot_authorize_an_empty_proposal() {
    on_selection_stack("sccp-select-empty", || {
        let (mut chain, _) = active_member_chain();
        let state = std::sync::Arc::clone(chain.state());
        let lagging = state.view();
        chain.commit_at(3_000, Vec::new());
        let outdated = carrier(&chain, original(&chain), 3_100);
        let hash = outdated.hash_as_entrypoint();
        let (_, clock) = TimeSource::new_mock(Duration::from_millis(3_101));
        let queue = std::sync::Arc::new(Queue::test(
            iroha_config::parameters::actual::Queue::default(),
            &clock,
        ));
        queue.push(outdated, lagging).unwrap();
        let view = state.view();
        let selected = select(
            &view,
            &queue,
            1 << 20,
            &MergeProposal::default(),
            clock.now(),
        )
        .unwrap();
        assert!(selected.is_empty());
        let parent = view.latest_block().unwrap().unwrap();
        assert!(matches!(
            assemble(
                &state,
                Assembly {
                    parent: &parent,
                    view: 0,
                    cadence: Duration::from_millis(1_000),
                    proposed_time: std::time::Duration::ZERO,
                },
                &selected
            ),
            Err(PayloadError::EmptyBlock)
        ));
        assert_eq!((queue.active_len(), queue.queued_len()), (1, 1));
        assert!(queue.contains_entrypoint_hash(hash));
        assert_eq!(chain.height(), 3);
        assert!(view.world().sccp_forgery_offences().is_empty());
    });
}

#[test]
fn physical_pairing_refusal_preserves_selected_input_and_publication_cause() {
    let (chain, keys) = active_member_chain();
    let view = chain.state().view();
    let parent = view.latest_block().unwrap().unwrap();
    let assembly = Assembly {
        parent: &parent,
        view: 0,
        cadence: Duration::from_millis(1_000),
        proposed_time: Duration::ZERO,
    };
    let mut selected = vec![carrier(&chain, future(&chain, &keys), 2_100)];
    let hash = selected[0].hash_as_entrypoint();
    let encoded = selected[0].entrypoint_bytes();
    let pool = view.execution_budget();
    let before = pool.reserved_bytes();
    let layout = iroha_crypto::bls::consensus::ConsensusAggregateScratch::<()>::backing_layout();
    let (result, observed) = crate::test_allocations::refuse_one_layout_during(layout, || {
        recheck_sccp_forgery_for_proposal(&view, assembly, &mut selected, &MergeProposal::default())
    });
    assert!(observed, "actual proposer pairing allocation was refused");
    let error = result.unwrap_err();
    assert!(matches!(&error, PayloadError::SccpForgeryDeferred(_)));
    let PayloadError::SccpForgeryDeferred(original) = error else {
        unreachable!("asserted typed pairing refusal");
    };
    assert!(original.allocation_refusal().is_none());
    assert!(
        original
            .allocator_refusal()
            .and_then(|cause| cause.vec_reserve_error())
            .is_some_and(|(_, actual)| actual == layout),
        "HC966 SCCP proposer must retain the original physical pairing cause"
    );
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].hash_as_entrypoint(), hash);
    assert!(std::sync::Arc::ptr_eq(
        &encoded,
        &selected[0].entrypoint_bytes()
    ));
    assert_eq!(pool.reserved_bytes(), before);
    recheck_sccp_forgery_for_proposal(&view, assembly, &mut selected, &MergeProposal::default())
        .unwrap();
    assert_eq!(selected[0].hash_as_entrypoint(), hash);
    assert!(std::sync::Arc::ptr_eq(
        &encoded,
        &selected[0].entrypoint_bytes()
    ));
    assert_eq!(pool.reserved_bytes(), before);
    assert_eq!(chain.height(), 2);
}
