//! Old-API causal terminal AMX target retry, through the genuine public archive/proof owner.

use std::sync::{Arc, Mutex};

use iroha_allocation::AllocationRefusal;
use iroha_data_model::sumeragi_amx::AmxRecordKind;

use super::issuer_tests::committed_source;
use crate::{
    execution_attempt::ExecutionAttemptError,
    query::native_receipts::{NativeAmxRecordProofErrorV1 as Error, amx_record_proof},
    sumeragi::certified_chain::{CertifiedChain, relation_counts},
};

#[test]
fn terminal_amx_retry_does_not_repeat_completed_target_after_gap_refusal() {
    let (mut chain, tx, _) = committed_source(1);
    chain.commit_at(3_000, Vec::new());
    chain.commit_at(4_000, Vec::new());
    let budget = chain.state().ivm_execution_budget();
    let decoder = norito::core::DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 128),
        &budget,
    )
    .unwrap();
    let loan = Arc::new(Mutex::new(None));
    let view = chain.state().view();
    let mut read = amx_record_proof(&view, 4, AmxRecordKind::Decision, tx);
    read.chain = Some(decoder.with(|| CertifiedChain::new(&view)).unwrap());
    let held = Arc::clone(&loan);
    let original_pool = budget.clone();
    read.chain
        .as_mut()
        .unwrap()
        .probe_terminal_target_once(move |_| {
            *held.lock().unwrap() = Some(
                original_pool
                    .try_reserve_bytes(original_pool.limit_bytes() - original_pool.reserved_bytes())
                    .unwrap(),
            );
            assert_eq!(original_pool.reserved_bytes(), original_pool.limit_bytes(),
                "real predecessor pressure occupies the original pool while the decoded target is live");
        })
        .unwrap();
    let (refused, counts) = relation_counts::measure(|| decoder.with(|| read.poll()));
    let cause = refused.unwrap_err();
    assert!(
        matches!(cause, Error::Chain(ExecutionAttemptError::Deferred(ref local))
        if matches!(local.allocation_refusal(), Some(AllocationRefusal::Capacity { .. }))),
        "genuine later predecessor refusal must remain original typed Capacity: {cause:?}"
    );
    assert_eq!(counts.frames, [1, 4]);
    assert!(counts.qcs.is_empty());
    let consumed = decoder.consumed_allocated_bytes();
    drop(loan.lock().unwrap().take());
    let (proof, resumed) = relation_counts::measure(|| decoder.with(|| read.complete()));
    let proof = proof.unwrap().unwrap();
    assert!(proof.belongs_to(&budget));
    assert!(decoder.consumed_allocated_bytes() >= consumed);
    assert_eq!(resumed.qcs, [2, 3, 4]);
    assert!(
        !resumed.frames.contains(&4),
        "completed terminal target must not be decoded again after predecessor refusal"
    );
    assert_eq!(resumed.frames, [2, 3]);
}
