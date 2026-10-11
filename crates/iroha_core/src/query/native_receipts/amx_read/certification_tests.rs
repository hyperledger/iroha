//! Genuine terminal AMX proof selection retaining original source/result work through refusal.

use std::sync::{Arc, Mutex};

use iroha_allocation::{AllocationBudget, AllocationRefusal, AllocationReservation};
use iroha_data_model::{
    block::SignedBlock,
    sumeragi_amx::{AmxRecordKind, AmxRecordV1},
};
use norito::core::DecodeBudgetContext;

use super::{NativeAmxRecordProofErrorV1 as Error, issuer_tests::committed_source};
use crate::{
    execution_attempt::ExecutionAttemptError,
    query::native_receipts::amx_record_proof,
    sumeragi::certified_chain::{CertifiedChain, CommittedBlock, relation_counts},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OriginalIdentity {
    receipt: usize,
    body: usize,
    committee: usize,
}
fn identity(original: &CommittedBlock) -> OriginalIdentity {
    let receipt: *const CommittedBlock = original;
    let body: *const SignedBlock = original.block().as_ref();
    OriginalIdentity {
        receipt: receipt.addr(),
        body: body.addr(),
        committee: original
            .commitment()
            .schedule
            .current
            .committee
            .as_ptr()
            .addr(),
    }
}
fn counter(budget: &AllocationBudget) -> DecodeBudgetContext {
    DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 128),
        budget,
    )
    .unwrap()
}
fn occupy(budget: &AllocationBudget) -> AllocationReservation {
    budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap()
}
fn is_capacity(error: &Error) -> bool {
    matches!(error,
        Error::Chain(ExecutionAttemptError::Deferred(local))
            if matches!(local.allocation_refusal(), Some(AllocationRefusal::Capacity { .. }))
    )
}

#[test]
fn terminal_amx_target_survives_original_later_gap_capacity_and_proof_retry() {
    let (mut chain, tx, _) = committed_source(1);
    chain.commit_at(3_000, Vec::new());
    chain.commit_at(4_000, Vec::new());
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let decoder = counter(&budget);
    let loan = Arc::new(Mutex::new(None));
    let observed = Arc::new(Mutex::new(None));
    let view = chain.state().view();
    let mut read = amx_record_proof(&view, 4, AmxRecordKind::Decision, tx);
    read.chain = Some(decoder.with(|| CertifiedChain::new(&view)).unwrap());
    let loan_capture = Arc::clone(&loan);
    let observed_capture = Arc::clone(&observed);
    let original_pool = budget.clone();
    read.chain
        .as_mut()
        .unwrap()
        .probe_terminal_target_once(move |target| {
            *observed_capture.lock().unwrap() = Some(identity(target));
            *loan_capture.lock().unwrap() = Some(occupy(&original_pool));
        })
        .unwrap();
    let (attempt, first) = relation_counts::measure(|| decoder.with(|| read.poll()));
    let cause = attempt.unwrap_err();
    assert!(
        is_capacity(&cause),
        "actual missing-predecessor pool refusal: {cause:?}"
    );
    assert_eq!(first.frames, [1, 4]);
    assert!(first.qcs.is_empty());
    let original = observed.lock().unwrap().unwrap();
    let retained = read
        .chain
        .as_ref()
        .unwrap()
        .terminal_target_for_test()
        .map(identity);
    assert_eq!(
        retained,
        Some(original),
        "terminal AMX selection must retain the exact decoded target across gap refusal"
    );
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    let consumed = decoder.consumed_allocated_bytes();
    let (repeat, repeated) = relation_counts::measure(|| decoder.with(|| read.poll()));
    assert!(is_capacity(&repeat.unwrap_err()));
    assert!(repeated.frames.is_empty() && repeated.qcs.is_empty());
    assert_eq!(
        read.chain
            .as_ref()
            .unwrap()
            .terminal_target_for_test()
            .map(identity),
        Some(original)
    );
    assert!(
        decoder.consumed_allocated_bytes() >= consumed,
        "source metadata work remains cumulative; completed target decoding is not repeated"
    );
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    drop(loan.lock().unwrap().take());
    let (proof, resumed) = relation_counts::measure(|| decoder.with(|| read.complete()));
    let proof = proof
        .unwrap()
        .expect("actual archived Decision from the original expiry witness");
    assert_eq!(resumed.frames, [2, 3]);
    assert_eq!(resumed.qcs, [2, 3, 4]);
    let certified = read.source.as_ref().unwrap().certified.as_ref().unwrap();
    let body: *const SignedBlock = certified.block().as_ref();
    assert_eq!(
        body.addr(),
        original.body,
        "delivery moves the original carrier body handle"
    );
    assert_eq!(
        certified
            .commitment()
            .schedule
            .current
            .committee
            .as_ptr()
            .addr(),
        original.committee,
        "delivery moves the original target result graph rather than recopying it"
    );
    assert!(proof.belongs_to(&budget));
    assert!(!proof.belongs_to(&AllocationBudget::new(budget.limit_bytes())));
    assert!(matches!(
        &proof.canonical().record,
        AmxRecordV1::Decision(_)
    ));
    assert!(
        read.complete().is_err(),
        "same terminal/proof job delivers once"
    );
    budget.with_deferred_refund_notifications(|_| {
        drop(proof);
        drop(read);
    });
    drop(view);
    drop(decoder);
    assert_eq!(
        budget.reserved_bytes(),
        baseline,
        "actual source/control retirement refunds its original pool"
    );
}

#[test]
fn terminal_amx_raw_frame_survives_original_shared_shell_refusal() {
    let (chain, tx, _) = committed_source(1);
    let budget = chain.state().ivm_execution_budget();
    let decoder = counter(&budget);
    let view = chain.state().view();
    let mut read = amx_record_proof(&view, 2, AmxRecordKind::Begin, tx);
    read.chain = Some(decoder.with(|| CertifiedChain::new(&view)).unwrap());
    let length = decoder
        .with(|| {
            chain
                .kura()
                .native_frame_read(2, *view.block_hashes().get(1).unwrap())
        })
        .unwrap()
        .unwrap()
        .wire_len();
    let length = usize::try_from(length).unwrap();
    let pressure = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes() - length)
        .unwrap();
    let cause = decoder.with(|| read.poll()).unwrap_err();
    assert!(
        is_capacity(&cause),
        "actual original shared-body shell refusal: {cause:?}"
    );
    let original = read.chain.as_ref().unwrap().terminal_frame_for_test();
    assert!(
        original.is_some(),
        "terminal AMX source must retain the exact acquired frame"
    );
    let original = original.unwrap();
    let pointer = original.as_slice().as_ptr();
    assert!(original.belongs_to(&budget));
    assert_eq!(original.as_slice().len(), length);
    let consumed = decoder.consumed_allocated_bytes();
    assert!(is_capacity(&decoder.with(|| read.poll()).unwrap_err()));
    assert_eq!(
        read.chain
            .as_ref()
            .unwrap()
            .terminal_frame_for_test()
            .unwrap()
            .as_slice()
            .as_ptr(),
        pointer
    );
    assert!(decoder.consumed_allocated_bytes() >= consumed);
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    drop(pressure);
    let proof = decoder.with(|| read.complete()).unwrap().unwrap();
    assert!(proof.belongs_to(&budget));
    assert_eq!(
        read.chain
            .as_ref()
            .unwrap()
            .terminal_frame_for_test()
            .unwrap()
            .as_slice()
            .as_ptr(),
        pointer
    );
    assert!(read.complete().is_err());
}
