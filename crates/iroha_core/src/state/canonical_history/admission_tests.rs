//! Real State/Kura callbacks retain declared semantics and original allocation refusal custody.

use super::*;
use crate::{
    state::{StateReadOnly, World},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_allocation::{AllocationRefusal, ChargedBuffer};
use ivm::error::ExecutionDeferral;
use std::{
    future::Future as _,
    task::{Context, Poll, Waker},
};

#[test]
fn source_admission_distinguishes_semantic_budget_error_from_local_history_limit() {
    // Keep old State generations from changing the exact pool baseline during source admission.
    let _retirement_pin = crossbeam_epoch::pin();
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let view = chain.state().view();
    let source = view.canonical_history();
    // The signed input genesis predates its executed outputs and result certificate.
    // Admit the exact persisted canonical frame, independently checking its bytes against
    // the authenticated stored block before the pool is constrained or read counts reset.
    let wire_len = {
        let executed = source.block(NonZeroUsize::MIN).unwrap();
        assert_eq!(executed.hash(), chain.genesis().hash());
        assert!(executed.commit_certificate().is_some());
        let wire = chain
            .kura()
            .canonical_block_wire_bytes_for_testing(NonZeroUsize::MIN)
            .unwrap();
        assert_eq!(wire, executed.encode_wire().unwrap());
        wire.len() as u64
    };
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let original_limit = budget.limit_bytes();
    // Even the original shared shell cannot be admitted. The declared callback
    // outcome must win before that reservation and before any body decode.
    budget.set_limit_bytes(baseline);
    for semantic in [true, false] {
        chain.kura().reset_canonical_query_reads_for_test();
        let mut calls = 0;
        let error = source
            .block_with_admission(NonZeroUsize::MIN, |frames, bytes| {
                calls += 1;
                assert_eq!((frames, bytes), (1, wire_len));
                Err(if semantic {
                    ExecutionAttemptError::Rejected(QueryExecutionFail::GasBudgetExceeded)
                } else {
                    ExecutionAttemptError::Deferred(
                        ExecutionDeferral::CanonicalHistoryCapacity.into(),
                    )
                })
            })
            .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
        assert_eq!(budget.reserved_bytes(), baseline);
        if semantic {
            assert!(
                matches!(error, ExecutionAttemptError::Rejected(actual_rejection) if actual_rejection == (QueryExecutionFail::GasBudgetExceeded))
            );
        } else {
            let ExecutionAttemptError::Deferred(local) = error else {
                panic!("declared local source allowance became semantic: {error:?}");
            };
            assert_eq!(local.reason(), ExecutionDeferral::CanonicalHistoryCapacity);
            assert!(local.allocation_refusal().is_none());
        }
    }
    budget.set_limit_bytes(original_limit);
    assert_eq!(
        source
            .block_with_admission(NonZeroUsize::MIN, |_, _| Ok(()))
            .unwrap()
            .hash(),
        chain.genesis().hash(),
    );
}

#[test]
fn callback_allocation_refusal_keeps_the_actual_state_pool_release_owner() {
    // Only the explicit held owner may refund this pool or wake the captured release source.
    let _retirement_pin = crossbeam_epoch::pin();
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let view = chain.state().view();
    let source = view.canonical_history();
    let budget = chain.state().ivm_execution_budget();
    assert!(source.budget.same_pool(&budget));
    let baseline = budget.reserved_bytes();
    let original_limit = budget.limit_bytes();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let held = ChargedBuffer::<u8>::new(1, &budget).unwrap();
    budget.set_limit_bytes(budget.reserved_bytes());
    let original = budget.try_reserve_bytes(1).unwrap_err();
    chain.kura().reset_canonical_query_reads_for_test();
    let error = source
        .executed_receipt(NonZeroUsize::MIN, |_, _| {
            Err(ExecutionAttemptError::Deferred(original.clone().into()))
        })
        .unwrap_err();
    assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
    let ExecutionAttemptError::Deferred(local) = error else {
        panic!("actual State admission lost its owner: {error:?}");
    };
    assert_eq!(local.allocation_refusal(), Some(&original));
    let Some(AllocationRefusal::Capacity { release, .. }) = local.allocation_refusal() else {
        panic!("original State pool release source absent");
    };
    {
        let mut wake = std::pin::pin!(release.clone().wait_for_release(&mut registration));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(wake.as_mut().poll(&mut context), Poll::Pending));
        let foreign = AllocationBudget::new(1);
        drop(ChargedBuffer::<u8>::new(1, &foreign).unwrap());
        assert!(matches!(wake.as_mut().poll(&mut context), Poll::Pending));
        drop(held);
        assert!(matches!(wake.as_mut().poll(&mut context), Poll::Ready(_)));
    }
    drop(registration);
    budget.set_limit_bytes(original_limit);
    assert_eq!(budget.reserved_bytes(), baseline);
    let receipt = source
        .executed_receipt(NonZeroUsize::MIN, |_, _| Ok(()))
        .unwrap();
    assert!(receipt.block().belongs_to(&budget));
    assert_eq!(receipt.block_hash(), chain.genesis().hash());
    drop(receipt);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn admitted_source_preserves_its_own_state_shell_refusal_before_body_io() {
    // Retain old State generations so shell refusal and refund use one exact resident baseline.
    let _retirement_pin = crossbeam_epoch::pin();
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let view = chain.state().view();
    let source = view.canonical_history();
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let original_limit = budget.limit_bytes();
    budget.set_limit_bytes(baseline);
    let expected = SharedSignedBlock::reserve(&budget)
        .err()
        .expect("original shell admission refusal");
    let expected: crate::execution_attempt::ExecutionDeferred = expected.into();
    chain.kura().reset_canonical_query_reads_for_test();
    let mut calls = 0;
    let error = source
        .block_with_admission(NonZeroUsize::MIN, |_, _| {
            calls += 1;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(
        calls, 1,
        "logical admission precedes the actual State shell reservation"
    );
    let ExecutionAttemptError::Deferred(actual) = error else {
        panic!("original shell refusal must remain deferred")
    };
    assert_eq!(actual.reason(), expected.reason());
    assert_eq!(actual.allocation_refusal(), expected.allocation_refusal());
    assert_eq!(actual.decode_refusal(), expected.decode_refusal());
    assert_eq!(actual.phase(), expected.phase());
    assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
    assert_eq!(budget.reserved_bytes(), baseline);
    budget.set_limit_bytes(original_limit);
    let block = source
        .block_with_admission(NonZeroUsize::MIN, |_, _| Ok(()))
        .unwrap();
    assert!(block.belongs_to(&budget));
    drop(block);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn admitted_source_frame_refusal_retains_the_original_state_pool_before_body_io() {
    let _retirement_pin = crossbeam_epoch::pin();
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let view = chain.state().view();
    let source = view.canonical_history();
    let budget = chain.state().ivm_execution_budget();
    assert!(source.budget.same_pool(&budget));
    let expected = source.block(NonZeroUsize::MIN).unwrap();
    let wire_length = expected.encode_wire().unwrap().len();
    let expected_hash = expected.hash();
    drop(expected);
    let baseline = budget.reserved_bytes();
    let original_limit = budget.limit_bytes();
    let shell_bytes = SharedSignedBlock::allocation_layout().size();
    let refused_limit = baseline + shell_bytes + wire_length - 1;
    budget.set_limit_bytes(refused_limit);
    let before = chain.kura().canonical_body_bytes_read_for_test();
    let mut calls = 0;
    let error = source
        .block_with_admission(NonZeroUsize::MIN, |frames, bytes| {
            calls += 1;
            assert_eq!((frames, bytes), (1, wire_length as u64));
            Ok(())
        })
        .unwrap_err();
    let ExecutionAttemptError::Deferred(local) = error else {
        panic!("original frame admission became a rejected query: {error:?}");
    };
    let Some(AllocationRefusal::Capacity {
        requested_bytes,
        reserved_bytes,
        limit_bytes,
        ..
    }) = local.allocation_refusal()
    else {
        panic!("original frame backing refusal was not retained");
    };
    assert_eq!(*requested_bytes, wire_length);
    assert_eq!(*reserved_bytes, baseline + shell_bytes);
    assert_eq!(*limit_bytes, refused_limit);
    assert_eq!(calls, 1);
    assert_eq!(chain.kura().canonical_body_bytes_read_for_test(), before);
    assert_eq!(budget.reserved_bytes(), baseline);
    budget.set_limit_bytes(original_limit);
    let block = source
        .block_with_admission(NonZeroUsize::MIN, |_, _| Ok(()))
        .unwrap();
    assert!(block.belongs_to(&budget));
    assert_eq!(block.hash(), expected_hash);
    drop(block);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn authenticated_receipt_visitors_keep_semantic_and_original_local_outcomes() {
    // Separate each receipt-shell refund from deferred reclamation of older State generations.
    let _retirement_pin = crossbeam_epoch::pin();
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let view = chain.state().view();
    let source = view.canonical_history();
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let original_limit = budget.limit_bytes();
    for semantic in [true, false] {
        chain.kura().reset_canonical_query_reads_for_test();
        let mut calls = 0;
        let mut original = None;
        let error = source
            .visit_executed_backwards(
                NonZeroUsize::MIN,
                NonZeroUsize::MIN,
                |_, _| Ok(()),
                |receipt| {
                    calls += 1;
                    assert!(receipt.block().belongs_to(&budget));
                    assert_eq!(receipt.block_hash(), chain.genesis().hash());
                    if semantic {
                        Err(ExecutionAttemptError::Rejected(
                            QueryExecutionFail::GasBudgetExceeded,
                        ))
                    } else {
                        budget.set_limit_bytes(budget.reserved_bytes());
                        let refusal = budget.try_reserve_bytes(1).unwrap_err();
                        original = Some(refusal.clone());
                        Err(ExecutionAttemptError::Deferred(refusal.into()))
                    }
                },
            )
            .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(chain.kura().canonical_query_reads_for_test().0, 1);
        assert_eq!(
            budget.reserved_bytes(),
            baseline,
            "failed visitor drops its receipt shell"
        );
        if semantic {
            assert!(
                matches!(error, ExecutionAttemptError::Rejected(actual_rejection) if actual_rejection == (QueryExecutionFail::GasBudgetExceeded))
            );
        } else {
            let ExecutionAttemptError::Deferred(local) = error else {
                panic!("visitor's original State refusal became semantic: {error:?}");
            };
            assert_eq!(local.allocation_refusal(), original.as_ref());
            budget.set_limit_bytes(original_limit);
        }
    }
}
