//! Genuine native successor authority allocations must retain the source's original pool.
//!
//! These tests use the unchanged production constructor before and after repair. The
//! signed genesis and two actual certified successor blocks are produced by the real
//! execution/schedule/QC fixture; no decoded DTO or World roster grants authority.

use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};

fn chain() -> CertifiedTestChain {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit_at(2_000, Vec::new());
    chain.commit_at(3_000, Vec::new());
    chain
}

#[test]
fn original_native_successor_authority_retains_its_actual_source_pool() {
    let chain = chain();
    let parent = chain.committed(2);
    let current = chain.committed(3);
    let original = (
        parent.id(),
        current.id(),
        parent.block().clone(),
        current.block().clone(),
    );
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let budget = view.execution_budget();
    let epoch = crossbeam_epoch::pin();
    let baseline = budget.reserved_bytes();
    let authority = reader
        .executed_successor_authority(&parent, &current)
        .unwrap();
    let retained = budget.reserved_bytes();
    eprintln!("original authority backing: before={baseline}, live={retained}");
    assert!(
        retained > baseline,
        "native successor authority owns its heap graph in the original source pool"
    );
    assert_eq!((parent.id(), current.id()), (original.0, original.1));
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        parent.block(),
        &original.2
    ));
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        current.block(),
        &original.3
    ));
    drop(authority);
    assert_eq!(
        budget.reserved_bytes(),
        baseline,
        "the final authority reader releases exactly its retired graph"
    );
    let certified = reader
        .verify_executed_successor(&parent, current.clone())
        .unwrap();
    assert_eq!(certified.id(), current.id());
    assert_eq!(certified.verification(), QcVerification::Verified);
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        certified.block(),
        current.block()
    ));
    assert_eq!(budget.reserved_bytes(), baseline);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _authority = reader
            .executed_successor_authority(&parent, &current)
            .unwrap();
        assert!(budget.reserved_bytes() > baseline);
        panic!("cancel original native authority reader");
    }));
    assert!(unwind.is_err());
    assert_eq!(budget.reserved_bytes(), baseline);
    drop(epoch);
}

#[test]
fn original_native_authority_capacity_refusal_waits_for_its_own_release_then_retries() {
    use iroha_allocation::{AllocationBudget, AllocationRefusal, release::ReleaseRegistration};
    use std::{
        future::Future as _,
        pin::Pin,
        task::{Context, Waker},
    };

    let chain = chain();
    let parent = chain.committed(2);
    let current = chain.committed(3);
    let original = (parent.id(), current.id());
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let budget = view.execution_budget();
    let epoch = crossbeam_epoch::pin();
    let baseline = budget.reserved_bytes();
    let waiter_bytes = ReleaseRegistration::allocation_layout().size();
    let mut reservation = budget.try_reserve_bytes(waiter_bytes).unwrap();
    let mut registration = ReleaseRegistration::from_reservation(&mut reservation).unwrap();
    drop(reservation);
    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let refused = reader.executed_successor_authority(&parent, &current);
    let Err(VerificationReadError::Deferred(local)) = refused else {
        panic!(
            "native authority must refuse the original full pool before allocating its owned graph"
        )
    };
    let Some(AllocationRefusal::Capacity { release, .. }) = local.allocation_refusal() else {
        panic!("native authority capacity retains the original allocation release owner")
    };
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    let mut wait = release.clone().wait_for_release(&mut registration);
    let mut task = Context::from_waker(Waker::noop());
    assert!(
        Pin::new(&mut wait).poll(&mut task).is_pending(),
        "refusal has no candidate allocation to refund and wake itself"
    );
    let unrelated = AllocationBudget::new(19);
    drop(unrelated.try_reserve_bytes(19).unwrap());
    assert!(Pin::new(&mut wait).poll(&mut task).is_pending());
    // Original source rejection keeps its precedence over the local pool limit.
    assert!(matches!(
        reader.executed_successor_authority(&current, &current),
        Err(VerificationReadError::Source(
            ChainReadError::Discontinuous { height: 3 }
        ))
    ));
    drop(blocker);
    assert!(Pin::new(&mut wait).poll(&mut task).is_ready());
    drop(wait);
    let authority = reader
        .executed_successor_authority(&parent, &current)
        .unwrap();
    assert!(budget.reserved_bytes() > baseline + waiter_bytes);
    assert_eq!((parent.id(), current.id()), original);
    drop(authority);
    let certified = reader
        .verify_executed_successor(&parent, current.clone())
        .unwrap();
    assert_eq!(certified.id(), current.id());
    assert_eq!(certified.verification(), QcVerification::Verified);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), baseline);
    drop(epoch);
}
