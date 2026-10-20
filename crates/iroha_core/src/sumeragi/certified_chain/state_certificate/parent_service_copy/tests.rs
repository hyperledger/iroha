//! Actual native receipt sources, original destination refusals and authenticated lends.
use super::*;
use crate::{
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    test_allocations::refuse_one_layout_during,
};
use iroha_allocation::{ChargedBufferFromChargeError, SharedFromChargeError};

fn fixture() -> (CertifiedTestChain, ParentServicePreparation) {
    let mut chain =
        CertifiedTestChain::start(TestChainConfig::new(crate::state::World::new(), 1_000)).unwrap();
    chain.commit_at(2_000, Vec::new());
    chain.commit_at(3_000, Vec::new());
    let mut prepared = ParentServicePreparation::default();
    prepared.prepare(&chain.state().view(), 3).unwrap();
    (chain, prepared)
}
fn deferred(error: ParentServiceError) -> ExecutionDeferred {
    let ParentServiceError::Deferred(original) = error else {
        panic!("original producer copy refusal: {error}")
    };
    original
}
#[test]
fn producer_copy_physical_byte_and_root_refusals_keep_original_charges_and_retry() {
    let _epoch = crossbeam_epoch::pin();
    let (chain, prepared) = fixture();
    let pool = chain.state().ivm_execution_budget();
    let (_, original, _, _, _) = prepared.inputs();
    let parent = original.block();
    let layouts = PreparedParentServiceCommitQc::from_parent(parent, &pool)
        .unwrap()
        .allocation_layouts()
        .unwrap();
    let baseline = pool.reserved_bytes();
    let demand: usize = layouts.iter().map(std::alloc::Layout::size).sum();
    for (step, layout) in layouts.into_iter().enumerate() {
        let mut copy = ParentServiceCopyPreparation::default();
        let (result, denied) = refuse_one_layout_during(layout, || copy.prepare(parent, &pool));
        assert!(
            denied,
            "actual producer destination allocation must be reached"
        );
        let cause = deferred(result.unwrap_err());
        assert_eq!(
            pool.reserved_bytes(),
            baseline + demand,
            "producer copy refusal must retain original byte and control charges"
        );
        let allocator = cause
            .allocator_refusal()
            .expect("original concrete allocator cause");
        assert!(cause.allocation_refusal().is_none());
        if step == 0 {
            assert_eq!(
                allocator.buffer_from_charge_error(),
                Some(&ChargedBufferFromChargeError::Allocator { layout })
            );
            assert!(allocator.shared_from_charge_error().is_none());
        } else {
            assert_eq!(
                allocator.shared_from_charge_error(),
                Some(&SharedFromChargeError::Allocator { layout })
            );
            assert!(allocator.buffer_from_charge_error().is_none());
        }
        let retained = copy
            .pending
            .as_ref()
            .unwrap()
            .initialized_parent(parent, &pool)
            .unwrap()
            .map(|bytes| bytes.as_ptr());
        assert_eq!(retained.is_some(), step == 1);
        assert!(copy.get(parent, &pool).is_err());
        let (result, denied) = refuse_one_layout_during(layout, || copy.prepare(parent, &pool));
        assert!(denied);
        let retry = deferred(result.unwrap_err());
        assert_eq!(
            retry
                .allocator_refusal()
                .unwrap()
                .buffer_from_charge_error(),
            allocator.buffer_from_charge_error()
        );
        assert_eq!(
            retry
                .allocator_refusal()
                .unwrap()
                .shared_from_charge_error(),
            allocator.shared_from_charge_error()
        );
        assert_eq!(
            copy.pending
                .as_ref()
                .unwrap()
                .initialized_parent(parent, &pool)
                .unwrap()
                .map(|bytes| bytes.as_ptr()),
            retained
        );
        assert_eq!(pool.reserved_bytes(), baseline + demand);
        // Even an already admitted destination must complete with its original credit.
        let blocker = pool
            .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
            .unwrap();
        copy.prepare(parent, &pool).unwrap();
        let first = copy.get(parent, &pool).unwrap();
        let last = copy.get(parent, &pool).unwrap();
        assert!(NposParentServiceCommitQc::ptr_eq(&first, &last));
        if let Some(pointer) = retained {
            assert_eq!(first.as_slice().as_ptr(), pointer);
        }
        assert_eq!(
            first.as_slice(),
            parent.commit_certificate().unwrap().commit_qc()
        );
        drop(blocker);
        drop((copy, first));
        assert_eq!(pool.reserved_bytes(), baseline + demand);
        drop(last);
        assert_eq!(pool.reserved_bytes(), baseline);
    }
}

#[test]
fn producer_copy_lending_reauthenticates_native_cut_and_rejects_equal_wire_source() {
    let _epoch = crossbeam_epoch::pin();
    let (chain, mut prepared) = fixture();
    let pool = chain.state().ivm_execution_budget();
    let parent = prepared.inputs().1.block().clone();
    let view = chain.state().view();
    assert!(prepared.proposal_original(&view, &parent).is_err());
    prepared.prepare_producer_copy(&view, &parent).unwrap();
    let first = prepared.proposal_original(&view, &parent).unwrap();
    let clone = prepared.proposal_original(&view, &parent).unwrap();
    assert!(NposParentServiceCommitQc::ptr_eq(&first, &clone));
    let distinct = SharedSignedBlock::try_new(parent.as_ref().clone(), &pool).unwrap();
    assert_eq!(
        distinct.encode_wire().unwrap(),
        parent.encode_wire().unwrap()
    );
    assert!(prepared.producer_copy.prepare(&distinct, &pool).is_err());
    assert!(prepared.producer_copy.get(&distinct, &pool).is_err());
    let foreign = AllocationBudget::new(pool.limit_bytes());
    assert!(prepared.producer_copy.get(&parent, &foreign).is_err());
    assert!(
        prepared
            .proposal_original(&view, chain.committed(2).block())
            .is_err()
    );
    // A changed real native predecessor slot invalidates an otherwise complete copy.
    let mut physical = crate::kura::BlockStore::new(crate::kura::Kura::canonical_storage_path(
        &chain.kura().store_root(),
    ));
    let predecessor = physical.read_block_index(1).unwrap();
    physical.write_block_index(1, predecessor.start, 0).unwrap();
    let refused = prepared.proposal_original(&view, &parent);
    physical
        .write_block_index(1, predecessor.start, predecessor.length)
        .unwrap();
    assert!(
        refused.is_err(),
        "complete copy cannot bypass original native carrier checks"
    );
    let retry = prepared.proposal_original(&view, &parent).unwrap();
    assert!(NposParentServiceCommitQc::ptr_eq(&first, &retry));
    let reader = CertifiedChain::new_for_parent_service(&view).unwrap();
    let initial = reader.parent_service_proposal_original(&parent).unwrap();
    assert_eq!(initial, first);
    assert!(initial.admitted_to(&pool));
    assert!(!NposParentServiceCommitQc::ptr_eq(&initial, &first));
}

#[test]
fn producer_copy_original_logical_refusal_precedes_destination_and_physical_retry_does_not_recharge()
 {
    let _epoch = crossbeam_epoch::pin();
    let (chain, prepared) = fixture();
    let pool = chain.state().ivm_execution_budget();
    let parent = prepared.inputs().1.block();
    let bytes = parent.commit_certificate().unwrap().commit_qc().len();
    let baseline = pool.reserved_bytes();
    let mut copy = ParentServiceCopyPreparation::default();
    let refusal = norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes - 1, 128),
        || copy.prepare(parent, &pool),
    )
    .unwrap_err();
    let original = deferred(refusal);
    assert_eq!(
        original.decode_refusal().unwrap().resource_error(),
        norito::core::DecodeResourceError::TotalAllocationExceeded {
            attempted: u64::try_from(bytes).unwrap(),
            limit: u64::try_from(bytes - 1).unwrap()
        }
    );
    assert!(original.allocation_refusal().is_none() && original.allocator_refusal().is_none());
    assert_eq!(pool.reserved_bytes(), baseline);
    assert!(copy.pending.is_none() && copy.complete.is_none());
    assert!(SharedSignedBlock::ptr_eq(
        copy.original.as_ref().unwrap(),
        parent
    ));
    let layout = NposParentServiceCommitQc::allocation_layout();
    let (result, denied) = refuse_one_layout_during(layout, || copy.prepare(parent, &pool));
    assert!(denied);
    assert!(deferred(result.unwrap_err()).allocator_refusal().is_some());
    let retained = copy
        .pending
        .as_ref()
        .unwrap()
        .initialized_parent(parent, &pool)
        .unwrap()
        .unwrap()
        .as_ptr();
    let copy_bytes = copy
        .pending
        .as_ref()
        .unwrap()
        .allocation_layouts()
        .unwrap()
        .iter()
        .map(std::alloc::Layout::size)
        .sum::<usize>();
    assert_eq!(pool.reserved_bytes(), baseline + copy_bytes);
    // The unchanged continuation already paid its logical copy allowance. A subsequent
    // physical retry may not pay again, even under a fresh zero-allowance scope.
    norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128),
        || copy.prepare(parent, &pool),
    )
    .unwrap();
    let output = copy.get(parent, &pool).unwrap();
    assert_eq!(output.as_slice().as_ptr(), retained);
    drop((copy, output));
    assert_eq!(pool.reserved_bytes(), baseline);
}
