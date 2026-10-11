//! Actual frozen State fields retain original scope, index backing and work on retry.

use super::{fixture, staged_block};
use crate::{
    state::{
        State, StateBlock, StatePublicationOutcome, publication::RetainedPackageReadError,
        storage_transactions,
    },
    test_allocations::allocations_during,
};
use concread::bptree::BptreeMapRowPosition;
use iroha_allocation::{AllocationBudget, AllocationRefusal, ChargedBufferError};
use iroha_data_model::{
    block::BlockHeader,
    musubi::{MusubiPackageIdV1, MusubiPackageRecordV1},
};
use mv::storage::StorageReadOnly;
use std::alloc::Layout;

fn frozen_pending(state: &State, header: BlockHeader) -> Box<StateBlock<'_>> {
    let mut block = Box::new(staged_block(state, header, false, true));
    let budget = state.ivm_execution_budget();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    assert!(matches!(
        block.try_publish(),
        StatePublicationOutcome::Deferred(
            storage_transactions::TransactionsBlockError::ExecutionDeferred(_)
        )
    ));
    drop(occupied);
    block
}

#[test]
fn original_package_read_retains_completed_current_index_on_later_physical_refusal() {
    let (state, proposal) = fixture();
    let budget = state.ivm_execution_budget();
    let mut block = frozen_pending(&state, proposal.header());
    let original = std::ptr::from_ref(&*block);
    let (current_count, undo_count, value_pointer) = {
        let source = block.world.musubi_packages.frozen_images().unwrap();
        let value_pointer = std::ptr::from_ref(source.current_entries().next().unwrap().1);
        (
            source.current_entries().len(),
            source.undo_entries().len(),
            value_pointer,
        )
    };
    assert!(current_count > 0 && undo_count > 0);
    let scope = budget.try_owned_refund_scope().unwrap();
    block
        .start_original_package_read(scope)
        .unwrap_or_else(|(_, cause)| panic!("original scope: {cause:?}"));
    let control_credit = budget.reserved_bytes();
    let current_layout = Layout::array::<
        BptreeMapRowPosition<MusubiPackageIdV1, MusubiPackageRecordV1>,
    >(current_count)
    .unwrap();
    let undo_layout = Layout::array::<
        BptreeMapRowPosition<MusubiPackageIdV1, Option<MusubiPackageRecordV1>>,
    >(undo_count)
    .unwrap();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - control_credit - current_layout.size())
        .unwrap();
    let Err(RetainedPackageReadError::Allocation(ChargedBufferError::Admission(actual))) =
        block.advance_original_package_read(usize::MAX)
    else {
        panic!("actual later undo backing must refuse the same occupied pool");
    };
    let expected = budget.try_reserve(undo_layout).unwrap_err();
    assert_eq!(
        actual, expected,
        "original pool/release cause, not just equal byte counts"
    );
    assert!(matches!(actual, AllocationRefusal::Capacity { .. }));
    let prefix = block.original_package_read_progress().unwrap();
    assert_eq!(prefix.current, current_count);
    assert_eq!(prefix.undo, 0);
    assert!(!prefix.complete);
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    let allocations = allocations_during(|| {
        assert!(matches!(
            block.advance_original_package_read(usize::MAX),
            Err(RetainedPackageReadError::Allocation(_))
        ));
        assert_eq!(block.original_package_read_progress().unwrap(), prefix);
    });
    assert_eq!(
        allocations, 0,
        "later retry neither copies nor rebuilds completed current backing"
    );
    drop(occupied);
    let complete = block.advance_original_package_read(usize::MAX).unwrap();
    assert!(complete.complete);
    assert_eq!(complete.current, current_count);
    assert_eq!(complete.undo, undo_count);
    assert_eq!(
        budget.reserved_bytes(),
        control_credit + current_layout.size() + undo_layout.size()
    );
    assert_eq!(
        std::ptr::from_ref(block.original_package_current_row(0, usize::MAX).unwrap().1),
        value_pointer
    );
    assert!(
        block
            .original_package_undo_row(0, usize::MAX)
            .unwrap()
            .1
            .is_none(),
        "newly inserted package has an original absent preimage"
    );
    block.retire_original_package_read().unwrap();
    assert_eq!(
        budget.reserved_bytes(),
        control_credit - control_data_bytes_for_test(),
        "actual indexes/control retire while the original scope remains"
    );
    assert_eq!(std::ptr::from_ref(&*block), original);
    assert!(matches!(
        block.try_publish(),
        StatePublicationOutcome::Published
    ));
    assert_eq!(state.world.musubi_packages.view().len(), current_count);
}

// Test the real admitted control layout, not an invented byte proxy.
fn control_data_bytes_for_test() -> usize {
    crate::state::publication::retained_package_control_layout_for_test().size()
}

#[test]
fn original_package_read_same_limit_retry_preserves_monotonic_work_and_exact_source() {
    let (state, proposal) = fixture();
    let mut block = frozen_pending(&state, proposal.header());
    let budget = state.ivm_execution_budget();
    let current_count = block.world.musubi_packages.len();
    let current_work = current_count
        .checked_mul(3 * (usize::BITS as usize + 1))
        .unwrap();
    block
        .start_original_package_read(budget.try_owned_refund_scope().unwrap())
        .unwrap_or_else(|(_, cause)| panic!("original scope: {cause:?}"));
    let Err(RetainedPackageReadError::Work {
        used,
        required,
        limit,
    }) = block.advance_original_package_read(current_work)
    else {
        panic!("later undo traversal must refuse only after a completed current prefix");
    };
    assert_eq!(used, current_work);
    assert!(required > used);
    assert_eq!(limit, current_work);
    let prefix = block.original_package_read_progress().unwrap();
    let credit = budget.reserved_bytes();
    assert_eq!(prefix.current, current_count);
    assert_eq!(prefix.undo, 0);
    assert!(matches!(
        block.retire_original_package_read(),
        Err(RetainedPackageReadError::Incomplete)
    ));
    let allocations = allocations_during(|| {
        assert!(
            matches!(block.advance_original_package_read(current_work), Err(RetainedPackageReadError::Work { used, .. }) if used == current_work)
        );
        assert_eq!(block.original_package_read_progress().unwrap(), prefix);
        assert_eq!(budget.reserved_bytes(), credit);
    });
    assert_eq!(allocations, 0);
    let completed = block.advance_original_package_read(usize::MAX).unwrap();
    assert!(completed.complete);
    assert!(completed.work > prefix.work);
    let before_resolve = completed.work;
    let allocations = allocations_during(|| {
        assert!(
            matches!(block.original_package_current_row(0, before_resolve), Err(RetainedPackageReadError::Work { used, .. }) if used == before_resolve)
        );
    });
    assert_eq!(
        allocations, 0,
        "row resolution admits structural work before inspection"
    );
    assert_eq!(
        block.original_package_read_progress().unwrap().work,
        before_resolve
    );
    block.original_package_current_row(0, usize::MAX).unwrap();
    assert!(block.original_package_read_progress().unwrap().work > before_resolve);
    block.retire_original_package_read().unwrap();
    assert!(matches!(
        block.try_publish(),
        StatePublicationOutcome::Published
    ));
}

#[test]
fn original_package_read_foreign_scope_and_changed_source_refuse_without_reacquisition() {
    let (state, proposal) = fixture();
    let mut block = frozen_pending(&state, proposal.header());
    let budget = state.ivm_execution_budget();
    let foreign = AllocationBudget::new(budget.limit_bytes());
    let scope = foreign.try_owned_refund_scope().unwrap();
    let foreign_credit = foreign.reserved_bytes();
    let (scope, error) = block.start_original_package_read(scope).unwrap_err();
    assert!(matches!(error, RetainedPackageReadError::ScopeIdentity));
    assert!(scope.belongs_to(&foreign));
    assert_eq!(foreign.reserved_bytes(), foreign_credit);
    assert!(block.world.musubi_packages.frozen_images().is_some());
    drop(scope);
    assert_eq!(foreign.reserved_bytes(), 0);
    block
        .start_original_package_read(budget.try_owned_refund_scope().unwrap())
        .unwrap_or_else(|(_, cause)| panic!("original scope: {cause:?}"));
    assert!(matches!(
        block.advance_original_package_read(0),
        Err(RetainedPackageReadError::Work { .. })
    ));
    let prefix = block.original_package_read_progress().unwrap();
    let credit = budget.reserved_bytes();
    state.with_held_view_publication_for_reader_test(|_| {});
    assert!(matches!(
        block.advance_original_package_read(usize::MAX),
        Err(RetainedPackageReadError::SourceChanged)
    ));
    assert!(matches!(
        block.retire_original_package_read(),
        Err(RetainedPackageReadError::SourceChanged)
    ));
    assert_eq!(block.original_package_read_progress().unwrap(), prefix);
    assert_eq!(budget.reserved_bytes(), credit);
    assert!(state.world.musubi_packages.view().is_empty());
}

#[test]
fn original_package_read_outside_reader_refuses_retirement_without_physical_wait() {
    let (state, proposal) = fixture();
    let mut block = frozen_pending(&state, proposal.header());
    let budget = state.ivm_execution_budget();
    block
        .start_original_package_read(budget.try_owned_refund_scope().unwrap())
        .unwrap_or_else(|(_, cause)| panic!("original scope: {cause:?}"));
    block.advance_original_package_read(usize::MAX).unwrap();
    let reader = block.retain_package_reader_for_test().unwrap();
    let credit = budget.reserved_bytes();
    assert!(matches!(
        block.retire_original_package_read(),
        Err(RetainedPackageReadError::ReadersRetained)
    ));
    assert!(
        budget.reserved_bytes() < credit,
        "indexes retire before their original scope"
    );
    let retained_credit = budget.reserved_bytes();
    let allocations = allocations_during(|| {
        assert!(matches!(
            block.retire_original_package_read(),
            Err(RetainedPackageReadError::ReadersRetained)
        ));
        assert_eq!(budget.reserved_bytes(), retained_credit);
    });
    assert_eq!(allocations, 0);
    assert!(
        matches!(block.try_publish(), StatePublicationOutcome::Deferred(
        storage_transactions::TransactionsBlockError::ExecutionDeferred(ref reason))
        if reason.reason() == ivm::error::ExecutionDeferral::LocalInvariantViolation && reason.allocation_refusal().is_none()),
        "premature publication is a local ordering error, never an invented release wait"
    );
    drop(reader);
    block.retire_original_package_read().unwrap();
    assert!(matches!(
        block.try_publish(),
        StatePublicationOutcome::Published
    ));
}
