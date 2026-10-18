//! Exact capture allocation causes survive the real State-to-executor classifier.

use super::*;
use crate::{
    state::capture_buffer_refusal_for_test,
    test_allocations::{allocations_during, refuse_one_layout_during},
};
use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};
use std::alloc::Layout;

#[test]
fn original_capture_pool_refusal_reaches_executor_without_allocation_or_replacement() {
    let budget = AllocationBudget::new(128);
    let occupied = budget.try_reserve_bytes(128).unwrap();
    let Err(ChargedBufferError::Admission(original)) = ChargedBuffer::<u64>::new(1, &budget) else {
        panic!("actual original buffer capacity refusal")
    };
    let expected = original.clone();
    let mut result = None;
    assert_eq!(
        allocations_during(|| {
            result = Some(original_refusal(capture_buffer_refusal_for_test(
                ChargedBufferError::Admission(original),
            )));
        }),
        0
    );
    let PublicationError::Deferred(actual) = result.unwrap() else {
        panic!("typed original capture cause")
    };
    assert!(actual.state_capture().is_some());
    assert_eq!(actual.allocation_refusal(), Some(&expected));
    let iroha_allocation::AllocationRefusal::Capacity { release, .. } = &expected else {
        panic!("actual pool capacity")
    };
    assert_eq!(actual.release_wait(), Some(release));
    assert!(actual.execution().is_none());
    assert_eq!(budget.reserved_bytes(), 128);
    drop(occupied);
    let retry = ChargedBuffer::<u64>::new(1, &budget).unwrap();
    drop(retry);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_capture_physical_allocator_refusal_has_exact_bytes_and_no_pool_wake() {
    let layout = Layout::array::<u64>(19).unwrap();
    let budget = AllocationBudget::new(layout.size());
    let (result, denied) =
        refuse_one_layout_during(layout, || ChargedBuffer::<u64>::new(19, &budget));
    assert!(denied);
    let original = match result {
        Err(original @ ChargedBufferError::Allocator { .. }) => original,
        _ => panic!("actual physical allocation refusal"),
    };
    let mut outcome = None;
    assert_eq!(
        allocations_during(|| {
            outcome = Some(original_refusal(capture_buffer_refusal_for_test(original)));
        }),
        0
    );
    let PublicationError::Deferred(actual) = outcome.unwrap() else {
        panic!("typed physical capture cause")
    };
    assert!(
        matches!(actual.state_capture().unwrap().buffer_refusal(), Some(ChargedBufferError::Allocator { requested_bytes }) if *requested_bytes == layout.size())
    );
    assert!(actual.allocation_refusal().is_none());
    assert!(actual.release_wait().is_none());
    assert!(actual.execution().is_none());
    assert_eq!(budget.reserved_bytes(), 0);
    let retry = ChargedBuffer::<u64>::new(19, &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), layout.size());
    drop(retry);
    assert_eq!(budget.reserved_bytes(), 0);
}
