//! Parent-reservation construction retains its exact original split/refund semantics.

use super::*;

#[test]
fn reservation_child_backing_consumes_parent_credit_without_reacquisition() {
    let _serial = serial_observation();
    let budget = AllocationBudget::new(137);
    let mut parent = budget.try_reserve_bytes(137).unwrap();
    let mut child = parent.try_partition_bytes(137).unwrap();
    observe_next(137, false, &budget);
    let bytes = ChargedBuffer::<u8>::from_reservation(137, &mut child).unwrap();
    assert_eq!(REQUESTED_SIZE.load(SeqCst), 137);
    assert_eq!(RESERVED_AT_ALLOCATION.load(SeqCst), 137);
    assert_eq!(parent.remaining_bytes(), 0);
    assert_eq!(child.remaining_bytes(), 0);
    drop(parent);
    drop(child);
    assert_eq!(budget.reserved_bytes(), 137);
    drop(bytes);
    assert!(FREED.load(SeqCst));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn reservation_refusal_never_allocates_and_allocator_failure_refunds_only_split_credit() {
    let _serial = serial_observation();
    let budget = AllocationBudget::new(113);
    let mut parent = budget.try_reserve_bytes(113).unwrap();
    observe_next(114, false, &budget);
    assert!(matches!(
        ChargedBuffer::<u8>::from_reservation(114, &mut parent),
        Err(iroha_allocation::PrepaidBufferError::Reservation(_))
    ));
    assert_eq!(NEXT_SIZE.load(SeqCst), 114);
    assert_eq!(parent.remaining_bytes(), 113);
    observe_next(101, true, &budget);
    assert!(matches!(
        ChargedBuffer::<u8>::from_reservation(101, &mut parent),
        Err(iroha_allocation::PrepaidBufferError::Allocation(
            ChargedBufferError::Allocator {
                requested_bytes: 101
            }
        ))
    ));
    assert_eq!(parent.remaining_bytes(), 12);
    assert_eq!(budget.reserved_bytes(), 12);
    drop(parent);
    assert_eq!(budget.reserved_bytes(), 0);
}
