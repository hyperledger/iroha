//! Refusal, original pointer custody and allocation-before-credit release.

use super::*;
use crate::{ChargedBufferError, without_allocations};
use std::{
    alloc::Layout,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::atomic::{AtomicBool, Ordering},
};

#[test]
#[allow(unsafe_code)]
fn ledger_refusal_then_retry_keeps_original_backing_and_returns_credit_once() {
    let bytes = 17;
    let ledger_bytes = Layout::array::<AllocationCharge>(1).unwrap().size();
    let budget = AllocationBudget::new(bytes);
    let mut original = ChargedBuffer::<u8>::new(bytes, &budget).unwrap();
    original.append(&[0x72; 17]).unwrap();
    let pointer = original.as_slice().as_ptr();
    assert!(matches!(
        ChargedBuffer::<AllocationCharge>::new(1, &budget),
        Err(ChargedBufferError::Admission(_))
    ));
    assert_eq!(original.as_slice().as_ptr(), pointer);
    assert_eq!(budget.reserved_bytes(), bytes);
    budget.set_limit_bytes(bytes + ledger_bytes);
    let mut ledger = ChargedBuffer::new(1, &budget).unwrap();
    let owner = without_allocations(|| {
        // SAFETY: no fallible work occurs between extraction and immediate owner
        // binding. The Vec and its exact charge remain paired in the new owner.
        let (values, charge) = unsafe { original.into_allocation_parts() };
        ledger.push_reserved(charge);
        unsafe { RetainedPayload::try_new(values, ledger, &budget) }.unwrap_or_else(
            |(_, _, error)| panic!("all original charges belong to the same pool: {error}"),
        )
    });
    assert_eq!(owner.get().as_ptr(), pointer);
    assert_eq!(owner.get().as_slice(), &[0x72; 17]);
    assert_eq!(budget.reserved_bytes(), bytes + ledger_bytes);
    without_allocations(|| drop(owner));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
#[allow(unsafe_code)]
fn foreign_ledger_refusal_returns_original_payload_and_ledger_without_refund() {
    let budget = AllocationBudget::new(4096);
    let foreign = AllocationBudget::new(4096);
    let mut original = ChargedBuffer::<u64>::new(2, &budget).unwrap();
    original.append(&[7, 11]).unwrap();
    let pointer = original.as_slice().as_ptr();
    let mut ledger = ChargedBuffer::new(1, &foreign).unwrap();
    let ledger_pointer = ledger.as_slice().as_ptr();
    // SAFETY: exact Vec and charge are immediately retained together below and
    // remain owned on refusal. The original source check deliberately fails.
    let (values, charge) = unsafe { original.into_allocation_parts() };
    ledger.push_reserved(charge);
    let before = (budget.reserved_bytes(), foreign.reserved_bytes());
    let (values, mut ledger, error) = without_allocations(|| {
        match unsafe { RetainedPayload::try_new(values, ledger, &budget) } {
            Err(parts) => parts,
            Ok(_) => panic!("equal configured limits do not authorize a foreign ledger"),
        }
    });
    assert_eq!(error, RetainedPayloadError::ForeignLedger);
    assert_eq!(values.as_ptr(), pointer);
    assert_eq!(ledger.as_slice().as_ptr(), ledger_pointer);
    assert_eq!((budget.reserved_bytes(), foreign.reserved_bytes()), before);
    let mut corrected = ChargedBuffer::new(1, &budget).unwrap();
    corrected.push_reserved(ledger.pop().unwrap());
    drop(ledger);
    assert_eq!(foreign.reserved_bytes(), 0);
    // SAFETY: the same original Vec now has its unchanged charge in a ledger
    // whose own backing belongs to the same pool. No clone/reallocation occurred.
    let owner = unsafe { RetainedPayload::try_new(values, corrected, &budget) }
        .unwrap_or_else(|(_, _, error)| panic!("source-corrected ledger: {error}"));
    assert_eq!(owner.get().as_ptr(), pointer);
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
#[allow(unsafe_code)]
fn foreign_child_charge_cannot_mix_two_original_pools() {
    let budget = AllocationBudget::new(4096);
    let foreign = AllocationBudget::new(4096);
    let first = ChargedBuffer::<u8>::new(13, &budget).unwrap();
    let second = ChargedBuffer::<u8>::new(19, &foreign).unwrap();
    let first_pointer = first.as_slice().as_ptr();
    let second_pointer = second.as_slice().as_ptr();
    let mut ledger = ChargedBuffer::new(2, &budget).unwrap();
    // SAFETY: both actual allocations and their exact charges stay together;
    // refusal returns every original allocation before orderly destruction.
    let (first, first_charge) = unsafe { first.into_allocation_parts() };
    let (second, second_charge) = unsafe { second.into_allocation_parts() };
    ledger.push_reserved(first_charge);
    ledger.push_reserved(second_charge);
    let before = (budget.reserved_bytes(), foreign.reserved_bytes());
    let (values, ledger, reason) = without_allocations(|| {
        match unsafe { RetainedPayload::try_new((first, second), ledger, &budget) } {
            Err(parts) => parts,
            Ok(_) => panic!("foreign payload storage must not be relabeled"),
        }
    });
    assert_eq!(reason, RetainedPayloadError::ForeignAllocation);
    assert_eq!(values.0.as_ptr(), first_pointer);
    assert_eq!(values.1.as_ptr(), second_pointer);
    assert_eq!((budget.reserved_bytes(), foreign.reserved_bytes()), before);
    drop(values);
    drop(ledger);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(foreign.reserved_bytes(), 0);
}

#[test]
#[allow(unsafe_code)]
fn payload_destructor_observes_retained_credit_and_unwind_cannot_refund_it() {
    struct Payload<'a> {
        _bytes: Vec<u8>,
        budget: &'a AllocationBudget,
        entered: &'a AtomicBool,
        panic: bool,
    }
    impl Drop for Payload<'_> {
        fn drop(&mut self) {
            assert!(self.budget.reserved_bytes() > 0);
            self.entered.store(true, Ordering::SeqCst);
            assert!(!self.panic, "injected payload destructor failure");
        }
    }
    for panic in [false, true] {
        let budget = AllocationBudget::new(4096);
        let entered = AtomicBool::new(false);
        let original = ChargedBuffer::<u8>::new(11, &budget).unwrap();
        let mut ledger = ChargedBuffer::new(1, &budget).unwrap();
        // SAFETY: original bytes and their exact charge move immediately into
        // an owner with no mutation/extraction and the original same-pool ledger.
        let (bytes, charge) = unsafe { original.into_allocation_parts() };
        ledger.push_reserved(charge);
        let payload = Payload {
            _bytes: bytes,
            budget: &budget,
            entered: &entered,
            panic,
        };
        let owner = unsafe { RetainedPayload::try_new(payload, ledger, &budget) }
            .unwrap_or_else(|(_, _, error)| panic!("same original pool: {error}"));
        let before = budget.reserved_bytes();
        let result = catch_unwind(AssertUnwindSafe(|| drop(owner)));
        assert_eq!(result.is_err(), panic);
        assert!(entered.load(Ordering::SeqCst));
        assert_eq!(budget.reserved_bytes(), if panic { before } else { 0 });
        // The panic branch intentionally retains the ledger rather than claim
        // successful reclamation; it is terminal recovery, never retry credit.
    }
}

#[test]
#[allow(unsafe_code)]
fn canonical_payload_move_retains_the_same_allocation_and_ledger_through_unwind() {
    struct Next {
        value: Vec<u64>,
    }
    for unwind in [false, true] {
        let budget = AllocationBudget::new(4096);
        let mut original = ChargedBuffer::<u64>::new(2, &budget).unwrap();
        original.append(&[3, 5]).unwrap();
        let pointer = original.as_slice().as_ptr();
        let mut ledger = ChargedBuffer::new(1, &budget).unwrap();
        // SAFETY: this exact original Vec and its charge enter the owner together.
        let (value, charge) = unsafe { original.into_allocation_parts() };
        ledger.push_reserved(charge);
        let owner = unsafe { RetainedPayload::try_new(value, ledger, &budget) }
            .unwrap_or_else(|(_, _, error)| panic!("same original pool: {error}"));
        let before = budget.reserved_bytes();
        if unwind {
            let error = catch_unwind(AssertUnwindSafe(|| {
                // SAFETY: the closure never exports or replaces the allocation.
                // Its injected unwind tests the conservative retained ledger.
                let _: RetainedPayload<Next> = unsafe {
                    owner.map_payload(|_value| panic!("injected canonical move failure"))
                };
            }));
            assert!(error.is_err());
            assert_eq!(budget.reserved_bytes(), before);
        } else {
            let next = without_allocations(|| {
                // SAFETY: the identical Vec is moved directly into the only field.
                unsafe { owner.map_payload(|value| Next { value }) }
            });
            assert_eq!(next.get().value.as_ptr(), pointer);
            assert_eq!(next.get().value, [3, 5]);
            assert_eq!(budget.reserved_bytes(), before);
            drop(next);
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
}

#[test]
#[allow(unsafe_code)]
fn retained_payload_source_check_is_exact_and_survives_original_field_movement() {
    let budget = AllocationBudget::new(4096);
    let same = budget.clone();
    let foreign = AllocationBudget::new(budget.limit_bytes());
    let mut bytes = ChargedBuffer::<u8>::new(17, &budget).unwrap();
    bytes.append(&[0x73; 17]).unwrap();
    let pointer = bytes.as_slice().as_ptr();
    let mut ledger = ChargedBuffer::new(1, &budget).unwrap();
    // SAFETY: original backing and exact charge move directly into one owner;
    // no callback, allocation or fallible work separates extraction and binding.
    let (bytes, charge) = unsafe { bytes.into_allocation_parts() };
    ledger.push_reserved(charge);
    let owner = unsafe { RetainedPayload::try_new(bytes, ledger, &budget) }
        .unwrap_or_else(|(_, _, error)| panic!("original exact pool: {error}"));
    let credit = budget.reserved_bytes();
    let owner = without_allocations(|| {
        assert!(owner.belongs_to(&budget));
        assert!(owner.belongs_to(&same));
        assert!(!owner.belongs_to(&foreign));
        // SAFETY: the one original Vec moves unchanged into a tuple field.
        let owner = unsafe { owner.map_payload(|bytes| (73_u64, bytes)) };
        assert!(owner.belongs_to(&budget));
        assert!(!owner.belongs_to(&foreign));
        assert_eq!(owner.get().1.as_ptr(), pointer);
        owner
    });
    assert_eq!(budget.reserved_bytes(), credit);
    assert_eq!(foreign.reserved_bytes(), 0);
    without_allocations(|| drop(owner));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
#[allow(unsafe_code)]
fn retained_byte_total_counts_original_spare_capacity_and_survives_payload_movement() {
    for ledger_capacity in [0, 3] {
        let budget = AllocationBudget::new(4096);
        let mut ledger = ChargedBuffer::new(ledger_capacity, &budget).unwrap();
        if ledger_capacity == 0 {
            // SAFETY: the unit payload owns no allocations; the zero-capacity
            // ledger is still the actual original-pool ledger owner.
            let owner = unsafe { RetainedPayload::try_new((), ledger, &budget) }
                .unwrap_or_else(|((), _, error)| panic!("empty original ledger: {error}"));
            assert_eq!(without_allocations(|| owner.allocation_bytes()), Some(0));
            drop(owner);
        } else {
            let mut bytes = ChargedBuffer::<u8>::new(17, &budget).unwrap();
            bytes.append(&[7, 11]).unwrap();
            let pointer = bytes.as_slice().as_ptr();
            let exact = 17 + Layout::array::<AllocationCharge>(3).unwrap().size();
            // SAFETY: retain the exact capacity-17 allocation even though only two
            // values are initialized. It moves with its original charge immediately.
            let (bytes, charge) = unsafe { bytes.into_allocation_parts() };
            ledger.push_reserved(charge);
            let owner = unsafe { RetainedPayload::try_new(bytes, ledger, &budget) }
                .unwrap_or_else(|(_, _, error)| panic!("original ledger: {error}"));
            assert_eq!(owner.get().len(), 2);
            assert_eq!(owner.get().capacity(), 17);
            assert_eq!(budget.reserved_bytes(), exact);
            assert_eq!(
                without_allocations(|| owner.allocation_bytes()),
                Some(exact)
            );
            let moved = without_allocations(|| {
                // SAFETY: the identical original allocation moves into one tuple
                // field without cloning, growing, dropping or exporting it.
                unsafe { owner.map_payload(|bytes| (bytes, 31u16)) }
            });
            assert_eq!(moved.get().0.as_ptr(), pointer);
            assert!(moved.belongs_to(&budget));
            assert_eq!(
                without_allocations(|| moved.allocation_bytes()),
                Some(exact)
            );
            assert_eq!(budget.reserved_bytes(), exact);
            drop(moved);
        }
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
