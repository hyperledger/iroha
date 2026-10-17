// SPDX-License-Identifier: MPL-2.0
//! Original shared-shell allocation, refusal, initialization and retirement.

use super::{Allocation, Reserved, Shared};
use crate::test_support::{
    Charge, all_refunded, prepaid, record, refusing_allocation, without_allocations,
};
use std::alloc::Layout;
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

#[repr(align(512))]
struct Aligned(u64);

#[test]
fn exact_padded_shell_initializes_and_clones_without_allocation() {
    let mut funding = prepaid();
    let layout = Reserved::<Aligned, Charge>::layout();
    assert_eq!(layout, Layout::new::<Allocation<Aligned, Charge>>());
    assert_eq!(layout, Shared::<Aligned, Charge>::layout());
    assert_eq!(layout.align(), 512);
    let charge = funding.take_allocation_charge(layout);
    let shell = Reserved::try_new(charge).unwrap_or_else(|_| panic!("admitted shell"));
    let pointer = shell.pointer.as_ptr() as usize;
    assert_eq!(pointer, record(0).pointer);
    assert_eq!(pointer % layout.align(), 0);
    let shared = without_allocations(|| shell.initialize(Aligned(37)));
    assert_eq!(shared.pointer.as_ptr() as usize, pointer);
    assert_eq!(shared.0, 37);
    assert_eq!((std::ptr::from_ref(&*shared) as usize) % 512, 0);
    let other = without_allocations(|| shared.clone());
    assert!(Shared::ptr_eq(&shared, &other));
    without_allocations(|| drop(shared));
    assert!(!record(0).freed);
    without_allocations(|| drop(other));
    all_refunded(&funding);
}

#[test]
fn zero_sized_payload_and_charge_still_use_a_nonzero_original_header() {
    let layout = Reserved::<(), ()>::layout();
    assert_eq!(layout, Layout::new::<Allocation<(), ()>>());
    assert!(layout.size() >= std::mem::size_of::<AtomicUsize>());
    assert!(layout.align() >= std::mem::align_of::<AtomicUsize>());
    let (charge, error) = refusing_allocation(layout, || Reserved::<(), ()>::try_new(()))
        .expect_err("even zero-sized fields require the refcount allocation");
    assert_eq!(error.layout(), layout);
    let shell = Reserved::try_new(charge).unwrap();
    let owner = without_allocations(|| shell.initialize(()));
    without_allocations(|| drop(owner));
}

struct UninitializedPayload;
impl Drop for UninitializedPayload {
    fn drop(&mut self) {
        panic!("an uninitialized payload must never be destroyed");
    }
}

#[test]
fn unused_shell_frees_before_its_original_charge_without_dropping_a_payload() {
    let mut funding = prepaid();
    let layout = Reserved::<UninitializedPayload, Charge>::layout();
    let shell =
        Reserved::<UninitializedPayload, _>::try_new(funding.take_allocation_charge(layout))
            .unwrap_or_else(|_| panic!("admitted shell"));
    assert!(!record(0).freed);
    without_allocations(|| drop(shell));
    all_refunded(&funding);
}

#[test]
fn partial_shell_construction_unwind_reclaims_each_original_allocation() {
    let mut funding = prepaid();
    let layout = Reserved::<UninitializedPayload, Charge>::layout();
    let failure = catch_unwind(AssertUnwindSafe(|| {
        let _first =
            Reserved::<UninitializedPayload, _>::try_new(funding.take_allocation_charge(layout))
                .unwrap_or_else(|_| panic!("first shell"));
        let _second =
            Reserved::<UninitializedPayload, _>::try_new(funding.take_allocation_charge(layout))
                .unwrap_or_else(|_| panic!("second shell"));
        panic!("later preparation refused");
    }));
    assert!(failure.is_err());
    assert_eq!(funding.next, 2);
    all_refunded(&funding);
}

#[derive(Debug)]
struct UniqueCharge {
    identity: Box<u64>,
    drops: Arc<AtomicUsize>,
}
impl Drop for UniqueCharge {
    fn drop(&mut self) {
        assert_eq!(self.drops.fetch_add(1, SeqCst), 0);
    }
}

#[test]
fn actual_null_allocation_returns_the_same_move_only_charge_for_retry() {
    let drops = Arc::new(AtomicUsize::new(0));
    let charge = UniqueCharge {
        identity: Box::new(91),
        drops: Arc::clone(&drops),
    };
    let identity = std::ptr::from_ref(&*charge.identity);
    let layout = Reserved::<Box<u64>, UniqueCharge>::layout();
    // The caller retains a prepared value until the shell actually exists.
    let value = Box::new(23_u64);
    let value_identity = std::ptr::from_ref(&*value);
    let (returned, error) =
        refusing_allocation(layout, || Reserved::<Box<u64>, _>::try_new(charge))
            .expect_err("the original allocation is refused");
    assert_eq!(error.layout(), layout);
    assert_eq!(std::ptr::from_ref(&*returned.identity), identity);
    assert_eq!(drops.load(SeqCst), 0);
    assert_eq!(std::ptr::from_ref(&*value), value_identity);
    let shell = Reserved::try_new(returned).unwrap();
    let owner = without_allocations(|| shell.initialize(value));
    assert_eq!(std::ptr::from_ref(&**owner), value_identity);
    assert_eq!(drops.load(SeqCst), 0);
    drop(owner);
    assert_eq!(drops.load(SeqCst), 1);
}

#[test]
fn null_allocation_returns_charge_without_forcing_a_retry_or_refund() {
    let drops = Arc::new(AtomicUsize::new(0));
    let charge = UniqueCharge {
        identity: Box::new(17),
        drops: Arc::clone(&drops),
    };
    let (returned, _) = refusing_allocation(Reserved::<u64, UniqueCharge>::layout(), || {
        Reserved::<u64, _>::try_new(charge)
    })
    .unwrap_err();
    assert_eq!(drops.load(SeqCst), 0);
    drop(returned);
    assert_eq!(drops.load(SeqCst), 1);
}

#[test]
fn later_shell_refusal_retains_earlier_shell_and_the_original_prepaid_charge() {
    let mut funding = prepaid();
    let layout = Reserved::<u64, Charge>::layout();
    let first = Reserved::<u64, _>::try_new(funding.take_allocation_charge(layout))
        .unwrap_or_else(|_| panic!("first shell"));
    let charge = funding.take_allocation_charge(layout);
    let (returned, error) = refusing_allocation(layout, || Reserved::<u64, _>::try_new(charge))
        .expect_err("second shell refused");
    assert_eq!(error.layout(), layout);
    assert!(!record(0).freed);
    // Prepaid's pending observation stays attached to that original charge:
    // retry consumes no new credit and uses precisely its original layout.
    assert_eq!(funding.next, 2);
    let second = Reserved::try_new(returned).unwrap_or_else(|_| panic!("retry original charge"));
    assert_eq!(funding.next, 2);
    assert_eq!(record(1).layout, layout);
    let first = first.initialize(11);
    let second = second.initialize(29);
    assert!(!Shared::ptr_eq(&first, &second));
    drop(first);
    assert!(!record(1).freed);
    drop(second);
    all_refunded(&funding);
}

struct ObservedPayload<'a>(&'a Cell<usize>);
impl Drop for ObservedPayload<'_> {
    fn drop(&mut self) {
        assert!(
            record(0).freed,
            "payload drop preceded original header free"
        );
        assert!(
            !record(0).refunded,
            "charge drop preceded payload destruction"
        );
        self.0.set(self.0.get() + 1);
    }
}

#[test]
fn final_reference_frees_header_then_payload_then_charge() {
    let mut funding = prepaid();
    let drops = Cell::new(0);
    let layout = Reserved::<ObservedPayload<'_>, Charge>::layout();
    let shell = Reserved::try_new(funding.take_allocation_charge(layout))
        .unwrap_or_else(|_| panic!("admitted shell"));
    let owner = shell.initialize(ObservedPayload(&drops));
    let last = owner.clone();
    drop(owner);
    assert_eq!(drops.get(), 0);
    assert!(!record(0).freed);
    without_allocations(|| drop(last));
    assert_eq!(drops.get(), 1);
    all_refunded(&funding);
}

struct PanicPayload;
impl Drop for PanicPayload {
    fn drop(&mut self) {
        panic!("payload destruction incomplete");
    }
}

#[test]
fn initialized_payload_unwind_retains_charge_conservatively() {
    let drops = Arc::new(AtomicUsize::new(0));
    let charge = UniqueCharge {
        identity: Box::new(43),
        drops: Arc::clone(&drops),
    };
    let shell = Reserved::try_new(charge).unwrap();
    let owner = shell.initialize(PanicPayload);
    assert!(catch_unwind(AssertUnwindSafe(|| drop(owner))).is_err());
    assert_eq!(drops.load(SeqCst), 0);
    // Existing Reclaimed policy deliberately retains the incomplete payload's
    // charge. This is not a successfully refunded allocation.
}

struct PanicCharge(Option<Charge>);
impl Drop for PanicCharge {
    fn drop(&mut self) {
        drop(self.0.take());
        panic!("charge callback failed after original deallocation");
    }
}

#[test]
fn unused_shell_charge_unwind_happens_only_after_deallocation() {
    let mut funding = prepaid();
    let layout = Reserved::<UninitializedPayload, PanicCharge>::layout();
    let shell = Reserved::<UninitializedPayload, _>::try_new(PanicCharge(Some(
        funding.take_allocation_charge(layout),
    )))
    .unwrap_or_else(|_| panic!("admitted shell"));
    assert!(catch_unwind(AssertUnwindSafe(|| drop(shell))).is_err());
    all_refunded(&funding);
}

#[test]
fn one_shot_refusal_does_not_affect_other_layouts_threads_or_later_allocations() {
    let layout = Reserved::<Aligned, ()>::layout();
    let other_layout = Reserved::<u64, ()>::layout();
    assert_ne!(layout, other_layout);
    refusing_allocation(layout, || {
        let other = Reserved::<u64, ()>::try_new(()).unwrap();
        // A different thread can allocate the exact armed layout normally.
        std::thread::scope(|scope| {
            scope.spawn(|| drop(Reserved::<Aligned, ()>::try_new(()).unwrap()));
        });
        let ((), error) = Reserved::<Aligned, ()>::try_new(()).unwrap_err();
        assert_eq!(error.layout(), layout);
        drop(Reserved::<Aligned, ()>::try_new(()).unwrap());
        drop(other);
    });
    drop(Reserved::<u64, ()>::try_new(()).unwrap());
}

#[test]
fn refusal_observer_disarms_when_its_action_unwinds_before_allocation() {
    let layout = Reserved::<Aligned, ()>::layout();
    assert!(
        catch_unwind(|| {
            refusing_allocation(layout, || panic!("abort before allocator"));
        })
        .is_err()
    );
    drop(Reserved::<Aligned, ()>::try_new(()).unwrap());
}

#[test]
fn initialized_shell_can_move_to_another_thread_without_refunding_early() {
    let drops = Arc::new(AtomicUsize::new(0));
    let shell = Reserved::<u64, _>::try_new(UniqueCharge {
        identity: Box::new(57),
        drops: Arc::clone(&drops),
    })
    .unwrap();
    let owner =
        std::thread::scope(|scope| scope.spawn(move || shell.initialize(13)).join().unwrap());
    assert_eq!(*owner, 13);
    assert_eq!(drops.load(SeqCst), 0);
    drop(owner);
    assert_eq!(drops.load(SeqCst), 1);
}

#[test]
fn refusal_error_describes_only_the_exact_allocator_layout() {
    let layout = Reserved::<Aligned, ()>::layout();
    let ((), error) =
        refusing_allocation(layout, || Reserved::<Aligned, ()>::try_new(())).unwrap_err();
    let copied = error;
    assert_eq!(error, copied);
    assert_eq!(error.layout(), layout);
    assert_eq!(
        error.to_string(),
        format!(
            "shared allocation refused ({} bytes, alignment {})",
            layout.size(),
            layout.align()
        )
    );
    assert!(std::error::Error::source(&error).is_none());
}

#[repr(align(1024))]
struct AlignedCharge(Charge);
impl Drop for AlignedCharge {
    fn drop(&mut self) {
        assert_eq!(
            std::mem::size_of_val(&self.0),
            std::mem::size_of::<Charge>()
        );
    }
}

#[test]
fn original_charge_alignment_is_part_of_the_same_exact_allocation() {
    let mut funding = prepaid();
    let layout = Reserved::<u8, AlignedCharge>::layout();
    assert_eq!(layout, Layout::new::<Allocation<u8, AlignedCharge>>());
    assert_eq!(layout.align(), 1024);
    let shell = Reserved::try_new(AlignedCharge(funding.take_allocation_charge(layout)))
        .unwrap_or_else(|_| panic!("aligned charge shell"));
    assert_eq!(record(0).pointer % 1024, 0);
    let owner = shell.initialize(7_u8);
    drop(owner);
    all_refunded(&funding);
}

#[test]
fn unused_large_payload_shell_does_not_require_payload_sized_stack_storage() {
    // The concrete payload layout is much larger than this thread's stack.
    // Reservation initializes only the fixed header fields, never a temporary T.
    std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(|| {
            let shell = Reserved::<[u8; 4 * 1024 * 1024], ()>::try_new(()).unwrap();
            drop(shell);
        })
        .unwrap()
        .join()
        .unwrap();
}
