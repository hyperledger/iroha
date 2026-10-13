//! Compact admission errors preserve allocation-free local conversion and retry ownership.

use iroha_allocation::{AllocationBudget, release::ReleaseRegistration};
use ivm_abi::{
    VMError,
    error::{AllocationRefusal, ExecutionDeferral},
};
use ivm_artifact_admission::ContractArtifactError;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

struct ObservedAllocator;

thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}

fn record_request() {
    let _ = ALLOCATIONS.try_with(|count| {
        if let Some(observed) = count.get() {
            count.set(Some(observed + 1));
        }
    });
}

// Test-only observation forwards exact requests to System; production code has
// no allocator hook. Every unsafe operation retains the original allocator contract.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_request();
        // SAFETY: forward the unchanged nonzero, valid allocation layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_request();
        // SAFETY: forward the unchanged nonzero, valid allocation layout.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_request();
        // SAFETY: forward the caller's original pointer/layout and valid new size.
        unsafe { System.realloc(pointer, layout, size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: forward the original system-owned pointer and matching layout.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

fn without_allocations<T>(operation: impl FnOnce() -> T) -> T {
    ALLOCATIONS.with(|count| count.set(Some(0)));
    let result = operation();
    let allocations = ALLOCATIONS.with(|count| count.replace(None).unwrap());
    assert_eq!(allocations, 0, "local conversion must not request storage");
    result
}

#[test]
fn local_reasons_and_nested_metering_convert_without_allocating() {
    for fixture in 0..5 {
        for depth in 0..=2 {
            let original = [
                VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable),
                VMError::ExecutionDeferred(ExecutionDeferral::ActiveMemoryCapacity),
                VMError::ExecutionDeferred(ExecutionDeferral::VerifierArtifactsUnavailable),
                VMError::AllocationDeferred(AllocationRefusal::DemandOverflow),
                VMError::AllocationDeferred(AllocationRefusal::ExceedsLimit {
                    requested_bytes: 9,
                    limit_bytes: 8,
                }),
            ]
            .into_iter()
            .nth(fixture)
            .unwrap();
            let expected_reason = original.execution_deferral();
            let expected_allocation = match &original {
                VMError::AllocationDeferred(original) => Some(original.clone()),
                VMError::ExecutionDeferred(_) => None,
                _ => unreachable!("fixture consists of exact local variants"),
            };
            let expected_display = original.to_string();
            let mut wrapped = original;
            for _ in 0..depth {
                wrapped = VMError::Metered {
                    gas: 91,
                    source: Box::new(wrapped),
                };
            }
            let error = without_allocations(|| {
                ContractArtifactError::preparation("decoded instructions", wrapped)
            });
            assert_eq!(
                error.to_string(),
                format!(
                    "contract preparation deferred during decoded instructions: {expected_display}"
                )
            );
            let converted = without_allocations(|| error.into_vm_error());
            assert_eq!(converted.execution_deferral(), expected_reason);
            match (&converted, expected_allocation.as_ref()) {
                (VMError::AllocationDeferred(actual), Some(expected)) => {
                    assert_eq!(actual, expected)
                }
                (VMError::ExecutionDeferred(_), None) => {}
                _ => panic!("conversion changed the exact local owner variant"),
            }
            assert_eq!(converted.metered_gas(), None);
        }
    }
}

#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn original_capacity_refusal_survives_unmetered_conversion_and_wakes_only_on_its_pool() {
    let observer_bytes = ReleaseRegistration::allocation_layout().size();
    let budget = AllocationBudget::new(8 + observer_bytes);
    let mut registration = ReleaseRegistration::from_reservation(
        &mut budget
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap(),
    )
    .unwrap();
    assert!(registration.belongs_to(&budget));
    let occupied = budget.try_reserve_bytes(8).unwrap();
    let refusal = budget.try_reserve_bytes(1).unwrap_err();
    let original = VMError::AllocationDeferred(refusal.clone());
    let wrapped = VMError::Metered {
        gas: 123,
        source: Box::new(VMError::Metered {
            gas: 456,
            source: Box::new(original),
        }),
    };
    let converted = without_allocations(|| {
        ContractArtifactError::preparation("prepared operations", wrapped).into_vm_error()
    });
    assert!(matches!(&converted, VMError::AllocationDeferred(actual) if actual == &refusal));
    assert_eq!(converted.metered_gas(), None);
    let VMError::AllocationDeferred(AllocationRefusal::Capacity { release, .. }) = converted else {
        panic!("must preserve the actual release owner");
    };
    let wake_count = Arc::new(Wakes::default());
    let waker = Waker::from(Arc::clone(&wake_count));
    let mut context = Context::from_waker(&waker);
    assert_eq!(
        registration.poll_wait(&release, &mut context),
        Poll::Pending
    );
    let unrelated = AllocationBudget::new(8);
    drop(unrelated.try_reserve_bytes(8).unwrap());
    assert_eq!(wake_count.0.load(Ordering::SeqCst), 0);
    assert_eq!(
        registration.poll_wait(&release, &mut context),
        Poll::Pending
    );
    drop(occupied);
    assert_eq!(wake_count.0.load(Ordering::SeqCst), 1);
    assert_eq!(
        registration.poll_wait(&release, &mut context),
        Poll::Ready(())
    );
    assert_eq!(budget.reserved_bytes(), observer_bytes);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn exact_abi_hash_pair_conversion_does_not_require_a_box() {
    let expected = [0xA3; 32];
    let actual = [0x5C; 32];
    let error = without_allocations(|| {
        ContractArtifactError::abi_hash_mismatch(expected, actual).into_vm_error()
    });
    assert!(match (
        &(error),
        &(VMError::ArtifactAbiHashMismatch { expected, actual })
    ) {
        (
            VMError::ArtifactAbiHashMismatch {
                expected: actual_field_0,
                actual: actual_field_1,
            },
            VMError::ArtifactAbiHashMismatch {
                expected: expected_field_0,
                actual: expected_field_1,
            },
        ) => actual_field_0 == expected_field_0 && actual_field_1 == expected_field_1,
        _ => false,
    });
}
