//! Actual allocator controls for MV's prepaid fixed typed buffer.

#![allow(unsafe_code)]

use iroha_allocation::release::ReleaseRegistration;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    },
    task::{Context, Poll, Wake, Waker},
};

use iroha_allocation::{
    AllocationBudget, AllocationRefusal, ChargedBuffer, ChargedBufferError,
    ChargedBufferFromChargeError,
};

struct ObservedAllocator;

thread_local! {
    static OBSERVE_ALLOCATIONS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static OBSERVED_BUDGET: std::cell::RefCell<Option<AllocationBudget>> = const { std::cell::RefCell::new(None) };
}

static SERIAL: Mutex<()> = Mutex::new(());
static NEXT_SIZE: AtomicUsize = AtomicUsize::new(usize::MAX);
static FAIL_NEXT: AtomicBool = AtomicBool::new(false);
static POINTER: AtomicUsize = AtomicUsize::new(0);
static OBSERVED_COUNT: AtomicUsize = AtomicUsize::new(0);
static RESERVED_AT_ALLOCATION: AtomicUsize = AtomicUsize::new(0);
static REQUESTED_SIZE: AtomicUsize = AtomicUsize::new(0);
static REQUESTED_ALIGN: AtomicUsize = AtomicUsize::new(0);
static FREED_SIZE: AtomicUsize = AtomicUsize::new(0);
static FREED_ALIGN: AtomicUsize = AtomicUsize::new(0);
static FREED: AtomicBool = AtomicBool::new(false);

// End the actual allocator observation before unlocking the shared counters.
struct ResetObservation;
impl Drop for ResetObservation {
    fn drop(&mut self) {
        OBSERVE_ALLOCATIONS.with(|enabled| enabled.set(false));
        NEXT_SIZE.store(usize::MAX, SeqCst);
        FAIL_NEXT.store(false, SeqCst);
        OBSERVED_BUDGET.with(|observed| observed.borrow_mut().take());
    }
}

// Struct fields drop in declaration order: retire the thread-local observer and
// its borrowed budget before another test can acquire the shared counters.
struct SerialObservation {
    _reset: ResetObservation,
    _serial: std::sync::MutexGuard<'static, ()>,
}

fn serial_observation() -> SerialObservation {
    let guard = SERIAL.lock().unwrap();
    SerialObservation {
        _reset: ResetObservation,
        _serial: guard,
    }
}

#[test]
fn observer_retires_before_harness_cleanup_and_the_next_control() {
    {
        let _observation = serial_observation();
        let budget = AllocationBudget::new(0);
        observe_next(0, false, &budget);
        assert!(OBSERVE_ALLOCATIONS.with(std::cell::Cell::get));
    }
    // This is the same thread after the test's local guard has retired. The
    // harness may now allocate capture/result storage while another test runs.
    assert!(!OBSERVE_ALLOCATIONS.with(std::cell::Cell::get));
    assert!(OBSERVED_BUDGET.with(|budget| budget.borrow().is_none()));
    let _observation = serial_observation();
    let before = OBSERVED_COUNT.load(SeqCst);
    let harness_storage = std::hint::black_box(Vec::<u8>::with_capacity(19));
    assert_eq!(OBSERVED_COUNT.load(SeqCst), before);
    drop(harness_storage);
}

fn registration(budget: &AllocationBudget) -> ReleaseRegistration {
    ReleaseRegistration::from_reservation(
        &mut budget
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn child_backing_consumes_parent_credit_before_allocating_without_reacquisition() {
    let _serial = serial_observation();
    let budget = AllocationBudget::new(137);
    let mut parent = budget.try_reserve_bytes(137).unwrap();
    let mut child = parent.try_partition_bytes(137).unwrap();
    observe_next(137, false, &budget);
    let charge = child.try_split(Layout::array::<u8>(137).unwrap()).unwrap();
    let bytes = ChargedBuffer::<u8>::try_from_charge(137, charge).unwrap();
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
fn prepaid_refusal_never_allocates_and_allocator_failure_retains_original_charge_for_retry() {
    let _serial = serial_observation();
    let budget = AllocationBudget::new(113);
    let mut parent = budget.try_reserve_bytes(113).unwrap();
    observe_next(114, false, &budget);
    assert!(parent.try_split(Layout::array::<u8>(114).unwrap()).is_err());
    assert_eq!(NEXT_SIZE.load(SeqCst), 114);
    assert_eq!(parent.remaining_bytes(), 113);
    let layout = Layout::array::<u8>(101).unwrap();
    let charge = parent.try_split(layout).unwrap();
    observe_next(101, true, &budget);
    let (charge, error) = ChargedBuffer::<u8>::try_from_charge(101, charge)
        .err()
        .expect("the observed allocator must refuse backing");
    assert_eq!(error, ChargedBufferFromChargeError::Allocator { layout });
    assert_eq!(charge.layout(), layout);
    assert_eq!(parent.remaining_bytes(), 12);
    assert_eq!(budget.reserved_bytes(), 113);
    assert!(matches!(
        budget.try_reserve_bytes(1),
        Err(AllocationRefusal::Capacity { .. })
    ));
    observe_next(101, false, &budget);
    let bytes = ChargedBuffer::<u8>::try_from_charge(101, charge).unwrap();
    assert_eq!(RESERVED_AT_ALLOCATION.load(SeqCst), 113);
    drop(bytes);
    assert!(FREED.load(SeqCst));
    assert_eq!(budget.reserved_bytes(), 12);
    drop(parent);
    assert_eq!(budget.reserved_bytes(), 0);
}

unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let enabled = OBSERVE_ALLOCATIONS
            .try_with(std::cell::Cell::get)
            .unwrap_or(false);
        if enabled {
            OBSERVED_COUNT.fetch_add(1, SeqCst);
        }
        let observed = enabled
            && NEXT_SIZE
                .compare_exchange(layout.size(), usize::MAX, SeqCst, SeqCst)
                .is_ok();
        if observed {
            let reserved = OBSERVED_BUDGET
                .try_with(|budget| {
                    budget
                        .borrow()
                        .as_ref()
                        .map_or(0, AllocationBudget::reserved_bytes)
                })
                .unwrap_or(0);
            RESERVED_AT_ALLOCATION.store(reserved, SeqCst);
            REQUESTED_SIZE.store(layout.size(), SeqCst);
            REQUESTED_ALIGN.store(layout.align(), SeqCst);
            if FAIL_NEXT.swap(false, SeqCst) {
                return std::ptr::null_mut();
            }
        }
        // SAFETY: forward the exact allocation request to the system allocator.
        let pointer = unsafe { System.alloc(layout) };
        if observed {
            POINTER.store(pointer as usize, SeqCst);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let observed = POINTER
            .compare_exchange(pointer as usize, 0, SeqCst, SeqCst)
            .is_ok();
        // SAFETY: the caller supplies the same pointer/layout as allocation.
        unsafe { System.dealloc(pointer, layout) };
        if observed {
            FREED_SIZE.store(layout.size(), SeqCst);
            FREED_ALIGN.store(layout.align(), SeqCst);
            FREED.store(true, SeqCst);
        }
    }
}

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

fn observe_next(size: usize, fail: bool, budget: &AllocationBudget) {
    OBSERVE_ALLOCATIONS.with(|enabled| enabled.set(false));
    OBSERVED_BUDGET.with(|observed| *observed.borrow_mut() = Some(budget.clone()));
    OBSERVED_COUNT.store(0, SeqCst);
    RESERVED_AT_ALLOCATION.store(0, SeqCst);
    OBSERVE_ALLOCATIONS.with(|enabled| enabled.set(true));
    POINTER.store(0, SeqCst);
    REQUESTED_SIZE.store(0, SeqCst);
    REQUESTED_ALIGN.store(0, SeqCst);
    FREED.store(false, SeqCst);
    FREED_SIZE.store(0, SeqCst);
    FREED_ALIGN.store(0, SeqCst);
    FAIL_NEXT.store(fail, SeqCst);
    NEXT_SIZE.store(size, SeqCst);
}

struct AfterFree {
    budget: AllocationBudget,
    expected: usize,
    expected_align: usize,
    wakes: AtomicUsize,
}

impl Wake for AfterFree {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        assert!(
            FREED.load(SeqCst),
            "refund woke before System.dealloc returned"
        );
        assert_eq!(FREED_SIZE.load(SeqCst), self.expected);
        assert_eq!(FREED_ALIGN.load(SeqCst), self.expected_align);
        assert_eq!(
            self.budget.reserved_bytes(),
            ReleaseRegistration::allocation_layout().size()
        );
        self.wakes.fetch_add(1, SeqCst);
    }
}

#[test]
fn exact_backing_layout_and_charge_survive_fill_until_actual_deallocation() {
    let _serial = serial_observation();
    let budget = AllocationBudget::new(257 + ReleaseRegistration::allocation_layout().size());
    let mut budget_registration = registration(&budget);
    observe_next(257, false, &budget);
    let mut bytes = ChargedBuffer::<u8>::new(257, &budget).unwrap();
    assert_eq!(REQUESTED_SIZE.load(SeqCst), 257);
    assert_eq!(
        RESERVED_AT_ALLOCATION.load(SeqCst),
        257 + ReleaseRegistration::allocation_layout().size()
    );
    assert_eq!(REQUESTED_ALIGN.load(SeqCst), 1);
    let pointer = bytes.as_slice().as_ptr();
    assert_eq!(pointer as usize, POINTER.load(SeqCst));
    bytes.append(&[37; 200]).unwrap();
    bytes.append(&[91; 57]).unwrap();
    assert_eq!(bytes.as_slice(), &[&[37; 200][..], &[91; 57][..]].concat());
    assert_eq!(bytes.as_slice().as_ptr(), pointer);
    assert!(bytes.append(&[0]).is_err());
    assert_eq!(bytes.as_slice().len(), 257);
    assert_eq!(
        budget.reserved_bytes(),
        257 + ReleaseRegistration::allocation_layout().size()
    );
    let Err(AllocationRefusal::Capacity { release, .. }) = budget.try_reserve_bytes(1) else {
        panic!("the actual buffer must still own its charge");
    };
    let observed = Arc::new(AfterFree {
        budget: budget.clone(),
        expected: 257,
        expected_align: 1,
        wakes: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&observed));
    let mut released = pin!(release.wait_for_release(&mut budget_registration));
    assert!(
        released
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    drop(bytes);
    assert_eq!(observed.wakes.load(SeqCst), 1);
    assert!(
        released
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_ready()
    );
}

#[test]
fn capacity_refusal_precedes_allocation_and_original_wait_allows_retry() {
    let _serial = serial_observation();
    let budget = AllocationBudget::new(79 + ReleaseRegistration::allocation_layout().size());
    let mut budget_registration = registration(&budget);
    let occupied = budget.try_reserve_bytes(79).unwrap();
    observe_next(79, false, &budget);
    let Err(ChargedBufferError::Admission(AllocationRefusal::Capacity {
        requested_bytes,
        reserved_bytes,
        limit_bytes,
        release,
    })) = ChargedBuffer::<u8>::new(79, &budget)
    else {
        panic!("capacity must return its original typed refusal");
    };
    assert_eq!(
        (requested_bytes, reserved_bytes, limit_bytes),
        (
            79,
            79 + ReleaseRegistration::allocation_layout().size(),
            79 + ReleaseRegistration::allocation_layout().size()
        )
    );
    assert_eq!(
        NEXT_SIZE.load(SeqCst),
        79,
        "allocator must not run on refusal"
    );
    let mut released = pin!(release.wait_for_release(&mut budget_registration));
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(released.as_mut().poll(&mut context), Poll::Pending);
    drop(occupied);
    assert_eq!(released.as_mut().poll(&mut context), Poll::Ready(()));
    let bytes = ChargedBuffer::<u8>::new(79, &budget).unwrap();
    assert_eq!(REQUESTED_SIZE.load(SeqCst), 79);
    drop(bytes);
    assert!(FREED.load(SeqCst));
    assert_eq!(
        budget.reserved_bytes(),
        ReleaseRegistration::allocation_layout().size()
    );
}

#[test]
fn allocator_failure_returns_unused_charge_without_constructing_a_vec() {
    let _serial = serial_observation();
    let budget = AllocationBudget::new(113);
    observe_next(113, true, &budget);
    let error = match ChargedBuffer::<u8>::new(113, &budget) {
        Err(error) => error,
        Ok(_) => panic!("the observed allocator must refuse this allocation"),
    };
    assert!(matches!(
        error,
        ChargedBufferError::Allocator {
            requested_bytes: 113
        }
    ));
    assert_eq!(
        error.to_string(),
        "failed to allocate 113 admitted buffer bytes"
    );
    assert!(std::error::Error::source(&error).is_none());
    assert_eq!(REQUESTED_SIZE.load(SeqCst), 113);
    assert_eq!(POINTER.load(SeqCst), 0);
    assert!(!FREED.load(SeqCst));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn zero_and_unrepresentable_layouts_never_request_backing_storage() {
    let _serial = serial_observation();
    let budget = AllocationBudget::new(0);
    observe_next(0, false, &budget);
    let mut bytes = ChargedBuffer::<u8>::new(0, &budget).unwrap();
    bytes.append(&[]).unwrap();
    assert!(bytes.as_slice().is_empty());
    assert!(bytes.append(&[1]).is_err());
    drop(bytes);
    assert_eq!(NEXT_SIZE.load(SeqCst), 0);
    NEXT_SIZE.store(usize::MAX, SeqCst);
    let error = match ChargedBuffer::<u8>::new(usize::MAX, &budget) {
        Err(error) => error,
        Ok(_) => panic!("the unrepresentable layout must be refused"),
    };
    assert!(matches!(
        error,
        ChargedBufferError::Admission(AllocationRefusal::DemandOverflow)
    ));
    assert_eq!(
        error.to_string(),
        AllocationRefusal::DemandOverflow.to_string()
    );
    assert!(
        std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<AllocationRefusal>()
            .is_some()
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn unwind_frees_the_original_initialized_buffer_before_refund() {
    let _serial = serial_observation();
    let budget = AllocationBudget::new(191);
    observe_next(191, false, &budget);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut bytes = ChargedBuffer::<u8>::new(191, &budget).unwrap();
        bytes.append(&[9; 87]).unwrap();
        assert_eq!(budget.reserved_bytes(), 191);
        panic!("injected snapshot decode unwind");
    }));
    assert!(result.is_err());
    assert!(FREED.load(SeqCst));
    assert_eq!(
        (FREED_SIZE.load(SeqCst), FREED_ALIGN.load(SeqCst)),
        (191, 1)
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn simultaneous_buffers_share_capacity_until_their_actual_owners_drop() {
    let _serial = serial_observation();
    let budget = AllocationBudget::new(128);
    let mut first = ChargedBuffer::<u8>::new(64, &budget).unwrap();
    first.append(&[13; 64]).unwrap();
    let second = ChargedBuffer::<u8>::new(64, &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), 128);
    assert!(matches!(
        ChargedBuffer::<u8>::new(1, &budget),
        Err(ChargedBufferError::Admission(
            AllocationRefusal::Capacity { .. }
        ))
    ));
    std::thread::spawn(move || {
        assert_eq!(first.as_slice(), &[13; 64]);
        drop(first);
    })
    .join()
    .unwrap();
    assert_eq!(budget.reserved_bytes(), 64);
    let retry = ChargedBuffer::<u8>::new(64, &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), 128);
    drop((retry, second));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn aligned_copy_elements_use_exact_typed_layout_before_allocation() {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(align(128))]
    struct Entry([u8; 33]);

    let _serial = serial_observation();
    let layout = Layout::array::<Entry>(3).unwrap();
    let budget = AllocationBudget::new(layout.size());
    observe_next(layout.size(), false, &budget);
    let mut entries = ChargedBuffer::<Entry>::new(3, &budget).unwrap();
    assert_eq!(REQUESTED_SIZE.load(SeqCst), layout.size());
    assert_eq!(REQUESTED_ALIGN.load(SeqCst), layout.align());
    assert_eq!(RESERVED_AT_ALLOCATION.load(SeqCst), layout.size());
    assert_eq!(entries.as_slice().as_ptr() as usize % layout.align(), 0);
    assert_eq!(entries.capacity(), 3);
    let pointer = entries.as_slice().as_ptr();
    let allocations = OBSERVED_COUNT.load(SeqCst);
    entries.append(&[Entry([9; 33]), Entry([4; 33])]).unwrap();
    entries.as_mut_slice()[0] = Entry([3; 33]);
    assert!(entries.append(&[Entry([1; 33]); 2]).is_err());
    assert_eq!(entries.as_slice(), &[Entry([3; 33]), Entry([4; 33])]);
    entries.append(&[Entry([1; 33])]).unwrap();
    assert_eq!(entries.as_slice().as_ptr(), pointer);
    assert_eq!(OBSERVED_COUNT.load(SeqCst), allocations);
    assert_eq!(budget.reserved_bytes(), layout.size());
    drop(entries);
    assert!(FREED.load(SeqCst));
    assert_eq!(FREED_SIZE.load(SeqCst), layout.size());
    assert_eq!(FREED_ALIGN.load(SeqCst), layout.align());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn canonical_hash_batch_sort_and_prefix_compaction_preserve_original_allocation() {
    let _serial = serial_observation();
    let layout = Layout::array::<[u8; 32]>(8).unwrap();
    let budget = AllocationBudget::new(layout.size());
    observe_next(layout.size(), false, &budget);
    let mut hashes = ChargedBuffer::<[u8; 32]>::new(8, &budget).unwrap();
    let pointer = hashes.as_slice().as_ptr();
    let allocations = OBSERVED_COUNT.load(SeqCst);
    hashes
        .append(&[[9; 32], [1; 32], [9; 32], [4; 32], [1; 32]])
        .unwrap();
    hashes.as_mut_slice().sort_unstable();
    let mut unique = 0;
    for index in 0..hashes.as_slice().len() {
        let hash = hashes.as_slice()[index];
        if unique == 0 || hashes.as_slice()[unique - 1] != hash {
            hashes.as_mut_slice()[unique] = hash;
            unique += 1;
        }
    }
    hashes.truncate(unique);
    hashes.truncate(usize::MAX);
    assert_eq!(hashes.as_slice(), &[[1; 32], [4; 32], [9; 32]]);
    assert_eq!(hashes.capacity(), 8);
    assert_eq!(hashes.as_slice().as_ptr(), pointer);
    assert_eq!(budget.reserved_bytes(), layout.size());
    assert_eq!(OBSERVED_COUNT.load(SeqCst), allocations);
    hashes.truncate(0);
    hashes.append(&[[7; 32]; 8]).unwrap();
    assert!(hashes.append(&[[8; 32]]).is_err());
    assert_eq!(hashes.as_slice(), &[[7; 32]; 8]);
    assert_eq!(hashes.as_slice().as_ptr(), pointer);
    assert_eq!(budget.reserved_bytes(), layout.size());
    drop(hashes);
    assert!(FREED.load(SeqCst));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn zero_sized_elements_obey_logical_capacity_without_allocation() {
    #[derive(Clone, Copy)]
    #[repr(align(256))]
    struct Entry;

    let _serial = serial_observation();
    let budget = AllocationBudget::new(0);
    observe_next(0, false, &budget);
    let allocations = OBSERVED_COUNT.load(SeqCst);
    let mut entries = ChargedBuffer::<Entry>::new(2, &budget).unwrap();
    assert_eq!(entries.capacity(), 2);
    assert_eq!(entries.as_slice().as_ptr() as usize % 256, 0);
    entries.append(&[Entry; 2]).unwrap();
    assert!(entries.append(&[Entry]).is_err());
    assert_eq!(entries.as_slice().len(), 2);
    entries.truncate(1);
    entries.append(&[Entry]).unwrap();
    entries.as_mut_slice()[0] = Entry;
    assert_eq!(entries.as_slice().len(), 2);
    drop(entries);
    assert_eq!(NEXT_SIZE.load(SeqCst), 0);
    assert_eq!(OBSERVED_COUNT.load(SeqCst), allocations);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn typed_layout_overflow_is_refused_before_reservation_or_allocation() {
    let _serial = serial_observation();
    let budget = AllocationBudget::new(usize::MAX);
    observe_next(1, false, &budget);
    let allocations = OBSERVED_COUNT.load(SeqCst);
    let result = ChargedBuffer::<[u64; 4]>::new(usize::MAX / 16, &budget);
    assert!(matches!(
        result,
        Err(ChargedBufferError::Admission(
            AllocationRefusal::DemandOverflow
        ))
    ));
    assert_eq!(NEXT_SIZE.load(SeqCst), 1);
    assert_eq!(OBSERVED_COUNT.load(SeqCst), allocations);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn appending_copy_elements_never_invokes_payload_clone() {
    #[derive(Copy, Debug, PartialEq, Eq)]
    struct Entry(u64);

    #[expect(
        clippy::non_canonical_clone_impl,
        clippy::expl_impl_clone_on_copy,
        reason = "prove the Copy append never invokes user Clone code"
    )]
    impl Clone for Entry {
        fn clone(&self) -> Self {
            panic!("a fixed Copy append must not call user Clone code");
        }
    }

    let _serial = serial_observation();
    let budget = AllocationBudget::new(16);
    let mut entries = ChargedBuffer::<Entry>::new(2, &budget).unwrap();
    entries.append(&[Entry(4), Entry(8)]).unwrap();
    assert_eq!(entries.as_slice(), &[Entry(4), Entry(8)]);
    entries.truncate(1);
    entries.append(&[Entry(9)]).unwrap();
    assert_eq!(entries.as_slice(), &[Entry(4), Entry(9)]);
    drop(entries);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn non_copy_elements_move_into_exact_backing_and_drop_before_refund() {
    #[repr(align(128))]
    struct DropEntry<'a> {
        id: usize,
        drops: &'a [AtomicUsize; 5],
        budget: &'a AllocationBudget,
        retained_bytes: usize,
    }

    impl Drop for DropEntry<'_> {
        fn drop(&mut self) {
            assert!(!FREED.load(SeqCst), "element dropped after backing free");
            assert_eq!(self.budget.reserved_bytes(), self.retained_bytes);
            self.drops[self.id].fetch_add(1, SeqCst);
        }
    }

    let _serial = serial_observation();
    let layout = Layout::array::<DropEntry<'_>>(3).unwrap();
    let budget =
        AllocationBudget::new(layout.size() + ReleaseRegistration::allocation_layout().size());
    let mut budget_registration = registration(&budget);
    let drops = std::array::from_fn(|_| AtomicUsize::new(0));
    let observer = Arc::new(AfterFree {
        budget: budget.clone(),
        expected: layout.size(),
        expected_align: layout.align(),
        wakes: AtomicUsize::new(0),
    });
    let original = budget
        .try_reserve(layout)
        .unwrap()
        .try_split(layout)
        .unwrap();
    observe_next(layout.size(), false, &budget);
    let mut entries = ChargedBuffer::<DropEntry<'_>>::try_from_charge(3, original).unwrap();
    assert_eq!(REQUESTED_SIZE.load(SeqCst), layout.size());
    assert_eq!(REQUESTED_ALIGN.load(SeqCst), layout.align());
    assert_eq!(
        RESERVED_AT_ALLOCATION.load(SeqCst),
        layout.size() + ReleaseRegistration::allocation_layout().size()
    );
    let pointer = entries.as_slice().as_ptr();
    let allocations = OBSERVED_COUNT.load(SeqCst);
    let entry = |id| DropEntry {
        id,
        drops: &drops,
        budget: &budget,
        retained_bytes: layout.size() + ReleaseRegistration::allocation_layout().size(),
    };
    assert!(entries.try_push(entry(0)).is_ok());
    assert!(entries.try_push(entry(1)).is_ok());
    assert!(entries.try_push(entry(2)).is_ok());
    let rejected = entries.try_push(entry(3)).err().unwrap();
    assert_eq!(entries.as_slice().len(), 3);
    assert_eq!(drops[3].load(SeqCst), 0, "refusal retains the input owner");
    drop(rejected);
    assert_eq!(drops[3].load(SeqCst), 1);
    entries.truncate(1);
    assert_eq!(drops[1].load(SeqCst), 1);
    assert_eq!(drops[2].load(SeqCst), 1);
    assert_eq!(
        budget.reserved_bytes(),
        layout.size() + ReleaseRegistration::allocation_layout().size()
    );
    assert!(entries.try_push(entry(4)).is_ok());
    assert_eq!(entries.as_slice().as_ptr(), pointer);
    assert_eq!(OBSERVED_COUNT.load(SeqCst), allocations);

    let Err(AllocationRefusal::Capacity { release, .. }) = budget.try_reserve_bytes(1) else {
        panic!("the original backing charge must remain occupied");
    };
    let waker = Waker::from(Arc::clone(&observer));
    let mut released = pin!(release.wait_for_release(&mut budget_registration));
    assert!(
        released
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    drop(entries);
    assert_eq!(observer.wakes.load(SeqCst), 1);
    assert!(
        released
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_ready()
    );
    assert_eq!(FREED_SIZE.load(SeqCst), layout.size());
    assert_eq!(FREED_ALIGN.load(SeqCst), layout.align());
    assert!(drops.iter().all(|count| count.load(SeqCst) == 1));
}

#[test]
fn non_copy_zero_sized_elements_keep_logical_capacity_and_drop_once() {
    #[repr(align(256))]
    struct DropZst;

    static DROPS: AtomicUsize = AtomicUsize::new(0);

    impl Drop for DropZst {
        fn drop(&mut self) {
            DROPS.fetch_add(1, SeqCst);
        }
    }

    let _serial = serial_observation();
    DROPS.store(0, SeqCst);
    let budget = AllocationBudget::new(0);
    observe_next(0, false, &budget);
    let allocations = OBSERVED_COUNT.load(SeqCst);
    let mut entries = ChargedBuffer::<DropZst>::new(2, &budget).unwrap();
    assert_eq!(entries.capacity(), 2);
    assert_eq!(entries.as_slice().as_ptr() as usize % 256, 0);
    assert!(entries.try_push(DropZst).is_ok());
    assert!(entries.try_push(DropZst).is_ok());
    let rejected = entries.try_push(DropZst).err().unwrap();
    assert_eq!(entries.as_slice().len(), 2);
    assert_eq!(DROPS.load(SeqCst), 0);
    drop(rejected);
    assert_eq!(DROPS.load(SeqCst), 1);
    entries.truncate(1);
    assert_eq!(DROPS.load(SeqCst), 2);
    assert!(entries.try_push(DropZst).is_ok());
    drop(entries);
    assert_eq!(DROPS.load(SeqCst), 4);
    assert_eq!(NEXT_SIZE.load(SeqCst), 0);
    assert_eq!(OBSERVED_COUNT.load(SeqCst), allocations);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[path = "charged_buffer_custody/from_charge.rs"]
mod from_charge;

#[path = "charged_buffer_custody/from_reservation.rs"]
mod from_reservation;
