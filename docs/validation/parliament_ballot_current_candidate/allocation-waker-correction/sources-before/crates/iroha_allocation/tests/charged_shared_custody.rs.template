//! Physical allocation and final-owner controls for exact prepaid shared nodes.

#![allow(unsafe_code)]

use iroha_allocation::release::ReleaseRegistration;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::{Cell, RefCell},
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::pin,
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    },
    task::{Context, Poll, Wake, Waker},
};

use iroha_allocation::shared::Shared;
use iroha_allocation::{
    AllocationBudget, AllocationRefusal, ChargedShared, InsufficientReservation, PrepaidSharedError,
};

struct ObservedAllocator;

struct Observation {
    pointer: AtomicUsize,
    requested_size: AtomicUsize,
    requested_align: AtomicUsize,
    reserved: AtomicUsize,
    freed_size: AtomicUsize,
    freed_align: AtomicUsize,
    freed: AtomicBool,
}

impl Observation {
    const fn new() -> Self {
        Self {
            pointer: AtomicUsize::new(0),
            requested_size: AtomicUsize::new(0),
            requested_align: AtomicUsize::new(0),
            reserved: AtomicUsize::new(0),
            freed_size: AtomicUsize::new(0),
            freed_align: AtomicUsize::new(0),
            freed: AtomicBool::new(false),
        }
    }

    fn reset(&self) {
        assert_eq!(self.pointer.load(SeqCst), 0);
        self.requested_size.store(0, SeqCst);
        self.requested_align.store(0, SeqCst);
        self.reserved.store(0, SeqCst);
        self.freed_size.store(0, SeqCst);
        self.freed_align.store(0, SeqCst);
        self.freed.store(false, SeqCst);
    }
}

const SLOT_COUNT: usize = 8;
static OBSERVED: [Observation; SLOT_COUNT] = [const { Observation::new() }; SLOT_COUNT];
static SERIAL: Mutex<()> = Mutex::new(());
thread_local! {
    static NEXT_SLOT: Cell<Option<(usize, bool)>> = const { Cell::new(None) };
    static BUDGET: RefCell<Option<AllocationBudget>> = const { RefCell::new(None) };
}

// Test-only forwarding observes exact System allocations; production MV has no
// added unsafe code. There are no assertions or allocating operations here.
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let selected = NEXT_SLOT.try_with(Cell::take).unwrap_or(None);
        if let Some((slot, fail)) = selected {
            let observed = &OBSERVED[slot];
            observed.requested_size.store(layout.size(), SeqCst);
            observed.requested_align.store(layout.align(), SeqCst);
            let reserved = BUDGET
                .try_with(|budget| {
                    budget
                        .borrow()
                        .as_ref()
                        .map_or(0, AllocationBudget::reserved_bytes)
                })
                .unwrap_or(0);
            observed.reserved.store(reserved, SeqCst);
            if fail {
                return std::ptr::null_mut();
            }
        }
        // SAFETY: forward the caller's exact nonzero layout to System.
        let pointer = unsafe { System.alloc(layout) };
        if let Some((slot, _)) = selected {
            OBSERVED[slot].pointer.store(pointer as usize, SeqCst);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let observed = OBSERVED.iter().find(|slot| {
            slot.pointer
                .compare_exchange(pointer as usize, 0, SeqCst, SeqCst)
                .is_ok()
        });
        // SAFETY: the caller returns the exact allocation and layout to System.
        unsafe { System.dealloc(pointer, layout) };
        if let Some(observed) = observed {
            observed.freed_size.store(layout.size(), SeqCst);
            observed.freed_align.store(layout.align(), SeqCst);
            observed.freed.store(true, SeqCst);
        }
    }
}

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

fn observe_next(slot: usize, fail: bool, budget: Option<&AllocationBudget>) {
    NEXT_SLOT.with(|next| next.set(None));
    OBSERVED[slot].reset();
    BUDGET.with(|observed| *observed.borrow_mut() = budget.cloned());
    NEXT_SLOT.with(|next| next.set(Some((slot, fail))));
}

fn disarm() {
    NEXT_SLOT.with(|next| next.set(None));
}

fn assert_allocation(slot: usize, layout: Layout, reserved: usize) {
    assert_eq!(OBSERVED[slot].requested_size.load(SeqCst), layout.size());
    assert_eq!(OBSERVED[slot].requested_align.load(SeqCst), layout.align());
    assert_eq!(OBSERVED[slot].reserved.load(SeqCst), reserved);
}

fn assert_freed(slot: usize, layout: Layout) {
    assert!(OBSERVED[slot].freed.load(SeqCst));
    assert_eq!(OBSERVED[slot].freed_size.load(SeqCst), layout.size());
    assert_eq!(OBSERVED[slot].freed_align.load(SeqCst), layout.align());
}

#[derive(Debug)]
#[repr(align(128))]
struct AlignedPayload(u64);

fn registration(budget: &AllocationBudget) -> ReleaseRegistration {
    ReleaseRegistration::from_reservation(
        &mut budget
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn reserved_shared_shell_funds_physical_control_before_consumption_and_final_release() {
    let _serial = SERIAL.lock().unwrap();
    let layout = ChargedShared::<AlignedPayload>::allocation_layout();
    let budget = AllocationBudget::new(layout.size());
    let mut parent = budget.try_reserve_bytes(layout.size()).unwrap();
    observe_next(0, true, Some(&budget));
    let error = ChargedShared::<AlignedPayload>::reserve_from(&mut parent)
        .err()
        .expect("physical allocator must refuse the original shell");
    disarm();
    assert!(matches!(error, PrepaidSharedError::Allocator { .. }));
    assert_allocation(0, layout, layout.size());
    assert_eq!(budget.reserved_bytes(), 0);
    drop(parent);
    let mut parent = budget.try_reserve_bytes(layout.size()).unwrap();
    observe_next(1, false, Some(&budget));
    let shell = ChargedShared::<AlignedPayload>::reserve_from(&mut parent).unwrap();
    disarm();
    assert_allocation(1, layout, layout.size());
    budget.set_limit_bytes(0);
    observe_next(2, true, Some(&budget));
    let owner = shell.initialize(AlignedPayload(91));
    disarm();
    assert_eq!(OBSERVED[2].requested_size.load(SeqCst), 0);
    assert!(owner.belongs_to(&budget));
    let last = owner.clone();
    drop(owner);
    assert!(!OBSERVED[1].freed.load(SeqCst));
    assert_eq!(budget.reserved_bytes(), layout.size());
    assert_eq!(last.0, 91);
    drop(last);
    assert_freed(1, layout);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn exact_aligned_layout_partitions_original_credit_after_budget_shrink() {
    let _serial = SERIAL.lock().unwrap();
    let layout = ChargedShared::<AlignedPayload>::allocation_layout();
    assert_eq!(layout.align(), 128);
    let budget = AllocationBudget::new(layout.size() * 2);
    let mut parent = budget.try_reserve_bytes(layout.size() * 2).unwrap();
    let mut child = parent.try_partition_bytes(layout.size()).unwrap();
    budget.set_limit_bytes(0);
    observe_next(0, false, Some(&budget));
    let owner = ChargedShared::from_reservation(AlignedPayload(37), &mut child).unwrap();
    disarm();
    assert_allocation(0, layout, layout.size() * 2);
    assert_eq!(child.remaining_bytes(), 0);
    assert_eq!(parent.remaining_bytes(), layout.size());
    assert_eq!((*owner).0, 37);
    observe_next(1, false, Some(&budget));
    let borrower = owner.clone();
    disarm();
    assert!(ChargedShared::ptr_eq(&owner, &borrower));
    assert_eq!(OBSERVED[1].requested_size.load(SeqCst), 0);
    drop(owner);
    drop(child);
    drop(parent);
    assert_eq!(budget.reserved_bytes(), layout.size());
    assert!(!OBSERVED[0].freed.load(SeqCst));
    drop(borrower);
    assert_freed(0, layout);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn zero_and_short_prepaid_refusals_do_not_call_the_allocator() {
    let _serial = SERIAL.lock().unwrap();
    let layout = ChargedShared::<()>::allocation_layout();
    assert!(
        layout.size() > 0,
        "even a ZST needs physical reference custody"
    );
    for available in [0, layout.size() - 1] {
        let budget = AllocationBudget::new(available);
        let mut parent = budget.try_reserve_bytes(available).unwrap();
        observe_next(0, true, Some(&budget));
        let result = ChargedShared::from_reservation((), &mut parent);
        disarm();
        assert!(matches!(result, Err(((), PrepaidSharedError::Reservation(
            InsufficientReservation { requested_bytes, remaining_bytes }
        ))) if requested_bytes == layout.size() && remaining_bytes == available));
        assert_eq!(OBSERVED[0].requested_size.load(SeqCst), 0);
        assert_eq!(parent.remaining_bytes(), available);
        assert_eq!(budget.reserved_bytes(), available);
        drop(parent);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    let budget = AllocationBudget::new(layout.size());
    let mut parent = budget.try_reserve_bytes(layout.size()).unwrap();
    observe_next(0, false, Some(&budget));
    let owner = ChargedShared::from_reservation((), &mut parent).unwrap();
    disarm();
    assert_allocation(0, layout, layout.size());
    drop(owner);
    assert_freed(0, layout);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn allocator_refusal_returns_original_payload_and_refunds_only_its_split() {
    let _serial = SERIAL.lock().unwrap();
    let value = Box::new(41_u64);
    let value_pointer = std::ptr::from_ref(&*value);
    let layout = ChargedShared::<Box<u64>>::allocation_layout();
    let budget = AllocationBudget::new(layout.size() + 17);
    let mut parent = budget.try_reserve_bytes(layout.size() + 17).unwrap();
    observe_next(0, true, Some(&budget));
    let result = ChargedShared::from_reservation(value, &mut parent);
    disarm();
    let (value, error) = result.unwrap_err();
    assert_eq!(std::ptr::from_ref(&*value), value_pointer);
    assert_eq!(*value, 41);
    assert_eq!(
        error,
        PrepaidSharedError::Allocator {
            requested_bytes: layout.size()
        }
    );
    assert_allocation(0, layout, layout.size() + 17);
    assert_eq!(OBSERVED[0].pointer.load(SeqCst), 0);
    assert!(!OBSERVED[0].freed.load(SeqCst));
    assert_eq!(parent.remaining_bytes(), 17);
    assert_eq!(budget.reserved_bytes(), 17);
    drop(value);
    drop(parent);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[derive(Debug)]
struct DropCount(Arc<AtomicUsize>);
impl Drop for DropCount {
    fn drop(&mut self) {
        self.0.fetch_add(1, SeqCst);
    }
}

#[test]
fn primitive_allocator_failure_returns_both_original_owners_undropped() {
    let _serial = SERIAL.lock().unwrap();
    let values = Arc::new(AtomicUsize::new(0));
    let charges = Arc::new(AtomicUsize::new(0));
    let value = DropCount(Arc::clone(&values));
    let charge = DropCount(Arc::clone(&charges));
    observe_next(0, true, None);
    let result = Shared::try_new(value, charge);
    disarm();
    let (value, charge, error) = result.unwrap_err();
    assert_eq!(error.layout(), Shared::<DropCount, DropCount>::layout());
    assert_allocation(0, Shared::<DropCount, DropCount>::layout(), 0);
    assert_eq!(values.load(SeqCst), 0);
    assert_eq!(charges.load(SeqCst), 0);
    assert!(Arc::ptr_eq(&values, &value.0));
    assert!(Arc::ptr_eq(&charges, &charge.0));
    drop(value);
    drop(charge);
    assert_eq!(values.load(SeqCst), 1);
    assert_eq!(charges.load(SeqCst), 1);
}

#[derive(Debug)]
struct Probe {
    slot: usize,
    budget: AllocationBudget,
    dropped: Arc<AtomicUsize>,
}
impl Drop for Probe {
    fn drop(&mut self) {
        let layout = ChargedShared::<Self>::allocation_layout();
        assert_freed(self.slot, layout);
        assert!(self.budget.reserved_bytes() >= layout.size());
        self.dropped.fetch_add(1, SeqCst);
    }
}

struct AfterPayload {
    budget: AllocationBudget,
    dropped: Arc<AtomicUsize>,
    size: usize,
    wakes: AtomicUsize,
}
impl Wake for AfterPayload {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        assert_eq!(self.dropped.load(SeqCst), 1);
        assert!(OBSERVED[0].freed.load(SeqCst));
        assert_eq!(
            self.budget.reserved_bytes(),
            ReleaseRegistration::allocation_layout().size()
        );
        let reentrant = self.budget.try_reserve_bytes(self.size).unwrap();
        drop(reentrant);
        self.wakes.fetch_add(1, SeqCst);
    }
}

#[test]
fn final_concurrent_clone_frees_payload_before_original_pool_reentrant_wake() {
    let _serial = SERIAL.lock().unwrap();
    let layout = ChargedShared::<Probe>::allocation_layout();
    let budget =
        AllocationBudget::new(layout.size() + ReleaseRegistration::allocation_layout().size());
    let mut budget_registration = registration(&budget);
    let dropped = Arc::new(AtomicUsize::new(0));
    let value = Probe {
        slot: 0,
        budget: budget.clone(),
        dropped: Arc::clone(&dropped),
    };
    let mut parent = budget.try_reserve_bytes(layout.size()).unwrap();
    observe_next(0, false, Some(&budget));
    let owner = ChargedShared::from_reservation(value, &mut parent).unwrap();
    disarm();
    drop(parent);
    let Err(AllocationRefusal::Capacity { release, .. }) = budget.try_reserve_bytes(1) else {
        panic!("the original owner must retain its credit");
    };
    let observer = Arc::new(AfterPayload {
        budget: budget.clone(),
        dropped: Arc::clone(&dropped),
        size: layout.size(),
        wakes: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&observer));
    let mut wait = pin!(release.wait_for_release(&mut budget_registration));
    let mut context = Context::from_waker(&waker);
    assert_eq!(wait.as_mut().poll(&mut context), Poll::Pending);
    let unrelated = AllocationBudget::new(layout.size());
    drop(unrelated.try_reserve_bytes(layout.size()).unwrap());
    assert_eq!(wait.as_mut().poll(&mut context), Poll::Pending);
    let barrier = Barrier::new(8);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let copy = owner.clone();
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                drop(copy);
            });
        }
        drop(owner);
    });
    assert_freed(0, layout);
    assert_eq!(dropped.load(SeqCst), 1);
    assert_eq!(
        budget.reserved_bytes(),
        ReleaseRegistration::allocation_layout().size()
    );
    assert_eq!(observer.wakes.load(SeqCst), 1);
    assert_eq!(wait.as_mut().poll(&mut context), Poll::Ready(()));
}

#[derive(Debug)]
struct Node {
    slot: usize,
    children: [Option<ChargedShared<Node>>; 2],
    budget: AllocationBudget,
    dropped: Arc<AtomicUsize>,
}
impl Drop for Node {
    fn drop(&mut self) {
        assert_freed(self.slot, ChargedShared::<Self>::allocation_layout());
        assert!(self.budget.reserved_bytes() >= ChargedShared::<Self>::allocation_layout().size());
        self.dropped.fetch_add(1, SeqCst);
    }
}

#[test]
fn recursive_shared_nodes_retain_borrowed_leaf_charge_after_other_nodes_are_freed() {
    let _serial = SERIAL.lock().unwrap();
    let layout = ChargedShared::<Node>::allocation_layout();
    let budget = AllocationBudget::new(layout.size() * 4);
    let mut parent = budget.try_reserve_bytes(layout.size() * 4).unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let (leaf, root) = {
        let mut make = |slot, children| {
            let value = Node {
                slot,
                children,
                budget: budget.clone(),
                dropped: Arc::clone(&dropped),
            };
            observe_next(slot, false, Some(&budget));
            let node = ChargedShared::from_reservation(value, &mut parent).unwrap();
            disarm();
            assert_allocation(slot, layout, layout.size() * 4);
            node
        };
        let leaf = make(0, [None, None]);
        let left = make(1, [Some(leaf.clone()), None]);
        let right = make(2, [Some(leaf.clone()), None]);
        let root = make(3, [Some(left), Some(right)]);
        (leaf, root)
    };
    assert_eq!(root.children.iter().flatten().count(), 2);
    drop(parent);
    budget.set_limit_bytes(0);
    let other = root.clone();
    std::thread::scope(|scope| {
        scope.spawn(move || drop(root));
        scope.spawn(move || drop(other));
    });
    assert_eq!(dropped.load(SeqCst), 3);
    for slot in 1..4 {
        assert_freed(slot, layout);
    }
    assert!(!OBSERVED[0].freed.load(SeqCst));
    assert_eq!(budget.reserved_bytes(), layout.size());
    drop(leaf);
    assert_freed(0, layout);
    assert_eq!(dropped.load(SeqCst), 4);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn unwind_reclaims_actual_control_block_and_original_credit() {
    let _serial = SERIAL.lock().unwrap();
    let layout = ChargedShared::<Probe>::allocation_layout();
    let budget = AllocationBudget::new(layout.size());
    let dropped = Arc::new(AtomicUsize::new(0));
    let value = Probe {
        slot: 0,
        budget: budget.clone(),
        dropped: Arc::clone(&dropped),
    };
    let mut parent = budget.try_reserve_bytes(layout.size()).unwrap();
    observe_next(0, false, Some(&budget));
    let owner = ChargedShared::from_reservation(value, &mut parent).unwrap();
    disarm();
    drop(parent);
    let result = catch_unwind(AssertUnwindSafe(move || {
        let _owner = owner;
        panic!("exercise original shared owner unwind");
    }));
    assert!(result.is_err());
    assert_freed(0, layout);
    assert_eq!(dropped.load(SeqCst), 1);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn charged_waker_keeps_exact_physical_control_until_last_consumed_wake() {
    #[derive(Debug)]
    struct WakePayload {
        budget: AllocationBudget,
        identity: Arc<AtomicUsize>,
        calls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }
    impl iroha_allocation::shared::SharedWake for WakePayload {
        fn wake(&self) {
            assert!(!OBSERVED[0].freed.load(SeqCst));
            assert_eq!(
                std::ptr::from_ref(self) as usize,
                self.identity.load(SeqCst)
            );
            assert_eq!(
                self.budget.reserved_bytes(),
                ChargedShared::<Self>::allocation_layout().size()
            );
            self.calls.fetch_add(1, SeqCst);
        }
    }
    impl Drop for WakePayload {
        fn drop(&mut self) {
            let layout = ChargedShared::<Self>::allocation_layout();
            assert_freed(0, layout);
            assert_eq!(
                self.budget.reserved_bytes(),
                layout.size(),
                "physical free precedes original charge refund"
            );
            self.drops.fetch_add(1, SeqCst);
        }
    }
    let _serial = SERIAL.lock().unwrap();
    let layout = ChargedShared::<WakePayload>::allocation_layout();
    let budget = AllocationBudget::new(layout.size());
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let identity = Arc::new(AtomicUsize::new(0));
    let payload = WakePayload {
        budget: budget.clone(),
        identity: Arc::clone(&identity),
        calls: Arc::clone(&calls),
        drops: Arc::clone(&drops),
    };
    let mut original = budget.try_reserve(layout).unwrap();
    observe_next(0, false, Some(&budget));
    let owner = ChargedShared::from_reservation(payload, &mut original).unwrap();
    disarm();
    assert_allocation(0, layout, layout.size());
    identity.store(std::ptr::from_ref(&*owner) as usize, SeqCst);
    drop(original);
    let first = owner.into_waker();
    let last = first.clone();
    assert!(first.will_wake(&last));
    first.wake_by_ref();
    first.wake();
    assert_eq!(calls.load(SeqCst), 2);
    assert_eq!(drops.load(SeqCst), 0);
    assert!(!OBSERVED[0].freed.load(SeqCst));
    std::thread::spawn(move || last.wake()).join().unwrap();
    assert_eq!(calls.load(SeqCst), 3);
    assert_eq!(drops.load(SeqCst), 1);
    assert_freed(0, layout);
    assert_eq!(budget.reserved_bytes(), 0);
}
