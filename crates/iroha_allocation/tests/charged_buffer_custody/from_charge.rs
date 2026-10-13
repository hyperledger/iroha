//! Exact original prepaid buffer custody and composition with one Shared shell.

use super::*;
use iroha_allocation::shared::{Reserved, Shared};
use iroha_allocation::{AllocationCharge, ChargedBufferFromChargeError};

fn charge(budget: &AllocationBudget, layout: Layout) -> AllocationCharge {
    budget
        .try_reserve(layout)
        .unwrap()
        .try_split(layout)
        .unwrap()
}

fn refusal<T: Copy>(
    result: Result<ChargedBuffer<T>, (AllocationCharge, ChargedBufferFromChargeError)>,
) -> (AllocationCharge, ChargedBufferFromChargeError) {
    match result {
        Err(original) => original,
        Ok(_) => panic!("expected the original charge to be returned"),
    }
}

fn wait<'a>(
    budget: &AllocationBudget,
    registration: &'a mut ReleaseRegistration,
) -> iroha_allocation::release::ReleaseFuture<'a> {
    let Err(AllocationRefusal::Capacity { release, .. }) = budget.try_reserve_bytes(1) else {
        panic!("the original exact pool must remain occupied");
    };
    release.wait_for_release(registration)
}

#[test]
fn original_charge_layout_mismatch_precedes_allocation_and_never_refunds() {
    let _serial = serial_observation();
    let expected = Layout::array::<u32>(4).unwrap();
    for actual in [
        Layout::from_size_align(15, 4).unwrap(),
        Layout::from_size_align(16, 1).unwrap(),
        Layout::from_size_align(16, 8).unwrap(),
        Layout::from_size_align(17, 4).unwrap(),
    ] {
        let budget =
            AllocationBudget::new(actual.size() + ReleaseRegistration::allocation_layout().size());
        let mut budget_registration = registration(&budget);
        let original = charge(&budget, actual);
        let mut released = pin!(wait(&budget, &mut budget_registration));
        let mut context = Context::from_waker(Waker::noop());
        assert!(released.as_mut().poll(&mut context).is_pending());
        observe_next(expected.size(), false, &budget);
        let (returned, error) = refusal(ChargedBuffer::<u32>::try_from_charge(4, original));
        assert_eq!(
            error,
            ChargedBufferFromChargeError::LayoutMismatch { expected, actual }
        );
        assert_eq!(returned.layout(), actual);
        assert_eq!(OBSERVED_COUNT.load(SeqCst), 0);
        assert_eq!(NEXT_SIZE.load(SeqCst), expected.size());
        assert_eq!(
            budget.reserved_bytes(),
            actual.size() + ReleaseRegistration::allocation_layout().size()
        );
        assert!(released.as_mut().poll(&mut context).is_pending());
        drop(returned);
        assert_eq!(
            budget.reserved_bytes(),
            ReleaseRegistration::allocation_layout().size()
        );
        assert!(released.as_mut().poll(&mut context).is_ready());
    }
}

#[test]
fn typed_layout_overflow_returns_original_charge_before_allocation() {
    let _serial = serial_observation();
    let layout = Layout::new::<u64>();
    let budget = AllocationBudget::new(layout.size());
    let original = charge(&budget, layout);
    observe_next(layout.size(), false, &budget);
    let (returned, error) = refusal(ChargedBuffer::<u64>::try_from_charge(usize::MAX, original));
    assert_eq!(error, ChargedBufferFromChargeError::DemandOverflow);
    assert_eq!(returned.layout(), layout);
    assert_eq!(budget.reserved_bytes(), layout.size());
    assert_eq!(OBSERVED_COUNT.load(SeqCst), 0);
    let mut corrected = ChargedBuffer::<u64>::try_from_charge(1, returned).unwrap();
    corrected.append(&[91]).unwrap();
    assert_eq!(corrected.as_slice(), &[91]);
    drop(corrected);
    assert!(FREED.load(SeqCst));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn equal_pool_limits_do_not_move_refusal_or_refund_to_a_foreign_pool() {
    let _serial = serial_observation();
    let layout = Layout::array::<u8>(53).unwrap();
    let original_pool = AllocationBudget::new(53 + ReleaseRegistration::allocation_layout().size());
    let mut original_pool_registration = registration(&original_pool);
    let foreign_pool = AllocationBudget::new(53 + ReleaseRegistration::allocation_layout().size());
    let mut foreign_pool_registration = registration(&foreign_pool);
    let original = charge(&original_pool, layout);
    let foreign = charge(&foreign_pool, layout);
    let mut original_wait = pin!(wait(&original_pool, &mut original_pool_registration));
    let mut foreign_wait = pin!(wait(&foreign_pool, &mut foreign_pool_registration));
    let mut context = Context::from_waker(Waker::noop());
    observe_next(53, true, &original_pool);
    let (returned, error) = refusal(ChargedBuffer::<u8>::try_from_charge(53, original));
    assert_eq!(error, ChargedBufferFromChargeError::Allocator { layout });
    assert!(original_wait.as_mut().poll(&mut context).is_pending());
    assert!(foreign_wait.as_mut().poll(&mut context).is_pending());
    drop(foreign);
    assert!(foreign_wait.as_mut().poll(&mut context).is_ready());
    assert!(original_wait.as_mut().poll(&mut context).is_pending());
    assert_eq!(
        original_pool.reserved_bytes(),
        53 + ReleaseRegistration::allocation_layout().size()
    );
    drop(returned);
    assert!(original_wait.as_mut().poll(&mut context).is_ready());
    assert_eq!(
        original_pool.reserved_bytes(),
        ReleaseRegistration::allocation_layout().size()
    );
}

#[test]
fn allocator_null_retains_exact_credit_for_retry_without_another_reservation() {
    let _serial = serial_observation();
    let layout = Layout::array::<u8>(113).unwrap();
    let budget =
        AllocationBudget::new(layout.size() + ReleaseRegistration::allocation_layout().size());
    let mut budget_registration = registration(&budget);
    let original = charge(&budget, layout);
    let mut released = pin!(wait(&budget, &mut budget_registration));
    let observer = Arc::new(AfterFree {
        budget: budget.clone(),
        expected: 113,
        expected_align: 1,
        wakes: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&observer));
    let mut context = Context::from_waker(&waker);
    assert!(released.as_mut().poll(&mut context).is_pending());
    observe_next(113, true, &budget);
    let (returned, error) = refusal(ChargedBuffer::<u8>::try_from_charge(113, original));
    assert_eq!(error, ChargedBufferFromChargeError::Allocator { layout });
    assert_eq!(returned.layout(), layout);
    assert_eq!(OBSERVED_COUNT.load(SeqCst), 1);
    assert_eq!(POINTER.load(SeqCst), 0);
    assert!(!FREED.load(SeqCst));
    assert_eq!(
        RESERVED_AT_ALLOCATION.load(SeqCst),
        113 + ReleaseRegistration::allocation_layout().size()
    );
    assert_eq!(
        budget.reserved_bytes(),
        113 + ReleaseRegistration::allocation_layout().size()
    );
    assert_eq!(observer.wakes.load(SeqCst), 0);
    assert!(released.as_mut().poll(&mut context).is_pending());
    observe_next(113, false, &budget);
    let mut buffer = ChargedBuffer::<u8>::try_from_charge(113, returned).unwrap();
    assert_eq!(OBSERVED_COUNT.load(SeqCst), 1);
    assert_eq!(
        RESERVED_AT_ALLOCATION.load(SeqCst),
        113 + ReleaseRegistration::allocation_layout().size()
    );
    let pointer = buffer.as_slice().as_ptr();
    buffer.append(&[7; 113]).unwrap();
    assert!(buffer.append(&[1]).is_err());
    assert_eq!(buffer.as_slice().as_ptr(), pointer);
    assert_eq!(OBSERVED_COUNT.load(SeqCst), 1);
    drop(buffer);
    assert_eq!(observer.wakes.load(SeqCst), 1);
    assert!(released.as_mut().poll(&mut context).is_ready());
}

#[test]
fn aborting_a_refused_allocation_refunds_only_when_the_returned_charge_drops() {
    let _serial = serial_observation();
    let budget = AllocationBudget::new(71 + ReleaseRegistration::allocation_layout().size());
    let mut budget_registration = registration(&budget);
    let original = charge(&budget, Layout::array::<u8>(71).unwrap());
    let mut released = pin!(wait(&budget, &mut budget_registration));
    let mut context = Context::from_waker(Waker::noop());
    observe_next(71, true, &budget);
    let (returned, _) = refusal(ChargedBuffer::<u8>::try_from_charge(71, original));
    assert_eq!(
        budget.reserved_bytes(),
        71 + ReleaseRegistration::allocation_layout().size()
    );
    assert!(released.as_mut().poll(&mut context).is_pending());
    drop(returned);
    assert_eq!(
        budget.reserved_bytes(),
        ReleaseRegistration::allocation_layout().size()
    );
    assert!(released.as_mut().poll(&mut context).is_ready());
    assert!(!FREED.load(SeqCst), "a refused allocation never existed");
}

#[test]
fn aligned_elements_use_the_validated_original_backing_layout() {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(align(256))]
    struct Entry([u8; 17]);
    let _serial = serial_observation();
    let layout = Layout::array::<Entry>(3).unwrap();
    let budget = AllocationBudget::new(layout.size());
    let original = charge(&budget, layout);
    observe_next(layout.size(), false, &budget);
    let mut values = ChargedBuffer::<Entry>::try_from_charge(3, original).unwrap();
    assert_eq!(REQUESTED_ALIGN.load(SeqCst), 256);
    assert_eq!(REQUESTED_SIZE.load(SeqCst), layout.size());
    assert_eq!(values.as_slice().as_ptr() as usize % 256, 0);
    values.append(&[Entry([8; 17]); 3]).unwrap();
    drop(values);
    assert!(FREED.load(SeqCst));
    assert_eq!(FREED_ALIGN.load(SeqCst), 256);
    assert_eq!(FREED_SIZE.load(SeqCst), layout.size());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn zero_bytes_still_require_exact_alignment_and_fixed_logical_capacity() {
    #[derive(Clone, Copy)]
    #[repr(align(256))]
    struct Entry;
    let _serial = serial_observation();
    let budget = AllocationBudget::new(0);
    let wrong = charge(&budget, Layout::array::<u8>(0).unwrap());
    observe_next(0, false, &budget);
    let (returned, error) = refusal(ChargedBuffer::<Entry>::try_from_charge(2, wrong));
    assert!(matches!(
        error,
        ChargedBufferFromChargeError::LayoutMismatch { .. }
    ));
    drop(returned);
    let exact = charge(&budget, Layout::array::<Entry>(2).unwrap());
    let mut values = ChargedBuffer::<Entry>::try_from_charge(2, exact).unwrap();
    values.append(&[Entry; 2]).unwrap();
    assert!(values.append(&[Entry]).is_err());
    assert_eq!(values.capacity(), 2);
    assert_eq!(values.as_slice().len(), 2);
    assert_eq!(values.as_slice().as_ptr() as usize % 256, 0);
    drop(values);
    assert_eq!(OBSERVED_COUNT.load(SeqCst), 0);
    assert_eq!(NEXT_SIZE.load(SeqCst), 0);
}

#[test]
fn zero_capacity_retains_its_exact_zero_charge_without_backing_allocation() {
    let _serial = serial_observation();
    let budget = AllocationBudget::new(0);
    let original = charge(&budget, Layout::array::<u64>(0).unwrap());
    observe_next(0, false, &budget);
    let mut empty = ChargedBuffer::<u64>::try_from_charge(0, original).unwrap();
    empty.append(&[]).unwrap();
    assert!(empty.append(&[1]).is_err());
    assert_eq!(empty.capacity(), 0);
    drop(empty);
    assert_eq!(OBSERVED_COUNT.load(SeqCst), 0);
    assert_eq!(budget.reserved_bytes(), 0);
}

type Header = Reserved<ChargedBuffer<u8>, AllocationCharge>;

#[test]
fn complete_buffer_and_header_demand_is_refused_before_either_allocation() {
    let _serial = serial_observation();
    let backing = Layout::array::<u8>(129).unwrap();
    let header = Header::layout();
    let total = backing.size().checked_add(header.size()).unwrap();
    let short = AllocationBudget::new(total - 1);
    observe_next(backing.size(), false, &short);
    assert!(matches!(
        short.try_reserve_layouts([backing, header]),
        Err(AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes })
            if requested_bytes == total && limit_bytes == total - 1
    ));
    assert_eq!(OBSERVED_COUNT.load(SeqCst), 0);
    assert_eq!(short.reserved_bytes(), 0);
    let exact = AllocationBudget::new(total + ReleaseRegistration::allocation_layout().size());
    let mut exact_registration = registration(&exact);
    let occupied = exact.try_reserve_bytes(1).unwrap();
    observe_next(header.size(), false, &exact);
    let error = exact.try_reserve_layouts([backing, header]).unwrap_err();
    let AllocationRefusal::Capacity {
        requested_bytes,
        reserved_bytes,
        limit_bytes,
        release,
    } = error
    else {
        panic!("complete original-pool capacity refusal");
    };
    assert_eq!(
        (requested_bytes, reserved_bytes, limit_bytes),
        (
            total,
            1 + ReleaseRegistration::allocation_layout().size(),
            total + ReleaseRegistration::allocation_layout().size()
        )
    );
    assert_eq!(OBSERVED_COUNT.load(SeqCst), 0);
    let mut released = pin!(release.wait_for_release(&mut exact_registration));
    let mut context = Context::from_waker(Waker::noop());
    assert!(released.as_mut().poll(&mut context).is_pending());
    drop(occupied);
    assert!(released.as_mut().poll(&mut context).is_ready());
    let mut prepaid = exact.try_reserve_layouts([backing, header]).unwrap();
    assert!(prepaid.belongs_to(&exact));
    let shell = Header::try_new(prepaid.try_split(header).unwrap()).unwrap();
    let buffer = ChargedBuffer::try_from_charge(129, prepaid.try_split(backing).unwrap()).unwrap();
    assert_eq!(prepaid.remaining_bytes(), 0);
    drop(prepaid);
    let published = shell.initialize(buffer);
    assert_eq!(
        exact.reserved_bytes(),
        total + ReleaseRegistration::allocation_layout().size()
    );
    drop(published);
    assert_eq!(
        exact.reserved_bytes(),
        ReleaseRegistration::allocation_layout().size()
    );
}

#[test]
fn allocated_header_survives_buffer_refusal_and_initializes_without_reconstruction() {
    let _serial = serial_observation();
    let backing = Layout::array::<u8>(193).unwrap();
    let header = Header::layout();
    let total = backing.size() + header.size();
    let budget = AllocationBudget::new(total);
    let mut prepaid = budget.try_reserve_layouts([backing, header]).unwrap();
    let header_charge = prepaid.try_split(header).unwrap();
    let buffer_charge = prepaid.try_split(backing).unwrap();
    drop(prepaid);
    observe_next(header.size(), false, &budget);
    let shell = Header::try_new(header_charge).unwrap();
    let header_pointer = POINTER.load(SeqCst);
    assert_eq!(RESERVED_AT_ALLOCATION.load(SeqCst), total);
    observe_next(backing.size(), true, &budget);
    let (returned, _) = refusal(ChargedBuffer::<u8>::try_from_charge(193, buffer_charge));
    assert_eq!(budget.reserved_bytes(), total);
    observe_next(backing.size(), false, &budget);
    let mut buffer = ChargedBuffer::try_from_charge(193, returned).unwrap();
    let buffer_pointer = buffer.as_slice().as_ptr();
    buffer.append(&[3; 193]).unwrap();
    let allocations = OBSERVED_COUNT.load(SeqCst);
    let published = shell.initialize(buffer);
    let payload_pointer = std::ptr::from_ref(&*published) as usize;
    assert!((header_pointer..header_pointer + header.size()).contains(&payload_pointer));
    assert_eq!(published.as_slice().as_ptr(), buffer_pointer);
    let reader = published.clone();
    assert!(Shared::ptr_eq(&published, &reader));
    drop(published);
    assert_eq!(OBSERVED_COUNT.load(SeqCst), allocations);
    assert_eq!(budget.reserved_bytes(), total);
    assert!(!FREED.load(SeqCst));
    drop(reader);
    assert!(FREED.load(SeqCst));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn initialized_buffer_survives_header_refusal_with_the_same_original_charge() {
    let _serial = serial_observation();
    let backing = Layout::array::<u8>(211).unwrap();
    let header = Header::layout();
    let total = backing.size() + header.size();
    let budget = AllocationBudget::new(total);
    let mut prepaid = budget.try_reserve_layouts([backing, header]).unwrap();
    let buffer_charge = prepaid.try_split(backing).unwrap();
    let header_charge = prepaid.try_split(header).unwrap();
    drop(prepaid);
    let mut buffer = ChargedBuffer::<u8>::try_from_charge(211, buffer_charge).unwrap();
    buffer.append(&[9; 211]).unwrap();
    let original_pointer = buffer.as_slice().as_ptr();
    observe_next(header.size(), true, &budget);
    let (returned, error) = Header::try_new(header_charge).unwrap_err();
    assert_eq!(error.layout(), header);
    assert_eq!(budget.reserved_bytes(), total);
    assert_eq!(buffer.as_slice().as_ptr(), original_pointer);
    observe_next(header.size(), false, &budget);
    let shell = Header::try_new(returned).unwrap();
    let allocations = OBSERVED_COUNT.load(SeqCst);
    let published = shell.initialize(buffer);
    assert_eq!(published.as_slice().as_ptr(), original_pointer);
    assert_eq!(published.as_slice(), &[9; 211]);
    assert_eq!(OBSERVED_COUNT.load(SeqCst), allocations);
    drop(published);
    assert!(FREED.load(SeqCst));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn dropping_unused_header_does_not_refund_live_nested_buffer() {
    let _serial = serial_observation();
    let backing = Layout::array::<u8>(149).unwrap();
    let header = Header::layout();
    let budget = AllocationBudget::new(backing.size() + header.size());
    let mut prepaid = budget.try_reserve_layouts([backing, header]).unwrap();
    let shell = Header::try_new(prepaid.try_split(header).unwrap()).unwrap();
    observe_next(backing.size(), false, &budget);
    let buffer =
        ChargedBuffer::<u8>::try_from_charge(149, prepaid.try_split(backing).unwrap()).unwrap();
    drop(prepaid);
    drop(shell);
    assert_eq!(budget.reserved_bytes(), backing.size());
    assert!(!FREED.load(SeqCst));
    drop(buffer);
    assert!(FREED.load(SeqCst));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn partially_allocated_preparation_unwind_releases_original_owners() {
    let _serial = serial_observation();
    let backing = Layout::array::<u8>(151).unwrap();
    let header = Header::layout();
    let budget = AllocationBudget::new(backing.size() + header.size());
    let failure = catch_unwind(AssertUnwindSafe(|| {
        let mut prepaid = budget.try_reserve_layouts([backing, header]).unwrap();
        let _shell = Header::try_new(prepaid.try_split(header).unwrap()).unwrap();
        observe_next(backing.size(), false, &budget);
        let mut buffer =
            ChargedBuffer::<u8>::try_from_charge(151, prepaid.try_split(backing).unwrap()).unwrap();
        buffer.append(&[1; 3]).unwrap();
        panic!("later preparation failed before payload initialization");
    }));
    assert!(failure.is_err());
    assert!(FREED.load(SeqCst));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn returned_allocator_error_reports_exact_layout_without_a_pool_admission_claim() {
    let _serial = serial_observation();
    let layout = Layout::array::<u8>(31).unwrap();
    let budget = AllocationBudget::new(31);
    let original = charge(&budget, layout);
    observe_next(31, true, &budget);
    let (returned, error) = refusal(ChargedBuffer::<u8>::try_from_charge(31, original));
    assert_eq!(
        error.to_string(),
        "failed to allocate 31 admitted buffer bytes with alignment 1"
    );
    assert!(std::error::Error::source(&error).is_none());
    assert_eq!(returned.layout(), layout);
    drop(returned);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn last_shared_reader_frees_header_before_buffered_payload_and_both_refunds() {
    struct BufferedPayload {
        buffer: Option<ChargedBuffer<u8>>,
        budget: AllocationBudget,
        backing: Layout,
        header: Layout,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for BufferedPayload {
        fn drop(&mut self) {
            // Observe the actual Shared allocation: its deallocator must have
            // completed before the moved payload and either charge can retire.
            assert!(FREED.load(SeqCst));
            assert_eq!(FREED_SIZE.load(SeqCst), self.header.size());
            assert_eq!(FREED_ALIGN.load(SeqCst), self.header.align());
            assert_eq!(
                self.budget.reserved_bytes(),
                self.backing.size() + self.header.size()
            );
            drop(self.buffer.take().expect("original nested backing"));
            assert_eq!(self.budget.reserved_bytes(), self.header.size());
            self.drops.fetch_add(1, SeqCst);
        }
    }

    type Shell = Reserved<BufferedPayload, AllocationCharge>;

    let _serial = serial_observation();
    let backing = Layout::array::<u8>(239).unwrap();
    let header = Shell::layout();
    let total = backing.size().checked_add(header.size()).unwrap();
    let budget = AllocationBudget::new(total);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut prepaid = budget.try_reserve_layouts([backing, header]).unwrap();
    assert!(prepaid.belongs_to(&budget));
    let header_charge = prepaid.try_split(header).unwrap();
    let buffer_charge = prepaid.try_split(backing).unwrap();
    drop(prepaid);

    observe_next(header.size(), false, &budget);
    let shell = Shell::try_new(header_charge).unwrap();
    let original_header = POINTER.load(SeqCst);
    assert_ne!(original_header, 0);
    assert_eq!(REQUESTED_SIZE.load(SeqCst), header.size());
    assert_eq!(REQUESTED_ALIGN.load(SeqCst), header.align());
    assert_eq!(RESERVED_AT_ALLOCATION.load(SeqCst), total);
    let mut buffer = ChargedBuffer::try_from_charge(239, buffer_charge).unwrap();
    buffer.append(&[17; 239]).unwrap();
    let original_backing = buffer.as_slice().as_ptr();
    let allocations = OBSERVED_COUNT.load(SeqCst);
    let published = shell.initialize(BufferedPayload {
        buffer: Some(buffer),
        budget: budget.clone(),
        backing,
        header,
        drops: Arc::clone(&drops),
    });
    let payload_address = std::ptr::from_ref(&*published) as usize;
    assert!((original_header..original_header + header.size()).contains(&payload_address));
    let first_reader = published.clone();
    let last_reader = first_reader.clone();
    assert!(Shared::ptr_eq(&published, &first_reader));
    assert!(Shared::ptr_eq(&published, &last_reader));
    drop((published, first_reader));
    assert_eq!(drops.load(SeqCst), 0);
    assert!(!FREED.load(SeqCst));
    assert_eq!(budget.reserved_bytes(), total);
    let retained_buffer = last_reader.buffer.as_ref().unwrap();
    assert_eq!(retained_buffer.as_slice().as_ptr(), original_backing);
    assert_eq!(retained_buffer.as_slice(), &[17; 239]);
    assert_eq!(OBSERVED_COUNT.load(SeqCst), allocations);
    drop(last_reader);
    assert_eq!(OBSERVED_COUNT.load(SeqCst), allocations);
    assert_eq!(drops.load(SeqCst), 1);
    assert_eq!(budget.reserved_bytes(), 0);
}

/// Observe the real nested backing deallocation and original pool notification.
/// The mutex models an enclosing physical owner solely for this composition
/// control; these tests do not claim Core State/publication integration.
struct AfterComposedRetirement {
    budget: AllocationBudget,
    physical: Arc<Mutex<()>>,
    backing: Layout,
    wakes: AtomicUsize,
}

impl Wake for AfterComposedRetirement {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let guard = match self.physical.try_lock() {
            Ok(guard) => guard,
            // An unwind poisons std's mutex after physically unlocking it.
            // Recovering this test guard demonstrates unlock, not a production
            // poison reset or permission to use an incomplete State owner.
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                panic!("composed refund notified beneath its enclosing physical guard")
            }
        };
        drop(guard);
        assert!(FREED.load(SeqCst));
        assert_eq!(FREED_SIZE.load(SeqCst), self.backing.size());
        assert_eq!(FREED_ALIGN.load(SeqCst), self.backing.align());
        assert_eq!(
            self.budget.reserved_bytes(),
            ReleaseRegistration::allocation_layout().size()
        );
        self.wakes.fetch_add(1, SeqCst);
    }
}

#[test]
fn composed_last_reader_refunds_wait_until_outer_physical_guard_releases() {
    let _serial = serial_observation();
    let backing = Layout::array::<u8>(241).unwrap();
    let header = Header::layout();
    let total = backing.size().checked_add(header.size()).unwrap();
    let budget = AllocationBudget::new(total + ReleaseRegistration::allocation_layout().size());
    let mut budget_registration = registration(&budget);
    let physical = Arc::new(Mutex::new(()));
    let observer = Arc::new(AfterComposedRetirement {
        budget: budget.clone(),
        physical: Arc::clone(&physical),
        backing,
        wakes: AtomicUsize::new(0),
    });
    let mut prepaid = budget.try_reserve_layouts([backing, header]).unwrap();
    let shell = Header::try_new(prepaid.try_split(header).unwrap()).unwrap();
    observe_next(backing.size(), false, &budget);
    let mut buffer =
        ChargedBuffer::<u8>::try_from_charge(241, prepaid.try_split(backing).unwrap()).unwrap();
    drop(prepaid);
    buffer.append(&[23; 241]).unwrap();
    let original_backing = buffer.as_slice().as_ptr();
    let published = shell.initialize(buffer);
    let last_reader = published.clone();
    drop(published);
    assert_eq!(last_reader.as_slice().as_ptr(), original_backing);
    assert_eq!(
        budget.reserved_bytes(),
        total + ReleaseRegistration::allocation_layout().size()
    );
    assert!(!FREED.load(SeqCst));
    let mut released = pin!(wait(&budget, &mut budget_registration));
    let waker = Waker::from(Arc::clone(&observer));
    let mut context = Context::from_waker(&waker);
    assert!(released.as_mut().poll(&mut context).is_pending());

    budget.with_deferred_refund_notifications(|_| {
        let guard = physical.lock().unwrap();
        drop(last_reader);
        assert!(FREED.load(SeqCst));
        assert_eq!(
            budget.reserved_bytes(),
            ReleaseRegistration::allocation_layout().size()
        );
        assert_eq!(observer.wakes.load(SeqCst), 0);
        assert!(released.as_mut().poll(&mut context).is_pending());
        drop(guard);
        assert_eq!(observer.wakes.load(SeqCst), 0);
    });
    assert_eq!(observer.wakes.load(SeqCst), 1);
    assert!(released.as_mut().poll(&mut context).is_ready());
}

#[test]
fn partially_allocated_composition_unwind_defers_refunds_past_outer_guard() {
    let _serial = serial_observation();
    let backing = Layout::array::<u8>(251).unwrap();
    let header = Header::layout();
    let total = backing.size().checked_add(header.size()).unwrap();
    let budget = AllocationBudget::new(total + ReleaseRegistration::allocation_layout().size());
    let mut budget_registration = registration(&budget);
    let physical = Arc::new(Mutex::new(()));
    let observer = Arc::new(AfterComposedRetirement {
        budget: budget.clone(),
        physical: Arc::clone(&physical),
        backing,
        wakes: AtomicUsize::new(0),
    });
    let mut prepaid = budget.try_reserve_layouts([backing, header]).unwrap();
    let header_charge = prepaid.try_split(header).unwrap();
    let buffer_charge = prepaid.try_split(backing).unwrap();
    drop(prepaid);
    let mut released = pin!(wait(&budget, &mut budget_registration));
    let waker = Waker::from(Arc::clone(&observer));
    let mut context = Context::from_waker(&waker);
    assert!(released.as_mut().poll(&mut context).is_pending());

    let failure = catch_unwind(AssertUnwindSafe(|| {
        budget.with_deferred_refund_notifications(|_| {
            let _guard = physical.lock().unwrap();
            let _shell = Header::try_new(header_charge).unwrap();
            observe_next(backing.size(), false, &budget);
            let mut buffer = ChargedBuffer::<u8>::try_from_charge(251, buffer_charge).unwrap();
            buffer.append(&[31; 19]).unwrap();
            assert_eq!(
                budget.reserved_bytes(),
                total + ReleaseRegistration::allocation_layout().size()
            );
            assert_eq!(observer.wakes.load(SeqCst), 0);
            panic!("later preparation failed before original shell initialization");
        });
    }));
    let panic = failure.expect_err("the deliberate post-allocation unwind must run");
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"later preparation failed before original shell initialization"),
        "an earlier assertion must not masquerade as the intended unwind"
    );
    assert!(physical.is_poisoned());
    assert_eq!(
        budget.reserved_bytes(),
        ReleaseRegistration::allocation_layout().size()
    );
    assert!(FREED.load(SeqCst));
    assert_eq!(observer.wakes.load(SeqCst), 1);
    assert!(released.as_mut().poll(&mut context).is_ready());
}
