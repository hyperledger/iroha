//! Native digit custody, exact transfer, source preservation and unwind controls.

use super::*;
use iroha_allocation::AllocationRefusal;

mod allocator;

#[test]
fn charged_copy_and_inline_result_keep_exact_layout_pointer_and_pool_until_drop() {
    for text in ["0", "1", "18446744073709551616.001"] {
        let source: Quantity = text.parse().unwrap();
        let inline = QuantityAccumulator::from_quantity(&source);
        let layout = inline.admission_layout().unwrap();
        let pool = AllocationBudget::new(layout.size());
        let foreign = AllocationBudget::new(layout.size());
        let value = ChargedQuantity::try_copy(&source, &pool).unwrap();
        assert_eq!(value.get(), &source);
        assert_eq!(value.charge.layout(), layout);
        assert_eq!(pool.reserved_bytes(), layout.size());
        let pointer = value
            .get()
            .mantissa()
            .inner()
            .magnitude()
            .native_digits()
            .as_ptr();
        pool.set_limit_bytes(0);
        let moved = value;
        assert!(moved.belongs_to(&pool));
        assert!(!moved.belongs_to(&foreign));
        assert_eq!(
            moved
                .get()
                .mantissa()
                .inner()
                .magnitude()
                .native_digits()
                .as_ptr(),
            pointer
        );
        assert_eq!(pool.reserved_bytes(), layout.size());
        drop(moved);
        assert_eq!(pool.reserved_bytes(), 0);
        assert_eq!(foreign.reserved_bytes(), 0);
        assert_eq!(source.to_string(), text);
    }
}

#[test]
fn prepaid_result_rejects_foreign_pool_size_and_alignment_without_refund() {
    let source = Quantity::from(7_u64);
    let inline = QuantityAccumulator::from_quantity(&source);
    let layout = inline.admission_layout().unwrap();
    let pool = AllocationBudget::new(1024);
    let foreign = AllocationBudget::new(1024);
    for offered in [
        layout,
        Layout::from_size_align(layout.size() + layout.align(), layout.align()).unwrap(),
        Layout::from_size_align(layout.size(), 1).unwrap(),
    ] {
        let charge = pool
            .try_reserve(offered)
            .unwrap()
            .try_split(offered)
            .unwrap();
        let (charge, error) =
            ChargedQuantity::try_from_accumulator_charge(inline, &foreign, charge)
                .err()
                .unwrap();
        assert!(matches!(error, QuantityBackingError::ForeignPool));
        assert!(charge.belongs_to(&pool));
        assert_eq!(pool.reserved_bytes(), offered.size());
        let result = ChargedQuantity::try_from_accumulator_charge(inline, &pool, charge);
        if offered == layout {
            let value = result.unwrap_or_else(|(_, error)| panic!("{error}"));
            assert_eq!(value.get(), &source);
            assert_eq!(value.charge.layout(), layout);
            drop(value);
        } else {
            let (charge, error) = result.err().unwrap();
            assert!(
                matches!(error, QuantityBackingError::Allocation(ChargedBufferFromChargeError::LayoutMismatch { expected, actual }) if expected == layout && actual == offered)
            );
            assert_eq!(pool.reserved_bytes(), offered.size());
            drop(charge);
        }
        assert_eq!(pool.reserved_bytes(), 0);
        assert_eq!(foreign.reserved_bytes(), 0);
    }
}

#[test]
fn original_capacity_observation_source_retry_and_unwind_are_preserved() {
    let source: Quantity = "18446744073709551616.001".parse().unwrap();
    let layout = source.admission_clone_layout().unwrap();
    let pool = AllocationBudget::new(layout.size());
    let unrelated = AllocationBudget::new(layout.size());
    let held = pool.try_reserve(layout).unwrap();
    let foreign_held = unrelated.try_reserve(layout).unwrap();
    let waiter_budget = AllocationBudget::new(1024);
    let mut waiter = iroha_allocation::release::ReleaseRegistration::from_reservation(
        &mut waiter_budget.try_reserve_bytes(1024).unwrap(),
    )
    .unwrap();
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    let error = ChargedQuantity::try_copy(&source, &pool).err().unwrap();
    let ChargedBufferError::Admission(AllocationRefusal::Capacity {
        release,
        requested_bytes,
        ..
    }) = error
    else {
        panic!("original capacity refusal required")
    };
    assert_eq!(requested_bytes, layout.size());
    assert!(waiter.poll_wait(&release, &mut context).is_pending());
    drop(foreign_held);
    assert!(waiter.poll_wait(&release, &mut context).is_pending());
    drop(held);
    assert!(waiter.poll_wait(&release, &mut context).is_ready());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let value = ChargedQuantity::try_copy(&source, &pool).unwrap();
        assert_eq!(value.get(), &source);
        assert_eq!(pool.reserved_bytes(), layout.size());
        panic!("test unwind after complete native digit ownership");
    }));
    assert!(result.is_err());
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(source.to_string(), "18446744073709551616.001");
}

#[test]
fn physical_digit_refusal_and_deallocation_preserve_original_custody() {
    let source: Quantity = "18446744073709551616.001".parse().unwrap();
    let inline = QuantityAccumulator::from_quantity(&source);
    let layout = inline.admission_layout().unwrap();
    let pool = AllocationBudget::new(layout.size());
    let (result, observed) = allocator::observe(&pool, layout, true, || {
        ChargedQuantity::try_copy(&source, &pool)
    });
    assert!(
        matches!(result, Err(ChargedBufferError::Allocator { requested_bytes })
        if requested_bytes == layout.size())
    );
    assert_eq!(observed.allocations, 1);
    assert_eq!(observed.deallocations, 0);
    assert_eq!(observed.minimum_reserved, layout.size());
    assert_eq!(pool.reserved_bytes(), 0);

    let charge = pool.try_reserve(layout).unwrap().try_split(layout).unwrap();
    let (result, observed) = allocator::observe(&pool, layout, true, || {
        ChargedQuantity::try_from_accumulator_charge(inline, &pool, charge)
    });
    let (charge, error) = result.err().unwrap();
    assert!(matches!(error, QuantityBackingError::Allocation(
        ChargedBufferFromChargeError::Allocator { layout: actual }) if actual == layout));
    assert_eq!(observed.allocations, 1);
    assert_eq!(pool.reserved_bytes(), layout.size());
    assert!(charge.belongs_to(&pool));
    drop(charge);

    for unwind in [false, true] {
        let ((), observed) = allocator::observe(&pool, layout, false, || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let value = ChargedQuantity::try_from_accumulator(inline, &pool).unwrap();
                assert_eq!(value.get(), &source);
                assert!(!unwind, "observe original digit destruction during unwind");
                drop(value);
            }));
            assert_eq!(outcome.is_err(), unwind);
        });
        assert_eq!(observed.deallocations, 1);
        assert!(observed.exact_deallocation_layout);
        assert_eq!(
            observed.minimum_reserved,
            layout.size(),
            "native digit custody must remain charged until System.dealloc returns"
        );
        assert_eq!(pool.reserved_bytes(), 0);
    }
    assert_eq!(source.to_string(), "18446744073709551616.001");
}

#[test]
fn charged_digits_survive_refused_shared_shell_and_last_reader_restore() {
    use iroha_allocation::{ChargedShared, SharedFromChargeError};

    let source: Quantity = "18446744073709551616.001".parse().unwrap();
    let inline = QuantityAccumulator::from_quantity(&source);
    let digits_layout = inline.admission_layout().unwrap();
    let shell_layout = ChargedShared::<ChargedQuantity>::allocation_layout();
    let total = digits_layout.size() + shell_layout.size();
    let pool = AllocationBudget::new(total);
    let mut reservation = pool.try_reserve_bytes(total).unwrap();
    let value = ChargedQuantity::try_from_accumulator_charge(
        inline,
        &pool,
        reservation.try_split(digits_layout).unwrap(),
    )
    .unwrap_or_else(|(_, error)| panic!("{error}"));
    let digits = |value: &Quantity| {
        value
            .mantissa()
            .inner()
            .magnitude()
            .native_digits()
            .as_ptr()
    };
    let pointer = digits(value.get());
    let shell_charge = reservation.try_split(shell_layout).unwrap();
    pool.set_limit_bytes(0);
    let (refused, observed) = allocator::observe(&pool, shell_layout, true, || {
        ChargedShared::<ChargedQuantity>::reserve_from_charge(shell_charge)
    });
    let (shell_charge, error) = refused.err().unwrap();
    assert!(matches!(error, SharedFromChargeError::Allocator { layout } if layout == shell_layout));
    assert_eq!(observed.allocations, 1);
    assert_eq!(observed.minimum_reserved, total);
    assert!(shell_charge.belongs_to(&pool));
    assert_eq!(pool.reserved_bytes(), total);
    assert_eq!(digits(value.get()), pointer);

    // Retry consumes the same prepaid shell charge even though fresh admission
    // is now disabled. Every subsequent reader shares those exact allocations.
    let shell = ChargedShared::<ChargedQuantity>::reserve_from_charge(shell_charge)
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    let original = shell.initialize(value);
    let reader = original.clone();
    assert!(ChargedShared::ptr_eq(&original, &reader));
    drop(original);
    assert_eq!(pool.reserved_bytes(), total);
    let reader = reader.project(ChargedQuantity::get);
    let restored = reader.clone();
    drop(reader);
    assert_eq!(digits(&restored), pointer);
    assert_eq!(&*restored, &source);
    assert_eq!(pool.reserved_bytes(), total);
    drop(restored);
    assert_eq!(pool.reserved_bytes(), 0);
}
