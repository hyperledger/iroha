//! Fixed bookkeeping capacity, original allocation identity and refund ordering.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(align(64))]
struct Aligned(usize);

#[test]
fn vec_tracking_keeps_explicit_untracked_allocation_when_cleared() {
    fn is_untracked<B: TrackingBuffer<usize, Charge = Untracked>>(_buffer: &B) {}
    let mut buffer = Vec::with_capacity(3);
    is_untracked(&buffer);
    let original = buffer.as_ptr();
    TrackingBuffer::push(&mut buffer, 11);
    TrackingBuffer::push(&mut buffer, 22);
    assert_eq!(TrackingBuffer::as_slice(&buffer), &[11, 22]);
    TrackingBuffer::clear(&mut buffer);
    assert!(TrackingBuffer::as_slice(&buffer).is_empty());
    TrackingBuffer::push(&mut buffer, 33);
    assert_eq!(TrackingBuffer::as_slice(&buffer), &[33]);
    assert_eq!(buffer.as_ptr(), original);
}

#[test]
fn fixed_tracking_initializes_only_its_prefix_and_reuses_original_capacity() {
    let mut buffer = FixedTrackingBuffer::try_new(3, Untracked).unwrap();
    let original = buffer.as_ptr();
    assert!(buffer.as_slice().is_empty());
    buffer.push(Aligned(11));
    buffer.push(Aligned(22));
    assert_eq!(buffer.as_slice(), &[Aligned(11), Aligned(22)]);
    buffer.clear();
    assert!(buffer.as_slice().is_empty());
    buffer.push(Aligned(33));
    assert_eq!(buffer.as_slice(), &[Aligned(33)]);
    assert_eq!(buffer.capacity(), 3);
    assert_eq!(buffer.as_ptr(), original);
}

#[test]
fn fixed_tracking_layout_checks_actual_alignment_empty_and_overflow() {
    type Buffer = FixedTrackingBuffer<Aligned, Untracked>;
    let empty = Buffer::allocation_layout(0).unwrap();
    assert_eq!(empty.size(), 0);
    assert_eq!(empty.align(), 64);
    assert_eq!(
        Buffer::allocation_layout(3).unwrap(),
        Layout::array::<Aligned>(3).unwrap()
    );
    assert!(Buffer::allocation_layout(usize::MAX).is_err());
    let oversized = isize::MAX as usize / std::mem::size_of::<Aligned>() + 1;
    assert!(Buffer::allocation_layout(oversized).is_err());
}

#[cfg(not(miri))]
mod allocated {
    use super::*;
    use crate::internals::bptree::node::allocation_tests::{
        all_refunded, prepaid, record, without_allocations, Charge,
    };
    use std::cell::Cell;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn vec_pop_and_truncate_preserve_original_allocation_without_allocating() {
        let mut buffer = Vec::with_capacity(3);
        let original = buffer.as_ptr();
        let capacity = buffer.capacity();
        without_allocations(|| {
            assert_eq!(TrackingBuffer::pop(&mut buffer), None);
            TrackingBuffer::truncate(&mut buffer, usize::MAX);
            for value in [Aligned(11), Aligned(22), Aligned(33)] {
                TrackingBuffer::push(&mut buffer, value);
            }
            TrackingBuffer::truncate(&mut buffer, usize::MAX);
            assert_eq!(TrackingBuffer::pop(&mut buffer), Some(Aligned(33)));
            assert_eq!(
                TrackingBuffer::as_slice(&buffer),
                &[Aligned(11), Aligned(22)]
            );
            TrackingBuffer::truncate(&mut buffer, 2);
            TrackingBuffer::truncate(&mut buffer, 1);
            assert_eq!(TrackingBuffer::pop(&mut buffer), Some(Aligned(11)));
            assert_eq!(TrackingBuffer::pop(&mut buffer), None);
            TrackingBuffer::push(&mut buffer, Aligned(44));
            TrackingBuffer::truncate(&mut buffer, 0);
            assert!(TrackingBuffer::as_slice(&buffer).is_empty());
            assert_eq!(buffer.as_ptr(), original);
            assert_eq!(buffer.capacity(), capacity);
            drop(buffer);
        });
    }

    #[test]
    fn fixed_pop_and_truncate_preserve_exact_aligned_allocation_and_charge() {
        let mut funding = prepaid();
        type Buffer = FixedTrackingBuffer<Aligned, Charge>;
        let layout = Buffer::allocation_layout(3).unwrap();
        let charge = funding.take_allocation_charge(layout);
        let mut buffer = Buffer::try_new(3, charge).unwrap_or_else(|_| panic!("valid layout"));
        let original = buffer.as_ptr();
        assert_eq!(record(0).pointer, original as usize);
        assert_eq!(record(0).layout, layout);
        assert_eq!(original as usize % layout.align(), 0);
        without_allocations(|| {
            assert_eq!(buffer.pop(), None);
            buffer.truncate(usize::MAX);
            assert_eq!(buffer.remaining_capacity(), Some(3));
            for value in [Aligned(11), Aligned(22), Aligned(33)] {
                buffer.push(value);
            }
            assert_eq!(buffer.remaining_capacity(), Some(0));
            buffer.truncate(usize::MAX);
            assert_eq!(buffer.pop(), Some(Aligned(33)));
            assert_eq!(buffer.as_slice(), &[Aligned(11), Aligned(22)]);
            assert_eq!(buffer.remaining_capacity(), Some(1));
            buffer.truncate(2);
            buffer.truncate(1);
            assert_eq!(buffer.as_slice(), &[Aligned(11)]);
            buffer.push(Aligned(44));
            assert_eq!(buffer.pop(), Some(Aligned(44)));
            assert_eq!(buffer.pop(), Some(Aligned(11)));
            assert_eq!(buffer.pop(), None);
            buffer.push(Aligned(55));
            buffer.truncate(0);
            assert!(buffer.as_slice().is_empty());
            assert_eq!(buffer.remaining_capacity(), Some(3));
            assert_eq!(buffer.as_ptr(), original);
            assert_eq!(buffer.capacity(), 3);
            assert!(!record(0).freed && !record(0).refunded);
            drop(buffer);
        });
        assert_eq!(funding.next, 1);
        all_refunded(&funding);
    }

    #[test]
    fn popped_entry_is_absent_when_its_retirement_callback_unwinds() {
        let targets = [const { Cell::new(0) }; 3];
        let mut funding = prepaid();
        type Buffer<'a> = FixedTrackingBuffer<&'a Cell<usize>, Charge>;
        let charge = funding.take_allocation_charge(Buffer::allocation_layout(3).unwrap());
        let mut buffer = Buffer::try_new(3, charge).unwrap_or_else(|_| panic!("valid layout"));
        for target in &targets {
            buffer.push(target);
        }
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let target = buffer.pop().expect("original last entry");
            assert_eq!(buffer.as_slice().len(), 2);
            assert!(std::ptr::eq(target, &targets[2]));
            target.set(target.get() + 1);
            panic!("retirement callback panic");
        }))
        .unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"retirement callback panic")
        );
        without_allocations(|| {
            while let Some(target) = buffer.pop() {
                target.set(target.get() + 1);
            }
            assert!(buffer.as_slice().is_empty());
            assert_eq!(targets.each_ref().map(Cell::get), [1, 1, 1]);
            assert!(!record(0).freed && !record(0).refunded);
            drop(buffer);
        });
        all_refunded(&funding);
    }

    #[test]
    fn moves_and_clear_preserve_original_system_allocation_and_charge() {
        fn handoff<T: Copy, C>(buffer: FixedTrackingBuffer<T, C>) -> FixedTrackingBuffer<T, C> {
            std::hint::black_box(buffer)
        }
        let mut funding = prepaid();
        type Buffer = FixedTrackingBuffer<Aligned, Charge>;
        let layout = Buffer::allocation_layout(3).unwrap();
        let charge = funding.take_allocation_charge(layout);
        let mut buffer = Buffer::try_new(3, charge).unwrap_or_else(|_| panic!("valid layout"));
        let original = buffer.as_ptr();
        assert_eq!(record(0).layout, layout);
        assert_eq!(record(0).pointer, original as usize);
        assert_eq!(original as usize % layout.align(), 0);
        assert!(!record(0).freed && !record(0).refunded);
        without_allocations(|| {
            buffer.push(Aligned(11));
            buffer.push(Aligned(22));
            let mut buffer = handoff(buffer);
            assert_eq!(buffer.as_ptr(), original);
            assert_eq!(buffer.as_slice(), &[Aligned(11), Aligned(22)]);
            buffer.clear();
            buffer.push(Aligned(33));
            let buffer = handoff(buffer);
            assert_eq!(buffer.as_ptr(), original);
            assert_eq!(buffer.capacity(), 3);
            assert_eq!(buffer.as_slice(), &[Aligned(33)]);
            assert!(!record(0).freed && !record(0).refunded);
            drop(buffer);
        });
        assert_eq!(funding.next, 1, "handoff must not obtain another charge");
        all_refunded(&funding);
    }

    #[test]
    fn overflow_rejects_before_write_and_retains_the_original_buffer() {
        let mut funding = prepaid();
        type Buffer = FixedTrackingBuffer<usize, Charge>;
        let charge = funding.take_allocation_charge(Buffer::allocation_layout(2).unwrap());
        let mut buffer = Buffer::try_new(2, charge).unwrap_or_else(|_| panic!("valid layout"));
        buffer.push(11);
        buffer.push(22);
        let original = buffer.as_ptr();
        assert!(catch_unwind(AssertUnwindSafe(|| buffer.push(33))).is_err());
        assert_eq!(buffer.as_slice(), &[11, 22]);
        assert_eq!(buffer.capacity(), 2);
        assert_eq!(buffer.as_ptr(), original);
        assert!(!record(0).freed && !record(0).refunded);
        without_allocations(|| {
            buffer.clear();
            buffer.push(44);
            assert_eq!(buffer.as_slice(), &[44]);
            drop(buffer);
        });
        all_refunded(&funding);
    }

    #[test]
    fn invalid_capacity_returns_original_charge_before_any_allocation() {
        let mut funding = prepaid();
        type Buffer = FixedTrackingBuffer<usize, Charge>;
        let layout = Buffer::allocation_layout(1).unwrap();
        let charge = funding.take_allocation_charge(layout);
        let (charge, _) = match without_allocations(|| Buffer::try_new(usize::MAX, charge)) {
            Err(refused) => refused,
            Ok(_) => panic!("overflowing layout accepted"),
        };
        // The observer's original expected allocation remains unconsumed. The
        // same returned charge now funds the valid original request.
        let buffer = Buffer::try_new(1, charge).unwrap_or_else(|_| panic!("valid retry layout"));
        assert_eq!(record(0).layout, layout);
        assert_eq!(record(0).pointer, buffer.as_ptr() as usize);
        assert_eq!(funding.next, 1);
        without_allocations(|| drop(buffer));
        all_refunded(&funding);
    }

    #[test]
    fn empty_buffer_allocates_nothing_and_retains_its_original_zero_charge() {
        let mut funding = prepaid();
        type Buffer = FixedTrackingBuffer<Aligned, Charge>;
        let layout = Buffer::allocation_layout(0).unwrap();
        let charge = funding.take_allocation_charge(layout);
        let mut buffer = without_allocations(|| {
            Buffer::try_new(0, charge).unwrap_or_else(|_| panic!("valid zero layout"))
        });
        assert_eq!(record(0).layout, layout);
        assert_eq!(record(0).pointer, 0, "zero capacity has no allocation");
        assert!(!record(0).refunded);
        assert_eq!(buffer.capacity(), 0);
        assert!(buffer.as_slice().is_empty());
        assert!(catch_unwind(AssertUnwindSafe(|| buffer.push(Aligned(1)))).is_err());
        assert!(buffer.as_slice().is_empty());
        without_allocations(|| {
            assert_eq!(buffer.pop(), None);
            buffer.truncate(usize::MAX);
            buffer.truncate(0);
            assert_eq!(buffer.capacity(), 0);
            buffer.clear();
            drop(buffer);
        });
        all_refunded(&funding);
    }

    #[test]
    fn zero_sized_entries_keep_exact_logical_capacity_without_allocating() {
        let mut funding = prepaid();
        type Buffer = FixedTrackingBuffer<(), Charge>;
        let layout = Buffer::allocation_layout(3).unwrap();
        assert_eq!(layout.size(), 0);
        let charge = funding.take_allocation_charge(layout);
        without_allocations(|| {
            let mut buffer =
                Buffer::try_new(3, charge).unwrap_or_else(|_| panic!("valid ZST layout"));
            for _ in 0..3 {
                buffer.push(());
            }
            assert_eq!(buffer.capacity(), 3);
            assert_eq!(buffer.as_slice(), &[(), (), ()]);
            buffer.truncate(usize::MAX);
            assert_eq!(buffer.pop(), Some(()));
            assert_eq!(buffer.as_slice(), &[(), ()]);
            buffer.truncate(1);
            assert_eq!(buffer.pop(), Some(()));
            assert_eq!(buffer.pop(), None);
            assert_eq!(buffer.remaining_capacity(), Some(3));
            buffer.clear();
            assert!(buffer.as_slice().is_empty());
            buffer.push(());
            assert_eq!(buffer.as_slice(), &[()]);
            drop(buffer);
        });
        all_refunded(&funding);
    }

    #[test]
    fn panicking_refund_runs_after_backing_free_without_replaying_destruction() {
        struct PanicRefund(Option<Charge>);
        impl Drop for PanicRefund {
            fn drop(&mut self) {
                assert!(record(0).freed);
                drop(self.0.take());
                panic!("original refund callback panic");
            }
        }
        let mut funding = prepaid();
        type Buffer = FixedTrackingBuffer<usize, PanicRefund>;
        let charge = funding.take_allocation_charge(Buffer::allocation_layout(1).unwrap());
        let mut buffer = Buffer::try_new(1, PanicRefund(Some(charge)))
            .unwrap_or_else(|_| panic!("valid layout"));
        buffer.push(42);
        let panic = catch_unwind(AssertUnwindSafe(|| drop(buffer))).unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"original refund callback panic")
        );
        all_refunded(&funding);
    }
}
