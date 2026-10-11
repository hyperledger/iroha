//! Actual scalar-pair backing, original metadata and intact reader-held refusal.

use super::*;
use crate::{BlockAcquisition as _, allocation_test_support::without_allocations};
use iroha_allocation::{AllocationBudget, AllocationCharge, OwnedAllocationScope};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering::SeqCst},
};

#[test]
fn frozen_cell_pair_retains_original_values_metadata_and_replacement_cut() {
    for mode in [BlockMode::Ordinary, BlockMode::Replace] {
        let target = Cell::new(String::from("base"));
        let mut tip = target.block();
        *tip.get_mut() = String::from("tip");
        tip.commit();
        let mut block = match mode {
            BlockMode::Ordinary => target.block(),
            BlockMode::Replace => target.block_and_revert(),
        };
        *block.get_mut() = String::from("successor");
        let identity = block.publication_identity();
        let current = std::ptr::from_ref(block.get());
        let before = std::ptr::from_ref(block.get_before_block());
        let admission = Box::new(73_u64);
        let admission_pointer = std::ptr::from_ref(admission.as_ref());
        let original = block.try_detach(|_| Ok::<_, ()>(admission)).unwrap();
        let original = without_allocations(|| {
            let frozen = original.freeze_pair();
            assert_eq!(frozen.mode(), mode);
            assert!(frozen.is_dirty());
            assert!(frozen.belongs_to(&target));
            assert!(frozen.matches_current(&target));
            assert_eq!(frozen.publication_identity(), identity);
            assert_eq!(
                std::ptr::from_ref(frozen.admission().as_ref()),
                admission_pointer
            );
            assert_eq!(std::ptr::from_ref(frozen.get()), current);
            assert_eq!(std::ptr::from_ref(frozen.get_before_block()), before);
            assert_eq!(frozen.get(), "successor");
            assert_eq!(
                frozen.get_before_block(),
                if mode == BlockMode::Ordinary {
                    "tip"
                } else {
                    "base"
                }
            );
            assert!(frozen.touched_value().is_some());
            let readers = frozen.readers();
            assert!(frozen.matches_read(&readers));
            assert!(readers.same_original(&frozen.readers()));
            assert_eq!(readers.publication_identity(), &identity);
            assert_eq!(std::ptr::from_ref(&**readers.current()), current);
            assert_eq!(std::ptr::from_ref(readers.get_before_block()), before);
            assert_eq!(readers.undo().as_ref().unwrap(), frozen.get_before_block());
            drop(readers);
            let original = frozen
                .try_into_detached()
                .unwrap_or_else(|_| panic!("all exact readers retired"));
            assert_eq!(original.publication_identity(), identity);
            assert_eq!(original.mode(), mode);
            assert!(original.is_dirty());
            assert_eq!(
                std::ptr::from_ref(original.admission().as_ref()),
                admission_pointer
            );
            assert_eq!(std::ptr::from_ref(original.get()), current);
            assert_eq!(std::ptr::from_ref(original.get_before_block()), before);
            original
        });
        let prepared = original
            .try_prepare_publication(&target, |_, _| Ok::<_, ()>(()))
            .unwrap_or_else(|(_, error, _)| panic!("same original target/predecessor: {error:?}"));
        drop(prepared.publish());
        assert_eq!(std::ptr::from_ref(target.view().get()), current);
        assert_eq!(
            std::ptr::from_ref(target.predecessor_view().as_ref().unwrap()),
            before
        );
    }
}

#[test]
fn frozen_cell_pair_either_reader_refusal_retains_both_allocations_and_metadata() {
    for hold_current in [false, true] {
        let target = Cell::new(String::from("before"));
        let mut block = target.block();
        *block.get_mut() = String::from("after");
        let original = block.try_detach(|_| Ok::<_, ()>(Box::new(19_u64))).unwrap();
        let current = std::ptr::from_ref(original.get());
        let undo = std::ptr::from_ref(original.original_undo());
        let before = std::ptr::from_ref(original.get_before_block());
        let admission = std::ptr::from_ref(original.admission().as_ref());
        let identity = original.publication_identity();
        without_allocations(|| {
            let frozen = original.freeze_pair();
            let read = frozen.readers();
            let current_read = hold_current.then(|| read.current().clone());
            let undo_read = (!hold_current).then(|| read.undo().clone());
            drop(read);
            // With only current held, undo really thaws before the second owner
            // refuses. With only undo held, the original first owner refuses.
            let mut frozen = match frozen.try_into_detached() {
                Err(original) => original,
                Ok(_) => panic!("held exact backing must refuse thaw"),
            };
            for _ in 0..2 {
                assert_eq!(std::ptr::from_ref(frozen.get()), current);
                assert_eq!(std::ptr::from_ref(frozen.original_undo()), undo);
                assert_eq!(std::ptr::from_ref(frozen.get_before_block()), before);
                assert_eq!(std::ptr::from_ref(frozen.admission().as_ref()), admission);
                assert_eq!(frozen.publication_identity(), identity);
                let read = frozen.readers();
                if let Some(held) = &current_read {
                    assert!(held.same_source(read.current()));
                }
                if let Some(held) = &undo_read {
                    assert!(held.same_source(read.undo()));
                }
                drop(read);
                frozen = match frozen.try_into_detached() {
                    Err(original) => original,
                    Ok(_) => panic!("same actual reader still owns backing"),
                };
            }
            drop((current_read, undo_read));
            let original = frozen
                .try_into_detached()
                .unwrap_or_else(|_| panic!("both exact readers retired"));
            assert_eq!(std::ptr::from_ref(original.get()), current);
            assert_eq!(std::ptr::from_ref(original.original_undo()), undo);
            assert_eq!(std::ptr::from_ref(original.admission().as_ref()), admission);
            assert_eq!(original.publication_identity(), identity);
        });
    }
}

#[test]
fn frozen_cell_pair_equal_same_predecessor_or_foreign_work_never_substitutes_original() {
    let target = Cell::new(10_u64);
    let foreign = Cell::new(10_u64);
    let first = target
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap()
        .freeze_pair();
    let second = target
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap()
        .freeze_pair();
    let other = foreign
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap()
        .freeze_pair();
    let identity = first.publication_identity();
    assert_eq!(
        identity,
        second.publication_identity(),
        "same predecessor is intentionally insufficient"
    );
    assert_ne!(identity, other.publication_identity());
    let read = first.readers();
    let equal = second.readers();
    let foreign_read = other.readers();
    assert!(!read.same_original(&equal));
    assert!(!read.same_original(&foreign_read));
    assert!(!first.matches_read(&equal));
    assert!(!first.matches_read(&foreign_read));
    assert!(!first.belongs_to(&foreign));
    // Private-path corruption: preserve the actual original current and cut,
    // but replace only undo with a distinct same-predecessor allocation.
    let mut mixed = first.readers();
    mixed.revert = equal.undo().clone();
    assert!(!first.matches_read(&mixed));
    assert!(!read.same_original(&mixed));
    let pointer = std::ptr::from_ref(&**read.current());
    drop((read, equal, foreign_read, mixed, second, other));
    let original = first
        .try_into_detached()
        .unwrap_or_else(|_| panic!("exact original reads retired"));
    let (original, reason, cleanup) = match original
        .try_prepare_publication(&foreign, |_, _| -> Result<(), ()> {
            panic!("foreign source must refuse before admission")
        }) {
        Err(error) => error,
        Ok(_) => panic!("equal foreign source is not original"),
    };
    assert_eq!(reason, PublicationPreparationError::Changed);
    drop(cleanup);
    target.block().commit();
    assert_eq!(
        *target.view(),
        10,
        "actual same-value publication still rotates predecessor"
    );
    let (original, reason, cleanup) = match original
        .try_prepare_publication(&target, |_, _| -> Result<(), ()> {
            panic!("stale predecessor must refuse before admission")
        }) {
        Err(error) => error,
        Ok(_) => panic!("changed source must refuse original installation"),
    };
    assert_eq!(reason, PublicationPreparationError::Changed);
    assert_eq!(original.publication_identity(), identity);
    assert_eq!(std::ptr::from_ref(original.get()), pointer);
    drop(cleanup);
}

#[test]
fn frozen_cell_pair_preserves_untouched_and_nested_optional_preimages_without_new_views() {
    for initial in [None, Some(7_u64)] {
        let target = Cell::new(initial);
        let original = target.block().try_detach(|_| Ok::<_, ()>(())).unwrap();
        without_allocations(|| {
            let frozen = original.freeze_pair();
            assert!(frozen.original_undo().is_none());
            assert!(frozen.touched_value().is_none());
            assert!(std::ptr::eq(frozen.get(), frozen.get_before_block()));
            let read = frozen.readers();
            assert_eq!(**read.current(), initial);
            assert_eq!(**read.undo(), None);
            assert_eq!(read.get_before_block(), &initial);
        });
        let mut block = target.block();
        *block.get_mut() = Some(8);
        let frozen = block.try_detach(|_| Ok::<_, ()>(())).unwrap().freeze_pair();
        let read = frozen.readers();
        assert_eq!(**read.undo(), Some(initial));
        assert_eq!(read.get_before_block(), &initial);
        let mut later = target.block();
        *later.get_mut() = Some(9);
        later.commit();
        assert_eq!(**read.current(), Some(8));
        assert_eq!(frozen.original_undo(), &Some(initial));
        assert!(!frozen.matches_current(&target));
    }
}

fn charged_block<'a>(
    target: &'a Cell<u64, AllocationCharge>,
    budget: &AllocationBudget,
) -> Block<'a, u64, AllocationCharge> {
    let [current, undo] = Cell::<u64, AllocationCharge>::allocation_layouts();
    let next = CellPublicationSuccessor::allocation_layout();
    let mut reservation = budget.try_reserve_layouts([current, undo, next]).unwrap();
    let charges = CellAllocationCharges::new(
        reservation.try_split(current).unwrap(),
        reservation.try_split(undo).unwrap(),
    );
    let backing = CellGenerationBacking::try_from_charges(budget, charges)
        .unwrap_or_else(|_| panic!("actual same-pool backing"));
    let next =
        CellPublicationSuccessor::try_from_charge(budget, reservation.try_split(next).unwrap())
            .unwrap_or_else(|_| panic!("actual same-pool successor"));
    assert_eq!(reservation.remaining_bytes(), 0);
    let mut acquired = target
        .try_block_acquisition_with_backing(backing, next, budget)
        .unwrap_or_else(|_| panic!("original exact pool"));
    acquired.initialize(BlockMode::Ordinary);
    acquired.into_block()
}

#[test]
fn frozen_cell_pair_actual_pool_and_refund_scope_survive_refusal_until_values_retire() {
    struct Admission {
        scope: OwnedAllocationScope,
        baseline: usize,
        drops: Arc<AtomicUsize>,
    }
    impl Drop for Admission {
        fn drop(&mut self) {
            assert_eq!(
                self.scope.allocation_budget().reserved_bytes(),
                self.baseline + OwnedAllocationScope::allocation_layout().size(),
                "actual payload shells and successor retire before original scope admission"
            );
            self.drops.fetch_add(1, SeqCst);
        }
    }
    let budget = AllocationBudget::new(64 * 1024);
    let foreign = AllocationBudget::new(budget.limit_bytes());
    let target = CellInitialization::try_reserve(&budget)
        .unwrap()
        .initialize(7_u64, None);
    let baseline = budget.reserved_bytes();
    let mut block = charged_block(&target, &budget);
    *block.get_mut() = 8;
    let pointer = std::ptr::from_ref(block.get());
    let undo_pointer = std::ptr::from_ref(block.original_undo());
    let identity = block.publication_identity();
    let drops = Arc::new(AtomicUsize::new(0));
    let admission = Admission {
        scope: budget.try_owned_refund_scope().unwrap(),
        baseline,
        drops: Arc::clone(&drops),
    };
    let original = block.try_detach(|_| Ok::<_, ()>(admission)).unwrap();
    let peak = budget.reserved_bytes();
    let original = without_allocations(|| {
        let mut frozen = original.freeze_pair();
        let read = frozen.readers();
        let held = read.current().clone();
        drop(read);
        for _ in 0..3 {
            frozen = match frozen.try_into_detached() {
                Err(original) => original,
                Ok(_) => panic!("actual paid current handle must retain original backing"),
            };
            assert_eq!(budget.reserved_bytes(), peak);
            assert_eq!(drops.load(SeqCst), 0);
            assert_eq!(std::ptr::from_ref(frozen.get()), pointer);
            assert_eq!(std::ptr::from_ref(frozen.original_undo()), undo_pointer);
            assert_eq!(frozen.publication_identity(), identity);
            assert!(frozen.admission().scope.belongs_to(&budget));
            assert!(!frozen.admission().scope.belongs_to(&foreign));
            assert!(frozen.readers().current().same_source(&held));
        }
        drop(held);
        let original = frozen
            .try_into_detached()
            .unwrap_or_else(|_| panic!("actual paid reader retired"));
        assert_eq!(std::ptr::from_ref(original.get()), pointer);
        assert_eq!(std::ptr::from_ref(original.original_undo()), undo_pointer);
        assert_eq!(original.publication_identity(), identity);
        assert_eq!(budget.reserved_bytes(), peak);
        original
    });
    // Exact EBR payload/backing and next identity drop before original Admission;
    // the initial target remains alive, independently retaining its actual charges.
    drop(original);
    assert_eq!(drops.load(SeqCst), 1);
    assert_eq!(budget.reserved_bytes(), baseline);
    assert_eq!(foreign.reserved_bytes(), 0);
}
