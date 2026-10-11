//! Actual original-pair predecessor rows, funded descriptors and refusal retries.

use super::*;
use crate::test_allocations::allocations_during;
use concread::bptree::{BptreeMapFrozenReader, BptreeMapRowPosition};
use iroha_allocation::ChargedBufferError;
use iroha_data_model::musubi::{
    ArchiveId, MusubiPackageIdV1, MusubiPackageScopeV1, MusubiReleaseIdV1,
};
use iroha_model_base::topology::DataSpaceId;
use mv::{BlockMode, storage::Storage};
use std::{alloc::Layout, mem::size_of};

fn key(value: u8) -> ArchiveId {
    ArchiveId::new([value; 32])
}

fn target() -> Storage<ArchiveId, String> {
    [(1, "base"), (2, "deleted"), (4, "equal"), (8, "untouched")]
        .into_iter()
        .map(|(id, value)| (key(id), value.into()))
        .collect()
}

type ReadFixture = (
    mv::storage::FrozenDetached<ArchiveId, String, ()>,
    OriginalTableRead<ArchiveId, String>,
    [(ArchiveId, usize); 4],
);

fn read_for(target: &Storage<ArchiveId, String>, mode: BlockMode) -> ReadFixture {
    let mut block = match mode {
        BlockMode::Ordinary => target.block(),
        BlockMode::Replace => target.block_and_revert(),
    };
    block.insert(key(1), "successor".into());
    block.remove(key(2));
    block.remove(key(3)); // explicit absent-to-absent preimage
    block.insert(key(4), "equal".into());
    block.insert(key(5), "inserted".into());
    let expected = [1, 2, 4, 8].map(|id| {
        (
            key(id),
            std::ptr::from_ref(block.get_before_block(&key(id)).unwrap()).addr(),
        )
    });
    let detached = block.try_detach(|_| Ok::<(), ()>(())).unwrap();
    let counts = {
        let images = detached.original_images();
        (images.current_entries().len(), images.undo_entries().len())
    };
    let frozen = detached.freeze_pair();
    let read = OriginalTableRead::new(frozen.readers(), counts.0, counts.1);
    (frozen, read, expected)
}

#[test]
fn retained_predecessor_ordered_merge_matches_exact_original_before_rows_in_both_modes() {
    for mode in [BlockMode::Ordinary, BlockMode::Replace] {
        let original = target();
        let mut tip = original.block();
        tip.insert(key(1), "tip".into());
        tip.commit();
        let (frozen, mut read, expected) = read_for(&original, mode);
        let budget = AllocationBudget::new(1 << 20);
        let mut work = 0;
        assert!(matches!(
            read.predecessor_row(0, &mut work, usize::MAX),
            Err(RetainedPackageReadError::Incomplete)
        ));
        read.advance(&budget, &mut work, usize::MAX).unwrap();
        read.advance_predecessor(&budget, &mut work, usize::MAX)
            .unwrap();
        let progress = read.predecessor_progress();
        assert!(progress.complete);
        assert_eq!(progress.rows, 4);
        assert_eq!(progress.current_consumed, 4);
        assert_eq!(progress.undo_consumed, 5);
        let charge = budget.reserved_bytes();
        let allocated = allocations_during(|| {
            for (index, (expected_key, pointer)) in expected.iter().enumerate() {
                let (actual_key, value) =
                    read.predecessor_row(index, &mut work, usize::MAX).unwrap();
                assert_eq!(actual_key, expected_key);
                assert_eq!(
                    std::ptr::from_ref(value).addr(),
                    *pointer,
                    "original preimage value allocation"
                );
                let expected_value = match index {
                    0 => {
                        if mode == BlockMode::Ordinary {
                            "tip"
                        } else {
                            "base"
                        }
                    }
                    1 => "deleted",
                    2 => "equal",
                    3 => "untouched",
                    _ => unreachable!(),
                };
                assert_eq!(value, expected_value);
            }
        });
        assert_eq!(
            allocated, 0,
            "descriptor resolve cannot clone a key/value or scan nth rows"
        );
        assert_eq!(budget.reserved_bytes(), charge);
        assert!(matches!(
            read.predecessor_row(4, &mut work, usize::MAX),
            Err(RetainedPackageReadError::Incomplete)
        ));
        drop(read);
        assert_eq!(
            budget.reserved_bytes(),
            0,
            "all actual index backing retires"
        );
        let detached = frozen
            .try_into_detached()
            .unwrap_or_else(|_| panic!("all original row owners retired"));
        assert_eq!(detached.mode(), mode);
        assert_eq!(
            detached.get_before_block(&key(1)).unwrap().as_str(),
            if mode == BlockMode::Ordinary {
                "tip"
            } else {
                "base"
            }
        );
    }
}

#[test]
fn retained_predecessor_backing_refusal_keeps_original_positions_pool_and_refund_order() {
    let original = target();
    let (frozen, mut read, _) = read_for(&original, BlockMode::Ordinary);
    let budget = AllocationBudget::new(1 << 20);
    let mut work = 0;
    read.advance(&budget, &mut work, usize::MAX).unwrap();
    let before = read.observe(work, false);
    let layout =
        Layout::array::<PredecessorPosition>(read.current_count + read.undo_count).unwrap();
    let position_pointer = read.current.as_ref().unwrap().as_slice().as_ptr();
    let charged = budget.reserved_bytes();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - charged - layout.size() + 1)
        .unwrap();
    let expected = budget.try_reserve(layout).unwrap_err();
    let allocated = allocations_during(|| {
        for _ in 0..2 {
            let Err(RetainedPackageReadError::Allocation(ChargedBufferError::Admission(actual))) =
                read.advance_predecessor(&budget, &mut work, usize::MAX)
            else {
                panic!("original descriptor pool must refuse before allocation");
            };
            assert_eq!(actual, expected);
            assert_eq!(read.observe(work, false), before);
            assert_eq!(
                read.current.as_ref().unwrap().as_slice().as_ptr(),
                position_pointer
            );
            assert_eq!(read.predecessor_progress().rows, 0);
        }
    });
    assert_eq!(allocated, 0);
    drop(occupied);
    read.advance_predecessor(&budget, &mut work, usize::MAX)
        .unwrap();
    assert_eq!(budget.reserved_bytes(), charged + layout.size());
    assert_eq!(
        read.current.as_ref().unwrap().as_slice().as_ptr(),
        position_pointer
    );
    let held = read.source.current().clone();
    drop(read);
    assert_eq!(budget.reserved_bytes(), 0);
    let frozen = match frozen.try_into_detached() {
        Err(same) => same,
        Ok(_) => panic!("outside original reader still owns cursor"),
    };
    assert!(frozen.readers().current().same_original(&held));
    drop(held);
    drop(
        frozen
            .try_into_detached()
            .unwrap_or_else(|_| panic!("same source thaws after reader retirement")),
    );
}

fn resolve_amount<V: mv::Value>(
    source: &BptreeMapFrozenReader<ArchiveId, V>,
    position: &BptreeMapRowPosition<ArchiveId, V>,
) -> usize {
    let mut amount = 0;
    source
        .resolve(position, |required| {
            amount = required;
            Ok::<(), ()>(())
        })
        .unwrap();
    amount
}

#[test]
fn retained_predecessor_later_work_refusal_preserves_descriptor_heads_frontiers_and_pool() {
    let original = target();
    let (frozen, mut read, _) = read_for(&original, BlockMode::Ordinary);
    let budget = AllocationBudget::new(1 << 20);
    let mut work = 0;
    read.advance(&budget, &mut work, usize::MAX).unwrap();
    // Derive the limit from the actual original tree's admitted resolve bounds
    // and the closed fixed-key geometry. It ends after one real merge result
    // and both next heads, immediately before the next actual merge step.
    let current = read.current.as_ref().unwrap().as_slice();
    let undo = read.undo.as_ref().unwrap().as_slice();
    let c0 = resolve_amount(read.source.current(), &current[0]);
    let u0 = resolve_amount(read.source.undo(), &undo[0]);
    let c1 = resolve_amount(read.source.current(), &current[1]);
    let u1 = resolve_amount(read.source.undo(), &undo[1]);
    let units = size_of::<ArchiveId>() + 1;
    let limit = work
        + (c0 + units)
        + (u0 + units)
        + (MERGE_CONTROL_WORK + c0 + u0 + 2 * units)
        + (c1 + units)
        + (u1 + units);
    assert!(
        matches!(read.advance_predecessor(&budget,&mut work,limit),Err(RetainedPackageReadError::Work{used,limit:actual,..})if used==limit&&actual==limit)
    );
    let prefix = read.predecessor_progress();
    assert_eq!(prefix.rows, 1);
    assert_eq!(prefix.current_consumed, 1);
    assert_eq!(prefix.undo_consumed, 1);
    assert!(!prefix.complete);
    let pointer = read.predecessor.rows.as_ref().unwrap().as_slice().as_ptr();
    let first = read.predecessor.rows.as_ref().unwrap().as_slice()[0];
    let charge = budget.reserved_bytes();
    let allocated = allocations_during(|| {
        for _ in 0..2 {
            assert!(
                matches!(read.advance_predecessor(&budget,&mut work,limit),Err(RetainedPackageReadError::Work{used,..})if used==limit)
            );
            assert_eq!(
                read.predecessor_progress(),
                prefix,
                "same completed descriptor frontiers survive refusal"
            );
            assert_eq!(
                read.predecessor.rows.as_ref().unwrap().as_slice().as_ptr(),
                pointer
            );
            assert_eq!(read.predecessor.rows.as_ref().unwrap().as_slice()[0], first);
            assert_eq!(budget.reserved_bytes(), charge);
        }
    });
    assert_eq!(
        allocated, 0,
        "no descriptor/key planning storage rebuilt on retry"
    );
    read.advance_predecessor(&budget, &mut work, usize::MAX)
        .unwrap();
    assert_eq!(
        read.predecessor.rows.as_ref().unwrap().as_slice().as_ptr(),
        pointer
    );
    assert!(read.predecessor_progress().complete);
    assert!(work > limit);
    drop(read);
    assert_eq!(budget.reserved_bytes(), 0);
    drop(frozen);
}

#[test]
fn retained_predecessor_foreign_positions_and_corrupted_geometry_cannot_supply_rows() {
    let original = target();
    let (_, mut read, _) = read_for(&original, BlockMode::Ordinary);
    let foreign = target();
    let (_, mut other, _) = read_for(&foreign, BlockMode::Ordinary);
    let budget = AllocationBudget::new(1 << 20);
    let mut work = 0;
    read.advance(&budget, &mut work, usize::MAX).unwrap();
    other.advance(&budget, &mut work, usize::MAX).unwrap();
    read.current.as_mut().unwrap().as_mut_slice()[0] =
        other.current.as_ref().unwrap().as_slice()[0].clone();
    let before = work;
    assert!(matches!(
        read.advance_predecessor(&budget, &mut work, usize::MAX),
        Err(RetainedPackageReadError::SourceChanged)
    ));
    assert_eq!(
        work, before,
        "foreign physical source rejects before quota admission"
    );
    assert_eq!(read.predecessor_progress().rows, 0);
    assert!(!read.predecessor_progress().complete);
    let original = target();
    let (_, mut geometry, _) = read_for(&original, BlockMode::Ordinary);
    geometry.current_complete = true;
    geometry.undo_complete = true;
    geometry.current_count = usize::MAX;
    let allocated = allocations_during(|| {
        assert!(matches!(
            geometry.advance_predecessor(&budget, &mut work, usize::MAX),
            Err(RetainedPackageReadError::Geometry)
        ));
    });
    assert_eq!(allocated, 0);
    assert_eq!(work, before);
}

#[test]
fn retained_predecessor_variable_key_geometry_is_admitted_before_comparison() {
    let package = MusubiPackageIdV1::new(
        DataSpaceId::new(9),
        MusubiPackageScopeV1::Domain("example".parse().unwrap()),
        "package".parse().unwrap(),
    );
    let release = MusubiReleaseIdV1::new(package, "1.2.3-alpha.4.longer".parse().unwrap());
    let mut work = 0;
    let units = release.comparison_units(&mut work, usize::MAX).unwrap();
    assert_eq!(units, work);
    assert!(units > 3 * 8 + release.version.prerelease.len());
    let mut prefix = 0;
    assert!(matches!(
        release.comparison_units(&mut prefix, units - 1),
        Err(RetainedPackageReadError::Work { .. })
    ));
    assert!(prefix > 0 && prefix < units);
    let before = prefix;
    assert!(release.comparison_units(&mut prefix, before).is_err());
    assert_eq!(prefix, before);
    let mut full = 0;
    let allocated = allocations_during(|| {
        assert_eq!(
            release.comparison_units(&mut full, usize::MAX).unwrap(),
            units
        )
    });
    assert_eq!(allocated, 0);
    assert_eq!(full, units);
}

#[test]
fn retained_predecessor_variable_semver_merge_has_only_one_original_pool_allocation() {
    let package = MusubiPackageIdV1::new(
        DataSpaceId::new(9),
        MusubiPackageScopeV1::Domain("example".parse().unwrap()),
        "package".parse().unwrap(),
    );
    let alpha = MusubiReleaseIdV1::new(package.clone(), "1.2.3-alpha".parse().unwrap());
    let inserted = MusubiReleaseIdV1::new(package.clone(), "1.2.3-alpha.2".parse().unwrap());
    let stable = MusubiReleaseIdV1::new(package, "1.2.3".parse().unwrap());
    let target: Storage<_, String> = [
        (alpha.clone(), "alpha-before".into()),
        (stable.clone(), "stable-untouched".into()),
    ]
    .into_iter()
    .collect();
    let mut block = target.block();
    block.insert(alpha.clone(), "alpha-after".into());
    block.insert(inserted, "inserted".into());
    let expected = [
        std::ptr::from_ref(block.get_before_block(&alpha).unwrap()),
        std::ptr::from_ref(block.get_before_block(&stable).unwrap()),
    ];
    let original = block.try_detach(|_| Ok::<(), ()>(())).unwrap();
    let counts = {
        let images = original.original_images();
        (images.current_entries().len(), images.undo_entries().len())
    };
    let frozen = original.freeze_pair();
    let mut read = OriginalTableRead::new(frozen.readers(), counts.0, counts.1);
    let budget = AllocationBudget::new(1 << 20);
    let mut work = 0;
    read.advance(&budget, &mut work, usize::MAX).unwrap();
    let before = budget.reserved_bytes();
    let layout = Layout::array::<PredecessorPosition>(counts.0 + counts.1).unwrap();
    let allocated = allocations_during(|| {
        read.advance_predecessor(&budget, &mut work, usize::MAX)
            .unwrap()
    });
    assert_eq!(
        allocated, 1,
        "only the exact admitted descriptor backing allocates; semantic key order allocates nothing"
    );
    assert_eq!(budget.reserved_bytes(), before + layout.size());
    assert_eq!(read.predecessor_progress().rows, 2);
    for (index, key) in [alpha, stable].iter().enumerate() {
        let (actual, value) = read.predecessor_row(index, &mut work, usize::MAX).unwrap();
        assert_eq!(actual, key);
        assert_eq!(std::ptr::from_ref(value), expected[index]);
    }
    drop(read);
    assert_eq!(budget.reserved_bytes(), 0);
    drop(frozen);
}
