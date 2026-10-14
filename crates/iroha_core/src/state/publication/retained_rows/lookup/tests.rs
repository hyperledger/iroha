//! Exact original lookup results, finite work and retained descriptor custody.

use super::*;
use crate::test_allocations::allocations_during;
use iroha_allocation::AllocationBudget;
use iroha_data_model::musubi::{
    ArchiveId, MusubiPackageIdV1, MusubiPackageScopeV1, MusubiReleaseIdV1,
};
use iroha_model_base::topology::DataSpaceId;
use mv::{BlockMode, storage::Storage};

const WORK: usize = 1_000_000;

fn key(value: u8) -> ArchiveId {
    ArchiveId::new([value; 32])
}

fn target() -> Storage<ArchiveId, String> {
    [(1, "base"), (2, "deleted"), (4, "equal"), (8, "untouched")]
        .into_iter()
        .map(|(id, value)| (key(id), value.into()))
        .collect()
}

fn read_for(
    target: &Storage<ArchiveId, String>,
    mode: BlockMode,
) -> (
    mv::storage::FrozenDetached<ArchiveId, String, ()>,
    OriginalTableRead<ArchiveId, String>,
) {
    let mut block = match mode {
        BlockMode::Ordinary => target.block(),
        BlockMode::Replace => target.block_and_revert(),
    };
    block.insert(key(1), "successor".into());
    block.remove(key(2));
    block.remove(key(3));
    block.insert(key(4), "equal".into());
    block.insert(key(5), "inserted".into());
    let detached = block.try_detach(|_| Ok::<(), ()>(())).unwrap();
    let counts = {
        let images = detached.original_images();
        (images.current_entries().len(), images.undo_entries().len())
    };
    let frozen = detached.freeze_pair();
    let read = OriginalTableRead::new(frozen.readers(), counts.0, counts.1);
    (frozen, read)
}

#[test]
fn exact_current_and_predecessor_lookup_keep_original_values_in_both_modes() {
    for mode in [BlockMode::Ordinary, BlockMode::Replace] {
        let original = target();
        let mut tip = original.block();
        tip.insert(key(1), "tip".into());
        tip.commit();
        let (frozen, mut read) = read_for(&original, mode);
        let budget = AllocationBudget::new(65_536);
        let mut work = 0;
        for prior in [false, true] {
            let result = if prior {
                read.predecessor_lookup(&key(1), &mut work, WORK)
            } else {
                read.current_lookup(&key(1), &mut work, WORK)
            };
            assert!(matches!(result, Err(RetainedPackageReadError::Incomplete)));
            assert_eq!(work, 0);
        }
        read.advance(&budget, &mut work, WORK).unwrap();
        assert!(
            read.current_lookup(&key(1), &mut work, WORK)
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            read.predecessor_lookup(&key(1), &mut work, WORK),
            Err(RetainedPackageReadError::Incomplete)
        ));
        read.advance_predecessor(&budget, &mut work, WORK).unwrap();
        let progress = read.predecessor_progress();
        let charged = budget.reserved_bytes();
        let allocation_count = allocations_during(|| {
            for id in 0..10 {
                let query = key(id);
                let current = read.current_lookup(&query, &mut work, WORK).unwrap();
                let predecessor = read.predecessor_lookup(&query, &mut work, WORK).unwrap();
                let expected_current = match id {
                    1 => Some("successor"),
                    4 => Some("equal"),
                    5 => Some("inserted"),
                    8 => Some("untouched"),
                    _ => None,
                };
                let expected_predecessor = match id {
                    1 if mode == BlockMode::Ordinary => Some("tip"),
                    1 => Some("base"),
                    2 => Some("deleted"),
                    4 => Some("equal"),
                    8 => Some("untouched"),
                    _ => None,
                };
                assert_eq!(current.map(|(_, value)| value.as_str()), expected_current);
                assert_eq!(
                    predecessor.map(|(_, value)| value.as_str()),
                    expected_predecessor
                );
                for (found, prior) in [(current, false), (predecessor, true)] {
                    if let Some((actual_key, value)) = found {
                        assert_eq!(actual_key, &query);
                        let count = if prior {
                            progress.rows
                        } else {
                            read.current_count
                        };
                        let actual = (0..count)
                            .find_map(|index| {
                                let row = if prior {
                                    read.predecessor_row(index, &mut work, WORK)
                                } else {
                                    read.current_row(index, &mut work, WORK)
                                }
                                .unwrap();
                                (row.0 == actual_key).then_some(row)
                            })
                            .unwrap();
                        assert!(std::ptr::eq(actual.0, actual_key));
                        assert!(
                            std::ptr::eq(actual.1, value),
                            "the exact original row allocation"
                        );
                    }
                }
            }
        });
        assert_eq!(allocation_count, 0);
        assert_eq!(budget.reserved_bytes(), charged);
        assert_eq!(read.predecessor_progress(), progress);
        drop(read);
        assert_eq!(budget.reserved_bytes(), 0);
        drop(
            frozen
                .try_into_detached()
                .unwrap_or_else(|_| panic!("original readers retired")),
        );
    }
}

#[test]
fn exact_lookup_resolve_and_comparison_refusals_keep_funded_original_progress() {
    for prior in [false, true] {
        for refuse_comparison in [false, true] {
            let original = target();
            let (frozen, mut read) = read_for(&original, BlockMode::Ordinary);
            let budget = AllocationBudget::new(65_536);
            let mut work = 0;
            read.advance(&budget, &mut work, WORK).unwrap();
            read.advance_predecessor(&budget, &mut work, WORK).unwrap();
            let current_pointer = read.current.as_ref().unwrap().as_slice().as_ptr();
            let predecessor_pointer = read.predecessor.rows_pointer_for_test().unwrap();
            let progress = read.predecessor_progress();
            let charge = budget.reserved_bytes();
            let query = key(if prior { 4 } else { 5 }); // actual first midpoint
            let mut resolve = 0;
            if prior {
                read.predecessor_row(2, &mut resolve, WORK).unwrap();
            } else {
                read.current_row(2, &mut resolve, WORK).unwrap();
            }
            let mut geometry = 0;
            let units = query.comparison_units(&mut geometry, WORK).unwrap();
            assert_eq!(units, geometry);
            let limit = work
                + 1
                + units
                + LOOKUP_CONTROL_WORK
                + if refuse_comparison {
                    resolve + units
                } else {
                    0
                };
            let allocation_count = allocations_during(|| {
                let result = if prior {
                    read.predecessor_lookup(&query, &mut work, limit)
                } else {
                    read.current_lookup(&query, &mut work, limit)
                };
                let Err(RetainedPackageReadError::Work {
                    used,
                    required,
                    limit: actual,
                }) = result
                else {
                    panic!("the exact original lookup demand must refuse before use: {result:?}");
                };
                assert_eq!(used, limit);
                assert_eq!(work, limit);
                assert_eq!(actual, limit);
                assert_eq!(
                    required,
                    limit
                        + if refuse_comparison {
                            2 * units
                        } else {
                            resolve
                        }
                );
                let repeat = if prior {
                    read.predecessor_lookup(&query, &mut work, limit)
                } else {
                    read.current_lookup(&query, &mut work, limit)
                };
                assert!(
                    matches!(repeat, Err(RetainedPackageReadError::Work { used, required, limit: actual })
                    if used == limit && required == limit + 1 && actual == limit)
                );
                assert_eq!(read.predecessor_progress(), progress);
                assert_eq!(
                    read.current.as_ref().unwrap().as_slice().as_ptr(),
                    current_pointer
                );
                assert_eq!(
                    read.predecessor.rows_pointer_for_test().unwrap(),
                    predecessor_pointer
                );
                assert_eq!(budget.reserved_bytes(), charge);
                let funded = if prior {
                    read.predecessor_lookup(&query, &mut work, WORK)
                } else {
                    read.current_lookup(&query, &mut work, WORK)
                }
                .unwrap()
                .unwrap();
                assert_eq!(funded.0, &query);
            });
            assert_eq!(allocation_count, 0);
            assert_eq!(budget.reserved_bytes(), charge);
            assert!(work > limit);
            drop(read);
            assert_eq!(budget.reserved_bytes(), 0);
            drop(frozen);
        }
    }
}

#[test]
fn exact_lookup_rejects_foreign_current_and_undo_positions() {
    for prior in [false, true] {
        let original = target();
        let (frozen, mut read) = read_for(&original, BlockMode::Ordinary);
        let foreign = target();
        let (other_frozen, mut other) = read_for(&foreign, BlockMode::Ordinary);
        let budget = AllocationBudget::new(65_536);
        let mut work = 0;
        for source in [&mut read, &mut other] {
            source.advance(&budget, &mut work, WORK).unwrap();
            source
                .advance_predecessor(&budget, &mut work, WORK)
                .unwrap();
        }
        if prior {
            // Predecessor midpoint key 4 resolves exact equal-value undo index 3.
            read.undo.as_mut().unwrap().as_mut_slice()[3] =
                other.undo.as_ref().unwrap().as_slice()[3].clone();
        } else {
            read.current.as_mut().unwrap().as_mut_slice()[2] =
                other.current.as_ref().unwrap().as_slice()[2].clone();
        }
        let progress = read.predecessor_progress();
        let charge = budget.reserved_bytes();
        let query = key(if prior { 4 } else { 5 });
        let result = if prior {
            read.predecessor_lookup(&query, &mut work, WORK)
        } else {
            read.current_lookup(&query, &mut work, WORK)
        };
        assert!(matches!(
            result,
            Err(RetainedPackageReadError::SourceChanged)
        ));
        assert_eq!(read.predecessor_progress(), progress);
        assert_eq!(budget.reserved_bytes(), charge);
        drop(read);
        drop(other);
        assert_eq!(budget.reserved_bytes(), 0);
        drop((frozen, other_frozen));
    }
}

#[test]
fn exact_lookup_variable_query_geometry_is_finite_and_empty_lookup_does_not_walk_it() {
    let package = MusubiPackageIdV1::new(
        DataSpaceId::new(9),
        MusubiPackageScopeV1::Domain("example".parse().unwrap()),
        "package".parse().unwrap(),
    );
    let query = MusubiReleaseIdV1::new(package, "1.2.3-alpha.4.longer".parse().unwrap());
    let target: Storage<_, String> = [(query.clone(), "original".into())].into_iter().collect();
    let detached = target.block().try_detach(|_| Ok::<(), ()>(())).unwrap();
    let frozen = detached.freeze_pair();
    let mut read = OriginalTableRead::new(frozen.readers(), 1, 0);
    let budget = AllocationBudget::new(65_536);
    let mut work = 0;
    read.advance(&budget, &mut work, WORK).unwrap();
    read.advance_predecessor(&budget, &mut work, WORK).unwrap();
    let mut geometry = 0;
    let units = query.comparison_units(&mut geometry, WORK).unwrap();
    let before = work;
    let limit = before + units; // initial branch leaves query one unit short
    assert!(matches!(
        read.predecessor_lookup(&query, &mut work, limit),
        Err(RetainedPackageReadError::Work { .. })
    ));
    assert!(work > before && work <= limit);
    assert_eq!(
        read.predecessor_lookup(&query, &mut work, WORK)
            .unwrap()
            .unwrap()
            .1,
        "original"
    );
    let empty: Storage<MusubiReleaseIdV1, String> = Storage::default();
    let empty_frozen = empty
        .block()
        .try_detach(|_| Ok::<(), ()>(()))
        .unwrap()
        .freeze_pair();
    let mut empty_read = OriginalTableRead::new(empty_frozen.readers(), 0, 0);
    empty_read.advance(&budget, &mut work, WORK).unwrap();
    empty_read
        .advance_predecessor(&budget, &mut work, WORK)
        .unwrap();
    let limit = work + 1;
    assert!(
        empty_read
            .predecessor_lookup(&query, &mut work, limit)
            .unwrap()
            .is_none()
    );
    assert_eq!(work, limit);
    assert!(
        matches!(empty_read.current_lookup(&query, &mut work, limit),
        Err(RetainedPackageReadError::Work { used, required, .. }) if used == limit && required == limit + 1)
    );
    drop((read, empty_read));
    assert_eq!(budget.reserved_bytes(), 0);
    drop((frozen, empty_frozen));
}

#[test]
fn retained_lookup_keeps_paid_geometry_and_comparison_across_native_refusal() {
    for predecessor in [false, true] {
        let target = target();
        let (_frozen, mut read) = read_for(&target, BlockMode::Ordinary);
        let budget = AllocationBudget::new(65_536);
        let mut work = 0;
        read.advance(&budget, &mut work, WORK).unwrap();
        read.advance_predecessor(&budget, &mut work, WORK).unwrap();
        let key = key(if predecessor { 4 } else { 5 });
        let mut resolve = 0;
        if predecessor {
            read.predecessor_row(2, &mut resolve, WORK).unwrap();
        } else {
            read.current_row(2, &mut resolve, WORK).unwrap();
        }
        let mut measured = 0;
        let key_units = key.comparison_units(&mut measured, WORK).unwrap();
        let limit = work + 1 + key_units + LOOKUP_CONTROL_WORK + resolve + key_units;
        let mut query = LookupCursor::new();
        let lookup = |query: &mut LookupCursor, work: &mut usize, limit| {
            if predecessor {
                read.predecessor_lookup_retained(&key, query, work, limit)
            } else {
                read.current_lookup_retained(&key, query, work, limit)
            }
        };
        assert!(matches!(
            lookup(&mut query, &mut work, limit),
            Err(RetainedPackageReadError::Work { .. })
        ));
        assert_eq!(work, limit);
        assert_eq!(query.phase, 4);
        assert_eq!(query.key.units, key_units);
        assert_eq!(query.candidate.units, key_units);
        let baseline = budget.reserved_bytes();
        assert_eq!(
            allocations_during(|| {
                assert!(matches!(lookup(&mut query, &mut work, limit),
                Err(RetainedPackageReadError::Work { used, required, limit: actual })
                if used == limit && required == limit + key_units * 2 && actual == limit));
            }),
            0
        );
        assert_eq!(work, limit);
        // Pay the canonical comparison but refuse its exact original native reborrow.
        let comparison_paid = limit + key_units * 2;
        assert!(matches!(
            lookup(&mut query, &mut work, comparison_paid),
            Err(RetainedPackageReadError::Work { .. })
        ));
        assert_eq!(work, comparison_paid);
        assert_eq!(
            query.phase, 5,
            "original comparison admission must survive native reborrow refusal"
        );
        let original = lookup(&mut query, &mut work, comparison_paid + resolve)
            .unwrap()
            .unwrap();
        assert_eq!(original.0, &key);
        assert_eq!(work, comparison_paid + resolve);
        assert_eq!(query.resolved, Some(Some(2)));
        assert_eq!(budget.reserved_bytes(), baseline);
        // A completed query only reborrows its original row, without a second search.
        let pointer = std::ptr::from_ref(original.1);
        let again = lookup(&mut query, &mut work, comparison_paid + resolve * 2)
            .unwrap()
            .unwrap();
        assert_eq!(std::ptr::from_ref(again.1), pointer);
        assert_eq!(work, comparison_paid + resolve * 2);
    }
}

#[test]
fn retained_variable_key_geometry_resumes_each_prefix_without_recharging_it() {
    let package = MusubiPackageIdV1::new(
        DataSpaceId::new(9),
        MusubiPackageScopeV1::Domain("example".parse().unwrap()),
        "package".parse().unwrap(),
    );
    let key = MusubiReleaseIdV1::new(package, "1.2.3-alpha.4.longer".parse().unwrap());
    let mut expected_work = 0;
    let expected = key.comparison_units(&mut expected_work, WORK).unwrap();
    let mut cursor = KeyWorkCursor::default();
    let mut work = 0;
    let mut ceiling = 0;
    let mut refusals = 0;
    loop {
        match key.comparison_units_retained(&mut cursor, &mut work, ceiling) {
            Ok(actual) => {
                assert_eq!(actual, expected);
                break;
            }
            Err(RetainedPackageReadError::Work {
                used,
                required,
                limit,
            }) => {
                assert_eq!(used, work);
                assert_eq!(limit, ceiling);
                assert!(required > limit);
                let before = work;
                assert!(
                    key.comparison_units_retained(&mut cursor, &mut work, ceiling)
                        .is_err()
                );
                assert_eq!(work, before);
                ceiling += 1;
                refusals += 1;
            }
            Err(error) => panic!("unexpected original key refusal: {error:?}"),
        }
    }
    assert!(refusals > 16);
    assert_eq!(work, expected_work);
    let final_limit = work;
    assert_eq!(
        key.comparison_units_retained(&mut cursor, &mut work, final_limit)
            .unwrap(),
        expected
    );
}
