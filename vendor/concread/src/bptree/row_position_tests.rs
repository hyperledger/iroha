//! Exact original row positions, finite work, immutable handoff and retirement.

use super::*;
use crate::internals::bptree::node::allocation_tests::without_allocations;
use crate::internals::bptree::positions::PATH_CAPACITY;
use std::cell::Cell;

fn populated(count: usize) -> (BptreeMap<usize, usize>, BptreeMapOwned<usize, usize>) {
    let map = BptreeMap::new();
    let mut writer = map.write();
    for key in 0..count {
        writer.insert(key, key * 3);
    }
    let owner = writer.detach();
    (map, owner)
}

fn admit(_: usize) -> Result<(), ()> {
    Ok(())
}

#[test]
fn frozen_positions_capture_complete_original_rows_without_allocating_or_cloning() {
    for count in [0, 1, 6, 7, 8, 63, 64, 127, 128, 255, 1024] {
        let (map, owner) = populated(count);
        let expected_pointers: Vec<_> = owner
            .iter()
            .map(|(key, value)| (std::ptr::from_ref(key), std::ptr::from_ref(value)))
            .collect();
        let frozen = without_allocations(|| owner.freeze());
        let reader = without_allocations(|| frozen.reader());
        let mut positions = without_allocations(|| reader.positions());
        let observed = Cell::new(0_usize);
        for key in 0..count {
            without_allocations(|| {
                let position = positions
                    .try_next(|bound| {
                        assert_eq!(bound, NEXT_WORK_BOUND);
                        observed.set(observed.get() + bound);
                        Ok::<_, ()>(())
                    })
                    .unwrap()
                    .unwrap();
                let copy = position.clone();
                let (actual_key, value) = reader
                    .resolve(&copy, |bound| {
                        assert_eq!(bound, position.path.depth + 1);
                        assert!(bound <= PATH_CAPACITY);
                        observed.set(observed.get() + bound);
                        Ok::<_, ()>(())
                    })
                    .unwrap();
                assert_eq!((*actual_key, *value), (key, key * 3));
                assert_eq!(
                    (std::ptr::from_ref(actual_key), std::ptr::from_ref(value)),
                    expected_pointers[key]
                );
            });
        }
        without_allocations(|| {
            assert!(positions
                .try_next(|_| -> Result<(), ()> {
                    panic!("completed traversal examines no original node")
                })
                .unwrap()
                .is_none());
        });
        assert!(count == 0 || observed.get() >= count * NEXT_WORK_BOUND);
        drop((positions, reader));
        let owner = without_allocations(|| frozen.try_into_owned())
            .unwrap_or_else(|_| panic!("all original readers retired"));
        assert_eq!(owner.len(), count);
        drop((owner, map));
    }
}

#[test]
fn frozen_positions_reject_equal_foreign_and_replaced_original_work_before_admission() {
    let (map, owner) = populated(8);
    let (foreign_map, foreign_owner) = populated(8);
    let frozen = owner.freeze();
    let foreign = foreign_owner.freeze();
    let reader = frozen.reader();
    let foreign_reader = foreign.reader();
    let mut positions = reader.positions();
    let position = positions.try_next(admit).unwrap().unwrap();
    assert!(!reader.same_original(&foreign_reader));
    without_allocations(|| {
        assert_eq!(
            foreign_reader.resolve(&position, |_| -> Result<(), ()> {
                panic!("foreign source must refuse before read-work admission")
            }),
            Err(RowPositionError::ForeignOwner)
        );
    });
    // Same target and exact same predecessor are still another work allocation.
    let replacement = map.write().detach().freeze();
    let replacement_reader = replacement.reader();
    assert!(!reader.same_original(&replacement_reader));
    assert_eq!(
        replacement_reader.resolve(&position, admit),
        Err(RowPositionError::ForeignOwner)
    );
    assert_eq!(reader.resolve(&position, admit).unwrap(), (&0, &0));
    drop((
        replacement_reader,
        replacement,
        position,
        positions,
        reader,
        foreign_reader,
    ));
    drop((frozen, foreign, map, foreign_map));
}

#[test]
fn frozen_positions_refused_thaw_retains_exact_source_and_completed_rows() {
    let (map, owner) = populated(64);
    let pointer = owner.get(&0).map(std::ptr::from_ref).unwrap();
    let frozen = owner.freeze();
    let reader = frozen.reader();
    let mut positions = reader.positions();
    let position = positions.try_next(admit).unwrap().unwrap();
    let retained_copy = position.clone();
    let frozen = without_allocations(|| match frozen.try_into_owned() {
        Err(original) => original,
        Ok(_) => panic!("original reader excludes mutable handoff"),
    });
    assert_eq!(
        reader
            .resolve(&position, admit)
            .map(|(_, value)| std::ptr::from_ref(value)),
        Ok(pointer)
    );
    drop((reader, positions, position));
    let frozen = without_allocations(|| match frozen.try_into_owned() {
        Err(original) => original,
        Ok(_) => panic!("retained original position still excludes mutable handoff"),
    });
    drop(retained_copy);
    let owner = without_allocations(|| frozen.try_into_owned())
        .unwrap_or_else(|_| panic!("last original read handle retired"));
    assert_eq!(owner.get(&0).map(std::ptr::from_ref), Some(pointer));
    let writer = map
        .try_write_owned(owner)
        .unwrap_or_else(|_| panic!("same original predecessor"));
    writer.commit();
    assert_eq!(map.read().get(&63), Some(&189));
}

#[test]
fn frozen_positions_old_source_survives_target_advance_drop_and_stale_reacquisition() {
    let (map, owner) = populated(64);
    let frozen = owner.freeze();
    let reader = frozen.reader();
    let mut positions = reader.positions();
    let position = positions.try_next(admit).unwrap().unwrap();
    let original_pointer = reader
        .resolve(&position, admit)
        .map(|(_, value)| std::ptr::from_ref(value))
        .unwrap();
    let mut advance = map.write();
    advance.insert(0, 999);
    advance.commit();
    let newest = map.write().detach().freeze();
    let newest_reader = newest.reader();
    assert_eq!(
        newest_reader.resolve(&position, admit),
        Err(RowPositionError::ForeignOwner)
    );
    drop((newest_reader, newest, positions));
    assert_eq!(
        reader
            .resolve(&position, admit)
            .map(|(_, value)| std::ptr::from_ref(value)),
        Ok(original_pointer)
    );
    drop((reader, position));
    let owner = frozen
        .try_into_owned()
        .unwrap_or_else(|_| panic!("original handles retired"));
    let (owner, error) = match map.try_write_owned(owner) {
        Err(original) => original,
        Ok(_) => panic!("thaw does not grant stale predecessor publication"),
    };
    assert_eq!(error, OwnedWriteError::Changed);
    let frozen = owner.freeze();
    let reader = frozen.reader();
    let mut positions = reader.positions();
    let position = positions.try_next(admit).unwrap().unwrap();
    drop((map, frozen));
    without_allocations(|| {
        assert_eq!(
            reader
                .resolve(&position, admit)
                .map(|(_, value)| std::ptr::from_ref(value)),
            Ok(original_pointer)
        );
    });
    drop((positions, reader, position));
}

#[test]
fn frozen_positions_preserve_cumulative_work_and_successful_prefix_on_refusal() {
    let (map, owner) = populated(8);
    let frozen = owner.freeze();
    let reader = frozen.reader();
    let mut positions = reader.positions();
    let charged = Cell::new(0_usize);
    let first = positions
        .try_next(|bound| {
            charged.set(charged.get() + bound);
            Ok::<_, u8>(())
        })
        .unwrap()
        .unwrap();
    assert!(matches!(
        without_allocations(|| positions.try_next(|bound| {
            assert_eq!(bound, NEXT_WORK_BOUND);
            assert_eq!(charged.get(), NEXT_WORK_BOUND);
            Err(17_u8)
        })),
        Err(RowPositionError::Work(17))
    ));
    let second = positions
        .try_next(|bound| {
            charged.set(charged.get() + bound);
            Ok::<_, u8>(())
        })
        .unwrap()
        .unwrap();
    assert_eq!(reader.resolve(&first, admit).unwrap(), (&0, &0));
    assert_eq!(reader.resolve(&second, admit).unwrap(), (&1, &3));
    let prefix = charged.get();
    assert_eq!(prefix, 2 * NEXT_WORK_BOUND);
    assert_eq!(
        reader.resolve(&second, |bound| {
            assert!(bound <= PATH_CAPACITY);
            assert_eq!(charged.get(), prefix);
            Err(23_u8)
        }),
        Err(RowPositionError::Work(23))
    );
    assert_eq!(
        reader
            .resolve(&second, |bound| {
                charged.set(charged.get() + bound);
                Ok::<_, u8>(())
            })
            .unwrap(),
        (&1, &3)
    );
    assert!(charged.get() > prefix);
    drop((positions, first, second, reader, frozen, map));
}

#[test]
fn frozen_positions_private_path_corruption_refuses_with_checked_finite_work() {
    let (map, owner) = populated(64);
    let frozen = owner.freeze();
    let reader = frozen.reader();
    let mut positions = reader.positions();
    let original = positions.try_next(admit).unwrap().unwrap();
    assert!(original.path.depth > 0);
    for damage in 0..5 {
        let mut damaged = original.clone();
        match damage {
            0 => damaged.path.depth = PATH_CAPACITY,
            1 => damaged.path.children[0] = usize::MAX,
            2 => damaged.path.row = usize::MAX,
            3 => damaged.path.depth -= 1,
            _ => damaged.path.depth = usize::MAX,
        }
        let admitted = Cell::new(0);
        assert_eq!(
            without_allocations(|| reader.resolve(&damaged, |bound| {
                assert!(bound <= PATH_CAPACITY);
                admitted.set(bound);
                Ok::<_, ()>(())
            })),
            Err(RowPositionError::InvalidPosition)
        );
        assert_eq!(admitted.get() == 0, damage == 0 || damage == 4);
    }
    // Corrupt a traversal path too: no wrap, unchecked slot or nth rescan.
    positions.previous.as_mut().unwrap().children[0] = usize::MAX;
    assert!(matches!(
        positions.try_next(admit),
        Err(RowPositionError::InvalidPosition)
    ));
    assert_eq!(reader.resolve(&original, admit).unwrap(), (&0, &0));
    drop((original, positions, reader, frozen, map));
}

struct OriginalPolicy {
    reservation: iroha_allocation::AllocationReservation,
}

impl NodeFunding for OriginalPolicy {
    type Charge = iroha_allocation::AllocationCharge;
    fn take_node_charge(&mut self, layout: std::alloc::Layout) -> Self::Charge {
        self.reservation
            .try_split(layout)
            .expect("actual prepaid original allocation")
    }
}

#[derive(Clone)]
struct Value {
    number: usize,
    pool: iroha_allocation::AllocationBudget,
}

impl Drop for Value {
    fn drop(&mut self) {
        assert!(
            self.pool.reserved_bytes() > 0,
            "original value dies before original graph credit refunds"
        );
    }
}

impl NodeCloning<usize, Value> for OriginalPolicy {
    fn clone_key(&mut self, key: &usize) -> usize {
        *key
    }
    fn clone_value(&mut self, value: &Value) -> Value {
        value.clone()
    }
}

impl ClonePlanning<usize, Value> for OriginalPolicy {
    fn plan_key(_: &usize, _: &mut AllocationDemand) -> Result<(), PlanningError> {
        Ok(())
    }
    fn plan_value(_: &Value, _: &mut AllocationDemand) -> Result<(), PlanningError> {
        Ok(())
    }
}

#[test]
fn frozen_positions_retain_actual_original_pool_until_last_payload_owner_drops() {
    let pool = iroha_allocation::AllocationBudget::new(1024 * 1024);
    let provider = |demand: AllocationDemand| {
        pool.try_reserve_bytes(demand.bytes())
            .map(|reservation| OriginalPolicy { reservation })
    };
    let map =
        BptreeMap::<usize, Value, Prepaid<OriginalPolicy>>::try_new_with_node_custody(provider)
            .unwrap();
    let (owner, previous) = map
        .try_insert_admitted(
            1,
            Value {
                number: 9,
                pool: pool.clone(),
            },
            provider,
        )
        .unwrap_or_else(|_| panic!("original funded scalar source"));
    assert!(previous.is_none());
    let frozen = owner.freeze();
    let reader = frozen.reader();
    let mut positions = reader.positions();
    let position = without_allocations(|| positions.try_next(admit))
        .unwrap()
        .unwrap();
    let reserved = pool.reserved_bytes();
    assert!(reserved > 0);
    without_allocations(|| {
        let copy = position.clone();
        assert_eq!(reader.resolve(&copy, admit).unwrap().1.number, 9);
        assert_eq!(pool.reserved_bytes(), reserved);
    });
    drop((map, frozen, positions));
    assert!(pool.reserved_bytes() > 0);
    without_allocations(|| {
        assert_eq!(reader.resolve(&position, admit).unwrap().1.number, 9);
    });
    drop(reader);
    assert!(pool.reserved_bytes() > 0);
    drop(position);
    assert_eq!(pool.reserved_bytes(), 0);
}
