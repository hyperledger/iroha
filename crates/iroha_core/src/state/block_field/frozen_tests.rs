//! Real typed fields retain private reads and source custody while writers are free.

use super::super::*;
use mv::{
    PublicationPreparationError,
    cell::Cell,
    storage::{Storage, StorageReadOnly},
};
use std::{
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
    task::{Context, Wake, Waker},
};

struct Pair<'a> {
    cell: CellField<'a, String>,
    map: StorageField<'a, u64, String>,
}
impl Drop for Pair<'_> {
    fn drop(&mut self) {
        self.cell.release_writers();
        self.map.release_writers();
    }
}

struct Notice(AtomicUsize);
impl Wake for Notice {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, SeqCst);
    }
}

#[test]
fn frozen_typed_inventory_keeps_exact_reads_and_snapshot_with_all_writers_free() {
    for mode in [mv::BlockMode::Ordinary, mv::BlockMode::Replace] {
        let cell = Cell::new(String::from("initial"));
        let map = Storage::<u64, String>::from_iter([(1, "initial".into()), (2, "keep".into())]);
        let mut tip = cell.block();
        *tip.get_mut() = "tip".into();
        tip.commit();
        let mut tip = map.block();
        tip.insert(1, "tip".into());
        tip.commit();
        let mut pair = Pair {
            cell: BlockField::new(if mode == mv::BlockMode::Ordinary {
                cell.block()
            } else {
                cell.block_and_revert()
            }),
            map: BlockField::new(if mode == mv::BlockMode::Ordinary {
                map.block()
            } else {
                map.block_and_revert()
            }),
        };
        *pair.cell.get_mut() = "original successor".into();
        pair.map.insert(1, "original successor".into());
        pair.map.remove(2);
        pair.map.insert(3, "new".into());
        let cell_pointer = pair.cell.get().as_ptr();
        let map_pointer = pair.map.get(&1).unwrap().as_ptr();
        let cell_before = pair.cell.get_before_block().as_ptr();
        let map_before = pair.map.get_before_block(&1).unwrap().as_ptr();
        let cell_undo = pair.cell.original_undo().as_ref().unwrap().as_ptr();
        let map_undo = pair
            .map
            .original_undo_entries()
            .map(|(key, value)| (*key, value.as_ref().map(|text| text.as_ptr())))
            .collect::<Vec<_>>();
        assert_eq!(
            map_undo.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert!(
            map_undo[2].1.is_none(),
            "original insertion has an absent preimage"
        );
        let cell_identity = pair.cell.publication_identity();
        let map_identity = pair.map.publication_identity();
        let expected_cell = json::to_json(&pair.cell).unwrap();
        let expected_map = json::to_json(&pair.map).unwrap();
        let bounded_cell = json::to_json_bounded(&pair.cell, 512);
        let bounded_map = json::to_json_bounded(&pair.map, 512);
        let field_pointer = std::ptr::from_ref(&pair.cell);
        pair.cell.begin_freeze();
        pair.map.begin_freeze();
        assert!(catch_unwind(AssertUnwindSafe(|| pair.cell.get())).is_err());
        pair.cell
            .try_finish_freeze(|original| {
                assert_eq!(original.publication_identity(), cell_identity);
                Ok::<_, ()>(())
            })
            .unwrap();
        pair.map
            .try_finish_freeze(|original| {
                assert_eq!(original.publication_identity(), map_identity);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(std::ptr::from_ref(&pair.cell), field_pointer);
        assert_eq!(pair.cell.get().as_ptr(), cell_pointer);
        assert_eq!(pair.map.get(&1).unwrap().as_ptr(), map_pointer);
        assert_eq!(pair.cell.get_before_block().as_ptr(), cell_before);
        assert_eq!(pair.map.get_before_block(&1).unwrap().as_ptr(), map_before);
        assert_eq!(
            pair.cell.original_undo().as_ref().unwrap().as_ptr(),
            cell_undo
        );
        assert_eq!(
            pair.map
                .original_undo_entries()
                .map(|(key, value)| (*key, value.as_ref().map(|text| text.as_ptr())))
                .collect::<Vec<_>>(),
            map_undo
        );
        assert_eq!(pair.cell.publication_identity(), cell_identity);
        assert_eq!(pair.map.publication_identity(), map_identity);
        assert_eq!(pair.cell.mode(), mode);
        assert_eq!(pair.map.mode(), mode);
        assert!(pair.cell.is_dirty() && pair.map.is_dirty());
        assert_eq!(
            pair.cell.touched_value().unwrap().after.as_ptr(),
            cell_pointer
        );
        assert_eq!(pair.map.touched_entries().len(), 3);
        assert_eq!(
            pair.map.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
            [1, 3]
        );
        assert_eq!(pair.map.range(1..=3).next_back().unwrap().0, &3);
        assert_eq!(pair.map.first_key_value().unwrap().0, &1);
        assert_eq!(pair.map.last_key_value().unwrap().0, &3);
        assert_eq!(pair.map.get_key_value(&1).unwrap().1.as_ptr(), map_pointer);
        assert_eq!(pair.map.len(), 2);
        assert_eq!(json::to_json(&pair.cell).unwrap(), expected_cell);
        assert_eq!(json::to_json(&pair.map).unwrap(), expected_map);
        assert_eq!(json::to_json_bounded(&pair.cell, 512), bounded_cell);
        assert_eq!(json::to_json_bounded(&pair.map, 512), bounded_map);
        // These independently acquired writers prove both original pairs are
        // free. They remain read-only and never become the retained execution.
        let independent_cell = cell.block();
        let independent_map = map.block();
        assert_eq!(pair.cell.get().as_ptr(), cell_pointer);
        assert_eq!(pair.map.get(&1).unwrap().as_ptr(), map_pointer);
        drop((independent_cell, independent_map));
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                pair.cell.get_mut().clear();
            }))
            .is_err()
        );
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                pair.map.insert(4, "forbidden".into());
            }))
            .is_err()
        );
        assert!(catch_unwind(AssertUnwindSafe(|| pair.cell.prepare_publication())).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| pair.map.begin_freeze())).is_err());
        assert_eq!(pair.cell.get().as_ptr(), cell_pointer);
        assert_eq!(pair.map.get(&1).unwrap().as_ptr(), map_pointer);
        assert_eq!(&*cell.view(), "tip");
        assert_eq!(map.view().get(&1).map(String::as_str), Some("tip"));
    }
}

#[test]
fn frozen_field_delays_actual_capture_notice_until_original_cleanup_is_retired() {
    let observer_budget = iroha_allocation::AllocationBudget::new(
        iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
    );
    let mut registration = crate::unit_test_support::release_registration(&observer_budget);
    let cell = Cell::new(7_u64);
    let probe = cell.block().try_detach(|_| Ok::<_, ()>(())).unwrap();
    let mut field = BlockField::new(cell.block());
    let (probe, error, probe_cleanup) = probe
        .try_prepare_publication(&cell, |_, _| Ok::<_, ()>(()))
        .err()
        .expect("original executing writer is held");
    let PublicationPreparationError::Busy(wait) = error else {
        panic!("expected real writer Busy")
    };
    let noticed = Arc::new(Notice(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&noticed));
    let mut future = wait.wait_for_release(&mut registration);
    assert!(
        Pin::new(&mut future)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    field.begin_freeze();
    field.try_finish_freeze(|_| Ok::<_, ()>(())).unwrap();
    assert_eq!(*field.get(), 7);
    assert_eq!(
        noticed.0.load(SeqCst),
        0,
        "field must retain actual cleanup"
    );
    let (original, cleanup) = field.into_frozen();
    assert_eq!(
        noticed.0.load(SeqCst),
        0,
        "moving original custody must not wake early"
    );
    // The caller has released every sibling and fence before retiring cleanup.
    drop(cleanup);
    assert_eq!(noticed.0.load(SeqCst), 1);
    assert!(
        Pin::new(&mut future)
            .poll(&mut Context::from_waker(&waker))
            .is_ready()
    );
    drop(probe_cleanup);
    let prepared = probe
        .try_prepare_publication(&cell, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|(_, error, _)| panic!("actual writers were not freed: {error:?}"));
    let (probe, cleanup) = prepared.abort();
    drop((probe, cleanup));
    assert_eq!(*original.get(), 7);
}

#[test]
fn frozen_field_original_survives_busy_and_rejects_equal_foreign_or_stale_sources() {
    let cell = Cell::new(String::from("equal"));
    let foreign = Cell::new(String::from("equal"));
    let mut field = BlockField::new(cell.block());
    *field.get_mut() = "original result".into();
    let pointer = field.get().as_ptr();
    let identity = field.publication_identity();
    field.begin_freeze();
    field.try_finish_freeze(|_| Ok::<_, ()>(())).unwrap();
    let (original, cleanup) = field.into_frozen();
    drop(cleanup);
    let (original, error, cleanup) = original
        .try_prepare_publication(&foreign, |_, _| Ok::<_, ()>(()))
        .err()
        .expect("equal foreign values are not original authority");
    assert_eq!(error, PublicationPreparationError::Changed);
    drop(cleanup);
    let blocker = cell.block();
    let (original, error, cleanup) = original
        .try_prepare_publication(&cell, |_, _| Ok::<_, ()>(()))
        .err()
        .expect("actual target Busy");
    assert!(matches!(error, PublicationPreparationError::Busy(_)));
    assert_eq!(original.get().as_ptr(), pointer);
    assert_eq!(original.publication_identity(), identity);
    drop(blocker);
    drop(cleanup);
    let prepared = original
        .try_prepare_publication(&cell, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|(_, error, _)| panic!("same original retry: {error:?}"));
    let (original, cleanup) = prepared.abort();
    drop(cleanup);
    // Publishing an equal-valued independent generation invalidates the exact
    // predecessor; readable original values do not permit refreshing it.
    cell.block().commit();
    let (original, error, cleanup) = original
        .try_prepare_publication(&cell, |_, _| Ok::<_, ()>(()))
        .err()
        .expect("unchanged value with new predecessor is terminal");
    assert_eq!(error, PublicationPreparationError::Changed);
    drop(cleanup);
    assert_eq!(original.get().as_ptr(), pointer);
    assert_eq!(original.publication_identity(), identity);
    assert_eq!(&*cell.view(), "equal");
}

#[test]
fn capture_refusal_and_unwind_keep_original_slots_for_joint_terminal_release() {
    for panic_in_capture in [false, true] {
        let cell = Cell::new(String::from("original"));
        let map = Storage::<u64, String>::new();
        let mut pair = Pair {
            cell: BlockField::new(cell.block()),
            map: BlockField::new(map.block()),
        };
        *pair.cell.get_mut() = "candidate".into();
        pair.map.insert(1, "candidate".into());
        pair.cell.begin_freeze();
        pair.map.begin_freeze();
        pair.cell.try_finish_freeze(|_| Ok::<_, ()>(())).unwrap();
        if panic_in_capture {
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    pair.map.try_finish_freeze::<()>(|original| {
                        assert_eq!(original.get(&1).map(String::as_str), Some("candidate"));
                        panic!("original capture callback unwinds")
                    })
                }))
                .is_err()
            );
        } else {
            assert_eq!(
                pair.map.try_finish_freeze(|original| {
                    assert_eq!(original.get(&1).map(String::as_str), Some("candidate"));
                    Err("local metadata refusal")
                }),
                Err("local metadata refusal")
            );
        }
        assert_eq!(pair.cell.get(), "candidate");
        assert!(catch_unwind(AssertUnwindSafe(|| pair.map.get(&1))).is_err());
        assert!(
            catch_unwind(AssertUnwindSafe(|| pair.map.try_finish_freeze(|_| Ok::<
                _,
                (),
            >(
                ()
            ))))
            .is_err()
        );
        pair.cell.release_writers();
        pair.map.release_writers();
        assert!(catch_unwind(AssertUnwindSafe(|| pair.cell.get())).is_err());
        drop(pair);
        assert_eq!(&*cell.view(), "original");
        assert!(map.view().is_empty());
        drop(cell.block());
        drop(map.block());
    }
}

#[test]
fn frozen_field_publishes_the_original_backing_once_after_actual_busy() {
    let target = Cell::new(String::from("predecessor"));
    let mut field = BlockField::new(target.block());
    *field.get_mut() = "original completed execution".into();
    let pointer = field.get().as_ptr();
    field.begin_freeze();
    field.try_finish_freeze(|_| Ok::<_, ()>(())).unwrap();
    let (original, capture_cleanup) = field.into_frozen();
    drop(capture_cleanup);
    let blocker = target.block();
    let (original, error, cleanup) = original
        .try_prepare_publication(&target, |_, _| Ok::<_, ()>(()))
        .err()
        .expect("actual original target is Busy");
    assert!(matches!(error, PublicationPreparationError::Busy(_)));
    assert_eq!(original.get().as_ptr(), pointer);
    drop(blocker);
    drop(cleanup);
    let prepared = original
        .try_prepare_publication(&target, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|(_, error, _)| panic!("original retry failed: {error:?}"));
    drop(prepared.publish());
    assert_eq!(target.view().as_ptr(), pointer);
    assert_eq!(&*target.view(), "original completed execution");
    assert_eq!(
        target.predecessor_view().as_ref().map(String::as_str),
        Some("predecessor")
    );
}

#[test]
fn world_read_trait_borrows_frozen_original_cell_fields_without_execution_deref() {
    use crate::state::{World, WorldReadOnly};

    let target = World::default();
    let mut original = target.block();
    *original.soradns_history_len.get_mut() = 55;
    macro_rules! freeze_cells {
        ($($name:ident),+ $(,)?) => {{
            $(original.$name.begin_freeze();)+
            $(original.$name.try_finish_freeze(|_| Ok::<_, ()>(())).unwrap();)+
            $(assert!(std::ptr::eq(original.$name(), original.$name.get()));)+
        }};
    }
    // This tests the actual read trait on its same original field inventory.
    // It deliberately does not claim the full State Deferred cursor is wired.
    original.parameters.begin_freeze();
    original
        .parameters
        .try_finish_freeze(|_| Ok::<_, ()>(()))
        .unwrap();
    // The read trait borrows the canonical input inside the same frozen owner.
    assert!(std::ptr::eq(
        original.parameters(),
        &**original.parameters.get()
    ));
    freeze_cells!(
        consensus_schedule,
        peers,
        executor,
        executor_data_model,
        merge_hint_roots,
        merge_global_state_root,
        sorafs_pricing,
        soradns_directory_latest,
        soradns_rotation_policy,
        soradns_last_publish_ms,
        soradns_history_len,
        governance_last_unlock_sweep_height,
        governance_unlock_stats,
    );
    assert_eq!(*original.soradns_history_len(), 55);
    let independent = target.soradns_history_len.block();
    assert_eq!(*independent.get(), 0);
    assert_eq!(*original.soradns_history_len(), 55);
    drop(independent);
    drop(original);
    assert_eq!(*target.soradns_history_len.view(), 0);
}

#[test]
fn inline_frozen_pair_recovers_actual_busy_without_replacing_originals() {
    for replacement in [false, true] {
        let observer_budget = iroha_allocation::AllocationBudget::new(
            iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
        );
        let mut registration = crate::unit_test_support::release_registration(&observer_budget);
        let cell = Cell::new(String::from("old"));
        let map = Storage::<u64, String>::from_iter([(1, "old".into())]);
        let mut pair = Pair {
            cell: BlockField::new(if replacement {
                cell.block_and_revert()
            } else {
                cell.block()
            }),
            map: BlockField::new(if replacement {
                map.block_and_revert()
            } else {
                map.block()
            }),
        };
        *pair.cell.get_mut() = "original cell".into();
        pair.map.insert(1, "original map".into());
        let cell_ptr = pair.cell.get().as_ptr();
        let map_ptr = pair.map.get(&1).unwrap().as_ptr();
        let cell_id = pair.cell.publication_identity();
        let map_id = pair.map.publication_identity();
        let field_ptr = std::ptr::from_ref(&pair.cell);
        pair.cell.begin_freeze();
        pair.map.begin_freeze();
        pair.cell.try_finish_freeze(|_| Ok::<_, ()>(())).unwrap();
        pair.map.try_finish_freeze(|_| Ok::<_, ()>(())).unwrap();
        pair.cell.retire_frozen_cleanup();
        pair.map.retire_frozen_cleanup();
        let cell_probe = cell.block().try_detach(|_| Ok::<_, ()>(())).unwrap();
        let blocker = map.block();
        pair.cell
            .begin_frozen_publication(|original| {
                Ok::<_, (mv::cell::Detached<String, ()>, ())>(
                    mv::cell::BlockPublicationSlot::from_frozen(original, &cell),
                )
            })
            .unwrap();
        pair.map
            .begin_frozen_publication(|original| {
                Ok::<_, (mv::storage::Detached<u64, String, ()>, ())>(
                    mv::storage::BlockPublicationSlot::from_frozen(original, &map),
                )
            })
            .unwrap();
        pair.cell.try_prepare_frozen_publication().unwrap();
        let (cell_probe, refusal, probe_cleanup) = cell_probe
            .try_prepare_publication(&cell, |_, _| Ok::<_, ()>(()))
            .err()
            .unwrap();
        let PublicationPreparationError::Busy(wait) = refusal else {
            panic!("prepared first field holds its actual identity")
        };
        let noticed = Arc::new(Notice(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&noticed));
        let mut future = wait.wait_for_release(&mut registration);
        assert!(
            Pin::new(&mut future)
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        assert!(matches!(
            pair.map.try_prepare_frozen_publication(),
            Err(PublicationPreparationError::Busy(_))
        ));
        pair.cell.recover_frozen_publication();
        assert_eq!(
            noticed.0.load(SeqCst),
            0,
            "first recovery cannot retire sibling cleanup"
        );
        pair.map.recover_frozen_publication();
        assert_eq!(noticed.0.load(SeqCst), 0);
        assert_eq!(std::ptr::from_ref(&pair.cell), field_ptr);
        assert_eq!(pair.cell.get().as_ptr(), cell_ptr);
        assert_eq!(pair.map.get(&1).unwrap().as_ptr(), map_ptr);
        assert_eq!(pair.cell.publication_identity(), cell_id);
        assert_eq!(pair.map.publication_identity(), map_id);
        assert_eq!(&*cell.view(), "old");
        assert_eq!(map.view().get(&1).map(String::as_str), Some("old"));
        drop(blocker);
        drop(cell.block());
        drop(map.block());
        // Only after ALL physical fields and the external blocker are free.
        pair.cell.retire_frozen_cleanup();
        pair.map.retire_frozen_cleanup();
        assert!(noticed.0.load(SeqCst) > 0);
        drop((cell_probe, probe_cleanup, future, waker));
        pair.cell
            .begin_frozen_publication(|original| {
                Ok::<_, (mv::cell::Detached<String, ()>, ())>(
                    mv::cell::BlockPublicationSlot::from_frozen(original, &cell),
                )
            })
            .unwrap();
        pair.map
            .begin_frozen_publication(|original| {
                Ok::<_, (mv::storage::Detached<u64, String, ()>, ())>(
                    mv::storage::BlockPublicationSlot::from_frozen(original, &map),
                )
            })
            .unwrap();
        pair.cell.try_prepare_frozen_publication().unwrap();
        pair.map.try_prepare_frozen_publication().unwrap();
        pair.cell.publish_prepared();
        pair.map.publish_prepared();
        assert_eq!(cell.view().get().as_ptr(), cell_ptr);
        assert_eq!(map.view().get(&1).unwrap().as_ptr(), map_ptr);
    }
}

#[test]
fn inline_frozen_field_refuses_foreign_and_equal_newer_sources() {
    let cell = Cell::new(String::from("same"));
    let foreign = Cell::new(String::from("same"));
    let mut field = BlockField::new(cell.block());
    *field.get_mut() = "retained".into();
    let pointer = field.get().as_ptr();
    let identity = field.publication_identity();
    field.begin_freeze();
    field.try_finish_freeze(|_| Ok::<_, ()>(())).unwrap();
    field.retire_frozen_cleanup();
    field
        .begin_frozen_publication(|original| {
            Ok::<_, (mv::cell::Detached<String, ()>, ())>(
                mv::cell::BlockPublicationSlot::from_frozen(original, &foreign),
            )
        })
        .unwrap();
    assert_eq!(
        field.try_prepare_frozen_publication(),
        Err(PublicationPreparationError::Changed)
    );
    field.recover_frozen_publication();
    assert_eq!(field.get().as_ptr(), pointer);
    assert_eq!(field.publication_identity(), identity);
    field.retire_frozen_cleanup();
    // Value equality cannot substitute for the exact original predecessor.
    cell.block().commit();
    field
        .begin_frozen_publication(|original| {
            Ok::<_, (mv::cell::Detached<String, ()>, ())>(
                mv::cell::BlockPublicationSlot::from_frozen(original, &cell),
            )
        })
        .unwrap();
    assert_eq!(
        field.try_prepare_frozen_publication(),
        Err(PublicationPreparationError::Changed)
    );
    field.recover_frozen_publication();
    assert_eq!(field.get().as_ptr(), pointer);
    assert_eq!(field.publication_identity(), identity);
    assert_eq!(&*cell.view(), "same");
    field.retire_frozen_cleanup();
}

#[test]
fn inline_frozen_publish_requires_preparation_and_terminal_release_grants_no_retry() {
    let cell = Cell::new(String::from("retained"));
    let mut field = BlockField::new(cell.block());
    let pointer = field.get().as_ptr();
    field.begin_freeze();
    field.try_finish_freeze(|_| Ok::<_, ()>(())).unwrap();
    field.retire_frozen_cleanup();
    field
        .begin_frozen_publication(|original| {
            Ok::<_, (mv::cell::Detached<String, ()>, ())>(
                mv::cell::BlockPublicationSlot::from_frozen(original, &cell),
            )
        })
        .unwrap();
    assert!(catch_unwind(AssertUnwindSafe(|| field.publish_prepared())).is_err());
    // The precondition is checked while the same slot still owns its journal.
    field.recover_frozen_publication();
    assert_eq!(field.get().as_ptr(), pointer);
    field.retire_frozen_cleanup();
    field
        .begin_frozen_publication(|original| {
            Ok::<_, (mv::cell::Detached<String, ()>, ())>(
                mv::cell::BlockPublicationSlot::from_frozen(original, &cell),
            )
        })
        .unwrap();
    field.try_prepare_frozen_publication().unwrap();
    field.release_writers();
    drop(cell.block());
    assert!(catch_unwind(AssertUnwindSafe(|| field.recover_frozen_publication())).is_err());
    assert_eq!(&*cell.view(), "retained");
}
