//! Actual original allocation custody and admission before World writer acquisition.

use super::*;
use crate::state::World;
use iroha_allocation::{AllocationBudget, AllocationRefusal};
use mv::cell::{Cell, CellPublicationSuccessor};
use std::{
    sync::{Arc, mpsc},
    time::Duration,
};

macro_rules! count_world_successors {
    ($world:ident; [$($prefix:ident,)*] [$($privacy:ident,)*] [$($suffix:ident,)*]) => {{
        let mut count = 0;
        $(count += usize::from($world.$prefix.successor_layout().is_some());)*
        $(count += usize::from($world.$privacy.successor_layout().is_some());)*
        $(count += usize::from($world.$suffix.successor_layout().is_some());)*
        count
    }};
}

#[test]
fn per_store_control_demand_counts_exact_layouts_and_rejects_overflow() {
    let source = Cell::new(11_u64);
    let mut demand = 17;
    super::add_original_control_demand(&source, &mut demand).unwrap();
    assert_eq!(
        demand,
        17 + CellPublicationSuccessor::allocation_layout().size()
    );
    let mut overflow = usize::MAX;
    assert!(matches!(
        super::add_original_control_demand(&source, &mut overflow),
        Err(AdmittedStorageError::Allocation(
            AllocationRefusal::DemandOverflow
        ))
    ));
    assert_eq!(overflow, usize::MAX);
    // Accounting is read-only, even when the requested total cannot fit.
    drop(source.block());
}

#[test]
fn original_world_shell_and_complete_successors_share_caller_pool_through_both_modes() {
    let world = World::default();
    let count = with_world_overlay_fields!(count_world_successors, world);
    assert!(count > 10, "the actual full Cell census must be exercised");
    let demand =
        OriginalWorldFields::layout().size() + super::original_world_cell_control_bytes(&world);
    for replacement in [false, true] {
        let source = AllocationBudget::new(demand);
        let foreign = AllocationBudget::new(demand);
        let mut original = if replacement {
            world.try_block_and_revert(&source)
        } else {
            world.try_block(&source)
        }
        .unwrap();
        let fields = original.fields.as_ref().unwrap();
        assert!(fields.belongs_to(&source));
        assert!(!fields.belongs_to(&foreign));
        let pointer = std::ptr::from_ref(&**fields);
        assert_eq!(source.reserved_bytes(), demand);
        assert_eq!(foreign.reserved_bytes(), 0);
        source.set_limit_bytes(0);
        // Retain the very same enlarged shell through a real typed field capture.
        original.parameters.begin_freeze();
        original
            .parameters
            .try_finish_freeze(|_| Ok::<_, ()>(()))
            .unwrap();
        assert_eq!(
            std::ptr::from_ref(&**original.fields.as_ref().unwrap()),
            pointer
        );
        assert_eq!(source.reserved_bytes(), demand);
        assert_eq!(
            original.parameters.mode(),
            if replacement {
                BlockMode::Replace
            } else {
                BlockMode::Ordinary
            }
        );
        drop(original);
        assert_eq!(
            source.reserved_bytes(),
            0,
            "backing and successors release before refund"
        );
        let probe = world.try_block(&foreign).unwrap();
        assert!(probe.fields.as_ref().unwrap().belongs_to(&foreign));
        drop(probe);
        assert_eq!(foreign.reserved_bytes(), 0);
    }
}

#[test]
fn insufficient_original_world_controls_refuse_before_any_held_writer_is_touched() {
    for replacement in [false, true] {
        let world = Arc::new(World::default());
        let held = world.block();
        let budget = AllocationBudget::new(0);
        let worker_world = Arc::clone(&world);
        let worker_budget = budget.clone();
        let (sent, received) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let error = match if replacement {
                worker_world.try_block_and_revert(&worker_budget)
            } else {
                worker_world.try_block(&worker_budget)
            } {
                Ok(_) => panic!("zero original pool cannot fund the shell"),
                Err(error) => error,
            };
            sent.send(error).unwrap();
        });
        let result = received.recv_timeout(Duration::from_secs(5));
        // A regressed acquisition can finish after this drop, so the assertion
        // does not strand a writer thread even when it diagnoses the ordering bug.
        drop(held);
        worker.join().unwrap();
        assert!(matches!(
            result.unwrap(),
            AdmittedStorageError::Allocation(AllocationRefusal::ExceedsLimit {
                limit_bytes: 0,
                ..
            })
        ));
        assert_eq!(budget.reserved_bytes(), 0);
        drop(world.block());
    }
}

#[test]
fn partial_successor_inventory_refusal_keeps_original_credit_and_acquires_no_writer() {
    let first = Cell::new(11_u64);
    let second = Cell::new(22_u64);
    let layout = CellPublicationSuccessor::allocation_layout();
    let source = AllocationBudget::new(layout.size());
    let foreign = AllocationBudget::new(layout.size());
    let mut parent = source.try_reserve(layout).unwrap();
    let before = parent.remaining_bytes();
    assert!(matches!(
        original_cell(&first, &foreign, &mut parent),
        Err(AdmittedStorageError::PolicyIdentity)
    ));
    assert_eq!(parent.remaining_bytes(), before);
    assert_eq!(source.reserved_bytes(), layout.size());
    assert_eq!(foreign.reserved_bytes(), 0);
    let mut slot = original_cell(&first, &source, &mut parent).unwrap();
    assert_eq!(parent.remaining_bytes(), 0);
    assert!(matches!(
        original_cell(&second, &source, &mut parent),
        Err(AdmittedStorageError::PolicyDemand {
            remaining_bytes: 0,
            ..
        })
    ));
    assert_eq!(source.reserved_bytes(), layout.size());
    drop(first.block());
    drop(second.block());
    source.set_limit_bytes(0);
    slot.initialize(BlockMode::Ordinary);
    let original = slot.into_block();
    assert_eq!(original.get(), &11);
    assert_eq!(source.reserved_bytes(), layout.size());
    drop(original);
    assert_eq!(source.reserved_bytes(), 0);
}

#[test]
fn original_charged_shell_outlives_capture_until_all_enclosing_writers_are_released() {
    use crate::state::world_journals::{
        WorldJournalCapture, resources::WorldJournalShellReservation,
    };
    let world = World::default();
    let field_control_bytes = super::original_world_cell_control_bytes(&world);
    let shell_bytes = OriginalWorldFields::layout().size();
    let source = AllocationBudget::new(shell_bytes + field_control_bytes);
    let original = world.try_block(&source).unwrap();
    let mut capture = original.capture_slot(WorldJournalShellReservation::for_test());
    assert_eq!(
        source.reserved_bytes(),
        shell_bytes + field_control_bytes,
        "moving original writers must not refund the emptied shell"
    );
    capture.capture().unwrap();
    assert_eq!(
        source.reserved_bytes(),
        shell_bytes + field_control_bytes,
        "capture retains charge until caller releases all enclosing writers"
    );
    // Actual original writers are free, although their capture cleanup remains.
    drop(world.block());
    let journals = capture.into_journals(());
    assert_eq!(
        source.reserved_bytes(),
        field_control_bytes,
        "only the physically freed empty shell is refunded"
    );
    assert!(journals.matches_current(&world));
    drop(journals);
    assert_eq!(source.reserved_bytes(), 0);
}

#[test]
fn original_world_partial_placement_releases_both_sides_before_reclaiming_backing() {
    use mv::PublicationPreparationError;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    macro_rules! count_fields {
        (; [$($prefix:ident,)*] [$($privacy:ident,)*] [$($suffix:ident,)*]) => {
            2 $(+ { let _ = stringify!($prefix); 1 })* $(+ { let _ = stringify!($privacy); 1 })* $(+ { let _ = stringify!($suffix); 1 })*
        };
    }
    let fields = with_world_overlay_fields!(count_fields);
    for replacement in [false, true] {
        for fail_after in [1, 2, 3, fields / 2, fields - 1, fields] {
            let world = World::default();
            let source = AllocationBudget::new(16 * 1024 * 1024);
            let parameters = world
                .parameters
                .block()
                .try_detach(|_| Ok::<_, ()>(()))
                .unwrap();
            let peers = world.peers.block().try_detach(|_| Ok::<_, ()>(())).unwrap();
            let state = world
                .smart_contract_state
                .block()
                .try_detach(|_| Ok::<_, ()>(()))
                .unwrap();
            let result = catch_unwind(AssertUnwindSafe(|| {
                original_control::with_placement_failure(fail_after, || {
                    drop(
                        if replacement {
                            world.try_block_and_revert(&source)
                        } else {
                            world.try_block(&source)
                        }
                        .unwrap(),
                    );
                });
            }));
            assert!(
                result.is_err(),
                "every selected actual transfer frontier must be reached"
            );
            assert_eq!(
                source.reserved_bytes(),
                0,
                "same admitted shell and successor controls reclaim on partial placement"
            );
            assert!(parameters.matches_current(&world.parameters));
            assert!(peers.matches_current(&world.peers));
            assert!(state.matches_current(&world.smart_contract_state));
            // A panic preserves native poison, but no original physical writer
            // may remain held on either side of the actual transfer frontier.
            macro_rules! released {
                ($original:expr, $target:expr) => {
                    match $original.try_prepare_publication($target, |_, _| Ok::<_, ()>(())) {
                        Ok(prepared) => drop(prepared.abort()),
                        Err((_, error, _)) => assert!(
                            matches!(error, PublicationPreparationError::Poisoned),
                            "released original must be healthy or explicitly poisoned: {error:?}"
                        ),
                    }
                };
            }
            released!(parameters, &world.parameters);
            released!(peers, &world.peers);
            released!(state, &world.smart_contract_state);
        }
    }
}

#[test]
fn borrowed_original_field_initialization_preserves_refusal_and_existing_custody() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let target = Cell::new(String::from("original"));
    let source = AllocationBudget::new(1024 * 1024);
    let foreign = AllocationBudget::new(1024 * 1024);
    let layout = CellPublicationSuccessor::allocation_layout();
    let mut reservation = source.try_reserve(layout).unwrap();
    let before = source.reserved_bytes();
    let mut slot = None;
    assert!(matches!(
        initialize_original_field(&mut slot, &target, &foreign, &mut reservation),
        Err(AdmittedStorageError::PolicyIdentity)
    ));
    assert!(slot.is_none());
    assert_eq!(reservation.remaining_bytes(), layout.size());
    assert_eq!(source.reserved_bytes(), before);
    assert_eq!(foreign.reserved_bytes(), 0);
    initialize_original_field(&mut slot, &target, &source, &mut reservation).unwrap();
    assert_eq!(reservation.remaining_bytes(), 0);
    assert_eq!(source.reserved_bytes(), before);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            initialize_original_field(&mut slot, &target, &source, &mut reservation)
        }))
        .is_err()
    );
    assert!(
        slot.is_some(),
        "existing original slot survives precondition refusal"
    );
    assert_eq!(source.reserved_bytes(), before);
    source.set_limit_bytes(0);
    let slot = slot.as_mut().unwrap();
    slot.try_initialize(BlockMode::Ordinary).unwrap();
    let block = slot.take_block();
    assert_eq!(block.get(), "original");
    drop(block);
    assert_eq!(source.reserved_bytes(), before - layout.size());
}
