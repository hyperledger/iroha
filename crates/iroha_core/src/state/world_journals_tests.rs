//! Real World capture releases writers and preserves the exact unpublished cut.

use super::*;
use crate::state::scalar_cell_custody::ScalarCellFixtureBlock;
use crate::sumeragi::amx::NativeAmxCellFixtureBlock as _;
use crate::{
    smartcontracts::isi::triggers::specialized::{SpecializedAction, SpecializedTrigger},
    state::{DataSpaceId, LaneConfig},
};
use iroha_data_model::{
    account::{AccountDetails, AccountValue},
    block::BlockHeader,
    nexus::DataSpaceMetadata,
    prelude::{Executable, ExecuteTriggerEventFilter, InstructionBox, Repeats, TriggerId},
};
use iroha_model_base::state_path::StatePath;
use iroha_primitives::const_vec::ConstVec;
use mv::storage::StorageReadOnly;
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

// Publish an untouched replacement through each field's ordinary writer.
macro_rules! commit_untouched_fixture_field {
    ($world:ident, $field:ident) => {
        $world.$field.block().commit()
    };
}

#[path = "world_publication_tests.rs"]
mod publication_tests;

fn path(value: &str) -> StatePath {
    value.parse().unwrap()
}

fn capture(block: WorldBlock<'_>) -> DetachedWorld<()> {
    block
        .try_detach_journals(
            crate::state::world_journals::resources::WorldJournalShellReservation::for_test(),
            |_| Ok::<(), ()>(()),
        )
        .unwrap()
}

fn fixture() -> Arc<World> {
    let world = Arc::new(World::default());
    {
        let mut original = world.block();
        original.accounts.insert(
            iroha_test_samples::ALICE_ID.clone(),
            AccountValue::new(AccountDetails::default()),
        );
        original
            .smart_contract_state
            .insert(path("capture/value"), vec![1]);
        *original.soradns_last_publish_ms.get_mut() = Some(10);
        original.commit();
    }
    world
}

fn images(world: &World) -> [String; 3] {
    [
        norito::json::to_json(&world.smart_contract_state).unwrap(),
        norito::json::to_json(&world.soradns_last_publish_ms).unwrap(),
        norito::json::to_json(&world.triggers).unwrap(),
    ]
}

fn register_trigger(block: &mut WorldBlock<'_>, name: &str) {
    let mut transaction = block.triggers.transaction();
    let action = SpecializedAction::new(
        Executable::Instructions(ConstVec::from(Vec::<InstructionBox>::new())),
        Repeats::Exactly(2),
        iroha_test_samples::ALICE_ID.clone(),
        ExecuteTriggerEventFilter::new(),
    )
    .unwrap();
    let trigger: TriggerId = name.parse().unwrap();
    assert!(
        transaction
            .add_by_call_trigger(SpecializedTrigger::new(trigger, action))
            .unwrap()
    );
    transaction.apply();
}

fn assert_all_writers_released(world: &Arc<World>) {
    let owner = Arc::clone(world);
    let (sent, received) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        // This acquires every actual current and undo writer, including all ten
        // TriggerSet components; no representative-lock shortcut is used.
        let original = owner.block();
        drop(original);
        sent.send(()).unwrap();
    });
    received
        .recv_timeout(Duration::from_secs(5))
        .expect("every World writer must be released");
    thread.join().unwrap();
}

struct Reservation(Arc<AtomicBool>);
impl Drop for Reservation {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn catalog() -> DataSpaceCatalog {
    DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: DataSpaceId::new(7),
            alias: "captured".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .unwrap()
}

#[test]
fn ordinary_world_capture_retains_deltas_events_catalog_and_releases_every_writer() {
    let world = fixture();
    let before = images(&world);
    let mut original = world.block();
    {
        let mut applied = original.transaction_without_telemetry(LaneConfig::default(), 1);
        applied
            .smart_contract_state
            .insert(path("capture/value"), vec![2]);
        *applied.soradns_last_publish_ms.get_mut() = Some(20);
        applied.apply();
    }
    {
        let mut aborted = original.transaction_without_telemetry(LaneConfig::default(), 1);
        aborted
            .smart_contract_state
            .insert(path("capture/value"), vec![99]);
        aborted
            .smart_contract_state
            .insert(path("capture/aborted"), vec![99]);
        *aborted.soradns_last_publish_ms.get_mut() = Some(99);
    }
    register_trigger(&mut original, "captured_trigger");
    original.dataspace_catalog = catalog();
    original.push_pipeline_warning(
        BlockHeader::new(std::num::NonZeroU64::MIN, None, None, 1, 0),
        "capture",
        "retained",
    );
    let events_pointer = original.external_event_buf.as_ptr();
    let expected_events = original.external_event_buf.clone();
    let expected_catalog = original.dataspace_catalog.clone();
    let dropped = Arc::new(AtomicBool::new(false));
    let calls = AtomicUsize::new(0);
    let detached = original
        .try_detach_journals(
            crate::state::world_journals::resources::WorldJournalShellReservation::for_test(),
            |inputs| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(
                    inputs.smart_contract_state.get(&path("capture/value")),
                    Some(&vec![2])
                );
                assert!(
                    inputs
                        .smart_contract_state
                        .get(&path("capture/aborted"))
                        .is_none()
                );
                assert_eq!(*inputs.soradns_last_publish_ms.get(), Some(20));
                Ok::<_, ()>(Reservation(Arc::clone(&dropped)))
            },
        )
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(detached.mode(), BlockMode::Ordinary);
    let expected_fields =
        crate::state::authority_registry::inventory_test_support::world_overlay_names();
    assert_eq!(detached.field_count(), expected_fields.len());
    assert_eq!(
        detached
            .fields()
            .map(|field| field.name)
            .collect::<BTreeSet<_>>()
            .len(),
        expected_fields.len()
    );
    assert_eq!(
        detached
            .fields()
            .map(|field| field.name.to_owned())
            .collect::<BTreeSet<_>>(),
        expected_fields,
    );
    assert_eq!(
        detached
            .field("smart_contract_state")
            .unwrap()
            .touched_values,
        1
    );
    assert_eq!(
        detached
            .field("soradns_last_publish_ms")
            .unwrap()
            .touched_values,
        1
    );
    assert_eq!(detached.field("triggers").unwrap().touched_values, 3);
    assert_eq!(detached.field("parameters").unwrap().touched_values, 0);
    assert!(detached.field("not_a_world_field").is_none());
    assert!(
        detached
            .fields()
            .all(|field| field.mode == BlockMode::Ordinary)
    );
    assert_eq!(
        detached.external_events().as_ptr(),
        events_pointer,
        "move the original allocation"
    );
    assert_eq!(detached.external_events(), expected_events.as_slice());
    assert_eq!(detached.dataspace_catalog(), &expected_catalog);
    assert!(Arc::ptr_eq(&detached.admission().0, &dropped));
    assert!(!dropped.load(Ordering::SeqCst));
    assert!(detached.matches_current(&world));
    assert_eq!(
        images(&world),
        before,
        "capture publishes neither current nor undo"
    );
    assert_all_writers_released(&world);
    drop(detached);
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(images(&world), before);
}

#[test]
fn typed_wrappers_retain_actual_named_storage_cell_and_trigger_values() {
    let world = fixture();
    let before = images(&world);
    let (storage, cell, triggers) = {
        let mut original = world.block();
        original
            .smart_contract_state
            .insert(path("capture/value"), vec![2]);
        original.smart_contract_state.remove(path("capture/noop"));
        *original.soradns_last_publish_ms.get_mut() = Some(22);
        register_trigger(&mut original, "typed_trigger");
        // Take only these original fields from the retained heap shell. Moving
        // the complete World inventory through this frame can overflow its stack.
        // Capture notifications remain held until every other writer is released.
        let mut storage = original.smart_contract_state.take_capture();
        let mut cell = original.soradns_last_publish_ms.take_capture();
        let mut triggers = original.triggers.take_capture();
        storage.capture().unwrap();
        cell.capture().unwrap();
        triggers.capture().unwrap();
        (storage, cell, triggers)
    };
    let storage = storage.retain("smart_contract_state", |world: &World| {
        &world.smart_contract_state
    });
    let cell = cell.retain("soradns_last_publish_ms", |world: &World| {
        &world.soradns_last_publish_ms
    });
    let triggers = triggers.retain("triggers", |world: &World| &world.triggers);
    let touches = storage
        .journal
        .as_ref()
        .unwrap()
        .touched_entries()
        .collect::<Vec<_>>();
    assert_eq!(touches.len(), 2);
    let changed = touches
        .iter()
        .find(|entry| entry.key == &path("capture/value"))
        .unwrap();
    assert_eq!(changed.before, Some(&vec![1]));
    assert_eq!(changed.after, Some(&vec![2]));
    let noop = touches
        .iter()
        .find(|entry| entry.key == &path("capture/noop"))
        .unwrap();
    assert_eq!(noop.before, None);
    assert_eq!(noop.after, None);
    let touch = cell.journal.as_ref().unwrap().touched_value().unwrap();
    assert_eq!(*touch.before, Some(10));
    assert_eq!(*touch.after, Some(22));
    let trigger = triggers
        .journal
        .as_ref()
        .unwrap()
        .by_call_triggers()
        .touched_entries()
        .next()
        .unwrap();
    assert_eq!(trigger.key.to_string(), "typed_trigger");
    assert!(trigger.before.is_none());
    assert!(trigger.after.is_some());
    assert_eq!(
        triggers
            .journal
            .as_ref()
            .unwrap()
            .ids()
            .touched_entries()
            .len(),
        1
    );
    assert_eq!(
        triggers
            .journal
            .as_ref()
            .unwrap()
            .active_by_call_trigger_ids()
            .touched_entries()
            .len(),
        1
    );
    assert!(storage.matches_current(&world));
    assert!(cell.matches_current(&world));
    assert!(triggers.matches_current(&world));
    assert_all_writers_released(&world);
    assert_eq!(images(&world), before);
}

#[test]
fn replacement_keeps_discarded_tip_identity_without_inventing_candidate_touches() {
    let world = fixture();
    {
        let mut tip = world.block();
        tip.smart_contract_state
            .insert(path("capture/value"), vec![2]);
        tip.smart_contract_state
            .insert(path("capture/tip_only"), vec![3]);
        *tip.soradns_last_publish_ms.get_mut() = Some(20);
        tip.commit();
    }
    let before = images(&world);
    let original = world.block_and_revert();
    assert_eq!(
        original.smart_contract_state.get(&path("capture/value")),
        Some(&vec![1])
    );
    assert!(
        original
            .smart_contract_state
            .get(&path("capture/tip_only"))
            .is_none()
    );
    assert_eq!(*original.soradns_last_publish_ms.get(), Some(10));
    let detached = capture(original);
    assert_eq!(detached.mode(), BlockMode::Replace);
    assert!(
        detached
            .fields()
            .all(|field| field.mode == BlockMode::Replace && field.touched_values == 0)
    );
    assert!(
        detached.matches_current(&world),
        "identity includes the discarded current tip"
    );
    assert_all_writers_released(&world);
    assert_eq!(images(&world), before);
    // Only the original existing raw publication path can perform the undo.
    world.block_and_revert().commit();
    assert!(!detached.matches_current(&world));
    assert_eq!(
        world
            .smart_contract_state
            .view()
            .get(&path("capture/value")),
        Some(&vec![1])
    );
    assert!(
        world
            .smart_contract_state
            .view()
            .get(&path("capture/tip_only"))
            .is_none()
    );
}

#[test]
fn admission_refusal_releases_all_writers_and_preserves_current_and_undo() {
    let world = fixture();
    let before = images(&world);
    for replace in [false, true] {
        let mut original = if replace {
            world.block_and_revert()
        } else {
            world.block()
        };
        original
            .smart_contract_state
            .insert(path("capture/value"), vec![7]);
        register_trigger(&mut original, "refused_trigger");
        let calls = AtomicUsize::new(0);
        let result = original.try_detach_journals(
            crate::state::world_journals::resources::WorldJournalShellReservation::for_test(),
            |inputs| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(
                    inputs.smart_contract_state.get(&path("capture/value")),
                    Some(&vec![7])
                );
                Err::<(), _>("resource bound")
            },
        );
        assert!(matches!(
            result,
            Err(CaptureError::Admission("resource bound"))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_all_writers_released(&world);
        assert_eq!(images(&world), before);
    }
}

#[test]
fn mismatched_cell_or_trigger_mode_refuses_before_the_world_admission() {
    let world = fixture();
    let foreign = fixture();
    let before = images(&world);
    let foreign_before = images(&foreign);
    for trigger in [false, true] {
        let mut original = world.block();
        if trigger {
            original.triggers = foreign.triggers.block_and_revert();
        } else {
            original.soradns_last_publish_ms = crate::state::block_field::BlockField::new(
                foreign.soradns_last_publish_ms.block_and_revert(),
            );
        }
        let calls = AtomicUsize::new(0);
        let result = original.try_detach_journals(
            crate::state::world_journals::resources::WorldJournalShellReservation::for_test(),
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok::<(), ()>(())
            },
        );
        match result {
            Err(CaptureError::InconsistentMode {
                field,
                expected,
                actual,
            }) => {
                assert_eq!(
                    field,
                    if trigger {
                        "triggers"
                    } else {
                        "soradns_last_publish_ms"
                    }
                );
                assert_eq!(expected, BlockMode::Ordinary);
                assert_eq!(actual, BlockMode::Replace);
            }
            _ => panic!("mixed original modes must not create a World capture"),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_all_writers_released(&world);
        assert_all_writers_released(&foreign);
        assert_eq!(images(&world), before);
        assert_eq!(images(&foreign), foreign_before);
    }
}

#[test]
fn every_inventory_field_binds_untouched_current_and_undo_publications() {
    macro_rules! invalidators {
        (; [$($prefix:ident,)*] [$($privacy:ident,)*] [$($suffix:ident,)*]) => {
            [
                $((stringify!($prefix), |world: &World| commit_untouched_fixture_field!(world, $prefix)),)*
                $((stringify!($privacy), |world: &World| commit_untouched_fixture_field!(world, $privacy)),)*
                $((stringify!($suffix), |world: &World| commit_untouched_fixture_field!(world, $suffix)),)*
            ]
        };
    }
    let owners: &[(&str, fn(&World))] = &with_world_overlay_fields!(invalidators);
    let world = fixture();
    for &(name, publish_same_values) in owners {
        let detached = capture(world.block());
        assert!(detached.matches_current(&world));
        assert_eq!(detached.field(name).unwrap().touched_values, 0);
        publish_same_values(&world);
        assert!(
            !detached.matches_current(&world),
            "untouched owner {name} must retain its exact pair identity"
        );
    }
}

#[test]
fn detached_world_is_static_and_does_not_retain_its_original_world() {
    fn assert_static_send_sync<T: Send + Sync + 'static>() {}
    assert_static_send_sync::<DetachedWorld<Reservation>>();
    let world = fixture();
    let weak = Arc::downgrade(&world);
    let dropped = Arc::new(AtomicBool::new(false));
    let mut original = world.block();
    original
        .smart_contract_state
        .insert(path("capture/value"), vec![8]);
    let detached = original
        .try_detach_journals(
            crate::state::world_journals::resources::WorldJournalShellReservation::for_test(),
            |_| Ok::<_, ()>(Reservation(Arc::clone(&dropped))),
        )
        .unwrap();
    assert_all_writers_released(&world);
    drop(world);
    assert!(
        weak.upgrade().is_none(),
        "captured accessors and identities own no World"
    );
    let detached = std::thread::spawn(move || detached).join().unwrap();
    assert_eq!(
        detached
            .field("smart_contract_state")
            .unwrap()
            .touched_values,
        1
    );
    assert!(!dropped.load(Ordering::SeqCst));
    drop(detached);
    assert!(dropped.load(Ordering::SeqCst));
}

#[test]
fn disjoint_candidates_aborted_children_and_equal_value_aba_keep_exact_owner_identity() {
    let world = fixture();
    let before = images(&world);
    let first = {
        let mut original = world.block();
        original
            .smart_contract_state
            .insert(path("capture/first"), vec![1]);
        capture(original)
    };
    let second = {
        let mut original = world.block();
        original
            .smart_contract_state
            .insert(path("capture/second"), vec![2]);
        capture(original)
    };
    {
        let mut aborted = world.block();
        let mut child = aborted.smart_contract_state.transaction();
        child.insert(path("capture/aborted"), vec![9]);
    }
    assert!(first.matches_current(&world));
    assert!(second.matches_current(&world));
    assert_eq!(images(&world), before);
    let distinct = fixture();
    assert_eq!(images(&distinct), before);
    assert!(!first.matches_current(&distinct));
    drop(first);
    assert!(second.matches_current(&world));
    let mut equal = world.smart_contract_state.block();
    equal.insert(path("capture/value"), vec![1]);
    equal.commit();
    assert!(
        !second.matches_current(&world),
        "equal visible bytes cannot rebind a publication identity"
    );
    assert!(
        world
            .smart_contract_state
            .view()
            .get(&path("capture/first"))
            .is_none()
    );
    assert!(
        world
            .smart_contract_state
            .view()
            .get(&path("capture/second"))
            .is_none()
    );
}

#[test]
fn equal_restored_field_cannot_launder_the_original_world_owner() {
    let mut world = fixture();
    let before = images(&world);
    let detached = capture(world.block());
    let serialized = norito::json::to_json(&world.smart_contract_state).unwrap();
    let restored: Storage<StatePath, Vec<u8>> = norito::json::from_str(&serialized).unwrap();
    assert_eq!(norito::json::to_json(&restored).unwrap(), serialized);
    Arc::get_mut(&mut world).unwrap().smart_contract_state = restored;
    assert_eq!(images(&world), before);
    assert!(!detached.matches_current(&world));
    assert_all_writers_released(&world);
}
