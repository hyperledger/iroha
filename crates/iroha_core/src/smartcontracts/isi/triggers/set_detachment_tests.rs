//! Real trigger lifecycle deltas retain every MV owner without a writer or Set borrow.

use super::*;
use crate::smartcontracts::isi::triggers::global_data_trigger_scope_metadata_for_testing;
use iroha_data_model::events::{pipeline::BlockEventFilter, time::Schedule};
use iroha_test_samples::ALICE_ID;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

#[path = "set_publication_tests.rs"]
mod publication_tests;

#[path = "set_acquisition_tests.rs"]
mod acquisition_tests;
#[path = "set_capture_tests.rs"]
mod capture_tests;

fn id(value: &str) -> TriggerId {
    value.parse().unwrap()
}

fn blob() -> IvmBytecode {
    let mut code = ivm::ProgramMetadata::default().encode();
    code.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    IvmBytecode::from_compiled(code)
}

fn register_call(tx: &mut SetTransaction<'_>, value: &str) {
    let action = SpecializedAction::new(
        Executable::Ivm(blob()),
        Repeats::Exactly(3),
        ALICE_ID.clone(),
        ExecuteTriggerEventFilter::new(),
    )
    .unwrap();
    assert!(
        tx.add_by_call_trigger(SpecializedTrigger::new(id(value), action))
            .unwrap()
    );
}

fn register_data(tx: &mut SetTransaction<'_>, value: &str) {
    let mut action = SpecializedAction::new(
        Executable::Instructions(ConstVec::from(Vec::<InstructionBox>::new())),
        Repeats::Exactly(3),
        ALICE_ID.clone(),
        DataEventFilter::Any,
    )
    .unwrap();
    action.metadata = global_data_trigger_scope_metadata_for_testing(&ALICE_ID);
    assert!(
        tx.add_data_trigger(SpecializedTrigger::new(id(value), action))
            .unwrap()
    );
}

fn seeded_set() -> Arc<Set> {
    let set = Arc::new(Set::default());
    let mut block = set.block();
    let mut tx = block.transaction();
    register_data(&mut tx, "data");
    let action = SpecializedAction::new(
        Executable::Instructions(ConstVec::from(Vec::<InstructionBox>::new())),
        Repeats::Exactly(3),
        ALICE_ID.clone(),
        PipelineEventFilterBox::from(BlockEventFilter::new().for_status(BlockStatus::Approved)),
    )
    .unwrap();
    assert!(
        tx.add_pipeline_trigger(SpecializedTrigger::new(id("pipeline"), action))
            .unwrap()
    );
    let mut action = SpecializedAction::new(
        Executable::Instructions(ConstVec::from(Vec::<InstructionBox>::new())),
        Repeats::Exactly(3),
        ALICE_ID.clone(),
        TimeEventFilter(ExecutionTime::Schedule(Schedule::starting_at(
            Duration::from_secs(1),
        ))),
    )
    .unwrap();
    action.retry_policy = Some(TimeTriggerRetryPolicy {
        max_retries: std::num::NonZeroU32::new(3).unwrap(),
        retry_after_ms: NonZeroU64::new(10).unwrap(),
    });
    assert!(
        tx.add_time_trigger(SpecializedTrigger::new(id("time"), action))
            .unwrap()
    );
    register_call(&mut tx, "call_a");
    register_call(&mut tx, "call_b");
    tx.apply();
    block.commit();
    set
}

fn images(set: &Set) -> Vec<String> {
    macro_rules! serialize {
        ($($field:ident),+ $(,)?) => {
            vec![$(norito::json::to_json(&set.$field).unwrap(),)+]
        };
    }
    serialize!(
        data_triggers,
        pipeline_triggers,
        time_triggers,
        by_call_triggers,
        ids,
        active_data_trigger_ids,
        active_pipeline_trigger_ids,
        active_time_trigger_ids,
        active_by_call_trigger_ids,
        contracts,
    )
}

fn capture(block: SetBlock<'_>) -> DetachedSet<()> {
    block.try_detach(|_| Ok::<(), ()>(())).unwrap()
}

fn assert_all_writers_released(set: &Arc<Set>) {
    let worker = Arc::clone(set);
    let (completion_sender, received) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        // Each Storage::block obtains both concrete writers. This exercises
        // every actual owner rather than checking one representative lock.
        let all_ten = worker.block();
        drop(all_ten);
        completion_sender.send(()).unwrap();
    });
    received
        .recv_timeout(Duration::from_secs(5))
        .expect("all twenty trigger MV writers must be released");
    worker.join().unwrap();
}

fn mutate_all(block: &mut SetBlock<'_>) {
    let mut tx = block.transaction();
    tx.inspect_by_id_mut(&id("data"), |action| {
        action.set_repeats(Repeats::Exactly(0))
    })
    .unwrap();
    assert!(tx.remove(&id("pipeline")));
    tx.inspect_by_id_mut(&id("time"), |action| {
        action.set_repeats(Repeats::Exactly(7))
    })
    .unwrap();
    assert!(tx.set_time_trigger_retry_state(
        &id("time"),
        Some(TimeTriggerRetryState {
            retries_used: 1,
            next_retry_at_ms: 42,
        })
    ));
    register_call(&mut tx, "call_c");
    tx.apply();
}

struct Reservation(Arc<AtomicBool>);
impl Drop for Reservation {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[test]
fn ordinary_capture_retains_all_action_index_and_contract_deltas_without_publication() {
    let set = seeded_set();
    let before = images(&set);
    let mut block = set.block();
    mutate_all(&mut block);
    {
        let mut aborted = block.transaction();
        assert!(aborted.remove(&id("call_a")));
        register_data(&mut aborted, "aborted");
    }
    let calls = AtomicUsize::new(0);
    let released = Arc::new(AtomicBool::new(false));
    let detached = block
        .try_detach(|original| {
            calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                original.data_triggers.get(&id("data")).unwrap().repeats,
                Repeats::Exactly(0)
            );
            assert_eq!(
                original
                    .contracts
                    .get(&HashOf::new(&blob()))
                    .unwrap()
                    .count
                    .get(),
                3
            );
            assert!(original.ids.get(&id("aborted")).is_none());
            Ok::<_, ()>(Reservation(Arc::clone(&released)))
        })
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(detached.mode(), mv::BlockMode::Ordinary);
    assert!(!detached.admission().0.load(Ordering::SeqCst));
    assert_all_writers_released(&set);
    macro_rules! touched {
        ($($field:ident),+ $(,)?) => {$(
            assert!(detached.$field().touched_entries().len() > 0, stringify!($field));
        )+};
    }
    touched!(
        data_triggers,
        pipeline_triggers,
        time_triggers,
        by_call_triggers,
        ids,
        active_data_trigger_ids,
        active_pipeline_trigger_ids,
        active_time_trigger_ids,
        active_by_call_trigger_ids,
        contracts
    );
    let data = detached.data_triggers().touched_entries().next().unwrap();
    assert_eq!(data.before.unwrap().repeats, Repeats::Exactly(3));
    assert_eq!(data.after.unwrap().repeats, Repeats::Exactly(0));
    assert!(
        detached
            .active_data_trigger_ids()
            .touched_entries()
            .next()
            .unwrap()
            .after
            .is_none()
    );
    assert!(
        detached
            .pipeline_triggers()
            .touched_entries()
            .next()
            .unwrap()
            .after
            .is_none()
    );
    assert_eq!(
        detached
            .time_triggers()
            .touched_entries()
            .next()
            .unwrap()
            .after
            .unwrap()
            .retry_state,
        Some(TimeTriggerRetryState {
            retries_used: 1,
            next_retry_at_ms: 42
        })
    );
    let contract = detached.contracts().touched_entries().next().unwrap();
    assert_eq!(contract.before.unwrap().count.get(), 2);
    assert_eq!(contract.after.unwrap().count.get(), 3);
    assert_eq!(contract.after.unwrap().original_contract, blob());
    assert_eq!(
        contract.after.unwrap().code_hash,
        ivm::contract_code_hash(blob().as_ref())
    );
    assert!(
        detached
            .ids()
            .touched_entries()
            .all(|entry| entry.key != &id("aborted"))
    );
    assert!(detached.matches_current(&set));
    assert!(detached.matches_block_predecessor(&set.block()));
    assert_eq!(images(&set), before);
    drop(detached);
    assert!(released.load(Ordering::SeqCst));
    assert_eq!(images(&set), before);
    assert_all_writers_released(&set);
}

#[test]
fn whole_retention_refusal_releases_all_stores_and_preserves_current_and_undo() {
    let set = seeded_set();
    let before = images(&set);
    for replacement in [false, true] {
        let mut block = if replacement {
            set.block_and_revert()
        } else {
            set.block()
        };
        // The replacement restores the empty predecessor from initial creation.
        if !replacement {
            mutate_all(&mut block);
        }
        let calls = AtomicUsize::new(0);
        let result = block.try_detach(|original| {
            calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                original.data_triggers.mode(),
                if replacement {
                    mv::BlockMode::Replace
                } else {
                    mv::BlockMode::Ordinary
                }
            );
            Err::<Reservation, _>("retention budget")
        });
        assert!(matches!(
            result,
            Err(DetachError::Admission("retention budget"))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_all_writers_released(&set);
        assert_eq!(images(&set), before);
    }
}

#[test]
fn replacement_capture_keeps_discarded_tip_only_undo_for_every_store() {
    let set = seeded_set();
    let original = SetDto::from(set.as_ref()).encode().unwrap();
    let mut tip = set.block();
    mutate_all(&mut tip);
    tip.commit();
    let tip_images = images(&set);
    let replacement = set.block_and_revert();
    assert_eq!(
        replacement
            .contracts
            .get(&HashOf::new(&blob()))
            .unwrap()
            .count
            .get(),
        2
    );
    assert!(replacement.pipeline_triggers.get(&id("pipeline")).is_some());
    assert!(replacement.by_call_triggers.get(&id("call_c")).is_none());
    let detached = capture(replacement);
    assert_eq!(detached.mode(), mv::BlockMode::Replace);
    macro_rules! untouched {
        ($($field:ident),+ $(,)?) => {$(
            assert_eq!(detached.$field().mode(), mv::BlockMode::Replace);
            assert!(detached.$field().is_dirty());
            assert_eq!(detached.$field().touched_entries().len(), 0);
        )+};
    }
    untouched!(
        data_triggers,
        pipeline_triggers,
        time_triggers,
        by_call_triggers,
        ids,
        active_data_trigger_ids,
        active_pipeline_trigger_ids,
        active_time_trigger_ids,
        active_by_call_trigger_ids,
        contracts
    );
    assert_all_writers_released(&set);
    assert!(detached.matches_current(&set));
    assert!(!detached.matches_block_predecessor(&set.block()));
    assert!(detached.matches_block_predecessor(&set.block_and_revert()));
    drop(detached);
    assert_eq!(images(&set), tip_images);
    let mut replacement = set.block_and_revert();
    let mut tx = replacement.transaction();
    assert!(tx.remove(&id("call_a")));
    tx.apply();
    let changed = capture(replacement);
    let contract = changed.contracts().touched_entries().next().unwrap();
    assert_eq!(contract.before.unwrap().count.get(), 2);
    assert_eq!(contract.after.unwrap().count.get(), 1);
    let action = changed.by_call_triggers().touched_entries().next().unwrap();
    assert_eq!(action.key, &id("call_a"));
    assert!(action.before.is_some());
    assert!(action.after.is_none());
    assert!(
        changed
            .active_by_call_trigger_ids()
            .touched_entries()
            .next()
            .unwrap()
            .after
            .is_none()
    );
    assert!(changed.matches_current(&set));
    drop(changed);
    assert_all_writers_released(&set);
    assert_eq!(images(&set), tip_images);
    // Commit through the existing live owner only; detached capture has no publisher.
    set.block_and_revert().commit();
    assert_eq!(SetDto::from(set.as_ref()).encode().unwrap(), original);
}

#[test]
fn applied_and_aborted_child_postings_have_only_their_real_persistent_effects() {
    let set = Arc::new(Set::default());
    let mut block = set.block();
    let event = DataEvent::Account(AccountEvent::Deleted(ALICE_ID.clone()));
    {
        let mut child = block.transaction();
        register_data(&mut child, "aborted");
        assert_eq!(child.data_trigger_candidates(&event), vec![id("aborted")]);
        assert!(child.registration_generation(&id("aborted")) > 0);
    }
    {
        let mut child = block.transaction();
        assert!(child.data_trigger_candidates(&event).is_empty());
        assert_eq!(child.registration_generation(&id("aborted")), 0);
        let earlier = child.data_trigger_match_snapshot();
        register_data(&mut child, "applied");
        assert_eq!(child.data_trigger_candidates(&event), vec![id("applied")]);
        assert!(
            child
                .data_trigger_matching_generation(earlier, &id("applied"), &event)
                .is_none()
        );
        child.apply();
    }
    {
        let child = block.transaction();
        // Postings rebuild from the applied map; ephemeral eligibility belongs
        // to this new child and is not a deferred SetBlock event queue.
        assert_eq!(child.data_trigger_candidates(&event), vec![id("applied")]);
        assert_eq!(child.registration_generation(&id("applied")), 0);
    }
    let detached = capture(block);
    let actions = detached
        .data_triggers()
        .touched_entries()
        .collect::<Vec<_>>();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].key, &id("applied"));
    assert!(actions[0].before.is_none());
    assert_eq!(detached.ids().touched_entries().count(), 1);
    assert_eq!(
        detached.active_data_trigger_ids().touched_entries().count(),
        1
    );
    assert_all_writers_released(&set);
    assert!(set.view().ids_iter().next().is_none());
}

#[test]
fn every_untouched_component_identity_is_required_even_for_equal_values() {
    for changed in 0..10 {
        let set = Arc::new(Set::default());
        let detached = capture(set.block());
        assert!(detached.matches_current(&set));
        assert!(detached.matches_block_predecessor(&set.block()));
        // Structural owner control: every single component's ordinary no-op
        // publication rotates identity, even though all current maps stay empty.
        match changed {
            0 => set.data_triggers.block().commit(),
            1 => set.pipeline_triggers.block().commit(),
            2 => set.time_triggers.block().commit(),
            3 => set.by_call_triggers.block().commit(),
            4 => set.ids.block().commit(),
            5 => set.active_data_trigger_ids.block().commit(),
            6 => set.active_pipeline_trigger_ids.block().commit(),
            7 => set.active_time_trigger_ids.block().commit(),
            8 => set.active_by_call_trigger_ids.block().commit(),
            9 => set.contracts.block().commit(),
            _ => unreachable!(),
        }
        assert!(!detached.matches_current(&set), "component {changed}");
        assert!(
            !detached.matches_block_predecessor(&set.block()),
            "component {changed}"
        );
        assert_all_writers_released(&set);
    }
}

#[test]
fn inconsistent_original_modes_refuse_before_callback_and_release_all_owners() {
    let set = Arc::new(Set::default());
    let foreign = Arc::new(Set::default());
    let mut block = set.block();
    block.ids = crate::state::block_field::BlockField::new(foreign.ids.block_and_revert());
    let called = AtomicBool::new(false);
    let result = block.try_detach(|_| {
        called.store(true, Ordering::SeqCst);
        Ok::<(), ()>(())
    });
    assert!(matches!(
        result,
        Err(DetachError::InconsistentMode {
            field: "ids",
            expected: mv::BlockMode::Ordinary,
            actual: mv::BlockMode::Replace,
        })
    ));
    assert!(!called.load(Ordering::SeqCst));
    assert_all_writers_released(&set);
    assert_all_writers_released(&foreign);
}

#[test]
fn captured_set_is_a_static_worker_result_and_outlives_its_original_owner() {
    fn assert_static<T: Send + Sync + 'static>() {}
    assert_static::<DetachedSet<Reservation>>();
    let set = seeded_set();
    let before = images(&set);
    let released = Arc::new(AtomicBool::new(false));
    let worker_set = Arc::clone(&set);
    let reservation = Arc::clone(&released);
    let detached = std::thread::spawn(move || {
        let mut block = worker_set.block();
        mutate_all(&mut block);
        block
            .try_detach(|_| Ok::<_, ()>(Reservation(reservation)))
            .unwrap()
    })
    .join()
    .unwrap();
    assert_eq!(Arc::strong_count(&set), 1);
    assert_all_writers_released(&set);
    assert_eq!(images(&set), before);
    assert!(detached.matches_current(&set));
    let weak = Arc::downgrade(&set);
    drop(set);
    assert!(weak.upgrade().is_none());
    assert_eq!(
        detached
            .contracts()
            .touched_entries()
            .next()
            .unwrap()
            .after
            .unwrap()
            .count
            .get(),
        3
    );
    assert!(!released.load(Ordering::SeqCst));
    drop(detached);
    assert!(released.load(Ordering::SeqCst));
}

#[test]
fn restored_equal_set_does_not_inherit_any_original_capture_authority() {
    let set = seeded_set();
    let detached = capture(set.block_and_revert());
    let wire = norito::json::to_json(set.as_ref()).unwrap();
    let restored: Set = norito::json::from_json(&wire).unwrap();
    assert_eq!(images(&restored), images(&set));
    assert!(detached.matches_current(&set));
    assert!(!detached.matches_current(&restored));
    assert!(!detached.matches_block_predecessor(&restored.block_and_revert()));
    let current = capture(set.block());
    {
        let mut aborted = set.block();
        mutate_all(&mut aborted);
    }
    assert!(current.matches_current(&set));
    let mut changed = set.block();
    mutate_all(&mut changed);
    changed.commit();
    assert!(!current.matches_current(&set));
    set.block_and_revert().commit();
    assert_eq!(
        SetDto::from(set.as_ref()).encode().unwrap(),
        SetDto::from(&restored).encode().unwrap()
    );
    assert!(
        !current.matches_current(&set),
        "returning to prior values cannot restore identity"
    );
    assert_all_writers_released(&set);
}

#[path = "set_frozen_read_tests.rs"]
mod frozen_read_tests;
