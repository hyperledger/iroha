//! Native journal preimages, explicit absence, finite funding and frozen retry.
use super::*;
use crate::state::{StateReadOnly, World};
use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
use iroha_model_base::state_path::StatePath;
use std::sync::OnceLock;

fn key(text: &str) -> StatePath {
    text.parse().unwrap()
}
fn tip() -> NativeExecutionTip {
    static TIP: OnceLock<NativeExecutionTip> = OnceLock::new();
    *TIP.get_or_init(|| {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1000)).unwrap();
        chain.commit_at(2000, Vec::new());
        let tip = chain.state().view().native_execution_tip().unwrap();
        tip
    })
}
fn seed(world: &World, values: &[(&str, Vec<u8>)]) {
    let mut block = world.block();
    for (name, value) in values {
        block.smart_contract_state.insert(key(name), value.clone());
    }
    let captured = WorldStateAccumulator::capture(&block).unwrap();
    *block.state_accumulator.get_mut() = captured;
    block.commit();
}
fn prepare(
    capture: &JournalCapture,
    world: &mut WorldBlock<'_>,
    budget: &AllocationBudget,
) -> ChargedShared<CutCapsule> {
    world.advance_state_accumulator(false).unwrap();
    world.begin_freeze();
    world.finish_freeze();
    capture.prepare(world, tip(), 2, budget).unwrap()
}

#[test]
fn touched_at_result_uses_current_value_instead_of_block_predecessor() {
    let world = World::new();
    seed(&world, &[("app/a", vec![1])]);
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut block = world.block();
    block.smart_contract_state.insert(key("app/a"), vec![2]);
    let original = JournalCapture::capture(&block, false, &budget).unwrap();
    block.smart_contract_state.insert(key("app/a"), vec![3]);
    let capsule = prepare(&original, &mut block, &budget);
    let row = capsule.changes().next().unwrap();
    assert_eq!(capsule.changes().len(), 1);
    assert_eq!(row.3, Some(hash_value(&vec![2_u8]).unwrap()));
    assert_eq!(row.4, Some(hash_value(&vec![3_u8]).unwrap()));
    assert_eq!(capsule.root, original.root);
    assert_ne!(capsule.root, capsule.applied_root);
}

#[test]
fn newly_touched_tail_insert_has_explicit_absent_result_preimage() {
    let world = World::new();
    seed(&world, &[]);
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut block = world.block();
    let original = JournalCapture::capture(&block, false, &budget).unwrap();
    block.smart_contract_state.insert(key("app/tail"), vec![7]);
    let capsule = prepare(&original, &mut block, &budget);
    let row = capsule.changes().next().unwrap();
    assert_eq!(row.3, None);
    assert_eq!(row.4, Some(hash_value(&vec![7_u8]).unwrap()));
    assert_eq!(capsule.applied_entries, capsule.entries + 1);
}

#[test]
fn result_deletion_then_tail_reinsert_never_recovers_block_before_value() {
    let world = World::new();
    seed(&world, &[("app/a", vec![1])]);
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut block = world.block();
    block.smart_contract_state.remove(key("app/a"));
    let original = JournalCapture::capture(&block, false, &budget).unwrap();
    assert_eq!(original.rows.as_slice()[0].after, None);
    block.smart_contract_state.insert(key("app/a"), vec![3]);
    let capsule = prepare(&original, &mut block, &budget);
    assert_eq!(capsule.changes().next().unwrap().3, None);
    assert_eq!(capsule.applied_entries, capsule.entries + 1);
}

#[test]
fn no_op_touch_at_result_is_retained_before_tail_delete() {
    let world = World::new();
    seed(&world, &[("app/a", vec![1])]);
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut block = world.block();
    block.smart_contract_state.insert(key("app/a"), vec![1]);
    let original = JournalCapture::capture(&block, false, &budget).unwrap();
    assert_eq!(original.rows.as_slice().len(), 1);
    assert_eq!(original.rows.as_slice()[0].before, None);
    assert_eq!(
        original.rows.as_slice()[0].after,
        Some(hash_value(&vec![1_u8]).unwrap())
    );
    block.smart_contract_state.remove(key("app/a"));
    let capsule = prepare(&original, &mut block, &budget);
    let row = capsule.changes().next().unwrap();
    assert_eq!(row.3, Some(hash_value(&vec![1_u8]).unwrap()));
    assert_eq!(row.4, None);
    assert_eq!(capsule.entries, capsule.applied_entries + 1);
}

#[test]
fn absent_to_absent_touch_at_result_remains_explicit_before_tail_insert() {
    let world = World::new();
    seed(&world, &[]);
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut block = world.block();
    block.smart_contract_state.insert(key("app/a"), vec![1]);
    block.smart_contract_state.remove(key("app/a"));
    let original = JournalCapture::capture(&block, false, &budget).unwrap();
    assert_eq!(original.rows.as_slice().len(), 1);
    assert_eq!(original.rows.as_slice()[0].before, None);
    assert_eq!(original.rows.as_slice()[0].after, None);
    assert_eq!(
        original.rows.as_slice()[0].key,
        Some(hash_value(&key("app/a")).unwrap())
    );
    block.smart_contract_state.insert(key("app/a"), vec![2]);
    let capsule = prepare(&original, &mut block, &budget);
    let row = capsule.changes().next().unwrap();
    assert_eq!(capsule.changes().len(), 1);
    assert_eq!(row.3, None);
    assert_eq!(row.4, Some(hash_value(&vec![2_u8]).unwrap()));
    assert_eq!(capsule.applied_entries, capsule.entries + 1);
}

#[test]
fn untouched_result_entry_deleted_by_tail_uses_native_journal_before() {
    let world = World::new();
    seed(&world, &[("app/a", vec![1])]);
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut block = world.block();
    let original = JournalCapture::capture(&block, false, &budget).unwrap();
    assert!(original.rows.as_slice().is_empty());
    block.smart_contract_state.remove(key("app/a"));
    let capsule = prepare(&original, &mut block, &budget);
    assert_eq!(
        capsule.changes().next().unwrap().3,
        Some(hash_value(&vec![1_u8]).unwrap())
    );
    assert_eq!(capsule.changes().next().unwrap().4, None);
}

#[test]
fn canonical_cell_and_tail_no_op_use_complete_semantic_projection() {
    let world = World::new();
    seed(&world, &[]);
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut block = world.block();
    *block.soradns_last_publish_ms.get_mut() = Some(4);
    let original = JournalCapture::capture(&block, false, &budget).unwrap();
    *block.soradns_last_publish_ms.get_mut() = Some(9);
    block
        .smart_contract_state
        .insert(key("app/transient"), vec![1]);
    block.smart_contract_state.remove(key("app/transient"));
    let capsule = prepare(&original, &mut block, &budget);
    assert_eq!(capsule.changes().len(), 1);
    let row = capsule.changes().next().unwrap();
    assert_eq!(row.0, "world.soradns_last_publish_ms");
    assert_eq!(row.1, WorldStateElementKindV1::Cell);
    assert_eq!(row.2, None);
    assert_eq!(row.3, Some(hash_value(&Some(4_u64)).unwrap()));
    assert_eq!(row.4, Some(hash_value(&Some(9_u64)).unwrap()));
}

#[test]
fn original_capture_budget_refusal_is_local_and_refunds_exact_pool() {
    let world = World::new();
    seed(&world, &[]);
    let block = world.block();
    let budget = AllocationBudget::new(0);
    assert!(matches!(
        JournalCapture::capture(&block, false, &budget),
        Err(CutError::Deferred(_))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn frozen_preparation_refusal_retries_same_original_and_releases_shared_charges() {
    let world = World::new();
    seed(&world, &[("app/a", vec![1])]);
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut block = world.block();
    block.smart_contract_state.insert(key("app/a"), vec![2]);
    let original = JournalCapture::capture(&block, false, &budget).unwrap();
    let original_root = original.root;
    block.smart_contract_state.insert(key("app/a"), vec![3]);
    block.advance_state_accumulator(false).unwrap();
    block.begin_freeze();
    block.finish_freeze();
    let refused = AllocationBudget::new(0);
    assert!(matches!(
        original.prepare(&block, tip(), 2, &refused),
        Err(CutError::Deferred(_))
    ));
    assert_eq!(refused.reserved_bytes(), 0);
    assert_eq!(original.root, original_root);
    let capsule = original.prepare(&block, tip(), 2, &budget).unwrap();
    let retained = capsule.clone();
    drop(capsule);
    assert!(budget.reserved_bytes() > 0);
    drop(retained);
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn frozen_capsule_rejects_corrupt_applied_accumulator_and_count() {
    let world = World::new();
    seed(&world, &[]);
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut block = world.block();
    let original = JournalCapture::capture(&block, false, &budget).unwrap();
    block.advance_state_accumulator(false).unwrap();
    block.state_accumulator.get_mut().entries += 1;
    block.begin_freeze();
    block.finish_freeze();
    assert!(matches!(
        original.prepare(&block, tip(), 2, &budget),
        Err(CutError::Invalid(_))
    ));
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn replacement_cut_is_derived_from_exact_reverted_world_journal() {
    let world = World::new();
    seed(&world, &[("app/a", vec![1])]);
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    {
        let mut first = world.block();
        first.smart_contract_state.insert(key("app/a"), vec![2]);
        first.advance_state_accumulator(false).unwrap();
        first.commit();
    }
    let mut replacement = world.block_and_revert();
    assert_eq!(
        replacement.smart_contract_state.get(&key("app/a")),
        Some(&vec![1])
    );
    replacement
        .smart_contract_state
        .insert(key("app/replacement"), vec![5]);
    let original = JournalCapture::capture(&replacement, false, &budget).unwrap();
    replacement
        .smart_contract_state
        .insert(key("app/replacement"), vec![6]);
    let capsule = prepare(&original, &mut replacement, &budget);
    assert_eq!(capsule.changes().len(), 1);
    assert_eq!(
        capsule.changes().next().unwrap().3,
        Some(hash_value(&vec![5_u8]).unwrap())
    );
}

#[test]
fn musubi_tail_uses_canonical_semantic_anchor_and_excludes_runtime_cache_rows() {
    use iroha_data_model::musubi::{
        ArchiveId, MusubiArchiveAvailabilityV1, MusubiStorageAvailabilityV1,
    };
    let world = World::new();
    let archive = ArchiveId::new([0x41; 32]);
    let original = MusubiArchiveAvailabilityV1 {
        archive_id: archive,
        availability: MusubiStorageAvailabilityV1::Unavailable,
        healthy_replicas: 0,
        active_locations: 0,
        finalized_height: 7,
        finalized_block_hash: [0x42; 32],
        index_revision: 9,
    };
    original.validate().unwrap();
    {
        let mut seed = world.block();
        seed.musubi_archive_availability.insert(archive, original);
        let accumulator = WorldStateAccumulator::capture(&seed).unwrap();
        *seed.state_accumulator.get_mut() = accumulator;
        seed.commit();
    }
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut block = world.block();
    let cut = JournalCapture::capture(&block, false, &budget).unwrap();
    let mut derived = original;
    derived.availability = MusubiStorageAvailabilityV1::BelowQuorum;
    derived.healthy_replicas = 1;
    derived.active_locations = 1;
    derived.validate().unwrap();
    block.musubi_archive_availability.insert(archive, derived);
    let capsule = prepare(&cut, &mut block, &budget);
    assert_eq!(capsule.changes().len(), 0);
    assert_eq!(capsule.root, capsule.applied_root);
}

#[test]
fn touched_journal_capture_storage_cost_is_independent_of_untouched_world_entries() {
    let world = World::new();
    {
        let mut seed = world.block();
        for i in 0..1000 {
            seed.smart_contract_state
                .insert(key(&format!("app/k{i}")), vec![7; 16]);
        }
        let accumulator = WorldStateAccumulator::capture(&seed).unwrap();
        *seed.state_accumulator.get_mut() = accumulator;
        seed.commit();
    }
    let budget = AllocationBudget::new(8192);
    let mut block = world.block();
    block
        .smart_contract_state
        .insert(key("app/k3"), vec![8; 16]);
    let cut = JournalCapture::capture(&block, false, &budget).unwrap();
    assert_eq!(cut.rows.as_slice().len(), 1);
    assert_eq!(budget.reserved_bytes(), std::mem::size_of::<JournalRow>());
    drop(cut);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn trigger_tail_projects_authoritative_action_and_excludes_derived_indexes() {
    use crate::smartcontracts::isi::triggers::specialized::{
        SpecializedAction, SpecializedTrigger,
    };
    use iroha_data_model::{events::execute_trigger::ExecuteTriggerEventFilter, prelude::*};
    let world = World::new();
    seed(&world, &[]);
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut block = world.block();
    let cut = JournalCapture::capture(&block, false, &budget).unwrap();
    {
        let mut tx = block.triggers.transaction();
        let action = SpecializedAction::new(
            Executable::Instructions(
                vec![InstructionBox::from(Log::new(
                    Level::INFO,
                    "native cut action".into(),
                ))]
                .into(),
            ),
            Repeats::Exactly(3),
            iroha_test_samples::ALICE_ID.clone(),
            ExecuteTriggerEventFilter::new(),
        )
        .unwrap();
        assert!(
            tx.add_by_call_trigger(SpecializedTrigger::new(
                "native_cut".parse().unwrap(),
                action
            ))
            .unwrap()
        );
        tx.apply();
    }
    let complete = WorldStateAccumulator::capture(&block).unwrap();
    assert_eq!(complete.entries(), cut.entries + 1);
    let capsule = prepare(&cut, &mut block, &budget);
    assert_eq!(capsule.changes().len(), 1);
    let row = capsule.changes().next().unwrap();
    assert_eq!(row.0, "triggers.by_call");
    assert_eq!(row.3, None);
    assert!(row.4.is_some());
    assert_eq!(capsule.entries + 1, capsule.applied_entries);
}

#[test]
fn frozen_tail_reconstructs_original_cut_with_absent_and_noop_touches() {
    let world = World::new();
    {
        let mut setup = world.block();
        setup
            .smart_contract_state
            .insert(key("cut/delete"), vec![4]);
        setup.smart_contract_state.insert(key("cut/noop"), vec![3]);
        setup.advance_state_accumulator(true).unwrap();
        setup.commit();
    }
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut block = world.block();
    block
        .smart_contract_state
        .insert(key("cut/update"), vec![1]);
    block.smart_contract_state.insert(key("cut/noop"), vec![3]);
    block.smart_contract_state.remove(key("cut/absent"));
    *block.soradns_last_publish_ms.get_mut() = Some(11);
    let original = WorldStateAccumulator::capture(&block).unwrap();
    let capture = JournalCapture::capture(&block, false, &budget).unwrap();
    assert_eq!(capture.root, original.root().unwrap());
    assert_eq!(capture.entries, original.entries());
    assert!(capture.rows.as_slice().iter().any(|row| {
        row.key == Some(hash_value(&key("cut/absent")).unwrap())
            && row.before.is_none()
            && row.after.is_none()
    }));
    assert!(capture.rows.as_slice().iter().any(|row| {
        row.key == Some(hash_value(&key("cut/noop")).unwrap())
            && row.before.is_none()
            && row.after == Some(hash_value(&vec![3_u8]).unwrap())
    }));
    let complete_journal = journal(&block, &budget, true).unwrap();
    assert!(complete_journal.as_slice().iter().any(|row| {
        row.key == Some(hash_value(&key("cut/noop")).unwrap())
            && row.before.is_some()
            && row.before == row.after
    }));
    drop(complete_journal);

    block
        .smart_contract_state
        .insert(key("cut/update"), vec![2]);
    block.smart_contract_state.remove(key("cut/delete"));
    block.smart_contract_state.insert(key("cut/new"), vec![5]);
    block
        .smart_contract_state
        .insert(key("cut/absent"), vec![6]);
    *block.soradns_last_publish_ms.get_mut() = Some(22);
    block.advance_state_accumulator(false).unwrap();
    let applied = WorldStateAccumulator::capture(&block).unwrap();
    let semantic_delta = block.net_state_delta().unwrap();
    let publication_delta = block.publication_state_delta().unwrap();
    let original_storage_value =
        std::ptr::from_ref(block.smart_contract_state.get(&key("cut/update")).unwrap());
    let original_cell_value = std::ptr::from_ref(block.soradns_last_publish_ms.get());
    assert_ne!(original.root(), applied.root());
    block.begin_freeze();
    block.finish_freeze();
    // Both visitors and cold capture read the same original payloads after
    // execution authority is consumed and all physical writers are released.
    assert_eq!(block.net_state_delta().unwrap(), semantic_delta);
    assert_eq!(block.publication_state_delta().unwrap(), publication_delta);
    assert_eq!(WorldStateAccumulator::capture(&block).unwrap(), applied);
    assert_eq!(
        std::ptr::from_ref(block.smart_contract_state.get(&key("cut/update")).unwrap()),
        original_storage_value
    );
    assert_eq!(
        std::ptr::from_ref(block.soradns_last_publish_ms.get()),
        original_cell_value
    );
    let tip = tip();
    let capsule = capture.prepare(&block, tip, 8, &budget).unwrap();
    assert_eq!(capsule.tip, tip);
    assert_eq!(capsule.generation, 8);
    assert_eq!(capsule.root, original.root().unwrap());
    assert_eq!(capsule.entries, original.entries());
    assert_eq!(capsule.applied_root, applied.root().unwrap());
    assert_eq!(capsule.applied_entries, applied.entries());
    assert_eq!(capsule.rows.as_slice().len(), 5);
    let changes: Vec<_> = capsule.changes().collect();
    assert!(
        changes
            .windows(2)
            .all(|pair| { (pair[0].0, pair[0].1, pair[0].2) < (pair[1].0, pair[1].1, pair[1].2) })
    );
    for (index, &(id, kind, key, before, after)) in changes.iter().enumerate() {
        assert_eq!(
            capsule.change_for(id, kind, key),
            Some((index, before, after))
        );
        assert_ne!(
            before, after,
            "only actual post-result changes are retained"
        );
    }
    for (name, before, after) in [
        ("cut/update", Some(vec![1_u8]), Some(vec![2_u8])),
        ("cut/delete", Some(vec![4]), None),
        ("cut/new", None, Some(vec![5])),
        ("cut/absent", None, Some(vec![6])),
    ] {
        let (_, observed_before, observed_after) = capsule
            .change_for(
                "world.smart_contract_state",
                WorldStateElementKindV1::Table,
                Some(hash_value(&key(name)).unwrap()),
            )
            .expect("exact tail change");
        assert_eq!(
            observed_before,
            before.as_ref().map(hash_value).transpose().unwrap()
        );
        assert_eq!(
            observed_after,
            after.as_ref().map(hash_value).transpose().unwrap()
        );
    }
    let (_, before, after) = capsule
        .change_for(
            "world.soradns_last_publish_ms",
            WorldStateElementKindV1::Cell,
            None,
        )
        .unwrap();
    assert_eq!(before, Some(hash_value(&Some(11_u64)).unwrap()));
    assert_eq!(after, Some(hash_value(&Some(22_u64)).unwrap()));
    assert!(
        capsule
            .change_for(
                "world.smart_contract_state",
                WorldStateElementKindV1::Table,
                Some(hash_value(&key("cut/noop")).unwrap()),
            )
            .is_none()
    );
    assert!(budget.reserved_bytes() > 0);
    drop(capsule);
    drop(capture);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn journal_cut_rejects_incomplete_registry_and_lost_original_touches() {
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let index = field_index().as_ref().unwrap();
    let mut visitor = JournalVisitor::new(index, &budget, None, false).unwrap();
    assert!(
        visitor
            .field("smart_contract_state", TABLE)
            .unwrap()
            .is_some()
    );
    assert!(visitor.field("smart_contract_state", TABLE).is_err());
    assert!(visitor.field("parameters", TABLE).is_err());
    assert!(visitor.field("not_registered", TABLE).is_err());
    assert_eq!(visitor.field("domains_by_owner", TABLE).unwrap(), None);
    assert!(visitor.finish().is_err());
    assert_eq!(budget.reserved_bytes(), 0);

    let world = World::new();
    let capture = {
        let mut original = world.block();
        original.smart_contract_state.remove(key("cut/absent"));
        JournalCapture::capture(&original, true, &budget).unwrap()
    };
    // A replacement overlay has the same values but has lost the original
    // absent-to-absent touch. It cannot stand in for the original execution.
    let mut replacement = world.block();
    replacement.advance_state_accumulator(true).unwrap();
    let retained = budget.reserved_bytes();
    assert!(matches!(
        capture.prepare(&replacement, tip(), 2, &budget),
        Err(CutError::Invalid(reason)) if reason.contains("original execution touches")
    ));
    assert_eq!(budget.reserved_bytes(), retained);
    drop(capture);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn cut_refusal_refunds_scratch_and_retries_the_original_frozen_journal() {
    let world = World::new();
    let mut block = world.block();
    block.smart_contract_state.insert(key("cut/value"), vec![1]);
    let empty_budget = AllocationBudget::new(0);
    assert!(matches!(
        JournalCapture::capture(&block, true, &empty_budget),
        Err(CutError::Deferred(_))
    ));
    assert_eq!(empty_budget.reserved_bytes(), 0);

    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut capture = JournalCapture::capture(&block, true, &budget).unwrap();
    block.smart_contract_state.insert(key("cut/value"), vec![2]);
    block.advance_state_accumulator(true).unwrap();
    block.begin_freeze();
    block.finish_freeze();
    let tip = tip();
    let retained = budget.reserved_bytes();
    budget.set_limit_bytes(retained);
    assert!(matches!(
        capture.prepare(&block, tip, 2, &budget),
        Err(CutError::Deferred(_))
    ));
    assert_eq!(budget.reserved_bytes(), retained);
    budget.set_limit_bytes(16 * 1024 * 1024);
    let capsule = capture.prepare(&block, tip, 2, &budget).unwrap();
    assert_eq!(capsule.root, capture.root);
    assert_eq!(capsule.rows.as_slice().len(), 1);
    drop(capsule);
    assert_eq!(budget.reserved_bytes(), retained);

    capture.entries += 1;
    assert!(matches!(
        capture.prepare(&block, tip, 2, &budget),
        Err(CutError::Invalid(reason)) if reason.contains("reconstruct original R/count")
    ));
    assert_eq!(budget.reserved_bytes(), retained);
    drop(capture);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn completed_cut_refusal_retains_exact_tail_rows_and_original_pool_until_delivery() {
    let world = World::new();
    seed(&world, &[("cut/completed", vec![1])]);
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let mut block = world.block();
    block
        .smart_contract_state
        .insert(key("cut/completed"), vec![2]);
    let capture = JournalCapture::capture(&block, false, &budget).unwrap();
    block
        .smart_contract_state
        .insert(key("cut/completed"), vec![3]);
    block.advance_state_accumulator(false).unwrap();
    block.begin_freeze();
    block.finish_freeze();
    let root = capture.root;
    let original_capture = capture.rows.as_slice().as_ptr();
    let original_tip = tip();
    completion_observer::observe(&budget, |observation| {
        let Err((Some(pending), CutError::Deferred(reason))) =
            capture.prepare_retained(&block, original_tip, 2, &budget)
        else {
            panic!("completed original tail must defer only its final actual shell");
        };
        assert!(matches!(reason.allocation_refusal(),
            Some(AllocationRefusal::Capacity { requested_bytes, .. })
            if *requested_bytes == ChargedShared::<CutCapsule>::allocation_layout().size()));
        drop(reason);
        let completed = observation.snapshot();
        assert_eq!(completed.0, 1);
        assert_eq!(completed.1, Some(pending.identity_for_test()));
        assert_eq!(pending.capsule.rows.as_slice().len(), 1);
        let tail = pending.capsule.rows.as_slice().as_ptr();
        assert!(pending.budget.same_pool(&budget));
        assert_eq!(pending.capsule.tip, original_tip);
        assert_eq!(pending.capsule.generation, 2);
        assert_eq!(pending.capsule.root, root);
        assert_ne!(pending.capsule.applied_root, root);
        assert_eq!(capture.rows.as_slice().as_ptr(), original_capture);
        // Reconstruction scratch retired at the first refused return. Once the
        // original blocker releases, the unchanged limit can fund final delivery.
        observation.release_original_blocker();
        let retained = budget.reserved_bytes();
        let capsule = match pending.try_share() {
            Ok(capsule) => capsule,
            Err((_pending, error)) => {
                panic!("same original final shell funds after release: {error}")
            }
        };
        assert_eq!(capsule.rows.as_slice().as_ptr(), tail);
        assert_eq!(capsule.identity_for_test(), completed.1.unwrap());
        assert_eq!(observation.snapshot(), completed);
        assert_eq!(
            budget.reserved_bytes(),
            retained + ChargedShared::<CutCapsule>::allocation_layout().size()
        );
        drop(capsule);
        assert_eq!(
            budget.reserved_bytes(),
            retained - std::alloc::Layout::array::<JournalRow>(1).unwrap().size()
        );
    });
    drop(capture);
    assert_eq!(budget.reserved_bytes(), 0);
}
