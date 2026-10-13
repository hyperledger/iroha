//! Actual ten-reader retention, all-probe materialization, canonical parity and refund controls.
use super::*;
use iroha_test_samples::ALICE_ID;
use std::panic::{AssertUnwindSafe, catch_unwind};
fn limits() -> LeafLimits {
    LeafLimits {
        max_tables: 1,
        max_rows: 8,
        max_payload_bytes: 65536,
        max_ordered_table_bytes: 131_072,
        max_streamed_value_bytes: 131_072,
    }
}
fn fixture() -> Set {
    let mut set = Set::default();
    let action = LoadedAction {
        executable: ExecutableRef::Instructions(Vec::<InstructionBox>::new().into()),
        repeats: Repeats::Indefinitely,
        authority: ALICE_ID.clone(),
        filter: ExecuteTriggerEventFilter::new(),
        retry_policy: None,
        retry_state: None,
        metadata: Metadata::default(),
    };
    set.by_call_triggers = [("call".parse().unwrap(), action)].into_iter().collect();
    set.ids = [("call".parse().unwrap(), TriggeringEventType::ExecuteTrigger)]
        .into_iter()
        .collect();
    set.active_by_call_trigger_ids = [("call".parse().unwrap(), ())].into_iter().collect();
    set
}
fn equal(actual: &CanonicalTablePairedSnapshot, expected: &CanonicalTablePairedSnapshot) {
    assert_eq!(actual.table_id(), expected.table_id());
    assert_eq!(actual.row_count(), expected.row_count());
    assert_eq!(actual.root(), expected.root());
    assert_eq!(actual.lookup_root(), expected.lookup_root());
    assert_eq!(actual.ordered_root(), expected.ordered_root());
}
#[test]
fn all_four_checked_projections_match_the_actual_original_borrowed_canonical_frames() {
    let set = fixture();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let mut checked = CheckedActions::capture(&set, u64::MAX, &pool).unwrap();
    let counter = pool.reserved_bytes();
    assert!(counter > 0);
    macro_rules! parity {
        ($field:ident,$table:literal,$domain:literal,$choice:expr) => {{
            let view = set.$field.view();
            let expected = CanonicalTableLeafSet::paired_semantic_table_from_rows(
                $table,
                $domain,
                limits(),
                &pool,
                view.iter(),
                BorrowedWorldAction::new,
            )
            .unwrap();
            let actual = checked.encode($choice, limits()).unwrap();
            equal(&actual, &expected);
        }};
    }
    parity!(
        data_triggers,
        "triggers.data",
        "iroha:state:trigger-data-action:v1",
        ActionTable::Data
    );
    parity!(
        pipeline_triggers,
        "triggers.pipeline",
        "iroha:state:trigger-pipeline-action:v1",
        ActionTable::Pipeline
    );
    parity!(
        time_triggers,
        "triggers.time",
        "iroha:state:trigger-time-action:v1",
        ActionTable::Time
    );
    parity!(
        by_call_triggers,
        "triggers.by_call",
        "iroha:state:trigger-by-call-action:v1",
        ActionTable::ByCall
    );
    assert_eq!(pool.reserved_bytes(), counter);
    assert_eq!(checked.matches_current(), Ok(true));
    assert_eq!(checked.probes.get(), [2; 10]);
    drop(checked);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn every_equal_value_native_publication_invalidates_the_same_original_ten_reader_cut() {
    for index in 0..10 {
        let set = fixture();
        let pool = AllocationBudget::new(16 * 1024 * 1024);
        let checked = CheckedActions::capture(&set, u64::MAX, &pool).unwrap();
        match index {
            0 => set.data_triggers.block().commit(),
            1 => set.pipeline_triggers.block().commit(),
            2 => set.time_triggers.block().commit(),
            3 => set.by_call_triggers.block().commit(),
            4 => set.ids.block().commit(),
            5 => set.active_data_trigger_ids.block().commit(),
            6 => set.active_pipeline_trigger_ids.block().commit(),
            7 => set.active_time_trigger_ids.block().commit(),
            8 => set.active_by_call_trigger_ids.block().commit(),
            _ => set.contracts.block().commit(),
        }
        assert_eq!(checked.matches_current(), Ok(false));
        assert_eq!(checked.probes.get(), [2; 10]);
        drop(checked);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
#[test]
fn first_native_probe_refusal_still_materializes_every_other_original_probe() {
    let set = fixture();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let checked = CheckedActions::capture(&set, u64::MAX, &pool).unwrap();
    let detached = set
        .data_triggers
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap();
    let prepared = detached
        .try_prepare_publication(&set.data_triggers, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|(_, error, _)| panic!("actual publication refusal {error:?}"));
    let original = checked
        .base
        .data
        .try_matches_current(&set.data_triggers)
        .unwrap_err();
    assert!(matches!(original, mv::PublicationPreparationError::Busy(_)));
    assert_eq!(
        checked.matches_current(),
        Err(TriggerContractError::Publication(original))
    );
    assert_eq!(checked.probes.get(), [2; 10]);
    drop(prepared);
    drop(checked);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn encoding_failure_is_held_through_native_probes_drop_and_retry() {
    let set = fixture();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let mut checked = CheckedActions::capture(&set, u64::MAX, &pool).unwrap();
    let counter = pool.reserved_bytes();
    let outcome = checked.encode(
        ActionTable::ByCall,
        LeafLimits {
            max_payload_bytes: 0,
            ..limits()
        },
    );
    assert!(outcome.is_err());
    assert_eq!(pool.reserved_bytes(), counter);
    set.active_time_trigger_ids.block().commit();
    assert_eq!(checked.matches_current(), Ok(false));
    assert_eq!(checked.probes.get(), [2; 10]);
    drop(checked);
    assert_eq!(pool.reserved_bytes(), 0);
    let mut retry = CheckedActions::capture(&set, u64::MAX, &pool).unwrap();
    assert_eq!(
        retry
            .encode(ActionTable::ByCall, limits())
            .unwrap()
            .row_count(),
        1
    );
}
#[test]
fn original_pool_refusal_and_unwind_leave_no_extra_action_bank_or_retained_counter() {
    let set = fixture();
    let pool = AllocationBudget::new(0);
    assert!(matches!(
        CheckedActions::capture(&set, u64::MAX, &pool),
        Err(TriggerContractError::Admission(_))
    ));
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(pool.peak_reserved_bytes(), 0);
    pool.set_limit_bytes(16 * 1024 * 1024);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let mut checked = CheckedActions::capture(&set, u64::MAX, &pool).unwrap();
            let _outcome = checked.encode(ActionTable::ByCall, limits()).unwrap();
            panic!("held action outcome");
        }))
        .is_err()
    );
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn selected_empty_action_output_cannot_hide_a_corrupt_populated_sibling() {
    let mut set = fixture();
    set.ids = mv::storage::Storage::default();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let result = CheckedActions::capture(&set, action_source_work(limits()), &pool)
        .map_err(LeafError::from)
        .and_then(|mut checked| {
            let outcome = checked.encode(ActionTable::Data, limits());
            let current = checked.matches_current();
            drop(checked);
            assert!(current.expect("original action source identities"));
            outcome
        });
    assert!(matches!(result, Err(LeafError::SourceValidation(_))));
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn frozen_context_rejects_every_foreign_original_component_without_refresh() {
    let set = fixture();
    let foreign = Set::default();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    for index in 0..10 {
        let mut block = set.block();
        let mut other = foreign.block();
        match index {
            0 => std::mem::swap(&mut block.data_triggers, &mut other.data_triggers),
            1 => std::mem::swap(&mut block.pipeline_triggers, &mut other.pipeline_triggers),
            2 => std::mem::swap(&mut block.time_triggers, &mut other.time_triggers),
            3 => std::mem::swap(&mut block.by_call_triggers, &mut other.by_call_triggers),
            4 => std::mem::swap(&mut block.ids, &mut other.ids),
            5 => std::mem::swap(
                &mut block.active_data_trigger_ids,
                &mut other.active_data_trigger_ids,
            ),
            6 => std::mem::swap(
                &mut block.active_pipeline_trigger_ids,
                &mut other.active_pipeline_trigger_ids,
            ),
            7 => std::mem::swap(
                &mut block.active_time_trigger_ids,
                &mut other.active_time_trigger_ids,
            ),
            8 => std::mem::swap(
                &mut block.active_by_call_trigger_ids,
                &mut other.active_by_call_trigger_ids,
            ),
            _ => std::mem::swap(&mut block.contracts, &mut other.contracts),
        }
        block.begin_freeze();
        block.finish_freeze();
        block.retire_frozen_cleanup();
        assert!(
            block
                .capture_frozen_action_authority_table(
                    &set,
                    ActionTable::ByCall,
                    limits(),
                    &pool,
                    u64::MAX
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn empty_and_singleton_full_capture_equations_are_independent_below_exact_above_controls() {
    if usize::BITS != 64 {
        return;
    }
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    // Empty: prior contract24S+16N+83; inverse Current9S+9N+27 and Prior18S+18N+45.
    // Singleton instructions: contract+encode24S+19N+159; inverse C23S+31N+304,P46S+54N+366.
    // call name4 rather than a name1 adds10 comparisons*6 bytes=60.
    assert_eq!(51 * 1900 + 43 * 1114 + 155, 144_957);
    assert_eq!(93 * 1900 + 104 * 1114 + 829 + 60, 293_445);
    for (set, table, exact, rows) in [
        (Set::default(), ActionTable::Data, 144_957_u64, 0),
        (fixture(), ActionTable::ByCall, 293_445, 1),
    ] {
        for amount in [exact - 1, exact, exact + 1] {
            let mut checked = CheckedActions::capture(&set, amount, &pool).unwrap();
            let outcome = checked.encode(table, limits());
            let current = checked.matches_current();
            assert_eq!(current, Ok(true));
            drop(checked);
            if amount < exact {
                assert!(matches!(
                    outcome,
                    Err(LeafError::TriggerContracts(TriggerContractError::WorkLimit))
                ));
            } else {
                let snapshot = outcome.unwrap();
                assert_eq!(snapshot.row_count(), rows);
                drop(snapshot);
            }
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}

#[test]
fn common_ordinary_replace_modes_are_retained_and_one_mixed_mode_is_absent() {
    let set = fixture();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    for replace in [false, true] {
        let mut block = if replace {
            set.block_and_revert()
        } else {
            set.block()
        };
        block.begin_freeze();
        block.finish_freeze();
        block.retire_frozen_cleanup();
        let owner = FrozenContracts::retain(&block, &set).unwrap();
        assert_eq!(
            owner.data.mode(),
            if replace {
                mv::BlockMode::Replace
            } else {
                mv::BlockMode::Ordinary
            }
        );
        drop(owner);
        let actual = block
            .capture_frozen_action_authority_table(
                &set,
                ActionTable::ByCall,
                limits(),
                &pool,
                u64::MAX,
            )
            .unwrap()
            .unwrap();
        assert_eq!(actual.row_count(), 1);
        drop(actual);
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let mut block = set.block();
    mv::BlockRetirement::release_writers(
        &mut block.fields.as_mut().unwrap().active_time_trigger_ids,
    );
    block.fields.as_mut().unwrap().active_time_trigger_ids =
        BlockField::new(set.active_time_trigger_ids.block_and_revert());
    block.begin_freeze();
    block.finish_freeze();
    block.retire_frozen_cleanup();
    assert!(
        block
            .capture_frozen_action_authority_table(
                &set,
                ActionTable::ByCall,
                limits(),
                &pool,
                u64::MAX
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(pool.reserved_bytes(), 0);
}
