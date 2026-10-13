//! Genuine original action/index corruption, both-image precedence and restore parity controls.
use super::*;
use iroha_allocation::AllocationBudget;
use iroha_test_samples::ALICE_ID;
use mv::storage::Storage;

pub(super) fn action() -> LoadedAction<DataEventFilter> {
    LoadedAction {
        executable: ExecutableRef::Instructions(Vec::<InstructionBox>::new().into()),
        repeats: Repeats::Indefinitely,
        authority: ALICE_ID.clone(),
        filter: DataEventFilter::Any,
        retry_policy: None,
        retry_state: None,
        metadata: Metadata::default(),
    }
}
pub(super) fn fixture() -> Set {
    let mut set = Set::default();
    set.data_triggers = [("a".parse().unwrap(), action())].into_iter().collect();
    set.ids = [("a".parse().unwrap(), TriggeringEventType::Data)]
        .into_iter()
        .collect();
    set.active_data_trigger_ids = [("a".parse().unwrap(), ())].into_iter().collect();
    set
}
pub(super) fn checked(set: &Set) -> Result<(), TriggerContractError> {
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let outcome = CheckedActions::capture(set, u64::MAX, &pool).map(|_| ());
    assert_eq!(pool.reserved_bytes(), 0);
    outcome
}
#[test]
fn the_four_empty_original_sources_and_a_real_active_action_are_admitted() {
    assert_eq!(checked(&Set::default()), Ok(()));
    assert_eq!(checked(&fixture()), Ok(()));
}
#[test]
fn source_action_requires_the_actual_id_and_exact_typed_kind() {
    let mut set = fixture();
    set.ids = Storage::default();
    assert_eq!(checked(&set), Err(fail(SemanticFailure::ActionIdMissing)));
    set.ids = [("a".parse().unwrap(), TriggeringEventType::Time)]
        .into_iter()
        .collect();
    assert_eq!(checked(&set), Err(fail(SemanticFailure::ActionKind)));
}
#[test]
fn the_same_id_cannot_become_two_independent_typed_actions() {
    let mut set = fixture();
    set.by_call_triggers = [(
        "a".parse().unwrap(),
        LoadedAction {
            executable: ExecutableRef::Instructions(Vec::<InstructionBox>::new().into()),
            repeats: Repeats::Indefinitely,
            authority: ALICE_ID.clone(),
            filter: ExecuteTriggerEventFilter::new(),
            retry_policy: None,
            retry_state: None,
            metadata: Metadata::default(),
        },
    )]
    .into_iter()
    .collect();
    assert_eq!(checked(&set), Err(fail(SemanticFailure::ActionDuplicate)));
}
#[test]
fn every_reverse_id_tail_requires_one_original_typed_action() {
    let mut set = fixture();
    set.ids = [
        ("a".parse().unwrap(), TriggeringEventType::Data),
        ("z_tail".parse().unwrap(), TriggeringEventType::Time),
    ]
    .into_iter()
    .collect();
    assert_eq!(checked(&set), Err(fail(SemanticFailure::ActionOrphan)));
}
#[test]
fn missing_enabled_membership_and_all_four_orphan_active_tails_refuse() {
    let mut set = fixture();
    set.active_data_trigger_ids = Storage::default();
    assert_eq!(
        checked(&set),
        Err(fail(SemanticFailure::ActionActiveMissing))
    );
    for table in ActionTable::ALL {
        let mut set = fixture();
        let tail = [("z_tail".parse().unwrap(), ())].into_iter().collect();
        match table {
            ActionTable::Data => {
                set.active_data_trigger_ids =
                    [("a".parse().unwrap(), ()), ("z_tail".parse().unwrap(), ())]
                        .into_iter()
                        .collect()
            }
            ActionTable::Pipeline => set.active_pipeline_trigger_ids = tail,
            ActionTable::Time => set.active_time_trigger_ids = tail,
            ActionTable::ByCall => set.active_by_call_trigger_ids = tail,
        }
        assert_eq!(
            checked(&set),
            Err(fail(SemanticFailure::ActionActiveUnexpected))
        );
    }
}
#[test]
fn original_bool_first_u64_and_malformed_json_decoding_semantics_are_identical() {
    use iroha_primitives::json::Json;
    for (value, expected) in [
        (Json::from(true), true),
        (Json::from(false), false),
        (Json::from(0_u64), false),
        (Json::from(1_u64), true),
        (Json::from(u64::MAX), true),
        (Json::from("true"), false),
        (Json::from(-1_f64), false),
        (Json::from(Vec::<u64>::new()), false),
    ] {
        let mut set = fixture();
        let mut entry = action();
        entry
            .metadata
            .insert("__enabled".parse().unwrap(), value.clone());
        let old = value
            .clone()
            .try_into_any_norito::<bool>()
            .or_else(|_| {
                value
                    .clone()
                    .try_into_any_norito::<u64>()
                    .map(|raw| raw != 0)
            })
            .unwrap_or(false);
        assert_eq!(old, expected);
        assert_eq!(
            super::super::super::trigger_is_enabled(&entry.metadata),
            expected
        );
        set.data_triggers = [("a".parse().unwrap(), entry)].into_iter().collect();
        if !expected {
            set.active_data_trigger_ids = Storage::default();
        }
        assert_eq!(checked(&set), Ok(()));
    }
}
#[test]
fn depletion_short_circuits_even_an_enabled_value_and_preserves_absent_default() {
    let mut set = fixture();
    let mut entry = action();
    entry.repeats = Repeats::Exactly(0);
    entry.metadata.insert("__enabled".parse().unwrap(), true);
    set.data_triggers = [("a".parse().unwrap(), entry)].into_iter().collect();
    set.active_data_trigger_ids = Storage::default();
    assert_eq!(checked(&set), Ok(()));
    assert_eq!(checked(&fixture()), Ok(()));
}
#[test]
fn current_source_fault_precedes_a_different_malformed_original_predecessor() {
    let set = fixture();
    let mut ids = set.ids.block();
    ids.insert("a".parse().unwrap(), TriggeringEventType::Time);
    ids.commit();
    let mut ids = set.ids.block();
    ids.insert("a".parse().unwrap(), TriggeringEventType::Data);
    ids.commit();
    let mut active = set.active_data_trigger_ids.block();
    active.remove("a".parse().unwrap());
    active.commit();
    assert_eq!(
        checked(&set),
        Err(fail(SemanticFailure::ActionActiveMissing))
    );
    let mut active = set.active_data_trigger_ids.block();
    active.insert("a".parse().unwrap(), ());
    active.commit();
    assert_eq!(checked(&set), Err(fail(SemanticFailure::ActionKind)));
}
#[test]
fn original_contract_failure_still_precedes_new_action_index_corruption() {
    let mut set = fixture();
    let bytes = IvmBytecode::from_compiled(vec![1, 2, 3]);
    let hash = HashOf::new(&bytes);
    let mut entry = action();
    entry.executable = ExecutableRef::Ivm(hash);
    set.data_triggers = [("a".parse().unwrap(), entry)].into_iter().collect();
    set.ids = Storage::default();
    assert_eq!(checked(&set), Err(fail(SemanticFailure::Missing)));
    assert_eq!(
        set.view().validate_world_contract_rows(),
        Err(SemanticFailure::Missing.original_message())
    );
}
#[test]
fn independent_noop_and_none_undo_rows_are_not_extra_index_authority() {
    let mut set = fixture();
    let mut ids = set.ids.block();
    ids.remove("not_present".parse().unwrap());
    ids.insert("a".parse().unwrap(), TriggeringEventType::Data);
    ids.commit();
    let mut active = set.active_data_trigger_ids.block();
    active.insert("a".parse().unwrap(), ());
    active.commit();
    assert_eq!(checked(&set), Ok(()));
    assert_eq!(set.ids.history().iter_before_block().count(), 1);
    assert_eq!(
        set.active_data_trigger_ids
            .history()
            .iter_before_block()
            .count(),
        1
    );
}

#[test]
fn active_membership_in_the_wrong_typed_stream_is_not_independent_authority() {
    let mut set = fixture();
    set.active_time_trigger_ids = [("a".parse().unwrap(), ())].into_iter().collect();
    assert_eq!(
        checked(&set),
        Err(fail(SemanticFailure::ActionActiveUnexpected))
    );
}
