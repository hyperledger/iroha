//! Actual trigger-store net-delta and borrowed semantic codec controls.
//! These tests do not execute callbacks or authenticate a full State root.

use super::*;
use crate::smartcontracts::isi::triggers::{
    TRIGGER_ENABLED_METADATA_KEY, global_data_trigger_scope_metadata_for_testing,
};
use crate::state::authority_registry::leaf::{CanonicalTableLeafSet, LeafError, LeafLimits};
use crate::state::world_projection::{WorldDeltaBuilder, WorldNetDelta, hash_value};
use iroha_data_model::events::{execute_trigger::ExecuteTriggerEventFilter, time::Schedule};
use iroha_primitives::json::Json;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use std::{num::NonZeroU32, time::Duration};

fn project(block: &SetBlock<'_>) -> WorldNetDelta {
    let mut builder = WorldDeltaBuilder::new();
    block
        .append_world_projection(&mut builder)
        .expect("trigger projection");
    builder.finish().expect("complete trigger projection")
}

#[test]
fn publication_identities_reject_equal_value_foreign_trigger_journals() {
    macro_rules! check {
        ($($field:ident),+ $(,)?) => {$(
            let expected = Set::default();
            let foreign = Set::default();
            let mut original = expected.block();
            let mut replacement = foreign.block();
            let mut captured = Vec::new();
            original.append_world_publication_identities(
                &expected, mv::BlockMode::Ordinary, &mut captured,
            ).expect("original trigger journals belong to their State owner");
            assert_eq!(captured.len(), 10);
            let original_identity = original.$field.publication_identity();
            assert_ne!(original_identity, replacement.$field.publication_identity(),
                "equal trigger values do not identify their journal owner: {}", stringify!($field));
            let values_before = project(&original);
            core::mem::swap(&mut original.$field, &mut replacement.$field);
            assert_eq!(project(&original), values_before,
                "the adversarial replacement must have exactly equal projected values");
            assert_ne!(original.$field.publication_identity(), original_identity,
                "an already captured identity rejects replacement: {}", stringify!($field));
            let mut first_capture = Vec::new();
            let error = original.append_world_publication_identities(
                &expected, mv::BlockMode::Ordinary, &mut first_capture,
            ).expect_err("foreign journal cannot become the initial publication identity");
            assert!(error.contains(stringify!($field)), "{error}");
            assert!(first_capture.is_empty(), "failed capture appends no partial ownership");
            core::mem::swap(&mut original.$field, &mut replacement.$field);
            let mut restored = Vec::new();
            original.append_world_publication_identities(
                &expected, mv::BlockMode::Ordinary, &mut restored,
            ).unwrap();
            assert_eq!(restored, captured, "the actual original owner remains accepted");
        )+};
    }
    check!(
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
    );
}

#[test]
fn publication_identities_require_the_original_common_block_mode() {
    let set = Set::default();
    let mut identities = Vec::new();
    {
        let block = set.block();
        assert!(
            block
                .append_world_publication_identities(&set, mv::BlockMode::Replace, &mut identities,)
                .is_err()
        );
        assert!(identities.is_empty());
        block
            .append_world_publication_identities(&set, mv::BlockMode::Ordinary, &mut identities)
            .unwrap();
    }
    let ordinary = identities;
    let mut replacement = Vec::new();
    let block = set.block_and_revert();
    assert!(
        block
            .append_world_publication_identities(&set, mv::BlockMode::Ordinary, &mut replacement,)
            .is_err()
    );
    assert!(replacement.is_empty());
    block
        .append_world_publication_identities(&set, mv::BlockMode::Replace, &mut replacement)
        .unwrap();
    assert_eq!(replacement.len(), 10);
    assert!(
        ordinary
            .iter()
            .zip(&replacement)
            .all(|(left, right)| left != right),
        "replacement mode cannot reuse an ordinary journal identity"
    );
}

fn log_instruction() -> InstructionBox {
    Log::new(Level::INFO, "world delta".to_owned()).into()
}

fn halt_blob() -> IvmBytecode {
    let mut program = ivm::ProgramMetadata::default().encode();
    program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    IvmBytecode::from_compiled(program)
}

fn invocation() -> ContractInvocation {
    let network = "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
        .parse()
        .expect("network fixture");
    ContractInvocation {
        contract_address: iroha_data_model::smart_contract::ContractAddress::derive(
            &network,
            &ALICE_ID,
            7,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )
        .expect("contract identity"),
        expected_code_hash: Hash::new(b"world-delta-contract"),
        entrypoint: "main".to_owned(),
        arguments: None,
    }
}

fn register_call(tx: &mut SetTransaction<'_>, id: &str, executable: Executable) {
    let action = SpecializedAction::new(
        executable,
        Repeats::Exactly(3),
        ALICE_ID.clone(),
        ExecuteTriggerEventFilter::new(),
    )
    .expect("valid by-call authority");
    assert!(
        tx.add_by_call_trigger(SpecializedTrigger::new(
            id.parse().expect("trigger id"),
            action,
        ))
        .expect("register by-call action")
    );
}

#[test]
fn borrowed_action_matches_owned_dto_for_all_executable_variants_and_flags() {
    let set = Set::default();
    let mut block = set.block();
    {
        let mut tx = block.transaction();
        for (id, executable) in [
            ("ivm", Executable::Ivm(halt_blob())),
            ("call", Executable::ContractCall(invocation())),
            (
                "instructions",
                Executable::Instructions(vec![log_instruction()].into()),
            ),
            (
                "batch",
                Executable::Batch(
                    vec![
                        ExecutableBatchItem::Instruction(log_instruction()),
                        ExecutableBatchItem::ContractCall(invocation()),
                    ]
                    .into(),
                ),
            ),
        ] {
            register_call(&mut tx, id, executable);
        }
        tx.apply();
    }
    for (_, action) in block.by_call_triggers.iter() {
        let expected = LoadedActionDto::from(action).encode();
        let expected_hash = hash_value(&LoadedActionDto::from(action)).unwrap();
        for flags in [0, norito::core::header_flags::COMPACT_LEN] {
            let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
            assert_eq!(BorrowedWorldAction::new(action).encode(), expected);
            assert_eq!(hash_world_action(action).unwrap(), expected_hash);
        }
    }
    assert_eq!(
        project(&block).changed_values(),
        13,
        "four actions/ids/active ids and one blob"
    );
}

#[test]
fn semantic_trigger_reader_rejects_changed_action_and_omitted_row() {
    let set = Set::default();
    let id: TriggerId = "captured".parse().expect("trigger id");
    let limits = LeafLimits {
        max_tables: 1,
        max_rows: 8,
        max_payload_bytes: 4 * 1024,
        max_ordered_table_bytes: 32 * 1024,
        max_streamed_value_bytes: 8 * 1024 * 1024,
    };
    {
        let mut block = set.block();
        let mut tx = block.transaction();
        register_call(
            &mut tx,
            "captured",
            Executable::Instructions(vec![log_instruction()].into()),
        );
        tx.apply();
        block.commit();
    }
    let before = {
        let pool = capture_budget();
        let mut checked = CheckedActions::capture(&set, action_source_work(limits), &pool)
            .expect("checked original action sources");
        let outcome = checked.encode(ActionTable::ByCall, limits);
        let current = checked.matches_current();
        drop(checked);
        assert!(current.expect("original action source identities"));
        outcome.expect("bounded trigger table")
    };
    assert_eq!(before.row_count(), 1);
    {
        let rows = set.by_call_triggers.view();
        assert!(matches!(
            CanonicalTableLeafSet::paired_semantic_table_from_rows(
                "triggers.by_call",
                "iroha:state:wrong-trigger-action:v1",
                limits,
                &capture_budget(),
                rows.iter(),
                BorrowedWorldAction::new,
            ),
            Err(LeafError::TypeMismatch("triggers.by_call"))
        ));
    }
    let original_proof = before
        .prove_lookup("triggers.by_call", &id)
        .expect("trigger inclusion proof");
    assert!(
        CanonicalTableLeafSet::verify_paired_lookup(
            "triggers.by_call",
            limits,
            &before.root(),
            &before.ordered_root(),
            &id,
            &original_proof,
        )
        .expect("valid scoped inclusion")
        .is_some()
    );

    {
        let mut block = set.block();
        let mut tx = block.transaction();
        tx.mod_repeats(&id, |count| Ok(count - 1))
            .expect("change action repeats");
        tx.apply();
        block.commit();
    }
    let changed = {
        let pool = capture_budget();
        let mut checked = CheckedActions::capture(&set, action_source_work(limits), &pool)
            .expect("checked original action sources");
        let outcome = checked.encode(ActionTable::ByCall, limits);
        let current = checked.matches_current();
        drop(checked);
        assert!(current.expect("original action source identities"));
        outcome.expect("bounded changed trigger table")
    };
    assert_ne!(before.root(), changed.root());
    let changed_proof = changed
        .prove_lookup("triggers.by_call", &id)
        .expect("changed trigger proof");
    assert!(matches!(
        CanonicalTableLeafSet::verify_paired_lookup(
            "triggers.by_call",
            limits,
            &before.root(),
            &changed.ordered_root(),
            &id,
            &changed_proof,
        ),
        Err(LeafError::RootMismatch)
    ));

    {
        let mut block = set.block();
        let mut tx = block.transaction();
        assert!(tx.remove(&id));
        tx.apply();
        block.commit();
    }
    let omitted = {
        let pool = capture_budget();
        let mut checked = CheckedActions::capture(&set, action_source_work(limits), &pool)
            .expect("checked original action sources");
        let outcome = checked.encode(ActionTable::ByCall, limits);
        let current = checked.matches_current();
        drop(checked);
        assert!(current.expect("original action source identities"));
        outcome.expect("bounded omitted trigger table")
    };
    assert_eq!(omitted.row_count(), 0);
    let omitted_proof = omitted
        .prove_lookup("triggers.by_call", &id)
        .expect("omitted trigger absence proof");
    assert!(matches!(
        CanonicalTableLeafSet::verify_paired_lookup(
            "triggers.by_call",
            limits,
            &before.root(),
            &omitted.ordered_root(),
            &id,
            &omitted_proof,
        ),
        Err(LeafError::RootMismatch)
    ));
}

#[test]
fn borrowed_contract_commits_only_bytecode_and_rejects_stale_derived_hash() {
    #[derive(Encode)]
    struct OriginalContractOnly {
        original_contract: IvmBytecode,
    }
    let blob = halt_blob();
    let entry = IvmBytecodeEntry {
        code_hash: ivm::contract_code_hash(blob.as_ref()),
        original_contract: blob,
        count: NonZeroU64::MIN,
    };
    assert_eq!(
        BorrowedWorldContract::from(&entry).encode(),
        OriginalContractOnly {
            original_contract: entry.original_contract.clone(),
        }
        .encode()
    );
    let original = hash_world_contract(&entry).unwrap();
    for flags in [0, norito::core::default_encode_flags()] {
        let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(hash_world_contract(&entry).unwrap(), original);
    }
    let different_count = IvmBytecodeEntry {
        count: NonZeroU64::new(2).unwrap(),
        ..entry.clone()
    };
    assert_eq!(hash_world_contract(&different_count).unwrap(), original);
    let wrong_code_hash = IvmBytecodeEntry {
        code_hash: Hash::new(b"substituted-code"),
        ..entry.clone()
    };
    assert!(hash_world_contract(&wrong_code_hash).is_err());
    let different_blob = IvmBytecode::from_compiled(vec![1, 2, 3]);
    let different_bytecode = IvmBytecodeEntry {
        code_hash: ivm::contract_code_hash(different_blob.as_ref()),
        original_contract: different_blob,
        ..entry
    };
    assert_ne!(hash_world_contract(&different_bytecode).unwrap(), original);
}

#[test]
fn trigger_contract_projection_checks_key_hash_and_derived_four_store_count() {
    let set = Set::default();
    let mut block = set.block();
    {
        let mut tx = block.transaction();
        let blob = halt_blob();
        let mut data_action = SpecializedAction::new(
            Executable::Ivm(blob.clone()),
            Repeats::Exactly(3),
            ALICE_ID.clone(),
            DataEventFilter::Any,
        )
        .expect("data action");
        data_action.metadata = global_data_trigger_scope_metadata_for_testing(&ALICE_ID);
        tx.add_data_trigger(SpecializedTrigger::new(
            "bound_data".parse().unwrap(),
            data_action,
        ))
        .expect("data trigger");
        let pipeline_filter = iroha_data_model::events::pipeline::BlockEventFilter {
            height: Some(NonZeroU64::new(5).unwrap()),
            status: Some(iroha_data_model::prelude::BlockStatus::Committed),
        }
        .into();
        tx.add_pipeline_trigger(SpecializedTrigger::new(
            "bound_pipeline".parse().unwrap(),
            SpecializedAction::new(
                Executable::Ivm(blob.clone()),
                Repeats::Exactly(3),
                ALICE_ID.clone(),
                pipeline_filter,
            )
            .expect("pipeline action"),
        ))
        .expect("pipeline trigger");
        tx.add_time_trigger(SpecializedTrigger::new(
            "bound_time".parse().unwrap(),
            SpecializedAction::new(
                Executable::Ivm(blob.clone()),
                Repeats::Exactly(3),
                ALICE_ID.clone(),
                TimeEventFilter(ExecutionTime::Schedule(Schedule::starting_at(
                    Duration::from_millis(5),
                ))),
            )
            .expect("time action"),
        ))
        .expect("time trigger");
        register_call(&mut tx, "bound_call", Executable::Ivm(blob));
        tx.apply();
    }
    let (key, original) = block
        .contracts
        .iter()
        .next()
        .map(|(key, entry)| (*key, entry.clone()))
        .expect("registered action has a contract");
    assert!(block.validate_world_contract_rows().is_ok());
    assert_eq!(original.count.get(), 4);
    let valid_delta = project(&block);
    block.contracts.get_mut(&key).unwrap().count = NonZeroU64::new(5).unwrap();
    assert!(block.validate_world_contract_rows().is_err());
    assert!(
        block
            .append_world_projection(&mut WorldDeltaBuilder::new())
            .is_err()
    );
    block.contracts.insert(key, original.clone());
    block.contracts.get_mut(&key).unwrap().code_hash = Hash::new(b"wrong code hash");
    assert!(block.validate_world_contract_rows().is_err());
    block.contracts.insert(key, original.clone());
    block.contracts.remove(key);
    assert!(
        block.validate_world_contract_rows().is_err(),
        "a referenced blob must exist"
    );
    let wrong_key = HashOf::new(&IvmBytecode::from_compiled(vec![9]));
    block.contracts.insert(wrong_key, original.clone());
    assert!(
        block.validate_world_contract_rows().is_err(),
        "the lookup key must bind bytecode"
    );
    block.contracts.remove(wrong_key);
    block.contracts.insert(key, original);
    assert_eq!(project(&block), valid_delta);
    block.commit();
    let captured = {
        let pool = capture_budget();
        let limits = LeafLimits {
            max_tables: 1,
            max_rows: 8,
            max_payload_bytes: 4 * 1024,
            max_ordered_table_bytes: 32 * 1024,
            max_streamed_value_bytes: 8 * 1024 * 1024,
        };
        let mut checked = CheckedContracts::capture(&set, contract_source_work(limits), &pool)
            .expect("checked original contract sources");
        let outcome = checked.encode(limits);
        let current = checked.matches_current();
        drop(checked);
        assert!(current.expect("original contract source identities"));
        outcome.expect("validated original contract bytecode has semantic table nodes")
    };
    assert_eq!(captured.row_count(), 1);
}

#[test]
fn frozen_trigger_world_projection_preserves_original_changes_and_noop_journals() {
    let set = Set::default();
    let mut block = set.block();
    let canceled: TriggerId = "frozen_canceled".parse().unwrap();
    {
        let mut tx = block.transaction();
        let blob = halt_blob();
        let mut data = SpecializedAction::new(
            Executable::Ivm(blob.clone()),
            Repeats::Exactly(3),
            ALICE_ID.clone(),
            DataEventFilter::Any,
        )
        .unwrap();
        data.metadata = global_data_trigger_scope_metadata_for_testing(&ALICE_ID);
        assert!(
            tx.add_data_trigger(SpecializedTrigger::new(
                "frozen_data".parse().unwrap(),
                data
            ))
            .unwrap()
        );
        let pipeline_filter = iroha_data_model::events::pipeline::BlockEventFilter {
            height: Some(NonZeroU64::new(5).unwrap()),
            status: Some(iroha_data_model::prelude::BlockStatus::Committed),
        }
        .into();
        assert!(
            tx.add_pipeline_trigger(SpecializedTrigger::new(
                "frozen_pipeline".parse().unwrap(),
                SpecializedAction::new(
                    Executable::Ivm(blob.clone()),
                    Repeats::Exactly(3),
                    ALICE_ID.clone(),
                    pipeline_filter,
                )
                .unwrap(),
            ))
            .unwrap()
        );
        assert!(
            tx.add_time_trigger(SpecializedTrigger::new(
                "frozen_time".parse().unwrap(),
                SpecializedAction::new(
                    Executable::Ivm(blob.clone()),
                    Repeats::Exactly(3),
                    ALICE_ID.clone(),
                    TimeEventFilter(ExecutionTime::Schedule(Schedule::starting_at(
                        Duration::from_millis(5),
                    ))),
                )
                .unwrap(),
            ))
            .unwrap()
        );
        register_call(&mut tx, "frozen_call", Executable::Ivm(blob.clone()));
        register_call(&mut tx, "frozen_canceled", Executable::Ivm(blob));
        assert!(tx.remove(&canceled));
        tx.apply();
    }
    let before = project(&block);
    assert_eq!(
        before.changed_values(),
        13,
        "four actions, ids, active ids and shared blob"
    );
    let contract_key = HashOf::new(&halt_blob());
    assert_eq!(block.contracts.get(&contract_key).unwrap().count.get(), 4);
    let original_contract = std::ptr::from_ref(block.contracts.get(&contract_key).unwrap());

    for frozen in [false, true] {
        if frozen {
            block.begin_freeze();
            block.finish_freeze();
        }
        assert_eq!(
            project(&block),
            before,
            "freeze retains the original semantic delta"
        );
        block.validate_world_contract_rows().unwrap();
        assert_eq!(
            std::ptr::from_ref(block.contracts.get(&contract_key).unwrap()),
            original_contract,
            "freeze retains the original validated contract row"
        );
        macro_rules! assert_canceled_touch {
            ($($field:ident),+ $(,)?) => {$(
                let touch = block.$field.touched_entries()
                    .find(|entry| entry.key == &canceled)
                    .expect("canceled registration retains its original journal row");
                assert!(touch.before.is_none() && touch.after.is_none(),
                    "absent-to-absent touch is retained through freeze: {}", stringify!($field));
            )+};
        }
        assert_canceled_touch!(by_call_triggers, ids, active_by_call_trigger_ids);
    }
}

#[test]
fn proved_ivm_trigger_registration_rejects_every_filter_without_mutation() {
    fn proved_executable() -> Executable {
        Executable::IvmProved(iroha_data_model::transaction::executable::IvmProved {
            bytecode: halt_blob(),
            overlay: Vec::<InstructionBox>::new().into(),
            events_commitment: Hash::new(b"trigger-events"),
            gas_policy_commitment: Hash::new(b"trigger-gas"),
        })
    }
    let set = Set::default();
    let mut block = set.block();
    let empty = project(&block);
    {
        let mut tx = block.transaction();
        let mut data = SpecializedAction::new(
            proved_executable(),
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            DataEventFilter::Any,
        )
        .expect("data action");
        data.metadata = global_data_trigger_scope_metadata_for_testing(&ALICE_ID);
        assert!(matches!(
            tx.add_data_trigger(SpecializedTrigger::new(
                "proved_data".parse().unwrap(),
                data,
            )),
            Err(Error::ProofBackedTriggerUnavailable)
        ));
        let pipeline_filter = iroha_data_model::events::pipeline::BlockEventFilter {
            height: Some(NonZeroU64::new(5).unwrap()),
            status: Some(iroha_data_model::prelude::BlockStatus::Committed),
        }
        .into();
        assert!(matches!(
            tx.add_pipeline_trigger(SpecializedTrigger::new(
                "proved_pipeline".parse().unwrap(),
                SpecializedAction::new(
                    proved_executable(),
                    Repeats::Exactly(1),
                    ALICE_ID.clone(),
                    pipeline_filter,
                )
                .expect("pipeline action"),
            )),
            Err(Error::ProofBackedTriggerUnavailable)
        ));
        assert!(matches!(
            tx.add_time_trigger(SpecializedTrigger::new(
                "proved_time".parse().unwrap(),
                SpecializedAction::new(
                    proved_executable(),
                    Repeats::Exactly(1),
                    ALICE_ID.clone(),
                    TimeEventFilter(ExecutionTime::Schedule(Schedule::starting_at(
                        Duration::from_millis(5),
                    ))),
                )
                .expect("time action"),
            )),
            Err(Error::ProofBackedTriggerUnavailable)
        ));
        assert!(matches!(
            tx.add_by_call_trigger(SpecializedTrigger::new(
                "proved_call".parse().unwrap(),
                SpecializedAction::new(
                    proved_executable(),
                    Repeats::Exactly(1),
                    ALICE_ID.clone(),
                    ExecuteTriggerEventFilter::new(),
                )
                .expect("by-call action"),
            )),
            Err(Error::ProofBackedTriggerUnavailable)
        ));
        tx.apply();
    }
    assert_eq!(project(&block), empty);
    assert!(block.contracts.iter().next().is_none());
}

#[test]
fn actual_trigger_rollback_and_canceled_registration_do_not_change_net_delta() {
    let set = Set::default();
    let mut block = set.block();
    let empty = project(&block);
    {
        let mut tx = block.transaction();
        register_call(&mut tx, "aborted", Executable::Ivm(halt_blob()));
        // Dropping the actual transaction removes action, ids, active ids and blob.
    }
    assert_eq!(project(&block), empty);
    {
        let mut tx = block.transaction();
        register_call(&mut tx, "canceled", Executable::Ivm(halt_blob()));
        assert!(tx.remove(&"canceled".parse().unwrap()));
        tx.apply();
    }
    assert!(block.by_call_triggers.touched_entries().next().is_some());
    assert!(block.contracts.touched_entries().next().is_some());
    assert_eq!(
        project(&block),
        empty,
        "applied absent-to-absent history is not a net change"
    );
    let mut legacy = Vec::new();
    block.append_merge_execution_write_set(&mut legacy);
    assert!(
        !legacy.is_empty(),
        "existing merge touch-history format remains unchanged"
    );
}

#[test]
fn actual_registration_order_and_shared_blob_refcount_history_are_canonical() {
    let set = Set::default();
    let mut first = set.block();
    {
        let mut tx = first.transaction();
        register_call(&mut tx, "a", Executable::Ivm(halt_blob()));
        register_call(&mut tx, "b", Executable::Ivm(halt_blob()));
        tx.apply();
    }
    let expected = project(&first);
    assert_eq!(
        expected.changed_values(),
        7,
        "two actions/ids/active ids and shared blob"
    );
    assert_eq!(first.contracts.iter().next().unwrap().1.count.get(), 2);
    drop(first);
    let mut second = set.block();
    {
        let mut tx = second.transaction();
        register_call(&mut tx, "temporary", Executable::Ivm(halt_blob()));
        assert!(tx.remove(&"temporary".parse().unwrap()));
        register_call(&mut tx, "b", Executable::Ivm(halt_blob()));
        register_call(&mut tx, "a", Executable::Ivm(halt_blob()));
        tx.apply();
    }
    assert_eq!(
        project(&second),
        expected,
        "temporary dedup entries do not alter final semantic delta"
    );
    assert_eq!(second.contracts.iter().next().unwrap().1.count.get(), 2);
}

#[test]
fn actual_repeat_enable_and_retry_mutations_are_bound_and_noop_access_is_not() {
    let set = Set::default();
    let id: TriggerId = "scheduled".parse().unwrap();
    {
        let mut block = set.block();
        let mut tx = block.transaction();
        let mut action = SpecializedAction::new(
            Executable::Instructions(vec![log_instruction()].into()),
            Repeats::Exactly(3),
            ALICE_ID.clone(),
            TimeEventFilter(ExecutionTime::Schedule(Schedule::starting_at(
                Duration::from_millis(5),
            ))),
        )
        .expect("time action");
        action.retry_policy = Some(TimeTriggerRetryPolicy {
            max_retries: NonZeroU32::new(3).unwrap(),
            retry_after_ms: NonZeroU64::new(500).unwrap(),
        });
        assert!(
            tx.add_time_trigger(SpecializedTrigger::new(id.clone(), action))
                .unwrap()
        );
        tx.apply();
        block.commit();
    }
    let mut block = set.block();
    let unchanged = project(&block);
    {
        let mut tx = block.transaction();
        tx.mod_repeats(&id, Ok).expect("unchanged repeats");
        tx.apply();
    }
    assert!(block.time_triggers.touched_entries().next().is_some());
    assert_eq!(project(&block), unchanged);
    {
        let mut tx = block.transaction();
        tx.mod_repeats(&id, |count| Ok(count - 1)).unwrap();
        tx.apply();
    }
    let repeated = project(&block);
    assert_eq!(repeated.changed_values(), 1);
    assert_ne!(repeated, unchanged);
    {
        let mut tx = block.transaction();
        assert!(tx.set_time_trigger_retry_state(
            &id,
            Some(TimeTriggerRetryState {
                retries_used: 1,
                next_retry_at_ms: 42
            })
        ));
        tx.apply();
    }
    let retry = project(&block);
    assert_ne!(retry, repeated);
    {
        let mut tx = block.transaction();
        tx.inspect_by_id_mut(&id, |action| {
            action.metadata_mut().insert(
                TRIGGER_ENABLED_METADATA_KEY.parse().unwrap(),
                Json::from(false),
            );
        })
        .expect("registered action");
        tx.apply();
    }
    assert_ne!(project(&block), retry);
    assert_eq!(
        project(&block).changed_values(),
        2,
        "action and exact active-id removal"
    );
    let action = block.time_triggers.get(&id).unwrap();
    assert_eq!(
        BorrowedWorldAction::new(action).encode(),
        LoadedActionDto::from(action).encode()
    );
}

#[test]
fn borrowed_action_binds_authority_filter_metadata_and_retry_fields() {
    let set = Set::default();
    let mut block = set.block();
    {
        let mut tx = block.transaction();
        register_call(
            &mut tx,
            "identity",
            Executable::Instructions(vec![log_instruction()].into()),
        );
        tx.apply();
    }
    let action = block
        .by_call_triggers
        .get(&"identity".parse().unwrap())
        .unwrap();
    let original = hash_world_action(action).unwrap();
    for changed in [
        LoadedAction {
            authority: BOB_ID.clone(),
            ..action.clone()
        },
        LoadedAction {
            filter: action.filter.clone().under_authority(BOB_ID.clone()),
            ..action.clone()
        },
        LoadedAction {
            retry_state: Some(TimeTriggerRetryState {
                retries_used: 2,
                next_retry_at_ms: 99,
            }),
            ..action.clone()
        },
        LoadedAction {
            retry_policy: Some(TimeTriggerRetryPolicy {
                max_retries: NonZeroU32::MIN,
                retry_after_ms: NonZeroU64::MIN,
            }),
            ..action.clone()
        },
        LoadedAction {
            metadata: {
                let mut m = Metadata::default();
                m.insert("bound".parse().unwrap(), Json::from(1_u64));
                m
            },
            ..action.clone()
        },
    ] {
        assert_ne!(hash_world_action(&changed).unwrap(), original);
    }
}

#[test]
fn net_delta_hook_mentions_every_trigger_block_store() {
    let source = include_str!("set.rs");
    let declaration = source
        .split("pub struct SetBlockFields<'set> {")
        .nth(1)
        .unwrap()
        .split("\n}")
        .next()
        .unwrap();
    let method = source
        .split("pub(crate) fn append_world_projection")
        .nth(1)
        .unwrap()
        .split("\n    }\n}")
        .next()
        .unwrap();
    let fields: Vec<_> = declaration
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            (!line.starts_with("///"))
                .then(|| line.split_once(':'))
                .flatten()
                .map(|(name, _)| name)
        })
        .collect();
    assert_eq!(
        fields.len(),
        10,
        "review new trigger-store owners explicitly"
    );
    for field in fields {
        assert!(
            method.contains(&format!("&self.{field},")),
            "missing trigger store {field}"
        );
    }
}

fn capture_budget() -> iroha_allocation::AllocationBudget {
    iroha_allocation::AllocationBudget::new(64 * 1024 * 1024)
}
