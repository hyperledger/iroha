//! Real original State ownership, complete catalog dispatch and canonical encoder parity.

use super::*;
use crate::state::authority_registry::inventory_test_support;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State, World, block_field::BlockField,
        verifying_key_index_validation::test_support as verifier_fixture,
    },
};
use iroha_data_model::block::BlockHeader;
use iroha_model_base::state_path::StatePath;
use mv::{BlockRetirement as _, storage::StorageReadOnly};
use std::num::NonZeroU64;

fn new_state() -> State {
    State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}
fn header() -> BlockHeader {
    BlockHeader::new(NonZeroU64::MIN, None, None, 1, 0)
}
fn limits() -> LeafLimits {
    LeafLimits {
        max_tables: 1,
        max_rows: 8,
        max_payload_bytes: 65536,
        max_ordered_table_bytes: 131072,
        max_streamed_value_bytes: 131072,
    }
}
fn path(value: &str) -> StatePath {
    value.parse().unwrap()
}
fn freeze_world(block: &mut StateBlock<'_>) {
    block.world.begin_freeze();
    block.world.finish_freeze();
    block.world.retire_frozen_cleanup();
}
fn capture(block: &StateBlock<'_>, table: &str) -> CanonicalTablePairedSnapshot {
    capture_original_table_once(block, table, limits(), 100_000)
        .unwrap()
        .unwrap()
}
fn assert_equal(actual: &CanonicalTablePairedSnapshot, expected: &CanonicalTablePairedSnapshot) {
    assert_eq!(actual.table_id(), expected.table_id());
    assert_eq!(actual.row_count(), expected.row_count());
    assert_eq!(actual.root(), expected.root());
    assert_eq!(actual.lookup_root(), expected.lookup_root());
    assert_eq!(actual.ordered_root(), expected.ordered_root());
}
fn committed(state: &State, table: &str) -> CanonicalTablePairedSnapshot {
    let owner = TABLE_MATERIALIZERS
        .iter()
        .find(|owner| owner.table_ids().any(|id| id == table))
        .unwrap();
    let (TableMaterializer::Native { capture, .. } | TableMaterializer::Single { capture, .. }) =
        owner
    else {
        panic!("test requested a singleton encoder")
    };
    capture(state, limits()).unwrap().unwrap()
}

#[test]
fn every_generated_raw_adapter_matches_its_declared_committed_encoder() {
    let state = new_state();
    let mut block = state.block(header());
    freeze_world(&mut block);
    assert_eq!(
        require_exact_table_materializers(STATE_FIELDS, TABLE_MATERIALIZERS),
        Ok(inventory_test_support::canonical_table_ids().len())
    );
    let mut raw_count = 0;
    let mut raw_ids = std::collections::BTreeSet::new();
    for owner in TABLE_MATERIALIZERS {
        let TableMaterializer::Native {
            id, capture: live, ..
        } = owner
        else {
            continue;
        };
        raw_count += 1;
        assert!(
            raw_ids.insert((*id).to_owned()),
            "duplicate raw adapter {id}"
        );
        let frozen = capture(&block, id);
        let control = live(&state, limits()).unwrap().unwrap();
        assert_equal(&frozen, &control);
        assert_eq!(frozen.table_id(), *id);
        // Fresh State initializes actual SNS records; even this baseline must
        // preserve populated raw rows rather than replacing them with emptiness.
        assert_eq!(
            frozen.row_count(),
            if *id == "world.smart_contract_state" {
                3
            } else {
                0
            }
        );
    }
    let expected_raw = inventory_test_support::raw_native_table_ids();
    assert_eq!(raw_count, expected_raw.len());
    assert_eq!(raw_ids, expected_raw);
}

#[test]
fn each_missing_checked_semantic_or_membership_adapter_names_its_exact_output() {
    let state = new_state();
    let mut block = state.block(header());
    freeze_world(&mut block);
    let budget = state.ivm_execution_budget();
    budget.set_limit_bytes(0);
    let mut missing = Vec::new();
    for owner in TABLE_MATERIALIZERS {
        for table in owner.table_ids() {
            if matches!(owner, TableMaterializer::Native { .. })
                || matches!(
                    table,
                    "world.verifying_keys"
                        | "world.proofs"
                        | "world.governance_proposals"
                        | "world.contract_alias_bindings"
                        | "world.domains"
                        | "world.accounts"
                        | "world.account_aliases"
                        | "world.contract_subject_bindings"
                        | "world.asset_definitions"
                        | "world.assets"
                        | "world.asset_escrows"
                        | "world.repo_agreements"
                        | "world.nfts"
                        | "world.rwas"
                        | "world.account_rekey_records"
                        | "triggers.contracts"
                        | "triggers.data"
                        | "triggers.pipeline"
                        | "triggers.time"
                        | "triggers.by_call"
                )
            {
                continue;
            }
            let error = capture_original_table_once(&block, table, limits(), 0)
                .err()
                .unwrap();
            if matches!(owner, TableMaterializer::TransactionMembership) {
                assert_eq!(error, Failure::MembershipGroupRequired.into());
                assert_eq!(error.missing_adapter(), None);
                assert!(matches!(
                    table,
                    "state.transactions.current" | "state.transactions.rollback"
                ));
                continue;
            }
            assert_eq!(error.missing_adapter(), Some(table));
            assert_eq!(error, Failure::MissingAdapter(table).into());
            assert!(error.to_string().ends_with(table));
            missing.push(table);
        }
    }
    assert_eq!(missing.len(), 3);
    assert!(!missing.contains(&"triggers.contracts"));
    assert!(!missing.contains(&"world.account_rekey_records"));
    assert!(!missing.contains(&"world.nfts"));
    assert!(!missing.contains(&"world.rwas"));
    assert!(!missing.contains(&"world.asset_escrows"));
    assert!(!missing.contains(&"world.repo_agreements"));
    assert!(!missing.contains(&"world.assets"));
    assert!(!missing.contains(&"world.asset_definitions"));
    assert!(!missing.contains(&"world.contract_alias_bindings"));
    assert!(!missing.contains(&"world.governance_proposals"));
    assert!(!missing.contains(&"world.domains"));
    assert!(!missing.contains(&"world.accounts"));
    assert!(!missing.contains(&"world.account_aliases"));
    assert!(!missing.contains(&"world.contract_subject_bindings"));
    assert!(!missing.contains(&"triggers.data"));
    assert!(!missing.contains(&"triggers.pipeline"));
    assert!(!missing.contains(&"triggers.time"));
    assert!(!missing.contains(&"triggers.by_call"));
    assert!(missing.contains(&"world.musubi_archive_availability"));
    assert!(!missing.contains(&"state.transactions.current"));
    assert!(!missing.contains(&"state.transactions.rollback"));
    for unknown in [
        "",
        "world",
        "world.parameters",
        "world.verifying_keys_by_circuit",
    ] {
        let error = capture_original_table_once(&block, unknown, limits(), 0)
            .err()
            .unwrap();
        assert_eq!(error, Failure::UnknownTable.into());
        assert_eq!(error.missing_adapter(), None);
    }
}

#[test]
fn executing_partial_foreign_and_terminally_released_sources_never_encode() {
    let state = new_state();
    let foreign = new_state();
    let mut block = state.block(header());
    let budget = state.ivm_execution_budget();
    let original_limit = budget.limit_bytes();
    budget.set_limit_bytes(0);
    assert!(
        capture_original_table_once(&block, "world.smart_contract_state", limits(), 0)
            .unwrap()
            .is_none()
    );
    block.world.smart_contract_state.begin_freeze();
    block.world.smart_contract_state.finish_freeze();
    assert!(
        capture_original_table_once(&block, "world.smart_contract_state", limits(), 0)
            .unwrap()
            .is_none()
    );
    drop(block);
    budget.set_limit_bytes(original_limit);
    let mut block = state.block(header());
    // Equal native rows and a real independently funded field cannot adopt the
    // original State's identity or become a source for its encoding pool.
    block.world.smart_contract_state.release_writers();
    block.world.smart_contract_state = BlockField::new(foreign.world.smart_contract_state.block());
    freeze_world(&mut block);
    budget.set_limit_bytes(0);
    assert!(
        capture_original_table_once(&block, "world.smart_contract_state", limits(), 0)
            .unwrap()
            .is_none()
    );
    block.world.smart_contract_state.release_writers();
    assert!(
        capture_original_table_once(&block, "world.smart_contract_state", limits(), 0)
            .unwrap()
            .is_none()
    );
}

#[test]
fn original_pool_refusal_retry_and_final_drop_preserve_same_private_bytes() {
    let _retirement_pin = crossbeam_epoch::pin();
    let state = new_state();
    let budget = state.ivm_execution_budget();
    let original_limit = budget.limit_bytes();
    let key = path("frozen/catalog");
    let mut block = state.block(header());
    block
        .world
        .smart_contract_state
        .insert(key.clone(), vec![7; 32]);
    let identity = block.world.smart_contract_state.publication_identity();
    let pointer = block.world.smart_contract_state.get(&key).unwrap().as_ptr();
    freeze_world(&mut block);
    let baseline = budget.reserved_bytes();
    budget.set_limit_bytes(0);
    let error = capture_original_table_once(&block, "world.smart_contract_state", limits(), 0)
        .err()
        .unwrap();
    assert!(matches!(
        &error.0,
        Failure::Leaf(LeafError::Admission(_) | LeafError::OrderedRange(_))
    ));
    assert_eq!(error.missing_adapter(), None);
    assert_eq!(budget.reserved_bytes(), baseline);
    budget.set_limit_bytes(original_limit);
    for (small, expected) in [
        (
            LeafLimits {
                max_rows: 0,
                ..limits()
            },
            LeafError::RowLimit,
        ),
        (
            LeafLimits {
                max_payload_bytes: 0,
                ..limits()
            },
            LeafError::PayloadLimit,
        ),
    ] {
        let error = capture_original_table_once(&block, "world.smart_contract_state", small, 0)
            .err()
            .unwrap();
        assert_eq!(error, Failure::Leaf(expected).into());
        assert_eq!(budget.reserved_bytes(), baseline);
    }
    let snapshot = capture(&block, "world.smart_contract_state");
    let retained = budget.reserved_bytes();
    assert!(retained > baseline);
    let before = committed(&state, "world.smart_contract_state");
    assert_ne!(snapshot.root(), before.root());
    drop(before);
    assert_eq!(budget.reserved_bytes(), retained);
    assert_eq!(
        block.world.smart_contract_state.publication_identity(),
        identity
    );
    assert_eq!(
        block.world.smart_contract_state.get(&key).unwrap().as_ptr(),
        pointer
    );
    drop(snapshot);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn later_equal_or_changed_target_publications_cannot_refresh_original_rows() {
    let state = new_state();
    let key = path("frozen/target");
    let mut block = state.block(header());
    block
        .world
        .smart_contract_state
        .insert(key.clone(), vec![2]);
    freeze_world(&mut block);
    let identity = block.world.smart_contract_state.publication_identity();
    let original = capture(&block, "world.smart_contract_state");
    for value in [vec![2], vec![3]] {
        let mut target = state.world.smart_contract_state.block();
        target.insert(key.clone(), value);
        target.commit();
        let same_source = capture(&block, "world.smart_contract_state");
        assert_equal(&same_source, &original);
        assert_eq!(
            block.world.smart_contract_state.publication_identity(),
            identity
        );
    }
    let changed = committed(&state, "world.smart_contract_state");
    assert_ne!(changed.root(), original.root());
}

#[test]
fn real_replacement_keeps_rewound_rows_deletion_and_absent_undo() {
    let state = new_state();
    let changed = path("frozen/changed");
    let removed = path("frozen/removed");
    let absent = path("frozen/absent");
    {
        let mut baseline = state.world.smart_contract_state.block();
        baseline.insert(changed.clone(), vec![1]);
        baseline.insert(removed.clone(), vec![1]);
        baseline.commit();
    }
    {
        let mut tip = state.world.smart_contract_state.block();
        tip.insert(changed.clone(), vec![2]);
        tip.commit();
    }
    let mut block = state.block_and_revert(header());
    assert_eq!(
        block.world.smart_contract_state.get(&changed),
        Some(&vec![1])
    );
    block.world.smart_contract_state.remove(removed.clone());
    block.world.smart_contract_state.remove(absent.clone());
    freeze_world(&mut block);
    let rows = block.world.smart_contract_state.frozen_images().unwrap();
    assert_eq!(rows.mode(), mv::BlockMode::Replace);
    assert_eq!(
        rows.undo_entries()
            .find(|(key, _)| *key == &removed)
            .unwrap()
            .1,
        &Some(vec![1])
    );
    assert_eq!(
        rows.undo_entries()
            .find(|(key, _)| *key == &absent)
            .unwrap()
            .1,
        &None
    );
    let original = capture(&block, "world.smart_contract_state");
    let expected = new_state();
    let mut target = expected.world.smart_contract_state.block();
    target.insert(changed, vec![1]);
    target.commit();
    assert_equal(
        &original,
        &committed(&expected, "world.smart_contract_state"),
    );
    assert_ne!(
        original.root(),
        committed(&state, "world.smart_contract_state").root()
    );
}

#[test]
fn catalog_verifier_dispatch_preserves_bounded_structural_validation() {
    for corrupt in [false, true] {
        let state = State::new_for_testing(
            *verifier_fixture::world(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut block = state.block(header());
        if corrupt {
            block
                .world
                .verifying_keys_by_circuit
                .remove(("circuit".into(), 1));
        }
        freeze_world(&mut block);
        let limited = capture_original_table_once(&block, "world.verifying_keys", limits(), 0)
            .err()
            .unwrap();
        assert!(matches!(
            limited.0,
            Failure::Leaf(LeafError::GroupedOwnership(_))
        ));
        let result = capture_original_table_once(&block, "world.verifying_keys", limits(), 100_000);
        if corrupt {
            assert!(matches!(
                result,
                Err(FrozenTableCaptureError(Failure::Leaf(
                    LeafError::GroupedOwnership(_)
                )))
            ));
        } else {
            assert_equal(
                &result.unwrap().unwrap(),
                &committed(&state, "world.verifying_keys"),
            );
        }
    }
}
