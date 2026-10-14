//! Native original-source admission, scoped roots and refusal preservation.

use super::*;
use crate::{
    state::{
        deserialize::{musubi_source_read::ReadFailure, musubi_source_work},
        publication::{
            RetainedPackageReadError,
            musubi_materializer_test_support::{fixture, pending, staged_block, start},
        },
    },
    test_allocations::allocations_during,
};
use iroha_allocation::AllocationBudget;

const WORK: usize = 64 * 1024 * 1024;

fn limits() -> [LeafLimits; 3] {
    [LeafLimits {
        max_tables: 1,
        max_rows: 8,
        max_payload_bytes: 4096,
        max_ordered_table_bytes: 64 * 1024,
        max_streamed_value_bytes: 64 * 1024,
    }; 3]
}

fn prepare(block: &mut StateBlock<'_>) {
    let budget = block.state_ref.ivm_execution_budget();
    start(block, &budget);
    for _ in 0..256 {
        match block.advance_configured_original_musubi_validation() {
            Ok(()) => return,
            Err(ReadFailure::Source(RetainedMusubiGroupReadError::Field {
                original: RetainedPackageReadError::Work { .. },
                ..
            })) => {}
            Err(error) => panic!("actual original semantic validation failed: {error:?}"),
        }
    }
    panic!("configured finite quanta did not finish the populated original fixture");
}

fn observed(block: &mut StateBlock<'_>) -> [RetainedSemanticProgress; 3] {
    block
        .with_validated_original_musubi_materializers(WORK, |_, _, retained| {
            retained
                .as_ref()
                .expect("same retained original")
                .progress()
        })
        .unwrap()
}

#[test]
fn all_three_cardinalities_and_policy_are_admitted_before_any_tree_backing() {
    let budget = AllocationBudget::new(1024 * 1024);
    let scope = budget.try_owned_refund_scope().unwrap();
    let mut counts = [0; 14];
    for position in POSITIONS {
        counts[position] = 1;
    }
    let baseline = budget.reserved_bytes();
    assert_eq!(
        allocations_during(|| {
            assert!(matches!(
                OriginalMusubiMaterializers::new(limits(), 2, &scope, counts),
                Err(FrozenMusubiError::Encoding(RetainedSemanticError::Table(
                    LeafError::RowLimit
                )))
            ));
            for index in 0..3 {
                let mut short = limits();
                short[index].max_rows = 0;
                assert!(matches!(
                    OriginalMusubiMaterializers::new(short, 3, &scope, counts),
                    Err(FrozenMusubiError::Encoding(RetainedSemanticError::Table(
                        LeafError::RowLimit
                    )))
                ));
                short = limits();
                short[index].max_tables = 0;
                assert!(matches!(
                    OriginalMusubiMaterializers::new(short, 3, &scope, counts),
                    Err(FrozenMusubiError::Encoding(RetainedSemanticError::Table(
                        LeafError::TableLimit
                    )))
                ));
            }
        }),
        0
    );
    assert_eq!(budget.reserved_bytes(), baseline);
    let materializers = OriginalMusubiMaterializers::new(limits(), 3, &scope, counts).unwrap();
    assert!(materializers.matches_policy(limits(), 3));
    for table in TABLES {
        assert!(materializers.snapshot(table).is_none());
    }
    assert!(
        materializers
            .progress()
            .iter()
            .all(|table| table.work == 0 && table.rows == 0)
    );
}

#[test]
fn semantic_gate_never_treats_unvalidated_original_maps_as_empty_tables() {
    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    start(&mut block, &state.ivm_execution_budget());
    block.advance_original_musubi_group_read(WORK).unwrap();
    block
        .advance_original_musubi_group_predecessor_read(WORK)
        .unwrap();
    assert!(matches!(
        with_original_musubi_tables(&mut block, limits(), 24, WORK, WORK, |_| panic!(
            "unvalidated rows cannot reach consumer"
        )),
        Err(FrozenMusubiError::Source(
            RetainedMusubiGroupReadError::Incomplete
        ))
    ));
}

#[test]
fn actual_frozen_three_table_roots_match_independent_borrowed_source_in_both_modes() {
    let seeded = crate::state::deserialize::seeded_musubi_publication_world_for_testing();
    let oracle_budget = AllocationBudget::new(8 * 1024 * 1024);
    let view = seeded.view();
    let source =
        musubi_source_work::validate(&view, &oracle_budget, super::super::musubi_test_limits())
            .unwrap();
    let expected = TABLES.map(|table| source.capture_table(table, limits()[0]).unwrap());
    for replacement in [false, true] {
        let (state, proposal) = fixture();
        if replacement {
            staged_block(&state, proposal.header(), false, true)
                .commit()
                .unwrap();
        }
        let mut block = pending(&state, proposal.header(), replacement);
        prepare(&mut block);
        with_original_musubi_tables(&mut block, limits(), 24, WORK, WORK, |tables| {
            for (actual, expected) in tables.into_iter().zip(&expected) {
                assert_eq!(actual.table_id(), expected.table_id());
                assert_eq!(actual.row_count(), 1);
                assert_eq!(actual.root(), expected.root());
                assert_eq!(actual.lookup_root(), expected.lookup_root());
                assert_eq!(actual.ordered_root(), expected.ordered_root());
            }
        })
        .unwrap();
        let complete = observed(&mut block);
        let structural = block.original_musubi_group_read_progress().unwrap().work;
        let encoding = complete.iter().map(|progress| progress.work).sum();
        with_original_musubi_tables(&mut block, limits(), 24, structural, encoding, |tables| {
            assert_eq!(tables[0].root(), expected[0].root());
        })
        .unwrap();
        assert_eq!(observed(&mut block), complete);
        assert_eq!(
            block.original_musubi_group_read_progress().unwrap().work,
            structural
        );
    }
}

#[test]
fn original_pool_refusal_preserves_materializer_owner_and_policy_until_retry() {
    let (state, proposal) = fixture();
    let mut block = pending(&state, proposal.header(), false);
    prepare(&mut block);
    let budget = state.ivm_execution_budget();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let refusal =
        with_original_musubi_tables(&mut block, limits(), 24, WORK, WORK, |_| ()).unwrap_err();
    assert!(
        matches!(
            refusal,
            FrozenMusubiError::Encoding(RetainedSemanticError::Table(
                LeafError::Admission(_) | LeafError::OrderedRange(_)
            ))
        ),
        "exact original-pool refusal expected: {refusal:?}"
    );
    let before = observed(&mut block);
    assert!(before.iter().any(|table| table.work > 0));
    let reserved = budget.reserved_bytes();
    let mut changed = limits();
    changed[2].max_rows += 1;
    assert!(matches!(
        with_original_musubi_tables(&mut block, changed, 24, WORK, WORK, |_| ()),
        Err(FrozenMusubiError::Changed)
    ));
    assert_eq!(observed(&mut block), before);
    assert_eq!(budget.reserved_bytes(), reserved);
    let spent: usize = before.iter().map(|progress| progress.work).sum();
    assert!(matches!(
        with_original_musubi_tables(&mut block, limits(), 24, WORK, spent, |_| ()),
        Err(FrozenMusubiError::Encoding(
            RetainedSemanticError::Work { .. }
        ))
    ));
    assert_eq!(observed(&mut block), before);
    drop(occupied);
    with_original_musubi_tables(&mut block, limits(), 24, WORK, WORK, |tables| {
        assert!(tables.iter().all(|table| table.row_count() == 1));
    })
    .unwrap();
    assert!(observed(&mut block).iter().all(|table| table.complete));
}
