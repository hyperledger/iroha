//! Real validated availability/resolver/directory producers share retained capture.

use super::super::super::{SourceWorkLimits, validate};
use super::*;
use crate::{
    state::deserialize::decode_tests::seeded_musubi_publication_snapshot,
    test_allocations::allocations_during,
};
use iroha_data_model::musubi::source_work::SourceGeometryLimits;

fn work() -> SourceWorkLimits {
    SourceWorkLimits {
        geometry: SourceGeometryLimits {
            elements: 1_000_000,
            variable_bytes: 1_000_000,
        },
        table_pass_rows: 1_000_000,
        lookup_index_entries: 1_000_000,
        model_operations: 1_000_000,
        signature_checks: 1_000_000,
    }
}
fn leaves() -> LeafLimits {
    LeafLimits {
        max_tables: 1,
        max_rows: 1,
        max_payload_bytes: 4096,
        max_ordered_table_bytes: 64 * 1024,
        max_streamed_value_bytes: 64 * 1024,
    }
}

#[test]
fn actual_three_validated_semantic_producers_retry_in_the_original_pool() {
    let (world, _, _, _) = seeded_musubi_publication_snapshot();
    let view = world.view();
    let budget = AllocationBudget::new(8 * 1024 * 1024);
    let source = validate(&view, &budget, work()).unwrap();
    let scope = budget.try_owned_refund_scope().unwrap();
    let baseline = budget.reserved_bytes();
    macro_rules! check {
        ($table:expr, $retain:ident) => {{
            let expected = source.capture_table($table, leaves()).unwrap();
            let expected_roots = (expected.root(), expected.lookup_root(), expected.ordered_root());
            drop(expected);
            let mut original = source.$retain(leaves(), &scope, usize::MAX).unwrap();
            let occupied = budget.try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes()).unwrap();
            assert!(matches!(original.advance(usize::MAX), Err(RetainedSemanticError::Table(LeafError::Admission(_)))));
            assert!(!original.progress().complete);
            let work = original.progress().work;
            let attempts = allocations_during(|| {
                assert!(matches!(original.advance(work), Err(RetainedSemanticError::Work { used, .. }) if used == work));
            });
            assert_eq!(attempts, 0);
            assert_eq!(original.progress().work, work);
            assert!(original.snapshot().is_none());
            drop(occupied);
            let progress = original.advance(usize::MAX).unwrap();
            assert!(progress.complete);
            assert_eq!(progress.rows, 1);
            let actual = original.snapshot().unwrap();
            assert_eq!(actual.table_id(), $table.id());
            assert_eq!((actual.root(), actual.lookup_root(), actual.ordered_root()), expected_roots);
            let reserved = budget.reserved_bytes();
            let attempts = allocations_during(|| { original.advance(progress.work).unwrap(); });
            assert_eq!(attempts, 0);
            assert_eq!(original.progress(), progress);
            assert_eq!(budget.reserved_bytes(), reserved);
            drop(original);
            assert_eq!(budget.reserved_bytes(), baseline);
        }};
    }
    check!(
        MusubiSemanticTable::Availability,
        retain_availability_capture
    );
    check!(MusubiSemanticTable::Resolver, retain_resolver_capture);
    check!(MusubiSemanticTable::Directory, retain_directory_capture);
    drop(scope);
    drop(source);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn actual_retained_semantic_source_remains_the_original_snapshot_after_new_commit() {
    let (world, release, archive, selector) = seeded_musubi_publication_snapshot();
    let view = world.view();
    let budget = AllocationBudget::new(8 * 1024 * 1024);
    let source = validate(&view, &budget, work()).unwrap();
    let scope = budget.try_owned_refund_scope().unwrap();
    let mut original = source
        .retain_availability_capture(leaves(), &scope, usize::MAX)
        .unwrap();
    original.advance(usize::MAX).unwrap();
    let root = original.snapshot().unwrap().root();
    let next_revision = world
        .musubi_resolver_index_revision
        .view()
        .get()
        .get()
        .checked_add(1)
        .unwrap();
    let mut block = world.block();
    let availability = block.musubi_archive_availability.get_mut(&archive).unwrap();
    availability.index_revision = next_revision;
    availability.finalized_block_hash[0] ^= 1;
    let availability = *availability;
    let resolver = block.musubi_resolver_index.get_mut(&release).unwrap();
    resolver.index_revision = next_revision;
    resolver.selection.storage = availability;
    block
        .musubi_public_directory
        .get_mut(&selector)
        .unwrap()
        .index_revision = next_revision;
    *block.musubi_resolver_index_revision.get_mut() =
        MusubiResolverIndexRevisionV1::new(next_revision).unwrap();
    block.commit();
    // This scoped diagnostic authenticates its borrowed snapshot, not the newer
    // State publication. It neither reacquires rows nor claims current authority.
    let progress = original.progress();
    let attempts = allocations_during(|| {
        original.advance(progress.work).unwrap();
    });
    assert_eq!(attempts, 0);
    assert_eq!(original.snapshot().unwrap().root(), root);
    let changed_view = world.view();
    let changed = validate(&changed_view, &budget, work()).unwrap();
    let newer = changed
        .capture_table(MusubiSemanticTable::Availability, leaves())
        .unwrap();
    assert_ne!(newer.root(), root);
    assert_eq!(original.progress(), progress);
    drop(newer);
    drop(changed);
    drop(original);
    drop(scope);
    drop(source);
    assert_eq!(budget.reserved_bytes(), 0);
}
