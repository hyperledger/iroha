//! Original-borrow projection and real validation-refusal controls.

use super::super::{SourceValidationError, SourceWorkLimits, validate};
use super::*;
use crate::state::deserialize::decode_tests::seeded_musubi_publication_snapshot;
use iroha_data_model::musubi::source_work::SourceGeometryLimits;

fn allowance() -> SourceWorkLimits {
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

#[test]
fn observation_preserves_original_pool_and_exact_borrowed_keys() {
    let (world, _, _, _) = seeded_musubi_publication_snapshot();
    let view = world.view();
    let budget = AllocationBudget::new(1_000_000);
    let source = validate(&view, &budget, allowance()).unwrap();
    assert!(std::ptr::eq(source.execution_budget(), &raw const budget));
    for ((key, authority), (original, row)) in source
        .availability_rows()
        .zip(view.musubi_archive_availability().iter())
    {
        assert!(std::ptr::eq(key, original));
        assert_eq!(authority, MusubiAvailabilityAuthorityV1::from_record(row));
    }
    for ((key, authority), (original, row)) in source
        .resolver_rows()
        .zip(view.musubi_resolver_index().iter())
    {
        assert!(std::ptr::eq(key, original));
        assert_eq!(authority, MusubiResolverAuthorityV1::from_record(row));
    }
    for ((key, authority), (original, row)) in source
        .directory_rows()
        .zip(view.musubi_public_directory().iter())
    {
        assert!(std::ptr::eq(key, original));
        assert_eq!(authority, MusubiDirectoryAuthorityV1::from_record(row));
    }
    assert_eq!(source.availability_rows().count(), 1);
    assert_eq!(source.resolver_rows().count(), 1);
    assert_eq!(source.directory_rows().count(), 1);
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "completed scratch is not a retained reservation"
    );
}

#[test]
fn observation_is_not_issued_on_original_pool_refusal_or_corrupt_projection() {
    let (world, _, _, _) = seeded_musubi_publication_snapshot();
    let budget = AllocationBudget::new(0);
    let view = world.view();
    assert!(matches!(
        validate(&view, &budget, allowance()),
        Err(SourceValidationError::Attempt(
            crate::execution_attempt::ExecutionAttemptError::Deferred(_)
        ))
    ));
    drop(view);
    let (key, mut row) = world
        .musubi_resolver_index
        .view()
        .iter()
        .next()
        .map(|(key, row)| (key.clone(), row.clone()))
        .unwrap();
    row.index_revision = 0;
    let mut block = world.musubi_resolver_index.block();
    block.insert(key, row);
    block.commit();
    let view = world.view();
    let budget = AllocationBudget::new(1_000_000);
    assert!(matches!(
        validate(&view, &budget, allowance()),
        Err(SourceValidationError::Attempt(
            crate::execution_attempt::ExecutionAttemptError::Rejected(_)
        ))
    ));
}

#[test]
fn observation_keeps_its_original_storage_snapshot_after_a_new_table_publication() {
    let (world, _, _, _) = seeded_musubi_publication_snapshot();
    let view = world.view();
    let budget = AllocationBudget::new(1_000_000);
    let source = validate(&view, &budget, allowance()).unwrap();
    let (_, original) = source.resolver_rows().next().unwrap();
    let (key, mut row) = view
        .musubi_resolver_index()
        .iter()
        .next()
        .map(|(key, row)| (key.clone(), row.clone()))
        .unwrap();
    row.index_revision = 0;
    let mut update = world.musubi_resolver_index.block();
    update.insert(key, row);
    update.commit();
    assert_eq!(source.resolver_rows().next().unwrap().1, original);
    let changed = world.view();
    assert!(validate(&changed, &budget, allowance()).is_err());
    assert_eq!(source.resolver_rows().count(), 1);
}

#[test]
fn supported_observation_carriers_are_the_sealed_native_cut_types() {
    fn require_native<W: MusubiObservationCut>() {}
    require_native::<WorldView<'_>>();
    require_native::<WorldBlock<'_>>();
    require_native::<WorldTransaction<'_, '_>>();
    require_native::<Box<WorldTransaction<'_, '_>>>();
}
