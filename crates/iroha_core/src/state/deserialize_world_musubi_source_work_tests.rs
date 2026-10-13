//! Whole-cut ceilings, repeated evidence and original-pool refusal controls.

use super::super::decode_tests::{
    seed_provider_attested_location, seeded_musubi_publication_snapshot,
};
use super::*;
use iroha_allocation::AllocationRefusal;
use iroha_data_model::musubi::{MusubiArchiveLocationIdV1, MusubiContentDigestV1};
use std::{
    future::Future,
    task::{Context, Poll, Waker},
};

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

fn measured(plan: &Plan) -> SourceWorkLimits {
    SourceWorkLimits {
        geometry: plan.geometry.used(),
        table_pass_rows: plan.table_rows,
        lookup_index_entries: plan.index_entries,
        model_operations: plan.operations,
        signature_checks: plan.signatures,
    }
}

#[test]
fn empty_cut_needs_no_work_or_original_pool_capacity() {
    let world = World::default();
    let budget = AllocationBudget::new(0);
    let zero = SourceWorkLimits {
        geometry: SourceGeometryLimits {
            elements: 0,
            variable_bytes: 0,
        },
        table_pass_rows: 0,
        lookup_index_entries: 0,
        model_operations: 0,
        signature_checks: 0,
    };
    validate(&world.view(), &budget, zero).unwrap();
    assert_eq!(budget.peak_reserved_bytes(), 0);
}

#[test]
fn complete_cut_accepts_exact_bounds_and_refuses_each_short_dimension() {
    let (world, _, _, _) = seeded_musubi_publication_snapshot();
    let before = json::to_json(&world).unwrap();
    let plan = admit(&world.view(), allowance()).unwrap();
    assert_eq!(plan.table_rows, 18);
    assert_eq!(plan.operations, 8);
    assert_eq!(
        plan.occurrences[Operation::NamespaceScratchPlan as usize],
        2
    );
    assert_eq!(plan.nfc_scratch_bytes, 0);
    assert_eq!(plan.signatures, 0);
    let exact = measured(&plan);
    let budget = AllocationBudget::new(1_000_000);
    validate(&world.view(), &budget, exact).unwrap();
    assert_eq!(budget.reserved_bytes(), 0);
    for dimension in 0..4 {
        let mut short = exact;
        match dimension {
            0 => short.geometry.elements -= 1,
            1 => short.geometry.variable_bytes -= 1,
            2 => short.table_pass_rows -= 1,
            3 => short.model_operations -= 1,
            _ => unreachable!(),
        }
        let empty = AllocationBudget::new(0);
        let error = validate(&world.view(), &empty, short).unwrap_err();
        assert!(matches!(error, SourceValidationError::Work(_)));
        assert_eq!(empty.peak_reserved_bytes(), 0);
    }
    assert_eq!(json::to_json(&world).unwrap(), before);
}

#[test]
fn repeated_location_edges_are_not_deduplicated_from_crypto_allowances() {
    let (mut world, release, archive, _) = seeded_musubi_publication_snapshot();
    let attestation_key = seed_provider_attested_location(&mut world, &release, archive);
    let mut location = world
        .musubi_archive_locations
        .view()
        .first_key_value()
        .unwrap()
        .1
        .clone();
    location.location_id = MusubiArchiveLocationIdV1::new([0x91; 32]);
    world
        .musubi_archive_locations
        .insert(location.key(), location);
    let plan = admit(&world.view(), allowance()).unwrap();
    assert_eq!(plan.occurrences[Operation::ArchiveValidation as usize], 7);
    assert_eq!(plan.occurrences[Operation::LocationValidation as usize], 6);
    assert_eq!(
        plan.occurrences[Operation::AttestationRecordValidation as usize],
        3
    );
    assert_eq!(
        plan.occurrences[Operation::AttestationValidation as usize],
        5
    );
    assert_eq!(plan.occurrences[Operation::AttestationDigest as usize], 5);
    assert_eq!(plan.occurrences[Operation::SigningHash as usize], 2);
    assert_eq!(plan.occurrences[Operation::ProviderSetDigest as usize], 4);
    assert_eq!(plan.signatures, 2);
    let mut exact = measured(&plan);
    exact.signature_checks -= 1;
    let budget = AllocationBudget::new(0);
    assert!(matches!(
        validate(&world.view(), &budget, exact),
        Err(SourceValidationError::Work(WorkRefusal::Limit {
            dimension: WorkDimension::SignatureChecks,
            requested: 2,
            limit: 1,
        }))
    ));
    assert_eq!(budget.peak_reserved_bytes(), 0);
    let mut record = world
        .musubi_provider_bundle_attestations
        .view()
        .get(&attestation_key)
        .unwrap()
        .clone();
    record
        .attestation
        .approvals
        .push(record.attestation.approvals[0].clone());
    world
        .musubi_provider_bundle_attestations
        .insert(attestation_key, record);
    // Shape admission never decides duplicate-approval validity; even invalid
    // complete input charges every possible repeated signature operation first.
    assert_eq!(admit(&world.view(), allowance()).unwrap().signatures, 4);
}

#[test]
fn source_work_refusal_precedes_validation_but_sufficient_work_preserves_rejection() {
    let (mut world, release, _, selector) = seeded_musubi_publication_snapshot();
    let mut row = world
        .musubi_resolver_index
        .view()
        .get(&release)
        .unwrap()
        .clone();
    row.source_digest = MusubiContentDigestV1::new([0x94; 32]);
    world.musubi_resolver_index.insert(release, row);
    let mut directory = world
        .musubi_public_directory
        .view()
        .get(&selector)
        .unwrap()
        .clone();
    directory.metadata_revision += 1;
    world.musubi_public_directory.insert(selector, directory);
    let mut short = allowance();
    short.table_pass_rows = 0;
    let budget = AllocationBudget::new(1_000_000);
    assert!(matches!(
        validate(&world.view(), &budget, short),
        Err(SourceValidationError::Work(WorkRefusal::Limit {
            dimension: WorkDimension::TablePassRows,
            ..
        }))
    ));
    assert_eq!(budget.peak_reserved_bytes(), 0);
    let direct = musubi_universal::validate_musubi_universal_projection_cut(
        &world.view(),
        ProjectionCut::Capture,
        &budget,
    )
    .unwrap_err();
    let SourceValidationError::Attempt(actual) =
        validate(&world.view(), &budget, allowance()).unwrap_err()
    else {
        panic!("complete admission preserves original semantic error")
    };
    assert_eq!(actual.to_string(), direct.to_string());
    let actual = actual.map_rejection(ProjectionRejection::into_json);
    assert!(
        matches!(&actual, ExecutionAttemptError::Rejected(json::Error::InvalidField { field, .. })
        if field == "world.musubi_resolver_index"),
        "{actual:?}"
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn memory_deferral_retains_the_supplied_pool_release_not_an_unrelated_one() {
    let (world, _, _, _) = seeded_musubi_publication_snapshot();
    let before = json::to_json(&world).unwrap();
    let budget = AllocationBudget::new(
        1_000_000 + iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
    );
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let held = budget.try_reserve_bytes(1_000_000).unwrap();
    let Err(SourceValidationError::Attempt(ExecutionAttemptError::Deferred(reason))) =
        validate(&world.view(), &budget, allowance())
    else {
        panic!("actual live scratch must retain the original pool refusal")
    };
    let Some(AllocationRefusal::Capacity { release, .. }) = reason.allocation_refusal() else {
        panic!("exact original capacity error")
    };
    let mut waiter = Box::pin(release.clone().wait_for_release(&mut registration));
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(waiter.as_mut().poll(&mut context), Poll::Pending);
    let unrelated = AllocationBudget::new(1_000_000);
    drop(unrelated.try_reserve_bytes(1_000_000).unwrap());
    assert_eq!(waiter.as_mut().poll(&mut context), Poll::Pending);
    budget.set_limit_bytes(0);
    drop(held);
    assert_eq!(waiter.as_mut().poll(&mut context), Poll::Ready(()));
    assert!(matches!(
        validate(&world.view(), &budget, allowance()),
        Err(SourceValidationError::Attempt(
            ExecutionAttemptError::Deferred(_)
        ))
    ));
    drop(waiter);
    drop(registration);
    budget.set_limit_bytes(1_000_000);
    validate(&world.view(), &budget, allowance()).unwrap();
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(json::to_json(&world).unwrap(), before);
}

#[test]
fn every_work_counter_refuses_overflow_without_wrapping() {
    let mut limits = allowance();
    limits.table_pass_rows = u64::MAX;
    limits.lookup_index_entries = u64::MAX;
    limits.model_operations = u64::MAX;
    limits.signature_checks = u64::MAX;
    let mut plan = Plan::new(limits);
    plan.table_rows = u64::MAX;
    plan.index_entries = u64::MAX;
    plan.operations = u64::MAX;
    plan.signatures = u64::MAX;
    for dimension in [
        WorkDimension::TablePassRows,
        WorkDimension::LookupIndexEntries,
        WorkDimension::ModelOperations,
        WorkDimension::SignatureChecks,
    ] {
        assert_eq!(
            plan.add(dimension, 1),
            Err(WorkRefusal::Overflow(dimension))
        );
    }
    assert_eq!(plan.table_rows, u64::MAX);
    assert_eq!(plan.index_entries, u64::MAX);
    assert_eq!(plan.operations, u64::MAX);
    assert_eq!(plan.signatures, u64::MAX);
}

#[test]
fn variable_storage_keys_are_measured_independently_of_unchanged_payloads() {
    let (world, release, _, _) = seeded_musubi_publication_snapshot();
    let before = admit(&world.view(), allowance()).unwrap().geometry.used();
    let row = world
        .musubi_resolver_index
        .view()
        .get(&release)
        .unwrap()
        .clone();
    let mut key = release.clone();
    key.version.prerelease = vec![
        iroha_data_model::musubi::MusubiPrereleaseIdentifierV1::AlphaNumeric("x".repeat(1024)),
    ];
    let mut block = world.musubi_resolver_index.block();
    block.remove(release);
    block.insert(key, row);
    block.commit();
    let after = admit(&world.view(), allowance()).unwrap().geometry.used();
    assert_eq!(after.variable_bytes, before.variable_bytes + 1024);
    let mut limits = allowance();
    limits.geometry.variable_bytes = before.variable_bytes;
    let budget = AllocationBudget::new(0);
    assert!(matches!(
        validate(&world.view(), &budget, limits),
        Err(SourceValidationError::Work(WorkRefusal::Geometry(
            SourceGeometryError::Limit { .. }
        )))
    ));
    assert_eq!(budget.peak_reserved_bytes(), 0);
}

#[test]
fn fixed_key_evidence_index_population_is_admitted_before_point_lookups() {
    let (mut world, release, archive, _) = seeded_musubi_publication_snapshot();
    let attestation = seed_provider_attested_location(&mut world, &release, archive);
    let owner = world
        .musubi_provider_bundle_attestations
        .view()
        .get(&attestation)
        .unwrap()
        .attestation
        .payload
        .binding
        .completed_by
        .clone();
    world.provider_owners.insert(attestation.provider_id, owner);
    let plan = admit(&world.view(), allowance()).unwrap();
    assert_eq!(plan.index_entries, 1);
    let mut limits = measured(&plan);
    limits.lookup_index_entries = 0;
    let budget = AllocationBudget::new(0);
    assert!(matches!(
        validate(&world.view(), &budget, limits),
        Err(SourceValidationError::Work(WorkRefusal::Limit {
            dimension: WorkDimension::LookupIndexEntries,
            requested: 1,
            limit: 0,
        }))
    ));
    assert_eq!(budget.peak_reserved_bytes(), 0);
}

#[test]
fn live_model_rejection_keeps_static_reason_before_original_pool_admission() {
    let (mut world, _, archive_id, _) = seeded_musubi_publication_snapshot();
    let mut archive = world
        .musubi_archives
        .view()
        .get(&archive_id)
        .unwrap()
        .clone();
    archive.location_revision = 0;
    let original = archive.validate().unwrap_err();
    world.musubi_archives.insert(archive_id, archive);
    let before = json::to_json(&world).unwrap();
    let budget = AllocationBudget::new(0);
    let ExecutionAttemptError::Rejected(rejection) =
        validate_musubi_live_projection_cut(&world.view(), &budget).unwrap_err()
    else {
        panic!("earlier semantic rejection must precede live scratch admission")
    };
    assert_eq!(
        rejection,
        ProjectionRejection::new(ProjectionTable::Archives, original.reason())
    );
    assert!(std::ptr::eq(rejection.reason(), original.reason()));
    let SourceValidationError::Attempt(actual) =
        validate(&world.view(), &budget, allowance()).unwrap_err()
    else {
        panic!("source work must retain the completed semantic rejection")
    };
    assert!(
        matches!(actual, ExecutionAttemptError::Rejected(actual_rejection) if actual_rejection == (rejection))
    );
    assert_eq!(budget.peak_reserved_bytes(), 0);
    assert_eq!(json::to_json(&world).unwrap(), before);
}

#[test]
fn universal_model_rejection_keeps_static_reason_and_cut_before_scratch() {
    let (mut world, release, _, _) = seeded_musubi_publication_snapshot();
    let mut package = world
        .musubi_packages
        .view()
        .get(&release.package)
        .unwrap()
        .clone();
    package.claimed_at_height = 0;
    let original = package.validate().unwrap_err();
    world.musubi_packages.insert(release.package, package);
    let before = json::to_json(&world).unwrap();
    let budget = AllocationBudget::new(0);
    for cut in [
        ProjectionCut::Current,
        ProjectionCut::Predecessor,
        ProjectionCut::Capture,
        ProjectionCut::Candidate,
    ] {
        let ExecutionAttemptError::Rejected(rejection) =
            musubi_universal::validate_musubi_universal_projection_cut(&world.view(), cut, &budget)
                .unwrap_err()
        else {
            panic!("package model rejection precedes universal scratch admission")
        };
        assert_eq!(
            rejection,
            ProjectionRejection::new(ProjectionTable::PublicDirectory, original.reason())
                .with_cut(cut)
        );
        assert!(std::ptr::eq(rejection.reason(), original.reason()));
    }
    assert_eq!(budget.peak_reserved_bytes(), 0);
    assert_eq!(json::to_json(&world).unwrap(), before);
}

#[test]
fn capture_rejection_outlives_the_world_and_budget_without_retained_backing() {
    let rejection = {
        let (mut world, release, _, _) = seeded_musubi_publication_snapshot();
        let mut row = world
            .musubi_resolver_index
            .view()
            .get(&release)
            .unwrap()
            .clone();
        row.source_digest = MusubiContentDigestV1::new([0x97; 32]);
        world.musubi_resolver_index.insert(release, row);
        let budget = AllocationBudget::new(1_000_000);
        let SourceValidationError::Attempt(ExecutionAttemptError::Rejected(rejection)) =
            validate(&world.view(), &budget, allowance()).unwrap_err()
        else {
            panic!("actual capture rejects the substituted resolver source")
        };
        assert_eq!(budget.reserved_bytes(), 0);
        rejection
    };
    fn requires_copy_static<T: Copy + 'static>(value: T) -> T {
        value
    }
    let copied = requires_copy_static(rejection);
    assert_eq!(
        copied.to_string(),
        "JSON error: invalid field `world.musubi_resolver_index`: capture World cut: resolver row diverges from authoritative release/archive projections"
    );
}

#[test]
fn publication_renders_the_same_rejection_without_erasing_local_refusals() {
    let (world, release, _, _) = seeded_musubi_publication_snapshot();
    let before = json::to_json(&world).unwrap();
    let mut row = world
        .musubi_resolver_index
        .view()
        .get(&release)
        .unwrap()
        .clone();
    row.source_digest = MusubiContentDigestV1::new([0x98; 32]);
    let mut block = world.block();
    block.musubi_resolver_index.insert(release, row);
    let budget = AllocationBudget::new(
        1_000_000 + iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
    );
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let Err(ExecutionAttemptError::Deferred(reason)) =
        crate::state::world_commit::PreparedWorldCommit::validate_prepared_overlay(&block, &budget)
    else {
        panic!("publication must retain the local refusal before its later semantic failure")
    };
    assert!(matches!(
        reason.allocation_refusal(),
        Some(AllocationRefusal::Capacity { .. })
    ));
    let mut wait = Box::pin(
        reason
            .allocation_refusal()
            .and_then(|refusal| match refusal {
                AllocationRefusal::Capacity { release, .. } => Some(release.clone()),
                _ => None,
            })
            .unwrap()
            .wait_for_release(&mut registration),
    );
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(wait.as_mut().poll(&mut context), Poll::Pending);
    let unrelated = AllocationBudget::new(1);
    drop(unrelated.try_reserve_bytes(1).unwrap());
    assert_eq!(wait.as_mut().poll(&mut context), Poll::Pending);
    drop(occupied);
    assert_eq!(wait.as_mut().poll(&mut context), Poll::Ready(()));
    let Err(ExecutionAttemptError::Rejected(rejection)) =
        crate::state::world_commit::PreparedWorldCommit::validate_prepared_overlay(&block, &budget)
    else {
        panic!("completed retry must report the original deterministic failure")
    };
    assert_eq!(
        rejection,
        "Musubi World publication refused: JSON error: invalid field `world.musubi_resolver_index`: candidate World cut: resolver row diverges from authoritative release/archive projections"
    );
    drop(wait);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), 0);
    drop(block);
    assert_eq!(json::to_json(&world).unwrap(), before);
}
