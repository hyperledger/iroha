//! Original pool, exact borrowed scratch and semantic refusal controls.

use super::super::decode_tests::seeded_musubi_publication_snapshot;
use super::*;
use iroha_allocation::AllocationRefusal;
use iroha_data_model::musubi::{MusubiArtifactGovernanceStateV1, MusubiStorageAvailabilityV1};
use std::{
    alloc::Layout,
    future::Future,
    task::{Context, Poll, Waker},
};

fn scratch_bytes(world: &World) -> usize {
    Layout::array::<PackageRevision<'_>>(world.musubi_packages.view().len())
        .unwrap()
        .size()
}

fn complete_projection_budget(world: &World) -> AllocationBudget {
    let probe = AllocationBudget::new(
        iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
    );
    let original = world.try_block_and_revert(&probe).unwrap();
    let original_controls = probe.reserved_bytes();
    assert!(original_controls >= std::mem::size_of::<crate::state::WorldBlockFields<'_>>());
    drop(original);
    assert_eq!(probe.reserved_bytes(), 0);
    AllocationBudget::new(original_controls + scratch_bytes(world))
}

#[test]
fn universal_scratch_retains_exact_backing_until_the_complete_check_returns() {
    let empty = AllocationBudget::new(0);
    let empty_world = World::default();
    validate_musubi_universal_projection_cut(&empty_world.view(), ProjectionCut::Current, &empty)
        .unwrap();
    assert!(matches!(
        validate_musubi_universal_projection_cuts(&empty_world, &empty),
        Err(StateRestoreError::Admission(
            crate::state::StateAdmissionError::Storage(
                crate::state::StateStorageAdmissionError::World(
                    mv::storage::AdmittedStorageError::Allocation(
                        AllocationRefusal::ExceedsLimit { limit_bytes: 0, .. }
                    )
                )
            )
        ))
    ));
    assert_eq!(empty.peak_reserved_bytes(), 0);
    let (world, _, _, _) = seeded_musubi_publication_snapshot();
    let before = json::to_json(&world).unwrap();
    let budget = complete_projection_budget(&world);
    validate_musubi_universal_projection_cuts(&world, &budget).unwrap();
    assert_eq!(budget.peak_reserved_bytes(), budget.limit_bytes());
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(json::to_json(&world).unwrap(), before);
}

#[test]
fn universal_capacity_refusal_keeps_only_the_original_release_owner() {
    let (world, _, _, _) = seeded_musubi_publication_snapshot();
    let bytes = scratch_bytes(&world);
    let budget = complete_projection_budget(&world);
    let complete_limit = budget.limit_bytes();
    budget.set_limit_bytes(
        complete_limit + iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
    );
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let held = budget.try_reserve_bytes(complete_limit).unwrap();
    let ExecutionAttemptError::Deferred(reason) =
        validate_musubi_universal_projection_cut(&world.view(), ProjectionCut::Current, &budget)
            .unwrap_err()
    else {
        panic!("capacity refusal must remain local")
    };
    let Some(AllocationRefusal::Capacity {
        requested_bytes,
        release,
        ..
    }) = reason.allocation_refusal()
    else {
        panic!("original finite pool refusal")
    };
    assert_eq!(*requested_bytes, bytes);
    let mut wait = Box::pin(release.clone().wait_for_release(&mut registration));
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(wait.as_mut().poll(&mut context), Poll::Pending);
    let unrelated = AllocationBudget::new(bytes);
    drop(unrelated.try_reserve_bytes(bytes).unwrap());
    assert_eq!(wait.as_mut().poll(&mut context), Poll::Pending);
    budget.set_limit_bytes(bytes - 1);
    assert!(matches!(
        validate_musubi_universal_projection_cuts(&world, &budget),
        Err(StateRestoreError::ExecutionDeferred(_))
    ));
    drop(held);
    assert_eq!(wait.as_mut().poll(&mut context), Poll::Ready(()));
    drop(wait);
    drop(registration);
    budget.set_limit_bytes(complete_limit);
    validate_musubi_universal_projection_cuts(&world, &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn malformed_package_is_rejected_before_universal_scratch_admission() {
    let (mut world, release, _, _) = seeded_musubi_publication_snapshot();
    let mut package = world
        .musubi_packages
        .view()
        .get(&release.package)
        .cloned()
        .unwrap();
    package.package.home_dataspace = iroha_model_base::topology::DataSpaceId::new(8);
    package.validate().unwrap();
    world.musubi_packages.insert(release.package, package);
    let budget = AllocationBudget::new(0);
    let error =
        validate_musubi_universal_projection_cut(&world.view(), ProjectionCut::Current, &budget)
            .unwrap_err();
    assert!(
        matches!(&error.clone().map_rejection(ProjectionRejection::into_json), ExecutionAttemptError::Rejected(json::Error::InvalidField { field, message })
        if field == "world.musubi_public_directory" && message == "current World cut: package lookup key differs from its canonical identity"),
        "unexpected semantic result: {error:?}"
    );
    assert_eq!(budget.peak_reserved_bytes(), 0);
}

#[test]
fn universal_source_and_directory_failures_release_all_accumulator_credit() {
    for directory in [false, true] {
        let (mut world, release, _, selector) = seeded_musubi_publication_snapshot();
        let budget = AllocationBudget::new(scratch_bytes(&world));
        if directory {
            let mut row = world
                .musubi_public_directory
                .view()
                .get(&selector)
                .cloned()
                .unwrap();
            row.metadata_revision += 1;
            world.musubi_public_directory.insert(selector, row);
        } else {
            let mut row = world
                .musubi_resolver_index
                .view()
                .get(&release)
                .cloned()
                .unwrap();
            row.source_digest = iroha_data_model::musubi::MusubiContentDigestV1::new([0xa5; 32]);
            world.musubi_resolver_index.insert(release, row);
        }
        let before = json::to_json(&world).unwrap();
        let error = validate_musubi_universal_projection_cut(
            &world.view(),
            ProjectionCut::Current,
            &budget,
        )
        .unwrap_err();
        assert!(
            matches!(&error.clone().map_rejection(ProjectionRejection::into_json), ExecutionAttemptError::Rejected(json::Error::InvalidField { field, .. })
            if field == if directory { "world.musubi_public_directory" } else { "world.musubi_resolver_index" }),
            "unexpected semantic result: {error:?}"
        );
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(budget.peak_reserved_bytes(), scratch_bytes(&world));
        assert_eq!(json::to_json(&world).unwrap(), before);
    }
}

#[test]
fn accumulator_borrows_latest_selectable_version_and_counts_every_revision() {
    let (world, release, _, _) = seeded_musubi_publication_snapshot();
    let mut row = world
        .musubi_resolver_index
        .view()
        .get(&release)
        .cloned()
        .unwrap();
    row.selection.storage.availability = MusubiStorageAvailabilityV1::Selectable;
    row.selection.governance = MusubiArtifactGovernanceStateV1::Available;
    row.selection.yank.yanked = false;
    let versions = ["1.0.0", "3.0.0", "2.0.0", "4.0.0"]
        .map(|version| MusubiReleaseIdV1::new(release.package.clone(), version.parse().unwrap()));
    let mut accumulator = PackageRevision::new(&release.package);
    assert_eq!(accumulator.latest, None);
    assert_eq!(accumulator.maximum, None);
    for (index, release) in versions.iter().enumerate() {
        row.index_revision = [7, 3, 11, 20][index];
        row.selection.yank.yanked = index == 3;
        accumulator.observe(release, &row);
    }
    assert_eq!(accumulator.maximum, Some(20));
    assert!(std::ptr::eq(
        accumulator.latest.unwrap(),
        &raw const versions[1].version
    ));
    assert!(std::ptr::eq(
        accumulator.package,
        &raw const release.package
    ));
}

#[test]
fn shared_selector_cannot_satisfy_a_second_package_identity() {
    for home in [6, 8] {
        let (mut world, release, _, _) = seeded_musubi_publication_snapshot();
        let mut duplicate = world
            .musubi_packages
            .view()
            .get(&release.package)
            .cloned()
            .unwrap();
        duplicate.package.home_dataspace = iroha_model_base::topology::DataSpaceId::new(home);
        duplicate.validate().unwrap();
        world
            .musubi_packages
            .insert(duplicate.package.clone(), duplicate);
        let budget = AllocationBudget::new(scratch_bytes(&world));
        let error = validate_musubi_universal_projection_cut(
            &world.view(),
            ProjectionCut::Current,
            &budget,
        )
        .unwrap_err();
        assert!(
            matches!(&error.clone().map_rejection(ProjectionRejection::into_json), ExecutionAttemptError::Rejected(json::Error::InvalidField { field, message })
            if field == "world.musubi_public_directory" && message == "current World cut: package is missing its exact public-directory entry"),
            "unexpected semantic result: {error:?}"
        );
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(budget.peak_reserved_bytes(), scratch_bytes(&world));
    }
}

#[test]
fn world_overlay_preserves_local_refusal_after_live_scratch_has_succeeded() {
    let (world, release, _, _) = seeded_musubi_publication_snapshot();
    let live_bytes = world.musubi_public_directory.view().len()
        * std::mem::size_of::<&MusubiOrderedPackageEntryV1>();
    assert!(scratch_bytes(&world) > live_bytes);
    let budget = AllocationBudget::new(live_bytes);
    let before = json::to_json(&world).unwrap();
    let row = world
        .musubi_resolver_index
        .view()
        .get(&release)
        .cloned()
        .unwrap();
    let mut block = world.block();
    block.musubi_resolver_index.insert(release, row);
    let result = crate::state::world_commit::PreparedWorldCommit::prepare_overlay(
        &mut block,
        &budget,
        2,
        &iroha_config::parameters::actual::Nexus::default(),
        &BTreeMap::new(),
        None,
        None,
    );
    assert!(matches!(result, Err(ExecutionAttemptError::Deferred(_))));
    drop(block);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(budget.peak_reserved_bytes(), live_bytes);
    assert_eq!(json::to_json(&world).unwrap(), before);
}
