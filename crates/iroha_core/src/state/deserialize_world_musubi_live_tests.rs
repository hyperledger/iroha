// Exact current/retired membership controls for the single borrowed location traversal.

fn world_with_retained_musubi_locations(
    retired: usize,
) -> (World, ArchiveId, MusubiArchiveLocationKeyV1) {
    let (mut world, release, archive_id, _) = seeded_musubi_publication_snapshot();
    seed_provider_attested_location(&mut world, &release, archive_id);
    let current = world
        .musubi_archive_locations
        .view()
        .iter()
        .next()
        .map(|(_, row)| row.clone())
        .unwrap();
    for index in 0..retired {
        let mut row = current.clone();
        let mut identity = [0; 32];
        identity[..8].copy_from_slice(&((index + 1) as u64).to_be_bytes());
        row.location_id = MusubiArchiveLocationIdV1::new(identity);
        row.revision = (index + 3) as u64;
        row.state = MusubiArchiveLocationStateV1::Retired;
        world.musubi_archive_locations.insert(row.key(), row);
    }
    let mut archive = world
        .musubi_archives
        .view()
        .get(&archive_id)
        .cloned()
        .unwrap();
    archive.location_revision = (retired + 2) as u64;
    world.musubi_archives.insert(archive_id, archive);
    (world, archive_id, current.key())
}

#[test]
fn musubi_live_linear_location_cut_includes_all_retired_rows_in_revision_and_evidence_checks() {
    let (mut world, archive_id, _) = world_with_retained_musubi_locations(96);
    assert_eq!(world.musubi_archive_locations.view().len(), 97);
    validate_musubi_live_projection_cut(
        &world.view(),
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
    )
    .map_err(crate::execution_attempt::expect_completed_rejection)
    .expect("retired rows do not consume the current directory capacity");
    let mut archive = world
        .musubi_archives
        .view()
        .get(&archive_id)
        .cloned()
        .unwrap();
    archive.location_revision += 1;
    world.musubi_archives.insert(archive_id, archive);
    let error = validate_musubi_live_projection_cut(
        &world.view(),
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
    )
    .map_err(crate::execution_attempt::expect_completed_rejection)
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("exact maximum retained location revision"),
        "{error}"
    );
    let (mut world, _, _) = world_with_retained_musubi_locations(96);
    let mut retired = world
        .musubi_archive_locations
        .view()
        .iter()
        .find(|(_, row)| row.state == MusubiArchiveLocationStateV1::Retired)
        .map(|(_, row)| row.clone())
        .unwrap();
    retired.provider_attestation_set_digest =
        MusubiProviderBundleAttestationSetDigestV1::new([0xee; 32]);
    world
        .musubi_archive_locations
        .insert(retired.key(), retired);
    let error = validate_musubi_live_projection_cut(
        &world.view(),
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
    )
    .map_err(crate::execution_attempt::expect_completed_rejection)
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("provider-attestation set digest is not exact"),
        "{error}"
    );
}

#[test]
fn musubi_live_linear_location_cut_rejects_missing_and_phantom_current_membership() {
    for phantom in [false, true] {
        let (mut world, archive_id, _) = world_with_retained_musubi_locations(12);
        let mut archive = world
            .musubi_archives
            .view()
            .get(&archive_id)
            .cloned()
            .unwrap();
        if phantom {
            archive
                .location_ids
                .push(MusubiArchiveLocationIdV1::new([0xff; 32]));
        } else {
            archive.location_ids.clear();
        }
        archive.validate().unwrap();
        world.musubi_archives.insert(archive_id, archive);
        let error = validate_musubi_live_projection_cut(
            &world.view(),
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
        )
        .map_err(crate::execution_attempt::expect_completed_rejection)
        .unwrap_err();
        assert!(
            error.to_string().contains(if phantom {
                "exact non-retired location set"
            } else {
                "absent from its archive directory"
            }),
            "{error}"
        );
    }
}

fn world_with_three_ordered_musubi_archive_groups() -> (World, [ArchiveId; 3]) {
    use iroha_data_model::{
        musubi::MusubiReplicationOrderArchiveBindingV1,
        sorafs::pin_registry::{
            PinManifestRecord, PinPolicy, ReplicationOrderCompletionRecord, ReplicationOrderRecord,
            ReplicationOrderStatus, StorageClass,
        },
    };
    let (mut world, release, original_id, _) = seeded_musubi_publication_snapshot();
    let attestation_key = seed_provider_attested_location(&mut world, &release, original_id);
    let template_archive = world
        .musubi_archives
        .view()
        .get(&original_id)
        .cloned()
        .unwrap();
    let template_location = world
        .musubi_archive_locations
        .view()
        .iter()
        .next()
        .map(|(_, row)| row.clone())
        .unwrap();
    let template_attestation = world
        .musubi_provider_bundle_attestations
        .view()
        .get(&attestation_key)
        .cloned()
        .unwrap();
    let template_availability = *world
        .musubi_archive_availability
        .view()
        .get(&original_id)
        .unwrap();
    {
        let mut locations = world.musubi_archive_locations.block();
        let _ = locations.remove(template_location.key());
        locations.commit();
        let mut attestations = world.musubi_provider_bundle_attestations.block();
        let _ = attestations.remove(attestation_key);
        attestations.commit();
    }
    let broker = KeyPair::try_from_seed(vec![62; 32], Algorithm::Ed25519).unwrap();
    let provider_signer = KeyPair::try_from_seed(vec![70; 32], Algorithm::Ed25519).unwrap();
    let mut archives = [
        template_archive.clone(),
        template_archive.clone(),
        template_archive,
    ];
    for (index, archive) in archives.iter_mut().enumerate() {
        archive.commitment.car_size += index as u64;
        archive.archive_id = archive.commitment.archive_id();
        archive.location_ids.clear();
        archive.location_revision = 1;
        archive.staging_receipt.payload.binding.archive_id = archive.archive_id;
        archive.staging_receipt.payload.binding.car_body_length = archive.commitment.car_size;
        archive.staging_receipt.approvals[0].signature = SignatureOf::try_from_hash(
            broker.private_key(),
            archive.staging_receipt.payload.signing_hash(),
        )
        .unwrap();
        archive.validate().unwrap();
    }
    archives.sort_unstable_by_key(|archive| archive.archive_id);
    let ids = std::array::from_fn(|index| archives[index].archive_id);
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
    for (index, mut archive) in archives.into_iter().enumerate() {
        let mut availability = template_availability;
        availability.archive_id = archive.archive_id;
        if index != 1 {
            let provider = ProviderId::new([0x91 + index as u8; 32]);
            let order_id = ReplicationOrderId::new([0xa1 + index as u8; 32]);
            let mut current = template_location.clone();
            current.archive_id = archive.archive_id;
            current.location_id = MusubiArchiveLocationIdV1::new([0xb1 + index as u8; 32]);
            current.replication_order = order_id;
            current.pin_manifest = ManifestDigest::new([0xc1 + index as u8; 32]);
            current.providers = vec![provider];
            current.finalized_height = 3;
            current.revision = 2 + 5 * index as u64;
            let mut record = template_attestation.clone();
            record.attestation.payload.binding.archive_id = archive.archive_id;
            record.attestation.payload.binding.replication_order = order_id;
            record.attestation.payload.binding.provider_id = provider;
            record.attestation.approvals[0].signature = SignatureOf::try_from_hash(
                provider_signer.private_key(),
                record.attestation.payload.signing_hash(),
            )
            .unwrap();
            record.key = record.attestation.key();
            record.attestation_digest = record.attestation.digest();
            record.validate().unwrap();
            current.provider_attestation_set_digest =
                musubi_provider_bundle_attestation_set_digest_v1(
                    archive.archive_id,
                    order_id,
                    &[record.attestation.reference()],
                )
                .unwrap();
            let mut retired = current.clone();
            retired.location_id = MusubiArchiveLocationIdV1::new([0xd1 + index as u8; 32]);
            retired.revision = current.revision + 2;
            retired.state = MusubiArchiveLocationStateV1::Retired;
            archive.location_ids = vec![current.location_id];
            archive.location_revision = retired.revision;
            if index == 0 {
                // The first populated archive has current provider evidence;
                // the second retains unavailable evidence. Availability must
                // therefore be recomputed separately for both cursor groups.
                let binding = &record.attestation.payload.binding;
                let mut pin = PinManifestRecord::new(
                    current.pin_manifest,
                    archive.commitment.root_cid.clone(),
                    archive.commitment.chunker.clone(),
                    *archive.commitment.chunk_plan_digest.as_bytes(),
                    *archive.commitment.por_root.as_bytes(),
                    archive.commitment.content_length,
                    PinPolicy {
                        min_replicas: iroha_data_model::musubi::MUSUBI_MIN_HEALTHY_REPLICAS_V1,
                        storage_class: StorageClass::Hot,
                        retention_epoch: current.expires_at_epoch,
                    },
                    archive.registered_by.clone(),
                    1,
                    None,
                    None,
                    iroha_model_base::metadata::Metadata::default(),
                );
                pin.approve(1, None);
                world.pin_manifests.insert(current.pin_manifest, pin);
                world.replication_orders.insert(
                    order_id,
                    ReplicationOrderRecord {
                        order_id,
                        manifest_digest: current.pin_manifest,
                        manifest_root_cid: archive.commitment.root_cid.clone(),
                        musubi_archive: Some(archive.archive_id),
                        issued_by: archive.registered_by.clone(),
                        issued_epoch: 1,
                        deadline_epoch: current.expires_at_epoch,
                        canonical_order: vec![1],
                        assignment_revision: binding.assignment_revision,
                        provider_completions: vec![ReplicationOrderCompletionRecord {
                            provider_id: provider,
                            completed_by: binding.completed_by.clone(),
                            completion_epoch: binding.completion_epoch,
                            assignment_revision: binding.assignment_revision,
                            completion_authority: binding.completion_authority.clone(),
                            finalized_anchor: binding.finalized_anchor,
                        }],
                        status: ReplicationOrderStatus::Completed(binding.completion_epoch),
                    },
                );
                world
                    .provider_owners
                    .insert(provider, binding.completed_by.clone());
                world.musubi_locations_by_pin.insert(
                    current.pin_manifest,
                    MusubiPinLocationReferenceV1 {
                        pin_manifest: current.pin_manifest,
                        location: current.key(),
                        active: true,
                    },
                );
                world.musubi_locations_by_replication_order.insert(
                    order_id,
                    MusubiReplicationOrderLocationReferenceV1 {
                        binding: MusubiReplicationOrderArchiveBindingV1::new(
                            order_id,
                            archive.archive_id,
                            archive.commitment.clone(),
                        ),
                        lifecycle: MusubiReplicationOrderLocationLifecycleV1::Active(current.key()),
                    },
                );
                world.musubi_locations_by_provider.insert(
                    MusubiProviderLocationKeyV1::new(provider, current.key()),
                    (),
                );
                availability.active_locations = 1;
                availability.healthy_replicas = 1;
                availability.availability = MusubiStorageAvailabilityV1::BelowQuorum;
            }
            current.validate().unwrap();
            retired.validate().unwrap();
            world
                .musubi_provider_bundle_attestations
                .insert(record.key, record);
            world
                .musubi_archive_locations
                .insert(current.key(), current);
            world
                .musubi_archive_locations
                .insert(retired.key(), retired);
        }
        archive.validate().unwrap();
        availability.validate().unwrap();
        if archive.archive_id == original_id {
            let mut resolver = world
                .musubi_resolver_index
                .view()
                .get(&release)
                .cloned()
                .unwrap();
            resolver.selection.storage = availability;
            world
                .musubi_resolver_index
                .insert(release.clone(), resolver);
        }
        world
            .musubi_archive_availability
            .insert(archive.archive_id, availability);
        world.musubi_archives.insert(archive.archive_id, archive);
    }
    (world, ids)
}

#[test]
fn musubi_live_linear_location_cut_separates_two_populated_groups_across_an_empty_archive() {
    let (mut world, ids) = world_with_three_ordered_musubi_archive_groups();
    assert_eq!(
        world
            .musubi_archives
            .view()
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>(),
        ids
    );
    assert_eq!(
        world
            .musubi_archive_locations
            .view()
            .iter()
            .map(|(key, _)| key.archive_id)
            .collect::<Vec<_>>(),
        [ids[0], ids[0], ids[2], ids[2]]
    );
    for (index, id) in ids.iter().enumerate() {
        let archives = world.musubi_archives.view();
        let archive = archives.get(id).unwrap();
        assert_eq!(archive.location_revision, [4, 1, 14][index]);
        let rows = world.musubi_archive_locations.view();
        assert_eq!(
            rows.iter()
                .filter(|(key, row)| key.archive_id == *id
                    && row.state == MusubiArchiveLocationStateV1::Retired)
                .count(),
            usize::from(index != 1)
        );
        assert_eq!(archive.location_ids.len(), usize::from(index != 1));
        let projections = world.musubi_archive_availability.view();
        let projection = projections.get(id).unwrap();
        assert_eq!(
            (projection.active_locations, projection.healthy_replicas),
            if index == 0 { (1, 1) } else { (0, 0) }
        );
    }
    validate_musubi_live_projection_cut(&world.view(), &iroha_allocation::AllocationBudget::new(iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES)).map_err(crate::execution_attempt::expect_completed_rejection).expect("two populated archive groups with an empty group between have exact independent projections");
    for id in ids {
        let original = world.musubi_archives.view().get(&id).cloned().unwrap();
        let mut changed = original.clone();
        changed.location_revision += 1;
        world.musubi_archives.insert(id, changed);
        let error = validate_musubi_live_projection_cut(
            &world.view(),
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
        )
        .map_err(crate::execution_attempt::expect_completed_rejection)
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("exact maximum retained location revision"),
            "{error}"
        );
        world.musubi_archives.insert(id, original);
        let original = *world.musubi_archive_availability.view().get(&id).unwrap();
        let mut changed = original;
        changed.active_locations += 1;
        world.musubi_archive_availability.insert(id, changed);
        let error = validate_musubi_live_projection_cut(
            &world.view(),
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
        )
        .map_err(crate::execution_attempt::expect_completed_rejection)
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("availability projection is not the exact result"),
            "{error}"
        );
        world.musubi_archive_availability.insert(id, original);
    }
    validate_musubi_live_projection_cut(
        &world.view(),
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
    )
    .map_err(crate::execution_attempt::expect_completed_rejection)
    .unwrap();
    let mut retired = world
        .musubi_archive_locations
        .view()
        .iter()
        .find(|(_, row)| row.state == MusubiArchiveLocationStateV1::Retired)
        .map(|(_, row)| row.clone())
        .unwrap();
    retired.archive_id = ArchiveId::new([0xfe; 32]);
    world
        .musubi_archive_locations
        .insert(retired.key(), retired);
    let error = validate_musubi_live_projection_cut(
        &world.view(),
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
    )
    .map_err(crate::execution_attempt::expect_completed_rejection)
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("archive location references a missing archive"),
        "{error}"
    );
}

#[test]
fn musubi_live_funded_revision_merge_preserves_unsorted_and_duplicate_payload_semantics() {
    let (mut world, release, _, selector) = seeded_musubi_publication_snapshot();
    let template_row = world
        .musubi_resolver_index
        .view()
        .get(&release)
        .cloned()
        .unwrap();
    let template_entry = world
        .musubi_public_directory
        .view()
        .get(&selector)
        .cloned()
        .unwrap();
    // Namespace key order deliberately opposes payload package order. Include
    // two distinct directory keys carrying the same malformed package identity:
    // this check must keep its original result, leaving identity rejection to
    // the later universal validator rather than silently dropping either row.
    for (namespace, package_name, revision) in [
        ("zulu", "alpha", 11),
        ("alpha", "zulu", 19),
        ("middle", "alpha", 11),
        ("empty", "missing", 2),
    ] {
        let package = musubi_package(package_name);
        let mut entry = template_entry.clone();
        entry.selector.namespace = namespace.parse().unwrap();
        entry.package = package.clone();
        entry.index_revision = revision;
        world
            .musubi_public_directory
            .insert(entry.selector.clone(), entry);
        if package_name != "missing" {
            let mut row = template_row.clone();
            row.release.package = package;
            row.index_revision = revision;
            world.musubi_resolver_index.insert(row.release.clone(), row);
        }
    }
    let bytes = world.musubi_public_directory.view().len()
        * core::mem::size_of::<&MusubiOrderedPackageEntryV1>();
    let budget = iroha_allocation::AllocationBudget::new(bytes);
    validate_musubi_live_projection_cut(&world.view(), &budget).unwrap();
    assert_eq!(budget.peak_reserved_bytes(), bytes);
    assert_eq!(budget.reserved_bytes(), 0);
    let key = MusubiPackageSelectorV1 {
        namespace: "middle".parse().unwrap(),
        name: selector.name.clone(),
    };
    let mut duplicate = world
        .musubi_public_directory
        .view()
        .get(&key)
        .cloned()
        .unwrap();
    duplicate.index_revision -= 1;
    world.musubi_public_directory.insert(key, duplicate);
    let error = validate_musubi_live_projection_cut(&world.view(), &budget).unwrap_err();
    assert!(
        matches!(&error.clone().map_rejection(ProjectionRejection::into_json), crate::execution_attempt::ExecutionAttemptError::Rejected(json::Error::InvalidField { field, message })
        if field == "world.musubi_public_directory" && message == "directory entry predates its package resolver rows"),
        "{error:?}"
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn musubi_live_revision_admission_preserves_prior_errors_and_empty_zero_budget() {
    let budget = iroha_allocation::AllocationBudget::new(0);
    validate_musubi_live_projection_cut(&World::default().view(), &budget).unwrap();
    let (mut world, release, _, _) = seeded_musubi_publication_snapshot();
    assert!(matches!(
        validate_musubi_live_projection_cut(&world.view(), &budget),
        Err(crate::execution_attempt::ExecutionAttemptError::Deferred(_))
    ));
    let mut row = world
        .musubi_resolver_index
        .view()
        .get(&release)
        .cloned()
        .unwrap();
    row.index_revision = row.selection.storage.index_revision - 1;
    world.musubi_resolver_index.insert(release, row);
    let error = validate_musubi_live_projection_cut(&world.view(), &budget).unwrap_err();
    assert!(
        matches!(&error.clone().map_rejection(ProjectionRejection::into_json), crate::execution_attempt::ExecutionAttemptError::Rejected(json::Error::InvalidField { field, message })
        if field == "world.musubi_resolver_index" && message == "resolver row predates its embedded availability projection"),
        "{error:?}"
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn musubi_live_revision_capacity_wakes_only_from_original_pool_then_retries() {
    use core::{future::Future, pin::Pin};
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };
    #[derive(Default)]
    struct Wakes(AtomicUsize);
    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let (world, _, _, _) = seeded_musubi_publication_snapshot();
    let bytes = world.musubi_public_directory.view().len()
        * core::mem::size_of::<&MusubiOrderedPackageEntryV1>();
    let budget = iroha_allocation::AllocationBudget::new(
        bytes + iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
    );
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let held = budget.try_reserve_bytes(bytes).unwrap();
    let crate::execution_attempt::ExecutionAttemptError::Deferred(refusal) =
        validate_musubi_live_projection_cut(&world.view(), &budget).unwrap_err()
    else {
        panic!("local capacity refusal")
    };
    let Some(iroha_allocation::AllocationRefusal::Capacity { release, .. }) =
        refusal.allocation_refusal()
    else {
        panic!("original release owner")
    };
    let mut future = release.clone().wait_for_release(&mut registration);
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let mut context = Context::from_waker(&waker);
    assert_eq!(Pin::new(&mut future).poll(&mut context), Poll::Pending);
    let unrelated = iroha_allocation::AllocationBudget::new(bytes);
    drop(unrelated.try_reserve_bytes(bytes).unwrap());
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    assert_eq!(Pin::new(&mut future).poll(&mut context), Poll::Pending);
    budget.set_limit_bytes(bytes - 1);
    assert!(matches!(
        validate_musubi_live_projection_cut(&world.view(), &budget),
        Err(crate::execution_attempt::ExecutionAttemptError::Deferred(_))
    ));
    drop(held);
    assert_eq!(Pin::new(&mut future).poll(&mut context), Poll::Ready(()));
    assert!(matches!(
        validate_musubi_live_projection_cut(&world.view(), &budget),
        Err(crate::execution_attempt::ExecutionAttemptError::Deferred(_))
    ));
    drop(future);
    drop(registration);
    budget.set_limit_bytes(bytes);
    validate_musubi_live_projection_cut(&world.view(), &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn musubi_restore_keeps_local_scratch_refusal_separate_from_malformed_world() {
    if crate::unit_test_support::run_in_isolated_harness(
        "state::deserialize::decode_tests::musubi_restore_keeps_local_scratch_refusal_separate_from_malformed_world",
    ) {
        return;
    }
    let (world, _, _, _) = seeded_musubi_publication_snapshot();
    let encoded = json::to_json(&world).unwrap();
    let vm = IVM::new(0);
    let seed = IvmSeed {
        ivm: &vm,
        _marker: PhantomData,
    };
    let budget = iroha_allocation::AllocationBudget::new(0);
    assert!(matches!(
        parse_world(
            &budget,
            SnapshotJsonMap::parse(&encoded, "world").unwrap(),
            &seed
        ),
        Err(StateRestoreError::Admission(
            crate::state::StateAdmissionError::Storage(
                crate::state::StateStorageAdmissionError::World(
                    mv::storage::AdmittedStorageError::Allocation(
                        iroha_allocation::AllocationRefusal::ExceedsLimit { .. }
                    )
                )
            )
        ))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    // Complete World rollback acquisition now precedes Musubi scratch. Check
    // the original scratch refusal at that exact validator boundary as well;
    // neither local resource refusal becomes malformed snapshot content.
    let Err(StateRestoreError::ExecutionDeferred(refusal)) =
        validate_musubi_live_projections(&world, &budget)
    else {
        panic!("current Musubi projection must retain its typed scratch refusal");
    };
    assert_eq!(
        refusal.allocation_refusal(),
        Some(
            &budget
                .try_reserve_bytes(core::mem::size_of::<
                    &iroha_data_model::musubi::MusubiOrderedPackageEntryV1,
                >())
                .unwrap_err()
        )
    );
    assert_eq!(budget.reserved_bytes(), 0);
    let mut malformed = SnapshotJsonMap::parse(&encoded, "world").unwrap();
    malformed.remove("account_aliases").unwrap();
    assert!(matches!(
        parse_world(&budget, malformed, &seed),
        Err(StateRestoreError::Serialization(_))
    ));
    budget.set_limit_bytes(iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES);
    let restored = parse_world(
        &budget,
        SnapshotJsonMap::parse(&encoded, "world").unwrap(),
        &seed,
    )
    .unwrap();
    let retired_generations =
        mv::cell::Cell::<u64, iroha_allocation::AllocationCharge>::allocation_layouts()
            .into_iter()
            .chain(mv::cell::Cell::<
                crate::sumeragi::amx::RetainedNativeAmx,
                iroha_allocation::AllocationCharge,
            >::allocation_layouts())
            .map(|layout| layout.size())
            .sum::<usize>();
    let retirement_pin = crossbeam_epoch::pin();
    drop(restored);
    retirement_pin.flush();
    assert_eq!(
        budget.reserved_bytes(),
        retired_generations,
        "both restored funded Cells retain their exact current and undo generations until epoch retirement",
    );
    drop(retirement_pin);
    collect_musubi_restore_ebr_until(&budget, 0);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn musubi_world_overlay_scratch_refusal_rolls_back_current_and_replacement_cuts() {
    let (world, release, _, _) = seeded_musubi_publication_snapshot();
    let original = json::to_json(&world).unwrap();
    let row = world
        .musubi_resolver_index
        .view()
        .get(&release)
        .cloned()
        .unwrap();
    let budget = iroha_allocation::AllocationBudget::new(0);
    let nexus = iroha_config::parameters::actual::Nexus::default();
    for replacement in [false, true] {
        let mut block = if replacement {
            world.block_and_revert()
        } else {
            world.block()
        };
        block
            .musubi_resolver_index
            .insert(release.clone(), row.clone());
        let Err(error) = crate::state::world_commit::PreparedWorldCommit::prepare_overlay(
            &mut block,
            &budget,
            2,
            &nexus,
            &BTreeMap::new(),
            None,
            None,
        ) else {
            panic!("occupied scratch cannot authorize preparation")
        };
        assert!(matches!(
            error,
            crate::execution_attempt::ExecutionAttemptError::Deferred(_)
        ));
        drop(block);
        assert_eq!(json::to_json(&world).unwrap(), original);
    }
    budget.set_limit_bytes(iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES);
    let mut block = world.block();
    block.musubi_resolver_index.insert(release, row);
    crate::state::world_commit::PreparedWorldCommit::prepare_overlay(
        &mut block,
        &budget,
        2,
        &nexus,
        &BTreeMap::new(),
        None,
        None,
    )
    .unwrap();
    drop(block);
    assert_eq!(json::to_json(&world).unwrap(), original);
    assert_eq!(budget.reserved_bytes(), 0);
}

fn collect_musubi_restore_ebr_until(budget: &iroha_allocation::AllocationBudget, expected: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while budget.reserved_bytes() != expected {
        assert!(
            std::time::Instant::now() < deadline,
            "original EBR custody {} != {expected}",
            budget.reserved_bytes(),
        );
        crossbeam_epoch::pin().flush();
        std::thread::yield_now();
    }
}
