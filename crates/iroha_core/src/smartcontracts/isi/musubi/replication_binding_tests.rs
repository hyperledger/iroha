// Borrowed lifecycle custody and unchanged rejection order on actual World rows.

#[test]
fn replication_binding_borrows_original_lifecycle_for_every_valid_variant() {
    let (mut world, key) = current_provider_fixture(1);
    let location = world
        .musubi_archive_locations
        .view()
        .get(&key)
        .cloned()
        .unwrap();
    let archive = world
        .musubi_archives
        .view()
        .get(&key.archive_id)
        .cloned()
        .unwrap();
    let original = world
        .musubi_locations_by_replication_order
        .view()
        .get(&location.replication_order)
        .cloned()
        .unwrap();
    for lifecycle in [
        MusubiReplicationOrderLocationLifecycleV1::PreLocation,
        MusubiReplicationOrderLocationLifecycleV1::Active(key),
        MusubiReplicationOrderLocationLifecycleV1::Retired(
            MusubiRetiredReplicationOrderLocationV1::new(key, location.providers.clone()),
        ),
    ] {
        let mut reference = original.clone();
        reference.lifecycle = lifecycle;
        reference.validate().unwrap();
        world
            .musubi_locations_by_replication_order
            .insert(location.replication_order, reference);
        let view = world.view();
        let retained = view
            .musubi_locations_by_replication_order()
            .get(&location.replication_order)
            .unwrap();
        let observed = validate_replication_order_archive_binding(
            &archive,
            &location.replication_order,
            &view,
        )
        .unwrap();
        assert!(std::ptr::eq(observed, &raw const retained.lifecycle));
        if let (
            MusubiReplicationOrderLocationLifecycleV1::Retired(left),
            MusubiReplicationOrderLocationLifecycleV1::Retired(right),
        ) = (observed, &retained.lifecycle)
        {
            assert_eq!(left.providers.as_ptr(), right.providers.as_ptr());
        }
    }
}

#[test]
fn active_location_rejects_retired_order_without_copying_historical_providers() {
    for count in [1, MUSUBI_MAX_LOCATION_PROVIDERS_V1] {
        let (mut world, key) = current_provider_fixture(count);
        let location = world
            .musubi_archive_locations
            .view()
            .get(&key)
            .cloned()
            .unwrap();
        assert_ne!(location.state, MusubiArchiveLocationStateV1::Retired);
        assert_eq!(
            current_location_providers(&location, &world.view())
                .unwrap()
                .len(),
            count
        );
        let mut reference = world
            .musubi_locations_by_replication_order
            .view()
            .get(&location.replication_order)
            .cloned()
            .unwrap();
        reference.lifecycle = MusubiReplicationOrderLocationLifecycleV1::Retired(
            MusubiRetiredReplicationOrderLocationV1::new(key, location.providers.clone()),
        );
        reference.validate().unwrap();
        world
            .musubi_locations_by_replication_order
            .insert(location.replication_order, reference);
        let view = world.view();
        let archive = view.musubi_archives().get(&key.archive_id).unwrap();
        let retained = view
            .musubi_locations_by_replication_order()
            .get(&location.replication_order)
            .unwrap();
        let observed =
            validate_replication_order_archive_binding(archive, &location.replication_order, &view)
                .unwrap();
        assert!(std::ptr::eq(observed, &raw const retained.lifecycle));
        assert!(current_location_providers(&location, &view).is_none());
        assert!(
            std::ptr::eq(observed, &raw const retained.lifecycle),
            "failed current-provider read must retain the original historical owner"
        );
    }
}

#[test]
fn replication_binding_preserves_archive_missing_reference_and_identity_error_order() {
    let (mut world, key) = current_provider_fixture(1);
    let location = world
        .musubi_archive_locations
        .view()
        .get(&key)
        .cloned()
        .unwrap();
    let archive = world
        .musubi_archives
        .view()
        .get(&key.archive_id)
        .cloned()
        .unwrap();
    let mut reference = world
        .musubi_locations_by_replication_order
        .view()
        .get(&location.replication_order)
        .cloned()
        .unwrap();
    let mut invalid_archive = archive.clone();
    invalid_archive.location_revision = 0;
    {
        let mut rows = world.musubi_locations_by_replication_order.block();
        let _ = rows.remove(location.replication_order);
        rows.commit();
    }
    let expected = invariant(invalid_archive.validate().unwrap_err().reason()).to_string();
    assert_eq!(
        validate_replication_order_archive_binding(
            &invalid_archive,
            &location.replication_order,
            &world.view()
        )
        .map_err(|error| invariant(error.reason()))
        .unwrap_err()
        .to_string(),
        expected
    );
    assert_eq!(
        validate_replication_order_archive_binding(
            &archive,
            &location.replication_order,
            &world.view()
        )
        .map_err(|error| invariant(error.reason()))
        .unwrap_err()
        .to_string(),
        invariant("Musubi replication order has no consensus archive binding").to_string()
    );

    reference.binding.replication_order =
        iroha_data_model::sorafs::pin_registry::ReplicationOrderId([0xee; 32]);
    reference.lifecycle = MusubiReplicationOrderLocationLifecycleV1::Retired(
        MusubiRetiredReplicationOrderLocationV1::new(key, Vec::new()),
    );
    let expected = invariant(reference.validate().unwrap_err().reason()).to_string();
    world
        .musubi_locations_by_replication_order
        .insert(location.replication_order, reference.clone());
    assert_eq!(
        validate_replication_order_archive_binding(
            &archive,
            &location.replication_order,
            &world.view()
        )
        .map_err(|error| invariant(error.reason()))
        .unwrap_err()
        .to_string(),
        expected
    );
    reference.lifecycle = MusubiReplicationOrderLocationLifecycleV1::Active(key);
    reference.validate().unwrap();
    world
        .musubi_locations_by_replication_order
        .insert(location.replication_order, reference);
    assert_eq!(
        validate_replication_order_archive_binding(
            &archive,
            &location.replication_order,
            &world.view()
        )
        .map_err(|error| invariant(error.reason()))
        .unwrap_err()
        .to_string(),
        invariant(
            "Musubi replication-order binding does not match the authoritative archive commitment"
        )
        .to_string()
    );
}

#[test]
fn replication_binding_rejection_keeps_model_reason_until_instruction_boundary() {
    let (world, key) = current_provider_fixture(1);
    let mut archive = world
        .musubi_archives
        .view()
        .get(&key.archive_id)
        .cloned()
        .unwrap();
    let order = world
        .musubi_archive_locations
        .view()
        .get(&key)
        .unwrap()
        .replication_order;
    archive.location_revision = 0;
    let model = archive.validate().unwrap_err();
    let error =
        validate_replication_order_archive_binding(&archive, &order, &world.view()).unwrap_err();
    assert!(std::ptr::eq(error.reason(), model.reason()));
    drop((world, archive));
    let mapped = invariant(error.reason());
    assert_eq!(mapped.to_string(), invariant(model.reason()).to_string());
    let Error::InvariantViolation(message) = mapped else {
        panic!("instruction adapter must preserve the original error variant")
    };
    assert_eq!(message.as_ref(), model.reason());
}
