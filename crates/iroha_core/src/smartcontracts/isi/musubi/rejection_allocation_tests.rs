//! Allocation observations for the production Musubi predicates and source contract.
//!
//! Fixtures and teardown remain outside each thread-local observation. The shared
//! Core allocator measures the original helper calls and borrowed table access.

use super::{MusubiSourceReadOnly, attestation_records, replication_binding};
use crate::state::{World, WorldReadOnly};
use iroha_data_model::musubi::*;

// Retain each result until after the shared observer stops, keeping result
// destruction and fixture cleanup outside the measured predicate boundary.
fn allocations_during<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    let mut result = None;
    let count = crate::test_allocations::allocations_during(|| result = Some(operation()));
    (result.expect("measured operation completed"), count)
}

fn provider_helper_sources() -> (MusubiArchiveRecordV1, MusubiArchiveLocationV1) {
    use iroha_data_model::sorafs::{capacity::ProviderId, pin_registry::*};
    use norito::json::{self, Value};
    let fixture: Value = json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/musubi/sdk_v1.json"
    )))
    .expect("canonical signed model fixture");
    let archive = fixture
        .get("routes")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .find(|route| route.get("id").and_then(Value::as_str) == Some("archive-locations"))
        .and_then(|route| route.get("response"))
        .and_then(|response| response.get("archive"))
        .unwrap();
    let archive: MusubiArchiveRecordV1 = json::from_value(archive.clone()).unwrap();
    let location = MusubiArchiveLocationV1 {
        location_id: MusubiArchiveLocationIdV1::new([1; 32]),
        archive_id: archive.archive_id,
        pin_manifest: ManifestDigest::new([2; 32]),
        replication_order: ReplicationOrderId::new([3; 32]),
        providers: vec![ProviderId::new([4; 32])],
        provider_attestation_set_digest: MusubiProviderBundleAttestationSetDigestV1::new([5; 32]),
        renew_after_epoch: 1,
        expires_at_epoch: 2,
        finalized_height: 2,
        revision: 1,
        state: MusubiArchiveLocationStateV1::Degraded,
    };
    // Warm shared codec/model initialization before observing the helper error
    // owner. These cases stop before signature verification; no crypto-memory
    // or cold initialization funding claim follows from their zero counts.
    archive.validate().unwrap();
    location.validate().unwrap();
    (archive, location)
}

fn missing_attestation_reason(
    archive: &MusubiArchiveRecordV1,
    location: &MusubiArchiveLocationV1,
    world: &impl WorldReadOnly,
) -> iroha_model_base::error::ParseError {
    match attestation_records::load_location_provider_attestations(archive, location, world) {
        Err(error) => error,
        Ok(records) => panic!(
            "empty source returned {} records / {} references",
            records.len(),
            records.iter().count()
        ),
    }
}

#[test]
fn provider_helpers_retain_warmed_missing_evidence_rejections_without_allocations() {
    let (archive, location) = provider_helper_sources();
    let world = World::new();
    let view = world.view();
    let (binding, count) = allocations_during(|| {
        replication_binding::validate_replication_order_archive_binding(
            &archive,
            &location.replication_order,
            &view,
        )
        .unwrap_err()
    });
    assert_eq!(
        count, 0,
        "missing binding needs no instruction-error String"
    );
    assert_eq!(
        binding.reason(),
        "Musubi replication order has no consensus archive binding"
    );
    let (record, count) =
        allocations_during(|| missing_attestation_reason(&archive, &location, &view));
    assert_eq!(
        count, 0,
        "missing evidence needs no instruction-error String"
    );
    assert_eq!(
        record.reason(),
        "Musubi archive location provider attestation record was not found"
    );
    assert!(!std::mem::needs_drop::<iroha_model_base::error::ParseError>());
}

#[test]
fn provider_helpers_keep_static_model_error_order_and_outlive_the_source() {
    let (mut archive, mut location) = provider_helper_sources();
    archive.location_revision = 0;
    location.revision = 0;
    let expected_archive = archive.validate().unwrap_err();
    let expected_location = location.validate().unwrap_err();
    let ((binding, record), count) = {
        let world = World::new();
        let view = world.view();
        allocations_during(|| {
            (
                replication_binding::validate_replication_order_archive_binding(
                    &archive,
                    &location.replication_order,
                    &view,
                )
                .unwrap_err(),
                missing_attestation_reason(&archive, &location, &view),
            )
        })
    };
    assert_eq!(count, 0);
    assert!(std::ptr::eq(binding.reason(), expected_archive.reason()));
    assert!(std::ptr::eq(record.reason(), expected_archive.reason()));
    archive.location_revision = 1;
    let (record, count) = {
        let world = World::new();
        let view = world.view();
        allocations_during(|| missing_attestation_reason(&archive, &location, &view))
    };
    assert_eq!(count, 0);
    assert!(std::ptr::eq(record.reason(), expected_location.reason()));
    drop((archive, location));
    assert_eq!(binding.reason(), expected_archive.reason());
    assert_eq!(record.reason(), expected_location.reason());
}

#[test]
fn shared_source_contract_borrows_every_original_world_table_without_allocations() {
    let world = World::new();
    let view = world.view();
    let ((), count) = allocations_during(|| {
        macro_rules! same {
            ($source:ident, $world:ident) => {
                assert!(std::ptr::eq(
                    std::ptr::from_ref(view.$source()).cast::<()>(),
                    std::ptr::from_ref(WorldReadOnly::$world(&view)).cast::<()>()
                ));
            };
        }
        same!(source_musubi_archives, musubi_archives);
        same!(
            source_musubi_archive_availability,
            musubi_archive_availability
        );
        same!(source_musubi_archive_locations, musubi_archive_locations);
        same!(source_musubi_locations_by_pin, musubi_locations_by_pin);
        same!(
            source_musubi_locations_by_provider,
            musubi_locations_by_provider
        );
        same!(
            source_musubi_locations_by_replication_order,
            musubi_locations_by_replication_order
        );
        same!(source_musubi_packages, musubi_packages);
        same!(
            source_musubi_provider_bundle_attestations,
            musubi_provider_bundle_attestations
        );
        same!(source_musubi_public_directory, musubi_public_directory);
        same!(source_musubi_releases, musubi_releases);
        same!(source_musubi_resolver_index, musubi_resolver_index);
        same!(source_pin_manifests, pin_manifests);
        same!(source_provider_owners, provider_owners);
        same!(source_replication_orders, replication_orders);
        assert_eq!(
            view.source_musubi_resolver_index_revision(),
            WorldReadOnly::musubi_resolver_index_revision(&view)
        );
    });
    assert_eq!(
        count, 0,
        "shared trait forwards original sources without rebuilding views"
    );
}
