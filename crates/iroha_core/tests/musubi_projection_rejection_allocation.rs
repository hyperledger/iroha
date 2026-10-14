//! Actual allocation observations for the shared static Musubi rejection owner.

#[path = "../src/state/deserialize_world_musubi_rejection.rs"]
mod rejection;

use rejection::{ProjectionCut, ProjectionRejection, ProjectionTable};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    fmt::Write as _,
};

thread_local! {
    static COUNT: Cell<Option<usize>> = const { Cell::new(None) };
}
struct Allocator;
fn record_allocation() {
    let _ = COUNT.try_with(|count| {
        if let Some(value) = count.get() {
            count.set(Some(value + 1));
        }
    });
}
#[allow(unsafe_code)]
// SAFETY: every allocation delegates its original request to System.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: the unmodified request is passed to the system allocator.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: the unmodified request is passed to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation();
        // SAFETY: the original allocation and requested size are forwarded.
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the original pointer and layout return to the same allocator.
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

struct Observation;
impl Drop for Observation {
    fn drop(&mut self) {
        COUNT.with(|count| count.set(None));
    }
}
fn allocations_during<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    COUNT.with(|count| {
        assert!(count.get().is_none(), "observations must not overlap");
        count.set(Some(0));
    });
    let observation = Observation;
    let result = operation();
    let count = COUNT.with(|count| count.get().unwrap());
    drop(observation);
    (result, count)
}

const TABLES: [ProjectionTable; 6] = [
    ProjectionTable::Archives,
    ProjectionTable::ArchiveLocations,
    ProjectionTable::ProviderBundleAttestations,
    ProjectionTable::ArchiveAvailability,
    ProjectionTable::ResolverIndex,
    ProjectionTable::PublicDirectory,
];
const CUTS: [(Option<ProjectionCut>, &str); 5] = [
    (None, ""),
    (Some(ProjectionCut::Current), "current World cut: "),
    (Some(ProjectionCut::Predecessor), "predecessor World cut: "),
    (Some(ProjectionCut::Capture), "capture World cut: "),
    (Some(ProjectionCut::Candidate), "candidate World cut: "),
];
struct Text {
    bytes: [u8; 512],
    len: usize,
}
impl Text {
    fn new() -> Self {
        Self {
            bytes: [0; 512],
            len: 0,
        }
    }
    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).unwrap()
    }
}
impl std::fmt::Write for Text {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(std::fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(std::fmt::Error)?
            .copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}

#[test]
fn static_rejections_preserve_all_contexts_and_format_without_allocation() {
    let model_error = iroha_model_base::error::ParseError::new("model reason: λ");
    for table in TABLES {
        for (cut, prefix) in CUTS {
            let expected = format!(
                "JSON error: invalid field `{}`: {prefix}{}",
                table.field(),
                model_error.reason()
            );
            let ((rejection, text), count) = allocations_during(|| {
                let rejection = ProjectionRejection::new(table, model_error.reason());
                let rejection = cut.map_or(rejection, |cut| rejection.with_cut(cut));
                let copied = std::hint::black_box(rejection);
                let mut text = Text::new();
                write!(&mut text, "{copied}").unwrap();
                (copied, text)
            });
            assert_eq!(count, 0, "static owner and borrowed output cannot allocate");
            assert_eq!(text.as_str(), expected);
            assert_eq!(rejection.field(), table.field());
            assert_eq!(rejection.reason(), model_error.reason());
            assert!(std::ptr::eq(rejection.reason(), model_error.reason()));
        }
    }
    assert!(!std::mem::needs_drop::<ProjectionRejection>());
}

#[test]
fn owned_restore_rendering_matches_the_original_json_error_exactly() {
    for table in TABLES {
        for (cut, prefix) in CUTS {
            let rejection = ProjectionRejection::new(table, "exact failure");
            let rejection = cut.map_or(rejection, |cut| rejection.with_cut(cut));
            let expected = norito::json::Error::InvalidField {
                field: table.field().to_owned(),
                message: format!("{prefix}exact failure"),
            };
            let (actual, count) = allocations_during(|| rejection.into_json());
            assert!(
                count >= 2,
                "the existing owned boundary is explicitly outside static custody"
            );
            assert_eq!(actual.to_string(), expected.to_string());
            let norito::json::Error::InvalidField { field, message } = actual else {
                panic!("restore keeps the exact original error shape")
            };
            assert_eq!(field, table.field());
            assert_eq!(message, format!("{prefix}exact failure"));
            assert_eq!(rejection.to_string(), expected.to_string());
        }
    }
}

#[test]
fn allocator_observer_detects_backing_growth_and_recovers_after_unwind() {
    let (value, count) = allocations_during(|| {
        let mut value = Vec::with_capacity(std::hint::black_box(8));
        value.resize(8, 0_u8);
        value.reserve_exact(std::hint::black_box(1024));
        std::hint::black_box(value)
    });
    assert!(count >= 2);
    drop(value);
    let _ = std::panic::catch_unwind(|| allocations_during(|| panic!("observer unwind")));
    let (_rejection, count) = allocations_during(|| {
        std::hint::black_box(ProjectionRejection::new(
            ProjectionTable::Archives,
            "static",
        ))
    });
    assert_eq!(count, 0);
}

// Include the production helpers, not a copied predicate or diagnostic shim.
#[path = "../src/state/deserialize_world_musubi_source_traits.rs"]
mod source_traits;
use source_traits::{
    MusubiSourceReadOnly,
    access::{MusubiEvidenceRead, ReadFailure},
};
#[path = "../src/smartcontracts/isi/musubi/attestation_records.rs"]
mod attestation_records;
#[path = "../src/smartcontracts/isi/musubi/replication_binding.rs"]
mod replication_binding;
use iroha_core::state::{World, WorldReadOnly};
use iroha_data_model::musubi::*;

fn provider_helper_sources() -> (MusubiArchiveRecordV1, MusubiArchiveLocationV1) {
    use iroha_data_model::sorafs::{capacity::ProviderId, pin_registry::*};
    use norito::json::{self, Value};
    let fixture: Value = json::from_str(include_str!("../../../fixtures/musubi/sdk_v1.json"))
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
