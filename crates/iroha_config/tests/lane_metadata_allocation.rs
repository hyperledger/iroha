//! Actual allocator observation for borrowed lane catalog validation.

use iroha_config::parameters::actual::{LaneConfig, Nexus};
use iroha_data_model::da::confidential_compute::{
    ConfidentialComputeMechanism, ConfidentialComputePolicy,
};
use iroha_data_model::nexus::{
    DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig as Metadata, LaneVisibility,
};
use iroha_model_base::topology::DataSpaceId;
use std::collections::BTreeSet;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    num::NonZeroU32,
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
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: unchanged allocation request is forwarded to the system.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: unchanged live pointer and layout are returned to the system.
        unsafe { System.dealloc(pointer, layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation();
        // SAFETY: unchanged live allocation and requested size are forwarded.
        unsafe { System.realloc(pointer, layout, size) }
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

#[test]
fn canonical_and_rejected_metadata_checks_allocate_nothing() {
    let metadata = Metadata {
        alias: "__Long Mixed 東京 Alias__".into(),
        storage: iroha_data_model::nexus::LaneStorageProfile::SplitReplica,
        confidential_compute: Some(ConfidentialComputePolicy::new(
            ConfidentialComputeMechanism::Encryption,
            NonZeroU32::MIN,
            BTreeSet::from(["original audience".into()]),
        )),
        ..Metadata::default()
    };
    let catalog = LaneCatalog::new(NonZeroU32::MIN, vec![metadata.clone()]).unwrap();
    let config = LaneConfig::from_catalog(&catalog);
    let foreign_catalog = LaneCatalog::default();
    let entry = config.primary();
    let mut drifted = entry.clone();
    drifted.merge_segment.push('x');
    // Initialize thread-local observation before counting. Assertions that can
    // allocate diagnostics run only after observation has stopped.
    COUNT.with(|count| count.set(Some(0)));
    let scope = Observation;
    let mut valid = true;
    for _ in 0..128 {
        valid &= std::hint::black_box(entry).matches_metadata(std::hint::black_box(&metadata));
        valid &= !std::hint::black_box(&drifted).matches_metadata(std::hint::black_box(&metadata));
        valid &= std::hint::black_box(&config).matches_catalog(std::hint::black_box(&catalog));
        valid &=
            !std::hint::black_box(&config).matches_catalog(std::hint::black_box(&foreign_catalog));
    }
    let allocations = COUNT.with(|count| count.get().unwrap());
    drop(scope);
    assert!(valid);
    assert_eq!(
        allocations, 0,
        "catalog validation may not clone or render heap data"
    );
}

#[test]
fn original_private_root_geometry_checks_allocate_nothing() {
    let home = DataSpaceId::new(u64::MAX);
    let mut nexus = Nexus::default();
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id: home,
        alias: "private".into(),
        ..DataSpaceMetadata::default()
    }])
    .unwrap();
    nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
    nexus.lane_catalog = LaneCatalog::new(
        NonZeroU32::MIN,
        vec![Metadata {
            dataspace_id: home,
            visibility: LaneVisibility::Restricted,
            alias: "__Original Private 東京 Root__".into(),
            ..Metadata::default()
        }],
    )
    .unwrap();
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    nexus.lane_config = LaneConfig::from_catalog(&nexus.lane_catalog);
    nexus.routing_policy.default_dataspace = home;
    let mut foreign_derived = nexus.clone();
    foreign_derived.lane_config = LaneConfig::default();
    let mut foreign_route = nexus.clone();
    foreign_route.routing_policy.default_dataspace = DataSpaceId::UNIVERSAL;
    assert!(nexus.validate_private_root_geometry(home).is_ok());
    assert!(
        foreign_derived
            .validate_private_root_geometry(home)
            .is_err()
    );
    assert!(foreign_route.validate_private_root_geometry(home).is_err());
    COUNT.with(|count| count.set(Some(0)));
    let scope = Observation;
    let mut valid = true;
    for _ in 0..128 {
        valid &= std::hint::black_box(&nexus)
            .validate_private_root_geometry(std::hint::black_box(home))
            .is_ok();
        valid &= std::hint::black_box(&foreign_derived)
            .validate_private_root_geometry(std::hint::black_box(home))
            .is_err();
        valid &= std::hint::black_box(&foreign_route)
            .validate_private_root_geometry(std::hint::black_box(home))
            .is_err();
    }
    let allocations = COUNT.with(|count| count.get().unwrap());
    drop(scope);
    assert!(valid);
    assert_eq!(
        allocations, 0,
        "private execution geometry must borrow the original catalog and derived graph"
    );
}
