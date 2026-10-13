//! Independent resource reductions, generation races, and real index-file tests.

use super::*;
use crate::kura::{
    self, FsyncMode, IndexResourceFormat, Kura, ResourceUsage, SidecarIndexLayout,
    index_resource_file_usage, index_resource_kind, index_resource_paths_usage,
    index_resource_tree_usage,
};
use std::{fs, num::NonZeroUsize, path::Path};

fn initialize_physical_fixture(kura: &Kura) {
    // A measured physical fixture baseline grants no runtime storage authority and
    // deliberately leaves residents unregistered. It is safe under fixture owner locks.
    let counts = kura
        .physical_resource_scope()
        .unwrap()
        .observe(kura.evidence_resource_limits())
        .unwrap();
    kura.resource_inventory
        .initialize(
            kura.resource_inventory.reconciliation_generation().unwrap(),
            &crate::kura::PHYSICAL_RESOURCE_FAMILIES
                .iter()
                .map(|family| (*family, counts[*family as usize]))
                .collect::<Vec<_>>(),
        )
        .unwrap();
    for family in crate::kura::PHYSICAL_RESOURCE_FAMILIES {
        assert_eq!(
            kura.resource_inventory_component_for_tests(family).unwrap(),
            counts[family as usize]
        );
    }
}

fn entries(count: u64) -> Usage {
    Usage {
        persisted_entries: count,
        index_bytes: count * 16,
        ..Usage::default()
    }
}

fn initialized() -> Inventory {
    let inventory = Inventory::default();
    let initial = ALL_FAMILIES.map(|family| (family, Usage::default()));
    inventory
        .initialize(0, &initial)
        .expect("complete independently empty owners");
    inventory
}

fn publish_total(inventory: &Inventory, family: Family, total: Usage) {
    let generation = inventory.reconciliation_generation().expect("stable epoch");
    inventory
        .initialize(generation, &[(family, total)])
        .expect("audited owner total");
}

#[test]
fn empty_requires_all_owners_and_partial_registration_never_qualifies() {
    let inventory = Inventory::default();
    assert_eq!(
        inventory.try_snapshot().unwrap_err(),
        Unavailable::Unregistered
    );
    inventory
        .initialize(0, &[(Family::CanonicalIndex, entries(0))])
        .unwrap();
    assert_eq!(
        inventory.try_snapshot().unwrap_err(),
        Unavailable::Unregistered
    );
    let complete = initialized().try_snapshot().unwrap();
    assert_eq!(complete.total, Usage::default());
    assert_eq!(complete.total.represented_entries().unwrap(), 0);
    assert_eq!(complete.components.len(), FAMILY_COUNT);
}

#[test]
fn represented_entries_preserve_resident_persisted_and_real_byte_units() {
    let inventory = initialized();
    publish_total(
        &inventory,
        Family::ResidentTransaction,
        Usage {
            resident_associations: 7,
            ..Usage::default()
        },
    );
    publish_total(
        &inventory,
        Family::PipelineIndex,
        Usage {
            persisted_entries: 5,
            index_bytes: 112,
            temporary_index_bytes: 48,
            ..Usage::default()
        },
    );
    publish_total(
        &inventory,
        Family::StorageBytes,
        Usage {
            storage_bytes: 901,
            ..Usage::default()
        },
    );
    let snapshot = inventory.try_snapshot().unwrap();
    assert_eq!(snapshot.total.resident_associations, 7);
    assert_eq!(snapshot.total.persisted_entries, 5);
    assert_eq!(snapshot.total.represented_entries().unwrap(), 12);
    assert_eq!(snapshot.total.index_bytes, 112);
    assert_eq!(snapshot.total.temporary_index_bytes, 48);
    assert_eq!(snapshot.total.storage_bytes, 901);
}

#[test]
fn concurrent_disjoint_paths_in_one_family_publish_checked_deltas() {
    let inventory = initialized();
    publish_total(&inventory, Family::CanonicalIndex, entries(7));
    let first = inventory.begin(Family::CanonicalIndex.mask()).unwrap();
    let second = inventory.begin(Family::CanonicalIndex.mask()).unwrap();
    assert_eq!(inventory.try_snapshot().unwrap_err(), Unavailable::Busy);
    second
        .publish(&[(Family::CanonicalIndex, entries(5), entries(7))])
        .unwrap();
    assert_eq!(inventory.try_snapshot().unwrap_err(), Unavailable::Busy);
    first
        .publish(&[(Family::CanonicalIndex, entries(2), entries(3))])
        .unwrap();
    let snapshot = inventory.try_snapshot().unwrap();
    assert_eq!(snapshot.total, entries(10));
    assert_eq!(snapshot.observed_high_water.persisted_entries, 10);
    // An idempotent existing-file publication changes no resource total.
    inventory
        .begin(Family::CanonicalIndex.mask())
        .unwrap()
        .publish(&[(Family::CanonicalIndex, entries(10), entries(10))])
        .unwrap();
    assert_eq!(inventory.try_snapshot().unwrap().total, entries(10));
}

#[test]
fn failed_and_incomplete_publications_invalidate_without_publishing_partial_totals() {
    let inventory = initialized();
    publish_total(&inventory, Family::CanonicalIndex, entries(4));
    let mutation = inventory
        .begin(Family::CanonicalIndex.mask() | Family::CanonicalHashes.mask())
        .unwrap();
    assert_eq!(
        mutation
            .publish(&[(Family::CanonicalIndex, entries(4), entries(2))])
            .unwrap_err(),
        Unavailable::OwnerMismatch
    );
    assert_eq!(
        inventory.try_snapshot().unwrap_err(),
        Unavailable::Interrupted
    );
    let state = inventory.state.lock();
    assert_eq!(
        state.components[Family::CanonicalIndex as usize].usage,
        entries(4)
    );
    assert!(state.fault_count > 0);
    assert_eq!(
        state.components[Family::CanonicalIndex as usize].mutations,
        0
    );
    assert_eq!(
        state.components[Family::CanonicalHashes as usize].mutations,
        0
    );
}

#[test]
fn overflow_underflow_and_generation_exhaustion_never_saturate() {
    let inventory = initialized();
    let error = inventory
        .begin(Family::CanonicalIndex.mask())
        .unwrap()
        .publish(&[(Family::CanonicalIndex, entries(1), entries(0))])
        .unwrap_err();
    assert_eq!(error, Unavailable::Arithmetic);
    assert_eq!(
        inventory.try_snapshot().unwrap_err(),
        Unavailable::Arithmetic
    );
    let overflow = initialized();
    publish_total(
        &overflow,
        Family::ResidentCanonical,
        Usage {
            resident_associations: u64::MAX,
            ..Usage::default()
        },
    );
    let generation = overflow.reconciliation_generation().unwrap();
    assert_eq!(
        overflow
            .initialize(generation, &[(Family::CanonicalIndex, entries(1))])
            .unwrap_err(),
        Unavailable::Arithmetic
    );
    assert_eq!(
        overflow.try_snapshot().unwrap_err(),
        Unavailable::Arithmetic
    );
    let exhausted = initialized();
    exhausted.state.lock().generation = u64::MAX;
    assert!(matches!(
        exhausted.begin(Family::CanonicalIndex.mask()),
        Err(Unavailable::Arithmetic)
    ));
    assert_eq!(
        exhausted.try_snapshot().unwrap_err(),
        Unavailable::Arithmetic
    );
    let count = initialized();
    count.state.lock().components[Family::CanonicalIndex as usize].mutations = u32::MAX;
    assert!(matches!(
        count.begin(Family::CanonicalIndex.mask()),
        Err(Unavailable::Arithmetic)
    ));
    assert_eq!(count.try_snapshot().unwrap_err(), Unavailable::Arithmetic);
}

#[test]
fn superseded_reconciliation_and_registry_contention_return_unavailable() {
    let inventory = initialized();
    let generation = inventory.reconciliation_generation().unwrap();
    inventory
        .begin(Family::CanonicalIndex.mask())
        .unwrap()
        .publish(&[(Family::CanonicalIndex, entries(0), entries(1))])
        .unwrap();
    assert_eq!(
        inventory
            .initialize(generation, &[(Family::CanonicalIndex, entries(0))])
            .unwrap_err(),
        Unavailable::GenerationChanged
    );
    assert_eq!(inventory.try_snapshot().unwrap().total.persisted_entries, 1);
    let guard = inventory.state.lock();
    assert_eq!(inventory.try_snapshot().unwrap_err(), Unavailable::Busy);
    assert_eq!(
        inventory.reconciliation_generation().unwrap_err(),
        Unavailable::Busy
    );
    drop(guard);
    let pending = inventory.begin(Family::CanonicalIndex.mask()).unwrap();
    drop(pending);
    assert_eq!(
        inventory.try_snapshot().unwrap_err(),
        Unavailable::Interrupted
    );
}

#[test]
fn preinitialization_writes_cannot_manufacture_an_empty_baseline() {
    let inventory = Inventory::default();
    inventory
        .begin(Family::PipelineIndex.mask())
        .unwrap()
        .publish(&[(Family::PipelineIndex, entries(7), entries(9))])
        .unwrap();
    assert_eq!(
        inventory.try_snapshot().unwrap_err(),
        Unavailable::Unregistered
    );
    assert_eq!(
        inventory.state.lock().components[Family::PipelineIndex as usize].usage,
        Usage::default()
    );
    assert!(
        inventory
            .initialize(0, &[(Family::PipelineIndex, entries(9))])
            .is_err()
    );
}

#[test]
fn real_canonical_and_pipeline_families_count_slots_headers_and_sparse_fillers() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let names = [kura::PIPELINE_SIDECARS_INDEX_FILE];
    for name in names {
        let path = root.join(name);
        let mut bytes = SidecarIndexLayout::base_header(73).to_vec();
        bytes.extend_from_slice(&[0_u8; 5 * 16]);
        fs::write(&path, &bytes).unwrap();
        let (family, format, temporary) = index_resource_kind(&path).unwrap();
        let usage = index_resource_file_usage(&path, format, temporary).unwrap();
        assert_eq!(
            usage.persisted_entries, 5,
            "base height and occupied slots are not a count"
        );
        assert_eq!(usage.index_bytes, fs::metadata(&path).unwrap().len());
        assert_eq!(usage.index_bytes, 112);
        assert_eq!(
            index_resource_paths_usage(&[path]).unwrap()[family as usize],
            usage
        );
    }
    fs::write(root.join(kura::INDEX_FILE_NAME), [0_u8; 3 * 16]).unwrap();
    fs::write(root.join(kura::HASHES_FILE_NAME), [0_u8; 3 * 32]).unwrap();
    let counts = index_resource_tree_usage(&root).unwrap();
    assert_eq!(counts[Family::CanonicalIndex as usize].persisted_entries, 3);
    assert_eq!(
        counts[Family::CanonicalHashes as usize].persisted_entries,
        3
    );
    assert_eq!(
        counts
            .iter()
            .map(|usage| usage.persisted_entries)
            .sum::<u64>(),
        11
    );
    assert_eq!(
        counts.iter().map(|usage| usage.index_bytes).sum::<u64>(),
        112 + 48 + 96
    );
}

#[test]
fn malformed_headers_trailing_bytes_links_and_unknown_index_formats_fail() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let path = root.join(kura::PIPELINE_SIDECARS_INDEX_FILE);
    for bytes in [
        vec![],
        vec![0; 32],
        SidecarIndexLayout::base_header(3)[..31].to_vec(),
        {
            let mut value = SidecarIndexLayout::base_header(3).to_vec();
            value.push(0);
            value
        },
        {
            let mut value = SidecarIndexLayout::base_header(3).to_vec();
            value[24] ^= 1;
            value
        },
    ] {
        fs::write(&path, bytes).unwrap();
        assert!(index_resource_file_usage(&path, IndexResourceFormat::SidecarV1, false).is_err());
    }
    fs::write(&path, SidecarIndexLayout::base_header(3)).unwrap();
    let header = index_resource_file_usage(&path, IndexResourceFormat::SidecarV1, false).unwrap();
    assert_eq!(header.persisted_entries, 0);
    assert_eq!(header.index_bytes, 32);
    let alias = root.join("alias");
    fs::hard_link(&path, &alias).unwrap();
    assert!(index_resource_file_usage(&path, IndexResourceFormat::SidecarV1, false).is_err());
    fs::remove_file(alias).unwrap();
    fs::write(root.join("unknown.index"), [0_u8; 16]).unwrap();
    assert!(index_resource_tree_usage(&root).is_err());
    fs::write(&path, [0_u8; 17]).unwrap();
    assert!(index_resource_file_usage(&path, IndexResourceFormat::Fixed(16), false).is_err());
}

fn fixture_pair(root: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    (
        root.join(kura::PIPELINE_SIDECARS_DATA_FILE),
        root.join(kura::PIPELINE_SIDECARS_INDEX_FILE),
    )
}

#[test]
fn real_append_sparse_growth_and_compaction_match_independent_file_lengths() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let (data, index) = fixture_pair(&root);
    assert!(Kura::append_indexed_sidecar(
        &data,
        &index,
        10,
        b"first",
        "resource fixture",
        FsyncMode::Always,
        None
    ));
    assert!(Kura::append_indexed_sidecar(
        &data,
        &index,
        14,
        b"last",
        "resource fixture",
        FsyncMode::Always,
        None
    ));
    let before = index_resource_paths_usage(&[
        index.clone(),
        index.with_extension("index.tmp"),
        index.with_extension("index.prepend.tmp"),
    ])
    .unwrap();
    assert_eq!(before[Family::PipelineIndex as usize].persisted_entries, 5);
    assert_eq!(
        before[Family::PipelineIndex as usize].index_bytes,
        32 + 5 * 16
    );
    assert!(Kura::prune_indexed_sidecars_to_retention_window(
        &data,
        &index,
        NonZeroUsize::new(2).unwrap(),
        "resource fixture"
    ));
    let after = index_resource_paths_usage(&[
        index.clone(),
        index.with_extension("index.tmp"),
        index.with_extension("index.prepend.tmp"),
    ])
    .unwrap();
    assert_eq!(after[Family::PipelineIndex as usize].persisted_entries, 2);
    assert_eq!(
        after[Family::PipelineIndex as usize].index_bytes,
        fs::metadata(&index).unwrap().len()
    );
    assert_eq!(after[Family::PipelineIndex as usize].index_bytes, 64);
}

#[test]
fn temporary_indexes_and_retained_geometry_keep_real_physical_ownership() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let active = root.join("active");
    let retained = root.join("retired");
    fs::create_dir(&active).unwrap();
    let index = active.join(kura::PIPELINE_SIDECARS_INDEX_FILE);
    let mut stable = SidecarIndexLayout::base_header(1).to_vec();
    stable.extend([0_u8; 48]);
    let mut temporary = SidecarIndexLayout::base_header(3).to_vec();
    temporary.extend([0_u8; 16]);
    fs::write(&index, stable).unwrap();
    fs::write(index.with_extension("index.tmp"), temporary).unwrap();
    let before = index_resource_tree_usage(&root).unwrap();
    assert_eq!(before[Family::PipelineIndex as usize].persisted_entries, 4);
    assert_eq!(before[Family::PipelineIndex as usize].index_bytes, 80);
    assert_eq!(
        before[Family::PipelineIndex as usize].temporary_index_bytes,
        48
    );
    fs::rename(&active, &retained).unwrap();
    assert_eq!(
        index_resource_tree_usage(&root).unwrap(),
        before,
        "retirement does not reclaim bytes"
    );
    fs::remove_dir_all(&retained).unwrap();
    assert_eq!(
        index_resource_tree_usage(&root).unwrap(),
        [ResourceUsage::default(); FAMILY_COUNT]
    );
}

#[test]
fn real_file_failure_drops_publication_and_duplicate_path_sets_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let index = root.join(kura::PIPELINE_SIDECARS_INDEX_FILE);
    fs::write(&index, SidecarIndexLayout::base_header(1)).unwrap();
    let before = index_resource_paths_usage(std::slice::from_ref(&index)).unwrap();
    let inventory = initialized();
    publish_total(
        &inventory,
        Family::PipelineIndex,
        before[Family::PipelineIndex as usize],
    );
    let mutation = inventory.begin(Family::PipelineIndex.mask()).unwrap();
    fs::write(&index, [0_u8; 7]).unwrap();
    assert!(index_resource_paths_usage(std::slice::from_ref(&index)).is_err());
    drop(mutation);
    assert_eq!(
        inventory.try_snapshot().unwrap_err(),
        Unavailable::Interrupted
    );
    fs::write(&index, SidecarIndexLayout::base_header(1)).unwrap();
    assert!(index_resource_paths_usage(&[index.clone(), index]).is_err());
    assert!(index_resource_paths_usage(&[]).is_err());
}

#[test]
fn actual_total_disk_guard_publishes_exact_index_delta_and_invalidates_unclassified_writes() {
    let kura = Kura::blank_kura_for_testing();
    let root = kura.store_root.join("blocks/resource_fixture");
    fs::create_dir(&root).unwrap();
    initialize_physical_fixture(&kura);
    let (data, index) = fixture_pair(&root);
    let _sidecar = kura.sidecar_lock.lock();
    let accounting = kura
        .begin_total_disk_usage_mutation()
        .with_resource_paths(Kura::sidecar_physical_resource_paths(&data, &index));
    assert!(Kura::append_indexed_sidecar(
        &data,
        &index,
        12,
        b"resource",
        "resource fixture",
        FsyncMode::Always,
        None
    ));
    accounting.finish();
    let component = kura.resource_inventory.state.lock().components[Family::PipelineIndex as usize];
    assert!(component.registered);
    assert_eq!(component.fault, None);
    assert_eq!(component.usage.persisted_entries, 1);
    assert_eq!(component.usage.index_bytes, 48);
    assert_eq!(
        kura.resource_inventory_snapshot().unwrap_err(),
        Unavailable::Unregistered
    );
    let unclassified = kura.begin_total_disk_usage_mutation();
    unclassified.finish();
    assert_eq!(
        kura.resource_inventory.state.lock().components[Family::PipelineIndex as usize].fault,
        Some(Unavailable::Interrupted)
    );
}

#[test]
fn singleton_record_accounting_retains_actual_bytes_and_rejects_empty_or_oversized_files() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let path = root.join(crate::query::index_status::QueryIndexJournal::JOURNAL_FILE);
    let (family, format, temporary) = index_resource_kind(&path).unwrap();
    assert_eq!(family, Family::QueryMarkerRecords);
    let bytes = vec![5_u8; 123];
    fs::write(&path, &bytes).unwrap();
    let usage = index_resource_file_usage(&path, format, temporary).unwrap();
    assert_eq!(usage.persisted_entries, 1);
    assert_eq!(usage.index_bytes, 123);
    let temporary_path = path.with_extension("norito.tmp");
    fs::write(&temporary_path, &bytes).unwrap();
    let (_, format, temporary) = index_resource_kind(&temporary_path).unwrap();
    let usage = index_resource_file_usage(&temporary_path, format, temporary).unwrap();
    assert_eq!(usage.persisted_entries, 1);
    assert_eq!(usage.temporary_index_bytes, 123);
    assert_eq!(usage.index_bytes, 0);
    fs::write(&path, []).unwrap();
    assert!(index_resource_file_usage(&path, format, false).is_err());
    let oversized = fs::File::create(&path).unwrap();
    oversized
        .set_len(crate::query::index_status::QueryIndexJournal::JOURNAL_MAX_BYTES + 1)
        .unwrap();
    assert!(index_resource_file_usage(&path, format, false).is_err());
}

#[test]
fn test_component_observation_never_qualifies_or_repairs_other_owners() {
    let inventory = Inventory::default();
    assert_eq!(
        inventory.component_usage_for_tests(Family::QueryMarkerRecords),
        Err(Unavailable::Unregistered)
    );
    inventory
        .initialize(0, &[(Family::QueryMarkerRecords, entries(2))])
        .unwrap();
    inventory.invalidate(Family::ResidentQueue.mask(), Unavailable::Interrupted);
    assert_eq!(
        inventory
            .component_usage_for_tests(Family::QueryMarkerRecords)
            .unwrap(),
        entries(2)
    );
    assert!(inventory.try_snapshot().is_err());
    let mutation = inventory.begin(Family::QueryMarkerRecords.mask()).unwrap();
    assert_eq!(
        inventory.component_usage_for_tests(Family::QueryMarkerRecords),
        Err(Unavailable::Busy)
    );
    drop(mutation);
    assert_eq!(
        inventory.component_usage_for_tests(Family::QueryMarkerRecords),
        Err(Unavailable::Interrupted)
    );
    assert_eq!(
        inventory.component_usage_for_tests(Family::ResidentQueue),
        Err(Unavailable::Interrupted)
    );
}

#[test]
fn successful_index_recovery_preserves_disk_rescan_and_failed_recovery_stays_unavailable() {
    let kura = Kura::blank_kura_for_testing();
    let root = kura.store_root.join("blocks/query_resource_fixture");
    fs::create_dir(&root).unwrap();
    let path = root.join(crate::query::index_status::QueryIndexJournal::JOURNAL_FILE);
    let temporary = path.with_extension("norito.tmp");
    fs::write(&temporary, [3_u8; 73]).unwrap();
    initialize_physical_fixture(&kura);
    kura.disk_usage_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    kura.disk_usage_total_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let accounting = kura
        .begin_total_disk_usage_mutation()
        .with_resource_paths(vec![path.clone(), temporary.clone()]);
    fs::rename(&temporary, &path).unwrap();
    accounting.finish_resources_before_disk_rescan();
    let usage = kura
        .resource_inventory_component_for_tests(Family::QueryMarkerRecords)
        .unwrap();
    assert_eq!(usage.persisted_entries, 1);
    assert_eq!(usage.index_bytes, 73);
    assert_eq!(usage.temporary_index_bytes, 0);
    assert!(
        !kura
            .disk_usage_initialized
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    assert!(
        !kura
            .disk_usage_total_initialized
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    assert!(kura.resource_inventory_snapshot().is_err());
    let failed = kura
        .begin_total_disk_usage_mutation()
        .with_resource_paths(vec![path.clone(), temporary]);
    fs::write(&path, [4_u8; 81]).unwrap();
    drop(failed);
    assert_eq!(
        kura.resource_inventory_component_for_tests(Family::QueryMarkerRecords),
        Err(Unavailable::Interrupted)
    );
}

#[test]
fn startup_children_account_more_than_twenty_four_lanes_and_require_every_completion() {
    let kura = Kura::blank_kura_for_testing();
    let root = kura.store_root.join("blocks/many_lane_resource_fixture");
    fs::create_dir(&root).unwrap();
    initialize_physical_fixture(&kura);
    let mut batch = kura
        .begin_total_disk_usage_mutation()
        .with_resource_children(30);
    for lane in 0..30 {
        let directory = root.join(lane.to_string());
        let path = directory.join(crate::query::index_status::QueryIndexJournal::JOURNAL_FILE);
        let child = batch.resource_child(vec![path.clone(), path.with_extension("norito.tmp")]);
        fs::create_dir(&directory).unwrap();
        fs::write(&path, [7_u8; 11]).unwrap();
        child.finish();
        assert_eq!(
            kura.resource_inventory_component_for_tests(Family::QueryMarkerRecords),
            Err(Unavailable::Busy)
        );
    }
    batch.finish();
    let usage = kura
        .resource_inventory_component_for_tests(Family::QueryMarkerRecords)
        .unwrap();
    assert_eq!(usage.persisted_entries, 30);
    assert_eq!(usage.index_bytes, 330);
    let mut incomplete = kura
        .begin_total_disk_usage_mutation()
        .with_resource_children(2);
    let absent = root
        .join("absent")
        .join(crate::query::index_status::QueryIndexJournal::JOURNAL_FILE);
    incomplete
        .resource_child(vec![absent.clone(), absent.with_extension("norito.tmp")])
        .finish();
    incomplete.finish();
    assert_eq!(
        kura.resource_inventory_component_for_tests(Family::QueryMarkerRecords),
        Err(Unavailable::Interrupted)
    );
}

#[test]
fn failed_or_extra_startup_child_cannot_publish_a_complete_batch() {
    for extra in [false, true] {
        let kura = Kura::blank_kura_for_testing();
        initialize_physical_fixture(&kura);
        let path = kura
            .store_root
            .join("blocks")
            .join(crate::query::index_status::QueryIndexJournal::JOURNAL_FILE);
        let mut batch = kura
            .begin_total_disk_usage_mutation()
            .with_resource_children(1);
        let child = batch.resource_child(vec![path.clone(), path.with_extension("norito.tmp")]);
        fs::write(&path, [8_u8; 19]).unwrap();
        if extra {
            child.finish();
            batch
                .resource_child(vec![path.clone(), path.with_extension("norito.tmp")])
                .finish();
        } else {
            drop(child);
        }
        batch.finish();
        assert!(
            kura.resource_inventory_component_for_tests(Family::QueryMarkerRecords)
                .is_err()
        );
    }
}

#[test]
fn every_query_marker_uses_its_real_owner_bound_and_temporary_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    for (name, bound) in [
        (crate::query::index_status::QueryIndexJournal::JOURNAL_FILE, crate::query::index_status::QueryIndexJournal::JOURNAL_MAX_BYTES),
        (crate::query::projection_checkpoint_journal::QueryProjectionCheckpointJournal::JOURNAL_FILE, crate::query::projection_checkpoint_journal::QUERY_PROJECTION_CHECKPOINT_JOURNAL_MAX_BYTES as u64),
    ] {
        let path = root.join(name);
        let temporary_path = path.with_extension("norito.tmp");
        let (family, format, temporary) = index_resource_kind(&temporary_path).unwrap();
        assert_eq!(family, Family::QueryMarkerRecords);
        assert!(temporary);
        let file = fs::File::create(&temporary_path).unwrap();
        file.set_len(bound).unwrap();
        let usage = index_resource_file_usage(&temporary_path, format, true).unwrap();
        assert_eq!(usage.persisted_entries, 1);
        assert_eq!(usage.temporary_index_bytes, bound);
        assert_eq!(usage.index_bytes, 0);
        file.set_len(bound + 1).unwrap();
        assert!(index_resource_file_usage(&temporary_path, format, true).is_err());
    }
}

#[test]
fn missing_paths_require_real_parent_binding_and_depth_is_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let absent = root.join("absent").join(kura::INDEX_FILE_NAME);
    assert_eq!(
        index_resource_paths_usage(&[absent]).unwrap(),
        [Usage::default(); FAMILY_COUNT]
    );
    assert!(index_resource_tree_usage(Path::new("relative_missing_inventory")).is_err());
    let mut nested = root.clone();
    for _ in 0..kura::INDEX_RESOURCE_MAX_DEPTH {
        nested = nested.join("d");
        fs::create_dir(&nested).unwrap();
    }
    assert!(index_resource_tree_usage(&root).is_err());
}

#[cfg(unix)]
#[test]
fn symlinked_parent_never_proves_an_absent_index_or_empty_tree() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let actual = root.join("actual");
    let linked = root.join("linked");
    fs::create_dir(&actual).unwrap();
    std::os::unix::fs::symlink(&actual, &linked).unwrap();
    assert!(index_resource_paths_usage(&[linked.join(kura::INDEX_FILE_NAME)]).is_err());
    assert!(index_resource_tree_usage(&linked.join("absent")).is_err());
    assert!(index_resource_tree_usage(&linked).is_err());
}

#[test]
fn read_recovery_counts_staged_slots_once_before_the_followup_writer() {
    let kura = Kura::blank_kura_for_testing();
    let root = kura.store_dir().unwrap().join(kura::PIPELINE_DIR_NAME);
    fs::create_dir_all(&root).unwrap();
    let (data, index) = fixture_pair(&root);
    let _sidecar = kura.sidecar_lock.lock();
    assert!(Kura::append_indexed_sidecar(
        &data,
        &index,
        10,
        b"payload",
        "resource fixture",
        FsyncMode::Always,
        None
    ));
    fs::copy(&data, data.with_extension("norito.tmp")).unwrap();
    fs::copy(&index, index.with_extension("index.tmp")).unwrap();
    initialize_physical_fixture(&kura);
    let before = kura
        .resource_inventory_component_for_tests(Family::PipelineIndex)
        .unwrap();
    assert_eq!(before.persisted_entries, 2);
    assert_eq!(before.index_bytes, 48);
    assert_eq!(before.temporary_index_bytes, 48);
    assert_eq!(
        kura.read_pipeline_sidecar(
            10,
            kura::PIPELINE_SIDECARS_DATA_FILE,
            kura::PIPELINE_SIDECARS_INDEX_FILE,
            |_| Ok::<_, norito::Error>(()),
            "resource fixture"
        ),
        Some(())
    );
    let recovered = kura
        .resource_inventory_component_for_tests(Family::PipelineIndex)
        .unwrap();
    assert_eq!(recovered.persisted_entries, 1);
    assert_eq!(recovered.index_bytes, 48);
    assert_eq!(recovered.temporary_index_bytes, 0);
    let append = kura
        .begin_total_disk_usage_mutation()
        .with_resource_paths(Kura::sidecar_physical_resource_paths(&data, &index));
    assert!(Kura::append_indexed_sidecar(
        &data,
        &index,
        11,
        b"next",
        "resource fixture",
        FsyncMode::Always,
        None
    ));
    append.finish();
    let after = kura
        .resource_inventory_component_for_tests(Family::PipelineIndex)
        .unwrap();
    assert_eq!(after.persisted_entries, 2);
    assert_eq!(after.index_bytes, 64);
    assert_eq!(after.temporary_index_bytes, 0);
    // An ordinary recovery-enabled read with no staged pair does no accounting mutation.
    let generation = kura.resource_inventory.reconciliation_generation().unwrap();
    kura.disk_usage_total_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(kura.recover_indexed_sidecar_with_physical_resources(
        &data,
        &index,
        "resource fixture"
    ));
    assert_eq!(
        kura.resource_inventory.reconciliation_generation().unwrap(),
        generation
    );
    assert!(
        kura.disk_usage_total_initialized
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    // An orphan payload temporary is an actual failed recovery, even when no index slot changed.
    fs::write(data.with_extension("norito.tmp"), b"orphan").unwrap();
    assert!(!kura.recover_indexed_sidecar_with_physical_resources(
        &data,
        &index,
        "resource fixture"
    ));
    assert_eq!(
        kura.resource_inventory_component_for_tests(Family::PipelineIndex),
        Err(Unavailable::Interrupted)
    );
}

#[test]
fn pipeline_owner_rejects_a_failed_append_even_when_measured_lengths_are_unchanged() {
    let kura = Kura::blank_kura_for_testing();
    initialize_physical_fixture(&kura);
    let before = kura
        .resource_inventory_component_for_tests(Family::PipelineIndex)
        .unwrap();
    let sidecar = kura::PipelineRecoverySidecar::new(
        0,
        iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"failed resource append"),
        ),
        kura::PipelineDagSnapshot {
            fingerprint: [5; 32],
            key_count: 0,
        },
        Vec::new(),
    );
    kura.write_pipeline_metadata(&sidecar);
    assert_eq!(
        kura.resource_inventory_component_for_tests(Family::PipelineIndex),
        Err(Unavailable::Interrupted)
    );
    let after = index_resource_tree_usage(&kura.store_root).unwrap();
    assert_eq!(after[Family::PipelineIndex as usize], before);
}

#[test]
fn geometry_guards_preserve_moves_and_publish_only_completed_retirement_deletions() {
    let kura = Kura::blank_kura_for_testing();
    let active = kura.store_root.join("blocks/resource_active");
    let retired = kura.store_root.join("blocks/resource_retired");
    let quarantine = kura.store_root.join("blocks/resource_quarantine");
    fs::create_dir(&active).unwrap();
    fs::write(active.join(kura::INDEX_FILE_NAME), [0_u8; 48]).unwrap();
    initialize_physical_fixture(&kura);
    let before = kura
        .resource_inventory_component_for_tests(Family::CanonicalIndex)
        .unwrap();
    let moving = kura
        .begin_total_disk_usage_mutation()
        .with_resource_tree_move(&active, &retired);
    fs::rename(&active, &retired).unwrap();
    moving.finish();
    assert_eq!(
        kura.resource_inventory_component_for_tests(Family::CanonicalIndex)
            .unwrap(),
        before
    );
    let deleting = kura
        .begin_total_disk_usage_mutation()
        .with_resource_tree_move(&retired, &quarantine);
    fs::rename(&retired, &quarantine).unwrap();
    fs::remove_dir_all(&quarantine).unwrap();
    deleting.finish();
    let after = kura
        .resource_inventory_component_for_tests(Family::CanonicalIndex)
        .unwrap();
    assert_eq!(after.persisted_entries + 3, before.persisted_entries);
    assert_eq!(after.index_bytes + 48, before.index_bytes);
    fs::create_dir(&retired).unwrap();
    fs::write(retired.join(kura::INDEX_FILE_NAME), [0_u8; 16]).unwrap();
    initialize_physical_fixture(&kura);
    let failed = kura
        .begin_total_disk_usage_mutation()
        .removing_resource_tree(&retired);
    failed.finish();
    assert_eq!(
        kura.resource_inventory_component_for_tests(Family::CanonicalIndex),
        Err(Unavailable::Interrupted)
    );
    assert!(retired.exists());
}

#[test]
fn non_sidecar_temporary_names_require_exact_owner_grammar() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    for name in [
        "0.norito",
        "01.norito",
        "1.norito",
        "1.norito.tmp",
        "unowned.norito",
    ] {
        assert!(index_resource_kind(&root.join(name)).is_none());
    }
    for name in [
        kura::INDEX_FILE_NAME,
        kura::HASHES_FILE_NAME,
        crate::query::index_status::QueryIndexJournal::JOURNAL_FILE,
        crate::query::projection_checkpoint_journal::QueryProjectionCheckpointJournal::JOURNAL_FILE,
    ] {
        assert!(index_resource_kind(&root.join(format!("{name}.prepend.tmp"))).is_none());
    }
}
