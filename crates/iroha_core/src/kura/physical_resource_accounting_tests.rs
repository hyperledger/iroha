//! Real-file byte accounting and atomic publication across physical resource families.

use std::fs;

use super::*;
use resource_inventory::{Inventory, Unavailable};

fn limits() -> EvidenceResourceLimits {
    EvidenceResourceLimits {
        fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
    }
}

fn initialize_physical(inventory: &Inventory, counts: &IndexResourceCounts) {
    inventory
        .initialize(
            inventory.reconciliation_generation().unwrap(),
            &PHYSICAL_RESOURCE_FAMILIES
                .iter()
                .map(|family| (*family, counts[*family as usize]))
                .collect::<Vec<_>>(),
        )
        .unwrap();
}

fn mutation(inventory: &Inventory, paths: Vec<PathBuf>) -> PhysicalResourceMutation<'_> {
    let token = inventory.begin(physical_resource_mask()).unwrap();
    PhysicalResourceMutation {
        mutation: token,
        before: [ResourceUsage::default(); resource_inventory::FAMILY_COUNT],
        target: PhysicalResourceTarget::ChildBatch,
        bindings: PhysicalResourceBindings(Vec::new()),
        limits: limits(),
    }
    .bind(PhysicalResourceTarget::Paths(paths))
    .unwrap()
}

#[test]
fn physical_bytes_include_real_data_headers_and_temporary_records_once() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let data = root.join(DATA_FILE_NAME);
    let index = root.join(INDEX_FILE_NAME);
    let stable = root.join(crate::query::index_status::QueryIndexJournal::JOURNAL_FILE);
    let temporary = stable.with_extension("norito.tmp");
    fs::write(&data, [7_u8; 31]).unwrap();
    fs::write(&index, [0_u8; 32]).unwrap();
    fs::write(&stable, [1_u8; 9]).unwrap();
    fs::write(&temporary, [2_u8; 11]).unwrap();
    let paths = [data, index, stable, temporary];
    let expected = paths
        .iter()
        .map(|path| fs::metadata(path).unwrap().len())
        .sum::<u64>();
    let counts = physical_resource_paths_usage(&paths, limits()).unwrap();
    assert_eq!(
        counts[ResourceFamily::StorageBytes as usize].storage_bytes,
        expected
    );
    assert_eq!(expected, 83);
    assert_eq!(
        counts[ResourceFamily::CanonicalIndex as usize].persisted_entries,
        2
    );
    assert_eq!(
        counts[ResourceFamily::QueryMarkerRecords as usize].persisted_entries,
        2
    );
    assert_eq!(
        counts[ResourceFamily::QueryMarkerRecords as usize].index_bytes,
        9
    );
    assert_eq!(
        counts[ResourceFamily::QueryMarkerRecords as usize].temporary_index_bytes,
        11
    );
    assert_eq!(
        physical_resource_tree_usage(&root, limits()).unwrap(),
        counts
    );
    let inventory = Inventory::default();
    initialize_physical(&inventory, &counts);
    assert_eq!(
        inventory.try_snapshot().unwrap_err(),
        Unavailable::Unregistered
    );
}

#[test]
fn physical_byte_observation_handles_empty_sparse_and_absent_data_without_payload_reads() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let data = root.join(DATA_FILE_NAME);
    assert_eq!(storage_resource_file_bytes(&data).unwrap(), 0);
    let file = fs::File::create(&data).unwrap();
    assert_eq!(storage_resource_file_bytes(&data).unwrap(), 0);
    file.set_len(1_048_576).unwrap();
    assert_eq!(
        storage_resource_file_bytes(&data).unwrap(),
        file.metadata().unwrap().len()
    );
    file.set_len(17).unwrap();
    assert_eq!(storage_resource_file_bytes(&data).unwrap(), 17);
    assert!(storage_resource_file_bytes(&root).is_err());
}

#[test]
fn physical_path_sets_reject_duplicates_unknown_index_formats_and_excess_cardinality() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let data = root.join(DATA_FILE_NAME);
    fs::write(&data, [0_u8; 7]).unwrap();
    assert_eq!(
        physical_resource_paths_usage(&[data.clone(), data.clone()], limits()).unwrap_err(),
        Unavailable::OwnerMismatch
    );
    assert!(physical_resource_paths_usage(&[], limits()).is_err());
    let paths = (0..=INDEX_RESOURCE_MAX_PATHS)
        .map(|index| root.join(format!("{index}.data")))
        .collect::<Vec<_>>();
    assert!(physical_resource_paths_usage(&paths, limits()).is_err());
    let unknown = root.join("future.index");
    fs::write(&unknown, [0_u8; 16]).unwrap();
    assert_eq!(
        physical_resource_paths_usage(&[unknown], limits()).unwrap_err(),
        Unavailable::OwnerMismatch
    );
    assert_eq!(
        physical_resource_tree_usage(&root, limits()).unwrap_err(),
        Unavailable::OwnerMismatch
    );
}

#[test]
fn disjoint_physical_writers_publish_checked_deltas_without_overlapping_byte_snapshots() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let data = root.join(DATA_FILE_NAME);
    let index = root.join(INDEX_FILE_NAME);
    fs::write(&data, [1_u8; 9]).unwrap();
    fs::write(&index, [0_u8; 16]).unwrap();
    let inventory = Inventory::default();
    initialize_physical(
        &inventory,
        &physical_resource_tree_usage(&root, limits()).unwrap(),
    );
    let left = mutation(&inventory, vec![data.clone()]);
    let right = mutation(&inventory, vec![index.clone()]);
    fs::write(&data, [2_u8; 23]).unwrap();
    fs::write(&index, [0_u8; 48]).unwrap();
    right.finish().unwrap();
    assert_eq!(
        inventory
            .component_usage_for_tests(ResourceFamily::StorageBytes)
            .unwrap_err(),
        Unavailable::Busy
    );
    left.finish().unwrap();
    let observed = physical_resource_tree_usage(&root, limits()).unwrap();
    for family in PHYSICAL_RESOURCE_FAMILIES {
        assert_eq!(
            inventory.component_usage_for_tests(family).unwrap(),
            observed[family as usize]
        );
    }
    assert_eq!(
        observed[ResourceFamily::StorageBytes as usize].storage_bytes,
        71
    );
}

#[test]
fn interrupted_or_invalid_physical_completion_never_publishes_partial_success() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let data = root.join(DATA_FILE_NAME);
    fs::write(&data, [1_u8; 9]).unwrap();
    let inventory = Inventory::default();
    initialize_physical(
        &inventory,
        &physical_resource_tree_usage(&root, limits()).unwrap(),
    );
    let interrupted = mutation(&inventory, vec![data.clone()]);
    fs::write(&data, [2_u8; 17]).unwrap();
    drop(interrupted);
    assert!(
        inventory
            .component_usage_for_tests(ResourceFamily::StorageBytes)
            .is_err()
    );
    initialize_physical(
        &inventory,
        &physical_resource_tree_usage(&root, limits()).unwrap(),
    );
    assert_eq!(
        inventory
            .component_usage_for_tests(ResourceFamily::StorageBytes)
            .unwrap()
            .storage_bytes,
        17
    );
    let invalid = mutation(&inventory, vec![data.clone()]);
    fs::remove_file(&data).unwrap();
    fs::create_dir(&data).unwrap();
    assert!(invalid.finish().is_err());
    for family in PHYSICAL_RESOURCE_FAMILIES {
        assert!(inventory.component_usage_for_tests(family).is_err());
    }
}

#[test]
fn physical_tree_depth_and_zero_owner_registration_remain_bounded_and_explicit() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let mut next = root.clone();
    for _ in 0..=INDEX_RESOURCE_MAX_DEPTH {
        next.push("d");
        fs::create_dir(&next).unwrap();
    }
    assert!(physical_resource_tree_usage(&root, limits()).is_err());
    let absent = root.join("absent");
    let counts = physical_resource_tree_usage(&absent, limits()).unwrap();
    assert!(
        counts
            .iter()
            .all(|usage| *usage == ResourceUsage::default())
    );
    let inventory = Inventory::default();
    let created = mutation(&inventory, vec![absent.clone()]);
    fs::write(absent, [1_u8; 13]).unwrap();
    created.finish().unwrap();
    assert_eq!(
        inventory
            .component_usage_for_tests(ResourceFamily::StorageBytes)
            .unwrap_err(),
        Unavailable::Unregistered
    );
}

#[cfg(unix)]
#[test]
fn physical_observation_rejects_symlinks_hardlinks_and_linked_absence() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let data = root.join(DATA_FILE_NAME);
    fs::write(&data, [0_u8; 8]).unwrap();
    let link = root.join("linked.data");
    symlink(&data, &link).unwrap();
    assert!(storage_resource_file_bytes(&link).is_err());
    fs::remove_file(&link).unwrap();
    fs::hard_link(&data, &link).unwrap();
    assert!(storage_resource_file_bytes(&data).is_err());
    assert!(physical_resource_tree_usage(&root, limits()).is_err());
    fs::remove_file(&link).unwrap();
    let real = root.join("real");
    fs::create_dir(&real).unwrap();
    let linked = root.join("linked");
    symlink(&real, &linked).unwrap();
    assert!(storage_resource_file_bytes(&linked.join("absent.data")).is_err());
    assert!(physical_resource_tree_usage(&linked, limits()).is_err());
}

fn target_mutation(
    inventory: &Inventory,
    target: PhysicalResourceTarget,
) -> std::result::Result<PhysicalResourceMutation<'_>, Unavailable> {
    PhysicalResourceMutation {
        mutation: inventory.begin(physical_resource_mask()).unwrap(),
        before: [ResourceUsage::default(); resource_inventory::FAMILY_COUNT],
        target: PhysicalResourceTarget::ChildBatch,
        bindings: PhysicalResourceBindings(Vec::new()),
        limits: limits(),
    }
    .bind(target)
}

fn assert_physical_components_unavailable(inventory: &Inventory) {
    for family in PHYSICAL_RESOURCE_FAMILIES {
        assert!(
            inventory.component_usage_for_tests(family).is_err(),
            "{family:?}"
        );
    }
}

fn assert_physical_components_match(inventory: &Inventory, root: &Path) {
    let actual = physical_resource_tree_usage(root, limits()).unwrap();
    for family in PHYSICAL_RESOURCE_FAMILIES {
        assert_eq!(
            inventory.component_usage_for_tests(family).unwrap(),
            actual[family as usize],
            "{family:?}"
        );
    }
}

#[test]
fn physical_path_mutation_rejects_replaced_existing_parent() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let live = root.join("live");
    fs::create_dir(&live).unwrap();
    let data = live.join(DATA_FILE_NAME);
    fs::write(&data, [1_u8; 9]).unwrap();
    let inventory = Inventory::default();
    initialize_physical(
        &inventory,
        &physical_resource_tree_usage(&root, limits()).unwrap(),
    );
    assert_physical_components_match(&inventory, &root);
    let guard = mutation(&inventory, vec![data.clone()]);
    fs::rename(&live, root.join("retained")).unwrap();
    fs::create_dir(&live).unwrap();
    fs::write(data, [2_u8; 23]).unwrap();
    assert!(guard.finish().is_err());
    assert_eq!(
        physical_resource_tree_usage(&root, limits()).unwrap()
            [ResourceFamily::StorageBytes as usize]
            .storage_bytes,
        32
    );
    assert_physical_components_unavailable(&inventory);
}

#[test]
fn physical_startup_tree_rejects_replaced_root_under_unchanged_parent() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let live = root.join("live");
    fs::create_dir(&live).unwrap();
    fs::write(live.join(DATA_FILE_NAME), [1_u8; 9]).unwrap();
    let inventory = Inventory::default();
    initialize_physical(
        &inventory,
        &physical_resource_tree_usage(&root, limits()).unwrap(),
    );
    assert_physical_components_match(&inventory, &root);
    let guard = target_mutation(
        &inventory,
        PhysicalResourceTarget::StartupTree(live.clone()),
    )
    .unwrap();
    fs::rename(&live, root.join("retained")).unwrap();
    fs::create_dir(&live).unwrap();
    fs::write(live.join(DATA_FILE_NAME), [2_u8; 23]).unwrap();
    assert!(guard.finish().is_err());
    assert_physical_components_unavailable(&inventory);
}

#[test]
fn physical_absent_leaf_creation_retains_existing_ancestor_identity() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let data = root.join("new/deep").join(DATA_FILE_NAME);
    let inventory = Inventory::default();
    initialize_physical(
        &inventory,
        &physical_resource_tree_usage(&root, limits()).unwrap(),
    );
    assert_physical_components_match(&inventory, &root);
    let guard = mutation(&inventory, vec![data.clone()]);
    fs::create_dir_all(data.parent().unwrap()).unwrap();
    fs::write(data, [1_u8; 13]).unwrap();
    guard.finish().unwrap();
    assert_physical_components_match(&inventory, &root);
    assert_eq!(
        inventory
            .component_usage_for_tests(ResourceFamily::StorageBytes)
            .unwrap()
            .storage_bytes,
        13
    );
}

#[test]
fn physical_absent_leaf_rejects_replaced_existing_ancestor() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let ancestor = root.join("ancestor");
    fs::create_dir(&ancestor).unwrap();
    let data = ancestor.join("new/deep").join(DATA_FILE_NAME);
    let inventory = Inventory::default();
    initialize_physical(
        &inventory,
        &physical_resource_tree_usage(&root, limits()).unwrap(),
    );
    assert_physical_components_match(&inventory, &root);
    let guard = mutation(&inventory, vec![data.clone()]);
    fs::rename(&ancestor, root.join("retained")).unwrap();
    fs::create_dir_all(data.parent().unwrap()).unwrap();
    fs::write(data, [1_u8; 13]).unwrap();
    assert!(guard.finish().is_err());
    assert_physical_components_unavailable(&inventory);
}

#[test]
fn physical_deletion_requires_the_counted_root_absent() {
    for remove_root in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let retired = root.join("retired");
        fs::create_dir(&retired).unwrap();
        fs::write(retired.join(DATA_FILE_NAME), [1_u8; 9]).unwrap();
        let inventory = Inventory::default();
        initialize_physical(
            &inventory,
            &physical_resource_tree_usage(&root, limits()).unwrap(),
        );
        assert_physical_components_match(&inventory, &root);
        let guard = target_mutation(
            &inventory,
            PhysicalResourceTarget::DeletedTree(retired.clone()),
        )
        .unwrap();
        assert!(!root.join("unrelated-absent").exists());
        if remove_root {
            fs::remove_dir_all(&retired).unwrap();
            guard.finish().unwrap();
            assert_physical_components_match(&inventory, &root);
            assert_eq!(
                inventory
                    .component_usage_for_tests(ResourceFamily::StorageBytes)
                    .unwrap()
                    .storage_bytes,
                0
            );
        } else {
            assert!(guard.finish().is_err());
            assert_eq!(fs::metadata(retired.join(DATA_FILE_NAME)).unwrap().len(), 9);
            assert_physical_components_unavailable(&inventory);
        }
    }
}

#[test]
fn physical_deletion_rejects_replaced_parent_even_when_counted_path_is_absent() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let parent = root.join("parent");
    let retired = parent.join("retired");
    fs::create_dir_all(&retired).unwrap();
    fs::write(retired.join(DATA_FILE_NAME), [1_u8; 9]).unwrap();
    let inventory = Inventory::default();
    initialize_physical(
        &inventory,
        &physical_resource_tree_usage(&root, limits()).unwrap(),
    );
    assert_physical_components_match(&inventory, &root);
    let guard = target_mutation(
        &inventory,
        PhysicalResourceTarget::DeletedTree(retired.clone()),
    )
    .unwrap();
    fs::rename(&parent, root.join("elsewhere")).unwrap();
    fs::create_dir(&parent).unwrap();
    assert!(!retired.exists());
    assert!(guard.finish().is_err());
    assert_physical_components_unavailable(&inventory);
}

#[test]
fn physical_exact_move_publishes_full_stable_and_temporary_vector() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let stable = root.join(INDEX_FILE_NAME);
    let temporary = root.join(format!("{INDEX_FILE_NAME}.tmp"));
    fs::write(&stable, [0_u8; 32]).unwrap();
    let inventory = Inventory::default();
    initialize_physical(
        &inventory,
        &physical_resource_tree_usage(&root, limits()).unwrap(),
    );
    assert_physical_components_match(&inventory, &root);
    let guard = mutation(&inventory, vec![stable.clone(), temporary.clone()]);
    fs::rename(stable, temporary).unwrap();
    guard.finish().unwrap();
    assert_physical_components_match(&inventory, &root);
    let actual = inventory
        .component_usage_for_tests(ResourceFamily::CanonicalIndex)
        .unwrap();
    assert_eq!(actual.index_bytes, 0);
    assert_eq!(actual.temporary_index_bytes, 32);
    assert_eq!(actual.persisted_entries, 2);
    assert_eq!(
        inventory
            .component_usage_for_tests(ResourceFamily::StorageBytes)
            .unwrap()
            .storage_bytes,
        32
    );
}

#[test]
fn physical_tree_move_observes_both_disjoint_roots_and_rejects_overlap() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let source = root.join("source");
    let destination = root.join("destination");
    fs::create_dir(&source).unwrap();
    fs::write(source.join(DATA_FILE_NAME), [1_u8; 9]).unwrap();
    let inventory = Inventory::default();
    initialize_physical(
        &inventory,
        &physical_resource_tree_usage(&root, limits()).unwrap(),
    );
    assert_physical_components_match(&inventory, &root);
    let guard = target_mutation(
        &inventory,
        PhysicalResourceTarget::MovedTrees {
            source: source.clone(),
            destination: destination.clone(),
        },
    )
    .unwrap();
    fs::rename(&source, &destination).unwrap();
    guard.finish().unwrap();
    assert_physical_components_match(&inventory, &root);
    assert_eq!(
        inventory
            .component_usage_for_tests(ResourceFamily::StorageBytes)
            .unwrap()
            .storage_bytes,
        9
    );
    assert!(physical_resource_moved_trees_usage(&destination, &destination, limits()).is_err());
    assert!(
        physical_resource_moved_trees_usage(&destination, &destination.join("nested"), limits())
            .is_err()
    );
    assert!(
        physical_resource_moved_trees_usage(&destination.join("nested"), &destination, limits())
            .is_err()
    );
}
