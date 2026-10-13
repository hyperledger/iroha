#[cfg(unix)]
fn copy_regular_test_tree(source: &Path, destination: &Path) {
    let metadata = fs::symlink_metadata(source).expect("source tree metadata");
    assert!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "test tree root must be a non-symlink directory"
    );
    fs::create_dir(destination).expect("create copied test tree root");
    for entry in fs::read_dir(source).expect("read source test tree") {
        let entry = entry.expect("source test tree entry");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path).expect("source entry metadata");
        assert!(
            !metadata.file_type().is_symlink(),
            "identity-swap fixtures must not contain symlinks"
        );
        if metadata.file_type().is_dir() {
            copy_regular_test_tree(&source_path, &destination_path);
        } else {
            assert!(metadata.file_type().is_file(), "fixture entry type");
            fs::copy(&source_path, &destination_path).expect("copy fixture file");
        }
    }
}
#[cfg(unix)]
fn snapshot_regular_test_tree(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, current: &Path, snapshot: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        let relative = current
            .strip_prefix(root)
            .expect("snapshot path below root")
            .to_path_buf();
        let metadata = fs::symlink_metadata(current).expect("snapshot entry metadata");
        assert!(
            !metadata.file_type().is_symlink(),
            "identity-swap fixtures must not contain symlinks"
        );
        if metadata.file_type().is_dir() {
            snapshot.insert(relative, None);
            for entry in fs::read_dir(current).expect("read snapshot directory") {
                visit(root, &entry.expect("snapshot entry").path(), snapshot);
            }
        } else {
            assert!(metadata.file_type().is_file(), "snapshot entry type");
            snapshot.insert(
                relative,
                Some(fs::read(current).expect("read snapshot file")),
            );
        }
    }
    let mut snapshot = BTreeMap::new();
    visit(root, root, &mut snapshot);
    snapshot
}
fn configured_primary_catalog(alias: &str) -> LaneCatalog {
    LaneCatalog::new(
        nonzero!(1_u32),
        vec![ModelLaneConfig {
            alias: alias.to_owned(),
            ..ModelLaneConfig::default()
        }],
    )
    .expect("configured primary-lane catalog")
}
#[test]
fn fresh_single_lane_constructor_provisions_a_missing_canonical_root() {
    let temp = TempDir::new().expect("temporary parent directory");
    let store_root = temp.path().join("fresh-kura");
    let config = kura_config_for_path(&store_root, BLOCKS_IN_MEMORY);
    let lane_config = RuntimeLaneConfig::default();
    let (fresh_kura, BlockCount(block_count)) = Kura::new_fresh_single_lane(&config, &lane_config)
        .expect("initialize canonical fresh Kura");
    assert_eq!(block_count, 0);
    assert!(store_root.is_dir());
    let canonical_blocks = Kura::canonical_storage_path(&store_root);
    assert!(canonical_blocks.is_dir());
    for name in [
        DATA_FILE_NAME,
        INDEX_FILE_NAME,
        HASHES_FILE_NAME,
        COUNT_FILE_NAME,
    ] {
        assert!(canonical_blocks.join(name).is_file());
    }
    assert!(!store_root.join("merge_ledger").exists());
    assert!(
        fresh_kura.lane_storage_entries.lock().is_empty(),
        "canonical startup grants no active lane authority"
    );
    assert!(!store_root.join("blocks/instances").exists());
}
#[test]
fn fresh_single_lane_preflight_rejects_custom_single_lane_without_mutation() {
    let temp = TempDir::new().expect("temporary parent directory");
    let store_root = temp.path().join("custom-kura");
    let config = kura_config_for_path(&store_root, BLOCKS_IN_MEMORY);
    let custom_catalog = configured_primary_catalog("custom-primary-path");
    let custom_config = RuntimeLaneConfig::from_catalog(&custom_catalog);
    let error = Kura::new_fresh_single_lane(&config, &custom_config)
        .expect_err("custom single-lane geometry requires catalog authentication");
    assert!(matches!(
        error,
        Error::IO(ref source, ref path)
            if source.kind() == ErrorKind::InvalidInput
                && source.to_string().contains("new_with_configured_lane_catalog")
                && path == &store_root
    ));
    assert!(
        !store_root.exists(),
        "rejected custom geometry must not create its store root"
    );
}
#[test]
fn fresh_single_lane_preflight_rejects_multilane_without_mutation() {
    let temp = TempDir::new().expect("temporary parent directory");
    let store_root = temp.path().join("multilane-kura");
    let config = kura_config_for_path(&store_root, BLOCKS_IN_MEMORY);
    let lane_zero = ModelLaneConfig::default();
    let lane_one = ModelLaneConfig {
        id: LaneId::new(1),
        alias: "secondary".to_owned(),
        ..ModelLaneConfig::default()
    };
    let catalog =
        LaneCatalog::new(nonzero!(2_u32), vec![lane_zero, lane_one]).expect("two-lane catalog");
    let lane_config = RuntimeLaneConfig::from_catalog(&catalog);
    let error = Kura::new_fresh_single_lane(&config, &lane_config)
        .expect_err("multilane geometry requires catalog authentication");
    assert!(matches!(
        error,
        Error::IO(ref source, ref path)
            if source.kind() == ErrorKind::InvalidInput
                && source.to_string().contains("new_with_configured_lane_catalog")
                && path == &store_root
    ));
    assert!(
        !store_root.exists(),
        "rejected multilane geometry must not create its store root"
    );
}
#[test]
fn fresh_single_lane_preflight_rejects_a_regular_file_root_without_mutation() {
    let temp = TempDir::new().expect("temporary parent directory");
    let store_root = temp.path().join("kura-file");
    let sentinel = b"not a Kura directory";
    fs::write(&store_root, sentinel).expect("create regular-file root");
    let config = kura_config_for_path(&store_root, BLOCKS_IN_MEMORY);
    let error = Kura::new_fresh_single_lane(&config, &RuntimeLaneConfig::default())
        .expect_err("a regular-file store root must fail closed");
    assert!(matches!(
        error,
        Error::IO(ref source, ref path)
            if source.kind() == ErrorKind::InvalidData
                && source.to_string().contains("non-symlink store root")
                && path == &store_root
    ));
    assert_eq!(
        fs::read(&store_root).expect("read unchanged regular-file root"),
        sentinel
    );
}
#[cfg(unix)]
#[test]
fn fresh_single_lane_preflight_rejects_symlink_root_without_mutation() {
    use std::os::unix::fs::symlink;
    let temp = TempDir::new().expect("temporary parent directory");
    let target = temp.path().join("target");
    fs::create_dir(&target).expect("create symlink target");
    let store_root = temp.path().join("kura-link");
    symlink(&target, &store_root).expect("create Kura root symlink");
    let config = kura_config_for_path(&store_root, BLOCKS_IN_MEMORY);
    let error = Kura::new_fresh_single_lane(&config, &RuntimeLaneConfig::default())
        .expect_err("a symlink store root must fail closed");
    assert!(matches!(
        error,
        Error::IO(ref source, ref path)
            if source.kind() == ErrorKind::InvalidData
                && source.to_string().contains("non-symlink store root")
                && path == &store_root
    ));
    assert!(
        fs::read_dir(&target)
            .expect("read unchanged symlink target")
            .next()
            .is_none(),
        "rejected symlink root must not provision its target"
    );
    assert!(
        fs::symlink_metadata(&store_root)
            .expect("symlink remains present")
            .file_type()
            .is_symlink(),
        "rejected root identity must remain unchanged"
    );
}
