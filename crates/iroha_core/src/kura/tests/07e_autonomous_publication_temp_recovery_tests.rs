// Current catalog preflight and exact debug-output custody controls.

#[test]
fn invalid_catalog_rejects_before_modifying_unowned_residue() {
    let temp_dir = TempDir::new().expect("invalid-catalog temp-recovery directory");
    let config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    let accepted = configured_primary_catalog("temp-recovery-accepted");
    let accepted_config = RuntimeLaneConfig::from_catalog(&accepted);
    let (kura, _) = Kura::new_with_configured_lane_catalog(&config, &accepted_config, &accepted)
        .expect("establish accepted configured catalog");
    publish_configured_catalog_baseline(&kura, &accepted);
    drop(kura);
    let residue = temp_dir.path().join("unowned-residue.norito");
    let residue_bytes = b"catalog-rejected unowned residue remains untouched";
    fs::write(&residue, residue_bytes).expect("write unowned residue before catalog rejection");
    let rejected = configured_primary_catalog("temp-recovery-rejected");
    let rejected_config = RuntimeLaneConfig::from_catalog(&rejected);
    Kura::new_with_configured_lane_catalog(&config, &rejected_config, &rejected)
        .expect_err("configured catalog drift must fail before residue cleanup");
    assert_eq!(
        fs::read(&residue).expect("read retained catalog-rejected residue"),
        residue_bytes,
    );
}

#[test]
fn debug_block_dump_is_pinned_single_link_and_counted() {
    let temp_dir = TempDir::new().expect("bound debug-dump temp dir");
    let mut config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    config.debug_output_new_blocks = true;
    let (kura, _) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .expect("initialize bound debug-dump Kura");
    let path = kura
        .block_plain_text_path
        .lock()
        .clone()
        .expect("debug block dump path");
    let parent = path.parent().expect("debug block dump parent");
    let bytes = b"{\"debug\":true}\n";
    assert_eq!(Kura::blocks_root_debug_file_bytes(parent).unwrap(), 0);
    assert_eq!(
        kura.append_bound_debug_block_dump(&path, bytes)
            .expect("create bound debug block dump"),
        (0, bytes.len() as u64),
    );
    assert_eq!(
        Kura::blocks_root_debug_file_bytes(parent).expect("count debug block dump"),
        bytes.len() as u64,
    );
    let hardlink = parent.join("blocks-jsonl-hardlink");
    fs::hard_link(&path, &hardlink).expect("hard-link debug block dump");
    assert!(
        Kura::blocks_root_debug_file_bytes(parent).is_err()
            && kura.append_bound_debug_block_dump(&path, bytes).is_err(),
        "multiply linked debug output must fail closed",
    );
    assert_eq!(fs::read(&path).expect("read unchanged linked dump"), bytes);
    fs::remove_file(&hardlink).expect("remove debug dump hardlink");
    fs::remove_file(&path).expect("remove regular debug dump");
    fs::create_dir(&path).expect("replace debug dump with directory");
    assert!(
        Kura::blocks_root_debug_file_bytes(parent).is_err()
            && kura.append_bound_debug_block_dump(&path, bytes).is_err(),
        "non-regular debug output must fail closed",
    );
    fs::remove_dir(&path).expect("remove debug dump directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let target = parent.join("blocks-jsonl-symlink-target");
        fs::write(&target, b"victim").expect("write debug symlink target");
        symlink(&target, &path).expect("symlink debug block dump");
        assert!(
            Kura::blocks_root_debug_file_bytes(parent).is_err()
                && kura.append_bound_debug_block_dump(&path, bytes).is_err(),
            "symlinked debug output must fail closed",
        );
        assert_eq!(
            fs::read(&target).expect("read untouched symlink target"),
            b"victim"
        );
    }
}

#[test]
fn debug_block_dump_reserves_capacity_before_first_creation() {
    let temp_dir = TempDir::new().expect("debug capacity temp dir");
    let mut config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    config.debug_output_new_blocks = true;
    let (mut kura, _) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .expect("initialize debug capacity Kura");
    let baseline = kura
        .kura_disk_usage_bytes()
        .expect("measure debug baseline");
    let path = kura
        .block_plain_text_path
        .lock()
        .clone()
        .expect("debug capacity path");
    Arc::get_mut(&mut kura)
        .expect("exclusive debug capacity Kura")
        .max_disk_usage_bytes = baseline;
    let block = NativeBlocks::new().next();
    let (mut prune_releases, mut canonical_releases, mut geometry_releases, mut sidecar_releases) = (
        kura.prune_lock.defer_notifications(),
        kura.canonical_chain_lock.defer_notifications(),
        kura.lane_geometry_lock.defer_notifications(),
        kura.sidecar_lock.defer_notifications(),
    );
    let _prune = prune_releases.lock();
    let _canonical = canonical_releases.lock();
    kura.append_debug_block_dump(&block, &mut geometry_releases, &mut sidecar_releases);
    assert!(
        !path.exists(),
        "debug output must not be created without capacity for its first line",
    );
    assert_eq!(
        kura.kura_disk_usage_bytes()
            .expect("remeasure debug capacity baseline"),
        baseline,
    );
}
