#[test]
fn prune_sidecars_remove_temps_and_fail_closed_on_non_file_suffix() {
    let temp_dir = TempDir::new().unwrap();
    let mut store = new_block_store(&temp_dir);
    store.create_files_if_they_do_not_exist().unwrap();
    store
        .write_da_block_bytes(1, b"retained")
        .expect("write retained sidecar");
    store
        .write_da_block_bytes(3, b"pruned")
        .expect("write pruned sidecar");
    let da_dir = primary_blocks_dir(&temp_dir).join("da_blocks");
    let retained = store.da_block_path(1);
    let pruned = store.da_block_path(3);
    let invalid_height = da_dir.join("not-a-height.norito");
    let temp_artifact = da_dir.join("00000000000000000004.norito.tmp");
    let directory_artifact = da_dir.join("00000000000000000005.norito");
    std::fs::write(&invalid_height, b"operator note").expect("write invalid sidecar name");
    std::fs::write(&temp_artifact, b"partial temp").expect("write temp artifact");
    std::fs::create_dir(&directory_artifact).expect("create directory artifact");
    assert!(matches!(
        store.prune(2),
        Err(Error::IO(error, _))
            if error.kind() == ErrorKind::InvalidData && error.to_string().contains("not removable as a file")
    ));
    std::fs::remove_dir(&directory_artifact).expect("remove blocking directory artifact");
    store.prune(2).expect("retry sidecar prune");
    assert!(
        !retained.exists(),
        "sidecars without a retained canonical index entry must be removed"
    );
    assert!(!pruned.exists(), "above-tip sidecar should be removed");
    assert!(
        invalid_height.exists(),
        "non-height .norito artifacts should be ignored"
    );
    assert!(
        !temp_artifact.exists(),
        "above-tip temporary sidecars must be removed"
    );
}
#[test]
fn fast_init_does_not_create_a_missing_store_root() {
    let parent = TempDir::new().unwrap();
    let missing = parent.path().join("not-initialized");
    let mut config = kura_config_for_path(&missing, BLOCKS_IN_MEMORY);
    config.init_mode = InitMode::Fast;

    Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
        .expect_err("Fast requires storage previously initialized by Strict mode");

    assert!(
        !missing.exists(),
        "Fast startup must not create a missing Kura store root"
    );
}

#[test]
fn fast_init_caps_recent_block_cache_without_changing_durable_history() {
    let temp_dir = TempDir::new().unwrap();
    let strict_config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    let lane_config = RuntimeLaneConfig::default();
    let catalog = LaneCatalog::default();
    let (strict_kura, _) =
        Kura::new_with_configured_lane_catalog(&strict_config, &lane_config, &catalog)
            .expect("Strict initializes the store");
    establish_configured_lane_markers_for_test(&strict_kura, &lane_config);
    drop(strict_kura);

    let mut fast_config = strict_config;
    fast_config.init_mode = InitMode::Fast;
    fast_config.blocks_in_memory = NonZeroUsize::new(usize::MAX).unwrap();
    let (fast_kura, BlockCount(count)) =
        Kura::new_with_configured_lane_catalog(&fast_config, &lane_config, &catalog)
            .expect("Fast opens the exact original canonical store");
    assert_eq!(count, 0);
    assert_eq!(fast_kura.blocks_in_memory, NonZeroUsize::new(256).unwrap());
}

#[test]
fn fast_init_rejects_an_unmarked_tip_hash_without_mutation() {
    let temp_dir = TempDir::new().unwrap();
    populate_strict_kura_store(&temp_dir, 1);
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let hash_path = blocks_dir.join(HASHES_FILE_NAME);
    let mut hash_bytes = std::fs::read(&hash_path).expect("read committed hash journal");
    hash_bytes[Hash::LENGTH - 1] &= !1;
    std::fs::write(&hash_path, &hash_bytes).expect("clear the canonical hash marker bit");
    let paths = [
        blocks_dir.join(DATA_FILE_NAME),
        blocks_dir.join(INDEX_FILE_NAME),
        hash_path,
        blocks_dir.join(COUNT_FILE_NAME),
    ];
    let before = paths
        .iter()
        .map(std::fs::read)
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();

    let mut config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    config.init_mode = InitMode::Fast;
    assert!(
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .is_err(),
        "Fast must compare the exact marker-bound tip bytes without normalizing corruption"
    );

    let after = paths
        .iter()
        .map(std::fs::read)
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(after, before, "Fast rejection must not repair the journal");
}

#[test]
fn hash_journal_reader_rejects_an_unmarked_entry() {
    let temp_dir = TempDir::new().unwrap();
    populate_raw_block_store(&temp_dir, 2);
    let hash_path = primary_blocks_dir(&temp_dir).join(HASHES_FILE_NAME);
    let mut hash_bytes = std::fs::read(&hash_path).expect("read committed hash journal");
    hash_bytes[Hash::LENGTH - 1] &= !1;
    std::fs::write(&hash_path, hash_bytes).expect("clear an interior canonical marker bit");

    let mut store = new_block_store(&temp_dir);
    assert!(matches!(
        store.read_block_hashes(0, 1),
        Err(Error::IO(error, _)) if error.kind() == ErrorKind::InvalidData
    ));
}

#[test]
fn fast_init_rejects_truncated_committed_body_without_mutation() {
    let temp_dir = TempDir::new().unwrap();
    populate_strict_kura_store(&temp_dir, 3);
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let data_path = blocks_dir.join(DATA_FILE_NAME);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&data_path)
        .unwrap();
    let len = file.metadata().unwrap().len();
    file.set_len(len.saturating_sub(4)).unwrap();
    drop(file);
    let paths = [
        blocks_dir.join(DATA_FILE_NAME),
        blocks_dir.join(INDEX_FILE_NAME),
        blocks_dir.join(HASHES_FILE_NAME),
        blocks_dir.join(COUNT_FILE_NAME),
    ];
    let before = paths
        .iter()
        .map(std::fs::read)
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    let mut config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    config.init_mode = InitMode::Fast;
    assert!(
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default(),)
            .is_err()
    );
    let after = paths
        .iter()
        .map(std::fs::read)
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        after, before,
        "Fast preflight must not lower the marker or prune committed bytes"
    );
}
#[test]
fn fast_init_leaves_unpublished_journal_suffix_for_strict_recovery() {
    let temp_dir = TempDir::new().unwrap();
    populate_strict_kura_store(&temp_dir, 3);
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let index_path = blocks_dir.join(INDEX_FILE_NAME);
    let hashes_path = blocks_dir.join(HASHES_FILE_NAME);
    {
        let mut index = std::fs::OpenOptions::new()
            .append(true)
            .open(&index_path)
            .unwrap();
        index
            .write_all(
                &BlockIndex {
                    start: 0,
                    length: 1,
                }
                .encode(),
            )
            .unwrap();
        let mut hashes = std::fs::OpenOptions::new()
            .append(true)
            .open(&hashes_path)
            .unwrap();
        hashes.write_all(&[0xCC; Hash::LENGTH]).unwrap();
    }
    let before_index = std::fs::read(&index_path).unwrap();
    let before_hashes = std::fs::read(&hashes_path).unwrap();

    let mut config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    config.init_mode = InitMode::Fast;
    let (kura, BlockCount(count)) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .expect("Fast must trust only the published marker boundary");
    assert_eq!(count, 3);
    assert_eq!(std::fs::read(&index_path).unwrap(), before_index);
    assert_eq!(std::fs::read(&hashes_path).unwrap(), before_hashes);
    drop(kura);

    config.init_mode = InitMode::Strict;
    let (_, BlockCount(count)) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .expect("Strict restart must reconcile the unpublished suffix");
    assert_eq!(count, 3);
    assert_eq!(
        std::fs::metadata(&index_path).unwrap().len(),
        3 * BlockIndex::SIZE
    );
    assert_eq!(
        std::fs::metadata(&hashes_path).unwrap().len(),
        3 * SIZE_OF_BLOCK_HASH
    );
}
#[test]
fn fast_init_ignores_auxiliary_storage_recovery_without_mutation() {
    let temp_dir = TempDir::new().unwrap();
    populate_strict_kura_store(&temp_dir, 3);
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let staged_bytes = b"Strict recovery required";
    let stage_paths = [
        blocks_dir
            .join(COUNT_FILE_NAME)
            .with_extension("norito.tmp"),
        blocks_dir.join(DA_BLOCK_REWRITE_STAGE_FILE_NAME),
        blocks_dir.join(EVICTION_COMPACTION_STAGE_FILE_NAME),
        blocks_dir.join("canonical_association_stage.norito"),
    ];
    for path in &stage_paths {
        std::fs::write(path, staged_bytes).expect("forge pending storage stage");
    }
    let retained_stage = blocks_dir.join("retained_block_rewrite_staging");
    std::fs::create_dir(&retained_stage).expect("create retained rewrite stage");
    std::fs::write(retained_stage.join("opaque"), staged_bytes)
        .expect("forge retained rewrite stage payload");
    let before = snapshot_regular_test_tree(&blocks_dir);

    let mut config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    config.init_mode = InitMode::Fast;
    let (kura, BlockCount(count)) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .expect("Fast must ignore a canonical association stage");
    assert_eq!(count, 3);
    drop(kura);

    assert_eq!(
        snapshot_regular_test_tree(&blocks_dir),
        before,
        "Fast startup must leave every auxiliary recovery artifact untouched"
    );
}
#[test]
fn fast_init_ignores_prune_recovery_without_root_inventory() {
    let temp_dir = TempDir::new().unwrap();
    populate_strict_kura_store(&temp_dir, 3);
    let intent_bytes = b"Strict recovery required";
    let intent_paths = [
        temp_dir.path().join("prune_intent.norito"),
        temp_dir.path().join("prune_intent.norito.tmp"),
    ];
    for path in &intent_paths {
        std::fs::write(path, intent_bytes).expect("forge pending prune intent");
    }
    let before = snapshot_regular_test_tree(temp_dir.path());

    let mut config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    config.init_mode = InitMode::Fast;
    let (kura, BlockCount(count)) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .expect("Fast must ignore prune artifacts");
    assert_eq!(count, 3);
    drop(kura);

    assert_eq!(snapshot_regular_test_tree(temp_dir.path()), before);
}
#[test]
fn fast_init_poisoned_oversized_interior_index_before_body_read() {
    let temp_dir = TempDir::new().unwrap();
    populate_strict_kura_store(&temp_dir, 3);
    let index_path = primary_blocks_dir(&temp_dir).join(INDEX_FILE_NAME);
    let oversized = BlockIndex {
        start: 0,
        length: STRICT_INIT_MAX_BLOCK_BYTES.saturating_add(1),
    };
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&index_path)
            .unwrap();
        file.seek(SeekFrom::Start(BlockIndex::SIZE)).unwrap();
        file.write_all(&oversized.encode()).unwrap();
        file.flush().unwrap();
    }

    let mut config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    config.init_mode = InitMode::Fast;
    let (kura, BlockCount(count)) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .expect("Fast init defers interior index validation");
    assert_eq!(count, 3);
    assert_eq!(kura.canonical_body_bytes_read_for_test(), 0);

    assert!(matches!(
        kura.get_block(
            nonzero!(2_usize),
            &crate::state::AllocationBudget::new(64 * 1024 * 1024)
        ),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(_))
    ));
    assert!(kura.canonical_storage_poisoned.load(Ordering::Acquire));
    assert_eq!(kura.canonical_body_bytes_read_for_test(), 0);
    assert!(kura.block_store.lock().data_mmap.is_none());
}
#[test]
fn block_height_hash_index_keeps_the_earliest_height() {
    let first =
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x11; Hash::LENGTH]));
    let second =
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x22; Hash::LENGTH]));
    let block_data: BlockData = vec![(first, None), (second, None), (first, None)]
        .into_iter()
        .collect();

    let index = Kura::build_block_height_index(&block_data);

    assert_eq!(index.get(&first), Some(&nonzero!(1_usize)));
    assert_eq!(index.get(&second), Some(&nonzero!(2_usize)));
}
#[test]
fn commit_marker_prunes_excess_entries_on_init() {
    let temp_dir = TempDir::new().unwrap();
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let mut store = BlockStore::new(&blocks_dir);
    store.create_files_if_they_do_not_exist().unwrap();
    let mut blocks = NativeBlocks::new();
    for _ in 0..3 {
        store.append_block_to_chain(&blocks.next()).unwrap();
    }
    store.write_commit_marker(1).unwrap();
    drop(store);
    let mut reopened = BlockStore::new(&blocks_dir);
    reopened.create_files_if_they_do_not_exist().unwrap();
    assert_eq!(reopened.read_index_count().unwrap(), 1);
    assert_eq!(reopened.read_hashes_count().unwrap(), 1);
    assert_eq!(reopened.read_durable_index_count().unwrap(), 1);
    let marker = reopened.read_commit_marker().unwrap().expect("marker");
    assert_eq!(marker.count, 1);
    let last = reopened.read_block_index(0).unwrap();
    let data_len = reopened.data_file_len().unwrap();
    assert_eq!(data_len, last.start + last.length);
}
#[test]
fn commit_marker_truncates_hashes_tail_on_init() {
    let temp_dir = TempDir::new().unwrap();
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let mut store = BlockStore::new(&blocks_dir);
    store.create_files_if_they_do_not_exist().unwrap();
    let mut blocks = NativeBlocks::new();
    for _ in 0..2 {
        store.append_block_to_chain(&blocks.next()).unwrap();
    }
    let hashes_path = blocks_dir.join(HASHES_FILE_NAME);
    let hashes_file = std::fs::OpenOptions::new()
        .write(true)
        .open(&hashes_path)
        .unwrap();
    hashes_file.set_len(3 * SIZE_OF_BLOCK_HASH).unwrap();
    drop(store);
    let mut reopened = BlockStore::new(&blocks_dir);
    reopened.create_files_if_they_do_not_exist().unwrap();
    assert_eq!(reopened.read_index_count().unwrap(), 2);
    assert_eq!(reopened.read_hashes_count().unwrap(), 2);
}
#[test]
fn commit_marker_overwrites_existing_file() {
    let temp_dir = TempDir::new().unwrap();
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let mut store = BlockStore::new(&blocks_dir);
    store.create_files_if_they_do_not_exist().unwrap();
    let mut blocks = NativeBlocks::new();
    store.append_block_to_chain(&blocks.next()).unwrap();
    store.append_block_to_chain(&blocks.next()).unwrap();
    store.write_commit_marker(1).unwrap();
    store.write_commit_marker(2).unwrap();
    let marker = store.read_commit_marker().unwrap().expect("marker");
    assert_eq!(marker.count, 2);
    assert!(blocks_dir.join(COUNT_FILE_NAME).exists());
}
#[test]
fn commit_marker_boundary_is_canonical_and_ambient_independent() {
    let temp_dir = TempDir::new().expect("create commit-marker root");
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let mut store = BlockStore::new(&blocks_dir);
    let marker = BlockStoreCommitMarker::new(0, None);
    let canonical = norito::encode_canonical(&marker).expect("encode canonical commit marker");
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    {
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        store
            .write_commit_marker_value(&marker)
            .expect("write marker under alternate ambient layout");
        assert_ne!(
            norito::to_bytes(&marker).expect("encode ambient marker fixture"),
            canonical,
            "canonical marker encoding must restore the caller's ambient layout"
        );
    }
    let marker_path = store.commit_marker_path();
    assert_eq!(
        std::fs::read(&marker_path).expect("read published commit marker"),
        canonical,
        "durable marker publication must ignore ambient layout"
    );
    let alternate = {
        let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        norito::to_bytes(&marker).expect("encode alternate-layout commit marker")
    };
    assert_ne!(alternate, canonical);
    std::fs::write(&marker_path, &alternate).expect("replace marker with alternate layout");
    assert!(
        store.read_commit_marker().is_err(),
        "alternate layouts are rejected"
    );
    assert_eq!(
        fs::read(&marker_path).unwrap(),
        alternate,
        "rejected main marker bytes remain intact"
    );
}
#[test]
fn init_rejects_commit_marker_tip_hash_mismatch() {
    let temp_dir = TempDir::new().unwrap();
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let mut store = BlockStore::new(&blocks_dir);
    store.create_files_if_they_do_not_exist().unwrap();
    let mut blocks = NativeBlocks::new();
    store.append_block_to_chain(&blocks.next()).unwrap();
    let mut marker = store.read_commit_marker().unwrap().expect("marker");
    marker.tip_hash = Some(HashOf::from_untyped_unchecked(Hash::prehashed([0xA6; 32])));
    let marker_bytes = norito::to_bytes(&marker).expect("encode tampered marker");
    std::fs::write(store.commit_marker_path(), marker_bytes).expect("write tampered marker");
    drop(store);
    let mut reopened = BlockStore::new(&blocks_dir);
    assert!(matches!(
        reopened.create_files_if_they_do_not_exist(),
        Err(Error::IO(error, _)) if error.kind() == ErrorKind::InvalidData
    ));
}
#[test]
fn init_rejects_nonempty_tip_on_empty_commit_marker() {
    let temp_dir = TempDir::new().unwrap();
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let mut store = BlockStore::new(&blocks_dir);
    store.create_files_if_they_do_not_exist().unwrap();
    let marker = BlockStoreCommitMarker {
        version: BlockStoreCommitMarker::VERSION,
        count: 0,
        tip_hash: Some(HashOf::from_untyped_unchecked(Hash::prehashed([0xA7; 32]))),
    };
    std::fs::write(
        store.commit_marker_path(),
        norito::to_bytes(&marker).expect("encode invalid empty marker"),
    )
    .expect("write invalid empty marker");
    drop(store);
    let mut reopened = BlockStore::new(&blocks_dir);
    assert!(matches!(
        reopened.create_files_if_they_do_not_exist(),
        Err(Error::IO(error, _)) if error.kind() == ErrorKind::InvalidData
    ));
}
#[test]
fn corrupt_or_missing_commit_marker_never_reconstructs_occupied_history() {
    for damage in [
        "corrupt",
        "missing",
        "missing-and-missing-data",
        "corrupt-and-short-data",
    ] {
        let temp_dir = TempDir::new().unwrap();
        let blocks_dir = primary_blocks_dir(&temp_dir);
        let mut store = BlockStore::new(&blocks_dir);
        store.create_files_if_they_do_not_exist().unwrap();
        let mut blocks = NativeBlocks::new();
        store.append_block_to_chain(&blocks.next()).unwrap();
        store.append_block_to_chain(&blocks.next()).unwrap();
        let first = store.read_block_index(0).unwrap();
        drop(store);
        if damage.starts_with("missing") {
            fs::remove_file(blocks_dir.join(COUNT_FILE_NAME)).unwrap();
        } else {
            fs::write(blocks_dir.join(COUNT_FILE_NAME), b"corrupt").unwrap();
        }
        if damage == "missing-and-missing-data" {
            fs::remove_file(blocks_dir.join(DATA_FILE_NAME)).unwrap();
        }
        if damage == "corrupt-and-short-data" {
            fs::OpenOptions::new()
                .write(true)
                .open(blocks_dir.join(DATA_FILE_NAME))
                .unwrap()
                .set_len(first.start + first.length)
                .unwrap();
        }
        let files = [
            INDEX_FILE_NAME,
            HASHES_FILE_NAME,
            DATA_FILE_NAME,
            COUNT_FILE_NAME,
        ];
        let before = files.map(|file| fs::read(blocks_dir.join(file)).ok());
        let mut reopened = BlockStore::new(&blocks_dir);
        assert!(
            reopened.create_files_if_they_do_not_exist().is_err(),
            "{damage}"
        );
        for (file, expected) in files.into_iter().zip(before) {
            assert_eq!(
                fs::read(blocks_dir.join(file)).ok(),
                expected,
                "startup changed {file} after {damage}"
            );
        }
    }
}
#[test]
fn unpublished_temp_never_rewinds_stable_commit_authority() {
    let temp_dir = TempDir::new().unwrap();
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let mut store = BlockStore::new(&blocks_dir);
    store.create_files_if_they_do_not_exist().unwrap();
    let mut blocks = NativeBlocks::new();
    store.append_block_to_chain(&blocks.next()).unwrap();
    store.append_block_to_chain(&blocks.next()).unwrap();
    let stable = store.read_commit_marker().unwrap().unwrap();
    let temporary = store.commit_marker_path().with_extension("norito.tmp");
    let unpublished = norito::encode_canonical(&BlockStoreCommitMarker::new(0, None)).unwrap();
    fs::write(&temporary, &unpublished).unwrap();
    let files = [
        INDEX_FILE_NAME,
        HASHES_FILE_NAME,
        DATA_FILE_NAME,
        COUNT_FILE_NAME,
    ];
    let before = files.map(|file| fs::read(blocks_dir.join(file)).unwrap());
    assert_eq!(store.read_commit_marker().unwrap(), Some(stable));
    assert_eq!(
        fs::read(&temporary).unwrap(),
        unpublished,
        "reading does not publish or abort a temp"
    );
    drop(store);
    let mut reopened = BlockStore::new(&blocks_dir);
    reopened.create_files_if_they_do_not_exist().unwrap();
    assert_eq!(reopened.read_durable_index_count().unwrap(), 2);
    assert!(
        !temporary.exists(),
        "startup aborts the unpublished temp after validating stable custody"
    );
    for (file, expected) in files.into_iter().zip(before) {
        assert_eq!(
            fs::read(blocks_dir.join(file)).unwrap(),
            expected,
            "stable {file} changed"
        );
    }
}
#[test]
fn index_misalignment_truncates_on_init() {
    let temp_dir = TempDir::new().unwrap();
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let mut store = BlockStore::new(&blocks_dir);
    store.create_files_if_they_do_not_exist().unwrap();
    let mut blocks = NativeBlocks::new();
    for _ in 0..2 {
        store.append_block_to_chain(&blocks.next()).unwrap();
    }
    let index_path = blocks_dir.join(INDEX_FILE_NAME);
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&index_path)
        .unwrap();
    file.write_all(&[0u8; 3]).unwrap();
    drop(store);
    let mut reopened = BlockStore::new(&blocks_dir);
    reopened.create_files_if_they_do_not_exist().unwrap();
    let len = reopened.index_file_len().unwrap();
    assert_eq!(len % BlockIndex::SIZE, 0);
    assert_eq!(reopened.read_index_count().unwrap(), 2);
}
#[test]
fn hashes_misalignment_truncates_on_init() {
    let temp_dir = TempDir::new().unwrap();
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let mut store = BlockStore::new(&blocks_dir);
    store.create_files_if_they_do_not_exist().unwrap();
    let mut blocks = NativeBlocks::new();
    for _ in 0..2 {
        store.append_block_to_chain(&blocks.next()).unwrap();
    }
    let hashes_path = blocks_dir.join(HASHES_FILE_NAME);
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&hashes_path)
        .unwrap();
    file.write_all(&[0u8; 3]).unwrap();
    drop(store);
    let mut reopened = BlockStore::new(&blocks_dir);
    reopened.create_files_if_they_do_not_exist().unwrap();
    let len = reopened.hashes_file_len().unwrap();
    assert_eq!(len % SIZE_OF_BLOCK_HASH, 0);
    assert_eq!(reopened.read_hashes_count().unwrap(), 2);
}
#[test]
fn prune_does_not_advance_commit_marker() {
    let temp_dir = TempDir::new().unwrap();
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let mut store = BlockStore::new(&blocks_dir);
    store.create_files_if_they_do_not_exist().unwrap();
    let block = NativeBlocks::new().next();
    store.append_block_to_chain(block.as_ref()).unwrap();
    let marker = store.read_commit_marker().unwrap().expect("marker");
    assert_eq!(marker.count, 1);
    store.prune(5).unwrap();
    let marker_after = store.read_commit_marker().unwrap().expect("marker");
    assert_eq!(marker_after.count, 1);
    assert_eq!(store.read_index_count().unwrap(), 1);
}
#[test]
fn batched_fsync_waits_until_interval_elapses() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut store = BlockStore::with_fsync(
        temp_dir.path(),
        FsyncMode::Batched,
        Duration::from_millis(5),
    );
    store.create_files_if_they_do_not_exist().unwrap();
    let block = NativeBlocks::new().next();
    store
        .append_block_to_chain(block.as_ref())
        .expect("append block");
    assert!(
        store.fsync_pending_for_tests(),
        "batched fsync should leave pending work"
    );
    let wait = store.next_fsync_wait().expect("pending fsync deadline");
    assert!(
        wait <= Duration::from_millis(5),
        "expected wait under batching window"
    );
    thread::sleep(Duration::from_millis(6));
    store
        .flush_pending_fsync(false)
        .expect("flush pending fsync succeeds");
    assert!(
        !store.fsync_pending_for_tests(),
        "batched fsync should clear after flush"
    );
}
#[test]
fn fsync_on_flushes_immediately() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut store = BlockStore::with_fsync(temp_dir.path(), FsyncMode::Always, FSYNC_INTERVAL);
    store.create_files_if_they_do_not_exist().unwrap();
    let block = NativeBlocks::new().next();
    store
        .append_block_to_chain(block.as_ref())
        .expect("append block");
    assert!(
        !store.fsync_pending_for_tests(),
        "immediate fsync should clear pending flag"
    );
    assert!(
        store.next_fsync_wait().is_none(),
        "immediate fsync should not schedule a wait"
    );
}
#[test]
fn commit_marker_write_failure_rolls_back_unpublished_append() {
    let temp_dir = TempDir::new().expect("temp dir");
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let mut store =
        BlockStore::with_fsync(&blocks_dir, FsyncMode::Batched, Duration::from_millis(10));
    store.create_files_if_they_do_not_exist().unwrap();
    let block = NativeBlocks::new().next();
    store
        .append_block_to_chain(block.as_ref())
        .expect("append block");
    assert!(
        store.commit_marker_pending.is_some(),
        "expected pending commit marker before flush"
    );
    assert!(
        store.fsync_pending_for_tests(),
        "fsync should be pending before flush"
    );
    store
        .fail_next_commit_marker_write
        .store(true, Ordering::Release);
    store
        .flush_pending_fsync(true)
        .expect_err("flush should fail when commit marker temp is a directory");
    assert!(
        store.commit_marker_pending.is_none(),
        "failed marker publication must clear the pending replacement"
    );
    assert!(
        !store.fsync_pending_for_tests(),
        "rolled-back journal work must not be published by a later fsync"
    );
    assert_eq!(store.read_index_count().unwrap(), 0);
    assert_eq!(store.read_hashes_count().unwrap(), 0);
}
#[test]
fn commit_marker_ack_failure_with_new_readback_commits_append() {
    let temp_dir = TempDir::new().expect("temp dir");
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let mut store =
        BlockStore::with_fsync(&blocks_dir, FsyncMode::Batched, Duration::from_secs(60));
    store.create_files_if_they_do_not_exist().unwrap();
    let block = NativeBlocks::new().next();
    store
        .append_block_to_chain(block.as_ref())
        .expect("append pending block");
    store
        .fail_next_commit_marker_ack_after_persist
        .store(true, Ordering::Release);
    store
        .flush_pending_fsync(true)
        .expect("readable new marker turns acknowledgement failure into committed success");
    assert!(store.commit_marker_pending.is_none());
    assert!(!store.fsync_pending_for_tests());
    assert_eq!(store.read_durable_index_count().unwrap(), 1);
    assert_eq!(
        store
            .read_commit_marker()
            .unwrap()
            .expect("committed marker")
            .tip_hash,
        Some(block.hash())
    );
}
#[test]
fn deterministic_commit_marker_temp_recovers_or_rolls_back_exactly() {
    let temp_dir = TempDir::new().expect("temp dir");
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let mut store = BlockStore::new(&blocks_dir);
    store.create_files_if_they_do_not_exist().unwrap();
    let block = NativeBlocks::new().next();
    store
        .append_block_to_chain(block.as_ref())
        .expect("append marker recovery block");
    store
        .flush_pending_fsync(true)
        .expect("publish stable marker");
    let marker = store
        .read_commit_marker()
        .expect("read stable marker")
        .expect("stable marker exists");
    let marker_path = store.commit_marker_path();
    let temporary_path = marker_path.with_extension("norito.tmp");
    store
        .fail_next_commit_marker_after_temp_sync
        .store(true, Ordering::Release);
    store
        .write_commit_marker_value(&marker)
        .expect_err("inject marker stop after deterministic temp sync");
    assert!(temporary_path.is_file());
    drop(store);
    let mut recovered = BlockStore::new(&blocks_dir);
    assert_eq!(
        recovered.read_commit_marker().expect("recover marker temp"),
        Some(marker.clone()),
    );
    assert!(
        temporary_path.exists(),
        "marker reads preserve unpublished bytes"
    );
    recovered.create_files_if_they_do_not_exist().unwrap();
    assert!(!temporary_path.exists());
    fs::write(&temporary_path, b"partial").expect("write partial marker temp");
    assert_eq!(
        recovered
            .read_commit_marker()
            .expect("read stable marker beside a partial temp"),
        Some(marker),
    );
    assert!(temporary_path.exists());
    recovered.create_files_if_they_do_not_exist().unwrap();
    assert!(!temporary_path.exists());
}
#[test]
fn commit_marker_rejects_oversized_deterministic_temp() {
    let temp_dir = TempDir::new().expect("temp dir");
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let mut store = BlockStore::new(&blocks_dir);
    store.create_files_if_they_do_not_exist().unwrap();
    let temporary_path = store.commit_marker_path().with_extension("norito.tmp");
    fs::write(
        &temporary_path,
        vec![0_u8; MAX_BLOCK_COMMIT_MARKER_BYTES + 1],
    )
    .expect("write oversized marker temp");
    assert!(
        matches!(store.read_commit_marker(), Err(Error::IO(_, path)) if path == temporary_path)
    );
    assert!(temporary_path.is_file());
}
#[cfg(unix)]
#[test]
fn commit_marker_rejects_symlinked_deterministic_temp() {
    use std::os::unix::fs::symlink;
    let temp_dir = TempDir::new().expect("temp dir");
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let mut store = BlockStore::new(&blocks_dir);
    store.create_files_if_they_do_not_exist().unwrap();
    let temporary_path = store.commit_marker_path().with_extension("norito.tmp");
    let target = temp_dir.path().join("marker-temp-target");
    fs::write(&target, b"partial").expect("write marker symlink target");
    symlink(&target, &temporary_path).expect("install marker temp symlink");
    assert!(
        matches!(store.read_commit_marker(), Err(Error::IO(_, path)) if path == temporary_path)
    );
}
#[test]
fn writer_loop_records_periodic_fsync_failure_without_panic() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    config.fsync_interval = Duration::from_millis(1);
    let (kura, _) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .expect("kura init");
    let block = NativeBlocks::new().next();
    {
        let mut store = kura.block_store.lock();
        store
            .append_block_to_chain(block.as_ref())
            .expect("append block");
        assert!(
            store.fsync_pending_for_tests(),
            "batched append should leave pending fsync work"
        );
    }
    kura.block_store
        .lock()
        .fail_next_commit_marker_write
        .store(true, Ordering::Release);
    let shutdown_signal = ShutdownSignal::new();
    let writer_kura = Arc::clone(&kura);
    let writer = thread::spawn(move || {
        writer_kura.receive_blocks_loop(&shutdown_signal);
    });
    writer.join().expect("writer loop should not panic");
    let fault = kura.writer_fault.lock().clone();
    assert!(
        fault
            .as_deref()
            .is_some_and(|fault| fault.contains("periodic fsync")),
        "writer should record periodic fsync failure, got {fault:?}"
    );
    assert!(
        !kura.block_store.lock().fsync_pending_for_tests(),
        "failed writer fsync must roll back instead of publishing after the caller unwinds"
    );
}

#[test]
fn fast_init_defers_body_validation_without_rewriting_hashes() {
    let temp_dir = TempDir::new().unwrap();
    populate_strict_kura_store(&temp_dir, 3);
    let geometry_path = temp_dir.path().join("lane_geometry_journal.norito");
    let invalid_geometry = [0xA5; 1024];
    std::fs::write(&geometry_path, invalid_geometry).expect("forge opaque geometry journal");
    let deferred_geometry_artifacts = [
        temp_dir.path().join("lane_geometry_journal.norito.tmp"),
        temp_dir
            .path()
            .join("lane_geometry_journal.norito.restore.tmp"),
        primary_blocks_dir(&temp_dir).join(".lane-incarnation.norito.tmp"),
    ];
    for path in &deferred_geometry_artifacts {
        std::fs::write(path, b"Strict recovery required")
            .expect("forge deferred geometry artifact");
    }
    let hash_path = primary_blocks_dir(&temp_dir).join(HASHES_FILE_NAME);
    let forged =
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xAA; Hash::LENGTH]));
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&hash_path)
            .unwrap();
        // Keep the marker-bound tip intact while corrupting an interior journal identity.
        file.seek(SeekFrom::Start(SIZE_OF_BLOCK_HASH)).unwrap();
        file.write_all(forged.as_ref()).unwrap();
        file.flush().unwrap();
    }
    let mut config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    config.init_mode = InitMode::Fast;
    let (kura, BlockCount(count)) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .expect("fast init trusts the stable committed journal");
    assert_eq!(count, 3);
    assert_eq!(kura.canonical_body_bytes_read_for_test(), 0);
    assert!(matches!(
        kura.disk_usage_bytes(),
        Err(Error::EmergencyFastAuxiliaryUnavailable {
            subsystem: "disk-usage inventory"
        })
    ));
    assert_eq!(
        std::fs::read(&geometry_path).expect("reread deferred geometry journal"),
        invalid_geometry,
        "Fast startup must not decode or repair lane geometry"
    );
    for path in deferred_geometry_artifacts {
        assert_eq!(
            std::fs::read(path).expect("reread deferred geometry artifact"),
            b"Strict recovery required",
            "Fast startup must ignore auxiliary geometry recovery artifacts",
        );
    }
    {
        let data = kura.block_data.lock();
        assert!(matches!(
            &*data,
            BlockData::Deferred { len: 3, entries } if entries.is_empty()
        ));
    }
    assert_eq!(kura.get_block_hash(nonzero!(2_usize)), Some(forged));
    assert_eq!(kura.get_block_height_by_hash(forged), None);
    assert!(matches!(
        kura.get_block(
            nonzero!(2_usize),
            &crate::state::AllocationBudget::new(64 * 1024 * 1024)
        ),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(_))
    ));
    assert!(kura.canonical_storage_poisoned.load(Ordering::Acquire));
    let mut store = new_block_store(&temp_dir);
    assert_eq!(store.read_block_hashes(1, 1).unwrap(), vec![forged]);
}

#[test]
fn fast_init_keeps_history_sparse_and_rejects_canonical_mutation() {
    let temp_dir = TempDir::new().unwrap();
    populate_strict_kura_store(&temp_dir, 3);
    let mut config = kura_config_for_dir(&temp_dir, nonzero!(1_usize));
    config.init_mode = InitMode::Fast;
    let (kura, BlockCount(count)) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .expect("open count-only Fast Kura");
    assert_eq!(count, 3);
    assert_eq!(kura.blocks_count(), 3);

    let oldest_hash = kura.get_block_hash(nonzero!(1_usize)).unwrap();
    let oldest = kura
        .get_block(
            nonzero!(1_usize),
            &crate::state::AllocationBudget::new(64 * 1024 * 1024),
        )
        .expect("completed structural storage read")
        .expect("load an old body on demand");
    assert_eq!(oldest.hash(), oldest_hash);
    assert_eq!(
        kura.get_block_height_by_hash(oldest_hash),
        None,
        "an old read must not grow the bounded Fast reverse index"
    );
    assert!(matches!(
        &*kura.block_data.lock(),
        BlockData::Deferred { len: 3, entries } if entries.is_empty()
    ));

    let tip = kura
        .get_block(
            nonzero!(3_usize),
            &crate::state::AllocationBudget::new(64 * 1024 * 1024),
        )
        .expect("completed structural storage read")
        .expect("load the retained-window tip on demand");
    assert_eq!(
        kura.get_block_height_by_hash(tip.hash()),
        Some(nonzero!(3_usize))
    );
    assert!(matches!(
        &*kura.block_data.lock(),
        BlockData::Deferred { len: 3, entries } if entries.len() <= 2
    ));
    assert!(matches!(
        kura.store_block((tip).clone()),
        Err(Error::EmergencyFastAuxiliaryUnavailable {
            subsystem: "canonical mutation"
        })
    ));
    let benchmark_block = NativeBlocks::new().next();
    assert!(matches!(
        kura.persist_block_immediate_for_bench(&benchmark_block),
        Err(Error::EmergencyFastAuxiliaryUnavailable {
            subsystem: "canonical mutation"
        })
    ));
    kura.append_pending_block_for_bench(benchmark_block);
    assert_eq!(kura.blocks_count(), 3);
    assert!(matches!(
        Kura::start(Arc::clone(&kura), ShutdownSignal::new()),
        Err(Error::EmergencyFastAuxiliaryUnavailable {
            subsystem: "canonical mutation"
        })
    ));
    assert!(
        kura.block_notify_rx.lock().is_some(),
        "Fast rejection must not consume or start the writer"
    );

    let pipeline_sidecar = PipelineRecoverySidecar::new(
        3,
        tip.hash(),
        PipelineDagSnapshot {
            fingerprint: [0; 32],
            key_count: 0,
        },
        Vec::new(),
    );
    kura.write_pipeline_metadata(&pipeline_sidecar);
    let pipeline_dir = primary_blocks_dir(&temp_dir).join(PIPELINE_DIR_NAME);
    assert!(!pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE).exists());
    assert!(!pipeline_dir.join(PIPELINE_SIDECARS_INDEX_FILE).exists());
    assert_eq!(
        kura.enqueue_pipeline_metadata(pipeline_sidecar),
        PipelineSidecarEnqueueResult::RejectedEmergencyFast
    );
    assert_eq!(
        kura.enqueue_fastpq_proof_snapshot(sample_fastpq_snapshot(3, tip.hash(), 8)),
        FastpqProofEnqueueResult::RejectedEmergencyFast
    );
    assert!(kura.pipeline_sidecar_queue.lock().is_empty());
    assert!(kura.fastpq_proof_queue.lock().is_empty());
    assert_eq!(
        kura.flush_pipeline_sidecars(&mut kura.sidecar_lock.defer_notifications()),
        0
    );
}
