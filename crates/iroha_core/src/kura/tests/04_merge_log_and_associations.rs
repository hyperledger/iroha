// Current native append capacity, durability, recovery and exact physical accounting.
fn canonical_storage_budget_base_for_test(kura: &Kura) -> u64 {
    let used = kura
        .kura_total_disk_usage_bytes()
        .expect("exact current physical bytes");
    let (persisted, unindexed) = kura.persisted_count_and_unindexed_bytes().unwrap();
    let pending = kura.pending_block_bytes(persisted, unindexed).unwrap();
    used.checked_add(pending)
        .and_then(|bytes| bytes.checked_add(kura.membership_storage.pending_bytes()))
        .expect("current native append base fits u64")
}

#[test]
fn native_frame_metadata_requires_durable_marker_and_does_not_grant_authority() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let mut config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    config.fsync_mode = FsyncMode::Batched;
    config.fsync_interval = Duration::from_secs(3600);
    let (kura, _) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .expect("kura init");
    let block = NativeBlocks::new().next();
    let block_hash = block.hash();
    {
        let mut store = kura.block_store.lock();
        store
            .append_block_to_chain(block.as_ref())
            .expect("append block without forced fsync");
        assert_eq!(store.read_index_count().expect("index count"), 1);
        assert_eq!(
            store
                .read_durable_index_count()
                .expect("durable index count"),
            0,
            "batched append should leave the commit marker behind"
        );
    }
    kura.block_data
        .lock()
        .push((block_hash, Some((block).clone())));
    kura.set_block_height_index_entry(1, block_hash);
    assert!(
        kura.native_frame_read(1, block_hash).unwrap().is_none(),
        "an uncommitted body cannot supply a native frame receipt"
    );
    {
        let mut store = kura.block_store.lock();
        store
            .flush_pending_fsync(true)
            .expect("force pending fsync");
    }
    let metadata = kura
        .native_frame_read(1, block_hash)
        .unwrap()
        .expect("exact durable frame");
    let wire = block.encode_wire().unwrap();
    assert_eq!(metadata.wire_len(), wire.len() as u64);
    assert_eq!(
        metadata
            .read(
                wire.len() as u64,
                &crate::state::AllocationBudget::new(64 * 1024 * 1024)
            )
            .unwrap()
            .unwrap()
            .as_slice(),
        wire
    );
    let hashes = vec![block_hash];
    let chain_id = ChainId::from("sumeragi-certified-test-chain");
    let network = native_storage_network_id();
    let history_budget = crate::state::AllocationBudget::new(64 * 1024 * 1024);
    let chain = CertifiedChain::from_pinned(&chain_id, &network, &hashes, &kura, &history_budget)
        .expect("independently pinned native genesis");
    assert!(
        chain.authenticated_execution(1).is_err(),
        "the durable genesis frame has no successor certificate for its execution"
    );
}

#[test]
fn store_block_exact_retry_requires_durable_marker() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let mut config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    config.fsync_mode = FsyncMode::Batched;
    config.fsync_interval = Duration::from_secs(3600);
    let (kura, _) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .expect("kura init");
    let block = NativeBlocks::new().next();
    let block_hash = block.hash();
    {
        let mut store = kura.block_store.lock();
        store
            .append_block_to_chain(block.as_ref())
            .expect("append block without forced fsync");
    }
    kura.block_data
        .lock()
        .push((block_hash, Some((block).clone())));
    kura.set_block_height_index_entry(1, block_hash);
    let err = kura
        .store_block((block).clone())
        .expect_err("exact original retry still needs durable Kura marker");
    assert!(matches!(
        err,
        Error::CanonicalBlockWireMismatch { height: 1 }
    ));
    {
        let mut store = kura.block_store.lock();
        store
            .flush_pending_fsync(true)
            .expect("force pending fsync");
    }
    kura.store_block(block)
        .expect("exact original retry succeeds after durable marker");
    assert_eq!(kura.blocks_count(), 1);
    assert_eq!(
        kura.get_durable_block_hash(nonzero!(1_usize)),
        Some(block_hash)
    );
}

#[test]
fn store_block_is_durable_before_return() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let mut config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    config.fsync_interval = Duration::from_secs(3600);
    let (kura, _) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .expect("initialize kura");
    let block = NativeBlocks::new().next();
    let block_hash = block.hash();
    kura.store_block(block).expect("store block");
    let mut store = kura.block_store.lock();
    assert_eq!(store.read_index_count().expect("index count"), 1);
    assert_eq!(
        store
            .read_durable_index_count()
            .expect("durable index count"),
        1,
        "commit marker must advance before store_block returns"
    );
    assert_eq!(
        store.read_block_hashes(0, 1).expect("stored hash"),
        vec![block_hash]
    );
}

#[test]
fn store_block_is_idempotent_for_same_height_and_hash() {
    let (kura, block) = blank_kura_with_next_block();
    let block_hash = block.hash();
    kura.store_block((block).clone()).expect("store block");
    let (index_len, data_len, hashes_len) = {
        let mut store = kura.block_store.lock();
        (
            store.index_file_len().expect("index len"),
            store.data_file_len().expect("data len"),
            store.hashes_file_len().expect("hashes len"),
        )
    };
    kura.store_block(block).expect("idempotent store");
    assert_eq!(kura.blocks_count(), 1);
    let mut store = kura.block_store.lock();
    assert_eq!(store.index_file_len().expect("index len"), index_len);
    assert_eq!(store.data_file_len().expect("data len"), data_len);
    assert_eq!(store.hashes_file_len().expect("hashes len"), hashes_len);
    assert_eq!(
        store.read_block_hashes(0, 1).expect("stored hash"),
        vec![block_hash]
    );
}

#[test]
fn store_block_rejects_height_gap() {
    let kura = Kura::blank_kura_for_testing();
    let block = (native_storage_frames(2)[1]).clone();
    let err = kura.store_block(block).expect_err("height gap");
    assert!(matches!(
        err,
        Error::BlockHeightGap {
            expected_next_height: 1,
            actual_height: 2,
        }
    ));
    assert_eq!(kura.blocks_count(), 0);
}

#[test]
fn store_block_rejects_same_height_different_hash() {
    let (kura, block) = blank_kura_with_next_block();
    let stored_hash = block.hash();
    kura.store_block(block).expect("store first block");
    let foreign = CertifiedTestChain::start(TestChainConfig::new(World::new(), 2_000)).unwrap();
    let conflicting = (foreign.committed(1).block()).clone();
    let conflicting_hash = conflicting.hash();
    assert_ne!(stored_hash, conflicting_hash);
    let err = kura
        .store_block(conflicting)
        .expect_err("same-height different hash must fail");
    assert!(matches!(
        err,
        Error::BlockHeightConflict {
            height: 1,
            expected,
            actual,
        } if expected == stored_hash && actual == conflicting_hash
    ));
    assert_eq!(kura.blocks_count(), 1);
}

#[test]
fn store_block_injected_failure_aborts_sync_append() {
    let (kura, block) = blank_kura_with_next_block();
    let before = snapshot_regular_files_recursively(&kura.store_root());
    kura.fail_next_store_for_tests();
    let result = kura.store_block(block.clone());
    assert!(result.is_err());
    assert_eq!(
        kura.blocks_count(),
        0,
        "failing append should not expose the block in memory"
    );
    assert_eq!(
        snapshot_regular_files_recursively(&kura.store_root()),
        before
    );
    assert!(!kura.canonical_storage_poisoned.load(Ordering::Acquire));
    kura.store_block(block)
        .expect("retry the unchanged original after prewrite failure");
    assert_eq!(kura.exact_durable_blocks_count().unwrap(), 1);
}

#[test]
fn store_block_rejects_when_budget_exceeded() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let kura_cfg = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    let (mut kura, _) =
        Kura::open_test_kura_with_configured_lane_config(&kura_cfg, &RuntimeLaneConfig::default())
            .expect("initialize kura");
    let baseline = canonical_storage_budget_base_for_test(&kura);
    Arc::get_mut(&mut kura)
        .expect("exclusive kura handle")
        .max_disk_usage_bytes = baseline.saturating_add(1);
    let block = NativeBlocks::new().next();
    let expected_required = baseline + Kura::block_required_bytes(&block).unwrap();
    let metrics = Arc::new(Metrics::default());
    let telemetry = StateTelemetry::new(metrics.clone(), true);
    kura.attach_telemetry(telemetry);
    let err = kura
        .store_block(block)
        .expect_err("budgeted kura should reject new blocks");
    assert!(matches!(err, Error::StorageBudgetExceeded { .. }));
    assert_eq!(kura.blocks_count(), 0);
    assert_eq!(canonical_storage_budget_base_for_test(&kura), baseline);
    assert_eq!(
        metrics
            .storage_budget_bytes_used
            .with_label_values(&["kura"])
            .get(),
        expected_required
    );
    assert_eq!(
        metrics
            .storage_budget_bytes_limit
            .with_label_values(&["kura"])
            .get(),
        kura.max_disk_usage_bytes
    );
    assert_eq!(
        metrics
            .storage_budget_exceeded_total
            .with_label_values(&["kura"])
            .get(),
        1
    );
}

#[test]
fn durable_budget_snapshot_avoids_repeated_metadata_reads() {
    let kura = Kura::blank_kura_for_testing();
    kura.invalidate_durable_budget_snapshot();
    assert_eq!(
        kura.durable_budget_metadata_reads.load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        kura.persisted_count_and_unindexed_bytes()
            .expect("cold durable budget snapshot"),
        (0, 0)
    );
    assert_eq!(
        kura.durable_budget_metadata_reads.load(Ordering::Relaxed),
        1,
        "cold snapshot should use one raw metadata read"
    );
    assert_eq!(
        kura.persisted_count_and_unindexed_bytes()
            .expect("cached durable budget snapshot"),
        (0, 0)
    );
    assert_eq!(
        kura.durable_budget_metadata_reads.load(Ordering::Relaxed),
        1,
        "cached snapshot should avoid repeated raw metadata reads"
    );
    let block = NativeBlocks::new().next();
    kura.persist_block_immediate_for_tests(&block);
    assert_eq!(
        kura.persisted_count_and_unindexed_bytes()
            .expect("published durable budget snapshot"),
        (1, 0)
    );
    assert_eq!(
        kura.durable_budget_metadata_reads.load(Ordering::Relaxed),
        1,
        "successful append should publish durable budget metadata directly"
    );
}

#[test]
fn kura_budget_check_scales_with_pending_depth() {
    const PENDING_DEPTH: usize = 128;
    let mut kura = Kura::blank_kura_for_testing();
    Arc::get_mut(&mut kura)
        .expect("exclusive test Kura")
        .max_disk_usage_bytes = u64::MAX / 4;
    let mut blocks = NativeBlocks::new();
    for _ in 0..PENDING_DEPTH {
        kura.append_pending_block_for_bench(blocks.next());
    }
    assert_eq!(kura.pending_budget_raw_scans.load(Ordering::Relaxed), 0);
    let candidate = blocks.next();
    for _ in 0..16 {
        kura.check_storage_budget_for_bench(candidate.as_ref())
            .expect("budget check should fit within the large test limit");
    }
    assert_eq!(
        kura.pending_budget_raw_scans.load(Ordering::Relaxed),
        1,
        "cached pending bytes should avoid repeated raw pending-queue scans"
    );
    let cached_pending_bytes = kura.pending_budget_bytes.load(Ordering::Relaxed);
    assert!(
        cached_pending_bytes > 0,
        "pending budget cache should include queued blocks"
    );
    let extra_pending = blocks.next();
    kura.append_pending_block_for_bench(extra_pending);
    let replacement_candidate = blocks.next();
    kura.check_storage_budget_for_bench(replacement_candidate.as_ref())
        .expect("budget check should still fit after adding one pending block");
    assert_eq!(
        kura.pending_budget_raw_scans.load(Ordering::Relaxed),
        2,
        "cache invalidation should force exactly one fresh raw pending scan"
    );
    assert!(
        kura.pending_budget_bytes.load(Ordering::Relaxed) > cached_pending_bytes,
        "fresh pending cache should include the additional pending block"
    );
}

#[test]
fn store_block_rejects_when_storage_exceeds_budget() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let mut blocks = NativeBlocks::new();
    let first_block = blocks.next();
    let second_block = blocks.next();
    let block1_required = Kura::block_required_bytes(&first_block).expect("block1 required bytes");
    let block2_required = Kura::block_required_bytes(&second_block).expect("block2 required bytes");
    let kura_cfg = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    let (mut kura, _) =
        Kura::open_test_kura_with_configured_lane_config(&kura_cfg, &RuntimeLaneConfig::default())
            .expect("initialize kura");
    publish_initial_configured_lane_geometry_for_test(
        &kura,
        &RuntimeLaneConfig::default(),
        &BTreeMap::new(),
    );
    let baseline = canonical_storage_budget_base_for_test(&kura);
    Arc::get_mut(&mut kura)
        .expect("exclusive kura handle")
        .max_disk_usage_bytes = baseline.saturating_add(block1_required.max(block2_required));
    kura.store_block(first_block).expect("store first block");
    let err = kura
        .store_block(second_block)
        .expect_err("stored bytes should exceed budget");
    assert!(
        matches!(err, Error::StorageBudgetExceeded { .. }),
        "unexpected storage rejection: {err:?}"
    );
}

#[test]
fn store_block_rejects_when_single_block_exceeds_budget() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let kura_cfg = kura_config_for_dir(&temp_dir, NonZeroUsize::new(1).expect("non-zero"));
    let (mut kura, _) =
        Kura::open_test_kura_with_configured_lane_config(&kura_cfg, &RuntimeLaneConfig::default())
            .expect("initialize kura");
    let used = kura.kura_disk_usage_bytes().expect("baseline usage");
    let overhead = BlockIndex::SIZE.saturating_add(SIZE_OF_BLOCK_HASH);
    let budget_limit = used
        .saturating_add(overhead.saturating_mul(2))
        .saturating_add(1);
    Arc::get_mut(&mut kura)
        .expect("exclusive kura handle")
        .max_disk_usage_bytes = budget_limit;
    let block1 = native_storage_frames(1).pop().unwrap();
    let block1_required = Kura::block_required_bytes(&block1).expect("block1 bytes");
    assert!(
        block1_required > budget_limit,
        "expected block to exceed budget"
    );
    let err = kura
        .store_block((block1).clone())
        .expect_err("single block larger than the budget should be rejected");
    assert!(matches!(err, Error::StorageBudgetExceeded { .. }));
    assert_eq!(kura.blocks_count(), 0);
}

#[test]
fn store_block_rejects_when_sidecar_bytes_exceed_budget() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let block = NativeBlocks::new().next();
    let budget_limit = Kura::block_required_bytes(&block).expect("block bytes");
    let kura_cfg = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    let (mut kura, _) =
        Kura::open_test_kura_with_configured_lane_config(&kura_cfg, &RuntimeLaneConfig::default())
            .expect("initialize kura");
    let exact_limit = canonical_storage_budget_base_for_test(&kura).saturating_add(budget_limit);
    Arc::get_mut(&mut kura)
        .expect("exclusive kura handle")
        .max_disk_usage_bytes = exact_limit;
    let blocks_dir = Kura::canonical_storage_path(temp_dir.path());
    let pipeline_dir = blocks_dir.join(PIPELINE_DIR_NAME);
    std::fs::create_dir_all(&pipeline_dir).expect("create pipeline dir");
    std::fs::write(pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE), [0u8; 1])
        .expect("write sidecar data");
    kura.refresh_disk_usage_bytes()
        .expect("refresh disk usage after sidecar write");
    let err = kura
        .store_block(block)
        .expect_err("sidecar bytes should exceed budget");
    assert!(matches!(err, Error::StorageBudgetExceeded { .. }));
    assert_eq!(kura.exact_durable_blocks_count().unwrap(), 0);
    assert_eq!(
        fs::read(pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE)).unwrap(),
        [0]
    );
}

#[test]
fn kura_disk_usage_includes_temp_and_debug_files() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let mut kura_cfg = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    kura_cfg.debug_output_new_blocks = true;
    let (kura, _) =
        Kura::open_test_kura_with_configured_lane_config(&kura_cfg, &RuntimeLaneConfig::default())
            .expect("initialize kura");
    let base = kura.disk_usage_bytes().expect("base usage");
    let blocks_dir = Kura::canonical_storage_path(temp_dir.path());
    let debug_path = kura
        .block_plain_text_path
        .lock()
        .clone()
        .expect("debug path");
    std::fs::write(&debug_path, [0u8; 7]).expect("write debug blocks");
    let temp_marker = blocks_dir
        .join(COUNT_FILE_NAME)
        .with_extension("norito.tmp");
    std::fs::write(&temp_marker, [0u8; 5]).expect("write temp marker");
    let pipeline_dir = blocks_dir.join(PIPELINE_DIR_NAME);
    std::fs::create_dir_all(&pipeline_dir).expect("create pipeline dir");
    let temp_sidecar = pipeline_dir
        .join(PIPELINE_SIDECARS_DATA_FILE)
        .with_extension("norito.tmp");
    std::fs::write(&temp_sidecar, [0u8; 3]).expect("write temp sidecar");
    let updated = kura.refresh_disk_usage_bytes().expect("usage with extras");
    let extra = 7u64 + 5 + 3;
    assert_eq!(updated, base.saturating_add(extra));
}

#[test]
fn combined_blocks_root_scan_separates_enforced_and_total_only_bytes() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let blocks_root = temp_dir.path().join("blocks");
    let blocks_dir = blocks_root.join("canonical");
    std::fs::create_dir_all(&blocks_dir).expect("create block store");
    std::fs::write(blocks_dir.join(DATA_FILE_NAME), [0u8; 11]).expect("write budgeted block bytes");
    let retained_dir = blocks_dir.join(DA_BLOCKS_DIR_NAME);
    std::fs::create_dir_all(&retained_dir).expect("create actual DA custody directory");
    std::fs::write(retained_dir.join("accounting.norito"), [0u8; 7])
        .expect("write total-only DA bytes");

    let (enforced, total) = Kura::blocks_root_usage_bytes(&blocks_root)
        .expect("scan enforced and total usage together");
    assert_eq!(enforced, 11);
    assert_eq!(total, 18);
}

#[test]
fn total_disk_usage_scan_retries_across_replacement_and_unfinished_mutation() {
    let (temp_dir, _config, kura) = kura_root_fixture(BLOCKS_IN_MEMORY);
    let pipeline_dir = Kura::canonical_storage_path(temp_dir.path()).join(PIPELINE_DIR_NAME);
    std::fs::create_dir_all(&pipeline_dir).expect("create actual pipeline accounting directory");
    let path = pipeline_dir.join("accounting-race.norito");
    std::fs::write(&path, [0_u8; 4]).expect("seed existing accounted file");
    let enforced_baseline = kura
        .refresh_disk_usage_bytes()
        .expect("establish enforced-usage baseline");
    let baseline = kura
        .refresh_total_disk_usage_bytes()
        .expect("establish total-usage baseline");
    kura.pause_next_total_disk_usage_scan_after_scan_for_tests();
    let scan_kura = Arc::clone(&kura);
    let (scan_tx, scan_rx) = mpsc::channel();
    let scan = thread::spawn(move || {
        scan_tx
            .send(scan_kura.refresh_total_disk_usage_bytes())
            .expect("report total-usage scan result");
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !kura.total_disk_usage_scan_paused_for_tests() {
        assert!(
            Instant::now() < deadline,
            "total-usage scan did not reach its publication barrier"
        );
        thread::yield_now();
    }
    let accounting_mutation = kura.begin_total_disk_usage_mutation();
    std::fs::write(&path, [0_u8; 9]).expect("replace existing accounted file");
    kura.update_disk_usage_delta(4, 9);
    accounting_mutation.finish();
    assert!(
        matches!(
            scan_rx.recv_timeout(Duration::from_millis(50)),
            Err(RecvTimeoutError::Timeout)
        ),
        "a stale scan must not publish before its deterministic barrier is released"
    );
    kura.resume_total_disk_usage_scan_for_tests();
    let refreshed = scan_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("total-usage scan must retry")
        .expect("retried total-usage scan succeeds");
    scan.join().expect("join total-usage scan");
    let exact_after_replacement = kura
        .kura_total_disk_usage_bytes()
        .expect("rescan after replacement");
    assert_eq!(exact_after_replacement, baseline.saturating_add(5));
    assert_eq!(refreshed, exact_after_replacement);
    assert_eq!(
        kura.disk_usage_total.load(Ordering::Relaxed),
        exact_after_replacement,
        "generation change must force the stale scan to retry before publication"
    );
    assert_eq!(
        kura.disk_usage.load(Ordering::Relaxed),
        enforced_baseline.saturating_add(5)
    );
    kura.pause_next_total_disk_usage_scan_after_scan_for_tests();
    let budget_scan_kura = Arc::clone(&kura);
    let (budget_tx, budget_rx) = mpsc::channel();
    let budget_scan = thread::spawn(move || {
        budget_tx
            .send(budget_scan_kura.refresh_disk_usage_bytes())
            .expect("report enforced-usage scan result");
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !kura.total_disk_usage_scan_paused_for_tests() {
        assert!(
            Instant::now() < deadline,
            "enforced-usage scan did not reach its publication barrier"
        );
        thread::yield_now();
    }
    let budget_mutation = kura.begin_total_disk_usage_mutation();
    std::fs::write(&path, [0_u8; 11]).expect("replace existing budgeted file");
    kura.update_disk_usage_delta(9, 11);
    budget_mutation.finish();
    assert!(matches!(
        budget_rx.recv_timeout(Duration::from_millis(50)),
        Err(RecvTimeoutError::Timeout)
    ));
    kura.resume_total_disk_usage_scan_for_tests();
    let refreshed_enforced = budget_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("enforced-usage scan must retry")
        .expect("retried enforced-usage scan succeeds");
    budget_scan.join().expect("join enforced-usage scan");
    let exact_enforced = kura
        .kura_disk_usage_bytes()
        .expect("rescan enforced usage after replacement");
    let exact_total = kura
        .kura_total_disk_usage_bytes()
        .expect("rescan total usage after budget replacement");
    assert_eq!(refreshed_enforced, exact_enforced);
    assert_eq!(
        kura.disk_usage.load(Ordering::Relaxed),
        exact_enforced,
        "stale enforced scan must retry before publication"
    );
    assert_eq!(
        kura.disk_usage_total.load(Ordering::Relaxed),
        exact_total,
        "combined refresh must publish total usage from the same stable generation"
    );
    let unfinished = kura.begin_total_disk_usage_mutation();
    std::fs::write(&path, [0_u8; 13]).expect("simulate a partially accounted replacement");
    drop(unfinished);
    assert!(
        !kura.disk_usage_total_initialized.load(Ordering::Relaxed),
        "an unfinished mutation must invalidate the total cache"
    );
    assert!(
        !kura.disk_usage_initialized.load(Ordering::Relaxed),
        "an unfinished mutation must invalidate the enforced cache"
    );
    let exact_after_unfinished = kura
        .kura_total_disk_usage_bytes()
        .expect("rescan unfinished replacement");
    let exact_enforced_after_unfinished = kura
        .kura_disk_usage_bytes()
        .expect("rescan enforced usage after unfinished replacement");
    assert_eq!(exact_after_unfinished, exact_total.saturating_add(2));
    assert_eq!(
        kura.refresh_disk_usage_bytes()
            .expect("invalidated enforced cache must refresh on demand"),
        exact_enforced_after_unfinished
    );
    assert_eq!(
        kura.disk_usage_bytes()
            .expect("combined refresh must restore the total cache"),
        exact_after_unfinished
    );
    assert!(kura.disk_usage_initialized.load(Ordering::Relaxed));
    assert!(kura.disk_usage_total_initialized.load(Ordering::Relaxed));
}

#[test]
fn cached_total_usage_read_waits_for_in_flight_mutation_publication() {
    let (_temp_dir, _config, kura) = kura_root_fixture(BLOCKS_IN_MEMORY);
    kura.refresh_disk_usage_bytes()
        .expect("establish exact disk-usage baseline");
    let baseline_total = kura
        .disk_usage_bytes()
        .expect("read exact total-usage baseline");
    let journal_path = kura
        .store_root()
        .join(crate::query::index_status::QueryIndexJournal::JOURNAL_FILE);
    assert!(!journal_path.exists());
    let accounting_mutation = kura.begin_total_disk_usage_mutation();
    std::fs::write(&journal_path, [0xA5_u8; 17]).expect("write an in-flight counted journal");
    let reader_kura = Arc::clone(&kura);
    let (reader_tx, reader_rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        reader_tx
            .send(reader_kura.disk_usage_bytes())
            .expect("report cached total-usage read");
    });
    assert!(
        matches!(
            reader_rx.recv_timeout(Duration::from_millis(50)),
            Err(RecvTimeoutError::Timeout)
        ),
        "a cached total read must not observe an in-flight filesystem mutation"
    );
    kura.update_disk_usage_delta(0, 17);
    accounting_mutation.finish();
    let observed = reader_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("cached reader must resume after publication")
        .expect("cached total-usage read succeeds");
    reader.join().expect("join cached total-usage reader");
    assert_eq!(observed, baseline_total.saturating_add(17));
    assert_eq!(
        observed,
        kura.kura_total_disk_usage_bytes()
            .expect("scan exact usage after publication")
    );
}

#[test]
fn total_only_refresh_invalidates_cached_total_on_scan_error() {
    let (_temp_dir, _config, kura) = kura_root_fixture(BLOCKS_IN_MEMORY);
    kura.refresh_disk_usage_bytes()
        .expect("establish exact disk-usage baseline");
    let cached_total = kura.disk_usage_total.load(Ordering::Relaxed);
    let cached_enforced = kura.disk_usage.load(Ordering::Relaxed);
    let blocks_dir = kura.active_blocks_dir.lock().clone();
    let invalid_total_only_directory = blocks_dir.join(DA_BLOCKS_DIR_NAME);
    std::fs::write(&invalid_total_only_directory, b"not a directory")
        .expect("plant invalid total-only directory path");
    assert!(kura.refresh_total_disk_usage_bytes().is_err());
    assert!(
        !kura.disk_usage_total_initialized.load(Ordering::Relaxed),
        "a failed total-only scan must invalidate the old total cache"
    );
    assert!(
        kura.disk_usage_initialized.load(Ordering::Relaxed),
        "a total-only scan failure must not discard an unchanged enforced cache"
    );
    assert_eq!(kura.disk_usage_total.load(Ordering::Relaxed), cached_total);
    assert_eq!(kura.disk_usage.load(Ordering::Relaxed), cached_enforced);
    std::fs::remove_file(&invalid_total_only_directory).expect("remove invalid total-only path");
    assert_eq!(
        kura.disk_usage_bytes()
            .expect("invalidated total cache refreshes on demand"),
        kura.kura_total_disk_usage_bytes()
            .expect("scan exact total usage after recovery")
    );
    assert!(kura.disk_usage_total_initialized.load(Ordering::Relaxed));
}

#[test]
fn combined_disk_usage_refresh_invalidates_both_caches_on_total_scan_error() {
    let (_temp_dir, _config, kura) = kura_root_fixture(BLOCKS_IN_MEMORY);
    let enforced_before = kura
        .refresh_disk_usage_bytes()
        .expect("establish enforced baseline");
    assert!(kura.durable_budget_snapshot().is_some());
    let total_before = kura.disk_usage_total.load(Ordering::Relaxed);
    let blocks_dir = kura.active_blocks_dir.lock().clone();
    let invalid_total_only_directory = blocks_dir.join(DA_BLOCKS_DIR_NAME);
    std::fs::write(&invalid_total_only_directory, b"not a directory")
        .expect("plant invalid total-only directory path");
    assert!(kura.refresh_disk_usage_bytes().is_err());
    assert!(!kura.disk_usage_initialized.load(Ordering::Relaxed));
    assert!(!kura.disk_usage_total_initialized.load(Ordering::Relaxed));
    assert!(
        kura.durable_budget_snapshot().is_none(),
        "a failed combined scan must invalidate the durable-budget snapshot"
    );
    assert_eq!(kura.disk_usage.load(Ordering::Relaxed), enforced_before);
    assert_eq!(
        kura.disk_usage_total.load(Ordering::Relaxed),
        total_before,
        "a failed combined scan must not partially publish either counter"
    );
    std::fs::remove_file(&invalid_total_only_directory).expect("remove invalid total-only path");
    kura.refresh_disk_usage_bytes()
        .expect("combined refresh recovers after invalid path removal");
    assert!(kura.disk_usage_initialized.load(Ordering::Relaxed));
    assert!(kura.disk_usage_total_initialized.load(Ordering::Relaxed));
}

#[test]
fn retained_physical_custody_remains_accounted_without_release_authority() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let kura_cfg = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    let (mut kura, _) =
        Kura::open_test_kura_with_configured_lane_config(&kura_cfg, &RuntimeLaneConfig::default())
            .expect("initialize kura");
    let baseline = kura.refresh_disk_usage_bytes().expect("baseline usage");
    let geometry_file = temp_dir
        .path()
        .join("retired/lane_geometry/transition/lane_0000000001/blocks/data.norito");
    std::fs::create_dir_all(geometry_file.parent().expect("geometry parent"))
        .expect("create geometry archive");
    std::fs::write(&geometry_file, [0u8; 7]).expect("write geometry evidence");
    let geometry_journal = kura.lane_geometry_journal_path();
    let authenticated_journal = fs::read(&geometry_journal)
        .expect("fresh Kura retains its authenticated configured catalog baseline");
    let with_evidence = kura
        .refresh_disk_usage_bytes()
        .expect("usage with geometry evidence");
    assert_eq!(with_evidence, baseline.saturating_add(7));
    assert_eq!(
        std::fs::read(&geometry_file).expect("geometry evidence retained"),
        [0u8; 7]
    );
    assert_eq!(
        fs::read(&geometry_journal).expect("retained journal"),
        authenticated_journal
    );
    let retired_root = temp_dir.path().join("retired");
    let retired_blocks = retired_root.join("blocks/unowned-accounting-fixture");
    std::fs::create_dir_all(&retired_blocks).expect("create unowned retired blocks");
    std::fs::write(retired_blocks.join(DATA_FILE_NAME), [0u8; 3])
        .expect("write unowned retired block bytes");
    assert_eq!(
        kura.refresh_disk_usage_bytes()
            .expect("usage with unowned retired bytes"),
        baseline.saturating_add(10)
    );
    Arc::get_mut(&mut kura).unwrap().max_disk_usage_bytes = baseline + 10;
    let before = snapshot_regular_files_recursively(&kura.store_root());
    let block = native_storage_frames(1).pop().unwrap();
    // Exhaustion must not turn physically retained bytes into releasable custody.
    assert!(matches!(
        kura.store_block(block),
        Err(Error::StorageBudgetExceeded { .. })
    ));
    assert_eq!(kura.exact_durable_blocks_count().unwrap(), 0);
    assert_eq!(
        snapshot_regular_files_recursively(&kura.store_root()),
        before
    );
    assert_eq!(kura.refresh_disk_usage_bytes().unwrap(), baseline + 10);
    assert!(retired_root.join("blocks").is_dir());
    assert!(geometry_file.is_file());
    assert_eq!(fs::read(geometry_journal).unwrap(), authenticated_journal);
}

#[test]
fn store_block_rejects_when_other_lane_storage_exceeds_budget() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let store_root = temp_dir.path().to_path_buf();
    let lane_count = NonZeroU32::new(2).expect("non-zero lane count");
    let lane0 = ModelLaneConfig::default();
    let lane1 = ModelLaneConfig {
        id: LaneId::from(1),
        alias: "beta".to_string(),
        ..ModelLaneConfig::default()
    };
    let catalog = LaneCatalog::new(lane_count, vec![lane0, lane1]).expect("lane catalog");
    let lane_config = RuntimeLaneConfig::from_catalog(&catalog);
    let block = NativeBlocks::new().next();
    let budget_limit = Kura::block_required_bytes(&block).expect("block bytes");
    let kura_cfg = kura_config_for_path(&store_root, BLOCKS_IN_MEMORY);
    let (mut kura, _) = test_kura_with_default_lane_markers(&kura_cfg, &lane_config);
    let exact_limit = canonical_storage_budget_base_for_test(&kura).saturating_add(budget_limit);
    let lane1_entry = kura
        .lane_storage_entry(LaneId::from(1))
        .expect("exact lane 1 identity");
    let physical_bytes = block.encode_wire().unwrap();
    fs::write(
        lane1_entry.blocks_dir(&store_root).join(DATA_FILE_NAME),
        &physical_bytes,
    )
    .expect("place actual native wire under an independently counted admitted instance");
    let lane1_before = snapshot_regular_files_recursively(&lane1_entry.blocks_dir(&store_root));
    assert!(
        canonical_storage_budget_base_for_test(&kura).saturating_add(budget_limit) > exact_limit
    );
    Arc::get_mut(&mut kura)
        .expect("exclusive kura handle")
        .max_disk_usage_bytes = exact_limit;
    let err = kura
        .store_block(block)
        .expect_err("lane 1 bytes should exceed budget");
    assert!(
        matches!(err, Error::StorageBudgetExceeded { .. }),
        "unexpected storage rejection: {err:?}"
    );
    assert_eq!(
        snapshot_regular_files_recursively(&lane1_entry.blocks_dir(&store_root)),
        lane1_before,
        "budget rejection cannot reclaim live lane-1 evidence"
    );
}

#[test]
fn store_block_does_not_depend_on_writer_channel() {
    let kura = Kura::blank_kura_for_testing();
    kura.block_notify_rx.lock().take();
    let block = NativeBlocks::new().next();
    kura.store_block(block).expect("store block");
    assert_eq!(kura.blocks_count(), 1);
}

#[test]
fn store_block_does_not_depend_on_writer_fault() {
    let kura = Kura::blank_kura_for_testing();
    kura.record_writer_fault("test", &Error::BlockWriterUnavailable);
    let block = NativeBlocks::new().next();
    kura.store_block(block).expect("store block");
    assert_eq!(kura.blocks_count(), 1);
}

#[test]
fn store_block_treats_readable_new_marker_after_ack_failure_as_committed() {
    let temp_dir = TempDir::new().expect("create Kura root");
    let mut config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    config.fsync_mode = FsyncMode::Batched;
    config.fsync_interval = Duration::from_secs(60);
    let (kura, _) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .expect("open Kura");
    kura.block_store
        .lock()
        .fail_next_commit_marker_ack_after_persist
        .store(true, Ordering::Release);
    let block = NativeBlocks::new().next();
    kura.store_block((block).clone())
        .expect("readable new marker is committed success");
    assert_eq!(kura.blocks_count(), 1);
    assert_eq!(
        kura.get_durable_block_hash(nonzero!(1_usize)),
        Some(block.hash())
    );
    assert_eq!(
        kura.get_block(
            nonzero!(1_usize),
            &crate::state::AllocationBudget::new(64 * 1024 * 1024)
        )
        .expect("completed structural storage read")
        .as_deref(),
        Some(block.as_ref())
    );
    assert!(!kura.canonical_storage_poisoned.load(Ordering::Acquire));
}

#[test]
fn unreadable_append_marker_state_poison_gates_live_kura_and_restart_rolls_back() {
    let temp_dir = TempDir::new().expect("create Kura root");
    let mut config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    config.fsync_mode = FsyncMode::Batched;
    config.fsync_interval = Duration::from_secs(60);
    {
        let (kura, _) = test_kura_with_default_lane_markers(&config, &RuntimeLaneConfig::default());
        kura.block_store
            .lock()
            .fail_next_commit_marker_write_and_readback
            .store(true, Ordering::Release);
        let block = NativeBlocks::new().next();
        assert!(matches!(
            kura.store_block(block),
            Err(Error::DaBlockRewriteCommitStateUnknown { .. })
        ));
        assert!(kura.canonical_storage_poisoned.load(Ordering::Acquire));
        assert!(matches!(
            kura.get_block(
                nonzero!(1_usize),
                &crate::state::AllocationBudget::new(64 * 1024 * 1024)
            ),
            Err(crate::execution_attempt::ExecutionAttemptError::Rejected(_))
        ));
        assert!(matches!(
            kura.store_block(NativeBlocks::new().next()),
            Err(Error::CanonicalStoragePoisoned)
        ));
    }
    let (reopened, count) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .expect("old marker prunes the ambiguous unpublished append on restart");
    assert_eq!(count.0, 0);
    assert_eq!(reopened.blocks_count(), 0);
}

#[test]
fn unknown_marker_resolution_selects_exact_native_append_without_publishing_stale_indexes() {
    for new_marker_won in [false, true] {
        let temp_dir = TempDir::new().expect("create Kura root");
        let mut config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
        config.fsync_mode = FsyncMode::Batched;
        config.fsync_interval = Duration::from_secs(60);
        {
            let (kura, _) =
                test_kura_with_default_lane_markers(&config, &RuntimeLaneConfig::default());
            let block = native_storage_frames(1).pop().unwrap();
            let store = kura.block_store.lock();
            if new_marker_won {
                store
                    .fail_next_commit_marker_ack_and_readback
                    .store(true, Ordering::Release);
            } else {
                store
                    .fail_next_commit_marker_write_and_readback
                    .store(true, Ordering::Release);
            }
            drop(store);
            assert!(matches!(
                kura.store_block(block),
                Err(Error::DaBlockRewriteCommitStateUnknown { .. })
            ));
            assert!(kura.canonical_storage_poisoned.load(Ordering::Acquire));
            assert!(kura.block_data.lock().is_empty());
            assert!(kura.block_height_index.lock().is_empty());
            let transaction_index = kura.transaction_entrypoint_index.lock();
            assert!(transaction_index.indexed_heights.is_empty());
            assert!(transaction_index.incomplete_heights.is_empty());
            assert!(transaction_index.heights_by_entrypoint.is_empty());
            drop(transaction_index);
            assert_eq!(
                kura.durable_budget_persisted_count.load(Ordering::Acquire),
                0,
                "fatal publication must not advance process-local budget metadata"
            );
            assert_eq!(
                kura.block_store
                    .lock()
                    .read_commit_marker()
                    .expect("read selected marker")
                    .expect("marker exists")
                    .count,
                u64::from(new_marker_won),
                "the durable marker, not process-local metadata, selects restart recovery"
            );
        }
        let (reopened, count) = Kura::open_test_kura_with_configured_lane_config(
            &config,
            &RuntimeLaneConfig::default(),
        )
        .expect("startup resolves exact native append by original durable marker");
        assert_eq!(count.0, usize::from(new_marker_won));
        assert!(reopened.lane_storage_entries.lock().is_empty());
        assert!(!reopened.canonical_storage_poisoned.load(Ordering::Acquire));
        if new_marker_won {
            let original = native_storage_frames(1).pop().unwrap();
            assert_eq!(
                reopened
                    .canonical_block_wire_bytes_for_testing(nonzero!(1_usize))
                    .unwrap(),
                original.encode_wire().unwrap()
            );
        }
    }
}
