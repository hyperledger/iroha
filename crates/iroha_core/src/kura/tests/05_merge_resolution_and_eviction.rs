#[test]
fn read_and_write_to_blockchain_data_store() {
    let dir = tempfile::tempdir().unwrap();
    let mut block_store = BlockStore::new(dir.path());
    block_store.create_files_if_they_do_not_exist().unwrap();
    block_store
        .write_block_data(43, b"This is some data!")
        .unwrap();
    let mut read_buffer = [0_u8; b"This is some data!".len()];
    block_store.read_block_data(43, &mut read_buffer).unwrap();
    assert_eq!(b"This is some data!", &read_buffer);
}
#[test]
fn block_bytes_matches_direct_read() {
    let dir = tempfile::tempdir().unwrap();
    let mut block_store = BlockStore::new(dir.path());
    block_store.create_files_if_they_do_not_exist().unwrap();
    let dummy_block: SignedBlock = ValidBlock::new_dummy(checked_keypair().private_key()).into();
    block_store.append_block_to_chain(&dummy_block).unwrap();
    let BlockIndex { start, length } = block_store.read_block_index(0).unwrap();
    let len: usize = usize::try_from(length).expect("test block length fits in usize");
    let mut direct = vec![0_u8; len];
    block_store.read_block_data(start, &mut direct).unwrap();
    let slice_bytes = {
        let borrowed = block_store.block_bytes(start, length).unwrap();
        borrowed.to_vec()
    };
    assert_eq!(slice_bytes, direct);
}
#[test]
fn fresh_block_store_has_zero_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let mut block_store = BlockStore::new(dir.path());
    block_store.create_files_if_they_do_not_exist().unwrap();
    assert_eq!(0, block_store.read_index_count().unwrap());
}
#[test]
fn append_block_to_chain_increases_block_count() {
    let dir = tempfile::tempdir().unwrap();
    let mut block_store = BlockStore::new(dir.path());
    block_store.create_files_if_they_do_not_exist().unwrap();
    let dummy_block = ValidBlock::new_dummy(checked_keypair().private_key()).into();
    let append_count: usize = 35;
    for _ in 0..append_count {
        block_store.append_block_to_chain(&dummy_block).unwrap();
    }
    let index_count =
        usize::try_from(block_store.read_index_count().unwrap()).expect("index count fits");
    assert_eq!(append_count, index_count);
}
#[test]
fn append_block_to_chain_increases_hashes_count() {
    let dir = tempfile::tempdir().unwrap();
    let mut block_store = BlockStore::new(dir.path());
    block_store.create_files_if_they_do_not_exist().unwrap();
    let dummy_block = ValidBlock::new_dummy(checked_keypair().private_key()).into();
    let append_count = 35;
    for _ in 0..append_count {
        block_store.append_block_to_chain(&dummy_block).unwrap();
    }
    assert_eq!(append_count, block_store.read_hashes_count().unwrap());
}
#[test]
fn append_block_to_chain_write_correct_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let mut block_store = BlockStore::new(dir.path());
    block_store.create_files_if_they_do_not_exist().unwrap();
    let dummy_block = ValidBlock::new_dummy(checked_keypair().private_key()).into();
    let append_count = 35;
    for _ in 0..append_count {
        block_store.append_block_to_chain(&dummy_block).unwrap();
    }
    let block_hashes = block_store.read_block_hashes(0, append_count).unwrap();
    for hash in block_hashes {
        assert_eq!(hash, dummy_block.hash())
    }
}
#[test]
fn append_block_to_chain_places_blocks_correctly_in_data_file() {
    let dir = tempfile::tempdir().unwrap();
    let mut block_store = BlockStore::new(dir.path());
    block_store.create_files_if_they_do_not_exist().unwrap();
    let dummy_block = ValidBlock::new_dummy(checked_keypair().private_key()).into();
    let append_count: u64 = 35;
    for _ in 0..append_count {
        block_store.append_block_to_chain(&dummy_block).unwrap();
    }
    let block_wire = dummy_block
        .canonical_wire()
        .expect("canonical wire encoding");
    let block_len = block_wire.as_framed().len() as u64;
    for i in 0..append_count {
        let BlockIndex { start, length } = block_store.read_block_index(i).unwrap();
        assert_eq!(i * block_len, start);
        assert_eq!(block_len, length);
    }
}
#[test]
fn append_block_to_chain_roundtrip_decodes() {
    let dir = tempfile::tempdir().unwrap();
    let mut block_store = BlockStore::new(dir.path());
    block_store.create_files_if_they_do_not_exist().unwrap();
    let block = NativeBlocks::new().next();
    block_store.append_block_to_chain(&block).unwrap();
    let BlockIndex { start, length } = block_store.read_block_index(0).unwrap();
    let len: usize = length.try_into().expect("block length fits in usize");
    let mut bytes = vec![0u8; len];
    block_store.read_block_data(start, &mut bytes).unwrap();
    let wire = block.canonical_wire().expect("canonical stored wire");
    let mut payload_cursor = std::io::Cursor::new(wire.payload());
    let decoded_inline =
        SignedBlock::decode(&mut payload_cursor).expect("decode adaptive payload for inline bytes");
    assert_eq!(decoded_inline.hash(), block.hash());
    assert_eq!(bytes[0], wire.version());
    assert!(bytes[1..].starts_with(MAGIC.as_slice()));
    assert_eq!(&bytes[1 + Header::SIZE..], wire.payload());
    let decoded = decode_framed_signed_block(&bytes).expect("decode stored block");
    assert_eq!(decoded.hash(), block.hash());
}
#[test]
fn append_block_batch_persists_all_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let mut block_store = BlockStore::new(dir.path());
    block_store.create_files_if_they_do_not_exist().unwrap();
    let leader = checked_keypair();
    let mut prev_hash = None;
    let mut blocks = Vec::new();
    for _ in 0..3 {
        let block: iroha_data_model::block::SharedSignedBlock = share_storage_fixture(
            ValidBlock::new_dummy_and_modify_header(leader.private_key(), |header| {
                header.set_prev_block_hash(prev_hash);
            })
            .into(),
        );
        prev_hash = Some(block.hash());
        blocks.push(block);
    }
    block_store.append_block_batch(&blocks).unwrap();
    assert_eq!(block_store.read_index_count().unwrap(), 3);
    assert_eq!(block_store.read_hashes_count().unwrap(), 3);
    for (idx, block) in blocks.iter().enumerate() {
        let hash = block_store.read_block_hashes(idx as u64, 1).unwrap();
        assert_eq!(hash, vec![block.hash()]);
    }
}
#[test]
fn append_block_batch_sidecars_block_when_inline_budget_exceeded() {
    let dir = tempfile::tempdir().unwrap();
    let mut block_store = BlockStore::new(dir.path());
    block_store.create_files_if_they_do_not_exist().unwrap();
    let leader = checked_keypair();
    let block1: iroha_data_model::block::SharedSignedBlock =
        share_storage_fixture(ValidBlock::new_dummy(leader.private_key()).into());
    let block2: iroha_data_model::block::SharedSignedBlock = share_storage_fixture(
        ValidBlock::new_dummy_and_modify_header(leader.private_key(), |header| {
            header.set_prev_block_hash(Some(block1.hash()));
        })
        .into(),
    );
    let block1_frame = block1.canonical_wire().expect("block1 wire").into_vec();
    let block2_frame = block2.canonical_wire().expect("block2 wire").into_vec();
    let block1_len = u64::try_from(block1_frame.len()).expect("block1 length");
    let block2_len = u64::try_from(block2_frame.len()).expect("block2 length");
    block_store
        .append_block_batch_at(0, std::slice::from_ref(&block1), 0)
        .expect("append first block");
    let inline_budget = block1_len.saturating_add(2 * (BlockIndex::SIZE + SIZE_OF_BLOCK_HASH));
    block_store
        .append_block_batch_at(1, std::slice::from_ref(&block2), inline_budget)
        .expect("append sidecar block");
    assert_eq!(block_store.read_index_count().unwrap(), 2);
    assert_eq!(block_store.read_hashes_count().unwrap(), 2);
    assert_eq!(
        block_store.data_file_len().expect("data length"),
        block1_len,
        "sidecar append must not grow blocks.data"
    );
    let block2_index = block_store.read_block_index(1).expect("block2 index");
    assert!(block2_index.is_evicted());
    assert_eq!(block2_index.length, block2_len);
    let sidecar_path = block_store.da_block_path(2);
    assert!(sidecar_path.exists(), "sidecar body should be written");
    let sidecar = block_store
        .read_da_block_bytes(2, block2_len)
        .expect("read sidecar body");
    let decoded = decode_framed_signed_block(&sidecar).expect("decode sidecar block");
    assert_eq!(decoded.hash(), block2.hash());
    assert_eq!(
        block_store.read_block_hashes(1, 1).unwrap(),
        vec![block2.hash()]
    );
}
/// Two independently certified successors over the same original signed genesis.
fn native_rewrite_branch_fixture() -> [iroha_data_model::block::SharedSignedBlock; 3] {
    let mut original = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
        .expect("original signed genesis");
    let block1 = (original.committed(1).block()).clone();
    original.commit(Vec::new());
    let block2 = (original.committed(2).block()).clone();
    let mut alternative = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
        .expect("same original signed genesis");
    assert_eq!(alternative.genesis().hash(), block1.hash());
    let replacement_time = original
        .committed(2)
        .block_time_ms()
        .checked_add(1)
        .expect("fixture time has room for a distinct successor");
    alternative.commit_at(replacement_time, Vec::new());
    let replacement = (alternative.committed(2).block()).clone();
    assert_ne!(block2.hash(), replacement.hash());
    [block1, block2, replacement]
}

#[test]
fn restart_resolves_staged_evicted_rewrite_by_durable_marker() {
    let dir = tempfile::tempdir().unwrap();
    let mut block_store = BlockStore::new(dir.path());
    block_store.create_files_if_they_do_not_exist().unwrap();
    let [block1, block2, replacement] = native_rewrite_branch_fixture();
    assert_ne!(replacement.hash(), block2.hash());
    let block1_frame = block1.canonical_wire().expect("block one wire").into_vec();
    let inline_budget = u64::try_from(block1_frame.len())
        .expect("block one length")
        .saturating_add(2 * (BlockIndex::SIZE + SIZE_OF_BLOCK_HASH));
    block_store
        .append_block_batch_at(0, std::slice::from_ref(&block1), 0)
        .expect("append first block");
    block_store
        .append_block_batch_at(1, std::slice::from_ref(&block2), inline_budget)
        .expect("append original evicted block");
    let sidecar_path = block_store.da_block_path(2);
    let original_sidecar = std::fs::read(&sidecar_path).expect("read original sidecar");
    assert_eq!(
        decode_framed_signed_block(&original_sidecar)
            .expect("decode original sidecar")
            .hash(),
        block2.hash()
    );
    block_store
        .fail_next_da_rewrite_before_marker
        .store(true, Ordering::Release);
    let error = block_store
        .append_block_batch_at(1, std::slice::from_ref(&replacement), inline_budget)
        .expect_err("injected pre-marker failure must roll back before returning");
    assert!(matches!(error, Error::IO(_, _)));
    assert_eq!(
        std::fs::read(&sidecar_path).expect("old sidecar survives failed replacement"),
        original_sidecar
    );
    assert!(
        !block_store.da_block_rewrite_stage_path().exists(),
        "in-call rollback must remove the rewrite stage"
    );
    assert_eq!(
        block_store.read_block_hashes(1, 1).unwrap(),
        vec![block2.hash()],
        "live readers must retain the old hash journal after a pre-marker error"
    );
    drop(block_store);
    let mut block_store = BlockStore::new(dir.path());
    block_store
        .create_files_if_they_do_not_exist()
        .expect("restart reconciles the pre-marker rewrite stage");
    assert!(
        !block_store.da_block_rewrite_stage_path().exists(),
        "successful rollback must remove its stage"
    );
    assert_eq!(
        block_store.read_block_hashes(1, 1).unwrap(),
        vec![block2.hash()],
        "the old marker must restore the exact original hash journal"
    );
    assert!(block_store.read_block_index(1).unwrap().is_evicted());
    assert_eq!(
        std::fs::read(&sidecar_path).expect("old sidecar survives restart rollback"),
        original_sidecar,
        "restart must preserve the exact original evicted body"
    );
    block_store
        .fail_next_da_rewrite_after_marker
        .store(true, Ordering::Release);
    block_store
        .append_block_batch_at(1, std::slice::from_ref(&replacement), inline_budget)
        .expect("a durable replacement marker is a committed success");
    assert!(
        !block_store.da_block_rewrite_stage_path().exists(),
        "in-call post-marker recovery must finish body promotion"
    );
    assert!(block_store.take_deferred_da_recovery_fault().is_none());
    let live_replacement_sidecar =
        std::fs::read(&sidecar_path).expect("read live replacement sidecar");
    assert_eq!(
        decode_framed_signed_block(&live_replacement_sidecar)
            .expect("decode live replacement sidecar")
            .hash(),
        replacement.hash(),
        "live readers must observe the committed replacement before return"
    );
    assert_eq!(
        block_store.read_block_hashes(1, 1).unwrap(),
        vec![replacement.hash()]
    );
    drop(block_store);
    let mut block_store = BlockStore::new(dir.path());
    block_store
        .create_files_if_they_do_not_exist()
        .expect("restart promotes a rewrite whose new marker is durable");
    assert!(!block_store.da_block_rewrite_stage_path().exists());
    let replacement_sidecar =
        std::fs::read(&sidecar_path).expect("read atomically replaced sidecar");
    assert_ne!(replacement_sidecar, original_sidecar);
    assert_eq!(
        decode_framed_signed_block(&replacement_sidecar)
            .expect("decode replacement sidecar")
            .hash(),
        replacement.hash()
    );
    assert_eq!(
        block_store.read_block_hashes(1, 1).unwrap(),
        vec![replacement.hash()]
    );
}
#[test]
fn startup_recovers_both_abrupt_da_rewrite_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let mut block_store = BlockStore::new(dir.path());
    block_store.create_files_if_they_do_not_exist().unwrap();
    let [block1, block2, replacement] = native_rewrite_branch_fixture();
    let block1_frame = block1.canonical_wire().expect("block one wire").into_vec();
    let inline_budget = u64::try_from(block1_frame.len())
        .expect("block one length")
        .saturating_add(2 * (BlockIndex::SIZE + SIZE_OF_BLOCK_HASH));
    block_store
        .append_block_batch_at(0, std::slice::from_ref(&block1), 0)
        .expect("append first block");
    block_store
        .append_block_batch_at(1, std::slice::from_ref(&block2), inline_budget)
        .expect("append original evicted block");
    let sidecar_path = block_store.da_block_path(2);
    let original_sidecar = std::fs::read(&sidecar_path).expect("read original sidecar");
    block_store
        .crash_next_da_rewrite_before_marker
        .store(true, Ordering::Release);
    block_store
        .append_block_batch_at(1, std::slice::from_ref(&replacement), inline_budget)
        .expect_err("simulate abrupt stop before marker publication");
    assert!(block_store.da_block_rewrite_stage_path().is_file());
    assert_eq!(
        block_store.read_block_hashes(1, 1).unwrap(),
        vec![replacement.hash()],
        "the simulated crash must occur after replacement journal writes"
    );
    assert_eq!(
        block_store
            .read_commit_marker()
            .unwrap()
            .expect("old marker")
            .tip_hash,
        Some(block2.hash())
    );
    drop(block_store);
    let mut block_store = BlockStore::new(dir.path());
    block_store
        .create_files_if_they_do_not_exist()
        .expect("old marker restores the original rewrite suffix");
    assert!(!block_store.da_block_rewrite_stage_path().exists());
    assert_eq!(
        block_store.read_block_hashes(1, 1).unwrap(),
        vec![block2.hash()]
    );
    assert_eq!(
        std::fs::read(&sidecar_path).expect("old sidecar after startup rollback"),
        original_sidecar
    );
    block_store
        .crash_next_da_rewrite_after_marker
        .store(true, Ordering::Release);
    block_store
        .append_block_batch_at(1, std::slice::from_ref(&replacement), inline_budget)
        .expect_err("simulate abrupt stop after marker publication");
    assert!(block_store.da_block_rewrite_stage_path().is_file());
    assert_eq!(
        block_store
            .read_commit_marker()
            .unwrap()
            .expect("new marker")
            .tip_hash,
        Some(replacement.hash())
    );
    assert_eq!(
        std::fs::read(&sidecar_path).expect("old sidecar before startup promotion"),
        original_sidecar
    );
    drop(block_store);
    let mut block_store = BlockStore::new(dir.path());
    block_store
        .create_files_if_they_do_not_exist()
        .expect("new marker promotes the staged replacement body");
    assert!(!block_store.da_block_rewrite_stage_path().exists());
    let promoted = std::fs::read(&sidecar_path).expect("promoted replacement sidecar");
    assert_eq!(
        decode_framed_signed_block(&promoted)
            .expect("decode promoted replacement")
            .hash(),
        replacement.hash()
    );
    assert_eq!(
        block_store.read_block_hashes(1, 1).unwrap(),
        vec![replacement.hash()]
    );
}

#[test]
fn append_block_batch_at_rewrites_tail() {
    let dir = tempfile::tempdir().unwrap();
    let mut block_store = BlockStore::new(dir.path());
    block_store.create_files_if_they_do_not_exist().unwrap();
    let leader = checked_keypair();
    let block1: iroha_data_model::block::SharedSignedBlock =
        share_storage_fixture(ValidBlock::new_dummy(leader.private_key()).into());
    let block2: iroha_data_model::block::SharedSignedBlock = share_storage_fixture(
        ValidBlock::new_dummy_and_modify_header(leader.private_key(), |header| {
            header.set_prev_block_hash(Some(block1.hash()));
        })
        .into(),
    );
    block_store
        .append_block_batch(&[block1.clone(), block2.clone()])
        .unwrap();
    let replacement: iroha_data_model::block::SharedSignedBlock = share_storage_fixture(
        ValidBlock::new_dummy_and_modify_header(leader.private_key(), |header| {
            header.set_prev_block_hash(Some(block1.hash()));
            header.set_view_change_index(header.view_change_index().saturating_add(1));
        })
        .into(),
    );
    assert_ne!(replacement.hash(), block2.hash(), "replacement must differ");
    block_store
        .append_block_batch_at(1, std::slice::from_ref(&replacement), 0)
        .unwrap();
    assert_eq!(block_store.read_index_count().unwrap(), 2);
    assert_eq!(block_store.read_hashes_count().unwrap(), 2);
    let hash = block_store.read_block_hashes(1, 1).unwrap();
    assert_eq!(hash, vec![replacement.hash()]);
    let BlockIndex { start, length } = block_store.read_block_index(1).unwrap();
    let len: usize = length.try_into().expect("block length fits in usize");
    let mut bytes = vec![0_u8; len];
    block_store.read_block_data(start, &mut bytes).unwrap();
    let decoded = decode_framed_signed_block(&bytes).expect("decode replaced block");
    assert_eq!(decoded.hash(), replacement.hash());
}
#[test]
fn strict_init_kura() {
    let temp_dir = TempDir::new().unwrap();
    Kura::open_test_kura_with_configured_lane_config(
        &Config {
            init_mode: iroha_config::kura::InitMode::Strict,
            store_dir: iroha_config::base::WithOrigin::inline(
                temp_dir.path().to_str().unwrap().into(),
            ),
            max_disk_usage_bytes: iroha_config::parameters::defaults::kura::MAX_DISK_USAGE_BYTES,
            blocks_in_memory: BLOCKS_IN_MEMORY,
            debug_output_new_blocks: false,
            fsync_mode: iroha_config::kura::FsyncMode::Batched,
            fsync_interval: iroha_config::parameters::defaults::kura::FSYNC_INTERVAL,
            native_context_archive_max_bytes:
                iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
            history_checkpoint_cache_capacity:
                iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
            block_hash_history_bytes:
                iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
            transaction_history_bytes:
                iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
            membership_storage: iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
            fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
        },
        &RuntimeLaneConfig::default(),
    )
    .unwrap();
}
#[test]
fn raw_block_read_preserves_wire_without_promoting_execution_custody() {
    let temp_dir = TempDir::new().unwrap();
    let block_count = 3usize;
    populate_store(&temp_dir, block_count);
    let (kura, _) = Kura::open_test_kura_with_configured_lane_config(
        &Config {
            init_mode: iroha_config::kura::InitMode::Strict,
            store_dir: iroha_config::base::WithOrigin::inline(
                temp_dir.path().to_str().unwrap().into(),
            ),
            max_disk_usage_bytes: iroha_config::parameters::defaults::kura::MAX_DISK_USAGE_BYTES,
            blocks_in_memory: BLOCKS_IN_MEMORY,
            debug_output_new_blocks: false,
            fsync_mode: iroha_config::kura::FsyncMode::Batched,
            fsync_interval: iroha_config::parameters::defaults::kura::FSYNC_INTERVAL,
            native_context_archive_max_bytes:
                iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
            history_checkpoint_cache_capacity:
                iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
            block_hash_history_bytes:
                iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
            transaction_history_bytes:
                iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
            membership_storage: iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
            fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
        },
        &RuntimeLaneConfig::default(),
    )
    .unwrap();
    let height = NonZeroUsize::new(block_count).unwrap();
    assert_eq!(
        kura.block_data.lock().len(),
        block_count,
        "strict init should load all appended blocks"
    );
    let first = kura
        .get_block(
            height,
            &crate::state::AllocationBudget::new(64 * 1024 * 1024),
        )
        .expect("completed structural storage read")
        .expect("block available");
    let second = kura
        .get_block(
            height,
            &crate::state::AllocationBudget::new(64 * 1024 * 1024),
        )
        .expect("completed structural storage read")
        .expect("same original wire available");
    assert_eq!(first.encode_wire().unwrap(), second.encode_wire().unwrap());
    assert!(!iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &first, &second
    ));
    assert!(
        kura.block_data
            .lock()
            .cached_body(height.get() - 1)
            .is_none()
    );
    assert!(!kura.transaction_entrypoint_index.lock().complete);
}
#[test]
fn raw_block_reads_do_not_authenticate_reopened_transaction_index() {
    let temp_dir = TempDir::new().unwrap();
    let config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    let (original, _) = test_kura_with_default_lane_markers(&config, &RuntimeLaneConfig::default());
    let blocks = store_dummy_block_arcs(&original, 3);
    drop(original);
    let entrypoint_hash = blocks[2]
        .as_ref()
        .network_input_hashes()
        .next()
        .expect("canonical test block has a transaction");
    let (kura, block_count) = Kura::open_test_kura_with_configured_lane_config(
        &Config {
            init_mode: iroha_config::kura::InitMode::Strict,
            store_dir: iroha_config::base::WithOrigin::inline(
                temp_dir.path().to_str().unwrap().into(),
            ),
            max_disk_usage_bytes: iroha_config::parameters::defaults::kura::MAX_DISK_USAGE_BYTES,
            blocks_in_memory: NonZeroUsize::new(1).expect("non-zero"),
            debug_output_new_blocks: false,
            fsync_mode: iroha_config::kura::FsyncMode::Batched,
            fsync_interval: iroha_config::parameters::defaults::kura::FSYNC_INTERVAL,
            native_context_archive_max_bytes:
                iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
            history_checkpoint_cache_capacity:
                iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
            block_hash_history_bytes:
                iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
            transaction_history_bytes:
                iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
            membership_storage: iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
            fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
        },
        &RuntimeLaneConfig::default(),
    )
    .expect("reopen Kura");
    assert_eq!(block_count.0, 3);
    // A structural read does not authenticate execution or complete query joins.
    let retained_body_index = {
        let block_data = kura.block_data.lock();
        Kura::build_transaction_entrypoint_index(&block_data)
    };
    assert!(
        !retained_body_index.complete,
        "a one-body retained cache must leave a three-block index partial"
    );
    *kura.transaction_entrypoint_index.lock() = retained_body_index;
    assert!(
        kura.get_block_heights_by_entrypoint_hash(entrypoint_hash)
            .is_none(),
        "the retained-body cache starts with a partial transaction index"
    );
    for height in 1..=block_count.0 {
        let height = NonZeroUsize::new(height).expect("non-zero height");
        kura.get_block(
            height,
            &crate::state::AllocationBudget::new(64 * 1024 * 1024),
        )
        .expect("completed structural storage read")
        .expect("block loads from disk");
    }
    assert!(
        kura.get_block_heights_by_entrypoint_hash(entrypoint_hash)
            .is_none()
    );
    assert!(!kura.transaction_entrypoint_index.lock().complete);
}
#[test]
fn drop_persisted_blocks_keeps_genesis_and_recent_blocks() {
    let mut generator = NativeBlocks::new();
    let mut block_data: BlockData = (0..4)
        .map(|_| {
            let block = generator.next();
            (block.hash(), Some(block))
        })
        .collect();
    Kura::drop_persisted_blocks(&mut block_data, 2, 2);
    assert_eq!(
        block_data
            .as_slice()
            .iter()
            .filter(|(_, block)| block.is_some())
            .count(),
        4,
        "no blocks should be dropped while within retention"
    );
    Kura::drop_persisted_blocks(&mut block_data, 4, 2);
    assert!(block_data[0].1.is_some(), "genesis block stays cached");
    assert!(
        block_data[1].1.is_none(),
        "oldest non-genesis block should be dropped"
    );
    assert!(block_data[2].1.is_some(), "recent block should stay cached");
    assert!(block_data[3].1.is_some(), "latest block should stay cached");
}
#[test]
fn drop_persisted_blocks_keeps_unpersisted_blocks() {
    let mut generator = NativeBlocks::new();
    let mut block_data: BlockData = (0..6)
        .map(|_| {
            let block = generator.next();
            (block.hash(), Some(block))
        })
        .collect();
    Kura::drop_persisted_blocks(&mut block_data, 4, 2);
    assert!(block_data[0].1.is_some(), "genesis block stays cached");
    assert!(
        block_data[1].1.is_none(),
        "oldest persisted block should be dropped"
    );
    assert!(
        block_data[2].1.is_some(),
        "retained persisted block stays cached"
    );
    assert!(
        block_data[3].1.is_some(),
        "latest persisted block stays cached"
    );
    assert!(block_data[4].1.is_some(), "unpersisted block stays cached");
    assert!(block_data[5].1.is_some(), "unpersisted block stays cached");
}
#[test]
fn get_block_returns_none_when_data_missing() {
    let temp_dir = TempDir::new().unwrap();
    // Keep a genesis block and one cached tail block around the non-cached block under test.
    // Otherwise `get_block` correctly serves the requested block from memory after the data
    // file is removed, and the test never exercises its missing-disk-data path.
    populate_store(&temp_dir, 3);
    let (kura, _) = Kura::open_test_kura_with_configured_lane_config(
        &Config {
            init_mode: iroha_config::kura::InitMode::Strict,
            store_dir: iroha_config::base::WithOrigin::inline(
                temp_dir.path().to_str().unwrap().into(),
            ),
            max_disk_usage_bytes: iroha_config::parameters::defaults::kura::MAX_DISK_USAGE_BYTES,
            blocks_in_memory: NonZeroUsize::new(1).expect("non-zero"),
            debug_output_new_blocks: false,
            fsync_mode: iroha_config::kura::FsyncMode::Batched,
            fsync_interval: iroha_config::parameters::defaults::kura::FSYNC_INTERVAL,
            native_context_archive_max_bytes:
                iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
            history_checkpoint_cache_capacity:
                iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
            block_hash_history_bytes:
                iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
            transaction_history_bytes:
                iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
            membership_storage: iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
            fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
        },
        &RuntimeLaneConfig::default(),
    )
    .unwrap();
    let data_path = primary_blocks_dir(&temp_dir).join(DATA_FILE_NAME);
    std::fs::remove_file(&data_path).unwrap();
    assert!(
        matches!(
            kura.get_block(
                nonzero!(2_usize),
                &crate::state::AllocationBudget::new(64 * 1024 * 1024)
            ),
            Err(crate::execution_attempt::ExecutionAttemptError::Rejected(_))
        ),
        "a missing committed data file is a storage error"
    );
}
#[test]
fn eviction_compaction_restart_removes_unpublished_orphan_replacements() {
    let temp_dir = TempDir::new().expect("create temp Kura directory");
    populate_store(&temp_dir, 2);
    let blocks_dir = primary_blocks_dir(&temp_dir);
    let data_orphan = blocks_dir.join(EVICTION_COMPACTION_DATA_FILE_NAME);
    let index_orphan = blocks_dir.join(EVICTION_COMPACTION_INDEX_FILE_NAME);
    std::fs::write(&data_orphan, b"unpublished replacement data")
        .expect("write orphan data replacement");
    std::fs::write(&index_orphan, b"unpublished replacement index")
        .expect("write orphan index replacement");
    let config = kura_config_for_dir(&temp_dir, BLOCKS_IN_MEMORY);
    let (_kura, count) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .expect("open and clean Kura");
    assert_eq!(count.0, 2);
    assert!(!data_orphan.exists());
    assert!(!index_orphan.exists());
}
#[test]
fn eviction_digest_is_independent_of_short_reads() {
    struct ShortReader<R> {
        inner: R,
        max: usize,
    }
    impl<R: Read> Read for ShortReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let limit = buffer.len().min(self.max);
            self.inner.read(&mut buffer[..limit])
        }
    }
    let bytes = (0_u32..200_000)
        .map(|value| {
            u8::try_from((value.wrapping_mul(31)) & 0xff).expect("masked fixture byte fits u8")
        })
        .collect::<Vec<_>>();
    let total = u64::try_from(bytes.len()).unwrap();
    let expected =
        BlockStore::eviction_reader_digest(&mut std::io::Cursor::new(bytes.clone()), total)
            .expect("digest ordinary reader");
    let actual = BlockStore::eviction_reader_digest(
        &mut ShortReader {
            inner: std::io::Cursor::new(bytes),
            max: 7,
        },
        total,
    )
    .expect("digest short reader");
    assert_eq!(actual, expected);
}
#[test]
fn canonical_poison_closes_every_handle_of_its_permanent_native_gate() {
    let unrelated = Kura::blank_kura_for_testing();
    let kura = Kura::blank_kura_for_testing();
    let global = kura.native_consensus_gate();
    let lane = kura.native_consensus_gate();
    assert!(Arc::ptr_eq(&global, &lane));
    assert!(global.enter().is_some());
    kura.poison_canonical_storage(
        "injected canonical poison",
        &Error::CanonicalStoragePoisoned,
    );
    assert!(global.is_closed());
    assert!(global.enter().is_none());
    assert!(lane.enter().is_none());
    assert!(unrelated.native_consensus_gate().enter().is_some());
    kura.poison_canonical_storage(
        "duplicate canonical poison",
        &Error::CanonicalStoragePoisoned,
    );
    assert!(global.enter().is_none());
}

#[test]
fn native_gate_obtained_after_canonical_poison_cannot_open_admission() {
    let kura = Kura::blank_kura_for_testing();
    kura.poison_canonical_storage(
        "poison before instance startup",
        &Error::CanonicalStoragePoisoned,
    );
    let later = kura.native_consensus_gate();
    assert!(later.is_closed());
    assert!(later.enter().is_none());
    assert!(Arc::ptr_eq(&later, &kura.native_consensus_gate()));
}

#[test]
fn published_canonical_poison_already_closes_native_admission() {
    let kura = Kura::blank_kura_for_testing();
    kura.pause_canonical_poison_after_latch
        .store(true, Ordering::Release);
    let poison_kura = Arc::clone(&kura);
    let poisoner = thread::spawn(move || {
        poison_kura.poison_canonical_storage(
            "poison racing native startup",
            &Error::CanonicalStoragePoisoned,
        );
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !kura
        .canonical_poison_paused_after_latch
        .load(Ordering::Acquire)
    {
        assert!(
            Instant::now() < deadline,
            "canonical poison missed the post-latch barrier"
        );
        thread::yield_now();
    }
    let published = kura.canonical_storage_poisoned.load(Ordering::Acquire);
    let late = kura.native_consensus_gate();
    let closed_before_resume = late.is_closed() && late.enter().is_none();
    kura.canonical_poison_paused_after_latch
        .store(false, Ordering::Release);
    poisoner.join().expect("canonical poison thread completes");
    assert!(published);
    assert!(
        closed_before_resume,
        "no late binding can reopen the storage owner's gate"
    );
    assert!(late.enter().is_none());
}

#[test]
fn eviction_streaming_digest_preserves_fixed_chunk_framing_and_exact_read_bounds() {
    for length in [
        0_usize, 1, 8191, 8192, 8193, 65_535, 65_536, 65_537, 200_003,
    ] {
        let source: Vec<_> = (0_u8..=u8::MAX).cycle().take(length).collect();
        let total = u64::try_from(length).unwrap();
        // Independent materialized framing is the durable file-digest contract.
        let mut expected = Hash::new(EVICTION_FILE_DIGEST_DOMAIN);
        for chunk in source.chunks(64 * 1024) {
            let mut frame = EVICTION_FILE_DIGEST_DOMAIN.to_vec();
            frame.extend_from_slice(expected.as_ref());
            frame.extend_from_slice(&u64::try_from(chunk.len()).unwrap().to_le_bytes());
            frame.extend_from_slice(chunk);
            expected = Hash::new(frame);
        }
        expected = Hash::new_from_chunks(&[
            EVICTION_FILE_DIGEST_DOMAIN,
            expected.as_ref(),
            &total.to_le_bytes(),
        ]);
        let mut with_tail = source.clone();
        with_tail.push(255);
        let mut reader = std::io::Cursor::new(with_tail);
        assert_eq!(
            BlockStore::eviction_reader_digest(&mut reader, total).unwrap(),
            expected
        );
        assert_eq!(reader.position(), total);
        if length > 0 {
            let mut truncated = std::io::Cursor::new(&source[..length - 1]);
            assert_eq!(
                BlockStore::eviction_reader_digest(&mut truncated, total)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::UnexpectedEof,
            );
        }
    }
}
#[test]
fn drop_persisted_blocks_evicts_only_what_leaves_the_window() {
    let mut generator = NativeBlocks::new();
    let mut block_data: BlockData = (0..2)
        .map(|_| {
            let block = generator.next();
            (block.hash(), Some(block))
        })
        .collect();
    for persisted in 3..=8 {
        let block = generator.next();
        block_data.push((block.hash(), Some(block)));
        Kura::drop_persisted_blocks(&mut block_data, persisted, 2);
        for (index, (_, body)) in block_data.as_slice().iter().enumerate() {
            assert_eq!(
                body.is_some(),
                index == 0 || index + 2 >= persisted,
                "persisted={persisted} index={index}"
            );
        }
    }
    // Shrinking the window evicts the whole newly exposed run at once.
    Kura::drop_persisted_blocks(&mut block_data, 8, 1);
    for (index, (_, body)) in block_data.as_slice().iter().enumerate() {
        assert_eq!(body.is_some(), index == 0 || index == 7, "index={index}");
    }
}
