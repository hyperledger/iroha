//! Regression test for reading blocks from large sparse files without loading the entire file into memory.

use iroha_config::kura::FsyncMode;
use iroha_core::kura::BlockStore;
use std::{
    fs::OpenOptions,
    io::{Seek, SeekFrom, Write},
    time::{Duration, Instant},
};
use tempfile::tempdir;
#[test]
#[cfg_attr(
    not(target_pointer_width = "64"),
    ignore = "requires 64-bit address space"
)]
fn block_bytes_sparse_file_reads_requested_slice() {
    const FILE_LEN: u64 = 16 * 1024 * 1024 * 1024; // 16 GiB
    let temp_dir = tempdir().expect("create temp dir");
    // Zero-interval batching exercises the production durable-write policy.
    let mut store = BlockStore::with_fsync(temp_dir.path(), FsyncMode::Batched, Duration::ZERO);
    store
        .create_files_if_they_do_not_exist()
        .expect("initialize block store");
    let payload = b"block-bytes-regression";
    let offset = FILE_LEN - payload.len() as u64;
    let mut data = OpenOptions::new()
        .write(true)
        .open(temp_dir.path().join("blocks.data"))
        .expect("open sparse block payload file");
    data.seek(SeekFrom::Start(offset))
        .expect("seek to sparse payload offset");
    data.write_all(payload).expect("write sparse payload");
    drop(data);
    let start = Instant::now();
    let slice = store
        .block_bytes(offset, payload.len() as u64)
        .expect("read sparse payload");
    let elapsed = start.elapsed();
    assert_eq!(slice, payload);
    assert!(
        elapsed < Duration::from_secs(5),
        "reading sparse payload took {elapsed:?}",
    );
}
