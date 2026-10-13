//! Durable DA receipt journal and duplicate-admission tests.

use super::*;
use iroha_data_model::da::ingest::StoredDaReceipt;

pub(super) fn test_receipt(
    signer: &KeyPair,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    seed: u8,
) -> DaIngestReceipt {
    let mut receipt = DaIngestReceipt {
        client_blob_id: BlobDigest::new([seed; 32]),
        lane_id,
        epoch,
        blob_hash: BlobDigest::new([seed.wrapping_add(1); 32]),
        chunk_root: BlobDigest::new([seed.wrapping_add(2); 32]),
        manifest_hash: BlobDigest::new([seed.wrapping_add(3); 32]),
        storage_ticket: StorageTicketId::new([seed; 32]),
        pdp_commitment: Some(vec![seed]),
        stripe_layout: DaStripeLayout::default(),
        queued_at_unix: 1234,
        rent_quote: DaRentQuote::default(),
        operator_signature: persistence::receipt_signature_placeholder(),
    };
    let unsigned =
        persistence::unsigned_receipt_bytes(&receipt, sequence).expect("test receipt encodes");
    receipt.operator_signature = checked_signature(signer.private_key(), &unsigned);
    receipt
}
pub(super) fn test_fingerprint(seed: u8) -> ReplayFingerprint {
    ReplayFingerprint::from([seed; blake3::OUT_LEN])
}
pub(super) fn receipt_fingerprint(receipt: &DaIngestReceipt) -> ReplayFingerprint {
    ReplayFingerprint::from(*receipt.storage_ticket.as_bytes())
}
fn receipt_fingerprint_bytes(receipt: &DaIngestReceipt) -> [u8; 32] {
    *receipt.storage_ticket.as_bytes()
}
fn receipt_spool_file_name(
    receipt: &DaIngestReceipt,
    sequence: u64,
    fingerprint: [u8; 32],
) -> String {
    format!(
        "da-receipt-{lane:08x}-{epoch:016x}-{sequence:016x}-{ticket_hex}-{fingerprint_hex}.norito",
        lane = receipt.lane_id.as_u32(),
        epoch = receipt.epoch,
        ticket_hex = hex::encode(receipt.storage_ticket.as_bytes()),
        fingerprint_hex = hex::encode(fingerprint)
    )
}
fn encoded_stored_receipt(receipt: &DaIngestReceipt, sequence: u64, version: u16) -> Vec<u8> {
    to_bytes(&StoredDaReceipt {
        version,
        sequence,
        receipt: receipt.clone(),
    })
    .expect("encode receipt")
}
pub(super) fn receipt_spool_path(
    dir: &Path,
    receipt: &DaIngestReceipt,
    sequence: u64,
    fingerprint: [u8; 32],
) -> PathBuf {
    dir.join(receipt_spool_file_name(receipt, sequence, fingerprint))
}
fn canonical_receipt_spool_path(dir: &Path, receipt: &DaIngestReceipt, sequence: u64) -> PathBuf {
    receipt_spool_path(dir, receipt, sequence, receipt_fingerprint_bytes(receipt))
}
pub(super) fn open_receipt_log(
    dir: &Path,
    cursor_store: &Arc<ReplayCursorStore>,
    signer: &KeyPair,
) -> eyre::Result<DaReceiptLog> {
    DaReceiptLog::open(
        dir.to_path_buf(),
        Arc::clone(cursor_store),
        signer.public_key().clone(),
    )
}
fn receipt_file_count(dir: &Path) -> usize {
    fs::read_dir(dir)
        .expect("read receipt directory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("da-receipt-") && name.ends_with(".norito"))
        })
        .count()
}
pub(super) fn temp_artifact_names(dir: &Path) -> Vec<String> {
    if !dir.exists() {
        return Vec::new();
    }
    fs::read_dir(dir)
        .expect("read artifact directory")
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str().map(ToOwned::to_owned))
        .filter(|name| name.contains(".tmp-"))
        .collect()
}
#[test]
fn persist_da_receipt_writes_and_is_idempotent() {
    let temp_dir = tempdir().expect("temp dir");
    let manifest_dir = temp_dir.path();
    let signer = checked_random_keypair();
    let lane_id = LaneId::new(3);
    let receipt = test_receipt(&signer, lane_id, 5, 7, 0xAA);
    let fingerprint = receipt_fingerprint(&receipt);
    let first_path = persistence::persist_da_receipt(manifest_dir, &receipt, 7, &fingerprint)
        .expect("persist receipt");
    let first_path = first_path.expect("receipt path");
    let bytes = fs::read(&first_path).expect("read receipt file");
    let decoded = decode_from_bytes::<StoredDaReceipt>(&bytes).expect("decode stored receipt");
    assert_eq!(
        bytes,
        norito::encode_canonical(&StoredDaReceipt {
            version: StoredDaReceipt::VERSION,
            sequence: 7,
            receipt: receipt.clone(),
        })
        .expect("shared model reproduces every byte written by the actual Torii producer")
    );
    assert_eq!(decoded.version, StoredDaReceipt::VERSION);
    assert_eq!(decoded.sequence, 7);
    assert_eq!(decoded.receipt.manifest_hash, receipt.manifest_hash);
    let loaded = persistence::load_da_receipts(manifest_dir).expect("load receipts");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].sequence, 7);
    assert_eq!(loaded[0].receipt.manifest_hash, receipt.manifest_hash);
    let core_entries = iroha_core::da::receipts::load_receipt_entries(manifest_dir)
        .expect("Core reads the actual Torii durable receipt frame");
    assert_eq!(core_entries.len(), 1);
    assert_eq!(core_entries[0].sequence, 7);
    assert_eq!(core_entries[0].receipt, receipt);
    assert_eq!(
        bytes[6..22],
        norito::schema::identity::frame_hash::<StoredDaReceipt>()
    );
    let second_path = persistence::persist_da_receipt(manifest_dir, &receipt, 7, &fingerprint)
        .expect("persist again");
    let second_path = second_path.expect("receipt path");
    assert_eq!(first_path, second_path);
}
#[test]
fn persist_da_receipt_rejects_fingerprint_storage_ticket_mismatch() {
    let temp_dir = tempdir().expect("temp dir");
    let signer = checked_fixture_ed25519_keypair(0x60);
    let receipt = test_receipt(&signer, LaneId::new(3), 5, 7, 0xAA);
    let wrong_fingerprint = test_fingerprint(0xCC);
    let err = persistence::persist_da_receipt(temp_dir.path(), &receipt, 7, &wrong_fingerprint)
        .expect_err("fingerprint/storage-ticket mismatch must reject receipt persistence");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        err.to_string().contains("does not match storage ticket"),
        "unexpected receipt persistence error: {err}"
    );
    assert_eq!(
        receipt_file_count(temp_dir.path()),
        0,
        "rejected receipt must not create a durable receipt file"
    );
}
#[cfg(unix)]
#[test]
fn persist_da_receipt_rejects_spool_dir_symlink() {
    use std::os::unix::fs::symlink;
    let temp_dir = tempdir().expect("temp dir");
    let target = temp_dir.path().join("receipt-write-target");
    fs::create_dir(&target).expect("create target directory");
    let spool = temp_dir.path().join("receipt-write-link");
    symlink(&target, &spool).expect("create receipt spool symlink");
    let signer = checked_fixture_ed25519_keypair(0x61);
    let receipt = test_receipt(&signer, LaneId::new(3), 5, 7, 0xAA);
    let fingerprint = receipt_fingerprint(&receipt);
    let err = persistence::persist_da_receipt(&spool, &receipt, 7, &fingerprint)
        .expect_err("symlinked receipt spool root must reject persistence");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains("DA spool path"),
        "unexpected receipt persistence error: {err}"
    );
    assert!(
        fs::symlink_metadata(&spool)
            .expect("inspect spool symlink")
            .file_type()
            .is_symlink(),
        "failed persistence should leave spool symlink visible"
    );
    assert_eq!(
        receipt_file_count(&target),
        0,
        "symlink target must not receive receipt artifacts"
    );
}
#[test]
fn persist_da_receipt_converges_under_same_process_writers() {
    let temp_dir = tempdir().expect("temp dir");
    let manifest_dir = temp_dir.path().to_path_buf();
    let signer = checked_random_keypair();
    let lane_id = LaneId::new(3);
    let receipt = Arc::new(test_receipt(&signer, lane_id, 5, 7, 0xAA));
    let fingerprint = Arc::new(receipt_fingerprint(&receipt));
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::with_capacity(4);
    // Start every barrier participant before waiting for any worker.
    for _ in 0..4 {
        let manifest_dir = manifest_dir.clone();
        let receipt = Arc::clone(&receipt);
        let fingerprint = Arc::clone(&fingerprint);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            persistence::persist_da_receipt(&manifest_dir, &receipt, 7, &fingerprint)
                .expect("concurrent receipt persist")
                .expect("receipt path")
        }));
    }
    let paths: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("writer thread"))
        .collect();
    let first = paths.first().expect("at least one writer");
    assert!(paths.iter().all(|path| path == first));
    assert_eq!(receipt_file_count(&manifest_dir), 1);
    assert!(
        temp_artifact_names(&manifest_dir).is_empty(),
        "concurrent receipt install should not leave temp artifacts"
    );
}
#[test]
fn load_da_receipts_rejects_unsupported_versions() {
    let temp_dir = tempdir().expect("temp dir");
    let manifest_dir = temp_dir.path();
    let signer = checked_random_keypair();
    let lane_id = LaneId::new(3);
    let receipt = test_receipt(&signer, lane_id, 5, 7, 0xAB);
    let bytes = encoded_stored_receipt(&receipt, 7, StoredDaReceipt::VERSION + 1);
    let path = canonical_receipt_spool_path(manifest_dir, &receipt, 7);
    fs::write(&path, bytes).expect("write receipt");
    let err = persistence::load_da_receipts(manifest_dir)
        .expect_err("unsupported receipt versions must reject the receipt load");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}
#[test]
fn load_da_receipts_rejects_filename_body_mismatch() {
    let temp_dir = tempdir().expect("temp dir");
    let manifest_dir = temp_dir.path();
    let signer = checked_random_keypair();
    let lane_id = LaneId::new(3);
    let receipt = test_receipt(&signer, lane_id, 5, 7, 0xAC);
    let bytes = encoded_stored_receipt(&receipt, 7, StoredDaReceipt::VERSION);
    let path = canonical_receipt_spool_path(manifest_dir, &receipt, 8);
    fs::write(&path, bytes).expect("write receipt");
    let err = persistence::load_da_receipts(manifest_dir)
        .expect_err("filename/body mismatches must reject the receipt load");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}
#[test]
fn load_da_receipts_rejects_filename_ticket_mismatch() {
    let temp_dir = tempdir().expect("temp dir");
    let manifest_dir = temp_dir.path();
    let signer = checked_random_keypair();
    let lane_id = LaneId::new(3);
    let receipt = test_receipt(&signer, lane_id, 5, 7, 0xAD);
    let bytes = encoded_stored_receipt(&receipt, 7, StoredDaReceipt::VERSION);
    let mut filename_receipt = receipt;
    filename_receipt.storage_ticket = StorageTicketId::new([0x99; 32]);
    let path = canonical_receipt_spool_path(manifest_dir, &filename_receipt, 7);
    fs::write(&path, bytes).expect("write receipt");
    let err = persistence::load_da_receipts(manifest_dir)
        .expect_err("filename/body ticket mismatches must reject the receipt load");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}
#[test]
fn load_da_receipts_rejects_receipt_shaped_directory() {
    let temp_dir = tempdir().expect("temp dir");
    let manifest_dir = temp_dir.path();
    let signer = checked_random_keypair();
    let receipt = test_receipt(&signer, LaneId::new(3), 5, 7, 0xAE);
    let first_path = canonical_receipt_spool_path(manifest_dir, &receipt, 7);
    let later_path = canonical_receipt_spool_path(manifest_dir, &receipt, 8);
    fs::create_dir(&later_path).expect("create later receipt-shaped directory");
    fs::create_dir(&first_path).expect("create first receipt-shaped directory");
    let err = persistence::load_da_receipts(manifest_dir)
        .expect_err("receipt-shaped directory must reject receipt loading");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    let message = err.to_string();
    assert!(
        message.contains("is not a regular file"),
        "unexpected receipt load error: {err}"
    );
    assert!(
        message.contains(
            first_path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("receipt fixture path is UTF-8")
        ),
        "receipt load should reject the first canonical path: {message}"
    );
    assert!(
        !message.contains(
            later_path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("receipt fixture path is UTF-8")
        ),
        "receipt load should stop at the first canonical path: {message}"
    );
}
#[cfg(unix)]
#[test]
fn load_da_receipts_rejects_spool_dir_symlink() {
    use std::os::unix::fs::symlink;
    let temp_dir = tempdir().expect("temp dir");
    let target = temp_dir.path().join("receipt-spool-target");
    fs::create_dir(&target).expect("create target directory");
    let spool = temp_dir.path().join("receipt-spool-link");
    symlink(&target, &spool).expect("create receipt spool symlink");
    let err = persistence::load_da_receipts(&spool)
        .expect_err("symlinked DA receipt spool root must reject");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains("DA spool path"),
        "unexpected receipt load error: {err}"
    );
    assert!(
        fs::symlink_metadata(&spool)
            .expect("inspect spool symlink")
            .file_type()
            .is_symlink(),
        "failed load should leave spool symlink visible"
    );
    assert!(
        target.exists(),
        "spool symlink target should not be removed"
    );
}
#[test]
fn load_da_receipts_rejects_same_manifest_duplicate_with_different_receipt() {
    let temp_dir = tempdir().expect("temp dir");
    let manifest_dir = temp_dir.path();
    let signer = checked_random_keypair();
    let receipt = test_receipt(&signer, LaneId::new(3), 5, 7, 0xAF);
    let mut conflicting = test_receipt(&signer, LaneId::new(3), 5, 7, 0xB0);
    conflicting.manifest_hash = receipt.manifest_hash;
    let unsigned = persistence::unsigned_receipt_bytes(&conflicting, 7).expect("unsigned bytes");
    conflicting.operator_signature = checked_signature(signer.private_key(), &unsigned);
    for receipt in [&receipt, &conflicting] {
        let bytes = encoded_stored_receipt(receipt, 7, StoredDaReceipt::VERSION);
        let path = canonical_receipt_spool_path(manifest_dir, receipt, 7);
        fs::write(path, bytes).expect("write duplicate receipt");
    }
    let err = persistence::load_da_receipts(manifest_dir)
        .expect_err("conflicting duplicate receipts must reject the receipt load");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains("conflicting duplicate DA receipt"),
        "unexpected receipt load error: {err}"
    );
}
#[test]
fn load_da_receipts_rejects_filename_fingerprint_mismatch() {
    let temp_dir = tempdir().expect("temp dir");
    let manifest_dir = temp_dir.path();
    let signer = checked_random_keypair();
    let receipt = test_receipt(&signer, LaneId::new(3), 5, 7, 0xB1);
    let bytes = encoded_stored_receipt(&receipt, 7, StoredDaReceipt::VERSION);
    for fingerprint in [[0xC2; 32], [0xC3; 32]] {
        let path = receipt_spool_path(manifest_dir, &receipt, 7, fingerprint);
        fs::write(path, &bytes).expect("write duplicate receipt");
    }
    let err = persistence::load_da_receipts(manifest_dir)
        .expect_err("filename fingerprint mismatch must reject the receipt load");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains("mismatches body storage ticket"),
        "unexpected receipt load error: {err}"
    );
}
#[cfg(unix)]
#[test]
fn da_receipt_log_open_rejects_spool_dir_symlink() {
    use std::os::unix::fs::symlink;
    let temp_dir = tempdir().expect("temp dir");
    let target = temp_dir.path().join("receipt-log-target");
    fs::create_dir(&target).expect("create target directory");
    let spool = temp_dir.path().join("receipt-log-link");
    symlink(&target, &spool).expect("create receipt log symlink");
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let signer = checked_fixture_ed25519_keypair(0x62);
    let err = match open_receipt_log(&spool, &cursor_store, &signer) {
        Ok(_) => panic!("symlinked DA receipt log root must reject"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("DA spool path")
            && format!("{err:?}").contains("not a direct directory"),
        "unexpected receipt log open error: {err:?}"
    );
    assert!(
        fs::symlink_metadata(&spool)
            .expect("inspect spool symlink")
            .file_type()
            .is_symlink(),
        "failed open should leave spool symlink visible"
    );
    assert!(
        target.exists(),
        "spool symlink target should not be removed"
    );
}
#[test]
fn da_receipt_log_requires_zero_for_a_fresh_lane_epoch() {
    let temp_dir = tempdir().expect("temp dir");
    let lane_epoch = LaneEpoch::new(LaneId::new(4), 8);
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let signer = checked_random_keypair();
    let log = open_receipt_log(temp_dir.path(), &cursor_store, &signer).unwrap();

    for sequence in [1, u64::MAX - 1] {
        let receipt = test_receipt(
            &signer,
            lane_epoch.lane_id,
            lane_epoch.epoch,
            sequence,
            0xC0,
        );
        assert_eq!(
            log.append(lane_epoch, sequence, receipt, test_fingerprint(0xC0))
                .unwrap(),
            ReceiptInsertOutcome::SequenceGap {
                expected_next: 0,
                observed: sequence,
            }
        );
    }
    assert_eq!(receipt_file_count(temp_dir.path()), 0);
    assert!(cursor_store.highest_sequences().is_empty());

    let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 0, 0xC1);
    assert!(matches!(
        log.append(lane_epoch, 0, receipt, test_fingerprint(0xC1))
            .unwrap(),
        ReceiptInsertOutcome::Stored { .. }
    ));
}
#[test]
fn da_receipt_log_enforces_ordering_and_dedupe() {
    let temp_dir = tempdir().expect("temp dir");
    let lane_epoch = LaneEpoch::new(LaneId::new(4), 9);
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let signer = checked_random_keypair();
    let log = open_receipt_log(temp_dir.path(), &cursor_store, &signer).unwrap();
    let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 0, 1);
    assert!(matches!(
        log.append(lane_epoch, 0, receipt.clone(), test_fingerprint(1))
            .unwrap(),
        ReceiptInsertOutcome::Stored { .. }
    ));
    assert_eq!(
        receipt_file_count(temp_dir.path()),
        1,
        "stored receipt should create one durable receipt file"
    );
    assert!(matches!(
        log.append(lane_epoch, 0, receipt.clone(), test_fingerprint(1))
            .unwrap(),
        ReceiptInsertOutcome::Duplicate { .. }
    ));
    assert_eq!(
        receipt_file_count(temp_dir.path()),
        1,
        "duplicate receipt must not create another durable receipt file"
    );
    let wrong_fingerprint = test_fingerprint(0xD0);
    let err = log
        .append(lane_epoch, 0, receipt.clone(), wrong_fingerprint)
        .expect_err("wrong-fingerprint duplicate must be rejected before durable lookup");
    assert!(
        format!("{err:?}").contains("does not match storage ticket"),
        "unexpected wrong-fingerprint duplicate error: {err:?}"
    );
    assert_eq!(
        receipt_file_count(temp_dir.path()),
        1,
        "wrong-fingerprint duplicate must not create another durable receipt file"
    );
    let mut receipt_conflict = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 0, 0xD1);
    receipt_conflict.manifest_hash = receipt.manifest_hash;
    let unsigned =
        persistence::unsigned_receipt_bytes(&receipt_conflict, 0).expect("unsigned bytes");
    receipt_conflict.operator_signature = checked_signature(signer.private_key(), &unsigned);
    assert!(matches!(
        log.append(lane_epoch, 0, receipt_conflict, test_fingerprint(0xD1))
            .unwrap(),
        ReceiptInsertOutcome::ReceiptConflict { .. }
    ));
    assert_eq!(
        receipt_file_count(temp_dir.path()),
        1,
        "receipt-evidence conflict must not create another durable receipt file"
    );
    let conflict = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 0, 2);
    assert!(matches!(
        log.append(lane_epoch, 0, conflict, test_fingerprint(2))
            .unwrap(),
        ReceiptInsertOutcome::ManifestConflict { .. }
    ));
    assert_eq!(
        receipt_file_count(temp_dir.path()),
        1,
        "conflicting receipt must not be written before validation"
    );
    let gap = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 2, 4);
    assert!(matches!(
        log.append(lane_epoch, 2, gap, test_fingerprint(4)).unwrap(),
        ReceiptInsertOutcome::SequenceGap {
            expected_next: 1,
            observed: 2
        }
    ));
    assert_eq!(
        receipt_file_count(temp_dir.path()),
        1,
        "gap receipt must not be written before validation"
    );
    let second = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 1, 5);
    assert!(matches!(
        log.append(lane_epoch, 1, second, test_fingerprint(5))
            .unwrap(),
        ReceiptInsertOutcome::Stored { .. }
    ));
    assert_eq!(
        receipt_file_count(temp_dir.path()),
        2,
        "contiguous receipt should still be accepted after a rejected gap"
    );
    let stale = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 0, 3);
    assert!(matches!(
        log.append(lane_epoch, 0, stale, test_fingerprint(3))
            .unwrap(),
        ReceiptInsertOutcome::StaleSequence { highest: 1 }
    ));
    assert_eq!(
        receipt_file_count(temp_dir.path()),
        2,
        "stale receipt must not be written before validation"
    );
}
#[test]
fn da_receipt_log_recovery_rejects_filename_fingerprint_mismatch_in_canonical_path_order() {
    for reverse_creation_order in [false, true] {
        let temp_dir = tempdir().expect("temp dir");
        let lane_epoch = LaneEpoch::new(LaneId::new(4), 29);
        let cursor_store = Arc::new(ReplayCursorStore::in_memory());
        let signer = checked_fixture_ed25519_keypair(0x63);
        let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 1, 0xE1);
        let bytes = encoded_stored_receipt(&receipt, 1, StoredDaReceipt::VERSION);
        let higher_path = receipt_spool_path(temp_dir.path(), &receipt, 2, [0xE3; 32]);
        let lower_path = receipt_spool_path(temp_dir.path(), &receipt, 1, [0xE2; 32]);
        let paths = if reverse_creation_order {
            [&higher_path, &lower_path]
        } else {
            [&lower_path, &higher_path]
        };
        for path in paths {
            fs::write(path, &bytes).expect("write mismatched receipt");
        }
        let err = match open_receipt_log(temp_dir.path(), &cursor_store, &signer) {
            Ok(_) => panic!("filename fingerprint mismatch must reject durable recovery"),
            Err(err) => err,
        };
        let message = format!("{err:?}");
        assert!(
            message.contains("mismatches body storage ticket"),
            "unexpected recovery error: {message}"
        );
        message
            .find(&lower_path.display().to_string())
            .expect("recovery error should include the lower canonical path");
        assert!(
            !message.contains(&higher_path.display().to_string()),
            "recovery should stop at the first canonical mismatched path: {message}"
        );
        assert!(
            cursor_store.highest_sequences().is_empty(),
            "failed recovery must not seed receipt cursors"
        );
    }
}
#[test]
fn da_receipt_log_rejected_append_does_not_advance_replay_cursor() {
    let temp_dir = tempdir().expect("temp dir");
    let lane_epoch = LaneEpoch::new(LaneId::new(4), 19);
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let signer = checked_fixture_ed25519_keypair(0x64);
    let log = open_receipt_log(temp_dir.path(), &cursor_store, &signer).unwrap();
    let first = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 0, 0xE1);
    assert!(matches!(
        log.append(lane_epoch, 0, first, test_fingerprint(0xE1))
            .unwrap(),
        ReceiptInsertOutcome::Stored { .. }
    ));
    assert_replay_cursor_sequences(&cursor_store, &[(lane_epoch, 0)]);
    let gap = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 2, 0xE3);
    assert!(matches!(
        log.append(lane_epoch, 2, gap, test_fingerprint(0xE3))
            .unwrap(),
        ReceiptInsertOutcome::SequenceGap {
            expected_next: 1,
            observed: 2
        }
    ));
    assert_replay_cursor_sequences(&cursor_store, &[(lane_epoch, 0)]);
    let second = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 1, 0xE2);
    assert!(matches!(
        log.append(lane_epoch, 1, second, test_fingerprint(0xE2))
            .unwrap(),
        ReceiptInsertOutcome::Stored { .. }
    ));
    assert_replay_cursor_sequences(&cursor_store, &[(lane_epoch, 1)]);
}
#[test]
fn da_receipt_log_recovers_after_cursor_failure_post_file_write() {
    let receipt_dir = tempdir().expect("receipt dir");
    let cursor_dir = tempdir().expect("cursor dir");
    let lane_epoch = LaneEpoch::new(LaneId::new(4), 20);
    let cursor_store =
        Arc::new(ReplayCursorStore::empty(cursor_dir.path().to_path_buf()).expect("cursor store"));
    let signer = checked_fixture_ed25519_keypair(0x65);
    let log = open_receipt_log(receipt_dir.path(), &cursor_store, &signer).unwrap();
    let replay_cache = Arc::new(ReplayCache::new(iroha_core::da::ReplayCacheConfig::new()));
    let journal_path = cursor_dir.path().join("replay_cursors.journal");
    let displaced_journal_path = cursor_dir.path().join("replay_cursors.journal.displaced");
    fs::rename(&journal_path, &displaced_journal_path).expect("displace open cursor journal");
    fs::write(&journal_path, b"replacement journal inode")
        .expect("replace cursor journal pathname");
    let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 0, 0xF1);
    let fingerprint = test_fingerprint(0xF1);
    let (initial_outcome, initial_reservation) =
        replay_cache.reserve(ReplayKey::new(lane_epoch, 0, fingerprint), Instant::now());
    assert!(matches!(initial_outcome, ReplayInsertOutcome::Fresh { .. }));
    let initial_reservation = FreshReplayReservation::new(
        Arc::clone(&replay_cache),
        initial_reservation.expect("fresh replay reservation"),
    );
    let err = log
        .append(lane_epoch, 0, receipt.clone(), fingerprint)
        .expect_err("blocked cursor persistence should fail append after file write");
    assert!(
        format!("{err:?}").contains("failed to persist receipt cursor"),
        "unexpected cursor persistence error: {err:?}"
    );
    assert_eq!(
        receipt_file_count(receipt_dir.path()),
        1,
        "receipt file is durable even when cursor persistence fails"
    );
    assert!(
        log.indexed_sequence_for(lane_epoch).is_none(),
        "failed append must not update the in-memory receipt index"
    );
    assert_replay_cursor_sequences(&cursor_store, &[]);
    drop(initial_reservation);
    fs::remove_file(&journal_path).expect("remove replacement cursor journal");
    fs::rename(&displaced_journal_path, &journal_path).expect("restore open cursor journal");
    let (_, recovered) = log
        .receipt_for_duplicate(lane_epoch, 0, fingerprint)
        .expect("duplicate handler probe repairs receipt state")
        .expect("durable receipt remains present");
    assert_eq!(recovered, receipt);
    assert_eq!(
        receipt_file_count(receipt_dir.path()),
        1,
        "retry should adopt the existing receipt file without duplicating it"
    );
    assert_eq!(log.receipts_for(lane_epoch).len(), 1);
    assert_eq!(log.indexed_sequence_for(lane_epoch), Some(0));
    assert_replay_cursor_sequences(&cursor_store, &[(lane_epoch, 0)]);
    adopt_recovered_da_receipt_in_replay_cache(replay_cache.as_ref(), lane_epoch, 0, fingerprint)
        .expect("retry adopts the repaired receipt into the same-process replay cache");
    let next = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 1, 0xF2);
    let next_fingerprint = test_fingerprint(0xF2);
    let (next_outcome, next_reservation) = replay_cache.reserve(
        ReplayKey::new(lane_epoch, 1, next_fingerprint),
        Instant::now(),
    );
    assert!(matches!(next_outcome, ReplayInsertOutcome::Fresh { .. }));
    let next_receipt_outcome = log
        .append(lane_epoch, 1, next, next_fingerprint)
        .expect("the next ingest succeeds after duplicate recovery");
    assert!(matches!(
        next_receipt_outcome,
        ReceiptInsertOutcome::Stored {
            cursor_advanced: true
        }
    ));
    assert!(
        replay_cache.commit_reservation(&next_reservation.expect("next fresh replay reservation"))
    );
    assert_replay_cursor_sequences(&cursor_store, &[(lane_epoch, 1)]);
}

#[test]
fn recovered_receipt_adoption_never_clears_live_replay_reservations() {
    let cache = ReplayCache::new(iroha_core::da::ReplayCacheConfig::new());
    let recovered_lane = LaneEpoch::new(LaneId::new(4), 120);
    cache
        .prime_lane_epoch(recovered_lane, 0)
        .expect("prime stale startup floor");
    adopt_recovered_da_receipt_in_replay_cache(&cache, recovered_lane, 2, test_fingerprint(0xA2))
        .expect("an empty lane can advance to its authoritative durable receipt");
    let (next_outcome, next_reservation) = cache.reserve(
        ReplayKey::new(recovered_lane, 3, test_fingerprint(0xA3)),
        Instant::now(),
    );
    assert!(matches!(next_outcome, ReplayInsertOutcome::Fresh { .. }));
    assert!(cache.rollback_reservation(
        next_reservation.expect("next sequence reservation remains available")
    ));

    let live_lane = LaneEpoch::new(LaneId::new(4), 121);
    let live_key = ReplayKey::new(live_lane, 0, test_fingerprint(0xB0));
    let (live_outcome, live_reservation) = cache.reserve(live_key, Instant::now());
    assert!(matches!(live_outcome, ReplayInsertOutcome::Fresh { .. }));
    let error =
        adopt_recovered_da_receipt_in_replay_cache(&cache, live_lane, 2, test_fingerprint(0xB2))
            .expect_err("recovery must not prime over a live reservation");
    assert!(error.contains("live replay entries or reservations"));
    assert!(matches!(
        cache.reserve(live_key, Instant::now()).0,
        ReplayInsertOutcome::InFlight { .. }
    ));
    assert!(cache.rollback_reservation(
        live_reservation.expect("live reservation survives rejected recovery")
    ));
}

#[test]
fn da_receipt_log_rejects_conflicting_preexisting_receipt_without_cursor_advance() {
    let receipt_dir = tempdir().expect("receipt dir");
    let lane_epoch = LaneEpoch::new(LaneId::new(4), 21);
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let signer = checked_fixture_ed25519_keypair(0x66);
    let log = open_receipt_log(receipt_dir.path(), &cursor_store, &signer).unwrap();
    let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 0, 0xF2);
    let fingerprint = test_fingerprint(0xF2);
    let poisoned_path = canonical_receipt_spool_path(receipt_dir.path(), &receipt, 0);
    fs::write(&poisoned_path, b"poison-receipt").expect("seed poisoned receipt");
    let err = log
        .append(lane_epoch, 0, receipt.clone(), fingerprint)
        .expect_err("conflicting preexisting receipt file must reject append");
    assert!(
        format!("{err:?}").contains("DA receipt artifact already exists"),
        "unexpected preexisting receipt error: {err:?}"
    );
    assert_eq!(
        fs::read(&poisoned_path).expect("read poisoned receipt"),
        b"poison-receipt",
        "conflicting receipt file must be preserved for operator repair"
    );
    assert_eq!(receipt_file_count(receipt_dir.path()), 1);
    assert!(
        log.indexed_sequence_for(lane_epoch).is_none(),
        "failed append must not update the in-memory receipt index"
    );
    assert_replay_cursor_sequences(&cursor_store, &[]);
    fs::remove_file(&poisoned_path).expect("remove poisoned receipt");
    assert!(matches!(
        log.append(lane_epoch, 0, receipt, fingerprint).unwrap(),
        ReceiptInsertOutcome::Stored {
            cursor_advanced: true
        }
    ));
    assert_eq!(receipt_file_count(receipt_dir.path()), 1);
    assert_eq!(log.receipts_for(lane_epoch).len(), 1);
    assert_eq!(log.indexed_sequence_for(lane_epoch), Some(0));
    assert_replay_cursor_sequences(&cursor_store, &[(lane_epoch, 0)]);
}
#[test]
fn da_receipt_log_in_memory_append_fails_closed() {
    let lane_epoch = LaneEpoch::new(LaneId::new(4), 10);
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let signer = checked_random_keypair();
    let log = DaReceiptLog::in_memory(Arc::clone(&cursor_store), signer.public_key().clone());
    let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 1, 0xA1);
    let err = log
        .append(lane_epoch, 1, receipt, test_fingerprint(0xA1))
        .expect_err("in-memory receipt logs must not acknowledge DA ingest appends");
    assert!(
        format!("{err:?}").contains("not durable"),
        "unexpected in-memory append error: {err:?}"
    );
    assert!(
        log.indexed_sequence_for(lane_epoch).is_none(),
        "failed in-memory append must not update receipt-log memory"
    );
    assert!(
        cursor_store.highest_sequences().is_empty(),
        "failed in-memory append must not advance replay cursors"
    );
    let err = log
        .receipt_for_duplicate(lane_epoch, 1, test_fingerprint(0xA1))
        .expect_err("in-memory duplicate lookup must fail closed");
    assert!(
        format!("{err:?}").contains("not durable"),
        "unexpected in-memory duplicate lookup error: {err:?}"
    );
}
#[cfg(unix)]
#[test]
fn da_receipt_log_duplicate_reload_rejects_receipt_symlink_replacement() {
    use std::os::unix::fs::symlink;
    let receipt_dir = tempdir().expect("receipt dir");
    let lane_epoch = LaneEpoch::new(LaneId::new(4), 10);
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let signer = checked_fixture_ed25519_keypair(0x67);
    let log =
        open_receipt_log(receipt_dir.path(), &cursor_store, &signer).expect("open receipt log");
    let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 0, 0xA2);
    let fingerprint = test_fingerprint(0xA2);
    assert!(matches!(
        log.append(lane_epoch, 0, receipt.clone(), fingerprint)
            .expect("append receipt"),
        ReceiptInsertOutcome::Stored { .. }
    ));
    let receipt_path = canonical_receipt_spool_path(receipt_dir.path(), &receipt, 0);
    let target_path = receipt_dir.path().join("receipt-symlink-target.norito");
    fs::write(
        &target_path,
        fs::read(&receipt_path).expect("read stored receipt"),
    )
    .expect("write receipt symlink target");
    fs::remove_file(&receipt_path).expect("remove stored receipt");
    symlink(&target_path, &receipt_path).expect("replace receipt with symlink");
    let err = log
        .receipt_for_duplicate(lane_epoch, 0, fingerprint)
        .expect_err("symlinked durable receipt must fail duplicate reload");
    assert!(
        format!("{err:?}").contains("not a direct regular file"),
        "unexpected duplicate receipt reload error: {err:?}"
    );
    assert!(
        fs::symlink_metadata(&receipt_path)
            .expect("inspect receipt symlink")
            .file_type()
            .is_symlink(),
        "failed duplicate reload should leave receipt symlink visible"
    );
    assert!(
        target_path.exists(),
        "receipt symlink target should remain for operator repair"
    );
}
#[test]
fn duplicate_da_ingest_reuses_durable_artifacts_after_timestamp_retry() {
    let temp_dir = tempdir().expect("temp dir");
    let spool_dir = temp_dir.path();
    let context = zero_sequence_manifest_context_for(BlobClass::NexusLaneSidecar);
    let request = context.request;
    let manifest = context.artifacts;
    let canonical = normalize_payload(&request).expect("normalize payload");
    let chunk_store = build_chunk_store(&request, canonical.as_slice());
    let metadata =
        encrypt_governance_metadata(&request.metadata, None, None).expect("metadata encryption");
    let rent_policy = DaRentPolicyV1::default();
    let retry_manifest = resolve_manifest(
        &request,
        &chunk_store,
        canonical.as_slice(),
        &metadata,
        &request.retention_policy,
        1_701_001_111,
        &rent_policy,
    )
    .expect("retry manifest");
    assert_eq!(retry_manifest.storage_ticket, manifest.storage_ticket);
    assert_eq!(retry_manifest.fingerprint, manifest.fingerprint);
    assert_ne!(
        retry_manifest.manifest_hash, manifest.manifest_hash,
        "retry timestamp should change the timestamped manifest hash"
    );
    persistence::persist_manifest_for_sorafs(
        spool_dir,
        &manifest.encoded,
        request.lane_id,
        request.epoch,
        request.sequence,
        &manifest.storage_ticket,
        &manifest.fingerprint,
    )
    .expect("persist manifest")
    .expect("manifest path");
    let durable_scope =
        build_da_pin_scope(&request, manifest.storage_ticket, manifest.manifest_hash)
            .expect("build durable pin scope");
    persistence::persist_da_pin_scope(
        spool_dir,
        &durable_scope,
        request.lane_id,
        request.epoch,
        request.sequence,
        &manifest.storage_ticket,
        &manifest.fingerprint,
    )
    .expect("persist pin scope")
    .expect("pin-scope path");
    let durable_pin_intent = signed_pin_intent_for_manifest(&request, &manifest);
    persistence::persist_da_pin_intent(
        spool_dir,
        &durable_pin_intent,
        request.lane_id,
        request.epoch,
        request.sequence,
        &manifest.storage_ticket,
        &manifest.fingerprint,
    )
    .expect("persist pin intent")
    .expect("pin intent path");
    let pdp_commitment = compute_pdp_commitment(
        &manifest.manifest_hash,
        &manifest.manifest,
        &chunk_store,
        canonical.as_slice(),
        1_701_000_999,
    )
    .expect("PDP commitment");
    let pdp_bytes = encode_pdp_commitment_bytes(&pdp_commitment).expect("encode PDP commitment");
    persistence::persist_pdp_commitment(
        spool_dir,
        &pdp_commitment,
        request.lane_id,
        request.epoch,
        request.sequence,
        &manifest.storage_ticket,
        &manifest.fingerprint,
    )
    .expect("persist PDP")
    .expect("PDP path");
    let signer = checked_random_keypair();
    let lane_epoch = LaneEpoch::new(request.lane_id, request.epoch);
    let receipt = build_receipt(
        &signer,
        &request,
        1_701_000_999,
        manifest.blob_hash,
        manifest.chunk_root,
        manifest.manifest_hash,
        manifest.storage_ticket,
        pdp_bytes.clone(),
        manifest.manifest.rent_quote.clone(),
        stripe_layout_from_manifest(&manifest.manifest),
    )
    .expect("build receipt");
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let log = open_receipt_log(spool_dir, &cursor_store, &signer).expect("open receipt log");
    assert!(matches!(
        log.append(
            lane_epoch,
            request.sequence,
            receipt.clone(),
            manifest.fingerprint
        )
        .expect("append receipt"),
        ReceiptInsertOutcome::Stored { .. }
    ));
    let duplicate = load_duplicate_da_artifacts(
        &log,
        spool_dir,
        lane_epoch,
        request.sequence,
        &retry_manifest.storage_ticket,
        retry_manifest.fingerprint,
        &request,
    )
    .expect("load duplicate artifacts");
    assert_eq!(duplicate.receipt, receipt);
    assert_eq!(duplicate.pdp_commitment_bytes, pdp_bytes);
    assert_eq!(
        receipt_file_count(spool_dir),
        1,
        "duplicate artifact recovery must not write another receipt"
    );
    let reopened_cursor = Arc::new(ReplayCursorStore::in_memory());
    let reopened_log = DaReceiptLog::open(
        spool_dir.to_path_buf(),
        reopened_cursor,
        signer.public_key().clone(),
    )
    .expect("reopen durable receipt log");
    let recovered_after_restart = load_duplicate_da_artifacts_if_receipt_present(
        &reopened_log,
        spool_dir,
        lane_epoch,
        request.sequence,
        &retry_manifest.storage_ticket,
        retry_manifest.fingerprint,
        &request,
    )
    .expect("check durable duplicate after restart")
    .expect("durable duplicate should be present after restart");
    assert_eq!(recovered_after_restart.receipt, receipt);
    assert_eq!(recovered_after_restart.pdp_commitment_bytes, pdp_bytes);
}

#[test]
fn duplicate_retry_finalizes_only_after_exact_pin_scope_signature() {
    let temp_dir = tempdir().expect("temp dir");
    let context = zero_sequence_manifest_context_for(BlobClass::TaikaiSegment);
    let mut request = context.request;
    let manifest = context.artifacts;
    let scope = build_da_pin_scope(&request, manifest.storage_ticket, manifest.manifest_hash)
        .expect("build exact pin scope");
    let operator = checked_fixture_ed25519_keypair(0x69);
    let receipt = build_receipt(
        &operator,
        &request,
        manifest.manifest.issued_at_unix.max(1),
        manifest.blob_hash,
        manifest.chunk_root,
        manifest.manifest_hash,
        manifest.storage_ticket,
        Vec::new(),
        manifest.manifest.rent_quote.clone(),
        stripe_layout_from_manifest(&manifest.manifest),
    )
    .expect("build pending receipt fixture");
    let lane_epoch = LaneEpoch::new(request.lane_id, request.epoch);
    // Readiness requires the envelope to have been staged by the earlier ingest phase.
    taikai_ingest::persist_envelope(
        temp_dir.path(),
        request.lane_id,
        request.epoch,
        request.sequence,
        &manifest.storage_ticket,
        &manifest.fingerprint,
        b"envelope",
    )
    .expect("stage envelope fixture")
    .expect("envelope path");
    let artifacts = DuplicateDaArtifacts {
        receipt_path: temp_dir.path().join("receipt.norito"),
        receipt,
        pdp_commitment_bytes: Vec::new(),
        pin_scope: scope.clone(),
        pin_intent: None,
    };

    let (pending, finalized) = finalize_duplicate_da_pin_intent(
        temp_dir.path(),
        &request,
        lane_epoch,
        manifest.fingerprint,
        artifacts,
    )
    .expect("unsigned scope remains pending");
    assert!(!finalized);
    assert!(pending.pin_intent.is_none());
    assert!(!taikai_ready_path(temp_dir.path(), &request, &manifest).exists());

    request
        .try_add_pin_scope_signature(
            &scope,
            &checked_fixture_keypair(vec![0x42; 32], Algorithm::Ed25519),
        )
        .expect("authorize exact durable pin scope");
    let (finalized_artifacts, finalized) = finalize_duplicate_da_pin_intent(
        temp_dir.path(),
        &request,
        lane_epoch,
        manifest.fingerprint,
        pending,
    )
    .expect("exact producer scope finalizes");
    assert!(finalized);
    assert!(finalized_artifacts.pin_intent.is_some());
    assert!(taikai_ready_path(temp_dir.path(), &request, &manifest).exists());
    persistence::load_da_pin_intent(
        temp_dir.path(),
        request.lane_id,
        request.epoch,
        request.sequence,
        &manifest.storage_ticket,
        &manifest.fingerprint,
    )
    .expect("producer-authorized pin intent must be durable");
}

#[test]
fn submitted_pin_scope_witness_cannot_authorize_a_different_durable_scope() {
    let context = zero_sequence_manifest_context_for(BlobClass::NexusLaneSidecar);
    let request = context.request;
    let manifest = context.artifacts;
    let exact_scope = build_da_pin_scope(&request, manifest.storage_ticket, manifest.manifest_hash)
        .expect("build exact durable pin scope");
    let signer = checked_fixture_keypair(vec![0x42; 32], Algorithm::Ed25519);

    for forged_scope in [
        DaPinScopeV1 {
            storage_ticket: StorageTicketId::new([0xA1; 32]),
            ..exact_scope.clone()
        },
        DaPinScopeV1 {
            manifest_hash: ManifestDigest::new([0xA2; 32]),
            ..exact_scope.clone()
        },
        DaPinScopeV1 {
            alias: Some("forged-alias".to_owned()),
            ..exact_scope.clone()
        },
    ] {
        let mut forged_request = request.clone();
        forged_request
            .try_add_pin_scope_signature(&forged_scope, &signer)
            .expect("sign forged pin scope fixture");
        let error = submitted_pin_scope_authorization(&forged_request, exact_scope.clone())
            .expect_err("a witness over another scope must reject");
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
    }
}

fn persist_completed_duplicate_fixture(
    spool_dir: &Path,
    request: &DaIngestRequest,
    manifest: &ManifestArtifacts,
) -> DaReceiptLog {
    let canonical = normalize_payload(request).expect("normalize duplicate fixture payload");
    let chunk_store = build_chunk_store(request, canonical.as_slice());
    persistence::persist_manifest_for_sorafs(
        spool_dir,
        &manifest.encoded,
        request.lane_id,
        request.epoch,
        request.sequence,
        &manifest.storage_ticket,
        &manifest.fingerprint,
    )
    .expect("persist duplicate fixture manifest")
    .expect("duplicate fixture manifest path");
    let pin_scope = build_da_pin_scope(request, manifest.storage_ticket, manifest.manifest_hash)
        .expect("build duplicate fixture pin scope");
    persistence::persist_da_pin_scope(
        spool_dir,
        &pin_scope,
        request.lane_id,
        request.epoch,
        request.sequence,
        &manifest.storage_ticket,
        &manifest.fingerprint,
    )
    .expect("persist duplicate fixture pin scope")
    .expect("duplicate fixture pin-scope path");
    let pin_intent = signed_pin_intent_for_manifest(request, manifest);
    persistence::persist_da_pin_intent(
        spool_dir,
        &pin_intent,
        request.lane_id,
        request.epoch,
        request.sequence,
        &manifest.storage_ticket,
        &manifest.fingerprint,
    )
    .expect("persist duplicate fixture pin intent")
    .expect("duplicate fixture pin-intent path");
    let sealed_at_unix = manifest.manifest.issued_at_unix.max(1);
    let pdp_commitment = compute_pdp_commitment(
        &manifest.manifest_hash,
        &manifest.manifest,
        &chunk_store,
        canonical.as_slice(),
        sealed_at_unix,
    )
    .expect("compute duplicate fixture PDP commitment");
    let pdp_bytes =
        encode_pdp_commitment_bytes(&pdp_commitment).expect("encode duplicate fixture PDP");
    persistence::persist_pdp_commitment(
        spool_dir,
        &pdp_commitment,
        request.lane_id,
        request.epoch,
        request.sequence,
        &manifest.storage_ticket,
        &manifest.fingerprint,
    )
    .expect("persist duplicate fixture PDP")
    .expect("duplicate fixture PDP path");
    let signer = checked_fixture_ed25519_keypair(0x6A);
    let receipt = build_receipt(
        &signer,
        request,
        sealed_at_unix,
        manifest.blob_hash,
        manifest.chunk_root,
        manifest.manifest_hash,
        manifest.storage_ticket,
        pdp_bytes,
        manifest.manifest.rent_quote.clone(),
        stripe_layout_from_manifest(&manifest.manifest),
    )
    .expect("build duplicate fixture receipt");
    let lane_epoch = LaneEpoch::new(request.lane_id, request.epoch);
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let log = open_receipt_log(spool_dir, &cursor_store, &signer)
        .expect("open duplicate fixture receipt log");
    assert!(matches!(
        log.append(lane_epoch, request.sequence, receipt, manifest.fingerprint)
            .expect("append duplicate fixture receipt"),
        ReceiptInsertOutcome::Stored { .. }
    ));
    log
}

fn load_duplicate_da_artifacts_and_publish_taikai_ready(
    receipt_log: &DaReceiptLog,
    spool_dir: &Path,
    request: &DaIngestRequest,
    manifest: &ManifestArtifacts,
    lane_epoch: LaneEpoch,
) -> Result<DuplicateDaArtifacts, DuplicateDaArtifactsError> {
    let artifacts = load_duplicate_da_artifacts(
        receipt_log,
        spool_dir,
        lane_epoch,
        request.sequence,
        &manifest.storage_ticket,
        manifest.fingerprint,
        request,
    )?;
    finalize_duplicate_da_pin_intent(
        spool_dir,
        request,
        lane_epoch,
        manifest.fingerprint,
        artifacts,
    )
    .map(|(artifacts, _)| artifacts)
}

fn resign_duplicate_fixture_request(request: &mut DaIngestRequest) {
    let keypair = checked_fixture_keypair(vec![0x42; 32], Algorithm::Ed25519);
    let digest = request.signing_digest();
    request.signatures[0].signature = checked_signature(keypair.private_key(), &digest);
}

fn taikai_ready_path(
    spool_dir: &Path,
    request: &DaIngestRequest,
    manifest: &ManifestArtifacts,
) -> PathBuf {
    spool_dir.join(TAIKAI_SPOOL_SUBDIR).join(format!(
        "{TAIKAI_ANCHOR_READY_PREFIX}{lane:08x}-{epoch:016x}-{sequence:016x}-{ticket}-{fingerprint}{TAIKAI_ANCHOR_READY_SUFFIX}",
        lane = request.lane_id.as_u32(),
        epoch = request.epoch,
        sequence = request.sequence,
        ticket = hex::encode(manifest.storage_ticket.as_ref()),
        fingerprint = hex::encode(manifest.fingerprint.as_bytes()),
    ))
}

#[test]
fn completed_taikai_duplicate_rejects_changed_stripped_ssm_identity() {
    let temp_dir = tempdir().expect("temp dir");
    let context = zero_sequence_manifest_context_for(BlobClass::TaikaiSegment);
    let mut request = context.request;
    let manifest = context.artifacts;
    request.norito_manifest = Some(manifest.encoded.clone());
    request.metadata.items.push(MetadataEntry::new(
        taikai::META_TAIKAI_SSM,
        b"first signed Taikai manifest".to_vec(),
        MetadataVisibility::Public,
    ));
    resign_duplicate_fixture_request(&mut request);
    let receipt_log = persist_completed_duplicate_fixture(temp_dir.path(), &request, &manifest);
    load_duplicate_da_artifacts(
        &receipt_log,
        temp_dir.path(),
        LaneEpoch::new(request.lane_id, request.epoch),
        request.sequence,
        &manifest.storage_ticket,
        manifest.fingerprint,
        &request,
    )
    .expect("matching completed Taikai duplicate must recover");

    let mut retry = request.clone();
    retry
        .metadata
        .items
        .iter_mut()
        .find(|entry| entry.key == taikai::META_TAIKAI_SSM)
        .expect("SSM metadata entry")
        .value = b"different signed Taikai manifest".to_vec();
    resign_duplicate_fixture_request(&mut retry);
    assert_ne!(request.signing_digest(), retry.signing_digest());
    let err = load_duplicate_da_artifacts_and_publish_taikai_ready(
        &receipt_log,
        temp_dir.path(),
        &retry,
        &manifest,
        LaneEpoch::new(retry.lane_id, retry.epoch),
    )
    .expect_err("changed stripped SSM must conflict with the completed request identity");
    assert!(matches!(err, DuplicateDaArtifactsError::Conflict(_)));
    assert!(
        !taikai_ready_path(temp_dir.path(), &retry, &manifest).exists(),
        "identity-conflicting duplicate must not publish Taikai readiness"
    );
}

#[test]
fn completed_taikai_duplicate_rejects_changed_caller_manifest_timestamp() {
    let temp_dir = tempdir().expect("temp dir");
    let context = zero_sequence_manifest_context_for(BlobClass::TaikaiSegment);
    let mut request = context.request;
    let manifest = context.artifacts;
    request.norito_manifest = Some(manifest.encoded.clone());
    resign_duplicate_fixture_request(&mut request);
    let receipt_log = persist_completed_duplicate_fixture(temp_dir.path(), &request, &manifest);

    let mut retry = request.clone();
    let mut changed_manifest = manifest.manifest.clone();
    changed_manifest.issued_at_unix = changed_manifest.issued_at_unix.saturating_add(1);
    retry.norito_manifest = Some(to_bytes(&changed_manifest).expect("encode changed manifest"));
    resign_duplicate_fixture_request(&mut retry);
    assert_ne!(request.signing_digest(), retry.signing_digest());
    let err = load_duplicate_da_artifacts_and_publish_taikai_ready(
        &receipt_log,
        temp_dir.path(),
        &retry,
        &manifest,
        LaneEpoch::new(retry.lane_id, retry.epoch),
    )
    .expect_err("changed caller manifest timestamp must conflict with completed identity");
    assert!(matches!(err, DuplicateDaArtifactsError::Conflict(_)));
    assert!(
        !taikai_ready_path(temp_dir.path(), &retry, &manifest).exists(),
        "identity-conflicting duplicate must not publish Taikai readiness"
    );
}

#[test]
fn completed_taikai_duplicate_fails_closed_on_corrupt_pin_intent() {
    let temp_dir = tempdir().expect("temp dir");
    let context = zero_sequence_manifest_context_for(BlobClass::TaikaiSegment);
    let request = context.request;
    let manifest = context.artifacts;
    let receipt_log = persist_completed_duplicate_fixture(temp_dir.path(), &request, &manifest);
    let pin_path = spool_artifact_path_for_key(
        temp_dir.path(),
        "da-pin-intent-",
        request.lane_id,
        request.epoch,
        request.sequence,
        &manifest.storage_ticket,
        *manifest.fingerprint.as_bytes(),
    );
    fs::write(&pin_path, b"corrupt durable pin intent").expect("corrupt pin intent");
    let err = load_duplicate_da_artifacts_and_publish_taikai_ready(
        &receipt_log,
        temp_dir.path(),
        &request,
        &manifest,
        LaneEpoch::new(request.lane_id, request.epoch),
    )
    .expect_err("corrupt durable pin intent must fail closed");
    assert!(matches!(err, DuplicateDaArtifactsError::Internal(_)));
    assert!(
        !taikai_ready_path(temp_dir.path(), &request, &manifest).exists(),
        "corrupt duplicate identity must not publish Taikai readiness"
    );
}

#[test]
fn completed_duplicate_identity_conflict_maps_to_http_conflict() {
    let error = duplicate_da_artifacts_response_error(
        DuplicateDaArtifactsError::Conflict("identity mismatch".to_owned()),
        "duplicate recovery",
        ResponseFormat::Json,
    );
    let response = axum::response::IntoResponse::into_response(error);
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let error = duplicate_da_artifacts_response_error(
        DuplicateDaArtifactsError::Internal(eyre!("corrupt durable artifact")),
        "duplicate recovery",
        ResponseFormat::Json,
    );
    let response = axum::response::IntoResponse::into_response(error);
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn duplicate_taikai_ingest_does_not_publish_readiness_before_receipt_validation() {
    let temp_dir = tempdir().expect("temp dir");
    let spool_dir = temp_dir.path();
    let context = sample_manifest_context_for(BlobClass::TaikaiSegment);
    let request = context.request;
    let manifest = context.artifacts;
    taikai_ingest::persist_envelope(
        spool_dir,
        request.lane_id,
        request.epoch,
        request.sequence,
        &manifest.storage_ticket,
        &manifest.fingerprint,
        b"envelope",
    )
    .expect("persist envelope fixture")
    .expect("envelope path");
    let lane_epoch = LaneEpoch::new(request.lane_id, request.epoch);
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let signer = checked_random_keypair();
    let receipt_log =
        open_receipt_log(spool_dir, &cursor_store, &signer).expect("open receipt log");
    load_duplicate_da_artifacts_and_publish_taikai_ready(
        &receipt_log,
        spool_dir,
        &request,
        &manifest,
        lane_epoch,
    )
    .expect_err("missing durable receipt artifacts must reject duplicate recovery");
    let ready_path = taikai_ready_path(spool_dir, &request, &manifest);
    assert!(
        !ready_path.exists(),
        "an invalid in-memory duplicate must not become visible to the anchor worker"
    );
}
#[test]
fn da_receipt_log_rejects_receipt_hash_mismatch_against_ticket_manifest_on_open() {
    let temp_dir = tempdir().expect("temp dir");
    let spool_dir = temp_dir.path();
    let context = sample_manifest_context_for(BlobClass::NexusLaneSidecar);
    let request = context.request;
    let manifest = context.artifacts;
    let canonical = normalize_payload(&request).expect("normalize payload");
    let chunk_store = build_chunk_store(&request, canonical.as_slice());
    let pdp_commitment = compute_pdp_commitment(
        &manifest.manifest_hash,
        &manifest.manifest,
        &chunk_store,
        canonical.as_slice(),
        1_701_000_999,
    )
    .expect("PDP commitment");
    let pdp_bytes = encode_pdp_commitment_bytes(&pdp_commitment).expect("encode PDP commitment");
    let signer = checked_fixture_ed25519_keypair(0x68);
    let receipt = build_receipt(
        &signer,
        &request,
        1_701_000_999,
        manifest.blob_hash,
        manifest.chunk_root,
        manifest.manifest_hash,
        manifest.storage_ticket,
        pdp_bytes,
        manifest.manifest.rent_quote.clone(),
        stripe_layout_from_manifest(&manifest.manifest),
    )
    .expect("build receipt");
    let correct_fingerprint = *manifest.fingerprint.as_bytes();
    let manifest_path = spool_artifact_path_for_key(
        spool_dir,
        "manifest-",
        request.lane_id,
        request.epoch,
        request.sequence,
        &manifest.storage_ticket,
        correct_fingerprint,
    );
    let mut mismatched_manifest = manifest.manifest.clone();
    mismatched_manifest.issued_at_unix = mismatched_manifest.issued_at_unix.saturating_add(1);
    fs::write(
        &manifest_path,
        to_bytes(&mismatched_manifest).expect("encode mismatched manifest sidecar"),
    )
    .expect("write mismatched manifest sidecar");
    let receipt_path =
        receipt_spool_path(spool_dir, &receipt, request.sequence, correct_fingerprint);
    fs::write(
        &receipt_path,
        encoded_stored_receipt(&receipt, request.sequence, StoredDaReceipt::VERSION),
    )
    .expect("write receipt");
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let err = match open_receipt_log(spool_dir, &cursor_store, &signer) {
        Ok(_) => panic!("receipt/manifest hash mismatch must reject receipt-log recovery"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}")
            .contains("receipt manifest hash does not match ticket-indexed DA manifest artifact"),
        "unexpected receipt-log recovery error: {err:?}"
    );
    assert!(
        cursor_store.highest_sequences().is_empty(),
        "failed recovery must not seed receipt cursors"
    );
}
#[test]
fn da_receipt_log_rejects_invalid_signature() {
    let temp_dir = tempdir().expect("temp dir");
    let lane_epoch = LaneEpoch::new(LaneId::new(5), 7);
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let signer = checked_random_keypair();
    let log = open_receipt_log(temp_dir.path(), &cursor_store, &signer).expect("open log");
    let mut receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 1, 4);
    let unsigned = persistence::unsigned_receipt_bytes(&receipt, 1).expect("unsigned bytes");
    let wrong_signer = checked_random_keypair();
    receipt.operator_signature = checked_signature(wrong_signer.private_key(), &unsigned);
    let outcome = log.append(lane_epoch, 1, receipt, test_fingerprint(4));
    assert!(
        outcome.is_err(),
        "receipt with mismatched signature must be rejected"
    );
}
#[test]
fn da_receipt_log_rejects_sequence_rebound_signature() {
    let temp_dir = tempdir().expect("temp dir");
    let lane_epoch = LaneEpoch::new(LaneId::new(5), 8);
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let signer = checked_random_keypair();
    let log = open_receipt_log(temp_dir.path(), &cursor_store, &signer).expect("open log");
    let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 1, 5);
    let outcome = log.append(lane_epoch, 2, receipt, test_fingerprint(5));
    assert!(
        outcome.is_err(),
        "receipt signature must bind the append sequence"
    );
    assert_eq!(
        receipt_file_count(temp_dir.path()),
        0,
        "sequence-rebound receipt must not be persisted"
    );
}
#[test]
fn da_receipt_log_reloads_from_disk() {
    let temp_dir = tempdir().expect("temp dir");
    let lane_epoch = LaneEpoch::new(LaneId::new(5), 11);
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let signer = checked_random_keypair();
    {
        let log = open_receipt_log(temp_dir.path(), &cursor_store, &signer).unwrap();
        let first = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 0, 9);
        let second = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 1, 10);
        log.append(lane_epoch, 0, first.clone(), test_fingerprint(9))
            .unwrap();
        log.append(lane_epoch, 1, second.clone(), test_fingerprint(10))
            .unwrap();
    }
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let reopened = open_receipt_log(temp_dir.path(), &cursor_store, &signer).unwrap();
    let entries = reopened.receipts_for(lane_epoch);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].sequence, 0);
    assert_eq!(entries[1].sequence, 1);
    assert_eq!(
        entries[1].manifest_hash,
        BlobDigest::new([10u8.wrapping_add(3); 32])
    );
    assert!(
        cursor_store
            .highest_sequences()
            .iter()
            .any(|(key, seq)| *key == lane_epoch && *seq == 1),
        "cursor store should be seeded from disk"
    );
}
#[test]
fn da_receipt_log_recovery_rejects_nonzero_origin() {
    let temp_dir = tempdir().expect("temp dir");
    let lane_epoch = LaneEpoch::new(LaneId::new(6), 19);
    let signer = checked_fixture_ed25519_keypair(0x6A);
    let receipt = test_receipt(
        &signer,
        lane_epoch.lane_id,
        lane_epoch.epoch,
        u64::MAX - 1,
        0x96,
    );
    persistence::persist_da_receipt(
        temp_dir.path(),
        &receipt,
        u64::MAX - 1,
        &test_fingerprint(0x96),
    )
    .expect("persist nonzero-origin receipt")
    .expect("receipt path");
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let err = match open_receipt_log(temp_dir.path(), &cursor_store, &signer) {
        Ok(_) => panic!("receipt-log recovery must reject a nonzero origin"),
        Err(err) => err,
    };
    let message = format!("{err:?}");
    assert!(
        message.contains(&format!("starts at {}; expected 0", u64::MAX - 1)),
        "unexpected nonzero-origin recovery error: {err:?}"
    );
    assert!(cursor_store.highest_sequences().is_empty());
}
#[test]
fn da_receipt_log_rejects_sequence_gap_on_open() {
    let temp_dir = tempdir().expect("temp dir");
    let lane_epoch = LaneEpoch::new(LaneId::new(6), 18);
    let signer = checked_fixture_ed25519_keypair(0x69);
    for (sequence, seed) in [(0, 0x94), (2, 0x95)] {
        let receipt = test_receipt(
            &signer,
            lane_epoch.lane_id,
            lane_epoch.epoch,
            sequence,
            seed,
        );
        let bytes = encoded_stored_receipt(&receipt, sequence, StoredDaReceipt::VERSION);
        let path = canonical_receipt_spool_path(temp_dir.path(), &receipt, sequence);
        fs::write(path, bytes).expect("write receipt");
    }
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let err = match open_receipt_log(temp_dir.path(), &cursor_store, &signer) {
        Ok(_) => panic!("receipt-log recovery must reject missing receipt sequences"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("missing DA receipt sequence"),
        "unexpected receipt-log recovery error: {err:?}"
    );
    assert!(
        cursor_store.highest_sequences().is_empty(),
        "gap receipt logs must not seed replay cursors"
    );
}
#[test]
fn da_receipt_log_rejects_same_manifest_duplicate_with_different_receipt_on_open() {
    let temp_dir = tempdir().expect("temp dir");
    let lane_epoch = LaneEpoch::new(LaneId::new(6), 16);
    let signer = checked_random_keypair();
    let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 1, 0x91);
    let mut conflicting = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 1, 0x92);
    conflicting.manifest_hash = receipt.manifest_hash;
    let unsigned = persistence::unsigned_receipt_bytes(&conflicting, 1).expect("unsigned bytes");
    conflicting.operator_signature = checked_signature(signer.private_key(), &unsigned);
    for receipt in [&receipt, &conflicting] {
        let bytes = encoded_stored_receipt(receipt, 1, StoredDaReceipt::VERSION);
        let path = canonical_receipt_spool_path(temp_dir.path(), receipt, 1);
        fs::write(path, bytes).expect("write duplicate receipt");
    }
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let err = match open_receipt_log(temp_dir.path(), &cursor_store, &signer) {
        Ok(_) => panic!("conflicting duplicate receipt must reject receipt-log recovery"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("conflicting duplicate DA receipt for sequence 1"),
        "unexpected receipt-log recovery error: {err:?}"
    );
    assert!(
        cursor_store.highest_sequences().is_empty(),
        "conflicting duplicate receipts must not seed replay cursors"
    );
}
#[test]
fn da_receipt_log_rejects_same_receipt_under_wrong_fingerprint_on_open() {
    let temp_dir = tempdir().expect("temp dir");
    let lane_epoch = LaneEpoch::new(LaneId::new(6), 17);
    let signer = checked_random_keypair();
    let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 1, 0x93);
    let bytes = encoded_stored_receipt(&receipt, 1, StoredDaReceipt::VERSION);
    for fingerprint in [receipt_fingerprint_bytes(&receipt), [0xA4; 32]] {
        let path = receipt_spool_path(temp_dir.path(), &receipt, 1, fingerprint);
        fs::write(path, &bytes).expect("write duplicate receipt");
    }
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let err = match open_receipt_log(temp_dir.path(), &cursor_store, &signer) {
        Ok(_) => {
            panic!("same receipt under different fingerprints must reject receipt-log recovery")
        }
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("mismatches body storage ticket"),
        "unexpected receipt-log recovery error: {err:?}"
    );
    assert!(
        cursor_store.highest_sequences().is_empty(),
        "ambiguous duplicate receipts must not seed replay cursors"
    );
}
#[test]
fn da_receipt_log_rejects_sequence_rebound_signature_on_open() {
    let temp_dir = tempdir().expect("temp dir");
    let lane_epoch = LaneEpoch::new(LaneId::new(6), 13);
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let signer = checked_random_keypair();
    let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 1, 9);
    let bytes = encoded_stored_receipt(&receipt, 2, StoredDaReceipt::VERSION);
    let path = canonical_receipt_spool_path(temp_dir.path(), &receipt, 2);
    fs::write(&path, bytes).expect("write rebound receipt");
    let err = match open_receipt_log(temp_dir.path(), &cursor_store, &signer) {
        Ok(_) => panic!("sequence-rebound receipt must reject receipt-log recovery"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("failed to verify durable DA receipt"),
        "unexpected receipt-log recovery error: {err:?}"
    );
    assert!(
        cursor_store.highest_sequences().is_empty(),
        "sequence-rebound receipt must not seed replay cursors"
    );
}
#[test]
fn da_receipt_log_rejects_invalid_entries_on_open() {
    let temp_dir = tempdir().expect("temp dir");
    let signer = checked_random_keypair();
    let corrupt_receipt = test_receipt(&signer, LaneId::new(1), 1, 1, 0xAA);
    let bad_path = canonical_receipt_spool_path(temp_dir.path(), &corrupt_receipt, 1);
    fs::write(&bad_path, b"corrupt").expect("write corrupt receipt");
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let err = match open_receipt_log(temp_dir.path(), &cursor_store, &signer) {
        Ok(_) => panic!("corrupt receipt must reject receipt-log recovery"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("failed to load durable DA receipt"),
        "unexpected receipt-log recovery error: {err:?}"
    );
}
#[test]
fn da_receipt_log_rejects_receipt_shaped_directory_on_open() {
    let temp_dir = tempdir().expect("temp dir");
    let signer = checked_random_keypair();
    let receipt = test_receipt(&signer, LaneId::new(1), 1, 1, 0xAB);
    let path = canonical_receipt_spool_path(temp_dir.path(), &receipt, 1);
    fs::create_dir(&path).expect("create receipt-shaped directory");
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let err = match open_receipt_log(temp_dir.path(), &cursor_store, &signer) {
        Ok(_) => panic!("receipt-shaped directory must reject receipt-log recovery"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("is not a regular file"),
        "unexpected receipt-log recovery error: {err:?}"
    );
    assert!(
        cursor_store.highest_sequences().is_empty(),
        "receipt-shaped directories must not seed replay cursors"
    );
}
#[test]
fn da_receipt_log_rejects_filename_body_mismatch_on_open() {
    let temp_dir = tempdir().expect("temp dir");
    let lane_epoch = LaneEpoch::new(LaneId::new(6), 12);
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let signer = checked_random_keypair();
    let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 1, 8);
    let bytes = encoded_stored_receipt(&receipt, 1, StoredDaReceipt::VERSION);
    let mismatched_path = canonical_receipt_spool_path(temp_dir.path(), &receipt, 2);
    fs::write(&mismatched_path, bytes).expect("write mismatched receipt");
    let err = match open_receipt_log(temp_dir.path(), &cursor_store, &signer) {
        Ok(_) => panic!("filename/body mismatch must reject receipt-log recovery"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("failed to load durable DA receipt"),
        "unexpected receipt-log recovery error: {err:?}"
    );
    assert!(cursor_store.highest_sequences().is_empty());
}
#[test]
fn da_receipt_log_rejects_filename_ticket_mismatch_on_open() {
    let temp_dir = tempdir().expect("temp dir");
    let lane_epoch = LaneEpoch::new(LaneId::new(6), 14);
    let cursor_store = Arc::new(ReplayCursorStore::in_memory());
    let signer = checked_random_keypair();
    let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 1, 0x8A);
    let bytes = encoded_stored_receipt(&receipt, 1, StoredDaReceipt::VERSION);
    let mut filename_receipt = receipt;
    filename_receipt.storage_ticket = StorageTicketId::new([0x99; 32]);
    let mismatched_path = canonical_receipt_spool_path(temp_dir.path(), &filename_receipt, 1);
    fs::write(&mismatched_path, bytes).expect("write mismatched receipt");
    let err = match open_receipt_log(temp_dir.path(), &cursor_store, &signer) {
        Ok(_) => panic!("filename/body ticket mismatch must reject receipt-log recovery"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("failed to load durable DA receipt"),
        "unexpected receipt-log recovery error: {err:?}"
    );
    assert!(cursor_store.highest_sequences().is_empty());
}
#[test]
fn da_receipt_log_rejects_replay_cursor_seed_failures_on_open() {
    let receipt_dir = tempdir().expect("receipt dir");
    let lane_epoch = LaneEpoch::new(LaneId::new(6), 15);
    let signer = checked_random_keypair();
    let receipt = test_receipt(&signer, lane_epoch.lane_id, lane_epoch.epoch, 0, 0x8B);
    persistence::persist_da_receipt(receipt_dir.path(), &receipt, 0, &test_fingerprint(0x8B))
        .expect("persist receipt")
        .expect("receipt path");
    let cursor_store = Arc::new(ReplayCursorStore::in_memory_with_max_lane_epochs(
        NonZeroUsize::new(1).unwrap(),
    ));
    let retained = LaneEpoch::new(LaneId::new(7), 15);
    cursor_store
        .record(retained, 9)
        .expect("seed the sole bounded replay cursor");
    let err = match open_receipt_log(receipt_dir.path(), &cursor_store, &signer) {
        Ok(_) => panic!("cursor seed failures must reject receipt-log recovery"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains(
            "durable DA receipt log and replay cursor contain more than 1 lane/epoch windows"
        ),
        "unexpected cursor seed error: {err:?}"
    );
    assert!(
        cursor_store.highest_sequences() == vec![(retained, 9)],
        "failed cursor seeding must not mutate bounded cursor memory"
    );
}
