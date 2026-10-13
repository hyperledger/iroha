//! Replay-cursor recovery, manifest resolution, fixtures, and metrics tests.

use super::*;

struct ReplayCursorFixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    main_path: PathBuf,
    temp_path: PathBuf,
    journal_path: PathBuf,
    lane_epoch: LaneEpoch,
}
fn replay_cursor_fixture() -> ReplayCursorFixture {
    let dir = tempdir().expect("tempdir");
    let root = dir.path().to_path_buf();
    let main_path = replay_cursor_main_path(&root);
    let temp_path = persistence::replay_cursor_temp_path(&main_path);
    let journal_path = replay_cursor_journal_path(&root);
    ReplayCursorFixture {
        _dir: dir,
        root,
        main_path,
        temp_path,
        journal_path,
        lane_epoch: LaneEpoch::new(LaneId::new(2), 9),
    }
}
#[test]
fn replay_cursor_store_persists_sequences() {
    let fixture = replay_cursor_fixture();
    let store = ReplayCursorStore::open(fixture.root.clone()).expect("open store");
    store.record(fixture.lane_epoch, 42).expect("record");
    drop(store);
    let reopened = ReplayCursorStore::open(fixture.root).expect("reopen store");
    let mut entries = reopened.highest_sequences();
    assert_eq!(entries.len(), 1);
    entries.sort_by_key(|(lane_epoch, _)| lane_epoch.lane_id.as_u32());
    assert_eq!(entries[0], (fixture.lane_epoch, 42));
}
#[test]
fn replay_cursor_store_persists_first_zero_sequence() {
    let fixture = replay_cursor_fixture();
    let store = ReplayCursorStore::open(fixture.root.clone()).expect("open store");
    store.record(fixture.lane_epoch, 0).expect("record zero");
    drop(store);
    let reopened = ReplayCursorStore::open(fixture.root).expect("reopen store");
    assert_replay_cursor_sequences(&reopened, &[(fixture.lane_epoch, 0)]);
}
#[test]
fn replay_cursor_store_rejects_new_lane_epochs_at_global_capacity() {
    let store = ReplayCursorStore::in_memory_with_max_lane_epochs(NonZeroUsize::new(2).unwrap());
    let first = LaneEpoch::new(LaneId::new(2), 9);
    let second = LaneEpoch::new(LaneId::new(2), 10);
    let rejected = LaneEpoch::new(LaneId::new(2), 11);
    store.record(first, 1).expect("first cursor");
    store.record(second, 2).expect("second cursor");
    let err = store
        .record(rejected, 3)
        .expect_err("third lane/epoch must exceed the global bound");
    assert!(
        format!("{err:?}").contains("capacity 2 is exhausted"),
        "unexpected capacity error: {err:?}"
    );
    assert_replay_cursor_sequences(&store, &[(first, 1), (second, 2)]);
    store
        .record(first, 4)
        .expect("existing lane/epoch may still advance at capacity");
    assert_replay_cursor_sequences(&store, &[(first, 4), (second, 2)]);
}
#[test]
fn replay_cursor_store_uses_journal_without_per_record_snapshot_rewrite() {
    let fixture = replay_cursor_fixture();
    let store = ReplayCursorStore::open(fixture.root.clone()).expect("open store");
    store
        .record(fixture.lane_epoch, 42)
        .expect("append cursor journal");
    assert!(
        !fixture.main_path.exists(),
        "a single cursor update must not rewrite the full snapshot"
    );
    assert!(
        fs::metadata(&fixture.journal_path)
            .expect("journal metadata")
            .len()
            > 0,
        "the constant-size journal entry must be durable"
    );
    drop(store);
    let reopened = ReplayCursorStore::open(fixture.root).expect("recover journal");
    assert_replay_cursor_sequences(&reopened, &[(fixture.lane_epoch, 42)]);
}
#[test]
fn replay_cursor_store_checkpoints_at_bounded_journal_interval() {
    let fixture = replay_cursor_fixture();
    let store = ReplayCursorStore::open_with_max_lane_epochs(
        fixture.root.clone(),
        NonZeroUsize::new(2).unwrap(),
    )
    .expect("open bounded store");
    store
        .record(fixture.lane_epoch, 1)
        .expect("first journal entry");
    assert!(!fixture.main_path.exists());
    store
        .record(fixture.lane_epoch, 2)
        .expect("second journal entry");
    assert!(
        fixture.main_path.exists(),
        "capacity-sized journal must checkpoint"
    );
    assert_eq!(
        fs::metadata(&fixture.journal_path)
            .expect("journal metadata after checkpoint")
            .len(),
        0,
        "checkpoint must truncate the fully applied journal"
    );
    drop(store);
    let reopened =
        ReplayCursorStore::open_with_max_lane_epochs(fixture.root, NonZeroUsize::new(2).unwrap())
            .expect("reopen checkpointed store");
    assert_replay_cursor_sequences(&reopened, &[(fixture.lane_epoch, 2)]);
}
#[test]
fn replay_cursor_store_recovers_torn_final_journal_frame() {
    let fixture = replay_cursor_fixture();
    let store = ReplayCursorStore::open(fixture.root.clone()).expect("open store");
    store
        .record(fixture.lane_epoch, 42)
        .expect("append cursor journal");
    drop(store);
    let valid_len = fs::metadata(&fixture.journal_path)
        .expect("journal metadata")
        .len();
    fs::OpenOptions::new()
        .append(true)
        .open(&fixture.journal_path)
        .expect("open journal for torn-tail fixture")
        .write_all(&[0, 0])
        .expect("append torn length prefix");
    let reopened = ReplayCursorStore::open(fixture.root).expect("recover torn final frame");
    assert_replay_cursor_sequences(&reopened, &[(fixture.lane_epoch, 42)]);
    assert_eq!(
        fs::metadata(&fixture.journal_path)
            .expect("recovered journal metadata")
            .len(),
        valid_len,
        "recovery must truncate only the torn tail"
    );
}
#[test]
fn replay_cursor_store_rejects_corrupt_complete_journal_frame() {
    let fixture = replay_cursor_fixture();
    let store = ReplayCursorStore::open(fixture.root.clone()).expect("open store");
    store
        .record(fixture.lane_epoch, 42)
        .expect("append cursor journal");
    drop(store);
    let mut bytes = fs::read(&fixture.journal_path).expect("read journal");
    let checksum_byte = bytes.last_mut().expect("journal frame is non-empty");
    *checksum_byte ^= 0x80;
    fs::write(&fixture.journal_path, bytes).expect("write corrupt journal fixture");
    let err = match ReplayCursorStore::open(fixture.root) {
        Ok(_) => panic!("corrupt complete journal frame must fail closed"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("checksum mismatch"),
        "unexpected corrupt journal error: {err:?}"
    );
}
#[test]
fn replay_cursor_store_retries_checkpoint_after_persist_failure() {
    let fixture = replay_cursor_fixture();
    let store = ReplayCursorStore::open(fixture.root.clone()).expect("open store");
    store
        .record(fixture.lane_epoch, 42)
        .expect("append journal entry");
    fs::create_dir(&fixture.temp_path).expect("block temp snapshot path");
    let err = store
        .checkpoint()
        .expect_err("blocked temp path should fail snapshot persistence");
    assert!(
        format!("{err:?}").contains("failed to create DA replay snapshot temp file"),
        "unexpected error: {err:?}"
    );
    assert_replay_cursor_sequences(&store, &[(fixture.lane_epoch, 42)]);
    fs::remove_dir(&fixture.temp_path).expect("unblock temp snapshot path");
    store.checkpoint().expect("retry checkpoint");
    drop(store);
    let reopened = ReplayCursorStore::open(fixture.root).expect("reopen store");
    assert_replay_cursor_sequences(&reopened, &[(fixture.lane_epoch, 42)]);
}
#[test]
fn replay_cursor_store_rejects_existing_temp_without_truncating() {
    let fixture = replay_cursor_fixture();
    let store = ReplayCursorStore::open(fixture.root.clone()).expect("open store");
    store
        .record(fixture.lane_epoch, 42)
        .expect("append journal entry");
    fs::write(&fixture.temp_path, b"existing-temp-snapshot").expect("seed temp snapshot");
    let err = store
        .checkpoint()
        .expect_err("existing temp snapshot should reject cursor persistence");
    assert!(
        format!("{err:?}").contains("failed to create DA replay snapshot temp file"),
        "unexpected error: {err:?}"
    );
    assert_replay_cursor_sequences(&store, &[(fixture.lane_epoch, 42)]);
    assert_eq!(
        fs::read(&fixture.temp_path).expect("read temp snapshot after failed record"),
        b"existing-temp-snapshot"
    );
}
#[cfg(unix)]
#[test]
fn replay_cursor_store_open_rejects_dir_symlink() {
    use std::os::unix::fs::symlink;
    let temp = tempdir().expect("tempdir");
    let target = temp.path().join("cursor-root-target");
    fs::create_dir(&target).expect("create cursor target directory");
    let lane_epoch = LaneEpoch::new(LaneId::new(2), 9);
    fs::write(
        replay_cursor_main_path(&target),
        replay_cursor_snapshot_bytes(&[(lane_epoch, 42)]),
    )
    .expect("write target cursor snapshot");
    let link = temp.path().join("cursor-root-link");
    symlink(&target, &link).expect("create cursor root symlink");
    let err = match ReplayCursorStore::open(link.clone()) {
        Ok(_) => panic!("symlinked replay cursor root must reject open"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("DA replay directory"),
        "unexpected cursor root symlink error: {err:?}"
    );
    assert!(
        fs::symlink_metadata(&link)
            .expect("inspect cursor root symlink")
            .file_type()
            .is_symlink(),
        "failed open should leave cursor root symlink visible"
    );
    assert!(
        replay_cursor_main_path(&target).exists(),
        "cursor root symlink target should remain for operator repair"
    );
}
#[cfg(unix)]
#[test]
fn replay_cursor_store_empty_rejects_dir_symlink() {
    use std::os::unix::fs::symlink;
    let temp = tempdir().expect("tempdir");
    let target = temp.path().join("cursor-empty-target");
    fs::create_dir(&target).expect("create cursor target directory");
    let link = temp.path().join("cursor-empty-link");
    symlink(&target, &link).expect("create cursor root symlink");
    let err = match ReplayCursorStore::empty(link.clone()) {
        Ok(_) => panic!("symlinked replay cursor root must reject empty store creation"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("DA replay directory"),
        "unexpected cursor root symlink error: {err:?}"
    );
    assert!(
        fs::symlink_metadata(&link)
            .expect("inspect cursor root symlink")
            .file_type()
            .is_symlink(),
        "failed empty store creation should leave cursor root symlink visible"
    );
}
#[cfg(unix)]
#[test]
fn replay_cursor_store_record_rejects_dir_symlink_replacement() {
    use std::os::unix::fs::symlink;
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("cursor-root");
    fs::create_dir(&path).expect("create cursor root");
    let store = ReplayCursorStore::open(path.clone()).expect("open store");
    fs::remove_file(replay_cursor_journal_path(&path)).expect("remove open cursor journal path");
    fs::remove_dir(&path).expect("remove cursor root");
    let target = temp.path().join("cursor-root-target");
    fs::create_dir(&target).expect("create cursor target directory");
    symlink(&target, &path).expect("replace cursor root with symlink");
    let lane_epoch = LaneEpoch::new(LaneId::new(2), 9);
    let err = store
        .record(lane_epoch, 42)
        .expect_err("symlinked replay cursor root replacement must reject persistence");
    assert!(
        format!("{err:?}").contains("DA replay journal directory"),
        "unexpected cursor root replacement error: {err:?}"
    );
    assert_replay_cursor_sequences(&store, &[]);
    assert!(
        fs::symlink_metadata(&path)
            .expect("inspect replacement root symlink")
            .file_type()
            .is_symlink(),
        "failed record should leave replacement cursor root symlink visible"
    );
    assert!(
        !replay_cursor_main_path(&target).exists(),
        "cursor root symlink target must not receive the main snapshot"
    );
    assert!(
        !persistence::replay_cursor_temp_path(&replay_cursor_main_path(&target)).exists(),
        "cursor root symlink target must not receive the temp snapshot"
    );
    assert!(
        !replay_cursor_journal_path(&target).exists(),
        "cursor root symlink target must not receive a journal entry"
    );
}
#[cfg(unix)]
#[test]
fn replay_cursor_store_open_rejects_main_snapshot_symlink() {
    use std::os::unix::fs::symlink;
    let fixture = replay_cursor_fixture();
    let target_path = fixture.root.join("cursor-symlink-target.json");
    fs::write(
        &target_path,
        replay_cursor_snapshot_bytes(&[(fixture.lane_epoch, 42)]),
    )
    .expect("write cursor symlink target");
    symlink(&target_path, &fixture.main_path).expect("create cursor snapshot symlink");
    let err = match ReplayCursorStore::open(fixture.root.clone()) {
        Ok(_) => panic!("symlinked main replay cursor snapshot must reject open"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("not a regular file"),
        "unexpected cursor symlink error: {err:?}"
    );
    assert!(
        fs::symlink_metadata(&fixture.main_path)
            .expect("inspect cursor symlink")
            .file_type()
            .is_symlink(),
        "failed open should leave main cursor symlink visible"
    );
    assert!(
        target_path.exists(),
        "cursor symlink target should remain for operator repair"
    );
}
#[cfg(unix)]
#[test]
fn replay_cursor_store_open_rejects_journal_symlink() {
    use std::os::unix::fs::symlink;
    let temp = tempdir().expect("tempdir");
    let journal_path = replay_cursor_journal_path(temp.path());
    let target_path = temp.path().join("cursor-journal-symlink-target");
    fs::write(&target_path, []).expect("write journal symlink target");
    symlink(&target_path, &journal_path).expect("create cursor journal symlink");
    let err = match ReplayCursorStore::open(temp.path().to_path_buf()) {
        Ok(_) => panic!("symlinked replay cursor journal must reject open"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("not a regular file"),
        "unexpected cursor journal symlink error: {err:?}"
    );
    assert!(
        fs::symlink_metadata(&journal_path)
            .expect("inspect cursor journal symlink")
            .file_type()
            .is_symlink(),
        "failed open should leave cursor journal symlink visible"
    );
}
#[cfg(unix)]
#[test]
fn replay_cursor_store_open_rejects_temp_snapshot_symlink() {
    use std::os::unix::fs::symlink;
    let fixture = replay_cursor_fixture();
    let target_path = fixture.root.join("cursor-temp-symlink-target.json");
    fs::write(
        &target_path,
        replay_cursor_snapshot_bytes(&[(fixture.lane_epoch, 42)]),
    )
    .expect("write cursor temp symlink target");
    symlink(&target_path, &fixture.temp_path).expect("create cursor temp snapshot symlink");
    let err = match ReplayCursorStore::open(fixture.root.clone()) {
        Ok(_) => panic!("symlinked temp replay cursor snapshot must reject open"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("not a regular file"),
        "unexpected cursor temp symlink error: {err:?}"
    );
    assert!(
        fs::symlink_metadata(&fixture.temp_path)
            .expect("inspect cursor temp symlink")
            .file_type()
            .is_symlink(),
        "failed open should leave temp cursor symlink visible"
    );
    assert!(
        target_path.exists(),
        "cursor temp symlink target should remain for operator repair"
    );
}
fn replay_cursor_main_path(dir: &Path) -> PathBuf {
    dir.join("replay_cursors.norito.json")
}
fn replay_cursor_journal_path(dir: &Path) -> PathBuf {
    dir.join("replay_cursors.journal")
}
fn replay_cursor_snapshot_bytes(entries: &[(LaneEpoch, u64)]) -> Vec<u8> {
    let temp = tempdir().expect("snapshot tempdir");
    let store = ReplayCursorStore::open(temp.path().to_path_buf()).expect("open snapshot store");
    for (lane_epoch, sequence) in entries {
        store.record(*lane_epoch, *sequence).expect("record cursor");
    }
    store.checkpoint().expect("checkpoint cursor snapshot");
    fs::read(replay_cursor_main_path(temp.path())).expect("read cursor snapshot")
}
fn replay_cursor_snapshot_value(entries: &[(LaneEpoch, u64)]) -> Value {
    json::from_slice(&replay_cursor_snapshot_bytes(entries)).expect("decode cursor snapshot")
}
fn replay_cursor_snapshot_order(entries: &[(LaneEpoch, u64)]) -> Vec<(u64, u64)> {
    let value = replay_cursor_snapshot_value(entries);
    let Value::Object(map) = value else {
        panic!("cursor snapshot must be an object");
    };
    let Some(Value::Array(entries)) = map.get("entries") else {
        panic!("cursor snapshot entries must be an array");
    };
    entries
        .iter()
        .map(|entry| {
            let Value::Object(entry) = entry else {
                panic!("cursor snapshot entry must be an object");
            };
            let lane_id = entry
                .get("lane_id")
                .and_then(Value::as_u64)
                .expect("cursor snapshot entry must include lane_id");
            let epoch = entry
                .get("epoch")
                .and_then(Value::as_u64)
                .expect("cursor snapshot entry must include epoch");
            (lane_id, epoch)
        })
        .collect()
}
fn replay_cursor_snapshot_bytes_with_version(
    entries: &[(LaneEpoch, u64)],
    version: i32,
) -> Vec<u8> {
    let mut value = replay_cursor_snapshot_value(entries);
    if let Value::Object(map) = &mut value {
        map.insert("version".into(), Value::from(version));
    } else {
        panic!("cursor snapshot must be an object");
    }
    json::to_vec(&value).expect("encode cursor snapshot")
}
fn replay_cursor_snapshot_bytes_with_duplicate_entry(entries: &[(LaneEpoch, u64)]) -> Vec<u8> {
    let mut value = replay_cursor_snapshot_value(entries);
    if let Value::Object(map) = &mut value {
        let entries = map
            .get_mut("entries")
            .expect("cursor snapshot entries must exist");
        if let Value::Array(entries) = entries {
            let duplicate = entries
                .first()
                .expect("cursor snapshot entry must exist")
                .clone();
            entries.push(duplicate);
        } else {
            panic!("cursor snapshot entries must be an array");
        }
    } else {
        panic!("cursor snapshot must be an object");
    }
    json::to_vec(&value).expect("encode cursor snapshot")
}
pub(super) fn assert_replay_cursor_sequences(
    store: &ReplayCursorStore,
    expected: &[(LaneEpoch, u64)],
) {
    let mut actual = store.highest_sequences();
    actual.sort_by_key(|(lane_epoch, _)| (lane_epoch.lane_id.as_u32(), lane_epoch.epoch));
    let mut expected = expected.to_vec();
    expected.sort_by_key(|(lane_epoch, _)| (lane_epoch.lane_id.as_u32(), lane_epoch.epoch));
    assert_eq!(actual, expected);
}
#[test]
fn replay_cursor_store_persists_canonical_snapshot_order() {
    let lane_a = LaneEpoch::new(LaneId::new(2), 9);
    let lane_b = LaneEpoch::new(LaneId::new(0), 9);
    let lane_c = LaneEpoch::new(LaneId::new(0), 8);
    assert_eq!(
        replay_cursor_snapshot_order(&[(lane_a, 42), (lane_b, 43), (lane_c, 44)]),
        vec![(0, 8), (0, 9), (2, 9)]
    );
    let temp = tempdir().expect("tempdir");
    let store = ReplayCursorStore::open(temp.path().to_path_buf()).expect("open store");
    store.record(lane_a, 42).expect("record lane a");
    store.record(lane_b, 43).expect("record lane b");
    store.record(lane_c, 44).expect("record lane c");
    assert_eq!(
        store.highest_sequences(),
        vec![(lane_c, 44), (lane_b, 43), (lane_a, 42)]
    );
}
#[test]
fn replay_cursor_store_open_promotes_temp_snapshot() {
    let fixture = replay_cursor_fixture();
    fs::write(
        &fixture.temp_path,
        replay_cursor_snapshot_bytes(&[(fixture.lane_epoch, 42)]),
    )
    .expect("write temp snapshot");
    let store = ReplayCursorStore::open(fixture.root.clone()).expect("open store");
    assert!(
        fixture.main_path.exists(),
        "temp snapshot should be promoted"
    );
    assert!(
        !fixture.temp_path.exists(),
        "promoted temp snapshot should be removed"
    );
    assert_replay_cursor_sequences(&store, &[(fixture.lane_epoch, 42)]);
}
#[test]
fn replay_cursor_store_open_promotes_newer_temp_snapshot() {
    let fixture = replay_cursor_fixture();
    fs::write(
        &fixture.main_path,
        replay_cursor_snapshot_bytes(&[(fixture.lane_epoch, 41)]),
    )
    .expect("write main snapshot");
    fs::write(
        &fixture.temp_path,
        replay_cursor_snapshot_bytes(&[(fixture.lane_epoch, 42)]),
    )
    .expect("write temp snapshot");
    let store = ReplayCursorStore::open(fixture.root.clone()).expect("open store");
    assert!(fixture.main_path.exists(), "newer temp should be promoted");
    assert!(!fixture.temp_path.exists(), "newer temp should be consumed");
    assert_replay_cursor_sequences(&store, &[(fixture.lane_epoch, 42)]);
}
#[test]
fn replay_cursor_store_open_removes_corrupt_temp_snapshot() {
    let fixture = replay_cursor_fixture();
    fs::write(
        &fixture.main_path,
        replay_cursor_snapshot_bytes(&[(fixture.lane_epoch, 42)]),
    )
    .expect("write main snapshot");
    fs::write(&fixture.temp_path, b"corrupt").expect("write corrupt temp snapshot");
    let store = ReplayCursorStore::open(fixture.root.clone()).expect("open store");
    assert!(
        !fixture.temp_path.exists(),
        "corrupt temp snapshot should be removed"
    );
    assert_replay_cursor_sequences(&store, &[(fixture.lane_epoch, 42)]);
}
#[test]
fn replay_cursor_store_open_rejects_unremovable_corrupt_temp_snapshot() {
    let fixture = replay_cursor_fixture();
    fs::write(
        &fixture.main_path,
        replay_cursor_snapshot_bytes(&[(fixture.lane_epoch, 42)]),
    )
    .expect("write main snapshot");
    fs::create_dir(&fixture.temp_path).expect("block corrupt temp snapshot cleanup");
    let err = match ReplayCursorStore::open(fixture.root.clone()) {
        Ok(_) => panic!("unremovable corrupt temp snapshot should reject recovery"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("failed to remove DA replay cursor temp snapshot"),
        "unexpected error: {err:?}"
    );
    assert!(
        fixture.temp_path.exists(),
        "failed cleanup should leave temp path visible for operator repair"
    );
}
#[test]
fn replay_cursor_store_open_rejects_orphan_corrupt_temp_snapshot() {
    let fixture = replay_cursor_fixture();
    fs::write(&fixture.temp_path, b"corrupt").expect("write corrupt temp snapshot");
    let err = match ReplayCursorStore::open(fixture.root.clone()) {
        Ok(_) => panic!("orphan corrupt temp snapshot should be rejected"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("failed to decode DA replay snapshot"),
        "unexpected error: {err:?}"
    );
    assert!(
        fixture.temp_path.exists(),
        "orphan corrupt temp snapshot should remain for operator inspection"
    );
    assert!(
        !fixture.main_path.exists(),
        "corrupt temp snapshot must not be promoted into the main cursor path"
    );
}
#[test]
fn replay_cursor_store_open_rejects_duplicate_main_snapshot() {
    let fixture = replay_cursor_fixture();
    fs::write(
        &fixture.main_path,
        replay_cursor_snapshot_bytes_with_duplicate_entry(&[(fixture.lane_epoch, 42)]),
    )
    .expect("write duplicate main snapshot");
    let err = match ReplayCursorStore::open(fixture.root.clone()) {
        Ok(_) => panic!("duplicate main snapshot should be rejected"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("duplicate DA replay cursor entry"),
        "unexpected error: {err:?}"
    );
}
#[test]
fn replay_cursor_store_open_rejects_snapshot_over_global_capacity() {
    let fixture = replay_cursor_fixture();
    let first = LaneEpoch::new(LaneId::new(2), 9);
    let second = LaneEpoch::new(LaneId::new(2), 10);
    fs::write(
        &fixture.main_path,
        replay_cursor_snapshot_bytes(&[(first, 41), (second, 42)]),
    )
    .expect("write over-capacity snapshot");
    let err = match ReplayCursorStore::open_with_max_lane_epochs(
        fixture.root.clone(),
        NonZeroUsize::new(1).unwrap(),
    ) {
        Ok(_) => panic!("over-capacity replay cursor snapshot must fail closed"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("exceeding configured maximum 1"),
        "unexpected over-capacity snapshot error: {err:?}"
    );
}
#[test]
fn replay_cursor_store_open_recovers_temp_when_main_version_unsupported() {
    let fixture = replay_cursor_fixture();
    fs::write(
        &fixture.main_path,
        replay_cursor_snapshot_bytes_with_version(&[(fixture.lane_epoch, 41)], 2),
    )
    .expect("write unsupported main snapshot");
    fs::write(
        &fixture.temp_path,
        replay_cursor_snapshot_bytes(&[(fixture.lane_epoch, 42)]),
    )
    .expect("write recoverable temp snapshot");
    let store = ReplayCursorStore::open(fixture.root.clone()).expect("recover from temp");
    assert!(fixture.main_path.exists(), "valid temp should be promoted");
    assert!(
        !fixture.temp_path.exists(),
        "promoted temp should be consumed"
    );
    assert_replay_cursor_sequences(&store, &[(fixture.lane_epoch, 42)]);
}
#[test]
fn replay_cursor_store_open_rejects_unpromotable_temp_snapshot() {
    let fixture = replay_cursor_fixture();
    fs::create_dir(&fixture.main_path).expect("block main snapshot path");
    fs::write(
        &fixture.temp_path,
        replay_cursor_snapshot_bytes(&[(fixture.lane_epoch, 42)]),
    )
    .expect("write temp snapshot");
    let err = match ReplayCursorStore::open(fixture.root.clone()) {
        Ok(_) => panic!("unpromotable temp snapshot should be rejected"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("failed to promote DA replay cursor temp snapshot"),
        "unexpected error: {err:?}"
    );
}
#[test]
fn replay_cursor_store_open_discards_conflicting_temp_snapshot() {
    let fixture = replay_cursor_fixture();
    let lane_a = LaneEpoch::new(LaneId::new(2), 9);
    let lane_b = LaneEpoch::new(LaneId::new(3), 9);
    fs::write(
        &fixture.main_path,
        replay_cursor_snapshot_bytes(&[(lane_a, 41), (lane_b, 50)]),
    )
    .expect("write main snapshot");
    fs::write(
        &fixture.temp_path,
        replay_cursor_snapshot_bytes(&[(lane_a, 42), (lane_b, 49)]),
    )
    .expect("write conflicting temp snapshot");
    let store = ReplayCursorStore::open(fixture.root.clone()).expect("open store");
    assert!(
        !fixture.temp_path.exists(),
        "conflicting temp snapshot should be removed"
    );
    assert_replay_cursor_sequences(&store, &[(lane_a, 41), (lane_b, 50)]);
}
#[test]
fn resolve_manifest_emits_parity_chunks() {
    let (fixture, artifacts) = resolved_manifest_fixture(
        sample_request(),
        1_701_000_111,
        "resolve manifest with parity",
    );
    let request = &fixture.request;
    let expected =
        build_chunk_commitments(request, &fixture.chunk_store, fixture.canonical.as_slice())
            .expect("expected chunk commitments");
    assert_eq!(artifacts.manifest.chunks, expected);
    let parity_chunks: Vec<_> = artifacts
        .manifest
        .chunks
        .iter()
        .filter(|chunk| chunk.parity)
        .collect();
    assert_eq!(
        parity_chunks.len(),
        usize::from(request.erasure_profile.parity_shards)
    );
    for (idx, chunk) in parity_chunks.into_iter().enumerate() {
        let expected_offset = request
            .total_size
            .checked_add(
                u64::try_from(idx)
                    .expect("parity index fits into u64")
                    .checked_mul(u64::from(request.chunk_size))
                    .expect("offset within test bounds"),
            )
            .expect("parity offset within test bounds");
        assert_eq!(chunk.offset, expected_offset);
        assert_eq!(chunk.length, request.chunk_size);
        assert!(chunk.parity);
    }
}
#[test]
fn resolve_manifest_rejects_malformed_request_manifest_without_panicking() {
    let mut fixture = ManifestResolutionFixture::new(sample_request());
    let valid = fixture
        .resolve(1_701_000_112)
        .expect("resolve valid manifest");
    let mut malformed = to_bytes(&valid.manifest).expect("encode valid manifest");
    malformed.truncate(malformed.len().saturating_sub(1));
    fixture.request.norito_manifest = Some(malformed);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fixture.resolve(1_701_000_113)
    }));
    let err = result
        .expect("malformed request manifest must not panic")
        .expect_err("malformed request manifest must be rejected");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("failed to decode DA manifest"),
        "unexpected malformed manifest error: {}",
        err.1
    );
}
#[test]
fn resolve_manifest_uses_provided_rent_policy() {
    let mut fixture = ManifestResolutionFixture::new(sample_request());
    fixture.rent_policy = DaRentPolicyV1::from_components(
        "0.75".parse().expect("canonical XOR rate"),
        1_500,
        250,
        125,
        "0.002".parse().expect("canonical XOR egress credit"),
    );
    let artifacts = fixture
        .resolve(1_701_001_000)
        .expect("resolve manifest with custom rent policy");
    let request = &fixture.request;
    let (gib, months) = rent_usage_from_request(request.total_size, &request.retention_policy)
        .expect("rent usage should fit test inputs");
    let expected_quote = fixture
        .rent_policy
        .quote(gib, months)
        .expect("rent quote should compute for test inputs");
    assert_eq!(artifacts.manifest.rent_quote, expected_quote);
}
#[test]
fn rent_usage_from_request_rejects_retention_month_overflow() {
    let request = sample_request();
    let mut retention = request.retention_policy.clone();
    retention.cold_retention_secs = u64::from(u32::MAX)
        .checked_mul(SECS_PER_MONTH)
        .and_then(|secs| secs.checked_add(1))
        .expect("overflow threshold fits into u64");
    let err = rent_usage_from_request(request.total_size, &retention)
        .expect_err("oversized retention duration must be rejected");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("rent quote month range"),
        "unexpected error: {}",
        err.1
    );
}
#[test]
fn resolve_manifest_rejects_retention_month_overflow() {
    let fixture = ManifestResolutionFixture::new(sample_request());
    let mut retention = fixture.request.retention_policy.clone();
    retention.hot_retention_secs = u64::from(u32::MAX)
        .checked_mul(SECS_PER_MONTH)
        .and_then(|secs| secs.checked_add(1))
        .expect("overflow threshold fits into u64");
    let err = fixture
        .resolve_with_retention(&retention, 1_701_001_001)
        .expect_err("oversized rent duration must reject manifest resolution");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("rent quote month range"),
        "unexpected error: {}",
        err.1
    );
}
#[test]
fn resolve_manifest_applies_enforced_retention_policy() {
    let fixture = ManifestResolutionFixture::new(sample_request());
    let enforced = RetentionPolicy {
        hot_retention_secs: 99,
        cold_retention_secs: 199,
        required_replicas: 9,
        storage_class: StorageClass::Cold,
        governance_tag: GovernanceTag::new("da.test"),
    };
    let artifacts = fixture
        .resolve_with_retention(&enforced, 1_701_000_555)
        .expect("resolve manifest with enforced retention");
    assert_eq!(artifacts.manifest.retention_policy, enforced);
}
fn provided_manifest_request() -> DaIngestRequest {
    let mut request = sample_request();
    taikai::apply_taikai_ingest_tags(
        &mut request.metadata,
        None,
        &request.retention_policy,
        request.total_size,
    );
    resign_sample_request(&mut request);
    request
}
#[test]
fn provided_manifest_roundtrip_preserves_computed_chunks() {
    let mut fixture = ManifestResolutionFixture::new(provided_manifest_request());
    let original = fixture
        .resolve(1_701_000_600)
        .expect("generate canonical manifest");
    fixture.request.norito_manifest = Some(to_bytes(&original.manifest).expect("encode manifest"));
    let supplied = fixture
        .resolve(1_701_000_601)
        .expect("admit matching supplied manifest");
    assert_eq!(supplied.manifest, original.manifest);
    assert_eq!(supplied.manifest_hash, original.manifest_hash);
}
#[test]
fn provided_manifest_must_match_enforced_retention_policy() {
    let mut fixture = ManifestResolutionFixture::new(provided_manifest_request());
    let artifacts = fixture.resolve(1_701_000_600).expect("resolve manifest");
    fixture.request.norito_manifest = Some(to_bytes(&artifacts.manifest).expect("encode manifest"));
    let strict_policy = RetentionPolicy {
        hot_retention_secs: fixture.request.retention_policy.hot_retention_secs + 1,
        cold_retention_secs: fixture.request.retention_policy.cold_retention_secs,
        required_replicas: fixture.request.retention_policy.required_replicas,
        storage_class: fixture.request.retention_policy.storage_class,
        governance_tag: GovernanceTag::new("da.strict"),
    };
    let err = fixture
        .resolve_with_retention(&strict_policy, 1_701_000_601)
        .expect_err("mismatched retention policy must be rejected");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
}
#[test]
fn provided_manifest_with_wrong_parity_is_rejected() {
    let mut fixture = ManifestResolutionFixture::new(provided_manifest_request());
    let artifacts = fixture.resolve(1_701_000_222).expect("resolve manifest");
    let mut tampered = artifacts.manifest.clone();
    let first_parity = tampered
        .chunks
        .iter_mut()
        .find(|chunk| chunk.parity)
        .expect("expected parity chunk to mutate");
    first_parity.parity = false;
    fixture.request.norito_manifest = Some(to_bytes(&tampered).expect("encode tampered manifest"));
    let err = match fixture.resolve(1_701_000_333) {
        Ok(_) => panic!("manifest with mismatched parity flag must be rejected"),
        Err(err) => err,
    };
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
}
#[test]
fn provided_manifest_with_parity_role_alias_is_rejected() {
    let mut fixture = ManifestResolutionFixture::new(provided_manifest_request());
    let artifacts = fixture.resolve(1_701_000_223).expect("resolve manifest");
    let mut tampered = artifacts.manifest.clone();
    let global_parity = tampered
        .chunks
        .iter_mut()
        .find(|chunk| chunk.parity && chunk.role == ChunkRole::GlobalParity)
        .expect("expected global parity chunk to mutate");
    global_parity.role = ChunkRole::Data;
    fixture.request.norito_manifest = Some(to_bytes(&tampered).expect("encode tampered manifest"));
    let err = fixture
        .resolve(1_701_000_334)
        .expect_err("a parity/Data role alias must not bypass IPA field binding");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("role mismatch"),
        "unexpected rejection: {err:?}"
    );
}
#[test]
fn provided_manifest_with_zero_group_alias_is_rejected() {
    let mut request = provided_manifest_request();
    request.payload = vec![0x5A; 9 * usize::try_from(request.chunk_size).unwrap()];
    request.total_size = u64::try_from(request.payload.len()).unwrap();
    request.payload_hash = BlobDigest::from_hash(blake3_hash(&request.payload));
    let mut fixture = ManifestResolutionFixture::new(request);
    let artifacts = fixture.resolve(1_701_000_224).expect("resolve manifest");
    let mut tampered = artifacts.manifest.clone();
    let later_group = tampered
        .chunks
        .iter_mut()
        .find(|chunk| chunk.group_id != 0)
        .expect("expected a non-zero stripe group to mutate");
    later_group.group_id = 0;
    fixture.request.norito_manifest = Some(to_bytes(&tampered).expect("encode tampered manifest"));
    let err = fixture
        .resolve(1_701_000_335)
        .expect_err("group zero must not act as a wildcard for IPA field binding");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("group_id mismatch"),
        "unexpected rejection: {err:?}"
    );
}
#[test]
fn provided_manifest_with_wrong_ipa_commitment_is_rejected() {
    let mut fixture = ManifestResolutionFixture::new(provided_manifest_request());
    let artifacts = fixture.resolve(1_701_000_920).expect("resolve manifest");
    let mut tampered = artifacts.manifest.clone();
    tampered.ipa_commitment = BlobDigest::new([0xAB; 32]);
    fixture.request.norito_manifest = Some(to_bytes(&tampered).expect("encode tampered manifest"));
    let err = fixture
        .resolve(1_701_000_921)
        .expect_err("manifest with mismatched ipa commitment must be rejected");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
}
#[test]
fn governance_metadata_is_encrypted_with_configured_key() {
    let mut request = sample_request();
    let secret = b"confidential-notes".to_vec();
    request.metadata.items.push(MetadataEntry::new(
        "gov-notes",
        secret.clone(),
        MetadataVisibility::GovernanceOnly,
    ));
    let key = [0x11u8; 32];
    let encrypted = encrypt_governance_metadata(&request.metadata, Some(&key), Some("primary"))
        .expect("encryption");
    let entry = encrypted
        .items
        .iter()
        .find(|item| item.key == "gov-notes")
        .expect("entry present");
    assert_eq!(
        entry.encryption,
        MetadataEncryption::chacha20poly1305_with_label(Some("primary"))
    );
    assert_ne!(entry.value, secret);
    let decryptor = SymmetricEncryptor::<ChaCha20Poly1305>::new_with_key(&key).expect("decryptor");
    let plaintext = decryptor
        .decrypt_easy(entry.key.as_bytes(), &entry.value)
        .expect("decrypt");
    assert_eq!(plaintext, secret);
}
#[test]
fn governance_metadata_without_key_is_rejected() {
    let metadata = ExtraMetadata {
        items: vec![MetadataEntry::new(
            "gov-only",
            b"secret".to_vec(),
            MetadataVisibility::GovernanceOnly,
        )],
    };
    let err = match encrypt_governance_metadata(&metadata, None, None) {
        Ok(_) => panic!("expected governance-only metadata to require encryption key"),
        Err(err) => err,
    };
    assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
}
#[test]
fn public_metadata_cannot_declare_encryption() {
    let metadata = ExtraMetadata {
        items: vec![MetadataEntry::with_encryption(
            "public",
            b"plain".to_vec(),
            MetadataVisibility::Public,
            MetadataEncryption::chacha20poly1305_with_label(Some("public")),
        )],
    };
    let err = match encrypt_governance_metadata(&metadata, Some(&[0u8; 32]), Some("primary")) {
        Ok(_) => panic!("expected public metadata to reject encryption hints"),
        Err(err) => err,
    };
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
}
#[test]
fn governance_metadata_rejects_label_mismatch() {
    let key = [0x22u8; 32];
    let encryptor = SymmetricEncryptor::<ChaCha20Poly1305>::new_with_key(&key).expect("encryptor");
    let ciphertext = encryptor
        .encrypt_easy(b"gov-notes".as_ref(), b"payload".as_ref())
        .expect("encrypt payload");
    let metadata = ExtraMetadata {
        items: vec![MetadataEntry::with_encryption(
            "gov-notes",
            ciphertext,
            MetadataVisibility::GovernanceOnly,
            MetadataEncryption::chacha20poly1305_with_label(Some("secondary")),
        )],
    };
    let err = match encrypt_governance_metadata(&metadata, Some(&key), Some("primary")) {
        Ok(_) => panic!("expected label mismatch to be rejected"),
        Err(err) => err,
    };
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
}
#[test]
fn governance_metadata_requires_label_when_expected() {
    let key = [0x33u8; 32];
    let encryptor = SymmetricEncryptor::<ChaCha20Poly1305>::new_with_key(&key).expect("encryptor");
    let ciphertext = encryptor
        .encrypt_easy(b"gov-notes".as_ref(), b"payload".as_ref())
        .expect("encrypt payload");
    let metadata = ExtraMetadata {
        items: vec![MetadataEntry::with_encryption(
            "gov-notes",
            ciphertext,
            MetadataVisibility::GovernanceOnly,
            MetadataEncryption::chacha20poly1305_with_label(None::<String>),
        )],
    };
    let err = match encrypt_governance_metadata(&metadata, Some(&key), Some("primary")) {
        Ok(_) => panic!("expected missing label to be rejected"),
        Err(err) => err,
    };
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
}
#[test]
fn governance_metadata_accepts_matching_label_ciphertext() {
    let key = [0x44u8; 32];
    let encryptor = SymmetricEncryptor::<ChaCha20Poly1305>::new_with_key(&key).expect("encryptor");
    let ciphertext = encryptor
        .encrypt_easy(b"gov-notes".as_ref(), b"payload".as_ref())
        .expect("encrypt payload");
    let metadata = ExtraMetadata {
        items: vec![MetadataEntry::with_encryption(
            "gov-notes",
            ciphertext.clone(),
            MetadataVisibility::GovernanceOnly,
            MetadataEncryption::chacha20poly1305_with_label(Some("primary")),
        )],
    };
    let processed =
        encrypt_governance_metadata(&metadata, Some(&key), Some("primary")).expect("process");
    let entry = processed
        .items
        .iter()
        .find(|item| item.key == "gov-notes")
        .expect("entry");
    assert_eq!(entry.value, ciphertext);
    assert_eq!(
        entry.encryption,
        MetadataEncryption::chacha20poly1305_with_label(Some("primary"))
    );
}
#[test]
fn streaming_chunk_ingest_matches_fixture() {
    let (request, canonical_payload) = sample_request_with_payload();
    let chunk_profile = chunk_profile_for_request(request.chunk_size);
    let plan = CarBuildPlan::single_file_with_profile(&canonical_payload, chunk_profile)
        .expect("plan derivation succeeds");
    let mut streaming_store = ChunkStore::with_profile(chunk_profile);
    let chunk_dir = tempdir().expect("chunk dir");
    let chunk_path = chunk_dir
        .path()
        .canonicalize()
        .expect("canonical chunk directory")
        .join("chunks");
    let mut payload_cursor: &[u8] = canonical_payload.as_slice();
    let stream_output = streaming_store
        .ingest_plan_stream_to_directory(&plan, &mut payload_cursor, &chunk_path)
        .expect("streaming ingest succeeds");
    assert_eq!(
        stream_output.total_bytes, request.total_size,
        "persisted byte count should match total_size"
    );
    let direct_store = build_chunk_store(&request, canonical_payload.as_slice());
    assert_eq!(
        streaming_store.profile(),
        direct_store.profile(),
        "chunk profiles must match"
    );
    assert_eq!(
        streaming_store.payload_digest(),
        direct_store.payload_digest(),
        "payload digests must match"
    );
    assert_eq!(
        streaming_store.payload_len(),
        direct_store.payload_len(),
        "payload lengths must match"
    );
    assert_eq!(
        streaming_store.chunks(),
        direct_store.chunks(),
        "chunk metadata mismatch between streaming/non-streaming ingestion"
    );
    let expected_records = load_chunk_record_fixture("sample_chunk_records.txt");
    assert_eq!(
        stream_output.records.len(),
        expected_records.len(),
        "chunk record count drifted; regenerate fixtures"
    );
    for (actual, expected) in stream_output.records.iter().zip(expected_records.iter()) {
        assert_eq!(actual.file_name, expected.file_name);
        assert_eq!(actual.offset, expected.offset);
        assert_eq!(actual.length, expected.length);
        assert_eq!(hex::encode(actual.digest), expected.digest_hex);
    }
}
#[test]
fn manifest_persistence_matches_fixture() {
    let context = sample_manifest_context_for(BlobClass::TaikaiSegment);
    let spool_dir = tempdir().expect("spool dir");
    let manifest_path = persistence::persist_manifest_for_sorafs(
        spool_dir.path(),
        &context.artifacts.encoded,
        context.request.lane_id,
        context.request.epoch,
        context.request.sequence,
        &context.artifacts.storage_ticket,
        &context.artifacts.fingerprint,
    )
    .expect("persist manifest")
    .expect("spool path");
    let actual_bytes = fs::read(manifest_path).expect("read manifest");
    let expected_bytes = load_manifest_fixture("manifests/taikai_segment/manifest.norito.hex");
    assert_eq!(
        actual_bytes, expected_bytes,
        "DA manifest drifted; rerun regenerate_da_ingest_fixtures"
    );
}
#[test]
fn manifest_fixtures_cover_all_blob_classes() {
    for case in &MANIFEST_FIXTURE_CASES {
        let context = sample_manifest_context_for(case.blob_class);
        let expected_bytes =
            load_manifest_fixture(&format!("manifests/{}/manifest.norito.hex", case.slug));
        assert_eq!(
            context.artifacts.encoded, expected_bytes,
            "manifest fixture hex drifted for {}; rerun regenerate_da_ingest_fixtures",
            case.slug
        );
        let expected_json =
            load_manifest_json_fixture(&format!("manifests/{}/manifest.json", case.slug));
        let actual_json =
            json::to_value(&context.artifacts.manifest).expect("serialize manifest to JSON");
        assert_eq!(
            actual_json, expected_json,
            "manifest JSON fixture drifted for {}; rerun regenerate_da_ingest_fixtures",
            case.slug
        );
    }
}
#[test]
#[ignore = "regenerates DA ingest fixtures on disk"]
fn regenerate_da_ingest_fixtures() {
    for case in &MANIFEST_FIXTURE_CASES {
        let context = sample_manifest_context_for(case.blob_class);
        write_manifest_fixture_bundle(case, &context).expect("write manifest fixture bundle");
    }
    println!(
        "Regenerated manifest fixtures for {} blob classes under {}/manifests",
        MANIFEST_FIXTURE_CASES.len(),
        fixtures_dir().display()
    );
    let (request, canonical_payload) = sample_request_with_payload();
    let chunk_profile = chunk_profile_for_request(request.chunk_size);
    let plan = CarBuildPlan::single_file_with_profile(&canonical_payload, chunk_profile)
        .expect("plan derivation succeeds");
    let mut streaming_store = ChunkStore::with_profile(chunk_profile);
    let chunk_dir = tempdir().expect("chunk dir");
    let chunk_path = chunk_dir
        .path()
        .canonicalize()
        .expect("canonical chunk directory")
        .join("chunks");
    let mut payload_cursor: &[u8] = canonical_payload.as_slice();
    let stream_output = streaming_store
        .ingest_plan_stream_to_directory(&plan, &mut payload_cursor, &chunk_path)
        .expect("streaming ingest succeeds");
    let metadata =
        encrypt_governance_metadata(&request.metadata, None, None).expect("encrypt metadata");
    let rent_policy = DaRentPolicyV1::default();
    let manifest = resolve_manifest(
        &request,
        &streaming_store,
        canonical_payload.as_slice(),
        &metadata,
        &request.retention_policy,
        1_701_000_999,
        &rent_policy,
    )
    .expect("resolve manifest");
    let chunk_fixture_path = fixtures_dir().join("sample_chunk_records.txt");
    write_chunk_record_fixture(
        &chunk_fixture_path,
        &stream_output.records,
        stream_output.total_bytes,
    )
    .expect("write chunk fixture");
    println!(
        "Regenerated chunk fixtures at {} (total bytes = {})",
        chunk_fixture_path.display(),
        stream_output.total_bytes
    );
    println!(
        "Manifest hex for reference (taikai segment): {}",
        hex::encode(&manifest.encoded)
    );
}
fn sample_request_with_payload() -> (DaIngestRequest, Vec<u8>) {
    let request = sample_request();
    let canonical_vec = {
        let canonical = normalize_payload(&request).expect("normalize payload");
        canonical.into_vec()
    };
    (request, canonical_vec)
}
#[derive(Clone, Copy)]
struct ManifestFixtureCase {
    slug: &'static str,
    blob_class: BlobClass,
}
const MANIFEST_FIXTURE_CASES: [ManifestFixtureCase; 4] = [
    ManifestFixtureCase {
        slug: "taikai_segment",
        blob_class: BlobClass::TaikaiSegment,
    },
    ManifestFixtureCase {
        slug: "nexus_lane_sidecar",
        blob_class: BlobClass::NexusLaneSidecar,
    },
    ManifestFixtureCase {
        slug: "governance_artifact",
        blob_class: BlobClass::GovernanceArtifact,
    },
    ManifestFixtureCase {
        slug: "custom_0042",
        blob_class: BlobClass::Custom(0x0042),
    },
];
const fn manifest_fixture_variant_guard(class: BlobClass) {
    match class {
        BlobClass::TaikaiSegment
        | BlobClass::NexusLaneSidecar
        | BlobClass::GovernanceArtifact
        | BlobClass::Custom(_) => {}
    }
}
const _: fn(BlobClass) = manifest_fixture_variant_guard;
pub(super) struct ManifestFixtureContext {
    pub(super) request: DaIngestRequest,
    pub(super) artifacts: ManifestArtifacts,
}
pub(super) fn sample_manifest_context_for(blob_class: BlobClass) -> ManifestFixtureContext {
    manifest_context_for_sequence(blob_class, 7)
}
pub(super) fn zero_sequence_manifest_context_for(blob_class: BlobClass) -> ManifestFixtureContext {
    manifest_context_for_sequence(blob_class, 0)
}
fn manifest_context_for_sequence(blob_class: BlobClass, sequence: u64) -> ManifestFixtureContext {
    let (mut request, canonical_payload) = sample_request_with_payload();
    request.blob_class = blob_class;
    request.sequence = sequence;
    let keypair = checked_fixture_keypair(vec![0x42; 32], Algorithm::Ed25519);
    let digest = request.signing_digest();
    request.signatures[0].signature = checked_signature(keypair.private_key(), &digest);
    let chunk_store = build_chunk_store(&request, canonical_payload.as_slice());
    let metadata =
        encrypt_governance_metadata(&request.metadata, None, None).expect("metadata encrypt");
    let rent_policy = DaRentPolicyV1::default();
    let artifacts = resolve_manifest(
        &request,
        &chunk_store,
        canonical_payload.as_slice(),
        &metadata,
        &request.retention_policy,
        1_701_000_999,
        &rent_policy,
    )
    .expect("resolve manifest");
    ManifestFixtureContext { request, artifacts }
}
const METRIC_ASSERT_EPSILON: f64 = 1e-6;
#[test]
fn record_taikai_ingest_metrics_updates_histograms() {
    let (metrics, telemetry) = telemetry_handle_for_tests();
    let sample = taikai_ingest::TaikaiTelemetrySample {
        event_id: "event".into(),
        stream_id: "stream-main".into(),
        rendition_id: "1080p".into(),
        segment_sequence: 5,
        ingest_latency_ms: Some(150),
        live_edge_drift_ms: Some(-37),
    };
    taikai::record_taikai_ingest_metrics(&telemetry, "cluster-a", &sample);
    let dump = metrics.try_to_string().expect("metrics text");
    let latency_line = find_metric_line(
        &dump,
        "taikai_ingest_segment_latency_ms_sum{cluster=\"cluster-a\"",
    );
    assert!(latency_line.contains(r#"stream="stream-main""#));
    let latency = parse_metric_value(latency_line);
    assert!(
        (latency - 150.0).abs() < METRIC_ASSERT_EPSILON,
        "expected ingest latency sum to equal 150.0, got {latency}"
    );
    let drift_line = find_metric_line(
        &dump,
        "taikai_ingest_live_edge_drift_ms_sum{cluster=\"cluster-a\"",
    );
    assert!(drift_line.contains(r#"stream="stream-main""#));
    let drift = parse_metric_value(drift_line);
    assert!(
        (drift - 37.0).abs() < METRIC_ASSERT_EPSILON,
        "expected live-edge drift sum to equal 37.0, got {drift}"
    );
    let signed_drift_line = find_metric_line(
        &dump,
        "taikai_ingest_live_edge_drift_signed_ms{cluster=\"cluster-a\"",
    );
    assert!(signed_drift_line.contains(r#"stream="stream-main""#));
    let signed_drift = parse_metric_value(signed_drift_line);
    assert!(
        (signed_drift + 37.0).abs() < METRIC_ASSERT_EPSILON,
        "expected signed live-edge drift gauge to equal -37.0, got {signed_drift}"
    );
}
#[test]
fn record_taikai_ingest_error_counts_by_status() {
    let (metrics, telemetry) = telemetry_handle_for_tests();
    taikai::record_taikai_ingest_error(
        &telemetry,
        "cluster-a",
        "stream-main",
        StatusCode::BAD_REQUEST,
    );
    let dump = metrics.try_to_string().expect("metrics text");
    let error_line = find_metric_line(&dump, "taikai_ingest_errors_total{cluster=\"cluster-a\"");
    assert!(error_line.contains(r#"stream="stream-main""#));
    assert!(error_line.contains(r#"reason="Bad Request""#));
    let errors = parse_metric_value(error_line);
    assert!(
        (errors - 1.0).abs() < METRIC_ASSERT_EPSILON,
        "expected error counter to equal 1.0, got {errors}"
    );
}
#[test]
fn record_taikai_alias_rotation_event_updates_metrics() {
    let (metrics, telemetry) = telemetry_handle_for_tests();
    let manifest = sample_trm_manifest();
    taikai::record_taikai_alias_rotation_event(&telemetry, "cluster-a", &manifest, "deadbeef");
    let dump = metrics.try_to_string().expect("metrics text");
    let metric_line = find_metric_line(
        &dump,
        "taikai_trm_alias_rotations_total{alias_name=\"docs\",alias_namespace=\"sora\"",
    );
    assert!(
        metric_line.contains("cluster=\"cluster-a\"")
            && metric_line.contains("event=\"global-keynote\"")
            && metric_line.contains("stream=\"stage-a\""),
        "metric labels should reflect cluster/event/stream"
    );
    let value = parse_metric_value(metric_line);
    assert!(
        (value - 1.0).abs() < METRIC_ASSERT_EPSILON,
        "expected alias rotation counter to increment"
    );
    let snapshots = metrics.taikai_alias_rotation_status();
    assert_eq!(snapshots.len(), 1);
    let snapshot = &snapshots[0];
    assert_eq!(snapshot.cluster, "cluster-a");
    assert_eq!(snapshot.event, "global-keynote");
    assert_eq!(snapshot.stream, "stage-a");
    assert_eq!(snapshot.alias_namespace, "sora");
    assert_eq!(snapshot.alias_name, "docs");
    assert_eq!(snapshot.window_start_sequence, 0);
    assert_eq!(snapshot.window_end_sequence, 64);
    assert_eq!(snapshot.manifest_digest_hex, "deadbeef");
    assert_eq!(snapshot.rotations_total, 1);
    assert!(snapshot.last_updated_unix > 0);
}
#[test]
fn record_da_rent_quote_metrics_accumulates_values() {
    let (metrics, telemetry) = telemetry_handle_for_tests();
    let quote = DaRentQuote {
        base_rent: XorQuantity::try_from_micro(1_000_000)
            .expect("legacy micro-XOR value is representable"),
        protocol_reserve: XorQuantity::try_from_micro(250_000)
            .expect("legacy micro-XOR value is representable"),
        provider_reward: XorQuantity::try_from_micro(750_000)
            .expect("legacy micro-XOR value is representable"),
        pdp_bonus: XorQuantity::try_from_micro(50_000)
            .expect("legacy micro-XOR value is representable"),
        potr_bonus: XorQuantity::try_from_micro(25_000)
            .expect("legacy micro-XOR value is representable"),
        egress_credit_per_gib: XorQuantity::try_from_micro(1_500)
            .expect("legacy micro-XOR value is representable"),
    };
    record_da_rent_quote_metrics(&telemetry, "cluster-a", StorageClass::Warm, 4, 3, &quote);
    let dump = metrics.try_to_string().expect("metrics text");
    let gib_line = find_metric_line(
        &dump,
        "torii_da_rent_gib_months_total{cluster=\"cluster-a\"",
    );
    assert!(gib_line.contains(r#"storage_class="warm""#));
    let gib_months = parse_metric_value(gib_line);
    assert!(
        (gib_months - 12.0).abs() < METRIC_ASSERT_EPSILON,
        "expected 12 GiB-months recorded"
    );
    for (metric, expected) in [
        ("torii_da_rent_base_micro_total", 1_000_000.0),
        ("torii_da_protocol_reserve_micro_total", 250_000.0),
        ("torii_da_provider_reward_micro_total", 750_000.0),
        ("torii_da_pdp_bonus_micro_total", 50_000.0),
        ("torii_da_potr_bonus_micro_total", 25_000.0),
    ] {
        let line = find_metric_line(
            &dump,
            &format!("{metric}{{cluster=\"cluster-a\",storage_class=\"warm\""),
        );
        let value = parse_metric_value(line);
        assert!(
            (value - expected).abs() < METRIC_ASSERT_EPSILON,
            "metric {metric} expected {expected}, got {value}"
        );
    }
}
#[test]
fn record_da_chunking_metrics_observes_histogram() {
    let (metrics, telemetry) = telemetry_handle_for_tests();
    record_da_chunking_metrics(&telemetry, Duration::from_millis(150));
    let samples = metrics.torii_da_chunking_seconds.get_sample_count();
    assert_eq!(samples, 1);
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn da_rent_metrics_exposed_via_metrics_handler_snapshot() {
    let (metrics, telemetry) = telemetry_handle_for_tests_with_profile(TelemetryProfile::Extended);
    let quote = DaRentQuote {
        base_rent: XorQuantity::try_from_micro(1_000_000)
            .expect("legacy micro-XOR value is representable"),
        protocol_reserve: XorQuantity::try_from_micro(250_000)
            .expect("legacy micro-XOR value is representable"),
        provider_reward: XorQuantity::try_from_micro(750_000)
            .expect("legacy micro-XOR value is representable"),
        pdp_bonus: XorQuantity::try_from_micro(50_000)
            .expect("legacy micro-XOR value is representable"),
        potr_bonus: XorQuantity::try_from_micro(25_000)
            .expect("legacy micro-XOR value is representable"),
        egress_credit_per_gib: XorQuantity::try_from_micro(1_500)
            .expect("legacy micro-XOR value is representable"),
    };
    record_da_rent_quote_metrics(&telemetry, "cluster-a", StorageClass::Warm, 4, 3, &quote);
    let prometheus = crate::handle_metrics(&telemetry).expect("prometheus snapshot");
    let snapshot = da_rent_metric_lines(&prometheus);
    assert_eq!(
        snapshot,
        vec![
            "# HELP torii_da_pdp_bonus_micro_total Aggregate PDP bonuses (micro XOR) quoted by DA ingest grouped by cluster and storage class",
            "# HELP torii_da_potr_bonus_micro_total Aggregate PoTR bonuses (micro XOR) quoted by DA ingest grouped by cluster and storage class",
            "# HELP torii_da_protocol_reserve_micro_total Aggregate protocol reserve (micro XOR) quoted by DA ingest grouped by cluster and storage class",
            "# HELP torii_da_provider_reward_micro_total Aggregate provider rewards (micro XOR) quoted by DA ingest grouped by cluster and storage class",
            "# HELP torii_da_rent_base_micro_total Aggregate base rent (micro XOR) quoted by DA ingest grouped by cluster and storage class",
            "# HELP torii_da_rent_gib_months_total Aggregate GiB-month usage quoted by DA ingest grouped by cluster and storage class",
            "# TYPE torii_da_pdp_bonus_micro_total counter",
            "# TYPE torii_da_potr_bonus_micro_total counter",
            "# TYPE torii_da_protocol_reserve_micro_total counter",
            "# TYPE torii_da_provider_reward_micro_total counter",
            "# TYPE torii_da_rent_base_micro_total counter",
            "# TYPE torii_da_rent_gib_months_total counter",
            "torii_da_pdp_bonus_micro_total{cluster=\"cluster-a\",storage_class=\"warm\"} 50000",
            "torii_da_potr_bonus_micro_total{cluster=\"cluster-a\",storage_class=\"warm\"} 25000",
            "torii_da_protocol_reserve_micro_total{cluster=\"cluster-a\",storage_class=\"warm\"} 250000",
            "torii_da_provider_reward_micro_total{cluster=\"cluster-a\",storage_class=\"warm\"} 750000",
            "torii_da_rent_base_micro_total{cluster=\"cluster-a\",storage_class=\"warm\"} 1000000",
            "torii_da_rent_gib_months_total{cluster=\"cluster-a\",storage_class=\"warm\"} 12"
        ],
        "DA rent Prometheus payload drifted"
    );
    let dump = metrics.try_to_string().expect("metrics text");
    for line in snapshot {
        assert!(
            dump.contains(&line),
            "metrics text missing `{line}`\n{dump}"
        );
    }
}
#[test]
fn record_da_receipt_metrics_tracks_outcomes_and_cursor() {
    let (metrics, telemetry) = telemetry_handle_for_tests();
    let lane_epoch = LaneEpoch::new(LaneId::new(7), 3);
    record_da_receipt_metrics(
        &telemetry,
        lane_epoch,
        5,
        &ReceiptInsertOutcome::Stored {
            cursor_advanced: true,
        },
    );
    record_da_receipt_metrics(
        &telemetry,
        lane_epoch,
        5,
        &ReceiptInsertOutcome::Duplicate {
            path: std::path::PathBuf::new(),
        },
    );
    record_da_receipt_metrics(
        &telemetry,
        lane_epoch,
        5,
        &ReceiptInsertOutcome::DuplicateFingerprintConflict {
            path: std::path::PathBuf::new(),
            expected: test_fingerprint(0xA1),
            observed: test_fingerprint(0xA2),
        },
    );
    record_da_receipt_metrics(
        &telemetry,
        lane_epoch,
        5,
        &ReceiptInsertOutcome::ReceiptConflict {
            path: std::path::PathBuf::new(),
        },
    );
    record_da_receipt_metrics(
        &telemetry,
        lane_epoch,
        6,
        &ReceiptInsertOutcome::SequenceGap {
            expected_next: 6,
            observed: 7,
        },
    );
    let stored = metrics
        .torii_da_receipts_total
        .with_label_values(&["stored", "7"])
        .get();
    assert_eq!(stored, 1, "stored counter should increment");
    let duplicate = metrics
        .torii_da_receipts_total
        .with_label_values(&["duplicate", "7"])
        .get();
    assert_eq!(duplicate, 1, "duplicate counter should increment");
    let duplicate_fingerprint_conflict = metrics
        .torii_da_receipts_total
        .with_label_values(&["duplicate_fingerprint_conflict", "7"])
        .get();
    assert_eq!(
        duplicate_fingerprint_conflict, 1,
        "duplicate fingerprint conflict counter should increment"
    );
    let receipt_conflict = metrics
        .torii_da_receipts_total
        .with_label_values(&["receipt_conflict", "7"])
        .get();
    assert_eq!(
        receipt_conflict, 1,
        "receipt conflict counter should increment"
    );
    let sequence_gap = metrics
        .torii_da_receipts_total
        .with_label_values(&["sequence_gap", "7"])
        .get();
    assert_eq!(sequence_gap, 1, "sequence gap counter should increment");
    let epoch = metrics
        .torii_da_receipt_epoch
        .with_label_values(&["7"])
        .get();
    assert_eq!(epoch, 3, "epoch gauge should reflect the current epoch");
    let cursor = metrics
        .torii_da_receipt_highest_sequence
        .with_label_values(&["7"])
        .get();
    assert_eq!(cursor, 5, "cursor gauge should reflect stored sequence");
}

// DA receipt-outcome and fixture-helper regressions.
#[test]
fn da_spool_rejection_response_allows_committed_receipt_outcomes() {
    for receipt_outcome in [
        ReceiptInsertOutcome::Stored {
            cursor_advanced: true,
        },
        ReceiptInsertOutcome::Duplicate {
            path: PathBuf::from("receipt.norito"),
        },
    ] {
        let mut batch = DaSpoolBatch::new();
        batch.push(DaSpoolAction::new("receipt_log", move || {
            Ok(DaSpoolActionOutput::ReceiptOutcome(receipt_outcome))
        }));
        let report = batch.execute_sync();
        assert!(
            da_spool_rejection_response(&report, ResponseFormat::Json).is_none(),
            "accepted receipt outcomes must not be converted into errors"
        );
    }
}
#[test]
fn da_spool_rejection_response_rejects_stale_receipt_outcome() {
    let mut batch = DaSpoolBatch::new();
    batch.push(DaSpoolAction::new("receipt_log", || {
        Ok(DaSpoolActionOutput::ReceiptOutcome(
            ReceiptInsertOutcome::StaleSequence { highest: 9 },
        ))
    }));
    let report = batch.execute_sync();
    let response = da_spool_rejection_response(&report, ResponseFormat::Json)
        .expect("stale receipt must produce a conflict response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
}
#[test]
fn da_spool_rejection_response_rejects_sequence_gap_outcome() {
    let mut batch = DaSpoolBatch::new();
    batch.push(DaSpoolAction::new("receipt_log", || {
        Ok(DaSpoolActionOutput::ReceiptOutcome(
            ReceiptInsertOutcome::SequenceGap {
                expected_next: 10,
                observed: 12,
            },
        ))
    }));
    let report = batch.execute_sync();
    let response = da_spool_rejection_response(&report, ResponseFormat::Json)
        .expect("sequence gap receipt must produce a conflict response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
}
#[test]
fn da_spool_rejection_response_rejects_receipt_conflict_outcome() {
    let mut batch = DaSpoolBatch::new();
    batch.push(DaSpoolAction::new("receipt_log", || {
        Ok(DaSpoolActionOutput::ReceiptOutcome(
            ReceiptInsertOutcome::ReceiptConflict {
                path: PathBuf::from("receipt.norito"),
            },
        ))
    }));
    let report = batch.execute_sync();
    let response = da_spool_rejection_response(&report, ResponseFormat::Json)
        .expect("receipt conflict must produce a conflict response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
}
#[test]
fn da_spool_rejection_response_rejects_duplicate_fingerprint_conflict_outcome() {
    let mut batch = DaSpoolBatch::new();
    batch.push(DaSpoolAction::new("receipt_log", || {
        Ok(DaSpoolActionOutput::ReceiptOutcome(
            ReceiptInsertOutcome::DuplicateFingerprintConflict {
                path: PathBuf::from("receipt.norito"),
                expected: test_fingerprint(0xA1),
                observed: test_fingerprint(0xA2),
            },
        ))
    }));
    let report = batch.execute_sync();
    let response = da_spool_rejection_response(&report, ResponseFormat::Json)
        .expect("duplicate fingerprint conflict must produce a conflict response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
}
#[test]
fn da_spool_rejection_response_rejects_manifest_conflict_outcome() {
    let mut batch = DaSpoolBatch::new();
    batch.push(DaSpoolAction::new("receipt_log", || {
        Ok(DaSpoolActionOutput::ReceiptOutcome(
            ReceiptInsertOutcome::ManifestConflict {
                expected: BlobDigest::new([1; 32]),
                observed: BlobDigest::new([2; 32]),
            },
        ))
    }));
    let report = batch.execute_sync();
    let response = da_spool_rejection_response(&report, ResponseFormat::Json)
        .expect("manifest conflict must produce a conflict response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
}
#[test]
fn da_spool_rejection_response_rejects_missing_receipt_log_outcome() {
    let mut batch = DaSpoolBatch::new();
    batch.push(DaSpoolAction::new("manifest", || {
        Ok(DaSpoolActionOutput::None)
    }));
    let report = batch.execute_sync();
    let response = da_spool_rejection_response(&report, ResponseFormat::Json)
        .expect("missing receipt log outcome must fail closed");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
#[test]
fn da_spool_rejection_response_rejects_spool_action_errors() {
    let mut batch = DaSpoolBatch::new();
    batch.push(DaSpoolAction::new("manifest", || {
        Err("disk full".to_owned())
    }));
    let report = batch.execute_sync();
    let response = da_spool_rejection_response(&report, ResponseFormat::Json)
        .expect("spool action errors must fail closed");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
fn telemetry_handle_for_tests_with_profile(
    profile: TelemetryProfile,
) -> (Arc<Metrics>, MaybeTelemetry) {
    let metrics = test_metrics();
    let telemetry = Telemetry::new(metrics.clone(), true);
    let handle = MaybeTelemetry::from_profile(Some(telemetry), profile);
    (metrics, handle)
}
pub(super) fn telemetry_handle_for_tests() -> (Arc<Metrics>, MaybeTelemetry) {
    telemetry_handle_for_tests_with_profile(TelemetryProfile::Operator)
}
fn test_metrics() -> Arc<Metrics> {
    enable_duplicate_metric_panic();
    Arc::new(Metrics::default())
}
fn enable_duplicate_metric_panic() {
    static INIT: LazyLock<()> = LazyLock::new(|| {
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("IROHA_METRICS_PANIC_ON_DUPLICATE", "1");
        }
    });
    LazyLock::force(&INIT);
}
fn find_metric_line<'a>(dump: &'a str, prefix: &str) -> &'a str {
    dump.lines()
        .find(|line| line.starts_with(prefix))
        .unwrap_or_else(|| panic!("metric `{prefix}` not found\n{dump}"))
}
fn da_rent_metric_lines(dump: &str) -> Vec<String> {
    let mut lines: Vec<String> = dump
        .lines()
        .filter(|line| {
            line.starts_with("# HELP torii_da_")
                || line.starts_with("# TYPE torii_da_")
                || line.starts_with("torii_da_")
        })
        .filter(|line| {
            line.contains("_rent_")
                || line.contains("protocol_reserve_micro_total")
                || line.contains("provider_reward_micro_total")
                || line.contains("_pdp_bonus_micro_total")
                || line.contains("_potr_bonus_micro_total")
        })
        .map(str::to_owned)
        .collect();
    lines.sort();
    lines
}
fn parse_metric_value(line: &str) -> f64 {
    line.split_whitespace()
        .last()
        .unwrap_or_default()
        .parse::<f64>()
        .expect("metric value")
}
struct ChunkRecordFixture {
    file_name: String,
    offset: u64,
    length: u32,
    digest_hex: String,
}
fn load_chunk_record_fixture(name: &str) -> Vec<ChunkRecordFixture> {
    let path = fixtures_dir().join(name);
    let contents = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("failed to read chunk fixture {}: {err}", path.display());
    });
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let mut parts = line.split_whitespace();
            let file_name = parts.next()?.to_string();
            let offset = parts
                .next()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or_else(|| panic!("missing offset in fixture line `{line}`"));
            let length = parts
                .next()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or_else(|| panic!("missing length in fixture line `{line}`"));
            let digest_hex = parts
                .next()
                .map(ToString::to_string)
                .unwrap_or_else(|| panic!("missing digest in fixture line `{line}`"));
            Some(ChunkRecordFixture {
                file_name,
                offset,
                length,
                digest_hex,
            })
        })
        .collect()
}
fn load_manifest_fixture(name: &str) -> Vec<u8> {
    let path = fixtures_dir().join(name);
    let contents = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("failed to read manifest fixture {}: {err}", path.display());
    });
    hex::decode(contents.trim()).expect("fixture must be valid hex")
}
fn load_manifest_json_fixture(name: &str) -> Value {
    let path = fixtures_dir().join(name);
    let contents = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "failed to read manifest JSON fixture {}: {err}",
            path.display()
        );
    });
    json::from_str(&contents).expect("fixture must be valid Norito JSON")
}
fn write_manifest_fixture_bundle(
    case: &ManifestFixtureCase,
    context: &ManifestFixtureContext,
) -> std::io::Result<()> {
    let manifest_dir = fixtures_dir().join("manifests").join(case.slug);
    fs::create_dir_all(&manifest_dir)?;
    let hex_path = manifest_dir.join("manifest.norito.hex");
    let hex_text = format!("{}\n", hex::encode(&context.artifacts.encoded));
    fs::write(hex_path, hex_text)?;
    let manifest_value =
        json::to_value(&context.artifacts.manifest).expect("serialize manifest as JSON value");
    let json_text = json::to_string_pretty(&manifest_value).expect("render manifest JSON fixture");
    fs::write(manifest_dir.join("manifest.json"), format!("{json_text}\n"))?;
    Ok(())
}
fn write_chunk_record_fixture(
    path: &Path,
    records: &[PersistedChunkRecord],
    total_bytes: u64,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::File::create(path)?;
    writeln!(file, "# file_name offset length digest_hex")?;
    for record in records {
        writeln!(
            file,
            "{} {} {} {}",
            record.file_name,
            record.offset,
            record.length,
            hex::encode(record.digest)
        )?;
    }
    writeln!(file, "# total_bytes {total_bytes}")?;
    Ok(())
}
pub(super) fn format_base_id(
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    ticket: &StorageTicketId,
    fingerprint: &ReplayFingerprint,
) -> String {
    let lane_hex = format!("{:08x}", lane_id.as_u32());
    let epoch_hex = format!("{:016x}", epoch);
    let sequence_hex = format!("{:016x}", sequence);
    let ticket_hex = hex::encode(ticket.as_ref());
    let fingerprint_hex = hex::encode(fingerprint.as_bytes());
    format!("{lane_hex}-{epoch_hex}-{sequence_hex}-{ticket_hex}-{fingerprint_hex}")
}
fn fixtures_dir() -> PathBuf {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/da/ingest");
    base.canonicalize()
        .expect("fixtures/da/ingest directory must exist")
}
