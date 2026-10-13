//! Crash recovery, canonical lineage, concurrency and filesystem rejection for software checkpoints.
use super::*;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

fn checkpoint(root: &Path) -> NativeCheckpointV1 {
    NativeCheckpointV1 {
        handle: "software://sorafs/native-checkpoint".to_owned(),
        qualification: ProviderIngestCheckpointProviderQualificationV1::new(1, [1; 32]),
        root: root.join("authority"),
        maximum: 4096,
        gate: Mutex::new(()),
        custody: OnceLock::new(),
    }
}

fn record(
    previous: Option<&ProviderIngestSealedCheckpointRecordV1>,
    marker: u8,
) -> ProviderIngestSealedCheckpointRecordV1 {
    let mut record = ProviderIngestSealedCheckpointRecordV1 {
        namespace: *b"sorafs.provider.ingest.outbox.v1",
        version: 1,
        checkpoint_sequence: previous.map_or(1, |value| value.checkpoint_sequence + 1),
        predecessor_revision: previous.map(|value| value.revision),
        predecessor_checkpoint_digest: previous.map(|value| value.checkpoint_digest),
        checkpoint_bytes: norito::to_bytes(&marker).unwrap(),
        checkpoint_digest: [0; 32],
        revision: [0; 32],
    };
    record.checkpoint_digest = *blake3::hash(&record.checkpoint_bytes).as_bytes();
    let mut hash = blake3::Hasher::new();
    hash.update(b"sorafs.provider.ingest.sealed-checkpoint.revision.v1\0");
    hash.update(&record.namespace);
    hash.update(&[record.version]);
    hash.update(&record.checkpoint_sequence.to_le_bytes());
    for predecessor in [
        record.predecessor_revision,
        record.predecessor_checkpoint_digest,
    ] {
        if let Some(value) = predecessor {
            hash.update(&[1]);
            hash.update(&value);
        } else {
            hash.update(&[0]);
        }
    }
    hash.update(&record.checkpoint_digest);
    hash.update(&(record.checkpoint_bytes.len() as u64).to_le_bytes());
    hash.update(&record.checkpoint_bytes);
    record.revision = *hash.finalize().as_bytes();
    record.validate(4096).unwrap();
    record
}

#[test]
fn native_checkpoint_cas_survives_restart_and_rejects_stale_or_corrupt_records() {
    let temporary = tempfile::tempdir().unwrap();
    let store = checkpoint(temporary.path());
    assert!(store.load_latest().unwrap().is_none());
    let first = record(None, 1);
    store.compare_and_swap_latest(None, &first).unwrap();
    let second = record(Some(&first), 2);
    assert!(store.compare_and_swap_latest(None, &second).is_err());
    assert_eq!(store.load_latest().unwrap(), Some(first.clone()));
    store
        .compare_and_swap_latest(Some(first.revision), &second)
        .unwrap();
    let other = checkpoint(temporary.path());
    assert!(
        other.load_latest().is_err(),
        "a second process incarnation cannot share authority"
    );
    drop(store);
    assert_eq!(other.load_latest().unwrap(), Some(second.clone()));
    let mut corrupt = record(Some(&second), 3);
    corrupt.checkpoint_bytes[0] ^= 1;
    assert!(
        other
            .compare_and_swap_latest(Some(second.revision), &corrupt)
            .is_err()
    );
    assert_eq!(other.load_latest().unwrap(), Some(second));
}

#[test]
fn native_checkpoint_competing_successors_have_exactly_one_winner() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Arc::new(checkpoint(temporary.path()));
    let first = record(None, 1);
    store.compare_and_swap_latest(None, &first).unwrap();
    let next = [record(Some(&first), 2), record(Some(&first), 3)];
    let barrier = Arc::new(std::sync::Barrier::new(2));
    // Both writers are spawned before either is joined, so they race on the same revision.
    let handles = next.clone().map(|next| {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let revision = first.revision;
        std::thread::spawn(move || {
            barrier.wait();
            store.compare_and_swap_latest(Some(revision), &next)
        })
    });
    let successes = handles
        .into_iter()
        .map(|handle| handle.join().unwrap().is_ok())
        .filter(|success| *success)
        .count();
    assert_eq!(successes, 1);
    assert!(next.contains(&store.load_latest().unwrap().unwrap()));
}

#[cfg(unix)]
#[test]
fn native_checkpoint_rejects_symlink_and_oversized_payload_before_read_or_write() {
    let temporary = tempfile::tempdir().unwrap();
    let store = checkpoint(temporary.path());
    store.load_latest().unwrap();
    let sentinel = temporary.path().join("untouched");
    fs::write(&sentinel, b"sentinel").unwrap();
    std::os::unix::fs::symlink(&sentinel, store.root.join("checkpoint.pending")).unwrap();
    assert!(
        store
            .compare_and_swap_latest(None, &record(None, 1))
            .is_err()
    );
    assert_eq!(fs::read(&sentinel).unwrap(), b"sentinel");
    fs::remove_file(store.root.join("checkpoint.pending")).unwrap();
    std::os::unix::fs::symlink(&sentinel, store.root.join("checkpoint.to")).unwrap();
    assert!(store.load_latest().is_err());
    fs::remove_file(store.root.join("checkpoint.to")).unwrap();
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(store.root.join("checkpoint.to"))
        .unwrap();
    file.set_len(8193).unwrap();
    assert!(store.load_latest().is_err());
}

#[test]
fn native_checkpoint_private_descriptor_rejects_hardlinks_oversize_and_corrupt_bytes() {
    let temporary = tempfile::tempdir().unwrap();
    let store = checkpoint(temporary.path());
    assert_eq!(store.load_latest().unwrap(), None);
    let directory = PrivateDirectory::open(&store.root).unwrap();
    let oversized = directory.open_lock("checkpoint.to").unwrap();
    oversized.set_len(8193).unwrap();
    drop(oversized);
    assert!(store.load_latest().is_err());
    directory
        .write_atomic(
            "checkpoint.to",
            b"not a canonical record",
            PublishMode::Replace,
        )
        .unwrap();
    assert!(store.load_latest().is_err(), "malformed is never absence");
    let first = record(None, 1);
    directory
        .write_atomic(
            "checkpoint.to",
            &first.to_canonical_bytes(4096).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert_eq!(store.load_latest().unwrap(), Some(first.clone()));
    let alias = temporary.path().join("shared-record");
    fs::hard_link(store.root.join("checkpoint.to"), &alias).unwrap();
    assert!(store.load_latest().is_err());
    assert!(
        store
            .compare_and_swap_latest(Some(first.revision), &record(Some(&first), 2))
            .is_err()
    );
    fs::remove_file(alias).unwrap();
    assert_eq!(store.load_latest().unwrap(), Some(first));
}

#[test]
fn native_checkpoint_retains_original_namespace_or_native_rename_is_denied() {
    let temporary = tempfile::tempdir().unwrap();
    let store = checkpoint(temporary.path());
    let first = record(None, 1);
    store.compare_and_swap_latest(None, &first).unwrap();
    let moved = temporary.path().join("moved-authority");
    let rename = fs::rename(&store.root, &moved);
    #[cfg(unix)]
    {
        rename.unwrap();
        let replacement = PrivateDirectory::open_or_create(&store.root).unwrap();
        replacement
            .write_atomic(
                "checkpoint.to",
                &first.to_canonical_bytes(4096).unwrap(),
                PublishMode::CreateNew,
            )
            .unwrap();
        assert!(
            store.load_latest().is_err(),
            "equal bytes in a substituted namespace are not original custody"
        );
        assert!(
            store
                .compare_and_swap_latest(Some(first.revision), &record(Some(&first), 2))
                .is_err()
        );
    }
    #[cfg(windows)]
    {
        assert!(
            rename.is_err(),
            "native retained ancestry denies deletion/rename"
        );
        assert_eq!(store.load_latest().unwrap(), Some(first));
    }
}

#[cfg(unix)]
#[test]
fn native_checkpoint_fifo_refuses_without_a_writer() {
    use std::{sync::mpsc, time::Duration};
    let temporary = tempfile::tempdir().unwrap();
    let store = Arc::new(checkpoint(temporary.path()));
    assert_eq!(store.load_latest().unwrap(), None);
    let fifo = store.root.join("checkpoint.to");
    // rustix has no mkfifoat on Apple; the exact POSIX call creates only this
    // test-owned FIFO without a child inheriting parallel tests' file locks.
    #[cfg(target_vendor = "apple")]
    #[allow(unsafe_code)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        unsafe extern "C" {
            fn mkfifo(path: *const std::ffi::c_char, mode: u16) -> std::ffi::c_int;
        }
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: Apple mode_t is u16; the owned NUL-terminated path lives
        // through this call, which creates only the fixture's FIFO.
        assert_eq!(unsafe { mkfifo(path.as_ptr(), 0o600) }, 0);
    }
    #[cfg(not(target_vendor = "apple"))]
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    let (sender, receiver) = mpsc::channel();
    let reader = Arc::clone(&store);
    let handle = std::thread::spawn(move || {
        let _ = sender.send(reader.load_latest());
    });
    let result = receiver.recv_timeout(Duration::from_secs(2));
    if result.is_err() {
        // Release an incorrectly blocking old implementation before failing; no stranded thread.
        let release = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(i32::from_ne_bytes(
                rustix::fs::OFlags::NONBLOCK.bits().to_ne_bytes(),
            ))
            .open(&fifo)
            .unwrap();
        drop(release);
    }
    handle.join().unwrap();
    assert!(
        result
            .expect("FIFO refusal must not need a writer")
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn native_checkpoint_replaced_lock_refuses_even_when_checkpoint_bytes_match() {
    let temporary = tempfile::tempdir().unwrap();
    let store = checkpoint(temporary.path());
    let first = record(None, 1);
    store.compare_and_swap_latest(None, &first).unwrap();
    fs::rename(store.root.join("lock"), store.root.join("original-lock")).unwrap();
    let directory = PrivateDirectory::open(&store.root).unwrap();
    let _substitute = directory.create_lock("lock").unwrap();
    assert!(store.load_latest().is_err());
    assert!(
        store
            .compare_and_swap_latest(Some(first.revision), &record(Some(&first), 2))
            .is_err()
    );
}

#[cfg(windows)]
#[test]
fn native_checkpoint_windows_ownership_denies_write_delete_and_reopen_can_recover() {
    let temporary = tempfile::tempdir().unwrap();
    let store = checkpoint(temporary.path());
    let first = record(None, 1);
    store.compare_and_swap_latest(None, &first).unwrap();
    assert!(
        fs::OpenOptions::new()
            .write(true)
            .open(store.root.join("lock"))
            .is_err()
    );
    assert!(fs::remove_file(store.root.join("lock")).is_err());
    assert!(fs::rename(&store.root, temporary.path().join("replaced")).is_err());
    assert_eq!(store.load_latest().unwrap(), Some(first.clone()));
    drop(store);
    let reopened = checkpoint(temporary.path());
    assert_eq!(reopened.load_latest().unwrap(), Some(first));
}
