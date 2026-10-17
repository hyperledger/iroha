//! Snapshot DATA integrity, bounded capture and closing-custody regressions.

use super::*;

#[test]
fn physical_capture_io_distinguishes_unavailability_from_corruption() {
    use io::ErrorKind;

    for kind in [
        ErrorKind::InvalidData,
        ErrorKind::InvalidInput,
        ErrorKind::UnexpectedEof,
    ] {
        assert!(matches!(
            capture_io(io::Error::from(kind)),
            Error::Inventory
        ));
    }
    for kind in [
        ErrorKind::NotFound,
        ErrorKind::PermissionDenied,
        ErrorKind::TimedOut,
        ErrorKind::Interrupted,
        ErrorKind::Other,
    ] {
        assert!(matches!(
            capture_io(io::Error::from(kind)),
            Error::Unavailable
        ));
    }
}

fn fixture(
    raws: &[&[u8]],
) -> (
    tempfile::TempDir,
    PrivateDirectory,
    EncodedDirectoryOriginalsV1,
) {
    let temp = tempfile::tempdir().unwrap();
    let root =
        PrivateDirectory::open_or_create(temp.path().canonicalize().unwrap().join("data")).unwrap();
    let mut rows = Vec::new();
    for raw in raws {
        let stored = zstd::stream::encode_all(*raw, 1).unwrap();
        let row = EncodedOriginalV1 {
            original: BlobV1::of(raw),
            stored: BlobV1::of(&stored),
        };
        let mut file = root
            .create_retained_private(hex::encode(row.original.sha256), stored.len())
            .unwrap();
        file.write_all(&stored).unwrap();
        file.seal_read_only().unwrap();
        rows.push(row);
    }
    rows.sort_by_key(|row| row.original.sha256);
    let source = EncodedDirectoryOriginalsV1::open_existing(
        root.path(),
        &EncodedTransportV1::new(rows).unwrap(),
    )
    .unwrap();
    (temp, root, source)
}

#[test]
fn snapshot_reads_exact_originals_repeatedly_without_persisting_decoded_data() {
    let raws: &[&[u8]] = &[b"first exact original", b"second exact original"];
    let (_temp, root, mut source) = fixture(raws);
    let before = root.entries(10).unwrap();
    source
        .with_snapshot::<_, Error>(|snapshot| {
            for _ in 0..3 {
                for raw in raws {
                    let mut reader = snapshot.open(BlobV1::of(raw).sha256)?;
                    let mut bytes = Vec::new();
                    reader.read_to_end(&mut bytes).unwrap();
                    assert_eq!(bytes, *raw);
                }
            }
            assert!(matches!(snapshot.open([0xff; 32]), Err(Error::Inventory)));
            Ok(())
        })
        .unwrap();
    assert_eq!(source.observed.lock().unwrap().len(), raws.len());
    assert_eq!(root.entries(10).unwrap(), before);
    // Runtime reads continue through the same observed native directory owner.
    let digest = BlobV1::of(raws[0]).sha256;
    let mut bytes = Vec::new();
    source
        .open(digest)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, raws[0]);
    std::fs::rename(
        root.path().join(hex::encode(digest)),
        root.path().join("old"),
    )
    .unwrap();
    assert!(matches!(source.open(digest), Err(Error::Inventory)));
}

#[test]
fn snapshot_shares_one_immutable_view_with_concurrent_readers_and_live_reads_do_not() {
    let raws: &[&[u8]] = &[b"first shared original", b"second shared original"];
    let (_temp, root, source) = fixture(raws);
    // A live directory keeps its per-read custody checks on the thread holding it.
    assert!(source.shared_view().is_none());
    let before = root.entries(10).unwrap();
    source
        .with_snapshot::<_, Error>(|snapshot| {
            let view = snapshot.shared_view().ok_or(Error::Inventory)?;
            std::thread::scope(|scope| {
                for _ in 0..4 {
                    scope.spawn(|| {
                        for _ in 0..3 {
                            for raw in raws {
                                let mut bytes = Vec::new();
                                view.open_shared(BlobV1::of(raw).sha256)
                                    .unwrap()
                                    .read_to_end(&mut bytes)
                                    .unwrap();
                                assert_eq!(bytes, *raw);
                            }
                        }
                        assert!(matches!(
                            view.open_shared([0xff; 32]),
                            Err(Error::Inventory)
                        ));
                    });
                }
            });
            // Every reader has joined; the exclusive handle reads the same bytes.
            let mut bytes = Vec::new();
            snapshot
                .open(BlobV1::of(raws[1]).sha256)?
                .read_to_end(&mut bytes)
                .unwrap();
            assert_eq!(bytes, raws[1]);
            Ok(())
        })
        .unwrap();
    assert_eq!(source.observed.lock().unwrap().len(), raws.len());
    assert_eq!(root.entries(10).unwrap(), before);
}

#[test]
fn snapshot_body_reads_immutable_memory_but_cannot_return_after_file_replacement() {
    let raw = b"immutable borrowed public bytes";
    let (_temp, root, source) = fixture(&[raw]);
    let result = source.with_snapshot::<_, Error>(|snapshot| {
        std::fs::rename(
            root.path().join(hex::encode(BlobV1::of(raw).sha256)),
            root.path().join("retained-old"),
        )
        .unwrap();
        let mut bytes = Vec::new();
        snapshot
            .open(BlobV1::of(raw).sha256)?
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, raw);
        Ok("must never escape changed custody")
    });
    assert!(matches!(result, Err(Error::Inventory)));
}

#[test]
fn snapshot_authenticates_unrequested_raw_and_stored_identities_before_body() {
    for raw_change in [false, true] {
        let (_temp, _root, mut source) = fixture(&[b"requested", b"never requested"]);
        let row = source.originals.values_mut().next_back().unwrap();
        if raw_change {
            row.original.bytes += 1;
        } else {
            row.stored.sha256[0] ^= 1;
        }
        let mut entered = false;
        let result = source.with_snapshot::<_, Error>(|_| {
            entered = true;
            Ok(())
        });
        assert!(matches!(result, Err(Error::Inventory)));
        assert!(!entered);
    }
}

#[test]
fn snapshot_refuses_malformed_frame_even_if_stored_hash_is_correct() {
    let (_temp, root, mut source) = fixture(&[b"a single current zstd frame"]);
    let (&digest, row) = source.originals.iter_mut().next().unwrap();
    let name = hex::encode(digest);
    let mut stored = std::fs::read(root.path().join(&name)).unwrap();
    stored.extend(zstd::stream::encode_all(&b""[..], 1).unwrap());
    std::fs::rename(root.path().join(&name), root.path().join("old")).unwrap();
    let mut file = root.create_retained_private(&name, stored.len()).unwrap();
    file.write_all(&stored).unwrap();
    file.seal_read_only().unwrap();
    row.stored = BlobV1::of(&stored);
    let mut entered = false;
    assert!(
        source
            .with_snapshot::<_, Error>(|_| {
                entered = true;
                Ok(())
            })
            .is_err()
    );
    assert!(!entered);
}

#[test]
fn snapshot_checks_complete_stored_budget_before_opening_any_original() {
    let (_temp, root, mut source) = fixture(&[b"small one", b"small two"]);
    for row in source.originals.values_mut() {
        row.stored.bytes = (MAX_STORED_BYTES / 2) as u64;
    }
    assert_eq!(source.snapshot_extent().unwrap(), MAX_STORED_BYTES);
    source
        .originals
        .values_mut()
        .next_back()
        .unwrap()
        .stored
        .bytes += 1;
    // Absence would be Unavailable if capture incorrectly opened before checking
    // the complete finite sum. Budget refusal must retain no observed baseline.
    for digest in source.originals.keys() {
        std::fs::remove_file(root.path().join(hex::encode(digest))).unwrap();
    }
    assert!(matches!(
        source.with_snapshot::<_, Error>(|_| Ok(())),
        Err(Error::Inventory)
    ));
    assert!(source.observed.lock().unwrap().is_empty());
}

#[test]
fn snapshot_closes_observed_custody_after_capture_failure() {
    let (_temp, root, source) = fixture(&[b"one", b"two"]);
    let digests: Vec<_> = source.originals.keys().copied().collect();
    // The later member has an earlier retained runtime baseline. The first one
    // is initially absent, so capture itself reports Unavailable before reaching
    // the changed observed member; closing must override it with Inventory.
    source.open_original(digests[1]).unwrap();
    for (index, digest) in digests.iter().enumerate() {
        std::fs::rename(
            root.path().join(hex::encode(digest)),
            root.path().join(format!("old-{index}")),
        )
        .unwrap();
    }
    let mut entered = false;
    let result = source.with_snapshot::<_, Error>(|_| {
        entered = true;
        Ok(())
    });
    assert!(matches!(result, Err(Error::Inventory)));
    assert!(!entered);
}

#[test]
fn snapshot_initial_absence_is_unavailable_without_entering_body() {
    let (_temp, root, source) = fixture(&[b"not previously observed"]);
    let digest = *source.originals.keys().next().unwrap();
    std::fs::remove_file(root.path().join(hex::encode(digest))).unwrap();
    let mut entered = false;
    let result = source.with_snapshot::<_, Error>(|_| {
        entered = true;
        Ok(())
    });
    assert!(matches!(result, Err(Error::Unavailable)));
    assert!(!entered);
    assert!(source.observed.lock().unwrap().is_empty());
}

#[test]
fn snapshot_preserves_body_errors_unless_closing_custody_fails() {
    let (_temp, root, source) = fixture(&[b"body cancellation"]);
    assert!(matches!(
        source.with_snapshot::<(), Error>(|_| Err(Error::Cancelled)),
        Err(Error::Cancelled)
    ));
    let result = source.with_snapshot::<(), Error>(|_| {
        std::fs::rename(root.path(), root.path().with_file_name("old-root")).unwrap();
        Err(Error::Cancelled)
    });
    assert!(matches!(result, Err(Error::Inventory)));
}

#[cfg(unix)]
#[test]
fn snapshot_closes_same_byte_rewrites_and_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    for rewrite in [false, true] {
        let raw = b"unchanged bytes do not excuse changed custody";
        let (_temp, root, source) = fixture(&[raw]);
        let path = root.path().join(hex::encode(BlobV1::of(raw).sha256));
        let result = source.with_snapshot::<_, Error>(|_| {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            if rewrite {
                let bytes = std::fs::read(&path).unwrap();
                let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
                file.write_all(&bytes).unwrap();
                file.set_modified(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap();
                drop(file);
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
            }
            Ok(())
        });
        assert!(matches!(result, Err(Error::Inventory)));
    }
}

#[cfg(unix)]
#[test]
fn snapshot_closes_symlink_and_hardlink_substitution() {
    use std::os::unix::fs::symlink;

    for link in [false, true] {
        let raw = b"original has exactly one retained private name";
        let (_temp, root, source) = fixture(&[raw]);
        let path = root.path().join(hex::encode(BlobV1::of(raw).sha256));
        let result = source.with_snapshot::<_, Error>(|_| {
            let other = root.path().join("other-name");
            if link {
                std::fs::hard_link(&path, other).unwrap();
            } else {
                std::fs::rename(&path, &other).unwrap();
                symlink(other, &path).unwrap();
            }
            Ok(())
        });
        assert!(matches!(result, Err(Error::Inventory)));
    }
}
