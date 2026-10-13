#[test]
fn stable_bounded_sidecar_read_rejects_post_admission_growth() {
    let root = tempfile::tempdir().expect("create bounded-read root");
    let path = root.path().join("bounded.norito");
    std::fs::write(&path, [0_u8; 8]).expect("write admitted sidecar");
    let error = super::Kura::read_regular_sidecar_snapshot_for_with_admission_hook(
        root.path(),
        &path,
        root.path(),
        8,
        || {
            use std::io::Write as _;
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open admitted sidecar for growth")
                .write_all(&[1])
                .expect("grow admitted sidecar by one byte");
        },
    )
    .expect_err("post-admission growth must invalidate the bounded read");
    assert!(matches!(
        error,
        super::Error::IO(ref source, _) if source.kind() == std::io::ErrorKind::InvalidData
    ));
    assert_eq!(
        std::fs::metadata(&path)
            .expect("inspect grown sidecar")
            .len(),
        9
    );
}

#[test]
fn stable_bounded_sidecar_read_allows_sibling_publication() {
    let root = tempfile::tempdir().expect("create bounded-read root");
    let path = root.path().join("bounded.norito");
    let bytes = [7_u8; 8];
    std::fs::write(&path, bytes).expect("write admitted sidecar");
    let sibling = root.path().join("concurrent-sibling.norito");
    let snapshot = super::Kura::read_regular_sidecar_snapshot_for_with_admission_hook(
        root.path(),
        &path,
        root.path(),
        bytes.len(),
        || std::fs::write(&sibling, [9_u8]).expect("publish sibling sidecar"),
    )
    .expect("sibling publication must not invalidate the bounded file read")
    .expect("admitted sidecar remains present");
    assert_eq!(snapshot.bytes, bytes);
    assert_eq!(std::fs::read(sibling).expect("read sibling sidecar"), [9]);
}

#[test]
fn stable_bounded_sidecar_read_prepays_exact_raw_buffer_cumulatively() {
    let root = tempfile::tempdir().expect("create bounded-read root");
    let path = root.path().join("bounded.norito");
    let bytes = [7_u8; 64];
    std::fs::write(&path, bytes).unwrap();
    let read =
        |bound| super::Kura::read_regular_sidecar_bytes_for(root.path(), &path, root.path(), bound);
    let limits =
        |allocation| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64);
    norito::with_decode_limits_scope(limits(0), || {
        assert!(matches!(
            read(bytes.len()),
            Err(super::Error::NoritoFrame(
                norito::Error::TotalAllocationExceeded {
                    attempted: 64,
                    limit: 0,
                }
            ))
        ));
    });
    norito::with_decode_limits_scope(limits(bytes.len()), || {
        assert!(read(bytes.len() - 1).is_err());
        assert_eq!(read(bytes.len()).unwrap().unwrap(), bytes);
        assert!(matches!(
            read(bytes.len()),
            Err(super::Error::NoritoFrame(
                norito::Error::TotalAllocationExceeded {
                    attempted: 128,
                    limit: 64,
                }
            ))
        ));
    });
    assert_eq!(read(bytes.len()).unwrap().unwrap(), bytes);
}

#[test]
fn stable_bounded_sidecar_read_charges_original_commit_marker_before_decode() {
    const PROBE_LIMIT: usize = 1024 * 1024;

    let root = tempfile::tempdir().expect("create bounded-marker root");
    let mut store = super::BlockStore::new(root.path());
    store.create_files_if_they_do_not_exist().unwrap();
    let raw_length = std::fs::metadata(store.commit_marker_path()).unwrap().len();
    let limits =
        |allocation| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64);
    norito::with_decode_limits_scope(limits(0), || {
        assert!(matches!(
            store.read_exact_durable_index_count(),
            Err(super::Error::NoritoFrame(norito::Error::TotalAllocationExceeded {
                attempted,
                limit: 0,
            })) if attempted == raw_length
        ));
    });
    // Measure the real typed marker decoder as well as its raw frame. The test must not
    // invent the current codec's allocation cost or reset the inherited budget per read.
    let exact = norito::with_decode_limits_scope(limits(PROBE_LIMIT), || {
        assert_eq!(store.read_exact_durable_index_count().unwrap(), 0);
        let error = norito::core::reserve_decode_allocation(PROBE_LIMIT).unwrap_err();
        let norito::Error::TotalAllocationExceeded { attempted, limit } = error else {
            panic!("original cumulative allocation refusal");
        };
        usize::try_from(attempted - limit).unwrap()
    });
    assert!(exact >= usize::try_from(raw_length).unwrap());
    norito::with_decode_limits_scope(limits(exact * 2), || {
        assert_eq!(store.read_exact_durable_index_count().unwrap(), 0);
        assert_eq!(store.read_exact_durable_index_count().unwrap(), 0);
        assert!(matches!(
            store.read_exact_durable_index_count(),
            Err(super::Error::NoritoFrame(
                norito::Error::TotalAllocationExceeded { .. }
            ))
        ));
    });
    norito::with_decode_limits_scope(limits(exact - 1), || {
        assert!(matches!(
            store.read_exact_durable_index_count(),
            Err(super::Error::NoritoFrame(
                norito::Error::TotalAllocationExceeded { .. }
            ))
        ));
    });
    assert_eq!(store.read_exact_durable_index_count().unwrap(), 0);
}

#[test]
fn stable_bounded_sidecar_read_rejects_post_admission_regular_replacement() {
    let root = tempfile::tempdir().expect("create bounded-read root");
    let path = root.path().join("bounded.norito");
    let original = root.path().join("original.norito");
    let bytes = [7_u8; 8];
    std::fs::write(&path, bytes).expect("write admitted sidecar");
    let error = super::Kura::read_regular_sidecar_snapshot_for_with_admission_hook(
        root.path(),
        &path,
        root.path(),
        bytes.len(),
        || {
            std::fs::rename(&path, &original).expect("retain original inode");
            std::fs::write(&path, bytes).expect("replace with equal bytes on a different inode");
        },
    )
    .expect_err("equal replacement bytes cannot replace the admitted file identity");
    assert!(matches!(
        error,
        super::Error::IO(ref source, _) if source.kind() == std::io::ErrorKind::InvalidData
    ));
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&original, &path).unwrap();
    assert_eq!(
        super::Kura::read_regular_sidecar_bytes_for(root.path(), &path, root.path(), bytes.len())
            .unwrap()
            .unwrap(),
        bytes
    );
}

#[cfg(unix)]
#[test]
fn stable_bounded_sidecar_read_refuses_post_admission_symlink_before_read() {
    let root = tempfile::tempdir().expect("create bounded-read root");
    let path = root.path().join("bounded.norito");
    let original = root.path().join("original.norito");
    let bytes = [7_u8; 8];
    std::fs::write(&path, bytes).expect("write admitted sidecar");
    let error = super::Kura::read_regular_sidecar_snapshot_for_with_admission_hook(
        root.path(),
        &path,
        root.path(),
        bytes.len(),
        || {
            std::fs::rename(&path, &original).expect("retain original inode");
            std::os::unix::fs::symlink(&original, &path).expect("substitute link to original");
        },
    )
    .expect_err("even a link to the original inode must be refused at open");
    assert!(matches!(
        error,
        super::Error::IO(ref source, _)
            if source.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error())
    ));
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&original, &path).unwrap();
    assert_eq!(
        super::Kura::read_regular_sidecar_bytes_for(root.path(), &path, root.path(), bytes.len())
            .unwrap()
            .unwrap(),
        bytes
    );
}

#[cfg(unix)]
#[test]
fn stable_bounded_sidecar_read_refuses_post_admission_fifo_without_a_writer() {
    use std::{os::unix::fs::OpenOptionsExt as _, sync::mpsc, time::Duration};

    let root = tempfile::tempdir().expect("create bounded-read root");
    let path = root.path().join("bounded.norito");
    let original = root.path().join("original.norito");
    let bytes = [7_u8; 8];
    std::fs::write(&path, bytes).expect("write admitted sidecar");
    let (admitted_send, admitted_receive) = mpsc::sync_channel(1);
    let (result_send, result_receive) = mpsc::sync_channel(1);
    let reader_root = root.path().to_path_buf();
    let reader_path = path.clone();
    let reader_original = original.clone();
    let reader = std::thread::spawn(move || {
        let result = super::Kura::read_regular_sidecar_snapshot_for_with_admission_hook(
            &reader_root,
            &reader_path,
            &reader_root,
            bytes.len(),
            || {
                std::fs::rename(&reader_path, &reader_original).unwrap();
                let status = std::process::Command::new("mkfifo")
                    .arg(&reader_path)
                    .status()
                    .expect("create post-admission FIFO");
                assert!(status.success());
                admitted_send.send(()).unwrap();
            },
        );
        let refused_regular_open = matches!(
            result,
            Err(super::Error::IO(ref source, _))
                if source.kind() == std::io::ErrorKind::InvalidInput
        );
        result_send.send(refused_regular_open).unwrap();
    });
    admitted_receive
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    let early = result_receive.recv_timeout(Duration::from_secs(2));
    // Keep the regression finite against the old blocking File::open: only after observing
    // its failure to finish without a writer, release that open and join the original reader.
    let release = if matches!(early, Err(mpsc::RecvTimeoutError::Timeout)) {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(i32::try_from(rustix::fs::OFlags::NONBLOCK.bits()).unwrap())
            .open(&path)
            .expect("release an old blocked FIFO open for bounded regression cleanup");
        result_receive.recv_timeout(Duration::from_secs(5)).unwrap();
        Some(file)
    } else {
        None
    };
    reader.join().unwrap();
    drop(release);
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&original, &path).unwrap();
    assert_eq!(
        super::Kura::read_regular_sidecar_bytes_for(root.path(), &path, root.path(), bytes.len())
            .unwrap()
            .unwrap(),
        bytes
    );
    assert_eq!(early, Ok(true), "FIFO must be refused without any writer");
}
