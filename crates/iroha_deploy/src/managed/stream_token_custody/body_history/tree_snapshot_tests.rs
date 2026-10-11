//! Fresh ordered snapshot reads share only borrowed ancestry, never source or codec verdicts.

use super::*;
use crate::managed::Error;
use std::io;

fn observed(directory: &Arc<PrivateDirectory>, name: &str, maximum: usize) -> RecordSnapshot {
    let bytes = read_optional(directory, name, maximum).unwrap();
    RecordSnapshot::from_read(Arc::clone(directory), name, maximum, bytes.as_deref())
}

// These native files exercise snapshot byte custody, not protocol/signature admission.
struct Store {
    _temporary: tempfile::TempDir,
    root: Arc<PrivateDirectory>,
    container: Arc<PrivateDirectory>,
    first: Arc<PrivateDirectory>,
    reference: Arc<PrivateDirectory>,
    snapshot: Arc<Snapshot>,
}
impl Store {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root =
            Arc::new(PrivateDirectory::open_or_create(temporary.path().join("purpose")).unwrap());
        root.write_atomic("original.nrt", b"original", PublishMode::CreateNew)
            .unwrap();
        root.write_atomic("anchor.nrt", b"anchor", PublishMode::CreateNew)
            .unwrap();
        let epochs = root.create_child("epochs").unwrap();
        drop(epochs);
        let container = Arc::new(root.create_child("bodies").unwrap());
        let reference =
            Arc::new(PrivateDirectory::open_or_create(temporary.path().join("authority")).unwrap());
        reference
            .write_atomic("enroll-selection.nrt", b"reference", PublishMode::CreateNew)
            .unwrap();
        let base = Arc::new(Snapshot {
            previous: None,
            records: vec![
                observed(&root, "original.nrt", MAX_SELECTION_BYTES),
                observed(&root, "anchor.nrt", MAX_BODY_BYTES),
                observed(&reference, "enroll-selection.nrt", MAX_SELECTION_BYTES),
            ],
            names: Vec::new(),
            root: Some(Arc::clone(&root)),
        });
        let mut rows = Vec::new();
        for ordinal in 1..=2_u8 {
            let row = Arc::new(container.create_child(body_name(ordinal).unwrap()).unwrap());
            row.write_atomic("reserved.nrt", b"reserved", PublishMode::CreateNew)
                .unwrap();
            rows.push(row);
        }
        let mut snapshot = Arc::new(Snapshot {
            previous: Some(base),
            records: Vec::new(),
            names: vec![NamesSnapshot::from_read(
                Arc::clone(&container),
                usize::from(MAX_BODIES) * 3,
                container.entries(usize::from(MAX_BODIES) * 3).unwrap(),
            )],
            root: None,
        });
        for (index, row) in rows.iter().enumerate() {
            let name = body_name(u8::try_from(index + 1).unwrap()).unwrap();
            snapshot = Arc::new(Snapshot {
                previous: Some(snapshot),
                records: vec![
                    observed(row, "reserved.nrt", MAX_BODY_BYTES),
                    observed(row, "original.nrt", journal::MAX_ORIGINAL_BYTES),
                    observed(
                        &container,
                        &format!("{name}-activation.nrt"),
                        MAX_SELECTION_BYTES,
                    ),
                    observed(
                        &container,
                        &format!("{name}-unused.nrt"),
                        MAX_SELECTION_BYTES,
                    ),
                ],
                names: vec![NamesSnapshot::from_read(
                    Arc::clone(row),
                    1,
                    row.entries(1).unwrap(),
                )],
                root: None,
            });
        }
        Self {
            _temporary: temporary,
            root,
            container,
            first: Arc::clone(&rows[0]),
            reference,
            snapshot,
        }
    }
}

#[test]
fn generated_paid_body_snapshots_reject_changed_original_and_reference_then_retry_same_sources() {
    use crate::managed::stream_token_custody::renewal_tests::Fixture;
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(60_000);
    let history = BodyHistory::open(&fixture.owner, CustodyPurpose::InitialEnroll)
        .unwrap()
        .unwrap();
    assert_eq!(history.bodies.len(), 1);
    let body = &history.bodies[0];
    let snapshot = &body.snapshots;
    assert!(snapshot.tree_root().is_some());
    snapshot.revalidate().unwrap();
    snapshot.revalidate_in_tree(None).unwrap();
    let original = body
        .directory
        .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
        .unwrap();
    let reservation = body.directory.read("reserved.nrt", MAX_BODY_BYTES).unwrap();
    let mut changed = original.to_vec();
    changed[0] ^= 1;
    body.directory
        .write_atomic("original.nrt", &changed, PublishMode::Replace)
        .unwrap();
    assert!(
        matches!(snapshot.revalidate(), Err(Error::Invalid(message)) if message == "retained enrollment body material changed")
    );
    assert!(
        matches!(snapshot.revalidate_in_tree(None), Err(Error::Invalid(message)) if message == "retained enrollment body material changed")
    );
    body.directory
        .write_atomic("original.nrt", &original, PublishMode::Replace)
        .unwrap();
    snapshot.revalidate().unwrap();
    let reference = &history.root_snapshots.records[2];
    assert!(!Arc::ptr_eq(&reference.directory, &history.root));
    let reference_bytes = reference
        .directory
        .read(&reference.name, reference.maximum)
        .unwrap();
    let held = reference.directory.path().join("held-selection");
    std::fs::rename(reference.directory.path().join(&reference.name), &held).unwrap();
    assert!(
        matches!(snapshot.revalidate(), Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound)
    );
    std::fs::rename(&held, reference.directory.path().join(&reference.name)).unwrap();
    snapshot.revalidate().unwrap();
    assert_eq!(
        reference
            .directory
            .read(&reference.name, reference.maximum)
            .unwrap(),
        reference_bytes
    );
    assert_eq!(
        body.directory.read("reserved.nrt", MAX_BODY_BYTES).unwrap(),
        reservation
    );
    assert_eq!(
        body.directory
            .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap(),
        original
    );
    let restored = BodyHistory::open(&fixture.owner, CustodyPurpose::InitialEnroll)
        .unwrap()
        .unwrap();
    restored.bodies[0].snapshots.revalidate().unwrap();
    assert_eq!(restored.bodies.len(), 1);
    assert_eq!(restored.anchor.highest, history.anchor.highest);
}

#[test]
fn snapshot_tree_keeps_inventory_hash_absence_order_and_late_active_codec_limits() {
    let store = Store::new();
    assert!(store.snapshot.tree_root().is_some());
    store.snapshot.revalidate().unwrap();
    store.snapshot.revalidate_in_tree(None).unwrap();
    store
        .first
        .write_atomic("reserved.nrt", b"modified", PublishMode::Replace)
        .unwrap();
    let second = &store.snapshot.records[0].directory;
    let held_second = store._temporary.path().join("held-second-reservation");
    std::fs::rename(second.path().join("reserved.nrt"), &held_second).unwrap();
    // The previous row's real hash refusal must precede the later row's real missing leaf.
    assert!(
        matches!(store.snapshot.revalidate(), Err(Error::Invalid(message)) if message == "retained enrollment body material changed")
    );
    store
        .first
        .write_atomic("reserved.nrt", b"reserved", PublishMode::Replace)
        .unwrap();
    assert!(
        matches!(store.snapshot.revalidate(), Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound)
    );
    std::fs::rename(&held_second, second.path().join("reserved.nrt")).unwrap();
    store.snapshot.revalidate().unwrap();
    store
        .container
        .write_atomic("0001-activation.nrt", b"appeared", PublishMode::CreateNew)
        .unwrap();
    // Container inventory precedes body records, retaining the original first refusal.
    assert!(
        matches!(store.snapshot.revalidate(), Err(Error::Invalid(message)) if message == "retained enrollment namespace changed")
    );
    std::fs::remove_file(store.container.path().join("0001-activation.nrt")).unwrap();
    store
        .first
        .write_atomic("original.nrt", b"appeared", PublishMode::CreateNew)
        .unwrap();
    assert!(
        matches!(store.snapshot.revalidate(), Err(Error::Invalid(message)) if message == "retained enrollment body material changed")
    );
    std::fs::remove_file(store.first.path().join("original.nrt")).unwrap();
    let held = store.first.path().join("held");
    std::fs::rename(store.first.path().join("reserved.nrt"), &held).unwrap();
    assert!(
        matches!(store.snapshot.revalidate(), Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound)
    );
    std::fs::rename(&held, store.first.path().join("reserved.nrt")).unwrap();
    let extra = store.container.create_child("0003").unwrap();
    drop(extra);
    assert!(
        matches!(store.snapshot.revalidate(), Err(Error::Invalid(message)) if message == "retained enrollment namespace changed")
    );
    std::fs::remove_dir(store.container.path().join("0003")).unwrap();
    store.snapshot.revalidate().unwrap();
    let encoded = encode(&vec![7_u8; 32], MAX_BODY_BYTES).unwrap();
    for allocation in [0, 1] {
        let limits = norito::DecodeLimits::new(
            MAX_BODY_BYTES,
            MAX_BODY_BYTES,
            MAX_BODY_BYTES,
            allocation,
            48,
        );
        let result = norito::core::with_decode_limits_scope(limits, || {
            store.snapshot.revalidate().unwrap();
            decode::<Vec<u8>>(&encoded, MAX_BODY_BYTES)
        });
        assert!(
            matches!(result, Err(Error::Invalid(message)) if message == "invalid canonical enrollment body record")
        );
    }
    let wide = norito::DecodeLimits::new(
        MAX_BODY_BYTES,
        MAX_BODY_BYTES,
        MAX_BODY_BYTES,
        96 * 1024 * 1024,
        48,
    );
    assert_eq!(
        norito::core::with_decode_limits_scope(wide, || {
            store.snapshot.revalidate().unwrap();
            decode::<Vec<u8>>(&encoded, MAX_BODY_BYTES)
        })
        .unwrap(),
        vec![7_u8; 32]
    );
    let one = norito::DecodeLimits::new(MAX_BODY_BYTES, MAX_BODY_BYTES, MAX_BODY_BYTES, 1, 48);
    norito::core::with_decode_limits_scope(one, || {
        norito::core::reserve_decode_allocation(1).unwrap();
        store.snapshot.revalidate().unwrap();
        assert!(norito::core::reserve_decode_allocation(1).is_err());
    });
    store.snapshot.revalidate().unwrap();
    assert_eq!(
        store
            .first
            .read("reserved.nrt", MAX_BODY_BYTES)
            .unwrap()
            .as_slice(),
        b"reserved"
    );
}

#[test]
fn snapshot_tree_eligibility_keeps_rootless_custom_multiple_root_and_singleton_fallbacks() {
    let store = Store::new();
    let rootless = Snapshot {
        previous: None,
        records: vec![observed(
            &store.reference,
            "enroll-selection.nrt",
            MAX_SELECTION_BYTES,
        )],
        names: Vec::new(),
        root: None,
    };
    assert!(rootless.tree_root().is_none());
    rootless.revalidate().unwrap();
    let custom = Snapshot {
        previous: Some(Arc::clone(&store.snapshot)),
        records: vec![observed(&store.first, "reserved.nrt", MAX_BODY_BYTES)],
        names: Vec::new(),
        root: None,
    };
    assert!(custom.tree_root().is_none());
    custom.revalidate().unwrap();
    let multiple = Snapshot {
        previous: Some(Arc::clone(&store.snapshot)),
        records: Vec::new(),
        names: Vec::new(),
        root: Some(Arc::clone(&store.root)),
    };
    assert!(multiple.tree_root().is_none());
    multiple.revalidate().unwrap();
    store
        .first
        .write_atomic("reserved.nrt", b"modified", PublishMode::Replace)
        .unwrap();
    for snapshot in [&custom, &multiple] {
        assert!(
            matches!(snapshot.revalidate(), Err(Error::Invalid(message)) if message == "retained enrollment body material changed")
        );
    }
    store
        .first
        .write_atomic("reserved.nrt", b"reserved", PublishMode::Replace)
        .unwrap();
    store
        .reference
        .write_atomic("enroll-selection.nrt", b"different", PublishMode::Replace)
        .unwrap();
    assert!(
        matches!(rootless.revalidate(), Err(Error::Invalid(message)) if message == "retained enrollment body material changed")
    );
    store
        .reference
        .write_atomic("enroll-selection.nrt", b"reference", PublishMode::Replace)
        .unwrap();
    rootless.revalidate().unwrap();
    custom.revalidate().unwrap();
    multiple.revalidate().unwrap();
    assert_eq!(store.root.entries(4).unwrap().len(), 4);
}

#[cfg(unix)]
#[test]
fn snapshot_tree_exit_overrides_real_body_results_and_restores_original_ancestor_and_suffix() {
    use std::{fs, os::unix::fs::PermissionsExt as _};
    for body in ["accepted_absence", "hash_refusal", "missing_required"] {
        let store = Store::new();
        let held = store.root.path().join("held-anchor");
        if body == "hash_refusal" {
            store
                .first
                .write_atomic("reserved.nrt", b"modified", PublishMode::Replace)
                .unwrap();
        } else if body == "missing_required" {
            // Move outside the root census so the real original leaf read reaches NotFound.
            fs::rename(store.root.path().join("anchor.nrt"), &held).unwrap();
            fs::rename(&held, store._temporary.path().join("held-anchor")).unwrap();
        }
        let refused = store.root.read_tree_scope(|tree| {
            let result = store.snapshot.revalidate_in_tree(Some(tree));
            match body {
                "accepted_absence" => assert!(result.is_ok()),
                "hash_refusal" => assert!(matches!(&result, Err(Error::Invalid(message)) if *message == "retained enrollment body material changed")),
                "missing_required" => assert!(matches!(&result, Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound)),
                _ => unreachable!(),
            }
            fs::set_permissions(store.root.path(), fs::Permissions::from_mode(0o755)).unwrap();
            result
        });
        assert!(
            matches!(refused, Err(Error::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        fs::set_permissions(store.root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        if body == "hash_refusal" {
            store
                .first
                .write_atomic("reserved.nrt", b"reserved", PublishMode::Replace)
                .unwrap();
        } else if body == "missing_required" {
            fs::rename(
                store._temporary.path().join("held-anchor"),
                store.root.path().join("anchor.nrt"),
            )
            .unwrap();
        }
        store.snapshot.revalidate().unwrap();
        let identity = store.first.identity().unwrap();
        fs::set_permissions(store.first.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            matches!(store.snapshot.revalidate(), Err(Error::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        fs::set_permissions(store.first.path(), fs::Permissions::from_mode(0o700)).unwrap();
        store.snapshot.revalidate().unwrap();
        assert_eq!(store.first.identity().unwrap(), identity);
    }
    let store = Store::new();
    store.root.read_tree_scope(|tree| {
        // The root's own full checks and external singleton must still see current custody.
        fs::set_permissions(store.reference.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let result = store.snapshot.revalidate_in_tree(Some(tree));
        assert!(matches!(result, Err(Error::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied));
        fs::set_permissions(store.reference.path(), fs::Permissions::from_mode(0o700)).unwrap();
        store.snapshot.revalidate_in_tree(Some(tree))
    }).unwrap();
    store
        .root
        .read_tree_scope(|tree| {
            store.snapshot.revalidate_in_tree(Some(tree))?;
            fs::set_permissions(store.root.path(), fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(
                store.root.revalidate().unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            fs::set_permissions(store.root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            Ok::<_, Error>(())
        })
        .unwrap();
    // Fully restored common-prefix changes inside the bracket have the documented temporal limit.
    store.snapshot.revalidate().unwrap();
}

#[test]
fn snapshot_closed_reader_keeps_native_count_bound_equal_count_census_and_original_retry() {
    let store = Store::new();
    assert!(store.snapshot.tree_root().is_some());
    let original = store.first.read("reserved.nrt", MAX_BODY_BYTES).unwrap();
    store
        .first
        .write_atomic("extra.nrt", b"extra", PublishMode::CreateNew)
        .unwrap();
    let native = store.first.entries(1).unwrap_err();
    assert_eq!(native.kind(), io::ErrorKind::InvalidInput);
    for result in [
        store.snapshot.revalidate(),
        store.snapshot.revalidate_in_tree(None),
    ] {
        match result {
            Err(Error::Io(error)) => {
                assert_eq!(error.kind(), native.kind());
                assert_eq!(error.to_string(), native.to_string());
            }
            other => panic!("native inventory cap refusal changed: {other:?}"),
        }
    }
    std::fs::remove_file(store.first.path().join("extra.nrt")).unwrap();
    store.snapshot.revalidate().unwrap();
    #[cfg(unix)]
    {
        let first_name = body_name(1).unwrap();
        let moved = store.container.path().join("different-body");
        // Keep the count unchanged. The earlier container census must still reject these names
        // before a later body's retained suffix or required record is visited.
        std::fs::rename(store.first.path(), &moved).unwrap();
        for result in [
            store.snapshot.revalidate(),
            store.snapshot.revalidate_in_tree(None),
        ] {
            assert!(
                matches!(result, Err(Error::Invalid(message)) if message == "retained enrollment namespace changed")
            );
        }
        std::fs::rename(&moved, store.container.path().join(first_name)).unwrap();
    }
    #[cfg(windows)]
    {
        let moved = store.container.path().join("different-body");
        // Retained native directory handles deny DELETE sharing on Windows.
        assert!(std::fs::rename(store.first.path(), &moved).is_err());
        assert!(!moved.exists());
    }
    store.snapshot.revalidate().unwrap();
    store.snapshot.revalidate_in_tree(None).unwrap();
    assert_eq!(
        store.first.read("reserved.nrt", MAX_BODY_BYTES).unwrap(),
        original
    );
}

#[cfg(unix)]
#[test]
fn snapshot_closed_reader_suffix_exit_keeps_typed_body_refusal_and_restored_boundary() {
    use std::{fs, os::unix::fs::PermissionsExt as _};
    let store = Store::new();
    let first = &store.snapshot.previous.as_ref().unwrap().records[0];
    assert!(Arc::ptr_eq(&first.directory, &store.first));
    let failure = store
        .root
        .read_tree_scope(|tree| {
            tree.read_scope(&store.first, |reader| {
                first.revalidate_in_scope(reader)?;
                fs::set_permissions(store.first.path(), fs::Permissions::from_mode(0o755)).unwrap();
                Err::<(), _>(invalid("typed snapshot consumer refusal"))
            })
        })
        .unwrap_err();
    assert!(matches!(failure, Error::Io(error) if error.kind() == io::ErrorKind::PermissionDenied));
    fs::set_permissions(store.first.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let typed = store
        .root
        .read_tree_scope(|tree| {
            tree.read_scope(&store.first, |reader| {
                first.revalidate_in_scope(reader)?;
                Err::<(), _>(invalid("typed snapshot consumer refusal"))
            })
        })
        .unwrap_err();
    assert!(
        matches!(typed, Error::Invalid(message) if message == "typed snapshot consumer refusal")
    );
    store
        .root
        .read_tree_scope(|tree| {
            tree.read_scope(&store.first, |reader| {
                fs::set_permissions(store.first.path(), fs::Permissions::from_mode(0o755)).unwrap();
                assert_eq!(
                    store.first.revalidate().unwrap_err().kind(),
                    io::ErrorKind::PermissionDenied
                );
                first.revalidate_in_scope(reader)?;
                fs::set_permissions(store.first.path(), fs::Permissions::from_mode(0o700)).unwrap();
                // This fully restored intermediate suffix change has the documented endpoint limit.
                Ok::<_, Error>(())
            })
        })
        .unwrap();
    store.snapshot.revalidate().unwrap();
    store.snapshot.revalidate_in_tree(None).unwrap();
}
