//! Exact ordered snapshot hashes and absence under lazy closed native read scopes.

use super::*;
use crate::managed::Error;
use std::io;

fn directory() -> (tempfile::TempDir, Arc<PrivateDirectory>) {
    let temporary = tempfile::tempdir().unwrap();
    let directory =
        Arc::new(PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap());
    (temporary, directory)
}

fn record(directory: &Arc<PrivateDirectory>, name: &str, maximum: usize) -> RecordSnapshot {
    let bytes = read_optional(directory, name, maximum).unwrap();
    RecordSnapshot::from_read(Arc::clone(directory), name, maximum, bytes.as_deref())
}

fn snapshot(records: Vec<RecordSnapshot>) -> Snapshot {
    Snapshot {
        previous: None,
        records,
        names: Vec::new(),
        root: None,
    }
}

#[test]
fn contiguous_snapshot_reads_keep_first_hash_refusal_absence_extent_and_original_retry() {
    let (_temporary, directory) = directory();
    directory
        .write_atomic("first.nrt", b"first", PublishMode::CreateNew)
        .unwrap();
    directory
        .write_atomic("second.nrt", b"second", PublishMode::CreateNew)
        .unwrap();
    let original = snapshot(vec![
        record(&directory, "first.nrt", 5),
        record(&directory, "second.nrt", 6),
        record(&directory, "missing.nrt", 4),
    ]);
    original.revalidate().unwrap();
    directory
        .write_atomic("first.nrt", b"other", PublishMode::Replace)
        .unwrap();
    directory
        .write_atomic("second.nrt", b"oversized", PublishMode::Replace)
        .unwrap();
    assert!(
        matches!(original.revalidate(), Err(Error::Invalid(message)) if message == "retained enrollment body material changed")
    );
    directory
        .write_atomic("first.nrt", b"first", PublishMode::Replace)
        .unwrap();
    assert!(
        matches!(original.revalidate(), Err(Error::Io(error)) if error.kind() == io::ErrorKind::InvalidInput)
    );
    directory
        .write_atomic("second.nrt", b"second", PublishMode::Replace)
        .unwrap();
    original.revalidate().unwrap();
    directory
        .write_atomic("missing.nrt", b"new", PublishMode::CreateNew)
        .unwrap();
    assert!(
        matches!(original.revalidate(), Err(Error::Invalid(message)) if message == "retained enrollment body material changed")
    );
    std::fs::remove_file(directory.path().join("missing.nrt")).unwrap();
    let saved = directory.path().join("saved.nrt");
    std::fs::rename(directory.path().join("second.nrt"), &saved).unwrap();
    assert!(
        matches!(original.revalidate(), Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound)
    );
    std::fs::rename(&saved, directory.path().join("second.nrt")).unwrap();
    original.revalidate().unwrap();
    assert_eq!(directory.read("first.nrt", 5).unwrap().as_slice(), b"first");
    assert_eq!(
        directory.read("second.nrt", 6).unwrap().as_slice(),
        b"second"
    );
}

#[test]
fn snapshot_grouping_preserves_previous_chain_and_noncontiguous_original_owner_order() {
    let (_temporary, first) = directory();
    let (_other_temporary, second) = directory();
    first
        .write_atomic("first.nrt", b"first", PublishMode::CreateNew)
        .unwrap();
    first
        .write_atomic("last.nrt", b"last", PublishMode::CreateNew)
        .unwrap();
    second
        .write_atomic("middle.nrt", b"middle", PublishMode::CreateNew)
        .unwrap();
    let previous = Arc::new(snapshot(vec![
        record(&first, "first.nrt", 5),
        record(&first, "absent.nrt", 0),
    ]));
    let current = Snapshot {
        previous: Some(Arc::clone(&previous)),
        records: vec![
            record(&first, "first.nrt", 5),
            record(&second, "middle.nrt", 6),
            record(&first, "last.nrt", 4),
            record(&first, "missing.nrt", 0),
        ],
        names: vec![NamesSnapshot::from_read(
            Arc::clone(&first),
            2,
            first.entries(2).unwrap(),
        )],
        root: None,
    };
    current.revalidate().unwrap();
    first
        .write_atomic("first.nrt", b"other", PublishMode::Replace)
        .unwrap();
    second
        .write_atomic("middle.nrt", b"oversized", PublishMode::Replace)
        .unwrap();
    assert!(
        matches!(current.revalidate(), Err(Error::Invalid(message)) if message == "retained enrollment body material changed")
    );
    first
        .write_atomic("first.nrt", b"first", PublishMode::Replace)
        .unwrap();
    assert!(
        matches!(current.revalidate(), Err(Error::Io(error)) if error.kind() == io::ErrorKind::InvalidInput)
    );
    second
        .write_atomic("middle.nrt", b"middle", PublishMode::Replace)
        .unwrap();
    first
        .write_atomic("last.nrt", b"lost", PublishMode::Replace)
        .unwrap();
    assert!(
        matches!(current.revalidate(), Err(Error::Invalid(message)) if message == "retained enrollment body material changed")
    );
    first
        .write_atomic("last.nrt", b"last", PublishMode::Replace)
        .unwrap();
    current.revalidate().unwrap();
    assert_eq!(first.entries(2).unwrap().len(), 2);
    assert_eq!(second.entries(1).unwrap().len(), 1);
}

#[cfg(unix)]
#[test]
fn snapshot_scoped_absence_and_hash_failure_do_not_mask_exit_native_refusal() {
    use std::{fs, os::unix::fs::PermissionsExt as _};
    let (_temporary, directory) = directory();
    directory
        .write_atomic("first.nrt", b"first", PublishMode::CreateNew)
        .unwrap();
    let original = record(&directory, "first.nrt", 5);
    let absent = record(&directory, "missing.nrt", 0);
    for body in ["absence", "hash_failure"] {
        if body == "hash_failure" {
            directory
                .write_atomic("first.nrt", b"other", PublishMode::Replace)
                .unwrap();
        }
        let refused = directory.read_scope(|reader| {
            let result = if body == "absence" { absent.revalidate_in_scope(reader) } else { original.revalidate_in_scope(reader) };
            if body == "absence" {
                assert!(result.is_ok());
            } else {
                assert!(matches!(&result, Err(Error::Invalid(message)) if message == "retained enrollment body material changed"));
            }
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
            result
        });
        assert!(
            matches!(refused, Err(Error::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        if body == "hash_failure" {
            directory
                .write_atomic("first.nrt", b"first", PublishMode::Replace)
                .unwrap();
        }
        directory
            .read_scope(|reader| {
                original.revalidate_in_scope(reader)?;
                absent.revalidate_in_scope(reader)
            })
            .unwrap();
    }
    snapshot(vec![original, absent]).revalidate().unwrap();
}
