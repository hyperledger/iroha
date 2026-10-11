//! Real native snapshot entry/exit custody, bounded reads and original-source retry controls.

use super::*;
use crate::managed::Error;
use std::io;

fn directory() -> (tempfile::TempDir, Arc<PrivateDirectory>) {
    let temporary = tempfile::tempdir().unwrap();
    let directory = Arc::new(
        PrivateDirectory::open_or_create(temporary.path().join("original-directory")).unwrap(),
    );
    (temporary, directory)
}

fn observed(directory: &Arc<PrivateDirectory>, name: &str, maximum: usize) -> RecordSnapshot {
    let bytes = read_optional(directory, name, maximum).unwrap();
    RecordSnapshot::from_read(Arc::clone(directory), name, maximum, bytes.as_deref())
}

fn io_kind(result: Result<()>) -> io::ErrorKind {
    match result {
        Err(Error::Io(error)) => error.kind(),
        Err(other) => panic!("expected original native I/O refusal, got {other}"),
        Ok(()) => panic!("expected original native I/O refusal"),
    }
}

#[test]
fn snapshot_entry_reads_preserve_material_absence_bounds_and_same_source_retry() {
    let (_temporary, directory) = directory();
    directory
        .write_atomic("record.nrt", b"original", PublishMode::CreateNew)
        .unwrap();
    let record = observed(&directory, "record.nrt", 8);
    let absent = observed(&directory, "absent.nrt", 8);
    let names = NamesSnapshot::from_read(Arc::clone(&directory), 2, directory.entries(2).unwrap());
    record.revalidate().unwrap();
    absent.revalidate().unwrap();
    names.revalidate().unwrap();

    directory
        .write_atomic("record.nrt", b"modified", PublishMode::Replace)
        .unwrap();
    assert!(matches!(record.revalidate(), Err(Error::Invalid(_))));
    directory
        .write_atomic("record.nrt", b"original", PublishMode::Replace)
        .unwrap();
    record.revalidate().unwrap();
    directory
        .write_atomic("record.nrt", b"oversized", PublishMode::Replace)
        .unwrap();
    assert_eq!(io_kind(record.revalidate()), io::ErrorKind::InvalidInput);
    directory
        .write_atomic("record.nrt", b"original", PublishMode::Replace)
        .unwrap();
    record.revalidate().unwrap();

    let held = directory.path().join("held.nrt");
    std::fs::rename(directory.path().join("record.nrt"), &held).unwrap();
    assert_eq!(io_kind(record.revalidate()), io::ErrorKind::NotFound);
    std::fs::rename(&held, directory.path().join("record.nrt")).unwrap();
    record.revalidate().unwrap();
    names.revalidate().unwrap();
    directory
        .write_atomic("absent.nrt", b"appeared", PublishMode::CreateNew)
        .unwrap();
    assert!(matches!(absent.revalidate(), Err(Error::Invalid(_))));
    assert!(matches!(names.revalidate(), Err(Error::Invalid(_))));
    std::fs::remove_file(directory.path().join("absent.nrt")).unwrap();
    absent.revalidate().unwrap();
    names.revalidate().unwrap();
    assert_eq!(
        directory.read("record.nrt", 8).unwrap().as_slice(),
        b"original"
    );
}

#[cfg(unix)]
#[test]
fn snapshot_entry_fences_refuse_unsafe_missing_replaced_and_linked_directory_custody() {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt as _, symlink},
    };

    let (temporary, directory) = directory();
    directory
        .write_atomic("record.nrt", b"original", PublishMode::CreateNew)
        .unwrap();
    let record = observed(&directory, "record.nrt", 8);
    let absent = observed(&directory, "absent.nrt", 8);
    let names = NamesSnapshot::from_read(Arc::clone(&directory), 2, directory.entries(2).unwrap());
    let original_identity = directory.identity().unwrap();
    let original_path = directory.path().to_owned();
    fs::set_permissions(&original_path, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        io_kind(record.revalidate()),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        io_kind(absent.revalidate()),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(io_kind(names.revalidate()), io::ErrorKind::PermissionDenied);
    fs::set_permissions(&original_path, fs::Permissions::from_mode(0o700)).unwrap();
    record.revalidate().unwrap();
    absent.revalidate().unwrap();
    names.revalidate().unwrap();

    let displaced = temporary.path().join("displaced-original");
    fs::rename(&original_path, &displaced).unwrap();
    // Missing directory custody must not become a successful optional-file
    // absence: read_optional independently revalidates its NotFound branch.
    assert_eq!(io_kind(record.revalidate()), io::ErrorKind::NotFound);
    assert_eq!(io_kind(absent.revalidate()), io::ErrorKind::NotFound);
    assert_eq!(io_kind(names.revalidate()), io::ErrorKind::NotFound);
    fs::create_dir(&original_path).unwrap();
    fs::set_permissions(&original_path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(original_path.join("record.nrt"), b"original").unwrap();
    fs::set_permissions(
        original_path.join("record.nrt"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    // The replacement has equal names/bytes and safe modes, but it is not the
    // live original directory retained by any of these three snapshots.
    assert_eq!(io_kind(record.revalidate()), io::ErrorKind::Other);
    assert_eq!(io_kind(absent.revalidate()), io::ErrorKind::Other);
    assert_eq!(io_kind(names.revalidate()), io::ErrorKind::Other);
    assert!(!original_path.join("absent.nrt").exists());
    assert!(!displaced.join("absent.nrt").exists());
    fs::remove_file(original_path.join("record.nrt")).unwrap();
    fs::remove_dir(&original_path).unwrap();
    symlink(&displaced, &original_path).unwrap();
    assert!(record.revalidate().is_err());
    assert!(absent.revalidate().is_err());
    assert!(names.revalidate().is_err());
    fs::remove_file(&original_path).unwrap();
    fs::rename(&displaced, &original_path).unwrap();
    record.revalidate().unwrap();
    absent.revalidate().unwrap();
    names.revalidate().unwrap();
    assert_eq!(directory.identity().unwrap(), original_identity);
    assert_eq!(directory.entries(2).unwrap(), names.names);
    assert_eq!(
        directory.read("record.nrt", 8).unwrap().as_slice(),
        b"original"
    );
}
