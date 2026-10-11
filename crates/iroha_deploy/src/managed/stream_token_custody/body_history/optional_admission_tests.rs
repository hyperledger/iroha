//! Optional snapshot absence remains distinct from required-record and native custody failures.

use super::*;
use crate::managed::Error;

#[test]
fn record_snapshot_optional_admission_keeps_original_absence_hash_and_required_error_order() {
    let temporary = tempfile::tempdir().unwrap();
    let directory =
        Arc::new(PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap());
    let absent = RecordSnapshot::from_read(Arc::clone(&directory), "record", 8, None);
    directory
        .read_scope(|reader| absent.revalidate_in_scope(reader))
        .unwrap();
    directory
        .write_atomic("record", b"original", PublishMode::CreateNew)
        .unwrap();
    assert!(
        matches!(directory.read_scope(|reader| absent.revalidate_in_scope(reader)), Err(Error::Invalid(message)) if message == "retained enrollment body material changed")
    );
    let present = RecordSnapshot::from_read(Arc::clone(&directory), "record", 8, Some(b"original"));
    directory
        .read_scope(|reader| present.revalidate_in_scope(reader))
        .unwrap();
    let saved = directory.path().join("saved");
    std::fs::rename(directory.path().join("record"), &saved).unwrap();
    assert!(
        matches!(directory.read_scope(|reader| present.revalidate_in_scope(reader)), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
    );
    directory
        .read_scope(|reader| absent.revalidate_in_scope(reader))
        .unwrap();
    std::fs::rename(saved, directory.path().join("record")).unwrap();
    directory
        .read_scope(|reader| present.revalidate_in_scope(reader))
        .unwrap();
    assert_eq!(directory.read("record", 8).unwrap().as_slice(), b"original");
}
