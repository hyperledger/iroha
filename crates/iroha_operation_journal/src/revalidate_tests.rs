//! Real directory and original-lock custody at the fixed-name revalidation boundary.

use super::*;
use std::{cell::Cell, fs, io, os::unix::fs::PermissionsExt as _};

#[test]
fn revalidation_preserves_directory_error_precedence_original_lock_and_retry() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("journal");
    let request = norito::json!({"original": "retained-request", "deadline_ms": 17});
    let journal = Journal::create_preparation(&path, &request).unwrap();
    let directory_identity = journal.directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&journal.lock).unwrap();
    let request_bytes = fs::read(path.join("preparation.json")).unwrap();
    let lock_path = path.join("lock");
    let displaced_lock = path.join("displaced-lock");
    let scope_refusal = || {
        let called = Cell::new(false);
        let error = journal
            .read_native_scope(|_| {
                called.set(true);
                Ok(())
            })
            .unwrap_err();
        assert!(
            !called.get(),
            "unsafe custody must precede the read callback"
        );
        error
    };

    // A directory refusal must win before an otherwise missing-lock error.
    fs::rename(&lock_path, &displaced_lock).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let expected = journal.directory.revalidate().unwrap_err();
    assert_eq!(expected.kind(), io::ErrorKind::PermissionDenied);
    let direct = journal.revalidate().unwrap_err();
    let direct = direct.downcast_ref::<io::Error>().unwrap();
    assert_eq!(direct.kind(), expected.kind());
    assert_eq!(direct.to_string(), expected.to_string());
    let scoped = scope_refusal();
    let scoped = scoped.downcast_ref::<io::Error>().unwrap();
    assert_eq!(scoped.kind(), expected.kind());
    assert_eq!(scoped.to_string(), expected.to_string());

    // Restoring private directory custody exposes the genuine missing lock.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    journal.directory.revalidate().unwrap();
    assert_eq!(
        journal
            .revalidate()
            .unwrap_err()
            .downcast_ref::<io::Error>()
            .unwrap()
            .kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(
        scope_refusal().downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::NotFound
    );

    // A safe new lock file cannot replace the retained exclusive ownership file.
    let replacement = journal.directory.create_lock("lock").unwrap();
    assert_ne!(FileIdentity::of(&replacement).unwrap(), lock_identity);
    let expected = "journal lock no longer identifies the retained ownership file";
    assert_eq!(journal.revalidate().unwrap_err().to_string(), expected);
    assert_eq!(scope_refusal().to_string(), expected);
    drop(replacement);
    fs::remove_file(&lock_path).unwrap();
    fs::rename(&displaced_lock, &lock_path).unwrap();

    // Restoring that exact file admits the original bytes without releasing ownership.
    journal.revalidate().unwrap();
    assert_eq!(journal.directory.identity().unwrap(), directory_identity);
    assert_eq!(FileIdentity::of(&journal.lock).unwrap(), lock_identity);
    assert_eq!(
        fs::read(path.join("preparation.json")).unwrap(),
        request_bytes
    );
    assert_eq!(
        journal
            .read_native::<norito::json::Value>(NativeRecord::Request)
            .unwrap(),
        Some(request.clone())
    );
    assert_eq!(
        journal
            .read_native_scope(|read| {
                read.read_native::<norito::json::Value>(NativeRecord::Request)
            })
            .unwrap(),
        Some(request.clone())
    );
    assert!(Journal::open(&path).is_err());
    assert!(Journal::open_optional(&path).is_err());
    drop(journal);
    let reopened = Journal::open(&path).unwrap();
    assert_eq!(reopened.directory.identity().unwrap(), directory_identity);
    assert_eq!(FileIdentity::of(&reopened.lock).unwrap(), lock_identity);
    assert_eq!(
        reopened
            .read_native::<norito::json::Value>(NativeRecord::Request)
            .unwrap(),
        Some(request)
    );
    assert!(Journal::open(&path).is_err());
}
