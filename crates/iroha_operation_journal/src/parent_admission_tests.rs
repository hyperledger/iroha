//! Original journal lock and typed optional admission through one retained parent.

use super::*;
use std::{ffi::OsStr, fs};

#[test]
fn optional_journal_keeps_initial_absence_original_bytes_exclusive_lock_and_missing_lock_refusal() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("journal");
    assert!(Journal::open_optional(&path).unwrap().is_none());
    assert!(!path.exists());
    let request = norito::json!({"original": true, "deadline_ms": 17});
    let original = Journal::create_preparation(&path, &request).unwrap();
    let directory_identity = original.directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&original.lock).unwrap();
    assert!(Journal::open_optional(&path).is_err());
    assert!(Journal::open(&path).is_err());
    drop(original);
    for optional in [false, true] {
        let selected = if optional {
            Journal::open_optional(&path).unwrap().unwrap()
        } else {
            Journal::open(&path).unwrap()
        };
        assert_eq!(selected.directory.identity().unwrap(), directory_identity);
        assert_eq!(FileIdentity::of(&selected.lock).unwrap(), lock_identity);
        assert_eq!(
            selected
                .read_native::<norito::json::Value>(NativeRecord::Request)
                .unwrap(),
            Some(request.clone())
        );
        assert!(Journal::open_optional(&path).is_err());
    }
    fs::remove_file(path.join("lock")).unwrap();
    assert!(Journal::open_optional(&path).is_err());
    assert!(!path.join("lock").exists());
    assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn optional_journal_borrowed_parent_refuses_loss_and_replacement_then_retries_exact_original() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = OwnerDirectory::open_or_create(temporary.path().join("parent")).unwrap();
    let path = parent.path().join("journal");
    let request = norito::json!({"original": "retained-parent"});
    let original = Journal::create_preparation(&path, &request).unwrap();
    let directory_identity = original.directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&original.lock).unwrap();
    drop(original);
    let displaced = temporary.path().join("displaced");
    fs::rename(parent.path(), &displaced).unwrap();
    for name in ["absent", "journal"] {
        let error = Journal::open_optional_in_parent(&parent, OsStr::new(name)).unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
    }
    let replacement = OwnerDirectory::open_or_create(parent.path()).unwrap();
    assert!(Journal::open_optional_in_parent(&parent, OsStr::new("absent")).is_err());
    drop(replacement);
    fs::remove_dir(parent.path()).unwrap();
    fs::rename(&displaced, parent.path()).unwrap();
    assert!(
        Journal::open_optional_in_parent(&parent, OsStr::new("absent"))
            .unwrap()
            .is_none()
    );
    let selected = Journal::open_optional_in_parent(&parent, OsStr::new("journal"))
        .unwrap()
        .unwrap();
    assert_eq!(selected.directory.identity().unwrap(), directory_identity);
    assert_eq!(FileIdentity::of(&selected.lock).unwrap(), lock_identity);
    assert_eq!(
        selected
            .read_native::<norito::json::Value>(NativeRecord::Request)
            .unwrap(),
        Some(request)
    );
}

#[cfg(windows)]
#[test]
fn optional_journal_borrowed_parent_preserves_native_sharing_absence_and_lock_retry() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = OwnerDirectory::open_or_create(temporary.path().join("parent")).unwrap();
    let path = parent.path().join("journal");
    let request = norito::json!({"original": "retained-parent"});
    let original = Journal::create_preparation(&path, &request).unwrap();
    let directory_identity = original.directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&original.lock).unwrap();
    drop(original);
    assert!(fs::rename(parent.path(), temporary.path().join("displaced")).is_err());
    assert!(
        Journal::open_optional_in_parent(&parent, OsStr::new("absent"))
            .unwrap()
            .is_none()
    );
    let selected = Journal::open_optional_in_parent(&parent, OsStr::new("journal"))
        .unwrap()
        .unwrap();
    assert_eq!(selected.directory.identity().unwrap(), directory_identity);
    assert_eq!(FileIdentity::of(&selected.lock).unwrap(), lock_identity);
    assert_eq!(
        selected
            .read_native::<norito::json::Value>(NativeRecord::Request)
            .unwrap(),
        Some(request)
    );
    assert!(fs::rename(&path, temporary.path().join("moved-journal")).is_err());
    assert!(Journal::open_optional_in_parent(&parent, OsStr::new("journal")).is_err());
    drop(selected);
    assert_eq!(
        FileIdentity::of(
            &Journal::open_optional_in_parent(&parent, OsStr::new("journal"))
                .unwrap()
                .unwrap()
                .lock
        )
        .unwrap(),
        lock_identity
    );
}
