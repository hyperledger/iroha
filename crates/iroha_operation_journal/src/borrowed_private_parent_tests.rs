//! Optional journal admission through the original private attempt parent.

use super::*;
use std::fs;

#[test]
fn borrowed_private_parent_journal_keeps_initial_absence_exact_identity_bytes_and_lock_lifetime() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = PrivateDirectory::open_or_create(temporary.path().join("attempt")).unwrap();
    let path = parent.path().join("transaction");
    assert!(
        Journal::open_optional_child(&parent, "transaction")
            .unwrap()
            .is_none()
    );
    assert!(!path.exists());
    assert!(Journal::open_optional_child(&parent, "../transaction").is_err());
    let request = norito::json!({"original": "private-parent", "deadline_ms": 17});
    let original = Journal::create_preparation(&path, &request).unwrap();
    let directory_identity = original.directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&original.lock).unwrap();
    drop(original);
    let selected = Journal::open_optional_child(&parent, "transaction")
        .unwrap()
        .unwrap();
    assert_eq!(selected.path(), path);
    assert_eq!(selected.directory.identity().unwrap(), directory_identity);
    assert_eq!(FileIdentity::of(&selected.lock).unwrap(), lock_identity);
    assert!(Journal::open_optional_child(&parent, "transaction").is_err());
    assert!(Journal::open_optional(&path).is_err());
    drop(parent);
    assert_eq!(
        selected
            .read_native::<norito::json::Value>(NativeRecord::Request)
            .unwrap(),
        Some(request.clone())
    );
    selected.revalidate().unwrap();
    drop(selected);
    let retry = Journal::open_optional(&path).unwrap().unwrap();
    assert_eq!(retry.directory.identity().unwrap(), directory_identity);
    assert_eq!(FileIdentity::of(&retry.lock).unwrap(), lock_identity);
    assert_eq!(
        retry
            .read_native::<norito::json::Value>(NativeRecord::Request)
            .unwrap(),
        Some(request)
    );
}

#[test]
fn borrowed_private_parent_journal_refuses_existing_nonjournal_and_restores_original_missing_lock()
{
    let temporary = tempfile::tempdir().unwrap();
    let parent = PrivateDirectory::open_or_create(temporary.path().join("attempt")).unwrap();
    fs::write(parent.path().join("not-directory"), b"not a journal").unwrap();
    assert!(Journal::open_optional_child(&parent, "not-directory").is_err());
    let incomplete = parent.ensure_child("incomplete").unwrap();
    assert!(Journal::open_optional_child(&parent, "incomplete").is_err());
    assert!(!incomplete.path().join("lock").exists());
    let path = parent.path().join("transaction");
    let request = norito::json!({"original": "same-lock"});
    let original = Journal::create_preparation(&path, &request).unwrap();
    let directory_identity = original.directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&original.lock).unwrap();
    drop(original);
    let saved_lock = parent.path().join("saved-lock");
    fs::rename(path.join("lock"), &saved_lock).unwrap();
    let error = Journal::open_optional_child(&parent, "transaction").unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    assert!(!path.join("lock").exists());
    fs::rename(&saved_lock, path.join("lock")).unwrap();
    let retry = Journal::open_optional_child(&parent, "transaction")
        .unwrap()
        .unwrap();
    assert_eq!(retry.directory.identity().unwrap(), directory_identity);
    assert_eq!(FileIdentity::of(&retry.lock).unwrap(), lock_identity);
    assert_eq!(
        retry
            .read_native::<norito::json::Value>(NativeRecord::Request)
            .unwrap(),
        Some(request)
    );
}

#[cfg(unix)]
#[test]
fn borrowed_private_parent_journal_refuses_lost_and_same_bytes_replaced_parent_then_retries_original()
 {
    let temporary = tempfile::tempdir().unwrap();
    let parent = PrivateDirectory::open_or_create(temporary.path().join("attempt")).unwrap();
    let path = parent.path().join("transaction");
    let request = norito::json!({"original": "same-bytes"});
    let original = Journal::create_preparation(&path, &request).unwrap();
    let directory_identity = original.directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&original.lock).unwrap();
    drop(original);
    let displaced = temporary.path().join("displaced");
    fs::rename(parent.path(), &displaced).unwrap();
    for name in ["absent", "transaction"] {
        let error = Journal::open_optional_child(&parent, name).unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
    }
    let replacement = PrivateDirectory::open_or_create(parent.path()).unwrap();
    let copied = Journal::create_preparation(&path, &request).unwrap();
    assert_ne!(copied.directory.identity().unwrap(), directory_identity);
    drop(copied);
    // A fresh absolute boundary sees this valid copy; the retained original must refuse it.
    let copied = Journal::open_optional(&path).unwrap().unwrap();
    assert_eq!(
        copied
            .read_native::<norito::json::Value>(NativeRecord::Request)
            .unwrap(),
        Some(request.clone())
    );
    drop(copied);
    for name in ["absent", "transaction"] {
        assert!(Journal::open_optional_child(&parent, name).is_err());
    }
    drop(replacement);
    fs::remove_dir_all(parent.path()).unwrap();
    fs::rename(&displaced, parent.path()).unwrap();
    assert!(
        Journal::open_optional_child(&parent, "absent")
            .unwrap()
            .is_none()
    );
    let retry = Journal::open_optional_child(&parent, "transaction")
        .unwrap()
        .unwrap();
    assert_eq!(retry.directory.identity().unwrap(), directory_identity);
    assert_eq!(FileIdentity::of(&retry.lock).unwrap(), lock_identity);
    assert_eq!(
        retry
            .read_native::<norito::json::Value>(NativeRecord::Request)
            .unwrap(),
        Some(request)
    );
}

#[cfg(unix)]
#[test]
fn borrowed_private_parent_journal_final_custody_overrides_some_none_and_lock_error_with_original_retry()
 {
    use std::os::unix::fs::PermissionsExt as _;

    let temporary = tempfile::tempdir().unwrap();
    let parent = PrivateDirectory::open_or_create(temporary.path().join("attempt")).unwrap();
    let request = norito::json!({"original": "exit-custody"});
    for name in ["valid", "unsafe-lock"] {
        drop(Journal::create_preparation(&parent.path().join(name), &request).unwrap());
    }
    let unsafe_lock = parent.path().join("unsafe-lock/lock");
    let permissions = fs::metadata(&unsafe_lock).unwrap().permissions();
    fs::set_permissions(&unsafe_lock, fs::Permissions::from_mode(0o666)).unwrap();
    let error = Journal::open_optional_child(&parent, "unsafe-lock").unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    let displaced = temporary.path().join("displaced");
    for name in ["absent", "valid", "unsafe-lock"] {
        let error = Journal::open_optional_with_parent(
            || parent.open_child_optional(name),
            || {
                fs::rename(parent.path(), &displaced).unwrap();
                parent.revalidate()
            },
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
        fs::rename(&displaced, parent.path()).unwrap();
        if name == "unsafe-lock" {
            fs::set_permissions(&unsafe_lock, permissions.clone()).unwrap();
        }
        let retry = Journal::open_optional_child(&parent, name).unwrap();
        match retry {
            None => {
                assert_eq!(name, "absent");
                assert!(!parent.path().join(name).exists());
            }
            Some(retry) => assert_eq!(
                retry
                    .read_native::<norito::json::Value>(NativeRecord::Request)
                    .unwrap(),
                Some(request.clone())
            ),
        }
    }
}

#[cfg(windows)]
#[test]
fn borrowed_private_parent_journal_keeps_native_rename_refusal_and_original_lock_retry() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = PrivateDirectory::open_or_create(temporary.path().join("attempt")).unwrap();
    let path = parent.path().join("transaction");
    let request = norito::json!({"original": "native-sharing"});
    let original = Journal::create_preparation(&path, &request).unwrap();
    let directory_identity = original.directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&original.lock).unwrap();
    drop(original);
    assert!(fs::rename(parent.path(), temporary.path().join("displaced")).is_err());
    assert!(
        Journal::open_optional_child(&parent, "absent")
            .unwrap()
            .is_none()
    );
    let selected = Journal::open_optional_child(&parent, "transaction")
        .unwrap()
        .unwrap();
    assert_eq!(selected.directory.identity().unwrap(), directory_identity);
    assert_eq!(FileIdentity::of(&selected.lock).unwrap(), lock_identity);
    assert!(fs::rename(&path, parent.path().join("displaced-transaction")).is_err());
    assert!(Journal::open_optional_child(&parent, "transaction").is_err());
    drop(selected);
    let retry = Journal::open_optional_child(&parent, "transaction")
        .unwrap()
        .unwrap();
    assert_eq!(retry.directory.identity().unwrap(), directory_identity);
    assert_eq!(FileIdentity::of(&retry.lock).unwrap(), lock_identity);
    assert_eq!(
        retry
            .read_native::<norito::json::Value>(NativeRecord::Request)
            .unwrap(),
        Some(request)
    );
}
