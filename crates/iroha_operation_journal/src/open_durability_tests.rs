//! Existing journal reads retain native ownership without a new publication flush.

use super::*;
use std::{cell::Cell, io};

#[test]
fn existing_journal_reopen_needs_no_publication_sync_and_keeps_original_lock() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = OwnerDirectory::open(temporary.path()).unwrap();
    let path = temporary.path().join("journal");
    let original = norito::json!({"original": "unchanged", "deadline_ms": 17});
    let created = Journal::create_preparation(&path, &original).unwrap();
    let directory_identity = created.directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&created.lock).unwrap();
    drop(created);

    // Real existing-directory/lock admission must succeed even if a publication
    // flush would fail. The failing operation is never consulted for a read-open.
    let sync_called = Cell::new(false);
    let reopened = Journal::lock_directory_with_sync(
        parent.open_private_child("journal").unwrap(),
        false,
        |_| {
            sync_called.set(true);
            Err(io::Error::other("unexpected publication flush on reopen"))
        },
    )
    .unwrap();
    assert!(!sync_called.get());
    assert_eq!(reopened.directory.identity().unwrap(), directory_identity);
    assert_eq!(FileIdentity::of(&reopened.lock).unwrap(), lock_identity);
    assert_eq!(
        reopened
            .read_native::<norito::json::Value>(NativeRecord::Request)
            .unwrap(),
        Some(original.clone())
    );
    assert!(Journal::open(&path).is_err());
    assert!(Journal::open_optional(&path).is_err());
    drop(reopened);

    // The public reopen path preserves the same exclusive owner and original bytes.
    let reopened = Journal::open(&path).unwrap();
    assert_eq!(FileIdentity::of(&reopened.lock).unwrap(), lock_identity);
    assert_eq!(
        reopened
            .read_native::<norito::json::Value>(NativeRecord::Request)
            .unwrap(),
        Some(original)
    );
    #[cfg(unix)]
    {
        std::fs::rename(path.join("lock"), path.join("displaced-lock")).unwrap();
        let replacement = reopened.directory.create_lock("lock").unwrap();
        assert_ne!(FileIdentity::of(&replacement).unwrap(), lock_identity);
        assert!(reopened.revalidate().is_err());
        assert!(
            reopened
                .read_native::<norito::json::Value>(NativeRecord::Request)
                .is_err()
        );
    }
}

#[test]
fn fresh_journal_sync_failure_is_reported_and_releases_the_acquired_lock() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = OwnerDirectory::open(temporary.path()).unwrap();
    let directory = parent.create_private_child("journal").unwrap();
    let path = directory.path().to_owned();
    let sync_called = Cell::new(false);
    let failure = Journal::lock_directory_with_sync(directory, true, |directory| {
        sync_called.set(true);
        // Exercise the real native boundary before injecting its reported failure.
        directory.sync()?;
        Err(io::Error::other("injected new-journal durability failure"))
    })
    .unwrap_err();
    assert!(sync_called.get());
    assert_eq!(
        failure.downcast_ref::<io::Error>().unwrap().to_string(),
        "injected new-journal durability failure"
    );
    assert!(path.join("lock").is_file());
    assert!(!path.join("operation.json").exists());
    assert!(Journal::create(&path).is_err());

    // A failure cannot retain the exclusive lock or silently publish an operation.
    // Explicitly reopening the same unprepared journal can publish its first record.
    let reopened = Journal::open(&path).unwrap();
    let lock_identity = FileIdentity::of(&reopened.lock).unwrap();
    let original = norito::json!({"signed": "original-after-recovery"});
    reopened.write_operation(&original).unwrap();
    assert!(reopened.write_operation(&original).is_err());
    drop(reopened);
    let retained = Journal::open(&path).unwrap();
    assert_eq!(FileIdentity::of(&retained.lock).unwrap(), lock_identity);
    assert_eq!(
        retained.read_operation::<norito::json::Value>().unwrap(),
        original
    );
}
