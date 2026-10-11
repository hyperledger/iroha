//! Exact private-file removal, initial-only absence and original native custody.

use super::*;
use std::{cell::RefCell, fs};

std::thread_local! {
    static EXIT_HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
}

/// Run the one-shot test hook before leaving a private-file removal.
pub fn before_exit() {
    let hook = EXIT_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(unix)]
fn with_exit_hook<T>(hook: impl FnOnce() + 'static, remove: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            EXIT_HOOK.with(|slot| slot.borrow_mut().take());
        }
    }
    EXIT_HOOK.with(|slot| {
        assert!(slot.borrow().is_none());
        *slot.borrow_mut() = Some(Box::new(hook));
    });
    let _reset = Reset;
    remove()
}

fn store() -> (tempfile::TempDir, PrivateDirectory) {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap();
    (temporary, directory)
}

#[test]
fn private_removal_keeps_initial_absence_exact_removal_and_unrelated_files() {
    let (_temporary, directory) = store();
    let directory_id = directory.identity().unwrap();
    assert!(!directory.remove_private("missing").unwrap());
    assert!(directory.entries(0).unwrap().is_empty());
    for name in ["", ".", "..", "../record", "record/child"] {
        assert_eq!(
            directory.remove_private(name).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    for (name, bytes) in [("record", b"original".as_slice()), ("keep", b"unrelated")] {
        directory
            .write_atomic(name, bytes, PublishMode::CreateNew)
            .unwrap();
    }
    let kept = FileSnapshot::private_journal(&directory.open_read("keep").unwrap()).unwrap();
    assert!(directory.remove_private("record").unwrap());
    assert!(!directory.remove_private("record").unwrap());
    assert_eq!(directory.read("keep", 9).unwrap().as_slice(), b"unrelated");
    assert_eq!(
        FileSnapshot::private_journal(&directory.open_read("keep").unwrap()).unwrap(),
        kept
    );
    assert_eq!(directory.identity().unwrap(), directory_id);
    directory.sync().unwrap();
}

#[test]
fn private_removal_refuses_directories_and_shared_links_then_original_retry() {
    let (_temporary, directory) = store();
    let child = directory.ensure_child("child").unwrap();
    let child_id = child.identity().unwrap();
    assert!(directory.remove_private("child").is_err());
    assert_eq!(child.identity().unwrap(), child_id);
    directory
        .write_atomic("record", b"original", PublishMode::CreateNew)
        .unwrap();
    let original = FileIdentity::of(&directory.open_read("record").unwrap()).unwrap();
    fs::hard_link(
        directory.path().join("record"),
        directory.path().join("alias"),
    )
    .unwrap();
    assert!(directory.remove_private("record").is_err());
    assert!(directory.path().join("record").is_file());
    assert!(directory.path().join("alias").is_file());
    fs::remove_file(directory.path().join("alias")).unwrap();
    assert_eq!(
        FileIdentity::of(&directory.open_read("record").unwrap()).unwrap(),
        original
    );
    assert!(directory.remove_private("record").unwrap());
    assert!(directory.open_child("child").is_ok());
}

#[cfg(unix)]
#[test]
fn private_removal_refuses_links_and_nonprivate_or_readonly_metadata_then_restores() {
    use std::os::unix::{fs::PermissionsExt as _, fs::symlink};
    let (_temporary, directory) = store();
    directory
        .write_atomic("record", b"original", PublishMode::CreateNew)
        .unwrap();
    let record = directory.path().join("record");
    let original = FileIdentity::of(&directory.open_read("record").unwrap()).unwrap();
    symlink("record", directory.path().join("linked")).unwrap();
    assert!(directory.remove_private("linked").is_err());
    assert!(
        fs::symlink_metadata(directory.path().join("linked"))
            .unwrap()
            .is_symlink()
    );
    for mode in [0o644, 0o400] {
        fs::set_permissions(&record, fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            directory.remove_private("record").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(fs::read(&record).unwrap(), b"original");
    }
    fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        FileIdentity::of(&directory.open_read("record").unwrap()).unwrap(),
        original
    );
    assert!(directory.remove_private("record").unwrap());
}

#[cfg(unix)]
#[test]
fn private_removal_late_named_absence_is_error_and_same_original_restores() {
    let (_temporary, directory) = store();
    directory
        .write_atomic("record", b"original", PublishMode::CreateNew)
        .unwrap();
    let original = FileIdentity::of(&directory.open_read("record").unwrap()).unwrap();
    let record = directory.path().join("record");
    let saved = directory.path().join("saved");
    let (moving, destination) = (record.clone(), saved.clone());
    let error = platform::with_readonly_named_hook(
        "record",
        move || fs::rename(moving, destination).unwrap(),
        || directory.remove_private("record"),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(fs::read(&saved).unwrap(), b"original");
    fs::rename(saved, &record).unwrap();
    assert_eq!(
        FileIdentity::of(&directory.open_read("record").unwrap()).unwrap(),
        original
    );
    assert!(directory.remove_private("record").unwrap());
}

#[cfg(unix)]
#[test]
fn private_removal_refuses_named_replacement_without_deleting_either_original() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_temporary, directory) = store();
    directory
        .write_atomic("record", b"original", PublishMode::CreateNew)
        .unwrap();
    let original = FileIdentity::of(&directory.open_read("record").unwrap()).unwrap();
    let record = directory.path().join("record");
    let saved = directory.path().join("saved");
    let (moving, destination) = (record.clone(), saved.clone());
    let error = platform::with_readonly_named_hook(
        "record",
        move || {
            fs::rename(&moving, destination).unwrap();
            fs::write(&moving, b"replacement").unwrap();
            fs::set_permissions(&moving, fs::Permissions::from_mode(0o600)).unwrap();
        },
        || directory.remove_private("record"),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), changed().to_string());
    assert_eq!(fs::read(&record).unwrap(), b"replacement");
    assert_eq!(fs::read(&saved).unwrap(), b"original");
    fs::remove_file(&record).unwrap();
    fs::rename(saved, &record).unwrap();
    assert_eq!(
        FileIdentity::of(&directory.open_read("record").unwrap()).unwrap(),
        original
    );
    assert!(directory.remove_private("record").unwrap());
}

#[cfg(unix)]
#[test]
fn private_removal_exit_custody_overrides_absence_success_and_body_error_then_restores() {
    use std::os::unix::fs::PermissionsExt as _;
    for outcome in ["absent", "removed", "refused"] {
        let (temporary, directory) = store();
        let original_directory = directory.identity().unwrap();
        if outcome != "absent" {
            directory
                .write_atomic("record", b"original", PublishMode::CreateNew)
                .unwrap();
        }
        if outcome == "refused" {
            fs::set_permissions(
                directory.path().join("record"),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
        }
        let path = directory.path().to_owned();
        let saved = temporary.path().join("saved-directory");
        let (moving, destination) = (path.clone(), saved.clone());
        let error = with_exit_hook(
            move || fs::rename(moving, destination).unwrap(),
            || directory.remove_private("record"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound, "{outcome}");
        assert_eq!(saved.join("record").exists(), outcome == "refused");
        // A copied safe replacement never becomes this retained directory's authority.
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(directory.remove_private("missing").is_err());
        fs::remove_dir(&path).unwrap();
        fs::rename(saved, &path).unwrap();
        assert_eq!(directory.identity().unwrap(), original_directory);
        if outcome == "refused" {
            fs::set_permissions(path.join("record"), fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(directory.read("record", 8).unwrap().as_slice(), b"original");
            assert!(directory.remove_private("record").unwrap());
        } else {
            assert!(!directory.remove_private("record").unwrap());
        }
    }
}

#[cfg(windows)]
#[test]
fn private_removal_keeps_native_parent_and_open_reader_refusal_then_original_retry() {
    let (temporary, directory) = store();
    let original_directory = directory.identity().unwrap();
    directory
        .write_atomic("record", b"original", PublishMode::CreateNew)
        .unwrap();
    let reader = directory.open_read("record").unwrap();
    let original_file = FileIdentity::of(&reader).unwrap();
    assert!(fs::rename(directory.path(), temporary.path().join("moved")).is_err());
    assert!(!directory.remove_private("missing").unwrap());
    assert!(directory.remove_private("record").is_err());
    assert_eq!(FileIdentity::of(&reader).unwrap(), original_file);
    assert_eq!(directory.read("record", 8).unwrap().as_slice(), b"original");
    drop(reader);
    assert!(directory.remove_private("record").unwrap());
    assert_eq!(directory.identity().unwrap(), original_directory);
}

#[cfg(windows)]
#[test]
fn private_removal_refuses_readonly_native_file_then_original_retry() {
    let (_temporary, directory) = store();
    directory
        .write_atomic("record", b"original", PublishMode::CreateNew)
        .unwrap();
    let path = directory.path().join("record");
    let original = FileIdentity::of(&directory.open_read("record").unwrap()).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&path, permissions).unwrap();
    assert!(directory.remove_private("record").is_err());
    assert!(path.is_file());
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(false);
    fs::set_permissions(&path, permissions).unwrap();
    assert_eq!(
        FileIdentity::of(&directory.open_read("record").unwrap()).unwrap(),
        original
    );
    assert!(directory.remove_private("record").unwrap());
}
