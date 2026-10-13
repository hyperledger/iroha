//! Original directory, bounded publication and retained-lock controls.

use super::*;

#[test]
fn observed_writer_retains_all_real_boundaries_and_exact_bytes() {
    let root = tempfile::tempdir().unwrap();
    let directory = OwnerDirectory::open(root.path()).unwrap();
    let retained = directory.retain().unwrap();
    let lock = directory.open_lock("lock").unwrap();
    lock.try_lock().unwrap();
    let bytes = [17; 8193];
    let mut steps = Vec::new();
    retained
        .write_atomic_observed("frame", &bytes, PublishMode::CreateNew, 16, |step, _| {
            steps.push(step);
            directory.require_same_lock("lock", &lock)
        })
        .unwrap();
    assert_eq!(
        steps,
        [
            AtomicWriteStep::CreateTemp,
            AtomicWriteStep::WriteHead,
            AtomicWriteStep::WriteTail,
            AtomicWriteStep::SyncFile,
            AtomicWriteStep::Publish,
            AtomicWriteStep::SyncDirectory
        ]
    );
    let mut file = retained.open_regular_optional("frame").unwrap().unwrap();
    let mut actual = Vec::new();
    file.read_to_end(&mut actual).unwrap();
    retained.require_same_regular_file("frame", &file).unwrap();
    assert_eq!(actual, bytes);
    assert!(retained.open_regular_optional("absent").unwrap().is_none());
    let mut names = Vec::new();
    retained
        .visit_entries(|name| {
            names.push(name.to_owned());
            Ok(())
        })
        .unwrap();
    names.sort();
    assert_eq!(
        names,
        [
            std::ffi::OsString::from("frame"),
            std::ffi::OsString::from("lock")
        ]
    );
    retained.sync_parent().unwrap();
    assert!(retained.remove_private("frame").unwrap());
    assert!(!retained.remove_private("frame").unwrap());
    directory.require_same_lock("lock", &lock).unwrap();
}

#[test]
fn observed_writer_retains_the_callers_temporary_attempt_bound() {
    let root = tempfile::tempdir().unwrap();
    let directory = OwnerDirectory::open(root.path()).unwrap();
    let mut attempts = Vec::new();
    let result = directory.write_atomic_observed(
        "frame",
        b"original",
        PublishMode::CreateNew,
        16,
        |step, path| {
            if step == AtomicWriteStep::CreateTemp {
                std::fs::write(path, b"collision")?;
                attempts.push(path.to_owned());
            }
            Ok(())
        },
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(attempts.len(), 16);
    assert!(!root.path().join("frame").exists());
    for path in attempts {
        assert_eq!(std::fs::read(path).unwrap(), b"collision");
    }
    assert_eq!(
        directory
            .write_atomic_observed(
                "frame",
                b"original",
                PublishMode::CreateNew,
                0,
                |_, _| panic!("zero attempts cannot run the observer")
            )
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
}

#[cfg(unix)]
#[test]
fn observed_writer_refuses_changed_directory_before_touching_replacement() {
    for boundary in [AtomicWriteStep::CreateTemp, AtomicWriteStep::Publish] {
        let root = tempfile::tempdir().unwrap();
        let selected = root.path().join("selected");
        std::fs::create_dir(&selected).unwrap();
        let directory = OwnerDirectory::open(&selected).unwrap();
        let original = root.path().join("original");
        let mut replaced = false;
        let result = directory.write_atomic_observed(
            "frame",
            b"original",
            PublishMode::CreateNew,
            16,
            |step, _| {
                if step == boundary {
                    std::fs::rename(&selected, &original)?;
                    std::fs::create_dir(&selected)?;
                    replaced = true;
                }
                Ok(())
            },
        );
        assert!(replaced);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Other);
        assert_eq!(std::fs::read_dir(&selected).unwrap().count(), 0);
        assert_eq!(
            std::fs::read_dir(&original).unwrap().count(),
            0,
            "identity-safe cleanup must remove only our original temporary file"
        );
        std::fs::remove_dir(&selected).unwrap();
        std::fs::rename(&original, &selected).unwrap();
        directory
            .write_atomic("frame", b"original", PublishMode::CreateNew)
            .unwrap();
        assert_eq!(std::fs::read(selected.join("frame")).unwrap(), b"original");
    }
}

#[cfg(unix)]
#[test]
fn retained_lock_joins_refuse_replacement_and_hardlinks() {
    let root = tempfile::tempdir().unwrap();
    let directory = OwnerDirectory::open(root.path()).unwrap();
    let lock = directory.open_lock("lock").unwrap();
    lock.try_lock().unwrap();
    std::fs::rename(root.path().join("lock"), root.path().join("original")).unwrap();
    let replacement = directory.open_lock("lock").unwrap();
    replacement.try_lock().unwrap();
    assert_eq!(
        directory
            .require_same_lock("lock", &lock)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Other
    );
    drop(replacement);
    std::fs::remove_file(root.path().join("lock")).unwrap();
    std::fs::rename(root.path().join("original"), root.path().join("lock")).unwrap();
    std::fs::hard_link(root.path().join("lock"), root.path().join("alias")).unwrap();
    assert_eq!(
        directory
            .require_same_lock("lock", &lock)
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    std::fs::remove_file(root.path().join("alias")).unwrap();
    directory.require_same_lock("lock", &lock).unwrap();
}

#[cfg(windows)]
#[test]
fn retained_owner_directory_kernel_handles_prevent_namespace_replacement() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("selected");
    std::fs::create_dir(&path).unwrap();
    let directory = OwnerDirectory::open(&path).unwrap();
    assert!(std::fs::rename(&path, root.path().join("replacement")).is_err());
    directory.revalidate().unwrap();
    directory
        .write_atomic_observed("frame", b"original", PublishMode::CreateNew, 16, |_, _| {
            Ok(())
        })
        .unwrap();
    assert_eq!(std::fs::read(path.join("frame")).unwrap(), b"original");
    assert!(!root.path().join("replacement").exists());
}

#[test]
fn original_owner_optional_child_existing_lock_and_regular_retirement_are_closed() {
    let root = tempfile::tempdir().unwrap();
    let directory = OwnerDirectory::open(root.path()).unwrap();
    assert!(directory.open_child_optional("absent").unwrap().is_none());
    assert_eq!(
        directory.open_existing_lock("lock").unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    assert!(!root.path().join("lock").exists());
    let lock = directory.open_lock("lock").unwrap();
    let operation = directory.open_existing_lock("lock").unwrap();
    operation.lock().unwrap();
    directory.require_same_lock("lock", &lock).unwrap();
    let child = directory.ensure_child("height").unwrap();
    child
        .write_atomic("body", b"original", PublishMode::CreateNew)
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            child.path().join("body"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert_eq!(
            child.remove_private("body").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
    assert_eq!(
        directory
            .open_child_optional("height")
            .unwrap()
            .unwrap()
            .identity()
            .unwrap(),
        child.identity().unwrap()
    );
    assert!(child.remove_regular("body").unwrap());
    assert!(!child.remove_regular("body").unwrap());
    child.remove_empty().unwrap();
    assert!(directory.open_child_optional("height").unwrap().is_none());
    directory.require_same_lock("lock", &lock).unwrap();
}
