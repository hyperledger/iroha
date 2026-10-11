//! Genuine optional-child admission distinguishes first absence from later custody refusal.

use super::*;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

#[test]
fn optional_child_keeps_first_absence_required_error_and_exact_present_identity() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = PrivateDirectory::open_or_create(temporary.path().join("parent")).unwrap();
    assert!(parent.open_child_optional("child").unwrap().is_none());
    let required = parent.open_child("child").unwrap_err();
    assert_eq!(required.kind(), io::ErrorKind::NotFound);
    assert!(parent.open_child_optional("../child").is_err());
    let original = parent.create_child("child").unwrap();
    let selected = parent.open_child_optional("child").unwrap().unwrap();
    assert_eq!(selected.identity().unwrap(), original.identity().unwrap());
    assert_eq!(
        parent.open_child("child").unwrap().identity().unwrap(),
        original.identity().unwrap()
    );
}

#[cfg(unix)]
#[test]
fn optional_child_refuses_post_open_disappearance_and_parent_loss_then_original_retry() {
    for attack in ["child", "parent", "replacement"] {
        let temporary = tempfile::tempdir().unwrap();
        let parent = PrivateDirectory::open_or_create(temporary.path().join("parent")).unwrap();
        let original = parent.create_child("child").unwrap();
        let expected = original.identity().unwrap();
        let path = if attack == "child" {
            original.path()
        } else {
            parent.path()
        }
        .to_owned();
        let displaced = temporary.path().join("displaced");
        let moved = displaced.clone();
        let changed = path.clone();
        let optional = platform::with_child_named_hook(
            "child",
            move || {
                std::fs::rename(&changed, &moved).unwrap();
                if attack == "replacement" {
                    std::fs::create_dir(&changed).unwrap();
                    std::fs::set_permissions(&changed, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                }
            },
            || parent.open_child_optional("child"),
        );
        let refusal = optional.unwrap_err();
        if attack != "replacement" {
            assert_eq!(refusal.kind(), io::ErrorKind::NotFound);
        }
        if attack == "replacement" {
            std::fs::remove_dir(&path).unwrap();
        }
        std::fs::rename(&displaced, &path).unwrap();
        assert_eq!(
            parent
                .open_child_optional("child")
                .unwrap()
                .unwrap()
                .identity()
                .unwrap(),
            expected
        );
        assert_eq!(
            parent.open_child("child").unwrap().identity().unwrap(),
            expected
        );
    }
}

#[cfg(unix)]
#[test]
fn optional_child_refuses_missing_replaced_parent_and_unsafe_child_without_absence() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let temporary = tempfile::tempdir().unwrap();
    let parent = PrivateDirectory::open_or_create(temporary.path().join("parent")).unwrap();
    let original = parent.create_child("child").unwrap();
    let expected = original.identity().unwrap();
    let displaced = temporary.path().join("displaced");
    std::fs::rename(parent.path(), &displaced).unwrap();
    assert_eq!(
        parent.open_child_optional("absent").unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    let replacement = PrivateDirectory::open_or_create(parent.path()).unwrap();
    assert!(parent.open_child_optional("absent").is_err());
    drop(replacement);
    std::fs::remove_dir(parent.path()).unwrap();
    std::fs::rename(&displaced, parent.path()).unwrap();
    symlink(original.path(), parent.path().join("linked")).unwrap();
    assert!(parent.open_child_optional("linked").is_err());
    parent
        .write_atomic("file", b"not a directory", PublishMode::CreateNew)
        .unwrap();
    assert!(parent.open_child_optional("file").is_err());
    std::fs::set_permissions(original.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        parent.open_child_optional("child").unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    std::fs::set_permissions(original.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        parent
            .open_child_optional("child")
            .unwrap()
            .unwrap()
            .identity()
            .unwrap(),
        expected
    );
    assert!(parent.open_child_optional("absent").unwrap().is_none());
}

#[cfg(unix)]
#[test]
fn optional_child_parent_exit_dominates_initial_absence_and_native_refusal_with_retry() {
    use std::os::unix::fs::PermissionsExt as _;
    for name in ["absent", "unsafe"] {
        let temporary = tempfile::tempdir().unwrap();
        let parent = PrivateDirectory::open_or_create(temporary.path().join("parent")).unwrap();
        let child = parent.create_child("unsafe").unwrap();
        let expected = child.identity().unwrap();
        std::fs::set_permissions(child.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        if name == "absent" {
            assert!(parent.open_child_optional(name).unwrap().is_none());
        } else {
            assert_eq!(
                parent.open_child_optional(name).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        let path = parent.path().to_owned();
        let displaced = temporary.path().join("displaced");
        let original = path.clone();
        let moved = displaced.clone();
        let refusal = platform::with_child_named_hook(
            name,
            move || std::fs::rename(&original, &moved).unwrap(),
            || parent.open_child_optional(name),
        )
        .unwrap_err();
        assert_eq!(refusal.kind(), io::ErrorKind::NotFound);
        std::fs::rename(&displaced, &path).unwrap();
        if name == "absent" {
            assert!(parent.open_child_optional(name).unwrap().is_none());
        } else {
            assert_eq!(
                parent.open_child_optional(name).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        std::fs::set_permissions(child.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            parent
                .open_child_optional("unsafe")
                .unwrap()
                .unwrap()
                .identity()
                .unwrap(),
            expected
        );
    }
}

#[cfg(unix)]
#[test]
fn private_child_publication_refuses_late_destination_absence_without_staging_and_retries() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = OwnerDirectory::open_or_create(temporary.path().join("parent")).unwrap();
    let original = parent.create_private_child("destination").unwrap();
    original
        .write_atomic("original", b"original bytes", PublishMode::CreateNew)
        .unwrap();
    let expected = original.identity().unwrap();
    let destination = original.path().to_owned();
    let displaced = temporary.path().join("displaced");
    let path = destination.clone();
    let moved = displaced.clone();
    let error = platform::with_child_named_hook(
        "destination",
        move || std::fs::rename(&path, &moved).unwrap(),
        || parent.publish_private_child("destination", &[("replacement", b"replacement bytes")]),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert!(parent.entries(1).unwrap().is_empty());
    std::fs::rename(&displaced, &destination).unwrap();
    assert_eq!(original.identity().unwrap(), expected);
    assert_eq!(
        original.read("original", 64).unwrap().as_slice(),
        b"original bytes"
    );
    assert_eq!(
        parent
            .publish_private_child("destination", &[("replacement", b"replacement bytes")])
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    let fresh = parent
        .publish_private_child("fresh", &[("original", b"fresh bytes")])
        .unwrap();
    assert_eq!(
        fresh.read("original", 64).unwrap().as_slice(),
        b"fresh bytes"
    );
    assert_eq!(
        original.read("original", 64).unwrap().as_slice(),
        b"original bytes"
    );
}
