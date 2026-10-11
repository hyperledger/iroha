//! Native private-child admission through the exact retained project parent.

use super::*;

#[test]
fn project_parent_private_child_preserves_absence_names_identity_and_no_creation() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = OwnerDirectory::open(temporary.path()).unwrap();
    assert!(
        parent
            .open_private_child_optional("journal")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        parent.open_private_child("journal").unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    assert!(parent.open_private_child_optional("../journal").is_err());
    assert!(parent.open_private_child("../journal").is_err());
    assert!(parent.entries(0).unwrap().is_empty());
    let original = parent.create_private_child("journal").unwrap();
    original
        .write_atomic("original", b"original bytes", PublishMode::CreateNew)
        .unwrap();
    let identity = original.identity().unwrap();
    for selected in [
        parent.open_private_child("journal").unwrap(),
        parent
            .open_private_child_optional("journal")
            .unwrap()
            .unwrap(),
    ] {
        assert_eq!(selected.identity().unwrap(), identity);
        assert_eq!(
            selected.read("original", 64).unwrap().as_slice(),
            b"original bytes"
        );
    }
    assert_eq!(
        parent.entries(1).unwrap(),
        [std::ffi::OsString::from("journal")]
    );
}

#[cfg(unix)]
#[test]
fn project_private_child_refuses_late_parent_loss_and_unsafe_child_then_original_retry() {
    use std::os::unix::fs::PermissionsExt as _;
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("parent");
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let parent = OwnerDirectory::open(&path).unwrap();
    let original = parent.create_private_child("journal").unwrap();
    let identity = original.identity().unwrap();
    std::fs::set_permissions(original.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        parent
            .open_private_child_optional("journal")
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        parent.open_private_child("journal").unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    std::fs::set_permissions(original.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["absent", "journal"] {
        let displaced = temporary.path().join("displaced");
        let moved = displaced.clone();
        let selected = path.clone();
        let result = platform::with_child_named_hook(
            name,
            move || std::fs::rename(&selected, &moved).unwrap(),
            || parent.open_private_child_optional(name),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
        assert!(parent.open_private_child_optional("absent").is_err());
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(parent.open_private_child_optional("absent").is_err());
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&displaced, &path).unwrap();
        assert!(
            parent
                .open_private_child_optional("absent")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            parent
                .open_private_child_optional("journal")
                .unwrap()
                .unwrap()
                .identity()
                .unwrap(),
            identity
        );
    }
}

#[cfg(windows)]
#[test]
fn project_private_child_keeps_native_rename_refusal_absence_and_original_identity() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = OwnerDirectory::open_or_create(temporary.path().join("parent")).unwrap();
    let original = parent.create_private_child("journal").unwrap();
    let identity = original.identity().unwrap();
    original
        .write_atomic("original", b"original bytes", PublishMode::CreateNew)
        .unwrap();
    assert!(std::fs::rename(parent.path(), temporary.path().join("moved-parent")).is_err());
    assert!(std::fs::rename(original.path(), temporary.path().join("moved-child")).is_err());
    assert!(
        parent
            .open_private_child_optional("absent")
            .unwrap()
            .is_none()
    );
    let selected = parent
        .open_private_child_optional("journal")
        .unwrap()
        .unwrap();
    assert_eq!(selected.identity().unwrap(), identity);
    assert_eq!(
        selected.read("original", 64).unwrap().as_slice(),
        b"original bytes"
    );
}
