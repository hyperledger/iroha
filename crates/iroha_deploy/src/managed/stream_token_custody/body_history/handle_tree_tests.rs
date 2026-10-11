//! Generated native enrollment histories keep fresh handle and source-prefix custody.

use super::*;
use crate::managed::stream_token_custody::renewal_tests::Fixture;

#[test]
fn generated_body_handle_tree_preserves_native_original_and_retained_reparse() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(60_000);
    let history = BodyHistory::open(&fixture.owner, CustodyPurpose::InitialEnroll)
        .unwrap()
        .unwrap();
    assert_eq!(history.bodies.len(), 1);
    assert!(history.active.is_some());
    let original = history.bodies[0]
        .directory
        .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
        .unwrap();
    let identity = history.bodies[0].directory.identity().unwrap();
    let anchor = history.anchor.completed;
    history.revalidate_handles().unwrap();
    history
        .current_history()
        .unwrap()
        .revalidate_retained_handles()
        .unwrap();
    let current = history.read_current(&fixture.owner).unwrap();
    assert_eq!(current.anchor.completed, anchor);
    assert_eq!(current.bodies[0].directory.identity().unwrap(), identity);
    assert_eq!(current.bodies.len(), history.bodies.len());
    assert_eq!(
        current.bodies[0]
            .directory
            .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap(),
        original
    );
    history.bodies[0]
        .directory
        .write_atomic("original.nrt", b"changed original", PublishMode::Replace)
        .unwrap();
    history.revalidate_handles().unwrap();
    assert!(history.read_current(&fixture.owner).is_err());
    history.bodies[0]
        .directory
        .write_atomic("original.nrt", &original, PublishMode::Replace)
        .unwrap();
    let restored = history.read_current(&fixture.owner).unwrap();
    assert_eq!(restored.anchor.completed, anchor);
    assert_eq!(restored.bodies[0].directory.identity().unwrap(), identity);
}

#[cfg(unix)]
#[test]
fn generated_body_handle_tree_refuses_container_row_and_active_attempt_edges_then_retries() {
    use std::os::unix::fs::PermissionsExt as _;
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(60_000);
    let history = BodyHistory::open(&fixture.owner, CustodyPurpose::InitialEnroll)
        .unwrap()
        .unwrap();
    let active = history.current_history().unwrap();
    let attempt = active.last().unwrap();
    let original = history.bodies[0]
        .directory
        .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
        .unwrap();
    let directories = [
        (history.root.as_ref(), "purpose"),
        (history.body_root.as_ref().unwrap().as_ref(), "container"),
        (history.bodies[0].directory.as_ref(), "body"),
        (attempt.directory(), "active-attempt"),
    ];
    for (directory, label) in directories {
        let identity = directory.identity().unwrap();
        let permissions = std::fs::metadata(directory.path()).unwrap().permissions();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            matches!(history.revalidate_handles(), Err(crate::managed::Error::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied)
        );
        assert!(history.read_current(&fixture.owner).is_err());
        std::fs::set_permissions(directory.path(), permissions).unwrap();
        history.revalidate_handles().unwrap();
        let saved = fixture._temporary.path().join(format!("held-body-{label}"));
        std::fs::rename(directory.path(), &saved).unwrap();
        assert!(
            matches!(history.revalidate_handles(), Err(crate::managed::Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
        );
        let replacement = PrivateDirectory::open_or_create(directory.path()).unwrap();
        assert_ne!(replacement.identity().unwrap(), identity);
        assert!(
            matches!(history.revalidate_handles(), Err(crate::managed::Error::Io(error)) if error.kind() == std::io::ErrorKind::Other)
        );
        assert!(history.read_current(&fixture.owner).is_err());
        drop(replacement);
        std::fs::remove_dir(directory.path()).unwrap();
        std::fs::rename(&saved, directory.path()).unwrap();
        history.revalidate_handles().unwrap();
        let restored = history.read_current(&fixture.owner).unwrap();
        assert_eq!(restored.anchor.completed, history.anchor.completed);
        assert_eq!(directory.identity().unwrap(), identity);
    }
    assert_eq!(
        history.bodies[0]
            .directory
            .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap(),
        original
    );
}
