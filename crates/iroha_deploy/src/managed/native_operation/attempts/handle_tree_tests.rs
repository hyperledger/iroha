//! Fresh handle-only censuses keep exact source identity and later record/codec admissions.

use super::*;
#[cfg(unix)]
use std::io;

#[test]
fn handle_tree_keeps_genuine_rows_fresh_records_and_late_active_decode_refusal() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    canonical_rows(&fixture);
    let history = fixture.history().unwrap();
    let original = history.attempts[0]
        .directory
        .read("authorization.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let identities: Vec<_> = history
        .attempts
        .iter()
        .map(|attempt| attempt.directory.identity().unwrap())
        .collect();
    let counter = parse_digest_tests::Counter::begin();
    history.revalidate_handles().unwrap();
    history.revalidate_retained_handles().unwrap();
    fixture
        .operation
        .read_tree_scope(|tree| history.revalidate_retained_handles_in_tree(Some(tree)))
        .unwrap();
    let counts = counter.finish();
    assert_eq!(counts.reads, 0);
    assert_eq!(counts.decoded, 0);
    assert_eq!(counts.requested, 0);
    assert_eq!(history.reserved_attempt_count(), 3);
    history.require_current().unwrap();
    history.attempts[0]
        .directory
        .write_atomic("authorization.nrt", b"not canonical", PublishMode::Replace)
        .unwrap();
    // Handles authenticate custody only; the unchanged canonical currentness owner must
    // reject new bytes even immediately after a successful tree census.
    history.revalidate_retained_handles().unwrap();
    assert!(matches!(
        history.require_current(),
        Err(crate::managed::Error::Invalid(message))
            if message == "invalid canonical dispatch custody record"
    ));
    history.attempts[0]
        .directory
        .write_atomic("authorization.nrt", &original, PublishMode::Replace)
        .unwrap();
    for allocation in [0, 1] {
        let limits = norito::DecodeLimits::new(
            MAX_RECORD_BYTES,
            MAX_RECORD_BYTES,
            MAX_RECORD_BYTES,
            allocation,
            32,
        );
        norito::core::with_decode_limits_scope(limits, || history.revalidate_handles()).unwrap();
        assert!(
            norito::core::with_decode_limits_scope(limits, || history.require_current()).is_err()
        );
    }
    history.require_current().unwrap();
    assert_eq!(
        history
            .attempts
            .iter()
            .map(|attempt| attempt.directory.identity().unwrap())
            .collect::<Vec<_>>(),
        identities
    );
    assert_eq!(
        history.attempts[0]
            .directory
            .read("authorization.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        original
    );
}

#[cfg(unix)]
#[test]
fn handle_tree_refuses_each_original_native_edge_and_reopened_foreign_fallbacks() {
    use std::os::unix::fs::PermissionsExt as _;
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let attempt = fixture.reserve();
    let mut history = fixture.history().unwrap();
    let original = attempt
        .directory
        .read("authorization.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let root = history.root.as_ref().unwrap().retain().unwrap();
    let row = history.attempts[0].directory.retain().unwrap();
    for (directory, label) in [
        (&fixture.operation, "operation"),
        (&root, "root"),
        (&row, "row"),
    ] {
        let identity = directory.identity().unwrap();
        let permissions = std::fs::metadata(directory.path()).unwrap().permissions();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            matches!(history.revalidate_retained_handles(), Err(crate::managed::Error::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        std::fs::set_permissions(directory.path(), permissions).unwrap();
        history.revalidate_retained_handles().unwrap();
        let displaced = fixture
            ._temporary
            .path()
            .join(format!("held-handle-{label}"));
        std::fs::rename(directory.path(), &displaced).unwrap();
        assert!(
            matches!(history.revalidate_retained_handles(), Err(crate::managed::Error::Io(error)) if error.kind() == io::ErrorKind::NotFound)
        );
        let replacement = PrivateDirectory::open_or_create(directory.path()).unwrap();
        assert_ne!(replacement.identity().unwrap(), identity);
        assert!(
            matches!(history.revalidate_retained_handles(), Err(crate::managed::Error::Io(error)) if error.kind() == io::ErrorKind::Other)
        );
        drop(replacement);
        std::fs::remove_dir(directory.path()).unwrap();
        std::fs::rename(&displaced, directory.path()).unwrap();
        history.revalidate_retained_handles().unwrap();
        assert_eq!(directory.identity().unwrap(), identity);
    }
    // A separately opened same-path row cannot borrow the anchor's native prefix.
    history.attempts[0].directory = PrivateDirectory::open(row.path()).unwrap();
    let result = fixture.operation.read_tree_scope(|tree| {
        std::fs::set_permissions(
            fixture.operation.path(),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        let result = history.revalidate_descendant_handles_in_tree(tree);
        std::fs::set_permissions(
            fixture.operation.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        result
    });
    assert!(
        matches!(result, Err(crate::managed::Error::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
    );
    history.revalidate_retained_handles().unwrap();
    history.attempts[0].directory = row.retain().unwrap();
    let foreign =
        PrivateDirectory::open_or_create(fixture._temporary.path().join("foreign-handles"))
            .unwrap();
    let foreign_row = foreign.create_child("row").unwrap();
    history.attempts[0].directory = foreign_row.retain().unwrap();
    std::fs::set_permissions(foreign.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        matches!(history.revalidate_retained_handles(), Err(crate::managed::Error::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
    );
    std::fs::set_permissions(foreign.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    history.revalidate_retained_handles().unwrap();
    history.attempts[0].directory = row.retain().unwrap();
    history.require_current().unwrap();
    assert_eq!(
        attempt
            .directory
            .read("authorization.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        original
    );
    assert!(!attempt.wallet_path().exists());
}
