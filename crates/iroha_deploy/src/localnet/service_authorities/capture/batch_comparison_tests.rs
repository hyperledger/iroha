//! Original captured-input comparison order, private custody and exact-source retry.

use super::*;
use iroha_fs::PublishMode;

fn captured() -> (tempfile::TempDir, CapturedDirectory) {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap();
    directory
        .write_atomic("first", b"first", PublishMode::CreateNew)
        .unwrap();
    directory
        .write_atomic("second", b"second", PublishMode::CreateNew)
        .unwrap();
    let mut captured = CapturedDirectory::new(directory, None).unwrap();
    let mut total = 0;
    captured
        .capture("first", 5, ConfigFileAccess::Private, &mut total)
        .unwrap();
    captured
        .capture("second", 6, ConfigFileAccess::Public, &mut total)
        .unwrap();
    (temporary, captured)
}

#[test]
fn captured_private_batch_keeps_first_mismatch_and_native_errors_before_retry() {
    let (_temporary, captured) = captured();
    captured.compare_inputs().unwrap();
    captured
        .directory
        .write_atomic("first", b"other", PublishMode::Replace)
        .unwrap();
    std::fs::remove_file(captured.directory.path().join("second")).unwrap();
    assert_eq!(
        captured.compare_inputs().unwrap_err().to_string(),
        invalid().to_string()
    );
    captured
        .directory
        .write_atomic("first", b"first", PublishMode::Replace)
        .unwrap();
    assert!(
        matches!(captured.compare_inputs(), Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound)
    );
    captured
        .directory
        .write_atomic("second", b"second", PublishMode::CreateNew)
        .unwrap();
    captured.compare_inputs().unwrap();
    captured
        .directory
        .write_atomic("second", b"oversize", PublishMode::Replace)
        .unwrap();
    let original = captured.directory.read("second", 6).unwrap_err();
    assert!(
        matches!(captured.compare_inputs(), Err(Error::Io(error)) if error.kind() == original.kind() && error.to_string() == original.to_string())
    );
    captured
        .directory
        .write_atomic("second", b"second", PublishMode::Replace)
        .unwrap();
    captured.compare_inputs().unwrap();
    assert_eq!(captured.read("first", 5).unwrap(), b"first");
    assert_eq!(captured.read("second", 6).unwrap(), b"second");
}

#[cfg(unix)]
#[test]
fn captured_public_loader_input_keeps_private_native_admission_and_original_retry() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_temporary, captured) = captured();
    assert_eq!(captured.inputs[1].access, ConfigFileAccess::Public);
    let path = captured.directory.path().join("second");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        matches!(captured.compare_inputs(), Err(Error::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    captured.compare_inputs().unwrap();
    assert_eq!(captured.read("second", 6).unwrap(), b"second");
}

#[cfg(unix)]
#[test]
fn captured_empty_input_directory_keeps_its_existing_outer_custody_owner() {
    use std::os::unix::fs::PermissionsExt as _;
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap();
    let captured = CapturedDirectory::new(directory, None).unwrap();
    captured.compare_inputs().unwrap();
    std::fs::set_permissions(
        captured.directory.path(),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    // The complete profile's unchanged outer inventories own even empty directory custody.
    // Empty byte comparison does not add another directory read or replace that owner.
    captured.compare_inputs().unwrap();
    assert!(captured.revalidate().is_err());
    std::fs::set_permissions(
        captured.directory.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    captured.revalidate().unwrap();
    captured.compare_inputs().unwrap();
}
