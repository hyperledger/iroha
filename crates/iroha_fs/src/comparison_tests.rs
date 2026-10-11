//! Genuine native private-file comparisons and post-entry custody refusal controls.

use super::*;
use std::fs;

fn store() -> (tempfile::TempDir, PrivateDirectory) {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap();
    directory
        .write_atomic("first", b"first", PublishMode::CreateNew)
        .unwrap();
    directory
        .write_atomic("second", b"second", PublishMode::CreateNew)
        .unwrap();
    (temporary, directory)
}

fn comparison<'a>(name: &'a str, maximum: usize, expected: &'a [u8]) -> PrivateFileComparison<'a> {
    PrivateFileComparison {
        name: OsStr::new(name),
        maximum,
        expected,
    }
}

#[test]
fn private_file_batch_keeps_exact_bounds_order_and_first_mismatch() {
    let (_temporary, directory) = store();
    directory
        .write_atomic("empty", b"", PublishMode::CreateNew)
        .unwrap();
    let original = [
        comparison("first", 5, b"first"),
        comparison("second", 6, b"second"),
        comparison("empty", 0, b""),
    ];
    assert!(directory.compare_files(&original).unwrap());
    assert!(directory.compare_files(&[]).unwrap());
    // A first mismatch still stops before a later invalid name or missing native file.
    let first = [
        comparison("first", 5, b"other"),
        comparison("../escape", 6, b"second"),
    ];
    assert!(!directory.compare_files(&first).unwrap());
    let late = [original[0], comparison("second", 6, b"change")];
    assert!(!directory.compare_files(&late).unwrap());
    directory
        .write_atomic("second", b"change", PublishMode::Replace)
        .unwrap();
    assert!(!directory.compare_files(&original).unwrap());
    directory
        .write_atomic("second", b"second", PublishMode::Replace)
        .unwrap();
    assert!(directory.compare_files(&original).unwrap());
    assert_eq!(directory.read("first", 5).unwrap().as_slice(), b"first");
    assert_eq!(directory.read("second", 6).unwrap().as_slice(), b"second");
}

#[test]
fn private_file_batch_keeps_native_missing_and_extent_errors_and_original_retry() {
    let (_temporary, directory) = store();
    let original = [
        comparison("first", 5, b"first"),
        comparison("second", 6, b"second"),
    ];
    fs::remove_file(directory.path().join("second")).unwrap();
    let expected = directory.read("second", 6).unwrap_err();
    let actual = directory.compare_files(&original).unwrap_err();
    assert_eq!(actual.kind(), io::ErrorKind::NotFound);
    assert_eq!(actual.kind(), expected.kind());
    directory
        .write_atomic("second", b"second", PublishMode::CreateNew)
        .unwrap();
    assert!(directory.compare_files(&original).unwrap());
    directory
        .write_atomic("second", b"oversize", PublishMode::Replace)
        .unwrap();
    let expected = directory.read("second", 6).unwrap_err();
    let actual = directory.compare_files(&original).unwrap_err();
    assert_eq!(actual.kind(), expected.kind());
    assert_eq!(actual.to_string(), expected.to_string());
    directory
        .write_atomic("second", b"second", PublishMode::Replace)
        .unwrap();
    assert!(directory.compare_files(&original).unwrap());
}

#[test]
fn private_file_batch_rejects_the_original_portable_leaf_namespace() {
    let (_temporary, directory) = store();
    for name in ["", "../escape", "child/file", "file:stream", "CON", "trim."] {
        let expected = directory.read(name, 16).unwrap_err();
        let actual = directory
            .compare_files(&[comparison(name, 16, b"original")])
            .unwrap_err();
        assert_eq!(actual.kind(), expected.kind());
        assert_eq!(actual.to_string(), expected.to_string());
    }
    assert!(
        directory
            .compare_files(&[comparison("first", 5, b"first")])
            .unwrap()
    );
}

#[test]
fn private_read_custody_bracket_keeps_real_body_error_when_custody_agrees() {
    let (_temporary, directory) = store();
    let result = directory.with_read_custody(|| {
        directory
            .inner
            .read_native(OsStr::new("missing"), 16, true, |_| Ok(true))
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
    assert!(
        directory
            .compare_files(&[comparison("first", 5, b"first")])
            .unwrap()
    );
}

#[cfg(unix)]
#[test]
fn private_file_batch_refuses_links_permissions_and_fifo_then_retries_original() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    for attack in ["symlink", "hardlink", "permissions", "fifo"] {
        let (_temporary, directory) = store();
        let first = directory.path().join("first");
        let saved = directory.path().join("saved");
        match attack {
            "symlink" => {
                fs::rename(&first, &saved).unwrap();
                symlink("saved", &first).unwrap();
            }
            "hardlink" => fs::hard_link(&first, &saved).unwrap(),
            "permissions" => {
                fs::set_permissions(&first, fs::Permissions::from_mode(0o644)).unwrap()
            }
            "fifo" => {
                fs::rename(&first, &saved).unwrap();
                assert!(
                    std::process::Command::new("mkfifo")
                        .arg(&first)
                        .status()
                        .unwrap()
                        .success()
                );
            }
            _ => unreachable!(),
        }
        let expected = directory.read("first", 5).unwrap_err();
        let actual = directory
            .compare_files(&[comparison("first", 5, b"first")])
            .unwrap_err();
        assert_eq!(actual.kind(), expected.kind(), "{attack}");
        match attack {
            "symlink" | "fifo" => {
                fs::remove_file(&first).unwrap();
                fs::rename(&saved, &first).unwrap();
            }
            "hardlink" => fs::remove_file(&saved).unwrap(),
            "permissions" => {
                fs::set_permissions(&first, fs::Permissions::from_mode(0o600)).unwrap()
            }
            _ => unreachable!(),
        }
        assert!(
            directory
                .compare_files(&[comparison("first", 5, b"first")])
                .unwrap(),
            "{attack}"
        );
    }
}

#[cfg(unix)]
#[test]
fn private_read_custody_exit_refuses_actual_ancestor_replacement_for_all_body_results() {
    use std::os::unix::fs::PermissionsExt as _;
    for outcome in ["equal", "mismatch", "missing"] {
        let temporary = tempfile::tempdir().unwrap();
        let ancestor = temporary.path().join("ancestor");
        let directory = PrivateDirectory::open_or_create(ancestor.join("private")).unwrap();
        directory
            .write_atomic("first", b"first", PublishMode::CreateNew)
            .unwrap();
        let displaced = temporary.path().join("displaced");
        let actual = directory
            .with_read_custody(|| {
                let result = directory.inner.read_native(
                    OsStr::new(if outcome == "missing" {
                        "missing"
                    } else {
                        "first"
                    }),
                    5,
                    true,
                    |bytes| {
                        Ok(bytes.as_slice()
                            == if outcome == "mismatch" {
                                b"other"
                            } else {
                                b"first"
                            })
                    },
                );
                match outcome {
                    "equal" => assert!(matches!(&result, Ok(true))),
                    "mismatch" => assert!(matches!(&result, Ok(false))),
                    "missing" => assert!(matches!(
                        &result,
                        Err(error) if error.kind() == io::ErrorKind::NotFound
                    )),
                    _ => unreachable!(),
                }
                fs::rename(&ancestor, &displaced).unwrap();
                fs::create_dir(&ancestor).unwrap();
                fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700)).unwrap();
                result
            })
            .unwrap_err();
        assert_eq!(actual.to_string(), changed().to_string(), "{outcome}");
        assert!(
            directory
                .compare_files(&[comparison("first", 5, b"first")])
                .is_err()
        );
        fs::remove_dir(&ancestor).unwrap();
        fs::rename(&displaced, &ancestor).unwrap();
        assert!(
            directory
                .compare_files(&[comparison("first", 5, b"first")])
                .unwrap(),
            "{outcome}"
        );
    }
}

#[cfg(unix)]
#[test]
fn private_read_custody_exit_refuses_actual_permissions_for_all_body_results() {
    use std::os::unix::fs::PermissionsExt as _;
    for outcome in ["equal", "mismatch", "missing"] {
        let (_temporary, directory) = store();
        let actual = directory
            .with_read_custody(|| {
                let result = directory.inner.read_native(
                    OsStr::new(if outcome == "missing" {
                        "missing"
                    } else {
                        "first"
                    }),
                    5,
                    true,
                    |bytes| {
                        Ok(bytes.as_slice()
                            == if outcome == "mismatch" {
                                b"other"
                            } else {
                                b"first"
                            })
                    },
                );
                match outcome {
                    "equal" => assert!(matches!(&result, Ok(true))),
                    "mismatch" => assert!(matches!(&result, Ok(false))),
                    "missing" => assert!(matches!(
                        &result,
                        Err(error) if error.kind() == io::ErrorKind::NotFound
                    )),
                    _ => unreachable!(),
                }
                fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
                result
            })
            .unwrap_err();
        assert_eq!(actual.kind(), io::ErrorKind::PermissionDenied, "{outcome}");
        assert!(directory.compare_files(&[]).is_err());
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            directory
                .compare_files(&[comparison("first", 5, b"first")])
                .unwrap(),
            "{outcome}"
        );
    }
}

#[cfg(target_vendor = "apple")]
#[test]
fn private_file_batch_refuses_extended_private_read_grants_then_retries_original() {
    let (_temporary, directory) = store();
    let path = directory.path().join("first");
    assert!(
        std::process::Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let expected = directory.read("first", 5).unwrap_err();
    let actual = directory
        .compare_files(&[comparison("first", 5, b"first")])
        .unwrap_err();
    assert_eq!(actual.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(actual.kind(), expected.kind());
    assert!(
        std::process::Command::new("chmod")
            .arg("-N")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        directory
            .compare_files(&[comparison("first", 5, b"first")])
            .unwrap()
    );
}

#[cfg(windows)]
#[test]
fn private_file_batch_retains_native_directory_delete_sharing_custody() {
    let (temporary, directory) = store();
    assert!(fs::rename(directory.path(), temporary.path().join("displaced")).is_err());
    assert!(
        directory
            .compare_files(&[
                comparison("first", 5, b"first"),
                comparison("second", 6, b"second")
            ])
            .unwrap()
    );
}
