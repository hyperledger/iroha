//! Genuine lazy native reads, borrowed-consumer errors and mandatory scope-exit custody.

use super::*;
use std::cell::Cell;
#[cfg(unix)]
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

#[test]
fn scoped_reads_are_lazy_and_preserve_native_bounds_names_and_nested_semantic_errors() {
    let (_temporary, directory) = store();
    let visits = Cell::new(0);
    let length = directory
        .read_scope(|reader| {
            let length = reader.read("first", 5, |bytes| {
                visits.set(visits.get() + 1);
                assert_eq!(bytes, b"first");
                bytes.len()
            })?;
            assert_eq!(visits.get(), 1);
            let second = reader.read("second", 6, |bytes| {
                visits.set(visits.get() + 1);
                assert_eq!(bytes, b"second");
                bytes.len()
            })?;
            Ok::<_, io::Error>(length + second)
        })
        .unwrap();
    assert_eq!(length, 11);
    assert_eq!(visits.get(), 2);
    let first = directory
        .read_scope(|reader| {
            let nested = reader.read("first", 5, |_| {
                Err::<(), _>(io::Error::new(
                    io::ErrorKind::NotFound,
                    "semantic missing source",
                ))
            })?;
            assert_eq!(
                nested.as_ref().unwrap_err().to_string(),
                "semantic missing source"
            );
            nested?;
            reader.read("../unreachable", 6, |_| visits.set(visits.get() + 1))?;
            Ok::<_, io::Error>(())
        })
        .unwrap_err();
    assert_eq!(first.kind(), io::ErrorKind::NotFound);
    assert_eq!(first.to_string(), "semantic missing source");
    assert_eq!(visits.get(), 2);
    for (name, maximum) in [("missing", 5), ("first", 4), ("../escape", 5)] {
        let expected = directory.read(name, maximum).unwrap_err();
        let actual = directory
            .read_scope(|reader| reader.read(name, maximum, <[u8]>::len))
            .unwrap_err();
        assert_eq!(actual.kind(), expected.kind());
        assert_eq!(actual.to_string(), expected.to_string());
    }
    assert_eq!(directory.read_scope(|_| Ok::<_, io::Error>(7)).unwrap(), 7);
    assert_eq!(directory.read("first", 5).unwrap().as_slice(), b"first");
}

#[cfg(unix)]
#[test]
fn scoped_leaf_checks_refuse_real_links_and_permissions_then_retry_original_objects() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    for attack in ["hardlink", "symlink", "permissions"] {
        let (_temporary, directory) = store();
        let original = directory.path().join("first");
        let alias = directory.path().join("alias");
        match attack {
            "hardlink" => fs::hard_link(&original, &alias).unwrap(),
            "symlink" => {
                fs::rename(&original, &alias).unwrap();
                symlink("alias", &original).unwrap();
            }
            "permissions" => {
                fs::set_permissions(&original, fs::Permissions::from_mode(0o644)).unwrap()
            }
            _ => unreachable!(),
        }
        let expected = directory.read("first", 5).unwrap_err();
        let visited = Cell::new(false);
        let actual = directory
            .read_scope(|reader| reader.read("first", 5, |_| visited.set(true)))
            .unwrap_err();
        assert_eq!(actual.kind(), expected.kind(), "{attack}");
        assert!(!visited.get());
        match attack {
            "hardlink" => fs::remove_file(&alias).unwrap(),
            "symlink" => {
                fs::remove_file(&original).unwrap();
                fs::rename(&alias, &original).unwrap();
            }
            "permissions" => {
                fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap()
            }
            _ => unreachable!(),
        }
        assert_eq!(
            directory
                .read_scope(|reader| reader.read("first", 5, <[u8]>::len))
                .unwrap(),
            5
        );
    }
}

#[cfg(unix)]
#[test]
fn scoped_exit_custody_overrides_actual_success_absence_native_and_semantic_errors() {
    use std::os::unix::fs::PermissionsExt as _;
    for outcome in ["success", "absence", "native_error", "semantic_error"] {
        let (temporary, directory) = store();
        let original = directory.path().to_owned();
        let displaced = temporary.path().join("displaced");
        let result = directory.read_scope(|reader| {
            let body = match outcome {
                "success" => reader.read("first", 5, |bytes| {
                    assert_eq!(bytes, b"first");
                    Some(bytes.len())
                }),
                "absence" => match reader.read("missing", 5, |_| Some(0)) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                    other => other,
                },
                "native_error" => reader.read("first", 4, |_| Some(0)),
                "semantic_error" => {
                    reader.read("first", 5, |bytes| assert_eq!(bytes, b"first"))?;
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "original semantic error",
                    ))
                }
                _ => unreachable!(),
            };
            match outcome {
                "success" => assert_eq!(*body.as_ref().unwrap(), Some(5)),
                "absence" => assert_eq!(*body.as_ref().unwrap(), None),
                "native_error" => assert_eq!(
                    body.as_ref().unwrap_err().kind(),
                    io::ErrorKind::InvalidInput
                ),
                "semantic_error" => assert_eq!(
                    body.as_ref().unwrap_err().to_string(),
                    "original semantic error"
                ),
                _ => unreachable!(),
            }
            fs::rename(&original, &displaced).unwrap();
            fs::create_dir(&original).unwrap();
            fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
            body
        });
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::Other,
            "{outcome}"
        );
        fs::remove_dir(&original).unwrap();
        fs::rename(&displaced, &original).unwrap();
        assert_eq!(
            directory
                .read_scope(|reader| reader.read("first", 5, <[u8]>::len))
                .unwrap(),
            5
        );
    }
}

#[cfg(unix)]
#[test]
fn scoped_absence_cannot_mask_real_missing_ancestor_or_exit_permission_refusal() {
    use std::os::unix::fs::PermissionsExt as _;
    for attack in ["missing", "permissions"] {
        let (temporary, directory) = store();
        let original = directory.path().to_owned();
        let displaced = temporary.path().join("displaced");
        let result = directory.read_scope(|reader| {
            assert_eq!(
                reader.read("missing", 5, |_| ()).unwrap_err().kind(),
                io::ErrorKind::NotFound
            );
            match attack {
                "missing" => fs::rename(&original, &displaced).unwrap(),
                "permissions" => {
                    fs::set_permissions(&original, fs::Permissions::from_mode(0o755)).unwrap()
                }
                _ => unreachable!(),
            }
            Ok::<_, io::Error>(None::<usize>)
        });
        assert_eq!(
            result.unwrap_err().kind(),
            if attack == "missing" {
                io::ErrorKind::NotFound
            } else {
                io::ErrorKind::PermissionDenied
            }
        );
        match attack {
            "missing" => fs::rename(&displaced, &original).unwrap(),
            "permissions" => {
                fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap()
            }
            _ => unreachable!(),
        }
        assert_eq!(
            directory
                .read_scope(|reader| reader.read("first", 5, <[u8]>::len))
                .unwrap(),
            5
        );
    }
}

#[cfg(windows)]
#[test]
fn scoped_consumer_keeps_actual_native_deny_write_and_delete_ownership_until_return() {
    let (_temporary, directory) = store();
    let path = directory.path().join("first");
    let moved = directory.path().join("moved");
    let result = directory.read_scope(|reader| {
        let semantic = reader.read("first", 5, |bytes| {
            assert_eq!(bytes, b"first");
            assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
            assert!(std::fs::rename(&path, &moved).is_err());
            Err::<(), _>(io::Error::new(
                io::ErrorKind::InvalidData,
                "semantic refusal",
            ))
        })?;
        semantic
    });
    assert_eq!(result.unwrap_err().to_string(), "semantic refusal");
    assert!(!moved.exists());
    assert!(std::fs::OpenOptions::new().write(true).open(&path).is_ok());
    assert_eq!(directory.read("first", 5).unwrap().as_slice(), b"first");
}
