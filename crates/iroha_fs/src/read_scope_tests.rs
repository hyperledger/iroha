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

#[test]
fn scoped_owned_optional_read_preserves_bytes_allocation_bounds_and_absence() {
    let (_temporary, directory) = store();
    let (bytes, pointer) = directory
        .read_scope(|reader| {
            let bytes = reader
                .read_optional_owned("first", 5)?
                .expect("present native leaf");
            let pointer = bytes.as_ptr();
            assert_eq!(bytes.as_slice(), b"first");
            assert!(reader.read_optional_owned("missing", 5)?.is_none());
            Ok::<_, io::Error>((bytes, pointer))
        })
        .unwrap();
    assert_eq!(
        bytes.as_ptr(),
        pointer,
        "the owned native buffer moves without copying"
    );
    assert_eq!(bytes.as_slice(), b"first");
    for (name, maximum) in [("first", 4), ("../escape", 5)] {
        let expected = directory.read_optional(name, maximum).unwrap_err();
        let actual = directory
            .read_scope(|reader| reader.read_optional_owned(name, maximum))
            .unwrap_err();
        assert_eq!(actual.kind(), expected.kind());
        assert_eq!(actual.to_string(), expected.to_string());
    }
}

#[cfg(unix)]
#[test]
fn scoped_owned_optional_exit_refuses_replaced_owner_after_success_absence_and_error() {
    use std::os::unix::fs::PermissionsExt as _;
    for outcome in ["present", "absent", "native_error", "semantic_error"] {
        let (temporary, directory) = store();
        let original = directory.path().to_path_buf();
        let displaced = temporary.path().join("displaced-owned");
        let result = directory.read_scope(|reader| {
            let result = match outcome {
                "present" => reader.read_optional_owned("first", 5),
                "absent" => reader.read_optional_owned("missing", 5),
                "native_error" => reader.read_optional_owned("first", 4),
                "semantic_error" => {
                    assert_eq!(
                        reader.read_optional_owned("first", 5)?.unwrap().as_slice(),
                        b"first"
                    );
                    Err(io::Error::other("original owned-read semantic refusal"))
                }
                _ => unreachable!(),
            };
            std::fs::rename(&original, &displaced).unwrap();
            std::fs::create_dir(&original).unwrap();
            std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700)).unwrap();
            result
        });
        let error = result.unwrap_err();
        assert_eq!(
            error.to_string(),
            directory.revalidate().unwrap_err().to_string()
        );
        assert_ne!(error.to_string(), "original owned-read semantic refusal");
        std::fs::remove_dir(&original).unwrap();
        std::fs::rename(&displaced, &original).unwrap();
        assert_eq!(
            directory
                .read_scope(|reader| reader.read_optional_owned("first", 5))
                .unwrap()
                .unwrap()
                .as_slice(),
            b"first"
        );
    }
}

fn sealed_store() -> (tempfile::TempDir, PrivateDirectory) {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap();
    for (name, bytes) in [("first", &b"first"[..]), ("second", &b"second"[..])] {
        let mut file = directory
            .create_retained_private(format!("{name}.partial"), 64)
            .unwrap();
        io::Write::write_all(&mut file, bytes).unwrap();
        file.seal_read_only()
            .unwrap()
            .publish_new_name(name)
            .unwrap();
    }
    (temporary, directory)
}

#[test]
fn scoped_sealed_files_keep_leaf_checks_and_walk_the_ancestry_only_at_scope_exits() {
    let (_temporary, directory) = sealed_store();
    let expected: Vec<_> = ["first", "second"]
        .into_iter()
        .map(|name| {
            directory
                .open_retained_read_only_optional(name, 64)
                .unwrap()
                .unwrap()
                .snapshot()
                .unwrap()
        })
        .collect();
    let before = CustodyWorkV1::current_thread();
    let snapshots = directory
        .read_scope(|scope| {
            let mut snapshots = Vec::new();
            for (name, bytes) in [("first", &b"first"[..]), ("second", &b"second"[..])] {
                let mut file = scope.open_sealed_optional(name, 64)?.unwrap();
                assert_eq!(file.len()?, bytes.len() as u64);
                let mut read = Vec::new();
                io::Read::read_to_end(&mut file, &mut read)?;
                assert_eq!(read, bytes);
                file.revalidate()?;
                snapshots.push(file.snapshot()?);
            }
            assert!(scope.open_sealed_optional("missing", 64)?.is_none());
            // The original extent ceiling is enforced before any byte is read.
            assert!(scope.open_sealed_optional("second", 5).is_err());
            Ok::<_, io::Error>(snapshots)
        })
        .unwrap();
    // Same native snapshots as the per-call capability, from one walk at entry and exit.
    assert_eq!(snapshots, expected);
    assert_eq!(
        CustodyWorkV1::current_thread().since(before).ancestry_walks,
        2
    );
}

#[cfg(unix)]
#[test]
fn scoped_sealed_open_refuses_links_writable_modes_and_replaced_leaves_like_retained_opens() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    for attack in ["hardlink", "symlink", "permissions"] {
        let (_temporary, directory) = sealed_store();
        let original = directory.path().join("first");
        let alias = directory.path().join("alias");
        match attack {
            "hardlink" => fs::hard_link(&original, &alias).unwrap(),
            "symlink" => {
                fs::rename(&original, &alias).unwrap();
                symlink("alias", &original).unwrap();
            }
            "permissions" => {
                fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
            }
            _ => unreachable!(),
        }
        let expected = directory
            .open_retained_read_only_optional("first", 64)
            .unwrap_err();
        let actual = directory
            .read_scope(|scope| scope.open_sealed_optional("first", 64).map(|_| ()))
            .unwrap_err();
        assert_eq!(actual.kind(), expected.kind(), "{attack}");
        assert_eq!(actual.to_string(), expected.to_string(), "{attack}");
    }
    // A leaf changed after its scoped open fails that file's own revalidation, exactly as a
    // per-call retained file does. The mode stays changed, so no timestamp granularity matters.
    let (_temporary, directory) = sealed_store();
    let path = directory.path().join("first");
    let retained = directory
        .open_retained_read_only_optional("first", 64)
        .unwrap()
        .unwrap();
    let refused = directory
        .read_scope(|scope| {
            let file = scope.open_sealed_optional("first", 64)?.unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            file.revalidate()
        })
        .unwrap_err();
    assert_eq!(
        refused.to_string(),
        retained.revalidate().unwrap_err().to_string()
    );
}

#[cfg(unix)]
#[test]
fn scoped_sealed_reads_cannot_leave_after_the_directory_is_displaced() {
    use std::os::unix::fs::PermissionsExt as _;
    let (temporary, directory) = sealed_store();
    let original = directory.path().to_path_buf();
    let displaced = temporary.path().join("displaced-sealed");
    let result = directory.read_scope(|scope| {
        let mut file = scope.open_sealed_optional("first", 64)?.unwrap();
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut file, &mut bytes)?;
        fs::rename(&original, &displaced).unwrap();
        fs::create_dir(&original).unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
        // Leaf checks use only the held directory, so this file still verifies. The
        // transaction's exit observes the displaced ancestry before any result leaves.
        file.revalidate()?;
        Ok::<_, io::Error>(bytes)
    });
    assert_eq!(
        result.unwrap_err().to_string(),
        directory.revalidate().unwrap_err().to_string()
    );
    fs::remove_dir(&original).unwrap();
    fs::rename(&displaced, &original).unwrap();
    let reread = directory
        .read_scope(|scope| {
            let mut bytes = Vec::new();
            io::Read::read_to_end(
                &mut scope.open_sealed_optional("first", 64)?.unwrap(),
                &mut bytes,
            )?;
            Ok::<_, io::Error>(bytes)
        })
        .unwrap();
    assert_eq!(reread, b"first");
}
