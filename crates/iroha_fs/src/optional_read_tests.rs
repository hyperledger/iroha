//! Initial-open-only absence, unchanged required errors and native optional read custody.

use super::*;
use std::{cell::Cell, fs};

fn store() -> (tempfile::TempDir, PrivateDirectory) {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap();
    directory
        .write_atomic("record", b"original", PublishMode::CreateNew)
        .unwrap();
    (temporary, directory)
}

#[test]
fn optional_admission_keeps_initial_absence_required_errno_bounds_and_lazy_consumers() {
    let (_temporary, directory) = store();
    let required = directory.read("missing", 0).unwrap_err();
    let original = File::open(directory.path().join("missing")).unwrap_err();
    assert_eq!(required.kind(), original.kind());
    assert_eq!(required.raw_os_error(), original.raw_os_error());
    assert_eq!(required.to_string(), original.to_string());
    assert!(directory.read_optional("missing", 0).unwrap().is_none());
    let consumed = Cell::new(0);
    directory
        .read_scope(|reader| {
            assert_eq!(
                reader.read_optional("missing", 0, |_| consumed.set(100))?,
                None
            );
            assert_eq!(consumed.get(), 0);
            let length = reader.read_optional("record", 8, |bytes| {
                consumed.set(consumed.get() + 1);
                assert_eq!(bytes, b"original");
                bytes.len()
            })?;
            assert_eq!(length, Some(8));
            let semantic = reader
                .read_optional("record", 8, |_| {
                    Err::<(), _>(io::Error::new(io::ErrorKind::NotFound, "semantic missing"))
                })?
                .unwrap();
            assert_eq!(semantic.unwrap_err().to_string(), "semantic missing");
            Ok::<_, io::Error>(())
        })
        .unwrap();
    assert_eq!(consumed.get(), 1);
    for (name, maximum) in [("../invalid", 8), ("record", 7)] {
        let required = directory.read(name, maximum).unwrap_err();
        let optional = directory.read_optional(name, maximum).unwrap_err();
        assert_eq!(optional.kind(), required.kind());
        assert_eq!(optional.to_string(), required.to_string());
        let scoped = directory
            .read_scope(|reader| reader.read_optional(name, maximum, |_| consumed.set(100)))
            .unwrap_err();
        assert_eq!(scoped.kind(), required.kind());
        assert_eq!(consumed.get(), 1);
    }
    let owner = OwnerDirectory::open(directory.path()).unwrap();
    assert!(owner.read_regular_optional("missing", 0).unwrap().is_none());
    assert!(owner.read_private_optional("missing", 0).unwrap().is_none());
    assert_eq!(
        owner
            .read_regular_optional("record", 8)
            .unwrap()
            .unwrap()
            .as_slice(),
        b"original"
    );
    assert_eq!(
        owner
            .read_private_optional("record", 8)
            .unwrap()
            .unwrap()
            .as_slice(),
        b"original"
    );
}

#[cfg(unix)]
#[test]
fn optional_admission_late_named_absence_stays_error_in_every_native_reader_then_restores() {
    for reader in [
        "private_required",
        "owner_required",
        "private_optional",
        "owner_regular",
        "owner_private",
        "scope_optional",
    ] {
        let (_temporary, directory) = store();
        let owner = OwnerDirectory::open(directory.path()).unwrap();
        let original = FileIdentity::of(&directory.open_read("record").unwrap()).unwrap();
        let name = directory.path().join("record");
        let saved = directory.path().join("saved");
        let moved_name = name.clone();
        let moved_saved = saved.clone();
        let consumed = Cell::new(false);
        let refusal = platform::with_readonly_named_hook(
            "record",
            move || fs::rename(moved_name, moved_saved).unwrap(),
            || match reader {
                "private_required" => directory.read("record", 8).map(|_| ()),
                "owner_required" => owner.read_regular("record", 8).map(|_| ()),
                "private_optional" => directory.read_optional("record", 8).map(|_| ()),
                "owner_regular" => owner.read_regular_optional("record", 8).map(|_| ()),
                "owner_private" => owner.read_private_optional("record", 8).map(|_| ()),
                "scope_optional" => directory.read_scope(|view| {
                    view.read_optional("record", 8, |_| consumed.set(true))
                        .map(|_| ())
                }),
                _ => unreachable!(),
            },
        )
        .unwrap_err();
        assert_eq!(refusal.kind(), io::ErrorKind::NotFound, "{reader}");
        assert!(!consumed.get());
        assert!(!name.exists());
        assert!(saved.is_file());
        fs::rename(&saved, &name).unwrap();
        assert_eq!(
            FileIdentity::of(&directory.open_read("record").unwrap()).unwrap(),
            original
        );
        assert_eq!(
            directory
                .read_optional("record", 8)
                .unwrap()
                .unwrap()
                .as_slice(),
            b"original"
        );
        assert_eq!(
            directory
                .read_scope(|view| view.read_optional("record", 8, <[u8]>::len))
                .unwrap(),
            Some(8)
        );
    }
}

#[cfg(unix)]
#[test]
fn optional_admission_standalone_exit_dominates_present_and_late_named_errors() {
    use std::os::unix::fs::PermissionsExt as _;
    for late_absence in [false, true] {
        let (_temporary, directory) = store();
        let original = FileIdentity::of(&directory.open_read("record").unwrap()).unwrap();
        let name = directory.path().join("record");
        let saved = directory.path().join("saved");
        let moved_name = name.clone();
        let moved_saved = saved.clone();
        let parent = directory.path().to_owned();
        let refused = platform::with_readonly_named_hook(
            "record",
            move || {
                if late_absence {
                    fs::rename(moved_name, moved_saved).unwrap();
                }
                fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).unwrap();
            },
            || directory.read_optional("record", 8),
        )
        .unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        if late_absence {
            fs::rename(&saved, &name).unwrap();
        }
        assert_eq!(
            FileIdentity::of(&directory.open_read("record").unwrap()).unwrap(),
            original
        );
        assert_eq!(
            directory
                .read_optional("record", 8)
                .unwrap()
                .unwrap()
                .as_slice(),
            b"original"
        );
    }
}

#[cfg(unix)]
#[test]
fn optional_admission_scope_absence_cannot_escape_changed_ancestor_then_retries() {
    let (temporary, directory) = store();
    let displaced = temporary.path().join("displaced");
    let refused = directory.read_scope(|reader| {
        assert_eq!(reader.read_optional("missing", 0, |_| ())?, None);
        fs::rename(directory.path(), &displaced)?;
        Ok::<_, io::Error>(None::<usize>)
    });
    assert_eq!(refused.unwrap_err().kind(), io::ErrorKind::NotFound);
    assert_eq!(
        directory.read_optional("missing", 0).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    fs::rename(displaced, directory.path()).unwrap();
    assert!(directory.read_optional("missing", 0).unwrap().is_none());
    assert_eq!(directory.read("record", 8).unwrap().as_slice(), b"original");
}

#[cfg(unix)]
#[test]
fn optional_admission_preserves_private_and_regular_leaf_policies_with_original_retry() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    for attack in ["hardlink", "symlink", "mode"] {
        let (_temporary, directory) = store();
        let owner = OwnerDirectory::open(directory.path()).unwrap();
        let original = directory.path().join("record");
        let saved = directory.path().join("saved");
        match attack {
            "hardlink" => fs::hard_link(&original, &saved).unwrap(),
            "symlink" => {
                fs::rename(&original, &saved).unwrap();
                symlink("saved", &original).unwrap();
            }
            "mode" => fs::set_permissions(&original, fs::Permissions::from_mode(0o644)).unwrap(),
            _ => unreachable!(),
        }
        let required = directory.read("record", 8).unwrap_err();
        let optional = directory.read_optional("record", 8).unwrap_err();
        assert_eq!(optional.kind(), required.kind());
        assert_eq!(optional.to_string(), required.to_string());
        assert!(owner.read_private_optional("record", 8).is_err());
        if attack == "mode" {
            assert_eq!(
                owner
                    .read_regular_optional("record", 8)
                    .unwrap()
                    .unwrap()
                    .as_slice(),
                b"original"
            );
        } else {
            assert!(owner.read_regular_optional("record", 8).is_err());
        }
        match attack {
            "hardlink" => fs::remove_file(&saved).unwrap(),
            "symlink" => {
                fs::remove_file(&original).unwrap();
                fs::rename(&saved, &original).unwrap();
            }
            "mode" => fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap(),
            _ => unreachable!(),
        }
        assert_eq!(
            directory
                .read_optional("record", 8)
                .unwrap()
                .unwrap()
                .as_slice(),
            b"original"
        );
        assert_eq!(
            owner
                .read_private_optional("record", 8)
                .unwrap()
                .unwrap()
                .as_slice(),
            b"original"
        );
    }
}

#[cfg(windows)]
#[test]
fn optional_admission_consumer_keeps_original_native_deny_write_and_delete_ownership() {
    let (_temporary, directory) = store();
    let path = directory.path().join("record");
    let moved = directory.path().join("moved");
    assert_eq!(
        directory
            .read_scope(|reader| {
                reader.read_optional("record", 8, |bytes| {
                    assert_eq!(bytes, b"original");
                    assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
                    assert!(fs::rename(&path, &moved).is_err());
                    bytes.len()
                })
            })
            .unwrap(),
        Some(8)
    );
    assert!(!moved.exists());
    assert!(fs::OpenOptions::new().write(true).open(&path).is_ok());
    assert_eq!(
        directory
            .read_optional("record", 8)
            .unwrap()
            .unwrap()
            .as_slice(),
        b"original"
    );
}
