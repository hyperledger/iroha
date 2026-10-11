//! Exact native records and census in one closed borrowed tree-directory read producer.

use super::*;
use std::{cell::Cell, fs};

fn store() -> (tempfile::TempDir, PrivateDirectory, PrivateDirectory) {
    let temporary = tempfile::tempdir().unwrap();
    let root = PrivateDirectory::open_or_create(temporary.path().join("tree")).unwrap();
    let row = root.create_child("row").unwrap();
    row.write_atomic("record", b"original", PublishMode::CreateNew)
        .unwrap();
    (temporary, root, row)
}

#[test]
fn closed_tree_read_keeps_native_caps_inventory_comparison_lazy_order_and_original_retry() {
    let (_temporary, root, row) = store();
    let consumed = Cell::new(0);
    root.read_tree_scope(|tree| {
        tree.read_scope(&row, |reader| {
            let before = reader.entries(1)?;
            assert_eq!(before, [std::ffi::OsString::from("record")]);
            assert_eq!(
                reader.read_optional("absent", 0, |_| consumed.set(100))?,
                None
            );
            assert_eq!(consumed.get(), 0);
            assert_eq!(
                reader.read("record", 8, |bytes| {
                    consumed.set(consumed.get() + 1);
                    assert_eq!(bytes, b"original");
                    bytes.len()
                })?,
                8
            );
            assert_eq!(reader.entries(1)?, before);
            Ok::<_, io::Error>(())
        })
    })
    .unwrap();
    assert_eq!(consumed.get(), 1);
    for (name, maximum) in [("record", 7), ("absent", 8), ("../escape", 8)] {
        let expected = row.read(name, maximum).unwrap_err();
        let actual = root
            .read_tree_scope(|tree| {
                tree.read_scope(&row, |reader| {
                    reader.read(name, maximum, |_| consumed.set(100))
                })
            })
            .unwrap_err();
        assert_eq!(actual.kind(), expected.kind());
        assert_eq!(actual.to_string(), expected.to_string());
        assert_eq!(consumed.get(), 1);
    }
    let native = row.entries(0).unwrap_err();
    let scoped = root
        .read_tree_scope(|tree| tree.read_scope(&row, |reader| reader.entries(0)))
        .unwrap_err();
    assert_eq!(scoped.kind(), native.kind());
    assert_eq!(scoped.to_string(), native.to_string());
    #[cfg(unix)]
    {
        let invalid = root.create_child("invalid-inventory").unwrap();
        fs::write(invalid.path().join("native\\name"), b"invalid").unwrap();
        let native = invalid.entries(1).unwrap_err();
        let scoped = root
            .read_tree_scope(|tree| tree.read_scope(&invalid, |reader| reader.entries(1)))
            .unwrap_err();
        assert_eq!(scoped.kind(), native.kind());
        assert_eq!(scoped.to_string(), native.to_string());
    }
    let empty = root.create_child("empty").unwrap();
    root.read_tree_scope(|tree| {
        tree.read_scope(&empty, |reader| {
            assert!(reader.entries(0)?.is_empty());
            assert!(reader.compare_files(&[])?);
            Ok::<_, io::Error>(())
        })
    })
    .unwrap();
    let mut inputs = [
        PrivateFileComparison {
            name: OsStr::new("record"),
            maximum: 8,
            expected: b"changed",
        },
        PrivateFileComparison {
            name: OsStr::new("../late-invalid"),
            maximum: 0,
            expected: b"",
        },
    ];
    assert!(!row.compare_files(&inputs).unwrap());
    assert!(
        !root
            .read_tree_scope(|tree| tree.read_scope(&row, |reader| reader.compare_files(&inputs)))
            .unwrap()
    );
    inputs[0].expected = b"original";
    let ordinary = row.compare_files(&inputs).unwrap_err();
    let scoped = root
        .read_tree_scope(|tree| tree.read_scope(&row, |reader| reader.compare_files(&inputs)))
        .unwrap_err();
    assert_eq!(scoped.kind(), ordinary.kind());
    assert_eq!(scoped.to_string(), ordinary.to_string());
    let original = [inputs[0]];
    assert!(root.read_tree_scope(|tree| tree.read_scope(&row, |reader| reader.compare_files(&original))).unwrap());
    let semantic = root
        .read_tree_scope(|tree| {
            tree.read_scope(&row, |reader| {
                reader.read("record", 8, |_| {
                    Err::<(), _>(io::Error::new(
                        io::ErrorKind::NotFound,
                        "typed body refusal",
                    ))
                })??;
                reader.read("../must-not-read", 0, |_| consumed.set(100))?;
                Ok::<_, io::Error>(())
            })
        })
        .unwrap_err();
    assert_eq!(semantic.to_string(), "typed body refusal");
    assert_eq!(consumed.get(), 1);
    assert_eq!(row.read("record", 8).unwrap().as_slice(), b"original");
}

#[cfg(unix)]
#[test]
fn closed_tree_read_initial_absence_and_late_named_loss_keep_distinct_native_outcomes() {
    let (_temporary, root, row) = store();
    let record = row.path().join("record");
    let held = row.path().join("held");
    let identity = FileIdentity::of(&row.open_read("record").unwrap()).unwrap();
    let consumed = Cell::new(false);
    assert_eq!(
        root.read_tree_scope(|tree| tree.read_scope(&row, |reader| {
            reader.read_optional("absent", 0, |_| consumed.set(true))
        }))
        .unwrap(),
        None
    );
    let moved_record = record.clone();
    let moved_held = held.clone();
    let refusal = platform::with_readonly_named_hook(
        "record",
        move || {
            fs::rename(moved_record, moved_held).unwrap();
        },
        || {
            root.read_tree_scope(|tree| {
                tree.read_scope(&row, |reader| {
                    reader.read_optional("record", 8, |_| consumed.set(true))
                })
            })
        },
    )
    .unwrap_err();
    assert_eq!(refusal.kind(), io::ErrorKind::NotFound);
    assert!(!consumed.get());
    fs::rename(&held, &record).unwrap();
    assert_eq!(
        FileIdentity::of(&row.open_read("record").unwrap()).unwrap(),
        identity
    );
    assert_eq!(
        root.read_tree_scope(|tree| tree.read_scope(&row, |reader| {
            reader.read_optional("record", 8, <[u8]>::len)
        }))
        .unwrap(),
        Some(8)
    );
}

#[cfg(unix)]
#[test]
fn closed_tree_read_anchor_and_suffix_exit_win_every_ordinary_result_then_restore() {
    use std::os::unix::fs::PermissionsExt as _;
    for target in ["anchor", "suffix"] {
        for outcome in ["some", "none", "native", "semantic", "inventory"] {
            let (_temporary, root, row) = store();
            let path = if target == "anchor" {
                root.path()
            } else {
                row.path()
            };
            let refusal = root
                .read_tree_scope(|tree| {
                    tree.read_scope(&row, |reader| {
                        let body: io::Result<Option<usize>> = match outcome {
                            "some" => reader.read("record", 8, |bytes| Some(bytes.len())),
                            "none" => reader.read_optional("absent", 0, |_| 0),
                            "native" => reader.read("record", 7, |_| Some(0)),
                            "semantic" => Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "typed body refusal",
                            )),
                            "inventory" => reader.entries(0).map(|names| Some(names.len())),
                            _ => unreachable!(),
                        };
                        match outcome {
                            "some" => assert_eq!(*body.as_ref().unwrap(), Some(8)),
                            "none" => assert_eq!(*body.as_ref().unwrap(), None),
                            "native" | "inventory" => assert_eq!(
                                body.as_ref().unwrap_err().kind(),
                                io::ErrorKind::InvalidInput
                            ),
                            "semantic" => assert_eq!(
                                body.as_ref().unwrap_err().to_string(),
                                "typed body refusal"
                            ),
                            _ => unreachable!(),
                        }
                        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
                        body
                    })
                })
                .unwrap_err();
            assert_eq!(
                refusal.kind(),
                io::ErrorKind::PermissionDenied,
                "{target}/{outcome}"
            );
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(
                root.read_tree_scope(|tree| tree.read_scope(&row, |reader| reader.read(
                    "record",
                    8,
                    <[u8]>::len
                )))
                .unwrap(),
                8
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn closed_tree_read_replaced_entry_and_suffix_exit_refuse_without_visiting_later_reads() {
    use std::os::unix::fs::PermissionsExt as _;
    for target in ["anchor", "suffix"] {
        let (temporary, root, row) = store();
        let path = if target == "anchor" {
            root.path()
        } else {
            row.path()
        };
        let displaced = temporary.path().join("displaced");
        let visited = Cell::new(false);
        fs::rename(path, &displaced).unwrap();
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            root.read_tree_scope(|tree| tree.read_scope(&row, |reader| reader.read_optional(
                "absent",
                0,
                |_| visited.set(true)
            )))
            .is_err()
        );
        assert!(!visited.get());
        fs::remove_dir(path).unwrap();
        fs::rename(&displaced, path).unwrap();
        assert_eq!(row.read("record", 8).unwrap().as_slice(), b"original");
        let refusal = root
            .read_tree_scope(|tree| {
                tree.read_scope(&row, |reader| {
                    assert_eq!(reader.read("record", 8, <[u8]>::len)?, 8);
                    fs::rename(path, &displaced).unwrap();
                    fs::create_dir(path).unwrap();
                    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
                    Err::<(), _>(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "original body refusal",
                    ))
                })
            })
            .unwrap_err();
        assert_ne!(refusal.to_string(), "original body refusal");
        fs::remove_dir(path).unwrap();
        fs::rename(&displaced, path).unwrap();
        assert_eq!(row.read("record", 8).unwrap().as_slice(), b"original");
    }
}

#[cfg(unix)]
#[test]
fn closed_tree_read_full_fallback_and_restored_suffix_changes_have_explicit_limits() {
    use std::os::unix::fs::PermissionsExt as _;
    let (temporary, root, row) = store();
    let reopened = PrivateDirectory::open(row.path()).unwrap();
    let foreign_root = PrivateDirectory::open_or_create(temporary.path().join("foreign")).unwrap();
    let foreign = foreign_root.create_child("row").unwrap();
    foreign
        .write_atomic("record", b"foreign", PublishMode::CreateNew)
        .unwrap();
    root.read_tree_scope(|tree| {
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        // A retained descendant shares the anchor, but the anchor itself must still use full checks.
        assert_eq!(
            tree.read_scope(&row, |reader| reader.read("record", 8, <[u8]>::len))?,
            8
        );
        assert_eq!(
            tree.read_scope(&root, |reader| reader.entries(1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let visited = Cell::new(false);
        let ordinary = reopened.read("record", 8).unwrap_err();
        let fallback = tree
            .read_scope(&reopened, |reader| {
                reader.read("record", 8, |_| visited.set(true))
            })
            .unwrap_err();
        assert_eq!(fallback.kind(), ordinary.kind());
        assert_eq!(fallback.to_string(), ordinary.to_string());
        assert!(!visited.get());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(foreign_root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let ordinary = foreign.read("record", 7).unwrap_err();
        let fallback = tree
            .read_scope(&foreign, |reader| {
                reader.read("record", 7, |_| visited.set(true))
            })
            .unwrap_err();
        assert_eq!(fallback.kind(), ordinary.kind());
        assert_eq!(fallback.to_string(), ordinary.to_string());
        assert!(!visited.get());
        fs::set_permissions(foreign_root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        tree.read_scope(&row, |reader| {
            fs::set_permissions(row.path(), fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(
                row.revalidate().unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            // The leaf remains genuine. Fully restored intermediate suffix changes are outside
            // the endpoint observation contract; no atomic-snapshot guarantee is asserted.
            assert_eq!(reader.read("record", 8, <[u8]>::len)?, 8);
            fs::set_permissions(row.path(), fs::Permissions::from_mode(0o700)).unwrap();
            Ok::<_, io::Error>(())
        })
    })
    .unwrap();
    assert_eq!(row.read("record", 8).unwrap().as_slice(), b"original");
}

#[cfg(windows)]
#[test]
fn closed_tree_read_keeps_native_directory_and_leaf_rename_refusals_then_original_retry() {
    let (temporary, root, row) = store();
    let moved_row = temporary.path().join("moved-row");
    let moved_record = row.path().join("moved-record");
    root.read_tree_scope(|tree| {
        tree.read_scope(&row, |reader| {
            assert!(fs::rename(row.path(), &moved_row).is_err());
            assert!(reader.read_optional("absent", 0, |_| ()).unwrap().is_none());
            reader.read("record", 8, |bytes| {
                assert_eq!(bytes, b"original");
                assert!(fs::rename(row.path().join("record"), &moved_record).is_err());
                assert!(
                    fs::OpenOptions::new()
                        .write(true)
                        .open(row.path().join("record"))
                        .is_err()
                );
            })
        })
    })
    .unwrap();
    assert!(!moved_row.exists());
    assert!(!moved_record.exists());
    assert_eq!(row.read("record", 8).unwrap().as_slice(), b"original");
}
