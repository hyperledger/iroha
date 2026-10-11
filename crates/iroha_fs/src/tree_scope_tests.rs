//! Borrowed tree prefixes preserve original suffix, leaf, inventory and Result custody.

use super::*;
use std::cell::Cell;

fn store() -> (
    tempfile::TempDir,
    PrivateDirectory,
    PrivateDirectory,
    PrivateDirectory,
) {
    let temporary = tempfile::tempdir().unwrap();
    let root = PrivateDirectory::open_or_create(temporary.path().join("tree")).unwrap();
    let first = root.create_child("first").unwrap();
    let second = root.create_child("second").unwrap();
    for row in [&first, &second] {
        row.write_atomic("record", b"original", PublishMode::CreateNew)
            .unwrap();
    }
    (temporary, root, first, second)
}

#[test]
fn tree_records_keep_native_inventory_bounds_lazy_errors_and_original_retry() {
    let (_temporary, root, first, second) = store();
    let visits = Cell::new(0);
    let length = root
        .read_tree_scope(|tree| {
            let mut total = 0;
            for row in [&first, &second] {
                total += tree.read_scope(row, |reader| {
                    let before = reader.entries(1)?;
                    assert_eq!(before, vec![std::ffi::OsString::from("record")]);
                    let length = reader.read("record", 8, |bytes| {
                        assert_eq!(bytes, b"original");
                        visits.set(visits.get() + 1);
                        bytes.len()
                    })?;
                    assert_eq!(reader.entries(1)?, before);
                    Ok::<_, io::Error>(length)
                })?;
                tree.revalidate_directory(row)?;
            }
            Ok::<_, io::Error>(total)
        })
        .unwrap();
    assert_eq!(length, 16);
    assert_eq!(visits.get(), 2);
    for (name, maximum) in [("missing", 8), ("record", 7), ("../escape", 8)] {
        let expected = first.read(name, maximum).unwrap_err();
        let actual = root
            .read_tree_scope(|tree| {
                tree.read_scope(&first, |reader| {
                    reader.read(name, maximum, |_| visits.set(visits.get() + 1))
                })
            })
            .unwrap_err();
        assert_eq!(actual.kind(), expected.kind());
        assert_eq!(actual.to_string(), expected.to_string());
    }
    let refusal = root
        .read_tree_scope(|tree| {
            tree.read_scope(&first, |reader| {
                let nested = reader.read("record", 8, |_| {
                    Err::<(), _>(io::Error::new(
                        io::ErrorKind::NotFound,
                        "typed semantic source refusal",
                    ))
                })?;
                nested?;
                reader.read("later", 8, |_| visits.set(visits.get() + 1))?;
                Ok::<_, io::Error>(())
            })?;
            tree.read_scope(&second, |_| {
                visits.set(visits.get() + 1);
                Ok::<_, io::Error>(())
            })
        })
        .unwrap_err();
    assert_eq!(refusal.kind(), io::ErrorKind::NotFound);
    assert_eq!(refusal.to_string(), "typed semantic source refusal");
    assert_eq!(visits.get(), 2);
    assert_eq!(root.read_tree_scope(|_| Ok::<_, io::Error>(7)).unwrap(), 7);
    let inventory_error = root
        .read_tree_scope(|tree| tree.read_scope(&first, |reader| reader.entries(0)))
        .unwrap_err();
    assert_eq!(inventory_error.kind(), first.entries(0).unwrap_err().kind());
    assert_eq!(first.read("record", 8).unwrap().as_slice(), b"original");
}

#[cfg(unix)]
#[test]
fn tree_shared_native_prefix_is_required_and_restored_changes_have_explicit_temporal_limits() {
    use std::os::unix::fs::PermissionsExt as _;
    let (temporary, root, first, second) = store();
    let retained = first.retain().unwrap();
    let reopened = PrivateDirectory::open(first.path()).unwrap();
    let foreign_root = PrivateDirectory::open_or_create(temporary.path().join("foreign")).unwrap();
    let foreign = foreign_root.create_child("row").unwrap();
    foreign
        .write_atomic("record", b"foreign", PublishMode::CreateNew)
        .unwrap();
    root.read_tree_scope(|tree| {
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            first.revalidate().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let anchor_view = tree.read_scope(&root, |reader| reader.entries(2));
        assert_eq!(
            anchor_view.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        for row in [&first, &retained, &second] {
            assert_eq!(
                tree.read_scope(row, |reader| reader.read("record", 8, <[u8]>::len))?,
                8
            );
        }
        // An independently reopened owner checks existing ancestors with the original
        // public policy: 0755 is safe there, despite the shared anchor's private policy.
        reopened.revalidate().unwrap();
        assert_eq!(reopened.read("record", 8).unwrap().as_slice(), b"original");
        tree.read_scope(&reopened, |reader| {
            reader.read("record", 8, |bytes| assert_eq!(bytes, b"original"))
        })?;
        // Use an actually unsafe ancestor to prove that a nonshared owner falls back
        // to the same complete native ancestry checks, before visiting the consumer.
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let ordinary = reopened.revalidate().unwrap_err();
        assert_eq!(ordinary.kind(), io::ErrorKind::PermissionDenied);
        let visited = Cell::new(false);
        let fallback = tree.read_scope(&reopened, |reader| {
            reader.read("record", 8, |_| visited.set(true))
        });
        let scoped = fallback.unwrap_err();
        assert_eq!(scoped.kind(), ordinary.kind());
        assert_eq!(scoped.to_string(), ordinary.to_string());
        assert!(!visited.get());
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(foreign_root.path(), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        let fallback = tree.read_scope(&foreign, |reader| reader.read("record", 7, |_| ()));
        assert_eq!(
            fallback.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        std::fs::set_permissions(foreign_root.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        Ok::<_, io::Error>(())
    })
    .unwrap();
    assert_eq!(
        root.entries(2).unwrap(),
        vec![
            std::ffi::OsString::from("first"),
            std::ffi::OsString::from("second")
        ]
    );
    first.revalidate().unwrap();
    foreign.revalidate().unwrap();
}

#[cfg(unix)]
#[test]
fn tree_persistent_ancestor_result_and_suffix_leaf_refusals_restore_exact_original_sources() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    for attack in ["permission", "missing", "replacement"] {
        for outcome in ["some", "none", "native_error", "semantic_error"] {
            let (temporary, root, first, _second) = store();
            let path = root.path().to_owned();
            let displaced = temporary.path().join("displaced");
            let refused = root
                .read_tree_scope(|tree| {
                    let body = tree.read_scope(&first, |reader| match outcome {
                        "some" => reader.read("record", 8, |bytes| Some(bytes.len())),
                        "none" => match reader.read("missing", 8, |_| Some(0)) {
                            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                            other => other,
                        },
                        "native_error" => reader.read("record", 7, |_| Some(0)),
                        "semantic_error" => reader
                            .read("record", 8, |bytes| assert_eq!(bytes, b"original"))
                            .and_then(|()| {
                                Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "real typed body refusal",
                                ))
                            }),
                        _ => unreachable!(),
                    });
                    match outcome {
                        "some" => assert_eq!(*body.as_ref().unwrap(), Some(8)),
                        "none" => assert_eq!(*body.as_ref().unwrap(), None),
                        "native_error" => assert_eq!(
                            body.as_ref().unwrap_err().kind(),
                            io::ErrorKind::InvalidInput
                        ),
                        "semantic_error" => assert_eq!(
                            body.as_ref().unwrap_err().to_string(),
                            "real typed body refusal"
                        ),
                        _ => unreachable!(),
                    }
                    match attack {
                        "permission" => {
                            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                                .unwrap()
                        }
                        "missing" | "replacement" => {
                            std::fs::rename(&path, &displaced).unwrap();
                            if attack == "replacement" {
                                std::fs::create_dir(&path).unwrap();
                                std::fs::set_permissions(
                                    &path,
                                    std::fs::Permissions::from_mode(0o700),
                                )
                                .unwrap();
                            }
                        }
                        _ => unreachable!(),
                    }
                    body
                })
                .unwrap_err();
            assert_eq!(
                refused.kind(),
                match attack {
                    "permission" => io::ErrorKind::PermissionDenied,
                    "missing" => io::ErrorKind::NotFound,
                    _ => io::ErrorKind::Other,
                }
            );
            match attack {
                "permission" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap()
                }
                "missing" | "replacement" => {
                    if attack == "replacement" {
                        std::fs::remove_dir(&path).unwrap();
                    }
                    std::fs::rename(&displaced, &path).unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(first.read("record", 8).unwrap().as_slice(), b"original");
        }
    }
    // Closing each row overrides every real typed leaf result observed inside its callback.
    for outcome in ["some", "none", "native_error", "semantic_error"] {
        let (_temporary, root, first, _second) = store();
        let refused = root
            .read_tree_scope(|tree| {
                tree.read_scope(&first, |reader| {
                    let body = match outcome {
                        "some" => reader.read("record", 8, |bytes| Some(bytes.len())),
                        "none" => match reader.read("missing", 8, |_| Some(0)) {
                            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                            other => other,
                        },
                        "native_error" => reader.read("record", 7, |_| Some(0)),
                        "semantic_error" => reader
                            .read("record", 8, |bytes| assert_eq!(bytes, b"original"))
                            .and_then(|()| {
                                Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "row semantic refusal",
                                ))
                            }),
                        _ => unreachable!(),
                    };
                    match outcome {
                        "some" => assert_eq!(*body.as_ref().unwrap(), Some(8)),
                        "none" => assert_eq!(*body.as_ref().unwrap(), None),
                        "native_error" => assert_eq!(
                            body.as_ref().unwrap_err().kind(),
                            io::ErrorKind::InvalidInput
                        ),
                        "semantic_error" => assert_eq!(
                            body.as_ref().unwrap_err().to_string(),
                            "row semantic refusal"
                        ),
                        _ => unreachable!(),
                    }
                    std::fs::set_permissions(first.path(), std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                    body
                })
            })
            .unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
        std::fs::set_permissions(first.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(first.read("record", 8).unwrap().as_slice(), b"original");
    }
    for attack in ["suffix", "hardlink", "symlink", "leaf_permission"] {
        let (_temporary, root, first, _second) = store();
        let record = first.path().join("record");
        let alias = first.path().join("alias");
        let visited = Cell::new(false);
        let refused = root
            .read_tree_scope(|tree| {
                match attack {
                    "suffix" => std::fs::set_permissions(
                        first.path(),
                        std::fs::Permissions::from_mode(0o755),
                    )
                    .unwrap(),
                    "hardlink" => std::fs::hard_link(&record, &alias).unwrap(),
                    "symlink" => {
                        std::fs::rename(&record, &alias).unwrap();
                        symlink("alias", &record).unwrap();
                    }
                    "leaf_permission" => {
                        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o644))
                            .unwrap()
                    }
                    _ => unreachable!(),
                }
                tree.read_scope(&first, |reader| {
                    reader.read("record", 8, |_| visited.set(true))
                })
            })
            .unwrap_err();
        assert_eq!(refused.kind(), first.read("record", 8).unwrap_err().kind());
        assert!(!visited.get());
        match attack {
            "suffix" => {
                std::fs::set_permissions(first.path(), std::fs::Permissions::from_mode(0o700))
                    .unwrap()
            }
            "hardlink" => std::fs::remove_file(&alias).unwrap(),
            "symlink" => {
                std::fs::remove_file(&record).unwrap();
                std::fs::rename(&alias, &record).unwrap();
            }
            "leaf_permission" => {
                std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap()
            }
            _ => unreachable!(),
        }
        assert_eq!(
            root.read_tree_scope(|tree| tree.read_scope(&first, |reader| reader.read(
                "record",
                8,
                <[u8]>::len
            )))
            .unwrap(),
            8
        );
    }
}

#[cfg(windows)]
#[test]
fn tree_leaf_consumer_keeps_native_deny_write_and_delete_ownership() {
    let (_temporary, root, first, _second) = store();
    let record = first.path().join("record");
    let moved = first.path().join("moved");
    root.read_tree_scope(|tree| {
        tree.read_scope(&first, |reader| {
            reader.read("record", 8, |bytes| {
                assert_eq!(bytes, b"original");
                assert!(
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&record)
                        .is_err()
                );
                assert!(std::fs::rename(&record, &moved).is_err());
            })
        })
    })
    .unwrap();
    assert!(!moved.exists());
    assert!(
        std::fs::OpenOptions::new()
            .write(true)
            .open(&record)
            .is_ok()
    );
}

#[test]
fn tree_comparison_reuses_standalone_lazy_names_bounds_empty_and_original_retry() {
    let (_temporary, root, first, _second) = store();
    let original = [PrivateFileComparison {
        name: OsStr::new("record"),
        maximum: 8,
        expected: b"original",
    }];
    let lazy = [
        PrivateFileComparison {
            name: OsStr::new("record"),
            maximum: 8,
            expected: b"different",
        },
        PrivateFileComparison {
            name: OsStr::new("missing"),
            maximum: 1,
            expected: b"x",
        },
    ];
    assert!(!first.compare_files(&lazy).unwrap());
    assert!(
        !root
            .read_tree_scope(|tree| tree.read_scope(&first, |reader| reader.compare_files(&lazy)))
            .unwrap()
    );
    for inputs in [
        vec![PrivateFileComparison {
            name: OsStr::new("missing"),
            maximum: 1,
            expected: b"x",
        }],
        vec![PrivateFileComparison {
            name: OsStr::new("record"),
            maximum: 7,
            expected: b"original",
        }],
        vec![PrivateFileComparison {
            name: OsStr::new("../record"),
            maximum: 8,
            expected: b"original",
        }],
    ] {
        let standalone = first.compare_files(&inputs).unwrap_err();
        let scoped = root
            .read_tree_scope(|tree| tree.read_scope(&first, |reader| reader.compare_files(&inputs)))
            .unwrap_err();
        assert_eq!(standalone.kind(), scoped.kind());
        assert_eq!(standalone.to_string(), scoped.to_string());
    }
    assert!(first.compare_files(&[]).unwrap());
    assert!(
        root.read_tree_scope(|tree| tree.read_scope(&first, |reader| reader.compare_files(&[])))
            .unwrap()
    );
    assert!(first.compare_files(&original).unwrap());
    assert!(
        root.read_tree_scope(
            |tree| tree.read_scope(&first, |reader| reader.compare_files(&original))
        )
        .unwrap()
    );
}

#[cfg(unix)]
#[test]
fn tree_comparison_closes_actual_boolean_error_and_empty_outcomes_before_anchor_retry() {
    use std::os::unix::fs::PermissionsExt as _;
    for outcome in ["equal", "different", "missing", "empty"] {
        let (_temporary, root, first, _second) = store();
        let inputs = match outcome {
            "equal" => vec![PrivateFileComparison {
                name: OsStr::new("record"),
                maximum: 8,
                expected: b"original",
            }],
            "different" => vec![PrivateFileComparison {
                name: OsStr::new("record"),
                maximum: 8,
                expected: b"different",
            }],
            "missing" => vec![PrivateFileComparison {
                name: OsStr::new("missing"),
                maximum: 1,
                expected: b"x",
            }],
            _ => vec![],
        };
        let refused = root
            .read_tree_scope(|tree| {
                let body = tree.read_scope(&first, |reader| reader.compare_files(&inputs));
                match outcome {
                    "equal" | "empty" => assert!(*body.as_ref().unwrap()),
                    "different" => assert!(!*body.as_ref().unwrap()),
                    _ => assert_eq!(body.as_ref().unwrap_err().kind(), io::ErrorKind::NotFound),
                }
                std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755))
                    .unwrap();
                body
            })
            .unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let restored = [PrivateFileComparison {
            name: OsStr::new("record"),
            maximum: 8,
            expected: b"original",
        }];
        assert!(first.compare_files(&restored).unwrap());
        assert!(
            root.read_tree_scope(
                |tree| tree.read_scope(&first, |reader| reader.compare_files(&restored))
            )
            .unwrap()
        );
    }
}
