//! Borrowed tree prefixes preserve original suffix, leaf, inventory and Result custody.

use super::*;
use std::cell::{Cell, RefCell};

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

#[test]
fn tree_operation_reader_and_descendants_keep_one_original_custody_recipe() {
    let (_temporary, root, operation, _other) = store();
    let child = operation.create_child("attempt").unwrap();
    child
        .write_atomic("row", b"row", PublishMode::CreateNew)
        .unwrap();
    let order = RefCell::new(Vec::new());
    let value = root
        .read_tree_scope(|tree| {
            tree.read_scope_with_tree(&operation, |tree, reader| {
                let before = reader.entries(2)?;
                reader.read("record", 8, |bytes| {
                    assert_eq!(bytes, b"original");
                    order.borrow_mut().push(1);
                })?;
                tree.read_scope(&child, |row| {
                    row.read("row", 3, |bytes| {
                        assert_eq!(bytes, b"row");
                        order.borrow_mut().push(2);
                    })
                })?;
                reader.read("record", 8, |bytes| {
                    assert_eq!(bytes, b"original");
                    order.borrow_mut().push(3);
                })?;
                assert_eq!(reader.entries(2)?, before);
                Ok::<_, io::Error>(8)
            })
        })
        .unwrap();
    assert_eq!(value, 8);
    assert_eq!(*order.borrow(), [1, 2, 3]);
    for (name, maximum) in [("missing", 8), ("record", 7), ("../escape", 8)] {
        let ordinary = operation.read(name, maximum).unwrap_err();
        let shared = root
            .read_tree_scope(|tree| {
                tree.read_scope_with_tree(&operation, |_, reader| {
                    reader.read(name, maximum, |_| ())
                })
            })
            .unwrap_err();
        assert_eq!(shared.kind(), ordinary.kind());
        assert_eq!(shared.to_string(), ordinary.to_string());
    }
    let error = root
        .read_tree_scope(|tree| {
            tree.read_scope_with_tree(&operation, |tree, reader| {
                reader.read("record", 8, |_| ())?;
                tree.read_scope(&child, |_| {
                    Err::<(), _>(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "nested native reader semantic refusal",
                    ))
                })
            })
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "nested native reader semantic refusal");
    operation.revalidate().unwrap();
    child.revalidate().unwrap();
}

#[cfg(unix)]
#[test]
fn tree_operation_reader_closes_renamed_replaced_and_unsafe_originals_on_every_result() {
    use std::os::unix::fs::PermissionsExt as _;
    for attack in ["permission", "missing", "replacement"] {
        for result_kind in ["some", "none", "native_error", "semantic_error"] {
            let (temporary, root, operation, _other) = store();
            let child = operation.create_child("attempt").unwrap();
            child
                .write_atomic("row", b"row", PublishMode::CreateNew)
                .unwrap();
            let path = operation.path().to_owned();
            let moved = temporary.path().join("moved-original-operation");
            let result = root.read_tree_scope(|tree| {
                tree.read_scope_with_tree(&operation, |tree, reader| {
                    tree.read_scope(&child, |row| row.read("row", 3, |_| ()))?;
                    let value = match result_kind {
                        "some" => reader.read("record", 8, |_| Some(8)),
                        "none" => reader.read_optional("absent", 8, |_| 8),
                        "native_error" => reader.read("record", 7, |_| Some(8)),
                        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "inner refusal")),
                    };
                    match attack {
                        "permission" => {
                            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                                .unwrap()
                        }
                        _ => {
                            std::fs::rename(&path, &moved).unwrap();
                            if attack == "replacement" {
                                std::fs::create_dir(&path).unwrap();
                                std::fs::set_permissions(
                                    &path,
                                    std::fs::Permissions::from_mode(0o700),
                                )
                                .unwrap();
                            }
                        }
                    }
                    value
                })
            });
            match attack {
                "permission" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap()
                }
                _ => {
                    if attack == "replacement" {
                        std::fs::remove_dir(&path).unwrap();
                    }
                    std::fs::rename(&moved, &path).unwrap();
                }
            }
            let error = result.unwrap_err();
            assert_eq!(
                error.kind(),
                match attack {
                    "permission" => io::ErrorKind::PermissionDenied,
                    "missing" => io::ErrorKind::NotFound,
                    _ => io::ErrorKind::Other,
                }
            );
            assert_eq!(operation.read("record", 8).unwrap().as_slice(), b"original");
            assert_eq!(child.read("row", 3).unwrap().as_slice(), b"row");
        }
    }
}

#[cfg(unix)]
#[test]
fn tree_operation_reader_reopened_owner_keeps_full_ancestry_fallback() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_temporary, root, operation, _other) = store();
    let reopened = PrivateDirectory::open(operation.path()).unwrap();
    let visited = Cell::new(false);
    root.read_tree_scope(|tree| {
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let expected = reopened.revalidate().unwrap_err();
        let actual = tree.read_scope_with_tree(&reopened, |_, reader| {
            reader.read("record", 8, |_| visited.set(true))
        });
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let actual = actual.unwrap_err();
        assert_eq!(expected.kind(), actual.kind());
        assert_eq!(expected.to_string(), actual.to_string());
        assert!(!visited.get());
        Ok::<_, io::Error>(())
    })
    .unwrap();
}

#[test]
fn root_tree_reader_keeps_lazy_leaves_and_removes_only_duplicate_root_walks() {
    let (_temporary, root, first, _second) = store();
    root.write_atomic("record", b"root", PublishMode::CreateNew)
        .unwrap();
    let order = RefCell::new(Vec::new());
    let inspect = |tree: &mut PrivateReadTreeScope<'_>, reader: &mut PrivateReadScope<'_>| {
        let names = reader.entries(3)?;
        reader.read("record", 4, |bytes| {
            assert_eq!(bytes, b"root");
            order.borrow_mut().push(1);
        })?;
        tree.read_scope(&first, |child| {
            child.read("record", 8, |bytes| {
                assert_eq!(bytes, b"original");
                order.borrow_mut().push(2);
            })
        })?;
        reader.read("record", 4, |bytes| {
            assert_eq!(bytes, b"root");
            order.borrow_mut().push(3);
        })?;
        assert_eq!(reader.entries(3)?, names);
        Ok::<_, io::Error>(())
    };
    let before = CustodyWorkV1::current_thread();
    root.revalidate().unwrap();
    let root_walk = CustodyWorkV1::current_thread().since(before);
    assert_eq!(root_walk.ancestry_walks, 1);
    let before = CustodyWorkV1::current_thread();
    root.read_tree_scope(|tree| root.read_scope(|reader| inspect(tree, reader)))
        .unwrap();
    let nested = CustodyWorkV1::current_thread().since(before);
    assert_eq!(*order.borrow(), [1, 2, 3]);
    order.borrow_mut().clear();
    let before = CustodyWorkV1::current_thread();
    root.read_tree_scope_with_root(inspect).unwrap();
    let shared = CustodyWorkV1::current_thread().since(before);
    assert_eq!(*order.borrow(), [1, 2, 3]);
    assert_eq!(nested.ancestry_walks, shared.ancestry_walks + 2);
    assert_eq!(
        nested.ancestry_opens,
        shared.ancestry_opens + 2 * root_walk.ancestry_opens
    );
    assert_eq!(shared.ancestry_walks, 4);
    for delegate in ["tree", "root", "both"] {
        let before = CustodyWorkV1::current_thread();
        let value = match delegate {
            "tree" => root.read_tree_scope(|_| Ok::<_, io::Error>(7)),
            "root" => root.read_scope(|_| Ok::<_, io::Error>(7)),
            _ => root.read_tree_scope_with_root(|_, _| Ok::<_, io::Error>(7)),
        }
        .unwrap();
        assert_eq!(value, 7);
        let work = CustodyWorkV1::current_thread().since(before);
        assert_eq!(work.ancestry_walks, 2);
        assert_eq!(work.ancestry_opens, 2 * root_walk.ancestry_opens);
    }
    for (name, maximum) in [("missing", 4), ("record", 3), ("../escape", 4)] {
        let ordinary = root.read(name, maximum).unwrap_err();
        let shared = root
            .read_tree_scope_with_root(|_, reader| reader.read(name, maximum, |_| ()))
            .unwrap_err();
        assert_eq!(shared.kind(), ordinary.kind());
        assert_eq!(shared.to_string(), ordinary.to_string());
    }
    let ordinary = root.entries(2).unwrap_err();
    let shared = root
        .read_tree_scope_with_root(|_, reader| reader.entries(2))
        .unwrap_err();
    assert_eq!(shared.kind(), ordinary.kind());
    assert_eq!(shared.to_string(), ordinary.to_string());
    order.borrow_mut().clear();
    let error = root
        .read_tree_scope_with_root(|tree, reader| {
            reader.read("record", 4, |_| order.borrow_mut().push(1))?;
            let refused: io::Result<()> = Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "original typed root refusal",
            ));
            refused?;
            tree.read_scope(&first, |child| {
                child.read("record", 8, |_| order.borrow_mut().push(2))
            })
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "original typed root refusal");
    assert_eq!(*order.borrow(), [1]);
}

#[cfg(unix)]
#[test]
fn root_tree_reader_closes_original_root_on_every_result_and_retries() {
    use std::os::unix::fs::PermissionsExt as _;
    for attack in ["permission", "missing", "replacement"] {
        for result_kind in ["some", "none", "native_error", "semantic_error"] {
            let (temporary, root, first, _second) = store();
            root.write_atomic("record", b"root", PublishMode::CreateNew)
                .unwrap();
            let path = root.path().to_owned();
            let moved = temporary.path().join("moved-original-root");
            let result = root.read_tree_scope_with_root(|tree, reader| {
                tree.read_scope(&first, |child| child.read("record", 8, |_| ()))?;
                let value = match result_kind {
                    "some" => reader.read("record", 4, |_| Some(4)),
                    "none" => reader.read_optional("absent", 4, |_| 4),
                    "native_error" => reader.read("record", 3, |_| Some(4)),
                    _ => Err(io::Error::new(io::ErrorKind::InvalidData, "inner refusal")),
                };
                match result_kind {
                    "some" => assert_eq!(*value.as_ref().unwrap(), Some(4)),
                    "none" => assert_eq!(*value.as_ref().unwrap(), None),
                    "native_error" => assert_eq!(
                        value.as_ref().unwrap_err().kind(),
                        io::ErrorKind::InvalidInput
                    ),
                    _ => assert_eq!(value.as_ref().unwrap_err().to_string(), "inner refusal"),
                }
                match attack {
                    "permission" => {
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                            .unwrap()
                    }
                    _ => {
                        std::fs::rename(&path, &moved).unwrap();
                        if attack == "replacement" {
                            std::fs::create_dir(&path).unwrap();
                            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                                .unwrap();
                        }
                    }
                }
                value
            });
            match attack {
                "permission" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap()
                }
                _ => {
                    if attack == "replacement" {
                        std::fs::remove_dir(&path).unwrap();
                    }
                    std::fs::rename(&moved, &path).unwrap();
                }
            }
            assert_eq!(
                result.unwrap_err().kind(),
                match attack {
                    "permission" => io::ErrorKind::PermissionDenied,
                    "missing" => io::ErrorKind::NotFound,
                    _ => io::ErrorKind::Other,
                }
            );
            root.read_tree_scope_with_root(|tree, reader| {
                reader.read("record", 4, |bytes| assert_eq!(bytes, b"root"))?;
                tree.read_scope(&first, |child| child.read("record", 8, |_| ()))
            })
            .unwrap();
        }
    }
}

#[cfg(unix)]
#[test]
fn root_tree_reader_entry_and_explicit_anchor_reads_keep_full_native_custody() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_temporary, root, first, _second) = store();
    root.write_atomic("record", b"root", PublishMode::CreateNew)
        .unwrap();
    let reopened = PrivateDirectory::open(root.path()).unwrap();
    let entered = Cell::new(false);
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let result = root.read_tree_scope_with_root(|_, _| {
        entered.set(true);
        Ok::<_, io::Error>(())
    });
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    assert!(!entered.get());
    struct DroppedValue<'a>(&'a Cell<bool>);
    impl Drop for DroppedValue<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    let dropped = Cell::new(false);
    let result: io::Result<_> = root.read_tree_scope_with_root(|_, _| {
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        Ok(DroppedValue(&dropped))
    });
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(result, Err(ref error) if error.kind() == io::ErrorKind::PermissionDenied));
    assert!(
        dropped.get(),
        "exit refusal must dispose of the completed callback value"
    );
    root.read_tree_scope_with_root(|tree, reader| {
        // This temporary change is inside the common root fence. The original root reader
        // keeps native leaf checks, while an explicit anchor read still checks full ancestry.
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        reader.read("record", 4, |bytes| assert_eq!(bytes, b"root"))?;
        tree.read_scope(&first, |child| child.read("record", 8, |_| ()))?;
        for anchor in [&root, &reopened] {
            let expected = anchor.revalidate().unwrap_err();
            let actual = tree.read_scope(anchor, |_| {
                entered.set(true);
                Ok::<_, io::Error>(())
            });
            assert_eq!(actual.as_ref().unwrap_err().kind(), expected.kind());
            assert_eq!(actual.unwrap_err().to_string(), expected.to_string());
            assert!(!entered.get());
        }
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        Ok::<_, io::Error>(())
    })
    .unwrap();
}
