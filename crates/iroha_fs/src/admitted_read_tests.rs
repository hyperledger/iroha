//! Original owned record admission, lazy allocation and closed native custody.

use super::*;
use std::{cell::Cell, fs};

fn store() -> (tempfile::TempDir, PrivateDirectory) {
    let root = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(root.path().join("private")).unwrap();
    directory
        .write_atomic("record", b"original", PublishMode::CreateNew)
        .unwrap();
    (root, directory)
}

fn read(reader: &mut PrivateReadScope<'_>, name: &str) -> io::Result<Option<Vec<u8>>> {
    reader.read_admitted(
        name,
        8,
        (
            |extent| usize::try_from(extent).map_err(io::Error::other),
            |length| Ok(vec![0; length]),
        ),
        |_| Ok(()),
        (
            |error| error,
            |named| {
                io::Error::other(if named {
                    "named object changed"
                } else {
                    "read object changed"
                })
            },
        ),
    )
}

#[test]
fn admitted_owned_reads_keep_extent_allocation_order_absence_and_original_owner_join() {
    let (_root, directory) = store();
    let lock = directory.create_lock("lock").unwrap();
    let other = directory.create_lock("other-lock").unwrap();
    let allocations = Cell::new(0);
    let middles = Cell::new(0);
    directory
        .read_scope(|reader| {
            reader.require_same_file("lock", &lock, || io::Error::other("wrong original"))?;
            assert!(
                reader
                    .require_same_file("lock", &other, || io::Error::other("wrong original"))
                    .is_err()
            );
            let missing = reader.read_admitted(
                "missing",
                8,
                (
                    |_| panic!("missing leaf cannot admit extent"),
                    |_| {
                        allocations.set(allocations.get() + 1);
                        Ok(Vec::new())
                    },
                ),
                |_| panic!("missing leaf has no middle observation"),
                (|error| error, |_| io::Error::other("changed")),
            )?;
            assert_eq!(missing, None);
            assert_eq!(allocations.get(), 0);
            let bytes = reader.read_admitted(
                "record",
                8,
                (
                    |extent| {
                        assert_eq!(extent, 8);
                        Ok(8)
                    },
                    |length| {
                        allocations.set(allocations.get() + 1);
                        Ok(vec![0; length])
                    },
                ),
                |view| {
                    middles.set(middles.get() + 1);
                    view.require_same_file("lock", &lock, || io::Error::other("wrong original"))
                },
                (|error| error, |_| io::Error::other("changed")),
            )?;
            assert_eq!(bytes.as_deref(), Some(b"original".as_slice()));
            let refusal = reader.read_admitted(
                "record",
                7,
                (
                    |extent| usize::try_from(extent).map_err(io::Error::other),
                    |_| {
                        allocations.set(allocations.get() + 1);
                        Ok(Vec::new())
                    },
                ),
                |_| panic!("inadmissible length cannot reach middle"),
                (|error| error, |_| io::Error::other("changed")),
            );
            assert_eq!(
                refusal.unwrap_err().to_string(),
                "record length admission differs from its native extent"
            );
            assert_eq!(allocations.get(), 1);
            assert_eq!(middles.get(), 1);
            Ok::<_, io::Error>(())
        })
        .unwrap();
    assert_eq!(
        directory
            .read_scope(|reader| read(reader, "record"))
            .unwrap()
            .as_deref(),
        Some(b"original".as_slice())
    );
}

#[cfg(unix)]
#[test]
fn existing_leaf_second_named_admission_notfound_is_error_and_original_restores() {
    let (_root, directory) = store();
    let original_id = FileIdentity::of(&directory.open_read("record").unwrap()).unwrap();
    let name = directory.path().join("record");
    let saved = directory.path().join("saved");
    let moved_name = name.clone();
    let moved_saved = saved.clone();
    let error = platform::with_readonly_named_hook(
        "record",
        move || fs::rename(&moved_name, &moved_saved).unwrap(),
        || directory.read_scope(|reader| read(reader, "record")),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert!(saved.is_file());
    assert!(!name.exists());
    fs::rename(&saved, &name).unwrap();
    assert_eq!(
        FileIdentity::of(&directory.open_read("record").unwrap()).unwrap(),
        original_id
    );
    assert_eq!(
        directory
            .read_scope(|reader| read(reader, "record"))
            .unwrap()
            .as_deref(),
        Some(b"original".as_slice())
    );
    assert_eq!(
        directory
            .read_scope(|reader| read(reader, "missing"))
            .unwrap(),
        None
    );
}

#[cfg(unix)]
#[test]
fn admitted_owned_read_refuses_post_eof_named_absence_replacement_and_original_retry() {
    for replacement in [false, true] {
        let (_root, directory) = store();
        let name = directory.path().join("record");
        let saved = directory.path().join("saved");
        let before = FileIdentity::of(&directory.open_read("record").unwrap()).unwrap();
        let actual = directory
            .read_scope(|reader| {
                reader.read_admitted(
                    "record",
                    8,
                    (
                        |extent| usize::try_from(extent).map_err(io::Error::other),
                        |length| Ok(vec![0; length]),
                    ),
                    |_| {
                        fs::rename(&name, &saved)?;
                        if replacement {
                            directory.write_atomic(
                                "record",
                                b"different",
                                PublishMode::CreateNew,
                            )?;
                        }
                        Ok(())
                    },
                    (
                        |error| error,
                        |named| {
                            io::Error::other(if named {
                                "named object changed"
                            } else {
                                "read object changed"
                            })
                        },
                    ),
                )
            })
            .unwrap_err();
        if replacement {
            assert_eq!(actual.to_string(), "named object changed");
        } else {
            assert_eq!(actual.kind(), io::ErrorKind::NotFound);
        }
        if replacement {
            fs::remove_file(&name).unwrap();
        }
        fs::rename(&saved, &name).unwrap();
        assert_eq!(
            FileIdentity::of(&directory.open_read("record").unwrap()).unwrap(),
            before
        );
        assert_eq!(
            directory
                .read_scope(|reader| read(reader, "record"))
                .unwrap()
                .as_deref(),
            Some(b"original".as_slice())
        );
    }
}

#[cfg(unix)]
#[test]
fn admitted_result_outer_ancestry_refusal_dominates_all_results_with_restored_temporal_limit() {
    for outcome in ["bytes", "absence", "allocation"] {
        let (root, directory) = store();
        let displaced = root.path().join("displaced");
        let actual = directory
            .read_scope(|reader| {
                let body = reader.read_admitted(
                    if outcome == "absence" {
                        "missing"
                    } else {
                        "record"
                    },
                    8,
                    (
                        |extent| usize::try_from(extent).map_err(io::Error::other),
                        |length| {
                            if outcome == "allocation" {
                                Err(io::Error::other("allocation owner refused"))
                            } else {
                                Ok(vec![0; length])
                            }
                        },
                    ),
                    |_| Ok(()),
                    (|error| error, |_| io::Error::other("changed")),
                );
                match outcome {
                    "bytes" => assert_eq!(
                        body.as_ref().unwrap().as_deref(),
                        Some(b"original".as_slice())
                    ),
                    "absence" => assert!(matches!(&body, Ok(None))),
                    "allocation" => assert_eq!(
                        body.as_ref().unwrap_err().to_string(),
                        "allocation owner refused"
                    ),
                    _ => unreachable!(),
                }
                fs::rename(directory.path(), &displaced)?;
                body
            })
            .unwrap_err();
        assert_eq!(actual.kind(), io::ErrorKind::NotFound);
        fs::rename(&displaced, directory.path()).unwrap();
        assert_eq!(
            directory
                .read_scope(|reader| {
                    let bytes = read(reader, "record")?;
                    fs::rename(directory.path(), &displaced)?;
                    fs::rename(&displaced, directory.path())?;
                    Ok::<_, io::Error>(bytes)
                })
                .unwrap()
                .as_deref(),
            Some(b"original".as_slice())
        );
    }
}
