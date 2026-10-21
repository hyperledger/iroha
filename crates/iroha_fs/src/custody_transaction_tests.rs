//! Thread-bound custody transactions: consolidated walks, unchanged leaf checks, and the entry,
//! first-use, fence and exit observations.

use super::*;
use std::{fs, os::unix::fs::PermissionsExt as _};

fn custody() -> (tempfile::TempDir, PrivateDirectory, PrivateDirectory) {
    let temporary = tempfile::tempdir().unwrap();
    let root = PrivateDirectory::open_or_create(temporary.path().join("custody")).unwrap();
    root.write_atomic("sentinel", b"sentinel", PublishMode::CreateNew)
        .unwrap();
    let slot = root.ensure_child("slot").unwrap();
    slot.write_atomic("record", b"record", PublishMode::CreateNew)
        .unwrap();
    (temporary, root, slot)
}

fn walks(work: impl FnOnce()) -> u64 {
    let before = CustodyWorkV1::current_thread();
    work();
    CustodyWorkV1::current_thread().since(before).ancestry_walks
}

#[test]
fn joined_custody_walks_only_at_entry_first_use_fences_and_exit() {
    let (_temporary, root, slot) = custody();
    // Outside a transaction every read walks its complete ancestry before and after the leaf.
    let outside = walks(|| assert_eq!(slot.read("record", 64).unwrap().as_slice(), b"record"));
    assert_eq!(outside, 2);
    let inside = walks(|| {
        custody_transaction(|| {
            // Entry: one complete walk of the root.
            root.join_custody_transaction()?;
            for _ in 0..4 {
                // The slot's own suffix is walked at its first use only.
                assert_eq!(slot.read("record", 64)?.as_slice(), b"record");
                assert_eq!(root.read("sentinel", 64)?.as_slice(), b"sentinel");
            }
            assert_eq!(
                root.custody_entry_kind("slot")?,
                CustodyEntryKind::Directory
            );
            root.join_custody_transaction()?;
            slot.join_custody_transaction()?;
            // A fence walks the root completely and the slot by its suffix.
            fence_custody_transaction()
        })
        .unwrap();
    });
    // Entry 1, first use 1, fence 2 and exit 2.
    assert_eq!(inside, 6);
}

#[test]
fn leaf_checks_inside_a_transaction_refuse_exactly_like_complete_walks() {
    for attack in ["hardlink", "symlink", "permissions"] {
        let (_temporary, root, slot) = custody();
        let original = slot.path().join("record");
        let alias = slot.path().join("alias");
        match attack {
            "hardlink" => fs::hard_link(&original, &alias).unwrap(),
            "symlink" => {
                fs::rename(&original, &alias).unwrap();
                std::os::unix::fs::symlink("alias", &original).unwrap();
            }
            "permissions" => {
                fs::set_permissions(&original, fs::Permissions::from_mode(0o644)).unwrap();
            }
            _ => unreachable!(),
        }
        let expected = slot.read("record", 64).unwrap_err();
        let actual = custody_transaction(|| {
            root.join_custody_transaction()?;
            slot.read("record", 64).map(drop)
        })
        .unwrap_err();
        assert_eq!(actual.kind(), expected.kind(), "{attack}");
        assert_eq!(actual.to_string(), expected.to_string(), "{attack}");
    }
}

#[test]
fn a_displaced_root_refuses_the_next_fence_and_the_exit_like_a_complete_walk() {
    let (temporary, root, slot) = custody();
    let original = root.path().to_path_buf();
    let displaced = temporary.path().join("displaced");
    let displace = || {
        fs::rename(&original, &displaced).unwrap();
        fs::create_dir(&original).unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
    };
    let restore = || {
        fs::remove_dir(&original).unwrap();
        fs::rename(&displaced, &original).unwrap();
    };
    let refused = custody_transaction(|| {
        root.join_custody_transaction()?;
        assert_eq!(slot.read("record", 64)?.as_slice(), b"record");
        displace();
        // Leaf work follows only held descriptors: the retained record still reads exactly.
        assert_eq!(slot.read("record", 64)?.as_slice(), b"record");
        let fence = fence_custody_transaction().unwrap_err();
        // After the refusal every walk is complete again and refuses the same way.
        assert_eq!(
            fence.to_string(),
            root.revalidate().unwrap_err().to_string()
        );
        assert!(slot.read("record", 64).is_err());
        Ok::<_, io::Error>(7)
    })
    .unwrap_err();
    assert_eq!(
        refused.to_string(),
        root.revalidate().unwrap_err().to_string(),
        "the exit refusal replaces the ordinary result"
    );
    restore();
    // A change that persists until the exit refuses it even without a fence.
    let exit = custody_transaction(|| {
        root.join_custody_transaction()?;
        assert_eq!(root.read("sentinel", 64)?.as_slice(), b"sentinel");
        displace();
        Ok::<_, io::Error>(7)
    });
    assert!(exit.is_err());
    restore();
    // A change made and restored between two observations is not one.
    let restored = custody_transaction(|| {
        root.join_custody_transaction()?;
        displace();
        restore();
        fence_custody_transaction()?;
        Ok::<_, io::Error>(7)
    });
    assert_eq!(restored.unwrap(), 7);
    let body = custody_transaction(|| Err::<(), _>(io::Error::other("body"))).unwrap_err();
    assert_eq!(
        body.to_string(),
        "body",
        "an observed exit keeps the body's error"
    );
}

#[test]
fn other_threads_unjoined_directories_and_code_outside_keep_complete_walks() {
    let (_temporary, root, slot) = custody();
    let (_other_temporary, other, _) = custody();
    custody_transaction(|| {
        root.join_custody_transaction()?;
        assert_eq!(walks(|| other.revalidate().unwrap()), 1);
        std::thread::scope(|scope| {
            scope
                .spawn(|| assert_eq!(walks(|| slot.revalidate().unwrap()), 1))
                .join()
                .unwrap();
        });
        // An independently opened owner of the same path retains no joined link.
        let reopened = PrivateDirectory::open(root.path())?;
        assert_eq!(walks(|| reopened.revalidate().unwrap()), 1);
        assert_eq!(walks(|| root.revalidate().unwrap()), 0);
        Ok::<_, io::Error>(())
    })
    .unwrap();
    assert_eq!(walks(|| root.revalidate().unwrap()), 1);
    // Outside a transaction, joining and fencing observe nothing and change nothing.
    assert_eq!(
        walks(|| {
            root.join_custody_transaction().unwrap();
            fence_custody_transaction().unwrap();
            slot.revalidate().unwrap();
        }),
        1
    );
}

#[test]
fn nested_transactions_are_part_of_the_outermost_one() {
    let (_temporary, root, slot) = custody();
    let total = walks(|| {
        custody_transaction(|| {
            root.join_custody_transaction()?;
            let inner = walks(|| {
                custody_transaction(|| {
                    root.join_custody_transaction()?;
                    slot.read("record", 64).map(drop)
                })
                .unwrap();
            });
            assert_eq!(
                inner, 1,
                "only the slot's first use; no inner exit observation"
            );
            Ok::<_, io::Error>(())
        })
        .unwrap();
    });
    assert_eq!(total, 1 + 1 + 2);
}

#[test]
fn removed_directories_are_observed_only_while_retained() {
    let (_temporary, root, _slot) = custody();
    custody_transaction(|| {
        root.join_custody_transaction()?;
        let empty = root.create_child("empty")?;
        let identity = empty.identity()?;
        drop(empty);
        root.remove_custody_directory("empty", identity)?;
        // No owner retains the removed chain, so no later observation walks it.
        fence_custody_transaction()
    })
    .unwrap();
    let refused = custody_transaction(|| {
        root.join_custody_transaction()?;
        let kept = root.create_child("kept")?;
        root.remove_custody_directory("kept", kept.identity()?)?;
        // A retained directory whose name is gone refuses, as its next operation would.
        let fence = fence_custody_transaction();
        drop(kept);
        fence
    });
    assert!(refused.is_err());
}

#[test]
fn removing_or_publishing_a_directory_checks_its_own_name_inside_a_transaction() {
    for operation in ["remove", "publish"] {
        let (temporary, root, _slot) = custody();
        let moved = temporary.path().join("moved");
        let substitute = custody_transaction(|| {
            root.join_custody_transaction()?;
            let draft = root.create_child("draft")?;
            // The chain's first use is behind it: its walks are now consolidated.
            draft.revalidate()?;
            let name = draft.path().to_path_buf();
            fs::rename(&name, &moved).unwrap();
            fs::create_dir(&name).unwrap();
            fs::set_permissions(&name, fs::Permissions::from_mode(0o700)).unwrap();
            // Both act on the directory's own name: they refuse the substitute at it.
            let refused = match operation {
                "remove" => draft.remove_empty().unwrap_err(),
                _ => draft
                    .rename_to_sibling("final", PublishMode::CreateNew)
                    .unwrap_err(),
            };
            assert!(name.is_dir(), "{operation}: the substitute stays in place");
            assert!(!root.path().join("final").exists(), "{operation}");
            Ok::<_, io::Error>(refused)
        })
        .unwrap();
        assert_eq!(
            substitute.to_string(),
            "retained filesystem identity or custody changed",
            "{operation}"
        );
        assert!(
            moved.is_dir(),
            "{operation}: the held directory was not touched"
        );
    }
}

#[test]
fn unwinding_closes_the_transaction_without_an_exit_observation() {
    let (_temporary, root, _slot) = custody();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = custody_transaction(|| -> io::Result<()> {
            root.join_custody_transaction()?;
            panic!("unwind inside a custody transaction")
        });
    }));
    assert!(unwound.is_err());
    assert_eq!(
        walks(|| root.revalidate().unwrap()),
        1,
        "no transaction stays open"
    );
}

#[test]
fn tree_scope_refusal_restores_complete_walks_before_an_ordinary_result_leaves() {
    for target_is_root in [true, false] {
        for refuse_at_entry in [true, false] {
            for inner_error in [true, false] {
                let (_temporary, root, slot) = custody();
                let target = if target_is_root { &root } else { &slot };
                let path = target.path().to_path_buf();
                let mut expected = None;
                let result = custody_transaction(|| {
                    root.join_custody_transaction()?;
                    // Both exact chains have already been used, so the old implementation
                    // would consolidate their next ordinary revalidation.
                    slot.revalidate()?;
                    root.read_tree_scope(|tree| {
                        let mut entered = false;
                        if refuse_at_entry {
                            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
                        }
                        let checked = tree.read_scope(target, |_reader| {
                            entered = true;
                            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
                            if inner_error {
                                Err(io::Error::other("inner semantic error"))
                            } else {
                                Ok(())
                            }
                        });
                        assert_eq!(entered, !refuse_at_entry);
                        let refused = checked.unwrap_err();
                        expected = Some((refused.kind(), refused.to_string()));
                        // A fresh tree refusal must end consolidation immediately, including
                        // when its caller catches the error instead of propagating it.
                        let before = CustodyWorkV1::current_thread();
                        let next = target.revalidate().expect_err(
                            "the failed native tree observation must restore complete walks",
                        );
                        assert_eq!(next.kind(), refused.kind());
                        assert_eq!(next.to_string(), refused.to_string());
                        assert_eq!(
                            CustodyWorkV1::current_thread().since(before).ancestry_walks,
                            1
                        );
                        let nested = custody_transaction(|| target.revalidate()).unwrap_err();
                        assert_eq!(nested.kind(), refused.kind());
                        assert_eq!(nested.to_string(), refused.to_string());
                        if inner_error {
                            Err(io::Error::other("outer semantic error"))
                        } else {
                            Ok(())
                        }
                    })
                });
                let refused = result.unwrap_err();
                assert_eq!(Some((refused.kind(), refused.to_string())), expected);
                // The root/suffix exit still overrides success and typed body failure, and
                // restoring the same owners permits a later ordinary retry.
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                assert_eq!(root.read("sentinel", 64).unwrap().as_slice(), b"sentinel");
                assert_eq!(slot.read("record", 64).unwrap().as_slice(), b"record");
            }
        }
    }
}

#[test]
fn complete_walk_refusal_keeps_consolidation_disabled_after_original_owner_restoration() {
    let (_temporary, root, slot) = custody();
    let (_other_temporary, other, _) = custody();
    let refused = custody_transaction(|| {
        root.join_custody_transaction()?;
        slot.revalidate()?;
        // An unjoined owner uses a fresh complete walk inside this transaction.
        fs::set_permissions(other.path(), fs::Permissions::from_mode(0o755))?;
        let original = other.revalidate().unwrap_err();
        assert_eq!(original.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(walks(|| root.revalidate().unwrap()), 1);
        fs::set_permissions(other.path(), fs::Permissions::from_mode(0o700))?;
        other.revalidate()?;
        assert_eq!(walks(|| slot.revalidate().unwrap()), 1);
        assert_eq!(slot.read("record", 64)?.as_slice(), b"record");
        Err::<(), _>(io::Error::other("retained semantic error"))
    })
    .unwrap_err();
    assert_eq!(refused.to_string(), "retained semantic error");
    assert_eq!(walks(|| root.revalidate().unwrap()), 1);
    other.revalidate().unwrap();
}
