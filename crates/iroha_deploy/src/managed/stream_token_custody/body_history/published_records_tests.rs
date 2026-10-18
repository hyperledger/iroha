//! Genuine terminal records share only parsing ownership; fresh scopes and budgets still rule.

use super::*;
use crate::managed::native_operation::attempts::metadata;

fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        MAX_BODY_BYTES,
        MAX_ALL_BODY_BYTES,
        MAX_ALL_BODY_BYTES,
        allocation,
        64,
    )
}

#[test]
fn published_terminal_records_share_exact_owner_and_keep_current_foreign_and_active_recipes() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(2);
    let native = history.current_history().unwrap();
    let oldest = native.test_oldest_retained_history();
    let published = PublishedBodyRead::new(&history).unwrap();
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    snapshot.head.revalidate().unwrap();
    EnrollmentReadPass::run(&snapshot, |pass| {
        let (result, parses) = History::test_closure_parse_work(|| {
            oldest.test_published_read(native, &published, Some(pass), false)
        });
        let (shared, reused) = result?;
        assert!(reused);
        assert_eq!(
            parses, 0,
            "the exact closed record owner needs no recovery parse"
        );
        assert!(oldest.test_shares_published_records(&shared));
        shared.close_published_epoch_error(Some(pass))?;
        let (result, parses) = History::test_closure_parse_work(|| {
            oldest.test_published_read(native, &published, Some(pass), true)
        });
        let (canonical, reused) = result?;
        assert!(!reused);
        assert_eq!(parses, 1);
        assert!(!oldest.test_shares_published_records(&canonical));
        canonical.close_published_epoch_error(Some(pass))?;
        assert_eq!(
            shared.cumulative_reserved_count(),
            canonical.cumulative_reserved_count()
        );

        // A valid closed DTO obtained through the ordinary parser has no shared-owner receipt.
        let owned = oldest.test_owned_closure_history()?;
        for (wanted, source, scoped) in [
            (oldest, &owned, true),
            (native, native, true),
            (oldest, native, false),
        ] {
            let (result, parses) = History::test_closure_parse_work(|| {
                wanted.test_published_read(source, &published, scoped.then_some(pass), false)
            });
            let (current, reused) = result?;
            assert!(!reused);
            assert_eq!(parses, 1);
            current.close_published_epoch_error(scoped.then_some(pass))?;
        }
        Ok(())
    })
    .unwrap();
    snapshot.head.revalidate().unwrap();

    // Same path, inode, metadata and records do not replace the original Arc owner.
    let independently_opened = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    assert_eq!(
        independently_opened.root.identity().unwrap(),
        history.root.identity().unwrap()
    );
    assert!(!Arc::ptr_eq(&independently_opened.root, &history.root));
    let foreign = PublishedBodyRead::new(&independently_opened).unwrap();
    EnrollmentReadPass::run(&snapshot, |pass| {
        let (result, parses) = History::test_closure_parse_work(|| {
            oldest.test_published_read(native, &foreign, Some(pass), false)
        });
        let (current, reused) = result?;
        assert!(!reused);
        assert_eq!(parses, 1);
        current.close_published_epoch_error(Some(pass))
    })
    .unwrap();

    // Install the finite owner after creating the concrete publication capability.
    let measured = |canonical, allocation| {
        norito::core::with_decode_limits_measured(limits(allocation), || {
            History::test_closure_parse_work(|| {
                EnrollmentReadPass::run(&snapshot, |pass| {
                    let (current, reused) =
                        oldest.test_published_read(native, &published, Some(pass), canonical)?;
                    current.close_published_epoch_error(Some(pass))?;
                    Ok((
                        reused,
                        oldest.test_shares_published_records(&current),
                        current.cumulative_reserved_count(),
                    ))
                })
                .map_err(|error| error.to_string())
            })
        })
    };
    // Separate canonical parses may use different physical alignment paths. Their observed
    // allocation is not a reusable minimum budget for a later parse of the same records.
    let ample = 64 * 1024 * 1024;
    let original = measured(true, ample);
    let current = measured(false, ample);
    assert_eq!(original.0, current.0);
    assert!(original.0.0.is_ok());
    assert_eq!(original.0.1, 1);
    assert!(!original.0.0.as_ref().unwrap().0);
    for usage in [&original.1, &current.1] {
        assert!(usage.total_allocated_bytes() > 1);
        assert!(usage.total_allocated_bytes() <= ample);
    }
    for allocation in [0, 1] {
        let original = measured(true, allocation);
        let current = measured(false, allocation);
        assert_eq!(original, current, "allocation {allocation}");
        assert!(original.0.0.is_err());
    }
    assert_eq!(
        fixture.native.chain.height(),
        4,
        "read controls submit no block"
    );
}

#[test]
fn shared_terminal_records_close_fresh_metadata_before_an_epoch_error() {
    struct Restore {
        directory: Arc<PrivateDirectory>,
        bytes: zeroize::Zeroizing<Vec<u8>>,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            metadata::test_replace_component(
                &self.directory,
                None,
                "closed.nrt",
                Some(&self.bytes),
            )
            .unwrap();
        }
    }
    let _resources = crate::managed::native_test_guard();
    let (_fixture, history) = shared_snapshot_tests::history_with_bodies(2);
    let native = history.current_history().unwrap();
    let oldest = native.test_oldest_retained_history();
    let published = PublishedBodyRead::new(&history).unwrap();
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    let directory = Arc::clone(&history.bodies[0].directory);
    let original = metadata::test_read_component(&directory, None, "closed.nrt")
        .unwrap()
        .unwrap();
    let restore = Restore {
        directory,
        bytes: zeroize::Zeroizing::new(original),
    };
    EnrollmentReadPass::run(&snapshot, |pass| {
        let (shared, reused) = oldest.test_published_read(native, &published, Some(pass), false)?;
        assert!(reused);
        shared.close_published_epoch_error(Some(pass))?;
        metadata::test_replace_component(
            &restore.directory,
            None,
            "closed.nrt",
            Some(b"changed closure"),
        )?;
        let result = shared
            .close_published_epoch_error(Some(pass))
            .and(Err::<(), _>(invalid("ordinary epoch-reference refusal")));
        assert!(result.is_err());
        assert!(
            !result
                .unwrap_err()
                .to_string()
                .contains("ordinary epoch-reference refusal")
        );
        metadata::test_replace_component(
            &restore.directory,
            None,
            "closed.nrt",
            Some(&restore.bytes),
        )?;
        shared.close_published_epoch_error(Some(pass))?;
        Ok(())
    })
    .unwrap();
    drop(restore);
    snapshot.head.revalidate().unwrap();
}

#[test]
fn published_handle_copy_omits_only_two_native_censuses_and_keeps_fresh_record_work() {
    // Isolate the prior handle-copy reduction with literal metadata decoding. Combined
    // exact-image reuse has its own fresh-byte/native-work tests in metadata_reuse_tests.
    metadata_reuse_tests::with_original_recipe(published_handle_copy_with_original_metadata);
}
fn published_handle_copy_with_original_metadata() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(2);
    let native = history.current_history().unwrap();
    let oldest = native.test_oldest_retained_history();
    let published = PublishedBodyRead::new(&history).unwrap();
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    snapshot.head.revalidate().unwrap();
    EnrollmentReadPass::run(&snapshot, |pass| {
        let read = |original| {
            History::test_published_handle_recipe(original, None, || {
                let ((result, copied_records), handles) = History::test_handle_work(|| {
                    History::test_operation_records(|| {
                        oldest.test_published_read(native, &published, Some(pass), false)
                    })
                });
                let (shared, reused) = result?;
                assert!(reused && oldest.test_shares_published_records(&shared));
                assert_eq!(copied_records, [0; 4]);
                let ((closed, records), leaves) = operation_scope_tests::observe_leaves(
                    |_| Ok(()),
                    || {
                        History::test_operation_records(|| {
                            shared.close_published_epoch_error(Some(pass))
                        })
                    },
                );
                closed?;
                Ok::<_, crate::managed::Error>((handles, records, leaves, shared.reserved_attempt_count()))
            })
        };
        let (old, old_records, old_leaves, old_count) = read(true)?;
        let (new, new_records, new_leaves, new_count) = read(false)?;
        assert_eq!(old.full_operations, new.full_operations + 2);
        assert_eq!(old.history_order, new.history_order);
        assert_eq!(old.tree_brackets, new.tree_brackets);
        assert_eq!(old.tree_operations, new.tree_operations);
        assert_eq!(old.operation_exits, new.operation_exits);
        let roots = |values: &[(bool, usize)]| values.iter().filter(|(attempt, _)| !*attempt).count();
        let attempts = |values: &[(bool, usize)]| values.iter().filter(|(attempt, _)| *attempt).count();
        assert_eq!(roots(&old.descendant_order), roots(&new.descendant_order) + 2);
        assert_eq!(
            attempts(&old.descendant_order),
            attempts(&new.descendant_order) + 2 * oldest.reserved_attempt_count()
        );
        assert_eq!((old_count, new_count), (oldest.reserved_attempt_count(), oldest.reserved_attempt_count()));
        assert!(new_count > 0);
        assert_eq!(old_records, new_records);
        assert!(new_records[0] > 0 && new_records[1] > 0);
        assert_eq!(old_leaves, new_leaves);
        assert!(!new_leaves.is_empty());

        // Install the decoder after both the publication capability and parser pass exist.
        // Its original parser still performs identical physical handle/record work.
        let measured = |original, capacity| {
            History::test_published_handle_recipe(original, None, || {
                norito::core::with_decode_limits_measured(limits(capacity), || {
                    History::test_handle_work(|| {
                        History::test_operation_records(|| {
                            oldest
                                .test_published_read(native, &published, Some(pass), false)
                                .map(|(current, reused)| (reused, current.reserved_attempt_count()))
                                .map_err(|error| error.to_string())
                        })
                    })
                })
            })
        };
        for capacity in [0, 1, 64 * 1024 * 1024] {
            let (((old_result, old_records), old), old_usage) = measured(true, capacity);
            let (((new_result, new_records), new), new_usage) = measured(false, capacity);
            assert_eq!(old_result, new_result);
            assert_eq!(old_records, new_records);
            assert_eq!(old.history_order, new.history_order);
            assert_eq!(old.full_operations, new.full_operations);
            assert_eq!(old.tree_operations, new.tree_operations);
            assert_eq!(old.operation_exits, new.operation_exits);
            assert_eq!(old.descendant_order.len(), new.descendant_order.len());
            if capacity <= 1 {
                assert!(new_result.is_err());
                assert_eq!(old_usage, new_usage);
            } else {
                assert!(matches!(new_result, Ok((false, count)) if count == oldest.reserved_attempt_count()));
            }
        }
        Ok(())
    })
    .unwrap();
    snapshot.head.revalidate().unwrap();
    assert_eq!(
        fixture.native.chain.height(),
        4,
        "read controls submit no block"
    );
}

#[cfg(unix)]
#[test]
fn published_handle_copy_closes_native_mutations_before_inner_errors_and_exact_retry() {
    use std::{cell::Cell, io, os::unix::fs::PermissionsExt as _, rc::Rc};

    struct RestorePermissions {
        path: std::path::PathBuf,
        original: std::fs::Permissions,
    }
    impl Drop for RestorePermissions {
        fn drop(&mut self) {
            std::fs::set_permissions(&self.path, self.original.clone()).unwrap();
        }
    }
    struct RestoreDirectory {
        path: std::path::PathBuf,
        held: std::path::PathBuf,
    }
    impl Drop for RestoreDirectory {
        fn drop(&mut self) {
            if self.held.exists() {
                if self.path.exists() {
                    std::fs::remove_dir(&self.path).unwrap();
                }
                std::fs::rename(&self.held, &self.path).unwrap();
            }
        }
    }
    let _resources = crate::managed::native_test_guard();
    let (_fixture, history) = shared_snapshot_tests::history_with_bodies(2);
    let native = history.current_history().unwrap();
    let oldest = native.test_oldest_retained_history();
    let published = PublishedBodyRead::new(&history).unwrap();
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    let operation = &history.bodies[0].directory;
    let attempts = operation.open_child("attempts").unwrap();
    let names = attempts.entries(64).unwrap();
    assert_eq!(names.len(), oldest.reserved_attempt_count());
    let attempt = attempts.open_child(&names[0]).unwrap();
    EnrollmentReadPass::run(&snapshot, |pass| {
        for directory in [operation.as_ref(), &attempts, &attempt] {
            let path = directory.path().to_owned();
            for inner_error in [false, true] {
                let mut outcomes = Vec::new();
                for original in [true, false] {
                    let restore = RestorePermissions {
                        path: path.clone(),
                        original: std::fs::metadata(&path).unwrap().permissions(),
                    };
                    let changed = path.clone();
                    let fired = Rc::new(Cell::new(false));
                    let observed = Rc::clone(&fired);
                    let result = History::test_published_handle_recipe(
                        original,
                        Some(Box::new(move || {
                            observed.set(true);
                            std::fs::set_permissions(&changed, std::fs::Permissions::from_mode(0o755))?;
                            if inner_error {
                                Err(invalid("ordinary post-copy refusal"))
                            } else {
                                Ok(())
                            }
                        })),
                        || oldest.test_published_read(native, &published, Some(pass), false),
                    );
                    drop(restore);
                    assert!(fired.get(), "the mutation occurs after the pure record copy");
                    let error = result.err().expect("final native handle census must refuse");
                    assert!(matches!(&error, crate::managed::Error::Io(error) if error.kind() == io::ErrorKind::PermissionDenied));
                    outcomes.push(error.to_string());
                    let (restored, reused) = oldest.test_published_read(native, &published, Some(pass), false)?;
                    assert!(reused && oldest.test_shares_published_records(&restored));
                    restored.close_published_epoch_error(Some(pass))?;
                }
                assert_eq!(outcomes[0], outcomes[1]);
            }
        }
        // The same final native observation also rejects a new same-path directory.
        for original in [true, false] {
            let path = attempt.path().to_owned();
            let held = path.with_extension("published-copy-original");
            assert!(!held.exists());
            let restore = RestoreDirectory {
                path: path.clone(),
                held: held.clone(),
            };
            let changed = path.clone();
            let displaced = held.clone();
            let result = History::test_published_handle_recipe(
                original,
                Some(Box::new(move || {
                    std::fs::rename(&changed, &displaced)?;
                    PrivateDirectory::open_or_create(&changed)?;
                    Ok(())
                })),
                || oldest.test_published_read(native, &published, Some(pass), false),
            );
            drop(restore);
            assert!(matches!(result, Err(crate::managed::Error::Io(error)) if error.kind() == io::ErrorKind::Other));
            let (restored, reused) = oldest.test_published_read(native, &published, Some(pass), false)?;
            assert!(reused);
            restored.close_published_epoch_error(Some(pass))?;
        }
        for original in [true, false] {
            let result = History::test_published_handle_recipe(
                original,
                Some(Box::new(|| Err(invalid("ordinary post-copy refusal")))),
                || oldest.test_published_read(native, &published, Some(pass), false),
            );
            assert!(matches!(result, Err(crate::managed::Error::Invalid(message)) if message == "ordinary post-copy refusal"));
        }
        Ok(())
    })
    .unwrap();
    snapshot.head.revalidate().unwrap();
}
