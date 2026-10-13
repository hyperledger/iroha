//! Genuine terminal records share only parsing ownership; fresh scopes and budgets still rule.

use super::*;

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
    impl Drop for Restore {
        fn drop(&mut self) {
            self.directory
                .write_atomic("closed.nrt", &self.bytes, PublishMode::Replace)
                .unwrap();
        }
    }
    struct Restore {
        directory: Arc<PrivateDirectory>,
        bytes: zeroize::Zeroizing<Vec<u8>>,
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
    let original = directory
        .read("closed.nrt", attempts::MAX_RECORD_BYTES)
        .unwrap();

    let restore = Restore {
        directory,
        bytes: original,
    };
    EnrollmentReadPass::run(&snapshot, |pass| {
        let (shared, reused) = oldest.test_published_read(native, &published, Some(pass), false)?;
        assert!(reused);
        shared.close_published_epoch_error(Some(pass))?;
        restore
            .directory
            .write_atomic("closed.nrt", b"changed closure", PublishMode::Replace)?;
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
        restore
            .directory
            .write_atomic("closed.nrt", &restore.bytes, PublishMode::Replace)?;
        shared.close_published_epoch_error(Some(pass))?;
        Ok(())
    })
    .unwrap();
    drop(restore);
    snapshot.head.revalidate().unwrap();
}
