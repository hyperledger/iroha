//! Publication closes the immediately preceding exact parser scan without retaining freshness.

use super::*;
use crate::managed::{
    Error,
    native_operation::authorization::{EpochReader, Scope},
};
use std::{cell::Cell, rc::Rc};

fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
}

// Compare the original caller's successful outer scan with the moved immediate close.
// Both start with genuine native history and use the publication's existing parsed records.
fn publication_parse(
    current: &mut BodyHistory,
    owner: &ManagedStreamTokenCustody,
    shared: bool,
) -> Result<()> {
    let tail = Arc::clone(&current.bodies.last().unwrap().snapshots);
    let previous = PublishedHistory {
        active: current.active.take(),
        closed: current.nearest_closure.take(),
    };
    let mut epochs = EpochReader::default();
    if let CustodyPurpose::Renewal(sequence) = current.purpose {
        epochs.validate_retained(
            &current.root,
            current.selection.digest()?,
            &current.selection.fees,
            Scope::Renewal {
                provider: owner.authority.provider_id()?,
                sequence,
            },
        )?;
    }
    current.verify_histories_from_with_wallets(
        owner,
        None,
        Some(&previous),
        &mut epochs,
        None,
        shared.then_some(tail.as_ref()),
    )?;
    if !shared {
        tail.revalidate()?;
    }
    Ok(())
}

fn same(actual: &BodyHistory, expected: &BodyHistory) {
    assert_eq!(
        actual.selection.digest().unwrap(),
        expected.selection.digest().unwrap()
    );
    assert_eq!(actual.bodies.len(), expected.bodies.len());
    assert_eq!(
        actual
            .current_history()
            .unwrap()
            .cumulative_reserved_count(),
        expected
            .current_history()
            .unwrap()
            .cumulative_reserved_count()
    );
    for (actual, expected) in actual.bodies.iter().zip(&expected.bodies) {
        assert_eq!(actual.semantic, expected.semantic);
        assert_eq!(
            actual.reservation.digest().unwrap(),
            expected.reservation.digest().unwrap()
        );
    }
}

#[test]
fn publication_close_removes_one_exact_scan_and_preserves_parser_work_and_decode_budgets() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let mut old = history.read_current(&fixture.owner).unwrap();
    let mut new = history.read_current(&fixture.owner).unwrap();
    let ((), tail_work) = shared_snapshot_tests::snapshot_work(|| {
        old.bodies.last().unwrap().snapshots.revalidate().unwrap();
    });
    assert_eq!(
        tail_work,
        (3 + 4 * history.bodies.len(), history.bodies.len() + 2)
    );
    let capture = finish_timing::Capture::start();
    let (result, old_work) =
        shared_snapshot_tests::snapshot_work(|| publication_parse(&mut old, &fixture.owner, false));
    result.unwrap();
    let old_phases = capture.finish();
    let capture = finish_timing::Capture::start();
    let (result, new_work) =
        shared_snapshot_tests::snapshot_work(|| publication_parse(&mut new, &fixture.owner, true));
    result.unwrap();
    let new_phases = capture.finish();
    same(&new, &old);
    assert_eq!(
        new_work,
        (old_work.0 - tail_work.0, old_work.1 - tail_work.1)
    );
    use finish_timing::Phase;
    for phase in [
        Phase::ParserWallet,
        Phase::GraphValidate,
        Phase::AttemptRecordRead,
        Phase::AttemptRecordDecode,
        Phase::AttemptScopedRecordRead,
        Phase::AttemptScopedRecordDecode,
        Phase::AttemptInventory,
        Phase::AttemptScopedInventory,
        Phase::EpochRecordDecode,
    ] {
        assert_eq!(
            new_phases.sample(phase).0,
            old_phases.sample(phase).0,
            "{phase:?}"
        );
    }
    assert!(old_phases.sample(Phase::ParserWallet).0 > 0);
    assert_eq!(
        new_phases.sample(Phase::SnapshotRevalidate).0 + 1,
        old_phases.sample(Phase::SnapshotRevalidate).0
    );

    let mut baseline = history.read_current(&fixture.owner).unwrap();
    let (result, usage) = norito::core::with_decode_limits_measured(limits(usize::MAX), || {
        publication_parse(&mut baseline, &fixture.owner, false)
    });
    result.unwrap();
    let exact = usage.total_allocated_bytes();
    assert!(exact > 1);
    for capacity in [0, 1, exact / 2, exact - 1, exact] {
        // Prepare before entering either finite decoder; no inherited allocation is hidden.
        let mut old = history.read_current(&fixture.owner).unwrap();
        let mut new = history.read_current(&fixture.owner).unwrap();
        let ((old_result, old_work), old_usage) =
            norito::core::with_decode_limits_measured(limits(capacity), || {
                shared_snapshot_tests::snapshot_work(|| {
                    publication_parse(&mut old, &fixture.owner, false)
                })
            });
        let ((new_result, new_work), new_usage) =
            norito::core::with_decode_limits_measured(limits(capacity), || {
                shared_snapshot_tests::snapshot_work(|| {
                    publication_parse(&mut new, &fixture.owner, true)
                })
            });
        assert_eq!(new_work, old_work, "capacity {capacity}");
        assert_eq!(new_usage, old_usage, "capacity {capacity}");
        assert_eq!(
            new_result.as_ref().err().map(ToString::to_string),
            old_result.as_ref().err().map(ToString::to_string)
        );
        if capacity == exact {
            new_result.unwrap();
            old_result.unwrap();
            same(&new, &old);
        } else {
            assert!(new_result.is_err());
        }
    }
    assert!(!norito::core::decode_limits_active());
    assert_eq!(fixture.native.chain.height(), 4);
}

struct RestoreOriginal {
    directory: Arc<PrivateDirectory>,
    bytes: Vec<u8>,
}
impl Drop for RestoreOriginal {
    fn drop(&mut self) {
        self.directory
            .write_atomic("original.nrt", &self.bytes, PublishMode::Replace)
            .unwrap();
    }
}

#[test]
fn publication_close_preserves_parser_error_and_changed_source_exit_precedence() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(2);
    for changed in [false, true] {
        let mut outcomes = Vec::new();
        for shared in [false, true] {
            let mut current = history.read_current(&fixture.owner).unwrap();
            let directory = Arc::clone(&history.bodies[0].directory);
            let original = directory
                .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
                .unwrap();
            let restore = RestoreOriginal {
                directory: Arc::clone(&directory),
                bytes: original.to_vec(),
            };
            let fired = Rc::new(Cell::new(false));
            let observed = Rc::clone(&fired);
            let (result, work) = shared_snapshot_tests::snapshot_work(|| {
                parser_handle_tests::with_hook(
                    move |point| {
                        if point == parser_handle_tests::Point::WalletInspected(0)
                            && !observed.replace(true)
                        {
                            if changed {
                                let mut bytes = original.to_vec();
                                bytes[0] ^= 1;
                                directory.write_atomic(
                                    "original.nrt",
                                    &bytes,
                                    PublishMode::Replace,
                                )?;
                            }
                            return Err(Error::NativeDeadline);
                        }
                        Ok(())
                    },
                    || publication_parse(&mut current, &fixture.owner, shared),
                )
            });
            assert!(fired.get(), "error follows a genuine wallet inspection");
            if changed {
                assert!(
                    matches!(&result, Err(Error::Invalid(message)) if message == "retained enrollment body material changed")
                );
            } else {
                assert!(matches!(&result, Err(Error::NativeDeadline)));
            }
            outcomes.push((result.unwrap_err().to_string(), work));
            drop(restore);
            history.read_current(&fixture.owner).unwrap();
        }
        assert_eq!(outcomes[0], outcomes[1], "changed source: {changed}");
    }
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn publication_close_keeps_empty_foreign_and_late_decoder_source_checks() {
    let temporary = tempfile::tempdir().unwrap();
    let directory =
        Arc::new(PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap());
    directory
        .write_atomic("original.nrt", b"original", PublishMode::CreateNew)
        .unwrap();
    let root = Arc::new(Snapshot {
        previous: None,
        records: vec![RecordSnapshot::from_read(
            Arc::clone(&directory),
            "original.nrt",
            8,
            Some(b"original"),
        )],
        names: vec![],
        root: None,
    });
    // Empty body publications still own a separate container namespace after the root.
    let empty_tail = Snapshot {
        previous: Some(Arc::clone(&root)),
        records: vec![],
        names: vec![NamesSnapshot::from_read(
            Arc::clone(&directory),
            2,
            directory.entries(2).unwrap(),
        )],
        root: None,
    };
    root.revalidate().unwrap();
    let (result, work) =
        shared_snapshot_tests::snapshot_work(|| empty_tail.close_publication_after_parser(&root));
    result.unwrap();
    assert_eq!(work, (1, 2));
    root.revalidate().unwrap();
    directory
        .write_atomic("unexpected.nrt", b"new", PublishMode::CreateNew)
        .unwrap();
    assert!(empty_tail.close_publication_after_parser(&root).is_err());
    std::fs::remove_file(directory.path().join("unexpected.nrt")).unwrap();

    let foreign = Snapshot {
        previous: None,
        records: root.records.clone(),
        names: vec![],
        root: None,
    };
    root.revalidate().unwrap();
    let (result, work) =
        shared_snapshot_tests::snapshot_work(|| foreign.close_publication_after_parser(&root));
    result.unwrap();
    assert_eq!(
        work,
        (1, 1),
        "equal bytes and paths cannot replace exact head identity"
    );
    root.revalidate().unwrap();
    let (result, work) =
        shared_snapshot_tests::snapshot_work(|| root.close_publication_after_parser(&root));
    result.unwrap();
    assert_eq!(
        work,
        (0, 0),
        "only the immediate exact inactive close shares its scan"
    );

    // A decoder admitted after the parser's scan must pay the original read/allocation cost.
    for changed in [false, true] {
        root.revalidate().unwrap();
        if changed {
            directory
                .write_atomic("original.nrt", b"replaced", PublishMode::Replace)
                .unwrap();
        }
        for capacity in [usize::MAX, 0, 1] {
            let ((old, old_work), old_usage) =
                norito::core::with_decode_limits_measured(limits(capacity), || {
                    shared_snapshot_tests::snapshot_work(|| root.revalidate())
                });
            let ((new, new_work), new_usage) =
                norito::core::with_decode_limits_measured(limits(capacity), || {
                    shared_snapshot_tests::snapshot_work(|| {
                        root.close_publication_after_parser(&root)
                    })
                });
            assert_eq!(new_work, old_work);
            assert_eq!(new_usage, old_usage);
            assert_eq!(
                new.as_ref().err().map(ToString::to_string),
                old.as_ref().err().map(ToString::to_string)
            );
            if changed {
                assert!(new.is_err());
            } else if capacity == usize::MAX {
                new.unwrap();
            }
        }
        directory
            .write_atomic("original.nrt", b"original", PublishMode::Replace)
            .unwrap();
    }
    root.revalidate().unwrap();
}
