//! Native observations keep exact bytes, lazy errors and fresh lock/source custody.

use super::*;
use std::{cell::Cell, fs};

fn decoded(
    value: ObservedNativeRecord<norito::json::Value>,
) -> (norito::json::Value, NativeRecordObservation) {
    match value {
        ObservedNativeRecord::Decoded { value, observation } => (value, observation),
        _ => panic!("fresh or changed native source must decode"),
    }
}

fn observe(
    journal: &Journal,
    record: NativeRecord,
    previous: Option<&NativeRecordObservation>,
) -> Result<ObservedNativeRecord<norito::json::Value>> {
    journal.read_native_scope(|read| read.read_native_observed(record, previous))
}

#[test]
fn native_observation_reuses_only_exact_bytes_record_directory_and_lock() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("operation");
    let original = norito::json!({"request": 7});
    let journal = Journal::create_preparation(&path, &original).unwrap();
    let (value, observation) = decoded(observe(&journal, NativeRecord::Request, None).unwrap());
    assert_eq!(value, original);
    assert!(matches!(
        observe(&journal, NativeRecord::Retired, Some(&observation)).unwrap(),
        ObservedNativeRecord::Missing
    ));
    journal
        .write_native(NativeRecord::Retired, &original)
        .unwrap();
    let (retired, _) =
        decoded(observe(&journal, NativeRecord::Retired, Some(&observation)).unwrap());
    assert_eq!(
        retired, original,
        "same bytes for another record must still decode"
    );
    drop(journal);

    // An observation retains no native handle or lock. A new original acquisition can
    // use the old bytes only after its own lock, inventory and per-record read succeeds.
    let journal = Journal::open(&path).unwrap();
    assert!(matches!(
        observe(&journal, NativeRecord::Request, Some(&observation)).unwrap(),
        ObservedNativeRecord::Unchanged
    ));
    let changed = norito::json!({"request": 8});
    journal
        .directory
        .write_atomic(
            "preparation.json",
            &canonical_bytes(&changed).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    let (actual, _) =
        decoded(observe(&journal, NativeRecord::Request, Some(&observation)).unwrap());
    assert_eq!(actual, changed);
    journal
        .directory
        .write_atomic(
            "preparation.json",
            b"{ \"request\": 7 }",
            PublishMode::Replace,
        )
        .unwrap();
    assert_eq!(
        observe(&journal, NativeRecord::Request, Some(&observation))
            .err()
            .unwrap()
            .to_string(),
        "noncanonical native preparation evidence"
    );
    journal
        .directory
        .write_atomic(
            "preparation.json",
            &canonical_bytes(&original).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert!(matches!(
        observe(&journal, NativeRecord::Request, Some(&observation)).unwrap(),
        ObservedNativeRecord::Unchanged
    ));
    drop(journal);

    // The record bytes are unchanged, but a different lock is a new native observation.
    // Keep the old file alive at another name so no native identifier can be recycled.
    let saved_lock = root.path().join("saved-lock");
    fs::rename(path.join("lock"), &saved_lock).unwrap();
    let directory = PrivateDirectory::open(&path).unwrap();
    drop(directory.create_lock("lock").unwrap());
    drop(directory);
    let journal = Journal::open(&path).unwrap();
    let (actual, different_lock) =
        decoded(observe(&journal, NativeRecord::Request, Some(&observation)).unwrap());
    assert_eq!(actual, original);
    assert!(matches!(
        observe(&journal, NativeRecord::Request, Some(&different_lock)).unwrap(),
        ObservedNativeRecord::Unchanged
    ));
    drop(journal);

    // A replacement directory with equal canonical content cannot borrow the old identity.
    let displaced = root.path().join("displaced-operation");
    fs::rename(&path, &displaced).unwrap();
    let journal = Journal::create_preparation(&path, &original).unwrap();
    let (actual, _) =
        decoded(observe(&journal, NativeRecord::Request, Some(&different_lock)).unwrap());
    assert_eq!(actual, original);
}

#[test]
fn native_observation_rereads_with_finite_budget_and_keeps_lazy_decode_order() {
    let root = tempfile::tempdir().unwrap();
    let original = norito::json!({"request": 7});
    let journal = Journal::create_preparation(&root.path().join("operation"), &original).unwrap();
    let (_, observation) = decoded(observe(&journal, NativeRecord::Request, None).unwrap());
    let limits =
        |allocation| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64);
    for allocation in [0, 1] {
        let (plain, plain_usage) =
            norito::core::with_decode_limits_measured(limits(allocation), || {
                journal.read_native_scope(|read| {
                    read.read_native::<norito::json::Value>(NativeRecord::Request)
                })
            });
        let (observed, observed_usage) =
            norito::core::with_decode_limits_measured(limits(allocation), || {
                observe(&journal, NativeRecord::Request, Some(&observation))
            });
        assert_eq!(
            format!("{:#}", plain.err().unwrap()),
            format!("{:#}", observed.err().unwrap())
        );
        assert_eq!(
            plain_usage, observed_usage,
            "the same original byte allocation must refuse before reuse"
        );
    }
    let (observed, usage) = norito::core::with_decode_limits_measured(limits(1024 * 1024), || {
        observe(&journal, NativeRecord::Request, Some(&observation))
    });
    assert!(matches!(observed.unwrap(), ObservedNativeRecord::Unchanged));
    assert!(usage.total_allocated_bytes() > 1 && usage.total_allocated_bytes() <= 1024 * 1024);

    journal
        .directory
        .write_atomic("preparation.json", b"{", PublishMode::Replace)
        .unwrap();
    journal
        .directory
        .write_atomic("payload.json", b"later", PublishMode::CreateNew)
        .unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(journal.path().join("payload.json"))
        .unwrap()
        .set_len(u64::try_from(MAX_JOURNAL_BYTES + 1).unwrap())
        .unwrap();
    let expected = journal
        .read_native_scope(|read| read.read_native::<norito::json::Value>(NativeRecord::Request))
        .err()
        .unwrap();
    let reached_payload = Cell::new(false);
    let actual = journal
        .read_native_scope(|read| {
            let _ = read.read_native_observed::<norito::json::Value>(
                NativeRecord::Request,
                Some(&observation),
            )?;
            reached_payload.set(true);
            read.read_native::<norito::json::Value>(NativeRecord::Payload)
        })
        .err()
        .unwrap();
    assert_eq!(format!("{actual:#}"), format!("{expected:#}"));
    assert!(
        !reached_payload.get(),
        "first-record canonical failure must precede later unsafe evidence"
    );
    journal
        .directory
        .write_atomic(
            "preparation.json",
            &canonical_bytes(&original).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert!(matches!(
        observe(&journal, NativeRecord::Request, Some(&observation)).unwrap(),
        ObservedNativeRecord::Unchanged
    ));
}

#[cfg(unix)]
#[test]
fn native_observation_closes_original_lock_and_ancestry_before_ordinary_results_escape() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("operation");
    let journal = Journal::create_preparation(&path, &norito::json!({"request": 7})).unwrap();
    let (_, observation) = decoded(observe(&journal, NativeRecord::Request, None).unwrap());
    for ordinary_error in [false, true] {
        let saved = root.path().join("saved-lock");
        let error = journal
            .read_native_scope(|read| {
                assert!(matches!(
                    read.read_native_observed::<norito::json::Value>(
                        NativeRecord::Request,
                        Some(&observation)
                    )?,
                    ObservedNativeRecord::Unchanged
                ));
                fs::rename(path.join("lock"), &saved)?;
                if ordinary_error {
                    Err(eyre!("ordinary observation refusal"))
                } else {
                    Ok(())
                }
            })
            .err()
            .unwrap();
        assert_ne!(error.to_string(), "ordinary observation refusal");
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
        fs::rename(saved, path.join("lock")).unwrap();
        assert!(matches!(
            observe(&journal, NativeRecord::Request, Some(&observation)).unwrap(),
            ObservedNativeRecord::Unchanged
        ));
    }
    let displaced = root.path().join("displaced-operation");
    let error = journal
        .read_native_scope(|read| {
            assert!(matches!(
                read.read_native_observed::<norito::json::Value>(
                    NativeRecord::Request,
                    Some(&observation)
                )?,
                ObservedNativeRecord::Unchanged
            ));
            fs::rename(&path, &displaced)?;
            Err::<(), _>(eyre!("ordinary observation refusal"))
        })
        .err()
        .unwrap();
    assert_ne!(error.to_string(), "ordinary observation refusal");
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    fs::rename(displaced, &path).unwrap();
    assert!(matches!(
        observe(&journal, NativeRecord::Request, Some(&observation)).unwrap(),
        ObservedNativeRecord::Unchanged
    ));
}
