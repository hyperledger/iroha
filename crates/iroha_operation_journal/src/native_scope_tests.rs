//! Genuine fixed-record reads with inherited allocation, lock exit and lazy decoder controls.

use super::*;
use norito::core::DecodeBudgetContext;
use std::{cell::Cell, fs};

fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(0, 0, 0, allocation, 0)
}

#[test]
fn native_scope_preserves_exact_cumulative_allocation_refusals_absence_and_retry() {
    let root = tempfile::tempdir().unwrap();
    let request = norito::json!({"request": 7});
    let payload = norito::json!({"payload": 9});
    let journal = Journal::create_preparation(&root.path().join("operation"), &request).unwrap();
    journal
        .write_native(NativeRecord::Payload, &payload)
        .unwrap();
    let first = fs::read(journal.path().join("preparation.json")).unwrap();
    let second = fs::read(journal.path().join("payload.json")).unwrap();
    for allocation in [0, 1, first.len()] {
        let plain = DecodeBudgetContext::new(limits(allocation));
        let expected = plain.with(|| journal.read_optional("preparation.json"));
        let scoped = DecodeBudgetContext::new(limits(allocation));
        let actual = scoped
            .with(|| journal.read_native_scope(|read| read.read_optional("preparation.json")));
        assert_eq!(
            scoped.consumed_allocated_bytes(),
            plain.consumed_allocated_bytes()
        );
        if allocation == first.len() {
            assert_eq!(actual.unwrap(), expected.unwrap());
        } else {
            let actual = actual.unwrap_err();
            assert_eq!(
                format!("{actual:#}"),
                format!("{:#}", expected.unwrap_err())
            );
            assert!(
                matches!(actual.downcast_ref::<norito::Error>().and_then(|error| error.decode_resource_error()),
                Some(norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit })
                    if attempted == u64::try_from(first.len()).unwrap() && limit == u64::try_from(allocation).unwrap())
            );
        }
        assert!(!norito::core::decode_limits_active());
    }
    let absent = DecodeBudgetContext::new(limits(0));
    assert_eq!(
        absent
            .with(|| journal.read_native_scope(|read| read.read_optional("retired.json")))
            .unwrap(),
        None
    );
    assert_eq!(absent.consumed_allocated_bytes(), 0);
    let exact = DecodeBudgetContext::new(limits(first.len() + second.len()));
    let bytes = exact
        .with(|| {
            journal.read_native_scope(|read| {
                let first = read.read_optional("preparation.json")?.unwrap();
                let second = read.read_optional("payload.json")?.unwrap();
                Ok((first, second))
            })
        })
        .unwrap();
    assert_eq!(bytes, (first.clone(), second.clone()));
    assert_eq!(
        exact.consumed_allocated_bytes(),
        u64::try_from(first.len() + second.len()).unwrap()
    );
    assert_eq!(journal.read_native_scope(|read| read.read_native::<norito::json::Value>(NativeRecord::Request)).unwrap(), Some(request));
    assert_eq!(
        journal
            .read_native::<norito::json::Value>(NativeRecord::Payload)
            .unwrap(),
        Some(payload)
    );
}

#[test]
fn native_scope_preserves_lazy_canonical_failure_and_submission_short_circuit() {
    let root = tempfile::tempdir().unwrap();
    let request = norito::json!({"request": 7});
    let journal = Journal::create_preparation(&root.path().join("operation"), &request).unwrap();
    journal
        .directory
        .write_atomic("preparation.json", b"{", PublishMode::Replace)
        .unwrap();
    journal
        .directory
        .write_atomic("payload.json", b"later", PublishMode::CreateNew)
        .unwrap();
    let original = journal
        .read_native::<norito::json::Value>(NativeRecord::Request)
        .unwrap_err();
    fs::OpenOptions::new()
        .write(true)
        .open(journal.path().join("payload.json"))
        .unwrap()
        .set_len(u64::try_from(MAX_JOURNAL_BYTES + 1).unwrap())
        .unwrap();
    let later = Cell::new(false);
    let actual = journal
        .read_native_scope(|read| {
            let value = read.read_native::<norito::json::Value>(NativeRecord::Request)?;
            assert!(value.is_some());
            later.set(true);
            let _ = read.read_native::<norito::json::Value>(NativeRecord::Payload)?;
            Err::<(), _>(eyre!(
                "the invalid first record reached a later semantic branch"
            ))
        })
        .unwrap_err();
    assert_eq!(format!("{actual:#}"), format!("{original:#}"));
    assert!(!later.get());
    assert!(!format!("{actual:#}").contains("journal evidence exceeds its byte bound"));
    journal
        .directory
        .write_atomic(
            "preparation.json",
            &canonical_bytes(&request).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert_eq!(journal.read_native_scope(|read| read.read_native::<norito::json::Value>(NativeRecord::Request)).unwrap(), Some(request.clone()));
    assert!(journal.record_submission(&request).unwrap());
    journal
        .directory
        .write_atomic(APPLIED_EVIDENCE, b"later", PublishMode::CreateNew)
        .unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(journal.path().join(APPLIED_EVIDENCE))
        .unwrap()
        .set_len(u64::try_from(MAX_JOURNAL_BYTES + 1).unwrap())
        .unwrap();
    assert!(
        journal
            .read_native_scope(|read| read.has_dispatch_evidence())
            .unwrap()
    );
    assert!(
        journal
            .read_native_scope(|read| read.submission_recorded(&request))
            .unwrap()
    );
    let different = norito::json!({"request": 8});
    assert_eq!(
        journal
            .read_native_scope(|read| read.submission_recorded(&different))
            .unwrap_err()
            .to_string(),
        "submission marker differs from the exact retained operation"
    );
}

#[cfg(unix)]
#[test]
fn native_scope_lock_exit_precedes_decode_and_outer_ancestry_dominates_typed_failures() {
    let root = tempfile::tempdir().unwrap();
    let journal = Journal::create_preparation(
        &root.path().join("operation"),
        &norito::json!({"request": 7}),
    )
    .unwrap();
    let original_lock = FileIdentity::of(&journal.lock).unwrap();
    let saved = root.path().join("saved-lock");
    journal
        .directory
        .write_atomic("preparation.json", b"{", PublishMode::Replace)
        .unwrap();
    let error = journal
        .directory
        .read_scope(|reader| {
            journal.with_read_custody_in_scope(reader, |reader| {
                let body = NativeJournalReadScope::read_optional_body(
                    &journal,
                    reader,
                    "preparation.json",
                );
                assert_eq!(body.as_ref().unwrap().as_deref(), Some(b"{".as_slice()));
                fs::rename(journal.path().join("lock"), &saved)?;
                body
            })
        })
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    assert!(!format!("{error:#}").contains("invalid native preparation evidence"));
    fs::rename(&saved, journal.path().join("lock")).unwrap();
    assert_eq!(FileIdentity::of(&journal.lock).unwrap(), original_lock);
    assert_eq!(journal.read_native_scope(|read| read.read_native::<norito::json::Value>(NativeRecord::Request)).unwrap_err().to_string(), "invalid native preparation evidence");

    for outcome in ["absence", "allocation", "decoder"] {
        let displaced = root.path().join("displaced-operation");
        let result = journal
            .read_native_scope(|read| {
                let body = match outcome {
                    "absence" => read
                        .read_optional("retired.json")
                        .map(|value| value.map(|_| ())),
                    "allocation" => DecodeBudgetContext::new(limits(0))
                        .with(|| read.read_optional("preparation.json"))
                        .map(|value| value.map(|_| ())),
                    "decoder" => read
                        .read_native::<norito::json::Value>(NativeRecord::Request)
                        .map(|value| value.map(|_| ())),
                    _ => unreachable!(),
                };
                match outcome {
                    "absence" => assert!(matches!(&body, Ok(None))),
                    "allocation" => assert!(
                        body.as_ref()
                            .unwrap_err()
                            .downcast_ref::<norito::Error>()
                            .is_some()
                    ),
                    "decoder" => assert_eq!(
                        body.as_ref().unwrap_err().to_string(),
                        "invalid native preparation evidence"
                    ),
                    _ => unreachable!(),
                }
                fs::rename(journal.path(), &displaced)?;
                body
            })
            .unwrap_err();
        assert_eq!(
            result.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
        fs::rename(&displaced, journal.path()).unwrap();
        assert_eq!(
            journal
                .read_native_scope(|read| read.read_optional("retired.json"))
                .unwrap(),
            None
        );
        assert_eq!(FileIdentity::of(&journal.lock).unwrap(), original_lock);
    }
    journal
        .directory
        .write_atomic(
            "preparation.json",
            &canonical_bytes(&norito::json!({"request": 7})).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert!(journal.read_native_scope(|read| read.read_native::<norito::json::Value>(NativeRecord::Request)).unwrap().is_some());
}
