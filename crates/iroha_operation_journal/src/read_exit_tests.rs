//! Mandatory original journal custody after real optional-read results.

use super::*;
use norito::core::DecodeBudgetContext;
use std::fs;

fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(0, 0, 0, allocation, 0)
}

#[test]
fn optional_read_preserves_absence_exact_allocation_refusal_bounds_and_retry() {
    let root = tempfile::tempdir().unwrap();
    let journal = Journal::create(&root.path().join("operation")).unwrap();
    let original = b"original";
    journal.install("evidence.json", original).unwrap();
    let lock = FileIdentity::of(&journal.lock).unwrap();

    let absent = DecodeBudgetContext::new(limits(0));
    assert_eq!(
        absent
            .with(|| journal.read_optional("missing.json"))
            .unwrap(),
        None
    );
    assert_eq!(absent.consumed_allocated_bytes(), 0);
    assert!(!norito::core::decode_limits_active());

    let exact = DecodeBudgetContext::new(limits(original.len()));
    assert_eq!(
        exact
            .with(|| journal.read_optional("evidence.json"))
            .unwrap(),
        Some(original.to_vec())
    );
    assert_eq!(exact.consumed_allocated_bytes(), original.len() as u64);
    for allocation in [0, 1] {
        let independent = DecodeBudgetContext::new(limits(allocation));
        let expected = independent
            .with(|| journal.read_optional_body("evidence.json"))
            .unwrap_err();
        let guarded = DecodeBudgetContext::new(limits(allocation));
        let actual = guarded
            .with(|| journal.read_optional("evidence.json"))
            .unwrap_err();
        assert!(matches!(
            actual.downcast_ref::<norito::Error>().and_then(|error| error.decode_resource_error()),
            Some(norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit })
                if attempted == original.len() as u64 && limit == allocation as u64
        ));
        assert_eq!(format!("{actual:#}"), format!("{expected:#}"));
        assert_eq!(
            guarded.consumed_allocated_bytes(),
            independent.consumed_allocated_bytes()
        );
        assert!(!norito::core::decode_limits_active());
        assert_eq!(
            journal.read_optional("evidence.json").unwrap(),
            Some(original.to_vec())
        );
    }

    let path = journal.path().join("evidence.json");
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len((MAX_JOURNAL_BYTES + 1) as u64)
        .unwrap();
    let bounded = DecodeBudgetContext::new(limits(0));
    assert_eq!(
        bounded
            .with(|| journal.read_optional("evidence.json"))
            .unwrap_err()
            .to_string(),
        "journal evidence exceeds its byte bound"
    );
    assert_eq!(bounded.consumed_allocated_bytes(), 0);
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(original.len() as u64)
        .unwrap();
    assert_eq!(
        journal.read_optional("evidence.json").unwrap(),
        Some(original.to_vec())
    );
    assert_eq!(fs::read(path).unwrap(), original);
    assert_eq!(FileIdentity::of(&journal.lock).unwrap(), lock);
}

#[cfg(unix)]
#[test]
fn real_optional_results_refuse_changed_ancestor_or_lock_at_exit_then_retry() {
    use std::{io, os::unix::fs::PermissionsExt as _};
    for attack in [
        "missing_directory",
        "replaced_ancestor",
        "missing_lock",
        "replaced_lock",
    ] {
        for outcome in ["absence", "oversize", "allocation", "bytes"] {
            let root = tempfile::tempdir().unwrap();
            let parent = OwnerDirectory::open(root.path())
                .unwrap()
                .create_private_child("parent")
                .unwrap();
            let path = parent.path().join("operation");
            let journal = Journal::create(&path).unwrap();
            let original = b"original";
            journal.install("evidence.json", original).unwrap();
            let lock = FileIdentity::of(&journal.lock).unwrap();
            if outcome == "oversize" {
                fs::OpenOptions::new()
                    .write(true)
                    .open(path.join("evidence.json"))
                    .unwrap()
                    .set_len((MAX_JOURNAL_BYTES + 1) as u64)
                    .unwrap();
            }
            let budget = DecodeBudgetContext::new(limits(if outcome == "allocation" {
                0
            } else {
                original.len()
            }));
            let displaced = root.path().join("displaced");
            let mut exit_message = String::new();
            let error = budget
                .with(|| {
                    journal.with_read_custody(|| {
                        // This is the sole production file-read body. Mutate only after its genuine
                        // None, bound/refusal, or completed bytes have been produced under custody.
                        let body = journal.read_optional_body(if outcome == "absence" {
                            "missing.json"
                        } else {
                            "evidence.json"
                        });
                        match outcome {
                            "absence" => assert!(matches!(&body, Ok(None))),
                            "oversize" => assert_eq!(
                                body.as_ref().unwrap_err().to_string(),
                                "journal evidence exceeds its byte bound"
                            ),
                            "allocation" => assert!(matches!(
                                body.as_ref().unwrap_err().downcast_ref::<norito::Error>().and_then(|error| error.decode_resource_error()),
                                Some(norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit: 0 })
                                    if attempted == original.len() as u64
                            )),
                            "bytes" => assert_eq!(
                                body.as_ref().unwrap().as_deref(),
                                Some(original.as_slice())
                            ),
                            _ => unreachable!(),
                        }
                        match attack {
                            "missing_directory" => fs::rename(&path, &displaced).unwrap(),
                            "replaced_ancestor" => {
                                fs::rename(parent.path(), &displaced).unwrap();
                                fs::create_dir(parent.path()).unwrap();
                                fs::set_permissions(
                                    parent.path(),
                                    fs::Permissions::from_mode(0o700),
                                )
                                .unwrap();
                            }
                            "missing_lock" => fs::rename(path.join("lock"), &displaced).unwrap(),
                            "replaced_lock" => {
                                fs::rename(path.join("lock"), &displaced).unwrap();
                                drop(journal.directory.create_lock("lock").unwrap());
                            }
                            _ => unreachable!(),
                        }
                        exit_message = format!("{:#}", journal.revalidate().unwrap_err());
                        if let Err(body_error) = &body {
                            assert_ne!(exit_message, format!("{body_error:#}"));
                        }
                        body
                    })
                })
                .unwrap_err();
            assert_eq!(format!("{error:#}"), exit_message);
            if matches!(attack, "missing_directory" | "missing_lock") {
                assert_eq!(
                    error.downcast_ref::<io::Error>().unwrap().kind(),
                    io::ErrorKind::NotFound
                );
            }
            assert_eq!(
                budget.consumed_allocated_bytes(),
                if outcome == "bytes" {
                    original.len() as u64
                } else {
                    0
                }
            );
            assert!(!norito::core::decode_limits_active());
            match attack {
                "missing_directory" => fs::rename(&displaced, &path).unwrap(),
                "replaced_ancestor" => {
                    fs::remove_dir(parent.path()).unwrap();
                    fs::rename(&displaced, parent.path()).unwrap();
                }
                "missing_lock" => fs::rename(&displaced, path.join("lock")).unwrap(),
                "replaced_lock" => {
                    fs::remove_file(path.join("lock")).unwrap();
                    fs::rename(&displaced, path.join("lock")).unwrap();
                }
                _ => unreachable!(),
            }
            if outcome == "oversize" {
                fs::OpenOptions::new()
                    .write(true)
                    .open(path.join("evidence.json"))
                    .unwrap()
                    .set_len(original.len() as u64)
                    .unwrap();
            }
            journal.revalidate().unwrap();
            assert_eq!(journal.read_optional("missing.json").unwrap(), None);
            assert_eq!(
                journal.read_optional("evidence.json").unwrap(),
                Some(original.to_vec())
            );
            assert_eq!(FileIdentity::of(&journal.lock).unwrap(), lock);
            assert_eq!(fs::read(path.join("evidence.json")).unwrap(), original);
        }
    }
}
