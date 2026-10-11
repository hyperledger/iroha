//! Consuming genuine closure ownership preserves wallet callbacks, custody and active charges.

use super::*;
use crate::managed::native_operation::attempts::UnsignedClosureVerification;
use std::cell::Cell;

fn complete(value: Result<UnsignedClosureVerification>) -> VerifiedUnsignedClosure {
    match value.unwrap_or_else(|error| panic!("genuine closure refused: {error}")) {
        UnsignedClosureVerification::Closed(value) => value,
        UnsignedClosureVerification::Pending(_) => panic!("genuine retired body remains pending"),
    }
}
fn same_closure(actual: &VerifiedUnsignedClosure, original: &VerifiedUnsignedClosure) {
    assert_eq!(actual.digest(), original.digest());
    assert_eq!(actual.purpose(), original.purpose());
    assert_eq!(actual.closed_semantic(), original.closed_semantic());
    assert_eq!(actual.successor_selection(), original.successor_selection());
    assert_eq!(
        actual.cumulative_reserved_count(),
        original.cumulative_reserved_count()
    );
    actual.retained_history().test_require_current(4).0.unwrap();
}
struct ChangedRecord {
    directory: Arc<PrivateDirectory>,
    name: &'static str,
    original: zeroize::Zeroizing<Vec<u8>>,
}
impl ChangedRecord {
    fn replace(directory: &Arc<PrivateDirectory>, name: &'static str) -> Self {
        let value = Self {
            directory: Arc::clone(directory),
            name,
            original: directory.read(name, journal::MAX_ORIGINAL_BYTES).unwrap(),
        };
        let mut changed = value.original.to_vec();
        changed[0] ^= 1;
        directory
            .write_atomic(name, &changed, PublishMode::Replace)
            .unwrap();
        value
    }
}
impl Drop for ChangedRecord {
    fn drop(&mut self) {
        self.directory
            .write_atomic(self.name, &self.original, PublishMode::Replace)
            .expect("restore only the original test-owned closure record");
    }
}
fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
}

#[test]
fn owned_closed_history_moves_after_fresh_wallet_and_source_checks_with_active_recipe_parity() {
    let _guard = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history();
    let original = history.bodies[0].original.as_ref().unwrap();
    let oldest = history
        .current_history()
        .unwrap()
        .test_oldest_retained_history();
    let successor = history.successor(0).unwrap().unwrap();
    let account = fixture.owner.wallet().unwrap();
    let calls = Cell::new(0usize);
    let inspect = |attempt: &attempts::Attempt| {
        calls.set(calls.get() + 1);
        original
            .request(
                attempt.terms(),
                attempt.observation()?,
                fixture.options.deadline,
            )?
            .inspect_in_parent(&account, attempt.directory())
    };
    let borrowed = oldest.test_owned_closure_history().unwrap();
    let (baseline, reparses) =
        History::test_closure_parse_work(|| borrowed.verify_unsigned_closure(&successor, inspect));
    let baseline = baseline.unwrap().unwrap();
    assert_eq!(
        reparses, 1,
        "borrowed return still obtains its own parsed owner"
    );
    let original_calls = calls.replace(0);
    assert_eq!(
        original_calls, 2,
        "whole wallet pass and final exact tail inspection"
    );
    let owned = oldest.test_owned_closure_history().unwrap();
    let (moved, reparses) = History::test_closure_parse_work(|| {
        owned.into_unsigned_closure_with_pass(&successor, inspect, None)
    });
    assert_eq!(
        reparses, 0,
        "the actual parsed owner moves without another DTO reconstruction"
    );
    assert_eq!(calls.replace(0), original_calls);
    same_closure(&complete(moved), &baseline);

    // A changed source before entry is rejected before any wallet callback.
    for name in ["original.nrt", "closing.nrt", "closed.nrt", "dispatch.nrt"] {
        let owned = oldest.test_owned_closure_history().unwrap();
        let changed = ChangedRecord::replace(&history.bodies[0].directory, name);
        assert!(
            owned
                .into_unsigned_closure_with_pass(&successor, inspect, None)
                .is_err()
        );
        assert_eq!(calls.replace(0), 0);
        drop(changed);
    }
    // The last callback must not carry earlier source bytes, even when it returns an error.
    for name in ["original.nrt", "closing.nrt", "closed.nrt", "dispatch.nrt"] {
        for ordinary_error in [false, true] {
            let owned = oldest.test_owned_closure_history().unwrap();
            let mut changed = None;
            let result = owned.into_unsigned_closure_with_pass(
                &successor,
                |attempt| {
                    let value = inspect(attempt)?;
                    if calls.get() == original_calls {
                        changed = Some(ChangedRecord::replace(&history.bodies[0].directory, name));
                        if ordinary_error {
                            return Err(invalid("ordinary closure wallet refusal"));
                        }
                    }
                    Ok(value)
                },
                None,
            );
            let error = result.err().expect("last callback mutation must refuse");
            assert_eq!(calls.replace(0), original_calls);
            assert!(changed.is_some());
            assert_ne!(
                error.to_string(),
                invalid("ordinary closure wallet refusal").to_string()
            );
            drop(changed);
        }
    }
    let owned = oldest.test_owned_closure_history().unwrap();
    let unchanged_error = owned
        .into_unsigned_closure_with_pass(
            &successor,
            |attempt| {
                let value = inspect(attempt)?;
                if calls.get() == original_calls {
                    return Err(invalid("ordinary closure wallet refusal"));
                }
                Ok(value)
            },
            None,
        )
        .err()
        .expect("ordinary wallet refusal remains an error");
    assert_eq!(calls.replace(0), original_calls);
    assert_eq!(
        unchanged_error.to_string(),
        invalid("ordinary closure wallet refusal").to_string()
    );

    #[cfg(unix)]
    {
        // The late callback may replace a directory while returning an ordinary error.
        // Native retained handles, rather than matching path strings, must close the call.
        struct ReplacedDirectory {
            original: std::path::PathBuf,
            held: std::path::PathBuf,
        }
        impl Drop for ReplacedDirectory {
            fn drop(&mut self) {
                if self.original.exists() {
                    std::fs::remove_dir(&self.original).unwrap();
                }
                std::fs::rename(&self.held, &self.original).unwrap();
            }
        }
        let owned = oldest.test_owned_closure_history().unwrap();
        let mut replacement = None;
        let result = owned.into_unsigned_closure_with_pass(
            &successor,
            |attempt| {
                let value = inspect(attempt)?;
                if calls.get() == original_calls {
                    let original = history.bodies[0].directory.path().to_path_buf();
                    let held = original.with_extension("closure-owner-original");
                    std::fs::rename(&original, &held).unwrap();
                    let restore = ReplacedDirectory { original, held };
                    PrivateDirectory::open_or_create(&restore.original).unwrap();
                    replacement = Some(restore);
                    return Err(invalid("ordinary closure wallet refusal"));
                }
                Ok(value)
            },
            None,
        );
        assert_eq!(calls.replace(0), original_calls);
        assert!(replacement.is_some());
        assert_ne!(
            result
                .err()
                .expect("replaced original must refuse")
                .to_string(),
            invalid("ordinary closure wallet refusal").to_string()
        );
        drop(replacement);
    }

    // Active callers retain the original physical parser and every cumulative charge.
    let borrowed = oldest.test_owned_closure_history().unwrap();
    let owned = oldest.test_owned_closure_history().unwrap();
    let ((expected, old_parses), old_usage) =
        norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            History::test_closure_parse_work(|| {
                borrowed.verify_unsigned_closure(&successor, inspect)
            })
        });
    let expected = expected.unwrap().unwrap();
    assert_eq!(calls.replace(0), original_calls);
    let ((actual, new_parses), new_usage) =
        norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            History::test_closure_parse_work(|| {
                owned.into_unsigned_closure_with_pass(&successor, inspect, None)
            })
        });
    assert_eq!(calls.replace(0), original_calls);
    assert_eq!((old_parses, new_parses), (1, 1));
    assert_eq!(new_usage, old_usage);
    same_closure(&complete(actual), &expected);
    let exact = old_usage.total_allocated_bytes();
    assert!(exact > 1);
    for capacity in [0, 1, exact - 1] {
        let borrowed = oldest.test_owned_closure_history().unwrap();
        let owned = oldest.test_owned_closure_history().unwrap();
        let old = norito::with_decode_limits_scope(limits(capacity), || {
            borrowed.verify_unsigned_closure(&successor, inspect)
        })
        .err()
        .expect("original active refusal");
        let before = calls.replace(0);
        let new = norito::with_decode_limits_scope(limits(capacity), || {
            owned.into_unsigned_closure_with_pass(&successor, inspect, None)
        })
        .err()
        .expect("consuming active refusal");
        assert_eq!(calls.replace(0), before);
        assert_eq!(new.to_string(), old.to_string());
    }
    let owned = oldest.test_owned_closure_history().unwrap();
    let (retried, usage) = norito::core::with_decode_limits_measured(limits(exact), || {
        owned.into_unsigned_closure_with_pass(&successor, inspect, None)
    });
    assert_eq!(calls.replace(0), original_calls);
    assert_eq!(usage, old_usage);
    same_closure(&complete(retried), &baseline);
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn consumed_receipt_closes_one_native_census_and_refuses_oldest_post_callback_substitution() {
    let _guard = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    // Close body two again read-only, so its native graph contains the genuine retired
    // first body. The third body's active owner retains both original ancestor handles.
    let head = history.current_history().unwrap();
    let original = history.bodies[1].original.as_ref().unwrap();
    let successor = history.successor(1).unwrap().unwrap();
    let account = fixture.owner.wallet().unwrap();
    let calls = Cell::new(0usize);
    let inspect = |attempt: &attempts::Attempt| {
        calls.set(calls.get() + 1);
        original
            .request(
                attempt.terms(),
                attempt.observation()?,
                fixture.options.deadline,
            )?
            .inspect_in_parent(&account, attempt.directory())
    };
    let evidence = ["original.nrt", "dispatch.nrt", "closing.nrt", "closed.nrt"].map(|name| {
        (
            name,
            history.bodies[1]
                .directory
                .read(name, journal::MAX_ORIGINAL_BYTES)
                .unwrap(),
        )
    });
    let run = |recipe| {
        let owned = head.test_owned_predecessor_closure_history().unwrap();
        let capture = finish_timing::Capture::start();
        let (result, work) = History::test_validation_work(usize::MAX, || {
            History::test_original_receipt_census(recipe, || {
                owned.into_unsigned_closure_with_pass(&successor, inspect, None)
            })
        });
        let phases = capture.finish();
        (complete(result), work, phases, calls.replace(0))
    };
    let (baseline, before, old_phases, old_calls) = run(true);
    let (actual, after, new_phases, new_calls) = run(false);
    assert_eq!(
        old_calls, 2,
        "complete wallet pass plus exact final tail callback"
    );
    assert_eq!(new_calls, old_calls);
    same_closure(&actual, &baseline);
    // The old second census sees the consumed leaf at its new Arc address. Count
    // physical visits, while the optimized census still reaches both genuine bodies.
    assert_eq!(after.distinct_histories, 2);
    assert!(before.distinct_histories >= after.distinct_histories);
    assert_eq!(
        before.visits - after.visits,
        4,
        "one real two-body forward/reverse census"
    );
    assert_eq!(before.native_tree_visits - after.native_tree_visits, 4);
    assert_eq!(
        old_phases.sample(finish_timing::Phase::GraphValidate).0
            - new_phases.sample(finish_timing::Phase::GraphValidate).0,
        1,
        "the actual graph walker, not a fixture counter, loses one call"
    );
    for (name, original) in &evidence {
        assert_eq!(
            history.bodies[1]
                .directory
                .read(name, journal::MAX_ORIGINAL_BYTES)
                .unwrap()
                .as_slice(),
            original.as_slice(),
            "receipt admission must not rewrite retained custody"
        );
    }

    // Each final native-wallet callback can corrupt the oldest ancestor, not just the
    // consumed leaf. Both recipes must refuse at the same existing source boundary;
    // native refusal still supersedes an ordinary callback error.
    for name in ["original.nrt", "dispatch.nrt", "closing.nrt", "closed.nrt"] {
        for ordinary_error in [false, true] {
            let mut errors = Vec::new();
            for recipe in [true, false] {
                let owned = head.test_owned_predecessor_closure_history().unwrap();
                let mut changed = None;
                let result = History::test_original_receipt_census(recipe, || {
                    owned.into_unsigned_closure_with_pass(
                        &successor,
                        |attempt| {
                            let value = inspect(attempt)?;
                            if calls.get() == old_calls {
                                changed = Some(ChangedRecord::replace(
                                    &history.bodies[0].directory,
                                    name,
                                ));
                                if ordinary_error {
                                    return Err(invalid("ordinary ancestor callback refusal"));
                                }
                            }
                            Ok(value)
                        },
                        None,
                    )
                });
                assert_eq!(calls.replace(0), old_calls);
                assert!(changed.is_some());
                errors.push(
                    result
                        .err()
                        .expect("oldest custody mutation must refuse")
                        .to_string(),
                );
                drop(changed);
            }
            assert_eq!(errors[0], errors[1]);
            assert_ne!(
                errors[0],
                invalid("ordinary ancestor callback refusal").to_string()
            );
        }
    }
    for recipe in [true, false] {
        let owned = head.test_owned_predecessor_closure_history().unwrap();
        let error = History::test_original_receipt_census(recipe, || {
            owned.into_unsigned_closure_with_pass(
                &successor,
                |attempt| {
                    let value = inspect(attempt)?;
                    if calls.get() == old_calls {
                        return Err(invalid("ordinary ancestor callback refusal"));
                    }
                    Ok(value)
                },
                None,
            )
        })
        .err()
        .expect("unchanged custody preserves ordinary callback refusal");
        assert_eq!(calls.replace(0), old_calls);
        assert_eq!(
            error.to_string(),
            invalid("ordinary ancestor callback refusal").to_string()
        );
    }

    #[cfg(unix)]
    {
        struct RestoredAncestor {
            path: std::path::PathBuf,
            held: std::path::PathBuf,
        }
        impl Drop for RestoredAncestor {
            fn drop(&mut self) {
                std::fs::remove_dir(&self.path).expect("remove only empty test replacement");
                std::fs::rename(&self.held, &self.path).expect("restore exact native ancestor");
            }
        }
        for ordinary_error in [false, true] {
            let mut errors = Vec::new();
            for recipe in [true, false] {
                let owned = head.test_owned_predecessor_closure_history().unwrap();
                let mut replacement = None;
                let result = History::test_original_receipt_census(recipe, || {
                    owned.into_unsigned_closure_with_pass(
                        &successor,
                        |attempt| {
                            let value = inspect(attempt)?;
                            if calls.get() == old_calls {
                                let path = history.bodies[0].directory.path().to_owned();
                                let held = path.with_extension("receipt-original-ancestor");
                                assert!(!held.exists());
                                std::fs::rename(&path, &held).unwrap();
                                let restore = RestoredAncestor { path, held };
                                PrivateDirectory::open_or_create(&restore.path).unwrap();
                                replacement = Some(restore);
                                if ordinary_error {
                                    return Err(invalid("ordinary ancestor callback refusal"));
                                }
                            }
                            Ok(value)
                        },
                        None,
                    )
                });
                assert_eq!(calls.replace(0), old_calls);
                assert!(replacement.is_some());
                errors.push(
                    result
                        .err()
                        .expect("original ancestor handle must refuse")
                        .to_string(),
                );
                drop(replacement);
            }
            assert_eq!(errors[0], errors[1]);
            assert_ne!(
                errors[0],
                invalid("ordinary ancestor callback refusal").to_string()
            );
        }
    }

    // The literal active decoder branch is independent of the inactive recipe choice.
    // Ample admission returns the same receipt and graph/callback counts; capacities zero
    // and one retain their native early refusal. No sampled exact-cost edge is assumed.
    let mut active_results = Vec::new();
    for recipe in [true, false] {
        let owned = head.test_owned_predecessor_closure_history().unwrap();
        let ((result, work), usage) =
            norito::core::with_decode_limits_measured(limits(usize::MAX), || {
                History::test_validation_work(usize::MAX, || {
                    History::test_original_receipt_census(recipe, || {
                        owned.into_unsigned_closure_with_pass(&successor, inspect, None)
                    })
                })
            });
        same_closure(&complete(result), &baseline);
        assert_eq!(calls.replace(0), old_calls);
        assert!(usage.total_allocated_bytes() > 1);
        active_results.push((
            work.visits,
            work.native_tree_visits,
            usage.total_allocated_bytes(),
        ));
    }
    assert_eq!(active_results[0], active_results[1]);
    for capacity in [0, 1] {
        let mut refused = Vec::new();
        for recipe in [true, false] {
            let owned = head.test_owned_predecessor_closure_history().unwrap();
            let (result, usage) =
                norito::core::with_decode_limits_measured(limits(capacity), || {
                    History::test_original_receipt_census(recipe, || {
                        owned.into_unsigned_closure_with_pass(&successor, inspect, None)
                    })
                });
            refused.push((
                result
                    .err()
                    .expect("original finite decode budget refuses")
                    .to_string(),
                calls.replace(0),
                usage.total_allocated_bytes(),
            ));
        }
        assert_eq!(refused[0], refused[1]);
    }
    let (retried, _, _, callback_count) = run(false);
    same_closure(&retried, &baseline);
    assert_eq!(callback_count, old_calls);
    assert_eq!(fixture.native.chain.height(), 4);
}
