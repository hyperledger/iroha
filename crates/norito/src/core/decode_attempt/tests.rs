//! Exact origin, protocol precedence, and complete canonical retry regressions.

use super::*;
use crate::core::{DecodeDepthGuard, DecodeLimits, with_decode_limits_scope};

fn allocation_limit(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}

#[test]
fn canonical_refusal_retries_original_frame_and_preserves_bytes() {
    let value = vec!["first".to_owned(), "second".to_owned()];
    let bytes = crate::encode_canonical(&value).unwrap();
    let original = bytes.clone();
    let protocol = crate::canonical_decode_limits(bytes.len());
    let failure = with_decode_limits_scope(allocation_limit(0), || {
        crate::decode_canonical_for_admission::<Vec<String>>(&bytes, protocol)
    })
    .unwrap_err();
    assert_eq!(failure.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert!(matches!(
        failure.into_error().decode_resource_error(),
        Some(DecodeResourceError::TotalAllocationExceeded { limit: 0, .. })
    ));
    assert_eq!(
        crate::decode_canonical_for_admission::<Vec<String>>(&bytes, protocol).unwrap(),
        value
    );
    assert_eq!(bytes, original);
}

#[test]
fn equal_protocol_limit_is_not_relabelled_by_an_enclosing_scope() {
    let failure = with_decode_limits_scope(allocation_limit(8), || {
        classify_decode_attempt(|| {
            with_decode_limits_scope(allocation_limit(8), || {
                super::super::reserve_decode_allocation(9)
            })
        })
    })
    .unwrap_err();
    assert_eq!(failure.kind(), DecodeAttemptErrorKind::Invalid);
    let error = failure.into_error();
    with_decode_limits_scope(allocation_limit(8), || {
        assert!(!super::super::decode_error_matches_active_limits(&error));
    });
}

#[test]
fn cumulative_enclosing_refusal_can_have_equal_or_wider_limit() {
    for outer in [8, 16] {
        let failure = with_decode_limits_scope(allocation_limit(outer), || {
            super::super::reserve_decode_allocation(outer - 1).unwrap();
            classify_decode_attempt(|| {
                with_decode_limits_scope(allocation_limit(8), || {
                    super::super::reserve_decode_allocation(2)
                })
            })
        })
        .unwrap_err();
        assert_eq!(failure.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        assert_eq!(
            failure.into_error().decode_resource_error(),
            Some(DecodeResourceError::TotalAllocationExceeded {
                attempted: u64::try_from(outer + 1).unwrap(),
                limit: u64::try_from(outer).unwrap(),
            })
        );
    }
}

#[test]
fn every_budget_check_preserves_the_actual_emitting_layer() {
    for check in 0..6 {
        let limits = match check {
            0 | 5 => DecodeLimits::new(0, usize::MAX, usize::MAX, usize::MAX, usize::MAX),
            1 => DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, usize::MAX),
            2 => DecodeLimits::new(usize::MAX, usize::MAX, 0, usize::MAX, usize::MAX),
            3 => allocation_limit(0),
            _ => DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 0),
        };
        let run = || match check {
            0 => super::super::check_decode_sequence_length(1),
            1 => super::super::check_decode_field_length(1),
            2 | 5 => super::super::enforce_decode_sequence_length(1),
            3 => super::super::reserve_decode_allocation(1),
            _ => DecodeDepthGuard::enter().map(|_| ()),
        };
        let local = with_decode_limits_scope(limits, || {
            classify_decode_attempt(|| with_decode_limits_scope(allocation_limit(usize::MAX), run))
        })
        .unwrap_err();
        assert_eq!(
            local.kind(),
            DecodeAttemptErrorKind::EnclosingLimit,
            "check {check}"
        );
        let protocol = with_decode_limits_scope(limits, || {
            classify_decode_attempt(|| with_decode_limits_scope(limits, run))
        })
        .unwrap_err();
        assert_eq!(
            protocol.kind(),
            DecodeAttemptErrorKind::Invalid,
            "check {check}"
        );
    }
}

#[test]
fn nested_attempts_preserve_protocol_precedence_before_consumers_project_errors() {
    for (outer_limit, protocol_limit, expected) in [
        (0, 1, DecodeAttemptErrorKind::Invalid),
        (0, 8, DecodeAttemptErrorKind::EnclosingLimit),
    ] {
        let failure = with_decode_limits_scope(allocation_limit(outer_limit), || {
            classify_decode_attempt(|| {
                with_decode_limits_scope(allocation_limit(protocol_limit), || {
                    let inner = classify_decode_attempt(|| {
                        with_decode_limits_scope(allocation_limit(8), || {
                            super::super::reserve_decode_allocation(2)
                        })
                    })
                    .unwrap_err();
                    // An immediate metadata adapter consumes this classification before
                    // any outer classifier can inspect the original error again.
                    assert_eq!(inner.kind(), expected);
                    Err::<(), _>(inner.into_error())
                })
            })
        })
        .unwrap_err();
        assert_eq!(failure.kind(), expected);
        assert!(matches!(
            failure.into_error().decode_resource_error(),
            Some(DecodeResourceError::TotalAllocationExceeded { limit, .. })
                if limit == if expected == DecodeAttemptErrorKind::Invalid { 1 } else { 0 }
        ));
    }
}

#[test]
fn swallowed_reconstructed_and_previous_attempt_errors_do_not_gain_origin() {
    let protocol = allocation_limit(8);
    let failure = with_decode_limits_scope(allocation_limit(0), || {
        classify_decode_attempt(|| {
            with_decode_limits_scope(protocol, || {
                let caught = classify_decode_attempt(|| super::super::reserve_decode_allocation(1))
                    .unwrap_err();
                let resource = caught.into_error().decode_resource_error().unwrap();
                Err::<(), _>(Error::from(resource))
            })
        })
    })
    .unwrap_err();
    assert_eq!(failure.kind(), DecodeAttemptErrorKind::Invalid);
    with_decode_limits_scope(allocation_limit(0), || {
        let old = classify_decode_attempt(|| {
            with_decode_limits_scope(protocol, || super::super::reserve_decode_allocation(1))
        })
        .unwrap_err();
        assert_eq!(old.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        let new = classify_decode_attempt(|| {
            with_decode_limits_scope(protocol, || Err::<(), _>(old.into_error()))
        })
        .unwrap_err();
        assert_eq!(new.kind(), DecodeAttemptErrorKind::Invalid);
    });
}

#[test]
fn observer_unwind_restores_ordinary_budget_errors() {
    let panic = std::panic::catch_unwind(|| {
        let _: Result<(), _> = classify_decode_attempt(|| {
            with_decode_limits_scope(allocation_limit(8), || panic!("decode unwind"))
        });
    });
    assert!(panic.is_err());
    let error = with_decode_limits_scope(allocation_limit(0), || {
        super::super::reserve_decode_allocation(1)
    })
    .unwrap_err();
    assert!(matches!(
        error,
        Error::TotalAllocationExceeded { limit: 0, .. }
    ));
}

#[test]
fn allocator_errors_are_local_but_unproven_resource_and_encode_errors_are_invalid() {
    let error = classify_decode_attempt(|| Err::<(), _>(Error::AllocationFailed { bytes: 16 }))
        .unwrap_err();
    assert_eq!(error.kind(), DecodeAttemptErrorKind::Allocator);
    for original in [
        Error::TotalAllocationExceeded {
            attempted: 1,
            limit: 0,
        },
        Error::NestingDepthExceeded {
            depth: 33,
            limit: 32,
            context: "encode budget",
        },
        Error::ArchiveLengthExceeded {
            length: 2,
            limit: 1,
        },
        Error::InvalidMagic,
    ] {
        assert_eq!(
            classify_decode_attempt(|| Err::<(), _>(original))
                .unwrap_err()
                .kind(),
            DecodeAttemptErrorKind::Invalid
        );
    }
}

#[cfg(feature = "json")]
#[test]
fn canonical_json_parser_and_writer_preserve_original_refusal_and_protocol_kind() {
    let allocator =
        crate::json::Error::from_decode_resource(Error::AllocationFailed { bytes: 137 });
    assert!(allocator.is_decode_resource_limit());
    let original = allocator.into_core_error();
    assert_eq!(
        original.decode_resource_error(),
        Some(DecodeResourceError::AllocationFailed { bytes: 137 })
    );
    assert_eq!(
        classify_decode_attempt(|| Err::<(), _>(original))
            .unwrap_err()
            .kind(),
        DecodeAttemptErrorKind::Allocator
    );

    for parse in [true, false] {
        for (outer, protocol, kind) in [
            (0, usize::MAX, DecodeAttemptErrorKind::EnclosingLimit),
            (0, 0, DecodeAttemptErrorKind::Invalid),
        ] {
            let refusal = with_decode_limits_scope(allocation_limit(outer), || {
                classify_decode_attempt(|| {
                    with_decode_limits_scope(allocation_limit(protocol), || {
                        if parse {
                            crate::json::parse_value("[1,2]")
                                .map(crate::json::drop_json_value_iteratively)
                                .map_err(crate::json::Error::into_core_error)
                        } else {
                            crate::json::to_json_bounded(&crate::json::Value::Null, 4)
                                .map(drop)
                                .map_err(crate::json::BoundedJsonError::into_core_error)
                        }
                    })
                })
            })
            .unwrap_err();
            assert_eq!(refusal.kind(), kind, "parse {parse}");
            assert!(matches!(
                refusal.into_error().decode_resource_error(),
                Some(DecodeResourceError::TotalAllocationExceeded { limit: 0, .. })
            ));
        }
    }
    assert_eq!(
        crate::json::parse_value("[1,2]").unwrap(),
        crate::json!([1, 2])
    );
    assert_eq!(
        crate::json::to_json_bounded(&crate::json::Value::Null, 4).unwrap(),
        "null"
    );
    let body = with_decode_limits_scope(allocation_limit(0), || {
        classify_decode_attempt(|| {
            with_decode_limits_scope(allocation_limit(usize::MAX), || {
                crate::json::to_json_bounded(&crate::json::Value::Null, 3)
                    .map_err(crate::json::BoundedJsonError::into_core_error)
            })
        })
    })
    .unwrap_err();
    assert_eq!(body.kind(), DecodeAttemptErrorKind::Invalid);
}

#[test]
fn public_closure_admission_uses_same_origin_kernel_after_caller_unwind() {
    let value = vec!["original first".to_owned(), "original second".to_owned()];
    let bytes = crate::encode_canonical(&value).unwrap();
    let saved = std::cell::RefCell::new(None);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_decode_limits_scope(allocation_limit(0), || {
            *saved.borrow_mut() = Some(
                classify_decode_attempt(|| {
                    crate::decode_canonical_with_limits::<Vec<String>>(
                        &bytes,
                        crate::canonical_decode_limits(bytes.len()),
                    )
                })
                .unwrap_err(),
            );
            panic!("retire enclosing caller scope");
        })
    }));
    assert!(unwind.is_err());
    let original = saved.into_inner().unwrap();
    assert_eq!(original.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert!(matches!(
        original.into_error().decode_resource_error(),
        Some(DecodeResourceError::TotalAllocationExceeded { limit: 0, .. })
    ));
    assert_eq!(
        classify_decode_attempt(|| crate::decode_canonical_with_limits::<Vec<String>>(
            &bytes,
            crate::canonical_decode_limits(bytes.len()),
        ))
        .unwrap(),
        value
    );
}

// Direct checked JSON producers share the original attempt provenance owner.

#[cfg(feature = "json")]
#[test]
fn direct_json_refusal_keeps_original_context_and_retry() {
    let source = "[1,2]";
    let expected = crate::json::parse_value(source).unwrap();
    let pool = iroha_allocation::AllocationBudget::new(65_536);
    let original =
        super::super::DecodeBudgetContext::try_new_owned(allocation_limit(usize::MAX), &pool)
            .unwrap();
    let quota = super::super::DecodeBudgetContext::new(allocation_limit(0));
    let baseline = pool.reserved_bytes();
    for parse in [true, false] {
        let refusal = original
            .with(|| {
                quota.with(|| {
                    classify_decode_attempt(|| {
                        if parse {
                            crate::json::parse_value(source)
                                .map(crate::json::drop_json_value_iteratively)
                                .map_err(crate::json::Error::into_core_error)
                        } else {
                            crate::json::to_json_bounded(&crate::json::Value::Null, 4)
                                .map(drop)
                                .map_err(crate::json::BoundedJsonError::into_core_error)
                        }
                    })
                })
            })
            .unwrap_err();
        assert_eq!(
            refusal.kind(),
            DecodeAttemptErrorKind::EnclosingLimit,
            "direct checked JSON refusal must retain its original enclosing provenance"
        );
        assert!(matches!(
            refusal.into_error().decode_resource_error(),
            Some(DecodeResourceError::TotalAllocationExceeded { limit: 0, .. })
        ));
        assert_eq!(pool.reserved_bytes(), baseline);
        original.with(|| {
            assert_eq!(crate::json::parse_value(source).unwrap(), expected);
            assert_eq!(
                crate::json::to_json_bounded(&crate::json::Value::Null, 4).unwrap(),
                "null"
            );
        });
        assert_eq!(pool.reserved_bytes(), baseline);
    }
    let malformed = original
        .with(|| {
            classify_decode_attempt(|| {
                crate::json::parse_value("{not-json}").map_err(crate::json::Error::into_core_error)
            })
        })
        .unwrap_err();
    assert_eq!(malformed.kind(), DecodeAttemptErrorKind::Invalid);
    drop(malformed);
    drop(quota);
    drop(original);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn direct_attempt_replay_under_same_counter_owner_is_invalid() {
    let pool = iroha_allocation::AllocationBudget::new(65_536);
    let original =
        super::super::DecodeBudgetContext::try_new_owned(allocation_limit(0), &pool).unwrap();
    let baseline = pool.reserved_bytes();
    original.with(|| {
        let failure =
            classify_decode_attempt(|| super::super::reserve_decode_allocation(1)).unwrap_err();
        assert_eq!(failure.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        let Error::ScopedDecodeResource(saved) = failure.into_error() else {
            panic!("actual original scope identity must be retained");
        };
        for swallow_fresh in [false, true] {
            let replay = classify_decode_attempt(|| {
                if swallow_fresh {
                    let current = super::super::reserve_decode_allocation(1).unwrap_err();
                    let Error::ScopedDecodeResource(current) = current else {
                        panic!("fresh same-context refusal must retain provenance");
                    };
                    assert!(saved.family.same(&current.family));
                    drop(current);
                }
                Err::<(), _>(Error::ScopedDecodeResource(saved.clone()))
            })
            .unwrap_err();
            assert_eq!(
                replay.kind(),
                DecodeAttemptErrorKind::Invalid,
                "saved refusal cannot acquire a later direct boundary under the same counters"
            );
        }
        let reconstructed =
            classify_decode_attempt(|| Err::<(), _>(Error::from(saved.resource()))).unwrap_err();
        assert_eq!(reconstructed.kind(), DecodeAttemptErrorKind::Invalid);
    });
    assert_eq!(pool.reserved_bytes(), baseline);
    drop(original);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn direct_attempt_cross_thread_replay_with_original_shared_context_is_invalid() {
    let pool = iroha_allocation::AllocationBudget::new(65_536);
    let original =
        super::super::DecodeBudgetContext::try_new_owned(allocation_limit(0), &pool).unwrap();
    let baseline = pool.reserved_bytes();
    let saved = original.with(|| {
        let failure =
            classify_decode_attempt(|| super::super::reserve_decode_allocation(1)).unwrap_err();
        assert_eq!(failure.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        let Error::ScopedDecodeResource(saved) = failure.into_error() else {
            panic!("actual original scope identity must be retained");
        };
        saved
    });
    let shared = original.clone();
    std::thread::spawn(move || {
        shared.with(|| {
            for swallow_fresh in [false, true] {
                let replay = classify_decode_attempt(|| {
                    if swallow_fresh {
                        let current = super::super::reserve_decode_allocation(1).unwrap_err();
                        let Error::ScopedDecodeResource(current) = current else {
                            panic!("fresh same-context refusal must retain provenance");
                        };
                        assert!(saved.family.same(&current.family));
                        drop(current);
                    }
                    Err::<(), _>(Error::ScopedDecodeResource(saved.clone()))
                })
                .unwrap_err();
                assert_eq!(
                    replay.kind(),
                    DecodeAttemptErrorKind::Invalid,
                    "foreign observer cannot adopt a saved refusal from the same shared counters"
                );
            }
            let current =
                classify_decode_attempt(|| super::super::reserve_decode_allocation(1)).unwrap_err();
            assert_eq!(current.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        });
    })
    .join()
    .unwrap();
    assert_eq!(pool.reserved_bytes(), baseline);
    drop(original);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn already_active_direct_attempt_rejects_later_foreign_thread_root() {
    let pool = iroha_allocation::AllocationBudget::new(65_536);
    let original =
        super::super::DecodeBudgetContext::try_new_owned(allocation_limit(0), &pool).unwrap();
    let baseline = pool.reserved_bytes();
    let shared = original.clone();
    let replay = original
        .with(|| {
            classify_decode_attempt(|| {
                // The receiver's observer already exists. A foreign refusal therefore
                // has a later ordinal, which alone cannot exclude its unrelated root.
                let saved = std::thread::spawn(move || {
                    shared.with(|| {
                        let refusal =
                            classify_decode_attempt(|| super::super::reserve_decode_allocation(1))
                                .unwrap_err();
                        assert_eq!(refusal.kind(), DecodeAttemptErrorKind::EnclosingLimit);
                        let Error::ScopedDecodeResource(saved) = refusal.into_error() else {
                            panic!("foreign original scope identity must be retained");
                        };
                        saved
                    })
                })
                .join()
                .unwrap();
                let Error::ScopedDecodeResource(current) =
                    super::super::reserve_decode_allocation(1).unwrap_err()
                else {
                    panic!("fresh local refusal must retain provenance");
                };
                assert!(saved.family.same(&current.family));
                assert_ne!(saved.identity.root, current.identity.root);
                assert!(saved.identity.boundary > current.identity.boundary);
                drop(current);
                Err::<(), _>(Error::ScopedDecodeResource(saved))
            })
        })
        .unwrap_err();
    assert_eq!(
        replay.kind(),
        DecodeAttemptErrorKind::Invalid,
        "a later foreign-thread refusal cannot borrow an already-active receiver's root"
    );
    drop(replay);
    assert_eq!(pool.reserved_bytes(), baseline);
    drop(original);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn direct_nested_attempts_preserve_parent_origin_and_refuse_old_sibling() {
    let pool = iroha_allocation::AllocationBudget::new(65_536);
    let original =
        super::super::DecodeBudgetContext::try_new_owned(allocation_limit(0), &pool).unwrap();
    let propagated = original
        .with(|| {
            classify_decode_attempt(|| {
                let inner = classify_decode_attempt(|| super::super::reserve_decode_allocation(1))
                    .unwrap_err();
                assert_eq!(inner.kind(), DecodeAttemptErrorKind::EnclosingLimit);
                Err::<(), _>(inner.into_error())
            })
        })
        .unwrap_err();
    assert_eq!(propagated.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    drop(propagated);
    original.with(|| {
        classify_decode_attempt(|| {
            let saved =
                classify_decode_attempt(|| super::super::reserve_decode_allocation(1)).unwrap_err();
            assert_eq!(saved.kind(), DecodeAttemptErrorKind::EnclosingLimit);
            let saved = saved.into_error();
            let sibling = classify_decode_attempt(|| {
                drop(super::super::reserve_decode_allocation(1).unwrap_err());
                Err::<(), _>(saved)
            })
            .unwrap_err();
            assert_eq!(sibling.kind(), DecodeAttemptErrorKind::Invalid);
            Ok(())
        })
        .unwrap();
    });
    drop(original);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn observer_boundary_sequence_exhaustion_never_wraps() {
    let sequence = super::super::AtomicU64::new(u64::MAX - 1);
    assert_eq!(super::next_boundary(&sequence), Some(u64::MAX));
    assert_eq!(super::next_boundary(&sequence), None);
    assert_eq!(super::next_boundary(&sequence), None);
    assert_eq!(sequence.load(super::super::Ordering::Relaxed), u64::MAX);
}
