// Original JSON scope identity, source custody and retry controls.
#[test]
fn json_scoped_refusal_preserves_original_context_source_and_retry() {
    use iroha_allocation::{AllocationBudget, ChargedBuffer};
    use norito::core::{DecodeBudgetContext, classify_decode_attempt, with_decode_limits_measured};
    let limits = |bytes| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, 32);
    let literal = b"\"original finite JSON\"";
    let (decoded, usage) = with_decode_limits_measured(limits(usize::MAX), || {
        norito::json::from_json::<String>(std::str::from_utf8(literal).unwrap())
    });
    assert_eq!(decoded.unwrap(), "original finite JSON");
    let demand = usage.total_allocated_bytes();
    assert!(demand > 0);
    let pool = AllocationBudget::new(
        literal
            .len()
            .checked_add(DecodeBudgetContext::allocation_layout().size())
            .unwrap(),
    );
    let mut source = ChargedBuffer::new(literal.len(), &pool).unwrap();
    source.append(literal).unwrap();
    let source_pointer = source.as_slice().as_ptr();
    let source_charge = pool.reserved_bytes();
    let context =
        DecodeBudgetContext::try_new_owned(limits(demand.checked_mul(2).unwrap()), &pool).unwrap();
    let reserved = pool.reserved_bytes();
    let input = std::str::from_utf8(source.as_slice()).unwrap();
    let refused = context.with(|| {
        norito::with_decode_limits_scope(limits(0), || {
            classify_decode_attempt(|| {
                let original = norito::json::from_json::<String>(input).unwrap_err();
                assert!(matches!(
                    &original,
                    norito::json::Error::ScopedDecodeResource(_)
                ));
                Ok::<_, norito::Error>(super::json_decode_attempt_error(
                    original,
                    std::convert::identity,
                ))
            })
            .unwrap()
        })
    });
    assert!(
        matches!(&refused, ExecutionAttemptError::Deferred(reason)
                if reason.reason() == ExecutionDeferral::ActiveMemoryCapacity && reason.allocation_refusal().is_none()),
        "original scoped JSON refusal must retain its existing local attempt: {refused:?}"
    );
    assert_eq!(pool.reserved_bytes(), reserved);
    assert_eq!(source.as_slice().as_ptr(), source_pointer);
    let before_retry = context.consumed_allocated_bytes();
    assert!(before_retry > 0 && before_retry <= u64::try_from(demand).unwrap());
    let retry = context
        .with(|| norito::json::from_json::<String>(input))
        .unwrap();
    assert_eq!(retry, "original finite JSON");
    assert_eq!(
        context.consumed_allocated_bytes() - before_retry,
        u64::try_from(demand).unwrap()
    );
    drop(retry);
    assert_eq!(source.as_slice().as_ptr(), source_pointer);
    let malformed = context.with(|| {
        classify_decode_attempt(|| {
            let error = norito::json::from_json::<String>("[broken").unwrap_err();
            Ok::<_, norito::Error>(super::json_decode_attempt_error(
                error,
                std::convert::identity,
            ))
        })
        .unwrap()
    });
    assert!(
        matches!(malformed, ExecutionAttemptError::Rejected(error) if !error.is_decode_resource_limit())
    );
    // Intrinsic structural rejection happens in allocation-free preflight. A
    // narrow local allocation quota is not a substitute for an over-depth input.
    let depth_limit = norito::json::MAX_JSON_VALUE_NESTING_DEPTH;
    let over_depth = format!("{}null{}", "[".repeat(depth_limit), "]".repeat(depth_limit));
    let before_intrinsic = context.consumed_allocated_bytes();
    let intrinsic = context.with(|| {
        classify_decode_attempt(|| {
            let error = norito::json::from_json::<norito::json::Value>(&over_depth).unwrap_err();
            Ok::<_, norito::Error>(super::json_decode_attempt_error(
                error,
                std::convert::identity,
            ))
        })
        .unwrap()
    });
    assert!(matches!(
        intrinsic,
        ExecutionAttemptError::Rejected(norito::json::Error::NestingDepthExceeded {
            depth,
            limit,
            context: "JSON value",
        }) if depth == depth_limit + 1 && limit == depth_limit
    ));
    assert_eq!(context.consumed_allocated_bytes(), before_intrinsic);
    drop(refused);
    drop(context);
    assert_eq!(pool.reserved_bytes(), source_charge);
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn json_stale_scoped_refusal_keeps_its_original_tag_without_retry_authority() {
    use iroha_allocation::{AllocationBudget, ChargedBuffer};
    use norito::core::{DecodeBudgetContext, classify_decode_attempt};
    let literal = b"\"saved original JSON\"";
    let pool = AllocationBudget::new(
        literal
            .len()
            .checked_add(DecodeBudgetContext::allocation_layout().size())
            .unwrap(),
    );
    let mut source = ChargedBuffer::new(literal.len(), &pool).unwrap();
    source.append(literal).unwrap();
    let pointer = source.as_slice().as_ptr();
    let context = DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32),
        &pool,
    )
    .unwrap();
    let input = std::str::from_utf8(source.as_slice()).unwrap();
    let saved = context.with(|| {
        classify_decode_attempt(|| {
            Ok::<_, norito::Error>(norito::json::from_json::<String>(input).unwrap_err())
        })
        .unwrap()
    });
    let norito::json::Error::ScopedDecodeResource(tag) = &saved else {
        panic!("real saved JSON refusal must retain its original private tag: {saved:?}");
    };
    let tag = tag.clone();
    let rejected = context.with(|| {
        classify_decode_attempt(|| {
            // Same original counter owner and unchanged zero quota. A fresh local
            // refusal cannot authorize the saved sibling observer's error.
            let fresh = norito::json::from_json::<String>(input).unwrap_err();
            assert!(matches!(
                fresh,
                norito::json::Error::ScopedDecodeResource(_)
            ));
            Ok::<_, norito::Error>(super::json_decode_attempt_error(
                saved,
                std::convert::identity,
            ))
        })
        .unwrap()
    });
    let ExecutionAttemptError::Rejected(norito::json::Error::ScopedDecodeResource(returned)) =
        rejected
    else {
        panic!("saved JSON scope must remain its original completed error");
    };
    assert_eq!(returned, tag);
    assert_eq!(source.as_slice().as_ptr(), pointer);
    drop(returned);
    drop(tag);
    drop(context);
    assert_eq!(pool.reserved_bytes(), literal.len());
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn instruction_bridges_keep_original_refusal_without_discarded_diagnostic_allocations() {
    use iroha_data_model::isi::error::InstructionExecutionError;

    let state = crate::state::State::new_for_testing(
        crate::state::World::default(),
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    );
    let budget = iroha_allocation::AllocationBudget::new(8);
    let occupied = budget.try_reserve_bytes(8).unwrap();
    let original = budget.try_reserve_bytes(1).unwrap_err();
    for world_bridge in [true, false] {
        let mut block = state.block(iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let mut transaction = block.transaction();
        assert_eq!(transaction.execution_deferral(), None);
        for first in [true, false] {
            let reason = if first {
                original.clone().into()
            } else {
                ExecutionDeferral::AllocationUnavailable.into()
            };
            let mut returned = None;
            let allocations = crate::test_allocations::allocations_during(|| {
                let attempt = ExecutionAttemptError::Deferred(reason);
                returned = Some(if world_bridge {
                    transaction
                        .world
                        .attempt_error_to_instruction_error(attempt)
                } else {
                    transaction.attempt_error_to_instruction_error(attempt)
                });
            });
            assert_eq!(
                allocations, 1,
                "instruction bridge must allocate only its returned diagnostic, without a discarded ValidationFail"
            );
            let InstructionExecutionError::InvariantViolation(message) =
                returned.expect("same returned instruction diagnostic")
            else {
                panic!("local bridge diagnostic shape changed");
            };
            assert_eq!(
                message.as_ref(),
                if world_bridge {
                    "local execution attempt did not complete"
                } else {
                    "local instruction read did not complete"
                }
            );
            let retained = transaction.execution_deferral().unwrap();
            assert_eq!(retained.reason(), ExecutionDeferral::ActiveMemoryCapacity);
            assert_eq!(retained.allocation_refusal(), Some(&original));
            assert_eq!(budget.reserved_bytes(), 8);
        }
    }
    drop(occupied);
    assert!(budget.try_reserve_bytes(1).is_ok());
}
