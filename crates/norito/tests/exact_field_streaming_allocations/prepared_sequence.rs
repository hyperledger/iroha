//! Prepared sequence scratch, exact canonical order and original refusal parity.

use iroha_allocation::{AllocationBudget, ChargedBuffer};
use norito::core::{
    DecodeFlagsGuard, DecodeFromSlice, DecodeIntoError, DecodeLimits, PreparedDecodeWorkspace,
    SequenceDestinationError, SequenceSpan, decode_element_sequence_from_slice_serial,
    decode_raw_byte_sequence_into, header_flags, prepare_element_sequence, with_decode_limits,
};
use std::convert::Infallible;

fn initialized<T: Copy>(pool: &AllocationBudget, count: usize, value: T) -> ChargedBuffer<T> {
    let layout = std::alloc::Layout::array::<T>(count).unwrap();
    let mut reservation = pool.try_reserve_layouts([layout]).unwrap();
    let mut buffer = ChargedBuffer::from_reservation(count, &mut reservation).unwrap();
    for _ in 0..count {
        buffer.push_reserved(value);
    }
    buffer
}
fn scratch(pool: &AllocationBudget, count: usize) -> ChargedBuffer<SequenceSpan> {
    initialized(
        pool,
        count,
        SequenceSpan {
            start: usize::MAX,
            end: usize::MAX,
        },
    )
}
fn codec(error: SequenceDestinationError) -> norito::Error {
    match error {
        SequenceDestinationError::Codec(error) => error,
        other => panic!("unexpected local geometry: {other}"),
    }
}
fn limits(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(4096, 1 << 20, 1 << 20, bytes, 32)
}
fn workspace(pool: &AllocationBudget) -> PreparedDecodeWorkspace {
    let mut reservation = pool
        .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
        .unwrap();
    PreparedDecodeWorkspace::from_reservation(pool, &mut reservation).unwrap()
}

#[test]
fn prepared_spans_keep_every_advertised_layout_and_unused_slots_out_of_the_plan() {
    let pool = AllocationBudget::new(1 << 20);
    let mut spans = scratch(&pool, 962);
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for count in [0, 4, 31, 961] {
            let values: Vec<u64> = (0..count as u64).map(|i| i * 7 + 3).collect();
            let bytes = super::bare_bytes(&values, flags);
            let (ordinary, used) =
                decode_element_sequence_from_slice_serial::<u64>(&bytes).unwrap();
            let plan = prepare_element_sequence(&bytes, spans.as_mut_slice()).unwrap();
            assert_eq!(plan.len(), count);
            assert_eq!(plan.is_empty(), count == 0);
            assert_eq!(plan.used(), used);
            let mut visited = 0;
            plan.decode_elements::<u64, Infallible>(|index, field| {
                let value = field.with_payload(|bytes| {
                    let (value, used) = u64::decode_from_slice(bytes)?;
                    if used != bytes.len() {
                        return Err(norito::Error::LengthMismatch.into());
                    }
                    Ok(value)
                })?;
                assert_eq!(value, ordinary[index]);
                visited += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(visited, count);
            assert_eq!(
                spans.as_slice()[961],
                SequenceSpan {
                    start: usize::MAX,
                    end: usize::MAX
                },
                "unused initialized slot must not be counted or overwritten"
            );
        }
    }
}

#[test]
fn prepared_plan_keeps_late_framing_failure_before_any_element_or_local_output() {
    let pool = AllocationBudget::new(4096);
    let mut spans = scratch(&pool, 4);
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let bytes = super::bare_bytes(&vec![false, true, false, true], flags);
        for end in 0..bytes.len() {
            let ordinary =
                decode_element_sequence_from_slice_serial::<bool>(&bytes[..end]).unwrap_err();
            let prepared = match prepare_element_sequence(&bytes[..end], spans.as_mut_slice()) {
                Err(error) => codec(error),
                Ok(_) => panic!("truncated plan must not produce any element visitor"),
            };
            assert_eq!(
                ordinary.to_string(),
                prepared.to_string(),
                "prefix {end}, flags {flags}"
            );
        }
        // Wrong first bool and malformed last framing must still report framing first.
        let first_prefix = if flags == 0 { 8 } else { 1 };
        let mut late = bytes.clone();
        late[8 + first_prefix] = 2;
        late.pop();
        assert!(matches!(
            decode_element_sequence_from_slice_serial::<bool>(&late),
            Err(norito::Error::LengthMismatch)
        ));
        assert!(matches!(
            prepare_element_sequence(&late, spans.as_mut_slice()),
            Err(SequenceDestinationError::Codec(
                norito::Error::LengthMismatch
            ))
        ));
        let too_small = prepare_element_sequence(&bytes, &mut spans.as_mut_slice()[..3])
            .err()
            .unwrap();
        assert!(matches!(
            too_small,
            SequenceDestinationError::Storage {
                available: 3,
                required: 4
            }
        ));
        let mut trailing = bytes.clone();
        trailing.extend_from_slice(&[0xff, 0xee]);
        let plan = prepare_element_sequence(&trailing, spans.as_mut_slice()).unwrap();
        assert_eq!(plan.used(), bytes.len());
    }
}

#[test]
fn prepared_sequence_preserves_original_count_span_and_output_limit_order() {
    let pool = AllocationBudget::new(4096);
    let mut spans = scratch(&pool, 4);
    let _flags = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
    let bytes = super::bare_bytes(&vec![3_u64, 5, 7, 11], header_flags::COMPACT_LEN);
    let span_bytes = 4 * std::mem::size_of::<SequenceSpan>();
    let value_bytes = 4 * std::mem::size_of::<u64>();
    for maximum in [3, 4 + span_bytes - 1, 4 + span_bytes + value_bytes - 1] {
        let ordinary = with_decode_limits(limits(maximum), || {
            decode_element_sequence_from_slice_serial::<u64>(&bytes)
        })
        .unwrap_err();
        let prepared = with_decode_limits(limits(maximum), || {
            let plan = prepare_element_sequence(&bytes, spans.as_mut_slice()).map_err(codec)?;
            plan.decode_elements::<u64, Infallible>(|_, _| {
                panic!("original logical refusal precedes every value")
            })
            .map_err(DecodeIntoError::into_codec)
        })
        .unwrap_err();
        assert_eq!(ordinary.to_string(), prepared.to_string());
        assert!(ordinary.is_decode_resource_limit());
    }
}

#[test]
fn nested_four_and_thirty_one_squared_rows_reuse_actual_original_scratch_without_allocations() {
    let pool = AllocationBudget::new(1 << 20);
    let mut work = workspace(&pool);
    let mut outer = scratch(&pool, 31);
    let mut inner = scratch(&pool, 31);
    let mut values = initialized(&pool, 961, 0_u64);
    let outer_pointer = outer.as_slice().as_ptr();
    let inner_pointer = inner.as_slice().as_ptr();
    let values_pointer = values.as_slice().as_ptr();
    for n in [4, 31] {
        let expected: Vec<Vec<u64>> = (0..n)
            .map(|row| (0..n).map(|column| (row * 31 + column) as u64).collect())
            .collect();
        let flags = header_flags::COMPACT_LEN;
        let _flags = DecodeFlagsGuard::enter(flags);
        let bytes = super::bare_bytes(&expected, flags);
        let held = pool
            .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
            .unwrap();
        let original = pool.try_reserve_bytes(1).unwrap_err();
        let mut visits = 0;
        let allocation_count = super::allocations_during(|| {
            work.with_limits(limits(1 << 20), limits(1 << 20), || {
                let plan = prepare_element_sequence(&bytes, outer.as_mut_slice()).unwrap();
                assert_eq!(plan.len(), n);
                assert_eq!(plan.used(), bytes.len());
                plan.decode_elements::<Vec<u64>, Infallible>(|row, field| {
                    field.with_payload(|bytes| {
                        let plan = prepare_element_sequence(bytes, inner.as_mut_slice())
                            .map_err(|error| DecodeIntoError::Codec(codec(error)))?;
                        assert_eq!(plan.len(), n);
                        assert_eq!(plan.used(), bytes.len());
                        plan.decode_elements::<u64, Infallible>(|column, field| {
                            field.with_payload(|bytes| {
                                let (value, used) = u64::decode_from_slice(bytes)?;
                                if used != bytes.len() {
                                    return Err(norito::Error::LengthMismatch.into());
                                }
                                values.as_mut_slice()[row * n + column] = value;
                                visits += 1;
                                Ok(())
                            })
                        })
                    })
                })
                .unwrap();
            })
            .unwrap();
        });
        assert_eq!(allocation_count, 0);
        assert_eq!(visits, n * n);
        for (actual, expected) in values.as_slice()[..n * n]
            .iter()
            .zip(expected.iter().flatten())
        {
            assert_eq!(actual, expected);
        }
        assert_eq!(outer.as_slice().as_ptr(), outer_pointer);
        assert_eq!(inner.as_slice().as_ptr(), inner_pointer);
        assert_eq!(values.as_slice().as_ptr(), values_pointer);
        assert!(matches!(
            original,
            iroha_allocation::AllocationRefusal::Capacity { .. }
        ));
        drop(held);
    }
}

#[test]
fn raw_bytes_keep_owning_layout_logical_limits_and_original_backing() {
    let pool = AllocationBudget::new(4096);
    let mut output = initialized(&pool, 31, 0_u8);
    let pointer = output.as_slice().as_ptr();
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let values: Vec<u8> = (1..32).collect();
        let bytes = super::bare_bytes(&values, flags);
        let count = super::allocations_during(|| {
            let (length, used) =
                decode_raw_byte_sequence_into(&bytes, output.as_mut_slice()).unwrap();
            assert_eq!((length, used), (31, bytes.len()));
        });
        assert_eq!(count, 0);
        assert_eq!(output.as_slice(), values);
        assert_eq!(output.as_slice().as_ptr(), pointer);
        let ordinary =
            with_decode_limits(limits(61), || Vec::<u8>::decode_from_slice(&bytes)).unwrap_err();
        let prepared = with_decode_limits(limits(61), || {
            decode_raw_byte_sequence_into(&bytes, output.as_mut_slice()).map_err(codec)
        })
        .unwrap_err();
        assert_eq!(ordinary.to_string(), prepared.to_string());
        assert!(matches!(
            decode_raw_byte_sequence_into(&bytes, &mut output.as_mut_slice()[..30]),
            Err(SequenceDestinationError::Storage {
                required: 31,
                available: 30
            })
        ));
    }
}

#[test]
fn inspected_complete_sequence_keeps_original_spans_without_allocating_or_decoding_children() {
    let pool = AllocationBudget::new(1 << 20);
    let mut work = workspace(&pool);
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for count in [0, 4, 31] {
            let values = (0..count).map(|i| i as u64 * 7 + 3).collect::<Vec<_>>();
            let bytes = super::bare_bytes(&values, flags);
            let mut spans = scratch(&pool, count);
            let original = prepare_element_sequence(&bytes, spans.as_mut_slice()).unwrap();
            let expected = (original.len(), original.used());
            let held = pool
                .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
                .unwrap();
            let mut result = None;
            let allocations = super::allocations_during(|| {
                result = Some(
                    work.with_limits(limits(1 << 20), limits(1 << 20), || {
                        norito::core::inspect_element_sequence(&bytes)
                    })
                    .unwrap()
                    .unwrap(),
                );
            });
            assert_eq!(allocations, 0);
            assert_eq!(result.unwrap(), expected);
            assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
            drop(held);
            let mut trailing = bytes.clone();
            trailing.extend_from_slice(&[0xff, 0xee]);
            assert_eq!(
                norito::core::inspect_element_sequence(&trailing).unwrap(),
                expected
            );
            for end in 0..bytes.len() {
                assert!(matches!(
                    norito::core::inspect_element_sequence(&bytes[..end]),
                    Err(norito::Error::LengthMismatch)
                ));
            }
        }
    }
    drop(work);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn inspected_sequence_keeps_declared_element_byte_charges_and_late_framing_error_order() {
    use norito::core::{DecodeResourceError, with_decode_limits_measured};
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let bytes = super::bare_bytes(&vec![3_u64, 5, 7, 11], flags);
        let (result, usage) = with_decode_limits_measured(limits(1 << 20), || {
            norito::core::inspect_element_sequence(&bytes)
        });
        assert_eq!(result.unwrap(), (4, bytes.len()));
        assert_eq!(
            usage.total_allocated_bytes(),
            4 * std::mem::size_of::<u64>()
        );
        let (result, usage) = with_decode_limits_measured(limits(31), || {
            norito::core::inspect_element_sequence(&bytes)
        });
        let error = result.unwrap_err();
        assert_eq!(
            error.decode_resource_error(),
            Some(DecodeResourceError::TotalAllocationExceeded {
                attempted: 32,
                limit: 31
            })
        );
        assert_eq!(usage.total_allocated_bytes(), 24);
        let mut late = super::bare_bytes(&vec![false, true, false, true], flags);
        let first_prefix = if flags == 0 { 8 } else { 1 };
        late[8 + first_prefix] = 2;
        late.pop();
        assert!(matches!(
            norito::core::inspect_element_sequence(&late),
            Err(norito::Error::LengthMismatch)
        ));
        let oversized = 4097_u64.to_le_bytes();
        assert!(matches!(
            with_decode_limits(limits(1 << 20), || norito::core::inspect_element_sequence(
                &oversized
            )),
            Err(norito::Error::SequenceLengthExceeded {
                length: 4097,
                limit: 4096
            })
        ));
    }
}

#[test]
fn charged_sequence_admits_only_exact_spans_and_decodes_the_original_borrowed_source() {
    use norito::core::{ChargedElementSequence, DecodeBudgetContext, plan_binary_sequence};
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for count in [0, 4, 31, 961] {
            let expected: Vec<u64> = (0..count as u64).map(|i| i * 7 + 3).collect();
            let bytes = super::bare_bytes(&expected, flags);
            let source = (bytes.as_ptr(), bytes.len());
            let (ordinary_values, used) =
                decode_element_sequence_from_slice_serial::<u64>(&bytes).unwrap();
            assert_eq!((ordinary_values, used), (expected.clone(), bytes.len()));
            let ordinary_context = DecodeBudgetContext::new(limits(1 << 20));
            let ordinary = ordinary_context
                .with(|| plan_binary_sequence(&bytes, flags))
                .unwrap();
            let context = DecodeBudgetContext::new(limits(1 << 20));
            context.with(|| ());
            let exact = std::alloc::Layout::array::<SequenceSpan>(count).unwrap();
            let pool = AllocationBudget::new(exact.size());
            let foreign = AllocationBudget::new(exact.size());
            let mut result = None;
            super::REQUESTED_ALLOCATION_BYTES.with(|bytes| bytes.set(0));
            let allocations = super::allocations_during(|| {
                result =
                    Some(context.with(|| ChargedElementSequence::try_from_payload(&bytes, &pool)));
            });
            let owner = result.unwrap().unwrap();
            assert_eq!(allocations, usize::from(count != 0));
            assert_eq!(
                super::REQUESTED_ALLOCATION_BYTES.with(std::cell::Cell::get),
                exact.size()
            );
            assert_eq!(
                context.consumed_allocated_bytes(),
                ordinary_context.consumed_allocated_bytes()
            );
            assert!(owner.belongs_to(&pool));
            assert!(!owner.belongs_to(&foreign));
            assert_eq!(pool.reserved_bytes(), exact.size());
            let view = owner.as_prepared();
            assert_eq!(
                (view.len(), view.used()),
                (ordinary.spans.len(), ordinary.used)
            );
            assert_eq!(view.is_empty(), count == 0);
            // Visiting scalar fields borrows these bytes. It neither copies nor
            // re-plans the sequence, and the private spans remain in their owner.
            let mut visited = 0;
            let allocations = super::allocations_during(|| {
                context.with(|| {
                    view.decode_elements::<u64, Infallible>(|index, field| {
                        field.with_payload(|payload| {
                            assert!(payload.as_ptr().addr() >= bytes.as_ptr().addr());
                            assert!(
                                payload.as_ptr().addr() + payload.len()
                                    <= bytes.as_ptr().addr() + bytes.len()
                            );
                            let (value, used) = u64::decode_from_slice(payload)?;
                            assert_eq!(used, payload.len());
                            assert_eq!(value, expected[index]);
                            visited += 1;
                            Ok(())
                        })
                    })
                    .unwrap();
                });
            });
            assert_eq!(allocations, 0);
            assert_eq!(visited, count);
            assert_eq!((bytes.as_ptr(), bytes.len()), source);
            pool.set_limit_bytes(0);
            assert_eq!(pool.reserved_bytes(), exact.size());
            drop(owner);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}

#[test]
fn charged_sequence_preserves_ordinary_failed_prefix_and_shared_context_retry() {
    use norito::core::{
        ChargedElementSequence, DecodeBudgetContext, SequenceAdmissionError, plan_binary_sequence,
    };
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let valid = super::bare_bytes(&vec![3_u64, 5, 7, 11], flags);
        let mut invalid = valid.clone();
        invalid.pop();
        let oracle = DecodeBudgetContext::new(limits(1 << 20));
        let _first = oracle.with(|| plan_binary_sequence(&valid, flags)).unwrap();
        let first_work = oracle.consumed_allocated_bytes();
        let expected_invalid = oracle
            .with(|| plan_binary_sequence(&invalid, flags))
            .unwrap_err();
        assert!(matches!(expected_invalid, norito::Error::LengthMismatch));
        let failed_prefix = oracle.consumed_allocated_bytes();
        assert!(failed_prefix > first_work);
        let maximum = usize::try_from(failed_prefix - 1).unwrap();
        let ordinary = DecodeBudgetContext::new(limits(maximum));
        let context = DecodeBudgetContext::new(limits(maximum));
        let shared = context.clone();
        let _ordinary_first = ordinary
            .with(|| plan_binary_sequence(&valid, flags))
            .unwrap();
        let exact = std::alloc::Layout::array::<SequenceSpan>(4).unwrap();
        let pool = AllocationBudget::new(2 * exact.size());
        let first = context
            .with(|| ChargedElementSequence::try_from_payload(&valid, &pool))
            .unwrap();
        let expected = ordinary
            .with(|| plan_binary_sequence(&invalid, flags))
            .unwrap_err();
        assert!(
            expected.is_decode_resource_limit(),
            "earlier quota refusal precedes the late truncated body"
        );
        let failure = shared
            .with(|| ChargedElementSequence::try_from_payload(&invalid, &pool))
            .err()
            .unwrap();
        let SequenceAdmissionError::Codec(actual) = failure else {
            panic!("original codec cause required")
        };
        assert_eq!(
            actual.decode_resource_error(),
            expected.decode_resource_error()
        );
        assert_eq!(
            context.consumed_allocated_bytes(),
            ordinary.consumed_allocated_bytes()
        );
        assert!(context.consumed_allocated_bytes() > first_work);
        assert_eq!(
            pool.reserved_bytes(),
            exact.size(),
            "only the earlier completed owner survives"
        );
        assert!(first.belongs_to(&pool));
        let expected = ordinary
            .with(|| plan_binary_sequence(&valid, flags))
            .unwrap_err();
        let failure = shared
            .with(|| ChargedElementSequence::try_from_payload(&valid, &pool))
            .err()
            .unwrap();
        let SequenceAdmissionError::Codec(actual) = failure else {
            panic!("retry cannot gain fresh quota")
        };
        assert_eq!(
            actual.decode_resource_error(),
            expected.decode_resource_error()
        );
        assert_eq!(
            context.consumed_allocated_bytes(),
            ordinary.consumed_allocated_bytes()
        );
        drop(first);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn charged_sequence_keeps_count_span_and_output_refusals_in_original_order() {
    use norito::core::{ChargedElementSequence, DecodeBudgetContext, SequenceAdmissionError};
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let bytes = super::bare_bytes(&vec![3_u64, 5, 7, 11], flags);
        let span_bytes = 4 * std::mem::size_of::<SequenceSpan>();
        let field_bytes = 4 * std::mem::size_of::<u64>();
        let pool = AllocationBudget::new(span_bytes);
        for maximum in [
            3,
            4 + span_bytes - 1,
            4 + span_bytes + field_bytes - 1,
            4 + span_bytes + 2 * field_bytes - 1,
        ] {
            let ordinary = DecodeBudgetContext::new(limits(maximum));
            let context = DecodeBudgetContext::new(limits(maximum));
            let expected = ordinary
                .with(|| decode_element_sequence_from_slice_serial::<u64>(&bytes))
                .unwrap_err();
            let outcome = context.with(|| {
                let owner = ChargedElementSequence::try_from_payload(&bytes, &pool)?;
                owner
                    .as_prepared()
                    .decode_elements::<u64, Infallible>(|_, _| {
                        panic!("original count/span/framing/output refusal precedes every scalar")
                    })
                    .map_err(|error| SequenceAdmissionError::Codec(error.into_codec()))
            });
            let SequenceAdmissionError::Codec(actual) = outcome.unwrap_err() else {
                panic!("logical quota cause required")
            };
            assert_eq!(
                actual.decode_resource_error(),
                expected.decode_resource_error()
            );
            assert_eq!(
                context.consumed_allocated_bytes(),
                ordinary.consumed_allocated_bytes()
            );
            assert_eq!(pool.reserved_bytes(), 0);
        }
        let mut late = super::bare_bytes(&vec![false, true, false, true], flags);
        late[8 + if flags == 0 { 8 } else { 1 }] = 2;
        late.pop();
        let failure = ChargedElementSequence::try_from_payload(&late, &pool)
            .err()
            .unwrap();
        assert!(
            matches!(
                failure,
                SequenceAdmissionError::Codec(norito::Error::LengthMismatch)
            ),
            "complete framing precedes the invalid first element"
        );
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn charged_sequence_preserves_exact_pool_and_allocator_causes_before_late_framing() {
    use iroha_allocation::ChargedBufferError;
    use norito::core::{ChargedElementSequence, DecodeBudgetContext, SequenceAdmissionError};
    let flags = header_flags::COMPACT_LEN;
    let _flags = DecodeFlagsGuard::enter(flags);
    let valid = super::bare_bytes(&vec![3_u64, 5, 7, 11], flags);
    let mut invalid = valid.clone();
    invalid.pop();
    let exact = std::alloc::Layout::array::<SequenceSpan>(4).unwrap();
    let pool = AllocationBudget::new(exact.size());
    let context = DecodeBudgetContext::new(limits(1 << 20));
    let first = context
        .with(|| ChargedElementSequence::try_from_payload(&valid, &pool))
        .unwrap();
    let before = context.consumed_allocated_bytes();
    let expected = pool.try_reserve(exact).unwrap_err();
    let failure = context
        .with(|| ChargedElementSequence::try_from_payload(&invalid, &pool))
        .err()
        .unwrap();
    let SequenceAdmissionError::Allocation(ChargedBufferError::Admission(actual)) = failure else {
        panic!("original capacity refusal precedes later framing")
    };
    assert_eq!(actual, expected);
    let admitted_work = u64::try_from(4 + exact.size()).unwrap();
    assert_eq!(context.consumed_allocated_bytes(), before + admitted_work);
    assert_eq!(pool.reserved_bytes(), exact.size());
    drop(first);
    assert_eq!(pool.reserved_bytes(), 0);
    // The existing real global allocator fault targets only this exact request.
    // Restore its test-local state before asserting or formatting any result.
    let prior_size = super::REFUSE_SIZE.with(|value| value.replace(exact.size()));
    let prior_matches = super::MATCHES_BEFORE_REFUSAL.with(|value| value.replace(0));
    let outcome = context.with(|| ChargedElementSequence::try_from_payload(&invalid, &pool));
    super::REFUSE_SIZE.with(|value| value.set(prior_size));
    super::MATCHES_BEFORE_REFUSAL.with(|value| value.set(prior_matches));
    let failure = outcome.err().unwrap();
    assert!(
        matches!(failure, SequenceAdmissionError::Allocation(ChargedBufferError::Allocator { requested_bytes }) if requested_bytes == exact.size())
    );
    assert_eq!(
        context.consumed_allocated_bytes(),
        before + 2 * admitted_work
    );
    assert_eq!(pool.reserved_bytes(), 0);
    let retry = context
        .with(|| ChargedElementSequence::try_from_payload(&valid, &pool))
        .unwrap();
    assert!(retry.belongs_to(&pool));
    assert_eq!(
        context.consumed_allocated_bytes(),
        2 * before + 2 * admitted_work
    );
    assert_eq!(pool.reserved_bytes(), exact.size());
    drop(retry);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn retained_sequence_keeps_late_framing_storage_and_cumulative_retry_work() {
    use norito::core::{
        DecodeBudgetContext, RetainedElementSequence, RetainedSequenceError,
        SequenceAdmissionError, plan_binary_sequence,
    };
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let mut bytes = super::bare_bytes(&vec![3_u64, 5, 7, 11], flags);
        bytes.pop();
        let exact = std::alloc::Layout::array::<SequenceSpan>(4).unwrap().size();
        let pool = AllocationBudget::new(exact);
        let foreign = AllocationBudget::new(exact);
        let context = DecodeBudgetContext::new(limits(1 << 20));
        let oracle = DecodeBudgetContext::new(limits(1 << 20));
        let mut owner = RetainedElementSequence::new(&pool);
        assert_eq!(owner.allocation_bytes(), Some(0));
        assert!(owner.belongs_to(&pool));
        assert!(!owner.belongs_to(&foreign));
        assert!(matches!(
            owner.as_prepared(&bytes),
            Err(RetainedSequenceError::Incomplete)
        ));
        for _ in 0..2 {
            let expected = oracle
                .with(|| plan_binary_sequence(&bytes, flags))
                .unwrap_err();
            let actual = context.with(|| owner.prepare(&bytes)).unwrap_err();
            let RetainedSequenceError::Admission(SequenceAdmissionError::Codec(actual)) = actual
            else {
                panic!("original late framing failure required");
            };
            assert_eq!(actual.to_string(), expected.to_string());
            assert!(matches!(actual, norito::Error::LengthMismatch));
            assert_eq!(
                context.consumed_allocated_bytes(),
                oracle.consumed_allocated_bytes()
            );
            assert_eq!(pool.reserved_bytes(), exact);
            assert_eq!(owner.allocation_bytes(), Some(exact));
            assert!(matches!(
                owner.as_prepared(&bytes),
                Err(RetainedSequenceError::Incomplete)
            ));
        }
        drop(owner);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn retained_sequence_does_not_wake_its_original_capacity_refusal_during_retry() {
    use iroha_allocation::{AllocationRefusal, release::ReleaseRegistration};
    use norito::core::{DecodeBudgetContext, RetainedElementSequence};
    use std::task::{Context, Poll, Waker};
    let _flags = DecodeFlagsGuard::enter(header_flags::COMPACT_LEN);
    let bytes = super::bare_bytes(&vec![3_u64, 5, 7, 11], header_flags::COMPACT_LEN);
    let exact = std::alloc::Layout::array::<SequenceSpan>(4).unwrap().size();
    let pool = AllocationBudget::new(4096);
    let mut reservation = pool
        .try_reserve(ReleaseRegistration::allocation_layout())
        .unwrap();
    let mut registration = ReleaseRegistration::from_reservation(&mut reservation).unwrap();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes() - exact)
        .unwrap();
    let context = DecodeBudgetContext::new(limits(1 << 20));
    context.with(|| ());
    let mut owner = None;
    assert_eq!(
        super::allocations_during(|| owner = Some(RetainedElementSequence::new(&pool))),
        0
    );
    let mut owner = owner.unwrap();
    context.with(|| owner.prepare(&bytes)).unwrap();
    let original = pool.try_reserve_bytes(1).unwrap_err();
    let AllocationRefusal::Capacity { release, .. } = &original else {
        panic!("original pool is full");
    };
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(registration.poll_wait(release, &mut cx), Poll::Pending);
    let before = context.consumed_allocated_bytes();
    assert_eq!(
        super::allocations_during(|| {
            context.with(|| owner.prepare(&bytes)).unwrap();
        }),
        0
    );
    assert!(context.consumed_allocated_bytes() > before);
    assert_eq!(owner.allocation_bytes(), Some(exact));
    assert_eq!(pool.try_reserve_bytes(1).unwrap_err(), original);
    assert_eq!(registration.poll_wait(release, &mut cx), Poll::Pending);
    drop(blocker);
    assert_eq!(registration.poll_wait(release, &mut cx), Poll::Ready(()));
    let view = owner.as_prepared(&bytes).unwrap();
    let mut visited = 0;
    view.decode_elements::<u64, Infallible>(|index, field| {
        field.with_payload(|payload| {
            let (value, used) = u64::decode_from_slice(payload)?;
            assert_eq!(used, payload.len());
            assert_eq!(value, [3, 5, 7, 11][index]);
            visited += 1;
            Ok(())
        })
    })
    .unwrap();
    assert_eq!(visited, 4);
}

#[test]
fn retained_sequence_rejects_substitution_in_place_mutation_and_changed_flags() {
    use norito::core::{RetainedElementSequence, RetainedSequenceError};
    let flags = header_flags::COMPACT_LEN;
    let _flags = DecodeFlagsGuard::enter(flags);
    let mut bytes = super::bare_bytes(&vec![3_u64, 5, 7, 11], flags);
    let pool = AllocationBudget::new(4096);
    let mut owner = RetainedElementSequence::new(&pool);
    owner.prepare(&bytes).unwrap();
    let retained = pool.reserved_bytes();
    let replacement = bytes.clone();
    assert!(matches!(
        owner.as_prepared(&replacement),
        Err(RetainedSequenceError::SourceMismatch)
    ));
    let address = bytes.as_ptr();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert_eq!(bytes.as_ptr(), address);
    assert!(matches!(
        owner.as_prepared(&bytes),
        Err(RetainedSequenceError::SourceMismatch)
    ));
    assert!(matches!(
        owner.prepare(&bytes),
        Err(RetainedSequenceError::SourceMismatch)
    ));
    assert!(matches!(
        owner.as_prepared(&bytes),
        Err(RetainedSequenceError::Incomplete)
    ));
    bytes[last] ^= 1;
    owner.prepare(&bytes).unwrap();
    {
        let _other_flags = DecodeFlagsGuard::enter(0);
        assert!(matches!(
            owner.as_prepared(&bytes),
            Err(RetainedSequenceError::SourceMismatch)
        ));
        assert!(matches!(
            owner.prepare(&bytes),
            Err(RetainedSequenceError::SourceMismatch)
        ));
    }
    owner.prepare(&bytes).unwrap();
    assert_eq!(owner.as_prepared(&bytes).unwrap().used(), bytes.len());
    assert_eq!(pool.reserved_bytes(), retained);
}

#[test]
fn retained_sequence_preserves_first_admission_and_exhausted_retry_order() {
    use iroha_allocation::ChargedBufferError;
    use norito::core::{
        DecodeBudgetContext, RetainedElementSequence, RetainedSequenceError,
        SequenceAdmissionError, plan_binary_sequence,
    };
    let flags = header_flags::COMPACT_LEN;
    let _flags = DecodeFlagsGuard::enter(flags);
    let bytes = super::bare_bytes(&vec![3_u64, 5, 7, 11], flags);
    let exact = std::alloc::Layout::array::<SequenceSpan>(4).unwrap();
    let pool = AllocationBudget::new(exact.size());
    let blocker = pool.try_reserve(exact).unwrap();
    let expected = pool.try_reserve(exact).unwrap_err();
    let mut owner = RetainedElementSequence::new(&pool);
    let error = owner.prepare(&bytes).unwrap_err();
    let RetainedSequenceError::Admission(SequenceAdmissionError::Allocation(
        ChargedBufferError::Admission(actual),
    )) = error
    else {
        panic!("original physical admission refusal required");
    };
    assert_eq!(actual, expected);
    assert_eq!(owner.allocation_bytes(), Some(0));
    drop(blocker);
    let sizing = DecodeBudgetContext::new(limits(1 << 20));
    sizing.with(|| plan_binary_sequence(&bytes, flags)).unwrap();
    let maximum = usize::try_from(sizing.consumed_allocated_bytes()).unwrap();
    let oracle = DecodeBudgetContext::new(limits(maximum));
    let context = DecodeBudgetContext::new(limits(maximum));
    oracle.with(|| plan_binary_sequence(&bytes, flags)).unwrap();
    context.with(|| owner.prepare(&bytes)).unwrap();
    let expected = oracle
        .with(|| plan_binary_sequence(&bytes, flags))
        .unwrap_err();
    let error = context.with(|| owner.prepare(&bytes)).unwrap_err();
    let RetainedSequenceError::Admission(SequenceAdmissionError::Codec(actual)) = error else {
        panic!("the original cumulative limit must reject retry");
    };
    assert!(actual.is_decode_resource_limit());
    assert_eq!(
        actual.decode_resource_error(),
        expected.decode_resource_error()
    );
    assert_eq!(
        context.consumed_allocated_bytes(),
        oracle.consumed_allocated_bytes()
    );
    assert_eq!(owner.allocation_bytes(), Some(exact.size()));
    assert_eq!(pool.reserved_bytes(), exact.size());
    assert!(matches!(
        owner.as_prepared(&bytes),
        Err(RetainedSequenceError::Incomplete)
    ));
}

#[test]
fn retained_sequence_admits_only_exact_spans_for_each_layout_and_empty_input() {
    use norito::core::{DecodeBudgetContext, RetainedElementSequence, plan_binary_sequence};
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for count in [0, 4, 31, 961] {
            let values: Vec<u64> = (0..count as u64).map(|value| value * 7 + 3).collect();
            let bytes = super::bare_bytes(&values, flags);
            let exact = std::alloc::Layout::array::<SequenceSpan>(count)
                .unwrap()
                .size();
            let pool = AllocationBudget::new(exact);
            let mut owner = RetainedElementSequence::new(&pool);
            let oracle = DecodeBudgetContext::new(limits(1 << 20));
            let expected = oracle.with(|| plan_binary_sequence(&bytes, flags)).unwrap();
            let context = DecodeBudgetContext::new(limits(1 << 20));
            context.with(|| ());
            super::REQUESTED_ALLOCATION_BYTES.with(|bytes| bytes.set(0));
            let allocations = super::allocations_during(|| {
                context.with(|| owner.prepare(&bytes)).unwrap();
            });
            assert_eq!(allocations, usize::from(count != 0));
            assert_eq!(
                super::REQUESTED_ALLOCATION_BYTES.with(std::cell::Cell::get),
                exact
            );
            assert_eq!(
                context.consumed_allocated_bytes(),
                oracle.consumed_allocated_bytes()
            );
            assert_eq!(owner.allocation_bytes(), Some(exact));
            assert_eq!(pool.reserved_bytes(), exact);
            let view = owner.as_prepared(&bytes).unwrap();
            assert_eq!(
                (view.len(), view.used()),
                (expected.spans.len(), expected.used)
            );
            assert_eq!(view.is_empty(), count == 0);
            let mut visited = 0;
            view.decode_elements::<u64, Infallible>(|index, field| {
                field.with_payload(|payload| {
                    let (value, used) = u64::decode_from_slice(payload)?;
                    assert_eq!((value, used), (values[index], payload.len()));
                    visited += 1;
                    Ok(())
                })
            })
            .unwrap();
            assert_eq!(visited, count);
            drop(owner);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}
