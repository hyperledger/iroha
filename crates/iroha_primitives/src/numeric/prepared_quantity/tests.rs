//! Sole ordinary-decoder parity and exact prepared backing refusal/retry controls.

use super::*;
use norito::core::{DecodeFlagsGuard, DecodeFromSlice, header_flags, serialize_to_buffer};

fn payload(mantissa: BigInt, scale: u32) -> Vec<u8> {
    let helper = scale_::NumericScaleHelper { mantissa, scale };
    let mut bytes = Vec::new();
    serialize_to_buffer(&helper, &mut bytes).unwrap();
    bytes
}
fn destination(bytes: &[u8], budget: &AllocationBudget) -> PreparedQuantityDecode {
    let plan = QuantityDecodePlan::decode_payload(bytes).unwrap();
    let layout = plan.allocation_layout();
    let charge = budget
        .try_reserve(layout)
        .unwrap()
        .try_split(layout)
        .unwrap();
    PreparedQuantityDecode::try_from_charge(&plan, budget, charge)
        .unwrap_or_else(|(_, error)| panic!("{error}"))
}

#[test]
fn prepared_quantity_moves_actual_original_native_backing_and_refunds_after_value_drop() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for mantissa in [
            BigInt::zero(),
            BigInt::one(),
            BigInt::from(127_u64),
            BigInt::from(128_u64),
            BigInt::from(1_u128 << 127),
            BigInt::from_inner((UnboundedBigInt::one() << 511_usize) - 1_u8).unwrap(),
        ] {
            let bytes = payload(mantissa, 0);
            let plan = QuantityDecodePlan::decode_payload(&bytes).unwrap();
            let budget = AllocationBudget::new(plan.allocation_layout().size());
            let mut prepared = destination(&bytes, &budget);
            let original = prepared.digits.as_slice().as_ptr();
            prepared.decode_payload(&bytes).unwrap();
            budget.set_limit_bytes(0);
            let value = prepared
                .finish()
                .unwrap_or_else(|_| panic!("canonical fill must finish"));
            let (ordinary, used) = Quantity::decode_from_slice(&bytes).unwrap();
            assert_eq!(used, bytes.len());
            assert_eq!(value.get(), &ordinary);
            // Observe actual final num-bigint storage, not retained pointer metadata.
            assert_eq!(
                value
                    .get()
                    .mantissa()
                    .inner()
                    .magnitude()
                    .native_digits()
                    .as_ptr(),
                original
            );
            assert!(value.belongs_to(&budget));
            assert_eq!(budget.reserved_bytes(), plan.allocation_layout().size());
            let mut encoded = Vec::new();
            serialize_to_buffer(value.get(), &mut encoded).unwrap();
            assert_eq!(encoded, bytes);
            drop(value);
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
}

#[test]
fn prepared_quantity_matches_ordinary_negative_minimum_zero_trailing_scale_and_width_rejections() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let minimum = BigInt::from_inner(-(UnboundedBigInt::one() << 511_usize)).unwrap();
        let too_wide = BigInt::from_inner(UnboundedBigInt::one() << 511_usize).unwrap();
        for mantissa in [
            BigInt::zero(),
            BigInt::from(-1_i64),
            BigInt::from(-10_i64),
            minimum,
            too_wide,
            BigInt::from(1_u64),
            BigInt::from(10_u64),
            BigInt::from(101_u64),
        ] {
            for scale in [0, 1, 2, 28, 29, u32::MAX] {
                let bytes = payload(mantissa.clone(), scale);
                let ordinary = Quantity::decode_from_slice(&bytes);
                let plan = QuantityDecodePlan::decode_payload(&bytes);
                match (ordinary, plan) {
                    (Ok((value, used)), Ok(plan)) => {
                        assert_eq!(used, bytes.len());
                        let budget = AllocationBudget::new(plan.allocation_layout().size());
                        let mut prepared = destination(&bytes, &budget);
                        prepared.decode_payload(&bytes).unwrap();
                        let prepared = prepared.finish().unwrap_or_else(|_| panic!("valid fill"));
                        assert_eq!(prepared.get(), &value);
                    }
                    (Err(ordinary), Err(prepared)) => {
                        assert_eq!(ordinary.to_string(), prepared.to_string())
                    }
                    (ordinary, prepared) => {
                        panic!("decoder disagreement: {ordinary:?} / {prepared:?}")
                    }
                }
            }
        }
    }
}

#[test]
fn prepared_quantity_one_byte_short_and_foreign_charge_preserve_exact_original_pool() {
    let _flags = DecodeFlagsGuard::enter(0);
    let bytes = payload(BigInt::from(1_u128 << 127), 0);
    let plan = QuantityDecodePlan::decode_payload(&bytes).unwrap();
    let layout = plan.allocation_layout();
    let short = AllocationBudget::new(layout.size() - 1);
    let refusal = short.try_reserve(layout).unwrap_err();
    assert!(
        matches!(refusal, iroha_allocation::AllocationRefusal::ExceedsLimit {
        requested_bytes, limit_bytes } if requested_bytes == layout.size() && limit_bytes == layout.size()-1)
    );
    assert_eq!(short.reserved_bytes(), 0);
    let original = AllocationBudget::new(layout.size());
    let foreign = AllocationBudget::new(layout.size());
    let charge = original
        .try_reserve(layout)
        .unwrap()
        .try_split(layout)
        .unwrap();
    let (charge, error) = PreparedQuantityDecode::try_from_charge(&plan, &foreign, charge)
        .err()
        .unwrap();
    assert!(matches!(error, QuantityBackingError::ForeignPool));
    assert!(charge.belongs_to(&original));
    assert_eq!(charge.layout(), layout);
    assert_eq!(original.reserved_bytes(), layout.size());
    let mut prepared = PreparedQuantityDecode::try_from_charge(&plan, &original, charge)
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    prepared.decode_payload(&bytes).unwrap();
    let value = prepared.finish().unwrap_or_else(|_| panic!("valid retry"));
    assert!(value.belongs_to(&original));
    assert_eq!(foreign.reserved_bytes(), 0);
    drop(value);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn prepared_quantity_malformed_geometry_and_reset_keep_same_backing_for_exact_source_retry() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let bytes = payload(BigInt::from(1_u128 << 127), 1);
        let budget = AllocationBudget::new(1024);
        let mut prepared = destination(&bytes, &budget);
        let original = prepared.digits.as_slice().as_ptr();
        let held = budget.reserved_bytes();
        for end in 0..bytes.len() {
            let ordinary = Quantity::decode_from_slice(&bytes[..end]).unwrap_err();
            let error = prepared.decode_payload(&bytes[..end]).unwrap_err();
            let QuantityDestinationError::Codec(error) = error else {
                panic!("codec cause required")
            };
            assert_eq!(error.to_string(), ordinary.to_string(), "truncation {end}");
            assert!(prepared.scale.is_none());
            assert_eq!(prepared.digits.as_slice().as_ptr(), original);
            assert_eq!(budget.reserved_bytes(), held);
        }
        let smaller = payload(BigInt::one(), 0);
        assert!(matches!(
            prepared.decode_payload(&smaller),
            Err(QuantityDestinationError::Geometry { .. })
        ));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            prepared.decode_payload(&trailing),
            Err(QuantityDestinationError::Codec(_))
        ));
        prepared = prepared
            .finish()
            .err()
            .expect("invalid fill must return exact owner");
        assert_eq!(prepared.digits.as_slice().as_ptr(), original);
        prepared.decode_payload(&bytes).unwrap();
        prepared.reset();
        prepared = prepared
            .finish()
            .err()
            .expect("reset invalidates value without freeing backing");
        assert_eq!(budget.reserved_bytes(), held);
        prepared.decode_payload(&bytes).unwrap();
        let value = prepared
            .finish()
            .unwrap_or_else(|_| panic!("same source retry"));
        assert_eq!(
            value
                .get()
                .mantissa()
                .inner()
                .magnitude()
                .native_digits()
                .as_ptr(),
            original
        );
        drop(value);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn borrowed_divisibility_probe_preserves_original_work_steps_and_observer_refusal_order() {
    for mantissa in [
        BigInt::zero(),
        BigInt::from(-10_i64),
        BigInt::from(10_u64),
        BigInt::from(-101_i64),
        BigInt::from(101_u64),
    ] {
        for scale in [0, 1, 28] {
            let value = Numeric::try_new_raw(mantissa.clone(), scale).unwrap();
            let mut steps = Vec::new();
            let result = value.validate_decimal_observed(&mut |step| {
                steps.push(step);
                Ok::<_, ()>(())
            });
            let expected = if scale == 0 {
                Ok(())
            } else if mantissa.is_zero() {
                Err(NumericOperationError::NonCanonical)
            } else {
                // Independent original quotient/remainder relation.
                let (_, remainder) =
                    quotient_remainder(mantissa.inner(), &UnboundedBigInt::from(10));
                if remainder.is_zero() {
                    Err(NumericOperationError::NonCanonical)
                } else {
                    Ok(())
                }
            };
            assert_eq!(
                result.map_err(|error| match error {
                    ObservedNumericError::Numeric(error) => error,
                    ObservedNumericError::Observer(()) => panic!("observer succeeds"),
                }),
                expected
            );
            let expected_steps = if scale == 0 || mantissa.is_zero() {
                vec![]
            } else {
                vec![NumericWorkStep::CanonicalityProbe {
                    mantissa_limbs: logical_limbs(mantissa.inner()),
                    scale: u8::try_from(scale).unwrap(),
                }]
            };
            assert_eq!(steps, expected_steps);
            if !expected_steps.is_empty() {
                assert!(matches!(
                    value.validate_decimal_observed(&mut |_| Err::<(), _>(37)),
                    Err(ObservedNumericError::Observer(37))
                ));
            }
        }
    }
}

#[test]
fn prepared_quantity_wrong_layout_returns_same_charge_without_physical_construction() {
    let _flags = DecodeFlagsGuard::enter(0);
    let bytes = payload(BigInt::from(1_u128 << 127), 0);
    let plan = QuantityDecodePlan::decode_payload(&bytes).unwrap();
    let wrong_layout = Layout::from_size_align(
        plan.allocation_layout().size() - 1,
        plan.allocation_layout().align(),
    )
    .unwrap();
    let original = AllocationBudget::new(1024);
    let charge = original
        .try_reserve(wrong_layout)
        .unwrap()
        .try_split(wrong_layout)
        .unwrap();
    let (charge, reason) = PreparedQuantityDecode::try_from_charge(&plan, &original, charge)
        .err()
        .unwrap();
    assert!(matches!(reason, QuantityBackingError::Allocation(
        ChargedBufferFromChargeError::LayoutMismatch { expected, actual }
    ) if expected == plan.allocation_layout() && actual == wrong_layout));
    assert!(charge.belongs_to(&original));
    assert_eq!(charge.layout(), wrong_layout);
    assert_eq!(original.reserved_bytes(), wrong_layout.size());
    drop(charge);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn prepared_quantity_planning_cannot_replenish_nested_scope_and_fill_retains_refused_backing() {
    let _flags = DecodeFlagsGuard::enter(0);
    let mantissa = BigInt::from(1_u128 << 127);
    // The canonical BigInt field has its u32 length followed by signed bytes.
    // Planning borrows both fields and allocates no storage; an owning decoder
    // charges only actual native digits and any required alignment copies.
    let mantissa_payload_len = core::mem::size_of::<u32>() + mantissa.to_twos_bytes().len();
    let bytes = payload(mantissa, 1);
    let budget = AllocationBudget::new(1024);
    let mut prepared = destination(&bytes, &budget);
    let pointer = prepared.digits.as_slice().as_ptr();
    let held = budget.reserved_bytes();
    let required = prepared.digits.capacity() * UNBOUNDED_BIGINT_DIGIT_BYTES;
    let limits = |bytes| {
        norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
    };
    let (zero_plan, usage) = norito::core::with_decode_limits_measured(limits(0), || {
        QuantityDecodePlan::decode_payload(&bytes)
    });
    assert_eq!(zero_plan.unwrap().allocation_layout().size(), required);
    assert_eq!(usage.total_allocated_bytes(), 0);
    assert_eq!(prepared.digits.as_slice().as_ptr(), pointer);
    assert_eq!(budget.reserved_bytes(), held);
    let (plan, usage) = norito::core::with_decode_limits_measured(limits(0), || {
        QuantityDecodePlan::decode_payload(&bytes)
    });
    assert_eq!(plan.unwrap().allocation_layout().size(), required);
    assert_eq!(usage.total_allocated_bytes(), 0);
    // Repeated borrowed planning consumes no allocation credit. A nested
    // unbounded caller still cannot replenish an insufficient native-digit budget.
    let ceiling = required - 1;
    let (outcome, usage) = norito::core::with_decode_limits_measured(limits(ceiling), || {
        for _ in 0..2 {
            QuantityDecodePlan::decode_payload(&bytes)?;
        }
        let fill = norito::core::with_decode_limits_scope(limits(usize::MAX), || {
            prepared.decode_payload(&bytes)
        });
        Ok::<_, Error>(fill)
    });
    let error = outcome.unwrap().unwrap_err();
    assert!(matches!(error,
        QuantityDestinationError::Codec(Error::TotalAllocationExceeded { attempted, limit })
        if attempted == required as u64 && limit == ceiling as u64));
    assert_eq!(usage.total_allocated_bytes(), 0);
    assert!(prepared.scale.is_none());
    assert_eq!(prepared.digits.as_slice().as_ptr(), pointer);
    assert_eq!(budget.reserved_bytes(), held);
    // Both fills admit actual native digits. Owning archived fields also pay
    // for real alignment copies; the prepared borrowed walker makes none.
    let exact_charge = required;
    let realignment_charge = [
        (
            bytes.as_ptr().addr() + core::mem::size_of::<u64>(),
            norito::core::archived_payload_align::<BigInt>(),
            mantissa_payload_len,
        ),
        (
            bytes.as_ptr().addr() + bytes.len() - core::mem::size_of::<u32>(),
            norito::core::archived_payload_align::<u32>(),
            core::mem::size_of::<u32>(),
        ),
    ]
    .into_iter()
    .filter_map(|(address, align, length)| (!address.is_multiple_of(align)).then_some(length))
    .sum::<usize>();
    if realignment_charge != 0 {
        let (refused, _) = norito::core::with_decode_limits_measured(limits(exact_charge), || {
            Quantity::decode_from_slice(&bytes)
        });
        assert!(refused.unwrap_err().decode_resource_error().is_some());
    }
    let ordinary_charge = exact_charge + realignment_charge;
    let (ordinary, ordinary_usage) =
        norito::core::with_decode_limits_measured(limits(ordinary_charge), || {
            Quantity::decode_from_slice(&bytes)
        });
    let (ordinary, used) = ordinary.unwrap();
    assert_eq!(used, bytes.len());
    assert_eq!(ordinary_usage.total_allocated_bytes(), ordinary_charge);
    let (result, usage) = norito::core::with_decode_limits_measured(limits(exact_charge), || {
        prepared.decode_payload(&bytes)
    });
    result.unwrap();
    assert_eq!(usage.total_allocated_bytes(), exact_charge);
    let value = prepared
        .finish()
        .unwrap_or_else(|_| panic!("same original source retry"));
    assert_eq!(value.get(), &ordinary);
    assert_eq!(
        value
            .get()
            .mantissa()
            .inner()
            .magnitude()
            .native_digits()
            .as_ptr(),
        pointer
    );
    drop(value);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn one_pass_quantity_matches_canonical_values_rejections_and_exact_original_digits() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for mantissa in [
            BigInt::zero(),
            BigInt::one(),
            BigInt::from(10_u32),
            BigInt::from(-1_i32),
            BigInt::from_inner((UnboundedBigInt::one() << 511_usize) - 1_u8).unwrap(),
            BigInt::from_inner(UnboundedBigInt::one() << 511_usize).unwrap(),
        ] {
            for scale in [0, 1, 28, 29, u32::MAX] {
                let bytes = payload(mantissa.clone(), scale);
                let original = (bytes.as_ptr(), bytes.len());
                let ordinary = Quantity::decode_from_slice(&bytes);
                let budget = AllocationBudget::new(crate::bigint::MAX_ENCODED_BYTES);
                let result = PreparedQuantityDecode::try_decode_payload(&bytes, &budget);
                match (ordinary, result) {
                    (Ok((ordinary, used)), Ok(owner)) => {
                        assert_eq!(used, bytes.len());
                        assert_eq!(owner.get(), &ordinary);
                        let digits = ordinary.mantissa().inner().magnitude().native_digits();
                        let exact = Layout::array::<NativeBigDigit>(digits.len()).unwrap();
                        assert_eq!(budget.reserved_bytes(), exact.size());
                        assert!(owner.belongs_to(&budget));
                        assert_eq!(
                            owner.get().mantissa().inner().magnitude().native_digits(),
                            digits
                        );
                        let mut encoded = Vec::new();
                        serialize_to_buffer(owner.get(), &mut encoded).unwrap();
                        assert_eq!(encoded, bytes);
                        budget.set_limit_bytes(0);
                        drop(owner);
                    }
                    (Err(ordinary), Err(QuantityDecodeAdmissionError::Codec(actual))) => {
                        assert_eq!(actual.to_string(), ordinary.to_string());
                    }
                    _ => panic!("one-pass Quantity changed canonical scalar behavior"),
                }
                assert_eq!((bytes.as_ptr(), bytes.len()), original);
                assert_eq!(budget.reserved_bytes(), 0);
            }
        }
    }
}

#[test]
fn one_pass_quantity_preserves_mantissa_quota_before_late_scale_and_cumulative_retry() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let small = payload(BigInt::one(), 0);
        let wide = payload(BigInt::from(1_u128 << 127), 0);
        let late = payload(BigInt::from(1_u128 << 127), MAX_DECIMAL_SCALE + 1);
        let original = (late.as_ptr(), late.len());
        let oracle_pool = AllocationBudget::new(1024);
        let mut ordinary_small = destination(&small, &oracle_pool);
        let mut ordinary_wide = destination(&wide, &oracle_pool);
        let small_work = ordinary_small.digits.capacity() * UNBOUNDED_BIGINT_DIGIT_BYTES;
        let wide_work = ordinary_wide.digits.capacity() * UNBOUNDED_BIGINT_DIGIT_BYTES;
        let limit = small_work + wide_work - 1;
        let limits = norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, limit, 32);
        // The existing prepared field path is the logical-work oracle. An owning
        // archived decoder additionally charges real alignment copies avoided
        // by both safe borrowed walkers; those are not fabricated here.
        let ordinary = norito::core::DecodeBudgetContext::new(limits);
        ordinary
            .with(|| ordinary_small.decode_payload(&small))
            .unwrap();
        let expected = ordinary
            .with(|| ordinary_wide.decode_payload(&late))
            .unwrap_err();
        let QuantityDestinationError::Codec(expected) = expected else {
            panic!("original mantissa quota must precede late scale")
        };
        assert!(expected.is_decode_resource_limit());
        let context = norito::core::DecodeBudgetContext::new(limits);
        let shared = context.clone();
        let pool = AllocationBudget::new(1024);
        let first = context
            .with(|| PreparedQuantityDecode::try_decode_payload(&small, &pool))
            .unwrap_or_else(|error| panic!("{error}"));
        let failure = shared
            .with(|| PreparedQuantityDecode::try_decode_payload(&late, &pool))
            .err()
            .expect("original cumulative mantissa quota must refuse");
        let QuantityDecodeAdmissionError::Codec(actual) = failure else {
            panic!("late scale must not bypass cumulative work")
        };
        assert_eq!(
            actual.decode_resource_error(),
            expected.decode_resource_error()
        );
        assert_eq!(
            context.consumed_allocated_bytes(),
            u64::try_from(small_work).unwrap()
        );
        assert_eq!(
            context.consumed_allocated_bytes(),
            ordinary.consumed_allocated_bytes()
        );
        assert_eq!(pool.reserved_bytes(), small_work);
        let expected = ordinary
            .with(|| ordinary_wide.decode_payload(&wide))
            .unwrap_err();
        let QuantityDestinationError::Codec(expected) = expected else {
            panic!("same quota")
        };
        let failure = shared
            .with(|| PreparedQuantityDecode::try_decode_payload(&wide, &pool))
            .err()
            .expect("failed prefix cannot replenish retry credit");
        let QuantityDecodeAdmissionError::Codec(actual) = failure else {
            panic!("same quota")
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

        let unlimited =
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 32);
        let ordinary = norito::core::DecodeBudgetContext::new(unlimited);
        let context = norito::core::DecodeBudgetContext::new(unlimited);
        ordinary
            .with(|| ordinary_small.decode_payload(&small))
            .unwrap();
        let first = context
            .with(|| PreparedQuantityDecode::try_decode_payload(&small, &pool))
            .unwrap_or_else(|error| panic!("{error}"));
        let expected = ordinary
            .with(|| ordinary_wide.decode_payload(&late))
            .unwrap_err();
        let QuantityDestinationError::Codec(expected) = expected else {
            panic!("late scale")
        };
        let failure = context
            .with(|| PreparedQuantityDecode::try_decode_payload(&late, &pool))
            .err()
            .expect("invalid scale must refuse after mantissa admission");
        let QuantityDecodeAdmissionError::Codec(actual) = failure else {
            panic!("late scale")
        };
        assert_eq!(actual.to_string(), expected.to_string());
        assert_eq!(
            context.consumed_allocated_bytes(),
            u64::try_from(small_work + wide_work).unwrap()
        );
        assert_eq!(
            context.consumed_allocated_bytes(),
            ordinary.consumed_allocated_bytes()
        );
        assert_eq!(
            pool.reserved_bytes(),
            small_work,
            "invalid value refunds physical digits only"
        );
        ordinary
            .with(|| ordinary_wide.decode_payload(&wide))
            .unwrap();
        let retry = context
            .with(|| PreparedQuantityDecode::try_decode_payload(&wide, &pool))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(retry.get(), &Quantity::decode_from_slice(&wide).unwrap().0);
        assert_eq!(
            context.consumed_allocated_bytes(),
            ordinary.consumed_allocated_bytes()
        );
        assert_eq!(pool.reserved_bytes(), small_work + wide_work);
        assert_eq!((late.as_ptr(), late.len()), original);
        drop((retry, first, ordinary_small, ordinary_wide));
        assert_eq!(pool.reserved_bytes(), 0);
        assert_eq!(oracle_pool.reserved_bytes(), 0);
    }
}

#[test]
fn one_pass_quantity_capacity_precedes_late_scalar_and_refunds_only_physical_credit() {
    let _flags = DecodeFlagsGuard::enter(0);
    let valid = payload(BigInt::one(), 0);
    let late = payload(BigInt::one(), MAX_DECIMAL_SCALE + 1);
    let original = (late.as_ptr(), late.len());
    let work = core::mem::size_of::<NativeBigDigit>();
    let layout = Layout::array::<NativeBigDigit>(1).unwrap();
    let pool = AllocationBudget::new(work);
    let limits =
        norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 32);
    let context = norito::core::DecodeBudgetContext::new(limits);
    let first = context
        .with(|| PreparedQuantityDecode::try_decode_payload(&valid, &pool))
        .unwrap_or_else(|error| panic!("{error}"));
    let expected = pool.try_reserve(layout).unwrap_err();
    let failure = context
        .with(|| PreparedQuantityDecode::try_decode_payload(&late, &pool))
        .err()
        .expect("live original digits occupy the pool");
    let QuantityDecodeAdmissionError::Allocation(ChargedBufferError::Admission(actual)) = failure
    else {
        panic!("physical admission must precede late scalar rejection")
    };
    assert_eq!(actual, expected);
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(2 * work).unwrap()
    );
    assert_eq!(pool.reserved_bytes(), work);
    drop(first);
    assert_eq!(pool.reserved_bytes(), 0);
    let expected = Quantity::decode_from_slice(&late).unwrap_err();
    let failure = context
        .with(|| PreparedQuantityDecode::try_decode_payload(&late, &pool))
        .err()
        .expect("late scale is still rejected");
    let QuantityDecodeAdmissionError::Codec(actual) = failure else {
        panic!("late scale")
    };
    assert_eq!(actual.to_string(), expected.to_string());
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(3 * work).unwrap()
    );
    assert_eq!(
        pool.reserved_bytes(),
        0,
        "digits are gone while original diagnostic still lives"
    );
    let retry = context
        .with(|| PreparedQuantityDecode::try_decode_payload(&valid, &pool))
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(retry.belongs_to(&pool));
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(4 * work).unwrap()
    );
    assert_eq!((late.as_ptr(), late.len()), original);
    drop(retry);
    assert_eq!(pool.reserved_bytes(), 0);
    let zero_pool = AllocationBudget::new(0);
    let zero = payload(BigInt::zero(), 0);
    let owner = context
        .with(|| PreparedQuantityDecode::try_decode_payload(&zero, &zero_pool))
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(owner.get().is_zero());
    assert!(owner.belongs_to(&zero_pool));
    assert_eq!(zero_pool.reserved_bytes(), 0);
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(4 * work).unwrap()
    );
    drop(owner);
    assert_eq!(zero_pool.reserved_bytes(), 0);
}

#[test]
fn quantity_backing_errors_preserve_original_diagnostics_and_sources() {
    use std::error::Error as _;

    let foreign = QuantityBackingError::ForeignPool;
    assert_eq!(
        foreign.to_string(),
        "quantity backing belongs to another pool"
    );
    assert!(foreign.source().is_none());
    let expected = Layout::from_size_align(16, 8).unwrap();
    let actual = Layout::from_size_align(8, 8).unwrap();
    for original in [
        ChargedBufferFromChargeError::DemandOverflow,
        ChargedBufferFromChargeError::LayoutMismatch { expected, actual },
        ChargedBufferFromChargeError::Allocator { layout: expected },
    ] {
        let diagnostic = original.to_string();
        let error = QuantityBackingError::Allocation(original);
        assert_eq!(error.to_string(), diagnostic);
        let QuantityBackingError::Allocation(original) = &error else {
            unreachable!("constructed original allocation cause");
        };
        let retained = error
            .source()
            .unwrap()
            .downcast_ref::<ChargedBufferFromChargeError>()
            .unwrap();
        assert!(core::ptr::eq(retained, original));
    }
}

#[test]
fn retained_quantity_digits_survive_late_scale_rejection_and_same_backing_retry() {
    let _flags = DecodeFlagsGuard::enter(0);
    let valid = payload(BigInt::from(17_u32), 0);
    let late = payload(BigInt::from(17_u32), u32::MAX);
    let plan = QuantityDecodePlan::decode_payload(&valid).unwrap();
    let pool = AllocationBudget::new(plan.allocation_layout().size());
    let mut destination = None;
    let failure = PreparedQuantityDecode::decode_payload_retained(&late, &pool, &mut destination)
        .unwrap_err();
    let QuantityDecodeAdmissionError::Codec(failure) = failure else {
        panic!("original late scale cause");
    };
    let ordinary = Quantity::decode_from_slice(&late).unwrap_err();
    assert_eq!(failure.to_string(), ordinary.to_string());
    let original = destination.as_ref().unwrap().digits.as_slice().as_ptr();
    assert!(destination.as_ref().unwrap().scale.is_none());
    assert_eq!(pool.reserved_bytes(), plan.allocation_layout().size());
    let retry = PreparedQuantityDecode::decode_payload_retained(&late, &pool, &mut destination)
        .unwrap_err();
    let QuantityDecodeAdmissionError::Codec(retry) = retry else {
        panic!("same late scale cause");
    };
    assert_eq!(retry.to_string(), ordinary.to_string());
    assert_eq!(
        destination.as_ref().unwrap().digits.as_slice().as_ptr(),
        original
    );
    assert_eq!(pool.reserved_bytes(), plan.allocation_layout().size());
    drop(destination);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn retained_quantity_original_quota_refusal_does_not_retire_digits_or_reset_outer_work() {
    let _flags = DecodeFlagsGuard::enter(0);
    let bytes = payload(BigInt::from(17_u32), 0);
    let plan = QuantityDecodePlan::decode_payload(&bytes).unwrap();
    let pool = AllocationBudget::new(plan.allocation_layout().size());
    let limits = norito::core::DecodeLimits::new(4096, 4096, 4096, 4096, 64);
    let outer = norito::core::DecodeBudgetContext::new(limits);
    let mut destination = None;
    outer
        .with(|| PreparedQuantityDecode::decode_payload_retained(&bytes, &pool, &mut destination))
        .unwrap();
    let original = destination.as_ref().unwrap().digits.as_slice().as_ptr();
    let before = outer.consumed_allocated_bytes();
    let failure = outer
        .with(|| {
            norito::core::with_decode_limits_scope(
                norito::core::DecodeLimits::new(4096, 4096, 4096, 0, 64),
                || PreparedQuantityDecode::decode_payload_retained(&bytes, &pool, &mut destination),
            )
        })
        .unwrap_err();
    let QuantityDecodeAdmissionError::Codec(failure) = failure else {
        panic!("original inner quota refusal");
    };
    assert!(failure.is_decode_resource_limit());
    assert!(outer.consumed_allocated_bytes() >= before);
    assert_eq!(
        destination.as_ref().unwrap().digits.as_slice().as_ptr(),
        original
    );
    assert!(destination.as_ref().unwrap().scale.is_none());
    assert_eq!(pool.reserved_bytes(), plan.allocation_layout().size());
    let before_retry = outer.consumed_allocated_bytes();
    outer
        .with(|| PreparedQuantityDecode::decode_payload_retained(&bytes, &pool, &mut destination))
        .unwrap();
    assert!(
        outer.consumed_allocated_bytes() > before_retry,
        "same outer cumulative counters consume retry work"
    );
    assert_eq!(
        destination.as_ref().unwrap().digits.as_slice().as_ptr(),
        original
    );
    let completed = destination
        .take()
        .unwrap()
        .finish()
        .unwrap_or_else(|_| panic!("same original canonical input"));
    assert_eq!(completed.get(), &Quantity::from(17_u32));
    assert_eq!(
        completed
            .get()
            .mantissa()
            .inner()
            .magnitude()
            .native_digits()
            .as_ptr(),
        original
    );
    drop(failure);
    drop(completed);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn borrowed_quantity_recheck_preserves_original_field_limits_without_backing_allocation() {
    let original = Quantity::from(17_u32);
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let bytes = payload(original.mantissa().clone(), original.scale());
    let pool = AllocationBudget::new(original.admission_clone_layout().unwrap().size());
    let destination = PreparedQuantityDecode::try_decode_payload(&bytes, &pool).unwrap();
    let pointer = destination
        .get()
        .mantissa()
        .inner()
        .magnitude()
        .native_digits()
        .as_ptr();
    let reserved = pool.reserved_bytes();
    PreparedQuantityDecode::recheck_payload(&bytes).unwrap();
    let ceiling = norito::core::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64);
    let ordinary = norito::core::with_decode_limits_scope(ceiling, || {
        PreparedQuantityDecode::try_decode_payload(&bytes, &pool)
    });
    let Err(QuantityDecodeAdmissionError::Codec(ordinary)) = ordinary else {
        panic!("canonical field ceiling precedes retained digit allocation");
    };
    let actual = norito::core::with_decode_limits_scope(ceiling, || {
        PreparedQuantityDecode::recheck_payload(&bytes)
    })
    .unwrap_err();
    assert_eq!(
        actual.decode_resource_error(),
        ordinary.decode_resource_error()
    );
    assert_eq!(
        destination
            .get()
            .mantissa()
            .inner()
            .magnitude()
            .native_digits()
            .as_ptr(),
        pointer
    );
    assert_eq!(pool.reserved_bytes(), reserved);
    PreparedQuantityDecode::recheck_payload(&bytes).unwrap();
    drop(destination);
    assert_eq!(pool.reserved_bytes(), 0);
}
