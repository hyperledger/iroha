//! Unit tests for the canonical decimal numeric types.
use super::*;
use core::cmp::Ordering;
use num_bigint::BigInt as ReferenceInt;
#[test]
fn aligned_quantity_sum_limbs_covers_the_complete_decimal_scale() {
    let aligned = aligned_quantity_sum_limbs(&Quantity::one(), MAX_DECIMAL_SCALE)
        .expect("one aligns to the maximum decimal scale");
    assert_eq!(
        u128::from(aligned[0]) | (u128::from(aligned[1]) << 64),
        10_u128.pow(MAX_DECIMAL_SCALE)
    );
    assert!(aligned[2..].iter().all(|limb| *limb == 0));
    let smallest = Quantity::from_canonical_numeric(Numeric::new(1, MAX_DECIMAL_SCALE))
        .expect("smallest decimal quantity");
    assert_eq!(aligned_quantity_sum_limbs(&smallest, 0), None);
    assert_eq!(
        aligned_quantity_sum_limbs(&Quantity::one(), MAX_DECIMAL_SCALE + 1),
        None
    );
}
#[test]
fn checked_add_equals_matches_canonical_arithmetic_at_boundaries() {
    let one = Quantity::one();
    let zero = Quantity::zero();
    let maximum = Quantity::from_canonical_numeric(Numeric::new(signed_maximum(), 0))
        .expect("largest quantity mantissa");
    let smallest = Quantity::from_canonical_numeric(Numeric::new(1, MAX_DECIMAL_SCALE))
        .expect("smallest decimal quantity");
    for (lhs, rhs) in [
        (zero.clone(), zero.clone()),
        (maximum.clone(), zero.clone()),
        (smallest.clone(), smallest.clone()),
        (quantity("0.1"), quantity("0.9")),
        (quantity("1.2"), quantity("0.03")),
        (quantity("18446744073709551615"), one.clone()),
    ] {
        let expected = lhs.checked_add(&rhs).expect("bounded boundary sum");
        assert!(lhs.checked_add_equals(&rhs, &expected));
        if let Ok(wrong) = expected.checked_add(&one) {
            assert!(!lhs.checked_add_equals(&rhs, &wrong));
        } else {
            assert!(!lhs.checked_add_equals(&rhs, &zero));
        }
    }
    assert_eq!(
        maximum.checked_add(&one),
        Err(NumericOperationError::MantissaOverflow)
    );
    assert!(!maximum.checked_add_equals(&one, &maximum));
    assert!(!maximum.checked_add_equals(&smallest, &maximum));

    // The aligned intermediate exceeds the signed 512-bit mantissa limit,
    // but its trailing decimal zero leaves a canonical integer in range.
    let near_limit_tenth = Quantity::from_canonical_numeric(Numeric::new(signed_maximum(), 1))
        .expect("canonical near-limit tenth");
    let three_tenths =
        Quantity::from_canonical_numeric(Numeric::new(3, 1)).expect("canonical three tenths");
    let normalized = near_limit_tenth
        .checked_add(&three_tenths)
        .expect("decimal normalization restores the mantissa bound");
    assert_eq!(normalized.scale(), 0);
    assert!(near_limit_tenth.checked_add_equals(&three_tenths, &normalized));
}
#[test]
fn checked_add_equals_matches_checked_add_for_deterministic_wide_inputs() {
    let mut seed = 0x6b8b_4567_327b_23c6_u64;
    for _ in 0..256 {
        let mut values = [Quantity::zero(), Quantity::zero()];
        for value in &mut values {
            let mut bytes = [0_u8; MAX_MANTISSA_BYTES];
            for chunk in bytes.chunks_exact_mut(8) {
                seed = seed
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                chunk.copy_from_slice(&seed.to_le_bytes());
            }
            bytes[MAX_MANTISSA_BYTES - 1] &= 0x7f;
            let mantissa = BigInt::from_twos_bytes(&bytes).expect("bounded positive mantissa");
            let scale = u32::try_from(seed % u64::from(MAX_DECIMAL_SCALE + 1))
                .expect("bounded decimal scale");
            *value = Quantity::from_canonical_numeric(Numeric::new(mantissa, scale))
                .expect("canonical nonnegative quantity");
        }
        let [lhs, rhs] = values;
        match lhs.checked_add(&rhs) {
            Ok(sum) => {
                assert!(lhs.checked_add_equals(&rhs, &sum));
                if let Ok(wrong) = sum.checked_add(&Quantity::one()) {
                    assert!(!lhs.checked_add_equals(&rhs, &wrong));
                }
            }
            Err(NumericOperationError::MantissaOverflow) => {
                assert!(!lhs.checked_add_equals(&rhs, &lhs));
                assert!(!lhs.checked_add_equals(&rhs, &rhs));
            }
            Err(other) => panic!("unexpected bounded sum error: {other}"),
        }
    }
}
#[test]
fn quantity_admission_clone_preserves_canonical_value_with_exact_digit_layout() {
    let zero = Quantity::zero();
    assert_eq!(zero.admission_clone_layout().unwrap().size(), 0);
    assert_eq!(zero.try_clone_for_admission().unwrap(), zero);

    let fractional = Quantity::from_canonical_numeric(Numeric::new(123, 2)).unwrap();
    let mut maximum_bytes = [0xff_u8; MAX_MANTISSA_BYTES];
    maximum_bytes[MAX_MANTISSA_BYTES - 1] = 0x7f;
    let maximum = Quantity::from_canonical_numeric(Numeric::new(
        BigInt::from_twos_bytes(&maximum_bytes).unwrap(),
        0,
    ))
    .unwrap();
    for value in [fractional, maximum] {
        let expected = value
            .mantissa()
            .bit_len()
            .div_ceil(UNBOUNDED_BIGINT_DIGIT_BYTES * 8)
            * UNBOUNDED_BIGINT_DIGIT_BYTES;
        assert_eq!(value.admission_clone_layout().unwrap().size(), expected);
        let cloned = value.try_clone_for_admission().unwrap();
        assert_eq!(cloned, value);
        assert_eq!(cloned.scale(), value.scale());
    }
}
#[test]
fn check_add() {
    let a = Numeric::new(10, 0);
    let b = Numeric::new(9, 3);
    assert_eq!(a.checked_add(b), Some(Numeric::new(10009, 3)));
    let a = Numeric::new(1, 2);
    let b = Numeric::new(999, 2);
    assert_eq!(a.checked_add(b), Some(Numeric::new(1000, 2)));
}
#[test]
fn numeric_ordering_compares_value_not_repr() {
    let ten = Numeric::new(10, 0);
    let nine_point_eight = Numeric::new(98, 1);
    let nine_point_eight_fine = Numeric::new(9_800, 3);
    assert!(nine_point_eight < ten);
    assert!(nine_point_eight_fine < ten);
    assert_eq!(
        nine_point_eight.partial_cmp(&nine_point_eight_fine),
        Some(Ordering::Equal)
    );
}
#[test]
fn numeric_decode_from_slice_reports_the_exact_prefix_length() {
    let expected: Numeric = "1.25".parse().expect("numeric");
    let canonical = expected.encode();
    let mut followed_by_next_field = canonical.clone();
    followed_by_next_field.extend_from_slice(b"next-field");
    let (decoded, used) =
        <Numeric as norito::core::DecodeFromSlice>::decode_from_slice(&followed_by_next_field)
            .expect("decode numeric prefix");
    assert_eq!(decoded, expected);
    assert_eq!(used, canonical.len());
}
#[test]
fn numeric_exact_norito_length_matches_canonical_payload() {
    let assert_exact_length = |value: &Numeric| {
        let owned = scale_::NumericScaleHelper {
            mantissa: value.mantissa.clone(),
            scale: value.scale(),
        };
        let borrowed = scale_::NumericScaleHelperView {
            mantissa: scale_::BigIntView(&value.mantissa),
            scale: value.scale(),
        };
        let owned_payload = norito::codec::Encode::encode(&owned);
        let borrowed_payload = norito::codec::Encode::encode(&borrowed);
        assert_eq!(borrowed_payload, owned_payload);
        assert_eq!(
            norito::codec::Encode::encode(value),
            owned_payload,
            "Numeric must retain the helper payload layout"
        );
        assert_eq!(owned.encoded_len_exact(), Some(owned_payload.len()));
        assert_eq!(borrowed.encoded_len_exact(), Some(owned_payload.len()));
        assert_eq!(value.encoded_len_exact(), Some(owned_payload.len()));
    };
    for value in [
        "-327.69",
        "-128",
        "-1",
        "0",
        "0.000000001",
        "1.25",
        "127",
        "128",
        "327.68",
    ] {
        let value: Numeric = value.parse().expect("canonical numeric");
        assert_exact_length(&value);
    }
    let signed_limit = ReferenceInt::one() << (MAX_MANTISSA_BITS - 1);
    for mantissa in [-signed_limit.clone(), signed_limit - 1_u8] {
        let mantissa = BigInt::from_inner(mantissa).expect("bounded numeric mantissa");
        let value =
            Numeric::try_new(mantissa, MAX_DECIMAL_SCALE).expect("canonical numeric extremum");
        assert_eq!(value.scale(), MAX_DECIMAL_SCALE);
        assert_eq!(value.mantissa.twos_byte_len(), MAX_MANTISSA_BYTES);
        assert_exact_length(&value);
    }
}
#[test]
fn streamed_numeric_matches_owned_helper_for_extrema_and_scales() {
    let limit = ReferenceInt::one() << (MAX_MANTISSA_BITS - 1);
    for raw in [
        ReferenceInt::zero(),
        ReferenceInt::from(-129),
        ReferenceInt::from(128),
        -limit.clone(),
        limit - 1_u8,
    ] {
        for scale in [0, 1, MAX_DECIMAL_SCALE] {
            let value = Numeric::try_new(BigInt::from_inner(raw.clone()).unwrap(), scale).unwrap();
            let owned = scale_::NumericScaleHelper {
                mantissa: value.mantissa.clone(),
                scale: value.scale(),
            };
            let expected = norito::codec::Encode::encode(&owned);
            let mut storage = [0_u8; 256];
            let actual_len = {
                let mut output = std::io::Cursor::new(storage.as_mut_slice());
                value
                    .serialize(&mut norito::core::Encoder::new(&mut output))
                    .unwrap();
                usize::try_from(output.position()).unwrap()
            };
            assert_eq!(&storage[..actual_len], expected.as_slice());
            assert_eq!(
                norito::core::encoded_payload_len(&value).unwrap(),
                actual_len
            );
            let (decoded, used) = <Numeric as norito::core::DecodeFromSlice>::decode_from_slice(
                &storage[..actual_len],
            )
            .unwrap();
            assert_eq!(decoded, value);
            assert_eq!(used, actual_len);
        }
    }
}
#[test]
fn check_json_roundtrip() {
    let num1 = Numeric::new(1002, 2);
    let s = norito::json::to_json(&num1).expect("failed to serialize numeric");
    assert_eq!(s, "\"10.02\"");
    let num2 = norito::json::from_str(&s).expect("failed to deserialize numeric");
    assert_eq!(num1, num2);
    for noncanonical in ["+1", "01", "-0", "1.0", ".5", "1."] {
        let source = format!("\"{noncanonical}\"");
        assert!(
            norito::json::from_str::<Numeric>(&source).is_err(),
            "alternate decimal spelling must be rejected: {source}"
        );
    }
}
#[test]
fn numeric_spec_json_roundtrip() {
    let specs = [NumericSpec::unconstrained(), NumericSpec::fractional(5)];
    let mut serialized = Vec::new();
    for spec in specs {
        serialized.push(norito::json::to_json(&spec).expect("serialize spec"));
    }
    assert_eq!(serialized[0], "{\"scale\":null}");
    assert_eq!(serialized[1], "{\"scale\":5}");
    for json in serialized {
        let decoded: NumericSpec = norito::json::from_json(&json).expect("deserialize spec");
        let reencoded = norito::json::to_json(&decoded).expect("re-serialize spec");
        assert_eq!(reencoded, json);
    }
    let duplicate = norito::json::from_json::<NumericSpec>(r#"{"scale":1,"scale":2}"#)
        .expect_err("duplicate numeric-spec scale must fail closed");
    assert!(matches!(
        duplicate,
        norito::json::Error::DuplicateField { ref field } if field == "scale"
    ));
}
#[test]
fn numeric_spec_rejects_scales_outside_the_v1_domain_on_every_boundary() {
    assert_eq!(
        NumericSpec::try_fractional(MAX_DECIMAL_SCALE).expect("the V1 maximum scale is valid"),
        NumericSpec::fractional(MAX_DECIMAL_SCALE)
    );
    assert!(matches!(
        NumericSpec::try_fractional(MAX_DECIMAL_SCALE + 1),
        Err(NumericSpecError::ScaleTooHigh)
    ));
    let hostile_json = format!(r#"{{"scale":{}}}"#, MAX_DECIMAL_SCALE + 1);
    assert!(
        norito::json::from_json::<NumericSpec>(&hostile_json).is_err(),
        "JSON must not construct an asset precision policy outside the numeric domain"
    );
    let invalid = NumericSpec {
        scale: Some(MAX_DECIMAL_SCALE + 1),
    };
    let encoded = norito::to_bytes(&invalid).expect("encode hostile archived fixture");
    assert!(
        norito::decode_from_bytes::<NumericSpec>(&encoded).is_err(),
        "Norito must not construct an asset precision policy outside the numeric domain"
    );
}
#[test]
fn numeric_spec_allows_trailing_zero_scale_reduction() {
    let integer_spec = NumericSpec::integer();
    assert!(integer_spec.check(&Numeric::new(100, 2)).is_ok());
    assert!(matches!(
        integer_spec.check(&Numeric::new(101, 2)),
        Err(NumericSpecError::ScaleTooHigh)
    ));
    let fractional_spec = NumericSpec::fractional(1);
    assert!(fractional_spec.check(&Numeric::new(120, 2)).is_ok());
    assert!(matches!(
        fractional_spec.check(&Numeric::new(121, 2)),
        Err(NumericSpecError::ScaleTooHigh)
    ));
}
#[test]
fn trim_trailing_zeros_normalises_scale() {
    assert_eq!(
        Numeric::new(1000, 3).trim_trailing_zeros(),
        Numeric::new(1, 0)
    );
    assert_eq!(
        Numeric::new(1230, 2).trim_trailing_zeros(),
        Numeric::new(123, 1)
    );
    assert_eq!(
        Numeric::new(1234, 2).trim_trailing_zeros(),
        Numeric::new(1234, 2)
    );
}
// Ensure Norito codec round-trips the value without loss.
#[test]
fn check_norito_roundtrip() {
    let num1 = Numeric::new(1002, 2);
    let s = num1.encode();
    let num2 = Numeric::decode(&mut s.as_slice()).expect("failed to decode numeric");
    assert_eq!(num1, num2);
}
#[test]
fn numeric_canonical_roundtrip() {
    let value = Numeric::new(12345, 3);
    let payload = norito::codec::Encode::encode(&value);
    let (decoded, used) = norito::core::decode_field_canonical::<Numeric>(&payload)
        .expect("decode canonical numeric");
    assert_eq!(decoded, value);
    assert_eq!(used, payload.len());
}
#[test]
fn signed_domain_minimum_parses_and_formats_at_fractional_scale() {
    let mut minimum_bytes = vec![0_u8; MAX_MANTISSA_BYTES];
    *minimum_bytes.last_mut().expect("nonempty signed domain") = 0x80;
    let minimum = BigInt::from_twos_bytes(&minimum_bytes).expect("signed minimum");
    let integer = minimum.to_string();
    let magnitude = integer.strip_prefix('-').expect("negative minimum");
    let split = magnitude.len() - 1;
    let source = format!("-{}.{}", &magnitude[..split], &magnitude[split..]);
    let numeric = source
        .parse::<Numeric>()
        .expect("fractional signed minimum");
    assert_eq!(numeric.mantissa(), &minimum);
    assert_eq!(numeric.scale(), 1);
    assert_eq!(numeric.to_string(), source);
}
fn decimal(source: &str) -> Numeric {
    source
        .parse::<Numeric>()
        .expect("valid decimal source")
        .canonicalize_decimal()
        .expect("representable canonical decimal")
}
fn quantity(source: &str) -> Quantity {
    source.parse().expect("valid quantity source")
}
fn signed_maximum() -> BigInt {
    let mut bytes = vec![0xff_u8; MAX_MANTISSA_BYTES - 1];
    bytes.push(0x7f);
    BigInt::from_twos_bytes(&bytes).expect("signed maximum")
}
fn signed_minimum() -> BigInt {
    let mut bytes = vec![0_u8; MAX_MANTISSA_BYTES - 1];
    bytes.push(0x80);
    BigInt::from_twos_bytes(&bytes).expect("signed minimum")
}
#[test]
fn lossy_f64_conversion_is_explicit_and_finite_across_the_domain() {
    let beyond_exact_binary_range = decimal("9007199254740993");
    assert_eq!(
        beyond_exact_binary_range.to_f64_lossy().to_bits(),
        9_007_199_254_740_992.0_f64.to_bits()
    );
    for endpoint in [
        Numeric::try_new(signed_minimum(), 0).expect("signed minimum"),
        Numeric::try_new(signed_maximum(), 0).expect("signed maximum"),
        Numeric::try_new(signed_minimum(), MAX_DECIMAL_SCALE).expect("fractional signed minimum"),
        Numeric::try_new(signed_maximum(), MAX_DECIMAL_SCALE).expect("fractional signed maximum"),
    ] {
        assert!(endpoint.to_f64_lossy().is_finite(), "{endpoint}");
    }
}
#[test]
fn decimal_canonicalization_is_unique_for_signed_zeroes_and_trailing_zeroes() {
    for (source, expected) in [
        ("0", Numeric::zero()),
        ("-0.000", Numeric::zero()),
        ("1.2300", Numeric::new(123, 2)),
        ("-1.2300", Numeric::new(-123, 2)),
        ("100.000", Numeric::new(100, 0)),
    ] {
        let parsed = source.parse::<Numeric>().expect("parse");
        let canonical = parsed.canonicalize_decimal().expect("canonicalize");
        assert_eq!(canonical, expected, "source={source}");
        canonical.validate_decimal().expect("canonical output");
    }
    for noncanonical in [
        Numeric::try_new_raw(0, 28).expect("raw zero"),
        Numeric::try_new_raw(10, 1).expect("raw trailing zero"),
    ] {
        assert_eq!(
            noncanonical.validate_decimal(),
            Err(NumericOperationError::NonCanonical)
        );
    }
    assert_eq!(
        Numeric::try_new(10, 29),
        Ok(Numeric::new(1, 28)),
        "normalization precedes the canonical scale bound"
    );
    assert_eq!(Numeric::try_new(1, 29), Err(NumericError::ScaleTooLarge));
    assert_eq!(Numeric::try_new(0, u32::MAX), Ok(Numeric::zero()));
    let removable = format!("0.{}10", "0".repeat(27));
    assert_eq!(
        removable.parse::<Numeric>(),
        Ok(Numeric::new(1, 28)),
        "source parsing must normalize a removable 29th digit"
    );
    let nonremovable = format!("0.{}1", "0".repeat(28));
    assert_eq!(
        nonremovable.parse::<Numeric>(),
        Err(NumericError::ScaleTooLarge)
    );
    let maximum = signed_maximum();
    let oversized_but_removable = format!("{maximum}.0");
    assert_eq!(
        oversized_but_removable.parse::<Numeric>(),
        Ok(Numeric::new(maximum.clone(), 0)),
        "mantissa bounds are checked after textual normalization"
    );
    let oversized_and_nonremovable = format!("{maximum}.1");
    assert_eq!(
        oversized_and_nonremovable.parse::<Numeric>(),
        Err(NumericError::MantissaTooLarge)
    );
}
#[test]
fn numeric_parser_rejects_multiple_leading_signs() {
    for malformed in ["++1", "+-1", "-+1", "--1"] {
        assert_eq!(
            malformed.parse::<Numeric>(),
            Err(NumericError::Malformed),
            "multiple leading signs must be rejected: {malformed}"
        );
    }
}

#[test]
fn decimal_endpoints_and_negation_enforce_signed_domain_after_normalization() {
    let maximum = Numeric::new(signed_maximum(), 0);
    let minimum = Numeric::new(signed_minimum(), 0);
    assert_eq!(
        maximum.try_decimal_add(&Numeric::one()),
        Err(NumericOperationError::MantissaOverflow)
    );
    assert_eq!(
        minimum.try_decimal_sub(&Numeric::one()),
        Err(NumericOperationError::MantissaOverflow)
    );
    assert_eq!(
        minimum.try_decimal_neg(),
        Err(NumericOperationError::MantissaOverflow)
    );
    assert_eq!(
        maximum
            .try_decimal_neg()
            .expect("negate max")
            .try_decimal_neg(),
        Ok(maximum)
    );
}
#[test]
fn numeric_construction_rejects_both_signed_512_bit_neighbors() {
    let above_maximum = signed_maximum()
        .checked_add(&BigInt::one())
        .expect("generic bigint can represent the upper neighbor");
    let below_minimum = signed_minimum()
        .checked_sub(&BigInt::one())
        .expect("generic bigint can represent the lower neighbor");
    assert_eq!(
        Numeric::try_new(above_maximum.clone(), 0),
        Err(NumericError::MantissaTooLarge)
    );
    assert_eq!(
        Numeric::try_new(below_minimum.clone(), 0),
        Err(NumericError::MantissaTooLarge)
    );
    assert_eq!(
        Numeric::try_new_raw(above_maximum, 0),
        Err(NumericError::MantissaTooLarge)
    );
    assert_eq!(
        Numeric::try_new_raw(below_minimum, 0),
        Err(NumericError::MantissaTooLarge)
    );
}
#[test]
fn decimal_multiplication_uses_unbounded_intermediate_then_normalizes() {
    let maximum = Numeric::new(signed_maximum(), MAX_DECIMAL_SCALE);
    maximum
        .validate_decimal()
        .expect("maximum is not divisible by ten");
    let decimal_power = Numeric::new(BigInt::pow10(MAX_DECIMAL_SCALE).expect("10^28 fits"), 0);
    assert_eq!(
        decimal_power.try_decimal_mul(&maximum),
        Ok(Numeric::new(signed_maximum(), 0)),
        "the conceptual product is wider than 512 bits but the canonical result fits"
    );
    assert_eq!(
        decimal("0.0000000000000000000000000001")
            .try_decimal_mul(&decimal("0.0000000000000000000000000001")),
        Err(NumericOperationError::ScaleOverflow)
    );
    assert_eq!(
        decimal("0.0000000000000000000000000002").try_decimal_mul(&decimal("0.5")),
        Ok(decimal("0.0000000000000000000000000001"))
    );
    assert_eq!(
        maximum.try_decimal_mul(&maximum),
        Err(NumericOperationError::ScaleOverflow),
        "after normalization, scale failure precedes simultaneous mantissa overflow"
    );
}
#[test]
fn fused_multiply_divide_bounds_only_the_final_result() {
    let maximum = Numeric::new(signed_maximum(), 0);
    let factor = Numeric::from(10_000_u64);
    assert_eq!(
        maximum.try_decimal_mul(&factor),
        Err(NumericOperationError::MantissaOverflow),
        "the deliberately staged product does not fit the public domain"
    );
    assert_eq!(
        maximum.try_decimal_mul_div_round(&factor, &factor, 0, RoundingMode::NearestEven,),
        Ok(maximum.clone()),
        "the fused operation must bound only its mathematical final result"
    );
    assert_eq!(
        maximum.try_decimal_mul_div_exact(&factor, &factor),
        Ok(maximum.clone()),
        "exact fused arithmetic must also bound only its final result"
    );
    let maximum_quantity =
        Quantity::from_canonical_numeric(maximum).expect("signed maximum is non-negative");
    let maximum_xor =
        XorQuantity::try_from_quantity(maximum_quantity).expect("scale-zero XOR quantity");
    assert_eq!(
        maximum_xor.checked_mul_ratio_round(
            10_000,
            core::num::NonZeroU64::new(10_000).expect("nonzero fixture"),
            XOR_QUANTITY_SCALE,
            RoundingMode::Ceil,
        ),
        Ok(maximum_xor),
        "domain wrappers must retain the fused-intermediate guarantee"
    );
}
#[test]
fn weighted_average_bounds_only_the_final_result_and_total_weight_is_unbounded() {
    let maximum = Quantity::from_canonical_numeric(Numeric::new(signed_maximum(), 0))
        .expect("signed maximum is a quantity");
    assert_eq!(
        maximum.try_mul_decimal(&Numeric::from(u64::MAX)),
        Err(NumericOperationError::MantissaOverflow),
        "a staged weighted product deliberately exceeds the public domain"
    );
    let entries = [(&maximum, u64::MAX), (&maximum, u64::MAX)];
    assert_eq!(
        Quantity::try_weighted_average_round(entries, 0, RoundingMode::NearestEven,),
        Ok(maximum),
        "neither the product, sum, nor total weight is narrowed before division"
    );
}
#[test]
fn weighted_average_aligns_scales_and_has_explicit_failure_boundaries() {
    let one = Quantity::try_from_numeric(decimal("1")).expect("quantity");
    let two = Quantity::try_from_numeric(decimal("2")).expect("quantity");
    let fractional = Quantity::try_from_numeric(decimal("0.000001")).expect("fractional quantity");
    let entries = [(&one, 1), (&two, 1), (&fractional, 2)];
    assert_eq!(
        Quantity::try_weighted_average_round(entries, 6, RoundingMode::TowardZero),
        Quantity::try_from_numeric(decimal("0.75")),
    );
    assert_eq!(
        Quantity::try_weighted_average_round([(&one, 0), (&two, 0)], 0, RoundingMode::TowardZero,),
        Err(NumericOperationError::DivisionByZero)
    );
    assert_eq!(
        Quantity::try_weighted_average_round(
            [(&one, 1)],
            MAX_DECIMAL_SCALE + 1,
            RoundingMode::TowardZero,
        ),
        Err(NumericOperationError::InvalidScale)
    );
}
#[test]
fn aggregate_decimal_product_bounds_only_its_canonical_final_result() {
    let maximum_even = Quantity::from_canonical_numeric(Numeric::new(
        signed_maximum()
            .checked_sub(&BigInt::one())
            .expect("maximum minus one fits"),
        0,
    ))
    .expect("largest even positive quantity");
    assert_eq!(
        maximum_even.try_mul_decimal(&Numeric::from(2_u32)),
        Err(NumericOperationError::MantissaOverflow)
    );
    assert_eq!(
        maximum_even.try_product_decimals([&Numeric::from(2_u32), &decimal("0.5")]),
        Ok(maximum_even.clone()),
        "a later exact factor may cancel a wide conceptual product"
    );
    let tiny = decimal("0.0000000000000000000000000001");
    assert_eq!(
        Quantity::one()
            .try_mul_decimal(&tiny)
            .and_then(|value| value.try_mul_decimal(&tiny)),
        Err(NumericOperationError::ScaleOverflow)
    );
    assert_eq!(
        Quantity::one().try_product_decimals([
            &tiny,
            &tiny,
            &decimal("10000000000000000000000000000"),
        ]),
        Ok(Quantity::try_from_numeric(tiny.clone()).expect("tiny is a quantity")),
        "final normalization, rather than the scale-56 temporary, controls success"
    );
    assert_eq!(
        Quantity::one().try_product_decimals([&decimal("-1")]),
        Err(DecimalProductError::Numeric(
            NumericOperationError::NegativeQuantity
        ))
    );
}
#[test]
fn aggregate_decimal_product_rejects_more_than_sixty_four_factors() {
    let one = Numeric::one();
    assert_eq!(
        Quantity::one()
            .try_product_decimals(core::iter::repeat_n(&one, MAX_DECIMAL_PRODUCT_FACTORS)),
        Ok(Quantity::one())
    );
    assert_eq!(
        Quantity::one()
            .try_product_decimals(core::iter::repeat_n(&one, MAX_DECIMAL_PRODUCT_FACTORS + 1)),
        Err(DecimalProductError::TooManyFactors)
    );
}
#[test]
fn aggregate_decimal_product_rounds_only_its_final_result() {
    let panel_multiplier = decimal("0.7142857142857142857142857143");
    let result = Quantity::from(150_u32)
        .try_product_decimals_round(
            [
                &decimal("1.06"),
                &decimal("1.08"),
                &decimal("1.2"),
                &panel_multiplier,
                &Numeric::one(),
            ],
            MAX_DECIMAL_SCALE,
            RoundingMode::NearestEven,
        )
        .expect("aggregate appeal-pricing product");
    assert_eq!(result.to_string(), "147.1885714285714285714285714315");
    assert_eq!(
        Quantity::from(150_u32)
            .try_product_decimals_round(
                [
                    &decimal("1.06"),
                    &decimal("1.08"),
                    &decimal("1.2"),
                    &panel_multiplier,
                    &Numeric::one(),
                ],
                XOR_QUANTITY_SCALE,
                RoundingMode::NearestEven,
            )
            .expect("nano-XOR aggregate appeal-pricing product")
            .to_string(),
        "147.188571429"
    );
    assert_eq!(
        Quantity::one()
            .try_product_decimals_round(
                [&decimal("1.25"), &decimal("1.25")],
                1,
                RoundingMode::NearestEven,
            )
            .expect("aggregate final-only rounding")
            .to_string(),
        "1.6",
        "one aggregate rounding must differ from staged tie-to-even rounding"
    );
    assert_eq!(
        Quantity::one().try_product_decimals_round(
            [&Numeric::one()],
            MAX_DECIMAL_SCALE + 1,
            RoundingMode::NearestEven,
        ),
        Err(DecimalProductError::Numeric(
            NumericOperationError::InvalidScale
        ))
    );
}
#[test]
fn rounded_aggregate_decimal_product_rejects_more_than_sixty_four_factors() {
    let one = Numeric::one();
    assert_eq!(
        Quantity::one().try_product_decimals_round(
            core::iter::repeat_n(&one, MAX_DECIMAL_PRODUCT_FACTORS),
            MAX_DECIMAL_SCALE,
            RoundingMode::NearestEven,
        ),
        Ok(Quantity::one())
    );
    assert_eq!(
        Quantity::one().try_product_decimals_round(
            core::iter::repeat_n(&one, MAX_DECIMAL_PRODUCT_FACTORS + 1),
            MAX_DECIMAL_SCALE,
            RoundingMode::NearestEven,
        ),
        Err(DecimalProductError::TooManyFactors)
    );
}
#[test]
fn multiplied_quantity_comparison_never_materializes_bounded_products() {
    let maximum = Quantity::from_canonical_numeric(Numeric::new(signed_maximum(), 0))
        .expect("signed maximum is a quantity");
    assert_eq!(maximum.cmp_mul_u64(3, &maximum, 2), Ordering::Greater);
    assert_eq!(
        Quantity::try_from_numeric(decimal("0.02"))
            .expect("quantity")
            .cmp_mul_u64(
                3,
                &Quantity::try_from_numeric(decimal("0.03")).expect("quantity"),
                2,
            ),
        Ordering::Equal,
        "scale alignment preserves an exact two-thirds boundary"
    );
}
#[test]
fn fused_multiply_divide_matches_bounded_reference_across_signs_and_rounding_modes() {
    let values = ["-12.5", "-1", "0", "0.125", "7.75"];
    let multipliers = ["-3.2", "-1", "0", "0.5", "4"];
    let divisors = ["-2.5", "-1", "0.25", "3"];
    let modes = [
        RoundingMode::TowardZero,
        RoundingMode::AwayFromZero,
        RoundingMode::Floor,
        RoundingMode::Ceil,
        RoundingMode::NearestEven,
        RoundingMode::NearestAway,
        RoundingMode::NearestTowardZero,
    ];
    for value in values.map(decimal) {
        for multiplier in multipliers.map(decimal) {
            for divisor in divisors.map(decimal) {
                let exact_reference = value
                    .try_decimal_mul(&multiplier)
                    .and_then(|product| product.try_decimal_div_exact(&divisor));
                assert_eq!(
                    value.try_decimal_mul_div_exact(&multiplier, &divisor),
                    exact_reference,
                    "exact value={value}, multiplier={multiplier}, divisor={divisor}"
                );
                for output_scale in 0..=4 {
                    for mode in modes {
                        let reference = value.try_decimal_mul(&multiplier).and_then(|product| {
                            product.try_decimal_div_round(&divisor, output_scale, mode)
                        });
                        assert_eq!(
                            value.try_decimal_mul_div_round(
                                &multiplier,
                                &divisor,
                                output_scale,
                                mode,
                            ),
                            reference,
                            "value={value}, multiplier={multiplier}, divisor={divisor}, scale={output_scale}, mode={mode:?}"
                        );
                    }
                }
            }
        }
    }
    assert_eq!(
        decimal("1").try_decimal_mul_div_round(
            &decimal("2"),
            &Numeric::zero(),
            0,
            RoundingMode::TowardZero,
        ),
        Err(NumericOperationError::DivisionByZero)
    );
    assert_eq!(
        decimal("1").try_decimal_mul_div_round(
            &decimal("2"),
            &decimal("3"),
            MAX_DECIMAL_SCALE + 1,
            RoundingMode::TowardZero,
        ),
        Err(NumericOperationError::InvalidScale)
    );
    assert_eq!(
        decimal("1").try_decimal_mul_div_exact(&decimal("1"), &decimal("3")),
        Err(NumericOperationError::RepeatingDecimal)
    );
    assert_eq!(
        decimal("0.0000000000000000000000000001")
            .try_decimal_mul_div_exact(&decimal("1"), &decimal("10")),
        Err(NumericOperationError::ExactDivisionScaleOverflow)
    );
}
#[test]
fn exact_division_distinguishes_repeating_and_over_scale_terminating_results() {
    assert_eq!(
        decimal("1").try_decimal_div_exact(&decimal("8")),
        Ok(decimal("0.125"))
    );
    assert_eq!(
        decimal("1.2").try_decimal_div_exact(&decimal("0.03")),
        Ok(decimal("40"))
    );
    assert_eq!(
        decimal("1").try_decimal_div_exact(&decimal("3")),
        Err(NumericOperationError::RepeatingDecimal)
    );
    assert_eq!(
        decimal("0.0000000000000000000000000001").try_decimal_div_exact(&decimal("10")),
        Err(NumericOperationError::ExactDivisionScaleOverflow)
    );
    assert_eq!(
        decimal("1").classify_exact_division(&decimal("3")),
        Ok(ExactDivisionClass::Repeating)
    );
    assert_eq!(
        decimal("0.0000000000000000000000000001").classify_exact_division(&decimal("10")),
        Ok(ExactDivisionClass::ScaleOverflow)
    );
    assert_eq!(
        decimal("1").try_decimal_div_exact(&Numeric::zero()),
        Err(NumericOperationError::DivisionByZero)
    );
}
#[test]
fn exact_division_at_scale_reports_inexact_without_conflating_failure_classes() {
    let one = decimal("1");
    let eight = decimal("8");
    for scale in 0..3 {
        assert_eq!(
            one.try_decimal_div_exact_at_scale(&eight, scale),
            Ok(None),
            "scale={scale}"
        );
    }
    assert_eq!(
        one.try_decimal_div_exact_at_scale(&eight, 3),
        Ok(Some(decimal("0.125")))
    );
    assert_eq!(
        one.try_decimal_div_exact_at_scale(&eight, 29),
        Err(NumericOperationError::InvalidScale)
    );
}
#[test]
fn all_rounding_modes_are_correct_for_positive_and_negative_ties() {
    let two = decimal("2");
    let positive = decimal("1");
    let negative = decimal("-1");
    let expectations = [
        (RoundingMode::TowardZero, "0", "0"),
        (RoundingMode::AwayFromZero, "1", "-1"),
        (RoundingMode::Floor, "0", "-1"),
        (RoundingMode::Ceil, "1", "0"),
        (RoundingMode::NearestEven, "0", "0"),
        (RoundingMode::NearestAway, "1", "-1"),
        (RoundingMode::NearestTowardZero, "0", "0"),
    ];
    for (mode, expected_positive, expected_negative) in expectations {
        assert_eq!(
            positive.try_decimal_div_round(&two, 0, mode),
            Ok(decimal(expected_positive)),
            "positive mode={mode:?}"
        );
        assert_eq!(
            negative.try_decimal_div_round(&two, 0, mode),
            Ok(decimal(expected_negative)),
            "negative mode={mode:?}"
        );
    }
    assert_eq!(
        decimal("3").try_decimal_div_round(&two, 0, RoundingMode::NearestEven),
        Ok(decimal("2"))
    );
    assert_eq!(
        decimal("-3").try_decimal_div_round(&two, 0, RoundingMode::NearestEven),
        Ok(decimal("-2"))
    );
}
#[test]
fn quantization_requires_an_explicit_mode_and_preserves_canonical_form() {
    let expectations = [
        (RoundingMode::TowardZero, "1.2", "-1.2"),
        (RoundingMode::AwayFromZero, "1.3", "-1.3"),
        (RoundingMode::Floor, "1.2", "-1.3"),
        (RoundingMode::Ceil, "1.3", "-1.2"),
        (RoundingMode::NearestEven, "1.2", "-1.2"),
        (RoundingMode::NearestAway, "1.3", "-1.3"),
        (RoundingMode::NearestTowardZero, "1.2", "-1.2"),
    ];
    for (mode, positive, negative) in expectations {
        assert_eq!(
            decimal("1.25").try_quantize(1, mode),
            Ok(decimal(positive)),
            "positive mode={mode:?}"
        );
        assert_eq!(
            decimal("-1.25").try_quantize(1, mode),
            Ok(decimal(negative)),
            "negative mode={mode:?}"
        );
    }
    let no_padding = decimal("1.2")
        .try_quantize(5, RoundingMode::NearestEven)
        .expect("a larger requested scale does not manufacture trailing zeros");
    assert_eq!(no_padding, decimal("1.2"));
    assert_eq!(no_padding.scale(), 1);
    let canonical_integer = decimal("1.004")
        .try_quantize(2, RoundingMode::TowardZero)
        .expect("truncated result is representable");
    assert_eq!(canonical_integer, decimal("1"));
    assert_eq!(canonical_integer.scale(), 0);
    assert_eq!(
        decimal("1").try_quantize(29, RoundingMode::TowardZero),
        Err(NumericOperationError::InvalidScale)
    );
}
#[test]
fn quantization_to_spec_preserves_unconstrained_values_and_applies_scale() {
    let value = decimal("1.25");
    assert_eq!(
        value.try_quantize_to_spec(NumericSpec::unconstrained(), RoundingMode::NearestEven,),
        Ok(value.clone())
    );
    assert_eq!(
        value.try_quantize_to_spec(NumericSpec::fractional(1), RoundingMode::NearestEven),
        Ok(decimal("1.2"))
    );
}
#[test]
fn exact_truncating_and_rounded_integer_conversions_are_distinct() {
    assert_eq!(
        decimal("42").try_decimal_to_int_exact(),
        Ok(BigInt::from(42_i32))
    );
    assert_eq!(
        decimal("42.01").try_decimal_to_int_exact(),
        Err(NumericOperationError::InexactConversion)
    );
    assert_eq!(
        decimal("-42.99").decimal_to_int_trunc(),
        Ok(BigInt::from(-42_i32))
    );
    assert_eq!(
        decimal("-42.5").decimal_to_int_round(RoundingMode::Floor),
        Ok(BigInt::from(-43_i32))
    );
    assert_eq!(
        decimal("42.5").decimal_to_int_round(RoundingMode::NearestEven),
        Ok(BigInt::from(42_i32))
    );
    assert_eq!(
        decimal("43.5").decimal_to_int_round(RoundingMode::NearestEven),
        Ok(BigInt::from(44_i32))
    );
}
#[test]
fn observed_canonicalization_reports_each_normalization_and_zero_finalization() {
    let mut normalization_steps = Vec::new();
    let normalized = Numeric::try_new_raw(10_000, 4)
        .expect("raw value for observed normalization")
        .canonicalize_decimal_observed(&mut |step| {
            normalization_steps.push(step);
            Ok::<_, ()>(())
        })
        .expect("normalize");
    assert_eq!(normalized, Numeric::one());
    assert_eq!(normalization_steps.len(), 5);
    assert!(
        normalization_steps[..4]
            .iter()
            .all(|step| matches!(step, NumericWorkStep::Normalize { .. }))
    );
    assert!(matches!(
        normalization_steps[4],
        NumericWorkStep::Finalize { value_limbs: 1 }
    ));
    let mut zero_steps = Vec::new();
    let zero = Numeric::try_new_raw(0, MAX_DECIMAL_SCALE)
        .expect("raw scaled zero")
        .canonicalize_decimal_observed(&mut |step| {
            zero_steps.push(step);
            Ok::<_, ()>(())
        })
        .expect("canonicalize zero");
    assert_eq!(zero, Numeric::zero());
    assert_eq!(
        zero_steps,
        [NumericWorkStep::Finalize { value_limbs: 1 }],
        "zero performs no division but still validates its final domain"
    );
}
#[test]
fn observed_validation_reports_canonicality_probe_before_division_and_can_abort() {
    let mut validation_steps = Vec::new();
    decimal("1.2")
        .validate_decimal_observed(&mut |step| {
            validation_steps.push(step);
            Ok::<_, ()>(())
        })
        .expect("canonical validation");
    assert_eq!(
        validation_steps,
        [NumericWorkStep::CanonicalityProbe {
            mantissa_limbs: 1,
            scale: 1,
        }]
    );
    assert_eq!(
        decimal("1.2").validate_decimal_observed(&mut |_| Err("out-of-gas")),
        Err(ObservedNumericError::Observer("out-of-gas"))
    );
}
#[test]
fn observed_repeating_division_classifies_without_speculative_attempts() {
    let mut attempts = Vec::new();
    let error = decimal("1")
        .try_decimal_div_exact_observed(&decimal("3"), &mut |step| {
            attempts.push(step);
            Ok::<_, ()>(())
        })
        .expect_err("repeating");
    assert_eq!(
        error,
        ObservedNumericError::Numeric(NumericOperationError::RepeatingDecimal)
    );
    assert_eq!(
        attempts
            .iter()
            .filter(|step| matches!(step, NumericWorkStep::ExactDivisionAttempt { .. }))
            .count(),
        0,
        "a repeating quotient must fail after classification without speculative attempts"
    );
    assert!(
        attempts
            .iter()
            .any(|step| matches!(step, NumericWorkStep::DivisionClassification { .. }))
    );
}
#[test]
fn observed_terminating_division_attempts_only_the_proven_scale() {
    let mut terminating_steps = Vec::new();
    assert_eq!(
        decimal("1")
            .try_decimal_div_exact_observed(&decimal("8"), &mut |step| {
                terminating_steps.push(step);
                Ok::<_, ()>(())
            })
            .expect("terminating quotient"),
        decimal("0.125")
    );
    assert_eq!(
        terminating_steps
            .iter()
            .filter(|step| matches!(step, NumericWorkStep::ExactDivisionAttempt { .. }))
            .count(),
        1,
        "a terminating quotient must perform exactly one proven-scale attempt"
    );
    assert!(terminating_steps.iter().any(|step| matches!(
        step,
        NumericWorkStep::ExactDivisionAttempt {
            output_scale: 3,
            ..
        }
    )));
}
#[test]
fn observed_division_stops_before_arithmetic_after_observer_rejection() {
    let mut callbacks = 0;
    let aborted = decimal("1").try_decimal_div_exact_observed(&decimal("3"), &mut |_| {
        callbacks += 1;
        Err("out-of-gas")
    });
    assert_eq!(aborted, Err(ObservedNumericError::Observer("out-of-gas")));
    assert_eq!(
        callbacks, 1,
        "no arithmetic phase is entered after observer rejection"
    );
}
#[test]
fn public_quantity_construction_makes_equality_ordering_and_hash_canonical() {
    use core::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    let representations = [
        Numeric::new(1, 0),
        Numeric::new(10, 1),
        Numeric::new(100, 2),
        "1.0000".parse::<Numeric>().expect("parse"),
    ];
    for value in &representations {
        assert_eq!(value, &representations[0]);
        assert_eq!(value.cmp(&representations[0]), Ordering::Equal);
        assert_eq!(value.scale(), 0);
    }
    let hashes = representations.map(|value| {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    });
    assert!(hashes.iter().all(|hash| *hash == hashes[0]));
}
#[test]
fn observed_alignment_and_multiplication_steps_precede_bigint_work() {
    let mut add_steps = Vec::new();
    let sum = decimal("1")
        .try_decimal_add_observed(&decimal("0.1"), &mut |step| {
            add_steps.push(step);
            Ok::<_, ()>(())
        })
        .expect("add");
    assert_eq!(sum, decimal("1.1"));
    assert!(matches!(
        add_steps[0],
        NumericWorkStep::CanonicalityProbe { .. }
    ));
    assert_eq!(
        add_steps[1],
        NumericWorkStep::ScaleByPowerOfTen {
            value_limbs: 1,
            exponent: 1,
        }
    );
    assert!(matches!(
        add_steps[2],
        NumericWorkStep::Materialize { value_limbs: 1 }
    ));
    assert!(matches!(add_steps[3], NumericWorkStep::Add { .. }));
    assert!(matches!(add_steps[4], NumericWorkStep::Normalize { .. }));
    assert!(matches!(add_steps[5], NumericWorkStep::Finalize { .. }));
    let mut zero_steps = Vec::new();
    let zero_sum = decimal("0")
        .try_decimal_add_observed(&decimal("0.1"), &mut |step| {
            zero_steps.push(step);
            Ok::<_, ()>(())
        })
        .expect("zero alignment add");
    assert_eq!(zero_sum, decimal("0.1"));
    assert!(matches!(
        zero_steps.first(),
        Some(NumericWorkStep::CanonicalityProbe { .. })
    ));
    assert!(matches!(
        zero_steps.get(1),
        Some(NumericWorkStep::Materialize { value_limbs: 1 })
    ));
    assert!(
        zero_steps
            .iter()
            .all(|step| !matches!(step, NumericWorkStep::ScaleByPowerOfTen { .. })),
        "zero alignment must not construct or multiply by a decimal power"
    );
    let mut multiply_steps = Vec::new();
    let product = decimal("0.2")
        .try_decimal_mul_observed(&decimal("0.5"), &mut |step| {
            multiply_steps.push(step);
            Ok::<_, ()>(())
        })
        .expect("multiply");
    assert_eq!(product, decimal("0.1"));
    let multiply_index = multiply_steps
        .iter()
        .position(|step| matches!(step, NumericWorkStep::Multiply { .. }))
        .expect("multiply work step");
    assert!(
        multiply_steps[..multiply_index]
            .iter()
            .all(|step| matches!(step, NumericWorkStep::CanonicalityProbe { .. }))
    );
    assert!(
        multiply_steps[multiply_index + 1..]
            .iter()
            .all(|step| matches!(
                step,
                NumericWorkStep::Normalize { .. } | NumericWorkStep::Finalize { .. }
            ))
    );
    assert!(matches!(
        multiply_steps.last(),
        Some(NumericWorkStep::Finalize { .. })
    ));
    let mut saw_add = false;
    let aborted = decimal("1").try_decimal_add_observed(&decimal("0.1"), &mut |step| match step {
        NumericWorkStep::ScaleByPowerOfTen { .. } => Err("out-of-gas"),
        NumericWorkStep::Add { .. } => {
            saw_add = true;
            Ok(())
        }
        _ => Ok(()),
    });
    assert_eq!(aborted, Err(ObservedNumericError::Observer("out-of-gas")));
    assert!(
        !saw_add,
        "aligned multiplication and addition did not begin after rejection"
    );
}
#[test]
fn core_numeric_decoder_rejects_noncanonical_raw_payloads() {
    for value in [
        Numeric::try_new_raw(0, 1).expect("raw zero"),
        Numeric::try_new_raw(10, 1).expect("raw trailing zero"),
    ] {
        let encoded = value.encode();
        assert!(Numeric::decode(&mut encoded.as_slice()).is_err());
    }
}
#[test]
fn quantity_canonicalization_is_unique_and_rejects_invalid_payloads() {
    for (source, expected, expected_scale) in [
        ("0", "0", 0),
        ("0.000", "0", 0),
        ("1.2500", "1.25", 2),
        ("10.000000", "10", 0),
    ] {
        let value = quantity(source);
        assert_eq!(value.to_string(), expected, "source={source}");
        assert_eq!(value.scale(), expected_scale, "source={source}");
        value
            .as_numeric()
            .validate_decimal()
            .expect("quantity contains a canonical decimal");
    }
    assert_eq!(
        Quantity::try_from_numeric(decimal("-0.01")),
        Err(NumericOperationError::NegativeQuantity)
    );
    let raw = Numeric::try_new_raw(10, 1).expect("representable noncanonical decimal");
    assert_eq!(
        raw.validate_decimal(),
        Err(NumericOperationError::NonCanonical)
    );
    assert_eq!(
        Quantity::try_from_numeric(raw),
        Ok(quantity("1")),
        "the canonicalizing constructor must produce the unique representation"
    );
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for _ in 0..10_000 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let base = state % 1_000_000_000_000;
        let extra_zeroes = u32::try_from((state >> 48) % 7).expect("bounded zero count");
        let base_scale = u32::try_from((state >> 32) % 22).expect("bounded scale");
        let factor = 10_u64.pow(extra_zeroes);
        let encoded = Numeric::try_new_raw(base.saturating_mul(factor), base_scale + extra_zeroes)
            .expect("bounded raw decimal");
        let value = Quantity::try_from_numeric(encoded.clone()).expect("nonnegative sample");
        value
            .as_numeric()
            .validate_decimal()
            .expect("canonical sample");
        assert_eq!(
            encoded.cmp(value.as_numeric()),
            Ordering::Equal,
            "canonicalization must preserve the represented value"
        );
        assert_eq!(
            Quantity::try_from_numeric(value.as_numeric().clone()),
            Ok(value.clone()),
            "canonicalization must be idempotent"
        );
        if value.is_zero() {
            assert_eq!(value.scale(), 0, "zero has one representation");
        }
    }
}
#[test]
fn quantity_arithmetic_is_exact_and_underflow_is_explicit() {
    let lhs = quantity("1.20");
    let rhs = quantity("0.03");
    assert_eq!(lhs.checked_add(&rhs).expect("add").to_string(), "1.23");
    assert_eq!(lhs.checked_sub(&rhs).expect("sub").to_string(), "1.17");
    assert_eq!(
        rhs.checked_sub(&lhs),
        Err(NumericOperationError::QuantityUnderflow)
    );
    assert_eq!(
        lhs.try_mul_decimal(&decimal("-1")),
        Err(NumericOperationError::NegativeQuantity)
    );
    assert_eq!(lhs.try_mul_decimal(&decimal("0.5")), Ok(quantity("0.6")));
    assert_eq!(lhs.try_ratio_exact(&rhs), Ok(decimal("40")));
    let maximum = Quantity::from_canonical_numeric(Numeric::new(signed_maximum(), 0))
        .expect("signed maximum is a quantity");
    assert_eq!(
        maximum.try_mul_decimal(&Numeric::from(2_u32)),
        Err(NumericOperationError::MantissaOverflow)
    );
    assert_eq!(
        maximum.try_mul_decimal(&decimal("-2")),
        Err(NumericOperationError::MantissaOverflow),
        "result-domain overflow precedes the nominal negative-quantity check"
    );
}
#[test]
fn quantity_exact_division_distinguishes_all_failure_classes() {
    assert_eq!(
        quantity("1").try_div_decimal_exact(quantity("8").as_numeric()),
        Ok(quantity("0.125"))
    );
    assert_eq!(
        quantity("1.2").try_div_decimal_exact(quantity("0.03").as_numeric()),
        Ok(quantity("40"))
    );
    assert_eq!(
        quantity("1").try_div_decimal_exact(quantity("3").as_numeric()),
        Err(NumericOperationError::RepeatingDecimal)
    );
    assert_eq!(
        quantity("0.0000000000000000000000000001")
            .try_div_decimal_exact(quantity("10").as_numeric()),
        Err(NumericOperationError::ExactDivisionScaleOverflow)
    );
    assert_eq!(
        quantity("1").try_div_decimal_exact(&Numeric::zero()),
        Err(NumericOperationError::DivisionByZero)
    );
    assert_eq!(
        quantity("1").try_div_decimal_exact(&decimal("-2")),
        Err(NumericOperationError::NegativeQuantity)
    );
}
#[test]
fn quantity_rounded_division_obeys_modes_and_small_domain_invariants() {
    assert_eq!(
        quantity("1").try_div_decimal_round(quantity("8").as_numeric(), 2, RoundingMode::Floor,),
        Ok(quantity("0.12"))
    );
    assert_eq!(
        quantity("1").try_div_decimal_round(quantity("8").as_numeric(), 2, RoundingMode::Ceil,),
        Ok(quantity("0.13"))
    );
    assert_eq!(
        quantity("1").try_div_decimal_round(
            quantity("8").as_numeric(),
            2,
            RoundingMode::NearestEven,
        ),
        Ok(quantity("0.12"))
    );
    assert_eq!(
        quantity("3").try_div_decimal_round(
            quantity("8").as_numeric(),
            2,
            RoundingMode::NearestEven,
        ),
        Ok(quantity("0.38"))
    );
    assert_eq!(
        quantity("1").try_div_decimal_round(quantity("2").as_numeric(), 29, RoundingMode::Floor,),
        Err(NumericOperationError::InvalidScale)
    );
    assert_eq!(
        quantity("1").try_div_decimal_round(&Numeric::zero(), 2, RoundingMode::NearestEven,),
        Err(NumericOperationError::DivisionByZero)
    );
    assert_eq!(
        quantity("1").try_div_decimal_round(&decimal("-2"), 2, RoundingMode::NearestEven),
        Err(NumericOperationError::NegativeQuantity)
    );
    for dividend in 0_u64..=50 {
        for divisor in 1_u64..=20 {
            let dividend = Quantity::from(dividend);
            let divisor = Quantity::from(divisor);
            for scale in 0..=4 {
                let floor = dividend
                    .try_div_decimal_round(divisor.as_numeric(), scale, RoundingMode::Floor)
                    .expect("bounded floor");
                let ceil = dividend
                    .try_div_decimal_round(divisor.as_numeric(), scale, RoundingMode::Ceil)
                    .expect("bounded ceil");
                let nearest = dividend
                    .try_div_decimal_round(divisor.as_numeric(), scale, RoundingMode::NearestEven)
                    .expect("bounded nearest-even");
                for value in [&floor, &ceil, &nearest] {
                    value
                        .as_numeric()
                        .validate_decimal()
                        .expect("rounded quantity remains canonical");
                }
                assert!(floor <= nearest && nearest <= ceil);
                assert!(
                    floor
                        .try_mul_decimal(divisor.as_numeric())
                        .expect("small product")
                        <= dividend
                );
                assert!(
                    ceil.try_mul_decimal(divisor.as_numeric())
                        .expect("small product")
                        >= dividend
                );
            }
        }
    }
}
#[test]
fn quantity_codec_json_and_schema_roundtrip_preserve_invariant() {
    let value: Quantity = "123.4500".parse().expect("quantity");
    assert_eq!(value.to_string(), "123.45");
    let encoded = norito::codec::Encode::encode(&value);
    let (decoded, used) = <Quantity as norito::core::DecodeFromSlice>::decode_from_slice(&encoded)
        .expect("decode quantity");
    assert_eq!(decoded, value);
    assert_eq!(used, encoded.len());
    let mut followed_by_next_field = encoded.clone();
    followed_by_next_field.extend_from_slice(b"next-field");
    let (decoded, used) =
        <Quantity as norito::core::DecodeFromSlice>::decode_from_slice(&followed_by_next_field)
            .expect("decode quantity prefix");
    assert_eq!(decoded, value);
    assert_eq!(used, encoded.len());
    let json = norito::json::to_json(&value).expect("json");
    assert_eq!(json, "\"123.45\"");
    assert_eq!(
        norito::json::from_str::<Quantity>(&json).expect("json decode"),
        value
    );
    assert_eq!(
        norito::json::from_str::<Quantity>(r#""\u003123.45""#).expect("escaped JSON quantity"),
        value
    );
    assert_eq!(
        <Quantity as json::JsonObjectKeyOwned>::from_json_key_text("123.45")
            .expect("quantity map key"),
        value
    );
    let map = std::collections::BTreeMap::from([(value, 1_u8)]);
    let expected_map = r#"{"123.45":1}"#;
    assert_eq!(
        json::to_json_bounded(&map, expected_map.len()).expect("quantity-key map at exact bound"),
        expected_map
    );
    assert!(matches!(
        json::to_json_bounded(&map, expected_map.len() - 1),
        Err(json::BoundedJsonError::BodyTooLarge)
    ));
    for noncanonical in ["+1", "01", "-0", "1.0", "123.4500"] {
        let source = format!("\"{noncanonical}\"");
        assert!(
            norito::json::from_str::<Quantity>(&source).is_err(),
            "alternate quantity spelling must be rejected: {source}"
        );
    }
    let schema = <Quantity as iroha_schema::IntoSchema>::schema();
    assert!(schema.contains_key::<Quantity>());
}
#[test]
fn quantity_json_object_key_map_contract_is_canonical_and_bounded() {
    type Map = std::collections::BTreeMap<Quantity, u8>;
    let quantity: Quantity = "123.45".parse().expect("canonical quantity fixture");
    let map = Map::from([(quantity.clone(), 7)]);
    let expected = r#"{"123.45":7}"#;
    assert_eq!(json::to_json(&map).expect("quantity-key map"), expected);
    assert_eq!(
        json::from_str::<Map>(expected).expect("quantity-key map roundtrip"),
        map
    );
    assert_eq!(
        json::to_json_bounded(&map, expected.len()).expect("exact map bound"),
        expected
    );
    assert!(matches!(
        json::to_json_bounded(&map, expected.len() - 1),
        Err(json::BoundedJsonError::BodyTooLarge)
    ));
    assert_eq!(
        json::from_str::<Map>(r#"{"\u003123.45":7}"#).expect("escaped canonical quantity key"),
        map
    );
    for key in ["+1", "01", "-0", "1.0", "123.4500"] {
        let encoded = format!("{{\"{key}\":7}}");
        assert!(
            json::from_str::<Map>(&encoded).is_err(),
            "noncanonical map key must fail: {encoded}"
        );
    }
    for duplicate in [
        r#"{"123.45":7,"123.45":8}"#,
        r#"{"123.45":7,"\u003123.45":8}"#,
    ] {
        assert!(
            json::from_str::<Map>(duplicate).is_err(),
            "duplicate decoded quantity key must fail: {duplicate}"
        );
    }
}
fn quantity_json_allocation_limits(bytes: usize) -> norito::core::DecodeLimits {
    norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}
fn maximum_scaled_quantity_text() -> String {
    let digits = signed_maximum().to_string();
    let split = digits.len() - MAX_DECIMAL_SCALE as usize;
    let text = format!("{}.{}", &digits[..split], &digits[split..]);
    assert_eq!(text.len(), MAX_CANONICAL_QUANTITY_TEXT_BYTES);
    text
}
struct FixedFormatBuffer {
    bytes: [u8; MAX_CANONICAL_QUANTITY_TEXT_BYTES],
    len: usize,
}
impl FixedFormatBuffer {
    fn new() -> Self {
        Self {
            bytes: [0; MAX_CANONICAL_QUANTITY_TEXT_BYTES],
            len: 0,
        }
    }
    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).expect("formatter emits ASCII")
    }
}
impl core::fmt::Write for FixedFormatBuffer {
    fn write_str(&mut self, value: &str) -> core::fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(core::fmt::Error)?;
        let destination = self.bytes.get_mut(self.len..end).ok_or(core::fmt::Error)?;
        destination.copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}
#[test]
fn quantity_display_formats_the_maximum_without_decode_heap() {
    use core::fmt::Write as _;

    let expected = maximum_scaled_quantity_text();
    let value = Quantity::from_canonical_numeric(Numeric::new(signed_maximum(), MAX_DECIMAL_SCALE))
        .expect("maximum scaled quantity");
    let (formatted, usage) =
        norito::core::with_decode_limits_measured(quantity_json_allocation_limits(0), || {
            let mut output = FixedFormatBuffer::new();
            write!(&mut output, "{value}").expect("stack formatting");
            output
        });
    assert_eq!(formatted.as_str(), expected);
    assert_eq!(usage.total_allocated_bytes(), 0);
}
#[test]
fn borrowed_quantity_json_decode_has_an_exact_allocation_boundary() {
    let source = maximum_scaled_quantity_text();
    let value = json::Value::String(source.clone());
    let expected_allocation =
        MAX_MANTISSA_BYTES.div_ceil(UNBOUNDED_BIGINT_DIGIT_BYTES) * UNBOUNDED_BIGINT_DIGIT_BYTES;
    let (decoded, usage) = norito::core::with_decode_limits_measured(
        quantity_json_allocation_limits(expected_allocation),
        || <Quantity as JsonDeserialize>::json_from_value(&value),
    );
    assert_eq!(decoded.expect("exact borrowed budget").to_string(), source);
    assert_eq!(usage.total_allocated_bytes(), expected_allocation);

    let (rejected, usage) = norito::core::with_decode_limits_measured(
        quantity_json_allocation_limits(expected_allocation - 1),
        || <Quantity as JsonDeserialize>::json_from_value(&value),
    );
    assert!(matches!(
        rejected,
        Err(json::Error::DecodeResource(
            norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
        ))
    ));
    assert_eq!(usage.total_allocated_bytes(), 0);
}
#[test]
fn quantity_native_digit_decode_matches_reference_at_capacity_boundaries() {
    for length in [1, 4, 8, 9, 16, 31, 32, 63, MAX_MANTISSA_BYTES] {
        let mut bytes = vec![0xa5_u8; length];
        if length == MAX_MANTISSA_BYTES {
            bytes[length - 1] = 0x7f;
        }
        let expected_allocation =
            length.div_ceil(UNBOUNDED_BIGINT_DIGIT_BYTES) * UNBOUNDED_BIGINT_DIGIT_BYTES;
        let (decoded, usage) = norito::core::with_decode_limits_measured(
            quantity_json_allocation_limits(expected_allocation),
            || quantity_mantissa_from_canonical_le_bytes(&bytes),
        );
        let reference = UnboundedBigInt::from_bytes_le(UnboundedSign::Plus, &bytes);
        assert_eq!(
            decoded.expect("canonical magnitude"),
            BigInt::from_inner(reference).unwrap()
        );
        assert_eq!(usage.total_allocated_bytes(), expected_allocation);
    }
}
#[test]
#[allow(unsafe_code)]
fn quantity_native_digit_decode_rejects_before_allocation_and_reports_allocator_refusal() {
    for invalid in [&[][..], &[0_u8][..], &[1_u8, 0_u8][..], &[0x80_u8; 64][..]] {
        let (result, usage) = norito::core::with_decode_limits_measured(
            quantity_json_allocation_limits(usize::MAX),
            || {
                // SAFETY: this callback panics if called, and validation
                // must reject before it can supply any pointer.
                unsafe {
                    quantity_mantissa_from_canonical_le_bytes_with::<json::Error>(invalid, |_| {
                        panic!("invalid magnitude must not allocate")
                    })
                }
            },
        );
        assert!(result.is_err());
        assert_eq!(usage.total_allocated_bytes(), 0);
    }
    let expected_allocation = UNBOUNDED_BIGINT_DIGIT_BYTES;
    let (rejected, usage) = norito::core::with_decode_limits_measured(
        quantity_json_allocation_limits(expected_allocation - 1),
        || {
            // SAFETY: this callback panics if called, and the budget
            // must reject before it can supply any pointer.
            unsafe {
                quantity_mantissa_from_canonical_le_bytes_with::<json::Error>(&[1], |_| {
                    panic!("budget refusal must precede allocation")
                })
            }
        },
    );
    assert!(matches!(
        rejected,
        Err(json::Error::DecodeResource(
            norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
        ))
    ));
    assert_eq!(usage.total_allocated_bytes(), 0);

    let (rejected, usage) = norito::core::with_decode_limits_measured(
        quantity_json_allocation_limits(expected_allocation),
        || {
            // SAFETY: null is an explicitly permitted allocation refusal.
            unsafe {
                quantity_mantissa_from_canonical_le_bytes_with(&[1], |_| {
                    Ok::<_, json::Error>(core::ptr::null_mut())
                })
            }
        },
    );
    assert!(matches!(rejected, Err(json::Error::AllocationFailed)));
    assert_eq!(usage.total_allocated_bytes(), expected_allocation);
}
#[test]
fn owned_quantity_json_decode_charges_text_and_final_storage_exactly() {
    let quantity = maximum_scaled_quantity_text();
    let source = format!(r#""{quantity}""#);
    let final_allocation =
        MAX_MANTISSA_BYTES.div_ceil(UNBOUNDED_BIGINT_DIGIT_BYTES) * UNBOUNDED_BIGINT_DIGIT_BYTES;
    let exact = quantity.len() + final_allocation;
    let (decoded, usage) =
        norito::core::with_decode_limits_measured(quantity_json_allocation_limits(exact), || {
            norito::json::from_str::<Quantity>(&source)
        });
    assert_eq!(decoded.expect("exact owned budget").to_string(), quantity);
    assert_eq!(usage.total_allocated_bytes(), exact);

    let (rejected, usage) = norito::core::with_decode_limits_measured(
        quantity_json_allocation_limits(exact - 1),
        || norito::json::from_str::<Quantity>(&source),
    );
    assert!(matches!(
        rejected,
        Err(json::Error::DecodeResource(
            norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
        ))
    ));
    assert_eq!(usage.total_allocated_bytes(), quantity.len());
}
#[test]
fn quantity_json_rejects_text_and_signed_domain_overflow_before_allocation() {
    let overlong = json::Value::String("1".repeat(MAX_CANONICAL_QUANTITY_TEXT_BYTES + 1));
    let signed_overflow =
        json::Value::String((ReferenceInt::one() << (MAX_MANTISSA_BITS - 1)).to_string());
    for value in [&overlong, &signed_overflow] {
        let (decoded, usage) = norito::core::with_decode_limits_measured(
            quantity_json_allocation_limits(usize::MAX),
            || <Quantity as JsonDeserialize>::json_from_value(value),
        );
        assert!(decoded.is_err());
        assert_eq!(usage.total_allocated_bytes(), 0);
    }
}
#[test]
fn small_domain_arithmetic_matches_integer_reference_exhaustively() {
    for lhs in -100_i64..=100 {
        for rhs in -100_i64..=100 {
            let lhs_decimal = Numeric::from(lhs);
            let rhs_decimal = Numeric::from(rhs);
            assert_eq!(
                lhs_decimal.try_decimal_add(&rhs_decimal),
                Ok(Numeric::from(lhs + rhs))
            );
            assert_eq!(
                lhs_decimal.try_decimal_sub(&rhs_decimal),
                Ok(Numeric::from(lhs - rhs))
            );
            assert_eq!(
                lhs_decimal.try_decimal_mul(&rhs_decimal),
                Ok(Numeric::from(lhs * rhs))
            );
            if rhs != 0 && lhs % rhs == 0 {
                assert_eq!(
                    lhs_decimal.try_decimal_div_exact(&rhs_decimal),
                    Ok(Numeric::from(lhs / rhs))
                );
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct ReferenceDecimal {
    mantissa: ReferenceInt,
    scale: u32,
}
impl ReferenceDecimal {
    fn read(value: &Numeric) -> Self {
        Self {
            mantissa: value
                .mantissa()
                .to_string()
                .parse()
                .expect("bounded mantissa parses as num_bigint::BigInt"),
            scale: value.scale(),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReferenceExactClass {
    Representable { minimum_scale: u8 },
    Repeating,
    ScaleOverflow,
}
fn reference_pow10(exponent: u32) -> ReferenceInt {
    ReferenceInt::from(10_u8).pow(exponent)
}
fn reference_normalize(
    mut mantissa: ReferenceInt,
    mut scale: u32,
) -> Result<ReferenceDecimal, NumericOperationError> {
    if mantissa.is_zero() {
        return Ok(ReferenceDecimal { mantissa, scale: 0 });
    }
    let ten = ReferenceInt::from(10_u8);
    while scale > 0 && (&mantissa % &ten).is_zero() {
        mantissa /= &ten;
        scale -= 1;
    }
    if scale > MAX_DECIMAL_SCALE {
        return Err(NumericOperationError::ScaleOverflow);
    }
    let signed_limit = ReferenceInt::one() << (MAX_MANTISSA_BITS - 1);
    if mantissa < -signed_limit.clone() || mantissa >= signed_limit {
        return Err(NumericOperationError::MantissaOverflow);
    }
    Ok(ReferenceDecimal { mantissa, scale })
}
fn reference_add_or_sub(
    lhs: &ReferenceDecimal,
    rhs: &ReferenceDecimal,
    subtract: bool,
) -> Result<ReferenceDecimal, NumericOperationError> {
    let scale = lhs.scale.max(rhs.scale);
    let lhs_aligned = &lhs.mantissa * reference_pow10(scale - lhs.scale);
    let rhs_aligned = &rhs.mantissa * reference_pow10(scale - rhs.scale);
    let mantissa = if subtract {
        lhs_aligned - rhs_aligned
    } else {
        lhs_aligned + rhs_aligned
    };
    reference_normalize(mantissa, scale)
}
fn reference_multiply(
    lhs: &ReferenceDecimal,
    rhs: &ReferenceDecimal,
) -> Result<ReferenceDecimal, NumericOperationError> {
    reference_normalize(&lhs.mantissa * &rhs.mantissa, lhs.scale + rhs.scale)
}
fn reference_gcd(mut lhs: ReferenceInt, mut rhs: ReferenceInt) -> ReferenceInt {
    lhs = lhs.abs();
    rhs = rhs.abs();
    while !rhs.is_zero() {
        let remainder = &lhs % &rhs;
        lhs = rhs;
        rhs = remainder;
    }
    lhs
}
fn reference_reduced_ratio(
    lhs: &ReferenceDecimal,
    rhs: &ReferenceDecimal,
) -> Result<(ReferenceInt, ReferenceInt), NumericOperationError> {
    if rhs.mantissa.is_zero() {
        return Err(NumericOperationError::DivisionByZero);
    }
    // This is a direct rational construction: (lm / 10^ls) /
    // (rm / 10^rs) = (lm * 10^rs) / (rm * 10^ls). It intentionally does
    // not use any Numeric division, scale-alignment, or classification
    // helper.
    let mut numerator = &lhs.mantissa * reference_pow10(rhs.scale);
    let mut denominator = &rhs.mantissa * reference_pow10(lhs.scale);
    if denominator.is_negative() {
        numerator = -numerator;
        denominator = -denominator;
    }
    let gcd = reference_gcd(numerator.clone(), denominator.clone());
    Ok((numerator / &gcd, denominator / gcd))
}
fn reference_exact_class(
    lhs: &ReferenceDecimal,
    rhs: &ReferenceDecimal,
) -> Result<ReferenceExactClass, NumericOperationError> {
    let (_, mut denominator) = reference_reduced_ratio(lhs, rhs)?;
    let mut factors_two = 0_u32;
    let mut factors_five = 0_u32;
    for (factor, count) in [
        (ReferenceInt::from(2_u8), &mut factors_two),
        (ReferenceInt::from(5_u8), &mut factors_five),
    ] {
        while (&denominator % &factor).is_zero() {
            denominator /= &factor;
            *count += 1;
        }
    }
    if denominator != ReferenceInt::one() {
        return Ok(ReferenceExactClass::Repeating);
    }
    let minimum_scale = factors_two.max(factors_five);
    if minimum_scale > MAX_DECIMAL_SCALE {
        return Ok(ReferenceExactClass::ScaleOverflow);
    }
    Ok(ReferenceExactClass::Representable {
        minimum_scale: u8::try_from(minimum_scale).expect("reference scale is at most 28"),
    })
}
fn reference_exact_divide(
    lhs: &ReferenceDecimal,
    rhs: &ReferenceDecimal,
) -> Result<ReferenceDecimal, NumericOperationError> {
    let class = reference_exact_class(lhs, rhs)?;
    let ReferenceExactClass::Representable { minimum_scale } = class else {
        return Err(match class {
            ReferenceExactClass::Repeating => NumericOperationError::RepeatingDecimal,
            ReferenceExactClass::ScaleOverflow => NumericOperationError::ExactDivisionScaleOverflow,
            ReferenceExactClass::Representable { .. } => unreachable!(),
        });
    };
    let (numerator, denominator) = reference_reduced_ratio(lhs, rhs)?;
    let scaled = numerator * reference_pow10(u32::from(minimum_scale));
    let quotient = &scaled / &denominator;
    assert!(
        (&scaled % &denominator).is_zero(),
        "independent classification must prove exact divisibility"
    );
    reference_normalize(quotient, u32::from(minimum_scale))
}
fn reference_rounded_divide(
    lhs: &ReferenceDecimal,
    rhs: &ReferenceDecimal,
    output_scale: u32,
    mode: RoundingMode,
) -> Result<ReferenceDecimal, NumericOperationError> {
    if output_scale > MAX_DECIMAL_SCALE {
        return Err(NumericOperationError::InvalidScale);
    }
    let (numerator, denominator) = reference_reduced_ratio(lhs, rhs)?;
    let scaled = numerator * reference_pow10(output_scale);
    let magnitude = scaled.abs();
    let mut quotient = &magnitude / &denominator;
    let remainder = &magnitude % &denominator;
    let negative = scaled.is_negative();
    let increment = if remainder.is_zero() {
        false
    } else {
        match mode {
            RoundingMode::TowardZero => false,
            RoundingMode::AwayFromZero => true,
            RoundingMode::Floor => negative,
            RoundingMode::Ceil => !negative,
            RoundingMode::NearestEven
            | RoundingMode::NearestAway
            | RoundingMode::NearestTowardZero => {
                match (&remainder * ReferenceInt::from(2_u8)).cmp(&denominator) {
                    Ordering::Less => false,
                    Ordering::Greater => true,
                    Ordering::Equal => match mode {
                        RoundingMode::NearestEven => {
                            !(&quotient % ReferenceInt::from(2_u8)).is_zero()
                        }
                        RoundingMode::NearestAway => true,
                        RoundingMode::NearestTowardZero => false,
                        _ => unreachable!("matched a nearest rounding mode"),
                    },
                }
            }
        }
    };
    if increment {
        quotient += ReferenceInt::one();
    }
    if negative {
        quotient = -quotient;
    }
    reference_normalize(quotient, output_scale)
}
fn reference_result(
    result: Result<Numeric, NumericOperationError>,
) -> Result<ReferenceDecimal, NumericOperationError> {
    result.map(|value| ReferenceDecimal::read(&value))
}
fn reference_class_result(
    result: Result<ExactDivisionClass, NumericOperationError>,
) -> Result<ReferenceExactClass, NumericOperationError> {
    result.map(|class| match class {
        ExactDivisionClass::Representable { minimum_scale } => {
            ReferenceExactClass::Representable { minimum_scale }
        }
        ExactDivisionClass::Repeating => ReferenceExactClass::Repeating,
        ExactDivisionClass::ScaleOverflow => ReferenceExactClass::ScaleOverflow,
    })
}
#[test]
fn randomized_decimal_arithmetic_matches_independent_rational_reference() {
    const ROUNDING_MODES: [RoundingMode; 7] = [
        RoundingMode::TowardZero,
        RoundingMode::AwayFromZero,
        RoundingMode::Floor,
        RoundingMode::Ceil,
        RoundingMode::NearestEven,
        RoundingMode::NearestAway,
        RoundingMode::NearestTowardZero,
    ];
    // Fixed xorshift seed makes failures reproducible without coupling the
    // oracle to a random-number crate or host entropy.
    let mut random = 0x6a09_e667_f3bc_c909_u64;
    let mut next = || {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        random
    };
    for case in 0..2_048 {
        let lhs_mantissa = i64::try_from(next() % 2_000_001).expect("bounded sample") - 1_000_000;
        let rhs_mantissa = i64::try_from(next() % 2_000_001).expect("bounded sample") - 1_000_000;
        let lhs_scale = u32::try_from(next() % 29).expect("bounded scale");
        let rhs_scale = u32::try_from(next() % 29).expect("bounded scale");
        let output_scale = u32::try_from(next() % 29).expect("bounded scale");
        let lhs = Numeric::new(lhs_mantissa, lhs_scale);
        let rhs = Numeric::new(rhs_mantissa, rhs_scale);
        let lhs_reference = ReferenceDecimal::read(&lhs);
        let rhs_reference = ReferenceDecimal::read(&rhs);
        let context = format!("case={case}, lhs={lhs}, rhs={rhs}, output_scale={output_scale}");
        assert_eq!(
            reference_result(lhs.try_decimal_add(&rhs)),
            reference_add_or_sub(&lhs_reference, &rhs_reference, false),
            "add: {context}"
        );
        assert_eq!(
            reference_result(lhs.try_decimal_sub(&rhs)),
            reference_add_or_sub(&lhs_reference, &rhs_reference, true),
            "subtract: {context}"
        );
        assert_eq!(
            reference_result(lhs.try_decimal_mul(&rhs)),
            reference_multiply(&lhs_reference, &rhs_reference),
            "multiply: {context}"
        );
        assert_eq!(
            reference_class_result(lhs.classify_exact_division(&rhs)),
            reference_exact_class(&lhs_reference, &rhs_reference),
            "exact classification: {context}"
        );
        assert_eq!(
            reference_result(lhs.try_decimal_div_exact(&rhs)),
            reference_exact_divide(&lhs_reference, &rhs_reference),
            "exact division: {context}"
        );
        for mode in ROUNDING_MODES {
            assert_eq!(
                reference_result(lhs.try_decimal_div_round(&rhs, output_scale, mode)),
                reference_rounded_divide(&lhs_reference, &rhs_reference, output_scale, mode,),
                "rounded division ({mode:?}): {context}"
            );
        }
    }
}
#[allow(clippy::too_many_lines)] // The full-width matrix stays together so its corpus cannot drift between helpers.
#[test]
fn full_width_decimal_arithmetic_matches_independent_rational_reference() {
    const ROUNDING_MODES: [RoundingMode; 7] = [
        RoundingMode::TowardZero,
        RoundingMode::AwayFromZero,
        RoundingMode::Floor,
        RoundingMode::Ceil,
        RoundingMode::NearestEven,
        RoundingMode::NearestAway,
        RoundingMode::NearestTowardZero,
    ];
    fn numeric_from_reference(mantissa: &ReferenceInt, scale: u32) -> Numeric {
        let bounded = mantissa
            .to_string()
            .parse::<BigInt>()
            .expect("edge-biased reference mantissa fits the generic bigint domain");
        Numeric::try_new(bounded, scale)
            .expect("edge-biased input is canonicalizable in the V1 domain")
    }
    let signed_limit = ReferenceInt::one() << (MAX_MANTISSA_BITS - 1);
    let maximum = &signed_limit - ReferenceInt::one();
    let minimum = -signed_limit;
    let powers = [63_usize, 64, 127, 128, 255, 256, 447, 448, 510];
    let mut mantissas = vec![
        ReferenceInt::zero(),
        ReferenceInt::one(),
        -ReferenceInt::one(),
        maximum.clone(),
        minimum.clone(),
        &maximum - ReferenceInt::from(8_u8),
        &minimum + ReferenceInt::from(9_u8),
    ];
    for bit in powers {
        let power = ReferenceInt::one() << bit;
        mantissas.extend([
            &power - ReferenceInt::one(),
            power.clone(),
            &power + ReferenceInt::one(),
            -&power - ReferenceInt::one(),
            -power.clone(),
            -power + ReferenceInt::one(),
        ]);
    }
    let divisors = [
        ReferenceInt::zero(),
        ReferenceInt::from(2_u8),
        ReferenceInt::from(-2_i8),
        ReferenceInt::from(5_u8),
        ReferenceInt::from(25_u8),
        ReferenceInt::from(3_u8),
        ReferenceInt::from(-7_i8),
        (ReferenceInt::one() << 255) + ReferenceInt::one(),
    ];
    let scales = [0_u32, 1, 27, 28];
    let output_scales = [0_u32, 1, 27, 28];
    let mut case = 0_usize;
    for (index, lhs_mantissa) in mantissas.iter().enumerate() {
        let rhs_mantissa = if index % 3 == 0 {
            &mantissas[mantissas.len() - 1 - index]
        } else {
            &divisors[index % divisors.len()]
        };
        for &lhs_scale in &scales {
            let rhs_scale =
                scales[(index + usize::try_from(lhs_scale).unwrap_or(0)) % scales.len()];
            let lhs = numeric_from_reference(lhs_mantissa, lhs_scale);
            let rhs = numeric_from_reference(rhs_mantissa, rhs_scale);
            let lhs_reference = ReferenceDecimal::read(&lhs);
            let rhs_reference = ReferenceDecimal::read(&rhs);
            let context = format!(
                "case={case}, lhs={lhs}, rhs={rhs}, lhs_scale={lhs_scale}, rhs_scale={rhs_scale}"
            );
            assert_eq!(
                reference_result(lhs.try_decimal_add(&rhs)),
                reference_add_or_sub(&lhs_reference, &rhs_reference, false),
                "add: {context}"
            );
            assert_eq!(
                reference_result(lhs.try_decimal_sub(&rhs)),
                reference_add_or_sub(&lhs_reference, &rhs_reference, true),
                "subtract: {context}"
            );
            assert_eq!(
                reference_result(lhs.try_decimal_mul(&rhs)),
                reference_multiply(&lhs_reference, &rhs_reference),
                "multiply: {context}"
            );
            assert_eq!(
                reference_class_result(lhs.classify_exact_division(&rhs)),
                reference_exact_class(&lhs_reference, &rhs_reference),
                "exact classification: {context}"
            );
            assert_eq!(
                reference_result(lhs.try_decimal_div_exact(&rhs)),
                reference_exact_divide(&lhs_reference, &rhs_reference),
                "exact division: {context}"
            );
            for &output_scale in &output_scales {
                for mode in ROUNDING_MODES {
                    assert_eq!(
                        reference_result(lhs.try_decimal_div_round(&rhs, output_scale, mode),),
                        reference_rounded_divide(
                            &lhs_reference,
                            &rhs_reference,
                            output_scale,
                            mode,
                        ),
                        "rounded division ({mode:?}, scale={output_scale}): {context}"
                    );
                }
            }
            case += 1;
        }
    }
    assert!(case >= 200, "full-width corpus unexpectedly shrank");
}

#[test]
fn manual_decode_numeric_spec_returns_missing_context_and_retries_same_payload() {
    use norito::core::{
        DecodeFlagsGuard, PayloadCtxGuard, archived_from_slice, serialize_to_buffer,
    };
    let _layout = DecodeFlagsGuard::enter(0);
    for expected in [NumericSpec::unconstrained(), NumericSpec::fractional(5)] {
        let mut bytes = Vec::new();
        serialize_to_buffer(&expected, &mut bytes).unwrap();
        let archived = archived_from_slice::<u8>(&bytes).unwrap();
        let missing = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            NumericSpec::try_deserialize(archived.archived().cast())
        }));
        assert!(
            matches!(missing, Ok(Err(Error::MissingPayloadContext))),
            "fallible NumericSpec decoder must return the missing-context error, not panic"
        );
        let decoded = {
            let _payload = PayloadCtxGuard::enter(archived.bytes());
            NumericSpec::try_deserialize(archived.archived().cast()).unwrap()
        };
        assert_eq!(decoded, expected);
        let mut repeated = Vec::new();
        serialize_to_buffer(&decoded, &mut repeated).unwrap();
        assert_eq!(repeated, bytes);
    }
    let invalid = NumericSpec {
        scale: Some(MAX_DECIMAL_SCALE + 1),
    };
    let mut bytes = Vec::new();
    serialize_to_buffer(&invalid, &mut bytes).unwrap();
    let archived = archived_from_slice::<u8>(&bytes).unwrap();
    let _payload = PayloadCtxGuard::enter(archived.bytes());
    assert!(matches!(
        NumericSpec::try_deserialize(archived.archived().cast()),
        Err(Error::Message(_))
    ));
}
