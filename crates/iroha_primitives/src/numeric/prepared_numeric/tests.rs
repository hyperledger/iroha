//! Captured decimal semantics and exact original-pool leaf controls.

use super::*;
use norito::core::{DecodeBudgetContext, DecodeLimits};
use num_traits::One as _;

// Exact previous FromStr algorithm, test-only. Production ordinary/admitted
// decoding shares scan_decimal and never routes through this allocating oracle.
fn captured(source: &str) -> Result<Numeric, NumericError> {
    let trimmed = source.trim();
    if trimmed.is_empty() {
        return Err(NumericError::Malformed);
    }
    let (negative, digits) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    let mut scale = 0_u32;
    let mut mantissa_str = String::new();
    let mut seen_dot = false;
    for ch in digits.chars() {
        if ch == '.' {
            if seen_dot {
                return Err(NumericError::Malformed);
            }
            seen_dot = true;
            continue;
        }
        if !ch.is_ascii_digit() {
            return Err(NumericError::Malformed);
        }
        mantissa_str.push(ch);
        if seen_dot {
            scale = scale.saturating_add(1);
        }
    }
    while scale > 0 && mantissa_str.ends_with('0') {
        mantissa_str.pop();
        scale -= 1;
    }
    if mantissa_str.is_empty() {
        return Err(NumericError::Malformed);
    }
    if mantissa_str.bytes().all(|byte| byte == b'0') {
        return Ok(Numeric::zero());
    }
    if negative {
        mantissa_str.insert(0, '-');
    }
    let unbounded = mantissa_str
        .parse::<UnboundedBigInt>()
        .map_err(|_| NumericError::Malformed)?;
    let mantissa = BigInt::from_inner(unbounded).map_err(|_| NumericError::MantissaTooLarge)?;
    Numeric::try_new(mantissa, scale)
}
fn compare(source: &str) {
    let expected = captured(source);
    assert_eq!(source.parse::<Numeric>(), expected, "ordinary {source}");
    let budget = AllocationBudget::new(1 << 16);
    match (ChargedNumeric::try_from_decimal(source, &budget), expected) {
        (Ok(actual), Ok(expected)) => {
            assert_eq!(actual.get(), &expected, "{source}");
            assert!(actual.belongs_to(&budget));
            assert_eq!(
                actual.charge.layout(),
                expected.admission_clone_layout().unwrap()
            );
            assert_eq!(budget.reserved_bytes(), actual.charge.layout().size());
            assert_eq!(
                norito::to_bytes(actual.get()).unwrap(),
                norito::to_bytes(&expected).unwrap()
            );
            drop(actual);
        }
        (Err(NumericDecimalAdmissionError::Numeric(actual)), Err(expected)) => {
            assert_eq!(actual, expected, "{source}")
        }
        (actual, expected) => panic!("semantic mismatch for {source}: {actual:?}, {expected:?}"),
    }
    assert_eq!(budget.reserved_bytes(), 0);
}
fn limits(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}

#[test]
fn admitted_numeric_reuses_complete_ordinary_syntax_and_normalization_relation() {
    for source in [
        "",
        " ",
        ".",
        ".0",
        ".000",
        "0.",
        ".01",
        "+1",
        "-1",
        "-0",
        "-0.000",
        "0000.00",
        "0012.3400",
        " +.1250 ",
        "\u{2003}-001.2500\u{2003}",
        "1e2",
        "1E2",
        "1_000",
        "1 0",
        "1..0",
        "--1",
        "++1",
        "+-1",
        "-+1",
        "１",
        "NaN",
        "inf",
    ] {
        compare(source);
    }
    compare(&format!("{}1.{}", "0".repeat(10_000), "0".repeat(10_000)));
    compare(&format!("0.{}", "0".repeat(10_000)));
    compare(&format!(".{}", "0".repeat(10_000)));
}

#[test]
fn admitted_numeric_keeps_signed_endpoints_and_original_width_scale_error_precedence() {
    let numeric_limit = UnboundedBigInt::one() << 511_usize;
    let generic_limit = UnboundedBigInt::one() << 4095_usize;
    for value in [
        &numeric_limit - 1_u8,
        numeric_limit.clone(),
        -&numeric_limit,
        -&numeric_limit - 1_u8,
        &generic_limit - 1_u8,
        generic_limit.clone(),
        -&generic_limit,
        -&generic_limit - 1_u8,
    ] {
        for suffix in ["", ".0", ".0000", ".00000000000000000000000000001"] {
            compare(&format!("{value}{suffix}"));
        }
    }
    // Generic width is checked before scale; Numeric width is checked after scale.
    assert_eq!(
        captured(&format!(
            "{}.{}1",
            UnboundedBigInt::one() << 600_usize,
            "0".repeat(28)
        )),
        Err(NumericError::ScaleTooLarge)
    );
    assert_eq!(
        captured(&format!(
            "{}.{}1",
            UnboundedBigInt::one() << 4096_usize,
            "0".repeat(28)
        )),
        Err(NumericError::MantissaTooLarge)
    );
    let huge = "9".repeat(2_000);
    compare(&format!("{huge}bad"));
    compare(&format!("{huge}.1.0"));
    compare(&format!("{huge}.{}", "0".repeat(32)));
}

#[test]
fn admitted_numeric_captured_generated_corpus_preserves_every_normalized_value() {
    let mut state = 0x72A4_19C3_8E06_D5B1_u64;
    for _ in 0..128 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let fraction = state % 10_000_000;
        let sign = if state & 1 == 0 { "+" } else { "-" };
        compare(&format!(" {sign}000{state}.{fraction:07}000 "));
    }
}

#[test]
fn admitted_numeric_exact_backing_refusal_and_same_source_retry_preserve_pool_identity() {
    for source in [
        "1",
        "-12.5",
        "1234567890123456789012345678901234567890.0001",
    ] {
        let expected = captured(source).unwrap();
        let bytes = expected.admission_clone_layout().unwrap().size();
        assert!(bytes > 0);
        let budget = AllocationBudget::new(bytes - 1);
        assert!(matches!(
            ChargedNumeric::try_from_decimal(source, &budget),
            Err(NumericDecimalAdmissionError::Allocation(
                ChargedBufferError::Admission(_)
            ))
        ));
        assert_eq!(budget.reserved_bytes(), 0);
        budget.set_limit_bytes(bytes);
        let owner = ChargedNumeric::try_from_decimal(source, &budget).unwrap();
        let foreign = AllocationBudget::new(bytes);
        assert!(owner.belongs_to(&budget));
        assert!(!owner.belongs_to(&foreign));
        assert_eq!(owner.get(), &expected);
        assert_eq!(budget.reserved_bytes(), bytes);
        assert_eq!(budget.peak_reserved_bytes(), bytes);
        drop(owner);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn admitted_numeric_zero_requires_no_backing_and_keeps_same_pool_marker() {
    let budget = AllocationBudget::new(0);
    let foreign = AllocationBudget::new(0);
    for source in [
        "0",
        "-0",
        "+000.000",
        "0.0000000000000000000000000000000000",
    ] {
        let owner = ChargedNumeric::try_from_decimal(source, &budget).unwrap();
        assert!(owner.get().is_zero());
        assert_eq!(owner.get().scale(), 0);
        assert!(owner.belongs_to(&budget));
        assert!(!owner.belongs_to(&foreign));
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(budget.peak_reserved_bytes(), 0);
    }
}

#[test]
fn admitted_numeric_cumulative_decoder_refusal_precedes_physical_pool_admission() {
    let source = "123456789012345678901234567890.125";
    let expected = captured(source).unwrap();
    let bytes = expected.admission_clone_layout().unwrap().size();
    let pool = AllocationBudget::new(bytes * 2);
    let context = DecodeBudgetContext::new(limits(bytes));
    let first = context
        .with(|| ChargedNumeric::try_from_decimal(source, &pool))
        .unwrap();
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(bytes).unwrap()
    );
    let mut original_scope = None;
    let attempt = context
        .with(|| {
            norito::core::classify_decode_attempt(|| {
                ChargedNumeric::try_from_decimal(source, &pool).map_err(|error| {
                    let NumericDecimalAdmissionError::Decode(error) = error else {
                        panic!("original decoder refusal must remain typed");
                    };
                    let norito::Error::ScopedDecodeResource(scope) = &error else {
                        panic!("native digit decoder must preserve original scope: {error:?}");
                    };
                    original_scope = Some(scope.clone());
                    error
                })
            })
        })
        .unwrap_err();
    assert_eq!(
        attempt.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    let retained = attempt.into_local_refusal().unwrap().into_error();
    let norito::Error::ScopedDecodeResource(scope) = &retained else {
        panic!("retained exact original decoder identity");
    };
    assert_eq!(scope, &original_scope.unwrap());
    let replay = norito::core::classify_decode_attempt::<()>(|| Err(retained)).unwrap_err();
    assert_eq!(replay.kind(), norito::core::DecodeAttemptErrorKind::Invalid);
    assert!(replay.local_refusal().is_none());
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(bytes).unwrap()
    );
    assert_eq!(pool.reserved_bytes(), bytes);
    assert_eq!(pool.peak_reserved_bytes(), bytes);
    drop(first);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn admitted_numeric_invalid_source_never_spends_decoder_or_pool_credit() {
    let pool = AllocationBudget::new(0);
    let context = DecodeBudgetContext::new(limits(0));
    for source in ["", ".0", "1..2", "1e3", "0.00000000000000000000000000001"] {
        let error = context
            .with(|| ChargedNumeric::try_from_decimal(source, &pool))
            .unwrap_err();
        assert!(matches!(error, NumericDecimalAdmissionError::Numeric(_)));
        assert_eq!(pool.reserved_bytes(), 0);
        assert_eq!(context.consumed_allocated_bytes(), 0);
    }
}
