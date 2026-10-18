//! Active depth custody for conversion from already-owned JSON values.

use super::*;
use crate::core::{
    DecodeAttemptErrorKind, DecodeLimits, DecodeResourceError, classify_decode_attempt,
    with_decode_limits_measured, with_decode_limits_scope,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

fn depth_limits(depth: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, depth)
}

fn assert_depth_error(error: Error, depth: usize, limit: usize) {
    assert_eq!(
        error.into_core_error().decode_resource_error(),
        Some(DecodeResourceError::NestingDepthExceeded {
            depth,
            limit,
            context: "decode budget",
        })
    );
}

fn assert_native_value_limits<T: JsonDeserialize + std::fmt::Debug + PartialEq>(
    input: &str,
    expected: &T,
    depth: usize,
) {
    let value = parse_value(input).expect("existing input value");
    assert_eq!(
        &with_decode_limits_scope(depth_limits(depth), || T::json_from_value(&value))
            .expect("exact direct value depth"),
        expected
    );
    let owned = value.clone();
    assert_eq!(
        &with_decode_limits_scope(depth_limits(depth), || from_value::<T>(owned))
            .expect("exact owned entry depth"),
        expected
    );
    let short = depth.checked_sub(1).expect("nested fixture");
    assert_depth_error(
        with_decode_limits_scope(depth_limits(short), || T::json_from_value(&value))
            .expect_err("direct native conversion must retain complete input depth"),
        depth,
        short,
    );
    let owned = value.clone();
    assert_depth_error(
        with_decode_limits_scope(depth_limits(short), || from_value::<T>(owned))
            .expect_err("owned entry must retain complete input depth"),
        depth,
        short,
    );
}

#[test]
fn native_value_and_aggregate_conversions_enforce_exact_and_short_depth() {
    assert_native_value_limits("[[7]]", &parse_value("[[7]]").unwrap(), 2);
    let branches = r#"[[],7,{"z":[8]},[9]]"#;
    assert_native_value_limits(branches, &parse_value(branches).unwrap(), 3);
    assert_native_value_limits("[[7]]", &vec![vec![7_u64]], 2);
    assert_native_value_limits("[[7]]", &BTreeSet::from([vec![7_u64]]), 2);
    assert_native_value_limits("[[7]]", &HashSet::from([vec![7_u64]]), 2);
    assert_native_value_limits(
        r#"{"key":[7]}"#,
        &BTreeMap::from([(String::from("key"), vec![7_u64])]),
        2,
    );
    assert_native_value_limits(
        r#"{"key":[7]}"#,
        &HashMap::from([(String::from("key"), vec![7_u64])]),
        2,
    );
}

#[derive(Debug, PartialEq, norito_derive::JsonDeserialize)]
struct DerivedValue {
    nested: Vec<Vec<u64>>,
}

#[test]
fn default_value_fallback_and_transparent_owners_preserve_complete_depth() {
    assert_native_value_limits(
        r#"{"nested":[[7]]}"#,
        &DerivedValue {
            nested: vec![vec![7]],
        },
        3,
    );
    assert_native_value_limits("[[7]]", &Some(Box::new(vec![vec![7_u64]])), 2);
    let value = parse_value("[[7]]").unwrap();
    let limits = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 1);
    let (result, usage) =
        with_decode_limits_measured(limits, || Box::<Vec<Vec<u64>>>::json_from_value(&value));
    assert_depth_error(
        result.expect_err("depth must refuse before Box reservation"),
        2,
        1,
    );
    assert_eq!(usage.total_allocated_bytes(), 0);
}

#[derive(Debug)]
struct CustomValue;
impl JsonDeserialize for CustomValue {
    fn json_deserialize(_parser: &mut Parser<'_>) -> Result<Self, Error> {
        Ok(Self)
    }
    fn json_from_value(_value: &Value) -> Result<Self, Error> {
        Ok(Self)
    }
}

#[test]
fn public_value_entry_cannot_delegate_around_the_original_depth_limit() {
    let value = parse_value("[[7]]").unwrap();
    let error = with_decode_limits_scope(depth_limits(1), || from_value::<CustomValue>(value))
        .expect_err("custom overrides run only after original input admission");
    assert_depth_error(error, 2, 1);
}

#[test]
fn public_value_refusal_dismantles_deep_owned_input_iteratively() {
    let mut value = Value::Null;
    for _ in 0..8_192 {
        value = Value::Array(vec![value]);
    }
    assert!(matches!(
        from_value::<CustomValue>(value),
        Err(Error::NestingDepthExceeded {
            depth,
            limit: MAX_JSON_VALUE_NESTING_DEPTH,
            context: "JSON value",
        }) if depth == MAX_JSON_VALUE_NESTING_DEPTH + 1
    ));
}

#[test]
fn value_depth_admission_keeps_empty_roots_and_string_contents_at_zero() {
    for input in ["7", "null", "[]", "{}", r#""[[{not structural}]]""#] {
        let value = parse_value(input).unwrap();
        let expected = value.clone();
        assert_eq!(
            with_decode_limits_scope(depth_limits(0), || from_value::<Value>(value)).unwrap(),
            expected
        );
    }
}

#[test]
fn global_value_depth_precedes_active_refusal_without_decode_allocation() {
    let mut value = Value::Null;
    for _ in 0..MAX_JSON_VALUE_NESTING_DEPTH {
        value = Value::Array(vec![value]);
    }
    let (result, usage) =
        with_decode_limits_measured(depth_limits(0), || from_value::<Value>(value));
    assert!(matches!(
        result,
        Err(Error::NestingDepthExceeded {
            depth,
            limit: MAX_JSON_VALUE_NESTING_DEPTH,
            context: "JSON value",
        }) if depth == MAX_JSON_VALUE_NESTING_DEPTH + 1
    ));
    assert_eq!(usage.total_allocated_bytes(), 0);
}

#[test]
fn direct_value_parser_checks_depth_before_scratch_allocation() {
    let limits = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 1);
    let (result, usage) = with_decode_limits_measured(limits, || parse_value("[[7]]"));
    assert_depth_error(
        result.expect_err("complete depth must refuse before parser scratch allocation"),
        2,
        1,
    );
    assert_eq!(usage.total_allocated_bytes(), 0);
}

#[test]
fn transparent_box_value_decode_retains_its_distinct_owned_depth_ceiling() {
    type Two<T> = Box<Box<T>>;
    type Four<T> = Two<Two<T>>;
    type Eight<T> = Four<Four<T>>;
    type Sixteen<T> = Eight<Eight<T>>;
    type ThirtyTwo<T> = Sixteen<Sixteen<T>>;
    let value = Value::from(7_u64);
    let owned = with_decode_limits_scope(depth_limits(0), || {
        ThirtyTwo::<u64>::json_from_value(&value)
    })
    .expect("transparent owners add no JSON field depth");
    assert_eq!(to_json(&owned).unwrap(), "7");
    assert!(matches!(
        with_decode_limits_scope(depth_limits(0), || Box::<ThirtyTwo<u64>>::json_from_value(&value)),
        Err(Error::NestingDepthExceeded {
            depth,
            limit: crate::core::MAX_VALUE_NESTING_DEPTH,
            context: "owned JSON value",
        }) if depth == crate::core::MAX_VALUE_NESTING_DEPTH + 1
    ));
    with_decode_limits_scope(depth_limits(0), || Box::<u64>::json_from_value(&value))
        .expect("the fixed owned guard must restore after failure");
}

#[test]
fn value_depth_refusal_retains_scope_identity_and_allows_same_input_retry() {
    for (outer, protocol, expected) in [
        (1, 8, DecodeAttemptErrorKind::EnclosingLimit),
        (8, 1, DecodeAttemptErrorKind::Invalid),
        (1, 1, DecodeAttemptErrorKind::Invalid),
    ] {
        let value = parse_value("[[7]]").unwrap();
        let error = with_decode_limits_scope(depth_limits(outer), || {
            classify_decode_attempt(|| {
                with_decode_limits_scope(depth_limits(protocol), || {
                    from_value::<Vec<Vec<u64>>>(value).map_err(Error::into_core_error)
                })
            })
        })
        .expect_err("the actual refusing budget owner must survive JSON conversion");
        assert_eq!(error.kind(), expected);
        assert_eq!(
            error.into_error().decode_resource_error(),
            Some(DecodeResourceError::NestingDepthExceeded {
                depth: 2,
                limit: 1,
                context: "decode budget",
            })
        );
    }
    let value = parse_value("[[7]]").unwrap();
    assert_eq!(
        with_decode_limits_scope(depth_limits(2), || from_value::<Vec<Vec<u64>>>(value)).unwrap(),
        vec![vec![7_u64]]
    );
}
