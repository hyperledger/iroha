//! Active JSON depth budgets across typed, accelerated and scoped entry points.

use super::*;
use crate::core::{
    DecodeAttemptErrorKind, DecodeBudgetContext, DecodeDepthGuard, DecodeLimits,
    DecodeResourceError, classify_decode_attempt, with_decode_limits_scope,
};

#[derive(Debug, PartialEq, Eq, norito_derive::FastJson, norito_derive::JsonDeserialize)]
#[norito(no_fast_from_json)]
struct LeafProbe {
    value: u64,
}

#[derive(Debug, PartialEq, Eq, norito_derive::FastJson, norito_derive::JsonDeserialize)]
#[norito(no_fast_from_json)]
struct NestedProbe {
    nested: Vec<LeafProbe>,
}

fn decode_fast(input: &str) -> Result<NestedProbe, Error> {
    from_json_fast(input)
}

fn decode_smart(input: &str) -> Result<NestedProbe, Error> {
    from_json_fast_smart(input)
}

fn depth_limit(depth: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, depth)
}

fn assert_depth_refusal(error: Error, depth: usize, limit: usize) {
    assert_eq!(
        error.into_core_error().decode_resource_error(),
        Some(DecodeResourceError::NestingDepthExceeded {
            depth,
            limit,
            context: "decode budget",
        })
    );
}

#[test]
fn typed_and_fast_documents_preserve_exact_and_short_active_depth() {
    let input = r#"{"nested":[{"value":7}]}"#;
    let expected = NestedProbe {
        nested: vec![LeafProbe { value: 7 }],
    };
    for decode in [from_json::<NestedProbe>, decode_fast, decode_smart] {
        assert_eq!(
            with_decode_limits_scope(depth_limit(3), || decode(input)).unwrap(),
            expected
        );
        for limit in [0, 2] {
            let error = with_decode_limits_scope(depth_limit(limit), || decode(input))
                .expect_err("an active caller must bound the complete typed document");
            assert_depth_refusal(error, 3, limit);
        }
    }
}

#[test]
fn zero_depth_admits_leaf_roots_but_not_populated_containers() {
    for input in ["7", "null", "[]", "{}"] {
        with_decode_limits_scope(depth_limit(0), || parse_value(input))
            .expect("a root without nested values requires no additional depth");
    }
    for input in ["[7]", r#"{"value":7}"#] {
        let error = with_decode_limits_scope(depth_limit(0), || parse_value(input))
            .expect_err("a child value must consume depth");
        assert_depth_refusal(error, 1, 0);
    }
}

#[test]
fn unknown_json_fields_cannot_hide_depth_from_the_original_document() {
    let input = r#"{"nested":[],"unused":[[7]]}"#;
    for decode in [from_json::<NestedProbe>, decode_fast] {
        assert_eq!(
            with_decode_limits_scope(depth_limit(3), || decode(input)).unwrap(),
            NestedProbe { nested: vec![] }
        );
        let error = with_decode_limits_scope(depth_limit(2), || decode(input))
            .expect_err("skipped fields remain inside the original depth budget");
        assert_depth_refusal(error, 3, 2);
    }
}

#[test]
fn escaped_json_budget_retains_relative_base_and_restores_after_refusal() {
    let context = {
        let _parent = DecodeDepthGuard::enter().unwrap();
        DecodeBudgetContext::new(depth_limit(2))
    };
    let input = r#"{"nested":[{"value":7}]}"#;
    let error = context
        .with(|| from_json::<NestedProbe>(input))
        .expect_err("the restored original context retains its relative ceiling");
    assert_depth_refusal(error, 3, 2);
    context
        .with(|| from_json::<NestedProbe>(r#"{"nested":[]}"#))
        .expect("failed peak checks must not consume depth");
    with_decode_limits_scope(depth_limit(3), || from_json::<NestedProbe>(input))
        .expect("the caller's original depth must be restored");
}

#[test]
fn json_depth_refusal_preserves_the_actual_attempt_owner() {
    let input = r#"{"nested":[{"value":7}]}"#;
    for (outer, protocol, expected) in [
        (2, 8, DecodeAttemptErrorKind::EnclosingLimit),
        (8, 2, DecodeAttemptErrorKind::Invalid),
        (2, 2, DecodeAttemptErrorKind::Invalid),
    ] {
        let error = with_decode_limits_scope(depth_limit(outer), || {
            classify_decode_attempt(|| {
                with_decode_limits_scope(depth_limit(protocol), || {
                    from_json::<NestedProbe>(input).map_err(Error::into_core_error)
                })
            })
        })
        .expect_err("a depth refusal must retain its original layer");
        assert_eq!(error.kind(), expected);
        assert_eq!(
            error.into_error().decode_resource_error(),
            Some(DecodeResourceError::NestingDepthExceeded {
                depth: 3,
                limit: 2,
                context: "decode budget",
            })
        );
    }
}

#[test]
fn borrowed_and_skipped_values_check_the_peak_before_advancing_the_cursor() {
    let input = "  [[7]], 0";
    for mode in 0..3 {
        let mut parser = Parser::new(input);
        let consume = |parser: &mut Parser<'_>| match mode {
            0 => parser
                .raw_value_slice()
                .map(|value| assert_eq!(value, "[[7]]")),
            1 => parser.skip_value_lexical(),
            _ => parser.skip_value(),
        };
        let error = with_decode_limits_scope(depth_limit(1), || consume(&mut parser))
            .expect_err("the entire borrowed or skipped value retains the active ceiling");
        assert_depth_refusal(error, 2, 1);
        assert_eq!(
            parser.position(),
            2,
            "refusal only consumes leading whitespace"
        );
        with_decode_limits_scope(depth_limit(2), || consume(&mut parser))
            .expect("the original value remains available under its exact ceiling");
        assert_eq!(&input[parser.position()..], ", 0");
    }
    let mut parser = Parser::new("[[7]]");
    let error = with_decode_limits_scope(depth_limit(3), || parser.skip_value_at_depth(3))
        .expect_err("an embedded root retains its enclosing structural depth");
    assert_depth_refusal(error, 4, 3);
    assert_eq!(parser.position(), 0);
    with_decode_limits_scope(depth_limit(4), || parser.skip_value_at_depth(3))
        .expect("the embedded subtree fits its exact ceiling");
}

#[test]
fn lexical_decode_limit_mapping_counts_only_nested_values() {
    for input in ["7", "null", "[]", "{}"] {
        let limits =
            preflight::JsonPreflightLimits::from_decode_limits(input.len(), depth_limit(0));
        preflight::preflight_slice(input.as_bytes(), limits)
            .expect("the root is not an additional decode depth");
    }
    for input in ["[7]", r#"{"value":7}"#] {
        for depth in [0, 1] {
            let limits =
                preflight::JsonPreflightLimits::from_decode_limits(input.len(), depth_limit(depth));
            let result = preflight::preflight_slice(input.as_bytes(), limits);
            if depth == 0 {
                let error = result.expect_err("the nested value requires one additional level");
                assert_eq!(
                    error.resource_kind(),
                    Some(preflight::JsonPreflightResource::NestingDepth)
                );
                assert_eq!((error.attempted(), error.limit()), (2, 1));
            } else {
                result.expect("the exact additional depth fits");
            }
        }
    }
    let input = format!(
        "{}7{}",
        "[".repeat(MAX_JSON_VALUE_NESTING_DEPTH),
        "]".repeat(MAX_JSON_VALUE_NESTING_DEPTH)
    );
    let limits =
        preflight::JsonPreflightLimits::from_decode_limits(input.len(), depth_limit(usize::MAX));
    let error = preflight::preflight_slice(input.as_bytes(), limits)
        .expect_err("a permissive caller cannot raise the fixed JSON ceiling");
    assert_eq!(
        error.resource_kind(),
        Some(preflight::JsonPreflightResource::NestingDepth)
    );
    assert_eq!(error.limit(), MAX_JSON_VALUE_NESTING_DEPTH);
}
