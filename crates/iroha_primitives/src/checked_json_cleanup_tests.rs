//! Exact bytes, refusals and inherited depth for manual primitive JSON writers.

use crate::{
    const_vec::ConstVec,
    numeric::{Numeric, NumericSpec, Quantity},
    small::SmallVec,
    unique_vec::UniqueVec,
};
use norito::json::{self, BoundedJsonError, JsonSerialize, JsonWriteSink};
use std::collections::BTreeSet;

const INHERITED_DEPTH: usize = 7;
const ASSERTION: &str = "owning manual JSON writers must restore the original inherited sink depth";
struct TrackingSink {
    output: String,
    limit: usize,
    depth: usize,
    depth_limit: Option<usize>,
}
impl TrackingSink {
    fn new(limit: usize) -> Self {
        Self {
            output: String::new(),
            limit,
            depth: INHERITED_DEPTH,
            depth_limit: None,
        }
    }
}
impl JsonWriteSink for TrackingSink {
    fn push(&mut self, value: char) -> Result<(), BoundedJsonError> {
        self.push_str(value.encode_utf8(&mut [0; 4]))
    }
    fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError> {
        if self
            .output
            .len()
            .checked_add(value.len())
            .is_none_or(|n| n > self.limit)
        {
            return Err(BoundedJsonError::BodyTooLarge);
        }
        self.output.push_str(value);
        Ok(())
    }
    fn begin_container(&mut self) -> Result<(), BoundedJsonError> {
        let next = self
            .depth
            .checked_add(1)
            .ok_or(BoundedJsonError::Unsupported)?;
        if self.depth_limit.is_some_and(|n| next >= n) {
            return Err(BoundedJsonError::Unsupported);
        }
        self.depth = next;
        Ok(())
    }
    fn end_container(&mut self) {
        assert!(
            self.depth > INHERITED_DEPTH,
            "writer must not release inherited levels"
        );
        self.depth -= 1;
    }
}
fn audit(value: &impl JsonSerialize, label: &str, defects: &mut Vec<String>) {
    let ordinary = json::to_json(value).expect("ordinary original serializer");
    let mut changed = BTreeSet::new();
    for limit in 0..ordinary.len() {
        let mut sink = TrackingSink::new(limit);
        assert_eq!(
            value.json_serialize_to(&mut sink),
            Err(BoundedJsonError::BodyTooLarge)
        );
        if sink.depth != INHERITED_DEPTH {
            changed.insert(sink.depth);
        }
    }
    let mut sink = TrackingSink::new(ordinary.len());
    assert_eq!(value.json_serialize_to(&mut sink), Ok(()));
    assert_eq!(sink.output, ordinary);
    assert_eq!(sink.depth, INHERITED_DEPTH);
    let mut sink = TrackingSink::new(usize::MAX);
    sink.depth_limit = Some(INHERITED_DEPTH + 1);
    assert_eq!(
        value.json_serialize_to(&mut sink),
        Err(BoundedJsonError::Unsupported)
    );
    assert!(sink.output.is_empty());
    assert_eq!(sink.depth, INHERITED_DEPTH);
    println!(
        "shape={label}; exact byte refusals={}; changed depths={changed:?}",
        ordinary.len()
    );
    if !changed.is_empty() {
        defects.push(format!("{label}: {changed:?}"));
    }
}
fn complete(defects: &[String]) {
    assert!(defects.is_empty(), "{ASSERTION}: {defects:?}");
}
#[derive(PartialEq)]
struct UnsupportedLeaf;
impl JsonSerialize for UnsupportedLeaf {
    fn json_serialize(&self, _: &mut String) {
        panic!("checked path must not use ordinary fallback");
    }
}
#[test]
fn original_const_vec_refusal_preserves_inherited_depth() {
    let mut defects = Vec::new();
    audit(
        &ConstVec::from(vec![17_u64, 42]),
        "ConstVec scalars",
        &mut defects,
    );
    audit(
        &ConstVec::<u64>::new_empty(),
        "ConstVec empty",
        &mut defects,
    );
    complete(&defects);
}
#[test]
fn original_unique_vec_refusal_preserves_inherited_depth() {
    let mut defects = Vec::new();
    audit(
        &UniqueVec::from_iter([17_u64, 42]),
        "UniqueVec scalars",
        &mut defects,
    );
    audit(&UniqueVec::<u64>::new(), "UniqueVec empty", &mut defects);
    complete(&defects);
}
#[test]
fn original_small_vec_refusal_preserves_inherited_depth() {
    let mut defects = Vec::new();
    audit(
        &SmallVec::<[u64; 4]>::from(vec![17, 42]),
        "SmallVec inline",
        &mut defects,
    );
    audit(
        &SmallVec::<[u64; 1]>::from(vec![17, 42]),
        "SmallVec spilled",
        &mut defects,
    );
    audit(
        &SmallVec::<[u64; 4]>::default(),
        "SmallVec empty",
        &mut defects,
    );
    complete(&defects);
}
#[test]
fn original_numeric_spec_refusal_preserves_inherited_depth() {
    let mut defects = Vec::new();
    for value in [
        NumericSpec::unconstrained(),
        NumericSpec::integer(),
        NumericSpec::try_fractional(28).unwrap(),
    ] {
        audit(&value, "NumericSpec", &mut defects);
    }
    complete(&defects);
}
#[test]
fn original_manual_containers_keep_exact_unsupported_leaf_error_and_depth() {
    fn refused(value: &impl JsonSerialize, label: &str, defects: &mut Vec<String>) {
        let mut sink = TrackingSink::new(usize::MAX);
        assert_eq!(
            value.json_serialize_to(&mut sink),
            Err(BoundedJsonError::Unsupported)
        );
        if sink.depth != INHERITED_DEPTH {
            defects.push(format!("{label}: {}", sink.depth));
        }
    }
    let mut defects = Vec::new();
    refused(
        &ConstVec::from(vec![UnsupportedLeaf]),
        "ConstVec",
        &mut defects,
    );
    refused(
        &UniqueVec::from_iter([UnsupportedLeaf]),
        "UniqueVec",
        &mut defects,
    );
    refused(
        &SmallVec::<[UnsupportedLeaf; 1]>::from(vec![UnsupportedLeaf]),
        "SmallVec",
        &mut defects,
    );
    complete(&defects);
}
#[test]
fn original_numeric_and_quantity_scalar_writers_preserve_depth_and_bytes() {
    for value in [
        Numeric::from(-17_i64),
        Numeric::from(0_i64),
        "1.25".parse::<Numeric>().unwrap(),
    ] {
        let ordinary = json::to_json(&value).unwrap();
        for limit in 0..=ordinary.len() {
            let mut sink = TrackingSink::new(limit);
            let result = value.json_serialize_to(&mut sink);
            assert_eq!(
                result,
                if limit < ordinary.len() {
                    Err(BoundedJsonError::BodyTooLarge)
                } else {
                    Ok(())
                }
            );
            assert_eq!(sink.depth, INHERITED_DEPTH);
            if result.is_ok() {
                assert_eq!(sink.output, ordinary);
            }
        }
    }
    let value = Quantity::from(17_u32);
    let ordinary = json::to_json(&value).unwrap();
    for limit in 0..=ordinary.len() {
        let mut sink = TrackingSink::new(limit);
        let result = value.json_serialize_to(&mut sink);
        assert_eq!(
            result,
            if limit < ordinary.len() {
                Err(BoundedJsonError::BodyTooLarge)
            } else {
                Ok(())
            }
        );
        assert_eq!(sink.depth, INHERITED_DEPTH);
        if result.is_ok() {
            assert_eq!(sink.output, ordinary);
        }
    }
}

#[test]
fn nested_primitive_containers_clean_only_their_original_levels() {
    let mut defects = Vec::new();
    audit(
        &ConstVec::from(vec![ConstVec::from(vec![17_u64])]),
        "ConstVec<ConstVec>",
        &mut defects,
    );
    audit(
        &UniqueVec::from_iter([ConstVec::from(vec![17_u64])]),
        "UniqueVec<ConstVec>",
        &mut defects,
    );
    audit(
        &SmallVec::<[ConstVec<u64>; 1]>::from(vec![ConstVec::from(vec![17_u64])]),
        "SmallVec<ConstVec>",
        &mut defects,
    );
    complete(&defects);
}
#[test]
fn primitive_cap_refusal_happens_before_manual_leaf_observation() {
    #[derive(PartialEq)]
    struct Observed<'a>(&'a std::cell::Cell<usize>);
    impl JsonSerialize for Observed<'_> {
        fn json_serialize(&self, _: &mut String) {
            panic!("checked path cannot use an ordinary fallback");
        }
        fn json_serialize_to(&self, sink: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
            self.0.set(self.0.get() + 1);
            sink.push_str("17")
        }
    }
    fn refused(value: &impl JsonSerialize, calls: &std::cell::Cell<usize>) {
        let mut sink = TrackingSink::new(0);
        assert_eq!(
            value.json_serialize_to(&mut sink),
            Err(BoundedJsonError::BodyTooLarge)
        );
        assert_eq!(calls.get(), 0);
        assert_eq!(sink.depth, INHERITED_DEPTH);
    }
    let calls = std::cell::Cell::new(0);
    refused(&ConstVec::from(vec![Observed(&calls)]), &calls);
    refused(&UniqueVec::from_iter([Observed(&calls)]), &calls);
    refused(
        &SmallVec::<[Observed<'_>; 1]>::from(vec![Observed(&calls)]),
        &calls,
    );
}
