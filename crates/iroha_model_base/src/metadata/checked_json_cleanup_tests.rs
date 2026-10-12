//! Checked metadata emission preserves exact canonical fields and inherited depth.

use crate::{metadata::Metadata, name::Name};
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
#[test]
fn original_metadata_refusal_preserves_inherited_depth() {
    let mut value = Metadata::default();
    value.insert(
        "retained".parse::<Name>().unwrap(),
        iroha_primitives::json::Json::new(17_u64),
    );
    let mut defects = Vec::new();
    audit(&value, "Metadata scalar", &mut defects);
    audit(&Metadata::default(), "Metadata empty", &mut defects);
    complete(&defects);
}

#[test]
fn quoted_metadata_keys_and_nested_canonical_json_keep_original_bytes_and_depth() {
    let mut value = Metadata::default();
    value.insert(
        "quote\"slash\\".parse::<Name>().unwrap(),
        iroha_primitives::json::Json::from_raw_json(r#"{"outer":[{"inner":17},null]}"#.to_owned())
            .unwrap(),
    );
    let mut defects = Vec::new();
    audit(&value, "quoted key and nested retained Json", &mut defects);
    complete(&defects);
}
