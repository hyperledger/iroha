//! Original deep comb fixtures shared by allocation and child-isolated cleanup controls.

use norito::json;
use std::collections::BTreeMap;

/// Container owner used for every pair in the original recursive fixture.
#[derive(Clone, Copy)]
pub enum CombContainer {
    /// A two-element JSON array.
    Array,
    /// A two-entry JSON object with the original a/z key order.
    Object,
}

/// Retain the two supplied children in the original container and order.
pub fn pair(container: CombContainer, first: json::Value, last: json::Value) -> json::Value {
    match container {
        CombContainer::Array => json::Value::Array(vec![first, last]),
        CombContainer::Object => {
            let mut values = BTreeMap::new();
            values.insert(String::from("a"), first);
            values.insert(String::from("z"), last);
            json::Value::Object(values)
        }
    }
}

/// Build the original fixed-block deep comb without recursive construction.
pub fn deep_comb(container: CombContainer, blocks: usize) -> json::Value {
    let mut value = json::Value::String(String::from("original terminal owner"));
    for _ in 0..blocks {
        value = pair(container, json::Value::Null, value);
        for _ in 0..json::MAX_JSON_VALUE_NESTING_DEPTH {
            value = pair(container, value, json::Value::Null);
        }
    }
    value
}
