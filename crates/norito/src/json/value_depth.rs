//! Allocation-free structural-depth admission for already-owned JSON values.

use super::{Error, MAX_JSON_VALUE_NESTING_DEPTH, Value, ensure_json_value_depth};

/// Check the complete borrowed value before a typed conversion allocates or recurses.
///
/// The fixed frame array holds only child iterators. Object keys and string contents
/// do not add structural depth. The complete peak is checked after the existing
/// fixed ceiling, preserving global-refusal priority over an active caller budget.
///
/// # Errors
/// Returns the original global JSON nesting error or the active decode budget's
/// scoped nesting error. No allocation, cursor, counter or depth owner is changed.
///
/// # Panics
/// Panics only if an internal traversal frame is unexpectedly uninitialized.
pub fn ensure(value: &Value) -> Result<(), Error> {
    enum Children<'a> {
        Array(core::slice::Iter<'a, Value>),
        Object(std::collections::btree_map::Values<'a, String, Value>),
    }
    let mut frames: [Option<Children<'_>>; MAX_JSON_VALUE_NESTING_DEPTH] =
        [const { None }; MAX_JSON_VALUE_NESTING_DEPTH];
    let mut frame_count = 0_usize;
    let mut peak = 1_usize;
    let mut current = value;
    loop {
        let depth = frame_count + 1;
        if depth > MAX_JSON_VALUE_NESTING_DEPTH {
            return ensure_json_value_depth(depth);
        }
        peak = peak.max(depth);
        let children = match current {
            Value::Array(values) => Some(Children::Array(values.iter())),
            Value::Object(values) => Some(Children::Object(values.values())),
            _ => None,
        };
        if let Some(children) = children {
            frames[frame_count] = Some(children);
            frame_count += 1;
        }
        current = loop {
            if frame_count == 0 {
                return ensure_json_value_depth(peak);
            }
            let next = match frames[frame_count - 1]
                .as_mut()
                .expect("JSON depth frame must be initialized")
            {
                Children::Array(values) => values.next(),
                Children::Object(values) => values.next(),
            };
            if let Some(value) = next {
                break value;
            }
            frame_count -= 1;
            frames[frame_count] = None;
        };
    }
}
