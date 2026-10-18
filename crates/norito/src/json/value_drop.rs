//! Constant-stack cleanup using ownership threaded through existing JSON child slots.
use super::{Error, Value, native::Map, try_decode_vec_with_capacity};

/// Drop a recursive JSON value without allocating cleanup storage or recursing.
///
/// Each nonempty container's last child slot temporarily owns the previous parent.
/// After the extracted child is dismantled, popping that same slot restores the
/// parent link. Only scalar values and empty containers reach ordinary drop.
/// This also covers manually constructed values beyond the parser's depth limit.
///
/// # Panics
/// Panics only if an internal parent link is not its original nonempty container.
#[doc(hidden)]
pub fn drop_json_value_iteratively(mut pending: Value) {
    let mut parents = Value::Null;
    loop {
        let last = match &mut pending {
            Value::Array(values) => values.last_mut(),
            Value::Object(values) => values
                .last_entry()
                .map(std::collections::btree_map::OccupiedEntry::into_mut),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => None,
        };
        if let Some(last) = last {
            let child = std::mem::replace(last, parents);
            parents = pending;
            pending = child;
            continue;
        }
        // This value owns no children; no recursive Value drop can occur here.
        drop(pending);
        match parents {
            Value::Array(mut values) => {
                parents = values.pop().expect("JSON parent array retains its link");
                pending = Value::Array(values);
            }
            Value::Object(mut values) => {
                let (_, previous) = values
                    .pop_last()
                    .expect("JSON parent object retains its link");
                parents = previous;
                pending = Value::Object(values);
            }
            Value::Null => return,
            Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                unreachable!("JSON parent link is an original container")
            }
        }
    }
}
pub(super) struct IterativeValueDropGuard(Option<Value>);
impl IterativeValueDropGuard {
    pub(super) fn new(value: Value) -> Self {
        Self(Some(value))
    }
    pub(super) fn take(&mut self) -> Value {
        self.0.take().expect("iterative JSON value guard is empty")
    }
}
impl Drop for IterativeValueDropGuard {
    fn drop(&mut self) {
        if let Some(value) = self.0.take() {
            drop_json_value_iteratively(value);
        }
    }
}
pub(super) enum ValueParseFrame {
    Array {
        values: Vec<Value>,
        child_depth: usize,
    },
    Object {
        values: Map,
        key: Option<String>,
        child_depth: usize,
    },
}
impl ValueParseFrame {
    fn drop_values(self) {
        match self {
            Self::Array { values, .. } => {
                drop_json_value_iteratively(Value::Array(values));
            }
            Self::Object { values, .. } => {
                drop_json_value_iteratively(Value::Object(values));
            }
        }
    }
    pub(super) fn finish(self) -> Value {
        match self {
            Self::Array { values, .. } => Value::Array(values),
            Self::Object { values, .. } => Value::Object(values),
        }
    }
}
pub(super) struct ValueParseState {
    pub(super) frames: Vec<ValueParseFrame>,
    pub(super) completed: Option<Value>,
}
impl ValueParseState {
    pub(super) fn with_frame_capacity(frames: usize) -> Result<Self, Error> {
        Ok(Self {
            frames: try_decode_vec_with_capacity(frames)?,
            completed: None,
        })
    }
    pub(super) fn take_completed(&mut self) -> Value {
        self.completed
            .take()
            .expect("iterative JSON parser has no completed value")
    }
}
impl Drop for ValueParseState {
    fn drop(&mut self) {
        if let Some(value) = self.completed.take() {
            drop_json_value_iteratively(value);
        }
        for frame in self.frames.drain(..) {
            frame.drop_values();
        }
    }
}
