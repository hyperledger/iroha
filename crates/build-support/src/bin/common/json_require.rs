//! Typed JSON field accessors shared by the Sumeragi report binaries.
//!
//! `sumeragi_baseline_report` and `sumeragi_da_report` include this file with
//! `#[path]`; each binary supplies its own `Result` alias and a `ReportError`
//! with matching `MissingField` and `InvalidType` variants.

use std::path::Path;

use norito::json::{Map, Value};

use super::{ReportError, Result};

/// Read a required JSON object field.
pub fn require_object<'a>(map: &'a Map, key: &str, path: &Path) -> Result<&'a Map> {
    map.get(key).map_or_else(
        || {
            Err(ReportError::MissingField {
                path: path.to_path_buf(),
                field: key.into(),
            })
        },
        |value| match value {
            Value::Object(obj) => Ok(obj),
            other => Err(ReportError::InvalidType {
                path: path.to_path_buf(),
                field: key.into(),
                expected: "object",
                actual: value_type(other),
            }),
        },
    )
}
/// Read a required unsigned integer field.
pub fn require_u64(map: &Map, key: &str, path: &Path) -> Result<u64> {
    map.get(key).map_or_else(
        || {
            Err(ReportError::MissingField {
                path: path.to_path_buf(),
                field: key.into(),
            })
        },
        |value| {
            value.as_u64().ok_or_else(|| ReportError::InvalidType {
                path: path.to_path_buf(),
                field: key.into(),
                expected: "u64",
                actual: value_type(value),
            })
        },
    )
}
/// Read a required floating-point field.
pub fn require_f64(map: &Map, key: &str, path: &Path) -> Result<f64> {
    map.get(key).map_or_else(
        || {
            Err(ReportError::MissingField {
                path: path.to_path_buf(),
                field: key.into(),
            })
        },
        |value| {
            value.as_f64().ok_or_else(|| ReportError::InvalidType {
                path: path.to_path_buf(),
                field: key.into(),
                expected: "f64",
                actual: value_type(value),
            })
        },
    )
}
/// Read a required string field.
pub fn require_string(map: &Map, key: &str, path: &Path) -> Result<String> {
    map.get(key).map_or_else(
        || {
            Err(ReportError::MissingField {
                path: path.to_path_buf(),
                field: key.into(),
            })
        },
        |value| match value {
            Value::String(s) => Ok(s.clone()),
            other => Err(ReportError::InvalidType {
                path: path.to_path_buf(),
                field: key.into(),
                expected: "string",
                actual: value_type(other),
            }),
        },
    )
}
/// Name the JSON type of `value` for diagnostics.
pub fn value_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
