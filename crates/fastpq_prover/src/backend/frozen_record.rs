//! Test access to the tracked records of the frozen transcript profile.
//!
//! `specs/zk_primitive_workloads.json` holds the profile record (parameters,
//! identity, measurement bindings) and `fixtures/fastpq/q77-transcript-profile.json`
//! the known answers that `scripts/zk_semantic_profile_reference.py` computes
//! independently of this crate. Both are public data; neither grants authority.

use std::{fs, path::PathBuf, sync::OnceLock};

use norito::json::Value;

/// Workloads record that names the frozen profile identities.
pub(super) const RECORD: &str = "specs/zk_primitive_workloads.json";
/// Independent known answers of the frozen transcript.
pub(super) const KNOWN_ANSWERS: &str = "fixtures/fastpq/q77-transcript-profile.json";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load(path: &str) -> Value {
    let text = fs::read_to_string(workspace_root().join(path))
        .unwrap_or_else(|error| panic!("read {path}: {error}"));
    norito::json::from_str(&text).unwrap_or_else(|error| panic!("{path} is not JSON: {error}"))
}

/// The parsed workloads record.
pub(super) fn record() -> &'static Value {
    static DOCUMENT: OnceLock<Value> = OnceLock::new();
    DOCUMENT.get_or_init(|| load(RECORD))
}

/// The parsed known-answer fixture.
pub(super) fn known_answers() -> &'static Value {
    static DOCUMENT: OnceLock<Value> = OnceLock::new();
    DOCUMENT.get_or_init(|| load(KNOWN_ANSWERS))
}

/// A required object field.
pub(super) fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .as_object()
        .and_then(|object| object.get(key))
        .unwrap_or_else(|| panic!("record object has no `{key}` field"))
}

/// A field that may be absent or null.
pub(super) fn optional<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_object()
        .and_then(|object| object.get(key))
        .filter(|found| !found.is_null())
}

/// A required array field.
pub(super) fn list<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    field(value, key)
        .as_array()
        .unwrap_or_else(|| panic!("record field `{key}` is not an array"))
}

/// A required string field.
pub(super) fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    field(value, key)
        .as_str()
        .unwrap_or_else(|| panic!("record field `{key}` is not a string"))
}

/// A required unsigned integer field, exact over the whole `u64` range.
pub(super) fn number(value: &Value, key: &str) -> u64 {
    as_u64(field(value, key))
}

/// An exact unsigned integer value.
pub(super) fn as_u64(value: &Value) -> u64 {
    value
        .as_u64()
        .unwrap_or_else(|| panic!("record value {value:?} is not a u64"))
}

/// A required array of unsigned integers.
pub(super) fn numbers(value: &Value, key: &str) -> Vec<u64> {
    list(value, key).iter().map(as_u64).collect()
}

/// The frozen profile entry with `name` in the workloads record.
pub(super) fn profile_entry(name: &str) -> &'static Value {
    list(field(record(), "semantic_profiles"), "profiles")
        .iter()
        .find(|profile| text(profile, "name") == name)
        .unwrap_or_else(|| panic!("{RECORD} has no frozen profile `{name}`"))
}

#[test]
fn tracked_records_are_readable_and_name_the_same_profile() {
    let shared = field(field(record(), "semantic_profiles"), "shared_transcript");
    let name = text(shared, "profile");
    assert_eq!(text(known_answers(), "profile"), name);
    assert_eq!(text(profile_entry(name), "kind"), "transcript");
    assert_eq!(
        text(field(shared, "known_answers"), "fixture"),
        KNOWN_ANSWERS
    );
    assert!(optional(shared, "absent-field").is_none());
    assert_eq!(number(known_answers(), "profile_frame_bytes"), 3_871);
    assert_eq!(list(profile_entry(name), "parameters").len(), 73);
}
