//! Canonical JSON writer and parser parity.

#![cfg(feature = "json")]

use norito::json::{self, Value};
fn samples() -> Vec<&'static str> {
    vec![
        "null",
        "true",
        "false",
        "0",
        "-0",
        "1",
        "-42",
        "3.1415",
        "1e-6",
        "-1.234e+10",
        "\"simple\"",
        r#""escapes\n\t\"\"""#,
        "\"unicode: \\u0416\"",
        "\"surrogate: \\uD834\\uDD1E\"",
        "[]",
        "[1,2,3,4,5]",
        "{}",
        "{\"a\":1,\"b\":true,\"c\":\"x\"}",
    ]
}
#[test]
fn roundtrip_value_stability() {
    for s in samples() {
        let v: Value = json::parse_value(s).expect("parse");
        let out = json::to_string(&v).expect("stringify");
        let v2: Value = json::parse_value(&out).expect("parse2");
        assert_eq!(v, v2, "roundtrip mismatch for input={s} out={out}");
    }
}
#[test]
fn canonical_writer_small_object() {
    // Canonical: lexicographic key order, stable escapes, booleans/ints as-is.
    let v = json::parse_value("{\"b\":true,\"a\":1,\"c\":\"x\\n\"}").expect("parse");
    let out = json::to_string(&v).expect("stringify");
    assert_eq!(out, "{\"a\":1,\"b\":true,\"c\":\"x\\n\"}");
}
#[test]
fn fast_writer_matches_canonical_output() {
    for sample in samples() {
        let value = json::parse_value(sample).expect("parse sample");
        let canonical = json::to_string(&value).expect("canonical stringify");
        let fast = json::to_json_fast(&value).expect("fast stringify");
        assert_eq!(
            fast, canonical,
            "fast writer output mismatch for input {sample}"
        );
    }
}
