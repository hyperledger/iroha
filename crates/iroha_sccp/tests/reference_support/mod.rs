//! Shared support of the Rust reference generators (`specs/sccp.md` §11, revision 5).
//!
//! `fixtures/sccp/finality_v1.json`, `committee_transitions_v1.json` and `control_v1.json`
//! are written by two independent generators whose outputs must be byte-identical: the
//! Python reference (`scripts/sccp_reference/`) and the Rust reference, the integration
//! tests `v1_reference_finality`, `v1_reference_transitions` and `v1_reference_control`.
//! Each test target builds one document from `iroha_sccp::v1`, `iroha_data_model` and
//! `iroha_crypto::bls::consensus` and compares it with the committed file. This module is
//! what they share:
//!
//! - [`python_json`]: the JSON text Python writes, and a readable difference of two documents;
//! - [`bls_support`]: the §11.3 test keys, signing, and the point and field forms;
//! - [`taira_sim`]: committees, certificates with their negative variants, and a small
//!   Taira that produces headers, blocks and proofs (the twin of `taira.py`);
//! - [`scenario`]: the certificate pool and the recorder that runs the destination model
//!   and writes the `(state, input, now) → (state', outcome, event)` rows (the twin of
//!   `scenario.py`);
//! - here: the JSON builders, the forms of headers and `QC_FIXED`, the texts every file
//!   repeats, the destination clock rule and the drift check.
//!
//! A generator derives every value. It reads a committed fixture only in
//! [`assert_matches_committed`], and prose, labels and ids are literals that both generators
//! repeat. A new row therefore needs both generators and one regeneration.
//!
//! The tests of this module are in `v1_reference_finality.rs` (the renderer, `KeyGen`,
//! committees, the certificate overrides, the simulator and the recorder) and in
//! `v1_reference_transitions.rs` (the checks of recorded rows), so they run once and not in
//! every target that compiles it.

#![allow(
    dead_code,
    reason = "every test target compiles this module and uses its own part of it"
)]

use std::{fs, path::PathBuf};

use iroha_sccp::v1::{
    destination::DestinationError,
    finality::{QcFixedV1, SccpFinalityHeaderFieldsV1, SccpFinalityHeaderV1},
    hashes::to_hex,
};
use norito::json::{Map, Value};

pub mod bls_support;
pub mod python_json;
pub mod scenario;
pub mod taira_sim;

/// The `generator` text of the three files that both references write.
pub const REFERENCE_GENERATORS: &str = "two generators write this file byte for byte: the \
     independent Python reference (python3 scripts/sccp_reference/generate.py --write, Python \
     3.10+) and the Rust reference (cargo test -p iroha_sccp --test v1_reference_finality --test \
     v1_reference_transitions --test v1_reference_control -- --ignored regenerate)";
/// What `now_ms` is, repeated under `conventions` of every file.
pub const DESTINATION_CLOCK_CONVENTION: &str = "`now_ms` is the destination clock: \
     block.timestamp (EVM) or now() (TON) in whole seconds, times 1000, so every `now_ms` is a \
     multiple of 1000";
/// How `now_ms` moves inside a scenario, repeated under `conventions` of the scenario files.
pub const SCENARIO_CLOCK_CONVENTION: &str = "within a scenario `now_ms` never decreases from \
     one step to the next (equal values are calls in the same block or second). Taira-side \
     times (`X.timestamp_ms`, `untilMs`, payload deadlines, fast-pause expiries) are \
     milliseconds and may be sub-second, so a time boundary is probed with the nearest \
     whole-second clock values on both sides";
/// The step of the destination clock: `block.timestamp × 1000` (`specs/sccp.md` §0).
pub const DESTINATION_CLOCK_STEP_MS: u64 = 1_000;
/// The command that rewrites the three files from the Rust reference.
pub const REGENERATE_COMMAND: &str = "cargo test -p iroha_sccp --test v1_reference_finality \
     --test v1_reference_transitions --test v1_reference_control -- --ignored regenerate";

// ---------------------------------------------------------------------------------------------
// JSON builders
// ---------------------------------------------------------------------------------------------

/// An object of `entries`.
///
/// # Panics
/// On a repeated key: a fixture object never names a field twice.
pub fn obj<const N: usize>(entries: [(&str, Value); N]) -> Value {
    let mut map = Map::new();
    for (key, value) in entries {
        assert!(
            map.insert(key.to_owned(), value).is_none(),
            "duplicate key {key}"
        );
    }
    Value::Object(map)
}

/// Add `key` to the object `target`.
///
/// # Panics
/// When `target` is not an object or already holds `key`.
pub fn insert(target: &mut Value, key: &str, value: Value) {
    let Value::Object(map) = target else {
        panic!("{key} is added to a JSON object");
    };
    assert!(
        map.insert(key.to_owned(), value).is_none(),
        "duplicate key {key}"
    );
}

/// `0x` and lowercase hexadecimal: the byte-string form of the fixtures.
pub fn hx_string(bytes: &[u8]) -> String {
    format!("0x{}", to_hex(bytes))
}

/// The bytes of a hexadecimal string without a prefix: the form of the published vectors
/// that a self-test quotes.
///
/// # Panics
/// When `digits` is not an even number of hexadecimal digits.
pub fn unhex(digits: &str) -> Vec<u8> {
    assert!(digits.len().is_multiple_of(2), "an odd number of digits");
    (0..digits.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&digits[index..index + 2], 16).expect("hex digits"))
        .collect()
}

/// A byte string as a JSON value.
pub fn hx(bytes: &[u8]) -> Value {
    Value::String(hx_string(bytes))
}

/// An array of byte strings.
pub fn hexes<T: AsRef<[u8]>>(items: &[T]) -> Value {
    list(items.iter().map(|item| hx(item.as_ref())))
}

/// A JSON string.
pub fn text(value: &str) -> Value {
    Value::String(value.to_owned())
}

/// A JSON number. The fixtures keep every number below `2^53`.
///
/// # Panics
/// At `2^53` or above: such a value is a decimal or hexadecimal string, not a number.
pub fn num(value: u64) -> Value {
    assert!(value < 1 << 53, "{value} is not a JSON-safe integer");
    Value::from(value)
}

/// A wide integer as a decimal string: amounts, supplies and `voidFrozen` nonces.
pub fn dec(value: u128) -> Value {
    Value::String(value.to_string())
}

/// A JSON array.
pub fn list(items: impl IntoIterator<Item = Value>) -> Value {
    Value::Array(items.into_iter().collect())
}

// ---------------------------------------------------------------------------------------------
// Shared forms
// ---------------------------------------------------------------------------------------------

/// The twelve header fields as the fixtures print them.
pub fn header_fields_json(fields: &SccpFinalityHeaderFieldsV1) -> Value {
    obj([
        ("network_id", hx(&fields.network_id)),
        ("height", num(fields.height)),
        ("timestamp_ms", num(fields.timestamp_ms)),
        ("flags", num(fields.flags.into())),
        ("message_count", num(fields.message_count.into())),
        ("sccp_root", hx(&fields.sccp_root)),
        ("history_size", num(fields.history_size)),
        ("history_root", hx(&fields.history_root)),
        ("generation", num(fields.generation)),
        ("committee_root", hx(&fields.committee_root)),
        ("validity_ms", num(fields.validity_ms)),
        ("next_committee_root", hx(&fields.next_committee_root)),
    ])
}

/// The fields of `header` when it is a finality header, `null` when it is not: a dirty
/// header is recorded raw.
pub fn parsed_header_json(header: &[u8]) -> Value {
    SccpFinalityHeaderV1::parse(header)
        .map_or(Value::Null, |header| header_fields_json(&header.fields()))
}

/// The six `QC_FIXED` fields as the fixtures print them.
pub fn qc_fixed_json(qc: &QcFixedV1) -> Value {
    obj([
        ("epoch", num(qc.epoch)),
        ("epoch_context", hx(&qc.epoch_context)),
        ("view", num(qc.view)),
        ("block_hash", hx(&qc.block_hash)),
        ("result_body", hx(&qc.result_body)),
        ("signers", num(qc.signers.into())),
    ])
}

/// The outcome name of a destination call: `ok` or the §5.2.2 error name.
pub fn outcome_name<T>(result: &Result<T, DestinationError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(error) => error.name(),
    }
}

/// Fail unless `now_ms` is a destination clock value that may follow `previous_ms`.
///
/// A destination reads whole seconds (`now_ms = block.timestamp × 1000`, §0) and its clock
/// never runs backwards; consecutive calls may share one value.
///
/// # Panics
/// On a sub-second `now_ms`, or one earlier than `previous_ms`.
pub fn check_destination_clock(now_ms: u64, previous_ms: Option<u64>, context: &str) {
    assert!(
        now_ms.is_multiple_of(DESTINATION_CLOCK_STEP_MS),
        "{context}: now_ms {now_ms} is not a whole-second destination clock value"
    );
    if let Some(previous_ms) = previous_ms {
        assert!(
            now_ms >= previous_ms,
            "{context}: now_ms {now_ms} is earlier than the previous step's {previous_ms}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Fixture files
// ---------------------------------------------------------------------------------------------

/// The path of `fixtures/sccp/<name>`.
pub fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/sccp")
        .join(name)
}

/// The drift check of one file: the committed document equals `generated`, value for value
/// and then byte for byte.
///
/// The values are compared first, so a failure names the first field that differs. The byte
/// comparison then pins the text itself: key order, indentation, escapes and the final
/// newline.
///
/// # Panics
/// When the file is missing, does not parse, or differs. `regenerate` is the command the
/// failure message names.
pub fn assert_matches_committed(name: &str, generated: &Value, regenerate: &str) {
    let path = fixture_path(name);
    let committed = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let parsed: Value = norito::json::from_str(&committed)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
    if let Some(difference) = python_json::first_difference(generated, &parsed) {
        panic!(
            "{name} differs from the generated document at {difference}\nafter a reviewed \
             change run `{regenerate}`"
        );
    }
    let rendered = python_json::render(generated);
    if rendered != committed {
        let line = rendered
            .lines()
            .zip(committed.lines())
            .position(|(left, right)| left != right)
            .unwrap_or_else(|| rendered.lines().count().min(committed.lines().count()));
        panic!(
            "{name} holds the generated values but not the generated text: the first \
             difference is at line {}\nafter a reviewed change run `{regenerate}`",
            line + 1
        );
    }
}

/// Rewrite `fixtures/sccp/<name>` with the canonical text of `generated`.
///
/// # Panics
/// When the file cannot be written.
pub fn write_fixture(name: &str, generated: &Value) {
    let path = fixture_path(name);
    fs::write(&path, python_json::render(generated))
        .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
}
