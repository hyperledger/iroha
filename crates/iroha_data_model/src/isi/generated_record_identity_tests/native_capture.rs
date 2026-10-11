//! Complete, bounded current record captures from the ordinary typed inventory.
//!
//! Existing current constructors replace only their explicitly selected cases.
//! Every other input must already decode and re-encode exactly in the current
//! layout, including all container frames. No retired decoder is invoked.

use super::{capture, frame_fields, json, kaigi_records, missing_record_values};
use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize, json::Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    io::Write,
};

#[path = "sorafs_values.rs"]
mod sorafs_values;

const MAX_FIXTURE_BYTES: usize = 8 * 1_024 * 1_024;
const MAX_RECORDS: usize = 1_024;
const MAX_CASES: usize = 64;
const MAX_FRAME_BYTES: usize = 1_024 * 1_024;
const MAX_CAPTURE_BYTES: usize = 16 * 1_024 * 1_024;
const MAX_NAME_BYTES: usize = 4_096;
const SOURCE: &str =
    include_str!("../../../tests/fixtures/instruction_record_generated_identity_frames.json");

type CaptureRecord = fn(&str, &Value, Option<&Value>, Option<usize>) -> Value;

/// One actual typed record from the ordinary generated-test inventory.
pub(super) struct Record {
    nominal: &'static str,
    replacement_index: Option<usize>,
    capture: CaptureRecord,
}

impl Record {
    /// Bind the exact existing codec and an optional current Kaigi case replacement.
    pub(super) const fn new<T>(nominal: &'static str, replacement_index: Option<usize>) -> Self
    where
        T: NoritoSchema
            + NoritoSerialize
            + for<'de> NoritoDeserialize<'de>
            + Clone
            + Debug
            + PartialEq,
    {
        Self {
            nominal,
            replacement_index,
            capture: capture_record::<T>,
        }
    }
}

pub(super) fn sorafs_values() -> Vec<Value> {
    sorafs_values::values()
}

fn nominal(row: &Value) -> &str {
    let name = row
        .get("nominal")
        .and_then(Value::as_str)
        .expect("record nominal");
    assert!(!name.is_empty() && name.len() <= MAX_NAME_BYTES);
    name
}

fn unique_rows(rows: Vec<Value>) -> BTreeMap<String, Value> {
    assert!(!rows.is_empty() && rows.len() <= MAX_RECORDS);
    let mut result = BTreeMap::new();
    for row in rows {
        let name = nominal(&row).to_owned();
        assert!(
            result.insert(name, row).is_none(),
            "duplicate native record"
        );
    }
    result
}

fn proposed_rows(source: &str) -> BTreeMap<String, Value> {
    assert!(!source.is_empty() && source.len() <= MAX_FIXTURE_BYTES);
    let rows: Value = json::from_str(source).expect("bounded proposed record JSON");
    let Value::Array(rows) = rows else {
        panic!("record proposal must be an array")
    };
    unique_rows(rows)
}

fn current_constructors() -> BTreeMap<String, Value> {
    let mut values = missing_record_values();
    values.extend(sorafs_values());
    values.extend(kaigi_records::current_values());
    // Capture the exact asset and expected ordinal of the current IssueLoad
    // constructor through the real codec;
    // retired discriminants and container frames are never decoded or projected.
    values.push(capture(
        crate::isi::kagemusha_wallet::KagemushaWalletLedgerV1::new(
            [1; 32],
            crate::isi::kagemusha_wallet::KagemushaWalletLedgerActionV1::IssueLoad {
                wallet: [2; 32],
                asset: [4; 32],
                ordinal: 0,
                request_id: [3; 32],
                amount: 7,
                charge: None,
            },
        ),
    ));
    unique_rows(values)
}

fn decode_current<T>(case: &Value) -> T
where
    T: NoritoSerialize + for<'de> NoritoDeserialize<'de>,
{
    let encoded = case
        .get("frame")
        .and_then(Value::as_str)
        .expect("root frame");
    assert!(encoded.len() <= MAX_FRAME_BYTES * 2 && encoded.len().is_multiple_of(2));
    assert!(
        encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "canonical lowercase frame hex"
    );
    let bytes = hex::decode(encoded).expect("root frame hex");
    let limits = norito::DecodeLimits::new(
        MAX_FRAME_BYTES,
        MAX_FRAME_BYTES,
        MAX_FRAME_BYTES * 4,
        MAX_FRAME_BYTES * 8,
        128,
    );
    norito::core::with_decode_limits_scope(limits, || {
        norito::decode_from_bytes(&bytes).expect("input must decode under the current typed layout")
    })
}

fn exact_current_case<T>(case: &Value) -> Value
where
    T: NoritoSchema + NoritoSerialize + for<'de> NoritoDeserialize<'de> + Clone + Debug + PartialEq,
{
    let actual = frame_fields(&capture(decode_current::<T>(case)));
    assert_eq!(
        &actual, case,
        "all four input frames must already be canonical current frames"
    );
    actual
}

fn capture_record<T>(
    name: &str,
    proposed: &Value,
    constructor: Option<&Value>,
    replacement_index: Option<usize>,
) -> Value
where
    T: NoritoSchema + NoritoSerialize + for<'de> NoritoDeserialize<'de> + Clone + Debug + PartialEq,
{
    assert_eq!(T::nominal_name(), name);
    assert_eq!(T::frame_name(), name);
    assert_eq!(nominal(proposed), name);
    let old_cases = proposed
        .get("cases")
        .and_then(Value::as_array)
        .expect("proposed cases");
    assert!(!old_cases.is_empty() && old_cases.len() <= MAX_CASES);
    let replacement = constructor.map(|row| {
        assert_eq!(nominal(row), name);
        let fields = frame_fields(row);
        exact_current_case::<T>(&fields)
    });
    if let Some(index) = replacement_index {
        assert!(
            index < old_cases.len() && replacement.is_some(),
            "explicit Kaigi case has a current constructor"
        );
    } else if replacement.is_some() {
        assert_eq!(
            old_cases.len(),
            1,
            "single current constructor cannot omit other fixture cases"
        );
    }
    let cases = old_cases
        .iter()
        .enumerate()
        .map(|(index, old)| {
            if let Some(current) = &replacement
                && replacement_index.is_none_or(|selected| selected == index)
            {
                return current.clone();
            }
            exact_current_case::<T>(old)
        })
        .collect();
    let hash = hex::encode(norito::schema::identity::frame_hash::<T>());
    json::object([
        ("nominal", Value::String(name.to_owned())),
        ("serialize_hash", Value::String(hash.clone())),
        ("deserialize_hash", Value::String(hash)),
        ("cases", Value::Array(cases)),
    ])
    .expect("current native record")
}

fn complete_rows(
    records: &[Record],
    proposed: &BTreeMap<String, Value>,
    constructors: &BTreeMap<String, Value>,
) -> Vec<Value> {
    assert!(!records.is_empty() && records.len() <= MAX_RECORDS);
    let names: BTreeSet<_> = records.iter().map(|record| record.nominal).collect();
    assert_eq!(
        names.len(),
        records.len(),
        "typed inventory contains no duplicate records"
    );
    assert_eq!(
        names,
        proposed.keys().map(String::as_str).collect(),
        "complete typed/proposed record inventories"
    );
    assert!(
        constructors
            .keys()
            .all(|name| names.contains(name.as_str())),
        "every current constructor has a typed inventory owner"
    );
    let mut rows = Vec::with_capacity(records.len());
    let mut bytes = 0_usize;
    for record in records {
        let row = (record.capture)(
            record.nominal,
            &proposed[record.nominal],
            constructors.get(record.nominal),
            record.replacement_index,
        );
        let encoded = json::to_json(&row).expect("native record JSON");
        bytes = bytes
            .checked_add(encoded.len())
            .expect("complete capture length");
        assert!(bytes <= MAX_CAPTURE_BYTES);
        rows.push(row);
    }
    rows.sort_by(|left, right| nominal(left).cmp(nominal(right)));
    rows
}

/// Print a complete current capture only after every typed record has succeeded.
pub(super) fn print_all(records: &[Record]) {
    let proposed = proposed_rows(SOURCE);
    let constructors = current_constructors();
    let rows = complete_rows(records, &proposed, &constructors);
    let document = json::object([
        ("schema", Value::from(1_u64)),
        (
            "input_sha256",
            Value::String(hex::encode(Sha256::digest(SOURCE.as_bytes()))),
        ),
        (
            "constructor_replacements",
            Value::Array(constructors.keys().cloned().map(Value::String).collect()),
        ),
        ("rows", Value::Array(rows)),
    ])
    .expect("complete native capture document");
    let encoded = json::to_json(&document).expect("serialize native capture document");
    assert!(encoded.len() <= MAX_CAPTURE_BYTES);
    let digest = hex::encode(Sha256::digest(encoded.as_bytes()));
    writeln!(
        std::io::stdout().lock(),
        "NATIVE_RECORD_FRAMES_V1\t{digest}\t{encoded}"
    )
    .expect("write complete native record capture");
}

#[test]
fn current_frame_capture_preserves_all_cases_and_rejects_omissions() {
    let name = <u64 as NoritoSchema>::nominal_name();
    let make_row = |values: &[u64]| {
        json::object([
            ("nominal", Value::String(name.clone())),
            (
                "cases",
                Value::Array(
                    values
                        .iter()
                        .map(|value| frame_fields(&capture(*value)))
                        .collect(),
                ),
            ),
        ])
        .unwrap()
    };
    let proposed = make_row(&[7, 9]);
    let current = capture_record::<u64>(&name, &proposed, None, None);
    assert_eq!(current.get("cases"), proposed.get("cases"));
    let replacement = capture(11_u64);
    let replaced = capture_record::<u64>(&name, &proposed, Some(&replacement), Some(1));
    let cases = replaced.get("cases").and_then(Value::as_array).unwrap();
    assert_eq!(cases[0], frame_fields(&capture(7_u64)));
    assert_eq!(cases[1], frame_fields(&capture(11_u64)));
    assert!(
        std::panic::catch_unwind(|| capture_record::<u64>(
            &name,
            &proposed,
            Some(&replacement),
            None
        ))
        .is_err()
    );
    assert!(
        std::panic::catch_unwind(|| capture_record::<u64>(
            &name,
            &proposed,
            Some(&replacement),
            Some(2)
        ))
        .is_err()
    );
    assert!(
        std::panic::catch_unwind(|| capture_record::<u64>(&name, &proposed, None, Some(1)))
            .is_err()
    );
    assert!(
        std::panic::catch_unwind(|| unique_rows(vec![proposed.clone(), proposed.clone()])).is_err()
    );
    assert!(std::panic::catch_unwind(|| proposed_rows("{}")).is_err());
    let bad_frame = json::object([("frame", Value::String("GG".to_owned()))]).unwrap();
    assert!(std::panic::catch_unwind(|| decode_current::<u64>(&bad_frame)).is_err());
}

#[test]
fn complete_native_capture_rejects_missing_or_unowned_records() {
    let name = <u64 as NoritoSchema>::nominal_name();
    assert_eq!(name, "u64");
    let proposed = unique_rows(vec![
        json::object([
            ("nominal", Value::String(name.clone())),
            ("cases", Value::Array(vec![frame_fields(&capture(7_u64))])),
        ])
        .unwrap(),
    ]);
    let records = [Record::new::<u64>("u64", None)];
    let rows = complete_rows(&records, &proposed, &BTreeMap::new());
    assert_eq!(rows.len(), 1);
    assert!(
        std::panic::catch_unwind(|| complete_rows(&records, &BTreeMap::new(), &BTreeMap::new()))
            .is_err()
    );
    let unowned = BTreeMap::from([("unowned".to_owned(), capture(3_u64))]);
    assert!(std::panic::catch_unwind(|| complete_rows(&records, &proposed, &unowned)).is_err());
}
