//! Explicit native maintenance output for the single compiled wire-ID inventory.

use super::wire_ids::{ALL, BuiltInWireId};
use norito::json::{self, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io::Write};

const MAX_ENTRIES: usize = 4_096;
const MAX_LABEL_BYTES: usize = 4_096;
const MAX_ASSIGNMENTS_BYTES: usize = 4 * 1_024 * 1_024;

// `include_governance` selects a diagnostic hash subset only; ALL is always the full registry.
fn assignment_rows(entries: &[BuiltInWireId], include_governance: bool) -> Value {
    assert!(!entries.is_empty() && entries.len() <= MAX_ENTRIES);
    let mut labels = BTreeSet::new();
    let mut wire_ids = BTreeSet::new();
    let mut assignments = Vec::with_capacity(entries.len());
    let mut total = 0_usize;
    for entry in entries
        .iter()
        .filter(|entry| include_governance || !entry.governance_only)
    {
        for label in [entry.type_label, entry.wire_id] {
            assert!(!label.is_empty() && label.len() <= MAX_LABEL_BYTES);
            assert!(
                !label.contains(['\t', '\n', '\r']),
                "ambiguous assignment label"
            );
        }
        assert!(
            labels.insert(entry.type_label),
            "duplicate native type label"
        );
        assert!(wire_ids.insert(entry.wire_id), "duplicate native wire ID");
        let line = format!("{}\t{}\n", entry.type_label, entry.wire_id);
        total = total
            .checked_add(line.len())
            .expect("assignment stream length");
        assert!(total <= MAX_ASSIGNMENTS_BYTES);
        assignments.push(line);
    }
    assignments.sort_unstable();
    let canonical = assignments.concat();
    json::object([
        ("count", Value::from(assignments.len() as u64)),
        (
            "sha256",
            Value::String(hex::encode(Sha256::digest(canonical.as_bytes()))),
        ),
        (
            "assignments",
            Value::Array(assignments.into_iter().map(Value::String).collect()),
        ),
    ])
    .expect("native assignment stream")
}

#[test]
#[ignore = "explicit maintenance capture of compiled type-to-wire-ID assignments"]
fn print_native_wire_id_capture_v1() {
    let document = json::object([
        ("schema", Value::from(1_u64)),
        ("governance_enabled", Value::Bool(true)),
        ("all", assignment_rows(ALL, true)),
        ("without_governance", assignment_rows(ALL, false)),
    ])
    .expect("compiled registry document");
    let encoded = json::to_json(&document).expect("serialize registry capture");
    let digest = hex::encode(Sha256::digest(encoded.as_bytes()));
    writeln!(
        std::io::stdout().lock(),
        "NATIVE_WIRE_IDS_V1\t{digest}\t{encoded}"
    )
    .expect("write native wire IDs");
}

#[test]
fn native_registry_capture_retains_sorted_assignments_and_rejects_collisions() {
    let rows = assignment_rows(ALL, true);
    let assignments = rows.get("assignments").and_then(Value::as_array).unwrap();
    assert_eq!(assignments.len(), ALL.len());
    let strings: Vec<_> = assignments
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert!(strings.windows(2).all(|pair| pair[0] < pair[1]));
    let stream = strings.concat();
    assert_eq!(
        rows.get("sha256").and_then(Value::as_str),
        Some(hex::encode(Sha256::digest(stream.as_bytes())).as_str())
    );
    let expected_without = ALL.iter().filter(|entry| !entry.governance_only).count();
    assert_eq!(
        assignment_rows(ALL, false)
            .get("count")
            .and_then(Value::as_u64),
        Some(expected_without as u64)
    );
    assert!(std::panic::catch_unwind(|| assignment_rows(&[ALL[0], ALL[0]], true)).is_err());
    let mut ambiguous = ALL[0];
    ambiguous.type_label = "injected\tlabel";
    assert!(std::panic::catch_unwind(|| assignment_rows(&[ambiguous], true)).is_err());
}
