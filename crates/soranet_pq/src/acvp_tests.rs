//! Shared readers for the pinned, independently generated NIST ACVP subset.

use std::sync::LazyLock;

use norito::json::Value;

const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/acvp/vectors.json");
static VECTORS: LazyLock<Value> =
    LazyLock::new(|| norito::json::from_slice(FIXTURE).expect("pinned ACVP JSON"));

pub(crate) fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).expect(key)
}

pub(crate) fn bytes(value: &Value, key: &str) -> Vec<u8> {
    let encoded = text(value, key);
    let mut decoded = vec![0; encoded.len() / 2];
    hex::decode_to_slice(encoded, &mut decoded).expect("complete ACVP hex bytes");
    decoded
}

pub(crate) fn number(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).expect(key)
}

pub(crate) fn passed(value: &Value) -> bool {
    value
        .get("testPassed")
        .and_then(Value::as_bool)
        .expect("official ACVP disposition")
}

pub(crate) fn cases(group: &Value) -> &[Value] {
    group.get("tests").and_then(Value::as_array).expect("cases")
}

pub(crate) fn groups(source: &str) -> &'static [Value] {
    VECTORS
        .get("vector_sets")
        .and_then(Value::as_array)
        .expect("vector sets")
        .iter()
        .find(|set| text(set, "source") == source)
        .expect("selected source")
        .get("testGroups")
        .and_then(Value::as_array)
        .expect("test groups")
}

#[test]
fn tracked_subset_has_the_independently_pinned_digest() {
    assert_eq!(
        crate::nistkat_sha256::sha256_hex(FIXTURE),
        "d9d0a4d7e15e07df887d8fd068e9cea86d2580ec179b47fa5b04cb4a00815860"
    );
    assert_eq!(
        text(&VECTORS, "upstream_revision"),
        "975de31eb83d87039ec88934fdc47d8c312b892d"
    );
}

#[test]
fn subset_has_exact_nonempty_groups_and_unique_cases() {
    for (source, group_count, case_count) in [
        ("ML-KEM-keyGen-FIPS203", 3, 3),
        ("ML-KEM-encapDecap-FIPS203-tr1", 12, 21),
        ("ML-DSA-keyGen-FIPS204", 3, 3),
        ("ML-DSA-sigGen-FIPS204-tr1", 3, 8),
        ("ML-DSA-sigVer-FIPS204", 3, 15),
    ] {
        let groups = groups(source);
        assert_eq!(groups.len(), group_count, "{source}");
        let mut group_ids = std::collections::BTreeSet::new();
        let mut case_ids = std::collections::BTreeSet::new();
        for group in groups {
            assert!(group_ids.insert(number(group, "tgId")), "{source}");
            assert!(!cases(group).is_empty(), "{source}");
            for case in cases(group) {
                assert!(case_ids.insert(number(case, "tcId")), "{source}");
            }
        }
        assert_eq!(case_ids.len(), case_count, "{source}");
    }
}
