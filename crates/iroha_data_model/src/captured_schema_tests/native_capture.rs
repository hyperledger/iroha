//! Bounded native identity output from existing owner-private typed inventories.
//!
//! This module is test-only. Explicit ignored maintenance tests print public
//! identities; ordinary checks compare the same bounded typed documents without printing.

use super::{Case, NoritoDeserialize, NoritoSchema, NoritoSerialize};
use norito::json::{self, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io::Write};

const MAX_OWNER_ROWS: usize = 4_096;
const MAX_IDENTITY_BYTES: usize = 4_096;
const MAX_ROW_BYTES: usize = 32 * 1_024;
const MAX_OWNER_BYTES: usize = 8 * 1_024 * 1_024;

/// Current declared identity and only the codec directions supported by its owner.
pub(super) struct Identity {
    nominal: String,
    root: String,
    hash: [u8; 16],
    serialize: bool,
    deserialize: bool,
}

fn identity<T: NoritoSchema>(nominal: &str, serialize: bool, deserialize: bool) -> Identity {
    let actual = T::nominal_name();
    let root = T::frame_name();
    assert_eq!(actual, nominal, "current typed nominal identity");
    assert!(!actual.is_empty() && actual.len() <= MAX_IDENTITY_BYTES);
    assert!(!root.is_empty() && root.len() <= MAX_IDENTITY_BYTES);
    Identity {
        nominal: actual,
        root,
        hash: norito::schema::identity::frame_hash::<T>(),
        serialize,
        deserialize,
    }
}

pub(super) fn serialize<T: NoritoSchema + NoritoSerialize>(nominal: &str) -> Identity {
    identity::<T>(nominal, true, false)
}

pub(super) fn deserialize<T>(nominal: &str) -> Identity
where
    T: NoritoSchema + for<'a> NoritoDeserialize<'a>,
{
    identity::<T>(nominal, false, true)
}

pub(super) fn bidirectional<T>(nominal: &str) -> Identity
where
    T: NoritoSchema + NoritoSerialize + for<'a> NoritoDeserialize<'a>,
{
    identity::<T>(nominal, true, true)
}

impl Identity {
    fn row(self) -> Value {
        let mut fields = vec![
            ("nominal", Value::String(self.nominal)),
            ("root", Value::String(self.root)),
        ];
        if self.serialize {
            fields.push(("serialize_hash", Value::String(hex::encode(self.hash))));
        }
        if self.deserialize {
            fields.push(("deserialize_hash", Value::String(hex::encode(self.hash))));
        }
        json::object(fields).expect("native identity object")
    }
}

fn owner_document(cases: &[Case], owner: &str) -> Vec<u8> {
    assert!(!owner.is_empty() && owner.len() <= MAX_IDENTITY_BYTES);
    assert!(!cases.is_empty() && cases.len() <= MAX_OWNER_ROWS);
    let mut names = BTreeSet::new();
    let mut rows = Vec::with_capacity(cases.len());
    let mut row_bytes = 0_usize;
    for case in cases {
        assert!(
            names.insert(case.nominal),
            "duplicate typed capture identity"
        );
        let row = (case.capture)(case.nominal).row();
        let encoded = json::to_json(&row).expect("serialize native identity");
        assert!(encoded.len() <= MAX_ROW_BYTES);
        row_bytes = row_bytes.checked_add(encoded.len()).expect("capture size");
        assert!(row_bytes <= MAX_OWNER_BYTES);
        rows.push(row);
    }
    let body = json::object([
        ("schema", Value::from(1_u64)),
        ("owner", Value::String(owner.to_owned())),
        ("rows", Value::Array(rows)),
    ])
    .expect("native owner document");
    let encoded = json::to_json(&body).expect("serialize native owner");
    assert!(encoded.len() <= MAX_OWNER_BYTES);
    encoded.into_bytes()
}

/// Emit one bounded owner document with a digest of its exact UTF-8 JSON bytes.
///
/// A single stdout lock prevents parallel test output from interleaving inside
/// the record. Collection must still require every expected compiled owner.
pub fn print_owner(cases: &[Case], owner: &str) {
    let document = owner_document(cases, owner);
    let digest = hex::encode(Sha256::digest(&document));
    let mut output = std::io::stdout().lock();
    write!(output, "NATIVE_CODEC_OWNER_V1\t{digest}\t").expect("write capture prefix");
    output
        .write_all(&document)
        .expect("write native owner capture");
    writeln!(output).expect("finish native owner capture");
}

macro_rules! owner_printer {
    ($cases:expr) => {
        #[test]
        fn current_native_codec_identities_match_paired_capture() {
            $crate::captured_schema_tests::native_capture::assert_current_owner(
                $cases,
                module_path!(),
            );
        }

        #[test]
        #[ignore = "explicit maintenance capture of current typed codec identities"]
        fn print_native_codec_capture_v1() {
            $crate::captured_schema_tests::native_capture::print_owner($cases, module_path!());
        }
    };
}
pub(crate) use owner_printer;

#[test]
fn current_capture_keeps_direction_bounds_and_exact_identity() {
    let nominal = <u64 as NoritoSchema>::nominal_name();
    let identity = serialize::<u64>(&nominal).row();
    assert_eq!(
        identity.get("nominal").and_then(Value::as_str),
        Some(nominal.as_str())
    );
    assert_eq!(
        identity.get("root").and_then(Value::as_str),
        Some(<u64 as NoritoSchema>::frame_name().as_str())
    );
    assert_eq!(
        identity.get("serialize_hash").and_then(Value::as_str),
        Some(hex::encode(norito::schema::identity::frame_hash::<u64>()).as_str())
    );
    assert!(identity.get("deserialize_hash").is_none());
    let decoder = deserialize::<u64>(&nominal).row();
    assert!(decoder.get("serialize_hash").is_none());
    assert!(decoder.get("deserialize_hash").is_some());
    let both = bidirectional::<u64>(&nominal).row();
    assert_eq!(both.get("serialize_hash"), both.get("deserialize_hash"));
}

#[test]
fn owner_capture_rejects_duplicates_wrong_identity_and_output_bounds() {
    fn callback(nominal: &str) -> Identity {
        identity::<u64>(nominal, true, true)
    }
    let nominal = <u64 as NoritoSchema>::nominal_name();
    assert_eq!(nominal, "u64");
    let case = || Case::bidirectional::<u64>("u64");
    let bytes = owner_document(&[case()], "native_test_owner");
    let parsed: Value = json::from_slice(&bytes).expect("capture JSON");
    assert_eq!(
        parsed.get("rows").and_then(Value::as_array).unwrap().len(),
        1
    );
    assert!(std::panic::catch_unwind(|| owner_document(&[case(), case()], "owner")).is_err());
    assert!(std::panic::catch_unwind(|| owner_document(&[], "owner")).is_err());
    assert!(
        std::panic::catch_unwind(|| owner_document(&[case()], &"x".repeat(MAX_IDENTITY_BYTES + 1)))
            .is_err()
    );
    assert!(std::panic::catch_unwind(|| callback("wrong-name")).is_err());
}

fn current_owner_fixture() -> &'static std::collections::BTreeMap<String, Value> {
    use std::{collections::BTreeMap, sync::OnceLock};
    static FIXTURE: OnceLock<BTreeMap<String, Value>> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let source =
            include_str!("../../tests/fixtures/native_current_codec_owner_identities.json");
        assert_eq!(
            hex::encode(Sha256::digest(source.as_bytes())),
            "1b809fde05de75fdec361d76391359a02a360e490870646b74d0b01fbdd9595a"
        );
        let document: Value = json::from_str(source).expect("paired native owner inventory");
        assert_eq!(
            document
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["schema", "owners"])
        );
        assert_eq!(document.get("schema").and_then(Value::as_u64), Some(1));
        let owners = document.get("owners").and_then(Value::as_array).unwrap();
        assert_eq!(owners.len(), 102, "complete current compiler owner census");
        let mut result = BTreeMap::new();
        let mut roots = BTreeMap::new();
        let mut directions = BTreeMap::new();
        for owner in owners {
            assert_eq!(
                owner
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from(["schema", "owner", "rows"])
            );
            assert_eq!(owner.get("schema").and_then(Value::as_u64), Some(1));
            let name = owner.get("owner").and_then(Value::as_str).unwrap();
            assert!(!name.is_empty() && name.len() <= MAX_IDENTITY_BYTES);
            let rows = owner.get("rows").and_then(Value::as_array).unwrap();
            assert!(!rows.is_empty() && rows.len() <= MAX_OWNER_ROWS);
            let mut names = BTreeSet::new();
            for row in rows {
                let nominal = row.get("nominal").and_then(Value::as_str).unwrap();
                let root = row.get("root").and_then(Value::as_str).unwrap();
                assert!(!nominal.is_empty() && nominal.len() <= MAX_IDENTITY_BYTES);
                assert!(!root.is_empty() && root.len() <= MAX_IDENTITY_BYTES);
                assert!(names.insert(nominal), "duplicate owner-local nominal");
                if let Some(previous) = roots.insert(nominal.to_owned(), root.to_owned()) {
                    assert_eq!(previous, root);
                }
                let mut keys = BTreeSet::from(["nominal", "root"]);
                for direction in ["serialize_hash", "deserialize_hash"] {
                    if row.get(direction).is_some() {
                        keys.insert(direction);
                        let hash = super::expected_hash(row, direction);
                        if let Some(previous) =
                            directions.insert((nominal.to_owned(), direction), hash)
                        {
                            assert_eq!(previous, hash);
                        }
                    }
                }
                assert!(keys.len() > 2, "each typed owner supplies an actual codec");
                assert_eq!(
                    row.as_object()
                        .unwrap()
                        .keys()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>(),
                    keys
                );
            }
            assert!(
                result.insert(name.to_owned(), owner.clone()).is_none(),
                "duplicate captured owner"
            );
        }
        assert_eq!(roots.len(), 1_469, "complete current nominal inventory");
        result
    })
}

/// Assert a changed first-release codec against its retained current compiler output.
pub(super) fn assert_current_identity<T>(nominal: &str)
where
    T: NoritoSchema + NoritoSerialize + for<'a> NoritoDeserialize<'a>,
{
    let actual = bidirectional::<T>(nominal).row();
    let mut matches = current_owner_fixture()
        .values()
        .flat_map(|owner| owner["rows"].as_array().expect("current owner rows"))
        .filter(|row| row["nominal"].as_str() == Some(nominal));
    let expected = matches.next().expect("current compiler-captured identity");
    assert_eq!(&actual, expected);
    for duplicate in matches {
        assert_eq!(duplicate, expected, "shared current identities agree");
    }
}

/// Compare this exact typed inventory with its separately retained paired native output.
/// Historical captures retain their original bytes; retired owners are not revived.
pub fn assert_current_owner(cases: &[Case], owner: &str) {
    let bytes = owner_document(cases, owner);
    let actual: Value = json::from_slice(&bytes).expect("current typed owner document");
    let expected = current_owner_fixture()
        .get(owner)
        .expect("every current owner is captured");
    let expected = owner_for_current_inventory(expected, cfg!(feature = "governance"));
    assert_eq!(
        actual, expected,
        "current codec owner or directional identity changed"
    );
}

#[test]
fn current_native_fixture_has_complete_owner_inventory() {
    assert_eq!(current_owner_fixture().len(), 102);
}

// Apply only the closed feature conditions in the current typed inventory.
// The current fixture already excludes retired governance owners.
fn owner_for_current_inventory(owner: &Value, governance: bool) -> Value {
    let name = owner.get("owner").and_then(Value::as_str).unwrap();
    let removed: &[&str] = match name {
        "iroha_data_model::fraud::types::captured_types_schema_tests" if !governance => &[
            "iroha_data_model::fraud::types::GovernanceExport",
            "iroha_data_model::fraud::types::DecisionAggregate",
        ],
        _ => return owner.clone(),
    };
    let rows = owner.get("rows").and_then(Value::as_array).unwrap();
    assert_eq!(
        rows.len(),
        9,
        "the complete feature-shaped source inventory has nine rows"
    );
    let actual_removed = rows
        .iter()
        .filter_map(|row| {
            let nominal = row.get("nominal").and_then(Value::as_str).unwrap();
            removed.contains(&nominal).then_some(nominal)
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_removed, removed.iter().copied().collect());
    let rows = rows
        .iter()
        .filter(|row| {
            let nominal = row.get("nominal").and_then(Value::as_str).unwrap();
            !removed.contains(&nominal)
        })
        .cloned()
        .collect();
    json::object([
        ("schema", owner.get("schema").unwrap().clone()),
        ("owner", owner.get("owner").unwrap().clone()),
        ("rows", Value::Array(rows)),
    ])
    .expect("explicit governance feature projection")
}

#[test]
fn current_owner_inventory_excludes_retired_types_under_every_feature_shape() {
    let owners = current_owner_fixture();
    for (name, owner) in owners {
        let complete = owner_for_current_inventory(owner, true);
        if name == "iroha_data_model::captured_schema_tests::current_release_capture" {
            assert_eq!(complete["rows"].as_array().unwrap().len(), 1);
            assert!(complete["rows"].as_array().unwrap().iter().all(|row| {
                !row["nominal"]
                    .as_str()
                    .unwrap()
                    .contains("KagemushaVerifier")
            }));
        } else if name == "iroha_data_model::nexus::staking::captured_staking_schema_tests" {
            let rows = complete["rows"].as_array().expect("current staking rows");
            assert_eq!(
                rows.len(),
                5,
                "only current automatic-reward staking models"
            );
            for retired in [
                "PublicLaneRewardShare",
                "PublicLaneRewardRole",
                "PublicLaneRewardRecord",
            ] {
                assert!(
                    rows.iter()
                        .all(|row| !row["nominal"].as_str().unwrap().ends_with(retired))
                );
            }
        } else {
            assert_eq!(complete, *owner);
        }
        let minimal = owner_for_current_inventory(owner, false);
        let expected = match name.as_str() {
            "iroha_data_model::captured_schema_tests::current_release_capture" => 1,
            "iroha_data_model::fraud::types::captured_types_schema_tests" => 7,
            _ => {
                assert_eq!(minimal, *owner);
                continue;
            }
        };
        assert_eq!(
            minimal.get("rows").and_then(Value::as_array).unwrap().len(),
            expected
        );
        assert_eq!(minimal.get("owner"), owner.get("owner"));
        assert_eq!(minimal.get("schema"), owner.get("schema"));
    }
}
