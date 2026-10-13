//! Captured schema identities and complete frames for generated instruction records.

use std::{collections::BTreeMap, fmt::Debug, sync::OnceLock};

use norito::{
    NoritoDeserialize, NoritoSchema, NoritoSerialize,
    json::{self, Value},
};

#[path = "generated_record_values.rs"]
mod values;

#[path = "generated_record_inventory.rs"]
mod inventory;

#[path = "kaigi_record_identity_tests.rs"]
mod kaigi_records;

mod native_capture;

use crate::fixture_json;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for byte in bytes {
        write!(out, "{byte:02x}").expect("String formatting");
    }
    out
}

fn frame<T>(value: &T) -> String
where
    T: NoritoSerialize + for<'de> NoritoDeserialize<'de> + Debug + PartialEq,
{
    let bytes = norito::to_bytes(value).expect("encode instruction record frame");
    let decoded: T = norito::decode_from_bytes(&bytes)
        .unwrap_or_else(|error| panic!("decode {} frame: {error}", core::any::type_name::<T>()));
    assert_eq!(&decoded, value);
    assert_eq!(norito::to_bytes(&decoded).expect("reencode record"), bytes);
    hex(&bytes)
}

/// Render the declared identity and complete root and container frames for comparison.
pub fn capture<T>(value: T) -> Value
where
    T: NoritoSchema + NoritoSerialize + for<'de> NoritoDeserialize<'de> + Clone + Debug + PartialEq,
{
    let identity = norito::schema::identity::frame_hash::<T>();
    assert_eq!(identity, norito::schema::identity::frame_hash::<T>());
    assert_eq!(identity, norito::schema::identity::frame_hash::<T>());
    json::object([
        ("nominal", Value::String(T::nominal_name())),
        (
            "serialize_hash",
            Value::String(hex(&norito::schema::identity::frame_hash::<T>())),
        ),
        (
            "deserialize_hash",
            Value::String(hex(&norito::schema::identity::frame_hash::<T>())),
        ),
        ("frame", Value::String(frame(&value))),
        ("vector_frame", Value::String(frame(&vec![value.clone()]))),
        ("option_frame", Value::String(frame(&Some(value.clone())))),
        (
            "map_frame",
            Value::String(frame(&BTreeMap::from([(7_u8, value)]))),
        ),
    ])
    .expect("generated instruction record")
}

/// Capture the populated staking records whose required monetary plans changed.
pub fn staking_monetary_fixture_rows() -> Vec<Value> {
    values::values()
        .into_iter()
        .filter(|row| {
            row.get("nominal")
                .and_then(Value::as_str)
                .is_some_and(|name| name.contains("::staking::"))
        })
        .collect()
}

fn missing_record_values() -> Vec<Value> {
    let mut records = values::values();
    records.extend(super::musubi::generated_identity_values::values());
    records.extend(super::private_settlement::generated_identity_values::values());
    records.push(capture(
        super::privacy::RegisterPrivacyExact12QualificationV1::new(
            crate::privacy::tests::generated_instruction_qualification(),
        ),
    ));
    assert_eq!(
        records.len(),
        49,
        "complete missing record fixture inventory"
    );
    let names: std::collections::BTreeSet<_> = records
        .iter()
        .map(|row| row.get("nominal").and_then(Value::as_str).expect("nominal"))
        .collect();
    assert_eq!(names.len(), 49, "one populated value per missing record");
    records.sort_by(|a, b| {
        a.get("nominal")
            .and_then(Value::as_str)
            .cmp(&b.get("nominal").and_then(Value::as_str))
    });
    records
}

fn captured(nominal: &str) -> &'static Value {
    static CAPTURE: OnceLock<Value> = OnceLock::new();
    let rows = CAPTURE
        .get_or_init(|| {
            use sha2::{Digest as _, Sha256};

            let source = include_str!(
                "../../tests/fixtures/instruction_record_generated_identity_frames.json"
            );
            assert_eq!(
                hex(&Sha256::digest(source.as_bytes())),
                "21084b066d6536a22354958e0bf9e42a64096a6c07347ebf4140cadc0cd05804",
                "instruction record capture digest drift"
            );
            let capture: Value =
                json::from_str(source).expect("immutable instruction record capture");
            let rows = capture.as_array().expect("captured type rows");
            assert_eq!(rows.len(), 332, "complete instantiated record inventory");
            let mut previous = None;
            let mut case_count = 0;
            for row in rows {
                let nominal = row
                    .get("nominal")
                    .and_then(Value::as_str)
                    .expect("captured nominal");
                if let Some(previous) = previous {
                    assert!(previous < nominal, "captured nominals are strictly sorted");
                }
                previous = Some(nominal);
                case_count += row
                    .get("cases")
                    .and_then(Value::as_array)
                    .expect("captured cases")
                    .len();
            }
            assert_eq!(case_count, 375, "complete populated record case inventory");
            capture
        })
        .as_array()
        .expect("captured type rows");
    assert_eq!(rows.len(), 332, "complete instantiated record inventory");
    let mut matches = rows
        .iter()
        .filter(|row| row.get("nominal").and_then(Value::as_str) == Some(nominal));
    let row = matches.next().expect("captured type");
    assert!(matches.next().is_none(), "exactly one captured type row");
    row
}

fn frame_fields(row: &Value) -> Value {
    json::object(
        ["frame", "vector_frame", "option_frame", "map_frame"].map(|key| {
            (
                key,
                row.get(key).expect("complete captured frame set").clone(),
            )
        }),
    )
    .expect("frame case")
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("fixture hex UTF8"), 16)
                .expect("fixture hex byte")
        })
        .collect()
}

fn check<T>(nominal: &str)
where
    T: NoritoSchema + NoritoSerialize + for<'de> NoritoDeserialize<'de> + Clone + Debug + PartialEq,
{
    assert_eq!(T::nominal_name(), nominal, "captured compiler identity");
    assert_eq!(T::frame_name(), nominal, "captured frame identity");
    let row = captured(nominal);
    assert_eq!(
        row.get("serialize_hash").and_then(Value::as_str),
        Some(hex(&norito::schema::identity::frame_hash::<T>()).as_str())
    );
    assert_eq!(
        row.get("deserialize_hash").and_then(Value::as_str),
        Some(hex(&norito::schema::identity::frame_hash::<T>()).as_str())
    );
    let cases = row
        .get("cases")
        .and_then(Value::as_array)
        .expect("captured cases");
    assert!(!cases.is_empty(), "every type has a populated frame");
    for expected in cases {
        let bytes = unhex(
            expected
                .get("frame")
                .and_then(Value::as_str)
                .expect("root frame"),
        );
        let value: T = norito::decode_from_bytes(&bytes)
            .unwrap_or_else(|error| panic!("decode captured {nominal}: {error}"));
        let actual = frame_fields(&capture(value));
        fixture_json::assert_json_matches(expected, &actual, nominal);
    }
}

#[test]
fn retired_load_instruction_without_asset_and_ordinal_is_rejected() {
    // Exact retired root frames before and after the verifier-install variant
    // was added. The latter uses the current IssueLoad tag but still lacks the
    // required asset/ordinal fields; neither payload may be decoded.
    for retired in [
        "4e52543000008eef66c2b4be9ed7b2604aec85793350007b000000000000000a09ab00d41fc01a020000000000000000200101010101010101010101010101010101010101010101010101010101010101590400000020020202020202020202020202020202020202020202020202020202020202020220030303030303030303030303030303030303030303030303030303030303030310070000000000000000000000000000000100",
        "4e52543000008eef66c2b4be9ed7b2604aec85793350007b00000000000000d6e8c972dd8bf2a0020000000000000000200101010101010101010101010101010101010101010101010101010101010101590500000020020202020202020202020202020202020202020202020202020202020202020220030303030303030303030303030303030303030303030303030303030303030310070000000000000000000000000000000100",
    ] {
        let retired = unhex(retired);
        assert!(
            norito::decode_from_bytes::<super::kagemusha_wallet::KagemushaWalletLedgerV1>(&retired)
                .is_err(),
            "retired Load instructions must not decode"
        );
    }
}

#[test]
fn populated_record_values_preserve_the_original_capture() {
    for actual in missing_record_values() {
        let nominal = actual
            .get("nominal")
            .and_then(Value::as_str)
            .expect("nominal");
        let expected = captured(nominal);
        for key in ["nominal", "serialize_hash", "deserialize_hash"] {
            fixture_json::assert_json_matches(
                expected.get(key).expect("identity"),
                actual.get(key).expect("actual identity"),
                nominal,
            );
        }
        let cases = expected
            .get("cases")
            .and_then(Value::as_array)
            .expect("cases");
        assert_eq!(cases.len(), 1, "one original populated value for each gap");
        fixture_json::assert_json_matches(&cases[0], &frame_fields(&actual), nominal);
    }
}

#[test]
#[ignore = "explicit maintenance command prints the canonical privacy qualification record"]
fn print_privacy_qualification_record_fixture_row() {
    let row = capture(super::privacy::RegisterPrivacyExact12QualificationV1::new(
        crate::privacy::tests::generated_instruction_qualification(),
    ));
    println!(
        "PRIVACY_QUALIFICATION_FIXTURE_ROW={}",
        json::to_json(&row).expect("privacy qualification record")
    );
}

#[test]
#[ignore = "explicit maintenance command captures recovery instructions with required generations"]
fn print_recovery_generation_record_fixture_rows() {
    use std::num::NonZeroU64;

    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_model_base::topology::DataSpaceId;

    use crate::{
        account::{AccountAlias, AccountAliasDomain, AccountController},
        isi::account_recovery::{
            ApproveAccountRecovery, CancelAccountRecovery, FinalizeAccountRecovery,
            ProposeAccountRecovery,
        },
    };

    fn row<T>(values: Vec<T>) -> Value
    where
        T: NoritoSchema
            + NoritoSerialize
            + for<'de> NoritoDeserialize<'de>
            + Clone
            + Debug
            + PartialEq,
    {
        let hash = hex(&norito::schema::identity::frame_hash::<T>());
        json::object([
            ("nominal", Value::String(T::nominal_name())),
            ("serialize_hash", Value::String(hash.clone())),
            ("deserialize_hash", Value::String(hash)),
            (
                "cases",
                Value::Array(
                    values
                        .into_iter()
                        .map(|value| frame_fields(&capture(value)))
                        .collect(),
                ),
            ),
        ])
        .expect("current recovery instruction row")
    }

    let alias = AccountAlias::new(
        "recoverable".parse().unwrap(),
        Some(AccountAliasDomain::new("banka".parse().unwrap())),
        DataSpaceId::UNIVERSAL,
    );
    let generation = NonZeroU64::new(17).unwrap();
    let proposals = [0xD6, 0xDB]
        .into_iter()
        .map(|seed| {
            let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                .expect("deterministic recovery fixture key");
            ProposeAccountRecovery::new(
                alias.clone(),
                AccountController::single(key.public_key().clone()),
                generation,
            )
        })
        .collect();
    let rows = vec![
        row(vec![ApproveAccountRecovery::new(alias.clone(), generation)]),
        row(vec![CancelAccountRecovery::new(alias.clone(), generation)]),
        row(vec![FinalizeAccountRecovery::new(alias, generation)]),
        row(proposals),
    ];
    println!(
        "RECOVERY_GENERATION_FIXTURE_ROWS={}",
        json::to_json(&rows).expect("canonical recovery instruction rows")
    );
}

#[test]
#[ignore = "explicit maintenance command captures deployment instructions with explicit artifact dataspaces"]
fn print_contract_artifact_record_fixture_rows() {
    use iroha_crypto::Hash;
    use iroha_model_base::topology::DataSpaceId;

    use crate::{
        isi::smart_contract_code::{
            CancelSmartContractCodeUpload, FinalizeSmartContractCodeUpload,
            RegisterSmartContractBytes, RegisterSmartContractCode, RemoveSmartContractBytes,
            UploadSmartContractCodeChunk,
        },
        smart_contract::{ContractArtifactId, manifest::ContractManifest},
    };

    let code_hash = Hash::new(b"contract-code");
    let abi_hash = Hash::new(b"abi-policy");
    assert_eq!(
        hex(code_hash.as_ref()),
        "5b3985441f11d36cc02dd108562faf5d4b8d5f3b13fb79b6d0f094ab648755f1"
    );
    assert_eq!(
        hex(abi_hash.as_ref()),
        "18b2577f70fcf90193eff287aacd10b76dd36b99c0f5935fdcc67443f8bc148d"
    );
    // Preserve both original cases in their declared order: full-width and universal.
    // Every frame is constructed and round-tripped by the current native codec.
    let mut rows = BTreeMap::<String, Value>::new();
    for dataspace in [DataSpaceId::new(u64::MAX), DataSpaceId::UNIVERSAL] {
        let artifact_id = ContractArtifactId::new(dataspace, code_hash);
        let values = vec![
            capture(CancelSmartContractCodeUpload { artifact_id }),
            capture(FinalizeSmartContractCodeUpload {
                artifact_id,
                total_size: 3,
                chunk_count: 1,
            }),
            capture(RegisterSmartContractBytes {
                artifact_id,
                code: vec![1, 2, 3],
            }),
            capture(RegisterSmartContractCode {
                artifact_id,
                manifest: ContractManifest {
                    permissions: Vec::new(),
                    events: Vec::new(),
                    enum_types: Vec::new(),
                    seiyaku_name: None,
                    code_hash: Some(code_hash),
                    abi_hash: Some(abi_hash),
                    compiler_fingerprint: Some("kotodama-1.2.3".to_owned()),
                    features_bitmap: Some(0),
                    access_set_hints: None,
                    entrypoints: None,
                    states: None,
                    error_types: None,
                    error_messages: None,
                    kotoba: None,
                    provenance: None,
                },
            }),
            capture(RemoveSmartContractBytes {
                artifact_id,
                reason: Some("superseded".to_owned()),
            }),
            capture(UploadSmartContractCodeChunk {
                artifact_id,
                total_size: 3,
                chunk_index: 0,
                chunk_count: 1,
                chunk: vec![1, 2, 3],
            }),
        ];
        for value in values {
            let name = value
                .get("nominal")
                .and_then(Value::as_str)
                .unwrap()
                .to_owned();
            let row = rows.entry(name).or_insert_with(|| {
                json::object([
                    ("nominal", value.get("nominal").unwrap().clone()),
                    (
                        "serialize_hash",
                        value.get("serialize_hash").unwrap().clone(),
                    ),
                    (
                        "deserialize_hash",
                        value.get("deserialize_hash").unwrap().clone(),
                    ),
                    ("cases", Value::Array(Vec::new())),
                ])
                .expect("current contract artifact instruction row")
            });
            let Value::Array(cases) = row.get_mut("cases").expect("cases") else {
                panic!("native record cases are an array");
            };
            cases.push(frame_fields(&value));
        }
    }
    let rows: Vec<_> = rows.into_values().collect();
    assert_eq!(rows.len(), 6);
    assert!(
        rows.iter()
            .all(|row| row.get("cases").and_then(Value::as_array).unwrap().len() == 2)
    );
    println!(
        "CONTRACT_ARTIFACT_FIXTURE_ROWS={}",
        json::to_json(&rows).expect("canonical contract artifact instruction rows")
    );
}

#[test]
#[ignore = "explicit maintenance command captures first-release SoraFS instruction frames"]
fn print_capacity_declaration_record_fixture_row() {
    for (label, row) in [
        "CAPACITY_DECLARATION_FIXTURE_ROW",
        "INITIALIZE_SORAFS_ADMISSION_FIXTURE_ROW",
        "ASSERT_SORAFS_PUBLICATION_FIXTURE_ROW",
    ]
    .into_iter()
    .zip(native_capture::sorafs_values())
    {
        println!("{label}={}", json::to_json(&row).expect("SoraFS record"));
    }
}
