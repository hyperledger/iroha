//! Immutable compiler-captured identity checks shared by private model codec owners.
//!
//! These checks preserve named identities and existing directional schema hashes.
//! They do not claim payload equivalence, generic identity closure or release qualification.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize, json::Value};
use sha2::{Digest, Sha256};

/// Bounded, explicitly requested capture of the current typed identity inventory.
pub mod native_capture;

mod current_release_capture;

/// Number of retained nominal codec identities in the reviewed fixture.
const EXPECTED_CODEC_COUNT: usize = 1_559;
const CAPTURE_REPORT_SHA256: &str =
    "5fae6cc228a9cd2a7e4575de0c7e54d2c8f94808da2c40dd8bac96b497c2ae58";
const FIXTURE_SHA256: &str = "64c66724285a78ebb915ce5d45242cc01fdc15bb19eee55a9168eb97f60b01ac";

fn fixture() -> &'static BTreeMap<String, Value> {
    static FIXTURE: OnceLock<BTreeMap<String, Value>> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let source = include_str!("../tests/fixtures/captured_codec_schema_identities.json");
        assert_eq!(
            hex::encode(Sha256::digest(source.as_bytes())),
            FIXTURE_SHA256,
            "the reviewed compiler capture fixture is immutable"
        );
        assert_eq!(
            hex::encode(Sha256::digest(include_bytes!(
                "../tests/fixtures/native_codec_capture_2026_09_27.json"
            ))),
            CAPTURE_REPORT_SHA256,
            "the native capture report must match its fixture binding"
        );
        let document: Value = norito::json::from_str(source).expect("immutable capture fixture");
        assert_eq!(document.get("schema").and_then(Value::as_u64), Some(1));
        assert_eq!(
            document
                .get("capture_report_sha256")
                .and_then(Value::as_str),
            Some(CAPTURE_REPORT_SHA256)
        );
        let rows = document
            .get("rows")
            .and_then(Value::as_array)
            .expect("captured rows");
        assert_eq!(rows.len(), EXPECTED_CODEC_COUNT);
        let mut names = BTreeMap::new();
        let mut direction_counts = [0, 0, 0];
        for row in rows {
            let nominal = row
                .get("nominal")
                .and_then(Value::as_str)
                .expect("captured nominal");
            let root = row
                .get("root")
                .and_then(Value::as_str)
                .expect("captured root");
            assert!(!nominal.is_empty() && !root.is_empty());
            let serialize = row.get("serialize_hash").is_some();
            let deserialize = row.get("deserialize_hash").is_some();
            match (serialize, deserialize) {
                (true, true) => direction_counts[0] += 1,
                (true, false) => direction_counts[1] += 1,
                (false, true) => direction_counts[2] += 1,
                (false, false) => panic!("a fixture row must preserve an existing codec"),
            }
            let mut expected_keys = BTreeSet::from(["nominal", "root"]);
            for (present, direction) in [
                (serialize, "serialize_hash"),
                (deserialize, "deserialize_hash"),
            ] {
                if present {
                    expected_keys.insert(direction);
                    let _ = expected_hash(row, direction);
                }
            }
            assert_eq!(
                row.as_object()
                    .expect("capture row")
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
                expected_keys
            );
            assert!(
                names.insert(nominal.to_owned(), row.clone()).is_none(),
                "capture names must be unique"
            );
        }
        assert_eq!(direction_counts, [1_501, 51, 7]);
        names
    })
}

fn captured(nominal: &str) -> &'static Value {
    fixture()
        .get(nominal)
        .expect("every checked type has immutable capture evidence")
}

fn expected_hash(row: &Value, direction: &str) -> [u8; 16] {
    let hash = row
        .get(direction)
        .and_then(Value::as_str)
        .expect("captured codec direction");
    assert_eq!(hash.len(), 32, "schema hashes have exactly 16 bytes");
    assert!(
        hash.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "schema hashes use lowercase hexadecimal"
    );
    hex::decode(hash)
        .expect("captured hash is hexadecimal")
        .try_into()
        .expect("schema hash is exactly 16 bytes")
}

fn assert_identity<T: NoritoSchema>(nominal: &str) -> &'static Value {
    let row = captured(nominal);
    assert_eq!(T::nominal_name(), nominal);
    assert_eq!(
        T::frame_name(),
        row.get("root")
            .and_then(Value::as_str)
            .expect("captured root")
    );
    row
}

/// Check an existing serializer against its fixed nominal, root and hash.
fn assert_serialize<T: NoritoSchema + NoritoSerialize>(nominal: &str) {
    let row = assert_identity::<T>(nominal);
    let hash = expected_hash(row, "serialize_hash");
    assert_eq!(norito::schema::identity::frame_hash::<T>(), hash);
}

/// Check an existing decoder without requiring a serializer or constructing a value.
fn assert_deserialize<T>(nominal: &str)
where
    T: NoritoSchema + for<'a> NoritoDeserialize<'a>,
{
    let row = assert_identity::<T>(nominal);
    let hash = expected_hash(row, "deserialize_hash");
    assert_eq!(norito::schema::identity::frame_hash::<T>(), hash);
}

/// Check both independently generated codec directions without adding either codec.
fn assert_bidirectional<T>(nominal: &str)
where
    T: NoritoSchema + NoritoSerialize + for<'a> NoritoDeserialize<'a>,
{
    assert_serialize::<T>(nominal);
    assert_deserialize::<T>(nominal);
}

// New first-release owners have an explicit current capture; the historical report stays exact.
fn assert_current_bidirectional<T>(nominal: &str)
where
    T: NoritoSchema + NoritoSerialize + for<'a> NoritoDeserialize<'a>,
{
    let source = include_str!("../tests/fixtures/native_availability_codec_identities.json");
    assert_eq!(
        hex::encode(Sha256::digest(source.as_bytes())),
        "607b58230d83a9404847c8dbb1afc80aec14f4deaee30524ad7e58082e7b3ba0"
    );
    let document: Value = norito::json::from_str(source).expect("current native codec capture");
    assert_eq!(document.get("schema").and_then(Value::as_u64), Some(1));
    let rows = document.get("rows").and_then(Value::as_array).unwrap();
    assert_eq!(rows.len(), 2, "complete new availability codec inventory");
    let row = rows
        .iter()
        .find(|row| row.get("nominal").and_then(Value::as_str) == Some(nominal))
        .expect("explicit current captured nominal");
    assert_eq!(
        row.as_object().unwrap().len(),
        4,
        "nominal, root and both codec directions"
    );
    assert_eq!(T::nominal_name(), nominal);
    assert_eq!(
        T::frame_name(),
        row.get("root").and_then(Value::as_str).unwrap()
    );
    let hash = norito::schema::identity::frame_hash::<T>();
    assert_eq!(hash, expected_hash(row, "serialize_hash"));
    assert_eq!(hash, expected_hash(row, "deserialize_hash"));
}

/// One compiler-captured codec owner and its supported assertion directions.
///
/// Inventories are static data; walking them preserves declaration order without
/// materializing a per-test stack array or one enormous generated test body.
pub struct Case {
    nominal: &'static str,
    assertion: fn(&str),
    capture: fn(&str) -> native_capture::Identity,
}

impl Case {
    /// Bind a serializer to its independently captured nominal identity.
    pub const fn serialize<T: NoritoSchema + NoritoSerialize>(nominal: &'static str) -> Self {
        Self {
            nominal,
            assertion: assert_serialize::<T>,
            capture: native_capture::serialize::<T>,
        }
    }

    /// Bind a decoder without requiring a serializer or constructing a value.
    pub const fn deserialize<T>(nominal: &'static str) -> Self
    where
        T: NoritoSchema + for<'a> NoritoDeserialize<'a>,
    {
        Self {
            nominal,
            assertion: assert_deserialize::<T>,
            capture: native_capture::deserialize::<T>,
        }
    }

    /// Bind both existing codec directions without adding either implementation.
    pub const fn bidirectional<T>(nominal: &'static str) -> Self
    where
        T: NoritoSchema + NoritoSerialize + for<'a> NoritoDeserialize<'a>,
    {
        Self {
            nominal,
            assertion: assert_bidirectional::<T>,
            capture: native_capture::bidirectional::<T>,
        }
    }

    /// Bind both codec directions to an explicit current native capture for a new owner.
    /// Historical capture identities retain their own original evidence and are never replaced.
    pub const fn current_bidirectional<T>(nominal: &'static str) -> Self
    where
        T: NoritoSchema + NoritoSerialize + for<'a> NoritoDeserialize<'a>,
    {
        Self {
            nominal,
            assertion: assert_current_bidirectional::<T>,
            capture: native_capture::bidirectional::<T>,
        }
    }

    /// Bind both codec directions to the current paired owner capture after a first-release change.
    /// The earlier capture remains retained as historical evidence, not as a retired decoder contract.
    pub const fn paired_bidirectional<T>(nominal: &'static str) -> Self
    where
        T: NoritoSchema + NoritoSerialize + for<'a> NoritoDeserialize<'a>,
    {
        Self {
            nominal,
            assertion: native_capture::assert_current_identity::<T>,
            capture: native_capture::bidirectional::<T>,
        }
    }

    /// Assert the captured nominal identity, frame identity, and directional hashes.
    pub fn check(&self) {
        (self.assertion)(self.nominal);
    }
}

#[test]
fn captured_codec_fixture_is_complete() {
    assert_eq!(fixture().len(), EXPECTED_CODEC_COUNT);
}
