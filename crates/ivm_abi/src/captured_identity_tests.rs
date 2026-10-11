//! Fixed original-code identity observations and populated frame regression checks.

use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize, json::Value};

fn fixture() -> &'static Value {
    static FIXTURE: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(|| {
        let fixture: Value = norito::json::from_str(include_str!(
            "../tests/fixtures/frame_identity_observations.json"
        ))
        .unwrap();
        assert_eq!(fixture["schema"].as_u64(), Some(1));
        assert_eq!(fixture["automatic"].as_array().unwrap().len(), 59);
        assert_eq!(fixture["manual"].as_array().unwrap().len(), 9);
        fixture
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn assert_direction<T: NoritoSchema>(nominal: &str, direction: &str) {
    let rows: Vec<_> = fixture()["automatic"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| {
            row["nominal"].as_str() == Some(nominal) && row["direction"].as_str() == Some(direction)
        })
        .collect();
    assert_eq!(rows.len(), 1, "each captured owner/direction is unique");
    let row = rows[0];
    assert_eq!(T::nominal_name(), nominal);
    assert_eq!(T::frame_name(), row["root_hint"].as_str().unwrap());
    assert_eq!(
        hex(&norito::schema::identity::frame_hash::<T>()),
        row["schema_hash"].as_str().unwrap()
    );
}

pub(crate) fn assert_serialize<T: NoritoSerialize>(nominal: &str) {
    assert_direction::<T>(nominal, "serialize");
}

pub(crate) fn assert_bidirectional<T>(nominal: &str)
where
    T: NoritoSerialize + for<'a> NoritoDeserialize<'a>,
{
    assert_direction::<T>(nominal, "serialize");
    assert_direction::<T>(nominal, "deserialize");
}

pub(crate) fn assert_manual<T>(case: &str, value: &T)
where
    T: NoritoSerialize + for<'a> NoritoDeserialize<'a> + std::fmt::Debug + PartialEq,
{
    let rows: Vec<_> = fixture()["manual"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["case"].as_str() == Some(case))
        .collect();
    assert_eq!(rows.len(), 1);
    let row = rows[0];
    assert_eq!(T::nominal_name(), row["nominal"].as_str().unwrap());
    assert_eq!(T::frame_name(), row["root"].as_str().unwrap());
    let hash = hex(&norito::schema::identity::frame_hash::<T>());
    assert_eq!(hash, row["serialize_hash"].as_str().unwrap());
    assert_eq!(hash, row["deserialize_hash"].as_str().unwrap());
    let frame = norito::encode_canonical(value).unwrap();
    assert_eq!(hex(&frame), row["canonical_hex"].as_str().unwrap());
    let decoded: T = norito::decode_canonical(&frame).unwrap();
    assert_eq!(&decoded, value);
    assert_eq!(norito::encode_canonical(&decoded).unwrap(), frame);
    for length in 0..frame.len() {
        assert!(norito::decode_canonical::<T>(&frame[..length]).is_err());
    }
    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(norito::decode_canonical::<T>(&trailing).is_err());
    let mut wrong_owner = frame;
    wrong_owner[6] ^= 1;
    assert!(matches!(
        norito::decode_canonical::<T>(&wrong_owner),
        Err(norito::Error::SchemaMismatch)
    ));
}

#[test]
fn captured_identity_fixture_is_complete() {
    let mut keys = std::collections::BTreeSet::new();
    for row in fixture()["automatic"].as_array().unwrap() {
        assert!(keys.insert((
            row["nominal"].as_str().unwrap(),
            row["direction"].as_str().unwrap()
        )));
    }
    assert_eq!(keys.len(), 59);
    let cases: std::collections::BTreeSet<_> = fixture()["manual"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["case"].as_str().unwrap())
        .collect();
    assert_eq!(cases.len(), 9);
}
