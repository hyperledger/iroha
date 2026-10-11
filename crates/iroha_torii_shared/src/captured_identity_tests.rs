//! Original-code frame identities and exact status-wrapper bytes.

use norito::{
    NoritoDeserialize, NoritoSchema, NoritoSerialize,
    json::{self, Value},
};

fn fixture() -> &'static Value {
    static FIXTURE: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(|| {
        json::from_str(include_str!(
            "../tests/fixtures/frame_identity_observations.json"
        ))
        .expect("captured frame identities")
    })
}

pub fn assert_bidirectional<T>(nominal: &str)
where
    T: NoritoSerialize + for<'a> NoritoDeserialize<'a>,
{
    assert_eq!(T::nominal_name(), nominal);
    for direction in ["serialize", "deserialize"] {
        let rows: Vec<_> = fixture()["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| {
                row["nominal"].as_str() == Some(nominal)
                    && row["direction"].as_str() == Some(direction)
            })
            .collect();
        assert_eq!(rows.len(), 1, "unique captured owner and direction");
        assert_eq!(T::frame_name(), rows[0]["root_hint"].as_str().unwrap());
        assert_eq!(
            hex::encode(norito::schema::identity::frame_hash::<T>()),
            rows[0]["schema_hash"].as_str().unwrap()
        );
    }
}

fn assert_frame<T>(value: &T, row: &Value, key: &str) -> T
where
    T: NoritoSerialize + for<'a> NoritoDeserialize<'a>,
{
    let frame = norito::to_bytes(value).expect("encode captured frame");
    assert_eq!(
        hex::encode(&frame),
        row[key].as_str().unwrap(),
        "complete frame: {key}"
    );
    assert_eq!(
        norito::core::Header::read(frame.as_slice()).unwrap().schema,
        norito::schema::identity::frame_hash::<T>()
    );
    let decoded = norito::decode_from_bytes::<T>(&frame).expect("decode captured frame");
    assert_eq!(norito::to_bytes(&decoded).unwrap(), frame);
    for length in 0..frame.len() {
        assert!(
            norito::decode_from_bytes::<T>(&frame[..length]).is_err(),
            "truncated frame: {key}"
        );
    }
    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(
        norito::decode_from_bytes::<T>(&trailing).is_err(),
        "trailing frame: {key}"
    );
    let mut wrong_owner = frame;
    wrong_owner[6] ^= 1;
    assert!(matches!(
        norito::decode_from_bytes::<T>(&wrong_owner),
        Err(norito::Error::SchemaMismatch)
    ));
    decoded
}

pub fn assert_manual<T>(case: &str)
where
    T: NoritoSerialize
        + for<'a> NoritoDeserialize<'a>
        + json::JsonSerialize
        + json::JsonDeserialize,
{
    let rows: Vec<_> = fixture()["manual_records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["case"].as_str() == Some(case))
        .collect();
    assert_eq!(rows.len(), 1);
    let row = rows[0];
    let golden: Value = json::from_str(include_str!(
        "../../../fixtures/torii/status_wire_golden.v1.json"
    ))
    .unwrap();
    let expected_json = &golden[case]["json"];
    let make = || json::from_value::<T>(expected_json.clone()).unwrap();
    assert_eq!(T::nominal_name(), row["nominal"].as_str().unwrap());
    assert_eq!(T::frame_name(), row["root"].as_str().unwrap());
    let hash = hex::encode(norito::schema::identity::frame_hash::<T>());
    assert_eq!(hash, row["serialize_hash"].as_str().unwrap());
    assert_eq!(hash, row["deserialize_hash"].as_str().unwrap());
    assert_eq!(row["wire_hex"], golden[case]["wire_hex"]);
    assert_eq!(
        json::to_value(&assert_frame(&make(), row, "wire_hex")).unwrap(),
        *expected_json
    );
    assert_eq!(
        Option::<T>::nominal_name(),
        row["option_nominal"].as_str().unwrap()
    );
    assert_eq!(
        Vec::<T>::nominal_name(),
        row["vec_nominal"].as_str().unwrap()
    );
    let option_hash = hex::encode(norito::schema::identity::frame_hash::<Option<T>>());
    assert_eq!(option_hash, row["option_serialize_hash"].as_str().unwrap());
    assert_eq!(
        option_hash,
        row["option_deserialize_hash"].as_str().unwrap()
    );
    let vec_hash = hex::encode(norito::schema::identity::frame_hash::<Vec<T>>());
    assert_eq!(vec_hash, row["vec_serialize_hash"].as_str().unwrap());
    assert_eq!(vec_hash, row["vec_deserialize_hash"].as_str().unwrap());
    assert!(assert_frame(&None::<T>, row, "option_none_hex").is_none());
    let some = assert_frame(&Some(make()), row, "option_some_hex").unwrap();
    assert_eq!(json::to_value(&some).unwrap(), *expected_json);
    assert!(assert_frame(&Vec::<T>::new(), row, "vec_empty_hex").is_empty());
    let two = assert_frame(&vec![make(), make()], row, "vec_two_hex");
    assert_eq!(two.len(), 2);
    for value in &two {
        assert_eq!(json::to_value(value).unwrap(), *expected_json);
    }
}

#[test]
fn captured_fixture_has_complete_unique_owner_directions() {
    assert_eq!(fixture()["records"].as_array().unwrap().len(), 316);
    assert_eq!(fixture()["manual_records"].as_array().unwrap().len(), 12);
    let mut identities = std::collections::BTreeSet::new();
    for row in fixture()["records"].as_array().unwrap() {
        assert!(identities.insert((
            row["nominal"].as_str().unwrap(),
            row["direction"].as_str().unwrap()
        )));
    }
    assert_eq!(identities.len(), 316);
    let mut manual = std::collections::BTreeSet::new();
    for row in fixture()["manual_records"].as_array().unwrap() {
        assert!(manual.insert(row["nominal"].as_str().unwrap()));
    }
    assert_eq!(manual.len(), 12);
}
