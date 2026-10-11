//! Immutable original-code observations for owners that emit or accept typed frames.

use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize, json::Value};
use sha2::{Digest, Sha256};

fn fixture() -> &'static Vec<Value> {
    static FIXTURE: std::sync::OnceLock<Vec<Value>> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(|| {
        let source = include_str!("../tests/fixtures/frame_owner_identity_observations.json");
        assert_eq!(
            hex::encode(Sha256::digest(source.as_bytes())),
            "53464a17aa48bcdaea70b1692c3d76e546c60d64152f6bee1b11680f84403670"
        );
        let mut rows: Vec<Value> =
            norito::json::from_str(source).expect("original-code observations");
        assert_eq!(rows.len(), 52);
        let additional =
            include_str!("../tests/fixtures/additional_frame_owner_identity_observations.json");
        assert_eq!(
            hex::encode(Sha256::digest(additional.as_bytes())),
            "70a60b15402c0a7145adfcb7807f9ed55251b408e44b4b04df53ecdc62b5b19d"
        );
        let additional: Vec<Value> =
            norito::json::from_str(additional).expect("additional original-code observations");
        assert_eq!(additional.len(), 46);
        rows.extend(additional);
        let http = include_str!("../tests/fixtures/http_frame_owner_identity_observations.json");
        assert_eq!(
            hex::encode(Sha256::digest(http.as_bytes())),
            "ed7393ee2bb6487a1f390c911770db49430a885af8ab39a3e60953f5b016570f"
        );
        let http: Vec<Value> =
            norito::json::from_str(http).expect("original HTTP frame observations");
        assert_eq!(http.len(), 6);
        rows.extend(http);
        rows
    })
}

fn assert_direction<T: NoritoSchema>(nominal: &str, direction: &str) {
    let matches: Vec<_> = fixture()
        .iter()
        .filter(|row| {
            row["nominal"].as_str() == Some(nominal) && row["direction"].as_str() == Some(direction)
        })
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "one original observation per owner/direction"
    );
    let row = matches[0];
    assert_eq!(T::nominal_name(), nominal);
    assert_eq!(T::frame_name(), row["root_hint"].as_str().unwrap());
    assert_eq!(
        hex::encode(norito::schema::identity::frame_hash::<T>()),
        row["schema_hash"].as_str().unwrap()
    );
}

/// Check a frame writer against the original serializer observation.
pub fn assert_serialize<T: NoritoSerialize>(nominal: &str) {
    assert_direction::<T>(nominal, "serialize");
}

/// Check both frame contracts against their independent original observations.
pub fn assert_bidirectional<T>(nominal: &str)
where
    T: NoritoSerialize + for<'a> NoritoDeserialize<'a>,
{
    assert_direction::<T>(nominal, "serialize");
    assert_direction::<T>(nominal, "deserialize");
}

#[test]
fn original_observations_are_complete_and_unique() {
    let mut keys = std::collections::BTreeSet::new();
    let mut names = std::collections::BTreeSet::new();
    for row in fixture() {
        assert!(keys.insert((
            row["nominal"].as_str().unwrap(),
            row["direction"].as_str().unwrap()
        )));
        names.insert(row["nominal"].as_str().unwrap());
        assert_eq!(row["kind"].as_str(), Some("capture"));
        assert_eq!(row["root_matches"].as_bool(), Some(true));
    }
    assert_eq!(keys.len(), 104);
    assert_eq!(names.len(), 53);
}

#[test]
fn captured_http_frame_owner_identities() {
    assert_bidirectional::<crate::ValidationFail>(
        "iroha_data_model::executor::model::ValidationFail",
    );
    assert_bidirectional::<crate::da::ingest::DaIngestRequest>(
        "iroha_data_model::da::ingest::DaIngestRequest",
    );
    assert_bidirectional::<crate::da::ingest::DaIngestReceipt>(
        "iroha_data_model::da::ingest::DaIngestReceipt",
    );
}
