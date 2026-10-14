//! Captured wire identities for the generated Musubi digest, text and page families.

use std::{collections::BTreeMap, fmt::Debug};

use iroha_data_model::{account::address::ChainDiscriminantGuard, musubi::*};
use norito::{
    NoritoDeserialize, NoritoSerialize,
    json::{self, JsonSerialize, Value},
};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut encoded = String::new();
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn framed<T>(value: &T) -> String
where
    T: NoritoSerialize + for<'de> NoritoDeserialize<'de> + Debug + PartialEq,
{
    let bytes = norito::to_bytes(value).expect("encode generated Musubi frame");
    let decoded: T = norito::decode_from_bytes(&bytes).expect("decode generated Musubi frame");
    assert_eq!(&decoded, value);
    let header = norito::core::Header::read(bytes.as_slice()).expect("read frame header");
    assert_eq!(header.schema, norito::schema::identity::frame_hash::<T>());
    let mut wrong_schema = bytes.clone();
    wrong_schema[6] ^= 1;
    assert!(matches!(
        norito::decode_from_bytes::<T>(&wrong_schema),
        Err(norito::Error::SchemaMismatch)
    ));
    hex(&bytes)
}

fn record<T>(values: impl IntoIterator<Item = T>) -> Value
where
    T: NoritoSerialize
        + for<'de> NoritoDeserialize<'de>
        + norito::NoritoSchema
        + JsonSerialize
        + Clone
        + Debug
        + PartialEq,
{
    let identity_hash = norito::schema::identity::frame_hash::<T>();
    assert_eq!(T::frame_name(), T::nominal_name());
    let cases = values
        .into_iter()
        .map(|value| {
            json::object([
                (
                    "json",
                    json::to_value(&value).expect("generated Musubi JSON"),
                ),
                ("frame", Value::String(framed(&value))),
                ("vector_frame", Value::String(framed(&vec![value.clone()]))),
                ("option_frame", Value::String(framed(&Some(value.clone())))),
                (
                    "map_frame",
                    Value::String(framed(&BTreeMap::from([(7_u8, value)]))),
                ),
            ])
            .expect("captured value")
        })
        .collect();
    json::object([
        ("nominal", Value::String(T::nominal_name())),
        ("serialize_hash", Value::String(hex(&identity_hash))),
        ("deserialize_hash", Value::String(hex(&identity_hash))),
        ("cases", Value::Array(cases)),
    ])
    .expect("captured type")
}

fn generated_families() -> Vec<Value> {
    // The shared SDK fixture uses the SORA discriminant. Keep this override local
    // to the test thread so other network-formatting tests remain independent.
    let _address_context = ChainDiscriminantGuard::enter(0x02f1);
    let mut rows = Vec::new();
    macro_rules! digest {
        ($ty:ty) => {
            rows.push(record([
                <$ty>::new([0; 32]),
                <$ty>::new([1; 32]),
                <$ty>::new(core::array::from_fn(|index| {
                    u8::try_from(index).expect("digest index")
                })),
            ]));
        };
    }
    digest!(ArchiveId);
    digest!(MusubiContentDigestV1);
    digest!(MusubiReleaseDigestV1);
    digest!(MusubiSemanticReleaseDigestV1);
    digest!(MusubiVerificationLockDigestV1);
    digest!(MusubiNamespaceBindingDigestV1);
    digest!(MusubiArchiveLocationIdV1);
    digest!(MusubiProviderBundleAttestationDigestV1);
    digest!(MusubiProviderBundleAttestationSetDigestV1);
    digest!(MusubiInviteIdV1);
    digest!(MusubiGovernanceActionDigestV1);
    digest!(MusubiQueryHashV1);
    macro_rules! text {
        ($ty:ty, $maximum:expr) => {
            rows.push(record([
                <$ty>::new("a").expect("short text"),
                <$ty>::new("公開された説明").expect("Unicode text"),
                <$ty>::new(&"a".repeat($maximum)).expect("maximum-length text"),
            ]));
        };
    }
    text!(MusubiDescriptionV1, 4_096);
    text!(MusubiDocumentRefV1, 2_048);
    text!(MusubiReasonV1, 1_024);

    let sdk: Value = json::from_str(include_str!("../../../fixtures/musubi/sdk_v1.json"))
        .expect("shared Musubi SDK fixture");
    let response = |id| {
        sdk.get("routes")
            .and_then(Value::as_array)
            .expect("SDK routes")
            .iter()
            .find(|route| route.get("id").and_then(Value::as_str) == Some(id))
            .and_then(|route| route.get("response"))
            .expect("SDK response")
            .clone()
    };
    let package: MusubiPackageRecordV1 =
        json::from_value(response("exact-package")).expect("canonical package record");
    let release: MusubiExactReleaseSnapshotV1 =
        json::from_value(response("exact-release")).expect("canonical release snapshot");
    let snapshot = release.snapshot;
    let packages = [
        MusubiPackagePageV1 {
            items: Vec::new(),
            next_cursor: None,
            snapshot,
        },
        MusubiPackagePageV1 {
            items: vec![package],
            next_cursor: None,
            snapshot,
        },
    ];
    for page in &packages {
        page.validate().expect("valid package page");
    }
    rows.push(record(packages));
    let releases = [
        MusubiReleasePageV1 {
            items: Vec::new(),
            next_cursor: None,
            snapshot,
        },
        MusubiReleasePageV1 {
            items: vec![release.home_release],
            next_cursor: None,
            snapshot,
        },
    ];
    for page in &releases {
        page.validate().expect("valid release page");
    }
    rows.push(record(releases));
    rows
}

#[test]
fn generated_musubi_identities_preserve_captured_frames() {
    let rows = generated_families();
    assert_eq!(rows.len(), 17);
    let captured: Vec<Value> = json::from_str(include_str!(
        "fixtures/musubi_generated_identity_frames.json"
    ))
    .expect("immutable pre-declaration fixture");
    assert_eq!(rows, captured);
}
