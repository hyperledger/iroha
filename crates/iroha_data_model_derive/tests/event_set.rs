//! Tests covering the `EventSet` derive macro behaviour.
#![allow(unexpected_cfgs)]
mod events {
    use iroha_data_model_derive::EventSet;
    /// Test event enumeration used with the `EventSet` derive.
    #[derive(EventSet)]
    #[event_set(schema_name = "derive_integration::event_set::events::TestEventSet")]
    pub enum TestEvent {
        Event1,
        Event2,
        NestedEvent(AnotherEvent),
    }
    /// Dummy nested event type used in the tests.
    pub struct AnotherEvent;
}
use events::{AnotherEvent, TestEvent, TestEventSet};
use norito::json::{self, Value};
#[test]
fn event_set_preserves_captured_identity() {
    assert_eq!(
        <TestEventSet as norito::NoritoSchema>::nominal_name(),
        "derive_integration::event_set::events::TestEventSet",
    );
    let captured = [
        159, 196, 218, 105, 112, 11, 120, 9, 55, 253, 142, 185, 70, 208, 133, 139,
    ];
    assert_eq!(
        norito::schema::identity::frame_hash::<TestEventSet>(),
        captured
    );
    let value = TestEventSet::all();
    let frame = norito::to_bytes(&value).expect("encode event set");
    let header = norito::core::Header::read(frame.as_slice()).expect("read event set header");
    assert_eq!(header.schema, captured);
    assert_eq!(
        norito::decode_from_bytes::<TestEventSet>(&frame).unwrap(),
        value
    );
    let mut wrong_schema = frame;
    wrong_schema[6] ^= 1;
    assert!(matches!(
        norito::decode_from_bytes::<TestEventSet>(&wrong_schema),
        Err(norito::Error::SchemaMismatch)
    ));
}
fn array(strings: &[&str]) -> Value {
    json::array(strings.iter().copied()).expect("serialize string array")
}

#[test]
fn production_event_sets_preserve_captured_frames() {
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
        T: norito::NoritoSerialize
            + for<'de> norito::NoritoDeserialize<'de>
            + core::fmt::Debug
            + PartialEq,
    {
        let bytes = norito::to_bytes(value).expect("frame encoding");
        let decoded = norito::decode_from_bytes::<T>(&bytes).expect("frame decoding");
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
    let mut rows = Vec::new();
    macro_rules! record {
        ($ty:ty) => {{
            let identity_hash = norito::schema::identity::frame_hash::<$ty>();
            let all_json = json::to_value(&<$ty>::all()).expect("all event names");
            let first_json =
                Value::Array(vec![all_json.as_array().expect("event names")[0].clone()]);
            let first: $ty = json::from_value(first_json).expect("first event");
            let cases: Vec<Value> = [<$ty>::empty(), first, <$ty>::all()]
                .into_iter()
                .map(|value| {
                    json::object([
                        ("json", json::to_value(&value).expect("event JSON")),
                        ("frame", Value::String(framed(&value))),
                        ("vector_frame", Value::String(framed(&vec![value]))),
                        ("option_frame", Value::String(framed(&Some(value)))),
                    ])
                    .expect("case object")
                })
                .collect();
            rows.push(
                json::object([
                    (
                        "nominal",
                        Value::String(<$ty as norito::NoritoSchema>::nominal_name()),
                    ),
                    ("serialize_hash", Value::String(hex(&identity_hash))),
                    ("deserialize_hash", Value::String(hex(&identity_hash))),
                    ("cases", Value::Array(cases)),
                ])
                .expect("type object"),
            );
        }};
    }
    record!(iroha_data_model::events::data::escrow::EscrowEventSet);
    record!(iroha_data_model::events::data::prelude::AccountEventSet);
    record!(iroha_data_model::events::data::prelude::AccountRecoveryEventSet);
    record!(iroha_data_model::events::data::prelude::AssetDefinitionEventSet);
    record!(iroha_data_model::events::data::prelude::AssetEventSet);
    record!(iroha_data_model::events::data::prelude::BridgeEventSet);
    record!(iroha_data_model::events::data::prelude::ConfigurationEventSet);
    record!(iroha_data_model::events::data::prelude::DomainEventSet);
    record!(iroha_data_model::events::data::prelude::ExecutorEventSet);
    record!(iroha_data_model::events::data::prelude::NftEventSet);
    record!(iroha_data_model::events::data::prelude::PeerEventSet);
    record!(iroha_data_model::events::data::prelude::RepoAccountEventSet);
    record!(iroha_data_model::events::data::prelude::RoleEventSet);
    record!(iroha_data_model::events::data::prelude::RwaEventSet);
    record!(iroha_data_model::events::data::prelude::TriggerEventSet);
    record!(iroha_data_model::events::data::governance::GovernanceEventSet);
    record!(iroha_data_model::events::data::musubi::MusubiEventSet);
    record!(iroha_data_model::events::data::oracle::OracleEventSet);
    record!(iroha_data_model::events::data::proof::ProofEventSet);
    record!(iroha_data_model::events::data::runtime_upgrade::RuntimeUpgradeEventSet);
    record!(iroha_data_model::events::data::smart_contract::SmartContractEventSet);
    record!(iroha_data_model::events::data::soradns::SoradnsDirectoryEventSet);
    record!(iroha_data_model::events::data::sorafs::SorafsGatewayEventSet);
    record!(iroha_data_model::events::data::space_directory::SpaceDirectoryEventSet);
    record!(iroha_data_model::events::data::verifying_keys::VerifyingKeyEventSet);
    let captured: Vec<Value> = json::from_str(include_str!("fixtures/event_set_frames.json"))
        .expect("immutable pre-declaration frames");
    assert_eq!(captured.len(), 25);
    assert_eq!(rows.len(), captured.len());
    for (observed, expected) in rows.iter().zip(&captured) {
        assert_eq!(
            observed,
            expected,
            "event set {:?}",
            expected.get("nominal")
        );
    }
}

#[test]
fn serialize() {
    assert_eq!(
        norito::json::to_value(&TestEventSet::Event1).unwrap(),
        array(&["Event1"])
    );
    assert_eq!(
        norito::json::to_value(&(TestEventSet::Event1 | TestEventSet::Event2)).unwrap(),
        array(&["Event1", "Event2"])
    );
    assert_eq!(
        norito::json::to_value(&(TestEventSet::Event1 | TestEventSet::AnyNestedEvent)).unwrap(),
        array(&["Event1", "AnyNestedEvent"])
    );
    assert_eq!(
        norito::json::to_value(&TestEventSet::all()).unwrap(),
        array(&["Event1", "Event2", "AnyNestedEvent"])
    );
}
#[test]
fn deserialize() {
    assert_eq!(
        norito::json::from_value::<TestEventSet>(array(&[])).unwrap(),
        TestEventSet::empty()
    );
    assert_eq!(
        norito::json::from_value::<TestEventSet>(array(&["Event1"])).unwrap(),
        TestEventSet::Event1
    );
    assert_eq!(
        norito::json::from_value::<TestEventSet>(array(&["Event1", "Event2"])).unwrap(),
        TestEventSet::Event1 | TestEventSet::Event2
    );
    assert_eq!(
        norito::json::from_value::<TestEventSet>(array(&["Event1", "AnyNestedEvent"])).unwrap(),
        TestEventSet::Event1 | TestEventSet::AnyNestedEvent
    );
    assert_eq!(
        norito::json::from_value::<TestEventSet>(array(&["Event1", "Event2", "AnyNestedEvent"]))
            .unwrap(),
        TestEventSet::all(),
    );
    assert_eq!(
        norito::json::from_value::<TestEventSet>(array(&["Event1", "Event1", "AnyNestedEvent"]))
            .unwrap(),
        TestEventSet::Event1 | TestEventSet::AnyNestedEvent,
    );
}
#[test]
fn deserialize_invalid() {
    assert_eq!(
        norito::json::from_value::<TestEventSet>(json::to_value(&32).unwrap())
            .unwrap_err()
            .to_string(),
        "invalid type: integer `32`, expected a sequence of strings"
    );
    assert_eq!(
        norito::json::from_value::<TestEventSet>(
            json::array([32]).expect("serialize integer array"),
        )
        .unwrap_err()
        .to_string(),
        "invalid type: integer `32`, expected a string"
    );
    assert_eq!(
        norito::json::from_value::<TestEventSet>(array(&["InvalidVariant"]))
            .unwrap_err()
            .to_string(),
        "unknown event variant `InvalidVariant`, expected one of `Event1`, `Event2`, `AnyNestedEvent`"
    );
    assert_eq!(
        norito::json::from_value::<TestEventSet>(array(&["Event1", "Event1", "InvalidVariant"]),)
            .unwrap_err()
            .to_string(),
        "unknown event variant `InvalidVariant`, expected one of `Event1`, `Event2`, `AnyNestedEvent`"
    );
}
#[test]
fn full_set() {
    let any_matcher = TestEventSet::all();
    assert_eq!(
        any_matcher,
        TestEventSet::Event1 | TestEventSet::Event2 | TestEventSet::AnyNestedEvent
    );
    assert_eq!(
        format!("{any_matcher:?}"),
        "TestEventSet[Event1, Event2, AnyNestedEvent]"
    );
    assert!(any_matcher.matches(&TestEvent::Event1));
    assert!(any_matcher.matches(&TestEvent::Event2));
    assert!(any_matcher.matches(&TestEvent::NestedEvent(AnotherEvent)));
}
#[test]
fn empty_set() {
    let none_matcher = TestEventSet::empty();
    assert_eq!(format!("{none_matcher:?}"), "TestEventSet[]");
    assert!(!none_matcher.matches(&TestEvent::Event1));
    assert!(!none_matcher.matches(&TestEvent::Event2));
    assert!(!none_matcher.matches(&TestEvent::NestedEvent(AnotherEvent)));
}
#[test]
fn event1_set() {
    let event1_matcher = TestEventSet::Event1;
    assert_eq!(format!("{event1_matcher:?}"), "TestEventSet[Event1]");
    assert!(event1_matcher.matches(&TestEvent::Event1));
    assert!(!event1_matcher.matches(&TestEvent::Event2));
    assert!(!event1_matcher.matches(&TestEvent::NestedEvent(AnotherEvent)));
}
#[test]
fn event1_or_2_set() {
    let event1_or_2_matcher = TestEventSet::Event1 | TestEventSet::Event2;
    assert_eq!(
        format!("{event1_or_2_matcher:?}"),
        "TestEventSet[Event1, Event2]"
    );
    assert!(event1_or_2_matcher.matches(&TestEvent::Event1));
    assert!(event1_or_2_matcher.matches(&TestEvent::Event2));
    assert!(!event1_or_2_matcher.matches(&TestEvent::NestedEvent(AnotherEvent)));
}
#[test]
fn repeated() {
    assert_eq!(
        TestEventSet::Event1 | TestEventSet::Event1,
        TestEventSet::Event1
    );
    assert_eq!(
        TestEventSet::Event1 | TestEventSet::Event2 | TestEventSet::Event1,
        TestEventSet::Event1 | TestEventSet::Event2
    );
    assert_eq!(
        TestEventSet::all() | TestEventSet::AnyNestedEvent,
        TestEventSet::all()
    );
}

/// Every bit of the widest supported event set.
#[derive(iroha_data_model_derive::EventSet)]
#[event_set(schema_name = "derive_integration::event_set::WideEventSet")]
pub enum WideEvent {
    /// Event at bit 0.
    Event0,
    /// Event at bit 1.
    Event1,
    /// Event at bit 2.
    Event2,
    /// Event at bit 3.
    Event3,
    /// Event at bit 4.
    Event4,
    /// Event at bit 5.
    Event5,
    /// Event at bit 6.
    Event6,
    /// Event at bit 7.
    Event7,
    /// Event at bit 8.
    Event8,
    /// Event at bit 9.
    Event9,
    /// Event at bit 10.
    Event10,
    /// Event at bit 11.
    Event11,
    /// Event at bit 12.
    Event12,
    /// Event at bit 13.
    Event13,
    /// Event at bit 14.
    Event14,
    /// Event at bit 15.
    Event15,
    /// Event at bit 16.
    Event16,
    /// Event at bit 17.
    Event17,
    /// Event at bit 18.
    Event18,
    /// Event at bit 19.
    Event19,
    /// Event at bit 20.
    Event20,
    /// Event at bit 21.
    Event21,
    /// Event at bit 22.
    Event22,
    /// Event at bit 23.
    Event23,
    /// Event at bit 24.
    Event24,
    /// Event at bit 25.
    Event25,
    /// Event at bit 26.
    Event26,
    /// Event at bit 27.
    Event27,
    /// Event at bit 28.
    Event28,
    /// Event at bit 29.
    Event29,
    /// Event at bit 30.
    Event30,
    /// Event at bit 31.
    Event31,
    /// Event at bit 32.
    Event32,
    /// Event at bit 33.
    Event33,
    /// Event at bit 34.
    Event34,
    /// Event at bit 35.
    Event35,
    /// Event at bit 36.
    Event36,
    /// Event at bit 37.
    Event37,
    /// Event at bit 38.
    Event38,
    /// Event at bit 39.
    Event39,
    /// Event at bit 40.
    Event40,
    /// Event at bit 41.
    Event41,
    /// Event at bit 42.
    Event42,
    /// Event at bit 43.
    Event43,
    /// Event at bit 44.
    Event44,
    /// Event at bit 45.
    Event45,
    /// Event at bit 46.
    Event46,
    /// Event at bit 47.
    Event47,
    /// Event at bit 48.
    Event48,
    /// Event at bit 49.
    Event49,
    /// Event at bit 50.
    Event50,
    /// Event at bit 51.
    Event51,
    /// Event at bit 52.
    Event52,
    /// Event at bit 53.
    Event53,
    /// Event at bit 54.
    Event54,
    /// Event at bit 55.
    Event55,
    /// Event at bit 56.
    Event56,
    /// Event at bit 57.
    Event57,
    /// Event at bit 58.
    Event58,
    /// Event at bit 59.
    Event59,
    /// Event at bit 60.
    Event60,
    /// Event at bit 61.
    Event61,
    /// Event at bit 62.
    Event62,
    /// Event at bit 63.
    Event63,
}

#[test]
fn wide_set_preserves_high_bits_across_matching_binary_json_and_schema() {
    let selected = WideEventSet::Event31 | WideEventSet::Event32 | WideEventSet::Event63;
    assert!(selected.matches(&WideEvent::Event31));
    assert!(selected.matches(&WideEvent::Event32));
    assert!(selected.matches(&WideEvent::Event63));
    assert!(!selected.matches(&WideEvent::Event0));
    let bytes = norito::to_bytes(&selected).unwrap();
    assert_eq!(
        norito::decode_from_bytes::<WideEventSet>(&bytes).unwrap(),
        selected
    );
    let value = json::to_value(&selected).unwrap();
    assert_eq!(value, array(&["Event31", "Event32", "Event63"]));
    assert_eq!(json::from_value::<WideEventSet>(value).unwrap(), selected);
    let map = <WideEventSet as iroha_schema::IntoSchema>::schema();
    let iroha_schema::Metadata::Bitmap(bitmap) = map.get::<WideEventSet>().unwrap() else {
        panic!("event set schema must be a bitmap");
    };
    assert_eq!(bitmap.repr, core::any::TypeId::of::<u64>());
    assert_eq!(bitmap.masks.last().unwrap().mask, 1_u64 << 63);
    assert_eq!(bitmap.masks[32].mask, 1_u64 << 32);
    assert_eq!(core::mem::size_of::<TestEventSet>(), 4);
    assert_eq!(core::mem::size_of::<WideEventSet>(), 8);
    assert_eq!(
        json::to_value(&WideEventSet::all())
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        64
    );
}

#[test]
fn wide_set_matches_each_bit_independently() {
    let events = [
        WideEvent::Event0,
        WideEvent::Event1,
        WideEvent::Event2,
        WideEvent::Event3,
        WideEvent::Event4,
        WideEvent::Event5,
        WideEvent::Event6,
        WideEvent::Event7,
        WideEvent::Event8,
        WideEvent::Event9,
        WideEvent::Event10,
        WideEvent::Event11,
        WideEvent::Event12,
        WideEvent::Event13,
        WideEvent::Event14,
        WideEvent::Event15,
        WideEvent::Event16,
        WideEvent::Event17,
        WideEvent::Event18,
        WideEvent::Event19,
        WideEvent::Event20,
        WideEvent::Event21,
        WideEvent::Event22,
        WideEvent::Event23,
        WideEvent::Event24,
        WideEvent::Event25,
        WideEvent::Event26,
        WideEvent::Event27,
        WideEvent::Event28,
        WideEvent::Event29,
        WideEvent::Event30,
        WideEvent::Event31,
        WideEvent::Event32,
        WideEvent::Event33,
        WideEvent::Event34,
        WideEvent::Event35,
        WideEvent::Event36,
        WideEvent::Event37,
        WideEvent::Event38,
        WideEvent::Event39,
        WideEvent::Event40,
        WideEvent::Event41,
        WideEvent::Event42,
        WideEvent::Event43,
        WideEvent::Event44,
        WideEvent::Event45,
        WideEvent::Event46,
        WideEvent::Event47,
        WideEvent::Event48,
        WideEvent::Event49,
        WideEvent::Event50,
        WideEvent::Event51,
        WideEvent::Event52,
        WideEvent::Event53,
        WideEvent::Event54,
        WideEvent::Event55,
        WideEvent::Event56,
        WideEvent::Event57,
        WideEvent::Event58,
        WideEvent::Event59,
        WideEvent::Event60,
        WideEvent::Event61,
        WideEvent::Event62,
        WideEvent::Event63,
    ];
    for (bit, event) in events.iter().enumerate() {
        let name = format!("Event{bit}");
        let selected = json::from_value::<WideEventSet>(array(&[&name])).unwrap();
        assert!(WideEventSet::all().matches(event));
        assert!(!WideEventSet::empty().matches(event));
        for (candidate_bit, candidate) in events.iter().enumerate() {
            assert_eq!(selected.matches(candidate), bit == candidate_bit);
        }
    }
}
