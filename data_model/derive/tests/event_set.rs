mod events {
    use iroha_data_model_derive::EventSet;
    #[derive(EventSet)]
    pub enum TestEvent {
        Event1,
        Event2,
        NestedEvent(AnotherEvent),
    }

    pub struct AnotherEvent;
}

use events::{AnotherEvent, TestEvent, TestEventSet};
use serde_json::json;

#[test]
fn serialize() {
    assert_eq!(
        serde_json::to_value(TestEventSet::Event1).unwrap(),
        json!(["Event1"])
    );
    assert_eq!(
        serde_json::to_value(TestEventSet::Event1 | TestEventSet::Event2).unwrap(),
        json!(["Event1", "Event2"])
    );
    assert_eq!(
        serde_json::to_value(TestEventSet::Event1 | TestEventSet::AnyNestedEvent).unwrap(),
        json!(["Event1", "AnyNestedEvent"])
    );
    assert_eq!(
        serde_json::to_value(TestEventSet::all()).unwrap(),
        json!(["Event1", "Event2", "AnyNestedEvent"])
    );
}

#[test]
fn deserialize() {
    assert_eq!(
        serde_json::from_value::<TestEventSet>(json!([])).unwrap(),
        TestEventSet::empty()
    );
    assert_eq!(
        serde_json::from_value::<TestEventSet>(json!(["Event1"])).unwrap(),
        TestEventSet::Event1
    );
    assert_eq!(
        serde_json::from_value::<TestEventSet>(json!(["Event1", "Event2"])).unwrap(),
        TestEventSet::Event1 | TestEventSet::Event2
    );
    assert_eq!(
        serde_json::from_value::<TestEventSet>(json!(["Event1", "AnyNestedEvent"])).unwrap(),
        TestEventSet::Event1 | TestEventSet::AnyNestedEvent
    );
    assert_eq!(
        serde_json::from_value::<TestEventSet>(json!(["Event1", "Event2", "AnyNestedEvent"]))
            .unwrap(),
        TestEventSet::all(),
    );

    assert_eq!(
        serde_json::from_value::<TestEventSet>(json!(["Event1", "Event1", "AnyNestedEvent"]))
            .unwrap(),
        TestEventSet::Event1 | TestEventSet::AnyNestedEvent,
    );
}

#[test]
fn deserialize_invalid() {
    assert_eq!(
        serde_json::from_value::<TestEventSet>(json!(32))
            .unwrap_err()
            .to_string(),
        "invalid type: integer `32`, expected a sequence of strings"
    );

    assert_eq!(
        serde_json::from_value::<TestEventSet>(json!([32]))
            .unwrap_err()
            .to_string(),
        "invalid type: integer `32`, expected a string"
    );

    assert_eq!(
        serde_json::from_value::<TestEventSet>(json!(["InvalidVariant"]))
            .unwrap_err()
            .to_string(),
        "unknown event variant `InvalidVariant`, expected one of `Event1`, `Event2`, `AnyNestedEvent`"
    );

    assert_eq!(
        serde_json::from_value::<TestEventSet>(json!(["Event1", "Event1", "InvalidVariant"]))
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
