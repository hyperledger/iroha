Create an event set structure from an event enum.

Event set is a set of multiple event types, allowing to efficiently test whether an event is in a set.

For this event enum:

```rust
# use iroha_data_model_derive::EventSet;
#[derive(EventSet)]
#[event_set(schema_name = "example::TestEventSet")]
pub enum TestEvent {
    Event1,
    Event2,
    NestedEvent(AnotherEvent),
}
pub struct AnotherEvent;
```

The macro will generate a `TestEventSet` struct.

Enums with up to 32 variants use a `u32` bitmap; enums with 33–64 variants
use a `u64` bitmap. More than 64 variants are rejected. The generated schema
reports that exact integer representation. Adding the 33rd event therefore
changes the set's binary layout and requires updating its wire fixtures.

Every caller declares the generated set's own nominal Norito identity with
`#[event_set(schema_name = "...")]`. The identity must be a nonempty string
literal without surrounding whitespace or control characters. Missing,
duplicate or unknown options are compile errors. A parent enum's identity is
never reused for the set. For an existing wire type, use its compiler-captured
identity so relocation preserves its frame contract.

It will have associated constants that correspond to a singleton set for each event that can be accessed like `TestEventSet::Event1`.

The sets can be combined either with a `|` operator or with the `or` method to match multiple events at once: `TestEventSet::Event1 | TestEventSet::Event2`.

Variants that:
1. have a single unnamed field
2. have the type name end with `Event`

are treated as nested events and their set constant has `Any` prepended to the name. For example, `TestEventSet::AnyNestedEvent`.

The set has the following methods:
```ignore
impl TestEventSet {
    /// Returns a set that doesn't contain any events
    const fn empty() -> TestEventSet;
    /// Returns a set that contains all events
    const fn all() -> TestEventSet;
    /// Computes union of two sets, const form of the `|` operator
    const fn or(self, other: TestEventSet) -> TestEventSet;
    /// Checks if the set contains a specific event
    const fn matches(&self, event: &TestEvent) -> bool;
}
```

Implemented traits:
```ignore
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    norito::codec::Decode,
    norito::codec::Encode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
)]

/// Prints the list of events in the set
///
/// For example: `TestEventSet[Event1, AnyNestedEvent]`
impl core::fmt::Debug;

/// Union of two sets
impl core::ops::BitOr;
```
