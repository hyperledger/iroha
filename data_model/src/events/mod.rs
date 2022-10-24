//! Events for streaming API.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};

use iroha_macro::FromVariant;
use iroha_schema::prelude::*;
use iroha_version::prelude::*;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub mod data;
pub mod execute_trigger;
pub mod pipeline;
pub mod time;

declare_versioned_with_scale!(VersionedEventMessage 1..2, Debug, Clone, FromVariant, IntoSchema);

impl VersionedEventMessage {
    /// Converts from `&VersionedEventPublisherMessage` to V1 reference
    pub const fn as_v1(&self) -> &EventMessage {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedEventPublisherMessage` to V1 mutable reference
    pub fn as_mut_v1(&mut self) -> &mut EventMessage {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedEventPublisherMessage` to V1
    pub fn into_v1(self) -> EventMessage {
        match self {
            Self::V1(v1) => v1,
        }
    }
}

/// Message sent by the stream producer.
/// Event sent by the peer.
#[version_with_scale(n = 1, versioned = "VersionedEventMessage")]
#[derive(Debug, Clone, Decode, Encode, IntoSchema)]
pub struct EventMessage(pub Event);

declare_versioned_with_scale!(VersionedEventSubscriptionRequest 1..2, Debug, Clone, FromVariant, IntoSchema);

impl VersionedEventSubscriptionRequest {
    /// Converts from `&VersionedEventSubscriberMessage` to V1 reference
    pub const fn as_v1(&self) -> &EventSubscriptionRequest {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedEventSubscriberMessage` to V1 mutable reference
    pub fn as_mut_v1(&mut self) -> &mut EventSubscriptionRequest {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedEventSubscriberMessage` to V1
    pub fn into_v1(self) -> EventSubscriptionRequest {
        match self {
            Self::V1(v1) => v1,
        }
    }
}

/// Message sent by the stream consumer.
/// Request sent by the client to subscribe to events.
#[version_with_scale(n = 1, versioned = "VersionedEventSubscriptionRequest")]
#[derive(Debug, Clone, Decode, Encode, IntoSchema)]
pub struct EventSubscriptionRequest(pub FilterBox);

/// Event.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    FromVariant,
    IntoSchema,
)]
pub enum Event {
    /// Pipeline event.
    Pipeline(pipeline::Event),
    /// Data event.
    Data(data::Event),
    /// Time event.
    Time(time::Event),
    /// Trigger execution event.
    ExecuteTrigger(execute_trigger::Event),
}

/// Event type. Like [`Event`] but without actual event data
#[derive(Debug, Copy, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, Hash)]
pub enum EventType {
    /// Pipeline event.
    Pipeline,
    /// Data event.
    Data,
    /// Time event.
    Time,
    /// Trigger execution event.
    ExecuteTrigger,
}

/// Trait for filters
pub trait Filter {
    /// Type of event that can be filtered
    type Event;

    /// Check if `item` matches filter
    ///
    /// Returns `true`, if `item` matches filter and `false` if not
    fn matches(&self, event: &Self::Event) -> bool;

    /// Returns a number of times trigger should be executed for
    ///
    /// Used for time-triggers
    fn count_matches(&self, event: &Self::Event) -> u32 {
        if self.matches(event) {
            1
        } else {
            0
        }
    }

    /// Check if filter is mintable.
    ///
    /// Returns `true` by default. Used for time-triggers
    fn mintable(&self) -> bool {
        true
    }
}

/// Event filter.
#[allow(variant_size_differences)]
#[derive(
    Debug,
    Clone,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Decode,
    Encode,
    FromVariant,
    IntoSchema,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum FilterBox {
    /// Listen to pipeline events with filter.
    Pipeline(pipeline::EventFilter),
    /// Listen to data events with filter.
    Data(data::EventFilter),
    /// Listen to time events with filter.
    Time(time::EventFilter),
    /// Listen to trigger execution event with filter.
    ExecuteTrigger(execute_trigger::EventFilter),
}

impl Filter for FilterBox {
    type Event = Event;

    /// Apply filter to event.
    fn matches(&self, event: &Event) -> bool {
        match (event, self) {
            (Event::Pipeline(event), FilterBox::Pipeline(filter)) => filter.matches(event),
            (Event::Data(event), FilterBox::Data(filter)) => filter.matches(event),
            (Event::Time(event), FilterBox::Time(filter)) => filter.matches(event),
            (Event::ExecuteTrigger(event), FilterBox::ExecuteTrigger(filter)) => {
                filter.matches(event)
            }
            _ => false,
        }
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        data::prelude::*, execute_trigger::prelude::*, pipeline::prelude::*, time::prelude::*,
        Event, EventMessage, EventSubscriptionRequest, EventType, Filter, FilterBox,
        VersionedEventMessage, VersionedEventSubscriptionRequest,
    };
}
