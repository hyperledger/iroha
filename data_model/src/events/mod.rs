//! Events for streaming API.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use data::Filter;
use iroha_macro::FromVariant;
use iroha_schema::prelude::*;
use iroha_version::prelude::*;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub mod data;
pub mod pipeline;
pub mod time;

declare_versioned_with_scale!(VersionedEventPublisherMessage 1..2, Debug, Clone, FromVariant, IntoSchema);

impl VersionedEventPublisherMessage {
    /// Converts from `&VersionedEventPublisherMessage` to V1 reference
    pub const fn as_v1(&self) -> &EventPublisherMessage {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedEventPublisherMessage` to V1 mutable reference
    pub fn as_mut_v1(&mut self) -> &mut EventPublisherMessage {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedEventPublisherMessage` to V1
    pub fn into_v1(self) -> EventPublisherMessage {
        match self {
            Self::V1(v1) => v1,
        }
    }
}

/// Message sent by the stream producer
#[version_with_scale(n = 1, versioned = "VersionedEventPublisherMessage")]
#[derive(Debug, Clone, Decode, Encode, FromVariant, IntoSchema)]
pub enum EventPublisherMessage {
    /// Reply sent by the peer.
    /// The message means that event stream connection is initialized and will be supplying
    /// events starting with the next message.
    SubscriptionAccepted,
    /// Event sent by the peer.
    Event(Event),
}

declare_versioned_with_scale!(VersionedEventSubscriberMessage 1..2, Debug, Clone, FromVariant, IntoSchema);

impl VersionedEventSubscriberMessage {
    /// Converts from `&VersionedEventSubscriberMessage` to V1 reference
    pub const fn as_v1(&self) -> &EventSubscriberMessage {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedEventSubscriberMessage` to V1 mutable reference
    pub fn as_mut_v1(&mut self) -> &mut EventSubscriberMessage {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedEventSubscriberMessage` to V1
    pub fn into_v1(self) -> EventSubscriberMessage {
        match self {
            Self::V1(v1) => v1,
        }
    }
}

/// Message sent by the stream consumer
#[version_with_scale(n = 1, versioned = "VersionedEventSubscriberMessage")]
#[derive(Debug, Clone, Decode, Encode, FromVariant, IntoSchema)]
pub enum EventSubscriberMessage {
    /// Request sent by the client to subscribe to events.
    //TODO: Sign request?
    SubscriptionRequest(EventFilter),
    /// Acknowledgment of receiving event sent from the peer.
    EventReceived,
}

/// Event.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, FromVariant, IntoSchema)]
pub enum Event {
    /// Pipeline event.
    Pipeline(pipeline::Event),
    /// Data event.
    Data(data::Event),
    /// Time event.
    Time(time::Event),
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
pub enum EventFilter {
    /// Listen to pipeline events with filter.
    Pipeline(pipeline::EventFilter),
    /// Listen to data events with filter.
    Data(data::EventFilter),
    /// Listen to time events with filter.
    Time(time::EventFilter),
}

impl EventFilter {
    /// Apply filter to event.
    pub fn matches(&self, event: &Event) -> bool {
        match (event, self) {
            (Event::Pipeline(event), EventFilter::Pipeline(filter)) => filter.matches(event),
            (Event::Data(event), EventFilter::Data(filter)) => filter.matches(event),
            (Event::Time(event), EventFilter::Time(filter)) => filter.count_matches(event) > 0,
            _ => false,
        }
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        data::prelude::*, pipeline::prelude::*, time::prelude::*, Event, EventFilter,
        EventPublisherMessage, EventSubscriberMessage, VersionedEventPublisherMessage,
        VersionedEventSubscriberMessage,
    };
}
