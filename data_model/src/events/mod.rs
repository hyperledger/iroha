//! Events for streaming API.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};

use iroha_macro::FromVariant;
use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::model;

pub mod data;
pub mod execute_trigger;
pub mod pipeline;
pub mod time;

model! {
    #[allow(missing_docs)]
    #[derive(Debug, Clone, PartialEq, Eq, Hash, FromVariant, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[ffi_type]
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
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Decode, Encode, IntoSchema)]
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
    #[inline]
    fn count_matches(&self, event: &Self::Event) -> u32 {
        self.matches(event).into()
    }

    /// Check if filter is mintable.
    ///
    /// Returns `true` by default. Used for time-triggers
    #[inline]
    fn mintable(&self) -> bool {
        true
    }
}

model! {
    /// Event filter.
    #[allow(variant_size_differences)]
    #[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, FromVariant, Decode, Encode, Deserialize, Serialize, IntoSchema)]
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

#[cfg(feature = "http")]
pub mod stream {
    //! Structures related to event streaming over HTTP

    use derive_more::Constructor;
    use iroha_version::prelude::*;

    use super::*;

    declare_versioned_with_scale!(VersionedEventMessage 1..2, Debug, Clone, FromVariant, IntoSchema);

    impl VersionedEventMessage {
        #[allow(missing_docs)]
        pub const fn as_v1(&self) -> &EventMessage {
            match self {
                Self::V1(v1) => v1,
            }
        }

        #[allow(missing_docs)]
        pub fn as_mut_v1(&mut self) -> &mut EventMessage {
            match self {
                Self::V1(v1) => v1,
            }
        }

        #[allow(missing_docs)]
        pub fn into_v1(self) -> EventMessage {
            match self {
                Self::V1(v1) => v1,
            }
        }
    }

    model! {
        /// Message sent by the stream producer.
        /// Event sent by the peer.
        #[version_with_scale(n = 1, versioned = "VersionedEventMessage")]
        #[derive(Debug, Clone, Decode, Encode, IntoSchema)]
        #[repr(transparent)]
        pub struct EventMessage(pub Event);
    }

    impl From<EventMessage> for Event {
        fn from(source: EventMessage) -> Self {
            source.0
        }
    }

    declare_versioned_with_scale!(VersionedEventSubscriptionRequest 1..2, Debug, Clone, FromVariant, IntoSchema);

    impl VersionedEventSubscriptionRequest {
        #[allow(missing_docs)]
        pub const fn as_v1(&self) -> &EventSubscriptionRequest {
            match self {
                Self::V1(v1) => v1,
            }
        }

        #[allow(missing_docs)]
        pub fn as_mut_v1(&mut self) -> &mut EventSubscriptionRequest {
            match self {
                Self::V1(v1) => v1,
            }
        }

        #[allow(missing_docs)]
        pub fn into_v1(self) -> EventSubscriptionRequest {
            match self {
                Self::V1(v1) => v1,
            }
        }
    }

    model! {
        /// Message sent by the stream consumer.
        /// Request sent by the client to subscribe to events.
        #[version_with_scale(n = 1, versioned = "VersionedEventSubscriptionRequest")]
        #[derive(Debug, Clone, Constructor, Decode, Encode, IntoSchema)]
        #[repr(transparent)]
        pub struct EventSubscriptionRequest(pub FilterBox);
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    #[cfg(feature = "http")]
    pub use super::stream::{
        EventMessage, EventSubscriptionRequest, VersionedEventMessage,
        VersionedEventSubscriptionRequest,
    };
    pub use super::{
        data::prelude::*, execute_trigger::prelude::*, pipeline::prelude::*, time::prelude::*,
        Event, EventType, Filter, FilterBox,
    };
}
