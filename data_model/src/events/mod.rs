//! Events for streaming API.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;

pub mod data;
pub mod execute_trigger;
pub mod pipeline;
pub mod time;

#[model]
pub mod model {
    use super::*;

    #[allow(missing_docs)]
    #[derive(
        Debug, Clone, PartialEq, Eq, FromVariant, Decode, Encode, Deserialize, Serialize, IntoSchema,
    )]
    #[ffi_type]
    pub enum Event {
        /// Pipeline event.
        Pipeline(pipeline::PipelineEvent),
        /// Data event.
        Data(data::DataEvent),
        /// Time event.
        Time(time::TimeEvent),
        /// Trigger execution event.
        ExecuteTrigger(execute_trigger::ExecuteTriggerEvent),
    }

    /// Event type. Like [`Event`] but without actual event data
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema)]
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

    /// Event filter.
    #[allow(variant_size_differences)]
    #[derive(
        Debug, Clone, PartialEq, Eq, FromVariant, Decode, Encode, Deserialize, Serialize, IntoSchema,
    )]
    // TODO: Temporarily made opaque
    #[ffi_type(opaque)]
    pub enum FilterBox {
        /// Listen to pipeline events with filter.
        Pipeline(pipeline::PipelineEventFilter),
        /// Listen to data events with filter.
        Data(data::DataEventFilter),
        /// Listen to time events with filter.
        Time(time::TimeEventFilter),
        /// Listen to trigger execution event with filter.
        ExecuteTrigger(execute_trigger::ExecuteTriggerEventFilter),
    }
}

/// Trait for filters
#[cfg(feature = "transparent_api")]
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

#[cfg(feature = "transparent_api")]
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
    use iroha_data_model_derive::model;
    use iroha_version::prelude::*;

    pub use self::model::*;
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

    #[model]
    pub mod model {
        use super::*;

        /// Message sent by the stream producer.
        /// Event sent by the peer.
        #[version_with_scale(n = 1, versioned = "VersionedEventMessage")]
        #[derive(Debug, Clone, Decode, Encode, IntoSchema)]
        #[repr(transparent)]
        pub struct EventMessage(pub Event);

        /// Message sent by the stream consumer.
        /// Request sent by the client to subscribe to events.
        #[version_with_scale(n = 1, versioned = "VersionedEventSubscriptionRequest")]
        #[derive(Debug, Clone, Constructor, Decode, Encode, IntoSchema)]
        #[repr(transparent)]
        pub struct EventSubscriptionRequest(pub FilterBox);
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
}

/// Exports common structs and enums from this module.
pub mod prelude {
    #[cfg(feature = "http")]
    pub use super::stream::{
        EventMessage, EventSubscriptionRequest, VersionedEventMessage,
        VersionedEventSubscriptionRequest,
    };
    #[cfg(feature = "transparent_api")]
    pub use super::Filter;
    pub use super::{
        data::prelude::*, execute_trigger::prelude::*, pipeline::prelude::*, time::prelude::*,
        Event, EventType, FilterBox,
    };
}
