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
pub mod notification;
pub mod pipeline;
pub mod time;

#[model]
pub mod model {
    use super::*;

    #[allow(missing_docs)]
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        FromVariant,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
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
        /// Notification event.
        Notification(notification::NotificationEvent),
    }

    /// Event type which could invoke trigger execution.
    #[derive(
        Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, Serialize, Deserialize,
    )]
    pub enum TriggeringEventType {
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
    pub enum EventFilterBox {
        /// Listen to pipeline events with filter.
        Pipeline(pipeline::PipelineEventFilter),
        /// Listen to data events with filter.
        Data(data::DataEventFilter),
        /// Listen to time events with filter.
        Time(time::TimeEventFilter),
        /// Listen to trigger execution event with filter.
        ExecuteTrigger(execute_trigger::ExecuteTriggerEventFilter),
        /// Listen to notifications event with filter.
        Notification(notification::NotificationEventFilter),
    }

    /// Event filter which could be attached to trigger.
    #[allow(variant_size_differences)]
    #[derive(
        Debug, Clone, PartialEq, Eq, FromVariant, Decode, Encode, Deserialize, Serialize, IntoSchema,
    )]
    // TODO: Temporarily made opaque
    #[ffi_type(opaque)]
    pub enum TriggeringEventFilterBox {
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
pub trait EventFilter {
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
impl EventFilter for EventFilterBox {
    type Event = Event;

    /// Apply filter to event.
    fn matches(&self, event: &Event) -> bool {
        match (event, self) {
            (Event::Pipeline(event), Self::Pipeline(filter)) => filter.matches(event),
            (Event::Data(event), Self::Data(filter)) => filter.matches(event),
            (Event::Time(event), Self::Time(filter)) => filter.matches(event),
            (Event::ExecuteTrigger(event), Self::ExecuteTrigger(filter)) => filter.matches(event),
            (Event::Notification(event), Self::Notification(filter)) => filter.matches(event),
            // Fail to compile in case when new variant to event or filter is added
            (
                Event::Pipeline(_)
                | Event::Data(_)
                | Event::Time(_)
                | Event::ExecuteTrigger(_)
                | Event::Notification(_),
                Self::Pipeline(_)
                | Self::Data(_)
                | Self::Time(_)
                | Self::ExecuteTrigger(_)
                | Self::Notification(_),
            ) => false,
        }
    }
}

#[cfg(feature = "transparent_api")]
impl EventFilter for TriggeringEventFilterBox {
    type Event = Event;

    /// Apply filter to event.
    fn matches(&self, event: &Event) -> bool {
        match (event, self) {
            (Event::Pipeline(event), Self::Pipeline(filter)) => filter.matches(event),
            (Event::Data(event), Self::Data(filter)) => filter.matches(event),
            (Event::Time(event), Self::Time(filter)) => filter.matches(event),
            (Event::ExecuteTrigger(event), Self::ExecuteTrigger(filter)) => filter.matches(event),
            // Fail to compile in case when new variant to event or filter is added
            (
                Event::Pipeline(_)
                | Event::Data(_)
                | Event::Time(_)
                | Event::ExecuteTrigger(_)
                | Event::Notification(_),
                Self::Pipeline(_) | Self::Data(_) | Self::Time(_) | Self::ExecuteTrigger(_),
            ) => false,
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

    #[model]
    pub mod model {
        use super::*;

        /// Message sent by the stream producer.
        /// Event sent by the peer.
        #[derive(Debug, Clone, Decode, Encode, IntoSchema)]
        #[repr(transparent)]
        pub struct EventMessage(pub Event);

        /// Message sent by the stream consumer.
        /// Request sent by the client to subscribe to events.
        #[derive(Debug, Clone, Constructor, Decode, Encode, IntoSchema)]
        #[repr(transparent)]
        pub struct EventSubscriptionRequest(pub EventFilterBox);
    }

    impl From<EventMessage> for Event {
        fn from(source: EventMessage) -> Self {
            source.0
        }
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    #[cfg(feature = "http")]
    pub use super::stream::{EventMessage, EventSubscriptionRequest};
    #[cfg(feature = "transparent_api")]
    pub use super::EventFilter;
    pub use super::{
        data::prelude::*, execute_trigger::prelude::*, notification::prelude::*,
        pipeline::prelude::*, time::prelude::*, Event, EventFilterBox, TriggeringEventFilterBox,
        TriggeringEventType,
    };
}
