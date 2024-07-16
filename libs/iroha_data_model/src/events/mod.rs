//! Events for streaming API.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use pipeline::{BlockEvent, TransactionEvent};
use serde::{Deserialize, Serialize};

pub use self::model::*;

pub mod data;
pub mod execute_trigger;
pub mod pipeline;
pub mod time;
pub mod trigger_completed;

#[model]
mod model {
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
    pub enum EventBox {
        /// Pipeline event.
        Pipeline(pipeline::PipelineEventBox),
        /// Data event.
        Data(data::DataEvent),
        /// Time event.
        Time(time::TimeEvent),
        /// Trigger execution event.
        ExecuteTrigger(execute_trigger::ExecuteTriggerEvent),
        /// Trigger completion event.
        TriggerCompleted(trigger_completed::TriggerCompletedEvent),
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
    // TODO: Temporarily made opaque
    #[ffi_type(opaque)]
    pub enum EventFilterBox {
        /// Listen to pipeline events with filter.
        Pipeline(pipeline::PipelineEventFilterBox),
        /// Listen to data events with filter.
        Data(data::DataEventFilter),
        /// Listen to time events with filter.
        Time(time::TimeEventFilter),
        /// Listen to trigger execution event with filter.
        ExecuteTrigger(execute_trigger::ExecuteTriggerEventFilter),
        /// Listen to trigger completion event with filter.
        TriggerCompleted(trigger_completed::TriggerCompletedEventFilter),
    }

    /// Event filter which could be attached to trigger.
    #[allow(variant_size_differences)]
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
    // TODO: Temporarily made opaque
    #[ffi_type(opaque)]
    pub enum TriggeringEventFilterBox {
        /// Listen to pipeline events with filter.
        Pipeline(pipeline::PipelineEventFilterBox),
        /// Listen to data events with filter.
        Data(data::DataEventFilter),
        /// Listen to time events with filter.
        Time(time::TimeEventFilter),
        /// Listen to trigger execution event with filter.
        ExecuteTrigger(execute_trigger::ExecuteTriggerEventFilter),
    }
}

impl From<TransactionEvent> for EventBox {
    fn from(source: TransactionEvent) -> Self {
        Self::Pipeline(source.into())
    }
}

impl From<BlockEvent> for EventBox {
    fn from(source: BlockEvent) -> Self {
        Self::Pipeline(source.into())
    }
}

impl TryFrom<EventBox> for TransactionEvent {
    type Error = iroha_macro::error::ErrorTryFromEnum<EventBox, Self>;

    fn try_from(event: EventBox) -> Result<Self, Self::Error> {
        use iroha_macro::error::ErrorTryFromEnum;

        let EventBox::Pipeline(pipeline_event) = event else {
            return Err(ErrorTryFromEnum::default());
        };

        pipeline_event
            .try_into()
            .map_err(|_| ErrorTryFromEnum::default())
    }
}

impl TryFrom<EventBox> for BlockEvent {
    type Error = iroha_macro::error::ErrorTryFromEnum<EventBox, Self>;

    fn try_from(event: EventBox) -> Result<Self, Self::Error> {
        use iroha_macro::error::ErrorTryFromEnum;

        let EventBox::Pipeline(pipeline_event) = event else {
            return Err(ErrorTryFromEnum::default());
        };

        pipeline_event
            .try_into()
            .map_err(|_| ErrorTryFromEnum::default())
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
    type Event = EventBox;

    /// Apply filter to event.
    fn matches(&self, event: &EventBox) -> bool {
        match (event, self) {
            (EventBox::Pipeline(event), Self::Pipeline(filter)) => filter.matches(event),
            (EventBox::Data(event), Self::Data(filter)) => filter.matches(event),
            (EventBox::Time(event), Self::Time(filter)) => filter.matches(event),
            (EventBox::ExecuteTrigger(event), Self::ExecuteTrigger(filter)) => {
                filter.matches(event)
            }
            (EventBox::TriggerCompleted(event), Self::TriggerCompleted(filter)) => {
                filter.matches(event)
            }
            // Fail to compile in case when new variant to event or filter is added
            (
                EventBox::Pipeline(_)
                | EventBox::Data(_)
                | EventBox::Time(_)
                | EventBox::ExecuteTrigger(_)
                | EventBox::TriggerCompleted(_),
                Self::Pipeline(_)
                | Self::Data(_)
                | Self::Time(_)
                | Self::ExecuteTrigger(_)
                | Self::TriggerCompleted(_),
            ) => false,
        }
    }
}

#[cfg(feature = "transparent_api")]
impl EventFilter for TriggeringEventFilterBox {
    type Event = EventBox;

    /// Apply filter to event.
    fn matches(&self, event: &EventBox) -> bool {
        match (event, self) {
            (EventBox::Pipeline(event), Self::Pipeline(filter)) => filter.matches(event),
            (EventBox::Data(event), Self::Data(filter)) => filter.matches(event),
            (EventBox::Time(event), Self::Time(filter)) => filter.matches(event),
            (EventBox::ExecuteTrigger(event), Self::ExecuteTrigger(filter)) => {
                filter.matches(event)
            }
            // Fail to compile in case when new variant to event or filter is added
            (
                EventBox::Pipeline(_)
                | EventBox::Data(_)
                | EventBox::Time(_)
                | EventBox::ExecuteTrigger(_)
                | EventBox::TriggerCompleted(_),
                Self::Pipeline(_) | Self::Data(_) | Self::Time(_) | Self::ExecuteTrigger(_),
            ) => false,
        }
    }
}

mod conversions {
    use super::{
        pipeline::{BlockEventFilter, TransactionEventFilter},
        prelude::*,
    };

    macro_rules! last_tt {
        ($last:tt) => {
            $last
        };
        ($head:tt $($tail:tt)+) => {
            last_tt!($($tail)*)
        };
    }

    // chain multiple conversions into one
    macro_rules! impl_from_via_path {
        ($($initial:ty $(=> $intermediate:ty)*),+ $(,)?) => {
            $(
                impl From<$initial> for last_tt!($($intermediate)*) {
                    fn from(filter: $initial) -> Self {
                        $(
                            let filter: $intermediate = filter.into();
                        )*
                        filter
                    }
                }
            )+
        };
    }

    impl_from_via_path! {
        PeerEventFilter             => DataEventFilter => EventFilterBox,
        DomainEventFilter           => DataEventFilter => EventFilterBox,
        AccountEventFilter          => DataEventFilter => EventFilterBox,
        AssetEventFilter            => DataEventFilter => EventFilterBox,
        AssetDefinitionEventFilter  => DataEventFilter => EventFilterBox,
        TriggerEventFilter          => DataEventFilter => EventFilterBox,
        RoleEventFilter             => DataEventFilter => EventFilterBox,
        ConfigurationEventFilter    => DataEventFilter => EventFilterBox,
        ExecutorEventFilter         => DataEventFilter => EventFilterBox,

        PeerEventFilter             => DataEventFilter => TriggeringEventFilterBox,
        DomainEventFilter           => DataEventFilter => TriggeringEventFilterBox,
        AccountEventFilter          => DataEventFilter => TriggeringEventFilterBox,
        AssetEventFilter            => DataEventFilter => TriggeringEventFilterBox,
        AssetDefinitionEventFilter  => DataEventFilter => TriggeringEventFilterBox,
        TriggerEventFilter          => DataEventFilter => TriggeringEventFilterBox,
        RoleEventFilter             => DataEventFilter => TriggeringEventFilterBox,
        ConfigurationEventFilter    => DataEventFilter => TriggeringEventFilterBox,
        ExecutorEventFilter         => DataEventFilter => TriggeringEventFilterBox,

        TransactionEventFilter => PipelineEventFilterBox => TriggeringEventFilterBox,
        BlockEventFilter       => PipelineEventFilterBox => TriggeringEventFilterBox,

        TransactionEventFilter => PipelineEventFilterBox => EventFilterBox,
        BlockEventFilter       => PipelineEventFilterBox => EventFilterBox,
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
    mod model {
        use super::*;

        /// Message sent by the stream producer.
        /// Event sent by the peer.
        #[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize, IntoSchema)]
        #[repr(transparent)]
        pub struct EventMessage(pub EventBox);

        /// Message sent by the stream consumer.
        /// Request sent by the client to subscribe to events.
        #[derive(Debug, Clone, Constructor, Decode, Encode, Deserialize, Serialize, IntoSchema)]
        #[repr(transparent)]
        pub struct EventSubscriptionRequest(pub Vec<EventFilterBox>);
    }

    impl From<EventMessage> for EventBox {
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
        data::prelude::*, execute_trigger::prelude::*, pipeline::prelude::*, time::prelude::*,
        trigger_completed::prelude::*, EventBox, EventFilterBox, TriggeringEventFilterBox,
        TriggeringEventType,
    };
}
