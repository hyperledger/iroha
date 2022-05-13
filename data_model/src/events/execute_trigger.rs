//! Trigger execution event and filter

use super::*;
use crate::prelude::*;

/// Trigger execution event. Produced every time [`ExecuteTrigger`] instruction is executed
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema)]
pub struct Event {
    /// Id of trigger to be executed
    trigger_id: TriggerId,
    /// Authority of user who tries to execute trigger
    authority: AccountId,
}

impl Event {
    /// Create new [`Event`] with `trigger_id` and `authority`
    pub const fn new(trigger_id: TriggerId, authority: AccountId) -> Self {
        Self {
            trigger_id,
            authority,
        }
    }
}

/// Filter for trigger execution [`Event`]
#[derive(
    Debug,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Clone,
    Decode,
    Encode,
    IntoSchema,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct EventFilter {
    /// Id of trigger catch executions of
    trigger_id: TriggerId,
    /// Authority of user who owns trigger
    authority: AccountId,
}

impl EventFilter {
    /// Create new [`EventFilter`] with `trigger_id` and `authority`
    pub const fn new(trigger_id: TriggerId, authority: AccountId) -> Self {
        Self {
            trigger_id,
            authority,
        }
    }
}

impl Filter for EventFilter {
    type EventType = Event;

    /// Check if `event` matches filter
    ///
    /// Event considered as matched if trigger ids are equal
    fn matches(&self, event: &Event) -> bool {
        self.trigger_id == event.trigger_id && self.authority == event.authority
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{Event as ExecuteTriggerEvent, EventFilter as ExecuteTriggerEventFilter};
}
