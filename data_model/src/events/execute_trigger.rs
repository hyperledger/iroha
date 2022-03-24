//! Trigger execution event and filter

use super::*;
use crate::prelude::*;

/// Trigger execution event. Produced every time [`ExecuteTrigger`] instruction is executed
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema)]
pub struct Event {
    /// Id of trigger to be executed
    pub trigger_id: TriggerId,
}

impl Event {
    /// Create new [`Event`] with `trigger_id`
    pub fn new(trigger_id: TriggerId) -> Self {
        Self { trigger_id }
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
    pub trigger_id: TriggerId,
}

impl EventFilter {
    /// Create new [`EventFilter`] with `trigger_id`
    pub fn new(trigger_id: TriggerId) -> Self {
        Self { trigger_id }
    }

    /// Check if `event` matches filter
    ///
    /// Event considered as matched if trigger ids are equal
    pub fn matches(&self, event: &Event) -> bool {
        self.trigger_id == event.trigger_id
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{Event as ExecuteTriggerEvent, EventFilter as ExecuteTriggerEventFilter};
}
