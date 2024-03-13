//! Trigger execution event and filter

use getset::Getters;
use iroha_data_model_derive::model;

pub use self::model::*;
use super::*;
use crate::prelude::*;

#[model]
pub mod model {
    use super::*;

    /// Trigger execution event. Produced every time the `ExecuteTrigger` instruction is executed.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct ExecuteTriggerEvent {
        /// Id of trigger to be executed
        pub trigger_id: TriggerId,
        /// Authority of user who tries to execute trigger
        pub authority: AccountId,
    }

    /// Filter for trigger execution [`Event`]
    #[derive(
        Debug,
        Clone,
        PartialOrd,
        Ord,
        PartialEq,
        Eq,
        Default,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct ExecuteTriggerEventFilter {
        /// Id of trigger catch executions of
        pub(super) trigger_id: Option<TriggerId>,
        /// Authority of user who owns trigger
        pub(super) authority: Option<AccountId>,
    }
}

impl ExecuteTriggerEventFilter {
    /// Creates a new [`ExecuteTriggerEventFilter`] accepting all [`ExecuteTriggerEvent`]s
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            trigger_id: None,
            authority: None,
        }
    }

    /// Modifies a [`ExecuteTriggerEventFilter`] to accept only [`ExecuteTriggerEvent`]s originating from a specific trigger
    #[must_use]
    #[inline]
    pub fn for_trigger(mut self, trigger_id: TriggerId) -> Self {
        self.trigger_id = Some(trigger_id);
        self
    }

    /// Modifies a [`ExecuteTriggerEventFilter`] to accept only [`ExecuteTriggerEvent`]s from triggers executed under specific authority
    #[must_use]
    #[inline]
    pub fn under_authority(mut self, authority: AccountId) -> Self {
        self.authority = Some(authority);
        self
    }
}

#[cfg(feature = "transparent_api")]
impl EventFilter for ExecuteTriggerEventFilter {
    type Event = ExecuteTriggerEvent;

    /// Check if `event` matches filter
    ///
    /// Event considered as matched if trigger ids are equal
    fn matches(&self, event: &ExecuteTriggerEvent) -> bool {
        if let Some(trigger_id) = &self.trigger_id {
            if trigger_id != &event.trigger_id {
                return false;
            }
        }
        if let Some(authority) = &self.authority {
            if authority != &event.authority {
                return false;
            }
        }

        true
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{ExecuteTriggerEvent, ExecuteTriggerEventFilter};
}
