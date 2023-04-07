//! Trigger execution event and filter

use derive_more::Constructor;
use getset::Getters;

use super::*;
use crate::{model, prelude::*};

model! {
    /// Trigger execution event. Produced every time the `ExecuteTrigger` instruction is executed.
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Getters, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct ExecuteTriggerEvent {
        /// Id of trigger to be executed
        pub trigger_id: TriggerId,
        /// Authority of user who tries to execute trigger
        pub authority: AccountId,
    }

    /// Filter for trigger execution [`Event`]
    #[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Constructor, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct ExecuteTriggerEventFilter {
        /// Id of trigger catch executions of
        trigger_id: TriggerId,
        /// Authority of user who owns trigger
        authority: AccountId,
    }
}

#[cfg(feature = "transparent_api")]
impl Filter for ExecuteTriggerEventFilter {
    type Event = ExecuteTriggerEvent;

    /// Check if `event` matches filter
    ///
    /// Event considered as matched if trigger ids are equal
    fn matches(&self, event: &ExecuteTriggerEvent) -> bool {
        self.trigger_id == event.trigger_id && self.authority == event.authority
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{ExecuteTriggerEvent, ExecuteTriggerEventFilter};
}
