//! Notification events and their filter

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use derive_more::Constructor;
use getset::Getters;
use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use strum::EnumDiscriminants;

pub use self::model::*;
use crate::trigger::TriggerId;

#[model]
pub mod model {
    use super::*;

    /// Event that notifies that a trigger was executed
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Constructor,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[ffi_type]
    #[getset(get = "pub")]
    pub struct TriggerCompletedEvent {
        trigger_id: TriggerId,
        outcome: TriggerCompletedOutcome,
    }

    /// Enum to represent outcome of trigger execution
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        FromVariant,
        EnumDiscriminants,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[strum_discriminants(
        name(TriggerCompletedOutcomeType),
        derive(PartialOrd, Ord, Decode, Encode, Deserialize, Serialize, IntoSchema,),
        cfg_attr(
            any(feature = "ffi_import", feature = "ffi_export"),
            derive(iroha_ffi::FfiType)
        ),
        allow(missing_docs),
        repr(u8)
    )]
    #[ffi_type(opaque)]
    pub enum TriggerCompletedOutcome {
        Success,
        Failure(String),
    }

    /// Filter [`TriggerCompletedEvent`] by
    /// 1. if `triger_id` is some filter based on trigger id
    /// 2. if `outcome_type` is some filter based on execution outcome (success/failure)
    /// 3. if both fields are none accept every event of this type
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Default,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[ffi_type]
    #[getset(get = "pub")]
    pub struct TriggerCompletedEventFilter {
        pub(super) trigger_id: Option<TriggerId>,
        pub(super) outcome_type: Option<TriggerCompletedOutcomeType>,
    }
}

impl TriggerCompletedEventFilter {
    /// Creates a new [`TriggerCompletedEventFilter`] accepting all [`TriggerCompletedEvent`]s
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            trigger_id: None,
            outcome_type: None,
        }
    }

    /// Modifies a [`TriggerCompletedEventFilter`] to accept only [`TriggerCompletedEvent`]s originating from a specific trigger
    #[must_use]
    #[inline]
    pub fn for_trigger(mut self, trigger_id: TriggerId) -> Self {
        self.trigger_id = Some(trigger_id);
        self
    }

    /// Modifies a [`TriggerCompletedEventFilter`] to accept only [`TriggerCompletedEvent`]s with a specific outcome
    #[must_use]
    #[inline]
    pub const fn for_outcome(mut self, outcome_type: TriggerCompletedOutcomeType) -> Self {
        self.outcome_type = Some(outcome_type);
        self
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for TriggerCompletedEventFilter {
    type Event = TriggerCompletedEvent;

    /// Check if `self` accepts the `event`.
    #[inline]
    fn matches(&self, event: &Self::Event) -> bool {
        if matches!(self.trigger_id(), Some(trigger_id) if trigger_id != event.trigger_id()) {
            return false;
        }

        if matches!(
            (self.outcome_type(), event.outcome()),
            (
                Some(TriggerCompletedOutcomeType::Success),
                TriggerCompletedOutcome::Failure(_)
            ) | (
                Some(TriggerCompletedOutcomeType::Failure),
                TriggerCompletedOutcome::Success
            )
        ) {
            return false;
        }

        true
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        TriggerCompletedEvent, TriggerCompletedEventFilter, TriggerCompletedOutcome,
        TriggerCompletedOutcomeType,
    };
}

#[cfg(test)]
#[cfg(feature = "transparent_api")]
mod tests {
    use super::*;
    use crate::events::EventFilter;

    #[test]
    fn trigger_completed_events_filter() {
        let trigger_id_1: TriggerId = "trigger_1".parse().expect("Valid");
        let trigger_id_2: TriggerId = "trigger_2".parse().expect("Valid");

        let event_1_failure = TriggerCompletedEvent::new(
            trigger_id_1.clone(),
            TriggerCompletedOutcome::Failure("Error".to_string()),
        );
        let event_1_success =
            TriggerCompletedEvent::new(trigger_id_1.clone(), TriggerCompletedOutcome::Success);
        let event_2_failure = TriggerCompletedEvent::new(
            trigger_id_2.clone(),
            TriggerCompletedOutcome::Failure("Error".to_string()),
        );
        let event_2_success =
            TriggerCompletedEvent::new(trigger_id_2.clone(), TriggerCompletedOutcome::Success);

        let filter_accept_all = TriggerCompletedEventFilter::new();
        assert!(filter_accept_all.matches(&event_1_failure));
        assert!(filter_accept_all.matches(&event_1_success));
        assert!(filter_accept_all.matches(&event_2_failure));
        assert!(filter_accept_all.matches(&event_2_success));

        let filter_accept_success =
            TriggerCompletedEventFilter::new().for_outcome(TriggerCompletedOutcomeType::Success);
        assert!(!filter_accept_success.matches(&event_1_failure));
        assert!(filter_accept_success.matches(&event_1_success));
        assert!(!filter_accept_success.matches(&event_2_failure));
        assert!(filter_accept_success.matches(&event_2_success));

        let filter_accept_failure =
            TriggerCompletedEventFilter::new().for_outcome(TriggerCompletedOutcomeType::Failure);
        assert!(filter_accept_failure.matches(&event_1_failure));
        assert!(!filter_accept_failure.matches(&event_1_success));
        assert!(filter_accept_failure.matches(&event_2_failure));
        assert!(!filter_accept_failure.matches(&event_2_success));

        let filter_accept_1 = TriggerCompletedEventFilter::new().for_trigger(trigger_id_1.clone());
        assert!(filter_accept_1.matches(&event_1_failure));
        assert!(filter_accept_1.matches(&event_1_success));
        assert!(!filter_accept_1.matches(&event_2_failure));
        assert!(!filter_accept_1.matches(&event_2_success));

        let filter_accept_1_failure = TriggerCompletedEventFilter::new()
            .for_trigger(trigger_id_1.clone())
            .for_outcome(TriggerCompletedOutcomeType::Failure);
        assert!(filter_accept_1_failure.matches(&event_1_failure));
        assert!(!filter_accept_1_failure.matches(&event_1_success));
        assert!(!filter_accept_1_failure.matches(&event_2_failure));
        assert!(!filter_accept_1_failure.matches(&event_2_success));

        let filter_accept_1_success = TriggerCompletedEventFilter::new()
            .for_trigger(trigger_id_1)
            .for_outcome(TriggerCompletedOutcomeType::Success);
        assert!(!filter_accept_1_success.matches(&event_1_failure));
        assert!(filter_accept_1_success.matches(&event_1_success));
        assert!(!filter_accept_1_success.matches(&event_2_failure));
        assert!(!filter_accept_1_success.matches(&event_2_success));

        let filter_accept_2 = TriggerCompletedEventFilter::new().for_trigger(trigger_id_2.clone());
        assert!(!filter_accept_2.matches(&event_1_failure));
        assert!(!filter_accept_2.matches(&event_1_success));
        assert!(filter_accept_2.matches(&event_2_failure));
        assert!(filter_accept_2.matches(&event_2_success));

        let filter_accept_2_failure = TriggerCompletedEventFilter::new()
            .for_trigger(trigger_id_2.clone())
            .for_outcome(TriggerCompletedOutcomeType::Failure);
        assert!(!filter_accept_2_failure.matches(&event_1_failure));
        assert!(!filter_accept_2_failure.matches(&event_1_success));
        assert!(filter_accept_2_failure.matches(&event_2_failure));
        assert!(!filter_accept_2_failure.matches(&event_2_success));

        let filter_accept_2_success = TriggerCompletedEventFilter::new()
            .for_trigger(trigger_id_2)
            .for_outcome(TriggerCompletedOutcomeType::Success);
        assert!(!filter_accept_2_success.matches(&event_1_failure));
        assert!(!filter_accept_2_success.matches(&event_1_success));
        assert!(!filter_accept_2_success.matches(&event_2_failure));
        assert!(filter_accept_2_success.matches(&event_2_success));
    }
}
