//! Event that notifies some trigger was somehow executed.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use iroha_ffi::FfiType;
use iroha_macro::FromVariant;
use iroha_schema::prelude::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::Filter;
use crate::prelude::{Metadata, TriggerId};

/// [`Event`] filter.
#[derive(
    Default,
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
    FfiType,
)]
pub struct EventFilter {
    /// If `Some`, filters by the [`TriggerId`]. Otherwise accepts any [`TriggerId`].
    pub id: Option<TriggerId>,
    /// If `Some`, filters by the [`StatusKind`]. Otherwise accepts any [`StatusKind`].
    pub status_kind: Option<StatusKind>,
}

impl EventFilter {
    /// Construct [`EventFilter`].
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by [`TriggerId`].
    #[must_use]
    #[inline]
    pub fn id(mut self, id: TriggerId) -> Self {
        self.id = Some(id);
        self
    }

    /// Filter by [`StatusKind`].
    #[must_use]
    #[inline]
    pub const fn status_kind(mut self, status_kind: StatusKind) -> Self {
        self.status_kind = Some(status_kind);
        self
    }

    #[inline]
    fn field_matches<T: Eq>(filter: Option<&T>, event: &T) -> bool {
        filter.map_or(true, |field| field == event)
    }
}

impl Filter for EventFilter {
    type Event = Event;

    /// Check if `self` accepts the `event`.
    #[inline]
    fn matches(&self, event: &Event) -> bool {
        [
            Self::field_matches(self.id.as_ref(), &event.id),
            Self::field_matches(self.status_kind.as_ref(), &event.status.kind()),
        ]
        .into_iter()
        .all(core::convert::identity)
    }
}

/// Notification that some trigger was somehow executed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Event {
    /// Which trigger was executed.
    pub id: TriggerId,
    /// How the trigger execution is going on, or resulted in.
    pub status: Status,
}

impl Event {
    /// Construct [`Event`].
    pub const fn new(id: TriggerId, status: Status) -> Self {
        Event { id, status }
    }
}

/// How the trigger execution is going on, or resulted in.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    Serialize,
    Deserialize,
    FromVariant,
    IntoSchema,
)]
pub enum Status {
    /// The trigger execution was succeeded.
    Succeeded,
    /// The trigger execution was failed due to [`FailReason`].
    Failed(FailReason),
}

/// Details of why the trigger execution failed.
pub type FailReason = Metadata;

/// Abstraction of [`Status`].
#[derive(
    Debug,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Decode,
    Encode,
    IntoSchema,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum StatusKind {
    /// The trigger execution was succeeded.
    Succeeded,
    /// The trigger execution was failed.
    Failed,
}

impl Status {
    fn kind(&self) -> StatusKind {
        use Status::*;
        match self {
            Succeeded => StatusKind::Succeeded,
            Failed(_) => StatusKind::Failed,
        }
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        Event as TriggerExecutedEvent, EventFilter as TriggerExecutedEventFilter,
        FailReason as TriggerExecutedFailReason, Status as TriggerExecutedStatus,
        StatusKind as TriggerExecutedStatusKind,
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]
    #[cfg(not(feature = "std"))]
    use alloc::{string::ToString as _, vec, vec::Vec};

    use super::*;

    #[test]
    fn events_are_correctly_filtered() {
        let events = vec![
            Event::new(
                "contract_1$jurisdiction".parse::<TriggerId>().unwrap(),
                Status::Succeeded,
            ),
            Event::new(
                "contract_1$jurisdiction".parse::<TriggerId>().unwrap(),
                Status::Failed(FailReason::default()),
            ),
            Event::new(
                "contract_2$jurisdiction".parse::<TriggerId>().unwrap(),
                Status::Succeeded,
            ),
            Event::new(
                "contract_2$jurisdiction".parse::<TriggerId>().unwrap(),
                Status::Failed(FailReason::default()),
            ),
        ];
        assert_eq!(
            events
                .iter()
                .cloned()
                .filter(|event| EventFilter::new().matches(event))
                .collect::<Vec<Event>>(),
            events,
        );
        assert_eq!(
            events
                .iter()
                .cloned()
                .filter(|event| EventFilter::new()
                    .id("contract_1$jurisdiction".parse::<TriggerId>().unwrap())
                    .matches(event))
                .collect::<Vec<Event>>(),
            vec![
                Event::new(
                    "contract_1$jurisdiction".parse::<TriggerId>().unwrap(),
                    Status::Succeeded,
                ),
                Event::new(
                    "contract_1$jurisdiction".parse::<TriggerId>().unwrap(),
                    Status::Failed(FailReason::default()),
                ),
            ],
        );
        assert_eq!(
            events
                .iter()
                .cloned()
                .filter(|event| EventFilter::new()
                    .status_kind(StatusKind::Failed)
                    .matches(event))
                .collect::<Vec<Event>>(),
            vec![
                Event::new(
                    "contract_1$jurisdiction".parse::<TriggerId>().unwrap(),
                    Status::Failed(FailReason::default()),
                ),
                Event::new(
                    "contract_2$jurisdiction".parse::<TriggerId>().unwrap(),
                    Status::Failed(FailReason::default()),
                )
            ],
        );
        assert_eq!(
            events
                .iter()
                .cloned()
                .filter(|event| EventFilter::new()
                    .id("contract_1$jurisdiction".parse::<TriggerId>().unwrap())
                    .status_kind(StatusKind::Succeeded)
                    .matches(event))
                .collect::<Vec<Event>>(),
            vec![Event::new(
                "contract_1$jurisdiction".parse::<TriggerId>().unwrap(),
                Status::Succeeded,
            ),],
        );
    }
}
