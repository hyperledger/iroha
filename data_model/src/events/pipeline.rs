//! Pipeline events.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use iroha_crypto::Hash;
use iroha_macro::FromVariant;
use iroha_schema::prelude::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use crate::transaction::RejectionReason as PipelineRejectionReason;

/// [`Event`] filter.
#[derive(
    Default,
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
pub struct EventFilter {
    /// If `Some::<EntityKind>` filters by the [`EntityKind`]. If `None` accepts all the [`EntityKind`].
    pub entity_kind: Option<EntityKind>,
    /// If `Some::<StatusKind>` filters by the [`StatusKind`]. If `None` accepts all the [`StatusKind`].
    pub status_kind: Option<StatusKind>,
    /// If `Some::<Hash>` filters by the [`Hash`]. If `None` accepts all the [`Hash`].
    pub hash: Option<Hash>,
}

impl EventFilter {
    /// Construct [`EventFilter`].
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by [`EntityKind`].
    #[must_use]
    #[inline]
    pub const fn entity_kind(mut self, entity_kind: EntityKind) -> Self {
        self.entity_kind = Some(entity_kind);
        self
    }

    /// Filter by [`StatusKind`].
    #[must_use]
    #[inline]
    pub const fn status_kind(mut self, status_kind: StatusKind) -> Self {
        self.status_kind = Some(status_kind);
        self
    }

    /// Filter by [`Hash`].
    #[must_use]
    #[inline]
    pub const fn hash(mut self, hash: Hash) -> Self {
        self.hash = Some(hash);
        self
    }

    /// Check if `self` accepts the `event`.
    #[inline]
    pub fn matches(&self, event: &Event) -> bool {
        [
            Self::field_matches(&self.entity_kind, &event.entity_kind),
            Self::field_matches(&self.status_kind, &event.status.kind()),
            Self::field_matches(&self.hash, &event.hash),
        ]
        .into_iter()
        .all(core::convert::identity)
    }

    #[inline]
    fn field_matches<T: Eq>(filter: &Option<T>, event: &T) -> bool {
        filter.as_ref().map_or(true, |field| field == event)
    }
}

/// Kind of the pipeline entity.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum EntityKind {
    /// Block.
    Block,
    /// Transaction.
    Transaction,
}

/// Strongly-typed [`Event`], which tells the receiver the kind of entity that changed, the change, and the hash of the entity.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema)]
pub struct Event {
    /// [`EntityKind`] of the entity that caused this [`Event`].
    pub entity_kind: EntityKind,
    /// [`Status`] of the entity that caused this [`Event`].
    pub status: Status,
    /// [`Hash`] of the entity that caused this [`Event`].
    pub hash: Hash,
}

impl Event {
    /// Construct [`Event`].
    pub const fn new(entity_kind: EntityKind, status: Status, hash: Hash) -> Self {
        Event {
            entity_kind,
            status,
            hash,
        }
    }
}

/// [`Status`] of the entity.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, FromVariant, IntoSchema)]
pub enum Status {
    /// Entity has been seen in blockchain, but has not passed validation.
    Validating,
    /// Entity was rejected in one of the validation stages.
    Rejected(PipelineRejectionReason),
    /// Entity has passed validation.
    Committed,
}

/// Kind of [`Status`].
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
    /// Represents [`Status::Validating`].
    Validating,
    /// Represents [`Status::Rejected`].
    Rejected,
    /// Represents [`Status::Committed`].
    Committed,
}

impl Status {
    fn kind(&self) -> StatusKind {
        use Status::*;
        match self {
            Validating => StatusKind::Validating,
            Rejected(_) => StatusKind::Rejected,
            Committed => StatusKind::Committed,
        }
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        EntityKind as PipelineEntityKind, Event as PipelineEvent,
        EventFilter as PipelineEventFilter, PipelineRejectionReason, Status as PipelineStatus,
        StatusKind as PipelineStatusKind,
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    #[cfg(not(feature = "std"))]
    use alloc::{string::ToString as _, vec, vec::Vec};

    use super::*;
    use crate::transaction::{NotPermittedFail, RejectionReason::*, TransactionRejectionReason::*};

    #[test]
    fn events_are_correctly_filtered() {
        let events = vec![
            Event {
                entity_kind: EntityKind::Transaction,
                status: Status::Validating,
                hash: Hash([0_u8; 32]),
            },
            Event {
                entity_kind: EntityKind::Transaction,
                status: Status::Rejected(Transaction(NotPermitted(NotPermittedFail {
                    reason: "Some reason".to_string(),
                }))),
                hash: Hash([0_u8; 32]),
            },
            Event {
                entity_kind: EntityKind::Transaction,
                status: Status::Committed,
                hash: Hash([2_u8; 32]),
            },
            Event {
                entity_kind: EntityKind::Block,
                status: Status::Committed,
                hash: Hash([2_u8; 32]),
            },
        ];
        assert_eq!(
            vec![
                Event {
                    entity_kind: EntityKind::Transaction,
                    status: Status::Validating,
                    hash: Hash([0_u8; 32]),
                },
                Event {
                    entity_kind: EntityKind::Transaction,
                    status: Status::Rejected(Transaction(NotPermitted(NotPermittedFail {
                        reason: "Some reason".to_string(),
                    }))),
                    hash: Hash([0_u8; 32]),
                },
            ],
            events
                .iter()
                .cloned()
                .filter(|event| EventFilter::new().hash(Hash([0_u8; 32])).matches(event))
                .collect::<Vec<Event>>()
        );
        assert_eq!(
            vec![Event {
                entity_kind: EntityKind::Block,
                status: Status::Committed,
                hash: Hash([2_u8; 32]),
            }],
            events
                .iter()
                .cloned()
                .filter(|event| EventFilter::new()
                    .entity_kind(EntityKind::Block)
                    .matches(event))
                .collect::<Vec<Event>>()
        );
        assert_eq!(
            vec![Event {
                entity_kind: EntityKind::Transaction,
                status: Status::Committed,
                hash: Hash([2_u8; 32]),
            }],
            events
                .iter()
                .cloned()
                .filter(|event| EventFilter::new()
                    .entity_kind(EntityKind::Transaction)
                    .hash(Hash([2_u8; 32]))
                    .matches(event))
                .collect::<Vec<Event>>()
        );
        assert_eq!(
            events,
            events
                .iter()
                .cloned()
                .filter(|event| EventFilter::new().matches(event))
                .collect::<Vec<Event>>()
        )
    }
}
