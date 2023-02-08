//! Pipeline events.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use derive_more::Display;
use getset::Getters;
use iroha_crypto::Hash;
use iroha_macro::FromVariant;
use iroha_schema::prelude::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::Filter;
use crate::model;

model! {
    /// [`Event`] filter.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Decode, Encode, Serialize, Deserialize, IntoSchema)]
    pub struct EventFilter {
        /// If `Some::<EntityKind>`, filter by the [`EntityKind`]. If `None`, accept all the [`EntityKind`].
        entity_kind: Option<EntityKind>,
        /// If `Some::<StatusKind>`, filter by the [`StatusKind`]. If `None`, accept all the [`StatusKind`].
        status_kind: Option<StatusKind>,
        /// If `Some::<Hash>`, filter by the [`struct@Hash`]. If `None`, accept all the [`struct@Hash`].
        hash: Option<Hash>,
    }
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

    /// Filter by [`struct@Hash`].
    #[must_use]
    #[inline]
    pub const fn hash(mut self, hash: Hash) -> Self {
        self.hash = Some(hash);
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
            Self::field_matches(self.entity_kind.as_ref(), &event.entity_kind),
            Self::field_matches(self.status_kind.as_ref(), &event.status.kind()),
            Self::field_matches(self.hash.as_ref(), &event.hash),
        ]
        .into_iter()
        .all(core::convert::identity)
    }
}

model! {
    /// The kind of the pipeline entity.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[ffi_type]
    #[repr(u8)]
    pub enum EntityKind {
        /// Block
        Block,
        /// Transaction
        Transaction,
    }

    /// Strongly-typed [`Event`] that tells the receiver the kind and the hash of the changed entity as well as its [`Status`].
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Getters, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct Event {
        /// [`EntityKind`] of the entity that caused this [`Event`].
        pub entity_kind: EntityKind,
        /// [`Status`] of the entity that caused this [`Event`].
        pub status: Status,
        /// [`struct@Hash`] of the entity that caused this [`Event`].
        pub hash: Hash,
    }

    /// [`Status`] of the entity.
    #[derive(Debug, Clone, PartialEq, Eq, Hash, FromVariant, Decode, Encode, Serialize, Deserialize, IntoSchema)]
    #[ffi_type(local)]
    pub enum Status {
        /// Entity has been seen in the blockchain but has not passed validation.
        Validating,
        /// Entity was rejected during validation.
        Rejected(RejectionReason),
        /// Entity has passed validation.
        Committed,
    }

    /// The kind of [`Status`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum StatusKind {
        /// Represents [`Status::Validating`].
        Validating,
        /// Represents [`Status::Rejected`].
        Rejected,
        /// Represents [`Status::Committed`].
        Committed,
    }
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

model! {
    /// The reason for rejecting pipeline entity such as transaction or block.
    #[derive(Debug, Display, Clone, PartialEq, Eq, Hash, FromVariant, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[cfg_attr(feature = "std", derive(thiserror::Error))]
    #[ffi_type(local)]
    pub enum RejectionReason {
        /// The reason for rejecting the block.
        #[display(fmt = "Block was rejected: {_0}")]
        Block(#[cfg_attr(feature = "std", source)] crate::block::error::BlockRejectionReason),
        /// The reason for rejecting transaction.
        #[display(fmt = "Transaction was rejected: {_0}")]
        Transaction(#[cfg_attr(feature = "std", source)] crate::transaction::error::TransactionRejectionReason),
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        EntityKind as PipelineEntityKind, Event as PipelineEvent,
        EventFilter as PipelineEventFilter, RejectionReason as PipelineRejectionReason,
        Status as PipelineStatus, StatusKind as PipelineStatusKind,
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    #[cfg(not(feature = "std"))]
    use alloc::{string::ToString as _, vec, vec::Vec};

    use super::{RejectionReason::*, *};
    use crate::transaction::error::{NotPermittedFail, TransactionRejectionReason::*};

    #[test]
    fn events_are_correctly_filtered() {
        let events = vec![
            Event {
                entity_kind: EntityKind::Transaction,
                status: Status::Validating,
                hash: Hash::prehashed([0_u8; Hash::LENGTH]),
            },
            Event {
                entity_kind: EntityKind::Transaction,
                status: Status::Rejected(Transaction(NotPermitted(NotPermittedFail {
                    reason: "Some reason".to_string(),
                }))),
                hash: Hash::prehashed([0_u8; Hash::LENGTH]),
            },
            Event {
                entity_kind: EntityKind::Transaction,
                status: Status::Committed,
                hash: Hash::prehashed([2_u8; Hash::LENGTH]),
            },
            Event {
                entity_kind: EntityKind::Block,
                status: Status::Committed,
                hash: Hash::prehashed([2_u8; Hash::LENGTH]),
            },
        ];
        assert_eq!(
            vec![
                Event {
                    entity_kind: EntityKind::Transaction,
                    status: Status::Validating,
                    hash: Hash::prehashed([0_u8; Hash::LENGTH]),
                },
                Event {
                    entity_kind: EntityKind::Transaction,
                    status: Status::Rejected(Transaction(NotPermitted(NotPermittedFail {
                        reason: "Some reason".to_string(),
                    }))),
                    hash: Hash::prehashed([0_u8; Hash::LENGTH]),
                },
            ],
            events
                .iter()
                .cloned()
                .filter(|event| EventFilter::new()
                    .hash(Hash::prehashed([0_u8; Hash::LENGTH]))
                    .matches(event))
                .collect::<Vec<Event>>()
        );
        assert_eq!(
            vec![Event {
                entity_kind: EntityKind::Block,
                status: Status::Committed,
                hash: Hash::prehashed([2_u8; Hash::LENGTH]),
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
                hash: Hash::prehashed([2_u8; Hash::LENGTH]),
            }],
            events
                .iter()
                .cloned()
                .filter(|event| EventFilter::new()
                    .entity_kind(EntityKind::Transaction)
                    .hash(Hash::prehashed([2_u8; Hash::LENGTH]))
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
