//! Pipeline events.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use derive_more::Display;
use getset::Getters;
use iroha_crypto::Hash;
use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use strum::EnumDiscriminants;

pub use self::model::*;

#[model]
pub mod model {
    use super::*;

    /// [`Event`] filter.
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Default,
        Decode,
        Encode,
        Serialize,
        Deserialize,
        IntoSchema,
    )]
    pub struct PipelineEventFilter {
        /// If `Some::<EntityKind>`, filter by the [`EntityKind`]. If `None`, accept all the [`EntityKind`].
        pub(super) entity_kind: Option<PipelineEntityKind>,
        /// If `Some::<StatusKind>`, filter by the [`StatusKind`]. If `None`, accept all the [`StatusKind`].
        pub(super) status_kind: Option<PipelineStatusKind>,
        /// If `Some::<Hash>`, filter by the [`struct@Hash`]. If `None`, accept all the [`struct@Hash`].
        pub(super) hash: Option<Hash>,
    }

    /// The kind of the pipeline entity.
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[ffi_type]
    #[repr(u8)]
    pub enum PipelineEntityKind {
        /// Block
        Block,
        /// Transaction
        Transaction,
    }

    /// Strongly-typed [`Event`] that tells the receiver the kind and the hash of the changed entity as well as its [`Status`].
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        Hash,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct PipelineEvent {
        /// [`EntityKind`] of the entity that caused this [`Event`].
        pub entity_kind: PipelineEntityKind,
        /// [`Status`] of the entity that caused this [`Event`].
        pub status: PipelineStatus,
        /// [`struct@Hash`] of the entity that caused this [`Event`].
        pub hash: Hash,
    }

    /// [`Status`] of the entity.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        Hash,
        FromVariant,
        EnumDiscriminants,
        Decode,
        Encode,
        Serialize,
        Deserialize,
        IntoSchema,
    )]
    #[strum_discriminants(
        name(PipelineStatusKind),
        derive(
            PartialOrd,
            Ord,
            Hash,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
        )
    )]
    #[ffi_type]
    pub enum PipelineStatus {
        /// Entity has been seen in the blockchain but has not passed validation.
        Validating,
        /// Entity was rejected during validation.
        Rejected(PipelineRejectionReason),
        /// Entity has passed validation.
        Committed,
    }

    /// The reason for rejecting pipeline entity such as transaction or block.
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Hash,
        FromVariant,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[cfg_attr(feature = "std", derive(thiserror::Error))]
    #[ffi_type]
    pub enum PipelineRejectionReason {
        /// The reason for rejecting the block.
        #[display(fmt = "Block was rejected")]
        Block(#[cfg_attr(feature = "std", source)] crate::block::error::BlockRejectionReason),
        /// The reason for rejecting transaction.
        #[display(fmt = "Transaction was rejected")]
        Transaction(
            #[cfg_attr(feature = "std", source)]
            crate::transaction::error::TransactionRejectionReason,
        ),
    }
}

impl PipelineEventFilter {
    /// Construct [`EventFilter`].
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by [`EntityKind`].
    #[must_use]
    #[inline]
    pub const fn entity_kind(mut self, entity_kind: PipelineEntityKind) -> Self {
        self.entity_kind = Some(entity_kind);
        self
    }

    /// Filter by [`StatusKind`].
    #[must_use]
    #[inline]
    pub const fn status_kind(mut self, status_kind: PipelineStatusKind) -> Self {
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
    #[cfg(feature = "transparent_api")]
    fn field_matches<T: Eq>(filter: Option<&T>, event: &T) -> bool {
        filter.map_or(true, |field| field == event)
    }
}

#[cfg(feature = "transparent_api")]
impl super::Filter for PipelineEventFilter {
    type Event = PipelineEvent;

    /// Check if `self` accepts the `event`.
    #[inline]
    fn matches(&self, event: &PipelineEvent) -> bool {
        [
            Self::field_matches(self.entity_kind.as_ref(), &event.entity_kind),
            Self::field_matches(self.status_kind.as_ref(), &event.status.kind()),
            Self::field_matches(self.hash.as_ref(), &event.hash),
        ]
        .into_iter()
        .all(core::convert::identity)
    }
}

#[cfg(feature = "transparent_api")]
impl PipelineStatus {
    fn kind(&self) -> PipelineStatusKind {
        PipelineStatusKind::from(self)
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        PipelineEntityKind, PipelineEvent, PipelineEventFilter, PipelineRejectionReason,
        PipelineStatus, PipelineStatusKind,
    };
}

#[cfg(test)]
#[cfg(feature = "transparent_api")]
mod tests {
    #![allow(clippy::restriction)]

    #[cfg(not(feature = "std"))]
    use alloc::{string::ToString as _, vec, vec::Vec};

    use super::{super::Filter, PipelineRejectionReason::*, *};
    use crate::{transaction::error::TransactionRejectionReason::*, ValidationFail};

    #[test]
    fn events_are_correctly_filtered() {
        let events = vec![
            PipelineEvent {
                entity_kind: PipelineEntityKind::Transaction,
                status: PipelineStatus::Validating,
                hash: Hash::prehashed([0_u8; Hash::LENGTH]),
            },
            PipelineEvent {
                entity_kind: PipelineEntityKind::Transaction,
                status: PipelineStatus::Rejected(Transaction(Validation(
                    ValidationFail::TooComplex,
                ))),
                hash: Hash::prehashed([0_u8; Hash::LENGTH]),
            },
            PipelineEvent {
                entity_kind: PipelineEntityKind::Transaction,
                status: PipelineStatus::Committed,
                hash: Hash::prehashed([2_u8; Hash::LENGTH]),
            },
            PipelineEvent {
                entity_kind: PipelineEntityKind::Block,
                status: PipelineStatus::Committed,
                hash: Hash::prehashed([2_u8; Hash::LENGTH]),
            },
        ];
        assert_eq!(
            vec![
                PipelineEvent {
                    entity_kind: PipelineEntityKind::Transaction,
                    status: PipelineStatus::Validating,
                    hash: Hash::prehashed([0_u8; Hash::LENGTH]),
                },
                PipelineEvent {
                    entity_kind: PipelineEntityKind::Transaction,
                    status: PipelineStatus::Rejected(Transaction(Validation(
                        ValidationFail::TooComplex,
                    ))),
                    hash: Hash::prehashed([0_u8; Hash::LENGTH]),
                },
            ],
            events
                .iter()
                .cloned()
                .filter(|event| PipelineEventFilter::new()
                    .hash(Hash::prehashed([0_u8; Hash::LENGTH]))
                    .matches(event))
                .collect::<Vec<PipelineEvent>>()
        );
        assert_eq!(
            vec![PipelineEvent {
                entity_kind: PipelineEntityKind::Block,
                status: PipelineStatus::Committed,
                hash: Hash::prehashed([2_u8; Hash::LENGTH]),
            }],
            events
                .iter()
                .cloned()
                .filter(|event| PipelineEventFilter::new()
                    .entity_kind(PipelineEntityKind::Block)
                    .matches(event))
                .collect::<Vec<PipelineEvent>>()
        );
        assert_eq!(
            vec![PipelineEvent {
                entity_kind: PipelineEntityKind::Transaction,
                status: PipelineStatus::Committed,
                hash: Hash::prehashed([2_u8; Hash::LENGTH]),
            }],
            events
                .iter()
                .cloned()
                .filter(|event| PipelineEventFilter::new()
                    .entity_kind(PipelineEntityKind::Transaction)
                    .hash(Hash::prehashed([2_u8; Hash::LENGTH]))
                    .matches(event))
                .collect::<Vec<PipelineEvent>>()
        );
        assert_eq!(
            events,
            events
                .iter()
                .cloned()
                .filter(|event| PipelineEventFilter::new().matches(event))
                .collect::<Vec<PipelineEvent>>()
        )
    }
}
