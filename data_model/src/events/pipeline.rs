//! Pipeline events.

use iroha_crypto::Hash;
use iroha_macro::FromVariant;
use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};

pub use crate::transaction::RejectionReason as PipelineRejectionReason;

/// Event filter.
#[derive(Default, Debug, Clone, Copy, Decode, Encode, IntoSchema)]
pub struct EventFilter {
    /// Filter by Entity if `Some`, if `None` all entities are accepted.
    pub entity: Option<EntityType>,
    /// Filter by Hash if `Some`, if `None` all hashes are accepted.
    pub hash: Option<Hash>,
}

impl EventFilter {
    /// Filter by entity.
    pub const fn by_entity(entity: EntityType) -> EventFilter {
        EventFilter {
            entity: Some(entity),
            hash: None,
        }
    }

    /// Filter by hash.
    pub const fn by_hash(hash: Hash) -> EventFilter {
        EventFilter {
            hash: Some(hash),
            entity: None,
        }
    }

    /// Filter by entity and hash.
    pub const fn by_entity_and_hash(entity: EntityType, hash: Hash) -> EventFilter {
        EventFilter {
            entity: Some(entity),
            hash: Some(hash),
        }
    }

    /// Apply filter to event.
    pub fn apply(&self, event: &Event) -> bool {
        let entity_check = self
            .entity
            .map_or(true, |entity| entity == event.entity_type);
        let hash_check = self.hash.map_or(true, |hash| hash == event.hash);
        entity_check && hash_check
    }
}

/// Entity type to filter events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema)]
pub enum EntityType {
    /// Block.
    Block,
    /// Transaction.
    Transaction,
}

/// Entity type to filter events.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema)]
pub struct Event {
    /// Type of entity that caused this event.
    pub entity_type: EntityType,
    /// The status of this entity.
    pub status: Status,
    /// The hash of this entity.
    pub hash: Hash,
}

impl Event {
    /// Constructs pipeline event.
    pub const fn new(entity_type: EntityType, status: Status, hash: Hash) -> Self {
        Event {
            entity_type,
            status,
            hash,
        }
    }
}

/// Entity type to filter events.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, FromVariant, IntoSchema)]
pub enum Status {
    /// Entity has been seen in blockchain, but has not passed validation.
    Validating,
    /// Entity was rejected in one of the validation stages.
    Rejected(PipelineRejectionReason),
    /// Entity has passed validation.
    Committed,
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        EntityType as PipelineEntityType, Event as PipelineEvent,
        EventFilter as PipelineEventFilter, PipelineRejectionReason, Status as PipelineStatus,
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use super::*;
    use crate::transaction::{NotPermittedFail, RejectionReason::*, TransactionRejectionReason::*};

    #[test]
    fn events_are_correctly_filtered() {
        let events = vec![
            Event {
                entity_type: EntityType::Transaction,
                status: Status::Validating,
                hash: Hash([0_u8; 32]),
            },
            Event {
                entity_type: EntityType::Transaction,
                status: Status::Rejected(Transaction(NotPermitted(NotPermittedFail {
                    reason: "Some reason".to_string(),
                }))),
                hash: Hash([0_u8; 32]),
            },
            Event {
                entity_type: EntityType::Transaction,
                status: Status::Committed,
                hash: Hash([2_u8; 32]),
            },
            Event {
                entity_type: EntityType::Block,
                status: Status::Committed,
                hash: Hash([2_u8; 32]),
            },
        ];
        assert_eq!(
            vec![
                Event {
                    entity_type: EntityType::Transaction,
                    status: Status::Validating,
                    hash: Hash([0_u8; 32]),
                },
                Event {
                    entity_type: EntityType::Transaction,
                    status: Status::Rejected(Transaction(NotPermitted(NotPermittedFail {
                        reason: "Some reason".to_string(),
                    }))),
                    hash: Hash([0_u8; 32]),
                },
            ],
            events
                .iter()
                .cloned()
                .filter(|event| EventFilter::by_hash(Hash([0_u8; 32])).apply(event))
                .collect::<Vec<Event>>()
        );
        assert_eq!(
            vec![Event {
                entity_type: EntityType::Block,
                status: Status::Committed,
                hash: Hash([2_u8; 32]),
            }],
            events
                .iter()
                .cloned()
                .filter(|event| EventFilter::by_entity(EntityType::Block).apply(event))
                .collect::<Vec<Event>>()
        );
        assert_eq!(
            vec![Event {
                entity_type: EntityType::Transaction,
                status: Status::Committed,
                hash: Hash([2_u8; 32]),
            }],
            events
                .iter()
                .cloned()
                .filter(|event| EventFilter::by_entity_and_hash(
                    EntityType::Transaction,
                    Hash([2_u8; 32])
                )
                .apply(event))
                .collect::<Vec<Event>>()
        );
        assert_eq!(
            events,
            events
                .iter()
                .cloned()
                .filter(|event| EventFilter::default().apply(event))
                .collect::<Vec<Event>>()
        )
    }
}
