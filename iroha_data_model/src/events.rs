//! Events for streaming API.

use serde::{Deserialize, Serialize};

//TODO: Sign request?
/// Subscription Request to listen to events
#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
pub struct SubscriptionRequest(pub EventFilter);

// TODO: Sign receipt?
/// Event receipt.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct EventReceived;

/// Event.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub enum Event {
    /// Pipeline event.
    Pipeline(pipeline::Event),
    /// Data event.
    Data(data::Event),
}

impl From<pipeline::Event> for Event {
    fn from(event: pipeline::Event) -> Self {
        Event::Pipeline(event)
    }
}

impl From<data::Event> for Event {
    fn from(event: data::Event) -> Self {
        Event::Data(event)
    }
}

/// Event filter.
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum EventFilter {
    /// Listen to pipeline events with filter.
    Pipeline(pipeline::EventFilter),
    /// Listen to data events with filter.
    Data(data::EventFilter),
}

impl From<pipeline::EventFilter> for EventFilter {
    fn from(filter: pipeline::EventFilter) -> Self {
        EventFilter::Pipeline(filter)
    }
}

impl From<data::EventFilter> for EventFilter {
    fn from(filter: data::EventFilter) -> Self {
        EventFilter::Data(filter)
    }
}

impl EventFilter {
    /// Apply filter to event.
    pub fn apply(&self, event: &Event) -> bool {
        match event {
            Event::Pipeline(event) => match self {
                EventFilter::Pipeline(filter) => filter.apply(event),
                _ => false,
            },
            Event::Data(event) => match self {
                EventFilter::Data(filter) => filter.apply(event),
                _ => false,
            },
        }
    }
}

/// Events of data entities.
pub mod data {
    use crate::prelude::*;
    use serde::{Deserialize, Serialize};

    /// Entity type to filter events.
    #[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Copy, Clone)]
    pub enum EntityType {
        /// Account.
        Account,
        /// AssetDefinition.
        AssetDefinition,
        /// Asset.
        Asset,
        /// Domain.
        Domain,
        /// Peer.
        Peer,
    }

    /// Entity type to filter events.
    #[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Copy, Clone)]
    pub enum Status {
        /// Entity was added, registered, minted or another action was made to make entity appear on
        /// the blockchain for the first time.
        Created,
        /// Entity's state was changed, any parameter updated it's value.
        Updated,
        /// Entity was archived or by any other way was put into state that guarantees absense of
        /// `Updated` events for this entity.
        Deleted,
    }

    /// Enumeration of all possible Iroha data entities.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum Entity {
        /// Account.
        Account(Account),
        /// AssetDefinition.
        AssetDefinition(AssetDefinition),
        /// Asset.
        Asset(Asset),
        /// Domain.
        Domain(Domain),
        /// Peer.
        Peer(Peer),
    }

    impl From<Entity> for EntityType {
        fn from(entity: Entity) -> Self {
            match entity {
                Entity::Account(_) => EntityType::Account,
                Entity::AssetDefinition(_) => EntityType::AssetDefinition,
                Entity::Asset(_) => EntityType::Asset,
                Entity::Domain(_) => EntityType::Domain,
                Entity::Peer(_) => EntityType::Peer,
            }
        }
    }

    //TODO: implement filter for data entities
    /// Event filter.
    #[derive(Debug, Serialize, Deserialize, Copy, Clone)]
    pub struct EventFilter;

    impl EventFilter {
        /// Apply filter to event.
        pub fn apply(&self, _event: &Event) -> bool {
            false
        }
    }

    //TODO: implement event for data entities
    /// Event.
    #[derive(Debug, Serialize, Deserialize, Copy, Clone, Eq, PartialEq)]
    pub struct Event;

    /// Exports common structs and enums from this module.
    pub mod prelude {
        pub use super::{
            Entity as DataEntity, EntityType as DataEntityType, Event as DataEvent,
            EventFilter as DataEventFilter, Status as DataStatus,
        };
    }
}

/// Pipeline events.
pub mod pipeline {
    use iroha_crypto::Hash;
    use serde::{Deserialize, Serialize};

    /// Event filter.
    #[derive(Debug, Serialize, Deserialize, Copy, Clone)]
    pub struct EventFilter {
        /// Filter by Entity if `Some`, if `None` all entities are accepted.
        pub entity: Option<EntityType>,
        /// Filter by Hash if `Some`, if `None` all hashes are accepted.
        pub hash: Option<Hash>,
    }

    impl EventFilter {
        /// Do not filter at all.
        pub fn identity() -> EventFilter {
            EventFilter {
                entity: None,
                hash: None,
            }
        }

        /// Filter by enitity.
        pub fn by_entity(entity: EntityType) -> EventFilter {
            EventFilter {
                entity: Some(entity),
                hash: None,
            }
        }

        /// Filter by hash.
        pub fn by_hash(hash: Hash) -> EventFilter {
            EventFilter {
                hash: Some(hash),
                entity: None,
            }
        }

        /// Filter by entity and hash.
        pub fn by_entity_and_hash(entity: EntityType, hash: Hash) -> EventFilter {
            EventFilter {
                entity: Some(entity),
                hash: Some(hash),
            }
        }

        /// Apply filter to event.
        pub fn apply(&self, event: &Event) -> bool {
            let entity_check = if let Some(entity) = self.entity {
                entity == event.entity_type
            } else {
                true
            };
            let hash_check = if let Some(hash) = self.hash {
                hash == event.hash
            } else {
                true
            };
            entity_check && hash_check
        }
    }

    /// Entity type to filter events.
    #[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Copy, Clone)]
    pub enum EntityType {
        /// Block.
        Block,
        /// Transaction.
        Transaction,
    }

    /// The reason for rejecting transaction.
    pub type RejectionReason = String;

    /// Entity type to filter events.
    #[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
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
        pub fn new(entity_type: EntityType, status: Status, hash: Hash) -> Self {
            Event {
                entity_type,
                status,
                hash,
            }
        }
    }

    /// Entity type to filter events.
    #[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
    pub enum Status {
        /// Entity has been seen in blockchain, but has not passed validation.
        Validating,
        /// Entity was rejected in one of the validation stages.
        Rejected(RejectionReason),
        /// Entity has passed validation.
        Committed,
    }

    /// Exports common structs and enums from this module.
    pub mod prelude {
        pub use super::{
            EntityType as PipelineEntityType, Event as PipelineEvent,
            EventFilter as PipelineEventFilter, Status as PipelineStatus,
        };
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn events_are_correctly_filtered() {
            let events = vec![
                Event {
                    entity_type: EntityType::Transaction,
                    status: Status::Validating,
                    hash: Hash([0u8; 32]),
                },
                Event {
                    entity_type: EntityType::Transaction,
                    status: Status::Rejected("Some reason".to_string()),
                    hash: Hash([0u8; 32]),
                },
                Event {
                    entity_type: EntityType::Transaction,
                    status: Status::Committed,
                    hash: Hash([2u8; 32]),
                },
                Event {
                    entity_type: EntityType::Block,
                    status: Status::Committed,
                    hash: Hash([2u8; 32]),
                },
            ];
            assert_eq!(
                vec![
                    Event {
                        entity_type: EntityType::Transaction,
                        status: Status::Validating,
                        hash: Hash([0u8; 32]),
                    },
                    Event {
                        entity_type: EntityType::Transaction,
                        status: Status::Rejected("Some reason".to_string()),
                        hash: Hash([0u8; 32]),
                    },
                ],
                events
                    .iter()
                    .cloned()
                    .filter(|event| EventFilter::by_hash(Hash([0u8; 32])).apply(&event))
                    .collect::<Vec<Event>>()
            );
            assert_eq!(
                vec![Event {
                    entity_type: EntityType::Block,
                    status: Status::Committed,
                    hash: Hash([2u8; 32]),
                }],
                events
                    .iter()
                    .cloned()
                    .filter(|event| EventFilter::by_entity(EntityType::Block).apply(&event))
                    .collect::<Vec<Event>>()
            );
            assert_eq!(
                vec![Event {
                    entity_type: EntityType::Transaction,
                    status: Status::Committed,
                    hash: Hash([2u8; 32]),
                }],
                events
                    .iter()
                    .cloned()
                    .filter(|event| EventFilter::by_entity_and_hash(
                        EntityType::Transaction,
                        Hash([2u8; 32])
                    )
                    .apply(&event))
                    .collect::<Vec<Event>>()
            );
            assert_eq!(
                events,
                events
                    .iter()
                    .cloned()
                    .filter(|event| EventFilter::identity().apply(&event))
                    .collect::<Vec<Event>>()
            )
        }
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        data::prelude::*, pipeline::prelude::*, Event, EventFilter, EventReceived,
        SubscriptionRequest,
    };
}
