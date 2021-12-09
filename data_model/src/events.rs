//! Events for streaming API.

use iroha_macro::FromVariant;
use iroha_schema::prelude::*;
use iroha_version::prelude::*;
use parity_scale_codec::{Decode, Encode};

declare_versioned_with_scale!(VersionedEventProducerMessage 1..2, Debug, Clone, FromVariant, IntoSchema);

impl VersionedEventProducerMessage {
    /// Converts from `&VersionedEventProducerMessage` to V1 reference
    pub const fn as_v1(&self) -> &EventProducerMessage {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedEventProducerMessage` to V1 mutable reference
    pub fn as_mut_v1(&mut self) -> &mut EventProducerMessage {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedEventProducerMessage` to V1
    pub fn into_v1(self) -> EventProducerMessage {
        match self {
            Self::V1(v1) => v1,
        }
    }
}

/// Message sent by the stream producer
#[version_with_scale(n = 1, versioned = "VersionedEventProducerMessage")]
#[derive(Debug, Clone, Decode, Encode, FromVariant, IntoSchema)]
pub enum EventProducerMessage {
    /// Answer sent by the peer.
    /// The message means that event stream connection is initialized and will be supplying
    /// events starting with the next message.
    SubscriptionAccepted,
    /// Event sent by the peer.
    Event(Event),
}

declare_versioned_with_scale!(VersionedEventConsumerMessage 1..2, Debug, Clone, FromVariant, IntoSchema);

impl VersionedEventConsumerMessage {
    /// Converts from `&VersionedEventConsumerMessage` to V1 reference
    pub const fn as_v1(&self) -> &EventConsumerMessage {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedEventConsumerMessage` to V1 mutable reference
    pub fn as_mut_v1(&mut self) -> &mut EventConsumerMessage {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedEventConsumerMessage` to V1
    pub fn into_v1(self) -> EventConsumerMessage {
        match self {
            Self::V1(v1) => v1,
        }
    }
}

/// Message sent by the stream consumer
#[version_with_scale(n = 1, versioned = "VersionedEventConsumerMessage")]
#[derive(Debug, Clone, Copy, Decode, Encode, FromVariant, IntoSchema)]
pub enum EventConsumerMessage {
    /// Request sent by the client to subscribe to events.
    //TODO: Sign request?
    SubscriptionRequest(EventFilter),
    /// Acknowledgment of receiving event sent from the peer.
    EventReceived,
}

/// Event.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, FromVariant, IntoSchema)]
pub enum Event {
    /// Pipeline event.
    Pipeline(pipeline::Event),
    /// Data event.
    Data(data::Event),
}

/// Event filter.
#[derive(Debug, Clone, Copy, Decode, Encode, FromVariant, IntoSchema)]
pub enum EventFilter {
    /// Listen to pipeline events with filter.
    Pipeline(pipeline::EventFilter),
    /// Listen to data events with filter.
    Data(data::EventFilter),
}

impl EventFilter {
    /// Apply filter to event.
    pub fn apply(&self, event: &Event) -> bool {
        match (event, self) {
            (Event::Pipeline(event), EventFilter::Pipeline(filter)) => filter.apply(event),
            (Event::Data(event), EventFilter::Data(filter)) => filter.apply(*event),
            _ => false,
        }
    }
}

/// Events of data entities.
pub mod data {
    use iroha_macro::FromVariant;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};

    use crate::prelude::*;

    /// Entity type to filter events.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode)]
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
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode)]
    pub enum Status {
        /// Entity was added, registered, minted or another action was made to make entity appear on
        /// the blockchain for the first time.
        Created,
        /// Entity's state was changed, any parameter updated it's value.
        Updated,
        /// Entity was archived or by any other way was put into state that guarantees absense of
        /// [`Updated`](`Status::Updated`) events for this entity.
        Deleted,
    }

    /// Enumeration of all possible Iroha data entities.
    #[derive(Debug, Clone, Decode, Encode, FromVariant)]
    pub enum Entity {
        /// Account.
        Account(Box<Account>),
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
    #[derive(Debug, Clone, Copy, Decode, Encode, IntoSchema)]
    pub struct EventFilter;

    impl EventFilter {
        /// Apply filter to event.
        #[allow(clippy::unused_self)]
        pub const fn apply(self, _event: Event) -> bool {
            false
        }
    }

    //TODO: implement event for data entities
    /// Event.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema)]
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
    use iroha_macro::FromVariant;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};

    pub use crate::transaction::RejectionReason as PipelineRejectionReason;

    /// Event filter.
    #[derive(Debug, Clone, Copy, Decode, Encode, IntoSchema)]
    pub struct EventFilter {
        /// Filter by Entity if `Some`, if `None` all entities are accepted.
        pub entity: Option<EntityType>,
        /// Filter by Hash if `Some`, if `None` all hashes are accepted.
        pub hash: Option<Hash>,
    }

    impl EventFilter {
        /// Do not filter at all.
        pub const fn identity() -> EventFilter {
            EventFilter {
                entity: None,
                hash: None,
            }
        }

        /// Filter by enitity.
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
        use crate::transaction::{
            NotPermittedFail, RejectionReason::*, TransactionRejectionReason::*,
        };

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
                    .filter(|event| EventFilter::identity().apply(event))
                    .collect::<Vec<Event>>()
            )
        }
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        data::prelude::*, pipeline::prelude::*, Event, EventConsumerMessage, EventFilter,
        EventProducerMessage, VersionedEventConsumerMessage, VersionedEventProducerMessage,
    };
}
