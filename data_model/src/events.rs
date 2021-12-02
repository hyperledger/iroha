//! Events for streaming API.
#![allow(clippy::unused_self)]

use iroha_macro::FromVariant;
use iroha_schema::prelude::*;
use iroha_version::prelude::*;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

declare_versioned_with_scale!(VersionedEventSocketMessage 1..2, Debug, Clone, FromVariant, IntoSchema);

impl VersionedEventSocketMessage {
    /// Converts from `&VersionedEventSocketMessage` to V1 reference
    pub const fn as_v1(&self) -> &EventSocketMessage {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedEventSocketMessage` to V1 mutable reference
    pub fn as_mut_v1(&mut self) -> &mut EventSocketMessage {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedEventSocketMessage` to V1
    pub fn into_v1(self) -> EventSocketMessage {
        match self {
            Self::V1(v1) => v1,
        }
    }
}

/// Message type used for communication over web socket event stream.
#[allow(variant_size_differences)]
#[version_with_scale(n = 1, versioned = "VersionedEventSocketMessage")]
#[derive(Debug, Clone, IntoSchema, FromVariant, Decode, Encode, Deserialize, Serialize)]
pub enum EventSocketMessage {
    /// Request sent by client to subscribe to events.
    SubscriptionRequest(SubscriptionRequest),
    /// Answer sent by peer.
    /// The message means that all event connection is initialized and will be supplying
    /// events starting from the next one.
    SubscriptionAccepted,
    /// Event, sent by peer.
    Event(Event),
    /// Acknowledgment of receiving event sent from client.
    EventReceived,
}

//TODO: Sign request?
/// Subscription Request to listen to events
#[derive(Debug, Decode, Encode, Deserialize, Serialize, Copy, Clone, IntoSchema)]
pub struct SubscriptionRequest(pub EventFilter);

/// Event.
#[derive(
    Debug, Decode, Encode, Deserialize, Serialize, Eq, PartialEq, Clone, FromVariant, IntoSchema,
)]
pub enum Event {
    /// Pipeline event.
    Pipeline(pipeline::Event),
    /// Data event.
    Data(data::Event),
}

/// Event filter.
#[derive(Debug, Decode, Encode, Deserialize, Serialize, Clone, Copy, FromVariant, IntoSchema)]
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
    use serde::{Deserialize, Serialize};

    use crate::prelude::*;

    /// Entity type to filter events.
    #[derive(Debug, Decode, Encode, Deserialize, Serialize, Eq, PartialEq, Copy, Clone)]
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
    #[derive(Debug, Decode, Encode, Deserialize, Serialize, Eq, PartialEq, Copy, Clone)]
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
    #[derive(Clone, Debug, Decode, Encode, Deserialize, Serialize, FromVariant)]
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
    #[derive(Debug, Decode, Encode, Deserialize, Serialize, Copy, Clone, IntoSchema)]
    pub struct EventFilter;

    impl EventFilter {
        /// Apply filter to event.
        pub const fn apply(self, _event: Event) -> bool {
            false
        }
    }

    //TODO: implement event for data entities
    /// Event.
    #[derive(
        Debug, Decode, Encode, Deserialize, Serialize, Copy, Clone, Eq, PartialEq, IntoSchema,
    )]
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
    use std::{
        error::Error as StdError,
        fmt::{Display, Formatter, Result as FmtResult},
    };

    use iroha_crypto::{Hash, SignatureVerificationFail};
    use iroha_macro::FromVariant;
    use iroha_schema::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    use crate::{isi::Instruction, transaction::Payload};

    /// Event filter.
    #[derive(Debug, Decode, Encode, Deserialize, Serialize, Copy, Clone, IntoSchema)]
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
    #[derive(
        Debug, Decode, Encode, Deserialize, Serialize, Eq, PartialEq, Copy, Clone, IntoSchema,
    )]
    pub enum EntityType {
        /// Block.
        Block,
        /// Transaction.
        Transaction,
    }

    /// Transaction was reject because it doesn't satisfy signature condition
    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decode, Encode, IntoSchema)]
    pub struct UnsatisfiedSignatureConditionFail {
        /// Reason why signature condition failed
        pub reason: String,
    }

    impl Display for UnsatisfiedSignatureConditionFail {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            write!(
                f,
                "Failed to verify signature condition specified in the account: {}",
                self.reason,
            )
        }
    }

    impl StdError for UnsatisfiedSignatureConditionFail {}

    /// Transaction was rejected because of one of its instructions failing.
    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decode, Encode, IntoSchema)]
    pub struct InstructionExecutionFail {
        /// Instruction which execution failed
        pub instruction: Instruction,
        /// Error which happened during execution
        pub reason: String,
    }

    impl Display for InstructionExecutionFail {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            use Instruction::*;
            let type_ = match self.instruction {
                Burn(_) => "burn",
                Fail(_) => "fail",
                If(_) => "if",
                Mint(_) => "mint",
                Pair(_) => "pair",
                Register(_) => "register",
                Sequence(_) => "sequence",
                Transfer(_) => "transfer",
                Unregister(_) => "unregister",
                SetKeyValue(_) => "set key-value pair",
                RemoveKeyValue(_) => "remove key-value pair",
                Grant(_) => "grant",
            };
            write!(
                f,
                "Failed to execute instruction of type {}: {}",
                type_, self.reason
            )
        }
    }
    impl StdError for InstructionExecutionFail {}

    /// Transaction was reject because of low authority
    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decode, Encode, IntoSchema)]
    pub struct NotPermittedFail {
        /// Reason of failure
        pub reason: String,
    }

    impl Display for NotPermittedFail {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            write!(f, "Action not permitted: {}", self.reason)
        }
    }

    impl StdError for NotPermittedFail {}

    /// The reason for rejecting transaction which happened because of new blocks.
    #[derive(
        Debug,
        Clone,
        Copy,
        Eq,
        PartialEq,
        Serialize,
        Deserialize,
        Decode,
        Encode,
        FromVariant,
        Error,
        IntoSchema,
    )]
    pub enum BlockRejectionReason {
        /// Block was rejected during consensus.
        //TODO: store rejection reasons for blocks?
        #[error("Block was rejected during consensus.")]
        ConsensusBlockRejection,
    }

    /// The reason for rejecting transaction which happened because of transaction.
    #[derive(
        Debug,
        Clone,
        Eq,
        PartialEq,
        Serialize,
        Deserialize,
        Decode,
        Encode,
        FromVariant,
        Error,
        IntoSchema,
    )]
    pub enum TransactionRejectionReason {
        /// Insufficient authorisation.
        #[error("Transaction rejected due to insufficient authorisation")]
        NotPermitted(#[source] NotPermittedFail),
        /// Failed to verify signature condition specified in the account.
        #[error("Transaction rejected due to an unsatisfied signature condition")]
        UnsatisfiedSignatureCondition(#[source] UnsatisfiedSignatureConditionFail),
        /// Failed to execute instruction.
        #[error("Transaction rejected due to failure in instruction execution")]
        InstructionExecution(#[source] InstructionExecutionFail),
        /// Failed to verify signatures.
        #[error("Transaction rejected due to failed signature verification")]
        SignatureVerification(#[source] SignatureVerificationFail<Payload>),
        /// Genesis account can sign only transactions in the genesis block.
        #[error("The genesis account can only sign transactions in the genesis block.")]
        UnexpectedGenesisAccountSignature,
    }

    /// The reason for rejecting pipeline entity such as transaction or block.
    #[derive(
        Debug,
        Clone,
        Eq,
        PartialEq,
        Serialize,
        Deserialize,
        Decode,
        Encode,
        FromVariant,
        Error,
        IntoSchema,
    )]
    pub enum RejectionReason {
        /// The reason for rejecting the block.
        #[error("Block was rejected")]
        Block(#[source] BlockRejectionReason),
        /// The reason for rejecting transaction.
        #[error("Transaction was rejected")]
        Transaction(#[source] TransactionRejectionReason),
    }

    /// Entity type to filter events.
    #[derive(Debug, Decode, Encode, Deserialize, Serialize, Eq, PartialEq, Clone, IntoSchema)]
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
    #[derive(
        Debug, Decode, Encode, Deserialize, Serialize, Eq, PartialEq, Clone, FromVariant, IntoSchema,
    )]
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
            BlockRejectionReason, EntityType as PipelineEntityType, Event as PipelineEvent,
            EventFilter as PipelineEventFilter, InstructionExecutionFail, NotPermittedFail,
            RejectionReason as PipelineRejectionReason, Status as PipelineStatus,
            TransactionRejectionReason, UnsatisfiedSignatureConditionFail,
        };
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::restriction)]

        use RejectionReason::*;
        use TransactionRejectionReason::*;

        use super::*;

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
        data::prelude::*, pipeline::prelude::*, Event, EventFilter, EventSocketMessage,
        SubscriptionRequest, VersionedEventSocketMessage,
    };
}
