//! Events for streaming API.
#![allow(unused_results, clippy::unused_self)]

use iroha_derive::FromVariant;
use iroha_version::prelude::*;
use serde::{Deserialize, Serialize};

declare_versioned_with_json!(VersionedSubscriptionRequest 1..2);

//TODO: Sign request?
/// Subscription Request to listen to events
#[version_with_json(n = 1, versioned = "VersionedSubscriptionRequest")]
#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
pub struct SubscriptionRequest(pub EventFilter);

declare_versioned_with_json!(VersionedEventReceived 1..2);

// TODO: Sign receipt?
/// Event receipt.
#[version_with_json(n = 1, versioned = "VersionedEventReceived")]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct EventReceived;

declare_versioned_with_json!(VersionedEvent 1..2);

/// Event.
#[version_with_json(n = 1, versioned = "VersionedEvent")]
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone, FromVariant)]
pub enum Event {
    /// Pipeline event.
    Pipeline(pipeline::Event),
    /// Data event.
    Data(data::Event),
}

/// Event filter.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, FromVariant)]
pub enum EventFilter {
    /// Listen to pipeline events with filter.
    Pipeline(pipeline::EventFilter),
    /// Listen to data events with filter.
    Data(data::EventFilter),
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
                EventFilter::Data(filter) => filter.apply(*event),
                _ => false,
            },
        }
    }
}

/// Events of data entities.
pub mod data {
    use crate::prelude::*;
    use iroha_derive::FromVariant;
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
    #[derive(Clone, Debug, Serialize, Deserialize, FromVariant)]
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
        pub const fn apply(self, _event: Event) -> bool {
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
    use crate::isi::Instruction;
    use iroha_crypto::{Hash, Signature};
    use iroha_derive::FromVariant;
    use iroha_error::derive::Error;
    use parity_scale_codec::{Decode, Encode};
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
    #[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Copy, Clone)]
    pub enum EntityType {
        /// Block.
        Block,
        /// Transaction.
        Transaction,
    }

    /// Transaction was reject during verification of signature
    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decode, Encode)]
    pub struct SignatureVerificationFail {
        /// Signature which verification has failed
        pub signature: Signature,
        /// Error which happened during verification
        pub reason: String,
    }
    impl std::fmt::Display for SignatureVerificationFail {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "Failed to verify signatures because of signature {}: {}",
                self.signature.public_key, self.reason,
            )
        }
    }
    impl std::error::Error for SignatureVerificationFail {}

    /// Transaction was reject because it doesn't satisfy signature condition
    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decode, Encode)]
    pub struct UnsatisfiedSignatureConditionFail {
        /// Reason why signature condition failed
        pub reason: String,
    }
    impl std::fmt::Display for UnsatisfiedSignatureConditionFail {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "Failed to verify signature condition specified in the account: {}",
                self.reason,
            )
        }
    }
    impl std::error::Error for UnsatisfiedSignatureConditionFail {}

    /// Transaction was reject because of fail of instruction
    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decode, Encode)]
    pub struct InstructionExecutionFail {
        /// Instruction which execution failed
        pub instruction: Instruction,
        /// Error which happened during execution
        pub reason: String,
    }
    impl std::fmt::Display for InstructionExecutionFail {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
            };
            write!(
                f,
                "Failed execute instruction of type {}: {}",
                type_, self.reason
            )
        }
    }
    impl std::error::Error for InstructionExecutionFail {}

    /// Transaction was reject because of low authority
    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decode, Encode)]
    pub struct NotPermittedFail {
        /// Reason of failure
        pub reason: String,
    }
    impl std::fmt::Display for NotPermittedFail {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Action not permitted: {}", self.reason)
        }
    }
    impl std::error::Error for NotPermittedFail {}

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
    )]
    pub enum BlockRejectionReason {
        /// Block was rejected during consensus.
        //TODO: store rejection reasons for blocks?
        #[error("Block was rejected during consensus.")]
        ConsensusBlockRejection,
    }

    /// The reason for rejecting transaction which happened because of transaction.
    #[derive(
        Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decode, Encode, FromVariant, Error,
    )]
    pub enum TransactionRejectionReason {
        /// Failed due to low authority.
        #[error("Transaction rejected due to low authority")]
        NotPermitted(#[source] NotPermittedFail),
        /// Failed verify signature condition specified in the account.
        #[error("Transaction rejected due to unsatisfied signature condition")]
        UnsatisfiedSignatureCondition(#[source] UnsatisfiedSignatureConditionFail),
        /// Failed execute instruction.
        #[error("Transaction rejected due to instruction execution")]
        InstructionExecution(#[source] InstructionExecutionFail),
        /// Failed to verify signatures.
        #[error("Transaction rejected due to signature verification")]
        SignatureVerification(#[source] SignatureVerificationFail),
        /// Genesis account can sign only transactions in the genesis block.
        #[error("Genesis account can sign only transactions in the genesis block.")]
        UnexpectedGenesisAccountSignature,
    }

    /// The reason for rejecting pipeline entity such as transaction or block.
    #[derive(
        Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decode, Encode, FromVariant, Error,
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
        pub const fn new(entity_type: EntityType, status: Status, hash: Hash) -> Self {
            Event {
                entity_type,
                status,
                hash,
            }
        }
    }

    /// Entity type to filter events.
    #[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone, FromVariant)]
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
            RejectionReason as PipelineRejectionReason, SignatureVerificationFail,
            Status as PipelineStatus, TransactionRejectionReason,
            UnsatisfiedSignatureConditionFail,
        };
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use RejectionReason::*;
        use TransactionRejectionReason::*;

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
        data::prelude::*, pipeline::prelude::*, Event, EventFilter, EventReceived,
        SubscriptionRequest, VersionedEvent, VersionedEventReceived, VersionedSubscriptionRequest,
    };
}
