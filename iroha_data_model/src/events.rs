//! Events for streaming API.

use iroha_derive::FromVariant;
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
                EventFilter::Data(filter) => filter.apply(event),
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
    use crate::isi::Instruction;
    use iroha_crypto::{Hash, Signature};
    use iroha_derive::FromVariant;
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

    /// Transaction was reject during verification of signature
    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decode, Encode)]
    pub struct SignatureVerificationFail {
        /// Signature which verification has failed
        pub signature: Signature,
        /// Error which happened during verification
        pub reason: String,
    }

    /// Transaction was reject because it doesn't satisfy signature condition
    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decode, Encode)]
    pub struct UnsatisfiedSignatureConditionFail {
        /// Reason why signature condition failed
        pub reason: String,
    }

    /// Transaction was reject because of fail of instruction
    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decode, Encode)]
    pub struct InstructionExecutionFail {
        /// Instruction which execution failed
        pub instruction: Instruction,
        /// Error which happened during execution
        pub reason: String,
    }

    /// Transaction was reject because of low authority
    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decode, Encode)]
    pub struct NotPermittedFail {
        /// Reason of failure
        pub reason: String,
    }

    /// The reason for rejecting transaction which happened because of new blocks.
    #[derive(
        Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Decode, Encode, FromVariant,
    )]
    pub enum BlockRejectionReason {
        /// Block was rejected during consensus.
        //TODO: store rejection reasons for blocks?
        ConsensusBlockRejection,
    }

    /// The reason for rejecting transaction which happened because of transaction.
    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decode, Encode, FromVariant)]
    pub enum TransactionRejectionReason {
        /// Failed due to low authority.
        NotPermitted(NotPermittedFail),
        /// Failed verify signature condition specified in the account.
        UnsatisfiedSignatureCondition(UnsatisfiedSignatureConditionFail),
        /// Failed execute instruction.
        InstructionExecution(InstructionExecutionFail),
        /// Failed to verify signatures.
        SignatureVerification(SignatureVerificationFail),
        /// Genesis account can sign only transactions in the genesis block.
        UnexpectedGenesisAccountSignature,
    }

    /// The reason for rejecting transaction.
    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Decode, Encode, FromVariant)]
    pub enum RejectionReason {
        /// The reason for rejecting the block.
        Block(BlockRejectionReason),
        /// The reason for rejecting transaction.
        Transaction(TransactionRejectionReason),
    }

    impl std::fmt::Display for RejectionReason {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            use BlockRejectionReason::*;
            use Instruction::*;
            use TransactionRejectionReason::*;

            match self {
                RejectionReason::Transaction(UnexpectedGenesisAccountSignature) => write!(
                    f,
                    "Genesis account can sign only transactions in the genesis block."
                ),
                RejectionReason::Transaction(SignatureVerification(verification_error)) => write!(
                    f,
                    "Failed to verify signatures because of signature {}: {}",
                    verification_error.signature.public_key, verification_error.reason,
                ),
                RejectionReason::Transaction(UnsatisfiedSignatureCondition(
                    signature_conditon_error,
                )) => {
                    write!(
                        f,
                        "Failed to verify signature condition specified in the account: {}",
                        signature_conditon_error.reason,
                    )
                }
                RejectionReason::Transaction(InstructionExecution(execute_instruction)) => {
                    let type_ = match execute_instruction.instruction {
                        Burn(_) => "burn",
                        Fail(_) => "fail",
                        If(_) => "if",
                        Mint(_) => "mint",
                        Pair(_) => "pair",
                        Register(_) => "register",
                        Sequence(_) => "sequence",
                        Transfer(_) => "transfer",
                        Unregister(_) => "unregister",
                    };
                    write!(
                        f,
                        "Failed execute instruction of type {}: {}",
                        type_, execute_instruction.reason
                    )
                }
                RejectionReason::Transaction(NotPermitted(permission_error)) => {
                    write!(f, "Action not permitted: {}", permission_error.reason)
                }
                RejectionReason::Block(ConsensusBlockRejection) => {
                    write!(f, "Block was rejected during consensus.")
                }
            }
        }
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
        pub fn new(entity_type: EntityType, status: Status, hash: Hash) -> Self {
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
                    hash: Hash([0u8; 32]),
                },
                Event {
                    entity_type: EntityType::Transaction,
                    status: Status::Rejected(Transaction(NotPermitted(NotPermittedFail {
                        reason: "Some reason".to_string(),
                    }))),
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
                        status: Status::Rejected(Transaction(NotPermitted(NotPermittedFail {
                            reason: "Some reason".to_string(),
                        }))),
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
