//! Iroha is a quite dynamic system so many events can happen.
//! This module contains descriptions of such an events and
//! utilitary Iroha Special Instructions to work with them.

use crate::prelude::*;
use async_std::sync::{Receiver, Sender};
use chrono::Utc;
use cloudevents::{Event, EventBuilder};
use iroha_data_model::prelude::*;
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use url::Url;

/// Type of `Sender<Event>` which should be used for channels of `Event` messages.
pub type EventsSender = Sender<Occurrence>;
/// Type of `Receiver<Event>` which should be used for channels of `Event` messages.
pub type EventsReceiver = Receiver<Occurrence>;

/// Payload for
/// [CloudEvents](https://docs.rs/cloudevents-sdk/0.1.0/cloudevents/event/enum.Data.html).
///
/// Can represent different possible captures of statements of facts during the operation of
/// Iroha - creation of new entities, updates on and deletion of existing entities.
///
/// [Specification](https://github.com/cloudevents/spec/blob/v1.0/spec.md#occurrence).
#[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
pub enum Occurrence {
    /// Entity was added, registered, minted or another action was made to make entity appear on
    /// the blockchain for the first time.
    Created(Entity),
    /// Entity's state was changed, lifecycle stage was moved forward or backward,
    /// any parameter updated it's value.
    Updated(Entity),
    /// Entity was archived or by any other way was put into state that guarantees absense of
    /// `Updated` events for this entity.
    Deleted(Entity),
}

/// Enumeration of all possible Iroha entities.
#[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
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
    /// Transaction.
    Transaction(Vec<u8>),
    /// Block.
    Block(Vec<u8>),
    /// Time.
    Time,
}

impl Occurrence {
    /// Find out which `Entity` relates to the `Occurrence`.
    pub fn entity(&self) -> &Entity {
        match self {
            Occurrence::Created(entity)
            | Occurrence::Updated(entity)
            | Occurrence::Deleted(entity) => entity,
        }
    }
}

impl Into<Event> for Occurrence {
    fn into(self) -> Event {
        EventBuilder::v10()
            .id("uid.created.account.iroha")
            //TODO: will be great to have `Environment` struct as Runtime read-only global
            //configurations holder?
            .source(Url::parse("127.0.0.1:8888").expect("Failed to parse Url."))
            .time(Utc::now())
            .build()
    }
}

/// Module `connection` provides functionality needed for Iroha Events consumers.
pub mod connection {
    use super::*;
    use async_std::{future, prelude::*};
    #[cfg(feature = "mock")]
    use iroha_network::mock::prelude::*;
    #[cfg(not(feature = "mock"))]
    use iroha_network::prelude::*;
    use std::{convert::TryFrom, fmt::Debug, str::FromStr, time::Duration};

    const TIMEOUT: Duration = Duration::from_millis(1000);

    /// Criteria to filter `Occurrences` based on.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct Criteria {
        occurrence_type: OccurrenceType,
        entity_type: EntityType,
    }

    /// Which type of `Occurrences` should be added to filter.
    #[derive(Clone, Debug, Eq, PartialEq, Io, Serialize, Deserialize, Encode, Decode)]
    pub enum OccurrenceType {
        /// Filter `Occurrence::Created` events.
        Created,
        /// Filter `Occurrence::Updated` events.
        Updated,
        /// Filter `Occurrence::Deleted` events.
        Deleted,
        /// Filter all types of `Occurrence`.
        All,
    }

    impl OccurrenceType {
        /// Returns if the `occurrence` matches this `OccurrenceType` filter.
        pub fn filter(&self, occurrence: &Occurrence) -> bool {
            let occurrence_type: OccurrenceType = occurrence.into();
            *self == OccurrenceType::All || *self == occurrence_type
        }
    }

    impl From<&Occurrence> for OccurrenceType {
        fn from(occurrence: &Occurrence) -> Self {
            match occurrence {
                Occurrence::Created(_) => OccurrenceType::Created,
                Occurrence::Updated(_) => OccurrenceType::Updated,
                Occurrence::Deleted(_) => OccurrenceType::Deleted,
            }
        }
    }

    impl FromStr for OccurrenceType {
        type Err = String;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s.trim().to_lowercase().as_ref() {
                "created" => Ok(OccurrenceType::Created),
                "updated" => Ok(OccurrenceType::Updated),
                "deleted" => Ok(OccurrenceType::Deleted),
                "all" => Ok(OccurrenceType::All),
                _ => Err("Failed to parse OccurrenceType.".to_string()),
            }
        }
    }

    /// Which type of `Entities` should be added to filter.
    #[derive(Clone, Debug, Eq, PartialEq, Io, Serialize, Deserialize, Encode, Decode)]
    pub enum EntityType {
        /// Filter `Entity::Account` events.
        Account,
        /// Filter `Entity::AssetDefinition` events.
        AssetDefinition,
        /// Filter `Entity::Asset` events.
        Asset,
        /// Filter `Entity::Domain` events.
        Domain,
        /// Filter `Entity::Peer` events.
        Peer,
        /// Filter `Entity::Transaction` events.
        Transaction,
        /// Filter `Entity::Block` events.
        Block,
        /// Filter `Entity::Time` events.
        Time,
        /// Filter all types of `Entity`.
        All,
    }

    impl EntityType {
        /// Returns if the `entity` matches this `EntityType` filter.
        pub fn filter(&self, entity: &Entity) -> bool {
            let entity_type: EntityType = entity.into();
            *self == EntityType::All || *self == entity_type
        }
    }

    impl From<&Entity> for EntityType {
        fn from(entity: &Entity) -> Self {
            match entity {
                Entity::Account(_) => EntityType::Account,
                Entity::AssetDefinition(_) => EntityType::AssetDefinition,
                Entity::Asset(_) => EntityType::Asset,
                Entity::Domain(_) => EntityType::Domain,
                Entity::Peer(_) => EntityType::Peer,
                Entity::Transaction(_) => EntityType::Transaction,
                Entity::Block(_) => EntityType::Block,
                Entity::Time => EntityType::Time,
            }
        }
    }

    impl FromStr for EntityType {
        type Err = String;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s.trim().to_lowercase().as_ref() {
                "account" => Ok(EntityType::Account),
                "asset_definition" => Ok(EntityType::AssetDefinition),
                "asset" => Ok(EntityType::Asset),
                "domain" => Ok(EntityType::Domain),
                "peer" => Ok(EntityType::Peer),
                "transaction" => Ok(EntityType::Transaction),
                "block" => Ok(EntityType::Block),
                "time" => Ok(EntityType::Time),
                "all" => Ok(EntityType::All),
                _ => Err("Failed to parse EntityType.".to_string()),
            }
        }
    }

    impl Criteria {
        /// Default `Criteria` constructor.
        pub fn new(occurrence_type: OccurrenceType, entity_type: EntityType) -> Self {
            Self {
                occurrence_type,
                entity_type,
            }
        }

        /// To create `ConnectRequest` `Criteria` should be signed.
        pub fn sign(self, key_pair: KeyPair) -> ConnectRequest {
            let signature =
                Signature::new(key_pair, &Vec::from(&self)).expect("Failed to create a signature.");
            ConnectRequest {
                criteria: self,
                signature,
            }
        }
    }

    /// Initial Message for Connect functionality.
    /// Provides Authority and Criteria to Filter Events.
    #[derive(Clone, Debug, Io, Serialize, Deserialize, Encode, Decode)]
    pub struct ConnectRequest {
        criteria: Criteria,
        signature: Signature,
    }

    impl ConnectRequest {
        /// Validates `ConnectRequest` and it's signature.
        pub fn validate(&self) -> ValidConnectRequest {
            self.signature
                .verify(&Vec::from(&self.criteria))
                .expect("Failed to verify Connect Request");
            ValidConnectRequest {
                criteria: self.criteria.clone(),
                _authority: self.signature.public_key.clone(),
            }
        }
    }

    /// Validated `ConnectRequest`.
    pub struct ValidConnectRequest {
        criteria: Criteria,
        _authority: PublicKey,
    }

    impl From<ValidConnectRequest> for Filter {
        fn from(valid_connect_request: ValidConnectRequest) -> Self {
            Filter {
                criteria: valid_connect_request.criteria,
            }
        }
    }

    /// Filter to apply to Events stream before sending to Consumers.
    #[derive(Debug)]
    pub struct Filter {
        criteria: Criteria,
    }

    impl Filter {
        /// Apply filter and decide - to send Event to the Consumer or not to send.
        pub fn apply(&self, occurrence: &Occurrence) -> bool {
            self.criteria.occurrence_type.filter(occurrence)
                && self.criteria.entity_type.filter(occurrence.entity())
        }
    }

    /// Consumer for Iroha `Occurrence`(s).
    /// Passes the occurences over the corresponding connection `stream` if they match the `filter`.
    pub struct Consumer {
        stream: Box<dyn AsyncStream>,
        filter: Filter,
    }

    impl Consumer {
        /// Constructs `Consumer`.
        pub fn new(stream: Box<dyn AsyncStream>, filter: Filter) -> Self {
            Consumer { stream, filter }
        }

        /// Forwards the `occurrence` over the `stream` if it matches the `filter`.
        pub async fn consume(&mut self, occurrence: &Occurrence) -> Result<(), String> {
            if self.filter.apply(occurrence) {
                let occurrence: Vec<u8> = occurrence.clone().into();
                future::timeout(TIMEOUT, self.stream.write_all(&occurrence))
                    .await
                    .map_err(|e| format!("Failed to write message: {}", e))?
                    .map_err(|e| format!("Failed to write message: {}", e))?;
                future::timeout(TIMEOUT, self.stream.flush())
                    .await
                    .map_err(|e| format!("Failed to flush: {}", e))?
                    .map_err(|e| format!("Failed to flush: {}", e))?;
                //TODO: replace with known size.
                let mut receipt = vec![0u8; 1000];
                let read_size = future::timeout(TIMEOUT, self.stream.read(&mut receipt))
                    .await
                    .map_err(|e| format!("Failed to read receipt: {}", e))?
                    .map_err(|e| format!("Failed to read receipt: {}", e))?;
                let _receipt = Receipt::try_from(receipt[..read_size].to_vec())?;
            }
            Ok(())
        }
    }

    unsafe impl Send for Consumer {}
    unsafe impl Sync for Consumer {}

    impl Debug for Consumer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("EventConnection")
                .field("filter", &self.filter)
                .finish()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn occurrences_are_filtered_correctly() {
            let filter = Filter {
                criteria: Criteria::new(OccurrenceType::Created, EntityType::All),
            };
            let occurrences = vec![
                Occurrence::Updated(Entity::Time),
                Occurrence::Created(Entity::Block(Vec::new())),
                Occurrence::Created(Entity::Transaction(Vec::new())),
            ];
            let filtered_occurrences: Vec<Occurrence> = occurrences
                .iter()
                .cloned()
                .filter(|occurrence| filter.apply(occurrence))
                .collect();
            let occurrences: Vec<u8> = occurrences
                .iter()
                .skip(1)
                .map(|occurrence| Vec::<u8>::from(occurrence))
                .flatten()
                .collect();
            let filtered_occurrences: Vec<u8> = filtered_occurrences
                .iter()
                .map(|occurrence| Vec::<u8>::from(occurrence))
                .flatten()
                .collect();
            assert_eq!(occurrences, filtered_occurrences);
        }
    }
}
