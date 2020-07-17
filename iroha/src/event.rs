//! Iroha is a quite dynamic system so many events can happen.
//! This module contains descriptions of such an events and
//! utilitary Iroha Special Instructions to work with them.

use crate::prelude::*;
use async_std::sync::{Receiver, Sender};
use chrono::Utc;
use cloudevents::{Event, EventBuilder};
use iroha_derive::*;
use parity_scale_codec::{Decode, Encode};
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
#[derive(Io, Encode, Decode, Debug, Clone)]
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
#[derive(Io, Encode, Decode, Debug, Clone)]
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
    use async_std::prelude::*;
    #[cfg(feature = "mock")]
    use iroha_network::mock::prelude::*;
    #[cfg(not(feature = "mock"))]
    use iroha_network::prelude::*;
    use std::{convert::TryFrom, fmt::Debug, str::FromStr};

    /// Criteria to filter `Occurrences` based on.
    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub struct Criteria {
        occurrence_type: OccurrenceType,
        entity_type: EntityType,
    }

    /// Which type of `Occurrences` should be added to filter.
    #[derive(Clone, Debug, Io, Encode, Decode, Eq, PartialEq)]
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
    #[derive(Clone, Debug, Io, Encode, Decode, Eq, PartialEq)]
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
    #[derive(Clone, Debug, Io, Encode, Decode)]
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
                _authority: self.signature.public_key,
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
                self.stream
                    .write_all(&occurrence)
                    .await
                    .map_err(|e| format!("Failed to write message: {}", e))?;
                self.stream
                    .flush()
                    .await
                    .map_err(|e| format!("Failed to flush: {}", e))?;
                //TODO: replace with known size.
                let mut receipt = vec![0u8; 1000];
                let read_size = self
                    .stream
                    .read(&mut receipt)
                    .await
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

/// Iroha Special Instructions module provides `EventInstruction` enum with all legal types of
/// events related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `EventInstruction` variants into generic ISI.
pub mod isi {
    use crate::prelude::*;
    use iroha_derive::*;
    use parity_scale_codec::{Decode, Encode};
    use std::time::SystemTime;

    type Trigger = IrohaQuery;

    /// Instructions related to different type of Iroha events.
    /// Some of them are time based triggers, another watch the Blockchain and others
    /// check the World State View.
    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub enum EventInstruction {
        /// This variant of Iroha Special Instruction will execute instruction when new Block
        /// will be created.
        OnBlockCreated(Box<Instruction>),
        /// This variant of Iroha Special Instruction will execute instruction when Blockchain
        /// will reach predefined height.
        OnBlockchainHeight(u64, Box<Instruction>),
        /// This variant of Iroha Special Instruction will execute instruction when World State
        /// View change will be detected by `Trigger`.
        OnWorldStateViewChange(Trigger, Box<Instruction>),
        /// This variant of Iroha Special Instruction will execute instruction regulary.
        OnTimestamp(u128, Box<Instruction>),
    }

    impl EventInstruction {
        /// Execute `EventInstruction` origin based on the changes in `world_state_view`.
        pub fn execute(
            &self,
            authority: <Account as Identifiable>::Id,
            world_state_view: &mut WorldStateView,
        ) -> Result<(), String> {
            use EventInstruction::*;
            match self {
                OnBlockCreated(instruction) => instruction.execute(authority, world_state_view),
                OnBlockchainHeight(height, instruction) => {
                    if &world_state_view
                        .blocks
                        .last()
                        .ok_or("Failed to find the last block on the chain.")?
                        .header
                        .height
                        == height
                    {
                        instruction.execute(authority, world_state_view)
                    } else {
                        Ok(())
                    }
                }
                OnWorldStateViewChange(trigger, instruction) => {
                    if Instruction::ExecuteQuery(trigger.clone())
                        .execute(authority.clone(), world_state_view)
                        .is_ok()
                    {
                        instruction.execute(authority, world_state_view)
                    } else {
                        Ok(())
                    }
                }
                OnTimestamp(duration, instruction) => {
                    let now = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .expect("Failed to get System Time.")
                        .as_millis();
                    if now
                        - world_state_view
                            .blocks
                            .last()
                            .ok_or("Failed to find the last block on the chain.")?
                            .header
                            .timestamp
                        >= *duration
                    {
                        instruction.execute(authority, world_state_view)
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            account::query::GetAccount,
            block::BlockHeader,
            crypto::{KeyPair, Signatures},
            peer::{Peer, PeerId},
            permission::Permission,
        };
        use std::collections::BTreeMap;

        #[test]
        fn test_on_block_created_should_trigger() {
            let block = CommittedBlock {
                header: BlockHeader {
                    timestamp: 0,
                    height: 0,
                    previous_block_hash: [0; 32],
                    merkle_root_hash: [0; 32],
                    number_of_view_changes: 0,
                    invalidated_blocks_hashes: Vec::new(),
                },
                transactions: Vec::new(),
                signatures: Signatures::default(),
            };
            let domain_name = "global".to_string();
            let mut asset_definitions = BTreeMap::new();
            let asset_definition_id = crate::permission::permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let public_key = KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key;
            let account_id = AccountId::new("root", &domain_name);
            let asset_id = AssetId {
                definition_id: asset_definition_id,
                account_id: account_id.clone(),
            };
            let asset = Asset::with_permission(asset_id.clone(), Permission::Anything);
            let mut account =
                Account::with_signatory(&account_id.name, &account_id.domain_name, public_key);
            account.assets.insert(asset_id, asset);
            let mut accounts = BTreeMap::new();
            accounts.insert(account_id, account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = BTreeMap::new();
            domains.insert(domain_name, domain);
            let address = "127.0.0.1:8080".to_string();
            let peer = Peer::with_domains(
                PeerId {
                    address,
                    public_key,
                },
                &Vec::new(),
                domains,
            );
            let add_domain_instruction = peer.add_domain(Domain::new("Test".to_string())).into();
            let authority = peer.authority();
            let mut world_state_view = WorldStateView::new(peer);
            world_state_view.put(&block);
            let on_block_created_listener =
                EventInstruction::OnBlockCreated(Box::new(add_domain_instruction));
            on_block_created_listener
                .execute(authority, &mut world_state_view)
                .expect("Failed to execute instruction.");
            assert!(world_state_view.domain("Test").is_some());
        }

        #[test]
        fn test_on_blockchain_height_should_trigger() {
            let block = CommittedBlock {
                header: BlockHeader {
                    timestamp: 0,
                    height: 0,
                    previous_block_hash: [0; 32],
                    merkle_root_hash: [0; 32],
                    number_of_view_changes: 0,
                    invalidated_blocks_hashes: Vec::new(),
                },
                transactions: Vec::new(),
                signatures: Signatures::default(),
            };
            let domain_name = "global".to_string();
            let mut asset_definitions = BTreeMap::new();
            let asset_definition_id = crate::permission::permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let public_key = KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key;
            let account_id = AccountId::new("root", &domain_name);
            let asset_id = AssetId {
                definition_id: asset_definition_id,
                account_id: account_id.clone(),
            };
            let asset = Asset::with_permission(asset_id.clone(), Permission::Anything);
            let mut account =
                Account::with_signatory(&account_id.name, &account_id.domain_name, public_key);
            account.assets.insert(asset_id, asset);
            let mut accounts = BTreeMap::new();
            accounts.insert(account_id, account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = BTreeMap::new();
            domains.insert(domain_name, domain);
            let address = "127.0.0.1:8080".to_string();
            let peer = Peer::with_domains(
                PeerId {
                    address,
                    public_key,
                },
                &Vec::new(),
                domains,
            );
            let add_domain_instruction = peer.add_domain(Domain::new("Test".to_string())).into();
            let authority = peer.authority();
            let mut world_state_view = WorldStateView::new(peer);
            world_state_view.put(&block);
            let on_block_created_listener =
                EventInstruction::OnBlockchainHeight(0, Box::new(add_domain_instruction));
            on_block_created_listener
                .execute(authority, &mut world_state_view)
                .expect("Failed to execute instruction.");
            assert!(world_state_view.domain("Test").is_some());
        }

        #[test]
        fn test_on_world_state_view_change_should_trigger() {
            let block = CommittedBlock {
                header: BlockHeader {
                    timestamp: 0,
                    height: 0,
                    previous_block_hash: [0; 32],
                    merkle_root_hash: [0; 32],
                    number_of_view_changes: 0,
                    invalidated_blocks_hashes: Vec::new(),
                },
                transactions: Vec::new(),
                signatures: Signatures::default(),
            };
            let domain_name = "global".to_string();
            let mut asset_definitions = BTreeMap::new();
            let asset_definition_id = crate::permission::permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let public_key = KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key;
            let account_id = AccountId::new("root", &domain_name);
            let asset_id = AssetId {
                definition_id: asset_definition_id,
                account_id: account_id.clone(),
            };
            let asset = Asset::with_permission(asset_id.clone(), Permission::Anything);
            let mut account = Account::new(&account_id.name, &account_id.domain_name);
            account.assets.insert(asset_id, asset);
            let mut accounts = BTreeMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = BTreeMap::new();
            domains.insert(domain_name, domain);
            let address = "127.0.0.1:8080".to_string();
            let peer = Peer::with_domains(
                PeerId {
                    address,
                    public_key,
                },
                &Vec::new(),
                domains,
            );
            let add_domain_instruction = peer.add_domain(Domain::new("Test".to_string())).into();
            let authority = peer.authority();
            let mut world_state_view = WorldStateView::new(peer);
            world_state_view.put(&block);
            let on_block_created_listener = EventInstruction::OnWorldStateViewChange(
                IrohaQuery::GetAccount(GetAccount { account_id }),
                Box::new(add_domain_instruction),
            );
            on_block_created_listener
                .execute(authority, &mut world_state_view)
                .expect("Failed to execute instruction.");
            assert!(world_state_view.domain("Test").is_some());
        }

        #[test]
        fn test_on_timestamp_should_trigger() {
            let block = CommittedBlock {
                header: BlockHeader {
                    timestamp: 0,
                    height: 0,
                    previous_block_hash: [0; 32],
                    merkle_root_hash: [0; 32],
                    number_of_view_changes: 0,
                    invalidated_blocks_hashes: Vec::new(),
                },
                transactions: Vec::new(),
                signatures: Signatures::default(),
            };
            let domain_name = "global".to_string();
            let mut asset_definitions = BTreeMap::new();
            let asset_definition_id = crate::permission::permission_asset_definition_id();
            asset_definitions.insert(
                asset_definition_id.clone(),
                AssetDefinition::new(asset_definition_id.clone()),
            );
            let public_key = KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key;
            let account_id = AccountId::new("root", &domain_name);
            let asset_id = AssetId {
                definition_id: asset_definition_id,
                account_id: account_id.clone(),
            };
            let asset = Asset::with_permission(asset_id.clone(), Permission::Anything);
            let mut account =
                Account::with_signatory(&account_id.name, &account_id.domain_name, public_key);
            account.assets.insert(asset_id, asset);
            let mut accounts = BTreeMap::new();
            accounts.insert(account_id, account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = BTreeMap::new();
            domains.insert(domain_name, domain);
            let address = "127.0.0.1:8080".to_string();
            let peer = Peer::with_domains(
                PeerId {
                    address,
                    public_key,
                },
                &Vec::new(),
                domains,
            );
            let add_domain_instruction = peer.add_domain(Domain::new("Test".to_string())).into();
            let authority = peer.authority();
            let mut world_state_view = WorldStateView::new(peer);
            world_state_view.put(&block);
            let on_block_created_listener =
                EventInstruction::OnTimestamp(1, Box::new(add_domain_instruction));
            on_block_created_listener
                .execute(authority, &mut world_state_view)
                .expect("Failed to execute instruction.");
            assert!(world_state_view.domain("Test").is_some());
        }
    }
}
