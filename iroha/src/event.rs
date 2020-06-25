//! Iroha is a quite dynamic system so many events can happen.
//! This module contains descriptions of such an events and
//! utilitary Iroha Special Instructions to work with them.

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
        use std::collections::HashMap;

        #[test]
        fn test_on_block_created_should_trigger() {
            let block = CommittedBlock {
                header: BlockHeader {
                    timestamp: 0,
                    height: 0,
                    previous_block_hash: [0; 32],
                    merkle_root_hash: [0; 32],
                    number_of_view_changes: 0,
                },
                transactions: Vec::new(),
                signatures: Signatures::default(),
            };
            let domain_name = "global".to_string();
            let mut asset_definitions = HashMap::new();
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
            let mut account = Account::with_signatory(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            account.assets.insert(asset_id.clone(), asset);
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let peer = Peer::with_domains(
                PeerId {
                    address: address.clone(),
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
                },
                transactions: Vec::new(),
                signatures: Signatures::default(),
            };
            let domain_name = "global".to_string();
            let mut asset_definitions = HashMap::new();
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
            let mut account = Account::with_signatory(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            account.assets.insert(asset_id.clone(), asset);
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let peer = Peer::with_domains(
                PeerId {
                    address: address.clone(),
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
                },
                transactions: Vec::new(),
                signatures: Signatures::default(),
            };
            let domain_name = "global".to_string();
            let mut asset_definitions = HashMap::new();
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
            account.assets.insert(asset_id.clone(), asset);
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let peer = Peer::with_domains(
                PeerId {
                    address: address.clone(),
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
                },
                transactions: Vec::new(),
                signatures: Signatures::default(),
            };
            let domain_name = "global".to_string();
            let mut asset_definitions = HashMap::new();
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
            let mut account = Account::with_signatory(
                &account_id.name,
                &account_id.domain_name,
                public_key.clone(),
            );
            account.assets.insert(asset_id.clone(), asset);
            let mut accounts = HashMap::new();
            accounts.insert(account_id.clone(), account);
            let domain = Domain {
                name: domain_name.clone(),
                accounts,
                asset_definitions,
            };
            let mut domains = HashMap::new();
            domains.insert(domain_name.clone(), domain);
            let address = "127.0.0.1:8080".to_string();
            let peer = Peer::with_domains(
                PeerId {
                    address: address.clone(),
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
