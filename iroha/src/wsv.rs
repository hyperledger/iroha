//! This module provides `WorldStateView` - in-memory representations of the current blockchain
//! state.

use crate::prelude::*;

/// Current state of the blockchain alligned with `Iroha` module.
#[derive(Debug, Clone)]
pub struct WorldStateView {
    /// The state of this peer.
    pub peer: Peer,
    /// Blockchain of commited transactions.
    pub blocks: Vec<CommittedBlock>,
}

impl WorldStateView {
    /// Default `WorldStateView` constructor.
    pub fn new(peer: Peer) -> Self {
        WorldStateView {
            peer,
            blocks: Vec::new(),
        }
    }

    /// Initializes WSV with the blocks from block storage.
    pub fn init(&mut self, blocks: &[ValidBlock]) {
        for block in blocks {
            self.put(&block.clone().commit());
        }
    }

    /// Put `ValidBlock` of information with changes in form of **Iroha Special Instructions**
    /// into the world.
    pub fn put(&mut self, block: &CommittedBlock) {
        for transaction in &block.transactions {
            if let Err(e) = &transaction.proceed(self) {
                eprintln!("Failed to procced transaction on WSV: {}", e);
            }
        }
        self.blocks.push(block.clone());
        for listener in self.peer.listeners.clone() {
            if let Err(e) = listener.execute(self.peer.authority(), self) {
                eprintln!("Failed to execute listener on WSV: {}", e);
            }
        }
    }

    /// Get `Peer` without an ability to modify it.
    pub fn read_peer(&self) -> &Peer {
        &self.peer
    }

    /// Get `Peer` with an ability to modify it.
    pub fn peer(&mut self) -> &mut Peer {
        &mut self.peer
    }

    /// Add new `Domain` entity.
    pub fn add_domain(&mut self, domain: Domain) {
        self.peer.domains.insert(domain.name.clone(), domain);
    }

    /// Get `Domain` without an ability to modify it.
    pub fn read_domain(&self, name: &str) -> Option<&Domain> {
        self.peer.domains.get(name)
    }

    /// Get `Domain` with an ability to modify it.
    pub fn domain(&mut self, name: &str) -> Option<&mut Domain> {
        self.peer.domains.get_mut(name)
    }

    /// Get `Account` without an ability to modify it.
    pub fn read_account(&self, id: &<Account as Identifiable>::Id) -> Option<&Account> {
        self.read_domain(&id.domain_name)?.accounts.get(id)
    }

    /// Get `Account` with an ability to modify it.
    pub fn account(&mut self, id: &<Account as Identifiable>::Id) -> Option<&mut Account> {
        self.domain(&id.domain_name)?.accounts.get_mut(id)
    }

    /// Get `Asset` without an ability to modify it.
    pub fn read_asset(&mut self, id: &<Asset as Identifiable>::Id) -> Option<&Asset> {
        self.account(&id.account_id)?.assets.get(id)
    }

    /// Get `Asset` with an ability to modify it.
    pub fn asset(&mut self, id: &<Asset as Identifiable>::Id) -> Option<&mut Asset> {
        self.account(&id.account_id)?.assets.get_mut(id)
    }

    /// Add new `Asset` entity.
    pub fn add_asset(&mut self, asset: Asset) {
        self.account(&asset.id.account_id)
            .expect("Failed to find an account.")
            .assets
            .insert(asset.id.clone(), asset);
    }

    /// Get `AssetDefinition` without an ability to modify it.
    pub fn read_asset_definition(
        &self,
        id: &<AssetDefinition as Identifiable>::Id,
    ) -> Option<&AssetDefinition> {
        self.read_domain(&id.domain_name)?.asset_definitions.get(id)
    }

    /// Get `AssetDefinition` with an ability to modify it.
    pub fn asset_definition(
        &mut self,
        id: &<AssetDefinition as Identifiable>::Id,
    ) -> Option<&mut AssetDefinition> {
        self.domain(&id.domain_name)?.asset_definitions.get_mut(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signatures;
    use crate::{
        block::BlockHeader,
        crypto::KeyPair,
        peer::{Peer, PeerId},
        permission::Permission,
    };
    use std::collections::HashMap;

    #[async_std::test]
    async fn test_listeners() {
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
        let mut peer = Peer::with_domains(
            PeerId {
                address: address.clone(),
                public_key,
            },
            &Vec::new(),
            domains,
        );
        peer.add_listener(Instruction::If(
            Box::new(Instruction::Notify("Test".to_string())),
            Box::new(peer.add_domain(Domain::new("Test".to_string())).into()),
            None,
        ));
        let mut world_state_view = WorldStateView {
            peer,
            blocks: Vec::new(),
        };
        world_state_view.put(&block);
        assert!(world_state_view.domain("Test").is_some());
    }
}
