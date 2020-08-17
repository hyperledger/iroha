//! This module provides `WorldStateView` - in-memory representations of the current blockchain
//! state.

use crate::prelude::*;
use iroha_data_model::prelude::*;

/// Current state of the blockchain alligned with `Iroha` module.
#[derive(Debug, Clone)]
pub struct WorldStateView {
    /// The state of this peer.
    pub peer: Peer,
    /// Blockchain of commited transactions.
    pub blocks: Vec<CommittedBlock>,
}

/// WARNING!!! INTERNAL USE ONLY!!!
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
                log::warn!("Failed to procced transaction on WSV: {}", e);
            }
        }
        self.blocks.push(block.clone());
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
        let _ = self.peer.domains.insert(domain.name.clone(), domain);
    }

    /// Get `Domain` without an ability to modify it.
    pub fn read_domain(&self, name: &str) -> Option<&Domain> {
        self.peer.domains.get(name)
    }

    /// Get `Domain` with an ability to modify it.
    pub fn domain(&mut self, name: &str) -> Option<&mut Domain> {
        self.peer.domains.get_mut(name)
    }

    /// Get all `Domain`s without an ability to modify them.
    pub fn read_all_domains(&self) -> Vec<&Domain> {
        self.peer.domains.values().collect()
    }

    /// Get all `Account`s without an ability to modify them.
    pub fn read_all_accounts(&self) -> Vec<&Account> {
        self.peer
            .domains
            .values()
            .flat_map(|domain| domain.accounts.values())
            .collect()
    }

    /// Get `Account` without an ability to modify it.
    pub fn read_account(&self, id: &<Account as Identifiable>::Id) -> Option<&Account> {
        self.read_domain(&id.domain_name)?.accounts.get(id)
    }

    /// Get `Account` with an ability to modify it.
    pub fn account(&mut self, id: &<Account as Identifiable>::Id) -> Option<&mut Account> {
        self.domain(&id.domain_name)?.accounts.get_mut(id)
    }

    /// Get all `Asset`s without an ability to modify them.
    pub fn read_all_assets(&self) -> Vec<&Asset> {
        self.peer
            .domains
            .values()
            .flat_map(|domain| domain.accounts.values())
            .flat_map(|account| account.assets.values())
            .collect()
    }

    /// Get all `Asset Definition`s without an ability to modify them.
    pub fn read_all_assets_definitions(&self) -> Vec<&AssetDefinition> {
        self.peer
            .domains
            .values()
            .flat_map(|domain| domain.asset_definitions.values())
            .collect()
    }

    /// Get `Asset` without an ability to modify it.
    pub fn read_asset(&self, id: &<Asset as Identifiable>::Id) -> Option<&Asset> {
        self.read_account(&id.account_id)?.assets.get(id)
    }

    /// Get `Asset` with an ability to modify it.
    pub fn asset(&mut self, id: &<Asset as Identifiable>::Id) -> Option<&mut Asset> {
        self.account(&id.account_id)?.assets.get_mut(id)
    }

    /// Add new `Asset` entity.
    pub fn add_asset(&mut self, asset: Asset) {
        let _ = self
            .account(&asset.id.account_id)
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
