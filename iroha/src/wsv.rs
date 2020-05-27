//! This module provides `WorldStateView` - in-memory representations of the current blockchain
//! state.

use crate::prelude::*;

/// Current state of the blockchain alligned with `Iroha` module.
#[derive(Debug, Clone)]
pub struct WorldStateView {
    peer: Peer,
}

impl WorldStateView {
    /// Default `WorldStateView` constructor.
    pub fn new(peer: Peer) -> Self {
        WorldStateView { peer }
    }

    /// Put `ValidBlock` of information with changes in form of **Iroha Special Instructions**
    /// into the world.
    pub async fn put(&mut self, block: &CommittedBlock) {
        for transaction in &block.transactions {
            if let Err(e) = &transaction.proceed(self) {
                eprintln!("Failed to procced transaction on WSV: {}", e);
            }
        }
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
    pub fn read_asset(&mut self, id: &<Asset as Identifiable>::Id) -> Option<&mut Asset> {
        self.account(&id.account_id)?.assets.get_mut(id)
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
