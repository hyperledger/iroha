//! This module provides `WorldStateView` - in-memory representations of the current blockchain
//! state.

use std::collections::HashSet;

use crate::prelude::*;
use iroha_data_model::prelude::*;

/// Current state of the blockchain alligned with `Iroha` module.
#[derive(Debug, Clone)]
pub struct WorldStateView {
    /// The world - contains `domains`, `triggers`, etc..
    pub world: World,
    /// Hashes of the committed and rejected transactions.
    pub transactions_hashes: HashSet<Hash>,
}

/// WARNING!!! INTERNAL USE ONLY!!!
impl WorldStateView {
    /// Default `WorldStateView` constructor.
    pub fn new(world: World) -> Self {
        WorldStateView {
            world,
            transactions_hashes: HashSet::new(),
        }
    }

    /// Initializes WSV with the blocks from block storage.
    pub fn init(&mut self, blocks: &[ValidBlock]) {
        for block in blocks {
            self.apply(&block.clone().commit());
        }
    }

    /// Apply `CommittedBlock` with changes in form of **Iroha Special Instructions** to `self`.
    pub fn apply(&mut self, block: &CommittedBlock) {
        for transaction in &block.transactions {
            if let Err(e) = &transaction.proceed(self) {
                log::warn!("Failed to procced transaction on WSV: {}", e);
            }
            let _ = self.transactions_hashes.insert(transaction.hash());
        }
        for transaction in &block.rejected_transactions {
            let _ = self.transactions_hashes.insert(transaction.hash());
        }
    }

    /// Get `World` without an ability to modify it.
    pub fn read_world(&self) -> &World {
        &self.world
    }

    /// Get `World` with an ability to modify it.
    pub fn world(&mut self) -> &mut World {
        &mut self.world
    }

    /// Add new `Domain` entity.
    pub fn add_domain(&mut self, domain: Domain) {
        let _ = self.world.domains.insert(domain.name.clone(), domain);
    }

    /// Get `Domain` without an ability to modify it.
    pub fn read_domain(&self, name: &str) -> Option<&Domain> {
        self.world.domains.get(name)
    }

    /// Get `Domain` with an ability to modify it.
    pub fn domain(&mut self, name: &str) -> Option<&mut Domain> {
        self.world.domains.get_mut(name)
    }

    /// Get all `Domain`s without an ability to modify them.
    pub fn read_all_domains(&self) -> Vec<&Domain> {
        let mut vec = self.world.domains.values().collect::<Vec<&Domain>>();
        vec.sort();
        vec
    }

    /// Get all `Account`s without an ability to modify them.
    pub fn read_all_accounts(&self) -> Vec<&Account> {
        let mut vec = self
            .world
            .domains
            .values()
            .flat_map(|domain| domain.accounts.values())
            .collect::<Vec<&Account>>();
        vec.sort();
        vec
    }

    /// Get `Account` without an ability to modify it.
    pub fn read_account(&self, id: &<Account as Identifiable>::Id) -> Option<&Account> {
        self.read_domain(&id.domain_name)?.accounts.get(id)
    }

    /// Get `Account`'s `Asset`s without an ability to modify it.
    pub fn read_account_assets(&self, id: &<Account as Identifiable>::Id) -> Option<Vec<&Asset>> {
        let mut vec = self
            .read_account(id)?
            .assets
            .values()
            .collect::<Vec<&Asset>>();
        vec.sort();
        Some(vec)
    }

    /// Get `Account` with an ability to modify it.
    pub fn account(&mut self, id: &<Account as Identifiable>::Id) -> Option<&mut Account> {
        self.domain(&id.domain_name)?.accounts.get_mut(id)
    }

    /// Get all `PeerId`s without an ability to modify them.
    pub fn read_all_peers(&self) -> Vec<Peer> {
        let mut vec = self
            .read_world()
            .trusted_peers_ids
            .iter()
            .cloned()
            .map(Peer::new)
            .collect::<Vec<Peer>>();
        vec.sort();
        vec
    }

    /// Get all `Asset`s without an ability to modify them.
    pub fn read_all_assets(&self) -> Vec<&Asset> {
        let mut vec = self
            .world
            .domains
            .values()
            .flat_map(|domain| domain.accounts.values())
            .flat_map(|account| account.assets.values())
            .collect::<Vec<&Asset>>();
        vec.sort();
        vec
    }

    /// Get all `Asset Definition Entry`s without an ability to modify them.
    pub fn read_all_assets_definitions_entries(&self) -> Vec<&AssetDefinitionEntry> {
        let mut vec = self
            .world
            .domains
            .values()
            .flat_map(|domain| domain.asset_definitions.values())
            .collect::<Vec<&AssetDefinitionEntry>>();
        vec.sort();
        vec
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

    /// Get `AssetDefinitionEntry` without an ability to modify it.
    pub fn read_asset_definition_entry(
        &self,
        id: &<AssetDefinition as Identifiable>::Id,
    ) -> Option<&AssetDefinitionEntry> {
        self.read_domain(&id.domain_name)?.asset_definitions.get(id)
    }

    /// Get `AssetDefinitionEntry` with an ability to modify it.
    pub fn asset_definition_entry(
        &mut self,
        id: &<AssetDefinition as Identifiable>::Id,
    ) -> Option<&mut AssetDefinitionEntry> {
        self.domain(&id.domain_name)?.asset_definitions.get_mut(id)
    }

    /// Checks if this `transaction_hash` is already committed or rejected.
    pub fn has_transaction(&self, transaction_hash: Hash) -> bool {
        self.transactions_hashes.contains(&transaction_hash)
    }
}
