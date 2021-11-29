//! This module provides `WorldStateView` - in-memory representations of the current blockchain
//! state.

use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use config::Configuration;
use dashmap::{
    mapref::one::{Ref as DashmapRef, RefMut as DashmapRefMut},
    DashSet,
};
use eyre::Result;
use iroha_crypto::HashOf;
use iroha_data_model::{domain::DomainsMap, peer::PeersIds, prelude::*};
use tokio::task;

use crate::{block::Chain, prelude::*, smartcontracts::FindError};

/// World proxy for using with `WorldTrait`
#[derive(Debug, Default, Clone)]
pub struct World(iroha_data_model::world::World);

impl Deref for World {
    type Target = iroha_data_model::world::World;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for World {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl WorldTrait for World {
    /// Creates `World` with these `domains` and `trusted_peers_ids`
    fn with(
        domains: impl IntoIterator<Item = (Name, Domain)>,
        trusted_peers_ids: impl IntoIterator<Item = PeerId>,
    ) -> Self {
        Self(iroha_data_model::world::World::with(
            domains,
            trusted_peers_ids,
        ))
    }
}

impl World {
    /// Creates an empty `World`.
    pub fn new() -> Self {
        Self::default()
    }
}

/// World trait for mocking
pub trait WorldTrait:
    Deref<Target = iroha_data_model::world::World>
    + DerefMut
    + Send
    + Sync
    + 'static
    + Debug
    + Default
    + Sized
    + Clone
{
    /// Creates `World` with these `domains` and `trusted_peers_ids`
    fn with(
        domains: impl IntoIterator<Item = (Name, Domain)>,
        trusted_peers_ids: impl IntoIterator<Item = PeerId>,
    ) -> Self;
}

/// Current state of the blockchain alligned with `Iroha` module.
#[derive(Debug, Clone)]
pub struct WorldStateView<W: WorldTrait> {
    /// The world - contains `domains`, `triggers`, etc..
    pub world: W,
    /// Configuration of World State View.
    pub config: Configuration,
    /// Blockchain.
    blocks: Arc<Chain>,
    /// Hashes of transactions
    pub transactions: DashSet<HashOf<VersionedTransaction>>,
}

impl<W: WorldTrait + Default> Default for WorldStateView<W> {
    fn default() -> Self {
        Self::new(W::default())
    }
}

/// WARNING!!! INTERNAL USE ONLY!!!
impl<W: WorldTrait> WorldStateView<W> {
    /// Default `WorldStateView` constructor.
    pub fn new(world: W) -> Self {
        WorldStateView {
            world,
            config: Configuration::default(),
            transactions: DashSet::new(),
            blocks: Arc::new(Chain::new()),
        }
    }

    /// [`WorldStateView`] constructor with configuration.
    pub fn from_config(config: Configuration, world: W) -> Self {
        WorldStateView {
            world,
            blocks: Arc::new(Chain::new()),
            transactions: DashSet::new(),
            config,
        }
    }

    /// Initializes WSV with the blocks from block storage.
    #[iroha_futures::telemetry_future]
    pub async fn init(&self, blocks: Vec<VersionedCommittedBlock>) {
        for block in blocks {
            self.apply(block).await
        }
    }

    /// Apply `CommittedBlock` with changes in form of **Iroha Special Instructions** to `self`.
    #[iroha_futures::telemetry_future]
    #[iroha_logger::log(skip(self, block))]
    pub async fn apply(&self, block: VersionedCommittedBlock) {
        for tx in &block.as_inner_v1().transactions {
            if let Err(error) = tx.proceed(self) {
                iroha_logger::warn!(%error, "Failed to proceed transaction on WSV");
            }
            self.transactions.insert(tx.hash());
            // Yeild control cooperatively to the task scheduler.
            // The transaction processing is a long CPU intensive task, so this should be included here.
            task::yield_now().await;
        }
        for tx in &block.as_inner_v1().rejected_transactions {
            self.transactions.insert(tx.hash());
        }
        self.blocks.push(block);
    }

    /// Hash of latest block
    pub fn latest_block_hash(&self) -> HashOf<VersionedCommittedBlock> {
        self.blocks
            .latest_block()
            .map_or(HashOf::from_hash(Hash([0_u8; 32])), |block| {
                block.value().hash()
            })
    }

    /// Height of blockchain
    pub fn height(&self) -> u64 {
        self.blocks
            .latest_block()
            .map_or(0, |block_entry| block_entry.value().header().height)
    }

    /// Returns blocks after hash
    pub fn blocks_after(
        &self,
        hash: HashOf<VersionedCommittedBlock>,
        max_blocks: u32,
    ) -> Vec<VersionedCommittedBlock> {
        self.blocks
            .iter()
            .skip_while(|block_entry| block_entry.value().header().previous_block_hash != hash)
            .take(max_blocks as usize)
            .map(|block_entry| block_entry.value().clone())
            .collect()
    }

    /// Calculates network TPS.
    ///
    /// `None` means that transactions can not yet be calculated.
    #[allow(clippy::float_arithmetic, clippy::cast_precision_loss)]
    pub fn transactions_per_second(&self) -> Option<f64> {
        let start_time_ms = self.blocks.iter().next()?.as_inner_v1().header.timestamp;
        let end_time_ms = current_time().as_millis();
        let transactions_number = self.blocks.iter().fold(0_u64, |acc, block| {
            acc + block.as_inner_v1().transactions.len() as u64
                + block.as_inner_v1().rejected_transactions.len() as u64
        });
        Some(transactions_number as f64 / ((end_time_ms - start_time_ms) as f64 / 1000_f64))
    }

    /// Get `World` without an ability to modify it.
    pub fn world(&self) -> &W {
        &self.world
    }

    /// Add new `Domain` entity.
    pub fn add_domain(&mut self, domain: Domain) {
        self.world.domains.insert(domain.name.clone(), domain);
    }

    /// Returns reference for domains map
    pub fn domains(&self) -> &DomainsMap {
        &self.world.domains
    }

    /// Returns reference for trusted peer ids
    pub fn trusted_peers_ids(&self) -> &PeersIds {
        &self.world.trusted_peers_ids
    }

    /// Get `Domain` without an ability to modify it.
    ///
    /// # Errors
    /// Fails if there is no domain
    pub fn domain(&self, name: &str) -> Result<DashmapRef<Name, Domain>> {
        let domain = self
            .world
            .domains
            .get(name)
            .ok_or_else(|| FindError::Domain(name.to_owned()))?;
        Ok(domain)
    }

    /// Get `Domain` with an ability to modify it.
    ///
    /// # Errors
    /// Fails if there is no domain
    pub fn domain_mut(&self, name: &str) -> Result<DashmapRefMut<Name, Domain>> {
        let domain = self
            .world
            .domains
            .get_mut(name)
            .ok_or_else(|| FindError::Domain(name.to_owned()))?;
        Ok(domain)
    }

    /// Get `Domain` and pass it to closure.
    /// # Errors
    /// Fails if there is no domain
    pub fn map_domain<T>(
        &self,
        id: &<Domain as Identifiable>::Id,
        f: impl FnOnce(&Domain) -> T,
    ) -> Result<T> {
        let domain = self.domain(id)?;
        Ok(f(domain.value()))
    }

    /// Get `Domain` and pass it to closure to modify it
    /// # Errors
    /// Fails if there is no domain
    pub fn modify_domain(
        &self,
        name: &str,
        f: impl FnOnce(&mut Domain) -> Result<()>,
    ) -> Result<()> {
        let mut domain = self.domain_mut(name)?;
        f(domain.value_mut())
    }

    /// Get `Account` and pass it to closure.
    /// # Errors
    /// Fails if there is no domain or account
    pub fn map_account<T>(
        &self,
        id: &<Account as Identifiable>::Id,
        f: impl FnOnce(&Account) -> T,
    ) -> Result<T> {
        let domain = self.domain(&id.domain_name)?;
        let account = domain
            .accounts
            .get(id)
            .ok_or_else(|| FindError::Account(id.clone()))?;
        Ok(f(account))
    }

    /// Get `Account` and pass it to closure to modify it
    /// # Errors
    /// Fails if there is no domain or account
    pub fn modify_account(
        &self,
        id: &<Account as Identifiable>::Id,
        f: impl FnOnce(&mut Account) -> Result<()>,
    ) -> Result<()> {
        let mut domain = self.domain_mut(&id.domain_name)?;
        let account = domain
            .accounts
            .get_mut(id)
            .ok_or_else(|| FindError::Account(id.clone()))?;
        f(account)
    }

    /// Get `Account`'s `Asset`s and pass it to closure
    ///
    /// # Errors
    /// Fails if account finding fails
    pub fn account_assets(&self, id: &<Account as Identifiable>::Id) -> Result<Vec<Asset>> {
        self.map_account(id, |account| account.assets.values().cloned().collect())
    }

    /// Get all `PeerId`s without an ability to modify them.
    pub fn peers(&self) -> Vec<Peer> {
        let mut vec = self
            .world
            .trusted_peers_ids
            .iter()
            .map(|peer| Peer::new((&*peer).clone()))
            .collect::<Vec<Peer>>();
        vec.sort();
        vec
    }

    /// Get `Asset` by its id
    ///
    /// # Errors
    /// Fails if there are no such asset or account
    pub fn asset(&self, id: &<Asset as Identifiable>::Id) -> Result<Asset> {
        self.map_account(&id.account_id, |account| -> Result<Asset> {
            account
                .assets
                .get(id)
                .ok_or_else(|| FindError::Asset(id.clone()).into())
                .map(Clone::clone)
        })?
    }

    /// Get `Asset` by its id
    ///
    /// # Errors
    /// Fails if there are no such asset or account
    pub fn modify_asset(
        &self,
        id: &<Asset as Identifiable>::Id,
        f: impl FnOnce(&mut Asset) -> Result<()>,
    ) -> Result<()> {
        self.modify_account(&id.account_id, |account| {
            let mut asset = account
                .assets
                .get_mut(id)
                .ok_or_else(|| FindError::Asset(id.clone()))?;
            f(&mut asset)?;
            if asset.value.is_zero_value() {
                account.assets.remove(id);
            }
            Ok(())
        })
    }

    /// Tries to get asset or inserts new with `default_asset_value`.
    ///
    /// # Errors
    /// Fails if there is no account with such name.
    pub fn asset_or_insert(
        &self,
        id: &<Asset as Identifiable>::Id,
        default_asset_value: impl Into<AssetValue>,
    ) -> Result<Asset> {
        self.modify_account(&id.account_id, |account| {
            let _ = account
                .assets
                .entry(id.clone())
                .or_insert_with(|| Asset::new(id.clone(), default_asset_value.into()));
            Ok(())
        })?;
        self.asset(id)
    }

    /// Add new `Asset` entity.
    /// # Errors
    /// Fails if there is no account for asset
    pub fn add_asset(&self, asset: Asset) -> Result<()> {
        let id = asset.id.account_id.clone();
        self.modify_account(&id, move |account| {
            account.assets.insert(asset.id.clone(), asset);
            Ok(())
        })
    }

    /// Get `AssetDefinitionEntry` without an ability to modify it.
    ///
    /// # Errors
    /// Fails if asset definition entry does not exist
    pub fn asset_definition_entry(
        &self,
        id: &<AssetDefinition as Identifiable>::Id,
    ) -> Result<AssetDefinitionEntry> {
        self.domain(&id.domain_name)?
            .asset_definitions
            .get(id)
            .ok_or_else(|| FindError::AssetDefinition(id.clone()).into())
            .map(Clone::clone)
    }

    /// Get `AssetDefinitionEntry` with an ability to modify it.
    ///
    /// # Errors
    /// Fails if asset definition entry does not exist
    pub fn modify_asset_definition_entry(
        &self,
        id: &<AssetDefinition as Identifiable>::Id,
        f: impl FnOnce(&mut AssetDefinitionEntry) -> Result<()>,
    ) -> Result<()> {
        let mut domain = self.domain_mut(&id.domain_name)?;
        let asset_definition_entry = domain
            .asset_definitions
            .get_mut(id)
            .ok_or_else(|| FindError::AssetDefinition(id.clone()))?;
        f(asset_definition_entry)
    }

    /// Checks if this `tx` is already committed or rejected.
    pub fn has_transaction(&self, hash: &HashOf<VersionedTransaction>) -> bool {
        self.transactions.contains(hash)
    }

    /// Find a transaction by provided hash
    pub fn transaction_value_by_hash(
        &self,
        hash: &HashOf<VersionedTransaction>,
    ) -> Option<TransactionValue> {
        self.blocks.iter().find_map(|b| {
            b.as_inner_v1()
                .rejected_transactions
                .iter()
                .find(|e| e.hash() == *hash)
                .cloned()
                .map(TransactionValue::RejectedTransaction)
                .or_else(|| {
                    b.as_inner_v1()
                        .transactions
                        .iter()
                        .find(|e| e.hash() == *hash)
                        .cloned()
                        .map(VersionedTransaction::from)
                        .map(TransactionValue::Transaction)
                })
        })
    }

    /// Get committed and rejected transaction of the account.
    pub fn transactions_values_by_account_id(
        &self,
        account_id: &AccountId,
    ) -> Vec<TransactionValue> {
        let mut transactions = self
            .blocks
            .iter()
            .flat_map(|block_entry| {
                let block = block_entry.value().as_inner_v1();
                block
                    .rejected_transactions
                    .iter()
                    .filter(|transaction| &transaction.payload().account_id == account_id)
                    .cloned()
                    .map(TransactionValue::RejectedTransaction)
                    .chain(
                        block
                            .transactions
                            .iter()
                            .filter(|transaction| &transaction.payload().account_id == account_id)
                            .cloned()
                            .map(VersionedTransaction::from)
                            .map(TransactionValue::Transaction),
                    )
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        transactions.sort();
        transactions
    }
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_config::derive::Configurable;
    use iroha_data_model::{metadata::Limits as MetadataLimits, LengthLimits};
    use serde::{Deserialize, Serialize};

    const DEFAULT_METADATA_LIMITS: MetadataLimits =
        MetadataLimits::new(2_u32.pow(20), 2_u32.pow(12));
    const DEFAULT_IDENT_LENGTH_LIMITS: LengthLimits = LengthLimits::new(1, 2_u32.pow(7));

    /// [`WorldStateView`] configuration.
    #[derive(Clone, Deserialize, Serialize, Debug, Copy, Configurable, PartialEq, Eq)]
    #[config(env_prefix = "WSV_")]
    #[serde(rename_all = "UPPERCASE", default)]
    pub struct Configuration {
        /// [`MetadataLimits`] for every asset with store.
        pub asset_metadata_limits: MetadataLimits,
        /// [`MetadataLimits`] of any asset definition's metadata.
        pub asset_definition_metadata_limits: MetadataLimits,
        /// [`MetadataLimits`] of any account's metadata.
        pub account_metadata_limits: MetadataLimits,
        /// [`MetadataLimits`] of any domain's metadata.
        pub domain_metadata_limits: MetadataLimits,
        /// [`LengthLimits`] for the number of chars in identifiers that can be stored in the WSV.
        pub ident_length_limits: LengthLimits,
    }

    impl Default for Configuration {
        fn default() -> Self {
            Configuration {
                asset_metadata_limits: DEFAULT_METADATA_LIMITS,
                asset_definition_metadata_limits: DEFAULT_METADATA_LIMITS,
                account_metadata_limits: DEFAULT_METADATA_LIMITS,
                domain_metadata_limits: DEFAULT_METADATA_LIMITS,
                ident_length_limits: DEFAULT_IDENT_LENGTH_LIMITS,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use super::{World, *};

    #[tokio::test]
    async fn get_blocks_after_hash() {
        const BLOCK_CNT: usize = 10;
        const BATCH_SIZE: u32 = 3;

        let mut block = ValidBlock::new_dummy().commit();
        let wsv = WorldStateView::<World>::default();

        let mut block_hashes = vec![];
        for i in 1..=BLOCK_CNT {
            block.header.height = i as u64;
            if let Some(block_hash) = block_hashes.last() {
                block.header.previous_block_hash = *block_hash;
            }
            let block: VersionedCommittedBlock = block.clone().into();
            block_hashes.push(block.hash());
            wsv.apply(block).await;
        }

        assert_eq!(
            wsv.blocks_after(block_hashes[2], BATCH_SIZE)
                .iter()
                .map(VersionedCommittedBlock::hash)
                .collect::<Vec<_>>(),
            block_hashes
                .into_iter()
                .skip(3)
                .take(BATCH_SIZE as usize)
                .collect::<Vec<_>>(),
        );
    }

    #[tokio::test]
    async fn calculate_tps() {
        let block = ValidBlock::new_dummy().commit();
        let block: VersionedCommittedBlock = block.clone().into();
        let wsv = WorldStateView::<World>::default();

        assert!(wsv.transactions_per_second().is_none());

        wsv.apply(block).await;

        assert!(wsv.transactions_per_second().is_some());
    }
}
