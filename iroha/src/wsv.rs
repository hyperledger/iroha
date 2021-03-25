//! This module provides `WorldStateView` - in-memory representations of the current blockchain
//! state.

use std::collections::HashMap;

use config::Configuration;
use iroha_data_model::prelude::*;

use crate::prelude::*;

/// Current state of the blockchain alligned with `Iroha` module.
#[derive(Debug, Clone)]
pub struct WorldStateView {
    /// The world - contains `domains`, `triggers`, etc..
    pub world: World,
    /// Hashes of the committed and rejected transactions.
    pub transactions: HashMap<Hash, TransactionValue>,
    /// Configuration of World State View.
    pub config: Configuration,
}

/// WARNING!!! INTERNAL USE ONLY!!!
impl WorldStateView {
    /// Default `WorldStateView` constructor.
    pub fn new(world: World) -> Self {
        WorldStateView {
            world,
            transactions: HashMap::new(),
            config: Configuration::default(),
        }
    }

    /// [`WorldStateView`] constructor with configuration.
    pub fn from_config(config: Configuration, world: World) -> Self {
        WorldStateView {
            world,
            transactions: HashMap::new(),
            config,
        }
    }

    /// Initializes WSV with the blocks from block storage.
    pub fn init(&mut self, blocks: &[VersionedValidBlock]) {
        for block in blocks {
            self.apply(&block.clone().commit());
        }
    }

    /// Apply `CommittedBlock` with changes in form of **Iroha Special Instructions** to `self`.
    pub fn apply(&mut self, block: &VersionedCommittedBlock) {
        for transaction in &block.as_inner_v1().transactions {
            if let Err(e) = &transaction.proceed(self) {
                log::warn!("Failed to proceed transaction on WSV: {}", e);
            }
            let _ = self.transactions.insert(
                transaction.hash(),
                TransactionValue::Transaction(transaction.clone().into()),
            );
        }
        for transaction in &block.as_inner_v1().rejected_transactions {
            let _ = self.transactions.insert(
                transaction.hash(),
                TransactionValue::RejectedTransaction(transaction.clone()),
            );
        }
    }

    /// Get `World` without an ability to modify it.
    pub const fn read_world(&self) -> &World {
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

    /// Get `Asset` with an ability to modify it.
    /// If no asset is present - create it. Similar to Entry API.
    ///
    /// Returns `None` if no corresponding account was found.
    pub fn asset_or_insert<V: Into<AssetValue>>(
        &mut self,
        id: &<Asset as Identifiable>::Id,
        default_value: V,
    ) -> Option<&mut Asset> {
        Some(
            self.account(&id.account_id)?
                .assets
                .entry(id.clone())
                .or_insert_with(|| Asset::new(id.clone(), default_value)),
        )
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
        self.transactions.contains_key(&transaction_hash)
    }

    /// Get committed and rejected transaction of the account.
    pub fn read_transactions(&self, account_id: &AccountId) -> Vec<&TransactionValue> {
        let mut vec: Vec<&TransactionValue> = self
            .transactions
            .values()
            .filter(|tx| &tx.payload().account_id == account_id)
            .collect();
        vec.sort();
        vec
    }
}

/// This module contains all configuration related logic.
pub mod config {
    use std::env;

    use iroha_data_model::metadata::Limits as MetadataLimits;
    use iroha_error::{Result, WrapErr};
    use serde::Deserialize;

    const ASSET_MAX_STORE_LEN: &str = "ASSET_MAX_STORE_LEN";
    const ASSET_MAX_STORE_ENTRY_BYTE_SIZE: &str = "ASSET_MAX_STORE_ENTRY_BYTE_SIZE";
    const ACCOUNT_MAX_METADATA_LEN: &str = "ACCOUNT_MAX_METADATA_LEN";
    const ACCOUNT_MAX_METADATA_ENTRY_BYTE_SIZE: &str = "ACCOUNT_MAX_METADATA_ENTRY_BYTE_SIZE";
    const DEFAULT_ASSET_LIMITS: MetadataLimits = MetadataLimits::new(2_u32.pow(20), 2_u32.pow(12));
    const DEFAULT_ACCOUNT_LIMITS: MetadataLimits =
        MetadataLimits::new(2_u32.pow(20), 2_u32.pow(12));

    /// [`WorldStateView`](super::WorldStateView) configuration.
    #[derive(Clone, Deserialize, Debug, Copy)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct Configuration {
        /// [`MetadataLimits`] for every asset with store.
        #[serde(default = "default_asset_limits")]
        pub asset_metadata_limits: MetadataLimits,
        /// [`MetadataLimits`] of any account's metadata.
        #[serde(default = "default_account_limits")]
        pub account_metadata_limits: MetadataLimits,
    }

    impl Default for Configuration {
        fn default() -> Self {
            Configuration {
                asset_metadata_limits: DEFAULT_ASSET_LIMITS,
                account_metadata_limits: DEFAULT_ACCOUNT_LIMITS,
            }
        }
    }

    impl Configuration {
        /// Load environment variables and replace predefined parameters with these variables
        /// values.
        ///
        /// # Errors
        /// Can fail if parsing numbers from env variables fails.
        pub fn load_environment(&mut self) -> Result<()> {
            if let Ok(asset_max_store_len) = env::var(ASSET_MAX_STORE_LEN) {
                self.asset_metadata_limits.max_len =
                    asset_max_store_len.parse::<u32>().wrap_err_with(|| {
                        format!("Failed to parse env variable {}.", ASSET_MAX_STORE_LEN)
                    })?;
            }
            if let Ok(asset_max_entry_byte_size) = env::var(ASSET_MAX_STORE_ENTRY_BYTE_SIZE) {
                self.asset_metadata_limits.max_entry_byte_size =
                    asset_max_entry_byte_size.parse::<u32>().wrap_err_with(|| {
                        format!(
                            "Failed to parse env variable {}.",
                            ASSET_MAX_STORE_ENTRY_BYTE_SIZE
                        )
                    })?;
            }
            if let Ok(account_max_metadata_len) = env::var(ACCOUNT_MAX_METADATA_LEN) {
                self.account_metadata_limits.max_len =
                    account_max_metadata_len.parse::<u32>().wrap_err_with(|| {
                        format!("Failed to parse env variable {}.", ACCOUNT_MAX_METADATA_LEN)
                    })?;
            }
            if let Ok(account_max_entry_byte_size) = env::var(ACCOUNT_MAX_METADATA_ENTRY_BYTE_SIZE)
            {
                self.account_metadata_limits.max_entry_byte_size = account_max_entry_byte_size
                    .parse::<u32>()
                    .wrap_err_with(|| {
                        format!(
                            "Failed to parse env variable {}.",
                            ACCOUNT_MAX_METADATA_ENTRY_BYTE_SIZE
                        )
                    })?;
            }
            Ok(())
        }
    }

    const fn default_asset_limits() -> MetadataLimits {
        DEFAULT_ASSET_LIMITS
    }

    const fn default_account_limits() -> MetadataLimits {
        DEFAULT_ACCOUNT_LIMITS
    }
}
