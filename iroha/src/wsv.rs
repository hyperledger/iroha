//! This module provides `WorldStateView` - in-memory representations of the current blockchain
//! state.

use config::Configuration;
use iroha_data_model::{domain::DomainsMap, peer::PeersIds, prelude::*};
use iroha_error::Result;
use iroha_structs::{HashMap, RwLock};

use crate::{isi::FindError, prelude::*};

/// Current state of the blockchain alligned with `Iroha` module.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
    pub fn init(&self, blocks: &[VersionedValidBlock]) {
        for block in blocks {
            self.apply(&block.clone().commit());
        }
    }

    /// Apply `CommittedBlock` with changes in form of **Iroha Special Instructions** to `self`.
    pub fn apply(&self, block: &VersionedCommittedBlock) {
        for transaction in &block.as_inner_v1().transactions {
            if let Err(e) = transaction.proceed(self) {
                iroha_logger::warn!("Failed to proceed transaction on WSV: {}", e);
            }
            drop(self.transactions.insert(
                transaction.hash(),
                TransactionValue::Transaction(transaction.clone().into()),
            ));
        }
        for transaction in &block.as_inner_v1().rejected_transactions {
            drop(self.transactions.insert(
                transaction.hash(),
                TransactionValue::RejectedTransaction(transaction.clone()),
            ));
        }
    }

    /// Get `World` without an ability to modify it.
    pub const fn world(&self) -> &World {
        &self.world
    }

    /// Add new `Domain` entity.
    pub fn add_domain(&mut self, domain: Domain) {
        drop(self.world.domains.insert(domain.name.clone(), domain));
    }

    /// Returns reference for domains map
    pub const fn domains(&self) -> &DomainsMap {
        &self.world.domains
    }

    /// Returns reference for trusted peer ids
    pub const fn trusted_peers_ids(&self) -> &PeersIds {
        &self.world.trusted_peers_ids
    }

    /// Returns reference for parameters
    pub const fn parameters(&self) -> &RwLock<Vec<Parameter>> {
        &self.world.parameters
    }

    /// Get `Domain` without an ability to modify it.
    /// # Errors
    /// Fails if there is no domain
    pub fn domain<T>(&self, name: &str, f: impl FnOnce(&Domain) -> T) -> Result<T> {
        let domain = self
            .world
            .domains
            .get(name)
            .ok_or_else(|| FindError::Domain(name.to_owned()))?;
        Ok(f(domain.value()))
    }

    /// Get `Account` and pass it to closure
    /// # Errors
    /// Fails if there is no domain or account
    pub fn account<T>(
        &self,
        id: &<Account as Identifiable>::Id,
        f: impl FnOnce(&Account) -> T,
    ) -> Result<T> {
        let result = self.domain(&id.domain_name, |domain| -> Result<T> {
            let account = domain
                .accounts
                .get(id)
                .ok_or_else(|| FindError::Account(id.clone()))?;
            Ok(f(account.value()))
        })??;
        Ok(result)
    }

    /// Get `Account`'s `Asset`s and pass it to closure
    /// # Errors
    /// Fails if account finding fails
    pub fn account_assets(
        &self,
        id: &<Account as Identifiable>::Id,
        mut f: impl FnMut(&Asset),
    ) -> Result<()> {
        self.account(id, |account| {
            account.assets.iter().for_each(|guard| f(&*guard.value()))
        })
    }

    /// Insert new account
    /// # Errors
    /// Fails if there are no such domain
    pub fn update_account(&self, account: Account) -> Result<()> {
        let id = account.id.domain_name.clone();
        self.domain(&id, move |domain| {
            drop(domain.accounts.insert(account.id.clone(), account));
        })
    }

    /// Get all `PeerId`s without an ability to modify them.
    pub fn read_all_peers(&self) -> Vec<Peer> {
        let mut vec = self
            .world
            .trusted_peers_ids
            .iter()
            .map(|peer| Peer::new((&*peer).clone()))
            .collect::<Vec<Peer>>();
        vec.sort();
        vec
    }

    /// Get `Asset` and passes it to closure
    /// # Errors
    /// Fails if there are no such asset or account
    pub fn asset<T>(
        &self,
        id: &<Asset as Identifiable>::Id,
        f: impl FnOnce(&Asset) -> T,
    ) -> Result<T> {
        self.account(&id.account_id, |account| -> Result<T> {
            let asset = account
                .assets
                .get(id)
                .ok_or_else(|| FindError::Asset(id.clone()))?;
            Ok(f(asset.value()))
        })?
    }

    /// Tries to get asset and call closure, if fails calls else closure
    pub fn asset_or<T>(
        &self,
        id: &<Asset as Identifiable>::Id,
        ok: impl FnOnce(&Asset) -> T,
        else_: impl FnOnce() -> T,
    ) -> T {
        match self.asset(id, ok) {
            Ok(ok) => ok,
            Err(_) => else_(),
        }
    }

    /// Tries to get asset and call closure, if fails, inserts new asset and calls else closure
    /// # Panics
    /// Can panic if getting after insert fails
    /// # Errors
    /// Fails if there is  no account with such name
    pub fn asset_or_insert<T>(
        &self,
        id: &<Asset as Identifiable>::Id,
        v: impl Into<AssetValue>,
        f: impl FnOnce(&Asset) -> T,
    ) -> Result<T> {
        self.account(&id.account_id, |account| -> Result<T> {
            let asset = account.assets.get(id).unwrap_or_else(|| {
                drop(
                    account
                        .assets
                        .insert(id.clone(), Asset::new(id.clone(), v.into())),
                );
                account.assets.get(id).unwrap()
            });
            Ok(f(asset.value()))
        })?
    }
    /// Add new `Asset` entity.
    /// # Errors
    /// Fails if there is no account for asset
    pub fn add_asset(&self, asset: Asset) -> Result<()> {
        let id = asset.id.account_id.clone();
        self.account(&id, move |account| {
            drop(account.assets.insert(asset.id.clone(), asset));
        })
    }

    /// Get `AssetDefinitionEntry` without an ability to modify it.
    /// # Errors
    /// Fails if asset definition entry does not exist
    pub fn asset_definition_entry<T>(
        &self,
        id: &<AssetDefinition as Identifiable>::Id,
        f: impl FnOnce(&AssetDefinitionEntry) -> T,
    ) -> Result<T> {
        self.domain(&id.domain_name, |domain| {
            let asset = domain
                .asset_definitions
                .get(id)
                .ok_or_else(|| FindError::AssetDefinition(id.clone()))?;
            Ok(f(asset.value()))
        })?
    }

    /// Checks if this `transaction_hash` is already committed or rejected.
    pub fn has_transaction(&self, transaction_hash: Hash) -> bool {
        self.transactions.contains_key(&transaction_hash)
    }

    /// Get committed and rejected transaction of the account.
    pub fn read_transactions(&self, account_id: &AccountId) -> Vec<TransactionValue> {
        let mut vec: Vec<TransactionValue> = self
            .transactions
            .iter()
            .filter(|read_guard| &read_guard.value().payload().account_id == account_id)
            .map(|read_guard| read_guard.value().clone())
            .collect();
        vec.sort();
        vec
    }
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_config::derive::Configurable;
    use iroha_data_model::metadata::Limits as MetadataLimits;
    use iroha_data_model::LengthLimits;
    use serde::{Deserialize, Serialize};

    const DEFAULT_ASSET_LIMITS: MetadataLimits = MetadataLimits::new(2_u32.pow(20), 2_u32.pow(12));
    const DEFAULT_ACCOUNT_LIMITS: MetadataLimits =
        MetadataLimits::new(2_u32.pow(20), 2_u32.pow(12));
    const DEFAULT_LENGTH_LIMITS: LengthLimits = LengthLimits::new(1, 2_u32.pow(7));
    /// [`WorldStateView`](super::WorldStateView) configuration.
    #[derive(Clone, Deserialize, Serialize, Debug, Copy, Configurable)]
    #[config(env_prefix = "WSV_")]
    #[serde(rename_all = "UPPERCASE", default)]
    pub struct Configuration {
        /// [`MetadataLimits`] for every asset with store.
        pub asset_metadata_limits: MetadataLimits,
        /// [`MetadataLimits`] of any account's metadata.
        pub account_metadata_limits: MetadataLimits,
        /// [`LengthLimits`] of identifiers in bytes that can be stored in the WSV.
        pub length_limits: LengthLimits,
    }

    impl Default for Configuration {
        fn default() -> Self {
            Configuration {
                asset_metadata_limits: DEFAULT_ASSET_LIMITS,
                account_metadata_limits: DEFAULT_ACCOUNT_LIMITS,
                length_limits: DEFAULT_LENGTH_LIMITS,
            }
        }
    }
}
