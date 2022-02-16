//! This module provides the [`WorldStateView`] - in-memory representations of the current blockchain
//! state.

use std::{
    collections::btree_map::Entry,
    fmt::Debug,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use config::Configuration;
use dashmap::{
    mapref::one::{Ref as DashMapRef, RefMut as DashMapRefMut},
    DashSet,
};
use eyre::Result;
use iroha_crypto::HashOf;
use iroha_data_model::{prelude::*, trigger::Action};
use iroha_logger::prelude::*;
use iroha_telemetry::metrics::Metrics;
use tokio::task;

use crate::{
    block::Chain,
    event::EventsSender,
    prelude::*,
    smartcontracts::{isi::Error, wasm, Execute, FindError, InstructionType},
    DomainsMap, PeersIds,
};

/// Sender type of the new block notification channel
pub type NewBlockNotificationSender = tokio::sync::watch::Sender<()>;
/// Receiver type of the new block notification channel
pub type NewBlockNotificationReceiver = tokio::sync::watch::Receiver<()>;

/// World trait for mocking
pub trait WorldTrait:
    Deref<Target = World> + DerefMut + Send + Sync + 'static + Debug + Default + Sized + Clone
{
    /// Creates a [`World`] with these [`Domain`]s and trusted [`PeerId`]s.
    fn with(
        domains: impl IntoIterator<Item = (DomainId, Domain)>,
        trusted_peers_ids: impl IntoIterator<Item = PeerId>,
    ) -> Self;
}

/// The global entity consisting of `domains`, `triggers` and etc.
/// For example registration of domain, will have this as an ISI target.
#[derive(Debug, Default, Clone)]
pub struct World {
    /// Identifications of discovered trusted peers.
    pub trusted_peers_ids: PeersIds,
    /// Roles. [`Role`] pairs.
    #[cfg(feature = "roles")]
    pub roles: crate::RolesMap,
    /// Registered domains.
    pub domains: DomainsMap,

    /// Iroha parameters.
    pub parameters: Vec<Parameter>,
    /// Iroha `Triggers` registered on the peer.
    pub triggers: Vec<Instruction>,
}

impl Deref for World {
    type Target = Self;
    #[inline]
    fn deref(&self) -> &Self::Target {
        self
    }
}

impl DerefMut for World {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self
    }
}

/// Current state of the blockchain aligned with `Iroha` module.
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
    /// Metrics for prometheus endpoint.
    pub metrics: Arc<Metrics>,
    /// Notifies subscribers when new block is applied
    new_block_notifier: Arc<NewBlockNotificationSender>,
    /// Triggers
    pub triggers: Arc<TriggerSet>,
    /// Transmitter to broadcast [`WorldStateView`]-related events.
    events_sender: Option<EventsSender>,
}

impl<W: WorldTrait + Default> Default for WorldStateView<W> {
    #[inline]
    fn default() -> Self {
        Self::new(W::default())
    }
}

impl World {
    /// Creates an empty `World`.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }
}

impl WorldTrait for World {
    fn with(
        domains: impl IntoIterator<Item = (DomainId, Domain)>,
        trusted_peers_ids: impl IntoIterator<Item = PeerId>,
    ) -> Self {
        let domains = domains.into_iter().collect();
        let trusted_peers_ids = trusted_peers_ids.into_iter().collect();
        World {
            domains,
            trusted_peers_ids,
            ..World::new()
        }
    }
}

/// WARNING!!! INTERNAL USE ONLY!!!
impl<W: WorldTrait> WorldStateView<W> {
    /// Get `Account`'s `Asset`s and pass it to closure
    ///
    /// # Errors
    /// Fails if account finding fails
    pub fn account_assets(&self, id: &AccountId) -> Result<Vec<Asset>, FindError> {
        self.map_account(id, |account| account.assets.values().cloned().collect())
    }

    /// Returns a set of permission tokens granted to this account as part of roles and separately.
    #[allow(clippy::unused_self)]
    pub fn account_permission_tokens(
        &self,
        account: &Account,
    ) -> iroha_data_model::account::Permissions {
        #[allow(unused_mut)]
        let mut tokens = account.permission_tokens.clone();
        #[cfg(feature = "roles")]
        for role_id in &account.roles {
            if let Some(role) = self.world.roles.get(role_id) {
                let mut role_tokens = role.permissions.clone();
                tokens.append(&mut role_tokens);
            }
        }
        tokens
    }

    /// Add new `Asset` entity.
    ///
    /// # Errors
    /// Fails if there is no account for asset
    pub fn add_asset(&self, asset: Asset) -> Result<(), Error> {
        let id = asset.id.account_id.clone();
        self.modify_account(&id, move |account| {
            account.assets.insert(asset.id.clone(), asset);
            Ok(())
        })
    }

    /// Add new `Domain` entity.
    pub fn add_domain(&mut self, domain: Domain) {
        self.world.domains.insert(domain.id.clone(), domain);
    }

    fn process_executable(&self, executable: &Executable, authority: &AccountId) -> Result<()> {
        match executable {
            Executable::Instructions(instructions) => {
                instructions.iter().cloned().try_for_each(|instruction| {
                    let events = instruction.execute(authority.clone(), self)?;

                    self.produce_events(events);
                    Ok::<_, eyre::Report>(())
                })?;
            }
            Executable::Wasm(bytes) => {
                let mut wasm_runtime = wasm::Runtime::new()?;
                wasm_runtime.execute(self, authority, bytes)?;
            }
        }
        Ok(())
    }

    /// Apply `CommittedBlock` with changes in form of **Iroha Special
    /// Instructions** to `self`. `trigger_recommendations` are
    /// applied first.
    ///
    /// # Errors
    ///
    /// - (RARE) if applying transaction after validation fails.  This
    /// scenario is rare, because the `tx` validation implies applying
    /// instructions directly to a clone of the wsv.  If this happens,
    /// you likely have data corruption.
    #[iroha_futures::telemetry_future]
    #[log(skip(self, block))]
    pub async fn apply(&self, block: VersionedCommittedBlock) -> Result<()> {
        // TODO: Validate the trigger executables as well as the technical account.
        for Action {
            technical_account,
            executable,
            ..
        } in &block.as_v1().trigger_recommendations
        {
            self.process_executable(executable, technical_account)?;
            task::yield_now().await;
        }

        // TODO: Should this block panic instead?
        for tx in &block.as_v1().transactions {
            let account_id = &tx.payload().account_id;

            match &tx.as_v1().payload.instructions {
                Executable::Instructions(instructions) => {
                    instructions.iter().cloned().try_for_each(|instruction| {
                        instruction.execute(account_id.clone(), self)
                    })?;
                }
                Executable::Wasm(bytes) => {
                    let mut wasm_runtime = wasm::Runtime::new()?;
                    wasm_runtime.execute(self, account_id, bytes)?;
                }
            }

            self.transactions.insert(tx.hash());
            task::yield_now().await;
        }
        for tx in &block.as_v1().rejected_transactions {
            self.transactions.insert(tx.hash());
        }
        self.blocks.push(block);
        self.block_commit_metrics_update_callback();
        self.new_block_notifier.send_replace(());
        Ok(())
    }

    /// Get `Asset` by its id
    ///
    /// # Errors
    /// - No such [`Asset`]
    /// - No [`Account`] to which the [`Asset`] is associated.
    pub fn asset(&self, id: &<Asset as Identifiable>::Id) -> Result<Asset, FindError> {
        self.map_account(&id.account_id, |account| -> Result<Asset, FindError> {
            account
                .assets
                .get(id)
                .ok_or_else(|| FindError::Asset(id.clone()))
                .map(Clone::clone)
        })?
    }

    /// Send event to known subscribers.
    fn produce_event(&self, event: DataEvent) {
        let events_sender = if let Some(sender) = &self.events_sender {
            sender
        } else {
            return warn!("wsv does not equip an events sender");
        };

        drop(events_sender.send(Event::from(event)))
    }

    /// Tries to get asset or inserts new with `default_asset_value`.
    ///
    /// # Errors
    /// Fails if there is no account with such name.
    pub fn asset_or_insert(
        &self,
        id: &<Asset as Identifiable>::Id,
        default_asset_value: impl Into<AssetValue>,
    ) -> Result<Asset, Error> {
        // This function is strictly infallible.
        self.modify_account(&id.account_id, |account| {
            let _ = account
                .assets
                .entry(id.clone())
                .or_insert_with(|| Asset::new(id.clone(), default_asset_value.into()));
            Ok(())
        })
        .map_err(|err| {
            iroha_logger::warn!(?err);
            err
        })?;
        self.asset(id).map_err(Into::into)
    }

    /// Update metrics; run when block commits.
    fn block_commit_metrics_update_callback(&self) {
        let last_block_txs_accepted = self
            .blocks
            .iter()
            .last()
            .map(|block| block.as_v1().transactions.len() as u64)
            .unwrap_or_default();
        let last_block_txs_rejected = self
            .blocks
            .iter()
            .last()
            .map(|block| block.as_v1().rejected_transactions.len() as u64)
            .unwrap_or_default();
        self.metrics
            .txs
            .with_label_values(&["accepted"])
            .inc_by(last_block_txs_accepted);
        self.metrics
            .txs
            .with_label_values(&["rejected"])
            .inc_by(last_block_txs_rejected);
        self.metrics
            .txs
            .with_label_values(&["total"])
            .inc_by(last_block_txs_accepted + last_block_txs_rejected);
        self.metrics.block_height.inc();
    }

    // TODO: There could be just this one method `blocks` instead of `blocks_from_height` and
    // `blocks_after_height`. Also, this method would return references instead of cloning
    // blockchain but comes with the risk of deadlock if consumer of the iterator stores
    // references to blocks
    /// Returns iterator over blockchain blocks
    ///
    /// **Locking behaviour**: Holding references to blocks stored in the blockchain can induce
    /// deadlock. This limitation is imposed by the fact that blockchain is backed by [`dashmap::DashMap`]
    pub fn blocks(
        &self,
    ) -> impl Iterator<Item = impl Deref<Target = VersionedCommittedBlock> + '_> + '_ {
        self.blocks.iter()
    }

    /// Returns iterator over blockchain blocks after the block with the given `hash`
    pub fn blocks_after_hash(
        &self,
        hash: HashOf<VersionedCommittedBlock>,
    ) -> impl Iterator<Item = VersionedCommittedBlock> + '_ {
        self.blocks
            .iter()
            .skip_while(move |block_entry| block_entry.value().header().previous_block_hash != hash)
            .map(|block_entry| block_entry.value().clone())
    }

    /// Get an immutable view of the `World`.
    pub fn world(&self) -> &W {
        &self.world
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
    pub fn domain(
        &self,
        id: &<Domain as Identifiable>::Id,
    ) -> Result<DashMapRef<DomainId, Domain>, FindError> {
        let domain = self
            .world
            .domains
            .get(id)
            .ok_or_else(|| FindError::Domain(id.clone()))?;
        Ok(domain)
    }

    /// Get `Domain` with an ability to modify it.
    ///
    /// # Errors
    /// Fails if there is no domain
    pub fn domain_mut(
        &self,
        id: &<Domain as Identifiable>::Id,
    ) -> Result<DashMapRefMut<DomainId, Domain>, FindError> {
        let domain = self
            .world
            .domains
            .get_mut(id)
            .ok_or_else(|| FindError::Domain(id.clone()))?;
        Ok(domain)
    }

    /// Returns reference for domains map
    pub fn domains(&self) -> &DomainsMap {
        &self.world.domains
    }

    /// Get `Domain` and pass it to closure to modify it
    ///
    /// # Errors
    /// Fails if there is no domain
    pub fn modify_domain(
        &self,
        id: &<Domain as Identifiable>::Id,
        f: impl FnOnce(&mut Domain) -> Result<DataEvent, Error>,
    ) -> Result<(), Error> {
        let mut domain = self.domain_mut(id)?;
        let events = f(domain.value_mut())?;
        self.produce_event(events);
        Ok(())
    }

    /// Get `Account` and pass it to closure.
    ///
    /// # Errors
    /// Fails if there is no domain or account
    pub fn map_account<T>(
        &self,
        id: &AccountId,
        f: impl FnOnce(&Account) -> T,
    ) -> Result<T, FindError> {
        let domain = self.domain(&id.domain_id)?;
        let account = domain
            .accounts
            .get(id)
            .ok_or_else(|| FindError::Account(id.clone()))?;
        Ok(f(account))
    }

    /// Get `Domain` and pass it to closure.
    ///
    /// # Errors
    /// Fails if there is no domain
    pub fn map_domain<T>(
        &self,
        id: &<Domain as Identifiable>::Id,
        f: impl FnOnce(&Domain) -> T,
    ) -> Result<T, FindError> {
        let domain = self.domain(id)?;
        Ok(f(domain.value()))
    }

    /// Get `Account` and pass it to closure to modify it
    ///
    /// # Errors
    /// Fails if there is no domain or account
    pub fn modify_account(
        &self,
        id: &AccountId,
        f: impl FnOnce(&mut Account) -> Result<DataEvent, Error>,
    ) -> Result<(), Error> {
        self.modify_domain(&id.domain_id, |domain| {
            let account = domain
                .accounts
                .get_mut(id)
                .ok_or_else(|| FindError::Account(id.clone()))?;
            f(account)
        })
    }

    /// Get `Asset` by its id
    ///
    /// # Errors
    /// Fails if there are no such asset or account
    pub fn modify_asset(
        &self,
        id: &<Asset as Identifiable>::Id,
        f: impl FnOnce(&mut Asset) -> Result<DataEvent, Error>,
    ) -> Result<(), Error> {
        self.modify_account(&id.account_id, |account| {
            let asset = account
                .assets
                .get_mut(id)
                .ok_or_else(|| FindError::Asset(id.clone()))?;
            let event = f(asset);
            if asset.value.is_zero_value() {
                account.assets.remove(id);
            }
            event
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
    ) -> Result<Asset, Error> {
        // This function is strictly infallible.
        self.asset(id).or_else(|_| {
            self.modify_account(&id.account_id, |account| {
                account.assets.insert(
                    id.clone(),
                    Asset::new(id.clone(), default_asset_value.into()),
                );
                Ok(DataEvent::new(id.clone(), DataStatus::Created))
            })
            .map_err(|err| {
                iroha_logger::warn!(?err);
                err
            })?;
            self.asset(id).map_err(Into::into)
        })
    }

    /// Get `AssetDefinitionEntry` without an ability to modify it.
    ///
    /// # Errors
    /// Fails if asset definition entry does not exist
    pub fn asset_definition_entry(
        &self,
        id: &<AssetDefinition as Identifiable>::Id,
    ) -> Result<AssetDefinitionEntry, FindError> {
        self.domain(&id.domain_id)?
            .asset_definitions
            .get(id)
            .ok_or_else(|| FindError::AssetDefinition(id.clone()))
            .map(Clone::clone)
    }

    /// Get `AssetDefinitionEntry` and pass it to closure to modify it
    ///
    /// # Errors
    /// Fails if asset definition entry does not exist
    pub fn modify_asset_definition_entry(
        &self,
        id: &<AssetDefinition as Identifiable>::Id,
        f: impl FnOnce(&mut AssetDefinitionEntry) -> Result<DataEvent, Error>,
    ) -> Result<(), Error> {
        self.modify_domain(&id.domain_id, |domain| {
            let asset_definition_entry = domain
                .asset_definitions
                .get_mut(id)
                .ok_or_else(|| FindError::AssetDefinition(id.clone()))?;
            f(asset_definition_entry)
        })
    }

    /// Get `Domain` and pass it to closure to modify it
    ///
    /// # Errors
    /// Fails if there is no domain
    pub fn modify_domain(
        &self,
        id: &<Domain as Identifiable>::Id,
        f: impl FnOnce(&mut Domain) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut domain = self.domain_mut(id)?;
        f(domain.value_mut())
    }

    /// Construct [`WorldStateView`] with given [`World`].
    pub fn new(world: W) -> Self {
        Self::from_configuration(Configuration::default(), world)
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

    /// Get `AssetDefinitionEntry` immutable view.
    ///
    /// # Errors
    /// - Asset definition entry not found
    pub fn asset_definition_entry(
        &self,
        id: &<AssetDefinition as Identifiable>::Id,
    ) -> Result<AssetDefinitionEntry, FindError> {
        self.domain(&id.domain_id)?
            .asset_definitions
            .get(id)
            .ok_or_else(|| FindError::AssetDefinition(id.clone()))
            .map(Clone::clone)
    }

    /// Returns receiving end of the mpsc channel through which
    /// subscribers are notified when new block is added to the
    /// blockchain(after block validation).
    pub fn subscribe_to_new_block_notifications(&self) -> NewBlockNotificationReceiver {
        self.new_block_notifier.subscribe()
    }

    /// Find a [`VersionedTransaction`] by hash.
    pub fn transaction_value_by_hash(
        &self,
        hash: &HashOf<VersionedTransaction>,
    ) -> Option<TransactionValue> {
        self.blocks.iter().find_map(|b| {
            b.as_v1()
                .rejected_transactions
                .iter()
                .find(|e| e.hash() == *hash)
                .cloned()
                .map(Box::new)
                .map(TransactionValue::RejectedTransaction)
                .or_else(|| {
                    b.as_v1()
                        .transactions
                        .iter()
                        .find(|e| e.hash() == *hash)
                        .cloned()
                        .map(VersionedTransaction::from)
                        .map(Box::new)
                        .map(TransactionValue::Transaction)
                })
        })
    }

    #[cfg(test)]
    pub fn transactions_number(&self) -> u64 {
        self.blocks.iter().fold(0_u64, |acc, block| {
            acc + block.as_v1().transactions.len() as u64
                + block.as_v1().rejected_transactions.len() as u64
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
                let block = block_entry.value().as_v1();
                block
                    .rejected_transactions
                    .iter()
                    .filter(|transaction| &transaction.payload().account_id == account_id)
                    .cloned()
                    .map(Box::new)
                    .map(TransactionValue::RejectedTransaction)
                    .chain(
                        block
                            .transactions
                            .iter()
                            .filter(|transaction| &transaction.payload().account_id == account_id)
                            .cloned()
                            .map(VersionedTransaction::from)
                            .map(Box::new)
                            .map(TransactionValue::Transaction),
                    )
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        transactions.sort();
        transactions
    }

    /// Register `elem` on behalf of `authority`.
    ///
    /// # Errors
    /// Any error during `elem.register()` call
    pub fn register<T: RegisterTrait<W>>(
        &self,
        elem: T,
        authority: AccountId,
    ) -> Result<(), Error> {
        let event = elem.register(authority, self)?;
        self.produce_event(event);
        Ok(())
    }

    /// Unregister object by `id`
    ///
    /// # Errors
    /// Any error during `T::unregister()` call
    pub fn unregister<T: RegisterTrait<W>>(&self, id: T::Id) -> Result<(), Error> {
        let event = T::unregister(id, self)?;
        self.produce_event(event);
        Ok(())
    }
}

/// Trait for objects that can be registered and unregistered
pub trait RegisterTrait<W: WorldTrait>: Identifiable {
    /// Register object on behalf of `authority`.
    ///
    /// # Errors
    /// Any error during registration
    fn register(self, authority: AccountId, wsv: &WorldStateView<W>) -> Result<DataEvent, Error>;

    /// Unregister object by `id`
    ///
    /// # Errors
    /// Any error during unregistering
    fn unregister(id: Self::Id, wsv: &WorldStateView<W>) -> Result<DataEvent, Error>;
}

impl<W: WorldTrait> RegisterTrait<W> for Peer {
    fn register(self, _authority: AccountId, wsv: &WorldStateView<W>) -> Result<DataEvent, Error> {
        let peer_id = self.id;

        if !wsv.trusted_peers_ids().insert(peer_id.clone()) {
            return Err(Error::Repetition(
                InstructionType::Register,
                IdBox::PeerId(peer_id),
            ));
        }

        Ok(DataEvent::new(peer_id, DataStatus::Created))
    }

    fn unregister(peer_id: Self::Id, wsv: &WorldStateView<W>) -> Result<DataEvent, Error> {
        if wsv.trusted_peers_ids().remove(&peer_id).is_none() {
            return Err(FindError::Peer(peer_id).into());
        }

        Ok(DataEvent::new(peer_id, DataStatus::Deleted))
    }
}

impl<W: WorldTrait> RegisterTrait<W> for Domain {
    fn register(self, _authority: AccountId, wsv: &WorldStateView<W>) -> Result<DataEvent, Error> {
        let domain_id = self.id.clone();

        domain_id
            .name
            .validate_len(wsv.config.ident_length_limits)
            .map_err(Error::Validate)?;
        wsv.domains().insert(domain_id.clone(), self);
        wsv.metrics.domains.inc();

        Ok(DataEvent::new(domain_id, DataStatus::Created))
    }

    fn unregister(domain_id: Self::Id, wsv: &WorldStateView<W>) -> Result<DataEvent, Error> {
        // TODO: Should we fail if no domain found?
        wsv.domains().remove(&domain_id);
        wsv.metrics.domains.dec();

        Ok(DataEvent::new(domain_id, DataStatus::Deleted))
    }
}

#[cfg(feature = "roles")]
impl<W: WorldTrait> RegisterTrait<W> for Role {
    fn register(self, _authority: AccountId, wsv: &WorldStateView<W>) -> Result<DataEvent, Error> {
        let role_id = role.id.clone();

        wsv.world.roles.insert(role_id.clone(), role);
        Ok(DataEvent::new(role_id, DataStatus::Created))
    }
    fn unregister(role_id: Self::Id, wsv: &WorldStateView<W>) -> Result<DataEvent, Error> {
        wsv.world.roles.remove(&role_id);
        for mut domain in wsv.domains().iter_mut() {
            for account in domain.accounts.values_mut() {
                let _ = account.roles.remove(&role_id);
            }
        }

        Ok(DataEvent::new(role_id, DataStatus::Deleted))
    }
}

impl<W: WorldTrait> RegisterTrait<W> for NewAccount {
    fn register(self, _authority: AccountId, wsv: &WorldStateView<W>) -> Result<DataEvent, Error> {
        let account_id = self.id.clone();

        self.id
            .name
            .validate_len(wsv.config.ident_length_limits)
            .map_err(Error::Validate)?;

        match wsv
            .domain_mut(&account_id.domain_id)?
            .accounts
            .entry(account_id.clone())
        {
            Entry::Occupied(_) => {
                return Err(Error::Repetition(
                    InstructionType::Register,
                    IdBox::AccountId(account_id),
                ))
            }
            Entry::Vacant(entry) => {
                let _ = entry.insert(self.into());
            }
        }

        Ok(DataEvent::new(account_id, DataStatus::Created))
    }

    fn unregister(account_id: Self::Id, wsv: &WorldStateView<W>) -> Result<DataEvent, Error> {
        wsv.domain_mut(&account_id.domain_id)?
            .accounts
            .remove(&account_id);

        Ok(DataEvent::new(account_id, DataStatus::Deleted))
    }
}

impl<W: WorldTrait> RegisterTrait<W> for AssetDefinition {
    fn register(self, authority: AccountId, wsv: &WorldStateView<W>) -> Result<DataEvent, Error> {
        let asset_id = self.id.clone();

        asset_id
            .name
            .validate_len(wsv.config.ident_length_limits)
            .map_err(Error::Validate)?;
        let domain_id = asset_id.domain_id.clone();
        let mut domain = wsv.domain_mut(&domain_id)?;
        match domain.asset_definitions.entry(asset_id.clone()) {
            Entry::Vacant(entry) => {
                let _ = entry.insert(AssetDefinitionEntry {
                    definition: self,
                    registered_by: authority,
                });
            }
            Entry::Occupied(entry) => {
                return Err(Error::Repetition(
                    InstructionType::Register,
                    IdBox::AccountId(entry.get().registered_by.clone()),
                ))
            }
        }

        Ok(DataEvent::new(asset_id, DataStatus::Created))
    }
    fn unregister(
        asset_definition_id: Self::Id,
        wsv: &WorldStateView<W>,
    ) -> Result<DataEvent, Error> {
        wsv.domain_mut(&asset_definition_id.domain_id)?
            .asset_definitions
            .remove(&asset_definition_id);
        for mut domain in wsv.domains().iter_mut() {
            for account in domain.accounts.values_mut() {
                let keys = account
                    .assets
                    .iter()
                    .filter(|(asset_id, _asset)| asset_id.definition_id == asset_definition_id)
                    .map(|(asset_id, _asset)| asset_id.clone())
                    .collect::<Vec<_>>();
                for id in &keys {
                    account.assets.remove(id);
                }
            }
        }

        Ok(DataEvent::new(asset_definition_id, DataStatus::Deleted))
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

    /// [`WorldStateView`](super::WorldStateView) configuration.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Configurable)]
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

    use super::*;

    #[tokio::test]
    async fn get_blocks_after_hash() {
        const BLOCK_CNT: usize = 10;

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
            wsv.apply(block).await.unwrap();
        }

        assert!(wsv
            .blocks_after_hash(block_hashes[6])
            .map(|block| block.hash())
            .eq(block_hashes.into_iter().skip(7)));
    }

    #[tokio::test]
    async fn get_blocks_from_height() {
        const BLOCK_CNT: usize = 10;

        let mut block = ValidBlock::new_dummy().commit();
        let wsv = WorldStateView::<World>::default();

        for i in 1..=BLOCK_CNT {
            block.header.height = i as u64;
            let block: VersionedCommittedBlock = block.clone().into();
            wsv.apply(block).await.unwrap();
        }

        assert_eq!(
            &wsv.blocks_from_height(8)
                .map(|block| block.header().height)
                .collect::<Vec<_>>(),
            &[8, 9, 10]
        );
    }
}
