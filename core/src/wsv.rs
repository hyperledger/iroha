//! This module provides the [`WorldStateView`] - in-memory representations of the current blockchain
//! state.

use std::{
    convert::Infallible,
    fmt::Debug,
    iter::once,
    ops::{Deref, DerefMut},
    sync::{Arc, RwLock},
    time::Duration,
};

use config::Configuration;
use dashmap::{
    mapref::one::{Ref as DashMapRef, RefMut as DashMapRefMut},
    DashSet,
};
use eyre::Result;
use iroha_crypto::HashOf;
use iroha_data_model::{prelude::*, small::SmallVec};
use iroha_logger::prelude::*;
use iroha_telemetry::metrics::Metrics;
use tokio::task;

use crate::{
    block::Chain,
    event::EventsSender,
    prelude::*,
    smartcontracts::{isi::Error, wasm, Execute, FindError},
    triggers::TriggerSet,
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
        domains: impl IntoIterator<Item = Domain>,
        trusted_peers_ids: impl IntoIterator<Item = PeerId>,
    ) -> Self;
}

/// The global entity consisting of `domains`, `triggers` and etc.
/// For example registration of domain, will have this as an ISI target.
#[derive(Debug, Default, Clone)]
pub struct World {
    /// Iroha parameters.
    pub parameters: Vec<Parameter>,
    /// Identifications of discovered trusted peers.
    pub trusted_peers_ids: PeersIds,
    /// Registered domains.
    pub domains: DomainsMap,
    /// Roles. [`Role`] pairs.
    #[cfg(feature = "roles")]
    pub roles: crate::RolesMap,
    /// Triggers
    pub triggers: TriggerSet,
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
#[derive(Debug)]
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
    /// Events produced in the current block
    events: RwLock<Vec<Event>>,
    /// Transmitter to broadcast [`WorldStateView`]-related events.
    events_sender: Option<EventsSender>,
}

impl<W: WorldTrait + Default> Default for WorldStateView<W> {
    #[inline]
    fn default() -> Self {
        Self::new(W::default())
    }
}

impl<W: WorldTrait + Clone> Clone for WorldStateView<W> {
    #[allow(clippy::expect_used)]
    fn clone(&self) -> Self {
        Self {
            world: Clone::clone(&self.world),
            config: self.config,
            blocks: Arc::clone(&self.blocks),
            transactions: self.transactions.clone(),
            metrics: Arc::clone(&self.metrics),
            new_block_notifier: Arc::clone(&self.new_block_notifier),
            events: RwLock::new(
                self.events
                    .read()
                    .expect("Failed to lock events while cloning")
                    .clone(),
            ),
            events_sender: self.events_sender.clone(),
        }
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
        domains: impl IntoIterator<Item = Domain>,
        trusted_peers_ids: impl IntoIterator<Item = PeerId>,
    ) -> Self {
        let domains = domains
            .into_iter()
            .map(|domain| (domain.id().clone(), domain))
            .collect();
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
    /// Construct [`WorldStateView`] with given [`World`].
    #[must_use]
    #[inline]
    pub fn new(world: W) -> Self {
        Self::from_configuration(Configuration::default(), world)
    }

    /// Add the ability of emitting events to [`WorldStateView`].
    #[must_use]
    pub fn with_events(mut self, events_sender: EventsSender) -> Self {
        self.events_sender = Some(events_sender);
        self
    }

    /// Get `Account`'s `Asset`s
    ///
    /// # Errors
    /// Fails if there is no domain or account
    pub fn account_assets(&self, id: &AccountId) -> Result<Vec<Asset>, FindError> {
        self.map_account(id, |account| account.assets().cloned().collect())
    }

    /// Returns a set of permission tokens granted to this account as part of roles and separately.
    #[allow(clippy::unused_self)]
    pub fn account_permission_tokens(&self, account: &Account) -> Vec<PermissionToken> {
        #[allow(unused_mut)]
        let mut tokens: Vec<PermissionToken> = account.permissions().cloned().collect();

        #[cfg(feature = "roles")]
        for role_id in account.roles() {
            if let Some(role) = self.world.roles.get(role_id) {
                tokens.append(&mut role.permissions().cloned().collect());
            }
        }
        tokens
    }

    fn process_executable(&self, executable: &Executable, authority: &AccountId) -> Result<()> {
        match executable {
            Executable::Instructions(instructions) => {
                instructions.iter().cloned().try_for_each(|instruction| {
                    instruction.execute(authority.clone(), self)?;
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
    /// Instructions** to `self`.
    ///
    /// Order of execution:
    /// 1) Transactions
    /// 2) Triggers
    ///
    /// # Errors
    ///
    /// - (RARE) if applying transaction after validation fails.  This
    /// scenario is rare, because the `tx` validation implies applying
    /// instructions directly to a clone of the wsv.  If this happens,
    /// you likely have data corruption.
    /// - If trigger execution fails
    /// - If timestamp conversion to `u64` fails
    #[iroha_futures::telemetry_future]
    #[log(skip(self, block))]
    #[allow(clippy::expect_used)]
    pub async fn apply(&self, block: VersionedCommittedBlock) -> Result<()> {
        let time_event = Event::Time(self.create_time_event(block.as_v1())?);
        self.produce_events(once(time_event.clone()));

        self.execute_transactions(block.as_v1()).await?;

        let events: Vec<Event> = self
            .events
            .write()
            .expect("Failed to lock events while applying block")
            .drain(..)
            .collect();

        let triggers = self.world.triggers.find_matching(
            events
                .iter()
                .chain(&block.as_v1().event_recommendations)
                .chain(once(&time_event)),
        );
        self.execute_triggers(triggers).await?;

        self.blocks.push(block);
        self.block_commit_metrics_update_callback();
        self.new_block_notifier.send_replace(());

        // TODO: On block commit triggers
        // TODO: Pass self.events to the next block

        Ok(())
    }

    /// Create time event using previous and current blocks
    fn create_time_event(&self, block: &CommittedBlock) -> Result<TimeEvent> {
        let prev_interval = self
            .blocks
            .latest_block()
            .map(|latest_block| {
                let header = latest_block.header();
                header.timestamp.try_into().map(|since| {
                    TimeInterval::new(
                        Duration::from_millis(since),
                        Duration::from_millis(header.consensus_estimation),
                    )
                })
            })
            .transpose()?;

        let interval = TimeInterval::new(
            Duration::from_millis(block.header.timestamp.try_into()?),
            Duration::from_millis(block.header.consensus_estimation),
        );

        Ok(TimeEvent::new(prev_interval, interval))
    }

    /// Execute `block` transactions and store their hashes as well as
    /// `rejected_transactions` hashes
    ///
    /// # Errors
    /// Fails if transaction instruction execution fails
    async fn execute_transactions(&self, block: &CommittedBlock) -> Result<()> {
        // TODO: Should this block panic instead?
        for tx in &block.transactions {
            self.process_executable(&tx.as_v1().payload.instructions, &tx.payload().account_id)?;
            self.transactions.insert(tx.hash());
            task::yield_now().await;
        }
        for tx in &block.rejected_transactions {
            self.transactions.insert(tx.hash());
        }

        Ok(())
    }

    /// Execute `triggers` and apply them to `self`
    ///
    /// # Errors
    /// Fails if trigger execution fails
    async fn execute_triggers<T, I>(&self, triggers: T) -> Result<()>
    where
        T: IntoIterator<Item = Action, IntoIter = I> + Send,
        I: Iterator<Item = Action> + Send,
    {
        // TODO: Validate the trigger executables as well as the technical account.
        for trigger in triggers {
            self.process_executable(&trigger.executable, &trigger.technical_account)?;
            task::yield_now().await;
        }

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
                .asset(id)
                .ok_or_else(|| FindError::Asset(id.clone()))
                .map(Clone::clone)
        })?
    }

    /// Send [`Event`]s to known subscribers.
    fn produce_events<E>(&self, events: E)
    where
        E: IntoIterator<Item = Event>,
    {
        let events_sender = if let Some(sender) = &self.events_sender {
            sender
        } else {
            return warn!("wsv does not equip an events sender");
        };

        for event in events {
            drop(events_sender.send(event))
        }
    }

    /// Tries to get asset or inserts new with `default_asset_value`.
    ///
    /// # Errors
    /// Fails if there is no account with such name.
    #[allow(clippy::missing_panics_doc)]
    pub fn asset_or_insert(
        &self,
        id: &<Asset as Identifiable>::Id,
        default_asset_value: impl Into<AssetValue>,
    ) -> Result<Asset, Error> {
        if let Ok(asset) = self.asset(id) {
            return Ok(asset);
        }

        // This function is strictly infallible.
        self.modify_account(&id.account_id, |account| {
            assert!(account
                .add_asset(Asset::new(id.clone(), default_asset_value.into()))
                .is_none());

            Ok(AccountEvent::Asset(AssetEvent::Created(id.clone())))
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

    // TODO: There could be just this one method `blocks` instead of
    // `blocks_from_height` and `blocks_after_height`. Also, this
    // method would return references instead of cloning blockchain
    // but comes with the risk of deadlock if consumer of the iterator
    // stores references to blocks
    /// Returns iterator over blockchain blocks
    ///
    /// **Locking behaviour**: Holding references to blocks stored in the blockchain can induce
    /// deadlock. This limitation is imposed by the fact that blockchain is backed by [`dashmap::DashMap`]
    #[inline]
    pub fn blocks(&self) -> crate::block::ChainIterator {
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

    /// Get `World` and pass it to closure to modify it
    ///
    /// Produces events in the `WSV` that are produced by `f` during execution.
    /// Events are produced in the order of expanding scope: from specific to general.
    /// Example: account events before domain events.
    ///
    /// # Errors
    /// Fails if `f` fails
    ///
    /// # Panics
    /// (Rare) Panics if can't lock `self.events` for writing
    #[allow(clippy::unwrap_in_result, clippy::expect_used)]
    pub fn modify_world(
        &self,
        f: impl FnOnce(&World) -> Result<WorldEvent, Error>,
    ) -> Result<(), Error> {
        let mut cur_events: SmallVec<[Event; 3]> = SmallVec::new();
        let event = f(&self.world)?;

        match event {
            WorldEvent::Domain(domain_event) => {
                match &domain_event {
                    DomainEvent::Account(account_event) => {
                        if let AccountEvent::Asset(asset_event) = account_event {
                            cur_events.push(DataEvent::Asset(asset_event.clone()).into())
                        }
                        cur_events.push(DataEvent::Account(account_event.clone()).into());
                    }
                    DomainEvent::AssetDefinition(asset_definition_event) => cur_events
                        .push(DataEvent::AssetDefinition(asset_definition_event.clone()).into()),
                    _ => (),
                }
                cur_events.push(DataEvent::Domain(domain_event).into());
            }
            WorldEvent::Peer(peer_event) => cur_events.push(DataEvent::Peer(peer_event).into()),
            #[cfg(feature = "roles")]
            WorldEvent::Role(role_event) => cur_events.push(DataEvent::Role(role_event).into()),
            WorldEvent::Trigger(trigger_event) => {
                cur_events.push(DataEvent::Trigger(trigger_event).into())
            }
        }

        self.produce_events(cur_events.iter().cloned());
        self.events
            .write()
            .expect("Failed to lock events while modifying world")
            .extend(cur_events);
        Ok(())
    }

    /// Returns reference for trusted peer ids
    #[inline]
    pub fn trusted_peers_ids(&self) -> &PeersIds {
        &self.world.trusted_peers_ids
    }

    /// Returns iterator over blockchain blocks starting with the block of the given `height`
    pub fn blocks_from_height(
        &self,
        height: usize,
    ) -> impl Iterator<Item = VersionedCommittedBlock> + '_ {
        self.blocks
            .iter()
            .skip(height.saturating_sub(1))
            .map(|block_entry| block_entry.value().clone())
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
    #[inline]
    pub fn domains(&self) -> &DomainsMap {
        &self.world.domains
    }

    /// Get `Domain` and pass it to closure.
    ///
    /// # Errors
    /// Fails if there is no domain
    #[allow(clippy::panic_in_result_fn)]
    pub fn map_domain<T>(
        &self,
        id: &<Domain as Identifiable>::Id,
        f: impl FnOnce(&Domain) -> Result<T, Infallible>,
    ) -> Result<T, FindError> {
        let domain = self.domain(id)?;
        let value = match f(domain.value()) {
            Ok(value) => value,
            Err(_) => unreachable!("Returning `Infallible` should not be possible"),
        };
        Ok(value)
    }

    /// Get `Domain` and pass it to closure to modify it
    ///
    /// # Errors
    /// Fails if there is no domain
    pub fn modify_domain(
        &self,
        id: &<Domain as Identifiable>::Id,
        f: impl FnOnce(&mut Domain) -> Result<DomainEvent, Error>,
    ) -> Result<(), Error> {
        self.modify_world(|world| {
            let mut domain = world
                .domains
                .get_mut(id)
                .ok_or_else(|| FindError::Domain(id.clone()))?;
            f(domain.value_mut()).map(Into::into)
        })
    }

    /// Construct [`WorldStateView`] with specific [`Configuration`].
    #[inline]
    pub fn from_configuration(config: Configuration, world: W) -> Self {
        let (new_block_notifier, _) = tokio::sync::watch::channel(());

        Self {
            world,
            config,
            transactions: DashSet::new(),
            blocks: Arc::new(Chain::new()),
            metrics: Arc::new(Metrics::default()),
            new_block_notifier: Arc::new(new_block_notifier),
            events: RwLock::new(Vec::new()),
            events_sender: None,
        }
    }

    /// Returns [`Some`] milliseconds since the genesis block was
    /// committed, or [`None`] if it wasn't.
    #[inline]
    pub fn genesis_timestamp(&self) -> Option<u128> {
        self.blocks
            .iter()
            .next()
            .map(|val| val.as_v1().header.timestamp)
    }

    /// Check if this [`VersionedTransaction`] is already committed or rejected.
    #[inline]
    pub fn has_transaction(&self, hash: &HashOf<VersionedTransaction>) -> bool {
        self.transactions.contains(hash)
    }

    /// Height of blockchain
    #[inline]
    pub fn height(&self) -> u64 {
        self.metrics.block_height.get()
    }

    /// Initializes WSV with the blocks from block storage.
    #[iroha_futures::telemetry_future]
    pub async fn init(&self, blocks: Vec<VersionedCommittedBlock>) {
        for block in blocks {
            #[allow(clippy::panic)]
            if let Err(error) = self.apply(block).await {
                error!(%error, "Initialization of WSV failed");
                panic!("WSV initialization failed");
            }
        }
    }

    /// Hash of latest block
    pub fn latest_block_hash(&self) -> HashOf<VersionedCommittedBlock> {
        self.blocks
            .latest_block()
            .map_or(HashOf::from_hash(Hash([0_u8; 32])), |block| {
                block.value().hash()
            })
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
            .account(id)
            .ok_or_else(|| FindError::Account(id.clone()))?;
        Ok(f(account))
    }

    /// Get `Account` and pass it to closure to modify it
    ///
    /// # Errors
    /// Fails if there is no domain or account
    pub fn modify_account(
        &self,
        id: &AccountId,
        f: impl FnOnce(&mut Account) -> Result<AccountEvent, Error>,
    ) -> Result<(), Error> {
        self.modify_domain(&id.domain_id, |domain| {
            let account = domain
                .account_mut(id)
                .ok_or_else(|| FindError::Account(id.clone()))?;
            f(account).map(DomainEvent::Account)
        })
    }

    /// Get `Asset` by its id
    ///
    /// # Errors
    /// Fails if there are no such asset or account
    #[allow(clippy::missing_panics_doc)]
    pub fn modify_asset(
        &self,
        id: &<Asset as Identifiable>::Id,
        f: impl FnOnce(&mut Asset) -> Result<AssetEvent, Error>,
    ) -> Result<(), Error> {
        self.modify_account(&id.account_id, |account| {
            let asset = account
                .asset_mut(id)
                .ok_or_else(|| FindError::Asset(id.clone()))?;

            let event_result = f(asset);
            if asset.value().is_zero_value() {
                assert!(account.remove_asset(id).is_some());
            }

            event_result.map(AccountEvent::Asset)
        })
    }

    /// Get `AssetDefinitionEntry` with an ability to modify it.
    ///
    /// # Errors
    /// Fails if asset definition entry does not exist
    pub fn modify_asset_definition_entry(
        &self,
        id: &<AssetDefinition as Identifiable>::Id,
        f: impl FnOnce(&mut AssetDefinitionEntry) -> Result<AssetDefinitionEvent, Error>,
    ) -> Result<(), Error> {
        self.modify_domain(&id.domain_id, |domain| {
            let asset_definition_entry = domain
                .asset_definition_mut(id)
                .ok_or_else(|| FindError::AssetDefinition(id.clone()))?;
            f(asset_definition_entry).map(DomainEvent::AssetDefinition)
        })
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
        asset_id: &<AssetDefinition as Identifiable>::Id,
    ) -> Result<AssetDefinitionEntry, FindError> {
        self.domain(&asset_id.domain_id)?
            .asset_definition(asset_id)
            .ok_or_else(|| FindError::AssetDefinition(asset_id.clone()))
            .map(Clone::clone)
    }

    /// Returns receiving end of the mpsc channel through which
    /// subscribers are notified when new block is added to the
    /// blockchain(after block validation).
    #[inline]
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

    /// Get an immutable view of the `World`.
    #[must_use]
    #[inline]
    pub fn world(&self) -> &W {
        &self.world
    }

    /// Get triggers set and modify it with `f`
    ///
    /// Produces trigger event from `f`
    ///
    /// # Errors
    /// Throws up `f` errors
    pub fn modify_triggers<F>(&self, f: F) -> Result<(), Error>
    where
        F: FnOnce(&TriggerSet) -> Result<TriggerEvent, Error>,
    {
        self.modify_world(|world| f(&world.triggers).map(WorldEvent::Trigger))
    }

    /// Execute trigger with `trigger_id` as id and `authority` as owner
    ///
    /// Produces [`ExecuteTriggerEvent`].
    ///
    /// Trigger execution time:
    /// - If this method is called by ISI inside *transaction*,
    /// then *trigger* will be executed on the **current** block
    /// - If this method is called by ISI inside *trigger*,
    /// then *trigger* will be executed on the **next** block
    ///
    /// # Panics
    /// (Rare) Panics if can't lock `self.events` for writing
    #[allow(clippy::expect_used)]
    pub fn execute_trigger(&self, trigger_id: TriggerId, authority: AccountId) {
        let event: Event = ExecuteTriggerEvent::new(trigger_id, authority).into();
        self.events
            .write()
            .expect("Failed to lock events while executing trigger")
            .push(event.clone());
        self.produce_events(once(event));
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
