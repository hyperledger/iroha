//! This module provides the [`WorldStateView`] — an in-memory representation of the current blockchain
//! state.
#![allow(
    clippy::new_without_default,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic_side_effects
)]

use std::{convert::Infallible, fmt::Debug, sync::Arc, time::Duration};

use dashmap::{
    mapref::one::{Ref as DashMapRef, RefMut as DashMapRefMut},
    DashSet,
};
use eyre::Result;
use getset::Getters;
use iroha_config::{
    base::proxy::Builder,
    wsv::{Configuration, ConfigurationProxy},
};
use iroha_crypto::HashOf;
use iroha_data_model::prelude::*;
use iroha_logger::prelude::*;
use iroha_primitives::small::SmallVec;

use crate::{
    kura::Kura,
    prelude::*,
    smartcontracts::{
        isi::{query::Error as QueryError, Error},
        wasm, Execute, FindError,
    },
    DomainsMap, Parameters, PeersIds,
};

/// The global entity consisting of `domains`, `triggers` and etc.
/// For example registration of domain, will have this as an ISI target.
#[derive(Debug, Default, Clone, Getters)]
pub struct World {
    /// Iroha config parameters.
    pub(crate) parameters: Parameters,
    /// Identifications of discovered trusted peers.
    pub(crate) trusted_peers_ids: PeersIds,
    /// Registered domains.
    pub(crate) domains: DomainsMap,
    /// Roles. [`Role`] pairs.
    pub(crate) roles: crate::RolesMap,
    /// Permission tokens of an account.
    pub(crate) account_permission_tokens: crate::PermissionTokensMap,
    /// Registered permission token ids.
    pub(crate) permission_token_definitions: crate::PermissionTokenDefinitionsMap,
    /// Triggers
    pub(crate) triggers: TriggerSet,
    /// Chain of *runtime* validators
    pub(crate) validators: crate::validator::Chain,
}

impl World {
    /// Creates an empty `World`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a [`World`] with these [`Domain`]s and trusted [`PeerId`]s.
    pub fn with<D, P>(domains: D, trusted_peers_ids: P) -> Self
    where
        D: IntoIterator<Item = Domain>,
        P: IntoIterator<Item = PeerId>,
    {
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

/// Current state of the blockchain aligned with `Iroha` module.
pub struct WorldStateView {
    /// The world. Contains `domains`, `triggers`, `roles` and other data representing the current state of the blockchain.
    pub world: World,
    /// Configuration of World State View.
    pub config: Configuration,
    /// Blockchain.
    pub block_hashes: std::cell::RefCell<Vec<HashOf<VersionedCommittedBlock>>>,
    /// Hashes of transactions
    pub transactions: DashSet<HashOf<VersionedSignedTransaction>>,
    /// Buffer containing events generated during `WorldStateView::apply`. Renewed on every block commit.
    pub events_buffer: std::cell::RefCell<Vec<Event>>,
    /// Accumulated amount of any asset that has been transacted.
    pub metric_tx_amounts: std::cell::Cell<f64>,
    /// Count of how many mints, transfers and burns have happened.
    pub metric_tx_amounts_counter: std::cell::Cell<u64>,

    /// Reference to Kura subsystem.
    kura: Arc<Kura>,
}

impl Clone for WorldStateView {
    fn clone(&self) -> Self {
        Self {
            world: Clone::clone(&self.world),
            config: self.config,
            block_hashes: self.block_hashes.clone(),
            transactions: self.transactions.clone(),
            events_buffer: std::cell::RefCell::new(Vec::new()),
            metric_tx_amounts: std::cell::Cell::new(0.0_f64),
            metric_tx_amounts_counter: std::cell::Cell::new(0),
            kura: Arc::clone(&self.kura),
        }
    }
}

/// WARNING!!! INTERNAL USE ONLY!!!
impl WorldStateView {
    /// Construct [`WorldStateView`] with given [`World`].
    #[must_use]
    #[inline]
    pub fn new(world: World, kura: Arc<Kura>) -> Self {
        // Added to remain backward compatible with other code primary in tests
        let config = ConfigurationProxy::default()
            .build()
            .expect("Wsv proxy always builds");
        Self::from_configuration(config, world, kura)
    }

    /// Get `Account`'s `Asset`s
    ///
    /// # Errors
    /// Fails if there is no domain or account
    pub fn account_assets(&self, id: &AccountId) -> Result<Vec<Asset>, QueryError> {
        self.map_account(id, |account| account.assets().cloned().collect())
    }

    /// Return a set of all permission tokens granted to this account.
    pub fn account_permission_tokens(&self, account: &Account) -> Vec<PermissionToken> {
        let mut tokens: Vec<PermissionToken> =
            self.account_inherent_permission_tokens(account).collect();
        for role_id in account.roles() {
            if let Some(role) = self.world.roles.get(role_id) {
                tokens.append(&mut role.permissions().cloned().collect());
            }
        }
        tokens
    }

    /// Return a set of permission tokens granted to this account not as part of any role.
    pub fn account_inherent_permission_tokens(
        &self,
        account: &Account,
    ) -> impl ExactSizeIterator<Item = PermissionToken> {
        self.world
            .account_permission_tokens
            .get(account.id())
            .map_or_else(Default::default, |permissions_ref| {
                permissions_ref.value().clone()
            })
            .into_iter()
    }

    /// Return `true` if [`Account`] contains a permission token not associated with any role.
    #[inline]
    pub fn account_contains_inherent_permission(
        &self,
        account: &<Account as Identifiable>::Id,
        token: &PermissionToken,
    ) -> bool {
        self.world
            .account_permission_tokens
            .get_mut(account)
            .map_or(false, |permissions| permissions.contains(token))
    }

    /// Add [`permission`](PermissionToken) to the [`Account`] if the account does not have this permission yet.
    ///
    /// Return a Boolean value indicating whether or not the  [`Account`] already had this permission.
    pub fn add_account_permission(
        &self,
        account: &<Account as Identifiable>::Id,
        token: PermissionToken,
    ) -> bool {
        // `match` here instead of `map_or_else` to avoid cloning token into each closure
        match self.world.account_permission_tokens.get_mut(account) {
            None => {
                let mut permissions = Permissions::new();
                permissions.insert(token);
                self.world
                    .account_permission_tokens
                    .insert(account.clone(), permissions);
                true
            }
            Some(mut permissions) => permissions.insert(token),
        }
    }

    /// Remove a [`permission`](PermissionToken) from the [`Account`] if the account has this permission.
    /// Return a Boolean value indicating whether the [`Account`] had this permission.
    pub fn remove_account_permission(
        &self,
        account: &<Account as Identifiable>::Id,
        token: &PermissionToken,
    ) -> bool {
        self.world
            .account_permission_tokens
            .get_mut(account)
            .map_or(false, |mut permissions| permissions.remove(token))
    }

    fn process_trigger(&self, action: &dyn ActionTrait, event: Event) -> Result<()> {
        let authority = action.technical_account();

        match action.executable() {
            Executable::Instructions(instructions) => {
                self.process_instructions(instructions.iter().cloned(), authority)
            }
            Executable::Wasm(bytes) => {
                let mut wasm_runtime = wasm::RuntimeBuilder::new()
                    .with_configuration(self.config.wasm_runtime_config)
                    .build()?;
                wasm_runtime
                    .execute_trigger(self, authority.clone(), bytes, event)
                    .map_err(Into::into)
            }
        }
    }

    fn process_executable(&self, executable: &Executable, authority: AccountId) -> Result<()> {
        match executable {
            Executable::Instructions(instructions) => {
                self.process_instructions(instructions.iter().cloned(), &authority)
            }
            Executable::Wasm(bytes) => {
                let mut wasm_runtime = wasm::RuntimeBuilder::new()
                    .with_configuration(self.config.wasm_runtime_config)
                    .build()?;
                wasm_runtime
                    .execute(self, authority, bytes)
                    .map_err(Into::into)
            }
        }
    }

    fn process_instructions(
        &self,
        instructions: impl IntoIterator<Item = Instruction>,
        authority: &AccountId,
    ) -> Result<()> {
        instructions.into_iter().try_for_each(|instruction| {
            instruction.execute(authority.clone(), self)?;
            Ok::<_, eyre::Report>(())
        })
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
    pub fn apply(&self, block: &VersionedCommittedBlock) -> Result<()> {
        debug!(?block, "Applying block to wsv");
        let time_event = self.create_time_event(block.as_v1())?;
        self.events_buffer
            .borrow_mut()
            .push(Event::Time(time_event));

        self.execute_transactions(block.as_v1())?;
        debug!("All block transactions successfully executed");

        self.world.triggers.handle_time_event(time_event);

        let res = self
            .world
            .triggers
            .inspect_matched(|action, event| -> Result<()> { self.process_trigger(action, event) });

        if let Err(errors) = res {
            warn!(
                ?errors,
                "The following errors have occurred during trigger execution"
            );
        }

        self.block_hashes.borrow_mut().push(block.hash());

        Ok(())
    }

    /// Get a reference to the latest block. Returns none if genesis is not committed.
    #[inline]
    pub fn latest_block_ref(&self) -> Option<Arc<VersionedCommittedBlock>> {
        self.kura
            .get_block_by_height(self.block_hashes.borrow().len() as u64)
    }

    /// Create time event using previous and current blocks
    fn create_time_event(&self, block: &CommittedBlock) -> Result<TimeEvent> {
        let prev_interval = self
            .latest_block_ref()
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
    fn execute_transactions(&self, block: &CommittedBlock) -> Result<()> {
        // TODO: Should this block panic instead?
        for tx in &block.transactions {
            self.process_executable(
                &tx.as_v1().payload.instructions,
                tx.payload().account_id.clone(),
            )?;
            self.transactions.insert(tx.hash());
        }
        for tx in &block.rejected_transactions {
            self.transactions.insert(tx.hash());
        }

        Ok(())
    }

    /// Get `Asset` by its id
    ///
    /// # Errors
    /// - No such [`Asset`]
    /// - The [`Account`] with which the [`Asset`] is associated doesn't exist.
    /// - The [`Domain`] with which the [`Account`] is associated doesn't exist.
    pub fn asset(&self, id: &<Asset as Identifiable>::Id) -> Result<Asset, QueryError> {
        self.map_account(&id.account_id, |account| -> Result<Asset, QueryError> {
            account
                .asset(id)
                .ok_or_else(|| QueryError::Find(Box::new(FindError::Asset(id.clone()))))
                .map(Clone::clone)
        })?
    }

    /// Get asset or inserts new with `default_asset_value`.
    ///
    /// # Errors
    /// - There is no account with such name.
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
            let asset = Asset::new(id.clone(), default_asset_value.into());
            assert!(account.add_asset(asset.clone()).is_none());

            Ok(AccountEvent::Asset(AssetEvent::Created(asset)))
        })
        .map_err(|err| {
            iroha_logger::warn!(?err);
            err
        })?;

        self.asset(id).map_err(Into::into)
    }

    /// Load all blocks in the block chain from disc and clone them for use.
    #[allow(clippy::expect_used)]
    pub fn all_blocks_by_value(
        &self,
    ) -> impl DoubleEndedIterator<Item = VersionedCommittedBlock> + '_ {
        let block_count = self.block_hashes.borrow().len() as u64;
        (1..=block_count)
            .map(|height| {
                self.kura
                    .get_block_by_height(height)
                    .expect("Failed to load block.")
            })
            .map(|block| VersionedCommittedBlock::clone(&block))
    }

    /// Return a vector of blockchain blocks after the block with the given `hash`
    pub fn block_hashes_after_hash(
        &self,
        hash: Option<HashOf<VersionedCommittedBlock>>,
    ) -> Vec<HashOf<VersionedCommittedBlock>> {
        hash.map_or_else(
            || self.block_hashes.borrow().clone(),
            |block_hash| {
                self.block_hashes
                    .borrow()
                    .iter()
                    .skip_while(|&x| *x != block_hash)
                    .skip(1)
                    .copied()
                    .collect()
            },
        )
    }

    /// The same as [`Self::modify_world_multiple_events`] except closure `f` returns a single [`WorldEvent`].
    ///
    /// # Errors
    /// Forward errors from [`Self::modify_world_multiple_events`]
    pub fn modify_world(
        &self,
        f: impl FnOnce(&World) -> Result<WorldEvent, Error>,
    ) -> Result<(), Error> {
        self.modify_world_multiple_events(move |world| f(world).map(std::iter::once))
    }

    /// Get [`World`] and pass it to `closure` to modify it.
    ///
    /// The function puts events produced by `f` into `events_buffer`.
    /// Events should be produced in the order of expanding scope: from specific to general.
    /// Example: account events before domain events.
    ///
    /// # Errors
    /// Forward errors from `f`
    pub fn modify_world_multiple_events<I: IntoIterator<Item = WorldEvent>>(
        &self,
        f: impl FnOnce(&World) -> Result<I, Error>,
    ) -> Result<(), Error> {
        let world_events = f(&self.world)?;
        let data_events: SmallVec<[DataEvent; 3]> = world_events
            .into_iter()
            .flat_map(WorldEvent::flatten)
            .collect();

        for event in data_events.iter() {
            self.world.triggers.handle_data_event(event.clone());
        }
        self.events_buffer
            .borrow_mut()
            .extend(data_events.into_iter().map(Into::into));

        Ok(())
    }

    /// Returns reference for trusted peer ids
    #[inline]
    pub fn peers_ids(&self) -> &PeersIds {
        &self.world.trusted_peers_ids
    }

    /// Return an iterator over blockchain block hashes starting with the block of the given `height`
    pub fn block_hashes_from_height(&self, height: usize) -> Vec<HashOf<VersionedCommittedBlock>> {
        self.block_hashes
            .borrow()
            .iter()
            .skip(height.saturating_sub(1))
            .copied()
            .collect()
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
        let value = f(domain.value()).map_or_else(
            |_infallible| unreachable!("Returning `Infallible` should not be possible"),
            |value| value,
        );
        Ok(value)
    }

    /// The same as [`Self::modify_domain_multiple_events`] except closure `f` returns a single [`DomainEvent`].
    ///
    /// # Errors
    /// Forward errors from [`Self::modify_domain_multiple_events`]
    pub fn modify_domain(
        &self,
        id: &<Domain as Identifiable>::Id,
        f: impl FnOnce(&mut Domain) -> Result<DomainEvent, Error>,
    ) -> Result<(), Error> {
        self.modify_domain_multiple_events(id, move |domain| f(domain).map(std::iter::once))
    }

    /// Get [`Domain`] and pass it to `closure` to modify it
    ///
    /// # Errors
    /// - If there is no domain
    /// - Forward errors from `f`
    pub fn modify_domain_multiple_events<I: IntoIterator<Item = DomainEvent>>(
        &self,
        id: &<Domain as Identifiable>::Id,
        f: impl FnOnce(&mut Domain) -> Result<I, Error>,
    ) -> Result<(), Error> {
        self.modify_world_multiple_events(|world| {
            let mut domain = world
                .domains
                .get_mut(id)
                .ok_or_else(|| FindError::Domain(id.clone()))?;
            f(domain.value_mut()).map(|events| events.into_iter().map(Into::into))
        })
    }

    /// Get all roles
    #[inline]
    pub fn roles(&self) -> &crate::RolesMap {
        &self.world.roles
    }

    /// Get all permission token ids
    #[inline]
    pub fn permission_token_definitions(&self) -> &crate::PermissionTokenDefinitionsMap {
        &self.world.permission_token_definitions
    }

    /// Construct [`WorldStateView`] with specific [`Configuration`].
    #[inline]
    pub fn from_configuration(config: Configuration, world: World, kura: Arc<Kura>) -> Self {
        Self {
            world,
            config,
            transactions: DashSet::new(),
            block_hashes: std::cell::RefCell::new(Vec::new()),
            events_buffer: std::cell::RefCell::new(Vec::new()),
            metric_tx_amounts: std::cell::Cell::new(0.0_f64),
            metric_tx_amounts_counter: std::cell::Cell::new(0),
            kura,
        }
    }

    /// Returns [`Some`] milliseconds since the genesis block was
    /// committed, or [`None`] if it wasn't.
    #[inline]
    pub fn genesis_timestamp(&self) -> Option<u128> {
        if self.block_hashes.borrow().is_empty() {
            None
        } else {
            let opt = self
                .kura
                .get_block_by_height(1)
                .map(|genesis_block| genesis_block.as_v1().header.timestamp);

            if opt.is_none() {
                error!("Failed to get genesis block from Kura.");
            }
            opt
        }
    }

    /// Check if this [`VersionedSignedTransaction`] is already committed or rejected.
    #[inline]
    pub fn has_transaction(&self, hash: &HashOf<VersionedSignedTransaction>) -> bool {
        self.transactions.contains(hash)
    }

    /// Height of blockchain
    #[inline]
    pub fn height(&self) -> u64 {
        self.block_hashes.borrow().len() as u64
    }

    /// Return the hash of the latest block
    pub fn latest_block_hash(&self) -> Option<HashOf<VersionedCommittedBlock>> {
        self.block_hashes.borrow().iter().nth_back(0).copied()
    }

    /// Return the view change index of the latest block
    pub fn latest_block_view_change_index(&self) -> u64 {
        self.kura
            .get_block_by_height(self.height())
            .map_or(0, |block| block.header().view_change_index)
    }

    /// Return the hash of the block one before the latest block
    pub fn previous_block_hash(&self) -> Option<HashOf<VersionedCommittedBlock>> {
        self.block_hashes.borrow().iter().nth_back(1).copied()
    }

    /// Get `Account` and pass it to closure.
    ///
    /// # Errors
    /// Fails if there is no domain or account
    pub fn map_account<T>(
        &self,
        id: &AccountId,
        f: impl FnOnce(&Account) -> T,
    ) -> Result<T, QueryError> {
        let domain = self.domain(&id.domain_id)?;
        let account = domain.account(id).ok_or(QueryError::Unauthorized)?;
        Ok(f(account))
    }

    /// The same as [`Self::modify_account_multiple_events`] except closure `f` returns a single [`AccountEvent`].
    ///
    /// # Errors
    /// Forward errors from [`Self::modify_account_multiple_events`]
    pub fn modify_account(
        &self,
        id: &AccountId,
        f: impl FnOnce(&mut Account) -> Result<AccountEvent, Error>,
    ) -> Result<(), Error> {
        self.modify_account_multiple_events(id, move |account| f(account).map(std::iter::once))
    }

    /// Get [`Account`] and pass it to `closure` to modify it
    ///
    /// # Errors
    /// - If there is no domain or account
    /// - Forward errors from `f`
    pub fn modify_account_multiple_events<I: IntoIterator<Item = AccountEvent>>(
        &self,
        id: &AccountId,
        f: impl FnOnce(&mut Account) -> Result<I, Error>,
    ) -> Result<(), Error> {
        self.modify_domain_multiple_events(&id.domain_id, |domain| {
            let account = domain
                .account_mut(id)
                .ok_or_else(|| FindError::Account(id.clone()))?;
            f(account).map(|events| events.into_iter().map(DomainEvent::Account))
        })
    }

    /// The same as [`Self::modify_asset_multiple_events`] except closure `f` returns a single [`AssetEvent`].
    ///
    /// # Errors
    /// Forward errors from [`Self::modify_asset_multiple_events`]
    pub fn modify_asset(
        &self,
        id: &<Asset as Identifiable>::Id,
        f: impl FnOnce(&mut Asset) -> Result<AssetEvent, Error>,
    ) -> Result<(), Error> {
        self.modify_asset_multiple_events(id, move |asset| f(asset).map(std::iter::once))
    }

    /// Get [`Asset`] and pass it to `closure` to modify it.
    /// If asset value hits 0 after modification, asset is removed from the [`Account`].
    ///
    /// # Errors
    /// - If there are no such asset or account
    /// - Forward errors from `f`
    ///
    /// # Panics
    /// If removing asset from account failed
    pub fn modify_asset_multiple_events<I: IntoIterator<Item = AssetEvent>>(
        &self,
        id: &<Asset as Identifiable>::Id,
        f: impl FnOnce(&mut Asset) -> Result<I, Error>,
    ) -> Result<(), Error> {
        self.modify_account_multiple_events(&id.account_id, |account| {
            let asset = account
                .asset_mut(id)
                .ok_or_else(|| FindError::Asset(id.clone()))?;

            let events_result = f(asset);
            if asset.value().is_zero_value() {
                assert!(account.remove_asset(id).is_some());
            }

            events_result.map(|events| events.into_iter().map(AccountEvent::Asset))
        })
    }

    /// The same as [`Self::modify_asset_definition_multiple_events`] except closure `f` returns a single [`AssetDefinitionEvent`].
    ///
    /// # Errors
    /// Forward errors from [`Self::modify_asset_definition_entry_multiple_events`]
    pub fn modify_asset_definition_entry(
        &self,
        id: &<AssetDefinition as Identifiable>::Id,
        f: impl FnOnce(&mut AssetDefinitionEntry) -> Result<AssetDefinitionEvent, Error>,
    ) -> Result<(), Error> {
        self.modify_asset_definition_entry_multiple_events(id, move |asset_definition| {
            f(asset_definition).map(std::iter::once)
        })
    }

    /// Get [`AssetDefinitionEntry`] and pass it to `closure` to modify it
    ///
    /// # Errors
    /// - If asset definition entry does not exist
    /// - Forward errors from `f`
    pub fn modify_asset_definition_entry_multiple_events<
        I: IntoIterator<Item = AssetDefinitionEvent>,
    >(
        &self,
        id: &<AssetDefinition as Identifiable>::Id,
        f: impl FnOnce(&mut AssetDefinitionEntry) -> Result<I, Error>,
    ) -> Result<(), Error> {
        self.modify_domain_multiple_events(&id.domain_id, |domain| {
            let asset_definition_entry = domain
                .asset_definition_mut(id)
                .ok_or_else(|| FindError::AssetDefinition(id.clone()))?;
            f(asset_definition_entry)
                .map(|events| events.into_iter().map(DomainEvent::AssetDefinition))
        })
    }

    /// Get all `PeerId`s without an ability to modify them.
    pub fn peers(&self) -> Vec<Peer> {
        let mut vec = self
            .world
            .trusted_peers_ids
            .iter()
            .map(|peer| Peer::new((*peer).clone()))
            .collect::<Vec<Peer>>();
        vec.sort();
        vec
    }

    /// Get all `Parameter`s registered in the world.
    pub fn parameters(&self) -> Vec<Parameter> {
        self.world
            .parameters
            .iter()
            .map(|param| param.clone())
            .collect::<Vec<Parameter>>()
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

    /// Get total amount of [`Asset`].
    ///
    /// # Errors
    /// - Asset definition not found
    pub fn asset_total_amount(
        &self,
        definition_id: &<AssetDefinition as Identifiable>::Id,
    ) -> Result<NumericValue, FindError> {
        self.domain(&definition_id.domain_id)?
            .asset_total_quantity(definition_id)
            .ok_or_else(|| FindError::AssetDefinition(definition_id.clone()))
            .copied()
    }

    /// Increase [`Asset`] total amount by given value
    ///
    /// # Errors
    /// - [`AssetDefinition`], [`Domain`] not found
    /// - Overflow
    pub fn increase_asset_total_amount<I>(
        &self,
        definition_id: &<AssetDefinition as Identifiable>::Id,
        increment: I,
    ) -> Result<(), Error>
    where
        I: iroha_primitives::CheckedOp + Copy,
        NumericValue: From<I> + TryAsMut<I>,
        eyre::Error: From<<NumericValue as TryAsMut<I>>::Error>,
    {
        #[allow(clippy::expect_used)]
        self.modify_domain(&definition_id.domain_id, |domain| {
            let asset_total_amount: &mut I = domain
                .asset_total_quantity_mut(definition_id)
                .expect("Asset total amount not being found is a bug: check `Register<AssetDefinition>` to insert initial total amount")
                .try_as_mut()
                .map_err(eyre::Error::from)
                .map_err(|e| Error::Conversion(e.to_string()))?;
            *asset_total_amount = asset_total_amount
                .checked_add(increment)
                .ok_or(crate::smartcontracts::MathError::Overflow)?;

            Ok(
                DomainEvent::AssetDefinition(
                    AssetDefinitionEvent::TotalQuantityChanged(
                        AssetDefinitionTotalQuantityChanged {
                            asset_definition_id: definition_id.clone(),
                            total_amount: NumericValue::from(*asset_total_amount)
                        }
                    )
                )
            )
        })
    }

    /// Decrease [`Asset`] total amount by given value
    ///
    /// # Errors
    /// - [`AssetDefinition`], [`Domain`] not found
    /// - Not enough quantity
    pub fn decrease_asset_total_amount<I>(
        &self,
        definition_id: &<AssetDefinition as Identifiable>::Id,
        decrement: I,
    ) -> Result<(), Error>
    where
        I: iroha_primitives::CheckedOp + Copy,
        NumericValue: From<I> + TryAsMut<I>,
        eyre::Error: From<<NumericValue as TryAsMut<I>>::Error>,
    {
        #[allow(clippy::expect_used)]
        self.modify_domain(&definition_id.domain_id, |domain| {
            let asset_total_amount: &mut I = domain
                .asset_total_quantity_mut(definition_id)
                .expect("Asset total amount not being found is a bug: check `Register<AssetDefinition>` to insert initial total amount")
                .try_as_mut()
                .map_err(eyre::Error::from)
                .map_err(|e| Error::Conversion(e.to_string()))?;
            *asset_total_amount = asset_total_amount
                .checked_sub(decrement)
                .ok_or(crate::smartcontracts::MathError::NotEnoughQuantity)?;

            Ok(
                DomainEvent::AssetDefinition(
                    AssetDefinitionEvent::TotalQuantityChanged(
                        AssetDefinitionTotalQuantityChanged {
                            asset_definition_id: definition_id.clone(),
                            total_amount: NumericValue::from(*asset_total_amount)
                        }
                    )
                )
            )
        })
    }

    /// Get all transactions
    pub fn transaction_values(&self) -> Vec<TransactionQueryResult> {
        let mut txs = self
            .all_blocks_by_value()
            .flat_map(|block| {
                let block = block.as_v1();
                block
                    .rejected_transactions
                    .iter()
                    .cloned()
                    .map(Box::new)
                    .map(|versioned_rejected_tx| TransactionQueryResult {
                        tx_value: TransactionValue::RejectedTransaction(versioned_rejected_tx),
                        block_hash: Hash::from(block.hash()),
                    })
                    .chain(
                        block
                            .transactions
                            .iter()
                            .cloned()
                            .map(VersionedSignedTransaction::from)
                            .map(Box::new)
                            .map(|versioned_tx| TransactionQueryResult {
                                tx_value: TransactionValue::Transaction(versioned_tx),
                                block_hash: Hash::from(block.hash()),
                            }),
                    )
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        txs.sort();
        txs
    }

    /// Find a [`VersionedSignedTransaction`] by hash.
    pub fn transaction_value_by_hash(
        &self,
        hash: &HashOf<VersionedSignedTransaction>,
    ) -> Option<TransactionValue> {
        self.all_blocks_by_value().find_map(|b| {
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
                        .map(VersionedSignedTransaction::from)
                        .map(Box::new)
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
            .all_blocks_by_value()
            .flat_map(|block_entry| {
                let block = block_entry.as_v1();
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
                            .map(VersionedSignedTransaction::from)
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
    pub fn world(&self) -> &World {
        &self.world
    }

    /// Returns reference for triggers
    #[inline]
    pub fn triggers(&self) -> &TriggerSet {
        &self.world.triggers
    }

    /// The same as [`Self::modify_triggers_multiple_events`] except closure `f` returns a single `TriggerEvent`.
    ///
    /// # Errors
    /// Forward errors from [`Self::modify_triggers_multiple_events`]
    pub fn modify_triggers<F>(&self, f: F) -> Result<(), Error>
    where
        F: FnOnce(&TriggerSet) -> Result<TriggerEvent, Error>,
    {
        self.modify_triggers_multiple_events(move |triggers| f(triggers).map(std::iter::once))
    }

    /// Get [`TriggerSet`] and pass it to `closure` to modify it
    ///
    /// # Errors
    /// Forward errors from `f`
    pub fn modify_triggers_multiple_events<I, F>(&self, f: F) -> Result<(), Error>
    where
        I: IntoIterator<Item = TriggerEvent>,
        F: FnOnce(&TriggerSet) -> Result<I, Error>,
    {
        self.modify_world_multiple_events(|world| {
            f(&world.triggers).map(|events| events.into_iter().map(WorldEvent::Trigger))
        })
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
    pub fn execute_trigger(&self, trigger_id: TriggerId, authority: AccountId) {
        let event = ExecuteTriggerEvent::new(trigger_id, authority);
        self.world
            .triggers
            .handle_execute_trigger_event(event.clone());
        self.events_buffer.borrow_mut().push(event.into());
    }

    /// The same as [`Self::modify_validator_multiple_events`] except closure `f` returns a single [`PermissionValidatorEvent`].
    ///
    /// # Errors
    /// Forward errors from [`Self::modify_validators_multiple_events`]
    pub fn modify_validators<F>(&self, f: F) -> Result<(), Error>
    where
        F: FnOnce(&crate::validator::Chain) -> Result<PermissionValidatorEvent, Error>,
    {
        self.modify_validators_multiple_events(move |chain| f(chain).map(std::iter::once))
    }

    /// Get [`crate::validator::Chain`] and pass it to `closure` to modify it
    ///
    /// # Errors
    /// Forward errors from `f`
    pub fn modify_validators_multiple_events<I, F>(&self, f: F) -> Result<(), Error>
    where
        I: IntoIterator<Item = PermissionValidatorEvent>,
        F: FnOnce(&crate::validator::Chain) -> Result<I, Error>,
    {
        self.modify_world_multiple_events(|world| {
            f(&world.validators)
                .map(|events| events.into_iter().map(WorldEvent::PermissionValidator))
        })
    }

    /// Get constant view to the chain of validators.
    ///
    /// View guarantees that no interior-mutability can be performed.
    pub fn validators_view(&self) -> crate::validator::ChainView {
        self.world.validators.view()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use super::*;

    #[test]
    fn get_block_hashes_after_hash() {
        const BLOCK_CNT: usize = 10;

        let mut block = SignedBlock::new_dummy().commit_unchecked();
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(World::default(), kura);

        let mut block_hashes = vec![];
        for i in 1..=BLOCK_CNT {
            block.header.height = i as u64;
            block.header.previous_block_hash = block_hashes.last().copied();
            let block: VersionedCommittedBlock = block.clone().into();
            block_hashes.push(block.hash());
            wsv.apply(&block).unwrap();
        }

        assert!(wsv
            .block_hashes_after_hash(Some(block_hashes[6]))
            .into_iter()
            .eq(block_hashes.into_iter().skip(7)));
    }

    #[test]
    fn get_blocks_from_height() {
        const BLOCK_CNT: usize = 10;

        let mut block = SignedBlock::new_dummy().commit_unchecked();
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(World::default(), kura.clone());

        for i in 1..=BLOCK_CNT {
            block.header.height = i as u64;
            let block: VersionedCommittedBlock = block.clone().into();
            wsv.apply(&block).unwrap();
            kura.store_block(block);
        }

        assert_eq!(
            &wsv.all_blocks_by_value()
                .skip(7)
                .map(|block| block.header().height)
                .collect::<Vec<_>>(),
            &[8, 9, 10]
        );
    }
}
