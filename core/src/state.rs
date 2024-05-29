//! This module provides the [`State`] — an in-memory representation of the current blockchain state.
use std::{borrow::Borrow, collections::BTreeSet, marker::PhantomData, sync::Arc, time::Duration};

use eyre::Result;
use iroha_config::parameters::actual::ChainWide as Config;
use iroha_crypto::HashOf;
use iroha_data_model::{
    account::AccountId,
    block::SignedBlock,
    events::{
        pipeline::BlockEvent,
        time::TimeEvent,
        trigger_completed::{TriggerCompletedEvent, TriggerCompletedOutcome},
        EventBox,
    },
    executor::ExecutorDataModel,
    isi::error::{InstructionExecutionError as Error, MathError},
    parameter::{Parameter, ParameterValueBox},
    permission::Permissions,
    prelude::*,
    query::error::{FindError, QueryExecutionFail},
    role::RoleId,
};
use iroha_logger::prelude::*;
use iroha_primitives::{must_use::MustUse, numeric::Numeric, small::SmallVec};
use parking_lot::Mutex;
use range_bounds::RoleIdByAccountBounds;
use serde::{
    de::{DeserializeSeed, MapAccess, Visitor},
    Deserializer, Serialize,
};
use storage::{
    cell::{Block as CellBlock, Cell, Transaction as CellTransaction, View as CellView},
    storage::{
        Block as StorageBlock, RangeIter, Storage, StorageReadOnly,
        Transaction as StorageTransaction, View as StorageView,
    },
};

use crate::{
    block::CommittedBlock,
    executor::Executor,
    kura::Kura,
    query::store::LiveQueryStoreHandle,
    role::RoleIdWithOwner,
    smartcontracts::{
        triggers::{
            self,
            set::{
                Set as TriggerSet, SetBlock as TriggerSetBlock, SetReadOnly as TriggerSetReadOnly,
                SetTransaction as TriggerSetTransaction, SetView as TriggerSetView,
            },
            specialized::LoadedActionTrait,
        },
        wasm, Execute,
    },
    tx::TransactionExecutor,
    Parameters, PeersIds,
};

/// The global entity consisting of `domains`, `triggers` and etc.
/// For example registration of domain, will have this as an ISI target.
#[derive(Default, Serialize)]
pub struct World {
    /// Iroha config parameters.
    pub(crate) parameters: Cell<Parameters>,
    /// Identifications of discovered trusted peers.
    pub(crate) trusted_peers_ids: Cell<PeersIds>,
    /// Registered domains.
    pub(crate) domains: Storage<DomainId, Domain>,
    /// Roles. [`Role`] pairs.
    pub(crate) roles: Storage<RoleId, Role>,
    /// Permission tokens of an account.
    pub(crate) account_permissions: Storage<AccountId, Permissions>,
    /// Roles of an account.
    pub(crate) account_roles: Storage<RoleIdWithOwner, ()>,
    /// Triggers
    pub(crate) triggers: TriggerSet,
    /// Runtime Executor
    pub(crate) executor: Cell<Executor>,
    /// Executor-defined data model
    pub(crate) executor_data_model: Cell<ExecutorDataModel>,
}

/// Struct for block's aggregated changes
pub struct WorldBlock<'world> {
    /// Iroha config parameters.
    pub(crate) parameters: CellBlock<'world, Parameters>,
    /// Identifications of discovered trusted peers.
    pub(crate) trusted_peers_ids: CellBlock<'world, PeersIds>,
    /// Registered domains.
    pub(crate) domains: StorageBlock<'world, DomainId, Domain>,
    /// Roles. [`Role`] pairs.
    pub(crate) roles: StorageBlock<'world, RoleId, Role>,
    /// Permission tokens of an account.
    pub(crate) account_permissions: StorageBlock<'world, AccountId, Permissions>,
    /// Roles of an account.
    pub(crate) account_roles: StorageBlock<'world, RoleIdWithOwner, ()>,
    /// Triggers
    pub(crate) triggers: TriggerSetBlock<'world>,
    /// Runtime Executor
    pub(crate) executor: CellBlock<'world, Executor>,
    /// Executor-defined data model
    pub(crate) executor_data_model: CellBlock<'world, ExecutorDataModel>,
    /// Events produced during execution of block
    events_buffer: Vec<EventBox>,
}

/// Struct for single transaction's aggregated changes
pub struct WorldTransaction<'block, 'world> {
    /// Iroha config parameters.
    pub(crate) parameters: CellTransaction<'block, 'world, Parameters>,
    /// Identifications of discovered trusted peers.
    pub(crate) trusted_peers_ids: CellTransaction<'block, 'world, PeersIds>,
    /// Registered domains.
    pub(crate) domains: StorageTransaction<'block, 'world, DomainId, Domain>,
    /// Roles. [`Role`] pairs.
    pub(crate) roles: StorageTransaction<'block, 'world, RoleId, Role>,
    /// Permission tokens of an account.
    pub(crate) account_permissions: StorageTransaction<'block, 'world, AccountId, Permissions>,
    /// Roles of an account.
    pub(crate) account_roles: StorageTransaction<'block, 'world, RoleIdWithOwner, ()>,
    /// Triggers
    pub(crate) triggers: TriggerSetTransaction<'block, 'world>,
    /// Runtime Executor
    pub(crate) executor: CellTransaction<'block, 'world, Executor>,
    /// Executor-defined data model
    pub(crate) executor_data_model: CellTransaction<'block, 'world, ExecutorDataModel>,
    /// Events produced during execution of a transaction
    events_buffer: TransactionEventBuffer<'block>,
}

/// Wrapper for event's buffer to apply transaction rollback
struct TransactionEventBuffer<'block> {
    /// Events produced during execution of block
    events_buffer: &'block mut Vec<EventBox>,
    /// Number of events produced during execution current transaction
    events_created_in_transaction: usize,
}

/// Consistent point in time view of the [`World`]
pub struct WorldView<'world> {
    /// Iroha config parameters.
    pub(crate) parameters: CellView<'world, Parameters>,
    /// Identifications of discovered trusted peers.
    pub(crate) trusted_peers_ids: CellView<'world, PeersIds>,
    /// Registered domains.
    pub(crate) domains: StorageView<'world, DomainId, Domain>,
    /// Roles. [`Role`] pairs.
    pub(crate) roles: StorageView<'world, RoleId, Role>,
    /// Permission tokens of an account.
    pub(crate) account_permissions: StorageView<'world, AccountId, Permissions>,
    /// Roles of an account.
    pub(crate) account_roles: StorageView<'world, RoleIdWithOwner, ()>,
    /// Triggers
    pub(crate) triggers: TriggerSetView<'world>,
    /// Runtime Executor
    pub(crate) executor: CellView<'world, Executor>,
    /// Executor-defined data model
    pub(crate) executor_data_model: CellView<'world, ExecutorDataModel>,
}

/// Current state of the blockchain
#[derive(Serialize)]
pub struct State {
    /// The world. Contains `domains`, `triggers`, `roles` and other data representing the current state of the blockchain.
    pub world: World,
    /// Configuration of World State View.
    pub config: Cell<Config>,
    /// Blockchain.
    // TODO: Cell is redundant here since block_hashes is very easy to rollback by just popping the last element
    pub block_hashes: Cell<Vec<HashOf<SignedBlock>>>,
    /// Hashes of transactions mapped onto block height where they stored
    pub transactions: Storage<HashOf<SignedTransaction>, u64>,
    /// Engine for WASM [`Runtime`](wasm::Runtime) to execute triggers.
    #[serde(skip)]
    pub engine: wasmtime::Engine,

    /// Reference to Kura subsystem.
    #[serde(skip)]
    kura: Arc<Kura>,
    /// Handle to the [`LiveQueryStore`].
    #[serde(skip)]
    pub query_handle: LiveQueryStoreHandle,
    /// Temporary metrics buffer of amounts of any asset that has been transacted.
    /// TODO: this should be done through events
    #[serde(skip)]
    pub new_tx_amounts: Arc<Mutex<Vec<f64>>>,
}

/// Struct for block's aggregated changes
pub struct StateBlock<'state> {
    /// The world. Contains `domains`, `triggers`, `roles` and other data representing the current state of the blockchain.
    pub world: WorldBlock<'state>,
    /// Configuration of World State View.
    pub config: CellBlock<'state, Config>,
    /// Blockchain.
    pub block_hashes: CellBlock<'state, Vec<HashOf<SignedBlock>>>,
    /// Hashes of transactions mapped onto block height where they stored
    pub transactions: StorageBlock<'state, HashOf<SignedTransaction>, u64>,
    /// Engine for WASM [`Runtime`](wasm::Runtime) to execute triggers.
    pub engine: &'state wasmtime::Engine,

    /// Reference to Kura subsystem.
    kura: &'state Kura,
    /// Handle to the [`LiveQueryStore`].
    pub query_handle: &'state LiveQueryStoreHandle,
    /// Temporary metrics buffer of amounts of any asset that has been transacted.
    /// TODO: this should be done through events
    pub new_tx_amounts: &'state Mutex<Vec<f64>>,
}

/// Struct for single transaction's aggregated changes
pub struct StateTransaction<'block, 'state> {
    /// The world. Contains `domains`, `triggers`, `roles` and other data representing the current state of the blockchain.
    pub world: WorldTransaction<'block, 'state>,
    /// Configuration of World State View.
    pub config: CellTransaction<'block, 'state, Config>,
    /// Blockchain.
    pub block_hashes: CellTransaction<'block, 'state, Vec<HashOf<SignedBlock>>>,
    /// Hashes of transactions mapped onto block height where they stored
    pub transactions: StorageTransaction<'block, 'state, HashOf<SignedTransaction>, u64>,
    /// Engine for WASM [`Runtime`](wasm::Runtime) to execute triggers.
    pub engine: &'state wasmtime::Engine,

    /// Reference to Kura subsystem.
    kura: &'state Kura,
    /// Handle to the [`LiveQueryStore`].
    pub query_handle: &'state LiveQueryStoreHandle,
    /// Temporary metrics buffer of amounts of any asset that has been transacted.
    /// TODO: this should be done through events
    pub new_tx_amounts: &'state Mutex<Vec<f64>>,
}

/// Consistent point in time view of the [`State`]
pub struct StateView<'state> {
    /// The world. Contains `domains`, `triggers`, `roles` and other data representing the current state of the blockchain.
    pub world: WorldView<'state>,
    /// Configuration of World State View.
    pub config: CellView<'state, Config>,
    /// Blockchain.
    pub block_hashes: CellView<'state, Vec<HashOf<SignedBlock>>>,
    /// Hashes of transactions mapped onto block height where they stored
    pub transactions: StorageView<'state, HashOf<SignedTransaction>, u64>,
    /// Engine for WASM [`Runtime`](wasm::Runtime) to execute triggers.
    pub engine: &'state wasmtime::Engine,

    /// Reference to Kura subsystem.
    kura: &'state Kura,
    /// Handle to the [`LiveQueryStore`].
    pub query_handle: &'state LiveQueryStoreHandle,
    /// Temporary metrics buffer of amounts of any asset that has been transacted.
    /// TODO: this should be done through events
    pub new_tx_amounts: &'state Mutex<Vec<f64>>,
}

impl World {
    /// Creates an empty `World`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a [`World`] with these [`Domain`]s and trusted [`PeerId`]s.
    pub fn with<D>(domains: D, trusted_peers_ids: PeersIds) -> Self
    where
        D: IntoIterator<Item = Domain>,
    {
        let domains = domains
            .into_iter()
            .map(|domain| (domain.id().clone(), domain))
            .collect();
        World {
            trusted_peers_ids: Cell::new(trusted_peers_ids),
            domains,
            ..World::new()
        }
    }

    /// Create struct to apply block's changes
    pub fn block(&self) -> WorldBlock {
        WorldBlock {
            parameters: self.parameters.block(),
            trusted_peers_ids: self.trusted_peers_ids.block(),
            domains: self.domains.block(),
            roles: self.roles.block(),
            account_permissions: self.account_permissions.block(),
            account_roles: self.account_roles.block(),
            triggers: self.triggers.block(),
            executor: self.executor.block(),
            executor_data_model: self.executor_data_model.block(),
            events_buffer: Vec::new(),
        }
    }

    /// Create struct to apply block's changes while reverting changes made in the latest block
    pub fn block_and_revert(&self) -> WorldBlock {
        WorldBlock {
            parameters: self.parameters.block_and_revert(),
            trusted_peers_ids: self.trusted_peers_ids.block_and_revert(),
            domains: self.domains.block_and_revert(),
            roles: self.roles.block_and_revert(),
            account_permissions: self.account_permissions.block_and_revert(),
            account_roles: self.account_roles.block_and_revert(),
            triggers: self.triggers.block_and_revert(),
            executor: self.executor.block_and_revert(),
            executor_data_model: self.executor_data_model.block_and_revert(),
            events_buffer: Vec::new(),
        }
    }

    /// Create point in time view of the [`World`]
    pub fn view(&self) -> WorldView {
        WorldView {
            parameters: self.parameters.view(),
            trusted_peers_ids: self.trusted_peers_ids.view(),
            domains: self.domains.view(),
            roles: self.roles.view(),
            account_permissions: self.account_permissions.view(),
            account_roles: self.account_roles.view(),
            triggers: self.triggers.view(),
            executor: self.executor.view(),
            executor_data_model: self.executor_data_model.view(),
        }
    }
}

/// Trait to perform read-only operations on [`WorldBlock`], [`WorldTransaction`] and [`WorldView`]
#[allow(missing_docs)]
pub trait WorldReadOnly {
    fn parameters(&self) -> &Parameters;
    fn trusted_peers_ids(&self) -> &PeersIds;
    fn domains(&self) -> &impl StorageReadOnly<DomainId, Domain>;
    fn roles(&self) -> &impl StorageReadOnly<RoleId, Role>;
    fn account_permissions(&self) -> &impl StorageReadOnly<AccountId, Permissions>;
    fn account_roles(&self) -> &impl StorageReadOnly<RoleIdWithOwner, ()>;
    fn triggers(&self) -> &impl TriggerSetReadOnly;
    fn executor(&self) -> &Executor;
    fn executor_data_model(&self) -> &ExecutorDataModel;

    // Domain-related methods

    /// Get `Domain` without an ability to modify it.
    ///
    /// # Errors
    /// Fails if there is no domain
    fn domain(&self, id: &DomainId) -> Result<&Domain, FindError> {
        let domain = self
            .domains()
            .get(id)
            .ok_or_else(|| FindError::Domain(id.clone()))?;
        Ok(domain)
    }

    /// Get `Domain` and pass it to closure.
    ///
    /// # Errors
    /// Fails if there is no domain
    fn map_domain<'slf, T>(
        &'slf self,
        id: &DomainId,
        f: impl FnOnce(&'slf Domain) -> T,
    ) -> Result<T, FindError> {
        let domain = self.domain(id)?;
        let value = f(domain);
        Ok(value)
    }

    /// Returns reference for domains map
    #[inline]
    fn domains_iter(&self) -> impl Iterator<Item = &Domain> {
        self.domains().iter().map(|(_, domain)| domain)
    }

    // Account-related methods

    /// Get `Account` and return reference to it.
    ///
    /// # Errors
    /// Fails if there is no domain or account
    fn account(&self, id: &AccountId) -> Result<&Account, FindError> {
        self.domain(&id.domain_id).and_then(|domain| {
            domain
                .accounts
                .get(id)
                .ok_or_else(|| FindError::Account(id.clone()))
        })
    }

    /// Get `Account` and pass it to closure.
    ///
    /// # Errors
    /// Fails if there is no domain or account
    fn map_account<'slf, T>(
        &'slf self,
        id: &AccountId,
        f: impl FnOnce(&'slf Account) -> T,
    ) -> Result<T, QueryExecutionFail> {
        let domain = self.domain(&id.domain_id)?;
        let account = domain
            .accounts
            .get(id)
            .ok_or(FindError::Account(id.clone()))?;
        Ok(f(account))
    }

    /// Get `Account`'s `Asset`s
    ///
    /// # Errors
    /// Fails if there is no domain or account
    fn account_assets(
        &self,
        id: &AccountId,
    ) -> Result<std::collections::btree_map::Values<'_, AssetId, Asset>, QueryExecutionFail> {
        self.map_account(id, |account| account.assets.values())
    }

    /// Get [`Account`]'s [`RoleId`]s
    // NOTE: have to use concreate type because don't want to capture lifetme of `id`
    #[allow(clippy::type_complexity)]
    fn account_roles_iter<'slf>(
        &'slf self,
        id: &AccountId,
    ) -> core::iter::Map<
        RangeIter<'slf, RoleIdWithOwner, ()>,
        fn((&'slf RoleIdWithOwner, &'slf ())) -> &'slf RoleId,
    > {
        self.account_roles()
            .range(RoleIdByAccountBounds::new(id))
            .map(|(role, ())| &role.role_id)
    }

    /// Return a set of all permission tokens granted to this account.
    ///
    /// # Errors
    ///
    /// - if `account_id` is not found in `self`
    fn account_permissions_iter<'slf>(
        &'slf self,
        account_id: &AccountId,
    ) -> Result<std::collections::btree_set::IntoIter<&'slf Permission>, FindError> {
        self.account(account_id)?;

        let mut tokens = self
            .account_inherent_permissions(account_id)
            .collect::<BTreeSet<_>>();

        for role_id in self.account_roles_iter(account_id) {
            if let Some(role) = self.roles().get(role_id) {
                tokens.extend(role.permissions.iter());
            }
        }

        Ok(tokens.into_iter())
    }

    /// Return a set of permission tokens granted to this account not as part of any role.
    ///
    /// # Errors
    ///
    /// - `account_id` is not found in `self.world`.
    fn account_inherent_permissions<'slf>(
        &'slf self,
        account_id: &AccountId,
    ) -> std::collections::btree_set::Iter<'slf, Permission> {
        self.account_permissions()
            .get(account_id)
            .map_or_else(Default::default, std::collections::BTreeSet::iter)
    }

    /// Return `true` if [`Account`] contains a permission token not associated with any role.
    #[inline]
    fn account_contains_inherent_permission(
        &self,
        account: &AccountId,
        token: &Permission,
    ) -> bool {
        self.account_permissions()
            .get(account)
            .map_or(false, |permissions| permissions.contains(token))
    }

    // Asset-related methods

    /// Get `Asset` by its id
    ///
    /// # Errors
    /// - No such [`Asset`]
    /// - The [`Account`] with which the [`Asset`] is associated doesn't exist.
    /// - The [`Domain`] with which the [`Account`] is associated doesn't exist.
    fn asset(&self, id: &AssetId) -> Result<Asset, QueryExecutionFail> {
        self.map_account(
            &id.account_id,
            |account| -> Result<Asset, QueryExecutionFail> {
                account
                    .assets
                    .get(id)
                    .ok_or_else(|| QueryExecutionFail::from(FindError::Asset(id.clone())))
                    .cloned()
            },
        )?
    }

    // AssetDefinition-related methods

    /// Get `AssetDefinition` immutable view.
    ///
    /// # Errors
    /// - Asset definition entry not found
    fn asset_definition(&self, asset_id: &AssetDefinitionId) -> Result<AssetDefinition, FindError> {
        self.domain(&asset_id.domain_id)?
            .asset_definitions
            .get(asset_id)
            .ok_or_else(|| FindError::AssetDefinition(asset_id.clone()))
            .cloned()
    }

    /// Get total amount of [`Asset`].
    ///
    /// # Errors
    /// - Asset definition not found
    fn asset_total_amount(&self, definition_id: &AssetDefinitionId) -> Result<Numeric, FindError> {
        self.domain(&definition_id.domain_id)?
            .asset_total_quantities
            .get(definition_id)
            .ok_or_else(|| FindError::AssetDefinition(definition_id.clone()))
            .copied()
    }

    /// Get an immutable iterator over the [`PeerId`]s.
    fn peers(&self) -> impl ExactSizeIterator<Item = &PeerId> {
        self.trusted_peers_ids().iter()
    }

    /// Get all `Parameter`s registered in the world.
    fn parameters_iter(&self) -> impl Iterator<Item = &Parameter> {
        self.parameters().iter()
    }

    /// Query parameter and convert it to a proper type
    fn query_param<T: TryFrom<ParameterValueBox>, P: core::hash::Hash + Eq + ?Sized>(
        &self,
        param: &P,
    ) -> Option<T>
    where
        Parameter: Borrow<P>,
    {
        Parameters::get(self.parameters(), param)
            .as_ref()
            .map(|param| &param.val)
            .cloned()
            .and_then(|param_val| param_val.try_into().ok())
    }

    /// Returns reference for trusted peer ids
    #[inline]
    fn peers_ids(&self) -> &PeersIds {
        self.trusted_peers_ids()
    }
}

macro_rules! impl_world_ro {
    ($($ident:ty),*) => {$(
        impl WorldReadOnly for $ident {
            fn parameters(&self) -> &Parameters {
                &self.parameters
            }
            fn trusted_peers_ids(&self) -> &PeersIds {
                &self.trusted_peers_ids
            }
            fn domains(&self) -> &impl StorageReadOnly<DomainId, Domain> {
                &self.domains
            }
            fn roles(&self) -> &impl StorageReadOnly<RoleId, Role> {
                &self.roles
            }
            fn account_permissions(&self) -> &impl StorageReadOnly<AccountId, Permissions> {
                &self.account_permissions
            }
            fn account_roles(&self) -> &impl StorageReadOnly<RoleIdWithOwner, ()> {
                &self.account_roles
            }
            fn triggers(&self) -> &impl TriggerSetReadOnly {
                &self.triggers
            }
            fn executor(&self) -> &Executor {
                &self.executor
            }
            fn executor_data_model(&self) -> &ExecutorDataModel {
                &self.executor_data_model
            }
        }
    )*};
}

impl_world_ro! {
    WorldBlock<'_>, WorldTransaction<'_, '_>, WorldView<'_>
}

impl<'world> WorldBlock<'world> {
    /// Create struct to apply transaction's changes
    pub fn trasaction(&mut self) -> WorldTransaction<'_, 'world> {
        WorldTransaction {
            parameters: self.parameters.transaction(),
            trusted_peers_ids: self.trusted_peers_ids.transaction(),
            domains: self.domains.transaction(),
            roles: self.roles.transaction(),
            account_permissions: self.account_permissions.transaction(),
            account_roles: self.account_roles.transaction(),
            triggers: self.triggers.transaction(),
            executor: self.executor.transaction(),
            executor_data_model: self.executor_data_model.transaction(),
            events_buffer: TransactionEventBuffer {
                events_buffer: &mut self.events_buffer,
                events_created_in_transaction: 0,
            },
        }
    }

    /// Commit block's changes
    pub fn commit(self) {
        // IMPORTANT!!! Commit fields in reverse order, this way consistent results are insured
        self.executor_data_model.commit();
        self.executor.commit();
        self.triggers.commit();
        self.account_roles.commit();
        self.account_permissions.commit();
        self.roles.commit();
        self.domains.commit();
        self.trusted_peers_ids.commit();
        self.parameters.commit();
    }
}

impl WorldTransaction<'_, '_> {
    /// Apply transaction's changes
    pub fn apply(mut self) {
        self.executor_data_model.apply();
        self.executor.apply();
        self.triggers.apply();
        self.account_roles.apply();
        self.account_permissions.apply();
        self.roles.apply();
        self.domains.apply();
        self.trusted_peers_ids.apply();
        self.parameters.apply();
        self.events_buffer.events_created_in_transaction = 0;
    }

    /// Get `Domain` with an ability to modify it.
    ///
    /// # Errors
    /// Fails if there is no domain
    pub fn domain_mut(&mut self, id: &DomainId) -> Result<&mut Domain, FindError> {
        let domain = self
            .domains
            .get_mut(id)
            .ok_or_else(|| FindError::Domain(id.clone()))?;
        Ok(domain)
    }

    /// Get mutable reference to [`Account`]
    ///
    /// # Errors
    /// Fail if domain or account not found
    pub fn account_mut(&mut self, id: &AccountId) -> Result<&mut Account, FindError> {
        self.domain_mut(&id.domain_id).and_then(move |domain| {
            domain
                .accounts
                .get_mut(id)
                .ok_or_else(|| FindError::Account(id.clone()))
        })
    }

    /// Add [`permission`](Permission) to the [`Account`] if the account does not have this permission yet.
    ///
    /// Return a Boolean value indicating whether or not the  [`Account`] already had this permission.
    pub fn add_account_permission(&mut self, account: &AccountId, token: Permission) -> bool {
        // `match` here instead of `map_or_else` to avoid cloning token into each closure
        match self.account_permissions.get_mut(account) {
            None => {
                self.account_permissions
                    .insert(account.clone(), BTreeSet::from([token]));
                true
            }
            Some(permissions) => {
                if permissions.contains(&token) {
                    return true;
                }
                permissions.insert(token);
                false
            }
        }
    }

    /// Remove a [`permission`](Permission) from the [`Account`] if the account has this permission.
    /// Return a Boolean value indicating whether the [`Account`] had this permission.
    pub fn remove_account_permission(&mut self, account: &AccountId, token: &Permission) -> bool {
        self.account_permissions
            .get_mut(account)
            .map_or(false, |permissions| permissions.remove(token))
    }

    /// Get mutable reference to [`Asset`]
    ///
    /// # Errors
    /// If domain, account or asset not found
    pub fn asset_mut(&mut self, id: &AssetId) -> Result<&mut Asset, FindError> {
        self.account_mut(&id.account_id).and_then(move |account| {
            account
                .assets
                .get_mut(id)
                .ok_or_else(|| FindError::Asset(id.clone()))
        })
    }

    /// Get asset or inserts new with `default_asset_value`.
    ///
    /// # Errors
    /// - There is no account with such name.
    #[allow(clippy::missing_panics_doc)]
    pub fn asset_or_insert(
        &mut self,
        asset_id: AssetId,
        default_asset_value: impl Into<AssetValue>,
    ) -> Result<&mut Asset, Error> {
        // Check that asset definition exists
        {
            let asset_definition_id = &asset_id.definition_id;
            let asset_definition_domain_id = &asset_id.definition_id.domain_id;
            let asset_definition_domain = self
                .domains
                .get(asset_definition_domain_id)
                .ok_or(FindError::Domain(asset_definition_domain_id.clone()))?;
            asset_definition_domain
                .asset_definitions
                .get(asset_definition_id)
                .ok_or(FindError::AssetDefinition(asset_definition_id.clone()))?;
        }

        let account_id = &asset_id.account_id;
        let account_domain = self
            .domains
            .get_mut(&asset_id.account_id.domain_id)
            .ok_or(FindError::Domain(asset_id.account_id.domain_id.clone()))?;
        let account = account_domain
            .accounts
            .get_mut(account_id)
            .ok_or(FindError::Account(account_id.clone()))?;

        Ok(account.assets.entry(asset_id.clone()).or_insert_with(|| {
            let asset = Asset::new(asset_id, default_asset_value.into());
            Self::emit_events_impl(
                &mut self.triggers,
                &mut self.events_buffer,
                Some(AccountEvent::Asset(AssetEvent::Created(asset.clone()))),
            );
            asset
        }))
    }

    /// Get mutable reference to [`AssetDefinition`]
    ///
    /// # Errors
    /// If domain or asset definition not found
    pub fn asset_definition_mut(
        &mut self,
        id: &AssetDefinitionId,
    ) -> Result<&mut AssetDefinition, FindError> {
        self.domain_mut(&id.domain_id).and_then(|domain| {
            domain
                .asset_definitions
                .get_mut(id)
                .ok_or_else(|| FindError::AssetDefinition(id.clone()))
        })
    }

    /// Increase [`Asset`] total amount by given value
    ///
    /// # Errors
    /// - [`AssetDefinition`], [`Domain`] not found
    /// - Overflow
    pub fn increase_asset_total_amount(
        &mut self,
        definition_id: &AssetDefinitionId,
        increment: Numeric,
    ) -> Result<(), Error> {
        let domain = self.domain_mut(&definition_id.domain_id)?;
        let asset_total_amount: &mut Numeric = domain
            .asset_total_quantities.get_mut(definition_id)
            .expect("Asset total amount not being found is a bug: check `Register<AssetDefinition>` to insert initial total amount");
        *asset_total_amount = asset_total_amount
            .checked_add(increment)
            .ok_or(MathError::Overflow)?;
        let asset_total_amount = *asset_total_amount;

        self.emit_events({
            Some(DomainEvent::AssetDefinition(
                AssetDefinitionEvent::TotalQuantityChanged(AssetDefinitionTotalQuantityChanged {
                    asset_definition_id: definition_id.clone(),
                    total_amount: asset_total_amount,
                }),
            ))
        });

        Ok(())
    }

    /// Decrease [`Asset`] total amount by given value
    ///
    /// # Errors
    /// - [`AssetDefinition`], [`Domain`] not found
    /// - Not enough quantity
    pub fn decrease_asset_total_amount(
        &mut self,
        definition_id: &AssetDefinitionId,
        decrement: Numeric,
    ) -> Result<(), Error> {
        let domain = self.domain_mut(&definition_id.domain_id)?;
        let asset_total_amount: &mut Numeric = domain
            .asset_total_quantities.get_mut(definition_id)
            .expect("Asset total amount not being found is a bug: check `Register<AssetDefinition>` to insert initial total amount");
        *asset_total_amount = asset_total_amount
            .checked_sub(decrement)
            .ok_or(MathError::NotEnoughQuantity)?;
        let asset_total_amount = *asset_total_amount;

        self.emit_events({
            Some(DomainEvent::AssetDefinition(
                AssetDefinitionEvent::TotalQuantityChanged(AssetDefinitionTotalQuantityChanged {
                    asset_definition_id: definition_id.clone(),
                    total_amount: asset_total_amount,
                }),
            ))
        });

        Ok(())
    }

    /// Set executor data model.
    pub fn set_executor_data_model(&mut self, executor_data_model: ExecutorDataModel) {
        *self.executor_data_model.get_mut() = executor_data_model;
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
    pub fn execute_trigger(&mut self, trigger_id: TriggerId, authority: &AccountId) {
        let event = ExecuteTriggerEvent {
            trigger_id,
            authority: authority.clone(),
        };

        self.triggers.handle_execute_trigger_event(event.clone());
        self.events_buffer.push(event.into());
    }

    /// The function puts events produced by iterator into `events_buffer`.
    /// Events should be produced in the order of expanding scope: from specific to general.
    /// Example: account events before domain events.
    pub fn emit_events<I: IntoIterator<Item = T>, T: Into<DataEvent>>(&mut self, world_events: I) {
        Self::emit_events_impl(&mut self.triggers, &mut self.events_buffer, world_events)
    }

    /// Implementation of [`Self::emit_events()`].
    ///
    /// Usable when you can't call [`Self::emit_events()`] due to mutable reference to self.
    fn emit_events_impl<I: IntoIterator<Item = T>, T: Into<DataEvent>>(
        triggers: &mut TriggerSetTransaction,
        events_buffer: &mut TransactionEventBuffer<'_>,
        world_events: I,
    ) {
        let data_events: SmallVec<[DataEvent; 3]> = world_events
            .into_iter()
            .map(Into::into)
            .map(Into::into)
            .collect();

        for event in data_events.iter() {
            triggers.handle_data_event(event.clone());
        }
        events_buffer.extend(data_events.into_iter().map(Into::into));
    }
}

impl TransactionEventBuffer<'_> {
    fn push(&mut self, event: EventBox) {
        self.events_created_in_transaction += 1;
        self.events_buffer.push(event);
    }
}

impl Extend<EventBox> for TransactionEventBuffer<'_> {
    fn extend<T: IntoIterator<Item = EventBox>>(&mut self, iter: T) {
        let len_before = self.events_buffer.len();
        self.events_buffer.extend(iter);
        let len_after = self.events_buffer.len();
        self.events_created_in_transaction += len_after - len_before;
    }
}

impl Drop for TransactionEventBuffer<'_> {
    fn drop(&mut self) {
        // remove events produced by current transaction
        self.events_buffer
            .truncate(self.events_buffer.len() - self.events_created_in_transaction);
    }
}

impl State {
    /// Construct [`State`] with given [`World`].
    #[must_use]
    #[inline]
    pub fn new(world: World, kura: Arc<Kura>, query_handle: LiveQueryStoreHandle) -> Self {
        // Added to remain backward compatible with other code primary in tests
        Self::from_config(Config::default(), world, kura, query_handle)
    }

    /// Construct [`State`] with specific [`Configuration`].
    #[inline]
    pub fn from_config(
        config: Config,
        world: World,
        kura: Arc<Kura>,
        query_handle: LiveQueryStoreHandle,
    ) -> Self {
        Self {
            world,
            config: Cell::new(config),
            transactions: Storage::new(),
            block_hashes: Cell::new(Vec::new()),
            new_tx_amounts: Arc::new(Mutex::new(Vec::new())),
            engine: wasm::create_engine(),
            kura,
            query_handle,
        }
    }

    /// Create structure to execute a block
    pub fn block(&self) -> StateBlock<'_> {
        StateBlock {
            world: self.world.block(),
            config: self.config.block(),
            block_hashes: self.block_hashes.block(),
            transactions: self.transactions.block(),
            engine: &self.engine,
            kura: &self.kura,
            query_handle: &self.query_handle,
            new_tx_amounts: &self.new_tx_amounts,
        }
    }

    /// Create structure to execute a block while reverting changes made in the latest block
    pub fn block_and_revert(&self) -> StateBlock<'_> {
        StateBlock {
            world: self.world.block_and_revert(),
            config: self.config.block_and_revert(),
            block_hashes: self.block_hashes.block_and_revert(),
            transactions: self.transactions.block_and_revert(),
            engine: &self.engine,
            kura: &self.kura,
            query_handle: &self.query_handle,
            new_tx_amounts: &self.new_tx_amounts,
        }
    }

    /// Create point in time view of [`WorldState`]
    pub fn view(&self) -> StateView<'_> {
        StateView {
            world: self.world.view(),
            config: self.config.view(),
            block_hashes: self.block_hashes.view(),
            transactions: self.transactions.view(),
            engine: &self.engine,
            kura: &self.kura,
            query_handle: &self.query_handle,
            new_tx_amounts: &self.new_tx_amounts,
        }
    }
}

/// Trait to perform read-only operations on [`StateBlock`], [`StateTransaction`] and [`StateView`]
#[allow(missing_docs)]
pub trait StateReadOnly {
    fn world(&self) -> &impl WorldReadOnly;
    fn config(&self) -> &Config;
    fn block_hashes(&self) -> &[HashOf<SignedBlock>];
    fn transactions(&self) -> &impl StorageReadOnly<HashOf<SignedTransaction>, u64>;
    fn engine(&self) -> &wasmtime::Engine;
    fn kura(&self) -> &Kura;
    fn query_handle(&self) -> &LiveQueryStoreHandle;
    fn new_tx_amounts(&self) -> &Mutex<Vec<f64>>;

    // Block-related methods

    /// Get a reference to the latest block. Returns none if genesis is not committed.
    #[inline]
    fn latest_block_ref(&self) -> Option<Arc<SignedBlock>> {
        self.kura()
            .get_block_by_height(self.block_hashes().len() as u64)
    }

    /// Return the hash of the latest block
    fn latest_block_hash(&self) -> Option<HashOf<SignedBlock>> {
        self.block_hashes().iter().nth_back(0).copied()
    }

    /// Return the view change index of the latest block
    fn latest_block_view_change_index(&self) -> u64 {
        self.kura()
            .get_block_by_height(self.height())
            .map_or(0, |block| block.header().view_change_index)
    }

    /// Return the hash of the block one before the latest block
    fn prev_block_hash(&self) -> Option<HashOf<SignedBlock>> {
        self.block_hashes().iter().nth_back(1).copied()
    }

    /// Load all blocks in the block chain from disc
    fn all_blocks(&self) -> impl DoubleEndedIterator<Item = Arc<SignedBlock>> + '_ {
        let block_count = self.block_hashes().len() as u64;
        (1..=block_count).map(|height| {
            self.kura()
                .get_block_by_height(height)
                .expect("Failed to load block.")
        })
    }

    /// Return a vector of blockchain blocks after the block with the given `hash`
    fn block_hashes_after_hash(
        &self,
        hash: Option<HashOf<SignedBlock>>,
    ) -> Vec<HashOf<SignedBlock>> {
        hash.map_or_else(
            || self.block_hashes().to_vec(),
            |block_hash| {
                self.block_hashes()
                    .iter()
                    .skip_while(|&x| *x != block_hash)
                    .skip(1)
                    .copied()
                    .collect()
            },
        )
    }

    /// Return an iterator over blockchain block hashes starting with the block of the given `height`
    fn block_hashes_from_height(&self, height: usize) -> Vec<HashOf<SignedBlock>> {
        self.block_hashes()
            .iter()
            .skip(height.saturating_sub(1))
            .copied()
            .collect()
    }

    /// Height of blockchain
    #[inline]
    fn height(&self) -> u64 {
        self.block_hashes().len() as u64
    }

    /// Find a [`SignedBlock`] by hash.
    fn block_with_tx(&self, hash: &HashOf<SignedTransaction>) -> Option<Arc<SignedBlock>> {
        let height = *self.transactions().get(hash)?;
        self.kura().get_block_by_height(height)
    }

    /// Returns [`Some`] milliseconds since the genesis block was
    /// committed, or [`None`] if it wasn't.
    #[inline]
    fn genesis_timestamp(&self) -> Option<Duration> {
        if self.block_hashes().is_empty() {
            None
        } else {
            let opt = self
                .kura()
                .get_block_by_height(1)
                .map(|genesis_block| genesis_block.header().timestamp());

            if opt.is_none() {
                error!("Failed to get genesis block from Kura.");
            }
            opt
        }
    }

    /// Check if this [`SignedTransaction`] is already committed or rejected.
    #[inline]
    fn has_transaction(&self, hash: HashOf<SignedTransaction>) -> bool {
        self.transactions().get(&hash).is_some()
    }

    /// Get transaction executor
    fn transaction_executor(&self) -> TransactionExecutor {
        TransactionExecutor::new(self.config().transaction_limits)
    }
}

macro_rules! impl_state_ro {
    ($($ident:ty),*) => {$(
        impl StateReadOnly for $ident {
            fn world(&self) -> &impl WorldReadOnly {
                &self.world
            }
            fn config(&self) -> &Config {
                &self.config
            }
            fn block_hashes(&self) -> &[HashOf<SignedBlock>] {
                &self.block_hashes
            }
            fn transactions(&self) -> &impl StorageReadOnly<HashOf<SignedTransaction>, u64> {
                &self.transactions
            }
            fn engine(&self) -> &wasmtime::Engine {
                &self.engine
            }
            fn kura(&self) -> &Kura {
                &self.kura
            }
            fn query_handle(&self) -> &LiveQueryStoreHandle {
                &self.query_handle
            }
            fn new_tx_amounts(&self) -> &Mutex<Vec<f64>> {
                &self.new_tx_amounts
            }
        }
    )*};
}

impl_state_ro! {
    StateBlock<'_>, StateTransaction<'_, '_>, StateView<'_>
}

impl<'state> StateBlock<'state> {
    /// Create struct to store changes during transaction or trigger execution
    pub fn transaction(&mut self) -> StateTransaction<'_, 'state> {
        StateTransaction {
            world: self.world.trasaction(),
            config: self.config.transaction(),
            block_hashes: self.block_hashes.transaction(),
            transactions: self.transactions.transaction(),
            engine: self.engine,
            kura: self.kura,
            query_handle: self.query_handle,
            new_tx_amounts: self.new_tx_amounts,
        }
    }

    /// Commit changes aggregated during application of block
    pub fn commit(self) {
        self.transactions.commit();
        self.block_hashes.commit();
        self.config.commit();
        self.world.commit();
    }

    /// Commit `CommittedBlock` with changes in form of **Iroha Special
    /// Instructions** to `self`.
    ///
    /// Order of execution:
    /// 1) Transactions
    /// 2) Triggers
    ///
    /// # Errors
    ///
    /// - (RARE) if applying transaction after validation fails.
    /// - If trigger execution fails
    /// - If timestamp conversion to `u64` fails
    #[cfg_attr(
        not(debug_assertions),
        deprecated(note = "This function is to be used in testing only. ")
    )]
    #[iroha_logger::log(skip_all, fields(block_height))]
    pub fn apply(&mut self, block: &CommittedBlock) -> Result<MustUse<Vec<EventBox>>> {
        self.execute_transactions(block)?;
        debug!("All block transactions successfully executed");
        Ok(self.apply_without_execution(block).into())
    }

    /// Execute `block` transactions and store their hashes as well as
    /// `rejected_transactions` hashes
    ///
    /// # Errors
    /// Fails if transaction instruction execution fails
    fn execute_transactions(&mut self, block: &CommittedBlock) -> Result<()> {
        // TODO: Should this block panic instead?
        for tx in block.as_ref().transactions() {
            if tx.error.is_none() {
                // Execute every tx in it's own transaction
                let mut transaction = self.transaction();
                transaction.process_executable(
                    tx.as_ref().instructions(),
                    tx.as_ref().authority().clone(),
                )?;
                transaction.apply();
            }
        }

        Ok(())
    }

    /// Apply transactions without actually executing them.
    /// It's assumed that block's transaction was already executed (as part of validation for example).
    #[iroha_logger::log(skip_all, fields(block_height = block.as_ref().header().height))]
    #[must_use]
    pub fn apply_without_execution(&mut self, block: &CommittedBlock) -> Vec<EventBox> {
        let block_hash = block.as_ref().hash();
        trace!(%block_hash, "Applying block");

        let time_event = self.create_time_event(block);
        self.world.events_buffer.push(time_event.into());

        let block_height = block.as_ref().header().height;
        block
            .as_ref()
            .transactions()
            .map(|tx| &tx.value)
            .map(SignedTransaction::hash)
            .for_each(|tx_hash| {
                self.transactions.insert(tx_hash, block_height);
            });

        self.world.triggers.handle_time_event(time_event);

        let res = self.process_triggers();

        if let Err(errors) = res {
            warn!(
                ?errors,
                "The following errors have occurred during trigger execution"
            );
        }

        self.block_hashes.push(block_hash);

        self.apply_parameters();
        self.world.events_buffer.push(
            BlockEvent {
                header: block.as_ref().header().clone(),
                hash: block.as_ref().hash(),
                status: BlockStatus::Applied,
            }
            .into(),
        );
        core::mem::take(&mut self.world.events_buffer)
    }

    /// Create time event using previous and current blocks
    fn create_time_event(&self, block: &CommittedBlock) -> TimeEvent {
        use iroha_config::parameters::defaults::chain_wide::CONSENSUS_ESTIMATION as DEFAULT_CONSENSUS_ESTIMATION;

        let prev_interval = self.latest_block_ref().map(|latest_block| {
            let header = &latest_block.as_ref().header();

            TimeInterval {
                since: header.timestamp(),
                length: DEFAULT_CONSENSUS_ESTIMATION,
            }
        });

        let interval = TimeInterval {
            since: block.as_ref().header().timestamp(),
            length: DEFAULT_CONSENSUS_ESTIMATION,
        };

        TimeEvent {
            prev_interval,
            interval,
        }
    }

    /// Process every trigger in `matched_ids`
    fn process_triggers(&mut self) -> Result<(), Vec<eyre::Report>> {
        // Cloning and clearing `self.matched_ids` so that `handle_` call won't deadlock
        let matched_ids = self.world.triggers.extract_matched_ids();
        let mut succeed = Vec::<TriggerId>::with_capacity(matched_ids.len());
        let mut errors = Vec::new();
        for (event, id) in matched_ids {
            // Eliding the closure triggers a lifetime mismatch
            #[allow(clippy::redundant_closure_for_method_calls)]
            let action = self
                .world
                .triggers
                .inspect_by_id(&id, |action| action.clone_and_box());
            if let Some(action) = action {
                if let Repeats::Exactly(repeats) = action.repeats() {
                    if *repeats == 0 {
                        continue;
                    }
                }
                // Execute every trigger in it's own transaction
                let event = {
                    let mut transaction = self.transaction();
                    match transaction.process_trigger(&id, &action, event) {
                        Ok(()) => {
                            transaction.apply();
                            succeed.push(id.clone());
                            TriggerCompletedEvent::new(id, TriggerCompletedOutcome::Success)
                        }
                        Err(error) => {
                            let event = TriggerCompletedEvent::new(
                                id,
                                TriggerCompletedOutcome::Failure(error.to_string()),
                            );
                            errors.push(error);
                            event
                        }
                    }
                };
                self.world.events_buffer.push(event.into());
            }
        }

        let mut transaction = self.transaction();
        transaction.world.triggers.decrease_repeats(&succeed);
        transaction.apply();

        errors.is_empty().then_some(()).ok_or(errors)
    }

    fn apply_parameters(&mut self) {
        use iroha_data_model::parameter::default::*;

        macro_rules! update_params {
            ($($param:expr => $config:expr),+ $(,)?) => {
                $(if let Some(param) = self.world.query_param($param) {
                    $config = param;
                })+
            };
        }

        update_params! {
            WSV_DOMAIN_METADATA_LIMITS => self.config.domain_metadata_limits,
            WSV_ASSET_DEFINITION_METADATA_LIMITS => self.config.asset_definition_metadata_limits,
            WSV_ACCOUNT_METADATA_LIMITS => self.config.account_metadata_limits,
            WSV_ASSET_METADATA_LIMITS => self.config.asset_metadata_limits,
            WSV_TRIGGER_METADATA_LIMITS => self.config.trigger_metadata_limits,
            WSV_IDENT_LENGTH_LIMITS => self.config.ident_length_limits,
            EXECUTOR_FUEL_LIMIT => self.config.executor_runtime.fuel_limit,
            EXECUTOR_MAX_MEMORY => self.config.executor_runtime.max_memory_bytes,
            WASM_FUEL_LIMIT => self.config.wasm_runtime.fuel_limit,
            WASM_MAX_MEMORY => self.config.wasm_runtime.max_memory_bytes,
            TRANSACTION_LIMITS => self.config.transaction_limits,
        }
    }
}

impl StateTransaction<'_, '_> {
    /// Apply transaction making it's changes visible
    pub fn apply(self) {
        self.transactions.apply();
        self.block_hashes.apply();
        self.config.apply();
        self.world.apply();
    }

    fn process_executable(&mut self, executable: &Executable, authority: AccountId) -> Result<()> {
        match executable {
            Executable::Instructions(instructions) => {
                self.process_instructions(instructions.iter().cloned(), &authority)
            }
            Executable::Wasm(bytes) => {
                let mut wasm_runtime = wasm::RuntimeBuilder::<wasm::state::SmartContract>::new()
                    .with_config(self.config.wasm_runtime)
                    .with_engine(self.engine.clone()) // Cloning engine is cheap
                    .build()?;
                wasm_runtime
                    .execute(self, authority, bytes)
                    .map_err(Into::into)
            }
        }
    }

    fn process_instructions(
        &mut self,
        instructions: impl IntoIterator<Item = InstructionBox>,
        authority: &AccountId,
    ) -> Result<()> {
        instructions.into_iter().try_for_each(|instruction| {
            instruction.execute(authority, self)?;
            Ok::<_, eyre::Report>(())
        })
    }

    fn process_trigger(
        &mut self,
        id: &TriggerId,
        action: &dyn LoadedActionTrait,
        event: EventBox,
    ) -> Result<()> {
        use triggers::set::ExecutableRef::*;
        let authority = action.authority();

        match action.executable() {
            Instructions(instructions) => {
                self.process_instructions(instructions.iter().cloned(), authority)
            }
            Wasm(blob_hash) => {
                let module = self
                    .world
                    .triggers
                    .get_compiled_contract(blob_hash)
                    .expect("contract is not present it's a bug")
                    .clone();
                let mut wasm_runtime = wasm::RuntimeBuilder::<wasm::state::Trigger>::new()
                    .with_config(self.config.wasm_runtime)
                    .with_engine(self.engine.clone()) // Cloning engine is cheap
                    .build()?;
                wasm_runtime
                    .execute_trigger_module(self, id, authority.clone(), &module, event)
                    .map_err(Into::into)
            }
        }
    }
}

/// Bounds for `range` queries
mod range_bounds {
    use core::ops::{Bound, RangeBounds};

    use iroha_primitives::{cmpext::MinMaxExt, impl_as_dyn_key};

    use super::*;
    use crate::role::RoleIdWithOwner;

    /// Key for range queries over account for roles
    #[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
    pub struct RoleIdByAccount<'role> {
        account_id: &'role AccountId,
        role_id: MinMaxExt<&'role RoleId>,
    }

    /// Bounds for range quired over account for roles
    pub struct RoleIdByAccountBounds<'role> {
        start: RoleIdByAccount<'role>,
        end: RoleIdByAccount<'role>,
    }

    impl<'role> RoleIdByAccountBounds<'role> {
        /// Create range bounds for range quires of roles over account
        pub fn new(account_id: &'role AccountId) -> Self {
            Self {
                start: RoleIdByAccount {
                    account_id,
                    role_id: MinMaxExt::Min,
                },
                end: RoleIdByAccount {
                    account_id,
                    role_id: MinMaxExt::Max,
                },
            }
        }
    }

    impl<'role> RangeBounds<dyn AsRoleIdByAccount + 'role> for RoleIdByAccountBounds<'role> {
        fn start_bound(&self) -> Bound<&(dyn AsRoleIdByAccount + 'role)> {
            Bound::Excluded(&self.start)
        }

        fn end_bound(&self) -> Bound<&(dyn AsRoleIdByAccount + 'role)> {
            Bound::Excluded(&self.end)
        }
    }

    impl AsRoleIdByAccount for RoleIdWithOwner {
        fn as_key(&self) -> RoleIdByAccount<'_> {
            RoleIdByAccount {
                account_id: &self.account_id,
                role_id: (&self.role_id).into(),
            }
        }
    }

    impl_as_dyn_key! {
        target: RoleIdWithOwner,
        key: RoleIdByAccount<'_>,
        trait: AsRoleIdByAccount
    }
}

pub(crate) mod deserialize {
    use storage::serde::CellSeeded;

    use super::*;

    // Loader for [`Set`]
    #[derive(Clone, Copy)]
    pub struct WasmSeed<'e, T> {
        pub engine: &'e wasmtime::Engine,
        _marker: PhantomData<T>,
    }

    impl<'e, T> WasmSeed<'e, T> {
        pub fn cast<U>(&self) -> WasmSeed<'e, U> {
            WasmSeed {
                engine: self.engine,
                _marker: PhantomData,
            }
        }
    }

    impl<'e, 'de, T> DeserializeSeed<'de> for WasmSeed<'e, Option<T>>
    where
        WasmSeed<'e, T>: DeserializeSeed<'de, Value = T>,
    {
        type Value = Option<T>;

        fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct OptionVisitor<'l, T> {
                loader: WasmSeed<'l, T>,
                _marker: PhantomData<T>,
            }

            impl<'e, 'de, T> Visitor<'de> for OptionVisitor<'e, T>
            where
                WasmSeed<'e, T>: DeserializeSeed<'de, Value = T>,
            {
                type Value = Option<T>;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("struct World")
                }

                fn visit_none<E>(self) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(None)
                }

                fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
                where
                    D: Deserializer<'de>,
                {
                    Some(self.loader.deserialize(deserializer)).transpose()
                }
            }

            let visitor = OptionVisitor {
                loader: self.cast::<T>(),
                _marker: PhantomData,
            };
            deserializer.deserialize_option(visitor)
        }
    }

    impl<'de> DeserializeSeed<'de> for WasmSeed<'_, World> {
        type Value = World;

        fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct WorldVisitor<'l> {
                loader: &'l WasmSeed<'l, World>,
            }

            impl<'de> Visitor<'de> for WorldVisitor<'_> {
                type Value = World;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("struct World")
                }

                fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
                where
                    M: MapAccess<'de>,
                {
                    let mut parameters = None;
                    let mut trusted_peers_ids = None;
                    let mut domains = None;
                    let mut roles = None;
                    let mut account_permissions = None;
                    let mut account_roles = None;
                    let mut triggers = None;
                    let mut executor = None;
                    let mut executor_data_model = None;

                    while let Some(key) = map.next_key::<String>()? {
                        match key.as_str() {
                            "parameters" => {
                                parameters = Some(map.next_value()?);
                            }
                            "trusted_peers_ids" => {
                                trusted_peers_ids = Some(map.next_value()?);
                            }
                            "domains" => {
                                domains = Some(map.next_value()?);
                            }
                            "roles" => {
                                roles = Some(map.next_value()?);
                            }
                            "account_permissions" => {
                                account_permissions = Some(map.next_value()?);
                            }
                            "account_roles" => {
                                account_roles = Some(map.next_value()?);
                            }
                            "triggers" => {
                                triggers =
                                    Some(map.next_value_seed(self.loader.cast::<TriggerSet>())?);
                            }
                            "executor" => {
                                executor = Some(map.next_value_seed(CellSeeded {
                                    seed: self.loader.cast::<Executor>(),
                                })?);
                            }
                            "executor_data_model" => {
                                executor_data_model = Some(map.next_value()?);
                            }

                            _ => { /* Skip unknown fields */ }
                        }
                    }

                    Ok(World {
                        parameters: parameters
                            .ok_or_else(|| serde::de::Error::missing_field("parameters"))?,
                        trusted_peers_ids: trusted_peers_ids
                            .ok_or_else(|| serde::de::Error::missing_field("trusted_peers_ids"))?,
                        domains: domains
                            .ok_or_else(|| serde::de::Error::missing_field("domains"))?,
                        roles: roles.ok_or_else(|| serde::de::Error::missing_field("roles"))?,
                        account_permissions: account_permissions.ok_or_else(|| {
                            serde::de::Error::missing_field("account_permissions")
                        })?,
                        account_roles: account_roles
                            .ok_or_else(|| serde::de::Error::missing_field("account_roles"))?,
                        triggers: triggers
                            .ok_or_else(|| serde::de::Error::missing_field("triggers"))?,
                        executor: executor
                            .ok_or_else(|| serde::de::Error::missing_field("executor"))?,
                        executor_data_model: executor_data_model.ok_or_else(|| {
                            serde::de::Error::missing_field("executor_data_model")
                        })?,
                    })
                }
            }

            deserializer.deserialize_struct(
                "World",
                &[
                    "parameters",
                    "trusted_peers_ids",
                    "domains",
                    "roles",
                    "account_permissions",
                    "account_roles",
                    "triggers",
                    "executor",
                    "executor_data_model",
                ],
                WorldVisitor { loader: &self },
            )
        }
    }

    /// Context necessary for deserializing [`State`]
    pub struct KuraSeed {
        /// Kura subsystem reference
        pub kura: Arc<Kura>,
        /// Handle to the [`LiveQueryStore`](crate::query::store::LiveQueryStore).
        pub query_handle: LiveQueryStoreHandle,
    }

    impl<'de> DeserializeSeed<'de> for KuraSeed {
        type Value = State;

        fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct StateVisitor {
                loader: KuraSeed,
            }

            impl<'de> Visitor<'de> for StateVisitor {
                type Value = State;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("struct WorldState")
                }

                fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
                where
                    M: MapAccess<'de>,
                {
                    let mut world = None;
                    let mut config = None;
                    let mut block_hashes = None;
                    let mut transactions = None;

                    let engine = wasm::create_engine();

                    let wasm_seed: WasmSeed<()> = WasmSeed {
                        engine: &engine,
                        _marker: PhantomData,
                    };

                    while let Some(key) = map.next_key::<String>()? {
                        match key.as_str() {
                            "world" => {
                                world = Some(map.next_value_seed(wasm_seed.cast::<World>())?);
                            }
                            "config" => {
                                config = Some(map.next_value()?);
                            }
                            "block_hashes" => {
                                block_hashes = Some(map.next_value()?);
                            }
                            "transactions" => {
                                transactions = Some(map.next_value()?);
                            }
                            _ => { /* Skip unknown fields */ }
                        }
                    }

                    Ok(State {
                        world: world.ok_or_else(|| serde::de::Error::missing_field("world"))?,
                        config: config.ok_or_else(|| serde::de::Error::missing_field("config"))?,
                        block_hashes: block_hashes
                            .ok_or_else(|| serde::de::Error::missing_field("block_hashes"))?,
                        transactions: transactions
                            .ok_or_else(|| serde::de::Error::missing_field("transactions"))?,
                        kura: self.loader.kura,
                        query_handle: self.loader.query_handle,
                        engine,
                        new_tx_amounts: Arc::new(Mutex::new(Vec::new())),
                    })
                }
            }

            deserializer.deserialize_struct(
                "WorldState",
                &["world", "config", "block_hashes", "transactions"],
                StateVisitor { loader: self },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use iroha_data_model::block::BlockPayload;
    use iroha_primitives::unique_vec::UniqueVec;
    use test_samples::gen_account_in;

    use super::*;
    use crate::{
        block::ValidBlock, query::store::LiveQueryStore, role::RoleIdWithOwner,
        sumeragi::network_topology::Topology,
    };

    /// Used to inject faulty payload for testing
    fn new_dummy_block_with_payload(f: impl FnOnce(&mut BlockPayload)) -> CommittedBlock {
        let topology = Topology::new(UniqueVec::new());
        ValidBlock::new_dummy_and_modify_payload(f)
            .commit(&topology)
            .unpack(|_| {})
            .unwrap()
    }

    #[tokio::test]
    async fn get_block_hashes_after_hash() {
        const BLOCK_CNT: usize = 10;

        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = State::new(World::default(), kura, query_handle);
        let mut state_block = state.block();

        let mut block_hashes = vec![];
        for i in 1..=BLOCK_CNT {
            let block = new_dummy_block_with_payload(|payload| {
                payload.header.height = i as u64;
                payload.header.previous_block_hash = block_hashes.last().copied();
            });

            block_hashes.push(block.as_ref().hash());
            let _events = state_block.apply(&block).unwrap();
        }

        assert!(state_block
            .block_hashes_after_hash(Some(block_hashes[6]))
            .into_iter()
            .eq(block_hashes.into_iter().skip(7)));
    }

    #[tokio::test]
    async fn get_blocks_from_height() {
        const BLOCK_CNT: usize = 10;

        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = State::new(World::default(), kura.clone(), query_handle);
        let mut state_block = state.block();

        for i in 1..=BLOCK_CNT {
            let block = new_dummy_block_with_payload(|payload| {
                payload.header.height = i as u64;
            });

            let _events = state_block.apply(&block).unwrap();
            kura.store_block(block);
        }

        assert_eq!(
            &state_block
                .all_blocks()
                .skip(7)
                .map(|block| block.header().height())
                .collect::<Vec<_>>(),
            &[8, 9, 10]
        );
    }

    #[test]
    fn role_account_range() {
        let (account_id, _account_keypair) = gen_account_in("wonderland");
        let roles = [
            RoleIdWithOwner::new(account_id.clone(), "1".parse().unwrap()),
            RoleIdWithOwner::new(account_id.clone(), "2".parse().unwrap()),
            RoleIdWithOwner::new(gen_account_in("wonderland").0, "3".parse().unwrap()),
            RoleIdWithOwner::new(gen_account_in("wonderland").0, "4".parse().unwrap()),
            RoleIdWithOwner::new(gen_account_in("0").0, "5".parse().unwrap()),
            RoleIdWithOwner::new(gen_account_in("1").0, "6".parse().unwrap()),
        ];
        let map = BTreeSet::from(roles);

        let range = map
            .range(RoleIdByAccountBounds::new(&account_id))
            .collect::<Vec<_>>();
        assert_eq!(range.len(), 2);
        for role in range {
            assert_eq!(&role.account_id, &account_id);
        }
    }
}
