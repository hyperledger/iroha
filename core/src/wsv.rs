//! This module provides the [`WorldStateView`] — an in-memory representation of the current blockchain
//! state.
use std::{
    borrow::Borrow, collections::BTreeSet, fmt::Debug, marker::PhantomData, sync::Arc,
    time::Duration,
};

use eyre::Result;
use indexmap::IndexMap;
use iroha_config::{
    base::proxy::Builder,
    wsv::{Configuration, ConfigurationProxy},
};
use iroha_crypto::HashOf;
use iroha_data_model::{
    account::AccountId,
    block::SignedBlock,
    events::notification::{TriggerCompletedEvent, TriggerCompletedOutcome},
    isi::error::{InstructionExecutionError as Error, MathError},
    parameter::Parameter,
    permission::PermissionTokenSchema,
    prelude::*,
    query::error::{FindError, QueryExecutionFail},
};
use iroha_logger::prelude::*;
use iroha_primitives::small::SmallVec;
use parking_lot::Mutex;
use range_bounds::RoleIdByAccountBounds;
use serde::{
    de::{DeserializeSeed, MapAccess, Visitor},
    Deserializer, Serialize,
};

use crate::{
    block::CommittedBlock,
    executor::Executor,
    kura::Kura,
    smartcontracts::{
        triggers::{
            self,
            set::{LoadedActionTrait, LoadedWasm, Set as TriggerSet},
        },
        wasm, Execute,
    },
    tx::TransactionExecutor,
    DomainsMap, Parameters, PeersIds,
};

/// The global entity consisting of `domains`, `triggers` and etc.
/// For example registration of domain, will have this as an ISI target.
#[derive(Debug, Default, Clone, Serialize)]
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
    /// Roles of an account.
    pub(crate) account_roles: crate::AccountRolesSet,
    /// Registered permission token ids.
    pub(crate) permission_token_schema: PermissionTokenSchema,
    /// Triggers
    pub(crate) triggers: TriggerSet,
    /// Runtime Executor
    pub(crate) executor: Executor,
}

// Loader for [`Set`]
#[derive(Clone, Copy)]
pub(crate) struct WasmSeed<'e, T> {
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
                let mut account_permission_tokens = None;
                let mut account_roles = None;
                let mut permission_token_schema = None;
                let mut triggers = None;
                let mut executor = None;

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
                        "account_permission_tokens" => {
                            account_permission_tokens = Some(map.next_value()?);
                        }
                        "account_roles" => {
                            account_roles = Some(map.next_value()?);
                        }
                        "permission_token_schema" => {
                            permission_token_schema = Some(map.next_value()?);
                        }
                        "triggers" => {
                            triggers = Some(map.next_value_seed(self.loader.cast::<TriggerSet>())?);
                        }
                        "executor" => {
                            executor = Some(map.next_value_seed(self.loader.cast::<Executor>())?);
                        }
                        _ => { /* Skip unknown fields */ }
                    }
                }

                Ok(World {
                    parameters: parameters
                        .ok_or_else(|| serde::de::Error::missing_field("parameters"))?,
                    trusted_peers_ids: trusted_peers_ids
                        .ok_or_else(|| serde::de::Error::missing_field("trusted_peers_ids"))?,
                    domains: domains.ok_or_else(|| serde::de::Error::missing_field("domains"))?,
                    roles: roles.ok_or_else(|| serde::de::Error::missing_field("roles"))?,
                    account_permission_tokens: account_permission_tokens.ok_or_else(|| {
                        serde::de::Error::missing_field("account_permission_tokens")
                    })?,
                    account_roles: account_roles
                        .ok_or_else(|| serde::de::Error::missing_field("account_roles"))?,
                    permission_token_schema: permission_token_schema.ok_or_else(|| {
                        serde::de::Error::missing_field("permission_token_schema")
                    })?,
                    triggers: triggers
                        .ok_or_else(|| serde::de::Error::missing_field("triggers"))?,
                    executor: executor
                        .ok_or_else(|| serde::de::Error::missing_field("executor"))?,
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
                "account_permission_tokens",
                "account_roles",
                "permission_token_schema",
                "triggers",
                "executor",
            ],
            WorldVisitor { loader: &self },
        )
    }
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
            trusted_peers_ids,
            domains,
            ..World::new()
        }
    }
}

/// Current state of the blockchain aligned with `Iroha` module.
#[derive(Serialize)]
pub struct WorldStateView {
    /// The world. Contains `domains`, `triggers`, `roles` and other data representing the current state of the blockchain.
    pub world: World,
    /// Configuration of World State View.
    pub config: Configuration,
    /// Blockchain.
    pub block_hashes: Vec<HashOf<SignedBlock>>,
    /// Hashes of transactions mapped onto block height where they stored
    pub transactions: IndexMap<HashOf<SignedTransaction>, u64>,
    /// Buffer containing events generated during `WorldStateView::apply`. Renewed on every block commit.
    #[serde(skip)]
    pub events_buffer: Vec<Event>,
    /// Engine for WASM [`Runtime`](wasm::Runtime) to execute triggers.
    #[serde(skip)]
    pub engine: wasmtime::Engine,

    /// Reference to Kura subsystem.
    #[serde(skip)]
    kura: Arc<Kura>,
    /// Temporary metrics buffer of amounts of any asset that has been transacted.
    #[serde(skip)]
    pub new_tx_amounts: Arc<Mutex<Vec<f64>>>,
}

/// Context necessary for deserializing [`WorldStateView`]
pub struct KuraSeed {
    /// Kura subsystem reference
    pub kura: Arc<Kura>,
}

impl<'de> DeserializeSeed<'de> for KuraSeed {
    type Value = WorldStateView;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct WorldStateViewVisitor {
            loader: KuraSeed,
        }

        impl<'de> Visitor<'de> for WorldStateViewVisitor {
            type Value = WorldStateView;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct WorldStateView")
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

                Ok(WorldStateView {
                    world: world.ok_or_else(|| serde::de::Error::missing_field("world"))?,
                    config: config.ok_or_else(|| serde::de::Error::missing_field("config"))?,
                    block_hashes: block_hashes
                        .ok_or_else(|| serde::de::Error::missing_field("block_hashes"))?,
                    transactions: transactions
                        .ok_or_else(|| serde::de::Error::missing_field("transactions"))?,
                    kura: self.loader.kura,
                    engine,
                    events_buffer: Vec::new(),
                    new_tx_amounts: Arc::new(Mutex::new(Vec::new())),
                })
            }
        }

        deserializer.deserialize_struct(
            "WorldStateView",
            &["world", "config", "block_hashes", "transactions"],
            WorldStateViewVisitor { loader: self },
        )
    }
}

impl Clone for WorldStateView {
    fn clone(&self) -> Self {
        Self {
            world: Clone::clone(&self.world),
            config: self.config,
            block_hashes: self.block_hashes.clone(),
            transactions: self.transactions.clone(),
            events_buffer: Vec::new(),
            new_tx_amounts: Arc::clone(&self.new_tx_amounts),
            engine: self.engine.clone(),
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
    pub fn account_assets(
        &self,
        id: &AccountId,
    ) -> Result<impl ExactSizeIterator<Item = &Asset>, QueryExecutionFail> {
        self.map_account(id, |account| account.assets.values())
    }

    /// Get [`Account`]'s [`RoleId`]s
    pub fn account_roles(&self, id: &AccountId) -> impl Iterator<Item = &RoleId> {
        self.world
            .account_roles
            .range(RoleIdByAccountBounds::new(id))
            .map(|role| &role.role_id)
    }

    /// Return a set of all permission tokens granted to this account.
    ///
    /// # Errors
    ///
    /// - if `account_id` is not found in `self`
    pub fn account_permission_tokens(
        &self,
        account_id: &AccountId,
    ) -> Result<impl ExactSizeIterator<Item = &PermissionToken>, FindError> {
        self.account(account_id)?;

        let mut tokens = self
            .account_inherent_permission_tokens(account_id)
            .collect::<BTreeSet<_>>();

        for role_id in self.account_roles(account_id) {
            if let Some(role) = self.world.roles.get(role_id) {
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
    pub fn account_inherent_permission_tokens(
        &self,
        account_id: &AccountId,
    ) -> impl ExactSizeIterator<Item = &PermissionToken> {
        self.world
            .account_permission_tokens
            .get(account_id)
            .map_or_else(Default::default, std::collections::BTreeSet::iter)
    }

    /// Return `true` if [`Account`] contains a permission token not associated with any role.
    #[inline]
    pub fn account_contains_inherent_permission(
        &self,
        account: &AccountId,
        token: &PermissionToken,
    ) -> bool {
        self.world
            .account_permission_tokens
            .get(account)
            .map_or(false, |permissions| permissions.contains(token))
    }

    /// Add [`permission`](PermissionToken) to the [`Account`] if the account does not have this permission yet.
    ///
    /// Return a Boolean value indicating whether or not the  [`Account`] already had this permission.
    pub fn add_account_permission(&mut self, account: &AccountId, token: PermissionToken) -> bool {
        // `match` here instead of `map_or_else` to avoid cloning token into each closure
        match self.world.account_permission_tokens.get_mut(account) {
            None => {
                self.world
                    .account_permission_tokens
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

    /// Remove a [`permission`](PermissionToken) from the [`Account`] if the account has this permission.
    /// Return a Boolean value indicating whether the [`Account`] had this permission.
    pub fn remove_account_permission(
        &mut self,
        account: &AccountId,
        token: &PermissionToken,
    ) -> bool {
        self.world
            .account_permission_tokens
            .get_mut(account)
            .map_or(false, |permissions| permissions.remove(token))
    }

    fn process_trigger(
        &mut self,
        id: &TriggerId,
        action: &dyn LoadedActionTrait,
        event: Event,
    ) -> Result<()> {
        use triggers::set::LoadedExecutable::*;
        let authority = action.authority();

        match action.executable() {
            Instructions(instructions) => {
                self.process_instructions(instructions.iter().cloned(), authority)
            }
            Wasm(LoadedWasm { module, .. }) => {
                let mut wasm_runtime = wasm::RuntimeBuilder::<wasm::state::Trigger>::new()
                    .with_configuration(self.config.wasm_runtime_config)
                    .with_engine(self.engine.clone()) // Cloning engine is cheap
                    .build()?;
                wasm_runtime
                    .execute_trigger_module(self, id, authority.clone(), module, event)
                    .map_err(Into::into)
            }
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
                let wsv = self.clone();
                let event = match self.process_trigger(&id, &action, event) {
                    Ok(_) => {
                        succeed.push(id.clone());
                        TriggerCompletedEvent::new(id, TriggerCompletedOutcome::Success)
                    }
                    Err(error) => {
                        // Revert to previous state on failure inside trigger
                        *self = wsv;
                        let event = TriggerCompletedEvent::new(
                            id,
                            TriggerCompletedOutcome::Failure(error.to_string()),
                        );
                        errors.push(error);
                        event
                    }
                };
                self.events_buffer
                    .push(NotificationEvent::from(event).into());
            }
        }

        self.world.triggers.decrease_repeats(&succeed);

        errors.is_empty().then_some(()).ok_or(errors)
    }

    fn process_executable(&mut self, executable: &Executable, authority: AccountId) -> Result<()> {
        match executable {
            Executable::Instructions(instructions) => {
                self.process_instructions(instructions.iter().cloned(), &authority)
            }
            Executable::Wasm(bytes) => {
                let mut wasm_runtime = wasm::RuntimeBuilder::<wasm::state::SmartContract>::new()
                    .with_configuration(self.config.wasm_runtime_config)
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
        instructions: impl IntoIterator<Item = InstructionExpr>,
        authority: &AccountId,
    ) -> Result<()> {
        instructions.into_iter().try_for_each(|instruction| {
            instruction.execute(authority, self)?;
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
    #[cfg_attr(
        not(debug_assertions),
        deprecated(note = "This function is to be used in testing only. ")
    )]
    #[iroha_logger::log(skip_all, fields(block_height))]
    pub fn apply(&mut self, block: &CommittedBlock) -> Result<()> {
        self.execute_transactions(block)?;
        debug!("All block transactions successfully executed");

        self.apply_without_execution(block)?;

        Ok(())
    }

    /// Apply transactions without actually executing them.
    /// It's assumed that block's transaction was already executed (as part of validation for example).
    #[iroha_logger::log(skip_all, fields(block_height = block.payload().header.height))]
    pub fn apply_without_execution(&mut self, block: &CommittedBlock) -> Result<()> {
        let block_hash = block.hash();
        trace!(%block_hash, "Applying block");

        let time_event = self.create_time_event(block);
        self.events_buffer.push(Event::Time(time_event));

        let block_height = block.payload().header.height;
        block
            .payload()
            .transactions
            .iter()
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

        Ok(())
    }

    fn apply_parameters(&mut self) {
        use iroha_data_model::parameter::default::*;
        macro_rules! update_params {
            ($ident:ident, $($param:expr => $config:expr),+ $(,)?) => {
                $(if let Some(param) = self.query_param($param) {
                    let $ident = &mut self.config;
                    $config = param;
                })+

            };
        }
        update_params! {
            config,
            WSV_ASSET_METADATA_LIMITS => config.asset_metadata_limits,
            WSV_ASSET_DEFINITION_METADATA_LIMITS => config.asset_definition_metadata_limits,
            WSV_ACCOUNT_METADATA_LIMITS => config.account_metadata_limits,
            WSV_DOMAIN_METADATA_LIMITS => config.domain_metadata_limits,
            WSV_IDENT_LENGTH_LIMITS => config.ident_length_limits,
            WASM_FUEL_LIMIT => config.wasm_runtime_config.fuel_limit,
            WASM_MAX_MEMORY => config.wasm_runtime_config.max_memory,
            TRANSACTION_LIMITS => config.transaction_limits,
        }
    }

    /// Get transaction executor
    pub fn transaction_executor(&self) -> TransactionExecutor {
        TransactionExecutor::new(self.config.transaction_limits)
    }

    /// Get a reference to the latest block. Returns none if genesis is not committed.
    #[inline]
    pub fn latest_block_ref(&self) -> Option<Arc<SignedBlock>> {
        self.kura
            .get_block_by_height(self.block_hashes.len() as u64)
    }

    /// Create time event using previous and current blocks
    fn create_time_event(&self, block: &CommittedBlock) -> TimeEvent {
        let prev_interval = self.latest_block_ref().map(|latest_block| {
            let header = &latest_block.payload().header;

            TimeInterval {
                since: header.timestamp(),
                length: header.consensus_estimation(),
            }
        });

        let interval = TimeInterval {
            since: block.payload().header.timestamp(),
            length: block.payload().header.consensus_estimation(),
        };

        TimeEvent {
            prev_interval,
            interval,
        }
    }

    /// Execute `block` transactions and store their hashes as well as
    /// `rejected_transactions` hashes
    ///
    /// # Errors
    /// Fails if transaction instruction execution fails
    fn execute_transactions(&mut self, block: &CommittedBlock) -> Result<()> {
        // TODO: Should this block panic instead?
        for tx in &block.payload().transactions {
            if tx.error.is_none() {
                self.process_executable(
                    tx.payload().instructions(),
                    tx.payload().authority.clone(),
                )?;
            }
        }

        Ok(())
    }

    /// Get `Asset` by its id
    ///
    /// # Errors
    /// - No such [`Asset`]
    /// - The [`Account`] with which the [`Asset`] is associated doesn't exist.
    /// - The [`Domain`] with which the [`Account`] is associated doesn't exist.
    pub fn asset(&self, id: &AssetId) -> Result<Asset, QueryExecutionFail> {
        self.map_account(
            &id.account_id,
            |account| -> Result<Asset, QueryExecutionFail> {
                account
                    .assets
                    .get(id)
                    .ok_or_else(|| QueryExecutionFail::from(FindError::Asset(id.clone())))
                    .map(Clone::clone)
            },
        )?
    }

    /// Get asset or inserts new with `default_asset_value`.
    ///
    /// # Errors
    /// - There is no account with such name.
    #[allow(clippy::missing_panics_doc)]
    pub fn asset_or_insert(
        &mut self,
        id: &AssetId,
        default_asset_value: impl Into<AssetValue>,
    ) -> Result<Asset, Error> {
        if let Ok(asset) = self.asset(id) {
            return Ok(asset);
        }

        // This function is strictly infallible.
        let asset = self
            .account_mut(&id.account_id)
            .map(|account| {
                let asset = Asset::new(id.clone(), default_asset_value.into());
                assert!(account.add_asset(asset.clone()).is_none());
                asset
            })
            .map_err(|err| {
                iroha_logger::warn!(?err);
                err
            })?;

        self.emit_events(Some(AccountEvent::Asset(AssetEvent::Created(asset))));

        self.asset(id).map_err(Into::into)
    }

    /// Load all blocks in the block chain from disc
    pub fn all_blocks(&self) -> impl DoubleEndedIterator<Item = Arc<SignedBlock>> + '_ {
        let block_count = self.block_hashes.len() as u64;
        (1..=block_count).map(|height| {
            self.kura
                .get_block_by_height(height)
                .expect("Failed to load block.")
        })
    }

    /// Return a vector of blockchain blocks after the block with the given `hash`
    pub fn block_hashes_after_hash(
        &self,
        hash: Option<HashOf<SignedBlock>>,
    ) -> Vec<HashOf<SignedBlock>> {
        hash.map_or_else(
            || self.block_hashes.clone(),
            |block_hash| {
                self.block_hashes
                    .iter()
                    .skip_while(|&x| *x != block_hash)
                    .skip(1)
                    .copied()
                    .collect()
            },
        )
    }

    /// Return mutable reference to the [`World`]
    pub fn world_mut(&mut self) -> &mut World {
        &mut self.world
    }

    /// Return an iterator over blockchain block hashes starting with the block of the given `height`
    pub fn block_hashes_from_height(&self, height: usize) -> Vec<HashOf<SignedBlock>> {
        self.block_hashes
            .iter()
            .skip(height.saturating_sub(1))
            .copied()
            .collect()
    }

    /// Get `Domain` without an ability to modify it.
    ///
    /// # Errors
    /// Fails if there is no domain
    pub fn domain<'wsv>(&'wsv self, id: &DomainId) -> Result<&'wsv Domain, FindError> {
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
    pub fn domain_mut(&mut self, id: &DomainId) -> Result<&mut Domain, FindError> {
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
    pub fn map_domain<'wsv, T>(
        &'wsv self,
        id: &DomainId,
        f: impl FnOnce(&'wsv Domain) -> T,
    ) -> Result<T, FindError> {
        let domain = self.domain(id)?;
        let value = f(domain);
        Ok(value)
    }

    /// Get all roles
    #[inline]
    pub fn roles(&self) -> &crate::RolesMap {
        &self.world.roles
    }

    /// Get all permission token definitions
    #[inline]
    pub fn permission_token_schema(&self) -> &crate::PermissionTokenSchema {
        &self.world.permission_token_schema
    }

    /// Construct [`WorldStateView`] with specific [`Configuration`].
    #[inline]
    pub fn from_configuration(config: Configuration, world: World, kura: Arc<Kura>) -> Self {
        Self {
            world,
            config,
            transactions: IndexMap::new(),
            block_hashes: Vec::new(),
            events_buffer: Vec::new(),
            new_tx_amounts: Arc::new(Mutex::new(Vec::new())),
            engine: wasm::create_engine(),
            kura,
        }
    }

    /// Returns [`Some`] milliseconds since the genesis block was
    /// committed, or [`None`] if it wasn't.
    #[inline]
    pub fn genesis_timestamp(&self) -> Option<Duration> {
        if self.block_hashes.is_empty() {
            None
        } else {
            let opt = self
                .kura
                .get_block_by_height(1)
                .map(|genesis_block| genesis_block.payload().header.timestamp());

            if opt.is_none() {
                error!("Failed to get genesis block from Kura.");
            }
            opt
        }
    }

    /// Check if this [`SignedTransaction`] is already committed or rejected.
    #[inline]
    pub fn has_transaction(&self, hash: HashOf<SignedTransaction>) -> bool {
        self.transactions.contains_key(&hash)
    }

    /// Height of blockchain
    #[inline]
    pub fn height(&self) -> u64 {
        self.block_hashes.len() as u64
    }

    /// Return the hash of the latest block
    pub fn latest_block_hash(&self) -> Option<HashOf<SignedBlock>> {
        self.block_hashes.iter().nth_back(0).copied()
    }

    /// Return the view change index of the latest block
    pub fn latest_block_view_change_index(&self) -> u64 {
        self.kura
            .get_block_by_height(self.height())
            .map_or(0, |block| block.payload().header.view_change_index)
    }

    /// Return the hash of the block one before the latest block
    pub fn previous_block_hash(&self) -> Option<HashOf<SignedBlock>> {
        self.block_hashes.iter().nth_back(1).copied()
    }

    /// Get `Account` and pass it to closure.
    ///
    /// # Errors
    /// Fails if there is no domain or account
    pub fn map_account<'wsv, T>(
        &'wsv self,
        id: &AccountId,
        f: impl FnOnce(&'wsv Account) -> T,
    ) -> Result<T, QueryExecutionFail> {
        let domain = self.domain(&id.domain_id)?;
        let account = domain
            .accounts
            .get(id)
            .ok_or(FindError::Account(id.clone()))?;
        Ok(f(account))
    }

    /// Get `Account` and return reference to it.
    ///
    /// # Errors
    /// Fails if there is no domain or account
    pub fn account(&self, id: &AccountId) -> Result<&Account, FindError> {
        self.domain(&id.domain_id).and_then(|domain| {
            domain
                .accounts
                .get(id)
                .ok_or_else(|| FindError::Account(id.clone()))
        })
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

    /// Get an immutable iterator over the [`PeerId`]s.
    pub fn peers(&self) -> impl ExactSizeIterator<Item = &PeerId> {
        self.world.trusted_peers_ids.iter()
    }

    /// Get all `Parameter`s registered in the world.
    pub fn parameters(&self) -> impl ExactSizeIterator<Item = &Parameter> {
        self.world.parameters.iter()
    }

    /// Query parameter and convert it to a proper type
    pub fn query_param<T: TryFrom<Value>, P: core::hash::Hash + Eq + ?Sized>(
        &self,
        param: &P,
    ) -> Option<T>
    where
        Parameter: Borrow<P>,
    {
        self.world
            .parameters
            .get(param)
            .as_ref()
            .map(|param| &*param.val)
            .cloned()
            .and_then(|param_val| param_val.try_into().ok())
    }

    /// Get `AssetDefinition` immutable view.
    ///
    /// # Errors
    /// - Asset definition entry not found
    pub fn asset_definition(
        &self,
        asset_id: &AssetDefinitionId,
    ) -> Result<AssetDefinition, FindError> {
        self.domain(&asset_id.domain_id)?
            .asset_definitions
            .get(asset_id)
            .ok_or_else(|| FindError::AssetDefinition(asset_id.clone()))
            .map(Clone::clone)
    }

    /// Get total amount of [`Asset`].
    ///
    /// # Errors
    /// - Asset definition not found
    pub fn asset_total_amount(
        &self,
        definition_id: &AssetDefinitionId,
    ) -> Result<NumericValue, FindError> {
        self.domain(&definition_id.domain_id)?
            .asset_total_quantities
            .get(definition_id)
            .ok_or_else(|| FindError::AssetDefinition(definition_id.clone()))
            .copied()
    }

    /// Increase [`Asset`] total amount by given value
    ///
    /// # Errors
    /// - [`AssetDefinition`], [`Domain`] not found
    /// - Overflow
    pub fn increase_asset_total_amount<I>(
        &mut self,
        definition_id: &AssetDefinitionId,
        increment: I,
    ) -> Result<(), Error>
    where
        I: iroha_primitives::CheckedOp + Copy,
        NumericValue: From<I> + TryAsMut<I>,
        eyre::Error: From<<NumericValue as TryAsMut<I>>::Error>,
    {
        let domain = self.domain_mut(&definition_id.domain_id)?;
        let asset_total_amount: &mut I = domain
            .asset_total_quantities.get_mut(definition_id)
            .expect("Asset total amount not being found is a bug: check `Register<AssetDefinition>` to insert initial total amount")
            .try_as_mut()
            .map_err(eyre::Error::from)
            .map_err(|e| Error::Conversion(e.to_string()))?;
        *asset_total_amount = asset_total_amount
            .checked_add(increment)
            .ok_or(MathError::Overflow)?;
        let asset_total_amount = *asset_total_amount;

        self.emit_events({
            Some(DomainEvent::AssetDefinition(
                AssetDefinitionEvent::TotalQuantityChanged(AssetDefinitionTotalQuantityChanged {
                    asset_definition_id: definition_id.clone(),
                    total_amount: NumericValue::from(asset_total_amount),
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
    pub fn decrease_asset_total_amount<I>(
        &mut self,
        definition_id: &AssetDefinitionId,
        decrement: I,
    ) -> Result<(), Error>
    where
        I: iroha_primitives::CheckedOp + Copy,
        NumericValue: From<I> + TryAsMut<I>,
        eyre::Error: From<<NumericValue as TryAsMut<I>>::Error>,
    {
        let domain = self.domain_mut(&definition_id.domain_id)?;
        let asset_total_amount: &mut I = domain
            .asset_total_quantities.get_mut(definition_id)
            .expect("Asset total amount not being found is a bug: check `Register<AssetDefinition>` to insert initial total amount")
            .try_as_mut()
            .map_err(eyre::Error::from)
            .map_err(|e| Error::Conversion(e.to_string()))?;
        *asset_total_amount = asset_total_amount
            .checked_sub(decrement)
            .ok_or(MathError::NotEnoughQuantity)?;
        let asset_total_amount = *asset_total_amount;

        self.emit_events({
            Some(DomainEvent::AssetDefinition(
                AssetDefinitionEvent::TotalQuantityChanged(AssetDefinitionTotalQuantityChanged {
                    asset_definition_id: definition_id.clone(),
                    total_amount: NumericValue::from(asset_total_amount),
                }),
            ))
        });

        Ok(())
    }

    /// Find a [`SignedBlock`] by hash.
    pub fn block_with_tx(&self, hash: &HashOf<SignedTransaction>) -> Option<Arc<SignedBlock>> {
        let height = *self.transactions.get(hash)?;
        self.kura.get_block_by_height(height)
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

    /// Return mutable reference for triggers
    #[inline]
    pub fn triggers_mut(&mut self) -> &mut TriggerSet {
        &mut self.world.triggers
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

        self.world
            .triggers
            .handle_execute_trigger_event(event.clone());
        self.events_buffer.push(event.into());
    }

    /// Get [`Executor`].
    pub fn executor(&self) -> &Executor {
        &self.world.executor
    }

    /// The function puts events produced by iterator into `events_buffer`.
    /// Events should be produced in the order of expanding scope: from specific to general.
    /// Example: account events before domain events.
    pub fn emit_events<I: IntoIterator<Item = T>, T: Into<WorldEvent>>(&mut self, world_events: I) {
        let data_events: SmallVec<[DataEvent; 3]> = world_events
            .into_iter()
            .map(Into::into)
            .flat_map(WorldEvent::flatten)
            .collect();

        for event in data_events.iter() {
            self.world.triggers.handle_data_event(event.clone());
        }
        self.events_buffer
            .extend(data_events.into_iter().map(Into::into));
    }

    /// Set new permission token schema.
    ///
    /// Produces [`PermissionTokenSchemaUpdateEvent`].
    pub fn set_permission_token_schema(&mut self, schema: PermissionTokenSchema) {
        let old_schema = std::mem::replace(&mut self.world.permission_token_schema, schema.clone());
        self.emit_events(std::iter::once(WorldEvent::PermissionTokenSchemaUpdate(
            PermissionTokenSchemaUpdateEvent {
                old_schema,
                new_schema: schema,
            },
        )))
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

#[cfg(test)]
mod tests {
    use iroha_primitives::unique_vec::UniqueVec;

    use super::*;
    use crate::{block::ValidBlock, role::RoleIdWithOwner, sumeragi::network_topology::Topology};

    #[test]
    fn get_block_hashes_after_hash() {
        const BLOCK_CNT: usize = 10;

        let topology = Topology::new(UniqueVec::new());
        let block = ValidBlock::new_dummy().commit(&topology).unwrap();
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(World::default(), kura);

        let mut block_hashes = vec![];
        for i in 1..=BLOCK_CNT {
            let mut block = block.clone();

            block.0.payload_mut().header.height = i as u64;
            block.0.payload_mut().header.previous_block_hash = block_hashes.last().copied();

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

        let topology = Topology::new(UniqueVec::new());
        let block = ValidBlock::new_dummy().commit(&topology).unwrap();
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(World::default(), kura.clone());

        for i in 1..=BLOCK_CNT {
            let mut block = block.clone();

            let SignedBlock::V1(v1_block) = &mut block.0;
            v1_block.payload.header.height = i as u64;

            wsv.apply(&block).unwrap();
            kura.store_block(block);
        }

        assert_eq!(
            &wsv.all_blocks()
                .skip(7)
                .map(|block| block.payload().header.height)
                .collect::<Vec<_>>(),
            &[8, 9, 10]
        );
    }

    #[test]
    fn role_account_range() {
        let account_id: AccountId = "alice@wonderland".parse().unwrap();
        let roles = [
            RoleIdWithOwner::new(account_id.clone(), "1".parse().unwrap()),
            RoleIdWithOwner::new(account_id.clone(), "2".parse().unwrap()),
            RoleIdWithOwner::new("bob@wonderland".parse().unwrap(), "3".parse().unwrap()),
            RoleIdWithOwner::new("a@wonderland".parse().unwrap(), "4".parse().unwrap()),
            RoleIdWithOwner::new("0@0".parse().unwrap(), "5".parse().unwrap()),
            RoleIdWithOwner::new("1@1".parse().unwrap(), "6".parse().unwrap()),
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
