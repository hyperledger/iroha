//! This module provides the [`WorldStateView`] — an in-memory representation of the current blockchain
//! state.
#![allow(
    clippy::new_without_default,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic_side_effects
)]

use std::{
    borrow::Borrow,
    collections::{BTreeSet, HashMap},
    convert::Infallible,
    fmt::Debug,
    sync::Arc,
    time::Duration,
};

use eyre::Result;
use iroha_config::{
    base::proxy::Builder,
    wsv::{Configuration, ConfigurationProxy},
};
use iroha_crypto::HashOf;
use iroha_data_model::{
    block::{CommittedBlock, VersionedCommittedBlock},
    isi::error::{InstructionExecutionError as Error, MathError},
    parameter::Parameter,
    prelude::*,
    query::error::{FindError, QueryExecutionFail},
    trigger::action::ActionTrait,
};
use iroha_logger::prelude::*;
use iroha_primitives::small::SmallVec;

#[cfg(test)]
use crate::validator::MockValidator as Validator;
#[cfg(not(test))]
use crate::validator::Validator;
use crate::{
    kura::Kura,
    smartcontracts::{
        triggers::{
            self,
            set::{LoadedExecutable, LoadedWasm, Set as TriggerSet},
        },
        wasm, Execute,
    },
    tx::TransactionValidator,
    DomainsMap, Parameters, PeersIds,
};

/// The global entity consisting of `domains`, `triggers` and etc.
/// For example registration of domain, will have this as an ISI target.
#[derive(Debug, Default, Clone)]
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
    /// Runtime Validator
    pub(crate) validator: Option<Validator>,
    /// New version of Validator, which will replace `validator` on the next
    /// [`validator_view()`](WorldStateView::validator_view) call.
    pub(crate) upgraded_validator: Option<Validator>,
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
    pub block_hashes: Vec<HashOf<VersionedCommittedBlock>>,
    /// Hashes of transactions mapped onto block height where they stored
    pub transactions: HashMap<HashOf<VersionedSignedTransaction>, u64>,
    /// Buffer containing events generated during `WorldStateView::apply`. Renewed on every block commit.
    pub events_buffer: Vec<Event>,
    /// Accumulated amount of any asset that has been transacted.
    pub metric_tx_amounts: f64,
    /// Count of how many mints, transfers and burns have happened.
    pub metric_tx_amounts_counter: u64,
    /// Engine for WASM [`Runtime`](wasm::Runtime) to execute triggers.
    pub engine: wasmtime::Engine,

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
            events_buffer: Vec::new(),
            metric_tx_amounts: 0.0_f64,
            metric_tx_amounts_counter: 0,
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
    pub fn account_assets(&self, id: &AccountId) -> Result<Vec<Asset>, QueryExecutionFail> {
        self.map_account(id, |account| account.assets.values().cloned().collect())
    }

    /// Return a set of all permission tokens granted to this account.
    pub fn account_permission_tokens(&self, account: &Account) -> BTreeSet<PermissionToken> {
        let mut tokens: BTreeSet<PermissionToken> =
            self.account_inherent_permission_tokens(account).collect();
        for role_id in &account.roles {
            if let Some(role) = self.world.roles.get(role_id) {
                tokens.append(&mut role.permissions.clone());
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
            .get(&account.id)
            .map_or_else(Default::default, Clone::clone)
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
            .get(account)
            .map_or(false, |permissions| permissions.contains(token))
    }

    /// Add [`permission`](PermissionToken) to the [`Account`] if the account does not have this permission yet.
    ///
    /// Return a Boolean value indicating whether or not the  [`Account`] already had this permission.
    pub fn add_account_permission(
        &mut self,
        account: &<Account as Identifiable>::Id,
        token: PermissionToken,
    ) -> bool {
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
        account: &<Account as Identifiable>::Id,
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
        action: &dyn ActionTrait<Executable = LoadedExecutable>,
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
                match self.process_trigger(&id, &action, event) {
                    Ok(_) => succeed.push(id),
                    Err(error) => errors.push(error),
                }
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
        instructions: impl IntoIterator<Item = InstructionBox>,
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
    #[iroha_logger::log(skip_all, fields(block_height))]
    pub fn apply(&mut self, block: &VersionedCommittedBlock) -> Result<()> {
        let hash = block.hash();
        let block = block.as_v1();
        iroha_logger::prelude::Span::current().record("block_height", block.header.height);
        trace!("Applying block");
        let time_event = self.create_time_event(block)?;
        self.events_buffer.push(Event::Time(time_event));

        self.execute_transactions(block)?;
        debug!("All block transactions successfully executed");

        self.world.triggers.handle_time_event(time_event);

        let res = self.process_triggers();

        if let Err(errors) = res {
            warn!(
                ?errors,
                "The following errors have occurred during trigger execution"
            );
        }

        self.block_hashes.push(hash);

        self.apply_parameters();

        Ok(())
    }

    fn apply_parameters(&mut self) {
        use iroha_data_model::parameter::default::*;
        macro_rules! update_params {
            ($ident:ident, $($param:expr => $config:expr),+ $(,)?) => {
                $(if let Some(param) = self.query_param($param) {
                    let mut $ident = &mut self.config;
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

    /// Get transaction validator
    pub fn transaction_validator(&self) -> TransactionValidator {
        TransactionValidator::new(self.config.borrow().transaction_limits)
    }

    /// Get a reference to the latest block. Returns none if genesis is not committed.
    #[inline]
    pub fn latest_block_ref(&self) -> Option<Arc<VersionedCommittedBlock>> {
        self.kura
            .get_block_by_height(self.block_hashes.len() as u64)
    }

    /// Create time event using previous and current blocks
    fn create_time_event(&self, block: &CommittedBlock) -> Result<TimeEvent> {
        let prev_interval = self
            .latest_block_ref()
            .map(|latest_block| {
                let header = &latest_block.as_v1().header;
                header.timestamp.try_into().map(|since| TimeInterval {
                    since: Duration::from_millis(since),
                    length: Duration::from_millis(header.consensus_estimation),
                })
            })
            .transpose()?;

        let interval = TimeInterval {
            since: Duration::from_millis(block.header.timestamp.try_into()?),
            length: Duration::from_millis(block.header.consensus_estimation),
        };

        Ok(TimeEvent {
            prev_interval,
            interval,
        })
    }

    /// Execute `block` transactions and store their hashes as well as
    /// `rejected_transactions` hashes
    ///
    /// # Errors
    /// Fails if transaction instruction execution fails
    fn execute_transactions(&mut self, block: &CommittedBlock) -> Result<()> {
        let height = block.header().height;
        // TODO: Should this block panic instead?
        for tx in &block.transactions {
            if tx.error.is_none() {
                self.process_executable(
                    tx.payload().instructions(),
                    tx.payload().authority.clone(),
                )?;
            }
            self.transactions.insert(tx.tx.hash(), height);
        }

        Ok(())
    }

    /// Get `Asset` by its id
    ///
    /// # Errors
    /// - No such [`Asset`]
    /// - The [`Account`] with which the [`Asset`] is associated doesn't exist.
    /// - The [`Domain`] with which the [`Account`] is associated doesn't exist.
    pub fn asset(&self, id: &<Asset as Identifiable>::Id) -> Result<Asset, QueryExecutionFail> {
        self.map_account(
            &id.account_id,
            |account| -> Result<Asset, QueryExecutionFail> {
                account
                    .assets
                    .get(id)
                    .ok_or_else(|| QueryExecutionFail::from(Box::new(FindError::Asset(id.clone()))))
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
        id: &<Asset as Identifiable>::Id,
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
    pub fn all_blocks(&self) -> impl DoubleEndedIterator<Item = Arc<VersionedCommittedBlock>> + '_ {
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
        hash: Option<HashOf<VersionedCommittedBlock>>,
    ) -> Vec<HashOf<VersionedCommittedBlock>> {
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

    /// Returns reference for trusted peer ids
    #[inline]
    pub fn peers_ids(&self) -> &PeersIds {
        &self.world.trusted_peers_ids
    }

    /// Return an iterator over blockchain block hashes starting with the block of the given `height`
    pub fn block_hashes_from_height(&self, height: usize) -> Vec<HashOf<VersionedCommittedBlock>> {
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
    pub fn domain(&self, id: &<Domain as Identifiable>::Id) -> Result<&Domain, FindError> {
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
        &mut self,
        id: &<Domain as Identifiable>::Id,
    ) -> Result<&mut Domain, FindError> {
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
        let value = f(domain).map_or_else(
            |_infallible| unreachable!("Returning `Infallible` should not be possible"),
            |value| value,
        );
        Ok(value)
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
            transactions: HashMap::new(),
            block_hashes: Vec::new(),
            events_buffer: Vec::new(),
            metric_tx_amounts: 0.0_f64,
            metric_tx_amounts_counter: 0,
            engine: wasm::create_engine(),
            kura,
        }
    }

    /// Returns [`Some`] milliseconds since the genesis block was
    /// committed, or [`None`] if it wasn't.
    #[inline]
    pub fn genesis_timestamp(&self) -> Option<u128> {
        if self.block_hashes.is_empty() {
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
    pub fn has_transaction(&self, hash: HashOf<VersionedSignedTransaction>) -> bool {
        self.transactions.contains_key(&hash)
    }

    /// Height of blockchain
    #[inline]
    pub fn height(&self) -> u64 {
        self.block_hashes.len() as u64
    }

    /// Return the hash of the latest block
    pub fn latest_block_hash(&self) -> Option<HashOf<VersionedCommittedBlock>> {
        self.block_hashes.iter().nth_back(0).copied()
    }

    /// Return the view change index of the latest block
    pub fn latest_block_view_change_index(&self) -> u64 {
        self.kura
            .get_block_by_height(self.height())
            .map_or(0, |block| block.as_v1().header.view_change_index)
    }

    /// Return the hash of the block one before the latest block
    pub fn previous_block_hash(&self) -> Option<HashOf<VersionedCommittedBlock>> {
        self.block_hashes.iter().nth_back(1).copied()
    }

    /// Get `Account` and pass it to closure.
    ///
    /// # Errors
    /// Fails if there is no domain or account
    pub fn map_account<T>(
        &self,
        id: &AccountId,
        f: impl FnOnce(&Account) -> T,
    ) -> Result<T, QueryExecutionFail> {
        let domain = self.domain(&id.domain_id)?;
        let account = domain
            .accounts
            .get(id)
            .ok_or(QueryExecutionFail::Unauthorized)?;
        Ok(f(account))
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
            .cloned()
            .collect::<Vec<Parameter>>()
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
        asset_id: &<AssetDefinition as Identifiable>::Id,
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
        definition_id: &<AssetDefinition as Identifiable>::Id,
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
        definition_id: &<AssetDefinition as Identifiable>::Id,
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
        definition_id: &<AssetDefinition as Identifiable>::Id,
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

    /// Get all transactions
    pub fn transaction_values(&self) -> Vec<TransactionQueryResult> {
        let mut txs = self
            .all_blocks()
            .flat_map(|block| {
                let block = block.as_v1();
                block
                    .transactions
                    .iter()
                    .cloned()
                    .map(|versioned_tx| TransactionQueryResult {
                        transaction: versioned_tx,
                        block_hash: block.hash(),
                    })
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
    ) -> Option<TransactionQueryResult> {
        let height = *self.transactions.get(hash)?;
        let block = self.kura.get_block_by_height(height)?;
        let block_hash = block.as_v1().hash();
        block
            .as_v1()
            .transactions
            .iter()
            .find(|e| e.tx.hash() == *hash)
            .cloned()
            .map(|tx| TransactionQueryResult {
                transaction: tx,
                block_hash,
            })
    }

    /// Get committed and rejected transaction of the account.
    pub fn transactions_values_by_account_id(
        &self,
        account_id: &AccountId,
    ) -> Vec<TransactionQueryResult> {
        let mut transactions = self
            .all_blocks()
            .flat_map(|block_entry| {
                let block = block_entry.as_v1();
                let block_hash = block.hash();

                block
                    .transactions
                    .iter()
                    .filter(|tx| &tx.payload().authority == account_id)
                    .cloned()
                    .map(|tx| TransactionQueryResult {
                        transaction: tx,
                        block_hash,
                    })
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

    /// Get constant view to a *Runtime Validator*.
    ///
    /// Performs lazy upgrade of the validator if [`Upgrade`] instruction was executed.
    ///
    /// # Panic
    ///
    /// Panics if validator is not initialized.
    /// Possible only before applying genesis.
    pub fn validator_view(&mut self) -> &Validator {
        {
            if let Some(upgraded_validator) = self.world.upgraded_validator.take() {
                self.world.validator.replace(upgraded_validator);
            }
        }

        #[cfg(test)]
        {
            self.world.validator.get_or_insert_with(Validator::default);
        }

        self.world
            .validator
            .as_ref()
            .expect("Must be initialized at this point")
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
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use super::*;
    use crate::block::PendingBlock;

    #[test]
    fn get_block_hashes_after_hash() {
        const BLOCK_CNT: usize = 10;

        let mut block = PendingBlock::new_dummy().commit_unchecked();
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(World::default(), kura);

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

        let mut block = PendingBlock::new_dummy().commit_unchecked();
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(World::default(), kura.clone());

        for i in 1..=BLOCK_CNT {
            block.header.height = i as u64;
            let block: VersionedCommittedBlock = block.clone().into();
            wsv.apply(&block).unwrap();
            kura.store_block(block);
        }

        assert_eq!(
            &wsv.all_blocks()
                .skip(7)
                .map(|block| block.as_v1().header.height)
                .collect::<Vec<_>>(),
            &[8, 9, 10]
        );
    }
}
