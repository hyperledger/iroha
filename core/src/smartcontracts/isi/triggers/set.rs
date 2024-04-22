//! Trigger logic. Instead of defining a Trigger as an entity, we
//! provide a collection of triggers as the smallest unit, which is an
//! idea borrowed from lisp hooks.
//!
//! The point of the idea is to create an ordering (or hash function)
//! which maps the event filter and the event that triggers it to the
//! same approximate location in the hierarchy, thus using Binary
//! search trees (common lisp) or hash tables (racket) to quickly
//! trigger hooks.

use core::cmp::min;
use std::{fmt, num::NonZeroU64};

use indexmap::IndexMap;
use iroha_crypto::HashOf;
use iroha_data_model::{
    events::EventFilter,
    isi::error::{InstructionExecutionError, MathError},
    prelude::*,
    query::error::FindError,
    transaction::WasmSmartContract,
};
use serde::{
    de::{DeserializeSeed, MapAccess, Visitor},
    ser::{SerializeMap, SerializeStruct},
    Serialize, Serializer,
};
use storage::{
    cell::{Block as CellBlock, Cell, Transaction as CellTransaction, View as CellView},
    storage::{
        Block as StorageBlock, Storage, StorageReadOnly, Transaction as StorageTransaction,
        View as StorageView,
    },
};
use thiserror::Error;

use crate::{
    smartcontracts::{
        isi::triggers::specialized::{
            LoadedAction, LoadedActionTrait, SpecializedAction, SpecializedTrigger,
        },
        wasm,
    },
    state::deserialize::WasmSeed,
};

/// Error type for [`Set`] operations.
#[derive(Debug, Error, displaydoc::Display)]
pub enum Error {
    /// Failed to preload wasm trigger
    Preload(#[from] wasm::error::Error),
}

/// Result type for [`Set`] operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// [`WasmSmartContract`]s by [`TriggerId`].
/// Stored together with number to count triggers with identical [`WasmSmartContract`].
type WasmSmartContractMap = Storage<HashOf<WasmSmartContract>, WasmSmartContractEntry>;
type WasmSmartContractMapBlock<'set> =
    StorageBlock<'set, HashOf<WasmSmartContract>, WasmSmartContractEntry>;
type WasmSmartContractMapTransaction<'block, 'set> =
    StorageTransaction<'block, 'set, HashOf<WasmSmartContract>, WasmSmartContractEntry>;
type WasmSmartContractMapView<'set> =
    StorageView<'set, HashOf<WasmSmartContract>, WasmSmartContractEntry>;

/// Specialized structure that maps event filters to Triggers.
// NB: `Set` has custom `Serialize` and `DeserializeSeed` implementations
// which need to be manually updated when changing the struct
#[derive(Default)]
pub struct Set {
    /// Triggers using [`DataEventFilter`]
    data_triggers: Storage<TriggerId, LoadedAction<DataEventFilter>>,
    /// Triggers using [`PipelineEventFilterBox`]
    pipeline_triggers: Storage<TriggerId, LoadedAction<PipelineEventFilterBox>>,
    /// Triggers using [`TimeEventFilter`]
    time_triggers: Storage<TriggerId, LoadedAction<TimeEventFilter>>,
    /// Triggers using [`ExecuteTriggerEventFilter`]
    by_call_triggers: Storage<TriggerId, LoadedAction<ExecuteTriggerEventFilter>>,
    /// Trigger ids with type of events they process
    ids: Storage<TriggerId, TriggeringEventType>,
    /// [`WasmSmartContract`]s map by hash for querying and optimization purposes.
    contracts: WasmSmartContractMap,
    /// List of actions that should be triggered by events provided by `handle_*` methods.
    /// Vector is used to save the exact triggers order.
    // NOTE: Cell is used because matched_ids changed as whole (not granularly)
    matched_ids: Cell<Vec<(EventBox, TriggerId)>>,
}

/// Trigger set for block's aggregated changes
pub struct SetBlock<'set> {
    /// Triggers using [`DataEventFilter`]
    data_triggers: StorageBlock<'set, TriggerId, LoadedAction<DataEventFilter>>,
    /// Triggers using [`PipelineEventFilterBox`]
    pipeline_triggers: StorageBlock<'set, TriggerId, LoadedAction<PipelineEventFilterBox>>,
    /// Triggers using [`TimeEventFilter`]
    time_triggers: StorageBlock<'set, TriggerId, LoadedAction<TimeEventFilter>>,
    /// Triggers using [`ExecuteTriggerEventFilter`]
    by_call_triggers: StorageBlock<'set, TriggerId, LoadedAction<ExecuteTriggerEventFilter>>,
    /// Trigger ids with type of events they process
    ids: StorageBlock<'set, TriggerId, TriggeringEventType>,
    /// Original [`WasmSmartContract`]s by [`TriggerId`] for querying purposes.
    contracts: WasmSmartContractMapBlock<'set>,
    /// List of actions that should be triggered by events provided by `handle_*` methods.
    /// Vector is used to save the exact triggers order.
    matched_ids: CellBlock<'set, Vec<(EventBox, TriggerId)>>,
}

/// Trigger set for transaction's aggregated changes
pub struct SetTransaction<'block, 'set> {
    /// Triggers using [`DataEventFilter`]
    data_triggers: StorageTransaction<'block, 'set, TriggerId, LoadedAction<DataEventFilter>>,
    /// Triggers using [`PipelineEventFilterBox`]
    pipeline_triggers:
        StorageTransaction<'block, 'set, TriggerId, LoadedAction<PipelineEventFilterBox>>,
    /// Triggers using [`TimeEventFilter`]
    time_triggers: StorageTransaction<'block, 'set, TriggerId, LoadedAction<TimeEventFilter>>,
    /// Triggers using [`ExecuteTriggerEventFilter`]
    by_call_triggers:
        StorageTransaction<'block, 'set, TriggerId, LoadedAction<ExecuteTriggerEventFilter>>,
    /// Trigger ids with type of events they process
    ids: StorageTransaction<'block, 'set, TriggerId, TriggeringEventType>,
    /// Original [`WasmSmartContract`]s by [`TriggerId`] for querying purposes.
    contracts: WasmSmartContractMapTransaction<'block, 'set>,
    /// List of actions that should be triggered by events provided by `handle_*` methods.
    /// Vector is used to save the exact triggers order.
    matched_ids: CellTransaction<'block, 'set, Vec<(EventBox, TriggerId)>>,
}

/// Consistent point in time view of the [`Set`]
pub struct SetView<'set> {
    /// Triggers using [`DataEventFilter`]
    data_triggers: StorageView<'set, TriggerId, LoadedAction<DataEventFilter>>,
    /// Triggers using [`PipelineEventFilterBox`]
    pipeline_triggers: StorageView<'set, TriggerId, LoadedAction<PipelineEventFilterBox>>,
    /// Triggers using [`TimeEventFilter`]
    time_triggers: StorageView<'set, TriggerId, LoadedAction<TimeEventFilter>>,
    /// Triggers using [`ExecuteTriggerEventFilter`]
    by_call_triggers: StorageView<'set, TriggerId, LoadedAction<ExecuteTriggerEventFilter>>,
    /// Trigger ids with type of events they process
    ids: StorageView<'set, TriggerId, TriggeringEventType>,
    /// Original [`WasmSmartContract`]s by [`TriggerId`] for querying purposes.
    contracts: WasmSmartContractMapView<'set>,
    /// List of actions that should be triggered by events provided by `handle_*` methods.
    /// Vector is used to save the exact triggers order.
    matched_ids: CellView<'set, Vec<(EventBox, TriggerId)>>,
}

/// Entry in wasm smart-contracts map
#[derive(Debug, Clone)]
struct WasmSmartContractEntry {
    /// Original wasm binary blob
    original_contract: WasmSmartContract,
    /// Compiled with [`wasmtime`] smart-contract
    compiled_contract: wasmtime::Module,
    /// Number of times this contract is used
    count: NonZeroU64,
}

/// Helper struct for serializing triggers.
struct TriggersWithContext<'s, F>
where
    F: storage::Value,
{
    /// Triggers being serialized
    triggers: &'s StorageView<'s, TriggerId, LoadedAction<F>>,
    /// Containing Set, used for looking up original [`WasmSmartContract`]s
    /// during serialization.
    set: &'s SetView<'s>,
}

impl<'s, F: storage::Value> TriggersWithContext<'s, F> {
    fn new(
        triggers: &'s StorageView<'s, TriggerId, LoadedAction<F>>,
        set: &'s SetView<'s>,
    ) -> Self {
        Self { triggers, set }
    }
}

impl<F: storage::Value + Serialize> Serialize for TriggersWithContext<'_, F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.triggers.len()))?;
        for (id, action) in self.triggers.iter() {
            let action = self.set.get_original_action(action.clone());
            map.serialize_entry(&id, &action)?;
        }
        map.end()
    }
}

impl Serialize for Set {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let set_view = self.view();
        let mut set = serializer.serialize_struct("Set", 6)?;
        set.serialize_field(
            "data_triggers",
            &TriggersWithContext::new(&set_view.data_triggers, &set_view),
        )?;
        set.serialize_field(
            "pipeline_triggers",
            &TriggersWithContext::new(&set_view.pipeline_triggers, &set_view),
        )?;
        set.serialize_field(
            "time_triggers",
            &TriggersWithContext::new(&set_view.time_triggers, &set_view),
        )?;
        set.serialize_field(
            "by_call_triggers",
            &TriggersWithContext::new(&set_view.by_call_triggers, &set_view),
        )?;
        set.serialize_field("ids", &self.ids)?;
        set.end()
    }
}

impl<'de> DeserializeSeed<'de> for WasmSeed<'_, Set> {
    type Value = Set;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SetVisitor<'e> {
            loader: WasmSeed<'e, Set>,
        }

        impl<'de> Visitor<'de> for SetVisitor<'_> {
            type Value = Set;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct Set")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let set = Set::default();
                let mut set_block = set.block();
                let mut set_transaction = set_block.transaction();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "data_triggers" => {
                            let triggers: IndexMap<TriggerId, SpecializedAction<DataEventFilter>> =
                                map.next_value()?;
                            for (id, action) in triggers {
                                set_transaction
                                    .add_data_trigger(
                                        self.loader.engine,
                                        SpecializedTrigger::new(id, action),
                                    )
                                    .unwrap();
                            }
                        }
                        "pipeline_triggers" => {
                            let triggers: IndexMap<
                                TriggerId,
                                SpecializedAction<PipelineEventFilterBox>,
                            > = map.next_value()?;
                            for (id, action) in triggers {
                                set_transaction
                                    .add_pipeline_trigger(
                                        self.loader.engine,
                                        SpecializedTrigger::new(id, action),
                                    )
                                    .unwrap();
                            }
                        }
                        "time_triggers" => {
                            let triggers: IndexMap<TriggerId, SpecializedAction<TimeEventFilter>> =
                                map.next_value()?;
                            for (id, action) in triggers {
                                set_transaction
                                    .add_time_trigger(
                                        self.loader.engine,
                                        SpecializedTrigger::new(id, action),
                                    )
                                    .unwrap();
                            }
                        }
                        "by_call_triggers" => {
                            let triggers: IndexMap<
                                TriggerId,
                                SpecializedAction<ExecuteTriggerEventFilter>,
                            > = map.next_value()?;
                            for (id, action) in triggers {
                                set_transaction
                                    .add_by_call_trigger(
                                        self.loader.engine,
                                        SpecializedTrigger::new(id, action),
                                    )
                                    .unwrap();
                            }
                        }
                        // TODO: ids look redundant because we insert ids already through `add_` methods
                        "ids" => {
                            let ids: IndexMap<TriggerId, TriggeringEventType> = map.next_value()?;
                            for (id, event_type) in ids {
                                set_transaction.ids.insert(id, event_type);
                            }
                        }
                        _ => { /* Ignore unknown fields */ }
                    }
                }
                set_transaction.apply();
                set_block.commit();

                Ok(set)
            }
        }

        deserializer.deserialize_map(SetVisitor { loader: self })
    }
}

/// Trait to perform read-only operations on [`WorldBlock`], [`WorldTransaction`] and [`WorldView`]
#[allow(missing_docs)]
pub trait SetReadOnly {
    fn data_triggers(&self) -> &impl StorageReadOnly<TriggerId, LoadedAction<DataEventFilter>>;
    fn pipeline_triggers(
        &self,
    ) -> &impl StorageReadOnly<TriggerId, LoadedAction<PipelineEventFilterBox>>;
    fn time_triggers(&self) -> &impl StorageReadOnly<TriggerId, LoadedAction<TimeEventFilter>>;
    fn by_call_triggers(
        &self,
    ) -> &impl StorageReadOnly<TriggerId, LoadedAction<ExecuteTriggerEventFilter>>;
    fn ids(&self) -> &impl StorageReadOnly<TriggerId, TriggeringEventType>;
    fn contracts(&self)
        -> &impl StorageReadOnly<HashOf<WasmSmartContract>, WasmSmartContractEntry>;
    fn matched_ids(&self) -> &[(EventBox, TriggerId)];

    /// Get original [`WasmSmartContract`] for [`TriggerId`].
    /// Returns `None` if there's no [`Trigger`]
    /// with specified `id` that has WASM executable
    #[inline]
    fn get_original_contract(
        &self,
        hash: &HashOf<WasmSmartContract>,
    ) -> Option<&WasmSmartContract> {
        self.contracts()
            .get(hash)
            .map(|entry| &entry.original_contract)
    }

    /// Convert [`LoadedAction`] to original [`Action`] by retrieving original
    /// [`WasmSmartContract`] if applicable
    fn get_original_action<F: Clone>(&self, action: LoadedAction<F>) -> SpecializedAction<F> {
        let LoadedAction {
            executable,
            repeats,
            authority,
            filter,
            metadata,
        } = action;

        let original_executable = match executable {
            LoadedExecutable::Wasm(LoadedWasm { ref blob_hash, .. }) => {
                let original_wasm = self
                    .get_original_contract(blob_hash)
                    .cloned()
                    .expect("No original smartcontract saved for trigger. This is a bug.");
                Executable::Wasm(original_wasm)
            }
            LoadedExecutable::Instructions(isi) => Executable::Instructions(isi),
        };

        SpecializedAction {
            executable: original_executable,
            repeats,
            authority,
            filter,
            metadata,
        }
    }

    /// Get all contained trigger ids without a particular order
    #[inline]
    fn ids_iter(&self) -> impl Iterator<Item = &TriggerId> {
        self.ids().iter().map(|(trigger_id, _)| trigger_id)
    }

    /// Get [`LoadedExecutable`] for given [`TriggerId`].
    /// Returns `None` if `id` is not in the set.
    fn get_executable(&self, id: &TriggerId) -> Option<&LoadedExecutable> {
        let event_type = self.ids().get(id)?;

        Some(match event_type {
            TriggeringEventType::Data => {
                &self
                    .data_triggers()
                    .get(id)
                    .expect("`Set::data_triggers` doesn't contain required id. This is a bug")
                    .executable
            }
            TriggeringEventType::Pipeline => {
                &self
                    .pipeline_triggers()
                    .get(id)
                    .expect("`Set::pipeline_triggers` doesn't contain required id. This is a bug")
                    .executable
            }
            TriggeringEventType::Time => {
                &self
                    .time_triggers()
                    .get(id)
                    .expect("`Set::time_triggers` doesn't contain required id. This is a bug")
                    .executable
            }
            TriggeringEventType::ExecuteTrigger => {
                &self
                    .by_call_triggers()
                    .get(id)
                    .expect("`Set::by_call_triggers` doesn't contain required id. This is a bug")
                    .executable
            }
        })
    }

    /// Apply `f` to triggers that belong to the given [`DomainId`]
    ///
    /// Return an empty list if [`Set`] doesn't contain any triggers belonging to [`DomainId`].
    fn inspect_by_domain_id<'a, F: 'a, R>(
        &'a self,
        domain_id: &DomainId,
        f: F,
    ) -> impl Iterator<Item = R> + '_
    where
        F: Fn(&TriggerId, &dyn LoadedActionTrait) -> R,
    {
        let domain_id = domain_id.clone();

        self.ids().iter().filter_map(move |(id, event_type)| {
            let trigger_domain_id = id.domain_id.as_ref()?;

            if *trigger_domain_id != domain_id {
                return None;
            }

            let result = match event_type {
                TriggeringEventType::Data => self
                    .data_triggers()
                    .get(id)
                    .map(|trigger| f(id, trigger))
                    .expect("`Set::data_triggers` doesn't contain required id. This is a bug"),
                TriggeringEventType::Pipeline => self
                    .pipeline_triggers()
                    .get(id)
                    .map(|trigger| f(id, trigger))
                    .expect("`Set::pipeline_triggers` doesn't contain required id. This is a bug"),
                TriggeringEventType::Time => self
                    .time_triggers()
                    .get(id)
                    .map(|trigger| f(id, trigger))
                    .expect("`Set::time_triggers` doesn't contain required id. This is a bug"),
                TriggeringEventType::ExecuteTrigger => self
                    .by_call_triggers()
                    .get(id)
                    .map(|trigger| f(id, trigger))
                    .expect("`Set::by_call_triggers` doesn't contain required id. This is a bug"),
            };

            Some(result)
        })
    }

    /// Apply `f` to the trigger identified by `id`.
    ///
    /// Return [`None`] if [`Set`] doesn't contain the trigger with the given `id`.
    fn inspect_by_id<F, R>(&self, id: &TriggerId, f: F) -> Option<R>
    where
        F: Fn(&dyn LoadedActionTrait) -> R,
    {
        let event_type = self.ids().get(id).copied()?;

        let result = match event_type {
            TriggeringEventType::Data => self
                .data_triggers()
                .get(id)
                .map(|entry| f(entry))
                .expect("`Set::data_triggers` doesn't contain required id. This is a bug"),
            TriggeringEventType::Pipeline => self
                .pipeline_triggers()
                .get(id)
                .map(|entry| f(entry))
                .expect("`Set::pipeline_triggers` doesn't contain required id. This is a bug"),
            TriggeringEventType::Time => self
                .time_triggers()
                .get(id)
                .map(|entry| f(entry))
                .expect("`Set::time_triggers` doesn't contain required id. This is a bug"),
            TriggeringEventType::ExecuteTrigger => self
                .by_call_triggers()
                .get(id)
                .map(|entry| f(entry))
                .expect("`Set::by_call_triggers` doesn't contain required id. This is a bug"),
        };
        Some(result)
    }
}

macro_rules! impl_set_ro {
    ($($ident:ty),*) => {$(
        impl SetReadOnly for $ident {
            fn data_triggers(&self) -> &impl StorageReadOnly<TriggerId, LoadedAction<DataEventFilter>> {
                &self.data_triggers
            }
            fn pipeline_triggers(&self) -> &impl StorageReadOnly<TriggerId, LoadedAction<PipelineEventFilterBox>> {
                &self.pipeline_triggers
            }
            fn time_triggers(&self) -> &impl StorageReadOnly<TriggerId, LoadedAction<TimeEventFilter>> {
                &self.time_triggers
            }
            fn by_call_triggers(&self) -> &impl StorageReadOnly<TriggerId, LoadedAction<ExecuteTriggerEventFilter>> {
                &self.by_call_triggers
            }
            fn ids(&self) -> &impl StorageReadOnly<TriggerId, TriggeringEventType> {
                &self.ids
            }
            fn contracts(&self) -> &impl StorageReadOnly<HashOf<WasmSmartContract>, WasmSmartContractEntry> {
                &self.contracts
            }
            fn matched_ids(&self) -> &[(EventBox, TriggerId)] {
                &self.matched_ids
            }
        }
    )*};
}

impl_set_ro! {
    SetBlock<'_>, SetTransaction<'_, '_>, SetView<'_>
}

impl Set {
    /// Create struct to apply block's changes
    pub fn block(&self) -> SetBlock<'_> {
        SetBlock {
            data_triggers: self.data_triggers.block(),
            pipeline_triggers: self.pipeline_triggers.block(),
            time_triggers: self.time_triggers.block(),
            by_call_triggers: self.by_call_triggers.block(),
            ids: self.ids.block(),
            contracts: self.contracts.block(),
            matched_ids: self.matched_ids.block(),
        }
    }

    /// Create struct to apply block's changes while reverting changes made in the latest block
    pub fn block_and_revert(&self) -> SetBlock<'_> {
        SetBlock {
            data_triggers: self.data_triggers.block_and_revert(),
            pipeline_triggers: self.pipeline_triggers.block_and_revert(),
            time_triggers: self.time_triggers.block_and_revert(),
            by_call_triggers: self.by_call_triggers.block_and_revert(),
            ids: self.ids.block_and_revert(),
            contracts: self.contracts.block_and_revert(),
            matched_ids: self.matched_ids.block_and_revert(),
        }
    }

    /// Create point in time view of the [`World`]
    pub fn view(&self) -> SetView<'_> {
        SetView {
            data_triggers: self.data_triggers.view(),
            pipeline_triggers: self.pipeline_triggers.view(),
            time_triggers: self.time_triggers.view(),
            by_call_triggers: self.by_call_triggers.view(),
            ids: self.ids.view(),
            contracts: self.contracts.view(),
            matched_ids: self.matched_ids.view(),
        }
    }
}

impl<'set> SetBlock<'set> {
    /// Create struct to apply transaction's changes
    pub fn transaction(&mut self) -> SetTransaction<'_, 'set> {
        SetTransaction {
            data_triggers: self.data_triggers.transaction(),
            pipeline_triggers: self.pipeline_triggers.transaction(),
            time_triggers: self.time_triggers.transaction(),
            by_call_triggers: self.by_call_triggers.transaction(),
            ids: self.ids.transaction(),
            contracts: self.contracts.transaction(),
            matched_ids: self.matched_ids.transaction(),
        }
    }

    /// Commit block's changes
    pub fn commit(self) {
        // NOTE: commit in reverse order
        self.matched_ids.commit();
        self.contracts.commit();
        self.ids.commit();
        self.by_call_triggers.commit();
        self.time_triggers.commit();
        self.pipeline_triggers.commit();
        self.data_triggers.commit();
    }

    /// Handle [`TimeEvent`].
    ///
    /// Find all actions that are triggered by `event` and store them.
    /// These actions are inspected in the next [`Set::inspect_matched()`] call.
    pub fn handle_time_event(&mut self, event: TimeEvent) {
        for (id, action) in self.time_triggers.iter() {
            let mut count = action.filter.count_matches(&event);
            if let Repeats::Exactly(repeats) = action.repeats {
                count = min(repeats, count);
            }
            if count == 0 {
                continue;
            }

            let ids = core::iter::repeat_with(|| (EventBox::Time(event), id.clone())).take(
                count
                    .try_into()
                    .expect("`u32` should always fit in `usize`"),
            );
            self.matched_ids.extend(ids);
        }
    }

    /// Extract `matched_id`
    pub fn extract_matched_ids(&mut self) -> Vec<(EventBox, TriggerId)> {
        core::mem::take(&mut self.matched_ids)
    }
}

impl<'block, 'set> SetTransaction<'block, 'set> {
    /// Apply transaction's changes
    pub fn apply(self) {
        // NOTE: apply in reverse order
        self.matched_ids.apply();
        self.contracts.apply();
        self.ids.apply();
        self.by_call_triggers.apply();
        self.time_triggers.apply();
        self.pipeline_triggers.apply();
        self.data_triggers.apply();
    }

    /// Add trigger with [`DataEventFilter`]
    ///
    /// Return `false` if a trigger with given id already exists
    ///
    /// # Errors
    ///
    /// Return [`Err`] if failed to preload wasm trigger
    #[inline]
    pub fn add_data_trigger(
        &mut self,
        engine: &wasmtime::Engine,
        trigger: SpecializedTrigger<DataEventFilter>,
    ) -> Result<bool> {
        self.add_to(engine, trigger, TriggeringEventType::Data, |me| {
            &mut me.data_triggers
        })
    }

    /// Add trigger with [`PipelineEventFilterBox`]
    ///
    /// Return `false` if a trigger with given id already exists
    ///
    /// # Errors
    ///
    /// Return [`Err`] if failed to preload wasm trigger
    #[inline]
    pub fn add_pipeline_trigger(
        &mut self,
        engine: &wasmtime::Engine,
        trigger: SpecializedTrigger<PipelineEventFilterBox>,
    ) -> Result<bool> {
        self.add_to(engine, trigger, TriggeringEventType::Pipeline, |me| {
            &mut me.pipeline_triggers
        })
    }

    /// Add trigger with [`TimeEventFilter`]
    ///
    /// Returns `false` if a trigger with given id already exists
    ///
    /// # Errors
    ///
    /// Return [`Err`] if failed to preload wasm trigger
    #[inline]
    pub fn add_time_trigger(
        &mut self,
        engine: &wasmtime::Engine,
        trigger: SpecializedTrigger<TimeEventFilter>,
    ) -> Result<bool> {
        self.add_to(engine, trigger, TriggeringEventType::Time, |me| {
            &mut me.time_triggers
        })
    }

    /// Add trigger with [`ExecuteTriggerEventFilter`]
    ///
    /// Returns `false` if a trigger with given id already exists
    ///
    /// # Errors
    ///
    /// Return [`Err`] if failed to preload wasm trigger
    #[inline]
    pub fn add_by_call_trigger(
        &mut self,
        engine: &wasmtime::Engine,
        trigger: SpecializedTrigger<ExecuteTriggerEventFilter>,
    ) -> Result<bool> {
        self.add_to(engine, trigger, TriggeringEventType::ExecuteTrigger, |me| {
            &mut me.by_call_triggers
        })
    }

    /// Add generic trigger to generic collection
    ///
    /// Returns `false` if a trigger with given id already exists
    ///
    /// # Errors
    ///
    /// Return [`Err`] if failed to preload wasm trigger
    fn add_to<F: storage::Value + EventFilter>(
        &mut self,
        engine: &wasmtime::Engine,
        trigger: SpecializedTrigger<F>,
        event_type: TriggeringEventType,
        map: impl FnOnce(&mut Self) -> &mut StorageTransaction<'block, 'set, TriggerId, LoadedAction<F>>,
    ) -> Result<bool> {
        let SpecializedTrigger {
            id: trigger_id,
            action:
                SpecializedAction {
                    executable,
                    repeats,
                    authority,
                    filter,
                    metadata,
                },
        } = trigger;

        if self.ids.get(&trigger_id).is_some() {
            return Ok(false);
        }

        let loaded_executable = match executable {
            Executable::Wasm(bytes) => {
                let hash = HashOf::new(&bytes);
                // Store original executable representation to respond to queries with.
                let module = if let Some(WasmSmartContractEntry {
                    compiled_contract,
                    count,
                    ..
                }) = self.contracts.get_mut(&hash)
                {
                    // Considering 1 trigger registration takes 1 second,
                    // it would take 584 942 417 355 years to overflow.
                    *count = count.checked_add(1).expect(
                        "There is no way someone could register 2^64 amount of same triggers",
                    );
                    // Cloning module is cheap, under Arc inside
                    compiled_contract.clone()
                } else {
                    let module = wasm::load_module(engine, &bytes)?;
                    // Cloning module is cheap, under Arc inside
                    self.contracts.insert(
                        hash,
                        WasmSmartContractEntry {
                            original_contract: bytes,
                            compiled_contract: module.clone(),
                            count: NonZeroU64::MIN,
                        },
                    );
                    module
                };
                LoadedExecutable::Wasm(LoadedWasm {
                    module,
                    blob_hash: hash,
                })
            }
            Executable::Instructions(instructions) => LoadedExecutable::Instructions(instructions),
        };
        map(self).insert(
            trigger_id.clone(),
            LoadedAction {
                executable: loaded_executable,
                repeats,
                authority,
                filter,
                metadata,
            },
        );
        self.ids.insert(trigger_id, event_type);
        Ok(true)
    }

    /// Apply `f` to the trigger identified by `id`.
    ///
    /// Return [`None`] if [`Set`] doesn't contain the trigger with the given `id`.
    pub fn inspect_by_id_mut<F, R>(&mut self, id: &TriggerId, f: F) -> Option<R>
    where
        F: Fn(&mut dyn LoadedActionTrait) -> R,
    {
        let event_type = self.ids.get(id).copied()?;

        let result = match event_type {
            TriggeringEventType::Data => self
                .data_triggers
                .get_mut(id)
                .map(|entry| f(entry))
                .expect("`Set::data_triggers` doesn't contain required id. This is a bug"),
            TriggeringEventType::Pipeline => self
                .pipeline_triggers
                .get_mut(id)
                .map(|entry| f(entry))
                .expect("`Set::pipeline_triggers` doesn't contain required id. This is a bug"),
            TriggeringEventType::Time => self
                .time_triggers
                .get_mut(id)
                .map(|entry| f(entry))
                .expect("`Set::time_triggers` doesn't contain required id. This is a bug"),
            TriggeringEventType::ExecuteTrigger => self
                .by_call_triggers
                .get_mut(id)
                .map(|entry| f(entry))
                .expect("`Set::by_call_triggers` doesn't contain required id. This is a bug"),
        };
        Some(result)
    }

    /// Remove a trigger from the [`Set`].
    ///
    /// Return `false` if [`Set`] doesn't contain the trigger with the given `id`.
    ///
    /// # Panics
    ///
    /// Panics on inconsistent state of [`Set`]. This is a bug.
    pub fn remove(&mut self, id: TriggerId) -> bool {
        let Some(event_type) = self.ids.remove(id.clone()) else {
            return false;
        };

        let removed = match event_type {
            TriggeringEventType::Data => {
                Self::remove_from(&mut self.contracts, &mut self.data_triggers, id)
            }
            TriggeringEventType::Pipeline => {
                Self::remove_from(&mut self.contracts, &mut self.pipeline_triggers, id)
            }
            TriggeringEventType::Time => {
                Self::remove_from(&mut self.contracts, &mut self.time_triggers, id)
            }
            TriggeringEventType::ExecuteTrigger => {
                Self::remove_from(&mut self.contracts, &mut self.by_call_triggers, id)
            }
        };

        assert!(
            removed,
            "`Set`'s `ids` and typed trigger collections are inconsistent. This is a bug"
        );

        true
    }

    /// Modify repetitions of the hook identified by [`Id`].
    ///
    /// # Errors
    ///
    /// - If a trigger with the given id is not found.
    /// - If updating the current trigger `repeats` causes an overflow. Indefinitely
    /// repeating triggers and triggers set for exact time always cause an overflow.
    pub fn mod_repeats(
        &mut self,
        id: &TriggerId,
        f: impl Fn(u32) -> Result<u32, RepeatsOverflowError>,
    ) -> Result<(), ModRepeatsError> {
        self.inspect_by_id_mut(id, |action| match action.repeats() {
            Repeats::Exactly(repeats) => {
                let new_repeats = f(*repeats)?;
                action.set_repeats(Repeats::Exactly(new_repeats));
                Ok(())
            }
            _ => Err(ModRepeatsError::RepeatsOverflow(RepeatsOverflowError)),
        })
        .ok_or_else(|| ModRepeatsError::NotFound(id.clone()))
        // .flatten() -- unstable
        .and_then(std::convert::identity)
    }

    /// Remove trigger from `triggers` and decrease the counter of the original [`WasmSmartContract`].
    ///
    /// Note that this function doesn't remove the trigger from [`Set::ids`].
    ///
    /// Returns `true` if trigger was removed and `false` otherwise.
    fn remove_from<F: storage::Value + EventFilter>(
        contracts: &mut WasmSmartContractMapTransaction<'block, 'set>,
        triggers: &mut StorageTransaction<'block, 'set, TriggerId, LoadedAction<F>>,
        trigger_id: TriggerId,
    ) -> bool {
        triggers
            .remove(trigger_id)
            .map(|loaded_action| {
                if let Some(blob_hash) = loaded_action.extract_blob_hash() {
                    Self::remove_original_trigger(contracts, blob_hash);
                }
            })
            .is_some()
    }

    /// Decrease the counter of the original [`WasmSmartContract`] by `blob_hash`
    /// or remove it if the counter reaches zero.
    ///
    /// # Panics
    ///
    /// Panics if `blob_hash` is not in the [`Set::contracts`].
    fn remove_original_trigger(
        contracts: &mut WasmSmartContractMapTransaction,
        blob_hash: HashOf<WasmSmartContract>,
    ) {
        #[allow(clippy::option_if_let_else)] // More readable this way
        match contracts.get_mut(&blob_hash) {
            Some(entry) => {
                let count = &mut entry.count;
                if let Some(new_count) = NonZeroU64::new(count.get() - 1) {
                    *count = new_count;
                } else {
                    contracts.remove(blob_hash);
                }
            }
            None => {
                panic!("`Set::contracts` doesn't contain required hash. This is a bug")
            }
        }
    }

    /// Decrease `action`s for provided triggers and remove those whose counter reached zero.
    pub fn decrease_repeats(&mut self, triggers: &[TriggerId]) {
        for id in triggers {
            // Ignoring error if trigger has not `Repeats::Exact(_)` but something else
            let _mod_repeats_res = self.mod_repeats(id, |n| Ok(n.saturating_sub(1)));
        }

        let Self {
            data_triggers,
            pipeline_triggers,
            time_triggers,
            by_call_triggers,
            ids,
            contracts,
            ..
        } = self;
        Self::remove_zeros(ids, contracts, data_triggers);
        Self::remove_zeros(ids, contracts, pipeline_triggers);
        Self::remove_zeros(ids, contracts, time_triggers);
        Self::remove_zeros(ids, contracts, by_call_triggers);
    }

    /// Remove actions with zero execution count from `triggers`
    fn remove_zeros<F: storage::Value + EventFilter>(
        ids: &mut StorageTransaction<'block, 'set, TriggerId, TriggeringEventType>,
        contracts: &mut WasmSmartContractMapTransaction<'block, 'set>,
        triggers: &mut StorageTransaction<'block, 'set, TriggerId, LoadedAction<F>>,
    ) {
        let to_remove: Vec<TriggerId> = triggers
            .iter()
            .filter_map(|(id, action)| {
                if let Repeats::Exactly(0) = action.repeats {
                    return Some(id.clone());
                }
                None
            })
            .collect();

        for id in to_remove {
            ids.remove(id.clone())
                .and_then(|_| Self::remove_from(contracts, triggers, id).then_some(()))
                .expect("`Set`'s `ids`, `contracts` and typed trigger collections are inconsistent. This is a bug")
        }
    }

    /// Handle [`DataEvent`].
    ///
    /// Finds all actions, that are triggered by `event` and stores them.
    /// This actions will be inspected in the next [`Set::handle_data_event()`] call
    // Passing by value to follow other `handle_` methods interface
    #[allow(clippy::needless_pass_by_value)]
    pub fn handle_data_event(&mut self, event: DataEvent) {
        self.data_triggers
            .iter()
            .filter(|(id, _)| id.domain_id.is_none() || id.domain_id.as_ref() == event.domain_id())
            .for_each(|entry| {
                Self::match_and_insert_trigger(&mut self.matched_ids, event.clone(), entry)
            });
    }

    /// Handle [`ExecuteTriggerEvent`].
    ///
    /// Find all actions that are triggered by `event` and store them.
    /// These actions are inspected in the next [`Set::inspect_matched()`] call.
    pub fn handle_execute_trigger_event(&mut self, event: ExecuteTriggerEvent) {
        if let Some(action) = self.by_call_triggers.get(&event.trigger_id) {
            let id = event.trigger_id.clone();
            Self::match_and_insert_trigger(&mut self.matched_ids, event, (&id, action));
        };
    }

    /// Match and insert a [`TriggerId`] into the set of matched ids.
    ///
    /// Skips insertion:
    /// - If the action's filter doesn't match an event
    /// - If the action's repeats count equals to 0
    fn match_and_insert_trigger<E: Into<EventBox>, F: EventFilter<Event = E>>(
        matched_ids: &mut Vec<(EventBox, TriggerId)>,
        event: E,
        (id, action): (&TriggerId, &LoadedAction<F>),
    ) {
        if !action.filter.matches(&event) {
            return;
        }

        if let Repeats::Exactly(repeats) = action.repeats {
            if repeats == 0 {
                return;
            }
        }

        matched_ids.push((event.into(), id.clone()));
    }
}

/// WASM blob loaded with `wasmtime`
#[derive(Clone)]
pub struct LoadedWasm {
    /// Loaded Module
    pub module: wasmtime::Module,
    /// Hash of original WASM blob on blockchain
    pub blob_hash: HashOf<WasmSmartContract>,
}

/// Same as [`Executable`](iroha_data_model::transaction::Executable), but instead of
/// [`Wasm`](iroha_data_model::transaction::Executable::Wasm) contains WASM module as loaded
/// by `wasmtime`
#[derive(Clone)]
pub enum LoadedExecutable {
    /// Loaded WASM
    Wasm(LoadedWasm),
    /// Vector of ISI
    Instructions(Vec<InstructionBox>),
}

impl core::fmt::Debug for LoadedExecutable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wasm(_) => f
                .debug_tuple("Wasm")
                .field(&"<Wasm module is truncated>")
                .finish(),
            Self::Instructions(instructions) => {
                f.debug_tuple("Instructions").field(instructions).finish()
            }
        }
    }
}

/// [`Set::mod_repeats()`] error
#[derive(Debug, Clone, thiserror::Error, displaydoc::Display)]
pub enum ModRepeatsError {
    /// Trigger with id = `{0}` not found
    NotFound(TriggerId),
    /// Trigger repeats count overflow error
    RepeatsOverflow(#[from] RepeatsOverflowError),
}

/// Trigger repeats count overflow
#[derive(Debug, Copy, Clone, thiserror::Error, displaydoc::Display)]
pub struct RepeatsOverflowError;

impl From<ModRepeatsError> for InstructionExecutionError {
    fn from(err: ModRepeatsError) -> Self {
        match err {
            ModRepeatsError::NotFound(not_found_id) => FindError::Trigger(not_found_id).into(),
            ModRepeatsError::RepeatsOverflow(_) => MathError::Overflow.into(),
        }
    }
}
