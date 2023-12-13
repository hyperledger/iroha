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

use indexmap::{map::Entry, IndexMap};
use iroha_crypto::HashOf;
use iroha_data_model::{
    events::Filter as EventFilter,
    isi::error::{InstructionExecutionError, MathError},
    prelude::*,
    query::error::FindError,
    transaction::WasmSmartContract,
    trigger::Trigger,
};
use serde::{
    de::{DeserializeSeed, MapAccess, Visitor},
    ser::{SerializeMap, SerializeStruct},
    Serialize, Serializer,
};
use thiserror::Error;

use crate::{smartcontracts::wasm, wsv::WasmSeed};

/// Error type for [`Set`] operations.
#[derive(Debug, Error, displaydoc::Display)]
pub enum Error {
    /// Failed to preload wasm trigger
    Preload(#[from] wasm::error::Error),
}

/// Result type for [`Set`] operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Same as [`Action`](`iroha_data_model::trigger::Action`) but with
/// executable in pre-loaded form
#[derive(Clone, Debug)]
pub struct LoadedAction<F> {
    /// The executable linked to this action in loaded form
    executable: LoadedExecutable,
    /// The repeating scheme of the action. It's kept as part of the
    /// action and not inside the [`Trigger`] type, so that further
    /// sanity checking can be done.
    pub repeats: Repeats,
    /// Account executing this action
    pub authority: AccountId,
    /// Defines events which trigger the `Action`
    pub filter: F,
    /// Metadata used as persistent storage for trigger data.
    pub metadata: Metadata,
}

impl<F> LoadedAction<F> {
    fn extract_blob_hash(&self) -> Option<HashOf<WasmSmartContract>> {
        match self.executable {
            LoadedExecutable::Wasm(LoadedWasm { blob_hash, .. }) => Some(blob_hash),
            LoadedExecutable::Instructions(_) => None,
        }
    }
}

/// Trait common for all `LoadedAction`s
pub trait LoadedActionTrait {
    /// Get action executable
    fn executable(&self) -> &LoadedExecutable;

    /// Get action repeats enum
    fn repeats(&self) -> &Repeats;

    /// Set action repeats
    fn set_repeats(&mut self, repeats: Repeats);

    /// Get action technical account
    fn authority(&self) -> &AccountId;

    /// Get action metadata
    fn metadata(&self) -> &Metadata;

    /// Check if action is mintable.
    fn mintable(&self) -> bool;

    /// Convert action to a boxed representation
    fn into_boxed(self) -> LoadedAction<TriggeringFilterBox>;

    /// Same as [`into_boxed()`](LoadedActionTrait::into_boxed) but clones `self`
    fn clone_and_box(&self) -> LoadedAction<TriggeringFilterBox>;
}

impl<F: Filter + Into<TriggeringFilterBox> + Clone> LoadedActionTrait for LoadedAction<F> {
    fn executable(&self) -> &LoadedExecutable {
        &self.executable
    }

    fn repeats(&self) -> &iroha_data_model::trigger::action::Repeats {
        &self.repeats
    }

    fn set_repeats(&mut self, repeats: iroha_data_model::trigger::action::Repeats) {
        self.repeats = repeats;
    }

    fn authority(&self) -> &AccountId {
        &self.authority
    }

    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn mintable(&self) -> bool {
        self.filter.mintable()
    }

    fn into_boxed(self) -> LoadedAction<TriggeringFilterBox> {
        let Self {
            executable,
            repeats,
            authority,
            filter,
            metadata,
        } = self;

        LoadedAction {
            executable,
            repeats,
            authority,
            filter: filter.into(),
            metadata,
        }
    }

    fn clone_and_box(&self) -> LoadedAction<TriggeringFilterBox> {
        self.clone().into_boxed()
    }
}

/// [`WasmSmartContract`]s by [`TriggerId`].
/// Stored together with number to count triggers with identical [`WasmSmartContract`].
type WasmSmartContractMap = IndexMap<HashOf<WasmSmartContract>, (WasmSmartContract, NonZeroU64)>;

/// Specialized structure that maps event filters to Triggers.
// NB: `Set` has custom `Serialize` and `DeserializeSeed` implementations
// which need to be manually updated when changing the struct
#[derive(Debug, Default)]
pub struct Set {
    /// Triggers using [`DataEventFilter`]
    data_triggers: IndexMap<TriggerId, LoadedAction<DataEventFilter>>,
    /// Triggers using [`PipelineEventFilter`]
    pipeline_triggers: IndexMap<TriggerId, LoadedAction<PipelineEventFilter>>,
    /// Triggers using [`TimeEventFilter`]
    time_triggers: IndexMap<TriggerId, LoadedAction<TimeEventFilter>>,
    /// Triggers using [`ExecuteTriggerEventFilter`]
    by_call_triggers: IndexMap<TriggerId, LoadedAction<ExecuteTriggerEventFilter>>,
    /// Trigger ids with type of events they process
    ids: IndexMap<TriggerId, TriggeringEventType>,
    /// Original [`WasmSmartContract`]s by [`TriggerId`] for querying purposes.
    original_contracts: WasmSmartContractMap,
    /// List of actions that should be triggered by events provided by `handle_*` methods.
    /// Vector is used to save the exact triggers order.
    matched_ids: Vec<(Event, TriggerId)>,
}

/// Helper struct for serializing triggers.
struct TriggersWithContext<'s, F> {
    /// Triggers being serialized
    triggers: &'s IndexMap<TriggerId, LoadedAction<F>>,
    /// Containing Set, used for looking up original [`WasmSmartContract`]s
    /// during serialization.
    set: &'s Set,
}

impl<'s, F> TriggersWithContext<'s, F> {
    fn new(triggers: &'s IndexMap<TriggerId, LoadedAction<F>>, set: &'s Set) -> Self {
        Self { triggers, set }
    }
}

impl<F: Clone + Serialize> Serialize for TriggersWithContext<'_, F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.triggers.len()))?;
        for (id, action) in self.triggers {
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
        let &Self {
            data_triggers,
            pipeline_triggers,
            time_triggers,
            by_call_triggers,
            ids,
            original_contracts: _original_contracts,
            matched_ids: _matched_ids,
        } = &self;
        let mut set = serializer.serialize_struct("Set", 6)?;
        set.serialize_field(
            "data_triggers",
            &TriggersWithContext::new(data_triggers, self),
        )?;
        set.serialize_field(
            "pipeline_triggers",
            &TriggersWithContext::new(pipeline_triggers, self),
        )?;
        set.serialize_field(
            "time_triggers",
            &TriggersWithContext::new(time_triggers, self),
        )?;
        set.serialize_field(
            "by_call_triggers",
            &TriggersWithContext::new(by_call_triggers, self),
        )?;
        set.serialize_field("ids", ids)?;
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
                let mut set = Set::default();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "data_triggers" => {
                            let triggers: IndexMap<TriggerId, Action<DataEventFilter>> =
                                map.next_value()?;
                            for (id, action) in triggers {
                                set.add_data_trigger(self.loader.engine, Trigger::new(id, action))
                                    .unwrap();
                            }
                        }
                        "pipeline_triggers" => {
                            let triggers: IndexMap<TriggerId, Action<PipelineEventFilter>> =
                                map.next_value()?;
                            for (id, action) in triggers {
                                set.add_pipeline_trigger(
                                    self.loader.engine,
                                    Trigger::new(id, action),
                                )
                                .unwrap();
                            }
                        }
                        "time_triggers" => {
                            let triggers: IndexMap<TriggerId, Action<TimeEventFilter>> =
                                map.next_value()?;
                            for (id, action) in triggers {
                                set.add_time_trigger(self.loader.engine, Trigger::new(id, action))
                                    .unwrap();
                            }
                        }
                        "by_call_triggers" => {
                            let triggers: IndexMap<TriggerId, Action<ExecuteTriggerEventFilter>> =
                                map.next_value()?;
                            for (id, action) in triggers {
                                set.add_by_call_trigger(
                                    self.loader.engine,
                                    Trigger::new(id, action),
                                )
                                .unwrap();
                            }
                        }
                        "ids" => {
                            set.ids = map.next_value()?;
                        }
                        _ => { /* Ignore unknown fields */ }
                    }
                }

                Ok(set)
            }
        }

        deserializer.deserialize_map(SetVisitor { loader: self })
    }
}

impl Clone for Set {
    fn clone(&self) -> Self {
        Self {
            data_triggers: self.data_triggers.clone(),
            pipeline_triggers: self.pipeline_triggers.clone(),
            time_triggers: self.time_triggers.clone(),
            by_call_triggers: self.by_call_triggers.clone(),
            ids: self.ids.clone(),
            original_contracts: self.original_contracts.clone(),
            matched_ids: Vec::default(),
        }
    }
}

impl Set {
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
        trigger: Trigger<DataEventFilter>,
    ) -> Result<bool> {
        self.add_to(engine, trigger, TriggeringEventType::Data, |me| {
            &mut me.data_triggers
        })
    }

    /// Add trigger with [`PipelineEventFilter`]
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
        trigger: Trigger<PipelineEventFilter>,
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
        trigger: Trigger<TimeEventFilter>,
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
        trigger: Trigger<ExecuteTriggerEventFilter>,
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
    fn add_to<F: Filter>(
        &mut self,
        engine: &wasmtime::Engine,
        trigger: Trigger<F>,
        event_type: TriggeringEventType,
        map: impl FnOnce(&mut Self) -> &mut IndexMap<TriggerId, LoadedAction<F>>,
    ) -> Result<bool> {
        if self.contains(trigger.id()) {
            return Ok(false);
        }

        let trigger_id = trigger.id;
        let Action {
            executable,
            repeats,
            authority,
            filter,
            metadata,
        } = trigger.action;

        let loaded_executable = match executable {
            Executable::Wasm(bytes) => {
                let hash = HashOf::new(&bytes);
                let loaded = LoadedExecutable::Wasm(LoadedWasm {
                    module: wasm::load_module(engine, &bytes)?,
                    blob_hash: hash,
                });
                // Store original executable representation to respond to queries with.
                self.original_contracts
                    .entry(hash)
                    .and_modify(|(_, count)| {
                        // Considering 1 trigger registration takes 1 second,
                        // it would take 584 942 417 355 years to overflow.
                        *count = count.checked_add(1).expect(
                            "There is no way someone could register 2^64 amount of same triggers",
                        )
                    })
                    .or_insert((bytes, NonZeroU64::MIN));
                loaded
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

    /// Get original [`WasmSmartContract`] for [`TriggerId`].
    /// Returns `None` if there's no [`Trigger`]
    /// with specified `id` that has WASM executable
    #[inline]
    pub fn get_original_contract(
        &self,
        hash: &HashOf<WasmSmartContract>,
    ) -> Option<&WasmSmartContract> {
        self.original_contracts
            .get(hash)
            .map(|(contract, _)| contract)
    }

    /// Convert [`LoadedAction`] to original [`Action`] by retrieving original
    /// [`WasmSmartContract`] if applicable
    pub fn get_original_action<F: Clone>(&self, action: LoadedAction<F>) -> Action<F> {
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

        Action {
            executable: original_executable,
            repeats,
            authority,
            filter,
            metadata,
        }
    }

    /// Get all contained trigger ids without a particular order
    #[inline]
    pub fn ids(&self) -> impl ExactSizeIterator<Item = &TriggerId> {
        self.ids.keys()
    }

    /// Get [`LoadedExecutable`] for given [`TriggerId`].
    /// Returns `None` if `id` is not in the set.
    pub fn get_executable(&self, id: &TriggerId) -> Option<&LoadedExecutable> {
        let event_type = self.ids.get(id)?;

        Some(match event_type {
            TriggeringEventType::Data => {
                &self
                    .data_triggers
                    .get(id)
                    .expect("`Set::data_triggers` doesn't contain required id. This is a bug")
                    .executable
            }
            TriggeringEventType::Pipeline => {
                &self
                    .pipeline_triggers
                    .get(id)
                    .expect("`Set::pipeline_triggers` doesn't contain required id. This is a bug")
                    .executable
            }
            TriggeringEventType::Time => {
                &self
                    .time_triggers
                    .get(id)
                    .expect("`Set::time_triggers` doesn't contain required id. This is a bug")
                    .executable
            }
            TriggeringEventType::ExecuteTrigger => {
                &self
                    .by_call_triggers
                    .get(id)
                    .expect("`Set::by_call_triggers` doesn't contain required id. This is a bug")
                    .executable
            }
        })
    }

    /// Apply `f` to triggers that belong to the given [`DomainId`]
    ///
    /// Return an empty list if [`Set`] doesn't contain any triggers belonging to [`DomainId`].
    pub fn inspect_by_domain_id<'a, F: 'a, R>(
        &'a self,
        domain_id: &DomainId,
        f: F,
    ) -> impl Iterator<Item = R> + '_
    where
        F: Fn(&TriggerId, &dyn LoadedActionTrait) -> R,
    {
        let domain_id = domain_id.clone();

        self.ids.iter().filter_map(move |(id, event_type)| {
            let trigger_domain_id = id.domain_id.as_ref()?;

            if *trigger_domain_id != domain_id {
                return None;
            }

            let result = match event_type {
                TriggeringEventType::Data => self
                    .data_triggers
                    .get(id)
                    .map(|trigger| f(id, trigger))
                    .expect("`Set::data_triggers` doesn't contain required id. This is a bug"),
                TriggeringEventType::Pipeline => self
                    .pipeline_triggers
                    .get(id)
                    .map(|trigger| f(id, trigger))
                    .expect("`Set::pipeline_triggers` doesn't contain required id. This is a bug"),
                TriggeringEventType::Time => self
                    .time_triggers
                    .get(id)
                    .map(|trigger| f(id, trigger))
                    .expect("`Set::time_triggers` doesn't contain required id. This is a bug"),
                TriggeringEventType::ExecuteTrigger => self
                    .by_call_triggers
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
    pub fn inspect_by_id<F, R>(&self, id: &TriggerId, f: F) -> Option<R>
    where
        F: Fn(&dyn LoadedActionTrait) -> R,
    {
        let event_type = self.ids.get(id).copied()?;

        let result = match event_type {
            TriggeringEventType::Data => self
                .data_triggers
                .get(id)
                .map(|entry| f(entry))
                .expect("`Set::data_triggers` doesn't contain required id. This is a bug"),
            TriggeringEventType::Pipeline => self
                .pipeline_triggers
                .get(id)
                .map(|entry| f(entry))
                .expect("`Set::pipeline_triggers` doesn't contain required id. This is a bug"),
            TriggeringEventType::Time => self
                .time_triggers
                .get(id)
                .map(|entry| f(entry))
                .expect("`Set::time_triggers` doesn't contain required id. This is a bug"),
            TriggeringEventType::ExecuteTrigger => self
                .by_call_triggers
                .get(id)
                .map(|entry| f(entry))
                .expect("`Set::by_call_triggers` doesn't contain required id. This is a bug"),
        };
        Some(result)
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
    pub fn remove(&mut self, id: &TriggerId) -> bool {
        let Some(event_type) = self.ids.remove(id) else {
            return false;
        };

        let removed = match event_type {
            TriggeringEventType::Data => {
                Self::remove_from(&mut self.original_contracts, &mut self.data_triggers, id)
            }
            TriggeringEventType::Pipeline => Self::remove_from(
                &mut self.original_contracts,
                &mut self.pipeline_triggers,
                id,
            ),
            TriggeringEventType::Time => {
                Self::remove_from(&mut self.original_contracts, &mut self.time_triggers, id)
            }
            TriggeringEventType::ExecuteTrigger => {
                Self::remove_from(&mut self.original_contracts, &mut self.by_call_triggers, id)
            }
        };

        assert!(
            removed,
            "`Set`'s `ids` and typed trigger collections are inconsistent. This is a bug"
        );

        true
    }

    /// Remove trigger from `triggers` and decrease the counter of the original [`WasmSmartContract`].
    ///
    /// Note that this function doesn't remove the trigger from [`Set::ids`].
    ///
    /// Returns `true` if trigger was removed and `false` otherwise.
    fn remove_from<F: Filter>(
        original_contracts: &mut WasmSmartContractMap,
        triggers: &mut IndexMap<TriggerId, LoadedAction<F>>,
        trigger_id: &TriggerId,
    ) -> bool {
        triggers
            .remove(trigger_id)
            .map(|loaded_action| {
                if let Some(blob_hash) = loaded_action.extract_blob_hash() {
                    Self::remove_original_trigger(original_contracts, blob_hash);
                }
            })
            .is_some()
    }

    /// Decrease the counter of the original [`WasmSmartContract`] by `blob_hash`
    /// or remove it if the counter reaches zero.
    ///
    /// # Panics
    ///
    /// Panics if `blob_hash` is not in the [`Set::original_contracts`].
    fn remove_original_trigger(
        original_contracts: &mut WasmSmartContractMap,
        blob_hash: HashOf<WasmSmartContract>,
    ) {
        #[allow(clippy::option_if_let_else)] // More readable this way
        match original_contracts.entry(blob_hash) {
            Entry::Occupied(mut entry) => {
                let count = &mut entry.get_mut().1;
                if let Some(new_count) = NonZeroU64::new(count.get() - 1) {
                    *count = new_count;
                } else {
                    entry.remove();
                }
            }
            Entry::Vacant(_) => {
                panic!("`Set::original_contracts` doesn't contain required hash. This is a bug")
            }
        }
    }

    /// Check if [`Set`] contains `id`.
    #[inline]
    pub fn contains(&self, id: &TriggerId) -> bool {
        self.ids.contains_key(id)
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

    /// Handle [`PipelineEvent`].
    ///
    /// Find all actions that are triggered by `event` and store them.
    /// These actions are inspected in the next [`Set::inspect_matched()`] call.
    // Passing by value to follow other `handle_` methods interface
    #[allow(clippy::needless_pass_by_value)]
    pub fn handle_pipeline_event(&mut self, event: PipelineEvent) {
        self.pipeline_triggers.iter().for_each(|entry| {
            Self::match_and_insert_trigger(&mut self.matched_ids, event.clone(), entry)
        });
    }

    /// Handle [`TimeEvent`].
    ///
    /// Find all actions that are triggered by `event` and store them.
    /// These actions are inspected in the next [`Set::inspect_matched()`] call.
    pub fn handle_time_event(&mut self, event: TimeEvent) {
        for (id, action) in &self.time_triggers {
            let mut count = action.filter.count_matches(&event);
            if let Repeats::Exactly(repeats) = action.repeats {
                count = min(repeats, count);
            }
            if count == 0 {
                continue;
            }

            let ids = core::iter::repeat_with(|| (Event::Time(event), id.clone())).take(
                count
                    .try_into()
                    .expect("`u32` should always fit in `usize`"),
            );
            self.matched_ids.extend(ids);
        }
    }

    /// Match and insert a [`TriggerId`] into the set of matched ids.
    ///
    /// Skips insertion:
    /// - If the action's filter doesn't match an event
    /// - If the action's repeats count equals to 0
    fn match_and_insert_trigger<E: Into<Event>, F: EventFilter<Event = E>>(
        matched_ids: &mut Vec<(Event, TriggerId)>,
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
            original_contracts,
            ..
        } = self;
        Self::remove_zeros(ids, original_contracts, data_triggers);
        Self::remove_zeros(ids, original_contracts, pipeline_triggers);
        Self::remove_zeros(ids, original_contracts, time_triggers);
        Self::remove_zeros(ids, original_contracts, by_call_triggers);
    }

    /// Remove actions with zero execution count from `triggers`
    fn remove_zeros<F: Filter>(
        ids: &mut IndexMap<TriggerId, TriggeringEventType>,
        original_contracts: &mut WasmSmartContractMap,
        triggers: &mut IndexMap<TriggerId, LoadedAction<F>>,
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
            ids.remove(&id)
                .and_then(|_| Self::remove_from(original_contracts, triggers, &id).then_some(()))
                .expect("`Set`'s `ids`, `original_contracts` and typed trigger collections are inconsistent. This is a bug")
        }
    }

    /// Extract `matched_id`
    pub fn extract_matched_ids(&mut self) -> Vec<(Event, TriggerId)> {
        core::mem::take(&mut self.matched_ids)
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
    Instructions(Vec<InstructionExpr>),
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
