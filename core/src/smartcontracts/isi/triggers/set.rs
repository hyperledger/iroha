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
use std::{fmt, sync::RwLock};

use dashmap::DashMap;
use iroha_data_model::{
    events::Filter as EventFilter,
    isi::error::{InstructionExecutionFailure, MathError},
    prelude::*,
    query::error::FindError,
    trigger::action::ActionTrait,
};
use thiserror::Error;

use crate::smartcontracts::wasm;

/// Error type for [`Set`] operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Preloading error
    #[error("Failed to preload wasm trigger: {0}")]
    Preload(#[from] wasm::Error),
}

/// Result type for [`Set`] operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Type of action with pre-loaded executable.
pub type LoadedAction<F> = Action<F, LoadedExecutable>;

/// Specialized structure that maps event filters to Triggers.
pub struct Set {
    /// Triggers using [`DataEventFilter`]
    data_triggers: DashMap<TriggerId, LoadedAction<DataEventFilter>>,
    /// Triggers using [`PipelineEventFilter`]
    pipeline_triggers: DashMap<TriggerId, LoadedAction<PipelineEventFilter>>,
    /// Triggers using [`TimeEventFilter`]
    time_triggers: DashMap<TriggerId, LoadedAction<TimeEventFilter>>,
    /// Triggers using [`ExecuteTriggerEventFilter`]
    by_call_triggers: DashMap<TriggerId, LoadedAction<ExecuteTriggerEventFilter>>,
    /// Trigger ids with type of events they process
    ids: DashMap<TriggerId, EventType>,
    /// List of actions that should be triggered by events provided by `handle_*` methods.
    /// Vector is used to save the exact triggers order.
    /// Not being cloned
    matched_ids: RwLock<Vec<(Event, TriggerId)>>,
    /// Engine for WASM [`Runtime`](wasm::Runtime) to execute triggers.
    engine: wasmtime::Engine,
}

impl fmt::Debug for Set {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Set")
            .field("data_triggers", &self.data_triggers)
            .field("pipeline_triggers", &self.pipeline_triggers)
            .field("time_triggers", &self.time_triggers)
            .field("by_call_triggers", &self.by_call_triggers)
            .field("ids", &self.ids)
            .field("matched_ids", &self.matched_ids)
            .field("engine", &"<Engine is truncated>")
            .finish()
    }
}

impl Default for Set {
    fn default() -> Self {
        Self {
            data_triggers: DashMap::default(),
            pipeline_triggers: DashMap::default(),
            time_triggers: DashMap::default(),
            by_call_triggers: DashMap::default(),
            ids: DashMap::default(),
            matched_ids: RwLock::new(Vec::default()),
            engine: wasm::create_engine(),
        }
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
            matched_ids: RwLock::new(Vec::new()),
            engine: self.engine.clone(),
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
    pub fn add_data_trigger(&self, trigger: Trigger<DataEventFilter, Executable>) -> Result<bool> {
        self.add_to(trigger, EventType::Data, &self.data_triggers)
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
        &self,
        trigger: Trigger<PipelineEventFilter, Executable>,
    ) -> Result<bool> {
        self.add_to(trigger, EventType::Pipeline, &self.pipeline_triggers)
    }

    /// Add trigger with [`TimeEventFilter`]
    ///
    /// Returns `false` if a trigger with given id already exists
    ///
    /// # Errors
    ///
    /// Return [`Err`] if failed to preload wasm trigger
    #[inline]
    pub fn add_time_trigger(&self, trigger: Trigger<TimeEventFilter, Executable>) -> Result<bool> {
        self.add_to(trigger, EventType::Time, &self.time_triggers)
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
        &self,
        trigger: Trigger<ExecuteTriggerEventFilter, Executable>,
    ) -> Result<bool> {
        self.add_to(trigger, EventType::ExecuteTrigger, &self.by_call_triggers)
    }

    /// Add generic trigger to generic collection
    ///
    /// Returns `false` if a trigger with given id already exists
    ///
    /// # Errors
    ///
    /// Return [`Err`] if failed to preload wasm trigger
    fn add_to<F: Filter>(
        &self,
        trigger: Trigger<F, Executable>,
        event_type: EventType,
        map: &DashMap<TriggerId, LoadedAction<F>>,
    ) -> Result<bool> {
        if self.contains(trigger.id()) {
            return Ok(false);
        }

        let trigger_id = trigger.id;
        let Action {
            executable,
            repeats,
            technical_account,
            filter,
            metadata,
        } = trigger.action;

        let loaded_executable = match executable {
            Executable::Wasm(bytes) => {
                LoadedExecutable::Wasm(wasm::load_module(&self.engine, bytes)?)
            }
            Executable::Instructions(instructions) => LoadedExecutable::Instructions(instructions),
        };

        map.insert(
            trigger_id.clone(),
            LoadedAction {
                executable: loaded_executable,
                repeats,
                technical_account,
                filter,
                metadata,
            },
        );
        self.ids.insert(trigger_id, event_type);
        Ok(true)
    }

    /// Get all contained trigger ids without a particular order
    #[inline]
    pub fn ids(&self) -> Vec<TriggerId> {
        self.ids.iter().map(|entry| entry.key().clone()).collect()
    }

    /// Apply `f` to triggers that belong to the given [`DomainId`]
    ///
    /// Return an empty list if [`Set`] doesn't contain any triggers belonging to [`DomainId`].
    pub fn inspect_by_domain_id<F, R>(&self, domain_id: &DomainId, f: F) -> Vec<R>
    where
        F: Fn(&TriggerId, &dyn ActionTrait<Executable = LoadedExecutable>) -> R,
    {
        self.ids
            .iter()
            .filter_map(|pair| {
                let id = pair.key();
                let trigger_domain_id = id.domain_id.as_ref()?;

                if trigger_domain_id != domain_id {
                    return None;
                }

                let event_type = pair.value();

                let result = match event_type {
                    EventType::Data => self
                        .data_triggers
                        .get(id)
                        .map(|entry| f(id, entry.value()))
                        .expect("`Set::data_triggers` doesn't contain required id. This is a bug"),
                    EventType::Pipeline => self
                        .pipeline_triggers
                        .get(id)
                        .map(|entry| f(id, entry.value()))
                        .expect(
                            "`Set::pipeline_triggers` doesn't contain required id. This is a bug",
                        ),
                    EventType::Time => self
                        .time_triggers
                        .get(id)
                        .map(|entry| f(id, entry.value()))
                        .expect("`Set::time_triggers` doesn't contain required id. This is a bug"),
                    EventType::ExecuteTrigger => self
                        .by_call_triggers
                        .get(id)
                        .map(|entry| f(id, entry.value()))
                        .expect(
                            "`Set::by_call_triggers` doesn't contain required id. This is a bug",
                        ),
                };

                Some(result)
            })
            .collect()
    }

    /// Apply `f` to the trigger identified by `id`
    ///
    /// Return [`None`] if [`Set`] doesn't contain the trigger with the given `id`.
    pub fn inspect_by_id<F, R>(&self, id: &TriggerId, f: F) -> Option<R>
    where
        F: Fn(&dyn ActionTrait<Executable = LoadedExecutable>) -> R,
    {
        self.ids.get(id).map(|pair| match pair.value() {
            EventType::Data => self
                .data_triggers
                .get(id)
                .map(|entry| f(entry.value()))
                .expect("`Set::data_triggers` doesn't contain required id. This is a bug"),
            EventType::Pipeline => self
                .pipeline_triggers
                .get(id)
                .map(|entry| f(entry.value()))
                .expect("`Set::pipeline_triggers` doesn't contain required id. This is a bug"),
            EventType::Time => self
                .time_triggers
                .get(id)
                .map(|entry| f(entry.value()))
                .expect("`Set::time_triggers` doesn't contain required id. This is a bug"),
            EventType::ExecuteTrigger => self
                .by_call_triggers
                .get(id)
                .map(|entry| f(entry.value()))
                .expect("`Set::by_call_triggers` doesn't contain required id. This is a bug"),
        })
    }

    /// Remove a trigger from the [`Set`].
    ///
    /// Return `false` if [`Set`] doesn't contain the trigger with the given `id`.
    pub fn remove(&self, id: &TriggerId) -> bool {
        self.ids
            .remove(id)
            .map(|(_, event_type)| match event_type {
                EventType::Data => self
                    .data_triggers
                    .remove(id)
                    .map(|_| ())
                    .expect("`Set::data_triggers` doesn't contain required id. This is a bug"),
                EventType::Pipeline => {
                    self.pipeline_triggers.remove(id).map(|_| ()).expect(
                        "`Set::pipeline_triggers` doesn't contain required id. This is a bug",
                    )
                }
                EventType::Time => self
                    .time_triggers
                    .remove(id)
                    .map(|_| ())
                    .expect("`Set::time_triggers` doesn't contain required id. This is a bug"),
                EventType::ExecuteTrigger => {
                    self.by_call_triggers.remove(id).map(|_| ()).expect(
                        "`Set::by_call_triggers` doesn't contain required id. This is a bug",
                    )
                }
            })
            .is_some()
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
        &self,
        id: &TriggerId,
        f: impl Fn(u32) -> Result<u32, RepeatsOverflowError>,
    ) -> Result<(), ModRepeatsError> {
        self.inspect_by_id(id, |action| match action.repeats() {
                Repeats::Exactly(atomic) => {
                    let new_repeats = f(atomic.get())?;
                    atomic.set(new_repeats);
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
    pub fn handle_data_event(&self, event: DataEvent) {
        self.data_triggers
            .iter()
            .filter(|entry| {
                let id = entry.key();
                id.domain_id.is_none() || id.domain_id.as_ref() == event.domain_id()
            })
            .for_each(|entry| self.match_and_insert_trigger(event.clone(), entry.pair()));
    }

    /// Handle [`ExecuteTriggerEvent`].
    ///
    /// Find all actions that are triggered by `event` and store them.
    /// These actions are inspected in the next [`Set::inspect_matched()`] call.
    pub fn handle_execute_trigger_event(&self, event: ExecuteTriggerEvent) {
        if let Some(entry) = self.by_call_triggers.get(&event.trigger_id) {
            self.match_and_insert_trigger(event, entry.pair());
        };
    }

    /// Handle [`PipelineEvent`].
    ///
    /// Find all actions that are triggered by `event` and store them.
    /// These actions are inspected in the next [`Set::inspect_matched()`] call.
    // Passing by value to follow other `handle_` methods interface
    #[allow(clippy::needless_pass_by_value)]
    pub fn handle_pipeline_event(&self, event: PipelineEvent) {
        self.pipeline_triggers
            .iter()
            .for_each(|entry| self.match_and_insert_trigger(event.clone(), entry.pair()));
    }

    /// Handle [`TimeEvent`].
    ///
    /// Find all actions that are triggered by `event` and store them.
    /// These actions are inspected in the next [`Set::inspect_matched()`] call.
    pub fn handle_time_event(&self, event: TimeEvent) {
        for entry in &self.time_triggers {
            let action = entry.value();

            let mut count = action.filter.count_matches(&event);
            if let Repeats::Exactly(atomic) = &action.repeats {
                count = min(atomic.get(), count);
            }
            if count == 0 {
                continue;
            }

            let ids = vec![
                (Event::Time(event), entry.key().clone());
                count
                    .try_into()
                    .expect("`u32` should always fit in `usize`")
            ];
            self.matched_ids
                .write()
                .expect("Trigger set is poisoned")
                .extend(ids);
        }
    }

    /// Match and insert a [`TriggerId`] into the set of matched ids.
    ///
    /// Skips insertion:
    /// - If the action's filter doesn't match an event
    /// - If the action's repeats count equals to 0
    fn match_and_insert_trigger<E: Into<Event>, F: EventFilter<Event = E>>(
        &self,
        event: E,
        (id, action): (&TriggerId, &LoadedAction<F>),
    ) {
        if !action.filter.matches(&event) {
            return;
        }

        if let Repeats::Exactly(atomic) = &action.repeats {
            if atomic.get() == 0 {
                return;
            }
        }

        self.matched_ids
            .write()
            .expect("Trigger set is poisoned")
            .push((event.into(), id.clone()));
    }

    /// Call `f` for every action matched by previously called `handle_` methods.
    /// Decrease the action's `repeats` count if inspection succeeds.
    ///
    /// Matched actions are cleared after this function call.
    /// If an action was matched by calling `handle_` method and removed before this method call,
    /// then it won't be inspected.
    ///
    /// # Errors
    ///
    /// Return `Err(Vec<E>)` if one or more errors occurred during action inspection.
    ///
    /// Failed actions won't appear on the next `inspect_matched()` call if they don't match new
    /// events found by `handle_` methods.
    /// Repeats count of failed actions won't be decreased.
    pub fn inspect_matched<F, E>(&self, f: F) -> Result<(), Vec<E>>
    where
        F: Fn(
                &TriggerId,
                wasmtime::Engine,
                &dyn ActionTrait<Executable = LoadedExecutable>,
                Event,
            ) -> std::result::Result<(), E>
            + Copy,
    {
        let (succeed, res) = self.map_matched(f);

        for id in &succeed {
            // Ignoring error if trigger has not `Repeats::Exact(_)` but something else
            let _mod_repeats_res = self.mod_repeats(id, |n| {
                if n == 0 {
                    // Possible i.e. if one trigger burned it-self or another trigger, cause we
                    // decrease the number of execution after successful execution
                    return Ok(0);
                }
                Ok(n - 1)
            });
        }

        self.remove_zeros(&self.data_triggers);
        self.remove_zeros(&self.pipeline_triggers);
        self.remove_zeros(&self.time_triggers);
        self.remove_zeros(&self.by_call_triggers);

        res
    }

    /// Map `f` to every trigger from `self.matched_ids`
    ///
    /// Return a vector of successfully executed triggers
    /// and a result with errors vector if there are any.
    fn map_matched<F, E>(&self, f: F) -> (Vec<TriggerId>, Result<(), Vec<E>>)
    where
        F: Fn(
                &TriggerId,
                wasmtime::Engine,
                &dyn ActionTrait<Executable = LoadedExecutable>,
                Event,
            ) -> std::result::Result<(), E>
            + Copy,
    {
        let mut succeed = Vec::new();
        let mut errors = Vec::new();

        let apply_f = move |id: &TriggerId,
                            action: &dyn ActionTrait<Executable = LoadedExecutable>,
                            event: Event| {
            if let Repeats::Exactly(atomic) = action.repeats() {
                if atomic.get() == 0 {
                    return None;
                }
            }
            Some(f(id, self.engine.clone(), action, event)) // Cloning engine is cheap, see [`wasmtime::Engine`] docs
        };

        // Cloning and clearing `self.matched_ids` so that `handle_` call won't deadlock
        let matched_ids = {
            let mut ids_write = self.matched_ids.write().expect("Trigger set is poisoned");
            let ids_clone = ids_write.clone();
            ids_write.clear();
            ids_clone
        };
        for (event, id) in matched_ids {
            // Ignoring `None` variant because this means that action was deleted after `handle_*()`
            // call and before `inspect_matching()` call
            let result = match event {
                Event::Data(_) => self
                    .data_triggers
                    .get(&id)
                    .map(|entry| apply_f(entry.key(), entry.value(), event)),
                Event::Pipeline(_) => self
                    .pipeline_triggers
                    .get(&id)
                    .map(|entry| apply_f(entry.key(), entry.value(), event)),
                Event::Time(_) => self
                    .time_triggers
                    .get(&id)
                    .map(|entry| apply_f(entry.key(), entry.value(), event)),
                Event::ExecuteTrigger(_) => self
                    .by_call_triggers
                    .get(&id)
                    .map(|entry| apply_f(entry.key(), entry.value(), event)),
            };

            match result.flatten() {
                Some(Ok(_)) => succeed.push(id),
                Some(Err(err)) => errors.push(err),
                None => {}
            };
        }

        if errors.is_empty() {
            return (succeed, Ok(()));
        }
        (succeed, Err(errors))
    }

    /// Remove actions with zero execution count from `triggers`
    fn remove_zeros<F: Filter>(&self, triggers: &DashMap<TriggerId, LoadedAction<F>>) {
        let to_remove: Vec<TriggerId> = triggers
            .iter()
            .filter_map(|entry| {
                if let Repeats::Exactly(atomic) = &entry.value().repeats {
                    if atomic.get() == 0 {
                        return Some(entry.key().clone());
                    }
                }
                None
            })
            .collect();

        for id in to_remove {
            triggers
                .remove(&id)
                .and_then(|_| self.ids.remove(&id))
                .expect(
                    "Removing existing keys from `Set` should be always possible. This is a bug",
                );
        }
    }
}

#[derive(Clone)]
pub enum LoadedExecutable {
    Wasm(wasmtime::Module),
    Instructions(Vec<Instruction>),
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
#[derive(Debug, Clone, thiserror::Error)]
pub enum ModRepeatsError {
    /// Trigger not found error
    #[error("Trigger with id = {0} not found")]
    NotFound(TriggerId),
    /// Trigger repeats count overflow error
    #[error("{0}")]
    RepeatsOverflow(#[from] RepeatsOverflowError),
}

/// Trigger repeats count overflow error
#[derive(Debug, Copy, Clone, thiserror::Error)]
#[error("Trigger repeats count overflow")]
pub struct RepeatsOverflowError;

impl From<ModRepeatsError> for InstructionExecutionFailure {
    fn from(err: ModRepeatsError) -> Self {
        match err {
            ModRepeatsError::NotFound(not_found_id) => FindError::Trigger(not_found_id).into(),
            ModRepeatsError::RepeatsOverflow(_) => MathError::Overflow.into(),
        }
    }
}
