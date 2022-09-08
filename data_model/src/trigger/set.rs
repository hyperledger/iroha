//! Trigger logic. Instead of defining a Trigger as an entity, we
//! provide a collection of triggers as the smallest unit, which is an
//! idea borrowed from lisp hooks.
//!
//! The point of the idea is to create an ordering (or hash function)
//! which maps the event filter and the event that triggers it to the
//! same approximate location in the hierarchy, thus using Binary
//! search trees (common lisp) or hash tables (racket) to quickly
//! trigger hooks.
#![allow(clippy::std_instead_of_core)]
#![cfg(feature = "std")]
#![allow(clippy::expect_used)]

use core::{cmp::min, result::Result};
use std::sync::RwLock;

use dashmap::DashMap;

use super::Id;
use crate::{events::Filter as EventFilter, prelude::*};

/// [`Set::mod_repeats()`] error
#[derive(Debug, Clone, thiserror::Error)]
pub enum ModRepeatsError {
    /// Trigger not found error
    #[error("Trigger with id = {0} not found")]
    NotFound(Id),
    /// Trigger repeats count overflow error
    #[error("{0}")]
    RepeatsOverflow(#[from] RepeatsOverflowError),
}

/// Trigger repeats count overflow error
#[derive(Debug, Copy, Clone, thiserror::Error)]
#[error("Trigger repeats count overflow")]
pub struct RepeatsOverflowError;

/// Specialized structure that maps event filters to Triggers.
#[derive(Debug, Default)]
pub struct Set {
    /// Triggers using [`DataEventFilter`]
    data_triggers: DashMap<Id, Action<DataEventFilter>>,
    /// Triggers using [`PipelineEventFilter`]
    pipeline_triggers: DashMap<Id, Action<PipelineEventFilter>>,
    /// Triggers using [`TimeEventFilter`]
    time_triggers: DashMap<Id, Action<TimeEventFilter>>,
    /// Triggers using [`ExecuteTriggerEventFilter`]
    by_call_triggers: DashMap<Id, Action<ExecuteTriggerEventFilter>>,
    /// Trigger ids with type of events they process
    ids: DashMap<Id, EventType>,
    /// List of actions that should be triggered by events provided by `handle_*` methods.
    /// Vector is used to save the exact triggers order.
    /// Not being cloned
    matched_ids: RwLock<Vec<(Event, Id)>>,
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
        }
    }
}

impl Set {
    /// Add trigger with [`DataEventFilter`]
    ///
    /// Returns `false` if trigger with such id already exists
    pub fn add_data_trigger(&self, trigger: Trigger<DataEventFilter>) -> bool {
        self.add_to(trigger, EventType::Data, &self.data_triggers)
    }

    /// Add trigger with [`PipelineEventFilter`]
    ///
    /// Returns `false` if trigger with such id already exists
    pub fn add_pipeline_trigger(&self, trigger: Trigger<PipelineEventFilter>) -> bool {
        self.add_to(trigger, EventType::Pipeline, &self.pipeline_triggers)
    }

    /// Add trigger with [`TimeEventFilter`]
    ///
    /// Returns `false` if trigger with such id already exists
    pub fn add_time_trigger(&self, trigger: Trigger<TimeEventFilter>) -> bool {
        self.add_to(trigger, EventType::Time, &self.time_triggers)
    }

    /// Add trigger with [`ExecuteTriggerEventFilter`]
    ///
    /// Returns `false` if trigger with such id already exists
    pub fn add_by_call_trigger(&self, trigger: Trigger<ExecuteTriggerEventFilter>) -> bool {
        self.add_to(trigger, EventType::ExecuteTrigger, &self.by_call_triggers)
    }

    /// Add generic trigger to generic collection
    ///
    /// Returns `false` if trigger with such id already exists
    fn add_to<F: Filter>(
        &self,
        trigger: Trigger<F>,
        event_type: EventType,
        map: &DashMap<Id, Action<F>>,
    ) -> bool {
        if self.contains(&trigger.id) {
            return false;
        }

        map.insert(trigger.id.clone(), trigger.action);
        self.ids.insert(trigger.id, event_type);
        true
    }

    /// Get all contained triggers ids without particular order
    pub fn ids(&self) -> Vec<Id> {
        self.ids.iter().map(|entry| entry.key().clone()).collect()
    }

    /// Apply `f` to triggers that belong to the given [`DomainId`]
    ///
    /// Returns an empty list if [`Set`] doesn't contain any trigger belonging to [`DomainId`].
    pub fn inspect_by_domain_id<F, R>(&self, domain_id: &DomainId, f: F) -> Vec<R>
    where
        F: Fn(&Id, &dyn ActionTrait) -> R,
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
    /// Returns [`None`] if [`Set`] doesn't contain the trigger with the given `id`.
    pub fn inspect_by_id<F, R>(&self, id: &Id, f: F) -> Option<R>
    where
        F: Fn(&dyn ActionTrait) -> R,
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
    /// Returns `false` if [`Set`] doesn't contain the trigger with the given `id`.
    pub fn remove(&self, id: &Id) -> bool {
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
    pub fn contains(&self, id: &Id) -> bool {
        self.ids.contains_key(id)
    }

    /// Modify repetitions of the hook identified by [`Id`].
    ///
    /// # Errors
    /// - if trigger not found.
    /// - if addition to remaining current trigger repeats
    /// overflows. Indefinitely repeating triggers and triggers set for
    /// exact time always cause an overflow.
    pub fn mod_repeats(
        &self,
        id: &Id,
        f: impl Fn(u32) -> Result<u32, RepeatsOverflowError>,
    ) -> Result<(), ModRepeatsError> {
        let res = self
            .inspect_by_id(id, |action| match action.repeats() {
                Repeats::Exactly(atomic) => {
                    let new_repeats = f(atomic.get())?;
                    atomic.set(new_repeats);
                    Ok(())
                }
                _ => Err(ModRepeatsError::RepeatsOverflow(RepeatsOverflowError)),
            })
            .ok_or_else(|| ModRepeatsError::NotFound(id.clone()));
        // .flatten() -- unstable
        match res {
            Ok(r) => r,
            Err(e) => Err(e),
        }
    }

    /// Handle [`DataEvent`].
    ///
    /// Finds all actions, that are triggered by `event` and stores them.
    /// This actions will be inspected in the next [`Set::handle_data_event()`] call
    // Passing by value to follow other `handle_` methods interface
    #[allow(clippy::needless_pass_by_value)]
    pub fn handle_data_event(&self, event: DataEvent) {
        for entry in self.data_triggers.iter() {
            let id = entry.key();

            if id.domain_id.is_some() && id.domain_id.as_ref() != event.domain_id() {
                continue;
            }

            self.match_and_insert_trigger(event.clone(), entry.pair());
        }
    }

    /// Handle [`ExecuteTriggerEvent`].
    ///
    /// Finds all actions, that are triggered by `event` and stores them.
    /// This actions will be inspected in the next [`Set::inspect_matched()`] call
    pub fn handle_execute_trigger_event(&self, event: ExecuteTriggerEvent) {
        let entry = match self.by_call_triggers.get(&event.trigger_id) {
            Some(entry) => entry,
            None => return,
        };

        self.match_and_insert_trigger(event, entry.pair());
    }

    /// Handle [`PipelineEvent`].
    ///
    /// Finds all actions, that are triggered by `event` and stores them.
    /// This actions will be inspected in the next [`Set::inspect_matched()`] call
    // Passing by value to follow other `handle_` methods interface
    #[allow(clippy::needless_pass_by_value)]
    pub fn handle_pipeline_event(&self, event: PipelineEvent) {
        for entry in self.pipeline_triggers.iter() {
            self.match_and_insert_trigger(event.clone(), entry.pair());
        }
    }

    /// Handle [`TimeEvent`].
    ///
    /// Finds all actions, that are triggered by `event` and stores them.
    /// This actions will be inspected in the next [`Set::inspect_matched()`] call
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
        (id, action): (&Id, &Action<F>),
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

    /// Calls `f` for every action, matched by previously called `handle_` methods.
    /// Decreases action repeats count if inspection succeed.
    ///
    /// Matched actions are cleared after this function call.
    /// If an action was matched by calling `handle_` method and removed before this method call,
    /// then it won't be presented.
    ///
    /// # Errors
    /// Returns `Err(Vec<E>)` if one or more error occurred during action inspection.
    ///
    /// Failed actions won't appear on the next `inspect_matched()` call if they don't match new
    /// events by calling `handle_` methods.
    /// Repeats count of failed actions won't be decreased.
    pub fn inspect_matched<F, E>(&self, f: F) -> Result<(), Vec<E>>
    where
        F: Fn(&dyn ActionTrait, Event) -> std::result::Result<(), E> + Send + Copy,
        E: Send + Sync,
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
    /// Returns vector of successfully executed triggers
    /// and result with errors vector if there are some
    fn map_matched<F, E>(&self, f: F) -> (Vec<Id>, Result<(), Vec<E>>)
    where
        F: Fn(&dyn ActionTrait, Event) -> std::result::Result<(), E> + Send + Copy,
        E: Send + Sync,
    {
        let mut succeed = Vec::new();
        let mut errors = Vec::new();

        let apply_f = move |action: &dyn ActionTrait, event: Event| {
            if let Repeats::Exactly(atomic) = action.repeats() {
                if atomic.get() == 0 {
                    return None;
                }
            }
            Some(f(action, event))
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
                    .map(|entry| apply_f(entry.value(), event)),
                Event::Pipeline(_) => self
                    .pipeline_triggers
                    .get(&id)
                    .map(|entry| apply_f(entry.value(), event)),
                Event::Time(_) => self
                    .time_triggers
                    .get(&id)
                    .map(|entry| apply_f(entry.value(), event)),
                Event::ExecuteTrigger(_) => self
                    .by_call_triggers
                    .get(&id)
                    .map(|entry| apply_f(entry.value(), event)),
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
    fn remove_zeros<F: Filter>(&self, triggers: &DashMap<Id, Action<F>>) {
        let to_remove: Vec<Id> = triggers
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
