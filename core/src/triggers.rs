//! Trigger logic. Instead of defining a Trigger as an entity, we
//! provide a collection of triggers as the smallest unit, which is an
//! idea borrowed from lisp hooks.
//!
//! The point of the idea is to create an ordering (or hash function)
//! which maps the event filter and the event that triggers it to the
//! same approximate location in the hierarchy, thus using Binary
//! search trees (common lisp) or hash tables (racket) to quickly
//! trigger hooks.

#![allow(clippy::expect_used, clippy::unwrap_in_result)]

use std::{cmp::min, sync::Arc};

use dashmap::{DashMap, DashSet};
use iroha_data_model::{
    events::Filter as _,
    prelude::*,
    trigger::{self, Action, Repeats, Trigger},
};
use tokio::{sync::RwLock, task};

use crate::smartcontracts::{self, FindError, InstructionType, MathError};

type Result<T> = std::result::Result<T, smartcontracts::Error>;

/// Specialized structure that maps event filters to Triggers.
/// TODO: trigger strong-typing
#[derive(Debug, Default)]
pub struct TriggerSet {
    /// Triggers using [`DataEventFilter`]
    data_triggers: DashMap<trigger::Id, Action<DataEventFilter>>,
    /// Triggers using [`PipelineEventFilter`]
    pipeline_triggers: DashMap<trigger::Id, Action<PipelineEventFilter>>,
    /// Triggers using [`TimeEventFilter`]
    time_triggers: DashMap<trigger::Id, Action<TimeEventFilter>>,
    /// Triggers using [`ExecuteTriggerEventFilter`]
    by_call_triggers: DashMap<trigger::Id, Action<ExecuteTriggerEventFilter>>,
    /// Set of all ids. Used to check that every id is unique
    ids: DashSet<trigger::Id>,
    /// List of actions that should be triggered by events provided by `handle_*` methods.
    /// Not being cloned
    matched_ids: RwLock<Vec<(EventType, trigger::Id)>>,
}

impl Clone for TriggerSet {
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

impl TriggerSet {
    /// Add trigger with [`DataEventFilter`]
    ///
    /// # Errors
    /// - If trigger with such id already exists
    pub fn add_data_trigger(&self, trigger: Trigger<DataEventFilter>) -> Result<()> {
        self.add_to(trigger, &self.data_triggers)
    }

    /// Add trigger with [`PipelineEventFilter`]
    ///
    /// # Errors
    /// - If trigger with such id already exists
    pub fn add_pipeline_trigger(&self, trigger: Trigger<PipelineEventFilter>) -> Result<()> {
        self.add_to(trigger, &self.pipeline_triggers)
    }

    /// Add trigger with [`TimeEventFilter`]
    ///
    /// # Errors
    /// - If trigger with such id already exists
    pub fn add_time_trigger(&self, trigger: Trigger<TimeEventFilter>) -> Result<()> {
        self.add_to(trigger, &self.time_triggers)
    }

    /// Add trigger with [`ExecuteTriggerEventFilter`]
    ///
    /// # Errors
    /// - If trigger with such id already exists
    pub fn add_by_call_trigger(&self, trigger: Trigger<ExecuteTriggerEventFilter>) -> Result<()> {
        self.add_to(trigger, &self.by_call_triggers)
    }

    fn add_to<F: Filter>(
        &self,
        trigger: Trigger<F>,
        map: &DashMap<trigger::Id, Action<F>>,
    ) -> Result<()> {
        if self.contains(&trigger.id) {
            return Err(smartcontracts::Error::Repetition(
                InstructionType::Register,
                IdBox::TriggerId(trigger.id),
            ));
        }

        map.insert(trigger.id.clone(), trigger.action);
        self.ids.insert(trigger.id);
        Ok(())
    }

    /// Apply `f` to the trigger identified by `id`
    ///
    /// # Errors
    /// - If [`TriggerSet`] doesn't contain the trigger with the given `id`.
    pub fn inspect<F, R>(&self, id: &trigger::Id, f: F) -> Result<R>
    where
        F: Fn(&dyn ActionTrait) -> R,
    {
        self.inspect_mut(id, |action| f(&*action))
    }

    fn inspect_mut<F, R>(&self, id: &trigger::Id, f: F) -> Result<R>
    where
        F: Fn(&mut dyn ActionTrait) -> R,
    {
        if !self.contains(id) {
            return Err(smartcontracts::Error::Find(Box::new(FindError::Trigger(
                id.clone(),
            ))));
        }

        Ok(self
            .data_triggers
            .get_mut(id)
            .map(|mut entry| f(entry.value_mut()))
            .or_else(|| {
                self.pipeline_triggers
                    .get_mut(id)
                    .map(|mut entry| f(entry.value_mut()))
            })
            .or_else(|| {
                self.time_triggers
                    .get_mut(id)
                    .map(|mut entry| f(entry.value_mut()))
            })
            .or_else(|| {
                self.by_call_triggers
                    .get_mut(id)
                    .map(|mut entry| f(entry.value_mut()))
            })
            .expect("`TriggerSet` sub-sets doesn't have required id. This is a bug"))
    }

    /// Remove a trigger from the [`TriggerSet`].
    ///
    /// # Errors
    /// - If [`TriggerSet`] doesn't contain the trigger with the given `id`.
    pub fn remove(&self, id: &trigger::Id) -> Result<()> {
        if !self.contains(id) {
            return Err(smartcontracts::Error::Repetition(
                InstructionType::Unregister,
                IdBox::TriggerId(id.clone()),
            ));
        }

        self.data_triggers
            .remove(id)
            .map(|_| ())
            .or_else(|| self.pipeline_triggers.remove(id).map(|_| ()))
            .or_else(|| self.time_triggers.remove(id).map(|_| ()))
            .or_else(|| self.by_call_triggers.remove(id).map(|_| ()))
            .expect("`TriggerSet` sub-sets doesn't have required id. This is a bug");

        self.ids.remove(id);
        Ok(())
    }

    /// Check if [`TriggerSet`] contains `id`.
    pub fn contains(&self, id: &trigger::Id) -> bool {
        self.ids.contains(id)
    }

    /// Forward the internal immutable iterator.
    pub fn iter(
        &self,
    ) -> dashmap::iter::Iter<iroha_data_model::trigger::Id, iroha_data_model::trigger::Action> {
        self.0.iter()
    }

    /// Modify repetitions of the hook identified by [`trigger::Id`].
    ///
    /// # Errors
    /// - if trigger not found.
    /// - if addition to remaining current trigger repeats
    /// overflows. Indefinitely repeating triggers and triggers set for
    /// exact time always cause an overflow.
    pub fn mod_repeats(
        &self,
        id: &trigger::Id,
        f: impl Fn(u32) -> std::result::Result<u32, MathError>,
    ) -> Result<()> {
        self.inspect_mut(id, |action| {
            let new_repeats = match action.repeats() {
                Repeats::Exactly(n) => f(n).map_err(Into::into),
                _ => Err(smartcontracts::Error::Math(MathError::Overflow)),
            }?;
            action.set_repeats(Repeats::Exactly(new_repeats));

            Ok(())
        })?
    }

    /// Handle [`DataEvent`].
    ///
    /// Finds all actions, that are triggered by `event` and stores them.
    /// This actions will be inspected ln the next `TriggerSet::inspect_matched()` call
    pub fn handle_data_event(&self, event: &DataEvent) {
        self.handle_event(&self.data_triggers, event, EventType::Data)
    }

    /// Handle [`PipelineEvent`].
    ///
    /// Finds all actions, that are triggered by `event` and stores them.
    /// This actions will be inspected ln the next `TriggerSet::inspect_matched()` call
    pub fn handle_pipeline_event(&self, event: &PipelineEvent) {
        self.handle_event(&self.pipeline_triggers, event, EventType::Pipeline)
    }

    /// Handle [`TimeEvent`].
    ///
    /// Finds all actions, that are triggered by `event` and stores them.
    /// This actions will be inspected ln the next `TriggerSet::inspect_matched()` call
    pub fn handle_time_event(&self, event: &TimeEvent) {
        for entry in &self.time_triggers {
            let action = entry.value();

            let mut count = action.filter.count_matches(event);
            if let Repeats::Exactly(n) = action.repeats {
                count = min(n, count);
            }
            if count == 0 {
                return;
            }

            let ids = vec![
                (EventType::Time, entry.key().clone());
                count
                    .try_into()
                    .expect("`u32` should always fit in `usize`")
            ];
            task::block_in_place(|| self.matched_ids.blocking_write()).extend(ids)
        }
    }

    /// Handle [`ExecuteTriggerEvent`].
    ///
    /// Finds all actions, that are triggered by `event` and stores them.
    /// This actions will be inspected ln the next `TriggerSet::inspect_matched()` call
    pub fn handle_execute_trigger_event(&self, event: &ExecuteTriggerEvent) {
        self.handle_event(&self.by_call_triggers, event, EventType::ExecuteTrigger)
    }

    fn handle_event<F, E>(
        &self,
        triggers: &DashMap<trigger::Id, Action<F>>,
        event: &E,
        event_type: EventType,
    ) where
        F: Filter<EventType = E>,
    {
        for entry in triggers {
            let action = entry.value();
            if !action.filter.matches(event) {
                return;
            }

            if let Repeats::Exactly(n) = action.repeats {
                if n == 0 {
                    return;
                }
            }

            task::block_in_place(|| self.matched_ids.blocking_write())
                .push((event_type, entry.key().clone()))
        }
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
    #[allow(clippy::missing_panics_doc, clippy::panic)] // Panicking only in internal bug-case
    pub async fn inspect_matched<F, E>(&self, f: F) -> std::result::Result<(), Vec<E>>
    where
        F: Fn(&dyn ActionTrait) -> std::result::Result<(), E> + Send + Copy,
        E: Send + Sync,
    {
        let succeed = Arc::new(RwLock::new(Vec::new()));
        let res = {
            let errors = Arc::new(RwLock::new(Vec::new()));
            let errors_clone = Arc::clone(&errors);
            let succeed_clone = Arc::clone(&succeed);
            let apply_f = move |id: trigger::Id, action: &dyn ActionTrait| {
                if action.repeats() == Repeats::Exactly(0) {
                    return;
                }

                match f(action) {
                    Ok(()) => task::block_in_place(|| succeed_clone.blocking_write()).push(id),
                    Err(err) => task::block_in_place(|| errors_clone.blocking_write()).push(err),
                }
            };

            // Cloning and clearing `self.ids_write` so that `handle_` call won't deadlock
            let matched_ids = {
                let mut ids_write = self.matched_ids.write().await;
                let ids_clone = ids_write.clone();
                ids_write.clear();
                ids_clone
            };
            for (event_type, id) in matched_ids {
                // Ignoring `None` variant cause this means that action was deleted after `handle_`
                // call and before `inspect_matching()` call
                let _ = match event_type {
                    EventType::Data => self
                        .data_triggers
                        .get(&id)
                        .map(|entry| apply_f(id, entry.value())),
                    EventType::Pipeline => self
                        .pipeline_triggers
                        .get(&id)
                        .map(|entry| apply_f(id, entry.value())),
                    EventType::Time => self
                        .time_triggers
                        .get(&id)
                        .map(|entry| apply_f(id, entry.value())),
                    EventType::ExecuteTrigger => self
                        .by_call_triggers
                        .get(&id)
                        .map(|entry| apply_f(id, entry.value())),
                };

                task::yield_now().await;
            }

            if task::block_in_place(|| errors.blocking_read()).is_empty() {
                return Ok(());
            }

            // Match with panic cause can't use `expect()` due to
            // error value not implementing `Display`
            #[allow(clippy::match_wild_err_arm)]
            let errors = match Arc::try_unwrap(errors) {
                Ok(e) => e.into_inner(),
                Err(_) => panic!("Errors `Arc` is has strong count > 1. This is a bug"),
            };
            std::result::Result::<(), Vec<E>>::Err(errors)
        };

        let succeed_read = task::block_in_place(|| succeed.blocking_read());
        for id in succeed_read.iter() {
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

    fn remove_zeros<F: Filter>(&self, triggers: &DashMap<trigger::Id, Action<F>>) {
        let to_remove: Vec<trigger::Id> = triggers
            .iter()
            .filter_map(|entry| {
                matches!(entry.value().repeats, Repeats::Exactly(0)).then(|| entry.key().clone())
            })
            .collect();

        for id in to_remove {
            triggers
                .remove(&id)
                .and_then(|_| self.ids.remove(&id))
                .expect(
                "Removing existing keys from `TriggerSet` should be always possible. This is a bug",
            );
        }
    }
}
