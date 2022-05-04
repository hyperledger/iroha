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

use std::cmp::min;

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
                Repeats::Exactly(n) => f(*n).map_err(Into::into),
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
        for mut entry in self.time_triggers.iter_mut() {
            let action = entry.value_mut();

            let mut count = action.filter.count_matches(event);
            if let Repeats::Exactly(n) = &mut action.repeats {
                count = min(*n, count);
                *n -= count
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
        for mut entry in triggers.iter_mut() {
            let action = entry.value_mut();
            if !action.filter.matches(event) {
                return;
            }

            if let Repeats::Exactly(n) = &mut action.repeats {
                if *n == 0 {
                    return;
                }

                *n -= 1;
            }

            task::block_in_place(|| self.matched_ids.blocking_write())
                .push((event_type, entry.key().clone()))
        }
    }

    /// Calls `f` for every action, matched by previously called `handle_` methods.
    ///
    /// Matched actions are cleared after this function call.
    /// If an action was matched by calling `handle_` method and removed before this method call,
    /// then it won't be presented.
    ///
    /// # Errors
    /// Throws up first `f` error
    pub async fn inspect_matched<F, E>(&self, f: F) -> std::result::Result<(), E>
    where
        F: Fn(&dyn ActionTrait) -> std::result::Result<(), E> + Send,
        E: Send,
    {
        {
            let matched_ids_read = self.matched_ids.read().await;
            for (event_type, id) in matched_ids_read.iter() {
                match event_type {
                    EventType::Data => self.data_triggers.get(id).map(|entry| f(entry.value())),
                    EventType::Pipeline => {
                        self.pipeline_triggers.get(id).map(|entry| f(entry.value()))
                    }
                    EventType::Time => self.time_triggers.get(id).map(|entry| f(entry.value())),
                    EventType::ExecuteTrigger => {
                        self.by_call_triggers.get(id).map(|entry| f(entry.value()))
                    }
                }
                .transpose()?;

                task::yield_now().await;
            }
        }

        self.remove_zeros(&self.data_triggers);
        self.remove_zeros(&self.pipeline_triggers);
        self.remove_zeros(&self.time_triggers);
        self.remove_zeros(&self.by_call_triggers);

        self.matched_ids.write().await.clear();
        Ok(())
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
