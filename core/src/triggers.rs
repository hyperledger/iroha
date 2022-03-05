//! Trigger logic. Instead of defining a Trigger as an entity, we
//! provide a collection of triggers as the smallest unit, which is an
//! idea borrowed from lisp hooks.
//!
//! The point of the idea is to create an ordering (or hash function)
//! which maps the event filter and the event that triggers it to the
//! same approximate location in the hierarchy, thus using Binary
//! search trees (common lisp) or hash tables (racket) to quickly
//! trigger hooks.

use std::sync::RwLock;

use dashmap::DashMap;
use iroha_data_model::{
    prelude::*,
    trigger::{self, Action, Repeats, Trigger},
};

use crate::smartcontracts::{self, FindError, InstructionType, MathError};

/// Specialised structure that maps event filters to Triggers.
#[derive(Debug)]
pub struct TriggerSet {
    event_hooks: DashMap<trigger::Id, EventAction>, // TODO: Consider tree structures.
    time_hooks: DashMap<trigger::Id, TimeAction>,   // TODO: Consider tree structures.
    recommendations: RwLock<Vec<Action>>,
}

impl Default for TriggerSet {
    fn default() -> Self {
        Self {
            event_hooks: DashMap::new(),
            time_hooks: DashMap::new(),
            recommendations: RwLock::new(Vec::new()),
        }
    }
}

impl TriggerSet {
    /// Add another trigger to the [`TriggerSet`].
    ///
    /// # Errors
    /// - If [`TriggerSet`] already contains a trigger with the same [`EventFilter`].
    /// It's the user's responsibility to first `Unregister` the `Trigger`.
    pub fn add(&self, trigger: Trigger) -> Result<(), smartcontracts::Error> {
        if self.event_hooks.contains_key(&trigger.id) || self.time_hooks.contains_key(&trigger.id) {
            return Err(smartcontracts::Error::Repetition(
                InstructionType::Register,
                IdBox::TriggerId(trigger.id),
            ));
        }

        match trigger.action {
            Action::EventBased(action) => Self::insert(&self.event_hooks, trigger.id, action),
            Action::TimeBased(action) => Self::insert(&self.time_hooks, trigger.id, action),
        }
    }

    fn insert<A>(
        hooks: &DashMap<trigger::Id, A>,
        id: trigger::Id,
        action: A,
    ) -> Result<(), smartcontracts::Error>
    where
        A: Into<Action>,
    {
        hooks.insert(id.clone(), action).map_or_else(
            || Ok(()),
            |_| {
                Err(smartcontracts::Error::Repetition(
                    InstructionType::Register,
                    IdBox::TriggerId(id),
                ))
            },
        )
    }

    /// Remove a trigger from the [`TriggerSet`].
    ///
    /// # Errors
    /// - If [`TriggerSet`] doesn't contain the trigger with the given [`EventFilter`].
    /// Note that the [`EventFilter`] must be specified exactly.
    pub fn remove(&self, id: trigger::Id) -> Result<(), smartcontracts::Error> {
        self.event_hooks
            .remove(&id)
            .map(|key_val| key_val.0)
            .or_else(|| self.time_hooks.remove(&id).map(|key_val| key_val.0))
            .map_or_else(
                || {
                    Err(smartcontracts::Error::Repetition(
                        InstructionType::Unregister,
                        IdBox::TriggerId(id),
                    ))
                },
                |_| Ok(()),
            )
    }

    /// Check if `self` contains `key`.
    pub fn contains(&self, key: &trigger::Id) -> bool {
        self.event_hooks.contains_key(key) || self.time_hooks.contains_key(key)
    }

    /// Modify repetitions of the hook identified by [`trigger::Id`].
    ///
    /// # Errors
    /// - if trigger not found.
    /// - if addition to remaining current trigger repeats
    /// overflows. Indefinitely repeating triggers always cause an
    /// overflow.
    pub fn mod_repeats(
        &self,
        key: trigger::Id,
        f: impl Fn(u32) -> Result<u32, MathError>,
    ) -> Result<(), smartcontracts::Error> {
        if let Some(mut event_entry) = self.event_hooks.get_mut(&key) {
            return Self::mod_repeats_directly(&mut event_entry.value_mut().repeats, f);
        }

        if let Some(mut time_entry) = self.time_hooks.get_mut(&key) {
            return Self::mod_repeats_directly(&mut time_entry.value_mut().repeats, f);
        }

        Err(smartcontracts::Error::Find(Box::new(FindError::Trigger(
            key,
        ))))
    }

    /// Modify `repeats` with `f`
    ///
    /// # Errors
    /// - if `repeats` is not `Exactly` variant
    /// - throws `f` errors
    fn mod_repeats_directly(
        repeats: &mut Repeats,
        f: impl Fn(u32) -> Result<u32, MathError>,
    ) -> Result<(), smartcontracts::Error> {
        let new_repeats = match repeats {
            Repeats::Exactly(n) => f(*n).map_err(Into::into),
            _ => Err(smartcontracts::Error::Math(MathError::Overflow)),
        }?;
        *repeats = Repeats::Exactly(new_repeats);
        Ok(())
    }

    /// Produce and store recommendations for next block execution.
    ///
    /// # Panics
    /// (RARE) If locking recommendations for writing fails.
    pub fn produce_recommendations(&self, events: &[Event]) {
        let event_actions = self.actions_matching(events);
        let time_actions: Vec<TimeAction> = vec![]; // TODO

        #[allow(clippy::expect_used)]
        let mut recommendations = self
            .recommendations
            .write()
            .expect("Failed to lock recommendations, when updating triggers.");
        *recommendations = event_actions
            .into_iter()
            .map(Into::into)
            .chain(time_actions.into_iter().map(Into::into))
            .collect();
    }

    /// Find all actions which match the current events.
    fn actions_matching(&self, events: &[Event]) -> Vec<EventAction> {
        let mut result = Vec::new();
        for event in events {
            for mut trigger in self.event_hooks.iter_mut() {
                if trigger.filter.apply(event) {
                    match trigger.repeats {
                        Repeats::Indefinitely => {
                            result.push(trigger.clone());
                        }
                        Repeats::Exactly(n) if n > 0_u32 => {
                            trigger.repeats = Repeats::Exactly(n - 1);
                            result.push(trigger.clone());
                        }
                        _ => {
                            // n == 0
                            continue;
                        }
                    }
                }
            }
        }

        self.event_hooks
            .retain(|_, action| !matches!(action.repeats, Repeats::Exactly(0)));
        result
    }
}
