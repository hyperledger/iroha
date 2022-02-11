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
    hooks: DashMap<trigger::Id, Action>, // TODO: Consider tree structures.
    recommendations: RwLock<Vec<Action>>,
}

impl Default for TriggerSet {
    fn default() -> Self {
        Self {
            hooks: DashMap::new(),
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
        let action = trigger.action;
        if self.hooks.contains_key(&trigger.id) {
            Err(smartcontracts::Error::Repetition(
                InstructionType::Register,
                IdBox::TriggerId(trigger.id),
            ))
        } else {
            self.hooks.insert(trigger.id.clone(), action).map_or_else(
                || Ok(()),
                |_| {
                    Err(smartcontracts::Error::Repetition(
                        InstructionType::Register,
                        IdBox::TriggerId(trigger.id),
                    ))
                },
            )
        }
    }

    /// Remove a trigger from the [`TriggerSet`].
    ///
    /// # Errors
    /// - If [`TriggerSet`] doesn't contain the trigger with the given [`EventFilter`].
    /// Note that the [`EventFilter`] must be specified exactly.
    pub fn remove(&self, id: trigger::Id) -> Result<(), smartcontracts::Error> {
        self.hooks.remove(&id).map_or_else(
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
        self.hooks.contains_key(key)
    }

    /// Add more repetitions to the hook identified by [`trigger::Id`].
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
        if self.hooks.contains_key(&key) {
            let mut action = self.hooks.get_mut(&key).ok_or(FindError::Trigger(key))?;
            let new_repeats = match action.value().repeats {
                Repeats::Exactly(n) => f(n).map_err(Into::into),
                _ => Err(smartcontracts::Error::Math(MathError::Overflow)),
            }?;
            action.value_mut().repeats = Repeats::Exactly(new_repeats);
            Ok(())
        } else {
            Err(smartcontracts::Error::Find(Box::new(FindError::Trigger(
                key,
            ))))
        }
    }

    /// Produce and store recommendations for next block execution.
    ///
    /// # Panics
    /// (RARE) If locking recommendations for writing fails.
    pub fn produce_recommendations(&self, events: &[Event]) {
        let actions = self.actions_matching(events);
        #[allow(clippy::expect_used)]
        let mut recommendations = self
            .recommendations
            .write()
            .expect("Failed to lock recommendations, when updating triggers.");
        *recommendations = actions;
    }

    /// Find all actions which match the current events.
    fn actions_matching(&self, events: &[Event]) -> Vec<Action> {
        let mut result = Vec::new();
        for event in events {
            for mut trigger in self.hooks.iter_mut() {
                if trigger.value().filter.apply(event) {
                    match trigger.value().repeats {
                        Repeats::Indefinitely => {
                            result.push(trigger.value().clone());
                        }
                        Repeats::Exactly(n) if n > 0_u32 => {
                            let value = trigger.value_mut();
                            value.repeats = Repeats::Exactly(n - 1);
                            result.push(value.clone());
                        }
                        _ => {
                            // n == 0
                            continue;
                        }
                    }
                }
            }
        }
        self.hooks
            .retain(|_, action| !matches!(action.repeats, Repeats::Exactly(0)));
        result
    }
}
