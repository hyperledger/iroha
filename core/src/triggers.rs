//! Trigger logic. Instead of defining a Trigger as an entity, we
//! provide a collection of triggers as the smallest unit, which is an
//! idea borrowed from lisp hooks.
//!
//! The point of the idea is to create an ordering (or hash function)
//! which maps the event filter and the event that triggers it to the
//! same approximate location in the hierarchy, thus using Binary
//! search trees (common lisp) or hash tables (racket) to quickly
//! trigger hooks.

use std::sync::Arc;

use dashmap::DashMap;
use iroha_data_model::{
    prelude::*,
    trigger::{self, Action, Repeats, Trigger},
};

use crate::smartcontracts::{self, FindError, InstructionType, MathError};

/// Specialised structure that maps event filters to Triggers.
#[derive(Debug, Default)]
pub struct TriggerSet(
    DashMap<trigger::Id, Arc<Action>>, // TODO: Consider tree structures.
);

impl TriggerSet {
    /// Add another trigger to the [`TriggerSet`].
    ///
    /// # Errors
    /// - If [`TriggerSet`] already contains a trigger with the same [`EventFilter`].
    /// It's the user's responsibility to first `Unregister` the `Trigger`.
    pub fn add(&self, trigger: Trigger) -> Result<(), smartcontracts::Error> {
        if self.0.contains_key(&trigger.id) {
            return Err(smartcontracts::Error::Repetition(
                InstructionType::Register,
                IdBox::TriggerId(trigger.id),
            ));
        }
        self.0.insert(trigger.id.clone(), Arc::new(trigger.action));

        Ok(())
    }

    pub fn get(&self, id: &trigger::Id) -> Result<Arc<Action>, smartcontracts::Error> {
        self.0.get(id).map_or_else(
            || {
                Err(smartcontracts::Error::Find(Box::new(FindError::Trigger(
                    id.clone(),
                ))))
            },
            |entry| Ok(entry.value().clone()),
        )
    }

    /// Remove a trigger from the [`TriggerSet`].
    ///
    /// # Errors
    /// - If [`TriggerSet`] doesn't contain the trigger with the given [`EventFilter`].
    /// Note that the [`EventFilter`] must be specified exactly.
    pub fn remove(&self, id: &trigger::Id) -> Result<(), smartcontracts::Error> {
        self.0.remove(id).map_or_else(
            || {
                Err(smartcontracts::Error::Repetition(
                    InstructionType::Unregister,
                    IdBox::TriggerId(id.clone()),
                ))
            },
            |_| Ok(()),
        )
    }

    /// Check if `self` contains `key`.
    pub fn contains(&self, key: &trigger::Id) -> bool {
        self.0.contains_key(key)
    }

    /// Modify repetitions of the hook identified by [`trigger::Id`].
    ///
    /// # Errors
    /// - if trigger not found.
    /// - if addition to remaining current trigger repeats
    /// overflows. Indefinitely repeating triggers and triggers set for
    /// exact time always cause an overflow.
    ///
    /// # Panics
    /// (Rare) Panics if someone stores actions, returned from `find_matching()`
    pub fn mod_repeats(
        &self,
        key: &trigger::Id,
        f: impl Fn(u32) -> Result<u32, MathError>,
    ) -> Result<(), smartcontracts::Error> {
        let mut entry = self
            .0
            .get_mut(key)
            .ok_or(smartcontracts::Error::Find(Box::new(FindError::Trigger(
                key.clone(),
            ))))?;

        let new_repeats = match &entry.repeats {
            Repeats::Exactly(n) => f(*n).map_err(Into::into),
            _ => Err(smartcontracts::Error::Math(MathError::Overflow)),
        }?;
        Arc::get_mut(&mut entry)
            .expect("Failed to get mutable action while modifying repeats")
            .repeats = Repeats::Exactly(new_repeats);

        Ok(())
    }

    pub fn find_matching<'e, E>(&self, events: E) -> Vec<Arc<Action>>
    where
        E: IntoIterator<Item = &'e Event>,
    {
        let mut result = Vec::new();

        for event in events {
            for mut trigger in self.0.iter_mut() {
                if trigger.filter.apply(event) {
                    match trigger.repeats {
                        Repeats::Indefinitely => {
                            result.push(trigger.value().clone());
                        }
                        Repeats::Exactly(n) if n > 0_u32 => {
                            Arc::get_mut(&mut trigger)
                                .expect("Failed to get mutable action while reducing repeats")
                                .repeats = Repeats::Exactly(n - 1);
                            result.push(trigger.value().clone());
                        }
                        _ => {
                            // n == 0
                            continue;
                        }
                    }
                }
            }
        }

        self.0
            .retain(|_, action| !matches!(action.repeats, Repeats::Exactly(0)));
        result
    }
}
