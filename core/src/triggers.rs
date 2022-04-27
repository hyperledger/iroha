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

use std::{cmp::min, collections::HashSet, sync::RwLock};

use dashmap::DashMap;
use iroha_data_model::{
    domain,
    prelude::*,
    trigger::{self, Action, Repeats, Trigger},
};
use tokio::task;

use crate::smartcontracts::{self, FindError, InstructionType, MathError};

/// Specialized structure that maps event filters to Triggers.
#[derive(Debug, Default)]
pub struct TriggerSet {
    /// Owns actions
    all_triggers: DashMap<trigger::Id, Action>,
    /// Triggers using [`DataEventFilter`]
    data_triggers: DataTriggerSet,
    /// Other triggers
    non_data_triggers: RwLock<HashSet<trigger::Id>>,
}

/// Set for triggers that uses [`DataEventFilter`]. Allows to quickly find triggers watching for a
/// specific domain.
///
/// Stores only [`trigger::Id`]. All real triggers are stored in [`TriggerSet`].
/// Then a trigger is removed from `TriggerSet` its id should be removed from this structure too
#[derive(Debug, Default)]
struct DataTriggerSet {
    /// Triggers that are associated with some domain
    domain_associated: DashMap<domain::Id, HashSet<trigger::Id>>,
    /// All other data-triggers
    non_domain_associated: RwLock<HashSet<trigger::Id>>,
}

impl Clone for DataTriggerSet {
    fn clone(&self) -> Self {
        Self {
            non_domain_associated: RwLock::new(
                self.non_domain_associated
                    .read()
                    .expect("Can't lock actions to clone them")
                    .clone(),
            ),
            domain_associated: self.domain_associated.clone(),
        }
    }
}

impl DataTriggerSet {
    /// Add new trigger
    ///
    /// Stores `id` and uses `action` to identify if the trigger is related to some domain
    pub fn add(&self, id: trigger::Id, action: &Action) {
        if let Some(domain_id) = Self::get_associated_domain(action) {
            match self.domain_associated.get_mut(domain_id) {
                Some(mut entry) => {
                    entry.insert(id);
                }
                None => {
                    self.domain_associated
                        .insert(domain_id.clone(), HashSet::from([id]));
                }
            }
        } else {
            self.non_domain_associated
                .write()
                .expect("Can't lock actions for inserting a new one")
                .insert(id);
        }
    }

    /// Remove trigger
    ///
    /// Removes `id` and uses `action` to identify if the trigger is related to some domain.
    /// Doesn't do anything, if provided `id` not found
    pub fn remove(&self, id: &trigger::Id, action: &Action) {
        Self::get_associated_domain(action).map_or_else(
            || {
                self.non_domain_associated
                    .write()
                    .expect("Can't lock actions for removing")
                    .remove(id);
            },
            |domain_id| {
                self.domain_associated
                    .get_mut(domain_id)
                    .map(|mut entry| entry.remove(id));
            },
        );
    }

    /// Apply `f` to every stored *id* when related action filter can match with provided `event`
    ///
    /// # Error
    /// Throws up first `f` error
    pub fn inspect_matching_ids<F, E>(&self, event: &DataEvent, f: F) -> Result<(), E>
    where
        F: Fn(&trigger::Id) -> Result<(), E>,
    {
        use DataEvent::*;

        let domain_id = match event {
            Domain(domain_event) => Some(domain_event.id()),
            Account(account_event) => Some(&account_event.id().domain_id),
            Asset(asset_event) => Some(&asset_event.id().definition_id.domain_id),
            AssetDefinition(asset_definition_event) => Some(&asset_definition_event.id().domain_id),
            // Not using `_` pattern to break compilation
            // if some new event variant will be added in the future
            Peer(_) | Trigger(_) | Role(_) => None,
        };

        if let Some(id) = domain_id {
            if let Some(entry) = self.domain_associated.get(id) {
                for trigger_id in entry.value() {
                    f(trigger_id)?
                }
            }
        }

        for id in self
            .non_domain_associated
            .read()
            .expect("Can't lock actions for iterating")
            .iter()
        {
            f(id)?
        }

        Ok(())
    }

    /// Get domain id associated with `action`
    ///
    /// Returns `None` if action filter isn't associated with any domain
    fn get_associated_domain(action: &Action) -> Option<&domain::Id> {
        use DataEntityFilter::*;

        if let EventFilter::Data(BySome(filter)) = &action.filter {
            match filter {
                ByDomain(BySome(domain_filter)) => {
                    if let BySome(id_filter) = domain_filter.id_filter() {
                        Some(id_filter.id())
                    } else {
                        None
                    }
                }
                ByAccount(BySome(account_filter)) => {
                    if let BySome(id_filter) = account_filter.id_filter() {
                        Some(&id_filter.id().domain_id)
                    } else {
                        None
                    }
                }
                ByAsset(BySome(asset_filter)) => {
                    if let BySome(id_filter) = asset_filter.id_filter() {
                        Some(&id_filter.id().definition_id.domain_id)
                    } else {
                        None
                    }
                }
                ByAssetDefinition(BySome(asset_definition_filter)) => {
                    if let BySome(id_filter) = asset_definition_filter.id_filter() {
                        Some(&id_filter.id().domain_id)
                    } else {
                        None
                    }
                }
                // Not using `_` pattern to break compilation
                // if some new filter variant will be added in the future
                ByDomain(_) | ByAccount(_) | ByAsset(_) | ByAssetDefinition(_) | ByPeer(_)
                | ByTrigger(_) | ByRole(_) => None,
            }
        } else {
            None
        }
    }
}

impl Clone for TriggerSet {
    fn clone(&self) -> Self {
        Self {
            all_triggers: self.all_triggers.clone(),
            data_triggers: self.data_triggers.clone(),
            non_data_triggers: RwLock::new(
                self.non_data_triggers
                    .read()
                    .expect("Can't lock non-data actions to clone them")
                    .clone(),
            ),
        }
    }
}

impl From<TriggerSet> for Vec<trigger::Id> {
    fn from(TriggerSet(map): TriggerSet) -> Self {
        map.iter()
            .map(|reference| reference.key().clone())
            .collect()
    }
}

impl TriggerSet {
    /// Add another trigger to the [`TriggerSet`].
    ///
    /// # Errors
    /// - If [`TriggerSet`] already contains a trigger with the same id.
    /// It's the user's responsibility to first `Unregister` the `Trigger`.
    pub fn add(&self, trigger: Trigger) -> Result<(), smartcontracts::Error> {
        if self.all_triggers.contains_key(&trigger.id) {
            return Err(smartcontracts::Error::Repetition(
                InstructionType::Register,
                IdBox::TriggerId(trigger.id),
            ));
        }

        self.all_triggers.insert(trigger.id.clone(), trigger.action);
        let entry = self
            .all_triggers
            .get_mut(&trigger.id)
            .expect("Just inserted key must exist");

        if let EventFilter::Data(_) = entry.value().filter {
            self.data_triggers.add(entry.key().clone(), entry.value());
        } else {
            self.non_data_triggers
                .write()
                .expect("Can't lock non-data triggers to insert a new one")
                .insert(entry.key().clone());
        }

        Ok(())
    }

    /// Apply `f` to the trigger identified by `id`
    ///
    /// # Errors
    /// - If [`TriggerSet`] doesn't contain the trigger with the given `id`.
    pub fn inspect<F, R>(&self, id: &trigger::Id, f: F) -> Result<R, smartcontracts::Error>
    where
        F: Fn(&Action) -> R,
    {
        let entry = self
            .all_triggers
            .get(id)
            .ok_or_else(|| smartcontracts::Error::Find(Box::new(FindError::Trigger(id.clone()))))?;
        Ok(f(entry.value()))
    }

    /// Remove a trigger from the [`TriggerSet`].
    ///
    /// # Errors
    /// - If [`TriggerSet`] doesn't contain the trigger with the given `id`.
    pub fn remove(&self, id: &trigger::Id) -> Result<(), smartcontracts::Error> {
        {
            let entry = self.all_triggers.get_mut(id).ok_or_else(|| {
                smartcontracts::Error::Repetition(
                    InstructionType::Unregister,
                    IdBox::TriggerId(id.clone()),
                )
            })?;

            if let EventFilter::Data(_) = entry.value().filter {
                self.data_triggers.remove(entry.key(), entry.value());
            } else {
                self.non_data_triggers
                    .write()
                    .expect("Can't lock non-data triggers to remove one")
                    .remove(entry.key());
            }
        }

        self.all_triggers.remove(id);
        Ok(())
    }

    /// Check if [`TriggerSet`] contains `key`.
    pub fn contains(&self, key: &trigger::Id) -> bool {
        self.all_triggers.contains_key(key)
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
        f: impl Fn(u32) -> Result<u32, MathError>,
    ) -> Result<(), smartcontracts::Error> {
        let mut action = self
            .all_triggers
            .get_mut(id)
            .ok_or_else(|| smartcontracts::Error::Find(Box::new(FindError::Trigger(id.clone()))))?;

        let new_repeats = match &action.repeats {
            Repeats::Exactly(n) => f(*n).map_err(Into::into),
            _ => Err(smartcontracts::Error::Math(MathError::Overflow)),
        }?;
        action.repeats = Repeats::Exactly(new_repeats);

        Ok(())
    }

    /// Apply `f` to every trigger, which filter matches at least one event from `events`
    ///
    /// # Errors
    /// Throws up first `f` error
    pub async fn inspect_matching<'evnt, E, I, F, Er>(&self, events: E, f: F) -> Result<(), Er>
    where
        E: IntoIterator<Item = &'evnt Event, IntoIter = I> + Send,
        I: Iterator<Item = &'evnt Event> + Send,
        F: Fn(&Action) -> Result<(), Er> + Send,
    {
        for event in events {
            // Using closure to be able to reuse `f`
            if let Event::Data(data_event) = event {
                self.inspect_data_actions(data_event, |action| f(action))?;
            } else {
                self.inspect_non_data_actions(event, |action| f(action))?;
            }
            task::yield_now().await;
        }

        let to_remove: Vec<trigger::Id> = self
            .all_triggers
            .iter()
            .filter_map(|entry| {
                matches!(entry.value().repeats, Repeats::Exactly(0)).then(|| entry.key().clone())
            })
            .collect();

        for id in to_remove {
            self.remove(&id)
                .expect("Removing existing keys should be always possible. This is a bug");
        }

        Ok(())
    }

    fn inspect_data_actions<F, E>(&self, event: &DataEvent, f: F) -> Result<(), E>
    where
        F: Fn(&Action) -> Result<(), E>,
    {
        self.data_triggers.inspect_matching_ids(event, |id| {
            let mut entry = self
                .all_triggers
                .get_mut(id)
                .expect("data-triggers contains non-existing key. This is a bug");

            Self::inspect_action(&Event::Data(event.clone()), entry.value_mut(), |action| {
                f(action)
            })
        })
    }

    fn inspect_non_data_actions<F, E>(&self, event: &Event, f: F) -> Result<(), E>
    where
        F: Fn(&Action) -> Result<(), E>,
    {
        for mut entry in self
            .non_data_triggers
            .read()
            .expect("Can't lock non-data triggers to iterate")
            .iter()
            .map(|id| {
                self.all_triggers
                    .get_mut(id)
                    .expect("non-data-triggers contains non-existing key. This is a bug")
            })
        {
            // Using closure to be able to reuse `f`
            Self::inspect_action(event, entry.value_mut(), |action| f(action))?
        }

        Ok(())
    }

    fn inspect_action<F, E>(event: &Event, action: &mut Action, f: F) -> Result<(), E>
    where
        F: Fn(&Action) -> Result<(), E>,
    {
        if let Event::Time(time_event) = event {
            if let EventFilter::Time(time_filter) = action.filter {
                let mut count = time_filter.count_matches(time_event);
                if let Repeats::Exactly(n) = &mut action.repeats {
                    count = min(*n, count);
                    *n -= count;
                }

                for _ in 0..count {
                    f(&*action)?;
                }
            }
        } else if action.filter.matches(event) {
            match action.repeats {
                Repeats::Indefinitely => {
                    f(&*action)?;
                }
                Repeats::Exactly(n) if n > 0_u32 => {
                    action.repeats = Repeats::Exactly(n - 1);
                    f(&*action)?;
                }
                _ => {
                    // n == 0
                }
            }
        }

        Ok(())
    }
}
