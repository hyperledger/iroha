//! Trigger logic. Instead of defining a Trigger as an entity, we
//! provide a collection of triggers as the smallest unit.

use core::ops::Deref;

use dashmap::DashMap;
use iroha_data_model::{prelude::*, transaction::Executable};

/// Specialised structure that maps event filters to Triggers.
#[derive(Debug, Default)]
pub struct TriggerSet(DashMap<EventFilter, Executable>);

impl Deref for TriggerSet {
    type Target = DashMap<EventFilter, Executable>;

    fn deref(&self) -> &Self::Target {
        todo!()
    }
}

/// Designed to differentiate between oneshot and unlimited
/// triggers. If the trigger must be run a limited number of times,
/// it's the end-user's responsibility to either unregister the
/// `Unlimited` variant.
///
/// # Considerations
///
/// The granularity might not be sufficient to run an action exactly
/// `n` times. In order to ensure that it is even possible to run the
/// triggers without gaps, the `Executable` wrapped in the action must
/// be run before any of the ISIs are pushed into the queue of the
/// next block.
pub enum Action {
    /// OneShot trigger.
    OneShot(Executable),
    /// Trigger that is run until it is unregistered.
    Unlimited(Executable),
}

impl TriggerSet {
    pub fn matching_event(&self, event: &Event) -> Vec<Executable> {
        let mut result = Vec::new();
        for element in self.iter() {
            if element.key().apply(event) {
                // TODO: Non oneshot triggers.
                let (_, value) = self.remove(element.key()).expect("The value disappeared");
                result.push(value);
            }
        }
        result
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn name() {
        let triggers = TriggerSet::default();
    }
}
