//! This module contains implementations of smart-contract traits and
//! instructions for triggers in Iroha.

use iroha_data_model::prelude::*;
use iroha_telemetry::metrics;

/// Trait to check if [`Action`] should be executed at exact time or not.
/// Implemented as a trait and not as basic method, cause it is needed only inside this module.
trait OccursExactlyAtTime {
    /// Check if action occurs exactly at set time.
    /// Returns `true` if yes and `false` in another case
    fn occurs_exactly_at_time(&self) -> bool;
}

impl OccursExactlyAtTime for Action {
    fn occurs_exactly_at_time(&self) -> bool {
        matches!(
            self.filter,
            EventFilter::Time(TimeEventFilter(ExecutionTime::Schedule(TimeSchedule {
                period: None,
                ..
            })))
        )
    }
}

/// All instructions related to triggers.
/// - registering a trigger
/// - un-registering a trigger
/// - TODO: technical accounts.
/// - TODO: technical account permissions.
pub mod isi {
    use iroha_data_model::trigger::Trigger;

    use super::{super::prelude::*, *};

    impl<W: WorldTrait> Execute<W> for Register<Trigger> {
        type Error = Error;

        #[metrics(+"register_trigger")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let new_trigger = self.object;

            if new_trigger.action.occurs_exactly_at_time()
                && !matches!(&new_trigger.action.repeats, Repeats::Exactly(1))
            {
                return Err(Error::Math(MathError::Overflow));
            }

            wsv.modify_triggers(|triggers| {
                let trigger_id = new_trigger.id.clone();
                triggers.add(new_trigger)?;
                Ok(TriggerEvent::Created(trigger_id))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Unregister<Trigger> {
        type Error = Error;

        #[metrics(+"unregister_trigger")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let trigger = self.object_id.clone();
            wsv.modify_triggers(|triggers| {
                triggers.remove(&trigger)?;
                Ok(TriggerEvent::Deleted(self.object_id))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Mint<Trigger, u32> {
        type Error = Error;

        #[metrics(+"mint_trigger_repetitions")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let id = self.destination_id;

            wsv.modify_triggers(|triggers| {
                let action = triggers.get(&id)?;
                if action.occurs_exactly_at_time() {
                    return Err(MathError::Overflow.into());
                }

                triggers.mod_repeats(&id, |n| {
                    n.checked_add(self.object).ok_or(MathError::Overflow)
                })?;
                Ok(TriggerEvent::Extended(id))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Burn<Trigger, u32> {
        type Error = Error;

        #[metrics(+"burn_trigger_repetitions")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let trigger = self.destination_id;
            wsv.modify_triggers(|triggers| {
                triggers.mod_repeats(&trigger, |n| {
                    n.checked_sub(self.object).ok_or(MathError::Overflow)
                })?;
                // TODO: Is it okay to remove triggers with 0 repeats count from `TriggerSet` only
                // when they will match some of the events?
                Ok(TriggerEvent::Shortened(trigger))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for ExecuteTriggerBox {
        type Error = Error;

        #[metrics(+"execute_trigger")]
        fn execute(
            self,
            authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            wsv.execute_trigger(self.trigger_id, authority);
            Ok(())
        }
    }
}
