//! This module contains implementations of smart-contract traits and
//! instructions for triggers in Iroha.

use iroha_data_model::prelude::*;
use iroha_telemetry::metrics;

/// All instructions related to triggers.
/// - registering a trigger
/// - un-registering a trigger
/// - TODO: technical accounts.
/// - TODO: technical account permissions.
pub mod isi {
    use iroha_data_model::trigger::Trigger;

    use super::{super::prelude::*, *};

    /// Assert `repeats` field correctness
    ///
    /// # Errors
    /// Fails with `Overflow` error if action is based on exact time and
    /// repeats more than once
    fn assert_repeats_correct(action: &Action) -> Result<(), Error> {
        if let EventFilter::Time(TimeEventFilter(Occurrence::ExactlyAt(_))) = &action.filter {
            if !matches!(&action.repeats, Repeats::Exactly(1)) {
                return Err(Error::Math(MathError::Overflow));
            }
        }

        Ok(())
    }

    impl<W: WorldTrait> Execute<W> for Register<Trigger> {
        type Error = Error;

        #[metrics(+"register_trigger")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let new_trigger = self.object.clone();

            assert_repeats_correct(&new_trigger.action)?;

            wsv.modify_triggers(|triggers| {
                triggers.add(new_trigger)?;
                Ok(TriggerEvent::Created(self.object.id))
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
                assert_repeats_correct(&action)?;

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
                Ok(TriggerEvent::Shortened(trigger))
            })
        }
    }
}
