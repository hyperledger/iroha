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

    impl<W: WorldTrait> Execute<W> for Register<Trigger> {
        type Error = Error;

        #[metrics(+"register_trigger")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Vec<DataEvent>, Self::Error> {
            let new_trigger = self.object.clone();
            wsv.triggers.add(new_trigger)?;
            Ok(vec![DataEvent::new(self.object.id, DataStatus::Created)])
        }
    }

    impl<W: WorldTrait> Execute<W> for Unregister<Trigger> {
        type Error = Error;

        #[metrics(+"unregister_trigger")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Vec<DataEvent>, Self::Error> {
            let trigger = self.object_id.clone();
            wsv.triggers.remove(trigger)?;
            Ok(vec![DataEvent::new(self.object_id, DataStatus::Deleted)])
        }
    }

    impl<W: WorldTrait> Execute<W> for Mint<Trigger, u32> {
        type Error = Error;

        #[metrics(+"mint_trigger_repetitions")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Vec<DataEvent>, Self::Error> {
            let trigger = self.destination_id.clone();
            wsv.triggers.mod_repeats(trigger, |n| {
                n.checked_add(self.object).ok_or(MathError::Overflow)
            })?;
            Ok(vec![DataEvent::new(
                self.destination_id,
                Updated::Trigger(TriggerUpdated::Extended),
            )])
        }
    }

    impl<W: WorldTrait> Execute<W> for Burn<Trigger, u32> {
        type Error = Error;

        #[metrics(+"burn_trigger_repetitions")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Vec<DataEvent>, Self::Error> {
            let trigger = self.destination_id.clone();
            wsv.triggers.mod_repeats(trigger, |n| {
                n.checked_sub(self.object).ok_or(MathError::Overflow)
            })?;
            Ok(vec![DataEvent::new(
                self.destination_id,
                Updated::Trigger(TriggerUpdated::Shortened),
            )])
        }
    }
}
