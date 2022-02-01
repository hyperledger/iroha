//! This module contains implementations of smart-contract traits and
//! instructions for triggers in Iroha.

use iroha_data_model::prelude::*;
use iroha_telemetry::metrics;

use crate::prelude::*;

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
        type Diff = DataEvent;

        #[metrics(+"register_trigger")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            let new_trigger = self.object.clone();
            wsv.triggers.add(new_trigger)?;
            Ok(self.into())
        }
    }

    impl<W: WorldTrait> Execute<W> for Unregister<Trigger> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"unregister_trigger")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            let trigger = self.object_id.clone();
            wsv.triggers.remove(trigger)?;
            Ok(self.into())
        }
    }

    impl<W: WorldTrait> Execute<W> for Mint<Trigger, u32> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"mint_trigger_repetitions")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            let trigger = self.destination_id.clone();
            wsv.triggers.mint_repeats(trigger, self.object)?;
            Ok(self.into())
        }
    }

    impl<W: WorldTrait> Execute<W> for Burn<Trigger, u32> {
        type Error = Error;
        type Diff = DataEvent;

        #[metrics(+"burn_trigger_repetitions")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<Self::Diff, Self::Error> {
            let trigger = self.destination_id.clone();
            wsv.triggers.burn_repeats(trigger, self.object)?;
            Ok(self.into())
        }
    }
}
