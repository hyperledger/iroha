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

    impl<W: WorldTrait> Execute<W> for Register<Trigger<FilterBox>> {
        type Error = Error;

        #[metrics(+"register_trigger")]
        #[allow(clippy::expect_used)]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let new_trigger = self.object;

            if !new_trigger.action.mintable() {
                match &new_trigger.action.repeats {
                    Repeats::Exactly(action) if action.get() == 1 => (),
                    _ => {
                        return Err(Error::Math(MathError::Overflow));
                    }
                }
            }

            wsv.modify_triggers(|triggers| {
                let trigger_id = new_trigger.id.clone();
                match &new_trigger.action.filter {
                    FilterBox::Data(_) => triggers.add_data_trigger(
                        new_trigger
                            .try_into()
                            .map_err(|e: &str| Self::Error::Conversion(e.to_owned()))?,
                    )?,
                    FilterBox::Pipeline(_) => triggers.add_pipeline_trigger(
                        new_trigger
                            .try_into()
                            .map_err(|e: &str| Self::Error::Conversion(e.to_owned()))?,
                    )?,
                    FilterBox::Time(_) => triggers.add_time_trigger(
                        new_trigger
                            .try_into()
                            .map_err(|e: &str| Self::Error::Conversion(e.to_owned()))?,
                    )?,
                    FilterBox::ExecuteTrigger(_) => triggers.add_by_call_trigger(
                        new_trigger
                            .try_into()
                            .map_err(|e: &str| Self::Error::Conversion(e.to_owned()))?,
                    )?,
                }
                Ok(TriggerEvent::Created(trigger_id))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Unregister<Trigger<FilterBox>> {
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

    impl<W: WorldTrait> Execute<W> for Mint<Trigger<FilterBox>, u32> {
        type Error = Error;

        #[metrics(+"mint_trigger_repetitions")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView<W>,
        ) -> Result<(), Self::Error> {
            let id = self.destination_id;

            wsv.modify_triggers(|triggers| {
                triggers.inspect(&id, |action| -> Result<(), Self::Error> {
                    if action.mintable() {
                        Ok(())
                    } else {
                        Err(MathError::Overflow.into())
                    }
                })??;

                triggers.mod_repeats(&id, |n| {
                    n.checked_add(self.object).ok_or(MathError::Overflow)
                })?;
                Ok(TriggerEvent::Extended(id))
            })
        }
    }

    impl<W: WorldTrait> Execute<W> for Burn<Trigger<FilterBox>, u32> {
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

pub mod query {
    //! Queries associated to triggers.
    use iroha_logger::prelude::*;

    use super::*;
    use crate::{
        prelude::*,
        smartcontracts::{isi::prelude::WorldTrait, query::Error, Evaluate as _, FindError},
    };

    impl<W: WorldTrait> ValidQuery<W> for FindAllActiveTriggerIds {
        #[log]
        #[metrics(+"find_all_active_triggers")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            Ok(wsv.world.triggers.clone().ids())
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindTriggerById {
        #[log]
        #[metrics(+"find_trigger_by_id")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(wsv, &Context::new())
                .map_err(|e| Error::Evaluate(format!("Failed to evaluate trigger id. {}", e)))?;

            // Can't use just `ActionTrait::clone_and_box` cause this will trigger lifetime mismatch
            #[allow(clippy::redundant_closure_for_method_calls)]
            let action = wsv
                .world
                .triggers
                .inspect(&id, |action| action.clone_and_box())?;

            // TODO: Should we redact the metadata if the account is not the technical account/owner?
            Ok(Trigger::<FilterBox>::new(id, action))
        }
    }

    impl<W: WorldTrait> ValidQuery<W> for FindTriggerKeyValueByIdAndKey {
        #[log]
        #[metrics(+"find_trigger_key_value_by_id_and_key")]
        fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(wsv, &Context::new())
                .map_err(|e| Error::Evaluate(format!("Failed to evaluate trigger id. {}", e)))?;
            let key = self
                .key
                .evaluate(wsv, &Context::new())
                .map_err(|e| Error::Evaluate(format!("Failed to evaluate key. {}", e)))?;
            wsv.world.triggers.inspect(&id, |action| {
                action
                    .metadata()
                    .get(&key)
                    .map(Clone::clone)
                    .ok_or_else(|| FindError::MetadataKey(key.clone()).into())
            })?
        }
    }
}
