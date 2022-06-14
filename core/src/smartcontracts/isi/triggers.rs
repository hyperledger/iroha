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
    use iroha_data_model::trigger::{self, prelude::*};

    use super::{super::prelude::*, *};

    impl Execute for Register<Trigger<FilterBox>> {
        type Error = Error;

        #[metrics(+"register_trigger")]
        #[allow(clippy::expect_used)]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let new_trigger = self.object;

            if !new_trigger.action.mintable() {
                match &new_trigger.action.repeats {
                    Repeats::Exactly(action) if action.get() == 1 => (),
                    _ => {
                        return Err(MathError::Overflow.into());
                    }
                }
            }

            wsv.modify_triggers(|triggers| {
                let trigger_id = new_trigger.id.clone();
                let success = match &new_trigger.action.filter {
                    FilterBox::Data(_) => triggers.add_data_trigger(
                        new_trigger
                            .try_into()
                            .map_err(|e: &str| Self::Error::Conversion(e.to_owned()))?,
                    ),
                    FilterBox::Pipeline(_) => triggers.add_pipeline_trigger(
                        new_trigger
                            .try_into()
                            .map_err(|e: &str| Self::Error::Conversion(e.to_owned()))?,
                    ),
                    FilterBox::Time(_) => triggers.add_time_trigger(
                        new_trigger
                            .try_into()
                            .map_err(|e: &str| Self::Error::Conversion(e.to_owned()))?,
                    ),
                    FilterBox::ExecuteTrigger(_) => triggers.add_by_call_trigger(
                        new_trigger
                            .try_into()
                            .map_err(|e: &str| Self::Error::Conversion(e.to_owned()))?,
                    ),
                };
                if success {
                    Ok(TriggerEvent::Created(trigger_id))
                } else {
                    Err(Error::Repetition(
                        InstructionType::Register,
                        trigger_id.into(),
                    ))
                }
            })
        }
    }

    impl Execute for Unregister<Trigger<FilterBox>> {
        type Error = Error;

        #[metrics(+"unregister_trigger")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let trigger_id = self.object_id.clone();
            wsv.modify_triggers(|triggers| {
                if triggers.remove(&trigger_id) {
                    Ok(TriggerEvent::Deleted(self.object_id))
                } else {
                    Err(Error::Repetition(
                        InstructionType::Unregister,
                        trigger_id.into(),
                    ))
                }
            })
        }
    }

    impl Execute for Mint<Trigger<FilterBox>, u32> {
        type Error = Error;

        #[metrics(+"mint_trigger_repetitions")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let id = self.destination_id;

            wsv.modify_triggers(|triggers| {
                triggers
                    .inspect(&id, |action| -> Result<(), Self::Error> {
                        if action.mintable() {
                            Ok(())
                        } else {
                            Err(MathError::Overflow.into())
                        }
                    })
                    .ok_or_else(|| Error::Find(Box::new(FindError::Trigger(id.clone()))))??;

                triggers.mod_repeats(&id, |n| {
                    n.checked_add(self.object)
                        .ok_or(trigger::set::RepeatsOverflowError)
                })?;
                Ok(TriggerEvent::Extended(id))
            })
        }
    }

    impl Execute for Burn<Trigger<FilterBox>, u32> {
        type Error = Error;

        #[metrics(+"burn_trigger_repetitions")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let trigger = self.destination_id;
            wsv.modify_triggers(|triggers| {
                triggers.mod_repeats(&trigger, |n| {
                    n.checked_sub(self.object)
                        .ok_or(trigger::set::RepeatsOverflowError)
                })?;
                // TODO: Is it okay to remove triggers with 0 repeats count from `TriggerSet` only
                // when they will match some of the events?
                Ok(TriggerEvent::Shortened(trigger))
            })
        }
    }

    impl Execute for ExecuteTriggerBox {
        type Error = Error;

        #[metrics(+"execute_trigger")]
        fn execute(
            self,
            authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            wsv.execute_trigger(self.trigger_id, authority);
            Ok(())
        }
    }
}

pub mod query {
    //! Queries associated to triggers.

    use super::*;
    use crate::{
        prelude::*,
        smartcontracts::{query::Error, Evaluate as _, FindError},
    };

    impl ValidQuery for FindAllActiveTriggerIds {
        #[metrics(+"find_all_active_triggers")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            Ok(wsv.world.triggers.ids())
        }
    }

    impl ValidQuery for FindTriggerById {
        #[metrics(+"find_trigger_by_id")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(wsv, &Context::new())
                .map_err(|e| Error::Evaluate(format!("Failed to evaluate trigger id. {}", e)))?;
            iroha_logger::trace!(%id);
            // Can't use just `ActionTrait::clone_and_box` cause this will trigger lifetime mismatch
            #[allow(clippy::redundant_closure_for_method_calls)]
            let action = wsv
                .world
                .triggers
                .inspect(&id, |action| action.clone_and_box())
                .ok_or_else(|| Error::Find(Box::new(FindError::Trigger(id.clone()))))?;

            // TODO: Should we redact the metadata if the account is not the technical account/owner?
            Ok(Trigger::<FilterBox>::new(id, action))
        }
    }

    impl ValidQuery for FindTriggerKeyValueByIdAndKey {
        #[metrics(+"find_trigger_key_value_by_id_and_key")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let id = self
                .id
                .evaluate(wsv, &Context::new())
                .map_err(|e| Error::Evaluate(format!("Failed to evaluate trigger id. {}", e)))?;
            let key = self
                .key
                .evaluate(wsv, &Context::new())
                .map_err(|e| Error::Evaluate(format!("Failed to evaluate key. {}", e)))?;
            iroha_logger::trace!(%id, %key);
            wsv.world
                .triggers
                .inspect(&id, |action| {
                    action
                        .metadata()
                        .get(&key)
                        .map(Clone::clone)
                        .ok_or_else(|| FindError::MetadataKey(key.clone()).into())
                })
                .ok_or_else(|| Error::Find(Box::new(FindError::Trigger(id))))?
        }
    }

    impl ValidQuery for FindTriggersByDomainId {
        #[metrics(+"find_triggers_by_domain_id")]
        fn execute(&self, _wsv: &WorldStateView) -> eyre::Result<Self::Output, Error> {
            iroha_logger::warn!("'find triggers by domain id' is implemented as a stub.");
            Ok(vec![])
        }
    }
}
