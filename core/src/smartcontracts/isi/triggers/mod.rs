//! This module contains implementations of smart-contract traits and
//! instructions for triggers in Iroha.

use iroha_data_model::{isi::error::MathError, prelude::*, query::error::FindError};
use iroha_telemetry::metrics;

pub mod set;
pub mod specialized;

/// All instructions related to triggers.
/// - registering a trigger
/// - un-registering a trigger
/// - TODO: authorities.
/// - TODO: authority permissions.
pub mod isi {
    use std::time::Duration;

    use iroha_data_model::{
        events::EventFilter,
        isi::error::{InvalidParameterError, RepetitionError},
        trigger::prelude::*,
    };

    use super::{super::prelude::*, *};

    impl Execute for Register<Trigger> {
        #[metrics(+"register_trigger")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let new_trigger = self.object;

            if !new_trigger.action.filter.mintable() {
                match &new_trigger.action.repeats {
                    Repeats::Exactly(action) if *action == 1 => (),
                    _ => {
                        return Err(MathError::Overflow.into());
                    }
                }
            }

            let last_block_estimation = state_transaction.latest_block_ref().map(|block| {
                block.header().timestamp()
                    + Duration::from_millis(block.header().consensus_estimation_ms)
            });

            let engine = state_transaction.engine.clone(); // Cloning engine is cheap
            let triggers = &mut state_transaction.world.triggers;
            let trigger_id = new_trigger.id().clone();
            let success = match &new_trigger.action.filter {
                TriggeringEventFilterBox::Data(_) => triggers.add_data_trigger(
                    &engine,
                    new_trigger
                        .try_into()
                        .map_err(|e: &str| Error::Conversion(e.to_owned()))?,
                ),
                TriggeringEventFilterBox::Pipeline(_) => triggers.add_pipeline_trigger(
                    &engine,
                    new_trigger
                        .try_into()
                        .map_err(|e: &str| Error::Conversion(e.to_owned()))?,
                ),
                TriggeringEventFilterBox::Time(time_filter) => {
                    if let ExecutionTime::Schedule(schedule) = time_filter.0 {
                        match last_block_estimation {
                            // We're in genesis
                            None => {
                                return Err(Error::InvalidParameter(
                                    InvalidParameterError::TimeTriggerInThePast,
                                ));
                            }
                            Some(latest_block_estimation)
                                if schedule.start < latest_block_estimation =>
                            {
                                return Err(Error::InvalidParameter(
                                    InvalidParameterError::TimeTriggerInThePast,
                                ));
                            }
                            Some(_) => (),
                        }
                    }
                    triggers.add_time_trigger(
                        &engine,
                        new_trigger
                            .try_into()
                            .map_err(|e: &str| Error::Conversion(e.to_owned()))?,
                    )
                }
                TriggeringEventFilterBox::ExecuteTrigger(_) => triggers.add_by_call_trigger(
                    &engine,
                    new_trigger
                        .try_into()
                        .map_err(|e: &str| Error::Conversion(e.to_owned()))?,
                ),
            }
            .map_err(|e| InvalidParameterError::Wasm(e.to_string()))?;

            if !success {
                return Err(RepetitionError {
                    instruction_type: InstructionType::Register,
                    id: trigger_id.into(),
                }
                .into());
            }

            state_transaction
                .world
                .emit_events(Some(TriggerEvent::Created(trigger_id)));

            Ok(())
        }
    }

    impl Execute for Unregister<Trigger> {
        #[metrics(+"unregister_trigger")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let trigger_id = self.object_id.clone();

            let triggers = &mut state_transaction.world.triggers;
            if triggers.remove(trigger_id.clone()) {
                state_transaction
                    .world
                    .emit_events(Some(TriggerEvent::Deleted(self.object_id)));
                Ok(())
            } else {
                Err(RepetitionError {
                    instruction_type: InstructionType::Unregister,
                    id: trigger_id.into(),
                }
                .into())
            }
        }
    }

    impl Execute for Mint<u32, Trigger> {
        #[metrics(+"mint_trigger_repetitions")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let id = self.destination_id;

            let triggers = &mut state_transaction.world.triggers;
            triggers
                .inspect_by_id(&id, |action| -> Result<(), Error> {
                    if action.mintable() {
                        Ok(())
                    } else {
                        Err(MathError::Overflow.into())
                    }
                })
                .ok_or_else(|| Error::Find(FindError::Trigger(id.clone())))??;

            triggers.mod_repeats(&id, |n| {
                n.checked_add(self.object)
                    .ok_or(super::set::RepeatsOverflowError)
            })?;

            state_transaction
                .world
                .emit_events(Some(TriggerEvent::Extended(
                    TriggerNumberOfExecutionsChanged {
                        trigger_id: id,
                        by: self.object,
                    },
                )));

            Ok(())
        }
    }

    impl Execute for Burn<u32, Trigger> {
        #[metrics(+"burn_trigger_repetitions")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let trigger = self.destination_id;
            let triggers = &mut state_transaction.world.triggers;
            triggers.mod_repeats(&trigger, |n| {
                n.checked_sub(self.object)
                    .ok_or(super::set::RepeatsOverflowError)
            })?;
            // TODO: Is it okay to remove triggers with 0 repeats count from `TriggerSet` only
            // when they will match some of the events?
            state_transaction
                .world
                .emit_events(Some(TriggerEvent::Shortened(
                    TriggerNumberOfExecutionsChanged {
                        trigger_id: trigger,
                        by: self.object,
                    },
                )));

            Ok(())
        }
    }

    impl Execute for SetKeyValue<Trigger> {
        #[metrics(+"set_trigger_key_value")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let trigger_id = self.object_id;

            let trigger_metadata_limits = state_transaction.config.account_metadata_limits;
            state_transaction
                .world
                .triggers
                .inspect_by_id_mut(&trigger_id, |action| {
                    action.metadata_mut().insert_with_limits(
                        self.key.clone(),
                        self.value.clone(),
                        trigger_metadata_limits,
                    )
                })
                .ok_or(FindError::Trigger(trigger_id.clone()))??;

            state_transaction
                .world
                .emit_events(Some(TriggerEvent::MetadataInserted(MetadataChanged {
                    target_id: trigger_id,
                    key: self.key,
                    value: self.value,
                })));

            Ok(())
        }
    }

    impl Execute for RemoveKeyValue<Trigger> {
        #[metrics(+"remove_trigger_key_value")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let trigger_id = self.object_id;

            let value = state_transaction
                .world
                .triggers
                .inspect_by_id_mut(&trigger_id, |action| {
                    action
                        .metadata_mut()
                        .remove(&self.key)
                        .ok_or_else(|| FindError::MetadataKey(self.key.clone()))
                })
                .ok_or(FindError::Trigger(trigger_id.clone()))??;

            state_transaction
                .world
                .emit_events(Some(TriggerEvent::MetadataRemoved(MetadataChanged {
                    target_id: trigger_id,
                    key: self.key,
                    value,
                })));

            Ok(())
        }
    }

    impl Execute for ExecuteTrigger {
        #[metrics(+"execute_trigger")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let id = &self.trigger_id;

            state_transaction
                .world
                .triggers
                .inspect_by_id(id, |action| -> Result<(), Error> {
                    let allow_execute = if let TriggeringEventFilterBox::ExecuteTrigger(filter) =
                        action.clone_and_box().filter
                    {
                        let event = ExecuteTriggerEvent {
                            trigger_id: id.clone(),
                            authority: authority.clone(),
                        };

                        filter.matches(&event) || action.authority() == authority
                    } else {
                        false
                    };
                    if allow_execute {
                        Ok(())
                    } else {
                        // TODO: We should check authority on Runtime Executor level
                        // so currently the error message is not exhaustive
                        Err(Error::InvariantViolation(String::from(
                            "Trigger can't be executed manually",
                        )))
                    }
                })
                .ok_or_else(|| Error::Find(FindError::Trigger(id.clone())))
                .and_then(core::convert::identity)?;

            state_transaction
                .world
                .execute_trigger(id.clone(), authority);

            Ok(())
        }
    }
}

pub mod query {
    //! Queries associated to triggers.
    use iroha_data_model::{
        metadata::MetadataValueBox,
        query::error::QueryExecutionFail as Error,
        trigger::{Trigger, TriggerId},
    };

    use super::*;
    use crate::{prelude::*, smartcontracts::triggers::set::SetReadOnly, state::StateReadOnly};

    impl ValidQuery for FindAllActiveTriggerIds {
        #[metrics(+"find_all_active_triggers")]
        fn execute<'state>(
            &self,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<Box<dyn Iterator<Item = TriggerId> + 'state>, Error> {
            Ok(Box::new(state_ro.world().triggers().ids_iter().cloned()))
        }
    }

    impl ValidQuery for FindTriggerById {
        #[metrics(+"find_trigger_by_id")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<Trigger, Error> {
            let id = &self.id;
            iroha_logger::trace!(%id);
            // Can't use just `LoadedActionTrait::clone_and_box` cause this will trigger lifetime mismatch
            #[allow(clippy::redundant_closure_for_method_calls)]
            let loaded_action = state_ro
                .world()
                .triggers()
                .inspect_by_id(id, |action| action.clone_and_box())
                .ok_or_else(|| Error::Find(FindError::Trigger(id.clone())))?;

            let action = state_ro
                .world()
                .triggers()
                .get_original_action(loaded_action)
                .into();

            // TODO: Should we redact the metadata if the account is not the authority/owner?
            Ok(Trigger::new(id.clone(), action))
        }
    }

    impl ValidQuery for FindTriggerKeyValueByIdAndKey {
        #[metrics(+"find_trigger_key_value_by_id_and_key")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<MetadataValueBox, Error> {
            let id = &self.id;
            let key = &self.key;
            iroha_logger::trace!(%id, %key);
            state_ro
                .world()
                .triggers()
                .inspect_by_id(id, |action| {
                    action
                        .metadata()
                        .get(key)
                        .cloned()
                        .ok_or_else(|| FindError::MetadataKey(key.clone()).into())
                })
                .ok_or_else(|| Error::Find(FindError::Trigger(id.clone())))?
                .map(Into::into)
        }
    }

    impl ValidQuery for FindTriggersByDomainId {
        #[metrics(+"find_triggers_by_domain_id")]
        fn execute<'state>(
            &self,
            state_ro: &'state impl StateReadOnly,
        ) -> eyre::Result<Box<dyn Iterator<Item = Trigger> + 'state>, Error> {
            let domain_id = &self.domain_id;

            Ok(Box::new(
                state_ro
                    .world()
                    .triggers()
                    .inspect_by_domain_id(domain_id, |trigger_id, action| {
                        (trigger_id.clone(), action.clone_and_box())
                    })
                    .map(|(trigger_id, action)| {
                        let action = state_ro
                            .world()
                            .triggers()
                            .get_original_action(action)
                            .into();
                        Trigger::new(trigger_id, action)
                    }),
            ))
        }
    }
}
