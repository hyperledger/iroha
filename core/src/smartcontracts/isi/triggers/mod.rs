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

            let last_block_estimation = state_transaction.latest_block().map(|block| {
                block.header().creation_time() + block.header().consensus_estimation()
            });

            let engine = state_transaction.engine.clone(); // Cloning engine is cheap
            let genesis_creation_time_ms = state_transaction.world().genesis_creation_time_ms();

            let triggers = &mut state_transaction.world.triggers;
            let trigger_id = new_trigger.id().clone();
            let success = match &new_trigger.action.filter {
                EventFilterBox::Data(_) => triggers.add_data_trigger(
                    &engine,
                    new_trigger
                        .try_into()
                        .map_err(|e: &str| Error::Conversion(e.to_owned()))?,
                ),
                EventFilterBox::Pipeline(_) => triggers.add_pipeline_trigger(
                    &engine,
                    new_trigger
                        .try_into()
                        .map_err(|e: &str| Error::Conversion(e.to_owned()))?,
                ),
                EventFilterBox::Time(time_filter) => {
                    if let ExecutionTime::Schedule(schedule) = time_filter.0 {
                        match last_block_estimation {
                            // Genesis block
                            None => {
                                let genesis_creation_time_ms = genesis_creation_time_ms
                                    .expect("INTERNAL BUG: genesis creation time not set");

                                if schedule.start_ms < genesis_creation_time_ms {
                                    return Err(Error::InvalidParameter(
                                        InvalidParameterError::TimeTriggerInThePast,
                                    ));
                                }
                            }
                            Some(latest_block_estimation) => {
                                if schedule.start() < latest_block_estimation {
                                    return Err(Error::InvalidParameter(
                                        InvalidParameterError::TimeTriggerInThePast,
                                    ));
                                }
                            }
                        }
                    }
                    triggers.add_time_trigger(
                        &engine,
                        new_trigger
                            .try_into()
                            .map_err(|e: &str| Error::Conversion(e.to_owned()))?,
                    )
                }
                EventFilterBox::ExecuteTrigger(_) => triggers.add_by_call_trigger(
                    &engine,
                    new_trigger
                        .try_into()
                        .map_err(|e: &str| Error::Conversion(e.to_owned()))?,
                ),
                EventFilterBox::TriggerCompleted(_) => {
                    unreachable!("Disallowed during deserialization");
                }
            }
            .map_err(|e| InvalidParameterError::Wasm(e.to_string()))?;

            if !success {
                return Err(RepetitionError {
                    instruction: InstructionType::Register,
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
            let trigger_id = self.object;

            let triggers = &mut state_transaction.world.triggers;
            if triggers.remove(trigger_id.clone()) {
                state_transaction
                    .world
                    .emit_events(Some(TriggerEvent::Deleted(trigger_id)));
                Ok(())
            } else {
                Err(RepetitionError {
                    instruction: InstructionType::Unregister,
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
            let id = self.destination;

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
                        trigger: id,
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
            let trigger = self.destination;
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
                        trigger,
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
            let trigger_id = self.object;

            state_transaction
                .world
                .triggers
                .inspect_by_id_mut(&trigger_id, |action| {
                    action
                        .metadata_mut()
                        .insert(self.key.clone(), self.value.clone())
                })
                .ok_or(FindError::Trigger(trigger_id.clone()))?;

            state_transaction
                .world
                .emit_events(Some(TriggerEvent::MetadataInserted(MetadataChanged {
                    target: trigger_id,
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
            let trigger_id = self.object;

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
                    target: trigger_id,
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
            let id = &self.trigger;

            let event = ExecuteTriggerEvent {
                trigger_id: id.clone(),
                authority: authority.clone(),
                args: self.args,
            };

            state_transaction
                .world
                .triggers
                .inspect_by_id(id, |action| -> Result<(), Error> {
                    let allow_execute = if let EventFilterBox::ExecuteTrigger(filter) =
                        action.clone_and_box().filter
                    {
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

            state_transaction.world.execute_trigger(event);

            Ok(())
        }
    }
}

pub mod query {
    //! Queries associated to triggers.
    use iroha_data_model::{
        query::{
            error::QueryExecutionFail as Error,
            predicate::{predicate_atoms::trigger::TriggerIdPredicateBox, CompoundPredicate},
        },
        trigger::{Trigger, TriggerId},
    };
    use iroha_primitives::json::JsonString;

    use super::*;
    use crate::{
        prelude::*,
        smartcontracts::{triggers::set::SetReadOnly, ValidQuery},
        state::StateReadOnly,
    };

    impl ValidQuery for FindActiveTriggerIds {
        #[metrics(+"find_active_triggers")]
        fn execute<'state>(
            self,
            filter: CompoundPredicate<TriggerIdPredicateBox>,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<impl Iterator<Item = TriggerId> + 'state, Error> {
            Ok(state_ro
                .world()
                .triggers()
                .ids_iter()
                .filter(move |&id| filter.applies(id))
                .cloned())
        }
    }

    impl ValidSingularQuery for FindTriggerById {
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

    impl ValidSingularQuery for FindTriggerMetadata {
        #[metrics(+"find_trigger_key_value_by_id_and_key")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<JsonString, Error> {
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
}
