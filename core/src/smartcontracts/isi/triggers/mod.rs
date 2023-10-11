//! This module contains implementations of smart-contract traits and
//! instructions for triggers in Iroha.

use iroha_data_model::{
    evaluate::ExpressionEvaluator, isi::error::MathError, prelude::*, query::error::FindError,
};
use iroha_telemetry::metrics;

pub mod set;

/// All instructions related to triggers.
/// - registering a trigger
/// - un-registering a trigger
/// - TODO: authorities.
/// - TODO: authority permissions.
pub mod isi {
    use iroha_data_model::{
        events::Filter,
        isi::error::{InvalidParameterError, RepetitionError},
        trigger::prelude::*,
    };

    use super::{super::prelude::*, *};

    impl Execute for Register<Trigger<TriggeringFilterBox, Executable>> {
        #[metrics(+"register_trigger")]
        #[allow(clippy::expect_used)]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let new_trigger = self.object;

            if !new_trigger.action.filter.mintable() {
                match &new_trigger.action.repeats {
                    Repeats::Exactly(action) if *action == 1 => (),
                    _ => {
                        return Err(MathError::Overflow.into());
                    }
                }
            }

            let engine = wsv.engine.clone(); // Cloning engine is cheap
            let triggers = wsv.triggers_mut();
            let trigger_id = new_trigger.id().clone();
            let success = match &new_trigger.action.filter {
                TriggeringFilterBox::Data(_) => triggers.add_data_trigger(
                    &engine,
                    new_trigger
                        .try_into()
                        .map_err(|e: &str| Error::Conversion(e.to_owned()))?,
                ),
                TriggeringFilterBox::Pipeline(_) => triggers.add_pipeline_trigger(
                    &engine,
                    new_trigger
                        .try_into()
                        .map_err(|e: &str| Error::Conversion(e.to_owned()))?,
                ),
                TriggeringFilterBox::Time(_) => triggers.add_time_trigger(
                    &engine,
                    new_trigger
                        .try_into()
                        .map_err(|e: &str| Error::Conversion(e.to_owned()))?,
                ),
                TriggeringFilterBox::ExecuteTrigger(_) => triggers.add_by_call_trigger(
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

            wsv.emit_events(Some(TriggerEvent::Created(trigger_id)));

            Ok(())
        }
    }

    impl Execute for Unregister<Trigger<TriggeringFilterBox, Executable>> {
        #[metrics(+"unregister_trigger")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let trigger_id = self.object_id.clone();

            let triggers = wsv.triggers_mut();
            if triggers.remove(&trigger_id) {
                wsv.emit_events(Some(TriggerEvent::Deleted(self.object_id)));
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

    impl Execute for Mint<u32, Trigger<TriggeringFilterBox, Executable>> {
        #[metrics(+"mint_trigger_repetitions")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let id = self.destination_id;

            let triggers = wsv.triggers_mut();
            triggers
                .inspect_by_id(&id, |action| -> Result<(), Error> {
                    if action.mintable() {
                        Ok(())
                    } else {
                        Err(MathError::Overflow.into())
                    }
                })
                .ok_or_else(|| Error::Find(Box::new(FindError::Trigger(id.clone()))))??;

            triggers.mod_repeats(&id, |n| {
                n.checked_add(self.object)
                    .ok_or(super::set::RepeatsOverflowError)
            })?;

            wsv.emit_events(Some(TriggerEvent::Extended(
                TriggerNumberOfExecutionsChanged {
                    trigger_id: id,
                    by: self.object,
                },
            )));

            Ok(())
        }
    }

    impl Execute for Burn<u32, Trigger<TriggeringFilterBox, Executable>> {
        #[metrics(+"burn_trigger_repetitions")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let trigger = self.destination_id;
            let triggers = wsv.triggers_mut();
            triggers.mod_repeats(&trigger, |n| {
                n.checked_sub(self.object)
                    .ok_or(super::set::RepeatsOverflowError)
            })?;
            // TODO: Is it okay to remove triggers with 0 repeats count from `TriggerSet` only
            // when they will match some of the events?
            wsv.emit_events(Some(TriggerEvent::Shortened(
                TriggerNumberOfExecutionsChanged {
                    trigger_id: trigger,
                    by: self.object,
                },
            )));

            Ok(())
        }
    }

    impl Execute for ExecuteTriggerExpr {
        #[metrics(+"execute_trigger")]
        fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let id = wsv.evaluate(&self.trigger_id)?;

            wsv.triggers()
                .inspect_by_id(&id, |action| -> Result<(), Error> {
                    let allow_execute = if let TriggeringFilterBox::ExecuteTrigger(filter) =
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
                .ok_or_else(|| Error::Find(Box::new(FindError::Trigger(id.clone()))))
                .and_then(core::convert::identity)?;

            wsv.execute_trigger(id, authority);

            Ok(())
        }
    }
}

pub mod query {
    //! Queries associated to triggers.
    use iroha_data_model::{
        events::TriggeringFilterBox,
        query::{error::QueryExecutionFail as Error, MetadataValue},
        trigger::{OptimizedExecutable, Trigger, TriggerId},
    };

    use super::*;
    use crate::prelude::*;

    impl ValidQuery for FindAllActiveTriggerIds {
        #[metrics(+"find_all_active_triggers")]
        fn execute<'wsv>(
            &self,
            wsv: &'wsv WorldStateView,
        ) -> Result<Box<dyn Iterator<Item = TriggerId> + 'wsv>, Error> {
            Ok(Box::new(wsv.triggers().ids().cloned()))
        }
    }

    impl ValidQuery for FindTriggerById {
        #[metrics(+"find_trigger_by_id")]
        fn execute(
            &self,
            wsv: &WorldStateView,
        ) -> Result<Trigger<TriggeringFilterBox, OptimizedExecutable>, Error> {
            let id = wsv
                .evaluate(&self.id)
                .map_err(|e| Error::Evaluate(format!("Failed to evaluate trigger id. {e}")))?;
            iroha_logger::trace!(%id);
            // Can't use just `ActionTrait::clone_and_box` cause this will trigger lifetime mismatch
            #[allow(clippy::redundant_closure_for_method_calls)]
            let Action {
                executable: loaded_executable,
                repeats,
                authority,
                filter,
                metadata,
            } = wsv
                .triggers()
                .inspect_by_id(&id, |action| action.clone_and_box())
                .ok_or_else(|| Error::Find(FindError::Trigger(id.clone())))?;

            let action =
                Action::new(loaded_executable, repeats, authority, filter).with_metadata(metadata);

            // TODO: Should we redact the metadata if the account is not the authority/owner?
            Ok(Trigger::new(id, action))
        }
    }

    impl ValidQuery for FindTriggerKeyValueByIdAndKey {
        #[metrics(+"find_trigger_key_value_by_id_and_key")]
        fn execute(&self, wsv: &WorldStateView) -> Result<MetadataValue, Error> {
            let id = wsv
                .evaluate(&self.id)
                .map_err(|e| Error::Evaluate(format!("Failed to evaluate trigger id. {e}")))?;
            let key = wsv
                .evaluate(&self.key)
                .map_err(|e| Error::Evaluate(format!("Failed to evaluate key. {e}")))?;
            iroha_logger::trace!(%id, %key);
            wsv.triggers()
                .inspect_by_id(&id, |action| {
                    action
                        .metadata()
                        .get(&key)
                        .cloned()
                        .ok_or_else(|| FindError::MetadataKey(key.clone()).into())
                })
                .ok_or_else(|| Error::Find(FindError::Trigger(id)))?
                .map(Into::into)
        }
    }

    impl ValidQuery for FindTriggersByDomainId {
        #[metrics(+"find_triggers_by_domain_id")]
        fn execute<'wsv>(
            &self,
            wsv: &'wsv WorldStateView,
        ) -> eyre::Result<
            Box<dyn Iterator<Item = Trigger<TriggeringFilterBox, OptimizedExecutable>> + 'wsv>,
            Error,
        > {
            let domain_id = wsv
                .evaluate(&self.domain_id)
                .map_err(|e| Error::Evaluate(format!("Failed to evaluate domain id. {e}")))?;

            Ok(Box::new(wsv.triggers().inspect_by_domain_id(
                &domain_id,
                |trigger_id, action| {
                    let Action {
                        executable: loaded_executable,
                        repeats,
                        authority,
                        filter,
                        metadata,
                    } = action.clone_and_box();

                    Trigger::new(
                        trigger_id.clone(),
                        Action::new(loaded_executable, repeats, authority, filter)
                            .with_metadata(metadata),
                    )
                },
            )))
        }
    }
}
