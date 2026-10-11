//! One rollback and retention boundary for actual Pipeline and Time invocations.
//! Failure policy uses the real rejection before bounded diagnostic projection.

use super::*;
use crate::smartcontracts::isi::triggers::{
    TRIGGER_ENABLED_METADATA_KEY,
    set::{
        SetReadOnly,
        invocation_identity::{pipeline_trigger_use_v1, time_trigger_use_v1},
    },
    specialized::{LoadedActionTrait, TimeTriggerRetryState},
};
use crate::state::StateReadOnly;
use crate::state::contract_event_journal::DrainedContractEvents;
use iroha_data_model::{
    ValidationFail,
    block::execution_output::{
        INTERNAL_REJECTION_DIAGNOSTIC_OMITTED, InvocationCompletionV1, PipelineExecutionOutputV1,
        PipelineInvocationV1, TimeExecutionOutputV1, TimeInvocationV1, TriggerFailureRootV1,
        TriggerUseV1,
    },
    events::{
        EventBox,
        trigger_completed::{TriggerCompletedEvent, TriggerCompletedOutcome},
    },
    transaction::{
        TransactionResult,
        error::{TransactionLimitError, TransactionRejectionReason},
        signed::ExecutionStep,
    },
};
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;
use mv::storage::StorageReadOnly;

pub(super) enum InternalInvocation {
    Pipeline(PipelineInvocationV1),
    Time(TimeInvocationV1),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum InternalOutputDisposition {
    Applied,
    OutputLimit,
    Rejected,
}

impl InternalInvocation {
    fn trigger(&self) -> &TriggerUseV1 {
        match self {
            Self::Pipeline(i) => &i.trigger,
            Self::Time(i) => &i.trigger,
        }
    }

    fn call(&self, proposal: HashOf<iroha_data_model::block::BlockHeader>) -> Result<Hash, String> {
        match self {
            Self::Pipeline(i) => i.execution_call_hash(proposal),
            Self::Time(i) => i.execution_call_hash(proposal),
        }
    }

    fn terminal(&self) -> ExecutionOutputV1 {
        match self {
            Self::Pipeline(i) => ExecutionOutputV1::pipeline_output_limit_rejection(i.clone()),
            Self::Time(i) => ExecutionOutputV1::time_output_limit_rejection(i.clone()),
        }
    }

    fn row(
        &self,
        result: TransactionResult,
        failure_root: Option<TriggerFailureRootV1>,
        completions: Vec<InvocationCompletionV1>,
    ) -> ExecutionOutputV1 {
        match self {
            Self::Pipeline(i) => ExecutionOutputV1::Pipeline(PipelineExecutionOutputV1 {
                invocation: i.clone(),
                result,
                failure_root,
                completions,
            }),
            Self::Time(i) => ExecutionOutputV1::Time(TimeExecutionOutputV1 {
                invocation: i.clone(),
                result,
                failure_root,
                completions,
            }),
        }
    }

    fn authenticate(&self, state: &StateBlock<'_>, height: u64) -> Result<(), String> {
        let id = &self.trigger().trigger_id;
        let actual = match self {
            Self::Pipeline(_) => pipeline_trigger_use_v1(&state.world.triggers, id, height)?,
            Self::Time(_) => time_trigger_use_v1(&state.world.triggers, id, height)?,
        };
        if &actual != self.trigger() {
            return Err("internal action changed its invocation owner".into());
        }
        Ok(())
    }

    // Called only after the failed overlay is dropped and the rejected row fits.
    // Persistent action identity, not a transaction-local generation, authenticates
    // the separate quarantine/retry transaction after rollback.
    fn apply_failure_policy(
        &self,
        state: &mut StateBlock<'_>,
        height: u64,
        now: u64,
    ) -> Result<(), String> {
        self.authenticate(state, height)?;
        let id = &self.trigger().trigger_id;
        match self {
            Self::Pipeline(_) => {
                let enabled: Name = TRIGGER_ENABLED_METADATA_KEY
                    .parse()
                    .map_err(|_| "invalid trigger enabled metadata key")?;
                let mut policy = OutputTransaction::new(state)?;
                let tx = policy
                    .transaction
                    .as_mut()
                    .ok_or("missing quarantine transaction")?;
                if tx
                    .world
                    .triggers
                    .inspect_by_id_mut(id, |action| {
                        action
                            .metadata_mut()
                            .insert(enabled.clone(), Json::from(false));
                    })
                    .is_none()
                {
                    return Err("quarantine action disappeared".into());
                }
                policy.apply()?;
            }
            Self::Time(_) => {
                let action = state
                    .world
                    .triggers
                    .time_triggers()
                    .get(id)
                    .ok_or("retry action disappeared")?;
                let Some(retry_policy) = action.retry_policy else {
                    return Ok(());
                };
                let used = action
                    .retry_state
                    .map_or(0, |s| s.retries_used)
                    .saturating_add(1);
                let mut policy = OutputTransaction::new(state)?;
                let tx = policy
                    .transaction
                    .as_mut()
                    .ok_or("missing retry transaction")?;
                if used > retry_policy.max_retries.get() {
                    if !tx.world.triggers.remove(id) {
                        return Err("retry action disappeared".into());
                    }
                    crate::smartcontracts::isi::triggers::isi::remove_trigger_associated_permissions(tx, id);
                } else if !tx.world.triggers.set_time_trigger_retry_state(
                    id,
                    Some(TimeTriggerRetryState {
                        retries_used: used,
                        next_retry_at_ms: now.saturating_add(retry_policy.retry_after_ms.get()),
                    }),
                ) {
                    return Err("retry action disappeared".into());
                }
                policy.apply()?;
            }
        }
        Ok(())
    }
}

impl ExecutionOutputProducer<'_, '_, '_> {
    pub(super) fn try_apply_internal(
        &mut self,
        invocation: InternalInvocation,
        event: EventBox,
        action: &impl LoadedActionTrait,
    ) -> Result<InternalOutputDisposition, ExecutionAttemptError<String>> {
        let height = self.source.header().height().get();
        let now = u64::try_from(self.source.header().creation_time().as_millis())
            .map_err(|_| "internal timestamp exceeds u64")?;
        invocation.authenticate(self.state, height)?;
        let call = invocation.call(self.source.hash())?;
        let id = &invocation.trigger().trigger_id;
        if self.rows.len() >= self.rows.capacity() {
            return Err("internal row storage exhausted".into());
        }
        let maximum = self.state.callback_output_byte_limit()?;
        let reservation = self
            .budget
            .as_mut()
            .ok_or("output budget already consumed")?
            .begin(invocation.terminal())?;
        self.state.retain_fastpq_source_invocation(call)?;
        let mut attempt = OutputTransaction::new(self.state)?;
        let tx = attempt
            .transaction
            .as_mut()
            .ok_or("missing internal transaction")?;
        tx.tx_call_hash = Some(call);
        tx.current_tx_hash = None;
        tx.current_entrypoint_index = None;
        let root_dataspace = capture_internal_root_dataspace(tx)?;
        let original_source = OwnedExecutionSource::new(call, None, root_dataspace);
        tx.bind_original_fastpq_invocation_source(original_source)?;
        // Event routing is authenticated event data, not authority to route the
        // callback's writes. The immutable root owns this invocation's namespace.
        let generation = tx.world.triggers.registration_generation(id);
        let nft = match &invocation {
            InternalInvocation::Pipeline(_) => None,
            InternalInvocation::Time(i) => Some(StateBlock::time_trigger_nft_seq_base(
                height,
                usize::try_from(i.schedule_index).map_err(|_| "Time index exceeds host width")?,
            )),
        };
        let root = tx.execute_trigger(id, action.authority(), action.executable(), event, 0, nft);
        let mut execution = match root {
            Err(reason) => Err((reason, None)),
            Ok(step) => {
                // Pipeline consumes its root repeat before chained callbacks;
                // Time consumes it only after the complete invocation succeeds.
                if matches!(invocation, InternalInvocation::Pipeline(_))
                    && tx.world.triggers.registration_generation(id) == generation
                {
                    tx.decrease_trigger_repeats_and_cleanup(id);
                }
                tx.execute_data_triggers_dfs_from(action.authority(), 1)
                    .map(|_| ())
                    .map_err(|reason| (reason, Some(step)))
            }
        };
        // Native fee settlement shares the internal invocation's disposable overlay.
        execution = execution
            .and_then(|()| crate::retail_fee::finalize(tx).map_err(|reason| (reason, None)));
        if tx.fastpq_source_quota.intrinsic_rejected()? {
            execution = Err((
                TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
                    crate::fastpq::source_reservation::admission::SOURCE_INTRINSIC_REJECTION.into(),
                )),
                None,
            ));
        }
        if let Some(reason) = tx.execution_deferral() {
            return Err(ExecutionAttemptError::Deferred(reason));
        }
        if tx.tx_call_hash != Some(call)
            || tx.current_tx_hash.is_some()
            || tx.current_entrypoint_index.is_some()
            || tx.current_dataspace_id != Some(root_dataspace)
            || tx.world.current_dataspace_id != Some(root_dataspace)
        {
            return Err("internal callback changed its execution owner".into());
        }
        tx.require_original_fastpq_invocation_source(original_source)?;
        let work = CompletedOutputWork::capture(tx);
        if let Err((reason, root)) = execution {
            // Refused/incomplete journal custody is a local carrier failure, even
            // when execute_trigger reports an InternalError. Never quarantine it.
            tx.callback_journal.discard_rejected(call)?;
            tx.contract_event_journal.discard_rejected(call)?;
            let actual = rejected_row(&invocation, action.executable(), root, reason, maximum)?;
            actual.validate_structure(height, &self.source)?;
            let row = reservation.finish_internal_rejection(actual)?;
            drop(attempt);
            work.account(self.state);
            invocation.apply_failure_policy(self.state, height, now)?;
            append_completions(&mut self.state.world.external_event_buf, call, &row)?;
            self.retain_completed_internal_source(original_source)?;
            self.rows.push(row);
            return Ok(InternalOutputDisposition::Rejected);
        }
        if matches!(invocation, InternalInvocation::Time(_))
            && tx.world.triggers.registration_generation(id) == generation
        {
            let _ = tx.world.triggers.set_time_trigger_retry_state(id, None);
            tx.decrease_trigger_repeats_and_cleanup(id);
        }
        if tx
            .world
            .external_event_buf
            .iter()
            .any(|event| matches!(event, EventBox::TriggerCompleted(_)))
        {
            return Err("internal completions must come from the callback journal".into());
        }
        let mut receipts = core::mem::take(&mut tx.pending_batch_transfer_outcomes);
        let owned = receipts
            .remove(&HashOf::from_untyped_unchecked(call))
            .unwrap_or_default();
        if !receipts.is_empty() {
            return Err("internal receipts belong to a foreign call".into());
        }
        let callback_capture = tx.callback_journal.take(call)?;
        let event_capture = if matches!(callback_capture, DrainedCallbacks::OutputLimit) {
            tx.contract_event_journal.discard_rejected(call)?;
            DrainedContractEvents::OutputLimit
        } else {
            let budget = tx.execution_budget();
            tx.contract_event_journal.take(call, &budget)?
        };
        let (actual, overflow) = match (callback_capture, event_capture) {
            (
                DrainedCallbacks::Complete { steps, completions },
                DrainedContractEvents::Complete(events),
            ) => {
                let mut result = TransactionResult::new(Ok(steps));
                result.set_batch_transfer_outcomes(owned);
                result.set_contract_events(events);
                (invocation.row(result, None, completions), false)
            }
            _ => (invocation.terminal(), true),
        };
        actual.validate_structure(height, &self.source)?;
        let (row, apply) = match reservation.finish(actual)? {
            ReservedExecutionOutput::Accepted(row) => (row, !overflow),
            ReservedExecutionOutput::OutputLimit(row) => (row, false),
        };
        if apply {
            let tx = attempt
                .transaction
                .as_mut()
                .ok_or("missing internal transaction")?;
            append_completions(&mut tx.world.external_event_buf, call, &row)?;
            attempt.apply()?;
        } else {
            drop(attempt);
            append_completions(&mut self.state.world.external_event_buf, call, &row)?;
        }
        work.account(self.state);
        self.retain_completed_internal_source(original_source)?;
        self.rows.push(row);
        Ok(if apply {
            InternalOutputDisposition::Applied
        } else {
            InternalOutputDisposition::OutputLimit
        })
    }
}

fn append_completions(
    events: &mut Vec<EventBox>,
    call: Hash,
    row: &ExecutionOutputV1,
) -> Result<(), ExecutionAttemptError<String>> {
    events.try_reserve(row.completions().len()).map_err(|_| {
        ExecutionAttemptError::Deferred(ivm::error::ExecutionDeferral::AllocationUnavailable.into())
    })?;
    for completion in row.completions() {
        events.push(
            TriggerCompletedEvent::new(
                completion.trigger_id.clone(),
                HashOf::from_untyped_unchecked(call),
                completion.callback_index,
                completion.outcome.clone(),
            )
            .into(),
        );
    }
    Ok(())
}

/// Size diagnostic copies before allocating them. These child payload sizes are
/// lower bounds, so exceeding the row ceiling is sufficient to omit the root.
fn rejected_row(
    invocation: &InternalInvocation,
    executable: &crate::smartcontracts::isi::triggers::set::ExecutableRef,
    returned: Option<ExecutionStep>,
    reason: TransactionRejectionReason,
    maximum: u64,
) -> Result<ExecutionOutputV1, ExecutionAttemptError<String>> {
    use crate::smartcontracts::isi::triggers::set::ExecutableRef;
    let limit = usize::try_from(maximum).map_err(|_| "diagnostic ceiling exceeds host width")?;
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let root_fits = if let Some(step) = returned.as_ref() {
        norito::core::encoded_payload_len(step).map_err(|e| e.to_string())? <= limit
    } else {
        match executable {
            ExecutableRef::Instructions(instructions) => {
                norito::core::encoded_payload_len(instructions).map_err(|e| e.to_string())? <= limit
            }
            ExecutableRef::Batch(items) => {
                let mut bytes = 0_usize;
                for item in items.iter() {
                    if let iroha_data_model::transaction::ExecutableBatchItem::Instruction(
                        instruction,
                    ) = item
                    {
                        let size = norito::core::encoded_payload_len(instruction)
                            .map_err(|e| e.to_string())?;
                        bytes = bytes.saturating_add(size);
                        if bytes > limit {
                            break;
                        }
                    }
                }
                bytes <= limit
            }
            ExecutableRef::Ivm(_) | ExecutableRef::ContractCall(_) => true,
        }
    };
    let diagnostic = if root_fits {
        bounded_diagnostic(&reason, limit)?
    } else {
        None
    };
    let (reason, root, diagnostic) = if let Some(diagnostic) = diagnostic {
        let root = match returned {
            Some(step) => TriggerFailureRootV1::ReturnedBeforeRollback(step),
            None => TriggerFailureRootV1::DeclaredInstructionProjection(
                StateTransaction::execution_step_from_executable(executable),
            ),
        };
        (reason, root, diagnostic)
    } else {
        (
            TransactionRejectionReason::LimitCheck(TransactionLimitError {
                reason: INTERNAL_REJECTION_DIAGNOSTIC_OMITTED.to_owned(),
            }),
            TriggerFailureRootV1::OmittedAfterRejection,
            INTERNAL_REJECTION_DIAGNOSTIC_OMITTED.to_owned(),
        )
    };
    Ok(invocation.row(
        TransactionResult::new(Err(reason)),
        Some(root),
        vec![InvocationCompletionV1 {
            callback_index: 0,
            trigger_id: invocation.trigger().trigger_id.clone(),
            outcome: TriggerCompletedOutcome::Failure(diagnostic),
        }],
    ))
}

fn bounded_diagnostic(
    reason: &impl std::fmt::Display,
    maximum: usize,
) -> Result<Option<String>, ExecutionAttemptError<String>> {
    use std::fmt::Write;
    struct Writer {
        text: String,
        maximum: usize,
        overflow: bool,
        refused: bool,
    }
    impl Write for Writer {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            if text.len() > self.maximum.saturating_sub(self.text.len()) {
                self.overflow = true;
                return Err(std::fmt::Error);
            }
            if self.text.try_reserve_exact(text.len()).is_err() {
                self.refused = true;
                return Err(std::fmt::Error);
            }
            self.text.push_str(text);
            Ok(())
        }
    }
    let mut writer = Writer {
        text: String::new(),
        maximum,
        overflow: false,
        refused: false,
    };
    let result = write!(&mut writer, "{reason}");
    if writer.refused {
        return Err(ExecutionAttemptError::Deferred(
            ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
        ));
    }
    if result.is_err() && !writer.overflow {
        return Err("host cannot retain internal failure diagnostic".into());
    }
    Ok(if writer.overflow {
        None
    } else {
        Some(writer.text)
    })
}

#[cfg(test)]
mod tests {
    use super::bounded_diagnostic;

    #[test]
    fn diagnostic_exact_utf8_boundary_and_overflow_are_distinct_from_formatter_refusal() {
        let text = "é界";
        assert_eq!(
            bounded_diagnostic(&text, text.len()).unwrap().as_deref(),
            Some(text)
        );
        assert!(bounded_diagnostic(&text, text.len() - 1).unwrap().is_none());
        struct Refused;
        impl std::fmt::Display for Refused {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                Err(std::fmt::Error)
            }
        }
        assert!(bounded_diagnostic(&Refused, 1024).is_err());
    }
}

/// Capture the immutable root's namespace for a fresh internal invocation.
/// The triggering event's route does not authorize the callback's own effects.
fn capture_internal_root_dataspace(
    tx: &mut StateTransaction<'_, '_>,
) -> Result<iroha_model_base::topology::DataSpaceId, String> {
    if tx.current_dataspace_id.is_some() || tx.world.current_dataspace_id.is_some() {
        return Err("internal invocation already has a captured dataspace".into());
    }
    let scope =
        crate::executor::root_scope::execution_root_scope(tx).map_err(|error| error.to_string())?;
    let dataspace = scope.dataspace_id();
    tx.current_dataspace_id = Some(dataspace);
    tx.world.current_dataspace_id = Some(dataspace);
    Ok(dataspace)
}

#[cfg(test)]
#[path = "output_internal_root_scope_tests.rs"]
mod root_scope_tests;
