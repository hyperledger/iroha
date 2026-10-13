//! Transaction-owned callback trace captured before any State application.
//!
//! Ordinals are allocated before dispatch, so nested completion order cannot
//! reorder or hide actual execution. This success journal never reformats a
//! callback error into a capacity rejection. TODO: integrate the separately
//! owned rejection/penalty corridor and internal root-failure diagnostics.

use crate::execution_attempt::ExecutionAttemptError;
use iroha_crypto::Hash;
use iroha_data_model::{
    block::execution_output::InvocationCompletionV1,
    events::trigger_completed::TriggerCompletedOutcome,
    transaction::{ExecutionStep, error::TransactionRejectionReason},
    trigger::{DataTriggerStep, TriggerId},
};

/// A non-copyable pre-body ordinal, usable only by its owning transaction.
pub(super) struct CallbackTicket {
    call: Hash,
    ordinal: u64,
}

struct CallbackSlot {
    id: TriggerId,
    step: Option<ExecutionStep>,
}

/// A drained journal transfers the complete successful callback collection.
pub(super) enum DrainedCallbacks {
    Complete {
        steps: Vec<DataTriggerStep>,
        completions: Vec<InvocationCompletionV1>,
    },
    /// The actual callback payload alone proves the complete row cannot fit.
    OutputLimit,
}

/// One journal per StateTransaction; no event or caller trace can populate it.
pub(super) struct CallbackJournal {
    maximum_bytes: Result<u64, String>,
    call: Option<Hash>,
    next_ordinal: u64,
    pending: u64,
    slots: Vec<CallbackSlot>,
    payload_bytes: u64,
    overflow: bool,
    failed: bool,
    refused: bool,
    consumed: bool,
}

impl CallbackJournal {
    pub(super) fn new(maximum_bytes: Result<u64, String>) -> Self {
        Self {
            maximum_bytes,
            call: None,
            next_ordinal: 0,
            pending: 0,
            slots: Vec::new(),
            payload_bytes: 0,
            overflow: false,
            failed: false,
            refused: false,
            consumed: false,
        }
    }

    pub(super) fn begin(
        &mut self,
        call: Option<Hash>,
        id: &TriggerId,
    ) -> Result<CallbackTicket, ExecutionAttemptError<String>> {
        let result = (|| {
            if self.consumed || self.refused {
                return Err("callback journal is no longer available".into());
            }
            let maximum_bytes = *self.maximum_bytes.as_ref().map_err(Clone::clone)?;
            let call = call.ok_or("callback has no pre-body execution owner")?;
            if self.call.is_some_and(|owner| owner != call) {
                return Err("callback changed its transaction execution owner".into());
            }
            self.call = Some(call);
            let ordinal = self.next_ordinal;
            self.next_ordinal = ordinal.checked_add(1).ok_or("callback ordinal overflow")?;
            self.pending = self
                .pending
                .checked_add(1)
                .ok_or("callback depth overflow")?;
            // Every retained completion has at least one encoded byte. This is
            // a lower bound, not an additional hidden callback-count policy.
            if self.next_ordinal > maximum_bytes || u32::try_from(ordinal).is_err() {
                self.overflow = true;
                self.slots.clear();
            }
            if !self.overflow && !self.failed {
                self.reserve_slots(1)?;
                self.slots.push(CallbackSlot {
                    id: id.clone(),
                    step: None,
                });
            }
            Ok(CallbackTicket { call, ordinal })
        })();
        if result.is_err() {
            self.refused = true;
        }
        result
    }

    /// Reserve physical capture storage without producing a consensus rejection.
    fn reserve_slots(&mut self, additional: usize) -> Result<(), ExecutionAttemptError<String>> {
        self.slots.try_reserve(additional).map_err(|_| {
            self.refused = true;
            ExecutionAttemptError::Deferred(ivm::ExecutionDeferral::AllocationUnavailable.into())
        })
    }

    pub(super) fn finish(
        &mut self,
        ticket: CallbackTicket,
        call: Option<Hash>,
        result: &Result<ExecutionStep, TransactionRejectionReason>,
    ) -> Result<(), String> {
        let finished = (|| {
            if self.consumed
                || self.refused
                || call != Some(ticket.call)
                || self.call != call
                || ticket.ordinal >= self.next_ordinal
            {
                return Err("callback completion lost its pre-body owner".into());
            }
            self.pending = self
                .pending
                .checked_sub(1)
                .ok_or("callback completed twice")?;
            let Ok(step) = result else {
                // Preserve the actual typed error at the caller. No unbounded
                // diagnostic clone and no invented OutputLimit disposition.
                self.failed = true;
                self.slots.clear();
                return Ok(());
            };
            if self.failed || self.overflow {
                return Ok(());
            }
            let index =
                usize::try_from(ticket.ordinal).map_err(|_| "callback exceeds host width")?;
            let slot = self.slots.get_mut(index).ok_or("callback slot is absent")?;
            if slot.step.is_some() {
                return Err("callback slot was already completed".into());
            }
            let completion = InvocationCompletionV1 {
                callback_index: u32::try_from(ticket.ordinal)
                    .map_err(|_| "callback exceeds u32")?,
                trigger_id: slot.id.clone(),
                outcome: TriggerCompletedOutcome::Success,
            };
            // Count actual child payloads under the canonical layout. Exclude
            // independent frame headers: those would overestimate nested bytes
            // and could incorrectly reject a row at its exact boundary. The
            // complete enclosing row is still fitted by its sole reservation.
            let _flags =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            let step_bytes =
                norito::core::encoded_payload_len(step).map_err(|error| error.to_string())?;
            let completion_bytes = norito::core::encoded_payload_len(&completion)
                .map_err(|error| error.to_string())?;
            let added = u64::try_from(step_bytes)
                .ok()
                .and_then(|bytes| bytes.checked_add(u64::try_from(completion_bytes).ok()?));
            let total = added.and_then(|bytes| self.payload_bytes.checked_add(bytes));
            if total.is_none_or(|bytes| {
                bytes > *self.maximum_bytes.as_ref().expect("begin checked capacity")
            }) {
                self.overflow = true;
                self.slots.clear();
            } else {
                self.payload_bytes = total.expect("bounded above");
                slot.step = Some(step.clone());
            }
            Ok(())
        })();
        if finished.is_err() {
            self.refused = true;
        }
        finished
    }

    /// Discard business capture for an actual rejection. Local ownership or
    /// allocation refusal still aborts the carrier; real callback failure wins
    /// over healthy overflow. This never authorizes applying the rejected overlay.
    pub(super) fn discard_rejected(&mut self, call: Hash) -> Result<(), String> {
        if self.consumed
            || self.refused
            || self.pending != 0
            || self.call.is_some_and(|owner| owner != call)
            || self.maximum_bytes.is_err()
        {
            self.refused = true;
            return Err("rejected callback capture lost its execution owner".into());
        }
        self.slots.clear();
        self.failed = true;
        self.consumed = true;
        Ok(())
    }

    pub(super) fn take(
        &mut self,
        call: Hash,
    ) -> Result<DrainedCallbacks, ExecutionAttemptError<String>> {
        if self.consumed
            || self.refused
            || self.failed
            || self.pending != 0
            || self.call.is_some_and(|owner| owner != call)
        {
            self.refused = true;
            return Err("callback journal is failed, unfinished or belongs to another call".into());
        }
        if self.overflow {
            self.consumed = true;
            return Ok(DrainedCallbacks::OutputLimit);
        }
        let mut steps = Vec::new();
        let mut completions = Vec::new();
        // Keep failed host allocation distinct from deterministic row overflow.
        steps
            .try_reserve_exact(self.slots.len())
            .and_then(|()| completions.try_reserve_exact(self.slots.len()))
            .map_err(|_| {
                self.refused = true;
                ExecutionAttemptError::Deferred(
                    ivm::ExecutionDeferral::AllocationUnavailable.into(),
                )
            })?;
        for (index, slot) in self.slots.iter_mut().enumerate() {
            let step = slot.step.take().ok_or("callback trace is unfinished")?;
            let callback_index = u32::try_from(index).map_err(|_| "callback index exceeds u32")?;
            steps.push(DataTriggerStep {
                id: slot.id.clone(),
                instructions: step,
            });
            completions.push(InvocationCompletionV1 {
                callback_index,
                trigger_id: slot.id.clone(),
                outcome: TriggerCompletedOutcome::Success,
            });
        }
        self.slots.clear();
        self.consumed = true;
        Ok(DrainedCallbacks::Complete { steps, completions })
    }

    /// Latch actual post-body matching/gas failure without inventing a callback.
    pub(super) fn record_failure(&mut self) {
        self.failed = true;
        self.slots.clear();
    }

    pub(super) fn allows_apply(&self) -> bool {
        !self.refused
            && !self.failed
            && !self.overflow
            && self.pending == 0
            && (self.consumed || self.next_ordinal == 0)
    }
}

impl super::StateTransaction<'_, '_> {
    /// Transfer the exact callback journal to direct transaction/lane replay.
    ///
    /// Ordinary output producers retain their own complete row reservation. This
    /// corridor returns the actual callback sequence used by certified lane result
    /// hashes; it does not authorize an ordinary execution-output row. Completions
    /// and nested by-call steps come only from the transaction's original journal.
    pub(crate) fn complete_direct_callbacks(
        &mut self,
        call: Hash,
    ) -> Result<
        iroha_data_model::transaction::DataTriggerSequence,
        ExecutionAttemptError<TransactionRejectionReason>,
    > {
        use iroha_data_model::{
            ValidationFail,
            events::{EventBox, trigger_completed::TriggerCompletedEvent},
            transaction::error::TransactionLimitError,
        };
        self.ensure_execution_ready()
            .map_err(ExecutionAttemptError::Deferred)?;
        if self
            .world
            .external_event_buf
            .iter()
            .any(|event| matches!(event, EventBox::TriggerCompleted(_)))
        {
            return Err(ExecutionAttemptError::Rejected(
                TransactionRejectionReason::Validation(ValidationFail::InternalError(
                    "direct completion bypassed its callback journal".into(),
                )),
            ));
        }
        let drained = self.callback_journal.take(call).map_err(|error| {
            error.map_rejection(|message| {
                TransactionRejectionReason::Validation(ValidationFail::InternalError(message))
            })
        })?;
        let DrainedCallbacks::Complete { steps, completions } = drained else {
            return Err(ExecutionAttemptError::Rejected(
                TransactionRejectionReason::LimitCheck(TransactionLimitError {
                    reason:
                        iroha_data_model::block::execution_output::EXECUTION_OUTPUT_LIMIT_REASON
                            .into(),
                }),
            ));
        };
        self.world
            .external_event_buf
            .try_reserve(completions.len())
            .map_err(|_| {
                ExecutionAttemptError::Deferred(
                    ivm::ExecutionDeferral::AllocationUnavailable.into(),
                )
            })?;
        for completion in completions {
            self.world.external_event_buf.push(
                TriggerCompletedEvent::new(
                    completion.trigger_id,
                    iroha_crypto::HashOf::from_untyped_unchecked(call),
                    completion.callback_index,
                    completion.outcome,
                )
                .into(),
            );
        }
        Ok(steps)
    }

    /// Consume an isolated component fixture's actual callbacks before applying
    /// its successful overlay. Failed, incomplete and overflowing journals keep
    /// the same production rejection semantics and are never applied.
    #[cfg(test)]
    pub(crate) fn apply_callback_for_testing(mut self) -> Result<(), String> {
        if self.block_execution_output_plan.is_some() {
            return Err("component callback capture cannot replace a block output owner".into());
        }
        let call = self
            .tx_call_hash
            .ok_or("callback fixture has no root owner")?;
        match self
            .callback_journal
            .take(call)
            .map_err(|error| format!("{error:?}"))?
        {
            DrainedCallbacks::Complete { completions, .. } => {
                if !self.execution_effects_allow_apply() {
                    return Err("callback fixture has unclosed execution effects".into());
                }
                for completion in completions {
                    self.world.external_event_buf.push(
                        iroha_data_model::events::trigger_completed::TriggerCompletedEvent::new(
                            completion.trigger_id,
                            iroha_crypto::HashOf::from_untyped_unchecked(call),
                            completion.callback_index,
                            completion.outcome,
                        )
                        .into(),
                    );
                }
                self.apply();
                Ok(())
            }
            DrainedCallbacks::OutputLimit => Err("callback fixture output limit exceeded".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::{isi::Log, prelude::Level, transaction::error::TransactionLimitError};

    fn step(bytes: usize) -> ExecutionStep {
        ExecutionStep(vec![Log::new(Level::INFO, "x".repeat(bytes)).into()].into())
    }

    fn call() -> Hash {
        Hash::new(b"actual source call")
    }

    #[test]
    fn actual_callback_reservation_refusal_is_local_and_prevents_publication() {
        let mut journal = CallbackJournal::new(Ok(4096));
        // Exercise the real fallible reservation without depending on host OOM.
        // Host address-space capacity is physical, not a transaction limit.
        {
            let ExecutionAttemptError::Deferred(actual) =
                (journal.reserve_slots(usize::MAX)).expect_err("expected local refusal")
            else {
                panic!("local refusal cannot become a completed verdict")
            };
            assert_eq!(
                actual.reason(),
                ivm::ExecutionDeferral::AllocationUnavailable
            );
            assert_eq!(actual.phase(), None);
            assert!(actual.allocation_refusal().is_none());
            assert!(actual.decode_refusal().is_none());
            assert!(actual.verification_refusal().is_none());
        };
        assert!(journal.refused);
        assert!(!journal.allows_apply());
        assert!(
            journal
                .begin(Some(call()), &"root".parse().unwrap())
                .is_err()
        );
        assert!(journal.take(call()).is_err());
    }

    #[test]
    fn component_fixture_requires_explicit_root_and_consumes_actual_capture() {
        let state = crate::state::State::new_for_testing(
            crate::state::World::default(),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let mut block = state.block(iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::new(2).unwrap(),
            None,
            None,
            0,
            0,
        ));
        assert!(block.transaction().tx_call_hash.is_none());
        let mut transaction = block.transaction_for_callback_testing();
        let root = transaction.tx_call_hash;
        let ticket = transaction
            .callback_journal
            .begin(root, &"fixture".parse().unwrap())
            .unwrap();
        transaction
            .callback_journal
            .finish(ticket, root, &Ok(step(1)))
            .unwrap();
        assert!(!transaction.callback_journal.allows_apply());
        transaction.apply_callback_for_testing().unwrap();
        let mut rejected = block.transaction_for_callback_testing();
        rejected.callback_journal.record_failure();
        assert!(rejected.apply_callback_for_testing().is_err());
    }

    #[test]
    fn nested_completions_keep_pre_body_order_and_move_once() {
        let mut journal = CallbackJournal::new(Ok(4096));
        let root = journal
            .begin(Some(call()), &"root".parse().unwrap())
            .unwrap();
        let child = journal
            .begin(Some(call()), &"child".parse().unwrap())
            .unwrap();
        journal.finish(child, Some(call()), &Ok(step(12))).unwrap();
        journal.finish(root, Some(call()), &Ok(step(24))).unwrap();
        assert!(!journal.allows_apply());
        let DrainedCallbacks::Complete { steps, completions } = journal.take(call()).unwrap()
        else {
            panic!("small trace fits")
        };
        assert_eq!(
            steps
                .iter()
                .map(|step| step.id.to_string())
                .collect::<Vec<_>>(),
            ["root", "child"]
        );
        assert_eq!(
            completions
                .iter()
                .map(|completion| completion.callback_index)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        assert_eq!(steps[0].instructions, step(24));
        assert_eq!(steps[1].instructions, step(12));
        assert!(journal.allows_apply());
        assert!(journal.take(call()).is_err());
        assert!(!journal.allows_apply());
    }

    #[test]
    fn callback_bytes_overflow_discards_partial_trace_but_finishes_nested_owners() {
        let mut journal = CallbackJournal::new(Ok(256));
        let root = journal
            .begin(Some(call()), &"root".parse().unwrap())
            .unwrap();
        let child = journal
            .begin(Some(call()), &"child".parse().unwrap())
            .unwrap();
        journal
            .finish(child, Some(call()), &Ok(step(1024)))
            .unwrap();
        assert!(journal.slots.is_empty());
        journal.finish(root, Some(call()), &Ok(step(1))).unwrap();
        assert!(matches!(
            journal.take(call()),
            Ok(DrainedCallbacks::OutputLimit)
        ));
        assert!(!journal.allows_apply());
    }

    #[test]
    fn real_failure_is_never_relabelled_output_limit() {
        let mut journal = CallbackJournal::new(Ok(256));
        let root = journal
            .begin(Some(call()), &"root".parse().unwrap())
            .unwrap();
        let child = journal
            .begin(Some(call()), &"child".parse().unwrap())
            .unwrap();
        journal
            .finish(child, Some(call()), &Ok(step(1024)))
            .unwrap();
        let failed = Err(TransactionRejectionReason::LimitCheck(
            TransactionLimitError {
                reason: "real failure".into(),
            },
        ));
        journal.finish(root, Some(call()), &failed).unwrap();
        assert!(journal.take(call()).is_err());
        assert!(!journal.allows_apply());
    }

    #[test]
    fn missing_foreign_and_changed_call_owners_are_sticky_refusals() {
        let id = "root".parse().unwrap();
        let foreign = Hash::new(b"foreign");
        let mut missing = CallbackJournal::new(Ok(4096));
        assert!(missing.begin(None, &id).is_err());
        assert!(missing.begin(Some(call()), &id).is_err());
        assert!(!missing.allows_apply());
        let mut changed = CallbackJournal::new(Ok(4096));
        let ticket = changed.begin(Some(call()), &id).unwrap();
        assert!(changed.finish(ticket, Some(foreign), &Ok(step(1))).is_err());
        assert!(changed.take(call()).is_err());
        let mut foreign_take = CallbackJournal::new(Ok(4096));
        let ticket = foreign_take.begin(Some(call()), &id).unwrap();
        foreign_take
            .finish(ticket, Some(call()), &Ok(step(1)))
            .unwrap();
        assert!(foreign_take.take(foreign).is_err());
        assert!(foreign_take.take(call()).is_err());
    }

    #[test]
    fn unfinished_dispatch_and_missing_capacity_cannot_apply() {
        let mut journal = CallbackJournal::new(Ok(4096));
        let _ticket = journal
            .begin(Some(call()), &"root".parse().unwrap())
            .unwrap();
        assert!(!journal.allows_apply());
        assert!(journal.take(call()).is_err());
        let mut absent = CallbackJournal::new(Err("capacity was not frozen".into()));
        assert!(absent.allows_apply()); // callback-free maintenance remains valid
        assert!(
            absent
                .begin(Some(call()), &"root".parse().unwrap())
                .is_err()
        );
        assert!(!absent.allows_apply());
    }

    #[test]
    fn child_payload_accounting_never_rejects_the_exact_complete_row_boundary() {
        use iroha_data_model::{
            block::execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
            transaction::TransactionResult,
        };
        for bytes in [0, 1, 127, 128, 4096] {
            let capture = |maximum_bytes| {
                let mut journal = CallbackJournal::new(Ok(maximum_bytes));
                let root = journal
                    .begin(Some(call()), &"root".parse().unwrap())
                    .unwrap();
                let child = journal
                    .begin(Some(call()), &"child".parse().unwrap())
                    .unwrap();
                journal
                    .finish(child, Some(call()), &Ok(step(bytes)))
                    .unwrap();
                journal
                    .finish(root, Some(call()), &Ok(step(bytes)))
                    .unwrap();
                let lower_bound = journal.payload_bytes;
                let DrainedCallbacks::Complete { steps, completions } =
                    journal.take(call()).unwrap()
                else {
                    panic!("a fitting complete row cannot overflow its child bound")
                };
                (
                    ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                        input_index: 0,
                        result: TransactionResult::new(Ok(steps)),
                        completions,
                    }),
                    lower_bound,
                )
            };
            let (actual, lower_bound) = capture(65_536);
            let exact = u64::try_from(norito::canonical_frame_len(&actual).unwrap()).unwrap();
            assert!(lower_bound < exact);
            let (at_limit, _) = capture(exact);
            assert_eq!(at_limit, actual);
        }
    }

    #[test]
    fn post_body_scan_failure_blocks_an_otherwise_complete_success() {
        let mut journal = CallbackJournal::new(Ok(4096));
        let ticket = journal
            .begin(Some(call()), &"root".parse().unwrap())
            .unwrap();
        journal.finish(ticket, Some(call()), &Ok(step(1))).unwrap();
        journal.record_failure();
        assert!(journal.take(call()).is_err());
        assert!(!journal.allows_apply());
        assert_eq!(journal.next_ordinal, 1);
    }

    #[test]
    fn successful_empty_step_is_an_invocation_not_a_skip() {
        let mut journal = CallbackJournal::new(Ok(4096));
        let ticket = journal
            .begin(Some(call()), &"noop".parse().unwrap())
            .unwrap();
        journal
            .finish(ticket, Some(call()), &Ok(ExecutionStep(vec![].into())))
            .unwrap();
        let DrainedCallbacks::Complete { steps, completions } = journal.take(call()).unwrap()
        else {
            panic!("empty successful step fits")
        };
        assert_eq!(steps.len(), 1);
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].outcome, TriggerCompletedOutcome::Success);
    }

    #[test]
    fn rejected_callback_failure_wins_over_prior_healthy_overflow() {
        for overflow_first in [false, true] {
            let mut journal = CallbackJournal::new(Ok(4096));
            let root = journal
                .begin(Some(call()), &"root".parse().unwrap())
                .unwrap();
            let child = journal
                .begin(Some(call()), &"child".parse().unwrap())
                .unwrap();
            journal
                .finish(
                    child,
                    Some(call()),
                    &Ok(step(if overflow_first { 32_768 } else { 1 })),
                )
                .unwrap();
            assert_eq!(journal.overflow, overflow_first);
            let actual_failure = Err(TransactionRejectionReason::LimitCheck(
                TransactionLimitError {
                    reason: "actual callback failure, not output capacity".into(),
                },
            ));
            journal.finish(root, Some(call()), &actual_failure).unwrap();
            assert!(journal.failed);
            assert_eq!(journal.pending, 0);
            // The caller already owns this typed failure; discard must not turn
            // an earlier healthy overflow into the final economic disposition.
            journal.discard_rejected(call()).unwrap();
            assert!(journal.consumed);
            assert!(journal.failed);
            assert_eq!(journal.overflow, overflow_first);
            assert!(journal.slots.is_empty());
            assert!(!journal.allows_apply());
            assert!(journal.take(call()).is_err());
        }
    }

    #[test]
    fn business_rejection_discards_completed_healthy_callbacks_without_apply() {
        for overflow in [false, true] {
            let mut journal = CallbackJournal::new(Ok(4096));
            let root = journal
                .begin(Some(call()), &"root".parse().unwrap())
                .unwrap();
            let child = journal
                .begin(Some(call()), &"child".parse().unwrap())
                .unwrap();
            journal
                .finish(
                    child,
                    Some(call()),
                    &Ok(step(if overflow { 32_768 } else { 12 })),
                )
                .unwrap();
            journal.finish(root, Some(call()), &Ok(step(24))).unwrap();
            assert_eq!(journal.slots.len(), if overflow { 0 } else { 2 });
            assert!(!journal.failed);
            assert_eq!(journal.overflow, overflow);
            // A later non-callback instruction rejects the enclosing business
            // attempt. No callback Success trace or completion may survive it,
            // and earlier healthy overflow must not replace this disposition.
            journal.discard_rejected(call()).unwrap();
            assert_eq!(journal.next_ordinal, 2);
            assert_eq!(journal.pending, 0);
            assert!(journal.slots.is_empty());
            assert!(journal.consumed);
            assert!(journal.failed);
            assert!(!journal.allows_apply());
            assert!(
                journal
                    .begin(Some(call()), &"later".parse().unwrap())
                    .is_err()
            );
            assert!(journal.take(call()).is_err());
        }
    }

    #[test]
    fn rejected_capture_pending_foreign_and_refused_owners_stay_poisoned() {
        let id = "root".parse().unwrap();
        let foreign = Hash::new(b"foreign rejected call");
        let mut pending = CallbackJournal::new(Ok(4096));
        let ticket = pending.begin(Some(call()), &id).unwrap();
        assert!(pending.discard_rejected(call()).is_err());
        assert!(pending.refused);
        assert!(!pending.consumed);
        assert!(pending.finish(ticket, Some(call()), &Ok(step(1))).is_err());
        assert!(pending.discard_rejected(call()).is_err());
        assert!(!pending.allows_apply());

        let mut wrong_owner = CallbackJournal::new(Ok(4096));
        let ticket = wrong_owner.begin(Some(call()), &id).unwrap();
        wrong_owner
            .finish(ticket, Some(call()), &Ok(step(1)))
            .unwrap();
        assert!(wrong_owner.discard_rejected(foreign).is_err());
        assert!(wrong_owner.refused);
        assert!(!wrong_owner.consumed);
        assert!(wrong_owner.discard_rejected(call()).is_err());
        assert!(wrong_owner.take(call()).is_err());
        assert!(!wrong_owner.allows_apply());

        let mut refused = CallbackJournal::new(Ok(4096));
        assert!(refused.begin(None, &id).is_err());
        assert!(refused.discard_rejected(call()).is_err());
        assert!(refused.refused);
        assert!(!refused.consumed);
        assert!(refused.begin(Some(call()), &id).is_err());
        assert!(!refused.allows_apply());
    }

    #[test]
    fn rejected_capture_requires_frozen_capacity_even_without_callbacks() {
        let mut journal = CallbackJournal::new(Err("applying policy unavailable".into()));
        assert!(
            journal.allows_apply(),
            "callback-free maintenance has a separate path"
        );
        assert!(journal.discard_rejected(call()).is_err());
        assert!(journal.refused);
        assert!(!journal.consumed);
        assert!(journal.take(call()).is_err());
        assert!(!journal.allows_apply());
    }

    #[test]
    fn rejected_discard_and_success_transfer_are_exclusive_single_consumptions() {
        let id = "root".parse().unwrap();
        // Even an empty capture has exactly one disposition owner.
        let mut empty = CallbackJournal::new(Ok(4096));
        empty.discard_rejected(call()).unwrap();
        assert!(empty.consumed);
        assert!(!empty.allows_apply());
        assert!(empty.discard_rejected(call()).is_err());
        assert!(empty.take(call()).is_err());

        for overflow in [false, true] {
            let mut journal = CallbackJournal::new(Ok(4096));
            let ticket = journal.begin(Some(call()), &id).unwrap();
            journal
                .finish(
                    ticket,
                    Some(call()),
                    &Ok(step(if overflow { 32_768 } else { 1 })),
                )
                .unwrap();
            match journal.take(call()).unwrap() {
                DrainedCallbacks::Complete { steps, completions } => {
                    assert!(!overflow);
                    assert_eq!(steps.len(), 1);
                    assert_eq!(completions.len(), 1);
                    assert!(journal.allows_apply());
                }
                DrainedCallbacks::OutputLimit => {
                    assert!(overflow);
                    assert!(!journal.allows_apply());
                }
            }
            assert!(
                journal.discard_rejected(call()).is_err(),
                "transferred capture cannot acquire a rejection owner"
            );
            assert!(journal.refused);
            assert!(journal.take(call()).is_err());
            assert!(!journal.allows_apply());
        }
    }
}
