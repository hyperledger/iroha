//! Actual Network execution and rejection settlement under one retained budget.
//!
//! Exact source routes and global carrier validation time are frozen before any
//! source runs. The caller still owes complete proposal/finality, duplicate/replay,
//! control, host-memory and common-wire admission before production integration.
//! Every global input, including the verified merged suffix, shares this executor.
//! Its original source and captured execution route survive rejection and fee handling.

use super::*;
use crate::state::StateReadOnly;
use crate::{
    queue::RoutingDecision,
    smartcontracts::ivm::cache::IvmCache,
    state::contract_event_journal::DrainedContractEvents,
    state::network_policy_routes::CapturedNetworkPolicyRoute,
    tx::{
        AcceptedTransaction, execution_rejection_from_admission_failure,
        rejected_transaction_gas_is_accountable,
    },
};
use iroha_data_model::{
    ValidationFail,
    events::{EventBox, trigger_completed::TriggerCompletedEvent},
    transaction::{TransactionResult, error::TransactionRejectionReason},
};
use std::borrow::Cow;

struct FrozenNetworkSource<'source> {
    pub(super) routing: RoutingDecision,
    admission: Option<Result<AcceptedTransaction<'source>, TransactionRejectionReason>>,
    genesis: Option<crate::block::AuthenticatedGenesisTransaction>,
    quarantine: QuarantineAdmission,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QuarantineAdmission {
    Normal,
    Selected,
    Overflow,
}

struct FrozenQuarantinePolicy {
    max_sources: usize,
    max_cycles: u64,
}

pub(super) struct FrozenNetworkSources<'source> {
    sources: Vec<FrozenNetworkSource<'source>>,
    pub(super) order: Option<Vec<usize>>,
    quarantine_policy: FrozenQuarantinePolicy,
}

impl<'source> ExecutionOutputProducer<'_, '_, 'source> {
    /// Resolve actual Network sources once, preserving immutable output positions.
    pub(super) fn execute_network_sources(
        &mut self,
        genesis: Option<&crate::block::AuthenticatedGenesisOutputSource>,
    ) -> Result<(), ExecutionAttemptError<String>> {
        let result = (|| {
            if self.failed
                || self.network_sources.is_some()
                || self.network_resolved.iter().any(|done| *done)
            {
                return Err("Network execution is repeated or has already started".into());
            }
            let sources = self.freeze_network_sources(genesis)?;
            if !self.source_entries.is_empty()
                || !self.source_routes.is_empty()
                || sources.sources.len() > self.source_entries.capacity()
                || sources.sources.len() > self.source_routes.capacity()
            {
                return Err("Network source storage differs from its retained plan".into());
            }
            // Existing bounded backing retains canonical source order even if
            // execution visits a reveal out of that order. No second map exists.
            for (index, frozen) in sources.sources.iter().enumerate() {
                let input = self
                    .source
                    .network_entrypoint_at(index)
                    .ok_or("Network source lost its exact original input")?;
                self.source_entries.push(OwnedExecutionSource::new(
                    Hash::from(input.execution_call_hash()),
                    Some(frozen.routing.lane_id),
                    frozen.routing.dataspace_id,
                ));
                self.source_routes.push(frozen.routing);
            }
            self.network_sources = Some(sources);
            let order = self
                .network_sources
                .as_mut()
                .and_then(|plan| plan.order.take())
                .ok_or("Network execution order lost its owner")?;
            let mut cache = IvmCache::with_prepared_contract_cache(
                self.state.pipeline.cache_size,
                self.state.pipeline_ivm_prepared_cache.clone(),
            );
            for index in order {
                self.execute_network_source(index, &mut cache)?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn freeze_network_sources(
        &self,
        genesis: Option<&crate::block::AuthenticatedGenesisOutputSource>,
    ) -> Result<FrozenNetworkSources<'source>, ExecutionAttemptError<String>> {
        let source = self.source.0;
        let genesis_account = match (source.header().is_genesis(), genesis) {
            (true, Some(genesis)) if self.state.block_hashes.is_empty() => {
                Some(genesis.account_for(source)?)
            }
            (false, None) => None,
            _ => return Err("Network source lacks its exact initial genesis admission".into()),
        };
        let now = source.header().creation_time();
        let count = source.network_entrypoint_count();
        let policy_routes = self
            .state
            .network_policy_routes
            .as_ref()
            .ok_or("Network source lacks its original pre-effect physical policy owner")?;
        policy_routes.validate_carrier(source)?;
        let parameters = self.state.world.parameters.get();
        let mut sources = Vec::new();
        sources.try_reserve_exact(count).map_err(|_| {
            ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
            )
        })?;
        for (index, input) in source.network_entrypoints().enumerate() {
            let (routing, policy_route) = policy_routes.get(source, index)?;
            // Lane admission does not preserve TTL. Expansion filters invalid
            // merged inputs at this same global time before they enter Network,
            // and execution repeats normal signature/network/expiry validation.
            let validation_time = now;
            let admission = if let Some(account) = genesis_account {
                let TransactionEntrypoint::External(signed) = input else {
                    return Err("authenticated genesis contains a non-signed Network source".into());
                };
                AcceptedTransaction::validate_genesis_with_now(
                    signed,
                    parameters.sumeragi().max_clock_drift(),
                    account,
                    &self.state.crypto,
                    validation_time,
                )
                .map(|()| AcceptedTransaction::new_unchecked_entrypoint(Cow::Borrowed(input)))
                .map_err(execution_rejection_from_admission_failure)
            } else {
                AcceptedTransaction::accept_borrowed_entrypoint_at_time(
                    input,
                    &self.state.network_id,
                    parameters.sumeragi().max_clock_drift(),
                    parameters.transaction(),
                    &self.state.crypto,
                    validation_time,
                )
                .map_err(execution_rejection_from_admission_failure)
            };
            let admission = if genesis_account.is_none() {
                if let Some(signed) = signed_source(input) {
                    if signed.creation_time() >= now {
                        Err(TransactionRejectionReason::Validation(
                            ValidationFail::NotPermitted(format!(
                                "transaction creation time {} is not earlier than block creation time {}",
                                signed.creation_time().as_millis(),
                                now.as_millis(),
                            )),
                        ))
                    } else {
                        #[cfg(feature = "telemetry")]
                        let telemetry = Some(self.state.telemetry);
                        #[cfg(not(feature = "telemetry"))]
                        let telemetry = None;
                        let fraud = if let Some(physical) = policy_route.physical() {
                            let physical = physical.decision();
                            crate::tx::enforce_fraud_policy(
                                &self.state.fraud_monitoring,
                                signed.metadata(),
                                telemetry,
                                &crate::tx::LaneAssignment {
                                    lane_id: physical.lane_id,
                                    dataspace_id: physical.dataspace_id,
                                    dataspace_catalog: &self.state.nexus.dataspace_catalog,
                                },
                            )
                        } else {
                            Ok(())
                        };
                        fraud.and(admission)
                    }
                } else {
                    admission
                }
            } else {
                admission
            };
            sources.push(FrozenNetworkSource {
                routing,
                admission: Some(admission),
                genesis: genesis
                    .map(|genesis| genesis.transaction_for(source, index))
                    .transpose()?,
                quarantine: QuarantineAdmission::Normal,
            });
        }
        self.freeze_network_order(sources)
    }

    /// Both source kinds share frozen reveal order and no-refill quarantine
    /// ranking. Later State changes cannot change selection or reorder effects.
    fn freeze_network_order(
        &self,
        mut sources: Vec<FrozenNetworkSource<'source>>,
    ) -> Result<FrozenNetworkSources<'source>, ExecutionAttemptError<String>> {
        let count = self.source.network_entrypoint_count();
        if sources.len() != count {
            return Err("Network admission lost a source position".into());
        }
        let quarantine_policy = FrozenQuarantinePolicy {
            max_sources: self.state.pipeline.quarantine_max_txs_per_block,
            max_cycles: self.state.pipeline.quarantine_tx_max_cycles,
        };
        let mut order = Vec::new();
        let mut reveal_positions = Vec::new();
        let mut sorted_reveals = Vec::new();
        let mut quarantine_candidates = Vec::new();
        for vector in [&mut order, &mut reveal_positions] {
            vector.try_reserve_exact(count).map_err(|_| {
                ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
                )
            })?;
        }
        sorted_reveals.try_reserve_exact(count).map_err(|_| {
            ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
            )
        })?;
        quarantine_candidates
            .try_reserve_exact(count)
            .map_err(|_| {
                ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
                )
            })?;
        for (index, frozen) in sources.iter_mut().enumerate() {
            let input = self
                .source
                .network_entrypoint_at(index)
                .ok_or("Network ordering lost a source")?;
            if frozen.admission.as_ref().is_some_and(Result::is_ok)
                && signed_source(input).is_some_and(crate::tx::is_quarantine_transaction)
            {
                quarantine_candidates.push((input.hash(), index));
                frozen.quarantine = QuarantineAdmission::Overflow;
            }
            order.push(index);
            if let TransactionEntrypoint::SealedReveal(reveal) = input {
                reveal_positions.push(index);
                sorted_reveals.push((
                    crate::tx::sealed_reveal_execution_key(self.state, reveal),
                    index,
                ));
            }
        }
        sorted_reveals.sort_unstable();
        for (slot, (_, source)) in reveal_positions.into_iter().zip(sorted_reveals) {
            order[slot] = source;
        }
        quarantine_candidates.sort_unstable();
        for (_, index) in quarantine_candidates
            .into_iter()
            .take(quarantine_policy.max_sources)
        {
            sources[index].quarantine = QuarantineAdmission::Selected;
        }
        Ok(FrozenNetworkSources {
            sources,
            order: Some(order),
            quarantine_policy,
        })
    }

    /// A later Pipeline phase consumes this frozen route, never reroutes against
    /// State changed by an earlier Network source.
    pub(super) fn network_route(&self, index: usize) -> Option<RoutingDecision> {
        self.network_sources
            .as_ref()?
            .sources
            .get(index)
            .map(|source| source.routing)
    }

    pub(super) fn execute_network_source(
        &mut self,
        index: usize,
        cache: &mut IvmCache,
    ) -> Result<(), ExecutionAttemptError<String>> {
        let policy = &self
            .network_sources
            .as_ref()
            .ok_or("Network execution has no frozen quarantine policy")?
            .quarantine_policy;
        if policy.max_sources != self.state.pipeline.quarantine_max_txs_per_block
            || policy.max_cycles != self.state.pipeline.quarantine_tx_max_cycles
        {
            return Err("Network quarantine policy changed after source admission".into());
        }
        let input_index = u32::try_from(index).map_err(|_| "Network position exceeds u32")?;
        if self.network_resolved.get(index) != Some(&false) {
            return Err("Network source is missing or already resolved".into());
        }
        let input = self
            .source
            .network_entrypoint_at(index)
            .ok_or("Network source disappeared")?;
        let frozen = self
            .network_sources
            .as_mut()
            .and_then(|plan| plan.sources.get_mut(index))
            .ok_or("Network admission has no frozen source")?;
        let routing = frozen.routing;
        let admitted = frozen
            .admission
            .take()
            .ok_or("Network admission was consumed twice")?;
        let quarantine = frozen.quarantine;
        let reservation = self
            .budget
            .as_mut()
            .ok_or("output budget already consumed")?
            .begin(ExecutionOutputV1::network_output_limit_rejection(
                input_index,
            ))?;
        let (captured_native, policy_route) = self
            .state
            .network_policy_routes
            .as_ref()
            .ok_or("Network source lost its physical policy owner")?
            .get(self.source.0, index)?;
        if captured_native != routing {
            return Err("Network source changed its captured native route".into());
        }
        let row = execute_network_attempt_with_amx(
            self.state,
            &self.source,
            input,
            input_index,
            u64::from(input_index),
            self.source.header().height().get(),
            routing,
            policy_route,
            admitted,
            frozen.genesis.as_ref(),
            quarantine == QuarantineAdmission::Overflow,
            reservation,
            cache,
            self.amx_legs.as_deref_mut(),
        )?;
        self.rows[index] = row;
        self.network_resolved[index] = true;
        Ok(())
    }
}

/// Execute one authenticated source under the shared State/witness/output owner.
/// The caller owns the complete authenticated input projection and frozen route;
/// this function never derives invocation authority from a supplied hash.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn execute_network_attempt_with_amx<'attempt>(
    state: &'attempt mut StateBlock<'_>,
    inputs: &(impl iroha_data_model::block::execution_output::ExecutionInputs + ?Sized),
    input: &'attempt TransactionEntrypoint,
    input_index: u32,
    execution_index: u64,
    height: u64,
    routing: RoutingDecision,
    policy_route: CapturedNetworkPolicyRoute,
    admitted: Result<AcceptedTransaction<'_>, TransactionRejectionReason>,
    genesis: Option<&crate::block::AuthenticatedGenesisTransaction>,
    quarantine_overflow: bool,
    reservation: iroha_data_model::block::output_budget::ExecutionOutputReservation<'_>,
    cache: &mut IvmCache,
    amx_legs: Option<&'attempt mut crate::sumeragi::amx::NativeAmxLegPreparations>,
) -> Result<ExecutionOutputV1, ExecutionAttemptError<String>> {
    if inputs.input_at(input_index as usize) != Some(input)
        || state._curr_block.height().get() != height
        || admitted
            .as_ref()
            .is_ok_and(|accepted| accepted.entrypoint() != input)
    {
        return Err("Network attempt differs from its exact authenticated projection".into());
    }
    state.retain_fastpq_source_invocation(Hash::from(input.execution_call_hash()))?;
    let gas_before = state.gas_used_in_block;
    let gas_limit = state.gas_limit_per_block;
    let mut attempt = OutputTransaction::new(state)?;
    let transaction = attempt
        .transaction
        .as_mut()
        .ok_or("Network attempt is absent")?;
    bind_source(transaction, input, execution_index, routing)?;
    transaction.native_amx_leg_execution = amx_legs.map(|bank| {
        crate::sumeragi::amx::NativeAmxLegExecution::new(bank, input, input_index as usize)
    });
    let mut result = match admitted {
        Ok(_) if quarantine_overflow => Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted("quarantine overflow".into()),
        )),
        Ok(accepted) => match StateBlock::execute_accepted_transaction_in_overlay(
            accepted,
            transaction,
            cache,
            routing,
            policy_route,
            genesis,
        ) {
            Ok(sequence) => Ok(sequence),
            Err(ExecutionAttemptError::Rejected(reason)) => Err(reason),
            Err(ExecutionAttemptError::Deferred(reason)) => {
                return Err(ExecutionAttemptError::Deferred(reason));
            }
        },
        Err(reason) => Err(reason),
    };
    if let Some(reason) = transaction.execution_deferral() {
        return Err(ExecutionAttemptError::Deferred(reason));
    }
    if transaction.fastpq_source_quota.intrinsic_rejected()? {
        result = Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(
                crate::fastpq::source_reservation::admission::SOURCE_INTRINSIC_REJECTION.into(),
            ),
        ));
    }
    transaction
        .require_storage_admission()
        .map_err(|error| error.to_string())?;
    require_source(transaction, input, execution_index, routing)?;
    transaction.require_completed_execution_effect_owner()?;
    let effect_limit_rejection = transaction.execution_effect_limit_exceeded();
    let work = CompletedOutputWork::capture(transaction);
    let rejection_fee = transaction.take_execution_fee_settlement()?;
    let penalties = transaction.take_deferred_governance_ballot_penalties_v1();
    if result.is_ok() && !penalties.is_empty() {
        return Err("successful Network attempt retains rejection-only penalties".into());
    }
    let block_gas_rejection = result.is_ok()
        && !crate::gas::gas_components_fit_block_limit(gas_limit, [gas_before, work.gas]);
    if block_gas_rejection {
        let attempted = u128::from(gas_before) + u128::from(work.gas);
        result = Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(format!(
                "block gas limit exceeded: {attempted} > {gas_limit}"
            )),
        ));
    }
    if let Err(reason) = result {
        transaction
            .callback_journal
            .discard_rejected(Hash::from(input.execution_call_hash()))?;
        transaction
            .contract_event_journal
            .discard_rejected(Hash::from(input.execution_call_hash()))?;
        drop(attempt);
        return complete_network_rejection(
            state,
            RejectedNetworkAttempt {
                inputs,
                input,
                input_index,
                execution_index,
                height,
                routing,
                reason,
                work,
                penalties,
                block_gas_rejection,
                effect_limit_rejection,
                reservation,
            },
            rejection_fee.map(|basis| {
                move |transaction: &mut StateTransaction<'_, '_>,
                      signed: &iroha_data_model::transaction::SignedTransaction| {
                    basis.settle(transaction, signed)
                }
            }),
        );
    }
    // The legacy returned DFS vector is not the capture owner. The actual
    // journal also retains nested by-call steps omitted from that vector.
    if transaction
        .world
        .external_event_buf
        .iter()
        .any(|event| matches!(event, EventBox::TriggerCompleted(_)))
    {
        return Err("Network completion bypassed its actual callback journal".into());
    }
    let call = Hash::from(input.execution_call_hash());
    let mut receipts = core::mem::take(&mut transaction.pending_batch_transfer_outcomes);
    let owned = receipts
        .remove(&HashOf::from_untyped_unchecked(call))
        .unwrap_or_default();
    if !receipts.is_empty() {
        return Err("Network receipts belong to another execution call".into());
    }
    let fee_receipt = transaction.pending_nexus_fee_receipt.take();
    let callback_capture = transaction.callback_journal.take(call)?;
    let event_capture = if matches!(callback_capture, DrainedCallbacks::OutputLimit) {
        transaction.contract_event_journal.discard_rejected(call)?;
        DrainedContractEvents::OutputLimit
    } else {
        let budget = transaction.execution_budget();
        transaction.contract_event_journal.take(call, &budget)?
    };
    let (actual, journal_overflow) = match (callback_capture, event_capture) {
        (
            DrainedCallbacks::Complete { steps, completions },
            DrainedContractEvents::Complete(events),
        ) => {
            let mut result = TransactionResult::new(Ok(steps));
            result.set_batch_transfer_outcomes(owned);
            result.set_nexus_fee_receipt(fee_receipt);
            result.set_contract_events(events);
            (
                ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                    input_index,
                    result,
                    completions,
                }),
                false,
            )
        }
        _ => (
            ExecutionOutputV1::network_output_limit_rejection(input_index),
            true,
        ),
    };
    actual.validate_structure(height, inputs)?;
    let (row, apply) = match reservation.finish(actual)? {
        ReservedExecutionOutput::Accepted(row) => (row, !journal_overflow),
        ReservedExecutionOutput::OutputLimit(row) => (row, false),
    };
    if apply {
        let transaction = attempt
            .transaction
            .as_mut()
            .ok_or("Network attempt is absent")?;
        transaction
            .world
            .external_event_buf
            .try_reserve(row.completions().len())
            .map_err(|_| {
                ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
                )
            })?;
        for completion in row.completions() {
            transaction.world.external_event_buf.push(
                TriggerCompletedEvent::new(
                    completion.trigger_id.clone(),
                    HashOf::from_untyped_unchecked(call),
                    completion.callback_index,
                    completion.outcome.clone(),
                )
                .into(),
            );
        }
        attempt.apply()?;
    } else {
        drop(attempt);
    }
    work.account(state);
    Ok(row)
}

// These owners are created only after the original business overlay has been dropped.
// Keeping rejection fragments in this stage avoids reserving their complete transaction
// values on the active nested-execution stack. No allocation or lifetime changes are needed.
struct RejectedNetworkAttempt<'input, 'reservation, Inputs: ?Sized> {
    inputs: &'input Inputs,
    input: &'input TransactionEntrypoint,
    input_index: u32,
    execution_index: u64,
    height: u64,
    routing: RoutingDecision,
    reason: TransactionRejectionReason,
    work: CompletedOutputWork,
    penalties: Vec<crate::state::DeferredGovernanceBallotPenaltyV1>,
    block_gas_rejection: bool,
    effect_limit_rejection: bool,
    reservation: iroha_data_model::block::output_budget::ExecutionOutputReservation<'reservation>,
}

fn complete_network_rejection<
    Inputs: iroha_data_model::block::execution_output::ExecutionInputs + ?Sized,
>(
    state: &mut StateBlock<'_>,
    rejected: RejectedNetworkAttempt<'_, '_, Inputs>,
    settle_fee: Option<
        impl FnOnce(
            &mut StateTransaction<'_, '_>,
            &iroha_data_model::transaction::SignedTransaction,
        ) -> Result<bool, crate::executor::ExecutionFeeSettlementError>,
    >,
) -> Result<ExecutionOutputV1, ExecutionAttemptError<String>> {
    let RejectedNetworkAttempt {
        inputs,
        input,
        input_index,
        execution_index,
        height,
        routing,
        reason,
        mut work,
        penalties,
        block_gas_rejection,
        effect_limit_rejection,
        reservation,
    } = rejected;
    // Confidential work survives every completed attempt. Actual gas/fee
    // eligibility is decided from the real rejection, never its bounded row.
    let used_gas = work.gas;
    work.gas = 0;
    work.account(state);
    let mut result = Err(reason);
    let mut funded_fee = None;
    let mut fee_receipt = None;
    let penalty_failure =
        settle_rejection_penalties(state, input, execution_index, routing, &penalties)?;
    let penalty_committed = penalty_failure.is_none();
    if let Some(reason) = penalty_failure {
        result = Err(reason);
    }
    if !block_gas_rejection && penalty_committed {
        if rejected_transaction_gas_is_accountable(used_gas, &result) {
            state.gas_used_in_block = state.gas_used_in_block.saturating_add(used_gas);
        }
        let chargeable = !matches!(
            &result,
            Err(TransactionRejectionReason::Validation(
                ValidationFail::InternalError(_)
            ))
        ) && !effect_limit_rejection;
        if let Some(signed) = signed_source(input)
            && chargeable
            && let Some(settle) = settle_fee
        {
            let mut fee = OutputTransaction::new(state)?;
            let transaction = fee.transaction.as_mut().ok_or("fee attempt is absent")?;
            bind_source(transaction, input, execution_index, routing)?;
            let charged = match settle(transaction, signed) {
                Ok(charged) => Ok(charged),
                Err(crate::executor::ExecutionFeeSettlementError::Owner(error)) => {
                    return Err(error.into());
                }
                Err(crate::executor::ExecutionFeeSettlementError::Charge(error)) => {
                    Err(TransactionRejectionReason::Validation(error))
                }
            };
            if transaction.fastpq_source_quota.intrinsic_rejected()? {
                return Err("rejection fee exceeded its admitted complete source tail".into());
            }
            match charged {
                Ok(true) => {
                    require_rejection_fragment(transaction, input, execution_index, routing)?;
                    fee_receipt = transaction.pending_nexus_fee_receipt.take();
                    funded_fee = Some(fee);
                }
                Ok(false) => drop(fee),
                Err(error) => {
                    drop(fee);
                    result = Err(error);
                }
            }
        }
    }
    let mut result = TransactionResult::new(result);
    result.set_nexus_fee_receipt(fee_receipt);
    let actual = ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
        input_index,
        result,
        completions: Vec::new(),
    });
    actual.validate_structure(height, inputs)?;
    let row = reservation.finish_network_rejection(actual)?;
    // No charge becomes real before its exact receipt-bearing terminal fits.
    if let Some(fee) = funded_fee {
        fee.apply()?;
    }
    Ok(row)
}

fn settle_rejection_penalties(
    state: &mut StateBlock<'_>,
    input: &TransactionEntrypoint,
    execution_index: u64,
    routing: RoutingDecision,
    penalties: &[crate::state::DeferredGovernanceBallotPenaltyV1],
) -> Result<Option<TransactionRejectionReason>, ExecutionAttemptError<String>> {
    if penalties.is_empty() {
        return Ok(None);
    }
    if signed_source(input).is_none() {
        return Ok(Some(TransactionRejectionReason::Validation(
            ValidationFail::InternalError(
                "deferred governance ballot penalty has no signed transaction".to_owned(),
            ),
        )));
    }
    let mut penalty = OutputTransaction::new(state)?;
    let transaction = penalty
        .transaction
        .as_mut()
        .ok_or("penalty attempt is absent")?;
    bind_source(transaction, input, execution_index, routing)?;
    let applied = StateBlock::stage_rejected_governance_ballot_penalties_v1(transaction, penalties);
    if transaction.fastpq_source_quota.intrinsic_rejected()? {
        return Err("rejection penalty exceeded its admitted complete source tail".into());
    }
    match applied {
        Ok(()) => {
            require_rejection_fragment(transaction, input, execution_index, routing)?;
            penalty.apply()?;
            Ok(None)
        }
        Err(error) => {
            drop(penalty);
            Ok(Some(error))
        }
    }
}

fn signed_source(
    input: &TransactionEntrypoint,
) -> Option<&iroha_data_model::transaction::SignedTransaction> {
    match input {
        TransactionEntrypoint::External(signed) => Some(signed),
        TransactionEntrypoint::SealedReveal(reveal) => Some(reveal.signed_transaction()),
        TransactionEntrypoint::SealedCommitment(_) => None,
    }
}

fn bind_source(
    transaction: &mut StateTransaction<'_, '_>,
    input: &TransactionEntrypoint,
    index: u64,
    route: RoutingDecision,
) -> Result<(), String> {
    transaction.current_entrypoint_index = Some(index);
    transaction.current_network_entrypoint_hash = Some(input.hash());
    transaction.tx_call_hash = Some(Hash::from(input.execution_call_hash()));
    transaction.current_tx_hash = signed_source(input).map(|signed| signed.hash());
    transaction.current_lane_id = Some(route.lane_id);
    transaction.current_dataspace_id = Some(route.dataspace_id);
    transaction.world.current_dataspace_id = Some(route.dataspace_id);
    transaction.bind_original_fastpq_invocation_source(OwnedExecutionSource::new(
        Hash::from(input.execution_call_hash()),
        Some(route.lane_id),
        route.dataspace_id,
    ))
}

fn require_source(
    transaction: &StateTransaction<'_, '_>,
    input: &TransactionEntrypoint,
    index: u64,
    route: RoutingDecision,
) -> Result<(), String> {
    if transaction.current_entrypoint_index != Some(index)
        || transaction.current_network_entrypoint_hash != Some(input.hash())
        || transaction.tx_call_hash != Some(Hash::from(input.execution_call_hash()))
        || transaction.current_tx_hash != signed_source(input).map(|signed| signed.hash())
        || transaction.current_lane_id != Some(route.lane_id)
        || transaction.current_dataspace_id != Some(route.dataspace_id)
        || transaction.world.current_dataspace_id != Some(route.dataspace_id)
    {
        return Err("Network execution changed its source or frozen route owner".into());
    }
    transaction.require_original_fastpq_invocation_source(OwnedExecutionSource::new(
        Hash::from(input.execution_call_hash()),
        Some(route.lane_id),
        route.dataspace_id,
    ))
}

fn require_rejection_fragment(
    transaction: &StateTransaction<'_, '_>,
    input: &TransactionEntrypoint,
    index: u64,
    route: RoutingDecision,
) -> Result<(), String> {
    require_source(transaction, input, index, route)?;
    if !transaction.callback_journal.allows_apply()
        || !transaction.pending_batch_transfer_outcomes.is_empty()
        || transaction
            .world
            .external_event_buf
            .iter()
            .any(|event| matches!(event, EventBox::TriggerCompleted(_)))
    {
        return Err("rejection settlement retained rejected business capture".into());
    }
    Ok(())
}
