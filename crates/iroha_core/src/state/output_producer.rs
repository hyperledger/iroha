//! Linear State-owned output retention and pre-apply invocation execution.
//!
//! Actual Network execution owns successful business rollback separately from
//! rejection penalties and fees. The callback journal owns the complete trace.
//! TODO: compose source, host-memory and complete-wire admission under the sole
//! canonical driver and common seal. The Block driver owns entry; this private
//! producer cannot authorize State publication.

use super::{
    ExecutionOutputAttemptError, ExecutionOutputPlanState, OwnedExecutionSource,
    OwnedExecutionSources, StateBlock, StateTransaction,
};
use crate::execution_attempt::ExecutionAttemptError;
use crate::state::callback_journal::DrainedCallbacks;
use iroha_crypto::{Hash, HashOf, MerkleTree};
use iroha_data_model::{
    block::{
        SignedBlock,
        execution_output::{
            ExecutionOutputV1, NetworkExecutionOutputV1, validate_execution_outputs_v1,
        },
        output_budget::{ExecutionOutputBudget, ExecutionOutputPhase, ReservedExecutionOutput},
    },
    transaction::signed::TransactionEntrypoint,
};

/// Retained by State until the complete common tail can consume this owner.
/// Neither a clone nor an output-only setter can authorize its publication.
pub(in crate::state) struct RetainedExecutionOutputs {
    rows: Vec<ExecutionOutputV1>,
    row_bytes: u64,
    proposal: iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>,
    input_root: Option<Hash>,
    sources: Option<OwnedExecutionSources>,
}

/// Actual attachment remains nonpublishable until witness/finality admission is
/// complete. Retain the exact result wire binding; never clear the State marker.
pub(in crate::state) struct SealedExecutionOutputs {
    proposal: iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>,
    wire_hash: Hash,
    wire_bytes: u64,
    // Actual canonical World net changes at attachment, including finalizer
    // effects. This is only one component of the still-unfinished State proof.
    world_delta: crate::state::world_projection::WorldNetDelta,
    // Captured by the sole witness recorder before the witness is handed out.
    witness_hash: Option<HashOf<iroha_data_model::block::consensus::ExecWitness>>,
    witness_surface: Option<Box<crate::state::output_publication::FinalizedPublicationSurface>>,
    // Preserve the actual complete invocation owner after inventory derivation;
    // a projection or caller-supplied row list cannot replace these sources.
    _sources: OwnedExecutionSources,
}

/// Exact durable finality over this owner's complete outputs and actual witness.
pub(in crate::state) struct AuthorizedExecutionOutputs {
    sealed: SealedExecutionOutputs,
    finality_hash: Hash,
    native_execution: crate::sumeragi::executor::NativeExecutionAuthorization,
}

/// Retain both execution authority and the deterministic publication surface.
pub(in crate::state) struct FinalizedExecutionOutputs {
    authorized: AuthorizedExecutionOutputs,
    surface: Box<crate::state::output_publication::FinalizedPublicationSurface>,
    _events_hash: Hash,
}

/// Owns both the State borrow and its only mutable output budget. It cannot be
/// moved to another State or used recursively while the continuation is live.
struct ExecutionOutputProducer<'owner, 'state, 'source> {
    state: &'owner mut StateBlock<'state>,
    source: ExecutionSource<'source>,
    amx_legs: Option<&'owner mut crate::sumeragi::amx::NativeAmxLegPreparations>,
    budget: Option<ExecutionOutputBudget>,
    unused_time: u32,
    // Allocate the complete row vector before work. Network placeholders are
    // private fallback values, never evidence of execution. The separate bit
    // for each source must be resolved before finish can expose the collection.
    // This also preserves source order when reveals execute out of input order.
    rows: Vec<ExecutionOutputV1>,
    network_resolved: Vec<bool>,
    network_sources: Option<network::FrozenNetworkSources<'source>>,
    source_entries: Vec<OwnedExecutionSource>,
    source_routes: Vec<crate::queue::RoutingDecision>,
    internal_dataspace: Option<iroha_model_base::topology::DataSpaceId>,
    pipeline_started: bool,
    time_started: bool,
    failed: bool,
    finished: bool,
}

impl StateBlock<'_> {
    /// Execute each actual ordinary phase exactly once on its reserved State owner.
    /// Complete source/finality/host admission remains the caller's prerequisite.
    #[cfg(test)]
    pub(crate) fn execute_ordinary_output_plan(
        &mut self,
        source: &SignedBlock,
        genesis: Option<&crate::block::AuthenticatedGenesisOutputSource>,
    ) -> Result<(), ExecutionOutputAttemptError> {
        self.execute_ordinary_output_plan_with_amx(source, genesis, None)
    }

    pub(crate) fn execute_ordinary_output_plan_with_amx(
        &mut self,
        source: &SignedBlock,
        genesis: Option<&crate::block::AuthenticatedGenesisOutputSource>,
        amx_legs: Option<&mut crate::sumeragi::amx::NativeAmxLegPreparations>,
    ) -> Result<(), ExecutionOutputAttemptError> {
        self.produce_ordinary_execution_outputs_with_amx(source, amx_legs, |producer| {
            producer.execute_network_sources(genesis)?;
            producer.execute_pipeline_outputs()?;
            producer.execute_scheduled_time_outputs()
        })
    }

    /// Observe completed actual rows without transferring or clearing their publication guard.
    #[cfg(test)]
    pub(crate) fn retained_execution_outputs_for_test(
        &self,
    ) -> Result<&[ExecutionOutputV1], String> {
        match self.execution_output_plan.as_ref() {
            Some(ExecutionOutputPlanState::Retained(retained)) => Ok(&retained.rows),
            _ => Err("actual execution outputs have not been retained".into()),
        }
    }

    /// Consume actual sources for narrow inventory controls without permitting seal
    /// or publication. Supplied projections and partial mock execution cannot enter.
    #[cfg(test)]
    pub(in crate::state) fn inspect_owned_execution_sources_for_test(
        &mut self,
        source: &SignedBlock,
        inspect: impl FnOnce(&mut Self, &OwnedExecutionSources) -> Result<(), String>,
    ) -> Result<(), String> {
        // The inspection owns the actual retained capsule while deriving a
        // source projection. Inspecting refuses capture and publication; every
        // exit, including unwinding, consumes the inspection into Poisoned.
        struct SourceInspectionOwner<'owner, 'state> {
            state: &'owner mut StateBlock<'state>,
        }
        impl Drop for SourceInspectionOwner<'_, '_> {
            fn drop(&mut self) {
                self.state.execution_output_plan = Some(ExecutionOutputPlanState::Poisoned);
            }
        }

        let Some(ExecutionOutputPlanState::Retained(retained)) = self
            .execution_output_plan
            .replace(ExecutionOutputPlanState::Inspecting)
        else {
            self.execution_output_plan = Some(ExecutionOutputPlanState::Poisoned);
            return Err("inspection requires completed actual execution".into());
        };
        let owner = SourceInspectionOwner { state: self };
        if retained.proposal != source.hash() || owner.state._curr_block != source.header() {
            return Err("inspection source differs from its actual execution".into());
        }
        let sources = retained
            .sources
            .ok_or("inspection requires all actual phases")?;
        inspect(&mut *owner.state, &sources)
    }

    /// Move the existing ordinary plan into exactly one borrowing continuation.
    /// The Block driver sequences every ordinary phase through this owner.
    /// TODO: complete source/host admission; every state remains gated.
    #[cfg(test)]
    fn produce_ordinary_execution_outputs(
        &mut self,
        source: &SignedBlock,
        execute: impl FnOnce(
            &mut ExecutionOutputProducer<'_, '_, '_>,
        ) -> Result<(), ExecutionOutputAttemptError>,
    ) -> Result<(), ExecutionOutputAttemptError> {
        self.produce_ordinary_execution_outputs_with_amx(source, None, execute)
    }

    fn produce_ordinary_execution_outputs_with_amx(
        &mut self,
        source: &SignedBlock,
        amx_legs: Option<&mut crate::sumeragi::amx::NativeAmxLegPreparations>,
        execute: impl FnOnce(
            &mut ExecutionOutputProducer<'_, '_, '_>,
        ) -> Result<(), ExecutionOutputAttemptError>,
    ) -> Result<(), ExecutionOutputAttemptError> {
        let mut producer = match amx_legs {
            Some(bank) => {
                ExecutionOutputProducer::new_with_amx(self, ExecutionSource(source), Some(bank))?
            }
            None => ExecutionOutputProducer::new(self, ExecutionSource(source))?,
        };
        execute(&mut producer)?;
        producer
            .finish()
            .map_err(ExecutionOutputAttemptError::Owner)
    }
}

#[path = "output_source.rs"]
mod source;
use source::ExecutionSource;

impl<'owner, 'state, 'source> ExecutionOutputProducer<'owner, 'state, 'source> {
    fn new(
        state: &'owner mut StateBlock<'state>,
        source: ExecutionSource<'source>,
    ) -> Result<Self, ExecutionAttemptError<String>> {
        Self::new_with_amx(state, source, None)
    }

    fn new_with_amx(
        state: &'owner mut StateBlock<'state>,
        source: ExecutionSource<'source>,
        amx_legs: Option<&'owner mut crate::sumeragi::amx::NativeAmxLegPreparations>,
    ) -> Result<Self, ExecutionAttemptError<String>> {
        let Some(ExecutionOutputPlanState::Reserved(plan)) = state.execution_output_plan.as_ref()
        else {
            return Err("execution output plan is not available for its producer".into());
        };
        {
            let block = source.0;
            block.validate_proposal_commitments()?;
        }
        if source.header() != state._curr_block
            || plan.proposal != source.hash()
            || plan.input_root != source.input_root()
            || usize::try_from(plan.network_inputs).ok() != Some(source.network_entrypoint_count())
        {
            return Err("output producer does not own this input projection".into());
        }
        // The publication guard remains occupied through allocation and unwind.
        let Some(ExecutionOutputPlanState::Reserved(plan)) = state
            .execution_output_plan
            .replace(ExecutionOutputPlanState::Running)
        else {
            return Err("execution output ownership changed before transfer".into());
        };
        let mut producer = ExecutionOutputProducer {
            state,
            source,
            amx_legs,
            budget: Some(plan.budget),
            unused_time: 0,
            rows: Vec::new(),
            network_resolved: Vec::new(),
            network_sources: None,
            source_entries: Vec::new(),
            source_routes: Vec::new(),
            internal_dataspace: None,
            pipeline_started: false,
            time_started: false,
            failed: false,
            finished: false,
        };
        producer
            .rows
            .try_reserve_exact(
                usize::try_from(plan.maximum_rows)
                    .map_err(|_| "row capacity exceeds host width")?,
            )
            .map_err(|_| {
                ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
                )
            })?;
        let network_count = usize::try_from(plan.network_inputs)
            .map_err(|_| "Network capacity exceeds host width")?;
        producer
            .source_entries
            .try_reserve_exact(
                usize::try_from(plan.maximum_rows)
                    .map_err(|_| "source capacity exceeds host width")?,
            )
            .map_err(|_| {
                ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
                )
            })?;
        producer
            .source_routes
            .try_reserve_exact(network_count)
            .map_err(|_| {
                ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
                )
            })?;
        producer
            .network_resolved
            .try_reserve_exact(network_count)
            .map_err(|_| {
                ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
                )
            })?;
        for index in 0..plan.network_inputs {
            producer
                .rows
                .push(ExecutionOutputV1::network_output_limit_rejection(index));
            producer.network_resolved.push(false);
        }
        Ok(producer)
    }
}

/// Transaction plus non-WSV rollback guards. Restores ZK dedup on pre-apply
/// unwind; witness overlays roll back on drop without resetting the recorder.
/// An interruption during apply invalidates the whole still-gated StateBlock.
struct OutputTransaction<'block, 'state> {
    transaction: Option<StateTransaction<'block, 'state>>,
    witness: Option<crate::exec_witness::ExecWitnessOverlay>,
    #[cfg(feature = "zk-preverify")]
    zk_checkpoint: Option<crate::zk::DedupCache>,
}

impl<'block, 'state> OutputTransaction<'block, 'state> {
    fn new(state: &'block mut StateBlock<'state>) -> Result<Self, String> {
        #[cfg(feature = "zk-preverify")]
        let zk_checkpoint = Some(state.zk_dedup.clone());
        let transaction = state.try_transaction().map_err(|error| error.to_string())?;
        let witness = Some(crate::exec_witness::begin_exec_witness_overlay());
        Ok(Self {
            transaction: Some(transaction),
            witness,
            #[cfg(feature = "zk-preverify")]
            zk_checkpoint,
        })
    }

    fn apply(mut self) -> Result<(), String> {
        // Keep State, witness and auxiliary rollback owners armed through refusal.
        // Taking State first would also prevent Drop from restoring zk_dedup.
        if self.witness.is_none() {
            return Err("output transaction witness owner is absent".into());
        }
        let transaction = self
            .transaction
            .as_mut()
            .ok_or("output transaction State owner is absent")?;
        if transaction.pending_nexus_fee_receipt.is_some() {
            return Err("actual Nexus charge has no retained consensus receipt".into());
        }
        transaction.prepare_apply()?;
        self.transaction
            .take()
            .expect("checked output transaction State owner")
            .apply_prepared();
        self.witness
            .take()
            .expect("checked output transaction witness owner")
            .commit();
        Ok(())
    }
}

impl Drop for OutputTransaction<'_, '_> {
    fn drop(&mut self) {
        #[cfg(feature = "zk-preverify")]
        if let (Some(transaction), Some(checkpoint)) =
            (self.transaction.as_mut(), self.zk_checkpoint.take())
        {
            *transaction.zk_dedup = checkpoint;
        }
    }
}

/// Completed work survives business rollback. The actual rejection owner decides
/// gas eligibility separately before accounting confidential work and settlement.
struct CompletedOutputWork {
    gas: u64,
    confidential_operations: u32,
    verify_calls: u32,
    proof_bytes: u64,
    confidential_gas: u64,
}

impl CompletedOutputWork {
    fn capture(transaction: &StateTransaction<'_, '_>) -> Self {
        Self {
            gas: transaction.last_tx_gas_used,
            confidential_operations: transaction.zk_confidential_ops_in_tx,
            verify_calls: transaction.zk_verify_calls_in_tx,
            proof_bytes: transaction.zk_proof_bytes_in_tx,
            confidential_gas: transaction.confidential_gas_used_in_tx,
        }
    }

    fn account(self, state: &mut StateBlock<'_>) {
        state.gas_used_in_block = state.gas_used_in_block.saturating_add(self.gas);
        state.account_confidential_work_v1(
            self.confidential_operations,
            self.verify_calls,
            self.proof_bytes,
            self.confidential_gas,
        );
    }
}

#[path = "output_seal.rs"]
mod seal;
pub(crate) use seal::{ExecutionOutputSealError, ExecutionOutputSealMetadata};

#[path = "output_internal.rs"]
mod internal;

#[path = "output_pipeline.rs"]
mod pipeline;

#[path = "output_time.rs"]
mod time;

#[path = "output_network.rs"]
mod network;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
enum NetworkSuccessDisposition {
    Applied,
    OutputLimit,
}

impl ExecutionOutputProducer<'_, '_, '_> {
    /// Fit a complete successful row while its actual State transaction remains
    /// disposable. Completed work is accounted even on healthy output overflow.
    /// Test-only rollback control; actual execution uses the Network owner.
    #[cfg(test)]
    fn try_apply_network_success(
        &mut self,
        input_index: u32,
        execute: impl FnOnce(
            &TransactionEntrypoint,
            &mut StateTransaction<'_, '_>,
        ) -> Result<NetworkExecutionOutputV1, String>,
    ) -> Result<NetworkSuccessDisposition, ExecutionAttemptError<String>> {
        if self.failed {
            return Err("output producer already refused this carrier".into());
        }
        let result = (|| {
            let index =
                usize::try_from(input_index).map_err(|_| "Network index exceeds host width")?;
            if self.network_resolved.get(index) != Some(&false) {
                return Err("Network output is foreign or already resolved".into());
            }
            let input = self
                .source
                .network_entrypoint_at(index)
                .ok_or("Network output lost its authenticated source")?;
            let reservation = self
                .budget
                .as_mut()
                .ok_or("output budget already consumed")?
                .begin(ExecutionOutputV1::network_output_limit_rejection(
                    input_index,
                ))?;
            self.state
                .retain_fastpq_source_invocation(Hash::from(input.execution_call_hash()))?;
            let mut attempt = OutputTransaction::new(self.state)?;
            let transaction = attempt
                .transaction
                .as_mut()
                .ok_or("output transaction is absent")?;
            let call = Hash::from(input.execution_call_hash());
            let signed_hash = match input {
                TransactionEntrypoint::External(signed) => Some(signed.hash()),
                TransactionEntrypoint::SealedReveal(reveal) => {
                    Some(reveal.signed_transaction().hash())
                }
                TransactionEntrypoint::SealedCommitment(_) => None,
            };
            transaction.current_entrypoint_index = Some(u64::from(input_index));
            transaction.tx_call_hash = Some(call);
            transaction.current_network_entrypoint_hash = Some(input.hash());
            transaction.current_tx_hash = signed_hash;
            let executed = execute(input, transaction);
            if let Some(reason) = transaction.execution_deferral() {
                return Err(ExecutionAttemptError::Deferred(reason));
            }
            let mut actual = executed?;
            if transaction.tx_call_hash != Some(call)
                || transaction.current_entrypoint_index != Some(u64::from(input_index))
                || transaction.current_tx_hash != signed_hash
            {
                return Err("Network transaction changed its output source owner".into());
            }
            if actual.result.is_err() {
                return Err("rejected Network output requires its penalty and fee corridor".into());
            }
            if !actual.completions.is_empty()
                || transaction.world.external_event_buf.iter().any(|event| {
                    matches!(
                        event,
                        iroha_data_model::events::EventBox::TriggerCompleted(_)
                    )
                })
            {
                return Err(
                    "callback completions must come from their transaction-owned journal".into(),
                );
            }
            if actual.result.nexus_fee_receipt().is_some() {
                return Err("Nexus receipt must come from actual settlement owner".into());
            }
            actual
                .result
                .set_nexus_fee_receipt(transaction.pending_nexus_fee_receipt.take());
            if !actual.result.batch_transfer_outcomes().is_empty() {
                return Err("Network receipts must come from the actual transaction owner".into());
            }
            // Drain exact-call custody BEFORE sizing, so apply cannot append
            // receipts that were absent from the retained canonical row.
            let mut receipts = core::mem::take(&mut transaction.pending_batch_transfer_outcomes);
            let owned = receipts
                .remove(&HashOf::from_untyped_unchecked(call))
                .unwrap_or_default();
            if !receipts.is_empty() {
                return Err(
                    "Network transaction retains receipts for a foreign execution call".into(),
                );
            }
            actual.result.set_batch_transfer_outcomes(owned);
            let work = CompletedOutputWork::capture(transaction);
            match transaction.callback_journal.take(call)? {
                DrainedCallbacks::Complete { steps, completions } => {
                    if !steps.is_empty() {
                        if actual
                            .result
                            .0
                            .as_ref()
                            .is_ok_and(|trace| !trace.is_empty())
                        {
                            return Err(
                                "callback trace was supplied by both caller and journal".into()
                            );
                        }
                        actual.result.0 = Ok(steps);
                    }
                    actual.completions = completions;
                }
                DrainedCallbacks::OutputLimit => {
                    // Actual child bytes already exceed the entire row ceiling.
                    // Consume this source's pre-reserved bounded terminal, drop
                    // all business effects, and retain no partial callback trace.
                    let terminal = ExecutionOutputV1::network_output_limit_rejection(input_index);
                    let row = match reservation.finish(terminal)? {
                        ReservedExecutionOutput::Accepted(row)
                        | ReservedExecutionOutput::OutputLimit(row) => row,
                    };
                    drop(attempt);
                    work.account(self.state);
                    self.rows[index] = row;
                    self.network_resolved[index] = true;
                    return Ok(NetworkSuccessDisposition::OutputLimit);
                }
            }
            let actual = ExecutionOutputV1::Network(actual);
            actual.validate_structure(self.source.header().height().get(), &self.source)?;
            let (row, disposition) = match reservation.finish(actual)? {
                ReservedExecutionOutput::Accepted(row) => {
                    let transaction = attempt
                        .transaction
                        .as_mut()
                        .ok_or("output transaction is absent")?;
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
                            iroha_data_model::events::trigger_completed::TriggerCompletedEvent::new(
                                completion.trigger_id.clone(),
                                HashOf::from_untyped_unchecked(call),
                                completion.callback_index,
                                completion.outcome.clone(),
                            ).into(),
                        );
                    }
                    attempt.apply()?;
                    (row, NetworkSuccessDisposition::Applied)
                }
                ReservedExecutionOutput::OutputLimit(row) => {
                    drop(attempt);
                    (row, NetworkSuccessDisposition::OutputLimit)
                }
            };
            work.account(self.state);
            // In-place retention cannot allocate or fail after State application.
            self.rows[index] = row;
            self.network_resolved[index] = true;
            Ok(disposition)
        })();
        if result.is_err() {
            // Catching a local error in the continuation never permits sealing.
            self.failed = true;
        }
        result
    }

    /// Only the actual matcher may release uninvoked internal candidates.
    /// TODO: keep the actual matchers under the sole production driver and seal.
    fn skip_uninvoked(&mut self, phase: ExecutionOutputPhase, count: u32) -> Result<(), String> {
        if self.failed {
            return Err("output producer already refused this carrier".into());
        }
        let result = self
            .budget
            .as_mut()
            .ok_or("output budget already consumed")?
            .skip_uninvoked(phase, count);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn finish(mut self) -> Result<(), String> {
        if self.failed || self.network_resolved.iter().any(|resolved| !resolved) {
            return Err("output producer retains failed or unresolved Network work".into());
        }
        validate_execution_outputs_v1(
            &self.rows,
            self.source.hash(),
            self.source.header().height().get(),
            &self.source,
        )?;
        let (count, row_bytes) = self
            .budget
            .take()
            .ok_or("output budget already consumed")?
            .finish()?;
        if usize::try_from(count).ok() != Some(self.rows.len()) {
            return Err("retained output count differs from its resolved budget".into());
        }
        let sources = if self.network_sources.is_some()
            && self.pipeline_started
            && self.time_started
        {
            if self.source_entries.len() != self.rows.len()
                || self.source_routes.len() != self.source.network_entrypoint_count()
            {
                return Err("retained source records differ from completed output rows".into());
            }
            for (row, original) in self.rows.iter().zip(&self.source_entries) {
                let call = match row {
                    ExecutionOutputV1::Network(output) => {
                        let index = usize::try_from(output.input_index)
                            .map_err(|_| "source index exceeds host width")?;
                        let input = self
                            .source
                            .network_entrypoint_at(index)
                            .ok_or("retained Network source is absent")?;
                        let route = self
                            .source_routes
                            .get(index)
                            .ok_or("retained Network route is absent")?;
                        if original.lane() != Some(route.lane_id)
                            || original.dataspace() != route.dataspace_id
                        {
                            return Err(
                                "retained Network record differs from its frozen route".into()
                            );
                        }
                        Hash::from(input.execution_call_hash())
                    }
                    ExecutionOutputV1::Pipeline(output) => {
                        output.invocation.execution_call_hash(self.source.hash())?
                    }
                    ExecutionOutputV1::Time(output) => {
                        output.invocation.execution_call_hash(self.source.hash())?
                    }
                };
                if original.call() != call {
                    return Err("retained output row differs from its original invocation".into());
                }
            }
            Some(OwnedExecutionSources {
                proposal: self.source.hash(),
                source_context: iroha_data_model::fastpq::FastpqSourceStatementContextV1 {
                    network_id: self.state.network_id,
                    height: self.state._curr_block.height().get(),
                },
                entries: core::mem::take(&mut self.source_entries),
                network_routes: core::mem::take(&mut self.source_routes),
                internal_dataspace: self.internal_dataspace,
            })
        } else {
            // The closure-only controls exercise pre-apply fitting, not a complete
            // actual phase driver. Their rows cannot enter the consuming seal.
            None
        };
        if let Some(sources) = &sources {
            self.state
                .fastpq_source_quota
                .as_ref()
                .ok_or("source capacity was not frozen")?
                .as_ref()
                .map_err(|error| error.clone())?
                .verify_ordinary_entries(sources.entries().iter().map(|source| source.call()))?;
        }
        self.state.execution_output_plan = Some(ExecutionOutputPlanState::Retained(
            RetainedExecutionOutputs {
                rows: core::mem::take(&mut self.rows),
                row_bytes,
                proposal: self.source.hash(),
                input_root: MerkleTree::root_from_typed_leaves(
                    self.source
                        .network_entrypoints()
                        .map(TransactionEntrypoint::hash),
                )
                .map(Hash::from),
                sources,
            },
        ));
        self.finished = true;
        Ok(())
    }
}

impl Drop for ExecutionOutputProducer<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.finished {
            self.state.execution_output_plan = Some(ExecutionOutputPlanState::Poisoned);
        }
    }
}

#[cfg(test)]
#[path = "output_producer_tests.rs"]
mod tests;

impl ExecutionOutputProducer<'_, '_, '_> {
    /// Append once beside the completed terminal row in the existing bounded source vector.
    /// Rejected roots retain their invocation even though business quantity effects roll back.
    fn retain_completed_internal_source(
        &mut self,
        original: OwnedExecutionSource,
    ) -> Result<(), String> {
        // Incomplete fitting continuations cannot construct a complete source
        // owner at finish. A later Network start refuses these existing records.
        if original.lane().is_some()
            || (self.network_sources.is_some() && self.source_entries.len() != self.rows.len())
            || self.source_entries.len() >= self.source_entries.capacity()
            || self
                .internal_dataspace
                .is_some_and(|actual| actual != original.dataspace())
        {
            return Err("internal source differs from its original completed root".into());
        }
        self.internal_dataspace = Some(original.dataspace());
        self.source_entries.push(original);
        Ok(())
    }
}
