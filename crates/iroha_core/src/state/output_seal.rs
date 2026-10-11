//! Consuming common output attachment, preserving State ownership on every exit.
//! Sealed actual outputs join the original witness and durable finality before
//! one deterministic metadata tail can authorize their exact journal publication.

use super::*;
use crate::queue::RoutingDecision;

/// Block validation supplies the actual fragment count before attachment.
/// Rows, sources, receipts, transcripts and applying policy remain State-owned.
pub(crate) struct ExecutionOutputSealMetadata {
    /// Actual fragment count after the finalizer's deterministic State changes.
    pub(crate) committed_fragment_count: u64,
}

/// Keep source-specific validation errors intact across State's consuming seal.
#[derive(Debug)]
pub(crate) enum ExecutionOutputSealError<E> {
    /// Original local storage admission refused; the carrier is retryable.
    Storage(crate::state::StateStorageAdmissionError),
    /// The State owner, retained source or canonical attachment was inconsistent.
    Owner(String),
    /// Local execution did not complete; no output may be sealed or published.
    Deferred(crate::execution_attempt::ExecutionDeferred),
    /// Authenticated genesis produced a rejected output before schedule finalization.
    RejectedGenesis(crate::block::GenesisOutputRejection),
    /// The block finalizer rejected its actual deterministic effects.
    Finalizer(E),
}

impl<E> From<ExecutionAttemptError<String>> for ExecutionOutputSealError<E> {
    fn from(error: ExecutionAttemptError<String>) -> Self {
        match error {
            ExecutionAttemptError::Rejected(reason) => Self::Owner(reason),
            ExecutionAttemptError::Deferred(reason) => Self::Deferred(reason),
        }
    }
}

impl<E> From<ExecutionOutputAttemptError> for ExecutionOutputSealError<E> {
    fn from(error: ExecutionOutputAttemptError) -> Self {
        match error {
            ExecutionOutputAttemptError::Owner(reason) => Self::Owner(reason),
            ExecutionOutputAttemptError::Deferred(reason) => Self::Deferred(reason),
            ExecutionOutputAttemptError::Storage(reason) => Self::Storage(reason),
        }
    }
}

impl<E> From<String> for ExecutionOutputSealError<E> {
    fn from(error: String) -> Self {
        Self::Owner(error)
    }
}

impl<E> From<&str> for ExecutionOutputSealError<E> {
    fn from(error: &str) -> Self {
        Self::Owner(error.to_owned())
    }
}

struct SealOwner<'owner, 'state> {
    state: &'owner mut StateBlock<'state>,
    finished: bool,
}

impl Drop for SealOwner<'_, '_> {
    fn drop(&mut self) {
        if !self.finished {
            self.state.execution_output_plan = Some(ExecutionOutputPlanState::Poisoned);
        }
    }
}

impl SealedExecutionOutputs {
    /// Rejoin the original result-bearing attachment without resealing World.
    /// The deterministic carrier tail may already have changed the World delta;
    /// this check authenticates only the immutable wire captured by execution.
    pub(in crate::state) fn verify_wire_binding(&self, block: &SignedBlock) -> Result<(), String> {
        let (wire_bytes, wire_hash) = block
            .executed_block_wire_identity()
            .map_err(|error| error.to_string())?;
        if self.proposal != block.hash()
            || wire_bytes != self.wire_bytes
            || wire_hash != self.wire_hash
        {
            return Err("execution output attachment changed after its seal".into());
        }
        Ok(())
    }
}

impl StateBlock<'_> {
    /// Bind the recorder's actual complete witness before extraction. A second
    /// capture cannot replace the first witness owned by this execution.
    pub(in crate::state) fn bind_execution_output_witness(
        &mut self,
        witness: &iroha_data_model::block::consensus::ExecWitness,
    ) -> Result<(), String> {
        if self.execution_output_plan.is_none() {
            return Ok(());
        }
        let surface = crate::state::output_publication::FinalizedPublicationSurface::capture(self)?;
        let Some(plan) = self.execution_output_plan.as_mut() else {
            return Ok(());
        };
        let ExecutionOutputPlanState::Sealed(sealed) = plan else {
            return Err("witness capture requires completed execution outputs".into());
        };
        let hash = HashOf::new(witness);
        match sealed.witness_hash {
            Some(previous) if previous != hash => {
                Err("captured execution witness changed after sealing".into())
            }
            _ => {
                if let Some(previous) = sealed.witness_surface.as_ref() {
                    if previous.as_ref() != &surface {
                        return Err("execution surface changed after witness capture".into());
                    }
                }
                sealed.witness_hash = Some(hash);
                sealed.witness_surface = Some(Box::new(surface));
                Ok(())
            }
        }
    }

    /// Check a borrowed witness against the exact original sealed execution.
    /// This grants no finality and performs no durable write or ownership transfer.
    pub(crate) fn verify_sumeragi_execution_witness(
        &self,
        block: &SignedBlock,
        witness: &iroha_data_model::block::consensus::ExecWitness,
    ) -> Result<(), String> {
        self.verify_execution_output_seal(block)?;
        let Some(ExecutionOutputPlanState::Sealed(sealed)) = self.execution_output_plan.as_ref()
        else {
            return Err("publication requires the original sealed output owner".into());
        };
        if sealed.witness_hash != Some(HashOf::new(witness)) {
            return Err("publication witness differs from the actual captured witness".into());
        }
        Ok(())
    }

    /// Authorize this exact execution of a block the Sumeragi core committed: its witness
    /// is the one sealed at execution, and Kura already holds the block with exactly this
    /// commit certificate (the durable boundary, `specs/sumeragi.md` §12.3 O3).
    pub(crate) fn authorize_sumeragi_output_publication(
        &mut self,
        block: &crate::block::CommittedBlock,
        witness: &iroha_data_model::block::consensus::ExecWitness,
        certificate: &iroha_data_model::block::CommitCertificate,
        native_execution: crate::sumeragi::executor::NativeExecutionAuthorization,
    ) -> Result<(), ExecutionAttemptError<String>> {
        self.verify_sumeragi_execution_witness(block.as_ref(), witness)?;
        self.validate_native_execution_authorization(&native_execution, block, certificate)?;
        let height = usize::try_from(block.as_ref().header().height().get())
            .ok()
            .and_then(core::num::NonZeroUsize::new)
            .ok_or("block height does not fit the store")?;
        let durable = self
            .state_ref
            .kura
            .get_block(height, &self.state_ref.ivm_execution_budget())
            .map_err(|error| error.map_rejection(|error| error.to_string()))?
            .ok_or("the committed block has not been durably stored")?;
        if durable.hash() != block.as_ref().hash()
            || durable.commit_certificate() != Some(certificate)
        {
            return Err(
                "the durable block or its certificate differs from the committed one".into(),
            );
        }
        let Some(ExecutionOutputPlanState::Sealed(sealed)) = self.execution_output_plan.take()
        else {
            unreachable!("exclusive borrow retains the checked seal")
        };
        self.execution_output_plan = Some(ExecutionOutputPlanState::Authorized(
            AuthorizedExecutionOutputs {
                sealed,
                finality_hash: HashOf::new(certificate).into(),
                native_execution,
            },
        ));
        Ok(())
    }

    /// Finalize the exact native commit authorized by `certificate`.
    pub(in crate::state) fn finalize_sumeragi_execution_outputs(
        &mut self,
        block: &crate::block::CommittedBlock,
        certificate: &iroha_data_model::block::CommitCertificate,
        prepare: impl FnOnce(
            &mut Self,
        ) -> Result<
            Vec<iroha_data_model::events::EventBox>,
            crate::state::MergeLedgerCommitError,
        >,
    ) -> Result<Vec<iroha_data_model::events::EventBox>, crate::state::MergeLedgerCommitError> {
        let finality_hash = Hash::from(HashOf::new(certificate));
        self.finalize_execution_outputs_with_finality(block, finality_hash, prepare)
    }

    fn finalize_execution_outputs_with_finality(
        &mut self,
        block: &crate::block::CommittedBlock,
        finality_hash: Hash,
        prepare: impl FnOnce(
            &mut Self,
        ) -> Result<
            Vec<iroha_data_model::events::EventBox>,
            crate::state::MergeLedgerCommitError,
        >,
    ) -> Result<Vec<iroha_data_model::events::EventBox>, crate::state::MergeLedgerCommitError> {
        let invalid = crate::state::MergeLedgerCommitError::ExecutionBatchInvalid;
        let Some(ExecutionOutputPlanState::Authorized(authorized)) = self
            .execution_output_plan
            .replace(ExecutionOutputPlanState::Finalizing)
        else {
            self.execution_output_plan = Some(ExecutionOutputPlanState::Poisoned);
            return Err(invalid(
                "execution publication lacks exact durable finality authorization".into(),
            ));
        };
        let mut owner = SealOwner {
            state: self,
            finished: false,
        };
        let state = &mut *owner.state;
        let (wire_bytes, wire_hash) = block
            .as_ref()
            .executed_block_wire_identity()
            .map_err(|error| invalid(error.to_string()))?;
        if authorized.finality_hash != finality_hash
            || authorized.sealed.proposal != block.as_ref().hash()
            || state._curr_block != block.as_ref().header()
            || wire_bytes != authorized.sealed.wire_bytes
            || wire_hash != authorized.sealed.wire_hash
            || state.world.net_state_delta().map_err(invalid)? != authorized.sealed.world_delta
        {
            return Err(invalid(
                "authorized execution changed before metadata preparation".into(),
            ));
        }
        authorized
            .sealed
            .witness_surface
            .as_ref()
            .ok_or_else(|| invalid("publication lost its captured execution surface".into()))?
            .verify(state)
            .map_err(invalid)?;
        let events = prepare(state)?;
        state
            .advance_native_execution_tip(&authorized.native_execution, block)
            .map_err(invalid)?;
        let surface = state
            .prepare_finalized_publication_surface()
            .map_err(invalid)?;
        state.execution_output_plan = Some(ExecutionOutputPlanState::Finalized(
            FinalizedExecutionOutputs {
                authorized,
                surface: Box::new(surface),
                _events_hash: crate::state::world_projection::hash_value(&events)
                    .map_err(invalid)?,
            },
        ));
        owner.finished = true;
        Ok(events)
    }

    /// Validate the retained linear owner immediately before journal publication.
    pub(in crate::state) fn verify_execution_output_publication(&self) -> Result<(), String> {
        match self.execution_output_plan.as_ref() {
            None => Ok(()),
            #[cfg(test)]
            Some(ExecutionOutputPlanState::Inspecting) => {
                Err("execution output inspection cannot authorize publication".into())
            }
            Some(ExecutionOutputPlanState::Finalized(finalized)) => {
                if finalized.authorized.sealed.proposal != self._curr_block.hash() {
                    return Err("finalized execution belongs to another carrier".into());
                }
                finalized.surface.verify(self)
            }
            _ => Err(
                "execution output owner has not completed finality and publication preparation"
                    .into(),
            ),
        }
    }

    /// Local telemetry classification belongs to the original authenticated output owner.
    /// It cannot authorize an execution or relax any source, witness or finality check.
    #[cfg(feature = "telemetry")]
    pub(in crate::state) fn committed_telemetry_origin(
        &self,
    ) -> Result<crate::sumeragi::executor::CommitTelemetryOrigin, String> {
        match self.execution_output_plan.as_ref() {
            None => Ok(crate::sumeragi::executor::CommitTelemetryOrigin::Forward),
            Some(ExecutionOutputPlanState::Finalized(finalized)) => {
                Ok(finalized.authorized.native_execution.telemetry_origin())
            }
            _ => Err("telemetry origin lacks finalized execution authority".into()),
        }
    }

    /// Run the complete execution output owner and consume its actual sources.
    /// The caller still owes source/finality and non-output resource admission.
    /// The sealed output owner does not grant commit authority by itself: the
    /// original witness, durable finality and publication surface must join it.
    #[cfg(test)]
    pub(crate) fn execute_and_seal_ordinary_outputs<E>(
        &mut self,
        block: &mut SignedBlock,
        genesis: Option<&crate::block::AuthenticatedGenesisOutputSource>,
        finalize: impl FnOnce(
            &mut Self,
            &SignedBlock,
            &[RoutingDecision],
        ) -> Result<ExecutionOutputSealMetadata, E>,
    ) -> Result<(), ExecutionOutputSealError<E>> {
        self.execute_and_seal_ordinary_outputs_with_amx(block, genesis, finalize, None)
    }

    pub(crate) fn execute_and_seal_ordinary_outputs_with_amx<E>(
        &mut self,
        block: &mut SignedBlock,
        genesis: Option<&crate::block::AuthenticatedGenesisOutputSource>,
        finalize: impl FnOnce(
            &mut Self,
            &SignedBlock,
            &[RoutingDecision],
        ) -> Result<ExecutionOutputSealMetadata, E>,
        amx_legs: Option<&mut crate::sumeragi::amx::NativeAmxLegPreparations>,
    ) -> Result<(), ExecutionOutputSealError<E>> {
        self.reserve_ordinary_execution_outputs(block)?;
        let execution = self.execute_ordinary_output_plan_with_amx(block, genesis, amx_legs);
        self.require_storage_admission()
            .map_err(ExecutionOutputSealError::Storage)?;
        execution?;
        // A rejected genesis transaction rolls back its entire batch, including
        // validator registrations. Report the actual output failure before the
        // schedule finalizer inspects that rolled-back World. Component fixtures
        // without authenticated genesis keep their ordinary output semantics.
        if genesis.is_some() {
            let rejection = match self.execution_output_plan.as_ref() {
                Some(ExecutionOutputPlanState::Retained(retained)) => {
                    crate::block::GenesisOutputRejection::first(&retained.rows)
                }
                _ => None,
            };
            if let Some(rejection) = rejection {
                self.execution_output_plan = Some(ExecutionOutputPlanState::Poisoned);
                return Err(ExecutionOutputSealError::RejectedGenesis(rejection));
            }
        }
        self.seal_execution_outputs(block, finalize)
    }

    /// Consume completed actual execution exactly once and attach all metadata.
    /// Taking or dropping the capsule never clears the publication guard. The
    /// finalizer cannot supply replacement rows, sources or policy. All its State
    /// effects precede transcript sealing and the sole checked model attachment.
    pub(crate) fn seal_execution_outputs<E>(
        &mut self,
        block: &mut SignedBlock,
        finalize: impl FnOnce(
            &mut Self,
            &SignedBlock,
            &[RoutingDecision],
        ) -> Result<ExecutionOutputSealMetadata, E>,
    ) -> Result<(), ExecutionOutputSealError<E>> {
        self.require_storage_admission()
            .map_err(ExecutionOutputSealError::Storage)?;
        let Some(ExecutionOutputPlanState::Retained(retained)) = self
            .execution_output_plan
            .replace(ExecutionOutputPlanState::Sealing)
        else {
            self.execution_output_plan = Some(ExecutionOutputPlanState::Poisoned);
            return Err("output seal requires one retained actual execution".into());
        };
        let mut owner = SealOwner {
            state: self,
            finished: false,
        };
        let state = &mut *owner.state;
        let result = (|| {
            // Reauthenticate auxiliary proposal bodies before any finalizer work;
            // equal headers and Network roots alone do not bind those bytes.
            block.validate_proposal_commitments()?;
            let input_root = MerkleTree::root_from_typed_leaves(
                block.network_entrypoints().map(TransactionEntrypoint::hash),
            )
            .map(Hash::from);
            if retained.proposal != block.hash()
                || block.header() != state._curr_block
                || retained.input_root != input_root
            {
                return Err("output seal source differs from its actual execution".into());
            }
            let sources = retained
                .sources
                .ok_or("output seal requires all actual phases")?;
            if sources.proposal() != block.hash()
                || sources.source_context().network_id != state.network_id
                || sources.source_context().height != state._curr_block.height().get()
                || sources.entries().len() != retained.rows.len()
                || sources.carrier_network_routes().len() != block.network_entrypoint_count()
            {
                return Err("output seal lost its complete actual source inventory".into());
            }
            if !state.batch_transfer_outcomes.is_empty() {
                return Err("output seal retains unowned business receipts".into());
            }
            let metadata = finalize(state, block, sources.carrier_network_routes())
                .map_err(ExecutionOutputSealError::Finalizer)?;
            if !matches!(
                state.execution_output_plan,
                Some(ExecutionOutputPlanState::Sealing)
            ) {
                return Err("output finalizer invalidated its State owner".into());
            }
            if !state.batch_transfer_outcomes.is_empty() {
                return Err("output finalizer introduced unowned business receipts".into());
            }
            let fragments = u64::try_from(state.committed_fragment_count())
                .map_err(|_| "committed fragment count exceeds u64")?;
            if fragments != metadata.committed_fragment_count {
                return Err("output finalizer did not account for every applied fragment".into());
            }
            let tx_set = iroha_data_model::nexus::axt_ordered_transaction_set_digest_v1(
                (0..block.network_entrypoint_count()).map(|index| {
                    block
                        .network_entrypoint_at(index)
                        .expect("immutable Network count and source positions agree")
                }),
            )
            .map_err(|error| error.to_string())?;
            state.set_fastpq_tx_set_hash(tx_set.into());
            let pending = state.submit_transfer_transcript_digest_batch();
            state.finalize_owned_fastpq_source_inventory_with_pending(&sources, pending)?;
            let transcripts = state.drain_transfer_transcripts_with_pending(None);
            let envelopes = state.drain_axt_envelopes();
            let policy = state.axt_policy_snapshot();
            let transitions = state.axt_authorization_transitioned().clone();
            let limits = state.frozen_output_capacity()?.policy.limits();
            let measured = retained.rows.iter().try_fold(0_u64, |total, row| {
                let bytes = norito::canonical_frame_len(row).map_err(|error| error.to_string())?;
                total
                    .checked_add(u64::try_from(bytes).map_err(|_| "row length exceeds u64")?)
                    .ok_or_else(|| "retained row bytes overflow".to_owned())
            })?;
            if measured != retained.row_bytes {
                return Err("retained rows differ from their consumed output budget".into());
            }
            // Borrow the actual World journals after every finalizer effect.
            // Encoding failure is a local ownership error before attachment.
            // Retain inclusion paths from this exact event cut before World and
            // witness capture. No carrier/QC hash enters these deterministic rows.
            let budget = state.state_ref.ivm_execution_budget();
            let height = state._curr_block.height().get();
            crate::kagemusha_wallet_v1::event_evidence::retain(&mut state.world, height, &budget)
                .map_err(|error| match error {
                crate::kagemusha_wallet_v1::event_evidence::PreparationError::Invalid(reason) => {
                    ExecutionOutputSealError::Owner(reason)
                }
                crate::kagemusha_wallet_v1::event_evidence::PreparationError::Deferred(reason) => {
                    ExecutionOutputSealError::Deferred(reason)
                }
            })?;
            state
                .require_storage_admission()
                .map_err(ExecutionOutputSealError::Storage)?;
            let world_delta = state.world.net_state_delta()?;
            block
                .set_execution_outputs(
                    retained.rows,
                    fragments,
                    transcripts,
                    envelopes,
                    policy,
                    transitions,
                    &limits,
                )
                .map_err(|error| error.to_string())?;
            let (wire_bytes, wire_hash) = block
                .executed_block_wire_identity()
                .map_err(|error| error.to_string())?;
            Ok(SealedExecutionOutputs {
                witness_hash: None,
                witness_surface: None,
                _sources: sources,
                world_delta,
                proposal: block.hash(),
                wire_hash,
                wire_bytes,
            })
        })();
        match result {
            Ok(sealed) => {
                state.execution_output_plan = Some(ExecutionOutputPlanState::Sealed(sealed));
                owner.finished = true;
                Ok(())
            }
            Err(error) => {
                state.execution_output_plan = Some(ExecutionOutputPlanState::Poisoned);
                Err(error)
            }
        }
    }

    /// Check the exact attached wire while publication is still gated. Later
    /// signatures or result changes require the eventual final publication owner;
    /// they cannot reuse this earlier attachment's binding.
    pub(crate) fn verify_execution_output_seal(&self, block: &SignedBlock) -> Result<(), String> {
        let Some(ExecutionOutputPlanState::Sealed(sealed)) = self.execution_output_plan.as_ref()
        else {
            return Err("execution outputs do not have a completed seal".into());
        };
        let limits = self.frozen_output_capacity()?.policy.limits();
        block
            .validate_execution_outputs(&limits)
            .map_err(|error| error.to_string())?;
        sealed.verify_wire_binding(block)?;
        if self._curr_block != block.header() {
            return Err("execution output attachment changed after its seal".into());
        }
        if self.world.net_state_delta()? != sealed.world_delta {
            return Err("World values changed after the execution output seal".into());
        }
        if let Some(surface) = sealed.witness_surface.as_ref() {
            surface.verify(self)?;
        }
        self.verified_fastpq_source_inventory_for_capture()?;
        Ok(())
    }
}
