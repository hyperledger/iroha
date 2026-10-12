// The common metadata finalizer runs inside State's consuming output seal.
// It cannot supply output rows, receipt owners or callback completion projections.

impl ValidBlock {
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn finalize_owned_execution_metadata(
        block: &SignedBlock,
        state: &mut StateBlock<'_>,
        routes: &[crate::queue::RoutingDecision],
        advertised_fragments: Option<u64>,
        advertised_policy: Option<&AxtPolicySnapshot>,
        advertised_transitions: Option<&BTreeSet<DataSpaceId>>,
        sccp_height: crate::smartcontracts::isi::sccp::height::SccpHeightSourceV1,
    ) -> Result<crate::state::ExecutionOutputSealMetadata, BlockValidationError> {
        Self::finalize_common_execution_metadata(
            block,
            state,
            routes,
            advertised_policy,
            advertised_transitions,
        )?;
        // Monetary fees have already executed as signed scoped asset effects.
        // Native output metadata has no synthetic conversion or relay receipt owner.
        let root_scope = if block.header().is_genesis() {
            iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(block)
                .map_err(|error| {
                    match crate::execution_attempt::genesis_read_attempt_error(error, |error| {
                        Self::execution_context_error(error.to_string())
                    }) {
                        crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
                        crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                            BlockValidationError::ExecutionDeferred(reason)
                        }
                    }
                })?
                .sumeragi_context
                .root_scope
        } else {
            state
                .native_execution_tip()
                .ok_or_else(|| {
                    Self::execution_context_error(
                        "SCCP finalization lacks its authenticated parent root scope",
                    )
                })?
                .root_scope()
        };
        // SCCP commitments and history are World writes of this block after all of its
        // transactions (`specs/sccp.md` §4.5), with the authenticated consensus inputs of its
        // height.
        let sccp_inputs_owner = Self::sccp_height_inputs(block, state, sccp_height);
        // This owner retains the original funded schedule across every mutable hook path.
        // Projection borrows the same immutable graph; no committee is copied or reacquired.
        let sccp_inputs = match sccp_inputs_owner.as_ref().map(|original| original.inputs()) {
            Some(Ok(inputs)) => Some(inputs),
            Some(Err(error)) => {
                iroha_logger::warn!(%error, "SCCP: original height projection failed closed");
                None
            }
            None => None,
        };
        let sccp_finality_header = crate::smartcontracts::isi::sccp::hook::finalize_block(
            state,
            &block.header(),
            sccp_inputs.as_ref(),
            root_scope,
        )?;
        let committed_fragment_count =
            Self::validated_committed_fragment_count(state, advertised_fragments)?;
        Ok(crate::state::ExecutionOutputSealMetadata {
            committed_fragment_count,
            sccp_finality_header,
        })
    }

    /// Derive the consensus inputs of the height `state` executes for the SCCP post-execution
    /// hook (`specs/sccp.md` §4.5, §4.6), or `None` when SCCP does not exist or the inputs
    /// cannot be derived (SCCP then fails closed; block execution is unaffected).
    ///
    /// Read the authenticated native schedule after the output-seal finalizer advanced it.
    /// Unauthenticated component executions never infer committee authority from their writes.
    fn sccp_height_inputs(
        block: &SignedBlock,
        state: &StateBlock<'_>,
        source: crate::smartcontracts::isi::sccp::height::SccpHeightSourceV1,
    ) -> Option<crate::smartcontracts::isi::sccp::height::RetainedSccpHeightInputsV1> {
        use crate::smartcontracts::isi::sccp::height::{
            RetainedSccpHeightInputsV1, SccpHeightSourceV1,
        };
        if !crate::smartcontracts::isi::sccp::params::exists(&state.world) {
            return None;
        }
        match source {
            SccpHeightSourceV1::SumeragiSchedule {
                genesis_height,
                mode,
                root_scope: iroha_data_model::block::consensus::SumeragiRootScope::Global,
            } => RetainedSccpHeightInputsV1::from_sumeragi_schedule(
                &state.world,
                block.header().height().get(),
                genesis_height,
                mode,
            )
            .map_err(|error| {
                iroha_logger::warn!(
                    %error,
                    "SCCP: the scheduled height inputs are unavailable; SCCP fails closed"
                );
            })
            .ok(),
            SccpHeightSourceV1::Unauthenticated | SccpHeightSourceV1::SumeragiSchedule { .. } => {
                None
            }
        }
    }

    /// Native G execution settles fee transfers directly under signed charge limits.
    /// A receipt-only debit cannot authorize a real XOR reserve change or finality.
    fn validate_native_fee_settlement_mode(
        state: &StateBlock<'_>,
    ) -> Result<(), BlockValidationError> {
        if state.nexus.fees.settlement_mode
            != iroha_config::parameters::actual::NexusFeeSettlementMode::Direct
        {
            return Err(Self::execution_context_error(
                "retired lane-relay-burn fee settlement is not admitted by native execution",
            ));
        }
        Ok(())
    }

    /// Shared deterministic metadata runs after actual Network/Pipeline/Time
    /// execution and before the one output seal captures its final World delta.
    fn finalize_common_execution_metadata(
        block: &SignedBlock,
        state: &mut StateBlock<'_>,
        routes: &[crate::queue::RoutingDecision],
        advertised_policy: Option<&AxtPolicySnapshot>,
        advertised_transitions: Option<&BTreeSet<DataSpaceId>>,
    ) -> Result<(), BlockValidationError> {
        Self::validate_native_fee_settlement_mode(state)?;
        if routes.len() != block.network_entrypoint_count() {
            return Err(Self::execution_context_error(
                "settlement lost its complete frozen Network routes",
            ));
        }
        let pruned = crate::tx::prune_expired_sealed_commitments(state);
        if pruned != 0 {
            iroha_logger::debug!(
                count = pruned,
                "pruned expired sealed transaction commitments"
            );
        }
        state.finalize_axt_asset_incarnations().map_err(|error| {
            Self::execution_context_error(format!(
                "failed to finalize AXT asset incarnations: {error}"
            ))
        })?;
        state
            .finalize_axt_policy_transition_ratchets()
            .map_err(|error| {
                Self::execution_context_error(format!(
                    "failed to finalize the AXT policy counter ratchet: {error}"
                ))
            })?;
        let policy = state.axt_policy_snapshot();
        Self::validate_advertised_axt_post_state(advertised_policy, &policy)?;
        Self::validate_advertised_axt_transitions(
            advertised_transitions,
            state.axt_authorization_transitioned(),
            policy.version,
        )?;
        Ok(())
    }
}
