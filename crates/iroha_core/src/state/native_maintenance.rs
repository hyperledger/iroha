//! Original retail and Time-phase SNS owners share one finite disposable quota.

use super::{Hash, StateBlock, StateTransaction, output_capacity::ExecutionOutputPlanState};

/// Original Time preparation scope; only the borrowing State output owner issues it.
pub(crate) struct NativeMaintenanceTimeScope {
    network: iroha_data_model::NetworkId,
    proposal: iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>,
    remaining_entries: usize,
}

impl NativeMaintenanceTimeScope {
    /// Remaining original native E at this sole Time-owner issuance.
    pub(crate) fn invocation_limit(&self) -> usize {
        self.remaining_entries
    }

    pub(crate) fn authenticate(
        &self,
        transaction: &StateTransaction<'_, '_>,
    ) -> Result<(), String> {
        transaction.validate_native_maintenance_scope()?;
        if self.network != transaction.network_id || self.proposal != transaction._curr_block.hash()
        {
            return Err("native Time source belongs to a foreign proposal".into());
        }
        Ok(())
    }
}

impl StateBlock<'_> {
    pub(super) fn native_maintenance_time_scope(
        &self,
    ) -> Result<NativeMaintenanceTimeScope, String> {
        if !matches!(
            self.execution_output_plan,
            Some(ExecutionOutputPlanState::Running)
        ) {
            return Err("native maintenance requires its original Time output owner".into());
        }
        let quota = self
            .fastpq_source_quota
            .as_ref()
            .ok_or("native Time source quota was not captured")?
            .as_ref()
            .map_err(Clone::clone)?;
        let total = u64::from(
            self.fastpq_source_policy_at_block_start()
                .0
                .max_native_maintenance_invocations,
        );
        let remaining = total
            .checked_sub(quota.native_usage().executed_entries)
            .ok_or("native Time source usage exceeds its frozen reservation")?;
        Ok(NativeMaintenanceTimeScope {
            network: self.network_id,
            proposal: self._curr_block.hash(),
            remaining_entries: usize::try_from(
                if cfg!(all(test, sumeragi_core_mutation = "HC367")) {
                    total
                } else {
                    remaining
                },
            )
            .map_err(|_| "native Time source count exceeds host width")?,
        })
    }

    #[cfg(test)]
    pub(crate) fn native_maintenance_usage_for_testing(
        &self,
    ) -> crate::fastpq::source_reservation::SourceUsage {
        self.fastpq_source_quota
            .as_ref()
            .expect("source quota captured")
            .as_ref()
            .expect("source quota admitted")
            .native_usage()
    }

    /// Consume the original complete seal for SNS source-inspection controls.
    /// Mandatory quantity custody is retained by the genuine producer before
    /// inspection. Every exit poisons this disposable owner; neither the caller's
    /// proposal nor this boundary gains witness capture or publication authority.
    #[cfg(test)]
    pub(crate) fn finalize_sns_owned_sources_for_testing(
        &mut self,
        source: &iroha_data_model::block::SignedBlock,
    ) -> Result<(), String> {
        struct SnsSourceInspectionOwner<'owner, 'state> {
            state: &'owner mut StateBlock<'state>,
        }
        impl Drop for SnsSourceInspectionOwner<'_, '_> {
            fn drop(&mut self) {
                self.state.execution_output_plan = Some(ExecutionOutputPlanState::Poisoned);
            }
        }

        let owner = SnsSourceInspectionOwner { state: self };
        let mut inspected = source.clone();
        owner
            .state
            .seal_execution_outputs(&mut inspected, |state, original, routes| {
                if original.network_entrypoint_count() != 0 || !routes.is_empty() {
                    return Err("SNS inspection requires its empty Network producer".to_owned());
                }
                Ok::<_, String>(super::output_capacity::ExecutionOutputSealMetadata {
                    sccp_finality_header:
                        iroha_data_model::sumeragi_finality::SccpFinalityHeaderV1::inactive(
                            *state.network_id.as_bytes(),
                            original.header().height().get(),
                            original.header().creation_time_ms,
                        )
                        .map_err(|error| error.to_string())?,
                    committed_fragment_count: u64::try_from(state.committed_fragment_count())
                        .map_err(|_| "SNS fragment count exceeds u64".to_owned())?,
                })
            })
            .map_err(|error| format!("SNS original source seal refused: {error:?}"))
    }
}

impl StateTransaction<'_, '_> {
    /// Require the actual applying Time-phase scope, never a synthetic transaction call.
    pub(crate) fn validate_native_maintenance_scope(&self) -> Result<(), String> {
        if !matches!(
            self.block_execution_output_plan.as_ref(),
            Some(ExecutionOutputPlanState::Running)
        ) || self.tx_call_hash.is_some()
            || self.current_entrypoint_index.is_some()
            || self.current_lane_id.is_some()
            || self
                .current_dataspace_id
                .is_some_and(|id| id != iroha_model_base::topology::DataSpaceId::UNIVERSAL)
            || self.fastpq_source_context.source.network_id != self.network_id
            || self.fastpq_source_context.source.height != self._curr_block.height().get()
        {
            return Err("SNS native source requires its original applying Time scope".into());
        }
        Ok(())
    }

    pub(crate) fn native_maintenance_binding_limit(&self) -> u64 {
        self.fastpq_source_policy
            .0
            .intrinsic
            .max_input_transcript_bytes
    }

    /// Consume the sweep's original record permit after the charge rereads its exact quote.
    /// Authorization alone retains no source entry; its actual nonempty transcript opens E.
    pub(crate) fn authorize_sns_native_source(
        &mut self,
        permit: crate::sns::SnsNativeMaintenancePermit,
        hash: Hash,
    ) -> Result<(), crate::sns::SnsError> {
        let result = permit.authenticate(self).and_then(|()| {
            self.fastpq_source_quota
                .authorize_native_purpose(hash)
                .map_err(crate::sns::SnsError::Internal)
        });
        if let Err(error) = &result {
            self.fastpq_source_quota.fail_preparation(error.to_string());
            *self.block_execution_output_plan = Some(ExecutionOutputPlanState::Poisoned);
        }
        result
    }
}

/// Original block-start identity retained across a single retail batch preparation.
/// Public proposal coordinates alone cannot recreate this source-context allocation.
pub(crate) struct RetailMaintenanceSource {
    transaction: crate::fastpq::source_reservation::SourceTransactionIdentity,
    context: std::sync::Arc<crate::fastpq::FastpqBlockStartSourceContext>,
    fragment: usize,
    proposal: iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>,
}

impl RetailMaintenanceSource {
    pub(crate) fn authenticate(
        &self,
        transaction: &StateTransaction<'_, '_>,
    ) -> Result<(), String> {
        transaction.validate_retail_maintenance_scope()?;
        if !transaction
            .fastpq_source_quota
            .matches_native_identity(&self.transaction)
            || !std::sync::Arc::ptr_eq(&self.context, &transaction.fastpq_source_context)
            || self.fragment != *transaction.committed_fragments
            || self.proposal != transaction._curr_block.hash()
        {
            return Err("retail maintenance belongs to a foreign original State source".into());
        }
        Ok(())
    }
}

impl StateTransaction<'_, '_> {
    /// Require original block-start maintenance before the ordinary output owner exists.
    fn validate_retail_maintenance_scope(&self) -> Result<(), String> {
        if self.block_execution_output_plan.is_some()
            || self.tx_call_hash.is_some()
            || self.current_entrypoint_index.is_some()
            || self.current_lane_id.is_some()
            || self.current_dataspace_id.is_some()
            || self.original_fastpq_invocation_source.is_some()
            || self.fastpq_source_context.source.network_id != self.network_id
            || self.fastpq_source_context.source.height != self._curr_block.height().get()
        {
            return Err("retail maintenance requires its original block-start State owner".into());
        }
        Ok(())
    }

    /// Retain the actual source allocation; this identity grants no source entry by itself.
    pub(crate) fn retain_retail_maintenance_source(
        &self,
    ) -> Result<RetailMaintenanceSource, String> {
        self.validate_retail_maintenance_scope()?;
        Ok(RetailMaintenanceSource {
            transaction: self.fastpq_source_quota.retain_native_identity()?,
            context: std::sync::Arc::clone(&self.fastpq_source_context),
            fragment: *self.committed_fragments,
            proposal: self._curr_block.hash(),
        })
    }

    /// Fair retail share of the unchanged finite native pool, less already retained E.
    /// The odd slot alternates by certified height; a one-entry policy serves both owners.
    pub(crate) fn retail_maintenance_entry_allowance(&self) -> Result<u64, String> {
        let total = u64::from(
            self.fastpq_source_policy
                .0
                .max_native_maintenance_invocations,
        );
        let share = total / 2
            + if self.block_height().is_multiple_of(2) {
                total % 2
            } else {
                0
            };
        let used = self.fastpq_source_quota.native_entries_in_use()?;
        let remaining = total
            .checked_sub(used)
            .ok_or("native source usage exceeds its frozen reservation")?;
        Ok(share.saturating_sub(used).min(remaining))
    }
}

impl StateTransaction<'_, '_> {
    /// Publish the selected retail State, source quota and witness as one checked attempt.
    /// The existing witness overlay drops on every preflight failure or unwind.
    pub(crate) fn apply_retail_maintenance(
        mut self,
        witness: crate::exec_witness::ExecWitnessOverlay,
    ) -> Result<(), String> {
        self.validate_retail_maintenance_scope()?;
        self.prepare_apply().map_err(str::to_owned)?;
        self.apply_prepared();
        witness.commit();
        Ok(())
    }
}

impl StateTransaction<'_, '_> {
    /// Commit one genuine SNS renewal and its source/witness together after all checks.
    pub(crate) fn apply_sns_maintenance(
        mut self,
        witness: crate::exec_witness::ExecWitnessOverlay,
    ) -> Result<(), String> {
        if let Err(error) = self.validate_native_maintenance_scope() {
            *self.block_execution_output_plan = Some(ExecutionOutputPlanState::Poisoned);
            return Err(error);
        }
        self.prepare_apply().map_err(str::to_owned)?;
        self.apply_prepared();
        witness.commit();
        Ok(())
    }
}
