//! Original Time-phase SNS source admission into its disjoint disposable quota.

use super::{Hash, StateBlock, StateTransaction, output_capacity::ExecutionOutputPlanState};

/// Original Time preparation scope; only the borrowing State output owner issues it.
pub(crate) struct NativeMaintenanceTimeScope {
    network: iroha_data_model::NetworkId,
    proposal: iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>,
}

impl NativeMaintenanceTimeScope {
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
        Ok(NativeMaintenanceTimeScope {
            network: self.network_id,
            proposal: self._curr_block.hash(),
        })
    }
    pub(crate) fn native_maintenance_invocation_limit(&self) -> usize {
        self.fastpq_source_policy_at_block_start()
            .0
            .max_native_maintenance_invocations as usize
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
                sccp_finality_header: iroha_data_model::sumeragi_finality::certified_result::SccpFinalityHeaderV1::inactive(
                    *state.network_id.as_bytes(), state._curr_block.height().get(), state._curr_block.creation_time_ms,
                ).expect("original component carrier"),
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
