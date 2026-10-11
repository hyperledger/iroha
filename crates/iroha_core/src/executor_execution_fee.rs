//! Execution-owned fee basis retained across business rollback.
//!
//! The direct body supplies its actual instruction count and VM/ISI gas. The
//! record closes before Data callbacks; their completed work remains separately
//! accountable to the block. Rejection settlement never executes that work again.

use super::*;

/// How the Nexus fee applies to one admitted signed body.
#[derive(core::fmt::Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecutionFeeExemption {
    /// The ordinary fee applies whether the body succeeds or fails.
    Charged,
    /// No fee applies, whether the body succeeds or fails: the initial genesis bootstrap and
    /// the protocol and successful-claim exemptions.
    Exempt,
    /// No fee applies when the body succeeds. When it fails, the ordinary Nexus fee is charged
    /// within the signed fee intent, when that intent covers it and the payer can pay it;
    /// otherwise the failure is uncharged and keeps its own rejection reason. SCCP exemptions
    /// work this way (`specs/sccp.md` §4.19).
    ExemptOnSuccess,
}

impl ExecutionFeeExemption {
    /// Return whether a successful body skips the fee.
    pub(crate) const fn skips_fee_on_success(self) -> bool {
        !matches!(self, Self::Charged)
    }

    /// Return whether a failed body with actual work owes a rejection fee.
    pub(crate) const fn charges_on_failure(self) -> bool {
        !matches!(self, Self::Exempt)
    }
}

/// Private meter for one admitted signed execution, never caller-supplied costs.
pub(crate) struct ExecutionFeeMeter {
    source: iroha_crypto::HashOf<SignedTransaction>,
    proposal: iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>,
    network: iroha_data_model::NetworkId,
    lane: Option<iroha_model_base::topology::LaneId>,
    dataspace: Option<DataSpaceId>,
    index: Option<u64>,
    gas_policy: iroha_config::parameters::actual::Gas,
    nexus_fees: iroha_config::parameters::actual::NexusFees,
    tx_bytes_len: usize,
    exemption: ExecutionFeeExemption,
    work: Option<ExecutionFeeWork>,
    closed: bool,
}

struct ExecutionFeeWork {
    instructions: usize,
    gas: u64,
}

/// Consuming fee authority from an actual admitted and attempted signed body.
/// It carries no business effects and cannot be cloned or built from a result.
pub(crate) struct ExecutionFeeSettlement {
    meter: ExecutionFeeMeter,
}

/// Distinguish a broken local owner from a legitimate fee-charge rejection.
pub(crate) enum ExecutionFeeSettlementError {
    /// Retained authority cannot be applied to the supplied fresh overlay.
    Owner(String),
    /// The authenticated charge could not be applied; its overlay must roll back.
    Charge(ValidationFail),
}

impl StateTransaction<'_, '_> {
    /// Freeze the exact admitted fee policy before any signed body effects.
    pub(crate) fn begin_execution_fee_meter(
        &mut self,
        transaction: &SignedTransaction,
        tx_bytes_len: usize,
        exemption: ExecutionFeeExemption,
    ) -> Result<(), ValidationFail> {
        if self.execution_fee_meter.is_some() {
            return Err(ValidationFail::InternalError(
                "signed execution already owns a fee meter".into(),
            ));
        }
        self.execution_fee_meter = Some(ExecutionFeeMeter {
            source: transaction.hash(),
            proposal: self._curr_block.hash(),
            network: self.network_id,
            lane: self.current_lane_id,
            dataspace: self.current_dataspace_id,
            index: self.current_entrypoint_index,
            gas_policy: self.pipeline.gas.clone(),
            nexus_fees: self.nexus.fees.clone(),
            tx_bytes_len,
            exemption,
            work: None,
            closed: false,
        });
        Ok(())
    }

    /// Record the actual authored/replayed instruction set when execution starts.
    pub(crate) fn record_execution_fee_instructions(
        &mut self,
        count: usize,
        gas: u64,
    ) -> Result<(), ValidationFail> {
        let Some(meter) = self.execution_fee_meter.as_mut() else {
            return Ok(());
        };
        if meter.closed {
            return Ok(());
        }
        if meter.work.is_some() {
            return Err(ValidationFail::InternalError(
                "direct instruction fee work was recorded twice".into(),
            ));
        }
        meter.work = Some(ExecutionFeeWork {
            instructions: count,
            gas,
        });
        Ok(())
    }

    /// Retain actual completed VM work, including a guest or artifact failure.
    /// Batch calls add to the already metered authored instruction set. A closed
    /// root never adopts later callback work as another direct-body fee basis.
    pub(crate) fn record_execution_fee_vm_work(&mut self, gas: u64) -> Result<(), ValidationFail> {
        let Some(meter) = self.execution_fee_meter.as_mut() else {
            return Ok(());
        };
        if meter.closed {
            return Ok(());
        }
        let work = meter.work.get_or_insert(ExecutionFeeWork {
            instructions: 0,
            gas: 0,
        });
        work.gas = work.gas.checked_add(gas).ok_or_else(|| {
            ValidationFail::InternalError("direct VM fee work overflows u64".into())
        })?;
        Ok(())
    }

    /// Finish the root meter before later callback traversal can alter its costs.
    pub(crate) fn close_execution_fee_meter(&mut self) {
        if let Some(meter) = self.execution_fee_meter.as_mut() {
            meter.closed = true;
        }
    }

    /// Transfer the sole fee record before dropping the failed business overlay.
    /// Admission-only failures and always-exempt roots have no chargeable record; a root
    /// exempt on success only (SCCP) keeps its record (`specs/sccp.md` §4.19).
    pub(crate) fn take_execution_fee_settlement(
        &mut self,
    ) -> Result<Option<ExecutionFeeSettlement>, String> {
        let Some(meter) = self.execution_fee_meter.take() else {
            return Ok(None);
        };
        if !meter.closed {
            return Err("execution fee meter was not closed by its actual root".into());
        }
        Ok(
            (meter.work.is_some() && meter.exemption.charges_on_failure())
                .then_some(ExecutionFeeSettlement { meter }),
        )
    }
}

impl ExecutionFeeSettlement {
    /// Charge the retained direct-body basis in its exact fresh fee-only overlay.
    /// Work was already counted by the failed execution owner. Charging its price
    /// must not reserve or count that gas a second time against the block ceiling.
    pub(crate) fn settle(
        self,
        state: &mut StateTransaction<'_, '_>,
        transaction: &SignedTransaction,
    ) -> Result<bool, ExecutionFeeSettlementError> {
        let meter = self.meter;
        if meter.source != transaction.hash()
            || meter.proposal != state._curr_block.hash()
            || meter.network != state.network_id
            || meter.lane != state.current_lane_id
            || meter.dataspace != state.current_dataspace_id
            || meter.dataspace != state.world.current_dataspace_id
            || meter.index != state.current_entrypoint_index
            || state.current_tx_hash != Some(meter.source)
            || state.tx_call_hash
                != Some(iroha_crypto::Hash::from(transaction.hash_as_entrypoint()))
            || state.last_tx_gas_used != 0
            || state.execution_fee_meter.is_some()
        {
            return Err(ExecutionFeeSettlementError::Owner(
                "rejection fee record differs from its exact fresh source overlay".into(),
            ));
        }
        let work = meter.work.ok_or_else(|| {
            ExecutionFeeSettlementError::Owner("fee settlement lost its actual direct work".into())
        })?;
        state.pipeline.gas = meter.gas_policy;
        state.nexus.fees = meter.nexus_fees;
        let on_success_only = meter.exemption == ExecutionFeeExemption::ExemptOnSuccess;
        // A root exempt on success was admitted without a fee quote, so its rejection tail
        // reserved no PipelineGas transfer: its failure is charged the Nexus fee only.
        let gas_asset = transaction
            .fee_payment_intent()
            .charge_limits()
            .iter()
            .find(|limit| limit.kind == FeeChargeKind::PipelineGas)
            .map(|limit| limit.asset_definition_id.canonical_address())
            .filter(|_| !on_success_only);
        let pipeline_charge =
            should_charge_pipeline_gas_asset(false, &state.nexus.fees, &gas_asset)
                && gas_asset.is_some()
                && work.gas != 0;
        let nexus_charge = compute_nexus_fee_amount(
            &state.nexus.fees,
            meter.tx_bytes_len,
            work.instructions,
            work.gas,
        )
        .map_err(ExecutionFeeSettlementError::Charge)?;
        if !pipeline_charge && nexus_charge.is_zero() {
            return Ok(false);
        }
        let sponsor = transaction
            .fee_payment_intent()
            .sponsor_program()
            .map(|(id, _)| id.clone());
        if should_charge_pipeline_gas_asset(false, &state.nexus.fees, &gas_asset)
            && let Some(asset) = gas_asset
        {
            Executor::charge_pipeline_gas_asset_fee(
                state,
                transaction.authority(),
                transaction,
                &asset,
                work.gas,
                sponsor.as_ref(),
            )
            .map_err(ExecutionFeeSettlementError::Charge)?;
        }
        match Executor::charge_nexus_fees(
            state,
            transaction.authority(),
            transaction,
            sponsor,
            meter.tx_bytes_len,
            work.instructions,
            work.gas,
        ) {
            Ok(()) => Ok(true),
            // A fee its signed intent does not cover, or its payer cannot pay, is not charged
            // to a root exempt on success; the failure keeps its own rejection reason and the
            // caller drops this fee-only overlay. A local deferral is never absorbed.
            Err(_) if on_success_only && state.execution_deferral().is_none() => Ok(false),
            Err(error) => Err(ExecutionFeeSettlementError::Charge(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ExecutionFeeExemption;

    #[test]
    fn exemptions_split_success_and_failure_charging() {
        use ExecutionFeeExemption::{Charged, Exempt, ExemptOnSuccess};
        assert!(!Charged.skips_fee_on_success());
        assert!(Charged.charges_on_failure());
        assert!(Exempt.skips_fee_on_success());
        assert!(!Exempt.charges_on_failure());
        assert!(ExemptOnSuccess.skips_fee_on_success());
        assert!(ExemptOnSuccess.charges_on_failure());
    }
}
