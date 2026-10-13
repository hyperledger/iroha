//! Pure native payment projection without source authentication.
//! The caller authenticates the exact header/input/output before treating the returned DTO as evidence.

use super::{
    AtomicSettlementDetails, SettleAtomic, SettlementDetails, SettlementInstructionBox,
    SettlementReceipt,
};
use crate::{
    NetworkId,
    block::BlockHeader,
    transaction::{Executable, FeeChargeKind, TransactionEntrypoint, TransactionResult},
};

/// A structural or semantic mismatch in unverified native payment source material.
#[derive(Debug, thiserror::Error)]
pub enum AtomicPaymentProjectionError {
    /// Network identity differs from the independently selected payment intent.
    #[error("payment source differs from the expected network")]
    NetworkMismatch,
    /// Native execution did not succeed.
    #[error("payment execution did not succeed")]
    RejectedExecution,
    /// The source must contain exactly one direct native atomic instruction.
    #[error("payment source requires one direct SettleAtomic instruction")]
    UnsupportedCarrier,
    /// Complete signed terms differ from the independently retained request.
    #[error("payment source differs from the expected complete intent")]
    IntentMismatch,
    /// The expected intent contains invalid movement or owner semantics.
    #[error("invalid expected payment intent: {0}")]
    InvalidIntent(&'static str),
    /// `PipelineGas` lacks a supported typed authenticated outcome.
    #[error("payment projection does not support PipelineGas charges")]
    UnsupportedFeeOutcome,
    /// The Nexus charge does not bind the original signed source and height.
    #[error("invalid native Nexus fee outcome: {0}")]
    InvalidFeeOutcome(String),
    /// Canonical intent encoding failed.
    #[error("payment intent encoding failed: {0}")]
    IntentEncoding(#[from] norito::Error),
}

/// Project complete successful native terms without authenticating the supplied source.
///
/// This pure function grants no finality, signature, inclusion, root-scope or current-State
/// authority. Decoded arguments and the returned ordinary receipt remain unverified data.
/// The SDK must first verify exact committed execution with its genesis-rooted verifier;
/// the node must retain its canonical authenticated carrier and recheck its State binding.
/// A caller authorizing fees additionally binds the carrier's exact signed fee intent.
///
/// # Errors
/// Refuses unsuccessful execution, foreign network/terms, composite or contract carriers,
/// unsupported fee kinds and inconsistent Nexus fee outcomes.
pub fn project_atomic_payment_receipt_unverified(
    expected_network: NetworkId,
    expected_intent: &SettleAtomic,
    header: &BlockHeader,
    entrypoint: &TransactionEntrypoint,
    result: &TransactionResult,
) -> Result<SettlementReceipt, AtomicPaymentProjectionError> {
    use AtomicPaymentProjectionError as Error;
    if expected_intent.network_id != expected_network {
        return Err(Error::NetworkMismatch);
    }
    expected_intent.validate().map_err(Error::InvalidIntent)?;
    if result.as_ref().is_err() {
        return Err(Error::RejectedExecution);
    }
    let TransactionEntrypoint::External(transaction) = entrypoint else {
        return Err(Error::UnsupportedCarrier);
    };
    if transaction.network_id() != Some(&expected_network) {
        return Err(Error::NetworkMismatch);
    }
    let Executable::Instructions(instructions) = transaction.instructions() else {
        return Err(Error::UnsupportedCarrier);
    };
    let [instruction] = instructions.as_ref() else {
        return Err(Error::UnsupportedCarrier);
    };
    let instruction = instruction.as_any();
    let actual = instruction
        .downcast_ref::<SettleAtomic>()
        .or_else(
            || match instruction.downcast_ref::<SettlementInstructionBox>() {
                Some(SettlementInstructionBox::Atomic(intent)) => Some(intent),
                _ => None,
            },
        )
        .ok_or(Error::UnsupportedCarrier)?;
    if actual != expected_intent {
        return Err(Error::IntentMismatch);
    }
    if transaction
        .fee_payment_intent()
        .charge_limits()
        .iter()
        .any(|limit| limit.kind == FeeChargeKind::PipelineGas)
    {
        return Err(Error::UnsupportedFeeOutcome);
    }
    if let Some(fee) = result.nexus_fee_receipt() {
        fee.validate_for_network_input(entrypoint, header.height().get())
            .map_err(Error::InvalidFeeOutcome)?;
    }
    Ok(SettlementReceipt {
        authority: transaction.authority().clone(),
        metadata: actual.metadata.clone(),
        block_height: header.height().get(),
        block_hash: header.hash(),
        executed_at_ms: header.creation_time_ms,
        details: SettlementDetails::Atomic(AtomicSettlementDetails {
            movements: actual.movements.resolve().map_err(Error::InvalidIntent)?,
            intent_hash: actual.intent_hash()?,
        }),
    })
}

#[cfg(test)]
mod tests;
