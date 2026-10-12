//! Classify an exact direct payment retry before opening its execution fee meter.

use iroha_data_model::{
    ValidationFail,
    executor::{SettlementReplayDispositionV1, SettlementReplayV1},
    isi::{SettleAtomic, SettlementDetails, SettlementInstructionBox},
    transaction::{Executable, SignedTransaction},
};

use crate::{
    execution_attempt::{ExecutionAttemptError, canonical_decode_attempt_error},
    state::{StateTransaction, WorldReadOnly},
};

/// A directly signed single payment may recover its consumed identity without paying again.
/// Composite executions and delegated carriers retain their ordinary execution/fee policy.
/// No new successful execution or successful receipt is fabricated for a duplicate carrier.
pub(crate) fn reject_committed_direct_payment(
    state: &StateTransaction<'_, '_>,
    transaction: &SignedTransaction,
) -> Result<(), ExecutionAttemptError<ValidationFail>> {
    let Executable::Instructions(instructions) = transaction.instructions() else {
        return Ok(());
    };
    let [instruction] = instructions.as_ref() else {
        return Ok(());
    };
    let instruction = instruction.as_any();
    let atomic = if let Some(atomic) = instruction.downcast_ref::<SettleAtomic>() {
        atomic
    } else if let Some(SettlementInstructionBox::Atomic(atomic)) =
        instruction.downcast_ref::<SettlementInstructionBox>()
    {
        atomic
    } else {
        return Ok(());
    };
    let [movement] = atomic.movements().as_slice() else {
        return Ok(());
    };
    if atomic.network_id() != &state.network_id
        || atomic.settlement_id().owner() != transaction.authority()
        || movement.source.account() != transaction.authority()
    {
        return Ok(());
    }
    let Some(receipt) = state
        .world
        .settlement_receipts()
        .get(atomic.settlement_id())
    else {
        return Ok(());
    };
    let intent_hash =
        norito::core::classify_decode_attempt(|| atomic.intent_hash()).map_err(|error| {
            canonical_decode_attempt_error(error, |error| {
                ValidationFail::NotPermitted(format!("invalid direct payment intent: {error}"))
            })
        })?;
    let disposition = match &receipt.details {
        SettlementDetails::Atomic(details) if details.intent_hash == intent_hash => {
            SettlementReplayDispositionV1::AlreadySettled
        }
        _ => SettlementReplayDispositionV1::ConflictingIntent,
    };
    Err(
        ValidationFail::SettlementReplay(Box::new(SettlementReplayV1 {
            settlement_id: atomic.settlement_id().clone(),
            disposition,
            committed_block_height: receipt.block_height,
            committed_block_hash: receipt.block_hash,
        }))
        .into(),
    )
}
