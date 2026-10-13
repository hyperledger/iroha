//! Exact account-signed direct SCCP panel operations; no callback or IVM authority.

use super::StateTransaction;
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::isi::error::InstructionExecutionError as Error;
use iroha_data_model::{
    account::AccountId,
    isi::{
        InstructionBox,
        sccp::{AcceptSccpPausePanelSeatV1, EndorseSccpFastPauseV1},
    },
    transaction::{Executable, SignedTransaction, TransactionEntrypoint},
};

/// Fixed-size signed operation, with no copied account or executable graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PauseOperation {
    Accept(AcceptSccpPausePanelSeatV1),
    Endorse(EndorseSccpFastPauseV1),
}
impl PauseOperation {
    fn of(instruction: &InstructionBox) -> Option<Self> {
        instruction
            .as_any()
            .downcast_ref::<AcceptSccpPausePanelSeatV1>()
            .copied()
            .map(Self::Accept)
            .or_else(|| {
                instruction
                    .as_any()
                    .downcast_ref::<EndorseSccpFastPauseV1>()
                    .copied()
                    .map(Self::Endorse)
            })
    }
}

#[derive(Debug)]
pub(super) struct PauseSource {
    signed: HashOf<SignedTransaction>,
    entry: HashOf<TransactionEntrypoint>,
    call: Hash,
    index: u64,
    // Monotonic direct instruction index prevents rearming a consumed frame.
    next_instruction: usize,
    armed: Option<PauseOperation>,
}
impl StateTransaction<'_, '_> {
    pub(super) fn bind_sccp_pause_source(&mut self, input: &TransactionEntrypoint, index: u64) {
        self.sccp_pause_source = None;
        let signed = match input {
            TransactionEntrypoint::External(signed) => signed,
            TransactionEntrypoint::SealedReveal(reveal) => reveal.signed_transaction(),
            TransactionEntrypoint::SealedCommitment(_) => return,
        };
        if !matches!(signed.instructions(), Executable::Instructions(rows) if rows.iter().any(|row| PauseOperation::of(row).is_some()))
        {
            return;
        }
        self.sccp_pause_source = Some(PauseSource {
            signed: signed.hash(),
            entry: input.hash(),
            call: Hash::from(input.execution_call_hash()),
            index,
            next_instruction: 0,
            armed: None,
        });
    }
    pub(crate) fn arm_direct_sccp_pause(
        &mut self,
        signed: &SignedTransaction,
        authority: &AccountId,
        instruction: &InstructionBox,
        index: usize,
        direct: bool,
    ) {
        self.clear_direct_sccp_pause();
        if !direct || self.execution_callback_active() || signed.authority() != authority {
            return;
        }
        let Executable::Instructions(rows) = signed.instructions() else {
            return;
        };
        let Some(operation) = PauseOperation::of(instruction) else {
            return;
        };
        if rows.get(index).and_then(PauseOperation::of) != Some(operation) {
            return;
        }
        let Some(source) = self.sccp_pause_source.as_mut() else {
            return;
        };
        if (index < source.next_instruction && !cfg!(all(test, sumeragi_core_mutation = "HC300")))
            || source.signed != signed.hash()
            || self.current_tx_hash != Some(source.signed)
            || self.current_network_entrypoint_hash != Some(source.entry)
            || self.current_entrypoint_index != Some(source.index)
            || self.tx_call_hash != Some(source.call)
        {
            return;
        }
        let Some(next) = index.checked_add(1) else {
            return;
        };
        source.next_instruction = next;
        source.armed = Some(operation);
    }
    pub(crate) fn consume_direct_sccp_pause(
        &mut self,
        operation: PauseOperation,
    ) -> Result<(), Error> {
        let callback = self.execution_callback_active();
        let valid = self.sccp_pause_source.as_mut().is_some_and(|source| {
            source.armed.take() == Some(operation)
                && !callback
                && self.current_tx_hash == Some(source.signed)
                && self.current_network_entrypoint_hash == Some(source.entry)
                && self.current_entrypoint_index == Some(source.index)
                && self.tx_call_hash == Some(source.call)
        });
        if valid {
            Ok(())
        } else {
            Err(Error::InvariantViolation(
                "SCCP panel operation requires its exact account-signed direct instruction".into(),
            ))
        }
    }
    pub(crate) fn clear_direct_sccp_pause(&mut self) {
        if let Some(source) = &mut self.sccp_pause_source {
            source.armed = None;
        }
    }
}
