//! One-shot native forgery execution tied to the original signed Network source.
//!
//! The output producer captures fixed-size source DATA. Only the executor's exact direct
//! instruction frame can consume it; source capture alone authenticates no evidence.

use super::StateTransaction;
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    account::AccountId,
    isi::{InstructionBox, error::InstructionExecutionError, sccp::SubmitSccpForgeryEvidenceV1},
    transaction::{Executable, SignedTransaction, TransactionEntrypoint},
};

/// Fixed-size original source, without a second account graph or evidence allocation.
#[derive(Debug)]
pub(super) struct SccpForgeryEntrypointBinding {
    // None denotes the canonical standalone shared Keepalive source.
    evidence: Option<SubmitSccpForgeryEvidenceV1>,
    signed_hash: HashOf<SignedTransaction>,
    entrypoint_hash: HashOf<TransactionEntrypoint>,
    call_hash: Hash,
    index: u64,
}

impl StateTransaction<'_, '_> {
    /// Capture the actual output producer's signed source, including a sealed reveal.
    /// This is DATA only; the original admission and direct execution frame remain required.
    pub(super) fn bind_sccp_forgery_source(&mut self, input: &TransactionEntrypoint, index: u64) {
        self.sccp_forgery_entrypoint_binding = None;
        self.current_direct_sccp_forgery = false;
        let signed = match input {
            TransactionEntrypoint::External(signed) => signed,
            TransactionEntrypoint::SealedReveal(reveal) => reveal.signed_transaction(),
            TransactionEntrypoint::SealedCommitment(_) => return,
        };
        let Executable::Instructions(instructions) = signed.instructions() else {
            return;
        };
        let [only] = instructions.as_ref() else {
            return;
        };
        let evidence = only.as_any().downcast_ref::<SubmitSccpForgeryEvidenceV1>();
        if evidence.is_none()
            && !crate::smartcontracts::isi::sccp::keepalive::valid_shape(signed.payload())
        {
            return;
        }
        self.sccp_forgery_entrypoint_binding = Some(SccpForgeryEntrypointBinding {
            evidence: evidence.cloned(),
            signed_hash: signed.hash(),
            entrypoint_hash: input.hash(),
            call_hash: Hash::from(input.execution_call_hash()),
            index,
        });
    }

    /// Arm only the exact single signed instruction in a direct native executor frame.
    /// No callback, contract, batch, altered instruction or substituted signed body qualifies.
    pub(crate) fn arm_direct_sccp_forgery(
        &mut self,
        signed: &SignedTransaction,
        authority: &AccountId,
        instruction: &InstructionBox,
        index: usize,
        direct: bool,
    ) {
        self.current_direct_sccp_forgery = direct
            && index == 0
            && !self.execution_callback_active()
            && signed.authority() == authority
            && self
                .sccp_forgery_entrypoint_binding
                .as_ref()
                .is_some_and(|binding| {
                    binding.signed_hash == signed.hash()
                        && self.current_tx_hash == Some(binding.signed_hash)
                        && self.current_network_entrypoint_hash == Some(binding.entrypoint_hash)
                        && self.current_entrypoint_index == Some(binding.index)
                        && self.tx_call_hash == Some(binding.call_hash)
                        && match &binding.evidence {
                            Some(evidence) => {
                                instruction
                                    .as_any()
                                    .downcast_ref::<SubmitSccpForgeryEvidenceV1>()
                                    == Some(evidence)
                            }
                            None => {
                                instruction
                                    .as_any()
                                    .is::<iroha_data_model::isi::chain::Keepalive>()
                                    && crate::smartcontracts::isi::sccp::keepalive::valid_shape(
                                        signed.payload(),
                                    )
                            }
                        }
                });
    }

    /// Consume the exact direct source before the handler performs its first possible write.
    /// Rejected attempts consume the ticket too, preventing caught-error replay in the overlay.
    pub(crate) fn consume_direct_sccp_forgery(
        &mut self,
        evidence: &SubmitSccpForgeryEvidenceV1,
    ) -> Result<(), InstructionExecutionError> {
        let direct = std::mem::take(&mut self.current_direct_sccp_forgery);
        let binding = self.sccp_forgery_entrypoint_binding.take();
        if direct
            && !self.execution_callback_active()
            && binding.is_some_and(|binding| {
                binding.evidence.as_ref() == Some(evidence)
                    && self.current_tx_hash == Some(binding.signed_hash)
                    && self.current_network_entrypoint_hash == Some(binding.entrypoint_hash)
                    && self.current_entrypoint_index == Some(binding.index)
                    && self.tx_call_hash == Some(binding.call_hash)
            })
        {
            Ok(())
        } else {
            Err(InstructionExecutionError::InvariantViolation(
                "SCCP forgery requires its exact single signed direct instruction".into(),
            ))
        }
    }

    /// Consume a standalone Keepalive's original one-shot direct signed-source binding.
    pub(crate) fn consume_direct_keepalive(&mut self) -> Result<(), InstructionExecutionError> {
        let direct = std::mem::take(&mut self.current_direct_sccp_forgery);
        let binding = self.sccp_forgery_entrypoint_binding.take();
        if direct
            && !self.execution_callback_active()
            && binding.is_some_and(|binding| {
                binding.evidence.is_none()
                    && self.current_tx_hash == Some(binding.signed_hash)
                    && self.current_network_entrypoint_hash == Some(binding.entrypoint_hash)
                    && self.current_entrypoint_index == Some(binding.index)
                    && self.tx_call_hash == Some(binding.call_hash)
            })
        {
            Ok(())
        } else {
            Err(InstructionExecutionError::InvariantViolation(
                "Keepalive requires its exact single signed direct instruction".into(),
            ))
        }
    }

    /// Remove signed-body authority before later callbacks or reuse of the transaction view.
    pub(crate) fn clear_sccp_forgery_source(&mut self) {
        self.sccp_forgery_entrypoint_binding = None;
        self.current_direct_sccp_forgery = false;
    }
}

#[cfg(test)]
mod tests;
