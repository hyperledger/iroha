//! Canonical ordered intent of a transaction and its attachment bindings.
//!
//! The ordered intent is the complete unsigned payload with every generated
//! value removed. A proof binds its digest, so the proof never hashes itself,
//! while the transaction signature covers the complete payload.

use super::{
    Executable, ExecutableBatchItem, SignedTransaction, TransactionBuilder, TransactionPayload,
    normalize_privacy_submission_for_intent_v1,
};
use crate::{
    isi::{
        InstructionBox, instruction_wire_id, privacy::SubmitPrivacyProofV1,
        registry::is_instruction_wire_id_registered,
    },
    nexus::LanePrivacyProof,
    proof::ProofAttachment,
    transaction::signed_attachments::{
        ActionInvocationBindingV1, ActionOperationV1, ActionRuleViolationV1,
        ActionStatementDigestV1, AttachmentRoleV1, OrderedIntentDigestV1, SignedAttachmentErrorV1,
        SignedAttachmentPlanV1, SignedAttachmentsV1, domain_separated_digest,
    },
};
use iroha_crypto::Hash;
use iroha_primitives::const_vec::ConstVec;
use std::collections::BTreeSet;

/// Domain separator of the ordered intent digest.
pub const ORDERED_INTENT_DIGEST_DOMAIN_V1: &[u8] = b"iroha.transaction.ordered-intent-digest.v1";

/// Remove the generated fields of one direct instruction.
///
/// A direct privacy submission embeds its proof and the digests derived from
/// the transaction intent; they are cleared exactly as the privacy intent
/// projection clears them. Every other instruction is independent.
fn normalize_instruction_for_ordered_intent_v1(instruction: &InstructionBox) -> InstructionBox {
    instruction
        .as_any()
        .downcast_ref::<SubmitPrivacyProofV1>()
        .map_or_else(
            || instruction.clone(),
            normalize_privacy_submission_for_intent_v1,
        )
}

/// Remove the generated fields of the executable.
///
/// A proved IVM executable loses its overlay and its two output commitments:
/// they are execution outputs, fixed only after the intent.
fn normalize_executable_for_ordered_intent_v1(executable: &Executable) -> Executable {
    match executable {
        Executable::Instructions(instructions) => Executable::Instructions(
            instructions
                .iter()
                .map(normalize_instruction_for_ordered_intent_v1)
                .collect::<Vec<_>>()
                .into(),
        ),
        Executable::Batch(items) => Executable::Batch(
            items
                .iter()
                .map(|item| match item {
                    ExecutableBatchItem::Instruction(instruction) => {
                        ExecutableBatchItem::Instruction(
                            normalize_instruction_for_ordered_intent_v1(instruction),
                        )
                    }
                    ExecutableBatchItem::ContractCall(call) => {
                        ExecutableBatchItem::ContractCall(call.clone())
                    }
                })
                .collect::<Vec<_>>()
                .into(),
        ),
        Executable::IvmProved(proved) => {
            let mut normalized = proved.clone();
            normalized.overlay = ConstVec::new_empty();
            normalized.events_commitment = Hash::prehashed([0; Hash::LENGTH]);
            normalized.gas_policy_commitment = Hash::prehashed([0; Hash::LENGTH]);
            Executable::IvmProved(normalized)
        }
        Executable::ContractCall(_) | Executable::Ivm(_) => executable.clone(),
    }
}

/// Resolve the direct instruction an action binds.
fn direct_instruction(
    executable: &Executable,
    instruction_index: u32,
    action_index: u32,
) -> Result<&InstructionBox, SignedAttachmentErrorV1> {
    let out_of_range = SignedAttachmentErrorV1::InvocationOutOfRange { action_index };
    let position = usize::try_from(instruction_index).map_err(|_| out_of_range.clone())?;
    match executable {
        Executable::Instructions(instructions) => instructions.get(position).ok_or(out_of_range),
        Executable::Batch(items) => match items.get(position) {
            Some(ExecutableBatchItem::Instruction(instruction)) => Ok(instruction),
            Some(ExecutableBatchItem::ContractCall(_)) => {
                Err(SignedAttachmentErrorV1::InvocationTargetMismatch { action_index })
            }
            None => Err(out_of_range),
        },
        Executable::ContractCall(_) | Executable::Ivm(_) | Executable::IvmProved(_) => {
            Err(out_of_range)
        }
    }
}

/// Check that an action's contract root names a contract invocation of the executable.
fn validate_contract_root(
    executable: &Executable,
    root_index: u32,
    action_index: u32,
) -> Result<(), SignedAttachmentErrorV1> {
    let out_of_range = SignedAttachmentErrorV1::InvocationOutOfRange { action_index };
    match executable {
        Executable::ContractCall(_) | Executable::Ivm(_) | Executable::IvmProved(_) => {
            if root_index == 0 {
                Ok(())
            } else {
                Err(out_of_range)
            }
        }
        Executable::Batch(items) => {
            let position = usize::try_from(root_index).map_err(|_| out_of_range.clone())?;
            match items.get(position) {
                Some(ExecutableBatchItem::ContractCall(_)) => Ok(()),
                Some(ExecutableBatchItem::Instruction(_)) => {
                    Err(SignedAttachmentErrorV1::InvocationTargetMismatch { action_index })
                }
                None => Err(out_of_range),
            }
        }
        Executable::Instructions(_) => Err(out_of_range),
    }
}

impl TransactionPayload {
    /// The normalized proof-free form of this payload.
    ///
    /// Every independent field is kept verbatim. Removed are: the generated
    /// fields of each direct privacy submission; the overlay and the two output
    /// commitments of a proved IVM executable; every attachment occurrence's
    /// bytes; the length and hash of every generated proof, in the occurrence
    /// and in its reference; and every action's derived statement digest.
    pub(super) fn ordered_intent_normalized_payload_v1(&self) -> Self {
        Self {
            domain: self.domain,
            authority: self.authority.clone(),
            creation_time_ms: self.creation_time_ms,
            instructions: normalize_executable_for_ordered_intent_v1(&self.instructions),
            time_to_live_ms: self.time_to_live_ms,
            nonce: self.nonce,
            fee_payment: self.fee_payment.clone(),
            metadata: self.metadata.clone(),
            attachments: self
                .attachments
                .as_ref()
                .map(SignedAttachmentsV1::normalized_for_intent_v1),
        }
    }

    /// Return the canonical ordered-intent projection bytes.
    ///
    /// This is the exact preimage of [`Self::ordered_intent_digest_v1`]: the
    /// canonical Norito frame of the normalized payload. It is a hashing
    /// preimage, not a decodable transaction payload.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical encoding fails.
    pub fn ordered_intent_projection_bytes_v1(&self) -> Result<Vec<u8>, SignedAttachmentErrorV1> {
        norito::encode_canonical(&self.ordered_intent_normalized_payload_v1())
            .map_err(|_| SignedAttachmentErrorV1::CanonicalEncodingFailed)
    }

    /// Digest of the normalized proof-free ordered intent.
    ///
    /// `BLAKE3(domain || u64le(len) || projection)`. Generated proof bytes,
    /// lengths and hashes and derived statement digests can change without
    /// changing it; every independent signed field, the order of actions and
    /// instructions, and the length and hash of admitted key material are bound.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical encoding fails.
    pub fn ordered_intent_digest_v1(
        &self,
    ) -> Result<OrderedIntentDigestV1, SignedAttachmentErrorV1> {
        let projection = self.ordered_intent_projection_bytes_v1()?;
        Ok(OrderedIntentDigestV1::new(domain_separated_digest(
            ORDERED_INTENT_DIGEST_DOMAIN_V1,
            &projection,
        )?))
    }

    /// Statement digest each declared action's proof binds, in action order.
    ///
    /// Empty for a payload without attachments.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical encoding fails.
    pub fn action_statement_digests_v1(
        &self,
    ) -> Result<Vec<ActionStatementDigestV1>, SignedAttachmentErrorV1> {
        let Some(attachments) = &self.attachments else {
            return Ok(Vec::new());
        };
        let intent_digest = self.ordered_intent_digest_v1()?;
        attachments
            .actions()
            .iter()
            .map(|action| action.statement_digest_for_v1(intent_digest))
            .collect()
    }

    /// Set every declared action's statement digest from this payload's
    /// ordered intent. A payload without attachments is left unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical encoding fails.
    pub fn bind_attachment_statements_v1(&mut self) -> Result<(), SignedAttachmentErrorV1> {
        if self.attachments.is_none() {
            return Ok(());
        }
        let intent_digest = self.ordered_intent_digest_v1()?;
        self.attachments.as_mut().map_or(Ok(()), |attachments| {
            attachments.bind_statements_v1(intent_digest)
        })
    }

    /// Replace the attachments by one transaction-level proof carrier per
    /// proof attachment, in order, bound to this payload.
    ///
    /// The payload is unchanged when an error is returned.
    ///
    /// # Errors
    ///
    /// Returns an error when no attachment is supplied, an attachment is
    /// structurally invalid or the carriers exceed a first-release bound.
    pub fn set_proof_attachments_v1(
        &mut self,
        attachments: &[ProofAttachment],
    ) -> Result<(), SignedAttachmentErrorV1> {
        let declared = SignedAttachmentPlanV1::transaction_proofs(attachments)?.declare();
        let previous = self.attachments.replace(declared);
        let outcome = self
            .bind_attachment_statements_v1()
            .and_then(|()| self.validate_signed_attachments_v1());
        if outcome.is_err() {
            self.attachments = previous;
        }
        outcome
    }

    /// Validate the ordered intent descriptor and the attachment occurrences
    /// against this payload.
    ///
    /// Beyond [`SignedAttachmentsV1::validate_v1`] this checks that each named
    /// instruction wire identifier is registered, that each invocation binding
    /// names an item of the executable of the right kind and operation, that
    /// an execution proof carrier is declared at most once and only for a
    /// proved IVM executable, that each wrapped proof carrier is one canonical
    /// proof attachment whose proof-free digest and role match its
    /// declaration, and that each statement digest is the one derived from
    /// this payload's ordered intent.
    ///
    /// A payload without attachments is valid.
    ///
    /// # Errors
    ///
    /// Returns the first violation.
    pub fn validate_signed_attachments_v1(&self) -> Result<(), SignedAttachmentErrorV1> {
        let Some(attachments) = &self.attachments else {
            return Ok(());
        };
        attachments.validate_v1()?;
        self.validate_attachment_invocations_v1(attachments)?;
        attachments.validate_proof_carriers_v1()?;
        attachments.validate_statement_bindings_v1(self.ordered_intent_digest_v1()?)
    }

    fn validate_attachment_invocations_v1(
        &self,
        attachments: &SignedAttachmentsV1,
    ) -> Result<(), SignedAttachmentErrorV1> {
        let mut bound_direct = BTreeSet::new();
        let mut execution_carrier_seen = false;
        for action in attachments.actions() {
            let action_index = action.action_index;
            match &action.operation {
                ActionOperationV1::TransactionProof => {}
                ActionOperationV1::IvmProvedExecution => {
                    if execution_carrier_seen
                        || !matches!(self.instructions, Executable::IvmProved(_))
                    {
                        return Err(SignedAttachmentErrorV1::ExecutionCarrierNotAdmitted {
                            action_index,
                        });
                    }
                    execution_carrier_seen = true;
                }
                ActionOperationV1::NativeInstruction(wire_id) => {
                    if !is_instruction_wire_id_registered(wire_id) {
                        return Err(SignedAttachmentErrorV1::UnregisteredOperation {
                            action_index,
                        });
                    }
                    match &action.invocation {
                        ActionInvocationBindingV1::Direct { instruction_index } => {
                            let instruction = direct_instruction(
                                &self.instructions,
                                *instruction_index,
                                action_index,
                            )?;
                            if instruction_wire_id(instruction) != Some(wire_id.as_str()) {
                                return Err(SignedAttachmentErrorV1::InvocationTargetMismatch {
                                    action_index,
                                });
                            }
                            if !bound_direct.insert(*instruction_index) {
                                return Err(SignedAttachmentErrorV1::DuplicateInvocation {
                                    action_index,
                                });
                            }
                        }
                        ActionInvocationBindingV1::Contract { root_index, .. } => {
                            validate_contract_root(&self.instructions, *root_index, action_index)?;
                        }
                        ActionInvocationBindingV1::Transaction => {
                            return Err(SignedAttachmentErrorV1::OperationRule {
                                action_index,
                                rule: ActionRuleViolationV1::Invocation,
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl SignedAttachmentsV1 {
    /// Lane privacy witnesses of the wrapped proof carriers that declare one,
    /// in action order.
    ///
    /// Only carriers whose attachment role is
    /// [`AttachmentRoleV1::LanePrivacyProof`] are decoded.
    ///
    /// # Errors
    ///
    /// Returns an error when such a carrier is missing or malformed.
    pub fn lane_privacy_proofs_v1(&self) -> Result<Vec<LanePrivacyProof>, SignedAttachmentErrorV1> {
        let mut proofs = Vec::new();
        for action in self.actions() {
            let declares_witness = action
                .attachments
                .first()
                .is_some_and(|reference| reference.role == AttachmentRoleV1::LanePrivacyProof);
            if !declares_witness {
                continue;
            }
            if let Some(witness) = self
                .proof_carrier_v1(action)?
                .and_then(|attachment| attachment.lane_privacy)
            {
                proofs.push(witness);
            }
        }
        Ok(proofs)
    }
}

impl SignedTransaction {
    /// Digest of the normalized proof-free ordered intent of the signed payload.
    ///
    /// Authorization signatures are outside the preimage.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical encoding fails.
    pub fn ordered_intent_digest_v1(
        &self,
    ) -> Result<OrderedIntentDigestV1, SignedAttachmentErrorV1> {
        self.payload.ordered_intent_digest_v1()
    }

    /// Validate the ordered intent descriptor and the attachment occurrences
    /// of the signed payload.
    ///
    /// # Errors
    ///
    /// Returns the first violation; see
    /// [`TransactionPayload::validate_signed_attachments_v1`].
    pub fn validate_signed_attachments_v1(&self) -> Result<(), SignedAttachmentErrorV1> {
        self.payload.validate_signed_attachments_v1()
    }

    /// The wrapped proof attachments of the transaction-level carriers, in
    /// action order. Empty for a transaction without attachments.
    ///
    /// # Errors
    ///
    /// Returns an error when a carrier occurrence is missing or malformed.
    pub fn proof_attachments_v1(&self) -> Result<Vec<ProofAttachment>, SignedAttachmentErrorV1> {
        self.payload.attachments.as_ref().map_or_else(
            || Ok(Vec::new()),
            |attachments| {
                Ok(attachments
                    .proof_carriers_v1()?
                    .into_iter()
                    .map(|(_, attachment)| attachment)
                    .collect())
            },
        )
    }

    /// Lane privacy witnesses carried by the transaction, in action order.
    ///
    /// # Errors
    ///
    /// Returns an error when a declared carrier is missing or malformed.
    pub fn lane_privacy_proofs_v1(&self) -> Result<Vec<LanePrivacyProof>, SignedAttachmentErrorV1> {
        self.payload.attachments.as_ref().map_or_else(
            || Ok(Vec::new()),
            SignedAttachmentsV1::lane_privacy_proofs_v1,
        )
    }
}

impl TransactionBuilder {
    /// Rebind every declared action's statement digest after a payload change.
    ///
    /// The digests are derived from the payload, so rebinding keeps a builder's
    /// descriptor consistent whatever order its fields are set in. A proof
    /// generated for an earlier intent no longer verifies against the new
    /// statement, which is the required outcome. A canonical encoding failure
    /// leaves the previous digests in place; validation then reports the same
    /// encoding failure, so such a payload is never admitted.
    pub(super) fn rebind_attachments(&mut self) {
        if self.payload.attachments.is_some() {
            let _ = self.payload.bind_attachment_statements_v1();
        }
    }

    /// Carry an ordered intent descriptor with its attachment occurrences.
    ///
    /// The statement digests are bound to this builder's payload here and
    /// again whenever the payload changes. The value is not validated: decoding
    /// and admission validate it, and [`Self::with_attachment_plan`] validates
    /// a complete plan.
    pub fn with_signed_attachments(mut self, attachments: SignedAttachmentsV1) -> Self {
        self.payload.attachments = Some(attachments);
        self.rebind_attachments();
        self
    }

    /// Carry a complete attachment plan.
    ///
    /// Set the executable first: invocation bindings are checked against it.
    ///
    /// # Errors
    ///
    /// Returns the first schema violation of the planned attachments.
    pub fn with_attachment_plan(
        self,
        plan: SignedAttachmentPlanV1,
    ) -> Result<Self, SignedAttachmentErrorV1> {
        let builder = self.with_signed_attachments(plan.declare());
        builder.payload.validate_signed_attachments_v1()?;
        Ok(builder)
    }

    /// Carry transaction-level proof attachments, one carrier action each, in order.
    ///
    /// # Errors
    ///
    /// Returns an error when no attachment is supplied, an attachment is
    /// structurally invalid or the carriers exceed a first-release bound.
    pub fn with_proof_attachments(
        self,
        attachments: impl IntoIterator<Item = ProofAttachment>,
    ) -> Result<Self, SignedAttachmentErrorV1> {
        let attachments = attachments.into_iter().collect::<Vec<_>>();
        self.with_attachment_plan(SignedAttachmentPlanV1::transaction_proofs(&attachments)?)
    }
}

#[cfg(test)]
#[path = "ordered_intent_tests.rs"]
mod tests;
