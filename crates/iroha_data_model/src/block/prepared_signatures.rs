//! Signature custody through the sole canonical `SignedBlock` field/frame walk.
//!
//! This prepared owner funds signatures, four certificate byte leaves, DA proof-policy
//! arrays/UTF-8 aliases, DA commitment arrays/tags/signatures, opaque parent-QC bytes,
//! native penalty actions and reusable decode controls. Evidence and Core construction
//! remain unowned; byte custody does not fund the independently decoded semantic QC.
//! The actual header/confidential digest and beacon pulse use the same model-private
//! inline destination through their generated Copy-field walks without heap scratch.
//! Other block/result children still use their canonical owning leaves and remain
//! explicit physical-custody obligations. No full-graph admission is claimed.

use super::commit_certificate::{CertificateCustodyError, PreparedCommitCertificate};
use super::{
    BlockPayload, BlockResult, BlockSignatureCustodyError, BlockSignatures, CommitCertificate,
    OutputFieldRef, PreparedBlockSignatures, SignedBlock, borrow_framed_signed_block_payload,
};
use crate::consensus::{
    NposConsensusEffects, NposParentServiceCommitQc, NposPenaltyActions,
    NposPenaltyActionsCustodyError, ParentServiceCustodyError, PreparedNposPenaltyActions,
    PreparedParentServiceCommitQc,
};
use crate::da::commitment::{
    DaCommitmentBundle, DaCommitmentCustodyError, DaProofPolicyBundle, DaProofPolicyCustodyError,
    PreparedDaCommitmentBundle, PreparedDaProofPolicyBundle,
};
use crate::inline_fields::DecodedField;
use iroha_allocation::{
    AllocationBudget, ChargedBuffer, ChargedBufferError, SharedFromChargeError,
};
use iroha_crypto::Hash;
use norito::core::DecodeRecordFields;
use norito::{
    SerializePayload,
    core::{
        CanonicalField, DecodeField, DecodeIntoError, FieldDestination, PreparedDecodeError,
        PreparedDecodeScopeError, PreparedDecodeWorkspace, PreparedDecodeWorkspaceConstruction,
        PreparedRecordDestination, SequenceSpan,
    },
};

/// Original prepared scope, complete-frame, source or signature-custody failure.
#[derive(Debug, thiserror::Error)]
pub enum PreparedSignatureBlockError {
    /// Original pool/allocator refused the two actual canonical decode controls.
    #[error(transparent)]
    Storage(#[from] ChargedBufferError),
    /// Physical construction refused an exact retained original counter charge.
    #[error(transparent)]
    ControlBacking(#[from] SharedFromChargeError),
    /// Actual reusable canonical control construction/reuse failed.
    #[error(transparent)]
    Scope(#[from] PreparedDecodeScopeError),
    /// Original header/version failure before the complete canonical frame walk.
    #[error(transparent)]
    Frame(#[from] norito::core::DecodeAttemptError),
    /// Original canonical or signature destination failure, retaining every owner.
    #[error(transparent)]
    Decode(#[from] PreparedDecodeError<BlockSignatureCustodyError>),
    /// Original certificate child preparation refused; all source-bound owners remain live.
    #[error(transparent)]
    Certificate(#[from] CertificateCustodyError),
    /// Original DA proof-policy children refused; all original source owners remain live.
    #[error(transparent)]
    Policy(#[from] DaProofPolicyCustodyError),
    /// Original DA commitment children refused; their exact source/owners remain retained.
    #[error(transparent)]
    Commitments(#[from] DaCommitmentCustodyError),
    /// Original opaque parent-service byte custody refusal.
    #[error(transparent)]
    ParentService(#[from] ParentServiceCustodyError),
    /// Original native action graph refusal; the same partial source owner remains live.
    #[error(transparent)]
    PenaltyActions(#[from] NposPenaltyActionsCustodyError),
    /// The original charged input, bytes or exact selected `SignedBlockWire` changed.
    #[error("prepared block signature decoder changed its original source")]
    SourceChanged,
    /// Source belongs to a different original pool or range is outside initialized input.
    #[error("prepared block signature decoder has no exact original funded input")]
    Source,
}
struct Source {
    address: usize,
    length: usize,
    hash: Hash,
    span: SequenceSpan,
}
impl Source {
    fn new(bytes: &[u8], span: SequenceSpan) -> Self {
        Self {
            address: bytes.as_ptr().addr(),
            length: bytes.len(),
            hash: Hash::new(bytes),
            span,
        }
    }
    fn matches(&self, bytes: &[u8], span: SequenceSpan) -> bool {
        self.address == bytes.as_ptr().addr()
            && self.length == bytes.len()
            && self.hash == Hash::new(bytes)
            && self.span == span
    }
}
/// Original-pool decoder controls and retained signature/certificate preparation for one source.
///
/// Construct before consuming a protocol attempt. The caller must retain the actual
/// input `ChargedBuffer` alive until success or explicit abandonment. Every refusal
/// preserves original signature/certificate preparation. Success shares those exact immutable
/// owners with `SignedBlock` while this decoder retains them through validation refusal.
/// Explicit retirement leaves the original block holding the same custody for publication/recovery.
/// TODO: prepare every other transaction, result, DA and authority graph child.
pub struct PreparedSignedBlockSignaturesDecode {
    parent_absent: bool,
    parent_pending: Option<PreparedParentServiceCommitQc>,
    parent_completed: Option<NposParentServiceCommitQc>,
    penalty_absent: bool,
    penalty_pending: Option<PreparedNposPenaltyActions>,
    penalty_completed: Option<NposPenaltyActions>,
    commitments_pending: Option<PreparedDaCommitmentBundle>,
    commitments_completed: Option<DaCommitmentBundle>,
    policy_pending: Option<PreparedDaProofPolicyBundle>,
    policy_completed: Option<DaProofPolicyBundle>,
    certificate_pending: Option<PreparedCommitCertificate>,
    certificate_completed: Option<CommitCertificate>,
    workspace: Option<PreparedDecodeWorkspace>,
    workspace_construction: Option<PreparedDecodeWorkspaceConstruction>,
    pending: Option<PreparedBlockSignatures>,
    completed: Option<BlockSignatures>,
    source: Option<Source>,
    budget: AllocationBudget,
}
impl PreparedSignedBlockSignaturesDecode {
    /// Reserve both original counter charges before returning a retained continuation.
    /// Physical construction happens inside `decode`, after the caller stores this owner
    /// and the exact source has been bound. No physical constructor can discard a prefix.
    ///
    /// # Errors
    /// Returns the exact original finite-pool refusal before consuming any source.
    pub fn new(budget: &AllocationBudget) -> Result<Self, PreparedSignatureBlockError> {
        let mut reservation = budget
            .try_reserve_layouts(PreparedDecodeWorkspace::allocation_layouts())
            .map_err(ChargedBufferError::Admission)?;
        let charges = PreparedDecodeWorkspace::allocation_layouts().map(|layout| {
            reservation
                .try_split(layout)
                .expect("both exact original counter charges")
        });
        let construction = PreparedDecodeWorkspaceConstruction::from_charges(budget, charges)
            .unwrap_or_else(|_| unreachable!("charges split from this exact original pool"));
        Ok(Self {
            parent_absent: false,
            parent_pending: None,
            parent_completed: None,
            penalty_absent: false,
            penalty_pending: None,
            penalty_completed: None,
            commitments_pending: None,
            commitments_completed: None,
            policy_pending: None,
            policy_completed: None,
            certificate_pending: None,
            certificate_completed: None,
            workspace: None,
            workspace_construction: Some(construction),
            pending: None,
            completed: None,
            source: None,
            budget: budget.clone(),
        })
    }
    /// Whether every retained control/collection/leaf keeps this same original pool.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.budget.same_pool(budget)
            && self
                .parent_pending
                .as_ref()
                .is_none_or(|owner| owner.belongs_to(budget))
            && self
                .parent_completed
                .as_ref()
                .is_none_or(|owner| owner.admitted_to(budget))
            && self
                .penalty_pending
                .as_ref()
                .is_none_or(|owner| owner.belongs_to(budget))
            && self
                .penalty_completed
                .as_ref()
                .is_none_or(|owner| owner.admitted_to(budget))
            && self
                .commitments_pending
                .as_ref()
                .is_none_or(|owner| owner.belongs_to(budget))
            && self
                .commitments_completed
                .as_ref()
                .is_none_or(|owner| owner.admitted_to(budget))
            && self
                .policy_pending
                .as_ref()
                .is_none_or(|owner| owner.belongs_to(budget))
            && self
                .policy_completed
                .as_ref()
                .is_none_or(|owner| owner.admitted_to(budget))
            && self
                .certificate_pending
                .as_ref()
                .is_none_or(|owner| owner.belongs_to(budget))
            && self
                .certificate_completed
                .as_ref()
                .is_none_or(|owner| owner.admitted_to(budget))
            && self
                .workspace
                .as_ref()
                .is_none_or(|owner| owner.belongs_to(budget))
            && self
                .workspace_construction
                .as_ref()
                .is_none_or(|owner| owner.belongs_to(budget))
            && self
                .pending
                .as_ref()
                .is_none_or(|owner| owner.belongs_to(budget))
            && self
                .completed
                .as_ref()
                .is_none_or(|owner| owner.admitted_to(budget))
    }
    /// Abandon the exact source explicitly after its enclosing owner retires the attempt.
    /// Completed/partial signature and certificate custody retires before preparing another source.
    pub fn clear_consumed(&mut self) {
        self.parent_absent = false;
        self.parent_pending = None;
        self.parent_completed = None;
        self.penalty_absent = false;
        self.penalty_pending = None;
        self.penalty_completed = None;
        self.commitments_pending = None;
        self.commitments_completed = None;
        self.policy_pending = None;
        self.policy_completed = None;
        self.certificate_pending = None;
        self.certificate_completed = None;
        self.pending = None;
        self.completed = None;
        self.source = None;
    }
    /// Borrow retained completed signature custody only for the unchanged original source.
    /// This proves allocation identity only; incomplete whole-frame verification grants no authority.
    ///
    /// # Errors
    /// Rejects a different pool, allocation or complete original source content.
    pub fn retained_signatures<'a>(
        &'a self,
        input: &ChargedBuffer<u8>,
    ) -> Result<Option<&'a BlockSignatures>, PreparedSignatureBlockError> {
        if !input.belongs_to(&self.budget) {
            return Err(PreparedSignatureBlockError::Source);
        }
        if let Some(source) = &self.source
            && !source.matches(input.as_slice(), source.span)
        {
            return Err(PreparedSignatureBlockError::SourceChanged);
        }
        Ok(self.completed.as_ref())
    }
    /// Whether this block retains this decoder's exact completed signature control.
    ///
    /// This allocation-free observation compares physical owners after the same original
    /// input address, whole-wire content and pool checks. Equal values or admission to
    /// the same pool do not substitute another independently prepared collection.
    /// It proves signature custody only, never execution, finality or full-graph admission.
    ///
    /// # Errors
    /// Rejects a changed original source or foreign pool exactly as `retained_signatures`.
    /// An incomplete/retired decoder or a different collection returns false.
    pub fn retains_signature_custody(
        &self,
        input: &ChargedBuffer<u8>,
        block: &SignedBlock,
    ) -> Result<bool, PreparedSignatureBlockError> {
        Ok(self
            .retained_signatures(input)?
            .is_some_and(|original| BlockSignatures::ptr_eq(original, &block.signatures)))
    }

    /// Borrow the original admitted certificate only for its unchanged complete source.
    /// Custody identity does not establish whole-frame validity or finality authority.
    ///
    /// # Errors
    /// Rejects a foreign pool, changed allocation or any changed complete input bytes.
    pub fn retained_certificate<'a>(
        &'a self,
        input: &ChargedBuffer<u8>,
    ) -> Result<Option<&'a CommitCertificate>, PreparedSignatureBlockError> {
        if !input.belongs_to(&self.budget) {
            return Err(PreparedSignatureBlockError::Source);
        }
        if self
            .source
            .as_ref()
            .is_some_and(|source| !source.matches(input.as_slice(), source.span))
        {
            return Err(PreparedSignatureBlockError::SourceChanged);
        }
        Ok(self.certificate_completed.as_ref())
    }
    /// Borrow the same original admitted DA policies for this unchanged complete source.
    /// This proves allocation custody only; whole-frame validation and protocol checks
    /// remain mandatory, as do all other payload/result/DA funding obligations.
    ///
    /// # Errors
    /// Rejects a foreign pool, changed allocation or changed complete input bytes.
    pub fn retained_da_proof_policies<'a>(
        &'a self,
        input: &ChargedBuffer<u8>,
    ) -> Result<Option<&'a DaProofPolicyBundle>, PreparedSignatureBlockError> {
        if !input.belongs_to(&self.budget) {
            return Err(PreparedSignatureBlockError::Source);
        }
        if self
            .source
            .as_ref()
            .is_some_and(|source| !source.matches(input.as_slice(), source.span))
        {
            return Err(PreparedSignatureBlockError::SourceChanged);
        }
        Ok(self.policy_completed.as_ref())
    }
    /// Borrow the same original admitted DA commitments for this unchanged complete source.
    /// This proves allocation custody only; whole-frame validation and protocol checks
    /// remain mandatory, as do all other payload/result/DA funding obligations.
    ///
    /// # Errors
    /// Rejects a foreign pool, changed allocation or changed complete input bytes.
    pub fn retained_da_commitments<'a>(
        &'a self,
        input: &ChargedBuffer<u8>,
    ) -> Result<Option<&'a DaCommitmentBundle>, PreparedSignatureBlockError> {
        if !input.belongs_to(&self.budget) {
            return Err(PreparedSignatureBlockError::Source);
        }
        if self
            .source
            .as_ref()
            .is_some_and(|source| !source.matches(input.as_slice(), source.span))
        {
            return Err(PreparedSignatureBlockError::SourceChanged);
        }
        Ok(self.commitments_completed.as_ref())
    }
    /// Borrow the same original admitted penalty actions for this unchanged complete source.
    /// This proves only action allocation custody, never parent-QC/evidence or protocol authority.
    ///
    /// # Errors
    /// Rejects a foreign pool, changed allocation or any changed complete source bytes.
    pub fn retained_npos_penalty_actions<'a>(
        &'a self,
        input: &ChargedBuffer<u8>,
    ) -> Result<Option<&'a NposPenaltyActions>, PreparedSignatureBlockError> {
        if !input.belongs_to(&self.budget) {
            return Err(PreparedSignatureBlockError::Source);
        }
        if self
            .source
            .as_ref()
            .is_some_and(|source| !source.matches(input.as_slice(), source.span))
        {
            return Err(PreparedSignatureBlockError::SourceChanged);
        }
        Ok(self.penalty_completed.as_ref())
    }
    /// Check exact action-owner identity after the same original full-source checks.
    /// Absence must agree; equal values or a separately admitted owner cannot substitute it.
    ///
    /// # Errors
    /// Preserves the source and pool errors of `retained_npos_penalty_actions`.
    pub fn retains_npos_penalty_action_custody(
        &self,
        input: &ChargedBuffer<u8>,
        block: &SignedBlock,
    ) -> Result<bool, PreparedSignatureBlockError> {
        let retained = self.retained_npos_penalty_actions(input)?;
        Ok(match (retained, block.npos_consensus_effects()) {
            (Some(original), Some(effects)) => {
                NposPenaltyActions::ptr_eq(original, &effects.penalty_actions)
            }
            (None, None) => self.penalty_absent,
            _ => false,
        })
    }

    /// Borrow the original immutable parent-QC byte owner, without authenticating its semantics.
    /// # Errors
    /// Rejects changed complete source allocation/content or a foreign pool.
    pub fn retained_parent_service<'a>(
        &'a self,
        input: &ChargedBuffer<u8>,
    ) -> Result<Option<&'a NposParentServiceCommitQc>, PreparedSignatureBlockError> {
        if !input.belongs_to(&self.budget) {
            return Err(PreparedSignatureBlockError::Source);
        }
        if self
            .source
            .as_ref()
            .is_some_and(|source| !source.matches(input.as_slice(), source.span))
        {
            return Err(PreparedSignatureBlockError::SourceChanged);
        }
        Ok(self.parent_completed.as_ref())
    }
    /// Whether the block retains the same original parent-QC owner or its decoded absence.
    /// # Errors
    /// Preserves the exact source/pool errors of `retained_parent_service`.
    pub fn retains_parent_service_custody(
        &self,
        input: &ChargedBuffer<u8>,
        block: &SignedBlock,
    ) -> Result<bool, PreparedSignatureBlockError> {
        let offered = block
            .npos_consensus_effects()
            .and_then(|effects| effects.parent_service_commit_qc.as_ref());
        Ok(match (self.retained_parent_service(input)?, offered) {
            (Some(original), Some(offered)) => NposParentServiceCommitQc::ptr_eq(original, offered),
            (None, None) => self.parent_absent,
            _ => false,
        })
    }

    fn prepare_workspace(&mut self) -> Result<(), PreparedSignatureBlockError> {
        if self.workspace.is_some() {
            return Ok(());
        }
        let pending = self
            .workspace_construction
            .take()
            .ok_or(PreparedSignatureBlockError::Source)?;
        match pending.try_finish() {
            Ok(workspace) => self.workspace = Some(workspace),
            Err((pending, error)) => {
                if !cfg!(all(test, sumeragi_model_mutation = "DM54")) {
                    self.workspace_construction = Some(pending);
                }
                return Err(error.into());
            }
        }
        Ok(())
    }
    /// Decode the original complete `SignedBlockWire` through its one canonical field walk.
    ///
    /// # Errors
    /// Preserves partial signature/certificate owners and original canonical/error provenance.
    pub fn decode(
        &mut self,
        input: &ChargedBuffer<u8>,
        span: SequenceSpan,
        limits: norito::DecodeLimits,
    ) -> Result<SignedBlock, PreparedSignatureBlockError> {
        if !input.belongs_to(&self.budget) {
            return Err(PreparedSignatureBlockError::Source);
        }
        if let Some(source) = &self.source {
            if !source.matches(input.as_slice(), span) {
                return Err(PreparedSignatureBlockError::SourceChanged);
            }
        } else {
            self.source = Some(Source::new(input.as_slice(), span));
        }
        self.prepare_workspace()?;
        let bytes = span
            .get(input.as_slice())
            .map_err(|_| PreparedSignatureBlockError::Source)?;
        let framed = norito::core::classify_decode_attempt(|| {
            let (version, framed) = borrow_framed_signed_block_payload(bytes)?;
            if version != SignedBlock::WIRE_VERSION {
                return Err(norito::Error::UnsupportedVersion {
                    found: version,
                    expected: 1,
                });
            }
            Ok(framed)
        })?;
        #[cfg(all(test, sumeragi_model_mutation = "DM49"))]
        {
            self.penalty_pending = None;
            self.penalty_completed = None;
        }
        #[cfg(all(test, sumeragi_model_mutation = "DM52"))]
        {
            self.parent_pending = None;
            self.parent_completed = None;
        }
        let mut destination = Fields {
            parent_absent: &mut self.parent_absent,
            parent_pending: &mut self.parent_pending,
            parent_completed: &mut self.parent_completed,
            input,
            penalty_absent: &mut self.penalty_absent,
            penalty_pending: &mut self.penalty_pending,
            penalty_completed: &mut self.penalty_completed,
            budget: &self.budget,
            pending: &mut self.pending,
            completed: &mut self.completed,
            signature_ready: false,
            commitments_pending: &mut self.commitments_pending,
            commitments_completed: &mut self.commitments_completed,
            policy_pending: &mut self.policy_pending,
            policy_completed: &mut self.policy_completed,
            certificate_pending: &mut self.certificate_pending,
            certificate_completed: &mut self.certificate_completed,
            payload: DecodedField::Missing,
            result: DecodedField::Missing,
            certificate: DecodedField::Missing,
        };
        self.workspace
            .as_mut()
            .expect("complete original counter controls")
            .decode_canonical_archive_into::<SignedBlock, _>(framed, limits, &mut destination)
            .map_err(retain_field_failure)?;
        let block = SignedBlock {
            signatures: destination
                .completed
                .as_ref()
                .expect("complete original signature custody")
                .clone(),
            payload: destination
                .payload
                .take()
                .expect("complete canonical payload"),
            result: destination
                .result
                .take()
                .expect("complete canonical result field"),
            commit_certificate: destination
                .certificate
                .take()
                .expect("complete canonical certificate field"),
        };
        // Keep the same physical collection and original source throughout later validation
        // refusal. The enclosing owner explicitly retires this decoder after moving the
        // successful original into its retained execution/publication phase.
        Ok(block)
    }
}
struct Fields<'a> {
    parent_absent: &'a mut bool,
    parent_pending: &'a mut Option<PreparedParentServiceCommitQc>,
    parent_completed: &'a mut Option<NposParentServiceCommitQc>,
    penalty_absent: &'a mut bool,
    penalty_pending: &'a mut Option<PreparedNposPenaltyActions>,
    penalty_completed: &'a mut Option<NposPenaltyActions>,
    input: &'a ChargedBuffer<u8>,
    budget: &'a AllocationBudget,
    pending: &'a mut Option<PreparedBlockSignatures>,
    completed: &'a mut Option<BlockSignatures>,
    signature_ready: bool,
    commitments_pending: &'a mut Option<PreparedDaCommitmentBundle>,
    commitments_completed: &'a mut Option<DaCommitmentBundle>,
    policy_pending: &'a mut Option<PreparedDaProofPolicyBundle>,
    policy_completed: &'a mut Option<DaProofPolicyBundle>,
    certificate_pending: &'a mut Option<PreparedCommitCertificate>,
    certificate_completed: &'a mut Option<CommitCertificate>,
    payload: DecodedField<BlockPayload>,
    result: DecodedField<Option<BlockResult>>,
    certificate: DecodedField<Option<CommitCertificate>>,
}
impl FieldDestination for Fields<'_> {
    type Error = FieldFailure;
}
impl DecodeField<0, BlockSignatures> for Fields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, BlockSignatures>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| {
            let start = bytes
                .as_ptr()
                .addr()
                .checked_sub(self.input.as_slice().as_ptr().addr())
                .ok_or(norito::Error::LengthMismatch)?;
            let end = start
                .checked_add(bytes.len())
                .ok_or(norito::Error::LengthMismatch)?;
            let plan = PreparedBlockSignatures::from_source(
                self.input,
                SequenceSpan { start, end },
                self.budget,
            )
            .map_err(|error| match error {
                BlockSignatureCustodyError::Decode(original) => {
                    DecodeIntoError::Codec(original.into_error())
                }
                other => DecodeIntoError::Destination(FieldFailure::Signature(other)),
            })?;
            if self.completed.is_none() {
                if self.pending.is_none() {
                    *self.pending = Some(plan);
                }
                self.pending
                    .as_mut()
                    .expect("same original pending signature owner")
                    .prepare(self.input)
                    .map_err(|error| {
                        DecodeIntoError::Destination(FieldFailure::Signature(error))
                    })?;
                match self
                    .pending
                    .take()
                    .expect("same prepared signatures")
                    .finish(self.input)
                {
                    Ok(owner) => *self.completed = Some(owner),
                    Err((owner, error)) => {
                        *self.pending = Some(owner);
                        return Err(DecodeIntoError::Destination(FieldFailure::Signature(error)));
                    }
                }
            }
            self.signature_ready = true;
            Ok(())
        })
    }
}
macro_rules! owned_field {
    ($index:literal,$ty:ty,$field:ident) => {
        impl DecodeField<$index, $ty> for Fields<'_> {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, $ty>,
            ) -> Result<(), DecodeIntoError<Self::Error>> {
                self.$field = DecodedField::Decoded(field.decode_owned()?);
                Ok(())
            }
        }
    };
}
impl DecodeField<1, BlockPayload> for Fields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, BlockPayload>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| {
            let mut payload = PayloadFields {
                parent_absent: self.parent_absent,
                parent_pending: self.parent_pending,
                parent_completed: self.parent_completed,
                penalty_absent: self.penalty_absent,
                penalty_pending: self.penalty_pending,
                penalty_completed: self.penalty_completed,
                input: self.input,
                budget: self.budget,
                commitments_pending: self.commitments_pending,
                commitments_completed: self.commitments_completed,
                pending: self.policy_pending,
                completed: self.policy_completed,
                header: DecodedField::Missing,
                external_entrypoints: DecodedField::Missing,
                da_commitments: DecodedField::Missing,
                da_proof_policies: DecodedField::Missing,
                da_pin_intents: DecodedField::Missing,
                npos_consensus_effects: DecodedField::Missing,
                global_beacon_pulse: DecodedField::Missing,
                execution_context: DecodedField::Missing,
            };
            let (_, used) = BlockPayload::decode_fields(bytes, &mut payload)?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            self.payload = DecodedField::Decoded(payload.finish()?);
            Ok(())
        })
    }
}
// TODO: prepare the remaining payload fields' real transaction,
// pin authorization, NPoS evidence and execution-context child graphs. Their owning
// canonical leaves below do not gain physical funding from either immutable DA child.
struct PayloadFields<'a> {
    parent_absent: &'a mut bool,
    parent_pending: &'a mut Option<PreparedParentServiceCommitQc>,
    parent_completed: &'a mut Option<NposParentServiceCommitQc>,
    penalty_absent: &'a mut bool,
    penalty_pending: &'a mut Option<PreparedNposPenaltyActions>,
    penalty_completed: &'a mut Option<NposPenaltyActions>,
    input: &'a ChargedBuffer<u8>,
    budget: &'a AllocationBudget,
    commitments_pending: &'a mut Option<PreparedDaCommitmentBundle>,
    commitments_completed: &'a mut Option<DaCommitmentBundle>,
    pending: &'a mut Option<PreparedDaProofPolicyBundle>,
    completed: &'a mut Option<DaProofPolicyBundle>,
    header: DecodedField<super::BlockHeader>,
    external_entrypoints: DecodedField<Vec<crate::transaction::signed::TransactionEntrypoint>>,
    da_commitments: DecodedField<Option<crate::da::commitment::DaCommitmentBundle>>,
    da_proof_policies: DecodedField<Option<DaProofPolicyBundle>>,
    da_pin_intents: DecodedField<Option<crate::da::pin_intent::DaPinIntentBundle>>,
    npos_consensus_effects: DecodedField<Option<crate::consensus::NposConsensusEffects>>,
    global_beacon_pulse:
        DecodedField<Option<crate::consensus::FinalizedGlobalThresholdBeaconPulseV1>>,
    execution_context: DecodedField<Option<super::execution_context::BlockExecutionContextBundle>>,
}
impl FieldDestination for PayloadFields<'_> {
    type Error = FieldFailure;
}
macro_rules! payload_owned_field {
    ($index:literal,$ty:ty,$field:ident) => {
        impl DecodeField<$index, $ty> for PayloadFields<'_> {
            type Value = ();
            fn decode_field(
                &mut self,
                field: CanonicalField<'_, $ty>,
            ) -> Result<(), DecodeIntoError<Self::Error>> {
                self.$field = DecodedField::Decoded(field.decode_owned()?);
                Ok(())
            }
        }
    };
}
impl DecodeField<0, super::BlockHeader> for PayloadFields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, super::BlockHeader>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        self.header = DecodedField::Decoded(field.with_payload(|bytes| {
            super::BlockHeader::decode_inline_payload(bytes).map_err(DecodeIntoError::Codec)
        })?);
        Ok(())
    }
}
payload_owned_field!(
    1,
    Vec<crate::transaction::signed::TransactionEntrypoint>,
    external_entrypoints
);
payload_owned_field!(
    4,
    Option<crate::da::pin_intent::DaPinIntentBundle>,
    da_pin_intents
);
impl DecodeField<5, Option<NposConsensusEffects>> for PayloadFields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, Option<NposConsensusEffects>>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        let effects = field.decode_optional(|field| {
            field.with_payload(|bytes| {
                let mut fields = PenaltyEffectsFields {
                    parent_absent: self.parent_absent,
                    parent_pending: self.parent_pending,
                    parent_completed: self.parent_completed,
                    input: self.input,
                    budget: self.budget,
                    pending: self.penalty_pending,
                    completed: self.penalty_completed,
                };
                let ((parent_service_commit_qc, evidence_admissions, penalty_actions), used) =
                    NposConsensusEffects::decode_fields(bytes, &mut fields)?;
                if used != bytes.len() {
                    return Err(norito::Error::LengthMismatch.into());
                }
                Ok(NposConsensusEffects {
                    parent_service_commit_qc,
                    evidence_admissions,
                    penalty_actions,
                })
            })
        })?;
        if effects.is_none() {
            *self.parent_absent = true;
        }
        *self.penalty_absent = effects.is_none();
        self.npos_consensus_effects = DecodedField::Decoded(effects);
        Ok(())
    }
}
// TODO: retain the actual evidence graph under its model owner; parent-QC bytes
// do not fund its independently decoded semantic QC graph.
// The canonical owning leaves below do not gain funding from the action child.
struct PenaltyEffectsFields<'a> {
    parent_absent: &'a mut bool,
    parent_pending: &'a mut Option<PreparedParentServiceCommitQc>,
    parent_completed: &'a mut Option<NposParentServiceCommitQc>,
    input: &'a ChargedBuffer<u8>,
    budget: &'a AllocationBudget,
    pending: &'a mut Option<PreparedNposPenaltyActions>,
    completed: &'a mut Option<NposPenaltyActions>,
}
impl FieldDestination for PenaltyEffectsFields<'_> {
    type Error = FieldFailure;
}
fn parent_failure(error: ParentServiceCustodyError) -> DecodeIntoError<FieldFailure> {
    match error {
        ParentServiceCustodyError::Decode(original) => {
            DecodeIntoError::Codec(original.into_error())
        }
        original => DecodeIntoError::Destination(FieldFailure::ParentService(original)),
    }
}
impl DecodeField<0, Option<NposParentServiceCommitQc>> for PenaltyEffectsFields<'_> {
    type Value = Option<NposParentServiceCommitQc>;
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, Option<NposParentServiceCommitQc>>,
    ) -> Result<Self::Value, DecodeIntoError<Self::Error>> {
        let value = field.decode_optional(|field| {
            field.with_payload(|bytes| {
                let start = bytes
                    .as_ptr()
                    .addr()
                    .checked_sub(self.input.as_slice().as_ptr().addr())
                    .ok_or(norito::Error::LengthMismatch)?;
                let end = start
                    .checked_add(bytes.len())
                    .ok_or(norito::Error::LengthMismatch)?;
                let plan = PreparedParentServiceCommitQc::from_source(
                    self.input,
                    SequenceSpan { start, end },
                    self.budget,
                )
                .map_err(parent_failure)?;
                if self.parent_completed.is_none() {
                    if self.parent_pending.is_none() {
                        *self.parent_pending = Some(plan);
                    }
                    self.parent_pending
                        .as_mut()
                        .expect("same original parent-QC attempt")
                        .prepare(self.input)
                        .map_err(parent_failure)?;
                    match self
                        .parent_pending
                        .take()
                        .expect("complete original parent-QC")
                        .finish(self.input)
                    {
                        Ok(value) => *self.parent_completed = Some(value),
                        Err((owner, error)) => {
                            *self.parent_pending = Some(owner);
                            return Err(parent_failure(error));
                        }
                    }
                }
                Ok(self
                    .parent_completed
                    .as_ref()
                    .expect("same original parent-QC bytes")
                    .clone())
            })
        })?;
        *self.parent_absent = value.is_none();
        Ok(value)
    }
}
impl DecodeField<1, Vec<crate::block::consensus::Evidence>> for PenaltyEffectsFields<'_> {
    type Value = Vec<crate::block::consensus::Evidence>;
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, Self::Value>,
    ) -> Result<Self::Value, DecodeIntoError<Self::Error>> {
        Ok(field.decode_owned()?)
    }
}
fn penalty_failure(error: NposPenaltyActionsCustodyError) -> DecodeIntoError<FieldFailure> {
    match error {
        NposPenaltyActionsCustodyError::Decode(original) => {
            DecodeIntoError::Codec(original.into_error())
        }
        NposPenaltyActionsCustodyError::Codec(original) => DecodeIntoError::Codec(original),
        original => DecodeIntoError::Destination(FieldFailure::PenaltyActions(original)),
    }
}
impl DecodeField<2, NposPenaltyActions> for PenaltyEffectsFields<'_> {
    type Value = NposPenaltyActions;
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, NposPenaltyActions>,
    ) -> Result<Self::Value, DecodeIntoError<Self::Error>> {
        if cfg!(all(test, sumeragi_model_mutation = "DM48")) {
            return Ok(field.decode_owned()?);
        }
        field.with_payload(|bytes| {
            let start = bytes
                .as_ptr()
                .addr()
                .checked_sub(self.input.as_slice().as_ptr().addr())
                .ok_or(norito::Error::LengthMismatch)?;
            let end = start
                .checked_add(bytes.len())
                .ok_or(norito::Error::LengthMismatch)?;
            let plan = PreparedNposPenaltyActions::from_source(
                self.input,
                SequenceSpan { start, end },
                self.budget,
            )
            .map_err(penalty_failure)?;
            if self.completed.is_none() {
                if self.pending.is_none() {
                    *self.pending = Some(plan);
                }
                self.pending
                    .as_mut()
                    .expect("same original action attempt")
                    .prepare(self.input)
                    .map_err(penalty_failure)?;
                match self
                    .pending
                    .take()
                    .expect("complete original actions")
                    .finish(self.input)
                {
                    Ok(owner) => *self.completed = Some(owner),
                    Err((owner, error)) => {
                        *self.pending = Some(owner);
                        return Err(penalty_failure(error));
                    }
                }
            }
            Ok(self
                .completed
                .as_ref()
                .expect("same original immutable actions")
                .clone())
        })
    }
}
impl DecodeField<6, Option<crate::consensus::FinalizedGlobalThresholdBeaconPulseV1>>
    for PayloadFields<'_>
{
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, Option<crate::consensus::FinalizedGlobalThresholdBeaconPulseV1>>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        self.global_beacon_pulse = DecodedField::Decoded(field.decode_optional(|field| {
            field.with_payload(|bytes| {
                crate::consensus::FinalizedGlobalThresholdBeaconPulseV1::decode_inline_payload(
                    bytes,
                )
                .map_err(DecodeIntoError::Codec)
            })
        })?);
        Ok(())
    }
}
payload_owned_field!(
    7,
    Option<super::execution_context::BlockExecutionContextBundle>,
    execution_context
);
fn policy_failure(error: DaProofPolicyCustodyError) -> DecodeIntoError<FieldFailure> {
    match error {
        DaProofPolicyCustodyError::Decode(original) => {
            DecodeIntoError::Codec(original.into_error())
        }
        original => DecodeIntoError::Destination(FieldFailure::Policy(original)),
    }
}
impl DecodeField<3, Option<DaProofPolicyBundle>> for PayloadFields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, Option<DaProofPolicyBundle>>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        let present = field.decode_optional(|field| {
            field.with_payload(|bytes| {
                let start = bytes
                    .as_ptr()
                    .addr()
                    .checked_sub(self.input.as_slice().as_ptr().addr())
                    .ok_or(norito::Error::LengthMismatch)?;
                let end = start
                    .checked_add(bytes.len())
                    .ok_or(norito::Error::LengthMismatch)?;
                let plan = PreparedDaProofPolicyBundle::from_source(
                    self.input,
                    SequenceSpan { start, end },
                    self.budget,
                )
                .map_err(policy_failure)?;
                if self.completed.is_none() {
                    if self.pending.is_none() {
                        *self.pending = Some(plan);
                    }
                    self.pending
                        .as_mut()
                        .expect("same original policy attempt")
                        .prepare(self.input)
                        .map_err(policy_failure)?;
                    match self
                        .pending
                        .take()
                        .expect("complete original policy attempt")
                        .finish(self.input)
                    {
                        Ok(owner) => *self.completed = Some(owner),
                        Err((owner, error)) => {
                            *self.pending = Some(owner);
                            return Err(policy_failure(error));
                        }
                    }
                }
                self.da_proof_policies = DecodedField::Decoded(Some(
                    self.completed
                        .as_ref()
                        .expect("same original immutable policies")
                        .clone(),
                ));
                Ok(())
            })
        })?;
        if present.is_none() {
            self.da_proof_policies = DecodedField::Decoded(None);
        }
        Ok(())
    }
}
fn commitments_failure(error: DaCommitmentCustodyError) -> DecodeIntoError<FieldFailure> {
    match error {
        DaCommitmentCustodyError::Decode(original) => DecodeIntoError::Codec(original.into_error()),
        original => DecodeIntoError::Destination(FieldFailure::Commitments(original)),
    }
}
impl DecodeField<2, Option<DaCommitmentBundle>> for PayloadFields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, Option<DaCommitmentBundle>>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        let present = field.decode_optional(|field| {
            field.with_payload(|bytes| {
                let start = bytes
                    .as_ptr()
                    .addr()
                    .checked_sub(self.input.as_slice().as_ptr().addr())
                    .ok_or(norito::Error::LengthMismatch)?;
                let end = start
                    .checked_add(bytes.len())
                    .ok_or(norito::Error::LengthMismatch)?;
                let plan = PreparedDaCommitmentBundle::from_source(
                    self.input,
                    SequenceSpan { start, end },
                    self.budget,
                )
                .map_err(commitments_failure)?;
                if self.commitments_completed.is_none() {
                    if self.commitments_pending.is_none() {
                        *self.commitments_pending = Some(plan);
                    }
                    self.commitments_pending
                        .as_mut()
                        .expect("same original commitment attempt")
                        .prepare(self.input)
                        .map_err(commitments_failure)?;
                    match self
                        .commitments_pending
                        .take()
                        .expect("complete original commitment attempt")
                        .finish(self.input)
                    {
                        Ok(owner) => *self.commitments_completed = Some(owner),
                        Err((owner, error)) => {
                            *self.commitments_pending = Some(owner);
                            return Err(commitments_failure(error));
                        }
                    }
                }
                self.da_commitments = DecodedField::Decoded(Some(
                    self.commitments_completed
                        .as_ref()
                        .expect("same original immutable commitments")
                        .clone(),
                ));
                Ok(())
            })
        })?;
        if present.is_none() {
            self.da_commitments = DecodedField::Decoded(None);
        }
        Ok(())
    }
}
impl PayloadFields<'_> {
    fn finish(self) -> Result<BlockPayload, norito::Error> {
        Ok(BlockPayload {
            header: self
                .header
                .into_value()
                .ok_or(norito::Error::LengthMismatch)?,
            external_entrypoints: self
                .external_entrypoints
                .into_value()
                .ok_or(norito::Error::LengthMismatch)?,
            da_commitments: self
                .da_commitments
                .into_value()
                .ok_or(norito::Error::LengthMismatch)?,
            da_proof_policies: self
                .da_proof_policies
                .into_value()
                .ok_or(norito::Error::LengthMismatch)?,
            da_pin_intents: self
                .da_pin_intents
                .into_value()
                .ok_or(norito::Error::LengthMismatch)?,
            npos_consensus_effects: self
                .npos_consensus_effects
                .into_value()
                .ok_or(norito::Error::LengthMismatch)?,
            global_beacon_pulse: self
                .global_beacon_pulse
                .into_value()
                .ok_or(norito::Error::LengthMismatch)?,
            execution_context: self
                .execution_context
                .into_value()
                .ok_or(norito::Error::LengthMismatch)?,
        })
    }
}
owned_field!(2, Option<BlockResult>, result);
#[derive(Debug, thiserror::Error)]
enum FieldFailure {
    #[error(transparent)]
    ParentService(ParentServiceCustodyError),
    #[error(transparent)]
    PenaltyActions(NposPenaltyActionsCustodyError),
    #[error(transparent)]
    Signature(BlockSignatureCustodyError),
    #[error(transparent)]
    Certificate(CertificateCustodyError),
    #[error(transparent)]
    Policy(DaProofPolicyCustodyError),
    #[error(transparent)]
    Commitments(DaCommitmentCustodyError),
}
fn retain_field_failure(error: PreparedDecodeError<FieldFailure>) -> PreparedSignatureBlockError {
    match error {
        PreparedDecodeError::Destination(FieldFailure::ParentService(original)) => {
            PreparedSignatureBlockError::ParentService(original)
        }
        PreparedDecodeError::Destination(FieldFailure::PenaltyActions(original)) => {
            PreparedSignatureBlockError::PenaltyActions(original)
        }
        PreparedDecodeError::Codec(original) => {
            PreparedSignatureBlockError::Decode(PreparedDecodeError::Codec(original))
        }
        PreparedDecodeError::Scope(original) => {
            PreparedSignatureBlockError::Decode(PreparedDecodeError::Scope(original))
        }
        PreparedDecodeError::Destination(FieldFailure::Signature(original)) => {
            PreparedSignatureBlockError::Decode(PreparedDecodeError::Destination(original))
        }
        PreparedDecodeError::Destination(FieldFailure::Certificate(original)) => {
            PreparedSignatureBlockError::Certificate(original)
        }
        PreparedDecodeError::Destination(FieldFailure::Policy(original)) => {
            PreparedSignatureBlockError::Policy(original)
        }
        PreparedDecodeError::Destination(FieldFailure::Commitments(original)) => {
            PreparedSignatureBlockError::Commitments(original)
        }
    }
}
fn certificate_failure(error: CertificateCustodyError) -> DecodeIntoError<FieldFailure> {
    match error {
        CertificateCustodyError::Decode(original) => DecodeIntoError::Codec(original.into_error()),
        original => DecodeIntoError::Destination(FieldFailure::Certificate(original)),
    }
}
impl DecodeField<3, Option<CommitCertificate>> for Fields<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, Option<CommitCertificate>>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        let present = field.decode_optional(|field| {
            field.with_payload(|bytes| {
                let start = bytes
                    .as_ptr()
                    .addr()
                    .checked_sub(self.input.as_slice().as_ptr().addr())
                    .ok_or(norito::Error::LengthMismatch)?;
                let end = start
                    .checked_add(bytes.len())
                    .ok_or(norito::Error::LengthMismatch)?;
                let plan = PreparedCommitCertificate::from_source(
                    self.input,
                    SequenceSpan { start, end },
                    self.budget,
                )
                .map_err(certificate_failure)?;
                if self.certificate_completed.is_none() {
                    if self.certificate_pending.is_none() {
                        *self.certificate_pending = Some(plan);
                    }
                    self.certificate_pending
                        .as_mut()
                        .expect("same original certificate attempt")
                        .prepare(self.input)
                        .map_err(certificate_failure)?;
                    match self
                        .certificate_pending
                        .take()
                        .expect("complete original certificate attempt")
                        .finish(self.input)
                    {
                        Ok(owner) => *self.certificate_completed = Some(owner),
                        Err((owner, error)) => {
                            *self.certificate_pending = Some(owner);
                            return Err(certificate_failure(error));
                        }
                    }
                }
                self.certificate = DecodedField::Decoded(Some(
                    self.certificate_completed
                        .as_ref()
                        .expect("same original immutable certificate")
                        .clone(),
                ));
                Ok(())
            })
        })?;
        if present.is_none() {
            self.certificate = DecodedField::Decoded(None);
        }
        Ok(())
    }
}
#[derive(norito::codec::Encode)]
struct Wire<'a> {
    signatures: OutputFieldRef<'a, BlockSignatures>,
    payload: OutputFieldRef<'a, BlockPayload>,
    result: OutputFieldRef<'a, Option<BlockResult>>,
    commit_certificate: OutputFieldRef<'a, Option<CommitCertificate>>,
}
impl SerializePayload for Fields<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        if !self.signature_ready {
            return Err(norito::Error::InvalidValue {
                context: "unfinished original signature fields",
            });
        }
        Wire {
            signatures: OutputFieldRef(
                self.completed
                    .as_ref()
                    .ok_or(norito::Error::LengthMismatch)?,
            ),
            payload: OutputFieldRef(self.payload.as_ref().ok_or(norito::Error::LengthMismatch)?),
            result: OutputFieldRef(self.result.as_ref().ok_or(norito::Error::LengthMismatch)?),
            commit_certificate: OutputFieldRef(
                self.certificate
                    .as_ref()
                    .ok_or(norito::Error::LengthMismatch)?,
            ),
        }
        .serialize(writer)
    }
}
impl PreparedRecordDestination<SignedBlock> for Fields<'_> {
    fn reset(&mut self) {
        self.signature_ready = false;
        self.payload = DecodedField::Missing;
        self.result = DecodedField::Missing;
        self.certificate = DecodedField::Missing;
    }
}

#[cfg(test)]
mod tests;
