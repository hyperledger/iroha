//! Independently qualified enrollment and terminal custody transitions with no old-key response.

use super::*;
#[cfg(test)]
use sorafs_manifest::signer::custody::SignerCustodyEnrollmentContextV1;
use sorafs_manifest::signer::custody::{
    VerifiedSignerCustodyEnrollmentV1, verify_signer_custody_enrollment_v1,
};

/// Explicit enrollment authority for an ordinary state source.
///
/// These methods and the inherited observations must use the same independently configured
/// authority. Ordinary signing sources need not implement this capability, and enrollment
/// authority does not imply permission to perform an old-key terminal transition.
pub trait SignerCustodyEnrollmentStateSourceV1: SignerOperationStateSourceV1 {
    /// Authenticate the next enrollment slot and governed expected successor configuration.
    ///
    /// # Errors
    /// Fails unless the independently configured successor exactly matches `binding`.
    fn observe_enrollment(
        &self,
        binding: &SignerCustodyBindingV1,
    ) -> Result<
        sorafs_manifest::signer::custody::SignerCustodyEnrollmentContextV1,
        SignerOperationErrorV1,
    >;

    /// Authoritatively enroll the initial independently qualified generation using durable CAS.
    ///
    /// # Errors
    /// Fails unless this is the exact initial predecessor slot and no generation is active.
    fn enroll_initial(
        &self,
        request: &SignerCustodyEnrollmentRequestV1<'_>,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1>;
}

/// Explicit audited custody-transition authority over the same enrollment and operation source.
///
/// Native emergency revocation without the old key is separately governed and cannot substitute
/// for this capability's exact old-key terminal audit contract.
pub trait SignerCustodyControlStateSourceV1: SignerCustodyEnrollmentStateSourceV1 {
    /// Atomically finalize the exact terminal audit before activating or revoking custody.
    ///
    /// The transaction compares the exact exclusive reservation, current control state, old active
    /// head, expected terminal intent and audit successor. Activation additionally compares the
    /// independently governed successor binding and exact enrollment sequence/predecessor. No
    /// response or further old-key signing is authorized after this transaction takes effect.
    ///
    /// # Errors
    /// Fails when audit durability, authoritative enrollment/control CAS or finality cannot be proved.
    fn commit_custody_transition(
        &self,
        request: &SignerCustodyTransitionRequestV1<'_>,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1>;
}

/// Privately verified enrollment request; candidate bytes never choose the trusted configuration.
pub struct SignerCustodyEnrollmentRequestV1<'a> {
    record: &'a [u8],
    enrollment: &'a VerifiedSignerCustodyEnrollmentV1,
}
impl SignerCustodyEnrollmentRequestV1<'_> {
    /// Exact canonical record whose digest must be persisted by the enrollment transaction.
    #[must_use]
    pub const fn record_bytes(&self) -> &[u8] {
        self.record
    }
    /// Independent-authority verification for the exact next predecessor slot.
    #[must_use]
    pub const fn enrollment(&self) -> &VerifiedSignerCustodyEnrollmentV1 {
        self.enrollment
    }
}

/// Privately constructed terminal CAS request with an already prepared old-key audit.
pub struct SignerCustodyTransitionRequestV1<'a> {
    check: SignerOperationReservationCheckV1<'a>,
    audit: SignerOperationAuditHeadV1,
    transition_digest: [u8; 32],
    activation: Option<SignerCustodyEnrollmentRequestV1<'a>>,
}
impl SignerCustodyTransitionRequestV1<'_> {
    /// Exact exclusive reservation, old active custody and terminal action to compare atomically.
    #[must_use]
    pub const fn check(&self) -> &SignerOperationReservationCheckV1<'_> {
        &self.check
    }
    /// Exact immutable terminal audit successor that must finalize before changing custody.
    #[must_use]
    pub const fn audit(&self) -> SignerOperationAuditHeadV1 {
        self.audit
    }
    /// Successor record digest for activation, or independently supplied reason digest for revoke.
    #[must_use]
    pub const fn transition_digest(&self) -> [u8; 32] {
        self.transition_digest
    }
    /// Independently verified successor, present only for activation.
    #[must_use]
    pub const fn activation(&self) -> Option<&SignerCustodyEnrollmentRequestV1<'_>> {
        self.activation.as_ref()
    }
}

/// Completed authoritative terminal transition; never contains an old-key signature response.
pub struct CompletedSignerCustodyTransitionV1 {
    action: SignerOperationActionV1,
    audit: SignerOperationAuditHeadV1,
    transition_digest: [u8; 32],
    activation: Option<VerifiedSignerCustodyV1>,
}
impl CompletedSignerCustodyTransitionV1 {
    /// Exact finalized activation or revocation action.
    #[must_use]
    pub const fn action(&self) -> SignerOperationActionV1 {
        self.action
    }
    /// Immutable old-key audit finalized before the control transition took effect.
    #[must_use]
    pub const fn audit(&self) -> SignerOperationAuditHeadV1 {
        self.audit
    }
    /// Exact activated custody record or revocation reason digest.
    #[must_use]
    pub const fn transition_digest(&self) -> [u8; 32] {
        self.transition_digest
    }
    /// Fresh eligible successor observation; absent for terminal revocation.
    #[must_use]
    pub const fn activation(&self) -> Option<&VerifiedSignerCustodyV1> {
        self.activation.as_ref()
    }
}
impl fmt::Debug for CompletedSignerCustodyTransitionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletedSignerCustodyTransitionV1")
            .field("action", &self.action)
            .finish_non_exhaustive()
    }
}

/// Canonical exact terminal-request digest used by the service and authoritative control owner.
///
/// # Errors
/// Rejects ordinary actions, empty identities/digests or an invalid journal predecessor.
pub fn signer_custody_transition_request_digest_v1(
    action: SignerOperationActionV1,
    operation_id: [u8; 32],
    previous_record_digest: [u8; 32],
    previous_audit: SignerOperationAuditHeadV1,
    transition_digest: [u8; 32],
) -> Result<[u8; 32], SignerOperationErrorV1> {
    if !matches!(
        action,
        SignerOperationActionV1::ActivateCustody | SignerOperationActionV1::RevokeCustody
    ) || operation_id == [0; 32]
        || previous_record_digest == [0; 32]
        || transition_digest == [0; 32]
        || previous_audit.sequence == 0
        || previous_audit.sequence == u64::MAX
        || previous_audit.digest == [0; 32]
    {
        return Err(SignerOperationErrorV1::InvalidOperation);
    }
    digest_canonical(
        b"iroha.sorafs.signer.custody.transition-request.v1",
        &(
            action,
            operation_id,
            previous_record_digest,
            previous_audit,
            transition_digest,
        ),
    )
    .map_err(|()| SignerOperationErrorV1::InvalidOperation)
}

/// Enroll only the first generation, with independently configured trust and authoritative CAS.
///
/// No key operation is performed. The source must independently pin `binding` and the authority,
/// commit the exact sequence-one record once and authenticate genuinely finalized activation.
///
/// # Errors
/// Rejects noninitial slots, unqualified records, failed CAS, stale or substituted activation.
pub fn enroll_initial_signer_custody_v1(
    binding: &SignerCustodyBindingV1,
    record: &[u8],
    trust: &SignerCustodyTrustV1,
    source: &dyn SignerCustodyEnrollmentStateSourceV1,
) -> Result<VerifiedSignerCustodyV1, SignerOperationErrorV1> {
    let context = source.observe_enrollment(binding)?;
    if context.next_sequence != 1 || context.predecessor_digest != [0; 32] {
        return Err(SignerOperationErrorV1::ReservationConflict);
    }
    let enrollment = verify_signer_custody_enrollment_v1(record, binding, trust, &context)
        .map_err(SignerOperationErrorV1::Custody)?;
    let committed = source.enroll_initial(&SignerCustodyEnrollmentRequestV1 {
        record,
        enrollment: &enrollment,
    })?;
    let active = verify_activation(record, binding, trust, &enrollment, &committed)?;
    let final_state =
        verify_signer_custody_use_v1(record, binding, trust, &source.observe(binding)?)
            .map_err(SignerOperationErrorV1::Custody)?;
    if !final_state.continues_active_state(&active) {
        return Err(SignerOperationErrorV1::CustodyChanged);
    }
    Ok(final_state)
}

/// Private prepared successor; it contains public metadata and independent trust, never key bytes.
// TODO: Compile the private terminal-transition helpers outside tests when a production control
// producer owns their independently governed successor configuration and durable terminal audit.
#[cfg(test)]
pub(in crate::signer_operation) struct PreparedSignerCustodyActivationV1 {
    binding: SignerCustodyBindingV1,
    record: Vec<u8>,
    trust: SignerCustodyTrustV1,
    context: SignerCustodyEnrollmentContextV1,
    enrollment: VerifiedSignerCustodyEnrollmentV1,
}
#[cfg(test)]
impl PreparedSignerCustodyActivationV1 {
    pub(in crate::signer_operation) fn record_digest(&self) -> [u8; 32] {
        self.enrollment.record_digest()
    }
}

#[cfg(test)]
impl SignerOperationCoordinatorV1 {
    /// Prepare only against independently governed expected successor configuration and trust.
    pub(in crate::signer_operation) fn prepare_custody_activation(
        &self,
        source: &dyn SignerCustodyEnrollmentStateSourceV1,
        binding: SignerCustodyBindingV1,
        record: Vec<u8>,
        trust: SignerCustodyTrustV1,
    ) -> Result<PreparedSignerCustodyActivationV1, SignerOperationErrorV1> {
        validate_successor(&self.binding, &binding)?;
        let context = source.observe_enrollment(&binding)?;
        let enrollment = verify_signer_custody_enrollment_v1(&record, &binding, &trust, &context)
            .map_err(SignerOperationErrorV1::Custody)?;
        Ok(PreparedSignerCustodyActivationV1 {
            binding,
            record,
            trust,
            context,
            enrollment,
        })
    }
}

#[cfg(test)]
fn validate_successor(
    previous: &SignerCustodyBindingV1,
    next: &SignerCustodyBindingV1,
) -> Result<(), SignerOperationErrorV1> {
    let same_key = next.public_key == previous.public_key
        && next.key_handle == previous.key_handle
        && next.algorithm == previous.algorithm
        && next.key_revision == previous.key_revision;
    let new_key = next.public_key != previous.public_key
        && next.key_handle != previous.key_handle
        && next.key_revision > previous.key_revision;
    let same_policy = next.policy_digest == previous.policy_digest
        && next.policy_revision == previous.policy_revision;
    let new_policy = next.policy_digest != previous.policy_digest
        && next.policy_revision > previous.policy_revision;
    if previous.chain_id != next.chain_id
        || previous.network_id != next.network_id
        || previous.runtime_handle != next.runtime_handle
        || previous.service_id != next.service_id
        || previous.administrator_id != next.administrator_id
        || previous.role != next.role
        || previous.purpose != next.purpose
        || !(same_key || new_key)
        || !(same_policy || new_policy)
    {
        return Err(SignerOperationErrorV1::InvalidOperation);
    }
    Ok(())
}

fn verify_activation(
    record: &[u8],
    binding: &SignerCustodyBindingV1,
    trust: &SignerCustodyTrustV1,
    enrollment: &VerifiedSignerCustodyEnrollmentV1,
    current: &SignerCustodyUseContextV1,
) -> Result<VerifiedSignerCustodyV1, SignerOperationErrorV1> {
    let active = verify_signer_custody_use_v1(record, binding, trust, current)
        .map_err(SignerOperationErrorV1::Custody)?;
    if active.record_digest() != enrollment.record_digest()
        || active.current_anchor().height <= enrollment.statement().anchor.height
        || active.current_anchor().state_digest == enrollment.statement().anchor.state_digest
        || active.verified_at_unix_ms() < enrollment.verified_at_unix_ms()
    {
        return Err(SignerOperationErrorV1::CustodyChanged);
    }
    Ok(active)
}

#[cfg(test)]
impl SignerOperationV1<'_> {
    fn prepare_terminal(
        &mut self,
        audit: SignerOperationAuditHeadV1,
        transition_digest: [u8; 32],
    ) -> Result<(), SignerOperationErrorV1> {
        if self.poisoned {
            return Err(SignerOperationErrorV1::Poisoned);
        }
        if self.intent.request_digest
            != signer_custody_transition_request_digest_v1(
                self.intent.action,
                self.intent.operation_id,
                self.custody.record_digest(),
                self.intent.previous_audit,
                transition_digest,
            )?
            || audit.sequence != self.intent.previous_audit.sequence + 1
            || audit.digest == [0; 32]
            || audit.digest == self.intent.previous_audit.digest
            || self.signatures.len() != 1
            || self.signatures[0].purpose != SignerKeyOperationPurposeV1::AuditRecord
            || self.signatures[0].message_digest
                != digest_parts(
                    b"iroha.sorafs.signer.operation.message.v1",
                    &[&audit.signing_message()],
                )
        {
            return Err(SignerOperationErrorV1::InvalidOperation);
        }
        self.refresh_reserved(SignerReservedObservationPhaseV1::BeforeCommit)
    }

    /// Finalize an old-key audit and activate the exact independent successor without old-key reply.
    pub(in crate::signer_operation) fn finish_custody_activation(
        mut self,
        source: &dyn SignerCustodyControlStateSourceV1,
        prepared: &PreparedSignerCustodyActivationV1,
        audit: SignerOperationAuditHeadV1,
    ) -> Result<CompletedSignerCustodyTransitionV1, SignerOperationErrorV1> {
        if self.intent.action != SignerOperationActionV1::ActivateCustody {
            return Err(SignerOperationErrorV1::InvalidOperation);
        }
        self.prepare_terminal(audit, prepared.record_digest())?;
        if prepared.enrollment.statement().predecessor_digest != self.custody.record_digest()
            || self.custody.statement().sequence.checked_add(1)
                != Some(prepared.enrollment.statement().sequence)
            || prepared.context.current_anchor.state_digest
                != self.custody.current_anchor().state_digest
            || prepared.context.current_anchor.height > self.custody.current_anchor().height
            || (prepared.context.current_anchor.height == self.custody.current_anchor().height
                && prepared.context.current_anchor.block_hash
                    != self.custody.current_anchor().block_hash)
            || prepared.enrollment.verified_at_unix_ms() > self.custody.verified_at_unix_ms()
        {
            return Err(SignerOperationErrorV1::ReservationConflict);
        }
        // Recheck signed validity using fresh independently authenticated time, retaining the
        // original observed approval anchor. No candidate field is converted into current trust.
        let mut context = prepared.context;
        context.now_unix_ms = self.custody.verified_at_unix_ms();
        let enrollment = verify_signer_custody_enrollment_v1(
            &prepared.record,
            &prepared.binding,
            &prepared.trust,
            &context,
        )
        .map_err(SignerOperationErrorV1::Custody)?;
        let current = source.commit_custody_transition(&SignerCustodyTransitionRequestV1 {
            check: self.check(),
            audit,
            transition_digest: enrollment.record_digest(),
            activation: Some(SignerCustodyEnrollmentRequestV1 {
                record: &prepared.record,
                enrollment: &enrollment,
            }),
        })?;
        let active = verify_activation(
            &prepared.record,
            &prepared.binding,
            &prepared.trust,
            &enrollment,
            &current,
        )?;
        if active.current_anchor().height <= self.custody.current_anchor().height
            || active.verified_at_unix_ms() < self.custody.verified_at_unix_ms()
        {
            return Err(SignerOperationErrorV1::CustodyChanged);
        }
        let final_state = verify_signer_custody_use_v1(
            &prepared.record,
            &prepared.binding,
            &prepared.trust,
            &source.observe(&prepared.binding)?,
        )
        .map_err(SignerOperationErrorV1::Custody)?;
        if !final_state.continues_active_state(&active) {
            return Err(SignerOperationErrorV1::CustodyChanged);
        }
        Ok(CompletedSignerCustodyTransitionV1 {
            action: self.intent.action,
            audit,
            transition_digest: enrollment.record_digest(),
            activation: Some(final_state),
        })
    }

    /// Finalize the old-key revocation audit, revoke custody, and return only transition metadata.
    pub(in crate::signer_operation) fn finish_custody_revocation(
        mut self,
        source: &dyn SignerCustodyControlStateSourceV1,
        reason_digest: [u8; 32],
        audit: SignerOperationAuditHeadV1,
    ) -> Result<CompletedSignerCustodyTransitionV1, SignerOperationErrorV1> {
        if self.intent.action != SignerOperationActionV1::RevokeCustody {
            return Err(SignerOperationErrorV1::InvalidOperation);
        }
        self.prepare_terminal(audit, reason_digest)?;
        let current = source.commit_custody_transition(&SignerCustodyTransitionRequestV1 {
            check: self.check(),
            audit,
            transition_digest: reason_digest,
            activation: None,
        })?;
        self.verify_revocation(&current)?;
        let final_state = source.observe(&self.coordinator.binding)?;
        self.verify_revocation(&final_state)?;
        if final_state.now_unix_ms < current.now_unix_ms
            || final_state.current_anchor.height < current.current_anchor.height
            || final_state.current_anchor.state_digest != current.current_anchor.state_digest
            || (final_state.current_anchor.height == current.current_anchor.height
                && final_state.current_anchor.block_hash != current.current_anchor.block_hash)
        {
            return Err(SignerOperationErrorV1::CustodyChanged);
        }
        Ok(CompletedSignerCustodyTransitionV1 {
            action: self.intent.action,
            audit,
            transition_digest: reason_digest,
            activation: None,
        })
    }

    fn verify_revocation(
        &self,
        current: &SignerCustodyUseContextV1,
    ) -> Result<(), SignerOperationErrorV1> {
        let statement = self.custody.statement();
        if !current.signer_revoked
            || current.attester_revoked
            || current.active_head.record_digest != self.custody.record_digest()
            || current.active_head.sequence != statement.sequence
            || current.active_head.approved_anchor != statement.anchor
            || current.active_head.key_revision != statement.binding.key_revision
            || current.active_head.policy_revision != statement.binding.policy_revision
            || current.active_head.policy_digest != statement.binding.policy_digest
            || current.current_anchor.height <= self.custody.current_anchor().height
            || current.current_anchor.block_hash == [0; 32]
            || current.current_anchor.state_digest == [0; 32]
            || current.current_anchor.state_digest == self.custody.current_anchor().state_digest
            || current.now_unix_ms < self.custody.verified_at_unix_ms()
            || current.now_unix_ms >= self.reservation.expires_at_unix_ms
            || current.now_unix_ms >= self.coordinator.trust.active_until_unix_ms
            || current.now_unix_ms >= statement.expires_at_unix_ms
            || current.anchor_observed_at_unix_ms > current.now_unix_ms
            || current.now_unix_ms - current.anchor_observed_at_unix_ms
                > self.coordinator.trust.max_anchor_age_ms
        {
            return Err(SignerOperationErrorV1::CustodyChanged);
        }
        // This is deliberately not a key-use observation: no verified-use object or signature
        // is returned for revoked custody, and no provider operation follows this point.
        Ok(())
    }
}
