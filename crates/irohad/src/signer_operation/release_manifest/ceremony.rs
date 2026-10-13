//! Private canonical messages for one already-reserved release-manifest operation.
//!
//! This owner authenticates no external state and performs no key I/O. Its caller retains the
//! original verified custody and authoritative reservation; each use compares those immutable
//! inputs with the operation's fresh verified check. Prefix signatures prove exact messages, not
//! finality or completion. The generic role-13 software-provider gate remains closed.

use super::*;
use sorafs_manifest::signer::custody::SignerCustodyAnchorV1;
use std::borrow::Cow;

/// Exact reviewed subject and original reservation retained for all four canonical messages.
/// This private value grants no state authority, provider capability or signature-release right.
pub(in crate::signer_operation) struct ReleaseManifestCeremonyV1<'a> {
    binding: &'a SignerCustodyBindingV1,
    original_custody: &'a VerifiedSignerCustodyV1,
    manifest: &'a [u8],
    request: SignerReleaseManifestRequestV1,
    intent: SignerOperationIntentV1,
    reservation: SignerOperationReservationV1,
}

/// One canonical next message after validating the complete ordered signature prefix.
pub(in crate::signer_operation) struct ReleaseManifestMessageV1<'owner, 'inputs> {
    ceremony: &'owner ReleaseManifestCeremonyV1<'inputs>,
    purpose: SignerKeyOperationPurposeV1,
    ordinal: u8,
    bytes: Cow<'inputs, [u8]>,
}
impl ReleaseManifestMessageV1<'_, '_> {
    /// Recheck the receiving operation before any provider call.
    pub(in crate::signer_operation) fn validate_operation(
        &self,
        check: &SignerOperationReservationCheckV1<'_>,
    ) -> Result<(), SignerReleaseManifestErrorV1> {
        self.ceremony.validate_check(check)
    }

    /// Sole allowed semantic purpose at this prefix length.
    pub(in crate::signer_operation) const fn purpose(&self) -> SignerKeyOperationPurposeV1 {
        self.purpose
    }
    /// Exact one-based sub-operation position within the original reservation.
    pub(in crate::signer_operation) const fn ordinal(&self) -> u8 {
        self.ordinal
    }
    /// Exact manifest bytes or canonical domain-separated message, never a caller-selected digest.
    pub(in crate::signer_operation) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<'a> ReleaseManifestCeremonyV1<'a> {
    /// Pin the independently reviewed subject and compare it with the actual admitted operation.
    pub(in crate::signer_operation) fn new(
        binding: &'a SignerCustodyBindingV1,
        expected: &SignerReleaseManifestExpectedV1,
        manifest: &'a [u8],
        original_custody: &'a VerifiedSignerCustodyV1,
        check: &SignerOperationReservationCheckV1<'_>,
    ) -> Result<Self, SignerReleaseManifestErrorV1> {
        if binding != &original_custody.statement().binding {
            return Err(SignerOperationErrorV1::CustodyChanged.into());
        }
        let request = SignerReleaseManifestRequestV1::new(original_custody, expected, manifest)?;
        let intent = *check.request().intent();
        if intent.action != SignerOperationActionV1::Sign
            || intent.operation_id != request.operation_id
            || intent.request_digest != request.digest()?
        {
            return Err(SignerReceiptErrorV1::InvalidReceipt.into());
        }
        let ceremony = Self {
            binding,
            original_custody,
            manifest,
            request,
            intent,
            reservation: check.reservation(),
        };
        ceremony.validate_check(check)?;
        Ok(ceremony)
    }

    /// Derive only the next allowed message after verifying every previous canonical signature.
    /// The provenance anchor is captured after `AuditRecord` and retained unchanged for Response.
    pub(in crate::signer_operation) fn message(
        &self,
        check: &SignerOperationReservationCheckV1<'_>,
        purpose: SignerKeyOperationPurposeV1,
        prefix: &[SignerOperationSignatureV1],
        signing_anchor: Option<SignerCustodyAnchorV1>,
    ) -> Result<ReleaseManifestMessageV1<'_, 'a>, SignerReleaseManifestErrorV1> {
        self.validate_check(check)?;
        if required_purposes(SignerOperationActionV1::Sign).get(prefix.len()) != Some(&purpose)
            || signing_anchor.is_some() != (prefix.len() >= 2)
        {
            return Err(SignerOperationErrorV1::InvalidOperation.into());
        }
        if let Some(anchor) = signing_anchor {
            self.validate_anchor(check, anchor)?;
            if prefix.len() == 2 && anchor != check.request().custody().current_anchor() {
                return Err(SignerOperationErrorV1::CustodyChanged.into());
            }
        }
        self.validate_prefix(prefix, signing_anchor)?;
        Ok(ReleaseManifestMessageV1 {
            ceremony: self,
            purpose,
            ordinal: u8::try_from(prefix.len() + 1)
                .map_err(|_| SignerOperationErrorV1::InvalidOperation)?,
            bytes: self.message_at(prefix.len(), prefix, signing_anchor)?,
        })
    }

    /// Validate all four signatures and derive the exact receipt commitments before staging.
    /// These values remain private until the existing journal and native completion fences pass.
    pub(in crate::signer_operation) fn completion(
        self,
        check: &SignerOperationReservationCheckV1<'_>,
        prefix: &[SignerOperationSignatureV1],
        signing_anchor: SignerCustodyAnchorV1,
    ) -> Result<
        (SignerOperationProvenanceV1, SignerOperationCommitmentV1),
        SignerReleaseManifestErrorV1,
    > {
        self.validate_check(check)?;
        self.validate_anchor(check, signing_anchor)?;
        if prefix.len() != 4 {
            return Err(SignerReceiptErrorV1::InvalidSignature.into());
        }
        self.validate_prefix(prefix, Some(signing_anchor))?;
        let provenance = self.provenance(prefix, signing_anchor)?;
        let commitment = self.commitment(prefix, &provenance)?;
        Ok((provenance, commitment))
    }

    fn validate_check(
        &self,
        check: &SignerOperationReservationCheckV1<'_>,
    ) -> Result<(), SignerReleaseManifestErrorV1> {
        let custody = check.request().custody();
        if &custody.statement().binding != self.binding
            || SignerOperationCustodyV1::from_verified(custody) != self.request.original_custody
            || !custody.continues_active_state(self.original_custody)
        {
            return Err(SignerOperationErrorV1::CustodyChanged.into());
        }
        if check.request().intent() != &self.intent
            || check.request().intent_digest()
                != self
                    .intent
                    .digest()
                    .map_err(|_| SignerOperationErrorV1::InvalidOperation)?
        {
            return Err(SignerOperationErrorV1::InvalidOperation.into());
        }
        let reservation = check.reservation();
        let now = custody.verified_at_unix_ms();
        if reservation != self.reservation
            || reservation.reservation_id == [0; 32]
            || reservation.fence == 0
            || reservation.expires_at_unix_ms <= now
            || reservation.expires_at_unix_ms > custody.statement().expires_at_unix_ms
            || reservation.expires_at_unix_ms.saturating_sub(now) > MAX_RESERVATION_MS
        {
            return Err(SignerOperationErrorV1::ReservationConflict.into());
        }
        Ok(())
    }

    fn validate_anchor(
        &self,
        check: &SignerOperationReservationCheckV1<'_>,
        anchor: SignerCustodyAnchorV1,
    ) -> Result<(), SignerReleaseManifestErrorV1> {
        let original = self.original_custody.current_anchor();
        let current = check.request().custody().current_anchor();
        if anchor.height == 0
            || anchor.block_hash == [0; 32]
            || anchor.state_digest != self.request.original_custody.control_state_digest
            || anchor.height < original.height
            || (anchor.height == original.height && anchor != original)
            || anchor.height > current.height
            || (anchor.height == current.height && anchor != current)
        {
            return Err(SignerOperationErrorV1::CustodyChanged.into());
        }
        Ok(())
    }

    fn validate_prefix(
        &self,
        prefix: &[SignerOperationSignatureV1],
        signing_anchor: Option<SignerCustodyAnchorV1>,
    ) -> Result<(), SignerReleaseManifestErrorV1> {
        if prefix.len() > 4 {
            return Err(SignerReceiptErrorV1::InvalidSignature.into());
        }
        for (index, signature) in prefix.iter().enumerate() {
            let message = self.message_at(index, prefix, signing_anchor)?;
            if required_purposes(SignerOperationActionV1::Sign).get(index)
                != Some(&signature.purpose)
                || signature.signature.len() != 64
                || signature.message_digest != signer_operation_message_digest_v1(&message)
            {
                return Err(SignerReceiptErrorV1::InvalidSignature.into());
            }
            let parsed = Zeroizing::new(
                Signature::try_from_bytes(&signature.signature)
                    .map_err(|_| SignerReceiptErrorV1::InvalidSignature)?,
            );
            parsed
                .verify(&self.binding.public_key, &message)
                .map_err(|_| SignerReceiptErrorV1::InvalidSignature)?;
        }
        Ok(())
    }

    fn message_at(
        &self,
        index: usize,
        prefix: &[SignerOperationSignatureV1],
        signing_anchor: Option<SignerCustodyAnchorV1>,
    ) -> Result<Cow<'a, [u8]>, SignerReleaseManifestErrorV1> {
        match index {
            0 => Ok(Cow::Borrowed(self.manifest)),
            1 => Ok(Cow::Owned(self.audit(prefix)?.signing_message().to_vec())),
            2 | 3 => {
                let anchor = signing_anchor.ok_or(SignerReceiptErrorV1::InvalidReceipt)?;
                let provenance = self.provenance(prefix, anchor)?;
                let message = if index == 2 {
                    provenance.signing_message()?
                } else {
                    self.commitment(prefix, &provenance)?
                        .response_signing_message()
                };
                Ok(Cow::Owned(message.to_vec()))
            }
            _ => Err(SignerOperationErrorV1::InvalidOperation.into()),
        }
    }
    fn audit(
        &self,
        prefix: &[SignerOperationSignatureV1],
    ) -> Result<SignerOperationAuditHeadV1, SignerReleaseManifestErrorV1> {
        let signature = prefix
            .first()
            .ok_or(SignerReceiptErrorV1::InvalidSignature)?;
        Ok(signer_release_manifest_audit_v1(
            &self.request,
            &self.intent,
            self.reservation,
            &signature.signature,
        )?)
    }
    fn provenance(
        &self,
        prefix: &[SignerOperationSignatureV1],
        signing_anchor: SignerCustodyAnchorV1,
    ) -> Result<SignerOperationProvenanceV1, SignerReleaseManifestErrorV1> {
        Ok(SignerOperationProvenanceV1 {
            original_custody: self.request.original_custody,
            signing_anchor,
            intent_digest: self
                .intent
                .digest()
                .map_err(|_| SignerOperationErrorV1::InvalidOperation)?,
            reservation: self.reservation,
            audit: self.audit(prefix)?,
        })
    }
    fn commitment(
        &self,
        prefix: &[SignerOperationSignatureV1],
        provenance: &SignerOperationProvenanceV1,
    ) -> Result<SignerOperationCommitmentV1, SignerReleaseManifestErrorV1> {
        Ok(SignerOperationCommitmentV1 {
            audit: provenance.audit,
            response_digest: signer_release_manifest_response_digest_v1(
                &self.request,
                provenance,
                prefix
                    .get(..3)
                    .ok_or(SignerReceiptErrorV1::InvalidSignature)?,
            )?,
        })
    }
}
