//! Current certificate and proof verification before a wallet pays destination fees (§7.1).
//!
//! Destination identity, current committee, latch, TON keys and checkpoint observations come
//! from the selected destination state. Torii supplies candidates only. The shared destination
//! certificate kernel preserves its exact current-generation and cached-header checks. Proofs
//! then bind the actual block, payload, route, recipient, cause and deadline.

use core::fmt;
use std::collections::BTreeMap;

use iroha_sccp::{
    api::{ApiShapeError, SccpCertificateV1, SccpMessageProofBundleV1},
    v1::{
        committee::{CommitteeError, CommitteeStateV1},
        destination::{
            CertificateAuthorityV1, CheckpointRefV1, DestinationFlavor, MessageProofV1,
            TairaCertificateV1,
        },
        destination_abi::DestinationError,
        finality::{QcFixedV1, SccpFinalityHeaderV1, checkpoint_id},
        proof::{DestinationV1, ProofError, VerifiedTransferV1, verify_transfer},
    },
};

/// One coherent destination observation against which candidate bundles are checked.
#[derive(Debug, Clone, Copy)]
pub struct DestinationContextV1<'a> {
    /// Taira network selected by the destination deployment.
    pub taira_network_id: [u8; 32],
    /// Original consensus instance bound into the destination deployment.
    pub consensus_instance: [u8; 32],
    /// Target network, route revision and contract word.
    pub destination: DestinationV1,
    /// Contract's verification flavour.
    pub flavor: DestinationFlavor,
    /// The actual current committee, including its independently read equivocation latch.
    pub committee_state: CommitteeStateV1,
    /// TON's original stored canonical key list; EVM reads certificate keys.
    pub ton_keys: Option<&'a [[u8; 48]]>,
    /// Checkpoint ids read at the same selected destination state, keyed by their actual heights.
    pub checkpoints: &'a BTreeMap<u64, [u8; 32]>,
    /// Destination time expected for execution, in milliseconds.
    pub now_ms: u64,
}

/// Which current entry-point source the caller intends to submit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateUseV1 {
    /// Submit the native certificate inline; the current generation must accept it.
    Inline,
    /// Use an exact header already stored at the destination; U1/U2 must still accept it.
    Checkpoint,
}

/// Deadline side required by the destination entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundlePurposeV1 {
    /// Mint at or before the deadline.
    Finalize,
    /// Void strictly after the deadline.
    VoidExpired,
}

/// A candidate bundle failed one of the destination checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleError {
    /// A candidate exceeds a bound or breaks its current API shape.
    Shape(ApiShapeError),
    /// A certificate, checkpoint or committee check failed.
    Certificate(DestinationError),
    /// The header's redundant height or selected network does not match.
    HeaderMismatch,
    /// The finality statement cannot be represented in the destination's wire form.
    CertificateEncoding,
    /// The actual block, leaf or payload failed inclusion or identity checks.
    Proof(ProofError),
    /// The bundle's message id differs from the recomputed payload id.
    MessageIdMismatch,
    /// The redundant deadline differs from the payload's deadline.
    DeadlineMismatch,
    /// A mint is past its deadline.
    DeadlinePassed,
    /// A void is at or before its deadline.
    DeadlineNotReached,
}
impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shape(e) => write!(f, "bundle shape: {e}"),
            Self::Certificate(e) => write!(f, "destination certificate: {e}"),
            Self::HeaderMismatch => f.write_str(
                "certificate header does not match its height or selected Taira network",
            ),
            Self::CertificateEncoding => {
                f.write_str("certificate has no current destination encoding")
            }
            Self::Proof(e) => write!(f, "message proof: {e}"),
            Self::MessageIdMismatch => f.write_str("message id differs from the payload's id"),
            Self::DeadlineMismatch => f.write_str("deadline differs from the payload's deadline"),
            Self::DeadlinePassed => f.write_str("the mint deadline has passed"),
            Self::DeadlineNotReached => f.write_str("the mint deadline has not passed"),
        }
    }
}
impl std::error::Error for BundleError {}
impl From<ApiShapeError> for BundleError {
    fn from(error: ApiShapeError) -> Self {
        Self::Shape(error)
    }
}
impl From<DestinationError> for BundleError {
    fn from(error: DestinationError) -> Self {
        Self::Certificate(error)
    }
}

pub(super) const fn committee_error(error: CommitteeError) -> DestinationError {
    match error {
        CommitteeError::Equivocated => DestinationError::Equivocated,
        CommitteeError::Expired
        | CommitteeError::NotCurrent
        | CommitteeError::CheckpointRetired => DestinationError::CommitteeNotAccepted,
        CommitteeError::LatchRequired => DestinationError::LatchRequired,
    }
}

/// A verified entry-point source. Fields stay private so callers cannot replace its header or wire bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCertificateV1 {
    pub(super) header: SccpFinalityHeaderV1,
    pub(super) source: VerifiedCertificateSourceV1,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum VerifiedCertificateSourceV1 {
    Inline(TairaCertificateV1),
    Checkpoint(CheckpointRefV1),
}
impl VerifiedCertificateV1 {
    /// The exact verified header, borrowed without reconstructing it.
    #[must_use]
    pub const fn header(&self) -> &SccpFinalityHeaderV1 {
        &self.header
    }
    /// Whether the entry point uses a stored checkpoint.
    #[must_use]
    pub const fn is_checkpoint(&self) -> bool {
        matches!(self.source, VerifiedCertificateSourceV1::Checkpoint(_))
    }
}

/// Convert the API certificate into the current destination wire forms.
/// This conversion authenticates nothing; the shared verification kernel must still run.
///
/// # Errors
/// Returns a shape or certificate-encoding error for malformed candidates.
pub fn certificate_wire(
    certificate: &SccpCertificateV1,
) -> Result<TairaCertificateV1, BundleError> {
    certificate.check_shape()?;
    let qc = QcFixedV1::parse(&certificate.qc).map_err(|_| BundleError::CertificateEncoding)?;
    let header = SccpFinalityHeaderV1::parse(&certificate.header)
        .map_err(|_| BundleError::CertificateEncoding)?;
    TairaCertificateV1::new(
        &qc,
        &header,
        &certificate.aggregate_signature,
        &certificate.committee,
    )
    .ok_or(BundleError::CertificateEncoding)
}

/// Verify an API certificate against the actual selected destination authority and source mode.
/// Inline use applies all V1–V3 refusal and Live rules to an isolated scalar copy; it never
/// installs a successor. Checkpoint use requires its exact stored id and current U1/U2 use rule.
///
/// # Errors
/// Returns the first failed shape, authority, checkpoint or certificate check.
pub fn verify_certificate_bundle(
    certificate: &SccpCertificateV1,
    context: &DestinationContextV1<'_>,
    usage: CertificateUseV1,
) -> Result<VerifiedCertificateV1, BundleError> {
    certificate.check_shape()?;
    let header = SccpFinalityHeaderV1::parse(&certificate.header)
        .map_err(|_| BundleError::HeaderMismatch)?;
    if header.height() != certificate.height
        || header.network_id() != context.taira_network_id
        || !header.is_active()
    {
        return Err(BundleError::HeaderMismatch);
    }
    let stored = context.checkpoints.get(&header.height());
    let source = match usage {
        CertificateUseV1::Inline => {
            let wire = certificate_wire(certificate)?;
            let authority = CertificateAuthorityV1::new(
                context.flavor,
                &context.taira_network_id,
                &context.consensus_instance,
                &context.committee_state,
                context.ton_keys,
            )?;
            let verified =
                authority.verify(&wire, |height| context.checkpoints.get(&height).copied())?;
            let mut committee = context.committee_state;
            committee
                .apply_inline(&verified.header, stored, context.now_ms)
                .map_err(committee_error)?;
            VerifiedCertificateSourceV1::Inline(wire)
        }
        CertificateUseV1::Checkpoint => {
            if stored != Some(&checkpoint_id(header.as_bytes())) {
                return Err(DestinationError::UnknownCheckpoint.into());
            }
            context
                .committee_state
                .require_checkpoint_use(&header, context.now_ms)
                .map_err(committee_error)?;
            VerifiedCertificateSourceV1::Checkpoint(CheckpointRefV1 {
                header: certificate.header.to_vec(),
            })
        }
    };
    Ok(VerifiedCertificateV1 { header, source })
}

/// A proof verified for one deployment and purpose. Wire fields cannot be changed after verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMessageBundleV1 {
    pub(super) certificate: VerifiedCertificateV1,
    pub(super) proof: MessageProofV1,
    pub(super) transfer: VerifiedTransferV1,
    pub(super) purpose: BundlePurposeV1,
}
impl VerifiedMessageBundleV1 {
    /// Whether inclusion traverses the selected header's history root.
    #[must_use]
    pub fn is_historical(&self) -> bool {
        self.proof.block.height < self.certificate.header.height()
    }
    /// Whether the transaction names a stored checkpoint.
    #[must_use]
    pub const fn is_checkpoint(&self) -> bool {
        self.certificate.is_checkpoint()
    }
    /// The destination nonce whose consumed bit must be checked before submitting.
    #[must_use]
    pub fn nonce(&self) -> u64 {
        self.transfer.payload.nonce
    }
    /// The exact payload deadline.
    #[must_use]
    pub fn deadline_ms(&self) -> u64 {
        self.transfer.payload.deadline_ms
    }
    /// Verified payload and computed message identity.
    #[must_use]
    pub const fn transfer(&self) -> &VerifiedTransferV1 {
        &self.transfer
    }
    /// Exact verified finality header.
    #[must_use]
    pub const fn header(&self) -> &SccpFinalityHeaderV1 {
        self.certificate.header()
    }
}

/// Check the deadline side required by the chosen entry point.
///
/// # Errors
/// Returns `DeadlinePassed` for a late mint or `DeadlineNotReached` for a premature void.
pub fn check_deadline(
    purpose: BundlePurposeV1,
    deadline_ms: u64,
    now_ms: u64,
) -> Result<(), BundleError> {
    match purpose {
        BundlePurposeV1::Finalize if now_ms > deadline_ms => Err(BundleError::DeadlinePassed),
        BundlePurposeV1::VoidExpired if now_ms <= deadline_ms => {
            Err(BundleError::DeadlineNotReached)
        }
        _ => Ok(()),
    }
}

/// Verify a message bundle, its current certificate source, actual block and leaf, payload and deadline.
/// The caller separately reads consumed state and runs the newest-control policy before paying.
///
/// # Errors
/// Returns the first failed candidate, authority, proof or deadline check.
pub fn verify_message_bundle(
    bundle: &SccpMessageProofBundleV1,
    context: &DestinationContextV1<'_>,
    purpose: BundlePurposeV1,
    usage: CertificateUseV1,
) -> Result<VerifiedMessageBundleV1, BundleError> {
    bundle.check_shape()?;
    let certificate = verify_certificate_bundle(&bundle.certificate, context, usage)?;
    let proof = bundle.message_proof();
    let transfer = verify_transfer(
        certificate.header(),
        &proof,
        &context.taira_network_id,
        &context.destination,
    )
    .map_err(BundleError::Proof)?;
    if transfer.message_id != bundle.message_id {
        return Err(BundleError::MessageIdMismatch);
    }
    if transfer.payload.deadline_ms != bundle.deadline_ms {
        return Err(BundleError::DeadlineMismatch);
    }
    check_deadline(purpose, transfer.payload.deadline_ms, context.now_ms)?;
    Ok(VerifiedMessageBundleV1 {
        certificate,
        proof,
        transfer,
        purpose,
    })
}

#[cfg(test)]
mod tests;
