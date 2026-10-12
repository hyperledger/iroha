//! Current SCCP certificate projection of one genuinely verified native Global receipt.
//!
//! The source reader owns authentication and acquisition. This producer borrows that original
//! receipt, preserves its exact X, body digest, QC and historical signing committee, and checks
//! the destination relation using one caller-funded pairing context. No World roster or
//! self-supplied certificate can enter this producer.

use std::alloc::Layout;

use crate::sumeragi::certified_chain::{CertifiedBlock, QcVerification};
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedBuffer,
    PrepaidBufferError,
};
use iroha_crypto::{Algorithm, bls::consensus::ConsensusAggregateScratch};
use iroha_data_model::block::consensus::{SumeragiRootScope, is_valid_committee_size};
use iroha_sccp::{
    api::{ApiShapeError, SccpCertificateV1},
    v1::finality::{
        CertificateError, QcFixedV1, X_LEN, body_digest, signers_from_bitmap,
        verify_certificate_with_scratch,
    },
};

/// Why an original native certificate cannot be projected into the SCCP wire form.
#[derive(Debug, thiserror::Error)]
pub enum SccpCertificateReadError {
    /// Genesis, private-root authority or inconsistent native fields cannot supply this proof.
    #[error("native SCCP certificate source differs: {0}")]
    Source(&'static str),
    /// The original caller pool refused the whole destination and pairing reservation.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// Exact prepaid destination allocation failed.
    #[error(transparent)]
    Backing(#[from] PrepaidBufferError),
    /// The current external certificate relation rejected the native projection.
    #[error(transparent)]
    Certificate(#[from] CertificateError),
    /// The projected API shape differs from the current fixed layout.
    #[error(transparent)]
    Shape(#[from] ApiShapeError),
}

/// Move-only response graph retaining its exact original committee allocation.
///
/// Safe access borrows only. The integrating reader retains its original request admission
/// and separately funds source/decoder and encoded HTTP response ownership. This object
/// does not establish that its historical height is the current State tip.
pub struct RetainedSccpCertificate {
    certificate: SccpCertificateV1,
    // Drop order reclaims the actual Vec before refunding its backing allocation.
    _committee: AllocationCharge,
}
impl RetainedSccpCertificate {
    /// Borrow the certified wire projection while its original allocation remains funded.
    #[must_use]
    pub fn certificate(&self) -> &SccpCertificateV1 {
        &self.certificate
    }

    // The only enclosing message owner moves both values directly into its immutable
    // body-before-charge layout without fallible work between extraction and publication.
    pub(super) fn into_parts(self) -> (SccpCertificateV1, AllocationCharge) {
        (self.certificate, self._committee)
    }
}

/// Project and independently verify one original native Global CommitQC.
///
/// One reservation admits the complete committee destination and cryptographic scratch
/// before any allocation. No partial destination is created on original capacity refusal.
/// The historical committee is borrowed from this receipt's authenticated schedule, including
/// the outgoing committee on a rotation height. Genesis never fabricates a CommitQC.
///
/// # Errors
/// Refuses unsupported authority, mismatched original fields, resource admission, allocation,
/// certificate relation and wire shape. The original capacity refusal remains typed.
pub fn certificate_from_native(
    block: &CertifiedBlock,
    budget: &AllocationBudget,
) -> Result<RetainedSccpCertificate, SccpCertificateReadError> {
    let draft = NativeCertificateDraft::new(block)?;
    let mut reservation = budget.try_reserve_bytes(draft.demand()?)?;
    draft.materialize(&mut reservation)
}

/// Borrow the same authenticated source while an enclosing operation admits its entire graph.
#[derive(Clone, Copy)]
pub(super) struct NativeCertificateDraft<'a> {
    block: &'a CertifiedBlock,
    fixed: [u8; 116],
    committee_layout: Layout,
    pairing_layout: Layout,
}
impl<'a> NativeCertificateDraft<'a> {
    pub(super) fn new(block: &'a CertifiedBlock) -> Result<Self, SccpCertificateReadError> {
        use SccpCertificateReadError::Source;
        if block.verification() != QcVerification::Verified
            || block.root_scope() != SumeragiRootScope::Global
        {
            return Err(Source("requires verified non-genesis Global authority"));
        }
        let qc = block.commit_qc().ok_or(Source("CommitQC missing"))?;
        let original = block
            .certificate()
            .ok_or(Source("original certificate missing"))?;
        let x = block.certified_result().header();
        if original.result_preimage().get(..X_LEN) != Some(x.as_bytes().as_slice()) {
            return Err(Source("original X differs"));
        }
        let body = original
            .result_preimage()
            .get(X_LEN..)
            .ok_or(Source("original body missing"))?;
        let members = &block.commitment().schedule.current.committee;
        if !is_valid_committee_size(members.len()) {
            return Err(Source("historical committee geometry"));
        }
        let fixed = QcFixedV1 {
            epoch: qc.epoch.epoch,
            epoch_context: qc.epoch.context.0,
            view: qc.view,
            block_hash: qc.block_hash.0,
            result_body: body_digest(body),
            signers: signers_from_bitmap(qc.signers.as_bytes(), members.len())
                .ok_or(Source("original signer bitmap"))?,
        }
        .encode();
        let committee_layout = Layout::array::<[u8; 48]>(members.len())
            .map_err(|_| AllocationRefusal::DemandOverflow)?;
        let pairing_layout = Layout::array::<u8>(ConsensusAggregateScratch::<()>::backing_bytes())
            .map_err(|_| AllocationRefusal::DemandOverflow)?;
        Ok(Self {
            block,
            fixed,
            committee_layout,
            pairing_layout,
        })
    }
    pub(super) fn demand(&self) -> Result<usize, AllocationRefusal> {
        self.committee_layout
            .size()
            .checked_add(self.pairing_layout.size())
            .ok_or(AllocationRefusal::DemandOverflow)
    }
    #[allow(
        unsafe_code,
        reason = "exact original buffer and charge move together into a closed immutable owner before fallible work"
    )]
    pub(super) fn materialize(
        self,
        reservation: &mut AllocationReservation,
    ) -> Result<RetainedSccpCertificate, SccpCertificateReadError> {
        use SccpCertificateReadError::Source;
        let Self {
            block,
            fixed,
            pairing_layout,
            ..
        } = self;
        let qc = block.commit_qc().ok_or(Source("CommitQC missing"))?;
        let x = block.certified_result().header();
        let members = &block.commitment().schedule.current.committee;
        let mut committee = ChargedBuffer::from_reservation(members.len(), reservation)?;
        for member in members {
            let (algorithm, bytes) = member
                .validator
                .public_key()
                .borrowed_parts()
                .map_err(|_| Source("original key encoding"))?;
            if algorithm != Algorithm::BlsNormal {
                return Err(Source("original key suite"));
            }
            committee.push_reserved(
                <[u8; 48]>::try_from(bytes).map_err(|_| Source("original key length"))?,
            );
        }
        let mut scratch = ConsensusAggregateScratch::new(|bytes| {
            if bytes != pairing_layout.size() {
                return Err(Source("pairing layout changed"));
            }
            reservation
                .try_split(pairing_layout)
                .map_err(|_| Source("pairing prepayment differs"))
        })?;
        let verified = verify_certificate_with_scratch(
            &qc.instance.0,
            &fixed,
            x.as_bytes(),
            &qc.agg_sig.0,
            committee.as_slice(),
            &mut scratch,
        )?;
        if verified.result != block.result().0
            || verified.result != qc.result.0
            || qc.height != block.height()
        {
            return Err(Source(
                "projection changed original signed result or height",
            ));
        }
        // SAFETY: the exact scalar-key backing moves with its original charge, before any
        // fallible operation; no accessor permits replacement, growth or an uncharged move-out.
        let (committee, charge) = unsafe { committee.into_allocation_parts() };
        let retained = RetainedSccpCertificate {
            certificate: SccpCertificateV1 {
                height: block.height(),
                qc: fixed,
                aggregate_signature: qc.agg_sig.0,
                header: *x.as_bytes(),
                committee,
            },
            _committee: charge,
        };
        retained.certificate.check_shape()?;
        Ok(retained)
    }
}

#[cfg(test)]
mod tests;
