//! Original-funded bulk certificate fields and resultless proposal bytes for prefix reads.
//!
//! TODO(S8): decoded result/genesis/schedule graphs and shared validation error diagnostics
//! still require original-pool custody on SCCP restore. This job owns the canonical metadata,
//! table and proposal graphs; the admitted verifier separately owns exact RS16 scratch.

#[cfg(test)]
use std::io;

use iroha_allocation::AllocationBudget;
#[cfg(test)]
use iroha_data_model::block::SignedBlock;
use iroha_sumeragi::{
    availability::{AvailabilityFrame, PayloadBytes},
    message::{BlockHeader, Qc},
};

use super::{ChainReadError, MAX_PROPOSAL_BYTES};
use crate::sumeragi::{
    block_store::certificate_read::{
        CertificateRead, CertificateReadError, FundedDecodedCertificate,
    },
    driver::payload_build::{PayloadBuild, PayloadBuildError},
};

pub(in crate::sumeragi) mod metadata;

enum Stage {
    Certificate(CertificateRead),
    Projecting(PayloadBuild<FundedDecodedCertificate>),
    Consumed,
}

/// Exact original carrier and every partial funded destination, retained before cursor advance.
#[must_use = "dropping this reader cancels the original pending acquisition"]
pub(in crate::sumeragi) struct PrefixArtifactsRead {
    budget: AllocationBudget,
    stage: Stage,
}
impl PrefixArtifactsRead {
    pub(in crate::sumeragi) fn new(
        source: iroha_data_model::block::SharedSignedBlock,
        budget: AllocationBudget,
    ) -> Self {
        Self {
            stage: Stage::Certificate(CertificateRead::new(source, budget.clone())),
            budget,
        }
    }

    /// Retain original source and partial backing on every failure. A foreign pool cannot
    /// replace a captured pool, even if its ceiling or remaining bytes happen to match.
    #[expect(
        clippy::result_large_err,
        reason = "return original funded source and partial backing without allocating on refusal"
    )]
    pub(in crate::sumeragi) fn complete(
        mut self,
        budget: &AllocationBudget,
    ) -> Result<PrefixArtifacts, (Self, PrefixArtifactsError)> {
        if !self.budget.same_pool(budget) {
            return Err((self, PrefixArtifactsError::ForeignPool));
        }
        loop {
            match std::mem::replace(&mut self.stage, Stage::Consumed) {
                Stage::Certificate(read) => match read.complete_for_prefix(budget) {
                    Ok(decoded) => {
                        self.stage = Stage::Projecting(PayloadBuild::new(
                            decoded,
                            self.budget.clone(),
                            MAX_PROPOSAL_BYTES,
                        ));
                    }
                    Err((read, error)) => {
                        self.stage = Stage::Certificate(read);
                        return Err((self, PrefixArtifactsError::Certificate(error)));
                    }
                },
                Stage::Projecting(read) => match read.finish(
                    |decoded| decoded.source.resultless_proposal_wire_len(),
                    |decoded, writer| decoded.source.write_resultless_proposal_wire(writer),
                ) {
                    Ok((decoded, payload)) => {
                        return Ok(PrefixArtifacts { decoded, payload });
                    }
                    Err((read, error)) => {
                        self.stage = Stage::Projecting(read);
                        return Err((self, PrefixArtifactsError::Projection(error)));
                    }
                },
                Stage::Consumed => {
                    return Err((self, PrefixArtifactsError::Consumed));
                }
            }
        }
    }
}

/// Failure without a diagnostic allocation or replacement of the original acquisition.
#[derive(Debug)]
pub(in crate::sumeragi) enum PrefixArtifactsError {
    ForeignPool,
    Certificate(CertificateReadError),
    Projection(PayloadBuildError),
    Consumed,
}
impl PrefixArtifactsError {
    #[cfg(test)]
    pub(in crate::sumeragi) fn kind(&self) -> io::ErrorKind {
        match self {
            Self::Certificate(CertificateReadError::Admission(error))
            | Self::Projection(PayloadBuildError::Admission(error))
                if error.is_local_refusal() =>
            {
                io::ErrorKind::WouldBlock
            }
            Self::Certificate(CertificateReadError::Canonical(original))
                if original.kind() != norito::core::DecodeAttemptErrorKind::Invalid =>
            {
                io::ErrorKind::WouldBlock
            }
            // A decoder-level allocator refusal also cannot prove malformed bytes.
            Self::Certificate(CertificateReadError::Decode(norito::Error::AllocationFailed {
                ..
            })) => io::ErrorKind::WouldBlock,
            _ => io::ErrorKind::InvalidData,
        }
    }
}
impl std::fmt::Display for PrefixArtifactsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForeignPool => {
                formatter.write_str("prefix artifacts use a foreign allocation pool")
            }
            Self::Certificate(error) => error.fmt(formatter),
            Self::Projection(PayloadBuildError::Admission(error)) => error.fmt(formatter),
            Self::Projection(PayloadBuildError::Encoding(error)) => error.fmt(formatter),
            Self::Projection(PayloadBuildError::TooLarge | PayloadBuildError::Poisoned) => {
                formatter.write_str("prefix proposal cannot produce its bounded canonical payload")
            }
            Self::Consumed => formatter.write_str("prefix artifacts already consumed"),
        }
    }
}
impl std::error::Error for PrefixArtifactsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Certificate(error) => Some(error),
            Self::Projection(PayloadBuildError::Admission(error)) => Some(error),
            Self::Projection(PayloadBuildError::Encoding(error)) => Some(error),
            _ => None,
        }
    }
}

/// Sealed source-bound decoded artifacts; this grants no certificate or execution authority.
#[derive(Clone)]
pub(crate) struct PrefixArtifacts {
    decoded: FundedDecodedCertificate,
    payload: PayloadBytes,
}
impl PrefixArtifacts {
    pub(crate) fn source(&self) -> &iroha_data_model::block::SharedSignedBlock {
        &self.decoded.source
    }

    /// Borrow the original immutable header owner without redecoding or copying its keys.
    pub(super) fn header(&self) -> &metadata::FundedMetadata<BlockHeader> {
        &self.decoded.header
    }

    /// Require the same original pool for every completed metadata and bulk owner.
    pub(super) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.decoded.header.belongs_to(budget)
            && self.decoded.commit_qc.belongs_to(budget)
            && self.decoded.availability.admitted_to(budget)
            && self.payload.admitted_to(budget)
    }

    /// Release the quorum and bulk owners for the receipt verified from this exact carrier.
    ///
    /// A prepared receipt must hold this same funded header owner: the sole metadata decoder
    /// produced both, so a value comparison would only compare the header with itself.
    /// A different carrier or header owner is local custody misuse, never a verdict on the
    /// stored bytes. A separately decoded header must still equal the decoded value.
    pub(super) fn into_parts(
        self,
        source: &iroha_data_model::block::SharedSignedBlock,
        header: &super::PrefixHeader,
    ) -> Result<
        (
            metadata::FundedMetadata<Qc>,
            AvailabilityFrame,
            PayloadBytes,
        ),
        super::VerificationReadError,
    > {
        let same_owner = match header {
            super::PrefixHeader::Funded(header) => header.same_owner(&self.decoded.header),
            super::PrefixHeader::Decoded(_) => true,
        };
        if !iroha_data_model::block::SharedSignedBlock::ptr_eq(source, &self.decoded.source)
            || !same_owner
        {
            return Err(super::VerificationReadError::Deferred(
                super::retained_query_authority::invariant(),
            ));
        }
        if let super::PrefixHeader::Decoded(header) = header
            && header != &*self.decoded.header
        {
            return Err(ChainReadError::HeaderMismatch {
                height: source.header().height().get(),
            }
            .into());
        }
        Ok((
            self.decoded.commit_qc,
            self.decoded.availability,
            self.payload,
        ))
    }
}

#[cfg(test)]
mod tests;
