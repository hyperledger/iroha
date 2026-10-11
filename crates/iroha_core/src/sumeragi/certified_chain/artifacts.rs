//! Original-funded bulk certificate fields and resultless proposal bytes for prefix reads.
//!
//! Metadata, decoded result/schedule graphs and cryptographic/RS16 scratch retain their own
//! accounting obligations. This job funds only the exact table, witness and proposal owners.

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
    block_store::certificate_read::{CertificateRead, CertificateReadError, DecodedCertificate},
    driver::payload_build::{PayloadBuild, PayloadBuildError},
};

enum Stage {
    Certificate(CertificateRead),
    Projecting(PayloadBuild<DecodedCertificate>),
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
                Stage::Certificate(read) => match read.complete(budget) {
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
            // The remaining bounded metadata decoder has no original-pool graph owner yet.
            // Physical refusal still does not prove malformed bytes: the original read keeps
            // its source and installs no partial metadata. Format bounds remain terminal.
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
pub(crate) struct PrefixArtifacts {
    decoded: DecodedCertificate,
    payload: PayloadBytes,
}
impl PrefixArtifacts {
    pub(crate) fn source(&self) -> &iroha_data_model::block::SharedSignedBlock {
        &self.decoded.source
    }

    pub(super) fn into_parts(
        self,
        source: &iroha_data_model::block::SharedSignedBlock,
        header: &BlockHeader,
    ) -> Result<(Qc, AvailabilityFrame, PayloadBytes), ChainReadError> {
        if !iroha_data_model::block::SharedSignedBlock::ptr_eq(source, &self.decoded.source)
            || header != &self.decoded.header
        {
            return Err(ChainReadError::HeaderMismatch {
                height: source.header().height().get(),
            });
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
