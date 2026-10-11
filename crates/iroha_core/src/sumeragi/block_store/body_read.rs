//! Source-bound Kura projection, retaining exact certificate and proposal backing on refusal.

use std::io;
#[cfg(test)]
use std::sync::Arc;

use iroha_allocation::AllocationBudget;
use iroha_data_model::sumeragi_finality::result_of_preimage;
use iroha_sumeragi::{
    availability::{AvailabilitySource, BodyRestoration},
    message::{ByteAdmissionError, Qc, VoteKind},
};

use super::certificate_read::{CertificateRead, CertificateReadError, DecodedCertificate};
use crate::sumeragi::{
    body_read::{BodyReadError, BodyReadJob, BodyReadPoll},
    driver::{
        SharedCrypto,
        payload_build::{PayloadBuild, PayloadBuildError},
    },
};

/// The same original decode/projection can either return its QC to a committed reader or
/// let the ordinary body-read adapter release it before returning untrusted restoration input.
pub(super) enum StoredBodyReadPoll {
    Absent,
    Pending(ByteAdmissionError),
    Ready(BodyRestoration, Qc),
}

enum Stage {
    Absent,
    Certificate(CertificateRead),
    Decoded(DecodedCertificate),
    Projecting(PayloadBuild<DecodedCertificate>),
    Consumed,
}

/// A source selected independently of the committed frame, with one retained decode/projection.
/// The caller supplies None only for real absence, never for a failed Kura read below its tip.
pub(super) struct StoredBodyRead {
    source: AvailabilitySource,
    budget: AllocationBudget,
    crypto: SharedCrypto,
    stage: Stage,
}
impl StoredBodyRead {
    #[cfg(test)]
    pub(super) fn new(
        source: AvailabilitySource,
        block: Option<iroha_data_model::block::SharedSignedBlock>,
        budget: AllocationBudget,
        crypto: SharedCrypto,
    ) -> Self {
        let stage = block.map_or(Stage::Absent, |block| {
            Stage::Certificate(CertificateRead::new(block, budget.clone()))
        });
        Self {
            source,
            budget,
            crypto,
            stage,
        }
    }

    /// Transfer the same original decoded owners from full committed-certificate verification.
    pub(super) fn from_decoded(
        source: AvailabilitySource,
        decoded: DecodedCertificate,
        budget: AllocationBudget,
        crypto: SharedCrypto,
    ) -> Self {
        Self {
            source,
            budget,
            crypto,
            stage: Stage::Decoded(decoded),
        }
    }

    fn check(&self, decoded: &DecodedCertificate) -> Result<(), BodyReadError> {
        let header = &decoded.header;
        let qc = &decoded.commit_qc;
        let certificate = decoded
            .source
            .commit_certificate()
            .expect("decoded original certificate");
        let result = result_of_preimage(certificate.result_preimage());
        if decoded.source.header().height().get() != self.source.height()
            || !decoded.source.has_results()
            || header.instance != self.source.instance()
            || header.height != self.source.height()
            || header.epoch != self.source.config().epoch.id
            || header.hash(&*self.crypto) != self.source.block_hash()
            || qc.kind != VoteKind::Commit
            || qc.instance != header.instance
            || qc.epoch != header.epoch
            || qc.height != header.height
            || qc.block_hash != self.source.block_hash()
            || qc.result != result
        {
            return Err(BodyReadError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "stored certificate does not bind the independently requested body and result",
            )));
        }
        super::execution::validate(&decoded.source).map_err(BodyReadError::from_attempt)?;
        Ok(())
    }
}

impl StoredBodyRead {
    pub(super) fn poll_with_qc(
        &mut self,
        budget: &AllocationBudget,
    ) -> Result<StoredBodyReadPoll, BodyReadError> {
        if !self.budget.same_pool(budget) {
            return Err(BodyReadError::ForeignBudget);
        }
        loop {
            match std::mem::replace(&mut self.stage, Stage::Consumed) {
                Stage::Absent => return Ok(StoredBodyReadPoll::Absent),
                Stage::Certificate(job) => match job.complete(budget) {
                    Ok(decoded) => self.stage = Stage::Decoded(decoded),
                    Err((job, error)) => {
                        self.stage = Stage::Certificate(job);
                        return match error {
                            CertificateReadError::ForeignBudget => {
                                Err(BodyReadError::ForeignBudget)
                            }
                            CertificateReadError::MissingCertificate => {
                                Err(BodyReadError::Io(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "stored block has no certificate",
                                )))
                            }
                            CertificateReadError::Decode(error) => {
                                Err(BodyReadError::from_decode(error))
                            }
                            CertificateReadError::Admission(error) if error.is_local_refusal() => {
                                Ok(StoredBodyReadPoll::Pending(error))
                            }
                            CertificateReadError::Admission(error) => {
                                Err(BodyReadError::Admission(error))
                            }
                        };
                    }
                },
                Stage::Decoded(decoded) => {
                    if let Err(error) = self.check(&decoded) {
                        self.stage = Stage::Decoded(decoded);
                        return Err(error);
                    }
                    self.stage = Stage::Projecting(PayloadBuild::new(
                        decoded,
                        budget.clone(),
                        self.source.config().params.max_block_bytes as usize,
                    ));
                }
                Stage::Projecting(job) => match job.finish(
                    |decoded| decoded.source.resultless_proposal_wire_len(),
                    |decoded, writer| decoded.source.write_resultless_proposal_wire(writer),
                ) {
                    Ok((decoded, payload)) => {
                        let qc = decoded.commit_qc;
                        #[cfg(all(test, sumeragi_core_mutation = "HC15"))]
                        let qc = qc.clone();
                        return Ok(StoredBodyReadPoll::Ready(
                            BodyRestoration::new(
                                self.source.clone(),
                                decoded.header,
                                decoded.availability,
                                payload,
                            ),
                            qc,
                        ));
                    }
                    Err((job, error)) => {
                        self.stage = Stage::Projecting(job);
                        return match error {
                            PayloadBuildError::Admission(error) if error.is_local_refusal() => {
                                Ok(StoredBodyReadPoll::Pending(error))
                            }
                            PayloadBuildError::Admission(error) => {
                                Err(BodyReadError::Admission(error))
                            }
                            PayloadBuildError::Encoding(error) => {
                                Err(BodyReadError::from_decode(error))
                            }
                            PayloadBuildError::TooLarge | PayloadBuildError::Poisoned => {
                                Err(BodyReadError::Io(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "stored proposal cannot produce its bounded canonical payload",
                                )))
                            }
                        };
                    }
                },
                Stage::Consumed => return Err(BodyReadError::Completed),
            }
        }
    }
}

impl BodyReadJob for StoredBodyRead {
    fn source(&self) -> &AvailabilitySource {
        &self.source
    }

    fn poll(&mut self, budget: &AllocationBudget) -> Result<BodyReadPoll, BodyReadError> {
        Ok(match self.poll_with_qc(budget)? {
            StoredBodyReadPoll::Absent => BodyReadPoll::Absent,
            StoredBodyReadPoll::Pending(error) => BodyReadPoll::Pending(error),
            StoredBodyReadPoll::Ready(restoration, qc) => {
                // This caller requested only a body. Release the original proof owners before
                // returning, including its decoded signer bitmap.
                drop(qc);
                BodyReadPoll::Ready(restoration)
            }
        })
    }
}

#[cfg(test)]
#[path = "body_read_tests.rs"]
mod tests;
