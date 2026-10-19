//! Source-bound Kura projection, retaining exact certificate and proposal backing on refusal.

use std::io;

use iroha_allocation::AllocationBudget;
use iroha_data_model::sumeragi_finality::result_of_preimage;
use iroha_sumeragi::{
    availability::{AvailabilitySource, BodyRestoration},
    message::{ByteAdmissionError, Qc, VoteKind},
};

use super::certificate_read::DecodedCertificate;
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
    Pending(ByteAdmissionError),
    Ready(BodyRestoration, Qc),
}

enum Stage {
    Decoded(DecodedCertificate),
    Projecting(PayloadBuild<DecodedCertificate>),
    Consumed,
}

/// Project the original decoded certificate selected by the committed or hash-keyed reader.
/// Those enclosing readers own certificate decoding and authenticating real slot absence.
pub(super) struct StoredBodyRead {
    source: AvailabilitySource,
    budget: AllocationBudget,
    crypto: SharedCrypto,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    stage: Stage,
}
impl StoredBodyRead {
    /// Transfer the same original decoded owners from full committed-certificate verification.
    pub(super) fn from_decoded(
        source: AvailabilitySource,
        decoded: DecodedCertificate,
        budget: AllocationBudget,
        crypto: SharedCrypto,
        root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    ) -> Self {
        Self {
            source,
            budget,
            crypto,
            root_scope,
            stage: Stage::Decoded(decoded),
        }
    }
}

/// Check the stored execution and certificate relations shared by body and metadata readers.
pub(super) fn validate_decoded(
    source: &AvailabilitySource,
    decoded: &DecodedCertificate,
    crypto: &dyn iroha_sumeragi::crypto::Crypto,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
) -> Result<(), BodyReadError> {
    let header = &decoded.header;
    let qc = &decoded.commit_qc;
    let certificate = decoded
        .source
        .commit_certificate()
        .expect("decoded original certificate");
    let result = result_of_preimage(certificate.result_preimage());
    if decoded.source.header().height().get() != source.height()
        || !decoded.source.has_results()
        || header.instance != source.instance()
        || header.height != source.height()
        || header.epoch != source.config().epoch.id
        || header.hash(crypto) != source.block_hash()
        || qc.kind != VoteKind::Commit
        || qc.instance != header.instance
        || qc.epoch != header.epoch
        || qc.height != header.height
        || qc.block_hash != source.block_hash()
        || Some(qc.result) != result
    {
        return Err(BodyReadError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "stored certificate does not bind the independently requested body and result",
        )));
    }
    super::execution::validate(&decoded.source, root_scope).map_err(BodyReadError::from_attempt)?;
    Ok(())
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
                Stage::Decoded(decoded) => {
                    if let Err(error) =
                        validate_decoded(&self.source, &decoded, &*self.crypto, self.root_scope)
                    {
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
