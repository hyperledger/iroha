//! Complete retained Kura authentication: original frame, full QC, and signed body restoration.
use super::body_read::StoredBodyReadPoll;
use super::*;
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use certificate_read::{CertificateRead, CertificateReadError, DecodedCertificate};
use iroha_sumeragi::availability::BodyRestoration;

enum Phase {
    Certificate(CertificateRead),
    Decoded(DecodedCertificate),
    Projecting(body_read::StoredBodyRead),
    Restoring(BodyRestoration, Qc),
    Consumed,
}
pub(super) struct CommittedRead {
    height: u64,
    budget: AllocationBudget,
    crypto: SharedCrypto,
    schedule: Arc<dyn AvailabilitySchedule>,

    phase: Phase,
}
impl CommittedRead {
    pub(super) fn new(
        block: iroha_data_model::block::SharedSignedBlock,
        height: u64,
        budget: AllocationBudget,
        crypto: SharedCrypto,
        schedule: Arc<dyn AvailabilitySchedule>,
    ) -> Self {
        Self {
            height,
            phase: Phase::Certificate(CertificateRead::new(block, budget.clone())),
            budget,
            crypto,
            schedule,
        }
    }
    pub(super) fn height(&self) -> u64 {
        self.height
    }
    /// Observe a refused original certificate read without progressing or replacing its owner.
    #[cfg(test)]
    pub(super) fn retained_certificate_owners_for_test(
        &self,
    ) -> Option<(*const SignedBlock, Option<*const u8>)> {
        match &self.phase {
            Phase::Certificate(job) => Some(job.retained_owners_for_test()),
            _ => None,
        }
    }
    pub(super) fn poll(&mut self) -> Result<(AvailableBody, Qc), Attempt<io::Error>> {
        loop {
            match std::mem::replace(&mut self.phase, Phase::Consumed) {
                Phase::Certificate(job) => match job.complete(&self.budget) {
                    Ok(decoded) => self.phase = Phase::Decoded(decoded),
                    Err((job, error)) => {
                        self.phase = Phase::Certificate(job);
                        return Err(match error {
                            CertificateReadError::Admission(error) => {
                                super::super::storage_attempt::byte(error)
                            }
                            CertificateReadError::Decode(error) => {
                                BodyReadError::from_decode(error).into_attempt()
                            }
                            error => io::Error::new(io::ErrorKind::InvalidData, error).into(),
                        });
                    }
                },
                Phase::Decoded(decoded) => {
                    let source = match certified_source(
                        &*self.schedule,
                        &*self.crypto,
                        self.height,
                        &decoded.header,
                        &decoded.commit_qc,
                    ) {
                        Ok(source) => source,
                        Err(error) => {
                            self.phase = Phase::Decoded(decoded);
                            return Err(error);
                        }
                    };
                    self.phase = Phase::Projecting(body_read::StoredBodyRead::from_decoded(
                        source,
                        decoded,
                        self.budget.clone(),
                        self.crypto.clone(),
                    ));
                }
                Phase::Projecting(mut job) => match job.poll_with_qc(&self.budget) {
                    Ok(StoredBodyReadPoll::Ready(restoration, qc)) => {
                        self.phase = Phase::Restoring(restoration, qc)
                    }
                    Ok(StoredBodyReadPoll::Pending(error)) => {
                        self.phase = Phase::Projecting(job);
                        return Err(super::super::storage_attempt::byte(error));
                    }
                    Ok(StoredBodyReadPoll::Absent) => {
                        return Err(invalid("retained committed block cannot become absent").into());
                    }
                    Err(error) => {
                        self.phase = Phase::Projecting(job);
                        // Keep the original operational category and typed cause so the
                        // outer Kura read slot retains this exact owner across local refusal.
                        return Err(error.into_attempt());
                    }
                },
                Phase::Restoring(job, qc) => match job.complete(&self.budget, &*self.crypto) {
                    Ok(body) => return Ok((body, qc)),
                    Err((job, error)) => {
                        self.phase = Phase::Restoring(job, qc);
                        return Err(super::super::storage_attempt::restoration(error));
                    }
                },
                Phase::Consumed => return Err(invalid("committed read already consumed").into()),
            }
        }
    }
}
/// A claimed QC never supplies its own authority. Full verification precedes source construction.
pub(super) fn certified_source(
    schedule: &dyn AvailabilitySchedule,
    crypto: &dyn iroha_sumeragi::crypto::Crypto,

    height: u64,
    header: &BlockHeader,
    qc: &Qc,
) -> Result<AvailabilitySource, Attempt<io::Error>> {
    let instance = schedule.instance();
    if header.height != height || header.instance != instance || qc.height != height {
        return Err(invalid("committed source height or instance mismatch").into());
    }
    let config = schedule
        .height_config(height)?
        .ok_or_else(|| busy("authenticated historical authority unavailable"))?;
    if !Verifier::new(crypto, &instance, &config.epoch.id, &config.committee)
        .verify_commit_qc(qc, Some(header))
    {
        return Err(invalid("original commit certificate does not verify").into());
    }
    AvailabilitySource::new(instance, height, qc.block_hash, config)
        .map_err(|error| invalid(format!("invalid committed source: {error:?}")).into())
}

#[cfg(test)]
#[path = "committed_read_tests.rs"]
mod tests;
