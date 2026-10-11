//! A hash-keyed lookup over Kura's height slots, with complete verification before absence.

use super::*;
use crate::sumeragi::body_read::BodyReadPoll;
use certificate_read::{CertificateRead, CertificateReadError, DecodedCertificate};
use iroha_sumeragi::availability::BodyRestoration;

enum Phase {
    Absent,
    Certificate(CertificateRead),
    Decoded(DecodedCertificate),
    Projecting(body_read::StoredBodyRead),
    VerifyingOther(BodyRestoration),
    Consumed,
}

/// Retain a canonical height slot while independently resolving the requested hash key.
pub(super) struct KeyedRead {
    source: AvailabilitySource,
    budget: AllocationBudget,
    crypto: SharedCrypto,
    schedule: Arc<dyn AvailabilitySchedule>,

    phase: Phase,
}

impl KeyedRead {
    /// Bind the original slot, allocation pool and authenticated historical authority once.
    pub(super) fn new(
        source: AvailabilitySource,
        block: Option<iroha_data_model::block::SharedSignedBlock>,
        budget: AllocationBudget,
        crypto: SharedCrypto,
        schedule: Arc<dyn AvailabilitySchedule>,
    ) -> Self {
        let phase = block.map_or(Phase::Absent, |block| {
            Phase::Certificate(CertificateRead::new(block, budget.clone()))
        });
        Self {
            source,
            budget,
            crypto,
            schedule,
            phase,
        }
    }
}

impl BodyReadJob for KeyedRead {
    fn source(&self) -> &AvailabilitySource {
        &self.source
    }

    fn poll(&mut self, budget: &AllocationBudget) -> Result<BodyReadPoll, BodyReadError> {
        if !self.budget.same_pool(budget) {
            return Err(BodyReadError::ForeignBudget);
        }
        loop {
            match std::mem::replace(&mut self.phase, Phase::Consumed) {
                Phase::Absent => return Ok(BodyReadPoll::Absent),
                Phase::Certificate(job) => match job.complete(budget) {
                    Ok(decoded) => self.phase = Phase::Decoded(decoded),
                    Err((job, error)) => {
                        self.phase = Phase::Certificate(job);
                        return match error {
                            CertificateReadError::ForeignBudget => {
                                Err(BodyReadError::ForeignBudget)
                            }
                            CertificateReadError::MissingCertificate => Err(BodyReadError::Io(
                                invalid("stored block has no certificate"),
                            )),
                            CertificateReadError::Decode(error) => {
                                Err(BodyReadError::from_decode(error))
                            }
                            CertificateReadError::Admission(error) if error.is_local_refusal() => {
                                Ok(BodyReadPoll::Pending(error))
                            }
                            CertificateReadError::Admission(error) => {
                                Err(BodyReadError::Admission(error))
                            }
                        };
                    }
                },
                Phase::Decoded(decoded) => {
                    let actual = match committed_read::certified_source(
                        &*self.schedule,
                        &*self.crypto,
                        self.source.height(),
                        &decoded.header,
                        &decoded.commit_qc,
                    ) {
                        Ok(source) => source,
                        Err(error) => {
                            self.phase = Phase::Decoded(decoded);
                            return Err(BodyReadError::from_attempt(error));
                        }
                    };
                    if actual.instance() != self.source.instance()
                        || actual.config() != self.source.config()
                    {
                        self.phase = Phase::Decoded(decoded);
                        return Err(BodyReadError::Io(invalid(
                            "stored body uses another historical authority",
                        )));
                    }
                    self.phase = Phase::Projecting(body_read::StoredBodyRead::from_decoded(
                        actual,
                        decoded,
                        budget.clone(),
                        self.crypto.clone(),
                    ));
                }
                Phase::Projecting(mut job) => match job.poll(budget) {
                    Ok(BodyReadPoll::Ready(restoration)) => {
                        if restoration.source() == &self.source {
                            return Ok(BodyReadPoll::Ready(restoration));
                        }
                        // Kura stores one canonical block per height. A competing hash is
                        // absent only after that slot's original result, QC, signed
                        // availability and complete payload all verify; corruption is fatal.
                        self.phase = Phase::VerifyingOther(restoration);
                    }
                    Ok(BodyReadPoll::Pending(error)) => {
                        self.phase = Phase::Projecting(job);
                        return Ok(BodyReadPoll::Pending(error));
                    }
                    Ok(BodyReadPoll::Absent) => {
                        return Err(BodyReadError::Io(invalid(
                            "retained committed block cannot become absent",
                        )));
                    }
                    Err(error) => {
                        self.phase = Phase::Projecting(job);
                        return Err(error);
                    }
                },
                Phase::VerifyingOther(job) => match job.complete(budget, &*self.crypto) {
                    Ok(_) => return Ok(BodyReadPoll::Absent),
                    Err((job, error)) => {
                        self.phase = Phase::VerifyingOther(job);
                        return Err(BodyReadError::from_attempt(
                            super::super::storage_attempt::restoration(error),
                        ));
                    }
                },
                Phase::Consumed => return Err(BodyReadError::Completed),
            }
        }
    }
}
