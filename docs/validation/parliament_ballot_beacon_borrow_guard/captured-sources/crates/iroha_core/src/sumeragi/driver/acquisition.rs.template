//! Source-bound stored-body acquisition on the existing bounded serve worker.
//! The same read/restoration owner survives local refusals; only complete verification
//! can return available custody to Core. File presence never grants execution authority.

use iroha_allocation::AllocationBudget;
use iroha_sumeragi::{
    availability::{AvailabilitySource, AvailableBody, BodyRestoration, RestorationError},
    crypto::Crypto,
    message::ByteAdmissionError,
};

use crate::sumeragi::durable_artifact::{BodyReadError, BodyReadJob, BodyReadPoll, BodyReader};

/// One retained acquisition outcome; absence is distinct from all resource and data errors.
pub enum StoredProgress {
    /// The independently requested source was genuinely absent in this store.
    Absent,
    /// Reading retains its original owner until this resource refusal clears.
    Pending(ByteAdmissionError),
    /// The original frame and complete payload passed source, signature and RS16 checks.
    Available(AvailableBody),
}

/// An acquisition failure. The caller retains the job when retrying a local refusal.
#[derive(Debug)]
pub enum StoredError {
    /// The storage implementation reported an error, never absence.
    Read(BodyReadError),
    /// Complete source-bound restoration could not finish.
    Restoration(RestorationError),
    /// The storage job changed its independently requested immutable source.
    Source,
    /// An available or absent result has already been consumed.
    Completed,
}

enum Stage {
    Reading(Box<dyn BodyReadJob>),
    Restoring(BodyRestoration),
    Complete,
}

/// A single move-only read/restoration job owned by the bounded serve worker.
pub struct StoredAcquisition {
    source: AvailabilitySource,
    stage: Stage,
}

impl StoredAcquisition {
    /// Begin from an authority selected by Core or an authenticated historical schedule.
    ///
    /// # Errors
    /// Storage could not open a job or substituted its requested source.
    pub fn begin(reader: &dyn BodyReader, source: AvailabilitySource) -> Result<Self, StoredError> {
        let job = reader
            .begin_read(source.clone())
            .map_err(StoredError::Read)?;
        if job.source() != &source {
            return Err(StoredError::Source);
        }
        Ok(Self {
            source,
            stage: Stage::Reading(job),
        })
    }

    /// Independently selected source, retained unchanged across every retry.
    pub fn source(&self) -> &AvailabilitySource {
        &self.source
    }

    /// Progress on a worker, keeping original owners until verification succeeds.
    /// No callback is allowed to emit an execution event from a decoded record.
    ///
    /// # Errors
    /// Storage or restoration failed, the source changed, or this result was consumed.
    /// Restoration resource failures retain exactly the returned partial job for retry.
    pub fn poll(
        &mut self,
        budget: &AllocationBudget,
        crypto: &dyn Crypto,
    ) -> Result<StoredProgress, StoredError> {
        loop {
            match &mut self.stage {
                Stage::Reading(job) => {
                    if job.source() != &self.source {
                        return Err(StoredError::Source);
                    }
                    match job.poll(budget).map_err(StoredError::Read)? {
                        BodyReadPoll::Absent => {
                            self.stage = Stage::Complete;
                            return Ok(StoredProgress::Absent);
                        }
                        BodyReadPoll::Pending(error) => return Ok(StoredProgress::Pending(error)),
                        BodyReadPoll::Ready(restoration) => {
                            if restoration.source() != &self.source {
                                self.stage = Stage::Complete;
                                return Err(StoredError::Source);
                            }
                            self.stage = Stage::Restoring(restoration);
                        }
                    }
                }
                Stage::Restoring(_) => {
                    let Stage::Restoring(job) = std::mem::replace(&mut self.stage, Stage::Complete)
                    else {
                        unreachable!("retained restoration stage")
                    };
                    match job.complete(budget, crypto) {
                        Ok(body) => return Ok(StoredProgress::Available(body)),
                        Err((job, error)) => {
                            self.stage = Stage::Restoring(job);
                            return Err(StoredError::Restoration(error));
                        }
                    }
                }
                Stage::Complete => return Err(StoredError::Completed),
            }
        }
    }
}
