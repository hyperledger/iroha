//! Retained lane file decoding and authenticated availability restoration jobs.

use crate::execution_attempt::ExecutionAttemptError as Attempt;
use iroha_allocation::AllocationBudget;
use iroha_sumeragi::{
    availability::{AvailabilitySource, BodyRestoration},
    crypto::Verifier,
    message::{BlockHeader, ByteAdmissionError, Qc},
};
use std::{io, path::Path, sync::Arc};

use super::{MAX_FRAME_FILE_BYTES, invalid};
use crate::sumeragi::{
    artifact_read::{ArtifactRead, ArtifactReadError},
    availability_schedule::AvailabilitySchedule,
    body_read::{BodyReadError, BodyReadJob, BodyReadPoll},
    driver::SharedCrypto,
    lanes::record::{LaneRecord, LaneRecordDecode, LaneRecordError, PreparedLaneWrite},
};

pub(super) fn record_error(error: LaneRecordError) -> Attempt<io::Error> {
    match error {
        LaneRecordError::Allocation(error) => crate::sumeragi::storage_attempt::buffer(error),
        LaneRecordError::Bytes(error) => crate::sumeragi::storage_attempt::byte(error),
        LaneRecordError::Codec(error) => BodyReadError::from_decode(error).into_attempt(),
        completed => io::Error::new(io::ErrorKind::InvalidData, completed).into(),
    }
}

pub(in crate::sumeragi) enum RecordPoll {
    Absent,
    Pending(ByteAdmissionError),
    Ready(LaneRecord),
}
enum RecordState {
    Absent,
    Reading(ArtifactRead),
    Decoding(LaneRecordDecode),
    Consumed,
}
pub(in crate::sumeragi) struct ReadRecord {
    state: RecordState,
    budget: AllocationBudget,
    custody: Option<super::LaneReadCustody>,
}
impl ReadRecord {
    pub(in crate::sumeragi) fn open(path: &Path, budget: AllocationBudget) -> io::Result<Self> {
        let state = ArtifactRead::open(path, MAX_FRAME_FILE_BYTES)?
            .map_or(RecordState::Absent, RecordState::Reading);
        Ok(Self {
            state,
            budget,
            custody: None,
        })
    }
    /// The enclosing ancestry/frame job retains this original directory through
    /// decoding and authentication; the raw reader independently retains its leaf.
    pub(in crate::sumeragi) fn open_owned(
        directory: &iroha_fs::OwnerDirectory,
        name: &str,
        budget: AllocationBudget,
    ) -> io::Result<Self> {
        let state = ArtifactRead::open_in(directory, name, MAX_FRAME_FILE_BYTES)?
            .map_or(RecordState::Absent, RecordState::Reading);
        Ok(Self {
            state,
            budget,
            custody: None,
        })
    }
    fn open_in(
        custody: super::LaneReadCustody,
        name: &str,
        budget: AllocationBudget,
    ) -> io::Result<Self> {
        custody.revalidate()?;
        let state = ArtifactRead::open_in(&custody.directory, name, MAX_FRAME_FILE_BYTES)?
            .map_or(RecordState::Absent, RecordState::Reading);
        custody.revalidate()?;
        Ok(Self {
            state,
            budget,
            custody: Some(custody),
        })
    }
    fn revalidate_custody(&self) -> io::Result<()> {
        if let Some(custody) = &self.custody {
            custody.revalidate()?;
        }
        Ok(())
    }
    pub(in crate::sumeragi) fn poll(
        &mut self,
        budget: &AllocationBudget,
    ) -> Result<RecordPoll, BodyReadError> {
        if !self.budget.same_pool(budget) {
            return Err(BodyReadError::ForeignBudget);
        }
        self.revalidate_custody().map_err(BodyReadError::Io)?;
        loop {
            match std::mem::replace(&mut self.state, RecordState::Consumed) {
                RecordState::Absent => {
                    self.state = RecordState::Absent;
                    return Ok(RecordPoll::Absent);
                }
                RecordState::Reading(read) => match read.complete(budget) {
                    Ok(raw) => self.state = RecordState::Decoding(LaneRecordDecode::new(raw)),
                    Err((read, error)) => {
                        self.state = RecordState::Reading(read);
                        return match error {
                            ArtifactReadError::Allocation(e) => {
                                Ok(RecordPoll::Pending(ByteAdmissionError::Buffer(e)))
                            }
                            ArtifactReadError::ForeignBudget => Err(BodyReadError::ForeignBudget),
                            ArtifactReadError::Io(e) => Err(BodyReadError::Io(e)),
                        };
                    }
                },
                RecordState::Decoding(decode) => match decode.complete(budget) {
                    Ok(record) => return Ok(RecordPoll::Ready(record)),
                    Err((decode, error)) => {
                        self.state = RecordState::Decoding(decode);
                        return match error {
                            LaneRecordError::Allocation(e) => {
                                Ok(RecordPoll::Pending(ByteAdmissionError::Buffer(e)))
                            }
                            LaneRecordError::Bytes(e) if e.is_local_refusal() => {
                                Ok(RecordPoll::Pending(e))
                            }
                            LaneRecordError::Bytes(e) => Err(BodyReadError::Admission(e)),
                            LaneRecordError::Codec(e) => Err(BodyReadError::from_decode(e)),
                            LaneRecordError::ForeignBudget => Err(BodyReadError::ForeignBudget),
                            error => Err(BodyReadError::from_attempt(record_error(error))),
                        };
                    }
                },
                RecordState::Consumed => return Err(BodyReadError::Completed),
            }
        }
    }
}

/// BodyReader's caller independently selects the source; no claimed QC config is consulted.
pub(super) struct LaneBodyRead {
    source: AvailabilitySource,
    read: ReadRecord,
    record: Option<LaneRecord>,
    budget: AllocationBudget,
    crypto: SharedCrypto,
}
impl LaneBodyRead {
    pub(super) fn open_in(
        source: AvailabilitySource,
        custody: super::LaneReadCustody,
        name: &str,
        budget: AllocationBudget,
        crypto: SharedCrypto,
    ) -> io::Result<Self> {
        Ok(Self {
            source,
            read: ReadRecord::open_in(custody, name, budget.clone())?,
            record: None,
            budget,
            crypto,
        })
    }
}
impl BodyReadJob for LaneBodyRead {
    fn source(&self) -> &AvailabilitySource {
        &self.source
    }
    fn poll(&mut self, budget: &AllocationBudget) -> Result<BodyReadPoll, BodyReadError> {
        if !self.budget.same_pool(budget) {
            return Err(BodyReadError::ForeignBudget);
        }
        self.read.revalidate_custody().map_err(BodyReadError::Io)?;
        if self.record.is_none() {
            match self.read.poll(budget)? {
                RecordPoll::Absent => {
                    self.read.revalidate_custody().map_err(BodyReadError::Io)?;
                    return Ok(BodyReadPoll::Absent);
                }
                RecordPoll::Pending(e) => return Ok(BodyReadPoll::Pending(e)),
                RecordPoll::Ready(record) => self.record = Some(record),
            }
        }
        self.record
            .as_ref()
            .expect("retained decoded owners")
            .check_context(&self.source, &*self.crypto)
            .map_err(|e| BodyReadError::from_attempt(record_error(e)))?;
        self.read.revalidate_custody().map_err(BodyReadError::Io)?;
        let (restoration, _qc) = self
            .record
            .take()
            .expect("validated source context")
            .into_restoration(self.source.clone());
        Ok(BodyReadPoll::Ready(restoration))
    }
}

enum RestoreState {
    Reading(ReadRecord),
    Decoded(LaneRecord),
    Restoring(BodyRestoration, Qc),
    Ready(PreparedLaneWrite),
    Consumed,
}
/// One lane height retained during startup, metadata reads and already-durable append checks.
/// Recovery verifies the original full QC against independent historical authority before
/// using its authenticated hash to reconstruct available custody.
pub(super) struct RestoreFrame {
    height: u64,
    custody: Option<super::LaneReadCustody>,
    state: RestoreState,
    schedule: Arc<dyn AvailabilitySchedule>,
    crypto: SharedCrypto,
}
impl RestoreFrame {
    pub(super) fn open(
        path: &Path,
        height: u64,
        budget: AllocationBudget,
        schedule: Arc<dyn AvailabilitySchedule>,
        crypto: SharedCrypto,
    ) -> io::Result<Self> {
        Ok(Self {
            height,
            custody: None,
            state: RestoreState::Reading(ReadRecord::open(path, budget)?),
            schedule,
            crypto,
        })
    }
    pub(super) fn open_in(
        custody: super::LaneReadCustody,
        name: &str,
        height: u64,
        budget: AllocationBudget,
        schedule: Arc<dyn AvailabilitySchedule>,
        crypto: SharedCrypto,
    ) -> io::Result<Self> {
        custody.revalidate()?;
        let state = ArtifactRead::open_in(&custody.directory, name, MAX_FRAME_FILE_BYTES)?
            .map_or(RecordState::Absent, RecordState::Reading);
        custody.revalidate()?;
        Ok(Self {
            height,
            state: RestoreState::Reading(ReadRecord {
                state,
                budget,
                custody: None,
            }),
            custody: Some(custody),
            schedule,
            crypto,
        })
    }
    pub(super) fn poll(
        &mut self,
        budget: &AllocationBudget,
    ) -> Result<PreparedLaneWrite, Attempt<io::Error>> {
        loop {
            // A completed restoration stays owned here until the original namespace joins.
            // Refusal after cryptographic work cannot drop it or restart from another file.
            if let Some(custody) = &self.custody {
                custody.revalidate()?;
            }
            match std::mem::replace(&mut self.state, RestoreState::Consumed) {
                RestoreState::Reading(mut read) => match read.poll(budget) {
                    Ok(RecordPoll::Ready(record)) => self.state = RestoreState::Decoded(record),
                    result => {
                        self.state = RestoreState::Reading(read);
                        return Err(match result {
                            Ok(RecordPoll::Absent) => {
                                invalid("committed lane frame disappeared").into()
                            }
                            Ok(RecordPoll::Pending(error)) => {
                                crate::sumeragi::storage_attempt::byte(error)
                            }
                            Err(error) => error.into_attempt(),
                            Ok(RecordPoll::Ready(_)) => unreachable!(),
                        });
                    }
                },
                RestoreState::Decoded(record) => {
                    let result = certified_source(
                        &*self.schedule,
                        &*self.crypto,
                        self.height,
                        record.header(),
                        record.commit_qc(),
                    )
                    .and_then(|source| {
                        record
                            .check_context(&source, &*self.crypto)
                            .map_err(record_error)?;
                        Ok(source)
                    });
                    match result {
                        Ok(source) => {
                            let (restoration, qc) = record.into_restoration(source);
                            self.state = RestoreState::Restoring(restoration, qc);
                        }
                        Err(error) => {
                            self.state = RestoreState::Decoded(record);
                            return Err(error);
                        }
                    }
                }
                RestoreState::Restoring(restoration, qc) => {
                    match restoration.complete(budget, &*self.crypto) {
                        Ok(body) => {
                            self.state = RestoreState::Ready(PreparedLaneWrite::new(body, qc))
                        }
                        Err((restoration, error)) => {
                            self.state = RestoreState::Restoring(restoration, qc);
                            return Err(crate::sumeragi::storage_attempt::restoration(error));
                        }
                    }
                }
                RestoreState::Ready(prepared) => return Ok(prepared),
                RestoreState::Consumed => {
                    return Err(invalid("lane restoration already consumed").into());
                }
            }
        }
    }
}

/// Authenticate the original full certificate before deriving a recovery source from its hash.
pub(super) fn certified_source(
    schedule: &dyn AvailabilitySchedule,
    crypto: &dyn iroha_sumeragi::crypto::Crypto,

    height: u64,
    header: &BlockHeader,
    qc: &Qc,
) -> Result<AvailabilitySource, Attempt<io::Error>> {
    let instance = schedule.instance();
    if header.instance != instance || header.height != height || qc.height != height {
        return Err(invalid("lane recovery instance or height mismatch").into());
    }
    let config = schedule.height_config(height)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "authenticated historical lane authority is not available",
        )
    })?;
    if !Verifier::new(crypto, &instance, &config.epoch.id, &config.committee)
        .verify_commit_qc(qc, Some(header))
    {
        return Err(invalid("original lane commit certificate does not verify").into());
    }
    AvailabilitySource::new(instance, height, qc.block_hash, config)
        .map_err(|error| invalid(format!("lane recovery source: {error:?}")).into())
}

#[cfg(all(test, unix))]
#[path = "read_custody_tests.rs"]
mod custody_tests;
