//! Object-safe, source-bound storage reads handed to the availability restoration worker.

use crate::execution_attempt::ExecutionAttemptError as Attempt;
use std::io;

use iroha_allocation::AllocationBudget;
use iroha_sumeragi::{
    availability::{AvailabilitySource, BodyRestoration},
    message::ByteAdmissionError,
};

use super::{
    artifact_read::{ArtifactRead, ArtifactReadError},
    bodies::BodyReadCustody,
    body_record::{BodyDecodeError, BodyRecord, BodyRecordDecode},
};

/// A persistent source that can begin one independently selected body acquisition.
pub trait BodyReader: Send + Sync {
    /// Open a retained read job. The caller obtains `source` from Core or authenticated
    /// historical state, never from the artifact this operation is about to inspect.
    ///
    /// # Errors
    /// Storage cannot start this read; errors are never translated into absence.
    fn begin_read(&self, source: AvailabilitySource)
    -> Result<Box<dyn BodyReadJob>, BodyReadError>;
}

/// One source-bound job retained by the bounded serve worker across local refusals.
pub trait BodyReadJob: Send {
    /// Independently selected immutable authority and expected identity.
    fn source(&self) -> &AvailabilitySource;
    /// Progress file reading and canonical decoding using the original State pool.
    /// `Ready` is untrusted restoration input, never proof of available custody.
    ///
    /// # Errors
    /// Corruption, I/O failure, foreign allocation source, or repeated consumption.
    fn poll(&mut self, budget: &AllocationBudget) -> Result<BodyReadPoll, BodyReadError>;
}

/// Storage progress before cryptographic and complete-codeword verification.
pub enum BodyReadPoll {
    /// The requested file was genuinely absent when this job was opened.
    Absent,
    /// Keep this exact job and its partial backing until the original pool can make progress.
    Pending(ByteAdmissionError),
    /// Exact decoded owners, to be completed outside Core by the restoration worker.
    Ready(BodyRestoration),
}

/// Storage read failures; none imply that a body is absent or available.
#[derive(Debug)]
pub enum BodyReadError {
    /// Filesystem refusal or a malformed physical source.
    Io(io::Error),
    /// Original historical authority read did not finish; retry the same source and pool.
    Deferred(crate::execution_attempt::ExecutionDeferred),
    /// Canonical Norito decoding rejected the complete stored record.
    Decode(norito::Error),
    /// A decoded semantic byte domain rejected its size or allocation source.
    Admission(ByteAdmissionError),
    /// A retry supplied another allocation pool.
    ForeignBudget,
    /// The worker tried to consume a completed job more than once.
    Completed,
}

impl BodyReadError {
    pub(super) fn into_attempt(self) -> Attempt<io::Error> {
        match self {
            Self::Io(error) => Attempt::Rejected(error),
            Self::Deferred(reason) => Attempt::Deferred(reason),
            Self::Admission(error) => super::storage_attempt::byte(error),
            Self::Decode(error) => io::Error::new(io::ErrorKind::InvalidData, error).into(),
            error => io::Error::new(io::ErrorKind::InvalidData, error).into(),
        }
    }

    pub(super) fn from_attempt(error: Attempt<io::Error>) -> Self {
        match error {
            Attempt::Rejected(error) => Self::Io(error),
            Attempt::Deferred(reason) => Self::Deferred(reason),
        }
    }

    /// Preserve physical decoder refusal as local I/O progress without allocating a diagnostic.
    /// Deterministic wire and decode-limit errors retain their original terminal typed cause.
    pub(super) fn from_decode(error: norito::Error) -> Self {
        if cfg!(all(test, sumeragi_core_mutation = "HC25"))
            && matches!(&error, norito::Error::AllocationFailed { .. })
        {
            return Self::Decode(error);
        }
        match crate::execution_attempt::norito_decode_attempt_error(error, std::convert::identity) {
            Attempt::Deferred(reason) => Self::Deferred(reason),
            Attempt::Rejected(error) => Self::Decode(error),
        }
    }
}

impl std::fmt::Display for BodyReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "body read: {error}"),
            Self::Deferred(reason) => write!(f, "body authority deferred: {reason}"),
            Self::Decode(error) => write!(f, "body record: {error}"),
            Self::Admission(error) => write!(f, "body record owner: {error}"),
            Self::ForeignBudget => f.write_str("body read retry uses a foreign allocation pool"),
            Self::Completed => f.write_str("body read job was already consumed"),
        }
    }
}

impl std::error::Error for BodyReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Deferred(reason) => Some(reason),
            Self::Decode(error) => Some(error),
            Self::Admission(error) => Some(error),
            Self::ForeignBudget | Self::Completed => None,
        }
    }
}

enum ReadState {
    Absent,
    Reading(ArtifactRead),
    Decoding(BodyRecordDecode),
    Ready(BodyRecord),
    Consumed,
}

/// Concrete file job; the store chooses the path independently of bytes found there.
pub(super) struct FileBodyRead {
    source: AvailabilitySource,
    budget: AllocationBudget,
    state: ReadState,
    custody: BodyReadCustody,
}

impl FileBodyRead {
    pub(super) fn open(
        custody: BodyReadCustody,
        source: AvailabilitySource,
        max_bytes: usize,
        budget: AllocationBudget,
    ) -> Result<Self, BodyReadError> {
        custody.revalidate().map_err(BodyReadError::Io)?;
        let state = match ArtifactRead::open_in_child(
            &custody.directory,
            &format!("{:020}", source.height()),
            &hex::encode(source.block_hash().0),
            max_bytes,
        )
        .map_err(BodyReadError::Io)?
        {
            Some(read) => ReadState::Reading(read),
            None => ReadState::Absent,
        };
        custody.revalidate().map_err(BodyReadError::Io)?;
        Ok(Self {
            source,
            budget,
            state,
            custody,
        })
    }
}

impl BodyReadJob for FileBodyRead {
    fn source(&self) -> &AvailabilitySource {
        &self.source
    }

    fn poll(&mut self, budget: &AllocationBudget) -> Result<BodyReadPoll, BodyReadError> {
        if !self.budget.same_pool(budget) {
            return Err(BodyReadError::ForeignBudget);
        }
        loop {
            // A completed original record stays owned here across a late root/lock refusal.
            self.custody.revalidate().map_err(BodyReadError::Io)?;
            match std::mem::replace(&mut self.state, ReadState::Consumed) {
                ReadState::Absent => {
                    self.state = ReadState::Absent;
                    return Ok(BodyReadPoll::Absent);
                }
                ReadState::Reading(read) => match read.complete(budget) {
                    Ok(bytes) => self.state = ReadState::Decoding(BodyRecordDecode::new(bytes)),
                    Err((read, error)) => {
                        self.state = ReadState::Reading(read);
                        return match error {
                            ArtifactReadError::Allocation(error) => {
                                Ok(BodyReadPoll::Pending(ByteAdmissionError::Buffer(error)))
                            }
                            ArtifactReadError::Io(error) => Err(BodyReadError::Io(error)),
                            ArtifactReadError::ForeignBudget => Err(BodyReadError::ForeignBudget),
                        };
                    }
                },
                ReadState::Decoding(decode) => match decode.complete(budget) {
                    Ok(record) => self.state = ReadState::Ready(record),
                    Err((decode, error)) => {
                        self.state = ReadState::Decoding(decode);
                        return match error {
                            BodyDecodeError::ForeignBudget => Err(BodyReadError::ForeignBudget),
                            BodyDecodeError::Decode(error) => {
                                Err(BodyReadError::from_decode(error))
                            }
                            BodyDecodeError::Bytes(error) if error.is_local_refusal() => {
                                Ok(BodyReadPoll::Pending(error))
                            }
                            BodyDecodeError::Bytes(error) => Err(BodyReadError::Admission(error)),
                        };
                    }
                },
                ReadState::Ready(record) => {
                    return Ok(BodyReadPoll::Ready(
                        record.into_restoration(self.source.clone()),
                    ));
                }
                ReadState::Consumed => return Err(BodyReadError::Completed),
            }
        }
    }
}

#[cfg(test)]
mod decode_refusal_tests {
    use super::*;
    #[test]
    fn physical_decode_refusal_is_operational_but_declared_limits_remain_terminal() {
        let error = BodyReadError::from_decode(norito::Error::AllocationFailed { bytes: 123 });
        let BodyReadError::Deferred(error) = error else {
            panic!("physical allocator refusal remains retryable");
        };
        assert_eq!(
            error.reason(),
            ivm::error::ExecutionDeferral::AllocationUnavailable
        );
        assert!(error.allocation_refusal().is_none());
        for error in [
            norito::Error::LengthMismatch,
            norito::Error::SchemaMismatch,
            norito::Error::FieldLengthExceeded {
                length: 2,
                limit: 1,
            },
            norito::Error::TotalAllocationExceeded {
                attempted: 2,
                limit: 1,
            },
            norito::Error::TotalElementsExceeded {
                attempted: 2,
                limit: 1,
            },
        ] {
            assert!(
                matches!(BodyReadError::from_decode(error), BodyReadError::Decode(_)),
                "static wire/decoder policy errors cannot become resource retries"
            );
        }
    }
}
