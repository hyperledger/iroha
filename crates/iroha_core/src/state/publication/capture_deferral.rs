//! Original local capture refusals cross publication without invented retry authority.

use super::{
    retained_musubi::RetainedPackageReadError, retained_musubi_group::RetainedMusubiGroupReadError,
};
use crate::{
    execution_attempt::ExecutionAttemptError,
    state::{
        authority_registry::{
            FrozenMusubiError,
            leaf::{LeafError, RetainedSemanticError},
        },
        deserialize::{
            musubi_source_read::ReadFailure,
            musubi_source_work::{SourceValidationError, WorkRefusal},
        },
        storage_transactions::TransactionsBlockError,
    },
};
use iroha_allocation::{AllocationRefusal, ChargedBufferError, PrepaidSharedError};
use iroha_crypto::NoritoKeyRangeError;

/// Move-only local capture refusal belonging to the pending original State.
///
/// This non-wire owner preserves the supplied cause without allocating, granting
/// work, replacing the source or creating a release event. It is diagnostic
/// custody, never transaction rejection, a completed root or publication authority.
#[derive(Debug)]
pub struct StateCaptureDeferral {
    original: Original,
}

#[derive(Debug)]
enum Original {
    Source(RetainedMusubiGroupReadError),
    SourcePolicy(WorkRefusal),
    Encoding(RetainedSemanticError),
}

impl StateCaptureDeferral {
    /// Exact native source work observation, as `(used, required, limit)`.
    pub fn native_work(&self) -> Option<(usize, usize, usize)> {
        match &self.original {
            Original::Source(RetainedMusubiGroupReadError::Field {
                original:
                    RetainedPackageReadError::Work {
                        used,
                        required,
                        limit,
                    },
                ..
            }) => Some((*used, *required, *limit)),
            _ => None,
        }
    }

    /// Exact canonical encoding work observation, as `(used, required, limit)`.
    pub fn encoding_work(&self) -> Option<(usize, usize, usize)> {
        match &self.original {
            Original::Encoding(RetainedSemanticError::Work {
                used,
                required,
                limit,
            }) => Some((*used, *required, *limit)),
            _ => None,
        }
    }

    /// Original source field, when the refusal identifies one.
    pub fn field(&self) -> Option<&'static str> {
        match &self.original {
            Original::Source(
                RetainedMusubiGroupReadError::Field { field, .. }
                | RetainedMusubiGroupReadError::ReadersRetained { field },
            ) => Some(field),
            _ => None,
        }
    }

    /// Borrow the exact original fixed-buffer admission or physical allocation error.
    pub fn buffer_refusal(&self) -> Option<&ChargedBufferError> {
        match &self.original {
            Original::Source(
                RetainedMusubiGroupReadError::Control(original)
                | RetainedMusubiGroupReadError::Field {
                    original: RetainedPackageReadError::Allocation(original),
                    ..
                },
            ) => Some(original),
            _ => None,
        }
    }

    /// Borrow the exact original shared-node physical or prepaid-partition refusal.
    pub fn shared_refusal(&self) -> Option<&PrepaidSharedError> {
        match &self.original {
            Original::Encoding(RetainedSemanticError::Table(LeafError::LookupAllocation(
                original,
            ))) => Some(original),
            _ => None,
        }
    }

    /// Requested bytes from the original canonical codec allocation failure, if known.
    pub fn codec_allocation_bytes(&self) -> Option<u64> {
        match &self.original {
            Original::Encoding(RetainedSemanticError::Table(LeafError::Encoding(original))) => {
                original.allocation_bytes()
            }
            _ => None,
        }
    }

    /// Borrow actual original pool demand, including ordered canonical tree backing.
    pub fn allocation_refusal(&self) -> Option<&AllocationRefusal> {
        if let Some(ChargedBufferError::Admission(original)) = self.buffer_refusal() {
            return Some(original);
        }
        match &self.original {
            Original::Encoding(RetainedSemanticError::Table(
                LeafError::Admission(original)
                | LeafError::OrderedRange(NoritoKeyRangeError::Admission(original)),
            )) => Some(original),
            _ => None,
        }
    }

    /// Borrow only an actual capacity refusal's pre-probe pool release observation.
    /// Work, policy, retained readers and physical allocator failure supply no wake.
    pub fn release_wait(&self) -> Option<&iroha_allocation::release::ReleaseWait> {
        match self.allocation_refusal() {
            Some(AllocationRefusal::Capacity { release, .. }) => Some(release),
            _ => None,
        }
    }
}

impl std::fmt::Display for StateCaptureDeferral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.original {
            Original::Source(original) => {
                write!(f, "original State capture source refused: {original:?}")
            }
            Original::SourcePolicy(original) => {
                write!(f, "original State capture policy refused: {original:?}")
            }
            Original::Encoding(original) => {
                write!(f, "original State capture encoding refused: {original}")
            }
        }
    }
}

impl std::error::Error for StateCaptureDeferral {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(original) = self.buffer_refusal() {
            return Some(original);
        }
        match &self.original {
            Original::Encoding(original) => Some(original),
            _ => None,
        }
    }
}

/// Retain a local source refusal; a changed original cut requires recovery.
pub(in crate::state) fn source_refusal(
    original: RetainedMusubiGroupReadError,
) -> TransactionsBlockError {
    match original {
        original @ (RetainedMusubiGroupReadError::Control(_)
        | RetainedMusubiGroupReadError::WorkGrantOverflow
        | RetainedMusubiGroupReadError::ReadersRetained { .. }
        | RetainedMusubiGroupReadError::Field {
            original:
                RetainedPackageReadError::Allocation(_)
                | RetainedPackageReadError::Work { .. }
                | RetainedPackageReadError::ReadersRetained,
            ..
        }) => TransactionsBlockError::CaptureDeferred(StateCaptureDeferral {
            original: Original::Source(original),
        }),
        RetainedMusubiGroupReadError::NotFrozen
        | RetainedMusubiGroupReadError::SourceChanged
        | RetainedMusubiGroupReadError::ScopeIdentity
        | RetainedMusubiGroupReadError::SemanticAlreadyStarted
        | RetainedMusubiGroupReadError::Incomplete
        | RetainedMusubiGroupReadError::Field {
            original:
                RetainedPackageReadError::NotFrozen
                | RetainedPackageReadError::SourceChanged
                | RetainedPackageReadError::ScopeIdentity
                | RetainedPackageReadError::Geometry
                | RetainedPackageReadError::Incomplete,
            ..
        } => TransactionsBlockError::SnapshotObservationChanged,
    }
}

/// Separate an unfinished local validator from its completed original semantic verdict.
pub(in crate::state) fn validation_refusal(
    original: ReadFailure<RetainedMusubiGroupReadError, SourceValidationError>,
) -> TransactionsBlockError {
    match original {
        ReadFailure::Source(original) => source_refusal(original),
        ReadFailure::Predicate(SourceValidationError::Work(original)) => {
            TransactionsBlockError::CaptureDeferred(StateCaptureDeferral {
                original: Original::SourcePolicy(original),
            })
        }
        ReadFailure::Predicate(SourceValidationError::Attempt(
            ExecutionAttemptError::Deferred(original),
        )) => TransactionsBlockError::ExecutionDeferred(original),
        ReadFailure::Predicate(SourceValidationError::Attempt(
            ExecutionAttemptError::Rejected(_),
        )) => TransactionsBlockError::WorldCommitPreparation,
    }
}

/// Preserve canonical materializer refusal without conferring complete State authority.
pub(in crate::state) fn materialization_refusal(
    original: FrozenMusubiError,
) -> TransactionsBlockError {
    match original {
        FrozenMusubiError::Source(original) => source_refusal(original),
        FrozenMusubiError::Encoding(RetainedSemanticError::Table(LeafError::Encoding(
            original,
        ))) if original.is_allocation_refusal() => {
            TransactionsBlockError::CaptureDeferred(StateCaptureDeferral {
                original: Original::Encoding(RetainedSemanticError::Table(LeafError::Encoding(
                    original,
                ))),
            })
        }
        FrozenMusubiError::Encoding(
            original @ (RetainedSemanticError::Work { .. }
            | RetainedSemanticError::Overflow
            | RetainedSemanticError::Table(
                LeafError::Allocation
                | LeafError::Admission(_)
                | LeafError::LookupAllocation(_)
                | LeafError::TableLimit
                | LeafError::RowLimit
                | LeafError::PayloadLimit
                | LeafError::StreamedTableLimit
                | LeafError::OrderedRange(
                    NoritoKeyRangeError::Capacity
                    | NoritoKeyRangeError::Allocation
                    | NoritoKeyRangeError::Admission(_)
                    | NoritoKeyRangeError::PrepaidCapacity(_),
                ),
            )),
        ) => TransactionsBlockError::CaptureDeferred(StateCaptureDeferral {
            original: Original::Encoding(original),
        }),
        FrozenMusubiError::Changed
        | FrozenMusubiError::Encoding(
            RetainedSemanticError::ScopeIdentity
            | RetainedSemanticError::Phase
            | RetainedSemanticError::Table(_),
        ) => TransactionsBlockError::SnapshotObservationChanged,
    }
}

#[cfg(test)]
pub(crate) fn buffer_refusal_for_test(original: ChargedBufferError) -> TransactionsBlockError {
    source_refusal(RetainedMusubiGroupReadError::Control(original))
}

#[cfg(test)]
mod tests;
