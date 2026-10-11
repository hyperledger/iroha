//! Original certificate-preparation refusals cross the worker boundary without text erasure.

use super::{BlockValidationError, PublicationDeferral, PublicationError};
use crate::execution_attempt::ExecutionDeferred;
use iroha_allocation::{ChargedBufferError, PrepaidSharedError};
use iroha_data_model::block::{CertificateAdmissionError, SharedBlockAdmissionError};
use ivm::error::ExecutionDeferral;

pub(super) fn buffer_refusal(error: &ChargedBufferError) -> ExecutionDeferred {
    match error {
        ChargedBufferError::Admission(original) => original.clone().into(),
        ChargedBufferError::Allocator { .. } => ExecutionDeferral::AllocationUnavailable.into(),
    }
}

pub(super) fn block_failure(error: &SharedBlockAdmissionError) -> PublicationError {
    let original: ExecutionDeferred = match error {
        SharedBlockAdmissionError::Admission(original) => original.clone().into(),
        SharedBlockAdmissionError::Allocation(PrepaidSharedError::Allocator { .. }) => {
            ExecutionDeferral::AllocationUnavailable.into()
        }
        SharedBlockAdmissionError::Allocation(PrepaidSharedError::Reservation(_)) => {
            ExecutionDeferral::ActiveMemoryCapacity.into()
        }
    };
    PublicationError::Deferred(original.into())
}

pub(super) fn encoding_failure(
    error: &super::super::commitment::ResultPreimageError,
) -> PublicationError {
    match error {
        super::super::commitment::ResultPreimageError::Allocation(error) => {
            PublicationError::Deferred(buffer_refusal(error).into())
        }
        other => PublicationError::Retryable(other.to_string()),
    }
}

pub(super) fn certificate_failure(error: &CertificateAdmissionError) -> PublicationError {
    match error {
        CertificateAdmissionError::Buffer(error) => {
            PublicationError::Deferred(buffer_refusal(error).into())
        }
        CertificateAdmissionError::ControlAdmission(original) => {
            PublicationError::Deferred(ExecutionDeferred::from(original.clone()).into())
        }
        CertificateAdmissionError::ControlAllocation(PrepaidSharedError::Allocator { .. }) => {
            PublicationError::Deferred(
                ExecutionDeferred::from(ExecutionDeferral::AllocationUnavailable).into(),
            )
        }
        // A short prepaid parent has no observed pool release that could repair it.
        CertificateAdmissionError::ControlAllocation(PrepaidSharedError::Reservation(_)) => {
            PublicationError::Deferred(
                ExecutionDeferred::from(ExecutionDeferral::ActiveMemoryCapacity).into(),
            )
        }
        CertificateAdmissionError::ForeignBudget => PublicationError::Retryable(error.to_string()),
    }
}

#[cfg(test)]
mod tests;

/// Preserve the exact witness backing/control refusal in unit classification controls.
#[cfg(test)]
pub(super) fn witness_failure(
    error: &iroha_sumeragi::message::ByteAdmissionError,
) -> PublicationError {
    use iroha_sumeragi::message::ByteAdmissionError;
    let original: ExecutionDeferred = match error {
        ByteAdmissionError::Buffer(error) => buffer_refusal(error),
        ByteAdmissionError::ControlAdmission(original) => original.clone().into(),
        ByteAdmissionError::ControlAllocation(PrepaidSharedError::Allocator { .. }) => {
            ExecutionDeferral::AllocationUnavailable.into()
        }
        ByteAdmissionError::ControlAllocation(PrepaidSharedError::Reservation(_)) => {
            ExecutionDeferral::ActiveMemoryCapacity.into()
        }
        ByteAdmissionError::Length { .. } | ByteAdmissionError::ForeignBudget => {
            return PublicationError::RecoveryRequired(error.to_string());
        }
    };
    PublicationError::Deferred(original.into())
}

/// Classify the actual validation error before retaining any diagnostic state.
/// Changed predecessors require another authenticated acquisition; their observation
/// never authorizes reuse. An impossible pool demand has no release source and may
/// require local policy changes. Malformed custody and poisoned owners require recovery.
pub(super) fn validation_failure(error: &BlockValidationError) -> Option<PublicationError> {
    use crate::state::{
        BlockHashAdmissionError, EvidencePreparationError, MembershipAdmissionError,
        StateStorageAdmissionError, StateViewError,
    };
    use mv::storage::AdmittedStorageError;
    let source = match error {
        BlockValidationError::NativeSourceChanged { .. } => {
            return Some(if cfg!(all(test, sumeragi_core_mutation = "HC98")) {
                PublicationError::RecoveryRequired(error.to_string())
            } else {
                PublicationError::Retryable(error.to_string())
            });
        }
        BlockValidationError::StateView(original) => match original {
            StateViewError::Busy(wait) => PublicationDeferral::StateViewBusy(wait.clone()),
            StateViewError::Runtime(crate::state::LaneLifecycleError::NposPolicy(
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason),
            )) if reason.reason() == ExecutionDeferral::LocalInvariantViolation => {
                return Some(PublicationError::RecoveryRequired(reason.to_string()));
            }
            StateViewError::Runtime(crate::state::LaneLifecycleError::NposPolicy(
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason),
            )) => PublicationDeferral::Execution(reason.clone()),
            StateViewError::Changed | StateViewError::Poisoned | StateViewError::Runtime(_) => {
                return Some(PublicationError::RecoveryRequired(original.to_string()));
            }
        },
        BlockValidationError::ExecutionDeferred(original) => {
            if !cfg!(all(test, sumeragi_core_mutation = "HC86"))
                && original.reason() == ExecutionDeferral::LocalInvariantViolation
            {
                return Some(PublicationError::RecoveryRequired(original.to_string()));
            }
            PublicationDeferral::Execution(original.clone())
        }
        BlockValidationError::StateStorageAdmission(original) => match original {
            StateStorageAdmissionError::World(
                AdmittedStorageError::Poisoned { .. }
                | AdmittedStorageError::Planning(_)
                | AdmittedStorageError::ScopeIdentity
                | AdmittedStorageError::PolicyIdentity
                | AdmittedStorageError::PolicyDemand { .. },
            )
            | StateStorageAdmissionError::NativeAmx(
                super::super::amx::NativeAmxAdmissionError::Invalid(_),
            ) => return Some(PublicationError::RecoveryRequired(original.to_string())),
            StateStorageAdmissionError::World(
                AdmittedStorageError::Busy { .. }
                | AdmittedStorageError::Changed
                | AdmittedStorageError::Allocation(_)
                | AdmittedStorageError::Allocator { .. },
            )
            | StateStorageAdmissionError::NativeAmx(
                super::super::amx::NativeAmxAdmissionError::Admission(_)
                | super::super::amx::NativeAmxAdmissionError::Allocator { .. }
                | super::super::amx::NativeAmxAdmissionError::Codec(_),
            )
            | StateStorageAdmissionError::AmxDecode(_)
            | StateStorageAdmissionError::RootScopeDecode(_) => {
                PublicationDeferral::StateStorage(original.clone())
            }
        },
        BlockValidationError::EvidencePreparation(original) => match original {
            EvidencePreparationError::Invariant => {
                return Some(PublicationError::RecoveryRequired(original.to_string()));
            }
            EvidencePreparationError::OriginalHistoryPending => {
                return Some(PublicationError::Retryable(original.to_string()));
            }
            EvidencePreparationError::Admission(_)
            | EvidencePreparationError::Allocator { .. }
            | EvidencePreparationError::DecodeScope { .. }
            | EvidencePreparationError::DecodeResource(_) => {
                PublicationDeferral::EvidencePreparation(original.clone())
            }
        },
        BlockValidationError::BlockHashAdmission(original) => match original {
            BlockHashAdmissionError::Planning(_)
            | BlockHashAdmissionError::Poisoned
            | BlockHashAdmissionError::ReadOnly => {
                return Some(PublicationError::RecoveryRequired(original.to_string()));
            }
            BlockHashAdmissionError::Busy(_)
            | BlockHashAdmissionError::Capacity(_)
            | BlockHashAdmissionError::Changed(_) => {
                PublicationDeferral::BlockHashAdmission(original.clone())
            }
        },
        BlockValidationError::MembershipAdmission(original) => match original {
            MembershipAdmissionError::Planning(_)
            | MembershipAdmissionError::Poisoned
            | MembershipAdmissionError::SourceNotFunded => {
                return Some(PublicationError::RecoveryRequired(original.to_string()));
            }
            MembershipAdmissionError::Busy(_)
            | MembershipAdmissionError::Capacity(_)
            | MembershipAdmissionError::Changed(_)
            | MembershipAdmissionError::Allocator { .. } => {
                PublicationDeferral::MembershipAdmission(original.clone())
            }
        },
        BlockValidationError::LaneStorage(original) => {
            let message = format!("lane storage: {original}");
            return Some(
                if matches!(
                    original.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) {
                    PublicationError::Retryable(message)
                } else {
                    PublicationError::RecoveryRequired(message)
                },
            );
        }
        BlockValidationError::DaIndexHydration(reason)
        | BlockValidationError::LocalStorageRecoveryRequired { reason } => {
            return Some(PublicationError::RecoveryRequired(reason.clone()));
        }
        _ => return None,
    };
    Some(
        if matches!(
            source.allocation_refusal(),
            Some(iroha_allocation::AllocationRefusal::DemandOverflow)
        ) {
            PublicationError::RecoveryRequired(source.to_string())
        } else {
            PublicationError::Deferred(source)
        },
    )
}
