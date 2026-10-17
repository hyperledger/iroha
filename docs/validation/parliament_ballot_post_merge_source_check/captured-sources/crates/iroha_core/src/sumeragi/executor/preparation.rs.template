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
            return PublicationError::RecoveryRequired(error.to_string());
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
        super::super::commitment::ResultPreimageError::ForeignBudget
        | super::super::commitment::ResultPreimageError::PreimageLength(_)
        | super::super::commitment::ResultPreimageError::Encoding(_) => {
            // Repeating this unchanged immutable source cannot repair its custody,
            // protocol extent or canonical serializer. Never blame the peer.
            PublicationError::RecoveryRequired(error.to_string())
        }
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
        // No pool release can enlarge this unchanged prepaid parent.
        CertificateAdmissionError::ControlAllocation(PrepaidSharedError::Reservation(_)) => {
            PublicationError::RecoveryRequired(error.to_string())
        }
        CertificateAdmissionError::ForeignBudget => {
            PublicationError::RecoveryRequired(error.to_string())
        }
    }
}

/// Preserve the resource owner across the actual producer/driver boundary.
/// Diagnostic side fields are not consumed by the driver's retry gate.
pub(super) fn producer_deferral(original: PublicationDeferral) -> PublicationError {
    let classified = match original {
        PublicationDeferral::Execution(original) => {
            validation_failure(BlockValidationError::ExecutionDeferred(original))
                .expect("execution refusal has an explicit validation classification")
        }
        other => PublicationError::Deferred(other),
    };
    if cfg!(all(test, sumeragi_core_mutation = "HC247"))
        && let PublicationError::Deferred(original) = classified
    {
        PublicationError::Retryable(original.to_string())
    } else {
        classified
    }
}

/// Reuse the validation classifier for the same original assembly refusal.
/// Permanent custody failures remain recovery errors, and non-resource failures remain local.
pub(super) fn payload_failure(
    error: super::payload::PayloadError,
) -> Result<PublicationError, super::payload::PayloadError> {
    use super::payload::PayloadError;
    use crate::state::StateAdmissionError;
    let classified = match error {
        PayloadError::SignatureCustodyInvariant(reason) => {
            return Ok(PublicationError::RecoveryRequired(reason));
        }
        PayloadError::RoutingDeferred(original) | PayloadError::DecodeResource(original) => {
            PublicationError::Deferred(original.into())
        }
        PayloadError::SccpForgeryPreparation(original) => {
            validation_failure(BlockValidationError::StateStorageAdmission(original))
                .expect("SCCP forgery preparation always has a local classification")
        }
        PayloadError::StakingPreparation(original) => {
            validation_failure(BlockValidationError::EvidencePreparation(original))
                .expect("evidence preparation always has a local classification")
        }
        PayloadError::StakingAdmission(original) => {
            let original = match original {
                StateAdmissionError::Storage(error) => {
                    BlockValidationError::StateStorageAdmission(error)
                }
                StateAdmissionError::History(error) => {
                    BlockValidationError::BlockHashAdmission(error)
                }
                StateAdmissionError::Membership(error) => {
                    BlockValidationError::MembershipAdmission(error)
                }
            };
            validation_failure(original).expect("State admission always has a local classification")
        }
        other => return Err(other),
    };
    Ok(match classified {
        PublicationError::Deferred(original) => producer_deferral(original),
        other => other,
    })
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
            return PublicationError::RecoveryRequired(error.to_string());
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
pub(super) fn validation_failure(
    error: BlockValidationError,
) -> Result<PublicationError, BlockValidationError> {
    use crate::state::{
        BlockHashAdmissionError, EvidencePreparationError, MembershipAdmissionError,
        StateStorageAdmissionError, StateViewError,
    };
    use mv::storage::AdmittedStorageError;
    if let BlockValidationError::GovernanceDueUnavailable(original) = error {
        return Ok(PublicationError::Retryable(original.to_string()));
    }
    let source = match error {
        BlockValidationError::NativeHistory(original) => {
            return Ok(super::parent_native_source_error(original));
        }
        BlockValidationError::NativeSourceChanged { .. } => {
            return Ok(if cfg!(all(test, sumeragi_core_mutation = "HC98")) {
                PublicationError::RecoveryRequired(error.to_string())
            } else {
                PublicationError::Retryable(error.to_string())
            });
        }
        BlockValidationError::StateView(original) => match original {
            StateViewError::Busy(wait) => PublicationDeferral::StateViewBusy(wait),
            StateViewError::Runtime(crate::state::LaneLifecycleError::NposPolicy(
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason),
            )) if reason.reason() == ExecutionDeferral::LocalInvariantViolation => {
                return Ok(PublicationError::RecoveryRefusal(reason));
            }
            StateViewError::Runtime(crate::state::LaneLifecycleError::NposPolicy(
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason),
            )) => PublicationDeferral::Execution(reason),
            StateViewError::Changed | StateViewError::Poisoned | StateViewError::Runtime(_) => {
                return Ok(PublicationError::RecoveryRequired(original.to_string()));
            }
        },
        BlockValidationError::ExecutionDeferred(original) => {
            // HC44 checks the actual caller transfer, never an unused duplicate slot.
            if cfg!(all(test, sumeragi_core_mutation = "HC44")) {
                return Ok(PublicationError::Retryable(original.to_string()));
            }
            if !cfg!(all(test, sumeragi_core_mutation = "HC86"))
                && original.reason() == ExecutionDeferral::LocalInvariantViolation
            {
                return Ok(PublicationError::RecoveryRefusal(original));
            }
            PublicationDeferral::Execution(original)
        }
        BlockValidationError::StateStorageAdmission(original) => match original {
            StateStorageAdmissionError::World(
                AdmittedStorageError::Poisoned { .. }
                | AdmittedStorageError::Planning(_)
                | AdmittedStorageError::ScopeIdentity
                | AdmittedStorageError::PolicyIdentity
                | AdmittedStorageError::PolicyDemand { .. },
            )
            | StateStorageAdmissionError::SccpForgery(
                crate::state::sccp_forgery_custody::ForgeryStorageError::Invalid
                | crate::state::sccp_forgery_custody::ForgeryStorageError::Storage(
                    AdmittedStorageError::Poisoned { .. }
                    | AdmittedStorageError::Planning(_)
                    | AdmittedStorageError::ScopeIdentity
                    | AdmittedStorageError::PolicyIdentity
                    | AdmittedStorageError::PolicyDemand { .. },
                ),
            )
            | StateStorageAdmissionError::SccpEvidence(EvidencePreparationError::Invariant)
            | StateStorageAdmissionError::NativeAmx(
                super::super::amx::NativeAmxAdmissionError::Invalid(_),
            ) => return Ok(PublicationError::RecoveryRequired(original.to_string())),
            StateStorageAdmissionError::SccpEvidence(
                EvidencePreparationError::OriginalHistoryPending,
            ) => {
                return Ok(PublicationError::Retryable(original.to_string()));
            }
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
            | StateStorageAdmissionError::SccpForgery(
                crate::state::sccp_forgery_custody::ForgeryStorageError::Codec(_)
                | crate::state::sccp_forgery_custody::ForgeryStorageError::Storage(
                    AdmittedStorageError::Busy { .. }
                    | AdmittedStorageError::Changed
                    | AdmittedStorageError::Allocation(_)
                    | AdmittedStorageError::Allocator { .. },
                ),
            )
            | StateStorageAdmissionError::SccpEvidence(
                EvidencePreparationError::Admission(_)
                | EvidencePreparationError::Allocator { .. }
                | EvidencePreparationError::DecodeScope { .. }
                | EvidencePreparationError::DecodeResource(_),
            )
            | StateStorageAdmissionError::AmxDecode(_)
            | StateStorageAdmissionError::RootScopeDecode(_) => {
                PublicationDeferral::StateStorage(original)
            }
        },
        BlockValidationError::EvidencePreparation(original) => match original {
            EvidencePreparationError::Invariant => {
                return Ok(PublicationError::RecoveryRequired(original.to_string()));
            }
            EvidencePreparationError::OriginalHistoryPending => {
                return Ok(PublicationError::Retryable(original.to_string()));
            }
            EvidencePreparationError::Admission(_)
            | EvidencePreparationError::Allocator { .. }
            | EvidencePreparationError::DecodeScope { .. }
            | EvidencePreparationError::DecodeResource(_) => {
                PublicationDeferral::EvidencePreparation(original)
            }
        },
        BlockValidationError::BlockHashAdmission(original) => match original {
            BlockHashAdmissionError::Planning(_)
            | BlockHashAdmissionError::Poisoned
            | BlockHashAdmissionError::ReadOnly => {
                return Ok(PublicationError::RecoveryRequired(original.to_string()));
            }
            BlockHashAdmissionError::Busy(_)
            | BlockHashAdmissionError::Capacity(_)
            | BlockHashAdmissionError::Changed(_) => {
                PublicationDeferral::BlockHashAdmission(original)
            }
        },
        BlockValidationError::MembershipAdmission(original) => match original {
            MembershipAdmissionError::Planning(_)
            | MembershipAdmissionError::Poisoned
            | MembershipAdmissionError::SourceNotFunded => {
                return Ok(PublicationError::RecoveryRequired(original.to_string()));
            }
            MembershipAdmissionError::Busy(_)
            | MembershipAdmissionError::Capacity(_)
            | MembershipAdmissionError::Changed(_)
            | MembershipAdmissionError::Allocator { .. } => {
                PublicationDeferral::MembershipAdmission(original)
            }
        },
        BlockValidationError::LaneStorage(original) => {
            let message = format!("lane storage: {original}");
            return Ok(
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
            return Ok(PublicationError::RecoveryRequired(reason));
        }
        other => return Err(other),
    };
    Ok(
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
