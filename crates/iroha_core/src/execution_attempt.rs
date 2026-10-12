//! Non-serializable local attempt outcomes and the instruction-layer retry owner.

use iroha_data_model::ValidationFail;
use ivm::error::{ExecutionDeferral, VMError};

/// Native Core boundary at which an unfinished execution returned to its caller.
///
/// This is non-wire diagnostic context. It grants no retry, execution or finality
/// authority and does not replace the original refusal or its release source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionPhase {
    /// Lane preparation refused inside the native output finalizer, before sealing.
    NativeLaneFinalizer,
}

/// An unfinished local execution, retaining the original capacity refusal owner.
///
/// This type has no wire codec. A capacity release observation survives cache
/// checkout, transaction rollback and output abandonment with the same pool
/// identity. It authorizes a fresh local attempt, never a transaction rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionDeferred {
    reason: ExecutionDeferral,
    original: Option<OriginalRefusal>,
    phase: Option<ExecutionPhase>,
}

/// The actual non-wire cause, never reconstructed from diagnostic fields.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OriginalRefusal {
    Allocation(iroha_allocation::AllocationRefusal),
    Decode(norito::core::DecodeLocalRefusal),
}

impl ExecutionDeferred {
    /// Native boundary provenance, independent of the original resource category.
    pub const fn phase(&self) -> Option<ExecutionPhase> {
        self.phase
    }

    /// Record the actual lane-finalizer boundary without replacing its refusal owner.
    pub(crate) fn at_native_lane_finalizer(mut self) -> Self {
        self.phase = Some(ExecutionPhase::NativeLaneFinalizer);
        self
    }

    /// The VM-facing local reason, without erasing this owner's retry evidence.
    pub const fn reason(&self) -> ExecutionDeferral {
        self.reason
    }

    /// Borrow the original allocation refusal and its pre-probe release observation.
    ///
    /// Only `Capacity` carries a release-driven retry source. An allocator
    /// refusal, arithmetic overflow, or demand exceeding the configured pool
    /// limit cannot be cured by waiting on an invented notification.
    pub fn allocation_refusal(&self) -> Option<&iroha_allocation::AllocationRefusal> {
        match self.original.as_ref() {
            Some(OriginalRefusal::Allocation(original)) => Some(original),
            _ => None,
        }
    }

    /// Borrow the captured decoder cause, including its original opaque scope identity.
    /// No pool release observation is created by retaining this decoder owner.
    pub fn decode_refusal(&self) -> Option<&norito::core::DecodeLocalRefusal> {
        match self.original.as_ref() {
            Some(OriginalRefusal::Decode(original)) => Some(original),
            _ => None,
        }
    }

    /// Preserve the original refusal across a VM/host error boundary.
    /// Native finalizer provenance is Core context, not a VM error category.
    pub fn from_vm_error(error: &VMError) -> Option<Self> {
        match error.as_unmetered() {
            VMError::AllocationDeferred(refusal) => Some(refusal.clone().into()),
            VMError::DecodeDeferred(original) => Some(original.clone().into()),
            VMError::ExecutionDeferred(reason) => Some((*reason).into()),
            other => other.execution_deferral().map(Into::into),
        }
    }

    /// Move this owner through a VM host boundary without losing its release source.
    /// Native finalizer provenance stays outside the VM error surface.
    pub fn into_vm_error(self) -> VMError {
        match self.original {
            Some(OriginalRefusal::Allocation(refusal)) => VMError::AllocationDeferred(refusal),
            Some(OriginalRefusal::Decode(original)) => VMError::DecodeDeferred(original),
            None => VMError::ExecutionDeferred(self.reason),
        }
    }
}

impl From<ExecutionDeferral> for ExecutionDeferred {
    fn from(reason: ExecutionDeferral) -> Self {
        Self {
            reason,
            original: None,
            phase: None,
        }
    }
}

impl From<iroha_allocation::AllocationRefusal> for ExecutionDeferred {
    fn from(refusal: iroha_allocation::AllocationRefusal) -> Self {
        Self {
            reason: ExecutionDeferral::ActiveMemoryCapacity,
            original: Some(OriginalRefusal::Allocation(refusal)),
            phase: None,
        }
    }
}

impl From<norito::core::DecodeLocalRefusal> for ExecutionDeferred {
    fn from(original: norito::core::DecodeLocalRefusal) -> Self {
        let reason = match original.kind() {
            norito::core::DecodeLocalRefusalKind::Allocator => {
                ExecutionDeferral::AllocationUnavailable
            }
            norito::core::DecodeLocalRefusalKind::EnclosingLimit => {
                ExecutionDeferral::ActiveMemoryCapacity
            }
        };
        Self {
            reason,
            original: Some(OriginalRefusal::Decode(original)),
            phase: None,
        }
    }
}

impl From<iroha_data_model::block::SharedBlockAdmissionError> for ExecutionDeferred {
    fn from(error: iroha_data_model::block::SharedBlockAdmissionError) -> Self {
        use iroha_allocation::PrepaidSharedError;
        use iroha_data_model::block::SharedBlockAdmissionError;
        match error {
            SharedBlockAdmissionError::Admission(original) => original.into(),
            SharedBlockAdmissionError::Allocation(PrepaidSharedError::Allocator { .. }) => {
                ExecutionDeferral::AllocationUnavailable.into()
            }
            SharedBlockAdmissionError::Allocation(PrepaidSharedError::Reservation(_)) => {
                ExecutionDeferral::ActiveMemoryCapacity.into()
            }
        }
    }
}

impl core::fmt::Display for ExecutionDeferred {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.phase == Some(ExecutionPhase::NativeLaneFinalizer) {
            formatter.write_str("native lane finalizer: ")?;
        }
        match &self.original {
            Some(OriginalRefusal::Allocation(refusal)) => refusal.fmt(formatter),
            Some(OriginalRefusal::Decode(original)) => original.fmt(formatter),
            None => self.reason.fmt(formatter),
        }
    }
}

impl std::error::Error for ExecutionDeferred {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.original {
            Some(OriginalRefusal::Allocation(original)) => Some(original),
            Some(OriginalRefusal::Decode(original)) => Some(original),
            None => None,
        }
    }
}

/// Require a completed outcome in deterministic execution regression tests.
#[cfg(test)]
pub(crate) fn expect_completed_rejection<E>(error: ExecutionAttemptError<E>) -> E {
    match error {
        ExecutionAttemptError::Rejected(error) => error,
        ExecutionAttemptError::Deferred(reason) => panic!("unexpected local deferral: {reason}"),
    }
}

/// Separate a deterministic rejection from an incomplete local attempt.
/// No conversion from this type to a wire rejection is provided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionAttemptError<E> {
    /// Execution completed with a deterministic rejection.
    Rejected(E),
    /// Execution did not complete and must be retried locally.
    Deferred(ExecutionDeferred),
}

impl<E> ExecutionAttemptError<E> {
    /// Preserve the local retry owner while projecting only completed rejection into a VM error.
    pub(crate) fn into_vm_error(self, rejected: impl FnOnce(E) -> VMError) -> VMError {
        match self {
            Self::Rejected(error) => rejected(error),
            Self::Deferred(reason) => reason.into_vm_error(),
        }
    }

    /// Transform a completed rejection while retaining the local retry carrier.
    pub fn map_rejection<T>(self, map: impl FnOnce(E) -> T) -> ExecutionAttemptError<T> {
        match self {
            Self::Rejected(error) => ExecutionAttemptError::Rejected(map(error)),
            Self::Deferred(reason) => ExecutionAttemptError::Deferred(reason),
        }
    }
}

impl ExecutionAttemptError<std::io::Error> {
    /// Operational I/O category for storage scheduling; matching this does not consume the
    /// original local refusal. Callers must retain `Deferred` with the unfinished job.
    pub fn io_kind(&self) -> std::io::ErrorKind {
        match self {
            Self::Rejected(error) => error.kind(),
            Self::Deferred(_) => std::io::ErrorKind::WouldBlock,
        }
    }
}

impl<E> From<E> for ExecutionAttemptError<E> {
    fn from(error: E) -> Self {
        Self::Rejected(error)
    }
}

impl From<&str> for ExecutionAttemptError<String> {
    fn from(error: &str) -> Self {
        Self::Rejected(error.to_owned())
    }
}

impl<E: core::fmt::Display> core::fmt::Display for ExecutionAttemptError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rejected(error) => error.fmt(f),
            Self::Deferred(reason) => write!(f, "execution deferred: {reason}"),
        }
    }
}

impl<E: core::fmt::Display + core::fmt::Debug + 'static> std::error::Error
    for ExecutionAttemptError<E>
{
}

/// Preserve original signature/certificate child allocation and canonical refusal provenance.
/// Source/control invariants are contextual failures; callers must not turn them
/// into a protocol verdict. No integer quota is treated as physical custody.
pub(crate) fn prepared_signature_block_attempt_error<E>(
    error: iroha_data_model::block::PreparedSignatureBlockError,
    rejected: impl FnOnce(String) -> E,
) -> ExecutionAttemptError<E> {
    use iroha_allocation::{
        ChargedBufferError, ChargedBufferFromChargeError, PrepaidSharedError, SharedFromChargeError,
    };
    use iroha_data_model::block::commit_certificate::CertificateCustodyError;
    use iroha_data_model::block::{BlockSignatureCustodyError, PreparedSignatureBlockError};
    use iroha_data_model::da::commitment::{DaCommitmentCustodyError, DaProofPolicyCustodyError};
    use norito::core::{PreparedDecodeError, PreparedDecodeScopeError};
    fn buffer(error: ChargedBufferError) -> ExecutionDeferred {
        match error {
            ChargedBufferError::Admission(original) => original.into(),
            ChargedBufferError::Allocator { .. } => ExecutionDeferral::AllocationUnavailable.into(),
        }
    }
    fn control(error: PrepaidSharedError) -> ExecutionDeferred {
        match error {
            PrepaidSharedError::Allocator { .. } => ExecutionDeferral::AllocationUnavailable.into(),
            PrepaidSharedError::Reservation(_) => ExecutionDeferral::ActiveMemoryCapacity.into(),
        }
    }
    match error {
        PreparedSignatureBlockError::Storage(original) => {
            ExecutionAttemptError::Deferred(buffer(original))
        }
        PreparedSignatureBlockError::Frame(original)
        | PreparedSignatureBlockError::Certificate(CertificateCustodyError::Decode(original))
        | PreparedSignatureBlockError::Policy(DaProofPolicyCustodyError::Decode(original))
        | PreparedSignatureBlockError::Commitments(DaCommitmentCustodyError::Decode(original))
        | PreparedSignatureBlockError::Decode(PreparedDecodeError::Codec(original))
        | PreparedSignatureBlockError::Decode(PreparedDecodeError::Destination(
            BlockSignatureCustodyError::Decode(original),
        )) => canonical_decode_attempt_error(original, |error| rejected(error.to_string())),
        PreparedSignatureBlockError::Certificate(CertificateCustodyError::Admission(original))
        | PreparedSignatureBlockError::Policy(DaProofPolicyCustodyError::Admission(original))
        | PreparedSignatureBlockError::Commitments(DaCommitmentCustodyError::Admission(original)) => {
            ExecutionAttemptError::Deferred(original.into())
        }
        PreparedSignatureBlockError::Certificate(CertificateCustodyError::Buffer(
            ChargedBufferFromChargeError::Allocator { .. },
        ))
        | PreparedSignatureBlockError::Certificate(CertificateCustodyError::Control(
            SharedFromChargeError::Allocator { .. },
        ))
        | PreparedSignatureBlockError::Policy(DaProofPolicyCustodyError::Buffer(
            ChargedBufferFromChargeError::Allocator { .. },
        ))
        | PreparedSignatureBlockError::Policy(DaProofPolicyCustodyError::Control(
            SharedFromChargeError::Allocator { .. },
        ))
        | PreparedSignatureBlockError::Commitments(DaCommitmentCustodyError::Buffer(
            ChargedBufferFromChargeError::Allocator { .. },
        ))
        | PreparedSignatureBlockError::Commitments(DaCommitmentCustodyError::Control(
            SharedFromChargeError::Allocator { .. },
        )) => ExecutionAttemptError::Deferred(ExecutionDeferral::AllocationUnavailable.into()),
        PreparedSignatureBlockError::Decode(PreparedDecodeError::Destination(
            BlockSignatureCustodyError::Buffer(original),
        )) => ExecutionAttemptError::Deferred(buffer(original)),
        PreparedSignatureBlockError::Decode(PreparedDecodeError::Destination(
            BlockSignatureCustodyError::ControlAdmission(original),
        )) => ExecutionAttemptError::Deferred(original.into()),
        PreparedSignatureBlockError::Decode(PreparedDecodeError::Destination(
            BlockSignatureCustodyError::ControlAllocation(original),
        )) => ExecutionAttemptError::Deferred(control(original)),
        PreparedSignatureBlockError::Scope(PreparedDecodeScopeError::Allocation(original))
        | PreparedSignatureBlockError::Decode(PreparedDecodeError::Scope(
            PreparedDecodeScopeError::Allocation(original),
        )) => ExecutionAttemptError::Deferred(control(original)),
        PreparedSignatureBlockError::Scope(PreparedDecodeScopeError::Reservation(_))
        | PreparedSignatureBlockError::Decode(PreparedDecodeError::Scope(
            PreparedDecodeScopeError::Reservation(_),
        )) => ExecutionAttemptError::Deferred(ExecutionDeferral::ActiveMemoryCapacity.into()),
        invariant => ExecutionAttemptError::Rejected(rejected(invariant.to_string())),
    }
}

/// Preserve a local Norito refusal before a caller constructs a deterministic rejection.
///
/// Matching surviving field, element and allocation ceilings belong to the current attempt. An
/// allocator failure is local even without an enclosing scope. Global archive and inner format limits,
/// malformed input and canonical-depth rejection remain deterministic. A matching surviving
/// narrower caller depth is local, like its field and allocation ceilings. Norito's cumulative
/// scope has no allocation-pool release owner, so this must not invent one.
pub(crate) fn norito_decode_attempt_error<E>(
    error: norito::Error,
    rejected: impl FnOnce(norito::Error) -> E,
) -> ExecutionAttemptError<E> {
    let local_limit = (norito::core::decode_error_matches_active_limits(&error)
        && !(cfg!(all(test, sumeragi_core_mutation = "HC46"))
            && matches!(&error, norito::Error::NestingDepthExceeded { .. })))
        || (cfg!(all(test, sumeragi_core_mutation = "HC33"))
            && norito::core::decode_limits_active()
            && matches!(
                &error,
                norito::Error::ArchiveLengthExceeded { .. }
                    | norito::Error::SequenceLengthExceeded { .. }
                    | norito::Error::FieldLengthExceeded { .. }
                    | norito::Error::TotalElementsExceeded { .. }
                    | norito::Error::TotalAllocationExceeded { .. }
            ));
    let reason = match &error {
        norito::Error::AllocationFailed { .. } => Some(ExecutionDeferral::AllocationUnavailable),
        _ if local_limit => Some(ExecutionDeferral::ActiveMemoryCapacity),
        _ => None,
    };
    if !cfg!(all(test, sumeragi_core_mutation = "HC32"))
        && let Some(reason) = reason
    {
        return ExecutionAttemptError::Deferred(reason.into());
    }
    ExecutionAttemptError::Rejected(rejected(error))
}

/// Consume the canonical decoder's captured origin after its caller scopes retire.
/// Invalid source bytes remain completed rejection; numeric error fields are not reclassified.
pub(crate) fn canonical_decode_attempt_error<E>(
    error: norito::core::DecodeAttemptError,
    rejected: impl FnOnce(norito::core::DecodeAttemptError) -> E,
) -> ExecutionAttemptError<E> {
    if cfg!(all(test, sumeragi_core_mutation = "HC32")) {
        return ExecutionAttemptError::Rejected(rejected(error));
    }
    match error.into_local_refusal() {
        Ok(original) => ExecutionAttemptError::Deferred(original.into()),
        Err(error) => ExecutionAttemptError::Rejected(rejected(error)),
    }
}

/// Borrow the decoder's captured origin while its actual error owner stays retained for retry.
/// This shares the consuming boundary's classification and invents no pool release source.
pub(crate) fn canonical_decode_deferral(
    error: &norito::core::DecodeAttemptError,
) -> Option<ExecutionDeferred> {
    if cfg!(all(test, sumeragi_core_mutation = "HC32")) {
        return None;
    }
    error.local_refusal().map(Into::into)
}

/// Preserve an original native storage/decode refusal before its caller formats a rejection.
///
/// Kura's durable metadata and body decoder share the active cumulative codec scope.
/// Physical buffer refusals retain their original pool owner; malformed bytes and
/// changed source slots remain completed errors chosen by the existing caller.
pub(crate) fn kura_read_attempt_error<E>(
    error: crate::kura::Error,
    rejected: impl FnOnce(crate::kura::Error) -> E,
) -> ExecutionAttemptError<E> {
    #[cfg(all(test, sumeragi_core_mutation = "HC206"))]
    return ExecutionAttemptError::Rejected(rejected(error));
    #[cfg(not(all(test, sumeragi_core_mutation = "HC206")))]
    {
        use crate::kura::Error;
        match error {
            Error::NoritoFrame(error) => {
                norito_decode_attempt_error(error, |error| rejected(Error::NoritoFrame(error)))
            }
            Error::BlockDecode(error) => {
                canonical_decode_attempt_error(error, |error| rejected(Error::BlockDecode(error)))
            }
            Error::NativeFrameAllocation(error) => {
                let original = match error {
                    iroha_allocation::ChargedBufferError::Admission(original) => original.into(),
                    iroha_allocation::ChargedBufferError::Allocator { .. } => {
                        ExecutionDeferral::AllocationUnavailable.into()
                    }
                };
                ExecutionAttemptError::Deferred(original)
            }
            error => ExecutionAttemptError::Rejected(rejected(error)),
        }
    }
}

/// Classify original JSON decoding before a diagnostic can discard local retry identity.
///
/// Scoped JSON errors delegate to the existing exact active-observer classifier. Rejected
/// scope tags remain unchanged; a saved sibling error cannot gain retry authority from a fresh
/// refusal. Malformed input, intrinsic parser bounds and recursive depth remain completed errors.
pub(crate) fn json_decode_attempt_error<E>(
    error: norito::json::Error,
    rejected: impl FnOnce(norito::json::Error) -> E,
) -> ExecutionAttemptError<E> {
    match error {
        norito::json::Error::ScopedDecodeResource(original) => {
            match norito_decode_attempt_error(
                norito::Error::ScopedDecodeResource(original),
                std::convert::identity,
            ) {
                ExecutionAttemptError::Deferred(original) => {
                    ExecutionAttemptError::Deferred(original)
                }
                ExecutionAttemptError::Rejected(original) => ExecutionAttemptError::Rejected(
                    rejected(norito::json::Error::from_decode_resource(original)),
                ),
            }
        }
        norito::json::Error::DecodeResourceLimit
        | norito::json::Error::DecodeResource(
            norito::core::DecodeResourceError::ArchiveLengthExceeded { .. }
            | norito::core::DecodeResourceError::SequenceLengthExceeded { .. }
            | norito::core::DecodeResourceError::FieldLengthExceeded { .. }
            | norito::core::DecodeResourceError::TotalElementsExceeded { .. }
            | norito::core::DecodeResourceError::TotalAllocationExceeded { .. },
        ) => ExecutionAttemptError::Deferred(ExecutionDeferral::ActiveMemoryCapacity.into()),
        norito::json::Error::AllocationFailed
        | norito::json::Error::DecodeResource(
            norito::core::DecodeResourceError::AllocationFailed { .. },
        ) => ExecutionAttemptError::Deferred(ExecutionDeferral::AllocationUnavailable.into()),
        error => ExecutionAttemptError::Rejected(rejected(error)),
    }
}

/// Preserve the original signed-genesis decoder before projecting completed authentication errors.
pub(crate) fn genesis_read_attempt_error<E>(
    error: iroha_data_model::sumeragi_finality::GenesisReadError,
    rejected: impl FnOnce(iroha_data_model::sumeragi_finality::GenesisReadError) -> E,
) -> ExecutionAttemptError<E> {
    use iroha_data_model::sumeragi_finality::GenesisReadError;
    match error {
        GenesisReadError::Json(error) => {
            json_decode_attempt_error(error, |error| rejected(GenesisReadError::Json(error)))
        }
        error => ExecutionAttemptError::Rejected(rejected(error)),
    }
}

/// Classify VM failure before any diagnostic conversion can discard local retry identity.
pub(crate) fn vm_attempt_error(
    error: VMError,
    deterministic: impl FnOnce(VMError) -> ValidationFail,
) -> ExecutionAttemptError<ValidationFail> {
    match ExecutionDeferred::from_vm_error(&error) {
        Some(reason) => ExecutionAttemptError::Deferred(reason),
        None => ExecutionAttemptError::Rejected(deterministic(error)),
    }
}

impl crate::state::WorldTransaction<'_, '_> {
    /// Retain the first original local retry owner at the common mutation boundary.
    /// This journal field has no serialization or monetary authority.
    pub(crate) fn defer_execution(&self, reason: impl Into<ExecutionDeferred>) -> ValidationFail {
        self.record_execution_deferral(reason);
        ValidationFail::InternalError("local execution attempt did not complete".into())
    }

    /// Keep the first retry owner without constructing a diagnostic that a caller discards.
    fn record_execution_deferral(&self, reason: impl Into<ExecutionDeferred>) {
        self.execution_deferral
            .borrow_mut()
            .get_or_insert_with(|| reason.into());
    }

    /// Bridge an ISI-owned signature while keeping its original local refusal.
    pub(crate) fn attempt_error_to_instruction_error(
        &self,
        error: ExecutionAttemptError<iroha_data_model::isi::error::InstructionExecutionError>,
    ) -> iroha_data_model::isi::error::InstructionExecutionError {
        match error {
            ExecutionAttemptError::Rejected(error) => error,
            ExecutionAttemptError::Deferred(reason) => {
                self.record_execution_deferral(reason);
                iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(
                    "local execution attempt did not complete".into(),
                )
            }
        }
    }
}

impl crate::state::StateTransaction<'_, '_> {
    /// Record the first local refusal before bridging a model-owned ISI signature.
    /// The enclosing attempt must extract this owner before settling any output.
    pub(crate) fn defer_execution(
        &mut self,
        reason: impl Into<ExecutionDeferred>,
    ) -> ValidationFail {
        self.world.defer_execution(reason)
    }

    /// Borrow the sticky local retry reason without clearing its publication guard.
    pub(crate) fn execution_deferral(&self) -> Option<ExecutionDeferred> {
        self.world.execution_deferral.borrow().clone()
    }

    /// Bridge a model-owned instruction result while retaining the retry owner.
    pub(crate) fn attempt_error_to_validation_fail(
        &mut self,
        error: ExecutionAttemptError<ValidationFail>,
    ) -> ValidationFail {
        match error {
            ExecutionAttemptError::Rejected(error) => error,
            ExecutionAttemptError::Deferred(reason) => self.defer_execution(reason),
        }
    }

    /// Preserve a local read owner before bridging a model-owned instruction result.
    pub(crate) fn attempt_error_to_instruction_error(
        &mut self,
        error: ExecutionAttemptError<iroha_data_model::isi::error::InstructionExecutionError>,
    ) -> iroha_data_model::isi::error::InstructionExecutionError {
        match error {
            ExecutionAttemptError::Rejected(error) => error,
            ExecutionAttemptError::Deferred(reason) => {
                self.world.record_execution_deferral(reason);
                iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(
                    "local instruction read did not complete".into(),
                )
            }
        }
    }

    /// Preserve a local VM refusal through an instruction API owned by the model.
    pub(crate) fn vm_error_to_validation_fail(
        &mut self,
        error: VMError,
        deterministic: impl FnOnce(VMError) -> ValidationFail,
    ) -> ValidationFail {
        match ExecutionDeferred::from_vm_error(&error) {
            Some(reason) => self.defer_execution(reason),
            None => deterministic(error),
        }
    }

    /// Keep analysis allocation refusal local before constructing a diagnostic.
    pub(crate) fn program_analysis_error_to_validation_fail(
        &mut self,
        error: ivm::analysis::ProgramAnalysisError,
        context: &str,
    ) -> ValidationFail {
        self.vm_error_to_validation_fail(error.into_vm_error(), |error| {
            ValidationFail::InternalError(format!("invalid admitted {context} analysis: {error}"))
        })
    }
}

#[cfg(test)]
mod tests {
    include!("execution_attempt/json_scoped_tests.rs");
    #[test]
    fn kura_storage_attempt_keeps_original_refusal_and_deterministic_source_error() {
        let pool = iroha_allocation::AllocationBudget::new(8);
        let occupied = pool.try_reserve_bytes(8).unwrap();
        let original = pool.try_reserve_bytes(1).unwrap_err();
        let error = crate::kura::Error::NativeFrameAllocation(
            iroha_allocation::ChargedBufferError::Admission(original.clone()),
        );
        let ExecutionAttemptError::<()>::Deferred(retained) =
            super::kura_read_attempt_error(error, |_| {
                panic!("original pool refusal cannot be rejected")
            })
        else {
            panic!("original storage refusal");
        };
        assert_eq!(retained.allocation_refusal(), Some(&original));
        let error = crate::kura::Error::NativeFrameAllocation(
            iroha_allocation::ChargedBufferError::Allocator { requested_bytes: 8 },
        );
        let ExecutionAttemptError::<()>::Deferred(retained) =
            super::kura_read_attempt_error(error, |_| {
                panic!("physical allocation cannot be rejected")
            })
        else {
            panic!("original storage allocation refusal");
        };
        assert_eq!(retained.reason(), ExecutionDeferral::AllocationUnavailable);
        assert!(retained.allocation_refusal().is_none());
        assert!(matches!(
            super::kura_read_attempt_error(
                crate::kura::Error::CanonicalBlockWireMismatch { height: 3 },
                std::convert::identity,
            ),
            ExecutionAttemptError::Rejected(crate::kura::Error::CanonicalBlockWireMismatch {
                height: 3
            })
        ));
        drop(occupied);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn prepared_signature_attempt_keeps_original_pool_refusal_and_source_invariants() {
        use iroha_data_model::block::{BlockSignatureCustodyError, PreparedSignatureBlockError};
        use norito::core::PreparedDecodeError;
        let pool = iroha_allocation::AllocationBudget::new(8);
        let occupied = pool.try_reserve_bytes(8).unwrap();
        let original = pool.try_reserve_bytes(1).unwrap_err();
        let error = PreparedSignatureBlockError::Decode(PreparedDecodeError::Destination(
            BlockSignatureCustodyError::ControlAdmission(original.clone()),
        ));
        let ExecutionAttemptError::<String>::Deferred(retained) =
            prepared_signature_block_attempt_error(error, |_| {
                panic!("original allocation cannot become rejection")
            })
        else {
            panic!("original local custody refusal");
        };
        assert_eq!(retained.allocation_refusal(), Some(&original));
        assert!(matches!(
            prepared_signature_block_attempt_error(
                PreparedSignatureBlockError::SourceChanged,
                |reason| reason
            ),
            ExecutionAttemptError::Rejected(_)
        ));
        let error =
            PreparedSignatureBlockError::Storage(iroha_allocation::ChargedBufferError::Allocator {
                requested_bytes: 64,
            });
        assert!(
            matches!(prepared_signature_block_attempt_error(error, |_| panic!("physical allocator refusal")), ExecutionAttemptError::<()>::Deferred(reason) if reason.reason() == ExecutionDeferral::AllocationUnavailable)
        );
        drop(occupied);
    }

    #[test]
    fn prepared_certificate_attempt_preserves_original_pool_refusal_and_physical_causes() {
        use iroha_allocation::{
            AllocationBudget, ChargedBufferFromChargeError, SharedFromChargeError,
        };
        use iroha_data_model::block::{
            PreparedSignatureBlockError, commit_certificate::CertificateCustodyError,
        };
        let pool = AllocationBudget::new(8);
        let occupied = pool.try_reserve_bytes(8).unwrap();
        let original = pool.try_reserve_bytes(1).unwrap_err();
        let retained = prepared_signature_block_attempt_error(
            PreparedSignatureBlockError::Certificate(CertificateCustodyError::Admission(
                original.clone(),
            )),
            |_| panic!("original certificate refusal must defer"),
        );
        let ExecutionAttemptError::<String>::Deferred(retained) = retained else {
            panic!("original retained certificate capacity owner");
        };
        assert_eq!(retained.allocation_refusal(), Some(&original));
        assert_eq!(retained.reason(), ExecutionDeferral::ActiveMemoryCapacity);
        let layout = std::alloc::Layout::array::<u8>(31).unwrap();
        for cause in [
            CertificateCustodyError::Buffer(ChargedBufferFromChargeError::Allocator { layout }),
            CertificateCustodyError::Control(SharedFromChargeError::Allocator { layout }),
        ] {
            let retained = prepared_signature_block_attempt_error(
                PreparedSignatureBlockError::Certificate(cause),
                |_| panic!("original physical allocator refusal must defer"),
            );
            assert!(
                matches!(retained, ExecutionAttemptError::<String>::Deferred(ref original)
                if original.reason() == ExecutionDeferral::AllocationUnavailable && original.allocation_refusal().is_none())
            );
        }
        for invariant in [
            CertificateCustodyError::ForeignPool,
            CertificateCustodyError::SourceChanged,
            CertificateCustodyError::LayoutChanged,
            CertificateCustodyError::Incomplete,
        ] {
            let retained = prepared_signature_block_attempt_error(
                PreparedSignatureBlockError::Certificate(invariant),
                |reason| reason,
            );
            assert!(matches!(retained, ExecutionAttemptError::Rejected(_)));
        }
        drop(occupied);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn prepared_policy_attempt_keeps_real_pool_physical_and_enclosing_refusal_owners() {
        use iroha_allocation::{
            AllocationBudget, ChargedBufferFromChargeError, SharedFromChargeError,
        };
        use iroha_data_model::{
            block::PreparedSignatureBlockError, da::commitment::DaProofPolicyCustodyError,
        };
        let pool = AllocationBudget::new(8);
        let occupied = pool.try_reserve_bytes(8).unwrap();
        let original = pool.try_reserve_bytes(1).unwrap_err();
        let retained = prepared_signature_block_attempt_error(
            PreparedSignatureBlockError::Policy(DaProofPolicyCustodyError::Admission(
                original.clone(),
            )),
            |_| panic!("actual policy pool refusal must defer"),
        );
        let ExecutionAttemptError::<String>::Deferred(retained) = retained else {
            panic!("original policy capacity owner");
        };
        assert_eq!(retained.allocation_refusal(), Some(&original));
        assert_eq!(retained.reason(), ExecutionDeferral::ActiveMemoryCapacity);
        let layout = std::alloc::Layout::array::<u8>(31).unwrap();
        for cause in [
            DaProofPolicyCustodyError::Buffer(ChargedBufferFromChargeError::Allocator { layout }),
            DaProofPolicyCustodyError::Control(SharedFromChargeError::Allocator { layout }),
        ] {
            assert!(
                matches!(prepared_signature_block_attempt_error(PreparedSignatureBlockError::Policy(cause),|_|panic!("original physical policy refusal")),ExecutionAttemptError::<String>::Deferred(reason) if reason.reason()==ExecutionDeferral::AllocationUnavailable)
            );
        }
        let protocol = norito::core::DecodeLimits::new(4096, 4096, 4096, 4096, 64);
        let narrow = norito::core::DecodeLimits::new(4096, 4096, 4096, 1, 64);
        let mut bytes = Vec::new();
        norito::core::SerializePayload::serialize(
            &"original UTF-8".to_owned(),
            &mut norito::core::Encoder::for_buffer(&mut bytes),
        )
        .unwrap();
        let cause = norito::core::with_decode_limits_scope(narrow, || {
            norito::core::classify_decode_attempt(|| {
                norito::core::with_decode_limits_scope(protocol, || {
                    norito::core::borrow_canonical_string(&bytes).map(|_| ())
                })
            })
        })
        .unwrap_err();
        assert_eq!(
            cause.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        assert!(
            matches!(prepared_signature_block_attempt_error(PreparedSignatureBlockError::Policy(DaProofPolicyCustodyError::Decode(cause)),|_|panic!("original caller refusal cannot become invalid policy")),ExecutionAttemptError::<String>::Deferred(reason) if reason.reason()==ExecutionDeferral::ActiveMemoryCapacity)
        );
        drop(occupied);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn prepared_commitment_attempt_preserves_original_generated_capacity_and_enclosing_cause_through_retry()
     {
        use iroha_allocation::{AllocationBudget, ChargedBuffer};
        use iroha_crypto::{Hash, Signature};
        use iroha_data_model::{
            block::PreparedSignatureBlockError,
            da::commitment::{
                DaCommitmentBundle, DaCommitmentCustodyError, DaCommitmentRecord, DaProofScheme,
                PreparedDaCommitmentBundle, RetentionClass,
            },
            da::types::{BlobDigest, StorageTicketId},
            sorafs::pin_registry::ManifestDigest,
        };
        use iroha_model_base::topology::LaneId;
        use norito::core::{
            DecodeAttemptErrorKind, DecodeFlagsGuard, DecodeLimits, SequenceSpan,
            with_decode_limits_scope,
        };
        let _flags = DecodeFlagsGuard::enter(0);
        let value = DaCommitmentBundle::default();
        let mut bytes = Vec::new();
        norito::core::SerializePayload::serialize(
            &value,
            &mut norito::core::Encoder::for_buffer(&mut bytes),
        )
        .unwrap();
        let pool = AllocationBudget::new(bytes.len());
        let mut source = ChargedBuffer::new(bytes.len(), &pool).unwrap();
        source.append(&bytes).unwrap();
        let pointer = source.as_slice().as_ptr();
        let hash = iroha_crypto::Hash::new(source.as_slice());
        let mut pending = PreparedDaCommitmentBundle::from_source(
            &source,
            SequenceSpan {
                start: 0,
                end: bytes.len(),
            },
            &pool,
        )
        .unwrap();
        let original = pending.prepare(&source).unwrap_err();
        let DaCommitmentCustodyError::Admission(original) = original else {
            panic!("actual original immutable control capacity must refuse");
        };
        let retained = prepared_signature_block_attempt_error(
            PreparedSignatureBlockError::Commitments(DaCommitmentCustodyError::Admission(
                original.clone(),
            )),
            |_| panic!("actual commitment pool refusal must defer"),
        );
        let ExecutionAttemptError::<String>::Deferred(retained) = retained else {
            panic!("actual original refusal owner");
        };
        assert_eq!(retained.allocation_refusal(), Some(&original));
        assert_eq!(retained.reason(), ExecutionDeferral::ActiveMemoryCapacity);
        pool.set_limit_bytes(
            bytes.len()
                + DaCommitmentBundle::allocation_layout().size()
                + pending.payload_layouts().unwrap()[1].size(),
        );
        pending.prepare(&source).unwrap();
        let admitted = pending
            .finish(&source)
            .unwrap_or_else(|_| panic!("same original source retry"));
        assert!(admitted.admitted_to(&pool));
        assert_eq!(admitted, value);
        drop(admitted);
        assert_eq!(pool.reserved_bytes(), bytes.len());
        // A stack scalar and borrowed empty framing consume no owning-body charge.
        // Exercise the enclosing ceiling with a real canonical commitment element;
        // the sole sequence walker charges its actual serialized body length.
        let record = DaCommitmentRecord {
            lane_id: LaneId::new(7),
            epoch: 42,
            sequence: 3,
            client_blob_id: BlobDigest::new([0x11; 32]),
            manifest_hash: ManifestDigest::new([0x22; 32]),
            proof_scheme: DaProofScheme::MerkleSha256,
            chunk_root: Hash::prehashed([0x33; 32]),
            proof_digest: Some(Hash::prehashed([0x55; 32])),
            retention_class: RetentionClass::default(),
            storage_ticket: StorageTicketId::new([0x66; 32]),
            acknowledgement_sig: Signature::try_from_bytes(&[0x77; 64])
                .expect("checked canonical commitment acknowledgement fixture"),
        };
        let mut record_bytes = Vec::new();
        norito::core::SerializePayload::serialize(
            &record,
            &mut norito::core::Encoder::for_buffer(&mut record_bytes),
        )
        .unwrap();
        let record_body_charge = u64::try_from(record_bytes.len()).unwrap();
        assert!(record_body_charge > 1);
        let owning_value = DaCommitmentBundle::new(vec![record]);
        let mut owning_bytes = Vec::new();
        norito::core::SerializePayload::serialize(
            &owning_value,
            &mut norito::core::Encoder::for_buffer(&mut owning_bytes),
        )
        .unwrap();
        let owning_pool = AllocationBudget::new(owning_bytes.len());
        let mut owning_source = ChargedBuffer::new(owning_bytes.len(), &owning_pool).unwrap();
        owning_source.append(&owning_bytes).unwrap();
        let owning_pointer = owning_source.as_slice().as_ptr();
        let owning_hash = Hash::new(owning_source.as_slice());
        let caller = DecodeLimits::new(4096, 4096, 4096, 1, 64);
        let protocol = DecodeLimits::new(4096, 4096, 4096, 4096, 64);
        let cause = with_decode_limits_scope(caller, || {
            norito::core::classify_decode_attempt(|| {
                with_decode_limits_scope(
                    protocol,
                    || match PreparedDaCommitmentBundle::from_source(
                        &owning_source,
                        SequenceSpan {
                            start: 0,
                            end: owning_bytes.len(),
                        },
                        &owning_pool,
                    ) {
                        Err(DaCommitmentCustodyError::Decode(original)) => {
                            Err::<(), _>(original.into_error())
                        }
                        other => panic!(
                            "same generated original field must preserve enclosing refusal: {}",
                            other.is_err()
                        ),
                    },
                )
            })
        })
        .unwrap_err();
        assert_eq!(cause.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        assert_eq!(
            std::error::Error::source(&cause)
                .expect("retained original error source")
                .downcast_ref::<norito::Error>()
                .expect("actual sole Norito error")
                .decode_resource_error(),
            Some(norito::core::DecodeResourceError::TotalAllocationExceeded {
                attempted: record_body_charge,
                limit: 1,
            })
        );
        assert!(
            matches!(prepared_signature_block_attempt_error(PreparedSignatureBlockError::Commitments(DaCommitmentCustodyError::Decode(cause)),|_|panic!("original caller refusal cannot invalidate commitment bytes")),ExecutionAttemptError::<String>::Deferred(reason) if reason.reason()==ExecutionDeferral::ActiveMemoryCapacity)
        );
        assert_eq!(owning_source.as_slice().as_ptr(), owning_pointer);
        assert_eq!(Hash::new(owning_source.as_slice()), owning_hash);
        assert_eq!(owning_pool.reserved_bytes(), owning_bytes.len());
        let owning_retry = with_decode_limits_scope(protocol, || {
            PreparedDaCommitmentBundle::from_source(
                &owning_source,
                SequenceSpan {
                    start: 0,
                    end: owning_bytes.len(),
                },
                &owning_pool,
            )
        })
        .expect("same canonical owning-body source retries after caller scope retirement");
        assert!(owning_retry.belongs_to(&owning_pool));
        assert_eq!(owning_source.as_slice().as_ptr(), owning_pointer);
        assert_eq!(Hash::new(owning_source.as_slice()), owning_hash);
        assert_eq!(owning_pool.reserved_bytes(), owning_bytes.len());
        drop(owning_retry);
        drop(owning_source);
        assert_eq!(owning_pool.reserved_bytes(), 0);
        assert_eq!(source.as_slice().as_ptr(), pointer);
        assert_eq!(iroha_crypto::Hash::new(source.as_slice()), hash);
        drop(source);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn prepared_certificate_attempt_keeps_original_enclosing_decode_cause_after_scope_retirement() {
        use iroha_data_model::block::{
            PreparedSignatureBlockError, commit_certificate::CertificateCustodyError,
        };
        use norito::core::{
            DecodeAttemptErrorKind, DecodeFromSlice, DecodeLimits, Encoder, SerializePayload,
            classify_decode_attempt, decode_field_canonical, with_decode_limits_scope,
        };
        let mut bytes = Vec::new();
        vec![23_u8; 23]
            .serialize(&mut Encoder::for_buffer(&mut bytes))
            .unwrap();
        let protocol = DecodeLimits::new(4096, 4096, 4096, 4096, 64);
        let narrow = DecodeLimits::new(4096, 4096, 4096, 1, 64);
        let original = with_decode_limits_scope(narrow, || {
            classify_decode_attempt(|| {
                with_decode_limits_scope(protocol, || {
                    decode_field_canonical::<Vec<u8>>(&bytes).map(|_| ())
                })
            })
        })
        .unwrap_err();
        assert_eq!(original.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        let retained = prepared_signature_block_attempt_error(
            PreparedSignatureBlockError::Certificate(CertificateCustodyError::Decode(original)),
            |_| panic!("original caller refusal cannot become rejection"),
        );
        assert!(
            matches!(retained, ExecutionAttemptError::<String>::Deferred(ref original)
            if original.reason() == ExecutionDeferral::ActiveMemoryCapacity && original.allocation_refusal().is_none())
        );
        let invalid =
            classify_decode_attempt(|| bool::decode_from_slice(&[2]).map(|_| ())).unwrap_err();
        assert_eq!(invalid.kind(), DecodeAttemptErrorKind::Invalid);
        let original_message = invalid.to_string();
        let rejected = prepared_signature_block_attempt_error(
            PreparedSignatureBlockError::Certificate(CertificateCustodyError::Decode(invalid)),
            |reason| reason,
        );
        assert_eq!(rejected, ExecutionAttemptError::Rejected(original_message));
    }

    use super::{
        ExecutionAttemptError, ExecutionDeferral, ExecutionDeferred,
        prepared_signature_block_attempt_error,
    };

    #[test]
    fn norito_global_archive_cap_is_terminal_inside_an_outer_decode_scope() {
        let mut bytes = norito::to_bytes(&vec![7_u64]).unwrap();
        let limit = norito::core::max_archive_len();
        let length_offset = 4 + 1 + 1 + 16 + 1;
        bytes[length_offset..length_offset + 8].copy_from_slice(&(limit + 1).to_le_bytes());
        norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 32),
            || {
                let error = norito::decode_from_bytes::<Vec<u64>>(&bytes).unwrap_err();
                assert!(
                    matches!(&error, norito::Error::ArchiveLengthExceeded { length, limit: actual } if *length == limit + 1 && *actual == limit)
                );
                assert!(
                    matches!(
                        super::norito_decode_attempt_error(error, std::convert::identity),
                        ExecutionAttemptError::Rejected(
                            norito::Error::ArchiveLengthExceeded { .. }
                        )
                    ),
                    "global archive format cap was mistaken for an inherited local refusal"
                );
            },
        );
    }

    #[test]
    fn norito_inner_format_limits_are_terminal_under_a_wider_outer_scope() {
        let sequence = norito::to_bytes(&vec![7_u64, 11, 13]).unwrap();
        let text = norito::to_bytes(&String::from("bounded field")).unwrap();
        for dimension in 0..4 {
            let mut limits = [usize::MAX; 4];
            limits[dimension] = 0;
            norito::with_decode_limits_scope(
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 32),
                || {
                    let inner =
                        norito::DecodeLimits::new(limits[0], limits[1], limits[2], limits[3], 32);
                    let error = if dimension == 1 {
                        norito::decode_from_bytes_with_limits::<String>(&text, inner).unwrap_err()
                    } else {
                        norito::decode_from_bytes_with_limits::<Vec<u64>>(&sequence, inner)
                            .unwrap_err()
                    };
                    assert!(matches!(
                        (dimension, &error),
                        (0, norito::Error::SequenceLengthExceeded { limit: 0, .. })
                            | (1, norito::Error::FieldLengthExceeded { limit: 0, .. })
                            | (2, norito::Error::TotalElementsExceeded { limit: 0, .. })
                            | (3, norito::Error::TotalAllocationExceeded { limit: 0, .. })
                    ));
                    let original = error.decode_resource_error();
                    let ExecutionAttemptError::Rejected(error) =
                        super::norito_decode_attempt_error(error, std::convert::identity)
                    else {
                        panic!(
                            "inner format dimension {dimension} was mistaken for an outer local refusal"
                        );
                    };
                    assert_eq!(error.decode_resource_error(), original);
                    assert_eq!(
                        norito::decode_from_bytes::<Vec<u64>>(&sequence).unwrap(),
                        vec![7_u64, 11, 13]
                    );
                    assert_eq!(
                        norito::decode_from_bytes::<String>(&text).unwrap(),
                        "bounded field"
                    );
                },
            );
        }
    }

    #[test]
    fn norito_outer_allocation_and_element_refusals_retry_original_bytes() {
        let expected = vec![7_u64, 11, 13];
        let bytes = norito::to_bytes(&expected).unwrap();
        for allocation in [false, true] {
            let limits = norito::DecodeLimits::new(
                usize::MAX,
                usize::MAX,
                if allocation { usize::MAX } else { 0 },
                if allocation { 0 } else { usize::MAX },
                usize::MAX,
            );
            let refused = norito::with_decode_limits_scope(limits, || {
                let error = norito::decode_from_bytes::<Vec<u64>>(&bytes).unwrap_err();
                if allocation {
                    assert!(matches!(
                        error,
                        norito::Error::TotalAllocationExceeded { limit: 0, .. }
                    ));
                } else {
                    assert!(matches!(
                        error,
                        norito::Error::TotalElementsExceeded { limit: 0, .. }
                    ));
                }
                super::norito_decode_attempt_error::<()>(error, |_| {
                    panic!("a local decode refusal cannot enter the deterministic mapper")
                })
            });
            let ExecutionAttemptError::Deferred(reason) = refused else {
                panic!("the original local scope must remain retryable")
            };
            assert_eq!(reason.reason(), ExecutionDeferral::ActiveMemoryCapacity);
            assert!(reason.allocation_refusal().is_none());
            let retried = norito::decode_from_bytes::<Vec<u64>>(&bytes).unwrap();
            assert_eq!(retried, expected);
            norito::verify_exact_frame(&retried, &bytes).unwrap();
        }
    }

    #[test]
    fn norito_intrinsic_limits_and_malformed_or_deep_values_remain_rejections() {
        let intrinsic = [
            norito::Error::ArchiveLengthExceeded {
                length: 2,
                limit: 1,
            },
            norito::Error::SequenceLengthExceeded {
                length: 2,
                limit: 1,
            },
            norito::Error::FieldLengthExceeded {
                length: 2,
                limit: 1,
            },
            norito::Error::TotalElementsExceeded {
                attempted: 2,
                limit: 1,
            },
            norito::Error::TotalAllocationExceeded {
                attempted: 2,
                limit: 1,
            },
        ];
        assert!(!norito::core::decode_limits_active());
        for error in intrinsic {
            let expected = error.decode_resource_error();
            let ExecutionAttemptError::Rejected(error) =
                super::norito_decode_attempt_error(error, std::convert::identity)
            else {
                panic!("an intrinsic format bound cannot imply an inherited local refusal")
            };
            assert_eq!(error.decode_resource_error(), expected);
        }
        let bytes = norito::to_bytes(&vec![vec![7_u64]]).unwrap();
        norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 64),
            || {
                let error = norito::with_decode_limits_scope(
                    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 0),
                    || norito::decode_from_bytes::<Vec<Vec<u64>>>(&bytes),
                )
                .unwrap_err();
                assert!(matches!(error, norito::Error::NestingDepthExceeded { .. }));
                assert!(matches!(
                    super::norito_decode_attempt_error(error, std::convert::identity),
                    ExecutionAttemptError::Rejected(norito::Error::NestingDepthExceeded { .. })
                ));
                let malformed = norito::decode_from_bytes::<Vec<u64>>(&[]).unwrap_err();
                assert!(malformed.decode_resource_error().is_none());
                assert!(matches!(
                    super::norito_decode_attempt_error(malformed, std::convert::identity),
                    ExecutionAttemptError::Rejected(_)
                ));
            },
        );
    }

    #[test]
    fn original_surviving_narrow_decode_depth_refusal_retries_identical_bytes() {
        let expected = vec![vec![7_u64]];
        let bytes = norito::to_bytes(&expected).unwrap();
        norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 0),
            || {
                let error = norito::decode_from_bytes::<Vec<Vec<u64>>>(&bytes).unwrap_err();
                assert!(matches!(
                    error,
                    norito::Error::NestingDepthExceeded {
                        depth: 1,
                        limit: 0,
                        context: "decode budget"
                    }
                ));
                let refused = super::norito_decode_attempt_error::<()>(error, |_| {
                    panic!("a surviving narrower caller depth cannot reject original valid bytes")
                });
                let ExecutionAttemptError::Deferred(reason) = refused else {
                    panic!("original local depth must remain retryable")
                };
                assert_eq!(reason.reason(), ExecutionDeferral::ActiveMemoryCapacity);
                assert!(reason.allocation_refusal().is_none());
            },
        );
        let retried = norito::decode_from_bytes::<Vec<Vec<u64>>>(&bytes).unwrap();
        assert_eq!(retried, expected);
        norito::verify_exact_frame(&retried, &bytes).unwrap();
    }

    #[test]
    fn original_inner_decode_depth_limit_is_terminal_after_scope_unwinds() {
        let expected = vec![vec![7_u64]];
        let bytes = norito::to_bytes(&expected).unwrap();
        norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 64),
            || {
                let error = norito::with_decode_limits_scope(
                    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 0),
                    || norito::decode_from_bytes::<Vec<Vec<u64>>>(&bytes),
                )
                .unwrap_err();
                let resource = error.decode_resource_error().unwrap();
                assert!(matches!(
                    resource,
                    norito::core::DecodeResourceError::NestingDepthExceeded {
                        depth: 1,
                        limit: 0,
                        context: "decode budget"
                    }
                ));
                let ExecutionAttemptError::Rejected(error) =
                    super::norito_decode_attempt_error(error, std::convert::identity)
                else {
                    panic!("a wider surviving scope cannot borrow a retired inner depth")
                };
                assert_eq!(error.decode_resource_error(), Some(resource));
            },
        );
        let retried = norito::decode_from_bytes::<Vec<Vec<u64>>>(&bytes).unwrap();
        assert_eq!(retried, expected);
        norito::verify_exact_frame(&retried, &bytes).unwrap();
    }

    #[test]
    fn norito_physical_refusal_is_local_without_fabricating_a_pool_waiter() {
        assert!(!norito::core::decode_limits_active());
        let refusal = super::norito_decode_attempt_error::<()>(
            norito::Error::AllocationFailed { bytes: 128 },
            |_| panic!("an allocator refusal must not produce a wire rejection"),
        );
        let ExecutionAttemptError::Deferred(reason) = refusal else {
            panic!("physical allocator refusal is local even without an inherited scope")
        };
        assert_eq!(reason.reason(), ExecutionDeferral::AllocationUnavailable);
        assert!(reason.allocation_refusal().is_none());
    }

    #[test]
    fn original_capacity_refusal_survives_owner_clone_and_budget_handle_drop() {
        use std::{
            future::Future,
            pin::Pin,
            sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
            },
            task::{Context, Poll, Wake, Waker},
        };
        #[derive(Default)]
        struct Wakes(AtomicUsize);
        impl Wake for Wakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let budget = iroha_allocation::AllocationBudget::new(
            8 + iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
        );
        let mut registration = crate::unit_test_support::release_registration(&budget);
        let occupied = budget.try_reserve_bytes(8).expect("initial reservation");
        let refusal = budget.try_reserve_bytes(1).expect_err("pool is occupied");
        let owner = ExecutionDeferred::from(refusal.clone());
        assert_eq!(owner.reason(), ExecutionDeferral::ActiveMemoryCapacity);
        assert_eq!(owner.allocation_refusal(), Some(&refusal));
        assert_eq!(owner.phase(), None);
        let finalizer = owner.clone().at_native_lane_finalizer();
        assert_eq!(
            finalizer.phase(),
            Some(super::ExecutionPhase::NativeLaneFinalizer)
        );
        assert_eq!(finalizer.reason(), owner.reason());
        assert_eq!(finalizer.allocation_refusal(), Some(&refusal));
        assert_eq!(
            ExecutionDeferred::from_vm_error(&finalizer.clone().into_vm_error()),
            Some(owner.clone()),
            "Core phase is not a VM category; the original refusal still crosses intact"
        );
        let cloned = finalizer.clone();
        drop(finalizer);
        drop(owner);
        drop(budget);
        let Some(iroha_allocation::AllocationRefusal::Capacity { release, .. }) =
            cloned.allocation_refusal()
        else {
            panic!("original capacity release evidence must survive");
        };
        let mut release = release.clone().wait_for_release(&mut registration);
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut context = Context::from_waker(&waker);
        assert_eq!(Pin::new(&mut release).poll(&mut context), Poll::Pending);
        drop(occupied);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        assert_eq!(Pin::new(&mut release).poll(&mut context), Poll::Ready(()));
    }

    #[test]
    fn non_capacity_deferral_never_fabricates_a_release_source() {
        let allocator = ExecutionDeferred::from(ExecutionDeferral::AllocationUnavailable);
        assert_eq!(allocator.reason(), ExecutionDeferral::AllocationUnavailable);
        assert!(allocator.allocation_refusal().is_none());
        assert_eq!(allocator.phase(), None);
        let finalizer = allocator.clone().at_native_lane_finalizer();
        assert_eq!(
            finalizer.phase(),
            Some(super::ExecutionPhase::NativeLaneFinalizer)
        );
        assert_eq!(finalizer.reason(), allocator.reason());
        assert!(finalizer.allocation_refusal().is_none());
        let overflow = ExecutionDeferred::from(iroha_allocation::AllocationRefusal::DemandOverflow);
        assert_eq!(overflow.phase(), None);
        assert!(matches!(
            overflow.allocation_refusal(),
            Some(iroha_allocation::AllocationRefusal::DemandOverflow)
        ));
        let budget = iroha_allocation::AllocationBudget::new(0);
        let impossible = ExecutionDeferred::from(budget.try_reserve_bytes(1).unwrap_err());
        assert_eq!(impossible.phase(), None);
        assert!(matches!(
            impossible.allocation_refusal(),
            Some(iroha_allocation::AllocationRefusal::ExceedsLimit { .. })
        ));
        assert_eq!(
            ExecutionDeferred::from_vm_error(&allocator.clone().into_vm_error()),
            Some(allocator)
        );
        assert_eq!(
            ExecutionDeferred::from_vm_error(&impossible.clone().into_vm_error()),
            Some(impossible)
        );
        assert_eq!(
            ExecutionDeferred::from_vm_error(&ivm::VMError::OutOfMemory),
            None
        );
    }

    #[test]
    fn transaction_bridge_is_sticky_and_does_not_account_gas() {
        use crate::{
            kura::Kura,
            query::store::LiveQueryStore,
            state::{State, World},
        };
        let state = State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut block = state.block(iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let mut transaction = block.transaction();
        assert_eq!(transaction.execution_deferral(), None);
        let refusal = ivm::VMError::ExecutionDeferred(ExecutionDeferral::ActiveMemoryCapacity);
        transaction.vm_error_to_validation_fail(refusal, |_| {
            panic!("local refusal cannot enter deterministic mapper")
        });
        transaction.defer_execution(ExecutionDeferral::AllocationUnavailable);
        assert_eq!(
            transaction.execution_deferral(),
            Some(ExecutionDeferral::ActiveMemoryCapacity.into())
        );
        assert_eq!(transaction.last_tx_gas_used, 0);
        let failure = transaction.vm_error_to_validation_fail(ivm::VMError::OutOfMemory, |error| {
            iroha_data_model::ValidationFail::NotPermitted(error.to_string())
        });
        assert!(matches!(
            failure,
            iroha_data_model::ValidationFail::NotPermitted(_)
        ));
        assert_eq!(
            transaction.execution_deferral(),
            Some(ExecutionDeferral::ActiveMemoryCapacity.into())
        );
    }

    #[test]
    fn trace_owner_deferral_abandons_writes_without_metering_or_rejection() {
        use crate::{
            kura::Kura,
            query::store::LiveQueryStore,
            state::{State, World},
        };
        use iroha_data_model::{
            Registrable,
            prelude::{Account, Domain},
        };
        use mv::storage::StorageReadOnly as _;

        let reason = ExecutionDeferral::TraceOwnerUnavailable;
        let original = ivm::VMError::ExecutionDeferred(reason);
        let wrapped = ivm::VMError::Metered {
            gas: 91,
            source: Box::new(original.clone()),
        };
        let attempt = super::vm_attempt_error(wrapped.clone(), |_| {
            panic!("trace custody refusal must not enter the rejection mapper")
        });
        let ExecutionAttemptError::Deferred(retained) = attempt else {
            panic!("trace custody refusal cannot complete an execution attempt");
        };
        assert_eq!(retained.reason(), reason);
        assert!(retained.allocation_refusal().is_none());
        assert_eq!(retained.clone().into_vm_error(), original);
        assert_eq!(wrapped.metered_gas(), None);

        let owner = iroha_test_samples::ALICE_ID.clone();
        let state = State::new_for_testing(
            World::with([], [Account::new(owner.clone()).build(&owner)], []),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut block = state.block(iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let domain =
            iroha_model_base::domain::DomainId::try_new("trace_retry", "universal").unwrap();
        let mut transaction = block.transaction();
        transaction
            .world
            .domains
            .insert(domain.clone(), Domain::new(domain.clone()).build(&owner));
        transaction.vm_error_to_validation_fail(wrapped, |_| {
            panic!("trace custody refusal must not become a wire rejection")
        });
        transaction.defer_execution(ExecutionDeferral::AllocationUnavailable);
        assert_eq!(transaction.execution_deferral(), Some(retained));
        assert_eq!(transaction.last_tx_gas_used, 0);
        transaction.apply();
        assert!(block.world.domains.get(&domain).is_none());
    }

    #[test]
    fn analysis_refusal_bridge_keeps_original_owner_and_never_accounts_gas() {
        use crate::{
            kura::Kura,
            query::store::LiveQueryStore,
            state::{State, World},
        };
        use ivm::analysis::ProgramAnalysisError;

        let state = State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut block = state.block(iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let budget = iroha_allocation::AllocationBudget::new(1);
        let occupied = budget.try_reserve_bytes(1).unwrap();
        let refusal = budget.try_reserve_bytes(1).unwrap_err();
        for original in [
            ivm::VMError::AllocationDeferred(refusal),
            ivm::VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable),
        ] {
            let expected = ExecutionDeferred::from_vm_error(&original);
            for (context, metadata) in [("generic-program", false), ("generic-trigger", true)] {
                let mut transaction = block.transaction();
                let error = if metadata {
                    ProgramAnalysisError::Metadata(original.clone())
                } else {
                    ProgramAnalysisError::Decode(original.clone())
                };
                transaction.program_analysis_error_to_validation_fail(error, context);
                transaction.defer_execution(ExecutionDeferral::ActiveMemoryCapacity);
                assert_eq!(transaction.execution_deferral(), expected);
                assert_eq!(transaction.last_tx_gas_used, 0);
            }
        }
        let mut transaction = block.transaction();
        let malformed = transaction.program_analysis_error_to_validation_fail(
            ProgramAnalysisError::Decode(ivm::VMError::DecodeError),
            "generic-program",
        );
        assert!(matches!(
            malformed,
            iroha_data_model::ValidationFail::InternalError(_)
        ));
        assert_eq!(transaction.execution_deferral(), None);
        assert_eq!(transaction.last_tx_gas_used, 0);
        drop(occupied);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn sticky_deferral_alone_prevents_regular_transaction_publication() {
        use crate::{
            kura::Kura,
            query::store::LiveQueryStore,
            state::{State, World},
        };
        use iroha_data_model::{
            Registrable,
            prelude::{Account, Domain},
        };
        use iroha_model_base::domain::DomainId;
        use mv::storage::StorageReadOnly as _;
        let owner = iroha_test_samples::ALICE_ID.clone();
        let state = State::new_for_testing(
            World::with([], [Account::new(owner.clone()).build(&owner)], []),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut block = state.block(iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let domain_id = DomainId::try_new("deferred", "universal").unwrap();
        let mut transaction = block.transaction();
        transaction.world.domains.insert(
            domain_id.clone(),
            Domain::new(domain_id.clone()).build(&owner),
        );
        transaction.defer_execution(ExecutionDeferral::AllocationUnavailable);
        transaction.apply();
        assert!(
            block.world.domains.get(&domain_id).is_none(),
            "a bare local deferral must abandon staged semantic writes"
        );
    }

    #[test]
    fn world_and_state_share_the_first_original_capacity_owner() {
        let state = crate::state::State::new_for_testing(
            crate::state::World::default(),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let mut block = state.block(iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let mut stx = block.transaction();
        let budget = iroha_allocation::AllocationBudget::new(8);
        let occupied = budget.try_reserve_bytes(8).unwrap();
        let original = budget.try_reserve_bytes(1).unwrap_err();
        let refusal = ExecutionAttemptError::<
            iroha_data_model::isi::error::InstructionExecutionError,
        >::Deferred(original.clone().into());
        stx.world.attempt_error_to_instruction_error(refusal);
        stx.defer_execution(ExecutionDeferral::AllocationUnavailable);
        let retained = stx.execution_deferral().unwrap();
        assert_eq!(retained.reason(), ExecutionDeferral::ActiveMemoryCapacity);
        assert_eq!(retained.allocation_refusal(), Some(&original));
        assert_eq!(*stx.world.execution_deferral.borrow(), Some(retained));
        drop(occupied);
        assert!(budget.try_reserve_bytes(1).is_ok());
    }

    #[test]
    fn poisoned_raw_world_apply_rolls_back_original_fields() {
        use iroha_data_model::{Registrable, prelude::Domain};
        use mv::storage::StorageReadOnly as _;
        let state = crate::state::State::new_for_testing(
            crate::state::World::default(),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let mut block = state.block(iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let domain =
            iroha_model_base::domain::DomainId::try_new("world_retry", "universal").unwrap();
        let mut world = block.world.transaction_without_telemetry(
            iroha_config::parameters::actual::LaneConfig::default(),
            0,
        );
        world.domains.insert(
            domain.clone(),
            Domain::new(domain.clone()).build(&iroha_test_samples::ALICE_ID),
        );
        world.defer_execution(ExecutionDeferral::ActiveMemoryCapacity);
        world.apply();
        assert!(block.world.domains.get(&domain).is_none());
    }

    #[test]
    fn mapping_rejections_cannot_erase_a_local_deferral() {
        let refusal =
            ExecutionAttemptError::<u8>::Deferred(ExecutionDeferral::ActiveMemoryCapacity.into());
        let mapped = refusal.map_rejection(|_| panic!("local refusal is not a rejection"));
        assert_eq!(
            mapped,
            ExecutionAttemptError::<()>::Deferred(ExecutionDeferral::ActiveMemoryCapacity.into())
        );
        assert_eq!(
            ExecutionAttemptError::Rejected(2).map_rejection(|n| n + 3),
            ExecutionAttemptError::Rejected(5)
        );
    }
    #[test]
    fn vm_projection_preserves_original_refusal_and_does_not_invoke_rejection_mapper() {
        let budget = iroha_allocation::AllocationBudget::new(8);
        let occupied = budget.try_reserve_bytes(8).unwrap();
        let refusal = budget.try_reserve_bytes(1).unwrap_err();
        let error = ExecutionAttemptError::<u8>::Deferred(refusal.clone().into())
            .into_vm_error(|_| panic!("local refusal cannot enter deterministic mapper"));
        assert_eq!(
            ExecutionDeferred::from_vm_error(&error),
            Some(refusal.into())
        );
        drop(occupied);
        assert_eq!(
            ExecutionAttemptError::Rejected(3_u8).into_vm_error(|value| {
                assert_eq!(value, 3);
                ivm::VMError::PermissionDenied
            }),
            ivm::VMError::PermissionDenied,
        );
    }
}

#[cfg(test)]
mod canonical_refusal_owner_tests {
    use super::*;
    use norito::core::{
        DecodeAttemptErrorKind, DecodeLimits, DecodeLocalRefusalKind, classify_decode_attempt,
        with_decode_limits_scope,
    };

    fn limits(bytes: usize) -> DecodeLimits {
        DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
    }

    #[test]
    fn canonical_refusal_keeps_original_owner_through_vm_and_equal_foreign_scope() {
        let bytes = norito::encode_canonical(&vec![19_u8; 32]).unwrap();
        let cause = with_decode_limits_scope(limits(0), || {
            norito::decode_canonical_for_admission::<Vec<u8>>(
                &bytes,
                norito::canonical_decode_limits(bytes.len()),
            )
        })
        .unwrap_err();
        let original = cause.local_refusal().unwrap();
        let borrowed = canonical_decode_deferral(&cause).unwrap();
        assert_eq!(borrowed.decode_refusal(), Some(&original));
        let ExecutionAttemptError::<()>::Deferred(retained) =
            canonical_decode_attempt_error(cause, |_| panic!("local refusal became rejection"))
        else {
            panic!("canonical admission must defer");
        };
        assert_eq!(retained, borrowed);
        assert_eq!(retained.reason(), ExecutionDeferral::ActiveMemoryCapacity);
        assert!(retained.allocation_refusal().is_none());
        assert_eq!(retained.decode_refusal(), Some(&original));
        assert_eq!(original.kind(), DecodeLocalRefusalKind::EnclosingLimit);
        assert!(
            std::error::Error::source(&retained)
                .unwrap()
                .downcast_ref::<norito::core::DecodeLocalRefusal>()
                .is_some()
        );
        with_decode_limits_scope(limits(0), || {
            let vm = VMError::metered(41, retained.into_vm_error());
            assert_eq!(vm.fault_kind(), None);
            let restored = ExecutionDeferred::from_vm_error(&vm).unwrap();
            assert_eq!(restored, borrowed);
            assert_eq!(restored.decode_refusal(), Some(&original));
            assert_eq!(vm.split_metered().0, None);
        });
        assert_eq!(
            norito::decode_canonical_for_admission::<Vec<u8>>(
                &bytes,
                norito::canonical_decode_limits(bytes.len())
            )
            .unwrap(),
            vec![19_u8; 32]
        );
    }

    #[test]
    fn canonical_rejections_keep_protocol_and_reconstructed_errors_terminal() {
        let bytes = norito::encode_canonical(&vec![19_u8; 32]).unwrap();
        let protocol = with_decode_limits_scope(limits(0), || {
            norito::decode_canonical_for_admission::<Vec<u8>>(&bytes, limits(0))
        })
        .unwrap_err();
        let reconstructed = classify_decode_attempt(|| {
            Err::<(), _>(norito::Error::TotalAllocationExceeded {
                attempted: 32,
                limit: 0,
            })
        })
        .unwrap_err();
        let malformed =
            classify_decode_attempt(|| Err::<(), _>(norito::Error::LengthMismatch)).unwrap_err();
        for original in [protocol, reconstructed, malformed] {
            assert_eq!(original.kind(), DecodeAttemptErrorKind::Invalid);
            assert!(canonical_decode_deferral(&original).is_none());
            let text = original.to_string();
            let ExecutionAttemptError::Rejected(returned) =
                canonical_decode_attempt_error(original, std::convert::identity)
            else {
                panic!("terminal input failure became deferral");
            };
            assert_eq!(returned.kind(), DecodeAttemptErrorKind::Invalid);
            assert_eq!(returned.to_string(), text);
        }
    }

    #[test]
    fn captured_allocator_fields_survive_core_owner_and_finalizer_context() {
        // The codec classifier trusts its decoder closure's allocation result;
        // this synthetic payload tests transport, not physical allocator authenticity.
        let cause =
            classify_decode_attempt(|| Err::<(), _>(norito::Error::AllocationFailed { bytes: 73 }))
                .unwrap_err();
        let ExecutionAttemptError::<()>::Deferred(retained) =
            canonical_decode_attempt_error(cause, |_| {
                panic!("captured allocator became rejection")
            })
        else {
            panic!("expected retained allocator outcome")
        };
        let retained = retained.at_native_lane_finalizer();
        assert_eq!(retained.phase(), Some(ExecutionPhase::NativeLaneFinalizer));
        assert_eq!(retained.reason(), ExecutionDeferral::AllocationUnavailable);
        assert_eq!(
            retained.decode_refusal().unwrap().allocation_bytes(),
            Some(73)
        );
        assert!(retained.allocation_refusal().is_none());
        let rendered = retained.to_string();
        assert!(rendered.starts_with("native lane finalizer: "));
        let vm = retained.into_vm_error();
        let restored = ExecutionDeferred::from_vm_error(&vm).unwrap();
        assert_eq!(restored.phase(), None);
        assert_eq!(
            restored.decode_refusal().unwrap().allocation_bytes(),
            Some(73)
        );
    }
}
