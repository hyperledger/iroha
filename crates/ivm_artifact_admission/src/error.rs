//! Typed admission failures and local native-preparation deferrals.

use std::{error::Error, fmt};

use ivm_abi::{
    VMError,
    error::{AllocationRefusal, ExecutionDeferral},
};

/// Failure returned by shared artifact admission or native preparation.
///
/// Local resource refusal remains a retryable VM deferral. It never changes
/// whether an immutable artifact satisfies the shared admission policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractArtifactError {
    kind: ArtifactFailure,
}

// Retain only the admission surface's concrete outcomes. Carrying a full VMError
// beside its diagnostic would also reserve space for unrelated guest abort data.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ArtifactFailure {
    Invalid(String),
    AbiHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    ExecutionDeferred {
        context: &'static str,
        reason: ExecutionDeferral,
    },
    AllocationDeferred {
        context: &'static str,
        refusal: AllocationRefusal,
    },
    DecodeDeferred {
        context: &'static str,
        original: norito::core::DecodeLocalRefusal,
    },
}

impl ContractArtifactError {
    /// Construct an ordinary admission error. Public for the native preparation
    /// adapter; artifact callers should receive errors from verification.
    #[doc(hidden)]
    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            kind: ArtifactFailure::Invalid(format!(
                "invalid contract artifact: {}",
                message.into()
            )),
        }
    }

    /// Construct the ABI-descriptor mismatch variant.
    #[doc(hidden)]
    pub fn abi_hash_mismatch(expected: [u8; 32], actual: [u8; 32]) -> Self {
        Self {
            kind: ArtifactFailure::AbiHashMismatch { expected, actual },
        }
    }

    /// Preserve local resource ownership when a native preparation stage fails.
    ///
    /// Deterministic preparation failures remain invalid artifacts. A local
    /// deferral retains its original cause and any existing pool observation,
    /// including through a metered wrapper; no guest gas is attached to it.
    /// Constructing a local deferral borrows static context and allocates nothing.
    #[doc(hidden)]
    pub fn preparation(context: &'static str, error: VMError) -> Self {
        let kind = match error {
            VMError::ExecutionDeferred(reason) => {
                ArtifactFailure::ExecutionDeferred { context, reason }
            }
            VMError::AllocationDeferred(refusal) => {
                ArtifactFailure::AllocationDeferred { context, refusal }
            }
            VMError::DecodeDeferred(original) => {
                ArtifactFailure::DecodeDeferred { context, original }
            }
            VMError::Metered { source, .. } if source.execution_deferral().is_some() => {
                return Self::preparation(context, *source);
            }
            error => return Self::invalid(format!("{context} failed: {error}")),
        };
        Self { kind }
    }

    /// Borrow a local failure as a VM error while retaining the original retry owner.
    ///
    /// Deterministic admission diagnostics return `None` and are not copied.
    #[must_use]
    pub fn local_vm_error(&self) -> Option<VMError> {
        match &self.kind {
            ArtifactFailure::ExecutionDeferred { reason, .. } => {
                Some(VMError::ExecutionDeferred(*reason))
            }
            ArtifactFailure::AllocationDeferred { refusal, .. } => {
                Some(VMError::AllocationDeferred(refusal.clone()))
            }
            ArtifactFailure::DecodeDeferred { original, .. } => {
                Some(VMError::DecodeDeferred(original.clone()))
            }
            ArtifactFailure::Invalid(_) | ArtifactFailure::AbiHashMismatch { .. } => None,
        }
    }

    /// Convert a failure into the VM error surface without losing local custody.
    #[must_use]
    pub fn into_vm_error(self) -> VMError {
        match self.kind {
            ArtifactFailure::Invalid(_) => VMError::InvalidMetadata,
            ArtifactFailure::AbiHashMismatch { expected, actual } => {
                VMError::ArtifactAbiHashMismatch { expected, actual }
            }
            ArtifactFailure::ExecutionDeferred { reason, .. } => VMError::ExecutionDeferred(reason),
            ArtifactFailure::AllocationDeferred { refusal, .. } => {
                VMError::AllocationDeferred(refusal)
            }
            ArtifactFailure::DecodeDeferred { original, .. } => VMError::DecodeDeferred(original),
        }
    }
}

impl fmt::Display for ContractArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ArtifactFailure::Invalid(message) => f.write_str(message),
            ArtifactFailure::AbiHashMismatch { .. } => f.write_str(
                "invalid contract artifact: contract interface abi_hash does not match the runtime ABI descriptor",
            ),
            ArtifactFailure::ExecutionDeferred { context, reason } => write!(
                f, "contract preparation deferred during {context}: execution deferred: {reason}",
            ),
            ArtifactFailure::AllocationDeferred { context, refusal } => write!(
                f, "contract preparation deferred during {context}: execution allocation deferred: {refusal}",
            ),
            ArtifactFailure::DecodeDeferred { context, original } => write!(
                f, "contract preparation deferred during {context}: execution decode deferred: {original}",
            ),
        }
    }
}

impl Error for ContractArtifactError {}

#[cfg(test)]
mod tests {
    use super::*;
    use ivm_abi::error::ExecutionDeferral;

    #[test]
    fn admission_error_stays_below_large_result_threshold_without_boxing() {
        // Keep the complete opaque scope inline, at most the ordinary 128-byte
        // large-error threshold; allocating a Box on resource refusal is unsafe.
        assert!(core::mem::size_of::<ContractArtifactError>() <= 128);
    }

    #[test]
    fn canonical_metadata_refusal_retains_original_scope_through_admission() {
        let bytes = norito::encode_canonical(&vec![17_u8; 32]).unwrap();
        let original = norito::core::with_decode_limits_scope(
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || {
                norito::decode_canonical_for_admission::<Vec<u8>>(
                    &bytes,
                    norito::canonical_decode_limits(bytes.len()),
                )
            },
        )
        .unwrap_err()
        .into_local_refusal()
        .unwrap();
        let source = VMError::DecodeDeferred(original.clone());
        for wrapped in [
            source.clone(),
            VMError::Metered {
                gas: 99,
                source: Box::new(source.clone()),
            },
        ] {
            let admission = ContractArtifactError::preparation("canonical metadata", wrapped);
            assert_eq!(admission.local_vm_error(), Some(source.clone()));
            assert!(admission.to_string().starts_with(
                "contract preparation deferred during canonical metadata: execution decode deferred: "
            ));
            let returned = admission.into_vm_error();
            assert_eq!(returned, source);
            assert_eq!(returned.metered_gas(), None);
            assert_eq!(returned.fault_kind(), None);
            let VMError::DecodeDeferred(retained) = returned else {
                panic!("lost scope")
            };
            assert_eq!(retained, original);
        }
    }

    #[test]
    fn metered_deterministic_diagnostic_keeps_original_gas_context() {
        let error = ContractArtifactError::preparation(
            "native index",
            VMError::Metered {
                gas: 99,
                source: Box::new(VMError::DecodeError),
            },
        );
        assert_eq!(
            error.to_string(),
            "invalid contract artifact: native index failed: metered syscall error after 99 gas: instruction decode error"
        );
        assert_eq!(error.into_vm_error(), VMError::InvalidMetadata);
    }

    #[test]
    fn local_preparation_refusal_remains_unmetered_and_retryable() {
        for reason in [
            ExecutionDeferral::AllocationUnavailable,
            ExecutionDeferral::ActiveMemoryCapacity,
            ExecutionDeferral::VerifierArtifactsUnavailable,
        ] {
            let source = VMError::Metered {
                gas: 99,
                source: Box::new(VMError::ExecutionDeferred(reason)),
            };
            let error = ContractArtifactError::preparation("decoded instructions", source);
            assert_eq!(
                error.local_vm_error(),
                Some(VMError::ExecutionDeferred(reason))
            );
            assert!(
                error
                    .to_string()
                    .starts_with("contract preparation deferred")
            );
            let error = error.into_vm_error();
            assert_eq!(error, VMError::ExecutionDeferred(reason));
            assert_eq!(error.metered_gas(), None);
        }
    }

    #[test]
    fn deterministic_preparation_failures_remain_invalid_artifacts() {
        for source in [
            VMError::DecodeError,
            VMError::OutOfMemory,
            VMError::InvalidMetadata,
        ] {
            let error = ContractArtifactError::preparation("native index", source);
            assert_eq!(error.local_vm_error(), None);
            assert!(error.to_string().starts_with("invalid contract artifact:"));
            assert_eq!(error.into_vm_error(), VMError::InvalidMetadata);
        }
        let ordinary = ContractArtifactError::invalid("missing interface");
        assert_eq!(
            ordinary.to_string(),
            "invalid contract artifact: missing interface"
        );
        assert_eq!(ordinary.into_vm_error(), VMError::InvalidMetadata);
    }

    #[test]
    fn abi_mismatch_preserves_both_exact_hashes() {
        let expected = [1; 32];
        let actual = [2; 32];
        let error = ContractArtifactError::abi_hash_mismatch(expected, actual);
        assert!(error.to_string().contains("abi_hash does not match"));
        assert_eq!(
            error.into_vm_error(),
            VMError::ArtifactAbiHashMismatch { expected, actual }
        );
    }
}
