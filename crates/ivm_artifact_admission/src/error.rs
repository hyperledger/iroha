//! Typed admission failures and local native-preparation deferrals.

use std::{error::Error, fmt};

use ivm_abi::{
    VMError,
    error::{AllocationRefusal, AllocatorRefusal, ExecutionDeferral, VerificationRefusal},
};

/// Failure returned by shared artifact admission or native preparation.
///
/// Local resource refusal remains a retryable VM deferral. It never changes
/// whether an immutable artifact satisfies the shared admission policy.
#[derive(Debug)]
pub struct ContractArtifactError {
    kind: ArtifactFailure,
}

// Retain only the admission surface's concrete outcomes. Carrying a full VMError
// beside its diagnostic would also reserve space for unrelated guest abort data.
#[derive(Debug)]
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
    AllocatorDeferred {
        context: &'static str,
        original: AllocatorRefusal,
    },
    VerificationDeferred {
        context: &'static str,
        original: VerificationRefusal,
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
            VMError::AllocatorDeferred(original) => {
                ArtifactFailure::AllocatorDeferred { context, original }
            }
            VMError::VerificationDeferred(original) => {
                ArtifactFailure::VerificationDeferred { context, original }
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

    /// Whether preparation stopped locally, without exporting or copying its cause.
    #[must_use]
    pub fn is_local_deferral(&self) -> bool {
        !matches!(
            self.kind,
            ArtifactFailure::Invalid(_) | ArtifactFailure::AbiHashMismatch { .. }
        )
    }

    /// Export a local cause exactly once, leaving an ordinary diagnostic intact on mismatch.
    pub fn try_into_local_vm_error(self) -> Result<VMError, Self> {
        match self.kind {
            ArtifactFailure::ExecutionDeferred { reason, .. } => {
                Ok(VMError::ExecutionDeferred(reason))
            }
            ArtifactFailure::AllocationDeferred { refusal, .. } => {
                Ok(VMError::AllocationDeferred(refusal))
            }
            ArtifactFailure::DecodeDeferred { original, .. } => {
                Ok(VMError::DecodeDeferred(original))
            }
            ArtifactFailure::AllocatorDeferred { original, .. } => {
                Ok(VMError::AllocatorDeferred(original))
            }
            ArtifactFailure::VerificationDeferred { original, .. } => {
                Ok(VMError::VerificationDeferred(original))
            }
            kind => Err(Self { kind }),
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
            ArtifactFailure::AllocatorDeferred { original, .. } => {
                VMError::AllocatorDeferred(original)
            }
            ArtifactFailure::VerificationDeferred { original, .. } => {
                VMError::VerificationDeferred(original)
            }
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
            ArtifactFailure::AllocatorDeferred { context, original } => write!(
                f, "contract preparation deferred during {context}: physical allocation deferred: {original}",
            ),
            ArtifactFailure::VerificationDeferred { context, original } => write!(
                f, "contract preparation deferred during {context}: execution verification deferred: {original}",
            ),
            ArtifactFailure::DecodeDeferred { context, original } => write!(
                f, "contract preparation deferred during {context}: execution decode deferred: {original}",
            ),
        }
    }
}

impl Error for ContractArtifactError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.kind {
            ArtifactFailure::ExecutionDeferred { reason, .. } => Some(reason),
            ArtifactFailure::AllocationDeferred { refusal, .. } => Some(refusal),
            ArtifactFailure::DecodeDeferred { original, .. } => Some(original),
            ArtifactFailure::VerificationDeferred { original, .. } => Some(original),
            ArtifactFailure::AllocatorDeferred { original, .. } => Some(original),
            ArtifactFailure::Invalid(_) | ArtifactFailure::AbiHashMismatch { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_error_stays_below_large_result_threshold_without_boxing() {
        eprintln!(
            "ContractArtifactError inline bytes: {}",
            core::mem::size_of::<ContractArtifactError>()
        );
        assert!(core::mem::size_of::<ContractArtifactError>() <= 128);
    }

    #[test]
    fn canonical_and_verification_refusals_retain_original_scope_through_admission() {
        let bytes = norito::encode_canonical(&vec![17_u8; 32]).unwrap();
        for native in [false, true] {
            for metered in [false, true] {
                for selective in [false, true] {
                    let original = norito::core::with_decode_limits_scope(
                        norito::core::DecodeLimits::new(
                            usize::MAX,
                            usize::MAX,
                            usize::MAX,
                            0,
                            usize::MAX,
                        ),
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
                    let source = if native {
                        VMError::VerificationDeferred(VerificationRefusal::from_decode_refusal(
                            original.clone(),
                        ))
                    } else {
                        VMError::DecodeDeferred(original.clone())
                    };
                    let source = if metered {
                        VMError::Metered {
                            gas: 99,
                            source: Box::new(source),
                        }
                    } else {
                        source
                    };
                    let admission =
                        ContractArtifactError::preparation("canonical metadata", source);
                    assert!(admission.is_local_deferral());
                    assert!(admission.source().is_some());
                    assert!(admission.to_string().starts_with(
                        "contract preparation deferred during canonical metadata: execution "
                    ));
                    let returned = if selective {
                        admission.try_into_local_vm_error().unwrap()
                    } else {
                        admission.into_vm_error()
                    };
                    assert_eq!(returned.metered_gas(), None);
                    assert_eq!(returned.fault_kind(), None);
                    assert_eq!(
                        returned.execution_deferral(),
                        Some(ExecutionDeferral::ActiveMemoryCapacity)
                    );
                    let retained = match returned {
                        VMError::VerificationDeferred(owner) if native => {
                            owner.into_decode_refusal().unwrap()
                        }
                        VMError::DecodeDeferred(owner) if !native => owner,
                        other => panic!("lost original owner: {other:?}"),
                    };
                    assert_eq!(retained, original);
                    assert_eq!(
                        norito::decode_canonical::<Vec<u8>>(&bytes).unwrap(),
                        vec![17_u8; 32]
                    );
                }
            }
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
        assert!(!error.is_local_deferral());
        let error = error.try_into_local_vm_error().unwrap_err();
        assert!(matches!(error.into_vm_error(), VMError::InvalidMetadata));
    }

    #[test]
    fn local_preparation_refusal_remains_unmetered_and_retryable() {
        for reason in [
            ExecutionDeferral::AllocationUnavailable,
            ExecutionDeferral::ActiveMemoryCapacity,
            ExecutionDeferral::VerifierArtifactsUnavailable,
            ExecutionDeferral::VerificationCancelled,
            ExecutionDeferral::NativeVerificationMemoryUnavailable,
            ExecutionDeferral::VerifierInitializationUnavailable,
        ] {
            for selective in [false, true] {
                let error = ContractArtifactError::preparation(
                    "decoded instructions",
                    VMError::Metered {
                        gas: 99,
                        source: Box::new(VMError::ExecutionDeferred(reason)),
                    },
                );
                assert!(error.is_local_deferral());
                assert!(
                    error
                        .to_string()
                        .starts_with("contract preparation deferred")
                );
                let error = if selective {
                    error.try_into_local_vm_error().unwrap()
                } else {
                    error.into_vm_error()
                };
                assert!(matches!(error, VMError::ExecutionDeferred(actual) if actual == reason));
                assert_eq!(error.metered_gas(), None);
            }
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
            assert!(!error.is_local_deferral());
            assert!(error.source().is_none());
            assert!(error.to_string().starts_with("invalid contract artifact:"));
            assert!(matches!(
                error.try_into_local_vm_error().unwrap_err().into_vm_error(),
                VMError::InvalidMetadata
            ));
        }
        let ordinary = ContractArtifactError::invalid("missing interface");
        assert_eq!(
            ordinary.to_string(),
            "invalid contract artifact: missing interface"
        );
        assert!(matches!(ordinary.into_vm_error(), VMError::InvalidMetadata));
    }

    #[test]
    fn abi_mismatch_preserves_both_exact_hashes() {
        let expected = [1; 32];
        let actual = [2; 32];
        let error = ContractArtifactError::abi_hash_mismatch(expected, actual);
        assert!(!error.is_local_deferral());
        assert!(error.to_string().contains("abi_hash does not match"));
        let error = error.try_into_local_vm_error().unwrap_err();
        assert!(
            matches!(error.into_vm_error(), VMError::ArtifactAbiHashMismatch { expected:e, actual:a } if e == expected && a == actual)
        );
    }
}
