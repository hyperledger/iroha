//! Local verification attempts retain the original decoder owner outside proof verdicts.

use norito::core::{DecodeAttemptError, DecodeLocalRefusal};

/// Typed initialization failure; a local arithmetic refusal is not a proof verdict.
#[derive(Debug)]
pub enum NativeVerifierInitError {
    /// Original parameter derivation failure.
    Params(crate::pcs::ipa::ParamsTrustError),
    /// Original verifier key construction failure.
    Key(crate::keys::KeyError),
    /// Original protocol table construction failure.
    Protocol(crate::protocol::ProtocolError),
    /// Original captured canonical reader or writer failure.
    Codec(norito::core::DecodeAttemptError),
    /// Original bounded canonical key-carrier output failure, including any scoped cause.
    Encoding(norito::core::BoundedEncodeError),
    /// A completed compiled-material invariant failure.
    Invariant(&'static str),
    /// A prior panic poisoned initialization; no verifier was published.
    CachePoisoned,
}

impl std::fmt::Display for NativeVerifierInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Params(original) => write!(f, "Params: {original}"),
            Self::Key(original) => write!(f, "Key: {original}"),
            Self::Protocol(original) => write!(f, "Protocol: {original}"),
            Self::Codec(original) => write!(f, "Codec: {original}"),
            Self::Encoding(original) => write!(f, "Encoding: {original}"),
            Self::Invariant(original) => write!(f, "Invariant: {original}"),
            Self::CachePoisoned => f.write_str("native material initialization lock is poisoned"),
        }
    }
}

impl std::error::Error for NativeVerifierInitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Params(original) => Some(original),
            Self::Key(original) => Some(original),
            Self::Protocol(original) => Some(original),
            Self::Codec(original) => Some(original),
            Self::Encoding(original) => Some(original),
            Self::Invariant(_) | Self::CachePoisoned => None,
        }
    }
}

/// Borrowed diagnostic category of an unfinished operation, without its owning evidence.
/// These categories do not create a memory-pool release observation or a proof verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationRefusalKind {
    /// Original enclosing decoder or reported allocator refusal.
    Decode(norito::core::DecodeLocalRefusalKind),
    /// A native operation returned cooperative cancellation.
    NativeCancelled,
    /// A native operation returned its typed MSM budget refusal, not a physical allocator report.
    NativeMemoryBudget,
    /// Trusted verifier material could not be initialized; incoming proof validity is unknown.
    InitializationUnavailable,
    /// Trusted compiled material is inconsistent or its initializer was poisoned.
    LocalInvariantViolation,
}

/// Opaque original cause of an unfinished verifier attempt.
///
/// There is no wire encoding. Typed consuming constructors retain the actual error
/// returned by the codec/native operation; it creates neither a new quota nor a release wait.
/// Trusted compiled-key initialization failures produce no verdict on an incoming proof.
#[derive(Debug)]
pub struct VerificationRefusal {
    original: OriginalRefusal,
}

#[derive(Debug)]
enum OriginalRefusal {
    Decode(DecodeLocalRefusal),
    NativeMath {
        original: crate::verifier::VerifyError,
        kind: VerificationRefusalKind,
    },
    Initialization(NativeVerifierInitError),
}

impl VerificationRefusal {
    /// Move an original captured decoder owner into the shared refusal carrier.
    pub fn from_decode_refusal(original: DecodeLocalRefusal) -> Self {
        Self {
            original: OriginalRefusal::Decode(original),
        }
    }

    /// Inspect a diagnostic category without copying or replacing the original cause.
    #[must_use]
    pub fn kind(&self) -> VerificationRefusalKind {
        use VerificationRefusalKind as Kind;
        match &self.original {
            OriginalRefusal::Decode(original) => Kind::Decode(original.kind()),
            OriginalRefusal::NativeMath { kind, .. } => *kind,
            OriginalRefusal::Initialization(original) => match original {
                NativeVerifierInitError::Invariant(_) | NativeVerifierInitError::CachePoisoned => {
                    Kind::LocalInvariantViolation
                }
                NativeVerifierInitError::Encoding(original) => match original {
                    norito::core::BoundedEncodeError::AllocationFailed { .. }
                    | norito::core::BoundedEncodeError::Serialization(
                        norito::Error::ScopedDecodeResource(_)
                        | norito::Error::AllocationFailed { .. },
                    ) => Kind::InitializationUnavailable,
                    // The complete public output bound and trusted serializer invariants are
                    // completed local defects, never transient capacity or incoming verdicts.
                    norito::core::BoundedEncodeError::FrameTooLarge { .. }
                    | norito::core::BoundedEncodeError::Serialization(_) => {
                        Kind::LocalInvariantViolation
                    }
                },
                NativeVerifierInitError::Key(original) if original.is_cancelled() => {
                    Kind::NativeCancelled
                }
                NativeVerifierInitError::Key(crate::keys::KeyError::Msm(
                    iroha_pasta::msm::MsmError::Budget(_),
                )) => Kind::NativeMemoryBudget,
                NativeVerifierInitError::Protocol(crate::protocol::ProtocolError::Plan(
                    original,
                )) => multiopen_refusal_kind(original).unwrap_or(Kind::InitializationUnavailable),
                _ => Kind::InitializationUnavailable,
            },
        }
    }

    /// Borrow an actual decoder owner, when this refusal came from a captured codec operation.
    #[must_use]
    pub fn decode_refusal(&self) -> Option<&DecodeLocalRefusal> {
        match &self.original {
            OriginalRefusal::Decode(original) => Some(original),
            _ => None,
        }
    }

    /// Borrow the original unfinished native verification error without rebuilding it.
    #[must_use]
    pub fn native_verification_error(&self) -> Option<&crate::verifier::VerifyError> {
        match &self.original {
            OriginalRefusal::NativeMath { original, .. } => Some(original),
            _ => None,
        }
    }

    /// Move out the exact decoder owner, leaving other native causes intact on mismatch.
    ///
    /// # Errors
    /// Returns this refusal unchanged if it retains a native math or initialization cause.
    pub fn into_decode_refusal(self) -> Result<DecodeLocalRefusal, Self> {
        match self.original {
            OriginalRefusal::Decode(original) => Ok(original),
            original => Err(Self { original }),
        }
    }

    /// Retain a trusted initializer failure without making a verdict on incoming material.
    /// A captured local codec owner is extracted without rebuilding its scope or cause.
    pub fn initialization(original: NativeVerifierInitError) -> Self {
        let original = match original {
            NativeVerifierInitError::Codec(error) => match error.into_local_refusal() {
                Ok(original) => return Self::from_decode_refusal(original),
                Err(original) => NativeVerifierInitError::Codec(original),
            },
            original => original,
        };
        Self {
            original: OriginalRefusal::Initialization(original),
        }
    }

    /// Borrow the exact initializer cause when no captured local codec owner was extracted.
    #[must_use]
    pub fn initialization_error(&self) -> Option<&NativeVerifierInitError> {
        match &self.original {
            OriginalRefusal::Initialization(original) => Some(original),
            _ => None,
        }
    }
}

impl core::fmt::Display for VerificationRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.original {
            OriginalRefusal::Decode(original) => original.fmt(f),
            OriginalRefusal::NativeMath { original, .. } => original.fmt(f),
            OriginalRefusal::Initialization(original) => original.fmt(f),
        }
    }
}

impl std::error::Error for VerificationRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match &self.original {
            OriginalRefusal::Decode(original) => original,
            OriginalRefusal::NativeMath { original, .. } => original,
            OriginalRefusal::Initialization(original) => original,
        })
    }
}

fn ipa_refusal_kind(error: &crate::pcs::ipa::IpaError) -> Option<VerificationRefusalKind> {
    use crate::pcs::ipa::IpaError;
    use iroha_pasta::msm::MsmError;
    match error {
        IpaError::Cancelled | IpaError::Msm(MsmError::Cancelled) => {
            Some(VerificationRefusalKind::NativeCancelled)
        }
        IpaError::Msm(MsmError::Budget(_)) => Some(VerificationRefusalKind::NativeMemoryBudget),
        _ => None,
    }
}

fn multiopen_refusal_kind(
    error: &crate::pcs::multiopen::MultiopenError,
) -> Option<VerificationRefusalKind> {
    use crate::pcs::multiopen::MultiopenError;
    match error {
        MultiopenError::Cancelled => Some(VerificationRefusalKind::NativeCancelled),
        MultiopenError::Ipa(original) => ipa_refusal_kind(original),
        _ => None,
    }
}

fn native_refusal_kind(error: &crate::verifier::VerifyError) -> Option<VerificationRefusalKind> {
    use crate::{protocol::ProtocolError, verifier::VerifyError};
    match error {
        VerifyError::Cancelled => Some(VerificationRefusalKind::NativeCancelled),
        VerifyError::Descriptor(original) if original.is_cancelled() => {
            Some(VerificationRefusalKind::NativeCancelled)
        }
        VerifyError::VerifyingKey(original) if original.is_cancelled() => {
            Some(VerificationRefusalKind::NativeCancelled)
        }
        VerifyError::Ipa(original) => ipa_refusal_kind(original),
        VerifyError::Multiopen(original) | VerifyError::Protocol(ProtocolError::Plan(original)) => {
            multiopen_refusal_kind(original)
        }
        VerifyError::BatchItem { error, .. } => native_refusal_kind(error),
        _ => None,
    }
}

/// Classify an original typed native result while preserving unfinished math operations.
/// Completed shape, scalar and equation failures alone enter the supplied rejection mapper.
pub fn native_verification_error<E>(
    original: crate::verifier::VerifyError,
    rejected: impl FnOnce(crate::verifier::VerifyError) -> E,
) -> VerificationAttemptError<E> {
    if let Some(kind) = native_refusal_kind(&original) {
        VerificationAttemptError::Deferred(VerificationRefusal {
            original: OriginalRefusal::NativeMath { original, kind },
        })
    } else {
        VerificationAttemptError::Rejected(rejected(original))
    }
}

/// A completed deterministic rejection or an unfinished local verification attempt.
///
/// This non-wire carrier is deliberately move-only. The local branch can only be obtained
/// from captured codec errors or original typed native operations; diagnostic numbers cannot
/// construct a decoder owner. Trusted initializer failures likewise produce no proof verdict.
/// It provides no conversion into a rejection and invents no pool release notification.
#[derive(Debug)]
pub enum VerificationAttemptError<E> {
    /// Verification completed and rejected the supplied material.
    Rejected(E),
    /// Verification did not complete; the original local operation or initializer cause is retained.
    Deferred(VerificationRefusal),
}

impl<E> VerificationAttemptError<E> {
    /// Project only a completed rejection while moving the original local cause unchanged.
    pub fn map_rejection<F>(self, map: impl FnOnce(E) -> F) -> VerificationAttemptError<F> {
        match self {
            Self::Rejected(error) => VerificationAttemptError::Rejected(map(error)),
            Self::Deferred(original) => VerificationAttemptError::Deferred(original),
        }
    }

    /// Borrow the original decoder cause after any surrounding scope has retired.
    /// `None` does not imply rejection: native math and initialization refusals have no decoder owner.
    #[must_use]
    pub fn local_refusal(&self) -> Option<&DecodeLocalRefusal> {
        match self {
            Self::Deferred(original) => original.decode_refusal(),
            Self::Rejected(_) => None,
        }
    }
}

impl<E> From<E> for VerificationAttemptError<E> {
    fn from(error: E) -> Self {
        Self::Rejected(error)
    }
}

impl<E: core::fmt::Display> core::fmt::Display for VerificationAttemptError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rejected(error) => error.fmt(f),
            Self::Deferred(original) => write!(f, "verification deferred: {original}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for VerificationAttemptError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rejected(error) => Some(error),
            Self::Deferred(original) => Some(original),
        }
    }
}

/// Convert only an already captured attempt; never classify a reconstructed raw error.
pub fn captured_codec_error<E>(
    error: DecodeAttemptError,
    rejected: impl FnOnce(norito::Error) -> E,
) -> VerificationAttemptError<E> {
    match error.into_local_refusal() {
        Ok(original) => {
            VerificationAttemptError::Deferred(VerificationRefusal::from_decode_refusal(original))
        }
        Err(invalid) => VerificationAttemptError::Rejected(rejected(invalid.into_error())),
    }
}

/// Complete an actual codec operation inside its original ambient scope.
/// Any protocol-specific nested limits must be entered by `operation`, after capture begins.
///
/// # Errors
/// Returns a mapped completed rejection for invalid input, or a deferred refusal retaining
/// the original local cause when the codec operation could not complete.
pub fn codec_attempt<T, E>(
    operation: impl FnOnce() -> Result<T, norito::Error>,
    rejected: impl FnOnce(norito::Error) -> E,
) -> Result<T, VerificationAttemptError<E>> {
    norito::core::classify_decode_attempt(operation)
        .map_err(|error| captured_codec_error(error, rejected))
}

/// Require a completed rejection in deterministic regression controls.
#[cfg(test)]
pub(crate) fn expect_rejected<E>(error: VerificationAttemptError<E>) -> E {
    match error {
        VerificationAttemptError::Rejected(error) => error,
        VerificationAttemptError::Deferred(original) => {
            panic!("unexpected local refusal: {original}")
        }
    }
}

#[cfg(test)]
mod tests;

/// Project a completed success/rejection without ever turning an unfinished operation into a verdict.
///
/// # Errors
/// Returns the original refusal unchanged when `attempt` is deferred. A completed rejection
/// returns `Ok(None)`.
pub fn completed_result<T, E>(
    attempt: Result<T, VerificationAttemptError<E>>,
) -> Result<Option<T>, VerificationRefusal> {
    match attempt {
        Ok(value) => Ok(Some(value)),
        Err(VerificationAttemptError::Rejected(_)) => Ok(None),
        Err(VerificationAttemptError::Deferred(original)) => Err(original),
    }
}
