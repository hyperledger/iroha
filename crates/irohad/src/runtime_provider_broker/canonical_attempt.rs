//! Original canonical codec outcomes retained by an already-received broker operation.
//!
//! Protocol and cumulative-operation ceilings are completed refusals, never pool pressure.
//! Typed codec causes stay local; no wire error carries retry or resource authority.
use super::*;

#[derive(Debug)]
pub(super) enum CanonicalAttemptErrorV1 {
    Rejected(BrokerError),
    Decode(norito::core::DecodeAttemptError),
    Encode(norito::core::BoundedEncodeError),
    Allocation(std::collections::TryReserveError),
}
impl std::fmt::Display for CanonicalAttemptErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(error) => write!(formatter, "canonical operation rejected: {error:?}"),
            Self::Decode(error) => std::fmt::Display::fmt(error, formatter),
            Self::Encode(error) => std::fmt::Display::fmt(error, formatter),
            Self::Allocation(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}
impl std::error::Error for CanonicalAttemptErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rejected(_) => None,
            Self::Decode(error) => Some(error),
            Self::Encode(error) => Some(error),
            Self::Allocation(error) => Some(error),
        }
    }
}

impl CanonicalAttemptErrorV1 {
    pub(super) fn retryable(&self) -> bool {
        match self {
            Self::Decode(error) => matches!(
                error.kind(),
                norito::core::DecodeAttemptErrorKind::Allocator
                    | norito::core::DecodeAttemptErrorKind::EnclosingLimit
            ),
            Self::Encode(
                norito::core::BoundedEncodeError::AllocationFailed { .. }
                | norito::core::BoundedEncodeError::Serialization(norito::Error::AllocationFailed {
                    ..
                }),
            )
            | Self::Allocation(_) => true,
            Self::Rejected(_) | Self::Encode(_) => false,
        }
    }

    // Only callers with no retained codec continuation project to the existing
    // payload-free service category. It never authorizes another provider call.
    pub(super) fn service_error(&self) -> BrokerError {
        match self {
            Self::Rejected(error) => *error,
            _ if self.retryable() => BrokerError::Unavailable,
            Self::Decode(_) | Self::Encode(_) | Self::Allocation(_) => BrokerError::Protocol,
        }
    }
}
impl From<BrokerError> for CanonicalAttemptErrorV1 {
    fn from(error: BrokerError) -> Self {
        Self::Rejected(error)
    }
}

pub(super) fn encode<T: NoritoSerialize>(
    value: &T,
    limit: usize,
) -> Result<Vec<u8>, CanonicalAttemptErrorV1> {
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    // Count and charge once before construction. A failed physical allocation
    // does not reset or refund the operation's cumulative-work counter.
    let framed_len = norito::canonical_frame_len(value).map_err(|error| {
        CanonicalAttemptErrorV1::Encode(norito::core::BoundedEncodeError::Serialization(error))
    })?;
    if framed_len == 0 || framed_len > limit {
        return Err(BrokerError::Rejected.into());
    }
    if let Some(admission) = current_decode_resource_admission() {
        admission.reserve_encoded_copy(framed_len, limit)?;
    }
    // TODO: the existing conservative operation permit does not fund all
    // serializer scratch or physical Vec backing. Preserve actual allocation
    // errors without claiming original-State funding or inventing pool wakes.
    let mut bytes = ScrubbedBytes::new(
        norito::core::to_bytes_bounded(value, limit).map_err(CanonicalAttemptErrorV1::Encode)?,
    );
    if bytes.len() != framed_len {
        return Err(BrokerError::Protocol.into());
    }
    Ok(bytes.take())
}

/// Preserve the actual bounded leaf-allocation failure; fixed work caps remain terminal.
pub(super) fn copy(bytes: &[u8], limit: usize) -> Result<ScrubbedBytes, CanonicalAttemptErrorV1> {
    if bytes.len() > limit {
        return Err(BrokerError::Rejected.into());
    }
    if let Some(admission) = current_decode_resource_admission() {
        admission.reserve_retained_bytes(bytes.len(), limit)?;
    }
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(CanonicalAttemptErrorV1::Allocation)?;
    copy.extend_from_slice(bytes);
    Ok(ScrubbedBytes::new(copy))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_refusal_exposes_the_original_cause_without_changing_retry_classification() {
        use std::error::Error as _;

        let cause = Vec::<u8>::new().try_reserve_exact(usize::MAX).unwrap_err();
        let expected = cause.to_string();
        let error = CanonicalAttemptErrorV1::Allocation(cause);
        assert!(error.retryable());
        assert_eq!(error.service_error(), BrokerError::Unavailable);
        assert_eq!(error.to_string(), expected);
        let original = match &error {
            CanonicalAttemptErrorV1::Allocation(original) => original,
            _ => unreachable!("the original allocation cause is retained"),
        };
        let source = error
            .source()
            .unwrap()
            .downcast_ref::<std::collections::TryReserveError>()
            .unwrap();
        assert!(std::ptr::eq(source, original));
    }

    #[test]
    fn copied_reply_leaves_preserve_exact_bytes_and_fixed_caps_are_terminal() {
        let original = [0x12, 0x34, 0x56];
        let copy = copy(&original, original.len()).unwrap();
        assert_eq!(copy.as_slice(), original);
        let error = super::copy(&original, original.len() - 1).err().unwrap();
        assert!(!error.retryable());
        assert_eq!(error.service_error(), BrokerError::Rejected);
    }
}
