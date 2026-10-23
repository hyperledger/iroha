//! Borrowed canonical signature encoding checks, separate from retention and verification.

use crate::{Error, ML_DSA_65_SIGNATURE_BYTES, ParseError, Signature, SignaturePayloadError};

/// Fixed rejection of raw signature encoding, without a copy or diagnostic allocation.
///
/// This is a completed encoding rejection. It cannot represent a local admission
/// refusal and does not establish that a signature authenticates any message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureEncodingError {
    /// The common signature payload rule rejected empty or all-zero bytes.
    Payload(SignaturePayloadError),
    /// The selected algorithm rejected the length or canonical encoding.
    Malformed,
}

impl SignatureEncodingError {
    /// Materialize the public crypto diagnostic for a completed encoding rejection.
    ///
    /// Empty/all-zero diagnostics allocate here; the borrowed validators do not.
    #[must_use]
    pub fn into_error(self) -> Error {
        match self {
            Self::Payload(_) => Error::Parse(ParseError::Invalid(
                "signature payload must not be empty or all zero".to_owned(),
            )),
            Self::Malformed => Error::BadSignature,
        }
    }
}

impl core::fmt::Display for SignatureEncodingError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Payload(_) => {
                "Key could not be parsed. signature payload must not be empty or all zero"
            }
            Self::Malformed => "Signature verification failed",
        })
    }
}

impl std::error::Error for SignatureEncodingError {}

/// Check raw Ed25519 signature encoding without retaining its bytes.
///
/// Uses the same length and canonical, non-small-order, prime-order `R` relation
/// as the owned parser. This grants no authority and performs no message verification.
/// Neither success nor rejection reserves decode capacity or allocates a copy/error.
///
/// # Errors
/// Rejects an empty/all-zero payload or an invalid Ed25519 encoding.
pub fn ed25519_validate_signature_encoding(payload: &[u8]) -> Result<(), SignatureEncodingError> {
    Signature::validate_payload(payload).map_err(SignatureEncodingError::Payload)?;
    super::ed25519::Ed25519Sha512::parse_signature(payload)
        .map(|_| ())
        .map_err(|_| SignatureEncodingError::Malformed)
}

/// Check raw ML-DSA-65 signature encoding without retaining its bytes.
///
/// Uses the owned parser's exact length and configured native detached-encoding
/// relation. This does not verify a message or enable ML-DSA verification in a
/// build without its backend. No decode capacity or heap backing is acquired.
///
/// # Errors
/// Rejects an empty/all-zero payload or an invalid ML-DSA-65 encoding.
pub fn mldsa65_validate_signature_encoding(payload: &[u8]) -> Result<(), SignatureEncodingError> {
    Signature::validate_payload(payload).map_err(SignatureEncodingError::Payload)?;
    if payload.len() != ML_DSA_65_SIGNATURE_BYTES {
        return Err(SignatureEncodingError::Malformed);
    }
    #[cfg(feature = "pqc")]
    {
        use pqcrypto_traits::sign::DetachedSignature as _;
        pqcrypto_mldsa::mldsa65::DetachedSignature::from_bytes(payload)
            .map_err(|_| SignatureEncodingError::Malformed)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "encoding_tests.rs"]
mod tests;
