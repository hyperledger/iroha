//! Allocation-free retained input geometry for complete source-work admission.

use super::{Algorithm, ParseError, PublicKey};

/// Fixed rejection while borrowing a compact key's existing envelope.
///
/// This error retains no key bytes or formatted diagnostic. It does not assert
/// that the algorithm-specific payload is canonical or cryptographically valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKeyEnvelopeError(EnvelopeFailure);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnvelopeFailure {
    MissingAlgorithm,
    InvalidAlgorithm(u8),
    MissingPayload,
}

impl PublicKeyEnvelopeError {
    pub(crate) fn into_parse_error(self) -> ParseError {
        ParseError::Invalid(match self.0 {
            EnvelopeFailure::MissingAlgorithm => "missing public key algorithm tag".to_owned(),
            EnvelopeFailure::InvalidAlgorithm(tag) => {
                format!("invalid public key algorithm tag {tag}")
            }
            EnvelopeFailure::MissingPayload => "missing public key payload".to_owned(),
        })
    }
}

pub fn algorithm(bytes: &[u8]) -> Result<Algorithm, PublicKeyEnvelopeError> {
    let tag = *bytes
        .first()
        .ok_or(PublicKeyEnvelopeError(EnvelopeFailure::MissingAlgorithm))?;
    Algorithm::try_from(tag)
        .map_err(|()| PublicKeyEnvelopeError(EnvelopeFailure::InvalidAlgorithm(tag)))
}

pub fn payload(bytes: &[u8]) -> Result<&[u8], PublicKeyEnvelopeError> {
    bytes
        .get(1..)
        .ok_or(PublicKeyEnvelopeError(EnvelopeFailure::MissingPayload))
}

impl PublicKey {
    /// Borrow the signature algorithm without constructing a public error String.
    ///
    /// # Errors
    /// Returns a fixed rejection for a missing or unsupported algorithm tag.
    pub fn borrowed_algorithm(&self) -> Result<Algorithm, PublicKeyEnvelopeError> {
        algorithm(&self.0.algorithm_and_payload)
    }

    /// Borrow the compact algorithm and payload with fixed rejection custody.
    ///
    /// This preserves algorithm-before-payload error order. It admits only the
    /// envelope; callers must still apply the existing algorithm relation.
    ///
    /// # Errors
    /// Returns a fixed rejection if the existing compact envelope is malformed.
    pub fn borrowed_parts(&self) -> Result<(Algorithm, &[u8]), PublicKeyEnvelopeError> {
        Ok((
            self.borrowed_algorithm()?,
            payload(&self.0.algorithm_and_payload)?,
        ))
    }

    /// Fallibly extracts the signature algorithm and raw public-key payload.
    ///
    /// This is the checked counterpart to [`Self::to_bytes`]. Use it for
    /// `Result`-returning paths that may receive in-memory public keys from
    /// fallible decoding or FFI boundaries.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the compact public-key state is missing its
    /// algorithm tag or otherwise cannot expose a well-formed payload envelope.
    pub fn try_to_bytes(&self) -> Result<(Algorithm, &[u8]), ParseError> {
        self.borrowed_parts()
            .map_err(PublicKeyEnvelopeError::into_parse_error)
    }

    /// Length of the retained key payload, excluding the compact algorithm tag.
    ///
    /// This constant-time, allocation-free probe does not validate the algorithm,
    /// envelope or key. An empty/discarded representation reports zero. Callers
    /// must keep their existing semantic validation after admitting source work;
    /// measuring a malformed input grants it no validity or authority.
    pub fn input_payload_len(&self) -> usize {
        self.0.algorithm_and_payload.len().saturating_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Algorithm, KeyPair, PublicKeyCompact};
    use iroha_primitives::const_vec::ConstVec;
    use norito::codec::{Decode, Encode};

    #[test]
    fn constructed_and_decoded_keys_report_the_existing_borrowed_payload_length() {
        let pair = KeyPair::try_from_seed(vec![0x72; 32], Algorithm::Ed25519).unwrap();
        let key = pair.public_key();
        assert_eq!(key.input_payload_len(), key.try_to_bytes().unwrap().1.len());
        let decoded = PublicKey::decode(&mut key.encode().as_slice()).unwrap();
        assert_eq!(decoded, *key);
        assert_eq!(decoded.input_payload_len(), 32);
    }

    #[test]
    fn malformed_and_discarded_compact_state_is_measured_without_parsing_it() {
        let mut malformed = PublicKey(PublicKeyCompact {
            algorithm_and_payload: ConstVec::from(vec![0xff; 8_193]),
        });
        assert_eq!(malformed.input_payload_len(), 8_192);
        assert!(malformed.try_to_bytes().is_err());
        malformed.zeroize_for_confidential_discard();
        assert_eq!(malformed.input_payload_len(), 0);
        assert!(malformed.try_to_bytes().is_err());
        let tag_only = PublicKey(PublicKeyCompact {
            algorithm_and_payload: ConstVec::from(vec![0xff]),
        });
        assert_eq!(tag_only.input_payload_len(), 0);
    }
}
