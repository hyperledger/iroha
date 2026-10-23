//! Shared canonical BLS point parsing with fixed backing and exact diagnostics.

use crate::ParseError;
use ark_serialize::SerializationError;
use w3f_bls::{EngineBLS, PublicKey, SerializableToBytes, Signature};

/// A deterministic parser failure; supported borrowed point decoders allocate no backing.
#[derive(Debug)]
pub(crate) enum Failure {
    /// The bounded BLS validator was called with another key algorithm.
    PublicKeyAlgorithm,
    /// Nonempty all-zero public-key material.
    PublicKeyZero,
    /// A short, off-curve, out-of-field or non-subgroup public key.
    PublicKeyInvalid,
    /// The original typed decoder failure, preserved without formatting it.
    PublicKeyDecode(SerializationError),
    /// The complete input differs from the canonical public-key encoding.
    PublicKeyNonCanonical,
    /// The canonical public key is the identity point.
    PublicKeyIdentity,
    /// Nonempty all-zero signature material.
    SignatureZero,
    /// A signature which the checked compressed decoder rejects.
    SignatureInvalid,
    /// The complete input differs from the canonical signature encoding.
    SignatureNonCanonical,
    /// The canonical signature is the identity point.
    SignatureIdentity,
}

impl Failure {
    /// Materialize the ordinary public API error outside the fixed parser.
    pub(super) fn into_parse_error(self) -> ParseError {
        let message = match self {
            Self::PublicKeyAlgorithm => "BLS validation requires a BLS algorithm",
            // Preserve the decoder's actual typed reason, including any future
            // new reason, instead of reclassifying it from input flags/length.
            Self::PublicKeyDecode(error) => return ParseError::Invalid(error.to_string()),
            Self::PublicKeyZero => "BLS public key material must not be all zero",
            Self::PublicKeyInvalid => "the input buffer contained invalid data",
            Self::PublicKeyNonCanonical => "non-canonical BLS public key encoding",
            Self::PublicKeyIdentity => "BLS public key is identity",
            Self::SignatureZero => "BLS signature material must not be all zero",
            Self::SignatureInvalid => "Failed to parse signature.",
            Self::SignatureNonCanonical => "non-canonical BLS signature encoding",
            Self::SignatureIdentity => "BLS signature is identity",
        };
        ParseError::Invalid(message.to_owned())
    }
}

/// One existing compressed point, using its exact 48- or 96-byte prefix.
pub(super) struct Encoding {
    bytes: [u8; 96],
    len: usize,
}

impl Encoding {
    /// Borrow the initialized canonical point bytes.
    pub(super) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn is_identity(&self) -> bool {
        self.as_slice().first() == Some(&0xc0) && self.as_slice()[1..].iter().all(|byte| *byte == 0)
    }
}

/// Serialize a point into fixed backing without `SerializableToBytes::to_bytes`.
pub(super) fn encode<T: SerializableToBytes>(point: &T) -> Option<Encoding> {
    let len = T::SERIALIZED_BYTES_SIZE;
    let mut bytes = [0_u8; 96];
    let output = bytes.get_mut(..len)?;
    point.serialize_compressed(output).ok()?;
    Some(Encoding { bytes, len })
}

fn all_zero(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|byte| *byte == 0)
}

/// Keep the typed verifier's all-zero diagnostic ahead of typed-key validation.
pub(super) fn signature_nonzero(bytes: &[u8]) -> Result<(), Failure> {
    if all_zero(bytes) {
        Err(Failure::SignatureZero)
    } else {
        Ok(())
    }
}

/// Decode a canonical nonidentity key with the original checked point parser.
pub(super) fn public_key<E: EngineBLS>(bytes: &[u8]) -> Result<(PublicKey<E>, Encoding), Failure> {
    if all_zero(bytes) {
        return Err(Failure::PublicKeyZero);
    }
    let key = PublicKey::<E>::from_bytes(bytes).map_err(Failure::PublicKeyDecode)?;
    let canonical = encode(&key).ok_or(Failure::PublicKeyInvalid)?;
    if canonical.as_slice() != bytes {
        return Err(Failure::PublicKeyNonCanonical);
    }
    if canonical.is_identity() {
        return Err(Failure::PublicKeyIdentity);
    }
    Ok((key, canonical))
}

/// Decode a canonical nonidentity signature with exact existing error ordering.
pub(super) fn signature<E: EngineBLS>(bytes: &[u8]) -> Result<(Signature<E>, Encoding), Failure> {
    signature_nonzero(bytes)?;
    let signature = Signature::<E>::from_bytes(bytes).map_err(|_| Failure::SignatureInvalid)?;
    let canonical = encode(&signature).ok_or(Failure::SignatureInvalid)?;
    if canonical.as_slice() != bytes {
        return Err(Failure::SignatureNonCanonical);
    }
    if canonical.is_identity() {
        return Err(Failure::SignatureIdentity);
    }
    Ok((signature, canonical))
}
