//! The sole uncached admission dispatch with unformatted rejection custody.
//!
//! Ordinary public diagnostics are materialized only by the outer Error adapter.
//! Algorithm parsing and verification reuse the existing canonical relations.

use super::{ed25519, mldsa, secp256k1};
use crate::{
    Algorithm, Error, PublicKey, PublicKeyEnvelopeError, Signature, UnsupportedImplementation,
};

/// Unformatted rejection from the borrowed, uncached signature relation.
///
/// This owns the original typed parser rejection, not a key, signature, cache or
/// rendered diagnostic. It is not a resource refusal or an execution permit.
#[derive(Debug)]
pub struct SignatureVerificationError(Failure);

#[derive(Debug)]
enum Failure {
    Envelope(PublicKeyEnvelopeError),
    Ed25519(ed25519::KeyRejection),
    Secp256k1(secp256k1::public_key::KeyRejection),
    #[cfg(feature = "bls")]
    Bls(super::bls::uncached::Rejection),
    #[cfg(feature = "gost")]
    Gost(super::gost::KeyRejection),
    #[cfg(feature = "sm")]
    Sm2(crate::sm::verification::KeyRejection),
    Signature,
    UnsupportedImplementation(UnsupportedImplementation),
}

impl SignatureVerificationError {
    /// Borrow the missing-implementation diagnostic without formatting or consuming this error.
    pub fn unsupported_implementation(&self) -> Option<UnsupportedImplementation> {
        match self.0 {
            Failure::UnsupportedImplementation(original) => Some(original),
            _ => None,
        }
    }

    #[cfg(feature = "bls")]
    pub(crate) fn bad_signature() -> Self {
        Self(Failure::Signature)
    }

    #[cfg(feature = "bls")]
    pub(crate) fn from_bls(error: super::bls::uncached::Rejection) -> Self {
        Self(Failure::Bls(error))
    }

    /// Materialize the existing public crypto diagnostic at a completed boundary.
    ///
    /// This adapter can allocate a String. Callers requiring fixed error custody
    /// must retain this owner instead of calling this method.
    #[must_use]
    pub fn into_error(self) -> Error {
        match self.0 {
            Failure::Envelope(error) => error.into_parse_error().into(),
            Failure::Ed25519(error) => error.into_parse_error().into(),
            Failure::Secp256k1(error) => error.into_parse_error().into(),
            #[cfg(feature = "bls")]
            Failure::Bls(error) => error.into_error(),
            #[cfg(feature = "gost")]
            Failure::Gost(error) => error.into_parse_error().into(),
            #[cfg(feature = "sm")]
            Failure::Sm2(error) => error.into_parse_error().into(),
            Failure::Signature => Error::BadSignature,
            Failure::UnsupportedImplementation(original) => {
                Error::UnsupportedImplementation(original)
            }
        }
    }
}

/// Verify normal-BLS wire fields without constructing signature or public-key owners.
///
/// This preserves the ordinary signature facade's canonical key-first relation
/// and geometry checks, with no positive cache or formatted diagnostic.
///
/// # Errors
/// Returns the original fixed canonical parse or signature rejection.
#[cfg(feature = "bls")]
pub fn verify_bls_normal_signature_borrowed(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), SignatureVerificationError> {
    super::bls::uncached::verify_facade(
        super::bls::uncached::Orientation::Normal,
        public_key,
        signature,
        message,
    )
    .map_err(SignatureVerificationError::from_bls)
}

/// Verify borrowed signature inputs without persistent caches or formatted errors.
///
/// This is the same admission relation used by `verify_signature_for_admission`.
/// It preserves algorithm/payload envelope order and each admitted algorithm's
/// canonical key and signature checks. It does not consult ordinary key caches
/// or positive-verdict caches.
///
/// # Errors
/// Returns the unformatted canonical parser or verification rejection, or the
/// exact missing local implementation. An unavailable verifier does not establish
/// an invalid signature and is distinct from a local resource deferral.
pub fn verify_signature_borrowed(
    proof: &Signature,
    public_key: &PublicKey,
    message: &[u8],
) -> Result<(), SignatureVerificationError> {
    verify(proof, public_key, message).map_err(SignatureVerificationError)
}

/// Verify fixed Ed25519 wire fields with the existing strict uncached relation.
///
/// Neither input gains an owned key/signature envelope. Parsing, verification,
/// and rejection use fixed stack storage and do not consult or populate caches.
/// No heap allocation is required from the caller's original execution pool.
///
/// # Errors
/// Returns the original unformatted canonical key or signature rejection.
pub fn verify_ed25519_signature_borrowed(
    public_key: &[u8; 32],
    signature: &[u8; 64],
    message: &[u8],
) -> Result<(), SignatureVerificationError> {
    let key = ed25519::Ed25519Sha512::parse_public_key_uncached_for_decode(public_key)
        .map_err(|error| SignatureVerificationError(Failure::Ed25519(error)))?;
    ed25519::Ed25519Sha512::verify_uncached(message, signature, &key)
        .map_err(|_| SignatureVerificationError(Failure::Signature))
}

/// Verify a borrowed BLS-normal proof of possession without retained caches.
///
/// The exact original `PoP` domain and typed key/proof parser order are retained.
/// Neither success nor failure copies the key/proof, owns a diagnostic String,
/// or consults/populates the ordinary positive-verdict caches.
///
/// # Errors
/// Returns the original unformatted envelope, canonical parser or relation rejection.
#[cfg(feature = "bls")]
pub fn verify_bls_normal_pop_borrowed(
    public_key: &PublicKey,
    proof: &[u8],
) -> Result<(), SignatureVerificationError> {
    verify_bls_normal_pop_key_borrowed(public_key, proof).map(drop)
}

#[cfg(feature = "bls")]
pub(crate) fn verify_bls_normal_pop_key_borrowed(
    public_key: &PublicKey,
    proof: &[u8],
) -> Result<blstrs::G1Affine, SignatureVerificationError> {
    let verify = || {
        let (algorithm, payload) = public_key.borrowed_parts().map_err(Failure::Envelope)?;
        if algorithm != Algorithm::BlsNormal {
            return Err(Failure::Signature);
        }
        let message = crate::bls_pop_message_hash(payload);
        // The ordinary PoP API uses the typed proof parser. The generic
        // Signature facade rejects proof geometry earlier with BadSignature.
        super::bls::verified_normal_key_borrowed(payload, proof, &message).map_err(Failure::Bls)
    };
    verify().map_err(SignatureVerificationError)
}

fn verify(proof: &Signature, public_key: &PublicKey, message: &[u8]) -> Result<(), Failure> {
    let (algorithm, payload) = public_key.borrowed_parts().map_err(Failure::Envelope)?;
    // Use the canonical capability owner before non-ML-DSA dispatch. Its missing
    // backend branches already refused before key parsing. ML-DSA keeps its
    // available key-geometry check before reporting an unavailable verifier.
    if algorithm != Algorithm::MlDsa {
        algorithm
            .require_implementation(crate::CryptoOperation::VerifySignature)
            .map_err(Failure::UnsupportedImplementation)?;
    }
    match algorithm {
        Algorithm::Ed25519 => {
            let key = ed25519::Ed25519Sha512::parse_public_key_uncached_for_decode(payload)
                .map_err(Failure::Ed25519)?;
            // Both the shared strict signature parser and verify_strict return
            // only BadSignature here; no public diagnostic is constructed.
            ed25519::Ed25519Sha512::verify_uncached(message, proof.payload(), &key)
                .map_err(|_| Failure::Signature)
        }
        Algorithm::Secp256k1 => {
            let key = secp256k1::public_key::parse(payload).map_err(Failure::Secp256k1)?;
            // Shared fixed scalar/point relation; its failures are BadSignature.
            secp256k1::EcdsaSecp256k1Sha256::verify(message, proof.payload(), &key)
                .map_err(|_| Failure::Signature)
        }
        Algorithm::MlDsa => {
            // Actual invalid key/signature relations retain their existing rejection;
            // a missing local verifier is never evidence that this signature is invalid.
            mldsa::verify(payload, proof.payload(), message).map_err(|error| match error {
                #[cfg(not(feature = "pqc"))]
                mldsa::Rejection::UnsupportedImplementation(original) => {
                    Failure::UnsupportedImplementation(original)
                }
                mldsa::Rejection::Key(_) => Failure::Signature,
                #[cfg(any(feature = "pqc", test))]
                mldsa::Rejection::Signature => Failure::Signature,
            })
        }
        #[cfg(feature = "gost")]
        Algorithm::Gost3410_2012_256ParamSetA
        | Algorithm::Gost3410_2012_256ParamSetB
        | Algorithm::Gost3410_2012_256ParamSetC
        | Algorithm::Gost3410_2012_512ParamSetA
        | Algorithm::Gost3410_2012_512ParamSetB => {
            super::gost::validate_public_key(algorithm, payload).map_err(Failure::Gost)?;
            // These five exhaustive admitted cases select a fixed curve. The
            // unsupported-algorithm diagnostic in the ordinary GOST facade is
            // unreachable; the selected relation returns only BadSignature.
            super::gost::verify_bytes(algorithm, message, proof.payload(), payload)
                .map_err(|_| Failure::Signature)
        }
        #[cfg(feature = "bls")]
        Algorithm::BlsNormal | Algorithm::BlsSmall => {
            let orientation = super::bls::uncached::Orientation::for_algorithm(algorithm)
                .ok_or(Failure::Signature)?;
            super::bls::uncached::verify_facade(orientation, payload, proof.payload(), message)
                .map_err(Failure::Bls)
        }
        #[cfg(feature = "sm")]
        Algorithm::Sm2 => crate::sm::verification::BorrowedKey::parse(payload)
            .map_err(Failure::Sm2)?
            // Shared fixed identity-hash/scalar/point relation, BadSignature only.
            .verify(message, proof.payload())
            .map_err(|_| Failure::Signature),
        #[cfg(not(feature = "bls"))]
        Algorithm::BlsNormal | Algorithm::BlsSmall => Err(Failure::UnsupportedImplementation(
            UnsupportedImplementation {
                algorithm,
                operation: crate::CryptoOperation::VerifySignature,
            },
        )),
        #[cfg(not(feature = "gost"))]
        Algorithm::Gost3410_2012_256ParamSetA
        | Algorithm::Gost3410_2012_256ParamSetB
        | Algorithm::Gost3410_2012_256ParamSetC
        | Algorithm::Gost3410_2012_512ParamSetA
        | Algorithm::Gost3410_2012_512ParamSetB => Err(Failure::UnsupportedImplementation(
            UnsupportedImplementation {
                algorithm,
                operation: crate::CryptoOperation::VerifySignature,
            },
        )),
        #[cfg(not(feature = "sm"))]
        Algorithm::Sm2 => Err(Failure::UnsupportedImplementation(
            UnsupportedImplementation {
                algorithm,
                operation: crate::CryptoOperation::VerifySignature,
            },
        )),
    }
}

#[cfg(test)]
mod tests;
