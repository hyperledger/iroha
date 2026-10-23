//! Local implementation capabilities, separate from canonical algorithm identity.

use crate::Algorithm;
use core::fmt;

/// A cryptographic operation whose implementation may be absent in a local build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoOperation {
    /// Validate a public key's canonical cryptographic encoding.
    ParsePublicKey,
    /// Validate and retain secret-key material.
    ParsePrivateKey,
    /// Derive or generate a signing key pair.
    GenerateKeyPair,
    /// Produce a signature with secret-key material.
    Sign,
    /// Verify a signature's cryptographic relation.
    VerifySignature,
}
impl fmt::Display for CryptoOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ParsePublicKey => "public-key parsing",
            Self::ParsePrivateKey => "private-key parsing",
            Self::GenerateKeyPair => "key-pair generation",
            Self::Sign => "signing",
            Self::VerifySignature => "signature verification",
        })
    }
}

/// A known canonical algorithm lacks the requested implementation in this build.
///
/// This fixed diagnostic is neither malformed protocol input nor a failed
/// signature relation. It does not carry or replace a local resource refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedImplementation {
    /// The canonical algorithm whose identity was recognized.
    pub algorithm: Algorithm,
    /// The operation that cannot be performed locally.
    pub operation: CryptoOperation,
}
impl UnsupportedImplementation {
    /// Recover a known unavailable public-key parser from its canonical codec error.
    ///
    /// Only the exact canonical algorithm identity and an actually absent parser
    /// produce this diagnostic. Unknown features, available parsers, malformed
    /// input and resource refusals retain their original caller-owned categories.
    #[must_use]
    pub fn from_public_key_decode_error(error: &norito::Error) -> Option<Self> {
        let norito::Error::UnsupportedFeature(name) = error else {
            return None;
        };
        let algorithm = Algorithm::ALL
            .iter()
            .copied()
            .find(|algorithm| algorithm.as_static_str() == *name)?;
        algorithm
            .require_implementation(CryptoOperation::ParsePublicKey)
            .err()
    }
}

impl fmt::Display for UnsupportedImplementation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} implementation unavailable for {}",
            self.operation, self.algorithm
        )
    }
}
impl std::error::Error for UnsupportedImplementation {}

impl Algorithm {
    /// Require a local implementation without changing protocol identity or policy validity.
    ///
    /// ML-DSA public-key encoding can be validated without its optional native
    /// signing/verifying implementation. Every other operation requires that backend.
    ///
    /// # Errors
    /// Returns the exact algorithm and operation when its implementation is absent.
    pub const fn require_implementation(
        self,
        operation: CryptoOperation,
    ) -> Result<(), UnsupportedImplementation> {
        let available = match self {
            Self::Ed25519 | Self::Secp256k1 => true,
            Self::MlDsa => {
                matches!(operation, CryptoOperation::ParsePublicKey) || cfg!(feature = "pqc")
            }
            Self::BlsNormal | Self::BlsSmall => cfg!(feature = "bls"),
            Self::Gost3410_2012_256ParamSetA
            | Self::Gost3410_2012_256ParamSetB
            | Self::Gost3410_2012_256ParamSetC
            | Self::Gost3410_2012_512ParamSetA
            | Self::Gost3410_2012_512ParamSetB => cfg!(feature = "gost"),
            Self::Sm2 => cfg!(feature = "sm"),
        };
        if available {
            Ok(())
        } else {
            Err(UnsupportedImplementation {
                algorithm: self,
                operation,
            })
        }
    }
}

#[cfg(test)]
mod tests;
